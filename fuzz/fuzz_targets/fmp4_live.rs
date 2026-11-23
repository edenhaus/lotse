//! `fmp4_live`: the live writer never panics on an arbitrary sequence of
//! frames and holes, and every fragment it completes is a movie fragment
//! mp4-atom reads (ISO/IEC 14496-12 §8.8.4 `moof`, §8.1.1 `mdat`) with its
//! runs inside its `mdat`, at most one video sample in it, each track's
//! decode times never going back from fragment to fragment, and the
//! fragment's description
//! (`independent`, `decode_time`, `duration`) matching its video run: a
//! sync sample first (§8.8.3.1), the run's `tfdt` (§8.8.12) and its
//! duration on the video's 90 kHz timescale, to the nanosecond the
//! conversion rounds to.
//!
//! The first input byte picks the output: bit 0 H.265 instead of H.264,
//! bits 1 and 2 the audio (none, AAC-LC, mono or stereo Opus). The rest is
//! frames, each a control byte (bit 0 audio, bit 1 keyframe, bit 2 a new
//! epoch, bit 3 a timestamp step from eight bytes instead of two, bit 4 a
//! hole before the frame), the step, a capture time step in milliseconds,
//! a length and the payload; a video payload gets a start code before it,
//! so it has a NAL unit.
//! Run with `cargo +nightly fuzz run fmp4_live` from the repository root.

#![no_main]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mp4_atom::{Any, Decode as _};
use rocko_codec::aac::test_data::CONFIG_16K_MONO;
use rocko_codec::{h264, h265};
use rocko_core::clock::{Clock as _, FakeClock};
use rocko_core::live::{LiveFragment, LiveMuxer as _, LiveStep};
use rocko_core::recording::RecordingTrack;
use rocko_core::{Codec, Kind, MediaFrame, MediaTime};
use rocko_mux::LiveWriter;

/// The most frames one input pushes.
const MAX_FRAMES: usize = 512;

/// The sync sample flags the writer gives a keyframe (ISO/IEC 14496-12
/// §8.8.3.1: `sample_depends_on` 2).
const SYNC_SAMPLE: u32 = 0x0200_0000;

/// Reads the input front to back.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn bytes(&mut self, len: usize) -> &[u8] {
        let (head, rest) = self.0.split_at(len.min(self.0.len()));
        self.0 = rest;
        head
    }
}

fn video_track(h265: bool) -> RecordingTrack {
    let codec = if h265 {
        Codec::H265 {
            vps: Some(Bytes::from(h265::test_data::vps())),
            sps: Some(Bytes::from(h265::test_data::sps(640, 480))),
            pps: Some(Bytes::from(h265::test_data::pps())),
        }
    } else {
        Codec::H264 {
            profile_level_id: None,
            sps: Some(Bytes::from(h264::test_data::sps(320, 240))),
            pps: Some(Bytes::from(h264::test_data::pps())),
        }
    };
    RecordingTrack {
        codec,
        clock_rate: 90_000,
    }
}

fn audio_track(selector: u8) -> Option<RecordingTrack> {
    match selector {
        1 => Some(RecordingTrack {
            codec: Codec::AacLc {
                sample_rate: 16_000,
                channels: 1,
                config: Bytes::from_static(&CONFIG_16K_MONO),
            },
            clock_rate: 16_000,
        }),
        2 | 3 => Some(RecordingTrack {
            codec: Codec::Opus {
                channels: selector - 1,
            },
            clock_rate: 48_000,
        }),
        _ => None,
    }
}

/// `ticks` of the 90 kHz video timescale as the writer converts them:
/// rounded down to the nanosecond.
fn video_time(ticks: u64) -> Duration {
    Duration::from_nanos(u64::try_from(u128::from(ticks) * 1_000_000_000 / 90_000).unwrap())
}

/// Checks one fragment against its description, and the tracks' decode
/// times against where each ended (`ends`, `None` before its first).
fn check(fragment: &LiveFragment, ends: &mut [Option<u64>; 2]) {
    let bytes: Vec<u8> = fragment.bytes.iter().flatten().copied().collect();
    let mut rest = bytes.as_slice();
    let Any::Moof(moof) = Any::decode(&mut rest).unwrap() else {
        panic!("a fragment starts with its moof");
    };
    let mdat_start = bytes.len() - rest.len();
    let Any::Mdat(mdat) = Any::decode(&mut rest).unwrap() else {
        panic!("a moof and its mdat");
    };
    assert!(rest.is_empty(), "one moof and one mdat");
    let mut at = mdat_start + 8;
    let mut video = None;
    for traf in &moof.traf {
        let track = usize::try_from(traf.tfhd.track_id).unwrap() - 1;
        let tfdt = traf.tfdt.as_ref().unwrap().base_media_decode_time;
        let mut end = tfdt;
        let mut first_flags = None;
        let mut count = 0;
        for trun in &traf.trun {
            assert_eq!(usize::try_from(trun.data_offset.unwrap()).unwrap(), at);
            for entry in &trun.samples {
                at += usize::try_from(entry.size.unwrap()).unwrap();
                end += u64::from(entry.duration.unwrap());
                first_flags = first_flags.or(Some(entry.flags));
                count += 1;
            }
        }
        if track == 0 {
            assert_eq!(count, 1, "one video frame per fragment");
            video = Some((tfdt, end, first_flags.flatten() == Some(SYNC_SAMPLE)));
        }
        if let Some(previous) = ends[track] {
            assert!(tfdt >= previous, "a track's decode times never go back");
        }
        ends[track] = Some(end);
    }
    assert_eq!(
        at,
        mdat_start + 8 + mdat.data.len(),
        "the mdat holds the samples"
    );
    match video {
        Some((tfdt, end, sync)) => {
            assert_eq!(fragment.independent, sync);
            assert_eq!(fragment.decode_time, video_time(tfdt));
            assert_eq!(fragment.duration, video_time(end) - video_time(tfdt));
        }
        None => {
            assert!(!fragment.independent);
            assert_eq!(fragment.duration, Duration::ZERO);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let Some(config) = input.byte() else {
        return;
    };
    let video = video_track(config & 1 == 1);
    let audio = audio_track((config >> 1) & 0x03);
    let mut writer = LiveWriter::new();
    let init = writer.start(&video, audio.as_ref()).unwrap();
    assert!(init.mime.starts_with("video/mp4; codecs=\""));

    let base = FakeClock::from_system().now();
    let (mut at, mut ts, mut epoch) = (Duration::ZERO, 0_i64, 0_u32);
    let mut ends = [None, None];
    for _ in 0..MAX_FRAMES {
        let Some(control) = input.byte() else {
            break;
        };
        if control & 0x10 != 0 {
            let Ok(skipped) = writer.skip() else {
                // A duration a field cannot hold ends the output.
                return;
            };
            if let Some(fragment) = skipped {
                check(&fragment, &mut ends);
            }
        }
        let kind = if control & 1 == 1 && audio.is_some() {
            Kind::Audio
        } else {
            Kind::Video
        };
        let step = if control & 0x08 == 0 {
            let step = input.bytes(2);
            i64::from(i16::from_be_bytes([
                step.first().copied().unwrap_or(0),
                step.get(1).copied().unwrap_or(0),
            ]))
        } else {
            let mut step = [0; 8];
            for (to, from) in step.iter_mut().zip(input.bytes(8)) {
                *to = *from;
            }
            i64::from_be_bytes(step)
        };
        ts = ts.wrapping_add(step);
        at += Duration::from_millis(u64::from(input.byte().unwrap_or(0)));
        epoch += u32::from(control & 0x04 != 0);
        let len = usize::from(input.byte().unwrap_or(0));
        let body = input.bytes(len);
        let payload = if kind == Kind::Video {
            let mut payload = vec![0, 0, 0, 1];
            payload.extend_from_slice(body);
            payload
        } else {
            body.to_vec()
        };
        let frame = MediaFrame {
            ts: MediaTime::from_ticks(ts),
            wallclock: base + at,
            arrival: base + at,
            keyframe: kind == Kind::Audio || control & 0x02 != 0,
            discontinuity: false,
            epoch,
            payload: Bytes::from(payload),
        };
        match writer.push(kind, Arc::new(frame)) {
            Ok(LiveStep::Fragment(fragment)) => check(&fragment, &mut ends),
            Ok(LiveStep::Held | LiveStep::Dropped) => {}
            // A timestamp a field cannot hold ends the output.
            Err(_) => return,
        }
    }
});
