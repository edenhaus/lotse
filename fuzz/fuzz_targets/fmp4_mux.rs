//! `fmp4_mux`: the clip muxer never panics on an arbitrary sequence of
//! frames, and every clip it completes is a fragmented MP4 that two
//! independent readers take: mp4-atom reads every box (ISO/IEC 14496-12
//! §8.8.4 `moof`, §8.1.1 `mdat`), each run's data lies inside its
//! fragment's `mdat`, the `mdat`s hold exactly the samples, each track's
//! samples are its pushed frames, in order, as their length-prefixed
//! units (ISO/IEC 14496-15 §5.3.2; H.265 without the sets of its
//! `hvc1` entry, §8.4.1.1.2), and each track's
//! fragments start no earlier than the one before ended; the HTTP
//! source's fragmented MP4 reader takes the init segment and the
//! fragments and hands on every non-empty H.264, H.265 and AAC sample as
//! the frame it was, in decode-time order per track.
//!
//! The first input byte picks the clip: bit 0 H.265 instead of H.264,
//! bits 1 and 2 the audio (none, AAC-LC, mono or stereo Opus), bits 3 to 5
//! the fragment span (100 ms to 800 ms). The rest is frames, each a
//! control byte (bit 0 audio, bit 1 keyframe, bit 2 a new epoch, bit 3 a
//! timestamp step from eight bytes instead of two), the step, a capture
//! time step in milliseconds, a length and the payload; a video payload
//! gets a start code before it, so it has a NAL unit.
//! Run with `cargo +nightly fuzz run fmp4_mux` from the repository root.

#![no_main]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use lotse_codec::aac::test_data::CONFIG_16K_MONO;
use lotse_codec::h264::annex_b_units;
use lotse_codec::{h264, h265};
use lotse_core::clip::{ClipMuxer as _, ClipPolicy, ClipTrack};
use lotse_core::clock::{Clock as _, FakeClock};
use lotse_core::{Codec, Kind, MediaFrame, MediaTime};
use lotse_http::fmp4::Reader;
use lotse_mux::Muxer;
use mp4_atom::{Any, Decode as _};

/// The most frames one input pushes.
const MAX_FRAMES: usize = 512;

/// The HTTP reader's frame limit: above any frame an input makes.
const MAX_FRAME: usize = 1 << 20;

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

/// The video track and its codec's tracks.
fn video_track(h265: bool) -> ClipTrack {
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
    ClipTrack {
        codec,
        clock_rate: 90_000,
    }
}

fn audio_track(selector: u8) -> Option<ClipTrack> {
    match selector {
        1 => Some(ClipTrack {
            codec: Codec::AacLc {
                sample_rate: 16_000,
                channels: 1,
                config: Bytes::from_static(&CONFIG_16K_MONO),
            },
            clock_rate: 16_000,
        }),
        2 | 3 => Some(ClipTrack {
            codec: Codec::Opus {
                channels: selector - 1,
            },
            clock_rate: 48_000,
        }),
        _ => None,
    }
}

/// The units of a video frame its sample keeps: all but the H.265 sets
/// equal to the sample entry's (`out_of_band`).
fn kept<'a>(payload: &'a [u8], out_of_band: &[Vec<u8>]) -> Vec<&'a [u8]> {
    annex_b_units(payload)
        .into_iter()
        .filter(|unit| !out_of_band.iter().any(|set| set == unit))
        .collect()
}

/// A sample as the frame becomes one: video's units behind 4-byte lengths.
fn sample(kind: Kind, payload: &[u8], out_of_band: &[Vec<u8>]) -> Vec<u8> {
    if kind == Kind::Audio {
        return payload.to_vec();
    }
    let mut out = Vec::new();
    for unit in kept(payload, out_of_band) {
        out.extend(u32::try_from(unit.len()).unwrap().to_be_bytes());
        out.extend(unit);
    }
    out
}

/// The frame as the HTTP reader hands it on: video's units behind 4-byte
/// start codes.
fn unit(kind: Kind, payload: &[u8], out_of_band: &[Vec<u8>]) -> Vec<u8> {
    if kind == Kind::Audio {
        return payload.to_vec();
    }
    let mut out = Vec::new();
    for unit in kept(payload, out_of_band) {
        out.extend([0, 0, 0, 1]);
        out.extend(unit);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let Some(config) = input.byte() else {
        return;
    };
    let video = video_track(config & 1 == 1);
    let out_of_band: Vec<Vec<u8>> = match &video.codec {
        Codec::H265 { vps, sps, pps } => [vps, sps, pps]
            .into_iter()
            .flatten()
            .map(|set| set.to_vec())
            .collect(),
        _ => Vec::new(),
    };
    let audio = audio_track((config >> 1) & 0x03);
    let span = Duration::from_millis(100 * (u64::from((config >> 3) & 0x07) + 1));
    let mut muxer = Muxer::new(&ClipPolicy {
        fragment: span,
        ..ClipPolicy::default()
    });

    let mut file = Vec::new();
    for piece in muxer.start(&video, audio.as_ref()).unwrap() {
        file.extend_from_slice(&piece);
    }
    let init_len = file.len();

    let base = FakeClock::from_system().now();
    let (mut at, mut ts, mut epoch) = (Duration::ZERO, 0_i64, 0_u32);
    let mut pushed: Vec<(Kind, Vec<u8>)> = Vec::new();
    while let Some(control) = input.byte() {
        if pushed.len() == MAX_FRAMES {
            break;
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
            payload: Bytes::from(payload.clone()),
        };
        let Ok(out) = muxer.push(kind, Arc::new(frame)) else {
            // A timestamp a field cannot hold ends the clip.
            return;
        };
        for piece in out {
            file.extend_from_slice(&piece);
        }
        pushed.push((kind, payload));
    }
    for piece in muxer.finish().unwrap() {
        file.extend_from_slice(&piece);
    }

    // mp4-atom reads every box, and the runs lie in their mdat.
    let mut rest = file.as_slice();
    let mut boxes = Vec::new();
    while !rest.is_empty() {
        let start = file.len() - rest.len();
        boxes.push((start, Any::decode(&mut rest).unwrap()));
    }
    assert!(matches!(boxes.first(), Some((_, Any::Ftyp(_)))));
    assert!(matches!(boxes.get(1), Some((_, Any::Moov(_)))));
    let mut read: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
    let mut ends = [0_u64; 2];
    for pair in boxes[2..].chunks(2) {
        let [(moof_start, Any::Moof(moof)), (mdat_start, Any::Mdat(mdat))] = pair else {
            panic!("a moof and its mdat");
        };
        let header = mdat_start + 8;
        let mut at = header;
        for traf in &moof.traf {
            let track = usize::try_from(traf.tfhd.track_id).unwrap() - 1;
            let tfdt = traf.tfdt.as_ref().unwrap().base_media_decode_time;
            assert!(
                tfdt >= ends[track],
                "a fragment starts before the last ended"
            );
            let mut end = tfdt;
            for trun in &traf.trun {
                assert_eq!(
                    moof_start + usize::try_from(trun.data_offset.unwrap()).unwrap(),
                    at
                );
                for entry in &trun.entries {
                    let size = usize::try_from(entry.size.unwrap()).unwrap();
                    read[track].push(file[at..at + size].to_vec());
                    at += size;
                    end += u64::from(entry.duration.unwrap());
                }
            }
            ends[track] = end;
        }
        assert_eq!(
            at,
            header + mdat.data.len(),
            "the mdat holds exactly the samples"
        );
    }
    for (track, kind) in [Kind::Video, Kind::Audio].into_iter().enumerate() {
        let expected: Vec<Vec<u8>> = pushed
            .iter()
            .filter(|(pushed, _)| *pushed == kind)
            .map(|(_, payload)| sample(kind, payload, &out_of_band))
            .collect();
        assert_eq!(read[track], expected, "the {kind} samples are the frames");
    }

    // The HTTP source's reader takes the clip.
    let mut reader = Reader::new(&file[..init_len], MAX_FRAME).unwrap();
    let layout = reader.layout().clone();
    let mut units = Vec::new();
    reader.read_segment(&file[init_len..], &mut units).unwrap();
    for (track, kind) in [Kind::Video, Kind::Audio].into_iter().enumerate() {
        let Some(declared) = layout.tracks.get(track) else {
            continue;
        };
        if !declared.codec.is_supported() {
            continue;
        }
        let expected: Vec<Vec<u8>> = pushed
            .iter()
            .filter(|(pushed, payload)| {
                *pushed == kind && !sample(kind, payload, &out_of_band).is_empty()
            })
            .map(|(_, payload)| unit(kind, payload, &out_of_band))
            .collect();
        let got: Vec<&lotse_http::media::Unit> =
            units.iter().filter(|unit| unit.track == track).collect();
        assert!(
            got.windows(2)
                .all(|pair| pair[0].decode_time <= pair[1].decode_time)
        );
        let got: Vec<Vec<u8>> = got.iter().map(|unit| unit.payload.to_vec()).collect();
        assert_eq!(got, expected, "the reader's {kind} units are the frames");
    }
});
