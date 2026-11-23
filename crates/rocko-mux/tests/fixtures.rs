//! The muxer's fixtures, in `crates/rocko-mux/testdata/`: whole recordings
//! and a live output (init segment and fragments) made here through the public API from the
//! codec crate's test data (its hand-built parameter sets and recorded
//! AAC) and from synthetic frames (slices of a few bytes, B-frame order,
//! Opus packets of one 20 ms CELT frame).
//!
//! `the_fixtures_are_what_the_muxer_writes` holds the committed files to
//! the muxer's output; `write_fixtures` (ignored, run by hand after a
//! deliberate change) rewrites them. The `ffprobe_` tests (ignored, run by
//! `mise run interop` with the pinned ffprobe on `PATH`) have an
//! independent reader check the same files: ISO/IEC 14496-12 boxes, the
//! codecs ISO/IEC 14496-15, ISO/IEC 14496-14 and Opus in ISOBMFF name,
//! and the packets' timing and sync flags.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use mp4_atom::{Any, Decode as _};
use rocko_codec::aac::test_data::{CONFIG_16K_MONO, SINE_16K_MONO, frames};
use rocko_codec::{h264, h265};
use rocko_core::clock::{Clock as _, FakeClock};
use rocko_core::live::{LiveMuxer as _, LiveStep};
use rocko_core::recording::{RecordingMuxer as _, RecordingPolicy, RecordingTrack};
use rocko_core::{Codec, Kind, MediaFrame, MediaTime};
use rocko_mux::{LiveWriter, Muxer};
use serde_json::Value;

/// One video frame at 25 fps in 90 kHz ticks.
const FRAME: i64 = 3600;

/// What makes a fixture.
type Make = fn() -> Vec<u8>;

/// The fixtures by file name.
const FIXTURES: [(&str, Make); 5] = [
    ("h264_aac.mp4", h264_aac),
    ("h265.mp4", h265),
    ("h264_opus.mp4", h264_opus),
    ("h264_bframes.mp4", h264_bframes),
    ("live_h264_aac.mp4", live_h264_aac),
];

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

/// A frame captured `after` the recording's base instant.
struct At {
    kind: Kind,
    after: Duration,
    ts: i64,
    keyframe: bool,
    payload: Bytes,
}

/// `frames` as a track's subscription hands them on: each track's in the
/// order given (video's in decode order, whose capture times go back at
/// a B-frame), the two tracks merged by capture time, video first on a
/// tie.
fn merged(frames: Vec<At>) -> Vec<At> {
    let (mut video, mut audio): (VecDeque<At>, VecDeque<At>) = frames
        .into_iter()
        .partition(|frame| frame.kind == Kind::Video);
    let mut out = Vec::with_capacity(video.len() + audio.len());
    loop {
        let next = match (video.front(), audio.front()) {
            (Some(first), Some(other)) if other.after < first.after => audio.pop_front(),
            (Some(_), _) => video.pop_front(),
            (None, _) => audio.pop_front(),
        };
        let Some(frame) = next else {
            return out;
        };
        out.push(frame);
    }
}

/// The recording of `video`, `audio` and `frames` ([`merged`]) with the
/// default policy, as one file.
fn recording(video: &RecordingTrack, audio: Option<&RecordingTrack>, frames: Vec<At>) -> Vec<u8> {
    let base: Instant = FakeClock::from_system().now();
    let frames = merged(frames);
    let mut muxer = Muxer::new(&RecordingPolicy::default());
    let mut file = Vec::new();
    let mut write = |pieces: Vec<Bytes>| {
        for piece in pieces {
            file.extend_from_slice(&piece);
        }
    };
    write(muxer.start(video, audio).unwrap());
    for frame in frames {
        write(muxer.push(frame.kind, media(base, frame)).unwrap());
    }
    write(muxer.finish().unwrap());
    file
}

/// The frame `frame` captured at `base` plus its offset.
fn media(base: Instant, frame: At) -> Arc<MediaFrame> {
    Arc::new(MediaFrame {
        ts: MediaTime::from_ticks(frame.ts),
        wallclock: base + frame.after,
        arrival: base + frame.after,
        keyframe: frame.keyframe,
        discontinuity: false,
        epoch: 0,
        payload: frame.payload,
    })
}

/// The live output of `video`, `audio` and `frames` ([`merged`]) as one
/// file, its reader having fallen behind once, at `skip_at`: the frames
/// held then go out, and the writer leaves out the rest up to the next
/// keyframe.
fn live(
    video: &RecordingTrack,
    audio: Option<&RecordingTrack>,
    frames: Vec<At>,
    skip_at: Duration,
) -> Vec<u8> {
    let base: Instant = FakeClock::from_system().now();
    let mut writer = LiveWriter::new();
    let mut file = writer.start(video, audio).unwrap().bytes.to_vec();
    let mut skipped = false;
    for frame in merged(frames) {
        if !skipped && frame.after >= skip_at {
            skipped = true;
            for piece in writer.skip().unwrap().into_iter().flat_map(|out| out.bytes) {
                file.extend_from_slice(&piece);
            }
        }
        if let LiveStep::Fragment(fragment) = writer.push(frame.kind, media(base, frame)).unwrap() {
            for piece in fragment.bytes {
                file.extend_from_slice(&piece);
            }
        }
    }
    file
}

fn annex_b(units: &[&[u8]]) -> Bytes {
    let mut out = Vec::new();
    for unit in units {
        out.extend([0, 0, 0, 1]);
        out.extend(*unit);
    }
    Bytes::from(out)
}

fn h264_track() -> RecordingTrack {
    RecordingTrack {
        codec: Codec::H264 {
            profile_level_id: None,
            sps: Some(Bytes::from(h264::test_data::sps(320, 240))),
            pps: Some(Bytes::from(h264::test_data::pps())),
        },
        clock_rate: 90_000,
    }
}

/// `count` H.264 frames from `first_ms` on at 25 fps in decode `order`
/// (frame numbers), each captured at its presentation, a keyframe every
/// `gop` frames (with the sets before it).
fn h264_frames(order: &[u32], first_ms: u64, gop: u32) -> Vec<At> {
    order
        .iter()
        .map(|&n| {
            let keyframe = n % gop == 0;
            let tag = u8::try_from(n % 256).unwrap();
            let slice = [if keyframe { 0x65 } else { 0x41 }, 0x88, tag, 0x5a];
            let payload = if keyframe {
                annex_b(&[
                    &h264::test_data::sps(320, 240),
                    &h264::test_data::pps(),
                    &slice,
                ])
            } else {
                annex_b(&[&slice])
            };
            At {
                kind: Kind::Video,
                after: Duration::from_millis(first_ms + u64::from(n) * 40),
                ts: i64::from(n) * FRAME,
                keyframe,
                payload,
            }
        })
        .collect()
}

/// The AAC-LC track of the fixtures: 16 kHz mono.
fn aac_track() -> RecordingTrack {
    RecordingTrack {
        codec: Codec::AacLc {
            sample_rate: 16_000,
            channels: 1,
            config: Bytes::from_static(&CONFIG_16K_MONO),
        },
        clock_rate: 16_000,
    }
}

/// `count` AAC-LC frames of 64 ms from 0 ms on.
fn aac_frames(count: u32) -> Vec<At> {
    let aac = frames(SINE_16K_MONO);
    (0..count)
        .map(|j| At {
            kind: Kind::Audio,
            after: Duration::from_millis(u64::from(j) * 64),
            ts: i64::from(j) * 1024,
            keyframe: true,
            payload: Bytes::copy_from_slice(aac[usize::try_from(j).unwrap() % aac.len()]),
        })
        .collect()
}

/// A live output of H.264 for 3 s with a keyframe every second, from 16 ms
/// on, and AAC-LC at 16 kHz mono from 0 ms on, whose reader fell behind at
/// 1.5 s: the frames up to the keyframe at 2 s are left out, and the
/// output goes on from where its video ended.
fn live_h264_aac() -> Vec<u8> {
    let order: Vec<u32> = (0..75).collect();
    let mut all = h264_frames(&order, 16, 25);
    all.extend(aac_frames(47));
    live(
        &h264_track(),
        Some(&aac_track()),
        all,
        Duration::from_millis(1500),
    )
}

/// H.264 for 3 s with a keyframe every 2 s, from 16 ms on, and AAC-LC
/// at 16 kHz mono from 0 ms on: 75 access units and 47 AAC frames, the
/// first captured before the first keyframe.
fn h264_aac() -> Vec<u8> {
    let order: Vec<u32> = (0..75).collect();
    let mut all = h264_frames(&order, 16, 50);
    all.extend(aac_frames(47));
    recording(&h264_track(), Some(&aac_track()), all)
}

/// H.265 for 2 s at 25 fps with a keyframe every second.
fn h265() -> Vec<u8> {
    let frames = (0..50_u32)
        .map(|n| {
            let keyframe = n % 25 == 0;
            let tag = u8::try_from(n).unwrap();
            let slice = [if keyframe { 19 << 1 } else { 1 << 1 }, 0x01, 0xaf, tag];
            let payload = if keyframe {
                annex_b(&[
                    &h265::test_data::vps(),
                    &h265::test_data::sps(640, 480),
                    &h265::test_data::pps(),
                    &slice,
                ])
            } else {
                annex_b(&[&slice])
            };
            At {
                kind: Kind::Video,
                after: Duration::from_millis(u64::from(n) * 40),
                ts: i64::from(n) * FRAME,
                keyframe,
                payload,
            }
        })
        .collect();
    let video = RecordingTrack {
        codec: Codec::H265 {
            vps: Some(Bytes::from(h265::test_data::vps())),
            sps: Some(Bytes::from(h265::test_data::sps(640, 480))),
            pps: Some(Bytes::from(h265::test_data::pps())),
        },
        clock_rate: 90_000,
    };
    recording(&video, None, frames)
}

/// H.264 for 1 s and mono Opus in 20 ms packets.
fn h264_opus() -> Vec<u8> {
    let order: Vec<u32> = (0..25).collect();
    let mut frames = h264_frames(&order, 0, 25);
    for j in 0..50_u32 {
        frames.push(At {
            kind: Kind::Audio,
            after: Duration::from_millis(u64::from(j) * 20),
            ts: i64::from(j) * 960,
            keyframe: true,
            // RFC 6716 §3.1: config 31 (CELT, fullband, 20 ms), mono, code 0.
            payload: Bytes::from(vec![0xf8, u8::try_from(j).unwrap(), 0xfe]),
        });
    }
    let audio = RecordingTrack {
        codec: Codec::Opus { channels: 1 },
        clock_rate: 48_000,
    };
    recording(&h264_track(), Some(&audio), frames)
}

/// The frame numbers of [`h264_bframes`] in decode order: two closed
/// GOPs of 12 frames, I0 P3 B1 B2 P6 B4 B5 P9 B7 B8 P11 B10.
fn bframes_order() -> Vec<u32> {
    let gop = [0, 3, 1, 2, 6, 4, 5, 9, 7, 8, 11, 10];
    [0, 12]
        .iter()
        .flat_map(|start| gop.iter().map(move |n| start + n))
        .collect()
}

/// H.264 with B-frames, pushed in decode order ([`bframes_order`]).
fn h264_bframes() -> Vec<u8> {
    recording(&h264_track(), None, h264_frames(&bframes_order(), 0, 12))
}

#[test]
fn the_fixtures_are_what_the_muxer_writes() {
    for (name, make) in FIXTURES {
        let committed = std::fs::read(path(name)).unwrap();
        assert!(
            make() == committed,
            "{name} differs: rerun write_fixtures and check it"
        );
    }
}

#[test]
fn iso14496_12_8_8_8_1_the_b_frame_fixture_keeps_decode_order_with_negative_composition_offsets() {
    let file = std::fs::read(path("h264_bframes.mp4")).unwrap();
    let mut rest = file.as_slice();
    let (mut presented, mut negative) = (Vec::new(), 0);
    while !rest.is_empty() {
        let Any::Moof(moof) = Any::decode(&mut rest).unwrap() else {
            continue;
        };
        for traf in moof.traf {
            let mut dts = i64::try_from(traf.tfdt.unwrap().base_media_decode_time).unwrap();
            for entry in traf.trun.iter().flat_map(|trun| &trun.samples) {
                let cts = entry.cts.unwrap_or(0);
                negative += usize::from(cts < 0);
                presented.push(dts + cts);
                dts += i64::from(entry.duration.unwrap());
            }
        }
    }
    let expected: Vec<i64> = bframes_order()
        .into_iter()
        .map(|n| i64::from(n) * FRAME)
        .collect();
    assert_eq!(presented, expected);
    assert!(negative > 0, "no negative composition offset");
}

#[test]
#[ignore = "rewrites the committed fixtures: run by hand after a deliberate change to the muxer"]
fn write_fixtures() {
    for (name, make) in FIXTURES {
        std::fs::write(path(name), make()).unwrap();
    }
}

/// ffprobe's streams and packets of a fixture.
#[expect(
    clippy::disallowed_methods,
    reason = "a third-party reader of the test fixtures, never the daemon's code"
)]
fn ffprobe(name: &str) -> Value {
    let output = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_streams",
            "-show_packets",
            "-of",
            "json",
        ])
        .arg(path(name))
        .output()
        .expect("ffprobe is not on PATH: `mise install`, then run through mise (mise run interop)");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// The packets of stream `index`: (pts, dts, keyframe), in file order.
fn packets(probe: &Value, index: u64) -> Vec<(i64, i64, bool)> {
    probe["packets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|packet| packet["stream_index"].as_u64() == Some(index))
        .map(|packet| {
            (
                packet["pts"].as_i64().unwrap(),
                packet["dts"].as_i64().unwrap(),
                packet["flags"].as_str().unwrap().starts_with('K'),
            )
        })
        .collect()
}

fn stream(probe: &Value, index: usize) -> &Value {
    &probe["streams"][index]
}

#[test]
#[ignore = "needs ffprobe on PATH: mise run interop"]
fn ffprobe_iso14496_15_reads_h264_with_aac_lc() {
    let probe = ffprobe("h264_aac.mp4");
    assert_eq!(probe["streams"].as_array().unwrap().len(), 2);
    let video = stream(&probe, 0);
    assert_eq!(video["codec_name"], "h264");
    assert_eq!(video["codec_tag_string"], "avc1");
    assert_eq!(
        (video["width"].as_u64(), video["height"].as_u64()),
        (Some(320), Some(240))
    );
    let audio = stream(&probe, 1);
    assert_eq!(audio["codec_name"], "aac");
    assert_eq!(audio["profile"], "LC");
    assert_eq!(audio["sample_rate"], "16000");
    assert_eq!(audio["channels"], 1);
    let video = packets(&probe, 0);
    assert_eq!(video.len(), 75);
    // 16 ms after the first audio frame, the recording's origin, at 90 kHz.
    assert_eq!(video[0], (1440, 1440, true));
    let keyframes: Vec<usize> = (0..video.len()).filter(|&i| video[i].2).collect();
    assert_eq!(keyframes, [0, 50]);
    assert!(video.windows(2).all(|pair| pair[1].1 - pair[0].1 == FRAME));
    let audio = packets(&probe, 1);
    assert_eq!(audio.len(), 47);
    assert_eq!(audio[0].1, 0);
    assert!(audio.windows(2).all(|pair| pair[1].1 - pair[0].1 == 1024));
}

#[test]
#[ignore = "needs ffprobe on PATH: mise run interop"]
fn ffprobe_iso14496_15_8_4_1_reads_h265_as_hvc1() {
    let probe = ffprobe("h265.mp4");
    let video = stream(&probe, 0);
    assert_eq!(video["codec_name"], "hevc");
    assert_eq!(video["codec_tag_string"], "hvc1");
    assert_eq!(
        (video["width"].as_u64(), video["height"].as_u64()),
        (Some(640), Some(480))
    );
    let packets = packets(&probe, 0);
    assert_eq!(packets.len(), 50);
    let keyframes: Vec<usize> = (0..packets.len()).filter(|&i| packets[i].2).collect();
    assert_eq!(keyframes, [0, 25]);
}

#[test]
#[ignore = "needs ffprobe on PATH: mise run interop"]
fn ffprobe_opus_isobmff_reads_h264_with_opus() {
    let probe = ffprobe("h264_opus.mp4");
    let audio = stream(&probe, 1);
    assert_eq!(audio["codec_name"], "opus");
    assert_eq!(audio["sample_rate"], "48000");
    assert_eq!(audio["channels"], 1);
    let audio = packets(&probe, 1);
    assert_eq!(audio.len(), 50);
    assert!(audio.windows(2).all(|pair| pair[1].1 - pair[0].1 == 960));
    assert_eq!(packets(&probe, 0).len(), 25);
}

#[test]
#[ignore = "needs ffprobe on PATH: mise run interop"]
fn ffprobe_iso14496_12_8_8_8_1_reads_negative_composition_offsets_in_presentation_order() {
    let probe = ffprobe("h264_bframes.mp4");
    let packets = packets(&probe, 0);
    assert_eq!(packets.len(), 24);
    assert!(
        packets.windows(2).all(|pair| pair[0].1 < pair[1].1),
        "decode times increase"
    );
    let keyframes: Vec<usize> = (0..packets.len()).filter(|&i| packets[i].2).collect();
    assert_eq!(keyframes, [0, 12]);
    // The packets in decode order, each presented at its frame number.
    // Counted from the first packet: ffprobe 6.1.1 shifts every PTS by the
    // largest negative offset (observed 2026-10-24).
    let first = packets[0];
    let presented: Vec<i64> = packets.iter().map(|packet| packet.0 - first.0).collect();
    let expected: Vec<i64> = bframes_order()
        .into_iter()
        .map(|n| i64::from(n) * FRAME)
        .collect();
    assert_eq!(presented, expected);
    // Negative composition offsets: PTS - DTS below the first packet's.
    assert!(
        packets
            .iter()
            .any(|packet| packet.0 - packet.1 < first.0 - first.1),
        "no negative composition offset"
    );
}

#[test]
#[ignore = "needs ffprobe on PATH: mise run interop"]
fn ffprobe_iso14496_12_8_8_reads_a_live_output_s_one_frame_fragments_without_a_hole() {
    let probe = ffprobe("live_h264_aac.mp4");
    let video = stream(&probe, 0);
    assert_eq!(video["codec_name"], "h264");
    assert_eq!(stream(&probe, 1)["codec_name"], "aac");
    let video = packets(&probe, 0);
    // The 38 frames before the reader fell behind at 1.5 s (the first at
    // 16 ms, the last at 1496 ms, held then and sent with the skip), then
    // the 25 from the keyframe at 2016 ms on but the last, still held.
    assert_eq!(video.len(), 38 + 24);
    assert_eq!(video[0], (0, 0, true), "the first keyframe is media time 0");
    let keyframes: Vec<usize> = (0..video.len()).filter(|&i| video[i].2).collect();
    assert_eq!(keyframes, [0, 25, 38]);
    assert!(
        video.windows(2).all(|pair| pair[1].1 - pair[0].1 == FRAME),
        "the decode times run on through the hole"
    );
    let file = std::fs::read(path("live_h264_aac.mp4")).unwrap();
    let mut rest = file.as_slice();
    let mut video_per_fragment = Vec::new();
    while !rest.is_empty() {
        if let Any::Moof(moof) = Any::decode(&mut rest).unwrap() {
            let video = moof.traf.iter().find(|traf| traf.tfhd.track_id == 1);
            video_per_fragment.push(video.map_or(0, |traf| traf.trun[0].samples.len()));
        }
    }
    assert!(
        video_per_fragment.iter().all(|&count| count <= 1),
        "one video frame per fragment: {video_per_fragment:?}"
    );
}
