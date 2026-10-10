//! `fmp4_segment`: the fragmented MP4 reader never panics, never hangs
//! and never allocates without bound on an arbitrary init segment and
//! media segment; reads the same segment the same way again; hands on
//! units in decode-time order, indexed into its layout, of a track it
//! reads, within the frame limit; and its video units go through the
//! framed normalizer of their codec, seeded with the init segment's
//! parameter sets as the publisher seeds it.
//!
//! The first input byte picks the init segment: one of the recorded
//! streams' (`crates/lotse-http/testdata/`, ISO/IEC 14496-12 §8.2.1), or
//! one from the input, whose first two bytes give its length. Its next
//! bits pick the media segment: the rest of the input, or the recorded
//! segment of the stream with the rest written over it at the offset the
//! rest's first two bytes give, so the fuzzer changes boxes it would
//! rarely build (§8.8.4: `moof`, `traf`, `tfhd`, `tfdt`, `trun`, `mdat`).
//! Run with `cargo +nightly fuzz run fmp4_segment` from the repository
//! root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::{h264, h265};
use lotse_core::Codec;
use lotse_http::fmp4::Reader;
use lotse_http::media::Layout;

/// The frame limit: small, so the limit is reached.
const MAX_FRAME: usize = 4096;

/// The recorded streams: init segment and a media segment.
const STREAMS: [(&[u8], &[u8]); 6] = [
    (
        include_bytes!("../../crates/lotse-http/testdata/h264_aac_init.mp4"),
        include_bytes!("../../crates/lotse-http/testdata/h264_aac_0.m4s"),
    ),
    (
        include_bytes!("../../crates/lotse-http/testdata/h265_init.mp4"),
        include_bytes!("../../crates/lotse-http/testdata/h265_0.m4s"),
    ),
    (
        include_bytes!("../../crates/lotse-http/testdata/h264_bframes_init.mp4"),
        include_bytes!("../../crates/lotse-http/testdata/h264_bframes_0.m4s"),
    ),
    (
        include_bytes!("../../crates/lotse-http/testdata/split_video_init.mp4"),
        include_bytes!("../../crates/lotse-http/testdata/split_video_0.m4s"),
    ),
    (
        include_bytes!("../../crates/lotse-http/testdata/split_audio_init.mp4"),
        include_bytes!("../../crates/lotse-http/testdata/split_audio_0.m4s"),
    ),
    (
        include_bytes!("../../crates/lotse-http/testdata/opus_init.mp4"),
        include_bytes!("../../crates/lotse-http/testdata/h264_aac_1.m4s"),
    ),
];

/// The normalizer of one track, seeded as the publisher seeds it.
enum Normalizer {
    H264(h264::FramedNormalizer),
    H265(h265::FramedNormalizer),
    None,
}

fn normalizers(layout: &Layout) -> Vec<Normalizer> {
    layout
        .tracks
        .iter()
        .map(|track| match &track.codec {
            Codec::H264 { sps, pps, .. } => Normalizer::H264(h264::FramedNormalizer::new(
                1_200,
                MAX_FRAME,
                h264::ParameterSets {
                    sps: sps.clone(),
                    pps: pps.clone(),
                },
            )),
            Codec::H265 { vps, sps, pps } => Normalizer::H265(h265::FramedNormalizer::new(
                1_200,
                MAX_FRAME,
                h265::ParameterSets {
                    vps: vps.clone(),
                    sps: sps.clone(),
                    pps: pps.clone(),
                },
            )),
            _ => Normalizer::None,
        })
        .collect()
}

/// The two bytes at the head of `data` as a number, and the rest.
fn length(data: &[u8]) -> (usize, &[u8]) {
    match data {
        [a, b, rest @ ..] => (usize::from(u16::from_be_bytes([*a, *b])), rest),
        _ => (0, &[]),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let which = usize::from(selector & 0x07);
    let (init, rest): (&[u8], &[u8]) = match STREAMS.get(which) {
        Some((init, _)) => (init, rest),
        None => {
            let (len, rest) = length(rest);
            rest.split_at(len.min(rest.len()))
        }
    };
    let recorded = STREAMS[which % STREAMS.len()].1;
    let segment = if selector & 0x08 == 0 {
        rest.to_vec()
    } else {
        let (at, patch) = length(rest);
        let mut segment = recorded.to_vec();
        let at = at.min(segment.len());
        let end = (at + patch.len()).min(segment.len());
        segment[at..end].copy_from_slice(&patch[..end - at]);
        segment
    };

    let Ok(mut reader) = Reader::new(init, MAX_FRAME) else {
        return;
    };
    let layout = reader.layout().clone();
    let mut units = Vec::new();
    let first = reader.read_segment(&segment, &mut units);
    let mut again = Vec::new();
    let second = reader.read_segment(&segment, &mut again);
    assert_eq!(first, second, "the same segment read otherwise");
    assert_eq!(units, again, "the same segment read otherwise");
    if first.is_err() {
        assert!(units.is_empty());
        return;
    }
    assert!(
        units
            .windows(2)
            .all(|pair| pair[0].decode_time <= pair[1].decode_time)
    );
    let mut normalizer = normalizers(&layout);
    let mut packets = Vec::new();
    let mut h264_units = Vec::new();
    let mut h265_units = Vec::new();
    for unit in &units {
        assert!(unit.track < layout.tracks.len());
        assert!(layout.tracks[unit.track].codec.is_supported());
        assert!(!unit.payload.is_empty());
        let ts = unit.ts as u32;
        match &mut normalizer[unit.track] {
            Normalizer::H264(n) => n.push(ts, &unit.payload, &mut packets, &mut h264_units),
            Normalizer::H265(n) => n.push(ts, &unit.payload, &mut packets, &mut h265_units),
            Normalizer::None => assert!(unit.payload.len() <= MAX_FRAME),
        }
    }
});
