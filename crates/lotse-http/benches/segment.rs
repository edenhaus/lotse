//! Microbenchmarks of the HTTP source's media path on recorded segments:
//! the MPEG-TS demultiplexer (ISO/IEC 13818-1) and the fragmented MP4
//! reader (ISO/IEC 14496-12, AVC samples to Annex B per ISO/IEC 14496-15),
//! each over one whole segment, and an MPEG-TS segment through to the RTP
//! payloads of its video (RFC 6184), as the source hands it to its tracks.
//!
//! The segments are this crate's test recordings (`testdata/`, made by
//! ffmpeg, see `src/ts/test_data.rs` and `src/fmp4/test_data.rs`): one
//! second of 160x90 video, so the container's share of the work is larger
//! than in a camera's stream. Run with `mise run bench`; divan's harness,
//! not libtest's.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    reason = "benchmark code, held to the tests' rules: a failed setup is a panic"
)]

use divan::Bencher;
use divan::counter::BytesCount;
use lotse_codec::h264;
use lotse_core::Codec;
use lotse_core::track::DEFAULT_MAX_FRAME_BYTES;
use lotse_http::fmp4::Reader;
use lotse_http::media::Event;
use lotse_http::ts::Demuxer;

/// H.264 and AAC-LC in MPEG-TS.
const TS_H264_AAC: &[u8] = include_bytes!("../testdata/h264_aac.m2t");

/// H.265 in MPEG-TS.
const TS_H265: &[u8] = include_bytes!("../testdata/h265_v1.m2t");

/// The init segment of H.264 and AAC-LC in fragmented MP4.
const FMP4_INIT: &[u8] = include_bytes!("../testdata/h264_aac_init.mp4");

/// The first media segment of [`FMP4_INIT`]'s stream.
const FMP4_SEGMENT: &[u8] = include_bytes!("../testdata/h264_aac_0.m4s");

/// Which MPEG-TS recording a benchmark reads.
#[derive(Debug, Clone, Copy)]
enum Recording {
    /// [`TS_H264_AAC`].
    H264Aac,
    /// [`TS_H265`].
    H265,
}

impl Recording {
    /// The recording's bytes.
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::H264Aac => TS_H264_AAC,
            Self::H265 => TS_H265,
        }
    }
}

/// The MPEG-TS demultiplexer on one whole segment, from a new
/// demultiplexer as at the start of a stream: PAT, PMT, PES packets and
/// the units they carry.
#[divan::bench(args = [Recording::H264Aac, Recording::H265])]
fn ts_demux(bencher: Bencher<'_, '_>, recording: Recording) {
    let segment = recording.bytes();
    let mut events = Vec::new();
    bencher
        .counter(BytesCount::new(segment.len()))
        .with_inputs(|| Demuxer::new(DEFAULT_MAX_FRAME_BYTES))
        .bench_local_refs(|demuxer| {
            events.clear();
            demuxer.push(segment, &mut events);
            demuxer.flush(&mut events);
            events.len()
        });
    assert!(events.iter().any(|event| matches!(event, Event::Unit(_))));
}

/// The fragmented MP4 reader on one media segment, its init segment read
/// beforehand: the movie fragment's boxes, then each sample, video
/// rewritten from length-prefixed NAL units to Annex B.
#[divan::bench]
fn fmp4_segment(bencher: Bencher<'_, '_>) {
    let mut units = Vec::new();
    bencher
        .counter(BytesCount::new(FMP4_SEGMENT.len()))
        .with_inputs(|| Reader::new(FMP4_INIT, DEFAULT_MAX_FRAME_BYTES).unwrap())
        .bench_local_refs(|reader| {
            units.clear();
            reader.read_segment(FMP4_SEGMENT, &mut units).unwrap();
            units.len()
        });
    assert!(!units.is_empty(), "the segment's samples come out");
}

/// One MPEG-TS segment through to RTP: demultiplexed, and each H.264
/// access unit normalized into the live path's payloads and the side
/// branch's access unit.
#[divan::bench]
fn ts_to_rtp(bencher: Bencher<'_, '_>) {
    let mut events = Vec::new();
    let mut packets = Vec::new();
    let mut units = Vec::new();
    bencher
        .counter(BytesCount::new(TS_H264_AAC.len()))
        .with_inputs(|| {
            let demuxer = Demuxer::new(DEFAULT_MAX_FRAME_BYTES);
            let normalizer = h264::FramedNormalizer::new(
                h264::DEFAULT_MAX_PAYLOAD,
                DEFAULT_MAX_FRAME_BYTES,
                h264::ParameterSets::default(),
            );
            (demuxer, normalizer)
        })
        .bench_local_refs(|(demuxer, normalizer)| {
            events.clear();
            packets.clear();
            units.clear();
            demuxer.push(TS_H264_AAC, &mut events);
            demuxer.flush(&mut events);
            let mut video = None;
            for event in &events {
                match event {
                    Event::Layout(layout) => {
                        video = layout
                            .tracks
                            .iter()
                            .position(|track| matches!(track.codec, Codec::H264 { .. }));
                    }
                    Event::Unit(unit) if Some(unit.track) == video => {
                        // The RTP timestamp: the track's clock, wrapped to
                        // 32 bits (RFC 3550 §5.1).
                        let ts = u32::try_from(unit.ts & 0xffff_ffff).unwrap();
                        normalizer.push(ts, &unit.payload, &mut packets, &mut units);
                    }
                    Event::Unit(_) => {}
                }
            }
            packets.len()
        });
    assert!(
        !packets.is_empty() && !units.is_empty(),
        "the video goes out"
    );
}

/// Runs the benchmarks of this file with divan's command line (`--help`).
fn main() {
    divan::main();
}
