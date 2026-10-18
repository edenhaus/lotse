//! Microbenchmarks of the video normalizers on a camera's RTP packets: the
//! live path's packet layer (H.264 RFC 6184 §5.6 to §5.8, H.265 RFC 7798
//! §4.4), which every packet of every camera passes, and the side branch's
//! depacketizer (H.264 to ISO/IEC 14496-10 Annex B).
//!
//! The access units are hand-built from this crate's `test-util`
//! parameter sets and a slice of filler bytes: the normalizers copy and
//! split bytes and read only NAL unit headers and parameter sets, so their
//! cost follows the size of a frame, not its picture. Run with
//! `mise run bench`; divan's harness, not libtest's.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    reason = "benchmark code, held to the tests' rules: a failed setup is a panic"
)]

use bytes::Bytes;
use divan::Bencher;
use divan::counter::BytesCount;
use lotse_codec::{h264, h265};
use lotse_core::track::DEFAULT_MAX_FRAME_BYTES;

/// The payload size a camera's packets are cut to: an Ethernet MTU less
/// the IP, UDP and RTP headers and some slack, so the packet layer cuts
/// each FU-A again to its smaller target ([`h264::DEFAULT_MAX_PAYLOAD`]).
const CAMERA_PAYLOAD: usize = 1_400;

/// One timestamp step of a 30 frames/s track on the 90 kHz clock.
const TS_STEP: u32 = 3_000;

/// The slice of a delta frame, in bytes: of the order a 1080p camera at a
/// few Mbit/s sends.
const DELTA_BYTES: usize = 16 * 1024;

/// The slice of a keyframe, in bytes, the same camera's IDR picture.
const KEY_BYTES: usize = 128 * 1024;

/// The filler a slice is made of: never zero, so it holds no start code
/// (ISO/IEC 14496-10 Annex B) and needs no emulation prevention.
const FILL: u8 = 0xab;

/// Which access unit a benchmark feeds.
#[derive(Debug, Clone, Copy)]
enum Frame {
    /// One non-IDR slice.
    Delta,
    /// The parameter sets and one IDR slice: what a viewer joins on.
    Key,
}

/// Both access units, the arguments of every benchmark.
const FRAMES: [Frame; 2] = [Frame::Delta, Frame::Key];

/// An H.264 access unit in Annex B form.
fn h264_access_unit(frame: Frame) -> Vec<u8> {
    let mut au = Vec::new();
    match frame {
        Frame::Delta => {
            // nal_ref_idc 2, type 1: a coded slice of a non-IDR picture.
            h264::nal::annex_b_append(&mut au, &unit(0x40 | h264::nal::NAL_SLICE, DELTA_BYTES));
        }
        Frame::Key => {
            h264::nal::annex_b_append(&mut au, &h264::test_data::sps(1920, 1088));
            h264::nal::annex_b_append(&mut au, &h264::test_data::pps());
            h264::nal::annex_b_append(&mut au, &unit(0x60 | h264::nal::NAL_IDR, KEY_BYTES));
        }
    }
    au
}

/// An H.265 access unit in Annex B form.
fn h265_access_unit(frame: Frame) -> Vec<u8> {
    let mut au = Vec::new();
    match frame {
        Frame::Delta => {
            // TRAIL_R, type 1 (ITU-T H.265 Table 7-1).
            h264::nal::annex_b_append(&mut au, &h265::test_data::unit(1, &vec![FILL; DELTA_BYTES]));
        }
        Frame::Key => {
            h264::nal::annex_b_append(&mut au, &h265::test_data::vps());
            h264::nal::annex_b_append(&mut au, &h265::test_data::sps(1920, 1080));
            h264::nal::annex_b_append(&mut au, &h265::test_data::pps());
            let idr = h265::test_data::unit(h265::nal::IDR_W_RADL, &vec![FILL; KEY_BYTES]);
            h264::nal::annex_b_append(&mut au, &idr);
        }
    }
    au
}

/// An H.264 NAL unit: `header`, then `len` bytes of filler.
fn unit(header: u8, len: usize) -> Vec<u8> {
    std::iter::once(header)
        .chain(std::iter::repeat_n(FILL, len))
        .collect()
}

/// The H.264 packet layer on one access unit cut as a camera cuts it:
/// FU-A fragments cut again to the target, the parameter sets ahead of an
/// IDR (RFC 6184 §5.8).
#[divan::bench(args = FRAMES)]
fn h264_packets(bencher: Bencher<'_, '_>, frame: Frame) {
    let au = h264_access_unit(frame);
    let packets = h264::packetize(&au, CAMERA_PAYLOAD);
    let mut normalizer =
        h264::PacketNormalizer::new(h264::DEFAULT_MAX_PAYLOAD, h264::ParameterSets::default());
    let mut out = Vec::new();
    let mut ts = 0_u32;
    // One access unit's packets, the marker bit on the last (RFC 6184 §5.1).
    let mut normalize =
        |normalizer: &mut h264::PacketNormalizer, packets: &[Bytes], out: &mut _| {
            ts = ts.wrapping_add(TS_STEP);
            for (i, packet) in packets.iter().enumerate() {
                let marker = i + 1 == packets.len();
                normalizer.normalize(ts, marker, packet, out).unwrap();
            }
        };
    // A keyframe first, as a stream starts, so delta frames go out.
    let key = h264::packetize(&h264_access_unit(Frame::Key), CAMERA_PAYLOAD);
    normalize(&mut normalizer, &key, &mut out);
    bencher.counter(BytesCount::new(au.len())).bench_local(|| {
        out.clear();
        normalize(&mut normalizer, &packets, &mut out);
        out.len()
    });
    // What was measured is the access unit going out, not a refusal.
    assert!(out.last().is_some_and(|packet| packet.marker));
    assert_eq!(normalizer.stats().violations, 0);
}

/// The H.264 depacketizer of the side branch on the same packets: one
/// Annex B access unit out (RFC 6184 §5.8, ISO/IEC 14496-10 Annex B).
#[divan::bench(args = FRAMES)]
fn h264_depacketize(bencher: Bencher<'_, '_>, frame: Frame) {
    let au = h264_access_unit(frame);
    let packets = h264::packetize(&au, CAMERA_PAYLOAD);
    let mut depacketizer =
        h264::Depacketizer::new(DEFAULT_MAX_FRAME_BYTES, h264::ParameterSets::default());
    let mut units = Vec::new();
    let mut seq = 0_u16;
    let mut ts = 0_u32;
    let mut push = |depacketizer: &mut h264::Depacketizer, packets: &[Bytes], units: &mut _| {
        ts = ts.wrapping_add(TS_STEP);
        for (i, packet) in packets.iter().enumerate() {
            seq = seq.wrapping_add(1);
            let marker = i + 1 == packets.len();
            depacketizer.push(seq, ts, marker, packet, units).unwrap();
        }
    };
    let key = h264::packetize(&h264_access_unit(Frame::Key), CAMERA_PAYLOAD);
    push(&mut depacketizer, &key, &mut units);
    bencher.counter(BytesCount::new(au.len())).bench_local(|| {
        units.clear();
        push(&mut depacketizer, &packets, &mut units);
        units.len()
    });
    assert_eq!(units.len(), 1, "the access unit comes out");
}

/// The H.265 packet layer on one access unit cut as a camera cuts it:
/// fragmentation units cut again to the target, the parameter sets ahead
/// of an IRAP picture (RFC 7798 §4.4.3).
#[divan::bench(args = FRAMES)]
fn h265_packets(bencher: Bencher<'_, '_>, frame: Frame) {
    let au = h265_access_unit(frame);
    let packets = h265::packetize(&au, CAMERA_PAYLOAD);
    let mut normalizer =
        h265::PacketNormalizer::new(h264::DEFAULT_MAX_PAYLOAD, h265::ParameterSets::default());
    let mut out = Vec::new();
    let mut ts = 0_u32;
    let mut normalize =
        |normalizer: &mut h265::PacketNormalizer, packets: &[Bytes], out: &mut _| {
            ts = ts.wrapping_add(TS_STEP);
            for (i, packet) in packets.iter().enumerate() {
                let marker = i + 1 == packets.len();
                normalizer.normalize(ts, marker, packet, out).unwrap();
            }
        };
    let key = h265::packetize(&h265_access_unit(Frame::Key), CAMERA_PAYLOAD);
    normalize(&mut normalizer, &key, &mut out);
    bencher.counter(BytesCount::new(au.len())).bench_local(|| {
        out.clear();
        normalize(&mut normalizer, &packets, &mut out);
        out.len()
    });
    // What was measured is the access unit going out, not a refusal.
    assert!(out.last().is_some_and(|packet| packet.marker));
    assert_eq!(normalizer.stats().violations, 0);
}

/// Runs the benchmarks of this file with divan's command line (`--help`).
fn main() {
    divan::main();
}
