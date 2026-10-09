//! The live path's H.264 and H.265 packets against the rules Chrome's
//! receiver enforces, which the headless `str0m` viewer does not
//! (`lotse_testing::libwebrtc`, libwebrtc as read on 2026-10-05).
//! The writer cuts these packets through unchanged, under its own
//! sequence numbers.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use bytes::Bytes;
use lotse_codec::h264;
use lotse_codec::h264::{DEFAULT_MAX_PAYLOAD, NormalizedPacket};
use lotse_codec::h265::test_data::{pps, sps, vps};
use lotse_codec::h265::{PacketNormalizer, ParameterSets, nal};
use lotse_testing::libwebrtc::{BUFFER_SIZE, H264Receiver, H265Receiver, PACKET_BUFFER_MAX_SIZE};

/// The fragment size of the camera: a 1400-byte MTU.
const CAMERA_MTU: usize = 1_400;

/// One coded slice segment of `unit_type` of `len` bytes.
fn segment(unit_type: u8, len: usize, seed: usize) -> Vec<u8> {
    [unit_type << 1, 0x01]
        .into_iter()
        .chain((0..len).map(|i| u8::try_from((i + seed) % 251).unwrap()))
        .collect()
}

/// The camera's packets of one picture: an AUD, on a keyframe its
/// parameter sets, a prefix SEI, then `segments` slice segments of
/// `segment_len` bytes in fragmentation units at the camera's MTU.
fn picture(keyframe: bool, segments: usize, segment_len: usize) -> Vec<Vec<u8>> {
    let mut packets = vec![vec![nal::AUD_NUT << 1, 0x01, 0x50]];
    if keyframe {
        packets.extend([vps(), sps(2160, 7680), pps()]);
    }
    packets.push(vec![nal::PREFIX_SEI_NUT << 1, 0x01, 0x05, 0x01, 0xaa, 0x80]);
    let unit_type = if keyframe { nal::IDR_W_RADL } else { 1 };
    for s in 0..segments {
        let unit = segment(unit_type, segment_len, s);
        packets.extend(nal::fragment(&unit, CAMERA_MTU).iter().map(|p| p.to_vec()));
    }
    packets
}

#[test]
fn libwebrtc_assembles_every_picture_of_a_duo_sized_stream_from_the_live_path() {
    // The Reolink Duo 3's main stream at 20 fps: a 1.6 MB IDR picture in
    // four slice segments every second, delta pictures of 60 kB between.
    // Cut fragment by fragment, the IDR's 1150 fragments made 2300
    // packets, and Chrome never assembles a frame of 2048 or more.
    let mut normalizer = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
    let mut chrome = H265Receiver::new();
    let mut seq = 0_u16;
    let mut keyframe_packets = 0;
    for index in 0..40_u32 {
        let keyframe = index % 20 == 0;
        let packets = if keyframe {
            picture(true, 4, 400_000)
        } else {
            picture(false, 4, 15_000)
        };
        let ts = 4_500 * index;
        let last = packets.len() - 1;
        let mut out: Vec<NormalizedPacket> = Vec::new();
        for (i, packet) in packets.iter().enumerate() {
            normalizer
                .normalize(ts, i == last, &Bytes::copy_from_slice(packet), &mut out)
                .unwrap();
        }
        if keyframe {
            assert!(packets.len() > 1_150, "{} camera packets", packets.len());
            keyframe_packets = out.len();
        }
        for packet in &out {
            chrome.insert(seq, ts, packet.marker, &packet.payload);
            seq = seq.wrapping_add(1);
        }
    }
    assert!(keyframe_packets < BUFFER_SIZE, "{keyframe_packets} packets");
    let frames = chrome.frames();
    assert_eq!(frames.len(), 40, "{} stashed", chrome.stashed());
    assert!(frames.iter().step_by(20).all(|f| f.keyframe));
    assert_eq!(frames.iter().filter(|f| f.keyframe).count(), 2);
}

/// One H.264 slice of `unit_type` of `len` bytes, the first of its
/// picture (`first_mb_in_slice` 0) or not.
fn h264_slice(unit_type: u8, len: usize, first: bool, seed: usize) -> Vec<u8> {
    [0x60 | unit_type, if first { 0x88 } else { 0x08 }]
        .into_iter()
        .chain((0..len).map(|i| u8::try_from((i + seed) % 251).unwrap()))
        .collect()
}

/// An H.264 camera's packets of one picture: an AUD, on a keyframe its
/// SPS and PPS, then `slices` slices of `slice_len` bytes in FU-A
/// fragments at the camera's MTU.
fn h264_picture(keyframe: bool, slices: usize, slice_len: usize) -> Vec<Vec<u8>> {
    let mut packets = vec![vec![h264::nal::NAL_AUD, 0xf0]];
    if keyframe {
        packets.extend([h264::test_data::sps(4608, 3456), h264::test_data::pps()]);
    }
    let unit_type = if keyframe {
        h264::nal::NAL_IDR
    } else {
        h264::nal::NAL_SLICE
    };
    for s in 0..slices {
        let unit = h264_slice(unit_type, slice_len, s == 0, s);
        packets.extend(
            h264::nal::fragment(&unit, CAMERA_MTU)
                .iter()
                .map(|p| p.to_vec()),
        );
    }
    packets
}

#[test]
fn libwebrtc_assembles_every_picture_of_a_large_h264_stream_from_the_live_path() {
    // A 16 MP H.264 camera at 20 fps: a 2 MB IDR picture in four slices
    // every second, delta pictures of 60 kB between. Cut fragment by
    // fragment, its 1430 fragments made 2860 packets, past the 2048 of
    // Chrome's packet buffer; filled, about 1810.
    let mut normalizer =
        h264::PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, h264::ParameterSets::default());
    let mut chrome = H264Receiver::new();
    let mut seq = 0_u16;
    let mut keyframe_packets = 0;
    for index in 0..40_u32 {
        let keyframe = index % 20 == 0;
        let packets = if keyframe {
            h264_picture(true, 4, 500_000)
        } else {
            h264_picture(false, 4, 15_000)
        };
        let ts = 4_500 * index;
        let last = packets.len() - 1;
        let mut out: Vec<NormalizedPacket> = Vec::new();
        for (i, packet) in packets.iter().enumerate() {
            normalizer
                .normalize(ts, i == last, &Bytes::copy_from_slice(packet), &mut out)
                .unwrap();
        }
        if keyframe {
            assert!(packets.len() > 1_430, "{} camera packets", packets.len());
            keyframe_packets = out.len();
        }
        for packet in &out {
            chrome.insert(seq, ts, packet.marker, &packet.payload);
            seq = seq.wrapping_add(1);
        }
    }
    assert!(
        keyframe_packets < PACKET_BUFFER_MAX_SIZE,
        "{keyframe_packets} packets"
    );
    let frames = chrome.frames();
    assert_eq!(frames.len(), 40, "{} stashed", chrome.stashed());
    assert!(frames.iter().step_by(20).all(|f| f.keyframe));
    assert_eq!(chrome.keyframe_requests(), 0);
}
