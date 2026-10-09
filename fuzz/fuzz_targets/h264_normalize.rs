//! `h264_normalize`: both H.264 normalization layers never panic, never
//! hang and keep their promises on arbitrary packets: every emitted payload
//! fits the target (inserted parameter sets included), a keyframe start is
//! either a self-contained aggregate or the first of the inserted
//! parameter-set packets that precede the IDR, and the depacketizer emits
//! only Annex B units within the size limit and never holds more than the
//! limit for the unit it is building.
//! Run with `cargo +nightly fuzz run h264_normalize` from the repository root.

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use lotse_codec::h264::{Depacketizer, PacketNormalizer, ParameterSets};

/// The depacketizer's frame limit: one packet's payload (at most 255
/// bytes) and its start code always fit, two packets can cross it, so
/// short inputs reach the oversize path (a 60-second run at a limit of 1024
/// never found a unit that grew without bound, 2026-10-08).
const MAX_FRAME: usize = 300;

fuzz_target!(|data: &[u8]| {
    // The input is a sequence of packets: [len:u8][ts_delta:u8][flags:u8][payload...].
    let mut normalizer = PacketNormalizer::new(200, ParameterSets::default());
    let mut depacketizer = Depacketizer::new(MAX_FRAME, ParameterSets::default());
    let mut rest = data;
    let mut ts = 0_u32;
    let mut seq = 0_u16;
    let mut packets = Vec::new();
    let mut units = Vec::new();
    while let Some((&len, after)) = rest.split_first() {
        let Some((&delta, after)) = after.split_first() else {
            break;
        };
        let Some((&flags, after)) = after.split_first() else {
            break;
        };
        let len = usize::from(len);
        let Some((payload, after)) = after.split_at_checked(len) else {
            break;
        };
        rest = after;
        ts = ts.wrapping_add(u32::from(delta));
        let marker = flags & 1 != 0;
        // Bit 1 skips a sequence number: a lost packet.
        seq = seq.wrapping_add(if flags & 2 != 0 { 2 } else { 1 });
        packets.clear();
        let _ = normalizer.normalize(ts, marker, &Bytes::copy_from_slice(payload), &mut packets);
        for (i, packet) in packets.iter().enumerate() {
            assert!(!packet.payload.is_empty());
            assert!(
                packet.payload.len() <= 200,
                "over the target: {}",
                packet.payload.len()
            );
            if packet.keyframe_start && packet.synthetic {
                // The inserted parameter sets, one STAP-A or split to fit,
                // then the IDR itself.
                assert!(packets[i + 1..].iter().any(|next| !next.synthetic));
            }
        }
        units.clear();
        let _ = depacketizer.push(seq, ts, marker, payload, &mut units);
        assert!(
            depacketizer.buffered() <= MAX_FRAME,
            "holds {} for one unit",
            depacketizer.buffered()
        );
        for unit in &units {
            assert!(unit.payload.len() <= MAX_FRAME);
            assert!(unit.payload.starts_with(&[0, 0, 0, 1]));
        }
    }
    units.clear();
    depacketizer.flush(&mut units);
});
