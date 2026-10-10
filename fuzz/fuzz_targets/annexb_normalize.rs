//! `annexb_normalize`: both codecs' framed normalizers never panic, never
//! hang and keep their promises on arbitrary access units: every packet
//! fits the target, an access unit's packets start at most one frame and
//! end it with the one marker bit (RFC 6184 §5.1, RFC 7798 §4.1), the layers see
//! no packetization violation and no loss, at most one Annex B access unit
//! within the size limit comes out, and nothing is held between access
//! units.
//! Run with `cargo +nightly fuzz run annexb_normalize` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::{h264, h265};

/// The packet target: small, so short inputs reach fragmentation.
const MAX_PAYLOAD: usize = 64;

/// The frame limit: one short access unit fits, a long one crosses it.
const MAX_FRAME: usize = 300;

/// What one push left: the packets' markers, frame starts and sizes, and
/// the access units' payloads.
fn check(packets: &[h264::NormalizedPacket], units: &[&[u8]], buffered: usize) {
    if let Some((last, rest)) = packets.split_last() {
        assert!(last.marker, "the access unit does not end");
        assert!(
            rest.iter().all(|p| !p.marker),
            "a marker inside the access unit"
        );
        // The first packet starts the frame unless the access unit's first
        // NAL unit was filler: the packet layer drops it and the frame start
        // with it, as it does for a camera's packets.
        assert!(packets[1..].iter().all(|p| !p.frame_start), "two frames");
    }
    for packet in packets {
        assert!(
            packet.payload.len() <= MAX_PAYLOAD,
            "over the target: {}",
            packet.payload.len()
        );
    }
    assert!(
        units.len() <= 1,
        "{} units from one access unit",
        units.len()
    );
    for unit in units {
        assert!(unit.len() <= MAX_FRAME);
        assert!(unit.starts_with(&[0, 0, 0, 1]));
    }
    assert_eq!(buffered, 0, "held between access units");
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks the codec and seeds no sets; the rest is a
    // sequence of access units: [len:u8][ts_delta:u8][annex b...].
    let Some((&codec, mut rest)) = data.split_first() else {
        return;
    };
    let mut h264 =
        h264::FramedNormalizer::new(MAX_PAYLOAD, MAX_FRAME, h264::ParameterSets::default());
    let mut h265 =
        h265::FramedNormalizer::new(MAX_PAYLOAD, MAX_FRAME, h265::ParameterSets::default());
    let mut ts = 0_u32;
    let mut packets = Vec::new();
    let mut units264 = Vec::new();
    let mut units265 = Vec::new();
    while let Some((&len, after)) = rest.split_first() {
        let Some((&delta, after)) = after.split_first() else {
            break;
        };
        let Some((au, after)) = after.split_at_checked(usize::from(len)) else {
            break;
        };
        rest = after;
        ts = ts.wrapping_add(u32::from(delta));
        packets.clear();
        if codec & 1 == 0 {
            units264.clear();
            h264.push(ts, au, &mut packets, &mut units264);
            let units: Vec<&[u8]> = units264.iter().map(|u| u.payload.as_ref()).collect();
            check(&packets, &units, h264.frame_layer().buffered());
            assert_eq!(h264.packet_layer().stats().violations, 0);
            let stats = h264.frame_layer().stats();
            assert_eq!((stats.violations, stats.dropped_lost), (0, 0));
        } else {
            units265.clear();
            h265.push(ts, au, &mut packets, &mut units265);
            let units: Vec<&[u8]> = units265.iter().map(|u| u.payload.as_ref()).collect();
            check(&packets, &units, h265.frame_layer().buffered());
            assert_eq!(h265.packet_layer().stats().violations, 0);
            let stats = h265.frame_layer().stats();
            assert_eq!((stats.violations, stats.dropped_lost), (0, 0));
        }
    }
});
