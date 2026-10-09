//! The latency harness's two ends: the stamp the synthetic camera puts in
//! front of every access unit, and the measurement a viewer takes from what
//! it received.
//!
//! The stamp is an H.264 SEI NAL unit (ISO/IEC 14496-10 §7.3.2.3) with one
//! `user_data_unregistered` message (D.1.6, payload type 5): a 16-byte UUID
//! and the send instant as 16 hex digits of nanoseconds since an origin the
//! camera and the viewer share. Hex keeps the payload free of zero bytes,
//! so no emulation prevention (§7.4.1) is needed and Annex B framing on
//! the side branch never splits it. Normalization passes SEI through, so
//! the stamp reaches the viewer as a single NAL unit packet (RFC 6184
//! §5.6) or inside a STAP-A (§5.7.1).
//!
//! Camera and viewer run in one test process on one monotonic clock: the
//! difference is what the daemon adds (worker, pacer, SRTP) plus loopback.

use std::time::{Duration, Instant};

use lotse_codec::h264::nal;
use str0m::rtp::RtpPacket;

/// Marks a stamp among other SEI messages; no zero bytes.
pub const STAMP_UUID: [u8; 16] = *b"lotse-latency-v1";

/// `user_data_unregistered` (ISO/IEC 14496-10 D.1.6).
const USER_DATA_UNREGISTERED: u8 = 5;

/// The message's size: the UUID and 16 hex digits.
const MESSAGE_LEN: u8 = 32;

/// The SEI NAL unit stamping an access unit sent `sent` after the origin.
pub fn stamp_sei(sent: Duration) -> Vec<u8> {
    let nanos = u64::try_from(sent.as_nanos()).unwrap_or(u64::MAX);
    let mut unit = vec![nal::NAL_SEI, USER_DATA_UNREGISTERED, MESSAGE_LEN];
    unit.extend_from_slice(&STAMP_UUID);
    unit.extend_from_slice(format!("{nanos:016x}").as_bytes());
    // rbsp_trailing_bits (§7.3.2.11).
    unit.push(0x80);
    unit
}

/// The send time a stamp SEI NAL unit carries, if `unit` is one.
pub fn read_stamp(unit: &[u8]) -> Option<Duration> {
    let (header, rest) = unit.split_first()?;
    if nal::nal_type(*header) != nal::NAL_SEI {
        return None;
    }
    let rest = rest.strip_prefix(&[USER_DATA_UNREGISTERED, MESSAGE_LEN])?;
    let digits = rest.strip_prefix(&STAMP_UUID)?.get(..16)?;
    let nanos = u64::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
    Some(Duration::from_nanos(nanos))
}

/// The stamp in an RTP payload: a single NAL unit, or any unit of a
/// STAP-A (RFC 6184 §5.7.1: a 16-bit size before each unit).
pub fn stamp_in_payload(payload: &[u8]) -> Option<Duration> {
    let (&indicator, mut rest) = payload.split_first()?;
    if nal::nal_type(indicator) != nal::STAP_A {
        return read_stamp(payload);
    }
    while let Some((size, tail)) = rest.split_at_checked(2) {
        let size = usize::from(u16::from_be_bytes([*size.first()?, *size.get(1)?]));
        let (unit, tail) = tail.split_at_checked(size)?;
        if let Some(stamp) = read_stamp(unit) {
            return Some(stamp);
        }
        rest = tail;
    }
    None
}

/// What the measurement needs of one received RTP packet.
#[derive(Debug, Clone, Copy)]
pub struct Received<'a> {
    /// The RTP timestamp.
    pub rtp_ts: u32,
    /// The marker bit: the last packet of the access unit (RFC 6184 §5.1).
    pub marker: bool,
    /// The payload.
    pub payload: &'a [u8],
    /// When the viewer received it.
    pub at: Instant,
}

impl<'a> From<&'a RtpPacket> for Received<'a> {
    fn from(packet: &'a RtpPacket) -> Self {
        Self {
            rtp_ts: packet.header.timestamp,
            marker: packet.header.marker,
            payload: &packet.payload,
            at: packet.timestamp,
        }
    }
}

/// Latencies a viewer measured, sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Latencies {
    /// Per stamped packet: sent by the camera → received by the viewer.
    pub first_packet: Vec<Duration>,
    /// Per stamped frame: sent by the camera → the frame's marker packet
    /// received.
    pub whole_frame: Vec<Duration>,
}

impl Latencies {
    /// Measures `packets`, received in order, against the camera's
    /// `origin`: every stamped packet, and the marker packet with its RTP
    /// timestamp. Only frames the camera sent once the first packet had
    /// arrived count: the join's catch-up frames come from the GOP cache
    /// with old stamps, and measure the join rather than cut-through.
    pub fn measure(packets: &[Received<'_>], origin: Instant) -> Self {
        let mut out = Self::default();
        let since = |at: Instant| at.saturating_duration_since(origin);
        let Some(live_from) = packets.first().map(|p| since(p.at)) else {
            return out;
        };
        for (index, packet) in packets.iter().enumerate() {
            let Some(sent) = stamp_in_payload(packet.payload) else {
                continue;
            };
            if sent < live_from {
                continue;
            }
            out.first_packet.push(since(packet.at).saturating_sub(sent));
            let marker = packets
                .get(index..)
                .unwrap_or_default()
                .iter()
                .take_while(|p| p.rtp_ts == packet.rtp_ts)
                .find(|p| p.marker);
            if let Some(marker) = marker {
                out.whole_frame.push(since(marker.at).saturating_sub(sent));
            }
        }
        out.first_packet.sort_unstable();
        out.whole_frame.sort_unstable();
        out
    }

    /// [`Latencies::measure`] over the packets a str0m viewer received.
    pub fn of_viewer(packets: &[RtpPacket], origin: Instant) -> Self {
        let received: Vec<Received<'_>> = packets.iter().map(Received::from).collect();
        Self::measure(&received, origin)
    }

    /// The `p`-th percentile (0–100, nearest rank) of sorted `values`.
    pub fn percentile(values: &[Duration], p: u32) -> Option<Duration> {
        let count = values.len();
        if count == 0 {
            return None;
        }
        let rank = count
            .saturating_mul(usize::try_from(p.min(100)).unwrap_or(100))
            .div_ceil(100)
            .max(1);
        values.get(rank.saturating_sub(1)).copied()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::clock::{Clock as _, SystemClock};

    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn stamps_round_trip_and_contain_no_zero_bytes() {
        for sent in [
            Duration::ZERO,
            ms(1),
            Duration::from_nanos(0x0100_0000_0001),
            Duration::MAX,
        ] {
            let unit = stamp_sei(sent);
            assert!(!unit.contains(&0), "{unit:?}");
            let expected = Duration::from_nanos(u64::try_from(sent.as_nanos()).unwrap_or(u64::MAX));
            assert_eq!(read_stamp(&unit), Some(expected));
        }
        assert_eq!(stamp_sei(ms(1)).len(), 36);
    }

    #[test]
    fn other_units_carry_no_stamp() {
        let stamp = stamp_sei(ms(5));
        assert_eq!(read_stamp(&[]), None);
        assert_eq!(read_stamp(&[0x65, 1, 2]), None, "an IDR slice");
        let mut other_sei = stamp.clone();
        other_sei[1] = 6;
        assert_eq!(read_stamp(&other_sei), None, "another payload type");
        let mut other_uuid = stamp.clone();
        other_uuid[3] = b'X';
        assert_eq!(read_stamp(&other_uuid), None);
        assert_eq!(read_stamp(&stamp[..20]), None, "truncated");
        let mut not_hex = stamp;
        not_hex[20] = b'z';
        assert_eq!(read_stamp(&not_hex), None);
    }

    #[test]
    fn rfc6184_5_7_1_a_stamp_is_found_inside_a_stap_a() {
        let stamp = stamp_sei(ms(7));
        assert_eq!(stamp_in_payload(&stamp), Some(ms(7)), "a single NAL unit");
        let sps = [0x67_u8, 0x42, 0xc0, 0x28];
        let mut aggregate = vec![nal::STAP_A];
        for unit in [&sps[..], &stamp] {
            aggregate.extend_from_slice(&u16::try_from(unit.len()).unwrap().to_be_bytes());
            aggregate.extend_from_slice(unit);
        }
        assert_eq!(stamp_in_payload(&aggregate), Some(ms(7)));
        assert_eq!(stamp_in_payload(&aggregate[..8]), None, "truncated unit");
        assert_eq!(
            stamp_in_payload(&[nal::STAP_A, 0, 4, 0x67, 0x42, 0xc0, 0x28]),
            None
        );
        assert_eq!(stamp_in_payload(&[]), None);
    }

    #[test]
    fn packets_and_frames_are_measured_from_their_stamps() {
        let origin = SystemClock.now();
        let (first, second) = (stamp_sei(ms(10)), stamp_sei(ms(43)));
        let slice = [0x41_u8, 1];
        let packet = |rtp_ts, marker, payload, after| Received {
            rtp_ts,
            marker,
            payload,
            at: origin + ms(after),
        };
        let (joined, burst) = (stamp_sei(ms(1)), stamp_sei(ms(2)));
        let received = [
            // The join: catch-up frames sent before anything arrived.
            packet(0, false, &burst[..], 8),
            packet(0, false, &joined[..], 9),
            // Frame 1, sent at 10 ms: stamp in at 11 ms, marker at 14 ms.
            packet(1, false, &first[..], 11),
            packet(1, true, &slice[..], 14),
            // Frame 2, sent at 43 ms, its marker never arrived.
            packet(2, false, &second[..], 45),
            packet(3, true, &slice[..], 80),
        ];
        let latencies = Latencies::measure(&received, origin);
        assert_eq!(latencies.first_packet, [ms(1), ms(2)]);
        assert_eq!(latencies.whole_frame, [ms(4)]);
        assert_eq!(Latencies::measure(&[], origin), Latencies::default());
    }

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let values: Vec<_> = (1..=100).map(ms).collect();
        assert_eq!(Latencies::percentile(&values, 50), Some(ms(50)));
        assert_eq!(Latencies::percentile(&values, 99), Some(ms(99)));
        assert_eq!(Latencies::percentile(&values, 100), Some(ms(100)));
        assert_eq!(Latencies::percentile(&values, 0), Some(ms(1)));
        assert_eq!(Latencies::percentile(&values, 500), Some(ms(100)));
        assert_eq!(Latencies::percentile(&[ms(3)], 99), Some(ms(3)));
        assert_eq!(Latencies::percentile(&[], 50), None);
    }
}
