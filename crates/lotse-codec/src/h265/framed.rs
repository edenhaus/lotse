//! H.265 from framed sources: whole access units in the Annex B byte
//! stream with their presentation time, as MPEG-TS carries them in PES
//! packets, normalized by the two layers of the RTP path.
//!
//! The H.265 twin of [`crate::h264::framed`]. Each access unit is cut into
//! its NAL units at the start codes (ITU-T H.265 Annex B), packetized as
//! RFC 7798 single NAL unit packets (§4.4.1) and fragmentation units
//! (§4.4.3) with the marker bit on its last packet (§4.1) and consecutive
//! synthetic sequence numbers, and fed to [`PacketNormalizer`] and
//! [`Depacketizer`] as a camera's packets are. Parameter-set insertion,
//! keyframe recognition (IRAP pictures, §3.73), the SPS reader, filler
//! dropping, the frame size limit and the packet count check are theirs;
//! this module adds none of its own. Parameter sets known out of band (an
//! `hvcC` record, ISO/IEC 14496-15 §8.3.3) seed both layers as an SDP's
//! do.
//!
//! A NAL unit that no single NAL unit packet carries is dropped and
//! counted: shorter than its two-byte header, `forbidden_zero_bit` set or
//! `nuh_temporal_id_plus1` zero (§7.4.2.2), or a type Table 7-1 leaves
//! unspecified (48 to 63), which RFC 7798 §4.4 takes for its aggregation,
//! fragmentation and PACI packets.

use bytes::Bytes;

use super::frame::{AccessUnit, Depacketizer};
use super::nal::{self, ParameterSets, Payload};
use super::packet::PacketNormalizer;
use crate::h264::{FrameOverLimit, NormalizedPacket};

/// Both normalization layers of one H.265 track fed from a framed source.
#[derive(Debug)]
pub struct FramedNormalizer {
    /// The largest payload to packetize into, the packet layer's target.
    max_payload: usize,
    /// The live path's layer.
    normalizer: PacketNormalizer,
    /// The side branch's layer.
    depacketizer: Depacketizer,
    /// The synthetic sequence number of the next payload: consecutive,
    /// wrapping, so the depacketizer never sees a loss.
    seq: u16,
    /// NAL units dropped as no single NAL unit packet carries them.
    dropped_units: u64,
}

impl FramedNormalizer {
    /// Layers emitting payloads of at most `max_payload` bytes and access
    /// units of at most `max_frame_bytes`, seeded with the parameter sets
    /// known out of band, if any.
    pub fn new(max_payload: usize, max_frame_bytes: usize, sets: ParameterSets) -> Self {
        Self {
            max_payload,
            normalizer: PacketNormalizer::new(max_payload, sets.clone()),
            depacketizer: Depacketizer::new(max_frame_bytes, sets),
            seq: 0,
            dropped_units: 0,
        }
    }

    /// The live path's layer: its counters and parameter sets.
    pub const fn packet_layer(&self) -> &PacketNormalizer {
        &self.normalizer
    }

    /// The side branch's layer: its counters and the parameter sets a
    /// codec update takes when a unit brings a new SPS.
    pub const fn frame_layer(&self) -> &Depacketizer {
        &self.depacketizer
    }

    /// The access unit that last went out in more packets than some
    /// libwebrtc receivers assemble, once
    /// ([`PacketNormalizer::take_frame_over_limit`]).
    pub const fn take_frame_over_limit(&mut self) -> Option<FrameOverLimit> {
        self.normalizer.take_frame_over_limit()
    }

    /// NAL units dropped as no single NAL unit packet carries them.
    pub const fn dropped_units(&self) -> u64 {
        self.dropped_units
    }

    /// Normalizes one access unit in Annex B form with timestamp `ts`
    /// (the track's clock, wrapped to 32 bits as an RTP timestamp): the
    /// live path's packets are appended to `packets`, the last one with
    /// the marker bit, and the access unit, unless it is dropped, to
    /// `units`. An access unit without a NAL unit to carry adds nothing.
    pub fn push(
        &mut self,
        ts: u32,
        access_unit: &[u8],
        packets: &mut Vec<NormalizedPacket>,
        units: &mut Vec<AccessUnit>,
    ) {
        let mut payloads: Vec<Bytes> = Vec::new();
        for unit in crate::h264::annex_b_units(access_unit) {
            if matches!(nal::parse(unit), Ok(Payload::Single(_))) {
                payloads.extend(nal::fragment(unit, self.max_payload));
            } else {
                self.dropped_units = self.dropped_units.saturating_add(1);
            }
        }
        let count = payloads.len();
        for (i, payload) in payloads.iter().enumerate() {
            let marker = i.saturating_add(1) == count;
            let seq = self.seq;
            self.seq = seq.wrapping_add(1);
            // Every payload is a single NAL unit packet `nal::parse` took,
            // or a fragment of one, so neither layer refuses it.
            let _readable = self.normalizer.normalize(ts, marker, payload, packets);
            let _readable = self.depacketizer.push(seq, ts, marker, payload, units);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::super::nal::{AP, AUD_NUT, CRA_NUT, FD_NUT, FU, IDR_W_RADL, PACI};
    use super::super::sps::test_data::{pps, sps, vps};
    use super::*;
    use crate::h264::{DEFAULT_MAX_PAYLOAD, LIBWEBRTC_MAX_FRAME_PACKETS};

    const MAX_FRAME: usize = 4 << 20;

    fn picture(unit_type: u8, len: usize) -> Vec<u8> {
        [unit_type << 1, 0x01]
            .into_iter()
            .chain(std::iter::repeat_n(0xab, len))
            .collect()
    }

    fn slice(len: usize) -> Vec<u8> {
        picture(1, len)
    }

    fn annex_b(units: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in units {
            crate::h264::nal::annex_b_append(&mut out, unit);
        }
        out
    }

    fn known_sets() -> ParameterSets {
        ParameterSets {
            vps: Some(Bytes::from(vps())),
            sps: Some(Bytes::from(sps(1280, 720))),
            pps: Some(Bytes::from(pps())),
        }
    }

    fn push(
        framed: &mut FramedNormalizer,
        ts: u32,
        au: &[u8],
    ) -> (Vec<NormalizedPacket>, Vec<AccessUnit>) {
        let (mut packets, mut units) = (Vec::new(), Vec::new());
        framed.push(ts, au, &mut packets, &mut units);
        (packets, units)
    }

    /// Only the last packet carries the marker bit, only the first starts
    /// the frame.
    fn assert_one_frame(packets: &[NormalizedPacket]) {
        let markers: Vec<bool> = packets.iter().map(|p| p.marker).collect();
        let mut expected = vec![false; packets.len()];
        *expected.last_mut().unwrap() = true;
        assert_eq!(markers, expected);
        let starts: Vec<bool> = packets.iter().map(|p| p.frame_start).collect();
        expected.fill(false);
        expected[0] = true;
        assert_eq!(starts, expected);
    }

    #[test]
    fn an_access_unit_with_in_band_sets_is_one_frame_on_both_layers_rfc7798_4_1() {
        let mut framed =
            FramedNormalizer::new(DEFAULT_MAX_PAYLOAD, MAX_FRAME, ParameterSets::default());
        let (vps, sps, pps, idr) = (vps(), sps(1280, 720), pps(), picture(IDR_W_RADL, 3000));
        let aud = [AUD_NUT << 1, 0x01, 0x50];
        let au = annex_b(&[&aud, &vps, &sps, &pps, &idr]);
        let (packets, units) = push(&mut framed, 9000, &au);
        assert_one_frame(&packets);
        assert_eq!(packets[0].payload.as_ref(), aud);
        assert!(packets.iter().any(|p| p.keyframe_start));
        assert_eq!(units.len(), 1);
        assert_eq!((units[0].ts, units[0].keyframe), (9000, true));
        assert_eq!(units[0].payload.as_ref(), au);
        assert_eq!(units[0].sps.map(|info| info.width), Some(1280));
        assert_eq!(framed.frame_layer().parameter_sets(), &known_sets());
        assert_eq!(framed.packet_layer().parameter_sets(), &known_sets());

        let (packets, units) = push(&mut framed, 12_000, &annex_b(&[&slice(200)]));
        assert_one_frame(&packets);
        assert!(!packets[0].keyframe_start);
        assert_eq!((units[0].ts, units[0].keyframe), (12_000, false));
        let stats = framed.frame_layer().stats();
        assert_eq!(
            (stats.frames, stats.keyframes, stats.dropped_lost),
            (2, 1, 0)
        );
        assert_eq!(framed.packet_layer().stats().violations, 0);
    }

    #[test]
    fn out_of_band_sets_precede_an_irap_picture_without_them_h265_7_4_2_4_4() {
        let mut framed = FramedNormalizer::new(DEFAULT_MAX_PAYLOAD, MAX_FRAME, known_sets());
        let cra = picture(CRA_NUT, 100);
        let (packets, units) = push(&mut framed, 0, &annex_b(&[&cra]));
        assert_one_frame(&packets);
        assert!(packets[0].synthetic && packets[0].keyframe_start);
        assert_eq!(nal::nal_type(packets[0].payload[0]), AP);
        assert_eq!(packets[1].payload.as_ref(), cra.as_slice());
        assert_eq!(framed.packet_layer().stats().inserted, 1);
        let sets = known_sets();
        let expected = annex_b(&[
            sets.vps.as_deref().unwrap(),
            sets.sps.as_deref().unwrap(),
            sets.pps.as_deref().unwrap(),
            &cra,
        ]);
        assert_eq!(units[0].payload.as_ref(), expected);
        assert!(units[0].keyframe);
    }

    #[test]
    fn every_packet_fits_the_payload_target_rfc7798_4_4_3() {
        let mut framed = FramedNormalizer::new(100, MAX_FRAME, ParameterSets::default());
        let (idr, slice) = (picture(IDR_W_RADL, 1000), slice(98));
        let (packets, units) = push(&mut framed, 0, &annex_b(&[&idr, &slice]));
        assert_one_frame(&packets);
        assert!(packets.iter().all(|p| p.payload.len() <= 100));
        // Eleven fragments of the IDR (97 bytes each), the slice whole.
        assert_eq!(packets.len(), 11 + 1);
        assert!(
            packets[..11]
                .iter()
                .all(|p| nal::nal_type(p.payload[0]) == FU)
        );
        assert!(packets[0].keyframe_start);
        assert_eq!(framed.packet_layer().stats().keyframes_without_sets, 1);
        assert_eq!(units[0].payload.as_ref(), annex_b(&[&idr, &slice]));
    }

    #[test]
    fn an_oversize_access_unit_goes_out_live_and_is_dropped_from_the_side_branch() {
        let mut framed = FramedNormalizer::new(DEFAULT_MAX_PAYLOAD, 1000, ParameterSets::default());
        let (packets, units) = push(&mut framed, 0, &annex_b(&[&slice(5000)]));
        assert_one_frame(&packets);
        assert!(units.is_empty());
        assert_eq!(framed.frame_layer().stats().dropped_oversize, 1);
        assert_eq!(framed.frame_layer().buffered(), 0);
        let (_, units) = push(&mut framed, 3000, &annex_b(&[&slice(500)]));
        assert_eq!(units.len(), 1);
    }

    #[test]
    fn an_access_unit_past_libwebrtc_max_frame_packets_is_reported_once() {
        let mut framed = FramedNormalizer::new(100, MAX_FRAME, ParameterSets::default());
        let big = slice(97 * LIBWEBRTC_MAX_FRAME_PACKETS + 1);
        let (packets, _) = push(&mut framed, 0, &annex_b(&[&big]));
        assert_eq!(packets.len(), LIBWEBRTC_MAX_FRAME_PACKETS + 1);
        let over = framed.take_frame_over_limit().unwrap();
        assert_eq!(over.packets, LIBWEBRTC_MAX_FRAME_PACKETS + 1);
        assert_eq!(framed.take_frame_over_limit(), None);
    }

    #[test]
    fn units_no_single_nal_unit_packet_carries_are_dropped_rfc7798_4_4() {
        let mut framed =
            FramedNormalizer::new(DEFAULT_MAX_PAYLOAD, MAX_FRAME, ParameterSets::default());
        // A lone header byte, the forbidden bit, a zero temporal id, and
        // the types RFC 7798 takes for its own packets, once past the
        // target.
        let garbage: [&[u8]; 7] = [
            &[0x02],
            &[0x82, 0x01, 1],
            &[0x02, 0x00, 1],
            &[AP << 1, 0x01, 0, 1, 2],
            &[FU << 1, 0x01, 0x81, 1],
            &[PACI << 1, 0x01, 1],
            &picture(FU, 2000),
        ];
        let (packets, units) = push(&mut framed, 0, &annex_b(&garbage));
        assert!(packets.is_empty() && units.is_empty());
        assert_eq!(framed.dropped_units(), 7);

        let slice = slice(10);
        let (packets, units) = push(&mut framed, 3000, &annex_b(&[garbage[1], &slice]));
        assert_eq!(packets.len(), 1);
        assert!(packets[0].marker && packets[0].frame_start);
        assert_eq!(units[0].payload.as_ref(), annex_b(&[&slice]));
        assert_eq!(framed.dropped_units(), 8);
    }

    #[test]
    fn empty_and_start_code_free_access_units_add_nothing_h265_b_2() {
        let mut framed =
            FramedNormalizer::new(DEFAULT_MAX_PAYLOAD, MAX_FRAME, ParameterSets::default());
        for au in [&[][..], &[0, 0, 1], &[0x02, 0x01, 0xab]] {
            let (packets, units) = push(&mut framed, 0, au);
            assert!(packets.is_empty() && units.is_empty(), "{au:?}");
        }
        assert_eq!(framed.dropped_units(), 0);
        assert_eq!(framed.packet_layer().stats().packets, 0);
    }

    #[test]
    fn filler_is_dropped_and_the_access_unit_still_ends_rfc7798_4_1() {
        let mut framed =
            FramedNormalizer::new(DEFAULT_MAX_PAYLOAD, MAX_FRAME, ParameterSets::default());
        let slice = slice(10);
        let (packets, units) = push(&mut framed, 0, &annex_b(&[&slice, &picture(FD_NUT, 20)]));
        assert_one_frame(&packets);
        assert_eq!(packets[1].payload.as_ref(), [FD_NUT << 1, 0x01, 0x80]);
        assert_eq!(framed.packet_layer().stats().filler_dropped, 1);
        assert_eq!(units[0].payload.as_ref(), annex_b(&[&slice]));
    }

    #[test]
    fn sequence_numbers_wrap_without_a_loss_rfc3550_5_1() {
        let mut framed =
            FramedNormalizer::new(DEFAULT_MAX_PAYLOAD, MAX_FRAME, ParameterSets::default());
        framed.seq = u16::MAX - 1;
        let slices: Vec<Vec<u8>> = (0..4).map(|_| slice(10)).collect();
        let refs: Vec<&[u8]> = slices.iter().map(Vec::as_slice).collect();
        let (_, units) = push(&mut framed, 0, &annex_b(&refs));
        let (_, more) = push(&mut framed, 3000, &annex_b(&refs));
        assert_eq!(framed.seq, 6);
        assert_eq!((units.len(), more.len()), (1, 1));
        assert_eq!(framed.frame_layer().stats().dropped_lost, 0);
    }
}
