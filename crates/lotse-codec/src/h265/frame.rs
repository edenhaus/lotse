//! The frame layer of H.265 normalization, on the side branch: RTP packets
//! in, complete access units out as Annex B with the parameter sets
//! in-band before every IRAP picture, keyframes recognized (IRAP, CRA only
//! without skipped leading pictures, or a recovery point), lost or oversize
//! units dropped and counted, and the camera's habits (marker bit,
//! B-frames) observed.
//! It never holds more than `max_frame_bytes` for the open unit: a unit
//! that outgrows the limit is dropped the moment it does, and the rest of
//! it is ignored until it ends.
//!
//! The H.265 twin of [`crate::h264::frame`]. Implements RFC 7798 §4.1
//! (marker bit), §4.4.1 to §4.4.3 (depacketization without decoding order
//! numbers), ITU-T H.265 §7.4.2.4.4 (VPS, SPS and PPS before the IRAP
//! picture) and Annex B. Feeds the source's packets as they came, never
//! the packet layer's output.

use bytes::Bytes;
use lotse_core::media::TimestampUnwrapper;

use super::nal::{self, ParameterSets, Payload, PayloadError};
use super::packet::joinable;
use super::sps::{self, SpsInfo};
pub use crate::h264::FrameStats;

/// One complete access unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    /// The RTP timestamp, as sent.
    pub ts: u32,
    /// A joinable IRAP picture, or a recovery point on intra-refresh
    /// cameras.
    pub keyframe: bool,
    /// Annex B, parameter sets in-band before an IRAP picture.
    pub payload: Bytes,
    /// The SPS changed in this unit: a new sequence (resolution switch).
    pub sps: Option<SpsInfo>,
}

/// The frame-layer depacketizer of one H.265 video track.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts about the stream and the open unit, as in the H.264 depacketizer"
)]
pub struct Depacketizer {
    /// Units larger than this are dropped.
    max_frame_bytes: usize,
    /// The latest parameter sets.
    sets: ParameterSets,
    /// The stream sent skipped leading pictures.
    rasl_seen: bool,
    /// The unit under construction, Annex B.
    au: Vec<u8>,
    /// Its timestamp.
    au_ts: Option<u32>,
    /// It holds a joinable IRAP picture or a recovery point.
    au_keyframe: bool,
    /// The parameter sets it already holds: VPS, SPS, PPS.
    au_has_sets: [bool; 3],
    /// It holds a VCL NAL unit: a parameter set from here on is left out.
    au_vcl_seen: bool,
    /// A packet inside it was lost.
    au_damaged: bool,
    /// It outgrew `max_frame_bytes`: emptied, and the rest of it is
    /// ignored until it ends.
    au_oversize: bool,
    /// The SPS changed inside it.
    au_sps: Option<SpsInfo>,
    /// The fragmented unit under reassembly, header included.
    fragment: Option<Vec<u8>>,
    /// The last sequence number seen.
    last_seq: Option<u16>,
    /// Whether the last packet carried the marker bit.
    last_marker: bool,
    /// Unwraps timestamps for the B-frame check.
    unwrapper: TimestampUnwrapper,
    /// The highest unwrapped timestamp emitted.
    max_ts: Option<i64>,
    /// The counters.
    stats: FrameStats,
}

impl Depacketizer {
    /// A depacketizer dropping units over `max_frame_bytes`, seeded with
    /// the parameter sets the SDP announced, if any.
    pub fn new(max_frame_bytes: usize, sets: ParameterSets) -> Self {
        Self {
            max_frame_bytes,
            sets,
            rasl_seen: false,
            au: Vec::new(),
            au_ts: None,
            au_keyframe: false,
            au_has_sets: [false; 3],
            au_vcl_seen: false,
            au_damaged: false,
            au_oversize: false,
            au_sps: None,
            fragment: None,
            last_seq: None,
            last_marker: false,
            unwrapper: TimestampUnwrapper::new(),
            max_ts: None,
            stats: FrameStats::default(),
        }
    }

    /// The latest parameter sets.
    pub const fn parameter_sets(&self) -> &ParameterSets {
        &self.sets
    }

    /// The counters.
    pub const fn stats(&self) -> FrameStats {
        self.stats
    }

    /// The bytes held for the open unit: the access unit so far and the
    /// fragmented unit under reassembly. Never more than `max_frame_bytes`.
    pub fn buffered(&self) -> usize {
        self.au
            .len()
            .saturating_add(self.fragment.as_ref().map_or(0, Vec::len))
    }

    /// Whether `extra` more bytes keep the open unit within
    /// `max_frame_bytes`. If not, the unit is oversize: what it holds is
    /// freed and the rest of it is ignored until it ends.
    fn reserve(&mut self, extra: usize) -> bool {
        if !self.au_oversize && self.buffered().saturating_add(extra) <= self.max_frame_bytes {
            return true;
        }
        self.au_oversize = true;
        self.au = Vec::new();
        self.fragment = None;
        false
    }

    /// Marks the open unit damaged after an unreadable payload.
    fn violation(&mut self, err: PayloadError) -> Result<(), PayloadError> {
        self.stats.violations = self.stats.violations.saturating_add(1);
        self.au_damaged = true;
        self.fragment = None;
        Err(err)
    }

    /// Feeds one source packet; complete units are appended to `out`. A
    /// payload lotse cannot read is an error after the unit it belongs to
    /// was marked damaged. A fragment start while another fragmented unit
    /// is open is counted as a violation and damages the unit, but is no
    /// error: the start itself is readable.
    pub fn push(
        &mut self,
        seq: u16,
        ts: u32,
        marker: bool,
        payload: &[u8],
        out: &mut Vec<AccessUnit>,
    ) -> Result<(), PayloadError> {
        if let Some(last) = self.last_seq
            && seq != last.wrapping_add(1)
        {
            self.au_damaged = true;
            self.fragment = None;
        }
        self.last_seq = Some(seq);
        if self.au_ts.is_some_and(|open| open != ts) {
            // A new timestamp ends the previous unit; without a marker on
            // its last packet the camera does not set the marker bit.
            if !self.last_marker {
                self.stats.marker_bit = Some(false);
            }
            self.finish(out);
        }
        self.last_marker = marker;
        let parsed = match nal::parse(payload) {
            Ok(parsed) => parsed,
            Err(err) => return self.violation(err),
        };
        self.au_ts = Some(ts);
        match parsed {
            Payload::Single(unit) => self.append(unit),
            Payload::Aggregate(units) => {
                for unit in units {
                    match unit {
                        Ok(unit) => self.append(unit),
                        Err(err) => return self.violation(err),
                    }
                }
            }
            Payload::Fragment {
                nal_header,
                start,
                end,
                fragment,
            } => {
                if start {
                    if self.fragment.take().is_some() {
                        // RFC 7798 §4.4.3: nothing is sent between a unit's
                        // first and last fragment, so the open unit lost
                        // its end; the access unit is incomplete.
                        self.stats.violations = self.stats.violations.saturating_add(1);
                        self.au_damaged = true;
                    }
                    // The reconstructed header, then the fragment.
                    let len = fragment.len().saturating_add(nal_header.len());
                    if self.reserve(len) {
                        let mut unit = Vec::with_capacity(len);
                        unit.extend_from_slice(&nal_header);
                        unit.extend_from_slice(fragment);
                        self.fragment = Some(unit);
                    }
                } else if self.fragment.is_none() {
                    // A fragment without its start: lost, or a violation
                    // (or the rest of an oversize unit, counted as such).
                    self.au_damaged = true;
                } else if self.reserve(fragment.len())
                    && let Some(open) = self.fragment.as_mut()
                {
                    open.extend_from_slice(fragment);
                }
                if end && let Some(done) = self.fragment.take() {
                    self.append(&done);
                }
            }
        }
        if marker {
            if self.stats.marker_bit.is_none() {
                self.stats.marker_bit = Some(true);
            }
            self.finish(out);
        }
        Ok(())
    }

    /// Ends the open unit, if any, at the end of the stream.
    pub fn flush(&mut self, out: &mut Vec<AccessUnit>) {
        self.finish(out);
    }

    /// Adds one NAL unit (header included) to the open access unit, the
    /// known parameter sets before an IRAP picture that lacks them, unless
    /// that makes the unit oversize. A parameter set after the unit's
    /// first VCL NAL unit is noted but left out: it would start a new
    /// access unit (§7.4.2.4.4), cutting the picture short in decoders
    /// (see [`super::packet`]).
    fn append(&mut self, unit: &[u8]) {
        let Some(unit_type) = nal::unit_type(unit) else {
            return;
        };
        let mut sets = Vec::new();
        match unit_type {
            nal::FD_NUT => return,
            nal::VPS_NUT => {
                self.sets.observe(unit);
                if self.au_vcl_seen {
                    return;
                }
                self.au_has_sets[0] = true;
            }
            nal::SPS_NUT => {
                if self.sets.observe(unit) {
                    self.au_sps = sps::parse_sps(unit).ok();
                }
                if self.au_vcl_seen {
                    return;
                }
                self.au_has_sets[1] = true;
            }
            nal::PPS_NUT => {
                self.sets.observe(unit);
                if self.au_vcl_seen {
                    return;
                }
                self.au_has_sets[2] = true;
            }
            nal::PREFIX_SEI_NUT if sps::has_recovery_point(unit) => self.au_keyframe = true,
            nal::RASL_N | nal::RASL_R => self.rasl_seen = true,
            _ if nal::is_irap(unit_type) => {
                if self.au_has_sets != [true; 3] && self.sets.annex_b_append(&mut sets) {
                    self.au_has_sets = [true; 3];
                }
                self.au_keyframe |= joinable(unit_type, self.rasl_seen);
            }
            _ => {}
        }
        if nal::is_vcl(unit_type) {
            self.au_vcl_seen = true;
        }
        let extra = sets
            .len()
            .saturating_add(crate::h264::nal::START_CODE.len())
            .saturating_add(unit.len());
        if self.reserve(extra) {
            self.au.extend_from_slice(&sets);
            crate::h264::nal::annex_b_append(&mut self.au, unit);
        }
    }

    /// Emits or drops the open unit and resets for the next.
    fn finish(&mut self, out: &mut Vec<AccessUnit>) {
        let Some(ts) = self.au_ts.take() else {
            return;
        };
        let payload = std::mem::take(&mut self.au);
        let keyframe = std::mem::take(&mut self.au_keyframe);
        let damaged = std::mem::take(&mut self.au_damaged);
        let oversize = std::mem::take(&mut self.au_oversize);
        self.au_has_sets = [false; 3];
        self.au_vcl_seen = false;
        self.fragment = None;
        if oversize {
            self.stats.dropped_oversize = self.stats.dropped_oversize.saturating_add(1);
            return;
        }
        if damaged {
            self.stats.dropped_lost = self.stats.dropped_lost.saturating_add(1);
            return;
        }
        if payload.is_empty() {
            return;
        }
        let unwrapped = self.unwrapper.unwrap(ts);
        if self.max_ts.is_some_and(|max| unwrapped < max) {
            self.stats.b_frames = true;
        }
        self.max_ts = Some(self.max_ts.map_or(unwrapped, |max| max.max(unwrapped)));
        self.stats.frames = self.stats.frames.saturating_add(1);
        if keyframe {
            self.stats.keyframes = self.stats.keyframes.saturating_add(1);
        }
        // A new SPS in a unit that was dropped is reported with the next
        // unit that is not: the sets changed already.
        let sps = self.au_sps.take();
        out.push(AccessUnit {
            ts,
            keyframe,
            payload: Bytes::from(payload),
            sps,
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::super::packet::PacketNormalizer;
    use super::super::sps::test_data::{pps, recovery_point_sei, sps, vps};
    use super::*;

    fn picture(unit_type: u8, len: usize) -> Vec<u8> {
        [unit_type << 1, 0x01]
            .into_iter()
            .chain(std::iter::repeat_n(0xab, len))
            .collect()
    }

    fn idr(len: usize) -> Vec<u8> {
        picture(nal::IDR_W_RADL, len)
    }

    fn slice(len: usize) -> Vec<u8> {
        picture(1, len)
    }

    fn annex_b(units: &[&[u8]]) -> Bytes {
        let mut out = Vec::new();
        for unit in units {
            crate::h264::nal::annex_b_append(&mut out, unit);
        }
        Bytes::from(out)
    }

    struct Feed {
        d: Depacketizer,
        seq: u16,
        out: Vec<AccessUnit>,
    }

    impl Feed {
        fn new() -> Self {
            Self {
                d: Depacketizer::new(4 << 20, ParameterSets::default()),
                seq: 100,
                out: Vec::new(),
            }
        }

        fn push(&mut self, ts: u32, marker: bool, payload: &[u8]) {
            self.d
                .push(self.seq, ts, marker, payload, &mut self.out)
                .unwrap();
            self.seq = self.seq.wrapping_add(1);
        }

        fn take(&mut self) -> Vec<AccessUnit> {
            std::mem::take(&mut self.out)
        }
    }

    #[test]
    fn parameter_sets_between_slice_segments_are_left_out_h265_7_4_2_4_4() {
        // A Reolink camera's IDR picture (observed 2026-10-09): three slice
        // segments, VPS, SPS and PPS sent again before each; the last PPS
        // differs, and is still noted.
        let mut other_pps = pps();
        other_pps.extend([0x00, 0x80]);
        let mut f = Feed::new();
        for unit in [
            vps(),
            sps(640, 480),
            pps(),
            idr(20),
            vps(),
            sps(640, 480),
            pps(),
            idr(5),
            vps(),
            sps(640, 480),
            other_pps.clone(),
        ] {
            f.push(1000, false, &unit);
        }
        f.push(1000, true, &idr(7));
        let units = f.take();
        assert_eq!(units.len(), 1);
        assert!(units[0].keyframe);
        assert_eq!(
            units[0].payload,
            annex_b(&[&vps(), &sps(640, 480), &pps(), &idr(20), &idr(5), &idr(7)])
        );
        assert_eq!(f.d.parameter_sets().pps.as_deref(), Some(&other_pps[..]));
        // The next unit's own sets stay.
        for unit in [vps(), sps(640, 480), other_pps.clone()] {
            f.push(2000, false, &unit);
        }
        f.push(2000, true, &idr(3));
        assert_eq!(
            f.take()[0].payload,
            annex_b(&[&vps(), &sps(640, 480), &other_pps, &idr(3)])
        );
    }

    #[test]
    fn units_complete_on_the_marker_with_parameter_sets_before_the_irap_picture() {
        let mut f = Feed::new();
        f.push(1000, false, &vps());
        f.push(1000, false, &sps(640, 480));
        f.push(1000, false, &pps());
        f.push(1000, true, &idr(20));
        let units = f.take();
        assert_eq!(units.len(), 1);
        let unit = &units[0];
        assert!(unit.keyframe);
        assert_eq!(unit.ts, 1000);
        assert_eq!(
            unit.payload,
            annex_b(&[&vps(), &sps(640, 480), &pps(), &idr(20)])
        );
        assert_eq!(unit.sps.unwrap().width, 640);
        assert_eq!(f.d.stats().marker_bit, Some(true));
        // A P frame.
        f.push(4000, true, &slice(10));
        let units = f.take();
        assert!(!units[0].keyframe && units[0].sps.is_none());
        assert_eq!(units[0].payload, annex_b(&[&slice(10)]));
        // An IDR without in-band sets gets the known ones inserted.
        f.push(7000, true, &idr(5));
        let units = f.take();
        assert!(units[0].keyframe);
        assert_eq!(
            units[0].payload,
            annex_b(&[&vps(), &sps(640, 480), &pps(), &idr(5)])
        );
        assert!(units[0].sps.is_none(), "unchanged SPS");
        // One with only the SPS in-band gets all three inserted before it.
        f.push(7500, false, &sps(640, 480));
        f.push(7500, true, &idr(5));
        assert_eq!(
            f.take()[0].payload,
            annex_b(&[&sps(640, 480), &vps(), &sps(640, 480), &pps(), &idr(5)])
        );
        // An aggregate with everything, and a resolution change.
        let ap = nal::aggregate(&[&vps(), &sps(1280, 720), &pps(), &idr(5)]);
        f.push(10_000, true, &ap);
        let units = f.take();
        assert_eq!(units[0].sps.unwrap().width, 1280);
        assert_eq!(
            units[0].payload,
            annex_b(&[&vps(), &sps(1280, 720), &pps(), &idr(5)])
        );
        assert_eq!(f.d.stats().frames, 5);
        assert_eq!(f.d.stats().keyframes, 4);
        assert!(!f.d.stats().b_frames);
    }

    #[test]
    fn a_cra_is_a_keyframe_until_rasl_pictures_show_up_h265_8_1_3() {
        let mut f = Feed::new();
        f.push(1, true, &picture(nal::CRA_NUT, 4));
        assert!(f.take()[0].keyframe);
        f.push(2, true, &picture(nal::RASL_N, 4));
        assert!(!f.take()[0].keyframe);
        f.push(3, true, &picture(nal::CRA_NUT, 4));
        assert!(!f.take()[0].keyframe);
        f.push(4, true, &picture(nal::BLA_W_LP, 4));
        assert!(f.take()[0].keyframe);
        let mut f = Feed::new();
        f.push(1, true, &picture(nal::RASL_R, 4));
        f.push(2, true, &picture(nal::CRA_NUT, 4));
        assert!(!f.take()[1].keyframe);
    }

    #[test]
    fn fragments_reassemble_and_a_lost_packet_drops_the_unit_rfc7798_4_4_3() {
        let mut f = Feed::new();
        let big = idr(3000);
        let parts = nal::fragment(&big, 1000);
        for (i, part) in parts.iter().enumerate() {
            f.push(1000, i + 1 == parts.len(), part);
        }
        let units = f.take();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].payload, annex_b(&[&big]));
        assert_eq!(f.d.stats().dropped_lost, 0);
        // Lose the middle fragment of the next one.
        f.push(4000, false, &parts[0]);
        f.seq = f.seq.wrapping_add(1);
        f.push(4000, true, &parts[2]);
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_lost, 1);
        // A fragment without a start is a damaged unit too.
        f.push(7000, true, &parts[1]);
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_lost, 2);
        f.push(10_000, true, &slice(3));
        assert_eq!(f.take().len(), 1);
    }

    #[test]
    fn a_new_sps_in_a_lost_unit_is_reported_with_the_next_unit() {
        let with = |sps: &[u8]| nal::aggregate(&[&vps(), sps, &pps(), &idr(5)]).to_vec();
        let mut f = Feed::new();
        f.push(1000, true, &with(&sps(640, 480)));
        assert_eq!(f.take()[0].sps.unwrap().width, 640);
        // The resolution switch arrives in a unit that loses a packet.
        f.push(4000, false, &with(&sps(1280, 720)));
        f.seq = f.seq.wrapping_add(1);
        f.push(4000, true, &idr(5));
        assert!(f.take().is_empty());
        // The next keyframe repeats the same SPS: still a new sequence.
        f.push(7000, true, &with(&sps(1280, 720)));
        assert_eq!(f.take()[0].sps.unwrap().width, 1280);
    }

    #[test]
    fn a_camera_without_marker_bits_completes_on_the_timestamp() {
        let mut f = Feed::new();
        f.push(1, false, &slice(3));
        f.push(1, false, &slice(3));
        assert!(f.take().is_empty());
        f.push(2, false, &slice(3));
        let units = f.take();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].ts, 1);
        assert_eq!(f.d.stats().marker_bit, Some(false));
        f.d.flush(&mut f.out);
        assert_eq!(f.take().len(), 1);
        f.d.flush(&mut f.out);
        assert!(f.take().is_empty(), "nothing open");
    }

    #[test]
    fn recovery_points_count_as_keyframes_and_b_frames_are_noticed() {
        let mut f = Feed::new();
        f.push(1000, false, &recovery_point_sei());
        f.push(1000, true, &slice(3));
        assert!(f.take()[0].keyframe);
        // Another prefix SEI (user data unregistered) is no keyframe.
        f.push(
            1000,
            false,
            &[nal::PREFIX_SEI_NUT << 1, 0x01, 5, 1, 0xaa, 0x80],
        );
        f.push(1000, true, &slice(3));
        assert!(!f.take()[0].keyframe);
        assert!(
            !f.d.stats().b_frames,
            "the same timestamp twice is no reordering"
        );
        f.push(7000, true, &slice(3));
        f.push(4000, true, &slice(3));
        f.take();
        assert!(f.d.stats().b_frames);
        assert_eq!(f.d.stats().frames, 4);
    }

    #[test]
    fn oversize_units_filler_and_violations_are_handled() {
        let mut f = Feed::new();
        f.d = Depacketizer::new(100, ParameterSets::default());
        f.push(1, true, &slice(200));
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_oversize, 1);
        // Exactly the limit: a 4-byte start code and 96 bytes of unit.
        f.push(1, true, &slice(94));
        assert_eq!(f.take()[0].payload.len(), 100);
        f.push(2, false, &[nal::FD_NUT << 1, 0x01, 0xff]);
        f.push(2, true, &slice(3));
        assert_eq!(f.take()[0].payload, annex_b(&[&slice(3)]));
        // A unit of filler alone is nothing at all.
        f.push(3, true, &[nal::FD_NUT << 1, 0x01, 0xff]);
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().frames, 2);
        let mut out = Vec::new();
        assert_eq!(
            f.d.push(f.seq, 3, false, &[nal::PACI << 1, 1], &mut out),
            Err(PayloadError::UnsupportedType(nal::PACI))
        );
        f.seq += 1;
        f.push(3, true, &slice(3));
        assert!(f.take().is_empty(), "damaged by the violation");
        assert_eq!(f.d.stats().violations, 1);
        assert_eq!(
            f.d.push(f.seq, 4, true, &[0x60, 0x01, 0x00, 0x09, 0x40], &mut out),
            Err(PayloadError::Truncated)
        );
        f.seq += 1;
        assert_eq!(f.d.stats().violations, 2);
        assert_eq!(
            f.d.push(f.seq, 5, true, &[], &mut out),
            Err(PayloadError::Empty)
        );
        assert_eq!(f.d.stats().violations, 3);
        assert!(f.d.parameter_sets().sps.is_none());
        // A unit too short for its header is skipped, not appended.
        let mut au = Vec::new();
        f.d.append(&[]);
        f.d.flush(&mut au);
        assert!(au.is_empty());
    }

    #[test]
    fn a_unit_that_never_ends_is_held_to_the_limit_and_dropped_once_over_it() {
        // Single units at one timestamp, never a marker: 205 bytes each
        // with the start code, so the fifth outgrows 1000.
        let mut f = Feed::new();
        f.d = Depacketizer::new(1000, ParameterSets::default());
        for _ in 0..4 {
            f.push(1, false, &slice(199));
        }
        assert_eq!(f.d.buffered(), 820);
        for _ in 0..100 {
            f.push(1, false, &slice(199));
            assert_eq!(f.d.buffered(), 0, "the rest of the unit is ignored");
        }
        // The next timestamp ends it: dropped as oversize, not as lost.
        f.push(2, true, &slice(3));
        let units = f.take();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].ts, 2);
        assert_eq!(f.d.stats().dropped_oversize, 1);
        assert_eq!(f.d.stats().dropped_lost, 0);
        assert_eq!(f.d.buffered(), 0);
        // A fragment start, then continuations that never end it.
        let parts = nal::fragment(&idr(100_000), 300);
        f.push(3, false, &parts[0]);
        assert_eq!(f.d.buffered(), parts[0].len() - 1);
        for part in &parts[1..20] {
            f.push(3, false, part);
            assert!(f.d.buffered() <= 1000, "{}", f.d.buffered());
        }
        assert_eq!(f.d.buffered(), 0);
        f.push(3, true, parts.last().unwrap());
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_oversize, 2);
        assert_eq!(f.d.stats().dropped_lost, 0, "counted as oversize");
        // A fragmented unit within the limit still reassembles, also
        // after the earlier units' single units.
        let small = slice(800);
        let parts = nal::fragment(&small, 300);
        f.push(4, false, &slice(10));
        for (i, part) in parts.iter().enumerate() {
            f.push(4, i + 1 == parts.len(), part);
        }
        assert_eq!(f.take()[0].payload, annex_b(&[&slice(10), &small]));
        assert_eq!(f.d.stats().violations, 0);
    }

    #[test]
    fn the_limit_counts_inserted_parameter_sets_and_fragment_headers() {
        let mut sets = ParameterSets::default();
        for unit in [vps(), sps(640, 480), pps()] {
            sets.observe(&unit);
        }
        let mut f = Feed::new();
        f.d = Depacketizer::new(100, sets);
        // The IDR alone would fit; with the inserted sets it does not.
        f.push(1, true, &idr(94));
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_oversize, 1);
        // A fragment start that fills the limit opens, one more byte does not.
        let mut start = vec![0x62, 0x01, 0x80 | nal::IDR_W_RADL];
        start.extend(std::iter::repeat_n(0xab, 98));
        f.push(2, false, &start);
        assert_eq!(f.d.buffered(), 100);
        f.push(2, false, &[0x62, 0x01, nal::IDR_W_RADL, 0xab]);
        assert_eq!(f.d.buffered(), 0);
        f.d.flush(&mut f.out);
        assert_eq!(f.d.stats().dropped_oversize, 2);
        start.push(0xab);
        f.push(3, false, &start);
        assert_eq!(f.d.buffered(), 0);
        f.d.flush(&mut f.out);
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_oversize, 3);
    }

    #[test]
    fn a_fragment_start_while_one_is_open_damages_the_unit_rfc7798_4_4_3() {
        let mut f = Feed::new();
        let parts = nal::fragment(&idr(3000), 1000);
        f.push(1000, false, &parts[0]);
        f.push(1000, false, &parts[0]);
        f.push(1000, false, &parts[1]);
        f.push(1000, true, &parts[2]);
        assert!(
            f.take().is_empty(),
            "the first fragmented unit lost its end"
        );
        assert_eq!(f.d.stats().dropped_lost, 1);
        assert_eq!(f.d.stats().violations, 1);
        f.push(4000, true, &slice(3));
        assert_eq!(f.take().len(), 1);
    }

    #[test]
    fn the_packet_layer_output_depacketizes_to_the_same_units() {
        let mut normalizer = PacketNormalizer::new(300, ParameterSets::default());
        let mut sets = ParameterSets::default();
        for unit in [vps(), sps(640, 480), pps()] {
            sets.observe(&unit);
        }
        let mut depacketizer = Depacketizer::new(4 << 20, sets.clone());
        let mut out = Vec::new();
        let mut seq = 0_u16;
        let frames: Vec<(u32, Vec<Vec<u8>>)> = vec![
            (1, vec![vps(), sps(640, 480), pps(), idr(700)]),
            (2, vec![slice(400)]),
            (3, vec![nal::aggregate(&[&slice(50), &slice(60)]).to_vec()]),
            (4, vec![idr(10)]),
        ];
        for (ts, packets) in &frames {
            for (i, packet) in packets.iter().enumerate() {
                let marker = i + 1 == packets.len();
                let mut emitted = Vec::new();
                normalizer
                    .normalize(*ts, marker, &Bytes::copy_from_slice(packet), &mut emitted)
                    .unwrap();
                for packet in emitted {
                    depacketizer
                        .push(seq, *ts, packet.marker, &packet.payload, &mut out)
                        .unwrap();
                    seq = seq.wrapping_add(1);
                }
            }
        }
        assert_eq!(out.len(), 4, "{out:?}");
        let (vps, sps, pps) = (vps(), sps(640, 480), pps());
        assert_eq!(
            out[0].payload,
            annex_b(&[&vps, &sps, &pps, &vps, &sps, &pps, &idr(700)])
        );
        assert_eq!(out[1].payload, annex_b(&[&slice(400)]));
        assert_eq!(out[2].payload, annex_b(&[&slice(50), &slice(60)]));
        assert_eq!(out[3].payload, annex_b(&[&vps, &sps, &pps, &idr(10)]));
        assert!(out[0].keyframe && !out[1].keyframe && out[3].keyframe);
        assert_eq!(depacketizer.stats().dropped_lost, 0);
        assert!(normalizer.stats().resplit >= 2);
    }
}
