//! The frame layer of H.264 normalization, on the side branch: RTP packets
//! in, complete access units out as Annex B with the parameter sets
//! in-band before every IDR, keyframes recognized (IDR or recovery point),
//! lost or oversize units dropped and counted, and the camera's habits
//! (marker bit, B-frames) observed.
//! It never holds more than `max_frame_bytes` for the open unit: a unit
//! that outgrows the limit is dropped the moment it does, and the rest of
//! it is ignored until it ends.
//!
//! Implements RFC 6184 §5.1 (marker bit), §5.6, §5.7.1 and §5.8
//! (depacketization), ISO/IEC 14496-10 §7.4.1.2.3 (access unit order:
//! parameter sets before the IDR) and Annex B. Feeds the source's packets
//! as they came, never the packet layer's output.

use bytes::Bytes;
use lotse_core::media::TimestampUnwrapper;

use super::nal::{self, ParameterSets, Payload, PayloadError};
use super::sps::{self, SpsInfo};

/// One complete access unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    /// The RTP timestamp, as sent.
    pub ts: u32,
    /// An IDR picture, or a recovery point on intra-refresh cameras.
    pub keyframe: bool,
    /// Annex B, parameter sets in-band before an IDR.
    pub payload: Bytes,
    /// The SPS changed in this unit: a new sequence (resolution switch).
    pub sps: Option<SpsInfo>,
}

/// What the depacketizer counted and observed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameStats {
    /// Access units emitted.
    pub frames: u64,
    /// Keyframes among them.
    pub keyframes: u64,
    /// Units dropped because a packet was lost inside them.
    pub dropped_lost: u64,
    /// Units dropped as larger than the limit.
    pub dropped_oversize: u64,
    /// Payloads that violate packetization mode 1.
    pub violations: u64,
    /// Whether the camera ends access units with the marker bit; `None`
    /// until the first unit completed.
    pub marker_bit: Option<bool>,
    /// Timestamps went backwards within an epoch: B-frames.
    pub b_frames: bool,
}

/// A fragmented unit under reassembly.
#[derive(Debug)]
struct Fragmented {
    /// The unit so far, header included.
    unit: Vec<u8>,
}

/// The frame-layer depacketizer of one video track.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts about the open unit and the last packet, as in the H.265 depacketizer"
)]
pub struct Depacketizer {
    /// Units larger than this are dropped.
    max_frame_bytes: usize,
    /// The latest parameter sets.
    sets: ParameterSets,
    /// The unit under construction, Annex B.
    au: Vec<u8>,
    /// Its timestamp.
    au_ts: Option<u32>,
    /// It holds an IDR or a recovery point.
    au_keyframe: bool,
    /// It already holds both parameter sets.
    au_has_sets: (bool, bool),
    /// It holds a VCL NAL unit: a parameter set from here on is left out.
    au_vcl_seen: bool,
    /// A packet inside it was lost.
    au_damaged: bool,
    /// It outgrew `max_frame_bytes`: emptied, and the rest of it is
    /// ignored until it ends.
    au_oversize: bool,
    /// The SPS changed inside it.
    au_sps: Option<SpsInfo>,
    /// The fragmented unit under reassembly.
    fragment: Option<Fragmented>,
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
            au: Vec::new(),
            au_ts: None,
            au_keyframe: false,
            au_has_sets: (false, false),
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
            .saturating_add(self.fragment.as_ref().map_or(0, |open| open.unit.len()))
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

    /// Feeds one source packet; complete units are appended to `out`. A
    /// payload that violates packetization mode 1 is an error after the
    /// unit it belongs to was marked damaged. A fragment start while
    /// another fragmented unit is open is counted as a violation and
    /// damages the unit, but is no error: the start itself is readable.
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
            Err(err) => {
                self.stats.violations = self.stats.violations.saturating_add(1);
                self.au_damaged = true;
                self.fragment = None;
                return Err(err);
            }
        };
        self.au_ts = Some(ts);
        match parsed {
            Payload::Single(unit) => self.append(unit),
            Payload::StapA(units) => {
                for unit in units {
                    match unit {
                        Ok(unit) => self.append(unit),
                        Err(err) => {
                            self.stats.violations = self.stats.violations.saturating_add(1);
                            self.au_damaged = true;
                            return Err(err);
                        }
                    }
                }
            }
            Payload::FuA {
                nal_header,
                start,
                end,
                fragment,
            } => {
                if start {
                    if self.fragment.take().is_some() {
                        // RFC 6184 §5.8: nothing is sent between a unit's
                        // first and last fragment, so the open unit lost
                        // its end; the access unit is incomplete.
                        self.stats.violations = self.stats.violations.saturating_add(1);
                        self.au_damaged = true;
                    }
                    // The reconstructed header, then the fragment.
                    if self.reserve(fragment.len().saturating_add(1)) {
                        let mut unit = Vec::with_capacity(fragment.len().saturating_add(1));
                        unit.push(nal_header);
                        unit.extend_from_slice(fragment);
                        self.fragment = Some(Fragmented { unit });
                    }
                } else if self.fragment.is_none() {
                    // A fragment without its start: lost, or a violation
                    // (or the rest of an oversize unit, counted as such).
                    self.au_damaged = true;
                } else if self.reserve(fragment.len())
                    && let Some(open) = self.fragment.as_mut()
                {
                    open.unit.extend_from_slice(fragment);
                }
                if end && let Some(done) = self.fragment.take() {
                    self.append(&done.unit);
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
    /// known parameter sets before an IDR that lacks them, unless that
    /// makes the unit oversize.
    fn append(&mut self, unit: &[u8]) {
        // No caller passes an empty unit; one would be dropped as filler.
        let header = unit.first().copied().unwrap_or(nal::NAL_FILLER);
        let mut sets = Vec::new();
        let unit_type = nal::nal_type(header);
        match unit_type {
            nal::NAL_FILLER => return,
            // A parameter set after the unit's first VCL NAL unit is noted
            // but left out: it would start a new access unit (ISO/IEC
            // 14496-10 §7.4.1.2.3), cutting the picture short in decoders
            // (see `crate::h265::packet`).
            nal::NAL_SPS => {
                if self.sets.observe(unit) {
                    self.au_sps = sps::parse_sps(unit).ok();
                }
                if self.au_vcl_seen {
                    return;
                }
                self.au_has_sets.0 = true;
            }
            nal::NAL_PPS => {
                self.sets.observe(unit);
                if self.au_vcl_seen {
                    return;
                }
                self.au_has_sets.1 = true;
            }
            nal::NAL_IDR => {
                if self.au_has_sets != (true, true) && self.sets.annex_b_append(&mut sets) {
                    self.au_has_sets = (true, true);
                }
                self.au_keyframe = true;
            }
            nal::NAL_SEI if sps::has_recovery_point(unit) => self.au_keyframe = true,
            _ => {}
        }
        if nal::is_vcl(unit_type) {
            self.au_vcl_seen = true;
        }
        let extra = sets
            .len()
            .saturating_add(nal::START_CODE.len())
            .saturating_add(unit.len());
        if self.reserve(extra) {
            self.au.extend_from_slice(&sets);
            nal::annex_b_append(&mut self.au, unit);
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
        self.au_has_sets = (false, false);
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
    use super::super::sps::test_data::{pps, recovery_point_sei, sps};
    use super::*;

    fn idr(len: usize) -> Vec<u8> {
        std::iter::once(0x65_u8)
            .chain(std::iter::repeat_n(0xab, len))
            .collect()
    }

    fn slice(len: usize) -> Vec<u8> {
        std::iter::once(0x41_u8)
            .chain(std::iter::repeat_n(0x11, len))
            .collect()
    }

    fn annex_b(units: &[&[u8]]) -> Bytes {
        let mut out = Vec::new();
        for unit in units {
            nal::annex_b_append(&mut out, unit);
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
    fn parameter_sets_between_slices_are_left_out_iso14496_10_7_4_1_2_3() {
        // An IDR picture of three slices with SPS and PPS sent again before
        // each, as a Reolink camera does in H.265 (observed 2026-10-09); the
        // last PPS differs, and is still noted.
        let mut other_pps = pps();
        other_pps.extend([0x00, 0x80]);
        let mut f = Feed::new();
        for unit in [
            sps(640, 480),
            pps(),
            idr(20),
            sps(640, 480),
            pps(),
            idr(5),
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
            annex_b(&[&sps(640, 480), &pps(), &idr(20), &idr(5), &idr(7)])
        );
        assert_eq!(f.d.parameter_sets().pps.as_deref(), Some(&other_pps[..]));
        // The next unit's own sets stay.
        f.push(2000, false, &sps(640, 480));
        f.push(2000, false, &other_pps);
        f.push(2000, true, &idr(3));
        assert_eq!(
            f.take()[0].payload,
            annex_b(&[&sps(640, 480), &other_pps, &idr(3)])
        );
    }

    #[test]
    fn units_complete_on_the_marker_with_parameter_sets_before_the_idr() {
        let mut f = Feed::new();
        f.push(1000, false, &sps(640, 480));
        f.push(1000, false, &pps());
        f.push(1000, true, &idr(20));
        let units = f.take();
        assert_eq!(units.len(), 1);
        let unit = &units[0];
        assert!(unit.keyframe);
        assert_eq!(unit.ts, 1000);
        assert_eq!(unit.payload, annex_b(&[&sps(640, 480), &pps(), &idr(20)]));
        assert_eq!(unit.sps.unwrap().width, 640);
        assert_eq!(f.d.stats().marker_bit, Some(true));
        // A P frame from single units.
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
            annex_b(&[&sps(640, 480), &pps(), &idr(5)])
        );
        assert!(units[0].sps.is_none(), "unchanged SPS");
        // A STAP-A with everything, and a resolution change.
        let stap = nal::stap_a(&[&sps(1280, 720), &pps(), &idr(5)]);
        f.push(10_000, true, &stap);
        let units = f.take();
        assert_eq!(units[0].sps.unwrap().width, 1280);
        assert_eq!(
            units[0].payload,
            annex_b(&[&sps(1280, 720), &pps(), &idr(5)])
        );
        assert_eq!(f.d.stats().frames, 4);
        assert_eq!(f.d.stats().keyframes, 3);
        assert!(!f.d.stats().b_frames);
    }

    #[test]
    fn fragments_reassemble_and_a_lost_packet_drops_the_unit_rfc6184_5_8() {
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
        // The next whole unit is fine.
        f.push(10_000, true, &slice(3));
        assert_eq!(f.take().len(), 1);
    }

    #[test]
    fn a_new_sps_in_a_lost_unit_is_reported_with_the_next_unit() {
        let mut f = Feed::new();
        f.push(1000, true, &stap_with(&sps(640, 480)));
        assert_eq!(f.take()[0].sps.unwrap().width, 640);
        // The resolution switch arrives in a unit that loses a packet.
        f.push(4000, false, &stap_with(&sps(1280, 720)));
        f.seq = f.seq.wrapping_add(1);
        f.push(4000, true, &idr(5));
        assert!(f.take().is_empty());
        // The next keyframe repeats the same SPS: still a new sequence.
        f.push(7000, true, &stap_with(&sps(1280, 720)));
        assert_eq!(f.take()[0].sps.unwrap().width, 1280);
    }

    fn stap_with(sps: &[u8]) -> Vec<u8> {
        nal::stap_a(&[sps, &pps(), &idr(5)]).to_vec()
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
        f.push(7000, true, &slice(3));
        f.push(4000, true, &slice(3));
        f.take();
        assert!(f.d.stats().b_frames);
        assert_eq!(f.d.stats().frames, 3);
    }

    #[test]
    fn oversize_units_filler_and_violations_are_handled() {
        let mut f = Feed::new();
        f.d = Depacketizer::new(100, ParameterSets::default());
        f.push(1, true, &slice(200));
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_oversize, 1);
        f.push(2, false, &[0x0c, 0xff]);
        f.push(2, true, &slice(3));
        assert_eq!(f.take()[0].payload, annex_b(&[&slice(3)]));
        // A unit of filler alone is no frame.
        f.push(10, true, &[0x0c, 0xff]);
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().frames, 1);
        let mut out = Vec::new();
        assert_eq!(
            f.d.push(f.seq, 3, false, &[nal::STAP_B], &mut out),
            Err(PayloadError::UnsupportedType(nal::STAP_B))
        );
        f.seq += 1;
        f.push(3, true, &slice(3));
        assert!(f.take().is_empty(), "damaged by the violation");
        assert_eq!(f.d.stats().violations, 1);
        assert_eq!(
            f.d.push(f.seq, 4, true, &[0x78, 0x00, 0x09, 0x67], &mut out),
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
    }

    #[test]
    fn a_unit_that_never_ends_is_held_to_the_limit_and_dropped_once_over_it() {
        // Single units at one timestamp, never a marker: 205 bytes each
        // with the start code, so the fifth outgrows 1000.
        let mut f = Feed::new();
        f.d = Depacketizer::new(1000, ParameterSets::default());
        for _ in 0..4 {
            f.push(1, false, &slice(200));
        }
        assert_eq!(f.d.buffered(), 820);
        for _ in 0..100 {
            f.push(1, false, &slice(200));
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
        // An FU-A start, then continuations that never end it.
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
    fn the_limit_counts_start_codes_and_inserted_parameter_sets() {
        let mut sets = ParameterSets::default();
        sets.observe(&sps(640, 480));
        sets.observe(&pps());
        // Exactly the limit: a 4-byte start code and 96 bytes of unit.
        let mut f = Feed::new();
        f.d = Depacketizer::new(100, sets);
        f.push(1, true, &slice(95));
        assert_eq!(f.take()[0].payload.len(), 100);
        // The IDR alone would fit; with the inserted sets it does not.
        f.push(2, true, &idr(95));
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_oversize, 1);
        // A fragment start that fills the limit opens, one more byte does not.
        let mut start = vec![0x7c, 0x85];
        start.extend(std::iter::repeat_n(0xab, 99));
        f.push(3, false, &start);
        assert_eq!(f.d.buffered(), 100);
        f.push(3, false, &[0x7c, 0x05, 0xab]);
        assert_eq!(f.d.buffered(), 0);
        f.d.flush(&mut f.out);
        assert_eq!(f.d.stats().dropped_oversize, 2);
        start.push(0xab);
        f.push(4, false, &start);
        assert_eq!(f.d.buffered(), 0);
        f.d.flush(&mut f.out);
        assert!(f.take().is_empty());
        assert_eq!(f.d.stats().dropped_oversize, 3);
    }

    #[test]
    fn a_fragment_start_while_one_is_open_damages_the_unit_rfc6184_5_8() {
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
        // What the live path emits (re-split, sets inserted) still assembles
        // into the frames the source sent, as a viewer sees them: renumbered,
        // with the inserted parameter sets in-band.
        let mut n = PacketNormalizer::new(300, ParameterSets::default());
        let mut sets = ParameterSets::default();
        sets.observe(&sps(640, 480));
        sets.observe(&pps());
        let mut d = Depacketizer::new(4 << 20, sets.clone());
        let mut out = Vec::new();
        let mut seq = 0_u16;
        let frames: Vec<(u32, Vec<Vec<u8>>)> = vec![
            (1, vec![sps(640, 480), pps(), idr(700)]),
            (2, vec![slice(400)]),
            (3, vec![nal::stap_a(&[&slice(50), &slice(60)]).to_vec()]),
            (4, vec![idr(10)]),
        ];
        for (ts, packets) in &frames {
            for (i, packet) in packets.iter().enumerate() {
                let marker = i + 1 == packets.len();
                let mut normalized = Vec::new();
                n.normalize(
                    *ts,
                    marker,
                    &Bytes::copy_from_slice(packet),
                    &mut normalized,
                )
                .unwrap();
                for p in normalized {
                    d.push(seq, *ts, p.marker, &p.payload, &mut out).unwrap();
                    seq = seq.wrapping_add(1);
                }
            }
        }
        assert_eq!(out.len(), 4, "{out:?}");
        // The camera's own sets, then the inserted aggregate, then the IDR.
        assert_eq!(
            out[0].payload,
            annex_b(&[&sps(640, 480), &pps(), &sps(640, 480), &pps(), &idr(700)])
        );
        assert_eq!(out[1].payload, annex_b(&[&slice(400)]));
        assert_eq!(out[2].payload, annex_b(&[&slice(50), &slice(60)]));
        assert_eq!(out[3].payload, annex_b(&[&sps(640, 480), &pps(), &idr(10)]));
        assert!(out[0].keyframe && !out[1].keyframe && out[3].keyframe);
        assert_eq!(d.stats().dropped_lost, 0);
        assert!(n.stats().resplit >= 2);
    }
}
