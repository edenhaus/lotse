//! The packet layer of H.265 normalization, on the live path: parameter
//! sets guaranteed before every IRAP picture and kept out from between
//! its slice segments, filler dropped, keyframe and frame boundaries
//! marked, and packets larger than the datagram target re-split into
//! fragmentation units, so a viewer can join at any `keyframe_start` and
//! every packet fits the tunnels on the way.
//!
//! The H.265 twin of [`crate::h264::packet`]. Implements RFC 7798 §4.1
//! (the marker bit ends the access unit), §4.4.2 (aggregation packets for
//! parameter-set insertion) and §4.4.3 (re-splitting fragmentation units),
//! and ITU-T H.265 §7.4.2.4.4 (VPS, SPS and PPS before the IRAP picture
//! that uses them, and a parameter set after a picture's first VCL NAL
//! unit starts a new access unit). Runs once per source packet; its
//! output is what every viewer gets, so nothing here is per viewer.
//!
//! A parameter set between the slice segments of one picture is dropped
//! (noted first, so a new SPS still counts). A Reolink camera's 4K main
//! stream (observed 2026-10-09) codes each picture as three slice segments
//! and repeats VPS, SPS and PPS before every one of them. By §7.4.2.4.4
//! the repeat ends the picture after its first segment, which is how
//! decoders take it. Chrome 154 (`media/gpu/h265_decoder.cc`, read
//! 2026-10-09) calls `FinishPrevFrameIfPresent` at every VPS, SPS and PPS,
//! then fails the next segment as one "with `first_slice_segment_in_pic_flag`
//! equal to 0 without an active picture": its hardware decoder failed
//! every keyframe and, with no software H.265 decoder to fall back to, the
//! session showed nothing. ffmpeg 9.0.2 logs `PPS changed between slices`
//! and skips the segments, and `VideoToolbox` then fails the picture.
//! Safari 26 played the same stream, as `WebKit` moves the parameter sets
//! out of the sample. `media/gpu/h264_decoder.cc` does the same at an SPS or
//! PPS, so the H.264 normalizer applies the rule too.
//!
//! Fragments too large for the target are re-split filling every packet:
//! the bytes left over from one source fragment go out with the next
//! fragment of the same unit, so a unit takes as few packets as the
//! target allows. Chrome assembles no frame of 2048 packets or more
//! (libwebrtc `modules/video_coding/h26x_packet_buffer.cc`, `kBufferSize`,
//! observed 2026-10-03), and cutting each 1400-byte fragment of a camera
//! into a full packet and a short one doubled the Reolink Duo 3's 1.4 MB
//! keyframes to over 2000 packets.

use bytes::Bytes;

use super::nal::{self, ParameterSets, Payload, PayloadError};
use crate::h264::NormalizedPacket;
use crate::h264::packet::FrameTally;
pub use crate::h264::{FrameOverLimit, LIBWEBRTC_MAX_FRAME_PACKETS, PacketStats};

/// A parsed payload sorted for emission.
struct Classified {
    /// The payloads to emit, in order.
    payloads: Vec<Bytes>,
    /// The payload starts a picture a viewer can join at.
    keyframe: bool,
    /// It carries all three parameter sets itself, so nothing is inserted.
    carries_sets: bool,
}

/// The fragmented unit being re-split: the bytes of its fragments not yet
/// sent, always less than one packet's worth between source packets.
#[derive(Debug)]
struct Carry {
    /// The unit's NAL header.
    nal_header: [u8; 2],
    /// The first fragment (start bit) is still to be sent.
    start: bool,
    /// The bytes not yet sent.
    bytes: Vec<u8>,
}

impl Classified {
    /// What is left of a dropped packet (filler, or a parameter set after
    /// the picture's first slice segment) that carries the marker bit:
    /// the smallest filler unit in the dropped one's layer and temporal
    /// sub-layer (ITU-T H.265 §7.3.2.8, only `rbsp_trailing_bits`), so
    /// the access unit still ends (RFC 7798 §4.1). Chrome assembles a
    /// frame only at a marker bit, and a delta frame only right after the
    /// frame before it (libwebrtc `h26x_packet_buffer.cc`,
    /// `rtp_seq_num_only_ref_finder.cc`, observed 2026-10-03): an access
    /// unit that lost its marker withheld every delta frame up to the
    /// next keyframe.
    fn end_of_unit(dropped: &[u8]) -> Self {
        let header = nal::header(dropped).unwrap_or([nal::FD_NUT << 1, 1]);
        // The forbidden bit and the layer id's high bit stay; the type is
        // filler (§7.3.1.2).
        let first = (header[0] & 0x81) | (nal::FD_NUT << 1);
        Self {
            payloads: vec![Bytes::from(vec![first, header[1], 0x80])],
            keyframe: false,
            carries_sets: false,
        }
    }
}

/// The packet-layer normalizer of one H.265 video track.
#[derive(Debug)]
pub struct PacketNormalizer {
    /// The largest payload to emit.
    max_payload: usize,
    /// The latest parameter sets.
    sets: ParameterSets,
    /// The stream sent skipped leading pictures: its CRA pictures are not
    /// joinable from then on.
    rasl_seen: bool,
    /// The timestamp of the last packet.
    last_ts: Option<u32>,
    /// The last packet did not end its access unit.
    au_open: bool,
    /// A VCL NAL unit of the open access unit went out: a parameter set
    /// from here on would start a new access unit (ITU-T H.265
    /// §7.4.2.4.4) and is dropped.
    au_vcl_seen: bool,
    /// The fragmented unit being re-split, between its fragments.
    carry: Option<Carry>,
    /// The packets of the current access unit.
    tally: FrameTally,
    /// The counters.
    stats: PacketStats,
}

/// Whether a unit of `unit_type` starts a picture a viewer can join at:
/// an IRAP picture (H.265 §3.73), except a CRA once the stream has shown
/// skipped leading pictures, which are not decodable after a join there
/// (§8.1.3).
pub(crate) const fn joinable(unit_type: u8, rasl_seen: bool) -> bool {
    nal::is_irap(unit_type) && !(unit_type == nal::CRA_NUT && rasl_seen)
}

impl PacketNormalizer {
    /// A normalizer emitting payloads of at most `max_payload` bytes,
    /// starting from the parameter sets the SDP announced, if any.
    pub fn new(max_payload: usize, sets: ParameterSets) -> Self {
        Self {
            max_payload: max_payload.max(4),
            sets,
            rasl_seen: false,
            last_ts: None,
            au_open: false,
            au_vcl_seen: false,
            carry: None,
            tally: FrameTally::default(),
            stats: PacketStats::default(),
        }
    }

    /// The latest parameter sets.
    pub const fn parameter_sets(&self) -> &ParameterSets {
        &self.sets
    }

    /// The counters.
    pub const fn stats(&self) -> PacketStats {
        self.stats
    }

    /// Normalizes one source packet into zero or more packets appended to
    /// `out`. A payload lotse cannot read is an error; the caller drops it.
    pub fn normalize(
        &mut self,
        ts: u32,
        marker: bool,
        payload: &Bytes,
        out: &mut Vec<NormalizedPacket>,
    ) -> Result<(), PayloadError> {
        let before = out.len();
        let result = self.packetize(ts, marker, payload, out);
        self.tally.add(out.get(before..).unwrap_or(&[]));
        if marker {
            self.tally.finish(&mut self.stats);
        }
        result
    }

    /// The access unit that last ended in more than
    /// [`LIBWEBRTC_MAX_FRAME_PACKETS`] packets, once: what some libwebrtc
    /// receivers may not assemble.
    pub const fn take_frame_over_limit(&mut self) -> Option<FrameOverLimit> {
        self.tally.take()
    }

    /// [`Self::normalize`] without the frame tally: the packets of one
    /// source packet.
    fn packetize(
        &mut self,
        ts: u32,
        marker: bool,
        payload: &Bytes,
        out: &mut Vec<NormalizedPacket>,
    ) -> Result<(), PayloadError> {
        self.stats.packets = self.stats.packets.saturating_add(1);
        let frame_start = !self.au_open || self.last_ts != Some(ts);
        self.last_ts = Some(ts);
        self.au_open = !marker;
        if frame_start {
            // The access unit before ended without a marker bit.
            self.tally.finish(&mut self.stats);
            self.au_vcl_seen = false;
        }
        let parsed = match nal::parse(payload) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.stats.violations = self.stats.violations.saturating_add(1);
                return Err(err);
            }
        };
        self.end_unfinished_unit(&parsed, frame_start, out);
        let picture_open = self.au_vcl_seen;
        let Some(Classified {
            payloads,
            keyframe,
            carries_sets,
        }) = self.classify(parsed, payload, marker)?
        else {
            return Ok(());
        };
        // Only a picture's first slice segment is a keyframe start: a later
        // IRAP segment is the same picture (§7.4.2.4.4), joinable nowhere,
        // and gets no parameter sets of its own.
        let keyframe = keyframe && !picture_open;

        let mut first_frame_start = frame_start;
        let mut keyframe_start = false;
        if keyframe {
            self.stats.keyframes = self.stats.keyframes.saturating_add(1);
            if carries_sets {
                keyframe_start = true;
            } else if let Some(sets) = self.parameter_set_payloads() {
                self.stats.inserted = self.stats.inserted.saturating_add(1);
                for (i, payload) in sets.into_iter().enumerate() {
                    out.push(NormalizedPacket {
                        payload,
                        frame_start: i == 0 && frame_start,
                        keyframe_start: i == 0,
                        marker: false,
                        synthetic: true,
                    });
                }
                first_frame_start = false;
            } else {
                self.stats.keyframes_without_sets =
                    self.stats.keyframes_without_sets.saturating_add(1);
                keyframe_start = true;
            }
        }
        let count = payloads.len();
        for (i, payload) in payloads.into_iter().enumerate() {
            let last = i.saturating_add(1) == count;
            out.push(NormalizedPacket {
                payload,
                frame_start: i == 0 && first_frame_start,
                keyframe_start: i == 0 && keyframe_start,
                marker: marker && last,
                synthetic: false,
            });
        }
        Ok(())
    }

    /// Notes what one unit says about the stream: a parameter set, or a
    /// skipped leading picture.
    fn observe(&mut self, unit: &[u8]) {
        self.sets.observe(unit);
        if nal::unit_type(unit).is_some_and(nal::is_rasl) {
            self.rasl_seen = true;
        }
    }

    /// Whether a unit of `unit_type` is a parameter set after the open
    /// access unit's first VCL NAL unit, which ITU-T H.265 §7.4.2.4.4
    /// makes the start of a new access unit: dropped, and counted.
    fn misplaced_set(&mut self, unit_type: u8) -> bool {
        let misplaced =
            self.au_vcl_seen && matches!(unit_type, nal::VPS_NUT | nal::SPS_NUT | nal::PPS_NUT);
        if misplaced {
            self.stats.misplaced_sets_dropped = self.stats.misplaced_sets_dropped.saturating_add(1);
        }
        misplaced
    }

    /// Notes a VCL NAL unit of the open access unit.
    fn saw_vcl(&mut self, unit_type: u8) {
        if nal::is_vcl(unit_type) {
            self.au_vcl_seen = true;
        }
    }

    /// Sorts one parsed payload into what to emit: `None` when it was only
    /// filler or misplaced parameter sets. `flush`: this packet ends the
    /// access unit, so a re-split unit's last bytes go out with it, and
    /// what is dropped whole is cut down to a filler unit that carries the
    /// marker.
    fn classify(
        &mut self,
        parsed: Payload<'_>,
        payload: &Bytes,
        flush: bool,
    ) -> Result<Option<Classified>, PayloadError> {
        let classified = match parsed {
            Payload::Single(unit) => {
                let unit_type = nal::unit_type(unit).unwrap_or(0);
                if unit_type == nal::FD_NUT {
                    self.stats.filler_dropped = self.stats.filler_dropped.saturating_add(1);
                    return Ok(flush.then(|| Classified::end_of_unit(unit)));
                }
                self.observe(unit);
                if self.misplaced_set(unit_type) {
                    return Ok(flush.then(|| Classified::end_of_unit(unit)));
                }
                self.saw_vcl(unit_type);
                let payloads = if unit.len() > self.max_payload {
                    self.stats.resplit = self.stats.resplit.saturating_add(1);
                    nal::fragment(unit, self.max_payload)
                } else {
                    vec![payload.clone()]
                };
                Classified {
                    payloads,
                    keyframe: joinable(unit_type, self.rasl_seen),
                    carries_sets: false,
                }
            }
            Payload::Aggregate(units) => {
                return self.classify_aggregate(units, payload, flush);
            }
            Payload::Fragment {
                nal_header,
                start,
                end,
                fragment,
            } => {
                let unit_type = nal::nal_type(nal_header[0]);
                if nal::is_rasl(unit_type) {
                    self.rasl_seen = true;
                }
                if start && self.misplaced_set(unit_type)
                    || !start && self.au_vcl_seen && nal::is_parameter_set(unit_type)
                {
                    // Every fragment of the misplaced unit, counted once.
                    return Ok(flush.then(|| Classified::end_of_unit(&nal_header)));
                }
                self.saw_vcl(unit_type);
                Classified {
                    payloads: self.fragment_payloads(
                        nal_header,
                        (start, end),
                        fragment,
                        payload,
                        flush,
                    ),
                    keyframe: start && joinable(unit_type, self.rasl_seen),
                    carries_sets: false,
                }
            }
        };
        Ok(Some(classified))
    }

    /// [`Self::classify`] for an aggregation packet (RFC 7798 §4.4.2):
    /// filler and misplaced parameter sets are taken out, and what is left
    /// goes out as it came when nothing was taken out and it fits the
    /// target, else repacked.
    fn classify_aggregate(
        &mut self,
        units: nal::Aggregate<'_>,
        payload: &Bytes,
        flush: bool,
    ) -> Result<Option<Classified>, PayloadError> {
        let mut kept: Vec<&[u8]> = Vec::new();
        let mut keyframe = false;
        let mut filler = false;
        // The first unit dropped, whose layer a marker's filler takes.
        let mut dropped = None;
        for unit in units {
            let unit = match unit {
                Ok(unit) => unit,
                Err(err) => {
                    self.stats.violations = self.stats.violations.saturating_add(1);
                    return Err(err);
                }
            };
            let unit_type = nal::unit_type(unit).unwrap_or(0);
            if unit_type == nal::FD_NUT {
                filler = true;
                dropped = dropped.or(Some(unit));
                continue;
            }
            self.observe(unit);
            if self.misplaced_set(unit_type) {
                dropped = dropped.or(Some(unit));
                continue;
            }
            self.saw_vcl(unit_type);
            keyframe |= joinable(unit_type, self.rasl_seen);
            kept.push(unit);
        }
        if filler {
            self.stats.filler_dropped = self.stats.filler_dropped.saturating_add(1);
        }
        if kept.is_empty() {
            return Ok(dropped.filter(|_| flush).map(Classified::end_of_unit));
        }
        let has = |wanted: u8| kept.iter().any(|u| nal::unit_type(u) == Some(wanted));
        let carries_sets = has(nal::VPS_NUT) && has(nal::SPS_NUT) && has(nal::PPS_NUT);
        let whole = dropped.is_none() && payload.len() <= self.max_payload;
        let payloads = if whole {
            vec![payload.clone()]
        } else {
            if payload.len() > self.max_payload {
                self.stats.resplit = self.stats.resplit.saturating_add(1);
            }
            self.pack_units(&kept)
        };
        // An aggregate that stayed whole still carries its sets first.
        Ok(Some(Classified {
            payloads,
            keyframe,
            carries_sets: carries_sets && whole,
        }))
    }

    /// Ends a re-split unit the camera never ended (RFC 7798 §4.4.3) when
    /// `parsed` does not continue it: within its access unit what is left
    /// goes out as it is, without the end bit; at the next access unit,
    /// whose timestamp it would take, it is dropped.
    fn end_unfinished_unit(
        &mut self,
        parsed: &Payload<'_>,
        frame_start: bool,
        out: &mut Vec<NormalizedPacket>,
    ) {
        let Some(mut carry) = self.carry.take() else {
            return;
        };
        let continues = matches!(
            parsed,
            Payload::Fragment { nal_header, start: false, .. } if *nal_header == carry.nal_header
        );
        if continues && !frame_start {
            self.carry = Some(carry);
            return;
        }
        self.stats.violations = self.stats.violations.saturating_add(1);
        if frame_start {
            return;
        }
        for payload in self.split_carry_into(&mut carry, false, true) {
            out.push(NormalizedPacket {
                payload,
                frame_start: false,
                keyframe_start: false,
                marker: false,
                synthetic: false,
            });
        }
    }

    /// The payloads of one fragment (RFC 7798 §4.4.3): as it came when it
    /// fits and no re-split unit is open, otherwise through the carry,
    /// which sends whole packets' worth and keeps the rest for the unit's
    /// next fragment, all of it at the unit's end or with `flush`.
    fn fragment_payloads(
        &mut self,
        nal_header: [u8; 2],
        (start, end): (bool, bool),
        fragment: &[u8],
        payload: &Bytes,
        flush: bool,
    ) -> Vec<Bytes> {
        let oversize = payload.len() > self.max_payload;
        if oversize {
            self.stats.resplit = self.stats.resplit.saturating_add(1);
        }
        let mut carry = match self.carry.take() {
            None if !oversize => return vec![payload.clone()],
            Some(carry) => carry,
            None => Carry {
                nal_header,
                start,
                bytes: Vec::new(),
            },
        };
        carry.bytes.extend_from_slice(fragment);
        let finish = end || flush;
        let payloads = self.split_carry_into(&mut carry, end, finish);
        if !finish {
            self.carry = Some(carry);
        }
        payloads
    }

    /// Fragmentation units of a re-split unit's bytes, each filling the
    /// target (RFC 7798 §4.4.3): with `finish` all of them, the last
    /// with the end bit if `end`; otherwise only whole packets' worth,
    /// keeping at least one byte back for the next fragment, so the end
    /// bit always has bytes to ride on.
    fn split_carry_into(&self, carry: &mut Carry, end: bool, finish: bool) -> Vec<Bytes> {
        let chunk = self.max_payload.saturating_sub(3).max(1);
        let mut out = Vec::new();
        let mut taken = 0_usize;
        loop {
            let rest = carry.bytes.get(taken..).unwrap_or(&[]);
            if !finish && rest.len() <= chunk {
                break;
            }
            let (part, after) = rest.split_at(rest.len().min(chunk));
            let last = after.is_empty();
            out.push(nal::fu_part(
                carry.nal_header,
                carry.start,
                end && last,
                part,
            ));
            carry.start = false;
            taken = taken.saturating_add(part.len());
            if last {
                break;
            }
        }
        carry.bytes.drain(..taken);
        out
    }

    /// The latest parameter sets as payloads to insert before an IRAP
    /// picture, once all three are known: one aggregation packet
    /// (RFC 7798 §4.4.2) when it fits the target, otherwise packed like any
    /// other units, so no packet exceeds the target.
    fn parameter_set_payloads(&self) -> Option<Vec<Bytes>> {
        let units = self.sets.units()?;
        let aggregate = nal::aggregate(&units);
        Some(if aggregate.len() <= self.max_payload {
            vec![aggregate]
        } else {
            self.pack_units(&units)
        })
    }

    /// Packs NAL units into aggregation packets no larger than the target,
    /// each unit too large on its own into fragmentation units.
    fn pack_units(&self, units: &[&[u8]]) -> Vec<Bytes> {
        let mut out = Vec::new();
        let mut group: Vec<&[u8]> = Vec::new();
        let mut group_len = nal::HEADER_LEN;
        for &unit in units {
            let cost = unit.len().saturating_add(2);
            if unit.len() > self.max_payload {
                flush_group(&mut group, &mut group_len, &mut out);
                out.extend(nal::fragment(unit, self.max_payload));
                continue;
            }
            if group_len.saturating_add(cost) > self.max_payload {
                flush_group(&mut group, &mut group_len, &mut out);
            }
            group.push(unit);
            group_len = group_len.saturating_add(cost);
        }
        flush_group(&mut group, &mut group_len, &mut out);
        out
    }
}

/// Emits a group of units as one aggregation packet, or one single NAL
/// unit packet when it is alone (RFC 7798 §4.4.2: an aggregate carries
/// two units at least).
fn flush_group(group: &mut Vec<&[u8]>, group_len: &mut usize, out: &mut Vec<Bytes>) {
    match group.as_slice() {
        [] => {}
        [single] => out.push(Bytes::copy_from_slice(single)),
        many => out.push(nal::aggregate(many)),
    }
    group.clear();
    *group_len = nal::HEADER_LEN;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::super::sps::test_data::{pps, sps, vps};
    use super::*;
    use crate::h264::DEFAULT_MAX_PAYLOAD;

    fn picture(unit_type: u8, len: usize) -> Vec<u8> {
        [unit_type << 1, 0x01]
            .into_iter()
            .chain((0..len).map(|i| u8::try_from(i % 251).unwrap()))
            .collect()
    }

    fn idr(len: usize) -> Vec<u8> {
        picture(nal::IDR_W_RADL, len)
    }

    fn slice(len: usize) -> Vec<u8> {
        picture(1, len)
    }

    fn known_sets() -> ParameterSets {
        let mut sets = ParameterSets::default();
        for unit in [vps(), sps(640, 480), pps()] {
            sets.observe(&unit);
        }
        sets
    }

    fn run(
        n: &mut PacketNormalizer,
        ts: u32,
        marker: bool,
        payload: &[u8],
    ) -> Vec<NormalizedPacket> {
        let mut out = Vec::new();
        n.normalize(ts, marker, &Bytes::copy_from_slice(payload), &mut out)
            .unwrap();
        out
    }

    #[test]
    fn parameter_sets_are_inserted_before_an_irap_picture_that_lacks_them_rfc7798_4_4_2() {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        let out = run(&mut n, 1000, true, &slice(10));
        assert_eq!(out.len(), 1);
        assert!(out[0].frame_start && !out[0].keyframe_start && out[0].marker);
        // An IDR before any parameter set is known: joinable only in name.
        let out = run(&mut n, 4000, true, &idr(10));
        assert_eq!(out.len(), 1);
        assert!(out[0].keyframe_start && !out[0].synthetic);
        assert_eq!(n.stats().keyframes_without_sets, 1);
        // The camera sends VPS, SPS and PPS as single units, then the IDR.
        run(&mut n, 7000, false, &vps());
        run(&mut n, 7000, false, &sps(640, 480));
        run(&mut n, 7000, false, &pps());
        assert!(n.parameter_sets().complete());
        let out = run(&mut n, 7000, true, &idr(10));
        assert_eq!(out.len(), 2, "aggregate inserted before the IDR");
        assert!(out[0].synthetic && out[0].keyframe_start && !out[0].frame_start);
        assert_eq!(out[0].payload, n.parameter_sets().aggregate().unwrap());
        assert!(!out[1].keyframe_start && !out[1].synthetic && out[1].marker);
        assert_eq!(n.stats().inserted, 1);
        assert_eq!(n.stats().keyframes, 2);
        // An aggregate that already carries the sets and the IDR is the
        // keyframe start itself.
        let ap = nal::aggregate(&[&vps(), &sps(640, 480), &pps(), &idr(10)]);
        let out = run(&mut n, 10_000, true, &ap);
        assert_eq!(out.len(), 1);
        assert!(out[0].keyframe_start && !out[0].synthetic && out[0].frame_start);
        // One without the VPS gets the insertion.
        let ap = nal::aggregate(&[&sps(640, 480), &pps(), &idr(10)]);
        let out = run(&mut n, 11_000, true, &ap);
        assert_eq!(out.len(), 2);
        assert!(out[0].synthetic);
        let ap = nal::aggregate(&[&vps(), &pps(), &idr(10)]);
        assert_eq!(run(&mut n, 11_500, true, &ap).len(), 2, "no SPS");
        let ap = nal::aggregate(&[&vps(), &sps(640, 480), &idr(10)]);
        assert_eq!(run(&mut n, 11_600, true, &ap).len(), 2, "no PPS");
        assert_eq!(n.stats().inserted, 4);
        // A fragmented IDR gets the insertion at its start; later
        // fragments nothing.
        let parts = nal::fragment(&idr(3000), 1000);
        let out = run(&mut n, 13_000, false, &parts[0]);
        assert_eq!(out.len(), 2);
        assert!(out[0].synthetic && out[0].frame_start);
        let out = run(&mut n, 13_000, true, &parts[2]);
        assert_eq!(out.len(), 1);
        assert!(!out[0].keyframe_start && !out[0].frame_start && out[0].marker);
    }

    #[test]
    fn parameter_sets_after_the_first_slice_segment_are_dropped_h265_7_4_2_4_4() {
        // A Reolink camera's IDR picture (observed 2026-10-09): three slice
        // segments, VPS, SPS and PPS sent again before each.
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        for set in [vps(), sps(640, 480), pps()] {
            assert_eq!(run(&mut n, 1000, false, &set).len(), 1);
        }
        let parts = nal::fragment(&idr(3000), 1000);
        let out = run(&mut n, 1000, false, &parts[0]);
        assert_eq!(out.len(), 2, "the sets inserted before the first segment");
        assert!(out[0].synthetic && out[0].keyframe_start);
        for part in &parts[1..] {
            assert_eq!(run(&mut n, 1000, false, part).len(), 1);
        }
        // The repeats before the second segment are dropped, and noted: a
        // new SPS still counts.
        for set in [vps(), sps(1280, 720), pps()] {
            assert!(run(&mut n, 1000, false, &set).is_empty(), "dropped");
        }
        assert_eq!(n.parameter_sets().sps.as_deref(), Some(&sps(1280, 720)[..]));
        assert_eq!(n.stats().misplaced_sets_dropped, 3);
        // The second segment: no insertion, no keyframe start of its own.
        let out = run(&mut n, 1000, false, &picture(nal::IDR_W_RADL, 50));
        assert_eq!(out.len(), 1);
        assert!(!out[0].keyframe_start && !out[0].synthetic && !out[0].frame_start);
        assert_eq!(n.stats().keyframes, 1);
        // In an aggregate with the third segment, only the segment stays.
        let ap = nal::aggregate(&[
            &vps(),
            &sps(1280, 720),
            &pps(),
            &picture(nal::IDR_W_RADL, 40),
        ]);
        let out = run(&mut n, 1000, false, &ap);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, picture(nal::IDR_W_RADL, 40));
        assert!(!out[0].keyframe_start);
        assert_eq!(n.stats().misplaced_sets_dropped, 6);
    }

    #[test]
    fn misplaced_parameter_sets_with_the_marker_leave_a_filler_that_ends_the_access_unit_rfc7798_4_1()
     {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, known_sets());
        run(&mut n, 1000, false, &slice(10));
        // A set alone with the marker leaves a filler unit in its layer and
        // sub-layer that ends the access unit.
        let mut late_pps = pps();
        late_pps[1] = 0x0a;
        let out = run(&mut n, 1000, true, &late_pps);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].payload[..], &[nal::FD_NUT << 1, 0x0a, 0x80][..]);
        assert!(out[0].marker);
        assert_eq!(n.stats().filler_dropped, 0);
        // An aggregate of nothing but late sets does the same.
        assert!(run(&mut n, 2000, false, &slice(10))[0].frame_start);
        let out = run(
            &mut n,
            2000,
            true,
            &nal::aggregate(&[&sps(640, 480), &pps()]),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].payload[..], &[nal::FD_NUT << 1, 0x01, 0x80][..]);
        assert!(out[0].marker);
        // Fragments of a set after the slice are dropped too, counted once.
        run(&mut n, 3000, false, &slice(10));
        let parts = nal::fragment(&sps(640, 480), 20);
        assert!(parts.len() >= 2, "{}", parts.len());
        let before = n.stats().misplaced_sets_dropped;
        for part in &parts[..parts.len() - 1] {
            assert!(run(&mut n, 3000, false, part).is_empty());
        }
        let out = run(&mut n, 3000, true, parts.last().unwrap());
        assert_eq!(out.len(), 1);
        assert!(out[0].marker);
        assert_eq!(&out[0].payload[..], &[nal::FD_NUT << 1, 0x01, 0x80][..]);
        assert_eq!(n.stats().misplaced_sets_dropped, before + 1);
        // The next access unit starts afresh: its sets go out.
        let out = run(&mut n, 4000, false, &vps());
        assert_eq!(out.len(), 1);
        assert!(out[0].frame_start);
    }

    #[test]
    fn every_irap_type_is_a_keyframe_and_cra_only_without_rasl_h265_8_1_3() {
        for unit_type in [
            nal::BLA_W_LP,
            17,
            18,
            nal::IDR_W_RADL,
            nal::IDR_N_LP,
            nal::CRA_NUT,
        ] {
            let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, known_sets());
            let out = run(&mut n, 1, true, &picture(unit_type, 10));
            assert!(out[0].keyframe_start, "type {unit_type}");
        }
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, known_sets());
        assert!(run(&mut n, 1, true, &picture(nal::CRA_NUT, 10))[0].keyframe_start);
        // A RASL picture follows: CRAs are no longer joinable, IDRs are.
        run(&mut n, 2, true, &picture(nal::RASL_N, 10));
        assert!(!run(&mut n, 3, true, &picture(nal::CRA_NUT, 10))[0].keyframe_start);
        assert!(run(&mut n, 4, true, &idr(10))[0].keyframe_start);
        // RASL seen in an aggregate and in a fragment count the same.
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, known_sets());
        let ap = nal::aggregate(&[&picture(nal::RASL_R, 4), &slice(4)]);
        run(&mut n, 1, true, &ap);
        let ap = nal::aggregate(&[&picture(nal::CRA_NUT, 4), &slice(4)]);
        assert!(!run(&mut n, 2, true, &ap)[0].keyframe_start);
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, known_sets());
        let parts = nal::fragment(&picture(nal::RASL_N, 3000), 1000);
        run(&mut n, 1, false, &parts[1]);
        let parts = nal::fragment(&picture(nal::CRA_NUT, 3000), 1000);
        assert!(!run(&mut n, 2, false, &parts[0])[0].keyframe_start);
        assert!(joinable(nal::CRA_NUT, false) && !joinable(nal::CRA_NUT, true));
        assert!(joinable(nal::IDR_N_LP, true) && !joinable(nal::RASL_N, false));
    }

    #[test]
    fn frame_boundaries_follow_the_marker_and_the_timestamp_rfc7798_4_1() {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        assert!(run(&mut n, 1, false, &slice(5))[0].frame_start);
        assert!(
            !run(&mut n, 1, false, &slice(5))[0].frame_start,
            "same access unit"
        );
        assert!(
            run(&mut n, 2, false, &slice(5))[0].frame_start,
            "next timestamp"
        );
        let out = run(&mut n, 2, true, &slice(5));
        assert!(!out[0].frame_start && out[0].marker);
        assert!(
            run(&mut n, 2, false, &slice(5))[0].frame_start,
            "after a marker"
        );
    }

    #[test]
    fn large_packets_are_resplit_to_the_datagram_target_rfc7798_4_4_3() {
        let mut n = PacketNormalizer::new(500, ParameterSets::default());
        let out = run(&mut n, 1, true, &slice(1200));
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|p| p.payload.len() <= 500));
        assert!(out[0].frame_start && !out[1].frame_start);
        assert!(!out[0].marker && !out[1].marker && out[2].marker);
        assert_eq!(n.stats().resplit, 1);
        // A fragment from a camera with a 1400-byte MTU.
        let parts = nal::fragment(&idr(2500), 1400);
        let out = run(&mut n, 2, false, &parts[0]);
        assert!(out.iter().all(|p| p.payload.len() <= 500));
        assert!(out[0].keyframe_start);
        let out = run(&mut n, 2, true, &parts[1]);
        assert!(out.last().unwrap().marker);
        assert!(out.iter().all(|p| p.payload.len() <= 500));
        assert_eq!(n.stats().resplit, 3);
        // An aggregate over the target is split by unit; a unit over it
        // alone is fragmented.
        let ap = nal::aggregate(&[&slice(200), &slice(200), &slice(900), &slice(100)]);
        let out = run(&mut n, 3, true, &ap);
        assert!(out.iter().all(|p| p.payload.len() <= 500), "{out:?}");
        let kinds: Vec<u8> = out.iter().map(|p| nal::nal_type(p.payload[0])).collect();
        assert_eq!(kinds, [nal::AP, nal::FU, nal::FU, 1]);
        assert!(out.last().unwrap().marker);
        // Payloads of exactly the target stay whole: a single unit, an
        // aggregate, a fragment.
        let mut n = PacketNormalizer::new(500, ParameterSets::default());
        assert_eq!(run(&mut n, 5, true, &slice(498)).len(), 1);
        let ap = nal::aggregate(&[&slice(200), &slice(290)]);
        assert_eq!(ap.len(), 500);
        assert_eq!(run(&mut n, 6, true, &ap)[0].payload, ap);
        let parts = nal::fragment(&slice(1000), 500);
        assert_eq!(parts[0].len(), 500);
        assert_eq!(run(&mut n, 7, false, &parts[0])[0].payload, parts[0]);
        assert_eq!(n.stats().resplit, 0);
        // Units of exactly the target, or filling a group to it, are packed
        // whole when an aggregate is re-split.
        let ap = nal::aggregate(&[&slice(498), &slice(246), &slice(244)]);
        let out = run(&mut n, 8, true, &ap);
        let sizes: Vec<usize> = out.iter().map(|p| p.payload.len()).collect();
        assert_eq!(sizes, [500, 500], "one single, one aggregate");
        assert_eq!(n.stats().resplit, 1);
        // An aggregate re-packed only for its filler is not re-split, even
        // at exactly the target.
        let filler = [nal::FD_NUT << 1, 0x01, 0xff];
        let ap = nal::aggregate(&[&filler, &slice(20), &slice(20)]);
        run(&mut n, 9, true, &ap);
        let ap = nal::aggregate(&[&filler, &slice(200), &slice(285)]);
        assert_eq!(ap.len(), 500);
        run(&mut n, 10, true, &ap);
        assert_eq!(n.stats().resplit, 1);
        // A tiny target still moves.
        let mut n = PacketNormalizer::new(1, ParameterSets::default());
        assert_eq!(run(&mut n, 4, true, &slice(4)).len(), 4, "one byte each");
    }

    /// The unit the fragmentation units `packets` carry: header and bytes,
    /// with each one's start and end bits.
    fn reassemble(packets: &[NormalizedPacket]) -> (Vec<u8>, Vec<(bool, bool)>) {
        let mut unit = Vec::new();
        let mut flags = Vec::new();
        for packet in packets {
            let Ok(Payload::Fragment {
                nal_header,
                start,
                end,
                fragment,
            }) = nal::parse(&packet.payload)
            else {
                panic!("a fragment: {packet:?}");
            };
            if start {
                unit.extend_from_slice(&nal_header);
            }
            unit.extend_from_slice(fragment);
            flags.push((start, end));
        }
        (unit, flags)
    }

    #[test]
    fn re_split_fragments_fill_every_packet_rfc7798_4_4_3() {
        // A camera fragmenting a 140 kB IDR at 1400 bytes: cut one by
        // one, each would make a full packet and a short one, 200 in all.
        let unit = idr(140_000);
        let parts = nal::fragment(&unit, 1_400);
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, known_sets());
        let mut out = Vec::new();
        let last = parts.len() - 1;
        for (i, part) in parts.iter().enumerate() {
            out.extend(run(&mut n, 1, i == last, part));
        }
        assert!(out[0].synthetic && out[0].keyframe_start);
        let packets = &out[1..];
        let chunk = DEFAULT_MAX_PAYLOAD - 3;
        assert_eq!(
            packets.len(),
            (unit.len() - 2).div_ceil(chunk),
            "as few as fit"
        );
        let sizes: Vec<usize> = packets.iter().map(|p| p.payload.len()).collect();
        assert!(
            sizes[..sizes.len() - 1]
                .iter()
                .all(|&l| l == DEFAULT_MAX_PAYLOAD),
            "{sizes:?}"
        );
        let (rebuilt, flags) = reassemble(packets);
        assert_eq!(rebuilt, unit);
        assert_eq!(flags[0], (true, false));
        assert_eq!(flags[flags.len() - 1], (false, true));
        assert!(
            flags[1..flags.len() - 1]
                .iter()
                .all(|f| *f == (false, false))
        );
        assert!(packets[..packets.len() - 1].iter().all(|p| !p.marker));
        assert!(packets[packets.len() - 1].marker);
        assert!(packets.iter().all(|p| !p.keyframe_start && !p.frame_start));
        assert_eq!(n.stats().resplit, u64::try_from(parts.len()).unwrap() - 1);
        // Fragments that fit go out as they came, also after a re-split
        // unit ended.
        let small = nal::fragment(&slice(2_000), 1_000);
        let out = run(&mut n, 2, false, &small[0]);
        assert_eq!(out[0].payload, small[0]);
        assert!(out[0].frame_start);
        // A small fragment after a large one waits for a packet's worth.
        let mut n = PacketNormalizer::new(500, ParameterSets::default());
        let unit = slice(1_500);
        let header = [unit[0], unit[1]];
        let parts = [
            nal::fu_part(header, true, false, &unit[2..799]),
            nal::fu_part(header, false, false, &unit[799..900]),
            nal::fu_part(header, false, true, &unit[900..]),
        ];
        let first = run(&mut n, 3, false, &parts[0]);
        assert_eq!(first.len(), 1, "497 bytes out, 300 held");
        assert!(first[0].frame_start);
        assert!(
            run(&mut n, 3, false, &parts[1]).is_empty(),
            "held: 300 + 101"
        );
        let rest = run(&mut n, 3, true, &parts[2]);
        let mut all = first;
        all.extend(rest);
        assert_eq!(reassemble(&all).0, unit);
        assert!(all.iter().all(|p| p.payload.len() <= 500));
    }

    #[test]
    fn a_fragmented_unit_the_camera_never_ended_goes_out_as_it_is_rfc7798_4_4_3() {
        let mut n = PacketNormalizer::new(500, ParameterSets::default());
        let parts = nal::fragment(&slice(3_000), 1_400);
        // Within its access unit: flushed without the end bit before the
        // next unit, here a single NAL unit packet.
        let out = run(&mut n, 1, false, &parts[0]);
        assert_eq!(out.len(), 2);
        let out = run(&mut n, 1, false, &slice(10));
        assert_eq!(out.len(), 2, "the held bytes, then the unit");
        assert_eq!(reassemble(&out[..1]).1, [(false, false)]);
        assert_eq!(out[1].payload, slice(10));
        assert_eq!(n.stats().violations, 1);
        // Before a new start of the same type, too.
        run(&mut n, 1, false, &parts[0]);
        let out = run(&mut n, 1, false, &parts[0]);
        assert_eq!(reassemble(&out[..1]).1, [(false, false)]);
        assert_eq!(reassemble(&out[1..2]).1, [(true, false)]);
        // A marker in the middle of a unit sends all of it, still
        // without the end bit.
        let out = run(&mut n, 1, true, &parts[1]);
        let (_, flags) = reassemble(&out);
        assert!(flags.iter().all(|f| *f == (false, false)), "{flags:?}");
        assert!(out.last().unwrap().marker);
        // At the next timestamp it would take that timestamp: dropped.
        run(&mut n, 2, false, &parts[0]);
        let out = run(&mut n, 3, true, &slice(10));
        assert_eq!(out.len(), 1);
        assert!(out[0].frame_start && out[0].marker);
        // A continuing fragment at a new timestamp starts afresh.
        run(&mut n, 4, false, &parts[0]);
        let out = run(&mut n, 5, true, &parts[2]);
        assert!(out[0].frame_start);
        assert_eq!(reassemble(&out).1.last(), Some(&(false, true)));
        assert_eq!(n.stats().violations, 4);
    }

    #[test]
    fn an_access_unit_past_libwebrtc_max_frame_packets_is_reported() {
        // At a 10-byte target an FU carries 7 bytes: a picture of 7 × 2047
        // bytes after its header is 2047 packets, the most libwebrtc
        // assembles; one byte more is 2048.
        let mut n = PacketNormalizer::new(10, ParameterSets::default());
        let fits = idr(7 * LIBWEBRTC_MAX_FRAME_PACKETS);
        assert_eq!(
            run(&mut n, 1, true, &fits).len(),
            LIBWEBRTC_MAX_FRAME_PACKETS
        );
        assert_eq!(n.take_frame_over_limit(), None);
        let over = idr(7 * LIBWEBRTC_MAX_FRAME_PACKETS + 1);
        run(&mut n, 2, false, &over);
        assert_eq!(n.take_frame_over_limit(), None, "not ended yet");
        run(&mut n, 3, true, &slice(4));
        let big = n.take_frame_over_limit().unwrap();
        assert_eq!(
            (big.packets, big.bytes, big.keyframe),
            (
                LIBWEBRTC_MAX_FRAME_PACKETS + 1,
                over.len() - 2 + 3 * (LIBWEBRTC_MAX_FRAME_PACKETS + 1),
                true
            )
        );
        assert_eq!(n.stats().frames_over_browser_limit, 1);
    }

    #[test]
    fn a_filler_packet_that_ends_the_access_unit_keeps_its_marker_rfc7798_4_1() {
        // A camera padding its pictures to a constant rate ends each with
        // filler: dropping that packet dropped the access unit's end.
        let filler = [nal::FD_NUT << 1, 0x03, 0xff, 0xff, 0xff, 0x80];
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        run(&mut n, 1, false, &slice(10));
        let out = run(&mut n, 1, true, &filler);
        assert_eq!(out.len(), 1);
        assert_eq!(
            &out[0].payload[..],
            [nal::FD_NUT << 1, 0x03, 0x80],
            "its header, no bytes"
        );
        assert!(out[0].marker && !out[0].frame_start && !out[0].synthetic);
        // In an aggregate of nothing else, the first filler's header.
        let ap = nal::aggregate(&[&filler, &[nal::FD_NUT << 1, 0x01, 0xff]]);
        let out = run(&mut n, 2, true, &ap);
        assert_eq!(&out[0].payload[..], [nal::FD_NUT << 1, 0x03, 0x80]);
        assert!(out[0].marker && out[0].frame_start);
        assert_eq!(n.stats().filler_dropped, 2);
        // A filler unit without a whole header gets a header of its own.
        assert_eq!(
            Classified::end_of_unit(&[nal::FD_NUT << 1]).payloads,
            [Bytes::from_static(&[nal::FD_NUT << 1, 1, 0x80])]
        );
    }

    #[test]
    fn filler_is_dropped_and_violations_are_errors() {
        let filler = [nal::FD_NUT << 1, 0x01, 0xff];
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        assert!(run(&mut n, 1, false, &filler).is_empty());
        let ap = nal::aggregate(&[&filler, &slice(4)]);
        let out = run(&mut n, 2, true, &ap);
        assert_eq!(out.len(), 1);
        assert_eq!(
            nal::nal_type(out[0].payload[0]),
            1,
            "rebuilt without filler"
        );
        let only_filler = nal::aggregate(&[&filler]);
        assert!(run(&mut n, 3, false, &only_filler).is_empty());
        assert_eq!(n.stats().filler_dropped, 3);
        let mut out = Vec::new();
        assert_eq!(
            n.normalize(4, true, &Bytes::from_static(&[nal::PACI << 1, 1]), &mut out),
            Err(PayloadError::UnsupportedType(nal::PACI))
        );
        assert_eq!(
            n.normalize(
                4,
                true,
                &Bytes::from_static(&[0x60, 0x01, 0x00, 0x09, 0x40]),
                &mut out
            ),
            Err(PayloadError::Truncated)
        );
        assert!(out.is_empty());
        assert_eq!(n.stats().violations, 2);
        assert_eq!(n.stats().packets, 5);
    }

    #[test]
    fn parameter_sets_too_large_for_one_aggregate_are_inserted_split_rfc7798_4_4_2() {
        let mut big_pps = pps();
        big_pps.resize(400, 0x55);
        let mut n = PacketNormalizer::new(200, ParameterSets::default());
        for unit in [vps(), sps(640, 480), big_pps.clone()] {
            run(&mut n, 1, false, &unit);
        }
        let out = run(&mut n, 1, true, &idr(10));
        assert!(out.iter().all(|p| p.payload.len() <= 200), "{out:?}");
        let kinds: Vec<u8> = out.iter().map(|p| nal::nal_type(p.payload[0])).collect();
        assert_eq!(
            kinds,
            [nal::AP, nal::FU, nal::FU, nal::FU, nal::IDR_W_RADL],
            "VPS and SPS together, the PPS fragmented, the IDR"
        );
        assert!(out[0].synthetic && out[0].keyframe_start && !out[0].frame_start);
        assert!(out[1..4].iter().all(|p| p.synthetic && !p.keyframe_start));
        assert!(!out[4].synthetic && out[4].marker);
        // At a frame start, only the first inserted packet starts the frame.
        let out = run(&mut n, 2, true, &idr(10));
        assert!(out[0].frame_start && out[1..].iter().all(|p| !p.frame_start));
        // At a target of exactly the aggregate's size, it stays one.
        let sets = n.parameter_sets().clone();
        let exact = sets.aggregate().unwrap().len();
        let mut n = PacketNormalizer::new(exact, sets);
        let out = run(&mut n, 3, true, &idr(10));
        assert_eq!(out.len(), 2);
        let mut n = PacketNormalizer::new(exact - 1, n.parameter_sets().clone());
        assert!(run(&mut n, 3, true, &idr(10)).len() > 2);
    }

    #[test]
    fn sdp_parameter_sets_seed_the_normalizer() {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, known_sets());
        let out = run(&mut n, 1, true, &idr(10));
        assert_eq!(out.len(), 2);
        assert!(out[0].synthetic && out[0].keyframe_start && out[0].frame_start);
        assert!(!out[1].frame_start);
    }
}
