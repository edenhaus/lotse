//! The packet layer of H.264 normalization, on the live path: parameter
//! sets guaranteed before every IDR, filler dropped, keyframe and frame
//! boundaries marked, and packets larger than the datagram target re-split
//! into FU-A fragments, so a viewer can join at any `keyframe_start` and
//! every packet fits the tunnels on the way.
//!
//! Implements RFC 6184 §5.1 (the marker bit ends the access unit), §5.7.1
//! (STAP-A for parameter-set insertion) and §5.8 (FU-A re-splitting).
//! Runs once per source packet; its output is what every viewer gets, so
//! nothing here is per viewer.
//!
//! FU-A fragments too large for the target are re-split filling every
//! packet, as [`crate::h265::packet`] does for H.265: the bytes left over
//! from one source fragment go out with the next fragment of the same
//! unit, so a unit takes as few packets as the target allows. A camera's
//! 1400-byte fragments cut one by one made a full packet and a short one
//! each, twice the packets of a frame, and libwebrtc assembles no frame
//! past its packet buffer.

use bytes::Bytes;

use super::nal::{self, ParameterSets, Payload, PayloadError};

/// The largest payload the normalizer emits, sized as libwebrtc sizes its
/// own video packets (observed behavior at libwebrtc `aeb9b375`, read
/// 2026-10-05): `kVideoMtu` (1200, `media/base/media_constants.h`) is the
/// largest RTP packet, its header and extensions included
/// (`max_packet_size`, capped in `media/engine/webrtc_video_engine.cc` and
/// handed to `SetMaxRtpPacketSize` in `call/rtp_video_sender.cc`).
/// `RTPSenderVideo::SendVideo` (`modules/rtp_rtcp/source/rtp_sender_video.cc`)
/// keeps `RtxPacketOverhead` of it free, so a retransmission fits too, and
/// gives the packetizer what is left after the packet's headers; the SRTP
/// tag comes on top (`pc/srtp_session.cc`).
///
/// So: 1200 less the RTP header, the most this session's one-byte-form
/// extension block takes (36: its 4-byte header, a mid of up to 16 bytes,
/// `abs-send-time`, `transport-cc`, `playout-delay` and CVO, each with its
/// ID byte, padded to 4) and RTX's original sequence number (2, RFC 4588
/// §4). The datagram adds the SRTP tag (16 with AES-GCM, RFC 7714 §8):
/// 1216 bytes at most, and with a TURN `ChannelData` header (4) and 48
/// bytes of IPv6 and UDP headers, 1268, which fits a 1280-byte IPv6 path.
/// str0m in RTP mode sends what it is given; its own 1150-byte datagram
/// target applies only where it packetizes.
pub const DEFAULT_MAX_PAYLOAD: usize = 1150;

/// The most RTP packets of one frame that every libwebrtc receiver
/// assembles (Chrome, Edge, Safari, and mobile apps through their web
/// views), as far as lotse knows; it only drives diagnostics. lotse sends
/// every frame whole regardless: it cannot tell which libwebrtc a viewer
/// runs, a newer one may assemble what an older one cannot, and lotse must
/// not depend on libwebrtc's internals or track their changes.
/// A frame of more packets is counted per stream and session and warned
/// about, since some receivers may freeze on it until a keyframe that fits.
///
/// Observed behavior, not a specification: libwebrtc at
/// `aeb9b3750c30bd1189448138b6431b73116b1f56`, read 2026-10-05.
///
/// - `modules/video_coding/h26x_packet_buffer.h`, `kBufferSize` (2048),
///   and `h26x_packet_buffer.cc`, `InsertPacket` and `FindFrames`: a ring
///   of 2048 slots indexed by sequence number. `FindFrames` walks back from
///   a packet with the marker bit to the slot before the frame's first
///   packet; for a frame of 2048 packets that slot is the frame's own last
///   packet, which has the same timestamp, so the frame is never found.
///   Hence 2047 and not 2048. `InsertPacket` drops the frame's packets past
///   the ring as duplicates. Every H.265 stream goes through this buffer,
///   H.264 only under the `WebRTC-Video-H26xPacketBuffer` field trial.
/// - `modules/video_coding/packet_buffer.cc`, `InsertPacket`, with
///   `kPacketBufferMaxSize` (2048) and `UseH26xPacketBuffer` in
///   `video/rtp_video_stream_receiver2.cc`: H.264's generic buffer
///   otherwise, which grows to 2048 slots and is cleared, with a keyframe
///   request, when the 2049th packet of a frame finds its slot taken. The
///   packets after it may stay as a stale tail that clears it again 2048
///   sequence numbers later (`lotse_testing::libwebrtc`).
///
/// The smaller limit holds for both codecs, since lotse cannot tell which
/// buffer a browser uses. Sources:
/// <https://webrtc.googlesource.com/src/+/aeb9b3750c30bd1189448138b6431b73116b1f56/modules/video_coding/h26x_packet_buffer.cc>,
/// <https://webrtc.googlesource.com/src/+/aeb9b3750c30bd1189448138b6431b73116b1f56/modules/video_coding/packet_buffer.cc>,
/// <https://webrtc.googlesource.com/src/+/aeb9b3750c30bd1189448138b6431b73116b1f56/video/rtp_video_stream_receiver2.cc>.
///
/// To re-check: read those files at libwebrtc's current `main`; if
/// `kBufferSize`, `kPacketBufferMaxSize` or the walk back in `FindFrames`
/// changed, update this value, the revision and date here, and the
/// `libwebrtc_aeb9b375_*` tests of `lotse_testing::libwebrtc`.
pub const LIBWEBRTC_MAX_FRAME_PACKETS: usize = 2047;

/// An access unit the packet layer emitted in more packets than
/// [`LIBWEBRTC_MAX_FRAME_PACKETS`]: some libwebrtc receivers may not
/// assemble it, nor the frames that depend on it. It is sent all the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameOverLimit {
    /// Its packets.
    pub packets: usize,
    /// Their payload bytes.
    pub bytes: usize,
    /// It started a keyframe.
    pub keyframe: bool,
}

/// The packets of the access unit being emitted, checked against
/// [`LIBWEBRTC_MAX_FRAME_PACKETS`] when it ends.
#[derive(Debug, Default)]
pub(crate) struct FrameTally {
    /// Packets so far.
    packets: usize,
    /// Their payload bytes.
    bytes: usize,
    /// One of them is a keyframe start.
    keyframe: bool,
    /// The last access unit that ended over the limit, not yet taken.
    over_limit: Option<FrameOverLimit>,
}

impl FrameTally {
    /// Counts the packets one source packet became.
    pub(crate) fn add(&mut self, packets: &[NormalizedPacket]) {
        for packet in packets {
            self.packets = self.packets.saturating_add(1);
            self.bytes = self.bytes.saturating_add(packet.payload.len());
            self.keyframe |= packet.keyframe_start;
        }
    }

    /// The access unit ended: counted in `stats` if it was over the limit.
    pub(crate) fn finish(&mut self, stats: &mut PacketStats) {
        let ended = std::mem::take(self);
        self.over_limit = ended.over_limit;
        if ended.packets > LIBWEBRTC_MAX_FRAME_PACKETS {
            stats.frames_over_browser_limit = stats.frames_over_browser_limit.saturating_add(1);
            self.over_limit = Some(FrameOverLimit {
                packets: ended.packets,
                bytes: ended.bytes,
                keyframe: ended.keyframe,
            });
        }
    }

    /// The last access unit that ended over the limit, once.
    pub(crate) const fn take(&mut self) -> Option<FrameOverLimit> {
        self.over_limit.take()
    }
}

/// One packet of the normalized stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "four independent facts about one packet that the writer reads; an enum would encode their product"
)]
pub struct NormalizedPacket {
    /// The RTP payload.
    pub payload: Bytes,
    /// The first packet of an access unit.
    pub frame_start: bool,
    /// Where a viewer may join: the parameter sets and the first bytes of
    /// an IDR follow from here.
    pub keyframe_start: bool,
    /// The last packet of the access unit (RFC 6184 §5.1).
    pub marker: bool,
    /// Inserted by the normalizer (a parameter-set STAP-A): it has no
    /// sequence number of its own and reuses the next packet's fields.
    pub synthetic: bool,
}

/// What the normalizer counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketStats {
    /// Packets that came in.
    pub packets: u64,
    /// Parameter-set aggregates inserted before IDRs.
    pub inserted: u64,
    /// IDRs that came before any parameter set was known; not joinable.
    pub keyframes_without_sets: u64,
    /// Packets re-split to fit the datagram target.
    pub resplit: u64,
    /// Filler units dropped.
    pub filler_dropped: u64,
    /// Parameter sets dropped from between the slices of one picture,
    /// where they would start a new access unit (ISO/IEC 14496-10
    /// §7.4.1.2.3, ITU-T H.265 §7.4.2.4.4).
    pub misplaced_sets_dropped: u64,
    /// Payloads that violate packetization mode 1.
    pub violations: u64,
    /// Keyframe starts seen.
    pub keyframes: u64,
    /// Access units emitted in more than [`LIBWEBRTC_MAX_FRAME_PACKETS`]
    /// packets.
    pub frames_over_browser_limit: u64,
}

/// The fragmented unit being re-split: the bytes of its fragments not yet
/// sent, always less than one packet's worth between source packets.
#[derive(Debug)]
struct Carry {
    /// The unit's NAL header.
    nal_header: u8,
    /// The first fragment (start bit) is still to be sent.
    start: bool,
    /// The bytes not yet sent.
    bytes: Vec<u8>,
}

/// A parsed payload sorted for emission.
struct Classified {
    /// The payloads to emit, in order.
    payloads: Vec<Bytes>,
    /// The payload starts an IDR.
    keyframe: bool,
    /// It carries both parameter sets itself, so nothing is inserted.
    carries_sets: bool,
}

impl Classified {
    /// Bundles the three.
    const fn new(payloads: Vec<Bytes>, keyframe: bool, carries_sets: bool) -> Self {
        Self {
            payloads,
            keyframe,
            carries_sets,
        }
    }

    /// What is left of a dropped packet (filler, or a parameter set after
    /// the picture's first slice) that carries the marker bit: the
    /// smallest filler unit with the dropped one's `nal_ref_idc` (ISO/IEC
    /// 14496-10 §7.3.2.7, only `rbsp_trailing_bits`), so the access unit
    /// still ends (RFC 6184 §5.1). Chrome assembles a frame only at a
    /// marker bit (libwebrtc `packet_buffer.cc`, observed 2026-10-03).
    fn end_of_unit(dropped: &[u8]) -> Self {
        let header = dropped.first().copied().unwrap_or(nal::NAL_FILLER);
        let header = (header & 0xe0) | nal::NAL_FILLER;
        Self::new(vec![Bytes::from(vec![header, 0x80])], false, false)
    }
}

/// The packet-layer normalizer of one video track.
#[derive(Debug)]
pub struct PacketNormalizer {
    /// The largest payload to emit.
    max_payload: usize,
    /// The latest parameter sets.
    sets: ParameterSets,
    /// The timestamp of the last packet.
    last_ts: Option<u32>,
    /// The last packet did not end its access unit.
    au_open: bool,
    /// A VCL NAL unit of the open access unit went out: a parameter set
    /// from here on would start a new access unit (ISO/IEC 14496-10
    /// §7.4.1.2.3) and is dropped.
    au_vcl_seen: bool,
    /// The fragmented unit being re-split, between its fragments.
    carry: Option<Carry>,
    /// The packets of the current access unit.
    tally: FrameTally,
    /// The counters.
    stats: PacketStats,
}

impl PacketNormalizer {
    /// A normalizer emitting payloads of at most `max_payload` bytes,
    /// starting from the parameter sets the SDP announced, if any.
    pub fn new(max_payload: usize, sets: ParameterSets) -> Self {
        Self {
            max_payload: max_payload.max(3),
            sets,
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
    /// `out`. A payload that violates packetization mode 1 is an error;
    /// the caller drops it and may switch the track to repacketized
    /// delivery.
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
        // Only a picture's first slice is a keyframe start: a later IDR
        // slice is the same picture (§7.4.1.2.3), joinable nowhere, and
        // gets no parameter sets of its own.
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

    /// Sorts one parsed payload into what to emit: `None` when it was only
    /// filler. `flush`: this packet ends the access unit (its marker bit),
    /// so a re-split unit's last bytes go out with it, and filler is cut
    /// down to a unit that carries the marker.
    fn classify(
        &mut self,
        parsed: Payload<'_>,
        payload: &Bytes,
        flush: bool,
    ) -> Result<Option<Classified>, PayloadError> {
        let classified = match parsed {
            Payload::Single(unit) => {
                let unit_type = nal::nal_type(unit.first().copied().unwrap_or(0));
                if unit_type == nal::NAL_FILLER {
                    self.stats.filler_dropped = self.stats.filler_dropped.saturating_add(1);
                    return Ok(flush.then(|| Classified::end_of_unit(unit)));
                }
                self.sets.observe(unit);
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
                Classified::new(payloads, unit_type == nal::NAL_IDR, false)
            }
            Payload::StapA(units) => {
                let mut kept: Vec<&[u8]> = Vec::new();
                let mut keyframe = false;
                let mut filler = false;
                // The first unit dropped, whose `nal_ref_idc` a marker's
                // filler takes.
                let mut dropped = None;
                for unit in units {
                    let unit = match unit {
                        Ok(unit) => unit,
                        Err(err) => {
                            self.stats.violations = self.stats.violations.saturating_add(1);
                            return Err(err);
                        }
                    };
                    let unit_type = nal::nal_type(unit.first().copied().unwrap_or(0));
                    if unit_type == nal::NAL_FILLER {
                        filler = true;
                        dropped = dropped.or(Some(unit));
                        continue;
                    }
                    self.sets.observe(unit);
                    if self.misplaced_set(unit_type) {
                        dropped = dropped.or(Some(unit));
                        continue;
                    }
                    self.saw_vcl(unit_type);
                    keyframe |= unit_type == nal::NAL_IDR;
                    kept.push(unit);
                }
                if filler {
                    self.stats.filler_dropped = self.stats.filler_dropped.saturating_add(1);
                }
                if kept.is_empty() {
                    return Ok(dropped.filter(|_| flush).map(Classified::end_of_unit));
                }
                let carries_sets = kept.iter().any(|u| unit_is(u, nal::NAL_SPS))
                    && kept.iter().any(|u| unit_is(u, nal::NAL_PPS));
                let whole = dropped.is_none() && payload.len() <= self.max_payload;
                let payloads = if whole {
                    vec![payload.clone()]
                } else {
                    if payload.len() > self.max_payload {
                        self.stats.resplit = self.stats.resplit.saturating_add(1);
                    }
                    self.pack_units(&kept)
                };
                // A STAP-A that stayed whole still carries its sets first.
                Classified::new(payloads, keyframe, carries_sets && whole)
            }
            Payload::FuA {
                nal_header,
                start,
                end,
                fragment,
            } => {
                let unit_type = nal::nal_type(nal_header);
                if start && self.misplaced_set(unit_type)
                    || !start && self.au_vcl_seen && nal::is_parameter_set(unit_type)
                {
                    // Every fragment of the misplaced unit, counted once.
                    return Ok(flush.then(|| Classified::end_of_unit(&[nal_header])));
                }
                self.saw_vcl(unit_type);
                Classified::new(
                    self.fragment_payloads(nal_header, (start, end), fragment, payload, flush),
                    start && unit_type == nal::NAL_IDR,
                    false,
                )
            }
        };
        Ok(Some(classified))
    }

    /// Whether a unit of `unit_type` is a parameter set after the open
    /// access unit's first VCL NAL unit, which ISO/IEC 14496-10 §7.4.1.2.3
    /// makes the start of a new access unit: dropped, and counted.
    fn misplaced_set(&mut self, unit_type: u8) -> bool {
        let misplaced = self.au_vcl_seen && nal::is_parameter_set(unit_type);
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

    /// Ends a re-split unit the camera never ended (RFC 6184 §5.8) when
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
            Payload::FuA { nal_header, start: false, .. } if *nal_header == carry.nal_header
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

    /// The payloads of one FU-A fragment (RFC 6184 §5.8): as it came when
    /// it fits and no re-split unit is open, otherwise through the carry,
    /// which sends whole packets' worth and keeps the rest for the unit's
    /// next fragment, all of it at the unit's end or with `flush`.
    fn fragment_payloads(
        &mut self,
        nal_header: u8,
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

    /// FU-A payloads of a re-split unit's bytes, each filling the target
    /// (RFC 6184 §5.8): with `finish` all of them, the last with the end
    /// bit if `end`; otherwise only whole packets' worth, keeping at least
    /// one byte back for the next fragment, so the end bit always has
    /// bytes to ride on.
    fn split_carry_into(&self, carry: &mut Carry, end: bool, finish: bool) -> Vec<Bytes> {
        let chunk = self.max_payload.saturating_sub(2).max(1);
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

    /// The latest parameter sets as payloads to insert before an IDR, once
    /// both are known: one STAP-A (RFC 6184 §5.7.1) when it fits the
    /// target, otherwise packed like any other units, so sets as large as a
    /// camera sends them never make a packet over the target.
    fn parameter_set_payloads(&self) -> Option<Vec<Bytes>> {
        let (Some(sps), Some(pps)) = (&self.sets.sps, &self.sets.pps) else {
            return None;
        };
        let stap = nal::stap_a(&[sps, pps]);
        Some(if stap.len() <= self.max_payload {
            vec![stap]
        } else {
            self.pack_units(&[sps, pps])
        })
    }

    /// Packs NAL units into STAP-As no larger than the target, each unit
    /// too large on its own into FU-A fragments.
    fn pack_units(&self, units: &[&[u8]]) -> Vec<Bytes> {
        let mut out = Vec::new();
        let mut group: Vec<&[u8]> = Vec::new();
        let mut group_len = 1_usize;
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

/// Emits a group of units as one STAP-A, or one single NAL unit packet
/// when it is alone.
fn flush_group(group: &mut Vec<&[u8]>, group_len: &mut usize, out: &mut Vec<Bytes>) {
    match group.as_slice() {
        [] => {}
        [single] => out.push(Bytes::copy_from_slice(single)),
        many => out.push(nal::stap_a(many)),
    }
    group.clear();
    *group_len = 1;
}

/// Whether `unit` has this NAL unit type.
fn unit_is(unit: &[u8], unit_type: u8) -> bool {
    unit.first().is_some_and(|&h| nal::nal_type(h) == unit_type)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::super::sps::test_data::{pps, sps};
    use super::*;

    fn idr(len: usize) -> Vec<u8> {
        std::iter::once(0x65_u8)
            .chain((0..len).map(|i| u8::try_from(i % 251).unwrap()))
            .collect()
    }

    fn slice(len: usize) -> Vec<u8> {
        std::iter::once(0x41_u8)
            .chain(std::iter::repeat_n(0x11, len))
            .collect()
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
    fn parameter_sets_after_the_first_slice_are_dropped_iso14496_10_7_4_1_2_3() {
        // An IDR picture of three slices with SPS and PPS sent again before
        // each, as a Reolink camera does in H.265 (observed 2026-10-09).
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        run(&mut n, 1000, false, &sps(640, 480));
        run(&mut n, 1000, false, &pps());
        let out = run(&mut n, 1000, false, &idr(10));
        assert_eq!(out.len(), 2, "STAP-A inserted before the first slice");
        // The repeats before the second slice are dropped, and noted: a new
        // SPS still counts.
        assert!(run(&mut n, 1000, false, &sps(1280, 720)).is_empty());
        assert!(run(&mut n, 1000, false, &pps()).is_empty());
        assert_eq!(n.parameter_sets().sps.as_deref(), Some(&sps(1280, 720)[..]));
        assert_eq!(n.stats().misplaced_sets_dropped, 2);
        // The second slice: no insertion, no keyframe start of its own.
        let out = run(&mut n, 1000, false, &idr(12));
        assert_eq!(out.len(), 1);
        assert!(!out[0].keyframe_start && !out[0].synthetic && !out[0].frame_start);
        assert_eq!(n.stats().keyframes, 1);
        // In a STAP-A with the third slice, only the slice stays.
        let stap = nal::stap_a(&[&sps(1280, 720), &pps(), &idr(14)]);
        let out = run(&mut n, 1000, false, &stap);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, idr(14));
        assert_eq!(n.stats().misplaced_sets_dropped, 4);
    }

    #[test]
    fn misplaced_parameter_sets_with_the_marker_leave_a_filler_that_ends_the_access_unit_rfc6184_5_1()
     {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, known_sets());
        run(&mut n, 1000, false, &slice(10));
        // A set alone with the marker leaves a filler unit with its
        // nal_ref_idc that ends the access unit.
        let out = run(&mut n, 1000, true, &pps());
        assert_eq!(out.len(), 1);
        assert_eq!(
            &out[0].payload[..],
            &[(pps()[0] & 0xe0) | nal::NAL_FILLER, 0x80][..]
        );
        assert!(out[0].marker);
        assert_eq!(n.stats().filler_dropped, 0);
        // A STAP-A of nothing but late sets does the same.
        assert!(run(&mut n, 2000, false, &slice(10))[0].frame_start);
        let out = run(&mut n, 2000, true, &nal::stap_a(&[&sps(640, 480), &pps()]));
        assert_eq!(out.len(), 1);
        assert_eq!(
            &out[0].payload[..],
            &[(sps(640, 480)[0] & 0xe0) | nal::NAL_FILLER, 0x80][..]
        );
        assert!(out[0].marker);
        // Fragments of a set after the slice are dropped too, counted once.
        run(&mut n, 3000, false, &slice(10));
        let parts = nal::fragment(&sps(640, 480), 6);
        assert!(parts.len() >= 2, "{}", parts.len());
        let before = n.stats().misplaced_sets_dropped;
        for part in &parts[..parts.len() - 1] {
            assert!(run(&mut n, 3000, false, part).is_empty());
        }
        let out = run(&mut n, 3000, true, parts.last().unwrap());
        assert_eq!(out.len(), 1);
        assert!(out[0].marker);
        assert_eq!(
            &out[0].payload[..],
            &[(sps(640, 480)[0] & 0xe0) | nal::NAL_FILLER, 0x80][..]
        );
        assert_eq!(n.stats().misplaced_sets_dropped, before + 1);
        // The next access unit starts afresh: its sets go out.
        let out = run(&mut n, 4000, false, &sps(640, 480));
        assert_eq!(out.len(), 1);
        assert!(out[0].frame_start);
    }

    #[test]
    fn parameter_sets_are_inserted_before_an_idr_that_lacks_them_rfc6184_5_7_1() {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        // A P slice first: nothing known, no keyframe.
        let out = run(&mut n, 1000, true, &slice(10));
        assert_eq!(out.len(), 1);
        assert!(out[0].frame_start && !out[0].keyframe_start && out[0].marker);
        // An IDR before any parameter set is known: joinable only in name.
        let out = run(&mut n, 4000, true, &idr(10));
        assert_eq!(out.len(), 1);
        assert!(out[0].keyframe_start && !out[0].synthetic);
        assert_eq!(n.stats().keyframes_without_sets, 1);
        // The camera sends SPS and PPS as single units, then the IDR.
        run(&mut n, 7000, false, &sps(640, 480));
        run(&mut n, 7000, false, &pps());
        assert!(n.parameter_sets().complete());
        let out = run(&mut n, 7000, true, &idr(10));
        assert_eq!(out.len(), 2, "STAP-A inserted before the IDR");
        assert!(out[0].synthetic && out[0].keyframe_start && !out[0].frame_start);
        assert_eq!(out[0].payload, n.parameter_sets().stap_a().unwrap());
        assert!(!out[1].keyframe_start && !out[1].synthetic && out[1].marker);
        assert_eq!(n.stats().inserted, 1);
        assert_eq!(n.stats().keyframes, 2);
        // A STAP-A that already carries SPS, PPS and the IDR is the keyframe start itself.
        let stap = nal::stap_a(&[&sps(640, 480), &pps(), &idr(10)]);
        let out = run(&mut n, 10_000, true, &stap);
        assert_eq!(out.len(), 1);
        assert!(out[0].keyframe_start && !out[0].synthetic && out[0].frame_start);
        assert_eq!(n.stats().inserted, 1, "nothing inserted");
        // One with the SPS alone, or the PPS alone, gets the insertion.
        let stap = nal::stap_a(&[&sps(640, 480), &idr(10)]);
        assert_eq!(run(&mut n, 11_000, true, &stap).len(), 2, "no PPS");
        let stap = nal::stap_a(&[&pps(), &idr(10)]);
        assert_eq!(run(&mut n, 12_000, true, &stap).len(), 2, "no SPS");
        assert_eq!(n.stats().inserted, 3);
        // An FU-A start of an IDR gets the insertion; later fragments nothing.
        let parts = nal::fragment(&idr(3000), 1000);
        let out = run(&mut n, 13_000, false, &parts[0]);
        assert_eq!(out.len(), 2);
        assert!(out[0].synthetic && out[0].frame_start);
        let out = run(&mut n, 13_000, true, &parts[2]);
        assert_eq!(out.len(), 1);
        assert!(!out[0].keyframe_start && !out[0].frame_start && out[0].marker);
    }

    #[test]
    fn frame_boundaries_follow_the_marker_and_the_timestamp_rfc6184_5_1() {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        let out = run(&mut n, 1, false, &slice(5));
        assert!(out[0].frame_start);
        let out = run(&mut n, 1, false, &slice(5));
        assert!(!out[0].frame_start, "same access unit");
        // A camera that never sets the marker: the next timestamp starts a frame.
        let out = run(&mut n, 2, false, &slice(5));
        assert!(out[0].frame_start);
        let out = run(&mut n, 2, true, &slice(5));
        assert!(!out[0].frame_start && out[0].marker);
        let out = run(&mut n, 2, false, &slice(5));
        assert!(
            out[0].frame_start,
            "after a marker, even at the same timestamp"
        );
    }

    #[test]
    fn large_packets_are_resplit_to_the_datagram_target_rfc6184_5_8() {
        let mut n = PacketNormalizer::new(500, ParameterSets::default());
        let out = run(&mut n, 1, true, &slice(1200));
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|p| p.payload.len() <= 500));
        assert!(out[0].frame_start && !out[1].frame_start);
        assert!(!out[0].marker && !out[1].marker && out[2].marker);
        assert_eq!(n.stats().resplit, 1);
        // An FU-A fragment from a camera with a 1400-byte MTU.
        let parts = nal::fragment(&idr(2500), 1400);
        let out = run(&mut n, 2, false, &parts[0]);
        assert!(out.iter().skip(1).all(|p| p.payload.len() <= 500));
        assert!(out[1].synthetic || out[0].synthetic || n.stats().keyframes_without_sets > 0);
        let out = run(&mut n, 2, true, &parts[1]);
        assert!(out.last().unwrap().marker);
        assert_eq!(n.stats().resplit, 3);
        // A STAP-A over the target is split by unit; a unit over it alone is fragmented.
        let stap = nal::stap_a(&[&slice(200), &slice(200), &slice(900), &slice(100)]);
        let out = run(&mut n, 3, true, &stap);
        assert!(out.iter().all(|p| p.payload.len() <= 500), "{out:?}");
        let kinds: Vec<u8> = out.iter().map(|p| nal::nal_type(p.payload[0])).collect();
        assert_eq!(kinds, [nal::STAP_A, nal::FU_A, nal::FU_A, nal::NAL_SLICE]);
        assert!(out.last().unwrap().marker);
        // A fragment of exactly the target goes out as it came.
        let mut n = PacketNormalizer::new(500, ParameterSets::default());
        let parts = nal::fragment(&slice(1_000), 500);
        assert_eq!(parts[0].len(), 500);
        assert_eq!(run(&mut n, 5, false, &parts[0])[0].payload, parts[0]);
        assert_eq!(n.stats().resplit, 0);
        // A tiny target still moves.
        let mut n = PacketNormalizer::new(1, ParameterSets::default());
        let out = run(&mut n, 4, true, &slice(4));
        assert_eq!(out.len(), 4);
    }

    /// The unit the FU-A packets `packets` carry: header and bytes, with
    /// each one's start and end bits.
    fn reassemble(packets: &[NormalizedPacket]) -> (Vec<u8>, Vec<(bool, bool)>) {
        let mut unit = Vec::new();
        let mut flags = Vec::new();
        for packet in packets {
            lotse_core::let_assert!(
                Ok(Payload::FuA {
                    nal_header,
                    start,
                    end,
                    fragment
                }) = nal::parse(&packet.payload),
                "an FU-A: {packet:?}"
            );
            if start {
                unit.push(nal_header);
            }
            unit.extend_from_slice(fragment);
            flags.push((start, end));
        }
        (unit, flags)
    }

    fn known_sets() -> ParameterSets {
        let mut sets = ParameterSets::default();
        sets.observe(&sps(640, 480));
        sets.observe(&pps());
        sets
    }

    #[test]
    fn re_split_fragments_fill_every_packet_rfc6184_5_8() {
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
        let chunk = DEFAULT_MAX_PAYLOAD - 2;
        assert_eq!(
            packets.len(),
            (unit.len() - 1).div_ceil(chunk),
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
        let header = unit[0];
        let parts = [
            nal::fu_part(header, true, false, &unit[1..799]),
            nal::fu_part(header, false, false, &unit[799..900]),
            nal::fu_part(header, false, true, &unit[900..]),
        ];
        let first = run(&mut n, 3, false, &parts[0]);
        assert_eq!(first.len(), 1, "498 bytes out, 300 held");
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
    fn a_fragmented_unit_the_camera_never_ended_goes_out_as_it_is_rfc6184_5_8() {
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
        // A fragment of another unit does not continue it either.
        run(&mut n, 6, false, &parts[0]);
        let other = nal::fragment(&idr(3_000), 1_400);
        let out = run(&mut n, 6, true, &other[1]);
        assert_eq!(reassemble(&out[..1]).1, [(false, false)]);
        assert_eq!(n.stats().violations, 5);
    }

    #[test]
    fn an_access_unit_past_libwebrtc_max_frame_packets_is_reported_once() {
        // At a 10-byte target an FU-A carries 8 bytes: a slice of 8 × 2047
        // bytes after its header is 2047 packets, the most libwebrtc
        // assembles; one byte more is 2048.
        let mut n = PacketNormalizer::new(10, ParameterSets::default());
        let fits = slice(8 * LIBWEBRTC_MAX_FRAME_PACKETS);
        assert_eq!(
            run(&mut n, 1, true, &fits).len(),
            LIBWEBRTC_MAX_FRAME_PACKETS
        );
        assert_eq!(n.take_frame_over_limit(), None);
        let over = slice(8 * LIBWEBRTC_MAX_FRAME_PACKETS + 1);
        assert_eq!(
            run(&mut n, 2, true, &over).len(),
            LIBWEBRTC_MAX_FRAME_PACKETS + 1
        );
        assert_eq!(
            n.take_frame_over_limit(),
            Some(FrameOverLimit {
                packets: LIBWEBRTC_MAX_FRAME_PACKETS + 1,
                bytes: over.len() - 1 + 2 * (LIBWEBRTC_MAX_FRAME_PACKETS + 1),
                keyframe: false,
            })
        );
        assert_eq!(n.take_frame_over_limit(), None, "reported once");
        // Counted over the access unit's packets, ended by the next
        // timestamp when the camera sets no marker; a keyframe says so.
        run(&mut n, 3, false, &idr(8 * 1_500));
        run(&mut n, 3, false, &slice(8 * 1_000));
        assert_eq!(n.take_frame_over_limit(), None, "not ended yet");
        run(&mut n, 4, true, &slice(4));
        let big = n.take_frame_over_limit().unwrap();
        assert_eq!(big.packets, 2_500);
        assert!(big.keyframe);
        assert_eq!(n.stats().frames_over_browser_limit, 2);
        // The next access unit starts its own count.
        run(&mut n, 5, true, &fits);
        assert_eq!(n.stats().frames_over_browser_limit, 2);
    }

    #[test]
    fn a_filler_packet_that_ends_the_access_unit_keeps_its_marker_rfc6184_5_1() {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        run(&mut n, 1, false, &slice(10));
        let out = run(&mut n, 1, true, &[0x2c, 0xff, 0xff, 0x80]);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].payload[..], [0x2c, 0x80], "its header, no bytes");
        assert!(out[0].marker && !out[0].frame_start && !out[0].synthetic);
        let stap = nal::stap_a(&[&[0x0c, 0xff], &[0x2c, 0xff]]);
        let out = run(&mut n, 2, true, &stap);
        assert_eq!(
            &out[0].payload[..],
            [0x0c, 0x80],
            "the first filler's header"
        );
        assert!(out[0].marker && out[0].frame_start);
        assert_eq!(n.stats().filler_dropped, 2);
        assert_eq!(
            Classified::end_of_unit(&[]).payloads,
            [Bytes::from_static(&[nal::NAL_FILLER, 0x80])]
        );
    }

    #[test]
    fn filler_is_dropped_and_violations_are_errors() {
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, ParameterSets::default());
        assert!(run(&mut n, 1, false, &[0x0c, 0xff, 0xff]).is_empty());
        let stap = nal::stap_a(&[&[0x0c, 0xff], &slice(4)]);
        let out = run(&mut n, 2, true, &stap);
        assert_eq!(out.len(), 1);
        assert_eq!(
            nal::nal_type(out[0].payload[0]),
            nal::NAL_SLICE,
            "rebuilt without filler"
        );
        let only_filler = nal::stap_a(&[&[0x0c, 0xff]]);
        assert!(run(&mut n, 3, false, &only_filler).is_empty());
        assert_eq!(n.stats().filler_dropped, 3);
        let mut out = Vec::new();
        assert_eq!(
            n.normalize(4, true, &Bytes::from_static(&[nal::STAP_B, 0]), &mut out),
            Err(PayloadError::UnsupportedType(nal::STAP_B))
        );
        assert_eq!(
            n.normalize(
                4,
                true,
                &Bytes::from_static(&[0x78, 0x00, 0x09, 0x67]),
                &mut out
            ),
            Err(PayloadError::Truncated)
        );
        assert!(out.is_empty());
        assert_eq!(n.stats().violations, 2);
        assert_eq!(n.stats().packets, 5);
    }

    /// Found by the `h264_normalize` fuzz target: a 7-byte SPS and a
    /// 189-byte PPS, then an IDR, at a 200-byte target. The STAP-A of both
    /// sets is 201 bytes, one over. The PPS bytes are opaque here; only
    /// their length matters.
    #[test]
    fn parameter_sets_too_large_for_one_stap_a_are_inserted_split_rfc6184_5_7_1() {
        let sps = [0x47, 0xb4, 0x92, 0xfe, 0xff, 0xff, 0xff];
        let mut pps = vec![0x08, 0x47];
        pps.resize(189, 0x05);
        let mut n = PacketNormalizer::new(200, ParameterSets::default());
        run(&mut n, 76, false, &sps);
        run(&mut n, 76, false, &pps);
        let out = run(&mut n, 76, true, &[0x05]);
        assert!(out.iter().all(|p| p.payload.len() <= 200), "{out:?}");
        assert_eq!(out.len(), 3, "the SPS, the PPS, the IDR");
        assert_eq!(
            (&out[0].payload[..], &out[1].payload[..]),
            (&sps[..], &pps[..])
        );
        assert!(out[0].synthetic && out[0].keyframe_start && !out[0].frame_start);
        assert!(out[1].synthetic && !out[1].keyframe_start && !out[1].frame_start);
        assert!(!out[2].synthetic && !out[2].keyframe_start && out[2].marker);
        assert_eq!(n.stats().inserted, 1);
        // At a frame start, only the first inserted packet starts the frame.
        let out = run(&mut n, 77, true, &[0x05]);
        assert!(out[0].frame_start && !out[1].frame_start && !out[2].frame_start);
        // At a target of exactly the aggregate's 201 bytes, it stays one.
        let mut n = PacketNormalizer::new(201, n.parameter_sets().clone());
        let out = run(&mut n, 78, true, &[0x05]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].payload, n.parameter_sets().stap_a().unwrap());
    }

    #[test]
    fn sdp_parameter_sets_seed_the_normalizer() {
        let mut sets = ParameterSets::default();
        sets.observe(&sps(640, 480));
        sets.observe(&pps());
        let mut n = PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, sets);
        let out = run(&mut n, 1, true, &idr(10));
        assert_eq!(out.len(), 2);
        assert!(out[0].synthetic && out[0].keyframe_start && out[0].frame_start);
        assert!(!out[1].frame_start);
    }
}
