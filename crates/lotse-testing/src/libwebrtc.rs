//! A model of how Chrome's WebRTC receiver turns H.264 and H.265 RTP into
//! frames it hands to the decoder, so tests can check the RTP lotse emits
//! against the rules the browser enforces, which the headless `str0m`
//! viewer does not.
//!
//! Observed behavior, not a specification: libwebrtc at
//! `aeb9b3750c30bd1189448138b6431b73116b1f56` (webrtc.googlesource.com,
//! read on 2026-10-05; the H.265 parts first at `b58dcf8f`, 2026-10-03).
//! `video/rtp_video_stream_receiver2.cc` sends every H.265 stream through
//! the H26x packet buffer, and H.264 through it only under the
//! `WebRTC-Video-H26xPacketBuffer` field trial, otherwise through the
//! generic one (`UseH26xPacketBuffer`):
//!
//! - `modules/video_coding/h26x_packet_buffer.cc` ([`H265Receiver`]): a
//!   ring of 2048 packet slots, indexed by sequence number. A packet starts
//!   a run only when it continues one of five tracked runs or carries a
//!   VPS. A packet with the marker bit ends a frame, whose start is found
//!   by walking back while the RTP timestamp stays the same; a frame of
//!   2048 packets or more is never found, and a packet landing on a slot
//!   that holds one with the same timestamp is dropped as a duplicate. A
//!   frame with an IRAP NAL unit (types 16 to 23) is a keyframe, and is
//!   assembled only when its VPS, SPS and PPS came no later than the
//!   packet holding the IRAP unit.
//! - `modules/video_coding/packet_buffer.cc` ([`H264Receiver`]): a ring of
//!   512 slots (`kPacketBufferStartSize` in the receiver) that doubles when
//!   a packet's slot holds another, up to 2048 (`kPacketBufferMaxSize`);
//!   full at 2048, the whole buffer is cleared and a keyframe requested,
//!   so a frame of 2049 packets or more is never assembled. A packet
//!   continues a frame when it starts one (the depacketizer's
//!   `is_first_packet_in_frame`: SPS, PPS, AUD, SEI, or a slice with
//!   `first_mb_in_slice` 0) or follows a continuous packet of its
//!   timestamp. A marker bit ends a frame, found by walking back while the
//!   timestamp stays the same, at most the ring's size; it is a keyframe
//!   when it holds an IDR slice, and a delta frame after a missing packet
//!   is not handed on. `modules/video_coding/h264_sps_pps_tracker.cc`
//!   drops the first packet of an IDR before its SPS and PPS and asks for
//!   a keyframe. A packet that lands on a slot after the buffer was full
//!   and cleared, but whose frame lost its first packets, stays in the
//!   ring until a decoded frame clears past it (below), or until a packet
//!   2048 sequence numbers later needs its slot and the buffer is cleared
//!   again.
//! - `modules/video_coding/rtp_seq_num_only_ref_finder.cc`, behind both: a
//!   delta frame is handed on only when its first sequence number directly
//!   follows the last packet of the last frame handed on in its group of
//!   pictures; otherwise it is stashed (at most 100), so one packet that
//!   belongs to no frame withholds every delta frame up to the next
//!   keyframe.
//! - `RtpVideoStreamReceiver2::FrameDecoded` (`video/rtp_video_stream_receiver2.cc`),
//!   the cleanup after each decoded frame: `PacketBuffer::ClearTo` empties
//!   every slot of the generic buffer up to the frame's last sequence
//!   number and from then on drops packets before it as old;
//!   `RtpSeqNumOnlyRefFinder::ClearTo` drops the stashed frames that start
//!   before it. The H26x buffer has no such cleanup. The model decodes
//!   every frame the moment it is handed on.
//!
//! The most packets of one frame both buffers assemble is recorded in one
//! place, `lotse_codec::h264::LIBWEBRTC_MAX_FRAME_PACKETS`, whose
//! documentation says how to re-check it. When a newer libwebrtc is read,
//! update that constant first, then the constants and the
//! `libwebrtc_aeb9b375_*` tests here, which record what a frame sent whole
//! past it does at that revision.
//!
//! Left out: padding, sequence number wrap-around beyond the 64-bit
//! unwrapping, the generic buffer's clear on a large backward jump in
//! sequence numbers, the cleanup of old groups of pictures, the parsing of
//! SPS, PPS and slice headers past `first_mb_in_slice`, and H.264 through
//! the H26x buffer.

use std::collections::{BTreeMap, BTreeSet};

/// `H26xPacketBuffer::kBufferSize`.
pub const BUFFER_SIZE: usize = 2048;

/// `kPacketBufferStartSize` (`rtp_video_stream_receiver2.cc`): the generic
/// packet buffer's first size.
pub const PACKET_BUFFER_START_SIZE: usize = 512;

/// `kPacketBufferMaxSize` (`rtp_video_stream_receiver2.cc`): the generic
/// packet buffer's largest size.
pub const PACKET_BUFFER_MAX_SIZE: usize = 2048;

/// [`BUFFER_SIZE`] in sequence numbers.
const SPAN: i64 = 2048;

/// `H26xPacketBuffer::kNumTrackedSequences`.
const TRACKED_SEQUENCES: usize = 5;

/// `RtpSeqNumOnlyRefFinder::kMaxStashedFrames`.
const MAX_STASHED_FRAMES: usize = 100;

/// RFC 7798 §4.4.2 aggregation packet.
const AP: u8 = 48;

/// RFC 7798 §4.4.3 fragmentation unit.
const FU: u8 = 49;

/// ITU-T H.265 Table 7-1: VPS, SPS and PPS.
const VPS: u8 = 32;
/// See [`VPS`].
const SPS: u8 = 33;
/// See [`VPS`].
const PPS: u8 = 34;

/// ISO/IEC 14496-10 Table 7-1: a non-IDR slice, an IDR slice, SEI, SPS,
/// PPS and the access unit delimiter.
const H264_SLICE: u8 = 1;
/// See [`H264_SLICE`].
const H264_IDR: u8 = 5;
/// See [`H264_SLICE`].
const H264_SEI: u8 = 6;
/// See [`H264_SLICE`].
const H264_SPS: u8 = 7;
/// See [`H264_SLICE`].
const H264_PPS: u8 = 8;
/// See [`H264_SLICE`].
const H264_AUD: u8 = 9;

/// RFC 6184 §5.7.1 STAP-A.
const STAP_A: u8 = 24;

/// RFC 6184 §5.8 FU-A.
const FU_A: u8 = 28;

/// One frame the receiver assembled and handed on to the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// The first packet's sequence number, unwrapped.
    pub first_seq: i64,
    /// The last packet's, unwrapped.
    pub last_seq: i64,
    /// The RTP timestamp.
    pub ts: u32,
    /// It holds an IRAP picture.
    pub keyframe: bool,
    /// Parameter set NAL units after the frame's first VCL NAL unit.
    /// Chrome's decoder (`media/gpu/h265_decoder.cc` and
    /// `media/gpu/h264_decoder.cc`, read 2026-10-09) finishes the picture
    /// at each of them, as ITU-T H.265 §7.4.2.4.4 and ISO/IEC 14496-10
    /// §7.4.1.2.3 make them start a new access unit, and then fails the
    /// slices after them as a picture without its first slice: the frame
    /// decodes to nothing. A frame the decoder shows has none.
    pub misplaced_sets: usize,
}

/// How many parameter set NAL units follow the first VCL NAL unit in
/// `types`, the NAL unit types of a frame's packets in order:
/// [`Frame::misplaced_sets`]. `vcl` and `set` tell the types apart.
fn misplaced_sets(
    types: impl IntoIterator<Item = u8>,
    vcl: fn(u8) -> bool,
    set: fn(u8) -> bool,
) -> usize {
    let mut seen_vcl = false;
    let mut count = 0_usize;
    for unit_type in types {
        if vcl(unit_type) {
            seen_vcl = true;
        } else if set(unit_type) && seen_vcl {
            count = count.saturating_add(1);
        }
    }
    count
}

/// One packet waiting in the ring.
#[derive(Debug, Clone)]
struct Slot {
    /// The unwrapped sequence number.
    seq: i64,
    /// The RTP timestamp.
    ts: u32,
    /// The marker bit.
    marker: bool,
    /// The types of the NAL units that start in it.
    types: Vec<u8>,
}

/// The receiver of one H.265 stream.
#[derive(Debug)]
pub struct H265Receiver {
    /// The ring of packets not yet assembled.
    slots: Vec<Option<Slot>>,
    /// The last continuous sequence number of each tracked run.
    runs: [Option<i64>; TRACKED_SEQUENCES],
    /// The run a new one replaces next.
    next_run: usize,
    /// Unwraps the sequence numbers.
    unwrapper: Unwrapper,
    /// The reference finder behind the buffer.
    refs: RefFinder,
}

impl Default for H265Receiver {
    fn default() -> Self {
        Self {
            slots: vec![None; BUFFER_SIZE],
            runs: [None; TRACKED_SEQUENCES],
            next_run: 0,
            unwrapper: Unwrapper::default(),
            refs: RefFinder::default(),
        }
    }
}

/// Unwraps 16-bit sequence numbers against the newest one.
#[derive(Debug, Default)]
struct Unwrapper {
    /// The newest sequence number seen, unwrapped.
    last: Option<i64>,
}

impl Unwrapper {
    /// `seq`, unwrapped.
    fn unwrap(&mut self, seq: u16) -> i64 {
        let unwrapped = self.last.map_or_else(
            || i64::from(seq),
            |last| {
                let last_u16 = u16::try_from(last.rem_euclid(1 << 16)).unwrap_or(0);
                let forward = seq.wrapping_sub(last_u16);
                if forward < 0x8000 {
                    last.saturating_add(i64::from(forward))
                } else {
                    last.saturating_sub(i64::from(last_u16.wrapping_sub(seq)))
                }
            },
        );
        self.last = Some(self.last.map_or(unwrapped, |last| last.max(unwrapped)));
        unwrapped
    }
}

/// Whether `a` is after `b` on the 32-bit RTP clock (`AheadOf`).
const fn ts_ahead(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < (1_u32 << 31)
}

/// The types of the NAL units that start in an RFC 7798 payload; empty for
/// a fragment other than the first, or a payload that does not parse.
fn nal_types(payload: &[u8]) -> Vec<u8> {
    let Some(&first) = payload.first() else {
        return Vec::new();
    };
    match (first >> 1) & 0x3f {
        AP => {
            let mut types = Vec::new();
            let mut rest = payload.get(2..).unwrap_or(&[]);
            while let Some((&[hi, lo], tail)) = rest.split_at_checked(2) {
                let len = usize::from(u16::from_be_bytes([hi, lo]));
                let Some((unit, tail)) = tail.split_at_checked(len) else {
                    break;
                };
                if let Some(&header) = unit.first() {
                    types.push((header >> 1) & 0x3f);
                }
                rest = tail;
            }
            types
        }
        FU => payload
            .get(2)
            .filter(|&&fu| fu & 0x80 != 0)
            .map(|&fu| vec![fu & 0x3f])
            .unwrap_or_default(),
        unit_type => vec![unit_type],
    }
}

impl H265Receiver {
    /// A receiver that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// The frames handed on to the decoder so far.
    pub fn frames(&self) -> &[Frame] {
        &self.refs.frames
    }

    /// How many frames are stashed, waiting for one before them.
    pub fn stashed(&self) -> usize {
        self.refs.stashed.len()
    }

    /// One received packet (`H26xPacketBuffer::InsertPacket`).
    pub fn insert(&mut self, seq: u16, ts: u32, marker: bool, payload: &[u8]) {
        let seq = self.unwrapper.unwrap(seq);
        let index = Self::index(seq);
        if let Some(Some(held)) = self.slots.get(index)
            && (held.ts == ts || ts_ahead(held.ts, ts))
        {
            // Old, or a duplicate: dropped.
            return;
        }
        if let Some(slot) = self.slots.get_mut(index) {
            *slot = Some(Slot {
                seq,
                ts,
                marker,
                types: nal_types(payload),
            });
        }
        let handed = self.refs.frames.len();
        self.find_frames(seq);
        // `FrameDecoded`: the H26x buffer has no `ClearTo`, the reference
        // finder does.
        if let Some(last) = self.refs.decoded_since(handed) {
            self.refs.clear_to(last);
        }
    }

    /// The ring slot of a sequence number.
    fn index(seq: i64) -> usize {
        usize::try_from(seq.rem_euclid(SPAN)).unwrap_or(0)
    }

    /// The packet in the ring at `seq`, if that slot holds it.
    fn slot(&self, seq: i64) -> Option<&Slot> {
        self.slots.get(Self::index(seq)).and_then(Option::as_ref)
    }

    /// `H26xPacketBuffer::FindFrames`.
    fn find_frames(&mut self, start: i64) {
        let previous = start.saturating_sub(1);
        let run = if let Some(run) = self.runs.iter().position(|r| *r == Some(previous)) {
            run
        } else {
            // Not continuous: only a packet with a VPS starts a run.
            if !self
                .slot(start)
                .is_some_and(|slot| slot.types.contains(&VPS))
            {
                return;
            }
            let run = self.next_run;
            self.next_run = self
                .next_run
                .saturating_add(1)
                .checked_rem(TRACKED_SEQUENCES)
                .unwrap_or(0);
            run
        };
        let mut seq = start;
        while seq < start.saturating_add(SPAN) {
            let Some((marker, ts)) = self
                .slot(seq)
                .filter(|slot| slot.seq == seq)
                .map(|slot| (slot.marker, slot.ts))
            else {
                return;
            };
            if let Some(last) = self.runs.get_mut(run) {
                *last = Some(seq);
            }
            if marker {
                // Walk back to the frame's start; a frame of 2048 packets
                // or more is never found.
                let mut first = seq;
                while first > seq.saturating_sub(SPAN) {
                    if self
                        .slot(first.saturating_sub(1))
                        .is_none_or(|prev| prev.ts != ts)
                    {
                        if !self.assemble(first, seq) {
                            return;
                        }
                        break;
                    }
                    first = first.saturating_sub(1);
                }
            }
            seq = seq.saturating_add(1);
        }
    }

    /// `H26xPacketBuffer::MaybeAssembleFrame`, then the reference finder.
    fn assemble(&mut self, first: i64, last: i64) -> bool {
        let (mut vps, mut sps, mut pps, mut irap) = (false, false, false, false);
        let mut ts = 0;
        for seq in first..=last {
            let Some(slot) = self.slot(seq) else {
                return false;
            };
            ts = slot.ts;
            for &unit_type in &slot.types {
                irap |= (16..=23).contains(&unit_type);
                vps |= unit_type == VPS;
                sps |= unit_type == SPS;
                pps |= unit_type == PPS;
            }
            if irap && !(vps && sps && pps) {
                return false;
            }
        }
        let misplaced = misplaced_sets(
            (first..=last)
                .filter_map(|seq| self.slot(seq))
                .flat_map(|slot| slot.types.iter().copied()),
            |unit_type| unit_type <= 31,
            |unit_type| (VPS..=PPS).contains(&unit_type),
        );
        for seq in first..=last {
            if let Some(slot) = self.slots.get_mut(Self::index(seq)) {
                *slot = None;
            }
        }
        self.refs.manage(Frame {
            first_seq: first,
            last_seq: last,
            ts,
            keyframe: irap,
            misplaced_sets: misplaced,
        });
        true
    }
}

/// `RtpSeqNumOnlyRefFinder`, which hands the frames either packet buffer
/// assembled on in an order the decoder can use.
#[derive(Debug, Default)]
struct RefFinder {
    /// Per group of pictures (keyed by its keyframe's last sequence
    /// number): the last sequence number of the last frame handed on.
    gops: BTreeMap<i64, i64>,
    /// Frames waiting for the one before them, newest first.
    stashed: Vec<Frame>,
    /// The frames handed on, in order.
    frames: Vec<Frame>,
}

impl RefFinder {
    /// `RtpSeqNumOnlyRefFinder::ManageFrame`.
    fn manage(&mut self, frame: Frame) {
        match self.decide(frame) {
            Decision::Stash => {
                if self.stashed.len() > MAX_STASHED_FRAMES {
                    let _oldest = self.stashed.pop();
                }
                self.stashed.insert(0, frame);
            }
            Decision::HandOff => {
                self.frames.push(frame);
                self.retry_stashed();
            }
            Decision::Drop => {}
        }
    }

    /// `RtpSeqNumOnlyRefFinder::ManageFrameInternal`.
    fn decide(&mut self, frame: Frame) -> Decision {
        if frame.keyframe {
            self.gops.insert(frame.last_seq, frame.last_seq);
        }
        if self.gops.is_empty() {
            return Decision::Stash;
        }
        let Some((_, last_in_gop)) = self.gops.range_mut(..=frame.last_seq).next_back() else {
            return Decision::Drop;
        };
        if !frame.keyframe && frame.first_seq.saturating_sub(1) != *last_in_gop {
            return Decision::Stash;
        }
        *last_in_gop = (*last_in_gop).max(frame.last_seq);
        Decision::HandOff
    }

    /// `RtpSeqNumOnlyRefFinder::ClearTo`, after a decoded frame that ends
    /// at `seq`: the stashed frames that start before it are dropped.
    fn clear_to(&mut self, seq: i64) {
        self.stashed.retain(|frame| frame.first_seq >= seq);
    }

    /// The last sequence number of the frames handed on since there were
    /// `handed`, which the decoder has decoded by now.
    fn decoded_since(&self, handed: usize) -> Option<i64> {
        self.frames
            .get(handed..)
            .and_then(|frames| frames.iter().map(|frame| frame.last_seq).max())
    }

    /// `RtpSeqNumOnlyRefFinder::RetryStashedFrames`.
    fn retry_stashed(&mut self) {
        loop {
            let mut progressed = false;
            let mut index = 0;
            while let Some(&frame) = self.stashed.get(index) {
                match self.decide(frame) {
                    Decision::Stash => index = index.saturating_add(1),
                    Decision::HandOff => {
                        self.frames.push(frame);
                        self.stashed.remove(index);
                        progressed = true;
                    }
                    Decision::Drop => {
                        self.stashed.remove(index);
                    }
                }
            }
            if !progressed {
                return;
            }
        }
    }
}

/// One packet waiting in the generic packet buffer.
#[derive(Debug, Clone)]
struct H264Slot {
    /// The unwrapped sequence number.
    seq: i64,
    /// The RTP timestamp.
    ts: u32,
    /// The marker bit.
    marker: bool,
    /// `is_first_packet_in_frame`, as the depacketizer sets it.
    first: bool,
    /// The types of the NAL units that start in it.
    types: Vec<u8>,
    /// `continuous`: every packet of its frame up to it is here.
    continuous: bool,
}

/// What `video_rtp_depacketizer_h264.cc` reads from an RFC 6184 payload:
/// the types of the NAL units that start in it, and whether it starts a
/// frame (`is_first_packet_in_frame`): an SPS, PPS, AUD or SEI, or a
/// slice whose `first_mb_in_slice` is 0 (ISO/IEC 14496-10 §7.3.3, the
/// first `ue(v)`: 0 is a single 1 bit).
fn h264_units(payload: &[u8]) -> (Vec<u8>, bool) {
    let first_slice = |unit_type: u8, body: Option<&u8>| {
        matches!(unit_type, H264_SLICE | H264_IDR) && body.is_some_and(|b| b & 0x80 != 0)
    };
    let starts = |unit_type: u8, body: Option<&u8>| {
        matches!(unit_type, H264_SPS | H264_PPS | H264_AUD | H264_SEI)
            || first_slice(unit_type, body)
    };
    let Some(&header) = payload.first() else {
        return (Vec::new(), false);
    };
    match header & 0x1f {
        STAP_A => {
            let (mut types, mut first) = (Vec::new(), false);
            let mut rest = payload.get(1..).unwrap_or(&[]);
            while let Some((&[hi, lo], tail)) = rest.split_at_checked(2) {
                let len = usize::from(u16::from_be_bytes([hi, lo]));
                let Some((unit, tail)) = tail.split_at_checked(len) else {
                    break;
                };
                if let Some(&unit_header) = unit.first() {
                    types.push(unit_header & 0x1f);
                    first |= starts(unit_header & 0x1f, unit.get(1));
                }
                rest = tail;
            }
            (types, first)
        }
        FU_A => match payload.get(1) {
            Some(&fu) if fu & 0x80 != 0 => {
                (vec![fu & 0x1f], first_slice(fu & 0x1f, payload.get(2)))
            }
            _ => (Vec::new(), false),
        },
        unit_type => (vec![unit_type], starts(unit_type, payload.get(1))),
    }
}

/// The receiver of one H.264 stream through the generic packet buffer,
/// with the SPS/PPS tracker in front of it.
#[derive(Debug)]
pub struct H264Receiver {
    /// The ring, [`PACKET_BUFFER_START_SIZE`] to [`PACKET_BUFFER_MAX_SIZE`]
    /// slots.
    buffer: Vec<Option<H264Slot>>,
    /// Unwraps the sequence numbers.
    unwrapper: Unwrapper,
    /// `first_seq_num_`, once `first_packet_received_`: the oldest
    /// sequence number the ring may hold.
    first: Option<i64>,
    /// `is_cleared_to_first_seq_num_`: a decoded frame cleared the ring up
    /// to [`Self::first`], so a packet before it is old.
    cleared_to_first: bool,
    /// `newest_inserted_seq_num_`.
    newest: Option<i64>,
    /// `missing_packets_`: sequence numbers skipped, at most 1000 back.
    missing: BTreeSet<i64>,
    /// The tracker has seen an SPS.
    sps: bool,
    /// The tracker has seen a PPS.
    pps: bool,
    /// Keyframes asked for.
    keyframe_requests: usize,
    /// The reference finder behind the buffer.
    refs: RefFinder,
}

impl Default for H264Receiver {
    fn default() -> Self {
        Self {
            buffer: vec![None; PACKET_BUFFER_START_SIZE],
            unwrapper: Unwrapper::default(),
            first: None,
            cleared_to_first: false,
            newest: None,
            missing: BTreeSet::new(),
            sps: false,
            pps: false,
            keyframe_requests: 0,
            refs: RefFinder::default(),
        }
    }
}

impl H264Receiver {
    /// A receiver that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// The frames handed on to the decoder so far.
    pub fn frames(&self) -> &[Frame] {
        &self.refs.frames
    }

    /// How many frames are stashed, waiting for one before them.
    pub fn stashed(&self) -> usize {
        self.refs.stashed.len()
    }

    /// The keyframes it asked the sender for: the buffer was full and
    /// cleared (`buffer_cleared`), or an IDR came before its SPS and PPS.
    pub const fn keyframe_requests(&self) -> usize {
        self.keyframe_requests
    }

    /// The ring's size now.
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }

    /// One received packet: `H264SpsPpsTracker::CopyAndFixBitstream`, then
    /// `PacketBuffer::InsertPacket`.
    pub fn insert(&mut self, seq: u16, ts: u32, marker: bool, payload: &[u8]) {
        let seq = self.unwrapper.unwrap(seq);
        let (types, first) = h264_units(payload);
        for &unit_type in &types {
            match unit_type {
                H264_SPS => self.sps = true,
                H264_PPS => self.pps = true,
                H264_IDR if first && !(self.sps && self.pps) => {
                    self.keyframe_requests = self.keyframe_requests.saturating_add(1);
                    return;
                }
                _ => {}
            }
        }
        match self.first {
            None => self.first = Some(seq),
            Some(first) if first > seq => {
                if self.cleared_to_first {
                    // Before a decoded frame: old.
                    return;
                }
                self.first = Some(seq);
            }
            Some(_) => {}
        }
        if let Some(held) = self.slot(seq) {
            if held.seq == seq {
                // A duplicate.
                return;
            }
            while self.expand() && self.slot(seq).is_some() {}
            if self.slot(seq).is_some() {
                // Full at the largest size: cleared (`ClearInternal`), and a
                // keyframe asked for.
                self.buffer.iter_mut().for_each(|slot| *slot = None);
                self.first = None;
                self.cleared_to_first = false;
                self.newest = None;
                self.missing.clear();
                self.keyframe_requests = self.keyframe_requests.saturating_add(1);
                return;
            }
        }
        let index = self.index(seq);
        if let Some(slot) = self.buffer.get_mut(index) {
            *slot = Some(H264Slot {
                seq,
                ts,
                marker,
                first,
                types,
                continuous: false,
            });
        }
        self.update_missing(seq);
        let handed = self.refs.frames.len();
        self.find_frames(seq);
        // `FrameDecoded`: both clear up to the last frame decoded.
        if let Some(last) = self.refs.decoded_since(handed) {
            self.clear_to(last);
            self.refs.clear_to(last);
        }
    }

    /// `PacketBuffer::ClearTo`, after a decoded frame that ends at `seq`:
    /// every slot from [`Self::first`] up to `seq` is emptied, at most the
    /// ring's size of them, and a packet before `seq + 1` is old from now
    /// on.
    fn clear_to(&mut self, seq: i64) {
        let Some(first) = self.first.filter(|&first| first <= seq) else {
            return;
        };
        let end = seq.saturating_add(1);
        let iterations = usize::try_from(end.saturating_sub(first))
            .unwrap_or(0)
            .min(self.buffer.len());
        let mut at = first;
        for _ in 0..iterations {
            let index = self.index(at);
            if let Some(slot) = self.buffer.get_mut(index)
                && slot.as_ref().is_some_and(|held| held.seq < end)
            {
                *slot = None;
            }
            at = at.saturating_add(1);
        }
        self.first = Some(end);
        self.cleared_to_first = true;
        self.missing = self.missing.split_off(&end);
    }

    /// The ring slot of a sequence number at the ring's size now.
    fn index(&self, seq: i64) -> usize {
        let size = i64::try_from(self.buffer.len()).unwrap_or(1);
        usize::try_from(seq.rem_euclid(size)).unwrap_or(0)
    }

    /// The packet in the slot of `seq`, whichever it is.
    fn slot(&self, seq: i64) -> Option<&H264Slot> {
        self.buffer.get(self.index(seq)).and_then(Option::as_ref)
    }

    /// `PacketBuffer::ExpandBufferSize`: doubles the ring up to its
    /// largest size; `false` when it is there already.
    fn expand(&mut self) -> bool {
        if self.buffer.len() >= PACKET_BUFFER_MAX_SIZE {
            return false;
        }
        let size = self
            .buffer
            .len()
            .saturating_mul(2)
            .min(PACKET_BUFFER_MAX_SIZE);
        let old = std::mem::replace(&mut self.buffer, vec![None; size]);
        for slot in old.into_iter().flatten() {
            let index = self.index(slot.seq);
            if let Some(entry) = self.buffer.get_mut(index) {
                *entry = Some(slot);
            }
        }
        true
    }

    /// `PacketBuffer::UpdateMissingPackets`.
    fn update_missing(&mut self, seq: i64) {
        let newest = *self.newest.get_or_insert(seq);
        if seq > newest {
            let old = seq.saturating_sub(1000);
            self.missing = self.missing.split_off(&old);
            let mut next = newest.max(old).saturating_add(1);
            while seq > next {
                self.missing.insert(next);
                next = next.saturating_add(1);
            }
            self.newest = Some(seq);
        } else {
            self.missing.remove(&seq);
        }
    }

    /// `PacketBuffer::PotentialNewFrame`.
    fn potential_new_frame(&self, seq: i64) -> bool {
        let Some(entry) = self.slot(seq).filter(|slot| slot.seq == seq) else {
            return false;
        };
        entry.first
            || self.slot(seq.saturating_sub(1)).is_some_and(|prev| {
                prev.seq == seq.saturating_sub(1) && prev.ts == entry.ts && prev.continuous
            })
    }

    /// `PacketBuffer::FindFrames`, for H.264 without a generic frame
    /// descriptor.
    fn find_frames(&mut self, start: i64) {
        let mut seq = start;
        for _ in 0..self.buffer.len() {
            if !self.potential_new_frame(seq) {
                return;
            }
            let index = self.index(seq);
            let Some(Some(slot)) = self.buffer.get_mut(index) else {
                return;
            };
            slot.continuous = true;
            let (marker, ts) = (slot.marker, slot.ts);
            if marker {
                // Walk back while the timestamp stays, at most the ring's
                // size.
                let mut first = seq;
                let mut idr = false;
                let mut tested = 0_usize;
                loop {
                    tested = tested.saturating_add(1);
                    idr |= self
                        .slot(first)
                        .is_some_and(|slot| slot.types.contains(&H264_IDR));
                    if tested == self.buffer.len() {
                        break;
                    }
                    let previous = first.saturating_sub(1);
                    if self
                        .slot(previous)
                        .is_none_or(|prev| prev.seq != previous || prev.ts != ts)
                    {
                        break;
                    }
                    first = previous;
                }
                if !idr && self.missing.range(..=first).next().is_some() {
                    // A delta frame after a gap.
                    return;
                }
                let misplaced = misplaced_sets(
                    (first..=seq)
                        .filter_map(|j| self.slot(j))
                        .flat_map(|slot| slot.types.iter().copied()),
                    |unit_type| (1..=H264_IDR).contains(&unit_type),
                    |unit_type| unit_type == H264_SPS || unit_type == H264_PPS,
                );
                for j in first..=seq {
                    let index = self.index(j);
                    if let Some(slot) = self.buffer.get_mut(index) {
                        *slot = None;
                    }
                }
                self.missing = self.missing.split_off(&seq.saturating_add(1));
                self.refs.manage(Frame {
                    first_seq: first,
                    last_seq: seq,
                    ts,
                    keyframe: idr,
                    misplaced_sets: misplaced,
                });
            }
            seq = seq.saturating_add(1);
        }
    }
}

/// What the reference finder does with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// Kept until the frame before it is handed on.
    Stash,
    /// Handed on to the decoder.
    HandOff,
    /// Belongs to no group of pictures.
    Drop,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    fn sets() -> Vec<u8> {
        vec![
            AP << 1,
            1,
            0,
            3,
            VPS << 1,
            1,
            0xaa,
            0,
            3,
            SPS << 1,
            1,
            0xbb,
            0,
            3,
            PPS << 1,
            1,
            0xcc,
        ]
    }

    fn idr() -> Vec<u8> {
        vec![19 << 1, 1, 0xab]
    }

    fn trail() -> Vec<u8> {
        vec![1 << 1, 1, 0xab]
    }

    fn fu(start: bool, unit_type: u8) -> Vec<u8> {
        vec![FU << 1, 1, u8::from(start) << 7 | unit_type, 0xab]
    }

    #[test]
    fn libwebrtc_h26x_packet_buffer_assembles_a_keyframe_and_continuous_delta_frames() {
        let mut rx = H265Receiver::new();
        // A delta frame before any VPS starts nothing.
        rx.insert(9, 0, true, &trail());
        assert!(rx.frames().is_empty());
        rx.insert(10, 100, false, &sets());
        rx.insert(11, 100, false, &fu(true, 19));
        rx.insert(12, 100, true, &fu(false, 19));
        rx.insert(13, 200, true, &trail());
        rx.insert(14, 300, false, &fu(true, 1));
        rx.insert(15, 300, true, &fu(false, 1));
        let frames = rx.frames();
        assert_eq!(frames.len(), 3);
        assert!(frames[0].keyframe && frames[0].first_seq == 10 && frames[0].last_seq == 12);
        assert!(!frames[1].keyframe && frames[2].first_seq == 14);
    }

    #[test]
    fn libwebrtc_rtp_seq_num_only_ref_finder_stashes_delta_frames_after_a_packet_of_no_frame() {
        let mut rx = H265Receiver::new();
        rx.insert(1, 100, false, &sets());
        rx.insert(2, 100, true, &idr());
        // A packet of no frame: its timestamp never ends with a marker.
        rx.insert(3, 150, false, &trail());
        rx.insert(4, 200, true, &trail());
        rx.insert(5, 300, true, &trail());
        assert_eq!(rx.frames().len(), 1, "only the keyframe");
        assert_eq!(rx.stashed(), 2);
        // The next keyframe goes through.
        rx.insert(6, 400, false, &sets());
        rx.insert(7, 400, true, &idr());
        rx.insert(8, 500, true, &trail());
        assert_eq!(rx.frames().len(), 3);
    }

    #[test]
    fn libwebrtc_h26x_packet_buffer_never_finds_a_frame_of_2048_packets() {
        for (count, found) in [(BUFFER_SIZE - 1, true), (BUFFER_SIZE, false)] {
            let mut rx = H265Receiver::new();
            rx.insert(0, 100, false, &sets());
            rx.insert(1, 100, false, &fu(true, 19));
            for seq in 2..count {
                let last = seq + 1 == count;
                rx.insert(u16::try_from(seq).unwrap(), 100, last, &fu(false, 19));
            }
            assert_eq!(rx.frames().len(), usize::from(found), "{count} packets");
        }
        // Past the ring, a packet of the same frame lands on a slot that
        // holds one with its timestamp: dropped as a duplicate.
        let mut rx = H265Receiver::new();
        rx.insert(0, 100, false, &sets());
        for seq in 1..=BUFFER_SIZE {
            rx.insert(u16::try_from(seq).unwrap(), 100, seq == BUFFER_SIZE, &idr());
        }
        assert!(rx.frames().is_empty());
    }

    #[test]
    fn libwebrtc_h26x_packet_buffer_wants_the_parameter_sets_by_the_irap_unit() {
        let mut rx = H265Receiver::new();
        rx.insert(1, 100, false, &[0x60, 1, 0, 3, VPS << 1, 1, 0xaa]);
        rx.insert(2, 100, false, &idr());
        rx.insert(
            3,
            100,
            true,
            &[0x60, 1, 0, 3, SPS << 1, 1, 0, 0, 3, PPS << 1, 1, 0],
        );
        assert!(rx.frames().is_empty(), "SPS and PPS after the IDR");
        // An old packet, and a duplicate, are dropped.
        let mut rx = H265Receiver::new();
        rx.insert(1, 100, false, &sets());
        rx.insert(1, 100, false, &sets());
        rx.insert(1 + u16::try_from(BUFFER_SIZE).unwrap(), 50, false, &sets());
        rx.insert(2, 100, true, &idr());
        assert_eq!(rx.frames().len(), 1);
        assert_eq!(nal_types(&[]), Vec::<u8>::new());
        assert_eq!(nal_types(&fu(false, 19)), Vec::<u8>::new());
        assert_eq!(
            nal_types(&[0x60, 1, 0, 9, 1]),
            Vec::<u8>::new(),
            "truncated"
        );
    }

    /// An H.264 STAP-A of an SPS and a PPS.
    fn h264_sets() -> Vec<u8> {
        vec![
            STAP_A,
            0,
            2,
            0x60 | H264_SPS,
            0x42,
            0,
            2,
            0x60 | H264_PPS,
            0xce,
        ]
    }

    /// An FU-A of an H.264 slice of `unit_type`; the first carries
    /// `first_mb_in_slice` 0.
    fn fu_a(start: bool, end: bool, unit_type: u8) -> Vec<u8> {
        vec![
            0x60 | FU_A,
            u8::from(start) << 7 | u8::from(end) << 6 | unit_type,
            0x88,
        ]
    }

    #[test]
    fn libwebrtc_packet_buffer_assembles_an_h264_keyframe_and_continuous_delta_frames() {
        let mut rx = H264Receiver::new();
        // An IDR before any SPS and PPS: dropped, a keyframe asked for.
        rx.insert(9, 0, true, &[0x65, 0x88]);
        assert_eq!(rx.keyframe_requests(), 1);
        rx.insert(10, 100, false, &h264_sets());
        rx.insert(11, 100, false, &fu_a(true, false, H264_IDR));
        rx.insert(12, 100, true, &fu_a(false, true, H264_IDR));
        rx.insert(13, 200, true, &[0x41, 0x88]);
        // An AUD and a SEI first, then a slice in a STAP-A.
        rx.insert(14, 300, false, &[0x09, 0xf0]);
        rx.insert(15, 300, false, &[0x06, 0x05, 0x80]);
        rx.insert(16, 300, true, &[STAP_A, 0, 2, 0x41, 0x88]);
        let frames = rx.frames();
        assert_eq!(frames.len(), 3, "{frames:?}");
        assert!(frames[0].keyframe && frames[0].first_seq == 10 && frames[0].last_seq == 12);
        assert!(!frames[1].keyframe && !frames[2].keyframe && frames[2].first_seq == 14);
        // A duplicate changes nothing.
        rx.insert(16, 300, true, &[STAP_A, 0, 2, 0x41, 0x88]);
        assert_eq!(rx.frames().len(), 3);
        assert_eq!(h264_units(&[]), (Vec::new(), false));
        assert_eq!(
            h264_units(&fu_a(false, false, H264_IDR)),
            (Vec::new(), false)
        );
        assert_eq!(
            h264_units(&[STAP_A, 0, 9, 1]),
            (Vec::new(), false),
            "truncated"
        );
        assert_eq!(
            h264_units(&[0x41, 0x08]),
            (vec![H264_SLICE], false),
            "not the first slice"
        );
    }

    #[test]
    fn libwebrtc_packet_buffer_holds_no_h264_delta_frame_after_a_missing_packet() {
        let mut rx = H264Receiver::new();
        rx.insert(1, 100, false, &h264_sets());
        rx.insert(2, 100, true, &[0x65, 0x88]);
        // Packet 3 never arrives: its frame and the one after are not
        // handed on, the next keyframe is.
        rx.insert(4, 200, true, &fu_a(false, true, H264_SLICE));
        rx.insert(5, 300, true, &[0x41, 0x88]);
        assert_eq!(rx.frames().len(), 1);
        rx.insert(6, 400, false, &h264_sets());
        rx.insert(7, 400, true, &[0x65, 0x88]);
        assert_eq!(rx.frames().len(), 2);
        assert!(rx.frames()[1].keyframe);
    }

    #[test]
    fn libwebrtc_packet_buffer_never_finds_an_h264_frame_of_2049_packets() {
        for (count, found) in [
            (PACKET_BUFFER_MAX_SIZE, true),
            (PACKET_BUFFER_MAX_SIZE + 1, false),
        ] {
            let mut rx = H264Receiver::new();
            rx.insert(0, 100, false, &h264_sets());
            rx.insert(1, 100, false, &fu_a(true, false, H264_IDR));
            for seq in 2..count {
                let last = seq + 1 == count;
                rx.insert(
                    u16::try_from(seq).unwrap(),
                    100,
                    last,
                    &fu_a(false, last, H264_IDR),
                );
            }
            assert_eq!(rx.buffer_size(), PACKET_BUFFER_MAX_SIZE, "grown from 512");
            let keyframes = rx.frames().iter().filter(|f| f.keyframe).count();
            assert_eq!(keyframes, usize::from(found), "{count} packets");
            // Full: cleared, and a keyframe asked for.
            assert_eq!(
                rx.keyframe_requests(),
                usize::from(!found),
                "{count} packets"
            );
        }
        let rx = H264Receiver::new();
        assert_eq!(rx.buffer_size(), PACKET_BUFFER_START_SIZE);
        assert_eq!(rx.stashed(), 0);
    }

    #[test]
    fn libwebrtc_packet_buffer_clear_to_drops_what_a_decoded_h264_frame_leaves_behind() {
        let mut rx = H264Receiver::new();
        rx.insert(1, 100, false, &h264_sets());
        // A packet of a frame that never completes: its first one is lost.
        rx.insert(3, 150, false, &fu_a(false, false, H264_SLICE));
        rx.insert(4, 200, false, &h264_sets());
        rx.insert(5, 200, true, &[0x65, 0x88]);
        assert_eq!(rx.frames().len(), 1);
        // Decoding the keyframe cleared the ring to its last packet: the
        // lost packet 2 comes too late, and the stale packet 3 no longer
        // holds its slot.
        rx.insert(2, 150, false, &fu_a(true, false, H264_SLICE));
        rx.insert(6, 300, true, &[0x41, 0x88]);
        assert_eq!(rx.frames().len(), 2);
        rx.insert(3 + 2048, 400, true, &[0x41, 0x88]);
        assert_eq!(rx.keyframe_requests(), 0, "slot 3 was free");
        assert_eq!(rx.buffer_size(), PACKET_BUFFER_START_SIZE);
    }

    /// Sends frames to a receiver with continuous sequence numbers.
    struct Sender {
        /// The next sequence number.
        seq: u16,
        /// The next RTP timestamp.
        ts: u32,
    }

    impl Sender {
        const fn new() -> Self {
            Self { seq: 0, ts: 0 }
        }

        /// The packets of the next frame: `packets` of them, as `payload`
        /// makes them from the index and whether it is the last. Returns
        /// the frame's timestamp and the first and the last packet's
        /// sequence number.
        fn frame(
            &mut self,
            packets: usize,
            mut payload: impl FnMut(usize, bool) -> Vec<u8>,
            mut insert: impl FnMut(u16, u32, bool, &[u8]),
        ) -> (u32, i64, i64) {
            self.ts = self.ts.wrapping_add(3_000);
            let first = i64::from(self.seq);
            for index in 0..packets {
                let last = index + 1 == packets;
                insert(self.seq, self.ts, last, &payload(index, last));
                self.seq = self.seq.wrapping_add(1);
            }
            (self.ts, first, first + i64::try_from(packets).unwrap() - 1)
        }

        /// An H.264 frame: a keyframe's first packet holds its SPS and
        /// PPS, then FU-A fragments of an IDR slice; a delta frame's are
        /// all FU-A fragments of a slice.
        fn h264(
            &mut self,
            rx: &mut H264Receiver,
            keyframe: bool,
            packets: usize,
        ) -> (u32, i64, i64) {
            let unit = if keyframe { H264_IDR } else { H264_SLICE };
            let head = usize::from(keyframe);
            self.frame(
                packets,
                |index, last| {
                    if index < head {
                        h264_sets()
                    } else {
                        fu_a(index == head, last, unit)
                    }
                },
                |seq, ts, marker, payload| rx.insert(seq, ts, marker, payload),
            )
        }

        /// An H.265 frame: a keyframe's first packet holds its VPS, SPS
        /// and PPS, then FU fragments of an IDR picture; a delta frame's
        /// are all FU fragments of a trailing picture.
        fn h265(
            &mut self,
            rx: &mut H265Receiver,
            keyframe: bool,
            packets: usize,
        ) -> (u32, i64, i64) {
            let unit = if keyframe { 19 } else { 1 };
            let head = usize::from(keyframe);
            self.frame(
                packets,
                |index, _| {
                    if index < head {
                        sets()
                    } else {
                        fu(index == head, unit)
                    }
                },
                |seq, ts, marker, payload| rx.insert(seq, ts, marker, payload),
            )
        }
    }

    /// The frames handed on at or after `ts`, and whether each is a
    /// keyframe.
    fn handed_from(frames: &[Frame], ts: u32) -> Vec<(u32, bool)> {
        frames
            .iter()
            .filter(|frame| frame.ts >= ts)
            .map(|frame| (frame.ts, frame.keyframe))
            .collect()
    }

    /// [`PACKET_BUFFER_MAX_SIZE`] in sequence numbers.
    fn ring() -> i64 {
        i64::try_from(PACKET_BUFFER_MAX_SIZE).unwrap()
    }

    /// The packets of the frame sent whole past the limit in the
    /// `libwebrtc_aeb9b375_*` tests: 2100, more than either buffer
    /// assembles.
    const WHOLE: usize = 2_100;

    #[test]
    fn libwebrtc_aeb9b375_h26x_packet_buffer_plays_the_next_keyframe_after_an_h265_frame_sent_whole_past_2047_packets()
     {
        // Observed behavior at libwebrtc aeb9b375 (read 2026-10-05), what
        // lotse relies on for H.265 when it sends such a frame whole: the
        // packets past the ring land on slots holding the frame's own
        // timestamp and are dropped as duplicates, the frame is never
        // found, the delta frames after it continue no run, and the next
        // keyframe (its VPS starts a run) plays, wherever it falls.
        for deltas in [3, 60] {
            let mut rx = H265Receiver::new();
            let mut tx = Sender::new();
            tx.h265(&mut rx, true, 30);
            tx.h265(&mut rx, false, 20);
            let (big, ..) = tx.h265(&mut rx, true, WHOLE);
            for _ in 0..deltas {
                tx.h265(&mut rx, false, 40);
            }
            let (next, ..) = tx.h265(&mut rx, true, 300);
            let (after, ..) = tx.h265(&mut rx, false, 40);
            assert_eq!(
                handed_from(rx.frames(), big),
                [(next, true), (after, false)],
                "{deltas} deltas"
            );
        }
    }

    #[test]
    fn libwebrtc_aeb9b375_packet_buffer_loses_an_h264_keyframe_across_the_stale_tail_of_a_frame_sent_whole()
     {
        // Observed behavior at libwebrtc aeb9b375 (read 2026-10-05), what a
        // browser does with an H.264 frame lotse sends whole past the
        // limit: its 2049th packet finds the full ring's slot taken, the
        // buffer is cleared and a keyframe asked for, and the packets after
        // it stay as a stale tail no frame start leads to. The delta
        // frames after it are stashed, never decoded.
        //
        // A keyframe that ends before the tail's first packet needs its
        // slot again (2048 sequence numbers on) plays, and decoding it
        // clears the tail away (`ClearTo`).
        let mut rx = H264Receiver::new();
        let mut tx = Sender::new();
        tx.h264(&mut rx, true, 30);
        let (big, first, _) = tx.h264(&mut rx, true, WHOLE);
        let tail = first + ring() + 1;
        assert_eq!(rx.keyframe_requests(), 1, "cleared at the 2049th");
        for _ in 0..10 {
            tx.h264(&mut rx, false, 40);
        }
        let (next, _, end) = tx.h264(&mut rx, true, 300);
        assert!(end < tail + ring());
        let (after, ..) = tx.h264(&mut rx, false, 40);
        assert_eq!(
            handed_from(rx.frames(), big),
            [(next, true), (after, false)]
        );
        // With the tail cleared, nothing collides 2048 on.
        for _ in 0..60 {
            tx.h264(&mut rx, false, 40);
        }
        assert_eq!(rx.keyframe_requests(), 1);
        assert_eq!(handed_from(rx.frames(), big).len(), 2 + 60);

        // A keyframe whose packets reach that point is lost: the buffer is
        // cleared again at it, and the keyframe's packets after it are the
        // next stale tail. The keyframe after it, ending before that tail
        // collides in turn, plays.
        let mut rx = H264Receiver::new();
        let mut tx = Sender::new();
        tx.h264(&mut rx, true, 30);
        let (big, first, _) = tx.h264(&mut rx, true, WHOLE);
        let collision = first + ring() + 1 + ring();
        while i64::from(tx.seq) + 300 < collision {
            tx.h264(&mut rx, false, 40);
        }
        let (lost, start, end) = tx.h264(&mut rx, true, 600);
        assert!(start < collision && collision <= end);
        assert_eq!(rx.keyframe_requests(), 2, "cleared again");
        for _ in 0..3 {
            tx.h264(&mut rx, false, 40);
        }
        let (next, ..) = tx.h264(&mut rx, true, 300);
        let handed = handed_from(rx.frames(), big);
        assert!(!handed.contains(&(lost, true)), "{handed:?}");
        assert_eq!(handed, [(next, true)]);
    }
}
