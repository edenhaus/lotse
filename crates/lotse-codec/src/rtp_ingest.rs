//! The receive path of an RTP source, whatever carries its session: each
//! packet of a declared stream cut through to its track, through the H.264
//! and H.265 normalizers for video, and depacketized on the side branch
//! into frames; the timestamps watched for a new timeline; RTCP Sender
//! Reports as sync hints. A source declares its tracks from its session
//! description ([`RtpTracks::carry`]), then hands each packet over as it
//! arrives ([`RtpTracks::receive`]) and each Sender Report
//! ([`RtpTracks::sender_report`]); what carries them, and their loss, stays
//! the source's.
//!
//! Implements RFC 3550 §5.1 (packet header fields kept, the timestamps of
//! one clock) and §6.4.1 (Sender Reports), RFC 6184 (H.264) and RFC 7798
//! (H.265) through [`crate::h264`] and [`crate::h265`], RFC 3640 (AAC)
//! through [`crate::aac`], and RFC 3551 §4.5 with RFC 7587 (an audio
//! packet of G.711, G.722 or Opus is one frame).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_core::codec::{Codec, Kind};
use lotse_core::discontinuity::TimestampGuard;
use lotse_core::media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields, TimestampUnwrapper};
use lotse_core::source::{ClockReport, SourceCtx, SourceError, SyncHint};
use lotse_core::throttle::Throttle;
use lotse_core::track::Track;

use crate::aac::{AacDepacketizer, AacFrame};
use crate::h264::{
    DEFAULT_MAX_PAYLOAD, Depacketizer, FrameOverLimit, LIBWEBRTC_MAX_FRAME_PACKETS,
    NormalizedPacket, PacketNormalizer, ParameterSets,
};
use crate::h265;

/// What the session description said about one stream, as core wants it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    /// Video or audio.
    pub kind: Kind,
    /// The codec.
    pub codec: Codec,
    /// Ticks per second.
    pub clock_rate: u32,
    /// The parameter sets the session description announced, if any.
    pub sets: Sprop,
}

/// The parameter sets a video stream's session description announced:
/// RFC 6184 §8.1 `sprop-parameter-sets`, or RFC 7798 §7.1 `sprop-vps`,
/// `sprop-sps` and `sprop-pps`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Sprop {
    /// None, or not a codec that has them.
    #[default]
    None,
    /// H.264's SPS and PPS.
    H264(ParameterSets),
    /// H.265's VPS, SPS and PPS.
    H265(h265::ParameterSets),
}

/// One received RTP packet of a stream (RFC 3550 §5.1): the header fields
/// the path keeps, and the payload. Its payload type is the stream's, as
/// declared ([`RtpTracks::carry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    /// The sequence number.
    pub seq: u16,
    /// The RTP timestamp, as sent.
    pub ts: u32,
    /// The synchronization source.
    pub ssrc: u32,
    /// The marker bit.
    pub marker: bool,
    /// The payload.
    pub payload: Bytes,
}

/// The two normalization layers of a video stream, with the side branch's
/// reused buffer of finished access units and what the stream's SPS says.
///
/// The track's codec follows an in-band SPS only when what it says
/// changes, and keeps the parameter sets of that change: a camera can send
/// a byte-different SPS with every frame, and each codec change is a
/// control event every session handles. What a session checks against
/// its payload type is what the SPS says, never its bytes.
#[derive(Debug)]
enum Video {
    /// H.264 (RFC 6184).
    H264 {
        /// The live-path normalizer.
        normalizer: PacketNormalizer,
        /// The side-branch depacketizer.
        depacketizer: Depacketizer,
        /// Its finished units.
        units: Vec<crate::h264::AccessUnit>,
        /// What the SPS the track's codec was last set from says.
        sps: Option<crate::h264::SpsInfo>,
    },
    /// H.265 (RFC 7798).
    H265 {
        /// The live-path normalizer.
        normalizer: h265::PacketNormalizer,
        /// The side-branch depacketizer.
        depacketizer: h265::Depacketizer,
        /// Its finished units.
        units: Vec<h265::AccessUnit>,
        /// What the SPS the track's codec was last set from says.
        sps: Option<h265::SpsInfo>,
    },
}

impl Video {
    /// The layers for a declared stream, seeded with the session
    /// description's sets, or with none when it announced none (or sets
    /// of another codec): the parameter sets then come in band (RFC 6184
    /// §8.4), which the layers follow either way. `None` for codecs
    /// without them.
    fn new(declared: &Declared, max_frame_bytes: usize) -> Option<Self> {
        match &declared.codec {
            Codec::H264 { .. } => {
                let sets = match &declared.sets {
                    Sprop::H264(sets) => sets.clone(),
                    Sprop::None | Sprop::H265(_) => ParameterSets::default(),
                };
                Some(Self::h264(&sets, max_frame_bytes))
            }
            Codec::H265 { .. } => {
                let sets = match &declared.sets {
                    Sprop::H265(sets) => sets.clone(),
                    Sprop::None | Sprop::H264(_) => h265::ParameterSets::default(),
                };
                Some(Self::h265(&sets, max_frame_bytes))
            }
            _ => None,
        }
    }

    /// H.264's layers, seeded with `sets`.
    fn h264(sets: &ParameterSets, max_frame_bytes: usize) -> Self {
        Self::H264 {
            normalizer: PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, sets.clone()),
            depacketizer: Depacketizer::new(max_frame_bytes, sets.clone()),
            units: Vec::new(),
            sps: sets
                .sps
                .as_deref()
                .and_then(|sps| crate::h264::parse_sps(sps).ok()),
        }
    }

    /// H.265's layers, seeded with `sets`.
    fn h265(sets: &h265::ParameterSets, max_frame_bytes: usize) -> Self {
        Self::H265 {
            normalizer: h265::PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, sets.clone()),
            depacketizer: h265::Depacketizer::new(max_frame_bytes, sets.clone()),
            units: Vec::new(),
            sps: sets
                .sps
                .as_deref()
                .and_then(|sps| h265::parse_sps(sps).ok()),
        }
    }
}

/// A stream the connection carries.
#[derive(Debug)]
struct RtpTrack {
    /// Its track.
    track: Arc<Track>,
    /// Its payload type in the session description.
    pt: u8,
    /// The source's protocol, the prefix of the lines logged.
    protocol: &'static str,
    /// The normalization layers, for H.264 and H.265.
    video: Option<Video>,
    /// The side-branch depacketizer, for AAC-LC.
    aac: Option<Aac>,
    /// Cut-through audio codecs: every packet is a frame too.
    packet_frames: bool,
    /// Unwraps timestamps for the side branch.
    unwrapper: TimestampUnwrapper,
    /// The last timestamp, for frame boundaries of raw video.
    last_ts: Option<u32>,
    /// Watches the timestamps for a new timeline.
    guard: TimestampGuard,
    /// Payloads that violated the packetization, for one warning.
    violations: u64,
    /// The rate limit of the `frame_over_browser_limit` warning.
    over_limit: Throttle,
}

/// An AAC-LC stream's side branch: its depacketizer and the frames one
/// packet yields, a buffer kept across packets so publishing them
/// allocates nothing once it has grown.
#[derive(Debug)]
struct Aac {
    /// The RFC 3640 depacketizer.
    depacketizer: AacDepacketizer,
    /// The frames of the packet being published; empty between packets.
    frames: Vec<AacFrame>,
}

impl RtpTrack {
    /// The state for a declared stream on `track`.
    fn new(track: Arc<Track>, pt: u8, declared: &Declared, protocol: &'static str) -> Self {
        Self {
            pt,
            protocol,
            video: Video::new(declared, track.limits().max_frame_bytes),
            aac: matches!(declared.codec, Codec::AacLc { .. }).then(|| Aac {
                depacketizer: AacDepacketizer::new(track.limits().max_frame_bytes),
                frames: Vec::new(),
            }),
            packet_frames: matches!(
                declared.codec,
                Codec::Pcmu | Codec::Pcma | Codec::G722 | Codec::Opus { .. }
            ),
            unwrapper: TimestampUnwrapper::new(),
            last_ts: None,
            guard: TimestampGuard::new(declared.clock_rate),
            violations: 0,
            over_limit: Throttle::default(),
            track,
        }
    }
}

/// The streams one connection attempt carries, by the source's index of
/// each, with the state their packets go through: what one attempt of an
/// RTP source publishes, from its first packet to its last. The indices
/// are the source's own (an SDP's media order) and may be sparse or
/// large: the streams are held as a short list of the ones carried, a
/// handful at most, so no index sizes anything.
#[derive(Debug)]
pub struct RtpTracks {
    /// The source's protocol, the prefix of the lines logged.
    protocol: &'static str,
    /// Each stream carried, by its index; one entry per index.
    tracks: Vec<(usize, RtpTrack)>,
    /// The new timelines of the attempt.
    timelines: Timelines,
    /// The live path's packets of one source packet, a reused buffer.
    normalized: Vec<NormalizedPacket>,
}

impl RtpTracks {
    /// No stream carried yet, for a source of `protocol` (`rtsp`), which
    /// prefixes the lines it logs.
    pub fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            tracks: Vec::new(),
            timelines: Timelines::default(),
            normalized: Vec::new(),
        }
    }

    /// Carries stream `index` on `track`, declared as `declared` with
    /// payload type `pt`, from the next packet on; the stream that index
    /// carried before is forgotten.
    pub fn carry(&mut self, index: usize, track: Arc<Track>, pt: u8, declared: &Declared) {
        let entry = RtpTrack::new(track, pt, declared, self.protocol);
        match self.entry_mut(index) {
            Some(slot) => *slot = entry,
            None => self.tracks.push((index, entry)),
        }
    }

    /// The stream `index`, if carried.
    fn entry(&self, index: usize) -> Option<&RtpTrack> {
        self.tracks
            .iter()
            .find_map(|(i, entry)| (*i == index).then_some(entry))
    }

    /// The stream `index`, if carried, to update.
    fn entry_mut(&mut self, index: usize) -> Option<&mut RtpTrack> {
        self.tracks
            .iter_mut()
            .find_map(|(i, entry)| (*i == index).then_some(entry))
    }

    /// One RTP packet of stream `index`, arrived at `arrival`: published
    /// on its track, cut through and depacketized on the side branch,
    /// after a new timeline if its timestamp left the stream's (RFC 3550
    /// §5.1). A packet of a stream not carried is dropped. An error ends
    /// the attempt: the camera's timestamps keep jumping, more than
    /// `MAX_TIMELINES` new timelines within `TIMELINE_WINDOW`.
    pub fn receive(
        &mut self,
        index: usize,
        packet: RtpPacket,
        arrival: Instant,
        ctx: &SourceCtx,
    ) -> Result<(), SourceError> {
        // One scan per packet: `new_timeline` restarts the tracks' state
        // but never adds or removes one, so the position stays valid.
        let Some(position) = self.tracks.iter().position(|(i, _)| *i == index) else {
            return Ok(());
        };
        let jumped = self
            .tracks
            .get_mut(position)
            .and_then(|(_, entry)| entry.guard.observe(packet.ts, arrival));
        if let Some(moved_ms) = jumped {
            self.new_timeline(index, ctx, moved_ms, arrival)?;
        }
        let normalized = &mut self.normalized;
        if let Some((_, entry)) = self.tracks.get_mut(position) {
            on_rtp(entry, ctx, arrival, packet, normalized);
        }
        Ok(())
    }

    /// An RTCP Sender Report of stream `index` (RFC 3550 §6.4.1), arrived
    /// at `arrival`: the NTP timestamp `ntp` and the RTP timestamp `rtp_ts`
    /// of the same instant, a sync hint of its track. A report of a stream
    /// not carried is dropped.
    pub fn sender_report(
        &self,
        index: usize,
        ntp: u64,
        rtp_ts: u32,
        arrival: Instant,
        ctx: &SourceCtx,
    ) {
        if let Some(entry) = self.entry(index) {
            ctx.clock.report(ClockReport {
                track: entry.track.id(),
                clock_rate: entry.track.clock_rate(),
                hint: SyncHint::RtcpSenderReport { ntp, rtp_ts },
                arrival,
            });
        }
    }

    /// The camera's timestamps left their timeline on stream `index` at
    /// `arrival`: one new epoch for every track, the clock mapping forgotten,
    /// and every stream's timestamp state restarted so the other tracks' own
    /// jumps are part of the same epoch, logged at most once per summary
    /// interval. An error, and nothing restarted, when the timelines refuse
    /// one more ([`MAX_TIMELINES`]).
    fn new_timeline(
        &mut self,
        index: usize,
        ctx: &SourceCtx,
        moved_ms: i64,
        arrival: Instant,
    ) -> Result<(), SourceError> {
        let protocol = self.protocol;
        self.timelines.admit(arrival, protocol)?;
        let logged = self.timelines.log.hit(arrival);
        for (i, entry) in &mut self.tracks {
            if *i == index {
                if let Some(count) = logged {
                    tracing::info!(track = %entry.track.id(), moved_ms, count, "{protocol}: timestamps jumped; new epoch");
                }
            } else {
                entry.guard.rebase();
            }
            entry.unwrapper = TimestampUnwrapper::new();
            entry.last_ts = None;
        }
        ctx.tracks.discontinuity();
        ctx.clock.reset();
        Ok(())
    }
}

/// How many new timelines one connection attempt starts within
/// [`TIMELINE_WINDOW`] before its camera's timestamps count as broken.
///
/// RFC 3550 §5.1 has a stream's timestamps come from a clock that
/// "increments monotonically and linearly in time", 32-bit wrap aside: a
/// jump ([`TimestampGuard`]) is a reset of that clock, a camera reboot or
/// an encoder restart, which happens once, not every few frames. A new
/// timeline is not free either: every track starts an epoch, so every
/// viewer's video waits for the next keyframe
/// ([`lotse_core::session::apply_track_event`]),
/// and the clock mapping forgets its Sender Report fit (RFC 3550 §6.4.1),
/// so lip sync falls back to arrival times until the next report. A
/// camera whose timestamps jump on every packet would start one epoch per
/// packet: viewers never reach a keyframe of the epoch they wait for and
/// the mapping never fits again. Capping the epochs while the attempt goes
/// on would leave the jumps inside an epoch, where a viewer's timestamp
/// offset no longer holds, so the attempt ends instead, with a protocol
/// error the stream's status shows, and core's runner reconnects under its
/// backoff, which bounds the epochs of the reconnects. Ten per window, one
/// a second on average, still passes a camera that restarts its clock at
/// every keyframe of a one-second GOP.
const MAX_TIMELINES: usize = 10;

/// The sliding window [`MAX_TIMELINES`] counts the new timelines of one
/// connection attempt in: the summary interval of the rate-limited log.
const TIMELINE_WINDOW: Duration = lotse_core::throttle::SUMMARY_INTERVAL;

/// The new timelines of one connection attempt: when the last
/// [`MAX_TIMELINES`] started, for the bound, and the rate limit of their
/// log line.
#[derive(Debug, Default)]
struct Timelines {
    /// When each new timeline within the last [`TIMELINE_WINDOW`] started,
    /// oldest first; never more than [`MAX_TIMELINES`].
    recent: VecDeque<Instant>,
    /// The rate limit of the `timestamps jumped` line.
    log: Throttle,
}

impl Timelines {
    /// Admits one more new timeline at `now`, or refuses it as the
    /// [`MAX_TIMELINES`] + 1st within [`TIMELINE_WINDOW`]: the camera's
    /// timestamps no longer follow a clock (RFC 3550 §5.1). A refusal is
    /// logged with the source's `protocol` as its prefix.
    fn admit(&mut self, now: Instant, protocol: &str) -> Result<(), SourceError> {
        while let Some(first) = self.recent.front()
            && now.saturating_duration_since(*first) >= TIMELINE_WINDOW
        {
            self.recent.pop_front();
        }
        if self.recent.len() >= MAX_TIMELINES {
            tracing::warn!(
                timelines = MAX_TIMELINES,
                window_s = TIMELINE_WINDOW.as_secs(),
                "{protocol}: the camera's timestamps keep jumping; ending the attempt"
            );
            return Err(SourceError::Protocol(format!(
                "the camera's RTP timestamps jumped more than {MAX_TIMELINES} times within {} s: they must follow one clock that increments linearly in time (RFC 3550 §5.1)",
                TIMELINE_WINDOW.as_secs()
            )));
        }
        self.recent.push_back(now);
        Ok(())
    }
}

/// Publishes the live path's packets of one source packet on `track`.
fn publish_normalized(
    track: &Track,
    arrival: Instant,
    rtp: RtpHeaderFields,
    normalized: &mut Vec<NormalizedPacket>,
) {
    for out in normalized.drain(..) {
        track.publish_packet(MediaPacket {
            arrival,
            rtp: RtpHeaderFields {
                marker: out.marker,
                ..rtp
            },
            frame_start: out.frame_start,
            keyframe_start: out.keyframe_start,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(out.payload.as_ref()),
        });
    }
}

/// Publishes one finished access unit of the side branch on `track`:
/// its timestamp, whether it is a keyframe, its Annex B bytes.
fn publish_unit(
    track: &Track,
    unwrapper: &mut TimestampUnwrapper,
    ctx: &SourceCtx,
    arrival: Instant,
    (ts, keyframe, payload): (u32, bool, Bytes),
) {
    let ticks = unwrapper.unwrap(ts);
    track.publish_frame(MediaFrame {
        ts: MediaTime::from_ticks(ticks),
        wallclock: ctx.clock.map(track.id(), ts, arrival),
        arrival,
        keyframe,
        discontinuity: false,
        epoch: 0,
        payload,
    });
}

/// A packet the normalizer cannot read: dropped, warned about once per
/// connection.
fn violation(track: &Track, protocol: &str, violations: &mut u64, err: &dyn std::fmt::Display) {
    *violations = violations.saturating_add(1);
    if *violations == 1 {
        tracing::warn!(track = %track.id(), error = %err, "{protocol}: packetization violation; packet dropped");
    }
}

/// A frame the live path carried in more packets than some libwebrtc
/// receivers assemble ([`LIBWEBRTC_MAX_FRAME_PACKETS`]): counted on the
/// track, and warned about at most once per summary interval. Every
/// session sends it whole all the same.
fn frame_over_limit(
    track: &Track,
    protocol: &str,
    throttle: &mut Throttle,
    arrival: Instant,
    frame: Option<FrameOverLimit>,
) {
    let Some(frame) = frame else { return };
    track.count_frame_over_browser_limit();
    if let Some(count) = throttle.hit(arrival) {
        tracing::warn!(
            track = %track.id(),
            code = "frame_over_browser_limit",
            codec = track.codec().name(),
            bytes = frame.bytes,
            packets = frame.packets,
            limit = LIBWEBRTC_MAX_FRAME_PACKETS,
            keyframe = frame.keyframe,
            count,
            advice = "lower the camera's bitrate or use its substream",
            "{protocol}: frame over the packet limit of some libwebrtc receivers (by version); sent whole, those viewers may freeze until a keyframe that fits"
        );
    }
}

/// One video packet through both normalization layers: the live path's
/// packets, then the side branch's finished units, with the track's codec
/// updated when a unit brings a new SPS.
fn on_video(
    entry: &mut RtpTrack,
    ctx: &SourceCtx,
    arrival: Instant,
    rtp: RtpHeaderFields,
    payload: &Bytes,
    normalized: &mut Vec<NormalizedPacket>,
) {
    let RtpTrack {
        track,
        protocol,
        video,
        unwrapper,
        violations,
        over_limit,
        ..
    } = entry;
    let RtpHeaderFields {
        seq, ts, marker, ..
    } = rtp;
    let Some(video) = video else { return };
    normalized.clear();
    match video {
        Video::H264 {
            normalizer,
            depacketizer,
            units,
            sps,
        } => {
            if let Err(err) = normalizer.normalize(ts, marker, payload, normalized) {
                violation(track, protocol, violations, &err);
            }
            frame_over_limit(
                track,
                protocol,
                over_limit,
                arrival,
                normalizer.take_frame_over_limit(),
            );
            publish_normalized(track, arrival, rtp, normalized);
            units.clear();
            let _violation = depacketizer.push(seq, ts, marker, payload, units);
            for unit in units.drain(..) {
                if let Some(info) = unit.sps.filter(|info| *sps != Some(*info)) {
                    *sps = Some(info);
                    let sets = depacketizer.parameter_sets();
                    track.set_codec(Codec::H264 {
                        profile_level_id: Some(info.profile_level_id),
                        sps: sets.sps.clone(),
                        pps: sets.pps.clone(),
                    });
                }
                publish_unit(
                    track,
                    unwrapper,
                    ctx,
                    arrival,
                    (unit.ts, unit.keyframe, unit.payload),
                );
            }
        }
        Video::H265 {
            normalizer,
            depacketizer,
            units,
            sps,
        } => {
            if let Err(err) = normalizer.normalize(ts, marker, payload, normalized) {
                violation(track, protocol, violations, &err);
            }
            frame_over_limit(
                track,
                protocol,
                over_limit,
                arrival,
                normalizer.take_frame_over_limit(),
            );
            publish_normalized(track, arrival, rtp, normalized);
            units.clear();
            let _violation = depacketizer.push(seq, ts, marker, payload, units);
            for unit in units.drain(..) {
                if let Some(info) = unit.sps.filter(|info| *sps != Some(*info)) {
                    *sps = Some(info);
                    let sets = depacketizer.parameter_sets();
                    track.set_codec(Codec::H265 {
                        vps: sets.vps.clone(),
                        sps: sets.sps.clone(),
                        pps: sets.pps.clone(),
                    });
                }
                publish_unit(
                    track,
                    unwrapper,
                    ctx,
                    arrival,
                    (unit.ts, unit.keyframe, unit.payload),
                );
            }
        }
    }
}

/// One RTP packet: cut through, and depacketized on the side branch.
fn on_rtp(
    entry: &mut RtpTrack,
    ctx: &SourceCtx,
    arrival: Instant,
    packet: RtpPacket,
    normalized: &mut Vec<NormalizedPacket>,
) {
    let RtpPacket {
        seq,
        ts,
        ssrc,
        marker,
        payload,
    } = packet;
    let rtp = RtpHeaderFields {
        pt: entry.pt,
        seq,
        ts,
        marker,
        ssrc,
    };
    if entry.video.is_some() {
        on_video(entry, ctx, arrival, rtp, &payload, normalized);
        return;
    }
    // Raw cut-through: audio, and video codecs without a normalizer yet.
    let frame_start = entry.track.kind() == Kind::Audio || entry.last_ts != Some(ts);
    entry.last_ts = Some(ts);
    entry.track.publish_packet(MediaPacket {
        arrival,
        rtp,
        frame_start,
        keyframe_start: false,
        epoch: 0,
        lateness: Duration::ZERO,
        payload: Arc::from(payload.as_ref()),
    });
    if let Some(aac) = entry.aac.as_mut() {
        let id = entry.track.id();
        let stamp = |ts| (ctx.clock.map(id, ts, arrival), arrival);
        publish_aac(
            aac,
            (&entry.track, entry.protocol),
            &mut entry.unwrapper,
            stamp,
            rtp,
            &payload,
        );
    }
    if entry.packet_frames {
        let ticks = entry.unwrapper.unwrap(ts);
        entry.track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(ticks),
            wallclock: ctx.clock.map(entry.track.id(), ts, arrival),
            arrival,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload,
        });
    }
}

/// One AAC packet on the side branch: its RFC 3640 units become frames
/// on `track`, each stamped by `stamp` from its RTP timestamp with its
/// capture time and its arrival. A violation is warned about once per
/// connection, prefixed with the source's `protocol`.
fn publish_aac(
    aac: &mut Aac,
    (track, protocol): (&Track, &str),
    unwrapper: &mut TimestampUnwrapper,
    stamp: impl Fn(u32) -> (Instant, Instant),
    rtp: RtpHeaderFields,
    payload: &[u8],
) {
    let Aac {
        depacketizer,
        frames,
    } = aac;
    if let Err(err) = depacketizer.push(rtp.seq, rtp.ts, rtp.marker, payload, frames)
        && depacketizer.stats().violations == 1
    {
        tracing::warn!(track = %track.id(), error = %err, "{protocol}: AAC payload violates RFC 3640; packet dropped");
    }
    for frame in frames.drain(..) {
        let ticks = unwrapper.unwrap(frame.ts);
        let (wallclock, arrival) = stamp(frame.ts);
        track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(ticks),
            wallclock,
            arrival,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: frame.payload,
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

    use std::future::Future as _;
    use std::task::{Context, Poll, Waker};

    use lotse_core::clock::{Clock as _, FakeClock, SystemClock};
    use lotse_core::clock_map::{ClockMapper, SyncMode};
    use lotse_core::source::{BackchannelSlot, ClockInput, ResolvedPeer, TrackSet};
    use lotse_core::track::{TrackEvent, TrackLimits, TrackSubscription, Unit};
    use tokio_util::sync::CancellationToken;
    use tracing::Level;

    use super::*;
    use crate::transcode::Logs;

    /// The protocol the tests' lines are logged for.
    const RTSP: &str = "rtsp";

    /// A source context on a fresh track set, reporting into `clock`.
    fn ctx_with(clock: ClockInput) -> (Instant, Arc<TrackSet>, SourceCtx) {
        let t0 = SystemClock.now();
        let set = TrackSet::new(TrackLimits::default(), t0);
        let ctx = SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock,
            time: Arc::new(SystemClock),
            backchannel: BackchannelSlot::default(),
            signaling: None,
            cancel: CancellationToken::new(),
        };
        (t0, set, ctx)
    }

    /// A source context on a fresh track set, its reports dropped.
    fn video_ctx() -> (Instant, Arc<TrackSet>, SourceCtx) {
        let (clock, _reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        ctx_with(clock)
    }

    /// What a session description declares for `codec`.
    fn declared(kind: Kind, codec: Codec, clock_rate: u32, sets: Sprop) -> Declared {
        Declared {
            kind,
            codec,
            clock_rate,
            sets,
        }
    }

    /// H.264 without sprop parameter sets.
    fn h264() -> Declared {
        declared(
            Kind::Video,
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
            Sprop::H264(ParameterSets::default()),
        )
    }

    /// H.265 without sprop parameter sets.
    fn h265() -> Declared {
        declared(
            Kind::Video,
            Codec::H265 {
                vps: None,
                sps: None,
                pps: None,
            },
            90_000,
            Sprop::H265(h265::ParameterSets::default()),
        )
    }

    /// G.711 μ-law.
    fn pcmu() -> Declared {
        declared(Kind::Audio, Codec::Pcmu, 8_000, Sprop::None)
    }

    /// The declared track of `declared` on `ctx`.
    fn declare(ctx: &mut SourceCtx, declared: &Declared) -> Arc<Track> {
        ctx.tracks
            .declare(declared.kind, declared.codec.clone(), declared.clock_rate)
    }

    /// The RTP fields of a video packet that ends its access unit.
    const fn video_rtp(seq: u16, ts: u32) -> RtpHeaderFields {
        RtpHeaderFields {
            pt: 96,
            seq,
            ts,
            marker: true,
            ssrc: 1,
        }
    }

    /// A received packet.
    fn packet(seq: u16, ts: u32, marker: bool, payload: &[u8]) -> RtpPacket {
        RtpPacket {
            seq,
            ts,
            ssrc: 0x1234_5678,
            marker,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn a_new_timeline_starts_one_epoch_and_restarts_every_streams_timestamps() {
        let mapper = Arc::new(ClockMapper::new());
        let (clock, _reports) = ClockInput::channel(Arc::clone(&mapper));
        let (t0, _set, mut ctx) = ctx_with(clock);
        let (video, audio) = (h264(), pcmu());
        let v0 = declare(&mut ctx, &video);
        let a0 = declare(&mut ctx, &audio);
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(0, Arc::clone(&v0), 96, &video);
        tracks.carry(2, Arc::clone(&a0), 0, &audio);
        for (_, entry) in &mut tracks.tracks {
            assert_eq!(entry.guard.observe(1_000, t0), None);
            entry.unwrapper.unwrap(1_000);
            entry.last_ts = Some(1_000);
        }
        mapper.ingest(ClockReport {
            track: v0.id(),
            clock_rate: 90_000,
            hint: SyncHint::RtcpSenderReport {
                ntp: 1 << 32,
                rtp_ts: 1_000,
            },
            arrival: t0,
        });
        assert_eq!(mapper.mode(v0.id()), SyncMode::SenderReports);

        // Video jumped: its guard already holds the new timestamp.
        assert!(
            tracks
                .entry_mut(0)
                .unwrap()
                .guard
                .observe(5_000_000, t0)
                .is_some()
        );
        tracks.new_timeline(0, &ctx, 55, t0).unwrap();
        assert_eq!((v0.epoch(), a0.epoch()), (1, 1), "one epoch for all tracks");
        assert_eq!(mapper.mode(v0.id()), SyncMode::Arrival);
        let [(vi, v), (ai, a)] =
            <&mut [(usize, RtpTrack); 2]>::try_from(tracks.tracks.as_mut_slice()).unwrap();
        assert_eq!((*vi, *ai), (0, 2), "the streams stay");
        assert_eq!(
            v.guard.observe(5_003_000, t0),
            None,
            "video continues its new timeline"
        );
        // Audio takes whatever comes next as its base: its own jump is part
        // of the same epoch.
        assert_eq!(a.guard.observe(9_999_999, t0), None);
        for entry in [v, a] {
            assert_eq!(entry.unwrapper.last(), None);
            assert_eq!(entry.last_ts, None);
        }
    }

    #[test]
    fn rfc3550_5_1_the_timelines_beyond_the_bound_within_the_window_are_refused() {
        let t0 = FakeClock::from_system().now();
        let mut timelines = Timelines::default();
        // Exactly the bound at one instant: every one admitted.
        for n in 0..MAX_TIMELINES {
            assert!(timelines.admit(t0, RTSP).is_ok(), "timeline {n}");
        }
        let refused = timelines.admit(
            t0 + TIMELINE_WINDOW.saturating_sub(Duration::from_nanos(1)),
            RTSP,
        );
        let message = refused.unwrap_err().to_string();
        assert!(
            message.contains("more than 10 times within 10 s"),
            "{message}"
        );
        assert!(message.contains("(RFC 3550 §5.1)"), "{message}");
        assert_eq!(
            timelines.recent.len(),
            MAX_TIMELINES,
            "a refusal is not counted"
        );
        // A window after them, they have left it.
        assert!(timelines.admit(t0 + TIMELINE_WINDOW, RTSP).is_ok());
        assert_eq!(timelines.recent.len(), 1);
    }

    #[test]
    fn occasional_timelines_below_the_bound_are_each_admitted() {
        let t0 = FakeClock::from_system().now();
        let mut timelines = Timelines::default();
        // One a second, for a minute: never more than the bound in a window.
        let every = TIMELINE_WINDOW / u32::try_from(MAX_TIMELINES).unwrap();
        for n in 0..60_u32 {
            assert!(
                timelines.admit(t0 + every * n, RTSP).is_ok(),
                "timeline {n}"
            );
        }
        assert_eq!(timelines.recent.len(), MAX_TIMELINES);
    }

    #[test]
    fn a_refused_timeline_restarts_nothing_and_every_jump_logs_throttled() {
        let (logs, _guard) = Logs::capture();
        let (t0, _set, mut ctx) = video_ctx();
        let video = h264();
        let v0 = declare(&mut ctx, &video);
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(0, Arc::clone(&v0), 96, &video);
        for _ in 0..MAX_TIMELINES {
            tracks.new_timeline(0, &ctx, 55, t0).unwrap();
        }
        tracks.entry_mut(0).unwrap().last_ts = Some(1_000);
        assert!(tracks.new_timeline(0, &ctx, 55, t0).is_err());
        assert_eq!(v0.epoch(), 10, "no epoch for the refused one");
        assert_eq!(tracks.entry(0).unwrap().last_ts, Some(1_000));
        let jumped = logs.fields(Level::INFO, "rtsp: timestamps jumped; new epoch");
        assert_eq!(jumped.len(), 1, "{jumped:?}");
        assert!(
            jumped[0].contains(&"moved_ms=55".to_owned())
                && jumped[0].contains(&"count=1".to_owned()),
            "{jumped:?}"
        );
        let ended = logs.fields(
            Level::WARN,
            "rtsp: the camera's timestamps keep jumping; ending the attempt",
        );
        assert_eq!(ended, [["timelines=10", "window_s=10"]]);
    }

    #[test]
    fn rfc3550_5_1_a_timestamp_jump_starts_a_new_epoch_and_too_many_end_the_attempt() {
        let (t0, _set, mut ctx) = video_ctx();
        let audio = pcmu();
        let a0 = declare(&mut ctx, &audio);
        let mut packets = a0.subscribe_packets();
        let mut tracks = RtpTracks::new("webrtc");
        tracks.carry(0, Arc::clone(&a0), 0, &audio);
        tracks
            .receive(0, packet(0, 0, true, &[0xff]), t0, &ctx)
            .unwrap();
        // Ten seconds ahead at the same arrival, every packet.
        for n in 1..=u16::try_from(MAX_TIMELINES).unwrap() {
            let ts = u32::from(n) * 80_000;
            tracks
                .receive(0, packet(n, ts, true, &[0xff]), t0, &ctx)
                .unwrap();
        }
        assert_eq!(a0.epoch(), 10);
        let refused = tracks
            .receive(0, packet(11, 11 * 80_000, true, &[0xff]), t0, &ctx)
            .unwrap_err();
        assert!(matches!(refused, SourceError::Protocol(_)), "{refused:?}");
        assert_eq!(a0.epoch(), 10, "no epoch for the refused one");
        let mut seqs = Vec::new();
        while let Some(packet) = packets.try_recv().unwrap() {
            seqs.push(packet.rtp.seq);
        }
        assert_eq!(
            seqs,
            (0..=10).collect::<Vec<u16>>(),
            "the refused one dropped"
        );
    }

    #[test]
    fn rfc3550_5_1_raw_video_is_cut_through_with_its_header_and_frame_starts() {
        let (t0, _set, mut ctx) = video_ctx();
        let mjpeg = declared(Kind::Video, Codec::Mjpeg, 90_000, Sprop::None);
        let v0 = declare(&mut ctx, &mjpeg);
        let mut packets = v0.subscribe_packets();
        let mut frames = v0.subscribe_frames();
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(1, Arc::clone(&v0), 26, &mjpeg);
        for (seq, ts, marker) in [(7, 1_000, false), (8, 1_000, true), (9, 4_000, true)] {
            let payload = [u8::try_from(seq).unwrap(); 3];
            tracks
                .receive(1, packet(seq, ts, marker, &payload), t0, &ctx)
                .unwrap();
        }
        let mut starts = Vec::new();
        for (seq, ts, marker) in [(7, 1_000, false), (8, 1_000, true), (9, 4_000, true)] {
            let out = packets.try_recv().unwrap().unwrap();
            assert_eq!(
                out.rtp,
                RtpHeaderFields {
                    pt: 26,
                    seq,
                    ts,
                    marker,
                    ssrc: 0x1234_5678,
                }
            );
            assert_eq!(&out.payload[..], &[u8::try_from(seq).unwrap(); 3]);
            assert_eq!(out.arrival, t0);
            assert!(!out.keyframe_start);
            starts.push(out.frame_start);
        }
        assert_eq!(
            starts,
            [true, false, true],
            "a frame starts at a new timestamp"
        );
        assert!(packets.try_recv().unwrap().is_none());
        assert!(frames.try_recv().unwrap().is_none(), "no side branch");
    }

    /// RTP cut through as it came (no normalizer for the codec): every
    /// audio packet starts a frame, a video packet only when its timestamp
    /// moves on (RFC 3550 §5.1: the packets of a frame share one).
    #[test]
    fn rfc3550_5_1_cut_through_frames_start_per_audio_packet_and_per_video_timestamp() {
        let (t0, _set, mut ctx) = video_ctx();
        let mjpeg = declared(Kind::Video, Codec::Mjpeg, 90_000, Sprop::None);
        for (stream, pt, starts) in [
            (pcmu(), 0, [true, true, true]),
            (mjpeg, 26, [true, false, true]),
        ] {
            let track = declare(&mut ctx, &stream);
            let mut tracks = RtpTracks::new(RTSP);
            tracks.carry(0, Arc::clone(&track), pt, &stream);
            assert!(tracks.entry(0).unwrap().video.is_none(), "cut through");
            let mut packets = track.subscribe_packets();
            for (seq, ts) in [(1, 1_000), (2, 1_000), (3, 4_000)] {
                tracks
                    .receive(0, packet(seq, ts, false, &[1, 2, 3]), t0, &ctx)
                    .unwrap();
            }
            let got: Vec<bool> = (0..3)
                .map(|_| packets.try_recv().unwrap().unwrap().frame_start)
                .collect();
            assert_eq!(got, starts, "{:?}", stream.codec);
        }
    }

    #[test]
    fn rfc3551_4_5_an_audio_packet_is_a_frame_and_starts_one() {
        let (t0, _set, mut ctx) = video_ctx();
        let audio = pcmu();
        let a0 = declare(&mut ctx, &audio);
        let mut packets = a0.subscribe_packets();
        let mut frames = a0.subscribe_frames();
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(0, Arc::clone(&a0), 0, &audio);
        // The same timestamp twice, then across the 32-bit wrap.
        for (seq, ts) in [(1, u32::MAX - 159), (2, u32::MAX - 159), (3, 0)] {
            tracks
                .receive(0, packet(seq, ts, false, &[0xd5; 160]), t0, &ctx)
                .unwrap();
        }
        for _ in 0..3 {
            assert!(packets.try_recv().unwrap().unwrap().frame_start);
        }
        let mut ticks = Vec::new();
        while let Some(frame) = frames.try_recv().unwrap() {
            assert!(frame.keyframe && !frame.discontinuity);
            assert_eq!(&frame.payload[..], &[0xd5; 160]);
            assert_eq!(frame.arrival, t0);
            ticks.push(frame.ts.ticks());
        }
        let first = ticks[0];
        assert_eq!(ticks, [first, first, first + 160], "unwrapped");
    }

    #[test]
    fn rfc3640_aac_units_become_frames_beside_the_cut_through() {
        let (t0, _set, mut ctx) = video_ctx();
        let aac = declared(
            Kind::Audio,
            Codec::AacLc {
                sample_rate: 16_000,
                channels: 1,
                config: Bytes::from_static(&[0x14, 0x08]),
            },
            16_000,
            Sprop::None,
        );
        let a0 = declare(&mut ctx, &aac);
        let mut packets = a0.subscribe_packets();
        let mut frames = a0.subscribe_frames();
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(0, Arc::clone(&a0), 97, &aac);
        let payload = crate::aac::packetize(&[b"ab", b"cd"]);
        tracks
            .receive(0, packet(1, 5_000, true, &payload), t0, &ctx)
            .unwrap();
        let raw = packets.try_recv().unwrap().unwrap();
        assert_eq!((&raw.payload[..], raw.rtp.pt), (&payload[..], 97));
        let first = frames.try_recv().unwrap().unwrap();
        let second = frames.try_recv().unwrap().unwrap();
        assert_eq!((first.ts.ticks(), &first.payload[..]), (5_000, &b"ab"[..]));
        assert_eq!(
            (second.ts.ticks(), &second.payload[..]),
            (6_024, &b"cd"[..])
        );
        assert_eq!((first.arrival, first.keyframe), (t0, true));
        assert!(frames.try_recv().unwrap().is_none(), "no packet frame too");
    }

    #[test]
    fn a_stream_not_carried_is_dropped() {
        let (clock, mut reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let (t0, _set, mut ctx) = ctx_with(clock);
        let mut tracks = RtpTracks::new(RTSP);
        tracks
            .receive(3, packet(1, 0, true, &[1]), t0, &ctx)
            .unwrap();
        let audio = pcmu();
        let a0 = declare(&mut ctx, &audio);
        tracks.carry(2, Arc::clone(&a0), 0, &audio);
        for index in [0, 1, 3] {
            tracks
                .receive(index, packet(1, 0, true, &[1]), t0, &ctx)
                .unwrap();
            tracks.sender_report(index, 1 << 32, 0, t0, &ctx);
        }
        assert_eq!(a0.stats().packets, 0);
        assert!(reports.try_recv().is_err(), "no report");
        tracks
            .receive(2, packet(1, 0, true, &[1]), t0, &ctx)
            .unwrap();
        assert_eq!(a0.stats().packets, 1);
    }

    #[test]
    fn rfc3550_6_4_1_a_sender_report_is_a_sync_hint_of_its_track() {
        let (clock, mut reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let (t0, _set, mut ctx) = ctx_with(clock);
        let (video, audio) = (h264(), pcmu());
        let _v0 = declare(&mut ctx, &video);
        let a0 = declare(&mut ctx, &audio);
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(1, Arc::clone(&a0), 0, &audio);
        tracks.sender_report(1, (7 << 32) | 5, 1_234, t0, &ctx);
        assert_eq!(
            reports.try_recv().unwrap(),
            ClockReport {
                track: a0.id(),
                clock_rate: 8_000,
                hint: SyncHint::RtcpSenderReport {
                    ntp: (7 << 32) | 5,
                    rtp_ts: 1_234,
                },
                arrival: t0,
            }
        );
        assert!(reports.try_recv().is_err());
    }

    #[test]
    fn a_sparse_or_large_index_is_carried_without_sizing_anything() {
        // RTSP carries the SDP's media index, which nothing bounds: a
        // camera may list many media sections before the one chosen.
        let (t0, _set, mut ctx) = video_ctx();
        let audio = pcmu();
        let a0 = declare(&mut ctx, &audio);
        let a1 = declare(&mut ctx, &audio);
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(usize::MAX, Arc::clone(&a0), 0, &audio);
        tracks.carry(70, Arc::clone(&a1), 8, &audio);
        assert_eq!(tracks.tracks.len(), 2, "one entry per stream carried");
        tracks
            .receive(usize::MAX, packet(1, 0, true, &[0xff; 160]), t0, &ctx)
            .unwrap();
        tracks
            .receive(70, packet(1, 0, true, &[0xd5; 160]), t0, &ctx)
            .unwrap();
        tracks
            .receive(69, packet(2, 160, true, &[0xd5; 160]), t0, &ctx)
            .unwrap();
        assert_eq!((a0.stats().packets, a1.stats().packets), (1, 1));
    }

    #[test]
    fn carrying_an_index_again_replaces_its_stream() {
        let (t0, _set, mut ctx) = video_ctx();
        let audio = pcmu();
        let a0 = declare(&mut ctx, &audio);
        let a1 = declare(&mut ctx, &audio);
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(0, Arc::clone(&a0), 0, &audio);
        tracks.carry(0, Arc::clone(&a1), 8, &audio);
        let mut packets = a1.subscribe_packets();
        tracks
            .receive(0, packet(1, 0, true, &[1]), t0, &ctx)
            .unwrap();
        assert_eq!(packets.try_recv().unwrap().unwrap().rtp.pt, 8);
        assert_eq!(a0.stats().packets, 0);
        assert_eq!(tracks.tracks.len(), 1);
    }

    #[test]
    fn rfc6184_a_unit_over_the_browser_packet_limit_is_counted_and_sent_whole() {
        let (logs, _guard) = Logs::capture();
        let (t0, _set, mut ctx) = video_ctx();
        let video = h264();
        let v0 = declare(&mut ctx, &video);
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(0, Arc::clone(&v0), 96, &video);
        // One IDR slice as a single NAL unit packet (RFC 6184 §5.6),
        // re-split into more FU-As than the limit.
        let mut idr = vec![0x65];
        idr.resize(
            1 + DEFAULT_MAX_PAYLOAD * (LIBWEBRTC_MAX_FRAME_PACKETS + 1),
            0xab,
        );
        tracks
            .receive(0, packet(1, 0, true, &idr), t0, &ctx)
            .unwrap();
        assert_eq!(v0.stats().frames_over_browser_limit, 1);
        let sent = usize::try_from(v0.stats().packets).unwrap();
        assert!(sent > LIBWEBRTC_MAX_FRAME_PACKETS, "{sent}");
        tracks
            .receive(0, packet(2, 3_000, true, &idr), t0, &ctx)
            .unwrap();
        assert_eq!(v0.stats().frames_over_browser_limit, 2);
        let lines = logs.fields(
            Level::WARN,
            "rtsp: frame over the packet limit of some libwebrtc receivers (by version); sent whole, those viewers may freeze until a keyframe that fits",
        );
        assert_eq!(lines.len(), 1, "rate-limited: {lines:?}");
        for field in [
            "code=\"frame_over_browser_limit\"",
            "codec=\"h264\"",
            "limit=2047",
            "keyframe=true",
            "count=1",
        ] {
            assert!(lines[0].contains(&field.to_owned()), "{field}: {lines:?}");
        }
    }

    #[test]
    fn rfc6184_8_4_video_declared_without_its_codecs_sets_is_normalized_from_in_band_sets() {
        // A source whose session description carries no sprop parameter
        // sets (WebRTC answers have none) declares `Sprop::None`, or sets of
        // another codec by mistake: the layers start from empty sets.
        for (codec, sets, idr) in [
            (h264().codec, Sprop::None, vec![0x65, 0xaa, 0xbb]),
            (
                h264().codec,
                Sprop::H265(h265::ParameterSets::default()),
                vec![0x65, 0xaa, 0xbb],
            ),
            (
                h265().codec,
                Sprop::None,
                vec![h265::nal::IDR_W_RADL << 1, 0x01, 0xaa],
            ),
            (
                h265().codec,
                Sprop::H264(ParameterSets::default()),
                vec![h265::nal::IDR_W_RADL << 1, 0x01, 0xaa],
            ),
        ] {
            let (t0, _set, mut ctx) = video_ctx();
            let video = declared(Kind::Video, codec, 90_000, sets);
            let v0 = declare(&mut ctx, &video);
            let mut packets = v0.subscribe_packets();
            let mut frames = v0.subscribe_frames();
            let mut tracks = RtpTracks::new(RTSP);
            tracks.carry(0, Arc::clone(&v0), 96, &video);
            tracks
                .receive(0, packet(1, 3_000, true, &idr), t0, &ctx)
                .unwrap();
            let packet = packets.try_recv().unwrap().unwrap();
            assert!(packet.keyframe_start && packet.rtp.marker, "{video:?}");
            let frame = frames.try_recv().unwrap().unwrap();
            assert!(frame.keyframe, "{video:?}");
            assert_eq!(frame.ts.ticks(), 3_000);
        }
    }

    #[test]
    fn rfc7798_a_unit_over_the_browser_packet_limit_is_counted() {
        let (t0, _set, mut ctx) = video_ctx();
        let video = h265();
        let v0 = declare(&mut ctx, &video);
        let mut tracks = RtpTracks::new(RTSP);
        tracks.carry(0, Arc::clone(&v0), 96, &video);
        let mut idr = vec![h265::nal::IDR_W_RADL << 1, 0x01];
        idr.resize(
            2 + DEFAULT_MAX_PAYLOAD * (LIBWEBRTC_MAX_FRAME_PACKETS + 1),
            0xab,
        );
        tracks
            .receive(0, packet(1, 0, true, &idr), t0, &ctx)
            .unwrap();
        assert_eq!(v0.stats().frames_over_browser_limit, 1);
    }

    #[test]
    fn rfc7798_a_unit_with_a_new_sps_updates_the_codec_and_violations_drop() {
        let (logs, _guard) = Logs::capture();
        let (t0, _set, mut ctx) = video_ctx();
        // No sprop parameters: the codec learns the sets from the stream.
        let video = h265();
        let v0 = declare(&mut ctx, &video);
        let mut entry = RtpTrack::new(Arc::clone(&v0), 96, &video, RTSP);
        let mut packets = v0.subscribe_packets();
        let mut frames = v0.subscribe_frames();
        let mut normalized = Vec::new();
        let (vps, sps, pps) = (
            h265::test_data::vps(),
            h265::test_data::sps(640, 480),
            h265::test_data::pps(),
        );
        let idr = [h265::nal::IDR_W_RADL << 1, 0x01, 0xaa];
        let ap = h265::nal::aggregate(&[&vps, &sps, &pps, &idr]);
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(2, 3_000),
            &ap,
            &mut normalized,
        );
        assert_eq!(
            v0.codec().as_ref(),
            &Codec::H265 {
                vps: Some(Bytes::from(vps)),
                sps: Some(Bytes::from(sps)),
                pps: Some(Bytes::from(pps)),
            }
        );
        let packet = packets.try_recv().unwrap().unwrap();
        assert!(packet.keyframe_start && packet.rtp.marker);
        let frame = frames.try_recv().unwrap().unwrap();
        assert!(frame.keyframe);
        assert_eq!(frame.ts.ticks(), 3_000);
        // A unit over the datagram target is re-split: only the last
        // packet carries the marker (RFC 7798 §4.1).
        let big: Vec<u8> = [1 << 1, 0x01].into_iter().chain([0x5a; 2_000]).collect();
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(3, 4_000),
            &Bytes::from(big),
            &mut normalized,
        );
        let first = packets.try_recv().unwrap().unwrap();
        let second = packets.try_recv().unwrap().unwrap();
        assert!(!first.rtp.marker && second.rtp.marker);
        // PACI is not read: dropped, counted.
        let paci = Bytes::from_static(&[h265::nal::PACI << 1, 0x01]);
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(4, 6_000),
            &paci,
            &mut normalized,
        );
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(5, 9_000),
            &paci,
            &mut normalized,
        );
        assert_eq!(entry.violations, 2, "warned once, counted twice");
        assert!(packets.try_recv().unwrap().is_none());
        assert_eq!(
            logs.count(Level::WARN, "rtsp: packetization violation; packet dropped"),
            1
        );
    }

    /// The codec changes announced to `sub` so far.
    fn codec_changes(sub: &mut TrackSubscription) -> Vec<Codec> {
        let mut changes = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            let next = std::pin::pin!(sub.next());
            let Poll::Ready(Some(event)) = next.poll(&mut cx) else {
                break;
            };
            if let TrackEvent::TrackChanged { codec, .. } = event {
                changes.push(Codec::clone(&codec));
            }
        }
        changes
    }

    /// The H.264 descriptor of `sps` and `pps`.
    fn h264_codec(sps: &[u8], pps: &[u8]) -> Codec {
        Codec::H264 {
            profile_level_id: Some(crate::h264::parse_sps(sps).unwrap().profile_level_id),
            sps: Some(Bytes::copy_from_slice(sps)),
            pps: Some(Bytes::copy_from_slice(pps)),
        }
    }

    #[test]
    fn rfc6184_the_codec_follows_what_an_sps_says_not_its_bytes() {
        use crate::h264::test_data;

        let (t0, _set, mut ctx) = video_ctx();
        let mut normalized = Vec::new();
        let (vga, hd, pps) = (
            test_data::sps(640, 480),
            test_data::sps(1280, 720),
            test_data::pps(),
        );
        // `test_data::sps(640, 480)` with two reference frames: other
        // bytes, the same profile, level and size.
        let mut bits = test_data::Bits::default();
        bits.bits(66, 8)
            .bits(0xc0, 8)
            .bits(40, 8)
            .ue(0)
            .ue(0)
            .ue(2)
            .ue(2)
            .bit(false);
        bits.ue(39).ue(29).bit(true).bit(true).bit(false).bit(false);
        let vga_again = [vec![0x67], bits.finish()].concat();
        assert_ne!(vga_again, vga);
        assert_eq!(
            crate::h264::parse_sps(&vga_again),
            crate::h264::parse_sps(&vga)
        );
        // The sprop SPS already says what the stream's does.
        let sets = ParameterSets {
            sps: Some(Bytes::from(vga.clone())),
            pps: Some(Bytes::from(pps.clone())),
        };
        let video = declared(
            Kind::Video,
            h264_codec(&vga, &pps),
            90_000,
            Sprop::H264(sets),
        );
        let v0 = declare(&mut ctx, &video);
        let mut entry = RtpTrack::new(Arc::clone(&v0), 96, &video, RTSP);
        let mut sub = v0.subscribe(Unit::Packets);
        let mut seq = 0;
        let mut send = |sps: &[u8]| {
            seq += 1;
            let stap = crate::h264::nal::stap_a(&[sps, &pps, &[0x65, 0xaa]]);
            let rtp = video_rtp(seq, u32::from(seq) * 3_000);
            on_video(&mut entry, &ctx, t0, rtp, &stap, &mut normalized);
        };
        for _ in 0..3 {
            send(&vga_again);
            send(&vga);
        }
        assert_eq!(codec_changes(&mut sub), []);
        assert_eq!(*v0.codec(), h264_codec(&vga, &pps));
        send(&hd);
        send(&vga_again);
        send(&vga);
        assert_eq!(
            codec_changes(&mut sub),
            [h264_codec(&hd, &pps), h264_codec(&vga_again, &pps)]
        );
    }

    #[test]
    fn rfc7798_the_codec_follows_what_an_sps_says_not_its_bytes() {
        let (t0, _set, mut ctx) = video_ctx();
        let mut normalized = Vec::new();
        let (vps, pps) = (h265::test_data::vps(), h265::test_data::pps());
        let (vga, hd) = (
            h265::test_data::sps(640, 480),
            h265::test_data::sps(1280, 720),
        );
        // Other bytes, the same SPS to the reader: a trailing zero byte.
        let vga_again = [vga.clone(), vec![0]].concat();
        assert_eq!(h265::parse_sps(&vga_again), h265::parse_sps(&vga));
        let sets = h265::ParameterSets {
            vps: Some(Bytes::from(vps.clone())),
            sps: Some(Bytes::from(vga.clone())),
            pps: Some(Bytes::from(pps.clone())),
        };
        let h265 = |sps: &[u8]| Codec::H265 {
            vps: Some(Bytes::from(vps.clone())),
            sps: Some(Bytes::copy_from_slice(sps)),
            pps: Some(Bytes::from(pps.clone())),
        };
        let video = declared(Kind::Video, h265(&vga), 90_000, Sprop::H265(sets));
        let v0 = declare(&mut ctx, &video);
        let mut entry = RtpTrack::new(Arc::clone(&v0), 96, &video, RTSP);
        let mut sub = v0.subscribe(Unit::Packets);
        let idr = [h265::nal::IDR_W_RADL << 1, 0x01, 0xaa];
        let mut seq = 0;
        let mut send = |sps: &[u8]| {
            seq += 1;
            let ap = h265::nal::aggregate(&[&vps, sps, &pps, &idr]);
            let rtp = video_rtp(seq, u32::from(seq) * 3_000);
            on_video(&mut entry, &ctx, t0, rtp, &ap, &mut normalized);
        };
        send(&vga_again);
        send(&vga);
        assert_eq!(codec_changes(&mut sub), []);
        send(&hd);
        assert_eq!(codec_changes(&mut sub), [h265(&hd)]);
    }

    #[test]
    fn rfc6184_a_unit_with_a_new_sps_updates_the_codec_and_violations_drop() {
        // A STAP-A with a new SPS, then STAP-Bs, which packetization mode 1
        // does not allow.
        let (logs, _guard) = Logs::capture();
        let (t0, _set, mut ctx) = video_ctx();
        let mut normalized = Vec::new();
        let video = h264();
        let v1 = declare(&mut ctx, &video);
        let mut entry = RtpTrack::new(Arc::clone(&v1), 96, &video, RTSP);
        let sps = [0x67, 0x42, 0xc0, 0x28, 0xda, 0x02, 0x80, 0xf6, 0x40];
        let pps = [0x68, 0xce, 0x38, 0x80];
        let stap = crate::h264::nal::stap_a(&[&sps, &pps, &[0x65, 0xaa]]);
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(1, 0),
            &stap,
            &mut normalized,
        );
        assert_eq!(
            *v1.codec(),
            Codec::H264 {
                profile_level_id: Some([0x42, 0xc0, 0x28]),
                sps: Some(Bytes::copy_from_slice(&sps)),
                pps: Some(Bytes::copy_from_slice(&pps)),
            }
        );
        let stap_b = Bytes::from_static(&[25, 0]);
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(2, 3_000),
            &stap_b,
            &mut normalized,
        );
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(3, 6_000),
            &stap_b,
            &mut normalized,
        );
        assert_eq!(entry.violations, 2);
        assert_eq!(
            logs.count(Level::WARN, "rtsp: packetization violation; packet dropped"),
            1
        );
    }

    #[test]
    fn rfc3640_violations_drop_the_packet_and_good_units_become_frames() {
        let (logs, _guard) = Logs::capture();
        let (t0, _set, mut ctx) = video_ctx();
        let audio = declared(
            Kind::Audio,
            Codec::AacLc {
                sample_rate: 16_000,
                channels: 1,
                config: Bytes::from_static(&[0x14, 0x08]),
            },
            16_000,
            Sprop::None,
        );
        let a0 = declare(&mut ctx, &audio);
        let mut entry = RtpTrack::new(Arc::clone(&a0), 97, &audio, RTSP);
        let mut frames = a0.subscribe_frames();
        let rtp = |seq, ts| RtpHeaderFields {
            pt: 97,
            seq,
            ts,
            marker: true,
            ssrc: 1,
        };
        let aac = entry.aac.as_mut().unwrap();
        // One stamp for every packet: one instance of `publish_aac`.
        let stamp = |_| (t0, t0);
        // Two violations (one warning), then a good packet.
        for (seq, payload) in [(1, &[0x00_u8][..]), (2, &[0x00, 0x0d, 0x00][..])] {
            publish_aac(
                aac,
                (&a0, RTSP),
                &mut entry.unwrapper,
                stamp,
                rtp(seq, 0),
                payload,
            );
        }
        assert!(frames.try_recv().unwrap().is_none(), "dropped");
        let good = crate::aac::packetize(&[b"ab", b"cd"]);
        publish_aac(
            aac,
            (&a0, RTSP),
            &mut entry.unwrapper,
            stamp,
            rtp(3, 5_000),
            &good,
        );
        let first = frames.try_recv().unwrap().unwrap();
        let second = frames.try_recv().unwrap().unwrap();
        assert_eq!((first.ts.ticks(), &first.payload[..]), (5_000, &b"ab"[..]));
        assert_eq!(
            (second.ts.ticks(), &second.payload[..]),
            (6_024, &b"cd"[..])
        );
        assert_eq!(aac.depacketizer.stats().violations, 2);
        assert!(aac.frames.is_empty(), "drained between packets");
        assert_eq!(
            logs.count(
                Level::WARN,
                "rtsp: AAC payload violates RFC 3640; packet dropped"
            ),
            1
        );
    }
}
