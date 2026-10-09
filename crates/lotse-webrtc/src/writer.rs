//! The RTP cut-through writer of one session and its join.
//!
//! Every viewer gets its own sequence space, renumbered continuously across
//! skips, and its own timestamp offset: the camera's timestamp plus a
//! constant per epoch, so A/V sync still comes from the camera's clock via
//! the Sender Reports str0m derives from the wallclock written with each
//! packet. Payloads are handed over as the shared slices the track
//! published; the only copy per viewer is SRTP's.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_codec::h264::{DEFAULT_MAX_PAYLOAD, LIBWEBRTC_MAX_FRAME_PACKETS};
use lotse_core::media::{MediaPacket, MediaTime};
use lotse_core::session::{SessionLimits, SessionStats};
use lotse_core::track::GopSnapshot;
use str0m::Rtc;
use str0m::media::{Frequency, MediaTime as EngineTime, Mid, Pt};
use str0m::rtp::{ExtensionValues, RtpWrite, SeqNo, VideoOrientation};

use crate::capture_time::CaptureTimeSender;

/// Splits an Annex B access unit into RTP payloads of at most the given
/// size: RFC 6184's packetizer for H.264, RFC 7798's for H.265.
pub(crate) type Packetizer = fn(&[u8], usize) -> Vec<Bytes>;

/// The video RTP clock (RFC 6184 §8.2.1, RFC 7798 §7.1: 90 kHz), in ticks
/// per millisecond.
const TICKS_PER_MS: u32 = 90;

/// How many packets the RTX history may hold; the age bound is
/// `max_packet_age`.
pub(crate) const RTX_CACHE_PACKETS: usize = 2048;

/// A packet's place in time: its session RTP timestamp, its capture time
/// (the wallclock str0m takes for the Sender Reports), and when it is
/// written.
#[derive(Debug, Clone, Copy)]
struct Stamp {
    /// The session timestamp.
    ts: u32,
    /// The capture time.
    capture: Instant,
    /// Now.
    now: Instant,
}

/// The capture time and session timestamp of the last packet written,
/// which a new epoch continues from.
#[derive(Debug, Clone, Copy)]
struct Last {
    /// The session timestamp written.
    session_ts: u32,
    /// When it was captured: the wallclock its Sender Reports take, or,
    /// for a join still, when it was written.
    at: Instant,
}

/// The longest gap between epochs a session timestamp follows: an hour,
/// well inside half the 32-bit RTP clock at 90 kHz (6.6 h, the RFC 1982
/// order [`ts_after`] keeps). A camera gone longer comes back an hour
/// later on the session clock; its Sender Reports start a new line then.
const MAX_EPOCH_GAP: Duration = Duration::from_secs(3_600);

/// The offset that maps `camera_ts`, captured `at`, onto the session clock
/// after `last`: the session timestamp moves on by the capture time that
/// passed (RFC 3550 §5.1: the timestamp follows the sampling instant), at
/// least a millisecond and at most [`MAX_EPOCH_GAP`], so the timestamps
/// stay on the line the Sender Reports describe (§6.4.1) across a
/// reconnect.
fn epoch_offset(last: Last, at: Instant, camera_ts: u32, ticks_per_ms: u32) -> u32 {
    let gap = at
        .saturating_duration_since(last.at)
        .clamp(Duration::from_millis(1), MAX_EPOCH_GAP);
    let ticks =
        u32::try_from(gap.as_millis().saturating_mul(u128::from(ticks_per_ms))).unwrap_or(u32::MAX);
    last.session_ts.wrapping_add(ticks).wrapping_sub(camera_ts)
}

/// A frame the session sent in more RTP packets than some libwebrtc
/// receivers assemble ([`LIBWEBRTC_MAX_FRAME_PACKETS`]), whole all the
/// same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OverLimit {
    /// Its packets.
    pub(crate) packets: usize,
    /// Their payload bytes.
    pub(crate) bytes: u64,
}

/// Where the writer is in the track's timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Dropping live packets until the next `keyframe_start`.
    Waiting {
        /// Why, for the log.
        reason: &'static str,
    },
    /// A catch-up burst went out up to this camera timestamp of this
    /// epoch: live packets up to it are already sent, the next frame
    /// start after it resumes cut-through.
    Resuming {
        /// The last burst frame's RTP timestamp.
        after: u32,
        /// The burst's epoch.
        epoch: u32,
    },
    /// Cut-through.
    Live,
}

/// The cut-through writer of one session's video.
#[derive(Debug)]
pub(crate) struct VideoWriter {
    /// The negotiated payload type.
    pt: Pt,
    /// The media's mid.
    mid: Mid,
    /// The packetizer of the join's frames, for the negotiated codec.
    packetize: Packetizer,
    /// The tunables.
    limits: SessionLimits,
    /// The `playout-delay` values every packet carries, or none.
    ext_vals: ExtensionValues,
    /// The CVO value the last packet of each frame carries, or none
    /// (`crate::cvo`).
    orientation: Option<VideoOrientation>,
    /// Which packets carry their capture time, when `abs-capture-time`
    /// was negotiated (`crate::capture_time`).
    capture_time: Option<CaptureTimeSender>,
    /// The next sequence number.
    seq: u64,
    /// The epoch the offset belongs to.
    epoch: Option<u32>,
    /// Session timestamp = camera timestamp + offset (mod 2³²).
    offset: u32,
    /// The last packet written.
    last: Option<Last>,
    /// Where the writer is.
    phase: Phase,
    /// Packets written of the current live frame.
    frame_packets: usize,
    /// Their payload bytes.
    frame_bytes: u64,
    /// The last frame sent over the limit, until the session takes it.
    over_limit: Option<OverLimit>,
    /// The session's counters; the session adds its own to them.
    pub(crate) stats: SessionStats,
}

/// A capture time for str0m, never after `now`: str0m derives each Sender
/// Report's RTP time from the last packet's wallclock, and one in its
/// future makes it send the report with RTP time 0 (str0m 0.24,
/// `StreamTx::current_rtp_time`), which puts the stream seconds off in the
/// browser. A mapped capture time can land a hair after `now` through the
/// mapping's slew.
fn not_after(wallclock: Instant, now: Instant) -> Instant {
    wallclock.min(now)
}

/// A frame's presentation time as the 32-bit RTP timestamp it came from.
fn rtp_ts(ts: MediaTime) -> u32 {
    u32::try_from(ts.ticks().rem_euclid(1_i64 << 32)).unwrap_or(0)
}

/// Whether `a` is after `b` on the 32-bit RTP clock (RFC 1982 order).
const fn ts_after(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) < (1_u32 << 31) && a != b
}

impl VideoWriter {
    /// A writer for `pt` on `mid`, waiting for the join, packetizing the
    /// join's frames with `packetize`. With `playout_delay`, every packet
    /// carries the `limits.playout_delay_ms` extension; without, the
    /// browser keeps its own playout timing. With an `orientation`, the
    /// last packet of every frame carries it as CVO.
    pub(crate) fn new(
        pt: Pt,
        mid: Mid,
        packetize: Packetizer,
        limits: SessionLimits,
        playout_delay: bool,
        orientation: Option<VideoOrientation>,
    ) -> Self {
        let (min, max) = limits.playout_delay_ms;
        let hundredths = |ms: u16| EngineTime::new(u64::from(ms) / 10, Frequency::HUNDREDTHS);
        Self {
            pt,
            mid,
            packetize,
            limits,
            ext_vals: ExtensionValues {
                play_delay_min: playout_delay.then(|| hundredths(min)),
                play_delay_max: playout_delay.then(|| hundredths(max)),
                ..ExtensionValues::default()
            },
            orientation,
            capture_time: None,
            seq: 0,
            epoch: None,
            offset: 0,
            last: None,
            phase: Phase::Waiting { reason: "join" },
            frame_packets: 0,
            frame_bytes: 0,
            over_limit: None,
            stats: SessionStats::default(),
        }
    }

    /// The CVO value the last packet of each frame carries from the next
    /// last packet on, or none (`crate::cvo`): a frame whose first packets
    /// went out already is turned as the new value says, since the
    /// receiver reads it off the frame's last packet.
    pub(crate) const fn set_orientation(&mut self, orientation: Option<VideoOrientation>) {
        self.orientation = orientation;
    }

    /// The writer, its packets carrying their capture time as `capture_time`
    /// decides.
    pub(crate) fn with_capture_time(mut self, capture_time: Option<CaptureTimeSender>) -> Self {
        self.capture_time = capture_time;
        self
    }

    /// Drops live packets until the next keyframe.
    pub(crate) fn skip(&mut self, reason: &'static str) {
        if self.phase != (Phase::Waiting { reason }) {
            tracing::debug!(reason, "skipping to the next keyframe");
        }
        self.phase = Phase::Waiting { reason };
        self.stats.skips = self.stats.skips.saturating_add(1);
    }

    /// The last frame sent over the limit, once.
    pub(crate) const fn take_over_limit(&mut self) -> Option<OverLimit> {
        self.over_limit.take()
    }

    /// A frame went out in more packets than some libwebrtc receivers
    /// assemble ([`LIBWEBRTC_MAX_FRAME_PACKETS`]): counted and kept for the
    /// session's warning. It was sent whole, as every frame is.
    fn over_browser_limit(&mut self, packets: usize, bytes: u64) {
        self.stats.frames_over_browser_limit =
            self.stats.frames_over_browser_limit.saturating_add(1);
        self.over_limit = Some(OverLimit { packets, bytes });
        tracing::debug!(
            packets,
            bytes,
            limit = LIBWEBRTC_MAX_FRAME_PACKETS,
            "frame over the packet limit of some libwebrtc receivers; sent whole"
        );
    }

    /// The live frame ended, or another began: checked against the limit,
    /// and the next one counted from zero.
    fn finish_frame(&mut self) {
        if self.frame_packets > LIBWEBRTC_MAX_FRAME_PACKETS {
            self.over_browser_limit(self.frame_packets, self.frame_bytes);
        }
        self.frame_packets = 0;
        self.frame_bytes = 0;
    }

    /// The join: a catch-up burst when the cached keyframe is fresh, a
    /// still otherwise, nothing without a cache. Returns whether an
    /// upstream keyframe would help.
    pub(crate) fn join(&mut self, rtc: &mut Rtc, now: Instant, gop: Option<&GopSnapshot>) -> bool {
        let Some(gop) = gop else {
            tracing::info!("join: no cached keyframe; waiting for the next one");
            self.phase = Phase::Waiting {
                reason: "no_keyframe",
            };
            return true;
        };
        let age = gop.age(now);
        if !gop.truncated() && age <= self.limits.catchup_max_age {
            let frames: Vec<_> = gop.frames().collect();
            let count = frames.len();
            // The frames start with the keyframe, so there is a last one.
            let keyframe = gop.keyframe();
            let last = frames.last().copied().unwrap_or(keyframe);
            let last_ts = rtp_ts(last.ts);
            for (index, frame) in frames.iter().enumerate() {
                // Re-stamped 1 ms apart into the gap before the live edge,
                // ending at the last frame's real timestamp.
                let back =
                    u32::try_from(count.saturating_sub(1).saturating_sub(index)).unwrap_or(0);
                let camera_ts = last_ts.wrapping_sub(back.saturating_mul(TICKS_PER_MS));
                let at = last
                    .wallclock
                    .checked_sub(Duration::from_millis(u64::from(back)))
                    .unwrap_or(last.wallclock);
                let ts = self.session_ts(frame.epoch, camera_ts, at);
                let stamp = Stamp {
                    ts,
                    capture: at,
                    now,
                };
                self.write_frame(rtc, stamp, &frame.payload);
            }
            self.stats.join_frames = self
                .stats
                .join_frames
                .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            tracing::info!(
                frames = count,
                age_ms = age.as_millis(),
                "join: catch-up burst"
            );
            self.phase = Phase::Resuming {
                after: last_ts,
                epoch: last.epoch,
            };
            false
        } else {
            // A still at the live edge: the keyframe projected to now on
            // the camera's clock; P-frames are withheld until the next
            // keyframe.
            let keyframe = gop.keyframe();
            let elapsed = now.saturating_duration_since(keyframe.wallclock);
            let ticks = u32::try_from(elapsed.as_millis().saturating_mul(u128::from(TICKS_PER_MS)))
                .unwrap_or(u32::MAX);
            let camera_ts = rtp_ts(keyframe.ts).wrapping_add(ticks);
            let ts = self.session_ts(keyframe.epoch, camera_ts, now);
            let stamp = Stamp {
                ts,
                capture: now,
                now,
            };
            self.write_frame(rtc, stamp, &keyframe.payload);
            self.stats.join_frames = self.stats.join_frames.saturating_add(1);
            tracing::info!(
                age_ms = age.as_millis(),
                truncated = gop.truncated(),
                "join: keyframe still"
            );
            self.phase = Phase::Waiting { reason: "still" };
            true
        }
    }

    /// A live packet. Returns whether an upstream keyframe would help.
    pub(crate) fn write(
        &mut self,
        rtc: &mut Rtc,
        now: Instant,
        packet: &MediaPacket,
        wallclock: Instant,
    ) -> bool {
        if now.saturating_duration_since(packet.arrival) > self.limits.max_packet_age {
            self.stats.dropped_old = self.stats.dropped_old.saturating_add(1);
            let was_live = !matches!(self.phase, Phase::Waiting { .. });
            self.skip("too_old");
            return was_live;
        }
        if packet.lateness > self.limits.max_ingest_lateness {
            // An ingest stall delivered this frame late: the viewer would
            // fall behind by as much, so wait for a timely keyframe.
            self.stats.dropped_late = self.stats.dropped_late.saturating_add(1);
            let was_live = !matches!(self.phase, Phase::Waiting { .. });
            if self.phase
                != (Phase::Waiting {
                    reason: "ingest_late",
                })
            {
                self.stats.ingest_late_skips = self.stats.ingest_late_skips.saturating_add(1);
                tracing::debug!(
                    lateness_ms = packet.lateness.as_millis(),
                    limit_ms = self.limits.max_ingest_lateness.as_millis(),
                    "frame arrived late after an ingest stall"
                );
            }
            self.skip("ingest_late");
            return was_live;
        }
        match self.phase {
            Phase::Waiting { .. } => {
                if !packet.keyframe_start {
                    self.stats.dropped_waiting = self.stats.dropped_waiting.saturating_add(1);
                    return false;
                }
            }
            Phase::Resuming { after, epoch } => {
                if packet.epoch != epoch {
                    if !packet.keyframe_start {
                        self.skip("epoch");
                        self.stats.dropped_waiting = self.stats.dropped_waiting.saturating_add(1);
                        return false;
                    }
                } else if !(packet.frame_start && ts_after(packet.rtp.ts, after)) {
                    // Already sent in the burst, or the tail of a frame
                    // that was.
                    self.stats.dropped_waiting = self.stats.dropped_waiting.saturating_add(1);
                    return false;
                }
            }
            Phase::Live => {}
        }
        if self.phase != Phase::Live {
            tracing::debug!(seq = packet.rtp.seq, "cut-through resumed");
            self.phase = Phase::Live;
            self.finish_frame();
        } else if packet.frame_start {
            self.finish_frame();
        }
        self.frame_packets = self.frame_packets.saturating_add(1);
        self.frame_bytes = self
            .frame_bytes
            .saturating_add(u64::try_from(packet.payload.len()).unwrap_or(u64::MAX));
        let capture = not_after(wallclock, now);
        let ts = self.session_ts(packet.epoch, packet.rtp.ts, capture);
        let stamp = Stamp { ts, capture, now };
        self.emit(rtc, stamp, packet.rtp.marker, Arc::clone(&packet.payload));
        if packet.rtp.marker {
            self.finish_frame();
        }
        false
    }

    /// The session timestamp of a camera timestamp of `epoch`, captured
    /// `at`, choosing a new offset when the epoch changes so the session
    /// clock continues from the last packet by the capture time that
    /// passed between them ([`epoch_offset`]).
    fn session_ts(&mut self, epoch: u32, camera_ts: u32, at: Instant) -> u32 {
        if self.epoch != Some(epoch) {
            if let Some(last) = self.last {
                self.offset = epoch_offset(last, at, camera_ts, TICKS_PER_MS);
                tracing::debug!(epoch, offset = self.offset, "new timestamp offset");
            }
            self.epoch = Some(epoch);
        }
        camera_ts.wrapping_add(self.offset)
    }

    /// One Annex B access unit as RFC 6184 or RFC 7798 packets, marker on
    /// the last; sent whole however many packets it takes.
    fn write_frame(&mut self, rtc: &mut Rtc, stamp: Stamp, access_unit: &[u8]) {
        let payloads = (self.packetize)(access_unit, DEFAULT_MAX_PAYLOAD);
        let count = payloads.len();
        if count > LIBWEBRTC_MAX_FRAME_PACKETS {
            let bytes = payloads.iter().map(Bytes::len).sum::<usize>();
            self.over_browser_limit(count, u64::try_from(bytes).unwrap_or(u64::MAX));
        }
        for (index, payload) in payloads.iter().enumerate() {
            let marker = index.saturating_add(1) == count;
            self.emit(rtc, stamp, marker, Arc::from(payload.as_ref()));
        }
    }

    /// One RTP packet into the negotiated stream. The last packet of every
    /// frame (the marker, RFC 6184 §5.1, RFC 7798 §4.1) carries the CVO
    /// value, which TS 26.114 §7.4.5 asks for on the last packet of each
    /// keyframe and allows on another frame's only when it changed; the
    /// capture time goes on the packets `crate::capture_time` picks.
    fn emit(&mut self, rtc: &mut Rtc, stamp: Stamp, marker: bool, payload: Arc<[u8]>) {
        let Stamp { ts, capture, now } = stamp;
        let mut api = rtc.direct_api();
        let Some(stream) = api.stream_tx_by_mid(self.mid, None) else {
            tracing::warn!(mid = %self.mid, "no send stream; packet dropped");
            return;
        };
        let len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        let abs_capture_time = self
            .capture_time
            .as_mut()
            .and_then(|sender| sender.value(now, ts, capture, payload.len()));
        let write = RtpWrite::new(self.pt, SeqNo::from(self.seq), ts, capture, payload)
            .marker(marker)
            .nackable(true)
            .ext_vals(ExtensionValues {
                // SPEC-DEVIATION(3GPP TS 26.114 §7.4.5): on every frame, not
                // only keyframes and changes, since libwebrtc takes each
                // frame's rotation from its last packet and keeps none
                // across frames (`video/rtp_video_stream_receiver2.cc`), and
                // its own sender does the same (`rtp_sender_video.cc`), both
                // observed 2026-10-03; gate:
                // ts_26_114_7_4_5_cvo_rides_the_last_packet_of_every_frame_when_offered
                video_orientation: self.orientation.filter(|_| marker),
                abs_capture_time,
                ..self.ext_vals.clone()
            });
        stream.write_rtp(write);
        self.seq = self.seq.wrapping_add(1);
        self.last = Some(Last {
            session_ts: ts,
            at: capture,
        });
        self.stats.packets = self.stats.packets.saturating_add(1);
        self.stats.bytes = self.stats.bytes.saturating_add(len);
    }
}

/// The cut-through writer of one session's audio: every packet is a frame,
/// so there is no join and no keyframe to wait for; audio starts at the
/// live edge.
/// Its timestamps are the camera's plus a constant per epoch, like the
/// video's, and its Sender Reports come from the same clock map, which is
/// what keeps the two in sync in the browser.
#[derive(Debug)]
pub(crate) struct AudioWriter {
    /// The negotiated payload type.
    pt: Pt,
    /// The media's mid.
    mid: Mid,
    /// Ticks per millisecond of the track's RTP clock (8 for G.711 and
    /// G.722, whose RTP clock is 8 kHz by RFC 3551 §4.5.2; 48 for Opus).
    ticks_per_ms: u32,
    /// The tunables.
    limits: SessionLimits,
    /// Which packets carry their capture time, when `abs-capture-time`
    /// was negotiated (`crate::capture_time`).
    capture_time: Option<CaptureTimeSender>,
    /// The next sequence number.
    seq: u64,
    /// The epoch the offset belongs to.
    epoch: Option<u32>,
    /// Session timestamp = camera timestamp + offset (mod 2³²).
    offset: u32,
    /// The last packet written.
    last: Option<Last>,
}

impl AudioWriter {
    /// A writer for `pt` on `mid`, whose RTP clock runs at `clock_rate`.
    pub(crate) fn new(pt: Pt, mid: Mid, clock_rate: u32, limits: SessionLimits) -> Self {
        Self {
            pt,
            mid,
            ticks_per_ms: (clock_rate / 1_000).max(1),
            limits,
            capture_time: None,
            seq: 0,
            epoch: None,
            offset: 0,
            last: None,
        }
    }

    /// The writer, its packets carrying their capture time as `capture_time`
    /// decides.
    pub(crate) fn with_capture_time(mut self, capture_time: Option<CaptureTimeSender>) -> Self {
        self.capture_time = capture_time;
        self
    }

    /// A live packet; `false` when it was dropped (too old, or late after
    /// an ingest stall).
    pub(crate) fn write(
        &mut self,
        rtc: &mut Rtc,
        now: Instant,
        packet: &MediaPacket,
        wallclock: Instant,
    ) -> bool {
        if now.saturating_duration_since(packet.arrival) > self.limits.max_packet_age
            || packet.lateness > self.limits.max_ingest_lateness
        {
            return false;
        }
        let capture = not_after(wallclock, now);
        let ts = self.session_ts(packet.epoch, packet.rtp.ts, capture);
        let mut api = rtc.direct_api();
        let Some(stream) = api.stream_tx_by_mid(self.mid, None) else {
            tracing::warn!(mid = %self.mid, "no audio send stream; packet dropped");
            return false;
        };
        let abs_capture_time = self
            .capture_time
            .as_mut()
            .and_then(|sender| sender.value(now, ts, capture, packet.payload.len()));
        let write = RtpWrite::new(
            self.pt,
            SeqNo::from(self.seq),
            ts,
            capture,
            Arc::clone(&packet.payload),
        )
        .marker(packet.rtp.marker)
        .nackable(false)
        .ext_vals(ExtensionValues {
            abs_capture_time,
            ..ExtensionValues::default()
        });
        stream.write_rtp(write);
        self.seq = self.seq.wrapping_add(1);
        self.last = Some(Last {
            session_ts: ts,
            at: capture,
        });
        true
    }

    /// The session timestamp of a camera timestamp of `epoch`, captured
    /// `at`: a new epoch continues the session clock from the last packet
    /// by the capture time that passed between them, as the video writer
    /// does ([`epoch_offset`]).
    fn session_ts(&mut self, epoch: u32, camera_ts: u32, at: Instant) -> u32 {
        if self.epoch != Some(epoch) {
            if let Some(last) = self.last {
                self.offset = epoch_offset(last, at, camera_ts, self.ticks_per_ms);
                tracing::debug!(epoch, offset = self.offset, "new audio timestamp offset");
            }
            self.epoch = Some(epoch);
        }
        camera_ts.wrapping_add(self.offset)
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

    #[test]
    fn rfc3550_5_1_an_epoch_offset_follows_the_capture_time_within_its_bounds() {
        let at = SystemClock.now();
        let last = Last {
            session_ts: 1_000,
            at,
        };
        let after = |ms: u64| at + Duration::from_millis(ms);
        // 2.5 s later at 90 kHz: the camera's 77 lands 225,000 ticks on.
        assert_eq!(
            epoch_offset(last, after(2_500), 77, 90).wrapping_add(77),
            1_000 + 225_000
        );
        // A capture time at or before the last one still moves on a
        // millisecond; one over an hour later moves on an hour.
        assert_eq!(epoch_offset(last, at, 0, 8), 1_008);
        assert_eq!(
            epoch_offset(last, at.checked_sub(Duration::from_secs(1)).unwrap(), 0, 8),
            1_008
        );
        assert_eq!(
            epoch_offset(last, after(5 * 3_600_000), 0, 90),
            1_000 + 3_600_000 * 90
        );
        assert_eq!(
            epoch_offset(last, after(3_600_000), 0, 90),
            1_000 + 3_600_000 * 90
        );
    }

    #[test]
    fn rtp_timestamps_wrap_and_order_per_rfc1982() {
        assert_eq!(rtp_ts(MediaTime::from_ticks(-1)), u32::MAX);
        assert_eq!(rtp_ts(MediaTime::from_ticks(1_i64 << 32)), 0);
        assert_eq!(rtp_ts(MediaTime::from_ticks(5)), 5);
        assert!(ts_after(1, 0));
        assert!(ts_after(0, u32::MAX));
        assert!(!ts_after(0, 0));
        assert!(!ts_after(0, 1));
    }

    /// An engine with a send stream on mid `v` (video) and on `a`
    /// (audio), declared directly, without an offer.
    fn engine(now: Instant) -> Rtc {
        use str0m::media::MediaKind;
        use str0m::rtp::Ssrc;

        crate::install_crypto_provider();
        let mut rtc = Rtc::builder().set_rtp_mode(true).build(now);
        let mut api = rtc.direct_api();
        for (mid, kind, ssrc) in [("v", MediaKind::Video, 1), ("a", MediaKind::Audio, 2)] {
            api.declare_media(Mid::from(mid), kind);
            api.declare_stream_tx(Ssrc::from(ssrc), None, Mid::from(mid), None);
        }
        rtc
    }

    /// A packet that starts a keyframe, arrived `now`.
    fn keyframe_start(now: Instant) -> MediaPacket {
        use lotse_core::media::RtpHeaderFields;

        MediaPacket {
            arrival: now,
            rtp: RtpHeaderFields {
                pt: 96,
                seq: 1,
                ts: 3_000,
                marker: true,
                ssrc: 9,
            },
            frame_start: true,
            keyframe_start: true,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0x65_u8, 0x88][..]),
        }
    }

    #[test]
    fn a_packet_for_a_mid_without_a_send_stream_is_dropped() {
        let now = SystemClock.now();
        let mut rtc = engine(now);
        let packet = keyframe_start(now);
        let limits = SessionLimits::default();
        for (mid, sent) in [("v", 1), ("x", 0)] {
            let mut video = VideoWriter::new(
                Pt::from(96),
                Mid::from(mid),
                lotse_codec::h264::packetize,
                limits,
                false,
                None,
            );
            assert!(!video.write(&mut rtc, now, &packet, now));
            assert_eq!(video.stats.packets, sent, "{mid}");
        }
        for (mid, sent) in [("a", true), ("x", false)] {
            let mut audio = AudioWriter::new(Pt::from(0), Mid::from(mid), 8_000, limits);
            assert_eq!(audio.write(&mut rtc, now, &packet, now), sent, "{mid}");
        }
        // Too old is dropped before the stream is looked up.
        let mut audio = AudioWriter::new(Pt::from(0), Mid::from("a"), 8_000, limits);
        let later = now + limits.max_packet_age + Duration::from_millis(1);
        assert!(!audio.write(&mut rtc, later, &packet, later));
    }
}
