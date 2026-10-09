//! The capture time of the frames as the `abs-capture-time` RTP header
//! extension, so a browser that asked for it reports when each frame was
//! captured (`captureTimestamp`, W3C webrtc-extensions) and a latency
//! measurement can take capture to render.
//!
//! The format is not an IETF standard: it is the webrtc.org experiments
//! document <http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time>
//! (`docs/native-code/rtp-hdrext/abs-capture-time/README.md`, libwebrtc at
//! `f56234a4ec`, observed 2026-10-07), cited as observed behavior. Its
//! extended form is sent: the 64-bit NTP capture timestamp (UQ32.32) and
//! the estimated capture clock offset, 0, in the one-byte header form
//! (RFC 8285 §4.2), answered only when offered (RFC 8285 §6), which str0m
//! does by echoing the offered `a=extmap` under its id.
//!
//! lotse presents itself as the capture system, as the document lets an
//! intermediate system do ("Intermediate systems"): the capture time is
//! the one the source clock map gives the packet, which str0m also takes
//! for the stream's Sender Reports, on the session's wall clock; the
//! offset is 0 because the capture system and the sender are one.
//!
//! When it goes out follows libwebrtc's own sender
//! (`modules/rtp_rtcp/source/absolute_capture_time_sender.cc`, observed
//! 2026-10-07 at `f56234a4ec`), which the document's "Timestamp
//! interpolation" describes: not with every packet, but on the first
//! packet, when more than [`INTERVAL`] passed since the last one, and when
//! the receiver's interpolation from the last one by RTP timestamp would be
//! off by more than [`MAX_ERROR`] (a new epoch, a slewed clock map, a join
//! burst). libwebrtc puts it on the first packet of a frame and shortens
//! that packet's payload for it; the cut-through writer sends the camera's
//! packets as they are, so it goes on the first packet of the frame with
//! room for it ([`ROOM`]), and a frame without one leaves it to the next
//! frame. A receiver takes the frame's capture time from any of its
//! packets, interpolating within the second.
//!
//! `SPEC-DEVIATION`: the capture timestamp "MUST be based on the same
//! clock as the clock used to generate NTP timestamps for RTCP sender
//! reports". str0m 0.24 makes its Sender Reports' NTP time from an
//! `Instant` through a wall-clock anchor it takes once per process and
//! keeps private (`util/time_tricks.rs`); the
//! session converts with its own anchor, read from the same clocks when
//! it opens ([`WallAnchor`]). The two agree to the microsecond unless the
//! system's wall clock was stepped between the worker's first session and
//! this one.

use std::time::{Duration, Instant, SystemTime};

use lotse_codec::h264::DEFAULT_MAX_PAYLOAD;
use str0m::Rtc;
use str0m::media::Mid;
use str0m::rtp::{AbsCaptureTime, Extension};

/// The longest a sender goes without the extension: libwebrtc's
/// `AbsoluteCaptureTimeSender::kInterpolationMaxInterval`, also the
/// longest its receiver interpolates from the last one
/// (`AbsoluteCaptureTimeInterpolator::kInterpolationMaxInterval`); the
/// document's "e.g. every second".
pub(crate) const INTERVAL: Duration = Duration::from_secs(1);

/// The interpolation error past which the extension is sent again:
/// libwebrtc's `AbsoluteCaptureTimeSender::kInterpolationMaxError`.
pub(crate) const MAX_ERROR: Duration = Duration::from_millis(1);

/// What the extension can add to a packet beyond the extension block the
/// payload size leaves room for: its one-byte header and 16 bytes of data
/// (RFC 8285 §4.2), less one byte of the padding the block had (it is
/// padded to 4). A packet whose payload leaves this much of
/// [`DEFAULT_MAX_PAYLOAD`] free still fits libwebrtc's 1200-byte RTP
/// packet with it.
pub(crate) const ROOM: usize = 16;

/// The session's wall clock: the monotonic and the wall clock read
/// together when it opened, which turns a capture `Instant` into the
/// `SystemTime` the extension carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WallAnchor {
    /// The monotonic reading.
    at: Instant,
    /// The wall clock at `at`.
    wall: SystemTime,
}

impl WallAnchor {
    /// The anchor of the readings `at` and `wall`.
    pub(crate) const fn new(at: Instant, wall: SystemTime) -> Self {
        Self { at, wall }
    }

    /// `instant` on the wall clock; the anchor's own reading where
    /// `SystemTime` cannot hold it.
    pub(crate) fn wall(&self, instant: Instant) -> SystemTime {
        if instant >= self.at {
            self.wall
                .checked_add(instant.saturating_duration_since(self.at))
                .unwrap_or(self.wall)
        } else {
            self.wall
                .checked_sub(self.at.saturating_duration_since(instant))
                .unwrap_or(self.wall)
        }
    }
}

/// The last extension sent, which the receiver interpolates from.
#[derive(Debug, Clone, Copy)]
struct Sent {
    /// When it went out.
    at: Instant,
    /// The packet's RTP timestamp.
    ts: u32,
    /// Its capture time.
    capture: Instant,
}

/// Decides, per packet, whether it carries the extension, and with what.
#[derive(Debug)]
pub(crate) struct CaptureTimeSender {
    /// The session's wall clock.
    anchor: WallAnchor,
    /// The media's RTP clock rate, in Hz.
    clock_rate: u32,
    /// The last one sent.
    last: Option<Sent>,
}

impl CaptureTimeSender {
    /// The sender of the media `mid` (`kind` for the log), whose RTP clock
    /// runs at `clock_rate`, or `None` when the offer did not list the
    /// extension for it. Logs the decision.
    pub(crate) fn negotiate(
        rtc: &Rtc,
        mid: Mid,
        kind: &'static str,
        clock_rate: u32,
        anchor: WallAnchor,
    ) -> Option<Self> {
        let id = rtc
            .media(mid)
            .and_then(|media| media.remote_extmap().id_of(Extension::AbsoluteCaptureTime));
        let Some(id) = id else {
            tracing::debug!(
                kind,
                "the offer has no abs-capture-time extension; capture times are not sent"
            );
            return None;
        };
        tracing::debug!(
            kind,
            extension_id = id,
            "abs-capture-time negotiated; capture times go out once a second"
        );
        Some(Self {
            anchor,
            clock_rate,
            last: None,
        })
    }

    /// The value a packet of RTP timestamp `ts`, captured at `capture`,
    /// with a payload of `payload` bytes, carries when written at `now`;
    /// `None` when it is not due or the packet has no room for it.
    pub(crate) fn value(
        &mut self,
        now: Instant,
        ts: u32,
        capture: Instant,
        payload: usize,
    ) -> Option<AbsCaptureTime> {
        if payload.saturating_add(ROOM) > DEFAULT_MAX_PAYLOAD || !self.due(now, ts, capture) {
            return None;
        }
        self.last = Some(Sent {
            at: now,
            ts,
            capture,
        });
        Some(AbsCaptureTime {
            // SPEC-DEVIATION(abs-capture-time, "Absolute capture
            // timestamp"): the session's anchor, not str0m's private one
            // of the Sender Reports (module docs); gate:
            // abs_capture_time_carries_the_written_capture_time_on_the_session_wall_clock_once_a_second
            capture_time: self.anchor.wall(capture),
            clock_offset: Some(0),
        })
    }

    /// Whether the extension is due: libwebrtc's
    /// `AbsoluteCaptureTimeSender::ShouldSendExtension` for one source,
    /// one clock rate and a constant offset.
    fn due(&self, now: Instant, ts: u32, capture: Instant) -> bool {
        let Some(last) = self.last else {
            return true;
        };
        if now.saturating_duration_since(last.at) > INTERVAL {
            return true;
        }
        self.interpolate(last, ts)
            .is_none_or(|interpolated| abs_diff(interpolated, capture) > MAX_ERROR)
    }

    /// The capture time a receiver interpolates for `ts` from `last`: the
    /// RTP time between them, forward or back (RFC 3550 §5.1, modulo 2³²),
    /// at the clock rate (libwebrtc
    /// `AbsoluteCaptureTimeInterpolator::InterpolateAbsoluteCaptureTimestamp`).
    fn interpolate(&self, last: Sent, ts: u32) -> Option<Instant> {
        let forward = ts.wrapping_sub(last.ts);
        let back = last.ts.wrapping_sub(ts);
        let rate = u64::from(self.clock_rate);
        if forward <= back {
            let nanos = u64::from(forward)
                .checked_mul(1_000_000_000)?
                .checked_div(rate)?;
            last.capture.checked_add(Duration::from_nanos(nanos))
        } else {
            let nanos = u64::from(back)
                .checked_mul(1_000_000_000)?
                .checked_div(rate)?;
            last.capture.checked_sub(Duration::from_nanos(nanos))
        }
    }
}

/// How far apart two instants are.
fn abs_diff(a: Instant, b: Instant) -> Duration {
    a.saturating_duration_since(b)
        .max(b.saturating_duration_since(a))
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

    const VIDEO: u32 = 90_000;

    /// The Unix epoch on the NTP timescale, in seconds (RFC 868: 70 years
    /// and 17 leap days).
    const NTP_UNIX_OFFSET_SECS: u64 = 2_208_988_800;

    fn sender(anchor: WallAnchor) -> CaptureTimeSender {
        CaptureTimeSender {
            anchor,
            clock_rate: VIDEO,
            last: None,
        }
    }

    /// NTP UQ32.32 of a wall time, as the extension carries it.
    fn ntp(time: SystemTime) -> u64 {
        let since = time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        let secs = since.as_secs() + NTP_UNIX_OFFSET_SECS;
        let frac = (u128::from(since.subsec_nanos()) << 32) / 1_000_000_000;
        (secs << 32) | u64::try_from(frac).unwrap()
    }

    #[test]
    fn the_anchor_maps_instants_on_both_sides_onto_the_wall_clock() {
        let at = SystemClock.now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_hours(500_000);
        let anchor = WallAnchor::new(at, wall);
        assert_eq!(anchor.wall(at), wall);
        assert_eq!(
            anchor.wall(at + Duration::from_millis(1_500)),
            wall + Duration::from_millis(1_500)
        );
        let earlier = at.checked_sub(Duration::from_millis(250)).unwrap();
        assert_eq!(anchor.wall(earlier), wall - Duration::from_millis(250));
    }

    #[test]
    fn abs_capture_time_first_packet_then_once_a_second_libwebrtc_interval() {
        let start = SystemClock.now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_hours(500_000);
        let mut sender = sender(WallAnchor::new(start, wall));
        // 30 fps: 3000 ticks and 33.3 ms a frame, captured 40 ms before
        // it is written.
        let frame = |n: u32| {
            let capture = start + Duration::from_nanos(u64::from(n) * 1_000_000_000 / 30);
            (n * 3_000, capture, capture + Duration::from_millis(40))
        };
        let mut sent = Vec::new();
        for n in 0..91 {
            let (ts, capture, now) = frame(n);
            if let Some(value) = sender.value(now, ts, capture, 1_000) {
                sent.push(n);
                assert_eq!(value.clock_offset, Some(0));
                assert_eq!(value.capture_time, sender.anchor.wall(capture));
            }
        }
        // The first frame, then the first more than a second after the
        // last one sent: frames 31 (1033 ms) and 62 (2067 ms).
        assert_eq!(sent, [0, 31, 62]);
        let (_, capture, _) = frame(0);
        assert_eq!(
            ntp(sender.anchor.wall(capture)) >> 32,
            1_800_000_000 + NTP_UNIX_OFFSET_SECS
        );
    }

    #[test]
    fn abs_capture_time_a_jump_beyond_1_ms_from_the_interpolation_goes_out_at_once() {
        let start = SystemClock.now();
        let mut sender = sender(WallAnchor::new(start, SystemTime::UNIX_EPOCH));
        assert!(sender.value(start, 1_000, start, 100).is_some());
        // 10 ms later on both clocks: interpolated exactly, not due.
        let later = start + Duration::from_millis(10);
        assert!(sender.value(later, 1_900, later, 100).is_none());
        // 1 ms off is within libwebrtc's error; just over it is not.
        let off = later + Duration::from_millis(1);
        assert!(sender.value(later, 1_900, off, 100).is_none());
        let over = off + Duration::from_micros(1);
        assert!(sender.value(later, 1_900, over, 100).is_some());
        // Back in RTP time (a join's re-stamped frame before the last
        // one): interpolated backwards, exact, so not due.
        let back = over.checked_sub(Duration::from_millis(5)).unwrap();
        assert!(sender.value(later, 1_450, back, 100).is_none());
        // Across the 32-bit wrap, forward.
        let mut sender = self::sender(WallAnchor::new(start, SystemTime::UNIX_EPOCH));
        assert!(sender.value(start, u32::MAX - 899, start, 100).is_some());
        assert!(sender.value(later, 0, later, 100).is_none());
        // Half the RTP clock away (a new epoch's offset): due.
        assert!(sender.value(later, 1 << 31, later, 100).is_some());
    }

    #[test]
    fn abs_capture_time_waits_for_a_packet_with_room_for_its_17_bytes() {
        let start = SystemClock.now();
        let mut sender = sender(WallAnchor::new(start, SystemTime::UNIX_EPOCH));
        // A full packet has no room: the extension stays due.
        assert!(sender.value(start, 0, start, DEFAULT_MAX_PAYLOAD).is_none());
        assert!(
            sender
                .value(start, 0, start, DEFAULT_MAX_PAYLOAD - ROOM + 1)
                .is_none()
        );
        assert!(
            sender
                .value(start, 0, start, DEFAULT_MAX_PAYLOAD - ROOM)
                .is_some()
        );
        // A one-byte header and 16 bytes of data, padded to 4 with the
        // block of 34 the payload size leaves room for (36): 52, 16 more.
        assert_eq!((34 + 1 + 16usize).div_ceil(4) * 4 - 36, ROOM);
    }

    #[test]
    fn abs_capture_time_interpolation_without_a_clock_rate_is_never_trusted() {
        let start = SystemClock.now();
        let mut sender = sender(WallAnchor::new(start, SystemTime::UNIX_EPOCH));
        sender.clock_rate = 0;
        assert!(sender.value(start, 0, start, 100).is_some());
        assert!(sender.value(start, 0, start, 100).is_some());
        assert!(sender.value(start, 1, start, 100).is_some());
    }
}
