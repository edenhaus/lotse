//! Timestamp discontinuities: when a track's RTP timestamps leave their
//! timeline (a camera reboot or a timestamp reset), which the source turns
//! into a new epoch for all tracks of the connection together.
//!
//! A timestamp is compared with the previous one of its track, 32-bit
//! wrap included (RFC 3550 §5.1), and with the arrival time that passed
//! between them. A jump back by more than [`MAX_TIMESTAMP_JUMP`] is a new
//! timeline, and so is a jump ahead of the elapsed time by more than it.
//! What is not: B-frame reordering (a few frames back), an ingest stall
//! (little media time over a lot of arrival time, which lateness handles),
//! an encoder pause or audio silence suppression (the timestamps move with
//! the time that passed, RFC 3551 §4.1).

use std::time::{Duration, Instant};

/// How far a timestamp may move back, or ahead of the elapsed time,
/// within one timeline.
pub const MAX_TIMESTAMP_JUMP: Duration = Duration::from_secs(1);

/// Nanoseconds per second.
const NANOS_PER_SEC: i128 = 1_000_000_000;

/// Watches one track's RTP timestamps for a new timeline.
#[derive(Debug, Clone)]
pub struct TimestampGuard {
    /// The track's declared ticks per second; zero disables the guard.
    clock_rate: u32,
    /// The last timestamp and when it arrived.
    last: Option<(u32, Instant)>,
}

impl TimestampGuard {
    /// A guard for a track at `clock_rate` ticks per second.
    pub const fn new(clock_rate: u32) -> Self {
        Self {
            clock_rate,
            last: None,
        }
    }

    /// Checks a packet's timestamp. `Some` when it starts a new timeline,
    /// with how far the timestamp moved in milliseconds (negative: back).
    pub fn observe(&mut self, rtp_ts: u32, arrival: Instant) -> Option<i64> {
        let (last_ts, last_at) = self.last.replace((rtp_ts, arrival))?;
        let ticks = i32::from_ne_bytes(rtp_ts.wrapping_sub(last_ts).to_ne_bytes());
        let moved = i128::from(ticks)
            .checked_mul(NANOS_PER_SEC)?
            .checked_div(i128::from(self.clock_rate))?;
        let elapsed = i128::try_from(arrival.saturating_duration_since(last_at).as_nanos()).ok()?;
        let bound = i128::try_from(MAX_TIMESTAMP_JUMP.as_nanos()).ok()?;
        let back = moved < bound.checked_neg()?;
        let ahead = moved.checked_sub(elapsed)? > bound;
        (back || ahead).then(|| i64::try_from(moved.checked_div(1_000_000)?).ok())?
    }

    /// Forgets the last timestamp: the next one starts the timeline, for a
    /// connection whose epoch another track already started.
    pub const fn rebase(&mut self) {
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::clock::{Clock as _, SystemClock};

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn rfc3550_5_1_a_steady_stream_wrapping_its_clock_stays_on_its_timeline() {
        let mut guard = TimestampGuard::new(90_000);
        let t0 = SystemClock.now();
        let start = u32::MAX - 30_000;
        for i in 0..60_u32 {
            let ts = start.wrapping_add(i * 3_000);
            assert_eq!(
                guard.observe(ts, t0 + ms(u64::from(i) * 33)),
                None,
                "frame {i}"
            );
        }
    }

    #[test]
    fn a_reset_back_or_far_ahead_starts_a_new_timeline() {
        let t0 = SystemClock.now();
        let mut guard = TimestampGuard::new(90_000);
        assert_eq!(guard.observe(900_000, t0), None);
        assert_eq!(guard.observe(3_000, t0 + ms(33)), Some(-9_966));
        // The new timeline continues from the jumped value.
        assert_eq!(guard.observe(6_000, t0 + ms(66)), None);
        // An hour ahead in 33 ms.
        assert_eq!(
            guard.observe(6_000 + 90_000 * 3_600, t0 + ms(99)),
            Some(3_600_000)
        );
    }

    #[test]
    fn bounds_are_exclusive_and_measured_against_the_elapsed_time() {
        let t0 = SystemClock.now();
        let mut guard = TimestampGuard::new(90_000);
        guard.observe(1_000_000, t0);
        // Exactly 1 s back is still reordering, a tick more is not.
        assert_eq!(guard.observe(1_000_000 - 90_000, t0), None);
        guard.rebase();
        guard.observe(1_000_000, t0);
        assert_eq!(guard.observe(1_000_000 - 90_001, t0), Some(-1_000));
        // Exactly 1 s ahead of the elapsed time is still the timeline.
        guard.rebase();
        guard.observe(0, t0);
        assert_eq!(guard.observe(90_000 + 45_000, t0 + ms(500)), None);
        assert_eq!(guard.observe(135_000 + 90_001, t0 + ms(500)), Some(1_000));
    }

    #[test]
    fn stalls_pauses_silence_and_b_frames_are_not_discontinuities() {
        let t0 = SystemClock.now();
        let mut guard = TimestampGuard::new(90_000);
        guard.observe(0, t0);
        // An ingest stall: one frame of media over three seconds.
        assert_eq!(guard.observe(3_000, t0 + ms(3_000)), None);
        // An encoder pause: five seconds of media over five seconds.
        assert_eq!(guard.observe(3_000 + 450_000, t0 + ms(8_000)), None);
        // B-frames: presentation order steps back a few frames.
        assert_eq!(guard.observe(453_000 - 9_000, t0 + ms(8_033)), None);
        // Audio silence suppression at 8 kHz: 4 s later, 4 s on.
        let mut audio = TimestampGuard::new(8_000);
        audio.observe(0, t0);
        assert_eq!(audio.observe(160 + 32_000, t0 + ms(4_020)), None);
    }

    #[test]
    fn a_rebased_guard_takes_the_next_timestamp_as_its_timeline() {
        let t0 = SystemClock.now();
        let mut guard = TimestampGuard::new(90_000);
        guard.observe(0, t0);
        guard.rebase();
        assert_eq!(
            guard.observe(90_000 * 3_600, t0),
            None,
            "a new base, not a jump"
        );
        assert_eq!(guard.observe(90_000 * 3_600 + 3_000, t0 + ms(33)), None);
    }

    #[test]
    fn without_a_clock_rate_nothing_is_detected() {
        let t0 = SystemClock.now();
        let mut guard = TimestampGuard::new(0);
        guard.observe(0, t0);
        assert_eq!(guard.observe(u32::MAX / 2, t0), None);
    }
}
