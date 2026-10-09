//! The three retry schedules: reconnecting to a source, restarting a
//! crashed worker and retrying a listener's failed `accept`.
//!
//! All are owned by core so every source, every worker and every listener
//! gets the same policy. Reconnect delays are jittered so a rebooting camera is not hit
//! by every stream at once.

use std::time::Duration;

/// The reconnect schedule: how many attempts at each delay before the next
/// step. After it, every attempt waits [`RECONNECT_MAX`].
const RECONNECT_SCHEDULE: [(Duration, u32); 3] = [
    (Duration::from_secs(1), 5),
    (Duration::from_secs(5), 5),
    (Duration::from_secs(10), 10),
];

/// The delay once the schedule is exhausted.
const RECONNECT_MAX: Duration = Duration::from_secs(60);

/// The first crash-restart delay.
const CRASH_FIRST: Duration = Duration::from_millis(500);

/// The crash-restart delay stops doubling here.
const CRASH_MAX: Duration = Duration::from_secs(60);

/// The pause after an `accept` that failed (`EMFILE`, `ENFILE`, `ENOMEM`,
/// which leave the connection queued and the socket readable, so retrying
/// at once would spin): 10 ms, doubled per failure in a row.
const ACCEPT_FIRST: Duration = Duration::from_millis(10);

/// The longest pause between failed `accept`s: 1 s, so a descriptor freed
/// elsewhere is noticed soon and the warning is logged at most once a second.
const ACCEPT_MAX: Duration = Duration::from_secs(1);

/// Jitter range around a delay, in parts per million: ±20 %.
const JITTER_PPM: u64 = 200_000;

/// A small xorshift64* generator for jitter. Not security-relevant: it
/// only spreads reconnects in time.
#[derive(Debug, Clone)]
struct Jitter {
    /// The generator state, never zero.
    state: u64,
}

impl Jitter {
    /// A generator from `seed`; zero, a fixed point of xorshift, is replaced.
    const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    /// The next value.
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x.wrapping_shr(12);
        x ^= x.wrapping_shl(25);
        x ^= x.wrapping_shr(27);
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// `delay` scaled by a factor in `[1 − JITTER, 1 + JITTER]`.
    fn apply(&mut self, delay: Duration) -> Duration {
        let band = JITTER_PPM.saturating_mul(2).saturating_add(1);
        let spread = self.next_u64().checked_rem(band).unwrap_or(0);
        let factor_ppm = u128::from(
            1_000_000_u64
                .saturating_sub(JITTER_PPM)
                .saturating_add(spread),
        );
        let nanos = delay
            .as_nanos()
            .checked_mul(factor_ppm)
            .and_then(|n| n.checked_div(1_000_000))
            .unwrap_or(delay.as_nanos());
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

/// The source reconnect schedule: after a live period one immediate
/// attempt, then 1 s ×5, 5 s ×5, 10 s ×10, then 60 s, each jittered
/// ±20 %; reset by the runner after `stable_after` of streaming.
#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    /// Delays handed out since the last reset.
    attempts: u32,
    /// The immediate attempt after a live period has been used.
    immediate_used: bool,
    /// The jitter generator.
    jitter: Jitter,
}

impl ReconnectBackoff {
    /// A fresh schedule with jitter seeded by `seed`.
    pub const fn new(seed: u64) -> Self {
        Self {
            attempts: 0,
            immediate_used: false,
            jitter: Jitter::new(seed),
        }
    }

    /// The delay before the next attempt. `after_live` says the connection
    /// that just ended had reached the live state; the first such loss
    /// since a reset is retried at once.
    pub fn next_delay(&mut self, after_live: bool) -> Duration {
        if after_live && !self.immediate_used {
            self.immediate_used = true;
            return Duration::ZERO;
        }
        let base = base_delay(self.attempts);
        self.attempts = self.attempts.saturating_add(1);
        self.jitter.apply(base)
    }

    /// Delays handed out since the last reset.
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Back to the start of the schedule, after stable streaming.
    pub const fn reset(&mut self) {
        self.attempts = 0;
        self.immediate_used = false;
    }
}

/// The unjittered delay for the `attempt`th (zero-based) scheduled retry.
fn base_delay(attempt: u32) -> Duration {
    let mut remaining = attempt;
    for (delay, count) in RECONNECT_SCHEDULE {
        if remaining < count {
            return delay;
        }
        remaining = remaining.saturating_sub(count);
    }
    RECONNECT_MAX
}

/// The worker crash-restart schedule: 0.5 s doubling to 60 s, reset by the
/// supervisor after a worker ran stably.
#[derive(Debug, Clone, Default)]
pub struct CrashBackoff {
    /// Restarts since the last reset.
    restarts: u32,
}

impl CrashBackoff {
    /// A fresh schedule.
    pub const fn new() -> Self {
        Self { restarts: 0 }
    }

    /// The delay before the next restart.
    pub fn next_delay(&mut self) -> Duration {
        let delay = CRASH_FIRST
            .checked_mul(1_u32.checked_shl(self.restarts).unwrap_or(u32::MAX))
            .map_or(CRASH_MAX, |d| d.min(CRASH_MAX));
        self.restarts = self.restarts.saturating_add(1);
        delay
    }

    /// Restarts since the last reset.
    pub const fn restarts(&self) -> u32 {
        self.restarts
    }

    /// Back to the first delay, after a worker ran stably.
    pub const fn reset(&mut self) {
        self.restarts = 0;
    }
}

/// The pause schedule of a listener whose `accept` fails: 10 ms doubling
/// to 1 s while it keeps failing, reset by the next success. Not jittered:
/// one listener, nothing to spread.
#[derive(Debug, Clone, Default)]
pub struct AcceptBackoff {
    /// The last pause, while `accept` keeps failing; `None` after a
    /// success.
    last: Option<Duration>,
}

impl AcceptBackoff {
    /// A fresh schedule.
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// The pause before retrying the `accept` that just failed.
    pub fn next_delay(&mut self) -> Duration {
        let pause = self
            .last
            .map_or(ACCEPT_FIRST, |last| last.saturating_mul(2).min(ACCEPT_MAX));
        self.last = Some(pause);
        pause
    }

    /// Back to the first pause, after an `accept` succeeded.
    pub const fn reset(&mut self) {
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

    fn within_jitter(actual: Duration, base: Duration) -> bool {
        actual >= base.mul_f64(0.8) && actual <= base.mul_f64(1.2)
    }

    #[test]
    fn reconnect_follows_the_documented_schedule_with_jitter() {
        let mut backoff = ReconnectBackoff::new(42);
        let expected: Vec<Duration> = [(1, 5), (5, 5), (10, 10), (60, 3)]
            .iter()
            .flat_map(|(secs, n)| std::iter::repeat_n(Duration::from_secs(*secs), *n))
            .collect();
        for (attempt, base) in expected.iter().enumerate() {
            let delay = backoff.next_delay(false);
            assert!(
                within_jitter(delay, *base),
                "attempt {attempt}: {delay:?} vs {base:?}"
            );
            assert_ne!(delay, *base, "jitter applied");
        }
        assert_eq!(backoff.attempts(), 23);
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert!(within_jitter(
            backoff.next_delay(false),
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn one_immediate_attempt_after_a_live_period() {
        let mut backoff = ReconnectBackoff::new(7);
        assert_eq!(backoff.next_delay(true), Duration::ZERO);
        assert_eq!(
            backoff.attempts(),
            0,
            "the immediate attempt is not a scheduled one"
        );
        assert!(within_jitter(
            backoff.next_delay(true),
            Duration::from_secs(1)
        ));
        assert!(within_jitter(
            backoff.next_delay(true),
            Duration::from_secs(1)
        ));
        backoff.reset();
        assert_eq!(backoff.next_delay(true), Duration::ZERO);
        let mut fresh = ReconnectBackoff::new(7);
        assert!(within_jitter(
            fresh.next_delay(false),
            Duration::from_secs(1)
        ));
        assert_eq!(
            fresh.next_delay(true),
            Duration::ZERO,
            "still available after a scheduled retry"
        );
    }

    #[test]
    fn jitter_differs_between_seeds_and_never_leaves_the_band() {
        let a = ReconnectBackoff::new(1).next_delay(false);
        let b = ReconnectBackoff::new(2).next_delay(false);
        assert_ne!(a, b);
        let mut jitter = Jitter::new(0);
        assert_ne!(jitter.state, 0);
        for _ in 0..10_000 {
            assert!(within_jitter(
                jitter.apply(Duration::from_secs(10)),
                Duration::from_secs(10)
            ));
        }
        assert!(Jitter::new(0).apply(Duration::MAX) <= Duration::MAX);
        assert_eq!(jitter.apply(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn crash_restart_doubles_from_half_a_second_to_a_minute() {
        let mut backoff = CrashBackoff::new();
        assert_eq!(backoff.restarts(), CrashBackoff::default().restarts());
        let expected = [
            500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000,
        ];
        for ms in expected {
            assert_eq!(backoff.next_delay(), Duration::from_millis(ms));
        }
        assert_eq!(backoff.restarts(), 9);
        for _ in 0..40 {
            assert_eq!(backoff.next_delay(), CRASH_MAX, "capped, no overflow");
        }
        backoff.reset();
        assert_eq!(backoff.restarts(), 0);
        assert_eq!(backoff.next_delay(), CRASH_FIRST);
    }

    #[test]
    fn accept_pauses_double_from_10_ms_to_1_s_and_reset_on_success() {
        let mut backoff = AcceptBackoff::new();
        let expected = [10, 20, 40, 80, 160, 320, 640, 1_000, 1_000];
        for ms in expected {
            assert_eq!(backoff.next_delay(), Duration::from_millis(ms));
        }
        for _ in 0..80 {
            assert_eq!(backoff.next_delay(), ACCEPT_MAX, "capped, no overflow");
        }
        backoff.reset();
        assert_eq!(backoff.next_delay(), ACCEPT_FIRST);
        assert_eq!(AcceptBackoff::default().next_delay(), ACCEPT_FIRST);
    }
}
