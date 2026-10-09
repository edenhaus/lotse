//! The injected clock. Every reading of time and every timer in the daemon
//! goes through [`Clock`], so tests drive time instead of sleeping.
//!
//! [`SystemClock`] is the one implementation that reads the operating
//! system's clocks and sleeps on the runtime's timer; it carries the scoped
//! `expect`s for the `disallowed_methods` lint. `FakeClock`, behind the
//! `test-util` feature, only moves when a test advances it, and its sleeps
//! wake when the advance passes their deadline.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

#[cfg(any(test, feature = "test-util"))]
use tokio::sync::watch;

use crate::task::BoxFuture;

/// Source of time for everything in the daemon.
///
/// `now` is the monotonic clock: packet ages, timeouts, backoff timers and
/// latency measurements. `wall_now` is the wall clock: RFC 3339 timestamps in
/// the API and the NTP half of the RTCP Sender Reports the daemon generates
/// (RFC 3550 §6.4.1). `sleep` is the timer. Clocks are shared between tasks,
/// hence `Send + Sync`.
pub trait Clock: fmt::Debug + Send + Sync {
    /// The monotonic time now.
    fn now(&self) -> Instant;

    /// The wall-clock time now.
    fn wall_now(&self) -> SystemTime;

    /// Completes once `duration` of this clock's time has passed.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now(&self) -> Instant {
        (**self).now()
    }

    fn wall_now(&self) -> SystemTime {
        (**self).wall_now()
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        (**self).sleep(duration)
    }
}

/// The real clock, backed by the operating system and the runtime's timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[expect(
        clippy::disallowed_methods,
        reason = "the one place that reads the system clock"
    )]
    fn now(&self) -> Instant {
        Instant::now()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the one place that reads the system clock"
    )]
    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the one place that sleeps on the runtime timer"
    )]
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// A clock that only moves when a test advances it.
///
/// Both readings start where the constructor says and move together, and a
/// sleep completes when an advance reaches its deadline, so a test can
/// assert on timeouts and timestamps without waiting.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct FakeClock {
    /// The monotonic reading at construction.
    base: Instant,
    /// The wall-clock reading at construction.
    wall_base: SystemTime,
    /// How far the clock has been advanced since construction; sleepers
    /// watch it.
    elapsed: watch::Sender<Duration>,
}

#[cfg(any(test, feature = "test-util"))]
impl FakeClock {
    /// A fake clock whose first readings are `now` and `wall_now`.
    pub fn new(now: Instant, wall_now: SystemTime) -> Self {
        let (elapsed, _rx) = watch::channel(Duration::ZERO);
        Self {
            base: now,
            wall_base: wall_now,
            elapsed,
        }
    }

    /// A fake clock that starts at the real clock's current readings.
    pub fn from_system() -> Self {
        let system = SystemClock;
        Self::new(system.now(), system.wall_now())
    }

    /// Moves both readings forward by `by` and wakes the sleeps whose
    /// deadline has passed. Saturates instead of overflowing.
    pub fn advance(&self, by: Duration) {
        self.elapsed
            .send_modify(|elapsed| *elapsed = elapsed.saturating_add(by));
    }

    /// How far the clock has been advanced since construction.
    fn elapsed(&self) -> Duration {
        *self.elapsed.borrow()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Default for FakeClock {
    fn default() -> Self {
        Self::from_system()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for FakeClock {
    /// The reading stays at its start on the overflow `checked_add` guards
    /// against, which no test reaches.
    fn now(&self) -> Instant {
        self.base.checked_add(self.elapsed()).unwrap_or(self.base)
    }

    /// See [`FakeClock::now`].
    fn wall_now(&self) -> SystemTime {
        self.wall_base
            .checked_add(self.elapsed())
            .unwrap_or(self.wall_base)
    }

    /// Completes at the first advance that reaches the deadline, or at once
    /// for a zero duration. Completes too if the clock is dropped, so a
    /// finished test never leaves a sleeper hanging.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let deadline = self.elapsed().saturating_add(duration);
        let mut elapsed = self.elapsed.subscribe();
        Box::pin(async move {
            while *elapsed.borrow_and_update() < deadline {
                if elapsed.changed().await.is_err() {
                    return;
                }
            }
        })
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

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock;
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
    }

    #[test]
    fn system_wall_clock_is_after_the_unix_epoch() {
        assert!(SystemClock.wall_now() > SystemTime::UNIX_EPOCH);
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::disallowed_methods,
        reason = "only the runtime's own instant moves with the paused timer this test measures"
    )]
    async fn system_clock_sleeps_on_the_runtime_timer() {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let before = tokio::time::Instant::now();
        clock.sleep(Duration::from_secs(3)).await;
        assert_eq!(before.elapsed(), Duration::from_secs(3));
        assert!(clock.now() <= SystemClock.now());
        assert!(clock.wall_now() <= SystemClock.wall_now());
    }

    #[test]
    fn fake_clock_only_moves_when_advanced() {
        let clock = FakeClock::default();
        let start = clock.now();
        let wall_start = clock.wall_now();
        assert_eq!(clock.now(), start);

        clock.advance(Duration::from_millis(150));
        assert_eq!(clock.now() - start, Duration::from_millis(150));
        assert_eq!(
            clock.wall_now().duration_since(wall_start).unwrap(),
            Duration::from_millis(150)
        );
    }

    #[test]
    fn fake_clock_starts_at_the_given_readings() {
        let now = SystemClock.now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = FakeClock::new(now, wall);
        assert_eq!(clock.now(), now);
        assert_eq!(clock.wall_now(), wall);
    }

    #[test]
    fn fake_clock_advance_saturates() {
        let clock = FakeClock::default();
        clock.advance(Duration::MAX);
        clock.advance(Duration::from_secs(1));
        assert_eq!(clock.elapsed(), Duration::MAX);
        // `Instant` cannot represent `now + Duration::MAX`; the reading stays put.
        assert_eq!(clock.now(), clock.base);
    }

    #[tokio::test]
    async fn fake_clock_sleeps_wake_on_advance() {
        let clock = Arc::new(FakeClock::default());
        let mut sleep = clock.sleep(Duration::from_secs(5));
        clock.sleep(Duration::ZERO).await;
        assert!(!futures_ready(&mut sleep), "not before the deadline");
        clock.advance(Duration::from_secs(4));
        assert!(!futures_ready(&mut sleep));
        clock.advance(Duration::from_secs(1));
        sleep.await;

        let late = clock.sleep(Duration::from_secs(1));
        drop(clock);
        late.await;
    }

    /// Polls `future` once without a runtime hook; whether it is ready.
    fn futures_ready(future: &mut BoxFuture<'static, ()>) -> bool {
        use std::task::{Context, Waker};
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    }
}
