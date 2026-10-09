//! The rate limit for repeating media-path conditions in the log: the
//! first occurrence is logged, then at most one summary line per
//! [`SUMMARY_INTERVAL`] with the count since the last one, so a broken
//! camera cannot flood the log.

use std::time::{Duration, Instant};

/// A repeating media-path condition is logged at most once per this, with
/// the count since the last line.
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(10);

/// Rate limit for one repeating condition: the first occurrence is logged,
/// then at most one line per [`SUMMARY_INTERVAL`], with the count since
/// the last line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Throttle {
    /// When the last line was logged.
    last: Option<Instant>,
    /// Occurrences since the last line.
    pending: u64,
}

impl Throttle {
    /// Counts one occurrence at `now`: `Some(count)` when a line is due,
    /// `count` being the occurrences it covers.
    pub fn hit(&mut self, now: Instant) -> Option<u64> {
        self.pending = self.pending.saturating_add(1);
        match self.last {
            Some(last) if now.saturating_duration_since(last) < SUMMARY_INTERVAL => None,
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.pending))
            }
        }
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
    use crate::clock::{Clock as _, FakeClock};

    #[test]
    fn throttle_logs_the_first_then_one_summary_per_interval() {
        let at = FakeClock::from_system().now();
        let mut throttle = Throttle::default();
        assert_eq!(throttle.hit(at), Some(1));
        assert_eq!(throttle.hit(at + Duration::from_secs(1)), None);
        assert_eq!(throttle.hit(at + Duration::from_secs(9)), None);
        assert_eq!(throttle.hit(at + SUMMARY_INTERVAL), Some(3));
        assert_eq!(throttle.hit(at + SUMMARY_INTERVAL), None);
    }
}
