//! The rate limit for repeating media-path conditions in the log: the
//! first occurrence is logged, then at most one summary line per
//! [`SUMMARY_INTERVAL`] with the count since the last one, so a broken
//! camera cannot flood the log. [`CallSites`] applies it per call site to
//! the lines of other crates, which log as often as a camera makes them.

use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::clock::Clock;

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

/// One [`Throttle`] per call site of another crate's log lines: the
/// daemon's bridge of `log` records and the RTSP source's layer for
/// retina's `tracing` events, both of which log once per packet or
/// request a camera, server or browser sent; or per limit whose warning
/// a client can repeat, shared by the control API's connections. Call
/// sites and limits are fixed in the code, so the map stays small.
#[derive(Debug)]
pub struct CallSites<K> {
    /// The time each line is counted at.
    clock: Arc<dyn Clock>,
    /// The throttle of each call site seen.
    throttles: Mutex<HashMap<K, Throttle>>,
}

impl<K: Eq + Hash> CallSites<K> {
    /// Throttles counting time on `clock`, with no call site seen yet.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            throttles: Mutex::default(),
        }
    }

    /// Counts one line of `site` now: `Some(count)` when it is due,
    /// `count` being the occurrences it covers ([`Throttle::hit`]).
    pub fn hit(&self, site: K) -> Option<u64> {
        let now = self.clock.now();
        self.throttles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(site)
            .or_default()
            .hit(now)
    }
}

/// The text of a line that covers `count` occurrences of `message`, more
/// than one: the message with the count since the last line.
pub fn summary(message: &dyn Display, count: u64) -> String {
    format!("{message} ({count} occurrences since the last line)")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::clock::FakeClock;

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

    #[test]
    fn call_sites_throttle_each_site_on_its_own_and_summarize_with_the_count() {
        let clock = Arc::new(FakeClock::from_system());
        let sites = CallSites::new(clock.clone());
        assert_eq!(sites.hit(1_u32), Some(1));
        assert_eq!(sites.hit(1), None);
        assert_eq!(sites.hit(2), Some(1), "another site");
        clock.advance(SUMMARY_INTERVAL);
        assert_eq!(sites.hit(1), Some(2));
        assert_eq!(
            summary(&"saw unknown rtcp ssrc", 2),
            "saw unknown rtcp ssrc (2 occurrences since the last line)"
        );
    }
}
