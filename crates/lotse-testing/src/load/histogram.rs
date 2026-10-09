//! A log-linear latency histogram: exact below 32 µs, then 32 buckets per
//! power of two, so a percentile is within 1/32 (3.1 %) of the value it
//! stands for, in memory that does not grow with the run.
//!
//! What a 72-hour soak needs instead of a list of every latency.

use std::time::Duration;

use serde::Serialize;

/// Buckets per power of two, and the exact range below the first one.
const SUB_BUCKETS: u64 = 32;

/// `log2(SUB_BUCKETS)`.
const SUB_BITS: u32 = 5;

/// Microsecond counts, bucketed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Histogram {
    /// Counts per bucket, grown to the largest bucket seen.
    counts: Vec<u64>,
    /// Values recorded.
    total: u64,
    /// The largest value recorded, exact.
    max_us: u64,
}

/// The bucket of `us`.
fn index(us: u64) -> usize {
    let bucket = if us < SUB_BUCKETS {
        us
    } else {
        // `us >= 32`, so the top bit is at least `SUB_BITS`.
        let octave = 63_u32.saturating_sub(us.leading_zeros());
        let shift = octave.saturating_sub(SUB_BITS);
        let mantissa = us.wrapping_shr(shift).saturating_sub(SUB_BUCKETS);
        u64::from(shift.saturating_add(1))
            .saturating_mul(SUB_BUCKETS)
            .saturating_add(mantissa)
    };
    usize::try_from(bucket).unwrap_or(usize::MAX)
}

/// The largest value bucket `index` holds.
fn upper_bound(index: usize) -> u64 {
    let index = u64::try_from(index).unwrap_or(u64::MAX);
    if index < SUB_BUCKETS {
        return index;
    }
    let shift = u32::try_from(index / SUB_BUCKETS)
        .unwrap_or(u32::MAX)
        .saturating_sub(1);
    let lower = (SUB_BUCKETS.saturating_add(index % SUB_BUCKETS))
        .checked_shl(shift)
        .unwrap_or(u64::MAX);
    let width = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    lower.saturating_add(width.saturating_sub(1))
}

impl Histogram {
    /// Records one value.
    pub fn record(&mut self, value: Duration) {
        let us = u64::try_from(value.as_micros()).unwrap_or(u64::MAX);
        let at = index(us);
        if self.counts.len() <= at {
            self.counts.resize(at.saturating_add(1), 0);
        }
        if let Some(count) = self.counts.get_mut(at) {
            *count = count.saturating_add(1);
        }
        self.total = self.total.saturating_add(1);
        self.max_us = self.max_us.max(us);
    }

    /// Adds every value of `other`.
    pub fn merge(&mut self, other: &Self) {
        if self.counts.len() < other.counts.len() {
            self.counts.resize(other.counts.len(), 0);
        }
        for (mine, theirs) in self.counts.iter_mut().zip(&other.counts) {
            *mine = mine.saturating_add(*theirs);
        }
        self.total = self.total.saturating_add(other.total);
        self.max_us = self.max_us.max(other.max_us);
    }

    /// Values recorded.
    pub const fn count(&self) -> u64 {
        self.total
    }

    /// The `p`-th percentile (0–100, nearest rank) as its bucket's upper
    /// bound, never above the largest value; `None` when empty.
    pub fn percentile(&self, p: u32) -> Option<Duration> {
        if self.total == 0 {
            return None;
        }
        let rank = self
            .total
            .saturating_mul(u64::from(p.min(100)))
            .div_ceil(100)
            .max(1);
        let mut seen = 0_u64;
        for (at, count) in self.counts.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= rank {
                return Some(Duration::from_micros(upper_bound(at).min(self.max_us)));
            }
        }
        Some(Duration::from_micros(self.max_us))
    }

    /// p50, p95, p99 and the maximum, in milliseconds.
    pub fn summary(&self) -> Percentiles {
        let ms = |p| self.percentile(p).map(|d| d.as_secs_f64() * 1e3);
        Percentiles {
            count: self.total,
            p50_ms: ms(50),
            p95_ms: ms(95),
            p99_ms: ms(99),
            max_ms: ms(100),
        }
    }
}

/// A distribution's report.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct Percentiles {
    /// Values recorded.
    pub count: u64,
    /// Median.
    pub p50_ms: Option<f64>,
    /// 95th percentile.
    pub p95_ms: Option<f64>,
    /// 99th percentile.
    pub p99_ms: Option<f64>,
    /// Largest.
    pub max_ms: Option<f64>,
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
    fn buckets_are_exact_below_32_us_and_within_a_32nd_above() {
        for us in 0..32 {
            assert_eq!(index(us), usize::try_from(us).unwrap());
            assert_eq!(upper_bound(index(us)), us);
        }
        assert_eq!(index(32), 32);
        assert_eq!(index(63), 63);
        assert_eq!(index(64), 64);
        assert_eq!(upper_bound(64), 65, "64 and 65 share a bucket");
        for us in [100_u64, 1_000, 12_345, 1_000_000, 86_400_000_000, u64::MAX] {
            let upper = upper_bound(index(us));
            assert!(upper >= us, "{us} → {upper}");
            assert!(upper - us <= us / 32, "{us} → {upper}");
            if us < u64::MAX {
                assert!(index(us + 1) >= index(us));
            }
        }
    }

    #[test]
    fn percentiles_are_nearest_rank_and_never_above_the_maximum() {
        let mut h = Histogram::default();
        assert_eq!(h.percentile(50), None);
        assert_eq!(h.summary().p50_ms, None);
        for ms in 1..=100 {
            h.record(Duration::from_millis(ms));
        }
        assert_eq!(h.count(), 100);
        let p50 = h.percentile(50).unwrap();
        assert!(
            p50 >= Duration::from_millis(50) && p50 <= Duration::from_micros(51_600),
            "{p50:?}"
        );
        assert_eq!(h.percentile(100), Some(Duration::from_millis(100)));
        assert_eq!(h.percentile(0), h.percentile(1));
        let one = {
            let mut one = Histogram::default();
            one.record(Duration::from_micros(1_234));
            one
        };
        assert_eq!(one.percentile(99), Some(Duration::from_micros(1_234)));
    }

    #[test]
    fn merging_adds_counts_and_keeps_the_maximum() {
        let mut a = Histogram::default();
        a.record(Duration::from_micros(10));
        let mut b = Histogram::default();
        b.record(Duration::from_millis(5));
        b.record(Duration::from_millis(7));
        a.merge(&b);
        assert_eq!(a.count(), 3);
        assert_eq!(a.percentile(100), Some(Duration::from_millis(7)));
        assert_eq!(a.percentile(1), Some(Duration::from_micros(10)));
        let mut empty = Histogram::default();
        empty.merge(&a);
        assert_eq!(empty, a);
    }
}
