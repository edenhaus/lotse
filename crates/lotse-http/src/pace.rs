//! Paces a demultiplexed program at its own time: each unit is sent when
//! as much time has passed since the first unit of the timeline as its
//! decoding time says, so viewers get media at the rate it was made, not
//! at the rate the network delivers whole segments.
//!
//! One clock for the whole program: the 90 kHz decoding time every unit
//! carries (ISO/IEC 13818-1 §2.4.3.7, `DTS`, see [`crate::media::Unit`])
//! is shared by its tracks, so audio and video leave on one base and stay
//! in step without a sync hint. The first unit of a timeline anchors it at
//! the instant it is offered; a unit is due at
//! `anchor + (decode_time - anchor's decode_time)`, computed in
//! nanoseconds with 128-bit arithmetic. A unit that is due or late (a
//! segment that arrived late, a unit from before the anchor) leaves at
//! once and moves nothing: the anchor stays, so the units after it are
//! due on the same base and a late segment is caught up, not carried
//! forward as latency.
//!
//! The pacer re-anchors only when told: at a new epoch, which the caller
//! starts for an `EXT-X-DISCONTINUITY` (RFC 8216 §4.3.2.3) and for a jump
//! of the timestamps. A unit due further ahead than `max_lead` is such a
//! jump, reported as [`Pace::Jump`] instead of waited for: an encoder that
//! restarted, a timeline the container did not mark.
//!
//! Pure: the caller passes the time and holds the units.

use std::time::{Duration, Instant};

use crate::media::TS_CLOCK_RATE;

/// Nanoseconds per second.
const NANOS_PER_SEC: i128 = 1_000_000_000;

/// When to send a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pace {
    /// Now: the first unit of the timeline, or one due or late.
    Now,
    /// At this instant, which lies ahead of the time passed in.
    At(Instant),
    /// Further ahead than the pacer waits: the program's timestamps
    /// jumped. The caller starts a new epoch and offers the unit again.
    Jump {
        /// How far ahead it was due; [`Duration::MAX`] when that does not
        /// fit an instant.
        ahead: Duration,
    },
}

/// Where a timeline began: the decoding time of its first unit and the
/// instant that unit was offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Anchor {
    /// The first unit's decoding time, on the 90 kHz program clock.
    decode_time: i64,
    /// When it was offered.
    at: Instant,
}

impl Anchor {
    /// When a unit with `decode_time` is due.
    fn due(self, decode_time: i64) -> Due {
        let ticks = i128::from(decode_time).saturating_sub(i128::from(self.decode_time));
        if ticks <= 0 {
            return Due::Passed;
        }
        ticks
            .checked_mul(NANOS_PER_SEC)
            .and_then(|nanos| nanos.checked_div(i128::from(TS_CLOCK_RATE)))
            .and_then(|nanos| u64::try_from(nanos).ok())
            .and_then(|nanos| self.at.checked_add(Duration::from_nanos(nanos)))
            .map_or(Due::Beyond, Due::At)
    }
}

/// When a unit is due against an [`Anchor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Due {
    /// At or before the anchor, which has passed.
    Passed,
    /// At this instant.
    At(Instant),
    /// Further ahead than an instant reaches.
    Beyond,
}

/// The pacer of one program.
#[derive(Debug, Clone)]
pub struct Pacer {
    /// How far ahead a unit may be due before it is a jump.
    max_lead: Duration,
    /// The current timeline's start; `None` until its first unit.
    anchor: Option<Anchor>,
}

impl Pacer {
    /// A pacer with no timeline yet, that waits at most `max_lead` for a
    /// unit: the media the caller holds ahead of the live edge, plus the
    /// interleaving of the tracks.
    #[must_use]
    pub const fn new(max_lead: Duration) -> Self {
        Self {
            max_lead,
            anchor: None,
        }
    }

    /// When to send the unit with `decode_time` (90 kHz), offered at
    /// `now`. The first unit of a timeline anchors it and is due now.
    pub fn pace(&mut self, decode_time: i64, now: Instant) -> Pace {
        let Some(anchor) = self.anchor else {
            self.anchor = Some(Anchor {
                decode_time,
                at: now,
            });
            return Pace::Now;
        };
        match anchor.due(decode_time) {
            Due::Passed => Pace::Now,
            Due::Beyond => Pace::Jump {
                ahead: Duration::MAX,
            },
            Due::At(due) => {
                let ahead = due.saturating_duration_since(now);
                if ahead.is_zero() {
                    Pace::Now
                } else if ahead > self.max_lead {
                    Pace::Jump { ahead }
                } else {
                    Pace::At(due)
                }
            }
        }
    }

    /// Forgets the timeline: the next unit anchors a new one. For a new
    /// epoch.
    pub const fn reset(&mut self) {
        self.anchor = None;
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

    const LEAD: Duration = Duration::from_secs(30);

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn iso13818_1_2_4_3_7_units_leave_at_their_decoding_time_after_the_anchor() {
        let t0 = SystemClock.now();
        let mut pacer = Pacer::new(LEAD);
        assert_eq!(pacer.pace(126_000, t0), Pace::Now, "the anchor");
        // 3000 ticks of 90 kHz: 33 333 333 ns, truncated.
        assert_eq!(
            pacer.pace(129_000, t0),
            Pace::At(t0 + Duration::from_nanos(33_333_333))
        );
        assert_eq!(pacer.pace(216_000, t0 + ms(400)), Pace::At(t0 + ms(1_000)));
        // Exactly due is now, as is anything later.
        assert_eq!(pacer.pace(216_000, t0 + ms(1_000)), Pace::Now);
        assert_eq!(pacer.pace(216_000, t0 + ms(1_001)), Pace::Now);
    }

    #[test]
    fn audio_and_video_leave_on_one_base() {
        let t0 = SystemClock.now();
        let mut pacer = Pacer::new(LEAD);
        // Video anchors; audio interleaved a little before it is late,
        // audio after it is due on the same base.
        assert_eq!(pacer.pace(900_000, t0), Pace::Now);
        assert_eq!(pacer.pace(899_000, t0 + ms(1)), Pace::Now);
        assert_eq!(pacer.pace(900_000, t0 + ms(1)), Pace::Now, "the same time");
        assert_eq!(
            pacer.pace(901_920, t0 + ms(1)),
            Pace::At(t0 + ms(21) + Duration::from_nanos(333_333))
        );
        assert_eq!(
            pacer.pace(903_000, t0 + ms(2)),
            Pace::At(t0 + ms(33) + Duration::from_nanos(333_333))
        );
    }

    #[test]
    fn a_late_segment_leaves_at_once_and_keeps_the_anchor() {
        let t0 = SystemClock.now();
        let mut pacer = Pacer::new(LEAD);
        assert_eq!(pacer.pace(0, t0), Pace::Now);
        // A segment of 2 s arrives 5 s in: every unit of it is late.
        for i in 0..20 {
            assert_eq!(pacer.pace(i * 9_000, t0 + ms(5_000)), Pace::Now, "unit {i}");
        }
        // The next is still due on the first anchor, not on the late one.
        assert_eq!(
            pacer.pace(540_000, t0 + ms(5_000)),
            Pace::At(t0 + ms(6_000))
        );
    }

    #[test]
    fn a_unit_further_ahead_than_the_lead_is_a_jump() {
        let t0 = SystemClock.now();
        let mut pacer = Pacer::new(ms(2_000));
        assert_eq!(pacer.pace(0, t0), Pace::Now);
        // Exactly the lead is waited for, more is a jump.
        assert_eq!(pacer.pace(180_000, t0), Pace::At(t0 + ms(2_000)));
        assert_eq!(pacer.pace(180_090, t0), Pace::Jump { ahead: ms(2_001) });
        // Measured from now, not from the anchor.
        assert_eq!(pacer.pace(180_090, t0 + ms(1)), Pace::At(t0 + ms(2_001)));
        // The jump moved nothing: the anchor is the first unit's.
        assert_eq!(pacer.pace(9_000, t0), Pace::At(t0 + ms(100)));
    }

    #[test]
    fn a_unit_beyond_any_instant_is_a_jump_of_unbounded_lead() {
        let t0 = SystemClock.now();
        let mut pacer = Pacer::new(LEAD);
        assert_eq!(pacer.pace(i64::MIN, t0), Pace::Now);
        // 2^64 ticks: more nanoseconds than a u64 holds.
        assert_eq!(
            pacer.pace(i64::MAX, t0),
            Pace::Jump {
                ahead: Duration::MAX
            }
        );
    }

    #[test]
    fn a_reset_anchors_the_next_unit() {
        let t0 = SystemClock.now();
        let mut pacer = Pacer::new(LEAD);
        assert_eq!(pacer.pace(0, t0), Pace::Now);
        pacer.reset();
        // An hour back is the new anchor, not a late unit.
        assert_eq!(pacer.pace(-324_000_000, t0 + ms(10)), Pace::Now);
        assert_eq!(
            pacer.pace(-324_000_000 + 9_000, t0 + ms(10)),
            Pace::At(t0 + ms(110))
        );
    }
}
