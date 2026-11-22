//! The skew watchdog: audio/video skew measured from the camera's Sender
//! Reports, never from arrival, and what the daemon does when it cannot be
//! held.
//!
//! The [`ClockMapper`](crate::clock_map::ClockMapper) measures, the watchdog
//! decides. A track's *mapping error* is the NTP time its newest Sender
//! Report states (RFC 3550 §6.4.1) minus the NTP time the track's mapping, as
//! slewed and applied, gives that report's RTP timestamp: how far the mapping
//! trails what the camera says now. For a report rejected as contradicting
//! the fit it is the whole residual. Every track adds the same NTP-to-local
//! offset, so the audio error minus the video error is how far apart audio
//! and video captured at the same camera instant land on the local base,
//! which is how the browser plays them by the daemon's Sender Reports.
//! Arrival times never enter it: jitter moves the offset, which is shared,
//! not the errors.
//!
//! Skew beyond [`MAX_SKEW`] at every evaluation for [`SUSTAIN`] is an
//! occurrence: a re-anchor is marked for the next epoch boundary, never
//! applied inside an epoch. Skew still beyond it [`SUSTAIN`] later is the
//! next occurrence. [`MAX_OCCURRENCES`] within [`RECURRENCE_WINDOW`] withdraw
//! audio for as long as the source runs.

use std::time::{Duration, Instant};

/// The most audio may lead or trail video, either way: EBU R37's bound for
/// audio early, the tighter of its two.
pub const MAX_SKEW: Duration = Duration::from_millis(40);

/// How long skew beyond [`MAX_SKEW`] must last to be an occurrence.
pub const SUSTAIN: Duration = Duration::from_secs(5);

/// The window occurrences are counted in.
pub const RECURRENCE_WINDOW: Duration = Duration::from_mins(10);

/// Occurrences within [`RECURRENCE_WINDOW`] that withdraw audio.
pub const MAX_OCCURRENCES: usize = 3;

/// The session warning sent when audio is withdrawn.
pub const AV_SYNC_LOST: &str = "av_sync_lost";

/// Nanoseconds per millisecond, for the logs.
const NANOS_PER_MILLI: i64 = 1_000_000;

/// The watchdog of one source: its state lives in the mapper's, so it is
/// swapped with the mapping it judges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SkewWatchdog {
    /// When skew beyond tolerance was first seen, or last counted as an
    /// occurrence; `None` while within it.
    since: Option<Instant>,
    /// The occurrences within the window, oldest first; at most
    /// [`MAX_OCCURRENCES`].
    occurrences: Vec<Instant>,
    /// An occurrence asked for a re-anchor the next epoch boundary applies.
    reanchor_pending: bool,
    /// Audio is withdrawn; nothing undoes it while the source runs.
    withdrawn: bool,
}

impl SkewWatchdog {
    /// Judges `lead`, how far audio leads video in nanoseconds (negative:
    /// trails), as of `at`, the arrival of the Sender Report that changed
    /// it; `None` when audio and video are not both mapped from Sender
    /// Reports, which ends any skew.
    pub(crate) fn observe(&mut self, at: Instant, lead: Option<i64>) {
        if self.withdrawn {
            return;
        }
        let Some(lead) = lead.filter(|lead| u128::from(lead.unsigned_abs()) > MAX_SKEW.as_nanos())
        else {
            if self.since.take().is_some() {
                tracing::debug!("audio/video skew back within tolerance");
            }
            return;
        };
        let skew_ms = lead.checked_div(NANOS_PER_MILLI).unwrap_or(0);
        let since = *self.since.get_or_insert_with(|| {
            tracing::debug!(skew_ms, "audio/video skew beyond tolerance");
            at
        });
        let sustained = at.saturating_duration_since(since);
        if sustained < SUSTAIN {
            return;
        }
        self.since = Some(at);
        self.occurrences
            .retain(|earlier| at.saturating_duration_since(*earlier) <= RECURRENCE_WINDOW);
        self.occurrences.push(at);
        self.reanchor_pending = true;
        let occurrences = self.occurrences.len();
        if occurrences < MAX_OCCURRENCES {
            let sustained_ms = sustained.as_millis();
            tracing::warn!(
                skew_ms,
                sustained_ms,
                occurrences,
                "audio/video skew sustained beyond tolerance; re-anchoring at the next epoch boundary"
            );
            return;
        }
        self.withdrawn = true;
        let window_s = RECURRENCE_WINDOW.as_secs();
        tracing::warn!(
            skew_ms,
            occurrences,
            window_s,
            "audio/video skew keeps recurring; audio withdrawn from the stream's sessions"
        );
    }

    /// A new epoch began: the mapping starts over, which is the re-anchor
    /// an occurrence asked for, and skew is measured afresh.
    pub(crate) fn epoch_boundary(&mut self) {
        self.since = None;
        if std::mem::take(&mut self.reanchor_pending) {
            tracing::info!(
                "clock mapping re-anchored at the epoch boundary after audio/video skew"
            );
        }
    }

    /// Whether audio is withdrawn.
    pub(crate) const fn withdrawn(&self) -> bool {
        self.withdrawn
    }

    /// Whether a re-anchor waits for the next epoch boundary.
    #[cfg(test)]
    pub(crate) const fn reanchor_pending(&self) -> bool {
        self.reanchor_pending
    }

    /// The occurrences within the window as of the last one.
    #[cfg(test)]
    pub(crate) const fn occurrences(&self) -> usize {
        self.occurrences.len()
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

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// `lead_ms` of audio lead, judged every second from `from` for
    /// `for_ms` (both ends included).
    fn hold(watchdog: &mut SkewWatchdog, from: Instant, for_ms: u64, lead_ms: i64) {
        let mut t = 0;
        while t < for_ms {
            watchdog.observe(from + ms(t), Some(lead_ms * 1_000_000));
            t += 1_000;
        }
        watchdog.observe(from + ms(for_ms), Some(lead_ms * 1_000_000));
    }

    #[test]
    fn ebu_r37_skew_of_39_or_40_ms_is_within_tolerance_however_long() {
        let t0 = FakeClock::default().now();
        for lead in [39, -39, 40, -40] {
            let mut watchdog = SkewWatchdog::default();
            hold(&mut watchdog, t0, 60_000, lead);
            assert_eq!(watchdog, SkewWatchdog::default(), "{lead} ms");
        }
    }

    #[test]
    fn ebu_r37_skew_of_41_ms_sustained_5_s_is_an_occurrence_either_way() {
        let t0 = FakeClock::default().now();
        for lead in [41, -41] {
            let mut watchdog = SkewWatchdog::default();
            hold(&mut watchdog, t0, 5_000, lead);
            assert_eq!(watchdog.occurrences(), 1, "{lead} ms");
            assert!(watchdog.reanchor_pending());
            assert!(!watchdog.withdrawn());
        }
    }

    #[test]
    fn skew_beyond_tolerance_for_4_9_s_is_not_an_occurrence() {
        let t0 = FakeClock::default().now();
        let mut watchdog = SkewWatchdog::default();
        hold(&mut watchdog, t0, 4_900, 41);
        assert_eq!(watchdog.occurrences(), 0);
        assert!(!watchdog.reanchor_pending());
        // Back within tolerance, the next episode starts from zero.
        watchdog.observe(t0 + ms(4_950), Some(0));
        hold(&mut watchdog, t0 + ms(5_000), 4_900, 41);
        assert_eq!(watchdog.occurrences(), 0);
        // So does one whose tracks stopped being mapped from Sender Reports.
        watchdog.observe(t0 + ms(9_950), None);
        hold(&mut watchdog, t0 + ms(10_000), 4_999, 41);
        assert_eq!(watchdog.occurrences(), 0);
    }

    #[test]
    fn skew_that_persists_recurs_every_5_s_and_withdraws_audio_on_the_third() {
        let t0 = FakeClock::default().now();
        let mut watchdog = SkewWatchdog::default();
        hold(&mut watchdog, t0, 10_000, 120);
        assert_eq!(watchdog.occurrences(), 2);
        assert!(!watchdog.withdrawn());
        watchdog.observe(t0 + ms(15_000), Some(120_000_000));
        assert!(watchdog.withdrawn());
        // Nothing undoes it, nor counts any more.
        watchdog.observe(t0 + ms(20_000), Some(0));
        watchdog.epoch_boundary();
        assert!(watchdog.withdrawn());
        assert_eq!(watchdog.occurrences(), 3);
    }

    /// One occurrence at `at`: 5 s of skew ending there, then none.
    fn occurrence(watchdog: &mut SkewWatchdog, at: Instant) {
        watchdog.observe(at.checked_sub(SUSTAIN).unwrap(), Some(50_000_000));
        watchdog.observe(at, Some(50_000_000));
        watchdog.observe(at + ms(1), Some(0));
    }

    #[test]
    fn three_occurrences_within_10_minutes_withdraw_audio() {
        let t0 = FakeClock::default().now() + Duration::from_hours(1);
        let mut watchdog = SkewWatchdog::default();
        occurrence(&mut watchdog, t0);
        occurrence(&mut watchdog, t0 + Duration::from_mins(4));
        assert!(!watchdog.withdrawn());
        // The window holds both ends: exactly 10 minutes counts.
        occurrence(&mut watchdog, t0 + RECURRENCE_WINDOW);
        assert!(watchdog.withdrawn());
    }

    #[test]
    fn three_occurrences_spread_over_11_minutes_do_not_withdraw_audio() {
        let t0 = FakeClock::default().now() + Duration::from_hours(1);
        let mut watchdog = SkewWatchdog::default();
        occurrence(&mut watchdog, t0);
        occurrence(&mut watchdog, t0 + Duration::from_secs(330));
        occurrence(&mut watchdog, t0 + Duration::from_mins(11));
        assert!(!watchdog.withdrawn());
        assert_eq!(watchdog.occurrences(), 2, "the first left the window");
        // Just past the window's end is outside it.
        let mut outside = SkewWatchdog::default();
        occurrence(&mut outside, t0);
        occurrence(&mut outside, t0 + RECURRENCE_WINDOW + ms(1));
        occurrence(&mut outside, t0 + RECURRENCE_WINDOW + ms(2));
        assert!(!outside.withdrawn());
    }

    #[test]
    fn the_re_anchor_waits_for_the_epoch_boundary_which_restarts_the_measurement() {
        let t0 = FakeClock::default().now();
        let mut watchdog = SkewWatchdog::default();
        hold(&mut watchdog, t0, 4_000, 60);
        watchdog.epoch_boundary();
        assert!(!watchdog.reanchor_pending(), "nothing was asked");
        // The skew before the boundary does not count toward the next.
        hold(&mut watchdog, t0 + ms(5_000), 4_000, 60);
        assert_eq!(watchdog.occurrences(), 0);
        watchdog.observe(t0 + ms(10_000), Some(60_000_000));
        assert!(watchdog.reanchor_pending());
        watchdog.epoch_boundary();
        assert!(!watchdog.reanchor_pending());
        assert_eq!(watchdog.occurrences(), 1, "the count spans epochs");
    }
}
