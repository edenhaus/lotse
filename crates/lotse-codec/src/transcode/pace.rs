//! Paces the transcoder's packets at their media rate.
//!
//! One AAC frame completes several 20 ms Opus packets at once (3 or 4 at
//! 16 kHz, 6 or 7 at 8 kHz). Published together, they reach the browser
//! in clumps one AAC frame apart, which its jitter buffer reads as heavy
//! jitter and answers by holding more audio: 189–285 ms in Chrome and
//! Safari for a 16 kHz camera on a LAN (2026-10-01), and lip-sync makes
//! video wait for it. The pacer spreads them out instead.
//!
//! It is a token bucket of one packet: a packet goes out at
//! `max(pushed, last release + SPACING)`, so a packet that finds the queue
//! idle leaves at once and a burst leaves one Opus frame (RFC 7587 §4.2,
//! one 20 ms frame per packet) apart. Over time the input equals the
//! output, but not exactly: the camera's audio clock may run fast against
//! ours, a frame that arrives late moves every later release with it, and
//! an ingest stall delivers seconds at once. Two rules bound the backlog,
//! and both release at [`FAST_SPACING`] until the queue has run dry:
//!
//! - **Persistent backlog.** If the queue never held fewer than [`FLOOR`]
//!   packets when a packet arrived during a whole [`WINDOW`], it is not a
//!   burst: bursts drain between frames. A camera on our clock leaves the
//!   queue empty when the next frame arrives.
//! - **Over the limit.** The queue never holds more than [`LIMIT`] packets:
//!   what exceeds it leaves at once. That is an ingest stall, whose packets
//!   the sessions drop as late anyway, and the rest drains at the fast
//!   spacing.
//!
//! The pacer never drops a packet. It is pure: the caller passes the time.
//! Every constant follows from the Opus frame ([`FRAME_DURATION`]), so the
//! frame size can change without the pacer losing its intent: the media
//! rate, a drain a quarter faster, a quarter second of queue.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use lotse_core::track::TrackId;

use crate::opus::FRAME_DURATION;
use lotse_core::throttle::Throttle;

/// The spacing at the media rate: one Opus frame per packet
/// (RFC 7587 §4.2, the encoder's 20 ms frames).
pub(super) const SPACING: Duration = FRAME_DURATION;

/// The spacing while a backlog drains: four fifths of [`SPACING`], 16 ms.
/// Packets leave a quarter faster than the media, so a backlog shrinks by
/// a quarter of the time that passes (250 ms in a second, whatever the
/// frame size), while each packet follows the one before a fifth of a
/// frame (4 ms) sooner than its media does: small against the 64 ms
/// clumps the pacer exists to remove.
pub(super) const FAST_SPACING: Duration = match SPACING.checked_div(5) {
    Some(fifth) => SPACING.saturating_sub(fifth),
    None => SPACING,
};

/// The audio the queue holds before the excess is an ingest stall, not a
/// burst: a quarter second.
const BACKLOG_LIMIT: Duration = Duration::from_millis(250);

/// The most packets the queue holds: [`BACKLOG_LIMIT`] in packets, rounded
/// up, so 13 (260 ms) and never less audio than a quarter second. A camera
/// that sends three 16 kHz AAC frames at once (192 ms, 9 or 10 packets) is
/// smoothed with room for the packet a frame's phase leaves queued; more
/// than this is an ingest stall, not a burst.
pub(super) const LIMIT: usize = BACKLOG_LIMIT.as_micros().div_ceil(SPACING.as_micros()) as usize;

/// The backlog that, kept for a whole [`WINDOW`], is not a burst: one
/// packet. A camera on our clock leaves none queued when its next frame
/// arrives: a frame's 3 packets at 16 kHz (6 at 8 kHz) are out 40 ms
/// (100 ms) after the first, well inside its 64 ms (128 ms), so the
/// queue runs dry before every short frame even after a long one pushed
/// the pace back. A fast camera or a late frame is corrected once a
/// packet (20 ms) is still queued at every frame for a whole window: at
/// 16 kHz once it is more than about 24 ms behind.
pub(super) const FLOOR: usize = 1;

/// How long the queue must keep [`FLOOR`] packets before it drains:
/// longer than any camera's burst period (192 ms for three 16 kHz
/// frames), short enough that a late frame's delay is undone within about
/// a second.
pub(super) const WINDOW: Duration = Duration::from_secs(1);

/// The pacer of one derived track: items pushed in order with the time
/// they were ready, popped in order no earlier than they are due.
#[derive(Debug)]
pub(super) struct Pacer<T> {
    /// The derived track, for the logs.
    track: TrackId,
    /// Each item with the instant it was pushed, oldest first.
    queue: VecDeque<(Instant, T)>,
    /// When the last item was due: the next is due one spacing later.
    /// The due time, not the pop time, so a late wake-up does not slow
    /// the pace.
    last: Option<Instant>,
    /// Whether a backlog is draining at [`FAST_SPACING`].
    fast: bool,
    /// When the current [`WINDOW`] began, at the first push in it.
    window: Option<Instant>,
    /// The smallest queue a push found in the current window.
    low: usize,
    /// Rate-limits the backlog lines: a jittery camera drains often.
    backlogs: Throttle,
    /// Whether the current backlog's start was logged, so its end is too.
    logged: bool,
}

impl<T> Pacer<T> {
    /// An idle pacer for `track`.
    pub(super) fn new(track: TrackId) -> Self {
        Self {
            track,
            queue: VecDeque::new(),
            last: None,
            fast: false,
            window: None,
            low: 0,
            backlogs: Throttle::default(),
            logged: false,
        }
    }

    /// Queues `item`, ready at `now`.
    pub(super) fn push(&mut self, now: Instant, item: T) {
        let before = self.queue.len();
        match self.window {
            Some(start) if now.saturating_duration_since(start) < WINDOW => {
                self.low = self.low.min(before);
            }
            Some(_) => {
                if self.low >= FLOOR {
                    self.speed_up(now, "backlog_persists");
                }
                self.window = Some(now);
                self.low = before;
            }
            None => {
                self.window = Some(now);
                self.low = before;
            }
        }
        self.queue.push_back((now, item));
        if self.queue.len() > LIMIT {
            self.speed_up(now, "over_limit");
        }
    }

    /// When the oldest item is due; `None` when the queue is empty. Over
    /// [`LIMIT`] it is due when it was pushed.
    pub(super) fn next_due(&self) -> Option<Instant> {
        let &(pushed, _) = self.queue.front()?;
        if self.queue.len() > LIMIT {
            return Some(pushed);
        }
        let spacing = if self.fast { FAST_SPACING } else { SPACING };
        let paced = self.last.and_then(|last| last.checked_add(spacing));
        Some(paced.map_or(pushed, |paced| paced.max(pushed)))
    }

    /// The oldest item if it is due at `now`. The queue running dry ends
    /// a fast drain.
    pub(super) fn pop(&mut self, now: Instant) -> Option<T> {
        let due = self.next_due().filter(|due| *due <= now)?;
        let (_, item) = self.queue.pop_front()?;
        self.last = Some(self.last.map_or(due, |last| last.max(due)));
        if self.queue.is_empty() && self.fast {
            self.fast = false;
            if std::mem::take(&mut self.logged) {
                tracing::debug!(
                    track = %self.track,
                    reason = "queue_empty",
                    "transcoder: backlog drained; pacing at the media rate"
                );
            }
        }
        Some(item)
    }

    /// Every queued item, oldest first, regardless of when it is due.
    pub(super) fn drain(&mut self) -> Vec<T> {
        self.queue.drain(..).map(|(_, item)| item).collect()
    }

    /// Starts a fast drain, for `reason`, unless one is running.
    fn speed_up(&mut self, now: Instant, reason: &'static str) {
        if self.fast {
            return;
        }
        self.fast = true;
        if let Some(count) = self.backlogs.hit(now) {
            self.logged = true;
            let queued = u32::try_from(self.queue.len()).unwrap_or(u32::MAX);
            tracing::debug!(
                track = %self.track,
                reason,
                queued_ms = SPACING.saturating_mul(queued).as_millis(),
                count,
                "transcoder: audio backlog; pacing faster"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        clippy::cast_possible_truncation,
        reason = "test code; counts and milliseconds far below 2^32"
    )]

    use lotse_core::clock::{Clock as _, FakeClock};
    use lotse_core::codec::Kind;
    use tracing::Level;

    use super::super::tests::Logs;
    use super::*;
    use lotse_core::throttle::SUMMARY_INTERVAL;

    const STARTED: &str = "transcoder: audio backlog; pacing faster";
    const DRAINED: &str = "transcoder: backlog drained; pacing at the media rate";

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn pacer() -> (Pacer<u32>, Instant) {
        (
            Pacer::new(TrackId::new(Kind::Audio, 1)),
            FakeClock::from_system().now(),
        )
    }

    /// Pushes `count` items numbered from `first`, all at `at`.
    fn burst(pacer: &mut Pacer<u32>, at: Instant, first: u32, count: u32) {
        for n in first..first + count {
            pacer.push(at, n);
        }
    }

    /// Pops everything due by `until`, each at its due time, as
    /// `(item, released ms after t0)`.
    fn run(pacer: &mut Pacer<u32>, t0: Instant, until: Instant) -> Vec<(u32, u64)> {
        let mut out = Vec::new();
        while let Some(due) = pacer.next_due().filter(|due| *due <= until) {
            let item = pacer.pop(due).unwrap();
            out.push((item, (due - t0).as_millis() as u64));
        }
        out
    }

    /// Opus frames per AAC frame of 1024 samples, as a fraction: 3072 / 960
    /// at 16 kHz.
    const AT_16K: (u32, u32) = (16, 5);

    /// 6144 / 960 at 8 kHz.
    const AT_8K: (u32, u32) = (32, 5);

    /// The packets AAC frame `i` completes at `rate` Opus frames per AAC
    /// frame: 3, 3, 3, 3, 4 at 16 kHz, 6, 6, 7, 6, 7 at 8 kHz.
    fn packets(i: u32, (num, den): (u32, u32)) -> u32 {
        (i + 1) * num / den - i * num / den
    }

    /// A camera whose AAC frames complete [`packets`] at `rate`, `frames`
    /// of them, the `i`th pushed at `arrive(i)` ms; returns every release,
    /// popped at its due time, and the most packets a frame found queued.
    fn camera(
        frames: u32,
        rate: (u32, u32),
        arrive: impl Fn(u32) -> u64,
    ) -> (Pacer<u32>, Vec<(u32, u64)>, usize) {
        let (mut pacer, t0) = pacer();
        let mut released = Vec::new();
        let mut next = 0;
        let mut found = 0;
        for i in 0..frames {
            let at = t0 + ms(arrive(i));
            released.extend(run(&mut pacer, t0, at));
            found = found.max(pacer.queue.len());
            let count = packets(i, rate);
            burst(&mut pacer, at, next, count);
            next += count;
        }
        released.extend(run(&mut pacer, t0, t0 + ms(3_600_000)));
        (pacer, released, found)
    }

    /// The largest number of items one release instant carries.
    fn largest_clump(released: &[(u32, u64)]) -> usize {
        released
            .chunk_by(|a, b| a.1 == b.1)
            .map(<[_]>::len)
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn an_idle_queue_releases_at_once() {
        let (mut pacer, t0) = pacer();
        assert_eq!(pacer.next_due(), None);
        assert_eq!(pacer.pop(t0), None);
        pacer.push(t0, 1);
        assert_eq!(pacer.next_due(), Some(t0));
        assert_eq!(pacer.pop(t0), Some(1));
        // Long after the last release, the next one is due when pushed.
        let later = t0 + ms(500);
        pacer.push(later, 2);
        assert_eq!(pacer.next_due(), Some(later));
        assert_eq!(pacer.pop(later), Some(2));
    }

    #[test]
    fn every_constant_follows_from_the_20_ms_opus_frame() {
        assert_eq!(SPACING, ms(20));
        // A quarter faster than the media: 5 packets in the time of 4.
        assert_eq!(FAST_SPACING, ms(16));
        assert_eq!(FAST_SPACING * 5, SPACING * 4);
        // At least a quarter second, by less than one packet.
        assert_eq!(LIMIT, 13);
        assert!(SPACING * LIMIT as u32 >= BACKLOG_LIMIT);
        assert!(SPACING * (LIMIT as u32 - 1) < BACKLOG_LIMIT);
    }

    #[test]
    fn rfc7587_4_2_a_7_packet_burst_leaves_20_ms_apart() {
        let (mut pacer, t0) = pacer();
        burst(&mut pacer, t0, 0, 7);
        assert_eq!(pacer.pop(t0), Some(0));
        // Not before its turn.
        assert_eq!(pacer.next_due(), Some(t0 + SPACING));
        assert_eq!(pacer.pop(t0 + ms(19)), None);
        let released = run(&mut pacer, t0, t0 + ms(1_000));
        assert_eq!(
            released,
            vec![(1, 20), (2, 40), (3, 60), (4, 80), (5, 100), (6, 120)]
        );
        assert_eq!(pacer.next_due(), None);
    }

    #[test]
    fn a_late_wake_up_does_not_slow_the_pace() {
        let (mut pacer, t0) = pacer();
        burst(&mut pacer, t0, 0, 3);
        assert_eq!(pacer.pop(t0), Some(0));
        // Woken 4 ms late: the next is still due 20 ms after the last was.
        assert_eq!(pacer.pop(t0 + ms(24)), Some(1));
        assert_eq!(pacer.next_due(), Some(t0 + ms(40)));
    }

    #[test]
    fn a_camera_on_our_clock_is_paced_without_draining() {
        let (logs, _guard) = Logs::capture();
        // Ten minutes of 16 kHz frames, 64 ms apart, and of 8 kHz frames,
        // 128 ms apart. Steady at the media rate: never faster, never a
        // gap of more than the one a frame's shortest run of packets
        // leaves (3 × 20 ms of 64, 6 × 20 ms of 128).
        for (frames, rate, period, longest) in [(9_375, AT_16K, 64, 24), (4_690, AT_8K, 128, 28)] {
            let (pacer, released, found) = camera(frames, rate, |i| u64::from(i) * period);
            let sent: u32 = (0..frames).map(|i| packets(i, rate)).sum();
            assert_eq!(released.len(), sent as usize);
            assert!(released.iter().enumerate().all(|(i, r)| r.0 == i as u32));
            assert_eq!(largest_clump(&released), 1);
            for pair in released.windows(2) {
                let gap = pair[1].1 - pair[0].1;
                assert!((20..=longest).contains(&gap), "{pair:?}");
            }
            // What FLOOR is set above: the queue is empty at every frame.
            assert_eq!(found, 0, "{period} ms frames");
            assert!(!pacer.fast);
        }
        assert_eq!(logs.count(Level::DEBUG, STARTED), 0);
    }

    #[test]
    fn a_three_frame_camera_burst_is_smoothed_without_a_fast_drain() {
        let (logs, _guard) = Logs::capture();
        // Three 16 kHz frames (9 or 10 packets) at once every 192 ms: 9
        // packets leave 192 − 8 × 20 ms before the next three.
        let (pacer, released, _) = camera(1_500, AT_16K, |i| u64::from(i / 3) * 192);
        assert_eq!(largest_clump(&released), 1);
        for pair in released.windows(2) {
            let gap = pair[1].1 - pair[0].1;
            assert!((20..=32).contains(&gap), "{pair:?}");
        }
        assert!(!pacer.fast);
        assert_eq!(logs.count(Level::DEBUG, STARTED), 0);
    }

    #[test]
    fn a_fast_camera_clock_keeps_a_bounded_backlog() {
        let (logs, _guard) = Logs::capture();
        // 1 % fast: a frame every 63.36 ms instead of 64, for ten minutes.
        let frames = 9_470;
        let arrive = |i: u32| u64::from(i) * 6_336 / 100;
        let (mut pacer, t0) = pacer();
        let mut next = 0;
        let mut worst = 0;
        let mut sent = 0;
        for i in 0..frames {
            let at = t0 + ms(arrive(i));
            sent += run(&mut pacer, t0, at).len();
            let count = packets(i, AT_16K);
            burst(&mut pacer, at, next, count);
            next += count;
            worst = worst.max(pacer.queue.len());
        }
        // Without draining it would hold 6 s. It holds at most a frame on
        // top of the floor and the 10 ms a window adds at 1 %, rounded up
        // to a packet (5 measured, 2026-10-01).
        assert!(worst <= 4 + FLOOR + 1, "worst backlog {worst}");
        assert!(sent + pacer.queue.len() == next as usize, "nothing dropped");
        // Drains are rate-limited in the log: about one line per 10 s.
        let lines = logs.count(Level::DEBUG, STARTED);
        assert!((1..=61).contains(&lines), "{lines} lines");
        assert_eq!(logs.count(Level::DEBUG, DRAINED), lines);
        assert_eq!(
            logs.fields(Level::DEBUG, STARTED)[0][..2],
            [
                "track=a1".to_owned(),
                "reason=\"backlog_persists\"".to_owned()
            ]
        );
    }

    /// When the first packet of each 16 kHz frame left, after the frame,
    /// on our clock but with frame 100 arriving `late` ms late.
    fn first_releases_with_a_late_frame(late: u64) -> impl Fn(u32) -> u64 {
        let (_, released, _) = camera(200, AT_16K, |i| {
            u64::from(i) * 64 + if i == 100 { late } else { 0 }
        });
        move |frame: u32| -> u64 {
            let before: u32 = (0..frame).map(|i| packets(i, AT_16K)).sum();
            released[before as usize].1 - u64::from(frame) * 64
        }
    }

    #[test]
    fn a_late_frame_s_delay_is_undone_within_about_a_window() {
        // The longest a frame's first packet waits after it, over frames
        // 150 to 199: a second and a half after the late one.
        let settled = |first_of: &dyn Fn(u32) -> u64| (150..200).map(first_of).max().unwrap();
        // On our clock, a 4-packet frame pushes the next back by 16 ms.
        assert_eq!(settled(&first_releases_with_a_late_frame(0)), 16);
        // Every later release moves with the late frame, and a packet is
        // left queued at every frame since. Within two windows the drain
        // takes the delay back until the queue runs dry, which leaves less
        // than one packet of it.
        for late in [40, 60] {
            let first_of = first_releases_with_a_late_frame(late);
            assert!(
                first_of(101) >= late - 10,
                "the late frame pushed the next back"
            );
            let left = settled(&first_of) - 16;
            assert!(left < 20, "{late} ms late: {left} ms left");
        }
        // 20 ms late, each 3-packet frame still finds the queue empty, as
        // on our clock: too little to tell from a phase, and it stays.
        assert_eq!(settled(&first_releases_with_a_late_frame(20)), 20);
    }

    #[test]
    fn over_the_limit_the_excess_leaves_at_once_and_the_rest_drains_fast() {
        let (logs, _guard) = Logs::capture();
        let (mut pacer, t0) = pacer();
        // An ingest stall: one second of packets at once.
        burst(&mut pacer, t0, 0, 50);
        let released = run(&mut pacer, t0, t0);
        assert_eq!(released.len(), 50 - LIMIT);
        assert_eq!(pacer.next_due(), Some(t0 + FAST_SPACING));
        // While the camera keeps sending at the media rate, the backlog
        // drains at 16 ms and the pace returns to the media's once it is
        // empty.
        let mut all = released;
        let mut next = 50;
        for i in 1..=30_u32 {
            let at = t0 + ms(u64::from(i) * 64);
            all.extend(run(&mut pacer, t0, at));
            let count = packets(i - 1, AT_16K);
            burst(&mut pacer, at, next, count);
            next += count;
        }
        all.extend(run(&mut pacer, t0, t0 + ms(10_000)));
        assert_eq!(all.len(), next as usize, "nothing dropped");
        assert!(all.iter().enumerate().all(|(i, r)| r.0 == i as u32));
        let gaps: Vec<u64> = all[50 - LIMIT..]
            .windows(2)
            .map(|w| w[1].1 - w[0].1)
            .collect();
        assert!(gaps[..20].iter().all(|gap| *gap == 16), "{gaps:?}");
        assert!(
            gaps[gaps.len() - 10..]
                .iter()
                .all(|gap| (20..=24).contains(gap)),
            "{gaps:?}"
        );
        assert!(!pacer.fast);
        let fields = logs.fields(Level::DEBUG, STARTED);
        assert_eq!(
            fields,
            vec![vec![
                "track=a1".to_owned(),
                "reason=\"over_limit\"".to_owned(),
                "queued_ms=280".to_owned(),
                "count=1".to_owned(),
            ]]
        );
        assert_eq!(
            logs.fields(Level::DEBUG, DRAINED),
            vec![vec![
                "track=a1".to_owned(),
                "reason=\"queue_empty\"".to_owned()
            ]]
        );
    }

    #[test]
    fn the_limit_is_inclusive() {
        let (mut pacer, t0) = pacer();
        pacer.push(t0, 0);
        assert_eq!(pacer.pop(t0), Some(0));
        burst(&mut pacer, t0, 1, LIMIT as u32);
        // Exactly the limit: paced.
        assert_eq!(pacer.next_due(), Some(t0 + SPACING));
        assert!(!pacer.fast);
        pacer.push(t0, 99);
        // One more: the oldest is due at once and the rest drain fast.
        assert_eq!(pacer.next_due(), Some(t0));
        assert!(pacer.fast);
        assert_eq!(pacer.pop(t0), Some(1));
        // The release at once does not move the pace back.
        assert_eq!(pacer.next_due(), Some(t0 + FAST_SPACING));
    }

    #[test]
    fn a_release_over_the_limit_keeps_the_pace_of_the_later_last_release() {
        let (mut pacer, t0) = pacer();
        burst(&mut pacer, t0, 0, 10);
        let now = t0 + ms(40);
        assert_eq!(run(&mut pacer, t0, now).len(), 3);
        // 7 queued; 7 more make 14, and the oldest, pushed at t0, goes.
        burst(&mut pacer, now, 10, 7);
        assert_eq!(pacer.pop(now), Some(3));
        assert_eq!(pacer.next_due(), Some(now + FAST_SPACING));
    }

    #[test]
    fn a_floor_kept_for_a_whole_window_drains_and_one_packet_less_does_not() {
        for (kept, drains) in [(FLOOR, true), (FLOOR - 1, false)] {
            let (mut pacer, t0) = pacer();
            burst(&mut pacer, t0, 0, kept as u32);
            // Nothing is due: the backlog stays.
            pacer.last = Some(t0 + ms(3_600_000));
            // The first window saw the queue empty; the second finds
            // `kept` at every push, judged as the third begins.
            for i in 1..20_u64 {
                pacer.push(t0 + ms(i * 100), 0);
                let _ = pacer.queue.pop_back();
                assert!(!pacer.fast);
            }
            pacer.push(t0 + WINDOW * 2, 0);
            assert_eq!(pacer.fast, drains, "{kept} kept");
        }
    }

    #[test]
    fn the_window_ends_at_exactly_its_length() {
        let (mut pacer, t0) = pacer();
        burst(&mut pacer, t0, 0, FLOOR as u32);
        pacer.last = Some(t0 + ms(3_600_000));
        // A window from t0 that found the floor at every push.
        pacer.low = FLOOR;
        // Just inside the window: still counted in it, no verdict yet.
        pacer.push((t0 + WINDOW).checked_sub(ms(1)).unwrap(), 0);
        assert!(!pacer.fast);
        // At its length: judged, and a new window starts here.
        pacer.push(t0 + WINDOW, 0);
        assert!(pacer.fast);
        assert_eq!(pacer.window, Some(t0 + WINDOW));
        assert_eq!(pacer.low, FLOOR + 1);
    }

    #[test]
    fn a_fast_drain_ends_only_when_the_queue_is_empty() {
        let (mut pacer, t0) = pacer();
        burst(&mut pacer, t0, 0, LIMIT as u32 + 1);
        assert!(pacer.fast);
        let released = run(&mut pacer, t0, t0 + FAST_SPACING * 10);
        assert_eq!(released.len(), 11);
        assert!(pacer.fast, "3 still queued");
        let _ = run(&mut pacer, t0, t0 + ms(1_000));
        assert!(!pacer.fast);
        // A second burst within the summary interval drains quietly.
        let (logs, _guard) = Logs::capture();
        let again = (t0 + SUMMARY_INTERVAL).checked_sub(ms(1)).unwrap();
        burst(&mut pacer, again, 0, LIMIT as u32 + 1);
        let _ = run(&mut pacer, t0, again + ms(1_000));
        assert_eq!(logs.count(Level::DEBUG, STARTED), 0);
        assert_eq!(logs.count(Level::DEBUG, DRAINED), 0);
    }

    #[test]
    fn drain_takes_everything_in_order() {
        let (mut pacer, t0) = pacer();
        burst(&mut pacer, t0, 0, 5);
        assert_eq!(pacer.pop(t0), Some(0));
        assert_eq!(pacer.drain(), vec![1, 2, 3, 4]);
        assert_eq!(pacer.next_due(), None);
    }
}
