//! Ingest lateness: how late each frame of a track arrived compared with
//! the track's recent best, so live sessions can skip what an ingest stall
//! delivered late while the side branch keeps everything.
//!
//! A frame's transit is its arrival minus its RTP timestamp in the track's
//! declared clock (RFC 3550 §5.1), both counted from the epoch's first
//! frame; the baseline is the smallest transit of the last 5 to 10 s (two
//! buckets), and lateness is transit minus baseline, less the time the
//! frame spent queued behind the frames before it. No Sender Reports are
//! needed: a camera clock 0.1 % off its declared rate moves the transit by
//! at most 10 ms over the window. Every packet of a frame gets the lateness
//! of the frame's first packet, so a keyframe spread over a slow link is
//! never cut in half.
//!
//! The queue: a camera's link delivers in order, so a frame cannot arrive
//! before the frames ahead of it have. A keyframe that takes 300 ms to
//! arrive delays the frames captured meanwhile by as much, though nothing
//! stalled (the Reolink Duo 3's 1.4 MB IDR pictures, 2026-10-03: Chrome
//! got only the keyframes, because every first frame after one counted as
//! late). The meter carries the backlog the frames' own transfer explains,
//! a Lindley recurrence: a frame's backlog is the previous one's, plus how
//! long the previous frame took to arrive, minus the media time between
//! them, never below zero and never above [`QUEUEING_BOUND`]. A stall
//! between frames adds nothing to it, so the frames after a stall are as
//! late as before; a stall inside a frame is excused like its transfer, up
//! to the bound.

use std::time::{Duration, Instant};

use crate::media::TimestampUnwrapper;

/// The span of the min-filtered baseline: two buckets of half of it.
pub const LATENESS_WINDOW: Duration = Duration::from_secs(10);

/// Lateness beyond this is a timestamp jump, not a stall (the stall
/// watchdog reconnects long before): the meter starts over.
pub const LATENESS_REBASE: Duration = Duration::from_secs(10);

/// The most queueing behind earlier frames a frame is excused: a 2 MB
/// keyframe over a link of 16 Mbit/s. A link slower than its stream for
/// longer is a stall.
pub const QUEUEING_BOUND: Duration = Duration::from_secs(1);

/// One bucket of the baseline: half the window.
const BUCKET: Duration = match LATENESS_WINDOW.checked_div(2) {
    Some(half) => half,
    None => LATENESS_WINDOW,
};

/// Nanoseconds per second.
const NANOS_PER_SEC: i128 = 1_000_000_000;

/// One track's lateness meter. Fed every live packet in order by the
/// track; reset when the track starts an epoch.
#[derive(Debug, Clone)]
pub(crate) struct LatenessMeter {
    /// The track's declared ticks per second.
    clock_rate: u32,
    /// Unwraps the RTP timestamps.
    unwrapper: TimestampUnwrapper,
    /// The arrival and unwrapped timestamp transit is counted from.
    anchor: Option<(Instant, i64)>,
    /// The latest arrival measured; an earlier one is not measured.
    last_arrival: Option<Instant>,
    /// When the current bucket began.
    bucket_start: Option<Instant>,
    /// The smallest transit of the current bucket, nanoseconds.
    current_min: i64,
    /// The smallest transit of the previous bucket.
    previous_min: Option<i64>,
    /// The lateness of the frame the latest packets belong to.
    lateness: Duration,
    /// The arrival of the latest packet of any frame.
    last_packet: Option<Instant>,
    /// The current frame's first arrival and unwrapped timestamp.
    frame: Option<(Instant, i64)>,
    /// The current frame's backlog: how long the frames before it held it
    /// up on the link, nanoseconds, within `0..=QUEUEING_BOUND`.
    queued: i64,
}

impl LatenessMeter {
    /// A meter for a track at `clock_rate` ticks per second.
    pub(crate) const fn new(clock_rate: u32) -> Self {
        Self {
            clock_rate,
            unwrapper: TimestampUnwrapper::new(),
            anchor: None,
            last_arrival: None,
            bucket_start: None,
            current_min: 0,
            previous_min: None,
            lateness: Duration::ZERO,
            last_packet: None,
            frame: None,
            queued: 0,
        }
    }

    /// Forgets everything, for a new epoch: its timestamps start afresh.
    pub(crate) fn reset(&mut self) {
        *self = Self::new(self.clock_rate);
    }

    /// The lateness of a packet that arrived at `arrival` with `rtp_ts`;
    /// only a frame's first packet is measured, the rest inherit it.
    pub(crate) fn packet(&mut self, arrival: Instant, rtp_ts: u32, frame_start: bool) -> Duration {
        if frame_start {
            self.lateness = self.measure(arrival, rtp_ts);
        }
        self.last_packet = Some(self.last_packet.map_or(arrival, |last| last.max(arrival)));
        self.lateness
    }

    /// The lateness of a frame's first packet.
    fn measure(&mut self, arrival: Instant, rtp_ts: u32) -> Duration {
        if self.last_arrival.is_some_and(|last| arrival < last) {
            // Arrivals are read times, so this is a replay: nothing to learn.
            return Duration::ZERO;
        }
        self.last_arrival = Some(arrival);
        let ts = self.unwrapper.unwrap(rtp_ts);
        self.queued = self.queued_behind(arrival, ts);
        self.frame = Some((arrival, ts));
        let (anchor_at, anchor_ts) = *self.anchor.get_or_insert((arrival, ts));
        let Some(transit) = self.transit(
            arrival.saturating_duration_since(anchor_at),
            ts.saturating_sub(anchor_ts),
        ) else {
            self.rebase(arrival, ts);
            return Duration::ZERO;
        };
        match self.bucket_start {
            Some(start) if arrival.saturating_duration_since(start) < BUCKET => {
                self.current_min = self.current_min.min(transit);
            }
            Some(_) => {
                self.previous_min = Some(self.current_min);
                self.bucket_start = Some(arrival);
                self.current_min = transit;
            }
            None => {
                self.bucket_start = Some(arrival);
                self.current_min = transit;
            }
        }
        let baseline = self
            .previous_min
            .map_or(self.current_min, |previous| previous.min(self.current_min));
        let late = Duration::from_nanos(transit.abs_diff(baseline));
        if late > LATENESS_REBASE {
            tracing::debug!(
                late_ms = late.as_millis(),
                "lateness beyond the rebase bound; the timestamps jumped"
            );
            self.rebase(arrival, ts);
            return Duration::ZERO;
        }
        late.saturating_sub(Duration::from_nanos(self.queued.unsigned_abs()))
    }

    /// The backlog of a frame starting at `arrival` with timestamp `ts`:
    /// the previous frame's, plus the time that frame took to arrive,
    /// minus the media time between the two, within `0..=QUEUEING_BOUND`.
    fn queued_behind(&self, arrival: Instant, ts: i64) -> i64 {
        let Some((previous_at, previous_ts)) = self.frame else {
            return 0;
        };
        let transfer = self
            .last_packet
            .unwrap_or(arrival)
            .min(arrival)
            .saturating_duration_since(previous_at);
        let Some(transfer_ns) = i128::try_from(transfer.as_nanos()).ok() else {
            return 0;
        };
        let Some(between) = self.nanos(ts.saturating_sub(previous_ts)) else {
            return 0;
        };
        let bound = i128::try_from(QUEUEING_BOUND.as_nanos()).unwrap_or(i128::MAX);
        let queued = i128::from(self.queued)
            .saturating_add(transfer_ns)
            .saturating_sub(between)
            .clamp(0, bound);
        i64::try_from(queued).unwrap_or(0)
    }

    /// Transit in nanoseconds: `elapsed` since the anchor minus `ticks`
    /// since it in the declared clock. `None` without a clock rate or on
    /// overflow.
    fn transit(&self, elapsed: Duration, ticks: i64) -> Option<i64> {
        let media = self.nanos(ticks)?;
        let elapsed = i128::try_from(elapsed.as_nanos()).ok()?;
        i64::try_from(elapsed.checked_sub(media)?).ok()
    }

    /// `ticks` of the declared clock in nanoseconds; `None` without a
    /// clock rate or on overflow.
    fn nanos(&self, ticks: i64) -> Option<i128> {
        i128::from(ticks)
            .checked_mul(NANOS_PER_SEC)?
            .checked_div(i128::from(self.clock_rate))
    }

    /// Counts transit from this frame on.
    fn rebase(&mut self, arrival: Instant, ts: i64) {
        self.anchor = Some((arrival, ts));
        self.bucket_start = None;
        self.previous_min = None;
        self.current_min = 0;
        self.queued = 0;
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

    /// Frames at 30 fps (3000 ticks at 90 kHz), `delay` late each.
    fn feed(
        meter: &mut LatenessMeter,
        t0: Instant,
        frames: std::ops::Range<u32>,
        delay: Duration,
    ) -> Vec<Duration> {
        frames
            .map(|i| meter.packet(t0 + ms(u64::from(i) * 100 / 3) + delay, i * 3_000, true))
            .collect()
    }

    #[test]
    fn frames_on_time_are_not_late() {
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        let late = feed(&mut meter, t0, 0..90, Duration::ZERO);
        assert!(late.iter().all(|l| *l <= ms(1)), "{late:?}");
    }

    #[test]
    fn a_stall_makes_the_burst_after_it_late_then_it_recovers() {
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        let _ = feed(&mut meter, t0, 0..30, Duration::ZERO);
        // Frames 30..45 (500 ms of video) held up, then read in one go.
        let stall_end = t0 + ms(1_500);
        let burst: Vec<_> = (30..45_u32)
            .map(|i| meter.packet(stall_end, i * 3_000, true))
            .collect();
        assert!(burst[0] >= ms(490), "{:?}", burst[0]);
        assert!(
            burst.windows(2).all(|w| w[1] < w[0]),
            "earlier frames are later"
        );
        assert!(burst[14] < ms(40), "{:?}", burst[14]);
        // Back on time.
        let after = feed(&mut meter, t0, 46..60, Duration::ZERO);
        assert!(after.iter().all(|l| *l <= ms(1)), "{after:?}");
    }

    #[test]
    fn packets_of_a_frame_share_its_lateness() {
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        assert_eq!(meter.packet(t0, 0, true), Duration::ZERO);
        // A big keyframe that takes 300 ms to arrive in full.
        assert_eq!(meter.packet(t0 + ms(33), 33 * 90, true), Duration::ZERO);
        assert_eq!(meter.packet(t0 + ms(333), 33 * 90, false), Duration::ZERO);
        // A late frame: its tail is as late as its head. The keyframe's
        // transfer held it up until 333 ms; the rest is a stall.
        let head = meter.packet(t0 + ms(600), 66 * 90, true);
        assert_eq!(head, ms(267));
        assert_eq!(meter.packet(t0 + ms(700), 66 * 90, false), head);
    }

    /// One frame of `packets` packets `spacing` apart, starting at `at`;
    /// the first packet's lateness.
    fn frame(
        meter: &mut LatenessMeter,
        at: Instant,
        ts: u32,
        packets: u32,
        spacing: Duration,
    ) -> Duration {
        let late = meter.packet(at, ts, true);
        for i in 1..packets {
            assert_eq!(meter.packet(at + spacing * i, ts, false), late);
        }
        late
    }

    #[test]
    fn frames_queued_behind_a_slow_keyframe_are_not_late() {
        // The Reolink Duo 3's shape: 20 fps, a keyframe whose 100 packets
        // take 400 ms to arrive; the frames captured meanwhile come right
        // after it, back to back, then the camera is back on its grid.
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        let tick = 4_500; // 50 ms
        for i in 0..20 {
            let late = frame(&mut meter, t0 + ms(50) * i, tick * i, 3, ms(1));
            assert_eq!(late, Duration::ZERO, "frame {i}");
        }
        let k = t0 + ms(1_000);
        assert_eq!(frame(&mut meter, k, tick * 20, 100, ms(4)), Duration::ZERO);
        // Frames 21 to 28 were due during the transfer.
        for i in 21..29_u32 {
            let at = k + ms(400) + ms(2) * (i - 21);
            let late = frame(&mut meter, at, tick * i, 3, Duration::ZERO);
            assert!(late <= ms(20), "frame {i}: {late:?}");
        }
        for i in 29..40_u32 {
            let late = frame(&mut meter, t0 + ms(50) * i, tick * i, 3, ms(1));
            assert_eq!(late, Duration::ZERO, "frame {i}");
        }
        // Without the queue the first of them would be 350 ms late.
        let mut fresh = LatenessMeter::new(90_000);
        assert_eq!(fresh.packet(k, 0, true), Duration::ZERO);
        assert_eq!(fresh.packet(k + ms(400), tick, true), ms(350));
    }

    #[test]
    fn a_stall_after_a_slow_keyframe_is_late_by_the_stall_alone() {
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        assert_eq!(frame(&mut meter, t0, 0, 100, ms(3)), Duration::ZERO);
        // The keyframe ended at 297 ms; the next frame, due at 50 ms,
        // came 300 ms after that.
        assert_eq!(meter.packet(t0 + ms(597), 4_500, true), ms(300));
        // The next, due at 100 ms, still had 197 ms of the keyframe's
        // transfer ahead of it; the rest of its wait is late.
        assert_eq!(meter.packet(t0 + ms(1_400), 9_000, true), ms(1_103));
        // Once the backlog drained, a stall is late by all of it.
        assert_eq!(meter.packet(t0 + ms(2_000), 36_000, true), ms(1_600));
    }

    #[test]
    fn queueing_is_excused_up_to_its_bound() {
        // A link at half the stream's rate: every 50 ms frame takes 100 ms
        // to arrive, and the frames fall behind until the bound is spent.
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        let mut late = Vec::new();
        for i in 0..40_u32 {
            let at = t0 + ms(100) * i;
            late.push(frame(&mut meter, at, 4_500 * i, 2, ms(99)));
        }
        // 1 ms of each 100 is idle: that much is late.
        assert!(late[..21].iter().all(|l| *l <= ms(20)), "{late:?}");
        assert!(late[39] > ms(800), "{late:?}");
        assert!(
            late.windows(2).all(|w| w[1] >= w[0]),
            "lateness only grows: {late:?}"
        );
        // An earlier arrival than the last one (a replay) adds no queue.
        let mut meter = LatenessMeter::new(90_000);
        meter.packet(t0 + ms(100), 0, true);
        meter.packet(t0, 0, false);
        assert_eq!(meter.packet(t0 + ms(150), 4_500, true), Duration::ZERO);
    }

    #[test]
    fn the_baseline_forgets_after_its_window() {
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        // One frame on time sets the baseline; the rest are 200 ms late...
        assert_eq!(meter.packet(t0, 0, true), Duration::ZERO);
        let mut late_frame =
            |media_ms: u32| meter.packet(t0 + ms(u64::from(media_ms) + 200), media_ms * 90, true);
        assert_eq!(late_frame(1_000), ms(200));
        // ...until the on-time frame has left both buckets.
        assert_eq!(
            late_frame(6_000),
            ms(200),
            "second bucket, the first still counts"
        );
        assert_eq!(late_frame(11_000), Duration::ZERO, "gone");
    }

    #[test]
    fn a_timestamp_jump_rebases_instead_of_skipping_forever() {
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        let _ = feed(&mut meter, t0, 0..30, Duration::ZERO);
        // The camera's clock jumps back an hour without a new epoch.
        let back = 90_000_u32.wrapping_sub(90_000 * 3_600);
        assert_eq!(meter.packet(t0 + ms(1_000), back, true), Duration::ZERO);
        assert_eq!(
            meter.packet(t0 + ms(1_033), back + 33 * 90, true),
            Duration::ZERO
        );
        assert_eq!(meter.packet(t0 + ms(1_266), back + 66 * 90, true), ms(200));
        // Exactly at the rebase bound is still a stall.
        assert_eq!(
            meter.packet(t0 + ms(11_099), back + 99 * 90, true),
            LATENESS_REBASE
        );
    }

    #[test]
    fn a_replayed_arrival_and_a_missing_clock_rate_measure_nothing() {
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now() + ms(1_000);
        assert_eq!(meter.packet(t0, 0, true), Duration::ZERO);
        assert_eq!(meter.packet(t0 + ms(500), 33 * 90, true), ms(467));
        assert_eq!(
            meter.packet(t0.checked_sub(ms(500)).unwrap(), 66 * 90, true),
            Duration::ZERO
        );
        assert_eq!(
            meter.packet(t0 + ms(533), 66 * 90, true),
            ms(467),
            "the baseline stayed"
        );
        assert_eq!(meter.transit(Duration::MAX, 0), None);

        let mut meter = LatenessMeter::new(0);
        assert_eq!(meter.packet(t0, 0, true), Duration::ZERO);
        assert_eq!(meter.packet(t0 + ms(500), 3_000, true), Duration::ZERO);
    }

    #[test]
    fn a_reset_starts_the_epoch_afresh() {
        let mut meter = LatenessMeter::new(90_000);
        let t0 = SystemClock.now();
        let _ = meter.packet(t0, 0, true);
        assert_eq!(meter.packet(t0 + ms(400), 33 * 90, true), ms(367));
        meter.reset();
        assert_eq!(meter.packet(t0 + ms(400), 50, true), Duration::ZERO);
        assert_eq!(
            meter.packet(t0 + ms(433), 50 + 33 * 90, true),
            Duration::ZERO
        );
    }
}
