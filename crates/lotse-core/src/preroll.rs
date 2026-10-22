//! The pre-roll ring of a [`Track`](crate::track::Track): the last stretch
//! of its frames, held in memory while a window is set, so a clip can start
//! before the moment it was asked for.
//!
//! Invariants: the ring holds the `Arc`s the track publishes and copies no
//! payload. A video ring holds whole GOPs: it starts at a keyframe and
//! drops a GOP at a time (the keyframe through the frame before the next
//! keyframe), so whatever it hands out starts decodable. At each keyframe
//! it starts again at the newest keyframe at least the window before it,
//! so it keeps the window plus the open GOP; at any frame it drops its
//! oldest GOPs while it would hold more than `preroll_bytes`. A GOP that
//! alone outgrows `preroll_bytes` keeps its keyframe and the frames that
//! fit, drops the rest until the next keyframe and is counted; a keyframe
//! itself is bounded only by `max_frame_bytes`, as in the GOP cache. An
//! audio ring follows the video: it keeps the newest frame at or before
//! the video ring's oldest keyframe and everything after it (by its own
//! window while the video ring holds nothing), and drops its oldest frames
//! while it holds more than `preroll_bytes`, down to the newest one. Every
//! frame is charged its payload plus [`PREROLL_FRAME_OVERHEAD`], so a
//! camera sending tiny frames cannot hold more memory than the bound says.
//! Every trim drops a prefix in one pass that stops where the kept frames
//! begin, so it costs what it drops.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::media::MediaFrame;
use crate::throttle::Throttle;

/// What a held frame costs beyond its payload: the `MediaFrame` and its
/// `Arc` counts, which the ring keeps alive after every other holder has
/// let go, and the ring's slot.
pub const PREROLL_FRAME_OVERHEAD: usize = size_of::<MediaFrame>()
    .saturating_add(2_usize.saturating_mul(size_of::<usize>()))
    .saturating_add(size_of::<Arc<MediaFrame>>());

/// What `frame` counts against `preroll_bytes`.
fn cost(frame: &MediaFrame) -> usize {
    frame.payload.len().saturating_add(PREROLL_FRAME_OVERHEAD)
}

/// A pre-roll ring's state, as a track reports it while a window is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrerollStats {
    /// What the held frames count against `preroll_bytes`: their payload
    /// plus [`PREROLL_FRAME_OVERHEAD`] each. A video ring shares its open
    /// GOP with the GOP cache, so the two overlap.
    pub bytes: u64,
    /// The capture time from the oldest held frame (a keyframe, on video)
    /// to the newest: how far back a clip can start now.
    pub held: Duration,
    /// GOPs that alone outgrew `preroll_bytes`, so only their start was
    /// held, over the track's life.
    pub truncations: u64,
}

/// A copy of a ring's frames from a chosen start to the newest: the
/// pre-roll a clip begins with. Holds the frames, not the ring, so the
/// track keeps publishing while the clip reads it.
pub struct PrerollSnapshot {
    /// The first frame: a keyframe on video.
    start: Arc<MediaFrame>,
    /// The frames after `start`, in the order the track published them.
    following: Vec<Arc<MediaFrame>>,
    /// The ring stopped holding the newest GOP because it outgrew
    /// `preroll_bytes`: the live frames after the snapshot's last one are
    /// not the next of its GOP, so a reader resumes at the next keyframe.
    truncated: bool,
}

impl PrerollSnapshot {
    /// The first frame: on video the chosen keyframe.
    pub const fn start(&self) -> &Arc<MediaFrame> {
        &self.start
    }

    /// Every frame, `start` first, in the order the track published them.
    pub fn frames(&self) -> impl Iterator<Item = &Arc<MediaFrame>> {
        std::iter::once(&self.start).chain(&self.following)
    }

    /// Frames held, `start` included.
    pub const fn frame_count(&self) -> usize {
        self.following.len().saturating_add(1)
    }

    /// Whether the newest GOP was cut short by `preroll_bytes`, so the
    /// frames after the last one held are missing.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// How old `start` is at `now`, by its capture time, but at least as
    /// old as its arrival makes it, as [`GopSnapshot::age`](crate::track::GopSnapshot::age)
    /// counts: how far before `now` a clip from it starts.
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.start.wallclock.min(self.start.arrival))
    }
}

impl fmt::Debug for PrerollSnapshot {
    /// A summary: the frames themselves would be the whole pre-roll.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrerollSnapshot")
            .field("start_ts", &self.start.ts)
            .field("frames", &self.frame_count())
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// The capture time of the oldest keyframe a connection's leading video
/// ring holds, which its audio rings trim by. Shared by every track of the
/// connection; written by the video track's source task, read by the audio
/// tracks', so the lock is never held for more than a copy.
#[derive(Debug, Default)]
pub(crate) struct PrerollFloor(Mutex<Option<Instant>>);

impl PrerollFloor {
    /// The oldest keyframe held, `None` while the video ring holds nothing.
    pub(crate) fn get(&self) -> Option<Instant> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records the video ring's oldest keyframe.
    pub(crate) fn set(&self, oldest: Option<Instant>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = oldest;
    }
}

/// A GOP outgrew the ring and a log line is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Truncation {
    /// What the GOP would have counted with the frame that did not fit.
    pub(crate) gop_bytes: usize,
    /// GOPs truncated since the last line.
    pub(crate) count: u64,
}

/// One track's ring. Written only by the track's source task, under the
/// track's lock.
#[derive(Debug)]
pub(crate) struct Preroll {
    /// A video ring, trimmed by whole GOPs; else an audio ring.
    video: bool,
    /// How far back to hold; `None` holds nothing and frees the ring.
    window: Option<Duration>,
    /// The held frames, oldest first; a keyframe first on video.
    frames: VecDeque<Arc<MediaFrame>>,
    /// What `frames` counts against `preroll_bytes`.
    bytes: usize,
    /// The newest GOP outgrew `preroll_bytes`; its frames are dropped
    /// until the next keyframe. Meaningless while nothing is held: only a
    /// keyframe starts an empty ring, and it resets this.
    truncated: bool,
    /// See [`PrerollStats::truncations`].
    truncations: u64,
    /// Rate-limits the line of a truncation, which a camera with GOPs
    /// larger than the bound hits on every GOP.
    truncation_log: Throttle,
}

impl Preroll {
    /// An empty ring without a window.
    pub(crate) fn new(video: bool) -> Self {
        Self {
            video,
            window: None,
            frames: VecDeque::new(),
            bytes: 0,
            truncated: false,
            truncations: 0,
            truncation_log: Throttle::default(),
        }
    }

    /// The window held, `None` without one.
    pub(crate) const fn window(&self) -> Option<Duration> {
        self.window
    }

    /// Sets the window: `None` frees the ring at once; a longer one fills
    /// forward from now; a shorter one trims at the next frame that trims
    /// (a keyframe, on video). Returns what it was.
    pub(crate) fn set_window(&mut self, window: Option<Duration>) -> Option<Duration> {
        if window.is_none() {
            self.frames = VecDeque::new();
            self.bytes = 0;
        }
        std::mem::replace(&mut self.window, window)
    }

    /// Drops every held frame and keeps the window and the allocation,
    /// for a codec change nothing before can share a clip with. Returns
    /// whether anything was held.
    pub(crate) fn clear(&mut self) -> bool {
        let held = !self.frames.is_empty();
        self.frames.clear();
        self.bytes = 0;
        held
    }

    /// The capture time of the oldest held frame: a keyframe, on video.
    pub(crate) fn oldest(&self) -> Option<Instant> {
        self.frames.front().map(|frame| frame.wallclock)
    }

    /// Takes `frame`, just published, and trims; `floor` is asked, on an
    /// audio ring only, for the video ring's oldest keyframe. Nothing
    /// without a window. `Some` when a GOP outgrew `cap` and its line is
    /// due.
    pub(crate) fn push(
        &mut self,
        frame: &Arc<MediaFrame>,
        cap: usize,
        floor: impl FnOnce() -> Option<Instant>,
    ) -> Option<Truncation> {
        let window = self.window?;
        if self.video {
            self.push_video(frame, window, cap)
        } else {
            self.push_audio(frame, window, cap, floor());
            None
        }
    }

    /// [`Self::push`] on a video ring.
    fn push_video(
        &mut self,
        frame: &Arc<MediaFrame>,
        window: Duration,
        cap: usize,
    ) -> Option<Truncation> {
        let cost = cost(frame);
        if frame.keyframe {
            self.truncated = false;
            self.append(frame, cost);
            let start = self.window_start(frame.wallclock, window);
            self.drop_front(start);
            let start = self.fitting_start(cap, 0);
            self.drop_front(start);
            return None;
        }
        // Before the first keyframe there is nothing a clip could start
        // from; after a truncation, nothing until the next.
        if self.frames.is_empty() || self.truncated {
            return None;
        }
        let start = self.fitting_start(cap, cost);
        self.drop_front(start);
        let gop_bytes = self.bytes.saturating_add(cost);
        if gop_bytes > cap {
            self.truncated = true;
            self.truncations = self.truncations.saturating_add(1);
            return self
                .truncation_log
                .hit(frame.wallclock)
                .map(|count| Truncation { gop_bytes, count });
        }
        self.append(frame, cost);
        None
    }

    /// [`Self::push`] on an audio ring: keeps the newest frame at or
    /// before `floor`, or before the window without one, and what follows.
    fn push_audio(
        &mut self,
        frame: &Arc<MediaFrame>,
        window: Duration,
        cap: usize,
        floor: Option<Instant>,
    ) {
        self.append(frame, cost(frame));
        let stale = floor
            .or_else(|| frame.wallclock.checked_sub(window))
            .map_or(0, |floor| {
                self.frames
                    .iter()
                    .skip(1)
                    .take_while(|next| next.wallclock <= floor)
                    .count()
            });
        self.drop_front(stale);
        let start = self.fitting_start(cap, 0);
        self.drop_front(start);
    }

    /// Whether a clip can start at `frame`: a keyframe, or any audio
    /// frame, whatever its source marked it.
    fn starts_at(&self, frame: &MediaFrame) -> bool {
        frame.keyframe || !self.video
    }

    /// Holds `frame`, which counts `cost`.
    fn append(&mut self, frame: &Arc<MediaFrame>, cost: usize) {
        self.frames.push_back(Arc::clone(frame));
        self.bytes = self.bytes.saturating_add(cost);
    }

    /// Drops the `count` oldest frames.
    fn drop_front(&mut self, count: usize) {
        for frame in self.frames.drain(..count.min(self.frames.len())) {
            self.bytes = self.bytes.saturating_sub(cost(&frame));
        }
    }

    /// Where the ring starts once whole GOPs older than `window` before
    /// `newest` are gone: the newest keyframe at least `window` before
    /// it, else the oldest. Stops at the first younger keyframe, so it
    /// costs what it drops and one GOP.
    fn window_start(&self, newest: Instant, window: Duration) -> usize {
        self.frames
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, frame)| frame.keyframe)
            .take_while(|(_, frame)| newest.saturating_duration_since(frame.wallclock) >= window)
            .last()
            .map_or(0, |(index, _)| index)
    }

    /// Where the ring starts so that what it holds, plus `extra`, fits in
    /// `cap`: the oldest start that fits, else the newest start, which is
    /// always kept. Stops at the first start that fits, so it costs what
    /// it drops.
    fn fitting_start(&self, cap: usize, extra: usize) -> usize {
        let mut dropped = 0_usize;
        let mut start = 0;
        for (index, frame) in self.frames.iter().enumerate() {
            if self.starts_at(frame) {
                start = index;
                if self.bytes.saturating_sub(dropped).saturating_add(extra) <= cap {
                    break;
                }
            }
            dropped = dropped.saturating_add(cost(frame));
        }
        start
    }

    /// The held frames from the newest keyframe captured at or before
    /// `target` to the newest frame, or from the oldest when every
    /// keyframe is later; `None` when nothing is held. Every audio frame
    /// is a start, so an audio ring starts at the frame playing at
    /// `target`.
    pub(crate) fn snapshot(&self, target: Instant) -> Option<PrerollSnapshot> {
        let from = self
            .frames
            .iter()
            .rposition(|frame| self.starts_at(frame) && frame.wallclock <= target)
            .unwrap_or(0);
        let mut frames = self.frames.range(from..).cloned();
        let start = frames.next()?;
        Some(PrerollSnapshot {
            start,
            following: frames.collect(),
            truncated: self.truncated,
        })
    }

    /// The ring's state; `None` without a window.
    pub(crate) fn stats(&self) -> Option<PrerollStats> {
        self.window?;
        let held = match (self.frames.front(), self.frames.back()) {
            (Some(oldest), Some(newest)) => {
                newest.wallclock.saturating_duration_since(oldest.wallclock)
            }
            _ => Duration::ZERO,
        };
        Some(PrerollStats {
            bytes: u64::try_from(self.bytes).unwrap_or(u64::MAX),
            held,
            truncations: self.truncations,
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

    use bytes::Bytes;

    use super::*;
    use crate::clock::{Clock as _, SystemClock};
    use crate::media::MediaTime;

    /// What a frame of `bytes` payload counts.
    const fn c(bytes: usize) -> usize {
        bytes + PREROLL_FRAME_OVERHEAD
    }

    /// Frames are labelled by their capture time: `ts` is the
    /// milliseconds after the test's start, which is also how far after it
    /// they were captured.
    struct Clip {
        t0: Instant,
    }

    impl Clip {
        fn new() -> Self {
            Self {
                t0: SystemClock.now(),
            }
        }

        fn at(&self, ms: u64) -> Instant {
            self.t0 + Duration::from_millis(ms)
        }

        fn frame(&self, ms: u64, keyframe: bool, bytes: usize) -> Arc<MediaFrame> {
            Arc::new(MediaFrame {
                ts: MediaTime::from_ticks(i64::try_from(ms).unwrap()),
                wallclock: self.at(ms),
                arrival: self.at(ms),
                keyframe,
                discontinuity: false,
                epoch: 0,
                payload: Bytes::from(vec![0; bytes]),
            })
        }
    }

    fn ring(video: bool, window_ms: u64) -> Preroll {
        let mut ring = Preroll::new(video);
        assert_eq!(
            ring.set_window(Some(Duration::from_millis(window_ms))),
            None
        );
        ring
    }

    /// The held frames' labels, oldest first.
    fn held(ring: &Preroll) -> Vec<i64> {
        ring.frames.iter().map(|frame| frame.ts.ticks()).collect()
    }

    /// Pushes a video GOP: a keyframe at `from` and frames every 250 ms
    /// up to, not including, `to`.
    fn gop(ring: &mut Preroll, clip: &Clip, from: u64, to: u64, cap: usize) {
        for ms in (from..to).step_by(250) {
            assert_eq!(
                ring.push(&clip.frame(ms, ms == from, 10), cap, || None),
                None
            );
        }
    }

    #[test]
    fn a_video_ring_drops_whole_gops_once_the_second_keyframe_is_a_window_old() {
        let clip = Clip::new();
        let mut ring = ring(true, 2000);
        gop(&mut ring, &clip, 0, 1000, usize::MAX);
        gop(&mut ring, &clip, 1000, 2000, usize::MAX);
        gop(&mut ring, &clip, 2000, 3000, usize::MAX);
        assert_eq!(
            held(&ring).first(),
            Some(&0),
            "the second keyframe is a GOP short of the window"
        );
        gop(&mut ring, &clip, 3000, 4000, usize::MAX);
        assert_eq!(
            held(&ring),
            (1000..4000).step_by(250).collect::<Vec<_>>(),
            "the first GOP went whole; the window plus the open GOP is held"
        );
        assert_eq!(ring.oldest(), Some(clip.at(1000)));
        let stats = ring.stats().unwrap();
        assert_eq!(stats.held, Duration::from_millis(2750));
        assert_eq!(stats.bytes, u64::try_from(12 * c(10)).unwrap());
        assert_eq!(stats.truncations, 0);

        // Two GOPs at once: a keyframe captured far later. The newest
        // keyframe at least a window before it stays, with its GOP.
        assert_eq!(
            ring.push(&clip.frame(9000, true, 10), usize::MAX, || None),
            None
        );
        assert_eq!(held(&ring), [3000, 3250, 3500, 3750, 9000]);
    }

    #[test]
    fn a_video_ring_holds_nothing_before_its_first_keyframe_or_without_a_window() {
        let clip = Clip::new();
        let mut ring = Preroll::new(true);
        assert_eq!(
            ring.push(&clip.frame(0, true, 10), usize::MAX, || None),
            None
        );
        assert!(held(&ring).is_empty(), "no window");
        assert_eq!(ring.stats(), None);
        assert_eq!(ring.window(), None);

        let mut ring = self::ring(true, 1000);
        assert_eq!(
            ring.push(&clip.frame(0, false, 10), usize::MAX, || None),
            None
        );
        assert!(held(&ring).is_empty(), "nothing to start a clip from");
        assert_eq!(ring.oldest(), None);
        assert_eq!(
            ring.stats(),
            Some(PrerollStats::default()),
            "a window with nothing held yet"
        );
        assert!(ring.snapshot(clip.at(0)).is_none());
        gop(&mut ring, &clip, 40, 600, usize::MAX);
        assert_eq!(held(&ring).first(), Some(&40));
    }

    #[test]
    fn the_byte_cap_drops_the_oldest_gops_and_keeps_the_newest() {
        let clip = Clip::new();
        let mut ring = ring(true, 60_000);
        let cap = 5 * c(10);
        gop(&mut ring, &clip, 0, 750, cap);
        gop(&mut ring, &clip, 750, 1250, cap);
        assert_eq!(
            held(&ring),
            [0, 250, 500, 750, 1000],
            "exactly the cap fits"
        );
        assert_eq!(ring.push(&clip.frame(1250, false, 10), cap, || None), None);
        assert_eq!(held(&ring), [750, 1000, 1250], "a GOP went, not a frame");
        // A keyframe over the cap drops the GOPs before it.
        assert_eq!(
            ring.push(&clip.frame(1500, true, 3 * c(10)), cap, || None),
            None
        );
        assert_eq!(held(&ring), [1500]);
        assert_eq!(
            ring.stats().unwrap().bytes,
            u64::try_from(3 * c(10) + PREROLL_FRAME_OVERHEAD).unwrap()
        );
        assert_eq!(
            ring.stats().unwrap().truncations,
            0,
            "trimming is not truncating"
        );
        // A keyframe alone larger than the cap is still held.
        assert_eq!(
            ring.push(&clip.frame(1750, true, 2 * cap), cap, || None),
            None
        );
        assert_eq!(held(&ring), [1750]);

        // A keyframe that brings the ring to exactly the cap drops nothing.
        let mut ring = self::ring(true, 60_000);
        for ms in [0, 250] {
            assert_eq!(
                ring.push(&clip.frame(ms, true, 10), 2 * c(10), || None),
                None
            );
        }
        assert_eq!(held(&ring), [0, 250]);
    }

    #[test]
    fn a_gop_larger_than_the_cap_keeps_its_start_and_is_counted_once() {
        let clip = Clip::new();
        let mut ring = ring(true, 60_000);
        let cap = 3 * c(10);
        gop(&mut ring, &clip, 0, 750, cap);
        assert_eq!(
            ring.push(&clip.frame(750, false, 10), cap, || None),
            Some(Truncation {
                gop_bytes: 4 * c(10),
                count: 1
            })
        );
        assert_eq!(
            ring.push(&clip.frame(1000, false, 10), cap, || None),
            None,
            "the rest of the GOP is dropped, not counted again"
        );
        assert_eq!(held(&ring), [0, 250, 500]);
        let snapshot = ring.snapshot(clip.at(0)).unwrap();
        assert!(
            snapshot.truncated(),
            "the live frames are not the next ones"
        );
        assert_eq!(snapshot.frame_count(), 3);

        gop(&mut ring, &clip, 1250, 1750, cap);
        assert_eq!(held(&ring), [1250, 1500], "the next keyframe resumes");
        assert!(!ring.snapshot(clip.at(0)).unwrap().truncated());
        assert_eq!(
            ring.push(&clip.frame(1750, false, 2 * c(10)), cap, || None),
            None,
            "a second truncation inside the summary interval is not logged"
        );
        assert_eq!(held(&ring), [1250, 1500]);
        assert_eq!(ring.stats().unwrap().truncations, 2);
    }

    #[test]
    fn an_audio_ring_keeps_the_frame_playing_at_the_video_s_oldest_keyframe() {
        let clip = Clip::new();
        let mut ring = ring(false, 60_000);
        let floor = || Some(clip.at(1000));
        for ms in (0..=1600).step_by(400) {
            assert_eq!(
                ring.push(&clip.frame(ms, false, 10), usize::MAX, floor),
                None
            );
        }
        assert_eq!(held(&ring), [800, 1200, 1600]);
        assert_eq!(
            ring.push(&clip.frame(2000, false, 10), usize::MAX, || Some(
                clip.at(1200)
            )),
            None
        );
        assert_eq!(
            held(&ring),
            [1200, 1600, 2000],
            "a frame captured at the floor starts"
        );
    }

    #[test]
    fn an_audio_ring_without_a_video_keyframe_keeps_its_own_window() {
        let clip = Clip::new();
        let mut ring = ring(false, 1000);
        for ms in (0..=1200).step_by(400) {
            assert_eq!(
                ring.push(&clip.frame(ms, false, 10), usize::MAX, || None),
                None
            );
        }
        assert_eq!(held(&ring), [0, 400, 800, 1200]);
        assert_eq!(
            ring.push(&clip.frame(1600, false, 10), usize::MAX, || None),
            None
        );
        assert_eq!(held(&ring), [400, 800, 1200, 1600]);
        assert_eq!(ring.oldest(), Some(clip.at(400)));
    }

    #[test]
    fn an_audio_ring_keeps_its_newest_frames_within_the_cap() {
        let clip = Clip::new();
        let mut ring = ring(false, 60_000);
        let cap = 2 * c(10);
        for ms in (0..=800).step_by(400) {
            assert_eq!(ring.push(&clip.frame(ms, false, 10), cap, || None), None);
        }
        assert_eq!(held(&ring), [400, 800]);
        assert_eq!(
            ring.push(&clip.frame(1200, false, 3 * cap), cap, || None),
            None
        );
        assert_eq!(held(&ring), [1200], "one frame over the cap is still held");
        assert_eq!(ring.stats().unwrap().truncations, 0);
    }

    #[test]
    fn a_snapshot_starts_at_the_newest_keyframe_at_or_before_the_target_else_the_oldest() {
        let clip = Clip::new();
        let mut ring = ring(true, 60_000);
        for from in [1000, 2000, 3000] {
            gop(&mut ring, &clip, from, from + 1000, usize::MAX);
        }
        let starts = |target: Instant| {
            let snapshot = ring.snapshot(target).unwrap();
            assert!(snapshot.start().keyframe);
            assert_eq!(
                snapshot.frames().count(),
                snapshot.frame_count(),
                "{snapshot:?}"
            );
            assert_eq!(
                snapshot.frames().last().unwrap().ts.ticks(),
                3750,
                "to the newest frame"
            );
            snapshot.start().ts.ticks()
        };
        assert_eq!(starts(clip.at(2500)), 2000);
        assert_eq!(starts(clip.at(2000)), 2000, "at the target counts");
        assert_eq!(starts(clip.at(1999)), 1000);
        assert_eq!(starts(clip.at(500)), 1000, "earlier than held: the oldest");
        assert_eq!(starts(clip.at(60_000)), 3000);
        let snapshot = ring.snapshot(clip.at(2000)).unwrap();
        assert_eq!(snapshot.frame_count(), 8);
        assert_eq!(
            snapshot
                .frames()
                .map(|frame| frame.ts.ticks())
                .collect::<Vec<_>>(),
            (2000..4000).step_by(250).collect::<Vec<_>>()
        );
        assert!(
            Arc::ptr_eq(snapshot.start(), ring.frames.get(4).unwrap()),
            "the ring's frames, not copies"
        );
        assert!(!snapshot.truncated());
        assert_eq!(snapshot.age(clip.at(12_000)), Duration::from_secs(10));
        let text = format!("{snapshot:?}");
        assert!(text.starts_with("PrerollSnapshot {"), "{text}");
        assert!(text.contains("start_ts: MediaTime(2000)"), "{text}");
        assert!(text.contains("frames: 8"), "{text}");
        assert!(text.contains("truncated: false"), "{text}");
    }

    #[test]
    fn a_snapshot_s_age_never_counts_from_after_the_arrival() {
        let clip = Clip::new();
        let mut ring = ring(true, 60_000);
        // A Sender Report maps the capture an hour ahead of the arrival.
        let frame = Arc::new(MediaFrame {
            wallclock: clip.at(3_600_000),
            ..(*clip.frame(1000, true, 10)).clone()
        });
        assert_eq!(ring.push(&frame, usize::MAX, || None), None);
        let snapshot = ring.snapshot(clip.at(0)).unwrap();
        assert_eq!(snapshot.age(clip.at(3000)), Duration::from_secs(2));
    }

    #[test]
    fn an_audio_snapshot_starts_with_the_frame_playing_at_the_target() {
        let clip = Clip::new();
        let mut ring = ring(false, 60_000);
        for ms in (0..=1600).step_by(400) {
            assert_eq!(
                ring.push(&clip.frame(ms, false, 10), usize::MAX, || None),
                None
            );
        }
        let snapshot = ring.snapshot(clip.at(1000)).unwrap();
        assert_eq!(
            snapshot
                .frames()
                .map(|frame| frame.ts.ticks())
                .collect::<Vec<_>>(),
            [800, 1200, 1600]
        );
    }

    #[test]
    fn removing_the_window_frees_the_ring_and_clearing_keeps_the_window() {
        let clip = Clip::new();
        let mut ring = ring(true, 1000);
        gop(&mut ring, &clip, 0, 1000, usize::MAX);
        assert!(ring.clear(), "frames were held");
        assert!(held(&ring).is_empty());
        assert_eq!(ring.stats(), Some(PrerollStats::default()));
        assert!(!ring.clear(), "nothing held");
        assert_eq!(ring.window(), Some(Duration::from_secs(1)));

        // A truncated GOP: the keyframe after clearing starts afresh.
        gop(&mut ring, &clip, 1000, 1500, usize::MAX);
        assert!(
            ring.push(&clip.frame(1500, false, 10), c(10), || None)
                .is_some()
        );
        assert!(ring.clear());
        assert_eq!(
            ring.push(&clip.frame(1750, false, 10), usize::MAX, || None),
            None
        );
        assert!(held(&ring).is_empty(), "no keyframe since the clear");
        gop(&mut ring, &clip, 2000, 2500, usize::MAX);
        assert_eq!(held(&ring), [2000, 2250]);

        assert_eq!(
            ring.set_window(Some(Duration::from_secs(2))),
            Some(Duration::from_secs(1))
        );
        assert_eq!(held(&ring), [2000, 2250], "a new window keeps what is held");
        assert_eq!(ring.set_window(None), Some(Duration::from_secs(2)));
        assert!(held(&ring).is_empty());
        assert_eq!(ring.frames.capacity(), 0, "the allocation is freed");
        assert_eq!(ring.stats(), None);
        assert!(ring.snapshot(clip.at(0)).is_none());
    }

    #[test]
    fn a_frame_costs_its_payload_and_a_fixed_overhead() {
        assert!(PREROLL_FRAME_OVERHEAD > size_of::<MediaFrame>());
        let clip = Clip::new();
        assert_eq!(cost(&clip.frame(0, true, 7)), 7 + PREROLL_FRAME_OVERHEAD);
    }

    #[test]
    fn the_floor_holds_what_was_set_last() {
        let floor = PrerollFloor::default();
        assert_eq!(floor.get(), None);
        let at = SystemClock.now();
        floor.set(Some(at));
        assert_eq!(floor.get(), Some(at));
        floor.set(None);
        assert_eq!(floor.get(), None);
    }
}
