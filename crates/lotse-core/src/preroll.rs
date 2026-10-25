//! The pre-roll ring of a [`Track`](crate::track::Track): the last stretch
//! of its frames, held in memory while a window is set, so a clip can start
//! before the moment it was asked for.
//!
//! Invariants: the ring holds the `Arc`s the track publishes and copies no
//! payload. A video ring holds whole GOPs: it starts at a keyframe and
//! drops a GOP at a time (the keyframe through the frame before the next
//! keyframe), so whatever it hands out starts decodable. At each keyframe
//! it starts again at the newest keyframe that arrived at least the window
//! before it, so it keeps the window plus the open GOP; at any frame it drops its
//! oldest GOPs while it would hold more than `preroll_bytes`. A GOP that
//! alone outgrows `preroll_bytes` keeps its keyframe and the frames that
//! fit, drops the rest and is counted; a GOP that loses a frame the track
//! dropped over `max_frame_bytes` (a keyframe too, whose frames would
//! otherwise follow the GOP before) is cut there the same way, counted by
//! the track. A cut GOP holds nothing after the cut, and the next keyframe
//! drops it with everything before it, so the ring starts again there, no
//! clip spans a gap the track saw unreported, and every GOP held but the
//! newest is whole as the track received it. A unit a source's
//! depacketizer dropped (a packet lost inside it, RFC 6184 §5.8) never
//! reaches the track, so the ring holds what the GOP cache and the live
//! frames hold, and a reader finds that hole in the timestamps as it does
//! in the live frames after the snapshot; a keyframe itself is bounded
//! only by `max_frame_bytes`, as in the GOP cache. An audio ring follows
//! the video: it keeps the newest frame at or before the floor, the oldest
//! capture time of any keyframe the video ring holds (the oldest
//! keyframe's, unless a Sender Report correcting the mapping back dated a
//! later one before it), and everything after it (by its own window, by
//! arrival, while the video ring holds nothing), and drops its oldest
//! frames while it holds more than `preroll_bytes`, down to the newest one.
//! Windows are measured by arrival, which only moves forward on a track,
//! never by capture time, which a camera's Sender Reports can move ahead
//! and back; only the floor, the audio frames trimmed by it and a
//! snapshot's start, which line audio up with video, use capture time, and
//! neither the floor nor an audio frame compared with it counts from after
//! it arrived.
//! Every frame is charged its payload plus [`PREROLL_FRAME_OVERHEAD`], so a
//! camera sending tiny frames cannot hold more memory than the bound says.
//! Every trim drops a prefix in one pass that stops where the kept frames
//! begin, so it costs what it drops, and the floor is kept in amortized
//! O(1) a keyframe.

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

/// When `frame` was captured, but never later than it arrived: a capture
/// time ahead of the arrival is a Sender Report mapping off, which a
/// later report corrects back. Arrival only moves forward on a track, so
/// a frame dated ahead cannot hold back what a trim by it drops.
pub(crate) fn captured(frame: &MediaFrame) -> Instant {
    frame.wallclock.min(frame.arrival)
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
    /// held, over the track's life. A frame the track dropped over
    /// `max_frame_bytes` cuts a GOP short too, but is counted in
    /// [`TrackStats::frames_dropped_oversize`](crate::track::TrackStats::frames_dropped_oversize).
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
    /// `preroll_bytes` or lost a frame the track dropped: the live frames
    /// after the snapshot's last one are not the next of its GOP, so a
    /// reader resumes at the next keyframe.
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

    /// Whether the newest GOP was cut short, by `preroll_bytes` or by a
    /// frame the track dropped over `max_frame_bytes`, so the frames after
    /// the last one held are missing; every GOP before it is whole.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// How old `start` is at `now`, by its capture time, but at least as
    /// old as its arrival makes it, as [`GopSnapshot::age`](crate::track::GopSnapshot::age)
    /// counts: how far before `now` a clip from it starts.
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(captured(&self.start))
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

/// The oldest capture time of any keyframe a connection's leading video
/// ring holds, but never later than its arrival ([`Preroll::oldest`]),
/// which its audio rings trim by. Shared by every track of the connection;
/// written by the video track's source task, read by the audio tracks', so
/// the lock is never held for more than a copy.
#[derive(Debug, Default)]
pub(crate) struct PrerollFloor(Mutex<Option<Instant>>);

impl PrerollFloor {
    /// The video ring's floor, `None` while it holds nothing.
    pub(crate) fn get(&self) -> Option<Instant> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records the video ring's floor ([`Preroll::oldest`]).
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
    /// How far back, by arrival, to hold; `None` holds nothing and frees
    /// the ring.
    window: Option<Duration>,
    /// The held frames, oldest first; a keyframe first on video.
    frames: VecDeque<Arc<MediaFrame>>,
    /// The held keyframes the floor can come from ([`Self::oldest`]),
    /// oldest first, each captured ([`captured`]) before every later one
    /// here: a keyframe enters at the back and evicts those captured at or
    /// after it, and leaves at the front when the ring drops it, so the
    /// front is the keyframe held with the oldest capture time. A keyframe
    /// is evicted at most once, so a frame costs amortized O(1). Empty on
    /// an audio ring.
    floor_keys: VecDeque<Arc<MediaFrame>>,
    /// What `frames` counts against `preroll_bytes`.
    bytes: usize,
    /// The newest GOP outgrew `preroll_bytes` or lost a frame the track
    /// dropped ([`Self::frame_dropped`]); its frames are dropped until
    /// the next keyframe, which drops the GOP too, so no older GOP held
    /// is ever truncated. Meaningless while nothing is held: only a
    /// keyframe starts an empty ring, and it resets this.
    truncated: bool,
    /// See [`PrerollStats::truncations`].
    truncations: u64,
    /// Rate-limits the line of a truncation, which a camera with GOPs
    /// larger than the bound hits on every GOP. Timed by the frames'
    /// arrival, never their capture time, which a camera's Sender Reports
    /// can move hours ahead and back.
    truncation_log: Throttle,
}

impl Preroll {
    /// An empty ring without a window.
    pub(crate) fn new(video: bool) -> Self {
        Self {
            video,
            window: None,
            frames: VecDeque::new(),
            floor_keys: VecDeque::new(),
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

    /// Sets the window, measured by arrival: `None` frees the ring at
    /// once; a longer one fills forward from now; a shorter one trims at
    /// the next frame that trims (a keyframe, on video). Returns what it
    /// was.
    pub(crate) fn set_window(&mut self, window: Option<Duration>) -> Option<Duration> {
        if window.is_none() {
            self.frames = VecDeque::new();
            self.floor_keys = VecDeque::new();
            self.bytes = 0;
        }
        std::mem::replace(&mut self.window, window)
    }

    /// Drops every held frame and keeps the window and the allocation,
    /// for a codec change the held frames cannot be read with. Returns
    /// whether anything was held.
    pub(crate) fn clear(&mut self) -> bool {
        let held = !self.frames.is_empty();
        self.frames.clear();
        self.floor_keys.clear();
        self.bytes = 0;
        held
    }

    /// The oldest capture time of any keyframe held, which the audio rings
    /// trim by ([`PrerollFloor`]): the oldest keyframe's, unless a Sender
    /// Report correcting the mapping back (RFC 3550 §6.4.1) dated a later
    /// one before it, whose audio a clip from it plays as well. Never later
    /// than the keyframe arrived, as [`PrerollSnapshot::age`] counts: a
    /// capture time ahead of the arrival is a mapping off, and as the floor
    /// it would drop the audio a clip from that keyframe plays
    /// ([`captured`]). `None` while nothing is held, and on an audio ring.
    pub(crate) fn oldest(&self) -> Option<Instant> {
        self.floor_keys.front().map(|keyframe| captured(keyframe))
    }

    /// Takes `frame`, just published, and trims; `floor` is asked, on an
    /// audio ring only, for the video ring's floor ([`Self::oldest`]). Nothing
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

    /// The track dropped a frame before the ring saw it (larger than
    /// `max_frame_bytes`). On video, the GOP it belongs to (the one it
    /// would have started, for a keyframe) lacks a frame the ones after
    /// it may reference: the ring holds nothing more of it and starts
    /// again at the next keyframe, as for a GOP outgrowing
    /// `preroll_bytes`, and a snapshot until then reports the cut. Not
    /// counted in [`PrerollStats::truncations`]: the track counts the
    /// frame. An audio ring keeps going, as every audio frame is a start.
    pub(crate) fn frame_dropped(&mut self) {
        if self.video {
            self.truncated = true;
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
            if self.truncated {
                // The truncated GOP lost frames before this keyframe: a
                // clip from its keyframe would skip them, and one from an
                // older keyframe would jump over the gap unreported, so
                // the ring starts again here. (After a cap truncation the
                // cap had already dropped every GOP before it.)
                self.drop_front(self.frames.len());
                self.truncated = false;
            }
            self.append(frame, cost);
            self.push_floor_key(frame);
            let start = self.window_start(frame.arrival, window);
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
                .hit(frame.arrival)
                .map(|count| Truncation { gop_bytes, count });
        }
        self.append(frame, cost);
        None
    }

    /// [`Self::push`] on an audio ring: keeps the newest frame captured at
    /// or before `floor`, a frame dated ahead of its arrival counting by
    /// its arrival as the floor does ([`captured`]), else the newest that
    /// arrived at least the window before this one, and what follows. A
    /// capture time that moves back while behind its arrival still ends the
    /// stale run at the frame before it: the ring holds what follows until
    /// the floor passes that frame or `preroll_bytes` drops it, and a
    /// snapshot still starts at the newest frame captured at or before its
    /// target.
    fn push_audio(
        &mut self,
        frame: &Arc<MediaFrame>,
        window: Duration,
        cap: usize,
        floor: Option<Instant>,
    ) {
        self.append(frame, cost(frame));
        let stale = match floor {
            Some(floor) => self
                .frames
                .iter()
                .skip(1)
                .take_while(|next| captured(next) <= floor)
                .count(),
            None => frame.arrival.checked_sub(window).map_or(0, |cutoff| {
                self.frames
                    .iter()
                    .skip(1)
                    .take_while(|next| next.arrival <= cutoff)
                    .count()
            }),
        };
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

    /// Takes `keyframe`, just held, into `floor_keys`: the keyframes held
    /// before it that were captured at or after it cannot be the oldest
    /// capture time while it is held, so they leave.
    fn push_floor_key(&mut self, keyframe: &Arc<MediaFrame>) {
        let at = captured(keyframe);
        while self
            .floor_keys
            .back()
            .is_some_and(|newer| captured(newer) >= at)
        {
            self.floor_keys.pop_back();
        }
        self.floor_keys.push_back(Arc::clone(keyframe));
    }

    /// Drops the `count` oldest frames, and a keyframe among them from
    /// `floor_keys`: both are in the ring's order, so it is at the front.
    fn drop_front(&mut self, count: usize) {
        for frame in self.frames.drain(..count.min(self.frames.len())) {
            self.bytes = self.bytes.saturating_sub(cost(&frame));
            if self
                .floor_keys
                .front()
                .is_some_and(|keyframe| Arc::ptr_eq(keyframe, &frame))
            {
                self.floor_keys.pop_front();
            }
        }
    }

    /// Where the ring starts once whole GOPs that arrived more than
    /// `window` before `newest` (the newest frame's arrival) are gone: the
    /// newest keyframe that arrived at least `window` before it, else the
    /// oldest. By arrival, which only moves forward on a track, so the
    /// first younger keyframe ends the search: it costs what it drops and
    /// one GOP. A capture time can move back (a Sender Report correcting
    /// the mapping), and one ahead would hold every later keyframe back.
    fn window_start(&self, newest: Instant, window: Duration) -> usize {
        self.frames
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, frame)| frame.keyframe)
            .take_while(|(_, frame)| newest.saturating_duration_since(frame.arrival) >= window)
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

        /// A frame captured `capture` ms after the start and read
        /// `arrival` ms after it, labelled by its arrival.
        fn shifted(&self, capture: u64, arrival: u64, keyframe: bool) -> Arc<MediaFrame> {
            Arc::new(MediaFrame {
                wallclock: self.at(capture),
                ..(*self.frame(arrival, keyframe, 10)).clone()
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
    fn a_truncated_gop_goes_whole_at_the_next_keyframe_even_when_that_fits() {
        let clip = Clip::new();
        let mut ring = ring(true, 60_000);
        let cap = 4 * c(10);
        gop(&mut ring, &clip, 0, 500, cap);
        assert_eq!(
            ring.push(&clip.frame(500, false, 3 * c(10)), cap, || None),
            Some(Truncation {
                gop_bytes: 2 * c(10) + c(3 * c(10)),
                count: 1
            })
        );
        assert_eq!(held(&ring), [0, 250]);
        // The next keyframe fits beside the truncated GOP, which still goes.
        assert_eq!(ring.push(&clip.frame(750, true, 10), cap, || None), None);
        assert_eq!(held(&ring), [750], "no clip may span the lost frame");
        assert_eq!(ring.stats().unwrap().bytes, u64::try_from(c(10)).unwrap());
        let snapshot = ring.snapshot(clip.at(0)).unwrap();
        assert_eq!(snapshot.start().ts.ticks(), 750);
        assert!(!snapshot.truncated());
        assert_eq!(ring.stats().unwrap().truncations, 1);
        assert_eq!(ring.push(&clip.frame(1000, false, 10), cap, || None), None);
        assert_eq!(held(&ring), [750, 1000]);
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
    fn a_dropped_frame_cuts_its_gop_and_the_next_keyframe_starts_the_ring_again() {
        let clip = Clip::new();
        let mut ring = ring(true, 60_000);
        gop(&mut ring, &clip, 0, 1000, usize::MAX);
        gop(&mut ring, &clip, 1000, 1500, usize::MAX);
        // The frame at 1500 never reaches the ring.
        ring.frame_dropped();
        assert_eq!(
            ring.push(&clip.frame(1750, false, 10), usize::MAX, || None),
            None
        );
        assert_eq!(
            held(&ring),
            [0, 250, 500, 750, 1000, 1250],
            "the whole GOPs before the gap stay"
        );
        let snapshot = ring.snapshot(clip.at(0)).unwrap();
        assert!(snapshot.truncated());
        assert_eq!(snapshot.frames().last().unwrap().ts.ticks(), 1250);
        assert_eq!(ring.stats().unwrap().truncations, 0, "counted by the track");
        assert_eq!(ring.oldest(), Some(clip.at(0)), "the floor does not move");

        gop(&mut ring, &clip, 2000, 2500, usize::MAX);
        assert_eq!(held(&ring), [2000, 2250], "the next keyframe restarts");
        assert!(!ring.snapshot(clip.at(0)).unwrap().truncated());

        // A lost keyframe: the frames of its GOP stay out as well.
        ring.frame_dropped();
        assert_eq!(
            ring.push(&clip.frame(3250, false, 10), usize::MAX, || None),
            None
        );
        assert_eq!(held(&ring), [2000, 2250]);
        assert!(ring.snapshot(clip.at(0)).unwrap().truncated());
        assert_eq!(
            ring.push(&clip.frame(4000, true, 10), usize::MAX, || None),
            None
        );
        assert_eq!(held(&ring), [4000]);
        assert!(!ring.snapshot(clip.at(0)).unwrap().truncated());
    }

    #[test]
    fn a_dropped_audio_frame_leaves_the_audio_ring_whole() {
        let clip = Clip::new();
        let mut ring = ring(false, 60_000);
        for ms in [0, 400] {
            assert_eq!(
                ring.push(&clip.frame(ms, false, 10), usize::MAX, || None),
                None
            );
        }
        ring.frame_dropped();
        assert_eq!(
            ring.push(&clip.frame(1200, false, 10), usize::MAX, || None),
            None
        );
        assert_eq!(held(&ring), [0, 400, 1200]);
        assert!(
            !ring.snapshot(clip.at(0)).unwrap().truncated(),
            "every audio frame is a start"
        );
    }

    #[test]
    fn a_truncation_line_is_timed_by_arrival_not_by_the_capture_time() {
        let clip = Clip::new();
        // Ten hours: no keyframe here is ever a window old.
        let mut ring = ring(true, 36_000_000);
        let cap = 2 * c(10);
        let frame =
            |capture: u64, arrival: u64, keyframe: bool| clip.shifted(capture, arrival, keyframe);
        let truncation = Some(Truncation {
            gop_bytes: 3 * c(10),
            count: 1,
        });
        // A Sender Report maps the third frame an hour ahead.
        assert_eq!(ring.push(&frame(0, 0, true), cap, || None), None);
        assert_eq!(ring.push(&frame(250, 250, false), cap, || None), None);
        assert_eq!(
            ring.push(&frame(3_600_500, 500, false), cap, || None),
            truncation
        );
        // The mapping is corrected; 12 s later by arrival a line is due.
        assert_eq!(ring.push(&frame(12_000, 12_000, true), cap, || None), None);
        assert_eq!(ring.push(&frame(12_250, 12_250, false), cap, || None), None);
        assert_eq!(
            ring.push(&frame(12_500, 12_500, false), cap, || None),
            truncation,
            "not held back by the capture time an hour ahead"
        );
        // A jump ahead 1 s later by arrival is still inside the interval.
        assert_eq!(ring.push(&frame(13_000, 13_000, true), cap, || None), None);
        assert_eq!(ring.push(&frame(13_250, 13_250, false), cap, || None), None);
        assert_eq!(
            ring.push(&frame(3_613_500, 13_500, false), cap, || None),
            None,
            "a capture time ahead does not bypass the interval"
        );
        assert_eq!(ring.stats().unwrap().truncations, 3);
    }

    #[test]
    fn a_video_ring_s_window_is_measured_by_arrival_when_a_capture_time_jumps_ahead_and_back() {
        let clip = Clip::new();
        let mut ring = ring(true, 2000);
        let push = |ring: &mut Preroll, capture: u64, arrival: u64| {
            assert_eq!(
                ring.push(&clip.shifted(capture, arrival, true), usize::MAX, || None),
                None
            );
        };
        push(&mut ring, 0, 0);
        // A Sender Report maps this keyframe an hour ahead.
        push(&mut ring, 3_600_000, 1000);
        for s in (2000..=7000).step_by(1000) {
            push(&mut ring, s, s);
        }
        assert_eq!(
            held(&ring),
            [5000, 6000, 7000],
            "the GOP dated an hour ahead went in its turn"
        );
        // A mapping corrected far back: the window counts from this
        // keyframe's arrival, not from the capture time it carries.
        push(&mut ring, 100, 9000);
        assert_eq!(held(&ring), [7000, 9000]);
    }

    #[test]
    fn the_oldest_held_frame_never_counts_from_after_its_arrival() {
        let clip = Clip::new();
        let mut ring = ring(true, 60_000);
        assert_eq!(
            ring.push(&clip.shifted(3_600_000, 1000, true), usize::MAX, || None),
            None
        );
        assert_eq!(ring.oldest(), Some(clip.at(1000)));
        let mut early = self::ring(true, 60_000);
        assert_eq!(
            early.push(&clip.shifted(200, 1000, true), usize::MAX, || None),
            None
        );
        assert_eq!(
            early.oldest(),
            Some(clip.at(200)),
            "a capture time before the arrival stands"
        );
    }

    /// RFC 3550 §6.4.1: a Sender Report correcting a camera's mapping
    /// back can date a later keyframe before the oldest held, and the
    /// audio a clip from it plays must stay too.
    #[test]
    fn rfc3550_6_4_1_the_floor_is_the_oldest_capture_time_of_any_keyframe_held() {
        let clip = Clip::new();
        let mut ring = ring(true, 2000);
        let push = |ring: &mut Preroll, capture: u64, arrival: u64, keyframe: bool| {
            assert_eq!(
                ring.push(
                    &clip.shifted(capture, arrival, keyframe),
                    usize::MAX,
                    || None
                ),
                None
            );
        };
        // Labelled by arrival.
        push(&mut ring, 10_000, 10_000, true);
        push(&mut ring, 10_250, 10_250, false);
        assert_eq!(ring.oldest(), Some(clip.at(10_000)));
        push(&mut ring, 1000, 11_000, true);
        push(&mut ring, 1250, 11_250, false);
        assert_eq!(
            ring.oldest(),
            Some(clip.at(1000)),
            "the later keyframe, dated before the oldest"
        );
        push(&mut ring, 5000, 12_000, true);
        push(&mut ring, 5000, 13_000, true);
        assert_eq!(ring.oldest(), Some(clip.at(1000)));
        assert_eq!(
            ring.floor_keys.len(),
            2,
            "a keyframe captured with a later one leaves for it"
        );

        // The window drops the first two GOPs: the floor moves to the
        // oldest capture time of the keyframes still held.
        push(&mut ring, 6000, 14_000, true);
        assert_eq!(held(&ring), [12_000, 13_000, 14_000]);
        assert_eq!(ring.oldest(), Some(clip.at(5000)));
        push(&mut ring, 7000, 16_000, true);
        assert_eq!(held(&ring), [14_000, 16_000]);
        assert_eq!(ring.oldest(), Some(clip.at(6000)));

        assert!(ring.clear());
        assert_eq!(ring.oldest(), None);
        push(&mut ring, 8000, 17_000, true);
        assert_eq!(ring.oldest(), Some(clip.at(8000)));
        assert_eq!(ring.set_window(None), Some(Duration::from_millis(2000)));
        assert_eq!(ring.oldest(), None);
        assert!(ring.floor_keys.is_empty());
    }

    #[test]
    fn an_audio_ring_s_own_window_is_measured_by_arrival() {
        let clip = Clip::new();
        let mut ring = ring(false, 1000);
        for (capture, arrival) in [
            (0, 0),
            (3_600_000, 400),
            (800, 800),
            (1200, 1200),
            (1600, 1600),
        ] {
            assert_eq!(
                ring.push(&clip.shifted(capture, arrival, false), usize::MAX, || None),
                None
            );
        }
        assert_eq!(held(&ring), [400, 800, 1200, 1600]);
        // The window counts from this frame's arrival, not its capture time.
        assert_eq!(
            ring.push(&clip.shifted(0, 2000, false), usize::MAX, || None),
            None
        );
        assert_eq!(held(&ring), [800, 1200, 1600, 2000]);
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
    fn an_audio_ring_s_floor_counts_a_frame_dated_ahead_of_its_arrival_by_its_arrival() {
        let clip = Clip::new();
        let mut ring = ring(false, 60_000);
        let floor = || Some(clip.at(1000));
        // A Sender Report maps the second frame an hour ahead; the next
        // one corrects it.
        for (capture, arrival) in [
            (0, 0),
            (3_600_000, 400),
            (800, 800),
            (1200, 1200),
            (1600, 1600),
        ] {
            assert_eq!(
                ring.push(&clip.shifted(capture, arrival, false), usize::MAX, floor),
                None
            );
        }
        assert_eq!(
            held(&ring),
            [800, 1200, 1600],
            "the frame dated ahead does not hold the obsolete prefix"
        );
        assert_eq!(
            ring.stats().unwrap().bytes,
            u64::try_from(3 * c(10)).unwrap()
        );
        let snapshot = ring.snapshot(clip.at(1000)).unwrap();
        assert_eq!(
            snapshot
                .frames()
                .map(|frame| frame.ts.ticks())
                .collect::<Vec<_>>(),
            [800, 1200, 1600],
            "the snapshot at the floor starts where the ring does"
        );

        // A capture time before the arrival stands: captured at 900, read
        // at 1300, it plays at the floor.
        let mut late = self::ring(false, 60_000);
        for (capture, arrival) in [(600, 1000), (900, 1300), (1200, 1600)] {
            assert_eq!(
                late.push(&clip.shifted(capture, arrival, false), usize::MAX, floor),
                None
            );
        }
        assert_eq!(held(&late), [1300, 1600]);
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
        assert_eq!(ring.oldest(), None, "an audio ring sets no floor");
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
