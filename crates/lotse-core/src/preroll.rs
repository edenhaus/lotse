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
//! Of the frames captured at or before the floor by the ring's measure,
//! the one it keeps is the newest dated at or before the floor, where a
//! snapshot from any held keyframe can start its audio, else the newest.
//! Windows are measured by arrival, which only moves forward on a track,
//! never by capture time, which a camera's Sender Reports can move ahead
//! and back; only the floor, the audio frames trimmed by it and a
//! snapshot's start, which line audio up with video, use capture time, and
//! neither the floor nor the end of the audio frames it trims counts from
//! after it arrived; of those, the one kept counts by its date. An audio
//! snapshot starts by the frames' capture times as they are, as a clip's
//! container places them: its target is the video start's capture time,
//! and the frame playing then is the one the file plays with that
//! keyframe.
//! Every frame is charged its payload plus [`PREROLL_FRAME_OVERHEAD`], so a
//! camera sending tiny frames cannot hold more memory than the bound says.
//! Every trim drops a prefix in one pass that stops where the kept frames
//! begin, so it costs what it drops; an audio ring's trim by the floor
//! remembers the frames it keeps that arrived before the floor, dated
//! after it, so it walks each of them once, and costs amortized O(1) a
//! frame plus what it drops. The floor is kept in amortized O(1) a
//! keyframe.

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
pub fn captured(frame: &MediaFrame) -> Instant {
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

    /// Starts the snapshot at its first keyframe after `start` that
    /// `accept` takes, dropping the frames before it; returns whether it
    /// moved, and leaves it as it is when none qualifies. The frames it
    /// drops all come before the ones it keeps, so the snapshot still pairs
    /// with the subscription it was taken with
    /// ([`Track::subscribe_from_preroll`](crate::track::Track::subscribe_from_preroll)).
    /// By position, never by capture time: a camera's Sender Reports can
    /// date a frame ahead of a later one.
    pub fn advance_to_keyframe(&mut self, mut accept: impl FnMut(&MediaFrame) -> bool) -> bool {
        let Some(at) = self
            .following
            .iter()
            .position(|frame| frame.keyframe && accept(frame))
        else {
            return false;
        };
        let mut kept = std::mem::take(&mut self.following).into_iter().skip(at);
        // `at` is a position in `following`: the keyframe is next.
        if let Some(keyframe) = kept.next() {
            self.start = keyframe;
        }
        self.following = kept.collect();
        true
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

/// What an audio ring's trim by the floor ([`Preroll::floor_start`])
/// knows of the frames it kept, so a push walks only the frames it adds
/// to the stale run or drops, never again the ones it keeps: without it,
/// a frame dated at the floor followed by frames that arrived before the
/// floor but are dated far after it had every push walk all of them.
///
/// Invariant: there is a floor, the last one a trim walked frames by,
/// that each of the `len` frames after the ring's front (positions 1 to
/// `len`) arrived at or before and is dated after. So under a floor at or
/// after the newest one's arrival they are all in the stale run, captured
/// ([`captured`]) at or before it; under an earlier floor none of them is
/// dated at or before it, and each is captured at or before it only if it
/// arrived by then, as arrival only moves forward, the oldest first. The
/// ring's frames leave only at its front ([`Self::dropped`]) and enter at
/// its back, so a frame stays known until it is dropped and joins the
/// known ones once.
#[derive(Debug, Default)]
struct FloorRun {
    /// How many frames after the ring's front are known.
    len: usize,
    /// The known frames dated before every known frame after them, as
    /// their position and date, oldest first, so their dates increase:
    /// the newest known frame dated at or before a floor is the last of
    /// them that is.
    minima: VecDeque<(usize, Instant)>,
    /// The position of the ring's front: frames are numbered as the ring
    /// appends them, wrapping, so a position in `minima` stays valid as
    /// the front moves.
    front: usize,
    /// Frames the trim walked, over the ring's life: what the tests count
    /// the cost by.
    #[cfg(test)]
    walked: usize,
}

impl FloorRun {
    /// The ring dropped its `count` oldest frames: the known ones among
    /// them are gone, and the one that became the front is not counted.
    fn dropped(&mut self, count: usize) {
        self.len = self.len.saturating_sub(count);
        while self
            .minima
            .front()
            .is_some_and(|&(position, _)| position.wrapping_sub(self.front) <= count)
        {
            self.minima.pop_front();
        }
        self.front = self.front.wrapping_add(count);
    }
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
    /// What the audio ring's trim by the floor knows of the frames it
    /// kept. Empty on a video ring.
    run: FloorRun,
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
            run: FloorRun::default(),
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
            self.run = FloorRun::default();
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
        self.run = FloorRun::default();
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

    /// [`Self::push`] on an audio ring: keeps from where `floor` starts it
    /// ([`Self::floor_start`]), else from the newest frame that arrived at
    /// least the window before this one, and what follows. A capture time
    /// that moves back while behind its arrival still ends the stale run at
    /// the frame before it: the ring holds what follows until the floor
    /// passes that frame or `preroll_bytes` drops it, and a snapshot still
    /// starts at the newest frame dated at or before its target.
    fn push_audio(
        &mut self,
        frame: &Arc<MediaFrame>,
        window: Duration,
        cap: usize,
        floor: Option<Instant>,
    ) {
        self.append(frame, cost(frame));
        let stale = match floor {
            Some(floor) => self.floor_start(floor),
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

    /// Where an audio ring starts by the video ring's `floor`: the stale
    /// run is the frames captured at or before it by the ring's measure
    /// ([`captured`]), up to the first captured after it, so a frame dated
    /// ahead of its arrival counts by its arrival and cannot hold the ring
    /// back. Of that run the ring keeps the newest frame dated at or before
    /// the floor, else the run's last frame. A snapshot starts its audio at
    /// the newest frame dated at or before the keyframe's date
    /// ([`Self::start_time`]), never before the floor: one that arrived
    /// before a later frame captured at or before the floor by its arrival
    /// but dated after it (AAC dated 8 ms after its arrival, a keyframe at
    /// 1.027 s and the next frame arriving at 1.024 s, dated 1.032 s) would
    /// otherwise be gone, and the audio start after the keyframe. The run
    /// kept beyond the ring's measure is the frames that arrived before the
    /// floor dated after it: the audio's own dating ahead of its arrival,
    /// at most `preroll_bytes` as all a ring holds.
    ///
    /// The run is the same as one pass from the front would find, for any
    /// floor, forward or back, and any dates, but the frames it kept are
    /// known ([`FloorRun`]): under a floor at or after the newest known
    /// one's arrival it walks only the frames after them, and finds the
    /// newest frame dated at or before the floor among the known ones by
    /// popping the dates it passes; under an earlier floor it walks only
    /// the frames it drops. So a frame joins the known ones once, and a
    /// push costs amortized O(1) plus what it drops. Returns how many frames to drop,
    /// which the caller does at once.
    fn floor_start(&mut self, floor: Instant) -> usize {
        let front_dated = self
            .frames
            .front()
            .is_some_and(|front| front.wallclock <= floor);
        let known = self.run.len;
        if known > 0
            && self
                .frames
                .get(known)
                .is_some_and(|newest| newest.arrival > floor)
        {
            // The floor moved back before the newest known frame arrived:
            // the run ends among the known frames, none of them dated at
            // or before it, so it ends the run or keeps the front.
            if front_dated {
                return 0;
            }
            let dropped = self
                .frames
                .iter()
                .skip(1)
                .take_while(|next| captured(next) <= floor)
                .count();
            #[cfg(test)]
            {
                self.run.walked = self.run.walked.saturating_add(dropped);
            }
            return dropped;
        }
        // Every known frame is in the run: walk the frames after them.
        while let Some(next) = self
            .frames
            .get(self.run.len.saturating_add(1))
            .filter(|next| captured(next) <= floor)
        {
            self.run.len = self.run.len.saturating_add(1);
            #[cfg(test)]
            {
                self.run.walked = self.run.walked.saturating_add(1);
            }
            while self
                .run
                .minima
                .back()
                .is_some_and(|&(_, date)| date >= next.wallclock)
            {
                self.run.minima.pop_back();
            }
            let position = self.run.front.wrapping_add(self.run.len);
            self.run.minima.push_back((position, next.wallclock));
        }
        let mut dated = None;
        while let Some(&(position, _)) = self.run.minima.front().filter(|&&(_, date)| date <= floor)
        {
            dated = Some(position);
            self.run.minima.pop_front();
        }
        match dated {
            Some(position) => position.wrapping_sub(self.run.front),
            None if front_dated => 0,
            None => self.run.len,
        }
    }

    /// Whether a clip can start at `frame`: a keyframe, or any audio
    /// frame, whatever its source marked it.
    fn starts_at(&self, frame: &MediaFrame) -> bool {
        frame.keyframe || !self.video
    }

    /// When `frame` was captured, as a snapshot's start counts it: by the
    /// ring's measure ([`captured`]) on video, whose target is a moment on
    /// the worker's clock (`now − before_ms`); as dated on audio, whose
    /// target is the video start's capture time and whose frames a clip's
    /// container places by their capture times as well. Counted from its
    /// arrival, an audio frame dated after the keyframe would start a clip
    /// whose container then puts it after the keyframe, and an audio frame
    /// that arrived before a keyframe dated ahead of its own arrival would
    /// start the audio that much before the video.
    fn start_time(&self, frame: &MediaFrame) -> Instant {
        if self.video {
            captured(frame)
        } else {
            frame.wallclock
        }
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
    /// The known frames of the stale run ([`FloorRun`]) among them leave it.
    fn drop_front(&mut self, count: usize) {
        let count = count.min(self.frames.len());
        self.run.dropped(count);
        for frame in self.frames.drain(..count) {
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
    /// keyframe is later; `None` when nothing is held. Captured by the
    /// ring's measure ([`captured`]), as a clip measures its start and
    /// `before_ms`: a keyframe dated ahead of its arrival counts from its
    /// arrival, so a Sender Report mapping off (RFC 3550 §6.4.1) cannot
    /// push the start back to an older one. Every audio frame is a start,
    /// so an audio ring starts at the frame playing at `target`, the video
    /// start's capture time, by the frames' capture times as they are
    /// ([`Self::start_time`]).
    pub(crate) fn snapshot(&self, target: Instant) -> Option<PrerollSnapshot> {
        let from = self
            .frames
            .iter()
            .rposition(|frame| self.starts_at(frame) && self.start_time(frame) <= target)
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

    /// An audio ring keeps the frame dated at the floor, which a snapshot
    /// from the oldest keyframe starts its audio with, when the frames
    /// after it arrived before the floor but are dated after it. AAC dated
    /// 8 ms after its arrival every 64 ms, the keyframe captured at
    /// 1.027 s, and the next frame after it arriving at 1.088 s: the frame
    /// dated 0.968 s stays. Opus dated 43 ms after its arrival every 20 ms
    /// (MediaMTX 1.21.1, 2026-10-26), the keyframe at 0.983 s: the frame
    /// dated then stays, at the floor, as do the two after it, dated after
    /// it, through the pushes after.
    /// Regression (Copilot on #77): the ring trimmed by the next frame's
    /// arrival alone, dropped the frame dated 0.968 s and the snapshot
    /// started the audio with the one dated 1.032 s, after the keyframe.
    #[test]
    fn rfc3550_6_4_1_an_audio_ring_keeps_the_frame_dated_at_the_floor() {
        let clip = Clip::new();
        for (every, ahead, keyframe, last, kept) in
            [(64, 8, 1_027, 1_088, 960), (20, 43, 983, 1_060, 940)]
        {
            let mut ring = ring(false, 60_000);
            for arrival in (0..=last).step_by(every) {
                let floor = (arrival >= keyframe).then(|| clip.at(keyframe));
                assert_eq!(
                    ring.push(
                        &clip.shifted(arrival + ahead, arrival, false),
                        usize::MAX,
                        || floor
                    ),
                    None
                );
            }
            assert_eq!(held(&ring)[0], kept, "{every} ms");
            let start = ring.snapshot(clip.at(keyframe)).unwrap();
            assert_eq!(start.start().ts.ticks(), kept);
            assert!(start.start().wallclock <= clip.at(keyframe));
        }
    }

    /// Where an audio ring starts by `floor`, found as 9fdcc7c did, in
    /// one pass from the front: the reference the cached trim must match.
    fn full_scan(frames: &[Arc<MediaFrame>], floor: Instant) -> usize {
        let mut dated = frames
            .first()
            .is_some_and(|front| front.wallclock <= floor)
            .then_some(0);
        let mut last = 0;
        for (index, next) in frames
            .iter()
            .enumerate()
            .skip(1)
            .take_while(|(_, next)| captured(next) <= floor)
        {
            last = index;
            if next.wallclock <= floor {
                dated = Some(index);
            }
        }
        dated.unwrap_or(last)
    }

    /// The trim by the floor keeps what one pass from the front keeps, for
    /// floors that move forward, move back and go unset, frames dated
    /// before and after their arrival, ties, the byte cap, a cleared ring
    /// and a removed window, so the frames it remembers never change what
    /// it drops.
    #[test]
    fn rfc3550_6_4_1_an_audio_ring_trims_by_the_floor_as_a_full_scan_would() {
        let clip = Clip::new();
        for seed in 1..=64_u64 {
            let mut xorshift = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut random = |bound: u64| {
                // xorshift64 (Marsaglia 2003): deterministic, no dependency.
                xorshift ^= xorshift << 13;
                xorshift ^= xorshift >> 7;
                xorshift ^= xorshift << 17;
                xorshift % bound
            };
            let mut ring = ring(false, 50);
            let mut arrival = 1000;
            for _ in 0..500 {
                arrival += random(4);
                let frame = clip.shifted(arrival + random(121) - 30, arrival, false);
                let floor = (random(10) > 0).then(|| clip.at(arrival - random(80)));
                let cap = match random(10) {
                    0 => usize::try_from(1 + random(8)).unwrap() * c(10),
                    _ => usize::MAX,
                };
                match random(200) {
                    0 => assert!(ring.clear() || ring.frames.is_empty()),
                    1 => {
                        let window = Some(Duration::from_millis(50));
                        assert_eq!(ring.set_window(None), window);
                        assert_eq!(ring.set_window(window), None);
                    }
                    _ => {}
                }
                let mut expected: Vec<_> = ring
                    .frames
                    .iter()
                    .cloned()
                    .chain([Arc::clone(&frame)])
                    .collect();
                let stale = match floor {
                    Some(floor) => full_scan(&expected, floor),
                    None => expected
                        .iter()
                        .skip(1)
                        .take_while(|next| {
                            next.arrival + Duration::from_millis(50) <= frame.arrival
                        })
                        .count(),
                };
                expected.drain(..stale);
                let fits = cap / c(10);
                if expected.len() > fits {
                    expected.drain(..expected.len() - fits);
                }
                assert_eq!(ring.push(&frame, cap, || floor), None);
                assert_eq!(
                    ring.frames.iter().map(Arc::as_ptr).collect::<Vec<_>>(),
                    expected.iter().map(Arc::as_ptr).collect::<Vec<_>>(),
                    "seed {seed}"
                );
            }
        }
    }

    /// Copilot's case on #77: a frame dated at the floor, then frames
    /// every 20 ms dated 60 s after their arrival, and the floor 1 s
    /// behind the arrival. The ring keeps them all, as before, but each
    /// frame joins the known run once, so 2,000 pushes walk 1,949 frames.
    /// Regression: each push walked every frame kept, 1,902,274 frames
    /// visited in all.
    #[test]
    fn rfc3550_6_4_1_an_audio_ring_s_trim_by_the_floor_walks_each_frame_once() {
        let clip = Clip::new();
        let mut ring = ring(false, 3_600_000);
        assert_eq!(
            ring.push(&clip.shifted(0, 1000, false), usize::MAX, || None),
            None
        );
        for arrival in (1020..41_000).step_by(20) {
            let floor = clip.at(arrival - 1000);
            assert_eq!(
                ring.push(
                    &clip.shifted(arrival + 60_000, arrival, false),
                    usize::MAX,
                    || Some(floor)
                ),
                None
            );
        }
        assert_eq!(ring.frames.len(), 2000);
        assert_eq!(held(&ring)[0], 1000, "the frame dated at the floor stays");
        assert_eq!(ring.run.len, 1949, "the frames that arrived by the floor");
        assert_eq!(ring.run.walked, 1949);
    }

    /// When the floor moves back before the newest known frame arrived,
    /// the run ends among the known frames: the trim keeps the front dated
    /// at or before the floor, else drops the frames that arrived by it,
    /// and walks only those. The front dated at 0, or at 200 ms, between
    /// the floor at 250 ms and the one at 150 ms after it.
    #[test]
    fn rfc3550_6_4_1_an_audio_ring_s_trim_by_an_earlier_floor_walks_what_it_drops() {
        let clip = Clip::new();
        for (front_date, kept, walked) in [
            (0, vec![0, 100, 200, 300], 2),
            (200, vec![100, 200, 300], 3),
        ] {
            let mut ring = ring(false, 60_000);
            assert_eq!(
                ring.push(&clip.shifted(front_date, 0, false), usize::MAX, || None),
                None
            );
            for arrival in [100, 200] {
                assert_eq!(
                    ring.push(
                        &clip.shifted(arrival + 10_000, arrival, false),
                        usize::MAX,
                        || Some(clip.at(250))
                    ),
                    None
                );
            }
            assert_eq!(ring.run.len, 2);
            assert_eq!(
                ring.push(&clip.shifted(10_300, 300, false), usize::MAX, || Some(
                    clip.at(150)
                )),
                None
            );
            assert_eq!(held(&ring), kept, "front dated at {front_date}");
            assert_eq!(ring.run.walked, walked);
        }
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

    /// A snapshot advances to a later keyframe by position, whatever its
    /// capture time: a Sender Report can date a keyframe ahead of a later
    /// one (RFC 3550 §6.4.1).
    #[test]
    fn rfc3550_6_4_1_a_snapshot_advances_to_a_later_keyframe_by_position_not_capture_time() {
        let clip = Clip::new();
        let mut ring = ring(true, 60_000);
        gop(&mut ring, &clip, 1000, 2000, usize::MAX);
        // Labelled by arrival: the keyframe at 2 s is dated 61 s, the one
        // at 3 s back to 9 s.
        for frame in [
            clip.shifted(61_000, 2000, true),
            clip.shifted(61_250, 2250, false),
            clip.shifted(9000, 3000, true),
            clip.shifted(9250, 3250, false),
        ] {
            assert_eq!(ring.push(&frame, usize::MAX, || None), None);
        }
        let labels = |snapshot: &PrerollSnapshot| {
            snapshot
                .frames()
                .map(|frame| frame.ts.ticks())
                .collect::<Vec<_>>()
        };
        let mut snapshot = ring.snapshot(clip.at(1000)).unwrap();
        let all = labels(&snapshot);
        assert!(!snapshot.advance_to_keyframe(|_| false));
        assert_eq!(labels(&snapshot), all, "none qualifies: unchanged");
        assert!(
            !snapshot.advance_to_keyframe(|frame| !frame.keyframe),
            "only a keyframe qualifies"
        );
        assert_eq!(labels(&snapshot), all);

        assert!(snapshot.advance_to_keyframe(|_| true));
        assert_eq!(labels(&snapshot), [2000, 2250, 3000, 3250]);
        assert_eq!(snapshot.frame_count(), 4);
        assert!(
            Arc::ptr_eq(snapshot.start(), ring.frames.get(4).unwrap()),
            "the ring's frames, not copies"
        );

        let mut snapshot = ring.snapshot(clip.at(1000)).unwrap();
        assert!(snapshot.advance_to_keyframe(|frame| frame.ts.ticks() == 3000));
        assert_eq!(labels(&snapshot), [3000, 3250]);
    }

    /// A video snapshot measures its keyframes' capture times as a clip
    /// measures its start ([`captured`]): a keyframe dated ahead of its
    /// arrival (a Sender Report mapping off, RFC 3550 §6.4.1) counts from
    /// its arrival. Video keyframes arriving at 1 s and 2 s dated 61 s and
    /// 62 s start a snapshot for 3 s at the second. Regression: the ring
    /// compared their dates, found none at or before the target and
    /// started at the oldest held. An audio snapshot's target is such a
    /// keyframe's date, and audio frames dated a minute ahead as well start
    /// one for 61 s with the frame dated playing then.
    #[test]
    fn rfc3550_6_4_1_a_snapshot_starts_by_when_its_frames_were_captured_never_after_their_arrival()
    {
        let clip = Clip::new();
        let mut video = ring(true, 60_000);
        // Labelled by arrival.
        for (capture, arrival, keyframe) in [
            (61_000, 1000, true),
            (61_250, 1250, false),
            (62_000, 2000, true),
            (62_250, 2250, false),
        ] {
            assert_eq!(
                video.push(
                    &clip.shifted(capture, arrival, keyframe),
                    usize::MAX,
                    || None
                ),
                None
            );
        }
        let starts = |ring: &Preroll, target: u64| {
            ring.snapshot(clip.at(target))
                .unwrap()
                .frames()
                .map(|frame| frame.ts.ticks())
                .collect::<Vec<_>>()
        };
        assert_eq!(starts(&video, 3000), [2000, 2250]);
        assert_eq!(starts(&video, 2000), [2000, 2250], "at the arrival counts");
        assert_eq!(starts(&video, 1999), [1000, 1250, 2000, 2250]);

        let mut audio = ring(false, 60_000);
        for ms in (0..=1600).step_by(400) {
            assert_eq!(
                audio.push(&clip.shifted(60_000 + ms, ms, false), usize::MAX, || None),
                None
            );
        }
        assert_eq!(starts(&audio, 61_000), [800, 1200, 1600]);
    }

    /// An audio snapshot starts with the frame playing at its target, the
    /// video start's capture time, by the frames' capture times as dated,
    /// where a clip's container places them: of audio frames dated 3 ms
    /// after their arrival every 20 ms, the one for a keyframe captured at
    /// 1.001 s is the one dated 0.983 s, which arrived at 0.98 s. Regression
    /// (interop with MediaMTX 1.21.1, 2026-10-26: G.722 transcoded with its
    /// video 0.9 and 2.2 ms short of the transcode's delay): the ring
    /// counted each from its arrival and started with the one that arrived
    /// at 1 s, dated 1.003 s, after the keyframe.
    #[test]
    fn rfc3550_6_4_1_an_audio_snapshot_starts_with_the_frame_dated_at_its_target() {
        let clip = Clip::new();
        let mut audio = ring(false, 60_000);
        for ms in (900..=1100).step_by(20) {
            assert_eq!(
                audio.push(&clip.shifted(ms + 3, ms, false), usize::MAX, || None),
                None
            );
        }
        let start = |target: u64| audio.snapshot(clip.at(target)).unwrap().start().ts.ticks();
        assert_eq!(start(1001), 980);
        assert_eq!(start(1003), 1000, "at the date counts");
        assert_eq!(start(902), 900, "before every date, the oldest held");
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
