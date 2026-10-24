//! A clip's tracks merged in capture order through a bounded reliable
//! queue: the egress contract's `Reliable` delivery and its interleaver,
//! for an output that writes a container.
//!
//! [`ReliableQueue`] takes what a clip's frame subscriptions yield (its
//! video, and its audio when it has some) the moment they yield it, and the
//! pre-roll they start from, so a track's broadcast never lags for a slow
//! reader. [`Interleaver`] hands the queued items out in capture
//! (`wallclock`) order. Both are pure: no task, no lock, no clock read;
//! every "now" is the caller's injected clock.
//!
//! Invariants: the producer never waits, so a frame that does not fit is
//! dropped, never held back. A live frame counts its payload plus
//! [`QUEUED_FRAME_OVERHEAD`] against the bound; a pre-roll frame counts
//! nothing, since its ring bounded it by `preroll_bytes` already, and the
//! live frames the pre-roll holds too are dropped, so none is written
//! twice. The snapshot must start at a frame the track published before the
//! clip subscribed, which
//! [`Track::subscribe_from_preroll`](crate::track::Track::subscribe_from_preroll)
//! guarantees: a live frame published before the snapshot's start could not
//! be told from one after its newest. A lag while those frames may still
//! come is no hole if the next frame is one of them, since what was lost
//! then is the pre-roll's. A frame always fits a queue that counts nothing,
//! so a frame larger than the bound cannot stall it. Video starts at a
//! keyframe and, after a hole, resumes at one; audio resumes at any frame,
//! waits for the video's first keyframe and is dropped while the queue
//! overflows, so an overflow is one hole for the clip; once the video
//! ended, an overflow is the audio's own hole, and the audio resumes at its
//! next frame that fits. A hole after a track's first frame is an explicit
//! gap, queued before the frame that ends it; one before it only starts the
//! track later. A gap or a control event counts nothing: a gap is queued
//! only before a frame, and a control event replaces one of its kind queued
//! since the track's last frame, so the items beside the frames stay
//! bounded with them. Each track's items keep their order: the
//! interleaver chooses between the tracks, never within one.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::codec::Kind;
use crate::media::MediaFrame;
use crate::preroll::{PrerollSnapshot, captured};
use crate::throttle::Throttle;
use crate::track::TrackEvent;

/// What a queued live frame costs beyond its payload: the `MediaFrame` and
/// its `Arc` counts, which the queue may be the last to hold, and the
/// queue's slot.
pub const QUEUED_FRAME_OVERHEAD: usize = size_of::<MediaFrame>()
    .saturating_add(2_usize.saturating_mul(size_of::<usize>()))
    .saturating_add(size_of::<Item>());

/// Why a track has a hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    /// The clip's queue was full: its reader is slower than the camera.
    Overflow,
    /// The clip's subscription missed frames: it fell behind the track's
    /// broadcast, or the track dropped one over `max_frame_bytes`.
    Lagged,
    /// The pre-roll ring cut its newest GOP short at `preroll_bytes` or
    /// lost a frame the track dropped over `max_frame_bytes`, so the live
    /// frames up to the next keyframe have nothing to follow.
    PrerollTruncated,
}

impl GapReason {
    /// The name the logs use.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Overflow => "overflow",
            Self::Lagged => "lagged",
            Self::PrerollTruncated => "preroll_truncated",
        }
    }
}

/// What the queue hands out, per track in the order it was queued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// The next frame of `track`.
    Frame {
        /// The track's kind.
        track: Kind,
        /// The frame.
        frame: Arc<MediaFrame>,
    },
    /// `track` has a hole: frames of it were lost between the frame queued
    /// before it and the one after it, which follows.
    Gap {
        /// The track's kind; an overflow is the video's hole while the
        /// video is open, else the audio's.
        track: Kind,
        /// Why.
        reason: GapReason,
        /// The capture time of the latest frame the track queued before the
        /// hole, `to` when the capture times moved back in it, so a gap
        /// never ends before it starts.
        from: Instant,
        /// The capture time of the frame after the hole, which follows.
        to: Instant,
    },
    /// A control event of `track`, in its place among the track's frames:
    /// `EpochStart`, `TrackChanged`, `SourceLost` or `SourceRestored`: the
    /// newest of its kind since the track's previous frame.
    Control {
        /// The track's kind.
        track: Kind,
        /// The event.
        event: TrackEvent,
    },
}

/// A queued item, without its track.
#[derive(Debug)]
enum Entry {
    /// See [`Out::Frame`].
    Frame(Arc<MediaFrame>),
    /// See [`Out::Gap`].
    Gap {
        /// See [`Out::Gap::reason`].
        reason: GapReason,
        /// See [`Out::Gap::from`].
        from: Instant,
        /// See [`Out::Gap::to`].
        to: Instant,
    },
    /// See [`Out::Control`].
    Control(TrackEvent),
}

/// One queued item.
#[derive(Debug)]
struct Item {
    /// What it is.
    entry: Entry,
    /// When it was queued, on the injected clock: the interleaver holds a
    /// frame for the other track at most `max_skew` from here.
    queued: Instant,
    /// What it counts against the bound: nothing for a pre-roll frame, a
    /// gap or a control event.
    cost: usize,
}

impl Item {
    /// The capture time of a frame; `None` for a gap or a control event,
    /// which go out as soon as they lead their track.
    fn wallclock(&self) -> Option<Instant> {
        match &self.entry {
            Entry::Frame(frame) => Some(frame.wallclock),
            Entry::Gap { .. } | Entry::Control(_) => None,
        }
    }
}

/// A hole a track is in: its frames are dropped until one it can resume
/// at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hole {
    /// Why.
    reason: GapReason,
    /// The capture time of the latest frame the track queued before it.
    from: Instant,
}

/// One track's side of the queue.
#[derive(Debug)]
struct Lane {
    /// Which track.
    kind: Kind,
    /// The queued items, oldest first.
    items: VecDeque<Item>,
    /// Still taking items: the track exists and has not ended.
    open: bool,
    /// A frame was queued: on video, a keyframe. Before it nothing is a
    /// hole, the track only starts later.
    started: bool,
    /// The hole the track is in, if any.
    hole: Option<Hole>,
    /// The capture time of the latest frame queued: where a hole starts.
    /// The latest, not the greatest, as for `reached`: after the capture
    /// times moved back, a hole starts at the frame before it, not at one
    /// dated ahead; with B-frames that can be a frame or two before the
    /// newest captured.
    last: Option<Instant>,
    /// Where the track is: the capture time of the latest frame seen,
    /// dropped frames included, a frame dated ahead of its arrival counting
    /// by its arrival ([`captured`]), so the other waits for nothing
    /// before it. The latest, not the greatest: a Sender Report that moves
    /// the capture times back moves it back with the next frame.
    reached: Option<Instant>,
    /// The pre-roll's frames, oldest first, while the live frames that
    /// repeat them may still come: those the track published after the
    /// clip subscribed, which the snapshot starting before the subscription
    /// makes its newest; empty once a live frame was none of them.
    duplicates: Vec<Arc<MediaFrame>>,
    /// The subscription lagged while `duplicates` may still come: a hole
    /// only once the next frame is none of them, since the frames lost
    /// before one of them are the pre-roll's.
    lagged: bool,
}

impl Lane {
    /// An empty lane; `open` when the clip has the track.
    const fn new(kind: Kind, open: bool) -> Self {
        Self {
            kind,
            items: VecDeque::new(),
            open,
            started: false,
            hole: None,
            last: None,
            reached: None,
            duplicates: Vec::new(),
            lagged: false,
        }
    }

    /// Whether the lane can start or resume at `frame`: a keyframe, or any
    /// audio frame, whatever its source marked it.
    fn resumes_at(&self, frame: &MediaFrame) -> bool {
        frame.keyframe || self.kind == Kind::Audio
    }

    /// Whether the lane drops frames until one it can resume at.
    const fn waiting(&self) -> bool {
        !self.started || self.hole.is_some()
    }

    /// Whether the lane is in an overflow's hole.
    fn overflowing(&self) -> bool {
        self.hole
            .is_some_and(|hole| hole.reason == GapReason::Overflow)
    }

    /// Whether audio is dropped now: this (video) lane has not started, or
    /// it is open and in an overflow's hole, which only its next keyframe
    /// ends; once it ended, the audio recovers on its own.
    fn blocks_audio(&self) -> bool {
        !self.started || (self.open && self.overflowing())
    }

    /// Whether `frame` is a live frame the pre-roll already queued. The
    /// duplicates are the ones the track published after the clip
    /// subscribed: with the subscription and the snapshot taken together,
    /// at most the newest, which the track's source task held in the ring
    /// but had not broadcast yet; more for a snapshot taken again later
    /// from a frame of the first. They come first, in order; the first
    /// frame that is none of them ends the check.
    fn is_duplicate(&mut self, frame: &Arc<MediaFrame>) -> bool {
        if let Some(at) = self
            .duplicates
            .iter()
            .rposition(|held| Arc::ptr_eq(held, frame))
        {
            self.duplicates.drain(..=at);
            true
        } else {
            self.duplicates = Vec::new();
            false
        }
    }

    /// Enters a hole for `reason`, unless the lane is in one already or
    /// has not started; whether it entered one.
    fn lose(&mut self, reason: GapReason) -> bool {
        if self.hole.is_some() {
            return false;
        }
        self.hole = self.last.map(|from| Hole { reason, from });
        self.hole.is_some()
    }

    /// Enters an overflow's hole, keeping the start of a hole the lane is
    /// in already; none before the lane's first frame.
    fn overflow(&mut self) {
        self.hole = self
            .hole
            .map_or(self.last, |hole| Some(hole.from))
            .map(|from| Hole {
                reason: GapReason::Overflow,
                from,
            });
    }

    /// Queues the control `event`, replacing one of its kind queued since
    /// the lane's last frame: no frame came under that one. So at most one
    /// of each kind waits between two frames, and a reader stalled through
    /// an overflow, which drops the frames, holds no more than one of each.
    fn queue_control(&mut self, event: TrackEvent, queued: Instant) {
        let run = self
            .items
            .iter()
            .rev()
            .take_while(|item| matches!(item.entry, Entry::Control(_)))
            .count();
        let start = self.items.len().saturating_sub(run);
        let kind = std::mem::discriminant(&event);
        let replaced = self
            .items
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, item)| {
                matches!(&item.entry, Entry::Control(held) if std::mem::discriminant(held) == kind)
            })
            .map(|(at, _)| at);
        if let Some(at) = replaced {
            tracing::trace!(
                track = %self.kind,
                "clip queue: a control event replaces one of its kind no frame came under"
            );
            let _replaced = self.items.remove(at);
        }
        self.items.push_back(Item {
            entry: Entry::Control(event),
            queued,
            cost: 0,
        });
    }

    /// Queues `frame`, which counts `cost`.
    fn queue_frame(&mut self, frame: Arc<MediaFrame>, queued: Instant, cost: usize) {
        self.started = true;
        self.last = Some(frame.wallclock);
        self.items.push_back(Item {
            entry: Entry::Frame(frame),
            queued,
            cost,
        });
    }
}

/// A clip's queue: its video and audio items, bounded in bytes, with the
/// drop and gap rules of the module's invariants.
#[derive(Debug)]
pub struct ReliableQueue {
    /// The video track's lane.
    video: Lane,
    /// The audio track's lane, closed for a clip without audio.
    audio: Lane,
    /// What the queued items count.
    bytes: usize,
    /// The most `bytes` may reach (`limits.clip_queue_bytes`).
    max_bytes: usize,
    /// Rate-limits the line of a hole, which a reader stalled for long
    /// hits on every GOP.
    holes: Throttle,
}

impl ReliableQueue {
    /// An empty queue of at most `max_bytes`, for a clip with video and,
    /// if `audio`, an audio track.
    pub fn new(max_bytes: usize, audio: bool) -> Self {
        Self {
            video: Lane::new(Kind::Video, true),
            audio: Lane::new(Kind::Audio, audio),
            bytes: 0,
            max_bytes,
            holes: Throttle::default(),
        }
    }

    /// What the queued live frames count against the bound now.
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// The lane of `track`.
    const fn lane(&self, track: Kind) -> &Lane {
        match track {
            Kind::Video => &self.video,
            Kind::Audio => &self.audio,
        }
    }

    /// The lane of `track`, to change it.
    const fn lane_mut(&mut self, track: Kind) -> &mut Lane {
        match track {
            Kind::Video => &mut self.video,
            Kind::Audio => &mut self.audio,
        }
    }

    /// Queues the pre-roll `track` starts from, counting nothing, before
    /// any live item of the track: the snapshot starts at a frame published
    /// before the clip subscribed
    /// ([`Track::subscribe_from_preroll`](crate::track::Track::subscribe_from_preroll)),
    /// so the live frames it holds too come first and are dropped as they
    /// come; a live frame published before the snapshot's start would be
    /// queued after it, so a clip never takes a snapshot that starts later.
    /// A video snapshot starts at a keyframe; an audio one is taken only
    /// after the video's (it is ignored before), from the video snapshot's
    /// start. A truncated snapshot puts the track in a hole until its next
    /// keyframe.
    pub fn preroll(&mut self, track: Kind, snapshot: &PrerollSnapshot, now: Instant) {
        let blocked = track == Kind::Audio && self.video.blocks_audio();
        let lane = self.lane_mut(track);
        if !lane.open || blocked {
            tracing::debug!(%track, "clip queue: pre-roll ignored, the track takes nothing now");
            return;
        }
        for frame in snapshot.frames() {
            lane.reached = Some(captured(frame));
            lane.queue_frame(Arc::clone(frame), now, 0);
        }
        lane.duplicates = snapshot.frames().cloned().collect();
        if snapshot.truncated() {
            self.hole(track, GapReason::PrerollTruncated, now);
        }
        tracing::debug!(
            %track,
            frames = snapshot.frame_count(),
            truncated = snapshot.truncated(),
            "clip queue: pre-roll queued"
        );
    }

    /// Takes what `track`'s subscription yielded at `now`. A frame is
    /// queued or dropped by the module's rules; a `Gap` (the broadcast
    /// lagged) puts the track in a hole; one while the pre-roll's frames
    /// may still repeat waits for the next frame and is no hole if that
    /// frame is one of them, as what was lost then is the pre-roll's; a
    /// control event is queued in its place, replacing one of its kind no
    /// frame came under. Nothing once the track ended or for a clip without
    /// it.
    pub fn push(&mut self, track: Kind, event: TrackEvent, now: Instant) {
        if !self.lane(track).open {
            return;
        }
        match event {
            TrackEvent::Frame(frame) => self.push_frame(track, frame, now),
            TrackEvent::Gap { skipped } => {
                // Per event, which a camera over `max_frame_bytes` makes on
                // every frame: the hole it opens is logged, rate-limited.
                tracing::trace!(%track, skipped, "clip queue: the subscription lagged");
                let lane = self.lane_mut(track);
                if lane.duplicates.is_empty() {
                    self.hole(track, GapReason::Lagged, now);
                } else {
                    lane.lagged = true;
                }
            }
            // A clip subscribes to frames, which yield no packet.
            TrackEvent::Packet(_) => {}
            control => self.lane_mut(track).queue_control(control, now),
        }
    }

    /// [`Self::push`] of a frame.
    fn push_frame(&mut self, track: Kind, frame: Arc<MediaFrame>, now: Instant) {
        let blocked = track == Kind::Audio && self.video.blocks_audio();
        let lane = self.lane_mut(track);
        lane.reached = Some(captured(&frame));
        let duplicate = lane.is_duplicate(&frame);
        if std::mem::take(&mut lane.lagged) {
            if duplicate {
                tracing::debug!(%track, "clip queue: the lag fell within the pre-roll, no hole");
            } else {
                self.hole(track, GapReason::Lagged, now);
            }
        }
        let lane = self.lane_mut(track);
        if duplicate || blocked || (lane.waiting() && !lane.resumes_at(&frame)) {
            tracing::trace!(%track, ts = %frame.ts, "clip queue: frame dropped");
            return;
        }
        let cost = frame.payload.len().saturating_add(QUEUED_FRAME_OVERHEAD);
        if self.bytes > 0 && self.bytes.saturating_add(cost) > self.max_bytes {
            self.overflow(now);
            return;
        }
        let lane = self.lane_mut(track);
        if let Some(Hole { reason, from }) = lane.hole.take() {
            lane.items.push_back(Item {
                entry: Entry::Gap {
                    reason,
                    from: from.min(frame.wallclock),
                    to: frame.wallclock,
                },
                queued: now,
                cost: 0,
            });
        }
        lane.queue_frame(frame, now, cost);
        self.bytes = self.bytes.saturating_add(cost);
    }

    /// A frame did not fit: while the video is open it drops to its next
    /// keyframe that fits, the audio until then, and the hole is the
    /// video's (an earlier hole keeps its start); once the video ended no
    /// keyframe comes, so the hole is the audio's, which resumes at its
    /// next frame that fits behind a gap of its own.
    fn overflow(&mut self, now: Instant) {
        let lane = if self.video.open {
            &mut self.video
        } else {
            &mut self.audio
        };
        lane.overflow();
        let track = lane.kind;
        if let Some(count) = self.holes.hit(now) {
            tracing::debug!(
                %track,
                bytes = self.bytes,
                limit = self.max_bytes,
                count,
                "clip queue: full, dropping until the track can resume"
            );
        }
    }

    /// Puts `track` in a hole for `reason` and logs it, rate-limited.
    fn hole(&mut self, track: Kind, reason: GapReason, now: Instant) {
        if self.lane_mut(track).lose(reason)
            && let Some(count) = self.holes.hit(now)
        {
            tracing::debug!(
                %track,
                reason = reason.name(),
                count,
                "clip queue: dropping to the next frame the track can resume at"
            );
        }
    }

    /// Ends `track`: its subscription ended. What it queued still goes
    /// out; nothing more is taken, and the interleaver no longer waits for
    /// it. An overflow hole the video ends in passes to the audio. Ending a
    /// track again, or one the clip lacks, does nothing, so the hole passes
    /// once.
    pub fn end(&mut self, track: Kind) {
        let lane = self.lane_mut(track);
        if !lane.open {
            return;
        }
        tracing::debug!(%track, queued = lane.items.len(), "clip queue: track ended");
        lane.open = false;
        if track == Kind::Video && self.video.overflowing() {
            // No keyframe ends the video's overflow now: the audio it
            // blocked takes the hole and resumes at its next frame.
            tracing::debug!("clip queue: the video ended in an overflow, the audio takes the hole");
            self.audio.overflow();
        }
    }

    /// The oldest frame `track` queued that is not out yet, past the gaps
    /// and control events ahead of it: where a sink that took none of the
    /// track's frames starts it.
    pub fn first_frame(&self, track: Kind) -> Option<&Arc<MediaFrame>> {
        self.lane(track)
            .items
            .iter()
            .find_map(|item| match &item.entry {
                Entry::Frame(frame) => Some(frame),
                Entry::Gap { .. } | Entry::Control(_) => None,
            })
    }

    /// The oldest item `track` queued, taken out.
    pub fn pop(&mut self, track: Kind) -> Option<Out> {
        let item = self.lane_mut(track).items.pop_front()?;
        self.bytes = self.bytes.saturating_sub(item.cost);
        Some(match item.entry {
            Entry::Frame(frame) => Out::Frame { track, frame },
            Entry::Gap { reason, from, to } => Out::Gap {
                track,
                reason,
                from,
                to,
            },
            Entry::Control(event) => Out::Control { track, event },
        })
    }
}

/// Hands a [`ReliableQueue`]'s items out in capture order: always the
/// queued frame captured first (video on a tie), but held while the other
/// track, still open and with nothing queued, has not reached its capture
/// time with its latest frame (counted by its arrival when dated ahead of
/// it, and taken back when a Sender Report moves the capture times back),
/// for at most `max_skew` after it was queued. So an audio path that
/// delivers late still lands in order, and a track that stops sending
/// delays the other by `max_skew` at most. A gap or a control event goes
/// out as soon as it leads its track (video's first), so a sink learns of
/// it before it writes the frames that follow it.
#[derive(Debug)]
pub struct Interleaver {
    /// The queue merged.
    queue: ReliableQueue,
    /// The longest a frame is held for the other track.
    max_skew: Duration,
}

impl Interleaver {
    /// Merges `queue`, holding a frame at most `max_skew`.
    pub const fn new(queue: ReliableQueue, max_skew: Duration) -> Self {
        Self { queue, max_skew }
    }

    /// The queue.
    pub const fn queue(&self) -> &ReliableQueue {
        &self.queue
    }

    /// The queue, to push to.
    pub const fn queue_mut(&mut self) -> &mut ReliableQueue {
        &mut self.queue
    }

    /// The next item at `now`; `None` when nothing is queued or the next
    /// frame is held (see [`Self::deadline`]). Called until `None` after
    /// every push.
    pub fn next(&mut self, now: Instant) -> Option<Out> {
        let (track, until) = self.lead()?;
        if until.is_some_and(|until| now < until) {
            return None;
        }
        self.queue.pop(track)
    }

    /// When the frame held for the other track goes out regardless: the
    /// injected-clock instant to call [`Self::next`] again at if nothing is
    /// pushed before; `None` when nothing is held.
    pub fn deadline(&self) -> Option<Instant> {
        self.lead().and_then(|(_, until)| until)
    }

    /// The track whose item goes out next, and the instant before which
    /// it is held (`None`: not held).
    fn lead(&self) -> Option<(Kind, Option<Instant>)> {
        let lanes = [&self.queue.video, &self.queue.audio];
        if let Some(lane) = lanes.iter().find(|lane| {
            lane.items
                .front()
                .is_some_and(|item| item.wallclock().is_none())
        }) {
            return Some((lane.kind, None));
        }
        let (lead, at, queued) = lanes
            .iter()
            .filter_map(|lane| {
                let item = lane.items.front()?;
                Some((lane.kind, item.wallclock()?, item.queued))
            })
            .min_by_key(|(_, at, _)| *at)?;
        let other = self.queue.lane(match lead {
            Kind::Video => Kind::Audio,
            Kind::Audio => Kind::Video,
        });
        let held = other.open && other.items.is_empty() && other.reached < Some(at);
        let until = if held {
            queued.checked_add(self.max_skew)
        } else {
            None
        };
        Some((lead, until))
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
    use crate::clock::{Clock as _, FakeClock};
    use crate::codec::Codec;
    use crate::media::MediaTime;
    use crate::preroll::Preroll;
    use crate::track::{Track, TrackId, TrackLimits, TrackSubscription, Unit};

    const SKEW: Duration = Duration::from_secs(1);

    /// What a queued live frame of `bytes` payload counts.
    const fn c(bytes: usize) -> usize {
        bytes + QUEUED_FRAME_OVERHEAD
    }

    /// Frames are labelled by their capture time: `ts` is the
    /// milliseconds after the clock's start, which is also how far after it
    /// they were captured. `now` is the fake clock's reading.
    struct Clip {
        clock: FakeClock,
        t0: Instant,
    }

    impl Clip {
        fn new() -> Self {
            let clock = FakeClock::from_system();
            let t0 = clock.now();
            Self { clock, t0 }
        }

        fn at(&self, ms: u64) -> Instant {
            self.t0 + Duration::from_millis(ms)
        }

        fn now(&self) -> Instant {
            self.clock.now()
        }

        fn advance(&self, ms: u64) {
            self.clock.advance(Duration::from_millis(ms));
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

        /// A frame captured `ms` after the start that arrived `arrival`
        /// after it.
        fn arrived(&self, ms: u64, arrival: u64, keyframe: bool) -> Arc<MediaFrame> {
            Arc::new(MediaFrame {
                arrival: self.at(arrival),
                ..MediaFrame::clone(&self.frame(ms, keyframe, 10))
            })
        }

        fn push_arrived(
            &self,
            queue: &mut ReliableQueue,
            track: Kind,
            ms: u64,
            arrival: u64,
            keyframe: bool,
        ) {
            queue.push(
                track,
                TrackEvent::Frame(self.arrived(ms, arrival, keyframe)),
                self.now(),
            );
        }

        fn push(&self, queue: &mut ReliableQueue, track: Kind, ms: u64, keyframe: bool) {
            queue.push(
                track,
                TrackEvent::Frame(self.frame(ms, keyframe, 10)),
                self.now(),
            );
        }
    }

    /// Everything `track` queued, as labels: frames by their `ts`, gaps as
    /// `(from, to)` in milliseconds after `t0`, control events by name.
    fn drain(queue: &mut ReliableQueue, track: Kind, clip: &Clip) -> Vec<String> {
        std::iter::from_fn(|| queue.pop(track))
            .map(|out| label(&out, clip))
            .collect()
    }

    fn label(out: &Out, clip: &Clip) -> String {
        let ms = |at: Instant| at.duration_since(clip.t0).as_millis();
        match out {
            Out::Frame { track, frame } => format!("{}{}", track.letter(), frame.ts),
            Out::Gap {
                track,
                reason,
                from,
                to,
            } => format!(
                "{}gap {} {}-{}",
                track.letter(),
                reason.name(),
                ms(*from),
                ms(*to)
            ),
            Out::Control { track, event } => format!("{}{event:?}", track.letter()),
        }
    }

    /// Everything the interleaver hands out at the clip's `now`.
    fn release(interleaver: &mut Interleaver, clip: &Clip) -> Vec<String> {
        std::iter::from_fn(|| interleaver.next(clip.now()))
            .map(|out| label(&out, clip))
            .collect()
    }

    /// A video ring holding `frames` (ms, keyframe), and its snapshot from
    /// the first; `cap` bounds it.
    fn snapshot(clip: &Clip, frames: &[Arc<MediaFrame>], cap: usize) -> PrerollSnapshot {
        let mut ring = Preroll::new(frames.first().unwrap().keyframe);
        ring.set_window(Some(Duration::from_secs(60)));
        for frame in frames {
            let _ = ring.push(frame, cap, || None);
        }
        ring.snapshot(clip.at(0)).unwrap()
    }

    #[test]
    fn live_frames_queue_in_order_and_count_against_the_bound() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Audio, 10, true);
        clip.push(&mut queue, Kind::Video, 40, false);
        assert_eq!(queue.bytes(), 3 * c(10));
        assert_eq!(drain(&mut queue, Kind::Video, &clip), ["v0", "v40"]);
        assert_eq!(queue.bytes(), c(10), "a popped frame no longer counts");
        assert_eq!(drain(&mut queue, Kind::Audio, &clip), ["a10"]);
        assert_eq!(queue.bytes(), 0);
        assert_eq!(queue.pop(Kind::Video), None);
    }

    #[test]
    fn video_waits_for_its_first_keyframe_and_audio_for_the_video() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        clip.push(&mut queue, Kind::Audio, 0, true);
        clip.push(&mut queue, Kind::Video, 20, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 3 }, clip.now());
        clip.push(&mut queue, Kind::Video, 40, true);
        clip.push(&mut queue, Kind::Audio, 30, false);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v40"],
            "a lag before the first keyframe is no gap: the track starts later"
        );
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["a30"],
            "audio after the video's start, captured before it or not, whatever its keyframe flag"
        );
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn an_overflow_drops_every_track_to_the_next_video_keyframe_with_one_gap() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(3 * c(10), true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Audio, 10, true);
        clip.push(&mut queue, Kind::Video, 40, false);
        assert_eq!(queue.bytes(), 3 * c(10), "an exact fit is kept");
        clip.push(&mut queue, Kind::Audio, 50, true);
        clip.push(&mut queue, Kind::Video, 80, false);
        assert_eq!(queue.bytes(), 3 * c(10));
        assert_eq!(drain(&mut queue, Kind::Audio, &clip), ["a10"]);
        clip.push(&mut queue, Kind::Audio, 90, true);
        clip.push(&mut queue, Kind::Video, 120, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, clip.now());
        assert_eq!(queue.bytes(), 2 * c(10), "dropped though it would fit now");
        clip.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v40", "vgap overflow 40-160", "v160"],
            "one gap, from the last frame held, an overflow's though the video lagged in it"
        );
        clip.push(&mut queue, Kind::Audio, 170, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["a170"],
            "the audio went with the video's hole and reports none of its own"
        );
    }

    #[test]
    fn a_keyframe_that_does_not_fit_keeps_the_hole_open() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(2 * c(10), false);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Video, 40, false);
        clip.push(&mut queue, Kind::Video, 80, true);
        clip.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(
            queue
                .pop(Kind::Video)
                .map(|out| label(&out, &clip))
                .unwrap(),
            "v0"
        );
        clip.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v40", "vgap overflow 40-160", "v160"]
        );
    }

    #[test]
    fn an_overflow_in_a_lag_keeps_the_lag_s_start_and_blocks_the_audio() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(2 * c(10), true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Video, 40, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, clip.now());
        clip.push(&mut queue, Kind::Video, 80, false);
        clip.push(&mut queue, Kind::Video, 120, true);
        clip.push(&mut queue, Kind::Audio, 130, true);
        assert_eq!(drain(&mut queue, Kind::Video, &clip), ["v0", "v40"]);
        clip.push(&mut queue, Kind::Audio, 140, true);
        clip.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["vgap overflow 40-160", "v160"]
        );
        assert!(
            drain(&mut queue, Kind::Audio, &clip).is_empty(),
            "the overflow blocked the audio until the video resumed"
        );
    }

    #[test]
    fn a_frame_always_fits_a_queue_that_counts_nothing() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(0, false);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Video, 40, false);
        assert_eq!(queue.bytes(), c(10));
        assert_eq!(drain(&mut queue, Kind::Video, &clip), ["v0"]);
        clip.push(&mut queue, Kind::Video, 80, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["vgap overflow 0-80", "v80"]
        );
    }

    #[test]
    fn a_lagged_video_subscription_skips_to_its_next_keyframe_and_reports_the_gap() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Video, 40, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 5 }, clip.now());
        clip.push(&mut queue, Kind::Audio, 50, true);
        clip.push(&mut queue, Kind::Video, 240, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, clip.now());
        clip.push(&mut queue, Kind::Video, 280, true);
        clip.push(&mut queue, Kind::Video, 320, false);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v40", "vgap lagged 40-280", "v280", "v320"]
        );
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["a50"],
            "the audio did not lag"
        );
    }

    #[test]
    fn a_lagged_audio_subscription_reports_the_hole_at_its_next_frame() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        clip.push(&mut queue, Kind::Video, 0, true);
        queue.push(Kind::Audio, TrackEvent::Gap { skipped: 2 }, clip.now());
        clip.push(&mut queue, Kind::Audio, 20, false);
        queue.push(Kind::Audio, TrackEvent::Gap { skipped: 2 }, clip.now());
        clip.push(&mut queue, Kind::Audio, 80, false);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["a20", "agap lagged 20-80", "a80"],
            "a lag before the first frame only starts the track later"
        );
        assert_eq!(drain(&mut queue, Kind::Video, &clip), ["v0"]);
    }

    #[test]
    fn control_events_keep_their_place_among_the_frames() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        clip.push(&mut queue, Kind::Video, 0, true);
        queue.push(Kind::Video, TrackEvent::SourceLost, clip.now());
        queue.push(Kind::Video, TrackEvent::SourceRestored, clip.now());
        queue.push(Kind::Video, TrackEvent::EpochStart { epoch: 1 }, clip.now());
        let packet = crate::media::MediaPacket {
            arrival: clip.now(),
            rtp: crate::media::RtpHeaderFields {
                pt: 96,
                seq: 1,
                ts: 0,
                marker: true,
                ssrc: 1,
            },
            frame_start: true,
            keyframe_start: true,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0_u8; 4][..]),
        };
        queue.push(
            Kind::Video,
            TrackEvent::Packet(Arc::new(packet)),
            clip.now(),
        );
        clip.push(&mut queue, Kind::Video, 5000, true);
        let codec = Arc::new(Codec::H265 {
            vps: None,
            sps: None,
            pps: None,
        });
        queue.push(
            Kind::Video,
            TrackEvent::TrackChanged(Arc::clone(&codec)),
            clip.now(),
        );
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            [
                "v0".to_owned(),
                "vSourceLost".to_owned(),
                "vSourceRestored".to_owned(),
                "vEpochStart { epoch: 1 }".to_owned(),
                "v5000".to_owned(),
                format!("v{:?}", TrackEvent::TrackChanged(codec)),
            ],
            "a packet is no frame and is not queued"
        );
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn the_pre_roll_counts_nothing_and_the_live_frames_it_holds_are_dropped() {
        let clip = Clip::new();
        let gop = [
            clip.frame(0, true, 10),
            clip.frame(40, false, 10),
            clip.frame(80, false, 10),
        ];
        let mut queue = ReliableQueue::new(c(10), true);
        queue.preroll(Kind::Video, &snapshot(&clip, &gop, usize::MAX), clip.now());
        assert_eq!(queue.bytes(), 0, "the ring bounded the pre-roll already");
        for frame in &gop[1..] {
            queue.push(
                Kind::Video,
                TrackEvent::Frame(Arc::clone(frame)),
                clip.now(),
            );
        }
        clip.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(
            queue.bytes(),
            c(10),
            "a live frame fits a queue that counts nothing"
        );
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v40", "v80", "v120"],
            "each frame once"
        );

        // The first live frame is none of the pre-roll's, so no later one is.
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.preroll(Kind::Video, &snapshot(&clip, &gop, usize::MAX), clip.now());
        clip.push(&mut queue, Kind::Video, 80, false);
        queue.push(
            Kind::Video,
            TrackEvent::Frame(Arc::clone(&gop[2])),
            clip.now(),
        );
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v40", "v80", "v80", "v80"],
            "a frame is the pre-roll's by identity, not by its timestamp"
        );
    }

    #[test]
    fn a_truncated_pre_roll_skips_the_live_video_to_its_next_keyframe() {
        let clip = Clip::new();
        let gop = [
            clip.frame(0, true, 10),
            clip.frame(40, false, 10),
            clip.frame(80, false, 10),
        ];
        let cap = 2 * crate::preroll::PREROLL_FRAME_OVERHEAD + 20;
        let snapshot = snapshot(&clip, &gop, cap);
        assert!(snapshot.truncated());
        let mut queue = ReliableQueue::new(usize::MAX, true);
        queue.preroll(Kind::Video, &snapshot, clip.now());
        queue.push(
            Kind::Video,
            TrackEvent::Frame(Arc::clone(&gop[2])),
            clip.now(),
        );
        clip.push(&mut queue, Kind::Video, 120, false);
        clip.push(&mut queue, Kind::Audio, 130, true);
        clip.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v40", "vgap preroll_truncated 40-160", "v160"]
        );
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["a130"],
            "the video's hole is no overflow: the audio goes on"
        );
    }

    #[test]
    fn a_queued_pre_roll_is_logged_with_its_size() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let clip = Clip::new();
        let gop = [clip.frame(0, true, 10), clip.frame(40, false, 10)];
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.preroll(Kind::Video, &snapshot(&clip, &gop, usize::MAX), clip.now());
        let lines = logs.lines(tracing::Level::DEBUG, "clip queue: pre-roll queued");
        assert_eq!(
            lines
                .iter()
                .map(|line| line.fields.as_str())
                .collect::<Vec<_>>(),
            [" track=video frames=2 truncated=false"]
        );
    }

    #[test]
    fn audio_takes_its_pre_roll_only_after_the_video_s() {
        let clip = Clip::new();
        let audio = [clip.frame(0, true, 10), clip.frame(20, true, 10)];
        let mut queue = ReliableQueue::new(usize::MAX, true);
        queue.preroll(
            Kind::Audio,
            &snapshot(&clip, &audio, usize::MAX),
            clip.now(),
        );
        assert!(drain(&mut queue, Kind::Audio, &clip).is_empty());

        let video = [clip.frame(10, true, 10)];
        queue.preroll(
            Kind::Video,
            &snapshot(&clip, &video, usize::MAX),
            clip.now(),
        );
        queue.preroll(
            Kind::Audio,
            &snapshot(&clip, &audio, usize::MAX),
            clip.now(),
        );
        queue.push(
            Kind::Audio,
            TrackEvent::Frame(Arc::clone(&audio[1])),
            clip.now(),
        );
        clip.push(&mut queue, Kind::Audio, 40, true);
        assert_eq!(drain(&mut queue, Kind::Audio, &clip), ["a0", "a20", "a40"]);
        assert_eq!(drain(&mut queue, Kind::Video, &clip), ["v10"]);
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn a_track_the_clip_lacks_or_that_ended_takes_nothing() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Audio, 10, true);
        queue.push(Kind::Audio, TrackEvent::SourceLost, clip.now());
        let audio = [clip.frame(0, true, 10)];
        queue.preroll(
            Kind::Audio,
            &snapshot(&clip, &audio, usize::MAX),
            clip.now(),
        );
        assert!(drain(&mut queue, Kind::Audio, &clip).is_empty());

        clip.push(&mut queue, Kind::Video, 40, false);
        queue.end(Kind::Video);
        queue.end(Kind::Video);
        clip.push(&mut queue, Kind::Video, 80, false);
        queue.push(Kind::Video, TrackEvent::SourceLost, clip.now());
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v40"],
            "what was queued before the end still goes out"
        );
    }

    #[test]
    fn holes_are_logged_rate_limited() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(c(10), true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Video, 40, false);
        queue.push(Kind::Audio, TrackEvent::Gap { skipped: 1 }, clip.now());
        clip.push(&mut queue, Kind::Audio, 50, true);
        let _ = drain(&mut queue, Kind::Video, &clip);
        clip.push(&mut queue, Kind::Video, 80, true);
        clip.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "clip queue: full, dropping until the track can resume"
            ),
            1
        );
        let full = logs.lines(
            tracing::Level::DEBUG,
            "clip queue: full, dropping until the track can resume",
        );
        assert!(full[0].fields.starts_with(" track=video"), "{full:?}");
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "clip queue: dropping to the next frame the track can resume at"
            ),
            0
        );
        clip.advance(10_000);
        let _ = drain(&mut queue, Kind::Video, &clip);
        clip.push(&mut queue, Kind::Video, 160, true);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, clip.now());
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "clip queue: dropping to the next frame the track can resume at"
            ),
            1
        );
    }

    #[test]
    fn a_lag_on_every_frame_is_logged_at_trace_and_its_hole_once() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        clip.push(&mut queue, Kind::Video, 0, true);
        // A camera whose every other frame is over `max_frame_bytes`: each
        // drop reaches the clip as a lag of one, all in the same hole.
        for ms in [40, 80, 120] {
            queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, clip.now());
            clip.push(&mut queue, Kind::Video, ms, false);
        }
        assert_eq!(
            logs.count(tracing::Level::DEBUG, "clip queue: the subscription lagged"),
            0,
            "nothing per frame above trace"
        );
        let lines = logs.lines(tracing::Level::TRACE, "clip queue: the subscription lagged");
        assert_eq!(
            lines
                .iter()
                .map(|line| line.fields.as_str())
                .collect::<Vec<_>>(),
            [" track=video skipped=1"; 3]
        );
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "clip queue: dropping to the next frame the track can resume at"
            ),
            1
        );
    }

    #[test]
    fn gap_reasons_have_names() {
        assert_eq!(GapReason::Overflow.name(), "overflow");
        assert_eq!(GapReason::Lagged.name(), "lagged");
        assert_eq!(GapReason::PrerollTruncated.name(), "preroll_truncated");
    }

    fn interleaver(audio: bool) -> Interleaver {
        Interleaver::new(ReliableQueue::new(usize::MAX, audio), SKEW)
    }

    #[test]
    fn frames_go_out_in_capture_order_across_the_tracks() {
        let clip = Clip::new();
        let mut merged = interleaver(true);
        for (track, ms, keyframe) in [
            (Kind::Video, 0, true),
            (Kind::Video, 40, false),
            (Kind::Audio, 20, true),
            (Kind::Video, 80, false),
            (Kind::Audio, 40, true),
            (Kind::Audio, 60, true),
        ] {
            clip.push(merged.queue_mut(), track, ms, keyframe);
        }
        assert_eq!(
            release(&mut merged, &clip),
            ["v0", "a20", "v40", "a40", "a60"],
            "video first on a tie; v80 waits for the audio past 60"
        );
        assert_eq!(merged.deadline(), Some(clip.now() + SKEW));
        clip.push(merged.queue_mut(), Kind::Audio, 80, true);
        assert_eq!(
            release(&mut merged, &clip),
            ["v80", "a80"],
            "each track reached the other's capture time"
        );
        assert_eq!(merged.queue().bytes(), 0);
        assert_eq!(merged.deadline(), None);
    }

    #[test]
    fn a_frame_waits_for_the_other_track_at_most_max_skew() {
        let clip = Clip::new();
        let mut merged = interleaver(true);
        assert_eq!(merged.next(clip.now()), None);
        assert_eq!(merged.deadline(), None, "nothing queued");
        clip.push(merged.queue_mut(), Kind::Video, 500, true);
        let deadline = clip.now() + SKEW;
        assert_eq!(merged.deadline(), Some(deadline), "no audio seen yet");
        clip.advance(400);
        clip.push(merged.queue_mut(), Kind::Audio, 300, true);
        assert_eq!(
            release(&mut merged, &clip),
            ["a300"],
            "the late audio still goes first"
        );
        clip.advance(599);
        assert!(release(&mut merged, &clip).is_empty());
        assert_eq!(merged.deadline(), Some(deadline));
        clip.advance(1);
        assert_eq!(
            release(&mut merged, &clip),
            ["v500"],
            "held max_skew, no longer"
        );
        assert_eq!(merged.deadline(), None);
    }

    #[test]
    fn a_frame_goes_out_once_the_other_track_reached_its_capture_time() {
        let clip = Clip::new();
        let mut merged = interleaver(true);
        clip.push(merged.queue_mut(), Kind::Video, 0, true);
        clip.push(merged.queue_mut(), Kind::Audio, 40, true);
        assert_eq!(release(&mut merged, &clip), ["v0"]);
        clip.push(merged.queue_mut(), Kind::Video, 40, false);
        assert_eq!(release(&mut merged, &clip), ["v40", "a40"]);
        // A dropped frame passes its capture time too.
        clip.push(merged.queue_mut(), Kind::Audio, 100, true);
        merged
            .queue_mut()
            .push(Kind::Video, TrackEvent::Gap { skipped: 1 }, clip.now());
        clip.push(merged.queue_mut(), Kind::Video, 120, false);
        assert_eq!(release(&mut merged, &clip), ["a100"]);
    }

    #[test]
    fn gaps_and_control_events_go_out_as_soon_as_they_lead_their_track() {
        let clip = Clip::new();
        let mut merged = interleaver(true);
        clip.push(merged.queue_mut(), Kind::Video, 0, true);
        clip.push(merged.queue_mut(), Kind::Audio, 0, true);
        merged
            .queue_mut()
            .push(Kind::Audio, TrackEvent::Gap { skipped: 1 }, clip.now());
        clip.push(merged.queue_mut(), Kind::Audio, 200, true);
        merged
            .queue_mut()
            .push(Kind::Video, TrackEvent::EpochStart { epoch: 1 }, clip.now());
        clip.push(merged.queue_mut(), Kind::Video, 300, true);
        assert_eq!(
            release(&mut merged, &clip),
            [
                "v0",
                "vEpochStart { epoch: 1 }",
                "a0",
                "agap lagged 0-200",
                "a200"
            ],
            "v300 waits for the audio past 200"
        );
        assert_eq!(merged.deadline(), Some(clip.now() + SKEW));
    }

    #[test]
    fn an_ended_or_absent_track_is_not_waited_for() {
        let clip = Clip::new();
        let mut merged = interleaver(false);
        clip.push(merged.queue_mut(), Kind::Video, 0, true);
        assert_eq!(release(&mut merged, &clip), ["v0"], "no audio to wait for");

        let mut merged = interleaver(true);
        clip.push(merged.queue_mut(), Kind::Video, 0, true);
        clip.push(merged.queue_mut(), Kind::Audio, 0, true);
        clip.push(merged.queue_mut(), Kind::Audio, 20, true);
        clip.push(merged.queue_mut(), Kind::Video, 40, false);
        merged.queue_mut().end(Kind::Audio);
        assert_eq!(
            release(&mut merged, &clip),
            ["v0", "a0", "a20", "v40"],
            "an ended track drains and is not waited for"
        );
        clip.push(merged.queue_mut(), Kind::Video, 80, false);
        assert_eq!(release(&mut merged, &clip), ["v80"]);
    }

    #[tokio::test]
    async fn subscribing_before_the_pre_roll_loses_and_doubles_nothing() {
        let clip = Clip::new();
        let track = Arc::new(Track::new(
            TrackId::new(Kind::Video, 0),
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
            TrackLimits::default(),
            clip.now(),
        ));
        track.set_preroll(Some(Duration::from_secs(10)));
        let publish = |ms: u64, keyframe: bool| {
            assert!(track.publish_frame(MediaFrame::clone(&clip.frame(ms, keyframe, 10))));
        };
        publish(0, true);
        publish(40, false);
        let mut subscription = track.subscribe(Unit::Frames);
        publish(80, false);
        publish(120, false);
        let snapshot = track.preroll_snapshot(clip.at(0)).unwrap();
        publish(160, false);
        let mut merged = interleaver(false);
        merged
            .queue_mut()
            .preroll(Kind::Video, &snapshot, clip.now());
        for _ in 0..3 {
            let event = subscription.next().await.unwrap();
            merged.queue_mut().push(Kind::Video, event, clip.now());
        }
        assert_eq!(
            release(&mut merged, &clip),
            ["v0", "v40", "v80", "v120", "v160"]
        );
    }

    #[tokio::test]
    async fn taking_the_subscription_with_the_pre_roll_queues_no_frame_before_its_start() {
        let clip = Clip::new();
        let track = Arc::new(Track::new(
            TrackId::new(Kind::Video, 0),
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
            TrackLimits::default(),
            clip.now(),
        ));
        track.set_preroll(Some(Duration::from_secs(10)));
        let publish = |ms: u64, keyframe: bool| {
            assert!(track.publish_frame(MediaFrame::clone(&clip.frame(ms, keyframe, 10))));
        };
        publish(0, true);
        let (mut subscription, snapshot, _) = track.subscribe_from_preroll(clip.at(80));
        publish(40, false);
        publish(80, true);
        publish(120, false);
        let mut merged = interleaver(false);
        merged
            .queue_mut()
            .preroll(Kind::Video, &snapshot.unwrap(), clip.now());
        for _ in 0..3 {
            let event = subscription.next().await.unwrap();
            merged.queue_mut().push(Kind::Video, event, clip.now());
        }
        assert_eq!(release(&mut merged, &clip), ["v0", "v40", "v80", "v120"]);
    }

    /// What `subscription` has queued now, taken without waiting.
    fn queued(subscription: &mut TrackSubscription) -> Vec<TrackEvent> {
        std::iter::from_fn(|| {
            let mut next = std::pin::pin!(subscription.next());
            match next
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            {
                std::task::Poll::Ready(event) => event,
                std::task::Poll::Pending => None,
            }
        })
        .collect()
    }

    #[test]
    fn a_live_frame_the_track_drops_over_max_frame_bytes_skips_the_video_to_its_next_keyframe() {
        let clip = Clip::new();
        let track = Arc::new(Track::new(
            TrackId::new(Kind::Video, 0),
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
            TrackLimits {
                max_frame_bytes: 100,
                ..TrackLimits::default()
            },
            clip.now(),
        ));
        let (mut subscription, snapshot, _) = track.subscribe_from_preroll(clip.at(0));
        assert!(snapshot.is_none(), "no window, no pre-roll");
        let publish = |ms: u64, keyframe: bool, bytes: usize| {
            track.publish_frame(MediaFrame::clone(&clip.frame(ms, keyframe, bytes)))
        };
        assert!(publish(0, true, 10));
        assert!(publish(40, false, 10));
        assert!(!publish(80, true, 101), "dropped over max_frame_bytes");
        assert!(publish(120, false, 10));
        assert!(publish(160, true, 10));
        let mut queue = ReliableQueue::new(usize::MAX, false);
        for event in queued(&mut subscription) {
            queue.push(Kind::Video, event, clip.now());
        }
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v40", "vgap lagged 40-160", "v160"],
            "v120 refers to the lost keyframe"
        );
    }

    #[test]
    fn a_lag_the_pre_roll_covers_opens_no_hole() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let clip = Clip::new();
        let gop = [
            clip.frame(0, true, 10),
            clip.frame(40, false, 10),
            clip.frame(80, false, 10),
        ];
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.preroll(Kind::Video, &snapshot(&clip, &gop, usize::MAX), clip.now());
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 2 }, clip.now());
        queue.push(
            Kind::Video,
            TrackEvent::Frame(Arc::clone(&gop[2])),
            clip.now(),
        );
        clip.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v40", "v80", "v120"]
        );
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "clip queue: the lag fell within the pre-roll, no hole"
            ),
            1
        );
    }

    #[test]
    fn a_lag_past_the_pre_roll_still_opens_a_hole() {
        let clip = Clip::new();
        let gop = [
            clip.frame(0, true, 10),
            clip.frame(40, false, 10),
            clip.frame(80, false, 10),
        ];
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.preroll(Kind::Video, &snapshot(&clip, &gop, usize::MAX), clip.now());
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 2 }, clip.now());
        queue.push(Kind::Video, TrackEvent::SourceLost, clip.now());
        clip.push(&mut queue, Kind::Video, 120, false);
        clip.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            [
                "v0",
                "v40",
                "v80",
                "vSourceLost",
                "vgap lagged 80-160",
                "v160"
            ]
        );
    }

    #[test]
    fn control_events_no_frame_came_under_are_replaced_by_their_kind_s_newest() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(c(10), false);
        clip.push(&mut queue, Kind::Video, 0, true);
        let mut last = Arc::new(Codec::Pcmu);
        for i in 1..=500_u32 {
            queue.push(Kind::Video, TrackEvent::EpochStart { epoch: i }, clip.now());
            last = Arc::new(if i % 2 == 0 { Codec::Pcmu } else { Codec::Pcma });
            queue.push(
                Kind::Video,
                TrackEvent::TrackChanged(Arc::clone(&last)),
                clip.now(),
            );
            queue.push(Kind::Video, TrackEvent::SourceLost, clip.now());
            queue.push(Kind::Video, TrackEvent::SourceRestored, clip.now());
            clip.push(&mut queue, Kind::Video, 40 * u64::from(i), false);
        }
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            [
                "v0".to_owned(),
                "vEpochStart { epoch: 500 }".to_owned(),
                format!("v{:?}", TrackEvent::TrackChanged(last)),
                "vSourceLost".to_owned(),
                "vSourceRestored".to_owned(),
            ]
        );
        assert_eq!(queue.bytes(), 0);
    }

    /// A sink that took none of a track's frames starts it at the oldest
    /// frame its lane holds, past the control events ahead of it; none
    /// for a track that queued none.
    #[test]
    fn the_first_frame_is_the_oldest_queued_past_the_events_ahead_of_it() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        assert!(queue.first_frame(Kind::Video).is_none());
        queue.push(Kind::Video, TrackEvent::EpochStart { epoch: 1 }, clip.now());
        clip.push(&mut queue, Kind::Video, 40, true);
        clip.push(&mut queue, Kind::Video, 80, false);
        let first = |queue: &ReliableQueue| queue.first_frame(Kind::Video).map(|f| f.wallclock);
        assert_eq!(first(&queue), Some(clip.at(40)));
        assert!(queue.first_frame(Kind::Audio).is_none());
        assert_eq!(drain(&mut queue, Kind::Video, &clip).len(), 3);
        assert_eq!(first(&queue), None);
        clip.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(first(&queue), Some(clip.at(120)));
    }

    #[test]
    fn a_control_event_a_frame_came_under_stays() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        clip.push(&mut queue, Kind::Video, 0, true);
        queue.push(Kind::Video, TrackEvent::EpochStart { epoch: 1 }, clip.now());
        clip.push(&mut queue, Kind::Video, 40, false);
        queue.push(Kind::Video, TrackEvent::EpochStart { epoch: 2 }, clip.now());
        queue.push(Kind::Video, TrackEvent::EpochStart { epoch: 3 }, clip.now());
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            [
                "v0",
                "vEpochStart { epoch: 1 }",
                "v40",
                "vEpochStart { epoch: 3 }"
            ]
        );
    }

    #[test]
    fn an_overflow_after_the_video_ended_is_the_audio_s_own_hole() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(2 * c(10), true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Audio, 10, true);
        queue.end(Kind::Video);
        clip.push(&mut queue, Kind::Audio, 20, true);
        assert_eq!(drain(&mut queue, Kind::Video, &clip), ["v0"]);
        assert_eq!(drain(&mut queue, Kind::Audio, &clip), ["a10"]);
        clip.push(&mut queue, Kind::Audio, 30, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["agap overflow 10-30", "a30"]
        );
    }

    #[test]
    fn the_video_ending_in_an_overflow_hands_the_hole_to_the_audio() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(2 * c(10), true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Audio, 10, true);
        clip.push(&mut queue, Kind::Video, 40, true);
        clip.push(&mut queue, Kind::Audio, 50, true);
        queue.end(Kind::Video);
        assert_eq!(drain(&mut queue, Kind::Video, &clip), ["v0"]);
        assert_eq!(drain(&mut queue, Kind::Audio, &clip), ["a10"]);
        clip.push(&mut queue, Kind::Audio, 60, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["agap overflow 10-60", "a60"]
        );

        let mut queue = ReliableQueue::new(usize::MAX, true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Audio, 10, true);
        queue.end(Kind::Video);
        clip.push(&mut queue, Kind::Audio, 20, true);
        assert_eq!(drain(&mut queue, Kind::Audio, &clip), ["a10", "a20"]);

        let mut queue = ReliableQueue::new(usize::MAX, true);
        clip.push(&mut queue, Kind::Audio, 0, true);
        queue.end(Kind::Video);
        clip.push(&mut queue, Kind::Audio, 20, true);
        assert!(drain(&mut queue, Kind::Audio, &clip).is_empty());
    }

    #[test]
    fn ending_a_track_again_hands_no_second_overflow_hole_to_the_audio() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(2 * c(10), true);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push(&mut queue, Kind::Audio, 10, true);
        clip.push(&mut queue, Kind::Video, 40, true);
        queue.end(Kind::Video);
        assert_eq!(drain(&mut queue, Kind::Video, &clip), ["v0"]);
        assert_eq!(drain(&mut queue, Kind::Audio, &clip), ["a10"]);
        clip.push(&mut queue, Kind::Audio, 60, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["agap overflow 10-60", "a60"]
        );
        queue.end(Kind::Video);
        clip.push(&mut queue, Kind::Audio, 80, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &clip),
            ["a80"],
            "nothing was dropped after a60: the second end is no new hole"
        );
    }

    #[test]
    fn a_track_whose_capture_times_move_back_is_waited_for_from_its_latest_frame() {
        let clip = Clip::new();
        let mut merged = interleaver(true);
        clip.push(merged.queue_mut(), Kind::Video, 0, true);
        clip.push(merged.queue_mut(), Kind::Audio, 0, true);
        clip.push(merged.queue_mut(), Kind::Video, 1000, false);
        clip.push(merged.queue_mut(), Kind::Audio, 1000, true);
        assert_eq!(release(&mut merged, &clip), ["v0", "a0", "v1000", "a1000"]);
        // The mapping moves the video's capture times back, behind their
        // arrival.
        clip.push_arrived(merged.queue_mut(), Kind::Video, 960, 1010, false);
        assert_eq!(release(&mut merged, &clip), ["v960"]);
        clip.push_arrived(merged.queue_mut(), Kind::Audio, 990, 1010, true);
        assert!(
            release(&mut merged, &clip).is_empty(),
            "the video is at 960 now, not at the 1000 it had passed before"
        );
        clip.push_arrived(merged.queue_mut(), Kind::Video, 975, 1020, false);
        assert_eq!(release(&mut merged, &clip), ["v975"]);
        clip.push_arrived(merged.queue_mut(), Kind::Video, 1015, 1030, false);
        assert_eq!(
            release(&mut merged, &clip),
            ["a990"],
            "v1015 waits for the audio past 990"
        );
    }

    #[test]
    fn a_gap_after_the_capture_times_moved_back_starts_at_the_latest_frame_queued() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push_arrived(&mut queue, Kind::Video, 3_600_000, 40, false);
        clip.push(&mut queue, Kind::Video, 1020, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, clip.now());
        clip.push(&mut queue, Kind::Video, 1060, false);
        clip.push(&mut queue, Kind::Video, 1100, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v3600000", "v1020", "vgap lagged 1020-1100", "v1100"]
        );
    }

    #[test]
    fn a_gap_never_ends_before_it_starts_when_the_capture_times_move_back_in_the_hole() {
        let clip = Clip::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        clip.push(&mut queue, Kind::Video, 0, true);
        clip.push_arrived(&mut queue, Kind::Video, 3_600_000, 40, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, clip.now());
        clip.push(&mut queue, Kind::Video, 1100, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &clip),
            ["v0", "v3600000", "vgap lagged 1100-1100", "v1100"]
        );
    }

    #[test]
    fn a_frame_dated_ahead_of_its_arrival_does_not_end_the_wait_for_the_corrected_frames() {
        let clip = Clip::new();
        let mut merged = interleaver(true);
        clip.push(merged.queue_mut(), Kind::Video, 0, true);
        clip.push(merged.queue_mut(), Kind::Audio, 0, true);
        // A Sender Report maps the video an hour ahead; a later one
        // corrects it back.
        clip.push_arrived(merged.queue_mut(), Kind::Video, 3_600_000, 40, false);
        assert_eq!(release(&mut merged, &clip), ["v0", "a0"]);
        clip.advance(1000);
        assert_eq!(release(&mut merged, &clip), ["v3600000"]);
        clip.push(merged.queue_mut(), Kind::Audio, 1040, true);
        assert!(
            release(&mut merged, &clip).is_empty(),
            "the video passed its frame dated ahead's arrival only"
        );
        clip.advance(10);
        clip.push(merged.queue_mut(), Kind::Video, 1020, false);
        assert_eq!(release(&mut merged, &clip), ["v1020"], "in capture order");

        // The same with the frame dated ahead in the video's pre-roll.
        let mut merged = interleaver(true);
        let gop = [clip.frame(0, true, 10), clip.arrived(3_600_000, 40, false)];
        merged
            .queue_mut()
            .preroll(Kind::Video, &snapshot(&clip, &gop, usize::MAX), clip.now());
        clip.advance(1000);
        assert_eq!(release(&mut merged, &clip), ["v0", "v3600000"]);
        clip.push(merged.queue_mut(), Kind::Audio, 1040, true);
        assert!(release(&mut merged, &clip).is_empty());
        clip.push(merged.queue_mut(), Kind::Video, 1020, false);
        assert_eq!(release(&mut merged, &clip), ["v1020"]);
    }
}
