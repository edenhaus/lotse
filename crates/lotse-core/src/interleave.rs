//! A recording's tracks merged in capture order through a bounded reliable
//! queue: the egress contract's `Reliable` delivery and its interleaver,
//! for an output that writes a container.
//!
//! [`ReliableQueue`] takes what a recording's frame subscriptions yield (its
//! video, and its audio when it has some) the moment they yield it, and the
//! pre-record they start from, so a track's broadcast never lags for a slow
//! reader. [`Interleaver`] hands the queued items out in capture order by
//! the ring's measure ([`captured`]: a frame dated ahead of its arrival
//! counts from its arrival), the measure a recording's start, its end and the
//! interleaver's hold count by too. Both are pure: no task, no lock, no
//! clock read; every "now" is the caller's injected clock.
//!
//! Invariants: the producer never waits, so a frame that does not fit is
//! dropped, never held back. A live frame counts its payload plus
//! [`QUEUED_FRAME_OVERHEAD`] against the bound; a pre-record frame counts
//! nothing against it, since it stays counted against the stream's
//! `prerecord_bytes` until it is handed out (the queue keeps its charge, see
//! [`crate::prerecord`]), and so does what the queue keeps beside each
//! ([`QUEUED_PRERECORD_OVERHEAD`]) until the last is out; the live frames
//! the pre-record holds too are dropped, so none is written twice. The snapshot must start at a frame the track published before the
//! recording subscribed, which
//! [`Track::subscribe_from_prerecord`](crate::track::Track::subscribe_from_prerecord)
//! guarantees: a live frame published before the snapshot's start could not
//! be told from one after its newest. A lag while those frames may still
//! come is no hole if the next frame is one of them, since what was lost
//! then is the pre-record's. A frame always fits a queue that counts nothing,
//! so a frame larger than the bound cannot stall it. Video starts at a
//! keyframe and, after a hole, resumes at one; audio resumes at any frame,
//! waits for the video's first keyframe and is dropped while the queue
//! overflows, so an overflow is one hole for the recording; once the video
//! ended, an overflow is the audio's own hole, and the audio resumes at its
//! next frame that fits. A hole after a track's first frame is an explicit
//! gap, queued before the frame that ends it; one before it only starts the
//! track later. A gap or a control event counts nothing: a gap is queued
//! only before a frame, and a control event replaces one of its kind queued
//! since the track's last frame, so the items beside the frames stay
//! bounded with them. Each track's items keep their order: the
//! interleaver chooses between the tracks, never within one.

use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use crate::codec::Kind;
use crate::media::MediaFrame;
use crate::prerecord::{PrerecordCharge, PrerecordSnapshot, captured};
use crate::throttle::Throttle;
use crate::track::TrackEvent;

/// What a queued live frame costs beyond its payload: the `MediaFrame` and
/// its `Arc` counts, which the queue may be the last to hold, and the
/// queue's slot.
pub const QUEUED_FRAME_OVERHEAD: usize = size_of::<MediaFrame>()
    .saturating_add(2_usize.saturating_mul(size_of::<usize>()))
    .saturating_add(size_of::<Item>());

/// What a recording's queue keeps for each pre-record frame beside the frame and
/// its charge ([`PRERECORD_FRAME_OVERHEAD`](crate::prerecord::PRERECORD_FRAME_OVERHEAD)),
/// counted against the stream's `prerecord_bytes` while it keeps it: two of
/// its items' slots, as the queue's capacity doubles while the pre-record
/// fills it; the duplicate check's weak reference; and the frame's
/// allocation that reference keeps after the frame's last holder let it
/// go, the `MediaFrame` and its `Arc` counts. The ring holds the frames
/// in far less than this per frame, so a camera of tiny frames cannot
/// make each recording that starts from them take more than the bound says.
pub const QUEUED_PRERECORD_OVERHEAD: usize = 2_usize
    .saturating_mul(size_of::<Item>())
    .saturating_add(size_of::<Weak<MediaFrame>>())
    .saturating_add(size_of::<MediaFrame>())
    .saturating_add(2_usize.saturating_mul(size_of::<usize>()));

/// Why a track has a hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    /// The recording's queue was full: its reader is slower than the camera.
    Overflow,
    /// The recording's subscription missed frames: it fell behind the track's
    /// broadcast, or the track dropped one over `max_frame_bytes`.
    Lagged,
    /// The pre-record ring cut its newest GOP short at `prerecord_bytes` or
    /// lost a frame the track dropped over `max_frame_bytes`, so the live
    /// frames up to the next keyframe have nothing to follow.
    PrerecordTruncated,
}

impl GapReason {
    /// The name the logs use.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Overflow => "overflow",
            Self::Lagged => "lagged",
            Self::PrerecordTruncated => "prerecord_truncated",
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
    /// What it counts against the bound: nothing for a pre-record frame, a
    /// gap or a control event.
    cost: usize,
    /// A pre-record frame's charge against the stream's `prerecord_bytes`,
    /// kept until the frame is handed out, so the frames a slow recording has
    /// not written yet count there; `None` for anything else.
    charge: Option<Arc<PrerecordCharge>>,
}

impl Item {
    /// The capture time of a frame by the ring's measure ([`captured`]),
    /// what the interleaver orders by; `None` for a gap or a control
    /// event, which go out as soon as they lead their track.
    fn captured(&self) -> Option<Instant> {
        match &self.entry {
            Entry::Frame(frame) => Some(captured(frame)),
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
    /// The pre-record's frames, oldest first, while the live frames that
    /// repeat them may still come: those the track published after the
    /// recording subscribed, which the snapshot starting before the
    /// subscription makes its newest; empty once a live frame was none of
    /// them. Weak, so a frame handed out before any live frame came frees
    /// its payload with its charge; the allocation a weak reference keeps
    /// cannot be reused by a later frame, so a pointer match is still that
    /// frame.
    duplicates: Vec<Weak<MediaFrame>>,
    /// The subscription lagged while `duplicates` may still come: a hole
    /// only once the next frame is none of them, since the frames lost
    /// before one of them are the pre-record's.
    lagged: bool,
    /// The pre-record's frames still queued: those whose item has a charge.
    prerecord_left: usize,
    /// What the lane keeps for its pre-record's frames beside them, counted
    /// against the stream's `prerecord_bytes`: [`QUEUED_PRERECORD_OVERHEAD`]
    /// for each frame of its pre-record, until the last is handed out and
    /// the duplicate check is over ([`Self::settle_prerecord`]), so it
    /// counts what it keeps while it drains, a little more than it holds.
    bookkeeping: Option<PrerecordCharge>,
}

impl Lane {
    /// An empty lane; `open` when the recording has the track.
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
            prerecord_left: 0,
            bookkeeping: None,
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

    /// Whether `frame` is a live frame the pre-record already queued. The
    /// duplicates are the ones the track published after the recording
    /// subscribed: with the subscription and the snapshot taken together,
    /// at most the newest, which the track's source task held in the ring
    /// but had not broadcast yet. They come first, in order; the first
    /// frame that is none of them ends the check.
    fn is_duplicate(&mut self, frame: &Arc<MediaFrame>) -> bool {
        if let Some(at) = self
            .duplicates
            .iter()
            .rposition(|held| std::ptr::eq(held.as_ptr(), Arc::as_ptr(frame)))
        {
            self.duplicates.drain(..=at);
            self.settle_prerecord();
            true
        } else {
            self.duplicates = Vec::new();
            self.settle_prerecord();
            false
        }
    }

    /// Gives the pre-record's bookkeeping back once nothing of it is kept:
    /// its last frame handed out and its duplicate check over. The slots
    /// it grew the queue by and the check's list go with it.
    fn settle_prerecord(&mut self) {
        if self.prerecord_left == 0
            && self.duplicates.is_empty()
            && let Some(bookkeeping) = self.bookkeeping.take()
        {
            self.items.shrink_to_fit();
            self.duplicates = Vec::new();
            drop(bookkeeping);
            tracing::trace!(track = %self.kind, "recording queue: the pre-record is out");
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
                "recording queue: a control event replaces one of its kind no frame came under"
            );
            let _replaced = self.items.remove(at);
        }
        self.items.push_back(Item {
            entry: Entry::Control(event),
            queued,
            cost: 0,
            charge: None,
        });
    }

    /// Queues `frame`, which counts `cost`, with its pre-record `charge`.
    fn queue_frame(
        &mut self,
        frame: Arc<MediaFrame>,
        queued: Instant,
        cost: usize,
        charge: Option<Arc<PrerecordCharge>>,
    ) {
        self.started = true;
        self.last = Some(frame.wallclock);
        self.items.push_back(Item {
            entry: Entry::Frame(frame),
            queued,
            cost,
            charge,
        });
    }
}

/// A recording's queue: its video and audio items, bounded in bytes, with the
/// drop and gap rules of the module's invariants.
#[derive(Debug)]
pub struct ReliableQueue {
    /// The video track's lane.
    video: Lane,
    /// The audio track's lane, closed for a recording without audio.
    audio: Lane,
    /// What the queued items count.
    bytes: usize,
    /// The most `bytes` may reach (`limits.recording_queue_bytes`).
    max_bytes: usize,
    /// Rate-limits the line of a hole, which a reader stalled for long
    /// hits on every GOP.
    holes: Throttle,
}

impl ReliableQueue {
    /// An empty queue of at most `max_bytes`, for a recording with video and,
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

    /// Queues the pre-record `track` starts from, counting nothing against
    /// the queue's bound, before any live item of the track; each frame
    /// keeps its charge against the stream's `prerecord_bytes` until it is
    /// handed out: the snapshot starts at a frame published
    /// before the recording subscribed
    /// ([`Track::subscribe_from_prerecord`](crate::track::Track::subscribe_from_prerecord)),
    /// so the live frames it holds too come first and are dropped as they
    /// come; a live frame published before the snapshot's start would be
    /// queued after it, so a recording never takes a snapshot that starts later.
    /// A video snapshot starts at a keyframe; an audio one is taken only
    /// after the video's (it is ignored before), from the video snapshot's
    /// start. A truncated snapshot puts the track in a hole until its next
    /// keyframe. What the lane keeps beside the frames counts against
    /// `prerecord_bytes` too ([`QUEUED_PRERECORD_OVERHEAD`] a frame) until the
    /// last of them is handed out and no live frame can repeat one; the
    /// snapshot's own list, which the caller drops at once, does not.
    pub fn prerecord(&mut self, track: Kind, snapshot: &PrerecordSnapshot, now: Instant) {
        let blocked = track == Kind::Audio && self.video.blocks_audio();
        let lane = self.lane_mut(track);
        if !lane.open || blocked {
            tracing::debug!(%track, "recording queue: pre-record ignored, the track takes nothing now");
            return;
        }
        for held in snapshot.charged() {
            lane.reached = Some(captured(&held.frame));
            lane.queue_frame(
                Arc::clone(&held.frame),
                now,
                0,
                Some(Arc::clone(&held.charge)),
            );
        }
        lane.duplicates = snapshot.frames().map(Arc::downgrade).collect();
        lane.prerecord_left = lane.prerecord_left.saturating_add(snapshot.frame_count());
        lane.bookkeeping = Some(
            snapshot.charge(
                lane.prerecord_left
                    .saturating_mul(QUEUED_PRERECORD_OVERHEAD),
            ),
        );
        if snapshot.truncated() {
            self.hole(track, GapReason::PrerecordTruncated, now);
        }
        tracing::debug!(
            %track,
            frames = snapshot.frame_count(),
            truncated = snapshot.truncated(),
            "recording queue: pre-record queued"
        );
    }

    /// Takes what `track`'s subscription yielded at `now`. A frame is
    /// queued or dropped by the module's rules; a `Gap` (the broadcast
    /// lagged) puts the track in a hole; one while the pre-record's frames
    /// may still repeat waits for the next frame and is no hole if that
    /// frame is one of them, as what was lost then is the pre-record's; a
    /// control event is queued in its place, replacing one of its kind no
    /// frame came under. Nothing once the track ended or for a recording without
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
                tracing::trace!(%track, skipped, "recording queue: the subscription lagged");
                let lane = self.lane_mut(track);
                if lane.duplicates.is_empty() {
                    self.hole(track, GapReason::Lagged, now);
                } else {
                    lane.lagged = true;
                }
            }
            // A recording subscribes to frames, which yield no packet.
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
                tracing::debug!(%track, "recording queue: the lag fell within the pre-record, no hole");
            } else {
                self.hole(track, GapReason::Lagged, now);
            }
        }
        let lane = self.lane_mut(track);
        if duplicate || blocked || (lane.waiting() && !lane.resumes_at(&frame)) {
            tracing::trace!(%track, ts = %frame.ts, "recording queue: frame dropped");
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
                charge: None,
            });
        }
        lane.queue_frame(frame, now, cost, None);
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
                "recording queue: full, dropping until the track can resume"
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
                "recording queue: dropping to the next frame the track can resume at"
            );
        }
    }

    /// Ends `track`: its subscription ended. What it queued still goes
    /// out; nothing more is taken, and the interleaver no longer waits for
    /// it. An overflow hole the video ends in passes to the audio. Ending a
    /// track again, or one the recording lacks, does nothing, so the hole passes
    /// once.
    pub fn end(&mut self, track: Kind) {
        let lane = self.lane_mut(track);
        if !lane.open {
            return;
        }
        tracing::debug!(%track, queued = lane.items.len(), "recording queue: track ended");
        lane.open = false;
        if track == Kind::Video && self.video.overflowing() {
            // No keyframe ends the video's overflow now: the audio it
            // blocked takes the hole and resumes at its next frame.
            tracing::debug!(
                "recording queue: the video ended in an overflow, the audio takes the hole"
            );
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

    /// The oldest item `track` queued, taken out. A pre-record frame's charge
    /// goes with it: the stream's bound no longer counts what the recording
    /// writes now; with the pre-record's last frame, so does what the lane
    /// kept beside them, once the duplicate check is over too.
    pub fn pop(&mut self, track: Kind) -> Option<Out> {
        let lane = self.lane_mut(track);
        let Item {
            entry,
            cost,
            charge,
            ..
        } = lane.items.pop_front()?;
        if let Some(charge) = charge {
            drop(charge);
            lane.prerecord_left = lane.prerecord_left.saturating_sub(1);
            lane.settle_prerecord();
        }
        self.bytes = self.bytes.saturating_sub(cost);
        Some(match entry {
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
/// time with its latest frame (taken back when a Sender Report moves the
/// capture times back), for at most `max_skew` after it was queued. So an
/// audio path that delivers late still lands in order, and a track that
/// stops sending delays the other by `max_skew` at most. Capture times are
/// the ring's measure ([`captured`]), the one a recording starts and ends by: a
/// frame dated ahead of its arrival (RFC 3550 §6.4.1, a Sender Report
/// mapping off) counts from its arrival, so a frame at a recording's end goes
/// out only after the other track's frames captured before it, which by
/// their dates went out behind it. A gap or a control event goes out as
/// soon as it leads its track (video's first), so a sink learns of it
/// before it writes the frames that follow it.
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
                .is_some_and(|item| item.captured().is_none())
        }) {
            return Some((lane.kind, None));
        }
        let (lead, at, queued) = lanes
            .iter()
            .filter_map(|lane| {
                let item = lane.items.front()?;
                Some((lane.kind, item.captured()?, item.queued))
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
    use crate::prerecord::{PRERECORD_FRAME_OVERHEAD, Prerecord};
    use crate::track::{Track, TrackId, TrackLimits, TrackSubscription, Unit};

    const SKEW: Duration = Duration::from_secs(1);

    /// What a queued live frame of `bytes` payload counts.
    const fn c(bytes: usize) -> usize {
        bytes + QUEUED_FRAME_OVERHEAD
    }

    /// Frames are labelled by their capture time: `ts` is the
    /// milliseconds after the clock's start, which is also how far after it
    /// they were captured. `now` is the fake clock's reading.
    struct Recording {
        clock: FakeClock,
        t0: Instant,
    }

    impl Recording {
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
    fn drain(queue: &mut ReliableQueue, track: Kind, recording: &Recording) -> Vec<String> {
        std::iter::from_fn(|| queue.pop(track))
            .map(|out| label(&out, recording))
            .collect()
    }

    fn label(out: &Out, recording: &Recording) -> String {
        let ms = |at: Instant| at.duration_since(recording.t0).as_millis();
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

    /// Everything the interleaver hands out at the recording's `now`.
    fn release(interleaver: &mut Interleaver, recording: &Recording) -> Vec<String> {
        std::iter::from_fn(|| interleaver.next(recording.now()))
            .map(|out| label(&out, recording))
            .collect()
    }

    /// A video ring holding `frames` (ms, keyframe), and its snapshot from
    /// the first; `cap` bounds it.
    fn snapshot(
        recording: &Recording,
        frames: &[Arc<MediaFrame>],
        cap: usize,
    ) -> PrerecordSnapshot {
        let mut ring = Prerecord::new(frames.first().unwrap().keyframe, Arc::default());
        ring.set_window(Some(Duration::from_secs(60)));
        for frame in frames {
            let _ = ring.push(frame, cap, || None);
        }
        ring.snapshot(recording.at(0)).unwrap()
    }

    #[test]
    fn live_frames_queue_in_order_and_count_against_the_bound() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Audio, 10, true);
        recording.push(&mut queue, Kind::Video, 40, false);
        assert_eq!(queue.bytes(), 3 * c(10));
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v0", "v40"]);
        assert_eq!(queue.bytes(), c(10), "a popped frame no longer counts");
        assert_eq!(drain(&mut queue, Kind::Audio, &recording), ["a10"]);
        assert_eq!(queue.bytes(), 0);
        assert_eq!(queue.pop(Kind::Video), None);
    }

    #[test]
    fn video_waits_for_its_first_keyframe_and_audio_for_the_video() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        recording.push(&mut queue, Kind::Audio, 0, true);
        recording.push(&mut queue, Kind::Video, 20, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 3 }, recording.now());
        recording.push(&mut queue, Kind::Video, 40, true);
        recording.push(&mut queue, Kind::Audio, 30, false);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v40"],
            "a lag before the first keyframe is no gap: the track starts later"
        );
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["a30"],
            "audio after the video's start, captured before it or not, whatever its keyframe flag"
        );
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn an_overflow_drops_every_track_to_the_next_video_keyframe_with_one_gap() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(3 * c(10), true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Audio, 10, true);
        recording.push(&mut queue, Kind::Video, 40, false);
        assert_eq!(queue.bytes(), 3 * c(10), "an exact fit is kept");
        recording.push(&mut queue, Kind::Audio, 50, true);
        recording.push(&mut queue, Kind::Video, 80, false);
        assert_eq!(queue.bytes(), 3 * c(10));
        assert_eq!(drain(&mut queue, Kind::Audio, &recording), ["a10"]);
        recording.push(&mut queue, Kind::Audio, 90, true);
        recording.push(&mut queue, Kind::Video, 120, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, recording.now());
        assert_eq!(queue.bytes(), 2 * c(10), "dropped though it would fit now");
        recording.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40", "vgap overflow 40-160", "v160"],
            "one gap, from the last frame held, an overflow's though the video lagged in it"
        );
        recording.push(&mut queue, Kind::Audio, 170, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["a170"],
            "the audio went with the video's hole and reports none of its own"
        );
    }

    #[test]
    fn a_keyframe_that_does_not_fit_keeps_the_hole_open() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(2 * c(10), false);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Video, 40, false);
        recording.push(&mut queue, Kind::Video, 80, true);
        recording.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(
            queue
                .pop(Kind::Video)
                .map(|out| label(&out, &recording))
                .unwrap(),
            "v0"
        );
        recording.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v40", "vgap overflow 40-160", "v160"]
        );
    }

    #[test]
    fn an_overflow_in_a_lag_keeps_the_lag_s_start_and_blocks_the_audio() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(2 * c(10), true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Video, 40, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, recording.now());
        recording.push(&mut queue, Kind::Video, 80, false);
        recording.push(&mut queue, Kind::Video, 120, true);
        recording.push(&mut queue, Kind::Audio, 130, true);
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v0", "v40"]);
        recording.push(&mut queue, Kind::Audio, 140, true);
        recording.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["vgap overflow 40-160", "v160"]
        );
        assert!(
            drain(&mut queue, Kind::Audio, &recording).is_empty(),
            "the overflow blocked the audio until the video resumed"
        );
    }

    #[test]
    fn a_frame_always_fits_a_queue_that_counts_nothing() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(0, false);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Video, 40, false);
        assert_eq!(queue.bytes(), c(10));
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v0"]);
        recording.push(&mut queue, Kind::Video, 80, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["vgap overflow 0-80", "v80"]
        );
    }

    #[test]
    fn a_lagged_video_subscription_skips_to_its_next_keyframe_and_reports_the_gap() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Video, 40, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 5 }, recording.now());
        recording.push(&mut queue, Kind::Audio, 50, true);
        recording.push(&mut queue, Kind::Video, 240, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, recording.now());
        recording.push(&mut queue, Kind::Video, 280, true);
        recording.push(&mut queue, Kind::Video, 320, false);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40", "vgap lagged 40-280", "v280", "v320"]
        );
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["a50"],
            "the audio did not lag"
        );
    }

    #[test]
    fn a_lagged_audio_subscription_reports_the_hole_at_its_next_frame() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        recording.push(&mut queue, Kind::Video, 0, true);
        queue.push(Kind::Audio, TrackEvent::Gap { skipped: 2 }, recording.now());
        recording.push(&mut queue, Kind::Audio, 20, false);
        queue.push(Kind::Audio, TrackEvent::Gap { skipped: 2 }, recording.now());
        recording.push(&mut queue, Kind::Audio, 80, false);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["a20", "agap lagged 20-80", "a80"],
            "a lag before the first frame only starts the track later"
        );
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v0"]);
    }

    #[test]
    fn control_events_keep_their_place_among_the_frames() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        recording.push(&mut queue, Kind::Video, 0, true);
        queue.push(Kind::Video, TrackEvent::SourceLost, recording.now());
        queue.push(Kind::Video, TrackEvent::SourceRestored, recording.now());
        queue.push(
            Kind::Video,
            TrackEvent::EpochStart { epoch: 1 },
            recording.now(),
        );
        let packet = crate::media::MediaPacket {
            arrival: recording.now(),
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
            recording.now(),
        );
        recording.push(&mut queue, Kind::Video, 5000, true);
        let codec = Arc::new(Codec::H265 {
            vps: None,
            sps: None,
            pps: None,
        });
        queue.push(
            Kind::Video,
            TrackEvent::TrackChanged(Arc::clone(&codec)),
            recording.now(),
        );
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
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
    fn the_pre_record_stays_counted_against_the_stream_until_it_is_handed_out() {
        let recording = Recording::new();
        let shared = Arc::default();
        let mut ring = Prerecord::new(true, Arc::clone(&shared));
        ring.set_window(Some(Duration::from_secs(60)));
        let one = 10 + PRERECORD_FRAME_OVERHEAD;
        let kept = 3 * QUEUED_PRERECORD_OVERHEAD;
        let cap = 4 * one + kept;
        for frame in [
            recording.frame(0, true, 10),
            recording.frame(40, false, 10),
            recording.frame(80, false, 10),
        ] {
            assert_eq!(ring.push(&frame, cap, || None), None);
        }
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &ring.snapshot(recording.at(0)).unwrap(),
            recording.now(),
        );
        assert_eq!(queue.bytes(), 0, "nothing against the queue's bound");
        assert_eq!(
            shared.held(),
            3 * one + kept,
            "the snapshot is gone, the queue holds them"
        );
        // The ring moves on: dropping the GOP the queue holds frees nothing,
        // so the next GOP is cut short instead.
        assert_eq!(
            ring.push(&recording.frame(120, true, 10), cap, || None),
            None
        );
        assert!(
            ring.push(&recording.frame(160, false, 10), cap, || None)
                .is_some()
        );
        assert_eq!(ring.stats().unwrap().truncations, 1);
        assert_eq!(shared.held(), cap);
        assert!(queue.pop(Kind::Video).is_some());
        assert_eq!(
            shared.held(),
            3 * one + kept,
            "the frame handed out gave its charge back"
        );
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v40", "v80"]);
        assert_eq!(
            shared.held(),
            one + kept,
            "the ring's keyframe, and the duplicate check's references"
        );

        queue.prerecord(
            Kind::Video,
            &ring.snapshot(recording.at(0)).unwrap(),
            recording.now(),
        );
        assert!(ring.clear());
        assert_eq!(
            shared.held(),
            one + QUEUED_PRERECORD_OVERHEAD,
            "the queue holds the keyframe, and keeps one frame's references"
        );
        drop(queue);
        assert_eq!(shared.held(), 0, "a queue that goes gives its charges back");
    }

    /// Regression: the duplicate check kept the snapshot's frames alive, so
    /// a queue that handed them out before any live frame came left their
    /// payloads allocated with their charges given back.
    #[test]
    fn a_pre_record_handed_out_before_a_live_frame_frees_its_payloads() {
        let recording = Recording::new();
        let shared = Arc::default();
        let mut ring = Prerecord::new(true, Arc::clone(&shared));
        ring.set_window(Some(Duration::from_secs(60)));
        let frames = [recording.frame(0, true, 10), recording.frame(40, false, 10)];
        for frame in &frames {
            assert_eq!(ring.push(frame, usize::MAX, || None), None);
        }
        let held: Vec<_> = frames.iter().map(Arc::downgrade).collect();
        drop(frames);
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &ring.snapshot(recording.at(0)).unwrap(),
            recording.now(),
        );
        assert!(ring.clear());
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v0", "v40"]);
        assert_eq!(
            shared.held(),
            2 * QUEUED_PRERECORD_OVERHEAD,
            "the duplicate check's references stay counted"
        );
        assert!(
            held.iter().all(|frame| frame.upgrade().is_none()),
            "no frame outlives its charge"
        );
    }

    /// Regression: a recording's queue kept an item and a weak reference for
    /// each pre-record frame uncounted, so a camera of tiny frames, whose
    /// ring held millions of them within the bound, had each recording from it
    /// take hundreds of megabytes beside the bound.
    #[test]
    fn what_the_queue_keeps_beside_the_pre_roll_counts_against_the_stream_until_it_is_out() {
        let recording = Recording::new();
        let shared = Arc::default();
        let mut ring = Prerecord::new(true, Arc::clone(&shared));
        ring.set_window(Some(Duration::from_secs(60)));
        let one = 10 + PRERECORD_FRAME_OVERHEAD;
        let gop = [
            recording.frame(0, true, 10),
            recording.frame(40, false, 10),
            recording.frame(80, false, 10),
        ];
        for frame in &gop {
            assert_eq!(ring.push(frame, usize::MAX, || None), None);
        }
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &ring.snapshot(recording.at(0)).unwrap(),
            recording.now(),
        );
        let kept = 3 * QUEUED_PRERECORD_OVERHEAD;
        assert!(kept >= one, "more than a frame the ring holds");
        assert_eq!(shared.held(), 3 * one + kept);

        // The ring holds that much less: with room for one more frame
        // beside the queue's, the next GOP keeps only its keyframe.
        assert!(ring.clear());
        let cap = 3 * one + kept + one;
        assert_eq!(
            ring.push(&recording.frame(120, true, 10), cap, || None),
            None
        );
        assert!(
            ring.push(&recording.frame(160, false, 10), cap, || None)
                .is_some()
        );
        assert_eq!(shared.held(), cap);

        // The frames handed out give their charges back; what the queue
        // keeps stays while a live frame may still repeat one of them.
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40", "v80"]
        );
        assert_eq!(shared.held(), one + kept);
        recording.push(&mut queue, Kind::Video, 200, false);
        assert_eq!(shared.held(), one, "the ring's keyframe alone");
        assert_eq!(queue.video.duplicates.capacity(), 0);
    }

    /// A live frame that ends the duplicate check before the pre-record is
    /// out leaves what the queue keeps beside the pre-record counted until
    /// its last frame is out, and frees the slots the pre-record grew the
    /// queue by with it.
    #[test]
    fn what_the_queue_keeps_beside_the_pre_roll_goes_with_its_last_frame() {
        let recording = Recording::new();
        let shared = Arc::default();
        let gop: Vec<_> = (0..8)
            .map(|i| recording.frame(1000 + 40 * i, i == 0, 10))
            .collect();
        let mut ring = Prerecord::new(true, Arc::clone(&shared));
        ring.set_window(Some(Duration::from_secs(60)));
        for frame in &gop {
            assert_eq!(ring.push(frame, usize::MAX, || None), None);
        }
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &ring.snapshot(recording.at(1000)).unwrap(),
            recording.now(),
        );
        let held = shared.held();
        recording.push(&mut queue, Kind::Video, 2000, false);
        assert_eq!(shared.held(), held, "the pre-record is still queued");
        for _ in 0..7 {
            assert!(queue.pop(Kind::Video).is_some());
        }
        assert_eq!(shared.held(), held, "one pre-record frame is left");
        assert!(queue.video.items.capacity() >= 8);
        assert!(queue.pop(Kind::Video).is_some());
        assert_eq!(shared.held(), held - 8 * QUEUED_PRERECORD_OVERHEAD);
        assert!(queue.video.items.capacity() < 8, "its slots are freed");
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v2000"]);

        // A queue that goes gives it back too.
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &ring.snapshot(recording.at(1000)).unwrap(),
            recording.now(),
        );
        assert_eq!(shared.held(), held);
        drop(queue);
        assert_eq!(shared.held(), held - 8 * QUEUED_PRERECORD_OVERHEAD);
    }

    #[test]
    fn the_pre_record_counts_nothing_and_the_live_frames_it_holds_are_dropped() {
        let recording = Recording::new();
        let gop = [
            recording.frame(0, true, 10),
            recording.frame(40, false, 10),
            recording.frame(80, false, 10),
        ];
        let mut queue = ReliableQueue::new(c(10), true);
        queue.prerecord(
            Kind::Video,
            &snapshot(&recording, &gop, usize::MAX),
            recording.now(),
        );
        assert_eq!(queue.bytes(), 0, "the ring bounded the pre-record already");
        for frame in &gop[1..] {
            queue.push(
                Kind::Video,
                TrackEvent::Frame(Arc::clone(frame)),
                recording.now(),
            );
        }
        recording.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(
            queue.bytes(),
            c(10),
            "a live frame fits a queue that counts nothing"
        );
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40", "v80", "v120"],
            "each frame once"
        );

        // The first live frame is none of the pre-record's, so no later one is.
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &snapshot(&recording, &gop, usize::MAX),
            recording.now(),
        );
        recording.push(&mut queue, Kind::Video, 80, false);
        queue.push(
            Kind::Video,
            TrackEvent::Frame(Arc::clone(&gop[2])),
            recording.now(),
        );
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40", "v80", "v80", "v80"],
            "a frame is the pre-record's by identity, not by its timestamp"
        );
    }

    #[test]
    fn a_truncated_pre_record_skips_the_live_video_to_its_next_keyframe() {
        let recording = Recording::new();
        let gop = [
            recording.frame(0, true, 10),
            recording.frame(40, false, 10),
            recording.frame(80, false, 10),
        ];
        let cap = 2 * PRERECORD_FRAME_OVERHEAD + 20;
        let snapshot = snapshot(&recording, &gop, cap);
        assert!(snapshot.truncated());
        let mut queue = ReliableQueue::new(usize::MAX, true);
        queue.prerecord(Kind::Video, &snapshot, recording.now());
        queue.push(
            Kind::Video,
            TrackEvent::Frame(Arc::clone(&gop[2])),
            recording.now(),
        );
        recording.push(&mut queue, Kind::Video, 120, false);
        recording.push(&mut queue, Kind::Audio, 130, true);
        recording.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40", "vgap prerecord_truncated 40-160", "v160"]
        );
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["a130"],
            "the video's hole is no overflow: the audio goes on"
        );
    }

    #[test]
    fn a_queued_pre_record_is_logged_with_its_size() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let recording = Recording::new();
        let gop = [recording.frame(0, true, 10), recording.frame(40, false, 10)];
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &snapshot(&recording, &gop, usize::MAX),
            recording.now(),
        );
        let lines = logs.lines(tracing::Level::DEBUG, "recording queue: pre-record queued");
        assert_eq!(
            lines
                .iter()
                .map(|line| line.fields.as_str())
                .collect::<Vec<_>>(),
            [" track=video frames=2 truncated=false"]
        );
    }

    #[test]
    fn audio_takes_its_pre_record_only_after_the_video_s() {
        let recording = Recording::new();
        let audio = [recording.frame(0, true, 10), recording.frame(20, true, 10)];
        let mut queue = ReliableQueue::new(usize::MAX, true);
        queue.prerecord(
            Kind::Audio,
            &snapshot(&recording, &audio, usize::MAX),
            recording.now(),
        );
        assert!(drain(&mut queue, Kind::Audio, &recording).is_empty());

        let video = [recording.frame(10, true, 10)];
        queue.prerecord(
            Kind::Video,
            &snapshot(&recording, &video, usize::MAX),
            recording.now(),
        );
        queue.prerecord(
            Kind::Audio,
            &snapshot(&recording, &audio, usize::MAX),
            recording.now(),
        );
        queue.push(
            Kind::Audio,
            TrackEvent::Frame(Arc::clone(&audio[1])),
            recording.now(),
        );
        recording.push(&mut queue, Kind::Audio, 40, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["a0", "a20", "a40"]
        );
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v10"]);
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn a_track_the_recording_lacks_or_that_ended_takes_nothing() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Audio, 10, true);
        queue.push(Kind::Audio, TrackEvent::SourceLost, recording.now());
        let audio = [recording.frame(0, true, 10)];
        queue.prerecord(
            Kind::Audio,
            &snapshot(&recording, &audio, usize::MAX),
            recording.now(),
        );
        assert!(drain(&mut queue, Kind::Audio, &recording).is_empty());

        recording.push(&mut queue, Kind::Video, 40, false);
        queue.end(Kind::Video);
        queue.end(Kind::Video);
        recording.push(&mut queue, Kind::Video, 80, false);
        queue.push(Kind::Video, TrackEvent::SourceLost, recording.now());
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40"],
            "what was queued before the end still goes out"
        );
    }

    #[test]
    fn holes_are_logged_rate_limited() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(c(10), true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Video, 40, false);
        queue.push(Kind::Audio, TrackEvent::Gap { skipped: 1 }, recording.now());
        recording.push(&mut queue, Kind::Audio, 50, true);
        let _ = drain(&mut queue, Kind::Video, &recording);
        recording.push(&mut queue, Kind::Video, 80, true);
        recording.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "recording queue: full, dropping until the track can resume"
            ),
            1
        );
        let full = logs.lines(
            tracing::Level::DEBUG,
            "recording queue: full, dropping until the track can resume",
        );
        assert!(full[0].fields.starts_with(" track=video"), "{full:?}");
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "recording queue: dropping to the next frame the track can resume at"
            ),
            0
        );
        recording.advance(10_000);
        let _ = drain(&mut queue, Kind::Video, &recording);
        recording.push(&mut queue, Kind::Video, 160, true);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, recording.now());
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "recording queue: dropping to the next frame the track can resume at"
            ),
            1
        );
    }

    #[test]
    fn a_lag_on_every_frame_is_logged_at_trace_and_its_hole_once() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        recording.push(&mut queue, Kind::Video, 0, true);
        // A camera whose every other frame is over `max_frame_bytes`: each
        // drop reaches the recording as a lag of one, all in the same hole.
        for ms in [40, 80, 120] {
            queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, recording.now());
            recording.push(&mut queue, Kind::Video, ms, false);
        }
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "recording queue: the subscription lagged"
            ),
            0,
            "nothing per frame above trace"
        );
        let lines = logs.lines(
            tracing::Level::TRACE,
            "recording queue: the subscription lagged",
        );
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
                "recording queue: dropping to the next frame the track can resume at"
            ),
            1
        );
    }

    #[test]
    fn gap_reasons_have_names() {
        assert_eq!(GapReason::Overflow.name(), "overflow");
        assert_eq!(GapReason::Lagged.name(), "lagged");
        assert_eq!(GapReason::PrerecordTruncated.name(), "prerecord_truncated");
    }

    fn interleaver(audio: bool) -> Interleaver {
        Interleaver::new(ReliableQueue::new(usize::MAX, audio), SKEW)
    }

    #[test]
    fn frames_go_out_in_capture_order_across_the_tracks() {
        let recording = Recording::new();
        let mut merged = interleaver(true);
        for (track, ms, keyframe) in [
            (Kind::Video, 0, true),
            (Kind::Video, 40, false),
            (Kind::Audio, 20, true),
            (Kind::Video, 80, false),
            (Kind::Audio, 40, true),
            (Kind::Audio, 60, true),
        ] {
            recording.push(merged.queue_mut(), track, ms, keyframe);
        }
        assert_eq!(
            release(&mut merged, &recording),
            ["v0", "a20", "v40", "a40", "a60"],
            "video first on a tie; v80 waits for the audio past 60"
        );
        assert_eq!(merged.deadline(), Some(recording.now() + SKEW));
        recording.push(merged.queue_mut(), Kind::Audio, 80, true);
        assert_eq!(
            release(&mut merged, &recording),
            ["v80", "a80"],
            "each track reached the other's capture time"
        );
        assert_eq!(merged.queue().bytes(), 0);
        assert_eq!(merged.deadline(), None);
    }

    #[test]
    fn a_frame_waits_for_the_other_track_at_most_max_skew() {
        let recording = Recording::new();
        let mut merged = interleaver(true);
        assert_eq!(merged.next(recording.now()), None);
        assert_eq!(merged.deadline(), None, "nothing queued");
        recording.push(merged.queue_mut(), Kind::Video, 500, true);
        let deadline = recording.now() + SKEW;
        assert_eq!(merged.deadline(), Some(deadline), "no audio seen yet");
        recording.advance(400);
        recording.push(merged.queue_mut(), Kind::Audio, 300, true);
        assert_eq!(
            release(&mut merged, &recording),
            ["a300"],
            "the late audio still goes first"
        );
        recording.advance(599);
        assert!(release(&mut merged, &recording).is_empty());
        assert_eq!(merged.deadline(), Some(deadline));
        recording.advance(1);
        assert_eq!(
            release(&mut merged, &recording),
            ["v500"],
            "held max_skew, no longer"
        );
        assert_eq!(merged.deadline(), None);
    }

    #[test]
    fn a_frame_goes_out_once_the_other_track_reached_its_capture_time() {
        let recording = Recording::new();
        let mut merged = interleaver(true);
        recording.push(merged.queue_mut(), Kind::Video, 0, true);
        recording.push(merged.queue_mut(), Kind::Audio, 40, true);
        assert_eq!(release(&mut merged, &recording), ["v0"]);
        recording.push(merged.queue_mut(), Kind::Video, 40, false);
        assert_eq!(release(&mut merged, &recording), ["v40", "a40"]);
        // A dropped frame passes its capture time too.
        recording.push(merged.queue_mut(), Kind::Audio, 100, true);
        merged
            .queue_mut()
            .push(Kind::Video, TrackEvent::Gap { skipped: 1 }, recording.now());
        recording.push(merged.queue_mut(), Kind::Video, 120, false);
        assert_eq!(release(&mut merged, &recording), ["a100"]);
    }

    #[test]
    fn gaps_and_control_events_go_out_as_soon_as_they_lead_their_track() {
        let recording = Recording::new();
        let mut merged = interleaver(true);
        recording.push(merged.queue_mut(), Kind::Video, 0, true);
        recording.push(merged.queue_mut(), Kind::Audio, 0, true);
        merged
            .queue_mut()
            .push(Kind::Audio, TrackEvent::Gap { skipped: 1 }, recording.now());
        recording.push(merged.queue_mut(), Kind::Audio, 200, true);
        merged.queue_mut().push(
            Kind::Video,
            TrackEvent::EpochStart { epoch: 1 },
            recording.now(),
        );
        recording.push(merged.queue_mut(), Kind::Video, 300, true);
        assert_eq!(
            release(&mut merged, &recording),
            [
                "v0",
                "vEpochStart { epoch: 1 }",
                "a0",
                "agap lagged 0-200",
                "a200"
            ],
            "v300 waits for the audio past 200"
        );
        assert_eq!(merged.deadline(), Some(recording.now() + SKEW));
    }

    #[test]
    fn an_ended_or_absent_track_is_not_waited_for() {
        let recording = Recording::new();
        let mut merged = interleaver(false);
        recording.push(merged.queue_mut(), Kind::Video, 0, true);
        assert_eq!(
            release(&mut merged, &recording),
            ["v0"],
            "no audio to wait for"
        );

        let mut merged = interleaver(true);
        recording.push(merged.queue_mut(), Kind::Video, 0, true);
        recording.push(merged.queue_mut(), Kind::Audio, 0, true);
        recording.push(merged.queue_mut(), Kind::Audio, 20, true);
        recording.push(merged.queue_mut(), Kind::Video, 40, false);
        merged.queue_mut().end(Kind::Audio);
        assert_eq!(
            release(&mut merged, &recording),
            ["v0", "a0", "a20", "v40"],
            "an ended track drains and is not waited for"
        );
        recording.push(merged.queue_mut(), Kind::Video, 80, false);
        assert_eq!(release(&mut merged, &recording), ["v80"]);
    }

    #[tokio::test]
    async fn subscribing_before_the_pre_record_loses_and_doubles_nothing() {
        let recording = Recording::new();
        let track = Arc::new(Track::new(
            TrackId::new(Kind::Video, 0),
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
            TrackLimits::default(),
            recording.now(),
        ));
        track.set_prerecord(Some(Duration::from_secs(10)));
        let publish = |ms: u64, keyframe: bool| {
            assert!(track.publish_frame(MediaFrame::clone(&recording.frame(ms, keyframe, 10))));
        };
        publish(0, true);
        publish(40, false);
        let mut subscription = track.subscribe(Unit::Frames);
        publish(80, false);
        publish(120, false);
        let snapshot = track.prerecord_snapshot(recording.at(0)).unwrap();
        publish(160, false);
        let mut merged = interleaver(false);
        merged
            .queue_mut()
            .prerecord(Kind::Video, &snapshot, recording.now());
        for _ in 0..3 {
            let event = subscription.next().await.unwrap();
            merged.queue_mut().push(Kind::Video, event, recording.now());
        }
        assert_eq!(
            release(&mut merged, &recording),
            ["v0", "v40", "v80", "v120", "v160"]
        );
    }

    #[tokio::test]
    async fn taking_the_subscription_with_the_pre_record_queues_no_frame_before_its_start() {
        let recording = Recording::new();
        let track = Arc::new(Track::new(
            TrackId::new(Kind::Video, 0),
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
            TrackLimits::default(),
            recording.now(),
        ));
        track.set_prerecord(Some(Duration::from_secs(10)));
        let publish = |ms: u64, keyframe: bool| {
            assert!(track.publish_frame(MediaFrame::clone(&recording.frame(ms, keyframe, 10))));
        };
        publish(0, true);
        let (mut subscription, snapshot, _, _) = track.subscribe_from_prerecord(recording.at(80));
        publish(40, false);
        publish(80, true);
        publish(120, false);
        let mut merged = interleaver(false);
        merged
            .queue_mut()
            .prerecord(Kind::Video, &snapshot.unwrap(), recording.now());
        for _ in 0..3 {
            let event = subscription.next().await.unwrap();
            merged.queue_mut().push(Kind::Video, event, recording.now());
        }
        assert_eq!(
            release(&mut merged, &recording),
            ["v0", "v40", "v80", "v120"]
        );
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
        let recording = Recording::new();
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
            recording.now(),
        ));
        let (mut subscription, snapshot, _, _) = track.subscribe_from_prerecord(recording.at(0));
        assert!(snapshot.is_none(), "no window, no pre-record");
        let publish = |ms: u64, keyframe: bool, bytes: usize| {
            track.publish_frame(MediaFrame::clone(&recording.frame(ms, keyframe, bytes)))
        };
        assert!(publish(0, true, 10));
        assert!(publish(40, false, 10));
        assert!(!publish(80, true, 101), "dropped over max_frame_bytes");
        assert!(publish(120, false, 10));
        assert!(publish(160, true, 10));
        let mut queue = ReliableQueue::new(usize::MAX, false);
        for event in queued(&mut subscription) {
            queue.push(Kind::Video, event, recording.now());
        }
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40", "vgap lagged 40-160", "v160"],
            "v120 refers to the lost keyframe"
        );
    }

    #[test]
    fn a_lag_the_pre_record_covers_opens_no_hole() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let recording = Recording::new();
        let gop = [
            recording.frame(0, true, 10),
            recording.frame(40, false, 10),
            recording.frame(80, false, 10),
        ];
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &snapshot(&recording, &gop, usize::MAX),
            recording.now(),
        );
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 2 }, recording.now());
        queue.push(
            Kind::Video,
            TrackEvent::Frame(Arc::clone(&gop[2])),
            recording.now(),
        );
        recording.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v40", "v80", "v120"]
        );
        assert_eq!(
            logs.count(
                tracing::Level::DEBUG,
                "recording queue: the lag fell within the pre-record, no hole"
            ),
            1
        );
    }

    #[test]
    fn a_lag_past_the_pre_record_still_opens_a_hole() {
        let recording = Recording::new();
        let gop = [
            recording.frame(0, true, 10),
            recording.frame(40, false, 10),
            recording.frame(80, false, 10),
        ];
        let mut queue = ReliableQueue::new(usize::MAX, false);
        queue.prerecord(
            Kind::Video,
            &snapshot(&recording, &gop, usize::MAX),
            recording.now(),
        );
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 2 }, recording.now());
        queue.push(Kind::Video, TrackEvent::SourceLost, recording.now());
        recording.push(&mut queue, Kind::Video, 120, false);
        recording.push(&mut queue, Kind::Video, 160, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
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
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(c(10), false);
        recording.push(&mut queue, Kind::Video, 0, true);
        let mut last = Arc::new(Codec::Pcmu);
        for i in 1..=500_u32 {
            queue.push(
                Kind::Video,
                TrackEvent::EpochStart { epoch: i },
                recording.now(),
            );
            last = Arc::new(if i % 2 == 0 { Codec::Pcmu } else { Codec::Pcma });
            queue.push(
                Kind::Video,
                TrackEvent::TrackChanged(Arc::clone(&last)),
                recording.now(),
            );
            queue.push(Kind::Video, TrackEvent::SourceLost, recording.now());
            queue.push(Kind::Video, TrackEvent::SourceRestored, recording.now());
            recording.push(&mut queue, Kind::Video, 40 * u64::from(i), false);
        }
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
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
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, true);
        assert!(queue.first_frame(Kind::Video).is_none());
        queue.push(
            Kind::Video,
            TrackEvent::EpochStart { epoch: 1 },
            recording.now(),
        );
        recording.push(&mut queue, Kind::Video, 40, true);
        recording.push(&mut queue, Kind::Video, 80, false);
        let first = |queue: &ReliableQueue| queue.first_frame(Kind::Video).map(|f| f.wallclock);
        assert_eq!(first(&queue), Some(recording.at(40)));
        assert!(queue.first_frame(Kind::Audio).is_none());
        assert_eq!(drain(&mut queue, Kind::Video, &recording).len(), 3);
        assert_eq!(first(&queue), None);
        recording.push(&mut queue, Kind::Video, 120, false);
        assert_eq!(first(&queue), Some(recording.at(120)));
    }

    #[test]
    fn a_control_event_a_frame_came_under_stays() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        recording.push(&mut queue, Kind::Video, 0, true);
        queue.push(
            Kind::Video,
            TrackEvent::EpochStart { epoch: 1 },
            recording.now(),
        );
        recording.push(&mut queue, Kind::Video, 40, false);
        queue.push(
            Kind::Video,
            TrackEvent::EpochStart { epoch: 2 },
            recording.now(),
        );
        queue.push(
            Kind::Video,
            TrackEvent::EpochStart { epoch: 3 },
            recording.now(),
        );
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
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
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(2 * c(10), true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Audio, 10, true);
        queue.end(Kind::Video);
        recording.push(&mut queue, Kind::Audio, 20, true);
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v0"]);
        assert_eq!(drain(&mut queue, Kind::Audio, &recording), ["a10"]);
        recording.push(&mut queue, Kind::Audio, 30, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["agap overflow 10-30", "a30"]
        );
    }

    #[test]
    fn the_video_ending_in_an_overflow_hands_the_hole_to_the_audio() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(2 * c(10), true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Audio, 10, true);
        recording.push(&mut queue, Kind::Video, 40, true);
        recording.push(&mut queue, Kind::Audio, 50, true);
        queue.end(Kind::Video);
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v0"]);
        assert_eq!(drain(&mut queue, Kind::Audio, &recording), ["a10"]);
        recording.push(&mut queue, Kind::Audio, 60, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["agap overflow 10-60", "a60"]
        );

        let mut queue = ReliableQueue::new(usize::MAX, true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Audio, 10, true);
        queue.end(Kind::Video);
        recording.push(&mut queue, Kind::Audio, 20, true);
        assert_eq!(drain(&mut queue, Kind::Audio, &recording), ["a10", "a20"]);

        let mut queue = ReliableQueue::new(usize::MAX, true);
        recording.push(&mut queue, Kind::Audio, 0, true);
        queue.end(Kind::Video);
        recording.push(&mut queue, Kind::Audio, 20, true);
        assert!(drain(&mut queue, Kind::Audio, &recording).is_empty());
    }

    #[test]
    fn ending_a_track_again_hands_no_second_overflow_hole_to_the_audio() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(2 * c(10), true);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push(&mut queue, Kind::Audio, 10, true);
        recording.push(&mut queue, Kind::Video, 40, true);
        queue.end(Kind::Video);
        assert_eq!(drain(&mut queue, Kind::Video, &recording), ["v0"]);
        assert_eq!(drain(&mut queue, Kind::Audio, &recording), ["a10"]);
        recording.push(&mut queue, Kind::Audio, 60, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["agap overflow 10-60", "a60"]
        );
        queue.end(Kind::Video);
        recording.push(&mut queue, Kind::Audio, 80, true);
        assert_eq!(
            drain(&mut queue, Kind::Audio, &recording),
            ["a80"],
            "nothing was dropped after a60: the second end is no new hole"
        );
    }

    #[test]
    fn a_track_whose_capture_times_move_back_is_waited_for_from_its_latest_frame() {
        let recording = Recording::new();
        let mut merged = interleaver(true);
        recording.push(merged.queue_mut(), Kind::Video, 0, true);
        recording.push(merged.queue_mut(), Kind::Audio, 0, true);
        recording.push(merged.queue_mut(), Kind::Video, 1000, false);
        recording.push(merged.queue_mut(), Kind::Audio, 1000, true);
        assert_eq!(
            release(&mut merged, &recording),
            ["v0", "a0", "v1000", "a1000"]
        );
        // The mapping moves the video's capture times back, behind their
        // arrival.
        recording.push_arrived(merged.queue_mut(), Kind::Video, 960, 1010, false);
        assert_eq!(release(&mut merged, &recording), ["v960"]);
        recording.push_arrived(merged.queue_mut(), Kind::Audio, 990, 1010, true);
        assert!(
            release(&mut merged, &recording).is_empty(),
            "the video is at 960 now, not at the 1000 it had passed before"
        );
        recording.push_arrived(merged.queue_mut(), Kind::Video, 975, 1020, false);
        assert_eq!(release(&mut merged, &recording), ["v975"]);
        recording.push_arrived(merged.queue_mut(), Kind::Video, 1015, 1030, false);
        assert_eq!(
            release(&mut merged, &recording),
            ["a990"],
            "v1015 waits for the audio past 990"
        );
    }

    #[test]
    fn a_gap_after_the_capture_times_moved_back_starts_at_the_latest_frame_queued() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push_arrived(&mut queue, Kind::Video, 3_600_000, 40, false);
        recording.push(&mut queue, Kind::Video, 1020, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, recording.now());
        recording.push(&mut queue, Kind::Video, 1060, false);
        recording.push(&mut queue, Kind::Video, 1100, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v3600000", "v1020", "vgap lagged 1020-1100", "v1100"]
        );
    }

    #[test]
    fn a_gap_never_ends_before_it_starts_when_the_capture_times_move_back_in_the_hole() {
        let recording = Recording::new();
        let mut queue = ReliableQueue::new(usize::MAX, false);
        recording.push(&mut queue, Kind::Video, 0, true);
        recording.push_arrived(&mut queue, Kind::Video, 3_600_000, 40, false);
        queue.push(Kind::Video, TrackEvent::Gap { skipped: 1 }, recording.now());
        recording.push(&mut queue, Kind::Video, 1100, true);
        assert_eq!(
            drain(&mut queue, Kind::Video, &recording),
            ["v0", "v3600000", "vgap lagged 1100-1100", "v1100"]
        );
    }

    /// A frame dated ahead of its arrival by a Sender Report mapping off
    /// (RFC 3550 §6.4.1) goes out by its arrival, the measure a recording ends
    /// by, never behind the other track's frames up to its date.
    #[test]
    fn rfc3550_6_4_1_a_frame_dated_ahead_of_its_arrival_goes_out_by_its_arrival() {
        let recording = Recording::new();
        let mut merged = interleaver(true);
        recording.push(merged.queue_mut(), Kind::Video, 0, true);
        recording.push(merged.queue_mut(), Kind::Audio, 0, true);
        recording.push_arrived(merged.queue_mut(), Kind::Video, 3_600_000, 40, false);
        for ms in [20, 60] {
            recording.push(merged.queue_mut(), Kind::Audio, ms, true);
        }
        assert_eq!(
            release(&mut merged, &recording),
            ["v0", "a0", "a20", "v3600000"],
            "a60 waits for the video past 40 ms, its arrival, not its date"
        );
    }

    #[test]
    fn a_frame_dated_ahead_of_its_arrival_does_not_end_the_wait_for_the_corrected_frames() {
        let recording = Recording::new();
        let mut merged = interleaver(true);
        recording.push(merged.queue_mut(), Kind::Video, 0, true);
        recording.push(merged.queue_mut(), Kind::Audio, 0, true);
        // A Sender Report maps the video an hour ahead; a later one
        // corrects it back.
        recording.push_arrived(merged.queue_mut(), Kind::Video, 3_600_000, 40, false);
        assert_eq!(release(&mut merged, &recording), ["v0", "a0"]);
        recording.advance(1000);
        assert_eq!(release(&mut merged, &recording), ["v3600000"]);
        recording.push(merged.queue_mut(), Kind::Audio, 1040, true);
        assert!(
            release(&mut merged, &recording).is_empty(),
            "the video passed its frame dated ahead's arrival only"
        );
        recording.advance(10);
        recording.push(merged.queue_mut(), Kind::Video, 1020, false);
        assert_eq!(
            release(&mut merged, &recording),
            ["v1020"],
            "in capture order"
        );

        // The same with the frame dated ahead in the video's pre-record.
        let mut merged = interleaver(true);
        let gop = [
            recording.frame(0, true, 10),
            recording.arrived(3_600_000, 40, false),
        ];
        merged.queue_mut().prerecord(
            Kind::Video,
            &snapshot(&recording, &gop, usize::MAX),
            recording.now(),
        );
        recording.advance(1000);
        assert_eq!(release(&mut merged, &recording), ["v0", "v3600000"]);
        recording.push(merged.queue_mut(), Kind::Audio, 1040, true);
        assert!(release(&mut merged, &recording).is_empty());
        recording.push(merged.queue_mut(), Kind::Video, 1020, false);
        assert_eq!(release(&mut merged, &recording), ["v1020"]);
    }
}
