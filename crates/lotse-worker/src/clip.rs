//! Event clips: one task per clip that starts from the connection's
//! pre-roll ring, continues with the live frames and writes the registered
//! container into the pipe the supervisor passed, until the clip ends.
//!
//! A clip waits for the source's tracks, then takes the native video
//! track's subscription and its ring's snapshot together, and the native
//! audio track's alike when asked and the container carries its codec or
//! the clip can transcode it, G.711 and G.722 to Opus with [`ToOpus`]
//! ([`Track::subscribe_from_preroll`]): a snapshot never starts after a
//! frame its subscription yields, so nothing is lost, reordered or
//! written twice between the two, and the [`ReliableQueue`] drops the live
//! frames the pre-roll holds. It starts at the newest held keyframe
//! captured at or before `now − before_ms` (else the oldest held),
//! preferring a later held one whose in-band parameter sets are the
//! track's, which the container's sample entry carries (the snapshot cut
//! there, by position, never by capture time); the audio starts with the
//! frame playing when that keyframe was captured, by the ring's measure
//! ([`captured`]: its arrival when it is dated ahead of it), from where
//! `before_ms` counts.
//! With nothing held it starts at the next keyframe, waiting for it up to
//! the start timeout, which a keyframe queued meets even while the
//! interleaver holds it for the audio. `before_ms` is the age of the first
//! video frame, the start keyframe, by the ring's measure, held or live,
//! when the container starts: the clip sends `Started` then, and the
//! supervisor stamps the API event's `at` on its arrival, so
//! `at − before_ms` is that keyframe's capture time whatever the start
//! waited for (a keyframe held for the audio, one that arrived late).
//! The container's sample entries are the codecs each track's frames were
//! taken with: the descriptor taken with its subscription and snapshot,
//! under the ring's lock, moved on by each change the queue hands out
//! before the first frame; never the track's codec when the container
//! starts, which may be past frames still queued; transcoded audio's is
//! Opus, from a transcode of that codec. A frame subscription yields a
//! change after the frames published before it, so each frame goes under
//! its own codec. An audio change before the start to a codec the
//! container cannot carry nor the clip transcode drops the audio, as one
//! at the outset; any change after it ends the clip. A switch to another
//! source is another stream: its `SourceSwitched` comes in its place among
//! the frames, after the old source's and before the new one's, and ends
//! the clip, started or not; the ring holds nothing of the old source
//! after it.
//! The frames go through the queue and the [`Interleaver`] into the
//! [`ClipMuxer`], and the bytes into the pipe without blocking. Transcoded
//! audio goes through its clip's own [`ToOpus`] on the way out of the
//! queue, so the ring keeps the camera's frames and the pre-roll's audio is
//! transcoded in a burst at the start, at most [`MAX_STEP_PACKETS`] packets,
//! a frame that completes none counting one (one item's over it, see
//! there) before the task yields to the worker's other tasks, in its steps
//! and its drain alike. A reader that
//! closes its end ends the clip at once, written to or not.
//!
//! Invariants: the media path never waits for a clip. While the pipe is
//! full the task takes nothing out of its queue but keeps draining the
//! subscriptions into it, so a stalled reader fills the kernel's pipe,
//! then the queue up to `clip_queue_bytes`, and then costs the clip a gap,
//! never the camera's other consumers. A clip ends at the first frame
//! captured at or after its end, by the ring's measure as its start
//! ([`captured`]), or [`END_GRACE`] after it when none comes. The
//! interleaver orders the tracks by that measure too, so a frame at the
//! end goes out only after the other track's frames queued ahead of that
//! track's own first frame at the end, and a graceful end's drain, which
//! stops at the next frame at the end, leaves none of them out. The
//! video's frames queued behind its first at the end are left out,
//! B-frames that may refer to it.
//! A graceful end (`completed`, `stopped`, `max_duration`) first writes
//! what the queue still holds, frames held for the other track included,
//! up to the clip's end, for at most [`FINISH_GRACE`] of a reader taking
//! it; any other end drops the queue. Every end but a gone reader then
//! writes the container's last fragment, for at most [`FINISH_GRACE`],
//! closes the pipe and reports `Stopped` last; a failure the drain meets
//! (a codec change, the container failing a frame), the container failing
//! a graceful end's last fragment, or a reader gone, or not taking the
//! last bytes within [`FINISH_GRACE`], while a graceful end writes them
//! ends the clip for that instead (`client_gone`). `Stopped`'s `bytes` is
//! the file's length, the bytes left out included, so the body, which ends
//! whole only when it read that many, is cut when any were.
//! Gaps and the duration carry clip media time, where the container put
//! the frames ([`ClipMuxer::media_time`]), never their capture times: a
//! gap runs from where the frame before the hole was put to where the
//! frame that ends it was, a hole the queue reports included; a hole the
//! clip ends in is none, and so is a hole in transcoded audio its
//! transcode fills with silence: the file's audio goes on there; an audio
//! frame without samples is left out of the transcode.
//!
//! Standards: the container is the muxer's (ISO/IEC 14496-12 fragmented
//! MP4 for the daemon's); the parameter sets a start keyframe carries in
//! band are told apart by NAL unit type (ISO/IEC 14496-10 Table 7-1, ITU-T
//! H.265 Table 7-1); a write after the reader closed its end fails with
//! `EPIPE` (POSIX `write`, Linux `pipe(7)`), and the write end polls
//! `POLLERR` from then on (Linux `poll(2)`).

use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSlice};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_codec::transcode::clip::{ToOpus, transcodes};
use lotse_codec::{h264, h265};
use lotse_core::clip::{ClipError, ClipMuxer, ClipMuxerFactory, ClipPolicy, ClipTrack};
use lotse_core::clock::Clock;
use lotse_core::codec::{Codec, Kind};
use lotse_core::interleave::{GapReason, Interleaver, Out, ReliableQueue};
use lotse_core::media::{MediaFrame, MediaTime};
use lotse_core::preroll::{PrerollSnapshot, captured};
use lotse_core::source::TrackSet;
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use lotse_core::track::{Track, TrackEvent, TrackSubscription};
use lotse_ipc::{ClipReport, ClipSpec};
use tokio::io::Interest;
use tokio::net::unix::pipe;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::params;

/// Default of `limits.clip_max_ms`: the longest a clip runs after its
/// start, open-ended or not.
pub const DEFAULT_CLIP_MAX: Duration = Duration::from_secs(600);

/// Default of `limits.clip_start_timeout_ms`: how long a clip with nothing
/// held waits for the source's tracks and their next keyframe, the
/// sessions' `source_not_live` bound.
pub const DEFAULT_CLIP_START_TIMEOUT: Duration = Duration::from_secs(10);

/// Default of `limits.max_clips`: the most clips the daemon runs at once,
/// so the most a worker takes from a supervisor that is wrong.
pub const DEFAULT_MAX_CLIPS: usize = 8;

/// How long an ending clip waits for its reader to take the container's
/// last bytes before it closes the pipe without them; they still count in
/// `Stopped`'s `bytes`, so the body is cut.
const FINISH_GRACE: Duration = Duration::from_secs(1);

/// How long the worker's shutdown waits for its clips to finish: their
/// [`FINISH_GRACE`] and the report after it.
const SHUTDOWN_GRACE: Duration = FINISH_GRACE.saturating_add(Duration::from_millis(500));

/// How long after its end a clip waits for a frame captured at or after
/// it, which a source's latency delivers late: a source that sends
/// nothing (lost, or stalled) ends the clip then.
const END_GRACE: Duration = Duration::from_secs(2);

/// The most gaps a clip reports one by one; it counts the rest in its
/// `Stopped`, so a camera that drops every other frame cannot flood the
/// supervisor and the client with events.
const MAX_GAP_REPORTS: u32 = 256;

/// The most buffers one write hands the pipe: `IOV_MAX` is 1024 on Linux,
/// and a pipe takes 64 KiB at most anyway.
const MAX_WRITE_SLICES: usize = 64;

/// The Opus packets a clip transcodes before it lets the worker's other
/// tasks run, in its steps and its drain alike: half a second of audio, a
/// few milliseconds of one core. Each audio frame through the transcode
/// counts its packets, and one at least: a frame that completes none (a
/// timeline's first, or each of a run that re-anchors on every frame, as
/// a camera repeating its timestamps makes) still costs its decode and
/// resampling. A pre-roll's audio comes out of the queue at once;
/// transcoded in one go, a 120 s window would hold a runtime thread for
/// the length of 6000 frames. It is checked between the queue's items, so
/// one item goes over it by its own packets at most: one RTP packet's
/// samples (a camera's 20 to 40 ms) and up to
/// [`MAX_SILENCE`](lotse_codec::transcode::clip::MAX_SILENCE)'s 50 packets
/// of silence before them.
const MAX_STEP_PACKETS: usize = 25;

/// What the worker's clips run under: the delivery policy and the limits
/// of `limits.clip_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipSettings {
    /// The queue's bound, the interleaver's hold and the fragment span.
    pub policy: ClipPolicy,
    /// The longest a clip runs after its start (`limits.clip_max_ms`).
    pub max_duration: Duration,
    /// How long a clip waits for the tracks and a keyframe to start at
    /// (`limits.clip_start_timeout_ms`).
    pub start_timeout: Duration,
    /// The most clips the worker runs at once (`limits.max_clips`).
    pub max_clips: usize,
}

impl Default for ClipSettings {
    fn default() -> Self {
        Self {
            policy: ClipPolicy::default(),
            max_duration: DEFAULT_CLIP_MAX,
            start_timeout: DEFAULT_CLIP_START_TIMEOUT,
            max_clips: DEFAULT_MAX_CLIPS,
        }
    }
}

/// Why a clip ended, by the name its `Stopped` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndReason {
    /// `after_ms` reached.
    Completed,
    /// `clip/stop`.
    Stopped,
    /// An open-ended clip reached `clip_max_ms`.
    MaxDuration,
    /// The video track closed: the stream is gone.
    StreamDeleted,
    /// A track's codec moved off the container's sample entry, or the
    /// connection switched to another source.
    StreamChanged,
    /// The connection's tracks have no video.
    NoVideoTrack,
    /// No tracks, or no keyframe, within the start timeout.
    SourceNotLive,
    /// The reader closed its end of the pipe, or at the end did not take
    /// the last bytes within [`FINISH_GRACE`]: either way its file is not
    /// whole.
    ClientGone,
    /// The worker is stopping.
    ShuttingDown,
    /// The container failed, or the worker could not run the clip.
    InternalError,
}

impl EndReason {
    /// Whether the clip ends as asked, its queue written first:
    /// `completed`, `stopped`, `max_duration`.
    const fn is_graceful(self) -> bool {
        matches!(self, Self::Completed | Self::Stopped | Self::MaxDuration)
    }

    /// The API's name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Stopped => "stopped",
            Self::MaxDuration => "max_duration",
            Self::StreamDeleted => "stream_deleted",
            Self::StreamChanged => "stream_changed",
            Self::NoVideoTrack => "no_video_track",
            Self::SourceNotLive => "source_not_live",
            Self::ClientGone => "client_gone",
            Self::ShuttingDown => "shutting_down",
            Self::InternalError => "internal_error",
        }
    }
}

/// The API's name of a hole the queue reports: the ring's byte cap cutting
/// a GOP short is the pre-roll's overflow.
const fn gap_name(reason: GapReason) -> &'static str {
    match reason {
        GapReason::Overflow | GapReason::PrerollTruncated => "overflow",
        GapReason::Lagged => "lagged",
    }
}

/// `duration` in whole milliseconds, saturating at `u32::MAX`.
fn millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

/// What a clip needs from the worker to run.
pub(crate) struct ClipStart {
    /// What the client asked for.
    pub(crate) spec: ClipSpec,
    /// The write end of the pipe the bytes go to.
    pub(crate) pipe: pipe::Sender,
    /// The connection's native tracks.
    pub(crate) tracks: Arc<TrackSet>,
    /// The container.
    pub(crate) factory: Arc<dyn ClipMuxerFactory>,
    /// The limits.
    pub(crate) settings: ClipSettings,
    /// The injected clock.
    pub(crate) clock: Arc<dyn Clock>,
}

/// One running clip's handles.
struct Handle {
    /// Asks the clip to end, with the first reason given.
    stop: watch::Sender<Option<EndReason>>,
    /// Its task.
    task: JoinHandle<()>,
}

/// The worker's running clips by id, and where their reports go. A clip
/// stays here from its start until its `Stopped` was passed on
/// ([`Self::ended`]).
pub(crate) struct Clips {
    /// The running clips.
    running: HashMap<String, Handle>,
    /// Where every clip reports.
    reports: mpsc::Sender<(String, ClipReport)>,
}

impl Clips {
    /// No clips yet; each reports to `reports`.
    pub(crate) fn new(reports: mpsc::Sender<(String, ClipReport)>) -> Self {
        Self {
            running: HashMap::new(),
            reports,
        }
    }

    /// How many run.
    pub(crate) fn len(&self) -> usize {
        self.running.len()
    }

    /// Whether `clip_id` runs.
    pub(crate) fn runs(&self, clip_id: &str) -> bool {
        self.running.contains_key(clip_id)
    }

    /// Starts `start`'s clip, its start the clock's reading now.
    pub(crate) fn start(&mut self, start: ClipStart) {
        let started = start.clock.now();
        let (stop, requested) = watch::channel(None);
        let clip_id = start.spec.clip_id.clone();
        let task = spawn_named("clip", run(start, started, requested, self.reports.clone()));
        self.running.insert(clip_id, Handle { stop, task });
    }

    /// Asks `clip_id` to end for `reason`, unless it ends already;
    /// whether it runs.
    pub(crate) fn stop(&self, clip_id: &str, reason: EndReason) -> bool {
        let Some(handle) = self.running.get(clip_id) else {
            return false;
        };
        ask(handle, reason);
        true
    }

    /// Asks every clip to end for `reason`.
    pub(crate) fn stop_all(&self, reason: EndReason) {
        for handle in self.running.values() {
            ask(handle, reason);
        }
    }

    /// `clip_id`'s `Stopped` was passed on: it is over.
    pub(crate) fn ended(&mut self, clip_id: &str) {
        self.running.remove(clip_id);
    }

    /// The worker stops: every clip ends `shutting_down` and gets
    /// [`SHUTDOWN_GRACE`] on `clock`, but no later than `by`, the worker's
    /// own shutdown deadline, to write its last fragment and report; one
    /// still running then is aborted, its pipe closed as its task drops.
    pub(crate) async fn shutdown(&mut self, clock: &Arc<dyn Clock>, by: Instant) {
        self.stop_all(EndReason::ShuttingDown);
        let now = clock.now();
        let deadline = now.checked_add(SHUTDOWN_GRACE).unwrap_or(now).min(by);
        for (clip_id, handle) in self.running.drain() {
            let mut task = handle.task;
            let left = deadline.saturating_duration_since(clock.now());
            tokio::select! {
                _ = &mut task => {}
                () = clock.sleep(left) => {
                    tracing::warn!(clip.id = %clip_id, grace_ms = deadline.saturating_duration_since(now).as_millis(), "clip still finishing at shutdown; aborted");
                    task.abort();
                }
            }
        }
    }

    /// The supervisor is gone: every clip is aborted, its pipe closed as
    /// its task drops, since nobody hears its report.
    pub(crate) fn abort_all(&mut self) {
        for (_, handle) in self.running.drain() {
            handle.task.abort();
        }
    }
}

/// Asks the clip behind `handle` to end for `reason`, unless a reason was
/// given before.
fn ask(handle: &Handle, reason: EndReason) {
    handle.stop.send_if_modified(|current| {
        let first = current.is_none();
        current.get_or_insert(reason);
        first
    });
}

/// The end the worker asks for; `shutting_down` once it dropped the
/// clip's handle.
async fn requested_end(requested: &mut watch::Receiver<Option<EndReason>>) -> EndReason {
    requested
        .wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|reason| *reason)
        .unwrap_or(EndReason::ShuttingDown)
}

/// The next event of the audio subscription; never without one.
async fn next_audio(audio: &mut Option<TrackSubscription>) -> Option<TrackEvent> {
    match audio {
        Some(subscription) => subscription.next().await,
        None => std::future::pending().await,
    }
}

/// Resolves once the reader closed its end of `pipe`, which the write end
/// then polls as an error whatever room the pipe has (`POLLERR`, Linux
/// `poll(2)`), so a clip with nothing to write sees it at once and plain
/// writability never wakes it. A failure to wait (the runtime stopping)
/// resolves it too: the clip could write no more either.
async fn hangup(pipe: &pipe::Sender) {
    let _ready = pipe.ready(Interest::ERROR).await;
}

/// The reader of `clip_id` is gone: logged, the clip ends.
fn gone(clip_id: &str) -> EndReason {
    tracing::info!(clip.id = %clip_id, "clip: the reader is gone");
    EndReason::ClientGone
}

/// Waits until the source declared `tracks`: `source_not_live` when it
/// does not by `deadline` on `clock`, or the worker's end, or `client_gone`
/// when the reader closed `pipe`; `clip_id` names the clip in the log.
async fn wait_ready(
    tracks: &TrackSet,
    pipe: &pipe::Sender,
    requested: &mut watch::Receiver<Option<EndReason>>,
    clock: &dyn Clock,
    deadline: Instant,
    clip_id: &str,
) -> Result<(), EndReason> {
    let mut ready = tracks.ready();
    while !*ready.borrow_and_update() {
        let left = deadline.saturating_duration_since(clock.now());
        tokio::select! {
            // The clip holds the set, whose sender outlives the wait.
            Ok(()) = ready.changed() => {}
            reason = requested_end(requested) => return Err(reason),
            () = hangup(pipe) => return Err(gone(clip_id)),
            () = clock.sleep(left) => {
                tracing::info!(clip.id = %clip_id, "clip: the source did not go live in time");
                return Err(EndReason::SourceNotLive);
            }
        }
    }
    Ok(())
}

/// One clip, from its start to its `Stopped`.
async fn run(
    start: ClipStart,
    started: Instant,
    mut requested: watch::Receiver<Option<EndReason>>,
    reports: mpsc::Sender<(String, ClipReport)>,
) {
    let ClipStart {
        spec,
        pipe,
        tracks,
        factory,
        settings,
        clock,
    } = start;
    let mut clip = Clip::new(&spec, pipe, factory, settings, clock, started, reports);
    tracing::debug!(
        clip.id = %clip.id,
        before_ms = spec.before_ms,
        after_ms = spec.after_ms,
        audio = spec.audio,
        "clip: waiting for the tracks"
    );
    let reason = match clip.open(&tracks, &mut requested).await {
        Ok(mut media) => {
            let reason = clip.record(&mut media, &mut requested).await;
            if reason.is_graceful() {
                clip.drain(&mut media).await.unwrap_or(reason)
            } else {
                reason
            }
        }
        Err(reason) => reason,
    };
    clip.finish(reason).await;
}

/// A clip's subscriptions, the queue they fill, and the sample entries
/// its frames go under.
struct Media {
    /// The video track's frames.
    video: TrackSubscription,
    /// The audio track's frames, until they end; `None` for a clip
    /// without audio.
    audio: Option<TrackSubscription>,
    /// The container's sample entries, video and audio (`None`: the clip
    /// has no audio): each track's descriptor as its subscription was
    /// taken, moved on by each `TrackChanged` the queue hands out before
    /// the container starts, so they are the codecs of the frames the
    /// queue holds, never the track's codec now, which may be past them.
    /// Fixed once the container started. Audio the clip transcodes keeps
    /// the camera's codec here, which its changes are compared with; the
    /// container's entry is then [`ToOpus::output`] ([`Clip::begin`]).
    entries: (ClipTrack, Option<ClipTrack>),
    /// The queue, merged in capture order.
    interleaver: Interleaver,
}

/// Where a clip continues a video track: the epoch and the newest
/// timestamp it wrote, and the shortest advance between two frames seen in
/// the epoch, so a hole inside an epoch shows.
///
/// A frame that advances the newest timestamp by more than twice that
/// interval is a hole only once the frame after it is not presented
/// before it. A B-frame run comes in decode order right after the
/// reference frame presented after it, so that frame jumps over the run
/// and the next frame shows the run, whatever its length (`I0 P3 B1 B2
/// P4 P7 B5 B6` has no hole, though `P4` teaches one interval and `P7`
/// advances three). A clip that ends right after a jump reports none, as
/// for any hole it ends in.
///
/// Timestamps, not capture times: inside an epoch the container lays the
/// frames out by their timestamps, so a hole there is a hole in the file,
/// while a capture time is the frame's arrival until the camera's first
/// Sender Report (and on a source without them), with the network's and
/// the encoder's jitter. Two frames arriving together made the shortest
/// advance a millisecond, and every later frame a `frames_dropped` gap
/// (found end to end, 2026-10-23: MediaMTX 1.21.1 relaying libx265, and
/// any connection's first seconds before its first report).
///
/// A new epoch's video before its first keyframe is left out: its
/// pictures refer to ones of the new connection the clip never had, and a
/// decoder would take the old epoch's instead (found end to end,
/// 2026-10-23: MediaMTX 1.21.1 hands a reader that connects mid-GOP its
/// stream from the frame at hand, so a reconnect resumed with P-frames).
#[derive(Debug, Default)]
struct Continuity {
    /// The epoch and the newest timestamp written; `None` at the start
    /// and after a hole the queue reported.
    last: Option<(u32, MediaTime)>,
    /// The shortest advance of the newest timestamp in the epoch, in the
    /// track's ticks: the frame interval, B-frames aside, which never
    /// advance it.
    step: Option<i64>,
    /// The new epoch whose frames are left out until its first keyframe.
    skipping: Option<u32>,
    /// Where the container put the frame that jumped past twice the
    /// interval (clip media time, from the frame before it to it), until
    /// the next frame tells whether it is a hole.
    jump: Option<(Duration, Duration)>,
}

/// What a video frame is to the clip's continuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// It follows the frame before it.
    Follows,
    /// It ends a hole: a reconnect.
    Reconnects,
    /// It advances the timestamp past twice the interval: a hole unless
    /// the next frame is presented before it ([`Continuity::settle`]).
    Jumps,
    /// A new epoch's frame before its first keyframe: left out.
    Undecodable,
}

impl Continuity {
    /// What `frame` is: the end of a hole when its epoch is not the last
    /// frame's (`reconnect`; undecodable unless a keyframe), a jump when it
    /// advances the timestamp by more than twice the epoch's frame
    /// interval.
    fn observe(&mut self, frame: &MediaFrame) -> Seen {
        let Some((epoch, newest)) = self.last else {
            self.last = Some((frame.epoch, frame.ts));
            return Seen::Follows;
        };
        if frame.epoch != epoch {
            if !frame.keyframe {
                if self.skipping != Some(frame.epoch) {
                    self.skipping = Some(frame.epoch);
                    tracing::debug!(
                        epoch = frame.epoch,
                        "clip: the new epoch's video is left out until its first keyframe"
                    );
                }
                return Seen::Undecodable;
            }
            self.last = Some((frame.epoch, frame.ts));
            self.step = None;
            return Seen::Reconnects;
        }
        let Some(advance) = frame.ts.checked_sub(newest).filter(|advance| *advance > 0) else {
            return Seen::Follows;
        };
        self.last = Some((epoch, frame.ts));
        let dropped = self
            .step
            .is_some_and(|step| advance > step.saturating_mul(2));
        self.step = Some(self.step.map_or(advance, |step| step.min(advance)));
        if dropped { Seen::Jumps } else { Seen::Follows }
    }

    /// The frame before `frame` jumped (`from` and `to`, where the
    /// container put it): `frame` tells whether that is a hole.
    const fn jumped(&mut self, from: Duration, to: Duration) {
        self.jump = Some((from, to));
    }

    /// The hole the jump before `frame` was, where the container put it:
    /// `None` when there was none, or when `frame` is presented before the
    /// jump's frame, which jumped over the B-frames that follow it then.
    /// Taken before [`Self::observe`] of `frame`.
    fn settle(&mut self, frame: &MediaFrame) -> Option<(Duration, Duration)> {
        let jump = self.jump.take()?;
        let reordered = self
            .last
            .is_some_and(|(epoch, newest)| frame.epoch == epoch && frame.ts < newest);
        if reordered {
            tracing::trace!(ts = %frame.ts, "clip: the jump before was a B-frame run's");
            return None;
        }
        Some(jump)
    }

    /// The queue reported a hole: the next frame continues from nothing,
    /// and teaches the interval anew, since the frames lost may span a
    /// reconnect to another frame rate whose epoch change the next frame
    /// then passes unseen; a jump before it is left unsettled, the queue's
    /// hole reported instead.
    const fn reset(&mut self) {
        self.last = None;
        self.step = None;
        self.jump = None;
    }
}

/// A clip's video subscription and the snapshot it starts from, taken
/// together ([`Track::subscribe_from_preroll`]): the ring's frames from
/// the newest keyframe captured at or before `target` (else the oldest
/// held), or from the first later keyframe the snapshot holds when that one
/// carries parameter sets other than the track's and a later one does not,
/// since the container's sample entry has the track's newest; no snapshot
/// when nothing is held. The later start is cut from the same snapshot, by
/// position: its frames still come before every frame the subscription
/// yields, and a camera's Sender Reports can date a keyframe ahead of a
/// later one, so a search by capture time could start past it. The
/// descriptor and the source the track takes come with the pair they were
/// taken with.
fn start_video(video: &Arc<Track>, target: Instant) -> TrackStart {
    let (subscription, mut snapshot, codec, source) = video.subscribe_from_preroll(target);
    if let Some(snapshot) = &mut snapshot
        && !sets_match(&codec, &snapshot.start().payload)
    {
        let later = snapshot.advance_to_keyframe(|frame| sets_match(&codec, &frame.payload));
        tracing::debug!(
            later,
            "clip: the start keyframe carries other parameter sets than the track's"
        );
    }
    (subscription, snapshot, codec, source)
}

/// A track's start as [`Track::subscribe_from_preroll`] takes it: the
/// subscription, the snapshot, the descriptor and the source the track
/// takes.
type TrackStart = (TrackSubscription, Option<PrerollSnapshot>, Arc<Codec>, u8);

/// A clip's audio start: the subscription, the snapshot and the sample
/// entry.
type AudioStart = (TrackSubscription, Option<PrerollSnapshot>, ClipTrack);

/// Whether every parameter set `access_unit` (Annex B) carries in band is
/// the one `codec` holds of its type; one that carries none qualifies, and
/// so does every unit of a codec without parameter sets.
fn sets_match(codec: &Codec, access_unit: &[u8]) -> bool {
    let units = h264::nal::annex_b_units(access_unit);
    match codec {
        Codec::H264 { sps, pps, .. } => units.iter().all(|unit| {
            let held = match unit.first().map(|header| h264::nal::nal_type(*header)) {
                Some(h264::nal::NAL_SPS) => sps,
                Some(h264::nal::NAL_PPS) => pps,
                _ => return true,
            };
            held.as_deref() == Some(*unit)
        }),
        Codec::H265 { vps, sps, pps } => units.iter().all(|unit| {
            let held = match h265::nal::unit_type(unit) {
                Some(h265::nal::VPS_NUT) => vps,
                Some(h265::nal::SPS_NUT) => sps,
                Some(h265::nal::PPS_NUT) => pps,
                _ => return true,
            };
            held.as_deref() == Some(*unit)
        }),
        _ => true,
    }
}

/// The transcode of audio in `codec` that the container cannot carry as
/// it is: G.711 or G.722 to Opus, when the container takes Opus; `None`
/// otherwise. The chain reads the frames on the codec's own RTP clock
/// ([`ToOpus::new`]), never the track's declared rate, which a reconnect
/// that changes the codec keeps.
fn transcoder(codec: &Codec, factory: &dyn ClipMuxerFactory) -> Option<ToOpus> {
    (transcodes(codec) && factory.accepts(&ToOpus::output().codec))
        .then(|| ToOpus::new(codec).ok())
        .flatten()
}

/// One clip's state.
struct Clip {
    /// Its id.
    id: String,
    /// How far before its start it asked to begin.
    before: Duration,
    /// Whether it asked for audio.
    audio: bool,
    /// The write end of its pipe.
    pipe: pipe::Sender,
    /// The container, which decides what audio the clip can carry.
    factory: Arc<dyn ClipMuxerFactory>,
    /// The container writer.
    muxer: Box<dyn ClipMuxer>,
    /// The limits.
    settings: ClipSettings,
    /// The injected clock.
    clock: Arc<dyn Clock>,
    /// The clock's reading at `StartClip`: where the pre-roll window and
    /// `after_ms` count from (`before_ms` counts from the container's
    /// start, [`Self::begin`]).
    started: Instant,
    /// The capture time at which it ends, by the ring's measure
    /// ([`captured`]).
    end_at: Instant,
    /// Why it ends then: `completed`, or `max_duration` when it asked for
    /// no end or for one past `clip_max_ms`.
    end_reason: EndReason,
    /// Where its reports go.
    reports: mpsc::Sender<(String, ClipReport)>,
    /// Reports not yet sent.
    outbox: Vec<ClipReport>,
    /// Bytes the muxer completed and the pipe has not taken yet, in order.
    pending: VecDeque<Bytes>,
    /// Bytes the pipe took.
    written: u64,
    /// The bytes the reader did not take within [`FINISH_GRACE`] of the
    /// end, which the pipe never got: never 0 once set, since only bytes
    /// still pending are left out. `Stopped` counts them in the file's
    /// length, so a body that read only what the pipe took is cut, not
    /// ended whole.
    left_out: u64,
    /// Whether the container started, at the first frame.
    begun: bool,
    /// The video met its first frame captured at or after the clip's
    /// end. In decode order the frames behind it may be B-frames
    /// presented before the end that refer to it, and it is not in the
    /// file, so no later video frame goes in; the audio drains on up to
    /// its own end.
    video_ended: bool,
    /// The furthest clip media time a frame was put at, on either track:
    /// the duration `Stopped` reports.
    reached: Duration,
    /// The holes the queue reported per track, by their API name, until
    /// the frame that ends each is in the container: where they are.
    /// Transcoded audio's come through [`Self::judging`], and only those
    /// the transcode re-anchors on.
    holes: HashMap<Kind, &'static str>,
    /// Transcoded audio's last hole until the audio frame with samples after
    /// it went through the transcode, which decides whether it is one
    /// ([`Self::frame`]): one it fills with silence is none and goes; one
    /// it re-anchors on or crosses an input epoch after moves to [`Self::holes`] for the new run's first
    /// packet, where no later hole of either kind takes it away.
    judging: Option<&'static str>,
    /// How far before its start it begins: its first video frame's age
    /// when the container starts, set then.
    before_ms: u32,
    /// The audio codec left out because the container cannot carry it
    /// and the clip cannot transcode it.
    omitted: Option<String>,
    /// The audio's transcode to Opus, for audio the container cannot
    /// carry as it is: the chain for the codec of the audio's entry in
    /// [`Media::entries`], which stays the camera's.
    transcoder: Option<ToOpus>,
    /// Opus packets transcoded since the clip last let the worker's other
    /// tasks run, one at least per frame through the transcode
    /// ([`MAX_STEP_PACKETS`]): in the current [`Self::step`], or in
    /// [`Self::drain`].
    step_packets: usize,
    /// Where the video continues.
    continuity: Continuity,
    /// The gaps it had.
    gaps: u32,
    /// Rate-limits the line of a gap.
    gap_log: Throttle,
    /// Rate-limits the line of an audio hole its transcode filled.
    concealed_log: Throttle,
}

impl Clip {
    /// The clip `spec` asks for, writing into `pipe` through a muxer of
    /// `factory`, started at `started`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the parts of a `ClipStart` the clip keeps, and what the worker adds"
    )]
    fn new(
        spec: &ClipSpec,
        pipe: pipe::Sender,
        factory: Arc<dyn ClipMuxerFactory>,
        settings: ClipSettings,
        clock: Arc<dyn Clock>,
        started: Instant,
        reports: mpsc::Sender<(String, ClipReport)>,
    ) -> Self {
        let after = spec
            .after_ms
            .map(|ms| Duration::from_millis(u64::from(ms)))
            .filter(|after| *after <= settings.max_duration);
        let end_reason = if after.is_some() {
            EndReason::Completed
        } else {
            EndReason::MaxDuration
        };
        let end_at = started
            .checked_add(after.unwrap_or(settings.max_duration))
            .unwrap_or(started);
        Self {
            id: spec.clip_id.clone(),
            before: Duration::from_millis(u64::from(spec.before_ms)),
            audio: spec.audio,
            pipe,
            muxer: factory.muxer(&settings.policy),
            factory,
            settings,
            clock,
            started,
            end_at,
            end_reason,
            reports,
            outbox: Vec::new(),
            pending: VecDeque::new(),
            written: 0,
            left_out: 0,
            begun: false,
            video_ended: false,
            reached: Duration::ZERO,
            holes: HashMap::new(),
            judging: None,
            before_ms: 0,
            omitted: None,
            transcoder: None,
            step_packets: 0,
            continuity: Continuity::default(),
            gaps: 0,
            gap_log: Throttle::default(),
            concealed_log: Throttle::default(),
        }
    }

    /// When a clip that has not started gives up, `source_not_live`: the
    /// start timeout, or its late end when that comes first.
    fn start_deadline(&self) -> Instant {
        self.started
            .checked_add(self.settings.start_timeout)
            .unwrap_or(self.started)
            .min(self.late_end())
    }

    /// When a clip whose end no frame showed ends anyway.
    fn late_end(&self) -> Instant {
        self.end_at.checked_add(END_GRACE).unwrap_or(self.end_at)
    }

    /// Waits for the tracks, picks them, subscribes and queues the
    /// pre-roll; the end instead when the tracks do not come in time, have
    /// no video, the reader goes or the worker asks first, and
    /// `stream_changed` when the connection switched source between the
    /// video's start and the audio's ([`Self::start_audio`]). Each track's
    /// descriptor is taken with its subscription, so a change after it
    /// comes to the clip as an event, after the frames before it.
    async fn open(
        &mut self,
        tracks: &TrackSet,
        requested: &mut watch::Receiver<Option<EndReason>>,
    ) -> Result<Media, EndReason> {
        wait_ready(
            tracks,
            &self.pipe,
            requested,
            self.clock.as_ref(),
            self.start_deadline(),
            &self.id,
        )
        .await?;
        let natives = tracks.tracks();
        let video_track = natives
            .iter()
            .find(|track| track.kind() == Kind::Video)
            .ok_or(EndReason::NoVideoTrack)?;
        // Linux's monotonic clock reads as a signed timespec, so a window
        // reaching back before it started does not fail there.
        let target = self
            .started
            .checked_sub(self.before)
            .unwrap_or(self.started);
        let (video, snapshot, codec, source) = start_video(video_track, target);
        let video_entry = ClipTrack {
            codec: (*codec).clone(),
            clock_rate: video_track.clock_rate(),
        };
        let audio_target = snapshot
            .as_ref()
            .map_or(target, |snapshot| captured(snapshot.start()));
        let mut audio = None;
        if let Some(track) = natives.iter().find(|track| track.kind() == Kind::Audio)
            && self.audio
        {
            audio = self.start_audio(track, audio_target, source)?;
        }
        let mut queue = ReliableQueue::new(self.settings.policy.queue_bytes, audio.is_some());
        let now = self.clock.now();
        if let Some(snapshot) = snapshot {
            queue.preroll(Kind::Video, &snapshot, now);
            // An audio snapshot without a video one would only be ignored.
            if let Some((_, Some(audio_snapshot), _)) = &audio {
                queue.preroll(Kind::Audio, audio_snapshot, now);
            }
        }
        let (audio, audio_entry) = audio.map_or((None, None), |(subscription, _, entry)| {
            (Some(subscription), Some(entry))
        });
        Ok(Media {
            video,
            audio,
            entries: (video_entry, audio_entry),
            interleaver: Interleaver::new(queue, self.settings.policy.max_skew),
        })
    }

    /// The audio `track`'s start from `target`, its subscription, snapshot
    /// and descriptor taken together ([`Track::subscribe_from_preroll`]);
    /// with the clip's [`ToOpus`] when the container cannot carry its codec
    /// as it is but takes it transcoded, and `None` when it takes it
    /// neither way, the clip warned `audio_omitted`. Its entry is the
    /// track's codec either way. It ends the clip `stream_changed` when
    /// the track takes another source than `source`, the video start's: the
    /// connection switched between the two, so the video's frames are the
    /// old source's up to its `SourceSwitched` and the audio's the new
    /// one's, and an audio frame captured before a video frame queued
    /// ahead of that event would go out with it, two sources in one clip.
    /// The video's subscription ends the clip at the switch all the same.
    fn start_audio(
        &mut self,
        track: &Arc<Track>,
        target: Instant,
        source: u8,
    ) -> Result<Option<AudioStart>, EndReason> {
        let (subscription, snapshot, codec, audio_source) = track.subscribe_from_preroll(target);
        if audio_source != source {
            tracing::info!(
                clip.id = %self.id,
                video_source = source,
                audio_source,
                "clip: the connection switched to another source between the video's start and the audio's; ending"
            );
            return Err(EndReason::StreamChanged);
        }
        if !self.factory.accepts(&codec) {
            self.transcoder = transcoder(&codec, self.factory.as_ref());
            if self.transcoder.is_none() {
                self.omitted = Some(codec.name().to_owned());
                return Ok(None);
            }
        }
        let entry = ClipTrack {
            codec: (*codec).clone(),
            clock_rate: track.clock_rate(),
        };
        Ok(Some((subscription, snapshot, entry)))
    }

    /// Runs the clip until it ends: takes what the subscriptions yield
    /// into the queue at once, and the queue's items into the container
    /// and the pipe as fast as the pipe takes them. After a step that
    /// stopped at [`MAX_STEP_PACKETS`] it yields before it looks at anything
    /// else.
    async fn record(
        &mut self,
        media: &mut Media,
        requested: &mut watch::Receiver<Option<EndReason>>,
    ) -> EndReason {
        loop {
            let more = match self.step(media) {
                Ok(more) => more,
                Err(reason) => return reason,
            };
            self.send_reports().await;
            if more {
                // The step stopped at its budget with work left: the
                // worker's other tasks run first, whatever is ready below.
                tokio::task::yield_now().await;
            }
            let wake = self.wake(&media.interleaver);
            let sleep = self
                .clock
                .sleep(wake.saturating_duration_since(self.clock.now()));
            tokio::select! {
                biased;
                reason = requested_end(requested) => return reason,
                event = media.video.next() => {
                    let Some(event) = event else {
                        tracing::info!(clip.id = %self.id, "clip: the video track closed");
                        return EndReason::StreamDeleted;
                    };
                    media.interleaver.queue_mut().push(Kind::Video, event, self.clock.now());
                }
                event = next_audio(&mut media.audio) => {
                    if let Some(event) = event {
                        media.interleaver.queue_mut().push(Kind::Audio, event, self.clock.now());
                    } else {
                        media.audio = None;
                        media.interleaver.queue_mut().end(Kind::Audio);
                    }
                }
                // A spurious readiness comes back as `WouldBlock`.
                _ = self.pipe.writable(), if !self.pending.is_empty() => {
                    if let Err(reason) = self.write() {
                        return reason;
                    }
                }
                // With nothing pending no write would tell: a stalled
                // camera would keep the clip, and its slot, to its end.
                () = hangup(&self.pipe) => return gone(&self.id),
                // Work is left: the next step goes on at once, after the
                // events above, without waiting for one.
                () = std::future::ready(()), if more => {}
                () = sleep => {}
            }
        }
    }

    /// Whether the start timeout still runs: the container has not
    /// started and the clip has no keyframe queued to start at. One the
    /// interleaver holds for the other track goes out by `max_skew`, so the
    /// timeout ends with the keyframe's arrival, not with its release.
    fn awaits_keyframe(&self, interleaver: &Interleaver) -> bool {
        !self.begun && interleaver.queue().first_frame(Kind::Video).is_none()
    }

    /// What can be done now: the end when a deadline passed, else the
    /// queue's items released now into the container while the pipe takes
    /// its bytes; whether it stopped at [`MAX_STEP_PACKETS`] with more to
    /// do.
    fn step(&mut self, media: &mut Media) -> Result<bool, EndReason> {
        let now = self.clock.now();
        if self.awaits_keyframe(&media.interleaver) && now >= self.start_deadline() {
            tracing::info!(clip.id = %self.id, "clip: no keyframe to start at in time");
            return Err(EndReason::SourceNotLive);
        }
        if now >= self.late_end() {
            tracing::info!(clip.id = %self.id, reason = self.end_reason.name(), "clip: no frame after its end came; ending");
            return Err(self.end_reason);
        }
        self.step_packets = 0;
        loop {
            self.write()?;
            if !self.pending.is_empty() {
                return Ok(false);
            }
            if self.step_packets >= MAX_STEP_PACKETS {
                return Ok(true);
            }
            let Some(out) = media.interleaver.next(now) else {
                return Ok(false);
            };
            self.take(out, media)?;
        }
    }

    /// When to look again with nothing pushed: the start timeout while it
    /// runs, the late end, or, while the pipe takes everything, when a
    /// frame the interleaver holds goes out, whichever comes first. A
    /// frame held behind a full pipe waits for the pipe, whose readiness
    /// wakes the clip: its hold over would wake it at once again and
    /// again, and so would a start timeout `step` no longer ends at.
    fn wake(&self, interleaver: &Interleaver) -> Instant {
        let mut wake = self.late_end();
        if self.awaits_keyframe(interleaver) {
            wake = wake.min(self.start_deadline());
        }
        if self.pending.is_empty()
            && let Some(held) = interleaver.deadline()
        {
            wake = wake.min(held);
        }
        wake
    }

    /// One item of the queue.
    fn take(&mut self, out: Out, media: &mut Media) -> Result<(), EndReason> {
        match out {
            Out::Frame { track, frame } => self.frame(track, frame, media),
            // Its capture times are not where the file has it: it waits for
            // the frame that ends it, which follows on its track.
            Out::Gap { track, reason, .. } => {
                if track == Kind::Video {
                    self.continuity.reset();
                }
                if track == Kind::Audio && self.transcoder.is_some() {
                    // The transcode decides at the next frame ([`Self::frame`]).
                    self.judging = Some(gap_name(reason));
                } else {
                    self.holes.insert(track, gap_name(reason));
                }
                Ok(())
            }
            Out::Control { track, event } => self.control(track, &event, media),
        }
    }

    /// One frame: the end when it was captured at or after the clip's,
    /// by the ring's measure ([`captured`]: a frame dated ahead of its
    /// arrival by a Sender Report mapping off, RFC 3550 §6.4.1, counts
    /// from its arrival, as the clip's start and `before_ms` do), and
    /// nothing for a video frame after the video's end
    /// ([`Self::video_ended`]); the container's start before the first;
    /// then into the container ([`Self::sample`]), audio the clip
    /// transcodes as the Opus packets its [`ToOpus`] completes with it. A
    /// hole the queue reported before an audio frame the transcode
    /// continues its output epoch with ([`ToOpus::continued`]: within the
    /// tolerance, or silence fills it, up to
    /// [`MAX_SILENCE`](lotse_codec::transcode::clip::MAX_SILENCE)) is no
    /// gap: the file has none there. Only the first frame after the hole
    /// decides (the first with samples: one without is left out of the
    /// transcode): one that re-anchors, or that crosses into an input epoch
    /// whose new output epoch is placed at its capture time (which can
    /// step), puts it in [`Self::holes`] for the
    /// first packet of the new run, where neither the frames that continue
    /// that run nor a later loss they fill with silence drop it.
    fn frame(
        &mut self,
        track: Kind,
        frame: Arc<MediaFrame>,
        media: &Media,
    ) -> Result<(), EndReason> {
        if track == Kind::Video && self.video_ended {
            tracing::trace!(clip.id = %self.id, ts = %frame.ts, "clip: a video frame behind the video's end left out");
            return Ok(());
        }
        if captured(&frame) >= self.end_at {
            if track == Kind::Video {
                self.video_ended = true;
            }
            tracing::debug!(clip.id = %self.id, %track, reason = self.end_reason.name(), "clip: its end is reached");
            return Err(self.end_reason);
        }
        if !self.begun {
            self.begin(track, &frame, media)?;
        }
        let seen = match track {
            Kind::Video => {
                if let Some((from, to)) = self.continuity.settle(&frame) {
                    self.gap("frames_dropped", from, to);
                }
                self.continuity.observe(&frame)
            }
            Kind::Audio => Seen::Follows,
        };
        if seen == Seen::Undecodable {
            return Ok(());
        }
        let Some(chain) = self.transcoder.as_mut().filter(|_| track == Kind::Audio) else {
            return self.sample(track, frame, seen);
        };
        if frame.payload.is_empty() {
            // No samples (an RTP packet of padding only, RFC 3550 §5.1):
            // the transcode leaves it out, and a hole the queue reported
            // waits for the frame with samples after it, which shows
            // whether the transcode fills it.
            tracing::trace!(clip.id = %self.id, ts = %frame.ts, "clip: an audio frame without samples left out of the transcode");
            return Ok(());
        }
        let packets = chain.push(&frame).map_err(ClipError::from);
        let concealed = chain.continued();
        let packets = packets.map_err(self.failed("transcode"))?;
        if let Some(reason) = self.judging.take() {
            if concealed {
                // Silence fills it: the file's audio goes on in one run, no
                // hole there, so no gap. A hole decided before it, waiting
                // in `holes` for its run's first packet, stays.
                if let Some(count) = self.concealed_log.hit(self.clock.now()) {
                    tracing::debug!(clip.id = %self.id, reason, count, "clip: the transcode filled the audio's hole with silence; no gap");
                }
            } else {
                // A hole in the file: it ends at the new run's first packet.
                self.holes.insert(track, reason);
            }
        }
        // A frame that completes no packet still cost its decode and
        // resample: one at least, or frames that re-anchor on every one
        // (a camera repeating its timestamps) would never reach the budget.
        self.step_packets = self.step_packets.saturating_add(packets.len().max(1));
        for packet in packets {
            self.sample(track, packet, seen)?;
        }
        Ok(())
    }

    /// One frame as the container takes it, `seen` by the video's
    /// continuity: a gap when it ends a hole, one the queue reported on
    /// its track or one the video's continuity shows (a jump, once the
    /// frame after it settles it): from the frame of its track before it
    /// to this one, where the container put them. That can be later than
    /// their capture times (an epoch captured before the last frame began
    /// starts where that frame ends, and a frame that came early in its
    /// interval where the one before it ends), and a gap from capture
    /// times then disagreed with the file, or ended before it began, a
    /// report the supervisor refuses (found end to end, 2026-10-23: a
    /// camera reconnecting within a frame). Where it was put is how far
    /// the clip reaches. A transcoded track's hole the transcode
    /// re-anchors on ends at the first packet of the new run, after what
    /// it held from before the hole was dropped; one it fills with silence
    /// is none ([`Self::frame`]).
    fn sample(&mut self, track: Kind, frame: Arc<MediaFrame>, seen: Seen) -> Result<(), EndReason> {
        // The queue's hole resets the continuity, which then sees none.
        let hole = self.holes.remove(&track);
        let from = self.muxer.media_time(track);
        let bytes = self.muxer.push(track, frame).map_err(self.failed("push"))?;
        let to = self.muxer.media_time(track);
        self.reached = self.reached.max(to);
        match (hole, seen) {
            (Some(reason), _) => self.gap(reason, from, to),
            (None, Seen::Reconnects) => self.gap("reconnect", from, to),
            (None, Seen::Jumps) => self.continuity.jumped(from, to),
            (None, Seen::Follows | Seen::Undecodable) => {}
        }
        self.queue(bytes);
        Ok(())
    }

    /// Starts the container with `media`'s sample entries at the first
    /// frame, `frame` of `track`, and reports `Started` (and the omitted
    /// audio's warning), `before_ms` the first video frame's age now, as
    /// `Started` goes out: this one, or the keyframe queued behind an audio
    /// frame captured before it. Counted from `StartClip` instead, it would
    /// disagree with the `at` the supervisor stamps on arrival by however
    /// long the start waited. Transcoded audio is Opus in the container
    /// ([`ToOpus::output`]), and the container's media time 0 is the
    /// transcode's delay before `frame`'s capture time, since its packets
    /// are moved back by it ([`ToOpus::delay`]); `before_ms` still counts
    /// to the keyframe, the first video frame.
    fn begin(
        &mut self,
        track: Kind,
        frame: &Arc<MediaFrame>,
        media: &Media,
    ) -> Result<(), EndReason> {
        let first = match track {
            Kind::Video => Some(frame),
            Kind::Audio => media.interleaver.queue().first_frame(Kind::Video),
        };
        self.before_ms = first.map_or(0, |first| {
            millis(self.clock.now().saturating_duration_since(captured(first)))
        });
        let (video, source_audio) = &media.entries;
        let opus = ToOpus::output();
        let transcoded_from = source_audio.as_ref().filter(|_| self.transcoder.is_some());
        let audio = transcoded_from.map_or(source_audio.as_ref(), |_| Some(&opus));
        let init = self
            .muxer
            .start(video, audio)
            .map_err(self.failed("start"))?;
        let lead = self
            .transcoder
            .as_ref()
            .map_or(Duration::ZERO, ToOpus::delay);
        let origin = frame.wallclock.checked_sub(lead).unwrap_or(frame.wallclock);
        self.muxer.set_origin(origin);
        self.queue(init);
        self.begun = true;
        let audio_name = audio.map(|audio| audio.codec.name().to_owned());
        tracing::info!(
            clip.id = %self.id,
            before_ms_asked = millis(self.before),
            before_ms = self.before_ms,
            video = video.codec.name(),
            audio = audio_name.as_deref(),
            audio_transcoded_from = transcoded_from.map(|entry| entry.codec.name()),
            audio_omitted = self.omitted.as_deref(),
            "clip: started"
        );
        self.outbox.push(ClipReport::Started {
            before_ms: self.before_ms,
            video: video.codec.name().to_owned(),
            picture: params::track_params(&video.codec).picture,
            audio: audio_name,
        });
        if let Some(codec) = &self.omitted {
            self.outbox.push(ClipReport::Warning {
                code: "audio_omitted".to_owned(),
                message: format!(
                    "{codec} does not fit the clip's container; the clip has no audio"
                ),
            });
        }
        Ok(())
    }

    /// What a failure of the container (or of the audio's transcode) at
    /// `what` does: logged, the clip ends.
    fn failed(&self, what: &'static str) -> impl FnOnce(ClipError) -> EndReason + '_ {
        move |err| {
            tracing::warn!(clip.id = %self.id, what, error = %err, "clip: the container failed");
            EndReason::InternalError
        }
    }

    /// A control event of `track`: a switch to another source ends the
    /// clip, started or not, since another source is another stream, and
    /// so do control events the subscription lost, since a codec change or
    /// a switch among them leaves the frames after them under a codec the
    /// clip does not know; a codec other than its sample entry's ends it
    /// once the container started, since one file has one entry per track;
    /// before, it is the entry the frames after it go under, audio the
    /// container cannot carry as it is transcoded by a new [`ToOpus`] for
    /// it (and no longer for one it carries), or, for audio the container
    /// cannot carry nor the clip transcode, the audio is dropped, the clip
    /// warned `audio_omitted` as at the outset. Before the start the clip
    /// takes every item it can after each push, so the change leads its
    /// track then and ending the track drops no frame.
    fn control(
        &mut self,
        track: Kind,
        event: &TrackEvent,
        media: &mut Media,
    ) -> Result<(), EndReason> {
        tracing::debug!(clip.id = %self.id, %track, ?event, "clip: track event");
        let codec = match event {
            TrackEvent::TrackChanged(codec) => codec,
            TrackEvent::SourceSwitched => {
                tracing::info!(clip.id = %self.id, %track, "clip: the connection switched to another source; ending");
                return Err(EndReason::StreamChanged);
            }
            TrackEvent::ControlLost { skipped } => {
                tracing::info!(clip.id = %self.id, %track, skipped, "clip: the track's control events were lost, so the codec of its frames is unknown; ending");
                return Err(EndReason::StreamChanged);
            }
            _ => return Ok(()),
        };
        let entry = match track {
            Kind::Video => Some(&mut media.entries.0),
            Kind::Audio => media.entries.1.as_mut(),
        };
        let Some(entry) = entry.filter(|entry| entry.codec != **codec) else {
            return Ok(());
        };
        if self.begun {
            tracing::info!(clip.id = %self.id, %track, codec = codec.name(), "clip: the track changed; ending");
            return Err(EndReason::StreamChanged);
        }
        if track == Kind::Audio {
            // No frame went into the chain before the start: one for the
            // new codec takes its place.
            self.transcoder = None;
            if !self.factory.accepts(codec) {
                self.transcoder = transcoder(codec, self.factory.as_ref());
                if self.transcoder.is_none() {
                    tracing::info!(clip.id = %self.id, codec = codec.name(), "clip: the audio changed before the start to a codec the container cannot carry nor the clip transcode; going without");
                    self.omitted = Some(codec.name().to_owned());
                    media.entries.1 = None;
                    media.audio = None;
                    media.interleaver.queue_mut().end(Kind::Audio);
                    return Ok(());
                }
            }
        }
        tracing::debug!(clip.id = %self.id, %track, codec = codec.name(), transcoded = self.transcoder.is_some(), "clip: the track changed before the start; its entry follows");
        entry.codec = (**codec).clone();
        Ok(())
    }

    /// A hole from clip media time `from` to `to`, for `reason`: counted,
    /// logged rate-limited and reported, up to [`MAX_GAP_REPORTS`].
    fn gap(&mut self, reason: &'static str, from: Duration, to: Duration) {
        self.gaps = self.gaps.saturating_add(1);
        let (from_ms, to_ms) = (millis(from), millis(to));
        if let Some(count) = self.gap_log.hit(self.clock.now()) {
            tracing::warn!(clip.id = %self.id, reason, from_ms, to_ms, count, "clip: gap");
        }
        if self.gaps <= MAX_GAP_REPORTS {
            self.outbox.push(ClipReport::Gap {
                reason: reason.to_owned(),
                from_ms,
                to_ms,
            });
        } else if self.gaps == MAX_GAP_REPORTS.saturating_add(1) {
            tracing::warn!(
                clip.id = %self.id,
                limit = MAX_GAP_REPORTS,
                "clip: gap reports capped; the rest are counted in its stop"
            );
        }
    }

    /// Queues the container's `bytes` for the pipe, in order. An empty
    /// slice is left out: the pipe would take nothing of it, which reads
    /// as full.
    fn queue(&mut self, bytes: Vec<Bytes>) {
        self.pending
            .extend(bytes.into_iter().filter(|bytes| !bytes.is_empty()));
    }

    /// Hands the pipe what it takes now of the pending bytes; the reader's
    /// end closed is `client_gone`.
    fn write(&mut self) -> Result<(), EndReason> {
        while !self.pending.is_empty() {
            let slices: Vec<IoSlice<'_>> = self
                .pending
                .iter()
                .take(MAX_WRITE_SLICES)
                .map(|bytes| IoSlice::new(bytes))
                .collect();
            match self.pipe.try_write_vectored(&slices) {
                Ok(written) if written > 0 => self.advance(written),
                Err(err) if err.kind() != io::ErrorKind::WouldBlock => {
                    tracing::debug!(clip.id = %self.id, error = %err, "clip: the write failed");
                    return Err(gone(&self.id));
                }
                // The pipe is full.
                _ => return Ok(()),
            }
        }
        Ok(())
    }

    /// `written` bytes of the pending ones went into the pipe.
    fn advance(&mut self, written: usize) {
        self.written = self
            .written
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        let mut left = written;
        while left > 0
            && let Some(front) = self.pending.front_mut()
        {
            if front.len() > left {
                *front = front.slice(left..);
                left = 0;
            } else {
                left = left.saturating_sub(front.len());
                self.pending.pop_front();
            }
        }
    }

    /// Sends the reports queued so far, in order.
    async fn send_reports(&mut self) {
        for report in std::mem::take(&mut self.outbox) {
            // A worker that stopped taking reports is gone; nobody waits.
            let _sent = self.reports.send((self.id.clone(), report)).await;
        }
    }

    /// A graceful end: what the queue still holds goes into the container
    /// and the pipe, frames held for the other track released at once, up
    /// to the first frame captured at or after the clip's end, for at most
    /// [`FINISH_GRACE`] of a reader taking it; what is left then is
    /// dropped. Once the video met its end, the video frames queued behind
    /// that frame are left out ([`Self::frame`]), and the audio's end
    /// stops the drain. `client_gone` when the reader went meanwhile, and
    /// what else ends the clip on the way (a codec change, the container
    /// failing a frame); reaching the clip's own end keeps the reason it
    /// ends for. It yields after every [`MAX_STEP_PACKETS`] packets it
    /// transcodes, a frame that completes none counting one, as `record`
    /// does between steps.
    async fn drain(&mut self, media: &mut Media) -> Option<EndReason> {
        let deadline = self.clock.now().checked_add(FINISH_GRACE);
        loop {
            if let Err(reason) = self.write() {
                return Some(reason);
            }
            if self.pending.is_empty() {
                if self.step_packets >= MAX_STEP_PACKETS {
                    // As between the steps of `record`: the worker's other
                    // tasks run first, then the drain goes on.
                    self.step_packets = 0;
                    tokio::task::yield_now().await;
                }
                // Every item was queued by now, so its hold ends by then.
                let now = self.clock.now();
                let release = now
                    .checked_add(self.settings.policy.max_skew)
                    .unwrap_or(now);
                let out = media.interleaver.next(release)?;
                if let Err(end) = self.take(out, media) {
                    return (end != self.end_reason).then_some(end);
                }
                continue;
            }
            let left = deadline.map_or(FINISH_GRACE, |deadline| {
                deadline.saturating_duration_since(self.clock.now())
            });
            tokio::select! {
                _ = self.pipe.writable() => {}
                () = self.clock.sleep(left) => {
                    tracing::warn!(
                        clip.id = %self.id,
                        queued = media.interleaver.queue().bytes(),
                        "clip: the reader did not take the queued frames in time; ending without them"
                    );
                    return None;
                }
            }
        }
    }

    /// Ends the clip for `reason`: the container's last fragment and the
    /// bytes still pending go to the pipe for at most [`FINISH_GRACE`],
    /// unless the reader is gone. A container that fails the last
    /// fragment ends a graceful clip `internal_error`, and a reader that
    /// goes meanwhile, or does not take the last bytes in time, a
    /// graceful clip `client_gone`: either way its file is not whole. Any
    /// other reason already says the clip did not end as asked,
    /// `shutting_down` included, and stays. The pipe closes, and `Stopped`
    /// is the last report, its duration the furthest media time a frame
    /// was put at. Its `bytes` is the file's length: the bytes the pipe
    /// took and those it did not take in time.
    async fn finish(mut self, mut reason: EndReason) {
        if reason != EndReason::ClientGone {
            if self.begun {
                match self.muxer.finish() {
                    Ok(last) => self.queue(last),
                    Err(err) => {
                        tracing::warn!(clip.id = %self.id, error = %err, "clip: the container's last fragment failed");
                        if reason.is_graceful() {
                            reason = EndReason::InternalError;
                        }
                    }
                }
            }
            if let Err(gone) = self.flush().await
                && reason.is_graceful()
            {
                reason = gone;
            }
        }
        self.send_reports().await;
        let duration_ms = millis(self.reached);
        let Self {
            id,
            pipe,
            reports,
            written,
            left_out,
            gaps,
            ..
        } = self;
        drop(pipe);
        // The file's length: what the pipe took and the tail it did not
        // take in time, so the body, which read only the former, is cut.
        let bytes = written.saturating_add(left_out);
        tracing::info!(
            clip.id = %id,
            reason = reason.name(),
            bytes,
            left_out,
            duration_ms,
            gaps,
            "clip: stopped"
        );
        let stopped = ClipReport::Stopped {
            reason: reason.name().to_owned(),
            bytes,
            duration_ms,
            gaps,
        };
        // As in `send_reports`.
        let _sent = reports.send((id, stopped)).await;
    }

    /// Writes the pending bytes as the pipe takes them, for at most
    /// [`FINISH_GRACE`]. A reader that takes them not in time gets the
    /// file without them, counted in `left_out`, and one that is gone
    /// gets nothing more: either way the file is not whole,
    /// `client_gone`.
    async fn flush(&mut self) -> Result<(), EndReason> {
        let deadline = self.clock.now().checked_add(FINISH_GRACE);
        loop {
            self.write()?;
            if self.pending.is_empty() {
                return Ok(());
            }
            let left = deadline.map_or(FINISH_GRACE, |deadline| {
                deadline.saturating_duration_since(self.clock.now())
            });
            tokio::select! {
                _ = self.pipe.writable() => {}
                () = self.clock.sleep(left) => {
                    let pending: usize = self.pending.iter().map(Bytes::len).sum();
                    self.left_out = u64::try_from(pending).unwrap_or(u64::MAX);
                    tracing::warn!(clip.id = %self.id, pending, "clip: the reader did not take the last bytes in time; closing without them");
                    return Err(EndReason::ClientGone);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::future::Future;
    use std::os::fd::OwnedFd;

    use lotse_codec::{g711, g722};
    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::let_assert;
    use lotse_core::source::TrackPublisher;
    use lotse_core::test_util::{FakeClipFailure, FakeClipMuxerFactory, fake_aac};
    use lotse_core::track::TrackLimits;
    use tokio::io::AsyncReadExt as _;
    use tracing::Level;

    use super::*;
    use crate::test_logs::Logs;

    /// The window every rig's tracks keep.
    const WINDOW: Duration = Duration::from_secs(30);

    /// `future`, or a failed test after ten seconds of real time.
    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::select! {
            out = future => out,
            () = SystemClock.sleep(Duration::from_secs(10)) => panic!("nothing within 10 s"),
        }
    }

    /// Lets the clip tasks run until they wait.
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    fn h264() -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        }
    }

    fn spec(before_ms: u32, after_ms: Option<u32>, audio: bool) -> ClipSpec {
        ClipSpec {
            clip_id: "k1".into(),
            before_ms,
            after_ms,
            audio,
        }
    }

    /// A connection's tracks on a fake clock, each keeping [`WINDOW`], and
    /// the clips that read them.
    struct Rig {
        clock: Arc<FakeClock>,
        t0: Instant,
        set: Arc<TrackSet>,
        publisher: TrackPublisher,
        video: Option<Arc<Track>>,
        audio: Option<Arc<Track>>,
        clips: Clips,
        reports: mpsc::Receiver<(String, ClipReport)>,
    }

    impl Rig {
        /// The tracks of `video` and `audio`, declared ready if `ready`;
        /// the clips report on a channel of `capacity`.
        fn with(video: Option<Codec>, audio: Option<Codec>, ready: bool, capacity: usize) -> Self {
            let clock = Arc::new(FakeClock::default());
            let t0 = clock.now();
            let set = TrackSet::new(TrackLimits::default(), t0);
            let mut publisher = set.publisher();
            let video = video.map(|codec| publisher.declare(Kind::Video, codec, 90_000));
            let audio = audio.map(|codec| {
                let rate = codec.rtp_clock_rate().unwrap_or(8_000);
                publisher.declare(Kind::Audio, codec, rate)
            });
            for track in video.iter().chain(&audio) {
                track.set_preroll(Some(WINDOW));
            }
            if ready {
                publisher.ready();
            }
            let (reports_tx, reports) = mpsc::channel(capacity);
            Self {
                clock,
                t0,
                set,
                publisher,
                video,
                audio,
                clips: Clips::new(reports_tx),
                reports,
            }
        }

        /// H.264 video and `audio`, ready.
        fn new(audio: Option<Codec>) -> Self {
            Self::with(Some(h264()), audio, true, 1024)
        }

        fn at(&self, ms: u64) -> Instant {
            self.t0 + Duration::from_millis(ms)
        }

        /// Moves the clock to `ms` after the start, never back.
        fn advance_to(&self, ms: u64) {
            let at = self.at(ms);
            let now = self.clock.now();
            if at > now {
                self.clock.advance(at - now);
            }
        }

        fn video(&self) -> &Arc<Track> {
            self.video.as_ref().unwrap()
        }

        /// Video frame `index`, `len` bytes, captured and arriving at `ms`,
        /// the clock moved there.
        fn video_frame(&self, ms: u64, index: u32, keyframe: bool, len: usize) {
            self.video_frame_on(self.video(), ms, index, keyframe, len);
        }

        /// [`Self::video_frame`] on `track`, a standby's.
        fn video_frame_on(&self, track: &Track, ms: u64, index: u32, keyframe: bool, len: usize) {
            self.advance_to(ms);
            let header = if keyframe { 0x65 } else { 0x41 };
            assert!(track.publish_frame(MediaFrame {
                ts: MediaTime::from_ticks(i64::from(index) * 3_000),
                wallclock: self.at(ms),
                arrival: self.at(ms),
                keyframe,
                discontinuity: false,
                epoch: 0,
                payload: vec![header; len].into(),
            }));
        }

        /// Audio frame `index`, captured on the 64 ms grid.
        fn audio_frame(&self, index: u32) {
            let ms = u64::from(index) * 64;
            self.advance_to(ms);
            assert!(self.audio.as_ref().unwrap().publish_frame(MediaFrame {
                ts: MediaTime::from_ticks(i64::from(index) * 1_024),
                wallclock: self.at(ms),
                arrival: self.at(ms),
                keyframe: true,
                discontinuity: false,
                epoch: 0,
                payload: vec![0xe0; 4].into(),
            }));
        }

        /// A 20 ms G.711 or G.722 frame `index` (160 ticks of the 8000 Hz
        /// clock, RFC 3551 §4.5.2, §4.5.14), captured on the 20 ms grid.
        fn narrowband_frame(&self, index: u32, payload: &Bytes) {
            self.narrowband_frame_stamped(index, i64::from(index) * 160, payload);
        }

        /// [`Self::narrowband_frame`] stamped `ticks`, wherever the grid has it.
        fn narrowband_frame_stamped(&self, index: u32, ticks: i64, payload: &Bytes) {
            self.narrowband_frame_at(u64::from(index) * 20, ticks, payload);
        }

        /// [`Self::narrowband_frame_stamped`] captured at `ms`, off the 20 ms grid.
        fn narrowband_frame_at(&self, ms: u64, ticks: i64, payload: &Bytes) {
            self.advance_to(ms);
            assert!(self.audio.as_ref().unwrap().publish_frame(MediaFrame {
                ts: MediaTime::from_ticks(ticks),
                wallclock: self.at(ms),
                arrival: self.at(ms),
                keyframe: true,
                discontinuity: false,
                epoch: 0,
                payload: payload.clone(),
            }));
        }

        /// Starts `spec`'s clip now, through `factory` under `settings`;
        /// the read end of its pipe.
        fn start_with(
            &mut self,
            spec: ClipSpec,
            factory: impl ClipMuxerFactory + 'static,
            settings: ClipSettings,
        ) -> Reader {
            let clock: Arc<dyn Clock> = self.clock.clone();
            self.start_on(spec, factory, settings, clock)
        }

        /// [`Self::start_with`], the clip reading `clock`.
        fn start_on(
            &mut self,
            spec: ClipSpec,
            factory: impl ClipMuxerFactory + 'static,
            settings: ClipSettings,
            clock: Arc<dyn Clock>,
        ) -> Reader {
            let (reader, writer) = io::pipe().unwrap();
            self.clips.start(ClipStart {
                spec,
                pipe: pipe::Sender::from_owned_fd(OwnedFd::from(writer)).unwrap(),
                tracks: Arc::clone(&self.set),
                factory: Arc::new(factory),
                settings,
                clock,
            });
            Reader(pipe::Receiver::from_owned_fd(OwnedFd::from(reader)).unwrap())
        }

        fn start(&mut self, spec: ClipSpec) -> Reader {
            self.start_with(
                spec,
                FakeClipMuxerFactory::default(),
                ClipSettings::default(),
            )
        }

        async fn report(&mut self) -> ClipReport {
            let (clip_id, report) = within(self.reports.recv()).await.unwrap();
            assert_eq!(clip_id, "k1");
            report
        }

        /// Every report up to and including `Stopped`.
        async fn until_stopped(&mut self) -> Vec<ClipReport> {
            let mut seen = Vec::new();
            loop {
                let report = self.report().await;
                let stopped = matches!(report, ClipReport::Stopped { .. });
                seen.push(report);
                if stopped {
                    return seen;
                }
            }
        }
    }

    /// The reader's end of a clip's pipe.
    struct Reader(pipe::Receiver);

    impl Reader {
        /// Reads until `total` bytes came.
        async fn read(&mut self, total: usize) -> Vec<u8> {
            let mut bytes = vec![0; total];
            within(self.0.read_exact(&mut bytes)).await.unwrap();
            bytes
        }

        /// Everything up to the end of the pipe.
        async fn rest(mut self) -> Vec<u8> {
            let mut bytes = Vec::new();
            within(self.0.read_to_end(&mut bytes)).await.unwrap();
            bytes
        }
    }

    /// The fake container's lines, payloads skipped.
    fn lines(bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while let Some(end) = rest.iter().position(|byte| *byte == b'\n') {
            let line = String::from_utf8(rest[..end].to_vec()).unwrap();
            rest = &rest[end + 1..];
            if line.starts_with("frame") {
                let len: usize = line.rsplit(' ').next().unwrap().parse().unwrap();
                rest = &rest[len..];
            }
            out.push(line);
        }
        assert!(rest.is_empty(), "{} bytes after the last line", rest.len());
        out
    }

    fn stopped(reason: &str, bytes: usize, duration_ms: u32, gaps: u32) -> ClipReport {
        ClipReport::Stopped {
            reason: reason.into(),
            bytes: bytes as u64,
            duration_ms,
            gaps,
        }
    }

    fn started(before_ms: u32, audio: Option<&str>) -> ClipReport {
        ClipReport::Started {
            before_ms,
            video: "h264".into(),
            picture: None,
            audio: audio.map(Into::into),
        }
    }

    fn gap(reason: &str, from_ms: u32, to_ms: u32) -> ClipReport {
        ClipReport::Gap {
            reason: reason.into(),
            from_ms,
            to_ms,
        }
    }

    /// Ten seconds of 10 fps video, a keyframe each second, and AAC
    /// every 64 ms: the ring holds them all.
    fn ten_seconds(rig: &Rig) {
        let mut audio = 0;
        for index in 0..100_u32 {
            let ms = u64::from(index) * 100;
            while u64::from(audio) * 64 <= ms {
                rig.audio_frame(audio);
                audio += 1;
            }
            rig.video_frame(
                ms,
                index,
                index % 10 == 0,
                if index % 10 == 0 { 32 } else { 16 },
            );
        }
        rig.advance_to(10_000);
    }

    /// A clip starts at the newest keyframe captured at or before `now −
    /// before_ms` (6 s for 10 s − 3.5 s), with the audio frame playing then
    /// (captured at 5.952 s), and runs on live until the first frame captured
    /// at `now + after_ms`, which it does not write; `before_ms` is that
    /// keyframe's age, `bytes` what the pipe took, the duration from the first
    /// frame to the last.
    #[tokio::test]
    async fn a_clip_starts_at_the_newest_keyframe_before_its_window_and_ends_at_its_after() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::new(Some(fake_aac()));
        ten_seconds(&rig);
        let reader = rig.start(spec(3_500, Some(1_000), true));
        settle().await;
        assert_eq!(rig.report().await, started(4_000, Some("aac_lc")));
        let mut audio = 155;
        for index in 100..111_u32 {
            let ms = u64::from(index) * 100;
            while u64::from(audio) * 64 <= ms + 200 {
                rig.audio_frame(audio);
                audio += 1;
            }
            rig.video_frame(ms, index, index % 10 == 0, 16);
            settle().await;
        }
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        let lines = lines(&bytes);
        assert_eq!(lines[0], "init video=h264 audio=aac_lc");
        assert_eq!(lines[1], format!("frame a 0 {} k 4", 93 * 1_024));
        assert_eq!(lines[2], "frame v 0 180000 k 32");
        assert_eq!(lines.last().unwrap(), "end");
        let video: Vec<&String> = lines
            .iter()
            .filter(|line| line.starts_with("frame v"))
            .collect();
        assert_eq!(video.len(), 50, "6.0 s to 10.9 s");
        assert_eq!(video.last().unwrap().as_str(), "frame v 0 327000 - 16");
        let last_audio = lines
            .iter()
            .rfind(|line| line.starts_with("frame a"))
            .unwrap();
        assert_eq!(
            *last_audio,
            format!("frame a 0 {} k 4", 171 * 1_024),
            "10.944 s"
        );
        // 10.944 s − 5.952 s.
        assert_eq!(reports, vec![stopped("completed", bytes.len(), 4_992, 0)]);
        let started = logs.lines(Level::INFO, "clip: started");
        assert!(
            started[0].fields.contains("before_ms_asked=3500")
                && started[0].fields.contains("before_ms=4000")
                && started[0].fields.contains("audio=\"aac_lc\""),
            "{started:?}"
        );
        assert_eq!(logs.count(Level::INFO, "clip: stopped"), 1);
    }

    /// An audio codec the container cannot carry and the clip cannot
    /// transcode leaves the clip video-only with an `audio_omitted`
    /// warning after `started`; a clip that asks for no audio, or a
    /// stream without any, gets none and no warning. `clip/stop` ends a
    /// clip `stopped`, its last fragment written.
    #[tokio::test]
    async fn audio_the_container_cannot_carry_is_omitted_with_a_warning() {
        let mut rig = Rig::new(Some(Codec::Unsupported {
            kind: Kind::Audio,
            name: "l16".into(),
        }));
        let reader = rig.start(spec(0, None, true));
        rig.video_frame(0, 0, true, 32);
        assert_eq!(rig.report().await, started(0, None));
        assert_eq!(
            rig.report().await,
            ClipReport::Warning {
                code: "audio_omitted".into(),
                message: "l16 does not fit the clip's container; the clip has no audio".into(),
            }
        );
        assert!(rig.clips.stop("k1", EndReason::Stopped));
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            ["init video=h264", "frame v 0 0 k 32", "end"]
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 0, 0)]);

        for (audio, asked) in [(Some(fake_aac()), false), (None, true)] {
            let mut rig = Rig::new(audio);
            let reader = rig.start(spec(0, None, asked));
            rig.video_frame(0, 0, true, 32);
            assert_eq!(rig.report().await, started(0, None));
            rig.clips.stop("k1", EndReason::Stopped);
            assert_eq!(rig.until_stopped().await.len(), 1, "no warning");
            assert_eq!(lines(&reader.rest().await)[0], "init video=h264");
        }
    }

    /// A container that takes what the fake one takes but Opus.
    #[derive(Debug)]
    struct NoOpus;

    impl ClipMuxerFactory for NoOpus {
        fn accepts(&self, codec: &Codec) -> bool {
            codec.family() != lotse_core::codec::CodecFamily::Opus
                && FakeClipMuxerFactory::default().accepts(codec)
        }

        fn muxer(&self, policy: &ClipPolicy) -> Box<dyn ClipMuxer> {
            FakeClipMuxerFactory::default().muxer(policy)
        }
    }

    /// A container that counts the frames pushed into it, audio (`.0`) and
    /// video (`.1`): the fake one otherwise.
    #[derive(Debug, Default)]
    struct Counting(
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    );

    /// [`Counting`]'s muxer.
    struct CountingMuxer {
        inner: Box<dyn ClipMuxer>,
        /// Audio frames pushed.
        audio: Arc<std::sync::atomic::AtomicUsize>,
        /// Video frames pushed.
        video: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ClipMuxerFactory for Counting {
        fn accepts(&self, codec: &Codec) -> bool {
            FakeClipMuxerFactory::default().accepts(codec)
        }

        fn muxer(&self, policy: &ClipPolicy) -> Box<dyn ClipMuxer> {
            Box::new(CountingMuxer {
                inner: FakeClipMuxerFactory::default().muxer(policy),
                audio: Arc::clone(&self.0),
                video: Arc::clone(&self.1),
            })
        }
    }

    impl ClipMuxer for CountingMuxer {
        fn start(
            &mut self,
            video: &ClipTrack,
            audio: Option<&ClipTrack>,
        ) -> Result<Vec<Bytes>, ClipError> {
            self.inner.start(video, audio)
        }

        fn set_origin(&mut self, origin: Instant) {
            self.inner.set_origin(origin);
        }

        fn push(&mut self, track: Kind, frame: Arc<MediaFrame>) -> Result<Vec<Bytes>, ClipError> {
            let count = match track {
                Kind::Audio => &self.audio,
                Kind::Video => &self.video,
            };
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.push(track, frame)
        }

        fn media_time(&self, track: Kind) -> Duration {
            self.inner.media_time(track)
        }

        fn finish(&mut self) -> Result<Vec<Bytes>, ClipError> {
            self.inner.finish()
        }
    }

    /// Yields `ticks` more times, as another task of the worker runs
    /// between the clip's polls (on the test's one thread the clip runs
    /// between two of them), and appends to `out` the audio frames `audio`
    /// counted since the tick before (`out`'s sum is what it counted
    /// before); the pipe is read empty into `bytes` at each tick so it never
    /// fills.
    async fn per_tick(
        audio: &std::sync::atomic::AtomicUsize,
        reader: &Reader,
        ticks: usize,
        out: &mut Vec<usize>,
        bytes: &mut Vec<u8>,
    ) {
        let mut buf = vec![0; 1 << 16];
        for _ in 0..ticks {
            tokio::task::yield_now().await;
            while let Ok(read @ 1..) = reader.0.try_read(&mut buf) {
                bytes.extend_from_slice(&buf[..read]);
            }
            let now = audio.load(std::sync::atomic::Ordering::SeqCst);
            out.push(now - out.iter().sum::<usize>());
        }
    }

    /// A clip transcodes audio only when it can (G.711 or G.722) and the
    /// container takes what comes out (Opus, RFC 7587): a container
    /// without Opus gets no transcode, so that audio is omitted, and a
    /// codec the clip cannot transcode gets none either.
    #[tokio::test]
    async fn a_transcode_needs_audio_it_can_transcode_and_a_container_that_takes_opus() {
        let fake = FakeClipMuxerFactory::default();
        for codec in [Codec::Pcmu, Codec::Pcma] {
            assert!(transcoder(&codec, &fake).is_some(), "{codec:?}");
            assert!(transcoder(&codec, &NoOpus).is_none(), "{codec:?}");
        }
        assert!(transcoder(&Codec::G722, &fake).is_some());
        assert!(transcoder(&Codec::G722, &NoOpus).is_none());
        let l16 = Codec::Unsupported {
            kind: Kind::Audio,
            name: "l16".into(),
        };
        assert!(transcoder(&l16, &fake).is_none());

        // A G.711 clip into the container without Opus: video only, and
        // the audio omitted with a warning.
        let mut rig = Rig::new(Some(Codec::Pcmu));
        let reader = rig.start_with(spec(0, None, true), NoOpus, ClipSettings::default());
        rig.video_frame(0, 0, true, 32);
        assert_eq!(rig.report().await, started(0, None));
        assert_eq!(
            rig.report().await,
            ClipReport::Warning {
                code: "audio_omitted".into(),
                message: "pcmu does not fit the clip's container; the clip has no audio".into(),
            }
        );
        assert!(rig.clips.stop("k1", EndReason::Stopped));
        rig.until_stopped().await;
        assert_eq!(lines(&reader.rest().await)[0], "init video=h264");
    }

    /// 20 ms of a 1 kHz tone in `codec`, G.711 or G.722.
    fn narrowband_payload(codec: &Codec) -> Bytes {
        let tone = g722::test_data::tone(1_000, 320);
        match g711::Law::of(codec) {
            Some(law) => tone
                .iter()
                .step_by(2)
                .map(|sample| law.encode(*sample))
                .collect(),
            None => g722::test_data::encode(&tone).into(),
        }
    }

    /// Ten seconds of 10 fps video, a keyframe each second, and a 20 ms
    /// frame of `codec` every 20 ms: the ring holds them all.
    fn ten_narrowband_seconds(rig: &Rig, codec: &Codec) {
        ten_narrowband_seconds_stamped(rig, codec, |index| i64::from(index) * 160);
    }

    /// [`ten_narrowband_seconds`], audio frame `index` stamped `stamp(index)`.
    fn ten_narrowband_seconds_stamped(rig: &Rig, codec: &Codec, stamp: fn(u32) -> i64) {
        let payload = narrowband_payload(codec);
        let mut audio = 0;
        for index in 0..100_u32 {
            let ms = u64::from(index) * 100;
            while u64::from(audio) * 20 <= ms {
                rig.narrowband_frame_stamped(audio, stamp(audio), &payload);
                audio += 1;
            }
            rig.video_frame(
                ms,
                index,
                index % 10 == 0,
                if index % 10 == 0 { 32 } else { 16 },
            );
        }
        rig.advance_to(10_000);
    }

    /// The fake container's audio lines as (epoch, timestamp, bytes).
    fn audio_samples(lines: &[String]) -> Vec<(u32, i64, usize)> {
        lines
            .iter()
            .filter(|line| line.starts_with("frame a"))
            .map(|line| {
                let fields: Vec<&str> = line.split(' ').collect();
                assert_eq!(fields[4], "k", "every Opus packet is a sync sample");
                (
                    fields[2].parse().unwrap(),
                    fields[3].parse().unwrap(),
                    fields[5].parse().unwrap(),
                )
            })
            .collect()
    }

    /// G.711 (PCMU, PCMA) and G.722 audio goes into the clip as Opus at
    /// 48 kHz, without `audio_omitted`: the pre-roll's 4 s in a burst at the
    /// start (more than one step's worth of packets) and the live frames
    /// after them, one run of 20 ms packets (RFC 7587 §4.1) from the first
    /// frame's timestamp less the transcode's delay, one packet per 20 ms
    /// frame but the last, which the resampler's short start holds back.
    /// The clip's media time starts that delay before its first frame.
    #[tokio::test]
    async fn rfc7587_4_1_g711_and_g722_audio_is_transcoded_to_opus_without_a_warning() {
        let (logs, _guard) = Logs::capture();
        for codec in [Codec::Pcmu, Codec::Pcma, Codec::G722] {
            let mut rig = Rig::new(Some(codec.clone()));
            ten_narrowband_seconds(&rig, &codec);
            let reader = rig.start(spec(3_500, Some(1_000), true));
            settle().await;
            assert_eq!(rig.report().await, started(4_000, Some("opus")));
            let payload = narrowband_payload(&codec);
            let mut audio = 500;
            for index in 100..111_u32 {
                let ms = u64::from(index) * 100;
                while u64::from(audio) * 20 <= ms + 200 {
                    rig.narrowband_frame(audio, &payload);
                    audio += 1;
                }
                rig.video_frame(ms, index, index % 10 == 0, 16);
                settle().await;
            }
            let reports = rig.until_stopped().await;
            let bytes = reader.rest().await;
            let lines = lines(&bytes);
            assert_eq!(lines[0], "init video=h264 audio=opus");
            assert_eq!(
                lines
                    .iter()
                    .filter(|line| line.starts_with("frame v"))
                    .count(),
                50,
                "6.0 s to 10.9 s"
            );
            let delay = ToOpus::new(&codec).unwrap().delay();
            let lead = i64::try_from(delay.as_nanos() * 48 / 1_000_000).unwrap();
            // The frame playing at the 6 s keyframe, captured with it, to the
            // last captured before 11 s: 250 frames.
            let first = 6 * 48_000 - lead;
            let expected: Vec<(u32, i64)> = (0..249).map(|k| (0, first + 960 * k)).collect();
            let samples = audio_samples(&lines);
            let timeline: Vec<(u32, i64)> =
                samples.iter().map(|(epoch, ts, _)| (*epoch, *ts)).collect();
            assert_eq!(timeline, expected, "{codec:?}");
            assert!(samples.iter().all(|(_, _, len)| *len > 0));
            // The last packet's capture time, 10.96 s less the delay, from the
            // origin, 6 s less the delay.
            assert_eq!(reports, vec![stopped("completed", bytes.len(), 4_960, 0)]);
        }
        let started = logs.lines(Level::INFO, "clip: started");
        for (line, from) in started.iter().zip(["pcmu", "pcma", "g722"]) {
            assert!(
                line.fields.contains("audio=\"opus\"")
                    && line
                        .fields
                        .contains(&format!("audio_transcoded_from=\"{from}\""))
                    && !line.fields.contains("audio_omitted=Some"),
                "{line:?}"
            );
        }
    }

    /// The camera's audio codec changing after the clip started
    /// transcoding it ends the clip `stream_changed`, as any track change
    /// once the container started does.
    #[tokio::test]
    async fn a_transcoded_audio_codec_that_changes_after_the_start_ends_the_clip_stream_changed() {
        let payload = narrowband_payload(&Codec::Pcmu);
        let mut rig = Rig::new(Some(Codec::Pcmu));
        let _reader = rig.start(spec(0, None, true));
        rig.video_frame(0, 0, true, 32);
        rig.narrowband_frame(1, &payload);
        rig.narrowband_frame(2, &payload);
        settle().await;
        // The clip task first runs at 40 ms, the keyframe captured at 0.
        assert_eq!(rig.report().await, started(40, Some("opus")));
        rig.audio.as_ref().unwrap().set_codec(Codec::Pcma);
        rig.video_frame(100, 1, false, 16);
        let reports = rig.until_stopped().await;
        let_assert_reason(&reports, "stream_changed");
    }

    /// The camera's audio codec changing before the container starts
    /// changes the transcode with it, since no frame went into the chain
    /// yet: G.722 to PCMU is transcoded by a PCMU chain (its packets
    /// start the PCMU chain's delay before the first frame, not G.722's),
    /// and PCMU to Opus, which the container carries, goes in as it is.
    #[tokio::test]
    async fn an_audio_change_before_the_start_changes_the_transcode_with_it() {
        let (logs, _guard) = Logs::capture();
        let payload = narrowband_payload(&Codec::Pcmu);
        let mut rig = Rig::new(Some(Codec::G722));
        let reader = rig.start(spec(0, None, true));
        settle().await;
        rig.audio.as_ref().unwrap().set_codec(Codec::Pcmu);
        settle().await;
        rig.video_frame(0, 0, true, 32);
        for index in 1..4 {
            rig.narrowband_frame(index, &payload);
        }
        settle().await;
        // The clip task first runs at 60 ms, the keyframe captured at 0.
        assert_eq!(rig.report().await, started(60, Some("opus")));
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        let file = lines(&bytes);
        assert_eq!(file[0], "init video=h264 audio=opus");
        let delay = ToOpus::new(&Codec::Pcmu).unwrap().delay();
        assert_ne!(delay, ToOpus::new(&Codec::G722).unwrap().delay());
        let lead = i64::try_from(delay.as_nanos() * 48 / 1_000_000).unwrap();
        // Frame 1 at 960 (48 kHz) makes no packet, frames 2 and 3 one each.
        let timeline: Vec<(u32, i64)> = audio_samples(&file)
            .iter()
            .map(|(epoch, ts, _)| (*epoch, *ts))
            .collect();
        assert_eq!(timeline, [(0, 960 - lead), (0, 1_920 - lead)]);
        let_assert_reason(&reports, "stopped");
        let logged = logs.lines(Level::INFO, "clip: started");
        assert!(
            logged[0].fields.contains("audio_transcoded_from=\"pcmu\""),
            "{logged:?}"
        );

        let mut rig = Rig::new(Some(Codec::Pcmu));
        let reader = rig.start(spec(0, None, true));
        settle().await;
        rig.audio
            .as_ref()
            .unwrap()
            .set_codec(Codec::Opus { channels: 2 });
        settle().await;
        rig.video_frame(10, 0, true, 32);
        rig.audio_frame(1);
        settle().await;
        // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
        assert_eq!(rig.report().await, started(54, Some("opus")));
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264 audio=opus",
                "frame v 0 0 k 32",
                "frame a 0 1024 k 4",
                "end"
            ]
        );
        let_assert_reason(&reports, "stopped");
        let logged = logs.lines(Level::INFO, "clip: started");
        assert!(
            !logged[1].fields.contains("audio_transcoded_from"),
            "{logged:?}"
        );
    }

    /// G.711 that comes back in place of Opus on a reconnect is transcoded
    /// on its own 8000 Hz clock (RFC 3551 §4.5.14), not the 48 kHz the
    /// track keeps from its first codec: whether the reconnect comes before
    /// the clip starts (its start picks the transcode) or while it waits for
    /// its first keyframe (the codec change does), its packets come out as
    /// for a track declared PCMU. Regression: the chain read the 8000 Hz
    /// stamps at 48 kHz, every 20 ms frame stepped back off the sample count
    /// and re-anchored, and the clip's audio had no packet.
    #[tokio::test]
    async fn rfc3551_4_5_14_g711_back_after_opus_is_transcoded_on_its_8000_hz_clock() {
        /// The camera reconnecting with PCMU where it had Opus: the track
        /// keeps its first rate (`TrackSet::declare`).
        fn reconnect(rig: &Rig) {
            let audio = rig.set.publisher().declare(Kind::Audio, Codec::Pcmu, 8_000);
            assert!(Arc::ptr_eq(&audio, rig.audio.as_ref().unwrap()));
            assert_eq!(audio.clock_rate(), 48_000, "the track keeps its first rate");
        }
        let payload = narrowband_payload(&Codec::Pcmu);
        let delay = ToOpus::new(&Codec::Pcmu).unwrap().delay();
        let lead = i64::try_from(delay.as_nanos() * 48 / 1_000_000).unwrap();
        for waiting in [false, true] {
            let mut rig = Rig::new(Some(Codec::Opus { channels: 1 }));
            if !waiting {
                reconnect(&rig);
            }
            let reader = rig.start(spec(0, None, true));
            settle().await;
            if waiting {
                reconnect(&rig);
                settle().await;
            }
            rig.video_frame(0, 0, true, 32);
            for index in 1..4 {
                rig.narrowband_frame(index, &payload);
            }
            settle().await;
            // The clip task first runs at 60 ms, the keyframe captured at 0.
            assert_eq!(
                rig.report().await,
                started(60, Some("opus")),
                "waiting {waiting}"
            );
            rig.clips.stop("k1", EndReason::Stopped);
            let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
            let file = lines(&bytes);
            assert_eq!(file[0], "init video=h264 audio=opus", "waiting {waiting}");
            // Frame 1 at 960 (48 kHz) makes no packet, frames 2 and 3 one each.
            let timeline: Vec<(u32, i64)> = audio_samples(&file)
                .iter()
                .map(|(epoch, ts, _)| (*epoch, *ts))
                .collect();
            assert_eq!(
                timeline,
                [(0, 960 - lead), (0, 1_920 - lead)],
                "waiting {waiting}"
            );
            let_assert_reason(&reports, "stopped");
        }
    }

    /// A container that never moves a frame back: each lasts 100 ms, and a
    /// frame captured before the latest one ended is put where it ends, as
    /// lotse-mux puts an epoch captured before the last frame began. Its
    /// bytes are the fake container's.
    #[derive(Debug)]
    struct Moving;

    /// [`Moving`]'s muxer: the fake one, and the latest place per track.
    struct MovingMuxer {
        inner: Box<dyn ClipMuxer>,
        origin: Option<Instant>,
        placed: HashMap<Kind, Duration>,
    }

    impl ClipMuxerFactory for Moving {
        fn accepts(&self, codec: &Codec) -> bool {
            FakeClipMuxerFactory::default().accepts(codec)
        }

        fn muxer(&self, policy: &ClipPolicy) -> Box<dyn ClipMuxer> {
            Box::new(MovingMuxer {
                inner: FakeClipMuxerFactory::default().muxer(policy),
                origin: None,
                placed: HashMap::new(),
            })
        }
    }

    impl ClipMuxer for MovingMuxer {
        fn start(
            &mut self,
            video: &ClipTrack,
            audio: Option<&ClipTrack>,
        ) -> Result<Vec<Bytes>, ClipError> {
            self.inner.start(video, audio)
        }

        fn set_origin(&mut self, origin: Instant) {
            self.origin.get_or_insert(origin);
        }

        fn push(&mut self, track: Kind, frame: Arc<MediaFrame>) -> Result<Vec<Bytes>, ClipError> {
            let origin = *self.origin.get_or_insert(frame.wallclock);
            let captured = frame.wallclock.saturating_duration_since(origin);
            let ended = self
                .placed
                .get(&track)
                .map(|placed| *placed + Duration::from_millis(100));
            let placed = ended.map_or(captured, |ended| captured.max(ended));
            self.placed.insert(track, placed);
            self.inner.push(track, frame)
        }

        fn media_time(&self, track: Kind) -> Duration {
            self.placed.get(&track).copied().unwrap_or_default()
        }

        fn finish(&mut self) -> Result<Vec<Bytes>, ClipError> {
            self.inner.finish()
        }
    }

    /// A reconnect whose first frame was captured before the frame ahead of
    /// it (the new connection's clock mapped a little early): the container
    /// puts it after that frame, and the gap is where the container put the
    /// two, so it never ends before it begins, and the clip's duration
    /// runs to there. Regression: from capture times the gap ended 50 ms
    /// before it began, a report the supervisor refuses, which ended the
    /// clip `internal_error` (the end-to-end clip test's camera reconnected
    /// within a frame); and the duration was the capture times' 100 ms,
    /// short of the gap's end.
    #[tokio::test]
    async fn a_reconnect_s_gap_is_where_the_container_put_its_frames() {
        assert!(Moving.accepts(&h264()), "what the fake container takes");
        let mut rig = Rig::new(None);
        let reader = rig.start_with(spec(0, None, false), Moving, ClipSettings::default());
        rig.video_frame(0, 0, true, 32);
        rig.video_frame(100, 1, false, 16);
        settle().await;
        rig.publisher.discontinuity();
        let captured = rig.at(50);
        assert!(rig.video().publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(0),
            wallclock: captured,
            arrival: rig.at(100),
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: vec![0x65; 32].into(),
        }));
        settle().await;
        // The clip task first runs at 100 ms, the keyframe captured at 0: 100 ms.
        assert_eq!(rig.report().await, started(100, None));
        assert_eq!(rig.report().await, gap("reconnect", 100, 200));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        // The duration is where the container put the last frame, as the
        // gap is: not its capture time, 100 ms after the first.
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 200, 1)]);
    }

    /// Frames dropped inside an epoch (the video's timestamp jumps by more
    /// than twice its frame interval) are a `frames_dropped` gap, B-frames are
    /// none; a reconnect (a new epoch) is a `reconnect` gap from the last frame
    /// of the old epoch to the first of the new, both in clip media time; the
    /// clip goes on.
    #[tokio::test]
    async fn a_reconnect_and_dropped_frames_are_gaps_in_clip_media_time() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        // Timestamps in steps of 3000 ticks: 100 ms apart, 6000.
        for (ms, step, keyframe) in [
            (0, 0, true),
            (100, 2, false),
            (200, 4, false),
            // A B-frame stamped before the newest: no hole.
            (150, 3, false),
            (300, 6, false),
            (700, 14, false),
        ] {
            rig.video_frame(ms, step, keyframe, 16);
            settle().await;
        }
        rig.publisher.discontinuity();
        rig.video_frame(3_000, 6, true, 32);
        rig.video_frame(3_100, 7, false, 16);
        settle().await;
        assert_eq!(rig.report().await, started(0, None));
        assert_eq!(rig.report().await, gap("frames_dropped", 300, 700));
        assert_eq!(rig.report().await, gap("reconnect", 700, 3_000));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(lines(&bytes)[7], "frame v 1 18000 k 32", "the new epoch's");
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 3_100, 2)]);
        let gaps = logs.lines(Level::WARN, "clip: gap");
        assert_eq!(gaps.len(), 1, "rate-limited: {gaps:?}");
        assert!(
            gaps[0].fields.contains("reason=\"frames_dropped\""),
            "{gaps:?}"
        );
    }

    /// A new epoch that begins mid-GOP (a server relaying the stream from
    /// the frame at hand) is written from its first keyframe on: the
    /// frames before it refer to pictures the clip never had. The
    /// `reconnect` gap ends at that keyframe. Regression (found end to end:
    /// MediaMTX 1.21.1, a publisher restarted inside a clip): the clip
    /// resumed with half a second of P-frames a decoder took the old
    /// epoch's pictures for. Leaving them out is logged once per epoch.
    #[tokio::test]
    async fn a_new_epoch_s_video_starts_at_its_first_keyframe() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        rig.video_frame(100, 1, false, 16);
        settle().await;
        rig.publisher.discontinuity();
        for (ms, index, keyframe) in [
            (3_000, 10, false),
            (3_100, 11, false),
            (3_200, 12, true),
            (3_300, 13, false),
        ] {
            rig.video_frame(ms, index, keyframe, if keyframe { 32 } else { 16 });
        }
        settle().await;
        // The clip task first runs at 100 ms, the keyframe captured at 0: 100 ms.
        assert_eq!(rig.report().await, started(100, None));
        assert_eq!(rig.report().await, gap("reconnect", 100, 3_200));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        let frames: Vec<String> = lines(&bytes)
            .into_iter()
            .filter(|line| line.starts_with("frame v"))
            .collect();
        assert_eq!(
            frames,
            [
                "frame v 0 0 k 32",
                "frame v 0 3000 - 16",
                "frame v 1 36000 k 32",
                "frame v 1 39000 - 16",
            ]
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 3_300, 1)]);
        assert_eq!(
            logs.count(
                Level::DEBUG,
                "clip: the new epoch's video is left out until its first keyframe"
            ),
            1,
            "once per epoch, not per frame"
        );
    }

    /// Capture times that jitter while the timestamps run evenly are no
    /// hole: before a camera's first Sender Report a frame's capture time
    /// is its arrival, and two frames arriving together made the shortest
    /// advance a millisecond and every later frame a `frames_dropped` gap.
    /// Nor is a frame that repeats the newest timestamp (it advances
    /// nothing, so it teaches no interval) or one that advances it by
    /// exactly twice the interval: a hole is more than twice. The frame
    /// after the last settles it, which a jump needs to be a gap.
    /// Regression (found end to end: MediaMTX 1.21.1 relaying libx265, and
    /// the first seconds after a reconnect): 163 gaps in a clip whose file
    /// had none.
    #[tokio::test]
    async fn frames_arriving_together_with_even_timestamps_are_no_gap() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        for (ms, index) in [
            (0, 0),
            (40, 1),
            (41, 2),
            (120, 3),
            (160, 4),
            (161, 5),
            (240, 6),
            // The newest timestamp again: no advance, so no interval.
            (250, 6),
            // Twice the interval: not more than twice, no hole.
            (320, 8),
            (360, 9),
        ] {
            rig.video_frame(ms, index, index == 0, 16);
            settle().await;
        }
        assert_eq!(rig.report().await, started(0, None));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 360, 0)]);
    }

    /// A reader that stops reading fills the pipe, then the clip's queue; the
    /// frame that does not fit drops the video to its next keyframe that fits,
    /// which the clip writes behind an `overflow` gap once the reader takes the
    /// backlog. Partial writes keep the bytes in order.
    #[tokio::test]
    async fn a_stalled_reader_costs_the_clip_an_overflow_gap_and_never_the_source() {
        let mut rig = Rig::new(None);
        let settings = ClipSettings {
            policy: ClipPolicy {
                queue_bytes: 4_096,
                ..ClipPolicy::default()
            },
            ..ClipSettings::default()
        };
        let mut reader = rig.start_with(
            spec(0, None, false),
            FakeClipMuxerFactory::default(),
            settings,
        );
        settle().await;
        let big = 16 * 1024;
        for index in 0..7_u32 {
            rig.video_frame(u64::from(index) * 100, index, index == 0, big);
            settle().await;
        }
        assert_eq!(rig.report().await, started(0, None));
        // The init line and five frames: the pipe's 64 KiB, the rest of
        // the fourth pending, and the fifth queued, which the reader's
        // taking lets through.
        let line = |index: u32| {
            format!(
                "frame v 0 {} {} {big}\n",
                index * 3_000,
                if index == 0 { 'k' } else { '-' }
            )
        };
        let through =
            "init video=h264\n".len() + (0..5).map(|index| line(index).len() + big).sum::<usize>();
        let mut bytes = reader.read(through).await;
        settle().await;
        rig.video_frame(700, 7, true, 32);
        assert_eq!(rig.report().await, gap("overflow", 400, 700));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        bytes.extend(reader.rest().await);
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264",
                "frame v 0 0 k 16384",
                "frame v 0 3000 - 16384",
                "frame v 0 6000 - 16384",
                "frame v 0 9000 - 16384",
                "frame v 0 12000 - 16384",
                "frame v 0 21000 k 32",
                "end",
            ]
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 700, 1)]);
    }

    /// A clip whose end no frame shows (the source went quiet) ends
    /// anyway, `END_GRACE` after its end; an open-ended one, or one asking
    /// past `clip_max_ms`, ends `max_duration` at the longest a clip runs.
    #[tokio::test]
    async fn a_clip_ends_after_its_end_without_frames_and_at_the_longest_without_one() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, Some(1_000), false));
        rig.video_frame(0, 0, true, 32);
        assert_eq!(rig.report().await, started(0, None));
        rig.advance_to(2_999);
        settle().await;
        assert!(rig.reports.try_recv().is_err(), "not before its late end");
        rig.advance_to(3_000);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(reports, vec![stopped("completed", bytes.len(), 0, 0)]);

        let settings = ClipSettings {
            max_duration: Duration::from_secs(2),
            ..ClipSettings::default()
        };
        for after in [None, Some(5_000)] {
            let mut rig = Rig::new(None);
            let reader = rig.start_with(
                spec(0, after, false),
                FakeClipMuxerFactory::default(),
                settings,
            );
            rig.video_frame(0, 0, true, 32);
            rig.video_frame(1_000, 1, false, 16);
            rig.video_frame(2_000, 2, false, 16);
            settle().await;
            // The clip task first runs at 2 s, the keyframe captured at 0: 2 s.
            assert_eq!(rig.report().await, started(2_000, None));
            let reports = rig.until_stopped().await;
            let bytes = reader.rest().await;
            assert_eq!(lines(&bytes).len(), 4, "the frame at 2 s is past the end");
            assert_eq!(
                reports,
                vec![stopped("max_duration", bytes.len(), 1_000, 0)]
            );
        }
    }

    /// A clip whose source declares no tracks, or sends no keyframe, within the
    /// start timeout ends `source_not_live` without a byte; nor does one start
    /// whose end comes first.
    #[tokio::test]
    async fn a_clip_without_tracks_or_a_keyframe_in_time_ends_source_not_live() {
        let (logs, _guard) = Logs::capture();
        for ready in [false, true] {
            let mut rig = Rig::with(Some(h264()), None, ready, 16);
            let reader = rig.start(spec(0, None, false));
            settle().await;
            rig.advance_to(9_999);
            settle().await;
            assert!(rig.reports.try_recv().is_err(), "not before the timeout");
            rig.advance_to(10_000);
            assert_eq!(
                rig.until_stopped().await,
                vec![stopped("source_not_live", 0, 0, 0)]
            );
            assert!(reader.rest().await.is_empty());
        }
        assert_eq!(
            logs.count(Level::INFO, "clip: the source did not go live in time"),
            1
        );
        assert_eq!(
            logs.count(Level::INFO, "clip: no keyframe to start at in time"),
            1
        );

        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, Some(500), false));
        rig.advance_to(2_500);
        assert_eq!(
            rig.until_stopped().await,
            vec![stopped("source_not_live", 0, 0, 0)]
        );
        assert!(reader.rest().await.is_empty());
    }

    /// A codec change after the container started (other parameter sets, the
    /// same family) ends the clip `stream_changed`, its last fragment written;
    /// one before it is what the start reads. A closed video track ends it
    /// `stream_deleted`.
    #[tokio::test]
    async fn a_codec_change_ends_the_clip_stream_changed_and_a_closed_track_stream_deleted() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, None, true));
        settle().await;
        let with_sets = Codec::H264 {
            profile_level_id: None,
            sps: Some(h264::test_data::sps(640, 480).into()),
            pps: Some(h264::test_data::pps().into()),
        };
        rig.video().set_codec(with_sets.clone());
        rig.audio_frame(0);
        rig.video_frame(10, 0, true, 32);
        rig.audio_frame(1);
        settle().await;
        // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
        assert_eq!(
            rig.report().await,
            ClipReport::Started {
                before_ms: 54,
                video: "h264".into(),
                picture: Some((640, 480)),
                audio: Some("aac_lc".into()),
            }
        );
        rig.video().set_codec(Codec::H264 {
            profile_level_id: None,
            sps: Some(h264::test_data::sps(1280, 720).into()),
            pps: Some(h264::test_data::pps().into()),
        });
        rig.audio_frame(2);
        rig.video_frame(200, 1, false, 16);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        // The audio frame at 64 ms waits for the video to pass it, which
        // the change ends before.
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264 audio=aac_lc",
                "frame a 0 0 k 4",
                "frame v 0 0 k 32",
                "end"
            ]
        );
        assert_eq!(reports, vec![stopped("stream_changed", bytes.len(), 10, 0)]);
        assert_eq!(
            logs.count(Level::INFO, "clip: the track changed; ending"),
            1
        );

        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        assert_eq!(rig.report().await, started(0, None));
        rig.video().close();
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(lines(&bytes).last().unwrap(), "end");
        assert_eq!(reports, vec![stopped("stream_deleted", bytes.len(), 0, 0)]);
    }

    /// An audio track that closes mid-clip ends the clip's audio, never
    /// the clip; an audio codec change ends it `stream_changed`.
    #[tokio::test]
    async fn the_audio_track_closing_ends_the_audio_and_its_codec_change_the_clip() {
        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, None, true));
        rig.audio_frame(0);
        rig.video_frame(10, 0, true, 32);
        rig.audio_frame(1);
        settle().await;
        // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
        assert_eq!(rig.report().await, started(54, Some("aac_lc")));
        rig.audio.as_ref().unwrap().close();
        settle().await;
        rig.video_frame(100, 1, false, 16);
        rig.video_frame(200, 2, false, 16);
        settle().await;
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        let lines = lines(&bytes);
        assert_eq!(
            lines,
            [
                "init video=h264 audio=aac_lc",
                "frame a 0 0 k 4",
                "frame v 0 0 k 32",
                "frame a 0 1024 k 4",
                "frame v 0 3000 - 16",
                "frame v 0 6000 - 16",
                "end",
            ]
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 200, 0)]);

        let mut rig = Rig::new(Some(fake_aac()));
        let _reader = rig.start(spec(0, None, true));
        rig.audio_frame(0);
        rig.video_frame(10, 0, true, 32);
        rig.audio_frame(1);
        settle().await;
        // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
        assert_eq!(rig.report().await, started(54, Some("aac_lc")));
        rig.audio
            .as_ref()
            .unwrap()
            .set_codec(Codec::Opus { channels: 2 });
        rig.video_frame(100, 1, false, 16);
        let reports = rig.until_stopped().await;
        let_assert_reason(&reports, "stream_changed");
    }

    fn let_assert_reason(reports: &[ClipReport], expected: &str) {
        let_assert!(Some(ClipReport::Stopped { reason, .. }) = reports.last());
        assert_eq!(reason, expected, "{reports:?}");
    }

    /// A reader that closed its end fails the next write with `EPIPE`, and the
    /// clip ends `client_gone` without its last fragment.
    #[tokio::test]
    async fn a_reader_that_closed_its_end_ends_the_clip_client_gone() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        assert_eq!(rig.report().await, started(0, None));
        drop(reader);
        rig.video_frame(100, 1, false, 16);
        let reports = rig.until_stopped().await;
        let_assert_reason(&reports, "client_gone");
        assert_eq!(logs.count(Level::INFO, "clip: the reader is gone"), 1);
    }

    /// The bytes the clip left out, as its warning logged them.
    fn left_out(logs: &Logs) -> usize {
        let lines = logs.lines(
            Level::WARN,
            "clip: the reader did not take the last bytes in time; closing without them",
        );
        let fields = &lines.last().unwrap().fields;
        fields
            .split(" pending=")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    /// Fills `rig`'s clip's pipe and leaves bytes pending: six 16 KiB
    /// frames, never read.
    async fn stall(rig: &Rig) {
        for index in 0..6_u32 {
            rig.video_frame(u64::from(index) * 100, index, index == 0, 16 * 1024);
            settle().await;
        }
    }

    /// A frame the interleaver holds for the other track while the pipe is
    /// full waits for the pipe, not for its hold: once the hold is over the
    /// clip sleeps until the pipe takes more instead of waking at once
    /// again and again, which would never let this test go on.
    #[tokio::test]
    async fn a_frame_held_while_the_pipe_is_full_waits_without_spinning() {
        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, None, true));
        let big = 24 * 1024;
        for (index, ms) in [10, 138, 266].into_iter().enumerate() {
            let index = u32::try_from(index).unwrap();
            rig.video_frame(ms, index, index == 0, big);
            settle().await;
            rig.audio_frame(2 * index + 1);
            settle().await;
        }
        // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
        assert_eq!(rig.report().await, started(54, Some("aac_lc")));
        // The audio frame at 320 ms is held for the video, past its hold.
        rig.clock.advance(Duration::from_secs(2));
        settle().await;
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        assert_eq!(lines(&bytes).last().unwrap(), "end");
        // The held audio frame at 320 ms is written with the stop.
        assert_eq!(
            lines(&bytes)[lines(&bytes).len() - 2],
            format!("frame a 0 {} k 4", 5 * 1_024)
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 310, 0)]);
    }

    /// An empty frame gives the container an empty slice, which the pipe
    /// would take nothing of: it is left out instead of read as a full
    /// pipe, which would wake the clip at once again and again.
    #[tokio::test]
    async fn an_empty_slice_from_the_container_is_no_full_pipe() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        rig.video_frame(100, 1, false, 0);
        settle().await;
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264",
                "frame v 0 0 k 32",
                "frame v 0 3000 - 0",
                "end"
            ]
        );
        assert_eq!(reports.len(), 2, "{reports:?}");
    }

    /// A reader that closes its end while the clip waits for the full pipe
    /// to take more wakes the clip, whose write fails with `EPIPE`:
    /// `client_gone`, nothing more written.
    #[tokio::test]
    async fn a_reader_gone_while_the_pipe_is_full_ends_the_clip_client_gone() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        stall(&rig).await;
        assert_eq!(rig.report().await, started(0, None));
        drop(reader);
        let reports = rig.until_stopped().await;
        let_assert_reason(&reports, "client_gone");
    }

    /// A stalled reader bounds a graceful end: the queue's drain waits
    /// `FINISH_GRACE` for the pipe, then the clip ends without what is
    /// left; the last fragment gets `FINISH_GRACE` too and goes without
    /// as well. The reader, which resumes after both, gets the file without
    /// its tail: the clip ends `client_gone`, and `bytes` counts the tail
    /// too, so the body is cut.
    #[tokio::test]
    async fn a_stalled_reader_bounds_the_drain_and_the_last_fragment_of_a_graceful_end() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        stall(&rig).await;
        assert_eq!(rig.report().await, started(0, None));
        rig.clips.stop("k1", EndReason::Stopped);
        settle().await;
        rig.clock.advance(FINISH_GRACE);
        settle().await;
        assert!(
            rig.reports.try_recv().is_err(),
            "the last fragment's grace runs"
        );
        rig.clock.advance(FINISH_GRACE);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert!(!bytes.ends_with(b"end\n"));
        // The frames the container took: the queued fifth goes when the
        // drain's grace runs out, the sixth with the overflow.
        let left = left_out(&logs);
        assert!(left > 0);
        assert_eq!(
            reports,
            vec![stopped("client_gone", bytes.len() + left, 300, 0)]
        );
        for line in [
            "clip: the reader did not take the queued frames in time; ending without them",
            "clip: the reader did not take the last bytes in time; closing without them",
        ] {
            assert_eq!(logs.count(Level::WARN, line), 1, "{line}");
        }
    }

    /// A reader that goes while a graceful end drains the queue into the
    /// full pipe ends the clip `client_gone`.
    #[tokio::test]
    async fn a_reader_gone_during_the_drain_ends_the_clip_client_gone() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        stall(&rig).await;
        assert_eq!(rig.report().await, started(0, None));
        rig.clips.stop("k1", EndReason::Stopped);
        settle().await;
        drop(reader);
        let_assert_reason(&rig.until_stopped().await, "client_gone");
    }

    /// A graceful end writes what the queue holds: `clip/stop` keeps the
    /// audio frame the interleaver held for the video (`max_skew`), and the
    /// drain stops at a held frame captured at or after the clip's end.
    #[tokio::test]
    async fn a_stop_writes_the_frames_held_for_the_other_track_up_to_the_end() {
        for after in [None, Some(100)] {
            let mut rig = Rig::new(Some(fake_aac()));
            let reader = rig.start(spec(0, after, true));
            rig.audio_frame(0);
            rig.video_frame(10, 0, true, 32);
            rig.audio_frame(1);
            settle().await;
            // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
            assert_eq!(rig.report().await, started(54, Some("aac_lc")));
            if after.is_some() {
                // Releases the audio frame; the video frame, past the end,
                // is held in its place.
                rig.video_frame(150, 1, false, 16);
                settle().await;
            }
            rig.clips.stop("k1", EndReason::Stopped);
            let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
            assert_eq!(
                lines(&bytes),
                [
                    "init video=h264 audio=aac_lc",
                    "frame a 0 0 k 4",
                    "frame v 0 0 k 32",
                    "frame a 0 1024 k 4",
                    "end",
                ]
            );
            assert_eq!(reports, vec![stopped("stopped", bytes.len(), 64, 0)]);
        }
    }

    /// A container that refuses the start ends the clip `internal_error`
    /// before it started; one that fails a push ends it after `started`,
    /// the last fragment still asked for; one whose finish fails says so
    /// and ends a graceful clip `internal_error`, its file without the
    /// last fragment, while any other end keeps its reason.
    #[tokio::test]
    async fn a_container_failure_ends_the_clip_internal_error_and_a_failed_finish_is_logged() {
        let (logs, _guard) = Logs::capture();
        for (fail, reports) in [(FakeClipFailure::Start, 1), (FakeClipFailure::Push, 2)] {
            let mut rig = Rig::new(None);
            let reader = rig.start_with(
                spec(0, None, false),
                FakeClipMuxerFactory { fail: Some(fail) },
                ClipSettings::default(),
            );
            rig.video_frame(0, 0, true, 32);
            let seen = rig.until_stopped().await;
            assert_eq!(seen.len(), reports, "{seen:?}");
            let_assert_reason(&seen, "internal_error");
            let bytes = reader.rest().await;
            assert_eq!(lines(&bytes).last().map_or("end", String::as_str), "end");
        }
        assert_eq!(logs.count(Level::WARN, "clip: the container failed"), 2);

        for (asked, ends) in [
            (EndReason::Stopped, "internal_error"),
            (EndReason::ShuttingDown, "shutting_down"),
        ] {
            let mut rig = Rig::new(None);
            let reader = rig.start_with(
                spec(0, None, false),
                FakeClipMuxerFactory {
                    fail: Some(FakeClipFailure::Finish),
                },
                ClipSettings::default(),
            );
            rig.video_frame(0, 0, true, 32);
            assert_eq!(rig.report().await, started(0, None));
            rig.clips.stop("k1", asked);
            let_assert_reason(&rig.until_stopped().await, ends);
            assert_eq!(
                lines(&reader.rest().await),
                ["init video=h264", "frame v 0 0 k 32"]
            );
        }
        assert_eq!(
            logs.count(Level::WARN, "clip: the container's last fragment failed"),
            2
        );
    }

    /// The worker's shutdown ends every clip `shutting_down` with its last
    /// fragment; a clip that cannot finish within the grace (here, its
    /// report has nowhere to go) is aborted, its pipe closed.
    #[tokio::test]
    async fn a_shutdown_ends_the_clips_with_their_last_fragment_or_aborts_them() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        assert_eq!(rig.report().await, started(0, None));
        let clock: Arc<dyn Clock> = rig.clock.clone();
        within(rig.clips.shutdown(&clock, rig.at(60_000))).await;
        assert_eq!(rig.clips.len(), 0);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(lines(&bytes).last().unwrap(), "end");
        assert_eq!(reports, vec![stopped("shutting_down", bytes.len(), 0, 0)]);

        let mut rig = Rig::with(Some(h264()), None, true, 1);
        let reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        settle().await;
        let fake = Arc::clone(&rig.clock);
        let clock: Arc<dyn Clock> = rig.clock.clone();
        within(async {
            tokio::join!(rig.clips.shutdown(&clock, rig.at(60_000)), async {
                settle().await;
                fake.advance(SHUTDOWN_GRACE);
            })
        })
        .await;
        assert_eq!(rig.report().await, started(0, None));
        assert_eq!(lines(&reader.rest().await).last().unwrap(), "end");
        let aborted = logs.lines(Level::WARN, "clip still finishing at shutdown; aborted");
        assert_eq!(aborted.len(), 1);
        assert!(aborted[0].fields.contains("grace_ms=1500"), "{aborted:?}");
    }

    /// The worker's own shutdown deadline cuts the clips' grace short: a
    /// clip that cannot finish is aborted by then, so the worker's later
    /// teardown keeps what is left of the deadline. Regression: the clips
    /// had their whole grace whatever the deadline, and the source its
    /// whole deadline after it.
    #[tokio::test]
    async fn a_shutdown_deadline_before_the_grace_aborts_the_clips_by_it() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::with(Some(h264()), None, true, 1);
        let reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        settle().await;
        let fake = Arc::clone(&rig.clock);
        let clock: Arc<dyn Clock> = rig.clock.clone();
        within(async {
            tokio::join!(rig.clips.shutdown(&clock, rig.at(500)), async {
                settle().await;
                fake.advance(Duration::from_millis(500));
            })
        })
        .await;
        assert_eq!(rig.report().await, started(0, None));
        assert_eq!(lines(&reader.rest().await).last().unwrap(), "end");
        let aborted = logs.lines(Level::WARN, "clip still finishing at shutdown; aborted");
        assert_eq!(aborted.len(), 1);
        assert!(aborted[0].fields.contains("grace_ms=500"), "{aborted:?}");
    }

    /// A clip on tracks without video ends `no_video_track`; one asked to
    /// stop while it waits for the tracks ends with that reason, the
    /// first reason given standing; one whose handle the worker dropped
    /// ends `shutting_down`.
    #[tokio::test]
    async fn a_clip_without_video_or_stopped_or_dropped_while_waiting_ends_at_once() {
        let mut rig = Rig::with(None, Some(fake_aac()), true, 16);
        let _reader = rig.start(spec(0, None, true));
        assert_eq!(
            rig.until_stopped().await,
            vec![stopped("no_video_track", 0, 0, 0)]
        );

        let mut rig = Rig::with(Some(h264()), None, false, 16);
        let _reader = rig.start(spec(0, None, true));
        assert!(rig.clips.stop("k1", EndReason::Stopped));
        rig.clips.stop_all(EndReason::ShuttingDown);
        assert!(!rig.clips.stop("k2", EndReason::Stopped), "no such clip");
        assert_eq!(rig.until_stopped().await, vec![stopped("stopped", 0, 0, 0)]);
        assert!(rig.clips.runs("k1"));
        rig.clips.ended("k1");
        assert!(!rig.clips.runs("k1"));

        let mut rig = Rig::with(Some(h264()), None, false, 16);
        let _reader = rig.start(spec(0, None, true));
        settle().await;
        rig.clips.running.clear();
        assert_eq!(
            rig.until_stopped().await,
            vec![stopped("shutting_down", 0, 0, 0)]
        );
    }

    /// A clip reports its first `MAX_GAP_REPORTS` gaps one by one and
    /// counts every gap in its `Stopped`, saying once that it capped them.
    #[tokio::test]
    async fn gap_reports_are_capped_and_every_gap_counted() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::new(None);
        let _reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        rig.video_frame(100, 1, false, 1);
        let mut ms = 100;
        for index in 2..262_u32 {
            // Each three frame intervals after the one before.
            ms += 300;
            rig.video_frame(ms, 3 * index - 2, false, 1);
            settle().await;
        }
        // The frame after the last jump, one interval on, makes it a hole.
        rig.video_frame(ms + 100, 3 * 262 - 4, false, 1);
        settle().await;
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let gaps = reports
            .iter()
            .filter(|report| matches!(report, ClipReport::Gap { .. }))
            .count();
        assert_eq!(gaps, MAX_GAP_REPORTS as usize);
        let_assert!(Some(ClipReport::Stopped { gaps, .. }) = reports.last());
        assert_eq!(*gaps, 260);
        assert_eq!(
            logs.count(
                Level::WARN,
                "clip: gap reports capped; the rest are counted in its stop"
            ),
            1
        );
    }

    /// ISO/IEC 14496-15 §5.3.3.1: the sample entry carries the track's
    /// newest parameter sets, so a clip prefers a later held keyframe
    /// whose in-band sets are those to the one its window names, when that
    /// one carries others; with none such, it keeps the one named.
    #[tokio::test]
    async fn iso14496_15_5_3_3_1_a_clip_starts_at_a_keyframe_carrying_the_entry_s_sets() {
        let (logs, _guard) = Logs::capture();
        let old = h264::test_data::sps(640, 480);
        let new = h264::test_data::sps(1280, 720);
        let codec = h264_with(&new);
        for (second, before_ms) in [(idr_with(&new), 1_000), (idr_with(&old), 2_000)] {
            let mut rig = Rig::with(Some(codec.clone()), None, true, 16);
            for (ms, payload) in [(0, idr_with(&old)), (1_000, second)] {
                rig.advance_to(ms);
                assert!(rig.video().publish_frame(MediaFrame {
                    ts: MediaTime::from_ticks(i64::try_from(ms).unwrap() * 90),
                    wallclock: rig.at(ms),
                    arrival: rig.at(ms),
                    keyframe: true,
                    discontinuity: false,
                    epoch: 0,
                    payload: payload.into(),
                }));
            }
            rig.advance_to(2_000);
            let _reader = rig.start(spec(5_000, None, false));
            settle().await;
            let_assert_started(&rig.report().await, before_ms);
            rig.clips.stop("k1", EndReason::Stopped);
            rig.until_stopped().await;
        }
        let other = logs.lines(
            Level::DEBUG,
            "clip: the start keyframe carries other parameter sets than the track's",
        );
        assert_eq!(other.len(), 2, "{other:?}");
        assert!(other[0].fields.contains("later=true"), "{other:?}");
        assert!(other[1].fields.contains("later=false"), "{other:?}");
    }

    /// The compatible keyframe a clip prefers is the one it starts at,
    /// whatever capture times the ring's later keyframes carry: before a
    /// camera's Sender Report corrects the mapping (RFC 3550 §6.4.1) a
    /// frame can be dated ahead of a later one. Regression: the clip took
    /// the ring again from the chosen keyframe's capture time, so a
    /// keyframe arriving at 1 s dated 61 s, followed by one arriving at
    /// 2 s dated 9 s, started the clip at the latter and dropped a second
    /// of pre-roll.
    #[tokio::test]
    async fn rfc3550_6_4_1_a_clip_keeps_its_compatible_keyframe_when_capture_times_move_back() {
        let (logs, _guard) = Logs::capture();
        let old = h264::test_data::sps(640, 480);
        let new = h264::test_data::sps(1280, 720);
        let codec = h264_with(&new);
        let mut rig = Rig::with(Some(codec), None, true, 16);
        // (captured, arrived) in ms after the start: the second keyframe is
        // dated a minute ahead, the third back behind it.
        for ((ms, arrival_ms), sps) in [
            ((0, 0), &old),
            ((61_000, 1_000), &new),
            ((9_000, 2_000), &new),
        ] {
            rig.advance_to(arrival_ms);
            assert!(rig.video().publish_frame(MediaFrame {
                ts: MediaTime::from_ticks(i64::try_from(arrival_ms).unwrap() * 90),
                wallclock: rig.at(ms),
                arrival: rig.at(arrival_ms),
                keyframe: true,
                discontinuity: false,
                epoch: 0,
                payload: idr_with(sps).into(),
            }));
        }
        rig.advance_to(3_000);
        let _reader = rig.start(spec(5_000, None, false));
        settle().await;
        // From the keyframe that arrived at 1 s, by its arrival: the
        // capture time ahead of it does not count (`captured`).
        let_assert_started(&rig.report().await, 2_000);
        rig.clips.stop("k1", EndReason::Stopped);
        rig.until_stopped().await;
        let other = logs.lines(
            Level::DEBUG,
            "clip: the start keyframe carries other parameter sets than the track's",
        );
        assert_eq!(other.len(), 1, "{other:?}");
        assert!(other[0].fields.contains("later=true"), "{other:?}");
    }

    /// H.264 whose in-band sets are `sps` and the test PPS.
    fn h264_with(sps: &[u8]) -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: Some(sps.to_vec().into()),
            pps: Some(h264::test_data::pps().into()),
        }
    }

    /// An IDR access unit (Annex B) carrying `sps` and the test PPS.
    fn idr_with(sps: &[u8]) -> Vec<u8> {
        let mut unit = Vec::new();
        for nal in [sps, &h264::test_data::pps()[..], &[0x65, 0x88][..]] {
            unit.extend_from_slice(&[0, 0, 0, 1]);
            unit.extend_from_slice(nal);
        }
        unit
    }

    fn let_assert_started(report: &ClipReport, expected: u32) {
        let_assert!(ClipReport::Started { before_ms, .. } = report);
        assert_eq!(*before_ms, expected);
    }

    /// ISO/IEC 14496-10 Table 7-1 and ITU-T H.265 Table 7-1: in-band
    /// SPS, PPS (and VPS) are told apart by NAL unit type and compared
    /// with the codec's; other units, a unit without sets, and a codec
    /// without sets always qualify.
    #[test]
    fn iso14496_10_table_7_1_and_h265_table_7_1_in_band_sets_are_compared_by_type() {
        let annex_b = |units: &[&[u8]]| {
            let mut out = Vec::new();
            for unit in units {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(unit);
            }
            out
        };
        let sps: &[u8] = &[0x67, 1, 2];
        let pps: &[u8] = &[0x68, 3];
        let h264_codec = Codec::H264 {
            profile_level_id: None,
            sps: Some(Bytes::from_static(&[0x67, 1, 2])),
            pps: Some(Bytes::from_static(&[0x68, 3])),
        };
        assert!(sets_match(&h264_codec, &annex_b(&[sps, pps, &[0x65, 0]])));
        assert!(!sets_match(
            &h264_codec,
            &annex_b(&[&[0x67, 9], pps, &[0x65, 0]])
        ));
        assert!(!sets_match(&h264_codec, &annex_b(&[sps, &[0x68, 9]])));
        assert!(sets_match(&h264_codec, &annex_b(&[&[0x65, 0]])));
        assert!(!sets_match(&h264(), &annex_b(&[sps])), "no SPS held");

        let (vps, sps, pps): (&[u8], &[u8], &[u8]) = (&[0x40, 1, 1], &[0x42, 1, 2], &[0x44, 1, 3]);
        let h265_codec = Codec::H265 {
            vps: Some(Bytes::copy_from_slice(vps)),
            sps: Some(Bytes::copy_from_slice(sps)),
            pps: Some(Bytes::copy_from_slice(pps)),
        };
        assert!(sets_match(
            &h265_codec,
            &annex_b(&[vps, sps, pps, &[0x26, 1, 0]])
        ));
        assert!(!sets_match(&h265_codec, &annex_b(&[&[0x40, 1, 9]])));
        assert!(!sets_match(&h265_codec, &annex_b(&[&[0x42, 1, 9]])));
        assert!(!sets_match(&h265_codec, &annex_b(&[&[0x44, 1, 9]])));
        assert!(sets_match(&Codec::Mjpeg, &annex_b(&[sps])));
    }

    /// The names a clip's end and gaps carry, the API's.
    #[test]
    fn ends_and_gaps_carry_the_api_s_names() {
        assert_eq!(
            [
                EndReason::Completed,
                EndReason::Stopped,
                EndReason::MaxDuration,
                EndReason::StreamDeleted,
                EndReason::StreamChanged,
                EndReason::NoVideoTrack,
                EndReason::SourceNotLive,
                EndReason::ClientGone,
                EndReason::ShuttingDown,
                EndReason::InternalError,
            ]
            .map(EndReason::name),
            [
                "completed",
                "stopped",
                "max_duration",
                "stream_deleted",
                "stream_changed",
                "no_video_track",
                "source_not_live",
                "client_gone",
                "shutting_down",
                "internal_error",
            ]
        );
        assert_eq!(
            [
                GapReason::Overflow,
                GapReason::Lagged,
                GapReason::PrerollTruncated
            ]
            .map(gap_name),
            ["overflow", "lagged", "overflow"]
        );
        assert_eq!(
            ClipSettings::default(),
            ClipSettings {
                policy: ClipPolicy::default(),
                max_duration: Duration::from_secs(600),
                start_timeout: Duration::from_secs(10),
                max_clips: 8,
            }
        );
    }

    /// A clock that publishes `frames` at its `at`-th reading: a source on
    /// another worker thread publishing between two steps of a clip's
    /// start, which a test on one thread interleaves no other way.
    #[derive(Debug)]
    struct Interposing {
        inner: Arc<FakeClock>,
        readings: std::sync::atomic::AtomicUsize,
        at: usize,
        frames: std::sync::Mutex<Vec<(Arc<Track>, MediaFrame)>>,
    }

    impl Clock for Interposing {
        fn now(&self) -> Instant {
            let reading = self
                .readings
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if reading + 1 == self.at {
                for (track, frame) in self.frames.lock().unwrap().drain(..) {
                    assert!(track.publish_frame(frame));
                }
            }
            self.inner.now()
        }

        fn wall_now(&self) -> std::time::SystemTime {
            self.inner.wall_now()
        }

        fn sleep(&self, duration: Duration) -> lotse_core::task::BoxFuture<'static, ()> {
            self.inner.sleep(duration)
        }
    }

    /// A frame of `rig`'s of `len` bytes, `ts` in the track's ticks,
    /// captured at `ms` and arriving at `arrival_ms` after the start.
    fn frame_at(
        rig: &Rig,
        (ms, arrival_ms): (u64, u64),
        ts: i64,
        keyframe: bool,
        len: usize,
    ) -> MediaFrame {
        MediaFrame {
            ts: MediaTime::from_ticks(ts),
            wallclock: rig.at(ms),
            arrival: rig.at(arrival_ms),
            keyframe,
            discontinuity: false,
            epoch: 0,
            payload: vec![if keyframe { 0x65 } else { 0x41 }; len].into(),
        }
    }

    /// A frame on `track` over `max_frame_bytes`, captured at `ms`: the
    /// track drops it, and its subscribers lag one.
    fn oversize(rig: &Rig, track: &Track, ms: u64) {
        rig.advance_to(ms);
        let len = TrackLimits::default().max_frame_bytes + 1;
        assert!(!track.publish_frame(frame_at(rig, (ms, ms), 0, false, len)));
    }

    /// Frames a source publishes while a clip starts (between its reading
    /// of the clock and its next) come after the pre-roll, each once and in
    /// order, on either track: the clip takes each track's subscription and
    /// snapshot together, so the snapshot never starts after a frame its
    /// subscription yields. Regression: subscribed first and snapshotted
    /// after, the snapshot started at the keyframe published in between,
    /// and the P-frame before it, and the keyframe again, were written after
    /// it; the audio the same way.
    #[tokio::test]
    async fn frames_published_while_a_clip_starts_follow_its_pre_roll_once_and_in_order() {
        let mut rig = Rig::new(Some(fake_aac()));
        rig.video_frame(0, 0, true, 32);
        rig.audio_frame(0);
        rig.audio_frame(1);
        rig.video_frame(100, 1, false, 16);
        rig.audio_frame(2);
        rig.advance_to(200);
        let audio = Arc::clone(rig.audio.as_ref().unwrap());
        let frames = vec![
            (
                Arc::clone(rig.video()),
                frame_at(&rig, (150, 200), 6_000, false, 16),
            ),
            (
                Arc::clone(&audio),
                frame_at(&rig, (172, 200), 3 * 1_024, true, 4),
            ),
            (
                Arc::clone(&audio),
                frame_at(&rig, (178, 200), 4 * 1_024, true, 4),
            ),
            (
                Arc::clone(rig.video()),
                frame_at(&rig, (180, 200), 9_000, true, 32),
            ),
        ];
        let clock = Arc::new(Interposing {
            inner: Arc::clone(&rig.clock),
            readings: std::sync::atomic::AtomicUsize::new(0),
            // The first reading is the clip's start, the second inside it.
            at: 2,
            frames: std::sync::Mutex::new(frames),
        });
        assert_eq!(clock.wall_now(), rig.clock.wall_now());
        let reader = rig.start_on(
            spec(0, None, true),
            FakeClipMuxerFactory::default(),
            ClipSettings::default(),
            clock,
        );
        settle().await;
        assert_eq!(rig.report().await, started(200, Some("aac_lc")));
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        let lines = lines(&bytes);
        let video: Vec<&str> = lines
            .iter()
            .filter(|line| line.starts_with("frame v"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            video,
            [
                "frame v 0 0 k 32",
                "frame v 0 3000 - 16",
                "frame v 0 6000 - 16",
                "frame v 0 9000 k 32",
            ]
        );
        let audio: Vec<String> = lines
            .iter()
            .filter(|line| line.starts_with("frame a"))
            .cloned()
            .collect();
        let expected: Vec<String> = (0..5)
            .map(|index| format!("frame a 0 {} k 4", index * 1_024))
            .collect();
        assert_eq!(audio, expected);
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 180, 0)]);
    }

    /// A pre-roll's transcode burst lets the worker's other tasks run after
    /// every step of `MAX_STEP_PACKETS` packets even while frames keep
    /// coming, so a ready subscription never skips the yield. Regression:
    /// the yield was a branch of the biased select after the subscriptions',
    /// and with a frame ready at each select the whole burst ran in one poll.
    #[tokio::test]
    async fn a_transcode_burst_lets_other_tasks_run_after_each_step_while_frames_keep_coming() {
        let mut rig = Rig::new(Some(Codec::Pcmu));
        ten_narrowband_seconds(&rig, &Codec::Pcmu);
        rig.advance_to(11_000);
        let count = Counting::default();
        let audio = Arc::clone(&count.0);
        let reader = rig.start_with(spec(4_500, None, true), count, ClipSettings::default());
        // The burst starts once the pipe is known to take the container's
        // header: until then every step ends at it, with nothing transcoded.
        let mut bytes = Vec::new();
        let mut ticks = Vec::new();
        while ticks.iter().sum::<usize>() == 0 {
            assert!(ticks.len() < 16, "no burst: {ticks:?}");
            per_tick(&audio, &reader, 1, &mut ticks, &mut bytes).await;
        }
        // Frames of the live audio, fewer than a subscription holds so none
        // lags: ready events at every select of the burst's steps.
        let payload = narrowband_payload(&Codec::Pcmu);
        for index in 496..544 {
            rig.narrowband_frame(index, &payload);
        }
        per_tick(&audio, &reader, 128, &mut ticks, &mut bytes).await;
        assert!(ticks.iter().all(|n| *n <= MAX_STEP_PACKETS), "{ticks:?}");
        assert!(
            ticks.iter().sum::<usize>() >= 4 * MAX_STEP_PACKETS,
            "{ticks:?}"
        );
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, rest) = tokio::join!(rig.until_stopped(), reader.rest());
        bytes.extend(rest);
        let_assert_reason(&reports, "stopped");
        assert_eq!(
            audio_samples(&lines(&bytes)).len(),
            audio.load(std::sync::atomic::Ordering::SeqCst),
            "the file is whole"
        );
    }

    /// A stop during a pre-roll's transcode burst drains the rest in steps
    /// of `MAX_STEP_PACKETS` packets, letting the worker's other tasks run
    /// between them as the clip's steps do. The timeline's first frame,
    /// which completes none, counts one. Regression: the drain
    /// transcoded all of it in one go while the pipe took the bytes.
    #[tokio::test]
    async fn a_stop_during_a_transcode_burst_drains_it_in_steps_that_let_other_tasks_run() {
        let mut rig = Rig::new(Some(Codec::Pcmu));
        ten_narrowband_seconds(&rig, &Codec::Pcmu);
        let count = Counting::default();
        let audio = Arc::clone(&count.0);
        let reader = rig.start_with(spec(3_500, None, true), count, ClipSettings::default());
        // Before the clip's first poll: it opens, takes its first step and
        // yields, then ends at the stop and drains what is left.
        assert!(rig.clips.stop("k1", EndReason::Stopped));
        let mut bytes = Vec::new();
        let mut ticks = Vec::new();
        per_tick(&audio, &reader, 64, &mut ticks, &mut bytes).await;
        let busy: Vec<usize> = ticks.into_iter().filter(|n| *n > 0).collect();
        let (last, full) = busy.split_last().unwrap();
        assert!(busy.len() >= 4, "{busy:?}");
        // The timeline's first frame completes no packet but counts one.
        let (first, full) = full.split_first().unwrap();
        assert_eq!(*first, MAX_STEP_PACKETS - 1, "{busy:?}");
        assert!(full.iter().all(|n| *n == MAX_STEP_PACKETS), "{busy:?}");
        assert!(*last <= MAX_STEP_PACKETS, "{busy:?}");
        let (reports, rest) = tokio::join!(rig.until_stopped(), reader.rest());
        bytes.extend(rest);
        let_assert_reason(&reports, "stopped");
        assert_eq!(
            audio_samples(&lines(&bytes)).len(),
            busy.iter().sum::<usize>(),
            "the file is whole"
        );
    }

    /// A transcode that re-anchors on every frame, completing no packet,
    /// still lets the worker's other tasks run after every
    /// `MAX_STEP_PACKETS` frames it takes, in the clip's steps and in its
    /// drain: PCMU frames all stamped 0, as a camera repeating its
    /// timestamps sends, each step back off the sample count. The 4 s
    /// pre-roll goes out in steps of 25 audio frames, half a second, so at
    /// most 6 of the 10 fps video frames between two yields. Regression:
    /// only packets counted, and the whole pre-roll went through the
    /// transcode in one step.
    #[tokio::test]
    async fn a_transcode_that_re_anchors_on_every_frame_still_yields_after_each_step() {
        for stop in [false, true] {
            let mut rig = Rig::new(Some(Codec::Pcmu));
            ten_narrowband_seconds_stamped(&rig, &Codec::Pcmu, |_| 0);
            let count = Counting::default();
            let (audio, video) = (Arc::clone(&count.0), Arc::clone(&count.1));
            let reader = rig.start_with(spec(3_500, None, true), count, ClipSettings::default());
            if stop {
                // Before the clip's first poll: the pre-roll goes out in the drain.
                assert!(rig.clips.stop("k1", EndReason::Stopped));
            }
            let mut bytes = Vec::new();
            let mut ticks = Vec::new();
            per_tick(&video, &reader, 64, &mut ticks, &mut bytes).await;
            let busy: Vec<usize> = ticks.into_iter().filter(|n| *n > 0).collect();
            assert!(busy.len() >= 6, "stop {stop}: {busy:?}");
            assert!(busy.iter().all(|n| *n <= 6), "stop {stop}: {busy:?}");
            if !stop {
                assert!(rig.clips.stop("k1", EndReason::Stopped));
            }
            let (reports, _) = tokio::join!(rig.until_stopped(), reader.rest());
            let_assert_reason(&reports, "stopped");
            assert_eq!(
                audio.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "stop {stop}: no packet"
            );
        }
    }

    /// The audio starts with the frame playing when the video's start
    /// keyframe was captured by the pre-roll's measure, its arrival when it
    /// is dated ahead of it (a Sender Report mapping off), as `before_ms`
    /// counts it: a keyframe arriving at 500 ms dated 900 ms starts the
    /// audio at 448 ms, and goes out after it by the same measure.
    /// Regression: the audio started at 896 ms, 400 ms
    /// short of what `before_ms` said the clip holds.
    #[tokio::test]
    async fn a_keyframe_dated_ahead_of_its_arrival_starts_the_audio_at_its_arrival() {
        let mut rig = Rig::new(Some(fake_aac()));
        for index in 0..8 {
            rig.audio_frame(index);
        }
        rig.advance_to(500);
        assert!(
            rig.video()
                .publish_frame(frame_at(&rig, (900, 500), 0, true, 32))
        );
        for index in 8..16 {
            rig.audio_frame(index);
        }
        rig.advance_to(1_000);
        let reader = rig.start(spec(0, None, true));
        settle().await;
        assert_eq!(rig.report().await, started(500, Some("aac_lc")));
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        let lines = lines(&bytes);
        assert_eq!(lines[1], format!("frame a 0 {} k 4", 7 * 1_024), "448 ms");
        assert_eq!(
            lines[2], "frame v 0 0 k 32",
            "by its arrival too: after the audio before 500 ms"
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 512, 0)]);
    }

    /// A clip starts at the newest keyframe captured at or before
    /// `now − before_ms` by the pre-roll's measure, its arrival when it is
    /// dated ahead of it (a Sender Report mapping off, RFC 3550 §6.4.1), as
    /// `before_ms` counts it: of keyframes arriving at 1 s and 2 s dated
    /// 61 s and 62 s, a clip asked at 3 s with `before_ms = 0` starts at
    /// the second, 1 s old. Regression: the ring compared their dates,
    /// found none at or before 3 s and started at the first, 2 s old.
    #[tokio::test]
    async fn rfc3550_6_4_1_a_clip_starts_at_the_newest_keyframe_by_when_it_was_captured() {
        let mut rig = Rig::new(None);
        for (index, arrival) in [(0, 1_000), (1, 2_000)] {
            rig.advance_to(arrival);
            assert!(rig.video().publish_frame(frame_at(
                &rig,
                (arrival + 60_000, arrival),
                index * 90_000,
                true,
                32
            )));
        }
        rig.advance_to(3_000);
        let reader = rig.start(spec(0, None, false));
        settle().await;
        assert_eq!(rig.report().await, started(1_000, None));
        rig.clips.stop("k1", EndReason::Stopped);
        let (_, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        let video: Vec<String> = lines(&bytes)
            .into_iter()
            .filter(|line| line.starts_with("frame v"))
            .collect();
        assert_eq!(video, ["frame v 0 90000 k 32"], "the second keyframe only");
    }

    /// A hole the queue reports (the subscription lagged: the track dropped
    /// a frame over `max_frame_bytes`) is where the container put the frames
    /// on either side of it, as a reconnect's is: the keyframe that ends it,
    /// captured 60 ms after the frame before it, goes where that one ends,
    /// at 200 ms. Regression: the gap was the capture times', 100 to 160 ms,
    /// in a file that had it from 100 to 200 ms.
    #[tokio::test]
    async fn a_lag_s_gap_is_where_the_container_put_its_frames() {
        let mut rig = Rig::new(None);
        let reader = rig.start_with(spec(0, None, false), Moving, ClipSettings::default());
        rig.video_frame(0, 0, true, 32);
        rig.video_frame(100, 1, false, 16);
        settle().await;
        oversize(&rig, rig.video(), 130);
        rig.video_frame(160, 3, true, 32);
        settle().await;
        // The clip task first runs at 100 ms, the keyframe captured at 0: 100 ms.
        assert_eq!(rig.report().await, started(100, None));
        assert_eq!(rig.report().await, gap("lagged", 100, 200));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 200, 1)]);
    }

    /// A lag leaves the frame interval before it behind, across a reconnect
    /// to a slower frame rate or within the epoch (a camera lowering its
    /// rate, as many do in the dark): the frames after it teach their own,
    /// so frames 300 ms apart after 100 ms ones are no `frames_dropped`
    /// gap. Regression: the keyframe after the lag passed the epoch's
    /// change unseen (the hole had cleared the newest timestamp, not the
    /// interval), the old 100 ms interval stayed, and every later frame
    /// was a gap.
    #[tokio::test]
    async fn a_lag_resumes_at_the_frame_interval_after_it_across_a_reconnect_or_not() {
        for reconnect in [true, false] {
            let mut rig = Rig::new(None);
            let reader = rig.start(spec(0, None, false));
            rig.video_frame(0, 0, true, 32);
            rig.video_frame(100, 1, false, 16);
            settle().await;
            oversize(&rig, rig.video(), 150);
            settle().await;
            if reconnect {
                rig.publisher.discontinuity();
            }
            for (ms, index, keyframe) in [(1_000, 10, true), (1_300, 13, false), (1_600, 16, false)]
            {
                rig.video_frame(ms, index, keyframe, if keyframe { 32 } else { 16 });
                settle().await;
            }
            // The clip task first runs at 100 ms, the keyframe captured at 0: 100 ms.
            assert_eq!(rig.report().await, started(100, None));
            assert_eq!(rig.report().await, gap("lagged", 100, 1_000));
            rig.clips.stop("k1", EndReason::Stopped);
            let reports = rig.until_stopped().await;
            let bytes = reader.rest().await;
            assert_eq!(
                reports,
                vec![stopped("stopped", bytes.len(), 1_600, 1)],
                "reconnect: {reconnect}"
            );
        }
    }

    /// A container that fails the push of the frame whose timestamp is
    /// the one it holds; the fake one otherwise.
    #[derive(Debug)]
    struct FailingAt(i64);

    /// [`FailingAt`]'s muxer.
    struct FailingMuxer {
        inner: Box<dyn ClipMuxer>,
        at: i64,
    }

    impl ClipMuxerFactory for FailingAt {
        fn accepts(&self, codec: &Codec) -> bool {
            FakeClipMuxerFactory::default().accepts(codec)
        }

        fn muxer(&self, policy: &ClipPolicy) -> Box<dyn ClipMuxer> {
            Box::new(FailingMuxer {
                inner: FakeClipMuxerFactory::default().muxer(policy),
                at: self.0,
            })
        }
    }

    impl ClipMuxer for FailingMuxer {
        fn start(
            &mut self,
            video: &ClipTrack,
            audio: Option<&ClipTrack>,
        ) -> Result<Vec<Bytes>, ClipError> {
            self.inner.start(video, audio)
        }

        fn set_origin(&mut self, origin: Instant) {
            self.inner.set_origin(origin);
        }

        fn push(&mut self, track: Kind, frame: Arc<MediaFrame>) -> Result<Vec<Bytes>, ClipError> {
            if frame.ts.ticks() == self.at {
                return Err(ClipError::Failed("the frame it fails".into()));
            }
            self.inner.push(track, frame)
        }

        fn media_time(&self, track: Kind) -> Duration {
            self.inner.media_time(track)
        }

        fn finish(&mut self) -> Result<Vec<Bytes>, ClipError> {
            self.inner.finish()
        }
    }

    /// A graceful end's drain that meets a codec change queued behind the
    /// full pipe ends the clip `stream_changed`, and one whose container
    /// fails a held frame ends it `internal_error`, not `stopped` as asked:
    /// only the clip's own end reached keeps the reason it ends for
    /// (`a_stop_writes_the_frames_held_for_the_other_track_up_to_the_end`).
    /// Regression: the drain dropped what ended it and reported `stopped`.
    #[tokio::test]
    async fn a_codec_change_or_a_container_failure_the_drain_meets_ends_the_clip_for_it() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        stall(&rig).await;
        assert_eq!(rig.report().await, started(0, None));
        rig.video().set_codec(Codec::H264 {
            profile_level_id: None,
            sps: Some(h264::test_data::sps(640, 480).into()),
            pps: Some(h264::test_data::pps().into()),
        });
        settle().await;
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        assert_eq!(lines(&bytes).last().unwrap(), "end");
        assert_eq!(
            reports,
            vec![stopped("stream_changed", bytes.len(), 500, 0)]
        );

        assert!(FailingAt(15_000).accepts(&h264()), "what the fake takes");
        let mut rig = Rig::new(None);
        let reader = rig.start_with(
            spec(0, None, false),
            FailingAt(15_000),
            ClipSettings::default(),
        );
        stall(&rig).await;
        assert_eq!(rig.report().await, started(0, None));
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        assert_eq!(lines(&bytes).last().unwrap(), "end");
        assert_eq!(
            reports,
            vec![stopped("internal_error", bytes.len(), 400, 0)]
        );
    }

    /// A reader that closes its end while the last fragment waits for the
    /// full pipe ends a graceful clip `client_gone`: the file it took is
    /// not whole. Any other end keeps its reason. Regression: the failed
    /// write was dropped and the clip reported `stopped`.
    #[tokio::test]
    async fn a_reader_gone_during_the_last_fragment_ends_a_graceful_clip_client_gone() {
        for (asked, reason) in [
            (EndReason::Stopped, "client_gone"),
            (EndReason::ShuttingDown, "shutting_down"),
        ] {
            let mut rig = Rig::new(None);
            let reader = rig.start(spec(0, None, false));
            stall(&rig).await;
            assert_eq!(rig.report().await, started(0, None));
            rig.clips.stop("k1", asked);
            settle().await;
            if asked.is_graceful() {
                // The drain gives up on the queue; the last fragment waits.
                rig.clock.advance(FINISH_GRACE);
                settle().await;
            }
            assert!(rig.reports.try_recv().is_err(), "the last fragment waits");
            drop(reader);
            let_assert_reason(&rig.until_stopped().await, reason);
        }
    }

    /// A reader that stalls past the last fragment's `FINISH_GRACE` and then
    /// resumes reads the file without its tail, and `Stopped` counts the
    /// file's length, tail included, so the body (which ends whole only on
    /// an equal count, RFC 9112 section 7.1) is cut (section 8). A graceful
    /// end becomes `client_gone`; any other end keeps its reason.
    /// Regression: the clip reported only what the pipe took, and the body
    /// ended whole.
    #[tokio::test]
    async fn a_reader_that_resumes_after_the_last_bytes_were_left_out_reads_fewer_than_stopped_counts()
     {
        for (asked, reason) in [
            (EndReason::Stopped, "client_gone"),
            (EndReason::ShuttingDown, "shutting_down"),
        ] {
            let (logs, _guard) = Logs::capture();
            let mut rig = Rig::new(None);
            let reader = rig.start(spec(0, None, false));
            stall(&rig).await;
            assert_eq!(rig.report().await, started(0, None));
            rig.clips.stop("k1", asked);
            settle().await;
            if asked.is_graceful() {
                // The drain gives up on the queue; the last fragment waits.
                rig.clock.advance(FINISH_GRACE);
                settle().await;
            }
            assert!(rig.reports.try_recv().is_err(), "the last fragment waits");
            rig.clock.advance(FINISH_GRACE);
            let reports = rig.until_stopped().await;
            // The reader resumes and reads to the end of the pipe.
            let bytes = reader.rest().await;
            assert!(!bytes.ends_with(b"end\n"));
            let left = left_out(&logs);
            assert!(left > 0);
            let_assert!(
                Some(ClipReport::Stopped {
                    reason: got,
                    bytes: counted,
                    ..
                }) = reports.last()
            );
            assert_eq!(got, reason, "{reports:?}");
            assert_eq!(*counted, (bytes.len() + left) as u64, "{reports:?}");
            assert_eq!(logs.count(Level::INFO, "clip: stopped"), 1);
        }
    }

    /// An audio hole the queue reports is the audio's: a gap from where the
    /// container put the audio frame before it to where it put the one
    /// after, and the video's continuity goes on through it, so the video's
    /// own hole after it still shows (a hole resets only its own track's).
    #[tokio::test]
    async fn an_audio_lag_is_the_audio_s_gap_and_leaves_the_video_s_continuity() {
        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, None, true));
        for index in 0..3_u32 {
            rig.audio_frame(index);
            rig.video_frame(u64::from(index) * 100, index, index == 0, 16);
        }
        rig.audio_frame(3);
        rig.audio_frame(4);
        settle().await;
        let audio = Arc::clone(rig.audio.as_ref().unwrap());
        oversize(&rig, &audio, 300);
        rig.audio_frame(5);
        settle().await;
        rig.video_frame(700, 7, false, 16);
        rig.video_frame(800, 8, false, 16);
        settle().await;
        // The clip task first runs at 256 ms (audio frame 4), the keyframe captured at 0: 256 ms.
        assert_eq!(rig.report().await, started(256, Some("aac_lc")));
        assert_eq!(rig.report().await, gap("lagged", 256, 320));
        // The video frames at 700 and 800 ms wait for the audio to pass
        // them, which the stop releases; the one at 800 ms makes the jump
        // to 700 ms a hole.
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            reports,
            vec![
                gap("frames_dropped", 200, 700),
                stopped("stopped", bytes.len(), 800, 2)
            ]
        );
    }

    /// A hole the queue reports in audio the clip transcodes is a gap only
    /// where the file has one. A frame lost to a lag, which the transcode
    /// fills with silence (up to `MAX_SILENCE`), leaves the audio one run of
    /// packets and is no gap; 1.02 s lost re-anchors, the packets go on in
    /// a new epoch at 1220 ms, and the gap runs from the packet before the
    /// hole, at 160 ms, to there. Regression: the first packet after a
    /// filled hole, which still held audio from before it, reported a
    /// `lagged` gap over that audio, 160 to 180 ms, in a file without one.
    /// Only the frame after the hole decides: the frames that continue a
    /// re-anchored run, as the next one does here, do not drop its gap.
    /// A second lost frame 200 ms after the first covers the rate limit of
    /// the line that says so: one line, both holes dropped. After the
    /// 1.02 s, a frame lost right after the one that re-anchors, which the
    /// transcode fills, leaves the long gap as it was: reported once and
    /// counted. Regression: filling it dropped the hole the re-anchor kept
    /// for the new run's first packet, and the file's 1.02 s hole had
    /// neither a gap nor a count.
    #[tokio::test]
    async fn a_transcoded_audio_hole_is_a_gap_only_where_the_file_has_one() {
        let (logs, _guard) = Logs::capture();
        let payload = narrowband_payload(&Codec::Pcmu);
        let lead = {
            let delay = ToOpus::new(&Codec::Pcmu).unwrap().delay();
            i64::try_from(delay.as_nanos() * 48 / 1_000_000).unwrap()
        };
        // (frames lost in a row from frame 10, a second single loss)
        for (lost, again) in [(1_u32, Some(20_u32)), (51, None), (51, Some(62))] {
            let mut rig = Rig::new(Some(Codec::Pcmu));
            let reader = rig.start(spec(0, None, true));
            settle().await; // the clip subscribes before any frame
            let audio = Arc::clone(rig.audio.as_ref().unwrap());
            for index in 0..10 + lost + 20 {
                let ms = u64::from(index) * 20;
                if ms % 100 == 0 && ms <= 400 {
                    let keyframe = ms == 0;
                    rig.video_frame(ms, index / 5, keyframe, if keyframe { 32 } else { 16 });
                }
                let skipped = (11..10 + lost).contains(&index);
                if index == 10 || again == Some(index) {
                    // Frame 10 is lost to a lag; the camera's next `lost - 1` never came.
                    // A second single loss: 200 ms on, whose line the clip's rate limit
                    // holds back; or right after the frame that re-anchors after 1.02 s.
                    oversize(&rig, &audio, ms);
                } else if !skipped {
                    rig.narrowband_frame(index, &payload);
                }
                settle().await;
            }
            rig.clips.stop("k1", EndReason::Stopped);
            let reports = rig.until_stopped().await;
            let bytes = reader.rest().await;
            let timeline: Vec<(u32, i64)> = audio_samples(&lines(&bytes))
                .into_iter()
                .map(|(epoch, ts, _)| (epoch, ts))
                .collect();
            if lost == 1 {
                // 31 frames' time, two filled: one run, but the last packet.
                let run: Vec<(u32, i64)> = (0..30).map(|k| (0, 960 * k - lead)).collect();
                assert_eq!(timeline, run);
                assert_eq!(
                    reports,
                    vec![
                        started(0, Some("opus")),
                        stopped("stopped", bytes.len(), 580, 0)
                    ]
                );
            } else {
                // Frames 0..=9, the 10th's packet dropped with the re-anchor; then
                // frames 61..=80 from 61 * 960 less the delay (also with frame 62
                // lost: frame 63 fills its 20 ms, and the packets are the same).
                let mut runs: Vec<(u32, i64)> = (0..9).map(|k| (0, 960 * k - lead)).collect();
                runs.extend((0..19).map(|k| (1, 61 * 960 + 960 * k - lead)));
                assert_eq!(timeline, runs);
                assert_eq!(
                    reports,
                    vec![
                        started(0, Some("opus")),
                        gap("lagged", 160, 1_220),
                        stopped("stopped", bytes.len(), 1_580, 1),
                    ]
                );
            }
        }
        assert_eq!(
            logs.count(
                Level::DEBUG,
                "clip: the transcode filled the audio's hole with silence; no gap"
            ),
            2
        );
    }

    /// An audio frame without samples, as an RTP packet of padding only
    /// makes (RFC 3550 §5.1), is left out of the transcode, and a hole the
    /// queue reported before it waits for the frame with samples after it:
    /// a lost frame that frame fills is no gap, though the empty one was
    /// stamped 7840 ticks on (which the chain once filled with silence,
    /// and the next frame stepped back off it); 1.02 s lost, which the
    /// next frame with samples re-anchors on, is the gap from 160 to
    /// 1220 ms, though the empty one was stamped on the run. Regression:
    /// the empty frame took the hole's judgment, and the transcode's
    /// handling of it decided the gap.
    #[tokio::test]
    async fn rfc3550_5_1_an_audio_frame_without_samples_leaves_a_transcoded_hole_to_the_next() {
        let (logs, _guard) = Logs::capture();
        let payload = narrowband_payload(&Codec::Pcmu);
        let lead = {
            let delay = ToOpus::new(&Codec::Pcmu).unwrap().delay();
            i64::try_from(delay.as_nanos() * 48 / 1_000_000).unwrap()
        };
        // (frames lost in a row from frame 10, the empty frame's stamp)
        for (lost, empty) in [(1_u32, 1_600 + 7_840), (51, 11 * 160)] {
            let mut rig = Rig::new(Some(Codec::Pcmu));
            let reader = rig.start(spec(0, None, true));
            settle().await; // the clip subscribes before any frame
            let audio = Arc::clone(rig.audio.as_ref().unwrap());
            for index in 0..10 + lost + 20 {
                let ms = u64::from(index) * 20;
                if ms % 100 == 0 && ms <= 400 {
                    let keyframe = ms == 0;
                    rig.video_frame(ms, index / 5, keyframe, if keyframe { 32 } else { 16 });
                }
                if index == 10 {
                    // Frame 10 is lost to a lag; an empty frame comes right after.
                    oversize(&rig, &audio, ms);
                    rig.narrowband_frame_at(ms, empty, &Bytes::new());
                } else if !(11..10 + lost).contains(&index) {
                    rig.narrowband_frame(index, &payload);
                }
                settle().await;
            }
            rig.clips.stop("k1", EndReason::Stopped);
            let reports = rig.until_stopped().await;
            let bytes = reader.rest().await;
            let timeline: Vec<(u32, i64)> = audio_samples(&lines(&bytes))
                .into_iter()
                .map(|(epoch, ts, _)| (epoch, ts))
                .collect();
            if lost == 1 {
                let run: Vec<(u32, i64)> = (0..30).map(|k| (0, 960 * k - lead)).collect();
                assert_eq!(timeline, run);
                assert_eq!(
                    reports,
                    vec![
                        started(0, Some("opus")),
                        stopped("stopped", bytes.len(), 580, 0)
                    ]
                );
            } else {
                let mut runs: Vec<(u32, i64)> = (0..9).map(|k| (0, 960 * k - lead)).collect();
                runs.extend((0..19).map(|k| (1, 61 * 960 + 960 * k - lead)));
                assert_eq!(timeline, runs);
                assert_eq!(
                    reports,
                    vec![
                        started(0, Some("opus")),
                        gap("lagged", 160, 1_220),
                        stopped("stopped", bytes.len(), 1_580, 1),
                    ]
                );
            }
        }
        assert_eq!(
            logs.count(
                Level::DEBUG,
                "clip: the transcode filled the audio's hole with silence; no gap"
            ),
            1
        );
        assert_eq!(
            logs.count(
                Level::TRACE,
                "clip: an audio frame without samples left out of the transcode"
            ),
            2
        );
    }

    /// A hole the queue reported before a new input epoch whose timestamps
    /// continue the sample count is a gap: the transcode goes on with the
    /// decoder, but in a new output epoch placed at the epoch's capture
    /// time, which can step (the source forgets its clock mapping with the
    /// epoch), so no silence covers the hole in the file. A 10 ms PCMU
    /// frame lost (80 ticks, within the tolerance, so the count goes on) as
    /// the epoch starts with the capture times 1 s later: the gap runs from
    /// the packet before, at 160 ms, to the new epoch's first, at 1190 ms,
    /// and is counted. Regression: the crossing frame was `continued`, the
    /// clip dropped the hole as one silence filled, and the file's
    /// second-long hole had neither a gap nor a count.
    #[tokio::test]
    async fn a_hole_before_a_continuing_epoch_whose_capture_times_step_is_a_gap() {
        let (logs, _guard) = Logs::capture();
        // 10 ms of PCMU: 80 octets, 80 ticks (RFC 3551 §4.5.14).
        let payload = narrowband_payload(&Codec::Pcmu).slice(..80);
        let lead = {
            let delay = ToOpus::new(&Codec::Pcmu).unwrap().delay();
            i64::try_from(delay.as_nanos() * 48 / 1_000_000).unwrap()
        };
        let mut rig = Rig::new(Some(Codec::Pcmu));
        let reader = rig.start(spec(0, None, true));
        settle().await; // the clip subscribes before any frame
        let audio = Arc::clone(rig.audio.as_ref().unwrap());
        for index in 0..40_u32 {
            // Captured every 10 ms, 1 s later from the new epoch on.
            let ms = u64::from(index) * 10 + if index > 20 { 1_000 } else { 0 };
            if index % 10 == 0 && index <= 20 {
                let keyframe = index == 0;
                rig.video_frame(ms, index / 10, keyframe, if keyframe { 32 } else { 16 });
            }
            if index == 20 {
                // Frame 20 is lost to a lag, and the audio's epoch starts.
                oversize(&rig, &audio, ms);
                let _epoch = audio.start_epoch();
            } else {
                rig.narrowband_frame_at(ms, i64::from(index) * 80, &payload);
            }
            settle().await;
        }
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        let timeline: Vec<(u32, i64)> = audio_samples(&lines(&bytes))
            .into_iter()
            .map(|(epoch, ts, _)| (epoch, ts))
            .collect();
        // The timestamps run on; the packets from the epoch's first frame on
        // are output epoch 1, placed at its capture time.
        let run: Vec<(u32, i64)> = (0..18)
            .map(|k| (u32::from(k >= 9), 960 * k - lead))
            .collect();
        assert_eq!(timeline, run);
        assert_eq!(
            reports,
            vec![
                started(0, Some("opus")),
                gap("lagged", 160, 1_190),
                stopped("stopped", bytes.len(), 1_350, 1),
            ]
        );
        assert_eq!(
            logs.count(
                Level::DEBUG,
                "clip: the transcode filled the audio's hole with silence; no gap"
            ),
            0
        );
    }

    /// A reader that closes its end while the clip has nothing to write
    /// ends it `client_gone` at once: started with the camera silent,
    /// waiting for a keyframe, and waiting for the tracks. The pipe's write
    /// end polls an error then, whatever room it has (`poll(2)`: `POLLERR`).
    /// Regression: nothing noticed until the next write or the clip's end,
    /// ten minutes for an open-ended clip, which kept its slot that long.
    #[tokio::test]
    async fn a_reader_gone_while_the_clip_has_nothing_to_write_ends_it_client_gone() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        rig.video_frame(0, 0, true, 32);
        assert_eq!(rig.report().await, started(0, None));
        settle().await;
        drop(reader);
        let reports = rig.until_stopped().await;
        let_assert!([ClipReport::Stopped { reason, bytes, .. }] = reports.as_slice());
        assert_eq!((reason.as_str(), *bytes > 0), ("client_gone", true));

        for ready in [true, false] {
            let mut rig = Rig::with(Some(h264()), None, ready, 16);
            let reader = rig.start(spec(0, None, false));
            settle().await;
            drop(reader);
            assert_eq!(
                rig.until_stopped().await,
                vec![stopped("client_gone", 0, 0, 0)],
                "ready: {ready}"
            );
        }
    }

    /// `Started.before_ms` counts back from the report, the moment the
    /// container starts, not from `StartClip`: a keyframe captured at 700 ms
    /// that arrives at 1100 ms, after a `StartClip` at 1000 ms, is 400 ms old
    /// when the clip starts (also when an audio frame captured before it
    /// starts the container), so the supervisor's `at`, stamped on the
    /// report's arrival, less `before_ms` is the keyframe's capture time.
    /// Regression: counted from `StartClip` it was 300, and the `at` the
    /// supervisor stamps on the report's arrival (1100 ms) less 300 put the
    /// keyframe at 800 ms.
    #[tokio::test]
    async fn a_delayed_start_s_before_ms_counts_back_from_its_started_report() {
        for audio in [false, true] {
            let mut rig = Rig::new(audio.then(fake_aac));
            rig.advance_to(1_000);
            let reader = rig.start(spec(0, None, audio));
            settle().await;
            rig.advance_to(1_100);
            assert!(
                rig.video()
                    .publish_frame(frame_at(&rig, (700, 1_100), 0, true, 32))
            );
            settle().await;
            if audio {
                // Captured at 640 ms, it goes first and starts the container.
                assert!(rig.audio.as_ref().unwrap().publish_frame(frame_at(
                    &rig,
                    (640, 1_100),
                    0,
                    true,
                    4
                )));
                settle().await;
            }
            assert_eq!(
                rig.report().await,
                started(400, audio.then_some("aac_lc")),
                "audio: {audio}"
            );
            assert_eq!(
                rig.at(1_100)
                    .checked_sub(Duration::from_millis(400))
                    .unwrap(),
                rig.at(700),
                "at − before_ms is the keyframe's capture, audio: {audio}"
            );
            rig.clips.stop("k1", EndReason::Stopped);
            let (_, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
            let first = if audio {
                "frame a 0 0 k 4"
            } else {
                "frame v 0 0 k 32"
            };
            assert_eq!(lines(&bytes)[1], first);
        }
    }

    /// A video codec change while the pre-roll's keyframe waits for the
    /// audio (another family: the ring dropped its frames, the queue holds
    /// them) starts the container with the codec those frames were taken
    /// with, and the change, after them in the queue, ends the clip
    /// `stream_changed`, as one after the start does. Regression: the
    /// container started with the new codec, the held H.264 keyframe under
    /// an H.265 sample entry, and the change then matched it, unseen.
    #[tokio::test]
    async fn a_video_change_while_the_pre_roll_waits_keeps_its_entry_and_ends_the_clip() {
        let mut rig = Rig::new(Some(fake_aac()));
        rig.video_frame(0, 0, true, 32);
        rig.advance_to(100);
        let reader = rig.start(spec(100, None, true));
        settle().await;
        rig.video().set_codec(Codec::H265 {
            vps: None,
            sps: None,
            pps: None,
        });
        settle().await;
        rig.audio_frame(1);
        settle().await;
        assert_eq!(rig.report().await, started(100, Some("aac_lc")));
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            ["init video=h264 audio=aac_lc", "frame v 0 0 k 32", "end"]
        );
        assert_eq!(reports, vec![stopped("stream_changed", bytes.len(), 0, 0)]);
    }

    /// The audio changing before the container starts (the clip waits for
    /// a video keyframe) is the audio's sample entry: to a codec the
    /// container cannot carry, the clip goes on without audio and warns
    /// `audio_omitted`, as a clip whose audio was that from the outset;
    /// to one it can, the entry takes the new codec. Regression: the start
    /// read the track's codec now, which the container refused, and the
    /// clip ended `internal_error`; or (the fake container takes any) the
    /// omitted codec was declared.
    #[tokio::test]
    async fn an_audio_change_before_the_start_omits_the_audio_or_is_its_entry() {
        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, None, true));
        settle().await;
        rig.audio.as_ref().unwrap().set_codec(Codec::Unsupported {
            kind: Kind::Audio,
            name: "l16".into(),
        });
        settle().await;
        rig.video_frame(10, 0, true, 32);
        rig.audio_frame(1);
        settle().await;
        // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
        assert_eq!(rig.report().await, started(54, None));
        assert_eq!(
            rig.report().await,
            ClipReport::Warning {
                code: "audio_omitted".into(),
                message: "l16 does not fit the clip's container; the clip has no audio".into(),
            }
        );
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        assert_eq!(
            lines(&bytes),
            ["init video=h264", "frame v 0 0 k 32", "end"]
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 0, 0)]);

        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, None, true));
        settle().await;
        rig.audio
            .as_ref()
            .unwrap()
            .set_codec(Codec::Opus { channels: 2 });
        settle().await;
        rig.video_frame(10, 0, true, 32);
        rig.audio_frame(1);
        settle().await;
        // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
        assert_eq!(rig.report().await, started(54, Some("opus")));
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        assert_eq!(lines(&bytes)[0], "init video=h264 audio=opus");
        let_assert_reason(&reports, "stopped");
    }

    /// A codec change undone before a frame came under it is none: the
    /// queue keeps the newest of the two, the entry's codec, and the clip
    /// goes on.
    #[tokio::test]
    async fn a_codec_change_undone_before_a_frame_came_under_it_is_none() {
        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, None, true));
        rig.audio_frame(0);
        rig.video_frame(10, 0, true, 32);
        rig.audio_frame(1);
        settle().await;
        // Audio frame 1 at 64 ms releases the keyframe captured at 10 ms: 54 ms.
        assert_eq!(rig.report().await, started(54, Some("aac_lc")));
        // Held for the audio, which reached 64 ms; the changes queue behind.
        rig.video_frame(100, 1, false, 16);
        settle().await;
        rig.video().set_codec(Codec::H264 {
            profile_level_id: None,
            sps: Some(h264::test_data::sps(640, 480).into()),
            pps: Some(h264::test_data::pps().into()),
        });
        settle().await;
        rig.video().set_codec(h264());
        settle().await;
        rig.audio_frame(2);
        settle().await;
        rig.clips.stop("k1", EndReason::Stopped);
        let (reports, bytes) = tokio::join!(rig.until_stopped(), reader.rest());
        assert!(
            lines(&bytes).contains(&"frame v 0 3000 - 16".to_owned()),
            "{bytes:?}"
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 128, 0)]);
    }

    /// A keyframe and a codec change published together, before the clip
    /// looks, come in that order: the keyframe starts the container under
    /// its own codec, and the change after it ends the clip
    /// `stream_changed`. Regression: the subscription yielded the change
    /// first, ahead of the keyframe queued before it, so the container
    /// started an H.265 sample entry for the H.264 keyframe.
    #[tokio::test]
    async fn a_keyframe_and_a_codec_change_published_together_keep_their_order() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        settle().await;
        rig.video_frame(0, 0, true, 32);
        rig.video().set_codec(Codec::H265 {
            vps: None,
            sps: None,
            pps: None,
        });
        rig.video_frame(100, 1, true, 32);
        settle().await;
        // The clip task first runs at 100 ms, the keyframe captured at 0: 100 ms.
        assert_eq!(rig.report().await, started(100, None));
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            ["init video=h264", "frame v 0 0 k 32", "end"]
        );
        assert_eq!(reports, vec![stopped("stream_changed", bytes.len(), 0, 0)]);
    }

    /// Control events the clip's subscription lost to a lag end the clip
    /// `stream_changed` before any frame published after them: here a
    /// codec change overwritten by epochs, so the keyframe after them is of
    /// a codec the clip's entry does not have. Regression: the loss was
    /// only logged, and the clip wrote the H.265 keyframe under its H.264
    /// entry, behind a `reconnect` gap.
    #[tokio::test]
    async fn control_events_lost_to_a_lag_end_the_clip_stream_changed() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        settle().await;
        rig.video_frame(0, 0, true, 32);
        settle().await;
        assert_eq!(rig.report().await, started(0, None));
        rig.video().set_codec(Codec::H265 {
            vps: None,
            sps: None,
            pps: None,
        });
        // As many as the control channel holds: the change is lost.
        for _ in 0..16 {
            let _epoch = rig.video().start_epoch();
        }
        rig.video_frame(100, 1, true, 32);
        settle().await;
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            ["init video=h264", "frame v 0 0 k 32", "end"]
        );
        assert_eq!(reports, vec![stopped("stream_changed", bytes.len(), 0, 0)]);
    }

    /// A video frame captured at or after the clip's end ends the video,
    /// and the frames queued behind it in decode order are left out though
    /// presented before the end: B-frames that may refer to it, which is
    /// not in the file. The audio before the end is written. Regression:
    /// with `I0 P3 B1 B2` and the end between B2 and P3, P3 ended the clip
    /// and the drain then wrote B1 and B2, an undecodable tail.
    #[tokio::test]
    async fn b_frames_behind_the_video_s_end_in_decode_order_are_left_out() {
        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, Some(290), true));
        rig.audio_frame(0);
        rig.video_frame(10, 0, true, 32);
        for index in 1..=4 {
            rig.audio_frame(index);
        }
        settle().await;
        // The audio at 256 ms releases the keyframe captured at 10 ms: 246 ms.
        assert_eq!(rig.report().await, started(246, Some("aac_lc")));
        // P3 (presented at 300 ms, past the end) arrives first and is held
        // for the audio, which reached 256 ms; B1 and B2 queue behind it.
        rig.advance_to(300);
        for (ms, ts) in [(300, 27_000), (100, 9_000), (200, 18_000)] {
            assert!(
                rig.video()
                    .publish_frame(frame_at(&rig, (ms, 300), ts, false, 16))
            );
        }
        settle().await;
        // Past the end too: releases P3, which ends the clip.
        rig.audio_frame(5);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264 audio=aac_lc",
                "frame a 0 0 k 4",
                "frame v 0 0 k 32",
                "frame a 0 1024 k 4",
                "frame a 0 2048 k 4",
                "frame a 0 3072 k 4",
                "frame a 0 4096 k 4",
                "end",
            ]
        );
        assert_eq!(reports, vec![stopped("completed", bytes.len(), 256, 0)]);
    }

    /// A finite clip's end is measured by when its frames were captured
    /// by the ring's measure ([`captured`]), as its start and `before_ms`
    /// are: before a camera's Sender Report corrects the mapping (RFC 3550
    /// §6.4.1) a frame can be dated ahead of its arrival. Regression: a
    /// pre-roll keyframe arriving at 1 s dated 61 s was past the 4 s end
    /// of a clip asked at 3 s with `after_ms = 1000`, which ended
    /// `completed` before its container started, an empty file.
    #[tokio::test]
    async fn rfc3550_6_4_1_a_finite_clip_ends_by_capture_time_not_a_date_ahead_of_arrival() {
        let mut rig = Rig::new(None);
        // (captured, arrived) in ms after the start: dated a minute ahead
        // until the report at 3.5 s corrects it.
        for (at, ts, keyframe, len) in [
            ((61_000, 1_000), 90_000, true, 32),
            ((61_100, 1_100), 99_000, false, 16),
        ] {
            rig.advance_to(at.1);
            assert!(
                rig.video()
                    .publish_frame(frame_at(&rig, at, ts, keyframe, len))
            );
        }
        rig.advance_to(3_000);
        let reader = rig.start(spec(5_000, Some(1_000), false));
        settle().await;
        assert_eq!(rig.report().await, started(2_000, None));
        rig.video_frame(3_500, 105, false, 16);
        settle().await;
        // At the end: not written, and it ends the clip.
        rig.video_frame(4_000, 120, false, 16);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264",
                "frame v 0 90000 k 32",
                "frame v 0 99000 - 16",
                "frame v 0 315000 - 16",
                "end",
            ]
        );
        // The fake container's furthest place: 61.1 s − 61 s.
        assert_eq!(reports, vec![stopped("completed", bytes.len(), 100, 0)]);
    }

    /// The tracks go out in the order of the measure the clip ends by
    /// ([`captured`]), so audio past the end cannot end the clip before
    /// video captured before it: video dated ahead of its arrival by a
    /// Sender Report mapping off (RFC 3550 §6.4.1) goes out by its
    /// arrival. Regression: ordered by the dates, the audio at 4 s, held
    /// for the video, went out before a P-frame arriving at 3.95 s dated
    /// 61.95 s, ended a clip ending at 4 s, and the drain stopped at the
    /// audio at 4.064 s queued behind it, the P-frame left out.
    #[tokio::test]
    async fn rfc3550_6_4_1_audio_past_the_end_does_not_leave_out_video_dated_ahead() {
        let mut rig = Rig::new(Some(fake_aac()));
        let audio = Arc::clone(rig.audio.as_ref().unwrap());
        rig.advance_to(960);
        assert!(audio.publish_frame(frame_at(&rig, (960, 960), 15_360, true, 4)));
        // (captured, arrived) in ms after the start: dated a minute ahead.
        rig.advance_to(1_000);
        assert!(
            rig.video()
                .publish_frame(frame_at(&rig, (61_000, 1_000), 90_000, true, 32))
        );
        rig.advance_to(2_000);
        let reader = rig.start(spec(5_000, Some(2_000), true));
        settle().await;
        assert_eq!(rig.report().await, started(1_000, Some("aac_lc")));
        // The keyframe goes out when its hold for the audio ends.
        rig.advance_to(3_000);
        settle().await;
        // The audio at 4 s and 4.064 s, past the end, held for the video,
        // which reached 1 s; then the P-frame that began arriving at
        // 3.95 s, published once whole.
        for (ms, ts) in [(4_000, 64_000), (4_064, 65_024)] {
            rig.advance_to(ms);
            assert!(audio.publish_frame(frame_at(&rig, (ms, ms), ts, true, 4)));
            settle().await;
        }
        rig.advance_to(4_070);
        assert!(
            rig.video()
                .publish_frame(frame_at(&rig, (61_950, 3_950), 175_500, false, 16))
        );
        settle().await;
        // The audio's hold for the video ends: the audio at 4 s ends the
        // clip, and the drain stops at the next.
        rig.advance_to(5_000);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264 audio=aac_lc",
                "frame a 0 15360 k 4",
                "frame v 0 90000 k 32",
                "frame v 0 175500 - 16",
                "end",
            ]
        );
        // The fake container's furthest place, by the dates from the
        // first frame's: 61.95 s − 0.96 s.
        assert_eq!(reports, vec![stopped("completed", bytes.len(), 60_990, 0)]);
    }

    /// A standby on `rig`'s tracks, of the same codec, armed: its first
    /// keyframe switches the connection to it.
    fn standby(rig: &Rig) -> Arc<Track> {
        let staging = TrackSet::staging(&rig.set);
        let mut publisher = staging.publisher();
        let video = publisher.declare(Kind::Video, h264(), 90_000);
        publisher.ready();
        staging.arm_switch();
        video
    }

    /// A switch to another source of the same codec ends a running clip
    /// `stream_changed` at the switch itself: the old source's frames up
    /// to it are written, none of the new one's. Regression: the clip took
    /// the new source's keyframe for a reconnect and wrote it behind a
    /// `reconnect` gap, until the worker's late stop came.
    #[tokio::test]
    async fn a_switch_to_another_source_ends_the_clip_at_the_switch() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        settle().await;
        rig.video_frame(0, 0, true, 32);
        rig.video_frame(100, 1, false, 16);
        let standby = standby(&rig);
        rig.video_frame_on(&standby, 200, 0, true, 32);
        rig.video_frame_on(&standby, 300, 1, false, 16);
        settle().await;
        // The container starts at 300 ms, when the frames published before the clip task ran are all in; the keyframe was captured at 0: 300 ms.
        assert_eq!(rig.report().await, started(300, None));
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264",
                "frame v 0 0 k 32",
                "frame v 0 3000 - 16",
                "end"
            ]
        );
        assert_eq!(
            reports,
            vec![stopped("stream_changed", bytes.len(), 100, 0)]
        );
    }

    /// A clip started right after a switch to another source of the same
    /// codec starts at the new source's first keyframe, however far back
    /// it asks: the ring holds nothing of the old source after the switch.
    /// Regression: the ring kept the old source's GOPs, and the clip began
    /// there and crossed into the new source behind a `reconnect` gap.
    #[tokio::test]
    async fn a_clip_started_after_a_switch_starts_in_the_new_source() {
        let mut rig = Rig::new(None);
        rig.video_frame(0, 0, true, 32);
        rig.video_frame(100, 1, false, 16);
        let standby = standby(&rig);
        rig.video_frame_on(&standby, 1_000, 0, true, 32);
        rig.video_frame_on(&standby, 1_100, 1, false, 16);
        rig.advance_to(1_200);
        let reader = rig.start(spec(5_000, None, false));
        settle().await;
        assert_eq!(rig.report().await, started(200, None));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264",
                "frame v 1 0 k 32",
                "frame v 1 3000 - 16",
                "end"
            ]
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 100, 0)]);
    }

    /// A switch between a clip's video start and its audio start ends the
    /// clip `stream_changed` there, before it takes a frame: the video's
    /// start is the old source's and the audio's the new one's, whose
    /// audio, captured before the old video frames queued ahead of the
    /// video's `SourceSwitched`, would go out among them. Without a switch
    /// between them, the same audio start is taken. Regression: the clip
    /// paired the two starts and wrote the new source's audio frame
    /// between the old source's video frames.
    #[tokio::test]
    async fn a_switch_between_the_video_s_start_and_the_audio_s_ends_the_clip_stream_changed() {
        let (logs, _guard) = Logs::capture();
        let rig = Rig::new(Some(fake_aac()));
        rig.video_frame(0, 0, true, 32);
        rig.audio_frame(0);
        rig.video_frame(100, 1, false, 16);
        let staging = TrackSet::staging(&rig.set);
        let mut publisher = staging.publisher();
        let standby_video = publisher.declare(Kind::Video, h264(), 90_000);
        let standby_audio = publisher.declare(Kind::Audio, fake_aac(), 16_000);
        publisher.ready();
        staging.arm_switch();
        let (_reader, writer) = io::pipe().unwrap();
        let (reports, _) = mpsc::channel(1);
        let mut clip = Clip::new(
            &spec(5_000, None, true),
            pipe::Sender::from_owned_fd(OwnedFd::from(writer)).unwrap(),
            Arc::new(FakeClipMuxerFactory::default()),
            ClipSettings::default(),
            rig.clock.clone(),
            rig.at(150),
            reports,
        );
        let (_video, snapshot, _, source) = start_video(rig.video(), rig.at(0));
        assert_eq!((snapshot.unwrap().frames().count(), source), (2, 0));
        // The switch, then the new source's audio, captured at 50 ms,
        // before the old P-frame at 100 the video's start holds.
        rig.video_frame_on(&standby_video, 200, 0, true, 32);
        assert!(standby_audio.publish_frame(MediaFrame {
            ts: MediaTime::ZERO,
            wallclock: rig.at(50),
            arrival: rig.at(200),
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: vec![0xe1; 4].into(),
        }));
        let audio = rig.audio.as_ref().unwrap();
        let_assert!(Err(EndReason::StreamChanged) = clip.start_audio(audio, rig.at(0), source));
        let lines = logs.lines(
            Level::INFO,
            "clip: the connection switched to another source between the video's start and the audio's; ending",
        );
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].fields, " clip.id=k1 video_source=0 audio_source=1");
        let_assert!(Ok(Some((_, Some(held), entry))) = clip.start_audio(audio, rig.at(0), 1));
        assert_eq!(held.frames().count(), 1, "the new source's frame alone");
        assert_eq!(entry.codec, fake_aac());
    }

    /// A B-frame run of any length is no hole: its reference frame jumps
    /// over it, and the run follows. Decode order `I0 P3 B1 B2 P4 P7 B5 B6
    /// P8` teaches one interval at `P4`, which `P7` jumps past by three,
    /// and `I0 P1 P2 P5 B3 B4 P6` meets its first run after one-interval
    /// steps. Regression: each jump was a `frames_dropped` gap at once.
    #[tokio::test]
    async fn b_frame_runs_of_varying_length_are_no_gap() {
        for order in [&[0, 3, 1, 2, 4, 7, 5, 6, 8][..], &[0, 1, 2, 5, 3, 4, 6][..]] {
            let mut rig = Rig::new(None);
            let reader = rig.start(spec(0, None, false));
            for (at, index) in order.iter().enumerate() {
                let ms = u64::try_from(at).unwrap() * 100;
                rig.video_frame(ms, *index, *index == 0, 16);
                settle().await;
            }
            assert_eq!(rig.report().await, started(0, None));
            rig.clips.stop("k1", EndReason::Stopped);
            let reports = rig.until_stopped().await;
            drop(reader);
            let_assert!([ClipReport::Stopped { gaps, .. }] = reports.as_slice());
            assert_eq!(*gaps, 0, "{order:?}: {reports:?}");
        }
    }

    /// A keyframe that arrives just before the start timeout meets it,
    /// though the interleaver holds it for the silent audio past the
    /// timeout: the clip starts once the hold ends. Regression: the
    /// timeout ended the clip `source_not_live` with its keyframe queued.
    #[tokio::test]
    async fn a_keyframe_held_for_the_audio_at_the_start_timeout_starts_the_clip() {
        let mut rig = Rig::new(Some(fake_aac()));
        let reader = rig.start(spec(0, None, true));
        settle().await;
        rig.video_frame(9_500, 95, true, 32);
        settle().await;
        rig.advance_to(10_000);
        settle().await;
        rig.advance_to(10_500);
        settle().await;
        // The keyframe was captured at 9.5 s, after `StartClip` at 0, and
        // `max_skew` (1 s) releases it at 10.5 s, when the container
        // starts: 10.5 s − 9.5 s. Counted from `StartClip` this saturated
        // to 0, so `at − before_ms` put the keyframe at the start of the
        // wait, not at its capture.
        assert_eq!(rig.report().await, started(1_000, Some("aac_lc")));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(
            lines(&bytes),
            [
                "init video=h264 audio=aac_lc",
                "frame v 0 285000 k 32",
                "end"
            ]
        );
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 0, 0)]);
    }

    /// A frame after a jump that repeats the jump's timestamp is not
    /// presented before it, so it shows no B-frame run: the jump is a
    /// `frames_dropped` gap.
    #[tokio::test]
    async fn a_jump_followed_by_its_own_timestamp_is_a_gap() {
        let mut rig = Rig::new(None);
        let reader = rig.start(spec(0, None, false));
        for (ms, index) in [(0, 0), (100, 1), (200, 2), (600, 6), (700, 6)] {
            rig.video_frame(ms, index, index == 0, 16);
            settle().await;
        }
        assert_eq!(rig.report().await, started(0, None));
        let_assert!(ClipReport::Gap { reason, .. } = rig.report().await);
        assert_eq!(reason, "frames_dropped");
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        drop(reader);
        let_assert!([ClipReport::Stopped { gaps, .. }] = reports.as_slice());
        assert_eq!(*gaps, 1);
    }
}
