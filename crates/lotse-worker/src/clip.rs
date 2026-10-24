//! Event clips: one task per clip that starts from the connection's
//! pre-roll ring, continues with the live frames and writes the registered
//! container into the pipe the supervisor passed, until the clip ends.
//!
//! A clip waits for the source's tracks, subscribes to the native video
//! track and, when asked and the container carries its codec or the clip
//! can transcode it (G.711 and G.722 to Opus, [`ToOpus`]), the native
//! audio track, and only then takes the rings' snapshots, so nothing is lost
//! or written twice between the two: the [`ReliableQueue`] drops the live
//! frames the pre-roll holds. It starts at the newest held keyframe
//! captured at or before `now − before_ms` (else the oldest held),
//! preferring a later held one whose in-band parameter sets are the
//! track's, which the container's sample entry carries; with nothing held
//! it starts at the next keyframe, waiting for it up to the start timeout.
//! The frames go through the queue and the [`Interleaver`] into the
//! [`ClipMuxer`], and the bytes into the pipe without blocking. Transcoded
//! audio goes through its clip's own [`ToOpus`] on the way out of the
//! queue, so the ring keeps the camera's frames and the pre-roll's audio is
//! transcoded in a burst at the start, at most [`MAX_STEP_PACKETS`] packets
//! before the task yields to the worker's other tasks.
//!
//! Invariants: the media path never waits for a clip. While the pipe is
//! full the task takes nothing out of its queue but keeps draining the
//! subscriptions into it, so a stalled reader fills the kernel's pipe,
//! then the queue up to `clip_queue_bytes`, and then costs the clip a gap,
//! never the camera's other consumers. A clip ends at the first frame
//! captured at or after its end, or [`END_GRACE`] after it when none comes.
//! A graceful end (`completed`, `stopped`, `max_duration`) first writes
//! what the queue still holds, frames held for the other track included,
//! up to the clip's end, for at most [`FINISH_GRACE`] of a reader taking
//! it; any other end drops the queue. Every end but a gone reader then
//! writes the container's last fragment, for at most [`FINISH_GRACE`],
//! closes the pipe and reports `Stopped` last.
//! Gaps carry clip media time: milliseconds from the clip's first frame.
//!
//! Standards: the container is the muxer's (ISO/IEC 14496-12 fragmented
//! MP4 for the daemon's); the parameter sets a start keyframe carries in
//! band are told apart by NAL unit type (ISO/IEC 14496-10 Table 7-1, ITU-T
//! H.265 Table 7-1); a write after the reader closed its end fails with
//! `EPIPE` (POSIX `write`, Linux `pipe(7)`).

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
use lotse_core::preroll::PrerollSnapshot;
use lotse_core::source::TrackSet;
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use lotse_core::track::{Track, TrackEvent, TrackSubscription, Unit};
use lotse_ipc::{ClipReport, ClipSpec};
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
/// last bytes before it closes the pipe without them.
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

/// The most Opus packets a clip transcodes before it lets the worker's
/// other tasks run: half a second of audio, a few milliseconds of one
/// core. A pre-roll's audio comes out of the queue at once; transcoded in
/// one go, a 120 s window would hold a runtime thread for the length of
/// 6000 packets.
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
    /// The reader closed its end of the pipe.
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
    /// [`SHUTDOWN_GRACE`] on `clock` to write its last fragment and
    /// report; one still running then is aborted, its pipe closed as its
    /// task drops.
    pub(crate) async fn shutdown(&mut self, clock: &Arc<dyn Clock>) {
        self.stop_all(EndReason::ShuttingDown);
        let deadline = clock.now().checked_add(SHUTDOWN_GRACE);
        for (clip_id, handle) in self.running.drain() {
            let mut task = handle.task;
            let left = deadline.map_or(SHUTDOWN_GRACE, |deadline| {
                deadline.saturating_duration_since(clock.now())
            });
            tokio::select! {
                _ = &mut task => {}
                () = clock.sleep(left) => {
                    tracing::warn!(clip.id = %clip_id, grace_ms = SHUTDOWN_GRACE.as_millis(), "clip still finishing at shutdown; aborted");
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

/// Waits until the source declared `tracks`: `source_not_live` when it
/// does not by `deadline` on `clock`, or the worker's end; `clip_id` names
/// the clip in the log.
async fn wait_ready(
    tracks: &TrackSet,
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
    let mut clip = Clip::new(
        &spec,
        pipe,
        factory.as_ref(),
        settings,
        clock,
        started,
        reports,
    );
    tracing::debug!(
        clip.id = %clip.id,
        before_ms = spec.before_ms,
        after_ms = spec.after_ms,
        audio = spec.audio,
        "clip: waiting for the tracks"
    );
    let reason = match clip.open(&tracks, factory.as_ref(), &mut requested).await {
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

/// A clip's subscriptions and the queue they fill.
struct Media {
    /// The video track's frames.
    video: TrackSubscription,
    /// The audio track's frames, until they end; `None` for a clip
    /// without audio.
    audio: Option<TrackSubscription>,
    /// The audio track, kept when its subscription ends.
    audio_track: Option<Arc<Track>>,
    /// The queue, merged in capture order.
    interleaver: Interleaver,
}

/// Where a clip continues a video track: the epoch and the newest
/// timestamp it wrote, and the shortest advance between two frames seen in
/// the epoch, so a hole inside an epoch shows.
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
}

/// What a video frame is to the clip's continuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// It follows the frame before it.
    Follows,
    /// It ends a hole, `reconnect` or `frames_dropped`.
    Ends(&'static str),
    /// A new epoch's frame before its first keyframe: left out.
    Undecodable,
}

impl Continuity {
    /// What `frame` is: the end of a hole when its epoch is not the last
    /// frame's (`reconnect`; undecodable unless a keyframe) or it advances
    /// the timestamp by more than twice the epoch's frame interval
    /// (`frames_dropped`).
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
            return Seen::Ends("reconnect");
        }
        let Some(advance) = frame.ts.checked_sub(newest).filter(|advance| *advance > 0) else {
            return Seen::Follows;
        };
        self.last = Some((epoch, frame.ts));
        let dropped = self
            .step
            .is_some_and(|step| advance > step.saturating_mul(2));
        self.step = Some(self.step.map_or(advance, |step| step.min(advance)));
        if dropped {
            Seen::Ends("frames_dropped")
        } else {
            Seen::Follows
        }
    }

    /// The queue reported a hole: the next frame continues from nothing.
    const fn reset(&mut self) {
        self.last = None;
    }
}

/// The video snapshot a clip starts from: the ring's frames from the
/// newest keyframe captured at or before `target` (else the oldest held),
/// or from a later held keyframe when that one carries parameter sets
/// other than the track's and a later one does not, since the container's
/// sample entry has the track's newest; `None` when nothing is held.
fn start_snapshot(video: &Track, target: Instant) -> Option<PrerollSnapshot> {
    let snapshot = video.preroll_snapshot(target)?;
    let codec = video.codec();
    if sets_match(&codec, &snapshot.start().payload) {
        return Some(snapshot);
    }
    let tidy = snapshot
        .frames()
        .find(|frame| frame.keyframe && sets_match(&codec, &frame.payload))
        .map(|frame| frame.wallclock);
    tracing::debug!(
        later = tidy.is_some(),
        "clip: the start keyframe carries other parameter sets than the track's"
    );
    tidy.and_then(|at| video.preroll_snapshot(at))
        .or(Some(snapshot))
}

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

/// The transcode of audio in `codec` at `clock_rate` that the container
/// cannot carry as it is: G.711 or G.722 to Opus, when the container takes
/// Opus; `None` otherwise.
fn transcoder(codec: &Codec, clock_rate: u32, factory: &dyn ClipMuxerFactory) -> Option<ToOpus> {
    (transcodes(codec) && factory.accepts(&ToOpus::output().codec))
        .then(|| ToOpus::new(codec, clock_rate).ok())
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
    /// The container writer.
    muxer: Box<dyn ClipMuxer>,
    /// The limits.
    settings: ClipSettings,
    /// The injected clock.
    clock: Arc<dyn Clock>,
    /// The clock's reading at `StartClip`: what `before_ms` and `after_ms`
    /// count from.
    started: Instant,
    /// The capture time at which it ends.
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
    /// The first frame's capture time, once the container started: clip
    /// media time counts from it.
    origin: Option<Instant>,
    /// The newest capture time written.
    newest: Option<Instant>,
    /// The tracks' codecs the container's sample entries were made from,
    /// video and audio (the camera's, for transcoded audio), once it
    /// started: a track that changes from it ends the clip.
    entries: Option<(Codec, Option<Codec>)>,
    /// How far before its start it begins: the start keyframe's age.
    before_ms: u32,
    /// The audio codec left out because the container cannot carry it
    /// and the clip cannot transcode it.
    omitted: Option<String>,
    /// The audio's transcode to Opus, with the camera's codec it decodes,
    /// for audio the container cannot carry as it is.
    transcoder: Option<(Codec, ToOpus)>,
    /// Opus packets transcoded since the clip last yielded.
    step_packets: usize,
    /// Where the video continues.
    continuity: Continuity,
    /// The gaps it had.
    gaps: u32,
    /// Rate-limits the line of a gap.
    gap_log: Throttle,
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
        factory: &dyn ClipMuxerFactory,
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
            settings,
            clock,
            started,
            end_at,
            end_reason,
            reports,
            outbox: Vec::new(),
            pending: VecDeque::new(),
            written: 0,
            origin: None,
            newest: None,
            entries: None,
            before_ms: 0,
            omitted: None,
            transcoder: None,
            step_packets: 0,
            continuity: Continuity::default(),
            gaps: 0,
            gap_log: Throttle::default(),
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
    /// no video, or the worker asks first.
    async fn open(
        &mut self,
        tracks: &TrackSet,
        factory: &dyn ClipMuxerFactory,
        requested: &mut watch::Receiver<Option<EndReason>>,
    ) -> Result<Media, EndReason> {
        wait_ready(
            tracks,
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
        let audio_track = match natives.iter().find(|track| track.kind() == Kind::Audio) {
            Some(track) if self.audio => {
                let codec = track.codec();
                if factory.accepts(&codec) {
                    Some(Arc::clone(track))
                } else if let Some(chain) = transcoder(&codec, track.clock_rate(), factory) {
                    self.transcoder = Some(((*codec).clone(), chain));
                    Some(Arc::clone(track))
                } else {
                    self.omitted = Some(codec.name().to_owned());
                    None
                }
            }
            _ => None,
        };
        let video = video_track.subscribe(Unit::Frames);
        let audio = audio_track
            .as_ref()
            .map(|track| track.subscribe(Unit::Frames));
        let mut queue = ReliableQueue::new(self.settings.policy.queue_bytes, audio.is_some());
        let now = self.clock.now();
        // Linux's monotonic clock reads as a signed timespec, so a window
        // reaching back before it started does not fail there.
        let target = self
            .started
            .checked_sub(self.before)
            .unwrap_or(self.started);
        if let Some(snapshot) = start_snapshot(video_track, target) {
            self.before_ms = millis(snapshot.age(self.started));
            queue.preroll(Kind::Video, &snapshot, now);
            if let Some(audio_snapshot) = audio_track
                .as_ref()
                .and_then(|track| track.preroll_snapshot(snapshot.start().wallclock))
            {
                queue.preroll(Kind::Audio, &audio_snapshot, now);
            }
        }
        Ok(Media {
            video,
            audio,
            audio_track,
            interleaver: Interleaver::new(queue, self.settings.policy.max_skew),
        })
    }

    /// Runs the clip until it ends: takes what the subscriptions yield
    /// into the queue at once, and the queue's items into the container
    /// and the pipe as fast as the pipe takes them.
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
                // The step stopped with work left: the worker's other tasks
                // run first, then the next step goes on.
                () = tokio::task::yield_now(), if more => {}
                () = sleep => {}
            }
        }
    }

    /// What can be done now: the end when a deadline passed, else the
    /// queue's items released now into the container while the pipe takes
    /// its bytes; whether it stopped at [`MAX_STEP_PACKETS`] with more to
    /// do.
    fn step(&mut self, media: &mut Media) -> Result<bool, EndReason> {
        let now = self.clock.now();
        if self.origin.is_none() && now >= self.start_deadline() {
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

    /// When to look again with nothing pushed: the start timeout, the late
    /// end, or, while the pipe takes everything, when a frame the
    /// interleaver holds goes out, whichever comes first. A frame held
    /// behind a full pipe waits for the pipe, whose readiness wakes the
    /// clip: its hold over would wake it at once again and again.
    fn wake(&self, interleaver: &Interleaver) -> Instant {
        let mut wake = self.late_end();
        if self.origin.is_none() {
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
    fn take(&mut self, out: Out, media: &Media) -> Result<(), EndReason> {
        match out {
            Out::Frame { track, frame } => self.frame(track, frame, media),
            Out::Gap {
                track,
                reason,
                from,
                to,
            } => {
                if track == Kind::Video {
                    self.continuity.reset();
                }
                // Every hole follows a frame written, so the origin is set.
                let origin = self.origin.unwrap_or(from);
                let (from, to) = (
                    from.saturating_duration_since(origin),
                    to.saturating_duration_since(origin),
                );
                self.gap(gap_name(reason), from, to);
                Ok(())
            }
            Out::Control { track, event } => self.control(track, &event),
        }
    }

    /// One frame: the end when it was captured at or after the clip's;
    /// the container's start before the first, its origin the transcode's
    /// delay earlier when the clip transcodes its audio (the packets are
    /// moved back by it); then into the container, transcoded first when
    /// the clip transcodes its track.
    fn frame(
        &mut self,
        track: Kind,
        frame: Arc<MediaFrame>,
        media: &Media,
    ) -> Result<(), EndReason> {
        if frame.wallclock >= self.end_at {
            tracing::debug!(clip.id = %self.id, reason = self.end_reason.name(), "clip: its end is reached");
            return Err(self.end_reason);
        }
        if self.origin.is_none() {
            let lead = self
                .transcoder
                .as_ref()
                .map_or(Duration::ZERO, |(_, chain)| chain.delay());
            let origin = frame.wallclock.checked_sub(lead).unwrap_or(frame.wallclock);
            self.begin(origin, media)?;
        }
        let Some((_, chain)) = self.transcoder.as_mut().filter(|_| track == Kind::Audio) else {
            return self.sample(track, frame);
        };
        let packets = chain.push(&frame).map_err(ClipError::from);
        let packets = packets.map_err(self.failed("transcode"))?;
        self.step_packets = self.step_packets.saturating_add(packets.len());
        for packet in packets {
            self.sample(track, packet)?;
        }
        Ok(())
    }

    /// One frame as the container takes it, a gap when it ends a hole of
    /// the video: from the video frame before it to this one, where the
    /// container put them. That can be later than their capture times (an
    /// epoch captured before the last frame began starts where that frame
    /// ends), and a gap from capture times then disagreed with the file,
    /// or ended before it began, a report the supervisor refuses (found
    /// end to end, 2026-10-23: a camera reconnecting within a frame).
    fn sample(&mut self, track: Kind, frame: Arc<MediaFrame>) -> Result<(), EndReason> {
        let hole = match track {
            Kind::Video => match self.continuity.observe(&frame) {
                Seen::Follows => None,
                Seen::Ends(reason) => Some(reason),
                Seen::Undecodable => return Ok(()),
            },
            Kind::Audio => None,
        };
        let from = self.muxer.media_time(Kind::Video);
        self.newest = self.newest.max(Some(frame.wallclock));
        let bytes = self.muxer.push(track, frame).map_err(self.failed("push"))?;
        if let Some(reason) = hole {
            let to = self.muxer.media_time(Kind::Video);
            self.gap(reason, from, to);
        }
        self.queue(bytes);
        Ok(())
    }

    /// Starts the container with the tracks' codecs as they are now, the
    /// newest parameter sets, its media time 0 at `origin`, and
    /// reports `Started` (and the omitted audio's warning). Transcoded
    /// audio is Opus in the container; a camera codec that changed since
    /// the clip chose to transcode it ends the clip `stream_changed`.
    fn begin(&mut self, origin: Instant, media: &Media) -> Result<(), EndReason> {
        let video_track = media.video.track();
        let video = ClipTrack {
            codec: (*video_track.codec()).clone(),
            clock_rate: video_track.clock_rate(),
        };
        let source = media
            .audio_track
            .as_ref()
            .map(|track| ((*track.codec()).clone(), track.clock_rate()));
        if let (Some((codec, _)), Some((from, _))) = (&source, &self.transcoder)
            && codec != from
        {
            tracing::info!(clip.id = %self.id, from = from.name(), codec = codec.name(), "clip: the audio changed before the clip started; ending");
            return Err(EndReason::StreamChanged);
        }
        let audio = source.as_ref().map(|(codec, clock_rate)| {
            if self.transcoder.is_some() {
                ToOpus::output()
            } else {
                ClipTrack {
                    codec: codec.clone(),
                    clock_rate: *clock_rate,
                }
            }
        });
        let init = self
            .muxer
            .start(&video, audio.as_ref())
            .map_err(self.failed("start"))?;
        self.muxer.set_origin(origin);
        self.queue(init);
        self.origin = Some(origin);
        let audio_name = audio.as_ref().map(|audio| audio.codec.name().to_owned());
        tracing::info!(
            clip.id = %self.id,
            before_ms_asked = millis(self.before),
            before_ms = self.before_ms,
            video = video.codec.name(),
            audio = audio_name.as_deref(),
            audio_transcoded_from = self.transcoder.as_ref().map(|(codec, _)| codec.name()),
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
        self.entries = Some((video.codec, source.map(|(codec, _)| codec)));
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

    /// A control event of `track`: a codec other than its sample entry's
    /// ends the clip, since one file has one entry per track; before the
    /// container started, the start reads the codec anyway.
    fn control(&self, track: Kind, event: &TrackEvent) -> Result<(), EndReason> {
        if let TrackEvent::TrackChanged(codec) = event
            && let Some(entry) = self.entry(track)
            && **codec != *entry
        {
            tracing::info!(clip.id = %self.id, %track, codec = codec.name(), "clip: the track changed; ending");
            return Err(EndReason::StreamChanged);
        }
        tracing::debug!(clip.id = %self.id, %track, ?event, "clip: track event");
        Ok(())
    }

    /// The codec of `track`'s sample entry, once the container started.
    fn entry(&self, track: Kind) -> Option<&Codec> {
        let (video, audio) = self.entries.as_ref()?;
        match track {
            Kind::Video => Some(video),
            Kind::Audio => audio.as_ref(),
        }
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
                    tracing::info!(clip.id = %self.id, error = %err, "clip: the reader is gone");
                    return Err(EndReason::ClientGone);
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
    /// dropped. `client_gone` when the reader went meanwhile.
    async fn drain(&mut self, media: &mut Media) -> Option<EndReason> {
        let deadline = self.clock.now().checked_add(FINISH_GRACE);
        loop {
            if let Err(reason) = self.write() {
                return Some(reason);
            }
            if self.pending.is_empty() {
                // Every item was queued by now, so its hold ends by then.
                let now = self.clock.now();
                let release = now
                    .checked_add(self.settings.policy.max_skew)
                    .unwrap_or(now);
                let out = media.interleaver.next(release)?;
                if self.take(out, media).is_err() {
                    return None;
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
    /// unless the reader is gone; the pipe closes, and `Stopped` is the
    /// last report.
    async fn finish(mut self, reason: EndReason) {
        if reason != EndReason::ClientGone {
            if self.origin.is_some() {
                match self.muxer.finish() {
                    Ok(last) => self.queue(last),
                    Err(err) => {
                        tracing::warn!(clip.id = %self.id, error = %err, "clip: the container's last fragment failed");
                    }
                }
            }
            self.flush().await;
        }
        self.send_reports().await;
        let duration_ms = self.newest.zip(self.origin).map_or(0, |(newest, origin)| {
            millis(newest.saturating_duration_since(origin))
        });
        let Self {
            id,
            pipe,
            reports,
            written,
            gaps,
            ..
        } = self;
        drop(pipe);
        tracing::info!(
            clip.id = %id,
            reason = reason.name(),
            bytes = written,
            duration_ms,
            gaps,
            "clip: stopped"
        );
        let stopped = ClipReport::Stopped {
            reason: reason.name().to_owned(),
            bytes: written,
            duration_ms,
            gaps,
        };
        // As in `send_reports`.
        let _sent = reports.send((id, stopped)).await;
    }

    /// Writes the pending bytes as the pipe takes them, for at most
    /// [`FINISH_GRACE`]; a reader that takes them not in time, or is gone,
    /// gets the file without them.
    async fn flush(&mut self) {
        let deadline = self.clock.now().checked_add(FINISH_GRACE);
        loop {
            if self.write().is_err() || self.pending.is_empty() {
                return;
            }
            let left = deadline.map_or(FINISH_GRACE, |deadline| {
                deadline.saturating_duration_since(self.clock.now())
            });
            tokio::select! {
                _ = self.pipe.writable() => {}
                () = self.clock.sleep(left) => {
                    let pending: usize = self.pending.iter().map(Bytes::len).sum();
                    tracing::warn!(clip.id = %self.id, pending, "clip: the reader did not take the last bytes in time; closing without them");
                    return;
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
            self.advance_to(ms);
            let header = if keyframe { 0x65 } else { 0x41 };
            assert!(self.video().publish_frame(MediaFrame {
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
            let ms = u64::from(index) * 20;
            self.advance_to(ms);
            assert!(self.audio.as_ref().unwrap().publish_frame(MediaFrame {
                ts: MediaTime::from_ticks(i64::from(index) * 160),
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
            let (reader, writer) = io::pipe().unwrap();
            let clock: Arc<dyn Clock> = self.clock.clone();
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
        let payload = narrowband_payload(codec);
        let mut audio = 0;
        for index in 0..100_u32 {
            let ms = u64::from(index) * 100;
            while u64::from(audio) * 20 <= ms {
                rig.narrowband_frame(audio, &payload);
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
            let delay = ToOpus::new(&codec, 8_000).unwrap().delay();
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

    /// The camera's audio codec changing after the clip chose to transcode
    /// it ends the clip `stream_changed`: mid-clip as any track change does,
    /// and before the first frame, which the container would otherwise
    /// start with another codec's frames in the transcode.
    #[tokio::test]
    async fn a_transcoded_audio_codec_that_changes_ends_the_clip_stream_changed() {
        let (logs, _guard) = Logs::capture();
        let payload = narrowband_payload(&Codec::Pcmu);
        let mut rig = Rig::new(Some(Codec::Pcmu));
        let _reader = rig.start(spec(0, None, true));
        rig.video_frame(0, 0, true, 32);
        rig.narrowband_frame(1, &payload);
        rig.narrowband_frame(2, &payload);
        settle().await;
        assert_eq!(rig.report().await, started(0, Some("opus")));
        rig.audio.as_ref().unwrap().set_codec(Codec::Pcma);
        rig.video_frame(100, 1, false, 16);
        let reports = rig.until_stopped().await;
        let_assert_reason(&reports, "stream_changed");

        let mut rig = Rig::new(Some(Codec::G722));
        let reader = rig.start(spec(0, None, true));
        settle().await;
        rig.audio.as_ref().unwrap().set_codec(Codec::Pcmu);
        rig.video_frame(0, 0, true, 32);
        // Audio past the keyframe lets the interleaver release it.
        rig.narrowband_frame(1, &payload);
        let reports = rig.until_stopped().await;
        assert_eq!(reports, vec![stopped("stream_changed", 0, 0, 0)]);
        assert!(reader.rest().await.is_empty());
        assert_eq!(
            logs.count(
                Level::INFO,
                "clip: the audio changed before the clip started; ending"
            ),
            1
        );
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
    /// two, so it never ends before it begins. Regression: from capture
    /// times the gap ended 50 ms before it began, a report the supervisor
    /// refuses, which ended the clip `internal_error` (the end-to-end clip
    /// test's camera reconnected within a frame).
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
        assert_eq!(rig.report().await, started(0, None));
        assert_eq!(rig.report().await, gap("reconnect", 100, 200));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 100, 1)]);
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
    /// epoch's pictures for.
    #[tokio::test]
    async fn a_new_epoch_s_video_starts_at_its_first_keyframe() {
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
        assert_eq!(rig.report().await, started(0, None));
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
    }

    /// Capture times that jitter while the timestamps run evenly are no
    /// hole: before a camera's first Sender Report a frame's capture time
    /// is its arrival, and two frames arriving together made the shortest
    /// advance a millisecond and every later frame a `frames_dropped` gap.
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
        ] {
            rig.video_frame(ms, index, index == 0, 16);
            settle().await;
        }
        assert_eq!(rig.report().await, started(0, None));
        rig.clips.stop("k1", EndReason::Stopped);
        let reports = rig.until_stopped().await;
        let bytes = reader.rest().await;
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 240, 0)]);
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
            assert_eq!(rig.report().await, started(0, None));
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
        assert_eq!(
            rig.report().await,
            ClipReport::Started {
                before_ms: 0,
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
        assert_eq!(rig.report().await, started(0, Some("aac_lc")));
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
        assert_eq!(rig.report().await, started(0, Some("aac_lc")));
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
        assert_eq!(rig.report().await, started(0, Some("aac_lc")));
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
    /// as well. The reader gets what `bytes` says.
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
        assert_eq!(reports, vec![stopped("stopped", bytes.len(), 300, 0)]);
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
            assert_eq!(rig.report().await, started(0, Some("aac_lc")));
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
    /// the last fragment still asked for; one whose finish fails keeps
    /// the clip's reason and says so.
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
        rig.clips.stop("k1", EndReason::Stopped);
        let_assert_reason(&rig.until_stopped().await, "stopped");
        assert_eq!(
            lines(&reader.rest().await),
            ["init video=h264", "frame v 0 0 k 32"]
        );
        assert_eq!(
            logs.count(Level::WARN, "clip: the container's last fragment failed"),
            1
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
        within(rig.clips.shutdown(&clock)).await;
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
            tokio::join!(rig.clips.shutdown(&clock), async {
                settle().await;
                fake.advance(SHUTDOWN_GRACE);
            })
        })
        .await;
        assert_eq!(rig.report().await, started(0, None));
        assert_eq!(lines(&reader.rest().await).last().unwrap(), "end");
        assert_eq!(
            logs.count(Level::WARN, "clip still finishing at shutdown; aborted"),
            1
        );
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
        let pps = h264::test_data::pps();
        let access_unit = |sps: &[u8]| {
            let mut unit = Vec::new();
            for nal in [sps, &pps[..], &[0x65, 0x88][..]] {
                unit.extend_from_slice(&[0, 0, 0, 1]);
                unit.extend_from_slice(nal);
            }
            unit
        };
        let codec = Codec::H264 {
            profile_level_id: None,
            sps: Some(new.clone().into()),
            pps: Some(pps.clone().into()),
        };
        for (second, before_ms) in [(access_unit(&new), 1_000), (access_unit(&old), 2_000)] {
            let mut rig = Rig::with(Some(codec.clone()), None, true, 16);
            for (ms, payload) in [(0, access_unit(&old)), (1_000, second)] {
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
}
