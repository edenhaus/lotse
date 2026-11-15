//! Live outputs: one task per output that writes the registered live
//! container into the pipe the supervisor passed, from the stream's cached
//! keyframe on, for a player that plays it as it comes (live fMP4 over
//! HTTP).
//!
//! An output waits for the source's tracks and for a video codec the
//! container carries (an H.264 track without its parameter sets yet waits
//! for them), up to the start timeout, then writes the container's init
//! segment and reports `Started` with the MIME type the container gives,
//! codecs included. The stream's audio goes in when asked and the
//! container carries its codec as it is; otherwise the output is video
//! alone, warned `audio_omitted`: no transcode, the client decides what its
//! player can play. The media waits for the supervisor's `FetchLive`, sent
//! when a reader takes the body, so a body fetched late does not start with
//! stale frames: the output then joins the video track at its cached GOP
//! ([`Track::subscribe_from_gop`], the subscription and the GOP taken
//! together, so no frame is lost or sent twice), hands every frame of the
//! GOP to the container at once and goes on with the live frames. The
//! first frame a player gets is so the GOP's keyframe, as old as the GOP
//! (at most the camera's keyframe interval, and what `limits.gop_cache_*`
//! keeps); the player plays the burst and jumps to the live edge. A GOP
//! the cache cut short (only its keyframe kept) is not sent: the frames after
//! it would miss their references, and the output starts at the next
//! keyframe instead.
//!
//! Back-pressure: the media path never waits for a reader. The bytes the
//! container completed go to the pipe as it takes them, without blocking,
//! and wait in the output's queue meanwhile. Once the queue holds more
//! than the output's bound (`buffer_bytes`, `limits.live_buffer_bytes`),
//! the next frame finds it full: the container finishes the frames it
//! holds ([`LiveMuxer::skip`]), and every frame is left out until the
//! queue has gone into the pipe; from there the container starts again
//! at the next video keyframe, where its video ended, so the player's
//! timeline has no hole. A frame the track's subscription lost (a lag, a
//! frame over `max_frame_bytes`) does the same without the wait. So an
//! output holds at most its bound, the container's frames finished at the
//! drop and the kernel's pipe buffer, whatever the reader does. Each drop
//! is counted, the frames left out too, and logged at warn, rate-limited.
//!
//! An output ends when its reader closes the pipe (`client_gone`), when the
//! supervisor stops it ([`lotse_ipc::STOPPED_AS_ASKED`]: `live/close`, its
//! control connection gone, its body not fetched in time), when the video
//! track closes (`stream_deleted`), when a codec changes in a way its init
//! segment cannot describe (`codec_changed`, [`LiveMuxer::continues`]), when
//! the subscription lost a control event, so the codec of what follows is
//! unknown (`stream_changed`), when no video track or no keyframe comes in
//! time (`no_video_track`, `source_not_live`), when the container fails
//! (`internal_error`) and when the worker stops (`shutting_down`). Its
//! `Closed` is its last report. A switch to another source goes on: the
//! container starts again at the new source's first keyframe, and a codec
//! change that comes with it ends the output as any other.
//!
//! Standards: the container is the registered one's (ISO/IEC 14496-12
//! fragmented MP4 for the daemon's); a write after the reader closed its
//! end fails with `EPIPE` (POSIX `write`, Linux `pipe(7)`), and the write
//! end polls `POLLERR` from then on (Linux `poll(2)`).

use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSlice};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_core::clock::Clock;
use lotse_core::codec::Kind;
use lotse_core::live::{LiveFragment, LiveMuxer, LiveMuxerFactory, LiveStep};
use lotse_core::media::MediaFrame;
use lotse_core::recording::RecordingTrack;
use lotse_core::source::TrackSet;
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use lotse_core::track::{Track, TrackEvent, TrackSubscription, Unit};
use lotse_ipc::fragments::{self, RecordKind};
use lotse_ipc::{LiveReport, LiveSpec};
use tokio::io::Interest;
use tokio::net::unix::pipe;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Default of `limits.live_start_timeout_ms`: how long an output waits for
/// the source's tracks and a video codec it can write, and after its fetch
/// for its first keyframe; the sessions' and recordings' bound.
pub const DEFAULT_LIVE_START_TIMEOUT: Duration = Duration::from_secs(10);

/// Default of `limits.max_live_per_stream`: the most live outputs one
/// stream, so one worker, runs at once: the bound of a supervisor that is
/// wrong, which keeps its own limits.
pub const DEFAULT_MAX_LIVE_PER_STREAM: usize = 8;

/// How long the worker's shutdown waits for its outputs to report.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

/// The most buffers one write hands the pipe, as a recording's.
const MAX_WRITE_SLICES: usize = 64;

/// What the worker's live outputs run under (`limits.live_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveSettings {
    /// How long an output waits for its tracks, a video codec it can write
    /// and, once fetched, its first keyframe.
    pub start_timeout: Duration,
    /// The most outputs the worker runs at once.
    pub max_outputs: usize,
}

impl Default for LiveSettings {
    fn default() -> Self {
        Self {
            start_timeout: DEFAULT_LIVE_START_TIMEOUT,
            max_outputs: DEFAULT_MAX_LIVE_PER_STREAM,
        }
    }
}

/// Why an output ended, by the name its `Closed` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveEnd {
    /// The supervisor's `StopLive`, for a reason of its own that it puts in
    /// place of this one.
    Stopped,
    /// The reader closed its end of the pipe.
    ClientGone,
    /// The video track closed: the stream is gone.
    StreamDeleted,
    /// A track's codec changed past what the init segment describes.
    CodecChanged,
    /// Control events were lost: the codec of what follows is unknown.
    StreamChanged,
    /// The connection's tracks have no video.
    NoVideoTrack,
    /// No tracks, no video codec the container carries, or no keyframe
    /// after the fetch, within the start timeout.
    SourceNotLive,
    /// The worker is stopping.
    ShuttingDown,
    /// The container failed.
    InternalError,
}

impl LiveEnd {
    /// The API's name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Stopped => lotse_ipc::STOPPED_AS_ASKED,
            Self::ClientGone => "client_gone",
            Self::StreamDeleted => "stream_deleted",
            Self::CodecChanged => "codec_changed",
            Self::StreamChanged => "stream_changed",
            Self::NoVideoTrack => "no_video_track",
            Self::SourceNotLive => "source_not_live",
            Self::ShuttingDown => "shutting_down",
            Self::InternalError => "internal_error",
        }
    }
}

/// What the worker asks of a running output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Asked {
    /// A reader took the body: the media may go.
    fetched: bool,
    /// The end asked for, the first given.
    end: Option<LiveEnd>,
}

/// What an output needs from the worker to run.
pub(crate) struct LiveStart {
    /// What the supervisor asked for.
    pub(crate) spec: LiveSpec,
    /// The write end of the pipe the bytes go to.
    pub(crate) pipe: pipe::Sender,
    /// The connection's native tracks.
    pub(crate) tracks: Arc<TrackSet>,
    /// The container.
    pub(crate) factory: Arc<dyn LiveMuxerFactory>,
    /// The limits.
    pub(crate) settings: LiveSettings,
    /// The injected clock.
    pub(crate) clock: Arc<dyn Clock>,
}

/// One running output's handles.
struct Handle {
    /// What the worker asks of it.
    asked: watch::Sender<Asked>,
    /// Its task.
    task: JoinHandle<()>,
}

/// The worker's running live outputs by id, and where their reports go.
/// An output stays here from its start until its `Closed` was passed on
/// ([`Self::ended`]).
pub(crate) struct Lives {
    /// The running outputs.
    running: HashMap<String, Handle>,
    /// Where every output reports.
    reports: mpsc::Sender<(String, LiveReport)>,
}

impl Lives {
    /// No outputs yet; each reports to `reports`.
    pub(crate) fn new(reports: mpsc::Sender<(String, LiveReport)>) -> Self {
        Self {
            running: HashMap::new(),
            reports,
        }
    }

    /// How many run.
    pub(crate) fn len(&self) -> usize {
        self.running.len()
    }

    /// Whether `live_id` runs.
    pub(crate) fn runs(&self, live_id: &str) -> bool {
        self.running.contains_key(live_id)
    }

    /// Starts `start`'s output.
    pub(crate) fn start(&mut self, start: LiveStart) {
        let (asked, requested) = watch::channel(Asked::default());
        let live_id = start.spec.live_id.clone();
        let task = spawn_named("live", run(start, requested, self.reports.clone()));
        self.running.insert(live_id, Handle { asked, task });
    }

    /// A reader took `live_id`'s body; whether it runs.
    pub(crate) fn fetch(&self, live_id: &str) -> bool {
        let Some(handle) = self.running.get(live_id) else {
            return false;
        };
        handle.asked.send_if_modified(|asked| {
            let first = !asked.fetched;
            asked.fetched = true;
            first
        });
        true
    }

    /// Asks `live_id` to end for `reason`, unless it ends already; whether
    /// it runs.
    pub(crate) fn stop(&self, live_id: &str, reason: LiveEnd) -> bool {
        let Some(handle) = self.running.get(live_id) else {
            return false;
        };
        ask_end(handle, reason);
        true
    }

    /// `live_id`'s `Closed` was passed on: it is over.
    pub(crate) fn ended(&mut self, live_id: &str) {
        self.running.remove(live_id);
    }

    /// The worker stops: every output ends `shutting_down` and gets
    /// [`SHUTDOWN_GRACE`] on `clock`, but no later than `by`, to report;
    /// one still running then is aborted, its pipe closed as its task
    /// drops.
    pub(crate) async fn shutdown(&mut self, clock: &Arc<dyn Clock>, by: Instant) {
        for handle in self.running.values() {
            ask_end(handle, LiveEnd::ShuttingDown);
        }
        let now = clock.now();
        let deadline = now.checked_add(SHUTDOWN_GRACE).unwrap_or(now).min(by);
        for (live_id, handle) in self.running.drain() {
            let mut task = handle.task;
            let left = deadline.saturating_duration_since(clock.now());
            tokio::select! {
                _ = &mut task => {}
                () = clock.sleep(left) => {
                    tracing::warn!(live.id = %live_id, "live output still ending at shutdown; aborted");
                    task.abort();
                }
            }
        }
    }

    /// The supervisor is gone: every output is aborted, its pipe closed as
    /// its task drops, since nobody hears its report.
    pub(crate) fn abort_all(&mut self) {
        for (_, handle) in self.running.drain() {
            handle.task.abort();
        }
    }
}

/// Asks the output behind `handle` to end for `reason`, unless a reason
/// was given before.
fn ask_end(handle: &Handle, reason: LiveEnd) {
    handle.asked.send_if_modified(|asked| {
        let first = asked.end.is_none();
        asked.end.get_or_insert(reason);
        first
    });
}

/// The end the worker asks for; `shutting_down` once it dropped the
/// output's handle.
async fn asked_end(asked: &mut watch::Receiver<Asked>) -> LiveEnd {
    asked
        .wait_for(|asked| asked.end.is_some())
        .await
        .ok()
        .and_then(|asked| asked.end)
        .unwrap_or(LiveEnd::ShuttingDown)
}

/// Resolves once the worker says a reader took the body, or asks the end:
/// whether it was the fetch.
async fn fetched(asked: &mut watch::Receiver<Asked>) -> bool {
    asked
        .wait_for(|asked| asked.fetched || asked.end.is_some())
        .await
        .is_ok_and(|asked| asked.end.is_none())
}

/// Resolves once the reader closed its end of `pipe` (`POLLERR`), or the
/// wait failed, after which no write would succeed either.
async fn hangup(pipe: &pipe::Sender) {
    let _ready = pipe.ready(Interest::ERROR).await;
}

/// The next event of an output's audio subscription; never without one.
async fn next_audio(audio: &mut Option<TrackSubscription>) -> Option<TrackEvent> {
    match audio {
        Some(subscription) => subscription.next().await,
        None => std::future::pending().await,
    }
}

/// One output, from its start to its `Closed`.
async fn run(
    start: LiveStart,
    mut asked: watch::Receiver<Asked>,
    reports: mpsc::Sender<(String, LiveReport)>,
) {
    let LiveStart {
        spec,
        pipe,
        tracks,
        factory,
        settings,
        clock,
    } = start;
    let started = clock.now();
    let mut output = Output {
        id: spec.live_id.clone(),
        muxer: factory.muxer(),
        pipe,
        framed: spec.framed,
        pending: VecDeque::new(),
        pending_bytes: 0,
        buffer_bytes: usize::try_from(spec.buffer_bytes).unwrap_or(usize::MAX),
        written: 0,
        drop: Dropping::No,
        drops: 0,
        dropped_frames: 0,
        drop_lines: Throttle::default(),
        begun: false,
        clock,
        reports,
    };
    tracing::debug!(live.id = %output.id, audio = spec.audio, buffer_bytes = spec.buffer_bytes, "live: waiting for the tracks");
    let deadline = started
        .checked_add(settings.start_timeout)
        .unwrap_or(started);
    let reason = match output
        .open(&tracks, factory.as_ref(), spec.audio, &mut asked, deadline)
        .await
    {
        Ok(media) => output.serve(media, &mut asked, settings).await,
        Err(reason) => reason,
    };
    output.finish(reason).await;
}

/// Where an output is in a drop to the next keyframe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dropping {
    /// Not dropping: every frame goes to the container.
    No,
    /// Every frame is left out until the queue went into the pipe.
    Draining,
    /// The container leaves frames out until the next keyframe; those count
    /// as dropped.
    ToKeyframe,
}

/// The tracks an output writes.
struct Media {
    /// The video track.
    video: Arc<Track>,
    /// The audio track, when the output has one.
    audio: Option<Arc<Track>>,
}

/// One output's container, pipe and counters.
struct Output {
    /// The output's id, for the logs and the reports.
    id: String,
    /// The container.
    muxer: Box<dyn LiveMuxer>,
    /// The write end of the pipe.
    pipe: pipe::Sender,
    /// Whether each record goes behind its header ([`lotse_ipc::fragments`]):
    /// an LL-HLS output, whose supervisor cuts parts and segments.
    framed: bool,
    /// The container's bytes the pipe has not taken yet, in order.
    pending: VecDeque<Bytes>,
    /// Their length.
    pending_bytes: usize,
    /// The most `pending_bytes` the output holds before it drops.
    buffer_bytes: usize,
    /// The bytes the pipe took.
    written: u64,
    /// Where the output is in a drop.
    drop: Dropping,
    /// How often the output dropped to the next keyframe.
    drops: u32,
    /// The frames left out by the drops.
    dropped_frames: u64,
    /// Rate-limits the drop warnings.
    drop_lines: Throttle,
    /// Whether the container wrote a fragment yet.
    begun: bool,
    /// The injected clock.
    clock: Arc<dyn Clock>,
    /// Where the output reports.
    reports: mpsc::Sender<(String, LiveReport)>,
}

impl Output {
    /// Waits for the tracks and a video codec the container carries, by
    /// `deadline`, then writes the init segment and reports `Started`.
    async fn open(
        &mut self,
        tracks: &TrackSet,
        factory: &dyn LiveMuxerFactory,
        audio: bool,
        asked: &mut watch::Receiver<Asked>,
        deadline: Instant,
    ) -> Result<Media, LiveEnd> {
        let mut ready = tracks.ready();
        while !*ready.borrow_and_update() {
            self.wait(
                ready.changed(),
                asked,
                deadline,
                "the source did not go live",
            )
            .await?;
        }
        let natives = tracks.tracks();
        let video = natives
            .iter()
            .find(|track| track.kind() == Kind::Video)
            .cloned()
            .ok_or_else(|| {
                tracing::info!(live.id = %self.id, "live: the stream has no video");
                LiveEnd::NoVideoTrack
            })?;
        // An H.264 or H.265 track learns its parameter sets from its
        // first keyframe: the codec changes then.
        let mut changes = video.subscribe(Unit::Frames);
        while !factory.accepts(&video.codec()) {
            let next = async {
                let _event = changes.next().await;
            };
            self.wait(
                next,
                asked,
                deadline,
                "no video codec the container carries",
            )
            .await?;
        }
        drop(changes);
        let video_entry = entry(&video);
        let mut audio_track = None;
        let mut omitted = None;
        if audio && let Some(track) = natives.iter().find(|track| track.kind() == Kind::Audio) {
            if factory.accepts(&track.codec()) {
                audio_track = Some(Arc::clone(track));
            } else {
                omitted = Some(track.codec().name().to_owned());
            }
        }
        let audio_entry = audio_track.as_ref().map(entry);
        let init = self
            .muxer
            .start(&video_entry, audio_entry.as_ref())
            .map_err(|err| {
                tracing::warn!(live.id = %self.id, error = %err, "live: the container refused the tracks");
                LiveEnd::InternalError
            })?;
        self.queue_record(RecordKind::Init, vec![init.bytes])?;
        self.write()?;
        tracing::info!(
            live.id = %self.id,
            mime = %init.mime,
            video = video_entry.codec.name(),
            audio = audio_entry.as_ref().map(|entry| entry.codec.name()),
            "live: started; the media waits for the fetch"
        );
        self.report(LiveReport::Started {
            mime: init.mime,
            video: video_entry.codec.name().to_owned(),
            audio: audio_entry.map(|entry| entry.codec.name().to_owned()),
        })
        .await;
        if let Some(codec) = omitted {
            tracing::warn!(live.id = %self.id, codec = %codec, "live: the container cannot carry the audio; video alone");
            self.report(LiveReport::Warning {
                code: "audio_omitted".to_owned(),
                message: format!(
                    "the live container cannot carry {codec}; the output has no audio"
                ),
            })
            .await;
        }
        Ok(Media {
            video,
            audio: audio_track,
        })
    }

    /// Waits for `event`, unless the output ends first: the worker's end,
    /// the reader gone, or `deadline` passed (`source_not_live`, logged
    /// with `why`).
    async fn wait(
        &self,
        event: impl Future<Output = impl Sized>,
        asked: &mut watch::Receiver<Asked>,
        deadline: Instant,
        why: &str,
    ) -> Result<(), LiveEnd> {
        let left = deadline.saturating_duration_since(self.clock.now());
        tokio::select! {
            _ = event => Ok(()),
            reason = asked_end(asked) => Err(reason),
            () = hangup(&self.pipe) => Err(self.gone()),
            () = self.clock.sleep(left) => {
                tracing::info!(live.id = %self.id, why, "live: not started in time");
                Err(LiveEnd::SourceNotLive)
            }
        }
    }

    /// Waits for the fetch, then joins the tracks and sends their frames
    /// until the output ends.
    async fn serve(
        &mut self,
        media: Media,
        asked: &mut watch::Receiver<Asked>,
        settings: LiveSettings,
    ) -> LiveEnd {
        if let Err(reason) = self.await_fetch(asked).await {
            return reason;
        }
        match self.join(&media) {
            Ok((video, audio)) => self.stream(video, audio, asked, settings).await,
            Err(reason) => reason,
        }
    }

    /// Writes the init segment as the pipe takes it until a reader took the
    /// body; the output's end before that.
    async fn await_fetch(&mut self, asked: &mut watch::Receiver<Asked>) -> Result<(), LiveEnd> {
        loop {
            // A new pipe is writable once the runtime polled it, not before.
            self.write()?;
            tokio::select! {
                biased;
                fetch = fetched(asked) => {
                    return if fetch { Ok(()) } else { Err(asked_end(asked).await) };
                }
                _ = self.pipe.writable(), if !self.pending.is_empty() => {}
                () = hangup(&self.pipe) => return Err(self.gone()),
            }
        }
    }

    /// Joins the tracks: the video's subscription and its GOP together, the
    /// GOP handed to the container, and the audio's subscription; a codec
    /// that changed past the init segment since the start ends the output.
    fn join(
        &mut self,
        media: &Media,
    ) -> Result<(TrackSubscription, Option<TrackSubscription>), LiveEnd> {
        let (video, gop, codec, clock_rate) = media.video.subscribe_from_gop();
        let audio = media
            .audio
            .as_ref()
            .map(|track| track.subscribe(Unit::Frames));
        let entries = [
            Some((
                Kind::Video,
                RecordingTrack {
                    codec: (*codec).clone(),
                    clock_rate,
                },
            )),
            media
                .audio
                .as_ref()
                .map(|track| (Kind::Audio, entry(track))),
        ];
        for (kind, entry) in entries.iter().flatten() {
            if !self.muxer.continues(*kind, entry) {
                tracing::info!(live.id = %self.id, track = %kind, "live: the codec changed before the fetch");
                return Err(LiveEnd::CodecChanged);
            }
        }
        match gop {
            Some(gop) if !gop.truncated() => {
                tracing::info!(
                    live.id = %self.id,
                    frames = gop.frame_count(),
                    bytes = gop.bytes(),
                    age_ms = gop.age(self.clock.now()).as_millis(),
                    "live: fetched; joining at the cached keyframe"
                );
                for frame in gop.frames() {
                    self.offer(Kind::Video, Arc::clone(frame), false)?;
                }
            }
            gop => tracing::info!(
                live.id = %self.id,
                truncated = gop.is_some(),
                "live: fetched; no whole GOP cached, joining at the next keyframe"
            ),
        }
        Ok((video, audio))
    }

    /// Sends the subscriptions' frames until the output ends.
    async fn stream(
        &mut self,
        mut video: TrackSubscription,
        mut audio: Option<TrackSubscription>,
        asked: &mut watch::Receiver<Asked>,
        settings: LiveSettings,
    ) -> LiveEnd {
        let now = self.clock.now();
        let deadline = now.checked_add(settings.start_timeout).unwrap_or(now);
        loop {
            if let Err(reason) = self.write() {
                return reason;
            }
            let left = deadline.saturating_duration_since(self.clock.now());
            let step = tokio::select! {
                biased;
                reason = asked_end(asked) => Err(reason),
                event = video.next() => if let Some(event) = event {
                    self.event(Kind::Video, event)
                } else {
                    tracing::info!(live.id = %self.id, "live: the video track closed");
                    Err(LiveEnd::StreamDeleted)
                },
                event = next_audio(&mut audio) => if let Some(event) = event {
                    self.event(Kind::Audio, event)
                } else {
                    tracing::info!(live.id = %self.id, "live: the audio track closed; video alone from here");
                    audio = None;
                    Ok(())
                },
                // A spurious readiness comes back as `WouldBlock`.
                _ = self.pipe.writable(), if !self.pending.is_empty() => Ok(()),
                // With nothing pending no write would tell.
                () = hangup(&self.pipe) => Err(self.gone()),
                () = self.clock.sleep(left), if !self.begun => {
                    tracing::info!(live.id = %self.id, "live: no keyframe after the fetch in time");
                    Err(LiveEnd::SourceNotLive)
                }
            };
            if let Err(reason) = step {
                return reason;
            }
        }
    }

    /// One event of the `kind` track's subscription.
    fn event(&mut self, kind: Kind, event: TrackEvent) -> Result<(), LiveEnd> {
        match event {
            TrackEvent::Frame(frame) => self.offer(kind, frame, true),
            TrackEvent::Gap { skipped } => {
                // The subscription missed frames: the next keyframe again.
                self.drop_to_keyframe(skipped, "the subscription lagged")
            }
            TrackEvent::TrackChanged { codec, clock_rate } => {
                let entry = RecordingTrack {
                    codec: (*codec).clone(),
                    clock_rate,
                };
                if self.muxer.continues(kind, &entry) {
                    tracing::debug!(live.id = %self.id, track = %kind, codec = codec.name(), "live: the codec changed within what the init segment describes; going on");
                    Ok(())
                } else {
                    tracing::info!(live.id = %self.id, track = %kind, codec = codec.name(), "live: the codec changed past the init segment; ending");
                    Err(LiveEnd::CodecChanged)
                }
            }
            TrackEvent::ControlLost { skipped } => {
                tracing::info!(live.id = %self.id, track = %kind, skipped, "live: control events lost, the codec is unknown; ending");
                Err(LiveEnd::StreamChanged)
            }
            // The frames carry their epochs, a switch's starting at its
            // source's first keyframe, and a lost source shows as frames
            // that stop coming.
            TrackEvent::SourceSwitched
            | TrackEvent::EpochStart { .. }
            | TrackEvent::SourceLost
            | TrackEvent::SourceRestored
            | TrackEvent::Packet(_) => Ok(()),
        }
    }

    /// Hands `frame` of `kind` to the container, unless the queue is full
    /// (`live`: a live frame; the GOP's burst at the join is not held to
    /// the bound) or the output drops until it went into the pipe.
    fn offer(&mut self, kind: Kind, frame: Arc<MediaFrame>, live: bool) -> Result<(), LiveEnd> {
        if self.drop == Dropping::Draining {
            if !self.pending.is_empty() {
                self.dropped_frames = self.dropped_frames.saturating_add(1);
                return Ok(());
            }
            self.drop = Dropping::ToKeyframe;
            tracing::debug!(live.id = %self.id, "live: the reader caught up; going on at the next keyframe");
        }
        if live && self.pending_bytes > self.buffer_bytes {
            self.drop_to_keyframe(1, "the reader fell behind")?;
            self.drop = Dropping::Draining;
            return Ok(());
        }
        match self.muxer.push(kind, frame) {
            Ok(LiveStep::Fragment(fragment)) => {
                if fragment.independent {
                    self.drop = Dropping::No;
                }
                self.begun = true;
                self.queue_fragment(fragment)
            }
            Ok(LiveStep::Dropped) => {
                if self.drop != Dropping::No {
                    self.dropped_frames = self.dropped_frames.saturating_add(1);
                }
                Ok(())
            }
            Ok(LiveStep::Held) => Ok(()),
            Err(err) => Err(self.failed(&err)),
        }
    }

    /// Drops to the next keyframe for `why`, `skipped` frames lost already:
    /// the container finishes the frames it holds and leaves out the rest
    /// until then.
    fn drop_to_keyframe(&mut self, skipped: u64, why: &'static str) -> Result<(), LiveEnd> {
        let finished = self.muxer.skip().map_err(|err| self.failed(&err))?;
        if let Some(fragment) = finished {
            self.queue_fragment(fragment)?;
        }
        self.drop = Dropping::ToKeyframe;
        self.drops = self.drops.saturating_add(1);
        self.dropped_frames = self.dropped_frames.saturating_add(skipped);
        if let Some(count) = self.drop_lines.hit(self.clock.now()) {
            tracing::warn!(
                live.id = %self.id,
                why,
                queued = self.pending_bytes,
                limit = self.buffer_bytes,
                drops = self.drops,
                dropped_frames = self.dropped_frames,
                count,
                "live: dropping to the next keyframe"
            );
        }
        Ok(())
    }

    /// The container failed: logged, the output ends.
    fn failed(&self, err: &dyn std::error::Error) -> LiveEnd {
        tracing::warn!(live.id = %self.id, error = %err, "live: the container failed");
        LiveEnd::InternalError
    }

    /// The reader is gone: logged, the output ends.
    fn gone(&self) -> LiveEnd {
        tracing::info!(live.id = %self.id, "live: the reader is gone");
        LiveEnd::ClientGone
    }

    /// Queues `fragment`'s bytes for the pipe, behind its record header in a
    /// framed output, its duration held to the longest a header says (a
    /// minute: a camera whose timestamps jumped).
    fn queue_fragment(&mut self, fragment: LiveFragment) -> Result<(), LiveEnd> {
        let longest = Duration::from_micros(u64::from(fragments::MAX_DURATION_US));
        let kind = RecordKind::Fragment {
            independent: fragment.independent,
            duration: fragment.duration.min(longest),
        };
        self.queue_record(kind, fragment.bytes)
    }

    /// Queues `bytes` for the pipe, in a framed output behind the header of
    /// a record of `kind` ([`lotse_ipc::fragments`]); one the header cannot
    /// describe (over its bounds, far above any frame) ends the output.
    fn queue_record(&mut self, kind: RecordKind, bytes: Vec<Bytes>) -> Result<(), LiveEnd> {
        if self.framed {
            let len = bytes
                .iter()
                .map(Bytes::len)
                .fold(0_usize, usize::saturating_add);
            let Some(header) = fragments::header(kind, len) else {
                tracing::warn!(live.id = %self.id, len, "live: a record over the framing's bounds");
                return Err(LiveEnd::InternalError);
            };
            self.queue(vec![Bytes::copy_from_slice(&header)]);
        }
        self.queue(bytes);
        Ok(())
    }

    /// Queues the container's `bytes` for the pipe, in order; an empty
    /// slice is left out, as the pipe would take nothing of it.
    fn queue(&mut self, bytes: Vec<Bytes>) {
        for piece in bytes.into_iter().filter(|piece| !piece.is_empty()) {
            self.pending_bytes = self.pending_bytes.saturating_add(piece.len());
            self.pending.push_back(piece);
        }
    }

    /// Hands the pipe what it takes now of the pending bytes; the reader's
    /// end closed is `client_gone`.
    fn write(&mut self) -> Result<(), LiveEnd> {
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
                    tracing::debug!(live.id = %self.id, error = %err, "live: the write failed");
                    return Err(self.gone());
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
        self.pending_bytes = self.pending_bytes.saturating_sub(written);
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

    /// Sends `report`; a worker that stopped taking reports is gone, and
    /// nobody waits.
    async fn report(&self, report: LiveReport) {
        let _sent = self.reports.send((self.id.clone(), report)).await;
    }

    /// Ends the output for `reason`: what the pipe takes at once of the
    /// pending bytes goes, the pipe closes, and `Closed` is the last
    /// report.
    async fn finish(mut self, reason: LiveEnd) {
        if reason != LiveEnd::ClientGone {
            // The rest is left out: a live body has no end to reach.
            let _taken = self.write();
        }
        let Self {
            id,
            pipe,
            reports,
            written,
            drops,
            dropped_frames,
            ..
        } = self;
        drop(pipe);
        tracing::info!(
            live.id = %id,
            reason = reason.name(),
            bytes = written,
            drops,
            dropped_frames,
            "live: closed"
        );
        let closed = LiveReport::Closed {
            reason: reason.name().to_owned(),
            bytes: written,
            dropped_frames,
            drops,
        };
        // As in `report`.
        let _sent = reports.send((id, closed)).await;
    }
}

/// `track`'s codec and clock rate as a sample entry declares them.
fn entry(track: &Arc<Track>) -> RecordingTrack {
    RecordingTrack {
        codec: (*track.codec()).clone(),
        clock_rate: track.clock_rate(),
    }
}

#[cfg(test)]
mod tests;
