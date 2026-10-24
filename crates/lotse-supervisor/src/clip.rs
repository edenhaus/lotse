//! Event clips as the supervisor keeps them: which stream and source
//! connection each records on, which control connection's subscription
//! gets its events, the read end of the pipe its worker writes the file
//! into until `GET /v0/clips/{clip_id}` takes it, the per-stream
//! counters, and the mapping of a worker's clip reports onto the API's
//! events (`lotse_api_types::clip`).
//!
//! The worker records the clip; the supervisor owns its signaling and its
//! body, and never sees a byte of it: the file goes from the worker's
//! write end to the body through the kernel. A clip is demand on its
//! connection, as a viewer is, from `clip/start` until it ends.
//!
//! A worker's report is untrusted, as its session reports are: it is
//! accepted only for a clip of that worker's own connection, every name is
//! mapped onto a known one, every number is bounded, and a warning's
//! message is made [`plain`] and capped at [`MAX_MESSAGE_BYTES`]. A report
//! that breaks the contract is dropped, logged, and ends its clip
//! `internal_error`, the worker told to stop it; a repeated or unknown
//! warning is only dropped.
//!
//! A clip ends with the worker's `Stopped` report, whose `bytes` go to the
//! body, which ends whole only when they match what it read. When the
//! supervisor ends a clip itself (`clip/stop`, `unsubscribe`, `not_fetched`,
//! its control connection closing) it asks the worker through a slot
//! reserved in the driver's queue at `clip/start` and waits for that
//! report, putting its own reason in place of the worker's `stopped`. When
//! the worker cannot report any more (it exited, the stream was deleted or
//! moved to another connection, shutdown, a malformed report), the clip
//! ends at once without it: `stopped` then says 0 bytes and 0 ms, since
//! only the worker knew them, and the body is cut.
//!
//! A clip that ends before its body was fetched keeps the body until the
//! fetch deadline (`limits.clip_fetch_timeout_ms` from the `clip/start`
//! result), so a short clip is not lost to a `GET` that comes a moment
//! late.

use std::time::{Duration, SystemTime};

use lotse_api::{ClipBody, ClipBodyError, ConnectionId, Event, EventClass};
use lotse_api_types::clip::{
    ClipAudio, ClipEvent, ClipGapReason, ClipStopReason, ClipVideo, ClipWarningCode,
};
use lotse_api_types::time::rfc3339;
use lotse_core::codec::CodecFamily;
use lotse_core::text::plain;
use lotse_ipc::{ClipReport, ClipSpec};
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::driver::DriverCommand;
use crate::registry::State;
use crate::worker_text::{MAX_MESSAGE_BYTES, MAX_NAME_BYTES};

/// Gap events a clip passes on: its worker reports at most this many and
/// counts the rest only in `stopped.gaps`, so one that reports more breaks
/// the contract.
pub(crate) const MAX_GAP_EVENTS: u32 = 256;

/// Events a clip's subscription holds: `started`, its one warning,
/// [`MAX_GAP_EVENTS`] gaps and `stopped`. That is every event a clip can
/// have, so its own events never fill it, and none is dropped while the
/// client reads.
pub(crate) const CLIP_QUEUE: usize = 259;

/// What a worker's report may name past the window and the clip's longest
/// run, in milliseconds of media time: a minute, since the ring holds the
/// GOP it cannot trim beyond the window, and a clip's end waits for the
/// first frame after it.
const REPORT_SLACK_MS: u32 = 60_000;

/// The largest picture side `started` passes on: `tkhd`'s width and height
/// are 16.16 fixed-point numbers (ISO/IEC 14496-12 §8.3.2.3), so a clip's
/// file cannot describe a larger picture.
const MAX_PICTURE_SIDE: u32 = 65_535;

/// The video codecs a clip's file carries.
const CLIP_VIDEO: [CodecFamily; 2] = [CodecFamily::H264, CodecFamily::H265];

/// The audio codecs a clip's file carries.
const CLIP_AUDIO: [CodecFamily; 2] = [CodecFamily::AacLc, CodecFamily::Opus];

/// The stop reasons only the supervisor gives: a worker naming one breaks
/// the contract.
const SUPERVISOR_REASONS: [ClipStopReason; 3] = [
    ClipStopReason::WorkerCrashed,
    ClipStopReason::NotFetched,
    ClipStopReason::SessionClosed,
];

/// The limits on clips and the pre-roll window, `limits.preroll_*` and
/// `limits.clip_*` as the binary resolves them ([`Limits::clips`]). A
/// supervisor with a clip output keeps them; one without keeps
/// [`ClipLimits::NONE`], and its workers refuse every clip. The worker's
/// share (`preroll_bytes`, `clip_max_ms`, `clip_queue_bytes`, `start_timeout`,
/// `max_clips`) reaches each worker as its flags, so both processes hold the
/// same bounds.
///
/// [`Limits::clips`]: crate::Limits::clips
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipLimits {
    /// `limits.preroll_max_ms`: the longest window `stream/put` may ask
    /// for, and the furthest back a clip's `before_ms` may ask.
    pub preroll_max_ms: u32,
    /// `limits.preroll_bytes`: what one track's ring may hold; the
    /// worker's bound, which `info` reports.
    pub preroll_bytes: u64,
    /// `limits.clip_max_ms`: the most `after_ms` may ask, and the worker's
    /// end of an open-ended clip.
    pub clip_max_ms: u32,
    /// `limits.clip_queue_bytes`: what one clip's queue in the worker holds
    /// before it drops to the next keyframe and reports the gap.
    pub clip_queue_bytes: u64,
    /// `limits.clip_fetch_timeout_ms`: how long a clip's body waits for
    /// its `GET` from the `clip/start` result on.
    pub fetch_timeout: Duration,
    /// `limits.clip_start_timeout_ms`: how long a clip in the worker waits
    /// for the tracks and a keyframe to start at.
    pub start_timeout: Duration,
    /// `limits.max_clips`: clips open at once over every stream, and in one
    /// worker.
    pub max_clips: u32,
    /// `limits.clips_per_stream`: clips open at once on one stream.
    pub clips_per_stream: u32,
}

impl ClipLimits {
    /// The defaults: a 2-minute window at most, 32 MiB per track (core's
    /// `DEFAULT_PREROLL_BYTES`), 10-minute clips (the worker's
    /// `DEFAULT_CLIP_MAX`), an 8 MiB queue (core's
    /// `DEFAULT_CLIP_QUEUE_BYTES`), 10 s to fetch, 10 s to start (the
    /// worker's `DEFAULT_CLIP_START_TIMEOUT`), 8 clips, 2 per stream.
    pub const DEFAULT: Self = Self {
        preroll_max_ms: 120_000,
        preroll_bytes: 32 * 1024 * 1024,
        clip_max_ms: 600_000,
        clip_queue_bytes: 8 * 1024 * 1024,
        fetch_timeout: Duration::from_secs(10),
        start_timeout: Duration::from_secs(10),
        max_clips: 8,
        clips_per_stream: 2,
    };

    /// No window and no clip: a supervisor without a clip output, whose
    /// workers refuse every clip, says so with these zeros.
    pub const NONE: Self = Self {
        preroll_max_ms: 0,
        preroll_bytes: 0,
        clip_max_ms: 0,
        clip_queue_bytes: 0,
        fetch_timeout: Self::DEFAULT.fetch_timeout,
        start_timeout: Self::DEFAULT.start_timeout,
        max_clips: 0,
        clips_per_stream: 0,
    };

    /// The most media time, in milliseconds, a worker's report may name:
    /// the longest window, the longest clip and [`REPORT_SLACK_MS`].
    const fn span_ms(self) -> u32 {
        self.preroll_max_ms
            .saturating_add(self.clip_max_ms)
            .saturating_add(REPORT_SLACK_MS)
    }
}

/// [`ClipLimits::NONE`]: what a supervisor holds until it knows it has a
/// clip output.
impl Default for ClipLimits {
    fn default() -> Self {
        Self::NONE
    }
}

/// A stream's clip counters, as `stream/get` and `metrics/get` report them;
/// kept over a `stream/put` that changes the stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClipCounters {
    /// Clips `clip/start` handed to the stream's connection.
    pub(crate) started: u64,
    /// Clips that ended with their whole file written: `completed`,
    /// `stopped` or `max_duration`.
    pub(crate) completed: u64,
    /// Gaps in the stream's clips, every one the workers counted, added
    /// as each clip ends.
    pub(crate) gaps: u64,
    /// Bytes of clip files the workers wrote to their bodies.
    pub(crate) bytes: u64,
}

/// A one-shot timer of a clip (its fetch deadline), aborted when dropped:
/// no timer task outlives what it was for.
#[derive(Debug)]
pub(crate) struct ClipTimer(pub(crate) AbortHandle);

impl Drop for ClipTimer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The control connection's subscription that gets a clip's events.
#[derive(Debug)]
pub(crate) struct ClipOwner {
    /// The control connection.
    pub(crate) connection: ConnectionId,
    /// The subscription: the id of its `clip/start`.
    pub(crate) subscription: u64,
    /// Where the events go; dropping it ends the subscription.
    pub(crate) events: mpsc::Sender<Event>,
}

/// How a clip ends ([`State::end_clip`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClipEnd {
    /// Its worker reported the end, with this reason (already the API's,
    /// the supervisor's own put in for `stopped`) and these figures.
    Reported {
        /// Why.
        reason: ClipStopReason,
        /// The bytes written to the pipe.
        bytes: u64,
        /// The media time the file covers.
        duration_ms: u32,
        /// The gaps the worker counted.
        gaps: u32,
    },
    /// The supervisor ends it without its worker's report, which will not
    /// come or not be believed.
    Now(ClipStopReason),
}

/// One clip that runs.
#[derive(Debug)]
pub(crate) struct ClipEntry {
    /// Unique over the daemon's lifetime, so its timer never acts on a
    /// later clip that reuses the id.
    pub(crate) serial: u64,
    /// The stream it records.
    pub(crate) stream_id: String,
    /// The source connection whose worker records it.
    pub(crate) connection: String,
    /// What was asked of the worker.
    spec: ClipSpec,
    /// The subscription, until the control connection closes or
    /// unsubscribes.
    owner: Option<ClipOwner>,
    /// The body, until its `GET` takes it.
    body: Option<ClipBody>,
    /// Where the worker's `bytes` go, which the body checks what it read
    /// against; dropped without them when the worker cannot report.
    written: Option<oneshot::Sender<u64>>,
    /// The slot reserved in the driver's queue for the clip's stop at
    /// `clip/start`: a full queue never keeps a stop from the worker.
    pub(crate) stop_slot: Option<OwnedPermit<DriverCommand>>,
    /// The supervisor asked the worker to stop the clip, for this reason,
    /// which its `stopped` then carries.
    ending: Option<ClipStopReason>,
    /// The fetch deadline passed: a body not taken by then is not kept.
    expired: bool,
    /// The worker reported `started`.
    started: bool,
    /// The worker's `audio_omitted` went out.
    warned: bool,
    /// Warnings dropped, repeated or unknown; only the first is logged.
    warnings_dropped: u32,
    /// Gap events passed on.
    gaps: u32,
    /// The fetch deadline.
    pub(crate) timer: Option<ClipTimer>,
}

/// The body of a clip that ended before it was fetched, kept for its
/// `GET` until the fetch deadline.
#[derive(Debug)]
pub(crate) struct FinishedClip {
    /// The clip's serial, which its timer names.
    serial: u64,
    /// The body.
    body: ClipBody,
    /// The fetch deadline, which drops it.
    _timer: Option<ClipTimer>,
}

impl ClipEntry {
    /// A clip of `stream_id` on `connection`, asked as `spec`, whose events
    /// go to `owner` and whose bytes are `body`, the worker's figure going
    /// to `written`.
    pub(crate) fn new(
        serial: u64,
        (stream_id, connection): (String, String),
        spec: ClipSpec,
        owner: ClipOwner,
        (body, written): (ClipBody, oneshot::Sender<u64>),
    ) -> Self {
        Self {
            serial,
            stream_id,
            connection,
            spec,
            owner: Some(owner),
            body: Some(body),
            written: Some(written),
            stop_slot: None,
            ending: None,
            expired: false,
            started: false,
            warned: false,
            warnings_dropped: 0,
            gaps: 0,
            timer: None,
        }
    }

    /// Whether `connection`'s subscription `subscription` gets its events.
    fn owned_by(&self, connection: ConnectionId, subscription: u64) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|o| o.connection == connection && o.subscription == subscription)
    }

    /// Hands an event to the owner, if there still is one. The queue holds
    /// every event a clip can have ([`CLIP_QUEUE`]), so only a forwarder
    /// that is gone loses one.
    fn deliver(&self, clip_id: &str, event: &ClipEvent) {
        if let Some(owner) = &self.owner
            && owner.events.try_send(clip_event(event)).is_err()
        {
            tracing::debug!(clip.id = clip_id, "clip subscription gone; event dropped");
        }
    }

    /// Tells the worker to stop the clip, through the slot reserved for
    /// it; a second call has no slot left and sends nothing.
    fn ask_stop(&mut self, clip_id: &str) {
        if let Some(slot) = self.stop_slot.take() {
            drop(slot.send(DriverCommand::StopClip {
                clip_id: clip_id.to_owned(),
            }));
        }
    }

    /// Checks a report against the clip and `limits`, `at` the wall time
    /// it came, and logs what it is: an event to pass on, the clip's end,
    /// nothing (a warning dropped), or the reason it breaks the contract.
    fn apply(
        &mut self,
        clip_id: &str,
        report: ClipReport,
        limits: ClipLimits,
        at: SystemTime,
    ) -> Result<Applied, &'static str> {
        match report {
            ClipReport::Started {
                before_ms,
                video,
                picture,
                audio,
            } => self.started_event(
                clip_id,
                (before_ms, &video, picture, audio.as_deref()),
                limits,
                at,
            ),
            ClipReport::Warning { code, message } => Ok(self.warning(clip_id, &code, &message)),
            ClipReport::Gap {
                reason,
                from_ms,
                to_ms,
            } => self.gap(clip_id, &reason, (from_ms, to_ms), limits),
            ClipReport::Stopped {
                reason,
                bytes,
                duration_ms,
                gaps,
            } => self
                .stopped(clip_id, (&reason, bytes, duration_ms, gaps), limits)
                .map(Applied::End),
        }
    }

    /// `started`, once, with a video codec a clip carries, audio only when
    /// asked for and one a clip carries, and numbers it can have; the
    /// supervisor stamps `at`.
    fn started_event(
        &mut self,
        clip_id: &str,
        (before_ms, video, picture, audio): (u32, &str, Option<(u32, u32)>, Option<&str>),
        limits: ClipLimits,
        at: SystemTime,
    ) -> Result<Applied, &'static str> {
        if self.started {
            return Err("a second started");
        }
        if before_ms > limits.span_ms() {
            return Err("started before_ms out of bounds");
        }
        let video = known(&CLIP_VIDEO, video).ok_or("started names an unknown video codec")?;
        let audio = match audio {
            Some(_) if !self.spec.audio => return Err("started has audio not asked for"),
            Some(name) => {
                Some(known(&CLIP_AUDIO, name).ok_or("started names an unknown audio codec")?)
            }
            None => None,
        };
        let side = 1..=MAX_PICTURE_SIDE;
        if picture.is_some_and(|(w, h)| !side.contains(&w) || !side.contains(&h)) {
            return Err("started picture out of bounds");
        }
        self.started = true;
        tracing::info!(
            event = "clip_started",
            clip.id = clip_id,
            stream.id = %self.stream_id,
            before_ms_asked = self.spec.before_ms,
            before_ms,
            video,
            audio,
            "clip: started"
        );
        Ok(Applied::Event(ClipEvent::Started {
            clip_id: clip_id.to_owned(),
            at: rfc3339(at),
            before_ms,
            video: ClipVideo {
                codec: video.to_owned(),
                width: picture.map(|(w, _)| w),
                height: picture.map(|(_, h)| h),
            },
            audio: audio.map(|codec| ClipAudio {
                codec: codec.to_owned(),
            }),
        }))
    }

    /// A warning: a known code once, its message made [`plain`]; a
    /// repeated or unknown one is dropped, only the first logged.
    fn warning(&mut self, clip_id: &str, code: &str, message: &str) -> Applied {
        let fresh = ClipWarningCode::parse(code).filter(|_| !self.warned);
        let Some(code) = fresh else {
            if self.warnings_dropped == 0 {
                tracing::warn!(
                    clip.id = clip_id,
                    code = ?plain(code, MAX_NAME_BYTES),
                    "a worker repeated a clip warning or named an unknown one; dropped, and later ones without a log"
                );
            }
            self.warnings_dropped = self.warnings_dropped.saturating_add(1);
            return Applied::Nothing;
        };
        self.warned = true;
        let message = plain(message, MAX_MESSAGE_BYTES);
        // The worker's text under `detail`, Debug-escaped.
        tracing::info!(
            event = "clip_warning",
            clip.id = clip_id,
            stream.id = %self.stream_id,
            code = code.as_str(),
            detail = ?message,
            "clip warning"
        );
        Applied::Event(ClipEvent::Warning { code, message })
    }

    /// A gap with a known reason, inside the span a clip can have, up to
    /// [`MAX_GAP_EVENTS`].
    fn gap(
        &mut self,
        clip_id: &str,
        reason: &str,
        (from_ms, to_ms): (u32, u32),
        limits: ClipLimits,
    ) -> Result<Applied, &'static str> {
        let reason = ClipGapReason::parse(reason).ok_or("gap names an unknown reason")?;
        if from_ms > to_ms || to_ms > limits.span_ms() {
            return Err("gap out of bounds");
        }
        if self.gaps >= MAX_GAP_EVENTS {
            return Err("more gaps than a clip reports");
        }
        self.gaps = self.gaps.saturating_add(1);
        // The worker logs each gap at warn, rate-limited.
        tracing::debug!(
            clip.id = clip_id,
            stream.id = %self.stream_id,
            reason = reason.as_str(),
            from_ms,
            to_ms,
            "clip gap passed on"
        );
        Ok(Applied::Event(ClipEvent::Gap {
            reason,
            from_ms,
            to_ms,
        }))
    }

    /// The end a worker's `Stopped` report makes: its reason mapped onto
    /// the API's (one it does not know, or one only the supervisor gives,
    /// is `internal_error`, logged), the supervisor's own for `stopped`
    /// when it asked; or the reason the figures break the contract.
    fn stopped(
        &self,
        clip_id: &str,
        (reason, bytes, duration_ms, gaps): (&str, u64, u32, u32),
        limits: ClipLimits,
    ) -> Result<ClipEnd, &'static str> {
        if duration_ms > limits.span_ms() {
            return Err("stopped duration out of bounds");
        }
        if gaps < self.gaps {
            return Err("stopped counts fewer gaps than were reported");
        }
        let parsed = ClipStopReason::parse(reason).filter(|r| !SUPERVISOR_REASONS.contains(r));
        let reason = match (parsed, self.ending) {
            (Some(ClipStopReason::Stopped), Some(ending)) => ending,
            (Some(reason), _) => reason,
            (None, _) => {
                tracing::warn!(
                    clip.id = clip_id,
                    reason = ?plain(reason, MAX_NAME_BYTES),
                    "a worker ended a clip with a reason it may not give; internal_error"
                );
                ClipStopReason::InternalError
            }
        };
        Ok(ClipEnd::Reported {
            reason,
            bytes,
            duration_ms,
            gaps,
        })
    }
}

/// What a worker's report comes to.
#[derive(Debug)]
enum Applied {
    /// An event for the owner.
    Event(ClipEvent),
    /// The clip's end.
    End(ClipEnd),
    /// Nothing: a warning dropped.
    Nothing,
}

/// `name` as the API name of one of `codecs`.
fn known(codecs: &[CodecFamily], name: &str) -> Option<&'static str> {
    codecs
        .iter()
        .map(|codec| codec.name())
        .find(|known| *known == name)
}

/// A clip event as the server queues it: signaling, never shed, a handful
/// per clip.
pub(crate) fn clip_event(event: &ClipEvent) -> Event {
    Event {
        class: EventClass::Signaling,
        payload: serde_json::to_value(event).unwrap_or_default(),
    }
}

/// Whether a clip that ended for `reason` wrote its whole file.
const fn completed(reason: ClipStopReason) -> bool {
    matches!(
        reason,
        ClipStopReason::Completed | ClipStopReason::Stopped | ClipStopReason::MaxDuration
    )
}

impl State {
    /// A worker's report about one of its clips, at `at` on the wall clock.
    /// One about a clip the supervisor does not hold is dropped (its
    /// subscription and body are gone; a pipe nobody reads ends the
    /// worker's clip `client_gone`), one about a clip of another
    /// connection is refused, and one that breaks the contract ends the
    /// clip `internal_error`.
    pub(crate) fn clip_report(
        &mut self,
        connection: &str,
        clip_id: &str,
        report: ClipReport,
        at: SystemTime,
    ) {
        let limits = self.clip_limits;
        let Some(entry) = self.clips.get_mut(clip_id) else {
            tracing::debug!(
                clip.id = %plain(clip_id, MAX_NAME_BYTES),
                connection.id = connection,
                "report for a clip the supervisor does not hold; dropped"
            );
            return;
        };
        if entry.connection != connection {
            tracing::warn!(
                clip.id = clip_id,
                connection.id = connection,
                "a worker reported a clip it does not run; ignored"
            );
            return;
        }
        match entry.apply(clip_id, report, limits, at) {
            Ok(Applied::Event(event)) => entry.deliver(clip_id, &event),
            Ok(Applied::End(end)) => self.end_clip(clip_id, end),
            Ok(Applied::Nothing) => {}
            Err(reason) => {
                tracing::warn!(
                    clip.id = clip_id,
                    connection.id = connection,
                    reason,
                    "a worker reported a malformed clip report; clip ended"
                );
                self.end_clip(clip_id, ClipEnd::Now(ClipStopReason::InternalError));
            }
        }
    }

    /// Asks the worker to stop clip `clip_id` cleanly for `reason`, which
    /// its `stopped` then carries; the clip stays until that report.
    /// Idempotent: an unknown clip, or one already being stopped, changes
    /// nothing.
    pub(crate) fn stop_clip(&mut self, clip_id: &str, reason: ClipStopReason) {
        let Some(entry) = self.clips.get_mut(clip_id) else {
            tracing::debug!(
                clip.id = clip_id,
                reason = reason.as_str(),
                "stop of a clip that is not open; nothing to do"
            );
            return;
        };
        if let Some(ending) = entry.ending {
            tracing::debug!(
                clip.id = clip_id,
                reason = reason.as_str(),
                ending = ending.as_str(),
                "clip already being stopped"
            );
            return;
        }
        entry.ending = Some(reason);
        entry.ask_stop(clip_id);
        tracing::info!(
            event = "clip_stopping",
            clip.id = clip_id,
            stream.id = %entry.stream_id,
            reason = reason.as_str(),
            "clip stop asked of its worker"
        );
    }

    /// Ends clip `clip_id` as `end` says: it leaves the registry and its
    /// connection's demand, its stream counts it, its owner gets `stopped`
    /// and its subscription ends. With its worker's report, the body gets
    /// the bytes, and one not fetched yet is kept until the fetch
    /// deadline; without it, the worker is told to stop the clip (unless
    /// it is gone, or was told already) and the body is cut.
    pub(crate) fn end_clip(&mut self, clip_id: &str, end: ClipEnd) {
        let Some(mut entry) = self.clips.remove(clip_id) else {
            return;
        };
        let connection = entry.connection.clone();
        self.refresh_connection(&connection);
        let reported = matches!(end, ClipEnd::Reported { .. });
        let (reason, bytes, duration_ms, gaps) = match end {
            ClipEnd::Reported {
                reason,
                bytes,
                duration_ms,
                gaps,
            } => {
                if let Some(written) = entry.written.take() {
                    // The body may be gone already; then nobody checks.
                    let _sent = written.send(bytes);
                }
                (reason, bytes, duration_ms, gaps)
            }
            ClipEnd::Now(reason) => {
                if reason != ClipStopReason::WorkerCrashed && entry.ending.is_none() {
                    entry.ask_stop(clip_id);
                }
                (reason, 0, 0, entry.gaps)
            }
        };
        if let Some(stream) = self.streams.get_mut(&entry.stream_id) {
            let counters = &mut stream.clips;
            if completed(reason) {
                counters.completed = counters.completed.saturating_add(1);
            }
            counters.bytes = counters.bytes.saturating_add(bytes);
            counters.gaps = counters.gaps.saturating_add(u64::from(gaps));
        }
        tracing::info!(
            event = "clip_stopped",
            clip.id = clip_id,
            stream.id = %entry.stream_id,
            connection.id = %connection,
            reason = reason.as_str(),
            bytes,
            duration_ms,
            gaps,
            by = if reported { "worker" } else { "supervisor" },
            "clip: stopped"
        );
        entry.deliver(
            clip_id,
            &ClipEvent::Stopped {
                reason,
                bytes,
                duration_ms,
                gaps,
            },
        );
        if reported
            && !entry.expired
            && let Some(body) = entry.body.take()
        {
            tracing::debug!(
                clip.id = clip_id,
                "clip ended before its body was fetched; the body is kept until the fetch deadline"
            );
            self.finished_clips.insert(
                clip_id.to_owned(),
                FinishedClip {
                    serial: entry.serial,
                    body,
                    _timer: entry.timer.take(),
                },
            );
        }
    }

    /// Ends every clip `select` picks without its worker's report
    /// ([`ClipEnd::Now`]), for `reason`.
    pub(crate) fn end_clips_where(
        &mut self,
        select: impl Fn(&ClipEntry) -> bool,
        reason: ClipStopReason,
    ) {
        let ids: Vec<String> = self
            .clips
            .iter()
            .filter(|(_, clip)| select(clip))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.end_clip(&id, ClipEnd::Now(reason));
        }
    }

    /// `unsubscribe` ended `connection`'s subscription `subscription`: the
    /// clip it was, if any, loses its owner and is stopped (`stopped`), its
    /// end going nowhere; `false` when no clip had it.
    pub(crate) fn unsubscribe_clip(&mut self, connection: ConnectionId, subscription: u64) -> bool {
        let Some((id, entry)) = self
            .clips
            .iter_mut()
            .find(|(_, clip)| clip.owned_by(connection, subscription))
        else {
            return false;
        };
        entry.owner = None;
        let id = id.clone();
        self.stop_clip(&id, ClipStopReason::Stopped);
        true
    }

    /// Control connection `connection` closed: its clips end
    /// (`session_closed`) at once, without the grace an orphaned session
    /// gets, since their events have nowhere to go.
    pub(crate) fn clips_connection_closed(&mut self, connection: ConnectionId) {
        let ids: Vec<String> = self
            .clips
            .iter_mut()
            .filter(|(_, clip)| {
                clip.owner
                    .as_ref()
                    .is_some_and(|owner| owner.connection == connection)
            })
            .map(|(id, clip)| {
                clip.owner = None;
                id.clone()
            })
            .collect();
        for id in ids {
            self.stop_clip(&id, ClipStopReason::SessionClosed);
        }
    }

    /// The fetch deadline of clip `serial` passed: a running clip whose
    /// body nobody took is stopped (`not_fetched`), and a finished one's
    /// body is dropped.
    pub(crate) fn clip_fetch_deadline(&mut self, clip_id: &str, serial: u64) {
        // A fetch aborts the timer; one that fired meanwhile finds no body.
        if let Some(entry) = self
            .clips
            .get_mut(clip_id)
            .filter(|clip| clip.serial == serial && clip.body.is_some())
        {
            entry.expired = true;
            tracing::info!(
                clip.id = clip_id,
                stream.id = %entry.stream_id,
                "clip not fetched in time"
            );
            self.stop_clip(clip_id, ClipStopReason::NotFetched);
        } else if self
            .finished_clips
            .get(clip_id)
            .is_some_and(|clip| clip.serial == serial)
        {
            self.finished_clips.remove(clip_id);
            tracing::info!(
                clip.id = clip_id,
                "body of a finished clip not fetched in time; dropped"
            );
        }
    }

    /// The body of clip `clip_id`, handed out once: a running clip's, or
    /// the kept body of one that ended before it was fetched.
    pub(crate) fn take_clip_body(&mut self, clip_id: &str) -> Result<ClipBody, ClipBodyError> {
        if let Some(entry) = self.clips.get_mut(clip_id) {
            let body = entry.body.take().ok_or(ClipBodyError::AlreadyFetched)?;
            // Fetched: the deadline has nothing left to do.
            entry.timer = None;
            return Ok(body);
        }
        self.finished_clips
            .remove(clip_id)
            .map(|clip| clip.body)
            .ok_or(ClipBodyError::NotFound)
    }

    /// Whether `clip_id` names a clip that runs or a body still to fetch:
    /// a new clip may not take it.
    pub(crate) fn clip_id_in_use(&self, clip_id: &str) -> bool {
        self.clips.contains_key(clip_id) || self.finished_clips.contains_key(clip_id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::UNIX_EPOCH;

    use lotse_core::let_assert;
    use serde_json::json;

    use super::*;
    use crate::test_support::Captured;

    const LIMITS: ClipLimits = ClipLimits::DEFAULT;

    /// A clip `k1` of `front` on `c1` asked with `audio`, and its events.
    fn entry(audio: bool) -> (ClipEntry, mpsc::Receiver<Event>) {
        let (events, rx) = mpsc::channel(CLIP_QUEUE);
        let (written, report) = oneshot::channel();
        let body = ClipBody {
            reader: Box::new(tokio::io::empty()),
            written: report,
        };
        let spec = ClipSpec {
            clip_id: "k1".into(),
            before_ms: 10_000,
            after_ms: Some(20_000),
            audio,
        };
        let owner = ClipOwner {
            connection: ConnectionId(1),
            subscription: 9,
            events,
        };
        let entry = ClipEntry::new(
            1,
            ("front".into(), "c1".into()),
            spec,
            owner,
            (body, written),
        );
        (entry, rx)
    }

    fn started(before_ms: u32, video: &str, picture: Option<(u32, u32)>) -> ClipReport {
        ClipReport::Started {
            before_ms,
            video: video.into(),
            picture,
            audio: None,
        }
    }

    fn applied(entry: &mut ClipEntry, report: ClipReport) -> Result<Applied, &'static str> {
        entry.apply("k1", report, LIMITS, UNIX_EPOCH)
    }

    fn passed(applied: Result<Applied, &'static str>) -> serde_json::Value {
        let_assert!(Ok(Applied::Event(event)) = applied);
        clip_event(&event).payload
    }

    #[test]
    fn the_defaults_bound_every_report_and_the_queue_holds_every_event() {
        assert_eq!(
            CLIP_QUEUE,
            usize::try_from(MAX_GAP_EVENTS).unwrap() + 3,
            "started, the warning, the gaps and stopped"
        );
        assert_eq!(
            usize::try_from(ClipLimits::DEFAULT.preroll_bytes).unwrap(),
            lotse_core::track::DEFAULT_PREROLL_BYTES
        );
        assert_eq!(
            usize::try_from(ClipLimits::DEFAULT.clip_queue_bytes).unwrap(),
            lotse_core::clip::DEFAULT_CLIP_QUEUE_BYTES
        );
        assert_eq!(ClipLimits::default(), ClipLimits::NONE);
        assert_eq!(
            (ClipLimits::NONE.max_clips, ClipLimits::NONE.preroll_max_ms),
            (0, 0)
        );
        assert_eq!(LIMITS.span_ms(), 120_000 + 600_000 + 60_000);
        let unbounded = ClipLimits {
            preroll_max_ms: u32::MAX,
            ..LIMITS
        };
        assert_eq!(unbounded.span_ms(), u32::MAX);
        assert!(completed(ClipStopReason::MaxDuration));
        assert!(!completed(ClipStopReason::ClientGone));
    }

    #[test]
    fn started_passes_once_with_the_known_codecs_the_supervisor_stamps() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut clip, _rx) = entry(true);
        let mut report = started(9_800, "h264", Some((1920, 1080)));
        if let ClipReport::Started { audio, .. } = &mut report {
            *audio = Some("aac_lc".into());
        }
        let at = UNIX_EPOCH + Duration::from_hours(489_202);
        let event = passed(clip.apply("k1", report, LIMITS, at));
        assert_eq!(
            event,
            json!({ "type": "started", "clip_id": "k1", "at": "2025-10-22T10:00:00.000Z",
                    "before_ms": 9_800,
                    "video": { "codec": "h264", "width": 1920, "height": 1080 },
                    "audio": { "codec": "aac_lc" } })
        );
        let lines = captured.lines("clip: started");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("before_ms_asked=10000") && lines[0].contains("audio=\"aac_lc\""),
            "{lines:?}"
        );
        // Once only.
        assert_eq!(
            applied(&mut clip, started(0, "h264", None)).unwrap_err(),
            "a second started"
        );
        // Without a picture or audio.
        let (mut clip, _rx) = entry(false);
        let event = passed(applied(&mut clip, started(0, "h265", None)));
        assert_eq!(event["video"], json!({ "codec": "h265" }));
        assert!(event["audio"].is_null());
    }

    #[test]
    fn started_with_an_unknown_codec_or_audio_not_asked_for_breaks_the_contract() {
        let cases = [
            (
                started(0, "mjpeg", None),
                false,
                "started names an unknown video codec",
            ),
            (
                ClipReport::Started {
                    before_ms: 0,
                    video: "h264".into(),
                    picture: None,
                    audio: Some("pcmu".into()),
                },
                true,
                "started names an unknown audio codec",
            ),
            (
                ClipReport::Started {
                    before_ms: 0,
                    video: "h264".into(),
                    picture: None,
                    audio: Some("opus".into()),
                },
                false,
                "started has audio not asked for",
            ),
            (
                started(LIMITS.span_ms() + 1, "h264", None),
                true,
                "started before_ms out of bounds",
            ),
        ];
        for (report, audio, reason) in cases {
            let (mut clip, _rx) = entry(audio);
            assert_eq!(applied(&mut clip, report).unwrap_err(), reason);
            assert!(!clip.started);
        }
        let (mut clip, _rx) = entry(false);
        assert!(applied(&mut clip, started(LIMITS.span_ms(), "h264", None)).is_ok());
    }

    #[test]
    fn iso14496_12_8_3_2_3_a_picture_side_tkhd_cannot_hold_or_zero_is_refused() {
        for picture in [(0, 1080), (1920, 0), (65_536, 1080), (1920, 65_536)] {
            let (mut clip, _rx) = entry(false);
            assert_eq!(
                applied(&mut clip, started(0, "h264", Some(picture))).unwrap_err(),
                "started picture out of bounds",
                "{picture:?}"
            );
        }
        let (mut clip, _rx) = entry(false);
        let event = passed(applied(&mut clip, started(0, "h264", Some((65_535, 1)))));
        assert_eq!(event["video"]["width"], 65_535);
    }

    #[test]
    fn a_warning_passes_once_plain_and_a_repeated_or_unknown_one_is_dropped_and_logged_once() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut clip, _rx) = entry(true);
        let warning = |code: &str, message: &str| ClipReport::Warning {
            code: code.into(),
            message: message.into(),
        };
        let event = passed(applied(
            &mut clip,
            warning("audio_omitted", &format!("pcmu\nforged{}", "x".repeat(600))),
        ));
        assert_eq!(event["code"], "audio_omitted");
        let message = event["message"].as_str().unwrap();
        assert!(message.starts_with("pcmu forged"), "{message}");
        assert!(message.len() <= MAX_MESSAGE_BYTES);
        assert_eq!(captured.lines("clip warning").len(), 1);
        for code in ["audio_omitted", "bogus\ncode"] {
            assert!(matches!(
                applied(&mut clip, warning(code, "again")),
                Ok(Applied::Nothing)
            ));
        }
        let dropped = captured.lines("a worker repeated a clip warning");
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(clip.warnings_dropped, 2);
    }

    #[test]
    fn gaps_pass_with_a_known_reason_inside_the_span_and_up_to_the_cap() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut clip, _rx) = entry(false);
        let gap = |reason: &str, from_ms: u32, to_ms: u32| ClipReport::Gap {
            reason: reason.into(),
            from_ms,
            to_ms,
        };
        let event = passed(applied(&mut clip, gap("reconnect", 12_040, 15_310)));
        assert_eq!(
            event,
            json!({ "type": "gap", "reason": "reconnect", "from_ms": 12_040, "to_ms": 15_310 })
        );
        for (report, reason) in [
            (gap("solar_flare", 0, 1), "gap names an unknown reason"),
            (gap("lagged", 2, 1), "gap out of bounds"),
            (gap("lagged", 0, LIMITS.span_ms() + 1), "gap out of bounds"),
        ] {
            assert_eq!(applied(&mut clip, report).unwrap_err(), reason);
        }
        for _ in 1..MAX_GAP_EVENTS {
            assert!(applied(&mut clip, gap("overflow", 1, 1)).is_ok());
        }
        assert_eq!(
            applied(&mut clip, gap("overflow", 1, 1)).unwrap_err(),
            "more gaps than a clip reports"
        );
        assert_eq!(clip.gaps, MAX_GAP_EVENTS);
        let passed = captured.lines("clip gap passed on");
        assert_eq!(passed.len(), 256);
        assert!(passed[0].contains("reason=\"reconnect\""), "{passed:?}");
    }

    #[test]
    fn stopped_maps_the_worker_s_reason_and_puts_the_supervisor_s_own_in_for_stopped() {
        let captured = Captured::default();
        let _logs = captured.install();
        let stopped = |reason: &str, duration_ms: u32, gaps: u32| ClipReport::Stopped {
            reason: reason.into(),
            bytes: 7,
            duration_ms,
            gaps,
        };
        let end = |clip: &mut ClipEntry, report| {
            let_assert!(Ok(Applied::End(ClipEnd::Reported { reason, .. })) = applied(clip, report));
            reason
        };
        let (mut clip, _rx) = entry(false);
        assert_eq!(
            end(&mut clip, stopped("completed", 1, 0)),
            ClipStopReason::Completed
        );
        assert_eq!(
            end(&mut clip, stopped("stopped", 1, 0)),
            ClipStopReason::Stopped
        );
        clip.ending = Some(ClipStopReason::NotFetched);
        assert_eq!(
            end(&mut clip, stopped("stopped", 1, 0)),
            ClipStopReason::NotFetched
        );
        // A worker that ended it otherwise first keeps its reason.
        assert_eq!(
            end(&mut clip, stopped("client_gone", 1, 0)),
            ClipStopReason::ClientGone
        );
        // A reason the worker may not give is an internal error, logged.
        for reason in [
            "worker_crashed",
            "session_closed",
            "not_fetched",
            "bogus\nreason",
        ] {
            assert_eq!(
                end(&mut clip, stopped(reason, 1, 0)),
                ClipStopReason::InternalError
            );
        }
        let lines = captured.lines("a worker ended a clip with a reason it may not give");
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[3].contains("bogus reason"), "{lines:?}");
        // Figures the clip cannot have break the contract.
        assert_eq!(
            applied(&mut clip, stopped("completed", LIMITS.span_ms() + 1, 0)).unwrap_err(),
            "stopped duration out of bounds"
        );
        clip.gaps = 2;
        assert_eq!(
            applied(&mut clip, stopped("completed", 1, 1)).unwrap_err(),
            "stopped counts fewer gaps than were reported"
        );
        let_assert!(
            Ok(Applied::End(ClipEnd::Reported {
                bytes,
                duration_ms,
                gaps,
                ..
            })) = applied(&mut clip, stopped("completed", 1, 2))
        );
        assert_eq!((bytes, duration_ms, gaps), (7, 1, 2));
    }

    #[tokio::test]
    async fn events_go_to_the_owner_while_it_listens_and_a_stop_takes_its_slot_once() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut clip, mut rx) = entry(false);
        assert!(clip.owned_by(ConnectionId(1), 9));
        assert!(!clip.owned_by(ConnectionId(1), 8));
        assert!(!clip.owned_by(ConnectionId(2), 9));
        let gap = ClipEvent::Gap {
            reason: ClipGapReason::Lagged,
            from_ms: 1,
            to_ms: 2,
        };
        clip.deliver("k1", &gap);
        let delivered = rx.recv().await.unwrap();
        assert_eq!(delivered.class, EventClass::Signaling);
        assert_eq!(delivered.payload["reason"], "lagged");
        drop(rx);
        clip.deliver("k1", &gap);
        assert_eq!(
            captured
                .lines("clip subscription gone; event dropped")
                .len(),
            1
        );
        // The stop goes through the reserved slot, once.
        let (commands, mut queue) = mpsc::channel(1);
        clip.stop_slot = Some(commands.clone().try_reserve_owned().unwrap());
        clip.ask_stop("k1");
        clip.ask_stop("k1");
        let_assert!(Some(DriverCommand::StopClip { clip_id }) = queue.recv().await);
        assert_eq!(clip_id, "k1");
        assert!(queue.try_recv().is_err());
        // A timer is aborted with what it was for.
        let task = lotse_core::task::spawn_named("test.timer", std::future::pending::<()>());
        drop(ClipTimer(task.abort_handle()));
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
