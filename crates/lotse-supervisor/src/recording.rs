//! Event recordings as the supervisor keeps them: which stream and source
//! connection each records on, which control connection's subscription
//! gets its events, the read end of the pipe its worker writes the file
//! into until `GET /v0/recording/{recording_id}` takes it, the per-stream
//! counters, and the mapping of a worker's recording reports onto the API's
//! events (`lotse_api_types::recording`).
//!
//! The worker makes the recording; the supervisor owns its signaling and its
//! body, and never sees a byte of it: the file goes from the worker's
//! write end to the body through the kernel. A recording is demand on its
//! connection, as a viewer is, from `recording/create` until it ends.
//!
//! A worker's report is untrusted, as its session reports are: it is
//! accepted only for a recording of that worker's own connection, every name is
//! mapped onto a known one, every number is held to what the worker
//! guarantees (a picture `tkhd` can describe, a gap that ends no earlier
//! than it begins, at most [`MAX_GAP_EVENTS`] gaps and a `Closed` that
//! counts each), and a warning's message is made [`plain`] and capped at
//! [`MAX_MESSAGE_BYTES`]. A media time (`prerecord_ms`, a gap's ends,
//! `duration_ms`) is passed on as the worker measured it, bounded only by
//! its type: the ring trims by time only at keyframes
//! (`lotse_core::prerecord`), so it keeps a GOP the window reaches into
//! however long that runs, a recording can start at a keyframe older than any
//! limit, and its file runs from there. A report
//! that breaks the contract is dropped, logged, and ends its recording
//! `internal_error`, the worker told to stop it unless the report was its
//! `Closed`, after which it runs the recording no more; a repeated or unknown
//! warning is only dropped.
//!
//! A recording ends with the worker's `Closed` report, whose `bytes` go to the
//! body, which ends whole only when they match what it read. When the
//! supervisor ends a recording itself (`not_fetched`, `unsubscribe` or its
//! control connection closing, both `session_closed`; a client never
//! stops a recording, which runs the length it asked for) it asks the worker
//! through a slot reserved in the driver's queue at `recording/create` and waits
//! for that report, putting its own reason in place of the worker's
//! [`STOPPED_AS_ASKED`], and in place of its `client_gone`, since its
//! reason already says the file is not whole: the worker ends a stop
//! `client_gone` when the reader does not take the last bytes in time, as a
//! body nobody fetched never does once the pipe is full, its tail counted in
//! the bytes. A
//! recording whose start still waits for a worker gets that report from its
//! driver instead, which also ends one that waited too long
//! (`source_not_live`, after [`RecordingLimits::start_timeout`]) or whose end
//! passed before a worker came, so a fetched recording without a worker still
//! ends. When
//! the worker cannot report any more (it exited, the stream was deleted or
//! moved to another connection, shutdown, a malformed report), the recording
//! ends at once without it: `closed` then says 0 bytes and 0 ms, since
//! only the worker knew them, and the body is cut.
//!
//! A worker runs one recording per id, drops a second start under an id it
//! runs, and its reports name the recording by its id alone. So a recording the
//! supervisor ended while its worker may still run it keeps its id
//! ([`StoppingRecording`]) until that worker's `Closed` comes, the worker
//! exits or its driver stops it, its connection is released, or its start
//! turns out never to have reached a worker ([`State::recording_start_wanted`]),
//! whether queued for one or sent to one: a new recording under
//! the id would otherwise be dropped by the worker and end with the old
//! one's report. A start the driver still holds when its recording is gone
//! (the recording ended while it waited for a worker, or its worker exited
//! with the start still queued) is dropped with its pipe, never handed to
//! the next worker.
//!
//! A recording that ends before its body was fetched keeps the body until the
//! fetch deadline (`limits.recording_fetch_timeout_ms` from the `recording/create`
//! result), so a short recording is not lost to a `GET` that comes a moment
//! late. `limits.max_recordings` counts every recording that holds something: one
//! that runs, one its worker is still finishing, and a body that waits for
//! its `GET`, each holding a descriptor or a worker's recording
//! ([`State::recordings_held`]).

use std::time::{Duration, SystemTime};

use lotse_api::{ConnectionId, Event, EventClass, RecordingBody, RecordingBodyError};
use lotse_api_types::recording::{
    RecordingAudio, RecordingCloseReason, RecordingEvent, RecordingGapReason, RecordingVideo,
    RecordingWarningCode,
};
use lotse_api_types::time::rfc3339;
use lotse_core::codec::CodecFamily;
use lotse_core::text::plain;
use lotse_ipc::{RecordingReport, RecordingSpec, STOPPED_AS_ASKED};
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::driver::DriverCommand;
use crate::registry::State;
use crate::worker_text::{MAX_MESSAGE_BYTES, MAX_NAME_BYTES};

/// Gap events a recording passes on: its worker reports at most this many and
/// counts the rest only in `closed.gaps`, so one that reports more breaks
/// the contract.
pub(crate) const MAX_GAP_EVENTS: u32 = 256;

/// Events a recording's subscription holds: `started`, its one warning,
/// [`MAX_GAP_EVENTS`] gaps and `closed`. That is every event a recording can
/// have, so its own events never fill it, and none is dropped while the
/// client reads.
pub(crate) const RECORDING_QUEUE: usize = 259;

/// The largest picture side `started` passes on: `tkhd`'s width and height
/// are 16.16 fixed-point numbers (ISO/IEC 14496-12 §8.3.2.3), so a recording's
/// file cannot describe a larger picture.
const MAX_PICTURE_SIDE: u32 = 65_535;

/// The video codecs a recording's file carries.
const RECORDING_VIDEO: [CodecFamily; 2] = [CodecFamily::H264, CodecFamily::H265];

/// The audio codecs a recording's file carries.
const RECORDING_AUDIO: [CodecFamily; 2] = [CodecFamily::AacLc, CodecFamily::Opus];

/// The stop reasons only the supervisor gives: a worker naming one breaks
/// the contract.
const SUPERVISOR_REASONS: [RecordingCloseReason; 3] = [
    RecordingCloseReason::WorkerCrashed,
    RecordingCloseReason::NotFetched,
    RecordingCloseReason::SessionClosed,
];

/// The limits on recordings and the pre-record window, `limits.prerecord_*` and
/// `limits.recording_*` as the binary resolves them ([`Limits::recordings`]). A
/// supervisor with a recording output keeps them; one without keeps
/// [`RecordingLimits::NONE`], and its workers refuse every recording. The worker's
/// share (`max_prerecord_bytes`, `max_recording_ms`, `recording_queue_bytes`, `start_timeout`,
/// `max_recordings`) reaches each worker as its flags, so both processes hold the
/// same bounds.
///
/// [`Limits::recordings`]: crate::Limits::recordings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingLimits {
    /// `limits.max_prerecord_ms`: the longest window `stream/put` may ask
    /// for, and the furthest back a recording's `prerecord_ms` may ask.
    pub max_prerecord_ms: u32,
    /// What a stream's pre-record frames may take together, all its tracks'
    /// rings and the frames its recordings took from them and have not written
    /// yet: no setting, half of `limits.worker_address_space`
    /// ([`RecordingLimits::max_prerecord_bytes_for`]); the worker's bound, which
    /// `info` reports as `limits.max_prerecord_bytes`.
    pub max_prerecord_bytes: u64,
    /// `limits.max_recording_ms`: the most `duration_ms` may ask, and the worker's
    /// bound on it.
    pub max_recording_ms: u32,
    /// `limits.recording_queue_bytes`: what one recording's queue in the worker holds
    /// before it drops to the next keyframe and reports the gap.
    pub recording_queue_bytes: u64,
    /// `limits.recording_fetch_timeout_ms`: how long a recording's body waits for
    /// its `GET` from the `recording/create` result on.
    pub fetch_timeout: Duration,
    /// `limits.recording_start_timeout_ms`: how long a recording in the worker waits
    /// for the tracks and a keyframe to start at, and how long its start
    /// waits in its connection's queue for a worker.
    pub start_timeout: Duration,
    /// `limits.max_recordings`: recordings open at once over every stream, and in one
    /// worker.
    pub max_recordings: u32,
    /// `limits.max_recordings_per_stream`: recordings open at once on one stream.
    pub max_recordings_per_stream: u32,
}

impl RecordingLimits {
    /// The defaults: a 5-minute window at most and 1-hour recordings (the
    /// worker's `DEFAULT_MAX_RECORDING`), so a client's record call that asks
    /// up to 5 minutes before an event and up to an hour after it is never
    /// refused; 512 MiB per stream (core's `DEFAULT_PRERECORD_BYTES`,
    /// [`RecordingLimits::max_prerecord_bytes_for`] the default worker address
    /// space), a bound no real camera's window reaches; an 8 MiB queue (core's
    /// `DEFAULT_RECORDING_QUEUE_BYTES`), 10 s to fetch, 10 s to start (the
    /// worker's `DEFAULT_RECORDING_START_TIMEOUT`), 8 recordings, 2 per stream.
    pub const DEFAULT: Self = Self {
        max_prerecord_ms: 300_000,
        max_prerecord_bytes: 512 * 1024 * 1024,
        max_recording_ms: 3_600_000,
        recording_queue_bytes: 8 * 1024 * 1024,
        fetch_timeout: Duration::from_secs(10),
        start_timeout: Duration::from_secs(10),
        max_recordings: 8,
        max_recordings_per_stream: 2,
    };

    /// The pre-record's byte bound for workers limited to
    /// `worker_address_space`: half of it for a stream's pre-record frames
    /// together, its rings' and its recordings' not yet written, so the window,
    /// a time, is what decides what they hold, and a camera sending far
    /// more than any real one, or recordings writing slower than it sends, get
    /// a shorter pre-record instead of taking the worker's memory; the rest
    /// of the worker fits in the other half.
    #[must_use]
    pub const fn max_prerecord_bytes_for(worker_address_space: u64) -> u64 {
        worker_address_space / 2
    }

    /// No window and no recording: a supervisor without a recording output, whose
    /// workers refuse every recording, says so with these zeros.
    pub const NONE: Self = Self {
        max_prerecord_ms: 0,
        max_prerecord_bytes: 0,
        max_recording_ms: 0,
        recording_queue_bytes: 0,
        fetch_timeout: Self::DEFAULT.fetch_timeout,
        start_timeout: Self::DEFAULT.start_timeout,
        max_recordings: 0,
        max_recordings_per_stream: 0,
    };
}

/// [`RecordingLimits::NONE`]: what a supervisor holds until it knows it has a
/// recording output.
impl Default for RecordingLimits {
    fn default() -> Self {
        Self::NONE
    }
}

/// A stream's recording counters, as `stream/get` and `metrics/get` report them;
/// kept over a `stream/put` that changes the stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RecordingCounters {
    /// Recordings `recording/create` handed to the stream's connection.
    pub(crate) started: u64,
    /// Recordings that ended with their whole file written: `completed`.
    pub(crate) completed: u64,
    /// Gaps in the stream's recordings, every one the workers counted, added
    /// as each recording ends.
    pub(crate) gaps: u64,
    /// The length of the stream's recording files, as their workers report
    /// them ([`RecordingEnd::Reported`]), a tail a body did not take in time
    /// included.
    pub(crate) bytes: u64,
}

/// A one-shot timer of a recording (its fetch deadline), aborted when dropped:
/// no timer task outlives what it was for.
#[derive(Debug)]
pub(crate) struct RecordingTimer(pub(crate) AbortHandle);

impl Drop for RecordingTimer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The control connection's subscription that gets a recording's events.
#[derive(Debug)]
pub(crate) struct RecordingOwner {
    /// The control connection.
    pub(crate) connection: ConnectionId,
    /// The subscription: the id of its `recording/create`.
    pub(crate) subscription: u64,
    /// Where the events go; dropping it ends the subscription.
    pub(crate) events: mpsc::Sender<Event>,
}

/// How a recording ends ([`State::end_recording`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordingEnd {
    /// Its worker reported the end, with this reason (already the API's,
    /// the supervisor's own put in where [`STOPPED_AS_ASKED`] says) and these
    /// figures.
    Reported {
        /// Why.
        reason: RecordingCloseReason,
        /// The file's length the worker reports, which the body checks
        /// what it read against.
        bytes: u64,
        /// The media time the file covers.
        duration_ms: u32,
        /// The gaps the worker counted.
        gaps: u32,
    },
    /// The supervisor ends it without its worker's report, which will not
    /// come or not be believed. Unless the worker is gone
    /// (`worker_crashed`), it is told to stop the recording, and the id stays
    /// taken until it says it did ([`StoppingRecording`]).
    Now(RecordingCloseReason),
    /// The worker's `Closed` came but breaks the contract: the recording ends
    /// `internal_error` without its figures, its body cut, and nothing is
    /// asked of the worker, which runs the recording no more.
    Rejected,
}

/// A recording that ended while its worker may still run it: the supervisor
/// asked it to stop and holds the id until the worker's `Closed` comes,
/// so no new recording takes the id meanwhile ([`State::recording_id_in_use`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoppingRecording {
    /// The source connection whose worker runs it.
    pub(crate) connection: String,
    /// Its serial, which its start in the driver's queue carries.
    pub(crate) serial: u64,
}

/// One recording that runs.
#[derive(Debug)]
pub(crate) struct RecordingEntry {
    /// Unique over the daemon's lifetime, so its timer never acts on a
    /// later recording that reuses the id.
    pub(crate) serial: u64,
    /// The stream it records.
    pub(crate) stream_id: String,
    /// The source connection whose worker records it.
    pub(crate) connection: String,
    /// What was asked of the worker.
    spec: RecordingSpec,
    /// The subscription, until the control connection closes or
    /// unsubscribes.
    owner: Option<RecordingOwner>,
    /// The body, until its `GET` takes it.
    body: Option<RecordingBody>,
    /// Where the worker's `bytes` go, which the body checks what it read
    /// against; dropped without them when the worker cannot report.
    written: Option<oneshot::Sender<u64>>,
    /// The slot reserved in the driver's queue for the recording's stop at
    /// `recording/create`: a full queue never keeps a stop from the worker.
    pub(crate) stop_slot: Option<OwnedPermit<DriverCommand>>,
    /// The supervisor asked the worker to stop the recording, for this reason,
    /// which its `closed` then carries.
    ending: Option<RecordingCloseReason>,
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
    pub(crate) timer: Option<RecordingTimer>,
}

/// The body of a recording that ended before it was fetched, kept for its
/// `GET` until the fetch deadline.
#[derive(Debug)]
pub(crate) struct FinishedRecording {
    /// The recording's serial, which its timer names.
    serial: u64,
    /// The body.
    body: RecordingBody,
    /// The fetch deadline, which drops it.
    _timer: Option<RecordingTimer>,
}

impl RecordingEntry {
    /// A recording of `stream_id` on `connection`, asked as `spec`, whose events
    /// go to `owner` and whose bytes are `body`, the worker's figure going
    /// to `written`.
    pub(crate) fn new(
        serial: u64,
        (stream_id, connection): (String, String),
        spec: RecordingSpec,
        owner: RecordingOwner,
        (body, written): (RecordingBody, oneshot::Sender<u64>),
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
    /// every event a recording can have ([`RECORDING_QUEUE`]), so only a forwarder
    /// that is gone loses one.
    fn deliver(&self, recording_id: &str, event: &RecordingEvent) {
        if let Some(owner) = &self.owner
            && owner.events.try_send(recording_event(event)).is_err()
        {
            tracing::debug!(
                recording.id = recording_id,
                "recording subscription gone; event dropped"
            );
        }
    }

    /// Tells the worker to stop the recording, through the slot reserved for
    /// it; a second call has no slot left and sends nothing.
    fn ask_stop(&mut self, recording_id: &str) {
        if let Some(slot) = self.stop_slot.take() {
            drop(slot.send(DriverCommand::StopRecording {
                recording_id: recording_id.to_owned(),
            }));
        }
    }

    /// Checks a report against the recording, `at` the wall time it came, and
    /// logs what it is: an event to pass on, the recording's end,
    /// nothing (a warning dropped), or the reason it breaks the contract.
    fn apply(
        &mut self,
        recording_id: &str,
        report: RecordingReport,
        at: SystemTime,
    ) -> Result<Applied, &'static str> {
        match report {
            RecordingReport::Started {
                prerecord_ms,
                video,
                picture,
                audio,
            } => self.started_event(
                recording_id,
                (prerecord_ms, &video, picture, audio.as_deref()),
                at,
            ),
            RecordingReport::Warning { code, message } => {
                Ok(self.warning(recording_id, &code, &message))
            }
            RecordingReport::Gap {
                reason,
                from_ms,
                to_ms,
            } => self.gap(recording_id, &reason, (from_ms, to_ms)),
            RecordingReport::Closed {
                reason,
                bytes,
                duration_ms,
                gaps,
            } => self
                .closed((&reason, bytes, duration_ms, gaps))
                .map(Applied::End),
        }
    }

    /// `started`, once, with a video codec a recording carries, audio only when
    /// asked for and one a recording carries, and a picture `tkhd` can hold.
    /// `at` is when the report arrived ([`State::recording_report`]): the worker
    /// measures `prerecord_ms` back from the container's start and sends
    /// `Started` then, so `at − prerecord_ms` is the first keyframe's capture
    /// time, within the report's transit time.
    fn started_event(
        &mut self,
        recording_id: &str,
        (prerecord_ms, video, picture, audio): (u32, &str, Option<(u32, u32)>, Option<&str>),
        at: SystemTime,
    ) -> Result<Applied, &'static str> {
        if self.started {
            return Err("a second started");
        }
        let video = known(&RECORDING_VIDEO, video).ok_or("started names an unknown video codec")?;
        let audio = match audio {
            Some(_) if !self.spec.audio => return Err("started has audio not asked for"),
            Some(name) => {
                Some(known(&RECORDING_AUDIO, name).ok_or("started names an unknown audio codec")?)
            }
            None => None,
        };
        let side = 1..=MAX_PICTURE_SIDE;
        if picture.is_some_and(|(w, h)| !side.contains(&w) || !side.contains(&h)) {
            return Err("started picture out of bounds");
        }
        self.started = true;
        tracing::info!(
            event = "recording_started",
            recording.id = recording_id,
            stream.id = %self.stream_id,
            prerecord_ms_asked = self.spec.prerecord_ms,
            prerecord_ms,
            video,
            audio,
            "recording: started"
        );
        Ok(Applied::Event(RecordingEvent::Started {
            recording_id: recording_id.to_owned(),
            at: rfc3339(at),
            prerecord_ms,
            video: RecordingVideo {
                codec: video.to_owned(),
                width: picture.map(|(w, _)| w),
                height: picture.map(|(_, h)| h),
            },
            audio: audio.map(|codec| RecordingAudio {
                codec: codec.to_owned(),
            }),
        }))
    }

    /// A warning: a known code once, its message made [`plain`]; a
    /// repeated or unknown one is dropped, only the first logged.
    fn warning(&mut self, recording_id: &str, code: &str, message: &str) -> Applied {
        let fresh = RecordingWarningCode::parse(code).filter(|_| !self.warned);
        let Some(code) = fresh else {
            if self.warnings_dropped == 0 {
                tracing::warn!(
                    recording.id = recording_id,
                    code = ?plain(code, MAX_NAME_BYTES),
                    "a worker repeated a recording warning or named an unknown one; dropped, and later ones without a log"
                );
            }
            self.warnings_dropped = self.warnings_dropped.saturating_add(1);
            return Applied::Nothing;
        };
        self.warned = true;
        let message = plain(message, MAX_MESSAGE_BYTES);
        // The worker's text under `detail`, Debug-escaped.
        tracing::info!(
            event = "recording_warning",
            recording.id = recording_id,
            stream.id = %self.stream_id,
            code = code.as_str(),
            detail = ?message,
            "recording warning"
        );
        Applied::Event(RecordingEvent::Warning { code, message })
    }

    /// A gap with a known reason that ends no earlier than it begins, up to
    /// [`MAX_GAP_EVENTS`].
    fn gap(
        &mut self,
        recording_id: &str,
        reason: &str,
        (from_ms, to_ms): (u32, u32),
    ) -> Result<Applied, &'static str> {
        let reason = RecordingGapReason::parse(reason).ok_or("gap names an unknown reason")?;
        if from_ms > to_ms {
            return Err("gap ends before it begins");
        }
        if self.gaps >= MAX_GAP_EVENTS {
            return Err("more gaps than a recording reports");
        }
        self.gaps = self.gaps.saturating_add(1);
        // The worker logs each gap at warn, rate-limited.
        tracing::debug!(
            recording.id = recording_id,
            stream.id = %self.stream_id,
            reason = reason.as_str(),
            from_ms,
            to_ms,
            "recording gap passed on"
        );
        Ok(Applied::Event(RecordingEvent::Gap {
            reason,
            from_ms,
            to_ms,
        }))
    }

    /// The end a worker's `Closed` report makes: its reason as the API's,
    /// the supervisor's own when it asked: for [`STOPPED_AS_ASKED`], and
    /// for `client_gone`, since its own reason (`not_fetched`,
    /// `session_closed`) already says the file is not whole; or the reason
    /// the report breaks the contract: a reason the API does not know or
    /// only the supervisor gives (a malformed report, whose figures are not
    /// believed: `lotse_api_types::recording::RecordingEvent::Closed` says 0 bytes
    /// and a cut body for one), [`STOPPED_AS_ASKED`] for a stop not asked
    /// for, or fewer gaps than it reported.
    fn closed(
        &self,
        (reason, bytes, duration_ms, gaps): (&str, u64, u32, u32),
    ) -> Result<RecordingEnd, &'static str> {
        if gaps < self.gaps {
            return Err("closed counts fewer gaps than were reported");
        }
        let reason = if reason == STOPPED_AS_ASKED {
            self.ending
                .ok_or("closed ends a stop the supervisor did not ask for")?
        } else {
            let reason = RecordingCloseReason::parse(reason)
                .filter(|r| !SUPERVISOR_REASONS.contains(r))
                .ok_or("closed names a reason the worker may not give")?;
            match (reason, self.ending) {
                // A stop is a graceful end at the worker, which ends it
                // `client_gone` when the reader does not take the last
                // bytes within its grace: always so for a body nobody
                // fetched once the pipe is full. The supervisor's reason
                // (`not_fetched`, `session_closed`) already says the file
                // is not whole, and is why the recording ended, so it stays, as
                // the worker keeps such a reason of its own.
                (RecordingCloseReason::ClientGone, Some(ending)) => ending,
                (reason, _) => reason,
            }
        };
        Ok(RecordingEnd::Reported {
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
    Event(RecordingEvent),
    /// The recording's end.
    End(RecordingEnd),
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

/// A recording event as the server queues it: signaling, never shed, a handful
/// per recording.
pub(crate) fn recording_event(event: &RecordingEvent) -> Event {
    Event {
        class: EventClass::Signaling,
        payload: serde_json::to_value(event).unwrap_or_default(),
    }
}

/// Whether a recording that ended for `reason` wrote its whole file.
const fn completed(reason: RecordingCloseReason) -> bool {
    matches!(reason, RecordingCloseReason::Completed)
}

impl State {
    /// A worker's report about one of its recordings, at `at` on the wall clock:
    /// its arrival, which a `Started`'s `prerecord_ms` counts back from.
    /// One about a recording the supervisor does not hold is dropped (its
    /// subscription and body are gone; a pipe nobody reads ends the
    /// worker's recording `client_gone`), one about a recording of another
    /// connection is refused, and one that breaks the contract ends the
    /// recording `internal_error`. The `Closed` of a recording that ended while its
    /// worker still ran it frees its id ([`StoppingRecording`]).
    pub(crate) fn recording_report(
        &mut self,
        connection: &str,
        recording_id: &str,
        report: RecordingReport,
        at: SystemTime,
    ) {
        let last = matches!(report, RecordingReport::Closed { .. });
        let Some(entry) = self.recordings.get_mut(recording_id) else {
            self.late_recording_report(connection, recording_id, last);
            return;
        };
        if entry.connection != connection {
            tracing::warn!(
                recording.id = recording_id,
                connection.id = connection,
                "a worker reported a recording it does not run; ignored"
            );
            return;
        }
        match entry.apply(recording_id, report, at) {
            Ok(Applied::Event(event)) => entry.deliver(recording_id, &event),
            Ok(Applied::End(end)) => self.end_recording(recording_id, end),
            Ok(Applied::Nothing) => {}
            Err(reason) => {
                tracing::warn!(
                    recording.id = recording_id,
                    connection.id = connection,
                    reason,
                    "a worker reported a malformed recording report; recording ended"
                );
                // After its `Closed` the worker runs the recording no more.
                let end = if last {
                    RecordingEnd::Rejected
                } else {
                    RecordingEnd::Now(RecordingCloseReason::InternalError)
                };
                self.end_recording(recording_id, end);
            }
        }
    }

    /// A report from `connection`'s worker for `recording_id`, which the
    /// supervisor does not hold: the `Closed` (`last`) of a recording that ended
    /// while that worker still ran it frees the id; any other report is
    /// dropped (its subscription and body are gone; a pipe nobody reads
    /// ends the worker's recording `client_gone`).
    fn late_recording_report(&mut self, connection: &str, recording_id: &str, last: bool) {
        let finishing = self
            .stopping_recordings
            .get(recording_id)
            .is_some_and(|recording| recording.connection == connection);
        if last && finishing {
            self.stopping_recordings.remove(recording_id);
            tracing::debug!(
                recording.id = recording_id,
                connection.id = connection,
                "the worker finished a recording that had ended; its id is free"
            );
            return;
        }
        tracing::debug!(
            recording.id = %plain(recording_id, MAX_NAME_BYTES),
            connection.id = connection,
            "report for a recording the supervisor does not hold; dropped"
        );
    }

    /// Asks the worker to stop recording `recording_id` cleanly for `reason`, which
    /// its `closed` then carries; the recording stays until that report.
    /// Idempotent: an unknown recording, or one already being stopped, changes
    /// nothing.
    pub(crate) fn stop_recording(&mut self, recording_id: &str, reason: RecordingCloseReason) {
        let Some(entry) = self.recordings.get_mut(recording_id) else {
            tracing::debug!(
                recording.id = recording_id,
                reason = reason.as_str(),
                "stop of a recording that is not open; nothing to do"
            );
            return;
        };
        if let Some(ending) = entry.ending {
            tracing::debug!(
                recording.id = recording_id,
                reason = reason.as_str(),
                ending = ending.as_str(),
                "recording already being stopped"
            );
            return;
        }
        entry.ending = Some(reason);
        entry.ask_stop(recording_id);
        tracing::info!(
            event = "recording_stopping",
            recording.id = recording_id,
            stream.id = %entry.stream_id,
            reason = reason.as_str(),
            "recording stop asked of its worker"
        );
    }

    /// Ends recording `recording_id` as `end` says: it leaves the registry and its
    /// connection's demand, its stream counts it, its owner gets `closed`
    /// and its subscription ends. With its worker's report, the body gets
    /// the bytes, and one not fetched yet is kept until the fetch
    /// deadline; without it, the body is cut, and a worker that may still
    /// run the recording is told to stop it (unless it was told already) and
    /// holds its id until it did ([`StoppingRecording`]).
    pub(crate) fn end_recording(&mut self, recording_id: &str, end: RecordingEnd) {
        let Some(mut entry) = self.recordings.remove(recording_id) else {
            return;
        };
        let connection = entry.connection.clone();
        self.refresh_connection(&connection);
        let reported = matches!(end, RecordingEnd::Reported { .. });
        let (reason, bytes, duration_ms, gaps) = match end {
            RecordingEnd::Reported {
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
            RecordingEnd::Now(reason) => {
                // A worker that exited, or one whose connection was released
                // and is stopped with it, reports nothing more.
                if reason != RecordingCloseReason::WorkerCrashed
                    && self.connections.contains_key(&connection)
                {
                    // A recording being stopped already used its slot.
                    entry.ask_stop(recording_id);
                    tracing::debug!(
                        recording.id = recording_id,
                        connection.id = %connection,
                        "recording ended while its worker may still run it; its id is held until the worker stops it"
                    );
                    self.stopping_recordings.insert(
                        recording_id.to_owned(),
                        StoppingRecording {
                            connection: connection.clone(),
                            serial: entry.serial,
                        },
                    );
                }
                (reason, 0, 0, entry.gaps)
            }
            RecordingEnd::Rejected => (RecordingCloseReason::InternalError, 0, 0, entry.gaps),
        };
        if let Some(stream) = self.streams.get_mut(&entry.stream_id) {
            let counters = &mut stream.recordings;
            if completed(reason) {
                counters.completed = counters.completed.saturating_add(1);
            }
            counters.bytes = counters.bytes.saturating_add(bytes);
            counters.gaps = counters.gaps.saturating_add(u64::from(gaps));
        }
        tracing::info!(
            event = "recording_closed",
            recording.id = recording_id,
            stream.id = %entry.stream_id,
            connection.id = %connection,
            reason = reason.as_str(),
            bytes,
            duration_ms,
            gaps,
            by = if reported { "worker" } else { "supervisor" },
            "recording: closed"
        );
        entry.deliver(
            recording_id,
            &RecordingEvent::Closed {
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
                recording.id = recording_id,
                "recording ended before its body was fetched; the body is kept until the fetch deadline"
            );
            self.finished_recordings.insert(
                recording_id.to_owned(),
                FinishedRecording {
                    serial: entry.serial,
                    body,
                    _timer: entry.timer.take(),
                },
            );
        }
    }

    /// Ends every recording `select` picks without its worker's report
    /// ([`RecordingEnd::Now`]), for `reason`.
    pub(crate) fn end_recordings_where(
        &mut self,
        select: impl Fn(&RecordingEntry) -> bool,
        reason: RecordingCloseReason,
    ) {
        let ids: Vec<String> = self
            .recordings
            .iter()
            .filter(|(_, recording)| select(recording))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.end_recording(&id, RecordingEnd::Now(reason));
        }
    }

    /// `unsubscribe` ended `connection`'s subscription `subscription`: the
    /// recording it was, if any, loses its owner and is stopped
    /// (`session_closed`, as a session's `unsubscribe` closes it), its end
    /// going nowhere; `false` when no recording had it.
    pub(crate) fn unsubscribe_recording(
        &mut self,
        connection: ConnectionId,
        subscription: u64,
    ) -> bool {
        let Some((id, entry)) = self
            .recordings
            .iter_mut()
            .find(|(_, recording)| recording.owned_by(connection, subscription))
        else {
            return false;
        };
        entry.owner = None;
        let id = id.clone();
        self.stop_recording(&id, RecordingCloseReason::SessionClosed);
        true
    }

    /// Control connection `connection` closed: its recordings end
    /// (`session_closed`) at once, without the grace an orphaned session
    /// gets, since their events have nowhere to go.
    pub(crate) fn recordings_connection_closed(&mut self, connection: ConnectionId) {
        let ids: Vec<String> = self
            .recordings
            .iter_mut()
            .filter(|(_, recording)| {
                recording
                    .owner
                    .as_ref()
                    .is_some_and(|owner| owner.connection == connection)
            })
            .map(|(id, recording)| {
                recording.owner = None;
                id.clone()
            })
            .collect();
        for id in ids {
            self.stop_recording(&id, RecordingCloseReason::SessionClosed);
        }
    }

    /// The fetch deadline of recording `serial` passed: a running recording whose
    /// body nobody took is stopped (`not_fetched`, which its `closed` says
    /// even when its worker's last bytes found the pipe full), and a
    /// finished one's body is dropped.
    pub(crate) fn recording_fetch_deadline(&mut self, recording_id: &str, serial: u64) {
        // A fetch aborts the timer; one that fired meanwhile finds no body.
        if let Some(entry) = self
            .recordings
            .get_mut(recording_id)
            .filter(|recording| recording.serial == serial && recording.body.is_some())
        {
            entry.expired = true;
            tracing::info!(
                recording.id = recording_id,
                stream.id = %entry.stream_id,
                "recording not fetched in time"
            );
            self.stop_recording(recording_id, RecordingCloseReason::NotFetched);
        } else if self
            .finished_recordings
            .get(recording_id)
            .is_some_and(|recording| recording.serial == serial)
        {
            self.finished_recordings.remove(recording_id);
            tracing::info!(
                recording.id = recording_id,
                "body of a finished recording not fetched in time; dropped"
            );
        }
    }

    /// The body of recording `recording_id`, handed out once: a running recording's, or
    /// the kept body of one that ended before it was fetched.
    pub(crate) fn take_recording_body(
        &mut self,
        recording_id: &str,
    ) -> Result<RecordingBody, RecordingBodyError> {
        if let Some(entry) = self.recordings.get_mut(recording_id) {
            let body = entry
                .body
                .take()
                .ok_or(RecordingBodyError::AlreadyFetched)?;
            // Fetched: the deadline has nothing left to do.
            entry.timer = None;
            return Ok(body);
        }
        self.finished_recordings
            .remove(recording_id)
            .map(|recording| recording.body)
            .ok_or(RecordingBodyError::NotFound)
    }

    /// Whether `recording_id` names a recording that runs, one its worker is still
    /// finishing, or a body still to fetch: a new recording may not take it.
    pub(crate) fn recording_id_in_use(&self, recording_id: &str) -> bool {
        self.recordings.contains_key(recording_id)
            || self.stopping_recordings.contains_key(recording_id)
            || self.finished_recordings.contains_key(recording_id)
    }

    /// The recordings `limits.max_recordings` counts: those that run, those their
    /// worker is still finishing, and the bodies that wait for their `GET`,
    /// each holding a pipe's end in one process or the other.
    pub(crate) fn recordings_held(&self) -> usize {
        self.recordings
            .len()
            .saturating_add(self.stopping_recordings.len())
            .saturating_add(self.finished_recordings.len())
    }

    /// Whether the start of recording `recording_id`, `serial`, which the driver is
    /// about to hand to a worker, is still wanted: only while that recording
    /// runs. One that ended meanwhile is dropped with its pipe, and since
    /// no worker got it, an id its end held is free.
    pub(crate) fn recording_start_wanted(&mut self, recording_id: &str, serial: u64) -> bool {
        if self
            .recordings
            .get(recording_id)
            .is_some_and(|recording| recording.serial == serial)
        {
            return true;
        }
        if self
            .stopping_recordings
            .get(recording_id)
            .is_some_and(|recording| recording.serial == serial)
        {
            self.stopping_recordings.remove(recording_id);
        }
        tracing::debug!(
            recording.id = recording_id,
            serial,
            "recording ended before its worker got it; its start is dropped"
        );
        false
    }

    /// Connection `connection`'s worker exited: its recordings end
    /// `worker_crashed`, their bodies cut, and the ids of the recordings it was
    /// finishing are free, as it reports nothing more.
    pub(crate) fn recordings_worker_gone(&mut self, connection: &str) {
        self.end_recordings_where(
            |recording| recording.connection == connection,
            RecordingCloseReason::WorkerCrashed,
        );
        self.forget_stopping_recordings(connection);
    }

    /// The ids of the recordings `connection`'s worker was finishing are free:
    /// that worker exited, its driver stopped it for want of demand, or the
    /// connection was released and stops it, so their `Closed` reaches no
    /// one.
    pub(crate) fn forget_stopping_recordings(&mut self, connection: &str) {
        self.stopping_recordings.retain(|recording_id, recording| {
            let keep = recording.connection != connection;
            if !keep {
                tracing::debug!(
                    recording.id = %recording_id,
                    connection.id = connection,
                    "the worker of a recording that had ended is gone; its id is free"
                );
            }
            keep
        });
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

    /// A recording `k1` of `front` on `c1` asked with `audio`, and its events.
    fn entry(audio: bool) -> (RecordingEntry, mpsc::Receiver<Event>) {
        let (events, rx) = mpsc::channel(RECORDING_QUEUE);
        let (written, report) = oneshot::channel();
        let body = RecordingBody {
            reader: Box::new(tokio::io::empty()),
            written: report,
        };
        let spec = RecordingSpec {
            recording_id: "k1".into(),
            prerecord_ms: 10_000,
            duration_ms: 20_000,
            audio,
        };
        let owner = RecordingOwner {
            connection: ConnectionId(1),
            subscription: 9,
            events,
        };
        let entry = RecordingEntry::new(
            1,
            ("front".into(), "c1".into()),
            spec,
            owner,
            (body, written),
        );
        (entry, rx)
    }

    fn started(prerecord_ms: u32, video: &str, picture: Option<(u32, u32)>) -> RecordingReport {
        RecordingReport::Started {
            prerecord_ms,
            video: video.into(),
            picture,
            audio: None,
        }
    }

    fn applied(
        entry: &mut RecordingEntry,
        report: RecordingReport,
    ) -> Result<Applied, &'static str> {
        entry.apply("k1", report, UNIX_EPOCH)
    }

    fn passed(applied: Result<Applied, &'static str>) -> serde_json::Value {
        let_assert!(Ok(Applied::Event(event)) = applied);
        recording_event(&event).payload
    }

    #[test]
    fn the_defaults_are_the_worker_s_and_the_queue_holds_every_event() {
        assert_eq!(
            RECORDING_QUEUE,
            usize::try_from(MAX_GAP_EVENTS).unwrap() + 3,
            "started, the warning, the gaps and closed"
        );
        assert_eq!(
            usize::try_from(RecordingLimits::DEFAULT.max_prerecord_bytes).unwrap(),
            lotse_core::track::DEFAULT_PRERECORD_BYTES
        );
        assert_eq!(
            usize::try_from(RecordingLimits::DEFAULT.recording_queue_bytes).unwrap(),
            lotse_core::recording::DEFAULT_RECORDING_QUEUE_BYTES
        );
        assert_eq!(RecordingLimits::default(), RecordingLimits::NONE);
        assert_eq!(
            (
                RecordingLimits::NONE.max_recordings,
                RecordingLimits::NONE.max_prerecord_ms
            ),
            (0, 0)
        );
        assert!(completed(RecordingCloseReason::Completed));
        assert!(!completed(RecordingCloseReason::ClientGone));
    }

    #[test]
    fn the_pre_record_bound_is_half_the_worker_s_address_space() {
        assert_eq!(
            RecordingLimits::max_prerecord_bytes_for(1 << 30),
            RecordingLimits::DEFAULT.max_prerecord_bytes,
            "the default address space gives the default bound"
        );
        assert_eq!(RecordingLimits::max_prerecord_bytes_for(6), 3);
        assert_eq!(
            RecordingLimits::max_prerecord_bytes_for(7),
            3,
            "rounded down"
        );
    }

    #[test]
    fn started_passes_once_with_the_known_codecs_the_supervisor_stamps() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut recording, _rx) = entry(true);
        let mut report = started(9_800, "h264", Some((1920, 1080)));
        if let RecordingReport::Started { audio, .. } = &mut report {
            *audio = Some("aac_lc".into());
        }
        let at = UNIX_EPOCH + Duration::from_hours(489_202);
        let event = passed(recording.apply("k1", report, at));
        assert_eq!(
            event,
            json!({ "type": "started", "recording_id": "k1", "at": "2025-10-22T10:00:00.000Z",
                    "prerecord_ms": 9_800,
                    "video": { "codec": "h264", "width": 1920, "height": 1080 },
                    "audio": { "codec": "aac_lc" } })
        );
        let lines = captured.lines("recording: started");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("prerecord_ms_asked=10000") && lines[0].contains("audio=\"aac_lc\""),
            "{lines:?}"
        );
        // Once only.
        assert_eq!(
            applied(&mut recording, started(0, "h264", None)).unwrap_err(),
            "a second started"
        );
        // Without a picture or audio.
        let (mut recording, _rx) = entry(false);
        let event = passed(applied(&mut recording, started(0, "h265", None)));
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
                RecordingReport::Started {
                    prerecord_ms: 0,
                    video: "h264".into(),
                    picture: None,
                    audio: Some("pcmu".into()),
                },
                true,
                "started names an unknown audio codec",
            ),
            (
                RecordingReport::Started {
                    prerecord_ms: 0,
                    video: "h264".into(),
                    picture: None,
                    audio: Some("opus".into()),
                },
                false,
                "started has audio not asked for",
            ),
        ];
        for (report, audio, reason) in cases {
            let (mut recording, _rx) = entry(audio);
            assert_eq!(applied(&mut recording, report).unwrap_err(), reason);
            assert!(!recording.started);
        }
    }

    /// A recording's media times are the worker's measure, which no limit
    /// bounds: the ring trims by time only at keyframes, so with a
    /// 14-minute GOP that fits `max_prerecord_bytes` (a low-bitrate camera) the
    /// recording starts at a keyframe 840 s old, past the longest window and
    /// recording, and its file runs on from there. Each report passes as the
    /// worker made it, and the recording ends with its figures, its body whole.
    /// Regression: `prerecord_ms` past the window, the longest recording and a
    /// minute ended the recording `internal_error`, its body cut, and so did a
    /// gap or a duration past them.
    #[test]
    fn a_recording_from_a_keyframe_older_than_any_limit_passes_its_media_times_as_measured() {
        let (mut recording, _rx) = entry(false);
        let event = passed(applied(&mut recording, started(840_000, "h264", None)));
        assert_eq!(event["prerecord_ms"], 840_000);
        let gap = RecordingReport::Gap {
            reason: "reconnect".into(),
            from_ms: 900_000,
            to_ms: u32::MAX,
        };
        let event = passed(applied(&mut recording, gap));
        assert_eq!(
            (&event["from_ms"], &event["to_ms"]),
            (&json!(900_000), &json!(u32::MAX))
        );
        let closed = RecordingReport::Closed {
            reason: "completed".into(),
            bytes: 7,
            duration_ms: u32::MAX,
            gaps: 1,
        };
        let_assert!(Ok(Applied::End(end)) = applied(&mut recording, closed));
        assert_eq!(
            end,
            RecordingEnd::Reported {
                reason: RecordingCloseReason::Completed,
                bytes: 7,
                duration_ms: u32::MAX,
                gaps: 1,
            }
        );
        let (mut recording, _rx) = entry(false);
        let event = passed(applied(&mut recording, started(u32::MAX, "h265", None)));
        assert_eq!(event["prerecord_ms"], u32::MAX);
    }

    #[test]
    fn iso14496_12_8_3_2_3_a_picture_side_tkhd_cannot_hold_or_zero_is_refused() {
        for picture in [(0, 1080), (1920, 0), (65_536, 1080), (1920, 65_536)] {
            let (mut recording, _rx) = entry(false);
            assert_eq!(
                applied(&mut recording, started(0, "h264", Some(picture))).unwrap_err(),
                "started picture out of bounds",
                "{picture:?}"
            );
        }
        let (mut recording, _rx) = entry(false);
        let event = passed(applied(
            &mut recording,
            started(0, "h264", Some((65_535, 1))),
        ));
        assert_eq!(event["video"]["width"], 65_535);
    }

    #[test]
    fn a_warning_passes_once_plain_and_a_repeated_or_unknown_one_is_dropped_and_logged_once() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut recording, _rx) = entry(true);
        let warning = |code: &str, message: &str| RecordingReport::Warning {
            code: code.into(),
            message: message.into(),
        };
        let event = passed(applied(
            &mut recording,
            warning("audio_omitted", &format!("pcmu\nforged{}", "x".repeat(600))),
        ));
        assert_eq!(event["code"], "audio_omitted");
        let message = event["message"].as_str().unwrap();
        assert!(message.starts_with("pcmu forged"), "{message}");
        assert!(message.len() <= MAX_MESSAGE_BYTES);
        assert_eq!(captured.lines("recording warning").len(), 1);
        for code in ["audio_omitted", "bogus\ncode"] {
            assert!(matches!(
                applied(&mut recording, warning(code, "again")),
                Ok(Applied::Nothing)
            ));
            // The first drop is logged, at once; the later ones are not.
            let dropped = captured.lines("a worker repeated a recording warning");
            assert_eq!(dropped.len(), 1, "{dropped:?}");
        }
        assert_eq!(recording.warnings_dropped, 2);
    }

    #[test]
    fn gaps_pass_with_a_known_reason_in_order_and_up_to_the_cap() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut recording, _rx) = entry(false);
        let gap = |reason: &str, from_ms: u32, to_ms: u32| RecordingReport::Gap {
            reason: reason.into(),
            from_ms,
            to_ms,
        };
        let event = passed(applied(&mut recording, gap("reconnect", 12_040, 15_310)));
        assert_eq!(
            event,
            json!({ "type": "gap", "reason": "reconnect", "from_ms": 12_040, "to_ms": 15_310 })
        );
        for (report, reason) in [
            (gap("solar_flare", 0, 1), "gap names an unknown reason"),
            (gap("lagged", 2, 1), "gap ends before it begins"),
        ] {
            assert_eq!(applied(&mut recording, report).unwrap_err(), reason);
        }
        // A gap may be empty.
        assert!(applied(&mut recording, gap("lagged", 1, 1)).is_ok());
        for _ in 2..MAX_GAP_EVENTS {
            assert!(applied(&mut recording, gap("overflow", 1, 1)).is_ok());
        }
        assert_eq!(
            applied(&mut recording, gap("overflow", 1, 1)).unwrap_err(),
            "more gaps than a recording reports"
        );
        assert_eq!(recording.gaps, MAX_GAP_EVENTS);
        let passed = captured.lines("recording gap passed on");
        assert_eq!(passed.len(), 256);
        assert!(passed[0].contains("reason=\"reconnect\""), "{passed:?}");
    }

    #[test]
    fn closed_maps_the_worker_s_reason_and_puts_the_supervisor_s_own_in_for_its_stop() {
        let closed = |reason: &str, duration_ms: u32, gaps: u32| RecordingReport::Closed {
            reason: reason.into(),
            bytes: 7,
            duration_ms,
            gaps,
        };
        let end = |recording: &mut RecordingEntry, report| {
            let_assert!(
                Ok(Applied::End(RecordingEnd::Reported { reason, .. })) =
                    applied(recording, report)
            );
            reason
        };
        let (mut recording, _rx) = entry(false);
        assert_eq!(
            end(&mut recording, closed("completed", 1, 0)),
            RecordingCloseReason::Completed
        );
        // A reader gone that no stop of the supervisor's ended stays.
        assert_eq!(
            end(&mut recording, closed("client_gone", 1, 0)),
            RecordingCloseReason::ClientGone
        );
        // A stop the supervisor did not ask for breaks the contract.
        assert_eq!(
            applied(&mut recording, closed("stopped", 1, 0)).unwrap_err(),
            "closed ends a stop the supervisor did not ask for"
        );
        recording.ending = Some(RecordingCloseReason::NotFetched);
        assert_eq!(
            end(&mut recording, closed("stopped", 1, 0)),
            RecordingCloseReason::NotFetched
        );
        // A worker whose stop found the pipe full (nobody fetched the body)
        // ends it `client_gone`, the tail counted in its bytes: a reason of
        // the supervisor's that says the file is not whole stays, the
        // figures as reported.
        let_assert!(
            Ok(Applied::End(RecordingEnd::Reported { reason, bytes, .. })) =
                applied(&mut recording, closed("client_gone", 1, 0))
        );
        assert_eq!((reason, bytes), (RecordingCloseReason::NotFetched, 7));
        recording.ending = Some(RecordingCloseReason::SessionClosed);
        assert_eq!(
            end(&mut recording, closed("client_gone", 1, 0)),
            RecordingCloseReason::SessionClosed
        );
        // A worker that ended it otherwise first keeps its reason.
        recording.ending = Some(RecordingCloseReason::NotFetched);
        assert_eq!(
            end(&mut recording, closed("stream_changed", 1, 0)),
            RecordingCloseReason::StreamChanged
        );
        // A reason the worker may not give breaks the contract: its
        // figures are not believed.
        for reason in [
            "worker_crashed",
            "session_closed",
            "not_fetched",
            "bogus\nreason",
        ] {
            assert_eq!(
                applied(&mut recording, closed(reason, 1, 0)).unwrap_err(),
                "closed names a reason the worker may not give"
            );
        }
        // A worker's own internal error is one it may give.
        assert_eq!(
            end(&mut recording, closed("internal_error", 1, 0)),
            RecordingCloseReason::InternalError
        );
        recording.gaps = 2;
        assert_eq!(
            applied(&mut recording, closed("completed", 1, 1)).unwrap_err(),
            "closed counts fewer gaps than were reported"
        );
        let_assert!(
            Ok(Applied::End(RecordingEnd::Reported {
                bytes,
                duration_ms,
                gaps,
                ..
            })) = applied(&mut recording, closed("completed", 1, 2))
        );
        assert_eq!((bytes, duration_ms, gaps), (7, 1, 2));
    }

    #[tokio::test]
    async fn events_go_to_the_owner_while_it_listens_and_a_stop_takes_its_slot_once() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut recording, mut rx) = entry(false);
        assert!(recording.owned_by(ConnectionId(1), 9));
        assert!(!recording.owned_by(ConnectionId(1), 8));
        assert!(!recording.owned_by(ConnectionId(2), 9));
        let gap = RecordingEvent::Gap {
            reason: RecordingGapReason::Lagged,
            from_ms: 1,
            to_ms: 2,
        };
        recording.deliver("k1", &gap);
        let delivered = rx.recv().await.unwrap();
        assert_eq!(delivered.class, EventClass::Signaling);
        assert_eq!(delivered.payload["reason"], "lagged");
        drop(rx);
        recording.deliver("k1", &gap);
        assert_eq!(
            captured
                .lines("recording subscription gone; event dropped")
                .len(),
            1
        );
        // The stop goes through the reserved slot, once.
        let (commands, mut queue) = mpsc::channel(1);
        recording.stop_slot = Some(commands.clone().try_reserve_owned().unwrap());
        recording.ask_stop("k1");
        recording.ask_stop("k1");
        let_assert!(Some(DriverCommand::StopRecording { recording_id }) = queue.recv().await);
        assert_eq!(recording_id, "k1");
        assert!(queue.try_recv().is_err());
        // A timer is aborted with what it was for.
        let task = lotse_core::task::spawn_named("test.timer", std::future::pending::<()>());
        drop(RecordingTimer(task.abort_handle()));
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
