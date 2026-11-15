//! LL-HLS sessions as the supervisor keeps them: the live outputs whose
//! records it reads into an LL-HLS window itself, the sessions that play
//! them, and the answers to their HTTP requests (`lotse_api_types::hls`,
//! `lotse_api::hls`).
//!
//! An HLS output is a framed live output (`lotse_ipc::fragments`) with no
//! owner: it is created as `live/create` creates one, its start handed to
//! the stream's connection with the write end of a pipe, and it is demand
//! on that connection as a viewer is. The supervisor reads the pipe from the
//! start (`hls.reader`), and once the worker's `Started` comes it tells the
//! worker a reader took it, at once and with no fetch deadline. The first
//! record makes the window ([`Window::new`]), each later one is pushed into
//! it, and a push that publishes a part wakes the blocked requests. The
//! records are untrusted: a broken one, a second init segment or a fragment
//! before the first ends the output `internal_error`; one the window cannot
//! hold (no keyframe within `limits.hls_window_bytes`) ends it
//! `window_full`.
//!
//! The sessions of one stream and audio choice share its one output: the
//! first `hls/create` starts it, those that come while it starts wait for
//! the same start (`limits.live_start_timeout_ms` and the slack of
//! `live/create`), later ones join it. Each session has its own id, a ULID,
//! its own subscription and its own idle clock. A session ends on
//! `hls/close` (`closed`), its subscription or control connection gone
//! (`session_closed`), no request within `limits.hls_idle_timeout_ms`
//! (`idle`), or its output's end; the output ends when its last session
//! leaves, and with it, at once, every session, with the reason mapped from
//! its live output's ([`hls_reason`]). An output counts against the live
//! outputs' limits too, being one.
//!
//! Requests are answered from the window (draft-pantos-hls-rfc8216bis-22):
//! a Blocking Playlist Reload (§6.2.5.2) or a request for the part a Preload
//! Hint names (§4.4.5.3) waits for a push to publish what it asks for, as
//! does any request before the first segment completes. A wait is bounded:
//! by [`HlsLimits::max_blocked_per_session`] and [`HlsLimits::max_blocked`]
//! at once (over is 429, RFC 6585 §4), and in time by three Target
//! Durations (§6.2.5.2: "the server SHOULD return Service Unavailable"),
//! before the first segment by the live start timeout. A request whose
//! session ends while it waits is answered as one for no session.
//!
//! The windows hold at most [`HlsLimits::max_outputs`] times
//! [`HlsLimits::window_bytes`] of media in the supervisor, the init segments
//! besides.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use lotse_api::{ConnectionId, Event, EventClass, HlsError, HlsReply, HlsRequest};
use lotse_api_types::command::HlsCreate;
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::hls::{HlsCloseReason, HlsCreateResult, HlsEvent, hls_playlist_path};
use lotse_api_types::live::{LiveCloseReason, LiveWarningCode};
use lotse_core::id::{HlsId, StreamId};
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use lotse_hls::{Config, Fragment, Lookup, PushError, Pushed, Reload, Window};
use lotse_ipc::LiveSpec;
use lotse_ipc::fragments::{Decoder, Record, RecordKind};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::net::unix::pipe;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::driver::DriverCommand;
use crate::handler::{
    LIVE_CREATE_SLACK, SessionConnection, check_live_limits, hand_over_live, internal,
    session_connection,
};
use crate::live::{LIVE_QUEUE, LiveEntry, LiveOwner};
use crate::recording::RecordingTimer;
use crate::registry::{Shared, State};
use crate::session::ulid;

/// The most bytes read from an output's pipe at once: a Linux pipe's
/// default capacity (pipe(7)).
const READ_BYTES: usize = 64 * 1024;

/// How many Target Durations a blocked request waits before it is answered
/// Service Unavailable (draft-pantos-hls-rfc8216bis-22 §6.2.5.2: "If the
/// server cannot fulfill the request within three Target Durations").
const BLOCK_TARGET_DURATIONS: u32 = 3;

/// The limits on LL-HLS, `limits.*hls*` as the binary resolves them. A
/// supervisor without LL-HLS (no live container, or a build without
/// `output-hls`) keeps none and refuses every `hls/create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HlsLimits {
    /// `limits.max_hls_outputs`: outputs (windows) at once over every
    /// stream; with [`Self::window_bytes`] the bound on the media the
    /// supervisor holds.
    pub max_outputs: u32,
    /// `limits.max_hls_sessions`: sessions at once over every stream.
    pub max_sessions: u32,
    /// `limits.max_hls_sessions_per_stream`: sessions at once on one stream.
    pub max_sessions_per_stream: u32,
    /// `limits.hls_window_bytes`: the media one window holds
    /// ([`Config::max_bytes`]).
    pub window_bytes: u32,
    /// `limits.hls_part_target_ms`: the part target a window closes parts
    /// at until its first segment measures the Part Target Duration
    /// ([`Config::part_target`]).
    pub part_target: Duration,
    /// `limits.hls_segment_target_ms`: the duration after which the next
    /// keyframe starts a segment ([`Config::segment_target`]).
    pub segment_target: Duration,
    /// `limits.hls_idle_timeout_ms`: how long a session lives without a
    /// request.
    pub idle_timeout: Duration,
    /// `limits.max_hls_blocked_per_session`: requests of one session blocked
    /// at once.
    pub max_blocked_per_session: u32,
    /// `limits.max_hls_blocked`: requests blocked at once over every
    /// session.
    pub max_blocked: u32,
}

impl HlsLimits {
    /// The defaults:
    ///
    /// - 8 outputs: one per camera of a home with a few, each watched in one
    ///   or two players at once, half `limits.max_live`'s 16, which they
    ///   count against; with the window's 32 MiB at most 256 MiB of media.
    /// - 32 sessions, 8 per stream: a session is one player, a dashboard
    ///   shows a camera on a few screens.
    /// - The window's own defaults: 32 MiB ([`lotse_hls::DEFAULT_MAX_BYTES`]),
    ///   200 ms parts ([`lotse_hls::DEFAULT_PART_TARGET`]) and 1 s segments
    ///   ([`lotse_hls::DEFAULT_SEGMENT_TARGET`]); each says why.
    /// - 30 s idle: a player asks every part, five times a second, and a
    ///   paused one reloads the playlist every Target Duration
    ///   (draft-pantos-hls-rfc8216bis-22 §6.3.4); 30 s without a request is
    ///   a player gone, and short enough that its camera is released soon.
    /// - 4 blocked requests a session: a player holds two, the playlist
    ///   reload and the hinted part (§6.2.5.2, §4.4.5.3), twice that leaves
    ///   room for a retry; 128 in all, four for each of 32 sessions.
    pub const DEFAULT: Self = Self {
        max_outputs: 8,
        max_sessions: 32,
        max_sessions_per_stream: 8,
        window_bytes: 32 * 1024 * 1024,
        part_target: lotse_hls::DEFAULT_PART_TARGET,
        segment_target: lotse_hls::DEFAULT_SEGMENT_TARGET,
        idle_timeout: Duration::from_secs(30),
        max_blocked_per_session: 4,
        max_blocked: 128,
    };

    /// The window an output of these limits builds.
    fn window(&self) -> Config {
        Config {
            part_target: self.part_target,
            segment_target: self.segment_target,
            segments: lotse_hls::DEFAULT_SEGMENTS,
            max_bytes: usize::try_from(self.window_bytes).unwrap_or(usize::MAX),
        }
    }
}

/// A cap whose refusal a client can repeat; each has its own rate-limited
/// warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cap {
    /// [`HlsLimits::max_outputs`].
    Outputs,
    /// [`HlsLimits::max_sessions`].
    Sessions,
    /// [`HlsLimits::max_sessions_per_stream`].
    SessionsPerStream,
    /// [`HlsLimits::max_blocked_per_session`].
    BlockedPerSession,
    /// [`HlsLimits::max_blocked`].
    Blocked,
}

impl Cap {
    /// The limit's name, as `details.limit` and the configuration say it.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Outputs => "max_hls_outputs",
            Self::Sessions => "max_hls_sessions",
            Self::SessionsPerStream => "max_hls_sessions_per_stream",
            Self::BlockedPerSession => "max_hls_blocked_per_session",
            Self::Blocked => "max_hls_blocked",
        }
    }
}

/// The rate limits of the caps' warnings, one each.
#[derive(Debug, Default)]
struct Caps {
    /// [`Cap::Outputs`].
    outputs: Throttle,
    /// [`Cap::Sessions`].
    sessions: Throttle,
    /// [`Cap::SessionsPerStream`].
    sessions_per_stream: Throttle,
    /// [`Cap::BlockedPerSession`].
    blocked_per_session: Throttle,
    /// [`Cap::Blocked`].
    blocked: Throttle,
}

impl Caps {
    /// The rate limit of `cap`'s warning.
    const fn of(&mut self, cap: Cap) -> &mut Throttle {
        match cap {
            Cap::Outputs => &mut self.outputs,
            Cap::Sessions => &mut self.sessions,
            Cap::SessionsPerStream => &mut self.sessions_per_stream,
            Cap::BlockedPerSession => &mut self.blocked_per_session,
            Cap::Blocked => &mut self.blocked,
        }
    }
}

/// Where an output's start stands, as the creates waiting for it see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Start {
    /// The worker has not written the init segment yet.
    Starting,
    /// Started, with the MIME type of its media.
    Started(String),
    /// Ended, for this reason.
    Ended(HlsCloseReason),
}

impl Start {
    /// What a create waiting for the start gets: the MIME type or why the
    /// output ended; `None` while it starts.
    fn outcome(&self) -> Option<Result<String, HlsCloseReason>> {
        match self {
            Self::Starting => None,
            Self::Started(mime) => Some(Ok(mime.clone())),
            Self::Ended(reason) => Some(Err(*reason)),
        }
    }
}

/// An output's window, shared by its reader, which fills it, and the
/// requests, which read it; a publish counter wakes the blocked ones.
#[derive(Debug)]
pub(crate) struct Feed {
    /// The window, from the init segment on.
    window: Mutex<Option<Window>>,
    /// Counts the pushes that published: a change wakes every blocked
    /// request, which asks the window again.
    published: watch::Sender<u64>,
}

/// What a request gets from a window now.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// Its answer.
    Done(Result<HlsReply, HlsError>),
    /// Nothing yet: it waits for the next publish.
    Wait,
}

impl Feed {
    /// A feed with no window yet.
    fn new() -> Self {
        Self {
            window: Mutex::new(None),
            published: watch::Sender::new(0),
        }
    }

    /// The window; a poisoned lock is still usable, a push changes it whole
    /// or not at all.
    fn lock(&self) -> MutexGuard<'_, Option<Window>> {
        self.window.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes one record of the pipe; the reason the output ends at it. The
    /// blocked requests are woken after the window is unlocked.
    fn take(&self, record: Record, config: Config) -> Result<(), HlsCloseReason> {
        if push_record(&mut self.lock(), record, config)? {
            self.published
                .send_modify(|count| *count = count.wrapping_add(1));
        }
        Ok(())
    }

    /// What `request` gets from the window now.
    fn answer(&self, request: HlsRequest) -> Answer {
        answer_from(self.lock().as_ref(), request)
    }

    /// How long a blocked request waits: three Target Durations once the
    /// window publishes (draft-pantos-hls-rfc8216bis-22 §6.2.5.2), `before`
    /// until then.
    fn block_bound(&self, before: Duration) -> Duration {
        self.lock()
            .as_ref()
            .and_then(Window::target_duration)
            .map_or(before, |target| {
                target.saturating_mul(BLOCK_TARGET_DURATIONS)
            })
    }
}

/// Takes one record into `window`, made by the first; whether a part was
/// published, or the reason the output ends at the record.
fn push_record(
    window: &mut Option<Window>,
    record: Record,
    config: Config,
) -> Result<bool, HlsCloseReason> {
    match (record.kind, window.as_mut()) {
        (RecordKind::Init, None) => {
            *window = Some(Window::new(config, record.bytes).map_err(|error| {
                tracing::error!(%error, "LL-HLS window refused its configuration");
                HlsCloseReason::InternalError
            })?);
            Ok(false)
        }
        (RecordKind::Init, Some(_)) => {
            tracing::warn!("LL-HLS records: a second init segment");
            Err(HlsCloseReason::InternalError)
        }
        (RecordKind::Fragment { .. }, None) => {
            tracing::warn!("LL-HLS records: a fragment before the init segment");
            Err(HlsCloseReason::InternalError)
        }
        (
            RecordKind::Fragment {
                independent,
                duration,
            },
            Some(window),
        ) => match window.push(Fragment {
            bytes: record.bytes,
            independent,
            duration,
        }) {
            Ok(pushed) => Ok(pushed == Pushed::Published),
            Err(PushError::Overflow { max_bytes }) => {
                tracing::warn!(
                    max_bytes,
                    "LL-HLS window full: the stream sent no keyframe within the window's bytes"
                );
                Err(HlsCloseReason::WindowFull)
            }
        },
    }
}

/// What `request` gets from `window` now; nothing before the window is
/// made.
fn answer_from(window: Option<&Window>, request: HlsRequest) -> Answer {
    let Some(window) = window else {
        return Answer::Wait;
    };
    match request {
        HlsRequest::Playlist(blocking) => match window.reload(blocking) {
            Reload::Ready => window.playlist().map_or(Answer::Wait, |text| {
                Answer::Done(Ok(HlsReply::Playlist(text)))
            }),
            Reload::Wait => Answer::Wait,
            Reload::BadRequest => Answer::Done(Err(HlsError::BadRequest)),
        },
        HlsRequest::Media(resource) => match window.get(resource) {
            Lookup::Ready(chunks) => Answer::Done(Ok(HlsReply::Media(chunks))),
            Lookup::Wait => Answer::Wait,
            Lookup::NotFound => Answer::Done(Err(HlsError::ResourceNotFound)),
        },
    }
}

/// One LL-HLS output: a live output's window and the sessions' shared
/// start.
#[derive(Debug)]
pub(crate) struct HlsOutput {
    /// The stream it plays.
    stream_id: String,
    /// Whether it takes the stream's audio.
    audio: bool,
    /// Its window.
    feed: Arc<Feed>,
    /// Its start, for the creates waiting for it.
    start: watch::Sender<Start>,
    /// The worker's warning, for the sessions that join later.
    warning: Option<(LiveWarningCode, String)>,
    /// Its reader, aborted when the output ends.
    _reader: RecordingTimer,
}

/// One LL-HLS session.
#[derive(Debug)]
pub(crate) struct HlsSession {
    /// Unique over the daemon's lifetime, so its idle timer never acts on a
    /// later session.
    serial: u64,
    /// Its output: the live output's id.
    output: String,
    /// Its output's window: the session ends with its output, so it never
    /// outlives the window it serves.
    feed: Arc<Feed>,
    /// The stream it plays.
    stream_id: String,
    /// The subscription that gets its events.
    owner: LiveOwner,
    /// Its last request, or its create.
    touched: Instant,
    /// Its requests blocked at once, against
    /// [`HlsLimits::max_blocked_per_session`].
    blocked: Arc<Semaphore>,
    /// Cancelled when the session ends: its blocked requests end.
    gone: CancellationToken,
    /// Cancels [`Self::gone`] when the session is dropped.
    _gone: DropGuard,
    /// Its idle timer, aborted when the session ends.
    _idle: RecordingTimer,
}

impl HlsSession {
    /// Passes `event` to the owner; a full or closed subscription drops it.
    fn deliver(&self, hls_id: &str, event: &HlsEvent) {
        let payload = Event {
            class: EventClass::Signaling,
            payload: serde_json::to_value(event).unwrap_or_default(),
        };
        if self.owner.events.try_send(payload).is_err() {
            tracing::debug!(
                hls.id = hls_id,
                "LL-HLS event dropped: its subscription is gone or full"
            );
        }
    }
}

/// The LL-HLS outputs and sessions, and what bounds them.
#[derive(Debug)]
pub(crate) struct Hls {
    /// The limits; `None` without LL-HLS.
    pub(crate) limits: Option<HlsLimits>,
    /// The outputs, by their live output's id.
    outputs: BTreeMap<String, HlsOutput>,
    /// The sessions, by id.
    sessions: BTreeMap<String, HlsSession>,
    /// The serial of the last session.
    last: u64,
    /// Requests blocked at once over every session, against
    /// [`HlsLimits::max_blocked`].
    blocked: Arc<Semaphore>,
    /// The rate limits of the caps' warnings.
    caps: Caps,
}

impl Default for Hls {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Hls {
    /// No output and no session, under `limits`.
    pub(crate) fn new(limits: Option<HlsLimits>) -> Self {
        let blocked = limits.map_or(0, |limits| {
            usize::try_from(limits.max_blocked).unwrap_or(usize::MAX)
        });
        Self {
            limits,
            outputs: BTreeMap::new(),
            sessions: BTreeMap::new(),
            last: 0,
            blocked: Arc::new(Semaphore::new(blocked.min(Semaphore::MAX_PERMITS))),
            caps: Caps::default(),
        }
    }
}

/// The session's reason for its output's live output ending for `reason`:
/// the same, but for what only a fetched body can end with
/// (`client_gone`, `not_fetched`), which the supervisor reading the output
/// itself makes a broken contract.
const fn hls_reason(reason: LiveCloseReason) -> HlsCloseReason {
    match reason {
        LiveCloseReason::Closed => HlsCloseReason::Closed,
        LiveCloseReason::SessionClosed => HlsCloseReason::SessionClosed,
        LiveCloseReason::StreamDeleted => HlsCloseReason::StreamDeleted,
        LiveCloseReason::StreamChanged => HlsCloseReason::StreamChanged,
        LiveCloseReason::CodecChanged => HlsCloseReason::CodecChanged,
        LiveCloseReason::NoVideoTrack => HlsCloseReason::NoVideoTrack,
        LiveCloseReason::SourceNotLive => HlsCloseReason::SourceNotLive,
        LiveCloseReason::WorkerCrashed => HlsCloseReason::WorkerCrashed,
        LiveCloseReason::ShuttingDown => HlsCloseReason::ShuttingDown,
        LiveCloseReason::ClientGone
        | LiveCloseReason::NotFetched
        | LiveCloseReason::InternalError => HlsCloseReason::InternalError,
    }
}

/// The live output's reason when its LL-HLS output ends for `reason` of
/// the supervisor's own: what its worker's stop and the log say.
const fn live_reason(reason: HlsCloseReason) -> LiveCloseReason {
    match reason {
        HlsCloseReason::SourceNotLive => LiveCloseReason::SourceNotLive,
        HlsCloseReason::ShuttingDown => LiveCloseReason::ShuttingDown,
        HlsCloseReason::InternalError => LiveCloseReason::InternalError,
        _ => LiveCloseReason::Closed,
    }
}

/// The error `hls/create` answers with when its output ended for `reason`
/// before its init segment.
fn start_error(reason: HlsCloseReason) -> ApiError {
    match reason {
        HlsCloseReason::NoVideoTrack => {
            ApiError::new(ErrorCode::NoVideoTrack, "the stream has no video track")
        }
        HlsCloseReason::SourceNotLive => ApiError::new(
            ErrorCode::SourceNotLive,
            "the stream showed no video the live container carries in time",
        ),
        HlsCloseReason::WorkerCrashed => ApiError::new(
            ErrorCode::WorkerCrashed,
            "the camera's worker process exited",
        ),
        HlsCloseReason::ShuttingDown => ApiError::new(ErrorCode::ShuttingDown, "shutting down"),
        HlsCloseReason::StreamDeleted => {
            ApiError::new(ErrorCode::StreamNotFound, "the stream was deleted")
        }
        other => ApiError::new(
            ErrorCode::InternalError,
            "the LL-HLS output ended before it started",
        )
        .with_detail("reason", other.as_str()),
    }
}

/// `hls_not_found` for `hls_id`.
fn not_found(hls_id: &str) -> ApiError {
    ApiError::new(ErrorCode::HlsNotFound, "no open LL-HLS session has this id")
        .with_detail("hls_id", hls_id)
}

impl State {
    /// `limit_reached` for `cap`, its warning logged rate-limited on the
    /// cap's own interval, as a client can ask again and again.
    fn hls_refused(&mut self, cap: Cap, stream_id: &str) -> ApiError {
        let now = self.signaling.clock.now();
        if let Some(count) = self.hls.caps.of(cap).hit(now) {
            tracing::warn!(
                stream.id = stream_id,
                limit = cap.as_str(),
                outputs = self.hls.outputs.len(),
                sessions = self.hls.sessions.len(),
                count,
                "LL-HLS refused at its limit"
            );
        }
        ApiError::new(ErrorCode::LimitReached, "an LL-HLS limit is reached")
            .with_detail("limit", cap.as_str())
    }

    /// The open output of `stream_id` and `audio` a session joins: not one
    /// whose live output is being stopped.
    fn hls_output_of(&self, stream_id: &str, audio: bool) -> Option<Joined> {
        self.hls
            .outputs
            .iter()
            .find(|(live_id, output)| {
                output.stream_id == stream_id
                    && output.audio == audio
                    && self
                        .lives
                        .get(*live_id)
                        .is_some_and(|live| live.ending.is_none())
            })
            .map(|(live_id, output)| Joined::of(live_id, output))
    }

    /// Refuses a session on `stream_id` past the sessions' limits.
    fn check_hls_sessions(&mut self, stream_id: &str, limits: HlsLimits) -> Result<(), ApiError> {
        let on_stream = self
            .hls
            .sessions
            .values()
            .filter(|session| session.stream_id == stream_id)
            .count();
        if self.hls.sessions.len() >= usize::try_from(limits.max_sessions).unwrap_or(usize::MAX) {
            return Err(self.hls_refused(Cap::Sessions, stream_id));
        }
        if on_stream >= usize::try_from(limits.max_sessions_per_stream).unwrap_or(usize::MAX) {
            return Err(self.hls_refused(Cap::SessionsPerStream, stream_id));
        }
        Ok(())
    }

    /// The worker started live output `live_id` with `mime`: if it is an
    /// LL-HLS output, the worker is told its reader took it, and the creates
    /// waiting for it are answered.
    pub(crate) fn hls_live_started(&mut self, live_id: &str, mime: &str) {
        let Some(output) = self.hls.outputs.get(live_id) else {
            return;
        };
        if let Some(slot) = self
            .lives
            .get_mut(live_id)
            .and_then(|entry| entry.fetch_slot.take())
        {
            drop(slot.send(DriverCommand::FetchLive {
                live_id: live_id.to_owned(),
            }));
        }
        output.start.send_replace(Start::Started(mime.to_owned()));
        tracing::info!(
            event = "hls_output_started",
            live.id = live_id,
            stream.id = %output.stream_id,
            mime,
            "LL-HLS output started; its reader took it"
        );
    }

    /// The worker warned about live output `live_id`: if it is an LL-HLS
    /// output, every session gets the warning, and so do those that join
    /// later.
    pub(crate) fn hls_live_warned(&mut self, live_id: &str, code: LiveWarningCode, message: &str) {
        let Some(output) = self.hls.outputs.get_mut(live_id) else {
            return;
        };
        output.warning = Some((code, message.to_owned()));
        let event = HlsEvent::Warning {
            code,
            message: message.to_owned(),
        };
        for (hls_id, session) in &self.hls.sessions {
            if session.output == live_id {
                session.deliver(hls_id, &event);
            }
        }
    }

    /// Live output `live_id` is over for `reason`: if it is an LL-HLS
    /// output, it ends with it.
    pub(crate) fn hls_live_closed(&mut self, live_id: &str, reason: LiveCloseReason) {
        if self.hls.outputs.contains_key(live_id) {
            self.close_hls_output(live_id, hls_reason(reason));
        }
    }

    /// LL-HLS output `live_id` ends for `reason`, at once: its creates
    /// waiting are answered, its sessions get `closed` and end, their
    /// blocked requests with them, its reader stops, and its live output is
    /// stopped. Idempotent.
    pub(crate) fn close_hls_output(&mut self, live_id: &str, reason: HlsCloseReason) {
        let Some(output) = self.hls.outputs.remove(live_id) else {
            return;
        };
        output.start.send_replace(Start::Ended(reason));
        let (ended, kept): (BTreeMap<_, _>, BTreeMap<_, _>) =
            std::mem::take(&mut self.hls.sessions)
                .into_iter()
                .partition(|(_, session)| session.output == live_id);
        self.hls.sessions = kept;
        for (hls_id, session) in &ended {
            session.deliver(
                hls_id,
                &HlsEvent::Closed {
                    hls_id: hls_id.clone(),
                    reason,
                },
            );
            tracing::info!(event = "hls_session_closed", hls.id = %hls_id, live.id = live_id, reason = reason.as_str(), "LL-HLS session closed: its output ended");
        }
        tracing::info!(
            event = "hls_output_closed",
            live.id = live_id,
            stream.id = %output.stream_id,
            reason = reason.as_str(),
            sessions = ended.len(),
            "LL-HLS output closed"
        );
        drop(output);
        // Gone already when its worker ended it.
        if self.lives.contains_key(live_id) {
            self.end_live(live_id, live_reason(reason));
        }
    }

    /// LL-HLS session `hls_id` ends for `reason`; its owner gets `closed`
    /// unless `tell` is false (an `unsubscribe` answers for it). Its output
    /// ends with its last session. Whether there was one.
    pub(crate) fn close_hls_session(
        &mut self,
        hls_id: &str,
        reason: HlsCloseReason,
        tell: bool,
    ) -> bool {
        let Some(session) = self.hls.sessions.remove(hls_id) else {
            return false;
        };
        if tell {
            session.deliver(
                hls_id,
                &HlsEvent::Closed {
                    hls_id: hls_id.to_owned(),
                    reason,
                },
            );
        }
        tracing::info!(
            event = "hls_session_closed",
            hls.id = hls_id,
            live.id = %session.output,
            reason = reason.as_str(),
            "LL-HLS session closed"
        );
        let last = !self
            .hls
            .sessions
            .values()
            .any(|other| other.output == session.output);
        if last {
            tracing::info!(live.id = %session.output, "LL-HLS output's last session left; output ends");
            self.close_hls_output(&session.output, HlsCloseReason::Closed);
        }
        true
    }

    /// The control connection `connection` closed: its sessions end
    /// `session_closed`.
    pub(crate) fn hls_connection_closed(&mut self, connection: ConnectionId) {
        let ids: Vec<String> = self
            .hls
            .sessions
            .iter()
            .filter(|(_, session)| session.owner.connection == connection)
            .map(|(id, _)| id.clone())
            .collect();
        for hls_id in ids {
            self.close_hls_session(&hls_id, HlsCloseReason::SessionClosed, true);
        }
    }

    /// `unsubscribe` of `connection`'s `subscription`: the session it names
    /// ends `session_closed`, its `closed` left to the `unsubscribe`;
    /// whether there was one.
    pub(crate) fn unsubscribe_hls(&mut self, connection: ConnectionId, subscription: u64) -> bool {
        let found = self.hls.sessions.iter().find_map(|(id, session)| {
            (session.owner.connection == connection && session.owner.subscription == subscription)
                .then(|| id.clone())
        });
        found.is_some_and(|hls_id| {
            self.close_hls_session(&hls_id, HlsCloseReason::SessionClosed, false)
        })
    }

    /// The daemon stops: every output ends `shutting_down` at once, its
    /// worker's report not waited for.
    pub(crate) fn hls_shutdown(&mut self) {
        let ids: Vec<String> = self.hls.outputs.keys().cloned().collect();
        for live_id in ids {
            self.close_hls_output(&live_id, HlsCloseReason::ShuttingDown);
        }
    }
}

/// What `hls/create` registered: the session's events and the start it
/// waits for.
struct Registered {
    /// The live output.
    live_id: String,
    /// The session's events.
    events: mpsc::Receiver<Event>,
    /// The output's start.
    start: watch::Receiver<Start>,
}

/// What a new session takes of the output it joins or starts.
struct Joined {
    /// The live output.
    live_id: String,
    /// Its window.
    feed: Arc<Feed>,
    /// The worker's warning so far, which the session gets at once.
    warning: Option<(LiveWarningCode, String)>,
    /// Its start.
    start: watch::Receiver<Start>,
}

impl Joined {
    /// What a session takes of `live_id`'s `output`.
    fn of(live_id: &str, output: &HlsOutput) -> Self {
        Self {
            live_id: live_id.to_owned(),
            feed: Arc::clone(&output.feed),
            warning: output.warning.clone(),
            start: output.start.subscribe(),
        }
    }
}

/// `hls/create`: validates against the limits, joins the stream's output
/// of that audio choice or starts one, registers the session, and waits for
/// the output's start for at most `limits.live_start_timeout_ms` and the
/// slack of `live/create`. The command's future may be dropped at its wait:
/// the session stays registered with its owner, whose connection's close,
/// or the idle timeout, ends it.
pub(crate) async fn create(
    shared: &Arc<Shared>,
    connection: ConnectionId,
    create: &HlsCreate,
) -> Result<(HlsCreateResult, mpsc::Receiver<Event>), ApiError> {
    let stream_id = StreamId::new(&create.stream_id).map_err(|err| {
        ApiError::new(ErrorCode::InvalidStreamId, err.to_string())
            .with_detail("stream_id", create.stream_id.as_str())
    })?;
    let hls_id = HlsId::new(&ulid(shared.clock.wall_now()).map_err(internal)?).map_err(internal)?;
    let (registered, wait) = register_locked(shared, connection, create, &stream_id, &hls_id);
    let Registered {
        live_id,
        events,
        mut start,
    } = registered?;
    let outcome = tokio::select! {
        started = start.wait_for(|start| start.outcome().is_some()) => started
            .map_or(Err(HlsCloseReason::InternalError), |start| {
                start.outcome().unwrap_or(Err(HlsCloseReason::InternalError))
            }),
        () = shared.clock.sleep(wait) => Err(HlsCloseReason::SourceNotLive),
    };
    let now = shared.clock.now();
    let mime = shared.lock().hls_started(&hls_id, &live_id, outcome, now)?;
    let result = HlsCreateResult {
        playlist: hls_playlist_path(hls_id.as_str()),
        hls_id: hls_id.as_str().to_owned(),
        mime,
    };
    Ok((result, events))
}

impl State {
    /// The start session `hls_id` of output `live_id` waited for came out
    /// as `outcome` at `now`: its MIME type, its idle clock running from
    /// here; or the refusal, the output ended for its reason.
    fn hls_started(
        &mut self,
        hls_id: &HlsId,
        live_id: &str,
        outcome: Result<String, HlsCloseReason>,
        now: Instant,
    ) -> Result<String, ApiError> {
        let mime = outcome.map_err(|reason| {
            self.close_hls_output(live_id, reason);
            tracing::info!(hls.id = %hls_id, live.id = live_id, reason = reason.as_str(), "LL-HLS output ended before its init segment");
            start_error(reason).with_detail("hls_id", hls_id.as_str())
        })?;
        let session = self
            .hls
            .sessions
            .get_mut(hls_id.as_str())
            .ok_or_else(|| not_found(hls_id.as_str()))?;
        session.touched = now;
        Ok(mime)
    }
}

/// [`register`] under the lock, and how long the create waits for the
/// start: `limits.live_start_timeout_ms` and the slack of `live/create`.
fn register_locked(
    shared: &Arc<Shared>,
    connection: ConnectionId,
    create: &HlsCreate,
    stream_id: &StreamId,
    hls_id: &HlsId,
) -> (Result<Registered, ApiError>, Duration) {
    let mut state = shared.lock();
    let wait = state
        .live_limits
        .start_timeout
        .saturating_add(LIVE_CREATE_SLACK);
    let registered = register(shared, &mut state, connection, create, stream_id, hls_id);
    drop(state);
    (registered, wait)
}

/// Registers session `hls_id` of `create` on `state`: the checks, the
/// output joined or started, the session and its idle timer.
fn register(
    shared: &Arc<Shared>,
    state: &mut State,
    connection: ConnectionId,
    create: &HlsCreate,
    stream_id: &StreamId,
    hls_id: &HlsId,
) -> Result<Registered, ApiError> {
    let limits = state.hls.limits.ok_or_else(|| {
        ApiError::new(ErrorCode::LimitReached, "no LL-HLS in this build")
            .with_detail("limit", Cap::Outputs.as_str())
    })?;
    let Some(stream) = state.streams.get(stream_id.as_str()) else {
        return Err(ApiError::new(ErrorCode::StreamNotFound, "no such stream")
            .with_detail("stream_id", stream_id.as_str()));
    };
    let source = session_connection(state, stream)?;
    state.check_hls_sessions(stream_id.as_str(), limits)?;
    let (output, joined) = match state.hls_output_of(stream_id.as_str(), create.audio) {
        Some(output) => (output, true),
        None => (
            start_output(shared, state, stream_id, source, create.audio, limits)?,
            false,
        ),
    };
    let Joined {
        live_id,
        feed,
        warning,
        start,
    } = output;
    let (events, rx) = mpsc::channel(LIVE_QUEUE);
    let serial = state.hls.last.wrapping_add(1);
    state.hls.last = serial;
    let gone = CancellationToken::new();
    let now = shared.clock.now();
    let session = HlsSession {
        serial,
        output: live_id.clone(),
        feed,
        stream_id: stream_id.as_str().to_owned(),
        owner: LiveOwner {
            connection,
            subscription: create.id,
            events,
        },
        touched: now,
        blocked: Arc::new(Semaphore::new(
            usize::try_from(limits.max_blocked_per_session)
                .unwrap_or(usize::MAX)
                .min(Semaphore::MAX_PERMITS),
        )),
        _gone: gone.clone().drop_guard(),
        gone,
        _idle: idle_timer(shared, hls_id.as_str(), serial, limits.idle_timeout),
    };
    if let Some((code, message)) = warning {
        session.deliver(hls_id.as_str(), &HlsEvent::Warning { code, message });
    }
    state
        .hls
        .sessions
        .insert(hls_id.as_str().to_owned(), session);
    tracing::info!(
        event = "hls_session_opened",
        hls.id = %hls_id,
        live.id = %live_id,
        stream.id = %stream_id,
        control.connection = connection.0,
        joined,
        "LL-HLS session opened"
    );
    Ok(Registered {
        live_id,
        events: rx,
        start,
    })
}

/// Starts an LL-HLS output of `stream_id` on its `source` connection: a
/// framed live output whose pipe the supervisor reads itself; what a
/// session joins of it.
fn start_output(
    shared: &Arc<Shared>,
    state: &mut State,
    stream_id: &StreamId,
    source: SessionConnection,
    audio: bool,
    limits: HlsLimits,
) -> Result<Joined, ApiError> {
    if state.hls.outputs.len() >= usize::try_from(limits.max_outputs).unwrap_or(usize::MAX) {
        return Err(state.hls_refused(Cap::Outputs, stream_id.as_str()));
    }
    let live_limits = state.live_limits;
    check_live_limits(state, stream_id.as_str(), live_limits, "hls/create")?;
    let SessionConnection {
        id: connection_id,
        commands,
        ..
    } = source;
    let live_id = ulid(shared.clock.wall_now()).map_err(internal)?;
    let (reader, writer) = std::io::pipe().map_err(internal)?;
    let reader = pipe::Receiver::from_owned_fd(reader.into()).map_err(internal)?;
    let spec = LiveSpec {
        live_id: live_id.clone(),
        audio,
        buffer_bytes: live_limits.buffer_bytes,
        framed: true,
    };
    let (fetch_slot, stop_slot) = hand_over_live(&commands, spec, writer.into())?;
    let serial = state.last_live.saturating_add(1);
    state.last_live = serial;
    state.lives.insert(
        live_id.clone(),
        LiveEntry {
            serial,
            stream_id: stream_id.as_str().to_owned(),
            connection: connection_id.clone(),
            owner: None,
            waiting: None,
            mime: None,
            body: None,
            fetch_slot: Some(fetch_slot),
            stop_slot: Some(stop_slot),
            ending: None,
            warned: false,
            timer: None,
        },
    );
    let feed = Arc::new(Feed::new());
    let reader = spawn_named(
        "hls.reader",
        read(
            Arc::clone(shared),
            live_id.clone(),
            Box::new(reader),
            Arc::clone(&feed),
            limits.window(),
        ),
    );
    let output = HlsOutput {
        stream_id: stream_id.as_str().to_owned(),
        audio,
        feed,
        start: watch::Sender::new(Start::Starting),
        warning: None,
        _reader: RecordingTimer(reader.abort_handle()),
    };
    let joined = Joined::of(&live_id, &output);
    state.hls.outputs.insert(live_id.clone(), output);
    state.refresh_connection(&connection_id);
    tracing::info!(
        event = "hls_output_opened",
        live.id = %live_id,
        stream.id = %stream_id,
        connection.id = %connection_id,
        audio,
        "LL-HLS output opened; waiting for its init segment"
    );
    Ok(joined)
}

/// The idle timer of session `serial`, `hls_id`: it ends the session
/// `idle` once no request reached it for `timeout` on the injected clock.
fn idle_timer(
    shared: &Arc<Shared>,
    hls_id: &str,
    serial: u64,
    timeout: Duration,
) -> RecordingTimer {
    // The first deadline counts from now, not from the task's first poll.
    let first = shared.clock.sleep(timeout);
    let shared = Arc::clone(shared);
    let hls_id = hls_id.to_owned();
    let timer = spawn_named("hls.idle", async move {
        first.await;
        loop {
            let now = shared.clock.now();
            let Some(left) = shared.lock().hls_idle(&hls_id, serial, timeout, now) else {
                return;
            };
            shared.clock.sleep(left).await;
        }
    });
    RecordingTimer(timer.abort_handle())
}

/// Reads LL-HLS output `live_id`'s pipe into `feed` until it ends; a
/// record that breaks the format or the window ends the output. The pipe
/// is a trait object, not a generic, so the one function serves the pipe
/// and a test's failing reader alike.
async fn read(
    shared: Arc<Shared>,
    live_id: String,
    mut pipe: Box<dyn AsyncRead + Unpin + Send>,
    feed: Arc<Feed>,
    config: Config,
) {
    let mut decoder = Decoder::new();
    let mut buffer = vec![0_u8; READ_BYTES];
    let ended = loop {
        let want = decoder.wants().min(READ_BYTES);
        let room = buffer.get_mut(..want).unwrap_or_default();
        let read = match pipe.read(room).await {
            Ok(0) => break Ok(()),
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(live.id = %live_id, %error, "LL-HLS output's pipe failed");
                break Err(HlsCloseReason::InternalError);
            }
        };
        let records = match decoder.push(buffer.get(..read).unwrap_or_default()) {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(live.id = %live_id, %error, "LL-HLS output's records are broken");
                break Err(HlsCloseReason::InternalError);
            }
        };
        if let Err(reason) = records
            .into_iter()
            .try_for_each(|record| feed.take(record, config))
        {
            break Err(reason);
        }
    };
    match ended {
        Ok(()) => tracing::debug!(live.id = %live_id, "LL-HLS output's pipe ended"),
        Err(reason) => {
            tracing::warn!(live.id = %live_id, reason = reason.as_str(), "LL-HLS output ended by its reader");
            shared.lock().close_hls_output(&live_id, reason);
        }
    }
}

impl State {
    /// Session `serial`, `hls_id`'s idle timer fired at `now`: how much
    /// longer it waits, the session's last request less than `timeout` ago;
    /// `None` when the session is gone, or idle and now ended `idle`.
    fn hls_idle(
        &mut self,
        hls_id: &str,
        serial: u64,
        timeout: Duration,
        now: Instant,
    ) -> Option<Duration> {
        let session = self
            .hls
            .sessions
            .get(hls_id)
            .filter(|session| session.serial == serial)?;
        let left = timeout.saturating_sub(now.saturating_duration_since(session.touched));
        if left.is_zero() {
            tracing::info!(
                hls.id = hls_id,
                timeout_ms = timeout.as_millis(),
                "LL-HLS session idle: no request in time"
            );
            self.close_hls_session(hls_id, HlsCloseReason::Idle, true);
            return None;
        }
        Some(left)
    }

    /// A request of session `hls_id` at `now`: its idle clock restarts, and
    /// what answering it needs.
    fn hls_asked(&mut self, hls_id: &HlsId, now: Instant) -> Result<Asked, HlsError> {
        let before = self.live_limits.start_timeout;
        let all = Arc::clone(&self.hls.blocked);
        let session = self
            .hls
            .sessions
            .get_mut(hls_id.as_str())
            .ok_or(HlsError::NotFound)?;
        session.touched = now;
        Ok(Asked {
            feed: Arc::clone(&session.feed),
            session: Arc::clone(&session.blocked),
            all,
            gone: session.gone.clone(),
            before,
        })
    }

    /// The refusal of a request of `hls_id` that would block past `cap`,
    /// its warning rate-limited.
    fn hls_blocked_refused(&mut self, cap: Cap, hls_id: &HlsId) -> HlsError {
        let now = self.signaling.clock.now();
        if let Some(count) = self.hls.caps.of(cap).hit(now) {
            tracing::warn!(hls.id = %hls_id, limit = cap.as_str(), count, "LL-HLS blocked request refused at its limit");
        }
        HlsError::TooManyBlocked {
            limit: cap.as_str(),
        }
    }
}

/// What a request of a session needs, taken under the lock.
struct Asked {
    /// The session's window.
    feed: Arc<Feed>,
    /// The session's blocked requests.
    session: Arc<Semaphore>,
    /// Every session's blocked requests.
    all: Arc<Semaphore>,
    /// Cancelled when the session ends.
    gone: CancellationToken,
    /// How long a request waits before the window publishes.
    before: Duration,
}

/// `GET /v0/hls/{hls_id}/{name}`: touches the session's idle clock and
/// answers from its window, waiting, bounded, for what it does not hold
/// yet. See the module docs.
pub(crate) async fn serve(
    shared: &Arc<Shared>,
    hls_id: &HlsId,
    request: HlsRequest,
) -> Result<HlsReply, HlsError> {
    let now = shared.clock.now();
    let asked = shared.lock().hls_asked(hls_id, now)?;
    let mut published = asked.feed.published.subscribe();
    if let Answer::Done(answer) = asked.feed.answer(request) {
        return answer;
    }
    let _permits = block(shared, hls_id, &asked)?;
    let deadline = shared.clock.sleep(asked.feed.block_bound(asked.before));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            // The request holds the feed, and so the sender: it never
            // closes while this waits.
            _published = published.changed() => {}
            () = asked.gone.cancelled() => return Err(HlsError::NotFound),
            () = &mut deadline => {
                tracing::debug!(hls.id = %hls_id, "LL-HLS request blocked past three Target Durations");
                return Err(HlsError::Timeout);
            }
        }
        if let Answer::Done(answer) = asked.feed.answer(request) {
            return answer;
        }
    }
}

/// A place among the blocked requests of the session and of all, or the
/// refusal of a request over either, its warning rate-limited.
fn block(
    shared: &Arc<Shared>,
    hls_id: &HlsId,
    asked: &Asked,
) -> Result<
    (
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::OwnedSemaphorePermit,
    ),
    HlsError,
> {
    let refused = |cap: Cap| shared.lock().hls_blocked_refused(cap, hls_id);
    let session = Arc::clone(&asked.session)
        .try_acquire_owned()
        .map_err(|_| refused(Cap::BlockedPerSession))?;
    let all = Arc::clone(&asked.all)
        .try_acquire_owned()
        .map_err(|_| refused(Cap::Blocked))?;
    Ok((session, all))
}

#[cfg(test)]
mod tests;
