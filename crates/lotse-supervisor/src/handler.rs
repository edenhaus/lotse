//! The supervisor's side of the control API: the [`Handler`] the server
//! calls. It validates commands, keeps desired state in the registry,
//! starts a driver per source connection, opens viewer sessions on the
//! stream's connection and converts core state into the API's DTOs.
//!
//! A session belongs to the control connection that opened it; when that
//! connection goes, the session is orphaned for `limits.session_grace` and
//! a `session/adopt` may take it back.
//!
//! An event recording is recorded by the stream's connection's worker into a
//! pipe the supervisor creates: the worker gets the write end with
//! `recording/create`, the read end waits here for `GET /v0/recording/{recording_id}`
//! ([`Handler::recording_body`]). A recording ends with its control connection, as
//! its events have nowhere else to go ([`crate::recording`]).
//!
//! A signaled source's signaling goes to the `signaling/subscribe`
//! subscription for its stream, and the client's answer, candidates and
//! errors back to its worker ([`crate::signaling`]).

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lotse_api::{ConnectionId, Event, Handler, Outcome, RecordingBody, RecordingBodyError};
use lotse_api_types::API_VERSION;
use lotse_api_types::command::{
    Command, RecordingCreate, StreamPut, WebrtcCandidate, WebrtcOffer, WebrtcRenegotiate,
};
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::frame::{Hello, HelloTag};
use lotse_api_types::info::{
    BuildInfo, Codecs, DemuxMetrics, InfoResult, Limits, Metrics, ProcessMetrics, SandboxInfo,
    SupervisorMetrics,
};
use lotse_api_types::recording::{RecordingCloseReason, RecordingCreateResult, recording_path};
use lotse_api_types::session::{CloseCode, SessionEvent, SessionList, WebrtcRenegotiateResult};
use lotse_api_types::stream::{
    AudioMode, BackchannelReleaseResult, SignaledSource, SourceSpec, StreamList, StreamPutResult,
    UrlSource,
};
use lotse_core::clock::Clock;
use lotse_core::codec::{CodecFamily, Kind};
use lotse_core::connection::{ConnectionConfig, ConnectionError, ConnectionState};
use lotse_core::id::{RecordingId, StreamId};
use lotse_core::registry::Registries;
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_ipc::{RecordingSpec, SessionSpec};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::task::TaskTracker;
use tracing::Instrument as _;

use crate::connect::ConnectPermits;
use crate::driver::{COMMAND_QUEUE, Demand, Driver, DriverCommand, DriverSpec};
use crate::gather::{GATHER_DEADLINE, IcePlan, StunServer, TurnServer};
use crate::memory::{Memory, MemoryProbe};
use crate::net::demux::{DemuxStats, Registrations};
use crate::net::stun_client::StunClient;
use crate::net::turn_client::TurnClient;
use crate::recording::{
    RECORDING_QUEUE, RecordingEntry, RecordingLimits, RecordingOwner, RecordingTimer,
};
use crate::registry::{
    CloseBy, ConnectionEntry, ConnectionKey, ConnectionSnapshot, Shared, SourceTarget, State,
    StreamEntry, StreamSource, Talker,
};
use crate::session::{
    MAX_EARLY_CANDIDATES, MAX_REMOTE_CANDIDATES, SESSION_QUEUE, SessionEntry, api_event,
    ice_credentials, ulid,
};
use crate::signaling::Owner;
use crate::worker::{WorkerConfig, WorkerManager};
use crate::{Settings, millis};

/// The output kind that opens WebRTC sessions.
const WEBRTC: &str = "webrtc";

/// The output kind of event recordings, announced when the build has a recording
/// container (`Registries::recording`).
const RECORDING: &str = "recording";

/// What `hello` and `info` always announce beyond the outputs.
const FEATURES: [&str; 1] = ["session_adopt"];

/// The feature of two-way audio, announced only while it works end to end
/// ([`Supervisor::features`]).
const TWO_WAY_AUDIO: &str = "two_way_audio";

/// The video codec families a viewer can play: MJPEG is ingested and
/// reported per track, but no output negotiates it.
const VIDEO_CODECS: [CodecFamily; 2] = [CodecFamily::H264, CodecFamily::H265];

/// The audio codec families the daemon carries.
const AUDIO_CODECS: [CodecFamily; 5] = [
    CodecFamily::Opus,
    CodecFamily::Pcmu,
    CodecFamily::Pcma,
    CodecFamily::G722,
    CodecFamily::AacLc,
];

/// Extra time the shutdown waits for drivers past the workers' budget.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

/// How long `webrtc/renegotiate` waits for the worker's answer: a worker
/// answers a re-offer in milliseconds, so this only bounds a stuck one.
const RENEGOTIATE_TIMEOUT: Duration = Duration::from_secs(10);

/// What `hello` and `info` say about this build and process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The daemon version.
    pub version: String,
    /// The build.
    pub build: BuildInfo,
    /// The supervisor's sandbox report.
    pub sandbox: SandboxInfo,
}

/// What the binary hands the supervisor besides the settings.
#[derive(Debug)]
pub struct Environment {
    /// The sources, outputs and transcoders compiled in.
    pub registries: Registries,
    /// How workers are started.
    pub worker: WorkerConfig,
    /// The build and sandbox.
    pub identity: Identity,
    /// The shared WebRTC UDP socket, bound before the sandbox; every
    /// worker gets a duplicate. `None` in tests without sessions.
    pub udp: Option<Arc<std::net::UdpSocket>>,
    /// The demux and the host addresses sessions answer with. `None` in
    /// tests without sessions.
    pub front_door: Option<FrontDoor>,
}

/// What sessions need from the network front door.
#[derive(Debug, Clone)]
pub struct FrontDoor {
    /// The demux's sessions, which the drivers register with.
    pub registrations: Arc<Registrations>,
    /// The host candidates' addresses.
    pub hosts: Vec<SocketAddr>,
    /// The passive ICE-TCP host candidates' addresses: the host addresses
    /// at the listener's port; empty with the listener off.
    pub tcp_hosts: Vec<SocketAddr>,
    /// The STUN client of server-reflexive gathering, on the shared socket.
    pub stun: Option<Arc<StunClient>>,
    /// The TURN client of relay gathering, on the shared socket.
    pub turn: Option<Arc<TurnClient>>,
    /// The demux's counters, for `metrics/get`.
    pub demux: Option<Arc<DemuxStats>>,
}

/// A source of `stream/put` after validation.
struct ValidatedSource {
    /// The parsed URL, or the signaled source's protocol and stream.
    target: SourceTarget,
    /// The URL as given, credentials included, or the protocol, for the
    /// worker.
    raw: lotse_ipc::SourceTarget,
    /// The options as given.
    options: serde_json::Map<String, serde_json::Value>,
    /// What the connection is keyed by: the target, credentials included,
    /// and the source's normalized connection options.
    key: ConnectionKey,
    /// The options as the source reports them, secrets redacted.
    described: serde_json::Value,
    /// The protocol name.
    protocol: &'static str,
    /// The scheme's default port.
    default_port: Option<u16>,
    /// The source asks for the camera's backchannel
    /// ([`Source::wants_backchannel`](lotse_core::source::Source::wants_backchannel)).
    backchannel: bool,
}

impl ValidatedSource {
    /// The port the source's worker may connect to, from the URL or the
    /// scheme's default; none for a signaled source, which connects to
    /// what the client's signaling names.
    fn port(&self) -> Option<u16> {
        self.target
            .url()
            .and_then(|url| url.port().or(self.default_port))
    }
}

/// The supervisor: the registry and the API handler over it.
#[derive(Debug)]
pub struct Supervisor {
    /// The settings.
    settings: Settings,
    /// The sources, outputs and transcoders.
    registries: Arc<Registries>,
    /// The build and sandbox.
    identity: Identity,
    /// The registry and what the drivers need.
    shared: Arc<Shared>,
    /// When the supervisor started, for `metrics/get`.
    started: Instant,
    /// Its own `smaps_rollup`; `None` without `/proc`.
    memory: Option<MemoryProbe>,
    /// The demux's counters; `None` without a front door.
    demux: Option<Arc<DemuxStats>>,
}

impl Supervisor {
    /// A supervisor with no streams.
    pub fn new(settings: Settings, environment: Environment, clock: Arc<dyn Clock>) -> Self {
        let started = clock.now();
        let (registrations, hosts, tcp_hosts, stun, turn, demux) = environment.front_door.map_or(
            (None, Vec::new(), Vec::new(), None, None, None),
            |door| {
                (
                    Some(door.registrations),
                    door.hosts,
                    door.tcp_hosts,
                    door.stun,
                    door.turn,
                    door.demux,
                )
            },
        );
        let mut state = State::default();
        state.registrations = registrations;
        state.signaling.clock = Arc::clone(&clock);
        // A signaled source gathers on the hosts sessions answer with.
        for ip in hosts.iter().map(SocketAddr::ip) {
            if !state.signaling.local_addrs.contains(&ip) {
                state.signaling.local_addrs.push(ip);
            }
        }
        // Without a recording output the workers refuse every recording: no window
        // and no recording is accepted, which `info` reports.
        state.recording_limits = if environment.registries.recording.is_some() {
            settings.limits.recordings
        } else {
            RecordingLimits::NONE
        };
        let shared = Arc::new(Shared {
            clock,
            manager: WorkerManager::new(environment.worker, environment.udp)
                .with_turn(turn.clone()),
            tracker: TaskTracker::new(),
            shutdown_budget: settings.shutdown_budget,
            connects: ConnectPermits::new(settings.connect_concurrency),
            hosts,
            tcp_hosts,
            stun,
            turn,
            state: Mutex::new(state),
        });
        Self {
            settings,
            registries: Arc::new(environment.registries),
            identity: environment.identity,
            shared,
            started,
            memory: MemoryProbe::open(crate::memory::OWN),
            demux,
        }
    }

    /// Closes every session and ends every recording with `shutting_down`,
    /// and ends the signaling (each offered signal closes `source_stopped`,
    /// each signaling subscription ends); the first step of the shutdown,
    /// before the control connections say goodbye. A recording's worker
    /// writes its last fragment while it stops, but its report is not
    /// waited for, so the body is cut.
    pub fn close_sessions(&self) {
        let mut state = self.shared.lock();
        state.close_sessions_where(
            |_| true,
            CloseCode::ShuttingDown,
            "the daemon is shutting down",
            CloseBy::Supervisor,
        );
        state.end_recordings_where(|_| true, RecordingCloseReason::ShuttingDown);
        state.signaling_shutdown();
    }

    /// Closes the sessions, stops every connection's worker within the
    /// budget and waits for the drivers.
    pub async fn shutdown(&self) {
        self.close_sessions();
        let connections = std::mem::take(&mut self.shared.lock().connections);
        let count = connections.len();
        drop(connections);
        self.shared.tracker.close();
        let budget = self.settings.shutdown_budget.saturating_add(SHUTDOWN_GRACE);
        tokio::select! {
            () = self.shared.tracker.wait() => {
                tracing::info!(connections = count, "connections stopped");
            }
            () = self.shared.clock.sleep(budget) => {
                tracing::warn!(connections = count, "connections missed the shutdown budget");
            }
        }
    }

    /// `info`.
    fn info(&self) -> InfoResult {
        let limits = &self.settings.limits;
        let recordings = self.shared.lock().recording_limits;
        InfoResult {
            version: self.identity.version.clone(),
            build: self.identity.build.clone(),
            schemes: self
                .registries
                .sources
                .schemes()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            signaled_protocols: self
                .registries
                .sources
                .signaled_protocols()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            outputs: self.outputs(),
            features: self.features(),
            codecs: Codecs {
                video: VIDEO_CODECS.iter().map(|c| c.name().to_owned()).collect(),
                audio: AUDIO_CODECS.iter().map(|c| c.name().to_owned()).collect(),
            },
            limits: Limits {
                max_streams: limits.max_streams,
                max_sessions: limits.max_sessions,
                max_sessions_per_stream: limits.max_sessions_per_stream,
                max_connections: limits.max_connections,
                session_grace_ms: millis(limits.session_grace),
                max_prerecord_ms: recordings.max_prerecord_ms,
                max_prerecord_bytes: recordings.max_prerecord_bytes,
                max_recording_ms: recordings.max_recording_ms,
                max_recordings: recordings.max_recordings,
                max_recordings_per_stream: recordings.max_recordings_per_stream,
            },
            sandbox: self.identity.sandbox.clone(),
        }
    }

    /// What `hello` and `info` announce in `features`. `two_way_audio`
    /// is there only when a viewer's talk-back can reach a camera: the
    /// `webrtc` output answers talk-back, a reverse chain is registered
    /// (`Registries::uplink`, which every G.711 camera needs) and at least
    /// one source protocol declares it can carry audio back
    /// (`SourceCapabilities::backchannel`, the gate the worker answers
    /// talk-back behind).
    fn features(&self) -> Vec<String> {
        let sources = &self.registries.sources;
        let backchannel = sources.schemes().into_iter().any(|scheme| {
            sources
                .get(scheme)
                .is_some_and(|factory| factory.capabilities().backchannel)
        });
        let two_way_audio = backchannel
            && self.registries.uplink.is_some()
            && self.registries.outputs.get(WEBRTC).is_some();
        FEATURES
            .iter()
            .copied()
            .chain(two_way_audio.then_some(TWO_WAY_AUDIO))
            .map(str::to_owned)
            .collect()
    }

    /// The output kinds compiled in: the session outputs, then `recording` with
    /// a recording container.
    fn outputs(&self) -> Vec<String> {
        self.registries
            .outputs
            .kinds()
            .into_iter()
            .chain(self.registries.recording.is_some().then_some(RECORDING))
            .map(str::to_owned)
            .collect()
    }

    /// `metrics/get`. The memory figures are read with the maps unlocked
    /// and on the blocking pool: each read walks a process's mappings in
    /// the kernel ([`MemoryProbe::sample`]).
    async fn metrics(&self) -> Metrics {
        let now = self.shared.clock.now();
        let (workers, worker_restarts, sessions, streams) = {
            let state = self.shared.lock();
            (
                state.workers(now),
                state.worker_restarts,
                u32::try_from(state.sessions.len()).unwrap_or(u32::MAX),
                state
                    .streams
                    .iter()
                    .map(|(id, entry)| (id.clone(), state.stream_stats(entry)))
                    .collect(),
            )
        };
        let memory = sample(self.memory.as_ref(), now).await;
        let mut worker_metrics = BTreeMap::new();
        for (id, (mut worker, probe)) in workers {
            let memory = sample(probe.as_ref(), now).await;
            worker.process.rss_bytes = memory.rss_bytes;
            worker.process.pss_bytes = memory.pss_bytes;
            worker_metrics.insert(id, worker);
        }
        Metrics {
            supervisor: SupervisorMetrics {
                process: ProcessMetrics {
                    pid: std::process::id(),
                    uptime_ms: millis(now.saturating_duration_since(self.started)),
                    rss_bytes: memory.rss_bytes,
                    pss_bytes: memory.pss_bytes,
                    tasks: tokio::runtime::Handle::try_current()
                        .ok()
                        .and_then(|runtime| {
                            u64::try_from(runtime.metrics().num_alive_tasks()).ok()
                        }),
                },
                demux: self.demux.as_deref().map(demux_metrics),
            },
            workers: worker_metrics,
            worker_restarts,
            sessions,
            streams,
        }
    }

    /// Checks a source of `stream_id` with its factory: a URL's scheme and
    /// options with the scheme's, a signaled source's options with its
    /// protocol's.
    fn validate_source(
        &self,
        stream_id: &StreamId,
        source: &SourceSpec,
    ) -> Result<ValidatedSource, ApiError> {
        match source {
            SourceSpec::Url(source) => self.validate_url_source(source),
            SourceSpec::Signaled(source) => self.validate_signaled_source(stream_id, source),
        }
    }

    /// Checks a source lotse connects to: its URL, its scheme, which must
    /// be no signaled protocol, and its options.
    fn validate_url_source(&self, source: &UrlSource) -> Result<ValidatedSource, ApiError> {
        let url = SourceUrl::parse(&source.url).map_err(|err| {
            ApiError::new(ErrorCode::InvalidRequest, format!("source url: {err}"))
        })?;
        let sources = &self.registries.sources;
        let Some(factory) = sources.get(url.scheme()) else {
            if sources.signaled(url.scheme()).is_some() {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    format!(
                        "a {0} source has no url: the client relays its signaling, so name it by protocol, {{\"protocol\": \"{0}\"}}",
                        url.scheme()
                    ),
                )
                .with_detail("protocol", url.scheme()));
            }
            return Err(ApiError::new(
                ErrorCode::SchemeUnsupported,
                format!("no source handles {:?} urls", url.scheme()),
            )
            .with_detail("scheme", url.scheme()));
        };
        let options = serde_json::Value::Object(source.options.clone());
        let built = factory
            .validate(&url, &options)
            .map_err(|err| ApiError::new(ErrorCode::InvalidRequest, err.to_string()))?;
        let described = built.describe();
        let default_port = factory.default_port(url.scheme());
        let target = SourceTarget::Url(url);
        Ok(ValidatedSource {
            key: ConnectionKey {
                target: target.clone(),
                options: built.connection_options(),
            },
            target,
            raw: lotse_ipc::SourceTarget::Url(source.url.clone()),
            options: source.options.clone(),
            described: described.options,
            protocol: described.protocol,
            default_port,
            backchannel: built.wants_backchannel(),
        })
    }

    /// Checks a source of `stream_id` whose signaling the client relays:
    /// its protocol, which must be no URL scheme, and its options. Its
    /// stream is its identity.
    fn validate_signaled_source(
        &self,
        stream_id: &StreamId,
        source: &SignaledSource,
    ) -> Result<ValidatedSource, ApiError> {
        let sources = &self.registries.sources;
        let protocol = source.protocol.as_str();
        let Some(factory) = sources.signaled(protocol) else {
            if sources.get(protocol).is_some() {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    format!(
                        "a {protocol} source is named by its url, {{\"url\": \"{protocol}://…\"}}, not by protocol"
                    ),
                )
                .with_detail("scheme", protocol));
            }
            return Err(ApiError::new(
                ErrorCode::ProtocolUnsupported,
                format!("no signaled source speaks {protocol:?}"),
            )
            .with_detail("protocol", protocol));
        };
        let options = serde_json::Value::Object(source.options.clone());
        let built = factory
            .validate(&options)
            .map_err(|err| ApiError::new(ErrorCode::InvalidRequest, err.to_string()))?;
        let described = built.describe();
        let target = SourceTarget::Signaled {
            protocol: factory.protocol(),
            stream: stream_id.as_str().to_owned(),
        };
        Ok(ValidatedSource {
            key: ConnectionKey {
                target: target.clone(),
                options: built.connection_options(),
            },
            target,
            raw: lotse_ipc::SourceTarget::Signaled(factory.protocol().to_owned()),
            options: source.options.clone(),
            described: described.options,
            protocol: described.protocol,
            default_port: None,
            backchannel: built.wants_backchannel(),
        })
    }

    /// `stream/put`: validates, then binds the stream to a connection per
    /// source, keyed by URL, credentials and the normalized
    /// receive-relevant options. A source URL that is another stream's,
    /// credentials aside, is refused with `source_in_use` naming that
    /// stream: a camera stream is one stream, so a connection is never
    /// shared and the camera never serves the same stream twice. A source
    /// whose key changed switches its connection's worker to it in place
    /// where the worker can follow ([`switchable`]), so the sessions play
    /// on from its first keyframe; otherwise the stream moves to another
    /// connection and its sessions on the old one close with
    /// `stream_changed`. A changed orientation reaches the open sessions
    /// that stay. Each connection the put touched then asks for the
    /// camera's backchannel iff a source on it does
    /// ([`State::follow_backchannel`]): `backchannel` is not part of the
    /// key, so opting in or out turns the shared connection's probe on or
    /// off instead of opening a second camera session, and restarts
    /// nothing.
    fn stream_put(&self, put: &StreamPut) -> Outcome {
        let (stream_id, validated) = match self.validate_put(put) {
            Ok(validated) => validated,
            Err(error) => return Outcome::Error(error),
        };
        let mut state = self.shared.lock();
        let before = state.stream_status(stream_id.as_str());
        let existing = state.streams.get(stream_id.as_str());
        let created = existing.is_none();
        if created
            && state.streams.len()
                >= usize::try_from(self.settings.limits.max_streams).unwrap_or(usize::MAX)
        {
            return Outcome::Error(
                ApiError::new(ErrorCode::LimitReached, "too many streams")
                    .with_detail("limit", "max_streams"),
            );
        }
        if let Some(entry) = existing.filter(|entry| unchanged(entry, put, &validated)) {
            // A window a full driver queue kept from a connection reaches it
            // now: the put is the same, the connection's window may not be.
            let connections: Vec<String> = entry
                .sources
                .iter()
                .map(|source| source.connection.clone())
                .collect();
            for connection in &connections {
                state.follow_prerecord(connection, stream_id.as_str());
            }
            tracing::debug!(stream.id = %stream_id, "stream/put: unchanged");
            return Outcome::Result(
                serde_json::to_value(StreamPutResult { created: false }).unwrap_or_default(),
            );
        }
        if let Some(error) = source_in_use(&state, stream_id.as_str(), &validated) {
            return Outcome::Error(error);
        }
        let reoriented = existing.is_some_and(|entry| entry.orientation != put.orientation);
        // The counters outlive a change of the stream.
        let recordings = existing.map(|entry| entry.recordings).unwrap_or_default();
        let previous: Vec<String> = existing.map_or_else(Vec::new, |entry| {
            entry.sources.iter().map(|s| s.connection.clone()).collect()
        });

        let sources = self.bind_sources(
            &mut state,
            (&stream_id, put.prerecord_ms),
            &previous,
            validated,
        );
        // Each once: a source that stays on its connection is in both.
        let connections: std::collections::BTreeSet<String> = previous
            .iter()
            .chain(sources.iter().map(|s| &s.connection))
            .cloned()
            .collect();
        state.streams.insert(
            stream_id.as_str().to_owned(),
            StreamEntry {
                sources,
                preload: put.preload,
                audio: put.audio,
                orientation: put.orientation,
                created: self.shared.clock.wall_now(),
                prerecord_ms: put.prerecord_ms,
                recordings,
            },
        );
        let now = (self.shared.clock.now(), self.shared.clock.wall_now());
        for connection in connections {
            state.refresh_connection(&connection);
            state.follow_backchannel(&connection, stream_id.as_str());
            state.follow_prerecord(&connection, stream_id.as_str());
            state.route_waiting_opens(&connection, now);
        }
        close_moved_sessions(&mut state, stream_id.as_str());
        if reoriented {
            state.reorient_sessions(stream_id.as_str(), put.orientation);
        }
        if state.stream_status(stream_id.as_str()) != before {
            state.notify_stream(stream_id.as_str());
        }
        drop(state);
        tracing::info!(
            event = "stream_put",
            stream.id = %stream_id,
            created,
            preload = put.preload,
            orientation = ?put.orientation,
            prerecord_ms = put.prerecord_ms,
            "stream desired state set"
        );
        Outcome::Result(serde_json::to_value(StreamPutResult { created }).unwrap_or_default())
    }

    /// Checks a `stream/put`'s stream id, its pre-record window against
    /// `limits.max_prerecord_ms`, and each source.
    fn validate_put(&self, put: &StreamPut) -> Result<(StreamId, Vec<ValidatedSource>), ApiError> {
        let stream_id = StreamId::new(&put.stream_id).map_err(|err| {
            ApiError::new(ErrorCode::InvalidStreamId, err.to_string())
                .with_detail("stream_id", put.stream_id.as_str())
        })?;
        if put.sources.is_empty() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "sources must name at least one source",
            ));
        }
        let max_prerecord_ms = self.shared.lock().recording_limits.max_prerecord_ms;
        if put.prerecord_ms > max_prerecord_ms {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                format!(
                    "`prerecord_ms` is {}, the maximum is {max_prerecord_ms} (`limits.max_prerecord_ms`)",
                    put.prerecord_ms
                ),
            )
            .with_detail("field", "prerecord_ms"));
        }
        let validated = put
            .sources
            .iter()
            .map(|source| self.validate_source(&stream_id, source))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((stream_id, validated))
    }

    /// Binds each validated source of `stream_id` to a connection: the
    /// one keyed by it, else the stream's previous connection at that
    /// index switched to it in place where the worker can follow
    /// ([`switchable`]), else a new one with the stream's pre-record window
    /// `prerecord_ms`.
    fn bind_sources(
        &self,
        state: &mut State,
        (stream_id, prerecord_ms): (&StreamId, u32),
        previous: &[String],
        validated: Vec<ValidatedSource>,
    ) -> Vec<StreamSource> {
        let mut sources = Vec::with_capacity(validated.len());
        for (index, source) in validated.into_iter().enumerate() {
            let connection = match state.connection_for(&source.key) {
                Some(id) => id,
                None => match previous
                    .get(index)
                    .filter(|id| switchable(state, id, &source))
                {
                    Some(id) => {
                        tracing::info!(
                            stream.id = %stream_id,
                            connection.id = %id,
                            source = %source.target,
                            "stream/put: the connection switches to the new source in place"
                        );
                        state.switch_connection(id, source.key.clone(), driver_spec(id, &source));
                        id.clone()
                    }
                    None => self.create_connection(state, &source, prerecord_ms),
                },
            };
            if let Some(entry) = state.connections.get_mut(&connection) {
                entry.streams.insert(stream_id.as_str().to_owned());
            }
            sources.push(StreamSource {
                spec: driver_spec(&connection, &source),
                target: source.target,
                options: source.options,
                protocol: source.protocol,
                connection,
            });
        }
        sources
    }

    /// Creates a connection for `source` and starts its driver, with a
    /// pre-record window of `prerecord_ms`.
    fn create_connection(
        &self,
        state: &mut State,
        source: &ValidatedSource,
        prerecord_ms: u32,
    ) -> String {
        state.next_connection = state.next_connection.saturating_add(1);
        let id = format!("c{}", state.next_connection);
        let (demand, demand_rx) = watch::channel(Demand::default());
        // Room besides the rest for the close each session reserves and
        // the stop each recording does.
        let sessions = usize::try_from(self.settings.limits.max_sessions).unwrap_or(usize::MAX);
        let recordings =
            usize::try_from(state.recording_limits.max_recordings).unwrap_or(usize::MAX);
        let (commands, commands_rx) = mpsc::channel(
            COMMAND_QUEUE
                .saturating_add(sessions)
                .saturating_add(recordings),
        );
        state.connections.insert(
            id.clone(),
            ConnectionEntry {
                key: source.key.clone(),
                port: source.port(),
                backchannel: source.backchannel,
                prerecord_ms,
                demand,
                snapshot: ConnectionSnapshot::idle(self.shared.clock.wall_now()),
                switches: 0,
                streams: std::collections::BTreeSet::new(),
                commands: commands.clone(),
                talker: Talker::default(),
            },
        );
        let spec = driver_spec(&id, source);
        let config = ConnectionConfig {
            linger: self.settings.linger,
            ..ConnectionConfig::default()
        };
        let span = tracing::info_span!("connection", connection.id = %id, source = %source.target);
        let run = Driver::new(
            (spec, prerecord_ms),
            Arc::clone(&self.shared),
            demand_rx,
            (commands, commands_rx),
            config,
        )
        .run()
        .instrument(span);
        let _handle = spawn_named("connection.driver", self.shared.tracker.track_future(run));
        tracing::info!(connection.id = %id, source = %source.target, options = %source.described, "connection created");
        id
    }

    /// `stream/get`. The workers' memory is read with the maps unlocked.
    async fn stream_get(&self, stream_id: &str) -> Outcome {
        let stream = self.shared.lock().stream(stream_id);
        match stream {
            Some(stream) => {
                let stream = stream.read_memory(self.shared.clock.now()).await;
                Outcome::Result(serde_json::to_value(stream).unwrap_or_default())
            }
            None => Outcome::Error(
                ApiError::new(ErrorCode::StreamNotFound, "no such stream")
                    .with_detail("stream_id", stream_id),
            ),
        }
    }

    /// `stream/list`. The workers' memory is read with the maps unlocked.
    async fn stream_list(&self) -> Outcome {
        let unread = self.shared.lock().streams();
        let now = self.shared.clock.now();
        let mut streams = BTreeMap::new();
        for (id, stream) in unread {
            streams.insert(id, stream.read_memory(now).await);
        }
        Outcome::Result(serde_json::to_value(StreamList { streams }).unwrap_or_default())
    }

    /// `stream/delete`: idempotent; the stream's sessions close and its
    /// recordings end first.
    fn stream_delete(&self, stream_id: &str) -> Outcome {
        let removed = {
            let mut state = self.shared.lock();
            state.close_sessions_where(
                |session| session.stream_id == stream_id,
                CloseCode::StreamDeleted,
                "the stream was deleted",
                CloseBy::Supervisor,
            );
            state.end_recordings_where(
                |recording| recording.stream_id == stream_id,
                RecordingCloseReason::StreamDeleted,
            );
            state.streams.remove(stream_id).map(|entry| {
                for source in entry.sources {
                    state.refresh_connection(&source.connection);
                    state.follow_backchannel(&source.connection, stream_id);
                    state.follow_prerecord(&source.connection, stream_id);
                }
                state.notify_removed(stream_id);
            })
        };
        if removed.is_some() {
            tracing::info!(
                event = "stream_deleted",
                stream.id = stream_id,
                "stream deleted"
            );
        }
        Outcome::Result(serde_json::Value::Object(serde_json::Map::new()))
    }

    /// `stream/subscribe`.
    fn stream_subscribe(&self, connection: ConnectionId, stream_id: Option<String>) -> Outcome {
        if let Some(id) = &stream_id
            && let Err(err) = StreamId::new(id)
        {
            return Outcome::Error(
                ApiError::new(ErrorCode::InvalidStreamId, err.to_string())
                    .with_detail("stream_id", id.as_str()),
            );
        }
        Outcome::Subscribed(self.shared.lock().subscribe(connection, stream_id))
    }

    /// `signaling/subscribe`: takes the signals of one stream's signaled
    /// sources, or of every stream's ([`crate::signaling`]).
    fn signaling_subscribe(
        &self,
        connection: ConnectionId,
        id: u64,
        stream_id: Option<String>,
    ) -> Outcome {
        if let Some(id) = &stream_id
            && let Err(err) = StreamId::new(id)
        {
            return Outcome::Error(
                ApiError::new(ErrorCode::InvalidStreamId, err.to_string())
                    .with_detail("stream_id", id.as_str()),
            );
        }
        let owner = Owner {
            connection,
            subscription: id,
        };
        let now = (self.shared.clock.now(), self.shared.clock.wall_now());
        Outcome::Subscribed(
            self.shared
                .lock()
                .signaling_subscribe(owner, stream_id, now),
        )
    }

    /// `webrtc/offer`: validates, registers the session on the stream's
    /// connection (which raises its demand) and hands the offer to its
    /// driver; the answer arrives as an event once the tracks are known.
    /// The session waits as long as the source's own deadlines let the
    /// attempt run: a failure closes it with the source's error
    /// ([`State::close_waiting`](crate::registry::State::close_waiting)).
    /// An offer to a connection that already failed
    /// ([`ConnectionSnapshot::failure`]) closes at once with that error and
    /// never reaches the driver; a stale error of an idle or connecting
    /// connection does not count, the session waits for the attempt.
    fn webrtc_offer(
        &self,
        connection: ConnectionId,
        offer: WebrtcOffer,
    ) -> Result<mpsc::Receiver<Event>, ApiError> {
        let stream_id = StreamId::new(&offer.stream_id).map_err(|err| {
            ApiError::new(ErrorCode::InvalidStreamId, err.to_string())
                .with_detail("stream_id", offer.stream_id.as_str())
        })?;
        let session_id = match offer.session_id {
            // The same pattern as stream ids.
            Some(id) => StreamId::new(&id)
                .map(|_| id.clone())
                .map_err(|_| invalid_session_id(&id))?,
            None => ulid(self.shared.clock.wall_now()).map_err(internal)?,
        };
        if self.registries.outputs.get(WEBRTC).is_none() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "no webrtc output is compiled in",
            ));
        }
        let mut ice = crate::gather::plan(offer.ice_servers.as_deref().unwrap_or_default())?;
        let (stun_servers, turn_servers) = self.gatherable(&mut ice);
        let (ice_ufrag, ice_pass) = ice_credentials().map_err(internal)?;

        let mut state = self.shared.lock();
        let stream = state.streams.get(stream_id.as_str()).ok_or_else(|| {
            ApiError::new(ErrorCode::StreamNotFound, "no such stream")
                .with_detail("stream_id", stream_id.as_str())
        })?;
        let audio = stream.audio == AudioMode::Auto;
        let orientation = stream.orientation;
        let SessionConnection {
            id: connection_id,
            commands,
            failure,
        } = session_connection(&state, stream)?;
        if state.sessions.contains_key(&session_id) {
            return Err(
                ApiError::new(ErrorCode::SessionIdInUse, "the session id is already open")
                    .with_detail("session_id", session_id.as_str()),
            );
        }
        check_session_limits(&state, stream_id.as_str(), &self.settings.limits)?;
        let spec = SessionSpec {
            session_id: session_id.clone(),
            kind: WEBRTC.to_owned(),
            offer: offer.sdp,
            ice_ufrag: ice_ufrag.clone(),
            ice_pass,
            candidates: self.shared.hosts.clone(),
            tcp_candidates: self.shared.tcp_hosts.clone(),
            audio,
            orientation: orientation.code(),
        };
        // An offer to a connection that already failed is not handed on:
        // the session closes below with the failure.
        let close_slot = hand_over(&commands, spec, failure.is_some())?;
        state.last_session = state.last_session.saturating_add(1);
        let serial = state.last_session;
        let (events, rx) = mpsc::channel(SESSION_QUEUE);
        let mut entry = SessionEntry::new(
            serial,
            stream_id.as_str().to_owned(),
            connection_id.clone(),
            ice_ufrag,
            (connection, offer.id, events),
            Arc::clone(&self.shared.clock),
        );
        entry.close_slot = close_slot;
        entry.deliver(
            &session_id,
            api_event(&SessionEvent::Session {
                session_id: session_id.clone(),
            }),
        );
        for warning in &ice.warnings {
            entry.deliver(&session_id, api_event(warning));
        }
        if let Some((error, connection_state)) = failure {
            state.close_offer(&session_id, entry, &error, connection_state);
            return Ok(rx);
        }
        entry.gathering(stun_servers.len().saturating_add(turn_servers.len()));
        state.sessions.insert(session_id.clone(), entry);
        state.refresh_connection(&connection_id);
        drop(state);
        let hosts = self.shared.hosts.len();
        tracing::info!(
            event = "session_opened",
            session.id = %session_id,
            stream.id = %stream_id,
            connection.id = %connection_id,
            control.connection = connection.0,
            audio,
            orientation = ?orientation,
            hosts,
            "session opened; offer handed to the connection"
        );
        self.start_gathering(&session_id, serial, stun_servers, turn_servers);
        Ok(rx)
    }

    /// The STUN and TURN servers of `ice` this front door has a client
    /// for.
    fn gatherable(&self, ice: &mut IcePlan) -> (Vec<StunServer>, Vec<TurnServer>) {
        let stun = std::mem::take(&mut ice.stun);
        let turn = std::mem::take(&mut ice.turn);
        (
            if self.shared.stun.is_some() {
                stun
            } else {
                Vec::new()
            },
            if self.shared.turn.is_some() {
                turn
            } else {
                Vec::new()
            },
        )
    }

    /// Gathers a server-reflexive candidate from each of `stun` and a
    /// relay candidate from each of `turn` for session `serial`, and
    /// releases end-of-candidates after [`GATHER_DEADLINE`] whatever they
    /// did; a lease that comes later than that is released.
    fn start_gathering(
        &self,
        session_id: &str,
        serial: u64,
        stun: Vec<StunServer>,
        turn: Vec<TurnServer>,
    ) {
        if self.shared.stun.is_none() && self.shared.turn.is_none() {
            return;
        }
        let counts = (stun.len(), turn.len());
        if let Some(client) = &self.shared.stun {
            for (index, server) in stun.into_iter().enumerate() {
                let client = Arc::clone(client);
                let shared = Arc::clone(&self.shared);
                let id = session_id.to_owned();
                let _handle = spawn_named("session.gather", async move {
                    let candidate = crate::gather::gather(&client, &server, &shared.hosts)
                        .await
                        .map(|(mapped, base)| crate::gather::srflx_candidate(index, mapped, base));
                    shared.lock().session_gathered(&id, serial, candidate);
                });
            }
        }
        if let Some(client) = &self.shared.turn {
            for server in turn {
                let client = Arc::clone(client);
                let shared = Arc::clone(&self.shared);
                let id = session_id.to_owned();
                let _handle = spawn_named("session.relay", async move {
                    let relayed = tokio::select! {
                        relayed = crate::gather::relay(&client, &server, &shared.hosts) => relayed,
                        () = shared.clock.sleep(GATHER_DEADLINE) => None,
                    };
                    shared.lock().session_relayed(&id, serial, relayed);
                });
            }
        }
        let id = session_id.to_owned();
        self.shared
            .after(session_id, serial, GATHER_DEADLINE, move |state| {
                state.session_gather_deadline(&id, serial);
            });
        tracing::debug!(
            session.id = session_id,
            stun = counts.0,
            turn = counts.1,
            "gathering started"
        );
    }

    /// `webrtc/candidate`: passed on to the session's worker; at most
    /// [`MAX_EARLY_CANDIDATES`] before the answer and
    /// [`MAX_REMOTE_CANDIDATES`] in all. Only the connection that owns the
    /// session signals for it, as its events reach that connection only:
    /// another one (or anyone while it is orphaned, until adopted) gets
    /// `session_not_found` and spends none of its budget.
    fn webrtc_candidate(&self, connection: ConnectionId, candidate: &WebrtcCandidate) -> Outcome {
        let mut state = self.shared.lock();
        let Some(session) = state.sessions.get_mut(&candidate.session_id) else {
            return Outcome::Error(session_not_found(&candidate.session_id));
        };
        if !session.owned_by_connection(connection) {
            drop(state);
            tracing::debug!(
                session.id = %candidate.session_id,
                control.connection = connection.0,
                "remote candidate refused: not the session's owner"
            );
            return Outcome::Error(
                ApiError::new(
                    ErrorCode::SessionNotFound,
                    "the session is not this connection's",
                )
                .with_detail("session_id", candidate.session_id.as_str()),
            );
        }
        let limit = if session.answered {
            (MAX_REMOTE_CANDIDATES, "remote_candidates")
        } else {
            (MAX_EARLY_CANDIDATES, "early_candidates")
        };
        if session.remote_candidates >= limit.0 {
            return Outcome::Error(
                ApiError::new(
                    ErrorCode::LimitReached,
                    "too many candidates for the session",
                )
                .with_detail("limit", limit.1),
            );
        }
        session.remote_candidates = session.remote_candidates.saturating_add(1);
        let connection = session.connection.clone();
        let queued = state.connections.get(&connection).is_some_and(|entry| {
            entry
                .commands
                .try_send(DriverCommand::Candidate {
                    session_id: candidate.session_id.clone(),
                    candidate: candidate.candidate.clone(),
                })
                .is_ok()
        });
        drop(state);
        if !queued {
            return Outcome::Error(
                ApiError::new(ErrorCode::LimitReached, "the stream's connection is busy")
                    .with_detail("limit", "connection_queue"),
            );
        }
        tracing::debug!(session.id = %candidate.session_id, end = candidate.candidate.is_empty(), "remote candidate");
        Outcome::Result(serde_json::Value::Object(serde_json::Map::new()))
    }

    /// `webrtc/renegotiate`: passed on to the session's worker, whose
    /// answer or refusal is the result; waited for up to
    /// [`RENEGOTIATE_TIMEOUT`] on the daemon's clock. Like
    /// `webrtc/candidate`, only the connection that owns the session may
    /// send one, and only once the session is answered; a session has one
    /// re-offer out at a time, until the worker answers it, even when its
    /// command gave up ([`SessionEntry::renegotiate`]).
    async fn webrtc_renegotiate(
        &self,
        connection: ConnectionId,
        command: WebrtcRenegotiate,
    ) -> Outcome {
        let session_id = command.session_id;
        let (reply, waiting) = oneshot::channel();
        {
            let mut state = self.shared.lock();
            let Some(session) = state.sessions.get_mut(&session_id) else {
                return Outcome::Error(session_not_found(&session_id));
            };
            if !session.owned_by_connection(connection) {
                drop(state);
                tracing::debug!(
                    session.id = %session_id,
                    control.connection = connection.0,
                    "re-offer refused: not the session's owner"
                );
                return Outcome::Error(
                    ApiError::new(
                        ErrorCode::SessionNotFound,
                        "the session is not this connection's",
                    )
                    .with_detail("session_id", session_id.as_str()),
                );
            }
            if let Err(error) = session.renegotiate(reply) {
                return Outcome::Error(error.with_detail("session_id", session_id.as_str()));
            }
            let connection = session.connection.clone();
            let queued = state.connections.get(&connection).is_some_and(|entry| {
                entry
                    .commands
                    .try_send(DriverCommand::Renegotiate {
                        session_id: session_id.clone(),
                        sdp: command.sdp,
                    })
                    .is_ok()
            });
            if !queued {
                if let Some(session) = state.sessions.get_mut(&session_id) {
                    session.renegotiation_unsent();
                }
                return Outcome::Error(
                    ApiError::new(ErrorCode::LimitReached, "the stream's connection is busy")
                        .with_detail("limit", "connection_queue"),
                );
            }
            drop(state);
        }
        tracing::info!(
            event = "session_renegotiate",
            session.id = %session_id,
            "re-offer handed to the worker"
        );
        let answer = tokio::select! {
            answer = waiting => answer,
            // The re-offer stays out until the worker's report, which
            // then goes nowhere: the next re-offer is refused till then,
            // so a late report never answers it.
            () = self.shared.clock.sleep(RENEGOTIATE_TIMEOUT) => {
                tracing::warn!(session.id = %session_id, "re-offer not answered by the worker in time");
                return Outcome::Error(
                    ApiError::new(ErrorCode::InternalError, "the worker did not answer the re-offer")
                        .with_detail("session_id", session_id.as_str()),
                );
            }
        };
        match answer {
            Ok(Ok(sdp)) => {
                tracing::info!(
                    event = "session_renegotiated",
                    session.id = %session_id,
                    "re-offer answered"
                );
                Outcome::Result(
                    serde_json::to_value(WebrtcRenegotiateResult { sdp }).unwrap_or_default(),
                )
            }
            Ok(Err(error)) => {
                let code = error.code.as_str();
                tracing::info!(session.id = %session_id, code, detail = ?error.message, "re-offer refused by the worker");
                Outcome::Error(error.with_detail("session_id", session_id.as_str()))
            }
            // The session closed while the re-offer waited: its entry, and
            // the answer's way back, went with it.
            Err(_closed) => Outcome::Error(session_not_found(&session_id)),
        }
    }

    /// `session/get`.
    fn session_get(&self, session_id: &str) -> Outcome {
        let state = self.shared.lock();
        match state.sessions.get(session_id) {
            Some(session) => Outcome::Result(
                serde_json::to_value(state.session_dto(session_id, session)).unwrap_or_default(),
            ),
            None => Outcome::Error(session_not_found(session_id)),
        }
    }

    /// `session/list`.
    fn session_list(&self) -> Outcome {
        let state = self.shared.lock();
        let sessions = state
            .sessions
            .iter()
            .map(|(id, session)| state.session_dto(id, session))
            .collect();
        drop(state);
        Outcome::Result(serde_json::to_value(SessionList { sessions }).unwrap_or_default())
    }

    /// `session/close`: any session, idempotent.
    fn session_close(&self, session_id: &str) -> Outcome {
        let _event = self.shared.lock().close_session(
            session_id,
            CloseCode::SessionClosed,
            "closed by session/close",
            CloseBy::Supervisor,
        );
        Outcome::Result(serde_json::Value::Object(serde_json::Map::new()))
    }

    /// `session/adopt`: takes back an orphaned session.
    fn session_adopt(&self, connection: ConnectionId, id: u64, session_id: &str) -> Outcome {
        let mut state = self.shared.lock();
        let Some(session) = state.sessions.get_mut(session_id) else {
            return Outcome::Error(session_not_found(session_id));
        };
        if session.is_owned() {
            return Outcome::Error(
                ApiError::new(ErrorCode::SessionIdInUse, "the session still has an owner")
                    .with_detail("session_id", session_id),
            );
        }
        let events = session.adopt(connection, id);
        drop(state);
        tracing::info!(
            event = "session_adopted",
            session.id = session_id,
            control.connection = connection.0,
            "session adopted"
        );
        Outcome::Subscribed(events)
    }

    /// `backchannel/release`: frees the camera's backchannel from its
    /// talker, or only from `session_id` when given, on each of the
    /// stream's sources whose protocol can carry audio back. Non-blocking:
    /// the worker decides against its claims and releases it, and a
    /// `talker_changed` with `released` follows on `stream/subscribe`.
    /// Releasing a free backchannel, or one another session holds, succeeds
    /// and changes nothing; the result names the talker as last heard
    /// either way.
    fn backchannel_release(&self, stream_id: &str, session_id: Option<&str>) -> Outcome {
        let state = self.shared.lock();
        let Some(stream) = state.streams.get(stream_id) else {
            return Outcome::Error(
                ApiError::new(ErrorCode::StreamNotFound, "no such stream")
                    .with_detail("stream_id", stream_id),
            );
        };
        let connections: Vec<&ConnectionEntry> = stream
            .sources
            .iter()
            .filter(|source| {
                source
                    .target
                    .url()
                    .and_then(|url| self.registries.sources.get(url.scheme()))
                    .is_some_and(|factory| factory.capabilities().backchannel)
            })
            .filter_map(|source| state.connections.get(&source.connection))
            .collect();
        if connections.is_empty() {
            return Outcome::Error(
                ApiError::new(
                    ErrorCode::BackchannelUnsupported,
                    "the stream's source cannot carry audio back to the camera",
                )
                .with_detail("stream_id", stream_id),
            );
        }
        // Sent whatever the supervisor last heard: a claim may be on its
        // way, and the worker's release is idempotent.
        let mut talker = None;
        for connection in connections {
            if let Some(session) = &connection.talker.session {
                talker.get_or_insert_with(|| session.clone());
            }
            if connection
                .commands
                .try_send(DriverCommand::ReleaseBackchannel {
                    session_id: session_id.map(str::to_owned),
                })
                .is_err()
            {
                return Outcome::Error(
                    ApiError::new(ErrorCode::LimitReached, "the stream's connection is busy")
                        .with_detail("limit", "connection_queue"),
                );
            }
        }
        drop(state);
        tracing::info!(
            event = "backchannel_release",
            stream.id = stream_id,
            session.id = session_id,
            talker = ?talker,
            "backchannel release requested"
        );
        Outcome::Result(
            serde_json::to_value(BackchannelReleaseResult { talker }).unwrap_or_default(),
        )
    }

    /// `recording/create`: validates against the limits, creates the recording's
    /// pipe, hands its start with the write end to the stream's
    /// connection's driver (which raises its demand: a recording is a viewer),
    /// keeps the read end for `GET /v0/recording/{recording_id}`, and answers with
    /// the recording's id and path, then its events. The fetch deadline runs
    /// from here until the body is taken.
    fn recording_create(
        &self,
        connection: ConnectionId,
        start: &RecordingCreate,
    ) -> Result<(RecordingCreateResult, mpsc::Receiver<Event>), ApiError> {
        let stream_id = StreamId::new(&start.stream_id).map_err(|err| {
            ApiError::new(ErrorCode::InvalidStreamId, err.to_string())
                .with_detail("stream_id", start.stream_id.as_str())
        })?;
        let recording_id = match &start.recording_id {
            Some(id) => RecordingId::new(id).map_err(|_| {
                ApiError::new(
                    ErrorCode::InvalidRequest,
                    "recording_id must match ^[A-Za-z0-9._-]{1,128}$ and not be `.` or `..`",
                )
                .with_detail("recording_id", id.as_str())
            })?,
            None => RecordingId::new(&ulid(self.shared.clock.wall_now()).map_err(internal)?)
                .map_err(internal)?,
        };
        let (reader, writer) = std::io::pipe().map_err(internal)?;
        let reader =
            tokio::net::unix::pipe::Receiver::from_owned_fd(reader.into()).map_err(internal)?;
        let mut state = self.shared.lock();
        let limits = state.recording_limits;
        check_recording_request(&state, start, limits)?;
        let stream = state.streams.get(stream_id.as_str()).ok_or_else(|| {
            ApiError::new(ErrorCode::StreamNotFound, "no such stream")
                .with_detail("stream_id", stream_id.as_str())
        })?;
        let SessionConnection {
            id: connection_id,
            commands,
            ..
        } = session_connection(&state, stream)?;
        check_recording_stream(&state, stream_id.as_str(), &connection_id, limits)?;
        if state.recording_id_in_use(recording_id.as_str()) {
            return Err(ApiError::new(
                ErrorCode::RecordingIdInUse,
                "the recording id is already open",
            )
            .with_detail("recording_id", recording_id.as_str()));
        }
        let spec = RecordingSpec {
            recording_id: recording_id.as_str().to_owned(),
            prerecord_ms: start.prerecord_ms,
            duration_ms: start.duration_ms,
            audio: start.audio,
        };
        let serial = state.last_recording.saturating_add(1);
        let stop_slot = hand_over_recording(&commands, (spec.clone(), serial), writer.into())?;
        state.last_recording = serial;
        let (events, rx) = mpsc::channel(RECORDING_QUEUE);
        let (written, report) = oneshot::channel();
        let body = RecordingBody {
            reader: Box::new(reader),
            written: report,
        };
        let owner = RecordingOwner {
            connection,
            subscription: start.id,
            events,
        };
        let mut entry = RecordingEntry::new(
            serial,
            (stream_id.as_str().to_owned(), connection_id.clone()),
            spec,
            owner,
            (body, written),
        );
        entry.stop_slot = Some(stop_slot);
        entry.timer =
            Some(self.fetch_deadline(recording_id.as_str(), serial, limits.fetch_timeout));
        state
            .recordings
            .insert(recording_id.as_str().to_owned(), entry);
        if let Some(stream) = state.streams.get_mut(stream_id.as_str()) {
            stream.recordings.started = stream.recordings.started.saturating_add(1);
        }
        state.refresh_connection(&connection_id);
        drop(state);
        tracing::info!(
            event = "recording_opened",
            recording.id = %recording_id,
            stream.id = %stream_id,
            connection.id = %connection_id,
            control.connection = connection.0,
            prerecord_ms = start.prerecord_ms,
            duration_ms = start.duration_ms,
            audio = start.audio,
            "recording opened; handed to the connection"
        );
        let result = RecordingCreateResult {
            url: recording_path(recording_id.as_str()),
            recording_id: recording_id.as_str().to_owned(),
        };
        Ok((result, rx))
    }

    /// The fetch deadline of recording `serial`, `recording_id`, `timeout` from now on
    /// the injected clock ([`State::recording_fetch_deadline`]).
    fn fetch_deadline(&self, recording_id: &str, serial: u64, timeout: Duration) -> RecordingTimer {
        // The deadline counts from now, not from the task's first poll.
        let sleep = self.shared.clock.sleep(timeout);
        let shared = Arc::clone(&self.shared);
        let id = recording_id.to_owned();
        let timer = spawn_named("recording.fetch", async move {
            sleep.await;
            shared.lock().recording_fetch_deadline(&id, serial);
        });
        RecordingTimer(timer.abort_handle())
    }

    /// Answers one command.
    async fn dispatch(&self, connection: ConnectionId, command: Command) -> Outcome {
        match command {
            Command::Info(_) => {
                Outcome::Result(serde_json::to_value(self.info()).unwrap_or_default())
            }
            Command::MetricsGet(_) => {
                Outcome::Result(serde_json::to_value(self.metrics().await).unwrap_or_default())
            }
            Command::StreamPut(put) => self.stream_put(&put),
            Command::StreamGet(get) => self.stream_get(&get.stream_id).await,
            Command::StreamList(_) => self.stream_list().await,
            Command::StreamDelete(delete) => self.stream_delete(&delete.stream_id),
            Command::StreamSubscribe(subscribe) => {
                self.stream_subscribe(connection, subscribe.stream_id)
            }
            Command::WebrtcOffer(offer) => match self.webrtc_offer(connection, offer) {
                Ok(events) => Outcome::Subscribed(events),
                Err(error) => Outcome::Error(error),
            },
            Command::WebrtcCandidate(candidate) => self.webrtc_candidate(connection, &candidate),
            Command::WebrtcRenegotiate(renegotiate) => {
                self.webrtc_renegotiate(connection, renegotiate).await
            }
            Command::SessionGet(get) => self.session_get(&get.session_id),
            Command::SessionList(_) => self.session_list(),
            Command::SessionClose(close) => self.session_close(&close.session_id),
            Command::SessionAdopt(adopt) => {
                self.session_adopt(connection, adopt.id, &adopt.session_id)
            }
            Command::BackchannelRelease(release) => {
                self.backchannel_release(&release.stream_id, release.session_id.as_deref())
            }
            Command::RecordingCreate(start) => match self.recording_create(connection, &start) {
                Ok((result, events)) => Outcome::SubscribedWith {
                    result: serde_json::to_value(result).unwrap_or_default(),
                    events,
                },
                Err(error) => {
                    tracing::debug!(code = error.code.as_str(), detail = %error.message, "recording/create refused");
                    Outcome::Error(error)
                }
            },
            Command::SignalingSubscribe(subscribe) => {
                self.signaling_subscribe(connection, subscribe.id, subscribe.stream_id)
            }
            Command::SignalingAnswer(answer) => {
                empty(self.shared.lock().signal_answer(connection, &answer))
            }
            Command::SignalingCandidate(candidate) => {
                empty(self.shared.lock().signal_candidate(connection, &candidate))
            }
            Command::SignalingError(error) => {
                empty(self.shared.lock().signal_error(connection, &error))
            }
            Command::Ping(_)
            | Command::Schema(_)
            | Command::Unsubscribe(_)
            | Command::PairingCreate(_)
            | Command::ClientsList(_)
            | Command::ClientsRemove(_) => {
                tracing::error!(
                    command = command.name(),
                    "the server answers this command itself"
                );
                Outcome::Error(ApiError::new(
                    ErrorCode::InternalError,
                    "the server answers this command itself",
                ))
            }
        }
    }
}

impl Handler for Supervisor {
    fn hello(&self) -> Hello {
        Hello {
            kind: HelloTag::default(),
            api: API_VERSION.to_owned(),
            version: self.identity.version.clone(),
            outputs: self.outputs(),
            features: self.features(),
        }
    }

    fn handle(
        &self,
        connection: ConnectionId,
        command: Command,
    ) -> impl Future<Output = Outcome> + Send {
        self.dispatch(connection, command)
    }

    /// A session's ends with its `closed`; a recording's is stopped, and its
    /// `closed` goes nowhere, the client having asked for no more events;
    /// a signaling one ends its signals, whose sources connect again.
    fn unsubscribed(&self, connection: ConnectionId, subscription: u64) -> Option<Event> {
        let mut state = self.shared.lock();
        if state.unsubscribe_recording(connection, subscription)
            || state.signaling_unsubscribed(connection, subscription)
        {
            return None;
        }
        let session_id = state
            .sessions
            .iter()
            .find(|(_, session)| session.owned_by(connection, subscription))
            .map(|(id, _)| id.clone())?;
        state.close_session(
            &session_id,
            CloseCode::SessionClosed,
            "unsubscribed",
            CloseBy::Unsubscribe,
        )
    }

    /// Its sessions are orphaned for the grace, its recordings and its
    /// signaling subscriptions end at once.
    fn connection_closed(&self, connection: ConnectionId) {
        let orphans = {
            let mut state = self.shared.lock();
            state.recordings_connection_closed(connection);
            state.connection_closed(connection)
        };
        for (id, serial, epoch) in orphans {
            let session_id = id.clone();
            self.shared.after(
                &session_id,
                serial,
                self.settings.limits.session_grace,
                move |state| {
                    if state.sessions.get(&id).is_some_and(|session| {
                        session.serial == serial
                            && !session.is_owned()
                            && session.orphan_epoch() == epoch
                    }) {
                        let _event = state.close_session(
                            &id,
                            CloseCode::SessionClosed,
                            "not adopted within the grace period",
                            CloseBy::Supervisor,
                        );
                    }
                },
            );
        }
    }

    /// Hands out the read end of the recording's pipe once, with the way its
    /// worker's `bytes` reach the body.
    fn recording_body(
        &self,
        recording_id: &RecordingId,
    ) -> Result<RecordingBody, RecordingBodyError> {
        let body = self
            .shared
            .lock()
            .take_recording_body(recording_id.as_str());
        match &body {
            Ok(_) => {
                tracing::info!(event = "recording_fetched", recording.id = %recording_id, "recording body handed out");
            }
            Err(error) => {
                tracing::debug!(recording.id = %recording_id, %error, "recording body refused");
            }
        }
        body
    }
}

/// The empty result of a command that changed what `result` says, or its
/// refusal.
fn empty(result: Result<(), ApiError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Result(serde_json::Value::Object(serde_json::Map::new())),
        Err(error) => Outcome::Error(error),
    }
}

/// A process's memory at `now` through its probe; unknown without one.
async fn sample(probe: Option<&MemoryProbe>, now: Instant) -> Memory {
    match probe {
        Some(probe) => probe.sample(now).await,
        None => Memory::default(),
    }
}

/// Whether `put` asks for what `entry` already is: its flags and its
/// sources, URL and options alike, in order.
fn unchanged(entry: &StreamEntry, put: &StreamPut, validated: &[ValidatedSource]) -> bool {
    entry.preload == put.preload
        && entry.prerecord_ms == put.prerecord_ms
        && entry.audio == put.audio
        && entry.orientation == put.orientation
        && entry.sources.len() == validated.len()
        && entry
            .sources
            .iter()
            .zip(validated)
            .all(|(a, b)| a.target == b.target && a.options == b.options)
}

/// `source_in_use` when a source of `stream_id`'s put is another stream's
/// URL, credentials aside: a camera stream is one stream, so the client is
/// pointed at the stream that has it.
fn source_in_use(
    state: &State,
    stream_id: &str,
    validated: &[ValidatedSource],
) -> Option<ApiError> {
    validated.iter().find_map(|source| {
        let url = source.target.url()?;
        let other = state.stream_with_source(stream_id, url)?;
        tracing::info!(
            stream.id = %stream_id,
            other.id = %other,
            url = %url,
            "stream/put refused: the source is another stream's"
        );
        Some(
            ApiError::new(
                ErrorCode::SourceInUse,
                format!(
                    "{url} is already the source of stream {other}; use that stream id, or put {other} with the new source"
                ),
            )
            .with_detail("stream_id", other),
        )
    })
}

/// What the driver of connection `id` runs for `source`.
fn driver_spec(id: &str, source: &ValidatedSource) -> DriverSpec {
    DriverSpec {
        connection_id: id.to_owned(),
        target: source.raw.clone(),
        options: serde_json::Value::Object(source.options.clone()).to_string(),
        host: source
            .target
            .url()
            .map(|url| url.host().to_owned())
            .unwrap_or_default(),
        port: source.port(),
        backchannel: source.backchannel,
    }
}

/// Whether connection `id` can switch to `source` in place, keeping its
/// worker and so its sessions: the worker's sandbox is pinned to the port
/// it may connect to, so a source on another port needs a new worker. A
/// signaled source never switches in place, to or from: its standby would
/// be a second signal of one camera, offered while the first still
/// streams.
fn switchable(state: &State, id: &str, source: &ValidatedSource) -> bool {
    state.connections.get(id).is_some_and(|entry| {
        !entry.key.target.signaled() && !source.target.signaled() && entry.port == source.port()
    })
}

/// Closes the sessions and ends the recordings of `stream_id` that are not on
/// its first source's connection any more: a `stream/put` changed the
/// source's port, so it moved to a new worker.
fn close_moved_sessions(state: &mut State, stream_id: &str) {
    let current = state
        .streams
        .get(stream_id)
        .and_then(|entry| entry.sources.first())
        .map(|source| source.connection.clone());
    state.close_sessions_where(
        |session| session.stream_id == stream_id && current.as_ref() != Some(&session.connection),
        CloseCode::StreamChanged,
        "the stream's source changed",
        CloseBy::Supervisor,
    );
    state.end_recordings_where(
        |recording| {
            recording.stream_id == stream_id && current.as_ref() != Some(&recording.connection)
        },
        RecordingCloseReason::StreamChanged,
    );
}

/// `limit_reached` when another session would exceed `max_sessions` or,
/// on `stream_id`, `max_sessions_per_stream`.
fn check_session_limits(
    state: &State,
    stream_id: &str,
    limits: &crate::Limits,
) -> Result<(), ApiError> {
    let on_stream = state
        .sessions
        .values()
        .filter(|session| session.stream_id == stream_id)
        .count();
    for (count, limit, name) in [
        (state.sessions.len(), limits.max_sessions, "max_sessions"),
        (
            on_stream,
            limits.max_sessions_per_stream,
            "max_sessions_per_stream",
        ),
    ] {
        if count >= usize::try_from(limit).unwrap_or(usize::MAX) {
            return Err(ApiError::new(ErrorCode::LimitReached, "too many sessions")
                .with_detail("limit", name));
        }
    }
    Ok(())
}

/// `invalid_request` when `start` asks further back than the longest
/// window or longer than the longest recording, `limit_reached` when another
/// recording would exceed `max_recordings`, which counts the recordings their workers are
/// still finishing and the bodies that wait for their `GET` besides those
/// that run ([`State::recordings_held`]): each holds a pipe's end.
fn check_recording_request(
    state: &State,
    start: &RecordingCreate,
    limits: RecordingLimits,
) -> Result<(), ApiError> {
    if start.prerecord_ms > limits.max_prerecord_ms {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!(
                "`prerecord_ms` is {}, the maximum is {} (`limits.max_prerecord_ms`)",
                start.prerecord_ms, limits.max_prerecord_ms
            ),
        )
        .with_detail("field", "prerecord_ms"));
    }
    if start.duration_ms > limits.max_recording_ms {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!(
                "`duration_ms` is {}, the maximum is {} (`limits.max_recording_ms`)",
                start.duration_ms, limits.max_recording_ms
            ),
        )
        .with_detail("field", "duration_ms"));
    }
    if state.recordings_held() >= usize::try_from(limits.max_recordings).unwrap_or(usize::MAX) {
        return Err(
            ApiError::new(ErrorCode::LimitReached, "too many recordings")
                .with_detail("limit", "max_recordings"),
        );
    }
    Ok(())
}

/// `limit_reached` when another recording of `stream_id` would exceed
/// `max_recordings_per_stream`; `no_video_track` when the tracks its connection
/// `connection` declared, while its source is live, have no video.
fn check_recording_stream(
    state: &State,
    stream_id: &str,
    connection: &str,
    limits: RecordingLimits,
) -> Result<(), ApiError> {
    let on_stream = state
        .recordings
        .values()
        .filter(|recording| recording.stream_id == stream_id)
        .count();
    if on_stream >= usize::try_from(limits.max_recordings_per_stream).unwrap_or(usize::MAX) {
        return Err(
            ApiError::new(ErrorCode::LimitReached, "too many recordings of the stream")
                .with_detail("limit", "max_recordings_per_stream"),
        );
    }
    // Only a live source's tracks are its own: those the connection keeps
    // from the last time it went live may be another source's (a
    // `stream/put` switched it in place since) or the camera's before it
    // changed, and with nothing running a refusal here would hold back
    // the very demand that finds out. A source that is not live takes the
    // start; its worker ends a recording without video itself
    // (`no_video_track`), on the tracks it declares when it comes up.
    let tracks = state
        .connections
        .get(connection)
        .filter(|entry| entry.snapshot.state == ConnectionState::Live)
        .map(|entry| entry.snapshot.tracks.as_slice())
        .unwrap_or_default();
    if !tracks.is_empty() && !tracks.iter().any(|track| track.kind == Kind::Video.name()) {
        return Err(ApiError::new(
            ErrorCode::NoVideoTrack,
            "the stream has no video track to record",
        )
        .with_detail("stream_id", stream_id));
    }
    Ok(())
}

/// Hands the start of recording `spec`, `serial`, with `pipe`, the write end of
/// its pipe, to its connection's driver, and returns the slot reserved
/// behind it for the recording's stop; a queue without room for both is
/// `limit_reached`.
fn hand_over_recording(
    commands: &mpsc::Sender<DriverCommand>,
    (spec, serial): (RecordingSpec, u64),
    pipe: std::os::fd::OwnedFd,
) -> Result<mpsc::OwnedPermit<DriverCommand>, ApiError> {
    let busy = |_| {
        ApiError::new(ErrorCode::LimitReached, "the stream's connection is busy")
            .with_detail("limit", "connection_queue")
    };
    let start = commands.clone().try_reserve_owned().map_err(busy)?;
    let stop = commands.clone().try_reserve_owned().map_err(busy)?;
    drop(start.send(DriverCommand::StartRecording { spec, serial, pipe }));
    Ok(stop)
}

/// The connection a session opens on, as [`session_connection`] finds it.
struct SessionConnection {
    /// The connection's id.
    id: String,
    /// The connection's command queue.
    commands: mpsc::Sender<DriverCommand>,
    /// The failure a session waiting for its answer closes with, and the
    /// connection's state with it; none while the connection can answer.
    failure: Option<(ConnectionError, ConnectionState)>,
}

/// The connection a session of `stream` opens on: its first source's.
fn session_connection(state: &State, stream: &StreamEntry) -> Result<SessionConnection, ApiError> {
    stream
        .sources
        .first()
        .and_then(|source| {
            let (id, entry) = state.connections.get_key_value(&source.connection)?;
            let snapshot = &entry.snapshot;
            Some(SessionConnection {
                id: id.clone(),
                commands: entry.commands.clone(),
                failure: snapshot.failure.clone().map(|e| (e, snapshot.state)),
            })
        })
        .ok_or_else(|| internal("the stream has no source connection"))
}

/// Hands the offer `spec` to its connection's driver, unless the
/// connection `failed` already, and returns the slot reserved behind it
/// for the session's close ([`SessionEntry::close_slot`]); a queue
/// without room for both is `limit_reached`.
fn hand_over(
    commands: &mpsc::Sender<DriverCommand>,
    spec: SessionSpec,
    failed: bool,
) -> Result<Option<mpsc::OwnedPermit<DriverCommand>>, ApiError> {
    if failed {
        return Ok(None);
    }
    let busy = |_| {
        ApiError::new(ErrorCode::LimitReached, "the stream's connection is busy")
            .with_detail("limit", "connection_queue")
    };
    let open = commands.clone().try_reserve_owned().map_err(busy)?;
    let close = commands.clone().try_reserve_owned().map_err(busy)?;
    drop(open.send(DriverCommand::OpenSession(spec)));
    Ok(Some(close))
}

/// `session_not_found` for `session_id`.
fn session_not_found(session_id: &str) -> ApiError {
    ApiError::new(ErrorCode::SessionNotFound, "no such session")
        .with_detail("session_id", session_id)
}

/// `invalid_request` for a session id off the pattern.
fn invalid_session_id(session_id: &str) -> ApiError {
    ApiError::new(
        ErrorCode::InvalidRequest,
        "session_id must match ^[A-Za-z0-9._-]{1,128}$",
    )
    .with_detail("session_id", session_id)
}

/// `internal_error` for a failure that is a bug or a broken host.
fn internal(error: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %error, "internal error");
    ApiError::new(ErrorCode::InternalError, error.to_string())
}

/// The demux's counters as `metrics/get` reports them.
fn demux_metrics(stats: &DemuxStats) -> DemuxMetrics {
    DemuxMetrics {
        received: DemuxStats::get(&stats.received),
        forwarded: DemuxStats::get(&stats.forwarded),
        unroutable: DemuxStats::get(&stats.unroutable),
        stun_rejected: DemuxStats::get(&stats.stun_rejected),
        addresses_learned: DemuxStats::get(&stats.addresses_learned),
        addresses_moved: DemuxStats::get(&stats.addresses_moved),
        worker_full: DemuxStats::get(&stats.worker_full),
        responses: DemuxStats::get(&stats.responses),
        relayed: DemuxStats::get(&stats.relayed),
        relay_discarded: DemuxStats::get(&stats.relay_discarded),
        idle_wakeups: DemuxStats::get(&stats.idle_wakeups),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    use lotse_api::Event;
    use lotse_api_types::command::parse_command;
    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::connection::{ConnectionError, ConnectionState};
    use lotse_core::let_assert;
    use lotse_core::source::SourceError;
    use lotse_core::test_util::{FakeOutputFactory, FakeSourceFactory};
    use lotse_ipc::SessionEvent as Report;
    use serde_json::{Value, json};
    use tokio::sync::mpsc;

    use super::*;
    use crate::test_support::{Captured, environment, private_dir, settings};

    #[test]
    fn the_schema_advertises_the_identifier_rule_the_core_checks() {
        use lotse_api_types::limits::{ID_PATTERN, MAX_ID_CHARS};
        assert_eq!(MAX_ID_CHARS, lotse_core::id::MAX_LEN);
        assert_eq!(
            ID_PATTERN,
            format!("^[A-Za-z0-9._-]{{1,{}}}$", lotse_core::id::MAX_LEN)
        );
    }

    fn supervisor(binary: &str, clock: Arc<dyn Clock>) -> Supervisor {
        let mut settings = settings(PathBuf::from("/nonexistent/lotse.sock"));
        settings.shutdown_budget = Duration::from_millis(200);
        Supervisor::new(settings, environment(binary), clock)
    }

    async fn call(supervisor: &Supervisor, command: &str) -> Outcome {
        let command = parse_command(command).expect(command);
        supervisor.handle(ConnectionId(1), command).await
    }

    fn result(outcome: Outcome) -> Value {
        let_assert!(Outcome::Result(value) = outcome);
        value
    }

    fn error(outcome: Outcome) -> ApiError {
        let_assert!(Outcome::Error(err) = outcome);
        err
    }

    fn subscription(outcome: Outcome) -> mpsc::Receiver<Event> {
        let_assert!(Outcome::Subscribed(rx) = outcome);
        rx
    }

    /// The next event, failing the test after 10 s instead of hanging it
    /// (a lost event is a failure, not a timeout of the mutation run).
    async fn next(rx: &mut mpsc::Receiver<Event>) -> Value {
        tokio::select! {
            event = rx.recv() => event.expect("an event").payload,
            () = SystemClock.sleep(Duration::from_secs(10)) => panic!("no event in 10 s"),
        }
    }
    /// `future`'s output, or a failed test after five seconds of real
    /// time: a command whose answer never comes fails instead of hanging.
    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::select! {
            output = future => output,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
        }
    }

    fn put(stream_id: &str, url: &str, preload: bool) -> String {
        json!({ "id": 1, "type": "stream/put", "stream_id": stream_id,
                "sources": [{ "url": url }], "preload": preload })
        .to_string()
    }

    /// A worker that ignores its arguments and blocks, standing in for a
    /// worker that never reports.
    fn blocking_worker(dir: &std::path::Path) -> String {
        let path = dir.join("worker.sh");
        std::fs::write(&path, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Settings with at most two sessions per stream and three in all.
    fn session_settings() -> Settings {
        let mut settings = settings(PathBuf::from("/nonexistent/lotse.sock"));
        settings.shutdown_budget = Duration::from_millis(200);
        settings.limits.max_sessions = 3;
        settings.limits.max_sessions_per_stream = 2;
        settings
    }

    /// An environment with a `webrtc` session output and `front_door`.
    fn webrtc_environment(binary: &str, front_door: FrontDoor) -> Environment {
        let mut environment = environment(binary);
        environment
            .registries
            .outputs
            .register(Arc::new(FakeOutputFactory(WEBRTC)))
            .unwrap();
        environment.front_door = Some(front_door);
        environment
    }

    /// A supervisor with a `webrtc` session output, whose workers are
    /// `binary`, and a front door without STUN.
    fn with_webrtc(binary: &str, clock: Arc<dyn Clock>) -> Supervisor {
        let door = FrontDoor {
            registrations: Arc::new(Registrations::default()),
            hosts: vec!["192.0.2.1:18556".parse().unwrap()],
            tcp_hosts: vec!["192.0.2.1:18557".parse().unwrap()],
            stun: None,
            turn: None,
            demux: None,
        };
        Supervisor::new(session_settings(), webrtc_environment(binary, door), clock)
    }

    async fn call_on(supervisor: &Supervisor, connection: u64, command: &Value) -> Outcome {
        let command = parse_command(&command.to_string()).unwrap();
        supervisor.handle(ConnectionId(connection), command).await
    }

    fn offer(id: u64, stream_id: &str, session_id: Option<&str>) -> Value {
        let mut offer =
            json!({ "id": id, "type": "webrtc/offer", "stream_id": stream_id, "sdp": "v=0" });
        if let Some(session_id) = session_id {
            offer["session_id"] = json!(session_id);
        }
        offer
    }

    fn report(s: &Supervisor, session_id: &str, event: lotse_ipc::SessionEvent) {
        let mut state = s.shared.lock();
        let connection = state.sessions[session_id].connection.clone();
        state.session_report(&connection, session_id, event, s.shared.clock.now());
    }

    #[tokio::test]
    async fn hello_and_info_reflect_the_build_and_the_registries() {
        let s = supervisor("/bin/sh", Arc::new(SystemClock));
        let hello = s.hello();
        assert_eq!(
            (hello.api.as_str(), hello.version.as_str()),
            (API_VERSION, "0.0.0-test")
        );
        assert!(hello.outputs.is_empty());
        assert_eq!(hello.features, ["session_adopt"]);
        let info = result(call(&s, r#"{"id":1,"type":"info"}"#).await);
        assert_eq!(info["schemes"], json!(["fake"]));
        assert_eq!(info["signaled_protocols"], json!(["fake-signaled"]));
        assert_eq!(info["build"]["target"], "test");
        // Only what an output can play: MJPEG is ingested and reported per
        // track, but no output negotiates it.
        assert_eq!(info["codecs"]["video"], json!(["h264", "h265"]));
        assert_eq!(info["limits"]["max_streams"], 2);
        assert_eq!(info["limits"]["session_grace_ms"], 10_000);
        assert_eq!(info["sandbox"]["mode"], "off");
        let metrics = result(call(&s, r#"{"id":2,"type":"metrics/get"}"#).await);
        assert_eq!(metrics["worker_restarts"], 0);
        assert_eq!(metrics["supervisor"]["pid"], std::process::id());
        assert_eq!(metrics["streams"], json!({}));
        let captured = Captured::default();
        let _logs = captured.install();
        let err = error(call(&s, r#"{"id":3,"type":"ping"}"#).await);
        assert_eq!(err.code, ErrorCode::InternalError);
        let err = error(call(&s, r#"{"id":4,"type":"pairing/create"}"#).await);
        assert_eq!(err.code, ErrorCode::InternalError);
        let err = error(call(&s, r#"{"id":5,"type":"clients/list"}"#).await);
        assert_eq!(err.code, ErrorCode::InternalError);
        let err = error(call(&s, r#"{"id":6,"type":"clients/remove","pin":"00"}"#).await);
        assert_eq!(err.code, ErrorCode::InternalError);
        let logged = captured.lines("the server answers this command itself");
        assert!(logged[0].contains("command=\"ping\""), "{logged:?}");
        assert!(
            logged[1].contains("command=\"pairing/create\""),
            "{logged:?}"
        );
        assert!(logged[2].contains("command=\"clients/list\""), "{logged:?}");
        assert!(
            logged[3].contains("command=\"clients/remove\""),
            "{logged:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn without_recordings_no_window_or_recording_is_taken_and_info_says_so() {
        let s = supervisor("/bin/sh", Arc::new(SystemClock));
        let info = result(call(&s, r#"{"id":1,"type":"info"}"#).await);
        for limit in [
            "max_prerecord_ms",
            "max_prerecord_bytes",
            "max_recording_ms",
            "max_recordings",
            "max_recordings_per_stream",
        ] {
            assert_eq!(info["limits"][limit], 0, "{limit}");
        }
        let captured = Captured::default();
        let _logs = captured.install();
        // A window asked for is refused, not ignored.
        let windowed = json!({ "id": 2, "type": "stream/put", "stream_id": "front",
                               "sources": [{ "url": "fake://127.0.0.1/" }], "prerecord_ms": 1 });
        let err = error(call(&s, &windowed.to_string()).await);
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert_eq!(
            err.message,
            "`prerecord_ms` is 1, the maximum is 0 (`limits.max_prerecord_ms`)"
        );
        assert_eq!(err.details["field"], "prerecord_ms");
        assert!(s.shared.lock().streams.is_empty());
        let err = error(
            call(
                &s,
                r#"{"id":3,"type":"recording/create","stream_id":"front","duration_ms":1}"#,
            )
            .await,
        );
        // No recording is long enough: the longest is 0.
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert_eq!(
            err.message,
            "`duration_ms` is 1, the maximum is 0 (`limits.max_recording_ms`)"
        );
        let refused = captured.lines("recording/create refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].contains("code=\"invalid_request\""),
            "{refused:?}"
        );
        // No id has a body.
        let recording_id = RecordingId::new("c1").unwrap();
        assert_eq!(
            s.recording_body(&recording_id).unwrap_err(),
            RecordingBodyError::NotFound
        );
    }

    #[tokio::test]
    async fn an_offer_for_a_stream_whose_connection_is_gone_is_an_internal_error() {
        let s = with_webrtc("/bin/sh", Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1/", false)).await);
        // The registry's invariant broken by hand: the stream outlives its
        // connection.
        s.shared.lock().connections.clear();
        let err = error(call_on(&s, 1, &offer(2, "front", Some("f1"))).await);
        assert_eq!(err.code, ErrorCode::InternalError);
        assert!(err.message.contains("no source connection"), "{err}");
        s.shutdown().await;
    }

    #[tokio::test]
    async fn a_shutdown_whose_connections_miss_the_budget_is_logged_and_ends() {
        let clock = Arc::new(FakeClock::default());
        let s = supervisor("/bin/sh", clock.clone());
        // A connection's driver that never stops.
        let _stuck = spawn_named(
            "test.driver",
            s.shared.tracker.track_future(std::future::pending::<()>()),
        );
        let captured = Captured::default();
        let _logs = captured.install();
        let mut shutdown = Box::pin(s.shutdown());
        // One poll starts the budget on the fake clock.
        let early = tokio::select! {
            biased;
            () = &mut shutdown => true,
            () = std::future::ready(()) => false,
        };
        assert!(!early, "the driver holds it up");
        clock.advance(Duration::from_millis(200) + SHUTDOWN_GRACE);
        shutdown.await;
        assert_eq!(
            captured
                .lines("connections missed the shutdown budget")
                .len(),
            1
        );
    }

    /// A reverse chain that is never asked to run.
    #[derive(Debug)]
    struct IdleUplink;

    impl lotse_core::transcode::UplinkFactory for IdleUplink {
        fn transcoder(&self, _frame: Duration) -> Arc<dyn lotse_core::transcode::Transcoder> {
            Arc::new(lotse_core::test_util::FakeTranscoder::aac_to_opus())
        }
    }

    /// `two_way_audio` is announced only when a viewer's
    /// talk-back can reach a camera: a source protocol that carries audio
    /// back, a reverse chain, and the `webrtc` output.
    #[tokio::test]
    async fn two_way_audio_is_announced_only_when_talk_back_can_reach_a_camera() {
        use lotse_core::transcode::UplinkFactory as _;

        for (backchannel, uplink, webrtc, announced) in [
            (true, true, true, true),
            (false, true, true, false),
            (true, false, true, false),
            (true, true, false, false),
        ] {
            let mut environment = environment("/bin/sh");
            if backchannel {
                environment
                    .registries
                    .sources
                    .register(Arc::new(FakeSourceFactory::with_backchannel(&["talk"])))
                    .unwrap();
            }
            if uplink {
                environment.registries.uplink = Some(Arc::new(IdleUplink));
            }
            if webrtc {
                environment
                    .registries
                    .outputs
                    .register(Arc::new(FakeOutputFactory(WEBRTC)))
                    .unwrap();
            }
            let s = Supervisor::new(
                settings(PathBuf::from("/nonexistent/lotse.sock")),
                environment,
                Arc::new(SystemClock),
            );
            let expected: &[&str] = if announced {
                &["session_adopt", "two_way_audio"]
            } else {
                &["session_adopt"]
            };
            let what = format!("backchannel {backchannel}, uplink {uplink}, webrtc {webrtc}");
            assert_eq!(s.hello().features, expected, "{what}");
            let info = result(call(&s, r#"{"id":1,"type":"info"}"#).await);
            assert_eq!(info["features"], json!(expected), "{what}");
        }
        assert!(
            IdleUplink
                .transcoder(Duration::from_millis(20))
                .derive(&lotse_core::codec::Codec::Pcmu, CodecFamily::Pcmu)
                .is_none()
        );
    }

    /// `backchannel/release` frees the camera's
    /// backchannel through the stream's connection, unconditionally or for
    /// one session, says who held it, and is refused for an unknown stream
    /// and a protocol without one.
    #[tokio::test]
    async fn backchannel_release_reaches_the_connection_and_says_who_held_it() {
        let dir = private_dir("release");
        let door = FrontDoor {
            registrations: Arc::new(Registrations::default()),
            hosts: vec!["192.0.2.1:18556".parse().unwrap()],
            tcp_hosts: Vec::new(),
            stun: None,
            turn: None,
            demux: None,
        };
        let mut environment = webrtc_environment(&blocking_worker(&dir), door);
        environment
            .registries
            .sources
            .register(Arc::new(FakeSourceFactory::with_backchannel(&["talk"])))
            .unwrap();
        let s = Supervisor::new(session_settings(), environment, Arc::new(SystemClock));
        let release = |id: u64, stream_id: &str| json!({ "id": id, "type": "backchannel/release", "stream_id": stream_id });
        let err = error(call_on(&s, 1, &release(1, "ghost")).await);
        assert_eq!(
            (err.code, &err.details["stream_id"]),
            (ErrorCode::StreamNotFound, &json!("ghost"))
        );
        result(call(&s, &put("plain", "fake://127.0.0.1:1/", false)).await);
        let err = error(call_on(&s, 1, &release(2, "plain")).await);
        assert_eq!(
            (err.code, &err.details["stream_id"]),
            (ErrorCode::BackchannelUnsupported, &json!("plain"))
        );

        result(call(&s, &put("front", "talk://127.0.0.1:1/", false)).await);
        let connection = s.shared.lock().streams["front"].sources[0]
            .connection
            .clone();
        let _s1 = subscription(call_on(&s, 1, &offer(3, "front", Some("s1"))).await);
        let (commands, mut sent) = mpsc::channel(1);
        s.shared
            .lock()
            .connections
            .get_mut(&connection)
            .unwrap()
            .commands = commands;
        // Nobody holds it: still passed on, since a claim may be on its way.
        assert_eq!(
            result(call_on(&s, 1, &release(4, "front")).await),
            json!({ "talker": null })
        );
        assert!(matches!(
            sent.try_recv(),
            Ok(DriverCommand::ReleaseBackchannel { session_id: None })
        ));
        let at = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        assert!(
            s.shared
                .lock()
                .talker_changed(
                    &connection,
                    "s1",
                    lotse_api_types::stream::TalkerReason::Claimed,
                    at
                )
                .is_some()
        );
        assert_eq!(
            result(call_on(&s, 1, &release(5, "front")).await),
            json!({ "talker": "s1" })
        );
        // A full queue is refused like any other command's.
        let err = error(call_on(&s, 1, &release(6, "front")).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("connection_queue"))
        );
        assert!(matches!(
            sent.try_recv(),
            Ok(DriverCommand::ReleaseBackchannel { session_id: None })
        ));
        // A release for one session takes it to the worker, which decides
        // against its claims; the result names the talker as last heard,
        // whichever session the release names.
        let mut conditional = release(7, "front");
        conditional["session_id"] = json!("s2");
        assert_eq!(
            result(call_on(&s, 1, &conditional).await),
            json!({ "talker": "s1" })
        );
        assert!(matches!(
            sent.try_recv(),
            Ok(DriverCommand::ReleaseBackchannel { session_id: Some(session) }) if session == "s2"
        ));
        s.shutdown().await;
    }

    #[tokio::test]
    async fn stream_put_validates_and_enforces_the_limit() {
        let s = supervisor("/bin/sh", Arc::new(SystemClock));
        let err = error(call(&s, &put("bad id!", "fake://cam/", false)).await);
        assert_eq!(err.code, ErrorCode::InvalidStreamId);
        assert_eq!(err.details["stream_id"], "bad id!");
        let err = error(
            call(
                &s,
                r#"{"id":1,"type":"stream/put","stream_id":"a","sources":[]}"#,
            )
            .await,
        );
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        let err = error(call(&s, &put("a", "rtsp://cam/", false)).await);
        assert_eq!(err.code, ErrorCode::SchemeUnsupported);
        assert_eq!(err.details["scheme"], "rtsp");
        let err = error(call(&s, &put("a", "not a url", false)).await);
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert!(err.message.contains("source url"), "{err}");
        let err = error(
            call(
                &s,
                &json!({ "id": 1, "type": "stream/put", "stream_id": "a",
                         "sources": [{ "url": "fake://cam/", "options": { "x": 1 } }] })
                .to_string(),
            )
            .await,
        );
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert!(
            err.message.contains("fake source takes no options"),
            "{err}"
        );
        assert_eq!(
            result(call(&s, &put("a", "fake://cam/", false)).await)["created"],
            true
        );
        assert_eq!(
            result(call(&s, &put("b", "fake://cam2/", false)).await)["created"],
            true
        );
        let err = error(call(&s, &put("c", "fake://cam3/", false)).await);
        assert_eq!(err.code, ErrorCode::LimitReached);
        let err = error(
            call(
                &s,
                r#"{"id":1,"type":"stream/subscribe","stream_id":"bad id!"}"#,
            )
            .await,
        );
        assert_eq!(err.code, ErrorCode::InvalidStreamId);
        let err = error(call(&s, r#"{"id":1,"type":"stream/get","stream_id":"zzz"}"#).await);
        assert_eq!(err.code, ErrorCode::StreamNotFound);
        assert_eq!(err.details["stream_id"], "zzz");
    }

    #[tokio::test]
    async fn stream_get_reports_a_source_url_redacted_to_its_origin() {
        let s = supervisor("/bin/sh", Arc::new(SystemClock));
        let url = "fake://admin:pw5b1c@cam:8/camkey7f3a/live?token=tok9d2e";
        result(call(&s, &put("front", url, false)).await);
        let front = result(call(&s, r#"{"id":1,"type":"stream/get","stream_id":"front"}"#).await);
        assert_eq!(front["sources"][0]["url"], "fake://****@cam:8/****?****");
        let list = result(call(&s, r#"{"id":1,"type":"stream/list"}"#).await);
        let listed = list.to_string();
        for secret in ["pw5b1c", "camkey7f3a", "tok9d2e"] {
            assert!(!listed.contains(secret), "{listed}");
        }
    }

    #[tokio::test]
    async fn a_source_url_belongs_to_one_stream_and_streams_are_listed_fetched_and_deleted() {
        let s = supervisor("/bin/sh", Arc::new(SystemClock));
        assert_eq!(
            result(call(&s, &put("front", "fake://cam/", false)).await)["created"],
            true
        );
        assert_eq!(
            result(call(&s, &put("front", "fake://cam/", false)).await)["created"],
            false
        );
        let front = result(call(&s, r#"{"id":1,"type":"stream/get","stream_id":"front"}"#).await);
        assert_eq!(front["state"], "idle");
        assert_eq!(front["preload"], false);
        assert_eq!(front["last_error"], Value::Null);
        assert_eq!(front["sources"][0]["url"], "fake://cam/");
        assert_eq!(front["sources"][0]["protocol"], "fake");
        assert_eq!(front["sources"][0]["connection"]["id"], "c1");
        assert_eq!(front["sources"][0]["connection"]["worker"], Value::Null);
        assert!(front["since"].as_str().unwrap().ends_with('Z'));
        // The same URL under another stream id is refused, credentials
        // aside, naming the stream it belongs to; nothing changes.
        let err = error(call(&s, &put("twin", "fake://cam/", false)).await);
        assert_eq!(err.code, ErrorCode::SourceInUse);
        assert_eq!(err.details["stream_id"], "front");
        assert_eq!(
            err.message,
            "fake://cam/ is already the source of stream front; use that stream id, or put front with the new source"
        );
        let err = error(call(&s, &put("twin", "fake://u:p@cam/", false)).await);
        assert_eq!(err.code, ErrorCode::SourceInUse);
        assert!(!s.shared.lock().streams.contains_key("twin"));
        assert_eq!(s.shared.lock().connections.len(), 1);
        // A different URL gets its own connection.
        result(call(&s, &put("twin", "fake://cam2/", false)).await);
        let list = result(call(&s, r#"{"id":1,"type":"stream/list"}"#).await);
        assert_eq!(
            list["streams"]["twin"]["sources"][0]["connection"]["id"],
            "c2"
        );
        // A stream that moves to another URL on the same port keeps its
        // connection, which switches to the new source in place.
        result(call(&s, &put("front", "fake://other/", false)).await);
        let front = result(call(&s, r#"{"id":1,"type":"stream/get","stream_id":"front"}"#).await);
        assert_eq!(front["sources"][0]["connection"]["id"], "c1");
        assert_eq!(front["sources"][0]["url"], "fake://other/");
        assert_eq!(s.shared.lock().connections.len(), 2);
        // On another port it needs a new worker: a new connection, and
        // the one it left is released.
        result(call(&s, &put("front", "fake://other:9/", false)).await);
        let front = result(call(&s, r#"{"id":1,"type":"stream/get","stream_id":"front"}"#).await);
        assert_eq!(front["sources"][0]["connection"]["id"], "c3");
        assert_eq!(s.shared.lock().connections.len(), 2);
        // Deleting releases a stream's connection.
        assert_eq!(
            result(call(&s, r#"{"id":1,"type":"stream/delete","stream_id":"front"}"#).await),
            json!({})
        );
        assert_eq!(
            result(call(&s, r#"{"id":1,"type":"stream/delete","stream_id":"front"}"#).await),
            json!({}),
            "idempotent"
        );
        assert_eq!(s.shared.lock().connections.len(), 1);
        // The URL front left is free again.
        result(call(&s, &put("third", "fake://cam/", false)).await);
        assert_eq!(s.shared.lock().connections.len(), 2);
        result(call(&s, r#"{"id":1,"type":"stream/delete","stream_id":"third"}"#).await);
        let metrics = result(call(&s, r#"{"id":2,"type":"metrics/get"}"#).await);
        assert_eq!(metrics["streams"]["twin"]["frames_dropped"], 0);
        assert_eq!(metrics["streams"]["twin"]["av_sync_lost"], 0);
        // The counters come from the connection's worker's latest.
        s.shared
            .lock()
            .connections
            .get_mut("c2")
            .unwrap()
            .snapshot
            .stats = Some(lotse_ipc::WorkerStats {
            av_sync_lost: 1,
            ..lotse_ipc::WorkerStats::default()
        });
        let metrics = result(call(&s, r#"{"id":2,"type":"metrics/get"}"#).await);
        assert_eq!(metrics["streams"]["twin"]["av_sync_lost"], 1);
        assert!(metrics["streams"].get("front").is_none());
        result(call(&s, r#"{"id":1,"type":"stream/delete","stream_id":"twin"}"#).await);
        assert!(s.shared.lock().connections.is_empty());
        s.shutdown().await;
    }

    #[tokio::test]
    async fn metrics_report_each_worker_with_its_memory_read_through_its_probe() {
        use std::io::Write as _;

        let clock = Arc::new(FakeClock::from_system());
        let s = supervisor("/bin/sh", clock.clone());
        result(call(&s, &put("front", "fake://cam/", false)).await);
        // The driver publishes its idle snapshot first; then the worker
        // its `Ready` would have described, with a file for its rollup.
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        let path = private_dir("rollup").join("smaps_rollup");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"Rss: 8 kB\nPss: 4 kB\n")
            .unwrap();
        let probe = MemoryProbe::from_fd(std::fs::File::open(&path).unwrap().into());
        {
            let mut state = s.shared.lock();
            let snapshot = &mut state.connections.get_mut("c1").unwrap().snapshot;
            snapshot.worker = Some(crate::registry::WorkerProcess {
                pid: 4711,
                started: clock.now(),
                memory: Some(probe),
            });
            snapshot.crashes = 2;
            snapshot.stats = Some(lotse_ipc::WorkerStats {
                sessions: 3,
                send_failures: 4,
                relay_unbound: 5,
                tasks: 6,
                ..lotse_ipc::WorkerStats::default()
            });
            drop(state);
        }
        clock.advance(Duration::from_millis(1500));
        let metrics = result(call(&s, r#"{"id":2,"type":"metrics/get"}"#).await);
        assert_eq!(
            metrics["workers"],
            json!({ "c1": { "pid": 4711, "uptime_ms": 1500, "rss_bytes": 8192, "pss_bytes": 4096,
                            "tasks": 6, "streams": ["front"], "restarts": 2, "sessions": 3,
                            "send_failures": 4, "relay_unbound": 5 } })
        );
        let supervisor = &metrics["supervisor"];
        assert_eq!(supervisor["uptime_ms"], 1500);
        assert_eq!(supervisor["demux"], Value::Null, "no front door");
        assert!(supervisor["tasks"].as_u64().unwrap() >= 1, "the driver");
        assert_eq!(
            supervisor["pss_bytes"].as_u64().is_some(),
            cfg!(target_os = "linux")
        );
        assert_eq!(metrics["sessions"], 0);
        let front = result(call(&s, r#"{"id":3,"type":"stream/get","stream_id":"front"}"#).await);
        assert_eq!(
            front["sources"][0]["connection"]["worker"]["pss_bytes"],
            4096
        );
        // A worker without a probe has unknown memory.
        s.shared
            .lock()
            .connections
            .get_mut("c1")
            .unwrap()
            .snapshot
            .worker
            .as_mut()
            .unwrap()
            .memory = None;
        let metrics = result(call(&s, r#"{"id":4,"type":"metrics/get"}"#).await);
        assert_eq!(metrics["workers"]["c1"]["pss_bytes"], Value::Null);
        s.shutdown().await;
    }

    #[tokio::test]
    async fn subscribers_get_the_current_state_then_every_change() {
        let s = supervisor("/bin/sh", Arc::new(SystemClock));
        result(call(&s, &put("a", "fake://a/", false)).await);
        let mut all = subscription(call(&s, r#"{"id":1,"type":"stream/subscribe"}"#).await);
        let first = next(&mut all).await;
        assert_eq!(first["type"], "stream");
        assert_eq!(
            (first["stream_id"].as_str(), first["state"].as_str()),
            (Some("a"), Some("idle"))
        );
        result(call(&s, &put("b", "fake://b/", false)).await);
        assert_eq!(next(&mut all).await["stream_id"], "b");
        let mut only_b =
            subscription(call(&s, r#"{"id":2,"type":"stream/subscribe","stream_id":"b"}"#).await);
        assert_eq!(next(&mut only_b).await["stream_id"], "b");
        result(call(&s, r#"{"id":3,"type":"stream/delete","stream_id":"a"}"#).await);
        let removed = next(&mut all).await;
        assert_eq!(
            (removed["type"].as_str(), removed["stream_id"].as_str()),
            (Some("stream_removed"), Some("a"))
        );
        assert!(only_b.try_recv().is_err(), "filtered out");
        // The control connection closes: its subscriptions end.
        s.connection_closed(ConnectionId(1));
        result(call(&s, &put("c", "fake://c/", false)).await);
        assert_eq!(all.recv().await, None);
        assert_eq!(only_b.recv().await, None);
    }

    #[tokio::test]
    async fn demand_starts_a_worker_and_a_crash_restarts_it_with_backoff() {
        let clock = Arc::new(FakeClock::from_system());
        let s = supervisor("/bin/sh", clock.clone());
        let mut events = subscription(call(&s, r#"{"id":1,"type":"stream/subscribe"}"#).await);
        result(call(&s, &put("front", "fake://127.0.0.1:1/", true)).await);
        // `/bin/sh worker ...` exits at once: the machine sees a crash.
        for expected in ["idle", "connecting", "restarting"] {
            let event = next(&mut events).await;
            assert_eq!(event["state"], expected, "{event}");
        }
        let front = result(call(&s, r#"{"id":1,"type":"stream/get","stream_id":"front"}"#).await);
        assert_eq!(front["state"], "restarting");
        assert_eq!(front["last_error"]["code"], "worker_crashed");
        assert_eq!(front["sources"][0]["connection"]["worker"], Value::Null);
        // The crash backoff runs on the injected clock: 0.5 s, then a new worker.
        clock.advance(Duration::from_millis(499));
        assert!(events.try_recv().is_err());
        clock.advance(Duration::from_millis(1));
        for expected in ["connecting", "restarting"] {
            let event = next(&mut events).await;
            assert_eq!(event["state"], expected, "{event}");
        }
        let metrics = result(call(&s, r#"{"id":2,"type":"metrics/get"}"#).await);
        assert_eq!(metrics["worker_restarts"], 2);
        // Losing demand cancels the backoff; deleting releases the driver.
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        assert_eq!(next(&mut events).await["state"], "idle");
        result(call(&s, r#"{"id":3,"type":"stream/delete","stream_id":"front"}"#).await);
        assert_eq!(next(&mut events).await["type"], "stream_removed");
        s.shutdown().await;
    }

    /// The pid of `front`'s worker. `connecting` is published before the
    /// lookup completes; the worker follows a few polls later.
    async fn worker_pid(s: &Supervisor) -> u64 {
        let mut pid = None;
        let mut polls = 0;
        while pid.is_none() && polls < 10_000 {
            tokio::task::yield_now().await;
            polls += 1;
            let front =
                result(call(s, r#"{"id":1,"type":"stream/get","stream_id":"front"}"#).await);
            pid = front["sources"][0]["connection"]["worker"]["pid"].as_u64();
        }
        pid.expect("no worker pid")
    }

    #[tokio::test]
    async fn a_put_that_only_changes_preload_keeps_the_connection_and_its_worker() {
        let dir = private_dir("preload-toggle");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        let mut events = subscription(call(&s, r#"{"id":1,"type":"stream/subscribe"}"#).await);
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        assert_eq!(next(&mut events).await["state"], "idle");
        let _s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(next(&mut events).await["state"], "connecting");
        let pid = worker_pid(&s).await;
        let demand = |s: &Supervisor| s.shared.lock().connections["c1"].demand.borrow().total();
        assert_eq!(demand(&s), 1, "the viewer");
        // Preload on, then off again, with the same sources: the demand
        // follows, the stream reports the flag, and nothing restarts.
        for (preload, expected) in [(true, 2), (false, 1)] {
            let put = result(call(&s, &put("front", "fake://127.0.0.1:1/", preload)).await);
            assert_eq!(put["created"], false);
            assert_eq!(demand(&s), expected);
            let front =
                result(call(&s, r#"{"id":3,"type":"stream/get","stream_id":"front"}"#).await);
            assert_eq!(front["preload"], preload);
            assert_eq!(front["state"], "connecting");
            assert_eq!(front["sources"][0]["connection"]["id"], "c1");
            assert_eq!(front["sessions"], json!(["s1"]));
            assert_eq!(worker_pid(&s).await, pid, "the same worker");
        }
        assert!(events.try_recv().is_err(), "no state change: {events:?}");
        assert_eq!(s.shared.lock().connections.len(), 1);
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A worker that records what the supervisor sends it in
    /// `received.<pid>` under `dir`, and never reports.
    fn recording_worker(dir: &std::path::Path) -> String {
        let path = dir.join("worker.sh");
        std::fs::write(
            &path,
            format!("#!/bin/sh\nexec cat > {}/received.$$\n", dir.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Waits until worker `pid` under `dir` received `needle`; five
    /// seconds without it fail the test.
    async fn wait_received(dir: &std::path::Path, pid: u64, needle: &[u8]) {
        wait_received_any(dir, pid, &[needle.to_vec()]).await;
    }

    /// Waits until worker `pid` under `dir` received one of `needles`; five
    /// seconds without any fail the test.
    async fn wait_received_any(dir: &std::path::Path, pid: u64, needles: &[Vec<u8>]) {
        let file = dir.join(format!("received.{pid}"));
        for attempt in 0_u32.. {
            let received = std::fs::read(&file).unwrap_or_default();
            if needles.iter().any(|needle| {
                received
                    .windows(needle.len())
                    .any(|w| w == needle.as_slice())
            }) {
                return;
            }
            assert!(
                attempt < 500,
                "worker {pid} never received any of {needles:?}"
            );
            SystemClock.sleep(Duration::from_millis(10)).await;
        }
    }

    /// `stream/put` of `front` on one fake source with `options`, which
    /// `null` leaves out, preloaded.
    fn put_options(options: &Value) -> String {
        let mut source = json!({ "url": "fake://127.0.0.1:1/" });
        if !options.is_null() {
            source["options"] = options.clone();
        }
        json!({ "id": 1, "type": "stream/put", "stream_id": "front",
                "sources": [source], "preload": true })
        .to_string()
    }

    /// `front`'s first source's connection id.
    async fn front_connection(s: &Supervisor) -> Value {
        let front = result(call(s, r#"{"id":1,"type":"stream/get","stream_id":"front"}"#).await);
        front["sources"][0]["connection"]["id"].clone()
    }

    #[tokio::test]
    async fn a_put_that_changes_the_source_on_the_same_port_switches_the_worker_in_place() {
        let dir = private_dir("options-change");
        let s = with_webrtc(&recording_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put_options(&json!({}))).await);
        let mut s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(next(&mut s1).await["type"], "session");
        let first = worker_pid(&s).await;
        assert_eq!(front_connection(&s).await, "c1");
        // Same URL, other options: the connection keeps its worker and its
        // session, and the worker is told to switch.
        let put = result(call(&s, &put_options(&json!({ "ready_after_ms": 1000 }))).await);
        assert_eq!(put["created"], false);
        assert_eq!(front_connection(&s).await, "c1");
        assert_eq!(worker_pid(&s).await, first, "the same worker");
        assert!(
            s.shared.lock().sessions.contains_key("s1"),
            "the session stays"
        );
        wait_received(&dir, first, br#"{"ready_after_ms":1000}"#).await;
        assert_eq!(s.shared.lock().connections.len(), 1);
        // The connection is keyed by the new source now: the same put is
        // unchanged.
        let put = result(call(&s, &put_options(&json!({ "ready_after_ms": 1000 }))).await);
        assert_eq!(put["created"], false);
        assert_eq!(worker_pid(&s).await, first);
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// ONVIF Streaming Specification §5.3.1: a stream that opts in to the
    /// camera's backchannel, or out of it, keeps its connection, worker
    /// and session; the worker is only told to turn its probe on or off.
    #[tokio::test]
    async fn opting_in_or_out_of_the_backchannel_only_tells_the_shared_connection_s_worker_onvif_5_3_1()
     {
        let dir = private_dir("backchannel-opt-in");
        let s = with_webrtc(&recording_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put_options(&json!({}))).await);
        let mut s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(next(&mut s1).await["type"], "session");
        let first = worker_pid(&s).await;
        wait_received(&dir, first, b"fake://127.0.0.1:1/").await;
        let asks = |s: &Supervisor| s.shared.lock().connections["c1"].backchannel;
        assert!(!asks(&s), "opt-in");
        // The message as the worker reads it: its length, then its body.
        let told = |asks: bool| {
            let body = lotse_ipc::encode(&lotse_ipc::ToWorker::Backchannel { asks }).unwrap();
            let mut framed = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
            framed.extend_from_slice(&body);
            framed
        };
        let put = result(call(&s, &put_options(&json!({ "talk": true }))).await);
        assert_eq!(put["created"], false);
        assert_eq!(front_connection(&s).await, "c1");
        assert_eq!(s.shared.lock().connections.len(), 1, "no second session");
        assert!(asks(&s));
        wait_received(&dir, first, &told(true)).await;
        assert_eq!(worker_pid(&s).await, first, "the same worker");
        assert!(s.shared.lock().sessions.contains_key("s1"));
        assert_eq!(
            s.shared.lock().streams["front"].sources[0].options["talk"],
            true,
            "the stream keeps its options as given"
        );
        result(call(&s, &put_options(&json!({}))).await);
        assert!(!asks(&s));
        wait_received(&dir, first, &told(false)).await;
        assert_eq!(worker_pid(&s).await, first);
        assert!(s.shared.lock().sessions.contains_key("s1"));
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// ONVIF Streaming Specification §5.3.1: a put that switches the
    /// source in place (another connection option) and opts in to the
    /// backchannel, or out of it, tells the worker both: the switch, and
    /// the ask, so its running source probes, or frees the talker the
    /// switch would keep, without a restart.
    #[tokio::test]
    async fn a_put_that_switches_the_source_and_opts_in_or_out_tells_the_worker_both_onvif_5_3_1() {
        let dir = private_dir("backchannel-switch");
        let s = with_webrtc(&recording_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put_options(&json!({}))).await);
        let mut s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(next(&mut s1).await["type"], "session");
        let first = worker_pid(&s).await;
        wait_received(&dir, first, b"fake://127.0.0.1:1/").await;
        let asks = |s: &Supervisor| s.shared.lock().connections["c1"].backchannel;
        let told =
            |asks: bool| lotse_ipc::encode(&lotse_ipc::ToWorker::Backchannel { asks }).unwrap();
        for (options, ask) in [
            (json!({ "talk": true, "ready_after_ms": 1000 }), true),
            (json!({ "ready_after_ms": 2000 }), false),
        ] {
            let put = result(call(&s, &put_options(&options)).await);
            assert_eq!(put["created"], false);
            assert_eq!(front_connection(&s).await, "c1");
            assert_eq!(asks(&s), ask);
            wait_received(&dir, first, &told(ask)).await;
            let switched = format!(r#""ready_after_ms":{}"#, options["ready_after_ms"]);
            wait_received(&dir, first, switched.as_bytes()).await;
            assert_eq!(worker_pid(&s).await, first, "the same worker");
            assert!(s.shared.lock().sessions.contains_key("s1"));
        }
        assert_eq!(s.shared.lock().connections.len(), 1);
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn relay_candidates_and_channels_reach_the_worker_process() {
        let dir = private_dir("relay-ipc");
        let s = with_webrtc(&recording_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(next(&mut s1).await["type"], "session");
        let pid = worker_pid(&s).await;
        let (relayed, server, local, peer): (SocketAddr, SocketAddr, SocketAddr, SocketAddr) = (
            "203.0.113.1:49153".parse().unwrap(),
            "192.0.2.3:3478".parse().unwrap(),
            "192.0.2.1:18556".parse().unwrap(),
            "192.0.2.9:5000".parse().unwrap(),
        );
        let commands = s.shared.lock().connections["c1"].commands.clone();
        commands
            .try_send(DriverCommand::RelayCandidate {
                session_id: "s1".into(),
                relayed,
                server,
                local,
                tcp: true,
                grant: crate::net::turn_client::Lease::detached(relayed).grant(),
            })
            .unwrap();
        commands
            .try_send(DriverCommand::RelayChannel {
                session_id: "s1".into(),
                relayed,
                peer,
                channel: 0x4000,
            })
            .unwrap();
        let candidate = lotse_ipc::ToWorker::RelayCandidate {
            session_id: "s1".into(),
            relayed,
            server,
            local,
            tcp: true,
        };
        wait_received(&dir, pid, &lotse_ipc::encode(&candidate).unwrap()).await;
        let channel = lotse_ipc::ToWorker::RelayChannel {
            session_id: "s1".into(),
            relayed,
            peer,
            channel: 0x4000,
        };
        wait_received(&dir, pid, &lotse_ipc::encode(&channel).unwrap()).await;
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_orientation_change_reaches_the_worker_process() {
        let dir = private_dir("turn-ipc");
        let s = with_webrtc(&recording_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(next(&mut s1).await["type"], "session");
        let pid = worker_pid(&s).await;
        let turn = json!({ "id": 3, "type": "stream/put", "stream_id": "front",
            "sources": [{ "url": "fake://127.0.0.1:1/" }], "orientation": "rotate_right" });
        result(call(&s, &turn.to_string()).await);
        let message = lotse_ipc::ToWorker::SessionOrientation {
            session_id: "s1".into(),
            orientation: 8,
        };
        wait_received(&dir, pid, &lotse_ipc::encode(&message).unwrap()).await;
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_put_with_options_equal_after_normalization_keeps_the_connection() {
        let dir = private_dir("options-same");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put_options(&json!({}))).await);
        let mut s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(next(&mut s1).await["type"], "session");
        let pid = worker_pid(&s).await;
        // Left out, empty or the default spelled out: one camera session.
        for same in [json!({ "ready_after_ms": 0 }), Value::Null, json!({})] {
            let put = result(call(&s, &put_options(&same)).await);
            assert_eq!(put["created"], false);
            assert_eq!(front_connection(&s).await, "c1", "{same}");
            assert_eq!(worker_pid(&s).await, pid, "the same worker for {same}");
        }
        assert!(s1.try_recv().is_err(), "the session stays: {s1:?}");
        assert_eq!(s.shared.lock().connections.len(), 1);
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_running_worker_is_stopped_when_demand_goes_and_at_shutdown() {
        let dir = private_dir("stop");
        let s = supervisor(&blocking_worker(&dir), Arc::new(SystemClock));
        let mut events = subscription(call(&s, r#"{"id":1,"type":"stream/subscribe"}"#).await);
        result(call(&s, &put("front", "fake://127.0.0.1:1/", true)).await);
        for expected in ["idle", "connecting"] {
            assert_eq!(next(&mut events).await["state"], expected);
        }
        assert!(worker_pid(&s).await > 0);
        // Demand goes while connecting: the worker is stopped at once.
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        assert_eq!(next(&mut events).await["state"], "idle");
        // Demand returns: a new worker; shutdown kills it within the budget.
        result(call(&s, &put("front", "fake://127.0.0.1:1/", true)).await);
        assert_eq!(next(&mut events).await["state"], "connecting");
        s.shutdown().await;
        assert!(s.shared.lock().connections.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn webrtc_offer_validates_opens_sessions_and_holds_the_limits() {
        let dir = private_dir("offer");
        let bare = supervisor(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&bare, &put("front", "fake://127.0.0.1:1/", false)).await);
        let err = error(call_on(&bare, 1, &offer(2, "front", None)).await);
        assert_eq!(
            err.code,
            ErrorCode::InvalidRequest,
            "no webrtc output: {err}"
        );

        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        result(call(&s, &put("back", "fake://127.0.0.1:2/", false)).await);
        let err = error(call_on(&s, 1, &offer(2, "bad id!", None)).await);
        assert_eq!(err.code, ErrorCode::InvalidStreamId);
        let err = error(call_on(&s, 1, &offer(2, "nope", None)).await);
        assert_eq!(err.code, ErrorCode::StreamNotFound);
        let err = error(call_on(&s, 1, &offer(2, "front", Some("bad id!"))).await);
        assert_eq!(
            (err.code, &err.details["session_id"]),
            (ErrorCode::InvalidRequest, &json!("bad id!"))
        );
        let mut bad_ice = offer(2, "front", Some("s1"));
        bad_ice["ice_servers"] = json!([{ "urls": ["stun:ok", "http://x/"] }]);
        let err = error(call_on(&s, 1, &bad_ice).await);
        assert_eq!(
            (err.code, &err.details["url"]),
            (ErrorCode::InvalidRequest, &json!("http://x/"))
        );
        assert!(
            s.shared.lock().sessions.is_empty(),
            "nothing opened on an error"
        );

        // RFC 7065 turns: is not supported yet: a warning after `session`.
        let mut with_ice = offer(2, "front", Some("s1"));
        with_ice["ice_servers"] = json!([{ "urls": ["stun:stun.example:3478", "TURN:t", "turns:t:5349"],
                                            "username": "u", "credential": "c" }]);
        let mut s1 = subscription(call_on(&s, 1, &with_ice).await);
        assert_eq!(
            next(&mut s1).await,
            json!({ "type": "session", "session_id": "s1" })
        );
        let warning = next(&mut s1).await;
        assert_eq!(
            (&warning["type"], &warning["code"]),
            (&json!("warning"), &json!("turn_unsupported"))
        );
        assert!(
            warning["message"]
                .as_str()
                .unwrap()
                .contains("turns:t:5349")
        );
        let err = error(call_on(&s, 1, &offer(3, "front", Some("s1"))).await);
        assert_eq!(err.code, ErrorCode::SessionIdInUse);
        // Without an id, a ULID.
        let mut generated = subscription(call_on(&s, 1, &offer(4, "front", None)).await);
        let session = next(&mut generated).await;
        let id = session["session_id"].as_str().unwrap().to_owned();
        assert_eq!(id.len(), 26);

        // The sessions are demand on the connection; both are listed.
        assert_eq!(s.shared.lock().connections["c1"].demand.borrow().total(), 2);
        let front = result(call(&s, r#"{"id":5,"type":"stream/get","stream_id":"front"}"#).await);
        let mut listed: Vec<Value> = front["sessions"].as_array().unwrap().clone();
        listed.sort_by_key(|v| v.as_str().unwrap().to_owned());
        let mut expected = vec![json!("s1"), json!(id)];
        expected.sort_by_key(|v| v.as_str().unwrap().to_owned());
        assert_eq!(listed, expected);
        let got = result(call(&s, r#"{"id":6,"type":"session/get","session_id":"s1"}"#).await);
        assert_eq!(
            (
                &got["stream_id"],
                &got["ice"],
                &got["answered"],
                &got["orphaned"]
            ),
            (&json!("front"), &json!("new"), &json!(false), &json!(false))
        );
        let err = error(call(&s, r#"{"id":7,"type":"session/get","session_id":"ghost"}"#).await);
        assert_eq!(err.code, ErrorCode::SessionNotFound);
        let list = result(call(&s, r#"{"id":8,"type":"session/list"}"#).await);
        assert_eq!(list["sessions"].as_array().unwrap().len(), 2);
        // The offer went to the driver with the credentials and the hosts.
        assert_eq!(s.shared.lock().sessions["s1"].ufrag.len(), 8);

        // Two per stream, three in all.
        let err = error(call_on(&s, 1, &offer(9, "front", Some("s3"))).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("max_sessions_per_stream"))
        );
        let _b1 = subscription(call_on(&s, 1, &offer(10, "back", Some("b1"))).await);
        let err = error(call_on(&s, 1, &offer(11, "back", Some("b2"))).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("max_sessions"))
        );
        s.shutdown().await;
        bare.shutdown().await;
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one session's signaling, start to end"
    )]
    async fn candidates_are_bounded_before_the_answer_and_reports_reach_the_owner() {
        let dir = private_dir("candidates");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        next(&mut events).await;
        let candidate = |id: u64, session: &str| {
            json!({ "id": id, "type": "webrtc/candidate", "session_id": session,
                    "candidate": "candidate:1 1 udp 1 192.0.2.9 5000 typ host" })
        };
        let err = error(call_on(&s, 1, &candidate(3, "ghost")).await);
        assert_eq!(err.code, ErrorCode::SessionNotFound);
        for n in 0..MAX_EARLY_CANDIDATES {
            result(call_on(&s, 1, &candidate(10 + u64::from(n), "s1")).await);
        }
        let err = error(call_on(&s, 1, &candidate(100, "s1")).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("early_candidates"))
        );

        // A worker speaks only for its own connection's sessions.
        let now = s.shared.clock.now();
        s.shared.lock().session_report(
            "c99",
            "s1",
            Report::Answer {
                sdp: "forged".into(),
                talkback: None,
            },
            now,
        );
        s.shared.lock().session_report(
            "c1",
            "ghost",
            Report::Answer {
                sdp: "x".into(),
                talkback: None,
            },
            now,
        );
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0\r\ns=answer\r\n".into(),
                talkback: None,
            },
        );
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "answer", "sdp": "v=0\r\ns=answer\r\n" })
        );
        // After the answer, candidates count up to the total cap.
        for n in MAX_EARLY_CANDIDATES..MAX_REMOTE_CANDIDATES {
            result(call_on(&s, 1, &candidate(101 + u64::from(n), "s1")).await);
        }
        let err = error(call_on(&s, 1, &candidate(200, "s1")).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("remote_candidates"))
        );
        report(
            &s,
            "s1",
            Report::Candidate {
                candidate: "candidate:1 1 udp 1 192.0.2.1 18556 typ host".into(),
                mid: Some("0".into()),
            },
        );
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "candidate", "candidate": "candidate:1 1 udp 1 192.0.2.1 18556 typ host",
                    "sdp_mid": "0" })
        );
        report(
            &s,
            "s1",
            Report::Warning {
                code: "not_a_code".into(),
                message: "m".into(),
            },
        );
        report(
            &s,
            "s1",
            Report::Warning {
                code: "h264_profile_mismatch".into(),
                message: "m".into(),
            },
        );
        assert_eq!(
            next(&mut events).await["code"],
            "h264_profile_mismatch",
            "the unknown warning was dropped"
        );
        report(
            &s,
            "s1",
            Report::State {
                ice: "connected".into(),
                dtls: "connected".into(),
            },
        );
        let state = events.recv().await.unwrap();
        assert_eq!(state.class, lotse_api::EventClass::Diagnostic);
        assert_eq!(
            state.payload,
            json!({ "type": "state", "ice": "connected", "dtls": "connected" })
        );
        let got = result(call(&s, r#"{"id":102,"type":"session/get","session_id":"s1"}"#).await);
        assert_eq!(
            (&got["ice"], &got["answered"]),
            (&json!("connected"), &json!(true))
        );
        // The worker's `closed` ends the subscription and the session.
        report(
            &s,
            "s1",
            Report::Closed {
                code: "peer_closed".into(),
                message: "bye".into(),
            },
        );
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "closed", "code": "peer_closed", "message": "bye" })
        );
        assert!(events.recv().await.is_none());
        assert!(s.shared.lock().sessions.is_empty());
        let front = result(call(&s, r#"{"id":103,"type":"stream/get","stream_id":"front"}"#).await);
        assert_eq!(front["sessions"], json!([]));
        s.shutdown().await;
    }

    fn renegotiate(id: u64, session_id: &str) -> Value {
        json!({ "id": id, "type": "webrtc/renegotiate", "session_id": session_id, "sdp": "v=0\r\n" })
    }

    /// Yields until the session `session_id` of `s` has a re-offer
    /// waiting for its worker, which the worker then answers.
    async fn until_waiting(s: &Supervisor, session_id: &str) {
        let mut yields = 0;
        while !s.shared.lock().sessions[session_id].renegotiating() {
            assert!(yields < 10_000, "no re-offer waiting");
            yields += 1;
            tokio::task::yield_now().await;
        }
    }

    /// `webrtc/renegotiate` is for the session's owner, after the answer:
    /// the worker's answer is its result, a refusal its error, and a
    /// session that closes meanwhile, or a worker that never answers, end
    /// the wait too.
    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "every end of a re-offer")]
    async fn a_re_offer_is_answered_by_the_worker_or_refused() {
        let dir = private_dir("renegotiate");
        let clock = Arc::new(FakeClock::default());
        let s = Arc::new(with_webrtc(&blocking_worker(&dir), clock.clone()));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        next(&mut events).await;
        let err = error(call_on(&s, 1, &renegotiate(3, "ghost")).await);
        assert_eq!(err.code, ErrorCode::SessionNotFound);
        let err = error(call_on(&s, 2, &renegotiate(3, "s1")).await);
        assert_eq!(
            (err.code, err.message.as_str()),
            (
                ErrorCode::SessionNotFound,
                "the session is not this connection's"
            )
        );
        let err = error(within(call_on(&s, 1, &renegotiate(4, "s1"))).await);
        assert_eq!(
            (err.code, err.message.as_str()),
            (ErrorCode::InvalidRequest, "the session has no answer yet")
        );
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0\r\n".into(),
                talkback: None,
            },
        );
        next(&mut events).await;

        // The worker answers: the answer is the result, and `session/get`
        // reports the talk-back it negotiated.
        let waiting = {
            let s = Arc::clone(&s);
            spawn_named("test.renegotiate", async move {
                call_on(&s, 1, &renegotiate(5, "s1")).await
            })
        };
        until_waiting(&s, "s1").await;
        let err = error(within(call_on(&s, 1, &renegotiate(6, "s1"))).await);
        assert_eq!(err.code, ErrorCode::InvalidRequest, "one at a time");
        report(
            &s,
            "s1",
            Report::Renegotiated {
                sdp: "v=0\r\na=mid:0\r\n".into(),
                talkback: Some("pcmu".into()),
            },
        );
        assert_eq!(
            result(within(waiting).await.unwrap()),
            json!({ "sdp": "v=0\r\na=mid:0\r\n" })
        );
        let got = result(call(&s, r#"{"id":7,"type":"session/get","session_id":"s1"}"#).await);
        assert_eq!(got["backchannel"]["codec"], "pcmu");
        // The decline that follows reaches the subscription as a warning.
        report(
            &s,
            "s1",
            Report::TalkbackDeclined {
                reason: "busy".into(),
                status: None,
                message: "s2 holds it".into(),
            },
        );
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "warning", "code": "backchannel_declined", "message": "s2 holds it",
                    "reason": "busy" })
        );

        // The worker refuses: the error is the result.
        let waiting = {
            let s = Arc::clone(&s);
            spawn_named("test.renegotiate", async move {
                call_on(&s, 1, &renegotiate(8, "s1")).await
            })
        };
        until_waiting(&s, "s1").await;
        report(
            &s,
            "s1",
            Report::RenegotiateRefused {
                code: "no_video_track".into(),
                message: "no video".into(),
            },
        );
        let err = error(within(waiting).await.unwrap());
        assert_eq!(
            (err.code, err.message.as_str(), &err.details["session_id"]),
            (ErrorCode::NoVideoTrack, "no video", &json!("s1"))
        );

        // A re-offer (A) loses its client: it is still out, so the retry
        // (B) is refused until the worker answers A, and A's late answer
        // goes nowhere; B gets its own.
        let a = renegotiate(14, "s1");
        tokio::select! {
            outcome = call_on(&s, 1, &a) => panic!("answered: {outcome:?}"),
            () = until_waiting(&s, "s1") => {}
        }
        let err = error(within(call_on(&s, 1, &renegotiate(15, "s1"))).await);
        assert_eq!(
            (err.code, err.message.as_str()),
            (
                ErrorCode::InvalidRequest,
                "a re-offer of the session is still being answered"
            )
        );
        report(
            &s,
            "s1",
            Report::RenegotiateRefused {
                code: "invalid_sdp".into(),
                message: "A".into(),
            },
        );
        let b = {
            let s = Arc::clone(&s);
            spawn_named("test.renegotiate", async move {
                call_on(&s, 1, &renegotiate(16, "s1")).await
            })
        };
        until_waiting(&s, "s1").await;
        report(
            &s,
            "s1",
            Report::Renegotiated {
                sdp: "v=0\r\na=mid:B\r\n".into(),
                talkback: None,
            },
        );
        assert_eq!(
            result(within(b).await.unwrap()),
            json!({ "sdp": "v=0\r\na=mid:B\r\n" }),
            "B gets its own answer"
        );

        // A second session, which keeps the connection and its worker
        // wanted once s1 is closed.
        let mut s2 = subscription(call_on(&s, 1, &offer(12, "front", Some("s2"))).await);
        next(&mut s2).await;
        report(
            &s,
            "s2",
            Report::Answer {
                sdp: "v=0\r\n".into(),
                talkback: None,
            },
        );
        next(&mut s2).await;

        // The session closes while the re-offer waits.
        let waiting = {
            let s = Arc::clone(&s);
            spawn_named("test.renegotiate", async move {
                call_on(&s, 1, &renegotiate(10, "s1")).await
            })
        };
        until_waiting(&s, "s1").await;
        result(
            call_on(
                &s,
                1,
                &json!({ "id": 11, "type": "session/close", "session_id": "s1" }),
            )
            .await,
        );
        let err = error(within(waiting).await.unwrap());
        assert_eq!(err.code, ErrorCode::SessionNotFound);

        // A full driver queue refuses the re-offer, and holds no slot.
        let (full, _rx) = mpsc::channel(1);
        full.try_send(DriverCommand::Candidate {
            session_id: "x".into(),
            candidate: String::new(),
        })
        .unwrap();
        let commands = std::mem::replace(
            &mut s.shared.lock().connections.get_mut("c1").unwrap().commands,
            full,
        );
        let err = error(within(call_on(&s, 1, &renegotiate(13, "s2"))).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("connection_queue"))
        );
        assert!(!s.shared.lock().sessions["s2"].renegotiating());
        s.shared.lock().connections.get_mut("c1").unwrap().commands = commands;

        // The worker never answers: the daemon's clock bounds the wait.
        // That re-offer (A) is still out: a retry is refused until the
        // worker answers A, whose late answer goes nowhere.
        //
        // The fake worker sends nothing at all, and the advance that ends
        // the wait passes its driver's `WORKER_SILENCE_LIMIT` too, which
        // counts from the worker's start, before any advance: once the
        // driver runs, it kills the worker and the exit closes the
        // session. So the steps up to the late answer are polled here,
        // each complete at once, and the driver runs only after them; the
        // close is the last thing the test waits for.
        worker_pid(&s).await;
        {
            let a = renegotiate(9, "s2");
            let mut waiting = std::pin::pin!(call_on(&s, 1, &a));
            assert!(poll_alone(waiting.as_mut()).is_pending());
            assert!(s.shared.lock().sessions["s2"].renegotiating());
            clock.advance(RENEGOTIATE_TIMEOUT);
            let_assert!(Poll::Ready(outcome) = poll_alone(waiting));
            let err = error(outcome);
            assert_eq!(
                (err.code, err.message.as_str()),
                (
                    ErrorCode::InternalError,
                    "the worker did not answer the re-offer"
                )
            );
        }
        assert!(s.shared.lock().sessions["s2"].renegotiating());
        let retry = renegotiate(17, "s2");
        let_assert!(Poll::Ready(outcome) = poll_alone(std::pin::pin!(call_on(&s, 1, &retry))));
        let err = error(outcome);
        assert_eq!(
            err.message, "a re-offer of the session is still being answered",
            "refused, not answered with A's answer"
        );
        report(
            &s,
            "s2",
            Report::Renegotiated {
                sdp: "v=0\r\na=mid:A\r\n".into(),
                talkback: None,
            },
        );
        assert!(!s.shared.lock().sessions["s2"].renegotiating());
        assert_eq!(
            next(&mut s2).await,
            json!({ "type": "closed", "code": "worker_crashed",
                    "message": "the camera's worker process exited" }),
            "the silent worker was killed"
        );
        Arc::try_unwrap(s).unwrap().shutdown().await;
    }

    /// Polls `future` once on this task alone: unlike an `.await` that
    /// yields, it lets no other task, no driver, act before the next step.
    /// The poll is free of the runtime's cooperative budget, so a step
    /// that can complete does.
    fn poll_alone(future: Pin<&mut impl Future<Output = Outcome>>) -> Poll<Outcome> {
        std::pin::pin!(tokio::task::unconstrained(future))
            .poll(&mut Context::from_waker(Waker::noop()))
    }

    /// A session timer's task that leaves the maps as they are.
    fn untouched(_: &mut State) {}

    #[tokio::test]
    async fn unsubscribe_and_session_close_end_sessions_idempotently() {
        let dir = private_dir("close");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let _s1 = subscription(call_on(&s, 1, &offer(5, "front", Some("s1"))).await);
        // A session keeps no timer of its own for its source; one it is
        // given (grace, the gather deadline) is the session's, and ends
        // with it rather than sleeping out its delay.
        assert!(s.shared.lock().sessions["s1"].timers().is_empty());
        let serial = s.shared.lock().sessions["s1"].serial;
        // One that fired is dropped as the next is kept.
        s.shared.after("s1", serial, Duration::ZERO, untouched);
        let fired = s.shared.lock().sessions["s1"].timers()[0].clone();
        for _ in 0..1000 {
            if fired.is_finished() {
                break;
            }
            SystemClock.sleep(Duration::from_millis(1)).await;
        }
        assert!(fired.is_finished());
        s.shared
            .after("s1", serial, Duration::from_secs(3600), untouched);
        let timers = s.shared.lock().sessions["s1"].timers().to_vec();
        assert_eq!(timers.len(), 1);
        let timer = timers[0].clone();
        assert!(!timer.is_finished());
        assert!(
            s.unsubscribed(ConnectionId(2), 5).is_none(),
            "another connection's id 5"
        );
        let last = s
            .unsubscribed(ConnectionId(1), 5)
            .expect("the closed event");
        assert_eq!(last.class, lotse_api::EventClass::Signaling);
        assert_eq!(
            last.payload,
            json!({ "type": "closed", "code": "session_closed", "message": "unsubscribed" })
        );
        assert!(s.unsubscribed(ConnectionId(1), 5).is_none());
        assert!(s.shared.lock().sessions.is_empty());
        for _ in 0..100 {
            if timer.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(timer.is_finished(), "aborted with its session");

        // session/close works across connections; the owner hears of it.
        let mut s2 = subscription(call_on(&s, 1, &offer(6, "front", Some("s2"))).await);
        next(&mut s2).await;
        result(
            call_on(
                &s,
                2,
                &json!({ "id": 1, "type": "session/close", "session_id": "s2" }),
            )
            .await,
        );
        assert_eq!(
            next(&mut s2).await,
            json!({ "type": "closed", "code": "session_closed", "message": "closed by session/close" })
        );
        assert!(s2.recv().await.is_none());
        result(
            call_on(
                &s,
                2,
                &json!({ "id": 2, "type": "session/close", "session_id": "s2" }),
            )
            .await,
        );
        s.shutdown().await;
    }

    /// `stream/put` with a signaled source: `{"protocol": ...}`.
    fn put_signaled(stream_id: &str, protocol: &str, options: &Value) -> String {
        json!({ "id": 1, "type": "stream/put", "stream_id": stream_id,
                "sources": [{ "protocol": protocol, "options": options }] })
        .to_string()
    }

    /// A signaled source is named by its protocol, a URL source by its
    /// URL, and each form is refused for the other, saying which it
    /// needs; an unknown protocol is `protocol_unsupported`.
    #[tokio::test]
    async fn a_signaled_source_is_named_by_protocol_and_a_url_source_by_url() {
        let s = supervisor("/bin/sh", Arc::new(SystemClock));
        // A URL whose scheme is a signaled protocol, as a client might
        // write one.
        let protocol = "fake-signaled";
        let url = format!("{protocol}://camera.front_door");
        let err = error(call(&s, &put("a", &url, false)).await);
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert_eq!(err.details["protocol"], "fake-signaled");
        assert_eq!(
            err.message,
            r#"a fake-signaled source has no url: the client relays its signaling, so name it by protocol, {"protocol": "fake-signaled"}"#
        );
        let err = error(call(&s, &put_signaled("a", "fake", &json!({}))).await);
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert_eq!(err.details["scheme"], "fake");
        assert_eq!(
            err.message,
            r#"a fake source is named by its url, {"url": "fake://…"}, not by protocol"#
        );
        let err = error(call(&s, &put_signaled("a", "webrtc", &json!({}))).await);
        assert_eq!(err.code, ErrorCode::ProtocolUnsupported);
        assert_eq!(err.details["protocol"], "webrtc");
        assert_eq!(err.message, r#"no signaled source speaks "webrtc""#);
        let err = error(
            call(
                &s,
                &put_signaled("a", "fake-signaled", &json!({ "audio": true })),
            )
            .await,
        );
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert!(
            err.message
                .contains("fake signaled source takes no options"),
            "{err}"
        );
        // Two streams each have their own: no source is another's.
        for stream in ["a", "b"] {
            let put = put_signaled(stream, "fake-signaled", &json!({}));
            assert_eq!(result(call(&s, &put).await)["created"], true);
            assert_eq!(result(call(&s, &put).await)["created"], false, "unchanged");
        }
        let a = result(call(&s, r#"{"id":1,"type":"stream/get","stream_id":"a"}"#).await);
        let reported = &a["sources"][0];
        assert_eq!(reported["protocol"], "fake-signaled");
        assert!(reported.get("url").is_none(), "no address: {reported}");
        let (a, b, key) = {
            let state = s.shared.lock();
            let a = state.streams["a"].sources[0].clone();
            let key = format!("{:?}", state.connections[&a.connection].key);
            (a, state.streams["b"].sources[0].clone(), key)
        };
        assert_ne!(a.connection, b.connection);
        assert_eq!(
            key,
            r#"ConnectionKey { target: fake-signaled of stream a, options: ["signaled"] }"#
        );
        assert_eq!(
            a.spec.target,
            lotse_ipc::SourceTarget::Signaled("fake-signaled".into())
        );
        assert_eq!((a.spec.host.as_str(), a.spec.port), ("", None));
        s.shutdown().await;
    }

    /// A signaled source has no port to pin its worker to, and a
    /// connection never switches to or from one in place: each is a new
    /// connection.
    #[tokio::test]
    async fn a_signaled_source_has_no_port_and_never_switches_in_place() {
        let dir = private_dir("signaled-switch");
        let s = Supervisor::new(
            settings(PathBuf::from("/nonexistent/lotse.sock")),
            environment(&blocking_worker(&dir)),
            Arc::new(SystemClock),
        );
        let captured = Captured::default();
        let _logs = captured.install();
        let source = |s: &Supervisor| {
            let state = s.shared.lock();
            let source = state.streams["front"].sources[0].clone();
            let port = state.connections[&source.connection].port;
            drop(state);
            (source.connection, source.spec, port)
        };
        let mut connections = Vec::new();
        for url in [
            "fake://127.0.0.1/",
            "fake-signaled",
            "fake://127.0.0.1/other",
            "fake://127.0.0.1/again",
        ] {
            let signaled = !url.contains("://");
            let put = if signaled {
                put_signaled("front", url, &json!({}))
            } else {
                put("front", url, false)
            };
            result(call(&s, &put).await);
            let (connection, spec, port) = source(&s);
            assert_eq!(spec.signaled(), signaled, "{url}");
            assert_eq!((spec.port, port), (None, None), "{url}");
            connections.push(connection);
        }
        // To the signaled source, away from it: new connections each; then
        // between two portless fakes, in place.
        assert_eq!(connections[1..], ["c2", "c3", "c3"], "{connections:?}");
        assert_eq!(
            captured
                .lines("the connection switches to the new source in place")
                .len(),
            1
        );
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A signal of the signaled source of `door`, its worker's offer
    /// handed to the registry.
    fn offered_signal(s: &Supervisor, request: u64) -> String {
        let mut state = s.shared.lock();
        let connection = state.streams["door"].sources[0].connection.clone();
        let from = crate::signaling::SignalFrom {
            connection: &connection,
            worker: 1,
        };
        let now = SystemClock.now();
        state.signal_report(
            &from,
            lotse_ipc::SignalReport::Open { request },
            now,
            std::time::UNIX_EPOCH,
        );
        let signal_id = state
            .signal_ids_for_tests()
            .into_iter()
            .last()
            .expect("a signal");
        state.signal_report(
            &from,
            lotse_ipc::SignalReport::Offer {
                signal_id: signal_id.clone(),
                sdp: lotse_core::test_util::FAKE_SIGNALED_OFFER.into(),
            },
            now,
            std::time::UNIX_EPOCH,
        );
        signal_id
    }

    #[tokio::test]
    async fn signaling_commands_reach_the_owner_s_signals_and_end_with_its_subscription() {
        let dir = private_dir("signaling-commands");
        let mut environment = environment(&blocking_worker(&dir));
        environment.front_door = Some(FrontDoor {
            registrations: Arc::new(Registrations::default()),
            // Two ports of one address: a source gathers on each address
            // once.
            hosts: vec![
                "192.0.2.1:18556".parse().unwrap(),
                "192.0.2.1:18557".parse().unwrap(),
                "[2001:db8::1]:18556".parse().unwrap(),
            ],
            tcp_hosts: vec![],
            stun: None,
            turn: None,
            demux: None,
        });
        let s = Supervisor::new(
            settings(PathBuf::from("/nonexistent/lotse.sock")),
            environment,
            Arc::new(SystemClock),
        );
        assert_eq!(
            s.shared.lock().signaling.local_addrs,
            [
                "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        result(call(&s, &put_signaled("door", "fake-signaled", &json!({}))).await);
        let refused = error(
            call_on(
                &s,
                1,
                &json!({ "id": 1, "type": "signaling/subscribe", "stream_id": "a b" }),
            )
            .await,
        );
        assert_eq!(refused.code, ErrorCode::InvalidStreamId);
        assert_eq!(refused.details["stream_id"], "a b");
        let mut door = subscription(
            call_on(
                &s,
                1,
                &json!({ "id": 2, "type": "signaling/subscribe", "stream_id": "door" }),
            )
            .await,
        );
        let signal_id = offered_signal(&s, 1);
        let offer = next(&mut door).await;
        assert_eq!(offer["type"], "offer");
        assert_eq!(offer["signal_id"], signal_id.as_str());
        assert_eq!(offer["protocol"], "fake-signaled");
        assert_eq!(offer["sdp"], lotse_core::test_util::FAKE_SIGNALED_OFFER);
        let commands = |id: u64, signal_id: &str| {
            [
                json!({ "id": id, "type": "signaling/answer", "signal_id": signal_id, "sdp": "v=0\r\n" }),
                json!({ "id": id + 1, "type": "signaling/candidate", "signal_id": signal_id, "candidate": "" }),
                json!({ "id": id + 2, "type": "signaling/error", "signal_id": signal_id, "code": "offline", "message": "m" }),
            ]
        };
        // Another control connection's are refused; the owner's taken.
        for command in commands(3, &signal_id) {
            let refused = error(call_on(&s, 2, &command).await);
            assert_eq!(refused.code, ErrorCode::SignalNotFound, "{command}");
        }
        for command in commands(6, &signal_id) {
            assert_eq!(
                result(call_on(&s, 1, &command).await),
                json!({}),
                "{command}"
            );
        }
        // Its unsubscribe ends its signals; another subscription's is no
        // signaling one.
        assert!(s.unsubscribed(ConnectionId(1), 99).is_none());
        assert!(s.unsubscribed(ConnectionId(1), 2).is_none());
        let refused = error(call_on(&s, 1, &commands(9, &signal_id)[0]).await);
        assert_eq!(refused.code, ErrorCode::SignalNotFound);
        assert!(door.recv().await.is_none(), "the subscription ended");
        // So does its control connection's close.
        let _all =
            subscription(call_on(&s, 3, &json!({ "id": 1, "type": "signaling/subscribe" })).await);
        let signal_id = offered_signal(&s, 2);
        s.connection_closed(ConnectionId(3));
        let refused = error(call_on(&s, 3, &commands(2, &signal_id)[1]).await);
        assert_eq!(refused.code, ErrorCode::SignalNotFound);
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Shuts down while moving a fake clock, so the worker stop budget
    /// passes.
    async fn shutdown_on(s: &Supervisor, clock: &FakeClock) {
        tokio::join!(s.shutdown(), async {
            for _ in 0..100 {
                tokio::task::yield_now().await;
                clock.advance(Duration::from_millis(50));
            }
        });
    }

    #[tokio::test]
    async fn a_worker_s_malformed_answer_or_candidate_refuses_its_session_rfc8839_5_1() {
        let dir = private_dir("malformed");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut first = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        let mut second = subscription(call_on(&s, 1, &offer(3, "front", Some("s2"))).await);
        next(&mut first).await;
        next(&mut second).await;
        let refused = json!({ "type": "closed", "code": "internal_error",
                              "message": "the worker's answer or candidate was malformed" });
        // An answer with a line that is no SDP line never reaches the owner.
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0\r\n<script>\r\n".into(),
                talkback: None,
            },
        );
        assert_eq!(next(&mut first).await, refused);
        assert!(first.recv().await.is_none(), "the subscription ended");
        // Nor does a candidate naming a host name instead of an address.
        report(
            &s,
            "s2",
            Report::Answer {
                sdp: "v=0\r\n".into(),
                talkback: None,
            },
        );
        assert_eq!(next(&mut second).await["type"], "answer");
        report(
            &s,
            "s2",
            Report::Candidate {
                candidate: "candidate:1 1 udp 1 evil.example 9 typ host".into(),
                mid: None,
            },
        );
        assert_eq!(next(&mut second).await, refused);
        assert!(second.recv().await.is_none(), "the subscription ended");
        assert!(s.shared.lock().sessions.is_empty());
        s.shutdown().await;
    }

    /// An offer id, a session id, its flood, the `closed` it ends with or
    /// the type of its last event while it lives, and the most bytes the
    /// flood may queue after the answer.
    type Flood<'a> = (u64, &'a str, &'a dyn Fn() -> Report, &'a Value, usize);

    /// The bytes of `rx`'s queued events as the server frames them, and
    /// the last one.
    fn drain(rx: &mut mpsc::Receiver<Event>, bytes: &mut usize) -> Option<Value> {
        let mut last = None;
        while let Ok(event) = rx.try_recv() {
            *bytes += event.payload.to_string().len();
            last = Some(event.payload);
        }
        last
    }

    #[tokio::test]
    async fn a_worker_flooding_well_formed_reports_loses_its_session_not_the_client_s_connection() {
        let dir = private_dir("flood");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut other = subscription(call_on(&s, 1, &offer(2, "front", Some("other"))).await);
        next(&mut other).await;
        // The largest answer that passes, then the same answer, candidate
        // lines or warnings over and over, as fast as the client's
        // forwarder takes them: everything the session's events add to the
        // connection's outbound queue.
        let sdp = format!(
            "v=0\r\na=mid:0\r\na={}\r\n",
            "x".repeat(crate::worker_text::MAX_ANSWER_BYTES - 18)
        );
        assert_eq!(sdp.len(), crate::worker_text::MAX_ANSWER_BYTES);
        let line = format!(
            "candidate:1 1 udp 1 192.0.2.1 9 typ host ufrag {}",
            "x".repeat(970)
        );
        let answer = || Report::Answer {
            sdp: sdp.clone(),
            talkback: None,
        };
        let candidate = || Report::Candidate {
            candidate: line.clone(),
            mid: Some("0".into()),
        };
        let warning = || Report::Warning {
            code: "av_sync_lost".into(),
            message: "m".repeat(200 * 1024),
        };
        let state = || Report::State {
            ice: "connected".into(),
            dtls: "connected".into(),
        };
        let refused = json!({ "type": "closed", "code": "internal_error",
                              "message": "the worker reported more than its session allows" });
        let share = lotse_api::OUTBOUND_BUDGET_BYTES / 8;
        let floods: [Flood<'_>; 4] = [
            (3, "answers", &answer, &refused, share),
            (4, "candidates", &candidate, &refused, share),
            // One warning per code: the rest are dropped, the session lives.
            (5, "warnings", &warning, &json!("warning"), share),
            // Regression for SUP-30: one `state` per report, changed or
            // not. Now the first is the one change, the session lives.
            (6, "states", &state, &json!("state"), 64),
        ];
        for (id, name, flood, last_event, most) in floods {
            let mut events = subscription(call_on(&s, 1, &offer(id, "front", Some(name))).await);
            next(&mut events).await;
            let connection = s.shared.lock().sessions[name].connection.clone();
            let report = |event| {
                let now = s.shared.clock.now();
                s.shared
                    .lock()
                    .session_report(&connection, name, event, now);
            };
            report(answer());
            let mut bytes = 0;
            let mut last = drain(&mut events, &mut bytes);
            let answered = bytes;
            for _ in 0..2_000 {
                report(flood());
                last = drain(&mut events, &mut bytes).or(last);
            }
            assert!(
                bytes < share,
                "{name}: {bytes} bytes queued for one session"
            );
            let after = bytes - answered;
            assert!(
                after <= most,
                "{name}: {after} bytes queued after the answer"
            );
            if last_event.is_object() {
                assert_eq!(last.as_ref(), Some(last_event), "{name}");
                assert!(events.recv().await.is_none(), "{name}: ended");
            } else {
                assert_eq!(&last.unwrap()["type"], last_event, "{name}");
                let _event = s.shared.lock().close_session(
                    name,
                    CloseCode::SessionClosed,
                    "test",
                    CloseBy::Supervisor,
                );
            }
        }
        // The connection's other session is untouched.
        report(
            &s,
            "other",
            Report::Answer {
                sdp: "v=0\r\n".into(),
                talkback: None,
            },
        );
        assert_eq!(next(&mut other).await["type"], "answer");
        s.shutdown().await;
    }

    #[tokio::test]
    async fn a_worker_s_message_is_logged_escaped_under_detail_never_as_a_line_of_its_own() {
        let captured = Captured::default();
        let _logs = captured.install();
        let dir = private_dir("escaped");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        next(&mut events).await;
        report(
            &s,
            "s1",
            Report::Warning {
                code: "av_sync_lost".into(),
                message: "said \"hi\"\n2026-10-09T00:00:00Z  INFO forged".into(),
            },
        );
        report(
            &s,
            "s1",
            Report::Closed {
                code: "ice_failed".into(),
                message: "bye \"now\"\u{1b}[2J".into(),
            },
        );
        let lines = captured.lines("forged");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(r#"session warning event="session_warning" session.id="s1" code="av_sync_lost" detail="said \"hi\" 2026-10-09T00:00:00Z  INFO forged""#),
            "{lines:?}"
        );
        let lines = captured.lines("session closed");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("detail=\"bye \\\"now\\\"\u{fffd}[2J\""),
            "{lines:?}"
        );
        s.shutdown().await;
    }

    #[tokio::test]
    async fn a_worker_flapping_a_session_s_state_logs_each_state_once_per_interval() {
        let captured = Captured::default();
        let _logs = captured.install();
        let dir = private_dir("flapping");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        next(&mut events).await;
        let state = |ice: &str| Report::State {
            ice: ice.into(),
            dtls: "connected".into(),
        };
        report(&s, "s1", state("checking"));
        for _ in 0..50 {
            report(&s, "s1", state("connected"));
            report(&s, "s1", state("disconnected"));
        }
        let lines = captured.lines("session state changed");
        assert_eq!(lines.len(), 3, "each state once: {lines:?}");
        assert!(
            lines[2].contains(r#"ice="disconnected" dtls="connected" count=1"#),
            "{lines:?}"
        );
        clock.advance(lotse_core::throttle::SUMMARY_INTERVAL);
        report(&s, "s1", state("connected"));
        let lines = captured.lines("session state changed");
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(
            lines[3].contains(r#"ice="connected" dtls="connected" count=50"#),
            "{lines:?}"
        );
        // Every change still reaches the client.
        let mut states = 0;
        while let Ok(event) = events.try_recv() {
            states += usize::from(event.payload["type"] == "state");
        }
        assert_eq!(states, 102);
        shutdown_on(&s, &clock).await;
    }

    #[tokio::test]
    async fn orphans_buffer_events_until_adopted_or_the_grace_expires() {
        let dir = private_dir("orphan");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut first = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        next(&mut first).await;
        let err = error(
            call_on(
                &s,
                2,
                &json!({ "id": 1, "type": "session/adopt", "session_id": "s1" }),
            )
            .await,
        );
        assert_eq!(err.code, ErrorCode::SessionIdInUse, "still owned");
        s.connection_closed(ConnectionId(1));
        let got = result(call(&s, r#"{"id":3,"type":"session/get","session_id":"s1"}"#).await);
        assert_eq!(got["orphaned"], true);
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0\r\ns=buffered\r\n".into(),
                talkback: None,
            },
        );
        let err = error(
            call_on(
                &s,
                2,
                &json!({ "id": 1, "type": "session/adopt", "session_id": "ghost" }),
            )
            .await,
        );
        assert_eq!(err.code, ErrorCode::SessionNotFound);
        let mut adopted = subscription(
            call_on(
                &s,
                2,
                &json!({ "id": 2, "type": "session/adopt", "session_id": "s1" }),
            )
            .await,
        );
        assert_eq!(
            next(&mut adopted).await,
            json!({ "type": "state", "ice": "new", "dtls": "new" })
        );
        assert_eq!(
            next(&mut adopted).await,
            json!({ "type": "answer", "sdp": "v=0\r\ns=buffered\r\n" })
        );
        // The first grace timer is stale once adopted.
        clock.advance(Duration::from_secs(10));
        tokio::task::yield_now().await;
        assert!(s.shared.lock().sessions.contains_key("s1"));
        // Orphaned again and not adopted: closed when the grace expires.
        // The fired first grace timer is dropped as the new one is kept.
        s.connection_closed(ConnectionId(2));
        assert_eq!(s.shared.lock().sessions["s1"].timers().len(), 1);
        clock.advance(Duration::from_millis(9_999));
        tokio::task::yield_now().await;
        assert!(s.shared.lock().sessions.contains_key("s1"));
        clock.advance(Duration::from_millis(1));
        for _ in 0..100 {
            if !s.shared.lock().sessions.contains_key("s1") {
                break;
            }
            tokio::task::yield_now().await;
        }
        let err = error(call(&s, r#"{"id":4,"type":"session/get","session_id":"s1"}"#).await);
        assert_eq!(err.code, ErrorCode::SessionNotFound);
        shutdown_on(&s, &clock).await;
    }

    /// What a driver publishes for its connection: `state`, with `error`
    /// as the last error, a failure after a failed attempt or a crash.
    fn snapshot(state: ConnectionState, error: Option<ConnectionError>) -> ConnectionSnapshot {
        let failed = matches!(
            state,
            ConnectionState::Backoff | ConnectionState::Restarting
        );
        ConnectionSnapshot {
            state,
            failure: error.clone().filter(|_| failed),
            last_error: error,
            ..ConnectionSnapshot::idle(std::time::UNIX_EPOCH)
        }
    }

    /// What a driver publishes after a live source dropped and its retry
    /// waits out a delay: no failure.
    fn dropped() -> ConnectionSnapshot {
        ConnectionSnapshot {
            failure: None,
            ..snapshot(
                ConnectionState::Backoff,
                Some(ConnectionError::Source(SourceError::Ended(
                    "the camera closed the session".into(),
                ))),
            )
        }
    }

    /// The event delivered already: what the tests here wait for is
    /// delivered under the lock, so a missing one fails at once.
    fn delivered(rx: &mut mpsc::Receiver<Event>) -> Value {
        rx.try_recv().expect("an event delivered").payload
    }

    /// Whether the subscription ended: its session is gone.
    fn ended(rx: &mut mpsc::Receiver<Event>) -> bool {
        matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Disconnected))
    }

    /// Lets the connection's driver run up to its first wait, so its first
    /// snapshot is in before the test publishes its own.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_waiting_session_closes_with_its_source_s_error_as_soon_as_the_attempt_fails() {
        let dir = private_dir("srcfail");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(delivered(&mut events)["type"], "session");
        // No deadline of the daemon's own: the source's bound the wait.
        assert!(s.shared.lock().sessions["s1"].timers().is_empty());
        let connection = s.shared.lock().sessions["s1"].connection.clone();
        let captured = Captured::default();
        let _logs = captured.install();
        // RFC 2326 §7.1.1: a 401 is a credential failure.
        let error = SourceError::AuthFailed(
            "401 Unauthorized response to DESCRIBE CSeq=1: Unauthorized".into(),
        );
        s.shared.update_connection(
            &connection,
            snapshot(
                ConnectionState::Backoff,
                Some(ConnectionError::Source(error)),
            ),
            true,
        );
        assert_eq!(
            delivered(&mut events),
            json!({ "type": "closed", "code": "source_auth_failed",
                "message": "source authentication failed: 401 Unauthorized response to DESCRIBE CSeq=1: Unauthorized" })
        );
        assert!(ended(&mut events));
        assert!(s.shared.lock().sessions.is_empty());
        let logged = captured.lines("session closed with its source's error");
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(
            logged[0].contains("session.id=s1")
                && logged[0].contains("error.code=\"source_auth_failed\"")
                && logged[0].contains("before the session was answered"),
            "{logged:?}"
        );
        shutdown_on(&s, &clock).await;
    }

    #[tokio::test]
    async fn an_offer_to_a_connection_that_already_failed_closes_at_once_with_its_error() {
        let dir = private_dir("srcfailed");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let connection = s.shared.lock().streams["front"].sources[0]
            .connection
            .clone();
        settle().await;
        let failures = [
            (
                ConnectionState::Backoff,
                ConnectionError::Source(SourceError::Unreachable(
                    "Unable to connect to RTSP server: Connection refused (os error 111)".into(),
                )),
                "source_unreachable",
            ),
            (
                ConnectionState::Backoff,
                ConnectionError::Source(SourceError::Ended("the camera closed the session".into())),
                "source_ended",
            ),
            (
                ConnectionState::Restarting,
                ConnectionError::WorkerCrashed,
                "worker_crashed",
            ),
        ];
        for (index, (state, error, code)) in failures.into_iter().enumerate() {
            let message = error.to_string();
            s.shared
                .update_connection(&connection, snapshot(state, Some(error)), true);
            let captured = Captured::default();
            let _logs = captured.install();
            let id = format!("s{index}");
            let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some(&id))).await);
            assert_eq!(
                delivered(&mut events),
                json!({ "type": "session", "session_id": id })
            );
            assert_eq!(
                delivered(&mut events),
                json!({ "type": "closed", "code": code, "message": message })
            );
            assert!(ended(&mut events));
            let state_now = s.shared.lock();
            assert!(state_now.sessions.is_empty());
            assert_eq!(
                state_now.connections[&connection].demand.borrow().total(),
                0,
                "no attempt for it"
            );
            drop(state_now);
            let logged = captured.lines("offer closed at once with its source's error");
            assert!(
                logged[0].contains(&format!("connection.state=\"{}\"", state.name()))
                    && logged[0].contains(&format!("error.code=\"{code}\"")),
                "{logged:?}"
            );
            let closed = captured.lines("session closed");
            assert!(
                closed.iter().any(|line| line.contains("by=Offer")),
                "{closed:?}"
            );
        }
        // A live source that dropped and waits out a delay before its
        // retry has not failed: the offer waits for the retry.
        s.shared.update_connection(&connection, dropped(), true);
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s9"))).await);
        assert_eq!(delivered(&mut events)["type"], "session");
        assert!(events.try_recv().is_err(), "no closed for a drop");
        assert_eq!(
            s.shared.lock().connections[&connection]
                .demand
                .borrow()
                .total(),
            1,
            "handed to the driver"
        );
        shutdown_on(&s, &clock).await;
    }

    #[tokio::test]
    async fn a_stale_error_does_not_close_an_offer_that_starts_a_fresh_attempt() {
        let dir = private_dir("srcstale");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let connection = s.shared.lock().streams["front"].sources[0]
            .connection
            .clone();
        settle().await;
        let stale = ConnectionError::Source(SourceError::AuthFailed("401".into()));
        s.shared.update_connection(
            &connection,
            snapshot(ConnectionState::Idle, Some(stale.clone())),
            true,
        );
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(delivered(&mut events)["type"], "session");
        assert_eq!(
            s.shared.lock().connections[&connection]
                .demand
                .borrow()
                .total(),
            1,
            "the offer starts an attempt"
        );
        // The attempt connects with the stale error still on the snapshot.
        s.shared.update_connection(
            &connection,
            snapshot(ConnectionState::Connecting, Some(stale)),
            true,
        );
        assert!(s.shared.lock().sessions.contains_key("s1"));
        assert!(events.try_recv().is_err(), "nothing yet");
        // Its own outcome closes it.
        s.shared.update_connection(
            &connection,
            snapshot(
                ConnectionState::Backoff,
                Some(ConnectionError::Source(SourceError::Timeout(
                    "DESCRIBE: no response within 10000 ms".into(),
                ))),
            ),
            true,
        );
        assert_eq!(
            delivered(&mut events),
            json!({ "type": "closed", "code": "source_timeout",
                "message": "source timed out: DESCRIBE: no response within 10000 ms" })
        );
        shutdown_on(&s, &clock).await;
    }

    #[tokio::test]
    async fn an_offer_after_a_source_switch_waits_for_the_new_source() {
        let dir = private_dir("srcswitch");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let connection = s.shared.lock().streams["front"].sources[0]
            .connection
            .clone();
        settle().await;
        s.shared.update_connection(
            &connection,
            snapshot(
                ConnectionState::Backoff,
                Some(ConnectionError::Source(SourceError::AuthFailed(
                    "401".into(),
                ))),
            ),
            true,
        );
        // The put switches the connection to another source; the offer
        // comes before its driver takes the switch.
        result(call(&s, &put("front", "fake://127.0.0.1:1/other", false)).await);
        assert_eq!(
            s.shared.lock().streams["front"].sources[0].connection,
            connection,
            "switched in place"
        );
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        assert_eq!(delivered(&mut events)["type"], "session");
        assert!(events.try_recv().is_err(), "no closed with the old error");
        assert_eq!(
            s.shared.lock().connections[&connection]
                .demand
                .borrow()
                .total(),
            1,
            "handed to the driver"
        );
        // The driver reports the old source's failure again before it
        // takes the switch: the session still waits.
        s.shared.update_connection(
            &connection,
            snapshot(
                ConnectionState::Backoff,
                Some(ConnectionError::Source(SourceError::AuthFailed(
                    "401".into(),
                ))),
            ),
            true,
        );
        assert!(events.try_recv().is_err(), "no closed with the old error");
        assert_eq!(
            s.shared.lock().connections[&connection].snapshot.failure,
            None
        );
        // The new source's own failure closes it.
        s.shared.update_connection(
            &connection,
            ConnectionSnapshot {
                switches: 1,
                ..snapshot(
                    ConnectionState::Backoff,
                    Some(ConnectionError::Source(SourceError::Timeout("new".into()))),
                )
            },
            true,
        );
        assert_eq!(
            delivered(&mut events),
            json!({ "type": "closed", "code": "source_timeout",
                "message": "source timed out: new" })
        );
        shutdown_on(&s, &clock).await;
    }

    #[tokio::test]
    async fn an_offer_closed_at_once_keeps_its_close_after_every_warning() {
        let dir = private_dir("srcwarn");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let connection = s.shared.lock().streams["front"].sources[0]
            .connection
            .clone();
        settle().await;
        s.shared.update_connection(
            &connection,
            snapshot(
                ConnectionState::Backoff,
                Some(ConnectionError::Source(SourceError::Timeout("late".into()))),
            ),
            true,
        );
        // As many turns: URLs as an offer may carry, each worth a warning.
        let servers: Vec<Value> = (0..lotse_api_types::limits::MAX_ICE_SERVERS)
            .map(|server| {
                let urls: Vec<String> = (0..lotse_api_types::limits::MAX_ICE_URLS)
                    .map(|url| format!("turns:t{server}-{url}.example"))
                    .collect();
                json!({ "urls": urls })
            })
            .collect();
        let mut request = offer(2, "front", Some("s1"));
        request["ice_servers"] = json!(servers);
        let mut events = subscription(call_on(&s, 1, &request).await);
        assert_eq!(delivered(&mut events)["type"], "session");
        for _ in 0..crate::gather::MAX_WARNINGS {
            assert_eq!(delivered(&mut events)["type"], "warning");
        }
        assert_eq!(
            delivered(&mut events),
            json!({ "type": "closed", "code": "source_timeout",
                "message": "source timed out: late" })
        );
        assert!(ended(&mut events));
        // The queue holds the session event, every warning and the close.
        const { assert!(crate::gather::MAX_WARNINGS + 2 <= SESSION_QUEUE) };
        shutdown_on(&s, &clock).await;
    }

    #[tokio::test]
    async fn a_waiting_session_rides_a_reconnect_and_closes_only_when_it_fails() {
        let dir = private_dir("srcride");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut playing = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        let mut waiting = subscription(call_on(&s, 1, &offer(3, "front", Some("s2"))).await);
        assert_eq!(delivered(&mut playing)["type"], "session");
        assert_eq!(delivered(&mut waiting)["type"], "session");
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0\r\n".into(),
                talkback: None,
            },
        );
        assert_eq!(delivered(&mut playing)["type"], "answer");
        let connection = s.shared.lock().sessions["s1"].connection.clone();
        s.shared.update_connection(
            &connection,
            snapshot(
                ConnectionState::Reconnecting,
                Some(ConnectionError::Source(SourceError::Ended(
                    "the camera closed the session".into(),
                ))),
            ),
            true,
        );
        // The worker retries at once: both sessions wait for it.
        assert!(s.shared.lock().sessions.contains_key("s2"));
        assert!(waiting.try_recv().is_err(), "no closed for a drop");
        // The source went live again and dropped again; its retry waits
        // out a delay this time, and both sessions wait for it too.
        s.shared.update_connection(&connection, dropped(), true);
        assert!(s.shared.lock().sessions.contains_key("s2"));
        assert!(waiting.try_recv().is_err(), "no closed for a drop");
        // The retry fails: the waiting session closes with its error, the
        // answered one plays on.
        s.shared.update_connection(
            &connection,
            snapshot(
                ConnectionState::Backoff,
                Some(ConnectionError::Source(SourceError::Unreachable(
                    "Unable to connect to RTSP server: Connection refused (os error 111)".into(),
                ))),
            ),
            true,
        );
        assert_eq!(
            delivered(&mut waiting),
            json!({ "type": "closed", "code": "source_unreachable",
                "message": "source unreachable: Unable to connect to RTSP server: Connection refused (os error 111)" })
        );
        assert!(ended(&mut waiting));
        let sessions: Vec<String> = s.shared.lock().sessions.keys().cloned().collect();
        assert_eq!(sessions, ["s1"]);
        assert!(playing.try_recv().is_err(), "no closed for it");
        shutdown_on(&s, &clock).await;
    }

    #[tokio::test]
    async fn a_put_is_unchanged_only_when_every_flag_and_source_matches() {
        let dir = private_dir("unchanged");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        let base = json!({ "id": 1, "type": "stream/put", "stream_id": "front",
            "sources": [{ "url": "fake://127.0.0.1:1/", "options": { "ready_after_ms": 1 } }],
            "preload": false, "audio": "auto", "orientation": "rotate_left" });
        result(call(&s, &base.to_string()).await);
        let parse = |value: &Value| {
            let mut fields = value.clone();
            fields.as_object_mut().unwrap().remove("type");
            let put: StreamPut = serde_json::from_value(fields).unwrap();
            let validated: Vec<ValidatedSource> = put
                .sources
                .iter()
                .map(|source| {
                    s.validate_source(&StreamId::new(&put.stream_id).unwrap(), source)
                        .unwrap()
                })
                .collect();
            (put, validated)
        };
        let check = |value: &Value| {
            let (put, validated) = parse(value);
            unchanged(&s.shared.lock().streams["front"], &put, &validated)
        };
        assert!(check(&base));
        let mut two = base.clone();
        two["sources"] = json!([{ "url": "fake://127.0.0.1:1/", "options": { "ready_after_ms": 1 } },
                                { "url": "fake://127.0.0.1:2/" }]);
        for (field, value) in [
            ("preload", json!(true)),
            ("audio", json!("off")),
            ("orientation", json!("rotate_right")),
            (
                "sources",
                json!([{ "url": "fake://127.0.0.1:2/", "options": { "ready_after_ms": 1 } }]),
            ),
            (
                "sources",
                json!([{ "url": "fake://127.0.0.1:1/", "options": { "ready_after_ms": 2 } }]),
            ),
            ("sources", two["sources"].clone()),
        ] {
            let mut changed = base.clone();
            changed[field] = value;
            assert!(!check(&changed), "{changed}");
        }
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn changing_or_deleting_the_stream_and_shutdown_close_its_sessions() {
        let dir = private_dir("stream-close");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        next(&mut s1).await;
        // Only a source on another port closes: an unchanged put does
        // not, nor one the worker switches to in place.
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        result(call(&s, &put("front", "fake://127.0.0.1:1/", true)).await);
        result(call(&s, &put("front", "fake://127.0.0.1:1/other", false)).await);
        assert!(s.shared.lock().sessions.contains_key("s1"));
        assert_eq!(front_connection(&s).await, "c1");
        result(call(&s, &put("front", "fake://127.0.0.1:3/", false)).await);
        assert_eq!(next(&mut s1).await["code"], "stream_changed");
        assert_eq!(front_connection(&s).await, "c2");
        let mut s2 = subscription(call_on(&s, 1, &offer(3, "front", Some("s2"))).await);
        next(&mut s2).await;
        result(call(&s, r#"{"id":4,"type":"stream/delete","stream_id":"front"}"#).await);
        assert_eq!(next(&mut s2).await["code"], "stream_deleted");
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut s3 = subscription(call_on(&s, 1, &offer(5, "front", Some("s3"))).await);
        next(&mut s3).await;
        s.shutdown().await;
        assert_eq!(next(&mut s3).await["code"], "shutting_down");
        assert!(s3.recv().await.is_none());
    }

    #[tokio::test]
    async fn a_worker_exit_closes_its_sessions_with_worker_crashed() {
        // `/bin/sh worker ...` exits at once.
        let s = with_webrtc("/bin/sh", Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        next(&mut events).await;
        let closed = next(&mut events).await;
        assert_eq!(
            (&closed["type"], &closed["code"]),
            (&json!("closed"), &json!("worker_crashed"))
        );
        assert!(s.shared.lock().sessions.is_empty());
        s.shutdown().await;
    }

    #[tokio::test]
    async fn a_candidate_is_taken_only_from_the_connection_that_owns_the_session() {
        let dir = private_dir("candidate-owner");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        let candidate = |id: u64| {
            json!({ "id": id, "type": "webrtc/candidate", "session_id": "s1",
                    "candidate": "candidate:1 1 udp 1 192.0.2.9 5000 typ host" })
        };
        let remote = |s: &Supervisor| s.shared.lock().sessions["s1"].remote_candidates;
        // Another connection neither reaches the worker nor spends the
        // session's candidate budget.
        let err = error(call_on(&s, 2, &candidate(3)).await);
        assert_eq!(err.code, ErrorCode::SessionNotFound);
        assert_eq!(err.message, "the session is not this connection's");
        assert_eq!(err.details["session_id"], "s1");
        assert_eq!(remote(&s), 0);
        result(call_on(&s, 1, &candidate(4)).await);
        assert_eq!(remote(&s), 1);
        // An orphan takes candidates only once adopted, from its new owner.
        drop(events);
        s.connection_closed(ConnectionId(1));
        let err = error(call_on(&s, 1, &candidate(5)).await);
        assert_eq!(err.code, ErrorCode::SessionNotFound);
        let _adopted = subscription(
            call_on(
                &s,
                2,
                &json!({ "id": 6, "type": "session/adopt", "session_id": "s1" }),
            )
            .await,
        );
        result(call_on(&s, 2, &candidate(7)).await);
        assert_eq!(remote(&s), 2);
        s.shutdown().await;
    }

    /// The offer reserves its close a slot in the driver's queue: a queue
    /// that fills up meanwhile still takes the close, behind what came
    /// before it.
    #[tokio::test]
    async fn a_close_reaches_the_driver_through_a_full_queue() {
        let dir = private_dir("closeslot");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        // The queue holds a close for every session the daemon allows
        // besides its own room.
        let sessions = usize::try_from(s.settings.limits.max_sessions).unwrap();
        assert_eq!(
            s.shared.lock().connections["c1"].commands.max_capacity(),
            COMMAND_QUEUE + sessions
        );
        let (tx, mut rx) = mpsc::channel(4);
        s.shared.lock().connections.get_mut("c1").unwrap().commands = tx.clone();
        let _s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        let filler = || DriverCommand::Candidate {
            session_id: "x".into(),
            candidate: String::new(),
        };
        while tx.try_send(filler()).is_ok() {}
        result(
            call_on(
                &s,
                1,
                &json!({ "id": 3, "type": "session/close", "session_id": "s1" }),
            )
            .await,
        );
        assert!(matches!(
            rx.recv().await,
            Some(DriverCommand::OpenSession(_))
        ));
        for _ in 0..2 {
            assert!(matches!(
                rx.recv().await,
                Some(DriverCommand::Candidate { .. })
            ));
        }
        let_assert!(Some(DriverCommand::CloseSession { session_id, .. }) = rx.recv().await);
        assert_eq!(session_id, "s1");
        s.shutdown().await;
    }

    #[tokio::test]
    async fn a_full_driver_queue_is_limit_reached_and_nothing_leaks() {
        let dir = private_dir("full");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let _s1 = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        let (full, _rx) = mpsc::channel(1);
        full.try_send(DriverCommand::Candidate {
            session_id: "x".into(),
            candidate: String::new(),
        })
        .unwrap();
        s.shared.lock().connections.get_mut("c1").unwrap().commands = full;
        let err = error(call_on(&s, 1, &offer(3, "front", Some("s2"))).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("connection_queue"))
        );
        assert!(!s.shared.lock().sessions.contains_key("s2"));
        // Room for the offer but not for its close is no room either.
        let (one_free, mut one_free_rx) = mpsc::channel(2);
        one_free
            .try_send(DriverCommand::Candidate {
                session_id: "x".into(),
                candidate: String::new(),
            })
            .unwrap();
        let full = std::mem::replace(
            &mut s.shared.lock().connections.get_mut("c1").unwrap().commands,
            one_free,
        );
        let err = error(call_on(&s, 1, &offer(3, "front", Some("s2"))).await);
        assert_eq!(err.details["limit"], json!("connection_queue"));
        assert!(matches!(
            one_free_rx.try_recv(),
            Ok(DriverCommand::Candidate { .. })
        ));
        assert!(
            one_free_rx.try_recv().is_err(),
            "the offer is not handed on"
        );
        s.shared.lock().connections.get_mut("c1").unwrap().commands = full;
        let err = error(call_on(&s, 1, &json!({ "id": 4, "type": "webrtc/candidate", "session_id": "s1", "candidate": "" })).await);
        assert_eq!(err.code, ErrorCode::LimitReached);
        // Another connection closing leaves the session with its owner.
        s.connection_closed(ConnectionId(9));
        let got = result(call(&s, r#"{"id":5,"type":"session/get","session_id":"s1"}"#).await);
        assert_eq!(got["orphaned"], false);
        // A close still ends the session; the worker drops it with its connection.
        result(
            call_on(
                &s,
                1,
                &json!({ "id": 6, "type": "session/close", "session_id": "s1" }),
            )
            .await,
        );
        assert!(s.shared.lock().sessions.is_empty());
        let err = internal("boom");
        assert_eq!(
            (err.code, err.message.as_str()),
            (ErrorCode::InternalError, "boom")
        );
        s.shutdown().await;
    }

    #[tokio::test]
    async fn the_driver_gets_the_offer_with_credentials_hosts_and_audio_and_the_closes() {
        let dir = private_dir("to-driver");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        let put = |stream: &str, audio: &str, orientation: &str| {
            json!({ "id": 1, "type": "stream/put", "stream_id": stream,
                "sources": [{ "url": format!("fake://127.0.0.1:{}/", stream.len()) }],
                "audio": audio, "orientation": orientation })
            .to_string()
        };
        for (stream, audio, orientation) in [
            ("front", "auto", "rotate_left"),
            ("back", "off", "no_transform"),
        ] {
            result(call(&s, &put(stream, audio, orientation)).await);
        }
        let (tx, mut rx) = mpsc::channel(8);
        for connection in ["c1", "c2"] {
            s.shared
                .lock()
                .connections
                .get_mut(connection)
                .unwrap()
                .commands = tx.clone();
        }
        let _f = subscription(call_on(&s, 1, &offer(2, "front", Some("f1"))).await);
        let _b = subscription(call_on(&s, 1, &offer(3, "back", Some("b1"))).await);
        for (session, audio, orientation) in [("f1", true, 6), ("b1", false, 1)] {
            let_assert!(
                Some(DriverCommand::OpenSession(spec)) = rx.recv().await,
                "an offer"
            );
            assert_eq!(
                (spec.session_id.as_str(), spec.audio, spec.orientation),
                (session, audio, orientation)
            );
            assert_eq!(spec.kind, WEBRTC);
            assert_eq!(spec.offer, "v=0");
            assert_eq!(
                spec.candidates,
                vec!["192.0.2.1:18556".parse::<SocketAddr>().unwrap()]
            );
            assert_eq!(
                spec.tcp_candidates,
                vec!["192.0.2.1:18557".parse::<SocketAddr>().unwrap()]
            );
            assert_eq!(spec.ice_ufrag, s.shared.lock().sessions[session].ufrag);
            assert_eq!(spec.ice_pass.len(), 24);
        }
        // A put that changes only the orientation is a change, keeps the
        // connection and the open session, and reaches the next offer.
        let changed = result(call(&s, &put("back", "off", "rotate_right")).await);
        assert_eq!(changed["created"], false);
        assert!(s.shared.lock().sessions.contains_key("b1"));
        assert_eq!(s.shared.lock().connections.len(), 2);
        assert!(matches!(
            rx.recv().await,
            Some(DriverCommand::Orientation { .. })
        ));
        let _b2 = subscription(call_on(&s, 1, &offer(5, "back", Some("b2"))).await);
        let_assert!(
            Some(DriverCommand::OpenSession(spec)) = rx.recv().await,
            "an offer"
        );
        assert_eq!((spec.session_id.as_str(), spec.orientation), ("b2", 8));
        // The supervisor's close reaches the worker; a gone worker's does not.
        result(
            call_on(
                &s,
                1,
                &json!({ "id": 4, "type": "session/close", "session_id": "f1" }),
            )
            .await,
        );
        let_assert!(
            Some(DriverCommand::CloseSession {
                session_id,
                code,
                ..
            }) = rx.recv().await,
            "a close"
        );
        assert_eq!((session_id.as_str(), code), ("f1", "session_closed"));
        s.shared.lock().close_sessions_where(
            |_| true,
            CloseCode::WorkerCrashed,
            "gone",
            CloseBy::WorkerGone,
        );
        assert!(s.shared.lock().sessions.is_empty());
        assert!(rx.try_recv().is_err(), "nothing for a worker that is gone");
        s.shutdown().await;
    }

    #[tokio::test]
    async fn a_put_that_turns_a_stream_turns_its_open_sessions_and_no_others() {
        let dir = private_dir("turn");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        let put = |stream: &str, audio: &str, orientation: &str| {
            json!({ "id": 1, "type": "stream/put", "stream_id": stream,
                "sources": [{ "url": format!("fake://127.0.0.1:{}/", stream.len()) }],
                "audio": audio, "orientation": orientation })
            .to_string()
        };
        for stream in ["front", "back"] {
            result(call(&s, &put(stream, "off", "no_transform")).await);
        }
        let (tx, mut rx) = mpsc::channel(8);
        for connection in ["c1", "c2"] {
            s.shared
                .lock()
                .connections
                .get_mut(connection)
                .unwrap()
                .commands = tx.clone();
        }
        let _f = subscription(call_on(&s, 1, &offer(2, "front", Some("f1"))).await);
        let _b = subscription(call_on(&s, 1, &offer(3, "back", Some("b1"))).await);
        for _ in 0..2 {
            assert!(matches!(
                rx.recv().await,
                Some(DriverCommand::OpenSession(_))
            ));
        }
        // The open session of the turned stream turns; the other stream's
        // hears nothing.
        result(call(&s, &put("back", "off", "rotate_right")).await);
        let_assert!(
            Some(DriverCommand::Orientation {
                session_id,
                orientation,
            }) = rx.recv().await,
            "an orientation"
        );
        assert_eq!((session_id.as_str(), orientation), ("b1", 8));
        assert!(rx.try_recv().is_err(), "one session turns");
        // A put that keeps the orientation tells no session about it.
        result(call(&s, &put("back", "auto", "rotate_right")).await);
        assert!(rx.try_recv().is_err(), "the orientation did not change");
        // A session whose driver queue is full keeps the orientation it has.
        let (full, _full) = mpsc::channel(1);
        full.try_send(DriverCommand::Candidate {
            session_id: "x".into(),
            candidate: String::new(),
        })
        .unwrap();
        let back = s.shared.lock().sessions["b1"].connection.clone();
        let commands = std::mem::replace(
            &mut s.shared.lock().connections.get_mut(&back).unwrap().commands,
            full,
        );
        result(call(&s, &put("back", "auto", "rotate_left")).await);
        s.shared.lock().connections.get_mut(&back).unwrap().commands = commands;
        assert!(rx.try_recv().is_err(), "dropped, not queued elsewhere");
        s.shutdown().await;
    }

    /// [`with_webrtc`] with a STUN client on a loopback socket and its
    /// demux; the host address is the socket's.
    fn with_stun(binary: &str, clock: Arc<dyn Clock>) -> (Supervisor, crate::net::demux::Demux) {
        let bound = crate::net::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let demux = crate::net::demux::Demux::start(
            Arc::clone(&bound.socket),
            bound.local,
            bound.hosts.clone(),
            Arc::new(SystemClock),
        )
        .unwrap();
        let door = FrontDoor {
            registrations: demux.registrations(),
            hosts: bound.hosts,
            tcp_hosts: vec![],
            stun: Some(Arc::new(StunClient::new(
                bound.socket,
                demux.responses(),
                Arc::clone(&clock),
                crate::net::stun_client::StunClientConfig::default(),
            ))),
            turn: None,
            demux: Some(demux.stats()),
        };
        let s = Supervisor::new(session_settings(), webrtc_environment(binary, door), clock);
        (s, demux)
    }

    /// A STUN server answering every Binding with `mapped`, or `None` for a
    /// silent one.
    fn stun_server(mapped: Option<SocketAddr>) -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let (Some(mapped), Ok(request)) = (mapped, crate::net::stun::parse(&buf[..n]))
                else {
                    continue;
                };
                let reply = crate::net::stun::Builder::new(
                    crate::net::stun::Class::Success,
                    crate::net::stun::METHOD_BINDING,
                    request.transaction_id,
                )
                .xor_mapped_address(mapped)
                .build();
                let _sent = socket.send_to(&reply, from);
            }
        });
        addr
    }

    fn stun_offer(id: u64, session_id: &str, server: SocketAddr) -> Value {
        let mut offer = offer(id, "front", Some(session_id));
        offer["ice_servers"] = json!([{ "urls": [format!("stun:{server}")] }]);
        offer
    }

    fn end_of_candidates() -> Report {
        Report::Candidate {
            candidate: String::new(),
            mid: None,
        }
    }

    #[tokio::test]
    async fn srflx_candidates_follow_the_answer_and_precede_end_of_candidates() {
        let dir = private_dir("srflx");
        let (s, demux) = with_stun(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let nat = stun_server(Some("203.0.113.7:40000".parse().unwrap()));
        let mut events = subscription(call_on(&s, 1, &stun_offer(2, "s1", nat)).await);
        next(&mut events).await;
        // The gather deadline is the session's one timer.
        assert_eq!(s.shared.lock().sessions["s1"].timers().len(), 1);
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0\r\na=mid:0\r\n".into(),
                talkback: None,
            },
        );
        assert_eq!(next(&mut events).await["type"], "answer");
        // The worker is done first; end-of-candidates waits for the gather.
        report(&s, "s1", end_of_candidates());
        let srflx = next(&mut events).await;
        assert_eq!(srflx["sdp_mid"], "0");
        assert!(
            srflx["candidate"]
                .as_str()
                .unwrap()
                .contains("203.0.113.7 40000 typ srflx raddr 127.0.0.1"),
            "{srflx}"
        );
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "candidate", "candidate": "" })
        );
        // The demux counted the STUN response as `metrics/get` shows, and
        // each counter is its own.
        demux
            .stats()
            .addresses_moved
            .store(3, std::sync::atomic::Ordering::Relaxed);
        let counted =
            &result(call(&s, r#"{"id":3,"type":"metrics/get"}"#).await)["supervisor"]["demux"];
        assert!(counted["responses"].as_u64().unwrap() >= 1, "{counted}");
        assert_eq!(counted["received"], counted["responses"], "{counted}");
        assert_eq!(counted["addresses_moved"], 3, "{counted}");
        s.shutdown().await;
        demux.stop();
    }

    #[tokio::test]
    async fn a_silent_stun_server_holds_end_of_candidates_for_the_deadline_only() {
        let dir = private_dir("srflx-deadline");
        let clock = Arc::new(FakeClock::from_system());
        let (s, demux) = with_stun(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let silent = stun_server(None);
        let mut events = subscription(call_on(&s, 1, &stun_offer(2, "s1", silent)).await);
        next(&mut events).await;
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0".into(),
                talkback: None,
            },
        );
        assert_eq!(next(&mut events).await["type"], "answer");
        report(&s, "s1", end_of_candidates());
        tokio::task::yield_now().await;
        assert!(events.try_recv().is_err(), "held while the gather runs");
        clock.advance(GATHER_DEADLINE);
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "candidate", "candidate": "" })
        );
        shutdown_on(&s, &clock).await;
        demux.stop();
    }

    /// [`with_webrtc`] with a TURN client on a loopback socket and its
    /// demux, and that socket's host address.
    fn with_turn(binary: &str) -> (Supervisor, crate::net::demux::Demux, SocketAddr) {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let bound = crate::net::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let demux = crate::net::demux::Demux::start(
            Arc::clone(&bound.socket),
            bound.local,
            bound.hosts.clone(),
            Arc::new(SystemClock),
        )
        .unwrap();
        let door = FrontDoor {
            registrations: demux.registrations(),
            hosts: bound.hosts,
            tcp_hosts: vec![],
            stun: None,
            turn: Some(Arc::new(TurnClient::new(
                bound.socket,
                &demux,
                Arc::clone(&clock),
                crate::net::allocation::AllocationConfig::default(),
            ))),
            demux: None,
        };
        let s = Supervisor::new(session_settings(), webrtc_environment(binary, door), clock);
        (s, demux, bound.local)
    }

    /// A fake TURN server knowing user `ha` with password `pw`.
    async fn turn_server() -> (
        Arc<lotse_testing::fake_turn::FakeTurn>,
        lotse_testing::fake_turn::FakeTurnServer,
    ) {
        let turn = Arc::new(lotse_testing::fake_turn::FakeTurn::new(
            Arc::new(SystemClock),
            "lotse.test",
            Duration::from_secs(600),
        ));
        turn.add_user("ha", "pw");
        let server = lotse_testing::fake_turn::FakeTurnServer::start(Arc::clone(&turn))
            .await
            .unwrap();
        (turn, server)
    }

    fn turn_offer(id: u64, server: SocketAddr, credential: &str) -> Value {
        let mut offer = offer(id, "front", Some("s1"));
        offer["ice_servers"] = json!([{ "urls": [format!("turn:{server}")],
                                        "username": "ha", "credential": credential }]);
        offer
    }

    /// The next command for the worker that is not the offer.
    async fn next_command(rx: &mut mpsc::Receiver<DriverCommand>) -> DriverCommand {
        loop {
            let command = tokio::select! {
                command = rx.recv() => command.expect("the driver queue is open"),
                () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no command for the worker"),
            };
            if !matches!(command, DriverCommand::OpenSession(_)) {
                return command;
            }
        }
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "one relay candidate's life")]
    async fn relay_candidates_reach_the_worker_and_their_channels_are_bound_rfc_8656() {
        let dir = private_dir("relay");
        let (turn, server) = turn_server().await;
        let (s, demux, host) = with_turn(&blocking_worker(&dir));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let (tx, mut rx) = mpsc::channel(16);
        s.shared.lock().connections.get_mut("c1").unwrap().commands = tx;
        let mut events =
            subscription(call_on(&s, 1, &turn_offer(2, server.udp_addr(), "pw")).await);
        next(&mut events).await;
        let_assert!(
            DriverCommand::RelayCandidate {
                session_id,
                relayed,
                server: via,
                local,
                tcp,
                grant: _,
            } = next_command(&mut rx).await,
            "a relay candidate"
        );
        let allocation = turn.allocations().remove(0);
        assert_eq!(
            (session_id.as_str(), relayed, via, local, tcp),
            ("s1", allocation.relayed, server.udp_addr(), host, false)
        );
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0\r\na=mid:0\r\n".into(),
                talkback: None,
            },
        );
        assert_eq!(next(&mut events).await["type"], "answer");
        // The worker is done; end-of-candidates waits for its relay line.
        report(&s, "s1", end_of_candidates());
        let line = "candidate:1 1 udp 37748479 203.0.113.1 49153 typ relay raddr 0.0.0.0 rport 0";
        report(
            &s,
            "s1",
            Report::Relayed {
                relayed,
                candidate: Some(line.into()),
            },
        );
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "candidate", "candidate": line, "sdp_mid": "0", "sdp_mline_index": 0 })
        );
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "candidate", "candidate": "" })
        );
        // A peer the agent sends to from the relay: one channel, with its
        // permission, handed to the worker.
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        for _ in 0..2 {
            report(&s, "s1", Report::ChannelWanted { relayed, peer });
        }
        let_assert!(
            DriverCommand::RelayChannel {
                session_id,
                relayed: on,
                peer: to,
                channel,
            } = next_command(&mut rx).await,
            "a relay channel"
        );
        assert_eq!(
            (session_id.as_str(), on, to, channel),
            ("s1", relayed, peer, 0x4000)
        );
        let allocation = turn.allocations().remove(0);
        assert_eq!(allocation.channels, [(0x4000, peer)]);
        assert_eq!(allocation.permissions, [peer.ip()]);
        // A peer the server refuses is not bound, and the worker hears
        // nothing.
        turn.forbid("192.0.2.66".parse().unwrap());
        let forbidden = "192.0.2.66:1".parse().unwrap();
        report(
            &s,
            "s1",
            Report::ChannelWanted {
                relayed,
                peer: forbidden,
            },
        );
        for attempt in 0_u32.. {
            if turn.requests().last().is_some_and(|r| r.error == Some(403)) {
                break;
            }
            assert!(attempt < 500, "no refused channel binding");
            SystemClock.sleep(Duration::from_millis(10)).await;
        }
        // A binding whose driver queue is full is not handed over; the
        // worker asks again with its next datagram to the peer.
        let (full, _full) = mpsc::channel(1);
        full.try_send(DriverCommand::Candidate {
            session_id: "x".into(),
            candidate: String::new(),
        })
        .unwrap();
        s.shared.lock().connections.get_mut("c1").unwrap().commands = full;
        let late: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        report(
            &s,
            "s1",
            Report::ChannelWanted {
                relayed,
                peer: late,
            },
        );
        for attempt in 0_u32.. {
            if turn.allocations()[0]
                .channels
                .iter()
                .any(|(_, to)| *to == late)
            {
                break;
            }
            assert!(attempt < 500, "no second channel");
            SystemClock.sleep(Duration::from_millis(10)).await;
        }
        SystemClock.sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err(), "nothing reached the old queue");
        // The session's end releases its lease, the last: the allocation
        // is deleted.
        result(
            call_on(
                &s,
                1,
                &json!({ "id": 3, "type": "session/close", "session_id": "s1" }),
            )
            .await,
        );
        for attempt in 0_u32.. {
            if turn.allocations().is_empty() {
                break;
            }
            assert!(attempt < 500, "the allocation outlived its last session");
            SystemClock.sleep(Duration::from_millis(10)).await;
        }
        s.shutdown().await;
        demux.stop();
    }

    #[tokio::test]
    async fn a_refused_turn_credential_ends_the_relay_gather_without_a_candidate() {
        let dir = private_dir("relay-refused");
        let (turn, server) = turn_server().await;
        let (s, demux, _host) = with_turn(&blocking_worker(&dir));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut events =
            subscription(call_on(&s, 1, &turn_offer(2, server.udp_addr(), "wrong")).await);
        next(&mut events).await;
        report(
            &s,
            "s1",
            Report::Answer {
                sdp: "v=0".into(),
                talkback: None,
            },
        );
        assert_eq!(next(&mut events).await["type"], "answer");
        report(&s, "s1", end_of_candidates());
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "candidate", "candidate": "" })
        );
        assert!(turn.allocations().is_empty());
        s.shutdown().await;
        demux.stop();
    }

    /// A supervisor with a recording output, whose workers are `binary`.
    fn with_recordings(binary: &str, clock: Arc<dyn Clock>) -> Supervisor {
        let mut environment = environment(binary);
        environment.registries.recording = Some(Arc::new(
            lotse_core::test_util::FakeRecordingMuxerFactory::default(),
        ));
        Supervisor::new(session_settings(), environment, clock)
    }

    /// `recording/create` of `stream_id` as `recording_id` (generated when `None`).
    fn recording(id: u64, stream_id: &str, recording_id: Option<&str>) -> Value {
        let mut start = json!({ "id": id, "type": "recording/create", "stream_id": stream_id,
                                "prerecord_ms": 5_000, "duration_ms": 20_000 });
        if let Some(recording_id) = recording_id {
            start["recording_id"] = json!(recording_id);
        }
        start
    }

    /// A subscription's result and events.
    fn started(outcome: Outcome) -> (Value, mpsc::Receiver<Event>) {
        let_assert!(Outcome::SubscribedWith { result, events } = outcome);
        (result, events)
    }

    /// A recording's report, as the driver hands it on from the worker of `c1`.
    fn recording_report(s: &Supervisor, recording_id: &str, report: lotse_ipc::RecordingReport) {
        let at = s.shared.clock.wall_now();
        s.shared
            .lock()
            .recording_report("c1", recording_id, report, at);
    }

    fn closed_report(reason: &str, bytes: u64) -> lotse_ipc::RecordingReport {
        lotse_ipc::RecordingReport::Closed {
            reason: reason.into(),
            bytes,
            duration_ms: 20_000,
            gaps: 1,
        }
    }

    /// The commands `c1`'s driver would get from now on, on a queue of
    /// `capacity`.
    fn intercept(s: &Supervisor, capacity: usize) -> mpsc::Receiver<DriverCommand> {
        let (tx, rx) = mpsc::channel(capacity);
        s.shared.lock().connections.get_mut("c1").unwrap().commands = tx;
        rx
    }

    fn front_stats(s: &Supervisor) -> (u64, u64, u64, u64) {
        let counters = {
            let state = s.shared.lock();
            state.stream_stats(&state.streams["front"])
        };
        (
            counters.recordings_started,
            counters.recordings_completed,
            counters.recording_gaps,
            counters.recording_bytes,
        )
    }

    fn demand(s: &Supervisor) -> Demand {
        *s.shared.lock().connections["c1"].demand.borrow()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_configured_recording_limits_are_reported_and_enforced() {
        let mut settings = session_settings();
        settings.limits.recordings = RecordingLimits {
            max_prerecord_ms: 30_000,
            max_prerecord_bytes: 1 << 20,
            max_recording_ms: 45_000,
            max_recordings: 5,
            max_recordings_per_stream: 1,
            ..RecordingLimits::DEFAULT
        };
        let mut environment = environment("/bin/sh");
        environment.registries.recording = Some(Arc::new(
            lotse_core::test_util::FakeRecordingMuxerFactory::default(),
        ));
        let s = Supervisor::new(settings, environment, Arc::new(SystemClock));
        let info = result(call(&s, r#"{"id":1,"type":"info"}"#).await);
        assert_eq!(info["outputs"], json!(["recording"]));
        assert_eq!(s.hello().outputs, ["recording"]);
        assert_eq!(
            (
                &info["limits"]["max_prerecord_ms"],
                &info["limits"]["max_prerecord_bytes"],
                &info["limits"]["max_recording_ms"],
                &info["limits"]["max_recordings"],
                &info["limits"]["max_recordings_per_stream"],
            ),
            (
                &json!(30_000),
                &json!(1 << 20),
                &json!(45_000),
                &json!(5),
                &json!(1)
            )
        );
        let windowed = json!({ "id": 2, "type": "stream/put", "stream_id": "front",
                               "sources": [{ "url": "fake://127.0.0.1/" }], "prerecord_ms": 30_001 });
        let err = error(call(&s, &windowed.to_string()).await);
        assert_eq!(
            err.message,
            "`prerecord_ms` is 30001, the maximum is 30000 (`limits.max_prerecord_ms`)"
        );
    }

    #[tokio::test]
    async fn a_recording_reaches_the_worker_with_its_pipe_and_its_reports_reach_the_owner() {
        use tokio::io::AsyncReadExt as _;

        let dir = private_dir("recording-start");
        let s = with_recordings(&recording_worker(&dir), Arc::new(SystemClock));
        let info = result(call(&s, r#"{"id":1,"type":"info"}"#).await);
        assert_eq!(
            info["limits"],
            json!({ "max_streams": 2, "max_sessions": 3, "max_sessions_per_stream": 2,
                    "max_connections": 8, "session_grace_ms": 10_000,
                    "max_prerecord_ms": 300_000, "max_prerecord_bytes": 512 << 20, "max_recording_ms": 3_600_000,
                    "max_recordings": 8, "max_recordings_per_stream": 2 })
        );
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        assert_eq!(demand(&s).total(), 0);
        let (result, mut events) =
            started(call(&s, &recording(2, "front", Some("k1")).to_string()).await);
        assert_eq!(
            result,
            json!({ "recording_id": "k1", "url": "/v0/recording/k1" })
        );
        // A recording is a viewer: the idle stream connects for it.
        assert_eq!(demand(&s).viewers, 1);
        let pid = worker_pid(&s).await;
        // The start waits in the driver's queue while the worker spawns,
        // and that wait comes off its `duration_ms` (`driver::duration_left`):
        // on the real clock, a millisecond or more of the 20 s.
        let starts: Vec<Vec<u8>> = (19_000..=20_000)
            .map(|duration_ms| {
                let spec = RecordingSpec {
                    recording_id: "k1".into(),
                    prerecord_ms: 5_000,
                    duration_ms,
                    audio: true,
                };
                lotse_ipc::encode(&lotse_ipc::ToWorker::StartRecording(spec)).unwrap()
            })
            .collect();
        wait_received_any(&dir, pid, &starts).await;
        let front = result_of(&s, "front").await;
        assert_eq!(front["recordings"], json!(["k1"]));
        // The write end went to the worker, which discarded it with the
        // message: the read end the body gets is at its end.
        let mut body = s.recording_body(&RecordingId::new("k1").unwrap()).unwrap();
        let mut bytes = Vec::new();
        within(body.reader.read_to_end(&mut bytes)).await.unwrap();
        assert!(bytes.is_empty());
        recording_report(
            &s,
            "k1",
            lotse_ipc::RecordingReport::Started {
                prerecord_ms: 4_960,
                video: "h264".into(),
                picture: Some((640, 480)),
                audio: None,
            },
        );
        let event = next(&mut events).await;
        assert_eq!(
            (
                &event["type"],
                &event["prerecord_ms"],
                &event["video"]["width"]
            ),
            (&json!("started"), &json!(4_960), &json!(640))
        );
        recording_report(
            &s,
            "k1",
            lotse_ipc::RecordingReport::Gap {
                reason: "reconnect".into(),
                from_ms: 1_000,
                to_ms: 2_000,
            },
        );
        assert_eq!(next(&mut events).await["reason"], "reconnect");
        recording_report(&s, "k1", closed_report("completed", 4_096));
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "closed", "reason": "completed", "bytes": 4_096,
                    "duration_ms": 20_000, "gaps": 1 })
        );
        assert!(events.recv().await.is_none(), "closed is the last event");
        // The body learns what the worker wrote; the stream counts the recording.
        assert_eq!(within(&mut body.written).await, Ok(4_096));
        assert_eq!(front_stats(&s), (1, 1, 1, 4_096));
        assert_eq!(demand(&s).viewers, 0);
        let front = result_of(&s, "front").await;
        assert_eq!(front["recordings"], json!([]));
        assert_eq!(front["stats"]["recording_bytes"], 4_096);
        // A report for a recording that is gone is dropped.
        recording_report(&s, "k1", closed_report("completed", 1));
        assert_eq!(front_stats(&s), (1, 1, 1, 4_096));
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `stream/get` of `stream_id`.
    async fn result_of(s: &Supervisor, stream_id: &str) -> Value {
        let get = json!({ "id": 1, "type": "stream/get", "stream_id": stream_id });
        result(call(s, &get.to_string()).await)
    }

    #[tokio::test]
    async fn recording_start_holds_the_request_to_the_limits_and_the_stream_to_its_tracks() {
        let dir = private_dir("recording-limits");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        let captured = Captured::default();
        let _logs = captured.install();
        let refused = |outcome: Outcome| error(outcome);
        let err = refused(call(&s, &recording(1, "a/b", None).to_string()).await);
        assert_eq!(err.code, ErrorCode::InvalidStreamId);
        let err = refused(call(&s, &recording(1, "front", Some("a/b")).to_string()).await);
        assert_eq!(
            (err.code, &err.details["recording_id"]),
            (ErrorCode::InvalidRequest, &json!("a/b"))
        );
        // A dot segment matches the characters but is refused (RFC 3986
        // section 3.3), and the message says so.
        let err = refused(call(&s, &recording(1, "front", Some("..")).to_string()).await);
        assert_eq!(
            (err.code, err.message.as_str(), &err.details["recording_id"]),
            (
                ErrorCode::InvalidRequest,
                "recording_id must match ^[A-Za-z0-9._-]{1,128}$ and not be `.` or `..`",
                &json!("..")
            )
        );
        let mut far = recording(1, "front", None);
        far["prerecord_ms"] = json!(300_001);
        let err = refused(call(&s, &far.to_string()).await);
        assert_eq!(err.details["field"], "prerecord_ms");
        assert_eq!(
            err.message,
            "`prerecord_ms` is 300001, the maximum is 300000 (`limits.max_prerecord_ms`)"
        );
        let mut long = recording(1, "front", None);
        long["duration_ms"] = json!(3_600_001);
        let err = refused(call(&s, &long.to_string()).await);
        assert_eq!(err.details["field"], "duration_ms");
        // The longest window and the longest recording are allowed, 5 minutes
        // before and an hour after, the most a client's record call asks:
        // what refuses this one is the stream.
        let mut longest = recording(1, "front", None);
        longest["prerecord_ms"] = json!(300_000);
        longest["duration_ms"] = json!(3_600_000);
        let err = refused(call(&s, &longest.to_string()).await);
        assert_eq!(err.code, ErrorCode::StreamNotFound);
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        result(call(&s, &put("back", "fake://127.0.0.1:2/", false)).await);
        // A recording whose id is generated.
        let (generated, _g) = started(call(&s, &recording(2, "front", None).to_string()).await);
        let id = generated["recording_id"].as_str().unwrap();
        assert_eq!(id.len(), 26, "a ULID");
        assert_eq!(generated["url"], format!("/v0/recording/{id}"));
        assert_eq!(s.shared.lock().recordings[id].stream_id, "front");
        let (_k1, _e1) = started(call(&s, &recording(3, "front", Some("k1")).to_string()).await);
        let err = refused(call(&s, &recording(4, "back", Some("k1")).to_string()).await);
        assert_eq!(err.code, ErrorCode::RecordingIdInUse);
        let err = refused(call(&s, &recording(4, "front", Some("k2")).to_string()).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("max_recordings_per_stream"))
        );
        s.shared.lock().recording_limits.max_recordings = 3;
        let (_k3, _e3) = started(call(&s, &recording(5, "back", Some("k3")).to_string()).await);
        let err = refused(call(&s, &recording(6, "back", Some("k4")).to_string()).await);
        assert_eq!(err.details["limit"], "max_recordings");
        assert_eq!(captured.lines("recording/create refused").len(), 9);
        assert_eq!(s.shared.lock().recordings_held(), 3);
        assert_eq!(
            captured
                .lines("recording opened; handed to the connection")
                .len(),
            3
        );
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_stream_without_video_or_a_busy_connection_takes_no_recording() {
        let dir = private_dir("recording-refused");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        let refused = |outcome: Outcome| error(outcome);
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        // A stream whose source declared no video records none.
        let mut audio = lotse_ipc::TrackInfo {
            id: "a0".into(),
            kind: "audio".into(),
            codec: "opus".into(),
            sync: "arrival".into(),
            derived_from: None,
            audio_delay_ms: None,
            params: lotse_ipc::TrackParams::default(),
        };
        // A live source's tracks without video refuse the recording.
        {
            let mut state = s.shared.lock();
            let snapshot = &mut state.connections.get_mut("c1").unwrap().snapshot;
            snapshot.tracks = vec![audio.clone()];
            snapshot.state = ConnectionState::Live;
            drop(state);
        }
        let err = refused(call(&s, &recording(7, "front", Some("k4")).to_string()).await);
        assert_eq!(err.code, ErrorCode::NoVideoTrack);
        audio.kind = "video".into();
        s.shared
            .lock()
            .connections
            .get_mut("c1")
            .unwrap()
            .snapshot
            .tracks = vec![audio];
        // A busy connection takes neither the start nor its stop.
        let full = {
            let (tx, rx) = mpsc::channel(1);
            tx.try_send(DriverCommand::StopRecording {
                recording_id: "x".into(),
            })
            .unwrap();
            s.shared.lock().connections.get_mut("c1").unwrap().commands = tx;
            rx
        };
        let err = refused(call(&s, &recording(8, "front", Some("k4")).to_string()).await);
        assert_eq!(err.details["limit"], "connection_queue");
        let (tx, mut one_free) = mpsc::channel(2);
        tx.try_send(DriverCommand::StopRecording {
            recording_id: "x".into(),
        })
        .unwrap();
        s.shared.lock().connections.get_mut("c1").unwrap().commands = tx;
        let err = refused(call(&s, &recording(9, "front", Some("k4")).to_string()).await);
        assert_eq!(err.details["limit"], "connection_queue");
        assert!(matches!(
            one_free.try_recv(),
            Ok(DriverCommand::StopRecording { .. })
        ));
        assert!(one_free.try_recv().is_err(), "the start is not handed on");
        assert!(!s.shared.lock().recordings.contains_key("k4"));
        drop(full);
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A source's tracks refuse a recording `no_video_track` only while it is
    /// live: the tracks a connection keeps from the last time it went live
    /// may be another source's after a `stream/put` switched it in place
    /// while idle, and the worker ends a recording without video itself.
    /// Regression: an audio-only source switched while idle to a video one
    /// refused every `recording/create`, and with `preload: false` none raised
    /// the demand that would declare the video.
    #[tokio::test]
    async fn only_the_tracks_of_a_live_source_refuse_a_recording_no_video_track() {
        let dir = private_dir("recording-stale-tracks");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        let captured = Captured::default();
        let _logs = captured.install();
        result(call(&s, &put("front", "fake://127.0.0.1:1/a", false)).await);
        result(call(&s, &put("front", "fake://127.0.0.1:1/b", false)).await);
        assert_eq!(
            captured
                .lines("the connection switches to the new source in place")
                .len(),
            1
        );
        let audio = lotse_ipc::TrackInfo {
            id: "a0".into(),
            kind: "audio".into(),
            codec: "opus".into(),
            sync: "arrival".into(),
            derived_from: None,
            audio_delay_ms: None,
            params: lotse_ipc::TrackParams::default(),
        };
        // Held throughout, so the driver publishes nothing in between.
        {
            let mut state = s.shared.lock();
            let limits = state.recording_limits;
            // The first source's, from when it was live.
            state.connections.get_mut("c1").unwrap().snapshot.tracks = vec![audio];
            for idle in [
                ConnectionState::Idle,
                ConnectionState::Connecting,
                ConnectionState::Backoff,
            ] {
                state.connections.get_mut("c1").unwrap().snapshot.state = idle;
                assert!(
                    check_recording_stream(&state, "front", "c1", limits).is_ok(),
                    "{idle:?}"
                );
            }
            state.connections.get_mut("c1").unwrap().snapshot.state = ConnectionState::Live;
            let err = check_recording_stream(&state, "front", "c1", limits).unwrap_err();
            drop(state);
            assert_eq!(err.code, ErrorCode::NoVideoTrack);
        }
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_recording_not_fetched_in_time_is_stopped_not_fetched_and_a_fetched_one_runs_on() {
        let dir = private_dir("recording-fetch");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_recordings(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut commands = intercept(&s, 16);
        let (_r1, mut k1) = started(call(&s, &recording(1, "front", Some("k1")).to_string()).await);
        let (_r2, mut k2) = started(call(&s, &recording(2, "front", Some("k2")).to_string()).await);
        for id in ["k1", "k2"] {
            let_assert!(Some(DriverCommand::StartRecording { spec, .. }) = commands.recv().await);
            assert_eq!(spec.recording_id, id);
        }
        let k2_id = RecordingId::new("k2").unwrap();
        let _body = s.recording_body(&k2_id).unwrap();
        // A deadline that fired as the body was taken, or for a recording that
        // is gone, does nothing.
        let serial = s.shared.lock().recordings["k2"].serial;
        s.shared.lock().recording_fetch_deadline("k2", serial);
        s.shared.lock().recording_fetch_deadline("gone", serial);
        assert_eq!(
            s.recording_body(&k2_id).unwrap_err(),
            RecordingBodyError::AlreadyFetched
        );
        clock.advance(Duration::from_millis(9_999));
        settle().await;
        assert!(commands.try_recv().is_err());
        clock.advance(Duration::from_millis(1));
        settle().await;
        let_assert!(Some(DriverCommand::StopRecording { recording_id }) = commands.recv().await);
        assert_eq!(recording_id, "k1");
        assert!(commands.try_recv().is_err(), "k2 was fetched");
        // A late fetch still gets the body of a recording being stopped.
        let k1_id = RecordingId::new("k1").unwrap();
        drop(s.recording_body(&k1_id).unwrap());
        recording_report(&s, "k1", closed_report(lotse_ipc::STOPPED_AS_ASKED, 10));
        assert_eq!(next(&mut k1).await["reason"], "not_fetched");
        assert_eq!(front_stats(&s).1, 0, "not a whole file");
        recording_report(&s, "k2", closed_report("completed", 10));
        assert_eq!(next(&mut k2).await["reason"], "completed");
        // A recording that ends before anyone fetched it keeps its body until
        // the deadline; one not taken by then goes.
        let (_r3, _k3) = started(call(&s, &recording(3, "front", Some("k3")).to_string()).await);
        let (_r4, _k4) = started(call(&s, &recording(4, "front", Some("k4")).to_string()).await);
        for id in ["k3", "k4"] {
            recording_report(&s, id, closed_report("completed", 0));
        }
        assert!(s.shared.lock().recording_id_in_use("k3"));
        let err = error(call(&s, &recording(5, "front", Some("k3")).to_string()).await);
        assert_eq!(err.code, ErrorCode::RecordingIdInUse);
        assert!(s.recording_body(&RecordingId::new("k3").unwrap()).is_ok());
        assert_eq!(
            s.recording_body(&RecordingId::new("k3").unwrap())
                .unwrap_err(),
            RecordingBodyError::NotFound
        );
        clock.advance(Duration::from_secs(10));
        settle().await;
        assert!(!s.shared.lock().recording_id_in_use("k4"));
        assert_eq!(
            s.recording_body(&RecordingId::new("k4").unwrap())
                .unwrap_err(),
            RecordingBodyError::NotFound
        );
        // A full pipe: nobody read the body, so the stop could not write
        // the file's last bytes in time and the worker ends it
        // `client_gone`, the tail counted in its bytes; the recording still
        // ends `not_fetched`, a file not whole.
        let (_r8, mut k8) = started(call(&s, &recording(8, "front", Some("k8")).to_string()).await);
        let before = front_stats(&s);
        clock.advance(Duration::from_secs(10));
        settle().await;
        recording_report(&s, "k8", closed_report("client_gone", 70_000));
        let end = next(&mut k8).await;
        assert_eq!(
            (&end["reason"], &end["bytes"]),
            (&json!("not_fetched"), &json!(70_000))
        );
        let after = front_stats(&s);
        assert_eq!(after.1, before.1, "not a whole file");
        assert_eq!(after.3, before.3 + 70_000, "the tail counted");
        assert!(!s.shared.lock().recording_id_in_use("k8"), "no body kept");
        // A recording whose deadline passed while it was being stopped keeps
        // no body.
        let (_r6, _k6) = started(call(&s, &recording(6, "front", Some("k6")).to_string()).await);
        assert!(s.unsubscribed(ConnectionId(1), 6).is_none());
        clock.advance(Duration::from_secs(10));
        settle().await;
        recording_report(&s, "k6", closed_report(lotse_ipc::STOPPED_AS_ASKED, 0));
        assert!(!s.shared.lock().recording_id_in_use("k6"));
        shutdown_on(&s, &clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `unsubscribe` stops a recording once (`session_closed`, as it closes a
    /// session), its end going nowhere, and a closed control connection
    /// ends its own recordings alike; a recording that ran its length is a whole
    /// file.
    #[tokio::test]
    async fn unsubscribe_stops_a_recording_once_and_a_closed_connection_ends_its_own_session_closed()
     {
        let dir = private_dir("recording-stop");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        let captured = Captured::default();
        let _logs = captured.install();
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut commands = intercept(&s, 16);
        let (_r1, mut k1) = started(call_on(&s, 1, &recording(1, "front", Some("k1"))).await);
        let (_r2, mut k2) = started(call_on(&s, 1, &recording(2, "front", Some("k2"))).await);
        let mut drained = Vec::new();
        while let Ok(command) = commands.try_recv() {
            drained.push(command);
        }
        assert_eq!(drained.len(), 2);
        // Another connection's subscription 1 is not k1's.
        assert!(s.unsubscribed(ConnectionId(2), 1).is_none());
        assert!(commands.try_recv().is_err(), "another connection's id 1");
        assert!(s.unsubscribed(ConnectionId(1), 1).is_none());
        let_assert!(Some(DriverCommand::StopRecording { recording_id }) = commands.recv().await);
        assert_eq!(recording_id, "k1");
        // A second stop of a recording being stopped, or of one not open, asks
        // nothing more.
        s.shared
            .lock()
            .stop_recording("k1", RecordingCloseReason::NotFetched);
        s.shared
            .lock()
            .stop_recording("nope", RecordingCloseReason::NotFetched);
        assert!(commands.try_recv().is_err(), "one stop");
        let asked = captured.lines("recording stop asked of its worker");
        assert!(asked[0].contains("reason=\"session_closed\""), "{asked:?}");
        let again = captured.lines("recording already being stopped");
        assert!(again[0].contains("ending=\"session_closed\""), "{again:?}");
        assert_eq!(
            captured.lines("stop of a recording that is not open").len(),
            1
        );
        recording_report(&s, "k1", closed_report(lotse_ipc::STOPPED_AS_ASKED, 5));
        assert!(k1.recv().await.is_none(), "its end goes nowhere");
        assert_eq!(
            front_stats(&s).1,
            0,
            "a recording stopped early is no whole file"
        );
        // A recording that ran its length is.
        recording_report(&s, "k2", closed_report("completed", 5));
        assert_eq!(next(&mut k2).await["reason"], "completed");
        assert_eq!(front_stats(&s).1, 1);
        // A closed control connection ends its recordings at once, and only its.
        let (_r3, mut k3) = started(call_on(&s, 1, &recording(4, "front", Some("k3"))).await);
        let (_r4, mut k4) = started(call_on(&s, 2, &recording(5, "front", Some("k4"))).await);
        let _starts = (commands.recv().await, commands.recv().await);
        s.connection_closed(ConnectionId(1));
        let_assert!(Some(DriverCommand::StopRecording { recording_id }) = commands.recv().await);
        assert_eq!(recording_id, "k3");
        assert!(commands.try_recv().is_err());
        recording_report(&s, "k3", closed_report(lotse_ipc::STOPPED_AS_ASKED, 5));
        assert!(k3.recv().await.is_none());
        let lines = captured.lines("recording: closed");
        assert!(lines[0].contains("reason=\"session_closed\""), "{lines:?}");
        assert!(lines[2].contains("reason=\"session_closed\""), "{lines:?}");
        assert!(s.shared.lock().recordings.contains_key("k4"));
        assert!(k4.try_recv().is_err());
        assert_eq!(front_stats(&s), (4, 1, 3, 15));
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_moved_or_deleted_stream_and_shutdown_end_its_recordings_and_cut_their_bodies() {
        let dir = private_dir("recording-end");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        result(call(&s, &put("back", "fake://127.0.0.1:2/", false)).await);
        let (_r1, mut k1) = started(call(&s, &recording(1, "front", Some("k1")).to_string()).await);
        let (_r9, _k9) = started(call(&s, &recording(9, "back", Some("k9")).to_string()).await);
        let mut body = s.recording_body(&RecordingId::new("k1").unwrap()).unwrap();
        recording_report(
            &s,
            "k1",
            lotse_ipc::RecordingReport::Gap {
                reason: "lagged".into(),
                from_ms: 0,
                to_ms: 1,
            },
        );
        next(&mut k1).await;
        // Another port is another worker: the recording ends with the old one.
        result(call(&s, &put("front", "fake://127.0.0.1:3/", false)).await);
        assert_eq!(
            next(&mut k1).await,
            json!({ "type": "closed", "reason": "stream_changed", "bytes": 0,
                    "duration_ms": 0, "gaps": 1 })
        );
        assert!(within(&mut body.written).await.is_err(), "the body is cut");
        assert_eq!(front_stats(&s), (1, 0, 1, 0), "kept over the put");
        // Its old worker stops with its connection: the id is free at once.
        assert!(!s.shared.lock().recording_id_in_use("k1"));
        // Another stream's recording, on another connection, runs on.
        assert!(s.shared.lock().recordings.contains_key("k9"));
        let (_r2, mut k2) = started(call(&s, &recording(2, "front", Some("k2")).to_string()).await);
        result(call(&s, r#"{"id":3,"type":"stream/delete","stream_id":"front"}"#).await);
        assert_eq!(next(&mut k2).await["reason"], "stream_deleted");
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let (_r4, mut k4) = started(call(&s, &recording(4, "front", Some("k4")).to_string()).await);
        s.shutdown().await;
        assert_eq!(next(&mut k4).await["reason"], "shutting_down");
        assert!(k4.recv().await.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_worker_exit_ends_its_recordings_worker_crashed() {
        // `/bin/sh worker ...` exits at once.
        let s = with_recordings("/bin/sh", Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let (_r, mut events) =
            started(call(&s, &recording(2, "front", Some("k1")).to_string()).await);
        let closed = next(&mut events).await;
        assert_eq!(
            (&closed["type"], &closed["reason"]),
            (&json!("closed"), &json!("worker_crashed"))
        );
        assert!(s.shared.lock().recordings.is_empty());
        s.shutdown().await;
    }

    #[tokio::test]
    async fn a_worker_s_report_on_another_connection_s_recording_is_ignored_and_a_malformed_one_ends_it()
     {
        let dir = private_dir("recording-report");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut commands = intercept(&s, 4);
        let (_r, mut events) =
            started(call(&s, &recording(1, "front", Some("k1")).to_string()).await);
        let _start = commands.recv().await;
        let captured = Captured::default();
        let _logs = captured.install();
        let gap = |reason: &str| lotse_ipc::RecordingReport::Gap {
            reason: reason.into(),
            from_ms: 0,
            to_ms: 1,
        };
        let at = s.shared.clock.wall_now();
        s.shared
            .lock()
            .recording_report("c9", "k1", gap("lagged"), at);
        // An unknown warning is dropped, the recording goes on.
        let warning = lotse_ipc::RecordingReport::Warning {
            code: "bogus".into(),
            message: String::new(),
        };
        recording_report(&s, "k1", warning);
        assert!(s.shared.lock().recordings.contains_key("k1"));
        assert_eq!(
            captured
                .lines("a worker reported a recording it does not run; ignored")
                .len(),
            1
        );
        assert!(events.try_recv().is_err());
        recording_report(&s, "k1", gap("solar\nflare"));
        let lines =
            captured.lines("a worker reported a malformed recording report; recording ended");
        assert!(
            lines[0].contains("gap names an unknown reason"),
            "{lines:?}"
        );
        assert_eq!(next(&mut events).await["reason"], "internal_error");
        let_assert!(Ok(DriverCommand::StopRecording { recording_id }) = commands.try_recv());
        assert_eq!(recording_id, "k1");
        assert!(s.shared.lock().recordings.is_empty());
        // Ending a recording that is gone changes nothing.
        s.shared.lock().end_recording(
            "k1",
            crate::recording::RecordingEnd::Now(RecordingCloseReason::SessionClosed),
        );
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_window_is_no_demand_and_a_put_that_changes_only_it_tells_the_running_worker() {
        let dir = private_dir("recording-window");
        let s = with_recordings(&recording_worker(&dir), Arc::new(SystemClock));
        let windowed = |prerecord_ms: u32, preload: bool| {
            json!({ "id": 1, "type": "stream/put", "stream_id": "front",
                    "sources": [{ "url": "fake://127.0.0.1:1/" }],
                    "preload": preload, "prerecord_ms": prerecord_ms })
            .to_string()
        };
        result(call(&s, &windowed(30_000, false)).await);
        assert_eq!(demand(&s).total(), 0, "a window is not demand");
        assert_eq!(s.shared.lock().connections["c1"].prerecord_ms, 30_000);
        assert_eq!(result_of(&s, "front").await["prerecord_ms"], 30_000);
        let err = error(call(&s, &windowed(300_001, false)).await);
        assert_eq!(err.details["field"], "prerecord_ms");
        let unchanged = result(call(&s, &windowed(30_000, false)).await);
        assert_eq!(unchanged["created"], false);
        result(call(&s, &windowed(30_000, true)).await);
        let pid = worker_pid(&s).await;
        // Only the window changes: the running worker is told, nothing
        // reconnects.
        let captured = Captured::default();
        let _logs = captured.install();
        result(call(&s, &windowed(10_000, true)).await);
        wait_received(
            &dir,
            pid,
            &lotse_ipc::encode(&lotse_ipc::ToWorker::Prerecord { ms: 10_000 }).unwrap(),
        )
        .await;
        assert_eq!(worker_pid(&s).await, pid);
        assert_eq!(front_connection(&s).await, "c1");
        let lines = captured.lines("connection pre-record window changed");
        assert!(
            lines[0].contains("prerecord.before_ms=30000")
                && lines[0].contains("prerecord.after_ms=10000"),
            "{lines:?}"
        );
        // A full driver queue keeps the window until the next put.
        let (full, _rx) = mpsc::channel(1);
        full.try_send(DriverCommand::StopRecording {
            recording_id: "x".into(),
        })
        .unwrap();
        s.shared.lock().connections.get_mut("c1").unwrap().commands = full;
        result(call(&s, &windowed(0, true)).await);
        assert_eq!(s.shared.lock().connections["c1"].prerecord_ms, 10_000);
        assert_eq!(
            captured
                .lines("driver queue full; the connection keeps its pre-record window")
                .len(),
            1
        );
        // The same put again, with room in the queue, passes the window on
        // although the stream has it already; once there, a repeat sends
        // nothing.
        let mut commands = intercept(&s, 4);
        let unchanged = result(call(&s, &windowed(0, true)).await);
        assert_eq!(unchanged["created"], false);
        let_assert!(Ok(DriverCommand::Prerecord { ms: 0 }) = commands.try_recv());
        assert_eq!(s.shared.lock().connections["c1"].prerecord_ms, 0);
        result(call(&s, &windowed(0, true)).await);
        assert!(commands.try_recv().is_err());
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn gap_report(reason: &str) -> lotse_ipc::RecordingReport {
        lotse_ipc::RecordingReport::Gap {
            reason: reason.into(),
            from_ms: 0,
            to_ms: 1,
        }
    }

    /// A worker runs one recording per id and drops a second start under an id
    /// it runs, and its reports name the recording by id alone: a recording the
    /// supervisor ended while its worker still runs it keeps its id until
    /// that worker's `Closed`, or a new recording under it would be dropped by
    /// the worker and end with the old one's figures.
    #[tokio::test]
    async fn a_recording_ended_while_its_worker_runs_it_holds_its_id_until_the_worker_stopped_it() {
        let dir = private_dir("recording-reuse");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut commands = intercept(&s, 8);
        let (_r1, mut k1) = started(call(&s, &recording(1, "front", Some("k1")).to_string()).await);
        let_assert!(Some(DriverCommand::StartRecording { serial, .. }) = commands.recv().await);
        let captured = Captured::default();
        let _logs = captured.install();
        // A malformed report ends it here; its worker is told to stop it.
        recording_report(&s, "k1", gap_report("solar\nflare"));
        assert_eq!(next(&mut k1).await["reason"], "internal_error");
        let_assert!(Ok(DriverCommand::StopRecording { recording_id }) = commands.try_recv());
        assert_eq!(recording_id, "k1");
        assert!(s.shared.lock().recordings.is_empty());
        let held = captured.lines("recording ended while its worker may still run it");
        assert_eq!(held.len(), 1, "{held:?}");
        // Until the worker stopped it, the id is taken and the recording counts.
        let err = error(call(&s, &recording(2, "front", Some("k1")).to_string()).await);
        assert_eq!(err.code, ErrorCode::RecordingIdInUse);
        s.shared.lock().recording_limits.max_recordings = 1;
        let err = error(call(&s, &recording(3, "front", Some("k2")).to_string()).await);
        assert_eq!(err.details["limit"], "max_recordings");
        s.shared.lock().recording_limits.max_recordings = 8;
        // Another worker's `Closed`, or a report that is not one, frees
        // nothing.
        let at = s.shared.clock.wall_now();
        s.shared.lock().recording_report(
            "c9",
            "k1",
            closed_report(lotse_ipc::STOPPED_AS_ASKED, 7),
            at,
        );
        recording_report(&s, "k1", gap_report("lagged"));
        assert!(s.shared.lock().recording_id_in_use("k1"));
        // Its worker's `Closed` frees it, and goes to no one.
        let stats = front_stats(&s);
        recording_report(&s, "k1", closed_report(lotse_ipc::STOPPED_AS_ASKED, 7));
        assert!(!s.shared.lock().recording_id_in_use("k1"));
        assert_eq!(
            front_stats(&s),
            stats,
            "the recording was counted as it ended"
        );
        assert_eq!(
            captured
                .lines("the worker finished a recording that had ended; its id is free")
                .len(),
            1
        );
        let (_r4, _k1) = started(call(&s, &recording(4, "front", Some("k1")).to_string()).await);
        let_assert!(
            Some(DriverCommand::StartRecording { serial: again, .. }) = commands.recv().await
        );
        assert!(again > serial);
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A held id is free once nothing can report on it: its worker exited,
    /// or its connection was released, which stops the worker. A recording whose
    /// worker is gone holds none.
    #[tokio::test]
    async fn a_held_recording_id_is_free_once_its_worker_or_its_connection_is_gone() {
        let dir = private_dir("recording-held");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        result(call(&s, &put("back", "fake://127.0.0.1:2/", false)).await);
        let mut commands = intercept(&s, 8);
        let (_r1, _k1) = started(call(&s, &recording(1, "front", Some("k1")).to_string()).await);
        let (_r2, _k2) = started(call(&s, &recording(2, "back", Some("k2")).to_string()).await);
        let at = s.shared.clock.wall_now();
        recording_report(&s, "k1", gap_report("bogus"));
        s.shared
            .lock()
            .recording_report("c2", "k2", gap_report("bogus"), at);
        assert!(
            s.shared.lock().recording_id_in_use("k1") && s.shared.lock().recording_id_in_use("k2")
        );
        let captured = Captured::default();
        let _logs = captured.install();
        // `c1`'s worker exited: k1 is free, `c2`'s k2 is not.
        s.shared.lock().recordings_worker_gone("c1");
        assert!(!s.shared.lock().recording_id_in_use("k1"));
        assert!(s.shared.lock().recording_id_in_use("k2"));
        // Deleting `back` releases `c2`, whose worker stops with it.
        result(call(&s, r#"{"id":3,"type":"stream/delete","stream_id":"back"}"#).await);
        assert!(!s.shared.lock().recording_id_in_use("k2"));
        let freed =
            captured.lines("the worker of a recording that had ended is gone; its id is free");
        assert_eq!(freed.len(), 2, "{freed:?}");
        // A recording whose worker exited holds no id and asks it nothing.
        let (_r4, _k4) = started(call(&s, &recording(4, "front", Some("k4")).to_string()).await);
        while commands.try_recv().is_ok() {}
        s.shared.lock().end_recording(
            "k4",
            crate::recording::RecordingEnd::Now(RecordingCloseReason::WorkerCrashed),
        );
        assert!(!s.shared.lock().recording_id_in_use("k4"));
        assert!(
            commands.try_recv().is_err(),
            "no stop for a worker that is gone"
        );
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Each body that waits for its `GET` holds the read end of its pipe
    /// until the fetch deadline: `max_recordings` counts it, or short recordings that
    /// nobody fetches would pile up descriptors without bound.
    #[tokio::test]
    async fn a_body_that_waits_for_its_get_counts_toward_max_recordings() {
        let dir = private_dir("recording-held-bodies");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let _commands = intercept(&s, 8);
        s.shared.lock().recording_limits.max_recordings = 1;
        let (_r1, mut k1) = started(call(&s, &recording(1, "front", Some("k1")).to_string()).await);
        recording_report(&s, "k1", closed_report("completed", 0));
        assert_eq!(next(&mut k1).await["reason"], "completed");
        assert!(s.shared.lock().recordings.is_empty());
        let err = error(call(&s, &recording(2, "front", Some("k2")).to_string()).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("max_recordings"))
        );
        // Fetched, it holds nothing here any more.
        drop(s.recording_body(&RecordingId::new("k1").unwrap()).unwrap());
        let (_r3, _k2) = started(call(&s, &recording(3, "front", Some("k2")).to_string()).await);
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A `Closed` naming a reason the worker may not give is a malformed
    /// report: its figures are not believed, so `closed` says 0 bytes and
    /// the body is cut (`RecordingEvent::Closed`); the worker, which ended the
    /// recording with it, is asked nothing and holds no id.
    #[tokio::test]
    async fn a_closed_with_a_reason_the_worker_may_not_give_cuts_the_body_and_says_nothing_written()
    {
        let dir = private_dir("recording-bad-stop");
        let s = with_recordings(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut commands = intercept(&s, 8);
        let (_r1, mut k1) = started(call(&s, &recording(1, "front", Some("k1")).to_string()).await);
        let _start = commands.recv().await;
        let mut body = s.recording_body(&RecordingId::new("k1").unwrap()).unwrap();
        let captured = Captured::default();
        let _logs = captured.install();
        recording_report(&s, "k1", closed_report("worker_crashed", 4_096));
        assert_eq!(
            next(&mut k1).await,
            json!({ "type": "closed", "reason": "internal_error", "bytes": 0,
                    "duration_ms": 0, "gaps": 0 })
        );
        assert!(within(&mut body.written).await.is_err(), "the body is cut");
        assert_eq!(front_stats(&s), (1, 0, 0, 0));
        let lines =
            captured.lines("a worker reported a malformed recording report; recording ended");
        assert!(
            lines[0].contains("closed names a reason the worker may not give"),
            "{lines:?}"
        );
        assert!(
            commands.try_recv().is_err(),
            "no stop for a recording that ended"
        );
        assert!(!s.shared.lock().recording_id_in_use("k1"));
        s.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }
}
