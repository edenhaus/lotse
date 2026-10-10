//! The supervisor's side of the control API: the [`Handler`] the server
//! calls. It validates commands, keeps desired state in the registry,
//! starts a driver per source connection, opens viewer sessions on the
//! stream's connection and converts core state into the API's DTOs.
//!
//! A session belongs to the control connection that opened it; when that
//! connection goes, the session is orphaned for `limits.session_grace` and
//! a `session/adopt` may take it back.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lotse_api::{ConnectionId, Event, Handler, Outcome};
use lotse_api_types::API_VERSION;
use lotse_api_types::command::{Command, StreamPut, WebrtcCandidate, WebrtcOffer};
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::frame::{Hello, HelloTag};
use lotse_api_types::info::{
    BuildInfo, Codecs, DemuxMetrics, InfoResult, Limits, Metrics, ProcessMetrics, SandboxInfo,
    SupervisorMetrics,
};
use lotse_api_types::session::{SessionEvent, SessionList};
use lotse_api_types::stream::{AudioMode, BackchannelReleaseResult, StreamList, StreamPutResult};
use lotse_core::clock::Clock;
use lotse_core::codec::CodecFamily;
use lotse_core::connection::ConnectionConfig;
use lotse_core::id::StreamId;
use lotse_core::registry::Registries;
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_ipc::SessionSpec;
use tokio::sync::{mpsc, watch};
use tokio_util::task::TaskTracker;
use tracing::Instrument as _;

use crate::connect::ConnectPermits;
use crate::driver::{COMMAND_QUEUE, Driver, DriverCommand, DriverSpec};
use crate::gather::{GATHER_DEADLINE, IcePlan, StunServer, TurnServer};
use crate::memory::{Memory, MemoryProbe};
use crate::net::demux::{DemuxStats, Registrations};
use crate::net::stun_client::StunClient;
use crate::net::turn_client::TurnClient;
use crate::registry::{
    CloseBy, ConnectionEntry, ConnectionKey, ConnectionSnapshot, Shared, State, StreamEntry,
    StreamSource, Talker,
};
use crate::session::{
    MAX_EARLY_CANDIDATES, MAX_REMOTE_CANDIDATES, SESSION_QUEUE, SOURCE_NOT_LIVE_AFTER,
    SessionEntry, api_event, ice_credentials, ulid,
};
use crate::worker::{WorkerConfig, WorkerManager};
use crate::{Settings, millis};

/// The output kind that opens WebRTC sessions.
const WEBRTC: &str = "webrtc";

/// What `hello` and `info` always announce beyond the outputs.
const FEATURES: [&str; 1] = ["session_adopt"];

/// The feature of two-way audio, announced only while it works end to end
/// ([`Supervisor::features`]).
const TWO_WAY_AUDIO: &str = "two_way_audio";

/// The video codec families the daemon carries.
const VIDEO_CODECS: [CodecFamily; 3] = [CodecFamily::H264, CodecFamily::H265, CodecFamily::Mjpeg];

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
    /// The parsed URL.
    url: SourceUrl,
    /// The URL as given, credentials included, for the worker.
    raw: String,
    /// The options as given.
    options: serde_json::Map<String, serde_json::Value>,
    /// What the connection is keyed by: the URL, credentials included, and
    /// the source's normalized connection options.
    key: ConnectionKey,
    /// The options as the source reports them, secrets redacted.
    described: serde_json::Value,
    /// The protocol name.
    protocol: &'static str,
    /// The scheme's default port.
    default_port: Option<u16>,
    /// The worker needs a loopback relay listener bound before its sandbox
    /// ([`SourceFactory::loopback_relay`](lotse_core::source::SourceFactory::loopback_relay)).
    loopback_relay: bool,
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

    /// Closes every session with `shutting_down`; the first step of the
    /// shutdown, before the control connections say goodbye.
    pub fn close_sessions(&self) {
        self.shared.lock().close_sessions_where(
            |_| true,
            "shutting_down",
            "the daemon is shutting down",
            CloseBy::Supervisor,
        );
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

    /// The output kinds compiled in.
    fn outputs(&self) -> Vec<String> {
        self.registries
            .outputs
            .kinds()
            .into_iter()
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

    /// Checks a source's URL, scheme and options with the scheme's factory.
    fn validate_source(
        &self,
        source: &lotse_api_types::stream::SourceSpec,
    ) -> Result<ValidatedSource, ApiError> {
        let url = SourceUrl::parse(&source.url).map_err(|err| {
            ApiError::new(ErrorCode::InvalidRequest, format!("source url: {err}"))
        })?;
        let factory = self.registries.sources.get(url.scheme()).ok_or_else(|| {
            ApiError::new(
                ErrorCode::SchemeUnsupported,
                format!("no source handles {:?} urls", url.scheme()),
            )
            .with_detail("scheme", url.scheme())
        })?;
        let options = serde_json::Value::Object(source.options.clone());
        let built = factory
            .validate(&url, &options)
            .map_err(|err| ApiError::new(ErrorCode::InvalidRequest, err.to_string()))?;
        let described = built.describe();
        let default_port = factory.default_port(url.scheme());
        let loopback_relay = factory.loopback_relay(url.scheme());
        Ok(ValidatedSource {
            key: ConnectionKey {
                url: url.clone(),
                options: built.connection_options(),
            },
            url,
            raw: source.url.clone(),
            options: source.options.clone(),
            described: described.options,
            protocol: described.protocol,
            default_port,
            loopback_relay,
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
    /// that stay.
    fn stream_put(&self, put: StreamPut) -> Outcome {
        let stream_id = match StreamId::new(&put.stream_id) {
            Ok(id) => id,
            Err(err) => {
                return Outcome::Error(
                    ApiError::new(ErrorCode::InvalidStreamId, err.to_string())
                        .with_detail("stream_id", put.stream_id),
                );
            }
        };
        if put.sources.is_empty() {
            return Outcome::Error(ApiError::new(
                ErrorCode::InvalidRequest,
                "sources must name at least one source",
            ));
        }
        let mut validated = Vec::with_capacity(put.sources.len());
        for source in &put.sources {
            match self.validate_source(source) {
                Ok(source) => validated.push(source),
                Err(error) => return Outcome::Error(error),
            }
        }

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
        if existing.is_some_and(|entry| unchanged(entry, &put, &validated)) {
            tracing::debug!(stream.id = %stream_id, "stream/put: unchanged");
            return Outcome::Result(
                serde_json::to_value(StreamPutResult { created: false }).unwrap_or_default(),
            );
        }
        if let Some(error) = source_in_use(&state, stream_id.as_str(), &validated) {
            return Outcome::Error(error);
        }
        let reoriented = existing.is_some_and(|entry| entry.orientation != put.orientation);
        let previous: Vec<String> = existing.map_or_else(Vec::new, |entry| {
            entry.sources.iter().map(|s| s.connection.clone()).collect()
        });

        let sources = self.bind_sources(&mut state, &stream_id, &previous, validated);
        let connections: Vec<String> = previous
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
            },
        );
        for connection in connections {
            state.refresh_connection(&connection);
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
            "stream desired state set"
        );
        Outcome::Result(serde_json::to_value(StreamPutResult { created }).unwrap_or_default())
    }

    /// Binds each validated source of `stream_id` to a connection: the
    /// one keyed by it, else the stream's previous connection at that
    /// index switched to it in place where the worker can follow
    /// ([`switchable`]), else a new one.
    fn bind_sources(
        &self,
        state: &mut State,
        stream_id: &StreamId,
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
                            url = %source.url,
                            "stream/put: the connection switches to the new source in place"
                        );
                        state.switch_connection(id, source.key.clone(), driver_spec(id, &source));
                        id.clone()
                    }
                    None => self.create_connection(state, &source),
                },
            };
            if let Some(entry) = state.connections.get_mut(&connection) {
                entry.streams.insert(stream_id.as_str().to_owned());
            }
            sources.push(StreamSource {
                url: source.url,
                options: source.options,
                protocol: source.protocol,
                connection,
            });
        }
        sources
    }

    /// Creates a connection for `source` and starts its driver.
    fn create_connection(&self, state: &mut State, source: &ValidatedSource) -> String {
        state.next_connection = state.next_connection.saturating_add(1);
        let id = format!("c{}", state.next_connection);
        let (demand, demand_rx) = watch::channel(0);
        let (commands, commands_rx) = mpsc::channel(COMMAND_QUEUE);
        state.connections.insert(
            id.clone(),
            ConnectionEntry {
                key: source.key.clone(),
                port: source.url.port().or(source.default_port),
                loopback_relay: source.loopback_relay,
                demand,
                snapshot: ConnectionSnapshot::idle(self.shared.clock.wall_now()),
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
        let span = tracing::info_span!("connection", connection.id = %id, url = %source.url);
        let run = Driver::new(
            spec,
            Arc::clone(&self.shared),
            demand_rx,
            (commands, commands_rx),
            config,
        )
        .run()
        .instrument(span);
        let _handle = spawn_named("connection.driver", self.shared.tracker.track_future(run));
        tracing::info!(connection.id = %id, url = %source.url, options = %source.described, "connection created");
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

    /// `stream/delete`: idempotent; the stream's sessions close first.
    fn stream_delete(&self, stream_id: &str) -> Outcome {
        let removed = {
            let mut state = self.shared.lock();
            state.close_sessions_where(
                |session| session.stream_id == stream_id,
                "stream_deleted",
                "the stream was deleted",
                CloseBy::Supervisor,
            );
            state.streams.remove(stream_id).map(|entry| {
                for source in entry.sources {
                    state.refresh_connection(&source.connection);
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

    /// `webrtc/offer`: validates, registers the session on the stream's
    /// connection (which raises its demand) and hands the offer to its
    /// driver; the answer arrives as an event once the tracks are known.
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
        let (connection_id, commands) = stream
            .sources
            .first()
            .and_then(|source| state.connections.get_key_value(&source.connection))
            .map(|(id, entry)| (id.clone(), entry.commands.clone()))
            .ok_or_else(|| internal("the stream has no source connection"))?;
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
        commands
            .try_send(DriverCommand::OpenSession(spec))
            .map_err(|_| {
                ApiError::new(ErrorCode::LimitReached, "the stream's connection is busy")
                    .with_detail("limit", "connection_queue")
            })?;
        state.last_session = state.last_session.saturating_add(1);
        let serial = state.last_session;
        let (events, rx) = mpsc::channel(SESSION_QUEUE);
        let mut entry = SessionEntry::new(
            serial,
            stream_id.as_str().to_owned(),
            connection_id.clone(),
            ice_ufrag,
            (connection, offer.id, events),
            self.shared.clock.wall_now(),
        );
        entry.deliver(
            &session_id,
            api_event(&SessionEvent::Session {
                session_id: session_id.clone(),
            }),
        );
        for warning in &ice.warnings {
            entry.deliver(&session_id, api_event(warning));
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
        let id = session_id.clone();
        self.shared
            .after(&session_id, serial, SOURCE_NOT_LIVE_AFTER, move |state| {
                close_if_not_live(state, &id, serial);
            });
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
            "session_closed",
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
    /// talker, on each of the stream's sources whose protocol can carry
    /// audio back. Non-blocking: the worker releases it, and a
    /// `talker_changed` with `released` follows on `stream/subscribe`.
    /// Releasing a free backchannel succeeds.
    fn backchannel_release(&self, stream_id: &str) -> Outcome {
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
                self.registries
                    .sources
                    .get(source.url.scheme())
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
                .try_send(DriverCommand::ReleaseBackchannel)
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
            talker = ?talker,
            "backchannel release requested"
        );
        Outcome::Result(
            serde_json::to_value(BackchannelReleaseResult { talker }).unwrap_or_default(),
        )
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
            Command::StreamPut(put) => self.stream_put(put),
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
            Command::SessionGet(get) => self.session_get(&get.session_id),
            Command::SessionList(_) => self.session_list(),
            Command::SessionClose(close) => self.session_close(&close.session_id),
            Command::SessionAdopt(adopt) => {
                self.session_adopt(connection, adopt.id, &adopt.session_id)
            }
            Command::BackchannelRelease(release) => self.backchannel_release(&release.stream_id),
            Command::Ping(_) | Command::Schema(_) | Command::Unsubscribe(_) => {
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

    fn unsubscribed(&self, connection: ConnectionId, subscription: u64) -> Option<Event> {
        let mut state = self.shared.lock();
        let session_id = state
            .sessions
            .iter()
            .find(|(_, session)| session.owned_by(connection, subscription))
            .map(|(id, _)| id.clone())?;
        state.close_session(
            &session_id,
            "session_closed",
            "unsubscribed",
            CloseBy::Unsubscribe,
        )
    }

    fn connection_closed(&self, connection: ConnectionId) {
        let orphans = self.shared.lock().connection_closed(connection);
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
                            "session_closed",
                            "not adopted within the grace period",
                            CloseBy::Supervisor,
                        );
                    }
                },
            );
        }
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
        && entry.audio == put.audio
        && entry.orientation == put.orientation
        && entry.sources.len() == validated.len()
        && entry
            .sources
            .iter()
            .zip(validated)
            .all(|(a, b)| a.url == b.url && a.options == b.options)
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
        let other = state.stream_with_source(stream_id, &source.url)?;
        tracing::info!(
            stream.id = %stream_id,
            other.id = %other,
            url = %source.url,
            "stream/put refused: the source is another stream's"
        );
        Some(
            ApiError::new(
                ErrorCode::SourceInUse,
                format!(
                    "{} is already the source of stream {other}; use that stream id, or put {other} with the new source",
                    source.url
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
        url: source.raw.clone(),
        options: serde_json::Value::Object(source.options.clone()).to_string(),
        host: source.url.host().to_owned(),
        port: source.url.port().or(source.default_port),
        loopback_relay: source.loopback_relay,
    }
}

/// Whether connection `id` can switch to `source` in place, keeping its
/// worker and so its sessions: the worker's sandbox is pinned to the port
/// it may connect to and to whether it relays loopback, so a source that
/// differs in either needs a new worker.
fn switchable(state: &State, id: &str, source: &ValidatedSource) -> bool {
    state.connections.get(id).is_some_and(|entry| {
        entry.port == source.url.port().or(source.default_port)
            && entry.loopback_relay == source.loopback_relay
    })
}

/// Closes the sessions of `stream_id` that are not on its first source's
/// connection any more: a `stream/put` changed the source's port or
/// loopback relay, so it moved to a new worker.
fn close_moved_sessions(state: &mut State, stream_id: &str) {
    let current = state
        .streams
        .get(stream_id)
        .and_then(|entry| entry.sources.first())
        .map(|source| source.connection.clone());
    state.close_sessions_where(
        |session| session.stream_id == stream_id && current.as_ref() != Some(&session.connection),
        "stream_changed",
        "the stream's source changed",
        CloseBy::Supervisor,
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

/// Closes session `serial` under `session_id` with `source_not_live` if it
/// still has no answer: the source declared no tracks in time.
fn close_if_not_live(state: &mut State, session_id: &str, serial: u64) {
    if state
        .sessions
        .get(session_id)
        .is_some_and(|session| session.serial == serial && !session.answered)
    {
        let _event = state.close_session(
            session_id,
            "source_not_live",
            "the source declared no tracks within 10 s of the offer",
            CloseBy::Supervisor,
        );
    }
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

    use lotse_api::Event;
    use lotse_api_types::command::parse_command;
    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::let_assert;
    use lotse_core::output::OutputShape;
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
            .register(Arc::new(FakeOutputFactory(WEBRTC, OutputShape::Session)))
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
        assert_eq!(info["build"]["target"], "test");
        assert!(
            info["codecs"]["video"]
                .as_array()
                .unwrap()
                .contains(&json!("h264"))
        );
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
        let logged = captured.lines("the server answers this command itself");
        assert!(logged[0].contains("command=\"ping\""), "{logged:?}");
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
                    .register(Arc::new(FakeOutputFactory(WEBRTC, OutputShape::Session)))
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
    /// backchannel through the stream's connection, says who held it, and
    /// is refused for an unknown stream and a protocol without one.
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
            Ok(DriverCommand::ReleaseBackchannel)
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
            Ok(DriverCommand::ReleaseBackchannel)
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
        let demand = |s: &Supervisor| *s.shared.lock().connections["c1"].demand.borrow();
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
        let file = dir.join(format!("received.{pid}"));
        for attempt in 0_u32.. {
            let received = std::fs::read(&file).unwrap_or_default();
            if received.windows(needle.len()).any(|w| w == needle) {
                return;
            }
            assert!(attempt < 500, "worker {pid} never received {needle:?}");
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
        assert_eq!(*s.shared.lock().connections["c1"].demand.borrow(), 2);
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

    #[tokio::test]
    async fn unsubscribe_and_session_close_end_sessions_idempotently() {
        let dir = private_dir("close");
        let s = with_webrtc(&blocking_worker(&dir), Arc::new(SystemClock));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let _s1 = subscription(call_on(&s, 1, &offer(5, "front", Some("s1"))).await);
        // The source_not_live timer is the session's, and ends with it
        // rather than sleeping out its 10 s.
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

    /// An offer id, a session id, its flood, and the `closed` it ends with.
    type Flood<'a> = (u64, &'a str, &'a dyn Fn() -> Report, Option<&'a Value>);

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
        let refused = json!({ "type": "closed", "code": "internal_error",
                              "message": "the worker reported more than its session allows" });
        let floods: [Flood<'_>; 3] = [
            (3, "answers", &answer, Some(&refused)),
            (4, "candidates", &candidate, Some(&refused)),
            // One warning per code: the rest are dropped, the session lives.
            (5, "warnings", &warning, None),
        ];
        for (id, session_id, flood, closed) in floods {
            let mut events =
                subscription(call_on(&s, 1, &offer(id, "front", Some(session_id))).await);
            next(&mut events).await;
            let connection = s.shared.lock().sessions[session_id].connection.clone();
            let report = |event| {
                let now = s.shared.clock.now();
                s.shared
                    .lock()
                    .session_report(&connection, session_id, event, now);
            };
            report(answer());
            let mut bytes = 0;
            let mut last = drain(&mut events, &mut bytes);
            for _ in 0..2_000 {
                report(flood());
                last = drain(&mut events, &mut bytes).or(last);
            }
            assert!(
                bytes < lotse_api::OUTBOUND_BUDGET_BYTES / 8,
                "{session_id}: {bytes} bytes queued for one session"
            );
            if let Some(closed) = closed {
                assert_eq!(last.as_ref(), Some(closed), "{session_id}");
                assert!(events.recv().await.is_none(), "{session_id}: ended");
            } else {
                assert_eq!(last.unwrap()["type"], "warning", "{session_id}");
                let _event = s.shared.lock().close_session(
                    session_id,
                    "session_closed",
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
        // Every report still reaches the client.
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
        // The fired timers (source_not_live, the first grace) are dropped
        // as the new grace timer is kept.
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

    #[tokio::test]
    async fn a_session_without_an_answer_closes_with_source_not_live() {
        let dir = private_dir("notlive");
        let clock = Arc::new(FakeClock::from_system());
        let s = with_webrtc(&blocking_worker(&dir), clock.clone());
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let mut events = subscription(call_on(&s, 1, &offer(2, "front", Some("s1"))).await);
        next(&mut events).await;
        clock.advance(SOURCE_NOT_LIVE_AFTER);
        let closed = next(&mut events).await;
        assert_eq!(
            (&closed["type"], &closed["code"]),
            (&json!("closed"), &json!("source_not_live"))
        );
        assert!(events.recv().await.is_none());
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
                .map(|source| s.validate_source(source).unwrap())
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
            "worker_crashed",
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
        // The gather deadline is the session's timer too, beside
        // source_not_live.
        assert_eq!(s.shared.lock().sessions["s1"].timers().len(), 2);
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
        // The demux counted the STUN response as `metrics/get` shows.
        let counted =
            &result(call(&s, r#"{"id":3,"type":"metrics/get"}"#).await)["supervisor"]["demux"];
        assert!(counted["responses"].as_u64().unwrap() >= 1, "{counted}");
        assert_eq!(counted["received"], counted["responses"], "{counted}");
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
}
