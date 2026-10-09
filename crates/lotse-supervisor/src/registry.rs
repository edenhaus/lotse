//! The registry: every stream's desired state, the source connections
//! streams share, each connection's demand and its latest snapshot as the
//! driver reports it, the viewer sessions, and the subscribers of
//! `stream/subscribe`.
//!
//! One mutex over the maps, taken only on control-plane operations and
//! never held across an await. Drivers publish snapshots into it, the
//! handler reads the API's DTOs out of it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use lotse_api::{ConnectionId, Event, EventClass};
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::info::{ProcessMetrics, WorkerMetrics};
use lotse_api_types::session::SessionEvent;
use lotse_api_types::stream::{
    AudioMode, ConnectionInfo, LastError, Orientation, SourceInfo, Stream, StreamEvent,
    StreamState, StreamStats, TrackInfo, WorkerInfo,
};
use lotse_api_types::time::rfc3339;
use lotse_core::clock::Clock;
use lotse_core::connection::{ConnectionError, ConnectionState};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_ipc::{
    SessionEvent as WorkerSessionEvent, SessionSpec, TrackInfo as IpcTrackInfo, WorkerStats,
};
use tokio::sync::{mpsc, watch};
use tokio_util::task::TaskTracker;

use crate::connect::ConnectPermits;
use crate::driver::{DriverCommand, DriverSpec};
use crate::gather::Relayed;
use crate::memory::MemoryProbe;
use crate::millis;
use crate::net::allocation::Transport;
use crate::net::demux::{DatagramSink, Registrations};
use crate::net::stun_client::StunClient;
use crate::net::turn_client::TurnClient;
use crate::session::{ChannelRequest, SessionEntry, api_event};
use crate::worker::WorkerManager;

/// Events a subscription may hold before the server's forwarder drains
/// them. Stream-state events coalesce in the server's outbox anyway, so a
/// full queue drops the event rather than blocking the control plane.
pub(crate) const SUBSCRIPTION_QUEUE: usize = 256;

/// Binds the channel `request` names, then hands its number to the
/// session's worker through the driver's `commands`; a refusal is logged,
/// and the peer stays unbound (RFC 8656 §12).
fn bind_channel(session_id: &str, request: ChannelRequest, commands: mpsc::Sender<DriverCommand>) {
    let session_id = session_id.to_owned();
    let _task = spawn_named("session.channel", async move {
        let ChannelRequest {
            lease,
            relayed,
            peer,
        } = request;
        match lease.bind_channel(peer).await {
            Ok(channel) => {
                tracing::debug!(session.id = %session_id, %relayed, %peer, channel = channel.number(), "relay channel bound");
                let command = DriverCommand::RelayChannel {
                    session_id,
                    relayed,
                    peer,
                    channel: channel.number(),
                };
                if commands.try_send(command).is_err() {
                    tracing::warn!(%relayed, %peer, "driver queue full; relay channel not handed over");
                }
            }
            Err(err) => {
                tracing::info!(session.id = %session_id, %relayed, %peer, error = %err, "relay channel not bound");
            }
        }
    });
}

/// What a driver reports about its connection, as `stream/get` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectionSnapshot {
    /// The machine's state.
    pub(crate) state: ConnectionState,
    /// The last error, if the connection is not live.
    pub(crate) last_error: Option<ConnectionError>,
    /// When the current state began.
    pub(crate) since: SystemTime,
    /// Source reconnects so far.
    pub(crate) reconnects: u32,
    /// The worker while one runs.
    pub(crate) worker: Option<WorkerProcess>,
    /// Worker crashes so far.
    pub(crate) crashes: u32,
    /// When the worker last crashed.
    pub(crate) last_crash: Option<SystemTime>,
    /// The tracks the source declared, from the last time it went live.
    pub(crate) tracks: Vec<IpcTrackInfo>,
    /// The worker's latest counters.
    pub(crate) stats: Option<WorkerStats>,
}

impl ConnectionSnapshot {
    /// An idle connection created at `now`.
    pub(crate) const fn idle(now: SystemTime) -> Self {
        Self {
            state: ConnectionState::Idle,
            last_error: None,
            since: now,
            reconnects: 0,
            worker: None,
            crashes: 0,
            last_crash: None,
            tracks: Vec::new(),
            stats: None,
        }
    }
}

/// The worker process running a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkerProcess {
    /// Its pid.
    pub(crate) pid: u32,
    /// When it was started, on the injected clock.
    pub(crate) started: Instant,
    /// Its `smaps_rollup`, once its `Ready` handed one over.
    pub(crate) memory: Option<MemoryProbe>,
}

/// What streams share a connection by: the canonical source spec.
/// The URL compares scheme, host, port, path, query and credentials; the
/// options are the source's [`connection_options`](lotse_core::source::Source::connection_options),
/// normalized by its factory (defaults applied, key order irrelevant) and
/// without options that do not change what is received. Holds the
/// credentials and unredacted options, so `Debug` shows the redacted URL
/// and the option names only.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ConnectionKey {
    /// The URL, credentials included.
    pub(crate) url: SourceUrl,
    /// The normalized receive-relevant options.
    pub(crate) options: serde_json::Value,
}

impl fmt::Debug for ConnectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self
            .options
            .as_object()
            .map(|fields| fields.keys().map(String::as_str).collect())
            .unwrap_or_default();
        f.debug_struct("ConnectionKey")
            .field("url", &self.url)
            .field("options", &names)
            .finish()
    }
}

/// One source of a stream, bound to its connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamSource {
    /// The URL, as `stream/get` reports it.
    pub(crate) url: SourceUrl,
    /// The per-scheme options as given.
    pub(crate) options: serde_json::Map<String, serde_json::Value>,
    /// The protocol name the factory reports.
    pub(crate) protocol: &'static str,
    /// The connection's id.
    pub(crate) connection: String,
}

/// A stream's desired state.
#[derive(Debug)]
pub(crate) struct StreamEntry {
    /// The sources, in order.
    pub(crate) sources: Vec<StreamSource>,
    /// Keep the stream connected without viewers.
    pub(crate) preload: bool,
    /// Audio handling.
    pub(crate) audio: AudioMode,
    /// How the picture is turned for display, handed to each session at
    /// its offer.
    pub(crate) orientation: Orientation,
    /// When the stream was created, the `since` of a stream without a
    /// connection.
    pub(crate) created: SystemTime,
}

/// A source connection and the streams that reference it.
#[derive(Debug)]
pub(crate) struct ConnectionEntry {
    /// The key the connection is found by: its source's URL, credentials
    /// and normalized options.
    pub(crate) key: ConnectionKey,
    /// The source's port, which the worker's sandbox is pinned to: a
    /// source on another port needs another connection.
    pub(crate) port: Option<u16>,
    /// The worker binds a loopback relay listener before its sandbox.
    pub(crate) loopback_relay: bool,
    /// The demand the driver follows; dropping it stops the driver.
    pub(crate) demand: watch::Sender<u32>,
    /// What the driver last reported.
    pub(crate) snapshot: ConnectionSnapshot,
    /// The streams reading from it.
    pub(crate) streams: BTreeSet<String>,
    /// What the driver passes on to the worker: session messages.
    pub(crate) commands: mpsc::Sender<DriverCommand>,
}

/// Who ends a session, which decides who hears of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseBy {
    /// The supervisor (`session/close`, grace, deletion, shutdown, a
    /// worker's malformed report): the worker is told and the owner gets
    /// `closed`.
    Supervisor,
    /// The owner's `unsubscribe`: the worker is told, and the `closed`
    /// event is returned for the server to send before the result.
    Unsubscribe,
    /// The worker is gone: only the owner hears of it.
    WorkerGone,
}

/// One `stream/subscribe`.
#[derive(Debug)]
struct Subscriber {
    /// The control connection it belongs to.
    connection: ConnectionId,
    /// One stream, or every stream.
    stream_id: Option<String>,
    /// Where the events go.
    events: mpsc::Sender<Event>,
}

/// The maps.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// Streams by id.
    pub(crate) streams: BTreeMap<String, StreamEntry>,
    /// Connections by id (`c1`, `c2`, ...).
    pub(crate) connections: BTreeMap<String, ConnectionEntry>,
    /// The number of the next connection.
    pub(crate) next_connection: u64,
    /// Open subscriptions.
    subscribers: Vec<Subscriber>,
    /// Worker crashes since start, over every connection.
    pub(crate) worker_restarts: u64,
    /// Viewer sessions by id.
    pub(crate) sessions: BTreeMap<String, SessionEntry>,
    /// The serial of the last session opened.
    pub(crate) last_session: u64,
    /// The demux's sessions; `None` without a front door (tests).
    pub(crate) registrations: Option<Arc<Registrations>>,
}

impl State {
    /// The connection a source spec is shared by, if one exists.
    pub(crate) fn connection_for(&self, key: &ConnectionKey) -> Option<String> {
        self.connections
            .iter()
            .find(|(_, entry)| entry.key == *key)
            .map(|(id, _)| id.clone())
    }

    /// The stream other than `except` with a source at `url`, credentials
    /// aside, if any: a camera stream is one stream, so a `stream/put`
    /// naming another stream's URL is refused (`source_in_use`).
    pub(crate) fn stream_with_source(&self, except: &str, url: &SourceUrl) -> Option<String> {
        self.streams
            .iter()
            .find(|(id, entry)| {
                id.as_str() != except
                    && entry
                        .sources
                        .iter()
                        .any(|source| source.url.url() == url.url())
            })
            .map(|(id, _)| id.clone())
    }

    /// Re-keys connection `id` to `key` and tells its driver to switch its
    /// worker to `spec`: the stream's sessions stay, and the tracks switch
    /// at the new source's first keyframe.
    pub(crate) fn switch_connection(&mut self, id: &str, key: ConnectionKey, spec: DriverSpec) {
        let Some(entry) = self.connections.get_mut(id) else {
            return;
        };
        entry.key = key;
        if entry
            .commands
            .try_send(DriverCommand::SwitchSource(spec))
            .is_err()
        {
            tracing::warn!(
                connection.id = id,
                "driver queue full; the connection keeps its source until the next put"
            );
        }
    }

    /// Recomputes which streams reference connection `id` and its demand
    /// from them; a connection nothing references any more is dropped,
    /// which stops its driver.
    pub(crate) fn refresh_connection(&mut self, id: &str) {
        let Some(entry) = self.connections.get_mut(id) else {
            return;
        };
        let streams = &self.streams;
        entry.streams.retain(|stream| {
            streams
                .get(stream)
                .is_some_and(|s| s.sources.iter().any(|source| source.connection == id))
        });
        if entry.streams.is_empty() {
            tracing::info!(connection.id = id, "connection released");
            self.connections.remove(id);
            return;
        }
        let preloads = entry
            .streams
            .iter()
            .filter(|stream| streams.get(*stream).is_some_and(|s| s.preload))
            .count();
        let viewers = self
            .sessions
            .values()
            .filter(|session| session.connection == id)
            .count();
        let demand = u32::try_from(preloads.saturating_add(viewers)).unwrap_or(u32::MAX);
        if *entry.demand.borrow() != demand {
            tracing::info!(connection.id = id, demand, "connection demand changed");
            entry.demand.send_replace(demand);
        }
    }

    /// Opens a subscription and queues the current state of every matching
    /// stream as its first events. The queue holds the whole snapshot on
    /// top of [`SUBSCRIPTION_QUEUE`], so no stream's first event is lost
    /// however many streams `max_streams` allows, and live events still
    /// find the usual room. Subscriptions whose receiver is gone
    /// (unsubscribed) are forgotten first, so the list holds only open
    /// ones even when no event ever reaches their stream.
    pub(crate) fn subscribe(
        &mut self,
        connection: ConnectionId,
        stream_id: Option<String>,
    ) -> mpsc::Receiver<Event> {
        self.subscribers
            .retain(|subscriber| !subscriber.events.is_closed());
        let snapshot: Vec<Event> = self
            .streams
            .iter()
            .filter(|(id, _)| {
                stream_id
                    .as_deref()
                    .is_none_or(|wanted| wanted == id.as_str())
            })
            .map(|(id, entry)| self.stream_event(id, entry))
            .collect();
        let (events, rx) = mpsc::channel(SUBSCRIPTION_QUEUE.saturating_add(snapshot.len()));
        for event in snapshot {
            let _queued = events.try_send(event);
        }
        self.subscribers.push(Subscriber {
            connection,
            stream_id,
            events,
        });
        rx
    }

    /// Drops the subscriptions of a control connection that closed and
    /// orphans its sessions; returns each orphan's id, serial and epoch
    /// for its grace timer.
    pub(crate) fn connection_closed(
        &mut self,
        connection: ConnectionId,
    ) -> Vec<(String, u64, u64)> {
        self.subscribers
            .retain(|subscriber| subscriber.connection != connection);
        let mut orphans = Vec::new();
        for (id, session) in &mut self.sessions {
            if session.owned_by_connection(connection) {
                let epoch = session.orphan();
                tracing::info!(event = "session_orphaned", session.id = %id, epoch, "session orphaned; media keeps flowing");
                orphans.push((id.clone(), session.serial, epoch));
            }
        }
        orphans
    }

    /// Removes a session and everything that routes to it: its demux
    /// registration and its share of the connection's demand.
    fn finish_session(&mut self, session_id: &str) -> Option<SessionEntry> {
        let entry = self.sessions.remove(session_id)?;
        if let Some(registrations) = &self.registrations {
            registrations.unregister(&entry.ufrag);
        }
        let connection = entry.connection.clone();
        self.refresh_connection(&connection);
        Some(entry)
    }

    /// Ends a session with a `closed` of `code`; returns that event, which
    /// [`CloseBy::Unsubscribe`] leaves to the caller to send. Idempotent:
    /// an unknown session is `None`.
    pub(crate) fn close_session(
        &mut self,
        session_id: &str,
        code: &'static str,
        message: &str,
        by: CloseBy,
    ) -> Option<Event> {
        let mut entry = self.finish_session(session_id)?;
        if by != CloseBy::WorkerGone
            && let Some(connection) = self.connections.get(&entry.connection)
            && connection
                .commands
                .try_send(DriverCommand::CloseSession {
                    session_id: session_id.to_owned(),
                    code,
                    message: message.to_owned(),
                })
                .is_err()
        {
            tracing::warn!(
                session.id = session_id,
                "driver queue full; the worker closes the session with its connection"
            );
        }
        tracing::info!(event = "session_closed", session.id = session_id, stream.id = %entry.stream_id, code, detail = message, by = ?by, "session closed");
        let event = api_event(&SessionEvent::Closed {
            code: code.to_owned(),
            message: message.to_owned(),
        });
        if by != CloseBy::Unsubscribe {
            entry.deliver(session_id, event.clone());
        }
        Some(event)
    }

    /// Closes every session matching `select` with `code`.
    pub(crate) fn close_sessions_where(
        &mut self,
        select: impl Fn(&SessionEntry) -> bool,
        code: &'static str,
        message: &str,
        by: CloseBy,
    ) {
        let ids: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, session)| select(session))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let _event = self.close_session(&id, code, message, by);
        }
    }

    /// Tells every session of `stream_id` that its orientation is now
    /// `orientation`: an open session turns the picture from its next
    /// frame, without a new answer. A session whose driver queue is full
    /// keeps the orientation it has.
    pub(crate) fn reorient_sessions(&self, stream_id: &str, orientation: Orientation) {
        let sessions = self
            .sessions
            .iter()
            .filter(|(_, session)| session.stream_id == stream_id)
            .filter_map(|(id, session)| Some((id, self.connections.get(&session.connection)?)));
        for (session_id, connection) in sessions {
            let command = DriverCommand::Orientation {
                session_id: session_id.clone(),
                orientation: orientation.code(),
            };
            if connection.commands.try_send(command).is_err() {
                tracing::warn!(
                    session.id = %session_id,
                    orientation = ?orientation,
                    "driver queue full; the session keeps its orientation"
                );
            }
        }
    }

    /// A worker's report about one of its sessions; a report about a
    /// session of another connection is refused, and one whose answer or
    /// candidate fails [`worker_text::check`](crate::worker_text::check),
    /// or that is over the session's budget ([`SessionEntry::apply`]),
    /// closes its session with `internal_error`. A state change is logged
    /// as [`SessionEntry::state_line`] allows at `now`.
    pub(crate) fn session_report(
        &mut self,
        connection: &str,
        session_id: &str,
        report: WorkerSessionEvent,
        now: Instant,
    ) {
        let Some(entry) = self.sessions.get_mut(session_id) else {
            tracing::debug!(
                session.id = session_id,
                ?report,
                "report for a session that is gone"
            );
            return;
        };
        if entry.connection != connection {
            tracing::warn!(
                session.id = session_id,
                connection.id = connection,
                "a worker reported a session it does not run; ignored"
            );
            return;
        }
        if let Err(reason) = crate::worker_text::check(&report) {
            tracing::warn!(
                session.id = session_id,
                connection.id = connection,
                reason,
                "a worker reported malformed text for the browser; session refused"
            );
            let _event = self.close_session(
                session_id,
                "internal_error",
                "the worker's answer or candidate was malformed",
                CloseBy::Supervisor,
            );
            return;
        }
        let events = match entry.apply(report) {
            Ok(events) => events,
            Err(reason) => {
                tracing::warn!(
                    session.id = session_id,
                    connection.id = connection,
                    reason,
                    "a worker reported more than its session allows; session refused"
                );
                let _event = self.close_session(
                    session_id,
                    "internal_error",
                    "the worker reported more than its session allows",
                    CloseBy::Supervisor,
                );
                return;
            }
        };
        for event in &events {
            if let SessionEvent::State { ice, dtls } = event
                && let Some(count) = entry.state_line(now)
            {
                tracing::info!(
                    event = "session_state",
                    session.id = session_id,
                    ice,
                    dtls,
                    count,
                    "session state changed"
                );
            }
        }
        let requests = entry.take_channel_requests();
        if !requests.is_empty()
            && let Some(commands) = self.connections.get(connection).map(|c| c.commands.clone())
        {
            for request in requests {
                bind_channel(session_id, request, commands.clone());
            }
        }
        self.deliver_session(session_id, events, "worker");
    }

    /// A TURN gather of session `serial` finished: a lease goes to the
    /// worker as a relay candidate, whose line the worker reports; without
    /// one, or once end-of-candidates went out, the gather just ends and a
    /// lease is released.
    pub(crate) fn session_relayed(
        &mut self,
        session_id: &str,
        serial: u64,
        relayed: Option<Relayed>,
    ) {
        let Some(entry) = self
            .sessions
            .get_mut(session_id)
            .filter(|s| s.serial == serial)
        else {
            return;
        };
        if let Some(relayed) = relayed.filter(|_| !entry.candidates_done()) {
            let address = relayed.lease.relayed();
            let command = DriverCommand::RelayCandidate {
                session_id: session_id.to_owned(),
                relayed: address,
                server: relayed.server,
                local: relayed.local,
                tcp: relayed.transport == Transport::Tcp,
                grant: relayed.lease.grant(),
            };
            let queued = self
                .connections
                .get(&entry.connection)
                .is_some_and(|connection| connection.commands.try_send(command).is_ok());
            if queued {
                tracing::info!(
                    session.id = session_id,
                    relayed = %address,
                    server = %relayed.server,
                    transport = ?relayed.transport,
                    "relay candidate handed to the worker"
                );
                entry.relay_handed_over(relayed.lease);
                return;
            }
            tracing::warn!(
                session.id = session_id,
                "driver queue full; relay candidate dropped"
            );
        }
        let events = entry.gathered(None);
        self.deliver_session(session_id, events, "gathering");
    }

    /// A STUN gather of session `serial` finished.
    pub(crate) fn session_gathered(
        &mut self,
        session_id: &str,
        serial: u64,
        candidate: Option<String>,
    ) {
        if let Some(entry) = self
            .sessions
            .get_mut(session_id)
            .filter(|s| s.serial == serial)
        {
            let events = entry.gathered(candidate);
            self.deliver_session(session_id, events, "gathering");
        }
    }

    /// The gather deadline of session `serial` passed.
    pub(crate) fn session_gather_deadline(&mut self, session_id: &str, serial: u64) {
        if let Some(entry) = self
            .sessions
            .get_mut(session_id)
            .filter(|s| s.serial == serial)
        {
            let events = entry.gather_deadline();
            self.deliver_session(session_id, events, "gathering");
        }
    }

    /// Logs and delivers a session's events; a `closed` among them ends the
    /// session after it is delivered.
    fn deliver_session(&mut self, session_id: &str, events: Vec<SessionEvent>, by: &'static str) {
        for event in events {
            match &event {
                SessionEvent::Answer { .. } => {
                    tracing::info!(
                        event = "session_answered",
                        session.id = session_id,
                        "answer sent"
                    );
                }
                // Logged, rate-limited, by `session_report`.
                SessionEvent::State { .. } => {}
                // The worker's text under `detail`, Debug-escaped: a field
                // named `message` is printed raw by the text format.
                SessionEvent::Warning { code, message } => {
                    tracing::info!(
                        event = "session_warning",
                        session.id = session_id,
                        code,
                        detail = ?message,
                        "session warning"
                    );
                }
                _ => tracing::debug!(session.id = session_id, ?event, by, "session event"),
            }
            if let SessionEvent::Closed { code, message } = &event {
                tracing::info!(
                    event = "session_closed",
                    session.id = session_id,
                    code,
                    detail = ?message,
                    by,
                    "session closed"
                );
                if let Some(mut entry) = self.finish_session(session_id) {
                    entry.deliver(session_id, api_event(&event));
                }
            } else if let Some(entry) = self.sessions.get_mut(session_id) {
                entry.deliver(session_id, api_event(&event));
            }
        }
    }

    /// Registers a session with the demux once its worker is about to get
    /// it; `false` when it closed in the meantime.
    pub(crate) fn register_session(&self, spec: &SessionSpec, sink: Arc<dyn DatagramSink>) -> bool {
        let current = self
            .sessions
            .get(&spec.session_id)
            .is_some_and(|session| session.ufrag == spec.ice_ufrag);
        if current && let Some(registrations) = &self.registrations {
            let _registration =
                registrations.register(&spec.ice_ufrag, spec.ice_pass.as_bytes().to_vec(), sink);
        }
        current
    }

    /// Tells the subscribers a stream's current state.
    pub(crate) fn notify_stream(&mut self, stream_id: &str) {
        let Some(entry) = self.streams.get(stream_id) else {
            return;
        };
        let event = self.stream_event(stream_id, entry);
        self.fan_out(stream_id, &event);
    }

    /// Tells the subscribers a stream is gone.
    pub(crate) fn notify_removed(&mut self, stream_id: &str) {
        let event = Event {
            class: EventClass::StreamState {
                stream_id: stream_id.to_owned(),
            },
            payload: serde_json::to_value(StreamEvent::StreamRemoved {
                stream_id: stream_id.to_owned(),
            })
            .unwrap_or_default(),
        };
        self.fan_out(stream_id, &event);
    }

    /// Queues `event` on every subscription matching `stream_id`; a closed
    /// subscription is forgotten, a full one drops the event.
    fn fan_out(&mut self, stream_id: &str, event: &Event) {
        self.subscribers.retain(|subscriber| {
            if subscriber
                .stream_id
                .as_deref()
                .is_some_and(|wanted| wanted != stream_id)
            {
                return true;
            }
            match subscriber.events.try_send(event.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::debug!(
                        stream.id = stream_id,
                        "subscription queue full; event dropped"
                    );
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
    }

    /// The `stream` event for a stream as it is now.
    fn stream_event(&self, stream_id: &str, entry: &StreamEntry) -> Event {
        let snapshot = self.first_connection(entry).map(|c| &c.snapshot);
        let payload = StreamEvent::Stream {
            stream_id: stream_id.to_owned(),
            state: snapshot.map_or(StreamState::Idle, |s| api_state(s.state)),
            last_error: snapshot.and_then(last_error),
        };
        Event {
            class: EventClass::StreamState {
                stream_id: stream_id.to_owned(),
            },
            payload: serde_json::to_value(payload).unwrap_or_default(),
        }
    }

    /// What a stream's `stream` event would say now, to tell whether a
    /// `stream/put` changed it.
    pub(crate) fn stream_status(
        &self,
        stream_id: &str,
    ) -> Option<(StreamState, Option<LastError>)> {
        let entry = self.streams.get(stream_id)?;
        let snapshot = self.first_connection(entry).map(|c| &c.snapshot);
        Some((
            snapshot.map_or(StreamState::Idle, |s| api_state(s.state)),
            snapshot.and_then(last_error),
        ))
    }

    /// The connection a stream's state comes from: its first source's.
    fn first_connection(&self, entry: &StreamEntry) -> Option<&ConnectionEntry> {
        entry
            .sources
            .first()
            .and_then(|source| self.connections.get(&source.connection))
    }

    /// A stream as `stream/get` returns it, its workers' memory still to
    /// read once the maps are unlocked.
    pub(crate) fn stream(&self, stream_id: &str) -> Option<UnreadStream> {
        self.streams
            .get(stream_id)
            .map(|entry| self.stream_dto(stream_id, entry))
    }

    /// Every stream, for `stream/list`, their workers' memory still to read
    /// once the maps are unlocked.
    pub(crate) fn streams(&self) -> BTreeMap<String, UnreadStream> {
        self.streams
            .iter()
            .map(|(id, entry)| (id.clone(), self.stream_dto(id, entry)))
            .collect()
    }

    /// A stream's counters, for `metrics/get`.
    pub(crate) fn stream_stats(&self, entry: &StreamEntry) -> StreamStats {
        stream_stats_of(
            self.first_connection(entry)
                .and_then(|c| c.snapshot.stats.as_ref()),
        )
    }

    /// The running workers for `metrics/get`, by connection id, each with
    /// the probe to read its memory through once the maps are unlocked.
    pub(crate) fn workers(
        &self,
        now: Instant,
    ) -> BTreeMap<String, (WorkerMetrics, Option<MemoryProbe>)> {
        self.connections
            .iter()
            .filter_map(|(id, connection)| {
                let snapshot = &connection.snapshot;
                let worker = snapshot.worker.as_ref()?;
                let stats = snapshot.stats.as_ref();
                let metrics = WorkerMetrics {
                    process: ProcessMetrics {
                        pid: worker.pid,
                        uptime_ms: millis(now.saturating_duration_since(worker.started)),
                        rss_bytes: None,
                        pss_bytes: None,
                        tasks: stats.map(|s| s.tasks),
                    },
                    streams: connection.streams.iter().cloned().collect(),
                    restarts: snapshot.crashes,
                    sessions: stats.map_or(0, |s| s.sessions),
                    send_failures: stats.map_or(0, |s| s.send_failures),
                    relay_unbound: stats.map_or(0, |s| s.relay_unbound),
                };
                Some((id.clone(), (metrics, worker.memory.clone())))
            })
            .collect()
    }

    /// The DTO of one stream, with the probe of each source's worker.
    fn stream_dto(&self, stream_id: &str, entry: &StreamEntry) -> UnreadStream {
        let first = self.first_connection(entry).map(|c| &c.snapshot);
        let (sources, probes) = entry
            .sources
            .iter()
            .map(|source| {
                let connection = self.connections.get(&source.connection);
                let snapshot = connection.map(|c| &c.snapshot);
                let probe = snapshot
                    .and_then(|s| s.worker.as_ref())
                    .and_then(|worker| worker.memory.clone());
                let info = SourceInfo {
                    url: source.url.to_string(),
                    protocol: source.protocol.to_owned(),
                    state: snapshot.map_or(StreamState::Idle, |s| api_state(s.state)),
                    reconnects: snapshot.map_or(0, |s| s.reconnects),
                    details: serde_json::Map::new(),
                    connection: ConnectionInfo {
                        id: source.connection.clone(),
                        worker: snapshot.and_then(|s| {
                            s.worker.as_ref().map(|worker| WorkerInfo {
                                pid: worker.pid,
                                restarts: s.crashes,
                                last_crash: s.last_crash.map(rfc3339),
                                pss_bytes: None,
                            })
                        }),
                    },
                };
                (info, probe)
            })
            .unzip();
        let tracks = first.map_or_else(Vec::new, |s| {
            s.tracks
                .iter()
                .map(|track| track_dto(track, s.stats.as_ref()))
                .collect()
        });
        let stream = Stream {
            stream_id: stream_id.to_owned(),
            state: first.map_or(StreamState::Idle, |s| api_state(s.state)),
            preload: entry.preload,
            since: rfc3339(first.map_or(entry.created, |s| s.since)),
            last_error: first.and_then(last_error),
            sources,
            tracks,
            sessions: self
                .sessions
                .iter()
                .filter(|(_, session)| session.stream_id == stream_id)
                .map(|(id, _)| id.clone())
                .collect(),
            stats: self.stream_stats(entry),
        };
        UnreadStream { stream, probes }
    }
}

/// A stream's DTO built under the registry lock, its workers' `pss_bytes`
/// still unknown: reading them walks each worker's mappings in the kernel,
/// so it waits until the lock is released
/// ([`MemoryProbe::sample`]).
#[derive(Debug)]
pub(crate) struct UnreadStream {
    /// The DTO.
    stream: Stream,
    /// The probe of each source's worker, in the order of `stream.sources`.
    probes: Vec<Option<MemoryProbe>>,
}

impl UnreadStream {
    /// The DTO with each source's worker's memory as of `now`; call with
    /// no lock held.
    pub(crate) async fn read_memory(self, now: Instant) -> Stream {
        let Self { mut stream, probes } = self;
        for (source, probe) in stream.sources.iter_mut().zip(probes) {
            if let (Some(worker), Some(probe)) = (source.connection.worker.as_mut(), probe) {
                worker.pss_bytes = probe.sample(now).await.pss_bytes;
            }
        }
        stream
    }
}

/// A core state as the API names it.
pub(crate) const fn api_state(state: ConnectionState) -> StreamState {
    match state {
        ConnectionState::Idle => StreamState::Idle,
        ConnectionState::Connecting => StreamState::Connecting,
        ConnectionState::Live => StreamState::Live,
        ConnectionState::Reconnecting => StreamState::Reconnecting,
        ConnectionState::Backoff => StreamState::Backoff,
        ConnectionState::Draining => StreamState::Draining,
        ConnectionState::Restarting => StreamState::Restarting,
    }
}

/// A connection error as the API carries it.
pub(crate) fn api_error(error: &ConnectionError) -> ApiError {
    ApiError::new(
        ErrorCode::parse(error.code()).unwrap_or(ErrorCode::InternalError),
        error.to_string(),
    )
}

/// A snapshot's last error with its time.
fn last_error(snapshot: &ConnectionSnapshot) -> Option<LastError> {
    snapshot.last_error.as_ref().map(|error| LastError {
        error: api_error(error),
        at: rfc3339(snapshot.since),
    })
}

/// A stream's counters from its connection's worker's, if it sent any.
fn stream_stats_of(stats: Option<&WorkerStats>) -> StreamStats {
    StreamStats {
        frames_dropped: stats.map_or(0, |s| {
            s.tracks.iter().fold(0_u64, |sum, (_, t)| {
                sum.saturating_add(t.frames_dropped_oversize)
            })
        }),
        frames_over_browser_limit: stats.map_or(0, |s| {
            s.tracks.iter().fold(0_u64, |sum, (_, t)| {
                sum.saturating_add(t.frames_over_browser_limit)
            })
        }),
        av_sync_lost: stats.map_or(0, |s| s.av_sync_lost),
        packets_lost: stats.map_or(0, |s| s.packets_lost),
        packets_out_of_order: stats.map_or(0, |s| s.packets_out_of_order),
        datagrams_rejected: stats.map_or(0, |s| s.datagrams_rejected),
        ..StreamStats::default()
    }
}

/// A track as the API reports it, with the counters of the latest stats.
fn track_dto(track: &IpcTrackInfo, stats: Option<&WorkerStats>) -> TrackInfo {
    let counters = stats.and_then(|s| {
        s.tracks
            .iter()
            .find(|(id, _)| *id == track.id)
            .map(|(_, t)| t)
    });
    TrackInfo {
        id: track.id.clone(),
        kind: track.kind.clone(),
        codec: track.codec.clone(),
        derived_from: track.derived_from.clone(),
        sync: track.sync.clone(),
        audio_delay_ms: track.audio_delay_ms,
        frames: counters.map_or(0, |t| t.frames),
        bytes: counters.map_or(0, |t| t.packet_bytes.max(t.frame_bytes)),
    }
}

/// What the handler and the connection drivers share.
#[derive(Debug)]
pub(crate) struct Shared {
    /// The clock.
    pub(crate) clock: Arc<dyn Clock>,
    /// Starts workers.
    pub(crate) manager: WorkerManager,
    /// The drivers and the worker stops in flight, awaited at shutdown.
    pub(crate) tracker: TaskTracker,
    /// The budget a worker gets to exit.
    pub(crate) shutdown_budget: Duration,
    /// The connect permits every driver's attempts share.
    pub(crate) connects: ConnectPermits,
    /// The host candidates' addresses every session answers with.
    pub(crate) hosts: Vec<SocketAddr>,
    /// The passive ICE-TCP host candidates' addresses; empty with the
    /// listener off.
    pub(crate) tcp_hosts: Vec<SocketAddr>,
    /// The STUN client of srflx gathering; `None` without a front door.
    pub(crate) stun: Option<Arc<StunClient>>,
    /// The TURN client of relay gathering; `None` without a front door.
    pub(crate) turn: Option<Arc<TurnClient>>,
    /// The maps.
    pub(crate) state: Mutex<State>,
}

impl Shared {
    /// The maps; a poisoned lock is still usable, the maps hold no
    /// invariant a panicking holder could have broken halfway.
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores a driver's snapshot and, when its state changed, tells the
    /// subscribers of every stream on the connection.
    pub(crate) fn update_connection(&self, id: &str, snapshot: ConnectionSnapshot, changed: bool) {
        let mut state = self.lock();
        let Some(entry) = state.connections.get_mut(id) else {
            return;
        };
        entry.snapshot = snapshot;
        if changed {
            let streams: Vec<String> = entry.streams.iter().cloned().collect();
            for stream in streams {
                state.notify_stream(&stream);
            }
        }
    }

    /// Counts a worker crash for `metrics/get`.
    pub(crate) fn count_crash(&self) {
        let mut state = self.lock();
        state.worker_restarts = state.worker_restarts.saturating_add(1);
    }

    /// Runs `task` on the maps after `delay` on the injected clock: a
    /// timer of session `session_id` (grace, `source_not_live`, the gather
    /// deadline), which the session keeps and aborts when it ends. A timer
    /// also checks the session's serial, since a session that is already
    /// gone by the time the timer is kept leaves it to fire.
    pub(crate) fn after(
        self: &Arc<Self>,
        session_id: &str,
        serial: u64,
        delay: Duration,
        task: impl FnOnce(&mut State) + Send + 'static,
    ) {
        // The deadline counts from now, not from the task's first poll.
        let sleep = self.clock.sleep(delay);
        let shared = Arc::clone(self);
        let timer = spawn_named("session.timer", async move {
            sleep.await;
            task(&mut shared.lock());
        });
        if let Some(session) = self
            .lock()
            .sessions
            .get_mut(session_id)
            .filter(|session| session.serial == serial)
        {
            session.add_timer(timer.abort_handle());
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

    use lotse_ipc::TrackStats;

    use super::*;

    fn ipc_track(id: &str, derived_from: Option<&str>, delay: Option<u32>) -> IpcTrackInfo {
        IpcTrackInfo {
            id: id.into(),
            kind: "audio".into(),
            codec: "opus".into(),
            clock_rate: 48_000,
            sync: "sender_reports".into(),
            derived_from: derived_from.map(Into::into),
            audio_delay_ms: delay,
        }
    }

    /// A stream reading from connection `c1`.
    fn stream_on_c1(preload: bool) -> StreamEntry {
        StreamEntry {
            sources: vec![StreamSource {
                url: SourceUrl::parse("fake://127.0.0.1/").unwrap(),
                options: serde_json::Map::new(),
                protocol: "fake",
                connection: "c1".into(),
            }],
            preload,
            audio: AudioMode::Auto,
            orientation: Orientation::NoTransform,
            created: SystemTime::UNIX_EPOCH,
        }
    }

    /// A viewer session of `stream_id` on connection `c1`.
    fn session_on_c1(serial: u64, stream_id: &str) -> SessionEntry {
        let (events, _events) = mpsc::channel(1);
        SessionEntry::new(
            serial,
            stream_id.into(),
            "c1".into(),
            format!("u{serial}"),
            (ConnectionId(1), serial, events),
            SystemTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn a_subscription_whose_receiver_is_gone_is_forgotten_at_the_next_subscribe() {
        let mut state = State::default();
        let first = state.subscribe(ConnectionId(1), Some("never".into()));
        let open = state.subscribe(ConnectionId(1), None);
        drop(first);
        // No event ever reaches `never`, so only `subscribe` can reap it.
        let _second = state.subscribe(ConnectionId(1), Some("never".into()));
        assert_eq!(state.subscribers.len(), 2);
        assert!(state.subscribers.iter().all(|s| !s.events.is_closed()));
        drop(open);
    }

    #[test]
    fn a_subscription_to_all_gets_every_stream_first_with_the_whole_queue_still_free() {
        let mut state = State::default();
        let count = SUBSCRIPTION_QUEUE + 1;
        for n in 0..count {
            state
                .streams
                .insert(format!("s{n:04}"), stream_on_c1(false));
        }
        let mut all = state.subscribe(ConnectionId(1), None);
        let mut one = state.subscribe(ConnectionId(1), Some("s0256".into()));
        // The snapshot is queued and the usual room is still free.
        assert_eq!(state.subscribers[0].events.capacity(), SUBSCRIPTION_QUEUE);
        assert_eq!(state.subscribers[1].events.capacity(), SUBSCRIPTION_QUEUE);
        let mut ids = Vec::new();
        while let Ok(event) = all.try_recv() {
            ids.push(event.payload["stream_id"].clone());
        }
        assert_eq!(ids.len(), count, "the snapshot is never cut");
        assert_eq!(ids.last().unwrap(), "s0256");
        assert_eq!(one.try_recv().unwrap().payload["stream_id"], "s0256");
        assert!(one.try_recv().is_err(), "one stream, one event");
    }

    #[test]
    fn demand_counts_each_preloaded_stream_and_each_viewer_of_the_connection() {
        let mut state = State::default();
        let (demand, rx) = watch::channel(0);
        let (commands, _commands) = mpsc::channel(1);
        state.connections.insert(
            "c1".into(),
            ConnectionEntry {
                port: None,
                loopback_relay: false,
                key: ConnectionKey {
                    url: SourceUrl::parse("fake://127.0.0.1/").unwrap(),
                    options: serde_json::Value::Null,
                },
                demand,
                snapshot: ConnectionSnapshot::idle(SystemTime::UNIX_EPOCH),
                streams: ["front".to_owned(), "twin".to_owned()].into(),
                commands,
            },
        );
        state.streams.insert("front".into(), stream_on_c1(true));
        state.streams.insert("twin".into(), stream_on_c1(false));
        state.refresh_connection("c1");
        assert_eq!(*rx.borrow(), 1, "one preloaded stream, no viewers");
        state.sessions.insert("s1".into(), session_on_c1(1, "twin"));
        state.refresh_connection("c1");
        assert_eq!(*rx.borrow(), 2, "plus a viewer of the other stream");
        // Both streams preloaded: each counts, so turning one off later
        // leaves the connection wanted.
        state.streams.insert("twin".into(), stream_on_c1(true));
        state.refresh_connection("c1");
        assert_eq!(*rx.borrow(), 3);
        state.streams.insert("front".into(), stream_on_c1(false));
        state.streams.insert("twin".into(), stream_on_c1(false));
        state.refresh_connection("c1");
        assert_eq!(*rx.borrow(), 1, "the viewer alone keeps it wanted");
        assert!(state.finish_session("s1").is_some());
        assert_eq!(*rx.borrow(), 0, "no preload, no viewer: no demand");
        // A stream that left the connection no longer counts; with none
        // left the connection is released, which stops its driver.
        state.streams.insert("front".into(), stream_on_c1(true));
        state.streams.remove("twin");
        state.refresh_connection("c1");
        assert_eq!(*rx.borrow(), 1);
        assert_eq!(
            state.connections["c1"].streams,
            BTreeSet::from(["front".to_owned()])
        );
        state.streams.remove("front");
        state.refresh_connection("c1");
        assert!(state.connections.is_empty());
        assert!(rx.has_changed().is_err(), "the demand sender is dropped");
        state.refresh_connection("c1");
    }

    /// A state with connection `c1`, whose driver queue holds one
    /// command, and its session `s1` (serial 1), gathering `gathers`.
    fn relay_state(gathers: usize) -> (State, mpsc::Receiver<DriverCommand>) {
        let mut state = State::default();
        let (demand, _demand) = watch::channel(0);
        let (commands, rx) = mpsc::channel(1);
        state.connections.insert(
            "c1".into(),
            ConnectionEntry {
                port: None,
                loopback_relay: false,
                key: ConnectionKey {
                    url: SourceUrl::parse("fake://127.0.0.1/").unwrap(),
                    options: serde_json::Value::Null,
                },
                demand,
                snapshot: ConnectionSnapshot::idle(SystemTime::UNIX_EPOCH),
                streams: BTreeSet::new(),
                commands,
            },
        );
        let mut session = session_on_c1(1, "front");
        session.gathering(gathers);
        state.sessions.insert("s1".into(), session);
        (state, rx)
    }

    fn relayed(port: u16) -> Relayed {
        Relayed {
            lease: crate::net::turn_client::Lease::detached(SocketAddr::from((
                [203, 0, 113, 1],
                port,
            ))),
            server: "192.0.2.3:3478".parse().unwrap(),
            transport: Transport::Tcp,
            local: "192.0.2.1:18556".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn a_relay_lease_goes_to_the_worker_unless_too_late_or_its_queue_is_full() {
        let (mut state, mut rx) = relay_state(4);
        // Another session, or an earlier one under the same id: released.
        state.session_relayed("ghost", 1, Some(relayed(1)));
        state.session_relayed("s1", 2, Some(relayed(1)));
        assert!(rx.try_recv().is_err());
        state.session_relayed("s1", 1, Some(relayed(1)));
        let Ok(DriverCommand::RelayCandidate {
            session_id,
            relayed: address,
            server,
            local,
            tcp,
            grant: _,
        }) = rx.try_recv()
        else {
            panic!("a relay candidate for the worker");
        };
        assert_eq!(
            (session_id.as_str(), address, server, local, tcp),
            (
                "s1",
                SocketAddr::from(([203, 0, 113, 1], 1)),
                "192.0.2.3:3478".parse().unwrap(),
                "192.0.2.1:18556".parse().unwrap(),
                true
            )
        );
        // A full queue: the gather ends without it; so does a failed one.
        state
            .connections
            .get("c1")
            .unwrap()
            .commands
            .try_send(DriverCommand::Candidate {
                session_id: "x".into(),
                candidate: String::new(),
            })
            .unwrap();
        state.session_relayed("s1", 1, Some(relayed(2)));
        state.session_relayed("s1", 1, None);
        let session = state.sessions.get_mut("s1").unwrap();
        session
            .apply(lotse_ipc::SessionEvent::Answer { sdp: "v=0".into() })
            .unwrap();
        session
            .apply(lotse_ipc::SessionEvent::Candidate {
                candidate: String::new(),
                mid: None,
            })
            .unwrap();
        assert!(
            !session.candidates_done(),
            "the first relay and one more gather"
        );
        session.gather_deadline();
        assert!(session.candidates_done());
        // After end-of-candidates a lease is too late.
        let _queued = rx.try_recv();
        state.session_relayed("s1", 1, Some(relayed(3)));
        assert!(rx.try_recv().is_err());
        // A channel on the relay the worker has: bound on its lease, which
        // here holds no allocation, so it is refused and logged.
        state.session_report(
            "c1",
            "s1",
            lotse_ipc::SessionEvent::ChannelWanted {
                relayed: SocketAddr::from(([203, 0, 113, 1], 1)),
                peer: "192.0.2.9:5000".parse().unwrap(),
            },
            lotse_core::clock::SystemClock.now(),
        );
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_connection_key_compares_url_and_options_and_debug_keeps_their_secrets() {
        let key = |url: &str, options: serde_json::Value| ConnectionKey {
            url: SourceUrl::parse(url).unwrap(),
            options,
        };
        let secret = key(
            "rtsp://admin:hunter2@cam/main",
            serde_json::json!({ "token": "sesame-open", "timeout_ms": 5000 }),
        );
        let text = format!("{secret:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("sesame-open"), "{text}");
        assert!(!text.contains("5000"), "{text}");
        assert!(text.contains("[\"timeout_ms\", \"token\"]"), "{text}");
        assert!(text.contains("cam/main"), "{text}");
        assert_eq!(
            format!("{:?}", key("fake://cam/", serde_json::Value::Null)),
            format!(
                "ConnectionKey {{ url: {:?}, options: [] }}",
                SourceUrl::parse("fake://cam/").unwrap()
            )
        );
        // The options and the credentials are part of the key.
        assert_ne!(
            secret,
            key(
                "rtsp://admin:hunter2@cam/main",
                serde_json::json!({ "token": "other", "timeout_ms": 5000 })
            )
        );
        assert_ne!(
            secret,
            key(
                "rtsp://admin:other@cam/main",
                serde_json::json!({ "token": "sesame-open", "timeout_ms": 5000 })
            )
        );
    }

    #[test]
    fn tracks_and_streams_are_reported_with_their_counters() {
        let stats = WorkerStats {
            tracks: vec![(
                "a1".into(),
                TrackStats {
                    packets: 5,
                    packet_bytes: 300,
                    frames: 5,
                    frame_bytes: 200,
                    keyframes: 5,
                    frames_dropped_oversize: 2,
                    frames_over_browser_limit: 3,
                },
            )],
            sessions: 1,
            send_failures: 0,
            av_sync_lost: 1,
            relay_unbound: 0,
            tasks: 0,
            packets_lost: 4,
            packets_out_of_order: 5,
            datagrams_rejected: 6,
        };
        let stream = stream_stats_of(Some(&stats));
        assert_eq!(
            (
                stream.frames_dropped,
                stream.frames_over_browser_limit,
                stream.av_sync_lost
            ),
            (2, 3, 1)
        );
        assert_eq!(
            (
                stream.packets_lost,
                stream.packets_out_of_order,
                stream.datagrams_rejected
            ),
            (4, 5, 6)
        );
        assert_eq!(stream_stats_of(None), StreamStats::default());
        let derived = track_dto(&ipc_track("a1", Some("a0"), Some(88)), Some(&stats));
        assert_eq!(
            (
                derived.derived_from.as_deref(),
                derived.audio_delay_ms,
                derived.frames,
                derived.bytes
            ),
            (Some("a0"), Some(88), 5, 300)
        );
        assert_eq!(derived.sync, "sender_reports");
        let native = track_dto(&ipc_track("a0", None, None), None);
        assert_eq!(
            (native.derived_from, native.audio_delay_ms, native.frames),
            (None, None, 0)
        );
    }
}
