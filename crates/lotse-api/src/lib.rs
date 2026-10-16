//! Control API server: axum on the Unix socket, peer-credential check,
//! the opt-in mutual-TLS listener ([`tls`]) with its server identity,
//! WebSocket command and subscription dispatch, and the snapshot route.
//!
//! Runs in the supervisor. Defines the [`Handler`] trait the supervisor
//! implements, so this crate never depends on the supervisor (dependency
//! inversion). Its own accept loops authenticate the peer before any byte
//! is read (the uid on the socket, the certificate pin over TLS) and serve
//! each connection on hyper's HTTP/1.1 with its own
//! upgrade limits (`axum::serve` sets none): a 16 KiB request head, 32
//! header fields, a deadline from accept to the upgrade on the injected
//! clock, and a bound on connections awaiting it. Enforces the request
//! limits and the ordering and backpressure rules of the control API:
//! strictly increasing ids, one `result` per command, a bounded outbound
//! queue that sheds low-value traffic and disconnects a client that still
//! overflows it, and a deadline on the closing handshake, so a peer that
//! stops reading cannot hold a connection or its slot.
//!
//! Standards: RFC 6455 (WebSocket, close codes §7.4.1, `Origin` §10.2),
//! RFC 9110 (HTTP), RFC 6585 §5 (431 for an oversized request head),
//! unix(7) `SO_PEERCRED`, RFC 8446 (TLS 1.3, in [`tls`]).

use std::future::Future;
use std::net::SocketAddr;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::time::Duration;

use axum::routing::get;
use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use lotse_api_types::command::Command;
use lotse_api_types::error::ApiError;
use lotse_api_types::frame::Hello;
use lotse_core::clock::Clock;
use lotse_core::task::{BoxFuture, spawn_named};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tokio_util::task::task_tracker::TaskTrackerToken;

mod clients;
mod connection;
pub mod identity;
mod listener;
mod outbox;
pub mod pairing;
pub mod tls;

pub use clients::ClientsError;
pub use listener::{BindError, PeerInfo};
pub use tls::TlsConfig;

/// The largest inbound WebSocket message, and so frame: 64 KiB, enough for
/// an SDP offer with many candidates. A frame announcing more is refused
/// at its header, before its payload is buffered.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The bounded outbound queue per connection: 1 MiB.
pub const OUTBOUND_BUDGET_BYTES: usize = 1024 * 1024;

/// The largest upgrade request head: 16 KiB.
/// It bounds hyper's read buffer; a head that does not fit is answered
/// `431 Request Header Fields Too Large` (RFC 6585 §5) and closed.
pub const MAX_UPGRADE_HEADER_BYTES: usize = 16 * 1024;

/// The most header fields in the upgrade request: 32, where a WebSocket
/// upgrade sends about ten. More are answered 431 (RFC 6585 §5).
pub const MAX_UPGRADE_HEADERS: usize = 32;

/// From accept to the upgrade: 10 s, after which the connection is closed
/// without a response. A local client sends its upgrade at once; this only
/// stops a peer that sends a request slowly or never.
pub const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);

/// From the close frame being queued to the socket being dropped: 5 s,
/// the `pong` timeout a client is expected to keep.
/// The connection's sessions are orphaned and its slot is released before
/// the wait; the deadline only bounds a peer that stopped reading, whose
/// socket is then dropped with the rest of its queue and the close frame
/// unsent (RFC 6455 §7.1.1: the server may close the underlying connection
/// without waiting on the client; a peer that reads nothing would never see
/// the Close anyway).
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Connections accepted and not yet upgraded, at once: 8. One more is
/// closed at accept, without a response. A TLS connection takes its place
/// when it authenticates, and holds it while it waits for the serve loop.
pub const MAX_PENDING_UPGRADES: u16 = 8;

/// A control connection, numbered from one for the daemon's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub u64);

/// How an event may be shed under backpressure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventClass {
    /// Never dropped: answers, candidates, `closed`.
    Signaling,
    /// Coalesced: the latest state per stream wins.
    StreamState {
        /// The stream the event is about.
        stream_id: String,
    },
    /// A subscription's state report, a session's `state`: coalesced per
    /// subscription (the latest wins), and dropped first, when it would
    /// take the outbound queue past half its budget.
    Diagnostic,
    /// Not an event but the handler's last word on a subscription whose
    /// own queue had no room for a [`EventClass::Signaling`] one: the
    /// client would miss it, so the connection is closed as when its
    /// outbound queue overflows (`1008`). Its payload is ignored, and
    /// nothing after it is sent.
    Overflowed,
}

/// One event of a subscription, as the handler produces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// How it may be shed.
    pub class: EventClass,
    /// The `event` object of the frame.
    pub payload: serde_json::Value,
}

/// What the handler answers a command with.
#[derive(Debug)]
pub enum Outcome {
    /// A successful `result`.
    Result(serde_json::Value),
    /// A failed `result`.
    Error(ApiError),
    /// An empty `result`, then the events on this channel until it closes
    /// or the client unsubscribes.
    Subscribed(mpsc::Receiver<Event>),
}

/// What the supervisor implements. `ping`, `schema`, `unsubscribe`,
/// `pairing/create`, `clients/list` and `clients/remove` are answered by
/// the server itself; everything else goes here.
pub trait Handler: Send + Sync + 'static {
    /// The `hello` frame's content.
    fn hello(&self) -> Hello;

    /// Handles one command of `connection`. Never waits on a camera. The
    /// future is dropped at an await point when the connection's client is
    /// removed or the daemon shuts down before it ends, so what it changes
    /// it changes between two awaits, never across one.
    fn handle(
        &self,
        connection: ConnectionId,
        command: Command,
    ) -> impl Future<Output = Outcome> + Send;

    /// `unsubscribe` ended subscription `subscription` of `connection`; the
    /// forwarder is already stopped. A returned event is sent as the
    /// subscription's last, before the `unsubscribe` result: a session's
    /// `closed`.
    fn unsubscribed(&self, connection: ConnectionId, subscription: u64) -> Option<Event> {
        let _ = (connection, subscription);
        None
    }

    /// The connection is gone; its sessions are now orphaned.
    fn connection_closed(&self, connection: ConnectionId) {
        let _ = connection;
    }
}

/// The server's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The socket path; its directory must be 0700 and owned by `owner_uid`.
    pub socket: PathBuf,
    /// The uid the daemon started as: owns the socket directory and may
    /// always connect.
    pub owner_uid: u32,
    /// A second uid allowed to connect (`--allow-uid`).
    pub allow_uid: u32,
    /// Control connections at once.
    pub max_connections: u32,
    /// Open subscriptions per connection (`stream/subscribe`,
    /// `webrtc/offer`, `session/adopt`); one more is answered
    /// `limit_reached` before the handler sees it. Ended ones do not count.
    pub max_subscriptions: u32,
    /// The mutual-TLS listener, if one is configured.
    pub tls: Option<TlsConfig>,
}

/// What every connection shares.
struct AppState<H> {
    /// The supervisor's side.
    handler: Arc<H>,
    /// The settings.
    config: Config,
    /// Open connections, against `max_connections`.
    connections: Arc<AtomicU32>,
    /// The next connection id.
    next_id: Arc<AtomicU64>,
    /// Cancelled on graceful shutdown.
    shutdown: CancellationToken,
    /// Times the closing handshake ([`CLOSE_TIMEOUT`]).
    clock: Arc<dyn Clock>,
    /// The TLS listener's pairing, for `pairing/create`; `None` without a
    /// listener.
    pairing: Option<Arc<pairing::Pairing>>,
    /// The TLS listener's clients, for `clients/list` and `clients/remove`
    /// and to close a removed client's connections; `None` without a
    /// listener.
    clients: Option<Arc<clients::ClientStore>>,
    /// Held by everything that serves a connection, and by the commands
    /// about the TLS listener's clients still at the disk: [`Server::serve`]
    /// returns once the last is dropped, so nothing it began, the client
    /// store's lock least of all, outlives it.
    serving: TaskTrackerToken,
}

impl<H> Clone for AppState<H> {
    fn clone(&self) -> Self {
        Self {
            handler: Arc::clone(&self.handler),
            config: self.config.clone(),
            connections: Arc::clone(&self.connections),
            next_id: Arc::clone(&self.next_id),
            shutdown: self.shutdown.clone(),
            clock: Arc::clone(&self.clock),
            pairing: self.pairing.clone(),
            clients: self.clients.clone(),
            serving: self.serving.clone(),
        }
    }
}

/// The listeners, bound in the main thread before the privilege drop.
#[derive(Debug)]
pub struct Server {
    /// The Unix socket.
    unix: std::os::unix::net::UnixListener,
    /// The TLS listener, if configured.
    tls: Option<tls::BoundTls>,
    /// The settings.
    config: Config,
}

/// Why serving stopped early.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// A listener could not be registered with the runtime.
    #[error("registering the listener with the runtime: {0}")]
    Register(#[source] std::io::Error),
    /// The TLS listener's configuration could not be built.
    #[error("control TLS configuration: {0}")]
    Tls(#[source] rustls::Error),
}

impl Server {
    /// Binds the Unix socket synchronously, with the control plane's checks:
    /// no abstract namespace, a 0700 directory owned by `owner_uid`, umask
    /// 0177 around the bind. With [`Config::tls`], also loads or makes the
    /// server identity and binds the TLS listener ([`tls`]).
    pub fn bind(config: Config) -> Result<Self, BindError> {
        let unix = listener::bind_unix(&config.socket, config.owner_uid)?;
        let tls = config
            .tls
            .as_ref()
            .map(|settings| tls::bind(settings, config.owner_uid))
            .transpose()?;
        Ok(Self { unix, tls, config })
    }

    /// The directory the daemon writes at runtime (the TLS listener's
    /// enrolled clients), for the sandbox: its path, for the logs, and the
    /// descriptor it was checked and locked through, which the sandbox's
    /// rule must be made from; `None` without a listener.
    pub fn state_dir(&self) -> Option<(&Path, BorrowedFd<'_>)> {
        self.tls.as_ref().map(|bound| bound.store.dir())
    }

    /// The address the TLS listener is bound to, if there is one.
    pub fn tls_local_addr(&self) -> Option<SocketAddr> {
        self.tls
            .as_ref()
            .and_then(|bound| bound.listener.local_addr().ok())
    }

    /// Serves until `shutdown` is cancelled: then no new connections, the
    /// ones not yet upgraded (or still in their TLS handshake) are closed,
    /// every upgraded one gets `shutdown` and a `1001` close, and the call
    /// returns once each has closed, within [`CLOSE_TIMEOUT`], and no
    /// command about the TLS listener's clients is still at the disk: the
    /// data directory can be bound again at once. `clock` times the
    /// handshake, upgrade and close deadlines.
    pub async fn serve<H: Handler>(
        self,
        handler: Arc<H>,
        clock: Arc<dyn Clock>,
        shutdown: CancellationToken,
    ) -> Result<(), ServeError> {
        let allowed = [self.config.owner_uid, self.config.allow_uid];
        let mut unix = listener::CheckedUnix::new(self.unix, allowed, Arc::clone(&clock))
            .map_err(ServeError::Register)?;
        let pending = Arc::new(Semaphore::new(usize::from(MAX_PENDING_UPGRADES)));
        // Each queued connection holds one of `pending`'s permits, so the
        // queue never fills and a handshake task never waits to send.
        let (admitted, mut authenticated) = mpsc::channel(usize::from(MAX_PENDING_UPGRADES));
        let (tls, pairing, clients) = match self.tls {
            Some(bound) => {
                let pairing = bound.pairing(Arc::clone(&clock));
                let config = bound
                    .server_config(Arc::clone(&pairing))
                    .map_err(ServeError::Tls)?;
                let listener = tokio::net::TcpListener::from_std(bound.listener)
                    .map_err(ServeError::Register)?;
                tls::announce_first_code(&pairing, &bound.store, &clock, &shutdown);
                let clients = Arc::clone(&bound.store);
                let accepting = spawn_named(
                    "api.tls_accept",
                    tls::accept_loop(
                        listener,
                        tls::Handshakes {
                            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
                            gate: Arc::default(),
                            clock: Arc::clone(&clock),
                            shutdown: shutdown.clone(),
                            upgrades: Arc::clone(&pending),
                            admitted,
                            store: bound.store,
                            pairing: Arc::clone(&pairing),
                        },
                    ),
                );
                (Some(accepting), Some(pairing), Some(clients))
            }
            None => (None, None, None),
        };
        let serving = TaskTracker::new();
        let state = AppState {
            handler,
            config: self.config,
            connections: Arc::new(AtomicU32::new(0)),
            next_id: Arc::new(AtomicU64::new(1)),
            shutdown: shutdown.clone(),
            clock: Arc::clone(&clock),
            pairing,
            clients,
            serving: serving.token(),
        };
        let app = Router::new()
            .route(lotse_api_types::WS_PATH, get(connection::upgrade::<H>))
            .with_state(state);
        let mut http = http1::Builder::new();
        // Keep-alive stays on: hyper's `Connection: close` would replace the
        // 101's `Connection: Upgrade`. The deadline bounds what a kept-alive
        // connection can send before it upgrades.
        http.max_buf_size(MAX_UPGRADE_HEADER_BYTES)
            .max_headers(MAX_UPGRADE_HEADERS);
        let admission = Admission {
            app,
            http,
            pending,
            clock,
            shutdown: shutdown.clone(),
        };
        tracing::info!(event = "api_listening", "control API listening");
        loop {
            tokio::select! {
                (stream, peer) = unix.accept() => admission.admit(stream, peer),
                Some(tls) = authenticated.recv() => admission.serve(tls.stream, tls.peer, tls.slot, tls.deadline),
                () = shutdown.cancelled() => break,
            }
        }
        drop(unix);
        if let Some(accepting) = tls {
            let _stopped = accepting.await;
            // Every handshake task holds a sender, so the channel closes
            // once the last one has ended and closed its socket. One that
            // authenticated meanwhile is dropped here, closed, and gives its
            // slot back.
            while authenticated.recv().await.is_some() {}
        }
        drop(authenticated);
        let drained = admission
            .pending
            .acquire_many(u32::from(MAX_PENDING_UPGRADES))
            .await;
        drop(drained);
        tracing::info!("control API stopped accepting");
        // The router holds the state, and with it a token, as does every
        // upgraded connection until it has closed.
        drop(admission);
        serving.close();
        serving.wait().await;
        tracing::info!("control API stopped: every connection closed");
        Ok(())
    }
}

/// What every authenticated connection is served with, from either
/// listener.
struct Admission {
    /// The router, with the shared state.
    app: Router,
    /// HTTP/1.1 with the upgrade limits.
    http: http1::Builder,
    /// Connections accepted and not yet upgraded.
    pending: Arc<Semaphore>,
    /// Times the upgrade deadline.
    clock: Arc<dyn Clock>,
    /// Cancelled on graceful shutdown.
    shutdown: CancellationToken,
}

impl Admission {
    /// Serves `stream`, whose peer is `peer`, up to its upgrade, unless
    /// [`MAX_PENDING_UPGRADES`] connections are already waiting for theirs:
    /// then it is closed without a response.
    fn admit<S>(&self, stream: S, peer: PeerInfo)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let Some(slot) = upgrade_slot(&self.pending, &peer) else {
            return;
        };
        self.serve(stream, peer, slot, self.clock.sleep(UPGRADE_TIMEOUT));
    }

    /// Serves `stream`, whose peer is `peer`, up to its upgrade, in the
    /// pending `slot` it was given, and closes it at `deadline` if it has
    /// not upgraded by then.
    fn serve<S>(
        &self,
        stream: S,
        peer: PeerInfo,
        slot: OwnedSemaphorePermit,
        deadline: BoxFuture<'static, ()>,
    ) where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let service = TowerToHyperService::new(self.app.clone().layer(Extension(peer.clone())));
        let connection = self
            .http
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades();
        spawn_named(
            "api.handshake",
            handshake(connection, deadline, self.shutdown.clone(), peer, slot),
        );
    }
}

/// A place among the [`MAX_PENDING_UPGRADES`] connections awaiting their
/// upgrade, from `pending`, for `peer`; `None`, logged, when there is none
/// and the connection is to be closed without a response.
pub(crate) fn upgrade_slot(
    pending: &Arc<Semaphore>,
    peer: &PeerInfo,
) -> Option<OwnedSemaphorePermit> {
    let slot = Arc::clone(pending).try_acquire_owned().ok();
    if slot.is_none() {
        tracing::warn!(
            %peer,
            max = MAX_PENDING_UPGRADES,
            "control connection refused: too many connections awaiting the upgrade"
        );
    }
    slot
}

/// Drives one connection from accept to the upgrade, after which the
/// connection task in [`connection`] owns it. Closes it at `deadline` or
/// on shutdown if it has not upgraded by then, and returns the pending
/// slot either way.
async fn handshake<F>(
    connection: F,
    deadline: BoxFuture<'static, ()>,
    shutdown: CancellationToken,
    peer: PeerInfo,
    permit: OwnedSemaphorePermit,
) where
    F: Future<Output = hyper::Result<()>> + Send,
{
    tokio::select! {
        served = connection => {
            if let Err(err) = served {
                tracing::debug!(%peer, error = %err, "control connection ended before the upgrade");
            }
        }
        () = deadline => {
            let timeout_ms = UPGRADE_TIMEOUT.as_millis();
            tracing::warn!(
                %peer,
                timeout_ms,
                "control connection closed: no upgrade before the deadline"
            );
        }
        () = shutdown.cancelled() => tracing::debug!(
            %peer,
            "control connection closed before the upgrade: shutting down"
        ),
    }
    drop(permit);
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_api_types::error::ErrorCode;
    use lotse_api_types::frame::HelloTag;

    use super::*;

    /// A handler that keeps every default.
    pub(crate) struct Minimal;

    impl Handler for Minimal {
        fn hello(&self) -> Hello {
            Hello {
                kind: HelloTag::default(),
                api: lotse_api_types::API_VERSION.into(),
                version: "0".into(),
                outputs: vec![],
                features: vec![],
            }
        }

        fn handle(
            &self,
            _connection: ConnectionId,
            _command: Command,
        ) -> impl Future<Output = Outcome> + Send {
            std::future::ready(Outcome::Result(serde_json::Value::Null))
        }
    }

    #[tokio::test]
    async fn the_default_hooks_have_no_last_word_and_no_side_effect() {
        let handler = Minimal;
        let ping = lotse_api_types::parse_command(r#"{"id":1,"type":"info"}"#).unwrap();
        assert!(matches!(
            handler.handle(ConnectionId(1), ping).await,
            Outcome::Result(serde_json::Value::Null)
        ));
        assert!(handler.unsubscribed(ConnectionId(1), 2).is_none());
        handler.connection_closed(ConnectionId(1));
        assert_eq!(handler.hello().api, lotse_api_types::API_VERSION);
    }

    /// A WebSocket upgrade as the router extracts it, from a request the
    /// connection cannot actually upgrade.
    async fn ws_upgrade() -> axum::extract::ws::WebSocketUpgrade {
        use axum::extract::FromRequestParts as _;

        let mut request = axum::http::Request::builder()
            .uri(lotse_api_types::WS_PATH)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap();
        let on_upgrade = hyper::upgrade::on(&mut request);
        let (mut parts, ()) = request.into_parts();
        parts.extensions.insert(on_upgrade);
        axum::extract::ws::WebSocketUpgrade::from_request_parts(&mut parts, &())
            .await
            .unwrap()
    }

    /// What every connection shares, with `max_connections` and the
    /// shutdown begun or not.
    pub(crate) fn state(max_connections: u32, shutting_down: bool) -> AppState<Minimal> {
        let shutdown = CancellationToken::new();
        if shutting_down {
            shutdown.cancel();
        }
        AppState {
            handler: Arc::new(Minimal),
            config: Config {
                socket: PathBuf::from("/run/lotse/lotse.sock"),
                owner_uid: 0,
                allow_uid: 0,
                max_connections,
                max_subscriptions: 1,
                tls: None,
            },
            connections: Arc::new(AtomicU32::new(0)),
            next_id: Arc::new(AtomicU64::new(1)),
            shutdown,
            clock: Arc::new(lotse_core::clock::FakeClock::default()),
            pairing: None,
            clients: None,
            serving: TaskTracker::new().token(),
        }
    }

    /// `upgrade`'s answer for `state` and `headers`, its status and its
    /// error code.
    async fn answer_with(
        state: AppState<Minimal>,
        headers: axum::http::HeaderMap,
    ) -> (u16, serde_json::Value) {
        let peer = PeerInfo::Unix { uid: 0, pid: None };
        let response = connection::upgrade(
            axum::extract::State(state),
            Extension(peer),
            headers,
            ws_upgrade().await,
        )
        .await;
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let code = serde_json::from_slice::<serde_json::Value>(&body)
            .map_or(serde_json::Value::Null, |error| error["code"].clone());
        (status, code)
    }

    /// `upgrade`'s answer for `state` to a request without `Origin`.
    async fn answer(state: AppState<Minimal>) -> (u16, serde_json::Value) {
        answer_with(state, axum::http::HeaderMap::new()).await
    }

    #[tokio::test]
    async fn an_upgrade_carrying_origin_is_refused_with_403_rfc6455_10_2() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("origin", "https://example.com".parse().unwrap());
        let state = state(1, false);
        let connections = Arc::clone(&state.connections);
        assert_eq!(
            answer_with(state, headers).await,
            (403, ErrorCode::InvalidRequest.as_str().into())
        );
        assert_eq!(
            connections.load(std::sync::atomic::Ordering::Acquire),
            0,
            "no slot taken"
        );
    }

    /// The upgrade handler driven directly, every check in one
    /// instantiation: over a socket, an upgrade read just before the
    /// shutdown is closed at the cancel as often as it is answered.
    #[tokio::test]
    async fn an_upgrade_is_refused_while_shutting_down_or_at_the_limit_and_else_switches() {
        let shutting_down = state(1, true);
        let connections = Arc::clone(&shutting_down.connections);
        assert_eq!(
            answer(shutting_down).await,
            (503, ErrorCode::ShuttingDown.as_str().into())
        );
        assert_eq!(
            connections.load(std::sync::atomic::Ordering::Acquire),
            0,
            "no slot taken"
        );
        assert_eq!(
            answer(state(0, false)).await,
            (503, ErrorCode::LimitReached.as_str().into())
        );
        // RFC 6455 §4.2.2: the handshake is answered 101 Switching Protocols.
        assert_eq!(
            answer(state(1, false)).await,
            (101, serde_json::Value::Null)
        );
    }
}
