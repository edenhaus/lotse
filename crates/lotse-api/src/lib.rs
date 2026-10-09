//! Control API server: axum on the Unix socket, peer-credential check,
//! WebSocket command and subscription dispatch, and the snapshot route.
//!
//! Runs in the supervisor. Defines the [`Handler`] trait the supervisor
//! implements, so this crate never depends on the supervisor (dependency
//! inversion). Its own accept loop checks the peer's uid before any byte
//! is read and serves each connection on hyper's HTTP/1.1 with its own
//! upgrade limits (`axum::serve` sets none): a 16 KiB request head, 32
//! header fields, a deadline from accept to the upgrade on the injected
//! clock, and a bound on connections awaiting it. Enforces the request
//! limits and the ordering and backpressure rules of the control API:
//! strictly increasing ids, one `result` per command, a bounded outbound
//! queue that sheds low-value traffic and disconnects a client that still
//! overflows it, and a deadline on the closing handshake, so a peer that
//! stops reading cannot hold a connection or its slot.
//!
//! Standards: RFC 6455 (WebSocket, close codes §7.4.1), RFC 9110 (HTTP),
//! RFC 6585 §5 (431 for an oversized request head), unix(7) `SO_PEERCRED`.

use std::future::Future;
use std::path::PathBuf;
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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

mod connection;
mod listener;
mod outbox;

pub use listener::{BindError, PeerInfo};

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
/// closed at accept, without a response.
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
    /// Dropped first: `state` diagnostics.
    Diagnostic,
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

/// What the supervisor implements. `ping`, `schema` and `unsubscribe` are
/// answered by the server itself; everything else goes here.
pub trait Handler: Send + Sync + 'static {
    /// The `hello` frame's content.
    fn hello(&self) -> Hello;

    /// Handles one command of `connection`. Never waits on a camera.
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
        }
    }
}

/// The listener, bound in the main thread before the privilege drop.
#[derive(Debug)]
pub struct Server {
    /// The Unix socket.
    unix: std::os::unix::net::UnixListener,
    /// The settings.
    config: Config,
}

/// Why serving stopped early.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// A listener could not be registered with the runtime.
    #[error("registering the listener with the runtime: {0}")]
    Register(#[source] std::io::Error),
}

impl Server {
    /// Binds the Unix socket synchronously, with the control plane's checks:
    /// no abstract namespace, a 0700 directory owned by `owner_uid`, umask
    /// 0177 around the bind.
    pub fn bind(config: Config) -> Result<Self, BindError> {
        let unix = listener::bind_unix(&config.socket, config.owner_uid)?;
        Ok(Self { unix, config })
    }

    /// Serves until `shutdown` is cancelled: then no new connections, the
    /// ones not yet upgraded are closed, every upgraded one gets `shutdown`
    /// and a `1001` close, and the call returns. `clock` times the upgrade
    /// and close deadlines.
    pub async fn serve<H: Handler>(
        self,
        handler: Arc<H>,
        clock: Arc<dyn Clock>,
        shutdown: CancellationToken,
    ) -> Result<(), ServeError> {
        let allowed = [self.config.owner_uid, self.config.allow_uid];
        let state = AppState {
            handler,
            config: self.config,
            connections: Arc::new(AtomicU32::new(0)),
            next_id: Arc::new(AtomicU64::new(1)),
            shutdown: shutdown.clone(),
            clock: Arc::clone(&clock),
        };
        let app = Router::new()
            .route(lotse_api_types::WS_PATH, get(connection::upgrade::<H>))
            .with_state(state);

        let mut unix = listener::CheckedUnix::new(self.unix, allowed, Arc::clone(&clock))
            .map_err(ServeError::Register)?;
        let mut http = http1::Builder::new();
        // Keep-alive stays on: hyper's `Connection: close` would replace the
        // 101's `Connection: Upgrade`. The deadline bounds what a kept-alive
        // connection can send before it upgrades.
        http.max_buf_size(MAX_UPGRADE_HEADER_BYTES)
            .max_headers(MAX_UPGRADE_HEADERS);
        let pending = Arc::new(Semaphore::new(usize::from(MAX_PENDING_UPGRADES)));
        tracing::info!(event = "api_listening", "control API listening");
        loop {
            let (stream, peer) = tokio::select! {
                accepted = unix.accept() => accepted,
                () = shutdown.cancelled() => break,
            };
            let Ok(permit) = Arc::clone(&pending).try_acquire_owned() else {
                tracing::warn!(
                    uid = peer.uid,
                    pid = ?peer.pid,
                    max = MAX_PENDING_UPGRADES,
                    "control connection refused: too many connections awaiting the upgrade"
                );
                continue;
            };
            let service = TowerToHyperService::new(app.clone().layer(Extension(peer.clone())));
            let connection = http
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            spawn_named(
                "api.handshake",
                handshake(
                    connection,
                    clock.sleep(UPGRADE_TIMEOUT),
                    shutdown.clone(),
                    peer,
                    permit,
                ),
            );
        }
        drop(unix);
        let _drained = pending.acquire_many(u32::from(MAX_PENDING_UPGRADES)).await;
        tracing::info!("control API stopped accepting");
        Ok(())
    }
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
                tracing::debug!(uid = peer.uid, pid = ?peer.pid, error = %err, "control connection ended before the upgrade");
            }
        }
        () = deadline => {
            let timeout_ms = UPGRADE_TIMEOUT.as_millis();
            tracing::warn!(
                uid = peer.uid,
                pid = ?peer.pid,
                timeout_ms,
                "control connection closed: no upgrade before the deadline"
            );
        }
        () = shutdown.cancelled() => tracing::debug!(
            uid = peer.uid,
            pid = ?peer.pid,
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
    struct Minimal;

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
    fn state(max_connections: u32, shutting_down: bool) -> AppState<Minimal> {
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
            },
            connections: Arc::new(AtomicU32::new(0)),
            next_id: Arc::new(AtomicU64::new(1)),
            shutdown,
            clock: Arc::new(lotse_core::clock::FakeClock::default()),
        }
    }

    /// `upgrade`'s answer for `state`, its status and its error code.
    async fn answer(state: AppState<Minimal>) -> (u16, serde_json::Value) {
        let peer = PeerInfo { uid: 0, pid: None };
        let response = connection::upgrade(
            axum::extract::State(state),
            Extension(peer),
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
