//! One control connection: the upgrade with its limit checks, `hello`,
//! the command loop with strictly increasing ids, subscriptions (capped per
//! connection, ended ones forgotten), the bounded outbound queue and the
//! close codes.
//!
//! Implements RFC 6455 §10.2 (an upgrade carrying `Origin`, which only a
//! browser sends, is refused with 403 as §4.2.2 allows: the control API is
//! not for web pages) and the RFC 6455 §7.4.1 close codes: `1001` going
//! away on shutdown, `1003` for a binary frame, `1008` policy violation on
//! an overflowed outbound queue or a removed client. Commands are processed
//! one at a time per connection; every one is non-blocking by contract. On close the sessions are
//! orphaned and the slot released first; the writer then gets
//! [`CLOSE_TIMEOUT`] to deliver the queue and the close frame, after which
//! the socket is dropped (RFC 6455 §7.1.1).

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Extension;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt as _, StreamExt as _};
use lotse_api_types::clients::ClientList;
use lotse_api_types::command::Command;
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::frame::{Empty, EventFrame, Failure, Pong, Shutdown, Success};
use lotse_api_types::pairing::PairingCreateResult;
use lotse_core::fingerprint::Fingerprint;
use lotse_core::task::spawn_blocking_named;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::clients::{ClientStore, Removal};
use crate::listener::PeerInfo;
use crate::outbox::{Class, Outbox, Outgoing};
use crate::pairing::Pairing;
use crate::{
    AppState, CLOSE_TIMEOUT, ConnectionId, Event, Handler, MAX_MESSAGE_BYTES,
    OUTBOUND_BUDGET_BYTES, Outcome,
};

/// RFC 6455 §7.4.1: going away.
const CLOSE_GOING_AWAY: u16 = 1001;

/// RFC 6455 §7.4.1: unsupported data (a binary frame).
const CLOSE_UNSUPPORTED_DATA: u16 = 1003;

/// RFC 6455 §7.4.1: policy violation (the outbound queue overflowed, or
/// the client was removed).
const CLOSE_POLICY_VIOLATION: u16 = 1008;

/// A JSON error body for a refused upgrade.
fn refuse(status: StatusCode, code: ErrorCode, message: &str) -> Response {
    let body = serde_json::to_string(&ApiError::new(code, message)).unwrap_or_default();
    (status, [("content-type", "application/json")], body).into_response()
}

/// `GET /v0/ws` ([`lotse_api_types::WS_PATH`]): the `Origin`, shutdown
/// and connection-limit checks, then the upgrade. The peer was
/// authenticated by its listener.
pub(crate) async fn upgrade<H: Handler>(
    State(state): State<AppState<H>>,
    Extension(peer): Extension<PeerInfo>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if headers.contains_key(header::ORIGIN) {
        tracing::warn!(%peer, "control connection refused: the request carries Origin, as only a browser sends");
        return refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest,
            "requests carrying Origin are refused: the control API is not for browsers",
        );
    }
    if state.shutdown.is_cancelled() {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ShuttingDown,
            "shutting down",
        );
    }
    let open = state.connections.fetch_add(1, Ordering::AcqRel);
    if open >= state.config.max_connections {
        state.connections.fetch_sub(1, Ordering::AcqRel);
        tracing::warn!(
            open,
            max = state.config.max_connections,
            "control connection refused: limit reached"
        );
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::LimitReached,
            "too many control connections",
        );
    }
    let slot = ConnectionSlot(Arc::clone(&state.connections));
    // tungstenite's default frame cap is 16 MiB and it reserves a frame's
    // announced length before the message cap applies; capping the frame
    // too refuses an oversized one at its header (RFC 6455 §5.2).
    ws.max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| run(socket, state, peer, slot))
}

/// The answer to a command about the TLS listener's clients
/// (`pairing/create`, `clients/list`, `clients/remove`), which the server
/// answers itself. Not generic over the handler, so every handler's
/// connection shares this one function.
async fn listener_answer(
    pairing: Option<&Pairing>,
    clients: Option<&Arc<ClientStore>>,
    peer: &PeerInfo,
    command: Command,
) -> serde_json::Value {
    let id = command.id();
    let outcome = match command {
        Command::ClientsList(_) => clients_list(clients).map(to_json),
        Command::ClientsRemove(remove) => clients_remove(clients, peer, &remove.pin)
            .await
            .map(to_json),
        _ => pairing_create(pairing, peer).map(to_json),
    };
    let frame = match outcome {
        Ok(result) => serde_json::to_value(Success::new(id, result)),
        Err(error) => serde_json::to_value(Failure::new(Some(id), error)),
    };
    frame.unwrap_or_default()
}

/// `value` as JSON.
fn to_json<T: serde::Serialize>(value: T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_default()
}

/// The refusal of a command about the TLS listener when there is none.
fn listener_off() -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest, "the control TLS listener is off")
}

/// `clients/list`: every pin the TLS listener lets in.
fn clients_list(clients: Option<&Arc<ClientStore>>) -> Result<ClientList, ApiError> {
    clients
        .map(|clients| clients.list())
        .ok_or_else(listener_off)
}

/// `clients/remove`: removes an enrolled pin and closes its connections.
/// Over the TLS listener a client may remove only itself; a fixed pin
/// stays; a pin that is not enrolled is already removed.
async fn clients_remove(
    clients: Option<&Arc<ClientStore>>,
    peer: &PeerInfo,
    pin: &str,
) -> Result<Empty, ApiError> {
    let Ok(pin) = Fingerprint::parse(pin) else {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "`pin` must be a certificate's SHA-256 as 64 hex digits, optionally with a colon between each pair",
        )
        .with_detail("field", "pin"));
    };
    let Some(clients) = clients else {
        return Err(listener_off());
    };
    if matches!(peer, PeerInfo::Tls { pin: own, .. } if *own != pin) {
        tracing::warn!(%peer, client_pin = %pin, "clients/remove refused: a client may remove only itself");
        return Err(ApiError::new(
            ErrorCode::NotPermitted,
            "over the TLS listener a client may remove only itself",
        ));
    }
    let store = Arc::clone(clients);
    let removed = spawn_blocking_named("api.clients_remove", move || store.remove(pin));
    match removed
        .await
        .map_err(io::Error::other)
        .and_then(|removal| removal)
    {
        Ok(Removal::Removed { closed }) => {
            tracing::info!(
                event = "control_client_removed",
                client_pin = %pin,
                by = %peer,
                closed,
                "control client removed"
            );
            Ok(Empty::default())
        }
        Ok(Removal::Unknown) => {
            tracing::info!(client_pin = %pin, by = %peer, "clients/remove: the pin is not enrolled, nothing to remove");
            Ok(Empty::default())
        }
        Ok(Removal::Fixed) => {
            tracing::warn!(%peer, client_pin = %pin, "clients/remove refused: the pin is fixed by the configuration");
            Err(ApiError::new(
                ErrorCode::NotPermitted,
                "the pin is fixed by the configuration; remove it from `--control-clients`",
            ))
        }
        Err(err) => {
            tracing::error!(%peer, client_pin = %pin, error = %err, "removing the control client failed");
            Err(ApiError::new(
                ErrorCode::InternalError,
                "the client list could not be stored",
            ))
        }
    }
}

/// The token that closes connection `id` once its client is removed:
/// registered with the TLS listener's clients for a peer that came through
/// it, never cancelled for a peer on the socket.
fn attach(clients: Option<&ClientStore>, peer: &PeerInfo, id: ConnectionId) -> CancellationToken {
    match (clients, peer) {
        (Some(clients), PeerInfo::Tls { pin, .. }) => clients.attach(id, *pin),
        _ => CancellationToken::new(),
    }
}

/// Forgets connection `id`, which closed.
fn detach(clients: Option<&ClientStore>, id: ConnectionId) {
    if let Some(clients) = clients {
        clients.detach(id);
    }
}

/// Closes a connection whose client was removed, and names why.
fn client_removed(outbox: &Outbox) -> &'static str {
    tracing::info!("control connection closing: its client was removed");
    outbox.close(CLOSE_POLICY_VIOLATION, "client removed");
    "client removed"
}

/// `pairing/create`: a new code for the TLS listener, replacing any open
/// one. Only a peer on the Unix socket may ask: it already controls the
/// daemon, while an enrolled TLS client must not enroll others.
fn pairing_create(
    pairing: Option<&Pairing>,
    peer: &PeerInfo,
) -> Result<PairingCreateResult, ApiError> {
    if matches!(peer, PeerInfo::Tls { .. }) {
        tracing::warn!(%peer, "pairing/create refused: not on the control socket");
        return Err(ApiError::new(
            ErrorCode::NotPermitted,
            "pairing codes are issued on the control socket only",
        ));
    }
    let Some(pairing) = pairing else {
        return Err(listener_off());
    };
    let Some(code) = pairing.open() else {
        tracing::error!(%peer, "pairing/create failed: the system provides no randomness");
        return Err(ApiError::new(
            ErrorCode::InternalError,
            "no randomness for a pairing code",
        ));
    };
    tracing::info!(event = "pairing_code_issued", %peer, "pairing code issued");
    Ok(code.result())
}

/// Releases the connection's slot when dropped.
struct ConnectionSlot(Arc<AtomicU32>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The connection's mutable state.
struct Connection<H> {
    /// The id.
    id: ConnectionId,
    /// What every connection shares.
    state: AppState<H>,
    /// The outbound queue.
    outbox: Arc<Outbox>,
    /// The last command id, for the strictly increasing rule.
    last_id: Option<u64>,
    /// Open subscriptions by command id.
    subscriptions: HashMap<u64, JoinHandle<()>>,
    /// Who is connected, as the listener authenticated it.
    peer: PeerInfo,
}

/// Serves one connection until the peer leaves, the queue overflows or the
/// daemon shuts down, inside its `connection` span. The span is entered
/// only while the connection's own futures are polled
/// ([`tracing::Instrument`]), never held across an `.await`, where it would wrap
/// whatever else the thread runs.
async fn run<H: Handler>(
    socket: WebSocket,
    state: AppState<H>,
    peer: PeerInfo,
    slot: ConnectionSlot,
) {
    let id = ConnectionId(state.next_id.fetch_add(1, Ordering::AcqRel));
    let span = tracing::info_span!("connection", connection.id = id.0);
    serve(socket, state, peer, slot, id).instrument(span).await;
}

/// [`run`]'s body, for connection `id`.
async fn serve<H: Handler>(
    socket: WebSocket,
    state: AppState<H>,
    peer: PeerInfo,
    slot: ConnectionSlot,
    id: ConnectionId,
) {
    tracing::info!(%peer, "control connection opened");

    let (sink, mut stream) = socket.split();
    let outbox = Arc::new(Outbox::new(OUTBOUND_BUDGET_BYTES));
    let mut writer = lotse_core::task::spawn_named(
        "api.writer",
        write_loop(sink, Arc::clone(&outbox)).in_current_span(),
    );
    let mut connection = Connection {
        id,
        state,
        outbox,
        last_id: None,
        subscriptions: HashMap::new(),
        peer,
    };
    let removed = attach(connection.state.clients.as_deref(), &connection.peer, id);
    connection.send(Class::Signaling, &connection.state.handler.hello());

    let closed_by = loop {
        tokio::select! {
            incoming = stream.next() => match incoming {
                None | Some(Ok(Message::Close(_))) => break "peer",
                Some(Err(err)) => {
                    tracing::debug!(error = %err, "control connection read failed");
                    break "peer";
                }
                Some(Ok(Message::Text(text))) => connection.command(text.as_str()).await,
                Some(Ok(Message::Binary(_))) => {
                    connection.outbox.close(CLOSE_UNSUPPORTED_DATA, "text frames only");
                    break "binary frame";
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            },
            () = connection.outbox.overflowed() => {
                let counters = connection.outbox.stats();
                tracing::warn!(dropped = counters.dropped, coalesced = counters.coalesced, "outbound queue overflowed; disconnecting the slow client");
                connection.outbox.close(CLOSE_POLICY_VIOLATION, "outbound queue overflowed");
                break "overflow";
            }
            () = removed.cancelled() => break client_removed(&connection.outbox),
            () = connection.state.shutdown.cancelled() => {
                connection.send(Class::Signaling, &Shutdown::default());
                connection.outbox.close(CLOSE_GOING_AWAY, "shutting down");
                break "shutdown";
            }
        }
    };

    for (_, task) in connection.subscriptions.drain() {
        task.abort();
    }
    connection.outbox.close(CLOSE_GOING_AWAY, "closed");
    // Nothing below waits on the peer before the deadline is set: its
    // sessions are orphaned and its slot is free while the writer drains.
    let deadline = connection.state.clock.sleep(CLOSE_TIMEOUT);
    connection.state.handler.connection_closed(id);
    detach(connection.state.clients.as_deref(), id);
    drop(slot);
    tokio::select! {
        _written = &mut writer => {}
        () = deadline => {
            // RFC 6455 §7.1.1: the server may drop the connection rather
            // than wait; aborting the writer drops the sink and, with the
            // stream below, the socket.
            writer.abort();
            let timeout_ms = CLOSE_TIMEOUT.as_millis();
            tracing::warn!(
                closed_by,
                timeout_ms,
                queued_bytes = connection.outbox.stats().bytes,
                "control connection dropped: the peer did not take the close frame before the deadline"
            );
        }
    }
    drop(stream);
    let counters = connection.outbox.stats();
    tracing::info!(
        closed_by,
        dropped = counters.dropped,
        coalesced = counters.coalesced,
        "control connection closed"
    );
}

/// Sends queued frames until the queue closes.
async fn write_loop(
    mut sink: futures_util::stream::SplitSink<WebSocket, Message>,
    outbox: Arc<Outbox>,
) {
    while let Some(item) = outbox.pop().await {
        let result = match item {
            Outgoing::Text { text, .. } => sink.send(Message::Text(text.into())).await,
            Outgoing::Close { code, reason } => {
                let close = sink
                    .send(Message::Close(Some(CloseFrame {
                        code,
                        reason: reason.into(),
                    })))
                    .await;
                let _flushed = sink.flush().await;
                if let Err(err) = close {
                    tracing::debug!(error = %err, "close frame not delivered");
                }
                return;
            }
        };
        if let Err(err) = result {
            tracing::debug!(error = %err, "control connection write failed");
            return;
        }
    }
}

impl<H: Handler> Connection<H> {
    /// Queues a frame; results and frames of the connection itself are
    /// signaling, never dropped.
    fn send<T: serde::Serialize>(&self, class: Class, frame: &T) {
        let text = serde_json::to_string(frame).unwrap_or_default();
        if self.outbox.push(class, text).is_err() {
            tracing::debug!("frame not queued: the outbound queue overflowed");
        }
    }

    /// Whether another subscription fits under `max_subscriptions`, after
    /// forgetting the ones that ended (a session's `closed`, a handler that
    /// dropped the channel), so a long-lived connection does not
    /// accumulate them.
    fn subscription_slot_free(&mut self) -> bool {
        self.subscriptions.retain(|_, task| !task.is_finished());
        let open = u32::try_from(self.subscriptions.len()).unwrap_or(u32::MAX);
        open < self.state.config.max_subscriptions
    }

    /// Answers `command`, one about the TLS listener's clients, which the
    /// server answers itself.
    async fn listener_command(&self, command: Command) {
        let answer = listener_answer(
            self.state.pairing.as_deref(),
            self.state.clients.as_ref(),
            &self.peer,
            command,
        )
        .await;
        self.send(Class::Signaling, &answer);
    }

    /// One text frame: parse, check the id, dispatch, answer.
    async fn command(&mut self, text: &str) {
        let command = match lotse_api_types::parse_command(text) {
            Ok(command) => command,
            Err(err) => {
                tracing::debug!(id = ?err.id, code = err.error.code.as_str(), "command rejected");
                self.send(Class::Signaling, &Failure::new(err.id, err.error));
                return;
            }
        };
        let id = command.id();
        if self.last_id.is_some_and(|last| id <= last) || id == 0 {
            tracing::debug!(id, last = ?self.last_id, "command id reused");
            self.send(
                Class::Signaling,
                &Failure::new(
                    Some(id),
                    ApiError::new(
                        ErrorCode::IdReuse,
                        "ids must be positive and strictly increasing",
                    ),
                ),
            );
            return;
        }
        self.last_id = Some(id);
        tracing::debug!(id, command = command.name(), "command");
        match command {
            Command::Ping(_) => self.send(Class::Signaling, &Pong::new(id)),
            command @ (Command::PairingCreate(_)
            | Command::ClientsList(_)
            | Command::ClientsRemove(_)) => self.listener_command(command).await,
            Command::Schema(_) => self.send(
                Class::Signaling,
                &Success::new(id, lotse_api_types::schema::bundle()),
            ),
            Command::Unsubscribe(unsubscribe) => {
                match self.subscriptions.remove(&unsubscribe.subscription) {
                    Some(task) => {
                        task.abort();
                        let subscription = unsubscribe.subscription;
                        if let Some(last) = self.state.handler.unsubscribed(self.id, subscription) {
                            self.send(
                                last.class.into(),
                                &EventFrame::new(subscription, last.payload),
                            );
                        }
                        self.send(Class::Signaling, &Success::new(id, Empty::default()));
                    }
                    None => self.send(
                        Class::Signaling,
                        &Failure::new(
                            Some(id),
                            ApiError::new(
                                ErrorCode::SubscriptionNotFound,
                                "no such subscription on this connection",
                            ),
                        ),
                    ),
                }
            }
            other if opens_subscription(&other) && !self.subscription_slot_free() => {
                tracing::warn!(
                    id,
                    command = other.name(),
                    max = self.state.config.max_subscriptions,
                    "command refused: subscription limit of the connection reached"
                );
                self.send(
                    Class::Signaling,
                    &Failure::new(
                        Some(id),
                        ApiError::new(
                            ErrorCode::LimitReached,
                            "too many open subscriptions on this connection",
                        ),
                    ),
                );
            }
            other => match self.state.handler.handle(self.id, other).await {
                Outcome::Result(result) => self.send(Class::Signaling, &Success::new(id, result)),
                Outcome::Error(error) => {
                    self.send(Class::Signaling, &Failure::new(Some(id), error));
                }
                Outcome::Subscribed(events) => {
                    self.send(Class::Signaling, &Success::new(id, Empty::default()));
                    let forwarder = lotse_core::task::spawn_named(
                        "api.subscription",
                        forward(id, events, Arc::clone(&self.outbox)).in_current_span(),
                    );
                    self.subscriptions.insert(id, forwarder);
                }
            },
        }
    }
}

/// Whether the handler answers `command` with a subscription, which
/// counts against `max_subscriptions`.
const fn opens_subscription(command: &Command) -> bool {
    matches!(
        command,
        Command::StreamSubscribe(_) | Command::WebrtcOffer(_) | Command::SessionAdopt(_)
    )
}

/// Forwards a subscription's events as frames until it ends or the queue
/// overflows.
async fn forward(id: u64, mut events: mpsc::Receiver<Event>, outbox: Arc<Outbox>) {
    while let Some(event) = events.recv().await {
        let text = serde_json::to_string(&EventFrame::new(id, event.payload)).unwrap_or_default();
        if outbox.push(event.class.into(), text).is_err() {
            break;
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

    use lotse_core::clock::FakeClock;
    use lotse_core::fingerprint::Fingerprint;

    use super::*;
    use crate::pairing::test_support::NO_RANDOM;

    fn command(text: &str) -> Command {
        lotse_api_types::parse_command(text).unwrap()
    }

    #[tokio::test]
    async fn pairing_create_needs_the_socket_a_listener_and_randomness() {
        let unix = PeerInfo::Unix { uid: 0, pid: None };
        let tls = PeerInfo::Tls {
            pin: Fingerprint::of(b"client"),
            addr: "192.0.2.1:1".parse().unwrap(),
        };
        let clock = Arc::new(FakeClock::default());
        let working = Pairing::new(
            Fingerprint::of(b"server"),
            clock.clone(),
            rustls::crypto::ring::default_provider().secure_random,
        );
        let broken = Pairing::new(Fingerprint::of(b"server"), clock, &NO_RANDOM);
        assert!(pairing_create(Some(&working), &unix).is_ok());
        let code = |result: Result<PairingCreateResult, ApiError>| result.unwrap_err().code;
        assert_eq!(
            code(pairing_create(Some(&working), &tls)),
            ErrorCode::NotPermitted
        );
        assert_eq!(code(pairing_create(None, &unix)), ErrorCode::InvalidRequest);
        assert_eq!(
            code(pairing_create(Some(&broken), &unix)),
            ErrorCode::InternalError
        );
        let create = |id: u64| command(&format!(r#"{{"id":{id},"type":"pairing/create"}}"#));
        let answer = listener_answer(Some(&working), None, &unix, create(7)).await;
        assert_eq!(answer["id"], 7);
        assert_eq!(answer["success"], true);
        let answer = listener_answer(None, None, &unix, create(8)).await;
        assert_eq!(answer["error"]["code"], "invalid_request");
    }

    #[tokio::test]
    async fn clients_remove_takes_an_enrolled_pin_from_the_socket_or_the_client_itself() {
        use std::os::unix::fs::DirBuilderExt as _;

        let (logs, _guard) = crate::pairing::test_support::capture();
        let dir =
            std::env::temp_dir().join(format!("lotse-connection-clients-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let runtime = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let fixed = Fingerprint::of(b"fixed");
        let store = Arc::new(
            ClientStore::open(&std::fs::File::open(&dir).unwrap(), &dir, &[fixed], runtime)
                .unwrap(),
        );
        let (own, other) = (Fingerprint::of(b"own"), Fingerprint::of(b"other"));
        store.enroll(own).unwrap();
        store.enroll(other).unwrap();
        let unix = PeerInfo::Unix { uid: 0, pid: None };
        let tls = PeerInfo::Tls {
            pin: own,
            addr: "192.0.2.1:1".parse().unwrap(),
        };
        let clients = Some(&store);
        let code = |result: Result<Empty, ApiError>| result.unwrap_err().code;

        let refused = clients_remove(clients, &unix, "not a pin")
            .await
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidRequest);
        assert_eq!(refused.details["field"], "pin");
        let own_text = own.to_string();
        assert_eq!(
            code(clients_remove(None, &unix, &own_text).await),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            code(clients_remove(clients, &tls, &other.to_string()).await),
            ErrorCode::NotPermitted
        );
        assert!(store.allows(&other));
        assert_eq!(
            code(clients_remove(clients, &unix, &fixed.to_hex()).await),
            ErrorCode::NotPermitted
        );
        let session = store.attach(ConnectionId(1), own);
        // Without colons it is the same pin.
        assert!(clients_remove(clients, &tls, &own.to_hex()).await.is_ok());
        assert!(!store.allows(&own));
        assert!(session.is_cancelled());
        assert!(
            clients_remove(clients, &unix, &own_text).await.is_ok(),
            "idempotent"
        );
        let blocker = dir.join(crate::clients::CLIENTS_DIR).join("pins.partial");
        std::fs::create_dir(&blocker).unwrap();
        assert_eq!(
            code(clients_remove(clients, &unix, &other.to_string()).await),
            ErrorCode::InternalError
        );
        std::fs::remove_dir(&blocker).unwrap();
        let text = logs.text();
        for line in [
            "clients/remove refused: a client may remove only itself",
            "clients/remove refused: the pin is fixed by the configuration",
            "the pin is not enrolled, nothing to remove",
            "removing the control client failed",
        ] {
            assert!(text.contains(line), "{line}: {text}");
        }
        let removed = text
            .lines()
            .find(|line| line.contains("control client removed"))
            .unwrap();
        assert!(removed.contains(&format!("client_pin={own}")), "{removed}");
        assert!(removed.contains("closed=1"), "{removed}");

        let list = command(r#"{"id":3,"type":"clients/list"}"#);
        let answer = listener_answer(None, clients, &unix, list.clone()).await;
        assert_eq!(answer["id"], 3);
        let listed = answer["result"]["clients"].as_array().unwrap();
        assert_eq!(listed.len(), 2, "{answer}");
        let answer = listener_answer(None, None, &unix, list).await;
        assert_eq!(answer["error"]["code"], "invalid_request");
        let remove = command(&format!(
            r#"{{"id":4,"type":"clients/remove","pin":"{other}"}}"#
        ));
        let answer = listener_answer(None, clients, &unix, remove).await;
        assert_eq!(answer["success"], true, "{answer}");
        assert_eq!(answer["result"], serde_json::json!({}));
        assert!(!store.allows(&other));
        let text = logs.text();
        let removed = text
            .lines()
            .rfind(|line| line.contains("control client removed"))
            .unwrap();
        assert!(
            removed.contains(&format!("client_pin={other}")),
            "{removed}"
        );
        assert!(removed.contains("by=uid 0"), "{removed}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
