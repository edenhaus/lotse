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
//! one at a time per connection; the handler's never wait on a camera, and
//! one the handler is still awaiting when the connection's client is
//! removed or the daemon shuts down is dropped and refused, so it never
//! holds up the close. The ones about the TLS listener's clients may wait
//! for the disk, so each runs as a task of its own: the connection reads no
//! further command until its answer is queued, but still closes on shutdown
//! or an overflow meanwhile. A removal or a shutdown is seen before any
//! further command, which then never runs; a client that removes itself
//! gets its answer before the close. On close the sessions are
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
use futures_util::future::OptionFuture;
use futures_util::{SinkExt as _, StreamExt as _};
use lotse_api_types::clients::ClientList;
use lotse_api_types::command::Command;
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::frame::{Empty, EventFrame, Failure, Pong, Shutdown, Success};
use lotse_api_types::pairing::PairingCreateResult;
use lotse_core::fingerprint::Fingerprint;
use lotse_core::task::{BoxFuture, spawn_blocking_named};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::clients::{ClientStore, Removal};
use crate::listener::PeerInfo;
use crate::outbox::{Class, Outbox, Outgoing, Overflow};
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
/// answers itself, asked by connection `by`; and whether `by` closes once
/// it has sent the answer: its client removed itself. Not generic over the
/// handler, so every handler's connection shares this one function.
async fn listener_answer(
    pairing: Option<&Pairing>,
    clients: Option<&Arc<ClientStore>>,
    peer: &PeerInfo,
    by: ConnectionId,
    command: Command,
) -> (serde_json::Value, bool) {
    let id = command.id();
    let mut leaving = false;
    let outcome = match command {
        Command::ClientsList(_) => clients_list(clients).map(to_json),
        Command::ClientsRemove(remove) => {
            let removed = clients_remove(clients, peer, by, &remove.pin).await;
            // Over TLS a client may remove only itself.
            leaving = removed.is_ok() && matches!(peer, PeerInfo::Tls { .. });
            removed.map(to_json)
        }
        _ => pairing_create(pairing, peer).map(to_json),
    };
    let frame = match outcome {
        Ok(result) => serde_json::to_value(Success::new(id, result)),
        Err(error) => serde_json::to_value(Failure::new(Some(id), error)),
    };
    (frame.unwrap_or_default(), leaving)
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

/// `clients/remove`, asked by connection `by`: removes an enrolled pin and
/// closes its connections but `by` (see [`ClientStore::remove`]). Over the
/// TLS listener a client may remove only itself; a fixed pin stays; a pin
/// that is not enrolled is already removed.
async fn clients_remove(
    clients: Option<&Arc<ClientStore>>,
    peer: &PeerInfo,
    by: ConnectionId,
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
    let removed = spawn_blocking_named("api.clients_remove", move || store.remove(pin, by));
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
    /// Cancelled once the connection's client is removed.
    removed: CancellationToken,
    /// The command about the TLS listener's clients being answered, if
    /// any: no further command is read until it ends. Left to finish when
    /// the connection closes first, so a change it began is still logged.
    pending: Option<JoinHandle<()>>,
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
    let removed = attach(state.clients.as_deref(), &peer, id);
    let mut connection = Connection {
        id,
        state,
        outbox,
        last_id: None,
        subscriptions: HashMap::new(),
        peer,
        removed,
        pending: None,
    };
    connection.send(Class::Signaling, &connection.state.handler.hello());

    let closed_by = loop {
        tokio::select! {
            // In this order, so a removal or a shutdown wins over a command
            // already received, a pending one too. A client removing itself
            // is not told to close by the removal but by the command's own
            // task, once the answer is queued, so it goes out before the
            // close.
            biased;
            // One line: the removal's break counts as covered in a copy of
            // this loop whose connection is never removed (the coverage gate
            // takes the best single copy of a generic function).
            () = connection.removed.cancelled() => break client_removed(&connection.outbox),
            () = connection.state.shutdown.cancelled() => {
                connection.send(Class::Signaling, &Shutdown::default());
                connection.outbox.close(CLOSE_GOING_AWAY, "shutting down");
                break "shutdown";
            }
            () = connection.outbox.overflowed() => {
                let counters = connection.outbox.stats();
                tracing::warn!(dropped = counters.dropped, coalesced = counters.coalesced, "outbound queue overflowed; disconnecting the slow client");
                connection.outbox.close(CLOSE_POLICY_VIOLATION, "outbound queue overflowed");
                break "overflow";
            }
            // Resolves to `None` at once, which disables the branch, while
            // no such command is being answered.
            Some(_ended) = OptionFuture::from(connection.pending.as_mut()) => connection.pending = None,
            incoming = stream.next(), if connection.pending.is_none() => match incoming {
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
            // stream below, the socket. Awaited, as `abort` only asks: the
            // connection's state, and with it its hold on serving, goes
            // only once the sink is gone.
            writer.abort();
            let _aborted = (&mut writer).await;
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

/// Queues a frame on `outbox`; results and frames of the connection itself
/// are signaling, never dropped.
fn queue<T: serde::Serialize>(outbox: &Outbox, class: Class, frame: &T) {
    let text = serde_json::to_string(frame).unwrap_or_default();
    if outbox.push(class, text).is_err() {
        tracing::debug!("frame not queued: the outbound queue overflowed");
    }
}

/// The handler's answer to command `id`, unless the connection's client is
/// removed (`removed`) or the daemon shuts down (`shutdown`) first: then
/// `handling` is dropped, as [`Handler::handle`] allows, and a refusal
/// answers the command, so a handler still awaiting never holds up the
/// close. Not generic over the handler, so every handler's connection
/// shares this one function.
async fn unless_closing(
    id: u64,
    handling: BoxFuture<'_, Outcome>,
    removed: &CancellationToken,
    shutdown: &CancellationToken,
) -> Outcome {
    tokio::select! {
        biased;
        () = removed.cancelled() => {
            tracing::info!(id, "command dropped before the handler answered: the connection's client was removed");
            Outcome::Error(ApiError::new(ErrorCode::NotPermitted, "the client was removed"))
        }
        () = shutdown.cancelled() => {
            tracing::info!(id, "command dropped before the handler answered: shutting down");
            Outcome::Error(ApiError::new(ErrorCode::ShuttingDown, "shutting down"))
        }
        outcome = handling => outcome,
    }
}

impl<H: Handler> Connection<H> {
    /// Queues a frame; see [`queue`].
    fn send<T: serde::Serialize>(&self, class: Class, frame: &T) {
        queue(&self.outbox, class, frame);
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

    /// Starts answering `command`, one about the TLS listener's clients,
    /// which the server answers itself, as a task of its own: a removal
    /// waits for the disk, which must not hold up the connection's loop.
    /// The task queues the answer before it ends, then closes the
    /// connection if its client removed itself, and [`crate::Server::serve`]
    /// waits for it.
    fn listener_command(&mut self, command: Command) {
        let pairing = self.state.pairing.clone();
        let clients = self.state.clients.clone();
        let peer = self.peer.clone();
        let by = self.id;
        let outbox = Arc::clone(&self.outbox);
        let removed = self.removed.clone();
        let answering = async move {
            let (answer, leaving) =
                listener_answer(pairing.as_deref(), clients.as_ref(), &peer, by, command).await;
            queue(&outbox, Class::Signaling, &answer);
            if leaving {
                removed.cancel();
            }
        };
        let tracked = self
            .state
            .serving
            .task_tracker()
            .track_future(answering.in_current_span());
        self.pending = Some(lotse_core::task::spawn_named(
            "api.listener_command",
            tracked,
        ));
    }

    /// The handler's answer to `command`, whose id is `id`; see
    /// [`unless_closing`].
    async fn handled(&self, id: u64, command: Command) -> Outcome {
        let handling = Box::pin(self.state.handler.handle(self.id, command));
        unless_closing(id, handling, &self.removed, &self.state.shutdown).await
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
            | Command::ClientsRemove(_)) => self.listener_command(command),
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
                            // An overflow wakes the loop, which logs it.
                            let _overflowed = deliver(&self.outbox, subscription, last);
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
            other => match self.handled(id, other).await {
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
/// overflows, here or in the handler's own queue.
async fn forward(id: u64, mut events: mpsc::Receiver<Event>, outbox: Arc<Outbox>) {
    while let Some(event) = events.recv().await {
        if deliver(&outbox, id, event).is_err() {
            break;
        }
    }
}

/// Queues `event` of subscription `id` as a frame. The handler's
/// [`crate::EventClass::Overflowed`] queues nothing and overflows the
/// outbox: the client is disconnected rather than left with a hole in
/// events it is promised.
fn deliver(outbox: &Outbox, id: u64, event: Event) -> Result<(), Overflow> {
    let Some(class) = Class::of(event.class) else {
        tracing::warn!(
            subscription = id,
            "subscription queue overflowed with an event that is never dropped"
        );
        return Err(outbox.overflow());
    };
    let text = serde_json::to_string(&EventFrame::new(id, event.payload)).unwrap_or_default();
    outbox.push(class, text)
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
        let (answer, _) =
            listener_answer(Some(&working), None, &unix, ConnectionId(1), create(7)).await;
        assert_eq!(answer["id"], 7);
        assert_eq!(answer["success"], true);
        let (answer, _) = listener_answer(None, None, &unix, ConnectionId(1), create(8)).await;
        assert_eq!(answer["error"]["code"], "invalid_request");
    }

    #[tokio::test]
    async fn clients_remove_takes_an_enrolled_pin_from_the_socket_or_the_client_itself() {
        let (logs, _guard) = crate::pairing::test_support::capture();
        let fixed = Fingerprint::of(b"fixed");
        let (own, other) = (Fingerprint::of(b"own"), Fingerprint::of(b"other"));
        let (store, dir) = store_with("clients", &[fixed], own, |_| Ok(()));
        store.enroll(other).unwrap();
        let unix = PeerInfo::Unix { uid: 0, pid: None };
        let tls = PeerInfo::Tls {
            pin: own,
            addr: "192.0.2.1:1".parse().unwrap(),
        };
        let clients = Some(&store);
        let code = |result: Result<Empty, ApiError>| result.unwrap_err().code;

        let refused = clients_remove(clients, &unix, ConnectionId(2), "not a pin")
            .await
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidRequest);
        assert_eq!(refused.details["field"], "pin");
        let own_text = own.to_string();
        assert_eq!(
            code(clients_remove(None, &unix, ConnectionId(2), &own_text).await),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            code(clients_remove(clients, &tls, ConnectionId(2), &other.to_string()).await),
            ErrorCode::NotPermitted
        );
        assert!(store.allows(&other));
        assert_eq!(
            code(clients_remove(clients, &unix, ConnectionId(2), &fixed.to_hex()).await),
            ErrorCode::NotPermitted
        );
        let session = store.attach(ConnectionId(1), own);
        // Without colons it is the same pin; asked by another connection of
        // it, so this one is told to close.
        assert!(
            clients_remove(clients, &tls, ConnectionId(2), &own.to_hex())
                .await
                .is_ok()
        );
        assert!(!store.allows(&own));
        assert!(session.is_cancelled());
        assert!(
            clients_remove(clients, &unix, ConnectionId(2), &own_text)
                .await
                .is_ok(),
            "idempotent"
        );
        let blocker = dir.join(crate::clients::CLIENTS_DIR).join("pins.partial");
        std::fs::create_dir(&blocker).unwrap();
        assert_eq!(
            code(clients_remove(clients, &unix, ConnectionId(2), &other.to_string()).await),
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
        let (answer, _) =
            listener_answer(None, clients, &unix, ConnectionId(2), list.clone()).await;
        assert_eq!(answer["id"], 3);
        let listed = answer["result"]["clients"].as_array().unwrap();
        assert_eq!(listed.len(), 2, "{answer}");
        let (answer, _) = listener_answer(None, None, &unix, ConnectionId(2), list).await;
        assert_eq!(answer["error"]["code"], "invalid_request");
        let remove = command(&format!(
            r#"{{"id":4,"type":"clients/remove","pin":"{other}"}}"#
        ));
        let (answer, _) = listener_answer(None, clients, &unix, ConnectionId(2), remove).await;
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

    #[tokio::test]
    async fn only_a_client_that_removed_itself_leaves_and_only_after_the_answer() {
        let (own, other) = (Fingerprint::of(b"own"), Fingerprint::of(b"other"));
        let (store, dir) = store_with("leaving", &[], own, |_| Ok(()));
        store.enroll(other).unwrap();
        let clients = Some(&store);
        let unix = PeerInfo::Unix { uid: 0, pid: None };
        let tls = tls_peer(own, 1);
        let remove = |id: u64, pin: Fingerprint| {
            command(&format!(
                r#"{{"id":{id},"type":"clients/remove","pin":"{pin}"}}"#
            ))
        };

        let (answer, leaving) =
            listener_answer(None, clients, &tls, ConnectionId(1), remove(1, other)).await;
        assert_eq!(answer["error"]["code"], "not_permitted", "{answer}");
        assert!(!leaving, "refused, the client stays");
        let (answer, leaving) =
            listener_answer(None, clients, &unix, ConnectionId(2), remove(2, other)).await;
        assert_eq!(answer["success"], true, "{answer}");
        assert!(!leaving, "the socket's peer stays");
        let (answer, leaving) =
            listener_answer(None, clients, &tls, ConnectionId(1), remove(3, own)).await;
        assert_eq!(answer["success"], true, "{answer}");
        assert!(leaving, "the client removed itself");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Both sides of the directory sync a removal is held in by
    /// `a_stalled_removal_does_not_hold_up_shutdown`.
    static STALLED: std::sync::Barrier = std::sync::Barrier::new(2);

    /// Both sides of each directory sync held open by
    /// `a_client_removed_by_another_request_closes_while_its_own_removal_waits`.
    static COMPETING: std::sync::Barrier = std::sync::Barrier::new(2);

    /// Waits on `barrier` off the runtime's thread.
    async fn stalled(barrier: &'static std::sync::Barrier) {
        spawn_blocking_named("test.stalled", || {
            barrier.wait();
        })
        .await
        .unwrap();
    }

    /// The store of a fresh data directory named after `test`, with the
    /// `fixed` pins, `pin` enrolled and `sync_dir` in place of `fsync`; and
    /// the directory.
    fn store_with(
        test: &str,
        fixed: &[Fingerprint],
        pin: Fingerprint,
        sync_dir: fn(&std::os::fd::OwnedFd) -> io::Result<()>,
    ) -> (Arc<ClientStore>, std::path::PathBuf) {
        use std::os::unix::fs::DirBuilderExt as _;

        let dir =
            std::env::temp_dir().join(format!("lotse-connection-{test}-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let runtime = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let store =
            ClientStore::open(&std::fs::File::open(&dir).unwrap(), &dir, fixed, runtime).unwrap();
        store.enroll(pin).unwrap();
        (Arc::new(store.with_sync_dir(sync_dir)), dir)
    }

    /// A TLS peer authenticated with `pin`, from `port`.
    fn tls_peer(pin: Fingerprint, port: u16) -> PeerInfo {
        PeerInfo::Tls {
            pin,
            addr: std::net::SocketAddr::from(([192, 0, 2, 1], port)),
        }
    }

    /// A WebSocket client of a connection served with `state` to `peer`,
    /// past its `hello`.
    async fn connect(
        state: AppState<crate::tests::Minimal>,
        peer: PeerInfo,
    ) -> tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream> {
        let app = axum::Router::new()
            .route(
                lotse_api_types::WS_PATH,
                axum::routing::get(upgrade::<crate::tests::Minimal>),
            )
            .with_state(state)
            .layer(Extension(peer));
        let (client, server) = tokio::io::duplex(64 * 1024);
        let serving = hyper::server::conn::http1::Builder::new()
            .serve_connection(
                hyper_util::rt::TokioIo::new(server),
                hyper_util::service::TowerToHyperService::new(app),
            )
            .with_upgrades();
        let _served = lotse_core::task::spawn_named("test.serve", serving);
        let (mut ws, _) = tokio_tungstenite::client_async(
            format!("ws://lotse{}", lotse_api_types::WS_PATH),
            client,
        )
        .await
        .unwrap();
        let hello = next_frame(&mut ws).await;
        assert!(hello.is_text(), "{hello:?}");
        ws
    }

    /// The next frame of `ws`, failing after 5 s of real time.
    #[expect(
        clippy::disallowed_methods,
        reason = "a real-time bound on a test step; the server's own timers run on the fake clock"
    )]
    async fn next_frame<S>(
        ws: &mut tokio_tungstenite::WebSocketStream<S>,
    ) -> tokio_tungstenite::tungstenite::Message
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("a frame within 5 s")
            .unwrap()
            .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_removal_does_not_hold_up_shutdown() {
        use tokio_tungstenite::tungstenite::Message as Frame;

        let (pin, unknown) = (Fingerprint::of(b"pin"), Fingerprint::of(b"unknown"));
        let (store, dir) = store_with("stalled", &[], pin, |_| {
            STALLED.wait();
            STALLED.wait();
            Ok(())
        });
        let state = crate::tests::state(4, false);
        let shutdown = state.shutdown.clone();
        let state = AppState {
            clients: Some(Arc::clone(&store)),
            ..state
        };
        let mut ws = connect(state, tls_peer(pin, 1)).await;
        let remove =
            serde_json::json!({ "id": 1, "type": "clients/remove", "pin": pin.to_string() });
        ws.send(Frame::Text(remove.to_string().into()))
            .await
            .unwrap();
        stalled(&STALLED).await;

        // The removal waits for the disk; the connection still shuts down.
        shutdown.cancel();
        assert!(matches!(
            next_frame(&mut ws).await,
            Frame::Text(text) if text.as_str().contains("shutdown")
        ));
        assert!(matches!(
            next_frame(&mut ws).await,
            Frame::Close(Some(close)) if u16::from(close.code) == CLOSE_GOING_AWAY
        ));

        // Let go, the removal still ends: a later change waits for it.
        stalled(&STALLED).await;
        let later = Arc::clone(&store);
        let after =
            spawn_blocking_named("test.after", move || later.remove(unknown, ConnectionId(9)));
        assert_eq!(after.await.unwrap().unwrap(), Removal::Unknown);
        assert!(!store.allows(&pin));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_client_removed_by_another_request_closes_while_its_own_removal_waits() {
        use tokio_tungstenite::tungstenite::Message as Frame;

        let (pin, other) = (Fingerprint::of(b"pin"), Fingerprint::of(b"other"));
        let (store, dir) = store_with("competing", &[], pin, |_| {
            COMPETING.wait();
            COMPETING.wait();
            Ok(())
        });
        let state = AppState {
            clients: Some(Arc::clone(&store)),
            ..crate::tests::state(4, false)
        };
        let mut first = connect(state.clone(), tls_peer(pin, 1)).await;
        let mut second = connect(state, tls_peer(pin, 2)).await;

        // A change of another pin holds the store's writes up in its sync
        // while both connections of `pin` ask to remove it.
        let writer = Arc::clone(&store);
        let held = spawn_blocking_named("test.enroll", move || writer.enroll(other));
        stalled(&COMPETING).await;
        let remove =
            serde_json::json!({ "id": 1, "type": "clients/remove", "pin": pin.to_string() });
        for ws in [&mut first, &mut second] {
            ws.send(Frame::Text(remove.to_string().into()))
                .await
                .unwrap();
        }
        // Every task here runs on this thread: yielding lets both
        // connections read their command and start answering it.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        stalled(&COMPETING).await;
        held.await.unwrap().unwrap();

        // One removal runs and is held in its own sync. The other
        // connection's client is gone: it closes without waiting for its
        // own removal, which waits for that sync.
        stalled(&COMPETING).await;
        let (closed, frame) = tokio::select! {
            frame = next_frame(&mut first) => (0, frame),
            frame = next_frame(&mut second) => (1, frame),
        };
        assert!(
            matches!(&frame, Frame::Close(Some(close)) if u16::from(close.code) == CLOSE_POLICY_VIOLATION),
            "{frame:?}"
        );

        // Let go, the client that removed itself has its answer, then the
        // close.
        stalled(&COMPETING).await;
        let mut remover = if closed == 0 { second } else { first };
        assert!(matches!(
            next_frame(&mut remover).await,
            Frame::Text(text) if text.as_str().contains(r#""success":true"#)
        ));
        assert!(matches!(
            next_frame(&mut remover).await,
            Frame::Close(Some(close)) if u16::from(close.code) == CLOSE_POLICY_VIOLATION
        ));
        assert!(!store.allows(&pin));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
