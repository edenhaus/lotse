//! One control connection: the upgrade with its limit checks, `hello`,
//! the command loop with strictly increasing ids, subscriptions (capped per
//! connection, ended ones forgotten), the bounded outbound queue and the
//! close codes.
//!
//! Implements RFC 6455 §7.4.1 close codes: `1001` going away on shutdown,
//! `1003` for a binary frame, `1008` policy violation on an overflowed
//! outbound queue. Commands are processed one at a time per connection;
//! every one is non-blocking by contract. On close the sessions are
//! orphaned and the slot released first; the writer then gets
//! [`CLOSE_TIMEOUT`] to deliver the queue and the close frame, after which
//! the socket is dropped (RFC 6455 §7.1.1).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Extension;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt as _, StreamExt as _};
use lotse_api_types::command::Command;
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::frame::{Empty, EventFrame, Failure, Pong, Shutdown, Success};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::Instrument as _;

use crate::listener::PeerInfo;
use crate::outbox::{Class, Outbox, Outgoing};
use crate::{
    AppState, CLOSE_TIMEOUT, ConnectionId, Event, Handler, MAX_MESSAGE_BYTES,
    OUTBOUND_BUDGET_BYTES, Outcome,
};

/// RFC 6455 §7.4.1: going away.
const CLOSE_GOING_AWAY: u16 = 1001;

/// RFC 6455 §7.4.1: unsupported data (a binary frame).
const CLOSE_UNSUPPORTED_DATA: u16 = 1003;

/// RFC 6455 §7.4.1: policy violation (the outbound queue overflowed).
const CLOSE_POLICY_VIOLATION: u16 = 1008;

/// A JSON error body for a refused upgrade.
fn refuse(status: StatusCode, code: ErrorCode, message: &str) -> Response {
    let body = serde_json::to_string(&ApiError::new(code, message)).unwrap_or_default();
    (status, [("content-type", "application/json")], body).into_response()
}

/// `GET /v0/ws` ([`lotse_api_types::WS_PATH`]): the shutdown and
/// connection-limit checks, then the upgrade. The peer's uid was checked
/// at accept.
pub(crate) async fn upgrade<H: Handler>(
    State(state): State<AppState<H>>,
    Extension(peer): Extension<PeerInfo>,
    ws: WebSocketUpgrade,
) -> Response {
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
    tracing::info!(uid = peer.uid, pid = ?peer.pid, "control connection opened");

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
    };
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
