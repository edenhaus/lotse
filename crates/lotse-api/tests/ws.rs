//! The control API end to end over a real Unix socket: `hello`, results,
//! ids, subscriptions, limits, shedding and the close codes, against a fake
//! handler that stands in for the supervisor.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt as _, StreamExt as _};
use lotse_api::{
    CLOSE_TIMEOUT, Config, ConnectionId, Event, EventClass, Handler, MAX_MESSAGE_BYTES,
    MAX_PENDING_UPGRADES, Outcome, ServeError, Server, UPGRADE_TIMEOUT,
};
use lotse_api_types::command::Command;
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::frame::{Hello, HelloTag};
use lotse_core::clock::FakeClock;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

/// The supervisor's stand-in: a stream map and its subscribers.
#[derive(Default)]
struct FakeHandler {
    streams: Mutex<BTreeMap<String, Value>>,
    subscribers: Mutex<Vec<mpsc::Sender<Event>>>,
    closed: AtomicU64,
    flood: Option<Arc<Notify>>,
    /// The subscriptions `webrtc/offer` opened, which end with `closed`.
    sessions: Mutex<Vec<(u64, mpsc::Sender<Event>)>>,
}

impl FakeHandler {
    fn event(stream_id: &str, state: &str) -> Event {
        Event {
            class: EventClass::StreamState {
                stream_id: stream_id.to_owned(),
            },
            payload: json!({ "type": "stream", "stream_id": stream_id, "state": state, "last_error": null }),
        }
    }
}

impl Handler for FakeHandler {
    fn hello(&self) -> Hello {
        Hello {
            kind: HelloTag::default(),
            api: lotse_api_types::API_VERSION.into(),
            version: "0.0.0-test".into(),
            outputs: vec![],
            features: vec![],
        }
    }

    async fn handle(&self, _connection: ConnectionId, command: Command) -> Outcome {
        match command {
            Command::StreamPut(put) => {
                let created = self
                    .streams
                    .lock()
                    .unwrap()
                    .insert(put.stream_id.clone(), json!({ "stream_id": put.stream_id }))
                    .is_none();
                let subscribers = self.subscribers.lock().unwrap().clone();
                for tx in subscribers {
                    let _delivered = tx.send(Self::event(&put.stream_id, "idle")).await;
                }
                Outcome::Result(json!({ "created": created }))
            }
            Command::StreamGet(get) => match self.streams.lock().unwrap().get(&get.stream_id) {
                Some(stream) => Outcome::Result(stream.clone()),
                None => Outcome::Error(ApiError::new(ErrorCode::StreamNotFound, "no such stream")),
            },
            Command::StreamSubscribe(_) => {
                let (tx, rx) = mpsc::channel(8192);
                if let Some(flood) = &self.flood {
                    // Two MiB of signaling, more than the 1 MiB budget.
                    let flood = Arc::clone(flood);
                    lotse_core::task::spawn_named("test.flood", async move {
                        for i in 0..2048 {
                            let event = Event {
                                class: EventClass::Signaling,
                                payload: json!({ "type": "candidate", "n": i, "pad": "x".repeat(1024) }),
                            };
                            if tx.send(event).await.is_err() {
                                break;
                            }
                        }
                        flood.notify_one();
                    });
                } else {
                    for stream_id in self.streams.lock().unwrap().keys() {
                        let _queued = tx.try_send(Self::event(stream_id, "idle"));
                    }
                    self.subscribers.lock().unwrap().push(tx);
                }
                Outcome::Subscribed(rx)
            }
            Command::WebrtcOffer(offer) => {
                let (tx, rx) = mpsc::channel(8);
                let _queued = tx.try_send(Event {
                    class: EventClass::Signaling,
                    payload: json!({ "type": "session", "session_id": "s1" }),
                });
                self.sessions.lock().unwrap().push((offer.id, tx));
                Outcome::Subscribed(rx)
            }
            Command::Info(_) => Outcome::Result(json!({ "version": "0.0.0-test" })),
            Command::StreamList(_) => Outcome::Result(json!({ "streams": {} })),
            // A result over the whole outbound budget.
            Command::MetricsGet(_) => Outcome::Result(json!({ "pad": "x".repeat(2 << 20) })),
            Command::StreamDelete(_)
            | Command::WebrtcCandidate(_)
            | Command::SessionGet(_)
            | Command::SessionList(_)
            | Command::SessionClose(_)
            | Command::SessionAdopt(_)
            | Command::BackchannelRelease(_) => Outcome::Result(json!({})),
            Command::Ping(_) | Command::Schema(_) | Command::Unsubscribe(_) => Outcome::Error(
                ApiError::new(ErrorCode::InternalError, "the server answers these itself"),
            ),
        }
    }

    fn unsubscribed(&self, _connection: ConnectionId, subscription: u64) -> Option<Event> {
        {
            let mut sessions = self.sessions.lock().unwrap();
            let index = sessions.iter().position(|(id, _)| *id == subscription)?;
            sessions.remove(index);
        }
        Some(Event {
            class: EventClass::Signaling,
            payload: json!({ "type": "closed", "code": "session_closed", "message": "unsubscribed" }),
        })
    }

    fn connection_closed(&self, _connection: ConnectionId) {
        self.closed.fetch_add(1, Ordering::AcqRel);
    }
}

struct Running {
    dir: PathBuf,
    socket: PathBuf,
    shutdown: CancellationToken,
    server: JoinHandle<Result<(), ServeError>>,
    handler: Arc<FakeHandler>,
    clock: Arc<FakeClock>,
}

impl Running {
    async fn finish(self) {
        self.shutdown.cancel();
        self.server.await.unwrap().unwrap();
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

fn start(name: &str, handler: FakeHandler, max_connections: u32) -> Running {
    start_limited(name, handler, max_connections, 64)
}

fn start_limited(
    name: &str,
    handler: FakeHandler,
    max_connections: u32,
    max_subscriptions: u32,
) -> Running {
    let dir = std::env::temp_dir().join(format!("lotse-ws-{name}-{}", std::process::id()));
    let _gone = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let socket = dir.join("lotse.sock");
    let uid = owner_uid(&dir);
    let server = Server::bind(Config {
        socket: socket.clone(),
        owner_uid: uid,
        allow_uid: uid,
        max_connections,
        max_subscriptions,
    })
    .unwrap();
    let handler = Arc::new(handler);
    let shutdown = CancellationToken::new();
    let clock = Arc::new(FakeClock::default());
    let task = lotse_core::task::spawn_named(
        "test.server",
        server.serve(
            Arc::clone(&handler),
            Arc::<FakeClock>::clone(&clock),
            shutdown.clone(),
        ),
    );
    Running {
        dir,
        socket,
        shutdown,
        server: task,
        handler,
        clock,
    }
}

fn owner_uid(dir: &std::path::Path) -> u32 {
    // The test's own uid, read through the file system to keep rustix out
    // of the dev-dependencies: the directory the test just made is its
    // own. Not the temp dir itself, which belongs to root on Linux (`/tmp`)
    // and to the user only on macOS (a per-user `$TMPDIR`).
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(dir).map(|m| m.uid()).unwrap()
}

type Client = WebSocketStream<UnixStream>;

async fn connect(socket: &PathBuf) -> Client {
    let stream = UnixStream::connect(socket).await.expect("connects");
    let (ws, response) =
        tokio_tungstenite::client_async(&format!("ws://lotse{}", lotse_api_types::WS_PATH), stream)
            .await
            .expect("upgrades");
    assert_eq!(response.status().as_u16(), 101);
    ws
}

async fn send<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    frame: Value,
) {
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

/// The next frame as JSON, or `{"closed": code}` for a close frame.
async fn recv<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
) -> Value {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(text.as_str()).unwrap(),
            Some(Ok(Message::Close(frame))) => {
                let code = frame.map_or(1005, |f| u16::from(f.code));
                return json!({ "closed": code });
            }
            Some(Ok(_)) => {}
            Some(Err(err)) => return json!({ "error": err.to_string() }),
            None => return json!({ "eof": true }),
        }
    }
}

/// A log writer that keeps every line.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// Everything logged so far.
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Captures this thread's log lines at `level` and above, field values
/// included, until the guard is dropped.
fn capture(level: tracing::Level) -> (Captured, tracing::subscriber::DefaultGuard) {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(level)
        .with_ansi(false)
        .finish();
    (captured, tracing::subscriber::set_default(subscriber))
}

#[tokio::test(flavor = "current_thread")]
async fn a_connection_span_wraps_its_own_lines_and_nothing_else_the_thread_runs() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    let _logs = tracing::subscriber::set_default(subscriber);
    let running = start("span", FakeHandler::default(), 8);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    send(&mut ws, json!({ "id": 1, "type": "ping" })).await;
    assert_eq!(recv(&mut ws).await["type"], "pong");
    // The connection task is parked on its next read: its span must not
    // be left entered on this thread.
    tracing::info!("outside every connection");
    ws.close(None).await.unwrap();
    running.finish().await;

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let line = |text: &str| {
        logs.lines()
            .find(|line| line.contains(text))
            .unwrap_or_else(|| panic!("no {text:?} in {logs}"))
            .to_owned()
    };
    for own in [
        "control connection opened",
        "command",
        "control connection closed",
    ] {
        assert!(
            line(own).contains("connection{connection.id=1}"),
            "{}",
            line(own)
        );
    }
    let outside = line("outside every connection");
    assert!(!outside.contains("connection{"), "{outside}");
}

#[tokio::test]
async fn hello_comes_first_then_results_follow_the_contract() {
    let running = start("hello", FakeHandler::default(), 8);
    let mut ws = connect(&running.socket).await;
    let hello = recv(&mut ws).await;
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["api"], lotse_api_types::API_VERSION);
    assert_eq!(hello["version"], "0.0.0-test");

    send(&mut ws, json!({ "id": 1, "type": "ping" })).await;
    assert_eq!(recv(&mut ws).await, json!({ "id": 1, "type": "pong" }));

    send(&mut ws, json!({ "id": 2, "type": "stream/put", "stream_id": "front", "sources": [{ "url": "rtsp://c/" }] })).await;
    assert_eq!(
        recv(&mut ws).await,
        json!({ "id": 2, "type": "result", "success": true, "result": { "created": true } })
    );

    send(
        &mut ws,
        json!({ "id": 3, "type": "stream/get", "stream_id": "back" }),
    )
    .await;
    let failure = recv(&mut ws).await;
    assert_eq!(failure["success"], false);
    assert_eq!(failure["error"]["code"], "stream_not_found");

    send(&mut ws, json!({ "id": 3, "type": "ping" })).await;
    let reuse = recv(&mut ws).await;
    assert_eq!(
        (reuse["id"].as_u64(), reuse["error"]["code"].as_str()),
        (Some(3), Some("id_reuse"))
    );

    send(&mut ws, json!({ "id": 4, "type": "stream/explode" })).await;
    assert_eq!(recv(&mut ws).await["error"]["code"], "unknown_command");

    send(&mut ws, json!({ "id": 5, "type": "ping", "extra": true })).await;
    assert_eq!(recv(&mut ws).await["error"]["code"], "invalid_request");

    ws.send(Message::Text("not json".into())).await.unwrap();
    let broken = recv(&mut ws).await;
    assert_eq!(
        (broken["id"].clone(), broken["error"]["code"].as_str()),
        (Value::Null, Some("invalid_request"))
    );

    send(&mut ws, json!({ "id": 6, "type": "schema" })).await;
    let schema = recv(&mut ws).await;
    assert_eq!(schema["result"]["api"], lotse_api_types::API_VERSION);
    assert!(schema["result"]["command"].is_object());

    send(&mut ws, json!({ "id": 7, "type": "info" })).await;
    assert_eq!(recv(&mut ws).await["result"]["version"], "0.0.0-test");

    ws.close(None).await.unwrap();
    running.finish().await;
}

#[tokio::test]
async fn subscriptions_deliver_events_until_unsubscribed() {
    let running = start("subscribe", FakeHandler::default(), 8);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    send(&mut ws, json!({ "id": 1, "type": "stream/put", "stream_id": "a", "sources": [{ "url": "rtsp://c/" }] })).await;
    recv(&mut ws).await;

    send(&mut ws, json!({ "id": 2, "type": "stream/subscribe" })).await;
    assert_eq!(
        recv(&mut ws).await,
        json!({ "id": 2, "type": "result", "success": true, "result": {} })
    );
    let current = recv(&mut ws).await;
    assert_eq!(
        current,
        json!({ "id": 2, "type": "event", "event": { "type": "stream", "stream_id": "a", "state": "idle", "last_error": null } })
    );

    send(&mut ws, json!({ "id": 3, "type": "stream/put", "stream_id": "b", "sources": [{ "url": "rtsp://c/" }] })).await;
    let mut seen = [recv(&mut ws).await, recv(&mut ws).await];
    seen.sort_by_key(|f| f["type"].as_str().unwrap().to_owned());
    assert_eq!(seen[0]["event"]["stream_id"], "b");
    assert_eq!(seen[1]["result"]["created"], true);

    send(
        &mut ws,
        json!({ "id": 4, "type": "unsubscribe", "subscription": 2 }),
    )
    .await;
    assert_eq!(recv(&mut ws).await["success"], true);
    send(&mut ws, json!({ "id": 5, "type": "stream/put", "stream_id": "c", "sources": [{ "url": "rtsp://c/" }] })).await;
    assert_eq!(recv(&mut ws).await["result"]["created"], true);
    send(&mut ws, json!({ "id": 6, "type": "ping" })).await;
    assert_eq!(recv(&mut ws).await["type"], "pong", "no event slipped in");

    send(
        &mut ws,
        json!({ "id": 7, "type": "unsubscribe", "subscription": 2 }),
    )
    .await;
    assert_eq!(
        recv(&mut ws).await["error"]["code"],
        "subscription_not_found"
    );
    ws.close(None).await.unwrap();
    running.finish().await;
}

#[tokio::test]
async fn unsubscribing_a_session_sends_its_closed_event_before_the_result() {
    let running = start("unsubscribe-session", FakeHandler::default(), 8);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    send(
        &mut ws,
        json!({ "id": 1, "type": "webrtc/offer", "stream_id": "a", "sdp": "v=0" }),
    )
    .await;
    assert_eq!(recv(&mut ws).await["success"], true);
    assert_eq!(
        recv(&mut ws).await,
        json!({ "id": 1, "type": "event", "event": { "type": "session", "session_id": "s1" } })
    );
    send(&mut ws, json!({ "id": 2, "type": "stream/subscribe" })).await;
    assert_eq!(recv(&mut ws).await["success"], true);
    // A subscription the handler has no last word for ends silently.
    send(
        &mut ws,
        json!({ "id": 3, "type": "unsubscribe", "subscription": 2 }),
    )
    .await;
    assert_eq!(
        recv(&mut ws).await,
        json!({ "id": 3, "type": "result", "success": true, "result": {} })
    );
    send(
        &mut ws,
        json!({ "id": 4, "type": "unsubscribe", "subscription": 1 }),
    )
    .await;
    assert_eq!(
        recv(&mut ws).await,
        json!({ "id": 1, "type": "event", "event": { "type": "closed", "code": "session_closed", "message": "unsubscribed" } })
    );
    assert_eq!(
        recv(&mut ws).await,
        json!({ "id": 4, "type": "result", "success": true, "result": {} })
    );
    ws.close(None).await.unwrap();
    running.finish().await;
}

#[tokio::test]
async fn subscriptions_are_capped_per_connection_and_ended_ones_do_not_count() {
    let (logs, _guard) = capture(tracing::Level::WARN);
    let running = start_limited("subscription-cap", FakeHandler::default(), 8, 2);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    send(
        &mut ws,
        json!({ "id": 1, "type": "webrtc/offer", "stream_id": "a", "sdp": "v=0" }),
    )
    .await;
    assert_eq!(recv(&mut ws).await["success"], true);
    assert_eq!(recv(&mut ws).await["event"]["type"], "session");
    send(&mut ws, json!({ "id": 2, "type": "stream/subscribe" })).await;
    assert_eq!(recv(&mut ws).await["success"], true);

    // Every command that opens a subscription is refused at the cap,
    // before the handler sees it.
    for (id, frame) in [
        (3, json!({ "type": "stream/subscribe" })),
        (
            4,
            json!({ "type": "webrtc/offer", "stream_id": "a", "sdp": "v=0" }),
        ),
        (5, json!({ "type": "session/adopt", "session_id": "s1" })),
    ] {
        let mut frame = frame;
        frame["id"] = json!(id);
        send(&mut ws, frame).await;
        let refused = recv(&mut ws).await;
        assert_eq!(refused["id"], id);
        assert_eq!(refused["error"]["code"], "limit_reached", "{refused}");
    }
    assert_eq!(running.handler.subscribers.lock().unwrap().len(), 1);
    assert_eq!(running.handler.sessions.lock().unwrap().len(), 1);
    let refusals: Vec<String> = logs
        .text()
        .lines()
        .filter(|line| line.contains("subscription limit of the connection reached"))
        .map(str::to_owned)
        .collect();
    assert_eq!(refusals.len(), 3, "{refusals:?}");
    assert!(
        refusals[2].contains("id=5") && refusals[2].contains("session/adopt"),
        "{refusals:?}"
    );
    // Other commands are not affected.
    send(&mut ws, json!({ "id": 6, "type": "info" })).await;
    assert_eq!(recv(&mut ws).await["result"]["version"], "0.0.0-test");

    // The session's channel closes: its subscription ended and frees a slot.
    running.handler.sessions.lock().unwrap().clear();
    send(&mut ws, json!({ "id": 7, "type": "ping" })).await;
    assert_eq!(recv(&mut ws).await["type"], "pong");
    send(&mut ws, json!({ "id": 8, "type": "stream/subscribe" })).await;
    assert_eq!(recv(&mut ws).await["success"], true);
    send(&mut ws, json!({ "id": 9, "type": "stream/subscribe" })).await;
    assert_eq!(recv(&mut ws).await["error"]["code"], "limit_reached");
    ws.close(None).await.unwrap();
    running.finish().await;
}

#[tokio::test]
async fn the_connection_limit_holds_and_shutdown_says_goodbye() {
    let running = start("limit", FakeHandler::default(), 1);
    let mut first = connect(&running.socket).await;
    recv(&mut first).await;
    let stream = UnixStream::connect(&running.socket).await.unwrap();
    let err =
        tokio_tungstenite::client_async(&format!("ws://lotse{}", lotse_api_types::WS_PATH), stream)
            .await
            .expect_err("second connection refused");
    let tokio_tungstenite::tungstenite::Error::Http(response) = err else {
        panic!("{err}")
    };
    assert_eq!(response.status().as_u16(), 503);
    let body = String::from_utf8_lossy(response.body().as_deref().unwrap_or_default()).to_string();
    assert!(body.contains("limit_reached"), "{body}");

    running.shutdown.cancel();
    assert_eq!(recv(&mut first).await, json!({ "type": "shutdown" }));
    assert_eq!(recv(&mut first).await, json!({ "closed": 1001 }));
    running.server.await.unwrap().unwrap();
    assert_eq!(running.handler.closed.load(Ordering::Acquire), 1);
    std::fs::remove_dir_all(&running.dir).unwrap();
}

#[tokio::test]
async fn oversize_and_binary_frames_end_the_connection() {
    let running = start("frames", FakeHandler::default(), 8);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    ws.send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(recv(&mut ws).await, json!({ "closed": 1003 }));

    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    let huge = format!(
        "{{\"id\":1,\"type\":\"ping\",\"pad\":\"{}\"}}",
        "x".repeat(70_000)
    );
    let _sent = ws.send(Message::Text(huge.into())).await;
    let ended = recv(&mut ws).await;
    assert!(
        ended.get("closed").is_some() || ended.get("eof").is_some() || ended.get("error").is_some(),
        "{ended}"
    );
    running.finish().await;
}

/// `future`, or a panic after 5 s of real time: a server that waits where
/// it must not fails the test instead of hanging it.
#[expect(
    clippy::disallowed_methods,
    reason = "a real-time bound on a test step; the server under test has no timer here"
)]
async fn within_5_s<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(5), future)
        .await
        .expect("finished within 5 s")
}

#[tokio::test]
async fn rfc6455_s5_2_a_frame_announcing_more_than_64_kib_ends_the_connection_at_its_header() {
    use tokio::io::AsyncWriteExt as _;

    let running = start("frame-header", FakeHandler::default(), 8);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    // A masked text frame with the 64-bit length form (RFC 6455 §5.2)
    // announcing one byte over the cap; its payload never comes. Before
    // the frame cap, the server reserved the length and waited for it.
    let announced = u64::try_from(MAX_MESSAGE_BYTES).unwrap() + 1;
    let mut header = vec![0x81, 0x80 | 127];
    header.extend_from_slice(&announced.to_be_bytes());
    header.extend_from_slice(&[1, 2, 3, 4]);
    ws.get_mut().write_all(&header).await.unwrap();
    let ended = within_5_s(recv(&mut ws)).await;
    assert!(
        ended.get("closed").is_some() || ended.get("eof").is_some() || ended.get("error").is_some(),
        "{ended}"
    );
    within_5_s(async {
        while running.handler.closed.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    running.finish().await;
}

#[tokio::test]
async fn a_client_that_cannot_keep_up_is_disconnected_with_1008() {
    let flood = Arc::new(Notify::new());
    let handler = FakeHandler {
        flood: Some(Arc::clone(&flood)),
        ..FakeHandler::default()
    };
    let running = start("overflow", handler, 8);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    send(&mut ws, json!({ "id": 1, "type": "stream/subscribe" })).await;
    // Do not read until the whole flood has been pushed at the server.
    flood.notified().await;
    let mut frames = 0;
    loop {
        let frame = recv(&mut ws).await;
        if frame.get("closed").is_some()
            || frame.get("eof").is_some()
            || frame.get("error").is_some()
        {
            assert_eq!(frame, json!({ "closed": 1008 }));
            break;
        }
        frames += 1;
    }
    assert!(
        frames > 0 && frames < 2049,
        "some events, not all: {frames}"
    );
    running.finish().await;
}

#[tokio::test]
async fn rfc6455_s7_1_1_a_peer_that_never_reads_is_dropped_at_the_close_deadline() {
    let (logs, _guard) = capture(tracing::Level::WARN);
    let flood = Arc::new(Notify::new());
    let handler = FakeHandler {
        flood: Some(Arc::clone(&flood)),
        ..FakeHandler::default()
    };
    let running = start("stalled", handler, 1);
    let mut stalled = connect(&running.socket).await;
    send(&mut stalled, json!({ "id": 1, "type": "stream/subscribe" })).await;
    // The client reads nothing: the socket fills, the queue overflows and
    // the 1008 close sits behind what the writer cannot send.
    flood.notified().await;

    // Before the deadline the sessions are orphaned and the one slot is
    // free again.
    assert_eq!(running.handler.closed.load(Ordering::Acquire), 1);
    let mut next = connect(&running.socket).await;
    assert_eq!(recv(&mut next).await["type"], "hello");

    running.clock.advance(CLOSE_TIMEOUT);
    // Let the connection task see the deadline before the client starts
    // reading and unblocks the writer.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    let mut frames = 0;
    let ended = loop {
        let frame = recv(&mut stalled).await;
        if frame.get("type").is_none() {
            break frame;
        }
        frames += 1;
    };
    assert!(
        ended.get("eof").is_some() || ended.get("error").is_some(),
        "dropped without the close frame: {ended}"
    );
    assert!(frames < 2049, "not every event: {frames}");
    let dropped = logs.text();
    let dropped = dropped
        .lines()
        .find(|line| line.contains("did not take the close frame before the deadline"))
        .unwrap_or_else(|| panic!("no deadline line in {dropped}"));
    assert!(dropped.contains("overflow"), "{dropped}");
    assert!(dropped.contains("queued_bytes="), "{dropped}");

    // The connection that took the slot is unaffected.
    send(&mut next, json!({ "id": 1, "type": "ping" })).await;
    assert_eq!(recv(&mut next).await, json!({ "id": 1, "type": "pong" }));
    next.close(None).await.unwrap();
    running.finish().await;
}

#[tokio::test]
async fn a_peer_gone_while_a_frame_is_written_ends_the_writer() {
    let (logs, _guard) = capture(tracing::Level::DEBUG);
    let flood = Arc::new(Notify::new());
    let handler = FakeHandler {
        flood: Some(Arc::clone(&flood)),
        ..FakeHandler::default()
    };
    let running = start("gone", handler, 8);
    let mut gone = connect(&running.socket).await;
    send(&mut gone, json!({ "id": 1, "type": "stream/subscribe" })).await;
    // Nothing is read: the writer waits on a full socket in a text frame,
    // which fails once the peer is gone.
    flood.notified().await;
    drop(gone);
    within_5_s(async {
        while !logs.text().contains("control connection write failed") {
            tokio::task::yield_now().await;
        }
    })
    .await;
    running.finish().await;
}

#[tokio::test]
async fn a_result_over_the_outbound_budget_disconnects_with_1008() {
    let running = start("huge-result", FakeHandler::default(), 8);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    send(&mut ws, json!({ "id": 1, "type": "metrics/get" })).await;
    assert_eq!(recv(&mut ws).await, json!({ "closed": 1008 }));
    running.finish().await;
}

#[tokio::test]
async fn rfc6455_s5_5_pings_change_nothing_and_a_close_frame_ends_the_connection() {
    let running = start("peer-close", FakeHandler::default(), 8);
    let mut ws = connect(&running.socket).await;
    recv(&mut ws).await;
    // §5.5.2: the WebSocket layer answers the ping; `recv` skips the pong.
    ws.send(Message::Ping(vec![1].into())).await.unwrap();
    ws.send(Message::Pong(vec![2].into())).await.unwrap();
    send(&mut ws, json!({ "id": 1, "type": "ping" })).await;
    assert_eq!(recv(&mut ws).await, json!({ "id": 1, "type": "pong" }));
    // §5.5.1: the peer's close frame ends the connection.
    ws.send(Message::Close(None)).await.unwrap();
    let ended = recv(&mut ws).await;
    assert!(ended.get("closed").is_some(), "{ended}");
    within_5_s(async {
        while running.handler.closed.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    running.finish().await;
}

/// A WebSocket upgrade request for the control path, with `extra` header
/// lines (each ending in CRLF) before the blank line.
fn upgrade_request(extra: &str) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: lotse\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{extra}\r\n",
        lotse_api_types::WS_PATH
    )
}

/// Writes `request` and reads the response head, or what came before EOF.
async fn raw_exchange(socket: &PathBuf, request: &str) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = UnixStream::connect(socket).await.unwrap();
    let _written = stream.write_all(request.as_bytes()).await;
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => break,
            Ok(_) => head.push(byte[0]),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

#[tokio::test]
async fn rfc6585_s5_upgrade_headers_over_16_kib_are_refused_with_431() {
    let running = start("big-headers", FakeHandler::default(), 8);
    let fits = upgrade_request(&format!("x-pad: {}\r\n", "x".repeat(12 * 1024)));
    assert!(
        raw_exchange(&running.socket, &fits)
            .await
            .starts_with("HTTP/1.1 101"),
        "12 KiB of headers still upgrade"
    );
    let big = upgrade_request(&format!("x-pad: {}\r\n", "x".repeat(17 * 1024)));
    let head = raw_exchange(&running.socket, &big).await;
    assert!(head.starts_with("HTTP/1.1 431"), "{head}");
    running.finish().await;
}

#[tokio::test]
async fn rfc6585_s5_more_than_32_upgrade_headers_are_refused_with_431() {
    let running = start("many-headers", FakeHandler::default(), 8);
    let lines = |n: usize| "x-h: v\r\n".repeat(n);
    // Five header fields of the upgrade itself, plus extras.
    let fits = upgrade_request(&lines(27));
    assert!(
        raw_exchange(&running.socket, &fits)
            .await
            .starts_with("HTTP/1.1 101"),
        "32 headers still upgrade"
    );
    let head = raw_exchange(&running.socket, &upgrade_request(&lines(28))).await;
    assert!(head.starts_with("HTTP/1.1 431"), "{head}");
    running.finish().await;
}

/// Connects and sends the start of an upgrade request, never its end.
async fn half_sent(socket: &PathBuf) -> UnixStream {
    use tokio::io::AsyncWriteExt as _;
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream
        .write_all(format!("GET {} HTTP/1.1\r\nHost: lo", lotse_api_types::WS_PATH).as_bytes())
        .await
        .unwrap();
    stream
}

/// Reads until EOF and returns what came.
async fn drain(stream: &mut UnixStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt as _;
    let mut rest = Vec::new();
    let _read = stream.read_to_end(&mut rest).await;
    rest
}

#[tokio::test]
async fn a_peer_that_never_finishes_its_upgrade_is_closed_at_the_deadline() {
    let running = start("slow-headers", FakeHandler::default(), 8);
    let mut slow = half_sent(&running.socket).await;
    // Accepted in order: once the next connection is upgraded, the slow
    // one's deadline is set.
    let mut upgraded = connect(&running.socket).await;
    recv(&mut upgraded).await;
    running.clock.advance(UPGRADE_TIMEOUT);
    assert!(
        drain(&mut slow).await.is_empty(),
        "closed without a response"
    );
    // The deadline ends with the upgrade: the open connection still works.
    send(&mut upgraded, json!({ "id": 2, "type": "ping" })).await;
    assert_eq!(
        recv(&mut upgraded).await,
        json!({ "id": 2, "type": "pong" })
    );
    running.finish().await;
}

#[tokio::test]
async fn connections_awaiting_the_upgrade_are_bounded() {
    let running = start("pending", FakeHandler::default(), 8);
    let mut parked = Vec::new();
    for _ in 0..MAX_PENDING_UPGRADES {
        parked.push(half_sent(&running.socket).await);
    }
    let mut refused = half_sent(&running.socket).await;
    assert!(drain(&mut refused).await.is_empty(), "closed at accept");
    // A parked connection that ends gives its slot back.
    drop(parked.pop());
    let mut attempts = 0;
    let mut upgraded = loop {
        attempts += 1;
        assert!(attempts < 10_000, "the slot never came back");
        let stream = UnixStream::connect(&running.socket).await.unwrap();
        if let Ok((ws, _)) = tokio_tungstenite::client_async(
            &format!("ws://lotse{}", lotse_api_types::WS_PATH),
            stream,
        )
        .await
        {
            break ws;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(recv(&mut upgraded).await["type"], "hello");
    // Shutdown closes the connections still waiting and returns.
    running.shutdown.cancel();
    for stream in &mut parked {
        assert!(drain(stream).await.is_empty());
    }
    running.server.await.unwrap().unwrap();
    std::fs::remove_dir_all(&running.dir).unwrap();
}
