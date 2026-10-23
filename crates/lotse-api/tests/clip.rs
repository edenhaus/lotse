//! `GET /v0/clips/{clip_id}` end to end over a real Unix socket: a clip's
//! bytes as one chunked body, whole or cut, the refusals, and what bounds
//! a body's connection (the client taking it, shutdown), against
//! `test_util`'s clips standing in for the supervisor's.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use futures_util::StreamExt as _;
use lotse_api::test_util::{FakeClipWriter, FakeClips};
use lotse_api::{
    BODY_STALL_TIMEOUT, CLOSE_TIMEOUT, ClipBody, ClipBodyError, Config, ConnectionId, Handler,
    MAX_PENDING_UPGRADES, Outcome, ServeError, Server, UPGRADE_TIMEOUT,
};
use lotse_api_types::command::Command;
use lotse_api_types::frame::{Hello, HelloTag};
use lotse_core::clock::FakeClock;
use lotse_core::id::ClipId;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

/// The supervisor's stand-in: its clips, nothing else.
#[derive(Default)]
struct ClipHandler {
    clips: FakeClips,
}

impl Handler for ClipHandler {
    fn hello(&self) -> Hello {
        Hello {
            kind: HelloTag::default(),
            api: lotse_api_types::API_VERSION.into(),
            version: "0.0.0-test".into(),
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

    fn clip_body(&self, clip_id: &ClipId) -> Result<ClipBody, ClipBodyError> {
        self.clips.take(clip_id)
    }
}

struct Running {
    dir: PathBuf,
    socket: PathBuf,
    shutdown: CancellationToken,
    server: JoinHandle<Result<(), ServeError>>,
    handler: Arc<ClipHandler>,
    clock: Arc<FakeClock>,
}

impl Running {
    async fn finish(self) {
        self.shutdown.cancel();
        self.server.await.unwrap().unwrap();
        std::fs::remove_dir_all(&self.dir).unwrap();
    }

    /// Opens clip `clip_id` on the handler.
    fn open(&self, clip_id: &str) -> FakeClipWriter {
        self.handler.clips.open(clip_id)
    }
}

fn start(name: &str) -> Running {
    let dir = std::env::temp_dir().join(format!("lotse-clip-{name}-{}", std::process::id()));
    let _gone = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let socket = dir.join("lotse.sock");
    let uid = {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(&dir).map(|m| m.uid()).unwrap()
    };
    let server = Server::bind(Config {
        socket: socket.clone(),
        owner_uid: uid,
        allow_uid: uid,
        max_connections: 8,
        max_subscriptions: 8,
        tls: None,
    })
    .unwrap();
    let handler = Arc::new(ClipHandler::default());
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

#[expect(
    clippy::disallowed_methods,
    reason = "a real-time bound on a test step; the server under test has no timer here"
)]
async fn within_5_s<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(5), future)
        .await
        .expect("finished within 5 s")
}

/// Lets the server's tasks run.
async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// Sends `method path` over a new connection and returns it; the server
/// closes it after its answer.
async fn request(socket: &PathBuf, method: &str, path: &str) -> UnixStream {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: lotse\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream
}

/// Everything the server sends until it closes the connection.
async fn read_all(stream: &mut UnixStream) -> Vec<u8> {
    let mut all = Vec::new();
    let _read = within_5_s(stream.read_to_end(&mut all)).await;
    all
}

/// A response as read off the wire.
#[derive(Debug)]
struct Response {
    /// The status line and header fields, lowercased.
    head: String,
    /// The body: the chunks' data, or the bytes after the head when not
    /// chunked.
    body: Vec<u8>,
    /// Whether a chunked body ended with its last chunk (RFC 9112 §7.1).
    last_chunk: bool,
}

impl Response {
    fn parse(raw: &[u8]) -> Self {
        let end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a complete head");
        let head = String::from_utf8(raw[..end].to_vec())
            .unwrap()
            .to_lowercase();
        let mut rest = &raw[end + 4..];
        if !head.contains("transfer-encoding: chunked") {
            return Self {
                head,
                body: rest.to_vec(),
                last_chunk: false,
            };
        }
        let mut body = Vec::new();
        loop {
            let Some(line) = rest.windows(2).position(|w| w == b"\r\n") else {
                return Self {
                    head,
                    body,
                    last_chunk: false,
                };
            };
            let size =
                usize::from_str_radix(std::str::from_utf8(&rest[..line]).unwrap(), 16).unwrap();
            rest = &rest[line + 2..];
            if size == 0 {
                assert_eq!(rest, b"\r\n", "the last chunk ends the message");
                return Self {
                    head,
                    body,
                    last_chunk: true,
                };
            }
            if rest.len() < size + 2 {
                body.extend_from_slice(&rest[..rest.len().min(size)]);
                return Self {
                    head,
                    body,
                    last_chunk: false,
                };
            }
            body.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
    }

    fn status(&self) -> &str {
        &self.head[9..12]
    }

    fn error_code(&self) -> String {
        let error: serde_json::Value = serde_json::from_slice(&self.body).unwrap();
        error["code"].as_str().unwrap().to_owned()
    }
}

/// Reads until the head of a response arrived and returns what came.
async fn read_head(stream: &mut UnixStream) -> Vec<u8> {
    let mut raw = Vec::new();
    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut buf = [0_u8; 4096];
        let n = within_5_s(stream.read(&mut buf)).await.unwrap();
        assert!(n > 0, "closed before the head: {raw:?}");
        raw.extend_from_slice(&buf[..n]);
    }
    raw
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
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Captures this thread's log lines at `level` and above until the guard
/// is dropped.
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
async fn rfc9112_7_1_chunked_body_ends_with_the_last_chunk() {
    let (logs, _guard) = capture(tracing::Level::INFO);
    let running = start("whole");
    let mut writer = running.open("c1");
    let mut client = request(&running.socket, "GET", "/v0/clips/c1").await;
    writer.write(b"ftyp-moov-").await.unwrap();
    settle().await;
    let middle = vec![7_u8; 100_000];
    writer.write(&middle).await.unwrap();
    writer.write(b"-moof-mdat").await.unwrap();
    writer.finish();
    // The server closes the connection after the body (RFC 9112 §9.6).
    let response = Response::parse(&read_all(&mut client).await);
    assert_eq!(response.status(), "200", "{}", response.head);
    for field in [
        "content-type: video/mp4",
        "cache-control: no-store",
        "connection: close",
        "x-clip-id: c1",
        "transfer-encoding: chunked",
    ] {
        assert!(response.head.contains(field), "{field}: {}", response.head);
    }
    assert!(response.last_chunk, "ended whole");
    let mut expected = b"ftyp-moov-".to_vec();
    expected.extend_from_slice(&middle);
    expected.extend_from_slice(b"-moof-mdat");
    assert_eq!(response.body, expected);
    let text = logs.text();
    assert!(text.contains("clip body: sending"), "{text}");
    assert!(text.contains("clip body: sent whole"), "{text}");
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9112_8_a_clip_cut_short_ends_without_the_last_chunk() {
    let running = start("cut");
    // Its worker died: the bytes end and no report comes.
    let mut crashed = running.open("crashed");
    let mut client = request(&running.socket, "GET", "/v0/clips/crashed").await;
    crashed.write(b"ftyp").await.unwrap();
    crashed.crash();
    let response = Response::parse(&read_all(&mut client).await);
    assert_eq!(response.status(), "200");
    assert_eq!(response.body, b"ftyp");
    assert!(!response.last_chunk, "a truncated transfer");
    // The report says more was written than arrived.
    let mut short = running.open("short");
    let mut client = request(&running.socket, "GET", "/v0/clips/short").await;
    short.write(b"ftyp").await.unwrap();
    short.finish_reporting(5);
    let response = Response::parse(&read_all(&mut client).await);
    assert!(!response.last_chunk);
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9110_15_5_a_clip_is_fetched_once_and_an_unknown_one_not_at_all() {
    let running = start("once");
    let writer = running.open("c1");
    let mut first = request(&running.socket, "GET", "/v0/clips/c1").await;
    let head = read_head(&mut first).await;
    assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    // RFC 9110 §15.5.10: a clip has one body.
    let mut second = request(&running.socket, "GET", "/v0/clips/c1").await;
    let response = Response::parse(&read_all(&mut second).await);
    assert_eq!(
        (response.status(), response.error_code().as_str()),
        ("409", "clip_already_fetched")
    );
    assert!(response.head.contains("content-type: application/json"));
    // RFC 9110 §15.5.5: no open clip has the id, or no clip can.
    for path in ["/v0/clips/never", "/v0/clips/%FF", "/v0/clips/a%20b"] {
        let mut other = request(&running.socket, "GET", path).await;
        let response = Response::parse(&read_all(&mut other).await);
        assert_eq!(
            (response.status(), response.error_code().as_str()),
            ("404", "clip_not_found"),
            "{path}"
        );
    }
    // The first request still gets the clip.
    writer.finish();
    let mut rest = head;
    rest.extend(read_all(&mut first).await);
    let response = Response::parse(&rest);
    assert!(response.last_chunk && response.body.is_empty());
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9110_15_5_6_head_and_other_methods_are_405_and_leave_the_clip() {
    let running = start("methods");
    let writer = running.open("c1");
    for method in ["HEAD", "POST", "DELETE"] {
        let mut client = request(&running.socket, method, "/v0/clips/c1").await;
        let raw = read_all(&mut client).await;
        let head = String::from_utf8_lossy(&raw).to_lowercase();
        assert!(head.starts_with("http/1.1 405"), "{method}: {head}");
        assert!(head.contains("allow: get\r\n"), "{method}: {head}");
    }
    let mut client = request(&running.socket, "GET", "/v0/clips/c1").await;
    writer.finish();
    let response = Response::parse(&read_all(&mut client).await);
    assert_eq!(response.status(), "200");
    assert!(response.last_chunk);
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_clip_body_leaves_the_upgrade_deadline_and_the_pending_slots() {
    let running = start("slots");
    let mut writer = running.open("c1");
    let mut client = request(&running.socket, "GET", "/v0/clips/c1").await;
    writer.write(b"ftyp").await.unwrap();
    let mut seen = read_head(&mut client).await;
    // Past the upgrade's deadline the body still flows.
    running.clock.advance(UPGRADE_TIMEOUT);
    settle().await;
    writer.write(b"moof").await.unwrap();
    // Every pending slot is free for others: the last one upgrades.
    let mut parked = Vec::new();
    for _ in 1..MAX_PENDING_UPGRADES {
        let mut stream = UnixStream::connect(&running.socket).await.unwrap();
        stream
            .write_all(b"GET /v0/ws HTTP/1.1\r\nHost: lo")
            .await
            .unwrap();
        parked.push(stream);
    }
    settle().await;
    let stream = UnixStream::connect(&running.socket).await.unwrap();
    let (mut ws, _) = within_5_s(tokio_tungstenite::client_async(
        &format!("ws://lotse{}", lotse_api_types::WS_PATH),
        stream,
    ))
    .await
    .expect("upgrades");
    let Some(Ok(Message::Text(hello))) = within_5_s(ws.next()).await else {
        panic!("no hello");
    };
    assert!(hello.as_str().contains("\"hello\""));
    writer.finish();
    seen.extend(read_all(&mut client).await);
    let response = Response::parse(&seen);
    assert_eq!(response.body, b"ftypmoof");
    assert!(response.last_chunk);
    drop(parked);
    drop(ws);
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_client_that_takes_none_of_a_body_is_dropped_at_the_stall_deadline() {
    let (logs, _guard) = capture(tracing::Level::WARN);
    let running = start("stall");
    let mut writer = running.open("c1");
    let client = request(&running.socket, "GET", "/v0/clips/c1").await;
    // The client reads nothing: the socket, the server's buffer and the
    // pipe fill, and the producer waits.
    let mut written = 0_usize;
    let chunk = [1_u8; 16 * 1024];
    loop {
        let wrote = tokio::select! {
            result = writer.write(&chunk) => { result.unwrap(); true }
            () = settle() => false,
        };
        if !wrote {
            break;
        }
        written += chunk.len();
        assert!(written < 64 << 20, "the body never filled up");
    }
    running.clock.advance(BODY_STALL_TIMEOUT);
    settle().await;
    // Dropped: the reader is gone, as a pipe whose read end closed.
    let failed = loop {
        if let Err(err) = writer.write(&chunk).await {
            break err;
        }
    };
    assert_eq!(failed.kind(), std::io::ErrorKind::BrokenPipe);
    let text = logs.text();
    assert!(
        text.contains("clip body dropped: the client made no room for it in time"),
        "{text}"
    );
    drop(client);
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_client_gone_early_fails_the_producers_writes() {
    let running = start("gone");
    let mut writer = running.open("c1");
    let mut client = request(&running.socket, "GET", "/v0/clips/c1").await;
    writer.write(b"ftyp").await.unwrap();
    read_head(&mut client).await;
    drop(client);
    let chunk = [1_u8; 16 * 1024];
    let mut attempts = 0;
    let failed = loop {
        attempts += 1;
        assert!(attempts < 10_000, "the body outlived its client");
        if let Err(err) = writer.write(&chunk).await {
            break err;
        }
        settle().await;
    };
    assert_eq!(failed.kind(), std::io::ErrorKind::BrokenPipe);
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_waits_for_a_body_that_ends_in_time_and_drops_one_that_does_not() {
    // The clip ends whole after shutdown began: the server waits for it.
    let running = start("shutdown-whole");
    let mut writer = running.open("c1");
    let mut client = request(&running.socket, "GET", "/v0/clips/c1").await;
    let mut seen = read_head(&mut client).await;
    running.shutdown.cancel();
    settle().await;
    assert!(
        !running.server.is_finished(),
        "the body is still being sent"
    );
    writer.write(b"last").await.unwrap();
    writer.finish();
    seen.extend(read_all(&mut client).await);
    let response = Response::parse(&seen);
    assert_eq!(response.body, b"last");
    assert!(response.last_chunk);
    within_5_s(running.server).await.unwrap().unwrap();
    std::fs::remove_dir_all(&running.dir).unwrap();

    // The clip outlives the close timeout: it is dropped, cut.
    let (logs, _guard) = capture(tracing::Level::WARN);
    let running = start("shutdown-cut");
    let _writer = running.open("c1");
    let mut client = request(&running.socket, "GET", "/v0/clips/c1").await;
    let mut seen = read_head(&mut client).await;
    running.shutdown.cancel();
    settle().await;
    running.clock.advance(CLOSE_TIMEOUT);
    within_5_s(running.server).await.unwrap().unwrap();
    seen.extend(read_all(&mut client).await);
    assert!(!Response::parse(&seen).last_chunk);
    let text = logs.text();
    assert!(
        text.contains("clip body dropped: still being sent when shutdown's close timeout ran out"),
        "{text}"
    );
    std::fs::remove_dir_all(&running.dir).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_connection_that_never_asks_for_a_clip_keeps_the_upgrade_deadline() {
    let (logs, _guard) = capture(tracing::Level::WARN);
    let running = start("deadline");
    let mut slow = UnixStream::connect(&running.socket).await.unwrap();
    slow.write_all(b"GET /v0/clips/c1 HTTP/1.1\r\nHost: lo")
        .await
        .unwrap();
    settle().await;
    running.clock.advance(UPGRADE_TIMEOUT);
    assert!(
        read_all(&mut slow).await.is_empty(),
        "closed without a response"
    );
    let text = logs.text();
    assert!(
        text.contains("control connection closed: no upgrade before the deadline"),
        "{text}"
    );
    running.finish().await;
}

#[test]
fn a_fake_clip_is_handed_out_once() {
    let clips = FakeClips::default();
    let id = ClipId::new("c1").unwrap();
    assert_eq!(clips.take(&id).unwrap_err(), ClipBodyError::NotFound);
    let _writer = clips.open("c1");
    assert!(clips.take(&id).is_ok());
    assert_eq!(clips.take(&id).unwrap_err(), ClipBodyError::AlreadyFetched);
}
