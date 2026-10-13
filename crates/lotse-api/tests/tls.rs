//! The mutual-TLS listener end to end over real TCP: who gets in, who is
//! refused before a byte of HTTP, the handshake deadline on the clock, the
//! pre-authentication budget per address, and what is logged.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures_util::StreamExt as _;
use lotse_api::identity::{IDENTITY_FILE, ServerIdentity};
use lotse_api::tls::{
    HANDSHAKE_TIMEOUT, MAX_HANDSHAKES_PER_ADDRESS, MAX_PENDING_HANDSHAKES, TlsConfig,
};
use lotse_api::{BindError, Config, ConnectionId, Handler, Outcome, ServeError, Server};
use lotse_api_types::command::Command;
use lotse_api_types::frame::{Hello, HelloTag};
use lotse_core::clock::FakeClock;
use lotse_core::fingerprint::Fingerprint;
use lotse_testing::control_tls::{
    ClientCert, ClientIdentity, client_config, connect, connect_from, tcp_from,
};
use rustls::HandshakeKind;
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

struct Minimal;

impl Handler for Minimal {
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
        std::future::ready(Outcome::Result(Value::Null))
    }
}

struct Running {
    dir: PathBuf,
    addr: SocketAddr,
    server_pin: Fingerprint,
    shutdown: CancellationToken,
    server: JoinHandle<Result<(), ServeError>>,
    clock: Arc<FakeClock>,
}

impl Running {
    async fn finish(self) {
        self.shutdown.cancel();
        self.server.await.unwrap().unwrap();
        std::fs::remove_dir_all(&self.dir).unwrap();
    }

    fn config(&self, cert: ClientCert<'_>) -> Arc<rustls::ClientConfig> {
        client_config(self.server_pin, cert, TLS13).unwrap()
    }
}

fn private_dir(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn uid_of(path: &Path) -> u32 {
    std::fs::metadata(path).map(|m| m.uid()).unwrap()
}

/// A test directory with the socket's and the data directory inside.
fn dirs(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("lotse-tls-{name}-{}", std::process::id()));
    let _gone = std::fs::remove_dir_all(&dir);
    private_dir(&dir);
    let data = dir.join("data");
    private_dir(&data);
    (dir, data)
}

fn config(dir: &Path, data: &Path, clients: Vec<Fingerprint>) -> Config {
    let uid = uid_of(dir);
    Config {
        socket: dir.join("lotse.sock"),
        owner_uid: uid,
        allow_uid: uid,
        max_connections: 8,
        max_subscriptions: 8,
        tls: Some(TlsConfig {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            clients,
            data_dir: data.to_path_buf(),
        }),
    }
}

fn start(name: &str, clients: Vec<Fingerprint>) -> Running {
    let (dir, data) = dirs(name);
    let server = Server::bind(config(&dir, &data, clients)).unwrap();
    let addr = server.tls_local_addr().unwrap();
    let server_pin = ServerIdentity::load(&data, uid_of(&dir)).unwrap().pin();
    let shutdown = CancellationToken::new();
    let clock = Arc::new(FakeClock::default());
    let task = lotse_core::task::spawn_named(
        "test.server",
        server.serve(
            Arc::new(Minimal),
            Arc::<FakeClock>::clone(&clock),
            shutdown.clone(),
        ),
    );
    Running {
        dir,
        addr,
        server_pin,
        shutdown,
        server: task,
        clock,
    }
}

/// The WebSocket upgrade on an authenticated stream, and its first frame.
async fn hello(stream: TlsStream<TcpStream>) -> Value {
    let (mut ws, response) =
        tokio_tungstenite::client_async(&format!("ws://lotse{}", lotse_api_types::WS_PATH), stream)
            .await
            .expect("upgrades");
    assert_eq!(response.status().as_u16(), 101);
    match ws.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(text.as_str()).unwrap(),
        other => panic!("no hello: {other:?}"),
    }
}

/// What the server answers an HTTP request after the client's half of the
/// handshake: `Ok` with the bytes until the server closed, or the error
/// that ended the connection (the server's alert).
async fn exchange(connected: io::Result<TlsStream<TcpStream>>) -> io::Result<Vec<u8>> {
    let mut stream = connected?;
    stream
        .write_all(b"GET /v0/ws HTTP/1.1\r\nHost: lotse\r\nConnection: close\r\n\r\n")
        .await?;
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await?;
    Ok(answer)
}

/// Refused before HTTP: no byte of an answer, whatever ended it.
fn refused(answer: &io::Result<Vec<u8>>) -> bool {
    answer.as_ref().map_or(true, Vec::is_empty)
}

/// Reads until EOF or an error and returns what came, failing the test
/// after 5 s of real time: a connection the server should have closed and
/// did not would otherwise wait for a fake clock that never moves.
#[expect(
    clippy::disallowed_methods,
    reason = "a real-time bound on a test step; the server's own timers run on the fake clock"
)]
async fn drain(stream: &mut TcpStream) -> Vec<u8> {
    let mut rest = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut rest),
    )
    .await;
    assert!(read.is_ok(), "still open after 5 s");
    rest
}

/// A log writer that keeps every line.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Captures this thread's log lines until the guard is dropped.
fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    io::Write::flush(&mut captured.clone()).unwrap();
    (captured, tracing::subscriber::set_default(subscriber))
}

#[tokio::test(flavor = "current_thread")]
async fn an_allowed_client_gets_the_api_and_is_logged_with_its_pin() {
    let (logs, _guard) = capture();
    let p256 = ClientIdentity::generate().unwrap();
    let ed25519 = ClientIdentity::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let running = start("allowed", vec![p256.pin, ed25519.pin]);
    for client in [&p256, &ed25519] {
        let stream = connect(running.addr, running.config(ClientCert::Own(client)))
            .await
            .unwrap();
        assert_eq!(hello(stream).await["type"], "hello");
    }
    let text = logs.text();
    let pin = format!("client_pin={}", p256.pin);
    assert!(
        text.lines()
            .any(|line| line.contains("control client authenticated") && line.contains(&pin)),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "control connection opened peer=client {} at 127.0.0.1:",
            ed25519.pin
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "control TLS listener bound addr={} server_pin={}",
            running.addr, running.server_pin
        )),
        "{text}"
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8446_4_4_2_a_client_without_a_certificate_is_refused_before_http() {
    let (logs, _guard) = capture();
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("no-cert", vec![allowed.pin]);
    let answer = exchange(connect(running.addr, running.config(ClientCert::None)).await).await;
    assert!(refused(&answer), "{answer:?}");
    assert!(
        logs.text().contains("control TLS handshake failed"),
        "{}",
        logs.text()
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_unknown_pin_is_refused_before_http_and_logged_once_per_interval() {
    let (logs, _guard) = capture();
    let allowed = ClientIdentity::generate().unwrap();
    let stranger = ClientIdentity::generate().unwrap();
    let running = start("unknown", vec![allowed.pin]);
    for _ in 0..2 {
        let answer =
            exchange(connect(running.addr, running.config(ClientCert::Own(&stranger))).await).await;
        assert!(refused(&answer), "{answer:?}");
    }
    let line = format!("refused_client={} refused=1", stranger.pin);
    assert_eq!(logs.text().matches(&line).count(), 1, "{}", logs.text());
    running
        .clock
        .advance(lotse_core::throttle::SUMMARY_INTERVAL);
    let answer =
        exchange(connect(running.addr, running.config(ClientCert::Own(&stranger))).await).await;
    assert!(refused(&answer), "{answer:?}");
    let summary = format!("refused_client={} refused=2", stranger.pin);
    assert!(logs.text().contains(&summary), "{}", logs.text());
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8446_4_4_3_the_allowed_certificate_with_another_key_is_refused() {
    let allowed = ClientIdentity::generate().unwrap();
    let thief = ClientIdentity::generate().unwrap();
    let running = start("wrong-key", vec![allowed.pin]);
    let cert = ClientCert::WrongKey {
        presented: &allowed,
        signing: &thief,
    };
    let answer = exchange(connect(running.addr, running.config(cert)).await).await;
    assert!(refused(&answer), "{answer:?}");
    // The same certificate with its own key gets in.
    let stream = connect(running.addr, running.config(ClientCert::Own(&allowed)))
        .await
        .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8446_4_3_2_a_signature_in_a_scheme_not_offered_is_refused() {
    let (logs, _guard) = capture();
    // A valid P-384 signature by an allowed certificate: only the offered
    // schemes keep it out.
    let p384 = ClientIdentity::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let running = start("scheme", vec![p384.pin]);
    let answer = exchange(
        connect(
            running.addr,
            running.config(ClientCert::UnofferedScheme(&p384)),
        )
        .await,
    )
    .await;
    assert!(refused(&answer), "{answer:?}");
    assert!(
        logs.text().contains("control TLS handshake failed"),
        "{}",
        logs.text()
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_1_2_is_refused() {
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("tls12", vec![allowed.pin]);
    let tls12 = client_config(
        running.server_pin,
        ClientCert::Own(&allowed),
        &[&rustls::version::TLS12],
    )
    .unwrap();
    let err = connect(running.addr, tls12).await.unwrap_err();
    assert!(err.to_string().contains("ProtocolVersion"), "{err}");
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8446_2_2_no_session_is_resumed() {
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("resume", vec![allowed.pin]);
    // One client configuration, so its session cache carries over.
    let config = running.config(ClientCert::Own(&allowed));
    for _ in 0..2 {
        let stream = connect(running.addr, Arc::clone(&config)).await.unwrap();
        assert_eq!(
            stream.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Full)
        );
        // Reading lets any ticket the server sent reach the cache.
        assert_eq!(hello(stream).await["type"], "hello");
    }
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_stalled_handshake_is_closed_at_the_deadline_on_the_clock() {
    let (logs, _guard) = capture();
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("deadline", vec![allowed.pin]);
    let mut stalled = TcpStream::connect(running.addr).await.unwrap();
    let second = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
    let mut also_stalled = tcp_from(second, running.addr).await.unwrap();
    // Accepted in order: once the next client is in, the stalled one's
    // deadline is set.
    let stream = connect(running.addr, running.config(ClientCert::Own(&allowed)))
        .await
        .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    running.clock.advance(HANDSHAKE_TIMEOUT);
    for stream in [&mut stalled, &mut also_stalled] {
        assert!(drain(stream).await.is_empty(), "closed without a byte");
    }
    // Both counted in one rate-limited line.
    assert_eq!(
        logs.text()
            .matches("no handshake before the deadline")
            .count(),
        1,
        "{}",
        logs.text()
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_handshakes_from_one_address_do_not_block_another() {
    let (logs, _guard) = capture();
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("per-address", vec![allowed.pin]);
    let attacker = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut stalled = Vec::new();
    for _ in 0..MAX_HANDSHAKES_PER_ADDRESS {
        stalled.push(tcp_from(attacker, running.addr).await.unwrap());
    }
    for _ in 0..2 {
        let mut one_more = tcp_from(attacker, running.addr).await.unwrap();
        assert!(drain(&mut one_more).await.is_empty(), "closed at accept");
    }
    // Both refusals counted in one rate-limited line.
    assert_eq!(
        logs.text()
            .matches("reason=\"too many handshakes from this address\"")
            .count(),
        1,
        "{}",
        logs.text()
    );
    let client = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let stream = connect_from(
        client,
        running.addr,
        running.config(ClientCert::Own(&allowed)),
    )
    .await
    .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    assert_eq!(
        stalled.len(),
        usize::from(MAX_HANDSHAKES_PER_ADDRESS),
        "held until here"
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_full_pool_still_lets_a_known_client_reconnect() {
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("reserve", vec![allowed.pin]);
    let client = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let stream = connect_from(
        client,
        running.addr,
        running.config(ClientCert::Own(&allowed)),
    )
    .await
    .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    // Fill the pool from addresses that never authenticated.
    let mut stalled = Vec::new();
    for i in 0..MAX_PENDING_HANDSHAKES {
        let from = IpAddr::V4(Ipv4Addr::new(127, 0, 1, u8::try_from(i / 2 + 1).unwrap()));
        stalled.push(tcp_from(from, running.addr).await.unwrap());
    }
    let stranger = IpAddr::V4(Ipv4Addr::new(127, 0, 2, 1));
    let mut refused_at_accept = tcp_from(stranger, running.addr).await.unwrap();
    assert!(drain(&mut refused_at_accept).await.is_empty(), "pool full");
    let stream = connect_from(
        client,
        running.addr,
        running.config(ClientCert::Own(&allowed)),
    )
    .await
    .unwrap();
    assert_eq!(hello(stream).await["type"], "hello", "the reserve");
    assert_eq!(stalled.len(), MAX_PENDING_HANDSHAKES, "held until here");
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_closes_handshakes_in_progress() {
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("shutdown", vec![allowed.pin]);
    let mut stalled = TcpStream::connect(running.addr).await.unwrap();
    let stream = connect(running.addr, running.config(ClientCert::Own(&allowed)))
        .await
        .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    running.shutdown.cancel();
    assert!(drain(&mut stalled).await.is_empty());
    running.server.await.unwrap().unwrap();
    assert!(
        TcpStream::connect(running.addr).await.is_err(),
        "no longer listening"
    );
    std::fs::remove_dir_all(&running.dir).unwrap();
}

#[test]
fn a_listener_without_client_pins_does_not_start() {
    let (dir, data) = dirs("no-pins");
    let err = Server::bind(config(&dir, &data, vec![])).unwrap_err();
    assert!(matches!(err, BindError::NoClients), "{err}");
    assert!(err.to_string().contains("at least one client pin"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_data_directory_or_listen_address_that_does_not_work_stops_the_start() {
    let (dir, data) = dirs("bind-errors");
    let pin = ClientIdentity::generate().unwrap().pin;
    let mut missing = config(&dir, &data, vec![pin]);
    if let Some(tls) = missing.tls.as_mut() {
        tls.data_dir = dir.join("missing");
    }
    let err = Server::bind(missing).unwrap_err();
    assert!(matches!(err, BindError::Identity(_)), "{err}");
    assert!(err.to_string().starts_with("data directory"), "{err}");

    let taken = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut busy = config(&dir, &data, vec![pin]);
    if let Some(tls) = busy.tls.as_mut() {
        tls.listen = taken.local_addr().unwrap();
    }
    let err = Server::bind(busy).unwrap_err();
    assert!(matches!(err, BindError::TlsListen { .. }), "{err}");
    assert!(err.to_string().starts_with("control TLS listener"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_identity_whose_key_is_not_the_certificate_s_stops_the_start() {
    let (dir, data) = dirs("mismatch");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let certificate = rcgen::CertificateParams::new(vec![])
        .unwrap()
        .self_signed(&other)
        .unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(data.join(IDENTITY_FILE))
        .unwrap();
    io::Write::write_all(
        &mut file,
        format!("{}{}", key.serialize_pem(), certificate.pem()).as_bytes(),
    )
    .unwrap();
    let pin = ClientIdentity::generate().unwrap().pin;
    let err = Server::bind(config(&dir, &data, vec![pin])).unwrap_err();
    assert!(matches!(err, BindError::Tls(_)), "{err}");
    assert!(
        err.to_string().starts_with("control TLS configuration"),
        "{err}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
