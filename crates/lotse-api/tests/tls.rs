//! The mutual-TLS listener end to end over real TCP: who gets in, who is
//! refused before a byte of HTTP, the handshake deadline on the clock, the
//! pre-authentication budget per address, pairing with a one-time code,
//! and what is logged.

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

use futures_util::{SinkExt as _, StreamExt as _};
use lotse_api::identity::{IDENTITY_FILE, ServerIdentity};
use lotse_api::pairing::{CODE_LIFETIME, PAIR_TIMEOUT};
use lotse_api::tls::{
    HANDSHAKE_TIMEOUT, MAX_HANDSHAKES_PER_ADDRESS, MAX_PENDING_HANDSHAKES, TlsConfig,
};
use lotse_api::{
    BindError, Config, ConnectionId, Handler, MAX_PENDING_UPGRADES, Outcome, ServeError, Server,
    UPGRADE_TIMEOUT,
};
use lotse_api_types::command::Command;
use lotse_api_types::frame::{Hello, HelloTag};
use lotse_core::clock::FakeClock;
use lotse_core::fingerprint::Fingerprint;
use lotse_testing::control_tls::{
    ClientCert, ClientIdentity, client_config, connect, connect_from, tcp_from,
};
use rustls::HandshakeKind;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
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
    data: PathBuf,
    addr: SocketAddr,
    server_pin: Fingerprint,
    shutdown: CancellationToken,
    server: JoinHandle<Result<(), ServeError>>,
    clock: Arc<FakeClock>,
}

impl Running {
    async fn finish(self) {
        let (dir, _data) = self.stop().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Stops the server and keeps its directories for the next start.
    async fn stop(self) -> (PathBuf, PathBuf) {
        self.shutdown.cancel();
        self.server.await.unwrap().unwrap();
        (self.dir, self.data)
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

fn gid_of(path: &Path) -> u32 {
    std::fs::metadata(path).map(|m| m.gid()).unwrap()
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
            state_owner: (uid, gid_of(dir)),
        }),
    }
}

fn start(name: &str, clients: Vec<Fingerprint>) -> Running {
    let (dir, data) = dirs(name);
    start_in(dir, data, clients)
}

/// A server in directories an earlier one used.
fn start_in(dir: PathBuf, data: PathBuf, clients: Vec<Fingerprint>) -> Running {
    let server = Server::bind(config(&dir, &data, clients)).unwrap();
    let (state_dir, fd) = server.state_dir().unwrap();
    assert_eq!(state_dir, data.join("clients"));
    // A copy shares the store's lock (flock(2)): this one is closed at once.
    let opened = std::fs::File::from(fd.try_clone_to_owned().unwrap());
    let checked = std::fs::metadata(state_dir).unwrap().ino();
    assert_eq!(opened.metadata().unwrap().ino(), checked);
    drop(opened);
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
        data,
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
async fn drain<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
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
async fn an_authenticated_connection_takes_its_upgrade_slot_and_deadline_at_once() {
    let (logs, _guard) = capture();
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("upgrade-slot", vec![allowed.pin]);
    // Authenticated, then silent: each holds a slot from its handshake on.
    let mut parked = Vec::new();
    for i in 1..=MAX_PENDING_UPGRADES {
        let from = IpAddr::V4(Ipv4Addr::new(127, 0, 3, u8::try_from(i).unwrap()));
        let config = running.config(ClientCert::Own(&allowed));
        parked.push(connect_from(from, running.addr, config).await.unwrap());
    }
    let one_more = connect(running.addr, running.config(ClientCert::Own(&allowed))).await;
    assert!(refused(&exchange(one_more).await), "no slot left");
    assert!(
        logs.text()
            .contains("too many connections awaiting the upgrade"),
        "{}",
        logs.text()
    );
    // Accepted in order: once the last one is refused, every parked one's
    // deadline is set.
    running.clock.advance(UPGRADE_TIMEOUT);
    for stream in &mut parked {
        assert!(drain(stream).await.is_empty(), "closed without a response");
    }
    let stream = connect(running.addr, running.config(ClientCert::Own(&allowed)))
        .await
        .unwrap();
    assert_eq!(hello(stream).await["type"], "hello", "the slots came back");
    running.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_closes_handshakes_in_progress() {
    let allowed = ClientIdentity::generate().unwrap();
    let running = start("shutdown", vec![allowed.pin]);
    let stalled = TcpStream::connect(running.addr).await.unwrap();
    let stream = connect(running.addr, running.config(ClientCert::Own(&allowed)))
        .await
        .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    running.shutdown.cancel();
    running.server.await.unwrap().unwrap();
    // Closed by the time `serve` returns, not some time after: a read
    // that cannot wait finds EOF, not `WouldBlock`.
    let mut stalled = stalled.into_std().unwrap();
    stalled.set_nonblocking(true).unwrap();
    assert_eq!(io::Read::read(&mut stalled, &mut [0_u8; 1]).unwrap(), 0);
    assert!(
        TcpStream::connect(running.addr).await.is_err(),
        "no longer listening"
    );
    std::fs::remove_dir_all(&running.dir).unwrap();
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

    std::fs::remove_dir_all(data.join("clients")).unwrap();
    std::fs::write(data.join("clients"), b"").unwrap();
    let err = Server::bind(config(&dir, &data, vec![pin])).unwrap_err();
    assert!(matches!(err, BindError::Clients(_)), "{err}");
    assert!(err.to_string().starts_with("enrolled clients"), "{err}");
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

/// The code a daemon without clients logs once its server task runs,
/// failing after 5 s of real time.
#[expect(
    clippy::disallowed_methods,
    reason = "a real-time bound on a test step; the server's own timers run on the fake clock"
)]
async fn logged_code(logs: &Captured) -> String {
    let line = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let text = logs.text();
            if let Some(line) = text
                .lines()
                .find(|line| line.contains("pairing code for the first client"))
            {
                return line.to_owned();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no code logged: {}", logs.text()));
    let (_, after) = line.split_once(" code=").unwrap();
    after.split_whitespace().next().unwrap().to_owned()
}

/// The secret, the code's last part.
fn secret_of(code: &str) -> &str {
    code.rsplit('-').next().unwrap()
}

/// One HTTP request on a connection whose client half of the handshake
/// ran, and the answer's status and body: `(0, "")` when the server closed
/// without a byte, an error when the handshake was refused.
async fn request(
    connected: io::Result<TlsStream<TcpStream>>,
    method: &str,
    path: &str,
    body: &str,
) -> io::Result<(u16, String)> {
    let mut stream = connected?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: lotse\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    let mut answer = Vec::new();
    let read = within_5_s(stream.read_to_end(&mut answer)).await;
    if answer.is_empty() {
        read?;
    }
    let text = String::from_utf8_lossy(&answer).into_owned();
    let status = text
        .get(9..12)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// `client` connects and sends `secret` to `POST /v1/pair`.
async fn pair(
    running: &Running,
    client: &ClientIdentity,
    secret: &str,
) -> io::Result<(u16, String)> {
    let connected = connect(running.addr, running.config(ClientCert::Own(client))).await;
    let body = format!(r#"{{"secret":"{secret}"}}"#);
    request(connected, "POST", "/v1/pair", &body).await
}

/// Whether a pairing attempt was refused in the handshake or closed
/// without an answer.
fn refused_pairing(answer: &io::Result<(u16, String)>) -> bool {
    answer.as_ref().map_or(true, |(status, _)| *status == 0)
}

#[tokio::test(flavor = "current_thread")]
async fn without_a_client_the_first_code_is_logged_and_pairs_exactly_one() {
    let (logs, _guard) = capture();
    let running = start("pair-first", vec![]);
    let code = logged_code(&logs).await;
    let parts: Vec<&str> = code.split('-').collect();
    assert_eq!(parts[0], "LOTSE1");
    assert_eq!(
        parts[1],
        running.server_pin.to_hex(),
        "the code pins this daemon"
    );
    let client = ClientIdentity::generate().unwrap();
    let (status, _) = pair(&running, &client, parts[2]).await.unwrap();
    assert_eq!(status, 204);
    let pin = format!("client_pin={}", client.pin);
    assert!(
        logs.text()
            .lines()
            .any(|line| line.contains("control client enrolled by pairing") && line.contains(&pin)),
        "{}",
        logs.text()
    );
    // Enrolled: the certificate the handshake proved gets the API.
    let stream = connect(running.addr, running.config(ClientCert::Own(&client)))
        .await
        .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    // Used: another unknown certificate is refused in the handshake.
    let other = ClientIdentity::generate().unwrap();
    let answer = pair(&running, &other, parts[2]).await;
    assert!(refused_pairing(&answer), "{answer:?}");
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_code_used_after_the_handshake_is_410_rfc9110_15_5_11() {
    let (logs, _guard) = capture();
    let running = start("pair-gone", vec![]);
    let code = logged_code(&logs).await;
    // Both handshakes pass while the code is open.
    let late_client = ClientIdentity::generate().unwrap();
    let late = connect(running.addr, running.config(ClientCert::Own(&late_client))).await;
    let first = ClientIdentity::generate().unwrap();
    let (status, _) = pair(&running, &first, secret_of(&code)).await.unwrap();
    assert_eq!(status, 204);
    let body = format!(r#"{{"secret":"{}"}}"#, secret_of(&code));
    let (status, body) = request(late, "POST", "/v1/pair", &body).await.unwrap();
    assert_eq!(status, 410, "{body}");
    assert!(body.contains("not_permitted"), "{body}");
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_wrong_secret_is_403_and_leaves_the_code_open() {
    let (logs, _guard) = capture();
    let running = start("pair-wrong", vec![]);
    let code = logged_code(&logs).await;
    let client = ClientIdentity::generate().unwrap();
    let (status, body) = pair(&running, &client, &"0".repeat(32)).await.unwrap();
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("not_permitted"), "{body}");
    assert!(
        logs.text()
            .contains("pairing request refused: wrong secret")
    );
    let (status, _) = pair(&running, &client, secret_of(&code)).await.unwrap();
    assert_eq!(status, 204);
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_expired_code_lets_no_unknown_certificate_in_and_the_log_says_what_to_do() {
    let (logs, _guard) = capture();
    let running = start("pair-expired", vec![]);
    let code = logged_code(&logs).await;
    running.clock.advance(CODE_LIFETIME);
    let client = ClientIdentity::generate().unwrap();
    let answer = pair(&running, &client, secret_of(&code)).await;
    assert!(refused_pairing(&answer), "{answer:?}");
    assert!(
        logs.text()
            .contains("first pairing code expired; get a new one with `lotse pair`"),
        "{}",
        logs.text()
    );
    assert_eq!(
        logs.text().matches("LOTSE1-").count(),
        1,
        "the code is logged once, the hint carries none"
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn enrolling_before_the_first_code_expires_keeps_the_hint_out_of_the_log() {
    let (logs, _guard) = capture();
    let running = start("pair-quiet", vec![]);
    let code = logged_code(&logs).await;
    let client = ClientIdentity::generate().unwrap();
    let (status, _) = pair(&running, &client, secret_of(&code)).await.unwrap();
    assert_eq!(status, 204);
    running.clock.advance(CODE_LIFETIME);
    // A full exchange later, the expiry task has run.
    let stream = connect(running.addr, running.config(ClientCert::Own(&client)))
        .await
        .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    assert!(
        !logs.text().contains("first pairing code expired"),
        "{}",
        logs.text()
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_pairing_connection_reaches_nothing_but_the_pair_request() {
    let (logs, _guard) = capture();
    let running = start("pair-only", vec![]);
    let code = logged_code(&logs).await;
    let client = ClientIdentity::generate().unwrap();
    let mut answers = Vec::new();
    for (method, path, body) in [
        ("GET", lotse_api_types::WS_PATH, String::new()),
        ("GET", "/v1/pair", String::new()),
        ("POST", "/v1/other", String::new()),
        ("POST", "/v1/pair", "{}".to_owned()),
        (
            "POST",
            "/v1/pair",
            format!(r#"{{"secret":"{}"}}"#, "a".repeat(300)),
        ),
    ] {
        let connected = connect(running.addr, running.config(ClientCert::Own(&client))).await;
        let (status, _) = request(connected, method, path, &body).await.unwrap();
        answers.push(status);
    }
    assert_eq!(answers, [404, 405, 404, 400, 413]);
    assert!(
        !logs.text().contains("control connection opened"),
        "no WebSocket"
    );
    // None of it touched the code.
    let (status, _) = pair(&running, &client, secret_of(&code)).await.unwrap();
    assert_eq!(status, 204);
    running.finish().await;
}

/// `future`, or a panic after 5 s of real time: a server that waits where
/// it must not fails the test instead of hanging it.
#[expect(
    clippy::disallowed_methods,
    reason = "a real-time bound on a test step; the server's own timers run on the fake clock"
)]
async fn within_5_s<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(5), future)
        .await
        .expect("finished within 5 s")
}

/// Reads until the server closes or errors, failing after 5 s of real time.
#[expect(
    clippy::disallowed_methods,
    reason = "a real-time bound on a test step; the server's own timers run on the fake clock"
)]
async fn closed(stream: &mut TlsStream<TcpStream>) -> Vec<u8> {
    let mut rest = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut rest),
    )
    .await;
    assert!(read.is_ok(), "still open after 5 s");
    rest
}

#[tokio::test(flavor = "current_thread")]
async fn a_pairing_connection_that_sends_nothing_is_closed_at_its_deadline() {
    let (logs, _guard) = capture();
    let running = start("pair-deadline", vec![]);
    let code = logged_code(&logs).await;
    let idle_client = ClientIdentity::generate().unwrap();
    let mut idle = connect(running.addr, running.config(ClientCert::Own(&idle_client)))
        .await
        .unwrap();
    // Served in order: once the next one is enrolled, the idle one waits
    // on its deadline.
    let client = ClientIdentity::generate().unwrap();
    let (status, _) = pair(&running, &client, secret_of(&code)).await.unwrap();
    assert_eq!(status, 204);
    running.clock.advance(PAIR_TIMEOUT);
    assert!(closed(&mut idle).await.is_empty());
    assert!(
        logs.text()
            .contains("pairing connection closed: no request before the deadline"),
        "{}",
        logs.text()
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_enrolled_pin_survives_a_restart_and_no_code_is_logged_then() {
    let (logs, _guard) = capture();
    let running = start("pair-restart", vec![]);
    let code = logged_code(&logs).await;
    let client = ClientIdentity::generate().unwrap();
    let (status, _) = pair(&running, &client, secret_of(&code)).await.unwrap();
    assert_eq!(status, 204);
    let (dir, data) = running.stop().await;
    let pins = data.join("clients").join("pins");
    assert_eq!(std::fs::metadata(&pins).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::read_to_string(&pins).unwrap(),
        format!("{}\n", client.pin)
    );

    let running = start_in(dir, data, vec![]);
    let stream = connect(running.addr, running.config(ClientCert::Own(&client)))
        .await
        .unwrap();
    assert_eq!(hello(stream).await["type"], "hello");
    assert_eq!(
        logs.text()
            .matches("pairing code for the first client")
            .count(),
        1,
        "a client is enrolled: nothing secret at the second start"
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_pin_that_cannot_be_stored_is_500_and_the_code_stays_open() {
    let (logs, _guard) = capture();
    let running = start("pair-store", vec![]);
    let code = logged_code(&logs).await;
    let blocker = running.data.join("clients").join("pins.partial");
    std::fs::create_dir(&blocker).unwrap();
    let client = ClientIdentity::generate().unwrap();
    let (status, body) = pair(&running, &client, secret_of(&code)).await.unwrap();
    assert_eq!(status, 500, "{body}");
    assert!(logs.text().contains("enrolling the paired client failed"));
    std::fs::remove_dir(&blocker).unwrap();
    let (status, _) = pair(&running, &client, secret_of(&code)).await.unwrap();
    assert_eq!(status, 204);
    running.finish().await;
}

/// A WebSocket on `stream` after its `hello`.
async fn upgraded<S>(stream: S) -> tokio_tungstenite::WebSocketStream<S>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut ws, _) =
        tokio_tungstenite::client_async(&format!("ws://lotse{}", lotse_api_types::WS_PATH), stream)
            .await
            .expect("upgrades");
    assert!(
        matches!(ws.next().await, Some(Ok(Message::Text(_)))),
        "hello"
    );
    ws
}

/// Sends `pairing/create` as command `id` and returns the answer.
async fn pairing_create<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, id: u64) -> Value
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let command = serde_json::json!({ "id": id, "type": "pairing/create" });
    ws.send(Message::Text(command.to_string().into()))
        .await
        .unwrap();
    match within_5_s(ws.next()).await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(text.as_str()).unwrap(),
        other => panic!("no answer: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_create_issues_codes_on_the_socket_and_refuses_tls_clients() {
    let (logs, _guard) = capture();
    let fixed = ClientIdentity::generate().unwrap();
    let running = start("pair-create", vec![fixed.pin]);

    let socket = tokio::net::UnixStream::connect(running.dir.join("lotse.sock"))
        .await
        .unwrap();
    let mut local = upgraded(socket).await;
    let answer = pairing_create(&mut local, 1).await;
    assert_eq!(answer["success"], true, "{answer}");
    assert_eq!(answer["result"]["expires_in_ms"], 600_000);
    let code = answer["result"]["code"].as_str().unwrap().to_owned();
    assert!(
        code.starts_with(&format!("LOTSE1-{}-", running.server_pin.to_hex())),
        "{code}"
    );
    assert!(logs.text().contains("pairing code issued"));
    assert!(
        !logs.text().contains("pairing code for the first client"),
        "a fixed client exists: no code at startup"
    );
    assert!(!logs.text().contains(secret_of(&code)), "never logged");

    let client = ClientIdentity::generate().unwrap();
    let (status, _) = pair(&running, &client, secret_of(&code)).await.unwrap();
    assert_eq!(status, 204);

    let stream = connect(running.addr, running.config(ClientCert::Own(&fixed)))
        .await
        .unwrap();
    let mut remote = upgraded(stream).await;
    let answer = pairing_create(&mut remote, 1).await;
    assert_eq!(answer["success"], false, "{answer}");
    assert_eq!(answer["error"]["code"], "not_permitted");
    running.finish().await;
}

/// A server whose data directory already holds `enrolled`, as pairing
/// leaves it, with `fixed` from the configuration.
fn start_enrolled(name: &str, fixed: Vec<Fingerprint>, enrolled: &[Fingerprint]) -> Running {
    let (dir, data) = dirs(name);
    let clients = data.join("clients");
    private_dir(&clients);
    let mut pins = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(clients.join("pins"))
        .unwrap();
    for pin in enrolled {
        io::Write::write_all(&mut pins, format!("{pin}\n").as_bytes()).unwrap();
    }
    start_in(dir, data, fixed)
}

/// Sends `command` and returns the next frame, its answer.
async fn call<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, command: Value) -> Value
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    ws.send(Message::Text(command.to_string().into()))
        .await
        .unwrap();
    match within_5_s(ws.next()).await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(text.as_str()).unwrap(),
        other => panic!("no answer: {other:?}"),
    }
}

/// The close frame the server sends next: its code and reason.
async fn close_frame<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> (u16, String)
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match within_5_s(ws.next()).await {
        Some(Ok(Message::Close(Some(frame)))) => (frame.code.into(), frame.reason.to_string()),
        other => panic!("no close frame: {other:?}"),
    }
}

/// A WebSocket on the control socket, after its `hello`.
async fn local(running: &Running) -> tokio_tungstenite::WebSocketStream<tokio::net::UnixStream> {
    let socket = tokio::net::UnixStream::connect(running.dir.join("lotse.sock"))
        .await
        .unwrap();
    upgraded(socket).await
}

/// A WebSocket over TLS as `client`, after its `hello`.
async fn remote(
    running: &Running,
    client: &ClientIdentity,
) -> tokio_tungstenite::WebSocketStream<TlsStream<TcpStream>> {
    let stream = connect(running.addr, running.config(ClientCert::Own(client)))
        .await
        .unwrap();
    upgraded(stream).await
}

/// `clients/remove` of `pin` as command `id`.
fn remove(id: u64, pin: Fingerprint) -> Value {
    serde_json::json!({ "id": id, "type": "clients/remove", "pin": pin.to_string() })
}

#[tokio::test(flavor = "current_thread")]
async fn removing_a_client_closes_its_connection_and_refuses_it_from_then_on() {
    let (logs, _guard) = capture();
    let fixed = ClientIdentity::generate().unwrap();
    let enrolled = ClientIdentity::generate().unwrap();
    let running = start_enrolled("remove", vec![fixed.pin], &[enrolled.pin]);
    let mut admin = local(&running).await;
    let mut gone = remote(&running, &enrolled).await;
    let mut other = remote(&running, &fixed).await;

    let mut expected = vec![
        serde_json::json!({ "pin": fixed.pin.to_string(), "fixed": true, "connected": true }),
        serde_json::json!({ "pin": enrolled.pin.to_string(), "fixed": false, "connected": true }),
    ];
    expected.sort_by_key(|client| client["pin"].as_str().unwrap().to_owned());
    let listed = call(
        &mut admin,
        serde_json::json!({ "id": 1, "type": "clients/list" }),
    )
    .await;
    assert_eq!(
        listed["result"]["clients"],
        Value::Array(expected.clone()),
        "{listed}"
    );
    let listed = call(
        &mut other,
        serde_json::json!({ "id": 1, "type": "clients/list" }),
    )
    .await;
    assert_eq!(
        listed["result"]["clients"],
        Value::Array(expected),
        "over TLS too"
    );

    // Over TLS a client removes only itself, and no one removes a fixed pin.
    for (id, pin) in [(2, enrolled.pin), (3, fixed.pin)] {
        let answer = call(&mut other, remove(id, pin)).await;
        assert_eq!(answer["error"]["code"], "not_permitted", "{answer}");
    }
    let answer = call(&mut admin, remove(2, fixed.pin)).await;
    assert_eq!(answer["error"]["code"], "not_permitted", "{answer}");

    let answer = call(&mut admin, remove(3, enrolled.pin)).await;
    assert_eq!(answer["success"], true, "{answer}");
    assert_eq!(answer["result"], serde_json::json!({}));
    // RFC 6455 §7.4.1: 1008, policy violation.
    assert_eq!(
        close_frame(&mut gone).await,
        (1008, "client removed".to_owned())
    );
    let answer =
        exchange(connect(running.addr, running.config(ClientCert::Own(&enrolled))).await).await;
    assert!(refused(&answer), "{answer:?}");
    let removed = logs.text();
    let line = removed
        .lines()
        .find(|line| line.contains("control client removed"))
        .unwrap();
    assert!(
        line.contains(&enrolled.pin.to_string()) && line.contains("closed=1"),
        "{line}"
    );
    assert!(line.contains("by=uid"), "{line}");
    // Idempotent: a pin that is not enrolled is already removed.
    let answer = call(&mut admin, remove(4, enrolled.pin)).await;
    assert_eq!(answer["success"], true, "{answer}");
    // The fixed client kept its connection.
    let listed = call(
        &mut other,
        serde_json::json!({ "id": 4, "type": "clients/list" }),
    )
    .await;
    assert_eq!(
        listed["result"]["clients"].as_array().unwrap().len(),
        1,
        "{listed}"
    );
    // Once its connection is gone, the fixed client is listed as not
    // connected.
    drop(other);
    let mut id = 5;
    within_5_s(async {
        loop {
            let list = serde_json::json!({ "id": id, "type": "clients/list" });
            let listed = call(&mut admin, list).await;
            if listed["result"]["clients"][0]["connected"] == false {
                break;
            }
            id += 1;
            tokio::task::yield_now().await;
        }
    })
    .await;
    drop(admin);

    let (dir, data) = running.stop().await;
    assert_eq!(
        std::fs::read_to_string(data.join("clients").join("pins")).unwrap(),
        ""
    );
    let running = start_in(dir, data, vec![fixed.pin]);
    let answer =
        exchange(connect(running.addr, running.config(ClientCert::Own(&enrolled))).await).await;
    assert!(
        refused(&answer),
        "still refused after a restart: {answer:?}"
    );
    running.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_client_that_removes_itself_gets_its_result_before_the_close() {
    let (logs, _guard) = capture();
    let client = ClientIdentity::generate().unwrap();
    let running = start_enrolled("remove-self", vec![], &[client.pin]);
    let mut ws = remote(&running, &client).await;
    let answer = call(&mut ws, remove(1, client.pin)).await;
    assert_eq!(answer["success"], true, "{answer}");
    assert_eq!(
        close_frame(&mut ws).await,
        (1008, "client removed".to_owned())
    );
    let text = logs.text();
    let line = text
        .lines()
        .find(|line| line.contains("control client removed"))
        .unwrap();
    assert!(
        line.contains(&format!("by=client {}", client.pin)),
        "{line}"
    );
    assert!(
        text.contains("control connection closing: its client was removed"),
        "{text}"
    );
    running.finish().await;
}
