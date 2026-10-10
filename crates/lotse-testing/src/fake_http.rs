//! A scripted HTTP/1.1 server for the HTTP source's tests: it serves byte
//! bodies by request target from a script the test edits while it runs,
//! keeps live HLS media playlists whose window the test slides (RFC 8216
//! §4.3.3.2 `EXT-X-MEDIA-SEQUENCE`, §6.2.2 the sliding window), and
//! injects faults: any status, redirects (RFC 9110 §15.4) to any
//! `Location`, an answer that never comes, a body that stalls, a hang-up
//! mid-body, a closed persistent connection (RFC 9112 §9.6
//! `Connection: close`) and a body without end that the test feeds.
//!
//! With credentials set, every request must carry them: a request without
//! them, or with wrong ones, gets a 401 with a Basic (RFC 7617 §2) or a
//! Digest (RFC 7616 §3.3, `qop=auth`, MD5 or SHA-256) challenge, and the
//! server checks the answer itself (RFC 7616 §3.4.1) instead of trusting
//! the client's library.
//!
//! Runs on axum, whose hyper server is the third-party HTTP/1.1 peer; it
//! records every request it saw and counts connections, so tests can
//! assert on persistence, `Host`, `User-Agent` and `Authorization`. In TLS
//! mode ([`FakeHttp::start_tls`]) it serves the same script as `https`
//! (RFC 9110 §4.2.2) with a [`CameraTls`] certificate, through rustls.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, USER_AGENT,
    WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::serve::{Listener, ListenerExt as _};
use bytes::Bytes;
use futures_util::StreamExt as _;
use futures_util::stream;
use lotse_core::task::spawn_named;
use md5::Md5;
use sha2::{Digest as _, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::base64;
use crate::fake_camera::CameraTls;

/// The realm of the server's challenges.
pub const REALM: &str = "fake http";

/// What the server answers a request target with.
#[derive(Debug, Clone)]
pub enum Reply {
    /// 200 with the body and its `Content-Type`.
    Body {
        /// The `Content-Type`.
        content_type: String,
        /// The body.
        body: Bytes,
    },
    /// The status with an empty body.
    Status(u16),
    /// The redirect status with `Location: location`, written as given.
    Redirect {
        /// 301, 302, 303, 307 or 308, or anything else.
        status: u16,
        /// The `Location`.
        location: String,
    },
    /// 200 with `Connection: close`: the server closes the connection
    /// after the body (RFC 9112 §9.6).
    Close(Bytes),
    /// No answer at all until the server stops.
    Hang,
    /// 200, the first bytes, then nothing until the server stops.
    Stall(Bytes),
    /// 200 declaring `declared` bytes (`Content-Length`), then `sent` and
    /// a hang-up.
    HangUp {
        /// The declared length.
        declared: usize,
        /// What is sent of it.
        sent: Bytes,
    },
    /// 200, chunked, the bytes the test sends on [`FakeHttp::stream`]'s
    /// sender, until the sender is dropped.
    Stream(Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>),
}

impl Reply {
    /// 200 with `body` as `content_type`.
    pub fn body(content_type: &str, body: impl Into<Bytes>) -> Self {
        Self::Body {
            content_type: content_type.to_owned(),
            body: body.into(),
        }
    }
}

/// The challenge a server with credentials sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    /// `Basic` (RFC 7617 §2).
    Basic,
    /// `Digest` with MD5 (RFC 7616 §3.3).
    DigestMd5,
    /// `Digest` with SHA-256 (RFC 7616 §3.3).
    DigestSha256,
}

/// One request as the server saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The request target, path and query.
    pub target: String,
    /// The `Host` field.
    pub host: Option<String>,
    /// The `User-Agent` field.
    pub user_agent: Option<String>,
    /// The `Authorization` field.
    pub authorization: Option<String>,
}

/// A live media playlist the test slides.
#[derive(Debug, Default)]
struct Live {
    /// How many segments the window keeps.
    window: usize,
    /// The media sequence number of the first segment in the window.
    media_sequence: u64,
    /// The window's segments: URI and duration.
    segments: Vec<(String, f64)>,
    /// Whether `EXT-X-ENDLIST` is out.
    ended: bool,
}

impl Live {
    /// The playlist text (RFC 8216 §4.3.3).
    fn render(&self) -> String {
        let target = self
            .segments
            .iter()
            .map(|(_, duration)| duration.ceil())
            .fold(1.0_f64, f64::max);
        let mut text = format!(
            "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:{target}\n#EXT-X-MEDIA-SEQUENCE:{}\n",
            self.media_sequence
        );
        for (uri, duration) in &self.segments {
            let _infallible = write!(text, "#EXTINF:{duration:.3},\n{uri}\n");
        }
        if self.ended {
            text.push_str("#EXT-X-ENDLIST\n");
        }
        text
    }
}

/// The script and what the server saw, shared with its handler.
#[derive(Debug, Default)]
struct Script {
    /// The answers by request target.
    replies: HashMap<String, Reply>,
    /// The live playlists by request target.
    live: HashMap<String, Live>,
    /// The credentials every request must carry, with the challenge.
    auth: Option<(Challenge, String, String)>,
    /// Every request so far.
    seen: Vec<Seen>,
    /// The last Digest nonce handed out.
    nonce: u64,
}

/// The handler's state.
#[derive(Debug)]
struct Shared {
    /// The script.
    script: Mutex<Script>,
    /// Ends hanging answers and stalled bodies.
    cancel: CancellationToken,
}

impl Shared {
    /// The script, poison or not.
    fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.script.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The listener of the TLS mode: each accepted connection's handshake
/// completes before it is served; a failed one is dropped and logged.
struct TlsListener {
    /// The TCP side.
    tcp: TcpListener,
    /// The handshakes.
    acceptor: TlsAcceptor,
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = Listener::accept(&mut self.tcp).await;
            match self.acceptor.accept(stream).await {
                Ok(tls) => return (tls, addr),
                Err(err) => tracing::debug!(error = %err, "fake http: TLS handshake failed"),
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// A running fake HTTP server.
pub struct FakeHttp {
    /// `http` or, in TLS mode, `https`.
    scheme: &'static str,
    /// Where it listens.
    addr: SocketAddr,
    /// The script and the record.
    shared: Arc<Shared>,
    /// Connections accepted so far.
    connections: Arc<AtomicU64>,
    /// The server task.
    serve: JoinHandle<()>,
}

impl fmt::Debug for FakeHttp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeHttp")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl FakeHttp {
    /// Binds a port on 127.0.0.1 and serves an empty script (every target
    /// 404) until stopped.
    pub async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        Ok(Self::serve("http", listener))
    }

    /// As [`FakeHttp::start`], over TLS with `tls`'s certificate: `https`.
    pub async fn start_tls(tls: &CameraTls) -> io::Result<Self> {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let acceptor = TlsAcceptor::from(Arc::clone(&tls.config));
        Ok(Self::serve("https", TlsListener { tcp, acceptor }))
    }

    /// Serves the script on `listener`.
    fn serve<L: Listener<Addr = SocketAddr>>(scheme: &'static str, listener: L) -> Self {
        let addr = listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let shared = Arc::new(Shared {
            script: Mutex::default(),
            cancel: CancellationToken::new(),
        });
        let connections = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&connections);
        let listener = listener.tap_io(move |_stream| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(Arc::clone(&shared));
        let cancel = shared.cancel.clone();
        let serve = spawn_named("fake_http.serve", async move {
            if let Err(err) = axum::serve(listener, app)
                .with_graceful_shutdown(cancel.cancelled_owned())
                .await
            {
                tracing::warn!(error = %err, "fake http: serving failed");
            }
        });
        Self {
            scheme,
            addr,
            shared,
            connections,
            serve,
        }
    }

    /// The address.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port><target>`, `https://` in TLS mode.
    pub fn url(&self, target: &str) -> String {
        format!("{}://{}{target}", self.scheme, self.addr)
    }

    /// Answers `target` (path and query) with `reply` from now on.
    pub fn set(&self, target: &str, reply: Reply) {
        self.shared
            .script()
            .replies
            .insert(target.to_owned(), reply);
    }

    /// Requires `user` and `pass` on every request from now on, challenging
    /// with `challenge`; `None` lifts the requirement.
    pub fn require(&self, auth: Option<(Challenge, &str, &str)>) {
        self.shared.script().auth =
            auth.map(|(challenge, user, pass)| (challenge, user.to_owned(), pass.to_owned()));
    }

    /// Serves `target` as a chunked body without end, fed through the
    /// returned sender until it is dropped.
    pub fn stream(&self, target: &str) -> mpsc::Sender<Bytes> {
        let (tx, rx) = mpsc::channel(16);
        self.set(target, Reply::Stream(Arc::new(tokio::sync::Mutex::new(rx))));
        tx
    }

    /// Serves `playlist` as a live media playlist keeping the last
    /// `window` segments; empty until [`FakeHttp::push_segment`].
    pub fn live(&self, playlist: &str, window: usize) {
        self.shared.script().live.insert(
            playlist.to_owned(),
            Live {
                window: window.max(1),
                ..Live::default()
            },
        );
    }

    /// Appends the segment `uri` (an absolute path, written into the
    /// playlist as is) of `duration` seconds to the live `playlist`, served
    /// as `video/mp2t` with `body`, and slides the window: the oldest
    /// segment leaves and the media sequence number counts it.
    pub fn push_segment(&self, playlist: &str, uri: &str, duration: f64, body: impl Into<Bytes>) {
        let mut script = self.shared.script();
        script
            .replies
            .insert(uri.to_owned(), Reply::body("video/mp2t", body));
        let live = script.live.entry(playlist.to_owned()).or_default();
        live.segments.push((uri.to_owned(), duration));
        while live.segments.len() > live.window.max(1) {
            live.segments.remove(0);
            live.media_sequence = live.media_sequence.saturating_add(1);
        }
        drop(script);
    }

    /// Ends the live `playlist` with `EXT-X-ENDLIST`.
    pub fn end_playlist(&self, playlist: &str) {
        if let Some(live) = self.shared.script().live.get_mut(playlist) {
            live.ended = true;
        }
    }

    /// Every request so far, in order.
    pub fn requests(&self) -> Vec<Seen> {
        self.shared.script().seen.clone()
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Stops the server: hanging answers and stalled bodies end.
    pub async fn stop(self) {
        self.shared.cancel.cancel();
        let _joined = self.serve.await;
    }
}

/// Answers one request from the script.
async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let target = request.uri().path_and_query().map_or_else(
        || request.uri().path().to_owned(),
        |pq| pq.as_str().to_owned(),
    );
    let headers = request.headers();
    let field = |name| {
        headers
            .get(name)
            .and_then(|value: &axum::http::HeaderValue| value.to_str().ok())
            .map(str::to_owned)
    };
    let seen = Seen {
        target: target.clone(),
        host: field(HOST),
        user_agent: field(USER_AGENT),
        authorization: field(AUTHORIZATION),
    };
    let reply = {
        let mut script = shared.script();
        script.seen.push(seen);
        if let Some(challenge) = unauthorized(&mut script, &target, headers) {
            return challenge;
        }
        match script.live.get(&target) {
            Some(live) => Some(Reply::body("application/vnd.apple.mpegurl", live.render())),
            None => script.replies.get(&target).cloned(),
        }
    };
    let Some(reply) = reply else {
        return status(StatusCode::NOT_FOUND);
    };
    answer(reply, &shared.cancel).await
}

/// The answer to `reply`.
async fn answer(reply: Reply, cancel: &CancellationToken) -> Response {
    let builder = Response::builder().status(StatusCode::OK);
    let response = match reply {
        Reply::Body { content_type, body } => builder
            .header(CONTENT_TYPE, content_type)
            .body(Body::from(body)),
        Reply::Status(code) => {
            return status(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
        }
        Reply::Redirect { status, location } => builder
            .status(status)
            .header(LOCATION, location)
            .body(Body::empty()),
        Reply::Close(body) => builder.header(CONNECTION, "close").body(Body::from(body)),
        Reply::Hang => {
            cancel.cancelled().await;
            return status(StatusCode::SERVICE_UNAVAILABLE);
        }
        Reply::Stall(first) => {
            let cancel = cancel.clone();
            let rest = stream::once(async move {
                cancel.cancelled_owned().await;
                Err(io::Error::other("fake http: stopped while stalling"))
            });
            builder.body(Body::from_stream(
                stream::once(async move { Ok(first) }).chain(rest),
            ))
        }
        Reply::HangUp { declared, sent } => {
            builder
                .header(CONTENT_LENGTH, declared)
                // The pending turn lets hyper flush the head and `sent`
                // before the error aborts the connection.
                .body(Body::from_stream(
                    stream::once(async move { Ok(sent) }).chain(stream::once(async {
                        tokio::task::yield_now().await;
                        Err(io::Error::other("fake http: hanging up mid-body"))
                    })),
                ))
        }
        Reply::Stream(rx) => {
            let cancel = cancel.clone();
            let chunks = stream::unfold((rx, cancel), |(rx, cancel)| async move {
                let next = tokio::select! {
                    next = async { rx.lock().await.recv().await } => next,
                    () = cancel.cancelled() => None,
                };
                next.map(|chunk| (Ok::<_, io::Error>(chunk), (rx, cancel)))
            });
            builder
                .header(CONTENT_TYPE, "video/mp2t")
                .body(Body::from_stream(chunks))
        }
    };
    response.unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR))
}

/// An empty answer with `code`.
fn status(code: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = code;
    response
}

/// The 401 for a request without the required credentials, or `None`
/// when it carries them (or none are required).
fn unauthorized(script: &mut Script, target: &str, headers: &HeaderMap) -> Option<Response> {
    let (challenge, user, pass) = script.auth.clone()?;
    let given = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let accepted = match challenge {
        Challenge::Basic => {
            given
                == format!(
                    "Basic {}",
                    base64::encode(format!("{user}:{pass}").as_bytes())
                )
        }
        Challenge::DigestMd5 | Challenge::DigestSha256 => {
            digest_accepts(challenge, given, target, &user, &pass)
        }
    };
    if accepted {
        return None;
    }
    script.nonce = script.nonce.saturating_add(1);
    let value = match challenge {
        Challenge::Basic => format!("Basic realm=\"{REALM}\""),
        Challenge::DigestMd5 => format!(
            "Digest realm=\"{REALM}\", qop=\"auth\", algorithm=MD5, nonce=\"n{}\"",
            script.nonce
        ),
        Challenge::DigestSha256 => format!(
            "Digest realm=\"{REALM}\", qop=\"auth\", algorithm=SHA-256, nonce=\"n{}\"",
            script.nonce
        ),
    };
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(WWW_AUTHENTICATE, value)
        .body(Body::empty())
        .ok()
}

/// Whether `given` is a Digest answer (RFC 7616 §3.4) with `qop=auth` for
/// a GET of `target` by `user` with `pass`, to a nonce of this server.
fn digest_accepts(challenge: Challenge, given: &str, target: &str, user: &str, pass: &str) -> bool {
    let Some(params) = given.strip_prefix("Digest ") else {
        return false;
    };
    let params = digest_params(params);
    let param = |name: &str| params.get(name).map(String::as_str).unwrap_or_default();
    let hash = |input: String| match challenge {
        Challenge::DigestSha256 => hex(&Sha256::digest(input.as_bytes())),
        Challenge::Basic | Challenge::DigestMd5 => hex(&Md5::digest(input.as_bytes())),
    };
    let ha1 = hash(format!("{user}:{REALM}:{pass}"));
    let ha2 = hash(format!("GET:{target}"));
    let expected = hash(format!(
        "{ha1}:{}:{}:{}:auth:{ha2}",
        param("nonce"),
        param("nc"),
        param("cnonce")
    ));
    param("username") == user
        && param("realm") == REALM
        && param("uri") == target
        && param("qop") == "auth"
        && param("nonce").starts_with('n')
        && param("response") == expected
}

/// The `name=value` and `name="value"` parameters of an `Authorization`
/// field (RFC 9110 §11.4), quoted pairs unescaped.
fn digest_params(input: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let mut rest = input.trim_start();
    while let Some((name, after)) = rest.split_once('=') {
        let name = name.trim().to_ascii_lowercase();
        let mut value = String::new();
        let after = after.trim_start();
        if let Some(quoted) = after.strip_prefix('"') {
            let mut chars = quoted.char_indices();
            let mut end = quoted.len();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, escaped)) = chars.next() {
                            value.push(escaped);
                        }
                    }
                    '"' => {
                        end = i.saturating_add(1);
                        break;
                    }
                    other => value.push(other),
                }
            }
            rest = quoted.get(end..).unwrap_or_default();
        } else {
            let end = after.find(',').unwrap_or(after.len());
            value.push_str(after.get(..end).unwrap_or_default().trim());
            rest = after.get(end..).unwrap_or_default();
        }
        params.insert(name, value);
        rest = rest.trim_start().trim_start_matches(',').trim_start();
    }
    params
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _infallible = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn digest_params_reads_quoted_and_token_values_rfc9110_11_4() {
        let params = digest_params(
            r#"username="a\"b", realm="fake http", nc=00000001, qop=auth, uri="/x?y=1""#,
        );
        assert_eq!(params["username"], "a\"b");
        assert_eq!(params["realm"], "fake http");
        assert_eq!(params["nc"], "00000001");
        assert_eq!(params["qop"], "auth");
        assert_eq!(params["uri"], "/x?y=1");
    }

    #[test]
    fn digest_accepts_the_rfc7616_3_9_1_example_shape() {
        // A response computed independently, as RFC 7616 §3.4.1 defines it.
        let ha1 = hex(&Md5::digest(format!("u:{REALM}:p").as_bytes()));
        let ha2 = hex(&Md5::digest(b"GET:/a"));
        let response = hex(&Md5::digest(
            format!("{ha1}:n1:00000001:c:auth:{ha2}").as_bytes(),
        ));
        let given = format!(
            "Digest username=\"u\", realm=\"{REALM}\", uri=\"/a\", qop=auth, nonce=\"n1\", nc=00000001, cnonce=\"c\", response=\"{response}\""
        );
        assert!(digest_accepts(Challenge::DigestMd5, &given, "/a", "u", "p"));
        assert!(!digest_accepts(
            Challenge::DigestMd5,
            &given,
            "/a",
            "u",
            "q"
        ));
        assert!(!digest_accepts(
            Challenge::DigestMd5,
            &given,
            "/b",
            "u",
            "p"
        ));
        assert!(!digest_accepts(
            Challenge::DigestSha256,
            &given,
            "/a",
            "u",
            "p"
        ));
    }

    #[test]
    fn a_live_playlist_renders_its_window_rfc8216_4_3_3() {
        let mut live = Live {
            window: 2,
            ..Live::default()
        };
        live.segments.push(("/s0.ts".to_owned(), 2.0));
        assert!(
            live.render()
                .contains("#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:2.000,\n/s0.ts\n")
        );
        live.ended = true;
        assert!(live.render().ends_with("#EXT-X-ENDLIST\n"));
    }
}
