//! The HTTP/1.1 client of the HTTP source: GET requests for playlists,
//! segments and raw MPEG-TS on one origin, over hyper's low-level
//! connection (`hyper::client::conn::http1`), with no DNS, pool or
//! redirect policy of hyper's own.
//!
//! One [`Client`] serves one source URL and keeps one persistent
//! connection to its origin (RFC 9112 §9.3), connecting to the addresses
//! the supervisor resolved ([`ResolvedPeer`]) in order. A kept-alive
//! connection the server closed in the meantime is replaced and the GET
//! sent again once (RFC 9112 §9.3.1: GET is idempotent). Requests carry
//! the origin-form target (RFC 9112 §3.2.1), `Host` (RFC 9112 §3.2, RFC
//! 9110 §7.2) and the daemon's `User-Agent` (RFC 9110 §10.1.5).
//!
//! Policy, as the source's error codes see it:
//!
//! - 2xx is the answer; its body is read whole under a cap
//!   ([`Body::bytes`]) or chunk by chunk ([`Body::chunk`]).
//! - 301, 302, 303, 307 and 308 (RFC 9110 §15.4) are followed at most
//!   [`MAX_REDIRECTS`] times, and only within the source's origin (RFC
//!   6454 §4): the HTTP source has no DNS of its own, so another origin is
//!   refused as `source_protocol_error` naming that origin only, never its
//!   path, query or userinfo.
//! - 401 (RFC 9110 §15.5.2) is answered once per request with the URL's
//!   credentials, Basic (RFC 7617) or Digest (RFC 7616) as the
//!   `WWW-Authenticate` challenge (RFC 9110 §11.6.1) asks; credentials are
//!   never sent before the origin challenged, and afterwards go with every
//!   request. A second 401, or a 403 (RFC 9110 §15.5.4), is
//!   `source_auth_failed`.
//! - 5xx (RFC 9110 §15.6) and every connect failure are
//!   `source_unreachable`; any other status is `source_protocol_error`
//!   naming it.
//! - No answer, or no body bytes, within the timeout is `source_timeout`.
//!
//! Credentials never reach a log line or an error message, and neither do
//! a URL's path and query, which can carry tokens.
//!
//! The byte stream under HTTP comes from a [`Connect`]: [`Plain`] TCP
//! here; a TLS connector wraps the same TCP connect for `https`.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_auth::{PasswordClient, PasswordClientBuilder, PasswordParams};
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1::{self, SendRequest};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, LOCATION, USER_AGENT, WWW_AUTHENTICATE};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use lotse_core::clock::Clock;
use lotse_core::secret::RedactedUrl;
use lotse_core::source::{ResolvedPeer, SourceError};
use lotse_core::source_url::{Credentials, SourceUrl};
use lotse_core::task::{BoxFuture, spawn_named};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use url::{Origin, Url};

/// Why a challenge the origin sent cannot be answered with the URL's
/// credentials. http-auth's own error quotes the value it could not write,
/// so it is not passed on; in practice it fails only when one Digest nonce
/// was used 2^32 times (RFC 7616 §3.4 `nc`).
const UNANSWERABLE: &str = "the url's credentials cannot answer the server's challenge";

/// The `User-Agent` of every request (RFC 9110 §10.1.5), as the RTSP
/// source announces itself.
pub const DAEMON_USER_AGENT: &str = concat!("lotse/", env!("CARGO_PKG_VERSION"));

/// How many redirects one request follows (RFC 9110 §15.4 leaves the
/// limit to the client): a CDN's one hop to a signed URL and one more,
/// never a loop.
pub const MAX_REDIRECTS: usize = 2;

/// Opens the byte stream HTTP/1.1 runs on: a TCP connection, or TLS over
/// one for `https`.
pub trait Connect: fmt::Debug + Send + Sync {
    /// The stream hyper reads and writes.
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Connects to `addr` for the URL's `host` (the TLS server name). The
    /// client bounds it with its timeout; a failure is typed
    /// (`Unreachable`, or `Protocol` for a certificate the source refuses).
    fn connect(
        &self,
        addr: SocketAddr,
        host: &str,
    ) -> BoxFuture<'static, Result<Self::Io, SourceError>>;
}

/// Plain TCP, for `http`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Plain;

impl Connect for Plain {
    type Io = TcpStream;

    fn connect(
        &self,
        addr: SocketAddr,
        _host: &str,
    ) -> BoxFuture<'static, Result<TcpStream, SourceError>> {
        Box::pin(async move {
            TcpStream::connect(addr).await.map_err(|err| {
                SourceError::Unreachable(format!("unable to connect to {addr}: {err}"))
            })
        })
    }
}

/// The HTTP/1.1 client of one source: its origin, addresses, credentials
/// and persistent connection. One request at a time: a response's body is
/// read to its end, or dropped, before the next GET.
#[derive(Debug)]
pub struct Client<C: Connect> {
    /// Opens the connections.
    connector: C,
    /// The source URL's origin (RFC 6454 §4); no request leaves it.
    origin: Origin,
    /// The host for the TLS server name and the addresses to connect to.
    peer: ResolvedPeer,
    /// The URL's userinfo, sent only once the origin challenged.
    credentials: Option<Credentials>,
    /// Deadlines.
    clock: Arc<dyn Clock>,
    /// The connect, answer and body-stall deadline.
    timeout: Duration,
    /// Ends every connection's task.
    cancel: CancellationToken,
    /// The kept-alive connection, when one is open.
    sender: Option<SendRequest<Empty<Bytes>>>,
    /// The origin's last challenge, answered on every request since.
    challenge: Option<PasswordClient>,
}

impl<C: Connect> Client<C> {
    /// A client for `url`'s origin, connecting through `connector` to
    /// `peer`, with `timeout` for each connect, each answer and each wait
    /// for body bytes. Connections end when `cancel` is cancelled. No I/O
    /// until the first [`Client::get`].
    pub fn new(
        connector: C,
        url: &SourceUrl,
        peer: ResolvedPeer,
        clock: Arc<dyn Clock>,
        timeout: Duration,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            connector,
            origin: url.expose_url().origin(),
            peer,
            credentials: url.credentials().cloned(),
            clock,
            timeout,
            cancel,
            sender: None,
            challenge: None,
        }
    }

    /// GETs `url`, which must be on the source's origin, following
    /// redirects and answering a challenge as the module says. Returns the
    /// 2xx answer with its body unread.
    pub async fn get(&mut self, url: &Url) -> Result<Response, SourceError> {
        self.check_origin(url)?;
        let mut target = url.clone();
        let mut redirects = 0_usize;
        let mut challenged = false;
        loop {
            let answer = self.send(&target).await?;
            let status = answer.status();
            if status.is_success() {
                return Ok(Response {
                    status,
                    content_type: answer
                        .headers()
                        .get(CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                    url: target,
                    body: Body {
                        incoming: answer.into_body(),
                        clock: Arc::clone(&self.clock),
                        timeout: self.timeout,
                    },
                });
            }
            if status == StatusCode::UNAUTHORIZED && !challenged {
                self.accept_challenge(&answer)?;
                challenged = true;
            } else if is_redirect(status) {
                redirects = redirects.saturating_add(1);
                if redirects > MAX_REDIRECTS {
                    return Err(SourceError::Protocol(format!(
                        "more than {MAX_REDIRECTS} redirects"
                    )));
                }
                target = self.redirect(&target, &answer)?;
            } else {
                return Err(status_error(status));
            }
        }
    }

    /// Refuses `url` unless it is on the source's origin, naming only the
    /// other origin (RFC 6454 §6.2), never a path, query or userinfo.
    fn check_origin(&self, url: &Url) -> Result<(), SourceError> {
        let origin = url.origin();
        if origin == self.origin {
            Ok(())
        } else {
            Err(SourceError::Protocol(format!(
                "{} is another origin than the source's; only the source's origin is fetched",
                origin.ascii_serialization()
            )))
        }
    }

    /// The URL a redirect answer points to (RFC 9110 §10.2.2: `Location`,
    /// relative to the request's URL), on the source's origin and without
    /// userinfo.
    fn redirect(&self, from: &Url, answer: &hyper::Response<Incoming>) -> Result<Url, SourceError> {
        let status = answer.status();
        let location = answer
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| SourceError::Protocol(format!("{status} without a usable Location")))?;
        let mut next = from.join(location).map_err(|err| {
            SourceError::Protocol(format!("the Location of a {status} does not parse: {err}"))
        })?;
        self.check_origin(&next)?;
        // Neither can fail: the URL is on an `http` or `https` origin, so it
        // has a host.
        let _no_username = next.set_username("");
        let _no_password = next.set_password(None);
        tracing::debug!(status = status.as_u16(), "http: following a redirect");
        Ok(next)
    }

    /// Takes the origin's challenge from a 401's `WWW-Authenticate` fields
    /// (RFC 9110 §11.6.1), preferring Digest over Basic as http-auth does.
    fn accept_challenge(&mut self, answer: &hyper::Response<Incoming>) -> Result<(), SourceError> {
        if self.credentials.is_none() {
            return Err(SourceError::AuthFailed(
                "the server asks for credentials and the url has none".to_owned(),
            ));
        }
        let challenge = answer
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .fold(PasswordClient::builder(), PasswordClientBuilder::challenges)
            .build()
            .map_err(|err| {
                SourceError::AuthFailed(format!("the server's challenge cannot be answered: {err}"))
            })?;
        tracing::debug!("http: answering the server's challenge with the url's credentials");
        self.challenge = Some(challenge);
        Ok(())
    }

    /// The `Authorization` field for a GET of `uri` (the origin-form
    /// target), once the origin challenged: RFC 7617 §2 or RFC 7616 §3.4.
    fn authorization(&mut self, uri: &str) -> Result<Option<String>, SourceError> {
        let (Some(challenge), Some(credentials)) =
            (self.challenge.as_mut(), self.credentials.as_ref())
        else {
            return Ok(None);
        };
        challenge
            .respond(&PasswordParams {
                username: credentials.username(),
                password: credentials
                    .password()
                    .map_or("", |password| password.expose_secret()),
                uri,
                method: "GET",
                body: Some(&[]),
            })
            .map(Some)
            .map_err(|_| SourceError::AuthFailed(UNANSWERABLE.to_owned()))
    }

    /// A GET of `target`: origin-form (RFC 9112 §3.2.1), `Host` (RFC 9112
    /// §3.2), `User-Agent` and, once challenged, `Authorization`.
    fn request(&mut self, target: &Url) -> Result<Request<Empty<Bytes>>, SourceError> {
        let uri = match target.query() {
            Some(query) => format!("{}?{query}", target.path()),
            None => target.path().to_owned(),
        };
        let host = match target.port() {
            Some(port) => format!("{}:{port}", target.host_str().unwrap_or_default()),
            None => target.host_str().unwrap_or_default().to_owned(),
        };
        let mut request = Request::get(uri.as_str())
            .header(HOST, host)
            .header(USER_AGENT, DAEMON_USER_AGENT);
        if let Some(authorization) = self.authorization(&uri)? {
            request = request.header(AUTHORIZATION, authorization);
        }
        request
            .body(Empty::new())
            .map_err(|err| SourceError::Protocol(format!("the request cannot be sent: {err}")))
    }

    /// Sends a GET of `target` on the kept-alive connection, or on a new
    /// one when there is none or the server closed it (RFC 9112 §9.3.1).
    async fn send(&mut self, target: &Url) -> Result<hyper::Response<Incoming>, SourceError> {
        if let Some(mut sender) = self.sender.take() {
            let request = self.request(target)?;
            match self.exchange(&mut sender, request).await? {
                Ok(answer) => {
                    self.sender = Some(sender);
                    return Ok(answer);
                }
                Err(err) => tracing::debug!(
                    error = %err,
                    "http: the kept-alive connection is gone; sending again on a new one"
                ),
            }
        }
        let mut sender = self.connect().await?;
        let request = self.request(target)?;
        let answer = self
            .exchange(&mut sender, request)
            .await?
            .map_err(|err| hyper_error(&err))?;
        self.sender = Some(sender);
        Ok(answer)
    }

    /// Waits for the connection to take a request, sends it and waits for
    /// the answer's head, within the timeout.
    async fn exchange(
        &self,
        sender: &mut SendRequest<Empty<Bytes>>,
        request: Request<Empty<Bytes>>,
    ) -> Result<hyper::Result<hyper::Response<Incoming>>, SourceError> {
        let answer = async {
            sender.ready().await?;
            sender.send_request(request).await
        };
        tokio::select! {
            answer = answer => Ok(answer),
            () = self.clock.sleep(self.timeout) => Err(timed_out("no answer", self.timeout)),
        }
    }

    /// Connects to the first of the peer's addresses that answers within
    /// the timeout, and runs HTTP/1.1 on it.
    async fn connect(&self) -> Result<SendRequest<Empty<Bytes>>, SourceError> {
        let mut failure =
            SourceError::Unreachable(format!("{} resolved to no address", self.peer.host));
        for &addr in &self.peer.addrs {
            let connected = tokio::select! {
                io = self.connector.connect(addr, &self.peer.host) => io,
                () = self.clock.sleep(self.timeout) => Err(SourceError::Unreachable(format!(
                    "connecting to {addr} took longer than {} ms",
                    self.timeout.as_millis()
                ))),
            };
            match connected {
                Ok(io) => return self.handshake(io, addr).await,
                Err(err) => {
                    tracing::debug!(%addr, error = %err, "http: connect failed");
                    failure = err;
                }
            }
        }
        Err(failure)
    }

    /// Runs HTTP/1.1 on `io` and drives the connection in its own task
    /// until it closes or the client's token is cancelled.
    async fn handshake(
        &self,
        io: C::Io,
        addr: SocketAddr,
    ) -> Result<SendRequest<Empty<Bytes>>, SourceError> {
        let (sender, connection) = http1::handshake(TokioIo::new(io))
            .await
            .map_err(|err| hyper_error(&err))?;
        let cancel = self.cancel.clone();
        let _driver = spawn_named("http.connection", async move {
            let ended = tokio::select! {
                result = connection => result.err().map(|err| err.to_string()),
                () = cancel.cancelled() => Some("cancelled".to_owned()),
            };
            tracing::debug!(%addr, error = ?ended, "http: connection closed");
        });
        tracing::debug!(%addr, "http: connected");
        Ok(sender)
    }
}

/// A 2xx answer: its status, `Content-Type`, the URL it came from after
/// redirects, and its unread body. `Debug` prints the URL redacted
/// ([`RedactedUrl`]).
pub struct Response {
    /// The 2xx status.
    status: StatusCode,
    /// The `Content-Type` field (RFC 9110 §8.3), when present and visible
    /// ASCII.
    content_type: Option<String>,
    /// The URL the body came from: the one asked for, or the last
    /// redirect's (RFC 9110 §15.4), against which a playlist's URIs
    /// resolve (RFC 8216 §4.1).
    url: Url,
    /// The body.
    body: Body,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("url", &RedactedUrl::new(&self.url))
            .field("body", &self.body)
            .finish()
    }
}

impl Response {
    /// The status code, 200 to 299.
    pub const fn status(&self) -> u16 {
        self.status.as_u16()
    }

    /// The `Content-Type`, when the answer has one.
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// The URL the answer came from, after redirects, without userinfo.
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// The body, to read.
    pub fn into_body(self) -> Body {
        self.body
    }
}

/// An answer's body, read whole or chunk by chunk; each wait for bytes is
/// bounded by the client's timeout.
pub struct Body {
    /// The bytes as they arrive.
    incoming: Incoming,
    /// Deadlines.
    clock: Arc<dyn Clock>,
    /// How long one wait for bytes may take.
    timeout: Duration,
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Body")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Body {
    /// The whole body, refused as `source_protocol_error` once it grows
    /// past `limit` bytes (a playlist's or a segment's cap).
    pub async fn bytes(self, limit: usize) -> Result<Bytes, SourceError> {
        let mut body = Limited::new(self.incoming, limit);
        let mut whole = BytesMut::new();
        while let Some(frame) = next_frame(&mut body, &*self.clock, self.timeout).await? {
            let frame = frame.map_err(|err| match err.downcast::<hyper::Error>() {
                Ok(err) => hyper_error(&err),
                Err(_) => SourceError::Protocol(format!("the body is larger than {limit} bytes")),
            })?;
            whole.extend_from_slice(&frame.into_data().unwrap_or_default());
        }
        Ok(whole.freeze())
    }

    /// The next bytes of the body as they arrive, `None` at its end: for
    /// a stream without end (raw MPEG-TS). Trailers read as an empty chunk.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, SourceError> {
        next_frame(&mut self.incoming, &*self.clock, self.timeout)
            .await?
            .transpose()
            .map(|frame| frame.map(|frame| frame.into_data().unwrap_or_default()))
            .map_err(|err| hyper_error(&err))
    }
}

/// The next frame of `body`, `None` at its end, or a timeout when none
/// comes within `timeout`; the body's own error is left to the caller.
async fn next_frame<B>(
    body: &mut B,
    clock: &dyn Clock,
    timeout: Duration,
) -> Result<Option<Result<Frame<Bytes>, B::Error>>, SourceError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    tokio::select! {
        frame = body.frame() => Ok(frame),
        () = clock.sleep(timeout) => Err(timed_out("no body bytes", timeout)),
    }
}

/// Whether `status` redirects a GET to `Location` (RFC 9110 §15.4.2,
/// §15.4.3, §15.4.4, §15.4.8, §15.4.9).
fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// The error of a final non-2xx answer: 401 and 403 are refused
/// credentials (RFC 9110 §15.5.2, §15.5.4), 5xx a server that cannot serve
/// (RFC 9110 §15.6), anything else a protocol error naming the status.
fn status_error(status: StatusCode) -> SourceError {
    let message = format!("the server answered {status}");
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        SourceError::AuthFailed(message)
    } else if status.is_server_error() {
        SourceError::Unreachable(message)
    } else {
        SourceError::Protocol(message)
    }
}

/// A hyper error typed: an answer that is not HTTP/1.1 is a protocol
/// error, anything else a lost connection.
fn hyper_error(err: &hyper::Error) -> SourceError {
    if err.is_parse() {
        SourceError::Protocol(format!("the answer is not HTTP/1.1: {err}"))
    } else {
        SourceError::Unreachable(format!("the connection failed: {err}"))
    }
}

/// The timeout error for `what` ("no answer") within `timeout`.
fn timed_out(what: &str, timeout: Duration) -> SourceError {
    SourceError::Timeout(format!("{what} within {} ms", timeout.as_millis()))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::future::Future;
    use std::io;
    use std::sync::Mutex;

    use lotse_core::clock::FakeClock;
    use lotse_testing::fake_http::{Challenge, FakeHttp, Reply};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);
    const PASSWORD: &str = "hunter2";

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
            io::Write::flush(&mut self.clone()).unwrap();
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        fn install(&self) -> tracing::subscriber::DefaultGuard {
            let writer = self.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::DEBUG)
                .finish();
            tracing::subscriber::set_default(subscriber)
        }
    }

    struct Setup {
        fake: FakeHttp,
        clock: Arc<FakeClock>,
        cancel: CancellationToken,
        client: Client<Plain>,
    }

    /// A client for `userinfo@<fake>/` and the fake it talks to.
    async fn setup(userinfo: &str) -> Setup {
        let fake = FakeHttp::start().await.unwrap();
        let clock = Arc::new(FakeClock::default());
        let cancel = CancellationToken::new();
        let client = client_to(&fake, userinfo, &clock, &cancel, vec![fake.addr()]);
        Setup {
            fake,
            clock,
            cancel,
            client,
        }
    }

    fn client_to(
        fake: &FakeHttp,
        userinfo: &str,
        clock: &Arc<FakeClock>,
        cancel: &CancellationToken,
        addrs: Vec<SocketAddr>,
    ) -> Client<Plain> {
        let url = SourceUrl::parse(&format!("http://{userinfo}{}/", fake.addr())).unwrap();
        let peer = ResolvedPeer {
            host: url.host().to_owned(),
            addrs,
        };
        Client::new(
            Plain,
            &url,
            peer,
            Arc::<FakeClock>::clone(clock),
            TIMEOUT,
            cancel.clone(),
        )
    }

    fn url(fake: &FakeHttp, target: &str) -> Url {
        Url::parse(&fake.url(target)).unwrap()
    }

    /// Polls `fut` until it finishes or `done` holds, yielding between polls.
    async fn drive<F: Future + Unpin>(fut: &mut F, done: impl Fn() -> bool) -> Option<F::Output> {
        let mut rounds = 0;
        loop {
            assert!(
                rounds < 100_000,
                "neither finished nor reached the condition"
            );
            rounds += 1;
            if done() {
                return None;
            }
            tokio::select! {
                biased;
                out = &mut *fut => return Some(out),
                () = tokio::task::yield_now() => {}
            }
        }
    }

    async fn wait_for_log(logs: &Captured, needle: &str) {
        let mut never = Box::pin(std::future::pending::<()>());
        let found = drive(&mut never, || logs.text().contains(needle)).await;
        assert!(found.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9112_3_2_a_get_sends_the_origin_form_host_and_user_agent() {
        let mut s = setup("").await;
        s.fake.set(
            "/live/a.m3u8?token=1",
            Reply::body("application/vnd.apple.mpegurl", "#EXTM3U\n"),
        );
        let response = s
            .client
            .get(&url(&s.fake, "/live/a.m3u8?token=1"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.content_type(),
            Some("application/vnd.apple.mpegurl")
        );
        assert_eq!(response.url().as_str(), s.fake.url("/live/a.m3u8?token=1"));
        let debug = format!("{response:?}");
        assert!(
            debug.contains(&format!("url: Url(\"http://{}/****?****\")", s.fake.addr()))
                && debug.contains("status: 200")
                && !debug.contains("token"),
            "{debug}"
        );
        assert_eq!(
            &response.into_body().bytes(1024).await.unwrap()[..],
            b"#EXTM3U\n"
        );
        let seen = s.fake.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].target, "/live/a.m3u8?token=1");
        assert_eq!(
            seen[0].host.as_deref(),
            Some(s.fake.addr().to_string().as_str())
        );
        assert_eq!(seen[0].user_agent.as_deref(), Some(DAEMON_USER_AGENT));
        assert_eq!(seen[0].authorization, None);
        assert!(DAEMON_USER_AGENT.starts_with("lotse/"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9112_3_2_host_leaves_out_the_default_port() {
        let fake = FakeHttp::start().await.unwrap();
        let source = SourceUrl::parse("http://cam.example/a").unwrap();
        let peer = ResolvedPeer {
            host: "cam.example".to_owned(),
            addrs: vec![fake.addr()],
        };
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::default());
        let mut client = Client::new(
            Plain,
            &source,
            peer,
            clock,
            TIMEOUT,
            CancellationToken::new(),
        );
        fake.set("/a", Reply::body("text/plain", "x"));
        let response = client.get(source.expose_url()).await.unwrap();
        assert_eq!(response.content_type(), Some("text/plain"));
        assert_eq!(fake.requests()[0].host.as_deref(), Some("cam.example"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9112_9_3_consecutive_gets_share_one_connection() {
        let mut s = setup("").await;
        s.fake.set("/a", Reply::body("video/mp2t", "aa"));
        s.fake.set("/b", Reply::body("video/mp2t", "bb"));
        for target in ["/a", "/b", "/a"] {
            let body = s
                .client
                .get(&url(&s.fake, target))
                .await
                .unwrap()
                .into_body();
            assert_eq!(body.bytes(16).await.unwrap().len(), 2);
        }
        assert_eq!(s.fake.connections(), 1);
        assert_eq!(s.fake.requests().len(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9112_9_3_1_a_connection_the_server_closed_is_replaced_and_the_get_sent_again() {
        let logs = Captured::default();
        let _logs = logs.install();
        let mut s = setup("").await;
        s.fake
            .set("/close", Reply::Close(Bytes::from_static(b"last")));
        s.fake.set("/next", Reply::body("video/mp2t", "next"));
        let response = s.client.get(&url(&s.fake, "/close")).await.unwrap();
        assert_eq!(response.content_type(), None);
        assert_eq!(&response.into_body().bytes(16).await.unwrap()[..], b"last");
        wait_for_log(&logs, "http: connection closed").await;
        let body = s
            .client
            .get(&url(&s.fake, "/next"))
            .await
            .unwrap()
            .into_body();
        assert_eq!(&body.bytes(16).await.unwrap()[..], b"next");
        assert_eq!(s.fake.connections(), 2);
        assert!(logs.text().contains("the kept-alive connection is gone"));
        assert!(
            logs.text().contains("error=None"),
            "a clean close: {}",
            logs.text()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_the_token_ends_the_connection_task() {
        let logs = Captured::default();
        let _logs = logs.install();
        let mut s = setup("").await;
        s.fake.set("/a", Reply::body("video/mp2t", "a"));
        let body = s.client.get(&url(&s.fake, "/a")).await.unwrap().into_body();
        assert_eq!(body.bytes(16).await.unwrap().len(), 1);
        s.cancel.cancel();
        wait_for_log(&logs, "http: connection closed").await;
        assert!(logs.text().contains("error=Some(\"cancelled\")"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_15_4_every_redirect_status_is_followed_on_the_same_origin() {
        let mut s = setup("").await;
        s.fake.set("/ok", Reply::body("video/mp2t", "ok"));
        for status in [301, 302, 303, 307, 308] {
            s.fake.set(
                "/moved",
                Reply::Redirect {
                    status,
                    location: "/ok".to_owned(),
                },
            );
            let response = s.client.get(&url(&s.fake, "/moved")).await.unwrap();
            assert_eq!(response.url().path(), "/ok", "{status}");
            assert_eq!(&response.into_body().bytes(16).await.unwrap()[..], b"ok");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_15_4_two_redirects_are_followed_relative_and_absolute_without_userinfo() {
        let mut s = setup("").await;
        s.fake.set(
            "/a/first",
            Reply::Redirect {
                status: 302,
                location: "second?x=1".to_owned(),
            },
        );
        s.fake.set(
            "/a/second?x=1",
            Reply::Redirect {
                status: 307,
                location: format!("http://someone:{PASSWORD}@{}/final?y=2", s.fake.addr()),
            },
        );
        s.fake.set("/final?y=2", Reply::body("video/mp2t", "done"));
        let response = s.client.get(&url(&s.fake, "/a/first")).await.unwrap();
        assert_eq!(response.url().as_str(), s.fake.url("/final?y=2"));
        let targets: Vec<_> = s
            .fake
            .requests()
            .into_iter()
            .map(|seen| seen.target)
            .collect();
        assert_eq!(targets, ["/a/first", "/a/second?x=1", "/final?y=2"]);
        assert!(
            s.fake
                .requests()
                .iter()
                .all(|seen| seen.authorization.is_none())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_15_4_a_third_redirect_is_refused() {
        let mut s = setup("").await;
        for (from, to) in [("/1", "/2"), ("/2", "/3"), ("/3", "/4")] {
            s.fake.set(
                from,
                Reply::Redirect {
                    status: 301,
                    location: to.to_owned(),
                },
            );
        }
        s.fake.set("/4", Reply::body("video/mp2t", "4"));
        assert!(
            s.client.get(&url(&s.fake, "/2")).await.is_ok(),
            "two are fine"
        );
        let err = s.client.get(&url(&s.fake, "/1")).await.unwrap_err();
        assert_eq!(
            err,
            SourceError::Protocol("more than 2 redirects".to_owned())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_15_4_a_redirect_to_another_origin_is_refused_naming_the_origin_only() {
        let mut s = setup("").await;
        s.fake.set(
            "/away",
            Reply::Redirect {
                status: 302,
                location: format!("http://user:{PASSWORD}@cdn.example:8080/private/path?token=abc"),
            },
        );
        let err = s.client.get(&url(&s.fake, "/away")).await.unwrap_err();
        assert_eq!(err.code(), "source_protocol_error");
        let message = err.to_string();
        assert!(
            message.starts_with("source protocol error: http://cdn.example:8080 is another origin"),
            "{message}"
        );
        for secret in [PASSWORD, "user", "private", "token", "abc"] {
            assert!(!message.contains(secret), "{message}");
        }
        assert_eq!(
            s.fake.requests().len(),
            1,
            "nothing sent to the other origin"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc6454_a_url_on_another_origin_is_never_fetched() {
        let mut s = setup("").await;
        for other in [
            "http://127.0.0.2:80/a".to_owned(),
            format!("https://{}/a", s.fake.addr()),
            format!(
                "http://127.0.0.1:{}/a",
                s.fake.addr().port().wrapping_add(1)
            ),
        ] {
            let err = s
                .client
                .get(&Url::parse(&other).unwrap())
                .await
                .unwrap_err();
            assert!(
                matches!(&err, SourceError::Protocol(m) if m.contains("another origin")),
                "{err:?}"
            );
        }
        assert_eq!(s.fake.connections(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_10_2_2_a_redirect_without_a_usable_location_is_refused() {
        let mut s = setup("").await;
        s.fake.set("/none", Reply::Status(302));
        let err = s.client.get(&url(&s.fake, "/none")).await.unwrap_err();
        assert_eq!(
            err,
            SourceError::Protocol("302 Found without a usable Location".to_owned())
        );
        s.fake.set(
            "/bad",
            Reply::Redirect {
                status: 301,
                location: "http://[::1".to_owned(),
            },
        );
        let err = s.client.get(&url(&s.fake, "/bad")).await.unwrap_err();
        assert!(
            matches!(&err, SourceError::Protocol(m) if m.starts_with("the Location of a 301 Moved Permanently does not parse")),
            "{err:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_15_final_statuses_map_to_the_source_error_codes() {
        let mut s = setup("").await;
        let cases = [
            (300, "source_protocol_error", "300 Multiple Choices"),
            (304, "source_protocol_error", "304 Not Modified"),
            (403, "source_auth_failed", "403 Forbidden"),
            (404, "source_protocol_error", "404 Not Found"),
            (410, "source_protocol_error", "410 Gone"),
            (500, "source_unreachable", "500 Internal Server Error"),
            (503, "source_unreachable", "503 Service Unavailable"),
            (599, "source_unreachable", "599 <unknown status code>"),
        ];
        for (status, code, text) in cases {
            s.fake.set("/x", Reply::Status(status));
            let err = s.client.get(&url(&s.fake, "/x")).await.unwrap_err();
            assert_eq!(err.code(), code, "{status}");
            assert!(
                err.to_string()
                    .ends_with(&format!("the server answered {text}")),
                "{err}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_15_5_2_a_challenge_without_credentials_in_the_url_is_auth_failed() {
        let mut s = setup("").await;
        s.fake.require(Some((Challenge::Basic, "admin", PASSWORD)));
        s.fake.set("/a", Reply::body("video/mp2t", "a"));
        let err = s.client.get(&url(&s.fake, "/a")).await.unwrap_err();
        assert_eq!(
            err,
            SourceError::AuthFailed(
                "the server asks for credentials and the url has none".to_owned()
            )
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc7617_2_basic_credentials_go_only_after_the_origins_challenge_and_then_on_every_get()
    {
        let logs = Captured::default();
        let _logs = logs.install();
        let mut s = setup(&format!("admin:{PASSWORD}@")).await;
        s.fake.require(Some((Challenge::Basic, "admin", PASSWORD)));
        s.fake.set("/a", Reply::body("video/mp2t", "a"));
        for _ in 0..2 {
            let body = s.client.get(&url(&s.fake, "/a")).await.unwrap().into_body();
            assert_eq!(&body.bytes(4).await.unwrap()[..], b"a");
        }
        let seen = s.fake.requests();
        assert_eq!(
            seen.len(),
            3,
            "one challenge, then the credentials up front"
        );
        assert_eq!(seen[0].authorization, None);
        assert!(
            seen[1]
                .authorization
                .as_deref()
                .unwrap()
                .starts_with("Basic ")
        );
        assert_eq!(seen[1].authorization, seen[2].authorization);
        assert!(logs.text().contains("answering the server's challenge"));
        assert!(!logs.text().contains(PASSWORD));
        assert!(
            !logs
                .text()
                .contains(&seen[1].authorization.clone().unwrap())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc7616_3_4_digest_challenges_are_answered_with_md5_and_sha256() {
        for challenge in [Challenge::DigestMd5, Challenge::DigestSha256] {
            let logs = Captured::default();
            let _logs = logs.install();
            let mut s = setup(&format!("admin:{PASSWORD}@")).await;
            s.fake.require(Some((challenge, "admin", PASSWORD)));
            s.fake
                .set("/seg.ts?part=1", Reply::body("video/mp2t", "seg"));
            for _ in 0..2 {
                let body = s
                    .client
                    .get(&url(&s.fake, "/seg.ts?part=1"))
                    .await
                    .unwrap()
                    .into_body();
                assert_eq!(&body.bytes(4).await.unwrap()[..], b"seg", "{challenge:?}");
            }
            let seen = s.fake.requests();
            assert_eq!(seen.len(), 3, "{challenge:?}");
            assert!(
                seen[1]
                    .authorization
                    .as_deref()
                    .unwrap()
                    .starts_with("Digest ")
            );
            assert!(
                seen[2]
                    .authorization
                    .as_deref()
                    .unwrap()
                    .contains("nc=00000002")
            );
            assert!(!logs.text().contains(PASSWORD));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc7616_3_3_a_new_challenge_on_a_later_get_is_answered_again() {
        let mut s = setup(&format!("admin:{PASSWORD}@")).await;
        s.fake.require(Some((Challenge::Basic, "admin", PASSWORD)));
        s.fake.set("/a", Reply::body("video/mp2t", "a"));
        assert!(s.client.get(&url(&s.fake, "/a")).await.is_ok());
        s.fake
            .require(Some((Challenge::DigestMd5, "admin", PASSWORD)));
        assert!(s.client.get(&url(&s.fake, "/a")).await.is_ok());
        let seen = s.fake.requests();
        assert_eq!(seen.len(), 4);
        assert!(
            seen[2]
                .authorization
                .as_deref()
                .unwrap()
                .starts_with("Basic ")
        );
        assert!(
            seen[3]
                .authorization
                .as_deref()
                .unwrap()
                .starts_with("Digest ")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc7617_wrong_credentials_are_auth_failed_after_one_answer() {
        for challenge in [Challenge::Basic, Challenge::DigestMd5] {
            let logs = Captured::default();
            let _logs = logs.install();
            let mut s = setup(&format!("admin:{PASSWORD}@")).await;
            s.fake.require(Some((challenge, "admin", "other")));
            s.fake.set("/a", Reply::body("video/mp2t", "a"));
            let target = url(&s.fake, "/a");
            let mut get = Box::pin(s.client.get(&target));
            let fake = &s.fake;
            let err = drive(&mut get, || fake.requests().len() > 2)
                .await
                .expect("one answer to the challenge, never a second")
                .unwrap_err();
            drop(get);
            assert_eq!(
                err,
                SourceError::AuthFailed("the server answered 401 Unauthorized".to_owned())
            );
            assert_eq!(s.fake.requests().len(), 2, "{challenge:?}");
            assert!(!logs.text().contains(PASSWORD));
            assert!(!format!("{err}{err:?}").contains(PASSWORD));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_11_6_1_a_401_without_a_usable_challenge_is_auth_failed() {
        let mut s = setup(&format!("admin:{PASSWORD}@")).await;
        s.fake.set("/a", Reply::Status(401));
        let err = s.client.get(&url(&s.fake, "/a")).await.unwrap_err();
        assert_eq!(
            err,
            SourceError::AuthFailed(
                "the server's challenge cannot be answered: no challenges given".to_owned()
            )
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_target_too_long_for_a_request_line_is_refused() {
        let mut s = setup("").await;
        let long = format!("/{}", "a".repeat(70_000));
        let err = s.client.get(&url(&s.fake, &long)).await.unwrap_err();
        assert!(
            matches!(&err, SourceError::Protocol(m) if m.starts_with("the request cannot be sent")),
            "{err:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_whole_body_over_its_cap_is_refused() {
        let mut s = setup("").await;
        s.fake
            .set("/big", Reply::body("video/mp2t", vec![0_u8; 2048]));
        let body = s
            .client
            .get(&url(&s.fake, "/big"))
            .await
            .unwrap()
            .into_body();
        assert_eq!(
            body.bytes(2048).await.unwrap().len(),
            2048,
            "the cap itself fits"
        );
        let body = s
            .client
            .get(&url(&s.fake, "/big"))
            .await
            .unwrap()
            .into_body();
        assert_eq!(
            body.bytes(2047).await.unwrap_err(),
            SourceError::Protocol("the body is larger than 2047 bytes".to_owned())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_hang_up_mid_body_is_unreachable() {
        let mut s = setup("").await;
        s.fake.set(
            "/cut",
            Reply::HangUp {
                declared: 100,
                sent: Bytes::from_static(b"part"),
            },
        );
        let body = s
            .client
            .get(&url(&s.fake, "/cut"))
            .await
            .unwrap()
            .into_body();
        let err = body.bytes(1000).await.unwrap_err();
        assert!(
            matches!(&err, SourceError::Unreachable(m) if m.starts_with("the connection failed")),
            "{err:?}"
        );
        let mut body = s
            .client
            .get(&url(&s.fake, "/cut"))
            .await
            .unwrap()
            .into_body();
        assert_eq!(&body.chunk().await.unwrap().unwrap()[..], b"part");
        assert_eq!(body.chunk().await.unwrap_err().code(), "source_unreachable");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_without_end_is_read_chunk_by_chunk_until_the_server_ends_it() {
        let mut s = setup("").await;
        let feed = s.fake.stream("/stream.ts");
        let response = s.client.get(&url(&s.fake, "/stream.ts")).await.unwrap();
        assert_eq!(response.content_type(), Some("video/mp2t"));
        let mut body = response.into_body();
        assert!(format!("{body:?}").starts_with("Body { timeout: 5s"));
        for chunk in [&b"\x47one"[..], b"\x47two"] {
            feed.send(Bytes::from_static(chunk)).await.unwrap();
            assert_eq!(&body.chunk().await.unwrap().unwrap()[..], chunk);
        }
        drop(feed);
        assert_eq!(body.chunk().await.unwrap(), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_body_times_out() {
        let mut s = setup("").await;
        s.fake
            .set("/stall", Reply::Stall(Bytes::from_static(b"first")));
        let mut body = s
            .client
            .get(&url(&s.fake, "/stall"))
            .await
            .unwrap()
            .into_body();
        assert_eq!(&body.chunk().await.unwrap().unwrap()[..], b"first");
        let mut next = Box::pin(body.chunk());
        assert!(poll_once(&mut next).await.is_none());
        s.clock.advance(Duration::from_millis(4_999));
        assert!(
            poll_once(&mut next).await.is_none(),
            "not before the deadline"
        );
        s.clock.advance(Duration::from_millis(1));
        assert_eq!(
            next.await.unwrap_err(),
            SourceError::Timeout("no body bytes within 5000 ms".to_owned())
        );
        drop(body);

        let body = s
            .client
            .get(&url(&s.fake, "/stall"))
            .await
            .unwrap()
            .into_body();
        let mut whole = Box::pin(body.bytes(1024));
        assert!(poll_once(&mut whole).await.is_none());
        s.clock.advance(TIMEOUT);
        assert_eq!(whole.await.unwrap_err().code(), "source_timeout");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_that_never_comes_times_out_on_a_kept_and_on_a_new_connection() {
        let mut s = setup("").await;
        s.fake.set("/a", Reply::body("video/mp2t", "a"));
        s.fake.set("/hang", Reply::Hang);
        let body = s.client.get(&url(&s.fake, "/a")).await.unwrap().into_body();
        assert_eq!(body.bytes(4).await.unwrap().len(), 1);
        for expected in [2, 3] {
            let target = url(&s.fake, "/hang");
            let mut get = Box::pin(s.client.get(&target));
            let fake = &s.fake;
            assert!(
                drive(&mut get, || fake.requests().len() == expected)
                    .await
                    .is_none()
            );
            s.clock.advance(TIMEOUT);
            assert_eq!(
                get.await.unwrap_err(),
                SourceError::Timeout("no answer within 5000 ms".to_owned())
            );
        }
        assert_eq!(
            s.fake.connections(),
            2,
            "the timed-out connection is not reused"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_addresses_are_tried_in_order_until_one_connects() {
        let s = setup("").await;
        s.fake.set("/a", Reply::body("video/mp2t", "a"));
        let closed = {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            listener.local_addr().unwrap()
        };
        let mut client = client_to(
            &s.fake,
            "",
            &s.clock,
            &s.cancel,
            vec![closed, s.fake.addr()],
        );
        assert!(client.get(&url(&s.fake, "/a")).await.is_ok());
        assert_eq!(s.fake.connections(), 1);

        let mut client = client_to(&s.fake, "", &s.clock, &s.cancel, vec![closed]);
        let err = client.get(&url(&s.fake, "/a")).await.unwrap_err();
        assert!(
            matches!(&err, SourceError::Unreachable(m) if m.starts_with(&format!("unable to connect to {closed}"))),
            "{err:?}"
        );

        let mut client = client_to(&s.fake, "", &s.clock, &s.cancel, Vec::new());
        assert_eq!(
            client.get(&url(&s.fake, "/a")).await.unwrap_err(),
            SourceError::Unreachable("127.0.0.1 resolved to no address".to_owned())
        );
    }

    /// A connector whose connections never complete.
    #[derive(Debug)]
    struct Never;

    impl Connect for Never {
        type Io = TcpStream;

        fn connect(
            &self,
            _addr: SocketAddr,
            _host: &str,
        ) -> BoxFuture<'static, Result<TcpStream, SourceError>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_connect_that_never_completes_is_unreachable_after_the_timeout() {
        let source = SourceUrl::parse("http://cam.example/a").unwrap();
        let addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        let peer = ResolvedPeer {
            host: "cam.example".to_owned(),
            addrs: vec![addr],
        };
        let clock = Arc::new(FakeClock::default());
        let mut client = Client::new(
            Never,
            &source,
            peer,
            Arc::<FakeClock>::clone(&clock),
            TIMEOUT,
            CancellationToken::new(),
        );
        let mut get = Box::pin(client.get(source.expose_url()));
        assert!(poll_once(&mut get).await.is_none());
        clock.advance(TIMEOUT);
        assert_eq!(
            get.await.unwrap_err(),
            SourceError::Unreachable(
                "connecting to 192.0.2.1:80 took longer than 5000 ms".to_owned()
            )
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9112_an_answer_that_is_not_http_is_a_protocol_error() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn_named("test.not_http", async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _read = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"SSH-2.0-OpenSSH_9.9\r\n\r\n")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let source = SourceUrl::parse(&format!("http://{addr}/a")).unwrap();
        let peer = ResolvedPeer {
            host: "127.0.0.1".to_owned(),
            addrs: vec![addr],
        };
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::default());
        let mut client = Client::new(
            Plain,
            &source,
            peer,
            clock,
            TIMEOUT,
            CancellationToken::new(),
        );
        let err = client.get(source.expose_url()).await.unwrap_err();
        assert!(
            matches!(&err, SourceError::Protocol(m) if m.starts_with("the answer is not HTTP/1.1")),
            "{err:?}"
        );
        server.await.unwrap();
    }

    /// Polls `fut` once: its output if it finished.
    async fn poll_once<F: Future + Unpin>(fut: &mut F) -> Option<F::Output> {
        tokio::select! {
            biased;
            out = &mut *fut => Some(out),
            () = std::future::ready(()) => None,
        }
    }
}
