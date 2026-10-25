//! `GET /v0/clips/{clip_id}`: an event clip's bytes as one HTTP response
//! body, on either listener, through the same `Extension(peer)` path as
//! the upgrade.
//!
//! The handler hands each clip over once ([`Handler::clip_body`]): a
//! reader of the file's bytes and the producer's report of how many it
//! wrote. The body is sent in the chunked transfer coding (RFC 9112 §7.1),
//! since its length is not known before the clip ends, and ends with the
//! last chunk only when the reader ended and the report says every byte
//! arrived. A clip cut short (its worker died, its reader failed, the
//! report disagrees or never comes within [`CLIP_REPORT_TIMEOUT`]) ends
//! without it, which a client reads as an incomplete message (RFC 9112
//! §8). The response carries `Connection: close` (RFC 9112 §9.6), so the
//! connection ends with the body and serves nothing else.
//!
//! Once its response begins, the connection leaves the pending upgrades
//! and their deadline (a clip runs for minutes) and is bounded instead by
//! the client taking the body: a socket that refuses the response, taking
//! none of it for [`BODY_STALL_TIMEOUT`], drops the connection, whether
//! the body waits for more of the clip meanwhile or not (each write the
//! socket takes ends the wait, so a client reading slowly keeps it), and
//! so does still sending
//! [`CLOSE_TIMEOUT`] after shutdown began, or the removal of the TLS
//! listener's client that takes it (`clients/remove`), which closes its
//! WebSocket connections alike: the connection is registered with the
//! client store while its body is sent. The server waits for it when it
//! stops.
//!
//! Refusals carry the error body of the WebSocket's results, and none
//! takes the clip: 403 for a request carrying `Origin` (RFC 6455 §10.2, as
//! the upgrade refuses it), 503 `shutting_down` (RFC 9110 §15.6.4), 403
//! `not_permitted` (RFC 9110 §15.5.4) for a TLS client removed since its
//! handshake, on a connection that then closes, 505 `invalid_request` (RFC
//! 9110 §15.6.6) for a request not in HTTP/1.1, whose response could not
//! be chunked (RFC 9112 §6.1) and so could not end cut (§6.3: it would be
//! close-delimited), 404 `clip_not_found` (RFC 9110 §15.5.5) for an id
//! that is no open clip's (`.` and `..` included, which no clip has), 409
//! `clip_already_fetched` (RFC 9110 §15.5.10) for a body another request
//! took, and 405 with `Allow: GET` (RFC 9110 §15.5.6) for any other
//! method, HEAD included, which would otherwise take the body.
//!
//! [`Handler::clip_body`]: crate::Handler::clip_body
//! [`CLIP_REPORT_TIMEOUT`]: crate::CLIP_REPORT_TIMEOUT
//! [`BODY_STALL_TIMEOUT`]: crate::BODY_STALL_TIMEOUT

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, StatusCode, Uri, Version, header};
use axum::response::{IntoResponse as _, Response};
use futures_util::StreamExt as _;
use lotse_api_types::CLIPS_PATH;
use lotse_api_types::error::ErrorCode;
use lotse_core::clock::Clock;
use lotse_core::id::ClipId;
use lotse_core::task::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{oneshot, watch};
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

use crate::connection::refuse;
use crate::listener::PeerInfo;
use crate::{AppState, BODY_STALL_TIMEOUT, CLIP_REPORT_TIMEOUT, CLOSE_TIMEOUT, Handler};

/// The most bytes read from a clip at once: a Linux pipe's default
/// capacity (pipe(7)), so one read can take all a full pipe holds.
const CHUNK_BYTES: usize = 64 * 1024;

/// The response header naming the clip a body belongs to.
const X_CLIP_ID: HeaderName = HeaderName::from_static("x-clip-id");

/// One clip's bytes, as the handler hands them to the one request that
/// takes them.
pub struct ClipBody {
    /// The file's bytes, read to their end: the read end of the pipe the
    /// clip's worker writes.
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    /// The number of bytes the producer reports having written, sent once
    /// it wrote its last. A sender dropped without it means the clip did
    /// not finish (its worker died): the body is then cut.
    pub written: oneshot::Receiver<u64>,
}

/// Names the type only: the reader is any byte source.
impl fmt::Debug for ClipBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipBody").finish_non_exhaustive()
    }
}

/// Why the handler has no body for a clip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClipBodyError {
    /// No open clip has the id: answered 404 `clip_not_found`.
    #[error("no open clip has this id")]
    NotFound,
    /// Another request took the clip's body: answered 409
    /// `clip_already_fetched`.
    #[error("the clip's body was already fetched")]
    AlreadyFetched,
}

/// What a connection's clip body is doing, as its connection task
/// watches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyState {
    /// No clip body: the connection is before its upgrade.
    Idle,
    /// A clip body is being sent, and the socket took what it was last
    /// offered, or was offered nothing yet.
    Taken,
    /// A clip body is being sent, and the socket refused a write of the
    /// response at this instant and took none of it since: what the
    /// response holds waits for the client, whether the body waits for
    /// more of the clip or not.
    Waiting(Instant),
}

impl BodyState {
    /// Whether a clip body is being sent.
    pub(crate) const fn is_sending(&self) -> bool {
        !matches!(self, Self::Idle)
    }
}

/// A connection's [`BodyState`], shared by the route, the body it sends
/// and the connection's task. Holding one keeps the task's receiver
/// open.
#[derive(Debug, Clone)]
pub(crate) struct BodyWatch(Arc<watch::Sender<BodyState>>);

impl BodyWatch {
    /// A connection without a clip body.
    pub(crate) fn new() -> Self {
        Self(Arc::new(watch::Sender::new(BodyState::Idle)))
    }

    /// Records what the body does now.
    fn set(&self, state: BodyState) {
        self.0.send_replace(state);
    }

    /// A receiver of every change.
    pub(crate) fn subscribe(&self) -> watch::Receiver<BodyState> {
        self.0.subscribe()
    }

    /// The socket took bytes of the response: a wait for the client ends.
    /// Nobody is woken (the stall timer finds the change when it next
    /// fires), so a write costs no wake-up.
    fn progressed(&self) {
        self.0.send_if_modified(|state| {
            if matches!(state, BodyState::Waiting(_)) {
                *state = BodyState::Taken;
            }
            false
        });
    }

    /// The socket refused a write: what the response holds waits for the
    /// client from `clock`'s now, unless it already did. Nobody is woken,
    /// as for [`Self::progressed`]; with no body sent, nothing changes.
    fn refused(&self, clock: &dyn Clock) {
        self.0.send_if_modified(|state| {
            if matches!(state, BodyState::Taken) {
                *state = BodyState::Waiting(clock.now());
            }
            false
        });
    }
}

/// What a connection's socket is to [`Watched`]: either listener's (a Unix
/// stream, the TCP stream under a TLS session), boxed, so [`Watched`] is
/// one type whatever the listener.
pub(crate) trait Transport: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Transport for T {}

/// A connection's socket, as hyper reads and writes it: a write it refuses
/// starts a clip body's wait for the client ([`BodyWatch::refused`]) and
/// one that takes bytes ends it ([`BodyWatch::progressed`]), so
/// [`BODY_STALL_TIMEOUT`] bounds a client that takes none of the response,
/// whatever the body does meanwhile, not one that takes it slowly. A
/// writer that holds bytes writes until the socket refuses them, as hyper
/// does each time it flushes.
///
/// It wraps the kernel's socket, under the session on the TLS listener. A
/// session takes what it is given into its own buffer and writes it to
/// the socket whenever hyper writes, flushes or shuts the session down, so
/// the session's own results say nothing of the client: it takes the
/// response's end, and then only flushes (tokio-rustls 0.26.6, observed
/// in 2026-10). The socket's flush and shutdown never wait (the kernel
/// buffers), so they pass through.
pub(crate) struct Watched {
    /// The socket.
    io: Box<dyn Transport>,
    /// The connection's body state.
    body: BodyWatch,
    /// Stamps the waits.
    clock: Arc<dyn Clock>,
}

impl Watched {
    /// `io`, reporting its writes to `body`.
    pub(crate) fn new(io: Box<dyn Transport>, body: BodyWatch, clock: Arc<dyn Clock>) -> Self {
        Self { io, body, clock }
    }

    /// Passes `written` on, after telling the body whether the socket
    /// took bytes or refused them; a write that took none, or failed, is
    /// neither.
    fn record(&self, written: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
        match written {
            Poll::Ready(Ok(1..)) => self.body.progressed(),
            Poll::Pending => self.body.refused(self.clock.as_ref()),
            Poll::Ready(Ok(0) | Err(_)) => {}
        }
        written
    }
}

impl AsyncRead for Watched {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Watched {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = Pin::new(&mut self.io).poll_write(cx, buf);
        self.record(written)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let written = Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        self.record(written)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// `GET /v0/clips/{clip_id}`: the checks, then the clip's body from the
/// handler. The peer was authenticated by its listener; a TLS client
/// removed since then is refused here, and one removed later is dropped
/// by its connection's task.
pub(crate) async fn fetch<H: Handler>(
    State(state): State<AppState<H>>,
    Extension(peer): Extension<PeerInfo>,
    Extension(body): Extension<BodyWatch>,
    version: Version,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let removed = match (state.clients.as_deref(), &peer) {
        (Some(clients), PeerInfo::Tls { pin, .. }) => !clients.allows(pin),
        _ => false,
    };
    let request = Request {
        peer: &peer,
        removed,
        version,
        headers: &headers,
        path: uri.path(),
        shutting_down: state.shutdown.is_cancelled(),
        body: &body,
        clock: &state.clock,
    };
    let handler = Arc::clone(&state.handler);
    answer(&request, &|clip_id| handler.clip_body(clip_id))
}

/// Any other method on a clip's path, HEAD included: 405 with `Allow: GET`
/// (RFC 9110 §15.5.6), the clip untouched.
pub(crate) async fn not_allowed() -> Response {
    let mut response = refuse(
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::InvalidRequest,
        "a clip's bytes are fetched with GET",
    );
    response
        .headers_mut()
        .insert(header::ALLOW, header::HeaderValue::from_static("GET"));
    response
}

/// A clip request as the route sees it, before the handler is asked.
struct Request<'a> {
    /// Who asks.
    peer: &'a PeerInfo,
    /// Whether the TLS listener's client that asks was removed since its
    /// handshake.
    removed: bool,
    /// The request's HTTP version.
    version: Version,
    /// The request's header fields.
    headers: &'a HeaderMap,
    /// The request's path, `/v0/clips/{clip_id}`.
    path: &'a str,
    /// Whether the daemon is shutting down.
    shutting_down: bool,
    /// The connection's body state.
    body: &'a BodyWatch,
    /// Times the producer's report.
    clock: &'a Arc<dyn Clock>,
}

/// The answer to `request`, the clip taken from `lookup`: not generic
/// over the handler, so every handler's route shares it.
fn answer(
    request: &Request<'_>,
    lookup: &dyn Fn(&ClipId) -> Result<ClipBody, ClipBodyError>,
) -> Response {
    let peer = request.peer;
    if request.headers.contains_key(header::ORIGIN) {
        tracing::warn!(%peer, "clip body refused: the request carries Origin, as only a browser sends");
        return refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest,
            "requests carrying Origin are refused: the control API is not for browsers",
        );
    }
    if request.shutting_down {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ShuttingDown,
            "shutting down",
        );
    }
    if request.removed {
        tracing::warn!(%peer, "clip body refused: its client was removed");
        let mut response = refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::NotPermitted,
            "the client was removed",
        );
        // RFC 9112 §9.6: the connection serves the removed client nothing
        // else.
        response.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
        return response;
    }
    // RFC 9112 §6.1: no chunked response to a request before HTTP/1.1, and
    // a close-delimited one (§6.3) would end alike whole or cut.
    if request.version != Version::HTTP_11 {
        tracing::warn!(%peer, version = ?request.version, "clip body refused: the request is not HTTP/1.1, so the body could not be chunked");
        return refuse(
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            ErrorCode::InvalidRequest,
            "a clip's bytes are sent in the chunked transfer coding, which needs HTTP/1.1",
        );
    }
    // A clip id never needs percent-encoding (RFC 3986 §2.3), so the raw
    // segment is the id or names no clip; it is never repeated.
    let clip_id = request
        .path
        .strip_prefix(CLIPS_PATH)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|raw| ClipId::new(raw).ok());
    let Some(clip_id) = clip_id else {
        tracing::debug!(%peer, "clip body refused: the path names no clip id");
        return clip_not_found();
    };
    match lookup(&clip_id) {
        Err(ClipBodyError::NotFound) => {
            tracing::debug!(%peer, clip.id = %clip_id, "clip body refused: no open clip has this id");
            clip_not_found()
        }
        Err(ClipBodyError::AlreadyFetched) => {
            tracing::warn!(%peer, clip.id = %clip_id, "clip body refused: another request took it");
            refuse(
                StatusCode::CONFLICT,
                ErrorCode::ClipAlreadyFetched,
                "the clip's bytes were already fetched; a clip has one body",
            )
        }
        Ok(clip) => {
            tracing::info!(%peer, clip.id = %clip_id, "clip body: sending");
            request.body.set(BodyState::Taken);
            let header = clip_id.to_string();
            let body = body_stream(Sending {
                chunks: ReaderStream::with_capacity(clip.reader, CHUNK_BYTES),
                written: clip.written,
                sent: 0,
                clip_id,
                peer: peer.clone(),
                clock: Arc::clone(request.clock),
            });
            (
                [
                    (header::CONTENT_TYPE, "video/mp4"),
                    (header::CACHE_CONTROL, "no-store"),
                    (header::CONNECTION, "close"),
                    (X_CLIP_ID, header.as_str()),
                ],
                Body::from_stream(body),
            )
                .into_response()
        }
    }
}

/// 404 `clip_not_found`.
fn clip_not_found() -> Response {
    refuse(
        StatusCode::NOT_FOUND,
        ErrorCode::ClipNotFound,
        "no open clip has this id",
    )
}

/// One clip's body while it is sent.
struct Sending {
    /// The file's bytes in chunks of up to [`CHUNK_BYTES`].
    chunks: ReaderStream<Box<dyn AsyncRead + Send + Unpin>>,
    /// The producer's report of the bytes it wrote.
    written: oneshot::Receiver<u64>,
    /// The bytes handed to the response so far.
    sent: u64,
    /// The clip, for the logs.
    clip_id: ClipId,
    /// Who takes it, for the logs.
    peer: PeerInfo,
    /// Times the report.
    clock: Arc<dyn Clock>,
}

/// One step of a body: a chunk and the rest, or the error that cuts it.
type Step = (io::Result<Bytes>, Option<Sending>);

/// `sending`'s chunks, ended as [`next_chunk`] decides.
fn body_stream(sending: Sending) -> impl futures_util::Stream<Item = io::Result<Bytes>> {
    futures_util::stream::unfold(Some(sending), next_chunk)
}

/// The next chunk of a body, or its end: `None` ends it whole (the last
/// chunk follows, RFC 9112 §7.1), an error cuts it (RFC 9112 §8).
async fn next_chunk(sending: Option<Sending>) -> Option<Step> {
    let mut sending = sending?;
    match sending.chunks.next().await {
        Some(Ok(chunk)) => {
            let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            sending.sent = sending.sent.saturating_add(len);
            Some((Ok(chunk), Some(sending)))
        }
        Some(Err(err)) => Some(sending.cut(err).await),
        None => sending.finish().await,
    }
}

impl Sending {
    /// The end of the clip's bytes: whole when the producer reports
    /// exactly the bytes sent within [`CLIP_REPORT_TIMEOUT`], else cut.
    async fn finish(mut self) -> Option<Step> {
        let report = self.clock.sleep(CLIP_REPORT_TIMEOUT);
        let written = tokio::select! {
            written = &mut self.written => written.ok(),
            () = report => None,
        };
        match written {
            Some(written) if written == self.sent => {
                tracing::info!(
                    peer = %self.peer,
                    clip.id = %self.clip_id,
                    bytes = self.sent,
                    "clip body: sent whole"
                );
                None
            }
            Some(written) => {
                let message = format!(
                    "the clip reports {written} bytes written, {} arrived",
                    self.sent
                );
                Some(self.cut(io::Error::other(message)).await)
            }
            None => Some(
                self.cut(io::Error::other(
                    "the clip ended without a report of its bytes",
                ))
                .await,
            ),
        }
    }

    /// Cuts the body for `err`: the response ends without its last chunk.
    /// The connection is aborted when the body fails, dropping what it
    /// has not flushed, so the body first yields once: the connection
    /// flushes the chunks before the cut while it waits.
    async fn cut(self, err: io::Error) -> Step {
        tokio::task::yield_now().await;
        tracing::warn!(
            peer = %self.peer,
            clip.id = %self.clip_id,
            bytes = self.sent,
            error = %err,
            "clip body cut: it ends without its last chunk"
        );
        (Err(err), None)
    }
}

/// Drives a connection whose clip body is being sent until it ends, its
/// client makes no room for the body within [`BODY_STALL_TIMEOUT`], its
/// client is `removed`, or [`CLOSE_TIMEOUT`] after shutdown began;
/// dropping it closes the socket.
pub(crate) async fn send_body(
    connection: BoxFuture<'static, hyper::Result<()>>,
    mut body: watch::Receiver<BodyState>,
    clock: &dyn Clock,
    shutdown: &CancellationToken,
    removed: &CancellationToken,
    peer: &PeerInfo,
) {
    tokio::select! {
        sent = connection => {
            tracing::debug!(%peer, error = ?sent.err(), "clip body: connection closed");
        }
        () = removed.cancelled() => {
            tracing::info!(%peer, "clip body dropped: its client was removed");
        }
        () = stalled(&mut body, clock) => {
            let timeout_ms = BODY_STALL_TIMEOUT.as_millis();
            tracing::warn!(%peer, timeout_ms, "clip body dropped: the client made no room for it in time");
        }
        () = closing(shutdown, clock) => {
            let timeout_ms = CLOSE_TIMEOUT.as_millis();
            tracing::warn!(%peer, timeout_ms, "clip body dropped: still being sent when shutdown's close timeout ran out");
        }
    }
}

/// Completes once the socket has refused the response for
/// [`BODY_STALL_TIMEOUT`], taking none of it meanwhile. `body`'s sender
/// must outlive the call.
async fn stalled(body: &mut watch::Receiver<BodyState>, clock: &dyn Clock) {
    loop {
        let state = *body.borrow_and_update();
        let left = match state {
            BodyState::Waiting(since) => {
                BODY_STALL_TIMEOUT.saturating_sub(clock.now().saturating_duration_since(since))
            }
            // The socket starts and ends a wait without a change
            // notification, so that a write costs no wake-up: the loop
            // looks again a stall deadline from now, which is before any
            // wait that starts meanwhile is due. No connection is idle
            // here: its body began before the call.
            BodyState::Idle | BodyState::Taken => BODY_STALL_TIMEOUT,
        };
        if left.is_zero() {
            return;
        }
        // The timer firing ends nothing by itself: the socket may have
        // taken bytes since, which ends the wait without a change
        // notification, and the loop reads it again.
        tokio::select! {
            () = clock.sleep(left) => {}
            _changed = body.changed() => {}
        }
    }
}

/// Completes [`CLOSE_TIMEOUT`] after `shutdown` is cancelled.
async fn closing(shutdown: &CancellationToken, clock: &dyn Clock) {
    shutdown.cancelled().await;
    clock.sleep(CLOSE_TIMEOUT).await;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use axum::http::HeaderValue;
    use lotse_core::clock::FakeClock;
    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::tests::state;

    /// A log writer that keeps every line.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

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
        /// Everything logged so far.
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    /// Captures this thread's log lines at `level` and above until the
    /// guard is dropped.
    fn capture(level: tracing::Level) -> (Captured, tracing::subscriber::DefaultGuard) {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(level)
            .with_ansi(false)
            .finish();
        io::Write::flush(&mut captured.clone()).unwrap();
        (captured, tracing::subscriber::set_default(subscriber))
    }

    fn peer() -> PeerInfo {
        PeerInfo::Unix { uid: 0, pid: None }
    }

    /// A clip whose bytes the test writes and whose report it sends.
    fn new_clip() -> (ClipBody, tokio::io::DuplexStream, oneshot::Sender<u64>) {
        let (reader, writer) = tokio::io::duplex(1024);
        let (report, written) = oneshot::channel();
        let body = ClipBody {
            reader: Box::new(reader),
            written,
        };
        (body, writer, report)
    }

    fn sending(clip: ClipBody, clock: &Arc<FakeClock>) -> Sending {
        Sending {
            chunks: ReaderStream::with_capacity(clip.reader, CHUNK_BYTES),
            written: clip.written,
            sent: 0,
            clip_id: ClipId::new("c1").unwrap(),
            peer: peer(),
            clock: Arc::<FakeClock>::clone(clock),
        }
    }

    /// `answer` for an HTTP/1.1 request to `path` with `headers` from a
    /// client not removed, the clip from `lookup`.
    fn answer_to(
        path: &str,
        headers: &HeaderMap,
        shutting_down: bool,
        body: &BodyWatch,
        lookup: &dyn Fn(&ClipId) -> Result<ClipBody, ClipBodyError>,
    ) -> Response {
        answer_as(
            (false, Version::HTTP_11),
            path,
            shutting_down,
            body,
            lookup,
            headers,
        )
    }

    /// `answer` for a request in `version` to `path`, from a client
    /// `removed` or not.
    fn answer_as(
        (removed, version): (bool, Version),
        path: &str,
        shutting_down: bool,
        body: &BodyWatch,
        lookup: &dyn Fn(&ClipId) -> Result<ClipBody, ClipBodyError>,
        headers: &HeaderMap,
    ) -> Response {
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::default());
        let peer = peer();
        let request = Request {
            peer: &peer,
            removed,
            version,
            headers,
            path,
            shutting_down,
            body,
            clock: &clock,
        };
        answer(&request, lookup)
    }

    async fn status_and_code(response: Response) -> (u16, serde_json::Value) {
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let code = serde_json::from_slice::<serde_json::Value>(&body)
            .map_or(serde_json::Value::Null, |error| error["code"].clone());
        (status, code)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_15_5_a_request_that_names_no_clip_it_may_take_is_refused_with_the_error_body()
    {
        let (logs, _guard) = capture(tracing::Level::DEBUG);
        let body = BodyWatch::new();
        let none = HeaderMap::new();
        let asked = std::cell::Cell::new(0);
        let gone = |_: &ClipId| {
            asked.set(asked.get() + 1);
            Err(ClipBodyError::NotFound)
        };
        let mut browser = HeaderMap::new();
        browser.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.com"),
        );
        // RFC 6455 §10.2, as the upgrade: a browser's request is refused.
        let refused = answer_to("/v0/clips/c1", &browser, false, &body, &gone);
        assert_eq!(
            status_and_code(refused).await,
            (403, "invalid_request".into())
        );
        let refused = answer_to("/v0/clips/c1", &none, true, &body, &gone);
        assert_eq!(
            status_and_code(refused).await,
            (503, "shutting_down".into())
        );
        // An id no clip can have is not looked up, and never repeated: a
        // dot segment neither (RFC 3986 §3.3), which a URL cannot keep.
        for path in [
            "/v0/clips/a%2Fb",
            "/v0/clips/secret secret",
            "/v0/clips",
            "/v0/clips/.",
            "/v0/clips/..",
        ] {
            let refused = answer_to(path, &none, false, &body, &gone);
            assert_eq!(
                status_and_code(refused).await,
                (404, "clip_not_found".into()),
                "{path}"
            );
        }
        assert_eq!(asked.get(), 0, "none of them was looked up");
        let refused = answer_to("/v0/clips/c1", &none, false, &body, &gone);
        assert_eq!(
            status_and_code(refused).await,
            (404, "clip_not_found".into())
        );
        assert_eq!(asked.get(), 1);
        let taken = |_: &ClipId| Err(ClipBodyError::AlreadyFetched);
        let refused = answer_to("/v0/clips/c1", &none, false, &body, &taken);
        assert_eq!(
            status_and_code(refused).await,
            (409, "clip_already_fetched".into())
        );
        assert_eq!(*body.subscribe().borrow(), BodyState::Idle, "nothing sent");
        let text = logs.text();
        assert!(
            text.contains("clip body refused: the request carries Origin"),
            "{text}"
        );
        assert!(
            text.contains("clip body refused: the path names no clip id"),
            "{text}"
        );
        assert!(
            text.contains("clip body refused: no open clip has this id"),
            "{text}"
        );
        assert!(
            text.contains("clip body refused: another request took it"),
            "{text}"
        );
        assert!(!text.contains("secret"), "{text}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9110_15_3_1_a_clip_is_answered_200_as_an_uncached_mp4_on_a_closing_connection() {
        let (logs, _guard) = capture(tracing::Level::INFO);
        let body = BodyWatch::new();
        let asked = std::sync::Mutex::new(None);
        let (clip, mut writer, report) = new_clip();
        let clip = std::sync::Mutex::new(Some(clip));
        let lookup = |id: &ClipId| {
            *asked.lock().unwrap() = Some(id.clone());
            Ok(clip.lock().unwrap().take().unwrap())
        };
        let response = answer_to(
            "/v0/clips/01JB.c-1_x",
            &HeaderMap::new(),
            false,
            &body,
            &lookup,
        );
        assert_eq!(
            asked.lock().unwrap().as_ref().unwrap().as_str(),
            "01JB.c-1_x"
        );
        assert_eq!(response.status().as_u16(), 200);
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "video/mp4");
        // RFC 9111 §5.2.2.5: never stored; RFC 9112 §9.6: the connection
        // ends with the body.
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::CONNECTION], "close");
        assert_eq!(headers["x-clip-id"], "01JB.c-1_x");
        assert!(
            headers.get(header::CONTENT_LENGTH).is_none(),
            "its length is not known"
        );
        assert_eq!(*body.subscribe().borrow(), BodyState::Taken);
        writer.write_all(b"ftyp").await.unwrap();
        drop(writer);
        report.send(4).unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"ftyp");
        let text = logs.text();
        assert!(text.contains("clip body: sending"), "{text}");
        assert!(text.contains("clip body: sent whole"), "{text}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_removed_client_or_a_request_before_http_1_1_is_refused_before_the_clip_is_taken() {
        let (logs, _guard) = capture(tracing::Level::WARN);
        let body = BodyWatch::new();
        let none = HeaderMap::new();
        let asked = std::cell::Cell::new(0);
        let lookup = |_: &ClipId| {
            asked.set(asked.get() + 1);
            Err(ClipBodyError::NotFound)
        };
        // RFC 9110 §15.5.4: its client was removed since its handshake; the
        // connection closes with the answer (RFC 9112 §9.6).
        let refused = answer_as(
            (true, Version::HTTP_11),
            "/v0/clips/c1",
            false,
            &body,
            &lookup,
            &none,
        );
        assert_eq!(refused.headers()[header::CONNECTION], "close");
        assert_eq!(
            status_and_code(refused).await,
            (403, "not_permitted".into())
        );
        // RFC 9110 §15.6.6, RFC 9112 §6.1: no chunked body before HTTP/1.1.
        for version in [Version::HTTP_10, Version::HTTP_09] {
            let refused = answer_as(
                (false, version),
                "/v0/clips/c1",
                false,
                &body,
                &lookup,
                &none,
            );
            assert_eq!(
                status_and_code(refused).await,
                (505, "invalid_request".into()),
                "{version:?}"
            );
        }
        assert_eq!(asked.get(), 0, "none of them was looked up");
        assert_eq!(*body.subscribe().borrow(), BodyState::Idle, "nothing sent");
        // The same request in HTTP/1.1 from a client still allowed is.
        let looked_up = answer_as(
            (false, Version::HTTP_11),
            "/v0/clips/c1",
            false,
            &body,
            &lookup,
            &none,
        );
        assert_eq!(
            status_and_code(looked_up).await,
            (404, "clip_not_found".into())
        );
        assert_eq!(asked.get(), 1);
        let text = logs.text();
        assert!(
            text.contains("clip body refused: its client was removed"),
            "{text}"
        );
        assert!(
            text.contains("clip body refused: the request is not HTTP/1.1"),
            "{text}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_7_a_body_reads_up_to_a_pipes_capacity_at_once() {
        let clock = Arc::new(FakeClock::default());
        let (reader, mut writer) = tokio::io::duplex(256 * 1024);
        let (_report, written) = oneshot::channel();
        let clip = ClipBody {
            reader: Box::new(reader),
            written,
        };
        let mut body = Box::pin(body_stream(sending(clip, &clock)));
        writer.write_all(&vec![1_u8; 3 * 64 * 1024]).await.unwrap();
        assert_eq!(body.next().await.unwrap().unwrap().len(), 64 * 1024);
    }

    #[tokio::test]
    async fn rfc9110_15_5_6_any_other_method_is_answered_405_with_allow_get() {
        let response = not_allowed().await;
        assert_eq!(response.headers()[header::ALLOW], "GET");
        assert_eq!(
            status_and_code(response).await,
            (405, "invalid_request".into())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_route_takes_the_clip_from_the_handler_by_the_paths_id() {
        let state = state(1, false);
        let response = fetch(
            State(state),
            Extension(peer()),
            Extension(BodyWatch::new()),
            Version::HTTP_11,
            HeaderMap::new(),
            Uri::from_static("/v0/clips/c1"),
        )
        .await;
        // The default handler has no clips.
        assert_eq!(
            status_and_code(response).await,
            (404, "clip_not_found".into())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9112_7_1_a_body_reported_whole_ends_after_its_chunks() {
        let clock = Arc::new(FakeClock::default());
        let (clip, mut writer, report) = new_clip();
        let mut body = Box::pin(body_stream(sending(clip, &clock)));
        writer.write_all(b"moov").await.unwrap();
        assert_eq!(&body.next().await.unwrap().unwrap()[..], b"moov");
        writer.write_all(b"moof").await.unwrap();
        drop(writer);
        assert_eq!(&body.next().await.unwrap().unwrap()[..], b"moof");
        // The reader ends and the report agrees, so the body ends whole.
        report.send(8).unwrap();
        assert!(body.next().await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9112_8_a_body_whose_report_disagrees_or_never_comes_is_cut() {
        let (logs, _guard) = capture(tracing::Level::WARN);
        let clock = Arc::new(FakeClock::default());
        // Fewer bytes arrived than the producer wrote.
        let (clip, mut writer, report) = new_clip();
        let mut body = Box::pin(body_stream(sending(clip, &clock)));
        writer.write_all(b"ab").await.unwrap();
        drop(writer);
        report.send(3).unwrap();
        assert_eq!(body.next().await.unwrap().unwrap().len(), 2);
        let err = body.next().await.unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            "the clip reports 3 bytes written, 2 arrived"
        );
        assert!(body.next().await.is_none());
        // The producer died: its report never comes.
        let (clip, writer, report) = new_clip();
        let mut body = Box::pin(body_stream(sending(clip, &clock)));
        drop((writer, report));
        let err = body.next().await.unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            "the clip ended without a report of its bytes"
        );
        // The producer is alive and silent: the report's deadline.
        let (clip, writer, report) = new_clip();
        let mut body = Box::pin(body_stream(sending(clip, &clock)));
        drop(writer);
        let end = lotse_core::task::spawn_named("test.end", async move { body.next().await });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(CLIP_REPORT_TIMEOUT);
        let err = end.await.unwrap().unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            "the clip ended without a report of its bytes"
        );
        drop(report);
        let text = logs.text();
        assert_eq!(
            text.matches("clip body cut: it ends without its last chunk")
                .count(),
            3,
            "{text}"
        );
    }

    /// A reader that fails.
    struct Failing;

    impl AsyncRead for Failing {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("pipe broke")))
        }
    }

    #[tokio::test]
    async fn rfc9112_8_a_body_whose_reader_fails_is_cut() {
        let clock = Arc::new(FakeClock::default());
        let (_report, written) = oneshot::channel();
        let clip = ClipBody {
            reader: Box::new(Failing),
            written,
        };
        assert_eq!(format!("{clip:?}"), "ClipBody { .. }");
        let mut body = Box::pin(body_stream(sending(clip, &clock)));
        assert_eq!(
            body.next().await.unwrap().unwrap_err().to_string(),
            "pipe broke"
        );
        assert!(body.next().await.is_none());
    }

    /// `send_body` over a stand-in connection that ends when `end` sends,
    /// with the watch it reads, for a client never removed.
    fn sent_body(
        clock: &Arc<FakeClock>,
        shutdown: &CancellationToken,
    ) -> (BodyWatch, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        sent_body_of(clock, shutdown, &CancellationToken::new())
    }

    /// `send_body` as [`sent_body`], for a client `removed` once cancelled.
    fn sent_body_of(
        clock: &Arc<FakeClock>,
        shutdown: &CancellationToken,
        removed: &CancellationToken,
    ) -> (BodyWatch, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let watch = BodyWatch::new();
        let (end, ended) = oneshot::channel::<()>();
        let connection: BoxFuture<'static, hyper::Result<()>> = Box::pin(async move {
            let _ended = ended.await;
            Ok(())
        });
        let states = watch.subscribe();
        let clock = Arc::<FakeClock>::clone(clock);
        let shutdown = shutdown.clone();
        let removed = removed.clone();
        let task = lotse_core::task::spawn_named("test.body", async move {
            send_body(
                connection,
                states,
                clock.as_ref(),
                &shutdown,
                &removed,
                &peer(),
            )
            .await;
        });
        (watch, end, task)
    }

    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_the_client_keeps_taking_lives_until_its_connection_ends() {
        let (logs, _guard) = capture(tracing::Level::DEBUG);
        let clock = Arc::new(FakeClock::default());
        let (watch, end, task) = sent_body(&clock, &CancellationToken::new());
        watch.set(BodyState::Taken);
        settle().await;
        // Waiting on the clip is no stall, however long.
        clock.advance(BODY_STALL_TIMEOUT * 3);
        settle().await;
        // A chunk taken just before its deadline restarts nothing.
        watch.set(BodyState::Waiting(clock.now()));
        settle().await;
        clock.advance(BODY_STALL_TIMEOUT.saturating_sub(Duration::from_millis(1)));
        settle().await;
        watch.set(BodyState::Taken);
        settle().await;
        clock.advance(Duration::from_secs(1));
        settle().await;
        assert!(!task.is_finished());
        end.send(()).unwrap();
        task.await.unwrap();
        let text = logs.text();
        assert!(text.contains("clip body: connection closed"), "{text}");
        assert!(!text.contains("clip body dropped"), "{text}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_the_client_makes_no_room_for_is_dropped_at_the_stall_deadline() {
        let (logs, _guard) = capture(tracing::Level::WARN);
        let clock = Arc::new(FakeClock::default());
        let (watch, _end, task) = sent_body(&clock, &CancellationToken::new());
        // Handed over a second before the watch is read: the deadline
        // counts from the hand-over.
        watch.set(BodyState::Waiting(clock.now()));
        clock.advance(Duration::from_secs(1));
        settle().await;
        clock.advance(BODY_STALL_TIMEOUT.saturating_sub(Duration::from_secs(1)));
        task.await.unwrap();
        let text = logs.text();
        assert!(
            text.contains("clip body dropped: the client made no room for it in time"),
            "{text}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_still_sent_at_shutdown_gets_the_close_timeout() {
        let (logs, _guard): (Captured, _) = capture(tracing::Level::WARN);
        let clock = Arc::new(FakeClock::default());
        let shutdown = CancellationToken::new();
        let (watch, _end, task) = sent_body(&clock, &shutdown);
        watch.set(BodyState::Taken);
        shutdown.cancel();
        settle().await;
        clock.advance(CLOSE_TIMEOUT.saturating_sub(Duration::from_millis(1)));
        settle().await;
        assert!(!task.is_finished(), "the clip may still end whole");
        clock.advance(Duration::from_millis(1));
        task.await.unwrap();
        let text = logs.text();
        assert!(
            text.contains(
                "clip body dropped: still being sent when shutdown's close timeout ran out"
            ),
            "{text}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_whose_client_is_removed_is_dropped_at_once() {
        let (logs, _guard) = capture(tracing::Level::INFO);
        let clock = Arc::new(FakeClock::default());
        let removed = CancellationToken::new();
        let (watch, _end, task) = sent_body_of(&clock, &CancellationToken::new(), &removed);
        watch.set(BodyState::Taken);
        settle().await;
        assert!(!task.is_finished());
        // On no clock: the removal alone ends it.
        removed.cancel();
        task.await.unwrap();
        let text = logs.text();
        assert!(
            text.contains("clip body dropped: its client was removed"),
            "{text}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_wait_the_socket_ends_restarts_at_its_next_refusal_and_is_dropped_a_stall_deadline_after_it()
     {
        let (logs, _guard) = capture(tracing::Level::WARN);
        let clock = Arc::new(FakeClock::default());
        let (watch, _end, task) = sent_body(&clock, &CancellationToken::new());
        watch.set(BodyState::Waiting(clock.now()));
        settle().await;
        clock.advance(BODY_STALL_TIMEOUT.saturating_sub(Duration::from_secs(1)));
        settle().await;
        // A second before the deadline the socket takes bytes and refuses
        // the next write: nobody is woken, and the timer that fires at the
        // old deadline finds the new wait.
        watch.progressed();
        assert_eq!(*watch.subscribe().borrow(), BodyState::Taken);
        watch.refused(clock.as_ref());
        assert_eq!(*watch.subscribe().borrow(), BodyState::Waiting(clock.now()));
        settle().await;
        clock.advance(Duration::from_secs(1));
        settle().await;
        assert!(!task.is_finished(), "the old deadline passed");
        clock.advance(
            BODY_STALL_TIMEOUT.saturating_sub(Duration::from_secs(1) + Duration::from_millis(1)),
        );
        settle().await;
        assert!(!task.is_finished(), "a millisecond before the new one");
        clock.advance(Duration::from_millis(1));
        task.await.unwrap();
        let text = logs.text();
        assert!(
            text.contains("clip body dropped: the client made no room for it in time"),
            "{text}"
        );
    }

    /// The body waits for more of the clip when the socket starts
    /// refusing the response, and nothing tells the stall timer.
    #[tokio::test(flavor = "current_thread")]
    async fn a_wait_that_begins_while_the_body_waits_for_the_clip_is_dropped_a_stall_deadline_after_it()
     {
        let (logs, _guard) = capture(tracing::Level::WARN);
        let clock = Arc::new(FakeClock::default());
        let (watch, _end, task) = sent_body(&clock, &CancellationToken::new());
        watch.set(BodyState::Taken);
        settle().await;
        clock.advance(Duration::from_secs(4));
        watch.refused(clock.as_ref());
        settle().await;
        // The timer looks again a stall deadline after it found the body
        // taken, and finds the wait.
        clock.advance(BODY_STALL_TIMEOUT.saturating_sub(Duration::from_secs(4)));
        settle().await;
        assert!(!task.is_finished(), "the wait is 6 s old");
        clock.advance(Duration::from_secs(4).saturating_sub(Duration::from_millis(1)));
        settle().await;
        assert!(!task.is_finished(), "a millisecond before its deadline");
        clock.advance(Duration::from_millis(1));
        settle().await;
        assert!(task.is_finished(), "dropped at the wait's deadline");
        task.await.unwrap();
        let text = logs.text();
        assert!(
            text.contains("clip body dropped: the client made no room for it in time"),
            "{text}"
        );
    }

    #[test]
    fn the_socket_starts_a_wait_only_for_a_body_and_ends_it_with_progress() {
        let clock = FakeClock::default();
        let watch = BodyWatch::new();
        let mut states = watch.subscribe();
        // A connection without a clip body has nothing to wait for.
        watch.refused(&clock);
        assert_eq!(*states.borrow(), BodyState::Idle);
        watch.progressed();
        assert_eq!(*states.borrow(), BodyState::Idle);
        watch.set(BodyState::Taken);
        states.borrow_and_update();
        watch.progressed();
        assert_eq!(*states.borrow(), BodyState::Taken);
        let refused = clock.now();
        watch.refused(&clock);
        assert_eq!(*states.borrow(), BodyState::Waiting(refused));
        // The wait counts from the first refusal.
        clock.advance(Duration::from_secs(3));
        watch.refused(&clock);
        assert_eq!(*states.borrow(), BodyState::Waiting(refused));
        watch.progressed();
        assert_eq!(*states.borrow(), BodyState::Taken);
        assert!(!states.has_changed().unwrap(), "no one is woken");
    }

    /// A socket that writes one byte at a time and never vectored, and
    /// fails its flush and its shutdown, so a test sees they were asked.
    struct Plain;

    impl AsyncRead for Plain {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Plain {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len().min(1)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("flushed")))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("shut down")))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_socket_starts_a_wait_with_each_write_it_refuses_and_ends_it_with_each_it_takes() {
        use futures_util::FutureExt as _;
        use tokio::io::AsyncReadExt as _;

        let clock = Arc::new(FakeClock::default());
        let watch = BodyWatch::new();
        let states = watch.subscribe();
        let (mut peer, io) = tokio::io::duplex(4);
        let mut socket = Watched::new(Box::new(io), watch.clone(), Arc::<FakeClock>::clone(&clock));
        assert!(socket.is_write_vectored(), "as the socket is");
        watch.set(BodyState::Taken);
        assert_eq!(socket.write(b"ab").await.unwrap(), 2);
        assert_eq!(*states.borrow(), BodyState::Taken);
        let bufs = [io::IoSlice::new(b"c"), io::IoSlice::new(b"d")];
        assert_eq!(socket.write_vectored(&bufs).await.unwrap(), 2);
        // Full: a write refused starts the wait.
        let full = clock.now();
        assert!(socket.write(b"e").now_or_never().is_none());
        assert_eq!(*states.borrow(), BodyState::Waiting(full));
        clock.advance(Duration::from_secs(1));
        let bufs = [io::IoSlice::new(b"e")];
        assert!(socket.write_vectored(&bufs).now_or_never().is_none());
        assert_eq!(*states.borrow(), BodyState::Waiting(full));
        // A write that takes nothing is neither.
        assert_eq!(socket.write(&[]).await.unwrap(), 0);
        assert_eq!(*states.borrow(), BodyState::Waiting(full));
        let mut taken = [0_u8; 4];
        peer.read_exact(&mut taken[..1]).await.unwrap();
        // Room again: a vectored write that takes bytes ends the wait, and
        // so does a plain one.
        assert_eq!(socket.write_vectored(&bufs).await.unwrap(), 1);
        assert_eq!(*states.borrow(), BodyState::Taken);
        assert!(socket.write(b"f").now_or_never().is_none());
        assert_eq!(*states.borrow(), BodyState::Waiting(clock.now()));
        peer.read_exact(&mut taken[1..2]).await.unwrap();
        assert_eq!(socket.write(b"f").await.unwrap(), 1);
        assert_eq!(*states.borrow(), BodyState::Taken);
        socket.flush().await.unwrap();
        peer.read_exact(&mut taken).await.unwrap();
        assert_eq!(&taken, b"cdef");
        // Reads pass through.
        peer.write_all(b"GET").await.unwrap();
        let mut read = [0_u8; 3];
        socket.read_exact(&mut read).await.unwrap();
        assert_eq!(&read, b"GET");
        // A socket that does not write vectored is not made to, and its
        // flush and shutdown are its own.
        let mut plain = Watched::new(Box::new(Plain), watch, clock);
        assert!(!plain.is_write_vectored());
        assert_eq!(plain.write(b"xy").await.unwrap(), 1);
        assert_eq!(plain.read(&mut taken).await.unwrap(), 0);
        assert_eq!(plain.flush().await.unwrap_err().to_string(), "flushed");
        assert_eq!(plain.shutdown().await.unwrap_err().to_string(), "shut down");
        // The end passes through.
        socket.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut taken).await.unwrap(), 0);
    }

    #[test]
    fn only_a_connection_without_a_clip_body_is_idle() {
        assert!(!BodyState::Idle.is_sending());
        assert!(BodyState::Taken.is_sending());
        assert!(BodyState::Waiting(FakeClock::default().now()).is_sending());
        assert_eq!(
            ClipBodyError::AlreadyFetched.to_string(),
            "the clip's body was already fetched"
        );
        assert_eq!(
            ClipBodyError::NotFound.to_string(),
            "no open clip has this id"
        );
    }
}
