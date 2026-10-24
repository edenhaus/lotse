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
//! the client taking the body: a chunk the client makes no room for within
//! [`BODY_STALL_TIMEOUT`] drops the connection, and so does still sending
//! [`CLOSE_TIMEOUT`] after shutdown began. The server waits for it when it
//! stops.
//!
//! Refusals carry the error body of the WebSocket's results: 403 for a
//! request carrying `Origin` (RFC 6455 §10.2, as the upgrade refuses it),
//! 503 `shutting_down` (RFC 9110 §15.6.4), 404 `clip_not_found` (RFC 9110
//! §15.5.5) for an id that is no open clip's, 409 `clip_already_fetched`
//! (RFC 9110 §15.5.10) for a body another request took, and 405 with
//! `Allow: GET` (RFC 9110 §15.5.6) for any other method, HEAD included,
//! which would otherwise take the body.
//!
//! [`Handler::clip_body`]: crate::Handler::clip_body
//! [`CLIP_REPORT_TIMEOUT`]: crate::CLIP_REPORT_TIMEOUT
//! [`BODY_STALL_TIMEOUT`]: crate::BODY_STALL_TIMEOUT

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, StatusCode, Uri, header};
use axum::response::{IntoResponse as _, Response};
use futures_util::StreamExt as _;
use futures_util::future::OptionFuture;
use lotse_api_types::CLIPS_PATH;
use lotse_api_types::error::ErrorCode;
use lotse_core::clock::Clock;
use lotse_core::id::ClipId;
use lotse_core::task::BoxFuture;
use tokio::io::AsyncRead;
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
    /// A clip body is being sent and the client took what it was given:
    /// the body waits for more of the clip.
    Taken,
    /// What the body handed over at this instant waits for the client to
    /// make room for it: a chunk, or the body's end.
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
}

/// `GET /v0/clips/{clip_id}`: the checks, then the clip's body from the
/// handler. The peer was authenticated by its listener.
pub(crate) async fn fetch<H: Handler>(
    State(state): State<AppState<H>>,
    Extension(peer): Extension<PeerInfo>,
    Extension(body): Extension<BodyWatch>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let request = Request {
        peer: &peer,
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
    /// The request's header fields.
    headers: &'a HeaderMap,
    /// The request's path, `/v0/clips/{clip_id}`.
    path: &'a str,
    /// Whether the daemon is shutting down.
    shutting_down: bool,
    /// The connection's body state.
    body: &'a BodyWatch,
    /// Stamps the body's waits.
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
                watch: request.body.clone(),
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
    /// Told when a chunk waits for the client and when it was taken.
    watch: BodyWatch,
    /// Stamps the waits and times the report.
    clock: Arc<dyn Clock>,
}

/// One step of a body: a chunk and the rest, or the error that cuts it.
type Step = (io::Result<Bytes>, Option<Sending>);

/// `sending`'s chunks, ended as [`next_chunk`] decides.
fn body_stream(sending: Sending) -> impl futures_util::Stream<Item = io::Result<Bytes>> {
    futures_util::stream::unfold(Some(sending), next_chunk)
}

/// The next chunk of a body, or its end: `None` ends it whole (the last
/// chunk follows, RFC 9112 §7.1), an error cuts it (RFC 9112 §8). Being
/// asked for a chunk means the client took the one before.
async fn next_chunk(sending: Option<Sending>) -> Option<Step> {
    let mut sending = sending?;
    sending.watch.set(BodyState::Taken);
    match sending.chunks.next().await {
        Some(Ok(chunk)) => {
            let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            sending.sent = sending.sent.saturating_add(len);
            sending.watch.set(BodyState::Waiting(sending.clock.now()));
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
        // The end waits for the client like a chunk.
        self.watch.set(BodyState::Waiting(self.clock.now()));
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
/// client makes no room for the body within [`BODY_STALL_TIMEOUT`], or
/// [`CLOSE_TIMEOUT`] after shutdown began; dropping it closes the socket.
pub(crate) async fn send_body(
    connection: BoxFuture<'static, hyper::Result<()>>,
    mut body: watch::Receiver<BodyState>,
    clock: &dyn Clock,
    shutdown: &CancellationToken,
    peer: &PeerInfo,
) {
    tokio::select! {
        sent = connection => {
            tracing::debug!(%peer, error = ?sent.err(), "clip body: connection closed");
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

/// Completes once what a body handed over has waited
/// [`BODY_STALL_TIMEOUT`] for the client. `body`'s sender must outlive
/// the call.
async fn stalled(body: &mut watch::Receiver<BodyState>, clock: &dyn Clock) {
    loop {
        let state = *body.borrow_and_update();
        let left = match state {
            BodyState::Waiting(since) => Some(
                BODY_STALL_TIMEOUT.saturating_sub(clock.now().saturating_duration_since(since)),
            ),
            BodyState::Idle | BodyState::Taken => None,
        };
        let timer: OptionFuture<_> = left.map(|left| clock.sleep(left)).into();
        tokio::select! {
            Some(()) = timer => return,
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
    use tokio::io::{AsyncWriteExt as _, ReadBuf};

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

    fn sending(clip: ClipBody, watch: &BodyWatch, clock: &Arc<FakeClock>) -> Sending {
        Sending {
            chunks: ReaderStream::with_capacity(clip.reader, CHUNK_BYTES),
            written: clip.written,
            sent: 0,
            clip_id: ClipId::new("c1").unwrap(),
            peer: peer(),
            watch: watch.clone(),
            clock: Arc::<FakeClock>::clone(clock),
        }
    }

    /// `answer` for a request to `path` with `headers`, the clip from
    /// `lookup`.
    fn answer_to(
        path: &str,
        headers: &HeaderMap,
        shutting_down: bool,
        body: &BodyWatch,
        lookup: &dyn Fn(&ClipId) -> Result<ClipBody, ClipBodyError>,
    ) -> Response {
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::default());
        let peer = peer();
        let request = Request {
            peer: &peer,
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
        // An id no clip can have is not looked up, and never repeated.
        for path in ["/v0/clips/a%2Fb", "/v0/clips/secret secret", "/v0/clips"] {
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
    async fn rfc9112_7_1_a_body_reported_whole_ends_after_its_chunks_and_each_waits_for_the_client()
    {
        let clock = Arc::new(FakeClock::default());
        let watch = BodyWatch::new();
        let states = watch.subscribe();
        let (clip, mut writer, report) = new_clip();
        let mut body = Box::pin(body_stream(sending(clip, &watch, &clock)));
        writer.write_all(b"moov").await.unwrap();
        assert_eq!(&body.next().await.unwrap().unwrap()[..], b"moov");
        let handed = clock.now();
        assert_eq!(*states.borrow(), BodyState::Waiting(handed));
        clock.advance(Duration::from_secs(1));
        writer.write_all(b"moof").await.unwrap();
        drop(writer);
        assert_eq!(&body.next().await.unwrap().unwrap()[..], b"moof");
        // Asked again: the client took it; the reader ends and the report
        // agrees, so the body ends whole.
        report.send(8).unwrap();
        assert!(body.next().await.is_none());
        assert_eq!(*states.borrow(), BodyState::Waiting(clock.now()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc9112_8_a_body_whose_report_disagrees_or_never_comes_is_cut() {
        let (logs, _guard) = capture(tracing::Level::WARN);
        let clock = Arc::new(FakeClock::default());
        let watch = BodyWatch::new();
        // Fewer bytes arrived than the producer wrote.
        let (clip, mut writer, report) = new_clip();
        let mut body = Box::pin(body_stream(sending(clip, &watch, &clock)));
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
        let mut body = Box::pin(body_stream(sending(clip, &watch, &clock)));
        drop((writer, report));
        let err = body.next().await.unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            "the clip ended without a report of its bytes"
        );
        // The producer is alive and silent: the report's deadline.
        let (clip, writer, report) = new_clip();
        let mut body = Box::pin(body_stream(sending(clip, &watch, &clock)));
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
        let watch = BodyWatch::new();
        let (_report, written) = oneshot::channel();
        let clip = ClipBody {
            reader: Box::new(Failing),
            written,
        };
        assert_eq!(format!("{clip:?}"), "ClipBody { .. }");
        let mut body = Box::pin(body_stream(sending(clip, &watch, &clock)));
        assert_eq!(
            body.next().await.unwrap().unwrap_err().to_string(),
            "pipe broke"
        );
        assert!(body.next().await.is_none());
    }

    /// `send_body` over a stand-in connection that ends when `end` sends,
    /// with the watch it reads.
    fn sent_body(
        clock: &Arc<FakeClock>,
        shutdown: &CancellationToken,
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
        let task = lotse_core::task::spawn_named("test.body", async move {
            send_body(connection, states, clock.as_ref(), &shutdown, &peer()).await;
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
