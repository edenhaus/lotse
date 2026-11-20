//! `GET /v0/live/{live_id}`: a live output's bytes as one HTTP response
//! body, on either listener, through the same `Extension(peer)` path as the
//! upgrade and the recordings' bodies.
//!
//! The handler hands each live output over once ([`Handler::live_body`]): a
//! reader of the bytes its worker writes, and their MIME type. The body is
//! sent in the chunked transfer coding (RFC 9112 §7.1), since it runs as
//! long as the output does, and ends with its last chunk when the reader
//! ends: the output ended, and the control connection's `closed` says why.
//! A read that fails cuts it (RFC 9112 §8). The response carries
//! `Connection: close` (RFC 9112 §9.6) and `Cache-Control: no-store` (RFC
//! 9111 §5.2.2.5), and its `Content-Type` is the output's MIME type with its
//! `codecs` (RFC 6381).
//!
//! Once its response begins the connection is bounded as a recording's body
//! is ([`crate::recording`]): a client that takes none of it for
//! [`BODY_STALL_TIMEOUT`] is dropped, so is one still sending
//! [`CLOSE_TIMEOUT`] after shutdown began, and one whose TLS client is
//! removed. A client that stops reading costs the output frames up to the
//! next keyframe first, where the worker drops them; the stall bounds a
//! client that reads nothing at all.
//!
//! Refusals are the recording route's, with the live codes: 403 for a
//! request carrying `Origin` (RFC 6455 §10.2), 503 `shutting_down` (RFC 9110
//! §15.6.4), 403 `not_permitted` for a removed TLS client, 505
//! `invalid_request` for a request not in HTTP/1.1 (RFC 9112 §6.1), 404
//! `live_not_found` (RFC 9110 §15.5.5) for an id that is no open live
//! output's, the path's segment checked against the identifier pattern
//! before any lookup, 409 `live_already_fetched` (RFC 9110 §15.5.10) for a
//! body another request took, and 405 with `Allow: GET` (RFC 9110 §15.5.6)
//! for any other method.
//!
//! [`Handler::live_body`]: crate::Handler::live_body
//! [`BODY_STALL_TIMEOUT`]: crate::BODY_STALL_TIMEOUT
//! [`CLOSE_TIMEOUT`]: crate::CLOSE_TIMEOUT

use std::fmt;
use std::io;
use std::sync::Arc;

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, Version, header};
use axum::response::{IntoResponse as _, Response};
use futures_util::StreamExt as _;
use lotse_api_types::LIVE_PATH;
use lotse_api_types::error::ErrorCode;
use lotse_core::id::LiveId;
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

use crate::connection::refuse;
use crate::listener::PeerInfo;
use crate::recording::{BodyState, BodyWatch, client_removed};
use crate::{AppState, Handler};

/// The most bytes read from a live output at once: a Linux pipe's default
/// capacity (pipe(7)), as for a recording.
const CHUNK_BYTES: usize = 64 * 1024;

/// The response header naming the live output a body belongs to.
const X_LIVE_ID: HeaderName = HeaderName::from_static("x-live-id");

/// The `Content-Type` of a live output whose MIME type is no header value:
/// the container's own type, without the codecs.
const FALLBACK_MIME: &str = "video/mp4";

/// One live output's bytes, as the handler hands them to the one request
/// that takes them.
pub struct LiveBody {
    /// The bytes, until the output ends: the read end of the pipe its
    /// worker writes.
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    /// Their MIME type with its codecs, the `Content-Type`.
    pub mime: String,
}

/// Names the type only: the reader is any byte source.
impl fmt::Debug for LiveBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveBody")
            .field("mime", &self.mime)
            .finish_non_exhaustive()
    }
}

/// Why the handler has no body for a live output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LiveBodyError {
    /// No open live output has the id: answered 404 `live_not_found`.
    #[error("no open live output has this id")]
    NotFound,
    /// Another request took the body: answered 409 `live_already_fetched`.
    #[error("the live output's body was already fetched")]
    AlreadyFetched,
}

/// `GET /v0/live/{live_id}`: the checks, then the output's body from the
/// handler.
pub(crate) async fn fetch<H: Handler>(
    State(state): State<AppState<H>>,
    Extension(peer): Extension<PeerInfo>,
    Extension(body): Extension<BodyWatch>,
    version: Version,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let removed = client_removed(state.clients.as_deref(), &peer);
    let request = Request {
        peer: &peer,
        removed,
        version,
        headers: &headers,
        path: uri.path(),
        shutting_down: state.shutdown.is_cancelled(),
        body: &body,
    };
    let handler = Arc::clone(&state.handler);
    answer(&request, &|live_id| handler.live_body(live_id))
}

/// Any other method on a live output's path, HEAD included: 405 with
/// `Allow: GET` (RFC 9110 §15.5.6), the output untouched.
pub(crate) async fn not_allowed() -> Response {
    let mut response = refuse(
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::InvalidRequest,
        "a live output's bytes are fetched with GET",
    );
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET"));
    response
}

/// A live request as the route sees it, before the handler is asked.
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
    /// The request's path, `/v0/live/{live_id}`.
    path: &'a str,
    /// Whether the daemon is shutting down.
    shutting_down: bool,
    /// The connection's body state.
    body: &'a BodyWatch,
}

/// The id `path` names, `/v0/live/{live_id}`, checked against the
/// identifier pattern: untrusted input, parsed before anything looks it up.
/// A live id never needs percent-encoding (RFC 3986 §2.3), so the raw
/// segment is the id or names no live output.
pub fn live_id_of(path: &str) -> Option<LiveId> {
    path.strip_prefix(LIVE_PATH)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|raw| LiveId::new(raw).ok())
}

/// The answer to `request`, the output taken from `lookup`: not generic
/// over the handler, so every handler's route shares it.
fn answer(
    request: &Request<'_>,
    lookup: &dyn Fn(&LiveId) -> Result<LiveBody, LiveBodyError>,
) -> Response {
    let peer = request.peer;
    if request.headers.contains_key(header::ORIGIN) {
        tracing::warn!(%peer, "live body refused: the request carries Origin, as only a browser sends");
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
        tracing::warn!(%peer, "live body refused: its client was removed");
        let mut response = refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::NotPermitted,
            "the client was removed",
        );
        // RFC 9112 §9.6: the connection serves the removed client nothing
        // else.
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
        return response;
    }
    // RFC 9112 §6.1: no chunked response to a request before HTTP/1.1.
    if request.version != Version::HTTP_11 {
        tracing::warn!(%peer, version = ?request.version, "live body refused: the request is not HTTP/1.1, so the body could not be chunked");
        return refuse(
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            ErrorCode::InvalidRequest,
            "a live output's bytes are sent in the chunked transfer coding, which needs HTTP/1.1",
        );
    }
    let Some(live_id) = live_id_of(request.path) else {
        tracing::debug!(%peer, "live body refused: the path names no live id");
        return live_not_found();
    };
    match lookup(&live_id) {
        Err(LiveBodyError::NotFound) => {
            tracing::debug!(%peer, live.id = %live_id, "live body refused: no open live output has this id");
            live_not_found()
        }
        Err(LiveBodyError::AlreadyFetched) => {
            tracing::warn!(%peer, live.id = %live_id, "live body refused: another request took it");
            refuse(
                StatusCode::CONFLICT,
                ErrorCode::LiveAlreadyFetched,
                "the live output's bytes were already fetched; a live output has one body",
            )
        }
        Ok(live) => {
            tracing::info!(%peer, live.id = %live_id, mime = %live.mime, "live body: sending");
            request.body.set(BodyState::Taken);
            let content_type = HeaderValue::from_str(&live.mime)
                .unwrap_or_else(|_| HeaderValue::from_static(FALLBACK_MIME));
            // A live id is a header value as it is (`LiveId`'s pattern).
            let id_header = HeaderValue::from_str(live_id.as_str()).ok();
            let body = body_stream(Sending {
                chunks: ReaderStream::with_capacity(live.reader, CHUNK_BYTES),
                sent: 0,
                live_id,
                peer: peer.clone(),
            });
            let mut response = Body::from_stream(body).into_response();
            let headers = response.headers_mut();
            headers.insert(header::CONTENT_TYPE, content_type);
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
            headers.extend(id_header.map(|id| (X_LIVE_ID, id)));
            response
        }
    }
}

/// 404 `live_not_found`.
fn live_not_found() -> Response {
    refuse(
        StatusCode::NOT_FOUND,
        ErrorCode::LiveNotFound,
        "no open live output has this id",
    )
}

/// One live output's body while it is sent.
struct Sending {
    /// The bytes in chunks of up to [`CHUNK_BYTES`].
    chunks: ReaderStream<Box<dyn AsyncRead + Send + Unpin>>,
    /// The bytes handed to the response so far.
    sent: u64,
    /// The output, for the logs.
    live_id: LiveId,
    /// Who takes it, for the logs.
    peer: PeerInfo,
}

/// `sending`'s chunks, ended as [`next_chunk`] decides.
fn body_stream(sending: Sending) -> impl futures_util::Stream<Item = io::Result<Bytes>> {
    futures_util::stream::unfold(Some(sending), next_chunk)
}

/// The next chunk of a body, or its end: `None` ends it with its last
/// chunk (RFC 9112 §7.1), an error cuts it (RFC 9112 §8).
async fn next_chunk(sending: Option<Sending>) -> Option<(io::Result<Bytes>, Option<Sending>)> {
    let mut sending = sending?;
    match sending.chunks.next().await {
        Some(Ok(chunk)) => {
            let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            sending.sent = sending.sent.saturating_add(len);
            Some((Ok(chunk), Some(sending)))
        }
        Some(Err(err)) => {
            // As a recording's cut: the connection flushes what it holds
            // before the error aborts it.
            tokio::task::yield_now().await;
            tracing::warn!(
                peer = %sending.peer,
                live.id = %sending.live_id,
                bytes = sending.sent,
                error = %err,
                "live body cut: its read failed"
            );
            Some((Err(err), None))
        }
        None => {
            tracing::info!(
                peer = %sending.peer,
                live.id = %sending.live_id,
                bytes = sending.sent,
                "live body: the output ended"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests;
