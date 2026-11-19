//! `GET /v0/hls/{hls_id}/{name}`: an LL-HLS session's Media Playlist, init
//! segment, Media Segments and Partial Segments
//! (draft-pantos-hls-rfc8216bis-22), on either listener, through the same
//! `Extension(peer)` path as the upgrade and the live outputs' bodies.
//!
//! Everything in the request is untrusted and parsed with bounds before the
//! handler is asked: the session id against the identifier pattern, the
//! name as `index.m3u8` or exactly as the playlist writes a resource
//! ([`Resource::parse`]), and a playlist request's query as its Delivery
//! Directives ([`Blocking::parse`], §6.2.5); a media request's query is
//! ignored (a cache buster). The handler ([`Handler::hls`]) answers from the
//! session's window, and holds a Blocking Playlist Reload (§6.2.5.2) or a
//! request for the part a Preload Hint names (§4.4.5.3) until it can, bounded
//! by its own limits.
//!
//! A response carries its `Content-Length`, so it needs no chunked transfer
//! coding and any HTTP/1.x request is served. Its connection holds the
//! handler's [`InFlight`], a refusal's too, until it ends, after the socket
//! took the last byte through any TLS session, or is dropped: the
//! handler's limits on the requests in flight bound the responses a client
//! takes slowly, and with them the media they keep after the window let it
//! go. A connection whose request the handler holds, or that took places
//! in flight, leaves the pending upgrades and their deadline, as a live
//! output's body does (`crate::live`): a blocked request may wait longer
//! than the upgrade deadline, and requests blocked at once must not take
//! the few places of connections awaiting their upgrade. One refused before
//! it took a place (an unknown session, a request over a limit) stays among
//! them, as a refused live body's does, so the connections are bounded
//! either way. Every response
//! carries `Connection: close` (RFC 9112 §9.6): the connection serves that
//! one request, bounded as a body's connection is, by the client taking the
//! response, shutdown's close timeout and its TLS client staying enrolled.
//! A client keeps several connections open for the requests it holds at
//! once, a playlist reload and a part, as LL-HLS has it (§6.2.5.2).
//!
//! The answers: the playlist `200` in `application/vnd.apple.mpegurl` (§4:
//! "the HTTP Content-Type MUST be "application/vnd.apple.mpegurl"") with
//! `Cache-Control: no-cache` (RFC 9111 §5.2.2.4: it changes with every
//! part); a resource `200` in `video/mp4` (fragmented MPEG-4, §3.1.2) with
//! `Cache-Control: max-age=60` (RFC 9111 §5.2.2.1): a name never names
//! other bytes within a session, whose id is never reused. Refusals carry
//! the error body of the WebSocket's results: 403 for a request carrying
//! `Origin` (RFC 6455 §10.2), 503 `shutting_down` (RFC 9110 §15.6.4), 403
//! `not_permitted` for a removed TLS client on a connection that then
//! closes, 404 `hls_not_found` (RFC 9110 §15.5.5) for an id that is no open
//! session's, 404 `hls_resource_not_found` for a name the window neither
//! holds nor hints (§6.2.6: "SHOULD respond with "Not Found""), 400
//! `invalid_request` for a malformed directive or one asking too far ahead
//! (§6.2.5.2: "MUST return Bad Request, such as HTTP 400"), 429
//! `limit_reached` (RFC 6585 §4) for a request over the limits on requests
//! in flight or a blocking one over the blocked requests' limits, 503
//! `source_timeout` for one not answered within three
//! Target Durations (§6.2.5.2: "SHOULD return Service Unavailable, such as
//! HTTP 503"), and 405 with `Allow: GET` (RFC 9110 §15.5.6) for any other
//! method.
//!
//! [`Handler::hls`]: crate::Handler::hls

use std::convert::Infallible;

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse as _, Response};
use futures_util::FutureExt as _;
use lotse_api_types::HLS_PATH;
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::hls::PLAYLIST_NAME;
use lotse_core::id::HlsId;
use lotse_hls::{Blocking, Chunks, DirectiveError, Resource};
use tokio::sync::OwnedSemaphorePermit;

use crate::connection::refuse;
use crate::listener::PeerInfo;
use crate::recording::{BodyState, BodyWatch, client_removed};
use crate::{AppState, Handler};

/// The Media Playlist's media type (draft-pantos-hls-rfc8216bis-22 §4).
pub const PLAYLIST_MIME: &str = "application/vnd.apple.mpegurl";

/// The init segment's, a Media Segment's and a Partial Segment's media
/// type: each is fragmented MPEG-4 (draft-pantos-hls-rfc8216bis-22 §3.1.2).
pub const MEDIA_MIME: &str = "video/mp4";

/// `Cache-Control` of the playlist, which changes with every part: stored
/// only to be validated (RFC 9111 §5.2.2.4).
const PLAYLIST_CACHE: &str = "no-cache";

/// `Cache-Control` of a resource, whose name never names other bytes within
/// its session: a minute (RFC 9111 §5.2.2.1), longer than the window serves
/// one with the default limits.
const MEDIA_CACHE: &str = "max-age=60";

/// What a request asks of a session, parsed: the playlist, once it holds
/// what the directives ask for, or one resource of the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HlsRequest {
    /// `index.m3u8`, with its Delivery Directives
    /// (draft-pantos-hls-rfc8216bis-22 §6.2.5.2).
    Playlist(Blocking),
    /// The init segment, a Media Segment or a Partial Segment.
    Media(Resource),
}

/// What the handler answers a request with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HlsReply {
    /// The Media Playlist's text.
    Playlist(String),
    /// A resource's bytes, as the window holds them.
    Media(Chunks),
}

/// What a request's response holds until its connection ends, its last
/// byte taken by the socket or the connection dropped: the handler's
/// places among the requests in flight, so a client taking a response
/// slowly keeps its place, and a limit on them bounds the connections and
/// the bytes the responses hold.
#[derive(Debug, Default)]
pub struct InFlight {
    /// The places, given back as they are dropped.
    permits: Vec<OwnedSemaphorePermit>,
}

impl InFlight {
    /// Holds `permits` until the response's connection ends.
    #[must_use]
    pub const fn new(permits: Vec<OwnedSemaphorePermit>) -> Self {
        Self { permits }
    }

    /// Whether it holds no place: the request took none, as one refused
    /// before it did.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.permits.is_empty()
    }
}

/// The handler's answer to an LL-HLS request: the reply or the refusal,
/// each with the places among the requests in flight the request took,
/// which its connection holds until it ends, a refusal's too, so a client
/// that takes neither slowly keeps within the limits on them.
pub type HlsAnswer = Result<(HlsReply, InFlight), (HlsError, InFlight)>;

/// Why the handler answers a request with no playlist or resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HlsError {
    /// No open session has the id: 404 `hls_not_found`. Also the answer to a
    /// request whose session ended while it was blocked.
    #[error("no open LL-HLS session has this id")]
    NotFound,
    /// The window neither holds nor hints the resource: 404
    /// `hls_resource_not_found` (draft-pantos-hls-rfc8216bis-22 §6.2.6).
    #[error("the session's window holds no such resource")]
    ResourceNotFound,
    /// The directives ask for a segment or part too far ahead: 400
    /// `invalid_request` (§6.2.5.2).
    #[error("the request asks for a segment or part too far ahead")]
    BadRequest,
    /// The request would block past a limit on blocked requests, which it
    /// names: 429 `limit_reached` (RFC 6585 §4).
    #[error("too many blocked requests ({limit})")]
    TooManyBlocked {
        /// The limit: `max_hls_blocked_per_session` or `max_hls_blocked`.
        limit: &'static str,
    },
    /// The request would be in flight past a limit on requests in flight,
    /// which it names: 429 `limit_reached` (RFC 6585 §4).
    #[error("too many requests in flight ({limit})")]
    TooManyRequests {
        /// The limit: `max_hls_requests_per_session` or `max_hls_requests`.
        limit: &'static str,
    },
    /// The request blocked for three Target Durations without what it waits
    /// for: 503 `source_timeout` (§6.2.5.2).
    #[error("nothing to answer within three Target Durations")]
    Timeout,
}

/// `GET /v0/hls/{hls_id}/{name}`: the checks, then the handler's answer.
pub(crate) async fn fetch<H: Handler>(
    State(state): State<AppState<H>>,
    Extension(peer): Extension<PeerInfo>,
    Extension(body): Extension<BodyWatch>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let request = Request {
        peer: &peer,
        removed: client_removed(state.clients.as_deref(), &peer),
        headers: &headers,
        path: uri.path(),
        query: uri.query().unwrap_or_default(),
        shutting_down: state.shutdown.is_cancelled(),
    };
    let (hls_id, asked) = match admit(&request) {
        Ok(admitted) => admitted,
        Err(refused) => return *refused,
    };
    let mut answering = std::pin::pin!(state.handler.hls(&hls_id, asked));
    // A request the handler holds leaves the pending upgrades: see the
    // module docs. One answered at once leaves them only for the places it
    // took ([`reply`]).
    let answer = if let Some(answer) = (&mut answering).now_or_never() {
        answer
    } else {
        body.set(BodyState::Taken);
        answering.await
    };
    reply(&peer, &hls_id, answer, &body)
}

/// Any other method on a session's path, HEAD included: 405 with
/// `Allow: GET` (RFC 9110 §15.5.6).
pub(crate) async fn not_allowed() -> Response {
    let mut response = refuse(
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::InvalidRequest,
        "an LL-HLS session's resources are fetched with GET",
    );
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET"));
    response
}

/// An LL-HLS request as the route sees it, before the handler is asked.
struct Request<'a> {
    /// Who asks.
    peer: &'a PeerInfo,
    /// Whether the TLS listener's client that asks was removed since its
    /// handshake.
    removed: bool,
    /// The request's header fields.
    headers: &'a HeaderMap,
    /// The request's path, `/v0/hls/{hls_id}/{name}`.
    path: &'a str,
    /// The request's query, empty without one.
    query: &'a str,
    /// Whether the daemon is shutting down.
    shutting_down: bool,
}

/// Why a path or query names nothing a session serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HlsPathError {
    /// The path names no session id: 404 `hls_not_found`.
    Session,
    /// The name is neither the playlist nor a resource the playlist writes:
    /// 404 `hls_resource_not_found`.
    Resource,
    /// A playlist request's Delivery Directives are malformed: 400
    /// `invalid_request` (draft-pantos-hls-rfc8216bis-22 §6.2.5.2).
    Directive(DirectiveError),
}

/// The session and request `path` and `query` name,
/// `/v0/hls/{hls_id}/{name}`, each part checked: untrusted input, parsed
/// before anything looks it up. A session id never needs percent-encoding
/// (RFC 3986 §2.3) nor does a name the playlist writes, so the raw segments
/// are what they name or name nothing. A media request's query is ignored.
pub fn hls_request_of(path: &str, query: &str) -> Result<(HlsId, HlsRequest), HlsPathError> {
    let (raw_id, name) = path
        .strip_prefix(HLS_PATH)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.split_once('/'))
        .ok_or(HlsPathError::Session)?;
    let hls_id = HlsId::new(raw_id).map_err(|_| HlsPathError::Session)?;
    let request = if name == PLAYLIST_NAME {
        HlsRequest::Playlist(Blocking::parse(query).map_err(HlsPathError::Directive)?)
    } else {
        HlsRequest::Media(Resource::parse(name).ok_or(HlsPathError::Resource)?)
    };
    Ok((hls_id, request))
}

/// The session and request `request` asks for, or the refusal it gets: not
/// generic over the handler, so every handler's route shares it.
fn admit(request: &Request<'_>) -> Result<(HlsId, HlsRequest), Box<Response>> {
    let peer = request.peer;
    if request.headers.contains_key(header::ORIGIN) {
        tracing::warn!(%peer, "LL-HLS request refused: the request carries Origin, as only a browser sends");
        return Err(Box::new(refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest,
            "requests carrying Origin are refused: the control API is not for browsers",
        )));
    }
    if request.shutting_down {
        return Err(Box::new(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ShuttingDown,
            "shutting down",
        )));
    }
    if request.removed {
        tracing::warn!(%peer, "LL-HLS request refused: its client was removed");
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
        return Err(Box::new(response));
    }
    hls_request_of(request.path, request.query).map_err(|error| {
        Box::new(match error {
        HlsPathError::Session => {
            tracing::debug!(%peer, "LL-HLS request refused: the path names no session id");
            hls_not_found()
        }
        HlsPathError::Resource => {
            tracing::debug!(%peer, "LL-HLS request refused: the name is no resource's");
            resource_not_found()
        }
        HlsPathError::Directive(error) => {
            tracing::debug!(%peer, %error, "LL-HLS request refused: a malformed delivery directive");
            refuse(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidRequest,
                &error.to_string(),
            )
        }
        })
    })
}

/// The response to the handler's `answer` for session `hls_id`; every one
/// closes its connection (see the module docs). A connection, whose `body`
/// watch this is, that took places among the requests in flight, its
/// answer's [`InFlight`], leaves the pending upgrades and holds them until
/// it ends, a refusal's as a `200`'s: hyper hands the last of a response to
/// a TLS session before the socket has taken it, and the session holds it,
/// flushing, until then. One refused before it took any stays among the
/// pending upgrades, bounded by their limit and deadline as any request
/// before its upgrade is.
fn reply(peer: &PeerInfo, hls_id: &HlsId, answer: HlsAnswer, body: &BodyWatch) -> Response {
    let (mut response, in_flight) = match answer {
        Ok((HlsReply::Playlist(text), in_flight)) => {
            tracing::trace!(%peer, hls.id = %hls_id, bytes = text.len(), "LL-HLS playlist sent");
            let len = text.len();
            let response = ok(PLAYLIST_MIME, PLAYLIST_CACHE, len, vec![Bytes::from(text)]);
            (response, in_flight)
        }
        Ok((HlsReply::Media(chunks), in_flight)) => {
            tracing::trace!(%peer, hls.id = %hls_id, bytes = chunks.len(), "LL-HLS resource sent");
            let len = chunks.len();
            let response = ok(MEDIA_MIME, MEDIA_CACHE, len, chunks.into_vec());
            (response, in_flight)
        }
        Err((error, in_flight)) => {
            tracing::debug!(%peer, hls.id = %hls_id, %error, "LL-HLS request refused");
            (refused(error), in_flight)
        }
    };
    if !in_flight.is_empty() {
        body.set(BodyState::Taken);
        body.hold(in_flight);
    }
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// A `200` of `len` bytes of `mime`, cached as `cache` says, its body
/// `parts` in order.
fn ok(mime: &'static str, cache: &'static str, len: usize, parts: Vec<Bytes>) -> Response {
    let parts = futures_util::stream::iter(parts.into_iter().map(Ok::<_, Infallible>));
    let mut response = Body::from_stream(parts).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    response
}

/// The refusal of the handler's `error`.
fn refused(error: HlsError) -> Response {
    match error {
        HlsError::NotFound => hls_not_found(),
        HlsError::ResourceNotFound => resource_not_found(),
        HlsError::BadRequest => refuse(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidRequest,
            "the request asks for a segment or part too far ahead",
        ),
        HlsError::TooManyBlocked { limit } => too_many("too many blocked requests", limit),
        HlsError::TooManyRequests { limit } => too_many("too many requests in flight", limit),
        HlsError::Timeout => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::SourceTimeout,
            "nothing to answer within three Target Durations",
        ),
    }
}

/// 429 `limit_reached` (RFC 6585 §4) for a request past `limit`.
fn too_many(message: &str, limit: &'static str) -> Response {
    let error = ApiError::new(ErrorCode::LimitReached, message).with_detail("limit", limit);
    let body = serde_json::to_string(&error).unwrap_or_default();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// 404 `hls_not_found`.
fn hls_not_found() -> Response {
    refuse(
        StatusCode::NOT_FOUND,
        ErrorCode::HlsNotFound,
        "no open LL-HLS session has this id",
    )
}

/// 404 `hls_resource_not_found`.
fn resource_not_found() -> Response {
    refuse(
        StatusCode::NOT_FOUND,
        ErrorCode::HlsResourceNotFound,
        "the session's window holds no such resource",
    )
}

#[cfg(test)]
mod tests;
