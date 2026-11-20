//! The dev viewer: a browser signaling shim for trying lotse with a real
//! camera, and for the browser tests that need one.
//!
//! It serves one page on HTTP (and at `/test` the browser test's,
//! [`crate::browser`]) and relays that page's WebSocket, frame by
//! frame and unchanged, to the daemon's control socket; the page speaks the
//! control API itself.
//! HTTP/1.1 (RFC 9112) and the WebSocket opening handshake (RFC 6455 §4.2.2)
//! are axum's, the server the control API runs on; this module only routes
//! and checks. Whoever reaches the relay drives the daemon, so an upgrade
//! is accepted only from the page itself: its one `Origin` must be
//! `http://` plus its one `Host`, and the `Host` an IP literal or
//! `localhost`, which a DNS-rebinding page cannot fake (RFC 6454 §7;
//! RFC 6455 §4.2.1 and §10.2). The pages may not be framed
//! (`X-Frame-Options: DENY`, RFC 7034 §2.1, and CSP `frame-ancestors
//! 'none'`, CSP Level 3 §6.4.2), so no other page can click Play or Delete
//! through them, and the viewer's page runs only its own inline script and
//! style, matched by hash (CSP Level 3 §2.3.1), and connects only to its
//! own origin. The browser test's page connects where its `api` parameter
//! says, so it is served only for an `api` on a loopback address. A
//! browser message the daemon would refuse as too large is refused at the
//! relay already. Its talk-back needs the microphone, which browsers
//! expose to a secure context only: on plain HTTP, a page opened at a
//! loopback address (W3C Secure Contexts §3.1).
//!
//! `GET /v0/live/{live_id}` is proxied to the daemon's route of the same
//! path, as a client proxies a live output's bytes to its browser: the id is
//! checked against the identifier pattern first (untrusted input), the
//! request goes out on a connection of its own to the control socket
//! (HTTP/1.1, RFC 9112) without the browser's `Origin`, which the daemon
//! refuses, and the daemon's status, `Content-Type` and body come back as
//! they come, the chunked body streamed through, never cached (RFC 9111
//! §5.2.2.5). Like the relay, it answers only a request whose `Host` names
//! the machine by address or as `localhost`, and with an `Origin` only the
//! page's own. Any other method, `HEAD` included, is a `405` that never
//! reaches the daemon, whose output has one body to give (RFC 9110
//! §15.5.6).
//!
//! `GET /v0/hls/{hls_id}/{name}` is proxied the same way, as a client proxies
//! an LL-HLS session's playlist and media (draft-pantos-hls-rfc8216bis-22) to
//! its player: the id checked against the identifier pattern and the name as
//! the playlist (`index.m3u8`) or exactly as the playlist writes a resource
//! (`lotse_hls::Resource::parse`) before anything else, the query (a
//! playlist's Delivery Directives, §6.2.5, or a cache buster) bounded and
//! limited to the characters a directive is written in, then passed through
//! for the daemon to parse. The daemon's status, `Content-Type`,
//! `Content-Length`, `Cache-Control` and body come back as they come. A
//! Blocking Playlist Reload (§6.2.5.2) or a hinted part's request (§6.2.6) is
//! held by the daemon, up to three Target Durations, and the proxy holds the
//! browser's with it; `HEAD` and any other method are a `405` there too. A
//! development tool, never part of the daemon.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::body::Body;
use axum::extract::ws::{self, WebSocket, WebSocketUpgrade};
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt as _, StreamExt as _};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use lotse_api_types::hls::PLAYLIST_NAME;
use lotse_core::id::{HlsId, LiveId};
use lotse_core::task::spawn_named;
use sha2::{Digest as _, Sha256};
use tokio::net::{TcpListener, UnixStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

/// The page, which speaks the control API through the relay.
pub const PAGE: &str = include_str!("dev_viewer.html");

/// The relay's path.
pub const RELAY_PATH: &str = "/ws";

/// The route of a live output's bytes, the daemon's own path
/// (`lotse_api_types::LIVE_PATH`, `/v0/live`) and its id.
const LIVE_ROUTE: &str = "/v0/live/{live_id}";

/// The route of an LL-HLS session's playlist and media, the daemon's own
/// path (`lotse_api_types::HLS_PATH`, `/v0/hls`), its id and the name.
const HLS_ROUTE: &str = "/v0/hls/{hls_id}/{name}";

/// The longest query of an LL-HLS request passed to the daemon, in bytes:
/// `_HLS_msn` and `_HLS_part` with values of up to 20 digits each
/// (draft-pantos-hls-rfc8216bis-22 §4.2) take 54, `_HLS_skip=YES` (§6.2.5.1)
/// 13 more, and a player's cache buster fits the rest.
const MAX_HLS_QUERY_BYTES: usize = 256;

/// The largest message the relay takes from a page, and its largest frame:
/// the daemon's own inbound limit, 64 KiB (`lotse_api::MAX_MESSAGE_BYTES`),
/// so a larger one is refused before the relay buffers it rather than by the
/// daemon after tungstenite's 64 MiB default.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The browser test's page's policy: not framed (CSP Level 3 §6.4.2).
/// Nothing else, because it runs its worker and audio worklet from `blob:`
/// URLs and, for the comparison, signals to a server on another
/// origin, which [`test_page`] keeps on a loopback address; it holds
/// no credentials and runs in the test's own browser profile.
const TEST_PAGE_POLICY: &str = "frame-ancestors 'none'";

/// The most of a refused `api` parameter a log line carries, in bytes: it
/// is whatever the link that opened the page says.
const MAX_LOGGED_API_BYTES: usize = 256;

/// The viewer page's policy ([`policy`] of [`PAGE`]).
static PAGE_POLICY: LazyLock<String> = LazyLock::new(|| policy(PAGE));

/// The Content Security Policy (CSP Level 3) of a page whose script and
/// style are all inline `<script>` and `<style>` elements: those run, by
/// their SHA-256 (§2.3.1 hash-source), and nothing else loads; it connects
/// only to its own origin, which includes `ws://` on its host and port
/// (§6.7.2.6), and may not be framed (§6.4.2).
fn policy(page: &str) -> String {
    format!(
        "default-src 'none'; script-src {}; style-src {}; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        hashes(page, "script"),
        hashes(page, "style"),
    )
}

/// The hash-sources (CSP Level 3 §2.3.1) of every `<tag>` element's
/// content in `page`, space-separated; `'none'` if there is none.
fn hashes(page: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let sources: Vec<String> = page
        .split(open.as_str())
        .skip(1)
        .filter_map(|rest| rest.split_once(close.as_str()))
        .map(|(content, _)| {
            format!(
                "'sha256-{}'",
                crate::base64::encode(&Sha256::digest(content.as_bytes()))
            )
        })
        .collect();
    if sources.is_empty() {
        "'none'".to_owned()
    } else {
        sources.join(" ")
    }
}

/// What every route shares.
#[derive(Debug, Clone)]
struct Shared {
    /// The daemon's control socket.
    socket: Arc<Path>,
    /// Ends the server and every open relay.
    cancel: CancellationToken,
}

/// The value of the one `name` header of a request; `None` if absent,
/// repeated or not visible ASCII.
fn single(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).into_iter();
    let value = values.next()?;
    values.next().is_none().then(|| value.to_str().ok())?
}

/// Whether `host` (a `Host` header, port included) names the machine by
/// address or as `localhost`: a name a rebinding DNS server cannot point
/// here.
fn host_is_literal(host: &str) -> bool {
    if host.parse::<SocketAddr>().is_ok() || host.parse::<IpAddr>().is_ok() {
        return true;
    }
    let name = host.rsplit_once(':').map_or(host, |(name, _port)| name);
    name.eq_ignore_ascii_case("localhost")
}

/// Whether a request for a live output's bytes may come from the page: its
/// one `Host` names the machine ([`host_is_literal`]), and an `Origin`, which
/// a same-origin `fetch()` of a `GET` leaves out (WHATWG Fetch §3.1), is the
/// page's own; a page of another origin, or one reached by DNS rebinding,
/// gets nothing. A cross-origin request can leave `Origin` out too (a
/// `no-cors` fetch, a media element's load), so one the browser marks as
/// coming from another site (`Sec-Fetch-Site: cross-site` or `same-site`,
/// W3C Fetch Metadata §2.1.2) is refused whatever its `Origin`; the page's
/// own requests say `same-origin`, and a client that sends no fetch metadata
/// is no browser page.
fn may_fetch(headers: &HeaderMap) -> bool {
    let Some(host) = single(headers, header::HOST) else {
        return false;
    };
    if !host_is_literal(host) {
        return false;
    }
    let other_site = headers
        .get_all(SEC_FETCH_SITE)
        .iter()
        .any(|site| site != "same-origin" && site != "none");
    !other_site && (headers.get(header::ORIGIN).is_none() || same_origin(headers))
}

/// The fetch metadata header saying which site a browser's request comes
/// from (W3C Fetch Metadata Request Headers §2.1.2).
const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// The live output `path` names, `/v0/live/{live_id}`, checked against the
/// identifier pattern as the daemon checks it; `None` for anything else.
fn live_id_of(path: &str) -> Option<LiveId> {
    path.strip_prefix(lotse_api_types::LIVE_PATH)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|raw| LiveId::new(raw).ok())
}

/// Why an LL-HLS request is refused before the daemon is asked: its status
/// and its reason.
type HlsRefusal = (StatusCode, &'static str);

/// The path and query to ask the daemon for what an LL-HLS request's `path`,
/// `/v0/hls/{hls_id}/{name}`, and `query` name, each part checked first, as
/// the daemon checks it: the id against the identifier pattern, the name as
/// the playlist or exactly as the playlist writes a resource
/// (draft-pantos-hls-rfc8216bis-22 §4.1, `lotse_hls::Resource`), written
/// back from what it parsed to. The query, which the daemon parses as a
/// playlist's Delivery Directives (§6.2.5) and ignores on a resource, is
/// passed as it is if it is at most [`MAX_HLS_QUERY_BYTES`] of what a
/// directive is written in: letters, digits, `_`, `-`, `.`, `~`, `=`, `&`
/// and `%` (RFC 3986 §2.3 and §3.4). A path is a `404`, a query a `400`.
fn hls_target_of(path: &str, query: Option<&str>) -> Result<String, HlsRefusal> {
    const NO_SESSION: HlsRefusal = (StatusCode::NOT_FOUND, "no such LL-HLS session");
    let (raw_id, name) = path
        .strip_prefix(lotse_api_types::HLS_PATH)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.split_once('/'))
        .ok_or(NO_SESSION)?;
    let hls_id = HlsId::new(raw_id).map_err(|_| NO_SESSION)?;
    let name = if name == PLAYLIST_NAME {
        PLAYLIST_NAME.to_owned()
    } else {
        lotse_hls::Resource::parse(name)
            .ok_or((StatusCode::NOT_FOUND, "no such LL-HLS resource"))?
            .to_string()
    };
    let mut target = format!("{}/{hls_id}/{name}", lotse_api_types::HLS_PATH);
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"_-.~=&%".contains(&byte);
        if query.len() > MAX_HLS_QUERY_BYTES || !query.bytes().all(allowed) {
            return Err((
                StatusCode::BAD_REQUEST,
                "the query is not one the daemon takes",
            ));
        }
        target.push('?');
        target.push_str(query);
    }
    Ok(target)
}

/// Whether an upgrade comes from the page itself (RFC 6455 §10.2).
fn same_origin(headers: &HeaderMap) -> bool {
    match (
        single(headers, header::HOST),
        single(headers, header::ORIGIN),
    ) {
        (Some(host), Some(origin)) => host_is_literal(host) && origin == format!("http://{host}"),
        _ => false,
    }
}

/// The routes: the page, the browser test's page, the relay, the live
/// outputs' bytes and the LL-HLS sessions' playlists and media; anything
/// else is `404` (axum answers a malformed request or upgrade `400`). The
/// proxied paths answer only `GET`: axum's `get` would answer `HEAD` with
/// the `GET` handler, whose `GET` to the daemon takes a live output's one
/// body (and holds an LL-HLS session's blocking reload for nothing), so
/// `HEAD` and every other method are [`not_allowed`] instead.
fn router(socket: PathBuf, cancel: CancellationToken) -> Router {
    Router::new()
        .route("/", get(|| async { page(PAGE, PAGE_POLICY.as_str()) }))
        .route(crate::browser::PAGE_PATH, get(test_page))
        .route(RELAY_PATH, get(upgrade))
        .route(
            LIVE_ROUTE,
            get(live).head(not_allowed).fallback(not_allowed),
        )
        .route(HLS_ROUTE, get(hls).head(not_allowed).fallback(not_allowed))
        .fallback(|| async { refuse(StatusCode::NOT_FOUND, "not found\n".to_owned()) })
        .with_state(Shared {
            socket: socket.into(),
            cancel,
        })
}

/// Serves the page and the relay on `listener` until `cancel`, relaying to
/// the control socket at `socket`; `cancel` also ends every open relay.
pub async fn serve(listener: TcpListener, socket: PathBuf, cancel: CancellationToken) {
    let app = router(socket, cancel.clone());
    // axum documents that serving never fails: accept errors are retried.
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await
    {
        tracing::warn!(error = %err, "dev viewer stopped");
    }
}

/// A page under `policy` (CSP Level 3), never framed (RFC 7034 §2.1, for
/// browsers without `frame-ancestors`) and never cached, so a rebuilt
/// viewer shows its new page.
fn page(body: &'static str, policy: &str) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, policy),
        ],
        Html(body),
    )
        .into_response()
}

/// Whether the browser test page's `api` parameter, the go2rtc WebSocket
/// URL it signals to for the comparison, names this machine: a `ws://` or
/// `wss://` URL, without userinfo, whose host is a loopback address
/// (127.0.0.0/8, RFC 1122 §3.2.1.3; `::1`, RFC 4291 §2.5.3) or
/// `localhost` (RFC 6761 §6.3), as the browser's WebSocket constructor
/// reads it (WHATWG URL Standard §4.4, `url`'s parser). Anything but
/// visible ASCII, or a `\`, is refused before parsing: the URL parser
/// strips tabs and newlines and reads `\` as `/`, and a browser that
/// does so differently must not find another host in the same text.
fn api_is_loopback(api: &str) -> bool {
    if !api
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
    {
        return false;
    }
    let Ok(url) = Url::parse(api) else {
        return false;
    };
    if !matches!(url.scheme(), "ws" | "wss")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        // The parser lowercases a special scheme's domain.
        host => host == Some(Host::Domain("localhost")),
    }
}

/// At most [`MAX_LOGGED_API_BYTES`] of `text`, cut at a character
/// boundary.
fn capped(text: &str) -> &str {
    text.get(..text.floor_char_boundary(MAX_LOGGED_API_BYTES))
        .unwrap_or(text)
}

/// `GET /test`: the browser test's page, unless an `api` parameter of its
/// query (read as the page's `URLSearchParams` reads it, WHATWG URL
/// Standard §5.1) is not on a loopback address ([`api_is_loopback`]):
/// the page would open a WebSocket to it, so a link to the dev viewer
/// could point the browser's signaling anywhere. Every `api` counts, not
/// only the first, which the page takes.
async fn test_page(RawQuery(query): RawQuery) -> Response {
    let query = query.unwrap_or_default();
    let refused = url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, value)| name == "api" && !api_is_loopback(value));
    if let Some((_, api)) = refused {
        tracing::warn!(
            api = ?capped(&api),
            "browser test page refused: its api parameter is not a WebSocket URL of a loopback address"
        );
        return refuse(
            StatusCode::BAD_REQUEST,
            "the api parameter must be a ws:// or wss:// URL of a loopback address\n".to_owned(),
        );
    }
    page(crate::browser::PAGE, TEST_PAGE_POLICY)
}

/// A refusal with a plain-text reason.
fn refuse(status: StatusCode, reason: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        reason,
    )
        .into_response()
}

/// `GET /ws`: the origin check, the daemon's WebSocket, then the browser's
/// upgrade; the daemon is connected first so that its absence is a clear
/// `502` rather than a WebSocket that closes at once.
async fn upgrade(
    State(shared): State<Shared>,
    headers: HeaderMap,
    browser: WebSocketUpgrade,
) -> Response {
    if !same_origin(&headers) {
        tracing::warn!(
            host = ?headers.get(header::HOST),
            origin = ?headers.get(header::ORIGIN),
            "relay refused: not the viewer page"
        );
        return refuse(
            StatusCode::FORBIDDEN,
            "only the viewer page may connect\n".to_owned(),
        );
    }
    let daemon = match UnixStream::connect(&shared.socket).await {
        Ok(daemon) => daemon,
        Err(err) => {
            tracing::warn!(socket = %shared.socket.display(), error = %err, "relay refused: no daemon");
            return refuse(
                StatusCode::BAD_GATEWAY,
                format!(
                    "the daemon's control socket {}: {err}\n",
                    shared.socket.display()
                ),
            );
        }
    };
    let url = format!("ws://lotse{}", lotse_api_types::WS_PATH);
    let daemon = match tokio_tungstenite::client_async(&url, daemon).await {
        Ok((daemon, _response)) => daemon,
        Err(err) => {
            tracing::warn!(error = %err, "relay refused: the daemon refused the upgrade");
            return refuse(
                StatusCode::BAD_GATEWAY,
                "the daemon refused the upgrade\n".to_owned(),
            );
        }
    };
    tracing::info!("relay open");
    let cancel = shared.cancel;
    browser
        .max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |browser| async move {
            tokio::select! {
                () = relay(browser, daemon) => tracing::info!("relay closed"),
                () = cancel.cancelled() => tracing::info!("relay closed: the dev viewer stops"),
            }
        })
}

/// `GET /v0/live/{live_id}`: a live output's bytes from the daemon, as a
/// client proxies them. The checks ([`may_fetch`], [`live_id_of`]), then
/// the daemon's `GET` of the same path on a connection of its own, without
/// the browser's header fields: its status, its `Content-Type` and its body
/// streamed through as they come, until the daemon ends it, the browser
/// goes, or the dev viewer stops. No daemon is a `502`.
async fn live(State(shared): State<Shared>, headers: HeaderMap, uri: Uri) -> Response {
    if !may_fetch(&headers) {
        tracing::warn!(
            host = ?headers.get(header::HOST),
            origin = ?headers.get(header::ORIGIN),
            "live body refused: not the page"
        );
        return refuse(
            StatusCode::FORBIDDEN,
            "only the viewer's pages may fetch a live output\n".to_owned(),
        );
    }
    let Some(live_id) = live_id_of(uri.path()) else {
        tracing::warn!(path = ?capped(uri.path()), "live body refused: the path names no live id");
        return refuse(StatusCode::NOT_FOUND, "no such live output\n".to_owned());
    };
    match fetch_live(&shared, &live_id).await {
        Ok(response) => response,
        Err(reason) => {
            tracing::warn!(live.id = %live_id, socket = %shared.socket.display(), %reason, "live body refused: no answer from the daemon");
            refuse(StatusCode::BAD_GATEWAY, format!("{reason}\n"))
        }
    }
}

/// Any other method on a proxied path, `HEAD` included: `405` with
/// `Allow: GET` (RFC 9110 §15.5.6), as the daemon's own routes answer it,
/// without asking the daemon, whose live output has one body to give.
async fn not_allowed() -> Response {
    let mut response = refuse(
        StatusCode::METHOD_NOT_ALLOWED,
        "only GET is proxied here\n".to_owned(),
    );
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET"));
    response
}

/// The daemon's answer to `GET /v0/live/{live_id}` on a connection of its
/// own to the control socket, as the response to the browser; why there is
/// none when the daemon cannot be reached or does not answer.
async fn fetch_live(shared: &Shared, live_id: &LiveId) -> Result<Response, String> {
    let path = lotse_api_types::live::live_path(live_id.as_str());
    let answer = ask_daemon(shared, &path).await?;
    let status = answer.status();
    let content_type = answer.headers().get(header::CONTENT_TYPE).cloned();
    tracing::info!(live.id = %live_id, %status, "live body: relaying the daemon's answer");
    let body = Body::new(answer.into_body())
        .into_data_stream()
        .take_until(shared.cancel.clone().cancelled_owned());
    let mut response = Response::new(Body::from_stream(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    if let Some(content_type) = content_type {
        headers.insert(header::CONTENT_TYPE, content_type);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// `GET /v0/hls/{hls_id}/{name}`: an LL-HLS session's playlist or media
/// from the daemon, as a client proxies them. The checks ([`may_fetch`],
/// [`hls_target_of`]), then the daemon's `GET` of the same path and query on
/// a connection of its own, without the browser's header fields, held as
/// long as the daemon holds it; its status, `Content-Type`,
/// `Content-Length`, `Cache-Control` (the playlist's `no-cache`, a
/// resource's `max-age`, RFC 9111 §5.2.2) and body passed through. No daemon
/// is a `502`.
async fn hls(State(shared): State<Shared>, headers: HeaderMap, uri: Uri) -> Response {
    if !may_fetch(&headers) {
        tracing::warn!(
            host = ?headers.get(header::HOST),
            origin = ?headers.get(header::ORIGIN),
            "LL-HLS request refused: not the page"
        );
        return refuse(
            StatusCode::FORBIDDEN,
            "only the viewer's pages may fetch an LL-HLS session\n".to_owned(),
        );
    }
    let target = match hls_target_of(uri.path(), uri.query()) {
        Ok(target) => target,
        Err((status, reason)) => {
            tracing::warn!(path = ?capped(uri.path()), query = ?uri.query().map(capped), reason, "LL-HLS request refused");
            return refuse(status, format!("{reason}\n"));
        }
    };
    let answer = match ask_daemon(&shared, &target).await {
        Ok(answer) => answer,
        Err(reason) => {
            tracing::warn!(target, socket = %shared.socket.display(), %reason, "LL-HLS request refused: no answer from the daemon");
            return refuse(StatusCode::BAD_GATEWAY, format!("{reason}\n"));
        }
    };
    // Several a second for each player: not worth more than debug.
    tracing::debug!(target, status = %answer.status(), "LL-HLS request: relaying the daemon's answer");
    let (parts, body) = answer.into_parts();
    let mut response = Response::new(Body::new(body));
    *response.status_mut() = parts.status;
    for name in [
        header::CONTENT_TYPE,
        header::CONTENT_LENGTH,
        header::CACHE_CONTROL,
    ] {
        if let Some(value) = parts.headers.get(&name) {
            response.headers_mut().insert(name, value.clone());
        }
    }
    response
}

/// The daemon's answer to `GET path` (its path and query) on a connection of
/// its own to the control socket (HTTP/1.1, RFC 9112), sent with `Host:
/// lotse` and none of the browser's header fields: the daemon refuses a
/// request carrying `Origin`. The connection runs until the answer's body
/// ends or the dev viewer stops. Why there is no answer when the daemon
/// cannot be reached or does not answer.
async fn ask_daemon(shared: &Shared, path: &str) -> Result<axum::http::Response<Incoming>, String> {
    let stream = UnixStream::connect(&shared.socket).await.map_err(|err| {
        format!(
            "the daemon's control socket {}: {err}",
            shared.socket.display()
        )
    })?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|err| format!("the daemon's HTTP connection: {err}"))?;
    let cancel = shared.cancel.clone();
    spawn_named("dev_viewer.daemon_request", async move {
        tokio::select! {
            ended = connection => {
                if let Err(err) = ended {
                    tracing::debug!(error = %err, "the daemon's HTTP connection ended");
                }
            }
            () = cancel.cancelled() => {}
        }
    });
    let request = axum::http::Request::get(path)
        .header(header::HOST, "lotse")
        .body(Body::empty())
        .map_err(|err| format!("the daemon's request: {err}"))?;
    sender
        .send_request(request)
        .await
        .map_err(|err| format!("the daemon did not answer: {err}"))
}

/// Relays text frames both ways until either side closes, then closes
/// both.
async fn relay(browser: WebSocket, daemon: WebSocketStream<UnixStream>) {
    let (mut to_browser, mut from_browser) = browser.split();
    let (mut to_daemon, mut from_daemon) = daemon.split();
    loop {
        tokio::select! {
            frame = from_browser.next() => match frame {
                Some(Ok(ws::Message::Text(text))) => {
                    if to_daemon.send(Message::text(text.as_str())).await.is_err() {
                        break;
                    }
                }
                Some(Ok(ws::Message::Close(_))) | None => break,
                // A message over [`MAX_MESSAGE_BYTES`] among others.
                Some(Err(err)) => {
                    tracing::warn!(error = %err, "relay closing: the page's frame is refused");
                    break;
                }
                Some(Ok(_)) => {}
            },
            frame = from_daemon.next() => match frame {
                Some(Ok(Message::Text(text))) => {
                    if to_browser.send(ws::Message::text(text.as_str())).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
    let _closed = to_browser.close().await;
    let _closed = to_daemon.close().await;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::unix::fs::DirBuilderExt as _;

    use axum::http::HeaderValue;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpStream, UnixListener};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    use tokio_tungstenite::tungstenite::protocol::frame::Frame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};

    use super::*;

    fn headers(list: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in list {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn rfc6455_s10_2_only_the_page_itself_is_same_origin() {
        let with = |host: &str, origin: &str| headers(&[("host", host), ("origin", origin)]);
        assert!(same_origin(&with(
            "127.0.0.1:8080",
            "http://127.0.0.1:8080"
        )));
        assert!(same_origin(&with(
            "localhost:8080",
            "http://localhost:8080"
        )));
        assert!(same_origin(&with("LocalHost", "http://LocalHost")));
        assert!(same_origin(&with("[::1]:8080", "http://[::1]:8080")));
        assert!(same_origin(&with("192.168.1.2", "http://192.168.1.2")));
        assert!(
            !same_origin(&headers(&[("host", "127.0.0.1:8080")])),
            "no Origin"
        );
        assert!(
            !same_origin(&headers(&[("origin", "http://127.0.0.1:8080")])),
            "no Host"
        );
        assert!(!same_origin(&with("127.0.0.1:8080", "http://evil.example")));
        assert!(
            !same_origin(&with("127.0.0.1:8080", "https://127.0.0.1:8080")),
            "the page is served on http"
        );
        assert!(
            !same_origin(&with("evil.example:8080", "http://evil.example:8080")),
            "DNS rebinding: a name, however consistent"
        );
        assert!(
            !same_origin(&headers(&[
                ("host", "evil.example:8080"),
                ("host", "127.0.0.1:8080"),
                ("origin", "http://127.0.0.1:8080"),
            ])),
            "two Hosts: neither is trusted"
        );
        assert!(
            !same_origin(&headers(&[
                ("host", "127.0.0.1:8080"),
                ("origin", "http://127.0.0.1:8080"),
                ("origin", "http://evil.example"),
            ])),
            "two Origins: neither is trusted"
        );
        let mut opaque = with("127.0.0.1:8080", "http://127.0.0.1:8080");
        opaque.insert(
            header::ORIGIN,
            HeaderValue::from_bytes(b"http://127.0.0.1:8080\xff").unwrap(),
        );
        assert!(!same_origin(&opaque), "not visible ASCII");
    }

    /// A daemon that sends `hello` and echoes text frames prefixed; `None`
    /// pings it before the echo, which the relay drops.
    /// Needs a runtime: binds a Tokio listener.
    fn fake_daemon(name: &str) -> (PathBuf, PathBuf) {
        let (dir, socket) = socket_dir(name);
        let listener = UnixListener::bind(&socket).unwrap();
        spawn_named("test.fake_daemon", async move {
            while let Ok((stream, _)) = listener.accept().await {
                spawn_named("test.fake_daemon.connection", async move {
                    let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                    ws.send(Message::text(r#"{"type":"hello"}"#)).await.unwrap();
                    while let Some(Ok(frame)) = ws.next().await {
                        match frame {
                            Message::Text(text) => {
                                ws.send(Message::Ping(Vec::new().into())).await.unwrap();
                                ws.send(Message::text(format!("echo {text}")))
                                    .await
                                    .unwrap();
                            }
                            Message::Close(_) => break,
                            _ => {}
                        }
                    }
                });
            }
        });
        (dir, socket)
    }

    fn socket_dir(name: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("lotse-dev-viewer-{name}-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let socket = dir.join("lotse.sock");
        (dir, socket)
    }

    async fn start(socket: PathBuf) -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        spawn_named("test.dev_viewer", serve(listener, socket, cancel.clone()));
        (addr, cancel)
    }

    /// Sends `request` as is and reads until the server closes.
    async fn raw(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// `GET path` from `127.0.0.1` with `Connection: close`, so the server
    /// ends the connection after its response.
    async fn get(addr: SocketAddr, path: &str) -> String {
        raw(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
        )
        .await
    }

    /// The page keeps saved camera URLs in localStorage with their
    /// userinfo (RFC 3986 §3.2.1), so a new tab gets them back, and moves
    /// what earlier pages kept in a tab's sessionStorage there.
    #[test]
    fn rfc3986_s3_2_1_the_page_keeps_userinfo_in_local_storage() {
        let page = PAGE;
        let save = page
            .split("function save()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("the page saves its settings in save()");
        // The URLs go to localStorage as typed, and nothing to
        // sessionStorage, which a new tab does not see.
        assert!(
            save.contains("localStorage.setItem(STORE,")
                && save.contains("url: cameraUrl,")
                && save.contains("saved: entries,")
                && !save.contains("splitUserinfo"),
            "localStorage gets the URLs with their userinfo: {save}"
        );
        assert!(!page.contains("sessionStorage.setItem"), "{page}");
        // The userinfo ends at the authority's last `@`: the split and
        // the mask take the same greedy run of authority characters.
        assert!(page.contains(r"/^([a-z][a-z0-9+.-]*:\/\/)([^\/?#]*@)/i.exec(url)"));
        // The credentials an earlier page left in this tab are put back; a
        // stored URL with its own userinfo, or anything not userinfo, is
        // left as it is.
        assert!(page.contains(
            r#"if (typeof userinfo !== "string" || !/^[^\/?#]*@$/.test(userinfo) || splitUserinfo(url).userinfo) return url;"#
        ));
        assert!(page.contains("credentials = parsed(sessionStorage.getItem(STORE));"));
        assert!(page.contains("url: withUserinfo(e.url, savedCredentials.get(e.id)),"));
        assert!(page.contains("withUserinfo(saved.url, credentials.url)"));
        // Saved streams match without their userinfo, so a changed
        // password updates the entry instead of adding one.
        assert!(page.contains("splitUserinfo(e.url).bare === bare && e.stream === stream"));
        // What earlier pages kept in sessionStorage moves to localStorage
        // on load, and sessionStorage is cleared.
        // sessionStorage is cleared only once localStorage has taken the
        // credentials: a failed write keeps them for the next load.
        let migrate = page
            .split("if (Object.keys(credentials).length && save()) {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("tab credentials move on load once saved");
        assert!(
            migrate.contains("sessionStorage.removeItem(STORE);"),
            "{migrate}"
        );
        assert!(
            save.contains("    }));\n    return true;\n  } catch (err) {\n    storageFailed(err);\n    return false;\n  }"),
            "save() says whether localStorage took the settings: {save}"
        );
        // Every storage access is inside a `try`, so the page works without
        // storage.
        let accesses = page
            .match_indices("localStorage.")
            .chain(page.match_indices("sessionStorage."))
            .map(|(at, _)| at);
        for at in accesses {
            let (_, since) = page[..at].rsplit_once("try {").expect("a try");
            assert!(!since.contains("catch"), "storage outside try: {since}");
        }
    }

    /// The panel sits right of the video or below it, as its dock buttons
    /// on the title line choose, and the choice is kept with the other
    /// settings.
    #[test]
    fn the_panel_docks_right_of_or_below_the_video() {
        let page = PAGE;
        assert!(page.contains(r#"<div class="app below" id="app">"#));
        assert!(page.contains(
            r#"title="Panel below the video" aria-label="Panel below the video" aria-pressed="true""#
        ));
        let header = page
            .split("<header>")
            .nth(1)
            .and_then(|rest| rest.split("</header>").next())
            .expect("the title line");
        assert!(
            header.contains("<h1>")
                && header.contains(
                    r#"<button id="dock-right" type="button" title="Panel right of the video""#
                )
                && header.contains(
                    r#"<button id="dock-below" type="button" title="Panel below the video""#
                ),
            "{header}"
        );
        // Below, the video keeps the full width and the panel is three
        // columns: the fields, the session, and the widest, the log. A
        // narrow window stacks them as before and has no dock buttons.
        let below = page
            .split("@media (min-width: 761px) {")
            .nth(1)
            .and_then(|rest| rest.split("\n  }\n").next())
            .expect("the panel below the video is styled for wide windows only");
        assert!(
            below.contains(".app.below { grid-template-columns: minmax(0, 1fr); grid-template-rows: minmax(0, 1fr) auto; }")
                && below.contains("grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr) minmax(0, 1.8fr);")
                && below.contains(".app.below .col, .app.below #log { min-height: 0; overflow: hidden auto; }"),
            "{below}"
        );
        let aside = page
            .split("<aside>")
            .nth(1)
            .and_then(|rest| rest.split("</aside>").next())
            .expect("the panel");
        assert_eq!(aside.matches(r#"<div class="col">"#).count(), 2, "{aside}");
        assert!(
            aside.trim_end().ends_with(r#"<pre id="log"></pre>"#),
            "{aside}"
        );
        assert!(page.contains("    .dock { display: none; }\n"));
        // The pressed button shows where the panel is; a stored choice is
        // applied on load, and anything else puts the panel below, the default.
        assert!(page.contains(r#"let panel = saved.panel === "right" ? "right" : "below";"#));
        assert!(page.contains(r#"$("app").classList.toggle("below", panel === "below");"#));
        assert!(page.contains(
            r#"for (const side of ["right", "below"]) $(`dock-${side}`).setAttribute("aria-pressed", String(panel === side));"#
        ));
        assert!(page.contains(
            r#"$(`dock-${side}`).addEventListener("click", () => { panel = side; placePanel(); save(); });"#
        ));
        let save = page
            .split("function save()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("the page saves its settings in save()");
        assert!(save.contains("      panel,\n"), "{save}");
    }

    /// A new stream's id is its name as a slug until the id is typed by
    /// hand; Play and Stop sit under the name, the stream id last.
    #[test]
    fn the_stream_id_follows_the_name_until_typed() {
        let page = PAGE;
        let form = page
            .split(r#"<form id="form">"#)
            .nth(1)
            .and_then(|rest| rest.split("</form>").next())
            .expect("the form");
        let at = |what: &str| {
            form.find(what)
                .unwrap_or_else(|| panic!("{what} in {form}"))
        };
        assert!(at(r#"id="label""#) < at(r#"id="play""#) && at(r#"id="play""#) < at(r#"id="url""#));
        assert!(
            form.trim_end().ends_with(r#"<input id="stream" value="cam" pattern="[A-Za-z0-9._\-]{1,128}" required></label>"#),
            "{form}"
        );
        // The slug fits the stream id's pattern: lowercase ASCII letters
        // and digits joined by `_`, at most 128 characters.
        let slugify = page
            .split("function slugify(name) {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("the name's slug");
        assert!(
            slugify
                .contains(r#".replace(/[^a-z0-9]+/g, "_").slice(0, 128).replace(/^_+|_+$/g, "");"#),
            "{slugify}"
        );
        // Typing a stream id stops the name driving it, unless it is
        // empty, the default or the slug; a saved stream keeps its id.
        assert!(page.contains(
            r#"const typedStream = () => !["", $("stream").defaultValue, slugify($("label").value)].includes($("stream").value.trim());"#
        ));
        let label = page
            .split(r#"$("label").addEventListener("input", () => {"#)
            .nth(1)
            .and_then(|rest| rest.split("\n});\n").next())
            .expect("the name drives the stream id");
        assert!(
            label.contains("if (streamTyped || selected() || !slug) return;")
                && label.contains(r#"$("stream").value = slug;"#),
            "{label}"
        );
        // An emptied stream id goes back to the name's slug when the field
        // is left, not while it is empty.
        let blur = page
            .split(r#"$("stream").addEventListener("blur", () => {"#)
            .nth(1)
            .and_then(|rest| rest.split("\n});\n").next())
            .expect("an emptied stream id is handed back to the name");
        assert!(
            blur.contains(r#"if ($("stream").value.trim() || !slug) return;"#)
                && blur.contains(r#"$("stream").value = slug;"#)
                && blur.contains("streamTyped = false;"),
            "{blur}"
        );
        assert_eq!(
            page.matches("streamTyped = typedStream();").count(),
            2,
            "guessed on load and on choosing a saved stream only"
        );
        // Typing marks any non-empty id as the user's, the default `cam`
        // and the name's slug included.
        let input = page
            .split(r#"$("stream").addEventListener("input", () => {"#)
            .nth(1)
            .and_then(|rest| rest.split("\n});\n").next())
            .expect("typing a stream id");
        assert!(
            input.contains(r#"streamTyped = $("stream").value.trim() !== "";"#),
            "{input}"
        );
    }

    /// CSS Color Adjustment Level 1 §2.1: the page declares both schemes,
    /// so native scrollbars and controls follow the dark one; its
    /// scrollable parts have thin, muted scrollbars (CSS Scrollbars Styling
    /// Level 1 §2, §3).
    #[test]
    fn css_color_adjust_1_s2_1_scrollbars_follow_the_color_scheme() {
        let style = PAGE
            .split("<style>")
            .nth(1)
            .and_then(|rest| rest.split("</style>").next())
            .expect("the page's style");
        assert!(
            style.contains(":root { color-scheme: light dark; scrollbar-color: color-mix(in srgb, var(--muted) 50%, transparent) transparent; }"),
            "{style}"
        );
        assert!(
            style.contains("aside, .col, #log { scrollbar-width: thin; }"),
            "{style}"
        );
    }

    /// CSP Level 3 §2.3.1: a hash-source is the base64 SHA-256 of the
    /// element's content, exactly as between its tags.
    #[test]
    fn csp3_s2_3_1_inline_elements_are_allowed_by_their_sha256() {
        // SHA-256 of "" and of "abc" (FIPS 180-4 example), in base64.
        let empty = "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='";
        let abc = "'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0='";
        assert_eq!(hashes("<p><script></script></p>", "script"), empty);
        assert_eq!(
            hashes("<script>abc</script><script></script>", "script"),
            format!("{abc} {empty}")
        );
        assert_eq!(hashes("<script>abc</script>", "style"), "'none'");
        assert_eq!(hashes("<script>abc", "script"), "'none'", "never closed");
        assert_eq!(
            policy("<style>abc</style><script></script>"),
            format!(
                "default-src 'none'; script-src {empty}; style-src {abc}; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )
        );
        // The viewer page: one script and one style, nothing loaded from
        // elsewhere, no inline handlers or style attributes, which the
        // hashes would not allow, and its form never submits.
        let script = PAGE
            .split_once("<script>")
            .and_then(|(_, rest)| rest.split_once("</script>"))
            .unwrap()
            .0;
        assert_eq!(PAGE.matches("<script").count(), 1);
        assert_eq!(PAGE.matches("<style").count(), 1);
        assert!(PAGE_POLICY.contains(&format!("script-src {}; ", hashes(PAGE, "script"))));
        assert_ne!(hashes(PAGE, "script"), hashes(PAGE, "style"));
        assert!(!PAGE.contains(" style=") && !PAGE.contains(" src=") && !PAGE.contains(" href="));
        assert!(!PAGE.contains(" onclick=") && !script.contains("innerHTML"));
        assert!(script.contains("new WebSocket(`ws://${location.host}/ws`)"));
        assert!(script.contains(
            r#"$("form").addEventListener("submit", (event) => { event.preventDefault();"#
        ));
    }

    #[tokio::test]
    async fn serves_the_page_and_refuses_everything_else() {
        let (dir, socket) = fake_daemon("page");
        let (addr, cancel) = start(socket).await;
        let page = get(addr, "/").await;
        assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
        let lower = page.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: text/html; charset=utf-8"),
            "{page}"
        );
        assert!(lower.contains("cache-control: no-store"), "{page}");
        // DEV-3 (2026-10-05): no page frames it (RFC 7034 §2.1, CSP Level 3
        // §6.4.2), and it runs only its own script and style.
        assert!(lower.contains("x-frame-options: deny"), "{page}");
        assert!(
            page.contains(&format!("content-security-policy: {}\r\n", *PAGE_POLICY)),
            "{page}"
        );
        assert!(page.contains("webrtc/offer") && page.contains("<video"));
        // The offer carries an audio m-line, or the daemon answers video
        // only with `audio_codec_unsupported` (seen 2026-10-01).
        assert!(page.contains(r#"peer.addTransceiver("audio", { direction: "recvonly" })"#));
        // Leaving playout-delay out of the offer is how the A/V sync
        // experiment of 2026-10-01 turns it off.
        assert!(
            page.contains(r#"id="playout-delay""#) && page.contains("rtp-hdrext\\/playout-delay")
        );
        // The URL field shows the password masked; the real URL is what is
        // sent.
        assert!(page.contains("function masked(url)"));
        assert!(page.contains("const url = cameraUrl;"));
        // CVO (2026-10-05): the eight orientations to choose from, the
        // choice in the put, and the answer read for the extension.
        for name in [
            "no_transform",
            "mirror",
            "rotate_180",
            "flip",
            "rotate_left_and_flip",
            "rotate_left",
            "rotate_right_and_flip",
            "rotate_right",
        ] {
            assert!(
                page.contains(&format!(r#"<option value="{name}">{name}</option>"#)),
                "{name}"
            );
        }
        assert!(page.contains("sources: [source(url, talkback)], orientation }"));
        assert!(page.contains(r#"const CVO = "urn:3gpp:video-orientation";"#));
        assert!(page.contains("extmapId(answer, \"video\", CVO)"));
        // A change while playing puts the stream again and keeps the
        // session, which turns from its next frame (2026-10-08).
        let handler = page
            .split(r#"$("orientation").addEventListener("change""#)
            .nth(1)
            .and_then(|rest| rest.split("\n});").next())
            .expect("the orientation handler");
        assert!(handler.contains(
            r#"send({ type: "stream/put", stream_id: streamId, sources: [source(url, talkback)], orientation }"#
        ));
        assert!(!handler.contains("play()"), "{handler}");
        // The saved-streams list shows URLs masked.
        assert!(page.contains("const shown = masked(entry.url);"));
        // The video fills the viewport beside or above the controls.
        assert!(page.contains("height: 100dvh") && page.contains("object-fit: contain"));
        // The browser test's page.
        let test = get(addr, "/test").await;
        assert!(test.starts_with("HTTP/1.1 200 OK"), "{test}");
        let lower = test.to_ascii_lowercase();
        assert!(lower.contains("cache-control: no-store"), "{test}");
        assert!(lower.contains("x-frame-options: deny"), "{test}");
        assert!(
            lower.contains("content-security-policy: frame-ancestors 'none'\r\n"),
            "{test}"
        );
        assert!(test.contains("window.lotseTest") && test.contains("requestVideoFrameCallback"));

        // Everything else is refused.
        let missing = get(addr, "/nope").await;
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
        assert!(missing.ends_with("not found\n"), "{missing}");
        let query = get(addr, "/?x=1").await;
        assert!(
            query.starts_with("HTTP/1.1 200"),
            "a query is no other page: {query}"
        );
        let post = raw(
            addr,
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        let post = raw(
            addr,
            "POST /ws HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        let plain = get(addr, RELAY_PATH).await;
        assert!(
            plain.starts_with("HTTP/1.1 400"),
            "the relay without an upgrade: {plain}"
        );
        let bad = raw(addr, "garbage\r\n\r\n").await;
        assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
        let mut cut = TcpStream::connect(addr).await.unwrap();
        cut.write_all(b"GET / HTTP/1.1").await.unwrap();
        cut.shutdown().await.unwrap();
        let mut response = String::new();
        cut.read_to_string(&mut response).await.unwrap();
        assert!(
            response.is_empty(),
            "a head cut short is no request: closed unanswered, {response}"
        );
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What counts as this machine in `api`: loopback addresses and
    /// `localhost`, as the browser parses the URL, and nothing that a
    /// parser could read as another host.
    #[test]
    fn rfc1122_s3_2_1_3_and_rfc4291_s2_5_3_only_a_loopback_api_is_accepted() {
        for api in [
            "ws://127.0.0.1:1984/api/ws",
            "ws://127.255.255.254/",
            "wss://127.0.0.1:1984/api/ws",
            "ws://[::1]:1984/api/ws",
            "ws://[0:0:0:0:0:0:0:1]/",
            "ws://localhost:1984/api/ws",
            "ws://LOCALHOST/",
            "ws://0x7f.1/",
        ] {
            assert!(api_is_loopback(api), "{api}");
        }
        for api in [
            "ws://192.0.2.1:1984/api/ws",
            "ws://10.0.0.1/",
            "ws://128.0.0.1/",
            "ws://[2001:db8::1]:1984/api/ws",
            "ws://[::ffff:127.0.0.1]/",
            "ws://evil.example/",
            "ws://localhost.evil.example/",
            "ws://localhost./",
            "http://127.0.0.1/",
            "wss+x://127.0.0.1/",
            "ws://user@127.0.0.1/",
            "ws://:secret@127.0.0.1/",
            "ws://127.0.0.1@evil.example/",
            "ws://127.0.0.1\\@evil.example/",
            "ws://127.0.0.1 /",
            "ws://127.0.0.1\t.evil.example/",
            "ws://127.0.0.1\n.evil.example/",
            "ws://127.0.0.1/\u{e9}",
            "ws://[::1/",
            "/api/ws",
            "",
        ] {
            assert!(!api_is_loopback(api), "{api:?}");
        }
    }

    #[test]
    fn a_logged_api_is_capped_at_a_character_boundary() {
        assert_eq!(capped("ws://127.0.0.1/"), "ws://127.0.0.1/");
        let long = "a".repeat(MAX_LOGGED_API_BYTES + 10);
        assert_eq!(capped(&long).len(), MAX_LOGGED_API_BYTES);
        let wide = format!("{}\u{e9}", "a".repeat(MAX_LOGGED_API_BYTES - 1));
        assert_eq!(capped(&wide), "a".repeat(MAX_LOGGED_API_BYTES - 1));
        let exact = "a".repeat(MAX_LOGGED_API_BYTES);
        assert_eq!(capped(&exact), exact);
    }

    /// DEV-10 (2026-10-16): the browser test page opens a WebSocket to its
    /// `api` parameter, so the page is served only when every `api` names a
    /// loopback address (RFC 1122 §3.2.1.3, RFC 4291 §2.5.3) or
    /// `localhost` (RFC 6761 §6.3); anything else is a `400` and the page
    /// is not sent.
    #[tokio::test]
    async fn rfc1122_s3_2_1_3_the_test_page_refuses_an_api_that_is_not_loopback() {
        let (dir, socket) = fake_daemon("api");
        let (addr, cancel) = start(socket).await;
        for api in [
            "ws://127.0.0.1:1984/api/ws",
            "ws%3A%2F%2F127.0.0.1%3A1984%2Fapi%2Fws",
            "ws://127.255.255.254:1984/api/ws",
            "ws://%5B::1%5D:1984/api/ws",
            "wss://localhost:1984/api/ws",
            "ws://LocalHost/api/ws",
        ] {
            let page = get(addr, &format!("/test?signal=go2rtc&api={api}")).await;
            assert!(page.starts_with("HTTP/1.1 200 OK"), "{api}: {page}");
            assert!(page.contains("window.lotseTest"), "{api}: {page}");
        }
        // Without `api`, or with other parameters only, it is the page.
        for query in [
            "",
            "?signal=go2rtc",
            "?apix=ws://192.0.2.1/",
            "?signal=ws://192.0.2.1/",
        ] {
            let page = get(addr, &format!("/test{query}")).await;
            assert!(page.starts_with("HTTP/1.1 200 OK"), "{query}: {page}");
        }
        for api in [
            "ws://192.0.2.1:1984/api/ws",
            "ws://10.0.0.1/api/ws",
            "ws://%5B2001:db8::1%5D:1984/api/ws",
            "ws://evil.example/api/ws",
            "ws://localhost.evil.example/api/ws",
            "ws://127.0.0.1@evil.example/api/ws",
            "ws%3A%2F%2F192.0.2.1%2F",
            "http://127.0.0.1:1984/api/ws",
            "/api/ws",
            "",
        ] {
            let refused = get(addr, &format!("/test?signal=go2rtc&api={api}")).await;
            assert!(refused.starts_with("HTTP/1.1 400"), "{api}: {refused}");
            assert!(!refused.contains("window.lotseTest"), "{api}: {refused}");
            assert!(
                refused.ends_with(
                    "the api parameter must be a ws:// or wss:// URL of a loopback address\n"
                ),
                "{api}: {refused}"
            );
        }
        // Every `api` counts, not only the first the page reads.
        let second = get(
            addr,
            "/test?api=ws://127.0.0.1/api/ws&api=ws://192.0.2.1/api/ws",
        )
        .await;
        assert!(second.starts_with("HTTP/1.1 400"), "{second}");
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Talk-back (2026-10-11): the opt-in puts the RTSP option
    /// `backchannel`, the offer carries a send-only audio m-line, which the
    /// daemon answers recvonly (RFC 3264 §6.1) when the offer claims the
    /// backchannel, and the microphone goes on it only while Talk is on.
    #[test]
    fn rfc3264_s6_1_talk_back_offers_a_sendonly_m_line_and_sends_only_while_talking() {
        let page = PAGE;
        assert!(page.contains(r#"<input id="talkback" type="checkbox">"#));
        assert!(page.contains(r#"<button id="talk" type="button" class="secondary" disabled"#));
        // The field only when opted in, so a camera without a backchannel
        // never sees the request; the URL's scheme names the protocol.
        assert!(page.contains(
            r#"({ protocol: url.slice(0, url.indexOf("://")).toLowerCase(), url, ...(talkback ? { backchannel: true } : {}) })"#
        ));
        assert!(page.contains(
            r#"call({ type: "stream/put", stream_id: streamId, sources: [source(url, talkback)], orientation })"#
        ));
        // The microphone API exists only in a secure context; without it
        // the offer goes out without talk-back.
        assert!(page.contains(
            r#"if (navigator.mediaDevices?.getUserMedia) {
      talkTransceiver = peer.addTransceiver("audio", { direction: "sendonly" });"#
        ));
        // The offer goes out right after the put's result, talk-back or
        // not: the daemon has it wait for the probe of the backchannel the
        // put opted in to, so the page neither waits nor polls.
        let play = page
            .split("async function play()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("play()");
        let awaited = "const putResult = await put;";
        let put = play.find(awaited).expect("awaits the put") + awaited.len();
        let offer = play.find(r#"type: "webrtc/offer""#).expect("offers");
        let between = &play[put..offer];
        assert!(!between.contains("await"), "{between}");
        assert!(!page.contains(r#"type: "stream/get""#), "no polling");
        assert!(!play.contains("setTimeout("), "no waiting: {play}");
        // A talk-back request the daemon cannot meet is declined in the
        // answer and the session plays on; the page says why and retries
        // nothing itself.
        let warning = page
            .split(r#"case "warning":"#)
            .nth(1)
            .and_then(|rest| rest.split("break;").next())
            .expect("the warning event");
        assert!(
            warning.contains(r#"if (event.code === "backchannel_declined") {"#),
            "{warning}"
        );
        assert!(warning.contains("${event.reason}"), "{warning}");
        assert!(warning.contains("${event.message}"), "{warning}");
        assert!(!warning.contains("play()"), "no retry: {warning}");
        assert!(
            !page.contains("backchannel_unavailable"),
            "a code that is gone"
        );
        // The answer took the m-line when the browser's side is sendonly.
        assert!(page.contains(r#"talkTransceiver.currentDirection === "sendonly""#));
        // The microphone is asked for on Talk, not on Play, and leaves the
        // sender when talking stops.
        assert!(!play.contains("getUserMedia({"), "{play}");
        let start = page
            .split("async function startTalking()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("startTalking()");
        assert!(start.contains("navigator.mediaDevices.getUserMedia({ audio: true })"));
        assert!(start.contains("transceiver.sender.replaceTrack(track)"));
        let stop = page
            .split("async function stopTalking()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("stopTalking()");
        assert!(stop.contains("transceiver.sender.replaceTrack(null)"));
        // Teardown stops the microphone.
        let teardown = page
            .split("function teardown(quiet)")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("teardown()");
        assert!(teardown.contains("releaseMic();"), "{teardown}");
    }

    /// Talk's start and stop are serialized per Play: a stale Play's
    /// failure never touches a later one's controls, and Talk stays
    /// disabled from a press until the re-offer it makes is answered.
    #[test]
    fn talk_controls_follow_only_the_current_play_and_wait_for_the_re_offer() {
        let page = PAGE;
        let start = page
            .split("async function startTalking()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("startTalking()");
        // A stale Play's failure leaves the controls alone: each failure
        // returns for it before touching them, and Talk comes back only
        // for the current one.
        for failed in start.split("} catch (err) {").skip(1) {
            let handler = failed.split("return;\n  }").next().unwrap();
            let stale = handler
                .find("if (mine !== attempt) return;")
                .expect(handler);
            for touch in ["log(", "$(\"talk\")", "releaseMic()"] {
                assert!(
                    handler.find(touch).is_none_or(|at| at > stale),
                    "{touch} before the stale check: {handler}"
                );
            }
            assert!(
                handler.contains("$(\"talk\").disabled = false;"),
                "{handler}"
            );
        }
        // A failed claim stops the microphone and leaves the controls to
        // a later Play the same way.
        let declined = start
            .split("if (mine !== attempt || claimed !== true) {")
            .nth(1)
            .and_then(|rest| rest.split("return;\n  }").next())
            .expect(start);
        let stopped = declined
            .find("for (const track of stream.getTracks()) track.stop();")
            .expect(declined);
        let stale = declined
            .find("if (mine !== attempt) return;")
            .expect(declined);
        assert!(stopped < stale, "{declined}");
        for touch in ["log(", "$(\"talk\")", "$(\"s-talk\")"] {
            assert!(
                declined.find(touch).is_some_and(|at| at > stale),
                "{touch} after the stale check: {declined}"
            );
        }
        let stop = page
            .split("async function stopTalking()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("stopTalking()");
        // Talk stays disabled from the stop until the re-offer dropping
        // talk-back is answered: the browser takes one offer at a time.
        let disabled = stop.find("$(\"talk\").disabled = true;").expect(stop);
        let reoffer = stop.find(r#"await reoffer("inactive", mine)"#).expect(stop);
        let stale = reoffer
            + stop[reoffer..]
                .find("if (mine !== attempt) return;")
                .expect(stop);
        let enabled = stop.rfind("$(\"talk\").disabled = false;").expect(stop);
        assert!(
            disabled < reoffer && reoffer < stale && stale < enabled,
            "{stop}"
        );
    }

    /// Talk-back comes and goes by re-offer (`webrtc/reoffer`, RFC
    /// 8829 §5.2.2): every Talk re-offers the m-line `sendonly`, Stop
    /// talking re-offers it `inactive`, which lets the backchannel go;
    /// nothing releases it by command. A declined claim (answered
    /// `inactive`) leaves the microphone off and Talk usable to ask again;
    /// a refused re-offer is rolled back.
    #[test]
    fn rfc8829_s5_2_2_talk_and_stop_re_offer_talk_back() {
        let page = PAGE;
        assert!(!page.contains("backchannel/release"), "no release command");
        let reoffer = page
            .split("async function reoffer(direction, mine)")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("reoffer()");
        let set = reoffer
            .find("transceiver.direction = direction;")
            .expect(reoffer);
        let offer = reoffer.find("await peer.createOffer()").expect(reoffer);
        let local = reoffer
            .find("await peer.setLocalDescription(offer)")
            .expect(reoffer);
        let posted = reoffer
            .find(r#"call({ type: "webrtc/reoffer", session_id: session, sdp: sent(offer.sdp) })"#)
            .expect(reoffer);
        let remote = reoffer
            .find(
                r#"await peer.setRemoteDescription({ type: "answer", sdp: answered.result.sdp })"#,
            )
            .expect(reoffer);
        assert!(
            set < offer && offer < local && local < posted && posted < remote,
            "{reoffer}"
        );
        // Refused: rolled back, the transceiver as it was.
        let refused = reoffer
            .split("if (!answered.success) {")
            .nth(1)
            .and_then(|rest| rest.split("\n  }").next())
            .expect(reoffer);
        assert!(
            refused.contains(r#"await peer.setLocalDescription({ type: "rollback" });"#)
                && refused.contains("transceiver.direction = before;")
                && refused.contains("return undefined;"),
            "{refused}"
        );
        // Whether the answer gave the session the backchannel.
        assert!(
            reoffer.contains(r#"return transceiver.currentDirection === "sendonly";"#),
            "{reoffer}"
        );
        // The re-offer leaves out what Play's offer left out.
        assert!(page.contains("const sdp = sent(offer.sdp);"));

        let start = page
            .split("async function startTalking()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("startTalking()");
        // Talk claims by re-offer before the microphone goes on the
        // m-line, on every press: an m-line answered recvonly says the
        // session held the backchannel then, and another client's
        // `backchannel/release` frees it without a re-offer, after which
        // the worker drops the session's packets. A regression: Talk once
        // skipped the re-offer while the m-line was negotiated `sendonly`.
        let mic = start
            .find("navigator.mediaDevices.getUserMedia({ audio: true })")
            .expect(start);
        let claim = start
            .find(r#"await reoffer("sendonly", mine)"#)
            .expect(start);
        let on = start
            .find("await transceiver.sender.replaceTrack(track)")
            .expect(start);
        assert!(mic < claim && claim < on, "{start}");
        assert!(!start.contains("currentDirection"), "{start}");
        assert!(
            start.contains("\n  try {\n    claimed = await reoffer(\"sendonly\", mine);"),
            "the re-offer is unconditional: {start}"
        );
        let declined = &start[claim..on];
        assert!(declined.contains("claimed !== true"), "{declined}");
        assert!(
            declined.contains(r#"$("talk").disabled = false;"#),
            "Talk asks again: {declined}"
        );
        // Stop talking drops talk-back only while it holds it.
        let stop = page
            .split("async function stopTalking()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("stopTalking()");
        let held = stop
            .find(r#"if (transceiver.currentDirection === "sendonly") {"#)
            .expect(stop);
        let off = stop
            .find("await transceiver.sender.replaceTrack(null)")
            .expect(stop);
        let drop = stop.find(r#"await reoffer("inactive", mine)"#).expect(stop);
        assert!(off < held && held < drop, "{stop}");
        // A declined offer still leaves Talk usable, to ask again.
        let answered = page
            .split("function answeredTalkback()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("answeredTalkback()");
        assert!(
            answered.contains(r#"$("talk").disabled = false;"#),
            "{answered}"
        );
        // The warning says why a claim was declined.
        assert!(page.contains("event.reason ? ` (${event.reason}"));
    }

    /// A decline's reason belongs to its own negotiation, Play's offer or
    /// a Talk or Stop re-offer (RFC 8829 §5.2.2): the page keeps the
    /// `backchannel_declined` warning's reason, shows it once the answer
    /// is applied, which can be after the warning arrived, as events are
    /// not awaited one after the other, and starts every negotiation
    /// without the last one's. A regression: the status once fell back to
    /// a generic decline as soon as the answer was applied.
    #[test]
    fn rfc8829_s5_2_2_a_decline_reason_stays_with_its_own_negotiation() {
        let page = PAGE;
        let body = |head: &str| {
            page.split(head)
                .nth(1)
                .and_then(|rest| rest.split("\n}\n").next())
                .expect(head)
        };
        // The warning keeps its reason, then shows it.
        let warning = page
            .split(r#"case "warning":"#)
            .nth(1)
            .and_then(|rest| rest.split("break;").next())
            .expect("the warning event");
        let kept = warning
            .find("declinedWhy = `declined (${event.reason}): ${event.message}`;")
            .expect(warning);
        let shown = warning
            .find(r#"$("s-talk").textContent = declinedStatus();"#)
            .expect(warning);
        assert!(kept < shown, "{warning}");
        // The status falls back to a pointer only without a reason.
        assert!(page.contains(
            r#"const declinedStatus = () => `${declinedWhy ?? "declined (the warning says why)"}; Talk asks again`;"#
        ));
        assert_eq!(
            page.matches("the warning says why").count(),
            1,
            "one fallback"
        );
        // Both paths that render after an answer use it.
        assert!(
            body("function answeredTalkback()").contains(
                r#"$("s-talk").textContent = negotiated ? "negotiated; press Talk" : declinedStatus();"#
            ),
            "Play's answer"
        );
        assert!(
            body("async function startTalking()")
                .contains(r#"$("s-talk").textContent = claimed === false ? declinedStatus() :"#),
            "Talk's re-offer"
        );
        // Every negotiation starts without the last one's reason, before
        // its offer, so an earlier reason cannot outlive it.
        let play = body("async function play()");
        let cleared = play.find("declinedWhy = undefined;").expect(play);
        let offer = play.find("await peer.createOffer()").expect(play);
        assert!(cleared < offer, "{play}");
        let reoffer = body("async function reoffer(direction, mine)");
        let cleared = reoffer.find("declinedWhy = undefined;").expect(reoffer);
        let offer = reoffer.find("await peer.createOffer()").expect(reoffer);
        assert!(cleared < offer, "{reoffer}");
        // Set nowhere else: the warning, Play and the re-offers.
        assert_eq!(page.matches("declinedWhy = ").count(), 3, "{page}");
    }

    /// A daemon's live route: reads one request head and sends it to the
    /// test, then writes `head`, then each of `chunks` once the test says
    /// so on `go`, then closes. Needs a runtime: binds a Tokio listener.
    fn fake_live_daemon(
        name: &str,
        head: String,
        chunks: Vec<&'static str>,
    ) -> (
        PathBuf,
        PathBuf,
        tokio::sync::mpsc::UnboundedReceiver<String>,
        tokio::sync::mpsc::UnboundedSender<()>,
    ) {
        let (dir, socket) = socket_dir(name);
        let listener = UnixListener::bind(&socket).unwrap();
        let (requests, asked) = tokio::sync::mpsc::unbounded_channel();
        let (go, mut gone) = tokio::sync::mpsc::unbounded_channel::<()>();
        spawn_named("test.fake_live_daemon", async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8];
                if stream.read(&mut byte).await.unwrap() == 0 {
                    break;
                }
                request.push(byte[0]);
            }
            requests.send(String::from_utf8(request).unwrap()).unwrap();
            stream.write_all(head.as_bytes()).await.unwrap();
            for chunk in chunks {
                let _go = gone.recv().await;
                // The dev viewer may have gone first.
                if stream.write_all(chunk.as_bytes()).await.is_err() {
                    return;
                }
            }
            let _go = gone.recv().await;
        });
        (dir, socket, asked, go)
    }

    /// A client's proxy of a live output's bytes: the path's id checked,
    /// the daemon asked without the browser's `Origin` (which it refuses),
    /// and its chunked body streamed through as it comes (RFC 9112 §7.1),
    /// with its `Content-Type` and never cached (RFC 9111 §5.2.2.5).
    #[tokio::test]
    async fn rfc9112_s7_1_a_live_body_is_relayed_from_the_daemon_as_it_comes() {
        let (dir, socket, mut asked, go) = fake_live_daemon(
            "live",
            "HTTP/1.1 200 OK\r\nContent-Type: video/mp4; codecs=\"avc1.42c01e,mp4a.40.2\"\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nX-Live-Id: 01JL\r\n\r\n".to_owned(),
            vec!["5\r\nfirst\r\n", "6\r\nsecond\r\n0\r\n\r\n"],
        );
        let (addr, cancel) = start(socket).await;
        let mut browser = TcpStream::connect(addr).await.unwrap();
        browser
            .write_all(
                format!(
                    "GET /v0/live/01JL HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: c=1\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let request = asked.recv().await.unwrap();
        assert!(
            request.starts_with("GET /v0/live/01JL HTTP/1.1\r\n"),
            "{request}"
        );
        let lower = request.to_ascii_lowercase();
        assert!(
            !lower.contains("origin:"),
            "the daemon refuses Origin: {request}"
        );
        assert!(
            !lower.contains("cookie:"),
            "nothing of the browser's: {request}"
        );
        // The first chunk reaches the browser before the daemon sends more.
        go.send(()).unwrap();
        let mut response = Vec::new();
        while !String::from_utf8_lossy(&response).contains("first") {
            let mut buffer = [0_u8; 1024];
            let read = browser.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "{}", String::from_utf8_lossy(&response));
            response.extend_from_slice(&buffer[..read]);
        }
        go.send(()).unwrap();
        browser.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        let lower = response.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: video/mp4; codecs=\"avc1.42c01e,mp4a.40.2\"\r\n"),
            "{response}"
        );
        assert!(lower.contains("cache-control: no-store\r\n"), "{response}");
        assert!(
            lower.contains("transfer-encoding: chunked\r\n"),
            "{response}"
        );
        assert!(!lower.contains("x-live-id"), "only the type: {response}");
        assert!(
            response.contains("first") && response.contains("second"),
            "{response}"
        );
        assert!(
            response.ends_with("0\r\n\r\n"),
            "the last chunk: {response}"
        );
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The daemon's refusal reaches the browser as the daemon wrote it:
    /// its status, `Content-Type` and error body.
    #[tokio::test]
    async fn rfc9110_s15_5_5_the_daemon_s_refusal_is_passed_through() {
        let body =
            r#"{"error":{"code":"live_not_found","message":"no open live output has this id"}}"#;
        let head = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (dir, socket, _asked, go) = fake_live_daemon("live-refused", head, Vec::new());
        let (addr, cancel) = start(socket).await;
        let response = get(addr, "/v0/live/01JL").await;
        drop(go);
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{response}"
        );
        let lower = response.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: application/json\r\n"),
            "{response}"
        );
        assert!(lower.contains("cache-control: no-store\r\n"), "{response}");
        assert!(response.contains(body), "{response}");
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The path's id is untrusted: checked against the identifier pattern
    /// before the daemon is asked, as the daemon checks it; a request from
    /// another origin or by a name a rebinding DNS server controls is
    /// refused, and so is one with no daemon to ask.
    #[tokio::test]
    async fn a_live_body_is_refused_for_a_bad_id_another_origin_or_no_daemon() {
        let (dir, socket) = socket_dir("live-checks");
        let (addr, cancel) = start(socket).await;
        for path in [
            "/v0/live/..",
            "/v0/live/.",
            "/v0/live/a%2Fb",
            "/v0/live/a/b",
            "/v0/live/",
        ] {
            let refused = get(addr, path).await;
            assert!(refused.starts_with("HTTP/1.1 404"), "{path}: {refused}");
        }
        let long = format!("/v0/live/{}", "a".repeat(129));
        let refused = get(addr, &long).await;
        assert!(refused.starts_with("HTTP/1.1 404"), "{refused}");
        assert!(refused.ends_with("no such live output\n"), "{refused}");
        for (host, origin) in [
            (format!("{addr}"), Some("http://evil.example".to_owned())),
            (format!("{addr}"), Some(format!("https://{addr}"))),
            (format!("evil.example:{}", addr.port()), None),
            (
                format!("evil.example:{}", addr.port()),
                Some(format!("http://evil.example:{}", addr.port())),
            ),
        ] {
            let origin = origin
                .map(|o| format!("Origin: {o}\r\n"))
                .unwrap_or_default();
            let refused = raw(
                addr,
                &format!("GET /v0/live/01JL HTTP/1.1\r\nHost: {host}\r\n{origin}Connection: close\r\n\r\n"),
            )
            .await;
            assert!(
                refused.starts_with("HTTP/1.1 403"),
                "{host} {origin}: {refused}"
            );
            assert!(
                refused.ends_with("only the viewer's pages may fetch a live output\n"),
                "{refused}"
            );
        }
        let refused = raw(
            addr,
            "GET /v0/live/01JL HTTP/1.1\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(refused.starts_with("HTTP/1.1 4"), "no Host: {refused}");
        let post = raw(
            addr,
            "POST /v0/live/01JL HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        // A good request with no daemon behind the socket.
        let gateway = raw(
            addr,
            &format!(
                "GET /v0/live/01JL HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
                addr.port()
            ),
        )
        .await;
        assert!(gateway.starts_with("HTTP/1.1 502"), "{gateway}");
        assert!(gateway.contains("the daemon's control socket"), "{gateway}");
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A socket that answers no HTTP is a `502`, and so is one that closes
    /// before its answer.
    #[tokio::test]
    async fn a_daemon_that_does_not_answer_is_a_bad_gateway() {
        let (dir, socket) = socket_dir("live-silent");
        let listener = UnixListener::bind(&socket).unwrap();
        spawn_named("test.not_http", async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = [0_u8; 256];
                let _read = stream.read(&mut buffer).await;
                drop(stream);
            }
        });
        let (addr, cancel) = start(socket).await;
        let gateway = get(addr, "/v0/live/01JL").await;
        assert!(gateway.starts_with("HTTP/1.1 502"), "{gateway}");
        assert!(gateway.contains("the daemon did not answer"), "{gateway}");
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The dev viewer stopping ends a live body that is still running.
    #[tokio::test]
    async fn the_dev_viewer_stopping_ends_a_live_body() {
        let (dir, socket, _asked, go) = fake_live_daemon(
            "live-stop",
            "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_owned(),
            vec!["5\r\nfirst\r\n", "0\r\n\r\n"],
        );
        let (addr, cancel) = start(socket).await;
        let mut browser = TcpStream::connect(addr).await.unwrap();
        browser
            .write_all(b"GET /v0/live/01JL HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        go.send(()).unwrap();
        let mut response = Vec::new();
        while !String::from_utf8_lossy(&response).contains("first") {
            let mut buffer = [0_u8; 1024];
            let read = browser.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0);
            response.extend_from_slice(&buffer[..read]);
        }
        cancel.cancel();
        // The body ends, and the connection with it, though the daemon
        // has not ended it.
        browser.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        drop(go);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `HEAD` (which axum's `get` would answer with the `GET` handler)
    /// or any other method is a `405` with `Allow: GET` (RFC 9110
    /// §15.5.6) that never asks the daemon: its `GET` would take the live
    /// output's one body, which the browser's `GET` after it could then
    /// no longer play.
    #[tokio::test]
    async fn rfc9110_s15_5_6_head_is_refused_without_taking_the_live_body() {
        let (dir, socket, mut asked, go) = fake_live_daemon(
            "live-head",
            "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .to_owned(),
            vec!["5\r\nfirst\r\n0\r\n\r\n"],
        );
        let (addr, cancel) = start(socket).await;
        for method in ["HEAD", "POST", "PUT", "DELETE"] {
            let refused = raw(
                addr,
                &format!("{method} /v0/live/01JL HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            )
            .await;
            assert!(
                refused.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
                "{method}: {refused}"
            );
            let lower = refused.to_ascii_lowercase();
            assert!(lower.contains("\r\nallow: get\r\n"), "{method}: {refused}");
            assert!(
                asked.try_recv().is_err(),
                "{method} reached the daemon: {refused}"
            );
        }
        // The daemon's one body is still there for the browser's GET.
        go.send(()).unwrap();
        go.send(()).unwrap();
        let response = get(addr, "/v0/live/01JL").await;
        assert!(
            asked
                .recv()
                .await
                .unwrap()
                .starts_with("GET /v0/live/01JL HTTP/1.1\r\n")
        );
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("first"), "{response}");
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_live_id_is_the_path_s_one_segment_checked_against_the_identifier_pattern() {
        assert_eq!(live_id_of("/v0/live/01JL").unwrap().as_str(), "01JL");
        for path in [
            "/v0/live",
            "/v0/live/",
            "/v0/live/..",
            "/v0/livex/01JL",
            "/v0/recording/01JL",
        ] {
            assert!(live_id_of(path).is_none(), "{path}");
        }
        let with = |list: &[(&str, &str)]| may_fetch(&headers(list));
        assert!(
            with(&[("host", "127.0.0.1:8080")]),
            "a same-origin fetch has no Origin"
        );
        assert!(with(&[
            ("host", "127.0.0.1:8080"),
            ("origin", "http://127.0.0.1:8080")
        ]));
        assert!(!with(&[("origin", "http://127.0.0.1:8080")]), "no Host");
        assert!(!with(&[("host", "evil.example")]), "DNS rebinding");
        assert!(!with(&[
            ("host", "127.0.0.1:8080"),
            ("origin", "http://evil.example")
        ]));
        // W3C Fetch Metadata §2.1.2: a request of another site is refused
        // even without an Origin (a no-cors fetch, a media element's load).
        for site in ["cross-site", "same-site"] {
            assert!(
                !with(&[("host", "127.0.0.1:8080"), ("sec-fetch-site", site)]),
                "{site}"
            );
        }
        for site in ["same-origin", "none"] {
            assert!(
                with(&[("host", "127.0.0.1:8080"), ("sec-fetch-site", site)]),
                "{site}"
            );
        }
    }

    /// A client's proxy of an LL-HLS session: the playlist's Blocking
    /// Playlist Reload (draft-pantos-hls-rfc8216bis-22 §6.2.5.2) reaches the
    /// daemon with its Delivery Directives as they were sent, without the
    /// browser's `Origin` (which the daemon refuses) or anything else of the
    /// browser's, and is held until the daemon answers; its status,
    /// `Content-Type` (§4), `Content-Length`, `Cache-Control` and body come
    /// back as the daemon sent them, nothing else.
    #[tokio::test]
    async fn rfc8216bis_s6_2_5_2_a_blocking_playlist_reload_is_held_and_passed_through() {
        let playlist = "#EXTM3U\n#EXT-X-TARGETDURATION:1\n";
        let answer: &'static str = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\nX-Hls-Id: 01JH\r\n\r\n{playlist}",
            playlist.len()
        )
        .leak();
        // Nothing until the test says so: the daemon holds the request.
        let (dir, socket, mut asked, go) =
            fake_live_daemon("hls-playlist", String::new(), vec![answer]);
        let (addr, cancel) = start(socket).await;
        let mut browser = TcpStream::connect(addr).await.unwrap();
        browser
            .write_all(
                format!(
                    "GET /v0/hls/01JH/index.m3u8?_HLS_msn=12&_HLS_part=3 HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: c=1\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let request = asked.recv().await.unwrap();
        assert!(
            request.starts_with("GET /v0/hls/01JH/index.m3u8?_HLS_msn=12&_HLS_part=3 HTTP/1.1\r\n"),
            "{request}"
        );
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("host: lotse\r\n"), "{request}");
        assert!(
            !lower.contains("origin:"),
            "the daemon refuses Origin: {request}"
        );
        assert!(
            !lower.contains("cookie:"),
            "nothing of the browser's: {request}"
        );
        lotse_core::clock::Clock::sleep(
            &lotse_core::clock::SystemClock,
            std::time::Duration::from_millis(200),
        )
        .await;
        let mut early = [0_u8; 1];
        assert!(
            browser.try_read(&mut early).is_err(),
            "held while the daemon holds it"
        );
        go.send(()).unwrap();
        let mut response = Vec::new();
        browser.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        let lower = response.to_ascii_lowercase();
        for field in [
            "content-type: application/vnd.apple.mpegurl\r\n".to_owned(),
            "cache-control: no-cache\r\n".to_owned(),
            format!("content-length: {}\r\n", playlist.len()),
        ] {
            assert!(lower.contains(&field), "{field}: {response}");
        }
        assert!(!lower.contains("x-hls-id"), "{response}");
        assert!(
            !lower.contains("transfer-encoding"),
            "the length, not chunks: {response}"
        );
        assert!(response.ends_with(playlist), "{response}");
        drop(go);
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A part (§3.2) is asked for by its name as the playlist writes it, with
    /// whatever query came along, and comes back with its `max-age`; the
    /// daemon's refusal of a resource comes back as the daemon wrote it.
    #[tokio::test]
    async fn rfc8216bis_s3_2_a_part_and_the_daemon_s_refusal_are_passed_through() {
        let part = "moofmdat";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nCache-Control: max-age=60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{part}",
            part.len()
        );
        let (dir, socket, mut asked, go) = fake_live_daemon("hls-part", head, Vec::new());
        let (addr, cancel) = start(socket).await;
        let response = get(addr, "/v0/hls/01JH/part7.2.m4s?v=1").await;
        drop(go);
        let request = asked.recv().await.unwrap();
        assert!(
            request.starts_with("GET /v0/hls/01JH/part7.2.m4s?v=1 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        let lower = response.to_ascii_lowercase();
        assert!(lower.contains("content-type: video/mp4\r\n"), "{response}");
        assert!(
            lower.contains("cache-control: max-age=60\r\n"),
            "{response}"
        );
        assert!(lower.contains("content-length: 8\r\n"), "{response}");
        assert!(response.ends_with(part), "{response}");
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();

        let body = r#"{"error":{"code":"hls_resource_not_found","message":"the session's window holds no such resource"}}"#;
        let head = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (dir, socket, mut asked, go) = fake_live_daemon("hls-refused", head, Vec::new());
        let (addr, cancel) = start(socket).await;
        let response = get(addr, "/v0/hls/01JH/seg3.m4s").await;
        drop(go);
        assert!(
            asked
                .recv()
                .await
                .unwrap()
                .starts_with("GET /v0/hls/01JH/seg3.m4s HTTP/1.1\r\n"),
            "no query, none added"
        );
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{response}"
        );
        let lower = response.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: application/json\r\n"),
            "{response}"
        );
        assert!(!lower.contains("cache-control"), "{response}");
        assert!(response.ends_with(body), "{response}");
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The id, the name and the query are untrusted: each checked before the
    /// daemon is asked; a request from another origin or by a name a
    /// rebinding DNS server controls is refused, and so is one with no
    /// daemon to ask.
    #[tokio::test]
    async fn an_ll_hls_request_is_refused_for_a_bad_name_or_query_another_origin_or_no_daemon() {
        let (dir, socket) = socket_dir("hls-checks");
        let (addr, cancel) = start(socket).await;
        for (path, reason) in [
            ("/v0/hls/../index.m3u8", "no such LL-HLS session\n"),
            ("/v0/hls/a%2Fb/index.m3u8", "no such LL-HLS session\n"),
            ("/v0/hls/01JH/seg01.m4s", "no such LL-HLS resource\n"),
            ("/v0/hls/01JH/index.m3u", "no such LL-HLS resource\n"),
            ("/v0/hls/01JH/..", "no such LL-HLS resource\n"),
            // No name: no route.
            ("/v0/hls/01JH/", "not found\n"),
        ] {
            let refused = get(addr, path).await;
            assert!(refused.starts_with("HTTP/1.1 404"), "{path}: {refused}");
            assert!(refused.ends_with(reason), "{path}: {refused}");
        }
        let long = format!("/v0/hls/{}/index.m3u8", "a".repeat(129));
        assert!(get(addr, &long).await.ends_with("no such LL-HLS session\n"));
        for query in [
            format!("v={}", "1".repeat(MAX_HLS_QUERY_BYTES - 1)),
            "_HLS_msn=1;x".to_owned(),
            "a=b+c".to_owned(),
            "a=/".to_owned(),
        ] {
            let refused = get(addr, &format!("/v0/hls/01JH/index.m3u8?{query}")).await;
            assert!(refused.starts_with("HTTP/1.1 400"), "{query}: {refused}");
            assert!(
                refused.ends_with("the query is not one the daemon takes\n"),
                "{refused}"
            );
        }
        for (host, origin) in [
            (format!("{addr}"), Some("http://evil.example".to_owned())),
            (format!("evil.example:{}", addr.port()), None),
        ] {
            let origin = origin
                .map(|o| format!("Origin: {o}\r\n"))
                .unwrap_or_default();
            let refused = raw(
                addr,
                &format!("GET /v0/hls/01JH/index.m3u8 HTTP/1.1\r\nHost: {host}\r\n{origin}Connection: close\r\n\r\n"),
            )
            .await;
            assert!(
                refused.starts_with("HTTP/1.1 403"),
                "{host} {origin}: {refused}"
            );
            assert!(
                refused.ends_with("only the viewer's pages may fetch an LL-HLS session\n"),
                "{refused}"
            );
        }
        let post = raw(
            addr,
            "POST /v0/hls/01JH/index.m3u8 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        // RFC 9110 §15.5.6: HEAD is refused here too, without the daemon: with
        // no daemon behind the socket, asking it would be a 502.
        let head = raw(
            addr,
            "HEAD /v0/hls/01JH/index.m3u8 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 405"), "{head}");
        assert!(
            head.to_ascii_lowercase().contains("\r\nallow: get\r\n"),
            "{head}"
        );
        // Good requests, the longest query among them, with no daemon behind
        // the socket.
        let longest = format!("v={}", "1".repeat(MAX_HLS_QUERY_BYTES - 2));
        for path in [
            format!("/v0/hls/01JH/index.m3u8?{longest}"),
            "/v0/hls/01JH/init.mp4?".to_owned(),
        ] {
            let gateway = get(addr, &path).await;
            assert!(gateway.starts_with("HTTP/1.1 502"), "{path}: {gateway}");
            assert!(gateway.contains("the daemon's control socket"), "{gateway}");
        }
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rfc8216bis_s4_1_an_ll_hls_target_is_the_name_the_playlist_writes() {
        let target = |path: &str, query: Option<&str>| hls_target_of(path, query);
        assert_eq!(
            target("/v0/hls/01JH/index.m3u8", Some("_HLS_msn=1&_HLS_part=0")).unwrap(),
            "/v0/hls/01JH/index.m3u8?_HLS_msn=1&_HLS_part=0"
        );
        assert_eq!(
            target("/v0/hls/01JH/index.m3u8", Some("")).unwrap(),
            "/v0/hls/01JH/index.m3u8",
            "an empty query, none"
        );
        for name in ["init.mp4", "seg0.m4s", "part18446744073709551615.9.m4s"] {
            assert_eq!(
                target(&format!("/v0/hls/01JH/{name}"), None).unwrap(),
                format!("/v0/hls/01JH/{name}")
            );
        }
        for path in [
            "/v0/hls",
            "/v0/hls/",
            "/v0/hls/01JH",
            "/v0/hlsx/01JH/index.m3u8",
            "/v0/live/01JH/index.m3u8",
            "/v0/hls/./index.m3u8",
        ] {
            assert_eq!(
                target(path, None).unwrap_err(),
                (StatusCode::NOT_FOUND, "no such LL-HLS session"),
                "{path}"
            );
        }
        for path in [
            "/v0/hls/01JH/index.m3u8/x",
            "/v0/hls/01JH/seg-1.m4s",
            "/v0/hls/01JH/part1.m4s",
            "/v0/hls/01JH/INIT.MP4",
        ] {
            assert_eq!(
                target(path, None).unwrap_err(),
                (StatusCode::NOT_FOUND, "no such LL-HLS resource"),
                "{path}"
            );
        }
        let longest = "a".repeat(MAX_HLS_QUERY_BYTES);
        assert!(target("/v0/hls/01JH/init.mp4", Some(&longest)).is_ok());
        let longer = "a".repeat(MAX_HLS_QUERY_BYTES + 1);
        assert_eq!(
            target("/v0/hls/01JH/init.mp4", Some(&longer))
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        assert!(target("/v0/hls/01JH/init.mp4", Some("a-b.c~d%20e_f=1&g")).is_ok());
    }

    type Connected = Result<
        (
            WebSocketStream<TcpStream>,
            tokio_tungstenite::tungstenite::handshake::client::Response,
        ),
        tokio_tungstenite::tungstenite::Error,
    >;

    async fn connect(addr: SocketAddr, url: String, origin: Option<String>) -> Connected {
        let mut request = url.into_client_request().unwrap();
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert("Origin", HeaderValue::from_str(&origin).unwrap());
        }
        let tcp = TcpStream::connect(addr).await.unwrap();
        tokio_tungstenite::client_async(request, tcp).await
    }

    fn refused(result: Connected) -> (u16, String) {
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => (
                response.status().as_u16(),
                String::from_utf8_lossy(response.body().as_deref().unwrap_or_default())
                    .into_owned(),
            ),
            Err(err) => panic!("{err}"),
            Ok(_) => panic!("accepted"),
        }
    }

    #[tokio::test]
    async fn relays_the_page_to_the_daemon_and_refuses_other_origins() {
        let (dir, socket) = fake_daemon("relay");
        let (addr, cancel) = start(socket).await;
        let url = format!("ws://{addr}{RELAY_PATH}");
        let (status, body) = refused(connect(addr, url.clone(), None).await);
        assert_eq!(status, 403, "no Origin: not a page");
        assert_eq!(body, "only the viewer page may connect\n");
        assert_eq!(
            refused(connect(addr, url.clone(), Some("http://evil.example".into())).await).0,
            403
        );
        let rebound = format!("ws://evil.example:{}{RELAY_PATH}", addr.port());
        let rebound_origin = format!("http://evil.example:{}", addr.port());
        assert_eq!(
            refused(connect(addr, rebound, Some(rebound_origin)).await).0,
            403,
            "DNS rebinding"
        );

        let origin = Some(format!("http://{addr}"));
        let (mut ws, _) = connect(addr, url.clone(), origin.clone()).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            Message::text(r#"{"type":"hello"}"#)
        );
        // A binary frame is not the API's: dropped, and the relay goes on.
        ws.send(Message::binary(vec![1, 2, 3])).await.unwrap();
        ws.send(Message::text("ping")).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            Message::text("echo ping"),
            "the daemon's ping stays between the relay and the daemon"
        );
        // A message as large as the daemon takes is relayed.
        let largest = "x".repeat(MAX_MESSAGE_BYTES);
        ws.send(Message::text(largest.clone())).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            Message::text(format!("echo {largest}"))
        );
        ws.close(None).await.unwrap();

        // DEV-4 (2026-10-05): one byte more ends the relay instead of
        // reaching the daemon, as one frame and as fragments alike.
        let too_large = "x".repeat(MAX_MESSAGE_BYTES + 1);
        for fragmented in [false, true] {
            let (mut ws, _) = connect(addr, url.clone(), origin.clone()).await.unwrap();
            let _hello = ws.next().await.unwrap().unwrap();
            if fragmented {
                let half = MAX_MESSAGE_BYTES / 2 + 1;
                let frames = [
                    Frame::message(
                        too_large[..half].to_owned(),
                        OpCode::Data(Data::Text),
                        false,
                    ),
                    Frame::message(
                        too_large[half..].to_owned(),
                        OpCode::Data(Data::Continue),
                        true,
                    ),
                ];
                for frame in frames {
                    ws.send(Message::Frame(frame)).await.unwrap();
                }
            } else {
                ws.send(Message::text(too_large.clone())).await.unwrap();
            }
            let ended = ws.next().await;
            assert!(
                matches!(ended, None | Some(Ok(Message::Close(_)) | Err(_))),
                "fragmented {fragmented}: {ended:?}"
            );
        }

        // The dev viewer stopping ends an open relay.
        let (mut ws, _) = connect(addr, url.clone(), origin.clone()).await.unwrap();
        let _hello = ws.next().await.unwrap().unwrap();
        cancel.cancel();
        assert!(
            matches!(ws.next().await, None | Some(Ok(Message::Close(_)) | Err(_))),
            "the relay ends with the server"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn without_a_daemon_the_relay_is_a_bad_gateway() {
        let (dir, socket) = socket_dir("gateway");
        let (addr, cancel) = start(socket.clone()).await;
        let url = format!("ws://{addr}{RELAY_PATH}");
        let origin = Some(format!("http://{addr}"));
        // No daemon behind the socket.
        let (status, body) = refused(connect(addr, url.clone(), origin.clone()).await);
        assert_eq!(status, 502);
        assert!(body.starts_with("the daemon's control socket"), "{body}");
        // A socket that is no WebSocket server.
        let listener = UnixListener::bind(&socket).unwrap();
        spawn_named("test.not_a_daemon", async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let (status, body) = refused(connect(addr, url, origin).await);
        assert_eq!(
            (status, body.as_str()),
            (502, "the daemon refused the upgrade\n")
        );
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn the_daemon_closing_ends_the_relay() {
        let (dir, socket) = socket_dir("daemon-close");
        let listener = UnixListener::bind(&socket).unwrap();
        spawn_named("test.closing_daemon", async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ws.close(None).await.unwrap();
            while ws.next().await.is_some() {}
        });
        let (addr, cancel) = start(socket).await;
        let (mut ws, _) = connect(
            addr,
            format!("ws://{addr}{RELAY_PATH}"),
            Some(format!("http://{addr}")),
        )
        .await
        .unwrap();
        assert!(
            matches!(ws.next().await, None | Some(Ok(Message::Close(_)) | Err(_))),
            "the browser sees the end"
        );
        cancel.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
