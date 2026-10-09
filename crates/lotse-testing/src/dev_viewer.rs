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
//! own origin. A browser message the daemon would refuse as too large is
//! refused at the relay already. A development tool, never part of the
//! daemon.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{self, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, HeaderName, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt as _, StreamExt as _};
use sha2::{Digest as _, Sha256};
use tokio::net::{TcpListener, UnixStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

/// The page, which speaks the control API through the relay.
pub const PAGE: &str = include_str!("dev_viewer.html");

/// The relay's path.
pub const RELAY_PATH: &str = "/ws";

/// The largest message the relay takes from a page, and its largest frame:
/// the daemon's own inbound limit, 64 KiB (`lotse_api::MAX_MESSAGE_BYTES`),
/// so a larger one is refused before the relay buffers it rather than by the
/// daemon after tungstenite's 64 MiB default.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The browser test's page's policy: not framed (CSP Level 3 §6.4.2).
/// Nothing else, because it runs its worker and audio worklet from `blob:`
/// URLs and, for the comparison, signals to a server on another
/// origin; it holds
/// no credentials and runs in the test's own browser profile.
const TEST_PAGE_POLICY: &str = "frame-ancestors 'none'";

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

/// The routes: the page, the browser test's page and the relay; anything
/// else is `404` (axum answers a wrong method on a route `405`, and a
/// malformed request or upgrade `400`).
fn router(socket: PathBuf, cancel: CancellationToken) -> Router {
    Router::new()
        .route("/", get(|| async { page(PAGE, PAGE_POLICY.as_str()) }))
        .route(
            crate::browser::PAGE_PATH,
            get(|| async { page(crate::browser::PAGE, TEST_PAGE_POLICY) }),
        )
        .route(RELAY_PATH, get(upgrade))
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
    use lotse_core::task::spawn_named;

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

    /// `GET path` with `Connection: close`, so the server ends the
    /// connection after its response.
    async fn get(addr: SocketAddr, path: &str) -> String {
        raw(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        )
        .await
    }

    /// The page keeps saved camera URLs in localStorage without their
    /// userinfo (RFC 3986 §3.2.1) and the userinfo in sessionStorage only.
    #[test]
    fn rfc3986_s3_2_1_the_page_keeps_no_userinfo_in_local_storage() {
        let page = PAGE;
        let save = page
            .split("function save()")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("the page saves its settings in save()");
        // Credentials never reach localStorage, which outlives the tab and
        // any page later served on the origin reads (DEV-1, 2026-10-05):
        // every URL it gets is split at its userinfo (RFC 3986 §3.2.1), and
        // the userinfo goes to sessionStorage.
        let (local, session) = save
            .split_once("sessionStorage.setItem(STORE,")
            .expect("the credentials go to sessionStorage");
        let local = local
            .split_once("localStorage.setItem(STORE,")
            .expect("the settings go to localStorage")
            .1;
        assert!(
            save.contains("const current = splitUserinfo(cameraUrl);")
                && save.contains("entries.map((e) => ({ entry: e, ...splitUserinfo(e.url) }))"),
            "{save}"
        );
        assert!(
            local.contains("url: current.bare,")
                && local
                    .contains("saved: split.map(({ entry, bare }) => ({ ...entry, url: bare })),")
                && !local.contains("cameraUrl")
                && !local.contains("userinfo")
                && !local.contains("entries"),
            "localStorage gets URLs without userinfo only: {local}"
        );
        assert!(
            session.contains("url: current.userinfo,")
                && session.contains("[s.entry.id, s.userinfo]"),
            "{session}"
        );
        // The userinfo ends at the authority's last `@`: the split and
        // the mask take the same greedy run of authority characters.
        assert!(page.contains(r"/^([a-z][a-z0-9+.-]*:\/\/)([^\/?#]*@)/i.exec(url)"));
        // A reload puts this tab's credentials back; a stored URL with its
        // own userinfo, or anything not userinfo, is left as it is.
        assert!(page.contains(
            r#"if (typeof userinfo !== "string" || !/^[^\/?#]*@$/.test(userinfo) || splitUserinfo(url).userinfo) return url;"#
        ));
        assert!(page.contains("url: withUserinfo(e.url, savedCredentials.get(e.id)),"));
        assert!(page.contains("withUserinfo(saved.url, credentials.url)"));
        // Saved streams match without their userinfo, so the password
        // typed again in a new tab updates the entry instead of adding one.
        assert!(page.contains("splitUserinfo(e.url).bare === bare && e.stream === stream"));
        // What earlier pages stored with credentials is rewritten on load.
        let migrate = page
            .split("if (hasUserinfo(saved.url) || (Array.isArray(saved.saved) && saved.saved.some((e) => hasUserinfo(e?.url)))) {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("stored credentials are scrubbed on load");
        assert!(migrate.contains("save();"), "{migrate}");
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
        assert!(page.contains("sources: [{ url }], orientation }"));
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
            r#"send({ type: "stream/put", stream_id: streamId, sources: [{ url }], orientation }"#
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
