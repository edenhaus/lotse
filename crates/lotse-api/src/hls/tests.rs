#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use std::io;
use std::sync::Arc;

use super::*;

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
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    io::Write::flush(&mut captured.clone()).unwrap();
    (captured, tracing::subscriber::set_default(subscriber))
}

fn peer() -> PeerInfo {
    PeerInfo::Unix { uid: 0, pid: None }
}

/// `admit` for a request to `path?query` with `headers`, from a client
/// `removed` or not, while `shutting_down` or not.
fn admit_as(
    (removed, shutting_down): (bool, bool),
    path: &str,
    query: &str,
    headers: &HeaderMap,
) -> Result<(HlsId, HlsRequest), Box<Response>> {
    let peer = peer();
    admit(&Request {
        peer: &peer,
        removed,
        headers,
        path,
        query,
        shutting_down,
    })
}

async fn status_and_error(response: Response) -> (u16, serde_json::Value) {
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let error = serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default();
    (status, error)
}

fn id(raw: &str) -> HlsId {
    HlsId::new(raw).unwrap()
}

#[test]
fn rfc8216bis_6_2_5_2_a_request_names_its_session_and_the_playlist_with_its_directives_or_a_resource()
 {
    for (path, query, expected) in [
        (
            "/v0/hls/01JH/index.m3u8",
            "",
            HlsRequest::Playlist(Blocking::None),
        ),
        (
            "/v0/hls/01JH/index.m3u8",
            "_HLS_msn=4&_HLS_part=2",
            HlsRequest::Playlist(Blocking::Part { msn: 4, part: 2 }),
        ),
        (
            "/v0/hls/01JH/index.m3u8",
            "_HLS_msn=4&cache=1",
            HlsRequest::Playlist(Blocking::Segment { msn: 4 }),
        ),
        (
            "/v0/hls/01JH/init.mp4",
            "",
            HlsRequest::Media(Resource::Init),
        ),
        (
            "/v0/hls/01JH/seg7.m4s",
            "_HLS_msn=x",
            HlsRequest::Media(Resource::Segment { msn: 7 }),
        ),
        (
            "/v0/hls/01JH/part7.3.m4s",
            "",
            HlsRequest::Media(Resource::Part { msn: 7, index: 3 }),
        ),
    ] {
        assert_eq!(
            hls_request_of(path, query),
            Ok((id("01JH"), expected)),
            "{path}?{query}"
        );
    }
}

#[test]
fn rfc3986_3_3_a_path_that_names_no_session_or_resource_is_refused_before_any_lookup() {
    for path in [
        "/v0/hls",
        "/v0/hls/",
        "/v0/hls/01JH",
        "/v0/hls/../index.m3u8",
        "/v0/hls/a%2Fb/index.m3u8",
        "/v0/hlsx/01JH/index.m3u8",
        "/v0/live/01JH/index.m3u8",
    ] {
        assert_eq!(
            hls_request_of(path, ""),
            Err(HlsPathError::Session),
            "{path}"
        );
    }
    for path in [
        "/v0/hls/01JH/",
        "/v0/hls/01JH/seg01.m4s",
        "/v0/hls/01JH/index.m3u",
        "/v0/hls/01JH/a/index.m3u8",
        "/v0/hls/01JH/part1.m4s",
    ] {
        assert_eq!(
            hls_request_of(path, ""),
            Err(HlsPathError::Resource),
            "{path}"
        );
    }
    assert_eq!(
        hls_request_of("/v0/hls/01JH/index.m3u8", "_HLS_part=1"),
        Err(HlsPathError::Directive(DirectiveError::PartWithoutMsn))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9110_15_5_a_request_the_route_refuses_gets_the_error_body() {
    let (logs, _guard) = capture();
    let mut browser = HeaderMap::new();
    browser.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://example.com"),
    );
    let none = HeaderMap::new();
    // RFC 6455 §10.2, as the upgrade.
    let refused = admit_as((false, false), "/v0/hls/01JH/index.m3u8", "", &browser)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(
        status_and_error(*refused).await,
        (
            403,
            serde_json::json!({ "code": "invalid_request",
                "message": "requests carrying Origin are refused: the control API is not for browsers" })
        )
    );
    let refused = admit_as((false, true), "/v0/hls/01JH/index.m3u8", "", &none)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(status_and_error(*refused).await.1["code"], "shutting_down");
    let refused = admit_as((true, false), "/v0/hls/01JH/index.m3u8", "", &none)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(refused.headers()[header::CONNECTION], "close");
    assert_eq!(
        status_and_error(*refused).await,
        (
            403,
            serde_json::json!({ "code": "not_permitted", "message": "the client was removed" })
        )
    );
    for (path, query, (status, code)) in [
        ("/v0/hls/secret secret/init.mp4", "", (404, "hls_not_found")),
        (
            "/v0/hls/01JH/secret.m4s",
            "",
            (404, "hls_resource_not_found"),
        ),
        (
            "/v0/hls/01JH/index.m3u8",
            "_HLS_msn=-1",
            (400, "invalid_request"),
        ),
    ] {
        let refused = admit_as((false, false), path, query, &none)
            .map(|_| ())
            .unwrap_err();
        assert!(refused.headers().get(header::CONNECTION).is_none());
        let (got, error) = status_and_error(*refused).await;
        assert_eq!((got, error["code"].as_str().unwrap()), (status, code));
    }
    let allowed = not_allowed().await;
    assert_eq!(allowed.headers()[header::ALLOW], "GET");
    assert_eq!(status_and_error(allowed).await.1["code"], "invalid_request");
    let text = logs.text();
    for line in [
        "LL-HLS request refused: the request carries Origin",
        "LL-HLS request refused: its client was removed",
        "LL-HLS request refused: the path names no session id",
        "LL-HLS request refused: the name is no resource's",
        "LL-HLS request refused: a malformed delivery directive",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    assert!(!text.contains("secret"), "{text}");
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216bis_4_a_playlist_is_an_uncached_mpegurl_of_its_length_on_a_closing_connection() {
    let (logs, _guard) = capture();
    let text = "#EXTM3U\n".to_owned();
    let answer = (HlsReply::Playlist(text.clone()), InFlight::default());
    let response = reply(&peer(), &id("01JH"), Ok(answer));
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "application/vnd.apple.mpegurl"
    );
    assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
    assert_eq!(headers[header::CONTENT_LENGTH], "8");
    assert_eq!(headers[header::CONNECTION], "close");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(&body[..], text.as_bytes());
    assert!(logs.text().contains("LL-HLS playlist sent"));
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216bis_3_1_2_a_resource_is_its_chunks_as_mp4_of_their_length() {
    let (logs, _guard) = capture();
    // A window's segment of two fragments is two slices, sent as they are.
    let mut window =
        lotse_hls::Window::new(lotse_hls::Config::default(), Bytes::from_static(b"init")).unwrap();
    for (bytes, independent, ms) in [
        (&b"moof"[..], true, 600),
        (&b"mdat"[..], false, 600),
        (&b"next"[..], true, 600),
    ] {
        window
            .push(lotse_hls::Fragment {
                bytes: Bytes::from_static(bytes),
                independent,
                duration: std::time::Duration::from_millis(ms),
            })
            .unwrap();
    }
    let lotse_hls::Lookup::Ready(segment) = window.get(Resource::Segment { msn: 0 }) else {
        panic!("the first segment is complete");
    };
    assert!(segment.as_slice().len() > 1, "{segment:?}");
    let answer = (HlsReply::Media(segment), InFlight::default());
    let response = reply(&peer(), &id("01JH"), Ok(answer));
    let headers = response.headers().clone();
    assert_eq!(headers[header::CONTENT_TYPE], "video/mp4");
    assert_eq!(headers[header::CACHE_CONTROL], "max-age=60");
    assert_eq!(headers[header::CONTENT_LENGTH], "8");
    assert_eq!(headers[header::CONNECTION], "close");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(&body[..], b"moofmdat");
    assert!(logs.text().contains("LL-HLS resource sent"));
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216bis_6_2_5_2_the_handler_s_refusals_map_to_their_status_and_code() {
    let (logs, _guard) = capture();
    for (error, status, code) in [
        (HlsError::NotFound, 404, "hls_not_found"),
        (HlsError::ResourceNotFound, 404, "hls_resource_not_found"),
        (HlsError::BadRequest, 400, "invalid_request"),
        // RFC 6585 §4.
        (
            HlsError::TooManyBlocked {
                limit: "max_hls_blocked",
            },
            429,
            "limit_reached",
        ),
        (
            HlsError::TooManyRequests {
                limit: "max_hls_requests",
            },
            429,
            "limit_reached",
        ),
        (HlsError::Timeout, 503, "source_timeout"),
    ] {
        let response = reply(&peer(), &id("01JH"), Err(error));
        assert_eq!(response.headers()[header::CONNECTION], "close");
        let (got, body) = status_and_error(response).await;
        assert_eq!((got, body["code"].as_str().unwrap()), (status, code));
        if let HlsError::TooManyBlocked { limit } | HlsError::TooManyRequests { limit } = error {
            assert_eq!(body["details"]["limit"], limit);
            assert_eq!(
                body["message"],
                error.to_string().split(" (").next().unwrap()
            );
        }
    }
    assert!(logs.text().contains("LL-HLS request refused"));
    assert_eq!(
        HlsError::TooManyBlocked {
            limit: "max_hls_blocked_per_session"
        }
        .to_string(),
        "too many blocked requests (max_hls_blocked_per_session)"
    );
    assert_eq!(
        HlsError::TooManyRequests {
            limit: "max_hls_requests_per_session"
        }
        .to_string(),
        "too many requests in flight (max_hls_requests_per_session)"
    );
}

/// An [`InFlight`] of one place of a one-place semaphore, and the
/// semaphore.
fn one_place() -> (InFlight, Arc<tokio::sync::Semaphore>) {
    let places = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = Arc::clone(&places).try_acquire_owned().unwrap();
    (InFlight::new(vec![permit]), places)
}

/// A response's body holds its place among the requests in flight while
/// it has parts to send, and gives it back as its last part is taken,
/// though the body is not dropped yet.
#[tokio::test(flavor = "current_thread")]
async fn a_body_holds_its_place_in_flight_until_its_last_part_is_taken() {
    use futures_util::StreamExt as _;

    let (in_flight, places) = one_place();
    let parts = vec![Bytes::from_static(b"moof"), Bytes::from_static(b"mdat")];
    let mut sending = Sending::new(parts, in_flight);
    for part in [&b"moof"[..], b"mdat"] {
        assert_eq!(places.available_permits(), 0, "parts left");
        assert_eq!(sending.next().await.unwrap().unwrap(), part);
    }
    assert_eq!(places.available_permits(), 0, "the end not taken yet");
    assert!(sending.next().await.is_none());
    assert_eq!(places.available_permits(), 1, "sent");
    assert!(sending.next().await.is_none());
    assert_eq!(places.available_permits(), 1);
}

/// A response's body dropped before its end, as when its client goes,
/// gives its place back; so does the response it is the body of.
#[tokio::test(flavor = "current_thread")]
async fn a_body_dropped_unsent_gives_its_place_in_flight_back() {
    use futures_util::StreamExt as _;

    let (in_flight, places) = one_place();
    let mut sending = Sending::new(vec![Bytes::from_static(b"moof")], in_flight);
    assert!(sending.next().await.is_some());
    drop(sending);
    assert_eq!(places.available_permits(), 1);
    let (in_flight, places) = one_place();
    let answer = (HlsReply::Playlist("#EXTM3U\n".to_owned()), in_flight);
    let response = reply(&peer(), &id("01JH"), Ok(answer));
    assert_eq!(places.available_permits(), 0, "the response holds it");
    drop(response);
    assert_eq!(places.available_permits(), 1);
}
