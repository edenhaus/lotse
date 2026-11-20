#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;

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
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    io::Write::flush(&mut captured.clone()).unwrap();
    (captured, tracing::subscriber::set_default(subscriber))
}

/// A refusal case: how the request comes, its header fields, the status
/// and code it gets.
type Case<'a> = ((bool, Version, bool), &'a HeaderMap, (u16, &'a str));

fn peer() -> PeerInfo {
    PeerInfo::Unix { uid: 0, pid: None }
}

/// `answer` for a request in `version` to `path` with `headers`, from a
/// client `removed` or not, while `shutting_down` or not.
fn answer_as(
    (removed, version, shutting_down): (bool, Version, bool),
    path: &str,
    headers: &HeaderMap,
    body: &BodyWatch,
    lookup: &dyn Fn(&LiveId) -> Result<LiveBody, LiveBodyError>,
) -> Response {
    let peer = peer();
    let request = Request {
        peer: &peer,
        removed,
        version,
        headers,
        path,
        shutting_down,
        body,
    };
    answer(&request, lookup)
}

fn answer_to(
    path: &str,
    body: &BodyWatch,
    lookup: &dyn Fn(&LiveId) -> Result<LiveBody, LiveBodyError>,
) -> Response {
    answer_as(
        (false, Version::HTTP_11, false),
        path,
        &HeaderMap::new(),
        body,
        lookup,
    )
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

fn live(bytes: &'static [u8], mime: &str) -> LiveBody {
    LiveBody {
        reader: Box::new(bytes),
        mime: mime.into(),
    }
}

#[test]
fn the_live_id_is_the_path_s_one_segment_checked_against_the_identifier_pattern() {
    assert_eq!(
        live_id_of("/v0/live/01JL").map(|id| id.to_string()),
        Some("01JL".into())
    );
    for path in [
        "/v0/live",
        "/v0/live/",
        "/v0/live/.",
        "/v0/live/..",
        "/v0/live/a%2Fb",
        "/v0/live/a/b",
        "/v0/livex/01JL",
        "/v0/recording/01JL",
    ] {
        assert_eq!(live_id_of(path), None, "{path}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9110_15_5_a_request_that_names_no_live_output_it_may_take_is_refused_with_the_error_body()
 {
    let (logs, _guard) = capture();
    let body = BodyWatch::new();
    let asked = std::cell::Cell::new(0);
    let gone = |_: &LiveId| {
        asked.set(asked.get() + 1);
        Err(LiveBodyError::NotFound)
    };
    let mut browser = HeaderMap::new();
    browser.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://example.com"),
    );
    let none = HeaderMap::new();
    let cases: [Case<'_>; 4] = [
        // RFC 6455 §10.2, as the upgrade.
        (
            (false, Version::HTTP_11, false),
            &browser,
            (403, "invalid_request"),
        ),
        (
            (false, Version::HTTP_11, true),
            &none,
            (503, "shutting_down"),
        ),
        (
            (true, Version::HTTP_11, false),
            &none,
            (403, "not_permitted"),
        ),
        // RFC 9112 §6.1: no chunked body before HTTP/1.1.
        (
            (false, Version::HTTP_10, false),
            &none,
            (505, "invalid_request"),
        ),
    ];
    for (how, headers, (status, code)) in cases {
        let refused = answer_as(how, "/v0/live/01JL", headers, &body, &gone);
        if how.0 {
            assert_eq!(refused.headers()[header::CONNECTION], "close");
        }
        assert_eq!(status_and_code(refused).await, (status, code.into()));
    }
    for path in ["/v0/live/a%2Fb", "/v0/live/..", "/v0/live/secret secret"] {
        let refused = answer_to(path, &body, &gone);
        assert_eq!(
            status_and_code(refused).await,
            (404, "live_not_found".into()),
            "{path}"
        );
    }
    assert_eq!(asked.get(), 0, "none of them was looked up");
    let refused = answer_to("/v0/live/01JL", &body, &gone);
    assert_eq!(
        status_and_code(refused).await,
        (404, "live_not_found".into())
    );
    assert_eq!(asked.get(), 1);
    let taken = |_: &LiveId| Err(LiveBodyError::AlreadyFetched);
    let refused = answer_to("/v0/live/01JL", &body, &taken);
    assert_eq!(
        status_and_code(refused).await,
        (409, "live_already_fetched".into())
    );
    assert_eq!(*body.subscribe().borrow(), BodyState::Idle, "nothing sent");
    let allowed = not_allowed().await;
    assert_eq!(allowed.headers()[header::ALLOW], "GET");
    assert_eq!(
        status_and_code(allowed).await,
        (405, "invalid_request".into())
    );
    let text = logs.text();
    for line in [
        "live body refused: the request carries Origin",
        "live body refused: its client was removed",
        "live body refused: the request is not HTTP/1.1",
        "live body refused: the path names no live id",
        "live body refused: no open live output has this id",
        "live body refused: another request took it",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    assert!(!text.contains("secret"), "{text}");
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9111_5_2_2_5_a_live_body_is_an_uncached_chunked_200_of_its_mime_type_on_a_closing_connection()
 {
    let (logs, _guard) = capture();
    let body = BodyWatch::new();
    let one = |_: &LiveId| Ok(live(b"init", "video/mp4; codecs=\"hvc1.1.6.L120.90\""));
    let response = answer_to("/v0/live/01JL", &body, &one);
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "video/mp4; codecs=\"hvc1.1.6.L120.90\""
    );
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::CONNECTION], "close");
    assert_eq!(headers["x-live-id"], "01JL");
    assert_eq!(*body.subscribe().borrow(), BodyState::Taken);
    assert_eq!(bounded_bytes(response.into_body()).await, b"init");
    assert!(logs.text().contains("live body: the output ended"));
    // A MIME type no header can carry falls back to the container's.
    let odd = |_: &LiveId| Ok(live(b"", "video/mp4\n"));
    let response = answer_to("/v0/live/01JL", &body, &odd);
    assert_eq!(response.headers()[header::CONTENT_TYPE], FALLBACK_MIME);
}

/// More chunks than any body here has: a body that never ends is cut at
/// this many, so its test fails at once instead of growing until nextest
/// ends it.
const MAX_CHUNKS: usize = 64;

/// `body`'s bytes, read as at most [`MAX_CHUNKS`] chunks; one that has not
/// ended by then fails the test.
async fn bounded_bytes(body: Body) -> Vec<u8> {
    let chunks: Vec<_> = body.into_data_stream().take(MAX_CHUNKS).collect().await;
    assert!(chunks.len() < MAX_CHUNKS, "a body that never ends");
    chunks
        .into_iter()
        .flat_map(|chunk| chunk.unwrap().to_vec())
        .collect()
}

/// A reader that yields its chunk once, then fails.
struct Failing(Option<&'static [u8]>);

impl AsyncRead for Failing {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.0.take() {
            Some(chunk) => {
                buf.put_slice(chunk);
                Poll::Ready(Ok(()))
            }
            None => Poll::Ready(Err(io::Error::other("the pipe failed"))),
        }
    }
}

/// A live body is read in chunks of up to a pipe's 64 KiB (pipe(7)).
#[tokio::test(flavor = "current_thread")]
async fn a_live_body_is_read_in_chunks_of_a_pipe_s_capacity() {
    static BYTES: [u8; 100 * 1024] = [7; 100 * 1024];
    let sending = Sending {
        chunks: ReaderStream::with_capacity(Box::new(&BYTES[..]), CHUNK_BYTES),
        sent: 0,
        live_id: LiveId::new("01JL").unwrap(),
        peer: peer(),
    };
    let sizes: Vec<usize> = body_stream(sending)
        .take(MAX_CHUNKS)
        .map(|chunk| chunk.unwrap().len())
        .collect()
        .await;
    assert_eq!(sizes, [64 * 1024, 36 * 1024]);
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9112_8_a_live_body_whose_read_fails_is_cut() {
    let (logs, _guard) = capture();
    let sending = Sending {
        chunks: ReaderStream::with_capacity(Box::new(Failing(Some(b"moof"))), CHUNK_BYTES),
        sent: 0,
        live_id: LiveId::new("01JL").unwrap(),
        peer: peer(),
    };
    let chunks: Vec<io::Result<Bytes>> = body_stream(sending).take(MAX_CHUNKS).collect().await;
    assert_eq!(chunks.len(), 2);
    assert_eq!(&chunks[0].as_ref().unwrap()[..], b"moof");
    assert!(chunks[1].is_err());
    let text = logs.text();
    assert!(text.contains("live body cut: its read failed"), "{text}");
    assert!(text.contains("bytes=4"), "{text}");
    assert_eq!(
        format!("{:?}", live(b"", "video/mp4")),
        "LiveBody { mime: \"video/mp4\", .. }"
    );
    assert_eq!(
        LiveBodyError::AlreadyFetched.to_string(),
        "the live output's body was already fetched"
    );
}
