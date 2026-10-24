//! A clip's body as a client fetches it: `GET /v0/clips/{clip_id}` over
//! HTTP/1.1 with hyper's client, read as the clip runs, telling a body that
//! ended with its last chunk (RFC 9112 §7.1) from a cut one. Shared by the
//! clip tests and the interop tests' clips.

use std::path::Path;

use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use lotse_core::task::spawn_named;
use tokio::net::UnixStream;

/// What a `GET` of a clip's body got.
#[derive(Debug)]
pub(crate) struct Fetched {
    pub(crate) status: u16,
    pub(crate) content_type: Option<String>,
    pub(crate) clip_id: Option<String>,
    pub(crate) bytes: Vec<u8>,
    /// The body ended with its last chunk (RFC 9112 §7.1), not cut.
    pub(crate) whole: bool,
}

/// `GET url` over `stream` (HTTP/1.1), read to its end as it comes.
pub(crate) async fn fetch<S>(stream: S, url: String) -> Fetched
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("an HTTP connection");
    let request = hyper::Request::get(url)
        .header(hyper::header::HOST, "lotse")
        .body(Empty::<Bytes>::new())
        .expect("a request");
    let exchange = async move {
        let response = sender.send_request(request).await.expect("a response");
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let (content_type, clip_id) = (header("content-type"), header("x-clip-id"));
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        let whole = loop {
            match body.frame().await {
                None => break true,
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        bytes.extend_from_slice(&data);
                    }
                }
                Some(Err(_cut)) => break false,
            }
        };
        Fetched {
            status,
            content_type,
            clip_id,
            bytes,
            whole,
        }
    };
    // The daemon closes the connection after the one body.
    let (fetched, _closed) = tokio::join!(exchange, connection);
    fetched
}

/// `GET url` over a new connection to the daemon's socket, on a task of
/// its own so the body is read as the clip runs.
pub(crate) async fn fetch_on_socket(socket: &Path, url: &str) -> tokio::task::JoinHandle<Fetched> {
    let stream = UnixStream::connect(socket).await.expect("socket connects");
    spawn_named("clip-fetch", fetch(stream, url.to_owned()))
}
