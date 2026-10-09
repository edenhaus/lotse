//! The dev viewer in front of a real `lotse serve`: the page's own command
//! sequence (`stream/put`, `webrtc/offer`, trickled candidates,
//! `unsubscribe`) through the relay, the fake camera behind the daemon and
//! the headless viewer standing in for the browser.
//! Needs the `source-rtsp` and `output-webrtc` features (the defaults).

#![cfg(all(feature = "source-rtsp", feature = "output-webrtc"))]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{Daemon, socket_dir};
use futures_util::{SinkExt as _, StreamExt as _};
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::task::spawn_named;
use lotse_testing::dev_viewer;
use lotse_testing::viewer::{Outgoing, Viewer};
use lotse_testing::{CameraConfig, FakeCamera};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_util::sync::CancellationToken;

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// The page's next text frame from the daemon, as JSON.
async fn next_frame(page: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        tokio::select! {
            frame = page.next() => match frame {
                Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
                Some(Ok(_)) => {}
                other => panic!("the relay closed: {other:?}"),
            },
            () = clock().sleep(Duration::from_secs(20)) => panic!("no frame from the daemon"),
        }
    }
}

async fn send_all(socket: &UdpSocket, out: &mut Vec<Outgoing>) {
    for datagram in out.drain(..) {
        let _sent = socket
            .send_to(&datagram.payload, datagram.destination)
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dev_viewer_page_plays_a_camera_through_a_running_daemon() {
    let cam = FakeCamera::start(CameraConfig::default(), clock())
        .await
        .expect("camera");
    let dir = socket_dir("dev-viewer");
    let socket = dir.join("lotse.sock");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            socket.to_str().unwrap(),
            "--sandbox",
            "off",
            "--log-format",
            "json",
        ],
        &[],
    );
    daemon.wait_for("\"event\":\"ready\"");

    // The dev viewer, and the page's WebSocket through it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    spawn_named(
        "test.dev_viewer",
        dev_viewer::serve(listener, socket.clone(), cancel.clone()),
    );
    let mut request = format!("ws://{addr}{}", dev_viewer::RELAY_PATH)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Origin",
        HeaderValue::from_str(&format!("http://{addr}")).unwrap(),
    );
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut page, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("the relay accepts the page");
    let hello = next_frame(&mut page).await;
    assert_eq!(hello["type"], "hello", "{hello}");

    // What the page does on Play; it sends the offer once the put's
    // result is in, so the orientation applies to this session.
    let viewer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let viewer_addr = viewer_socket.local_addr().unwrap();
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(viewer_addr, clock().now()).expect("a viewer");
    let put = json!({ "id": 1, "type": "stream/put", "stream_id": "cam",
                      "sources": [{ "url": cam.url() }], "orientation": "rotate_left" });
    page.send(Message::text(put.to_string())).await.unwrap();
    let put = next_frame(&mut page).await;
    assert_eq!(
        (&put["id"], &put["success"]),
        (&json!(1), &json!(true)),
        "{put}"
    );
    let offer = json!({ "id": 2, "type": "webrtc/offer", "stream_id": "cam", "session_id": "viewer-1",
                        "sdp": viewer.offer(), "ice_servers": [] });
    page.send(Message::text(offer.to_string())).await.unwrap();
    let mut out = Vec::new();
    let mut frames = vec![put];
    let mut answered = false;
    let mut buf = vec![0_u8; 2_000];
    let mut deadline = clock().sleep(Duration::from_secs(30));
    while !(viewer.packets().len() >= 20 && viewer.keyframe_starts() >= 1) {
        let wait = viewer
            .next_timeout()
            .map_or(Duration::from_millis(20), |at| {
                at.saturating_duration_since(clock().now())
            });
        tokio::select! {
            frame = page.next() => {
                let Some(Ok(Message::Text(text))) = frame else { continue };
                let frame: Value = serde_json::from_str(&text).unwrap();
                if frame["type"] == "result" {
                    assert_eq!(frame["success"], true, "{frame}");
                } else if frame["type"] == "event" && frame["event"]["type"] == "answer" {
                    viewer.accept_answer(frame["event"]["sdp"].as_str().unwrap(), &mut out).expect("answer applies");
                    send_all(&viewer_socket, &mut out).await;
                    // The page trickles its own candidate, then the end.
                    for candidate in [format!("candidate:1 1 udp 2130706431 {} {} typ host", viewer_addr.ip(), viewer_addr.port()), String::new()] {
                        let command = json!({ "id": 3 + u64::from(answered), "type": "webrtc/candidate",
                                              "session_id": "viewer-1", "candidate": candidate, "sdp_mid": "0" });
                        answered = true;
                        page.send(Message::text(command.to_string())).await.unwrap();
                    }
                }
                frames.push(frame);
            }
            received = viewer_socket.recv_from(&mut buf) => {
                let (len, source) = received.unwrap();
                viewer.receive(clock().now(), source, &buf[..len], &mut out);
                send_all(&viewer_socket, &mut out).await;
            }
            () = clock().sleep(wait) => {
                viewer.timeout(clock().now(), &mut out);
                send_all(&viewer_socket, &mut out).await;
            }
            () = &mut deadline => panic!("no video in time; {} packets, frames {frames:#?}", viewer.packets().len()),
        }
    }
    let results: Vec<u64> = frames
        .iter()
        .filter(|f| f["type"] == "result")
        .map(|f| f["id"].as_u64().unwrap())
        .collect();
    for id in [1, 2, 3, 4] {
        assert!(results.contains(&id), "command {id} answered: {frames:#?}");
    }
    let events: Vec<&str> = frames
        .iter()
        .filter(|f| f["type"] == "event" && f["id"] == 2)
        .map(|f| f["event"]["type"].as_str().unwrap())
        .collect();
    assert_eq!(events.first(), Some(&"session"), "{events:?}");
    assert!(
        events.contains(&"answer") && events.contains(&"candidate"),
        "{events:?}"
    );

    // Stop: the page unsubscribes, and the session closes.
    page.send(Message::text(
        json!({ "id": 5, "type": "unsubscribe", "subscription": 2 }).to_string(),
    ))
    .await
    .unwrap();
    let closed = loop {
        tokio::select! {
            frame = page.next() => {
                let Some(Ok(Message::Text(text))) = frame else { continue };
                let frame: Value = serde_json::from_str(&text).unwrap();
                if frame["type"] == "event" && frame["event"]["type"] == "closed" {
                    break frame;
                }
            }
            () = clock().sleep(Duration::from_secs(10)) => panic!("no closed event"),
        }
    };
    assert_eq!(closed["event"]["code"], "session_closed", "{closed}");

    cancel.cancel();
    let (code, _rest) = daemon.terminate();
    assert_eq!(code, Some(0));
    cam.stop().await;
}
