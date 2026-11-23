//! Live outputs end to end: a real daemon (supervisor and workers) plays the
//! fake RTSP camera and streams it through `live/create` and `GET
//! /v0/live/{live_id}`. The body is read back with mp4-atom, an independent
//! reader of ISO/IEC 14496-12: it starts with the init segment the result's
//! MIME type describes, its video starts at a keyframe and runs without a
//! hole, one video frame per movie fragment, and `live/close` ends it with its
//! last chunk; an output nobody fetches ends `not_fetched`, and one whose
//! control connection closes ends with it. ffprobe decoding every frame is
//! the interop test's (`mediamtx_iso14496_12_live_*`). Needs the
//! `source-rtsp` and `output-live` features (the defaults).

#![cfg(all(feature = "source-rtsp", feature = "output-live"))]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

mod common;

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::mp4::{assert_starts_at_a_keyframe_without_holes, parse};
use common::recording_body::fetch_on_socket;
use common::{Daemon, SocketDir, socket_dir};
use rocko_core::clock::{Clock, SystemClock};
use rocko_testing::fake_camera::CameraAudio;
use rocko_testing::load::control::Control;
use rocko_testing::{CameraConfig, FakeCamera};
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// How long one step of a test may take before it fails.
const STEP: Duration = Duration::from_secs(20);

/// How long a body is read before the output is closed.
const PLAY: Duration = Duration::from_secs(2);

/// `future`, or a failed test after [`STEP`] of real time.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::select! {
        out = future => out,
        () = SystemClock.sleep(STEP) => panic!("{what}: nothing within {STEP:?}"),
    }
}

/// A daemon on a socket of its own with `args` on top, ready, and its
/// control connection.
async fn daemon(test: &str, args: &[&str]) -> (Daemon, Control, SocketDir) {
    let dir = socket_dir(test);
    let socket = dir.join("rocko.sock");
    let mut all = vec![
        "--webrtc-udp-listen",
        "127.0.0.1:0",
        "--webrtc-tcp-listen",
        "off",
        "--socket",
        socket.to_str().expect("utf-8 path"),
        "--sandbox",
        "off",
        "--log-format",
        "json",
    ];
    all.extend_from_slice(args);
    let mut daemon = Daemon::start(&all, &[]);
    daemon.wait_for("\"event\":\"ready\"");
    let (control, _hello) = Control::connect(&socket).await.expect("the control socket");
    (daemon, control, dir)
}

/// The fake camera with H.264 and AAC-LC.
async fn camera() -> FakeCamera {
    let config = CameraConfig {
        audio: Some(CameraAudio::Aac),
        ..CameraConfig::default()
    };
    FakeCamera::start(config, Arc::new(SystemClock))
        .await
        .expect("camera binds")
}

/// `stream/put` of `front` playing the camera, preloaded so its GOP is
/// cached by the time an output joins.
async fn put(control: &Control, camera: &FakeCamera) {
    control
        .command(json!({ "type": "stream/put", "stream_id": "front",
                         "sources": [rocko_testing::source(&camera.url(), json!({}))],
                         "preload": true }))
        .await
        .expect("stream/put");
}

/// `live/create` of `front`; its result and events.
async fn create(control: &Control) -> (Value, mpsc::UnboundedReceiver<Value>) {
    let (_id, result, events) = within(
        "live/create",
        control.subscribe(json!({ "type": "live/create", "stream_id": "front" })),
    )
    .await
    .expect("live/create");
    (result, events)
}

/// The events up to and including `closed`.
async fn until_closed(events: &mut mpsc::UnboundedReceiver<Value>) -> Vec<Value> {
    let mut seen = Vec::new();
    loop {
        let event = within("a live event", events.recv())
            .await
            .expect("the subscription ends with closed");
        let closed = event["type"] == "closed";
        seen.push(event);
        if closed {
            return seen;
        }
    }
}

/// A live output answered with its MIME type streams the camera from its
/// cached keyframe, one video frame per fragment and without a hole, until
/// `live/close` ends it `closed` and its body with its last chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9112_7_1_a_live_output_streams_one_frame_per_fragment_until_closed() {
    let camera = camera().await;
    let (daemon, control, dir) = daemon("live-stream", &[]).await;
    put(&control, &camera).await;
    let (result, mut events) = create(&control).await;
    let mime = result["mime"].as_str().unwrap().to_owned();
    assert!(
        mime.starts_with("video/mp4; codecs=\"avc1.") && mime.ends_with(",mp4a.40.2\""),
        "{mime}"
    );
    let live_id = result["live_id"].as_str().unwrap().to_owned();
    assert_eq!(result["url"], format!("/v0/live/{live_id}"));
    let socket = dir.join("rocko.sock");
    let fetch = fetch_on_socket(&socket, result["url"].as_str().unwrap()).await;
    SystemClock.sleep(PLAY).await;
    within(
        "live/close",
        control.command(json!({ "type": "live/close", "live_id": live_id })),
    )
    .await
    .expect("live/close");
    let events = until_closed(&mut events).await;
    assert_eq!(events.last().unwrap()["reason"], "closed", "{events:?}");
    let fetched = within("the body", fetch).await.expect("the fetch");
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.content_type.as_deref(), Some(mime.as_str()));
    assert!(fetched.whole, "the body ends with its last chunk");
    let file = &fetched.bytes;
    let mp4 = parse(file);
    let (video_id, _rate) = mp4.video();
    let video = mp4.samples(file, video_id);
    assert_starts_at_a_keyframe_without_holes(&video);
    assert!(video.len() >= 25, "two seconds at 25 fps: {}", video.len());
    for (moof, _) in &mp4.fragments {
        let video_samples: usize = moof
            .traf
            .iter()
            .filter(|traf| traf.tfhd.track_id == video_id)
            .flat_map(|traf| &traf.trun)
            .map(|trun| trun.samples.len())
            .sum();
        assert!(video_samples <= 1, "one video frame per fragment");
    }
    assert!(mp4.audio(file).is_some(), "the camera's AAC");
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}

/// An output nobody fetches within `limits.live_fetch_timeout_ms` ends
/// `not_fetched`; a fetched one whose control connection closes ends with
/// it, `session_closed`, its body with its last chunk, nothing else asking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_output_not_fetched_or_left_by_its_control_connection_ends() {
    let camera = camera().await;
    let (mut daemon, control, dir) = daemon("live-ends", &["--live-fetch-timeout-ms", "500"]).await;
    put(&control, &camera).await;
    let (_result, mut events) = create(&control).await;
    let events = until_closed(&mut events).await;
    assert_eq!(
        events.last().unwrap()["reason"],
        "not_fetched",
        "{events:?}"
    );
    let (other, _hello) = Control::connect(Path::new(&dir.join("rocko.sock")))
        .await
        .expect("a second control connection");
    let (result, _events) = create(&other).await;
    let fetch = fetch_on_socket(&dir.join("rocko.sock"), result["url"].as_str().unwrap()).await;
    // Fetched: the fetch timeout is over, and only the connection's close
    // ends the output.
    daemon.wait_for("\"event\":\"live_fetched\"");
    other.close().await;
    let fetched = within("the body", fetch).await.expect("the fetch");
    assert_eq!(fetched.status, 200);
    assert!(fetched.whole, "the body ends with its last chunk");
    let closed = daemon.wait_for("\"event\":\"live_closed\"");
    assert!(closed.contains("\"reason\":\"session_closed\""), "{closed}");
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}
