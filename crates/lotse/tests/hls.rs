//! LL-HLS end to end: a real daemon (supervisor and workers) plays the fake
//! RTSP camera as an LL-HLS session through `hls/create` and `GET
//! /v0/hls/{hls_id}/{name}` (draft-pantos-hls-rfc8216bis-22): the playlist,
//! a Blocking Playlist Reload of the part its Preload Hint names (§6.2.5.2),
//! the init segment, a part and a segment, read back with mp4-atom, an
//! independent reader of ISO/IEC 14496-12, as one fragmented MP4 that starts
//! at a keyframe and runs without a hole; `hls/close` ends the session
//! `closed` and its routes with it. ffprobe decoding a segment is the
//! interop test's to come. Needs the `source-rtsp` and `output-hls` features
//! (the defaults).

#![cfg(all(feature = "source-rtsp", feature = "output-hls"))]
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
use common::recording_body::{Fetched, fetch_on_socket};
use common::{Daemon, SocketDir, socket_dir};
use lotse_core::clock::{Clock as _, SystemClock};
use lotse_testing::fake_camera::CameraAudio;
use lotse_testing::load::control::Control;
use lotse_testing::{CameraConfig, FakeCamera};
use serde_json::json;

/// How long one step of a test may take before it fails.
const STEP: Duration = Duration::from_secs(20);

/// `future`, or a failed test after [`STEP`] of real time.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::select! {
        out = future => out,
        () = SystemClock.sleep(STEP) => panic!("{what}: nothing within {STEP:?}"),
    }
}

/// `GET path` on `socket`, read whole.
async fn get(socket: &Path, path: &str) -> Fetched {
    let fetch = fetch_on_socket(socket, path).await;
    within(path, fetch).await.expect("the fetch")
}

/// The value of attribute `URI` of the first line of `playlist` starting
/// with `tag`.
fn uri_of<'a>(playlist: &'a str, tag: &str) -> &'a str {
    let line = playlist
        .lines()
        .find(|line| line.starts_with(tag))
        .unwrap_or_else(|| panic!("no {tag} in {playlist}"));
    line.split("URI=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a URI")
}

/// A daemon on a socket of its own, ready, and its control connection,
/// whose `hello` announces LL-HLS, playing the fake camera as `front`,
/// preloaded so its GOP is cached by the time a session joins.
async fn daemon(test: &str, camera: &FakeCamera) -> (Daemon, Control, SocketDir) {
    let dir = socket_dir(test);
    let socket = dir.join("lotse.sock");
    let mut daemon = Daemon::start(
        &[
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
        ],
        &[],
    );
    daemon.wait_for("\"event\":\"ready\"");
    let (control, hello) = Control::connect(&socket).await.expect("the control socket");
    assert!(
        hello["outputs"].as_array().unwrap().contains(&json!("hls")),
        "{hello}"
    );
    control
        .command(json!({ "type": "stream/put", "stream_id": "front",
                         "sources": [lotse_testing::source(&camera.url(), json!({}))],
                         "preload": true }))
        .await
        .expect("stream/put");
    (daemon, control, dir)
}

/// The init segment `playlist`'s `EXT-X-MAP` names and its first listed
/// segment, under `base` on `socket`, are one fragmented MP4 that starts at
/// a keyframe and runs without a hole, with the camera's audio.
async fn check_segment(socket: &Path, base: &str, playlist: &str) {
    let init = get(
        socket,
        &format!("{base}/{}", uri_of(playlist, "#EXT-X-MAP:")),
    )
    .await;
    assert_eq!(init.status, 200);
    let segment_name = playlist
        .lines()
        .find(|line| line.starts_with("seg"))
        .expect("a segment");
    let segment = get(socket, &format!("{base}/{segment_name}")).await;
    assert_eq!(segment.status, 200);
    let file = [init.bytes, segment.bytes].concat();
    let mp4 = parse(&file);
    let (video_id, _rate) = mp4.video();
    let video = mp4.samples(&file, video_id);
    assert_starts_at_a_keyframe_without_holes(&video);
    assert!(
        video.len() >= 25,
        "a segment of a second at 25 fps: {}",
        video.len()
    );
    assert!(mp4.audio(&file).is_some(), "the camera's AAC");
}

/// A session plays the camera: its playlist lists parts and segments and
/// hints the next part, a blocking reload for that part is answered once it
/// is listed, and the init segment with a segment is one fragmented MP4 from
/// a keyframe without a hole; `hls/close` ends it `closed`, and its playlist
/// is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8216bis_6_2_5_2_an_hls_session_plays_the_camera_until_closed() {
    let camera = FakeCamera::start(
        CameraConfig {
            audio: Some(CameraAudio::Aac),
            ..CameraConfig::default()
        },
        Arc::new(SystemClock),
    )
    .await
    .expect("camera binds");
    let (daemon, control, dir) = daemon("hls-play", &camera).await;
    let socket = dir.join("lotse.sock");
    let (_id, result, mut events) = within(
        "hls/create",
        control.subscribe(json!({ "type": "hls/create", "stream_id": "front" })),
    )
    .await
    .expect("hls/create");
    let mime = result["mime"].as_str().unwrap();
    assert!(
        mime.starts_with("video/mp4; codecs=\"avc1.") && mime.ends_with(",mp4a.40.2\""),
        "{mime}"
    );
    let hls_id = result["hls_id"].as_str().unwrap().to_owned();
    let playlist_path = format!("/v0/hls/{hls_id}/index.m3u8");
    assert_eq!(result["playlist"], playlist_path);
    let base = format!("/v0/hls/{hls_id}");

    // The first playlist waits for the first segment.
    let fetched = get(&socket, &playlist_path).await;
    assert_eq!(fetched.status, 200);
    assert_eq!(
        fetched.content_type.as_deref(),
        Some("application/vnd.apple.mpegurl")
    );
    let playlist = String::from_utf8(fetched.bytes).unwrap();
    assert!(playlist.starts_with("#EXTM3U\n"), "{playlist}");
    // §6.2.5.2: a reload for the hinted part is held until it is listed.
    let hinted = uri_of(&playlist, "#EXT-X-PRELOAD-HINT:").to_owned();
    let (msn, part) = hinted
        .strip_prefix("part")
        .and_then(|rest| rest.strip_suffix(".m4s"))
        .and_then(|rest| rest.split_once('.'))
        .expect("a part's name");
    let reload = get(
        &socket,
        &format!("{playlist_path}?_HLS_msn={msn}&_HLS_part={part}"),
    )
    .await;
    assert_eq!(reload.status, 200);
    let reloaded = String::from_utf8(reload.bytes).unwrap();
    // The hint alone names the part too: only a part tag shows that the reload waited for it.
    assert!(
        reloaded
            .lines()
            .any(|line| line.starts_with("#EXT-X-PART:")
                && line.contains(&format!("URI=\"{hinted}\""))),
        "{reloaded}"
    );
    let part = get(&socket, &format!("{base}/{hinted}")).await;
    assert_eq!(
        (part.status, part.content_type.as_deref()),
        (200, Some("video/mp4"))
    );
    assert_ne!(part.bytes.len(), 0);

    check_segment(&socket, &base, &playlist).await;

    let missing = get(&socket, &format!("{base}/seg999999.m4s")).await;
    assert_eq!(missing.status, 404);
    within(
        "hls/close",
        control.command(json!({ "type": "hls/close", "hls_id": hls_id })),
    )
    .await
    .expect("hls/close");
    let closed = within("closed", events.recv()).await.expect("closed");
    assert_eq!(
        closed,
        json!({ "type": "closed", "hls_id": hls_id, "reason": "closed" })
    );
    let gone = get(&socket, &playlist_path).await;
    assert_eq!(gone.status, 404);
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}
