//! The daemon against a third-party RTSP server: ffmpeg encodes a
//! synthetic stream (libx264, and AAC, PCMU or Opus) and publishes it to
//! MediaMTX, a real `lotse serve` pulls it from MediaMTX with RTP
//! interleaved on TCP (RFC 2326 §10.12) or as UDP datagrams (§12.39), and a
//! headless viewer plays it. Each test checks what `stream/get` reports
//! (the source live, H.264 and the audio codec ffmpeg sent), that the
//! daemon connected at its first attempt, MediaMTX's own view of the
//! reader (one session, over the transport asked for), that the viewer
//! receives video with keyframes and the audio the answer negotiated,
//! that every track was timed by MediaMTX's Sender Reports
//! (`stream/get`'s `sync`), and that MediaMTX's session ends promptly once
//! the daemon is done with it, after `stream/delete` and after a UDP
//! attempt that failed (its `TEARDOWN`, RFC 2326 §10.7).
//!
//! Ignored by default: they need `mediamtx` and `ffmpeg` on `PATH`, which
//! `mise run interop` provides (pinned in `mise.toml`) before it runs them.
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

use std::sync::Arc;
use std::time::Duration;

use common::{Daemon, socket_dir};
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::task::spawn_named;
use lotse_testing::load::control::Control;
use lotse_testing::load::play::{self, Play};
use lotse_testing::mediamtx::{Audio, Camera};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// How long the stream may take to go live.
const LIVE_WITHIN: Duration = Duration::from_secs(20);

/// How long the viewer plays.
const PLAY: Duration = Duration::from_secs(4);

/// How long MediaMTX may keep a reader's session once the daemon's
/// attempt ended: its `TEARDOWN` ends it at once (RFC 2326 §10.7), while
/// a UDP session left without one lives until MediaMTX's `readTimeout`,
/// 10 s.
const TORN_DOWN_WITHIN: Duration = Duration::from_secs(1);

/// The stream's id.
const STREAM: &str = "interop";

/// The RTSP lower transport the daemon asks MediaMTX for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// The codec the viewer should get for the camera's `audio`: the native
/// one, or Opus from the daemon's AAC transcoder.
fn negotiated(audio: Audio) -> Option<&'static str> {
    match audio {
        Audio::None => None,
        Audio::Aac | Audio::Opus => Some("opus"),
        Audio::Pcmu => Some("pcmu"),
    }
}

/// `stream/get` until the stream is live with every track, or a failure
/// after [`LIVE_WITHIN`].
async fn wait_live(control: &Control, audio: Audio, clock: &dyn Clock) -> Value {
    let deadline = clock.now() + LIVE_WITHIN;
    loop {
        let (_, stream) = control
            .command(json!({ "type": "stream/get", "stream_id": STREAM }))
            .await
            .expect("stream/get");
        let native = stream["tracks"].as_array().map_or(0, |tracks| {
            tracks
                .iter()
                .filter(|t| t["derived_from"].is_null())
                .count()
        });
        if stream["state"] == "live" && native == audio.tracks() {
            return stream;
        }
        assert!(
            clock.now() < deadline,
            "not live with every track: {stream}"
        );
        clock.sleep(Duration::from_millis(100)).await;
    }
}

/// The track of `kind` that came from the camera.
fn native<'a>(stream: &'a Value, kind: &str) -> &'a Value {
    stream["tracks"]
        .as_array()
        .and_then(|tracks| {
            tracks
                .iter()
                .find(|t| t["kind"] == kind && t["derived_from"].is_null())
        })
        .unwrap_or_else(|| panic!("no native {kind} track: {stream}"))
}

/// Every MediaMTX session that reads the path.
async fn readers(camera: &Camera) -> Vec<Value> {
    let sessions = camera
        .api("/v3/rtspsessions/list")
        .await
        .expect("the API")
        .expect("a session list");
    sessions["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|s| s["state"] == "read")
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// The `transport` of every MediaMTX session that reads the path.
async fn reader_transports(camera: &Camera) -> Vec<String> {
    readers(camera)
        .await
        .iter()
        .map(|s| s["transport"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// Waits until no reader session `gone` names is left, or fails after
/// [`TORN_DOWN_WITHIN`]; every session when `gone` is `None`.
async fn wait_torn_down(camera: &Camera, gone: Option<&[Value]>, clock: &dyn Clock) {
    let deadline = clock.now() + TORN_DOWN_WITHIN;
    loop {
        let left: Vec<Value> = readers(camera)
            .await
            .into_iter()
            .filter(|s| gone.is_none_or(|gone| gone.iter().any(|g| g["id"] == s["id"])))
            .collect();
        if left.is_empty() {
            return;
        }
        assert!(
            clock.now() < deadline,
            "MediaMTX still has the sessions after {TORN_DOWN_WITHIN:?}, no TEARDOWN: {left:?}"
        );
        clock.sleep(Duration::from_millis(20)).await;
    }
}

/// The live stream: its source, H.264 and the audio codec ffmpeg sent.
fn check_live(stream: &Value, audio: Audio) {
    assert_eq!(stream["sources"][0]["state"], "live", "{stream}");
    assert_eq!(native(stream, "video")["codec"], "h264", "{stream}");
    if let Some(codec) = audio.lotse_codec() {
        assert_eq!(native(stream, "audio")["codec"], codec, "{stream}");
    }
}

/// What the viewer got: video at the camera's rate with a keyframe a
/// second, and the audio the answer negotiated.
fn check_viewer(stats: &play::ViewerStats, audio: Audio) {
    assert_eq!(stats.error, None, "{stats:?}");
    assert!(stats.connected_after.is_some(), "{stats:?}");
    // 30 fps with a keyframe a second, for about 4 s after the answer.
    assert!(stats.frames >= 60, "{stats:?}");
    assert!(stats.keyframes >= 3, "{stats:?}");
    assert_eq!(stats.audio_codec.as_deref(), negotiated(audio), "{stats:?}");
    if audio != Audio::None {
        // 20 ms packets: 50 a second.
        assert!(stats.audio_packets >= 100, "{stats:?}");
    }
}

/// MediaMTX sends its readers RTCP Sender Reports of its own, from the
/// first packet on, and every track is timed by them (RFC 3550 §6.4.1):
/// `stream/get` says so once the first report arrived, a moment after the
/// stream went live, a derived track as its source.
fn synced(stream: &Value) -> bool {
    stream["tracks"].as_array().is_some_and(|tracks| {
        !tracks.is_empty() && tracks.iter().all(|t| t["sync"] == "sender_reports")
    })
}

/// The daemon's log lines `rest` show one connection attempt: MediaMTX
/// answers the first reader's `PLAY` without `rtptime` in `RTP-Info`
/// (RFC 2326 §12.33; observed 2026-10-06 with MediaMTX 1.21.1), and the
/// daemon plays it rather than failing and retrying a second later.
fn check_one_attempt(rest: &[String]) {
    let attempts = rest
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|line| line["message"] == "rtsp: connecting")
        .count();
    assert_eq!(attempts, 1, "connection attempts");
}

/// Waits until MediaMTX counts the daemon's RTCP Receiver Reports
/// (RFC 3550 §6.4.2) on its reader session, `rtcpPacketsReceived` in
/// `/v3/rtspsessions/list` (MediaMTX 1.21.1, observed 2026-10-07): two
/// at least, beyond the one firewall hole punch a UDP reader sends, or a
/// failure after [`LIVE_WITHIN`].
async fn wait_rtcp_received(camera: &Camera, transport: Transport, clock: &dyn Clock) {
    let wanted = match transport {
        Transport::Tcp => 2,
        Transport::Udp => 3,
    };
    let deadline = clock.now() + LIVE_WITHIN;
    loop {
        let sessions = readers(camera).await;
        let received: u64 = sessions
            .iter()
            .filter_map(|s| s["rtcpPacketsReceived"].as_u64())
            .sum();
        if received >= wanted {
            return;
        }
        assert!(
            clock.now() < deadline,
            "MediaMTX counts {received} RTCP packets from the daemon, not {wanted}: {sessions:?}"
        );
        clock.sleep(Duration::from_millis(200)).await;
    }
}

/// The whole run for one transport and one audio variant.
async fn interop(transport: Transport, audio: Audio) {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let camera = Camera::start(audio, Arc::clone(&clock))
        .await
        .expect("MediaMTX and ffmpeg (run through `mise run interop`)");
    let dir = socket_dir(&format!("interop-{}-{}", transport.name(), audio.name()));
    let socket = dir.join("lotse.sock");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            socket.to_str().unwrap(),
            // The test binary is dynamic, and Landlock checks `execute` on
            // its loader too; the sandbox is covered on the static build
            // (`ctl.rs`, `mise run test-musl`).
            "--sandbox",
            "off",
            "--log-format",
            "json",
        ],
        &[],
    );
    daemon.wait_for("\"event\":\"ready\"");
    lotse_webrtc::install_crypto_provider();
    let (control, _hello) = Control::connect(&socket).await.expect("the control socket");
    let control = Arc::new(control);
    control
        .command(json!({
            "type": "stream/put",
            "stream_id": STREAM,
            "sources": [{ "url": camera.url(), "options": { "transport": transport.name() } }],
            "preload": true,
        }))
        .await
        .expect("stream/put");

    check_live(&wait_live(&control, audio, &*clock).await, audio);
    assert_eq!(
        reader_transports(&camera).await,
        [transport.name().to_uppercase()],
        "MediaMTX serves the daemon one session, over the transport it asked for"
    );
    wait_stream(&control, &*clock, synced).await;

    let stop = CancellationToken::new();
    let viewer = spawn_named(
        "interop.viewer",
        play::view(Play {
            control: Arc::clone(&control),
            stream_id: STREAM.to_owned(),
            session_id: "interop-viewer".to_owned(),
            clock: Arc::clone(&clock),
            origin: clock.now(),
            audio: audio != Audio::None,
            stop: stop.clone(),
        }),
    );
    clock.sleep(PLAY).await;
    let during = control
        .command(json!({ "type": "stream/get", "stream_id": STREAM }))
        .await
        .expect("stream/get")
        .1;
    stop.cancel();
    check_viewer(&viewer.await.expect("the viewer"), audio);
    if audio == Audio::Aac {
        let derived = during["tracks"]
            .as_array()
            .and_then(|tracks| tracks.iter().find(|t| !t["derived_from"].is_null()))
            .unwrap_or_else(|| panic!("no transcoded track while the viewer played: {during}"));
        assert_eq!(derived["codec"], "opus", "{during}");
    }
    assert!(synced(&during), "{during}");
    wait_rtcp_received(&camera, transport, &*clock).await;

    control
        .command(json!({ "type": "stream/delete", "stream_id": STREAM }))
        .await
        .expect("stream/delete");
    wait_torn_down(&camera, None, &*clock).await;
    Arc::into_inner(control)
        .expect("the viewer is done")
        .close()
        .await;
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0));
    check_one_attempt(&rest);
    camera.stop();
}

/// `stream/get` until `done` says the stream is as wanted, or a failure
/// after [`LIVE_WITHIN`].
async fn wait_stream(control: &Control, clock: &dyn Clock, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = clock.now() + LIVE_WITHIN;
    loop {
        let (_, stream) = control
            .command(json!({ "type": "stream/get", "stream_id": STREAM }))
            .await
            .expect("stream/get");
        if done(&stream) {
            return stream;
        }
        assert!(clock.now() < deadline, "not as wanted: {stream}");
        clock.sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_10_7_a_failed_udp_attempt_is_torn_down() {
    // With ffmpeg stopped MediaMTX still describes the path and answers
    // PLAY, but sends no datagram: the attempt ends as `source_timeout`
    // at the read deadline. Its session outlives the connection over UDP
    // (RFC 2326 §1.1), so only the daemon's TEARDOWN ends it before
    // MediaMTX's 10 s `readTimeout`.
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let camera = Camera::start(Audio::Pcmu, Arc::clone(&clock))
        .await
        .expect("MediaMTX and ffmpeg (run through `mise run interop`)");
    let dir = socket_dir("interop-udp-failed");
    let socket = dir.join("lotse.sock");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            socket.to_str().unwrap(),
            // The test binary is dynamic, and Landlock checks `execute` on
            // its loader too; the sandbox is covered on the static build
            // (`ctl.rs`, `mise run test-musl`).
            "--sandbox",
            "off",
            "--log-format",
            "json",
        ],
        &[],
    );
    daemon.wait_for("\"event\":\"ready\"");
    let (control, _hello) = Control::connect(&socket).await.expect("the control socket");
    camera.pause().expect("ffmpeg stops");
    control
        .command(json!({
            "type": "stream/put",
            "stream_id": STREAM,
            "sources": [{ "url": camera.url(), "options": { "transport": "udp", "timeout_ms": 1500 } }],
            "preload": true,
        }))
        .await
        .expect("stream/put");
    // The attempt's session, playing and waiting for media.
    let deadline = clock.now() + LIVE_WITHIN;
    let failed = loop {
        let sessions = readers(&camera).await;
        if !sessions.is_empty() {
            break sessions;
        }
        assert!(clock.now() < deadline, "no reader session");
        clock.sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(failed.len(), 1, "{failed:?}");
    let stream = wait_stream(&control, &*clock, |s| s["state"] == "backoff").await;
    assert_eq!(stream["last_error"]["code"], "source_timeout", "{stream}");
    wait_torn_down(&camera, Some(&failed), &*clock).await;
    // ffmpeg goes on: the retry plays, on one session.
    camera.resume().expect("ffmpeg goes on");
    check_live(
        &wait_live(&control, Audio::Pcmu, &*clock).await,
        Audio::Pcmu,
    );
    assert_eq!(reader_transports(&camera).await, ["UDP"]);
    control
        .command(json!({ "type": "stream/delete", "stream_id": STREAM }))
        .await
        .expect("stream/delete");
    wait_torn_down(&camera, None, &*clock).await;
    control.close().await;
    let (code, _rest) = daemon.terminate();
    assert_eq!(code, Some(0));
    camera.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_10_12_video_over_tcp_interleaved() {
    interop(Transport::Tcp, Audio::None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_10_12_aac_over_tcp_interleaved_rfc3640() {
    interop(Transport::Tcp, Audio::Aac).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_10_12_pcmu_over_tcp_interleaved_rfc3551() {
    interop(Transport::Tcp, Audio::Pcmu).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_10_12_opus_over_tcp_interleaved_rfc7587() {
    interop(Transport::Tcp, Audio::Opus).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_12_39_video_over_udp() {
    interop(Transport::Udp, Audio::None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_12_39_aac_over_udp_rfc3640() {
    interop(Transport::Udp, Audio::Aac).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_12_39_pcmu_over_udp_rfc3551() {
    interop(Transport::Udp, Audio::Pcmu).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
async fn mediamtx_rfc2326_12_39_opus_over_udp_rfc7587() {
    interop(Transport::Udp, Audio::Opus).await;
}
