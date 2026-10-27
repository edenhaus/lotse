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
//! The [`http`] tests do the same over HTTP: the daemon pulls MediaMTX's
//! HLS (RFC 8216) of the same stream, with MPEG-TS segments, with fMP4
//! segments and the audio as a separate rendition, low-latency (played by
//! full segments), and over HTTPS with a pinned self-signed certificate,
//! and ffmpeg's own raw MPEG-TS (ISO/IEC 13818-1) over HTTP; a publisher
//! that restarts is seen as a reconnect.
//!
//! The [`clip`] tests record event clips of the stream (H.264 or libx265's
//! H.265; AAC, Opus, PCMU or G.722) from the daemon's pre-roll window and
//! have ffprobe decode them (ISO/IEC 14496-12).
//!
//! Ignored by default: they need `mediamtx`, `ffmpeg` and `ffprobe` on
//! `PATH`, which `mise run interop` provides (pinned in `mise.toml`) before
//! it runs them. Needs the `source-rtsp` and `output-webrtc` features (the
//! defaults), `source-http` for the HTTP tests and `output-clip` for the
//! clip tests.

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
        // Not played by these tests: the clips transcode it.
        Audio::G722 => Some("g722"),
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

/// The daemon against MediaMTX's HLS and ffmpeg's raw MPEG-TS over HTTP.
/// Each test checks what `stream/get` reports (the `http` source live,
/// H.264 and AAC-LC when ffmpeg sends audio, every track timed by its
/// arrival: HTTP carries no Sender Reports), that the daemon fetched the
/// source once, MediaMTX's own view of the reader (one HLS session, the
/// daemon's `User-Agent`), and that the viewer receives video with
/// keyframes and the AAC transcoded to Opus.
#[cfg(feature = "source-http")]
mod http {
    use lotse_testing::fake_camera::CameraTls;
    use lotse_testing::mediamtx::{HlsVariant, PATH, TsServer};

    use super::*;

    /// The daemon's log message for each attempt at an HTTP source.
    const FETCHING: &str = "http: fetching the source";

    /// A daemon with its control connection.
    async fn daemon(test: &str) -> (Daemon, Arc<Control>) {
        let dir = socket_dir(&format!("interop-{test}"));
        let socket = dir.join("lotse.sock");
        let mut daemon = Daemon::start(
            &[
                "--webrtc-udp-listen",
                "127.0.0.1:0",
                "--webrtc-tcp-listen",
                "off",
                "--socket",
                socket.to_str().unwrap(),
                "--log-format",
                "json",
            ],
            &[],
        );
        daemon.wait_for("\"event\":\"ready\"");
        lotse_webrtc::install_crypto_provider();
        let (control, _hello) = Control::connect(&socket).await.expect("the control socket");
        (daemon, Arc::new(control))
    }

    /// `stream/put` of `url` with `options`, preloaded.
    async fn put(control: &Control, url: &str, options: Value) {
        control
            .command(json!({
                "type": "stream/put",
                "stream_id": STREAM,
                "sources": [{ "url": url, "options": options }],
                "preload": true,
            }))
            .await
            .expect("stream/put");
    }

    /// The live HTTP stream: the source over `http` and every track timed
    /// by its arrival.
    fn check_live_http(stream: &Value, audio: Audio) {
        check_live(stream, audio);
        assert_eq!(stream["sources"][0]["protocol"], "http", "{stream}");
        let tracks = stream["tracks"].as_array().expect("tracks");
        assert!(tracks.iter().all(|t| t["sync"] == "arrival"), "{stream}");
    }

    /// A viewer for [`PLAY`], checked as the RTSP tests check theirs; the
    /// stream as `stream/get` reports it while the viewer played.
    async fn view(control: &Arc<Control>, audio: Audio, clock: &Arc<dyn Clock>) -> Value {
        let stop = CancellationToken::new();
        let viewer = spawn_named(
            "interop.viewer",
            play::view(Play {
                control: Arc::clone(control),
                stream_id: STREAM.to_owned(),
                session_id: "interop-viewer".to_owned(),
                clock: Arc::clone(clock),
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
        during
    }

    /// How many attempts at the source the daemon's log lines `rest` show,
    /// and the errors that ended them, for the failure message.
    fn attempts(rest: &[String]) -> (usize, Vec<String>) {
        let lines: Vec<Value> = rest
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect();
        let count = lines
            .iter()
            .filter(|line| line["message"] == FETCHING)
            .count();
        let ended = lines
            .iter()
            .filter(|line| line["message"] == "source connection ended")
            .map(|line| line["error"].to_string())
            .collect();
        (count, ended)
    }

    /// MediaMTX's HLS sessions on the path: one, made by the daemon.
    /// MediaMTX 1.21.1 (observed 2026-10-08) answers the first request for
    /// `index.m3u8` with a redirect to `?cookieCheck=1`, and names the
    /// session it made in the URI of every playlist and segment it lists
    /// (`?session=`), so the daemon's media playlists, and a separate audio
    /// rendition's, are one session.
    async fn check_hls_session(camera: &Camera) {
        let sessions = camera
            .api("/v3/hlssessions/list")
            .await
            .expect("the API")
            .expect("a session list");
        let items = sessions["items"].as_array().expect("items");
        assert_eq!(items.len(), 1, "{sessions}");
        assert_eq!(items[0]["path"], PATH, "{sessions}");
        assert!(
            items[0]["userAgent"]
                .as_str()
                .is_some_and(|agent| agent.starts_with("lotse/")),
            "{sessions}"
        );
    }

    /// The whole run against MediaMTX's HLS in `variant`, over HTTPS with a
    /// pinned self-signed certificate when `tls`.
    async fn hls(variant: HlsVariant, audio: Audio, tls: bool) {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let certificate =
            tls.then(|| CameraTls::self_signed(&["127.0.0.1"]).expect("a certificate"));
        let camera = Camera::start_hls(audio, variant, certificate.as_ref(), Arc::clone(&clock))
            .await
            .expect("MediaMTX and ffmpeg (run through `mise run interop`)");
        let url = camera.hls_url().expect("HLS");
        let options = certificate.as_ref().map_or_else(
            || json!({}),
            |c| json!({ "tls_fingerprint": c.fingerprint() }),
        );
        let (daemon, control) = daemon(&format!("hls-{}-{}", variant.name(), audio.name())).await;
        put(&control, &url, options).await;

        check_live_http(&wait_live(&control, audio, &*clock).await, audio);
        check_hls_session(&camera).await;
        let during = view(&control, audio, &clock).await;
        assert_eq!(during["sources"][0]["reconnects"], 0, "{during}");

        control
            .command(json!({ "type": "stream/delete", "stream_id": STREAM }))
            .await
            .expect("stream/delete");
        Arc::into_inner(control)
            .expect("the viewer is done")
            .close()
            .await;
        let (code, rest) = daemon.terminate();
        assert_eq!(code, Some(0));
        let (count, ended) = attempts(&rest);
        assert_eq!(count, 1, "attempts at the source, ended by {ended:?}");
        camera.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
    async fn mediamtx_rfc8216_mpegts_video() {
        hls(HlsVariant::MpegTs, Audio::None, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
    async fn mediamtx_rfc8216_mpegts_aac() {
        hls(HlsVariant::MpegTs, Audio::Aac, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
    async fn mediamtx_rfc8216_fmp4_video() {
        hls(HlsVariant::Fmp4, Audio::None, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
    async fn mediamtx_rfc8216_fmp4_aac() {
        // MediaMTX 1.21.1 serves the audio as a separate rendition
        // (`EXT-X-MEDIA`, RFC 8216 §4.3.4.1): two media playlists.
        hls(HlsVariant::Fmp4, Audio::Aac, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
    async fn mediamtx_rfc8216_low_latency() {
        // Partial segments are not fetched: the daemon plays the full
        // segments the low-latency playlist lists as well.
        hls(HlsVariant::LowLatency, Audio::Aac, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
    async fn mediamtx_rfc8216_https_pinned() {
        hls(HlsVariant::MpegTs, Audio::Aac, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX and ffmpeg: mise run interop"]
    async fn mediamtx_rfc8216_a_publisher_restart_is_a_reconnect() {
        // ffmpeg restarts: MediaMTX drops the path with its HLS muxer, the
        // daemon's attempt ends, and the next one plays the new muxer's
        // playlist from the start of its new timeline.
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut camera =
            Camera::start_hls(Audio::Aac, HlsVariant::MpegTs, None, Arc::clone(&clock))
                .await
                .expect("MediaMTX and ffmpeg (run through `mise run interop`)");
        let (daemon, control) = daemon("hls-restart").await;
        put(&control, &camera.hls_url().expect("HLS"), json!({})).await;
        check_live_http(&wait_live(&control, Audio::Aac, &*clock).await, Audio::Aac);

        camera
            .restart_publisher(Arc::clone(&clock))
            .await
            .expect("ffmpeg restarts");
        let stream = wait_stream(&control, &*clock, |s| {
            s["state"] == "live" && s["sources"][0]["reconnects"].as_u64() >= Some(1)
        })
        .await;
        check_live_http(&stream, Audio::Aac);
        let during = view(&control, Audio::Aac, &clock).await;
        assert_eq!(during["state"], "live", "{during}");

        control
            .command(json!({ "type": "stream/delete", "stream_id": STREAM }))
            .await
            .expect("stream/delete");
        Arc::into_inner(control)
            .expect("the viewer is done")
            .close()
            .await;
        let (code, rest) = daemon.terminate();
        assert_eq!(code, Some(0));
        let (count, ended) = attempts(&rest);
        assert!(count >= 2, "attempts at the source, ended by {ended:?}");
        camera.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs ffmpeg: mise run interop"]
    async fn ffmpeg_iso13818_1_raw_mpegts_http() {
        // ffmpeg serves one client and listens only a moment after it
        // starts: an attempt before that is refused and retried, so the
        // attempts are not counted here.
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let server = TsServer::start(Audio::Aac).expect("ffmpeg (run through `mise run interop`)");
        let (daemon, control) = daemon("raw-mpegts").await;
        put(&control, &server.url(), json!({})).await;
        check_live_http(&wait_live(&control, Audio::Aac, &*clock).await, Audio::Aac);
        let during = view(&control, Audio::Aac, &clock).await;
        assert_eq!(during["sources"][0]["state"], "live", "{during}");

        control
            .command(json!({ "type": "stream/delete", "stream_id": STREAM }))
            .await
            .expect("stream/delete");
        Arc::into_inner(control)
            .expect("the viewer is done")
            .close()
            .await;
        let (code, rest) = daemon.terminate();
        assert_eq!(code, Some(0));
        let (count, ended) = attempts(&rest);
        assert!(count >= 1, "attempts at the source, ended by {ended:?}");
        server.stop();
    }
}

/// Event clips of MediaMTX's stream, checked by ffprobe, an independent
/// reader of ISO/IEC 14496-12 that decodes every frame: a preloaded
/// stream with a pre-roll window records a clip from `before_ms` ago to
/// `after_ms` from now (`clip/start`), fetched as it runs (`GET
/// /v0/clips/{clip_id}`), written to a file and read with `ffprobe
/// -show_streams -show_frames`. Each test checks the streams and their
/// codecs (H.264 as `avc1`, H.265 as `hvc1`, AAC-LC as the camera sent it,
/// Opus as sent or transcoded from G.711 and G.722, never `audio_omitted`),
/// that every frame decodes (ffprobe reports no error), the frames against
/// the clip's duration, the first video frame a keyframe, and the audio
/// starting with the video; a publisher restart inside a clip is one `gap`
/// event where the file has a real hole.
#[cfg(feature = "output-clip")]
mod clip {
    use std::path::Path;

    use lotse_testing::mediamtx::{FPS, HEIGHT, Video, WIDTH};
    use tokio::sync::mpsc;

    use super::*;
    use crate::common::SocketDir;
    use crate::common::clip_body::{Fetched, fetch_on_socket};

    /// The pre-roll window the stream keeps.
    const PREROLL_MS: u64 = 10_000;

    /// How much of the window the clip asks for.
    const BEFORE_MS: u64 = 2_000;

    /// How long the clip runs after it starts.
    const AFTER_MS: u64 = 3_000;

    /// One video frame at the camera's rate, in the 90 kHz RTP clock of
    /// H.264 and H.265 (RFC 6184 §8.2.1, RFC 7798 §7.1), which the clip's
    /// video track keeps as its timescale.
    const FRAME_TICKS: i64 = 90_000 / FPS as i64;

    /// One video frame, in milliseconds (33.3, rounded up).
    const FRAME_MS: u64 = 34;

    /// EBU R37's bound on audio against video: within 40 ms.
    const AV_SYNC_MS: u64 = 40;

    /// The G.711 to Opus transcode's delay, 312 ticks at 48 kHz: what the
    /// clip's origin lies before its first frame's capture time, so its
    /// first video sample starts there.
    const G711_DELAY_US: u64 = 6_500;

    /// The G.722 to Opus transcode's delay, 282 ticks at 48 kHz.
    const G722_DELAY_US: u64 = 5_875;

    /// A daemon on a socket of its own with its control connection.
    async fn daemon(test: &str) -> (Daemon, Arc<Control>, SocketDir) {
        let dir = socket_dir(&format!("interop-clip-{test}"));
        let socket = dir.join("lotse.sock");
        let mut daemon = Daemon::start(
            &[
                "--webrtc-udp-listen",
                "127.0.0.1:0",
                "--webrtc-tcp-listen",
                "off",
                "--socket",
                socket.to_str().unwrap(),
                // The test binary is dynamic, and Landlock checks `execute`
                // on its loader too; the sandbox records a clip in
                // `worker.rs`.
                "--sandbox",
                "off",
                "--log-format",
                "json",
            ],
            &[],
        );
        daemon.wait_for("\"event\":\"ready\"");
        let (control, _hello) = Control::connect(&socket).await.expect("the control socket");
        (daemon, Arc::new(control), dir)
    }

    /// `stream/put` of the camera, preloaded with a [`PREROLL_MS`] window,
    /// then `stream/get` until it is live with every track and the video's
    /// window holds `held_ms`.
    async fn put_and_fill(
        control: &Control,
        camera: &Camera,
        held_ms: u64,
        clock: &dyn Clock,
    ) -> Value {
        control
            .command(json!({
                "type": "stream/put",
                "stream_id": STREAM,
                "sources": [{ "url": camera.url() }],
                "preload": true,
                "preroll_ms": PREROLL_MS,
            }))
            .await
            .expect("stream/put");
        let live = wait_live(control, camera.audio(), clock).await;
        assert_eq!(
            native(&live, "video")["codec"],
            camera.video().lotse_codec(),
            "{live}"
        );
        wait_stream(control, clock, |stream| {
            native(stream, "video")["preroll"]["held_ms"]
                .as_u64()
                .is_some_and(|held| held >= held_ms)
        })
        .await
    }

    /// The next event of a clip's subscription, or a failure after
    /// [`LIVE_WITHIN`].
    async fn next_event(events: &mut mpsc::UnboundedReceiver<Value>, clock: &dyn Clock) -> Value {
        tokio::select! {
            event = events.recv() => event.expect("the subscription ends with stopped"),
            () = clock.sleep(LIVE_WITHIN) => panic!("no clip event in {LIVE_WITHIN:?}"),
        }
    }

    /// The events up to and including `stopped`.
    async fn until_stopped(
        events: &mut mpsc::UnboundedReceiver<Value>,
        clock: &dyn Clock,
    ) -> Vec<Value> {
        let mut seen = Vec::new();
        loop {
            let event = next_event(events, clock).await;
            let stopped = event["type"] == "stopped";
            seen.push(event);
            if stopped {
                return seen;
            }
        }
    }

    /// The body as the clip ended `reason`: 200 `video/mp4`, ended with its
    /// last chunk (RFC 9112 §7.1), as many bytes as `stopped` counts.
    fn check_whole(fetched: &Fetched, events: &[Value], reason: &str) {
        assert_eq!(fetched.status, 200, "{fetched:?}");
        assert_eq!(fetched.content_type.as_deref(), Some("video/mp4"));
        assert!(fetched.whole, "the body ends with its last chunk");
        assert_eq!(events[0]["type"], "started", "{events:?}");
        let stopped = events.last().unwrap();
        assert_eq!(
            (&stopped["reason"], stopped["bytes"].as_u64()),
            (&json!(reason), u64::try_from(fetched.bytes.len()).ok()),
            "{events:?}"
        );
    }

    /// One decoded frame as ffprobe reports it, its times in its stream's
    /// timescale.
    #[derive(Debug, Clone)]
    struct Frame {
        pts: i64,
        duration: i64,
        key: bool,
        picture: Option<String>,
    }

    /// One stream of the file: its description and its decoded frames.
    #[derive(Debug)]
    struct Probed {
        stream: Value,
        /// The stream's timescale: ticks a second.
        rate: i64,
        frames: Vec<Frame>,
    }

    impl Probed {
        /// Milliseconds from the file's zero to `ticks`, rounded down as the
        /// daemon's clip times are.
        fn ms(&self, ticks: i64) -> u64 {
            u64::try_from(ticks * 1_000 / self.rate).unwrap()
        }

        /// Where the first frame begins, in microseconds.
        fn start_us(&self) -> u64 {
            u64::try_from(self.frames[0].pts * 1_000_000 / self.rate).unwrap()
        }

        /// From the first frame's start to the last one's end, in ms.
        fn span_ms(&self) -> u64 {
            let (first, last) = (&self.frames[0], self.frames.last().unwrap());
            self.ms(last.pts + last.duration - first.pts)
        }

        /// Each place a frame begins later than the one before it ended:
        /// the holes on the stream's timeline, as the indexes of the frames
        /// around them.
        fn holes(&self) -> Vec<(usize, usize)> {
            (1..self.frames.len())
                .filter(|&at| {
                    let before = &self.frames[at - 1];
                    self.frames[at].pts > before.pts + before.duration
                })
                .map(|at| (at - 1, at))
                .collect()
        }
    }

    /// ffprobe's streams and frames of `file`: the video, and the audio if
    /// the file has any. ffprobe decodes every frame (`-show_frames`) and
    /// reports at `-v error` whatever does not decode, so its silence says
    /// every frame did.
    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party reader of the daemon's clip, never the daemon's code"
    )]
    fn ffprobe(file: &Path) -> (Probed, Option<Probed>) {
        let output = std::process::Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_streams",
                "-show_frames",
                "-of",
                "json",
            ])
            .arg(file)
            .output()
            .expect(
                "ffprobe is not on PATH: `mise install`, then run through mise (mise run interop)",
            );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert_eq!(stderr, "", "ffprobe decodes every frame without an error");
        let probe: Value = serde_json::from_slice(&output.stdout).unwrap();
        let streams = probe["streams"].as_array().unwrap();
        let probed = |kind: &str| {
            let stream = streams.iter().find(|s| s["codec_type"] == kind)?;
            let index = stream["index"].as_u64();
            let (_, rate) = stream["time_base"]
                .as_str()
                .and_then(|base| base.split_once('/'))
                .unwrap();
            let frames = probe["frames"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|frame| frame["stream_index"].as_u64() == index)
                .map(|frame| Frame {
                    pts: frame["pts"].as_i64().unwrap(),
                    duration: frame["duration"].as_i64().unwrap(),
                    key: frame["key_frame"] == 1,
                    picture: frame["pict_type"].as_str().map(str::to_owned),
                })
                .collect();
            Some(Probed {
                stream: stream.clone(),
                rate: rate.parse().unwrap(),
                frames,
            })
        };
        assert!(streams.len() <= 2, "{streams:?}");
        (probed("video").expect("a video stream"), probed("audio"))
    }

    /// The file's video as ffprobe decodes it: `video`'s codec in its
    /// MP4 sample entry (`avc1`, ISO/IEC 14496-15 §5.4.2.1; `hvc1`,
    /// §8.4.1.1.2) at the camera's size and timescale, its first frame a
    /// keyframe (an I picture), and every frame there, one after the other
    /// at the camera's rate, without a hole.
    fn check_video(video: &Probed, codec: Video) {
        let (name, tag) = match codec {
            Video::H264 => ("h264", "avc1"),
            Video::H265 => ("hevc", "hvc1"),
        };
        assert_eq!(
            (
                &video.stream["codec_name"],
                &video.stream["codec_tag_string"]
            ),
            (&json!(name), &json!(tag)),
            "{}",
            video.stream
        );
        assert_eq!(
            (&video.stream["width"], &video.stream["height"]),
            (&json!(WIDTH), &json!(HEIGHT))
        );
        assert_eq!(video.rate, 90_000);
        let first = &video.frames[0];
        assert!(
            first.key && first.picture.as_deref() == Some("I"),
            "the first frame is a keyframe: {first:?}"
        );
        assert!(
            video
                .frames
                .windows(2)
                .all(|pair| pair[1].pts - pair[0].pts == FRAME_TICKS),
            "every frame at {FPS} fps"
        );
        let frames = i64::try_from(video.frames.len()).unwrap();
        let last = video.frames.last().unwrap();
        assert_eq!(
            last.pts + last.duration - first.pts,
            frames * FRAME_TICKS,
            "as many frames as the span holds"
        );
    }

    /// A clip of a preloaded camera sending `video` and `audio`: from the
    /// newest keyframe at least [`BEFORE_MS`] old to [`AFTER_MS`] from the
    /// start, whole, its streams checked by ffprobe.
    async fn clip(video: Video, audio: Audio) {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let camera = Camera::start_video(video, audio, Arc::clone(&clock))
            .await
            .expect("MediaMTX and ffmpeg (run through `mise run interop`)");
        let (daemon, control, dir) = daemon(&format!("{}-{}", video.name(), audio.name())).await;
        put_and_fill(&control, &camera, BEFORE_MS + 1_000, &*clock).await;

        let asked = clock.now();
        let (_id, result, mut events) = control
            .subscribe(json!({
                "type": "clip/start",
                "stream_id": STREAM,
                "before_ms": BEFORE_MS,
                "after_ms": AFTER_MS,
            }))
            .await
            .expect("clip/start");
        let fetch = fetch_on_socket(&dir.join("lotse.sock"), result["url"].as_str().unwrap()).await;
        let first = next_event(&mut events, &*clock).await;
        // At least how long after the command the clip started (`at`,
        // which `before_ms` counts back from), while `after_ms` counts from
        // the command.
        let start_delay =
            u64::try_from(clock.now().saturating_duration_since(asked).as_millis()).unwrap();
        let events = [vec![first], until_stopped(&mut events, &*clock).await].concat();
        let fetched = fetch.await.expect("the fetch");
        check_whole(&fetched, &events, "completed");
        assert_eq!(
            fetched.clip_id.as_ref(),
            result["clip_id"].as_str().map(str::to_owned).as_ref()
        );
        // `started` and `stopped`: no gap, and no `audio_omitted` warning.
        assert_eq!(events.len(), 2, "{events:?}");
        let started = &events[0];
        let audio_codec = match audio {
            Audio::None => None,
            Audio::Aac => Some("aac_lc"),
            Audio::Opus | Audio::Pcmu | Audio::G722 => Some("opus"),
        };
        assert_eq!(
            (&started["video"], &started["audio"]),
            (
                &json!({ "codec": video.lotse_codec(), "width": WIDTH, "height": HEIGHT }),
                &audio_codec.map_or(Value::Null, |codec| json!({ "codec": codec })),
            ),
            "{started}"
        );
        let before_ms = started["before_ms"].as_u64().unwrap();
        assert!(
            (BEFORE_MS..BEFORE_MS + 1_000 + FRAME_MS).contains(&before_ms),
            "the newest keyframe {BEFORE_MS} ms ago or more, a second apart: {before_ms}"
        );

        let file = dir.join("clip.mp4");
        std::fs::write(&file, &fetched.bytes).unwrap();
        let (video_frames, audio_frames) = ffprobe(&file);
        check_video(&video_frames, video);
        // From the keyframe `before_ms` before the clip started to the
        // first frame at or after `after_ms` from the command, which the
        // clip leaves out: `before_ms + AFTER_MS` less however long after
        // the command the clip started, which the round trip bounds.
        let span = video_frames.span_ms();
        let asked_span = before_ms + AFTER_MS;
        assert!(
            (asked_span.saturating_sub(start_delay + 2 * FRAME_MS)..=asked_span + 2 * FRAME_MS)
                .contains(&span),
            "the video covers {span} ms, the clip {before_ms} + {AFTER_MS} ms, \
             started at most {start_delay} ms after it was asked"
        );
        let stopped = events.last().unwrap();
        assert!(
            stopped["duration_ms"].as_u64().unwrap().abs_diff(span) <= 2 * FRAME_MS,
            "{stopped} for {span} ms of video"
        );

        check_audio(audio, &video_frames, audio_frames.as_ref());

        Arc::into_inner(control).expect("one owner").close().await;
        let (code, rest) = daemon.terminate();
        assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
        camera.stop();
    }

    /// The file's audio against what the camera sent: none, AAC-LC as sent
    /// (16 kHz mono, 1024 samples a frame, ISO/IEC 14496-3 §4.5.1.1), or
    /// Opus in 20 ms packets at 48 kHz (RFC 7587 §4.2), as sent (two
    /// channels, the count RFC 7587 §7 has every Opus `rtpmap` declare,
    /// whatever the encoder sends; mono packets decode to both) or
    /// transcoded (mono), without a hole, over the video's span. The audio starts with the
    /// video (EBU R37, within 40 ms), except AAC-LC: the clip starts with
    /// the audio frame playing at the keyframe, 64 ms long, so the keyframe
    /// falls inside the first audio frame. A transcoded clip's origin lies
    /// the transcode's delay before its first frame, so its video starts at
    /// that delay, plus the lead of the audio frame playing at the keyframe
    /// when that one was captured before it and so came first.
    fn check_audio(audio: Audio, video: &Probed, sound: Option<&Probed>) {
        let Some(sound) = sound else {
            assert_eq!(audio, Audio::None, "an audio stream");
            return;
        };
        let (codec, rate, frame_ticks, channels) = match audio {
            Audio::Aac => ("aac", 16_000, 1_024, 1),
            Audio::Opus => ("opus", 48_000, 960, 2),
            _ => ("opus", 48_000, 960, 1),
        };
        assert_eq!(
            (
                &sound.stream["codec_name"],
                &sound.stream["sample_rate"],
                sound.rate
            ),
            (&json!(codec), &json!(rate.to_string()), rate),
            "{}",
            sound.stream
        );
        assert_eq!(sound.stream["channels"], channels, "{}", sound.stream);
        assert!(
            sound
                .frames
                .iter()
                .all(|frame| frame.duration == frame_ticks),
            "every audio frame {frame_ticks} ticks"
        );
        assert_eq!(sound.holes(), [], "the audio runs without a hole");
        let (video_us, audio_us) = (video.start_us(), sound.start_us());
        if audio == Audio::Aac {
            assert!(
                audio_us <= video_us + 1_000 && video_us < audio_us + 64_000 + 1_000,
                "audio at {audio_us} us, video at {video_us} us"
            );
        } else {
            assert!(
                audio_us.abs_diff(video_us) <= AV_SYNC_MS * 1_000,
                "audio at {audio_us} us, video at {video_us} us"
            );
        }
        let delay_us = match audio {
            Audio::Pcmu => Some(G711_DELAY_US),
            Audio::G722 => Some(G722_DELAY_US),
            _ => None,
        };
        if let Some(delay_us) = delay_us {
            // Whole ticks of 90 kHz, rounded down: 12 µs at most; the audio
            // frame playing at the keyframe began less than its 20 ms before
            // it (observed 10 to 20 ms with MediaMTX 1.21.1 and ffmpeg 9.0.2,
            // 2026-10-23), give or take a millisecond of the two tracks'
            // Sender Report fits.
            assert!(
                video_us + 12 >= delay_us && video_us < delay_us + 21_000,
                "video at {video_us} us, the delay {delay_us} us"
            );
        }
        // Give or take a frame at each end, and the 20 ms a transcode keeps.
        let (audio_span, video_span) = (sound.span_ms(), video.span_ms());
        assert!(
            audio_span.abs_diff(video_span) <= 2 * sound.ms(frame_ticks) + 20,
            "audio over {audio_span} ms, video over {video_span} ms"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX, ffmpeg and ffprobe: mise run interop"]
    async fn mediamtx_iso14496_12_clip_h264_aac() {
        clip(Video::H264, Audio::Aac).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX, ffmpeg and ffprobe: mise run interop"]
    async fn mediamtx_iso14496_12_clip_h265() {
        clip(Video::H265, Audio::None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX, ffmpeg and ffprobe: mise run interop"]
    async fn mediamtx_iso14496_12_clip_opus() {
        clip(Video::H264, Audio::Opus).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX, ffmpeg and ffprobe: mise run interop"]
    async fn mediamtx_iso14496_12_clip_pcmu_to_opus() {
        clip(Video::H264, Audio::Pcmu).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX, ffmpeg and ffprobe: mise run interop"]
    async fn mediamtx_iso14496_12_clip_g722_to_opus() {
        clip(Video::H264, Audio::G722).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs MediaMTX, ffmpeg and ffprobe: mise run interop"]
    async fn mediamtx_iso14496_12_clip_reconnect() {
        // ffmpeg restarts while the clip runs, a camera that reboots:
        // MediaMTX drops the path, the daemon reconnects once ffmpeg
        // publishes again, and the clip goes on with a hole of the real time
        // the restart took.
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut camera = Camera::start_video(Video::H264, Audio::Aac, Arc::clone(&clock))
            .await
            .expect("MediaMTX and ffmpeg (run through `mise run interop`)");
        let (daemon, control, dir) = daemon("reconnect").await;
        put_and_fill(&control, &camera, 1_000, &*clock).await;
        let (_id, result, mut events) = control
            .subscribe(json!({ "type": "clip/start", "stream_id": STREAM, "before_ms": 1_000 }))
            .await
            .expect("clip/start");
        let clip_id = result["clip_id"].as_str().unwrap().to_owned();
        let fetch = fetch_on_socket(&dir.join("lotse.sock"), result["url"].as_str().unwrap()).await;
        let started = next_event(&mut events, &*clock).await;
        assert_eq!(started["type"], "started", "{started}");

        camera
            .restart_publisher(Arc::clone(&clock))
            .await
            .expect("ffmpeg restarts");
        let gap = next_event(&mut events, &*clock).await;
        assert_eq!(
            (&gap["type"], &gap["reason"]),
            (&json!("gap"), &json!("reconnect")),
            "{gap}"
        );
        // Two seconds of the new connection's media in the clip.
        clock.sleep(Duration::from_secs(2)).await;
        control
            .command(json!({ "type": "clip/stop", "clip_id": clip_id }))
            .await
            .expect("clip/stop");
        let mut all = vec![started, gap.clone()];
        all.extend(until_stopped(&mut events, &*clock).await);
        let fetched = fetch.await.expect("the fetch");
        check_whole(&fetched, &all, "stopped");
        assert_eq!(all.len(), 3, "one gap: {all:?}");
        assert_eq!(all[2]["gaps"], 1, "{all:?}");

        let file = dir.join("clip.mp4");
        std::fs::write(&file, &fetched.bytes).unwrap();
        let (video, sound) = ffprobe(&file);
        assert!(video.frames[0].key, "the clip starts at a keyframe");
        assert!(sound.is_some(), "with its audio");
        // One hole: from the last frame before the restart to the new
        // connection's first, a keyframe, at the times the gap names (whole
        // milliseconds, rounded down by both), and a real one: what the
        // restart took beyond the last frame's length.
        let holes = video.holes();
        assert_eq!(holes.len(), 1, "one hole in the video: {holes:?}");
        let (before, after) = holes[0];
        let (from, to) = (&video.frames[before], &video.frames[after]);
        assert!(to.key && to.picture.as_deref() == Some("I"), "{to:?}");
        assert_eq!(
            (video.ms(from.pts), video.ms(to.pts)),
            (
                gap["from_ms"].as_u64().unwrap(),
                gap["to_ms"].as_u64().unwrap()
            ),
            "{gap}"
        );
        let hole_ms = video.ms(to.pts - from.pts - from.duration);
        assert!(hole_ms >= 100, "a hole of {hole_ms} ms");
        assert!(
            video.frames[after..]
                .windows(2)
                .all(|pair| pair[1].pts - pair[0].pts == FRAME_TICKS)
                && video.frames.len() - after >= usize::try_from(FPS).unwrap(),
            "a second or more of the new connection at {FPS} fps"
        );

        Arc::into_inner(control).expect("one owner").close().await;
        let (code, rest) = daemon.terminate();
        assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
        camera.stop();
    }
}
