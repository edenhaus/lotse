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
//! Ignored by default: they need `mediamtx` and `ffmpeg` on `PATH`, which
//! `mise run interop` provides (pinned in `mise.toml`) before it runs them.
//! Needs the `source-rtsp` and `output-webrtc` features (the defaults), and
//! `source-http` for the HTTP tests.

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
