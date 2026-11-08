//! WebRTC cameras end to end: a real daemon (`lotse serve` and its
//! workers, the binary's own registries) plays `webrtc` sources, the
//! test playing Home Assistant, the client that relays their signaling over
//! the control socket, and the fake WebRTC camera answering on loopback
//! UDP. `signaling/subscribe` gets the source's offer (with the Nest
//! integration's data channel) and its trickled candidates; the camera's
//! answer and candidates go back with `signaling/answer` and
//! `signaling/candidate`, and the stream goes live: a viewer plays its video
//! and audio and a recording of it, read back with mp4-atom, holds both. An
//! ICE lite camera (RFC 8445 §2.5) that drops the source's candidates is
//! reached through the candidates it gave, in its answer or trickled. A
//! camera that closes its connection ends the signal `peer_closed`, a
//! camera's error relayed with `signaling/error` ends it `camera_error`,
//! and each time the source offers again with a new signal after its
//! backoff. Without a client to relay the signaling the source is
//! unreachable.
//! Needs the `source-webrtc`, `output-webrtc` and `output-recording`
//! features (the defaults).

#![cfg(all(
    feature = "source-webrtc",
    feature = "output-webrtc",
    feature = "output-recording"
))]
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

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::mp4::{assert_starts_at_a_keyframe_without_holes, holes, ms, parse};
use common::recording_body::fetch_on_socket;
use common::{Daemon, SocketDir, socket_dir};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt as _, StreamExt as _};
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::task::spawn_named;
use lotse_testing::fake_camera::{HEIGHT, WIDTH};
use lotse_testing::fake_webrtc_camera::{
    CameraRefusal, CandidateDelivery, FakeWebRtcCamera, WebRtcCameraAudio, WebRtcCameraConfig,
    WebRtcCameraStats,
};
use lotse_testing::viewer::{Outgoing, Viewer};
use mp4_atom::Codec as SampleEntry;
use serde_json::{Value, json};
use tokio::net::{UdpSocket, UnixStream};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

/// How long one step of a test may take before it fails: an event, a
/// state, a recording.
const STEP: Duration = Duration::from_secs(20);

/// The protocol of the source every test puts: a WebRTC camera has no
/// address, its stream is its identity.
const PROTOCOL: &str = "webrtc";

/// The data channel Nest's integration asks for.
const NEST_CHANNEL: &str = "dataSendChannel";

/// The fake camera's frame interval, in milliseconds (25 fps).
const FRAME_MS: u64 = 40;

/// The video's timescale, the RTP clock of H.264 (RFC 6184 §8.2.1).
const VIDEO_RATE: u64 = 90_000;

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// `future`, or a failed test after [`STEP`] of real time.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::select! {
        out = future => out,
        () = SystemClock.sleep(STEP) => panic!("{what}: nothing within {STEP:?}"),
    }
}

/// A daemon on a socket of its own, ready.
fn daemon(test: &str) -> (Daemon, SocketDir) {
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
    (daemon, dir)
}

/// One control connection over the daemon's socket: commands out, every
/// frame in through a task of its own, kept until a test asks for it.
struct Control {
    sink: SplitSink<WebSocketStream<UnixStream>, Message>,
    frames: mpsc::UnboundedReceiver<Value>,
    next_id: u64,
    kept: Vec<Value>,
}

impl Control {
    /// Connects, upgrades and reads `hello`.
    async fn connect(socket: &Path) -> Self {
        let stream = UnixStream::connect(socket).await.expect("socket connects");
        let (ws, _response) = tokio_tungstenite::client_async("ws://lotse/v0/ws", stream)
            .await
            .expect("websocket upgrade");
        let (sink, mut source) = ws.split();
        let (tx, frames) = mpsc::unbounded_channel();
        spawn_named("test.control_frames", async move {
            while let Some(Ok(message)) = source.next().await {
                if let Message::Text(text) = message
                    && tx.send(serde_json::from_str(&text).expect("JSON")).is_err()
                {
                    return;
                }
            }
        });
        let mut control = Self {
            sink,
            frames,
            next_id: 1,
            kept: Vec::new(),
        };
        let hello = control.take(|frame| frame["type"] == "hello").await;
        assert_eq!(hello["type"], "hello");
        control
    }

    /// The next frame from the daemon.
    async fn frame(&mut self) -> Value {
        within("a frame", self.frames.recv())
            .await
            .expect("the connection stays open")
    }

    /// Sends `command` with the next id; the id.
    async fn send(&mut self, mut command: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        command["id"] = json!(id);
        self.sink
            .send(Message::Text(command.to_string().into()))
            .await
            .expect("command sent");
        id
    }

    /// The first kept frame `wanted` takes, if any.
    fn kept(&mut self, wanted: impl Fn(&Value) -> bool) -> Option<Value> {
        let at = self.kept.iter().position(wanted)?;
        Some(self.kept.remove(at))
    }

    /// The next kept or arriving frame that `wanted` takes.
    async fn take(&mut self, wanted: impl Fn(&Value) -> bool) -> Value {
        if let Some(frame) = self.kept(&wanted) {
            return frame;
        }
        loop {
            let frame = self.frame().await;
            if wanted(&frame) {
                return frame;
            }
            self.kept.push(frame);
        }
    }

    /// Sends `command`; its result frame.
    async fn result(&mut self, command: Value) -> Value {
        let id = self.send(command).await;
        self.take(|frame| frame["type"] == "result" && frame["id"] == id)
            .await
    }

    /// Sends `command` and returns its result, which must be a success.
    async fn call(&mut self, command: Value) -> Value {
        let frame = self.result(command.clone()).await;
        assert_eq!(frame["success"], true, "{command} failed: {frame}");
        frame["result"].clone()
    }

    /// Opens a subscription with `command`; its id and result.
    async fn subscribe(&mut self, command: Value) -> (u64, Value) {
        let id = self.send(command.clone()).await;
        let frame = self
            .take(|frame| frame["type"] == "result" && frame["id"] == id)
            .await;
        assert_eq!(frame["success"], true, "{command} failed: {frame}");
        (id, frame["result"].clone())
    }

    /// The next event of the subscription `id`.
    async fn event(&mut self, id: u64) -> Value {
        let frame = self
            .take(|frame| frame["type"] == "event" && frame["id"] == id)
            .await;
        frame["event"].clone()
    }

    /// `stream/get` of `stream_id` once `done` holds for it, looked at
    /// every 50 ms for up to [`STEP`].
    async fn stream_where(&mut self, stream_id: &str, done: impl Fn(&Value) -> bool) -> Value {
        let get = json!({ "type": "stream/get", "stream_id": stream_id });
        let deadline = SystemClock.now() + STEP;
        loop {
            let stream = self.call(get.clone()).await;
            if done(&stream) {
                return stream;
            }
            assert!(
                SystemClock.now() < deadline,
                "{stream_id} never got there: {stream}"
            );
            SystemClock.sleep(Duration::from_millis(50)).await;
        }
    }
}

/// `stream/put` of `door` playing a [`PROTOCOL`] source with `options`, preloaded,
/// with a pre-record window of `prerecord_ms`.
fn put(options: &Value, prerecord_ms: u32) -> Value {
    json!({ "type": "stream/put", "stream_id": "door", "preload": true,
            "prerecord_ms": prerecord_ms,
            "sources": [signaled(options)] })
}

/// A [`PROTOCOL`] source with `options` beside its protocol.
fn signaled(options: &Value) -> Value {
    let mut source = json!({ "protocol": PROTOCOL });
    if let (Some(source), Some(options)) = (source.as_object_mut(), options.as_object()) {
        source.extend(options.clone());
    }
    source
}

/// One signal's offer as the subscription delivers it.
struct Offer {
    signal_id: String,
    sdp: String,
    /// The trickled candidates up to and including end-of-candidates.
    candidates: Vec<Value>,
}

/// The next signal's `offer` event on subscription `id` and the candidates
/// trickled after it, checked against what the source offers.
async fn offer(control: &mut Control, id: u64) -> Offer {
    let offer = control.event(id).await;
    assert_eq!(offer["type"], "offer", "{offer}");
    let signal_id = offer["signal_id"].as_str().unwrap().to_owned();
    assert_eq!(signal_id.len(), 26, "a ULID: {offer}");
    assert_eq!(offer["stream_id"], "door");
    assert_eq!(offer["protocol"], PROTOCOL);
    assert!(offer.get("source").is_none(), "{offer}");
    let sdp = offer["sdp"].as_str().unwrap().to_owned();
    // The host candidate is in the offer itself, for integrations that read
    // no trickled one (Nest).
    assert!(
        sdp.contains("a=candidate:") && sdp.contains(" 127.0.0.1 "),
        "{sdp}"
    );
    // Then trickled (RFC 8838 §8), each of the BUNDLE's first m-line, up to
    // end-of-candidates (§13).
    let mut candidates = Vec::new();
    loop {
        let candidate = control.event(id).await;
        assert_eq!(candidate["type"], "candidate", "{candidate}");
        assert_eq!(candidate["signal_id"], signal_id);
        assert_eq!(candidate["sdp_mline_index"], 0, "{candidate}");
        let end = candidate["candidate"] == "";
        candidates.push(candidate);
        if end {
            break;
        }
    }
    assert!(candidates.len() >= 2, "a host candidate: {candidates:?}");
    Offer {
        signal_id,
        sdp,
        candidates,
    }
}

/// Hands `offer` to a camera configured as `config` and relays what it
/// answers: the answer, its trickled candidates, and the source's to it.
async fn answer(
    control: &mut Control,
    offer: &Offer,
    config: WebRtcCameraConfig,
) -> FakeWebRtcCamera {
    let mid_extension = config.mid_extension;
    let (camera, answer) = FakeWebRtcCamera::answer(&offer.sdp, config, clock())
        .await
        .expect("the camera answers");
    // RFC 9143 §15: the answer has the `mid` extension only when the camera
    // sends it; its streams' `a=ssrc` (RFC 5576 §4.1) either way.
    assert_eq!(
        answer.sdp.contains("urn:ietf:params:rtp-hdrext:sdes:mid"),
        mid_extension,
        "{}",
        answer.sdp
    );
    assert!(answer.sdp.contains("\r\na=ssrc:"), "{}", answer.sdp);
    control
        .call(
            json!({ "type": "signaling/answer", "signal_id": offer.signal_id, "sdp": answer.sdp }),
        )
        .await;
    for candidate in answer.candidates {
        control
            .call(
                json!({ "type": "signaling/candidate", "signal_id": offer.signal_id,
                          "candidate": candidate.candidate, "sdp_mid": candidate.sdp_mid,
                          "sdp_mline_index": candidate.sdp_mline_index }),
            )
            .await;
    }
    for candidate in &offer.candidates {
        camera
            .add_remote_candidate(
                candidate["candidate"].as_str().unwrap(),
                candidate["sdp_mline_index"].as_u64(),
            )
            .expect("the camera takes the source's candidate");
    }
    camera
}

/// Sends what the viewer wants sent.
async fn send_all(socket: &UdpSocket, out: &mut Vec<Outgoing>) {
    for datagram in out.drain(..) {
        socket
            .send_to(&datagram.payload, datagram.destination)
            .await
            .expect("viewer send");
    }
}

/// Runs the viewer whose `webrtc/offer` is subscription `id` until `done`
/// holds for it, relaying the daemon's answer and candidates to it.
async fn play(
    control: &mut Control,
    id: u64,
    viewer: &mut Viewer,
    socket: &UdpSocket,
    done: impl Fn(&Viewer) -> bool,
) {
    let mut out = Vec::new();
    let mut buf = vec![0_u8; 2_000];
    let mut deadline = clock().sleep(STEP);
    let ours = |frame: &Value| frame["type"] == "event" && frame["id"] == id;
    while !done(viewer) {
        let event = if let Some(frame) = control.kept(ours) {
            Some(frame["event"].clone())
        } else {
            let next_timeout = viewer
                .next_timeout()
                .map_or(Duration::from_millis(20), |at| {
                    at.saturating_duration_since(clock().now())
                });
            tokio::select! {
                frame = control.frames.recv() => {
                    let frame = frame.expect("the connection stays open");
                    if ours(&frame) {
                        Some(frame["event"].clone())
                    } else {
                        control.kept.push(frame);
                        None
                    }
                }
                received = socket.recv_from(&mut buf) => {
                    let (len, source) = received.expect("viewer recv");
                    viewer.receive(clock().now(), source, &buf[..len], &mut out);
                    None
                }
                () = clock().sleep(next_timeout) => {
                    viewer.timeout(clock().now(), &mut out);
                    None
                }
                () = &mut deadline => panic!(
                    "the viewer timed out: {} video and {} audio packets",
                    viewer.packets().len(),
                    viewer.audio_packets().len()
                ),
            }
        };
        match event {
            Some(event) if event["type"] == "answer" => viewer
                .accept_answer(event["sdp"].as_str().unwrap(), &mut out)
                .expect("the answer applies"),
            Some(event) if event["type"] == "candidate" => {
                viewer.add_remote_candidate(event["candidate"].as_str().unwrap(), &mut out);
            }
            Some(event) if event["type"] == "closed" => panic!("the viewer's session: {event}"),
            Some(_) | None => {}
        }
        send_all(socket, &mut out).await;
    }
}

/// Whether `stream`'s video track holds at least `held_ms` of pre-record.
fn holds(stream: &Value, held_ms: u64) -> bool {
    stream["tracks"]
        .as_array()
        .and_then(|tracks| tracks.iter().find(|track| track["kind"] == "video"))
        .and_then(|video| video["prerecord"]["held_ms"].as_u64())
        .is_some_and(|held| held >= held_ms)
}

/// A recording of a second with a second of pre-record, read back with
/// mp4-atom: an `avc1` track at 90 kHz from a keyframe with its IDR and
/// without a hole, as long as the pre-record and the second together,
/// and an Opus track of 20 ms packets (RFC 7587 §4.2) at 48 kHz without a
/// hole that starts with the video (EBU R37: within 40 ms).
fn check_recording(file: &[u8], prerecord_ms: u64) {
    let mp4 = parse(file);
    let (video_id, video_rate) = mp4.video();
    assert_eq!(video_rate, VIDEO_RATE);
    let video = mp4.samples(file, video_id);
    assert_starts_at_a_keyframe_without_holes(&video);
    let last = video.last().unwrap();
    let span = ms(last.dts + last.duration - video[0].dts, video_rate);
    let expected = prerecord_ms + 1_000;
    assert!(
        span.abs_diff(expected) <= 2 * FRAME_MS,
        "the video covers {span} ms, the recording asked {expected} ms"
    );
    assert!(
        video.iter().all(|sample| !sample.bytes.is_empty()),
        "every picture has its bytes"
    );
    let (entry, audio_rate, audio) = mp4.audio(file).expect("an audio track");
    assert!(matches!(entry, SampleEntry::Opus(_)), "{entry:?}");
    assert_eq!(audio_rate, 48_000);
    assert!(audio.len() >= 40, "{} audio samples", audio.len());
    assert!(audio.iter().all(|sample| sample.duration == 960));
    assert_eq!(holes(&audio), [], "the audio runs without a hole");
    let (video_start, audio_start) = (ms(video[0].dts, video_rate), ms(audio[0].dts, audio_rate));
    assert!(
        audio_start.abs_diff(video_start) <= FRAME_MS,
        "audio at {audio_start} ms, video at {video_start} ms"
    );
}

/// A Nest-like camera answers the source's offer, which carries its
/// candidates and the data channel. Like Nest it refuses an offer without
/// the data channel's `application` m-line, its candidates are in its
/// answer only, it drops the source's trickled candidates, and it is ICE
/// lite (RFC 8445 §2.5), checking nothing itself: the source reaches it
/// through the answer's candidate alone. The stream goes live with the
/// camera's H.264 and Opus, the camera sees the data channel open and a
/// keyframe request, a viewer plays both tracks, and a recording of the
/// stream holds both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8445_2_5_a_nest_like_ice_lite_camera_answers_the_offer_and_its_stream_plays_and_records()
 {
    lotse_webrtc::install_crypto_provider();
    let (daemon, dir) = daemon("webrtc-source-live");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    let (signaling, _) = control
        .subscribe(json!({ "type": "signaling/subscribe", "stream_id": "door" }))
        .await;
    let put = control
        .call(put(&json!({ "data_channel": NEST_CHANNEL }), 3_000))
        .await;
    assert_eq!(put, json!({ "created": true }));
    let offer = offer(&mut control, signaling).await;
    // RFC 8829 §5.2.1: audio, video, then the data channel, the order the
    // integrations take.
    let media: Vec<&str> = offer
        .sdp
        .lines()
        .filter_map(|line| line.strip_prefix("m="))
        .map(|line| line.split(' ').next().unwrap())
        .collect();
    assert_eq!(media, ["audio", "video", "application"]);
    let camera = answer(
        &mut control,
        &offer,
        WebRtcCameraConfig {
            require_application: true,
            candidates: CandidateDelivery::InAnswer,
            ice_lite: true,
            drop_remote_candidates: true,
            ..WebRtcCameraConfig::default()
        },
    )
    .await;

    let door = control
        .stream_where("door", |door| door["state"] == "live")
        .await;
    assert_eq!(door["last_error"], Value::Null, "{door}");
    assert_eq!(door["sources"][0]["source"]["protocol"], PROTOCOL);
    assert!(door["sources"][0]["source"].get("url").is_none(), "{door}");
    let codecs: Vec<&str> = door["tracks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|track| track["codec"].as_str().unwrap())
        .collect();
    assert_eq!(codecs, ["opus", "h264"], "{door}");
    let stats = camera.stats();
    assert!(WebRtcCameraStats::get(&stats.connected));
    // The source's candidates were relayed and dropped: it found the camera.
    assert_eq!(WebRtcCameraStats::count(&stats.remote_candidates), 0);
    assert!(WebRtcCameraStats::count(&stats.dropped_candidates) >= 1);
    within("the data channel", async {
        while stats.data_channels().is_empty() {
            SystemClock.sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(stats.data_channels(), [NEST_CHANNEL]);
    within("a keyframe request", async {
        while WebRtcCameraStats::count(&stats.keyframe_requests) == 0 {
            SystemClock.sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    // A viewer plays the camera's pictures from a keyframe on, and its
    // audio.
    let viewer_socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    let mut viewer = Viewer::new_with_audio(viewer_socket.local_addr().unwrap(), clock().now())
        .expect("a viewer");
    let (session, _) = control
        .subscribe(
            json!({ "type": "webrtc/offer", "stream_id": "door", "session_id": "ha-1",
                           "sdp": viewer.offer() }),
        )
        .await;
    play(
        &mut control,
        session,
        &mut viewer,
        &viewer_socket,
        |viewer| {
            viewer.is_connected()
                && viewer.keyframe_starts() >= 1
                && viewer.packets().len() >= 40
                && viewer.audio_packets().len() >= 25
        },
    )
    .await;

    // A recording of the stream: its pre-record from the last keyframe,
    // then a second, as an fMP4 file.
    control
        .stream_where("door", |door| holds(door, 1_000))
        .await;
    let (recording, created) = control
        .subscribe(json!({ "type": "recording/create", "stream_id": "door",
                           "prerecord_ms": 1_000, "duration_ms": 1_000 }))
        .await;
    let fetch = fetch_on_socket(&socket, created["url"].as_str().unwrap()).await;
    let started = control.event(recording).await;
    assert_eq!(started["type"], "started", "{started}");
    assert_eq!(
        (&started["video"], &started["audio"]),
        (
            &json!({ "codec": "h264", "width": WIDTH, "height": HEIGHT }),
            &json!({ "codec": "opus" })
        ),
        "{started}"
    );
    let closed = control.event(recording).await;
    assert_eq!(closed["type"], "closed", "{closed}");
    assert_eq!(closed["reason"], "completed", "{closed}");
    let fetched = within("the recording", fetch).await.expect("the fetch");
    assert_eq!(fetched.status, 200, "{fetched:?}");
    assert!(fetched.whole, "the body ends with its last chunk");
    assert_eq!(
        closed["bytes"].as_u64(),
        u64::try_from(fetched.bytes.len()).ok()
    );
    let prerecord_ms = started["prerecord_ms"].as_u64().unwrap();
    assert!(prerecord_ms >= 1_000, "{started}");
    check_recording(&fetched.bytes, prerecord_ms);

    drop(control);
    camera.stop().await;
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}

/// A camera that closes its connection (DTLS `close_notify`, RFC 6347
/// §4.2.7) once its stream is live ends the signal `peer_closed`; after
/// its backoff the source offers again under a new signal, which a
/// Ring-like camera answers, PCMU audio and all: its candidate trickled
/// only, each of the source's taken with its `sdpMLineIndex` (one without
/// it refused), and ICE lite, so the source reaches it through the
/// trickled candidate alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc6347_4_2_7_a_camera_that_closes_ends_its_signal_and_the_source_offers_again() {
    lotse_webrtc::install_crypto_provider();
    let (daemon, dir) = daemon("webrtc-source-closes");
    let mut control = Control::connect(&dir.join("lotse.sock")).await;
    let (signaling, _) = control
        .subscribe(json!({ "type": "signaling/subscribe" }))
        .await;
    control.call(put(&json!({}), 0)).await;
    let first = offer(&mut control, signaling).await;
    // No data channel asked for: no application m-line.
    assert!(!first.sdp.contains("m=application"), "{}", first.sdp);
    let closing = answer(&mut control, &first, WebRtcCameraConfig::default()).await;
    control
        .stream_where("door", |door| door["state"] == "live")
        .await;
    assert!(WebRtcCameraStats::count(&closing.stats().remote_candidates) >= 1);
    closing.close();
    let closed = control.event(signaling).await;
    assert_eq!(
        (&closed["type"], &closed["signal_id"], &closed["code"]),
        (
            &json!("closed"),
            &json!(first.signal_id),
            &json!("peer_closed")
        ),
        "{closed}"
    );
    assert!(WebRtcCameraStats::get(&closing.stats().closed));
    // The client may no longer signal for it.
    let late = control
        .result(
            json!({ "type": "signaling/answer", "signal_id": first.signal_id, "sdp": "v=0\r\n" }),
        )
        .await;
    assert_eq!(late["error"]["code"], "signal_not_found", "{late}");

    let second = offer(&mut control, signaling).await;
    assert_ne!(second.signal_id, first.signal_id);
    let camera = answer(
        &mut control,
        &second,
        WebRtcCameraConfig {
            audio: Some(WebRtcCameraAudio::Pcmu),
            candidates: CandidateDelivery::Trickled,
            require_mline_index: true,
            ice_lite: true,
            ..WebRtcCameraConfig::default()
        },
    )
    .await;
    // Like Ring's integration, it refuses a candidate without
    // `sdpMLineIndex`, however valid its line: none reaches its agent.
    let taken = WebRtcCameraStats::count(&camera.stats().remote_candidates);
    assert!(taken >= 1, "the source's candidates, with their index");
    let host = second.candidates[0]["candidate"].as_str().unwrap();
    let dropped = WebRtcCameraStats::count(&camera.stats().dropped_candidates);
    assert_eq!(
        camera.add_remote_candidate(host, None),
        Err("a candidate without sdpMLineIndex".to_owned())
    );
    // A line that does not parse (RFC 8839 §5.1) is refused with its
    // index too.
    assert!(
        camera
            .add_remote_candidate("candidate:1 1 udp nonsense", Some(0))
            .is_err()
    );
    assert_eq!(
        WebRtcCameraStats::count(&camera.stats().remote_candidates),
        taken
    );
    assert_eq!(
        WebRtcCameraStats::count(&camera.stats().dropped_candidates),
        dropped
    );
    let door = control
        .stream_where("door", |door| {
            door["state"] == "live" && door["tracks"][0]["codec"] == "pcmu"
        })
        .await;
    assert_eq!(door["tracks"][1]["codec"], "h264", "{door}");
    within("media of the second connection", async {
        while WebRtcCameraStats::count(&camera.stats().video_packets) < 50 {
            SystemClock.sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(!WebRtcCameraStats::get(&camera.stats().peer_closed));

    // The stream's delete ends the signal as the source stops: the camera
    // gets the source's close_notify.
    control
        .call(json!({ "type": "stream/delete", "stream_id": "door" }))
        .await;
    let closed = control.event(signaling).await;
    assert_eq!(
        (&closed["type"], &closed["signal_id"], &closed["code"]),
        (
            &json!("closed"),
            &json!(second.signal_id),
            &json!("source_stopped")
        ),
        "{closed}"
    );
    within("the source's close_notify", async {
        while !WebRtcCameraStats::get(&camera.stats().peer_closed) {
            SystemClock.sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    drop(control);
    closing.stop().await;
    camera.stop().await;
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}

/// A Nest-like camera refuses an offer without the data channel: the
/// client relays its error with `signaling/error`, which ends the signal
/// `camera_error`; the attempt failed before an answer, so the stream
/// reports the source unreachable with the camera's words, and after its
/// backoff the source offers again under a new signal, which a camera
/// without audio answers (its audio m-line rejected with port 0, RFC 3264
/// §6, so the stream has the video alone), whose candidates come in its
/// answer and trickled, and whose RTP
/// has no RFC 9143 `mid` header extension: the source finds its m-line by
/// the answer's `a=ssrc` (RFC 5576 §4.1). Its handle dropped closes its
/// connection and ends its task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_camera_error_ends_the_signal_and_the_source_offers_again_after_its_backoff() {
    lotse_webrtc::install_crypto_provider();
    let (daemon, dir) = daemon("webrtc-source-error");
    let mut control = Control::connect(&dir.join("lotse.sock")).await;
    let (signaling, _) = control
        .subscribe(json!({ "type": "signaling/subscribe", "stream_id": "door" }))
        .await;
    control.call(put(&json!({}), 2_000)).await;
    let first = offer(&mut control, signaling).await;
    let media = first.sdp.matches("\r\nm=").count();
    assert_eq!(media, 2, "audio and video, no data channel: {}", first.sdp);
    let nest = WebRtcCameraConfig {
        require_application: true,
        ..WebRtcCameraConfig::default()
    };
    let refusal = FakeWebRtcCamera::answer(&first.sdp, nest, clock())
        .await
        .expect_err("no data channel, no answer");
    let CameraRefusal { code, message } = refusal;
    assert_eq!(code, "webrtc_offer_failed");
    control
        .call(
            json!({ "type": "signaling/error", "signal_id": first.signal_id,
                      "code": code, "message": message }),
        )
        .await;
    let closed = control.event(signaling).await;
    let what = format!("camera: {code}: {message}");
    assert_eq!(
        closed,
        json!({ "type": "closed", "signal_id": first.signal_id, "code": "camera_error",
                "message": what })
    );
    let door = control
        .stream_where("door", |door| door["last_error"] != Value::Null)
        .await;
    assert_eq!(door["last_error"]["code"], "source_unreachable", "{door}");
    assert!(
        door["last_error"]["message"]
            .as_str()
            .unwrap()
            .contains(&what),
        "{door}"
    );

    let second = offer(&mut control, signaling).await;
    assert_ne!(second.signal_id, first.signal_id);
    let camera = answer(
        &mut control,
        &second,
        WebRtcCameraConfig {
            audio: None,
            candidates: CandidateDelivery::Both,
            mid_extension: false,
            ..WebRtcCameraConfig::default()
        },
    )
    .await;
    let door = control
        .stream_where("door", |door| door["state"] == "live")
        .await;
    assert_eq!(door["tracks"].as_array().unwrap().len(), 1, "{door}");
    // Its media reaches the stream: the video track's pre-record fills.
    control.stream_where("door", |door| holds(door, 200)).await;

    // A camera's handle dropped without a stop closes its connection, so
    // the signal ends `peer_closed`, and ends its task, which lets its
    // socket go.
    let addr = camera.addr();
    drop(camera);
    let closed = control.event(signaling).await;
    assert_eq!(
        (&closed["type"], &closed["signal_id"], &closed["code"]),
        (
            &json!("closed"),
            &json!(second.signal_id),
            &json!("peer_closed")
        ),
        "{closed}"
    );
    within("the dropped camera's socket", async {
        while UdpSocket::bind(addr).await.is_err() {
            SystemClock.sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    drop(control);
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}

/// Without a client subscribed to relay its signaling, the source's open
/// waits its 10 s for one and is refused: the stream reports the source
/// unreachable, no signaling client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_signaling_client_the_source_is_unreachable() {
    let (daemon, dir) = daemon("webrtc-source-unsubscribed");
    let mut control = Control::connect(&dir.join("lotse.sock")).await;
    control.call(put(&json!({}), 0)).await;
    let door = control
        .stream_where("door", |door| door["last_error"] != Value::Null)
        .await;
    assert_eq!(door["last_error"]["code"], "source_unreachable", "{door}");
    assert!(
        door["last_error"]["message"]
            .as_str()
            .unwrap()
            .contains("no_signaling_client"),
        "{door}"
    );
    assert_ne!(door["state"], "live");

    drop(control);
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}
