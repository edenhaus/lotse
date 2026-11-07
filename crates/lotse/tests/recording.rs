//! Event recordings end to end: a real daemon (supervisor and workers) plays
//! the fake RTSP camera, keeps a pre-record window while the stream is
//! preloaded, and records recordings through `recording/create` and `GET
//! /v0/recording/{recording_id}`. Every file is read back with mp4-atom, an
//! independent reader of ISO/IEC 14496-12: the first sample is a keyframe
//! as old as `started.prerecord_ms` says, the audio starts with the video
//! (EBU R37, on the container's timestamps) and runs to its end, a camera
//! reconnect inside a recording is one `gap` event where the file's timeline
//! has it, a recording's end ends the body with its last chunk, a worker crash
//! cuts it, a recording nobody fetches ends `not_fetched`, two recordings run on one
//! stream, and the mTLS listener serves the route as the socket does.
//! Needs the `source-rtsp` and `output-recording` features (the defaults).

#![cfg(all(feature = "source-rtsp", feature = "output-recording"))]
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
use common::recording_body::{Fetched, fetch, fetch_on_socket};
use common::{Daemon, SocketDir, json, socket_dir};
use futures_util::{SinkExt as _, StreamExt as _};
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::task::spawn_named;
use lotse_testing::fake_camera::{CameraAudio, HEIGHT, WIDTH};
use lotse_testing::{CameraConfig, FakeCamera};
use mp4_atom::Codec as SampleEntry;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

/// How long one step of a test may take before it fails: a frame, a
/// result, a recording's end.
const STEP: Duration = Duration::from_secs(20);

/// The camera's frame rate: 40 ms frames.
const FPS: u32 = 25;

/// Frames per GOP: a keyframe every 1.28 s.
const GOP: u32 = 32;

/// One GOP, in milliseconds.
const GOP_MS: u64 = 1_280;

/// One frame, in milliseconds.
const FRAME_MS: u64 = 40;

/// The video's timescale, the RTP clock of H.264 (RFC 6184 §8.2.1).
const VIDEO_RATE: u64 = 90_000;

/// `future`, or a failed test after [`STEP`] of real time.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::select! {
        out = future => out,
        () = SystemClock.sleep(STEP) => panic!("{what}: nothing within {STEP:?}"),
    }
}

/// The fake camera with H.264 at [`FPS`], a keyframe every [`GOP`] frames
/// and `audio`, its Sender Reports from one wall clock.
async fn camera(audio: Option<CameraAudio>) -> FakeCamera {
    let config = CameraConfig {
        fps: FPS,
        gop: GOP,
        audio,
        ..CameraConfig::default()
    };
    FakeCamera::start(config, Arc::new(SystemClock))
        .await
        .expect("camera binds")
}

/// A daemon on a socket of its own, with `args` and `env` on top, ready.
fn daemon(test: &str, args: &[&str], env: &[(&str, &str)]) -> (Daemon, SocketDir) {
    let dir = socket_dir(test);
    let socket = dir.join("lotse.sock");
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
    let daemon = Daemon::start(&all, env);
    (daemon, dir)
}

/// One control connection over the daemon's socket, with the frames of
/// other commands and subscriptions kept until asked for.
struct Control {
    ws: WebSocketStream<UnixStream>,
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
        let mut control = Self {
            ws,
            next_id: 1,
            kept: Vec::new(),
        };
        let hello = control.frame().await;
        assert_eq!(hello["type"], "hello", "{hello}");
        control
    }

    /// The next JSON frame from the daemon.
    async fn frame(&mut self) -> Value {
        loop {
            let message = within("a frame", self.ws.next())
                .await
                .expect("the connection stays open")
                .expect("a websocket message");
            if let Message::Text(text) = message {
                return serde_json::from_str(&text).expect("JSON");
            }
        }
    }

    /// Sends `command` with the next id; the id.
    async fn send(&mut self, mut command: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        command["id"] = json!(id);
        self.ws
            .send(Message::Text(command.to_string().into()))
            .await
            .expect("command sent");
        id
    }

    /// The next kept or arriving frame that `wanted` takes.
    async fn take(&mut self, wanted: impl Fn(&Value) -> bool) -> Value {
        if let Some(at) = self.kept.iter().position(&wanted) {
            return self.kept.remove(at);
        }
        loop {
            let frame = self.frame().await;
            if wanted(&frame) {
                return frame;
            }
            self.kept.push(frame);
        }
    }

    /// The result frame of command `id`.
    async fn result_of(&mut self, id: u64) -> Value {
        self.take(|frame| frame["type"] == "result" && frame["id"] == id)
            .await
    }

    /// Sends `command` and returns its result, which must be a success.
    async fn call(&mut self, command: Value) -> Value {
        let id = self.send(command.clone()).await;
        let frame = self.result_of(id).await;
        assert_eq!(frame["success"], true, "{command} failed: {frame}");
        frame["result"].clone()
    }

    /// The next event of the subscription `id`.
    async fn event(&mut self, id: u64) -> Value {
        let frame = self
            .take(|frame| frame["type"] == "event" && frame["id"] == id)
            .await;
        frame["event"].clone()
    }

    /// The events of the recording subscribed as `id` up to and including its
    /// `closed`.
    async fn until_closed(&mut self, id: u64) -> Vec<Value> {
        let mut events = Vec::new();
        loop {
            let event = self.event(id).await;
            let closed = event["type"] == "closed";
            events.push(event);
            if closed {
                return events;
            }
        }
    }

    /// `stream/put` of `stream_id` playing `url`, preloaded with a window
    /// of `prerecord_ms` when `preload`.
    async fn put(&mut self, stream_id: &str, url: &str, preload: bool, prerecord_ms: u32) {
        let put = self
            .call(json!({ "type": "stream/put", "stream_id": stream_id,
                          "sources": [lotse_testing::source(url, json!({}))], "preload": preload,
                          "prerecord_ms": prerecord_ms }))
            .await;
        assert_eq!(put, json!({ "created": true }));
    }

    /// `stream/get` until the video track's pre-record holds `held_ms`.
    async fn wait_window(&mut self, stream_id: &str, held_ms: u64) -> Value {
        let deadline = SystemClock.now() + STEP;
        loop {
            let stream = self
                .call(json!({ "type": "stream/get", "stream_id": stream_id }))
                .await;
            let held = stream["tracks"]
                .as_array()
                .and_then(|tracks| tracks.iter().find(|track| track["kind"] == "video"))
                .and_then(|video| video["prerecord"]["held_ms"].as_u64());
            if held.is_some_and(|held| held >= held_ms) {
                return stream;
            }
            assert!(
                SystemClock.now() < deadline,
                "{stream_id}'s window never held {held_ms} ms: {stream}"
            );
            // The worker reports its tracks once a second.
            SystemClock.sleep(Duration::from_millis(100)).await;
        }
    }

    /// `recording/create` with `fields`; the subscription's id and the result.
    async fn start_recording(&mut self, fields: Value) -> (u64, Value) {
        let mut command = json!({ "type": "recording/create" });
        for (key, value) in fields.as_object().expect("an object") {
            command[key] = value.clone();
        }
        let id = self.send(command).await;
        let frame = self.result_of(id).await;
        assert_eq!(frame["success"], true, "recording/create: {frame}");
        (id, frame["result"].clone())
    }
}

/// The common checks of a recording that ended `reason` with its body whole:
/// the events' order, `closed`'s bytes against the body, the headers.
fn assert_ended_whole(fetched: &Fetched, recording_id: &str, events: &[Value], reason: &str) {
    assert_eq!(fetched.status, 200, "{fetched:?}");
    assert_eq!(fetched.content_type.as_deref(), Some("video/mp4"));
    assert_eq!(fetched.recording_id.as_deref(), Some(recording_id));
    assert!(fetched.whole, "the body ends with its last chunk");
    assert_eq!(events[0]["type"], "started", "{events:?}");
    let closed = events.last().unwrap();
    assert_eq!(
        (&closed["reason"], closed["bytes"].as_u64()),
        (&json!(reason), u64::try_from(fetched.bytes.len()).ok()),
        "{events:?}"
    );
}

/// A recording of a preloaded stream with a window starts at the newest
/// keyframe captured at or before `prerecord_ms` ago: `started.prerecord_ms` is
/// that keyframe's age, so at least what was asked and less than a GOP
/// more, and the file's video starts at it with its IDR and covers its age
/// and `duration_ms`. The audio starts with the video on the file's timeline
/// (EBU R37: within 40 ms) and runs to the video's end, each track's last
/// sample the last captured before the recording's end: AAC-LC as the camera
/// sends it, starting with the frame playing at the keyframe, and PCMU
/// transcoded to Opus, whose last PCM short of a packet the end leaves
/// out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ebu_r37_a_preloaded_recording_starts_at_a_keyframe_prerecord_ms_old_with_its_audio() {
    let aac = camera(Some(CameraAudio::Aac)).await;
    let pcmu = camera(Some(CameraAudio::Pcmu)).await;
    let (mut daemon, dir) = daemon("recording-av", &[], &[]);
    daemon.wait_for("\"event\":\"ready\"");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    control.put("front", &aac.url(), true, 10_000).await;
    control.put("door", &pcmu.url(), true, 10_000).await;
    control.wait_window("front", 3_000).await;
    control.wait_window("door", 3_000).await;

    let mut recordings = Vec::new();
    for stream_id in ["front", "door"] {
        let (id, result) = control
            .start_recording(
                json!({ "stream_id": stream_id, "prerecord_ms": 2_000, "duration_ms": 2_000 }),
            )
            .await;
        let fetch = fetch_on_socket(&socket, result["url"].as_str().unwrap()).await;
        recordings.push((id, result, fetch));
    }
    for ((id, result, fetch), audio) in recordings.into_iter().zip(["aac_lc", "opus"]) {
        let events = control.until_closed(id).await;
        let fetched = within("the body", fetch).await.expect("the fetch");
        let recording_id = result["recording_id"].as_str().unwrap();
        assert_ended_whole(&fetched, recording_id, &events, "completed");
        assert_eq!(events.len(), 2, "started and closed: {events:?}");
        let started = &events[0];
        assert_eq!(
            (&started["video"], &started["audio"]),
            (
                &json!({ "codec": "h264", "width": WIDTH, "height": HEIGHT }),
                &json!({ "codec": audio })
            )
        );
        let prerecord_ms = started["prerecord_ms"].as_u64().unwrap();
        assert!(
            (2_000..2_000 + GOP_MS + FRAME_MS).contains(&prerecord_ms),
            "the newest keyframe 2 s ago or more: {prerecord_ms}"
        );

        let file = &fetched.bytes;
        let mp4 = parse(file);
        let (video_id, video_rate) = mp4.video();
        assert_eq!(video_rate, VIDEO_RATE);
        let video = mp4.samples(file, video_id);
        assert_starts_at_a_keyframe_without_holes(&video);
        // From the keyframe `prerecord_ms` ago to the first frame at or after
        // `duration_ms` from now, which the recording leaves out.
        let last = video.last().unwrap();
        let span = ms(last.dts + last.duration - video[0].dts, video_rate);
        let expected = prerecord_ms + 2_000;
        assert!(
            span.abs_diff(expected) <= 2 * FRAME_MS,
            "the video covers {span} ms, the recording asked {expected} ms"
        );
        let closed = events.last().unwrap();
        assert!(
            closed["duration_ms"].as_u64().unwrap().abs_diff(span) <= 2 * FRAME_MS,
            "{closed} for {span} ms of video"
        );

        let (entry, audio_rate, audio) = mp4.audio(file).expect("an audio track");
        assert_eq!(holes(&audio), [], "the audio runs without a hole");
        let video_start = ms(video[0].dts, video_rate);
        let audio_start = ms(audio[0].dts, audio_rate);
        // Each arm: the audio packet's length, and what the end leaves
        // out of the audio besides, in milliseconds.
        let (packet_ms, held_ms) = match entry {
            SampleEntry::Mp4a(_) => {
                assert_eq!(audio_rate, 16_000);
                assert!(audio.iter().all(|sample| sample.duration == 1_024));
                // The audio frame playing at the keyframe, 64 ms long (each
                // track's ticks rounded down: 1 ms of slack).
                assert!(
                    audio_start <= video_start + 1 && video_start <= audio_start + 64,
                    "audio at {audio_start} ms, video at {video_start} ms"
                );
                // The camera's frames as they came: 1024 samples at 16 kHz.
                (64, 0)
            }
            SampleEntry::Opus(_) => {
                assert_eq!(audio_rate, 48_000);
                // 20 ms packets (RFC 7587 §4.2).
                assert!(audio.iter().all(|sample| sample.duration == 960));
                assert!(
                    audio_start.abs_diff(video_start) <= 40,
                    "audio at {audio_start} ms, video at {video_start} ms"
                );
                // The end leaves out the PCM not yet encoded: less than a
                // packet plus the chain's delay, the encoder's 2.5 ms
                // look-ahead and the resampler's (under 5 ms together).
                (20, 20 + 5)
            }
            other => panic!("audio {other:?}"),
        };
        // The audio runs to the video's end: each track's last sample is
        // the last captured before the recording's end, so the audio ends at
        // most a packet after the video and at most a video frame, and what
        // the end leaves out, before it. 5 ms of slack: each track's ticks
        // rounded down, and the capture times the end goes by against the
        // file's timestamps.
        let last_audio = audio.last().unwrap();
        let audio_end = ms(last_audio.dts + last_audio.duration, audio_rate);
        let video_end = ms(last.dts + last.duration, video_rate);
        assert!(
            audio_end <= video_end + packet_ms + 5
                && video_end <= audio_end + FRAME_MS + held_ms + 5,
            "the audio ends at {audio_end} ms, the video at {video_end} ms"
        );
    }
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    aac.stop().await;
    pcmu.stop().await;
}

/// Two recordings run on one stream at once, one fetched over the socket and
/// one over the mutual-TLS listener, which serves the same route; a third
/// is refused `limit_reached` (`max_recordings_per_stream`). A recording without audio
/// has one track, and one asking nothing before now starts at the newest
/// keyframe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9112_7_1_two_recordings_of_one_stream_come_whole_over_the_socket_and_the_mtls_listener()
{
    use std::os::unix::fs::DirBuilderExt as _;

    use lotse_core::fingerprint::Fingerprint;
    use lotse_testing::control_tls::{self, ClientCert, ClientIdentity};

    let cam = camera(Some(CameraAudio::Aac)).await;
    let client = ClientIdentity::generate().unwrap();
    let dir = socket_dir("recording-two");
    let data = dir.join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let socket = dir.join("lotse.sock");
    let pin = client.pin.to_string();
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
            "--control-listen",
            "127.0.0.1:0",
        ],
        &[
            ("LOTSE_CONTROL_CLIENTS", &pin),
            ("LOTSE_DATA_DIR", data.to_str().expect("utf-8 path")),
        ],
    );
    let bound = json(&daemon.wait_for("control TLS listener bound"));
    let listener: std::net::SocketAddr = bound["addr"].as_str().unwrap().parse().unwrap();
    let server_pin = Fingerprint::parse(bound["server_pin"].as_str().unwrap()).unwrap();
    daemon.wait_for("\"event\":\"ready\"");
    let mut control = Control::connect(&socket).await;
    control.put("front", &cam.url(), true, 10_000).await;
    control.wait_window("front", 2_000).await;

    let (with_audio, first) = control
        .start_recording(json!({ "stream_id": "front", "recording_id": "with-audio",
                            "prerecord_ms": 1_000, "duration_ms": 1_500 }))
        .await;
    assert_eq!(
        first,
        json!({ "recording_id": "with-audio", "url": "/v0/recording/with-audio" })
    );
    let over_socket = fetch_on_socket(&socket, "/v0/recording/with-audio").await;
    let (video_only, second) = control
        .start_recording(json!({ "stream_id": "front", "duration_ms": 1_000, "audio": false }))
        .await;
    let config =
        control_tls::client_config(server_pin, ClientCert::Own(&client), control_tls::TLS13)
            .unwrap();
    let tls = control_tls::connect(listener, config).await.expect("mTLS");
    let over_tls = spawn_named(
        "recording-fetch",
        fetch(tls, second["url"].as_str().unwrap().to_owned()),
    );
    let third = control
        .send(json!({ "type": "recording/create", "stream_id": "front", "duration_ms": 1_000 }))
        .await;
    let refused = control.result_of(third).await;
    assert_eq!(
        (&refused["success"], &refused["error"]["code"]),
        (&json!(false), &json!("limit_reached")),
        "{refused}"
    );
    assert_eq!(
        refused["error"]["details"]["limit"],
        "max_recordings_per_stream"
    );

    let events = control.until_closed(with_audio).await;
    let fetched = within("the socket's body", over_socket).await.unwrap();
    assert_ended_whole(&fetched, "with-audio", &events, "completed");
    let mp4 = parse(&fetched.bytes);
    let (video_id, _) = mp4.video();
    assert_starts_at_a_keyframe_without_holes(&mp4.samples(&fetched.bytes, video_id));
    assert!(mp4.audio(&fetched.bytes).is_some(), "with its audio");

    let events = control.until_closed(video_only).await;
    let fetched = within("the listener's body", over_tls).await.unwrap();
    let recording_id = second["recording_id"].as_str().unwrap();
    assert_ended_whole(&fetched, recording_id, &events, "completed");
    assert_eq!(events[0]["audio"], Value::Null, "{events:?}");
    let prerecord_ms = events[0]["prerecord_ms"].as_u64().unwrap();
    assert!(
        prerecord_ms < GOP_MS + FRAME_MS,
        "the newest keyframe: {prerecord_ms}"
    );
    let mp4 = parse(&fetched.bytes);
    assert_eq!(mp4.moov.trak.len(), 1, "video only");
    let (video_id, _) = mp4.video();
    assert_starts_at_a_keyframe_without_holes(&mp4.samples(&fetched.bytes, video_id));

    let stream = control
        .call(json!({ "type": "stream/get", "stream_id": "front" }))
        .await;
    assert_eq!(
        (
            &stream["stats"]["recordings_started"],
            &stream["stats"]["recordings_completed"]
        ),
        (&json!(2), &json!(2)),
        "{stream}"
    );
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    drop(dir);
    cam.stop().await;
}

/// The camera drops its connection while a recording runs: the stream
/// reconnects, the recording goes on and reports one `reconnect` gap, from the
/// last frame before the drop to the new connection's first, a keyframe,
/// where the file has them; the hole between them is what the reconnect
/// took beyond the last frame's length (the fake camera's, on the same
/// host, takes a few milliseconds, so the file has none). The recording then
/// ends `completed` at its end with the body's last chunk (RFC 9112 §7.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9112_7_1_a_reconnect_inside_a_recording_is_one_gap_where_the_file_has_it_and_its_end_ends_it_whole()
 {
    let cam = camera(Some(CameraAudio::Aac)).await;
    let (mut daemon, dir) = daemon("recording-gap", &[], &[]);
    daemon.wait_for("\"event\":\"ready\"");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    control.put("front", &cam.url(), true, 10_000).await;
    control.wait_window("front", 1_000).await;
    let (id, result) = control
        .start_recording(json!({ "stream_id": "front", "prerecord_ms": 500, "duration_ms": 5_000 }))
        .await;
    let recording_id = result["recording_id"].as_str().unwrap().to_owned();
    let fetch = fetch_on_socket(&socket, result["url"].as_str().unwrap()).await;
    let started = control.event(id).await;
    assert_eq!(started["type"], "started", "{started}");

    cam.drop_connections();
    let gap = control.event(id).await;
    assert_eq!(gap["type"], "gap", "{gap}");
    assert_eq!(gap["reason"], "reconnect", "{gap}");
    let mut events = vec![started, gap.clone()];
    events.extend(control.until_closed(id).await);
    let fetched = within("the body", fetch).await.unwrap();
    assert_ended_whole(&fetched, &recording_id, &events, "completed");
    assert_eq!(events.len(), 3, "one gap: {events:?}");
    assert_eq!(events[2]["gaps"], 1);

    let file = &fetched.bytes;
    let mp4 = parse(file);
    let (video_id, rate) = mp4.video();
    let video = mp4.samples(file, video_id);
    assert!(video[0].sync, "the recording starts at a keyframe");
    // The gap's times are recording media times, as the file's (whole
    // milliseconds, rounded down by both): the frame before the hole and
    // the new connection's first, a keyframe that begins a fragment of
    // its own. The hole between them is what the camera's reconnect took
    // beyond the last frame's length, none for one quicker than a frame.
    let (from_ms, to_ms) = (
        gap["from_ms"].as_u64().unwrap(),
        gap["to_ms"].as_u64().unwrap(),
    );
    let at = |time_ms: u64| {
        video
            .iter()
            .position(|sample| ms(sample.dts, rate).abs_diff(time_ms) <= 1)
            .unwrap_or_else(|| panic!("no video sample at {time_ms} ms: {gap}"))
    };
    let (before, after) = (at(from_ms), at(to_ms));
    assert_eq!(after, before + 1, "{gap}");
    assert!(video[after].sync, "the new connection starts at a keyframe");
    assert!(
        mp4.fragments
            .iter()
            .any(|(moof, _)| moof.traf.iter().any(|traf| {
                traf.tfhd.track_id == video_id
                    && traf.tfdt.as_ref().unwrap().base_media_decode_time == video[after].dts
            })),
        "the new connection begins a fragment"
    );
    let ended = video[before].dts + video[before].duration;
    let hole = video[after].dts - ended;
    assert_eq!(
        holes(&video),
        if hole == 0 {
            vec![]
        } else {
            vec![(video[before].dts, video[after].dts)]
        },
        "no other hole"
    );
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    cam.stop().await;
}

/// The worker dies while its recording runs, its body fetched: the recording ends
/// `worker_crashed` with no bytes counted, and its body ends without its
/// last chunk, a cut transfer (RFC 9112 §8), after the bytes the worker
/// wrote: the file's beginning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9112_8_a_worker_crash_ends_the_recording_worker_crashed_and_cuts_its_body() {
    let cam = camera(None).await;
    let (mut daemon, dir) = daemon("recording-crash", &[], &[]);
    daemon.wait_for("\"event\":\"ready\"");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    control.put("front", &cam.url(), true, 10_000).await;
    let stream = control.wait_window("front", 1_000).await;
    let pid = stream["sources"][0]["connection"]["worker"]["pid"]
        .as_i64()
        .unwrap();
    let (id, result) = control
        .start_recording(
            json!({ "stream_id": "front", "prerecord_ms": 500, "duration_ms": 60_000 }),
        )
        .await;
    let fetch = fetch_on_socket(&socket, result["url"].as_str().unwrap()).await;
    let started = control.event(id).await;
    assert_eq!(started["type"], "started", "{started}");
    // The supervisor handed the body to the `GET` before the worker dies:
    // a recording that ends `worker_crashed` keeps no body nobody took, so a
    // `GET` it beat would find no recording (404). Neither `started` nor the
    // request leaving the test says the body was taken.
    let handed_out = json(&daemon.wait_for("\"event\":\"recording_fetched\""));
    assert_eq!(
        handed_out["recording.id"], result["recording_id"],
        "{handed_out}"
    );

    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
        rustix::process::Signal::KILL,
    )
    .expect("SIGKILL sent");
    let events = control.until_closed(id).await;
    assert_eq!(
        events.last().unwrap(),
        &json!({ "type": "closed", "reason": "worker_crashed", "bytes": 0,
                 "duration_ms": 0, "gaps": 0 }),
        "{events:?}"
    );
    let fetched = within("the body", fetch).await.unwrap();
    assert_eq!(fetched.status, 200);
    assert!(!fetched.whole, "the body is cut");
    assert_eq!(fetched.bytes.get(4..8), Some(&b"ftyp"[..]));
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    cam.stop().await;
}

/// A recording of an idle stream is demand: the stream connects for it, and it
/// starts at the first keyframe as it arrives (`prerecord_ms` under a frame:
/// the time it took to reach the container). Nobody fetches its body
/// within `limits.recording_fetch_timeout_ms`, so it ends `not_fetched`, and a
/// `GET` afterwards finds no recording (404 `recording_not_found`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9110_15_5_5_a_recording_nobody_fetches_ends_not_fetched_and_its_body_is_gone() {
    let cam = camera(None).await;
    let (mut daemon, dir) = daemon(
        "recording-unfetched",
        &[],
        &[("LOTSE_RECORDING_FETCH_TIMEOUT_MS", "4000")],
    );
    daemon.wait_for("\"event\":\"ready\"");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    control.put("front", &cam.url(), false, 0).await;
    let (id, result) = control
        .start_recording(
            json!({ "stream_id": "front", "prerecord_ms": 2_000, "duration_ms": 60_000 }),
        )
        .await;
    let events = control.until_closed(id).await;
    assert_eq!(events[0]["type"], "started", "{events:?}");
    let prerecord_ms = events[0]["prerecord_ms"].as_u64().unwrap();
    assert!(
        prerecord_ms < FRAME_MS,
        "nothing held: the first keyframe as it arrived, {prerecord_ms} ms old: {events:?}"
    );
    assert_eq!(
        events.last().unwrap()["reason"],
        "not_fetched",
        "{events:?}"
    );
    let fetched = fetch(
        UnixStream::connect(&socket).await.unwrap(),
        result["url"].as_str().unwrap().to_owned(),
    )
    .await;
    assert_eq!(fetched.status, 404, "{fetched:?}");
    let error: Value = serde_json::from_slice(&fetched.bytes).unwrap();
    assert_eq!(error["code"], "recording_not_found", "{error}");
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    cam.stop().await;
}
