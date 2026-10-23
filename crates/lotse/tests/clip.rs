//! Event clips end to end: a real daemon (supervisor and workers) plays
//! the fake RTSP camera, keeps a pre-roll window while the stream is
//! preloaded, and records clips through `clip/start` and `GET
//! /v0/clips/{clip_id}`. Every file is read back with mp4-atom, an
//! independent reader of ISO/IEC 14496-12: the first sample is a keyframe
//! as old as `started.before_ms` says, the audio starts with the video
//! (EBU R37, on the container's timestamps), a camera reconnect inside a
//! clip is one `gap` event where the file's timeline has it, `clip/stop`
//! ends the body with its last chunk, a worker crash cuts it, a clip nobody
//! fetches ends `not_fetched`, two clips run on one stream, and the mTLS
//! listener serves the route as the socket does. Needs the `source-rtsp`
//! and `output-clip` features (the defaults).

#![cfg(all(feature = "source-rtsp", feature = "output-clip"))]
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

use common::{Daemon, SocketDir, json, socket_dir};
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::task::spawn_named;
use lotse_testing::fake_camera::{CameraAudio, HEIGHT, WIDTH};
use lotse_testing::{CameraConfig, FakeCamera};
use mp4_atom::{Any, Codec as SampleEntry, Decode as _, Moof, Moov};
use serde_json::{Value, json};
use tokio::net::UnixStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

/// How long one step of a test may take before it fails: a frame, a
/// result, a clip's end.
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

/// `sample_is_non_sync_sample` in a sample's flags (ISO/IEC 14496-12
/// §8.8.3.1).
const NON_SYNC: u32 = 0x0001_0000;

/// An IDR slice's NAL unit type (ISO/IEC 14496-10 Table 7-1).
const NAL_IDR: u8 = 5;

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

    /// The events of the clip subscribed as `id` up to and including its
    /// `stopped`.
    async fn until_stopped(&mut self, id: u64) -> Vec<Value> {
        let mut events = Vec::new();
        loop {
            let event = self.event(id).await;
            let stopped = event["type"] == "stopped";
            events.push(event);
            if stopped {
                return events;
            }
        }
    }

    /// `stream/put` of `stream_id` playing `url`, preloaded with a window
    /// of `preroll_ms` when `preload`.
    async fn put(&mut self, stream_id: &str, url: &str, preload: bool, preroll_ms: u32) {
        let put = self
            .call(json!({ "type": "stream/put", "stream_id": stream_id,
                          "sources": [{ "url": url }], "preload": preload,
                          "preroll_ms": preroll_ms }))
            .await;
        assert_eq!(put, json!({ "created": true }));
    }

    /// `stream/get` until the video track's pre-roll holds `held_ms`.
    async fn wait_window(&mut self, stream_id: &str, held_ms: u64) -> Value {
        let deadline = SystemClock.now() + STEP;
        loop {
            let stream = self
                .call(json!({ "type": "stream/get", "stream_id": stream_id }))
                .await;
            let held = stream["tracks"]
                .as_array()
                .and_then(|tracks| tracks.iter().find(|track| track["kind"] == "video"))
                .and_then(|video| video["preroll"]["held_ms"].as_u64());
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

    /// `clip/start` with `fields`; the subscription's id and the result.
    async fn start_clip(&mut self, fields: Value) -> (u64, Value) {
        let mut command = json!({ "type": "clip/start" });
        for (key, value) in fields.as_object().expect("an object") {
            command[key] = value.clone();
        }
        let id = self.send(command).await;
        let frame = self.result_of(id).await;
        assert_eq!(frame["success"], true, "clip/start: {frame}");
        (id, frame["result"].clone())
    }
}

/// What a `GET` of a clip's body got.
#[derive(Debug)]
struct Fetched {
    status: u16,
    content_type: Option<String>,
    clip_id: Option<String>,
    bytes: Vec<u8>,
    /// The body ended with its last chunk (RFC 9112 §7.1), not cut.
    whole: bool,
}

/// `GET url` over `stream` (HTTP/1.1), read to its end as it comes.
async fn fetch<S>(stream: S, url: String) -> Fetched
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
async fn fetch_on_socket(socket: &Path, url: &str) -> tokio::task::JoinHandle<Fetched> {
    let stream = UnixStream::connect(socket).await.expect("socket connects");
    spawn_named("clip-fetch", fetch(stream, url.to_owned()))
}

/// A clip's file as mp4-atom reads it: every top-level box, in order.
struct Mp4 {
    moov: Moov,
    /// Each fragment and where its `moof` starts in the file.
    fragments: Vec<(Moof, usize)>,
}

/// One sample read back.
#[derive(Debug, Clone)]
struct Sample {
    /// Decode time in the track's timescale.
    dts: u64,
    duration: u64,
    sync: bool,
    bytes: Vec<u8>,
}

/// Reads `file` box by box: `ftyp` first (ISO/IEC 14496-12 §4.3), then
/// `moov`, then a `moof` and an `mdat` per fragment, nothing left over.
fn parse(file: &[u8]) -> Mp4 {
    let mut rest = file;
    let mut boxes = Vec::new();
    while !rest.is_empty() {
        let start = file.len() - rest.len();
        boxes.push((Any::decode(&mut rest).expect("a box"), start));
    }
    let mut boxes = boxes.into_iter();
    let Some((Any::Ftyp(ftyp), 0)) = boxes.next() else {
        panic!("the file does not begin with ftyp");
    };
    assert_eq!(ftyp.major_brand, b"iso6".into());
    let Some((Any::Moov(movie), _)) = boxes.next() else {
        panic!("no moov after ftyp");
    };
    let mut fragments = Vec::new();
    while let Some((placed, start)) = boxes.next() {
        let Any::Moof(moof) = placed else {
            panic!("a {:?} where a moof belongs", placed.kind());
        };
        let Some((Any::Mdat(_), _)) = boxes.next() else {
            panic!("a moof without its mdat");
        };
        fragments.push((moof, start));
    }
    Mp4 {
        moov: movie,
        fragments,
    }
}

impl Mp4 {
    /// The track whose sample entry `pick` takes: its id and timescale.
    fn track(&self, pick: impl Fn(&SampleEntry) -> bool) -> Option<(u32, u64)> {
        self.moov
            .trak
            .iter()
            .find(|trak| trak.mdia.minf.stbl.stsd.codecs.iter().any(&pick))
            .map(|trak| (trak.tkhd.track_id, u64::from(trak.mdia.mdhd.timescale)))
    }

    /// The video track: `avc1`.
    fn video(&self) -> (u32, u64) {
        self.track(|entry| matches!(entry, SampleEntry::Avc1(_)))
            .expect("an avc1 track")
    }

    /// The audio track's sample entry and samples, if it has one.
    fn audio(&self, file: &[u8]) -> Option<(SampleEntry, u64, Vec<Sample>)> {
        let trak = self.moov.trak.iter().find(|trak| {
            trak.mdia
                .minf
                .stbl
                .stsd
                .codecs
                .iter()
                .any(|entry| matches!(entry, SampleEntry::Mp4a(_) | SampleEntry::Opus(_)))
        })?;
        let entry = trak.mdia.minf.stbl.stsd.codecs[0].clone();
        let samples = self.samples(file, trak.tkhd.track_id);
        Some((entry, u64::from(trak.mdia.mdhd.timescale), samples))
    }

    /// The samples of track `track_id`, in decode order.
    fn samples(&self, file: &[u8], track_id: u32) -> Vec<Sample> {
        let default_flags = self
            .moov
            .mvex
            .as_ref()
            .and_then(|mvex| mvex.trex.iter().find(|trex| trex.track_id == track_id))
            .map_or(0, |trex| trex.default_sample_flags);
        let mut out = Vec::new();
        for (moof, start) in &self.fragments {
            for traf in moof
                .traf
                .iter()
                .filter(|traf| traf.tfhd.track_id == track_id)
            {
                // ISO/IEC 14496-12 §8.8.7: offsets count from the moof.
                assert!(traf.tfhd.default_base_is_moof);
                let mut dts = traf.tfdt.as_ref().expect("a tfdt").base_media_decode_time;
                for trun in &traf.trun {
                    let offset = usize::try_from(trun.data_offset.expect("a data offset")).unwrap();
                    let mut at = start + offset;
                    for entry in &trun.entries {
                        let size = usize::try_from(entry.size.expect("a size")).unwrap();
                        let duration = u64::from(entry.duration.expect("a duration"));
                        let flags = entry
                            .flags
                            .or(traf.tfhd.default_sample_flags)
                            .unwrap_or(default_flags);
                        out.push(Sample {
                            dts,
                            duration,
                            sync: flags & NON_SYNC == 0,
                            bytes: file[at..at + size].to_vec(),
                        });
                        at += size;
                        dts += duration;
                    }
                }
            }
        }
        out
    }
}

/// The NAL unit types of a sample of 4-byte length-prefixed NAL units
/// (ISO/IEC 14496-15 §5.3.3.1, `lengthSizeMinusOne` 3).
fn nal_types(sample: &[u8]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut rest = sample;
    while let Some((length, after)) = rest.split_first_chunk::<4>() {
        let length = usize::try_from(u32::from_be_bytes(*length)).unwrap();
        let (unit, next) = after.split_at(length);
        types.push(unit[0] & 0x1f);
        rest = next;
    }
    assert!(rest.is_empty(), "a sample ends inside a NAL unit's length");
    types
}

/// Milliseconds of `ticks` at `rate`, rounded down as the daemon's
/// clip times are.
fn ms(ticks: u64, rate: u64) -> u64 {
    ticks * 1_000 / rate
}

/// Where each sample after the first in `samples` begins later than the
/// one before it ended: the holes on the track's timeline, as the
/// decode times of the samples around them.
fn holes(samples: &[Sample]) -> Vec<(u64, u64)> {
    samples
        .windows(2)
        .filter(|pair| pair[1].dts > pair[0].dts + pair[0].duration)
        .map(|pair| (pair[0].dts, pair[1].dts))
        .collect()
}

/// A video track of `samples` starts at a keyframe with its IDR and has no
/// hole.
fn assert_starts_at_a_keyframe_without_holes(samples: &[Sample]) {
    let first = samples.first().expect("video samples");
    assert!(first.sync, "the first sample is a sync sample");
    assert!(
        nal_types(&first.bytes).contains(&NAL_IDR),
        "{:?}",
        nal_types(&first.bytes)
    );
    assert_eq!(holes(samples), [], "the video runs without a hole");
}

/// The common checks of a clip that ended `reason` with its body whole:
/// the events' order, `stopped`'s bytes against the body, the headers.
fn assert_ended_whole(fetched: &Fetched, clip_id: &str, events: &[Value], reason: &str) {
    assert_eq!(fetched.status, 200, "{fetched:?}");
    assert_eq!(fetched.content_type.as_deref(), Some("video/mp4"));
    assert_eq!(fetched.clip_id.as_deref(), Some(clip_id));
    assert!(fetched.whole, "the body ends with its last chunk");
    assert_eq!(events[0]["type"], "started", "{events:?}");
    let stopped = events.last().unwrap();
    assert_eq!(
        (&stopped["reason"], stopped["bytes"].as_u64()),
        (&json!(reason), u64::try_from(fetched.bytes.len()).ok()),
        "{events:?}"
    );
}

/// A clip of a preloaded stream with a window starts at the newest
/// keyframe captured at or before `before_ms` ago: `started.before_ms` is
/// that keyframe's age, so at least what was asked and less than a GOP
/// more, and the file's video starts at it with its IDR and covers its age
/// and `after_ms`. The audio starts with the video on the file's timeline
/// (EBU R37: within 40 ms): AAC-LC as the camera sends it, starting with
/// the frame playing at the keyframe, and PCMU transcoded to Opus.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ebu_r37_a_preloaded_clip_starts_at_a_keyframe_before_ms_old_with_its_audio() {
    let aac = camera(Some(CameraAudio::Aac)).await;
    let pcmu = camera(Some(CameraAudio::Pcmu)).await;
    let (mut daemon, dir) = daemon("clip-av", &[], &[]);
    daemon.wait_for("\"event\":\"ready\"");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    control.put("front", &aac.url(), true, 10_000).await;
    control.put("door", &pcmu.url(), true, 10_000).await;
    control.wait_window("front", 3_000).await;
    control.wait_window("door", 3_000).await;

    let mut clips = Vec::new();
    for stream_id in ["front", "door"] {
        let (id, result) = control
            .start_clip(json!({ "stream_id": stream_id, "before_ms": 2_000, "after_ms": 2_000 }))
            .await;
        let fetch = fetch_on_socket(&socket, result["url"].as_str().unwrap()).await;
        clips.push((id, result, fetch));
    }
    for ((id, result, fetch), audio) in clips.into_iter().zip(["aac_lc", "opus"]) {
        let events = control.until_stopped(id).await;
        let fetched = within("the body", fetch).await.expect("the fetch");
        let clip_id = result["clip_id"].as_str().unwrap();
        assert_ended_whole(&fetched, clip_id, &events, "completed");
        assert_eq!(events.len(), 2, "started and stopped: {events:?}");
        let started = &events[0];
        assert_eq!(
            (&started["video"], &started["audio"]),
            (
                &json!({ "codec": "h264", "width": WIDTH, "height": HEIGHT }),
                &json!({ "codec": audio })
            )
        );
        let before_ms = started["before_ms"].as_u64().unwrap();
        assert!(
            (2_000..2_000 + GOP_MS + FRAME_MS).contains(&before_ms),
            "the newest keyframe 2 s ago or more: {before_ms}"
        );

        let file = &fetched.bytes;
        let mp4 = parse(file);
        let (video_id, video_rate) = mp4.video();
        assert_eq!(video_rate, VIDEO_RATE);
        let video = mp4.samples(file, video_id);
        assert_starts_at_a_keyframe_without_holes(&video);
        // From the keyframe `before_ms` ago to the first frame at or after
        // `after_ms` from now, which the clip leaves out.
        let last = video.last().unwrap();
        let span = ms(last.dts + last.duration - video[0].dts, video_rate);
        let expected = before_ms + 2_000;
        assert!(
            span.abs_diff(expected) <= 2 * FRAME_MS,
            "the video covers {span} ms, the clip asked {expected} ms"
        );
        let stopped = events.last().unwrap();
        assert!(
            stopped["duration_ms"].as_u64().unwrap().abs_diff(span) <= 2 * FRAME_MS,
            "{stopped} for {span} ms of video"
        );

        let (entry, audio_rate, audio) = mp4.audio(file).expect("an audio track");
        assert_eq!(holes(&audio), [], "the audio runs without a hole");
        let video_start = ms(video[0].dts, video_rate);
        let audio_start = ms(audio[0].dts, audio_rate);
        match entry {
            SampleEntry::Mp4a(_) => {
                assert_eq!(audio_rate, 16_000);
                assert!(audio.iter().all(|sample| sample.duration == 1_024));
                // The audio frame playing at the keyframe, 64 ms long (each
                // track's ticks rounded down: 1 ms of slack).
                assert!(
                    audio_start <= video_start + 1 && video_start <= audio_start + 64,
                    "audio at {audio_start} ms, video at {video_start} ms"
                );
            }
            SampleEntry::Opus(_) => {
                assert_eq!(audio_rate, 48_000);
                // 20 ms packets (RFC 7587 §4.2).
                assert!(audio.iter().all(|sample| sample.duration == 960));
                assert!(
                    audio_start.abs_diff(video_start) <= 40,
                    "audio at {audio_start} ms, video at {video_start} ms"
                );
            }
            other => panic!("audio {other:?}"),
        }
    }
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    aac.stop().await;
    pcmu.stop().await;
}

/// Two clips run on one stream at once, one fetched over the socket and
/// one over the mutual-TLS listener, which serves the same route; a third
/// is refused `limit_reached` (`clips_per_stream`). A clip without audio
/// has one track, and one asking nothing before now starts at the newest
/// keyframe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9112_7_1_two_clips_of_one_stream_come_whole_over_the_socket_and_the_mtls_listener() {
    use std::os::unix::fs::DirBuilderExt as _;

    use lotse_core::fingerprint::Fingerprint;
    use lotse_testing::control_tls::{self, ClientCert, ClientIdentity};

    let cam = camera(Some(CameraAudio::Aac)).await;
    let client = ClientIdentity::generate().unwrap();
    let dir = socket_dir("clip-two");
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
        .start_clip(json!({ "stream_id": "front", "clip_id": "with-audio",
                            "before_ms": 1_000, "after_ms": 1_500 }))
        .await;
    assert_eq!(
        first,
        json!({ "clip_id": "with-audio", "url": "/v0/clips/with-audio" })
    );
    let over_socket = fetch_on_socket(&socket, "/v0/clips/with-audio").await;
    let (video_only, second) = control
        .start_clip(json!({ "stream_id": "front", "after_ms": 1_000, "audio": false }))
        .await;
    let config =
        control_tls::client_config(server_pin, ClientCert::Own(&client), control_tls::TLS13)
            .unwrap();
    let tls = control_tls::connect(listener, config).await.expect("mTLS");
    let over_tls = spawn_named(
        "clip-fetch",
        fetch(tls, second["url"].as_str().unwrap().to_owned()),
    );
    let third = control
        .send(json!({ "type": "clip/start", "stream_id": "front" }))
        .await;
    let refused = control.result_of(third).await;
    assert_eq!(
        (&refused["success"], &refused["error"]["code"]),
        (&json!(false), &json!("limit_reached")),
        "{refused}"
    );
    assert_eq!(refused["error"]["details"]["limit"], "clips_per_stream");

    let events = control.until_stopped(with_audio).await;
    let fetched = within("the socket's body", over_socket).await.unwrap();
    assert_ended_whole(&fetched, "with-audio", &events, "completed");
    let mp4 = parse(&fetched.bytes);
    let (video_id, _) = mp4.video();
    assert_starts_at_a_keyframe_without_holes(&mp4.samples(&fetched.bytes, video_id));
    assert!(mp4.audio(&fetched.bytes).is_some(), "with its audio");

    let events = control.until_stopped(video_only).await;
    let fetched = within("the listener's body", over_tls).await.unwrap();
    let clip_id = second["clip_id"].as_str().unwrap();
    assert_ended_whole(&fetched, clip_id, &events, "completed");
    assert_eq!(events[0]["audio"], Value::Null, "{events:?}");
    let before_ms = events[0]["before_ms"].as_u64().unwrap();
    assert!(
        before_ms < GOP_MS + FRAME_MS,
        "the newest keyframe: {before_ms}"
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
            &stream["stats"]["clips_started"],
            &stream["stats"]["clips_completed"]
        ),
        (&json!(2), &json!(2)),
        "{stream}"
    );
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    drop(dir);
    cam.stop().await;
}

/// The camera drops its connection while a clip runs: the stream
/// reconnects, the clip goes on and reports one `reconnect` gap, from the
/// last frame before the drop to the new connection's first, a keyframe,
/// where the file has them; the hole between them is what the reconnect
/// took beyond the last frame's length (the fake camera's, on the same
/// host, takes a few milliseconds, so the file has none). `clip/stop`
/// then ends the clip `stopped` with the frames up to the stop and the
/// body's last chunk (RFC 9112 §7.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9112_7_1_a_reconnect_inside_a_clip_is_one_gap_where_the_file_has_it_and_a_stop_ends_it_whole()
 {
    let cam = camera(Some(CameraAudio::Aac)).await;
    let (mut daemon, dir) = daemon("clip-gap", &[], &[]);
    daemon.wait_for("\"event\":\"ready\"");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    control.put("front", &cam.url(), true, 10_000).await;
    control.wait_window("front", 1_000).await;
    let (id, result) = control
        .start_clip(json!({ "stream_id": "front", "before_ms": 500 }))
        .await;
    let clip_id = result["clip_id"].as_str().unwrap().to_owned();
    let fetch = fetch_on_socket(&socket, result["url"].as_str().unwrap()).await;
    let started = control.event(id).await;
    assert_eq!(started["type"], "started", "{started}");

    cam.drop_connections();
    let gap = control.event(id).await;
    assert_eq!(gap["type"], "gap", "{gap}");
    assert_eq!(gap["reason"], "reconnect", "{gap}");
    control
        .call(json!({ "type": "clip/stop", "clip_id": clip_id }))
        .await;
    let mut events = vec![started, gap.clone()];
    events.extend(control.until_stopped(id).await);
    let fetched = within("the body", fetch).await.unwrap();
    assert_ended_whole(&fetched, &clip_id, &events, "stopped");
    assert_eq!(events.len(), 3, "one gap: {events:?}");
    assert_eq!(events[2]["gaps"], 1);

    let file = &fetched.bytes;
    let mp4 = parse(file);
    let (video_id, rate) = mp4.video();
    let video = mp4.samples(file, video_id);
    assert!(video[0].sync, "the clip starts at a keyframe");
    // The gap's times are clip media times, as the file's (whole
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

/// The worker dies while its clip runs: the clip ends `worker_crashed`
/// with no bytes counted, and its body ends without its last chunk, a cut
/// transfer (RFC 9112 §8), after the bytes the worker wrote: the file's
/// beginning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9112_8_a_worker_crash_ends_the_clip_worker_crashed_and_cuts_its_body() {
    let cam = camera(None).await;
    let (mut daemon, dir) = daemon("clip-crash", &[], &[]);
    daemon.wait_for("\"event\":\"ready\"");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    control.put("front", &cam.url(), true, 10_000).await;
    let stream = control.wait_window("front", 1_000).await;
    let pid = stream["sources"][0]["connection"]["worker"]["pid"]
        .as_i64()
        .unwrap();
    let (id, result) = control
        .start_clip(json!({ "stream_id": "front", "before_ms": 500 }))
        .await;
    let fetch = fetch_on_socket(&socket, result["url"].as_str().unwrap()).await;
    let started = control.event(id).await;
    assert_eq!(started["type"], "started", "{started}");

    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
        rustix::process::Signal::KILL,
    )
    .expect("SIGKILL sent");
    let events = control.until_stopped(id).await;
    assert_eq!(
        events.last().unwrap(),
        &json!({ "type": "stopped", "reason": "worker_crashed", "bytes": 0,
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

/// A clip of an idle stream is demand: the stream connects for it, and it
/// starts at the first keyframe, `before_ms` 0. Nobody fetches its body
/// within `limits.clip_fetch_timeout_ms`, so it ends `not_fetched`, and a
/// `GET` afterwards finds no clip (404 `clip_not_found`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc9110_15_5_5_a_clip_nobody_fetches_ends_not_fetched_and_its_body_is_gone() {
    let cam = camera(None).await;
    let (mut daemon, dir) = daemon(
        "clip-unfetched",
        &[],
        &[("LOTSE_CLIP_FETCH_TIMEOUT_MS", "4000")],
    );
    daemon.wait_for("\"event\":\"ready\"");
    let socket = dir.join("lotse.sock");
    let mut control = Control::connect(&socket).await;
    control.put("front", &cam.url(), false, 0).await;
    let (id, result) = control
        .start_clip(json!({ "stream_id": "front", "before_ms": 2_000 }))
        .await;
    let events = control.until_stopped(id).await;
    assert_eq!(events[0]["type"], "started", "{events:?}");
    assert_eq!(events[0]["before_ms"], 0, "nothing held: {events:?}");
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
    assert_eq!(error["code"], "clip_not_found", "{error}");
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    cam.stop().await;
}
