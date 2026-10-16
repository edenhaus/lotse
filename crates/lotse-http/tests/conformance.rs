//! The HTTP source against the scripted HTTP server of `lotse-testing`
//! (`FakeHttp`), built by `HttpFactory` as the worker builds it: the rows
//! of the source conformance suite that apply to it.
//!
//! - Normalization: video is packetized for the live path and framed on
//!   the side branch, keyframes led by their parameter sets; AAC frames
//!   1024 samples apart.
//! - Sync: no sync hints, every track mapped by arrival on one base.
//! - Epochs: a timestamp reset starts one epoch for all tracks; a
//!   reconnect through core's runner keeps the tracks and starts one.
//! - Stall, cancellation within 100 ms, and the typed errors for
//!   unreachable, auth, timeout, protocol and ended.
//! - Credentials never in `describe()`, `Debug`, an error or a log line.
//! - Options: unknown fields refused.
//!
//! The rows that do not apply here, and why:
//!
//! - Cut-through packets (the first packet out before the frame
//!   completes): the source reads whole access units from MPEG-TS and
//!   fragmented MP4 segments, so there is no packet to cut through; each
//!   unit is packetized when it is released, which the normalization row
//!   checks.
//! - A sync hint mapping a track from the camera's clock, and a lying hint
//!   rejected: HLS and MPEG-TS give none the source reads (the program
//!   clock reference is not read); the hints row checks that none is
//!   reported. The mapper's own rows are unit tests of
//!   `lotse-core/src/clock_map.rs`.
//! - Keyframe requests: HTTP cannot ask the server for one; the factory
//!   says so and the source refuses the request (last row).
//! - The worker sandbox: a sandboxed worker playing HLS over `http` and
//!   `https` is a row of `crates/lotse/tests/worker.rs`.
//! - A teardown: HTTP has no session to end (RFC 9112 §9.6: the
//!   connection closes); the cancellation row checks that nothing is
//!   fetched after it instead.
//! - An options schema snapshot: the options are not part of the API's
//!   JSON Schema bundle (`stream/put` carries them untyped), so there is
//!   none to keep.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use lotse_codec::h264::{DEFAULT_MAX_PAYLOAD, nal};
use lotse_core::Kind;
use lotse_core::backoff::ReconnectBackoff;
use lotse_core::clock::{Clock, FakeClock, SystemClock};
use lotse_core::clock_map::{ClockMapper, SyncMode};
use lotse_core::codec::Codec;
use lotse_core::media::{MediaFrame, MediaPacket};
use lotse_core::runner::{ConnectGate, RunnerConfig, RunnerEvent, SourceRunner};
use lotse_core::source::{
    BackchannelSlot, KeyframeRequest, ResolvedPeer, Source, SourceConfigError, SourceError,
    SourceExit, SourceFactory as _, TrackSet,
};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_core::track::{
    FrameSubscription, PacketSubscription, Track, TrackEvent, TrackLimits, TrackSubscription, Unit,
};
use lotse_http::HttpFactory;
use lotse_testing::Harness;
use lotse_testing::fake_http::{Challenge, FakeHttp, Reply};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Three contiguous one-second HLS segments of H.264 (10 frames a second,
/// a keyframe each, no B-frames) and AAC-LC 48 kHz, recorded by ffmpeg
/// (`src/source/test_data.rs` has the command).
const LIVE: [&[u8]; 3] = [
    include_bytes!("../testdata/live_0.m2t"),
    include_bytes!("../testdata/live_1.m2t"),
    include_bytes!("../testdata/live_2.m2t"),
];

const M3U8: &str = "application/vnd.apple.mpegurl";
const MP2T: &str = "video/mp2t";

/// How far a fake clock moves per real millisecond while a row waits.
const STEP: Duration = Duration::from_millis(10);

/// A log writer that keeps every line.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// Everything logged so far.
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    /// The lines logged so far that contain `needle`.
    fn lines(&self, needle: &str) -> Vec<String> {
        self.text()
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_owned)
            .collect()
    }

    /// Captures this thread's log lines, every level, which the
    /// current-thread runtime's tasks log on too.
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }
}

async fn server() -> FakeHttp {
    FakeHttp::start().await.expect("the server binds")
}

fn peer(server: &FakeHttp) -> ResolvedPeer {
    ResolvedPeer {
        host: "127.0.0.1".into(),
        addrs: vec![server.addr()],
    }
}

/// The source `HttpFactory` builds for `url` and `options`.
fn make_source(url: &str, options: &serde_json::Value) -> Box<dyn Source> {
    let url = SourceUrl::parse(url).expect("url");
    HttpFactory.validate(&url, options).expect("valid source")
}

/// A media playlist of one-second segments (RFC 8216 §4.3.3).
fn playlist(segments: &[&str], end: bool) -> String {
    let mut text = String::from("#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:1\n");
    for segment in segments {
        text.push_str("#EXTINF:1.000,\n");
        text.push_str(segment);
        text.push('\n');
    }
    if end {
        text.push_str("#EXT-X-ENDLIST\n");
    }
    text
}

/// Serves `segments` (fixture indices) as `/<dir>/<n>.m2t` and an ended
/// playlist of them at `/<dir>/index.m3u8`.
fn serve_vod(server: &FakeHttp, dir: &str, segments: &[usize]) {
    let names: Vec<String> = (0..segments.len()).map(|n| format!("{n}.m2t")).collect();
    for (name, &fixture) in names.iter().zip(segments) {
        server.set(
            &format!("/{dir}/{name}"),
            Reply::body(MP2T, Bytes::from_static(LIVE[fixture])),
        );
    }
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    server.set(
        &format!("/{dir}/index.m3u8"),
        Reply::body(M3U8, playlist(&names, true)),
    );
}

fn ended(exit: SourceExit) -> SourceError {
    let SourceExit::Ended(err) = exit else {
        panic!("{exit:?}");
    };
    err
}

/// Waits up to `real` for the exit of a source that needs no clock.
async fn exit_within(harness: Harness, real: Duration) -> SourceError {
    tokio::select! {
        exit = harness.finish() => ended(exit),
        () = SystemClock.sleep(real) => panic!("the source did not exit within {real:?}"),
    }
}

/// [`Harness::wait_ready`] within three seconds of real time.
async fn ready_within(harness: &mut Harness) -> bool {
    tokio::select! {
        ready = harness.wait_ready() => ready,
        () = SystemClock.sleep(Duration::from_secs(3)) => panic!("not ready within 3 s"),
    }
}

/// Moves `clock` by [`STEP`] per real millisecond, calling `each` after
/// every step, until the source exits: why.
async fn run_to_exit(clock: &FakeClock, harness: Harness, mut each: impl FnMut()) -> SourceError {
    let finish = harness.finish();
    tokio::pin!(finish);
    for _ in 0..10_000 {
        tokio::select! {
            exit = &mut finish => {
                each();
                return ended(exit);
            }
            () = SystemClock.sleep(Duration::from_millis(1)) => {
                clock.advance(STEP);
                each();
            }
        }
    }
    panic!("the source did not exit");
}

fn video_and_audio(set: &TrackSet) -> (Arc<Track>, Arc<Track>) {
    let tracks = set.tracks();
    assert_eq!(tracks.len(), 2, "{tracks:?}");
    assert_eq!(tracks[0].id().kind(), Kind::Video);
    assert_eq!(tracks[1].id().kind(), Kind::Audio);
    assert!(
        matches!(*tracks[1].codec(), Codec::AacLc { .. }),
        "{:?}",
        tracks[1].codec()
    );
    (Arc::clone(&tracks[0]), Arc::clone(&tracks[1]))
}

fn drain_packets(sub: &mut PacketSubscription, into: &mut Vec<Arc<MediaPacket>>) {
    while let Some(packet) = sub.try_recv().expect("no lag") {
        into.push(packet);
    }
}

fn drain_frames(sub: &mut FrameSubscription, into: &mut Vec<Arc<MediaFrame>>) {
    while let Some(frame) = sub.try_recv().expect("no lag") {
        into.push(frame);
    }
}

/// The next event of `sub`, within 10 s.
async fn next_event(sub: &mut TrackSubscription) -> TrackEvent {
    tokio::select! {
        event = sub.next() => event.expect("the track is open"),
        () = SystemClock.sleep(Duration::from_secs(10)) => panic!("no track event in 10 s"),
    }
}

/// A unit published after the subscriptions were made: what the clock
/// released from the first segment on.
#[tokio::test(flavor = "current_thread")]
async fn rfc6184_h264_is_packetized_for_the_live_path_and_framed_on_the_side_branch() {
    let server = server().await;
    serve_vod(&server, "vod", &[0, 1, 2]);
    let clock = Arc::new(FakeClock::from_system());
    let source = make_source(&server.url("/vod/index.m3u8"), &json!(null));
    let mut harness = Harness::start(source.as_ref(), peer(&server), clock.clone());
    assert!(ready_within(&mut harness).await);
    let (video, audio) = video_and_audio(&harness.tracks);
    let mut packet_sub = video.subscribe_packets();
    let mut frame_sub = video.subscribe_frames();
    let mut audio_sub = audio.subscribe_frames();
    let (mut packets, mut frames, mut audio_frames) = (Vec::new(), Vec::new(), Vec::new());
    let err = run_to_exit(&clock, harness, || {
        drain_packets(&mut packet_sub, &mut packets);
        drain_frames(&mut frame_sub, &mut frames);
        drain_frames(&mut audio_sub, &mut audio_frames);
    })
    .await;
    assert!(
        matches!(&err, SourceError::Ended(m) if m.contains("EXT-X-ENDLIST")),
        "{err:?}"
    );
    // The in-band sequence parameter set reached the track's codec.
    let Codec::H264 {
        profile_level_id: Some(_),
        sps: Some(_),
        pps: Some(_),
    } = video.codec().as_ref().clone()
    else {
        panic!("h264 with its in-band sets: {:?}", video.codec());
    };

    // Side branch: one Annex B access unit per frame (4-byte start
    // codes), 100 ms apart, the keyframes (one a segment) with their
    // parameter sets in band before the IDR (RFC 6184 §1.3, ITU-T H.264
    // §7.4.1.2.3); access unit delimiters kept.
    assert!(frames.len() >= 20, "{} frames", frames.len());
    let keyframes: Vec<_> = frames.iter().filter(|f| f.keyframe).collect();
    assert!(keyframes.len() >= 2, "{} keyframes", keyframes.len());
    for frame in &frames {
        assert!(frame.payload.starts_with(&[0, 0, 0, 1]));
        let types: Vec<u8> = nal::annex_b_units(&frame.payload)
            .iter()
            .map(|unit| nal::nal_type(unit[0]))
            .collect();
        let idr = types.iter().position(|&t| t == nal::NAL_IDR);
        assert_eq!(idr.is_some(), frame.keyframe, "{types:?}");
        if let Some(idr) = idr {
            assert!(types[..idr].contains(&nal::NAL_SPS), "{types:?}");
            assert!(types[..idr].contains(&nal::NAL_PPS), "{types:?}");
        }
    }
    let ticks: Vec<i64> = frames.iter().map(|f| f.ts.ticks()).collect();
    assert!(ticks.windows(2).all(|w| w[1] - w[0] == 9_000), "{ticks:?}");
    assert!(frames.iter().all(|f| f.epoch == 0 && !f.discontinuity));

    // Live path: every packet fits the datagram target, each access unit
    // starts a frame, ends with the marker (RFC 6184 §5.1) and carries
    // its frame's timestamp, and a keyframe's IDR is preceded by one
    // packet aggregating the parameter sets (STAP-A, §5.7.1) that starts
    // the keyframe.
    assert!(
        packets
            .iter()
            .all(|p| p.payload.len() <= DEFAULT_MAX_PAYLOAD)
    );
    let seqs: Vec<u16> = packets.iter().map(|p| p.rtp.seq).collect();
    assert!(
        seqs.windows(2).all(|w| w[1] == w[0].wrapping_add(1)),
        "{seqs:?}"
    );
    for frame in &frames {
        let ts = u32::try_from(frame.ts.ticks().rem_euclid(1 << 32)).unwrap();
        let unit: Vec<_> = packets.iter().filter(|p| p.rtp.ts == ts).collect();
        assert!(!unit.is_empty(), "the packets of {ts}");
        assert!(unit[0].frame_start, "{ts}");
        assert!(unit.last().unwrap().rtp.marker, "{ts}");
        assert_eq!(unit.iter().filter(|p| p.rtp.marker).count(), 1, "{ts}");
        let starts: Vec<_> = unit.iter().filter(|p| p.keyframe_start).collect();
        assert_eq!(starts.len(), usize::from(frame.keyframe), "{ts}");
        if let Some(start) = starts.first() {
            assert_eq!(nal::nal_type(start.payload[0]), nal::STAP_A, "{ts}");
        }
    }

    // AAC: raw frames on the side branch, 1024 samples apart on the
    // sample-rate clock (ISO/IEC 14496-3 §1.6.2.1), no live packets.
    assert_eq!(audio.clock_rate(), 48_000);
    assert!(audio_frames.len() >= 90, "{} frames", audio_frames.len());
    let ticks: Vec<i64> = audio_frames.iter().map(|f| f.ts.ticks()).collect();
    assert!(ticks.windows(2).all(|w| w[1] - w[0] == 1_024), "{ticks:?}");
    assert!(
        audio_frames.iter().all(|f| f.payload[0] != 0xFF),
        "no ADTS header"
    );
    assert_eq!(audio.stats().packets, 0);
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn without_sync_hints_audio_and_video_map_by_arrival_on_one_base() {
    let server = server().await;
    serve_vod(&server, "vod", &[0, 1]);
    let clock = Arc::new(FakeClock::from_system());
    let source = make_source(&server.url("/vod/index.m3u8"), &json!(null));
    let mut harness = Harness::start(source.as_ref(), peer(&server), clock.clone());
    assert!(ready_within(&mut harness).await);
    let (video, audio) = video_and_audio(&harness.tracks);
    let mapper = Arc::clone(&harness.mapper);
    // The hints the attempt reports, read after it ended.
    let mut reports = std::mem::replace(&mut harness.reports, mpsc::channel(1).1);
    let mut video_sub = video.subscribe_frames();
    let mut audio_sub = audio.subscribe_frames();
    let (mut video_frames, mut audio_frames) = (Vec::new(), Vec::new());
    let err = run_to_exit(&clock, harness, || {
        drain_frames(&mut video_sub, &mut video_frames);
        drain_frames(&mut audio_sub, &mut audio_frames);
    })
    .await;
    assert!(matches!(err, SourceError::Ended(_)), "{err:?}");
    assert!(reports.try_recv().is_err(), "no sync hint");
    assert_eq!(mapper.hints_seen(video.id()), 0);
    assert_eq!(mapper.hints_seen(audio.id()), 0);
    assert_eq!(mapper.mode(video.id()), SyncMode::Arrival);
    assert_eq!(mapper.mode(audio.id()), SyncMode::Arrival);

    // Each frame's capture time is its arrival, and the arrivals of both
    // tracks follow their presentation times from one base: the daemon
    // adds no skew of its own (within one step of the clock, the
    // granularity of the release).
    assert!(video_frames.len() >= 10 && audio_frames.len() >= 45);
    let base = video_frames[0].arrival;
    let offset = |frame: &MediaFrame, rate: i128| -> i128 {
        assert_eq!(frame.wallclock, frame.arrival);
        let at = if frame.arrival >= base {
            i128::try_from(frame.arrival.duration_since(base).as_nanos()).unwrap()
        } else {
            -i128::try_from(base.duration_since(frame.arrival).as_nanos()).unwrap()
        };
        at - i128::from(frame.ts.ticks()) * 1_000_000_000 / rate
    };
    let offsets: Vec<i128> = video_frames
        .iter()
        .map(|f| offset(f, 90_000))
        .chain(audio_frames.iter().map(|f| offset(f, 48_000)))
        .collect();
    let spread = offsets.iter().max().unwrap() - offsets.iter().min().unwrap();
    assert!(
        spread <= i128::try_from(STEP.as_nanos()).unwrap() + 1_000_000,
        "A/V offsets spread over {spread} ns"
    );
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc3550_5_1_a_timestamp_reset_without_a_discontinuity_starts_one_epoch_for_all_tracks() {
    let logs = Captured::default();
    let _logging = logs.install();
    let server = server().await;
    // The encoder restarted between the second and the third segment, and
    // the playlist does not say so: the third segment's timestamps are
    // the first's again, two seconds back.
    serve_vod(&server, "reset", &[0, 1, 0]);
    let clock = Arc::new(FakeClock::from_system());
    let source = make_source(&server.url("/reset/index.m3u8"), &json!(null));
    let mut harness = Harness::start(source.as_ref(), peer(&server), clock.clone());
    assert!(ready_within(&mut harness).await);
    let (video, audio) = video_and_audio(&harness.tracks);
    let video_events = Arc::new(Mutex::new(Vec::new()));
    let audio_events = Arc::new(Mutex::new(Vec::new()));
    let mut collectors = Vec::new();
    for (track, events) in [(&video, &video_events), (&audio, &audio_events)] {
        let mut sub = track.subscribe(Unit::Frames);
        let events = Arc::clone(events);
        collectors.push(spawn_named("test.events", async move {
            while let Some(event) = sub.next().await {
                events.lock().unwrap().push(event);
            }
        }));
    }
    let err = run_to_exit(&clock, harness, || {}).await;
    assert!(matches!(err, SourceError::Ended(_)), "{err:?}");
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!((video.epoch(), audio.epoch()), (1, 1), "one epoch for all");
    assert_eq!(logs.lines("timestamps jumped; new epoch").len(), 1);
    for (name, events) in [("video", &video_events), ("audio", &audio_events)] {
        let events = events.lock().unwrap().clone();
        let epochs: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, TrackEvent::EpochStart { .. }))
            .collect();
        assert_eq!(epochs, [&TrackEvent::EpochStart { epoch: 1 }], "{name}");
        let first = events
            .iter()
            .find_map(|e| match e {
                TrackEvent::Frame(frame) if frame.epoch == 1 => Some(frame),
                _ => None,
            })
            .expect("a frame of the new epoch");
        assert!(first.discontinuity, "{name}");
        // Back: before the last frame of the old timeline.
        let last_old = events
            .iter()
            .rev()
            .find_map(|e| match e {
                TrackEvent::Frame(frame) if frame.epoch == 0 => Some(frame.ts.ticks()),
                _ => None,
            })
            .expect("frames of the first timeline");
        let rate = i64::from(if name == "video" { 90_000_u32 } else { 48_000 });
        assert!(
            first.ts.ticks() < last_old - rate,
            "{name}: {} after {last_old}",
            first.ts.ticks()
        );
        if name == "video" {
            assert!(first.keyframe, "the new timeline starts at a keyframe");
        }
        assert!(
            events
                .iter()
                .all(|e| !matches!(e, TrackEvent::Frame(f) if f.epoch > 1)),
            "{name}: one timeline after the reset"
        );
    }
    for collector in collectors {
        collector.abort();
    }
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_reconnect_keeps_the_tracks_and_starts_one_epoch_for_them() {
    let server = server().await;
    // A raw MPEG-TS body that ends after a second: every attempt plays it
    // and ends, and the runner reconnects.
    server.set("/raw", Reply::body(MP2T, Bytes::from_static(LIVE[0])));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let tracks = TrackSet::new(TrackLimits::default(), clock.now());
    let (tx, mut events) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let runner = SourceRunner::new(
        make_source(&server.url("/raw"), &json!(null)),
        peer(&server),
        Arc::clone(&tracks),
        Arc::new(ClockMapper::new()),
        BackchannelSlot::default(),
        clock,
        RunnerConfig::default(),
        ReconnectBackoff::new(1),
        tx,
        ConnectGate::open(),
        cancel.clone(),
    );
    let runner = spawn_named("test.runner", runner.run());
    assert_eq!(
        events.recv().await,
        Some(RunnerEvent::Connecting { attempt: 1 })
    );
    assert_eq!(events.recv().await, Some(RunnerEvent::Live));
    let (v0, a0) = video_and_audio(&tracks);
    let mut sub = v0.subscribe(Unit::Frames);
    let Some(RunnerEvent::Reconnecting { error }) = events.recv().await else {
        panic!("the end of the body is retried at once");
    };
    assert_eq!(error.code(), "source_ended", "{error}");
    assert_eq!(events.recv().await, Some(RunnerEvent::Live));

    // The same tracks, one epoch later.
    let now = tracks.tracks();
    assert_eq!(now.len(), 2);
    assert!(Arc::ptr_eq(&now[0], &v0) && Arc::ptr_eq(&now[1], &a0));
    assert_eq!((v0.epoch(), a0.epoch()), (1, 1));
    // Subscribers see the loss, the epoch and the restore, then the new
    // connection's frames, a keyframe first; the codec stays as it was.
    let mut control = Vec::new();
    let first = loop {
        match next_event(&mut sub).await {
            TrackEvent::Frame(frame) if frame.epoch == 0 => {}
            TrackEvent::Frame(frame) => break frame,
            TrackEvent::TrackChanged(codec) if control.is_empty() => {
                // The first attempt's in-band SPS, if subscribed before it.
                assert!(
                    matches!(*codec, Codec::H264 { sps: Some(_), .. }),
                    "{codec:?}"
                );
            }
            event => control.push(event),
        }
    };
    assert_eq!(
        control,
        [
            TrackEvent::SourceLost,
            TrackEvent::EpochStart { epoch: 1 },
            TrackEvent::SourceRestored
        ]
    );
    assert!(first.keyframe && first.discontinuity);
    assert!(server.connections() >= 2);

    cancel.cancel();
    while let Some(event) = events.recv().await {
        if event == RunnerEvent::Stopped {
            break;
        }
    }
    runner.await.unwrap();
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_6_2_1_a_live_playlist_that_stops_growing_and_a_stalled_body_time_out() {
    let server = server().await;
    // A live playlist that never adds a segment after its first.
    server.live("/live/index.m3u8", 3);
    server.push_segment(
        "/live/index.m3u8",
        "/live/0.m2t",
        1.0,
        Bytes::from_static(LIVE[0]),
    );
    let clock = Arc::new(FakeClock::from_system());
    let source = make_source(&server.url("/live/index.m3u8"), &json!(null));
    let harness = Harness::start(source.as_ref(), peer(&server), clock.clone());
    let err = run_to_exit(&clock, harness, || {}).await;
    assert!(
        matches!(&err, SourceError::Timeout(m) if m.contains("3 times its target duration")),
        "{err:?}"
    );

    // A raw MPEG-TS body that stops after its first packets: the body
    // read deadline (`timeout_ms`).
    server.set(
        "/stalled",
        Reply::Stall(Bytes::from_static(&LIVE[0][..188 * 40])),
    );
    let source = make_source(&server.url("/stalled"), &json!({ "timeout_ms": 200 }));
    let harness = Harness::start(source.as_ref(), peer(&server), Arc::new(SystemClock));
    let err = exit_within(harness, Duration::from_secs(3)).await;
    assert!(matches!(err, SourceError::Timeout(_)), "{err:?}");
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_ends_the_attempt_within_100_ms_and_stops_fetching() {
    let server = server().await;
    server.live("/live/index.m3u8", 3);
    for (n, segment) in LIVE.iter().enumerate() {
        server.push_segment(
            "/live/index.m3u8",
            &format!("/live/{n}.m2t"),
            1.0,
            Bytes::from_static(segment),
        );
    }
    server.set("/hang", Reply::Hang);
    // Playing, paced on the real clock, a reload ahead.
    let source = make_source(&server.url("/live/index.m3u8"), &json!(null));
    let mut playing = Harness::start(source.as_ref(), peer(&server), Arc::new(SystemClock));
    assert!(ready_within(&mut playing).await);
    // Waiting for the first answer.
    let source = make_source(&server.url("/hang"), &json!(null));
    let waiting = Harness::start(source.as_ref(), peer(&server), Arc::new(SystemClock));
    for _ in 0..1_000 {
        if server.requests().iter().any(|seen| seen.target == "/hang") {
            break;
        }
        SystemClock.sleep(Duration::from_millis(1)).await;
    }
    for harness in [playing, waiting] {
        harness.cancel();
        let err = exit_within(harness, Duration::from_millis(100)).await;
        assert_eq!(err, SourceError::Ended("cancelled".into()));
    }
    // Nothing more is fetched: the fetch tasks and their connections ended
    // with the attempt (a live playlist of one-second segments would be
    // reloaded within a second).
    let seen = server.requests().len();
    SystemClock.sleep(Duration::from_millis(1_500)).await;
    assert_eq!(server.requests().len(), seen);
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn unreachable_timeout_protocol_and_ended_are_typed_errors() {
    // Unreachable: nothing listens.
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let closed = make_source(&format!("http://{addr}/index.m3u8"), &json!(null));
    let harness = Harness::start(
        closed.as_ref(),
        ResolvedPeer {
            host: "127.0.0.1".into(),
            addrs: vec![addr],
        },
        Arc::new(SystemClock),
    );
    let err = exit_within(harness, Duration::from_secs(3)).await;
    assert!(matches!(err, SourceError::Unreachable(_)), "{err:?}");
    assert_eq!(err.code(), "source_unreachable");

    let server = server().await;
    let run = |target: &str, options: serde_json::Value| {
        let source = make_source(&server.url(target), &options);
        Harness::start(source.as_ref(), peer(&server), Arc::new(SystemClock))
    };
    // Timeout: an answer that never comes.
    server.set("/hang", Reply::Hang);
    let err = exit_within(
        run("/hang", json!({ "timeout_ms": 200 })),
        Duration::from_secs(3),
    )
    .await;
    assert!(matches!(err, SourceError::Timeout(_)), "{err:?}");
    // Protocol: a missing playlist (RFC 9110 §15.5.5), and something that is
    // neither HLS nor MPEG-TS.
    let err = exit_within(run("/missing.m3u8", json!(null)), Duration::from_secs(3)).await;
    assert!(
        matches!(&err, SourceError::Protocol(m) if m.contains("404")),
        "{err:?}"
    );
    server.set("/page", Reply::body("text/html", "<html></html>"));
    let err = exit_within(run("/page", json!(null)), Duration::from_secs(3)).await;
    assert!(
        matches!(&err, SourceError::Protocol(m) if m.contains("text/html")),
        "{err:?}"
    );
    // Ended: an ended playlist played out (RFC 8216 §4.3.3.4), and a raw
    // MPEG-TS body the server ends.
    serve_vod(&server, "vod", &[0]);
    let err = exit_within(run("/vod/index.m3u8", json!(null)), Duration::from_secs(5)).await;
    assert!(
        matches!(&err, SourceError::Ended(m) if m.contains("EXT-X-ENDLIST")),
        "{err:?}"
    );
    server.set("/raw", Reply::body(MP2T, Bytes::from_static(LIVE[0])));
    let err = exit_within(run("/raw", json!(null)), Duration::from_secs(5)).await;
    assert!(
        matches!(&err, SourceError::Ended(m) if m.contains("MPEG-TS")),
        "{err:?}"
    );
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc7616_credentials_are_checked_and_never_described_debugged_or_logged() {
    let logs = Captured::default();
    let _logging = logs.install();
    let server = server().await;
    serve_vod(&server, "vod", &[0]);
    server.set(
        "/vod/index.m3u8?token=hidden",
        Reply::body(M3U8, playlist(&["0.m2t"], true)),
    );
    let addr = server.addr();
    for challenge in [Challenge::Basic, Challenge::DigestMd5] {
        server.require(Some((challenge, "admin", "secret")));
        // None, then wrong ones: auth failed.
        for url in [
            format!("http://{addr}/vod/index.m3u8"),
            format!("http://admin:wrong@{addr}/vod/index.m3u8"),
        ] {
            let source = make_source(&url, &json!(null));
            let harness = Harness::start(source.as_ref(), peer(&server), Arc::new(SystemClock));
            let err = exit_within(harness, Duration::from_secs(3)).await;
            assert!(matches!(err, SourceError::AuthFailed(_)), "{err:?}");
            assert!(!err.to_string().contains("wrong"), "{err}");
        }
        // The right ones: it plays, and nothing shows them.
        let url = format!("http://admin:secret@{addr}/vod/index.m3u8?token=hidden");
        let source = make_source(&url, &json!(null));
        let described = source.describe();
        let shown = format!("{described:?} {} {source:?}", described.url);
        assert!(!shown.contains("secret"), "{shown}");
        let harness = Harness::start(source.as_ref(), peer(&server), Arc::new(SystemClock));
        let err = exit_within(harness, Duration::from_secs(5)).await;
        assert!(
            matches!(&err, SourceError::Ended(m) if m.contains("EXT-X-ENDLIST")),
            "{err:?}"
        );
        assert!(!err.to_string().contains("secret"), "{err}");
    }
    let requests = server.requests();
    assert!(
        requests.iter().any(|seen| seen
            .authorization
            .as_deref()
            .is_some_and(|a| a.starts_with("Digest "))),
        "{requests:?}"
    );
    // Neither the password, nor its Basic encoding, nor the path or query
    // of the URL reached a log line.
    let text = logs.text();
    assert!(!text.is_empty());
    for needle in ["secret", "YWRtaW46c2VjcmV0", "hidden", "index.m3u8"] {
        assert!(!text.contains(needle), "{needle} logged: {text}");
    }
    server.stop().await;
}

#[test]
fn unknown_options_are_refused() {
    let url = SourceUrl::parse("http://camera.local/index.m3u8").unwrap();
    for options in [
        json!({ "nope": 1 }),
        json!({ "transport": "tcp" }),
        json!({ "timeout_ms": 1_000, "user_agent": "x" }),
    ] {
        let err = HttpFactory.validate(&url, &options).unwrap_err();
        assert!(
            matches!(
                err,
                SourceConfigError::InvalidOptions { scheme: "http", .. }
            ),
            "{options}: {err}"
        );
    }
    assert!(
        HttpFactory
            .validate(&url, &json!({ "timeout_ms": 1_000 }))
            .is_ok()
    );
}

#[test]
fn keyframe_requests_are_not_offered() {
    assert!(!HttpFactory.capabilities().keyframe_request);
    assert!(!HttpFactory.capabilities().backchannel);
    let source = make_source("http://camera.local/index.m3u8", &json!(null));
    assert!(matches!(
        source.request_keyframe(),
        KeyframeRequest::Unsupported
    ));
}
