//! Every attempt that ends after the camera set up a session sends it a
//! `TEARDOWN` (RFC 2326 §10.7, RFC 7826 §13.7), whatever ends it, over TCP
//! interleaved and over UDP, against the fake camera of `lotse-testing`,
//! which counts them: a refused or unanswered `PLAY`, a cancel while
//! `PLAY` is pending or while playing, no datagram within the read
//! deadline, a `PLAY` answer followed by what no RTSP parser reads over
//! UDP, and a camera that hangs up. Over UDP the session outlives its
//! control connection (RFC 2326 §1.1), so when that connection is gone,
//! or cannot carry the answer, retina's `Auto` policy sends the
//! `TEARDOWN` on a fresh one, which the source dials; over TCP the
//! session ends with its connection, except on a camera whose SDP names a
//! live555 version with the stale TCP session bug, which that policy
//! tears down on fresh connections too, within the source's budget for
//! that case (2 s), unless the attempt is cancelled: then, through the
//! runner on a fake clock, within the source contract's 100 ms of the
//! cancel, before the runner's stop grace drops it, whether the cancel
//! comes while playing or while a retry is under way. The source's
//! attempt ends only once its teardown is over, so what the camera
//! counted is final when the harness has the exit; the retries' timing is
//! the driver's unit tests', on a fake clock.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::sync::Arc;
use std::time::Duration;

use lotse_core::backoff::ReconnectBackoff;
use lotse_core::clock::{Clock, FakeClock, SystemClock};
use lotse_core::clock_map::ClockMapper;
use lotse_core::runner::{ConnectGate, RunnerConfig, RunnerEvent, SourceRunner};
use lotse_core::source::{
    BackchannelSlot, ResolvedPeer, SourceError, SourceFactory as _, TrackSet,
};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_core::track::TrackLimits;
use lotse_rtsp::RtspFactory;
use lotse_testing::fake_camera::{CameraAudio, CameraUdp, PlayAnswer, Stats, UdpService};
use lotse_testing::{CameraConfig, FakeCamera, Harness};
use serde_json::json;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio_util::sync::CancellationToken;

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// Every log line's fields are evaluated, as in production at `trace`;
/// the lines go nowhere.
fn traced() {
    let _installed = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(std::io::sink)
        .try_init();
}

const TRANSPORTS: [&str; 2] = ["tcp", "udp"];

/// A camera with video and PCMU audio, two streams set up, as `config`
/// says otherwise.
async fn camera(config: CameraConfig) -> FakeCamera {
    traced();
    FakeCamera::start(
        CameraConfig {
            audio: Some(CameraAudio::Pcmu),
            ..config
        },
        clock(),
    )
    .await
    .expect("camera binds")
}

/// A source for `camera` over `transport` with a 300 ms read deadline.
fn start(camera: &FakeCamera, transport: &str) -> Harness {
    let source = RtspFactory
        .validate(
            &SourceUrl::parse(&camera.url()).unwrap(),
            &json!({ "transport": transport, "timeout_ms": 300 }),
        )
        .expect("valid source");
    let peer = ResolvedPeer {
        host: "127.0.0.1".into(),
        addrs: vec![camera.addr()],
    };
    Harness::start(source.as_ref(), peer, clock())
}

/// Waits up to `steps` × 20 ms for `done`.
async fn eventually(steps: u32, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..steps {
        if done() {
            return true;
        }
        clock().sleep(Duration::from_millis(20)).await;
    }
    done()
}

/// The camera got exactly one `TEARDOWN`.
async fn torn_down_once(camera: &FakeCamera, what: &str) {
    let stats = camera.stats();
    assert!(
        eventually(50, || Stats::get(&stats.teardowns) >= 1).await,
        "{what}: no TEARDOWN"
    );
    // Nothing more trickles in.
    clock().sleep(Duration::from_millis(100)).await;
    assert_eq!(Stats::get(&stats.teardowns), 1, "{what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_refused_play_is_torn_down() {
    for transport in TRANSPORTS {
        let cam = camera(CameraConfig {
            play: PlayAnswer::Refuse,
            ..CameraConfig::default()
        })
        .await;
        let harness = start(&cam, transport);
        let exit = harness.finish().await;
        assert!(
            matches!(exit, SourceError::Protocol(ref m) if m.contains("503")),
            "{transport}: {exit:?}"
        );
        torn_down_once(&cam, transport).await;
        cam.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_an_unanswered_play_is_torn_down_at_the_read_deadline() {
    for transport in TRANSPORTS {
        let cam = camera(CameraConfig {
            play: PlayAnswer::Never,
            ..CameraConfig::default()
        })
        .await;
        let harness = start(&cam, transport);
        let exit = harness.finish().await;
        assert!(
            matches!(exit, SourceError::Timeout(ref m) if m.starts_with("PLAY")),
            "{transport}: {exit:?}"
        );
        torn_down_once(&cam, transport).await;
        cam.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_cancel_while_play_is_pending_tears_down() {
    for transport in TRANSPORTS {
        let cam = camera(CameraConfig {
            play: PlayAnswer::Never,
            ..CameraConfig::default()
        })
        .await;
        let mut harness = start(&cam, transport);
        let stats = cam.stats();
        assert!(
            eventually(50, || Stats::get(&stats.plays) == 1).await,
            "{transport}: PLAY sent"
        );
        harness.cancel();
        assert!(!harness.wait_ready().await);
        let exit = harness.finish().await;
        assert!(
            matches!(exit, SourceError::Ended(ref m) if m == "cancelled"),
            "{transport}: {exit:?}"
        );
        torn_down_once(&cam, transport).await;
        cam.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_cancel_while_playing_tears_down() {
    for transport in TRANSPORTS {
        let cam = camera(CameraConfig::default()).await;
        let mut harness = start(&cam, transport);
        assert!(harness.wait_ready().await, "{transport}: live");
        harness.cancel();
        let exit = harness.finish().await;
        assert!(
            matches!(exit, SourceError::Ended(ref m) if m == "cancelled"),
            "{transport}: {exit:?}"
        );
        torn_down_once(&cam, transport).await;
        assert_eq!(Stats::get(&cam.stats().connections), 1, "{transport}");
        cam.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_no_datagram_within_the_read_deadline_tears_down_over_udp() {
    let cam = camera(CameraConfig {
        udp: CameraUdp {
            service: UdpService::Blackhole,
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    })
    .await;
    let harness = start(&cam, "udp");
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceError::Timeout(ref m) if m.contains("of PLAY")),
        "{exit:?}"
    );
    torn_down_once(&cam, "udp").await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_an_unreadable_play_answer_is_torn_down_on_a_fresh_connection_over_udp() {
    // RFC 2326 §1.1: the session is not tied to its connection, so the
    // camera would keep sending datagrams. retina reads past the PLAY
    // answer what no RTSP parser reads, so the session's own connection
    // cannot carry the TEARDOWN's answer: it goes on a fresh one.
    let cam = camera(CameraConfig {
        play: PlayAnswer::Unreadable,
        ..CameraConfig::default()
    })
    .await;
    let harness = start(&cam, "udp");
    let exit = harness.finish().await;
    assert!(matches!(exit, SourceError::Protocol(_)), "{exit:?}");
    torn_down_once(&cam, "udp").await;
    assert_eq!(
        Stats::get(&cam.stats().connections),
        2,
        "a fresh connection"
    );
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_camera_that_hangs_up_is_torn_down_on_a_fresh_connection_over_udp_only() {
    for transport in TRANSPORTS {
        let cam = camera(CameraConfig {
            packets_before_close: Some(20),
            ..CameraConfig::default()
        })
        .await;
        let harness = start(&cam, transport);
        let exit = harness.finish().await;
        assert!(
            matches!(exit, SourceError::Ended(_)),
            "{transport}: {exit:?}"
        );
        let stats = cam.stats();
        if transport == "udp" {
            torn_down_once(&cam, transport).await;
            assert_eq!(Stats::get(&stats.connections), 2, "a fresh connection");
        } else {
            // The interleaved session ended with its connection.
            clock().sleep(Duration::from_millis(200)).await;
            assert_eq!(Stats::get(&stats.teardowns), 0);
            assert_eq!(Stats::get(&stats.connections), 1);
        }
        cam.stop().await;
    }
}

/// A live555 server before 2017.06.04 keeps an interleaved session whose
/// connection is gone (observed by retina, which names it in its
/// `Tool::has_live555_tcp_bug`), so retina's `Auto` policy retries the
/// `TEARDOWN` on a fresh connection, which the source dials. The attempt's
/// exit comes after its teardown, so the counts are final by then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_live555_camera_that_hangs_up_is_torn_down_on_a_fresh_connection_over_tcp() {
    let cam = camera(CameraConfig {
        packets_before_close: Some(20),
        sdp_session_lines: "a=tool:LIVE555 Streaming Media v2016.11.28\r\n".into(),
        ..CameraConfig::default()
    })
    .await;
    let harness = start(&cam, "tcp");
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceError::Ended(ref m) if m == "the camera closed the session"),
        "{exit:?}"
    );
    torn_down_once(&cam, "tcp").await;
    assert_eq!(
        Stats::get(&cam.stats().connections),
        2,
        "a fresh connection"
    );
    cam.stop().await;
}

/// When the runner is stopped during [`cancelled_live555_teardown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelAt {
    /// While the stream plays: the teardown starts cancelled.
    Playing,
    /// Once the camera hung up and retina's retry on a fresh connection is
    /// under way, with the 2 s budget of that case.
    Retrying,
}

/// A live555 camera with the stale TCP session bug (retina's
/// `Tool::has_live555_tcp_bug`) that hangs up on every `TEARDOWN`, so
/// retina's `Auto` policy retries on fresh connections that never succeed,
/// run by a [`SourceRunner`] on a fake clock and stopped `at`. Once the
/// camera counted what comes before the cancel, the fake clock moves 5 ms
/// at a time, with real time for the sockets after each: the runner must
/// report `Stopped` within the source contract's 100 ms of the cancel
/// (`Source::run`), long before its stop grace would drop the source and
/// end the attempt as a timeout. The session is left to expire on the
/// camera (RFC 2326 §12.37). Returns the camera's `TEARDOWN`s and
/// connections.
async fn cancelled_live555_teardown(at: CancelAt) -> (u64, u64) {
    traced();
    let clock = Arc::new(FakeClock::from_system());
    let time: Arc<dyn Clock> = Arc::<FakeClock>::clone(&clock);
    let cam = FakeCamera::start(
        CameraConfig {
            packets_before_close: (at == CancelAt::Retrying).then_some(1),
            sdp_session_lines: "a=tool:LIVE555 Streaming Media v2016.11.28\r\n".into(),
            hang_up_on_teardown: true,
            ..CameraConfig::default()
        },
        Arc::clone(&time),
    )
    .await
    .expect("camera binds");
    let source = RtspFactory
        .validate(
            &SourceUrl::parse(&cam.url()).unwrap(),
            &json!({ "transport": "tcp" }),
        )
        .expect("valid source");
    let peer = ResolvedPeer {
        host: "127.0.0.1".into(),
        addrs: vec![cam.addr()],
    };
    let (tx, mut events) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let runner = SourceRunner::new(
        source,
        peer,
        TrackSet::new(TrackLimits::default(), time.now()),
        Arc::new(ClockMapper::new()),
        BackchannelSlot::default(),
        Arc::clone(&time),
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
    let stats = cam.stats();
    if at == CancelAt::Retrying {
        // The session's own connection is gone with the camera's hang-up,
        // so the one TEARDOWN went out on a fresh connection, and retina
        // waits out that attempt's deadline (1 s) before the next.
        assert!(
            eventually(250, || Stats::get(&stats.teardowns) == 1).await,
            "a TEARDOWN on a fresh connection"
        );
    }
    cancel.cancel();
    if at == CancelAt::Playing {
        // The TEARDOWN on the session's own connection, hung up on, then
        // the one on a fresh connection, hung up on too.
        assert!(
            eventually(250, || Stats::get(&stats.teardowns) == 2).await,
            "a TEARDOWN on a fresh connection"
        );
    }
    let step = Duration::from_millis(5);
    let grace = RunnerConfig::default().stop_grace;
    let mut advanced = Duration::ZERO;
    loop {
        match events.try_recv() {
            Ok(RunnerEvent::Stopped) => break,
            Ok(_) | Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => panic!("the runner ended without Stopped"),
        }
        assert!(
            advanced < grace,
            "{at:?}: still running {advanced:?} after its cancel"
        );
        clock.advance(step);
        advanced += step;
        SystemClock.sleep(Duration::from_millis(3)).await;
    }
    assert!(
        advanced <= Duration::from_millis(100) + step,
        "{at:?}: stopped {advanced:?} after its cancel"
    );
    runner.await.unwrap();
    let counted = (Stats::get(&stats.teardowns), Stats::get(&stats.connections));
    cam.stop().await;
    counted
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_cancel_while_playing_bounds_a_live555_teardown_on_fresh_connections() {
    let (teardowns, connections) = cancelled_live555_teardown(CancelAt::Playing).await;
    assert_eq!(
        (teardowns, connections),
        (2, 2),
        "no retry beyond the cancellation's budget"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_cancel_during_a_live555_teardown_retry_stops_it() {
    let (teardowns, connections) = cancelled_live555_teardown(CancelAt::Retrying).await;
    assert_eq!(
        (teardowns, connections),
        (1, 2),
        "no retry beyond the cancellation's budget"
    );
}
