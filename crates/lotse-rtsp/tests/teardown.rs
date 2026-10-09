//! Every attempt that ends after the camera set up a session sends it a
//! `TEARDOWN` (RFC 2326 §10.7, RFC 7826 §13.7), whatever ends it, over TCP
//! interleaved and over UDP, against the fake camera of `lotse-testing`,
//! which counts them: a refused or unanswered `PLAY`, a cancel while
//! `PLAY` is pending or while playing, no datagram within the read
//! deadline, a camera the relay refuses and one that hangs up. Over UDP
//! the session outlives its control connection (RFC 2326 §1.1), so when
//! that connection is gone the `TEARDOWN` goes out on a fresh one; over
//! TCP the session ends with its connection.

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

use lotse_core::clock::{Clock, SystemClock};
use lotse_core::source::{ResolvedPeer, SourceError, SourceExit, SourceFactory as _};
use lotse_core::source_url::SourceUrl;
use lotse_rtsp::RtspFactory;
use lotse_testing::fake_camera::{CameraAudio, CameraUdp, PlayAnswer, Stats, UdpService};
use lotse_testing::{CameraConfig, FakeCamera, Harness};
use serde_json::json;

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
    let source = RtspFactory::default()
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
            matches!(exit, SourceExit::Ended(SourceError::Protocol(ref m)) if m.contains("503")),
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
            matches!(exit, SourceExit::Ended(SourceError::Timeout(ref m)) if m.starts_with("PLAY")),
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
            matches!(exit, SourceExit::Ended(SourceError::Ended(ref m)) if m == "cancelled"),
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
            matches!(exit, SourceExit::Ended(SourceError::Ended(ref m)) if m == "cancelled"),
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
        matches!(exit, SourceExit::Ended(SourceError::Timeout(ref m)) if m.contains("of PLAY")),
        "{exit:?}"
    );
    torn_down_once(&cam, "udp").await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_camera_the_relay_refuses_is_torn_down_on_a_fresh_connection_over_udp() {
    // RFC 2326 §1.1: the session is not tied to its connection, so the
    // camera would keep sending datagrams after the relay closed it.
    let cam = camera(CameraConfig {
        play: PlayAnswer::Unreadable,
        ..CameraConfig::default()
    })
    .await;
    let harness = start(&cam, "udp");
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Protocol(ref m)) if m.contains("unreadable")),
        "{exit:?}"
    );
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
            matches!(exit, SourceExit::Ended(SourceError::Ended(_))),
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
