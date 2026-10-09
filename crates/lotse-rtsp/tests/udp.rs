//! The RTSP source with `transport: "udp"` against the fake camera of
//! `lotse-testing`, which answers `SETUP` with its own `server_port` pair
//! and sends RTP and RTCP as datagrams to the client's (RFC 2326 §12.39,
//! RFC 3550 §11): media and sync hints over UDP with the firewall hole
//! punched, loss, reordering and duplicates counted without ending the
//! session, a foreign sender refused, a `461` refusal and a camera whose
//! datagrams never arrive ending with a repair hint, answers without
//! `server_port` or with `source`, the sender taken from the RTSP
//! endpoint without `source` and never in place of a silent one, a
//! `source` no camera can send from ending the attempt, and keepalives
//! on the control connection while the media takes UDP.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::{Clock, SystemClock};
use lotse_core::codec::Kind;
use lotse_core::ingest::IngestStats;
use lotse_core::source::{ResolvedPeer, SourceError, SourceExit, SourceFactory as _};
use lotse_core::source_url::SourceUrl;
use lotse_core::track::{SubscriptionError, Track};
use lotse_rtsp::RtspFactory;
use lotse_testing::fake_camera::{CameraAudio, CameraUdp, Stats, UdpService};
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

async fn camera(config: CameraConfig) -> FakeCamera {
    traced();
    FakeCamera::start(config, clock())
        .await
        .expect("camera binds")
}

fn peer(camera: &FakeCamera) -> ResolvedPeer {
    ResolvedPeer {
        host: camera.addr().ip().to_string(),
        addrs: vec![camera.addr()],
    }
}

/// A source for `camera` with `transport: "udp"` and `extra` options.
fn udp_source(
    camera: &FakeCamera,
    extra: &serde_json::Value,
) -> Box<dyn lotse_core::source::Source> {
    let mut options = json!({ "transport": "udp" });
    if let (Some(options), Some(extra)) = (options.as_object_mut(), extra.as_object()) {
        options.extend(extra.clone());
    }
    RtspFactory::default()
        .validate(&SourceUrl::parse(&camera.url()).unwrap(), &options)
        .expect("valid source")
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

/// Frames `track` publishes until `keyframes` keyframes went by, or 10 s:
/// how many, and how many of them were keyframes.
async fn count_frames(track: &Track, keyframes: usize) -> (usize, usize) {
    let mut frames = track.subscribe_frames();
    let (mut seen, mut keys) = (0, 0);
    let deadline = clock().now() + Duration::from_secs(10);
    while clock().now() < deadline && keys < keyframes {
        loop {
            match frames.try_recv() {
                Ok(Some(frame)) => {
                    seen += 1;
                    keys += usize::from(frame.keyframe);
                }
                Ok(None) | Err(SubscriptionError::Closed) => break,
                Err(SubscriptionError::Lagged(_)) => {}
            }
        }
        clock().sleep(Duration::from_millis(10)).await;
    }
    (seen, keys)
}

/// Plays `config` over UDP until two keyframes went by, then cancels:
/// the frames seen and the ingest counters.
async fn play(config: CameraConfig) -> (FakeCamera, usize, IngestStats) {
    let cam = camera(config).await;
    let source = udp_source(&cam, &json!({}));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "live over UDP");
    let v0 = harness.tracks.tracks()[0].clone();
    let (frames, keyframes) = count_frames(&v0, 2).await;
    assert_eq!(keyframes, 2, "{frames} frames");
    let stats = harness.tracks.ingest();
    harness.cancel();
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Ended(ref m)) if m == "cancelled"),
        "{exit:?}"
    );
    (cam, frames, stats)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_39_video_audio_and_sender_reports_flow_over_udp_then_tear_down() {
    let cam = camera(CameraConfig {
        audio: Some(CameraAudio::Pcmu),
        ..CameraConfig::default()
    })
    .await;
    let source = udp_source(&cam, &json!({}));
    assert_eq!(source.describe().options["transport"], "udp");
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "live once RTP arrived");
    let tracks = harness.tracks.tracks();
    assert_eq!(
        tracks.iter().map(|t| t.kind()).collect::<Vec<_>>(),
        [Kind::Video, Kind::Audio]
    );
    let (frames, keyframes) = count_frames(&tracks[0], 2).await;
    assert!(frames >= 11 && keyframes == 2, "{frames} frames");
    let mut audio = tracks[1].subscribe_packets();
    assert!(
        eventually(100, || matches!(audio.try_recv(), Ok(Some(_)))).await,
        "audio over UDP"
    );
    // RFC 3550 §6.4.1: the Sender Reports came over the RTCP ports.
    assert!(harness.reports.try_recv().is_ok(), "a sender report hint");
    let counters = cam.stats();
    assert_eq!(Stats::get(&counters.udp_setups), 2, "both streams over UDP");
    assert!(Stats::get(&counters.datagrams) > 0);
    // One hole punch per port of each pair reached the camera's ports.
    assert!(
        eventually(50, || Stats::get(&counters.datagrams_received) >= 4).await,
        "{} hole punches",
        Stats::get(&counters.datagrams_received)
    );
    assert_eq!(
        harness.tracks.ingest(),
        IngestStats::default(),
        "a clean LAN"
    );
    harness.cancel();
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Ended(ref m)) if m == "cancelled"),
        "{exit:?}"
    );
    // The control connection carried the TEARDOWN: the camera stops.
    assert!(
        eventually(50, || Stats::get(&counters.teardowns) == 1).await,
        "teardown sent"
    );
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3550_a_1_loss_reordering_and_duplicates_are_counted_and_media_goes_on() {
    let (cam, frames, stats) = play(CameraConfig {
        udp: CameraUdp {
            drop_every: Some(7),
            swap_every: Some(11),
            duplicate_every: Some(13),
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    })
    .await;
    assert!(frames > 0);
    assert!(stats.packets_lost > 0, "{stats:?}");
    assert!(stats.packets_out_of_order > 0, "{stats:?}");
    assert_eq!(stats.datagrams_rejected, 0, "{stats:?}");
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_from_another_port_are_refused_and_counted() {
    // The foreign copies run 1000 sequence numbers ahead: had one passed,
    // the camera's own packets would read as late and the stream stall.
    let (cam, frames, stats) = play(CameraConfig {
        udp: CameraUdp {
            foreign_every: Some(5),
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    })
    .await;
    assert!(frames > 0);
    assert!(stats.datagrams_rejected > 0, "{stats:?}");
    assert_eq!(
        (stats.packets_lost, stats.packets_out_of_order),
        (0, 0),
        "{stats:?}"
    );
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_39_answers_without_server_port_or_naming_the_source_play() {
    let named = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    for (omit_server_port, announce_source) in [(true, None), (false, named)] {
        let (cam, frames, stats) = play(CameraConfig {
            udp: CameraUdp {
                omit_server_port,
                announce_source,
                ..CameraUdp::default()
            },
            ..CameraConfig::default()
        })
        .await;
        assert!(frames > 0);
        assert_eq!(stats, IngestStats::default());
        if omit_server_port {
            // Nowhere to punch a hole to.
            assert_eq!(Stats::get(&cam.stats().datagrams_received), 0);
        }
        cam.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_39_without_source_the_media_comes_from_the_rtsp_endpoint_address() {
    // The camera's endpoint is ::1 and the relay's own side 127.0.0.1:
    // its datagrams pass only if the sender is the endpoint the relay
    // connected to.
    let (cam, frames, stats) = play(CameraConfig {
        ip: Ipv6Addr::LOCALHOST.into(),
        ..CameraConfig::default()
    })
    .await;
    assert!(frames > 0);
    assert_eq!(stats, IngestStats::default());
    // The hole punched to the endpoint's `server_port` pair.
    assert!(Stats::get(&cam.stats().datagrams_received) > 0);
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_39_a_named_source_that_stays_silent_is_not_replaced_by_the_rtsp_endpoint() {
    // The answer names a documentation address (RFC 3849) the camera never
    // sends from; its datagrams from the endpoint, ::1, are refused.
    let cam = camera(CameraConfig {
        ip: Ipv6Addr::LOCALHOST.into(),
        udp: CameraUdp {
            announce_source: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into()),
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    })
    .await;
    let source = udp_source(&cam, &json!({ "timeout_ms": 300 }));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(!harness.wait_ready().await);
    let stats = harness.tracks.ingest();
    let exit = harness.finish().await;
    let SourceExit::Ended(SourceError::Timeout(message)) = exit else {
        panic!("a timeout, not {exit:?}");
    };
    assert!(message.contains("firewall or NAT"), "{message}");
    assert!(stats.datagrams_rejected > 0, "{stats:?}");
    assert!(Stats::get(&cam.stats().datagrams) > 0);
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc1122_3_2_1_3_a_source_the_camera_cannot_send_from_ends_the_attempt() {
    // An IPv4 source for the endpoint ::1, whose IPv6 pair can never hear
    // it: refused before anything is sent there.
    let cam = camera(CameraConfig {
        ip: Ipv6Addr::LOCALHOST.into(),
        udp: CameraUdp {
            announce_source: Some(Ipv4Addr::LOCALHOST.into()),
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    })
    .await;
    let source = udp_source(&cam, &json!({}));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(!harness.wait_ready().await);
    let exit = harness.finish().await;
    let SourceExit::Ended(SourceError::Protocol(message)) = exit else {
        panic!("a protocol error, not {exit:?}");
    };
    assert!(
        message.contains("source 127.0.0.1") && message.contains("another address family"),
        "{message}"
    );
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_11_3_11_a_camera_that_refuses_udp_fails_with_a_repair_hint() {
    let cam = camera(CameraConfig {
        udp: CameraUdp {
            service: UdpService::Refuse,
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    })
    .await;
    let source = udp_source(&cam, &json!({}));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(!harness.wait_ready().await);
    let exit = harness.finish().await;
    let SourceExit::Ended(SourceError::Protocol(message)) = exit else {
        panic!("a protocol error, not {exit:?}");
    };
    assert!(message.contains("461"), "{message}");
    assert!(
        message.contains("set the stream's transport to tcp"),
        "{message}"
    );
    // The same camera plays over TCP.
    let source = RtspFactory::default()
        .validate(&SourceUrl::parse(&cam.url()).unwrap(), &json!({}))
        .unwrap();
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_11_3_11_a_udp_only_camera_plays_over_udp_and_refuses_tcp_without_the_udp_hint() {
    let cam = camera(CameraConfig {
        udp: CameraUdp {
            service: UdpService::Only,
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    })
    .await;
    let source = RtspFactory::default()
        .validate(&SourceUrl::parse(&cam.url()).unwrap(), &json!({}))
        .unwrap();
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(!harness.wait_ready().await, "not over TCP");
    let exit = harness.finish().await;
    let SourceExit::Ended(SourceError::Protocol(message)) = exit else {
        panic!("a protocol error, not {exit:?}");
    };
    assert!(message.contains("461"), "{message}");
    assert!(!message.contains("transport to tcp"), "{message}");
    let source = udp_source(&cam, &json!({}));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "over UDP");
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_that_never_arrive_end_the_attempt_with_a_repair_hint() {
    let cam = camera(CameraConfig {
        udp: CameraUdp {
            service: UdpService::Blackhole,
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    })
    .await;
    let source = udp_source(&cam, &json!({ "timeout_ms": 300 }));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    // Never live: no stall later, a timeout that says why.
    assert!(!harness.wait_ready().await);
    let exit = harness.finish().await;
    let SourceExit::Ended(SourceError::Timeout(message)) = exit else {
        panic!("a timeout, not {exit:?}");
    };
    assert!(message.contains("within 300 ms of PLAY"), "{message}");
    assert!(message.contains("firewall or NAT"), "{message}");
    assert_eq!(Stats::get(&cam.stats().plays), 1);
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_37_keepalives_flow_on_the_control_connection_while_media_takes_udp() {
    // A 2 s session timeout: retina keeps it alive every second.
    let cam = camera(CameraConfig {
        session_timeout_s: 2,
        ..CameraConfig::default()
    })
    .await;
    let source = udp_source(&cam, &json!({}));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    let counters = cam.stats();
    assert!(
        eventually(150, || Stats::get(&counters.keepalives) >= 2).await,
        "keepalives over the control connection"
    );
    let v0 = harness.tracks.tracks()[0].clone();
    let (frames, _) = count_frames(&v0, 1).await;
    assert!(frames > 0, "media still flows");
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}
