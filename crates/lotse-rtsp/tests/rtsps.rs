//! The RTSP source over TLS against the fake camera in TLS mode: a pinned
//! self-signed camera plays over TLS 1.3 and TLS 1.2, a wrong pin and an
//! untrusted certificate are `auth_failed` before any RTSP request,
//! `insecure_tls` plays and warns, a camera that does not speak TLS fails
//! the handshake, a silent one times out in it, and a pin mismatch is
//! retried only after the reconnect backoff.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::net::TcpListener as StdListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lotse_core::backoff::ReconnectBackoff;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::clock_map::ClockMapper;
use lotse_core::runner::{ConnectGate, RunnerConfig, RunnerEvent, SourceRunner};
use lotse_core::source::{
    BackchannelSlot, ResolvedPeer, Source, SourceError, SourceExit, SourceFactory as _, TrackSet,
};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_core::track::TrackLimits;
use lotse_rtsp::RtspFactory;
use lotse_rtsp::tls::Fingerprint;
use lotse_testing::fake_camera::{CameraTls, Stats};
use lotse_testing::{CameraConfig, FakeCamera, Harness};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// A TLS camera whose certificate names only `elsewhere.test`, so a pin
/// that plays proves the host name is not checked.
async fn tls_camera(tls: CameraTls) -> FakeCamera {
    FakeCamera::start(
        CameraConfig {
            tls: Some(tls),
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera binds")
}

/// The camera reached by the name `camera.test`.
fn peer(camera: &FakeCamera) -> ResolvedPeer {
    ResolvedPeer {
        host: "camera.test".into(),
        addrs: vec![camera.addr()],
    }
}

fn url(camera: &FakeCamera) -> String {
    format!("rtsps://camera.test:{}/stream", camera.addr().port())
}

fn source(factory: &RtspFactory, url: &str, options: &serde_json::Value) -> Box<dyn Source> {
    factory
        .validate(&SourceUrl::parse(url).unwrap(), options)
        .expect("valid source")
}

/// Plays `source` until a frame arrives, then cancels it.
async fn plays(source: &dyn Source, peer: ResolvedPeer) {
    let mut harness = Harness::start(source, peer, clock());
    assert!(harness.wait_ready().await, "ready");
    let track = harness.tracks.tracks()[0].clone();
    let mut frames = track.subscribe_frames();
    let mut got = false;
    for _ in 0..200 {
        if frames.try_recv().ok().flatten().is_some() {
            got = true;
            break;
        }
        clock().sleep(Duration::from_millis(10)).await;
    }
    assert!(got, "frames flow over TLS");
    harness.cancel();
    harness.finish().await;
}

/// Runs `source` to its exit, which must come before going live.
async fn fails(source: &dyn Source, peer: ResolvedPeer) -> SourceError {
    let mut harness = Harness::start(source, peer, clock());
    assert!(!harness.wait_ready().await, "never ready");
    let SourceExit::Ended(err) = harness.finish().await else {
        panic!("ended");
    };
    err
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rtsps_plays_with_a_pinned_certificate_rfc7826_19_2() {
    let tls = CameraTls::self_signed(&["elsewhere.test"]).unwrap();
    let pin = tls.fingerprint();
    let cam = tls_camera(tls).await;
    // A pre-bound relay listener, as a sandboxed worker has, serves two
    // attempts in a row.
    let relay = StdListener::bind("127.0.0.1:0").unwrap();
    let factory = RtspFactory::new(Some(relay));
    let options = json!({ "tls_fingerprint": pin });
    let source = source(&factory, &url(&cam), &options);
    assert_eq!(
        source.connection_options()["tls_fingerprint"],
        pin.to_lowercase()
    );
    plays(source.as_ref(), peer(&cam)).await;
    plays(source.as_ref(), peer(&cam)).await;
    let stats = cam.stats();
    assert_eq!(Stats::get(&stats.plays), 2);
    assert_eq!(Stats::get(&stats.tls_failures), 0);
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls_1_2_only_camera_plays_rfc5246() {
    let tls = CameraTls::tls12_only(&["elsewhere.test"]).unwrap();
    let options = json!({ "tls_fingerprint": tls.fingerprint() });
    let cam = tls_camera(tls).await;
    let source = source(&RtspFactory::default(), &url(&cam), &options);
    plays(source.as_ref(), peer(&cam)).await;
    assert_eq!(Stats::get(&cam.stats().plays), 1);
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_pin_is_auth_failed_before_any_request() {
    let tls = CameraTls::self_signed(&["camera.test"]).unwrap();
    let presented = tls.fingerprint().to_lowercase();
    let cam = tls_camera(tls).await;
    let wrong = Fingerprint::of(b"another certificate").to_string();
    let source = source(
        &RtspFactory::default(),
        &url(&cam),
        &json!({ "tls_fingerprint": wrong }),
    );
    let SourceError::AuthFailed(message) = fails(source.as_ref(), peer(&cam)).await else {
        panic!("auth_failed");
    };
    assert!(
        message.contains("does not match tls_fingerprint")
            && message.contains(&wrong)
            && message.contains(&presented),
        "{message}"
    );
    assert_eq!(Stats::get(&cam.stats().describes), 0, "no RTSP request");
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_signed_camera_without_a_pin_is_not_trusted() {
    let tls = CameraTls::self_signed(&["camera.test"]).unwrap();
    let presented = tls.fingerprint().to_lowercase();
    let cam = tls_camera(tls).await;
    let source = source(&RtspFactory::default(), &url(&cam), &json!({}));
    let SourceError::AuthFailed(message) = fails(source.as_ref(), peer(&cam)).await else {
        panic!("auth_failed");
    };
    assert!(
        message.contains("not trusted") && message.contains(&presented),
        "{message}"
    );
    assert_eq!(Stats::get(&cam.stats().describes), 0);
    cam.stop().await;
}

/// A log writer that keeps every line.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn insecure_tls_plays_and_warns() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    let _logs = tracing::subscriber::set_default(subscriber);
    let tls = CameraTls::self_signed(&["camera.test"]).unwrap();
    let presented = tls.fingerprint().to_lowercase();
    let cam = tls_camera(tls).await;
    let source = source(
        &RtspFactory::default(),
        &url(&cam),
        &json!({ "insecure_tls": true }),
    );
    plays(source.as_ref(), peer(&cam)).await;
    cam.stop().await;
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let warnings: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("insecure_tls"))
        .collect();
    assert_eq!(warnings.len(), 1, "{logs}");
    assert!(
        warnings[0].contains("WARN") && warnings[0].contains(&presented),
        "{logs}"
    );
    assert!(
        logs.lines()
            .any(|l| l.contains("TLS established") && l.contains("Insecure")),
        "{logs}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_camera_without_tls_fails_the_handshake_and_a_silent_one_times_out() {
    // A plain camera hangs up on the ClientHello it cannot parse.
    let plain = FakeCamera::start(CameraConfig::default(), clock())
        .await
        .unwrap();
    let options = json!({ "insecure_tls": true });
    let hangs_up = source(&RtspFactory::default(), &url(&plain), &options);
    let err = fails(hangs_up.as_ref(), peer(&plain)).await;
    assert!(
        matches!(err, SourceError::Unreachable(ref m) if m.starts_with("tls: handshake failed")),
        "{err:?}"
    );
    plain.stop().await;

    // A peer that accepts and never answers meets the read deadline.
    let quiet = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = quiet.local_addr().unwrap();
    let options = json!({ "insecure_tls": true, "timeout_ms": 300 });
    let silent = source(
        &RtspFactory::default(),
        &format!("rtsps://camera.test:{}/stream", addr.port()),
        &options,
    );
    let err = fails(
        silent.as_ref(),
        ResolvedPeer {
            host: "camera.test".into(),
            addrs: vec![addr],
        },
    )
    .await;
    assert!(
        matches!(err, SourceError::Timeout(ref m) if m.starts_with("TLS handshake")),
        "{err:?}"
    );
    drop(quiet);

    // A peer that answers the ClientHello with an RTSP response is not TLS.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answer = spawn_named("test.not_tls", async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0_u8; 512];
        let _read = stream.read(&mut hello).await.unwrap();
        stream
            .write_all(b"RTSP/1.0 400 Bad Request\r\nCSeq: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let not_tls = source(
        &RtspFactory::default(),
        &format!("rtsps://camera.test:{}/stream", addr.port()),
        &json!({ "insecure_tls": true }),
    );
    let err = fails(
        not_tls.as_ref(),
        ResolvedPeer {
            host: "camera.test".into(),
            addrs: vec![addr],
        },
    )
    .await;
    assert!(
        matches!(err, SourceError::Protocol(ref m) if m.starts_with("tls: handshake failed")),
        "{err:?}"
    );
    answer.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_an_address_or_a_listening_camera_rtsps_is_unreachable() {
    let source = source(
        &RtspFactory::default(),
        "rtsps://camera.test/stream",
        &json!({ "insecure_tls": true }),
    );
    let err = fails(
        source.as_ref(),
        ResolvedPeer {
            host: "camera.test".into(),
            addrs: vec![],
        },
    )
    .await;
    assert!(
        matches!(err, SourceError::Unreachable(ref m) if m.contains("no address resolved for camera.test")),
        "{err:?}"
    );
    let free = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let err = fails(
        source.as_ref(),
        ResolvedPeer {
            host: "camera.test".into(),
            addrs: vec![addr],
        },
    )
    .await;
    assert!(
        matches!(err, SourceError::Unreachable(ref m) if m.starts_with("Unable to connect")),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_mismatch_waits_for_the_reconnect_backoff() {
    let tls = CameraTls::self_signed(&["camera.test"]).unwrap();
    let cam = tls_camera(tls).await;
    let wrong = Fingerprint::of(b"another certificate").to_string();
    let tracks = TrackSet::new(TrackLimits::default(), clock().now());
    let (tx, mut events) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let runner = SourceRunner::new(
        source(
            &RtspFactory::default(),
            &url(&cam),
            &json!({ "tls_fingerprint": wrong }),
        ),
        peer(&cam),
        Arc::clone(&tracks),
        Arc::new(ClockMapper::new()),
        BackchannelSlot::default(),
        clock(),
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
    let Some(RunnerEvent::Backoff { error, retry_in }) = events.recv().await else {
        panic!("a failed attempt backs off");
    };
    assert_eq!(error.code(), "source_auth_failed", "{error}");
    assert!(retry_in >= Duration::from_millis(500), "{retry_in:?}");
    cancel.cancel();
    while let Some(event) = events.recv().await {
        assert!(
            !matches!(event, RunnerEvent::Connecting { .. }),
            "no second attempt before the backoff"
        );
        if event == RunnerEvent::Stopped {
            break;
        }
    }
    runner.await.unwrap();
    assert_eq!(Stats::get(&cam.stats().connections), 1);
    cam.stop().await;
}
