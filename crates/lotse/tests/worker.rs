//! Drives a real `lotse worker` through the supervisor's worker manager:
//! spawn, run the fake source, see its reports, stop it within the budget;
//! and the M0 exit criterion, a worker crash that the supervisor observes
//! and survives; an `rtsps` camera played by a worker under its sandbox
//! through the loopback relay it bound before the sandbox; an `rtsp`
//! camera whose media takes UDP, received under the same sandbox; and an
//! HLS stream over `http` and over `https` with a pinned certificate,
//! fetched by a sandboxed worker from the server's port alone; a clip's
//! pipe passed to a sandboxed worker; and a clip of that HLS stream
//! recorded into its pipe under the sandbox. Needs the `source-fake`
//! feature (on with `--all-features`).

#![cfg(feature = "source-fake")]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

mod common;

use std::os::unix::process::ExitStatusExt as _;
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::{Clock, SystemClock};
use lotse_core::connection::WorkerReport;
use lotse_supervisor::worker::{
    ClipReport, ClipSpec, SourceSpec, WorkerConfig, WorkerEvent, WorkerManager,
};

fn manager() -> WorkerManager {
    manager_with_sandbox("off")
}

fn manager_with_sandbox(sandbox: &str) -> WorkerManager {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("a udp socket");
    WorkerManager::new(
        WorkerConfig {
            binary: common::worker_binary(),
            log_format: "json".into(),
            log_level: "debug".into(),
            sandbox: sandbox.into(),
            worker_threads: 1,
            worker_address_space: 1 << 30,
            max_sessions: 256,
            clips: lotse_supervisor::ClipLimits::DEFAULT,
        },
        Some(Arc::new(udp)),
    )
}

fn spec(options: &str) -> SourceSpec {
    SourceSpec {
        connection_id: "c1".into(),
        url: "fake://cam/".into(),
        options: options.into(),
        peer_host: "cam".into(),
        peer_addrs: vec![],
        backoff: lotse_ipc::BackoffPosition::default(),
        preroll_ms: 0,
    }
}

#[tokio::test]
async fn a_worker_runs_the_fake_source_and_stops_within_the_budget() {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut worker = manager().spawn(&[554], false).expect("spawns");
    let pid = worker.pid();
    let WorkerEvent::Ready { pid: ready, memory } = worker.next_event().await else {
        panic!("ready expected");
    };
    assert_eq!(ready, pid);
    // The worker's `smaps_rollup` where there is a `/proc`.
    assert_eq!(memory.is_some(), cfg!(target_os = "linux"));
    worker.run_source(&spec("null")).await.expect("run source");
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Connecting)
    );
    // The attempt waits for the supervisor's grant.
    worker.grant_connect().await.expect("grant");
    // The tracks come first, so a live stream always has them.
    let WorkerEvent::Tracks(tracks) = worker.next_event().await else {
        panic!("tracks expected");
    };
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Live)
    );
    assert_eq!(tracks.len(), 1);
    assert_eq!(tracks[0].codec, "h264");
    let WorkerEvent::Stats(stats) = worker.next_event().await else {
        panic!("stats expected within a second");
    };
    assert_eq!(stats.tracks[0].0, "v0");

    let exit = worker.stop(Duration::from_secs(5), &clock).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
}

/// A worker asked for a loopback relay binds it before its sandbox and
/// still starts and stops cleanly; here without a sandbox, the relay path
/// the sandboxed `rtsps` test below takes under one.
#[tokio::test]
async fn a_worker_with_a_loopback_relay_starts_and_stops_cleanly() {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut worker = manager().spawn(&[], true).expect("spawns");
    assert!(matches!(
        worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    let exit = worker.stop(Duration::from_secs(5), &clock).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
}

#[tokio::test]
async fn a_worker_crash_is_observed_and_contained() {
    let mut worker = manager().spawn(&[], false).expect("spawns");
    assert!(matches!(
        worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    worker
        .run_source(&spec("{\"crash\": true}"))
        .await
        .expect("run source");
    worker.grant_connect().await.expect("grant");
    // The crash comes right after ready; whatever reports raced ahead of it,
    // the channel ends and the exit is by SIGABRT.
    let status = loop {
        match worker.next_event().await {
            WorkerEvent::Exited(status) => break status,
            WorkerEvent::ChannelClosed
            | WorkerEvent::ChannelError(_)
            | WorkerEvent::Report(_)
            | WorkerEvent::Tracks(_)
            | WorkerEvent::Stats(_)
            | WorkerEvent::Session { .. } => {}
            other @ (WorkerEvent::Ready { .. }
            | WorkerEvent::SourceStopped
            | WorkerEvent::SwitchReport(..)
            | WorkerEvent::StandbyStopped
            | WorkerEvent::Switched
            | WorkerEvent::ProbeConnecting(_)
            | WorkerEvent::ProbeEnded(_)
            | WorkerEvent::Talker { .. }
            | WorkerEvent::Clip { .. }) => {
                panic!("unexpected {other:?}")
            }
        }
    };
    assert!(!status.success());
    assert_eq!(status.signal(), Some(6), "SIGABRT, got {status:?}");
    // The supervisor side is unaffected: it can start another worker.
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut next = manager().spawn(&[], false).expect("spawns again");
    assert!(matches!(next.next_event().await, WorkerEvent::Ready { .. }));
    assert!(next.stop(Duration::from_secs(5), &clock).await.success());
}

/// A clip's pipe crosses into a worker under its sandbox with its
/// `StartClip`, and the worker, which runs no source, refuses the clip
/// `source_not_live` and closes the pipe: the reader sees its end, with
/// nothing written.
#[tokio::test]
async fn a_sandboxed_worker_takes_a_clip_s_pipe_and_closes_it() {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut worker = manager_with_sandbox("on")
        .spawn(&[], false)
        .expect("spawns");
    assert!(matches!(
        worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    let (mut reader, writer) = std::io::pipe().expect("a pipe");
    let clip = ClipSpec {
        clip_id: "k1".into(),
        before_ms: 10_000,
        after_ms: Some(20_000),
        audio: true,
    };
    worker
        .start_clip(&clip, writer.into())
        .await
        .expect("start clip");
    let mut event = worker.next_event().await;
    while matches!(event, WorkerEvent::Stats(_)) {
        event = worker.next_event().await;
    }
    assert_eq!(
        event,
        WorkerEvent::Clip {
            clip_id: "k1".into(),
            event: ClipReport::Stopped {
                reason: "source_not_live".into(),
                bytes: 0,
                duration_ms: 0,
                gaps: 0,
            },
        }
    );
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut rest).expect("reads to the end");
    assert!(rest.is_empty());
    let exit = worker.stop(Duration::from_secs(5), &clock).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
}

/// On Linux the worker's Landlock rules allow TCP only to the camera's port
/// and the relay port bound before the sandbox, and seccomp has to allow
/// what TLS needs (`getrandom`); on macOS the sandbox is a no-op and this
/// checks the relay path of a real worker.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sandboxed_worker_plays_rtsps_through_its_loopback_relay() {
    use lotse_testing::fake_camera::CameraTls;
    use lotse_testing::{CameraConfig, FakeCamera};

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let tls = CameraTls::self_signed(&["camera.test"]).expect("certificate");
    let pin = tls.fingerprint();
    let cam = FakeCamera::start(
        CameraConfig {
            tls: Some(tls),
            ..CameraConfig::default()
        },
        Arc::clone(&clock),
    )
    .await
    .expect("camera binds");
    let port = cam.addr().port();
    let mut worker = manager_with_sandbox("on")
        .spawn(&[port], true)
        .expect("spawns");
    let pid = worker.pid();
    let WorkerEvent::Ready { pid: ready, memory } = worker.next_event().await else {
        panic!("ready expected");
    };
    assert_eq!(ready, pid);
    // Not dumpable under the sandbox, the worker's `/proc` entries are
    // closed to the supervisor; the descriptor it handed over still reads.
    let read = match memory {
        Some(memory) => Some(
            memory
                .sample(clock.now())
                .await
                .pss_bytes
                .is_some_and(|pss| pss > 0),
        ),
        None => None,
    };
    assert_eq!(read, cfg!(target_os = "linux").then_some(true));
    let spec = SourceSpec {
        connection_id: "c1".into(),
        url: format!("rtsps://camera.test:{port}/stream"),
        options: format!("{{\"tls_fingerprint\": \"{pin}\"}}"),
        peer_host: "camera.test".into(),
        peer_addrs: vec![cam.addr()],
        backoff: lotse_ipc::BackoffPosition::default(),
        preroll_ms: 0,
    };
    worker.run_source(&spec).await.expect("run source");
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Connecting)
    );
    worker.grant_connect().await.expect("grant");
    let WorkerEvent::Tracks(tracks) = worker.next_event().await else {
        panic!("tracks expected");
    };
    assert_eq!(tracks[0].codec, "h264");
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Live)
    );
    let exit = worker.stop(Duration::from_secs(5), &clock).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    cam.stop().await;
}

/// RTP over UDP under the sandbox: Landlock's network rules (ABI 4 to 6)
/// cover TCP only and seccomp lets a worker open `AF_INET` sockets, so the
/// worker binds its RTP/RTCP pairs itself after the sandbox, and the
/// stream is live only once a datagram arrived. On macOS the sandbox is a
/// no-op and this checks the UDP path of a real worker.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sandboxed_worker_receives_rtsp_media_over_udp() {
    use lotse_testing::fake_camera::Stats;
    use lotse_testing::{CameraConfig, FakeCamera};

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let cam = FakeCamera::start(CameraConfig::default(), Arc::clone(&clock))
        .await
        .expect("camera binds");
    let port = cam.addr().port();
    let mut worker = manager_with_sandbox("on")
        .spawn(&[port], true)
        .expect("spawns");
    assert!(matches!(
        worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    let spec = SourceSpec {
        connection_id: "c1".into(),
        url: cam.url(),
        options: r#"{"transport": "udp"}"#.into(),
        peer_host: "127.0.0.1".into(),
        peer_addrs: vec![cam.addr()],
        backoff: lotse_ipc::BackoffPosition::default(),
        preroll_ms: 0,
    };
    worker.run_source(&spec).await.expect("run source");
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Connecting)
    );
    worker.grant_connect().await.expect("grant");
    let WorkerEvent::Tracks(tracks) = worker.next_event().await else {
        panic!("tracks expected");
    };
    assert_eq!(tracks[0].codec, "h264");
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Live)
    );
    assert_eq!(Stats::get(&cam.stats().udp_setups), 1);
    let exit = worker.stop(Duration::from_secs(5), &clock).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    cam.stop().await;
}

/// Serves three one-second HLS MPEG-TS segments of H.264 and AAC (the HTTP
/// source's recorded fixtures) as the live playlist `/live/index.m3u8`.
#[cfg(feature = "source-http")]
fn serve_live(server: &lotse_testing::fake_http::FakeHttp) {
    let playlist = "/live/index.m3u8";
    server.live(playlist, 3);
    for (uri, body) in [
        (
            "/live/0.m2t",
            &include_bytes!("../../lotse-http/testdata/live_0.m2t")[..],
        ),
        (
            "/live/1.m2t",
            &include_bytes!("../../lotse-http/testdata/live_1.m2t")[..],
        ),
        (
            "/live/2.m2t",
            &include_bytes!("../../lotse-http/testdata/live_2.m2t")[..],
        ),
    ] {
        server.push_segment(playlist, uri, 1.0, body);
    }
}

/// Plays `url` with `options` in a worker under the sandbox, allowed to
/// connect to the server's port only and without a loopback relay, until
/// it is live with the fixtures' H.264 and AAC tracks.
#[cfg(feature = "source-http")]
async fn play_http_in_sandbox(
    server: &lotse_testing::fake_http::FakeHttp,
    url: String,
    options: String,
) {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut worker = manager_with_sandbox("on")
        .spawn(&[server.addr().port()], false)
        .expect("spawns");
    assert!(matches!(
        worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    let spec = SourceSpec {
        connection_id: "c1".into(),
        url,
        options,
        peer_host: "camera.test".into(),
        peer_addrs: vec![server.addr()],
        backoff: lotse_ipc::BackoffPosition::default(),
        preroll_ms: 0,
    };
    worker.run_source(&spec).await.expect("run source");
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Connecting)
    );
    worker.grant_connect().await.expect("grant");
    let WorkerEvent::Tracks(tracks) = worker.next_event().await else {
        panic!("tracks expected");
    };
    let codecs: Vec<&str> = tracks.iter().map(|track| track.codec.as_str()).collect();
    assert_eq!(codecs, ["h264", "aac_lc"]);
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Live)
    );
    let exit = worker.stop(Duration::from_secs(5), &clock).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
}

/// On Linux the worker's Landlock rules allow TCP to the server's port
/// alone (the port of the URL; the playlist's segments share its origin);
/// on macOS the sandbox is a no-op and this checks the HTTP path of a real
/// worker.
#[cfg(feature = "source-http")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sandboxed_worker_plays_hls_over_http() {
    let server = lotse_testing::fake_http::FakeHttp::start()
        .await
        .expect("server binds");
    serve_live(&server);
    let port = server.addr().port();
    play_http_in_sandbox(
        &server,
        format!("http://camera.test:{port}/live/index.m3u8"),
        "null".into(),
    )
    .await;
    assert!(!server.requests().is_empty());
    server.stop().await;
}

/// `https` under the sandbox: seccomp has to allow what TLS needs, as for
/// `rtsps`; the certificate is pinned, so it may name another host.
#[cfg(feature = "source-http")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sandboxed_worker_plays_hls_over_https_with_a_pinned_certificate() {
    use lotse_testing::fake_camera::CameraTls;

    let tls = CameraTls::self_signed(&["server.test"]).expect("certificate");
    let pin = tls.fingerprint();
    let server = lotse_testing::fake_http::FakeHttp::start_tls(&tls)
        .await
        .expect("server binds");
    serve_live(&server);
    let port = server.addr().port();
    play_http_in_sandbox(
        &server,
        format!("https://camera.test:{port}/live/index.m3u8"),
        format!("{{\"tls_fingerprint\": \"{pin}\"}}"),
    )
    .await;
    server.stop().await;
}

/// A clip recorded under the sandbox, the first time a worker writes into a
/// clip's pipe: taking it (`fstat`, `fcntl`), waiting for it to take bytes
/// (epoll) and writing them (`writev`) must pass seccomp and Landlock. The
/// HLS fixtures carry the H.264 parameter sets and the AAC configuration
/// the clip's container needs; the stream's window holds what the clip
/// starts from. On macOS the sandbox is a no-op and this checks the clip
/// path of a real worker.
#[cfg(all(feature = "source-http", feature = "output-clip"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sandboxed_worker_records_a_clip_into_its_pipe() {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let server = lotse_testing::fake_http::FakeHttp::start()
        .await
        .expect("server binds");
    serve_live(&server);
    let port = server.addr().port();
    let mut worker = manager_with_sandbox("on")
        .spawn(&[port], false)
        .expect("spawns");
    assert!(matches!(
        worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    let spec = SourceSpec {
        connection_id: "c1".into(),
        url: format!("http://camera.test:{port}/live/index.m3u8"),
        options: "null".into(),
        peer_host: "camera.test".into(),
        peer_addrs: vec![server.addr()],
        backoff: lotse_ipc::BackoffPosition::default(),
        preroll_ms: 10_000,
    };
    worker.run_source(&spec).await.expect("run source");
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Connecting)
    );
    worker.grant_connect().await.expect("grant");
    assert!(matches!(worker.next_event().await, WorkerEvent::Tracks(_)));
    assert_eq!(
        worker.next_event().await,
        WorkerEvent::Report(WorkerReport::Live)
    );
    // The clip starts from the window once it holds a keyframe and what
    // follows it, as the once-per-second counters say.
    loop {
        if let WorkerEvent::Stats(stats) = worker.next_event().await
            && stats.tracks.iter().any(|(id, track)| {
                id == "v0" && track.preroll.as_ref().is_some_and(|ring| ring.held_ms > 0)
            })
        {
            break;
        }
    }
    // The pipe is read as the worker writes: a reader that waited for the
    // end would hold the clip at the pipe's 64 KiB.
    let (mut reader, writer) = std::io::pipe().expect("a pipe");
    let reading = std::thread::spawn(move || {
        let mut file = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut file).map(|_| file)
    });
    let clip = ClipSpec {
        clip_id: "k1".into(),
        before_ms: 10_000,
        after_ms: Some(1_000),
        audio: true,
    };
    worker
        .start_clip(&clip, writer.into())
        .await
        .expect("start clip");
    let mut reports = Vec::new();
    loop {
        match worker.next_event().await {
            WorkerEvent::Clip { clip_id, event } => {
                assert_eq!(clip_id, "k1");
                let stopped = matches!(event, ClipReport::Stopped { .. });
                reports.push(event);
                if stopped {
                    break;
                }
            }
            WorkerEvent::Stats(_) | WorkerEvent::Report(_) | WorkerEvent::Tracks(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    let file = reading
        .join()
        .expect("the reader")
        .expect("reads to the end");
    assert!(
        matches!(
            &reports[0],
            ClipReport::Started { video, audio: Some(audio), .. }
                if video == "h264" && audio == "aac_lc"
        ),
        "{reports:?}"
    );
    let Some(ClipReport::Stopped { reason, bytes, .. }) = reports.last() else {
        panic!("stopped last: {reports:?}");
    };
    assert_eq!(reason, "completed", "{reports:?}");
    assert_eq!(*bytes, u64::try_from(file.len()).unwrap());
    // ISO/IEC 14496-12 §4.3: the file begins with its `ftyp` box.
    assert_eq!(file.get(4..8), Some(&b"ftyp"[..]), "{} bytes", file.len());
    let exit = worker.stop(Duration::from_secs(5), &clock).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    server.stop().await;
}
