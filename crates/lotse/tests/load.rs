//! The load generator against a real `lotse serve`: a short soak of two
//! fake cameras with two headless viewers each, three cycles with a camera
//! hang-up in each, so every check of the report runs on real figures:
//! one camera connection and one worker per stream, every viewer playing,
//! the latency stamps, the quiet samples compared for growth, and no worker
//! left once the streams are deleted.
//! The long runs are `mise run load` and `mise run soak`. Needs the
//! `source-rtsp` and `output-webrtc` features (the defaults).

#![cfg(all(feature = "source-rtsp", feature = "output-webrtc"))]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Daemon, socket_dir};
use lotse_core::clock::SystemClock;
use lotse_testing::load::report::Tolerances;
use lotse_testing::load::{self, CameraProfile, LoadConfig};

fn config(socket: std::path::PathBuf) -> LoadConfig {
    LoadConfig {
        socket,
        cameras: 2,
        viewers: 2,
        cycle: Duration::from_secs(1),
        cycles: 3,
        drop_cameras: true,
        sample_every: Duration::from_millis(250),
        // The fake camera's small default stream: a keyframe every 333 ms.
        camera: CameraProfile {
            fps: 30,
            gop: 10,
            idr_bytes: 3_000,
            p_bytes: 600,
        },
        // A debug daemon on a shared runner: the mechanics are under test
        // here, the budgets are the soak job's.
        tolerances: Tolerances {
            memory_bytes: 16 << 20,
            latency: Duration::from_millis(20),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_soak_passes_every_check_against_a_real_daemon() {
    let dir = socket_dir("load");
    let socket = dir.join("lotse.sock");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            socket.to_str().unwrap(),
            "--sandbox",
            "off",
            "--log-format",
            "json",
        ],
        &[],
    );
    daemon.wait_for("\"event\":\"ready\"");
    lotse_webrtc::install_crypto_provider();

    let report = load::run(&config(socket), Arc::new(SystemClock))
        .await
        .expect("the run starts");
    println!("{}", report.summary());

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.cycle_reports.len(), 3);
    for cycle in &report.cycle_reports {
        assert_eq!(cycle.drops, 1);
        assert_eq!(
            cycle.camera_connections,
            [1, 1],
            "one reconnect each, shared"
        );
        assert_eq!((cycle.workers_at_load, cycle.sessions_at_load), (2, 4));
        assert_eq!(cycle.viewers.played, 4);
        assert!(cycle.cpu_percent.contains_key("supervisor"), "{cycle:?}");
        assert!(cycle.memory_bytes_total.is_some_and(|m| m > 0), "{cycle:?}");
    }
    assert_eq!((report.viewers.viewers, report.viewers.connected), (12, 12));
    assert!(report.latency_first_packet.count > 0);
    assert!(report.answer.p50_ms.is_some() && report.first_frame.p50_ms.is_some());
    let leaks = report.leaks.as_ref().expect("three cycles are a soak");
    assert_eq!(leaks.compared, 2, "the warm-up cycle is left out");
    let names: Vec<&str> = leaks.processes.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names.len(), 3, "{names:?}");
    assert_eq!(names[0], "supervisor");
    assert!(report.streams.get("load-0").is_some(), "{}", report.streams);
    // Under load, quiet after each cycle, and the samples in between.
    assert!(report.samples.len() >= 3 * 2, "{}", report.samples.len());

    let (code, _rest) = daemon.terminate();
    assert_eq!(code, Some(0));
}

#[tokio::test]
async fn without_a_daemon_the_run_does_not_start() {
    let dir = socket_dir("load-missing");
    let err = load::run(&config(dir.join("absent.sock")), Arc::new(SystemClock))
        .await
        .unwrap_err();
    assert!(err.contains("the control socket"), "{err}");
}
