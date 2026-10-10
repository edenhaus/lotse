//! The M0 exit criterion: a `lotse ctl` round trip over the socket of a
//! real daemon. `info`, `stream put` with `preload` (a worker runs the fake
//! source), `stream get` until it is live, `stream subscribe`, an error
//! result, `raw`, `stream delete`, and a clean stop. Needs the
//! `source-fake` feature (on with `--all-features`).

#![cfg(feature = "source-fake")]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

mod common;

use std::path::Path;
use std::process::Output;

use common::{Daemon, SocketDir, json, lotse, socket_dir};
use serde_json::Value;

/// Runs `lotse ctl --socket <socket> <args>`.
fn ctl(socket: &Path, args: &[&str]) -> Output {
    lotse()
        .arg("ctl")
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("ctl runs")
}

/// Runs `lotse ctl --socket <socket> <args>` with `stdin` as its input.
fn ctl_with_stdin(socket: &Path, args: &[&str], stdin: &str) -> Output {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = lotse()
        .arg("ctl")
        .arg("--socket")
        .arg(socket)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ctl runs");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin.as_bytes())
        .expect("stdin written");
    child.wait_with_output().expect("ctl exits")
}

/// The JSON on stdout of a ctl run that must exit zero.
fn ok(socket: &Path, args: &[&str]) -> Value {
    let output = ctl(socket, args);
    assert!(
        output.status.success(),
        "ctl {args:?} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    serde_json::from_str(&stdout).unwrap_or_else(|err| panic!("ctl {args:?}: {err}\n{stdout}"))
}

/// `info`, pretty and compact.
fn check_info(socket: &Path) {
    let info = ok(socket, &["info"]);
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        info["schemes"]
            .as_array()
            .unwrap()
            .contains(&Value::from("fake"))
    );
    assert_eq!(info["sandbox"]["mode"], "off");
    assert!(!info["build"]["target"].as_str().unwrap().is_empty());
    // No source this build carries declares a backchannel yet, so two-way
    // audio stays off.
    assert_eq!(info["features"], serde_json::json!(["session_adopt"]));
    let compact = ctl(socket, &["--compact", "info"]);
    assert!(compact.status.success());
    assert_eq!(
        String::from_utf8_lossy(&compact.stdout).lines().count(),
        1,
        "one line"
    );
}

/// `stream put` with `preload` and its URL on stdin, then `stream
/// subscribe --limit 1` (which prints the current state at once) until the
/// stream is live.
fn put_and_wait_live(socket: &Path) -> Value {
    let put = ctl_with_stdin(
        socket,
        &["stream", "put", "front", "--url-file", "-", "--preload"],
        "fake://127.0.0.1/\n",
    );
    assert!(
        put.status.success(),
        "{}",
        String::from_utf8_lossy(&put.stderr)
    );
    assert_eq!(
        json(String::from_utf8_lossy(&put.stdout).trim()),
        serde_json::json!({ "created": true })
    );
    wait_live(socket, "front")
}

/// `stream subscribe <id> --limit 1` (which prints the current state at
/// once) until the stream is live, for at most 20 s, then its `stream get`.
fn wait_live(socket: &Path, id: &str) -> Value {
    use lotse_core::clock::{Clock as _, SystemClock};

    let deadline = SystemClock.now() + std::time::Duration::from_secs(20);
    let mut last = Value::Null;
    while SystemClock.now() < deadline {
        let events = ctl(socket, &["stream", "subscribe", id, "--limit", "1"]);
        assert!(
            events.status.success(),
            "subscribe {id}: {}",
            String::from_utf8_lossy(&events.stderr)
        );
        last = json(String::from_utf8_lossy(&events.stdout).trim());
        assert_eq!(last["type"], "stream");
        assert_eq!(last["stream_id"], id);
        if last["state"] == "live" {
            break;
        }
    }
    assert_eq!(last["state"], "live", "{id} never live: {last}");
    ok(socket, &["stream", "get", id])
}

/// Failed results print their error and exit 1.
fn check_errors(socket: &Path) {
    let missing = ctl(socket, &["stream", "get", "nope"]);
    assert_eq!(missing.status.code(), Some(1));
    let error = json(&String::from_utf8_lossy(&missing.stdout));
    assert_eq!(error["error"]["code"], "stream_not_found");
    let bad_scheme = ctl(socket, &["stream", "put", "x", "--url", "rtmp://cam/"]);
    assert_eq!(bad_scheme.status.code(), Some(1));
    assert_eq!(
        json(&String::from_utf8_lossy(&bad_scheme.stdout))["error"]["code"],
        "scheme_unsupported"
    );
    let raw = ctl(socket, &["raw", "not json"]);
    assert_eq!(raw.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&raw.stderr).contains("not JSON"));
}

/// `raw` prints every frame up to the result, as sent.
fn check_raw(socket: &Path) {
    let raw = ctl(socket, &["--compact", "raw", r#"{"type":"ping"}"#]);
    assert!(raw.status.success());
    let pong = json(String::from_utf8_lossy(&raw.stdout).trim());
    assert_eq!(
        (pong["type"].as_str(), pong["id"].as_u64()),
        (Some("pong"), Some(1))
    );
    let raw = ctl(
        socket,
        &["--compact", "raw", r#"{"id":7,"type":"stream/list"}"#],
    );
    assert!(raw.status.success());
    let frame = json(String::from_utf8_lossy(&raw.stdout).trim());
    assert_eq!(
        (
            frame["type"].as_str(),
            frame["id"].as_u64(),
            frame["success"].as_bool()
        ),
        (Some("result"), Some(7), Some(true))
    );
}

#[test]
fn ctl_round_trips_over_the_socket_of_a_running_daemon() {
    let dir = socket_dir("ctl");
    let socket = dir.join("lotse.sock");
    let socket_str = socket.to_str().expect("utf-8 path");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "127.0.0.1:0",
            "--socket",
            socket_str,
            "--sandbox",
            "off",
            "--linger-ms",
            "100",
            "--log-format",
            "json",
        ],
        &[],
    );
    daemon.wait_for("\"event\":\"ready\"");

    check_info(&socket);
    let front = put_and_wait_live(&socket);
    assert_eq!(front["tracks"][0]["id"], "v0");
    assert_eq!(front["tracks"][0]["codec"], "h264");
    assert!(
        front["sources"][0]["connection"]["worker"]["pid"]
            .as_u64()
            .unwrap()
            > 0
    );
    let list = ok(&socket, &["stream", "list"]);
    assert_eq!(list["streams"]["front"]["state"], "live");
    let metrics = ok(&socket, &["metrics"]);
    assert!(metrics["streams"].get("front").is_some(), "{metrics}");
    check_errors(&socket);
    check_raw(&socket);
    let schema = ok(&socket, &["schema"]);
    assert_eq!(schema["api"], lotse_api_types::API_VERSION);

    // Delete, idempotently; the worker is stopped and the connection released.
    assert_eq!(
        ok(&socket, &["stream", "delete", "front"]),
        serde_json::json!({})
    );
    assert_eq!(
        ok(&socket, &["stream", "delete", "front"]),
        serde_json::json!({})
    );
    assert_eq!(
        ok(&socket, &["stream", "list"]),
        serde_json::json!({ "streams": {} })
    );
    daemon.wait_for("connection released");

    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}

/// Regression for SBX-1 (reproduced 2026-10-07 on Linux 7.0): under
/// `--sandbox on` the supervisor's Landlock domain, which its workers
/// inherit, denied the `/dev/null` a spawn opens, so no worker started,
/// and denied every TCP `bind`, so no `rtsp` worker could bind its loopback
/// relay; its seccomp filter killed the supervisor at `pidfd_open` and,
/// inherited, the worker at its first Landlock call. A fake source, an
/// `rtsp` camera over TCP (through the relay) and the same camera over UDP
/// go live through workers of a sandboxed supervisor. Needs a static binary: Landlock's `execute` right is checked
/// on a dynamic binary's loader too, and the supervisor grants it on its
/// own binary alone, so this runs on the musl target (`mise run test-musl`).
#[cfg(all(
    target_os = "linux",
    target_feature = "crt-static",
    feature = "source-rtsp"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sandboxed_supervisor_spawns_workers_that_go_live() {
    use std::sync::Arc;

    use lotse_core::clock::{Clock, SystemClock};
    use lotse_testing::fake_camera::Stats;
    use lotse_testing::{CameraConfig, FakeCamera};

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let cam = FakeCamera::start(CameraConfig::default(), clock)
        .await
        .expect("camera binds");
    let dir = socket_dir("sandboxed-live");
    let socket = dir.join("lotse.sock");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "127.0.0.1:0",
            "--socket",
            socket.to_str().expect("utf-8 path"),
            "--sandbox",
            "on",
            "--log-format",
            "json",
        ],
        &[],
    );
    daemon.wait_for("\"event\":\"ready\"");
    let info = ok(&socket, &["info"]);
    assert_eq!(info["sandbox"]["mode"], "on", "{info}");
    assert_eq!(info["sandbox"]["no_new_privs"], true, "{info}");

    let url = cam.url();
    for (id, url, options) in [
        ("fake", "fake://127.0.0.1/", None),
        ("tcp", url.as_str(), None),
        ("udp", url.as_str(), Some(r#"{"transport":"udp"}"#)),
    ] {
        let mut args = vec!["stream", "put", id, "--url", url, "--preload"];
        if let Some(options) = options {
            args.extend(["--options", options]);
        }
        assert_eq!(ok(&socket, &args), serde_json::json!({ "created": true }));
        let stream = wait_live(&socket, id);
        assert!(
            stream["sources"][0]["connection"]["worker"]["pid"]
                .as_u64()
                .unwrap()
                > 0,
            "{stream}"
        );
        // A URL is the source of one stream at a time (`source_in_use`),
        // so the camera is released before the next transport takes it.
        assert_eq!(
            ok(&socket, &["stream", "delete", id]),
            serde_json::json!({})
        );
    }
    assert_eq!(Stats::get(&cam.stats().udp_setups), 1, "one UDP setup");

    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    cam.stop().await;
}

#[test]
fn ctl_without_a_daemon_fails_with_a_message() {
    let dir = socket_dir("ctl-none");
    let output = ctl(&dir.join("missing.sock"), &["info"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("connecting to"), "{stderr}");
    assert!(output.stdout.is_empty());
}

/// A daemon started with `--log-level <level>` and `env` on top.
fn daemon_at(test: &str, level: &str, env: &[(&str, &str)]) -> (SocketDir, Daemon) {
    let dir = socket_dir(test);
    let socket = dir.join("lotse.sock");
    let daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "127.0.0.1:0",
            "--socket",
            socket.to_str().expect("utf-8 path"),
            "--sandbox",
            "off",
            "--log-level",
            level,
        ],
        env,
    );
    (dir, daemon)
}

#[test]
fn rust_log_reaches_the_workers_and_is_reported_as_the_effective_level() {
    // Observed 2026-10-01: `RUST_LOG=info,lotse_codec=debug lotse serve`
    // gave no debug lines from workers, which got `--log-level info`.
    let (dir, mut daemon) = daemon_at("rust-log", "error", &[("RUST_LOG", "info")]);
    let config = json(&daemon.wait_for("\"setting\":\"log.level\""));
    assert_eq!(
        (config["value"].as_str(), config["source"].as_str()),
        (Some("info"), Some("env"))
    );
    daemon.wait_for("\"event\":\"ready\"");
    put_and_wait_live(&dir.join("lotse.sock"));
    // `error` alone would hide it: the worker logs at RUST_LOG's level.
    let starting = json(&daemon.wait_for("worker starting"));
    assert_eq!(starting["level"], "INFO", "{starting}");
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}

#[test]
fn an_invalid_rust_log_is_ignored_by_the_supervisor_and_its_workers() {
    let (dir, mut daemon) = daemon_at("bad-rust-log", "info", &[("RUST_LOG", "lotse=loudest")]);
    let config = json(&daemon.wait_for("\"setting\":\"log.level\""));
    assert_eq!(
        (config["value"].as_str(), config["source"].as_str()),
        (Some("info"), Some("flag"))
    );
    let warning = json(&daemon.wait_for("RUST_LOG is not a filter directive"));
    assert_eq!(
        (warning["level"].as_str(), warning["value"].as_str()),
        (Some("WARN"), Some("lotse=loudest"))
    );
    daemon.wait_for("\"event\":\"ready\"");
    // A worker handed the invalid filter would fail to start logging and
    // never go live; it gets the configured level instead.
    put_and_wait_live(&dir.join("lotse.sock"));
    let starting = json(&daemon.wait_for("worker starting"));
    assert_eq!(starting["level"], "INFO", "{starting}");
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}
