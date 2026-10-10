//! Runs the built `lotse` binary as a subprocess, the only way to cover
//! `main`: usage errors, configuration precedence, the `ready` event, and a
//! clean stop on `SIGTERM`. Coverage of the child is collected because the
//! binary is instrumented too.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

mod common;

use common::{Daemon, json, lotse, socket_dir};

#[test]
fn help_and_version_print_and_exit_zero() {
    let output = lotse().arg("--help").output().expect("runs");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("serve"), "{help}");
    let output = lotse().args(["serve", "--help"]).output().expect("runs");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("LOTSE_SOCKET"), "{help}");
    assert!(help.contains("--sandbox"), "{help}");
    let output = lotse().arg("--version").output().expect("runs");
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("lotse "));
}

#[test]
fn usage_errors_exit_two_and_config_errors_exit_one() {
    let output = lotse().output().expect("runs");
    assert_eq!(output.status.code(), Some(2), "no subcommand");
    let output = lotse()
        .args(["serve", "--socket", "/x", "--no-such-flag"])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(2), "an unknown flag");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--no-such-flag"));

    let output = lotse().arg("serve").output().expect("runs");
    assert_eq!(output.status.code(), Some(1), "no socket");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("lotse failed"), "{stderr}");
    assert!(stderr.contains("--socket"), "{stderr}");
    assert!(output.stdout.is_empty(), "nothing on stdout");
}

#[test]
fn serve_logs_its_config_reports_ready_and_stops_on_sigterm() {
    let dir = socket_dir("ready");
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
            "off",
            "--log-format",
            "json",
        ],
        &[],
    );
    let starting = json(&daemon.wait_for("lotse starting"));
    assert_eq!(starting["level"], "INFO");
    assert_eq!(starting["spans"][0]["kind"], "supervisor");
    assert!(starting["spans"][0]["pid"].is_number());

    let line = daemon.wait_for("\"setting\":\"sandbox\"");
    let setting = json(&line);
    assert_eq!(setting["value"], "off");
    assert_eq!(setting["source"], "flag");
    let line = daemon.wait_for("\"setting\":\"limits.max_streams\"");
    assert_eq!(json(&line)["source"], "default");

    let ready = json(&daemon.wait_for("\"event\":\"ready\""));
    assert_eq!(ready["socket"], socket.to_str().expect("utf-8 path"));
    assert!(
        ready["udp_listen"]
            .as_str()
            .is_some_and(|udp| udp.starts_with("127.0.0.1:") && !udp.ends_with(":0")),
        "{ready}"
    );
    assert!(ready["udp_recv_buffer"].as_u64().is_some_and(|n| n > 0));

    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
    let stopping = rest
        .iter()
        .find(|line| line.contains("shutting down"))
        .unwrap_or_else(|| panic!("no shutdown line\n{}", rest.join("\n")));
    assert_eq!(json(stopping)["reason"], "sigterm");
    assert!(rest.iter().any(|line| line.contains("lotse exited")));
}

#[test]
fn environment_overrides_the_file_and_flags_override_the_environment() {
    let dir = socket_dir("precedence");
    let config = dir.join("lotse.toml");
    std::fs::write(
        &config,
        format!(
            // Ephemeral listeners, so a daemon on the default port does not
            // fail the test.
            "socket = \"{}\"\nsandbox = \"off\"\n[webrtc]\nudp_listen = \"127.0.0.1:0\"\ntcp_listen = \"127.0.0.1:0\"\n[stream]\nlinger_ms = 1234\n[limits]\nmax_streams = 3\nsession_grace_ms = 4321\n[log]\nformat = \"json\"\n",
            dir.join("lotse.sock").display()
        ),
    )
    .expect("config written");
    let socket = dir.join("env.sock");
    let socket = socket.to_str().expect("utf-8");
    let mut daemon = Daemon::start(
        &[
            "--config",
            config.to_str().expect("utf-8"),
            "--max-streams",
            "7",
        ],
        &[
            ("LOTSE_SOCKET", socket),
            ("LOTSE_LINGER_MS", "999"),
            ("LOTSE_MAX_STREAMS", "5"),
        ],
    );
    // Settings are logged in a fixed order: the socket first, then limits
    // before stream before log.
    let from_env = json(&daemon.wait_for("\"setting\":\"socket\""));
    assert_eq!(
        (from_env["value"].as_str(), from_env["source"].as_str()),
        (Some(socket), Some("env"))
    );
    let streams = json(&daemon.wait_for("\"setting\":\"limits.max_streams\""));
    assert_eq!(
        (streams["value"].as_str(), streams["source"].as_str()),
        (Some("7"), Some("flag"))
    );
    // Neither a flag nor a variable sets it: the file's value applies.
    let grace = json(&daemon.wait_for("\"setting\":\"limits.session_grace_ms\""));
    assert_eq!(
        (grace["value"].as_str(), grace["source"].as_str()),
        (Some("4321"), Some("file"))
    );
    let linger = json(&daemon.wait_for("\"setting\":\"stream.linger_ms\""));
    assert_eq!(
        (linger["value"].as_str(), linger["source"].as_str()),
        (Some("999"), Some("env"))
    );
    let format = json(&daemon.wait_for("\"setting\":\"log.format\""));
    assert_eq!(
        (format["value"].as_str(), format["source"].as_str()),
        (Some("json"), Some("file"))
    );
    let ready = json(&daemon.wait_for("\"event\":\"ready\""));
    assert_eq!(ready["socket"], socket);
    assert_eq!(ready["max_streams"], 7);
    assert_eq!(ready["linger_ms"], 999);
    let (code, _) = daemon.terminate();
    assert_eq!(code, Some(0));
}

#[test]
fn text_logs_and_rust_log_override_the_level() {
    let dir = socket_dir("text");
    let socket = dir.join("lotse.sock");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "127.0.0.1:0",
            "--socket",
            socket.to_str().expect("utf-8"),
            "--sandbox",
            "off",
            "--log-format",
            "text",
            "--log-level",
            "error",
        ],
        &[("RUST_LOG", "info")],
    );
    // `error` alone would hide the ready line; RUST_LOG=info wins.
    let ready = daemon.wait_for("supervisor ready");
    assert!(!ready.starts_with('{'), "text, not JSON: {ready}");
    assert!(ready.contains("INFO"), "{ready}");
    let (code, _) = daemon.terminate();
    assert_eq!(code, Some(0));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn sandbox_require_refuses_to_start_off_linux() {
    let dir = socket_dir("require");
    let output = lotse()
        .args([
            "serve",
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "127.0.0.1:0",
            "--socket",
            dir.join("lotse.sock").to_str().expect("utf-8"),
            "--sandbox",
            "require",
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("require"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_on_lets_the_supervisor_run_under_its_profile() {
    let dir = socket_dir("sandboxed");
    let socket = dir.join("lotse.sock");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "127.0.0.1:0",
            "--socket",
            socket.to_str().expect("utf-8"),
            "--sandbox",
            "on",
        ],
        &[],
    );
    let applied = json(&daemon.wait_for("sandbox applied"));
    assert!(applied["no_new_privs"].as_bool().unwrap_or(false));
    daemon.wait_for("\"event\":\"ready\"");
    let (code, _) = daemon.terminate();
    assert_eq!(code, Some(0));
}
