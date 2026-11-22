//! Runs the built `rocko` binary as a subprocess, the only way to cover
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

use common::{Daemon, json, rocko, socket_dir};

#[test]
fn help_and_version_print_and_exit_zero() {
    let output = rocko().arg("--help").output().expect("runs");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("serve"), "{help}");
    let output = rocko().args(["serve", "--help"]).output().expect("runs");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("ROCKO_SOCKET"), "{help}");
    assert!(help.contains("--sandbox"), "{help}");
    let output = rocko().arg("--version").output().expect("runs");
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("rocko "));
}

#[test]
fn usage_errors_exit_two_and_config_errors_exit_one() {
    let output = rocko().output().expect("runs");
    assert_eq!(output.status.code(), Some(2), "no subcommand");
    let output = rocko()
        .args(["serve", "--socket", "/x", "--no-such-flag"])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(2), "an unknown flag");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--no-such-flag"));

    let output = rocko().arg("serve").output().expect("runs");
    assert_eq!(output.status.code(), Some(1), "no socket");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rocko failed"), "{stderr}");
    assert!(stderr.contains("--socket"), "{stderr}");
    assert!(output.stdout.is_empty(), "nothing on stdout");
}

#[test]
fn serve_logs_its_config_reports_ready_and_stops_on_sigterm() {
    let dir = socket_dir("ready");
    let socket = dir.join("rocko.sock");
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
    let starting = json(&daemon.wait_for("rocko starting"));
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
    assert!(rest.iter().any(|line| line.contains("rocko exited")));
}

#[test]
fn environment_overrides_the_file_and_flags_override_the_environment() {
    let dir = socket_dir("precedence");
    let config = dir.join("rocko.toml");
    std::fs::write(
        &config,
        format!(
            // Ephemeral listeners, so a daemon on the default port does not
            // fail the test.
            "socket = \"{}\"\nsandbox = \"off\"\n[webrtc]\nudp_listen = \"127.0.0.1:0\"\ntcp_listen = \"127.0.0.1:0\"\n[stream]\nlinger_ms = 1234\n[limits]\nmax_streams = 3\nsession_grace_ms = 4321\n[log]\nformat = \"json\"\n",
            dir.join("rocko.sock").display()
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
            ("ROCKO_SOCKET", socket),
            ("ROCKO_LINGER_MS", "999"),
            ("ROCKO_MAX_STREAMS", "5"),
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
    let socket = dir.join("rocko.sock");
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
    let output = rocko()
        .args([
            "serve",
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "127.0.0.1:0",
            "--socket",
            dir.join("rocko.sock").to_str().expect("utf-8"),
            "--sandbox",
            "require",
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("require"), "{stderr}");
}

/// `require` is the default: started with no sandbox setting, the daemon
/// either enforces every layer or refuses to start, naming the layer it
/// lacks and how to choose `on`. Which one depends on the host's kernel
/// (and outside Linux it always refuses), so the test takes the branch the
/// daemon took and checks it.
#[test]
fn sandbox_defaults_to_require_every_layer_or_no_start() {
    let dir = socket_dir("default-sandbox");
    let socket = dir.join("rocko.sock");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "127.0.0.1:0",
            "--socket",
            socket.to_str().expect("utf-8"),
            "--log-format",
            "json",
        ],
        &[],
    );
    let setting = json(&daemon.wait_for("\"setting\":\"sandbox\""));
    assert_eq!(setting["value"], "require");
    assert_eq!(setting["source"], "default");
    let outcome = json(&daemon.wait_for_any(&["sandbox applied", "rocko failed"]));
    if outcome["message"] == "sandbox applied" {
        for layer in ["seccomp", "landlock_fs", "landlock_net"] {
            assert_eq!(outcome[layer], "enforced", "{layer}: {outcome}");
        }
        daemon.wait_for("\"event\":\"ready\"");
        let (code, _) = daemon.terminate();
        assert_eq!(code, Some(0));
    } else {
        let error = outcome["error"].as_str().unwrap_or_default();
        assert!(error.starts_with("sandbox: sandbox layer "), "{outcome}");
        assert!(
            error.contains("is unavailable and the sandbox mode is `require`, the default"),
            "{outcome}"
        );
        assert!(
            error.contains("`--sandbox on`, `ROCKO_SANDBOX=on`"),
            "{outcome}"
        );
        let (code, _) = daemon.exit();
        assert_eq!(code, Some(1));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_on_lets_the_supervisor_run_under_its_profile() {
    let dir = socket_dir("sandboxed");
    let socket = dir.join("rocko.sock");
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

#[test]
fn the_control_tls_listener_starts_with_its_identity_and_identity_prints_its_pin() {
    use std::os::unix::fs::DirBuilderExt as _;

    let dir = socket_dir("control-tls");
    let socket = dir.join("rocko.sock");
    let data = dir.join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let data = data.to_str().expect("utf-8 path");
    let output = rocko()
        .args(["identity", "--data-dir", data])
        .output()
        .expect("runs");
    assert_eq!(
        output.status.code(),
        Some(1),
        "no identity before the first start"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("first start"));

    let client = "ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad";
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
            "--control-listen",
            "127.0.0.1:0",
        ],
        &[("ROCKO_CONTROL_CLIENTS", client), ("ROCKO_DATA_DIR", data)],
    );
    let created = json(&daemon.wait_for("control identity generated"));
    let bound = json(&daemon.wait_for("control TLS listener bound"));
    assert_eq!(bound["server_pin"], created["server_pin"]);
    assert_eq!(bound["clients"], 1);
    daemon.wait_for("\"event\":\"ready\"");
    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));

    // The drop target, as `serve` takes it, changes nothing for a start
    // that is not root.
    for user in [None, Some("4242")] {
        let mut identity = rocko();
        identity.arg("identity").env("ROCKO_DATA_DIR", data);
        if let Some(user) = user {
            identity.env("ROCKO_USER", user);
        }
        let output = identity.output().expect("runs");
        assert!(output.status.success(), "{user:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            bound["server_pin"].as_str().unwrap()
        );
    }
}

/// An identity an older daemon made, without the DNS name: `--certificate`
/// prints it and says what to do, `--reissue` replaces the certificate
/// from the same key, and the pin changes.
#[test]
fn identity_prints_the_certificate_rfc7468_5_and_reissues_it_naming_rocko_rfc5280_4_2_1_6() {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let dir = socket_dir("identity-reissue");
    let data = dir.join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let identity = |args: &[&str]| {
        rocko()
            .arg("identity")
            .args(args)
            .env("ROCKO_DATA_DIR", &data)
            .output()
            .expect("runs")
    };
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let missing = identity(&["--reissue"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(text(&missing.stderr).contains("reissuing the control identity"));

    let legacy = rocko_testing::control_tls::legacy_server_identity_pem().unwrap();
    let file = data.join("control-identity.pem");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .unwrap()
        .write_all(legacy.as_bytes())
        .unwrap();
    let old_pin = text(&identity(&[]).stdout).trim().to_owned();
    let old = identity(&["--certificate"]);
    assert!(old.status.success());
    let old_pem = text(&old.stdout);
    assert!(
        old_pem.starts_with("-----BEGIN CERTIFICATE-----\n"),
        "{old_pem}"
    );
    assert!(
        old_pem.ends_with("-----END CERTIFICATE-----\n"),
        "{old_pem}"
    );
    assert!(!old_pem.contains("PRIVATE"), "never the key");
    assert!(legacy.ends_with(&old_pem), "the certificate as it is");
    assert!(text(&old.stderr).contains("rocko identity --reissue"));

    let both = identity(&["--certificate", "--reissue"]);
    assert_eq!(both.status.code(), Some(2), "the flags exclude each other");
    assert_eq!(text(&identity(&[]).stdout).trim(), old_pin, "untouched");

    let reissued = identity(&["--reissue"]);
    assert!(reissued.status.success(), "{reissued:?}");
    let new_pin = text(&reissued.stdout).trim().to_owned();
    assert_ne!(new_pin, old_pin);
    assert!(text(&reissued.stderr).contains("every client must pair again"));
    assert_eq!(text(&identity(&[]).stdout).trim(), new_pin);
    let new = identity(&["--certificate"]);
    assert!(new.status.success());
    assert_ne!(text(&new.stdout), old_pem);
    assert!(
        new.stderr.is_empty(),
        "it names rocko: {}",
        text(&new.stderr)
    );
    let key = |pem: &str| pem[..pem.find("-----BEGIN CERTIFICATE").unwrap()].to_owned();
    assert_eq!(
        key(&std::fs::read_to_string(&file).unwrap()),
        key(&legacy),
        "the same key"
    );
}

#[test]
fn without_a_client_the_daemon_logs_a_first_code_and_pair_prints_a_new_one() {
    use std::os::unix::fs::DirBuilderExt as _;

    let dir = socket_dir("pair");
    let socket = dir.join("rocko.sock");
    let socket = socket.to_str().expect("utf-8 path");
    let data = dir.join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let data = data.to_str().expect("utf-8 path");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            socket,
            "--sandbox",
            "off",
            "--control-listen",
            "127.0.0.1:0",
            "--data-dir",
            data,
        ],
        &[],
    );
    let bound = json(&daemon.wait_for("control TLS listener bound"));
    let pin = bound["server_pin"].as_str().unwrap().replace(':', "");
    let first = json(&daemon.wait_for("pairing code for the first client"));
    let first = first["code"].as_str().unwrap().to_owned();
    assert!(first.starts_with(&format!("ROCKO1-{pin}-")), "{first}");

    let output = rocko()
        .args(["pair", "--socket", socket])
        .output()
        .expect("runs");
    assert!(output.status.success(), "{output:?}");
    let code = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(code.starts_with(&format!("ROCKO1-{pin}-")), "{code}");
    assert_ne!(code, first, "a new code replaces the first");
    daemon.wait_for("pairing code issued");
    let (exit, rest) = daemon.terminate();
    assert_eq!(exit, Some(0), "clean exit\n{}", rest.join("\n"));
    assert!(
        rest.iter().all(|line| !line.contains(&code)),
        "the issued code is never logged"
    );
}

#[test]
fn pair_without_a_control_tls_listener_fails() {
    let dir = socket_dir("pair-off");
    let socket = dir.join("rocko.sock");
    let socket = socket.to_str().expect("utf-8 path");
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            socket,
            "--sandbox",
            "off",
        ],
        &[],
    );
    daemon.wait_for("\"event\":\"ready\"");
    let output = rocko()
        .args(["pair", "--socket", socket])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(printed.contains("invalid_request"), "{printed}");
    let (exit, _rest) = daemon.terminate();
    assert_eq!(exit, Some(0));
}

#[test]
fn ctl_clients_lists_the_pins_adds_a_metrics_pin_and_removes_an_enrolled_one_for_good() {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

    let dir = socket_dir("clients");
    let socket = dir.join("rocko.sock");
    let socket = socket.to_str().expect("utf-8 path");
    let data = dir.join("data");
    let mut private = std::fs::DirBuilder::new();
    private.mode(0o700);
    private.create(&data).unwrap();
    private.create(data.join("clients")).unwrap();
    let pins = data.join("clients").join("pins");
    let fixed = "ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad";
    let enrolled = ["11"; 32].join(":");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pins)
        .unwrap();
    writeln!(file, "{enrolled}").unwrap();
    drop(file);
    // Owned by the uid the daemon runs as: root drops to nobody.
    let meta = std::fs::metadata(&data).unwrap();
    let owner = if meta.uid() == 0 {
        (65534, 65534)
    } else {
        (meta.uid(), meta.gid())
    };
    for path in [data.join("clients"), pins.clone()] {
        std::os::unix::fs::chown(path, Some(owner.0), Some(owner.1)).unwrap();
    }
    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            socket,
            "--sandbox",
            "off",
            "--control-listen",
            "127.0.0.1:0",
            "--data-dir",
            data.to_str().expect("utf-8 path"),
        ],
        &[("ROCKO_CONTROL_CLIENTS", fixed)],
    );
    daemon.wait_for("\"event\":\"ready\"");
    let ctl = |args: &[&str]| {
        rocko()
            .args(["ctl", "--socket", socket, "--compact", "clients"])
            .args(args)
            .output()
            .expect("runs")
    };
    let printed = |output: &std::process::Output| -> serde_json::Value {
        serde_json::from_slice(&output.stdout).expect("JSON on stdout")
    };

    let output = ctl(&["list"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        printed(&output),
        serde_json::json!({ "clients": [
            { "pin": enrolled, "fixed": false, "role": "control", "connected": false },
            { "pin": fixed, "fixed": true, "role": "control", "connected": false },
        ] })
    );
    let output = ctl(&["remove", fixed]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(printed(&output)["error"]["code"], "not_permitted");
    let output = ctl(&["remove", &"11".repeat(32)]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(printed(&output), serde_json::json!({}));
    daemon.wait_for("control client removed");
    let output = ctl(&["list"]);
    assert_eq!(
        printed(&output)["clients"],
        serde_json::json!([{ "pin": fixed, "fixed": true, "role": "control", "connected": false }])
    );
    // A scraper's pin, as `openssl x509 -fingerprint -sha256` prints it:
    // enrolled as `metrics` on the socket, no restart.
    let scraper = ["AB"; 32].join(":");
    let output = ctl(&["add", &scraper, "metrics"]);
    assert!(output.status.success(), "{output:?}");
    daemon.wait_for("control client added");
    let output = ctl(&["add", fixed, "metrics"]);
    assert_eq!(printed(&output)["error"]["details"]["role"], "control");
    let output = ctl(&["add", &scraper, "admin"]);
    assert_eq!(printed(&output)["error"]["code"], "invalid_request");
    let output = ctl(&["list"]);
    assert_eq!(
        printed(&output)["clients"][0],
        serde_json::json!({ "pin": scraper.to_lowercase(), "fixed": false, "role": "metrics", "connected": false })
    );
    let (exit, rest) = daemon.terminate();
    assert_eq!(exit, Some(0), "clean exit\n{}", rest.join("\n"));
    assert_eq!(
        std::fs::read_to_string(&pins).unwrap(),
        format!("{} metrics\n", scraper.to_lowercase())
    );
}

#[test]
fn a_pin_in_both_client_lists_stops_the_start() {
    use std::os::unix::fs::DirBuilderExt as _;

    let dir = socket_dir("both-roles");
    let socket = dir.join("rocko.sock");
    let data = dir.join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let pin = ["ab"; 32].join(":");
    let output = rocko()
        .args([
            "serve",
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            socket.to_str().expect("utf-8 path"),
            "--sandbox",
            "off",
            "--control-listen",
            "127.0.0.1:0",
            "--data-dir",
            data.to_str().expect("utf-8 path"),
            "--control-clients",
            &pin,
            "--metrics-clients",
            &pin,
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("is configured both as a control and as a metrics client"),
        "{output:?}"
    );
}
