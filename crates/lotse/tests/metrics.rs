//! A real Prometheus scrapes `GET /v0/metrics` of a real `lotse serve`
//! over the control listener's mutual TLS, as the README's "Metrics with
//! Prometheus" sets it up: openssl makes the scraper's P-256 key and
//! self-signed certificate, the daemon gets only its pin, as a `metrics`
//! client (`--metrics-clients`, the fingerprint as openssl prints it), and
//! Prometheus trusts the daemon's certificate (`lotse identity
//! --certificate`) as its CA file with `server_name: lotse`. So the Go TLS
//! path is a third party's: the DNS name in the server certificate (Go's
//! x509 refuses a Common Name alone), the leaf as its own root, TLS 1.3
//! with the client certificate (RFC 8446 §4.4.2), and the exposition as
//! Prometheus parses it, in both formats the daemon offers: one job with
//! Prometheus' default scrape protocols, which negotiate OpenMetrics 1.0.0,
//! and one limited to the Prometheus text format 0.0.4. Which one each job
//! parsed shows in Prometheus' target metadata: only OpenMetrics carries a
//! metric's unit. A third job presents a certificate the daemon never
//! enrolled, and its scrapes fail.
//!
//! Ignored by default: it needs `prometheus` and `openssl` on `PATH`,
//! which `mise run interop` provides (Prometheus pinned in `mise.toml`)
//! before it runs it.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

mod common;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::{Daemon, json, lotse, socket_dir};
use serde_json::Value;

/// How long Prometheus may take to report both targets' first scrapes.
const SCRAPED_WITHIN: Duration = Duration::from_secs(60);

/// How often its API is asked meanwhile.
const POLL: Duration = Duration::from_millis(500);

/// `program` with `args`, which must succeed; its stdout.
#[expect(
    clippy::disallowed_methods,
    reason = "the test runs third-party tools, as the interop tests run MediaMTX and ffmpeg"
)]
fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|err| panic!("{program} runs: {err}"));
    assert!(output.status.success(), "{program} {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// A P-256 key and a self-signed certificate made by openssl in `dir` as
/// `<name>.key` and `<name>.pem`, as the README has the Prometheus host
/// make them, and the certificate's SHA-256 fingerprint as openssl prints
/// it (`AB:CD:...`).
fn openssl_client(dir: &Path, name: &str) -> String {
    let key = dir.join(format!("{name}.key"));
    let pem = dir.join(format!("{name}.pem"));
    run(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            pem.to_str().unwrap(),
            "-days",
            "36500",
            "-subj",
            &format!("/CN={name}"),
        ],
    );
    let printed = run(
        "openssl",
        &[
            "x509",
            "-in",
            pem.to_str().unwrap(),
            "-noout",
            "-fingerprint",
            "-sha256",
        ],
    );
    // `sha256 Fingerprint=AB:CD:...` (OpenSSL 3; `SHA256 Fingerprint=` before).
    printed
        .trim()
        .split_once('=')
        .map(|(_, pin)| pin.to_owned())
        .unwrap()
}

/// A port free on the loopback right now, for Prometheus' own web listener.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `GET path` of Prometheus' HTTP API on `port`, as JSON; `None` while it
/// does not answer yet.
fn api(port: u16, path: &str) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer).ok()?;
    let (_, body) = answer.split_once("\r\n\r\n")?;
    serde_json::from_str(body).ok()
}

/// Waits `POLL` of real time.
#[expect(
    clippy::disallowed_methods,
    reason = "the test waits on a third-party process in real time"
)]
fn pause() {
    std::thread::sleep(POLL);
}

/// Prometheus, killed when dropped.
struct Prometheus(Child);

impl Drop for Prometheus {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _reaped = self.0.wait();
    }
}

/// Starts Prometheus with `config` in `dir`, its API on `port`.
#[expect(
    clippy::disallowed_methods,
    reason = "the test runs a third-party tool, as the interop tests run MediaMTX"
)]
fn prometheus(dir: &Path, config: &Path, port: u16) -> Prometheus {
    let child = Command::new("prometheus")
        .args([
            &format!("--config.file={}", config.display()),
            &format!("--storage.tsdb.path={}", dir.join("tsdb").display()),
            &format!("--web.listen-address=127.0.0.1:{port}"),
            "--log.level=warn",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("prometheus runs: is it on PATH (`mise run interop`)?");
    Prometheus(child)
}

/// The active target of `job` in Prometheus' `/api/v1/targets`, once it
/// has been scraped (`health` no longer `unknown`).
fn scraped(targets: &Value, job: &str) -> Option<Value> {
    targets["data"]["activeTargets"]
        .as_array()?
        .iter()
        .find(|target| target["labels"]["job"] == job && target["health"] != "unknown")
        .cloned()
}

#[test]
#[ignore = "needs prometheus and openssl on PATH: `mise run interop`"]
fn prometheus_scrapes_the_metrics_over_mutual_tls_with_an_openssl_p256_client_rfc8446_4_4_2() {
    use std::os::unix::fs::DirBuilderExt as _;

    let dir = socket_dir("prometheus");
    let host = dir.join("prometheus");
    std::fs::create_dir(&host).unwrap();
    let data = dir.join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let data_text = data.to_str().unwrap();
    // On the Prometheus host: the key never leaves it, lotse gets the pin.
    let pin = openssl_client(&host, "scraper");
    let _unenrolled = openssl_client(&host, "stranger");

    let mut daemon = Daemon::start(
        &[
            "--webrtc-udp-listen",
            "127.0.0.1:0",
            "--webrtc-tcp-listen",
            "off",
            "--socket",
            dir.join("lotse.sock").to_str().unwrap(),
            "--sandbox",
            "off",
            "--control-listen",
            "127.0.0.1:0",
            "--data-dir",
            data_text,
        ],
        &[("LOTSE_METRICS_CLIENTS", &pin)],
    );
    let bound = json(&daemon.wait_for("control TLS listener bound"));
    assert_eq!(bound["metrics_clients"], 1);
    assert_eq!(bound["names_server"], true);
    let addr: SocketAddr = bound["addr"].as_str().unwrap().parse().unwrap();
    daemon.wait_for("\"event\":\"ready\"");
    let output = lotse()
        .args(["identity", "--certificate", "--data-dir", data_text])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let server = host.join("lotse-server.pem");
    std::fs::write(&server, &output.stdout).unwrap();

    let job = |name: &str, client: &str, protocols: &str| {
        format!(
            "  - job_name: {name}\n{protocols}    scheme: https\n    metrics_path: /v0/metrics\n    static_configs: [{{ targets: [\"{addr}\"] }}]\n    tls_config:\n      ca_file: {}\n      server_name: lotse\n      cert_file: {}\n      key_file: {}\n",
            server.display(),
            host.join(format!("{client}.pem")).display(),
            host.join(format!("{client}.key")).display(),
        )
    };
    let config = host.join("prometheus.yml");
    std::fs::write(
        &config,
        format!(
            "global:\n  scrape_interval: 1s\n  scrape_timeout: 1s\nscrape_configs:\n{}{}{}",
            job("lotse", "scraper", ""),
            job(
                "lotse_text",
                "scraper",
                "    scrape_protocols: [PrometheusText0.0.4]\n"
            ),
            job("unenrolled", "stranger", ""),
        ),
    )
    .unwrap();
    let port = free_port();
    let _prometheus = prometheus(&host, &config, port);

    let polls = SCRAPED_WITHIN.as_millis() / POLL.as_millis();
    let mut all = None;
    for _ in 0..polls {
        if let Some(targets) = api(port, "/api/v1/targets")
            && let (Some(lotse), Some(text), Some(unenrolled)) = (
                scraped(&targets, "lotse"),
                scraped(&targets, "lotse_text"),
                scraped(&targets, "unenrolled"),
            )
        {
            all = Some((lotse, text, unenrolled));
            break;
        }
        pause();
    }
    let (scraped_lotse, scraped_text, unenrolled) =
        all.expect("Prometheus scraped every target in time");
    for target in [&scraped_lotse, &scraped_text] {
        assert_eq!(target["health"], "up", "{target}");
        assert_eq!(target["lastError"], "", "{target}");
    }
    // Refused in the handshake: no certificate the daemon knows.
    assert_eq!(unenrolled["health"], "down", "{unenrolled}");
    assert_ne!(unenrolled["lastError"], "", "{unenrolled}");
    daemon.wait_for("control TLS handshake refused: client certificate not allowed");

    // The samples arrived as Prometheus parsed them.
    let mut uptime = None;
    for _ in 0..polls {
        let answer = api(
            port,
            "/api/v1/query?query=lotse_supervisor_uptime_seconds%7Bjob%3D%22lotse%22%7D",
        );
        if let Some(result) = answer
            .as_ref()
            .and_then(|answer| answer["data"]["result"].as_array())
            .filter(|result| !result.is_empty())
        {
            uptime = Some(result[0]["value"][1].as_str().unwrap().to_owned());
            break;
        }
        pause();
    }
    let uptime: f64 = uptime.expect("the uptime sample").parse().unwrap();
    assert!(uptime > 0.0, "{uptime}");
    let streams = api(port, "/api/v1/query?query=lotse_streams").unwrap();
    for series in streams["data"]["result"].as_array().unwrap() {
        assert_eq!(series["value"][1], "0", "{streams}");
    }
    // OpenMetrics' `# UNIT` reached the default job, the text format has
    // none: each job parsed the format it negotiated.
    let unit_of = |job: &str| {
        let metadata = api(
            port,
            &format!(
                "/api/v1/targets/metadata?metric=lotse_supervisor_uptime_seconds&match_target=%7Bjob%3D%22{job}%22%7D"
            ),
        )
        .unwrap();
        metadata["data"][0]["unit"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(unit_of("lotse"), "seconds", "OpenMetrics 1.0.0");
    assert_eq!(
        unit_of("lotse_text"),
        "",
        "the Prometheus text format 0.0.4"
    );

    let (code, rest) = daemon.terminate();
    assert_eq!(code, Some(0), "clean exit\n{}", rest.join("\n"));
}
