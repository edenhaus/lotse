//! `lotse-dev-viewer`: plays a camera through a running `lotse serve` in a
//! browser, for development and manual smoke tests. Serves one page and
//! relays it to the daemon's control socket
//! ([`lotse_testing::dev_viewer`]).
//!
//! Runs on the daemon's machine, as the daemon's user (the control socket
//! admits no one else). Never part of a release: `lotse-testing` is a
//! dev-only crate.
//!
//! ```text
//! cargo run -p lotse-testing --bin lotse-dev-viewer -- --socket /tmp/lotse/lotse.sock [--listen 127.0.0.1:8080 [--insecure-listen]]
//! ```
//!
//! `--listen` takes a loopback address only, unless `--insecure-listen`
//! is given too: the relay's `Origin` check stops web pages, not other
//! programs, and whoever reaches the relay drives the daemon (any RTSP URL
//! in `stream/put`, every camera's video).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use lotse_testing::dev_viewer;
use tokio_util::sync::CancellationToken;

/// Where the page is served unless `--listen` says otherwise.
const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

/// The flag that allows a `--listen` address other than loopback.
const INSECURE_LISTEN: &str = "--insecure-listen";

/// The usage line.
const USAGE: &str =
    "usage: lotse-dev-viewer --socket PATH [--listen 127.0.0.1:8080 [--insecure-listen]]";

/// The command line.
#[derive(Debug)]
struct Args {
    /// The daemon's control socket.
    socket: PathBuf,
    /// Where the page is served.
    listen: SocketAddr,
}

/// Parses `--socket PATH`, `--listen ADDR` and `--insecure-listen`; a
/// `--listen` address that is not loopback is refused without
/// `--insecure-listen`, since anything on the network that reaches it
/// drives the daemon: the relay's `Origin` check is no authentication
/// (DEV-2, 2026-10-05).
fn parse(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut socket = None;
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut insecure = false;
    let mut args = args.skip(1);
    while let Some(flag) = args.next() {
        if flag == INSECURE_LISTEN {
            insecure = true;
            continue;
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--socket" => socket = Some(PathBuf::from(value)),
            "--listen" => listen = value,
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    let socket = socket.ok_or("--socket is required: the path `lotse serve --socket` was given")?;
    let listen: SocketAddr = listen
        .parse()
        .map_err(|err| format!("--listen {listen}: {err}"))?;
    if !listen.ip().is_loopback() && !insecure {
        return Err(format!(
            "--listen {listen} is not a loopback address: anything that reaches it drives the daemon (any RTSP URL, every camera's video); add {INSECURE_LISTEN} to serve it anyway"
        ));
    }
    Ok(Args { socket, listen })
}

#[expect(
    clippy::print_stderr,
    reason = "a development tool's only output: where to point the browser, or why it cannot"
)]
fn main() -> ExitCode {
    let args = match parse(std::env::args()) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("lotse-dev-viewer: {err}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("lotse-dev-viewer: runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let listener = match tokio::net::TcpListener::bind(args.listen).await {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("lotse-dev-viewer: listening on {}: {err}", args.listen);
                return ExitCode::FAILURE;
            }
        };
        if !args.listen.ip().is_loopback() {
            eprintln!(
                "lotse-dev-viewer: warning ({INSECURE_LISTEN}): {} is reachable from the network, and anything that reaches it drives the daemon",
                args.listen
            );
        }
        eprintln!(
            "lotse-dev-viewer: open http://{}/ (relaying to {})",
            args.listen,
            args.socket.display()
        );
        dev_viewer::serve(listener, args.socket, CancellationToken::new()).await;
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        parse(
            std::iter::once("lotse-dev-viewer")
                .chain(list.iter().copied())
                .map(String::from),
        )
    }

    #[test]
    fn flags_parse_with_a_loopback_default() {
        let parsed = args(&["--socket", "/tmp/l.sock"]).unwrap();
        assert_eq!(parsed.socket, PathBuf::from("/tmp/l.sock"));
        assert_eq!(parsed.listen, DEFAULT_LISTEN.parse().unwrap());
        let parsed = args(&["--listen", "[::1]:9000", "--socket", "/s"]).unwrap();
        assert_eq!(parsed.listen, "[::1]:9000".parse().unwrap());
        assert!(args(&[]).unwrap_err().contains("--socket is required"));
        assert!(args(&["--socket"]).unwrap_err().contains("needs a value"));
        assert!(args(&["--port", "1"]).unwrap_err().contains("unknown flag"));
        assert!(args(&["--socket", "/s", "--listen", "x"]).is_err());
        assert!(USAGE.contains(DEFAULT_LISTEN) && USAGE.contains(INSECURE_LISTEN));
    }

    /// DEV-2 (2026-10-05): the `Origin` check stops web pages, not other
    /// programs on the network, so only loopback is served by default.
    #[test]
    fn a_listen_address_off_loopback_needs_insecure_listen() {
        for addr in [
            "0.0.0.0:9000",
            "[::]:9000",
            "192.168.1.2:8080",
            "[::ffff:127.0.0.1]:8080",
        ] {
            let err = args(&["--socket", "/s", "--listen", addr]).unwrap_err();
            assert!(
                err.contains("is not a loopback address") && err.contains("--insecure-listen"),
                "{addr}: {err}"
            );
            let parsed = args(&["--socket", "/s", "--listen", addr, "--insecure-listen"]).unwrap();
            assert_eq!(parsed.listen, addr.parse().unwrap());
            let parsed = args(&["--insecure-listen", "--listen", addr, "--socket", "/s"]).unwrap();
            assert_eq!(parsed.listen, addr.parse().unwrap(), "in any order");
        }
        // Loopback needs no flag, and the flag changes nothing there.
        for addr in ["127.0.0.1:8080", "127.1.2.3:8080", "[::1]:8080"] {
            let parsed = args(&["--socket", "/s", "--listen", addr]).unwrap();
            assert_eq!(parsed.listen, addr.parse().unwrap());
            let parsed = args(&["--socket", "/s", "--listen", addr, "--insecure-listen"]).unwrap();
            assert_eq!(parsed.listen, addr.parse().unwrap());
        }
        // The flag takes no value: what follows it is the next flag.
        assert!(
            args(&["--insecure-listen", "--socket"])
                .unwrap_err()
                .contains("needs a value")
        );
    }
}
