//! `lotse-browser`: the camera and the page of the browser test
//! ([`lotse_testing::browser`]), for the Selenium test in `tests/browser/`.
//! Starts the synthetic camera (ffmpeg publishing to MediaMTX, both from
//! `PATH`) and the dev viewer relaying to a running `lotse serve`, prints
//! one JSON line on stdout once both run ([`browser::Ready`]: the page's
//! URL, the camera's, the stream the camera sends), runs the commands it
//! reads on stdin, one a line, answering each with one JSON line
//! ([`browser::Served::command`]: `restart-camera`), and stops both when
//! stdin ends. Exits 2 when they could not start.
//!
//! An example of the dev-only `lotse-testing` crate, never part of a
//! release. `mise run browser` builds it, and the test's fixture starts it:
//!
//! ```text
//! cargo run --release -p lotse-testing --example lotse-browser -- --socket /tmp/lotse/lotse.sock
//! ```

use std::io::{self, BufRead as _, Write as _};
use std::process::ExitCode;
use std::sync::Arc;

use lotse_core::clock::SystemClock;
use lotse_testing::browser;

#[expect(
    clippy::print_stderr,
    reason = "a development tool's output: errors on stderr"
)]
fn main() -> ExitCode {
    let config = match browser::args::parse(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("lotse-browser: {err}\n{}", browser::args::USAGE);
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("lotse-browser: runtime: {err}");
            return ExitCode::from(2);
        }
    };
    let mut served = match runtime.block_on(browser::Served::start(&config, Arc::new(SystemClock)))
    {
        Ok(served) => served,
        Err(err) => {
            eprintln!("lotse-browser: {err}");
            return ExitCode::from(2);
        }
    };
    let line = match serde_json::to_string(served.ready()) {
        Ok(line) => line,
        Err(err) => {
            eprintln!("lotse-browser: {err}");
            return ExitCode::from(2);
        }
    };
    let mut stdout = io::stdout().lock();
    if let Err(err) = writeln!(stdout, "{line}").and_then(|()| stdout.flush()) {
        eprintln!("lotse-browser: stdout: {err}");
        return ExitCode::from(2);
    }
    // The runtime's workers serve the page meanwhile; stdin ends when the
    // test closes it or exits.
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let answer = runtime.block_on(served.command(&line, Arc::new(SystemClock)));
        if let Err(err) = writeln!(stdout, "{answer}").and_then(|()| stdout.flush()) {
            eprintln!("lotse-browser: stdout: {err}");
            break;
        }
    }
    served.stop();
    ExitCode::SUCCESS
}
