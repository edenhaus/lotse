//! `rocko-load`: the load generator and soak against a running
//! `rocko serve` ([`rocko_testing::load`]). Prints the verdict on stderr
//! and the JSON report on stdout or to `--report`; exits 1 when a check
//! failed, 2 when the run could not start.
//!
//! An example of the dev-only `rocko-testing` crate, so it can install
//! `rocko-webrtc`'s crypto provider for its viewers (a dev-dependency here)
//! and is never part of a release. `mise run load` and `mise run soak`
//! start a release daemon and run it:
//!
//! ```text
//! cargo run --release -p rocko-testing --example rocko-load -- --socket /tmp/rocko/rocko.sock --cameras 2 --viewers 5 --duration 60s
//! ```

use std::process::ExitCode;
use std::sync::Arc;

use rocko_core::clock::SystemClock;
use rocko_testing::load;

#[expect(
    clippy::print_stderr,
    clippy::print_stdout,
    reason = "a development tool's output: the verdict on stderr, the JSON report on stdout"
)]
fn main() -> ExitCode {
    let args = match load::args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("rocko-load: {err}\n{}", load::args::USAGE);
            return ExitCode::from(2);
        }
    };
    rocko_webrtc::install_crypto_provider();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("rocko-load: runtime: {err}");
            return ExitCode::from(2);
        }
    };
    let report = match runtime.block_on(load::run(&args.config, Arc::new(SystemClock))) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("rocko-load: {err}");
            return ExitCode::from(2);
        }
    };
    eprint!("{}", report.summary());
    let json = match serde_json::to_string_pretty(&report) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("rocko-load: the report: {err}");
            return ExitCode::from(2);
        }
    };
    match &args.report {
        Some(path) => {
            if let Err(err) = std::fs::write(path, json) {
                eprintln!("rocko-load: {}: {err}", path.display());
                return ExitCode::from(2);
            }
        }
        None => println!("{json}"),
    }
    if report.failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
