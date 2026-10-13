//! `lotse identity`: prints the pin of the control TLS listener's
//! certificate, the SHA-256 a client checks before it trusts the daemon, read
//! from the data directory without a running daemon.

#![expect(
    clippy::print_stdout,
    reason = "the pin on stdout is the command's output, like `lotse ctl`'s JSON"
)]

use std::process::ExitCode;

use anyhow::Context as _;
use lotse_supervisor::ServerIdentity;

use crate::cli::IdentityArgs;

/// Reads the identity in `args.data_dir` as the uid this runs as, which
/// must be the daemon's starting uid, and prints its pin.
pub(crate) fn run(args: &IdentityArgs) -> anyhow::Result<ExitCode> {
    let uid = rustix::process::getuid().as_raw();
    let identity = ServerIdentity::load(&args.data_dir, uid).context("control identity")?;
    println!("{}", identity.pin());
    Ok(ExitCode::SUCCESS)
}
