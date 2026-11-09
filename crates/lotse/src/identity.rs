//! `lotse identity`: prints the pin of the control TLS listener's
//! certificate, the SHA-256 a client checks before it trusts the daemon, read
//! from the data directory without a running daemon.

#![expect(
    clippy::print_stdout,
    reason = "the pin on stdout is the command's output, like `lotse ctl`'s JSON"
)]

use std::process::ExitCode;

use anyhow::Context as _;
use lotse_supervisor::{Owners, ServerIdentity};

use crate::cli::IdentityArgs;

/// Reads the identity in `args.data_dir` as the uid this runs as, and
/// prints its pin. The directory and the identity must belong to this uid
/// or, run as root, to the uid `serve` drops to (`args.user`): the owners
/// a start of the daemon as this uid accepts.
pub(crate) fn run(args: &IdentityArgs) -> anyhow::Result<ExitCode> {
    let owners = Owners {
        starting: rustix::process::getuid().as_raw(),
        drop_to: args.user.unwrap_or(lotse_sandbox::DEFAULT_UID),
    };
    let identity = ServerIdentity::load(&args.data_dir, owners).context("control identity")?;
    println!("{}", identity.pin());
    Ok(ExitCode::SUCCESS)
}
