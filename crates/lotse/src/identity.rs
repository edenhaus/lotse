//! `lotse identity`: prints the pin of the control TLS listener's
//! certificate, the SHA-256 a client checks before it trusts the daemon, read
//! from the data directory without a running daemon; with `--certificate`
//! the certificate itself as PEM (RFC 7468 §5), never the key; with
//! `--reissue` makes a new certificate from the same key that names the DNS
//! name `lotse` ([`CONTROL_SERVER_NAME`]) and prints its pin.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the pin or the certificate on stdout is the command's output, like `lotse ctl`'s JSON; what the operator must do next goes to stderr"
)]

use std::process::ExitCode;

use anyhow::Context as _;
use lotse_supervisor::{CONTROL_SERVER_NAME, Owners, ServerIdentity};

use crate::cli::IdentityArgs;

/// Reads the identity in `args.data_dir` as the uid this runs as, and
/// prints its pin, or its certificate, or reissues it and prints the new
/// pin. The directory and the identity must belong to this uid or, run as
/// root, to the uid `serve` drops to (`args.user`): the owners a start of
/// the daemon as this uid accepts.
pub(crate) fn run(args: &IdentityArgs) -> anyhow::Result<ExitCode> {
    let owners = Owners {
        starting: rustix::process::getuid().as_raw(),
        drop_to: args.user.unwrap_or(lotse_sandbox::DEFAULT_UID),
    };
    if args.reissue {
        let reissued = ServerIdentity::reissue(&args.data_dir, owners)
            .context("reissuing the control identity")?;
        println!("{}", reissued.identity.pin());
        eprintln!("lotse: {}", reissued.notice());
        return Ok(ExitCode::SUCCESS);
    }
    let identity = ServerIdentity::load(&args.data_dir, owners).context("control identity")?;
    if !args.certificate {
        println!("{}", identity.pin());
        return Ok(ExitCode::SUCCESS);
    }
    print!("{}", identity.certificate_pem());
    if !identity.names_server() {
        eprintln!(
            "lotse: this certificate names no DNS name, so a client that verifies the daemon by name (Prometheus, any Go program) refuses it; `lotse identity --reissue` makes one that names `{CONTROL_SERVER_NAME}`, after which every client must pair again."
        );
    }
    Ok(ExitCode::SUCCESS)
}
