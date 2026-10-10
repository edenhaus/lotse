//! lotse: a small, fast, memory-safe media daemon.
//!
//! One binary, three process kinds (`serve`, `worker`, `decode`) plus the
//! `ctl` client, dispatched from the command line. The binary is the only
//! place that names concrete sources, outputs and transcoders: it registers
//! the ones its Cargo features enable and hands the registries to
//! `lotse-supervisor` or `lotse-worker`. It also reads the configuration
//! once and applies the sandbox before any runtime starts. `anyhow` lives
//! here and nowhere else.

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context as _;
use clap::{ArgMatches, CommandFactory as _, FromArgMatches as _};
use lotse_api_types::info::{BuildInfo, LandlockInfo, SandboxInfo};
use lotse_codec::transcode::AacToOpus;
use lotse_core::clock::SystemClock;
use lotse_core::registry::Registries;
use lotse_core::runner::RunnerConfig;
use lotse_core::track::TrackLimits;
use lotse_sandbox::{Profile, SandboxConfig, SandboxReport};
use lotse_supervisor::worker::WorkerConfig;
use lotse_supervisor::{Environment, Identity};

use crate::cli::{Cli, Command, ServeArgs, WorkerArgs};

mod cli;
mod config;
mod ctl;
mod logging;

/// Parses the command line and dispatches. Exit code 0 on a clean stop, 1
/// on an error (logged), 2 on a usage error (printed by clap).
fn main() -> ExitCode {
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    };
    match dispatch(&cli, &matches) {
        Ok(code) => code,
        Err(err) => {
            logging::ensure_fallback();
            tracing::error!(error = format!("{err:#}"), "lotse failed");
            ExitCode::FAILURE
        }
    }
}

/// Runs the chosen subcommand.
fn dispatch(cli: &Cli, matches: &ArgMatches) -> anyhow::Result<ExitCode> {
    match &cli.command {
        Command::Serve(args) => {
            let serve_matches = matches
                .subcommand_matches("serve")
                .context("serve arguments")?;
            serve(args, serve_matches)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Worker(args) => {
            worker(args)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Ctl(args) => ctl::run(args),
    }
}

/// The sources, outputs and transcoders this build carries: the only place
/// that names a concrete one. Sources and outputs sit behind their Cargo
/// feature; the transcoders are always there. `relay` is a worker's
/// pre-bound loopback listener for the `rtsps` relay.
fn registries(relay: Option<std::net::TcpListener>) -> Registries {
    let mut registries = Registries::default();
    // AAC-LC → Opus: pure computation on the side branch, in every build.
    registries
        .transcoders
        .register(Arc::new(AacToOpus::new(Arc::new(SystemClock))));
    #[cfg(feature = "output-webrtc")]
    registered(
        "webrtc output",
        registries
            .outputs
            .register(Arc::new(lotse_webrtc::WebRtcFactory)),
    );
    #[cfg(feature = "source-rtsp")]
    registered(
        "rtsp source",
        registries
            .sources
            .register(Arc::new(lotse_rtsp::RtspFactory::new(relay))),
    );
    #[cfg(not(feature = "source-rtsp"))]
    drop(relay);
    #[cfg(feature = "source-http")]
    registered(
        "http source",
        registries
            .sources
            .register(Arc::new(lotse_http::HttpFactory)),
    );
    #[cfg(feature = "source-fake")]
    registered(
        "fake source",
        registries
            .sources
            .register(Arc::new(lotse_core::test_util::FakeSourceFactory::new(&[
                "fake",
            ]))),
    );
    registries
}

/// Logs a registration [`registries`] could not make: the daemon runs on
/// without `what`, which its `info` then does not list.
#[cfg(any(
    feature = "output-webrtc",
    feature = "source-rtsp",
    feature = "source-http",
    feature = "source-fake"
))]
fn registered(what: &str, outcome: Result<(), lotse_core::registry::RegistryError>) {
    if let Err(err) = outcome {
        tracing::error!(error = %err, "{what} not registered");
    }
}

/// The worker process: logging from its flags, the panic hook, the worker
/// sandbox, then the runtime on the channel it inherited as stdin.
fn worker(args: &WorkerArgs) -> anyhow::Result<()> {
    logging::init(args.log_format, &args.log_level).context("logging")?;
    let _process =
        tracing::info_span!("process", kind = "worker", pid = std::process::id()).entered();
    logging::install_panic_hook();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "worker starting");
    let sandbox = SandboxConfig {
        mode: args.sandbox,
        uid: lotse_sandbox::DEFAULT_UID,
        gid: lotse_sandbox::DEFAULT_GID,
        worker_address_space: args.worker_address_space,
    };
    // The relay listener is bound before the sandbox: Landlock allows
    // `bind` and `connect` only on the ports it is given now. Until then the
    // supervisor's inherited domain applies, which allows `bind` to port 0.
    let relay = args
        .loopback_relay
        .then(|| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)))
        .transpose()
        .context("loopback relay")?;
    let mut connect_ports = args.connect_ports.clone();
    if let Some(listener) = &relay {
        let port = listener.local_addr().context("loopback relay")?.port();
        tracing::info!(port, "loopback relay bound");
        connect_ports.push(port);
    }
    // The supervisor reads the worker's memory through this descriptor:
    // once the worker is not dumpable, its `/proc` entries are closed to
    // the supervisor. There is no `/proc` on macOS.
    let memory = std::fs::File::open("/proc/self/smaps_rollup")
        .ok()
        .map(std::os::fd::OwnedFd::from);
    let profile = Profile::Worker { connect_ports };
    let _report = lotse_sandbox::apply(&profile, &sandbox).context("sandbox")?;
    let settings = lotse_worker::Settings {
        worker_threads: args.worker_threads,
        limits: TrackLimits::default(),
        runner: RunnerConfig::default(),
        session: lotse_core::session::SessionLimits::default(),
        max_sessions: args.max_sessions,
        // The filter keeps the shared socket to sending at this number; the
        // control channel stays on standard input, `WORKER_CONTROL_FD`.
        shared_udp_fd: Some(lotse_sandbox::WORKER_SHARED_UDP_FD),
    };
    let reason = lotse_worker::run(&settings, registries(relay), memory).context("worker")?;
    tracing::info!(reason = ?reason, "worker exited");
    Ok(())
}

/// The supervisor process, in the documented startup order: configuration,
/// logging, panic hook, the control socket, sandbox, runtime.
fn serve(args: &ServeArgs, matches: &ArgMatches) -> anyhow::Result<()> {
    let (settings, provenance) = config::load(args, matches).context("configuration")?;
    logging::init(settings.log.format, &settings.log.level).context("logging")?;
    let _process =
        tracing::info_span!("process", kind = "supervisor", pid = std::process::id()).entered();
    logging::install_panic_hook();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "lotse starting");
    config::log_effective(&provenance, &settings.log);

    let listeners = lotse_supervisor::bind(&settings.supervisor).context("sockets")?;
    let binary = std::env::current_exe().context("own executable path")?;
    let profile = Profile::Supervisor {
        binary: binary.clone(),
    };
    let report = lotse_sandbox::apply(&profile, &settings.sandbox).context("sandbox")?;

    let limits = &settings.supervisor.limits;
    let environment = Environment {
        registries: registries(None),
        worker: WorkerConfig {
            binary,
            log_format: settings.log.format.name().to_owned(),
            // The effective filter, `RUST_LOG` included: workers start
            // with an empty environment and log exactly as the supervisor.
            log_level: settings.log.level.clone(),
            sandbox: settings.sandbox.mode.name().to_owned(),
            worker_threads: limits.worker_threads,
            worker_address_space: limits.worker_address_space,
            max_sessions: limits.max_sessions,
        },
        udp: None,
        front_door: None,
        identity: Identity {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            build: BuildInfo {
                target: env!("LOTSE_TARGET").to_owned(),
                git_sha: option_env!("LOTSE_GIT_SHA").map(str::to_owned),
                rustc: env!("LOTSE_RUSTC").to_owned(),
            },
            sandbox: sandbox_info(&report),
        },
    };
    let reason = lotse_supervisor::run(&settings.supervisor, listeners, environment)
        .context("supervisor")?;
    tracing::info!(reason = reason.name(), "lotse exited");
    Ok(())
}

/// The sandbox report as `info.sandbox` shows it.
fn sandbox_info(report: &SandboxReport) -> SandboxInfo {
    SandboxInfo {
        mode: report.mode.name().to_owned(),
        uid: report.uid,
        gid: report.gid,
        no_new_privs: report.no_new_privs,
        seccomp: report.seccomp.name().to_owned(),
        landlock: LandlockInfo {
            fs: report.landlock.fs.name().to_owned(),
            net: report.landlock.net.name().to_owned(),
            abi: report.landlock.abi,
        },
        notes: report.notes.clone(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn the_sandbox_report_maps_onto_the_api_shape() {
        let mut report = SandboxReport::off(65534, 65534);
        report
            .notes
            .push("seccomp: unavailable on this platform".into());
        let info = sandbox_info(&report);
        assert_eq!(
            (info.mode.as_str(), info.uid, info.gid),
            ("off", 65534, 65534)
        );
        assert!(!info.no_new_privs);
        assert_eq!(info.seccomp, "off");
        assert_eq!(
            (
                info.landlock.fs.as_str(),
                info.landlock.net.as_str(),
                info.landlock.abi
            ),
            ("off", "off", 0)
        );
        assert_eq!(info.notes.len(), 1);
        assert!(!env!("LOTSE_TARGET").is_empty());
        assert!(
            env!("LOTSE_RUSTC").starts_with('1'),
            "{}",
            env!("LOTSE_RUSTC")
        );
    }

    #[cfg(any(
        feature = "output-webrtc",
        feature = "source-rtsp",
        feature = "source-fake"
    ))]
    #[test]
    fn a_refused_registration_is_logged_and_an_accepted_one_is_not() {
        use lotse_core::registry::RegistryError;
        let logs = logging::capture_logs(|| {
            registered("fake source", Ok(()));
            registered("fake source", Err(RegistryError::DuplicateScheme("fake")));
        });
        assert_eq!(logs.lines().count(), 1, "{logs}");
        assert!(logs.contains("ERROR"), "{logs}");
        assert!(logs.contains("fake source not registered"), "{logs}");
        assert!(logs.contains("scheme fake is already registered"), "{logs}");
    }
}
