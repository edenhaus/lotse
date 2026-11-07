//! lotse: a small, fast, memory-safe media daemon.
//!
//! One binary, three process kinds (`serve`, `worker`, `decode`) plus the
//! `ctl` client and the `identity` and `pair` tools, dispatched from the
//! command line. The binary is the only
//! place that names concrete sources, outputs and transcoders: it registers
//! the ones its Cargo features enable and hands the registries to
//! `lotse-supervisor` or `lotse-worker`. It also reads the configuration
//! once and applies the sandbox before any runtime starts. `anyhow` lives
//! here and nowhere else.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::{ArgMatches, CommandFactory as _, FromArgMatches as _};
use lotse_api_types::info::{BuildInfo, LandlockInfo, SandboxInfo};
use lotse_codec::transcode::AacToOpus;
use lotse_codec::transcode::uplink::ToG711Factory;
use lotse_core::clock::SystemClock;
use lotse_core::recording::RecordingPolicy;
use lotse_core::registry::Registries;
use lotse_core::runner::RunnerConfig;
use lotse_core::track::TrackLimits;
use lotse_sandbox::{Profile, SandboxConfig, SandboxReport, StateDir};
use lotse_supervisor::worker::WorkerConfig;
use lotse_supervisor::{Environment, Identity};

use crate::cli::{Cli, Command, ServeArgs, WorkerArgs};

mod cli;
mod config;
mod ctl;
mod identity;
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
        Command::Identity(args) => identity::run(args),
        Command::Pair(args) => ctl::pair(args),
    }
}

/// The sources, outputs and transcoders this build carries: the only place
/// that names a concrete one. Sources and outputs sit behind their Cargo
/// feature; the transcoders are always there.
fn registries() -> Registries {
    let mut registries = Registries::default();
    // AAC-LC → Opus: pure computation on the side branch, in every build.
    registries
        .transcoders
        .register(Arc::new(AacToOpus::new(Arc::new(SystemClock))));
    // Talk-back to the camera's G.711, framed per backchannel: apart from
    // the downlink list, so no viewer is offered it.
    registries.uplink = Some(Arc::new(ToG711Factory::new(Arc::new(SystemClock))));
    #[cfg(feature = "output-webrtc")]
    registered(
        "webrtc output",
        registries
            .outputs
            .register(Arc::new(lotse_webrtc::WebRtcFactory)),
    );
    // The event recordings' container: fragmented MP4.
    #[cfg(feature = "output-recording")]
    {
        registries.recording = Some(Arc::new(lotse_mux::Factory));
    }
    #[cfg(feature = "source-rtsp")]
    registered(
        "rtsp source",
        registries
            .sources
            .register(Arc::new(lotse_rtsp::RtspFactory)),
    );
    #[cfg(feature = "source-http")]
    registered(
        "http source",
        registries
            .sources
            .register(Arc::new(lotse_http::HttpFactory)),
    );
    // WebRTC cameras (Nest, Ring, Matter through Home Assistant): lotse
    // offers, the control-API client relays the signaling.
    #[cfg(feature = "source-webrtc")]
    registered(
        "webrtc source",
        registries
            .sources
            .register(Arc::new(lotse_webrtc::ingest::WebRtcSourceFactory)),
    );
    #[cfg(feature = "source-fake")]
    // With a backchannel, so the talk-back tests reach a worker's arbiter
    // through the control API.
    registered(
        "fake source",
        registries.sources.register(Arc::new(
            lotse_core::test_util::FakeSourceFactory::with_backchannel(&["fake"]),
        )),
    );
    #[cfg(feature = "source-fake")]
    // Signaled, so the end-to-end tests reach a worker's signaling through
    // the supervisor.
    registered(
        "signaled fake source",
        registries.sources.register_signaled(Arc::new(
            lotse_core::test_util::FakeSignaledSourceFactory::new("fake-signaled"),
        )),
    );
    registries
}

/// Logs a registration [`registries`] could not make: the daemon runs on
/// without `what`, which its `info` then does not list.
#[cfg(any(
    feature = "output-webrtc",
    feature = "source-rtsp",
    feature = "source-http",
    feature = "source-webrtc",
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
    logging::init(args.log_format, &args.log_level, Arc::new(SystemClock)).context("logging")?;
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
    // Landlock allows `connect` only on the camera's ports, the ones the
    // supervisor passed; the worker binds no TCP port.
    let connect_ports = args.connect_ports.clone();
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
        limits: track_limits(args),
        runner: RunnerConfig::default(),
        session: lotse_core::session::SessionLimits::default(),
        max_sessions: args.max_sessions,
        // The filter keeps the shared socket to sending at this number; the
        // control channel stays on standard input, `WORKER_CONTROL_FD`.
        shared_udp_fd: Some(lotse_sandbox::WORKER_SHARED_UDP_FD),
        recording: recording_settings(args),
    };
    let reason = lotse_worker::run(&settings, registries(), memory).context("worker")?;
    tracing::info!(reason = ?reason, "worker exited");
    Ok(())
}

/// The worker's track limits: the pre-record ring's bound from the flag its
/// supervisor passed, the rest the defaults.
fn track_limits(args: &WorkerArgs) -> TrackLimits {
    TrackLimits {
        prerecord_bytes: args.max_prerecord_bytes,
        ..TrackLimits::default()
    }
}

/// The worker's recording limits from the flags its supervisor passed, the
/// values the supervisor checks recordings against.
fn recording_settings(args: &WorkerArgs) -> lotse_worker::RecordingSettings {
    lotse_worker::RecordingSettings {
        policy: RecordingPolicy {
            queue_bytes: args.recording_queue_bytes,
            ..RecordingPolicy::default()
        },
        max_duration: Duration::from_millis(args.max_recording_ms),
        start_timeout: Duration::from_millis(args.recording_start_timeout_ms),
        max_recordings: args.max_recordings,
    }
}

/// The supervisor process, in the documented startup order: configuration,
/// logging, panic hook, the control socket, sandbox, runtime.
fn serve(args: &ServeArgs, matches: &ArgMatches) -> anyhow::Result<()> {
    let (settings, provenance) = config::load(args, matches).context("configuration")?;
    logging::init(
        settings.log.format,
        &settings.log.level,
        Arc::new(SystemClock),
    )
    .context("logging")?;
    let _process =
        tracing::info_span!("process", kind = "supervisor", pid = std::process::id()).entered();
    logging::install_panic_hook();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "lotse starting");
    config::log_effective(&provenance, &settings.log);

    let listeners = lotse_supervisor::bind(&settings.supervisor).context("sockets")?;
    let binary = std::env::current_exe().context("own executable path")?;
    // The rule is made from the descriptor the directory was checked and
    // locked through, not its path, which could name another by now. The
    // copy is close-on-exec (`F_DUPFD_CLOEXEC`) and closed with the profile.
    let state_dir = listeners
        .api
        .state_dir()
        .map(|(path, fd)| {
            fd.try_clone_to_owned().map(|fd| StateDir {
                path: path.to_path_buf(),
                fd,
            })
        })
        .transpose()
        .context("state directory")?;
    let profile = Profile::Supervisor {
        binary: binary.clone(),
        state_dir,
    };
    let report = lotse_sandbox::apply(&profile, &settings.sandbox).context("sandbox")?;
    drop(profile);

    let limits = &settings.supervisor.limits;
    let environment = Environment {
        registries: registries(),
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
            recordings: limits.recordings,
        },
        udp: None,
        front_door: None,
        identity: Identity {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            build: BuildInfo {
                target: env!("LOTSE_TARGET").to_owned(),
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

    #[test]
    fn a_worker_runs_its_recordings_under_the_limits_its_flags_pass() {
        let matches = Cli::command()
            .try_get_matches_from([
                "lotse",
                "worker",
                "--max-prerecord-bytes",
                "1048576",
                "--max-recording-ms",
                "45000",
                "--recording-queue-bytes",
                "65536",
                "--recording-start-timeout-ms",
                "2500",
                "--max-recordings",
                "3",
            ])
            .unwrap();
        let args =
            WorkerArgs::from_arg_matches(matches.subcommand_matches("worker").unwrap()).unwrap();
        assert_eq!(
            recording_settings(&args),
            lotse_worker::RecordingSettings {
                policy: RecordingPolicy {
                    queue_bytes: 1 << 16,
                    ..RecordingPolicy::default()
                },
                max_duration: Duration::from_secs(45),
                start_timeout: Duration::from_millis(2_500),
                max_recordings: 3,
            }
        );
        assert_eq!(track_limits(&args).prerecord_bytes, 1 << 20);
    }

    /// The registries of a build with every feature hold the recording container.
    #[cfg(feature = "output-recording")]
    #[test]
    fn the_recording_output_is_registered_behind_its_feature() {
        let registries = registries();
        let recording = registries.recording.expect("a recording output");
        let h264 = lotse_core::codec::Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        };
        assert!(!recording.accepts(&h264), "fMP4 needs the parameter sets");
    }

    /// The registries of a build with the WebRTC source hold its scheme,
    /// a signaled one without a backchannel.
    #[cfg(feature = "source-webrtc")]
    #[test]
    fn the_webrtc_source_is_registered_behind_its_feature() {
        let registries = registries();
        assert!(registries.sources.schemes().contains(&"webrtc"));
        let webrtc = registries
            .sources
            .get("webrtc")
            .expect("the webrtc factory");
        let capabilities = webrtc.capabilities();
        assert!(capabilities.signaled);
        assert!(!capabilities.backchannel);
    }

    #[cfg(any(
        feature = "output-webrtc",
        feature = "source-rtsp",
        feature = "source-http",
        feature = "source-webrtc",
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
