//! Privilege drop, `no_new_privs`, `dumpable`, rlimits, and the Landlock and
//! seccomp profiles for each process kind (supervisor, worker, decoder).
//!
//! Applied by the binary in the main thread before any runtime starts, and
//! reports which layers are enforced for `info.sandbox`. Linux-only: on
//! macOS every layer reports `unavailable` so the workspace still builds and
//! tests. Depends on nothing in the workspace: it runs before anything else
//! exists in the process.
//!
//! Standards: landlock(7), seccomp(2), prctl(2), setresuid(2), setrlimit(2).

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

mod error;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod other;
mod report;
#[cfg(target_os = "linux")]
mod seccomp;

pub use error::SandboxError;
pub use report::{LandlockReport, LayerStatus, SandboxReport};

/// The uid the daemon drops to when started as root: `nobody`.
pub const DEFAULT_UID: u32 = 65534;

/// The gid the daemon drops to when started as root: `nogroup`.
pub const DEFAULT_GID: u32 = 65534;

/// Default of `limits.worker_address_space`: 1 GiB of `RLIMIT_AS` per worker.
pub const DEFAULT_WORKER_ADDRESS_SPACE: u64 = 1 << 30;

/// `RLIMIT_NOFILE` for a worker.
pub const WORKER_MAX_FILES: u64 = 256;

/// The descriptor number a worker keeps the shared WebRTC UDP socket at,
/// the highest [`WORKER_MAX_FILES`] leaves it. Every worker sends on one
/// open file description with the supervisor, which receives on it, so the
/// worker's seccomp filter denies, on this number, every call that would
/// receive from it, reconfigure it or give it another number: a worker
/// sends on it and nothing else. The worker moves the socket here itself
/// when it arrives (`fcntl(2)` `F_DUPFD_CLOEXEC`, which takes the lowest
/// free number at or above this one, so it never replaces another).
pub const WORKER_SHARED_UDP_FD: i32 = 255;

/// The descriptor number of a worker's control channel: its standard
/// input, where the supervisor puts it. The channel stays at this number,
/// the only one the worker's filter lets `sendmsg(2)` use besides
/// [`WORKER_SHARED_UDP_FD`], and the filter keeps it from being closed or
/// replaced, so no socket of the worker's own can carry the shared socket
/// back to it under a new number by `SCM_RIGHTS`.
pub const WORKER_CONTROL_FD: i32 = 0;

/// `RLIMIT_AS` for a decoder: 256 MiB.
pub const DECODER_ADDRESS_SPACE: u64 = 256 << 20;

/// `RLIMIT_CPU` for a decoder, in seconds.
pub const DECODER_CPU_SECONDS: u64 = 5;

/// The `sandbox` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Best effort: every layer the kernel offers is enforced, the rest is
    /// reported so a client can warn the user.
    #[default]
    On,
    /// Refuse to start if any layer is unavailable.
    Require,
    /// Debugging only; warns on every start. Only the privilege drop
    /// applies: no rlimits, `dumpable`, `no_new_privs`, Landlock or seccomp.
    /// The drop is not a sandbox layer, so no mode lets a process started as
    /// root keep root.
    Off,
}

impl Mode {
    /// The setting's text: `on`, `require` or `off`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Require => "require",
            Self::Off => "off",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a string is not a [`Mode`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("sandbox mode must be `on`, `require` or `off`, not {0:?}")]
pub struct ParseModeError(String);

impl FromStr for Mode {
    type Err = ParseModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "on" => Ok(Self::On),
            "require" => Ok(Self::Require),
            "off" => Ok(Self::Off),
            other => Err(ParseModeError(other.to_owned())),
        }
    }
}

/// Which process kind is being sandboxed, with what that kind still needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// The supervisor: reads `/etc/resolv.conf`, `/etc/hosts` and `/proc`,
    /// re-executes its own binary, spawns processes, opens sockets.
    Supervisor {
        /// The path of the daemon's own executable, which it re-executes
        /// for workers and decoders.
        binary: PathBuf,
    },
    /// A worker: no filesystem, TCP only to its camera's ports, no
    /// subprocesses, threads only.
    Worker {
        /// The TCP ports the worker may connect to on its camera (RTSP,
        /// and ONVIF when keyframe requests are on).
        connect_ports: Vec<u16>,
    },
    /// A decoder: memory, its inherited descriptors and exit; nothing else.
    Decoder,
}

impl Profile {
    /// The process kind's name, as the logs tag it.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Supervisor { .. } => "supervisor",
            Self::Worker { .. } => "worker",
            Self::Decoder => "decoder",
        }
    }
}

/// The settings every profile shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    /// The `sandbox` setting.
    pub mode: Mode,
    /// The uid to drop to when started as root.
    pub uid: u32,
    /// The gid to drop to when started as root.
    pub gid: u32,
    /// `RLIMIT_AS` for a worker.
    pub worker_address_space: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: Mode::On,
            uid: DEFAULT_UID,
            gid: DEFAULT_GID,
            worker_address_space: DEFAULT_WORKER_ADDRESS_SPACE,
        }
    }
}

/// Applies `profile` to the calling process. Call it in the main thread
/// before any other thread exists: the privilege drop is per thread at the
/// syscall level and seccomp applies to the calling thread.
///
/// The order is privileges, rlimits, `dumpable`, the parent-death signal
/// (workers and decoders), `no_new_privs`, Landlock, seccomp. In `on` mode
/// a layer the kernel lacks is reported, in `require` mode it is an error,
/// and `off` applies the privilege drop alone: started as root, every mode
/// drops to `config.uid`/`config.gid` and proves the drop stuck, so camera
/// bytes are never parsed as root.
pub fn apply(profile: &Profile, config: &SandboxConfig) -> Result<SandboxReport, SandboxError> {
    tracing::info!(
        profile = profile.name(),
        mode = config.mode.name(),
        "applying sandbox"
    );
    let report = match config.mode {
        Mode::Off => {
            let (uid, gid) = platform::drop_privileges(config)?;
            tracing::warn!(
                "sandbox is off: no rlimits, no_new_privs, Landlock or seccomp, only the privilege drop; use only for debugging"
            );
            SandboxReport::off(uid, gid)
        }
        Mode::On | Mode::Require => platform::apply(profile, config)?,
    };
    tracing::info!(
        uid = report.uid,
        gid = report.gid,
        no_new_privs = report.no_new_privs,
        seccomp = report.seccomp.name(),
        landlock_fs = report.landlock.fs.name(),
        landlock_net = report.landlock.net.name(),
        landlock_abi = report.landlock.abi,
        notes = ?report.notes,
        "sandbox applied"
    );
    Ok(report)
}

/// The calling process's real uid.
fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// The calling process's real gid.
fn current_gid() -> u32 {
    rustix::process::getgid().as_raw()
}

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(not(target_os = "linux"))]
use other as platform;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use tracing_subscriber::fmt::MakeWriter as _;

    use super::*;

    #[test]
    fn mode_parses_and_prints_its_three_values() {
        for (text, mode) in [
            ("on", Mode::On),
            ("require", Mode::Require),
            ("off", Mode::Off),
        ] {
            assert_eq!(text.parse::<Mode>().unwrap(), mode);
            assert_eq!(mode.to_string(), text);
            assert_eq!(serde_json::to_string(&mode).unwrap(), format!("\"{text}\""));
        }
        let err = "loud".parse::<Mode>().unwrap_err();
        assert_eq!(
            err.to_string(),
            "sandbox mode must be `on`, `require` or `off`, not \"loud\""
        );
        assert_eq!(Mode::default(), Mode::On);
    }

    #[test]
    fn profiles_and_config_have_names_and_documented_defaults() {
        assert_eq!(
            Profile::Supervisor {
                binary: PathBuf::from("/lotse")
            }
            .name(),
            "supervisor"
        );
        assert_eq!(
            Profile::Worker {
                connect_ports: vec![554]
            }
            .name(),
            "worker"
        );
        assert_eq!(Profile::Decoder.name(), "decoder");
        assert_eq!(
            u64::try_from(WORKER_SHARED_UDP_FD).unwrap(),
            WORKER_MAX_FILES - 1,
            "the highest descriptor a worker may hold"
        );
        assert_eq!(WORKER_CONTROL_FD, 0, "standard input");
        let config = SandboxConfig::default();
        assert_eq!((config.uid, config.gid), (65534, 65534));
        assert_eq!(config.worker_address_space, 1 << 30);
        assert_eq!(config.mode, Mode::On);
    }

    #[test]
    fn off_enforces_nothing_and_reports_it() {
        let config = SandboxConfig {
            mode: Mode::Off,
            ..SandboxConfig::default()
        };
        let report = apply(&Profile::Decoder, &config).unwrap();
        assert_eq!(report.mode, Mode::Off);
        assert_eq!(report.uid, current_uid());
        assert_eq!(report.gid, current_gid());
        assert!(!report.no_new_privs);
        assert_eq!(report.seccomp, LayerStatus::Off);
        assert_eq!(report.landlock.fs, LayerStatus::Off);
        assert_eq!(report.landlock.net, LayerStatus::Off);
        assert!(report.missing_layers().is_empty(), "off is not missing");
    }

    /// Regression for `off` skipping the drop: started as root (as a
    /// deployment may start it in a container), the process ended up
    /// parsing camera bytes as root. Only a root run reaches the drop;
    /// unprivileged it keeps its own ids. The drop is per thread at the
    /// syscall level, so it ends with this test's thread.
    #[cfg(target_os = "linux")]
    #[test]
    fn off_still_drops_root_to_the_configured_ids() {
        let started_as_root = rustix::process::geteuid().is_root();
        let config = SandboxConfig {
            mode: Mode::Off,
            uid: 4242,
            gid: 4343,
            ..SandboxConfig::default()
        };
        let worker = Profile::Worker {
            connect_ports: vec![554],
        };
        let report = apply(&worker, &config).unwrap();
        assert!(!rustix::process::geteuid().is_root(), "still root");
        assert_eq!((report.uid, report.gid), (current_uid(), current_gid()));
        let dropped = (report.uid, report.gid, rustix::process::getegid().as_raw());
        assert!(
            !started_as_root || dropped == (4242, 4343, 4343),
            "{dropped:?}"
        );
        assert_eq!(report.seccomp, LayerStatus::Off);
    }

    /// Started as root on a platform without the drop, `off` refuses to
    /// run rather than keep root.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_refuses_root_where_there_is_no_drop() {
        let config = SandboxConfig {
            mode: Mode::Off,
            ..SandboxConfig::default()
        };
        let started_as_root = rustix::process::geteuid().is_root();
        match apply(&Profile::Decoder, &config) {
            Ok(report) => assert!(!started_as_root, "{report:?}"),
            Err(err) => {
                assert!(started_as_root, "{err}");
                assert!(matches!(err, SandboxError::RootUnsupported), "{err}");
            }
        }
    }

    /// The log lines of [`apply_logs_the_profile_and_mode_then_every_layers_status`].
    static LOGS: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

    #[test]
    fn apply_logs_the_profile_and_mode_then_every_layers_status() {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| LOGS.make_writer())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        let config = SandboxConfig {
            mode: Mode::Off,
            ..SandboxConfig::default()
        };
        let report = tracing::subscriber::with_default(subscriber, || {
            apply(&Profile::Decoder, &config).unwrap()
        });
        let logs = String::from_utf8(LOGS.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("applying sandbox profile=\"decoder\" mode=\"off\""),
            "{logs}"
        );
        assert!(logs.contains("sandbox is off"), "{logs}");
        let applied = format!(
            "sandbox applied uid={} gid={} no_new_privs=false seccomp=\"off\" landlock_fs=\"off\" landlock_net=\"off\" landlock_abi=0 notes=[]",
            report.uid, report.gid
        );
        assert!(logs.contains(&applied), "{logs}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn other_platforms_report_every_layer_unavailable() {
        let report = apply(&Profile::Decoder, &SandboxConfig::default()).unwrap();
        assert_eq!(report.seccomp, LayerStatus::Unavailable);
        assert_eq!(report.landlock.fs, LayerStatus::Unavailable);
        assert_eq!(report.landlock.net, LayerStatus::Unavailable);
        assert_eq!(report.landlock.abi, 0);
        assert!(!report.no_new_privs);
        assert_eq!(
            report.missing_layers(),
            ["seccomp", "landlock.fs", "landlock.net"]
        );
        assert!(!report.notes.is_empty());

        let config = SandboxConfig {
            mode: Mode::Require,
            ..SandboxConfig::default()
        };
        let err = apply(&Profile::Decoder, &config).unwrap_err();
        assert!(
            matches!(
                err,
                SandboxError::Required {
                    layer: "sandbox",
                    ..
                }
            ),
            "{err}"
        );
    }
}
