//! Privilege drop, `no_new_privs`, `dumpable`, rlimits, a worker's lower
//! scheduling priority, and the Landlock and seccomp profiles for each
//! process kind (supervisor, worker, decoder).
//!
//! Applied by the binary in the main thread before any runtime starts, and
//! reports which layers are enforced for `info.sandbox`. Linux-only: on
//! macOS every layer reports `unavailable` so the workspace still builds and
//! tests. Depends on nothing in the workspace: it runs before anything else
//! exists in the process.
//!
//! Standards: landlock(7), seccomp(2), prctl(2), setresuid(2), setrlimit(2),
//! setpriority(2) and sched(7).

use std::fmt;
use std::os::fd::OwnedFd;
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

/// How many nice units a worker adds to the nice value it inherits from
/// the supervisor (setpriority(2)), so the supervisor and its control plane
/// outrank a worker that spins: each unit makes the scheduler favor the
/// higher-priority thread by a factor of about 1.25 (sched(7), "The nice
/// value"), so 10 units give a supervisor thread about nine times the CPU
/// share of a worker thread competing with it. It is nice(1)'s default
/// adjustment. Not 19: a worker carries live video, and at 19 it would get
/// about a seventieth of a core it shares with any other busy process
/// of the host. The kernel clamps the result at 19 (setpriority(2)).
///
/// A bound only per thread: a supervisor thread on a core with N spinning
/// worker threads gets 1024/(1024 + 110·N) of it (the weights of nice 0
/// and nice 10, kernel/sched/core.c `sched_prio_to_weight`), half of it at
/// about N = 9, and sibling workers, at the same nice, share the CPU with
/// them evenly. Thread count and CPU time are not bounded otherwise.
///
/// Nice values count only among the threads of one task group: one
/// autogroup (sched(7), "The autogroup feature"; a worker stays in the
/// supervisor's session, which spawns it without `setsid(2)`) and one
/// cgroup. So where the daemon runs inside its client's container, workers
/// under load yield about 9:1 to the client's threads too. A worker that
/// cannot set its nice value does not start (`setpriority` refused by a
/// container's seccomp profile; Docker's default profile allows it), and
/// its `RLIMIT_NICE` is 0 ([`WORKER_MAX_NICE_RLIMIT`]) so it cannot lower
/// the value again.
pub const WORKER_NICE_INCREMENT: i32 = 10;

/// `RLIMIT_NICE` for a worker, soft and hard: 0, so no nice value below
/// the one it has is within its reach. An unprivileged process may lower
/// its nice value only as far as its `RLIMIT_NICE` soft limit allows
/// (setpriority(2), since Linux 2.6.12), whose ceiling is `20 - rlim_cur`
/// (getrlimit(2), `RLIMIT_NICE`): nice 20, beyond the range, at 0. An
/// inherited limit above 0 (`docker run --ulimit nice=20:20`, say) would
/// let the dropped uid undo [`WORKER_NICE_INCREMENT`] wherever the seccomp
/// layer is unavailable. Lowering a hard limit needs no privilege.
pub const WORKER_MAX_NICE_RLIMIT: u64 = 0;

/// `RLIMIT_FSIZE` for a worker, soft and hard: 0, so every write(2)-family
/// call on a regular file fails. getrlimit(2): an attempt to extend a file
/// past the limit gets `SIGXFSZ`, or fails with `EFBIG` where the signal is
/// caught or ignored; at 0 the kernel refuses any write at an offset at or
/// past the limit (mm/filemap.c, `generic_write_check_limits`), so
/// `write`, `pwrite` and `writev` fail even within a file's current size,
/// and no file can grow. Pipes, sockets and character devices such as
/// `/dev/null` are not regular files and keep working. Lowering a hard
/// limit needs no privilege.
///
/// The limit does not cover a shared writable mapping: stores through
/// `mmap(MAP_SHARED, PROT_WRITE)` change an existing file in place, within
/// its size, with no write call to refuse (observed on Linux 6.18 on
/// 2026-10-17). What keeps a worker from opening a file for writing at all
/// is Landlock; where the kernel lacks it (Linux 5.13) or has it disabled,
/// a worker can still modify, in place, an existing file its uid may open
/// for writing, since its seccomp allowlist keeps `openat` and `mmap`.
///
/// Nothing a worker runs writes a file: it logs to its standard error,
/// sends on sockets it holds and reads `/proc/self/smaps_rollup` through a
/// descriptor opened before its sandbox. The limit backs Landlock with what
/// it does cover: no file a worker opens can grow, and none can be written
/// by a write call, which the seccomp allowlist keeps (`write`, `pwrite64`;
/// it denies `memfd_create` and `ftruncate`).
///
/// Not set while the worker's standard error is a regular file
/// (`lotse serve 2>lotse.log`, systemd's `StandardError=file:`, CI's
/// Sandbox isolation job): a worker inherits the supervisor's standard
/// error and logs to it, so its first log line would end it. The report
/// then notes that the limit is missing; `require` does not refuse, since
/// the limit is not one of the layers it requires.
///
/// `SIGXFSZ` keeps its default action, ending the worker (no core dump:
/// `RLIMIT_CORE` is 0 and the worker is not dumpable), as seccomp's
/// `SIGSYS` does: a worker writing a regular file runs code it was not
/// built to run. Ignoring it would need sigaction(2), which nothing but
/// `unsafe` code reaches, and would only turn the end into `EFBIG`.
pub const WORKER_MAX_FILE_SIZE: u64 = 0;

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
    /// applies: no rlimits, lower priority, `dumpable`, `no_new_privs`,
    /// Landlock or seccomp.
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

/// The directory the supervisor writes at runtime, as the caller opened
/// and checked it. Its Landlock rule is made from `fd`, never from `path`:
/// a rule names the inode (landlock(7)), and looking the path up again
/// could find another directory than the one checked, should someone who
/// may rename in a parent have swapped it meanwhile.
#[derive(Debug)]
pub struct StateDir {
    /// What the directory was opened as, for the notes and the logs only.
    pub path: PathBuf,
    /// The directory, open; close-on-exec, so no child inherits it.
    pub fd: OwnedFd,
}

/// Which process kind is being sandboxed, with what that kind still needs.
#[derive(Debug)]
pub enum Profile {
    /// The supervisor: reads `/etc/resolv.conf`, `/etc/hosts` and `/proc`,
    /// re-executes its own binary, spawns processes, opens sockets, and
    /// writes files in its state directory.
    Supervisor {
        /// The path of the daemon's own executable, which it re-executes
        /// for workers and decoders.
        binary: PathBuf,
        /// The directory the supervisor writes at runtime (the control TLS
        /// listener's enrolled clients), if it has one.
        state_dir: Option<StateDir>,
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
/// The order is privileges, rlimits, a worker's scheduling priority
/// ([`WORKER_NICE_INCREMENT`]), `dumpable`, the parent-death signal
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
                "sandbox is off: no rlimits, lower worker priority, no_new_privs, Landlock or seccomp, only the privilege drop; use only for debugging"
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
                binary: PathBuf::from("/lotse"),
                state_dir: None,
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
