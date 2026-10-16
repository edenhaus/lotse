//! The Linux implementation: privilege drop, rlimits, a worker's
//! scheduling priority, `dumpable`, the parent-death signal,
//! `no_new_privs` and Landlock, then the seccomp allowlist from
//! [`crate::seccomp`].
//!
//! Implements setresuid(2)/setgroups(2) for the drop, setrlimit(2),
//! setpriority(2) for a worker's nice value (sched(7)), prctl(2)
//! `PR_SET_DUMPABLE`, `PR_SET_PDEATHSIG` and `PR_SET_NO_NEW_PRIVS`, and
//! landlock(7) filesystem rules (ABI 1) and TCP rules (ABI 4). Every
//! Landlock ruleset is best effort: the kernel's ABI is probed first, and
//! what it lacks is reported rather than fatal unless the mode is `require`.

use std::io;
use std::os::fd::AsFd;
use std::path::Path;

use landlock::{
    ABI, Access as _, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible as _, NetPort,
    PathBeneath, PathFd, Ruleset, RulesetAttr as _, RulesetCreatedAttr as _, RulesetStatus,
};
use rustix::io::Errno;
use rustix::process::{DumpableBehavior, Gid, Resource, Rlimit, Signal, Uid};

use crate::report::{LandlockReport, LayerStatus};
use crate::{
    DECODER_ADDRESS_SPACE, DECODER_CPU_SECONDS, Mode, Profile, SandboxConfig, SandboxError,
    SandboxReport, WORKER_MAX_FILES, WORKER_MAX_NICE_RLIMIT, WORKER_NICE_INCREMENT, seccomp,
};

/// The highest Landlock ABI this crate asks for. Filesystem rules need
/// ABI 1, TCP rules ABI 4; later ABIs add nothing the profiles use.
const WANTED_ABI: u32 = 4;

/// Applies the profile in the documented order.
pub(crate) fn apply(
    profile: &Profile,
    config: &SandboxConfig,
) -> Result<SandboxReport, SandboxError> {
    let mut notes = Vec::new();
    // Before the drop: the dropped uid may not reach a rule's path.
    let rules = open_rules(profile);
    let (uid, gid) = drop_privileges(config)?;
    apply_rlimits(profile, config)?;
    apply_priority(profile)?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(step("PR_SET_DUMPABLE"))?;
    if !matches!(profile, Profile::Supervisor { .. }) {
        // Workers and decoders die with the supervisor.
        rustix::process::set_parent_process_death_signal(Some(Signal::KILL))
            .map_err(step("PR_SET_PDEATHSIG"))?;
    }
    rustix::thread::set_no_new_privs(true).map_err(step("PR_SET_NO_NEW_PRIVS"))?;
    let landlock = apply_landlock(profile, rules, config.mode, probe_abi(), &mut notes)?;
    let seccomp = seccomp::apply(profile, config.mode, std::env::consts::ARCH, &mut notes)?;
    Ok(SandboxReport {
        mode: config.mode,
        uid,
        gid,
        no_new_privs: true,
        seccomp,
        landlock,
        notes,
    })
}

/// Wraps a syscall error with the step it belongs to.
fn step(step: &'static str) -> impl Fn(Errno) -> SandboxError {
    move |errno| SandboxError::Step {
        step,
        source: io::Error::from(errno),
    }
}

/// Drops to the configured uid and gid when running as root, clearing the
/// supplementary groups first, and proves the drop stuck. Returns the
/// real ids afterwards. Every mode runs it, `off` included.
pub(crate) fn drop_privileges(config: &SandboxConfig) -> Result<(u32, u32), SandboxError> {
    drop_ids(&mut ThreadIds, config)
}

/// The id calls [`drop_privileges`] makes, so a test can stand in for the
/// kernel: the drop's own path runs only in a process started as root.
trait IdCalls {
    /// The effective uid (geteuid(2)).
    fn effective_uid(&self) -> u32;
    /// The real and effective uid and gid, in that order (getuid(2),
    /// geteuid(2), getgid(2), getegid(2)).
    fn ids(&self) -> (u32, u32, u32, u32);
    /// No supplementary group (setgroups(2) with an empty list).
    fn clear_groups(&mut self) -> Result<(), Errno>;
    /// The real, effective and saved gid all `gid` (setresgid(2)).
    fn set_gids(&mut self, gid: u32) -> Result<(), Errno>;
    /// The real, effective and saved uid all `uid` (setresuid(2)).
    fn set_uids(&mut self, uid: u32) -> Result<(), Errno>;
}

/// The calling thread's ids, through rustix: the privilege drop is per
/// thread at the syscall level, which is why the sandbox is applied before
/// any other thread exists.
///
/// The ids are passed unchecked: `-1` is setresuid(2)'s and setresgid(2)'s
/// "unchanged", which leaves root in place, and [`drop_ids`] must see it to
/// refuse it (rustix's checked constructor asserts on it in debug builds
/// only).
struct ThreadIds;

impl IdCalls for ThreadIds {
    fn effective_uid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn ids(&self) -> (u32, u32, u32, u32) {
        let effective_gid = rustix::process::getegid().as_raw();
        let (uid, gid) = (crate::current_uid(), crate::current_gid());
        (uid, self.effective_uid(), gid, effective_gid)
    }

    fn clear_groups(&mut self) -> Result<(), Errno> {
        rustix::thread::set_thread_groups(&[])
    }

    fn set_gids(&mut self, gid: u32) -> Result<(), Errno> {
        let gid = Gid::from_raw_unchecked(gid);
        rustix::thread::set_thread_res_gid(gid, gid, gid)
    }

    fn set_uids(&mut self, uid: u32) -> Result<(), Errno> {
        let uid = Uid::from_raw_unchecked(uid);
        rustix::thread::set_thread_res_uid(uid, uid, uid)
    }
}

/// [`drop_privileges`] through `calls`.
fn drop_ids(calls: &mut impl IdCalls, config: &SandboxConfig) -> Result<(u32, u32), SandboxError> {
    if calls.effective_uid() != 0 {
        let (uid, _, gid, _) = calls.ids();
        return Ok((uid, gid));
    }
    let failed = |step: &'static str| {
        move |errno: Errno| SandboxError::PrivilegeDrop {
            uid: config.uid,
            gid: config.gid,
            step,
            source: io::Error::from(errno),
        }
    };
    calls.clear_groups().map_err(failed("setgroups"))?;
    calls.set_gids(config.gid).map_err(failed("setresgid"))?;
    calls.set_uids(config.uid).map_err(failed("setresuid"))?;

    let still_privileged = SandboxError::StillPrivileged {
        uid: config.uid,
        gid: config.gid,
    };
    if calls.ids() != (config.uid, config.uid, config.gid, config.gid) {
        return Err(still_privileged);
    }
    // The saved ids are gone too, so root cannot come back.
    if calls.set_uids(0).is_ok() {
        return Err(still_privileged);
    }
    tracing::info!(uid = config.uid, gid = config.gid, "privileges dropped");
    Ok((config.uid, config.gid))
}

/// `RLIMIT_CORE` zero everywhere, plus the profile's own limits.
fn apply_rlimits(profile: &Profile, config: &SandboxConfig) -> Result<(), SandboxError> {
    let hard = |value: u64| Rlimit {
        current: Some(value),
        maximum: Some(value),
    };
    rustix::process::setrlimit(Resource::Core, hard(0)).map_err(step("RLIMIT_CORE"))?;
    match profile {
        Profile::Supervisor { .. } => {}
        Profile::Worker { .. } => {
            rustix::process::setrlimit(Resource::Nofile, hard(WORKER_MAX_FILES))
                .map_err(step("RLIMIT_NOFILE"))?;
            rustix::process::setrlimit(Resource::As, hard(config.worker_address_space))
                .map_err(step("RLIMIT_AS"))?;
            rustix::process::setrlimit(Resource::Nice, hard(WORKER_MAX_NICE_RLIMIT))
                .map_err(step("RLIMIT_NICE"))?;
        }
        Profile::Decoder => {
            rustix::process::setrlimit(Resource::As, hard(DECODER_ADDRESS_SPACE))
                .map_err(step("RLIMIT_AS"))?;
            rustix::process::setrlimit(Resource::Cpu, hard(DECODER_CPU_SECONDS))
                .map_err(step("RLIMIT_CPU"))?;
        }
    }
    Ok(())
}

/// Lowers a worker's scheduling priority by [`WORKER_NICE_INCREMENT`] nice
/// units from the one it inherited, and logs the nice value it now runs at;
/// the other profiles keep theirs.
///
/// The nice value is per thread on Linux: setpriority(2) with
/// `PRIO_PROCESS` and `who` 0 changes the calling thread only (BUGS: "the
/// nice value is a per-thread attribute"), and a thread starts with the
/// nice value of the thread that created it (setpriority(2) NOTES for
/// fork(2); the kernel's `sched_fork` copies it for a thread too). So the
/// worker sets it itself, here, in the main thread before any other thread
/// exists, as every step of [`crate::apply`] requires, and every thread of
/// its runtime inherits it. The supervisor setting it on the child's pid
/// after the spawn would race the child's runtime threads, which would keep
/// the supervisor's nice value, and a hook that runs between `fork` and
/// `execve` needs `unsafe`.
///
/// After the privilege drop and the rlimits: a higher nice value needs no
/// privilege, and nothing the worker keeps lets it raise its priority
/// again, neither the dropped uid with its `RLIMIT_NICE` of 0
/// ([`WORKER_MAX_NICE_RLIMIT`], set by [`apply_rlimits`] whatever limit it
/// inherited) nor the worker's seccomp allowlist, which has no call that
/// changes a priority or a scheduling policy. The read (getpriority(2))
/// and the write both run under the supervisor's inherited filter, which
/// allows them on the calling thread only. A failure of either is fatal,
/// as a refused rlimit is: a container whose seccomp profile refuses
/// `setpriority` starts no worker (Docker's default profile allows it).
///
/// No `SCHED_BATCH` (sched(7)): it changes only how the scheduler treats a
/// thread that wakes up, not its CPU share, so it does nothing against a
/// spinning thread and delays the media path's wakeups; rustix has no
/// `sched_setscheduler(2)` either, and `unsafe` is not allowed.
fn apply_priority(profile: &Profile) -> Result<(), SandboxError> {
    if let Profile::Worker { .. } = profile {
        // getpriority(2) then setpriority(2) on the calling thread, clamped
        // to the kernel's range.
        let nice = rustix::process::nice(WORKER_NICE_INCREMENT).map_err(step("setpriority"))?;
        tracing::info!(
            nice,
            increment = WORKER_NICE_INCREMENT,
            "worker scheduling priority lowered"
        );
    }
    Ok(())
}

/// The highest Landlock ABI the kernel supports, up to [`WANTED_ABI`];
/// zero when Landlock is missing or disabled. Each ABI is probed with
/// every right it defines ([`probe_rights`]) as a hard requirement, so a
/// kernel lacking one of them fails that ABI's probe.
fn probe_abi() -> u32 {
    (1..=WANTED_ABI)
        .rev()
        .find(|&abi| {
            let (fs, net) = probe_rights(abi);
            Ruleset::default()
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(fs)
                .and_then(|ruleset| net.into_iter().try_fold(ruleset, Ruleset::handle_access))
                .and_then(Ruleset::create)
                .is_ok()
        })
        .unwrap_or(0)
}

/// The rights that tell ABI `abi` from the one before it: every filesystem
/// right it defines and, from ABI 4, the TCP rights. ABI 4 adds no
/// filesystem right (landlock(7), "Landlock ABI versions"), so a probe of
/// the filesystem rights alone succeeds on an ABI 3 kernel (Linux 6.2 to
/// 6.6) and reported it as 4.
fn probe_rights(abi: u32) -> (BitFlags<AccessFs>, Option<BitFlags<AccessNet>>) {
    let net = (abi >= 4).then(|| AccessNet::from_all(ABI::V4));
    (AccessFs::from_all(abi_of(abi)), net)
}

/// The crate's ABI value for a probed number.
const fn abi_of(abi: u32) -> ABI {
    match abi {
        0 | 1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        _ => ABI::V4,
    }
}

/// A Landlock error as a step error.
fn landlock_step(err: landlock::RulesetError) -> SandboxError {
    SandboxError::Step {
        step: "landlock",
        source: io::Error::other(err),
    }
}

/// The status of an applied ruleset.
fn layer_status(status: &RulesetStatus, layer: &str, notes: &mut Vec<String>) -> LayerStatus {
    match *status {
        RulesetStatus::FullyEnforced => LayerStatus::Enforced,
        RulesetStatus::PartiallyEnforced => {
            notes.push(format!(
                "{layer}: partially enforced; the kernel lacks some of the requested access rights"
            ));
            LayerStatus::Enforced
        }
        RulesetStatus::NotEnforced => {
            notes.push(format!("{layer}: not enforced by this kernel"));
            LayerStatus::Unavailable
        }
    }
}

/// Filesystem and TCP rulesets for the profile, on a kernel whose highest
/// Landlock ABI is `abi` ([`probe_abi`]; zero without Landlock).
fn apply_landlock(
    profile: &Profile,
    rules: Vec<OpenedRule<'_>>,
    mode: Mode,
    abi: u32,
    notes: &mut Vec<String>,
) -> Result<LandlockReport, SandboxError> {
    if abi == 0 {
        let reason =
            "landlock: not supported or disabled by this kernel (needs Linux 5.13)".to_owned();
        if mode == Mode::Require {
            return Err(SandboxError::Required {
                layer: "landlock.fs",
                reason,
            });
        }
        notes.push(reason);
        return Ok(LandlockReport {
            fs: LayerStatus::Unavailable,
            net: LayerStatus::Unavailable,
            abi,
        });
    }

    let mut fs_ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi_of(abi)))
        .map_err(landlock_step)?
        .create()
        .map_err(landlock_step)?;
    for (path, opened, access) in rules {
        match opened {
            Ok(fd) => {
                fs_ruleset = fs_ruleset
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(landlock_step)?;
            }
            Err(err) => notes.push(format!("landlock: {path} not granted: {err}")),
        }
    }
    let fs = layer_status(
        &fs_ruleset.restrict_self().map_err(landlock_step)?.ruleset,
        "landlock.fs",
        notes,
    );

    let net = if abi >= 4 {
        let mut net_ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(net_access(profile))
            .map_err(landlock_step)?
            .create()
            .map_err(landlock_step)?;
        for (port, access) in net_rules(profile) {
            net_ruleset = net_ruleset
                .add_rule(NetPort::new(port, access))
                .map_err(landlock_step)?;
        }
        layer_status(
            &net_ruleset.restrict_self().map_err(landlock_step)?.ruleset,
            "landlock.net",
            notes,
        )
    } else {
        notes.push(format!(
            "landlock.net: TCP rules need ABI 4 (Linux 6.7); this kernel has ABI {abi}"
        ));
        LayerStatus::Unavailable
    };

    if mode == Mode::Require {
        for (layer, status) in [("landlock.fs", fs), ("landlock.net", net)] {
            if status != LayerStatus::Enforced {
                return Err(SandboxError::Required {
                    layer,
                    reason: notes.join("; "),
                });
            }
        }
    }
    Ok(LandlockReport { fs, net, abi })
}

/// The paths a profile may still reach, and how.
///
/// The supervisor's domain is inherited by every process it starts and
/// survives `execve` (landlock(7)), so its rules are also the most a worker
/// can ever reach; the worker's own empty ruleset narrows them to nothing.
/// `/dev/null` is write-only: spawning a worker opens it in the supervisor
/// for the worker's stdout (`Stdio::null()`), and nothing reads it. Only
/// the binary is executable, so it must be static: a dynamic binary's
/// loader needs the `execute` right too (release builds are static musl).
/// The state directory is no path here: [`open_rules`] adds its rule from
/// its descriptor.
fn fs_rules(profile: &Profile) -> Vec<(&Path, BitFlags<AccessFs>)> {
    match profile {
        Profile::Supervisor { binary, .. } => vec![
            (Path::new("/etc/resolv.conf"), AccessFs::ReadFile.into()),
            (Path::new("/etc/hosts"), AccessFs::ReadFile.into()),
            (Path::new("/proc"), AccessFs::ReadFile | AccessFs::ReadDir),
            (Path::new("/dev/null"), AccessFs::WriteFile.into()),
            (binary.as_path(), AccessFs::Execute | AccessFs::ReadFile),
        ],
        Profile::Worker { .. } | Profile::Decoder => Vec::new(),
    }
}

/// A Landlock rule's file or directory, opened or why not, with its
/// rights: a path opened here (`O_PATH`), or the state directory's
/// descriptor as the profile holds it.
type OpenedRule<'a> = (
    String,
    Result<Box<dyn AsFd + 'a>, String>,
    BitFlags<AccessFs>,
);

/// Opens `profile`'s rule paths, then adds the state directory, if any,
/// on the descriptor the profile holds, never looked up by its path again.
/// Called before the privilege drop: a rule names the inode, so a path only
/// the starting uid can reach (a state directory under a root-only parent)
/// still gets its rule.
fn open_rules(profile: &Profile) -> Vec<OpenedRule<'_>> {
    let mut rules: Vec<OpenedRule<'_>> = fs_rules(profile)
        .into_iter()
        .map(|(path, access)| {
            let opened = PathFd::new(path)
                .map(|fd| -> Box<dyn AsFd> { Box::new(fd) })
                .map_err(|err| err.to_string());
            (path.display().to_string(), opened, access)
        })
        .collect();
    if let Profile::Supervisor {
        state_dir: Some(dir),
        ..
    } = profile
    {
        let fd: Box<dyn AsFd> = Box::new(dir.fd.as_fd());
        rules.push((dir.path.display().to_string(), Ok(fd), STATE_ACCESS));
    }
    rules
}

/// What the supervisor may do beneath its state directory, the one place
/// it writes: read, create, write and remove regular files, which a rename
/// within it needs (landlock(7): `REMOVE_FILE` and `MAKE_REG`).
const STATE_ACCESS: BitFlags<AccessFs> = landlock::make_bitflags!(AccessFs::{
    ReadFile | WriteFile | ReadDir | RemoveFile | MakeReg
});

/// The TCP ports a profile's ruleset still allows, and for what.
///
/// The supervisor may bind port 0 only, which the kernel maps onto the
/// ephemeral range (landlock(7), `struct landlock_net_port_attr`: a rule
/// for port 0 with `LANDLOCK_ACCESS_NET_BIND_TCP` allows `bind(2)` to port
/// 0). Its sockets are bound before the sandbox; the rule exists for the
/// workers, which inherit its domain and bind their loopback relay on
/// `127.0.0.1:0` before applying their own. No fixed port becomes
/// bindable. A worker may connect to its camera's ports and its relay.
fn net_rules(profile: &Profile) -> Vec<(u16, BitFlags<AccessNet>)> {
    match profile {
        Profile::Supervisor { .. } => vec![(0, AccessNet::BindTcp.into())],
        Profile::Worker { connect_ports } => connect_ports
            .iter()
            .map(|&port| (port, AccessNet::ConnectTcp.into()))
            .collect(),
        Profile::Decoder => Vec::new(),
    }
}

/// Which TCP actions a profile's ruleset handles. The supervisor keeps
/// `connect` unrestricted: TURN servers arrive per offer, on ports unknown
/// at startup, and Landlock rules cannot be added later.
fn net_access(profile: &Profile) -> BitFlags<AccessNet> {
    match profile {
        Profile::Supervisor { .. } => AccessNet::BindTcp.into(),
        Profile::Worker { .. } | Profile::Decoder => AccessNet::BindTcp | AccessNet::ConnectTcp,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;
    use std::process::{Command, Output};

    use tracing_subscriber::fmt::MakeWriter as _;

    use super::*;
    use crate::StateDir;

    /// The variable that turns this test binary into a child that changes
    /// process-wide state (rlimits), which no other test may share.
    const CHILD: &str = "LOTSE_SANDBOX_LINUX_CHILD";

    /// The line a child prints once its checks passed, so a child that
    /// returned early does not pass.
    const CHILD_DONE: &str = "child: checks passed";

    /// Whether this process is a child run by [`in_child`].
    #[expect(
        clippy::disallowed_methods,
        reason = "the child reads the variable that marks it"
    )]
    fn is_child() -> bool {
        std::env::var_os(CHILD).is_some()
    }

    /// Runs this test binary's test `test` as a child and returns its
    /// output once it exited successfully having passed its checks. The
    /// child exits normally, so a coverage build writes its profile.
    #[expect(
        clippy::disallowed_methods,
        reason = "spawns this test binary as the child"
    )]
    fn in_child(test: &str) -> Output {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains(CHILD_DONE),
            "{}\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        );
        output
    }

    /// The soft and the hard limit of `resource`.
    fn limits(resource: Resource) -> (Option<u64>, Option<u64>) {
        let limit = rustix::process::getrlimit(resource);
        (limit.current, limit.maximum)
    }

    #[test]
    fn setrlimit2_a_limit_the_kernel_refuses_names_its_step() {
        in_child("linux::tests::setrlimit2_refused_limit_child");
    }

    /// The child: a hard `RLIMIT_AS` below the configured one, which no
    /// unprivileged process may raise (setrlimit(2), `EPERM`); a root run
    /// drops to `nobody` first and loses `CAP_SYS_RESOURCE` with it.
    #[test]
    fn setrlimit2_refused_limit_child() {
        if !is_child() {
            return;
        }
        let ceiling = rustix::process::getrlimit(Resource::As)
            .maximum
            .unwrap_or(u64::MAX)
            .min(1 << 36);
        let lowered = Rlimit {
            current: Some(ceiling),
            maximum: Some(ceiling),
        };
        rustix::process::setrlimit(Resource::As, lowered).unwrap();
        let config = SandboxConfig {
            worker_address_space: ceiling + 1,
            ..SandboxConfig::default()
        };
        let profile = Profile::Worker {
            connect_ports: vec![554],
        };
        // Through the crate's entry point, so this binary runs its `on` arm.
        let err = crate::apply(&profile, &config).unwrap_err();
        assert!(
            matches!(&err, SandboxError::Step { step: "RLIMIT_AS", source }
                if source.kind() == io::ErrorKind::PermissionDenied),
            "{err}"
        );
        assert!(err.to_string().starts_with("RLIMIT_AS failed: "), "{err}");
        assert_eq!(limits(Resource::Core), (Some(0), Some(0)), "set before");
        println!("{CHILD_DONE}");
    }

    #[test]
    fn setrlimit2_a_decoder_gets_its_address_space_and_cpu_limits() {
        in_child("linux::tests::setrlimit2_decoder_limits_child");
    }

    /// The child: the decoder's limits, set and read back.
    #[test]
    fn setrlimit2_decoder_limits_child() {
        if !is_child() {
            return;
        }
        apply_rlimits(&Profile::Decoder, &SandboxConfig::default()).unwrap();
        let supervisor = Profile::Supervisor {
            binary: "/lotse".into(),
            state_dir: None,
        };
        apply_rlimits(&supervisor, &SandboxConfig::default()).unwrap();
        let address_space = Some(DECODER_ADDRESS_SPACE);
        assert_eq!(limits(Resource::As), (address_space, address_space));
        let cpu = Some(DECODER_CPU_SECONDS);
        assert_eq!(limits(Resource::Cpu), (cpu, cpu));
        assert_eq!(limits(Resource::Core), (Some(0), Some(0)));
        println!("{CHILD_DONE}");
    }

    /// The calling thread's nice value (getpriority(2): on Linux,
    /// `PRIO_PROCESS` with `who` 0 is the calling thread).
    fn own_nice() -> i32 {
        rustix::process::getpriority_process(None).unwrap()
    }

    /// The log lines of
    /// [`setpriority2_a_worker_lowers_its_priority_and_its_later_threads_inherit_it`].
    static PRIORITY_LOGS: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

    /// Regression for SBX-25: a worker's threads ran at the supervisor's
    /// nice value, so one that spun took the supervisor's CPU share. The
    /// nice value is per thread, so this changes this test's thread only
    /// and ends with it.
    #[test]
    fn setpriority2_a_worker_lowers_its_priority_and_its_later_threads_inherit_it() {
        let before = own_nice();
        let supervisor = Profile::Supervisor {
            binary: "/lotse".into(),
            state_dir: None,
        };
        apply_priority(&supervisor).unwrap();
        apply_priority(&Profile::Decoder).unwrap();
        assert_eq!(own_nice(), before, "only a worker lowers its priority");

        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| PRIORITY_LOGS.make_writer())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        let worker = Profile::Worker {
            connect_ports: vec![554],
        };
        tracing::subscriber::with_default(subscriber, || apply_priority(&worker)).unwrap();
        // setpriority(2): the kernel clamps the value at 19.
        let lowered = (before + WORKER_NICE_INCREMENT).min(19);
        assert_eq!(own_nice(), lowered);
        let started = std::thread::spawn(own_nice).join().unwrap();
        assert_eq!(started, lowered, "a thread started afterwards inherits it");
        let logs = String::from_utf8(PRIORITY_LOGS.lock().unwrap().clone()).unwrap();
        let line = format!("worker scheduling priority lowered nice={lowered} increment=10");
        assert!(logs.contains(&line), "{logs}");
    }

    /// As a container's own seccomp profile can, a filter on this test's
    /// thread answers setpriority(2) with `EPERM` (seccomp(2): a filter
    /// applies to the calling thread only, without
    /// `SECCOMP_FILTER_FLAG_TSYNC`): the worker does not run on at the
    /// priority it inherited.
    #[test]
    fn setpriority2_a_priority_the_kernel_refuses_is_a_setpriority_step_error() {
        let arch = seccompiler::TargetArch::try_from(std::env::consts::ARCH).unwrap();
        let rules = std::collections::BTreeMap::from([(libc::SYS_setpriority, Vec::new())]);
        let eperm = u32::try_from(libc::EPERM).unwrap();
        let refuse: seccompiler::BpfProgram = seccompiler::SeccompFilter::new(
            rules,
            seccompiler::SeccompAction::Allow,
            seccompiler::SeccompAction::Errno(eperm),
            arch,
        )
        .unwrap()
        .try_into()
        .unwrap();
        seccompiler::apply_filter(&refuse).unwrap();
        let before = own_nice();
        let worker = Profile::Worker {
            connect_ports: vec![554],
        };
        let err = apply_priority(&worker).unwrap_err();
        assert!(
            matches!(&err, SandboxError::Step { step: "setpriority", source }
                if source.raw_os_error() == Some(libc::EPERM)),
            "{err}"
        );
        assert_eq!(
            err.to_string(),
            "setpriority failed: Operation not permitted (os error 1)"
        );
        assert_eq!(own_nice(), before);
    }

    #[test]
    fn setrlimit2_a_worker_gets_its_limits_and_cannot_raise_its_priority_again() {
        in_child("linux::tests::setrlimit2_worker_limits_child");
    }

    /// The child: the worker's limits, set and read back, over whatever
    /// `RLIMIT_NICE` it inherited (`docker run --ulimit nice=20:20` lets an
    /// unprivileged process lower its nice value to 0); then its lower
    /// priority, which it cannot undo unless it holds `CAP_SYS_NICE`, as
    /// root does outside a container (setpriority(2): `EACCES`; Docker's
    /// default capability set has no `CAP_SYS_NICE`).
    #[test]
    fn setrlimit2_worker_limits_child() {
        if !is_child() {
            return;
        }
        let worker = Profile::Worker {
            connect_ports: vec![554],
        };
        apply_rlimits(&worker, &SandboxConfig::default()).unwrap();
        let nice = Some(WORKER_MAX_NICE_RLIMIT);
        assert_eq!(limits(Resource::Nice), (nice, nice));
        assert_eq!(nice, Some(0));
        let files = Some(WORKER_MAX_FILES);
        assert_eq!(limits(Resource::Nofile), (files, files));
        let address_space = Some(crate::DEFAULT_WORKER_ADDRESS_SPACE);
        assert_eq!(limits(Resource::As), (address_space, address_space));
        apply_priority(&worker).unwrap();
        let lowered = own_nice();
        let raised = rustix::process::setpriority_process(None, lowered - 1);
        let effective = rustix::thread::capabilities(None).unwrap().effective;
        let privileged = effective.contains(rustix::thread::CapabilitySet::SYS_NICE);
        assert_eq!(raised.err(), (!privileged).then_some(Errno::ACCESS));
        println!("{CHILD_DONE}");
    }

    #[test]
    fn landlock7_a_ruleset_the_kernel_cannot_create_is_a_landlock_step_error() {
        in_child("linux::tests::landlock7_no_descriptor_left_child");
    }

    /// The child: no descriptor left for the ruleset that
    /// `landlock_create_ruleset(2)` returns (`EMFILE`), and the soft limit
    /// back afterwards. Needs a kernel with Landlock: without it nothing
    /// is created.
    #[test]
    fn landlock7_no_descriptor_left_child() {
        if !is_child() {
            return;
        }
        assert!(probe_abi() > 0, "needs a kernel with Landlock");
        let before = rustix::process::getrlimit(Resource::Nofile);
        let lowest_free = rustix::io::fcntl_dupfd_cloexec(io::stderr(), 0).unwrap();
        let exhausted = Rlimit {
            current: Some(u64::try_from(lowest_free.as_raw_fd()).unwrap()),
            maximum: before.maximum,
        };
        drop(lowest_free);
        rustix::process::setrlimit(Resource::Nofile, exhausted).unwrap();
        let mut notes = Vec::new();
        let result = apply_landlock(
            &Profile::Decoder,
            open_rules(&Profile::Decoder),
            Mode::On,
            1,
            &mut notes,
        );
        rustix::process::setrlimit(Resource::Nofile, before).unwrap();
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                SandboxError::Step {
                    step: "landlock",
                    ..
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("(os error 24)"), "{err}");
        println!("{CHILD_DONE}");
    }

    #[test]
    fn landlock7_without_landlock_on_reports_it_and_require_refuses() {
        let mut notes = Vec::new();
        let report = apply_landlock(
            &Profile::Decoder,
            open_rules(&Profile::Decoder),
            Mode::On,
            0,
            &mut notes,
        )
        .unwrap();
        assert_eq!(
            report,
            LandlockReport {
                fs: LayerStatus::Unavailable,
                net: LayerStatus::Unavailable,
                abi: 0,
            }
        );
        assert_eq!(
            notes,
            ["landlock: not supported or disabled by this kernel (needs Linux 5.13)"]
        );
        let err = apply_landlock(
            &Profile::Decoder,
            open_rules(&Profile::Decoder),
            Mode::Require,
            0,
            &mut notes,
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                SandboxError::Required { layer: "landlock.fs", reason }
                    if reason == "landlock: not supported or disabled by this kernel (needs Linux 5.13)"
            ),
            "{err}"
        );
        assert_eq!(notes.len(), 1, "require reports through the error");
    }

    /// Restricts this test's thread (landlock(7): a domain applies to the
    /// calling thread), which touches no file afterwards.
    #[test]
    fn landlock7_tcp_rules_need_abi_4_and_require_refuses_without_them() {
        let mut notes = Vec::new();
        let report = apply_landlock(
            &Profile::Decoder,
            open_rules(&Profile::Decoder),
            Mode::On,
            3,
            &mut notes,
        )
        .unwrap();
        assert_eq!((report.net, report.abi), (LayerStatus::Unavailable, 3));
        let tcp_note = "landlock.net: TCP rules need ABI 4 (Linux 6.7); this kernel has ABI 3";
        assert!(notes.iter().any(|note| note == tcp_note), "{notes:?}");
        let mut notes = Vec::new();
        let err = apply_landlock(
            &Profile::Decoder,
            open_rules(&Profile::Decoder),
            Mode::Require,
            3,
            &mut notes,
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                SandboxError::Required { layer: "landlock.fs" | "landlock.net", reason }
                    if reason.contains(tcp_note)
            ),
            "{err}"
        );
    }

    /// Restricts this test's thread, which touches no file afterwards.
    #[test]
    fn landlock7_a_path_that_cannot_be_opened_is_noted_and_not_granted() {
        let profile = Profile::Supervisor {
            binary: "/nonexistent/lotse".into(),
            state_dir: None,
        };
        let mut notes = Vec::new();
        let report =
            apply_landlock(&profile, open_rules(&profile), Mode::On, 4, &mut notes).unwrap();
        assert_eq!(report.abi, 4);
        assert!(
            notes
                .iter()
                .any(|note| note.starts_with("landlock: /nonexistent/lotse not granted: ")),
            "{notes:?}"
        );
    }

    #[test]
    fn landlock7_partial_or_no_enforcement_is_noted() {
        let mut notes = Vec::new();
        let full = layer_status(&RulesetStatus::FullyEnforced, "landlock.fs", &mut notes);
        assert_eq!(full, LayerStatus::Enforced);
        assert!(notes.is_empty());
        let partial = layer_status(&RulesetStatus::PartiallyEnforced, "landlock.fs", &mut notes);
        assert_eq!(partial, LayerStatus::Enforced);
        let none = layer_status(&RulesetStatus::NotEnforced, "landlock.net", &mut notes);
        assert_eq!(none, LayerStatus::Unavailable);
        assert_eq!(
            notes,
            [
                "landlock.fs: partially enforced; the kernel lacks some of the requested access rights",
                "landlock.net: not enforced by this kernel",
            ]
        );
    }

    #[test]
    fn landlock7_each_profile_keeps_only_its_own_paths_and_ports() {
        let supervisor = Profile::Supervisor {
            binary: "/lotse".into(),
            state_dir: None,
        };
        assert!(!STATE_ACCESS.contains(AccessFs::Execute));
        assert!(!STATE_ACCESS.contains(AccessFs::MakeDir));
        let worker = Profile::Worker {
            connect_ports: vec![554, 80],
        };
        let paths: Vec<_> = fs_rules(&supervisor)
            .into_iter()
            .map(|(path, _)| path)
            .collect();
        assert_eq!(
            paths,
            [
                Path::new("/etc/resolv.conf"),
                Path::new("/etc/hosts"),
                Path::new("/proc"),
                Path::new("/dev/null"),
                Path::new("/lotse"),
            ]
        );
        assert!(fs_rules(&worker).is_empty());
        assert!(fs_rules(&Profile::Decoder).is_empty());
        assert_eq!(net_rules(&supervisor), [(0, AccessNet::BindTcp.into())]);
        assert_eq!(
            net_rules(&worker),
            [
                (554, AccessNet::ConnectTcp.into()),
                (80, AccessNet::ConnectTcp.into())
            ]
        );
        assert!(net_rules(&Profile::Decoder).is_empty());
        assert_eq!(net_access(&supervisor), AccessNet::BindTcp);
        let both = AccessNet::BindTcp | AccessNet::ConnectTcp;
        assert_eq!(net_access(&worker), both);
        assert_eq!(net_access(&Profile::Decoder), both);
    }

    /// Regression: the rule was made from the state directory's path, looked
    /// up again after the caller had checked and locked the directory, so a
    /// directory swapped in meanwhile got the write rights instead.
    #[test]
    fn landlock7_the_state_directory_rule_is_the_directory_checked_not_the_one_its_path_names_now()
    {
        let path = std::env::temp_dir().join(format!("lotse-sandbox-state-{}", std::process::id()));
        let checked = PathBuf::from(format!("{}-checked", path.display()));
        for dir in [&path, &checked] {
            let _gone = std::fs::remove_dir_all(dir);
        }
        std::fs::create_dir(&path).unwrap();
        let fd = OwnedFd::from(std::fs::File::open(&path).unwrap());
        let inode = std::fs::metadata(&path).unwrap().ino();
        // Someone who may rename in the parent swaps another directory in.
        std::fs::rename(&path, &checked).unwrap();
        std::fs::create_dir(&path).unwrap();
        let profile = Profile::Supervisor {
            binary: "/lotse".into(),
            state_dir: Some(StateDir {
                path: path.clone(),
                fd,
            }),
        };
        let rules = open_rules(&profile);
        assert_eq!(rules.len(), fs_rules(&profile).len() + 1);
        let (name, opened, access) = rules.into_iter().last().unwrap();
        assert_eq!(name, path.display().to_string());
        assert_eq!(access, STATE_ACCESS);
        let granted = opened.unwrap().as_fd().try_clone_to_owned().unwrap();
        let granted = std::fs::File::from(granted).metadata().unwrap().ino();
        assert_eq!(granted, inode, "the directory checked");
        assert_ne!(granted, std::fs::metadata(&path).unwrap().ino());
        for dir in [&path, &checked] {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    /// A stand-in for one thread's ids in the kernel, with setresuid(2)'s
    /// and setresgid(2)'s rules: only an effective uid of 0 may set ids
    /// other than its own, `-1` leaves an id unchanged, and the saved ids
    /// follow the real ones. It records every call by its syscall's name
    /// and fails the one named `fail` with `EPERM`.
    struct FakeIds {
        /// The real uid, and the saved one.
        uid: u32,
        /// The effective uid.
        euid: u32,
        /// The real gid, and the saved one.
        gid: u32,
        /// The effective gid.
        egid: u32,
        /// Every call so far, in order.
        calls: std::cell::RefCell<Vec<&'static str>>,
        /// The call that fails, if any.
        fail: Option<&'static str>,
    }

    impl FakeIds {
        /// A thread whose ids are all `id`.
        fn all(id: u32) -> Self {
            Self {
                uid: id,
                euid: id,
                gid: id,
                egid: id,
                calls: std::cell::RefCell::default(),
                fail: None,
            }
        }

        /// Records `call` and decides it: `EPERM` when it is the failing
        /// one or would need privileges the thread lacks.
        fn call(&self, call: &'static str, needs_root: bool) -> Result<(), Errno> {
            self.calls.borrow_mut().push(call);
            let refused = self.fail == Some(call) || (needs_root && self.euid != 0);
            if refused { Err(Errno::PERM) } else { Ok(()) }
        }

        /// The calls made, in order.
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl IdCalls for FakeIds {
        fn effective_uid(&self) -> u32 {
            self.calls.borrow_mut().push("geteuid");
            self.euid
        }

        fn ids(&self) -> (u32, u32, u32, u32) {
            self.calls.borrow_mut().push("getids");
            (self.uid, self.euid, self.gid, self.egid)
        }

        fn clear_groups(&mut self) -> Result<(), Errno> {
            self.call("setgroups", true)
        }

        fn set_gids(&mut self, gid: u32) -> Result<(), Errno> {
            let own = [self.gid, self.egid, u32::MAX].contains(&gid);
            self.call("setresgid", !own)?;
            if gid != u32::MAX {
                (self.gid, self.egid) = (gid, gid);
            }
            Ok(())
        }

        fn set_uids(&mut self, uid: u32) -> Result<(), Errno> {
            let own = [self.uid, self.euid, u32::MAX].contains(&uid);
            self.call("setresuid", !own)?;
            if uid != u32::MAX {
                (self.uid, self.euid) = (uid, uid);
            }
            Ok(())
        }
    }

    /// The configured ids the drop tests drop to.
    fn to(uid: u32, gid: u32) -> SandboxConfig {
        SandboxConfig {
            uid,
            gid,
            ..SandboxConfig::default()
        }
    }

    #[test]
    fn setresuid2_root_clears_groups_then_sets_gids_then_uids_and_cannot_return() {
        let mut ids = FakeIds::all(0);
        assert_eq!(drop_ids(&mut ids, &to(4242, 4343)).unwrap(), (4242, 4343));
        assert_eq!(
            ids.calls(),
            [
                "geteuid",
                "setgroups",
                "setresgid",
                "setresuid",
                "getids",
                "setresuid"
            ],
            "the last call is the refused return to root"
        );
        assert_eq!(
            (ids.uid, ids.euid, ids.gid, ids.egid),
            (4242, 4242, 4343, 4343)
        );
    }

    #[test]
    fn setresuid2_an_unprivileged_process_keeps_its_ids_and_calls_nothing_else() {
        let mut ids = FakeIds::all(1001);
        assert_eq!(drop_ids(&mut ids, &to(4242, 4343)).unwrap(), (1001, 1001));
        assert_eq!(ids.calls(), ["geteuid", "getids"]);
    }

    #[test]
    fn setresuid2_each_failed_drop_call_is_a_privilege_drop_error_naming_it() {
        let made = ["geteuid", "setgroups", "setresgid", "setresuid"];
        for (failing, step) in made.iter().enumerate().skip(1) {
            let mut ids = FakeIds {
                fail: Some(*step),
                ..FakeIds::all(0)
            };
            let err = drop_ids(&mut ids, &to(4242, 4343)).unwrap_err();
            assert!(
                matches!(&err, SandboxError::PrivilegeDrop { uid: 4242, gid: 4343, step: named, source }
                    if named == step && source.raw_os_error() == Some(libc::EPERM)),
                "{err}"
            );
            assert_eq!(
                err.to_string(),
                format!(
                    "privilege drop to 4242:4343 failed at {step}: Operation not permitted (os error 1)"
                )
            );
            assert_eq!(ids.calls(), made[..=failing], "nothing after {step}");
        }
    }

    /// uid `-1` is setresuid(2)'s "unchanged", so root stays; uid 0 is
    /// root itself, so root can come back.
    #[test]
    fn setresuid2_unchanged_or_root_ids_are_still_privileged() {
        let mut ids = FakeIds::all(0);
        let err = drop_ids(&mut ids, &to(u32::MAX, u32::MAX)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "still privileged after dropping to 4294967295:4294967295"
        );
        assert_eq!(
            ids.calls().last(),
            Some(&"getids"),
            "refused by the id check"
        );

        let mut ids = FakeIds::all(0);
        let err = drop_ids(&mut ids, &to(0, 0)).unwrap_err();
        assert!(
            matches!(err, SandboxError::StillPrivileged { uid: 0, gid: 0 }),
            "{err}"
        );
        assert_eq!(
            ids.calls().last(),
            Some(&"setresuid"),
            "refused by the return to root"
        );
    }

    /// Each wrapper makes its call on this test's thread. Unprivileged
    /// (as CI runs) the calls that change ids to another one are refused
    /// with `EPERM`; as root they succeed, ending root for this thread.
    #[test]
    fn setresuid2_the_thread_wrappers_make_the_real_calls() {
        let mut thread = ThreadIds;
        let ids = thread.ids();
        let (uid, gid) = (crate::current_uid(), crate::current_gid());
        let effective = rustix::process::geteuid().as_raw();
        let kernel = (uid, effective, gid, rustix::process::getegid().as_raw());
        assert_eq!(ids, kernel);
        let refused = (effective != 0).then_some(Errno::PERM);
        assert_eq!(thread.clear_groups().err(), refused);
        assert_eq!(thread.set_gids(gid.wrapping_add(1)).err(), refused);
        assert_eq!(thread.set_uids(uid.wrapping_add(1)).err(), refused);
    }

    /// The thread's effective capabilities without `CAP_SETUID` and
    /// `CAP_SETGID`: root by uid, but unable to change its ids.
    fn without_setid_capabilities() {
        let mut sets = rustix::thread::capabilities(None).unwrap();
        sets.effective
            .remove(rustix::thread::CapabilitySet::SETUID | rustix::thread::CapabilitySet::SETGID);
        rustix::thread::set_capabilities(None, sets).unwrap();
    }

    /// Root without the capabilities to change ids fails the drop's first
    /// call (setgroups(2), `EPERM`); unprivileged there is nothing to
    /// drop. Per thread: it ends with this test's thread.
    #[test]
    fn setresuid2_a_failed_drop_call_is_a_privilege_drop_error() {
        let root = rustix::process::geteuid().is_root();
        let own = (crate::current_uid(), crate::current_gid());
        without_setid_capabilities();
        let config = SandboxConfig {
            uid: 4242,
            gid: 4343,
            ..SandboxConfig::default()
        };
        let result = drop_privileges(&config);
        let refused = result.as_ref().err().map(ToString::to_string);
        let expected =
            "privilege drop to 4242:4343 failed at setgroups: Operation not permitted (os error 1)";
        assert_eq!(result.ok(), (!root).then_some(own));
        assert_eq!(refused.as_deref(), root.then_some(expected));
    }

    /// Two configurations that would leave root: uid `-1`, which
    /// setresuid(2) reads as "unchanged", and uid 0, which root can return
    /// to. Unprivileged there is nothing to drop. Per thread: it ends with
    /// this test's thread.
    #[test]
    fn setresuid2_a_drop_that_leaves_root_is_still_privileged() {
        let root = rustix::process::geteuid().is_root();
        let own = (crate::current_uid(), crate::current_gid());
        for id in [u32::MAX, 0] {
            let config = SandboxConfig {
                uid: id,
                gid: id,
                ..SandboxConfig::default()
            };
            let result = drop_privileges(&config);
            let refused = result.as_ref().err().map(ToString::to_string);
            let expected = format!("still privileged after dropping to {id}:{id}");
            assert_eq!(result.ok(), (!root).then_some(own));
            assert_eq!(refused, root.then_some(expected));
        }
    }

    #[test]
    fn landlock7_abi_4_is_probed_with_the_tcp_rights_an_abi_3_kernel_lacks() {
        let (fs3, net3) = probe_rights(3);
        let (fs4, net4) = probe_rights(4);
        // ABI 4 adds no filesystem right: a filesystem probe alone cannot
        // tell 3 from 4.
        assert_eq!(fs3, fs4);
        assert_eq!(net4, Some(AccessNet::BindTcp | AccessNet::ConnectTcp));
        assert_eq!(net3, None);
        for abi in 1..=2 {
            let (fs, net) = probe_rights(abi);
            assert_eq!(fs, AccessFs::from_all(abi_of(abi)));
            assert_eq!(net, None, "ABI {abi}");
        }
        assert_ne!(probe_rights(1).0, probe_rights(2).0);
    }

    /// Whether this kernel creates a ruleset handling `fs` and `net`, as
    /// a hard requirement.
    fn creates(fs: BitFlags<AccessFs>, net: Option<BitFlags<AccessNet>>) -> bool {
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(fs)
            .unwrap();
        match net {
            Some(net) => ruleset.handle_access(net).unwrap().create().is_ok(),
            None => ruleset.create().is_ok(),
        }
    }

    #[test]
    fn landlock7_the_probe_reports_abi_4_exactly_when_the_kernel_handles_tcp_rights() {
        let abi = probe_abi();
        let tcp = creates(
            AccessFs::from_all(ABI::V1),
            Some(AccessNet::from_all(ABI::V4)),
        );
        assert_eq!(abi == 4, tcp, "probed ABI {abi}");
        let fs = creates(AccessFs::from_all(ABI::V1), None);
        assert_eq!(abi > 0, fs, "probed ABI {abi}");
    }
}
