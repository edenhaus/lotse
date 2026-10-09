//! The Linux implementation: privilege drop, rlimits, `dumpable`, the
//! parent-death signal, `no_new_privs` and Landlock, then the seccomp
//! allowlist from [`crate::seccomp`].
//!
//! Implements setresuid(2)/setgroups(2) for the drop, setrlimit(2),
//! prctl(2) `PR_SET_DUMPABLE`, `PR_SET_PDEATHSIG` and `PR_SET_NO_NEW_PRIVS`,
//! and landlock(7) filesystem rules (ABI 1) and TCP rules (ABI 4). Every
//! Landlock ruleset is best effort: the kernel's ABI is probed first, and
//! what it lacks is reported rather than fatal unless the mode is `require`.

use std::io;
use std::path::Path;

use landlock::{
    ABI, Access as _, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible as _, NetPort,
    PathBeneath, PathFd, Ruleset, RulesetAttr as _, RulesetCreatedAttr as _, RulesetStatus,
};
use rustix::process::{DumpableBehavior, Gid, Resource, Rlimit, Signal, Uid};

use crate::report::{LandlockReport, LayerStatus};
use crate::{
    DECODER_ADDRESS_SPACE, DECODER_CPU_SECONDS, Mode, Profile, SandboxConfig, SandboxError,
    SandboxReport, WORKER_MAX_FILES, seccomp,
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
    let (uid, gid) = drop_privileges(config)?;
    apply_rlimits(profile, config)?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(step("PR_SET_DUMPABLE"))?;
    if !matches!(profile, Profile::Supervisor { .. }) {
        // Workers and decoders die with the supervisor.
        rustix::process::set_parent_process_death_signal(Some(Signal::KILL))
            .map_err(step("PR_SET_PDEATHSIG"))?;
    }
    rustix::thread::set_no_new_privs(true).map_err(step("PR_SET_NO_NEW_PRIVS"))?;
    let landlock = apply_landlock(profile, config.mode, probe_abi(), &mut notes)?;
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
fn step(step: &'static str) -> impl Fn(rustix::io::Errno) -> SandboxError {
    move |errno| SandboxError::Step {
        step,
        source: io::Error::from(errno),
    }
}

/// Drops to the configured uid and gid when running as root, clearing the
/// supplementary groups first, and proves the drop stuck. Returns the
/// real ids afterwards. Every mode runs it, `off` included.
pub(crate) fn drop_privileges(config: &SandboxConfig) -> Result<(u32, u32), SandboxError> {
    if !rustix::process::geteuid().is_root() {
        return Ok((crate::current_uid(), crate::current_gid()));
    }
    // Unchecked: `-1` is setresuid(2)'s and setresgid(2)'s "unchanged", which
    // leaves root in place, and the check below must see it to refuse it
    // (rustix's checked constructor asserts on it in debug builds only).
    let uid = Uid::from_raw_unchecked(config.uid);
    let gid = Gid::from_raw_unchecked(config.gid);
    let failed = |errno: rustix::io::Errno| SandboxError::PrivilegeDrop {
        uid: config.uid,
        gid: config.gid,
        source: io::Error::from(errno),
    };
    rustix::thread::set_thread_groups(&[]).map_err(failed)?;
    rustix::thread::set_thread_res_gid(gid, gid, gid).map_err(failed)?;
    rustix::thread::set_thread_res_uid(uid, uid, uid).map_err(failed)?;

    let still_privileged = SandboxError::StillPrivileged {
        uid: config.uid,
        gid: config.gid,
    };
    let ids = (
        rustix::process::getuid(),
        rustix::process::geteuid(),
        rustix::process::getgid(),
        rustix::process::getegid(),
    );
    if ids != (uid, uid, gid, gid) {
        return Err(still_privileged);
    }
    // The saved ids are gone too, so root cannot come back.
    if rustix::thread::set_thread_res_uid(Uid::ROOT, Uid::ROOT, Uid::ROOT).is_ok() {
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
    for (path, access) in fs_rules(profile) {
        match PathFd::new(path) {
            Ok(fd) => {
                fs_ruleset = fs_ruleset
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(landlock_step)?;
            }
            Err(err) => notes.push(format!("landlock: {} not granted: {err}", path.display())),
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
fn fs_rules(profile: &Profile) -> Vec<(&Path, BitFlags<AccessFs>)> {
    match profile {
        Profile::Supervisor { binary } => vec![
            (Path::new("/etc/resolv.conf"), AccessFs::ReadFile.into()),
            (Path::new("/etc/hosts"), AccessFs::ReadFile.into()),
            (Path::new("/proc"), AccessFs::ReadFile | AccessFs::ReadDir),
            (Path::new("/dev/null"), AccessFs::WriteFile.into()),
            (binary.as_path(), AccessFs::Execute | AccessFs::ReadFile),
        ],
        Profile::Worker { .. } | Profile::Decoder => Vec::new(),
    }
}

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

    use std::os::fd::AsRawFd as _;
    use std::process::{Command, Output};

    use super::*;

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
        let err = apply(&profile, &config).unwrap_err();
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
        let address_space = Some(DECODER_ADDRESS_SPACE);
        assert_eq!(limits(Resource::As), (address_space, address_space));
        let cpu = Some(DECODER_CPU_SECONDS);
        assert_eq!(limits(Resource::Cpu), (cpu, cpu));
        assert_eq!(limits(Resource::Core), (Some(0), Some(0)));
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
        let result = apply_landlock(&Profile::Decoder, Mode::On, 1, &mut notes);
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
        let report = apply_landlock(&Profile::Decoder, Mode::On, 0, &mut notes).unwrap();
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
        let err = apply_landlock(&Profile::Decoder, Mode::Require, 0, &mut notes).unwrap_err();
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
        let report = apply_landlock(&Profile::Decoder, Mode::On, 3, &mut notes).unwrap();
        assert_eq!((report.net, report.abi), (LayerStatus::Unavailable, 3));
        let tcp_note = "landlock.net: TCP rules need ABI 4 (Linux 6.7); this kernel has ABI 3";
        assert!(notes.iter().any(|note| note == tcp_note), "{notes:?}");
        let mut notes = Vec::new();
        let err = apply_landlock(&Profile::Decoder, Mode::Require, 3, &mut notes).unwrap_err();
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
        };
        let mut notes = Vec::new();
        apply_landlock(&profile, Mode::On, 1, &mut notes).unwrap();
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
        };
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
        let outcome = drop_privileges(&config).map_err(|err| err.to_string());
        let refused = "privilege drop to 4242:4343 failed: Operation not permitted (os error 1)";
        assert_eq!(
            outcome.as_ref().ok(),
            (!root).then_some(&own),
            "{outcome:?}"
        );
        assert_eq!(
            outcome.as_ref().err().map(String::as_str),
            root.then_some(refused),
            "{outcome:?}"
        );
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
            let outcome = drop_privileges(&config).map_err(|err| err.to_string());
            let refused = format!("still privileged after dropping to {id}:{id}");
            assert_eq!(
                outcome.as_ref().ok(),
                (!root).then_some(&own),
                "{outcome:?}"
            );
            assert_eq!(outcome.err(), root.then_some(refused));
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
