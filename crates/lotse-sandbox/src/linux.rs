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
    let landlock = apply_landlock(profile, config.mode, &mut notes)?;
    let seccomp = seccomp::apply(profile, config.mode, &mut notes)?;
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
    let uid = Uid::from_raw(config.uid);
    let gid = Gid::from_raw(config.gid);
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

/// Filesystem and TCP rulesets for the profile.
fn apply_landlock(
    profile: &Profile,
    mode: Mode,
    notes: &mut Vec<String>,
) -> Result<LandlockReport, SandboxError> {
    let abi = probe_abi();
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

    use super::*;

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
