//! The non-Linux stand-in: nothing is enforced, and the report says so.
//! macOS is a development host only.

use crate::report::{LandlockReport, LayerStatus};
use crate::{Mode, Profile, SandboxConfig, SandboxError, SandboxReport};

/// Reports every layer unavailable; refuses `require`, and refuses to run
/// as root since there is no privilege drop to protect it.
pub(crate) fn apply(
    profile: &Profile,
    config: &SandboxConfig,
) -> Result<SandboxReport, SandboxError> {
    let (uid, gid) = drop_privileges(config)?;
    let reason = format!(
        "process isolation is Linux-only; the {} runs without seccomp and Landlock on this platform",
        profile.name()
    );
    if config.mode == Mode::Require {
        return Err(SandboxError::Required {
            layer: "sandbox",
            reason,
        });
    }
    tracing::warn!(profile = profile.name(), "{reason}");
    Ok(SandboxReport {
        mode: config.mode,
        uid,
        gid,
        no_new_privs: false,
        seccomp: LayerStatus::Unavailable,
        landlock: LandlockReport {
            fs: LayerStatus::Unavailable,
            net: LayerStatus::Unavailable,
            abi: 0,
        },
        notes: vec![reason],
    })
}

/// The stand-in for the Linux privilege drop, which every mode runs: there
/// is none here, so a process started as root is refused in every mode
/// rather than left running as root. Returns the real ids otherwise.
pub(crate) fn drop_privileges(_config: &SandboxConfig) -> Result<(u32, u32), SandboxError> {
    if rustix::process::geteuid().is_root() {
        return Err(SandboxError::RootUnsupported);
    }
    Ok((crate::current_uid(), crate::current_gid()))
}
