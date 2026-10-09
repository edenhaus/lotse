//! What can stop a process from sandboxing itself. Every variant is fatal
//! where it occurs: a process that cannot apply its profile does not serve.

use std::io;

/// Why a profile could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// A privilege-drop syscall failed.
    #[error("privilege drop to {uid}:{gid} failed at {step}: {source}")]
    PrivilegeDrop {
        /// The target uid.
        uid: u32,
        /// The target gid.
        gid: u32,
        /// The call that failed (`setgroups`, `setresgid`, `setresuid`).
        step: &'static str,
        /// The syscall's error.
        #[source]
        source: io::Error,
    },
    /// The drop went through but the process could still regain privileges.
    #[error("still privileged after dropping to {uid}:{gid}")]
    StillPrivileged {
        /// The target uid.
        uid: u32,
        /// The target gid.
        gid: u32,
    },
    /// A hardening step the kernel supports failed anyway.
    #[error("{step} failed: {source}")]
    Step {
        /// The step (`RLIMIT_CORE`, `PR_SET_DUMPABLE`, `landlock`, ...).
        step: &'static str,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The mode is `require` and a layer is unavailable on this kernel.
    #[error("sandbox layer {layer} is unavailable and the mode is `require`: {reason}")]
    Required {
        /// The layer (`seccomp`, `landlock.fs`, `landlock.net`, or
        /// `sandbox` where no layer exists at all).
        layer: &'static str,
        /// Why.
        reason: String,
    },
    /// Started as root on a platform without the privilege drop.
    #[error("started as root, but the privilege drop is Linux-only; start unprivileged")]
    RootUnsupported,
}
