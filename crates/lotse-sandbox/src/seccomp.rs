//! The seccomp-bpf allowlists per process kind (seccomp(2)). Anything not
//! listed kills the process; a worker's `socket` is limited to
//! `AF_INET`/`AF_INET6` and its `clone` to threads, and no worker or
//! decoder may `execve`, `ptrace` or read another process's memory.
//!
//! Every lotse process runs as one uid, so a call that takes a pid reaches
//! every other lotse process unless the filter stops it: a worker's or
//! decoder's `tgkill` (tgkill(2)) is limited to its own thread group, a
//! worker's `prlimit64` (prlimit(2)) to reading its own limits and its
//! `prctl` (prctl(2)) to thread names, and neither may ask for its parent's
//! pid. Only the supervisor keeps them unconditional: its children call
//! `prctl` and `prlimit64` under its inherited filter while they sandbox
//! themselves, and it signals its children with `kill` anyway.
//!
//! Every worker also holds the shared WebRTC UDP socket, one open file
//! description with the supervisor, which receives every viewer's datagrams
//! on it. A worker's filter lets it send on that socket and nothing else:
//! the socket sits at a fixed number ([`crate::WORKER_SHARED_UDP_FD`]),
//! the filter denies receiving from it and changing or duplicating it
//! there, and it keeps the socket from coming back under another number
//! (`descriptor_rules`).
//!
//! A coverage build (`--cfg coverage`, which cargo-llvm-cov sets) also
//! lets a worker read its parent-death signal and set it to none or
//! `SIGKILL`, which the profiler runtime does when it writes its profile at
//! exit ([`profile_writer`]). No other build carries the rule: a worker
//! that clears the signal outlives the supervisor and keeps the shared UDP
//! port.
//!
//! Two filters are installed: first one that answers `clone3` with
//! `ENOSYS`, so a glibc-linked test binary falls back to `clone`, then the
//! allowlist. The kernel applies the strictest verdict, so the allowlist
//! must allow `clone3` for the first filter's `ENOSYS` to be the answer.
//! The allowlist is the last syscall-affecting step of a worker or decoder:
//! `seccomp(2)` is not in theirs.
//!
//! Filters are inherited by children and kept across `execve` (seccomp(2),
//! `SECCOMP_SET_MODE_FILTER`), so the supervisor's allowlist
//! also bounds every worker it starts: it must allow what a worker does
//! before its own allowlist is in place, which is applying its Landlock
//! rulesets and its filters. Both only ever restrict the calling process.

use std::collections::BTreeMap;
use std::io;

use seccompiler::{
    BackendError, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

use crate::report::LayerStatus;
use crate::{Mode, Profile, SandboxError, WORKER_CONTROL_FD, WORKER_SHARED_UDP_FD};

/// Builds and installs the profile's filters for the architecture named
/// `arch` (`std::env::consts::ARCH`); seccompiler 0.5.0 has backends for
/// `x86_64`, `aarch64` and `riscv64` only.
pub(crate) fn apply(
    profile: &Profile,
    mode: Mode,
    arch: &str,
    notes: &mut Vec<String>,
) -> Result<LayerStatus, SandboxError> {
    let arch = match TargetArch::try_from(arch) {
        Ok(arch) => arch,
        Err(err) => {
            let reason = format!("seccomp: no allowlist for this architecture: {err}");
            if mode == Mode::Require {
                return Err(SandboxError::Required {
                    layer: "seccomp",
                    reason,
                });
            }
            notes.push(reason);
            return Ok(LayerStatus::Unavailable);
        }
    };
    let errno_filter = errno_filter(arch).map_err(seccomp_step)?;
    let own_pid = rustix::process::getpid().as_raw_nonzero().get();
    let allowlist = allowlist(profile, arch, own_pid, PROFILED).map_err(seccomp_step)?;
    let installed = seccompiler::apply_filter(&errno_filter)
        .and_then(|()| seccompiler::apply_filter(&allowlist));
    match installed {
        Ok(()) => Ok(LayerStatus::Enforced),
        Err(err) => {
            let reason = format!("seccomp: the kernel or container refused the filter: {err}");
            if mode == Mode::Require {
                return Err(SandboxError::Required {
                    layer: "seccomp",
                    reason,
                });
            }
            notes.push(reason);
            Ok(LayerStatus::Unavailable)
        }
    }
}

/// A seccompiler error (building or installing) as a step error.
fn seccomp_step<E: std::error::Error + Send + Sync + 'static>(err: E) -> SandboxError {
    SandboxError::Step {
        step: "seccomp",
        source: io::Error::other(err),
    }
}

/// `clone3` → `ENOSYS`, everything else untouched.
fn errno_filter(arch: TargetArch) -> Result<BpfProgram, BackendError> {
    let mut rules = BTreeMap::new();
    rules.insert(libc::SYS_clone3, Vec::new());
    let enosys = u32::try_from(libc::ENOSYS).unwrap_or(38);
    compile(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(enosys),
        arch,
    )
}

/// The BPF program that answers the calls in `rules` (each matching one of
/// its rules) with `matched` and every other call with `mismatched`.
/// seccompiler refuses identical actions.
fn compile(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    mismatched: SeccompAction,
    matched: SeccompAction,
    arch: TargetArch,
) -> Result<BpfProgram, BackendError> {
    SeccompFilter::new(rules, mismatched, matched, arch)?.try_into()
}

/// Whether this build carries the LLVM profiler runtime, which writes the
/// coverage profile at exit: cargo-llvm-cov builds with `--cfg coverage`.
const PROFILED: bool = cfg!(coverage);

/// The profile's allowlist for the process `own_pid`, the caller; anything
/// else kills the process. `profiled` adds a worker's [`profile_writer`]
/// rules, and only [`PROFILED`] builds pass it.
fn allowlist(
    profile: &Profile,
    arch: TargetArch,
    own_pid: libc::pid_t,
    profiled: bool,
) -> Result<BpfProgram, BackendError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let allow = |rules: &mut BTreeMap<i64, Vec<SeccompRule>>, numbers: &[i64]| {
        for number in numbers {
            rules.insert(*number, Vec::new());
        }
    };
    match profile {
        Profile::Supervisor { .. } => {
            allow(&mut rules, COMMON);
            allow(&mut rules, DESCRIPTOR_CALLS);
            allow(&mut rules, ARCH_SPECIFIC);
            allow(&mut rules, ARCH_DESCRIPTOR_CALLS);
            allow(&mut rules, SUPERVISOR);
        }
        Profile::Worker { .. } => {
            allow(&mut rules, COMMON);
            allow(&mut rules, ARCH_SPECIFIC);
            allow(&mut rules, WORKER);
            rules.extend(descriptor_rules()?);
            rules.insert(libc::SYS_socket, inet_only()?);
            rules.insert(libc::SYS_clone, threads_only()?);
            rules.insert(libc::SYS_tgkill, own_thread_group(own_pid)?);
            rules.insert(libc::SYS_prlimit64, read_own_limits()?);
            let mut prctl = thread_names()?;
            if profiled {
                prctl.extend(profile_writer()?);
            }
            rules.insert(libc::SYS_prctl, prctl);
        }
        Profile::Decoder => {
            allow(&mut rules, DECODER);
            rules.insert(libc::SYS_tgkill, own_thread_group(own_pid)?);
        }
    }
    compile(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
}

/// A syscall argument value; a negative constant becomes a value no
/// argument matches, so a mistake denies rather than allows.
fn arg(value: libc::c_int) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// `socket(domain, ..)` with `domain` `AF_INET` or `AF_INET6`.
fn inet_only() -> Result<Vec<SeccompRule>, BackendError> {
    [libc::AF_INET, libc::AF_INET6]
        .into_iter()
        .map(|domain| SeccompRule::new(vec![equals(0, SeccompCmpArgLen::Dword, arg(domain))?]))
        .collect()
}

/// `clone(flags, ..)` with `CLONE_THREAD` set: a thread, never a process.
fn threads_only() -> Result<Vec<SeccompRule>, BackendError> {
    let thread = arg(libc::CLONE_THREAD);
    let has_thread = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::MaskedEq(thread),
        thread,
    );
    Ok(vec![SeccompRule::new(vec![has_thread?])?])
}

/// `tgkill(tgid, ..)` with `tgid` the caller's own pid: a signal to one of
/// its own threads, which is how glibc's `raise` and `pthread_kill` signal
/// (tgkill(2)), never to another process. `tgid` is a `pid_t`, so the
/// kernel reads the argument's low 32 bits and so does the comparison.
fn own_thread_group(own_pid: libc::pid_t) -> Result<Vec<SeccompRule>, BackendError> {
    let tgid = equals(0, SeccompCmpArgLen::Dword, arg(own_pid))?;
    Ok(vec![SeccompRule::new(vec![tgid])?])
}

/// `prlimit64(0, resource, NULL, old)`: the caller reading its own limits,
/// which is how glibc's, musl's and rustix's `getrlimit` read them
/// (prlimit(2): pid 0 is the caller, a null `new_limit` changes nothing).
/// Every limit is set before the allowlist, so nothing is left to change,
/// and another process's limits are out of reach.
fn read_own_limits() -> Result<Vec<SeccompRule>, BackendError> {
    let caller = equals(0, SeccompCmpArgLen::Dword, 0)?;
    let no_new_limit = equals(2, SeccompCmpArgLen::Qword, 0)?;
    Ok(vec![SeccompRule::new(vec![caller, no_new_limit])?])
}

/// `prctl(option, ..)` with `option` `PR_SET_NAME` or `PR_GET_NAME`: the
/// standard library and the runtime name their threads (prctl(2)). Every
/// other option is closed, so `PR_SET_DUMPABLE` and `PR_SET_PDEATHSIG`, set
/// before the allowlist, cannot be undone.
fn thread_names() -> Result<Vec<SeccompRule>, BackendError> {
    [libc::PR_SET_NAME, libc::PR_GET_NAME]
        .into_iter()
        .map(|option| SeccompRule::new(vec![equals(0, SeccompCmpArgLen::Dword, arg(option))?]))
        .collect()
}

/// `prctl(PR_GET_PDEATHSIG, ..)`, and `prctl(PR_SET_PDEATHSIG, signal)`
/// with `signal` 0 or `SIGKILL`: what the LLVM profiler runtime does around
/// writing its profile at exit, as observed in compiler-rt 22.1.8 (Rust
/// 1.98.0) on 2026-10-09 (`lib/profile/InstrProfilingUtil.c`,
/// `lprofSuspendSigKill` and `lprofRestoreSigKill`): it reads the signal
/// and, when it is `SIGKILL`, clears it for the write and sets it again.
/// Only a coverage build adds these rules ([`PROFILED`]). `option` is an
/// `int` and the kernel reads the signal as an `unsigned long` (prctl(2)),
/// so the comparisons do too.
fn profile_writer() -> Result<Vec<SeccompRule>, BackendError> {
    let option = |option: libc::c_int| equals(0, SeccompCmpArgLen::Dword, arg(option));
    let set_to = |signal: libc::c_int| {
        SeccompRule::new(vec![
            option(libc::PR_SET_PDEATHSIG)?,
            equals(1, SeccompCmpArgLen::Qword, arg(signal))?,
        ])
    };
    Ok(vec![
        SeccompRule::new(vec![option(libc::PR_GET_PDEATHSIG)?])?,
        set_to(0)?,
        set_to(libc::SIGKILL)?,
    ])
}

/// A worker's rules for [`DESCRIPTOR_CALLS`] and [`ARCH_DESCRIPTOR_CALLS`].
///
/// On [`WORKER_SHARED_UDP_FD`] it may send (`sendto`, `sendmsg`) and close,
/// nothing else: no receive, no `connect`, `shutdown`, `setsockopt`,
/// `ioctl` or `fcntl` but `F_GETFD`, and no `dup`, `dup2` or `dup3` from
/// it. Every other
/// descriptor keeps these calls.
///
/// Numbers alone do not hold if the socket can come back under another
/// one: a worker could send it by `SCM_RIGHTS` on a socketpair of its own,
/// its runtime's included, and receive the copy. So `sendmsg` and
/// `sendmmsg`, the only calls that carry `SCM_RIGHTS`, are limited to
/// [`WORKER_CONTROL_FD`], whose peer is the supervisor, and to the shared
/// socket itself, where the kernel refuses them (an inet socket takes no
/// `SCM_RIGHTS`); and the control channel cannot be closed or replaced by
/// `dup2`/`dup3`, so that number never names a socket of the worker's own.
/// Every other send is `sendto`, `write` or `writev`.
///
/// A descriptor is an `int` (`unsigned int` for some calls) and the kernel
/// reads the argument's low 32 bits, so the comparisons do too.
fn descriptor_rules() -> Result<Vec<(i64, Vec<SeccompRule>)>, BackendError> {
    let shared = arg(WORKER_SHARED_UDP_FD);
    let control = arg(WORKER_CONTROL_FD);
    let fd_is = |fd: u64| equals(0, SeccompCmpArgLen::Dword, fd);
    let fd_is_not = |index: u8, fd: u64| differs(index, SeccompCmpArgLen::Dword, fd);
    let mut rules = Vec::new();
    for number in [
        libc::SYS_read,
        libc::SYS_readv,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_connect,
        libc::SYS_shutdown,
        libc::SYS_setsockopt,
        libc::SYS_ioctl,
        libc::SYS_dup,
    ] {
        rules.push((number, vec![SeccompRule::new(vec![fd_is_not(0, shared)?])?]));
    }
    // `F_GETFD` reads the descriptor's own close-on-exec flag, not the
    // description: the standard library's debug builds check it before
    // they close a descriptor (`OwnedFd`'s drop).
    let get_fd = equals(1, SeccompCmpArgLen::Dword, arg(libc::F_GETFD))?;
    rules.push((
        libc::SYS_fcntl,
        vec![
            SeccompRule::new(vec![fd_is_not(0, shared)?])?,
            SeccompRule::new(vec![get_fd])?,
        ],
    ));
    let mut renumbering = vec![libc::SYS_dup3];
    renumbering.extend(ARCH_DESCRIPTOR_CALLS);
    for number in renumbering {
        let rule = SeccompRule::new(vec![fd_is_not(0, shared)?, fd_is_not(1, control)?])?;
        rules.push((number, vec![rule]));
    }
    rules.push((
        libc::SYS_close,
        vec![SeccompRule::new(vec![fd_is_not(0, control)?])?],
    ));
    for number in [libc::SYS_sendmsg, libc::SYS_sendmmsg] {
        let to_supervisor = SeccompRule::new(vec![fd_is(control)?])?;
        let on_shared = SeccompRule::new(vec![fd_is(shared)?])?;
        rules.push((number, vec![to_supervisor, on_shared]));
    }
    Ok(rules)
}

/// Argument `index`, read as `len`, differs from `value`.
fn differs(index: u8, len: SeccompCmpArgLen, value: u64) -> Result<SeccompCondition, BackendError> {
    SeccompCondition::new(index, len, SeccompCmpOp::Ne, value)
}

/// Argument `index`, read as `len`, equals `value`.
fn equals(index: u8, len: SeccompCmpArgLen, value: u64) -> Result<SeccompCondition, BackendError> {
    SeccompCondition::new(index, len, SeccompCmpOp::Eq, value)
}

/// What every lotse process needs: I/O on inherited descriptors, memory,
/// threads and their synchronization, signals, time, sockets it already
/// has, the event loop, and exiting.
const COMMON: &[i64] = &[
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_lseek,
    libc::SYS_openat,
    libc::SYS_readlinkat,
    libc::SYS_faccessat,
    libc::SYS_getdents64,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_pipe2,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getrandom,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_rseq,
    libc::SYS_membarrier,
    libc::SYS_restart_syscall,
    libc::SYS_uname,
    libc::SYS_socketpair,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept4,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_getsockopt,
    libc::SYS_sendto,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_eventfd2,
    libc::SYS_ppoll,
    libc::SYS_pselect6,
    libc::SYS_clone3,
];

/// The calls that take a descriptor and would let a worker receive from
/// the shared socket, change its open file description, give it another
/// number or pass it on: every process but the decoder needs them, and a
/// worker gets them under [`descriptor_rules`]. Receiving covers `read`
/// and `readv` too, which take a datagram from a socket (socket(7)); the
/// description is changed by `connect` (an unconnect, `AF_UNSPEC`,
/// included), `shutdown`, `setsockopt`, `ioctl` (`FIONBIO`, `FIOASYNC`,
/// `FIOSETOWN`) and `fcntl` (`F_SETFL`, `F_SETOWN`); the number by `dup`,
/// `dup3` and `fcntl` (`F_DUPFD`); and `sendmsg`/`sendmmsg` carry
/// `SCM_RIGHTS` (unix(7)).
const DESCRIPTOR_CALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_readv,
    libc::SYS_recvfrom,
    libc::SYS_recvmsg,
    libc::SYS_recvmmsg,
    libc::SYS_connect,
    libc::SYS_shutdown,
    libc::SYS_setsockopt,
    libc::SYS_ioctl,
    libc::SYS_fcntl,
    libc::SYS_dup,
    libc::SYS_dup3,
    libc::SYS_close,
    libc::SYS_sendmsg,
    libc::SYS_sendmmsg,
];

/// [`DESCRIPTOR_CALLS`] only x86-64 has: `dup2`, which aarch64 lacks.
#[cfg(target_arch = "x86_64")]
const ARCH_DESCRIPTOR_CALLS: &[i64] = &[libc::SYS_dup2];

/// See the x86-64 list.
#[cfg(not(target_arch = "x86_64"))]
const ARCH_DESCRIPTOR_CALLS: &[i64] = &[];

/// Legacy syscalls x86-64 libcs still use where aarch64 has only the new
/// forms.
#[cfg(target_arch = "x86_64")]
const ARCH_SPECIFIC: &[i64] = &[
    libc::SYS_open,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_access,
    libc::SYS_readlink,
    libc::SYS_poll,
    libc::SYS_select,
    libc::SYS_epoll_create,
    libc::SYS_epoll_wait,
    libc::SYS_eventfd,
    libc::SYS_pipe,
    libc::SYS_arch_prctl,
    libc::SYS_getrlimit,
    libc::SYS_time,
];

/// See the x86-64 list; aarch64 needs nothing beyond the common set.
#[cfg(not(target_arch = "x86_64"))]
const ARCH_SPECIFIC: &[i64] = &[];

/// What only the supervisor does: spawn, signal and reap processes
/// (`pidfd_open` is how tokio waits for a child), open any socket family,
/// hand keyframes over by memfd. Its children inherit this filter, so it
/// also allows what they need to sandbox themselves: `prlimit64` and
/// `prctl` for their limits and flags, the Landlock calls and `seccomp`,
/// which can only add restrictions to the caller. `tgkill` and `getppid`
/// are unconditional here only: it may signal any process with `kill`.
const SUPERVISOR: &[i64] = &[
    libc::SYS_getppid,
    libc::SYS_prctl,
    libc::SYS_prlimit64,
    libc::SYS_tgkill,
    libc::SYS_socket,
    libc::SYS_clone,
    libc::SYS_execve,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_pidfd_open,
    libc::SYS_kill,
    libc::SYS_memfd_create,
    libc::SYS_ftruncate,
    libc::SYS_landlock_create_ruleset,
    libc::SYS_landlock_add_rule,
    libc::SYS_landlock_restrict_self,
    libc::SYS_seccomp,
];

/// What a worker does beyond the common set (`socket`, `clone`, `tgkill`,
/// `prlimit64` and `prctl` are added with conditions).
const WORKER: &[i64] = &[libc::SYS_memfd_create, libc::SYS_ftruncate];

/// A decoder: read its input, write its output, memory, and exit
/// (`tgkill` is added with a condition).
const DECODER: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_futex,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_sched_yield,
    libc::SYS_clock_gettime,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_getrandom,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use seccompiler::sock_filter;

    use super::*;

    /// The pid the filters under test are built for.
    const OWN: libc::pid_t = 4242;

    /// Another lotse process, the supervisor say.
    const OTHER: libc::pid_t = 4241;

    /// `AUDIT_ARCH_X86_64` (linux/audit.h): `EM_X86_64` (62) with the 64-bit and
    /// little-endian flags.
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0x3e | 0x8000_0000 | 0x4000_0000;

    /// `AUDIT_ARCH_AARCH64` (linux/audit.h): `EM_AARCH64` (183) with the 64-bit and
    /// little-endian flags.
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xb7 | 0x8000_0000 | 0x4000_0000;

    /// The verdict `program` returns for syscall `nr` with `args`: a classic
    /// BPF interpreter (Documentation/networking/filter.rst) for the
    /// instructions seccompiler emits, over the `struct seccomp_data` the
    /// kernel hands a filter (seccomp(2): `nr` at 0, `arch` at 4, the
    /// instruction pointer at 8, the six arguments from 16, little-endian
    /// on both targets).
    fn verdict(program: &[sock_filter], nr: i64, args: [u64; 6]) -> u32 {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&u32::try_from(nr).unwrap().to_le_bytes());
        data.extend_from_slice(&AUDIT_ARCH.to_le_bytes());
        data.extend_from_slice(&0_u64.to_le_bytes());
        for arg in args {
            data.extend_from_slice(&arg.to_le_bytes());
        }
        let mut accumulator = 0_u32;
        let mut pc = 0_usize;
        loop {
            let instruction = &program[pc];
            pc += 1;
            let k = instruction.k;
            let jump = |taken: bool| {
                usize::from(if taken {
                    instruction.jt
                } else {
                    instruction.jf
                })
            };
            match instruction.code {
                // BPF_LD | BPF_W | BPF_ABS
                0x20 => {
                    let at = usize::try_from(k).unwrap();
                    accumulator = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                }
                // BPF_ALU | BPF_AND | BPF_K
                0x54 => accumulator &= k,
                // BPF_JMP | BPF_JA
                0x05 => pc += usize::try_from(k).unwrap(),
                // BPF_JMP | BPF_JEQ | BPF_K
                0x15 => pc += jump(accumulator == k),
                code => {
                    assert_eq!(code, 0x06, "BPF_RET | BPF_K is the only other opcode");
                    return k;
                }
            }
        }
    }

    /// The verdict of `profile`'s production allowlist, built for [`OWN`].
    fn allows(profile: &Profile, nr: i64, args: [u64; 6]) -> bool {
        allows_in(profile, false, nr, args)
    }

    /// The verdict of `profile`'s allowlist, built for [`OWN`] in a build
    /// that is `profiled` or not.
    fn allows_in(profile: &Profile, profiled: bool, nr: i64, args: [u64; 6]) -> bool {
        let arch = TargetArch::try_from(std::env::consts::ARCH).unwrap();
        let program = allowlist(profile, arch, OWN, profiled).unwrap();
        let verdict = verdict(&program, nr, args);
        if verdict == u32::from(SeccompAction::Allow) {
            return true;
        }
        assert_eq!(verdict, u32::from(SeccompAction::KillProcess));
        false
    }

    fn supervisor() -> Profile {
        Profile::Supervisor {
            binary: "/lotse".into(),
        }
    }

    fn worker() -> Profile {
        Profile::Worker {
            connect_ports: vec![554],
        }
    }

    #[test]
    fn the_interpreter_agrees_with_the_unconditional_and_conditional_rules() {
        assert!(allows(&worker(), libc::SYS_read, [0; 6]));
        assert!(!allows(&worker(), libc::SYS_execve, [0; 6]));
        let inet = [arg(libc::AF_INET), 0, 0, 0, 0, 0];
        let unix = [arg(libc::AF_UNIX), 0, 0, 0, 0, 0];
        assert!(allows(&worker(), libc::SYS_socket, inet));
        assert!(!allows(&worker(), libc::SYS_socket, unix));
        assert!(allows(&supervisor(), libc::SYS_socket, unix));
        let thread = arg(libc::CLONE_THREAD | libc::CLONE_VM);
        assert!(allows(&worker(), libc::SYS_clone, [thread, 0, 0, 0, 0, 0]));
        assert!(!allows(
            &worker(),
            libc::SYS_clone,
            [arg(libc::SIGCHLD), 0, 0, 0, 0, 0]
        ));
    }

    /// Regression for SBX-3: one uid for every process, so an
    /// unconditional `tgkill(supervisor, supervisor, SIGKILL)` from a
    /// worker or decoder ended the supervisor (tgkill(2): the main thread's
    /// tid is the pid).
    #[test]
    fn tgkill_reaches_only_the_callers_own_thread_group() {
        let kill = arg(libc::SIGKILL);
        for profile in [worker(), Profile::Decoder] {
            let name = profile.name();
            let own = [arg(OWN), arg(OWN + 1), kill, 0, 0, 0];
            let other = [arg(OTHER), arg(OTHER), kill, 0, 0, 0];
            assert!(allows(&profile, libc::SYS_tgkill, own), "{name}");
            assert!(!allows(&profile, libc::SYS_tgkill, other), "{name}");
            assert!(!allows(&profile, libc::SYS_tkill, other), "{name}");
            assert!(!allows(&profile, libc::SYS_kill, other), "{name}");
        }
        let other = [arg(OTHER), arg(OTHER), kill, 0, 0, 0];
        assert!(allows(&supervisor(), libc::SYS_tgkill, other));
    }

    /// Regression for SBX-3: an unconditional `prlimit64` let a worker lower
    /// the supervisor's limits. Reading its own (`getrlimit`) still works;
    /// the supervisor, whose children set their limits under its filter,
    /// keeps the call whole.
    #[test]
    fn prlimit_lets_a_worker_read_only_its_own_limits() {
        // RLIMIT_NOFILE (asm-generic/resource.h); libc types it per libc.
        let nofile = 7;
        let buffer = 0x7fff_0000_u64;
        let read_own = [0, nofile, 0, buffer, 0, 0];
        let set_own = [0, nofile, buffer, 0, 0, 0];
        let set_other = [arg(OTHER), nofile, buffer, 0, 0, 0];
        let read_other = [arg(OTHER), nofile, 0, buffer, 0, 0];
        let read_own_high = [0, nofile, 1 << 32, buffer, 0, 0];
        assert!(allows(&worker(), libc::SYS_prlimit64, read_own));
        assert!(!allows(&worker(), libc::SYS_prlimit64, set_own));
        assert!(!allows(&worker(), libc::SYS_prlimit64, set_other));
        assert!(!allows(&worker(), libc::SYS_prlimit64, read_other));
        assert!(!allows(&worker(), libc::SYS_prlimit64, read_own_high));
        assert!(!allows(&Profile::Decoder, libc::SYS_prlimit64, read_own));
        assert!(allows(&supervisor(), libc::SYS_prlimit64, set_own));
    }

    /// Regression for SBX-3: a worker's unconditional `prctl` could undo
    /// what `apply` set before the allowlist; thread names still work.
    #[test]
    fn prctl_lets_a_worker_name_its_threads_only() {
        let option = |option: libc::c_int| [arg(option), 0, 0, 0, 0, 0];
        assert!(allows(
            &worker(),
            libc::SYS_prctl,
            option(libc::PR_SET_NAME)
        ));
        assert!(allows(
            &worker(),
            libc::SYS_prctl,
            option(libc::PR_GET_NAME)
        ));
        for closed in [
            libc::PR_SET_DUMPABLE,
            libc::PR_SET_PDEATHSIG,
            libc::PR_SET_NO_NEW_PRIVS,
        ] {
            assert!(
                !allows(&worker(), libc::SYS_prctl, option(closed)),
                "{closed}"
            );
            assert!(
                allows(&supervisor(), libc::SYS_prctl, option(closed)),
                "{closed}"
            );
        }
    }

    /// Regression for the coverage gate after SBX-3: the profiler runtime
    /// reads, clears and restores a worker's parent-death signal around
    /// writing its profile, and the thread-name rule killed every sandboxed
    /// worker of a coverage build at exit. A coverage build opens exactly
    /// those calls to a worker; every other build keeps them closed.
    #[test]
    fn only_a_coverage_build_lets_a_worker_handle_its_parent_death_signal() {
        assert_eq!(PROFILED, cfg!(coverage));
        let call = |option: libc::c_int, value: u64| [arg(option), value, 0, 0, 0, 0];
        let kill = arg(libc::SIGKILL);
        let profiler = [
            call(libc::PR_GET_PDEATHSIG, 0x7fff_0000),
            call(libc::PR_SET_PDEATHSIG, 0),
            call(libc::PR_SET_PDEATHSIG, kill),
        ];
        for args in profiler {
            assert!(
                allows_in(&worker(), true, libc::SYS_prctl, args),
                "{args:?}"
            );
            assert!(!allows(&worker(), libc::SYS_prctl, args), "{args:?}");
            assert!(!allows_in(&Profile::Decoder, true, libc::SYS_prctl, args));
        }
        let never = [
            call(libc::PR_SET_PDEATHSIG, arg(libc::SIGTERM)),
            call(libc::PR_SET_PDEATHSIG, kill | 1 << 32),
            call(libc::PR_SET_DUMPABLE, 1),
            call(libc::PR_SET_NO_NEW_PRIVS, 0),
        ];
        for args in never {
            assert!(
                !allows_in(&worker(), true, libc::SYS_prctl, args),
                "{args:?}"
            );
        }
        // The option is an `int`: high bits do not make it another one.
        let high = [arg(libc::PR_SET_PDEATHSIG) | 1 << 32, 0, 0, 0, 0, 0];
        assert!(allows_in(&worker(), true, libc::SYS_prctl, high));
        assert!(allows_in(
            &worker(),
            true,
            libc::SYS_prctl,
            call(libc::PR_SET_NAME, 0)
        ));
    }

    /// Regression for SBX-3: `getppid` handed a worker the supervisor's pid.
    #[test]
    fn getppid_is_the_supervisors_only() {
        assert!(!allows(&worker(), libc::SYS_getppid, [0; 6]));
        assert!(!allows(&Profile::Decoder, libc::SYS_getppid, [0; 6]));
        assert!(allows(&supervisor(), libc::SYS_getppid, [0; 6]));
    }

    /// The shared socket's number as a syscall argument.
    const SHARED: u64 = 255;

    /// The control channel's number.
    const CONTROL: u64 = 0;

    /// Any other descriptor: a camera's socket, a session's TCP stream.
    const ANY: u64 = 7;

    /// Arguments with `fd` first and, second, another descriptor that is
    /// not the control channel (`dup3`'s new number).
    fn on(fd: u64) -> [u64; 6] {
        [fd, ANY + 1, 0, 0, 0, 0]
    }

    /// Regression for SBX-4: the worker's `recvfrom`, `recvmsg` and
    /// `recvmmsg` were unconditional, so a compromised worker could race
    /// the supervisor's receive thread for every viewer's datagrams on the
    /// shared socket. `read` and `readv` receive too (socket(7)).
    #[test]
    fn a_worker_cannot_receive_from_the_shared_socket() {
        assert_eq!(SHARED, arg(WORKER_SHARED_UDP_FD));
        for receive in [
            libc::SYS_read,
            libc::SYS_readv,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            libc::SYS_recvmmsg,
        ] {
            assert!(!allows(&worker(), receive, on(SHARED)), "{receive}");
            // The kernel reads an `int`: high bits do not make it another fd.
            assert!(
                !allows(&worker(), receive, on(SHARED | 1 << 32)),
                "{receive}"
            );
            assert!(allows(&worker(), receive, on(ANY)), "{receive}");
            assert!(allows(&worker(), receive, on(CONTROL)), "{receive}");
            assert!(allows(&supervisor(), receive, on(SHARED)), "{receive}");
        }
    }

    /// Regression for WRK-8: `connect`, `shutdown` and `setsockopt` were
    /// unconditional, and the socket's open file description is the
    /// supervisor's and every other worker's: one `shutdown` or `connect`
    /// ended the whole WebRTC transport. `ioctl` and `fcntl` change it too
    /// (`FIONBIO`, `FIOASYNC`, `F_SETFL`, `F_SETOWN`), and `dup`, `dup3`
    /// (and `dup2` on x86-64) would give it a number the rules do not name.
    /// Sending and closing its own copy stay.
    #[test]
    fn a_worker_can_only_send_on_the_shared_socket() {
        let mut closed = vec![
            libc::SYS_connect,
            libc::SYS_shutdown,
            libc::SYS_setsockopt,
            libc::SYS_ioctl,
            libc::SYS_fcntl,
            libc::SYS_dup,
            libc::SYS_dup3,
        ];
        closed.extend(ARCH_DESCRIPTOR_CALLS);
        for call in closed {
            assert!(!allows(&worker(), call, on(SHARED)), "{call}");
            assert!(allows(&worker(), call, on(ANY)), "{call}");
            assert!(allows(&supervisor(), call, on(SHARED)), "{call}");
        }
        for send in [libc::SYS_sendto, libc::SYS_sendmsg, libc::SYS_sendmmsg] {
            assert!(allows(&worker(), send, on(SHARED)), "{send}");
        }
        assert!(allows(&worker(), libc::SYS_close, on(SHARED)));
        // fcntl(2): `F_GETFD` reads the descriptor's flag; the description's
        // flags, its owner and a duplicate stay closed.
        let fcntl = |cmd: libc::c_int| [SHARED, arg(cmd), 0, 0, 0, 0];
        assert!(allows(&worker(), libc::SYS_fcntl, fcntl(libc::F_GETFD)));
        for cmd in [
            libc::F_SETFD,
            libc::F_GETFL,
            libc::F_SETFL,
            libc::F_SETOWN,
            libc::F_DUPFD,
            libc::F_DUPFD_CLOEXEC,
        ] {
            assert!(!allows(&worker(), libc::SYS_fcntl, fcntl(cmd)), "{cmd}");
        }
        // Replacing its own copy only loses the worker its egress.
        let onto_shared = [ANY, SHARED, 0, 0, 0, 0];
        assert!(allows(&worker(), libc::SYS_dup3, onto_shared));
    }

    /// Regression for SBX-4: the numbers hold only while the socket cannot
    /// come back under another one, as a copy sent by `SCM_RIGHTS` on a
    /// socketpair of the worker's own would. Only the control channel, to
    /// the supervisor, and the shared socket, which refuses them, carry
    /// `sendmsg`; the control channel stays where it is.
    #[test]
    fn a_worker_passes_descriptors_to_the_supervisor_only() {
        for send in [libc::SYS_sendmsg, libc::SYS_sendmmsg] {
            assert!(allows(&worker(), send, on(CONTROL)), "{send}");
            assert!(!allows(&worker(), send, on(ANY)), "{send}");
            assert!(!allows(&worker(), send, on(ANY | 1 << 32)), "{send}");
            // The low 32 bits are what the kernel reads: still the channel.
            assert!(allows(&worker(), send, on(CONTROL | 1 << 32)), "{send}");
            assert!(allows(&supervisor(), send, on(ANY)), "{send}");
        }
        assert!(allows(&worker(), libc::SYS_sendto, on(ANY)));
        assert!(!allows(&worker(), libc::SYS_close, on(CONTROL)));
        assert!(allows(&worker(), libc::SYS_close, on(ANY)));
        assert!(allows(&supervisor(), libc::SYS_close, on(CONTROL)));
        let mut renumbering = vec![libc::SYS_dup3];
        renumbering.extend(ARCH_DESCRIPTOR_CALLS);
        for call in renumbering {
            assert!(!allows(&worker(), call, [ANY, CONTROL, 0, 0, 0, 0]));
            assert!(allows(&worker(), call, [ANY, ANY + 1, 0, 0, 0, 0]));
            assert!(allows(&worker(), call, [CONTROL, ANY, 0, 0, 0, 0]));
            assert!(allows(&supervisor(), call, [ANY, CONTROL, 0, 0, 0, 0]));
        }
    }

    #[test]
    fn every_descriptor_call_has_a_worker_rule() {
        let rules = descriptor_rules().unwrap();
        let mut numbers: Vec<i64> = rules.iter().map(|(number, _)| *number).collect();
        numbers.sort_unstable();
        let mut expected: Vec<i64> = DESCRIPTOR_CALLS
            .iter()
            .chain(ARCH_DESCRIPTOR_CALLS)
            .copied()
            .collect();
        expected.sort_unstable();
        assert_eq!(numbers, expected);
        for call in DESCRIPTOR_CALLS.iter().chain(ARCH_DESCRIPTOR_CALLS) {
            assert!(!COMMON.contains(call), "{call}");
            assert!(!ARCH_SPECIFIC.contains(call), "{call}");
            assert!(!WORKER.contains(call), "{call}");
        }
    }

    #[test]
    fn every_profile_compiles_to_a_filter() {
        let arch = TargetArch::try_from(std::env::consts::ARCH).unwrap();
        assert!(!errno_filter(arch).unwrap().is_empty());
        let empty = [
            Profile::Supervisor {
                binary: "/lotse".into(),
            },
            Profile::Worker {
                connect_ports: vec![554],
            },
            Profile::Decoder,
        ]
        .map(|profile| allowlist(&profile, arch, OWN, false).unwrap().is_empty());
        assert_eq!(empty, [false; 3], "supervisor, worker, decoder");
    }

    #[test]
    fn seccomp2_an_architecture_without_an_allowlist_is_reported_or_refused() {
        let mut notes = Vec::new();
        let status = apply(&Profile::Decoder, Mode::On, "s390x", &mut notes).unwrap();
        assert_eq!(status, LayerStatus::Unavailable);
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].starts_with("seccomp: no allowlist for this architecture: "),
            "{notes:?}"
        );
        let err = apply(&Profile::Decoder, Mode::Require, "s390x", &mut notes).unwrap_err();
        assert!(
            matches!(&err, SandboxError::Required { layer: "seccomp", reason } if *reason == notes[0]),
            "{err}"
        );
        assert_eq!(notes.len(), 1, "require reports through the error");
    }

    /// As a container's own seccomp profile can, a filter on this test's
    /// thread answers `seccomp(2)` with `EPERM`, so neither of the
    /// profile's filters is installed. Filters apply to the calling thread
    /// only (seccomp(2), without `SECCOMP_FILTER_FLAG_TSYNC`).
    #[test]
    fn seccomp2_a_filter_the_kernel_refuses_is_reported_or_refused() {
        let arch = TargetArch::try_from(std::env::consts::ARCH).unwrap();
        let mut rules = BTreeMap::new();
        rules.insert(libc::SYS_seccomp, Vec::new());
        let eperm = u32::try_from(libc::EPERM).unwrap();
        let refuse = compile(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(eperm),
            arch,
        );
        seccompiler::apply_filter(&refuse.unwrap()).unwrap();

        let worker = Profile::Worker {
            connect_ports: vec![554],
        };
        let mut notes = Vec::new();
        let status = apply(&worker, Mode::On, std::env::consts::ARCH, &mut notes).unwrap();
        assert_eq!(status, LayerStatus::Unavailable);
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].starts_with("seccomp: the kernel or container refused the filter: "),
            "{notes:?}"
        );
        let err = apply(&worker, Mode::Require, std::env::consts::ARCH, &mut notes).unwrap_err();
        assert!(
            matches!(&err, SandboxError::Required { layer: "seccomp", reason } if *reason == notes[0]),
            "{err}"
        );
    }

    /// Installs the supervisor's filters on this test's thread only
    /// (seccomp(2), without `SECCOMP_FILTER_FLAG_TSYNC`); the supervisor's
    /// allowlist keeps what the thread does afterwards, finishing the test.
    #[test]
    fn seccomp2_the_supervisors_filters_install_on_the_calling_thread() {
        let supervisor = Profile::Supervisor {
            binary: "/lotse".into(),
        };
        let mut notes = Vec::new();
        let status = apply(
            &supervisor,
            Mode::Require,
            std::env::consts::ARCH,
            &mut notes,
        );
        assert_eq!(status.unwrap(), LayerStatus::Enforced);
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn a_filter_seccompiler_cannot_build_is_a_seccomp_step_error() {
        let arch = TargetArch::try_from(std::env::consts::ARCH).unwrap();
        let built = compile(
            BTreeMap::new(),
            SeccompAction::Allow,
            SeccompAction::Allow,
            arch,
        );
        let err = built.map_err(seccomp_step).unwrap_err();
        assert!(
            matches!(
                err,
                SandboxError::Step {
                    step: "seccomp",
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            err.to_string(),
            "seccomp failed: `match_action` and `mismatch_action` are equal."
        );
    }

    #[test]
    fn negative_constants_never_match_an_argument() {
        assert_eq!(arg(-1), u64::MAX);
        assert_eq!(arg(libc::AF_INET), 2);
        assert_eq!(inet_only().unwrap().len(), 2);
        assert_eq!(threads_only().unwrap().len(), 1);
    }

    #[test]
    fn lists_do_not_grant_what_the_design_denies() {
        for denied in [
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
        ] {
            assert!(!COMMON.contains(&denied));
            assert!(!SUPERVISOR.contains(&denied));
            assert!(!WORKER.contains(&denied));
            assert!(!DECODER.contains(&denied));
        }
        assert!(!COMMON.contains(&libc::SYS_execve));
        assert!(!WORKER.contains(&libc::SYS_execve));
        for sandboxing in [
            libc::SYS_seccomp,
            libc::SYS_landlock_create_ruleset,
            libc::SYS_landlock_add_rule,
            libc::SYS_landlock_restrict_self,
        ] {
            assert!(
                !COMMON.contains(&sandboxing),
                "only the supervisor's children sandbox themselves"
            );
            assert!(!WORKER.contains(&sandboxing));
        }
        assert!(!COMMON.contains(&libc::SYS_socket), "socket is per profile");
        for reaching in [
            libc::SYS_tgkill,
            libc::SYS_prlimit64,
            libc::SYS_prctl,
            libc::SYS_getppid,
        ] {
            assert!(
                !COMMON.contains(&reaching),
                "conditional outside the supervisor"
            );
            assert!(!WORKER.contains(&reaching));
            assert!(!DECODER.contains(&reaching));
        }
        assert!(!COMMON.contains(&libc::SYS_clone), "clone is per profile");
    }
}
