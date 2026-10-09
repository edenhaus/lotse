//! Applies the worker and the supervisor profile in a child process each
//! and checks what it can still and can no longer do. Linux only; the
//! child is this test binary re-run with an environment variable, since the
//! sandbox is irreversible in a process.

#![cfg(target_os = "linux")]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::panic,
    reason = "test code; the helper outside #[test] functions panics on harness failures"
)]

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Command, ExitStatus, Stdio};

use lotse_sandbox::{LayerStatus, Mode, Profile, SandboxConfig, SandboxReport};
use rustix::net::{
    RecvAncillaryBuffer, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use rustix::process::{DumpableBehavior, Resource, Rlimit};

/// The variable that turns this binary into the probe child.
const PROBE: &str = "LOTSE_SANDBOX_PROBE";

/// The variable that turns this binary into the supervisor probe child.
const SUPERVISOR_PROBE: &str = "LOTSE_SANDBOX_SUPERVISOR_PROBE";

/// The variable that turns this binary into the escape probe child; its
/// value names the one call that reaches beyond the worker, tried last.
const ESCAPE_PROBE: &str = "LOTSE_SANDBOX_ESCAPE_PROBE";

/// The variable that turns this binary into the shared-socket probe child;
/// its value names the one call on the shared socket, tried last.
const SHARED_PROBE: &str = "LOTSE_SANDBOX_SHARED_PROBE";

/// `SIGSYS`, without pulling libc into the test.
const SIGSYS: i32 = 31;

/// The child: sandbox itself as a worker, print the report, then try to
/// read a file and to run a program.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the probe child must try to spawn a process; that is the behavior under test"
)]
fn probe_child() {
    if std::env::var_os(PROBE).is_none() {
        return;
    }
    let profile = Profile::Worker {
        connect_ports: vec![554],
    };
    let report =
        lotse_sandbox::apply(&profile, &SandboxConfig::default()).expect("worker profile applies");
    println!(
        "{}",
        serde_json::to_string(&report).expect("report serializes")
    );
    let open = std::fs::File::open("/etc/hostname")
        .map(drop)
        .map_err(|e| e.kind());
    println!("open:{open:?}");
    // Under the allowlist `execve` kills the process before anything prints.
    let spawned = Command::new("/bin/true").status().map(|s| s.success());
    println!("spawn:{spawned:?}");
}

/// The supervisor probe child: sandbox itself as the supervisor, print the
/// report, then try what spawning a worker needs from the inherited domain
/// (`/dev/null` for its stdout, a pidfd to reap it, a TCP listener on port
/// 0 for its relay) and what it does not (reading `/dev/null`, a fixed TCP
/// port). Last, it does what a worker does under the supervisor's
/// inherited filter and domain: bind its relay, apply the worker profile,
/// and connect to the relay.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the probe child reads the variable that marks it"
)]
fn supervisor_probe_child() {
    if std::env::var_os(SUPERVISOR_PROBE).is_none() {
        return;
    }
    // A port that was free a moment ago, found before the sandbox.
    let fixed = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
        .port();
    let profile = Profile::Supervisor {
        binary: std::env::current_exe().expect("own path"),
    };
    let report = lotse_sandbox::apply(&profile, &SandboxConfig::default())
        .expect("supervisor profile applies");
    println!(
        "{}",
        serde_json::to_string(&report).expect("report serializes")
    );
    let kind = |result: std::io::Result<()>| result.map_err(|e| e.kind());
    let null_write = kind(
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .map(drop),
    );
    println!("null_write:{null_write:?}");
    let null_read = kind(std::fs::File::open("/dev/null").map(drop));
    println!("null_read:{null_read:?}");
    let bind_any = kind(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map(drop));
    println!("bind_any:{bind_any:?}");
    let bind_fixed = kind(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, fixed)).map(drop));
    println!("bind_fixed:{bind_fixed:?}");
    let pidfd = rustix::process::pidfd_open(
        rustix::process::getpid(),
        rustix::process::PidfdFlags::empty(),
    )
    .map(drop);
    println!("pidfd:{pidfd:?}");

    let relay = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("relay");
    let relay_port = relay.local_addr().expect("relay address").port();
    let worker = Profile::Worker {
        connect_ports: vec![relay_port],
    };
    let report = lotse_sandbox::apply(&worker, &SandboxConfig::default())
        .expect("worker profile applies under the supervisor's");
    println!(
        "worker:{}",
        serde_json::to_string(&report).expect("report serializes")
    );
    let relayed = kind(std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, relay_port)).map(drop));
    println!("relay_connect:{relayed:?}");
}

/// The escape probe child: learn the parent's pid, sandbox itself as a
/// worker, do what its runtime still does (name a thread, read its own
/// limits), then try the act the variable names: lower the parent's
/// limits, make itself dumpable again, clear its parent-death signal, or
/// ask for its parent's pid.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the probe child reads the variable that marks it"
)]
fn escape_probe_child() {
    let Some(act) = std::env::var_os(ESCAPE_PROBE) else {
        return;
    };
    // Learnt before the sandbox, as a compromised worker could learn it by
    // trying pids in turn.
    let parent = rustix::process::getppid().expect("a parent");
    let profile = Profile::Worker {
        connect_ports: vec![554],
    };
    let report =
        lotse_sandbox::apply(&profile, &SandboxConfig::default()).expect("worker profile applies");
    println!(
        "{}",
        serde_json::to_string(&report).expect("report serializes")
    );
    let named = std::thread::Builder::new()
        .name("lotse-probe".into())
        .spawn(|| rustix::thread::name().map(std::ffi::CString::into_string))
        .expect("thread spawns")
        .join()
        .expect("thread joins");
    println!("thread_name:{named:?}");
    let files = rustix::process::getrlimit(Resource::Nofile).current;
    println!("nofile:{files:?}");
    let act = act.to_str().expect("act is UTF-8");
    match act {
        "prlimit_parent" => {
            // Zero core size: harmless to the test harness should the call
            // get through, and the same call that would starve a supervisor.
            let none = Rlimit {
                current: Some(0),
                maximum: Some(0),
            };
            let lowered = rustix::process::prlimit(Some(parent), Resource::Core, none).map(drop);
            println!("prlimit_parent:{lowered:?}");
        }
        "dumpable" => {
            let dumpable = rustix::process::set_dumpable_behavior(DumpableBehavior::Dumpable);
            println!("dumpable:{dumpable:?}");
        }
        "pdeathsig" => {
            let cleared = rustix::process::set_parent_process_death_signal(None);
            println!("pdeathsig:{cleared:?}");
        }
        _ => {
            assert_eq!(act, "getppid", "unknown act");
            let asked = rustix::process::getppid();
            println!("getppid:{asked:?}");
        }
    }
}

/// The shared-socket probe child: bind a socket for the supervisor's
/// shared one, a viewer and a camera's socket, sandbox itself as a worker,
/// move the shared socket to its number as a worker does when it arrives,
/// do what a worker still does (send on it, receive on the camera's socket
/// with `recvmsg` as retina does), then try the act the variable names on
/// the shared socket, closing it the one that must get through.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the probe child reads the variable that marks it"
)]
fn shared_probe_child() {
    let Some(act) = std::env::var_os(SHARED_PROBE) else {
        return;
    };
    let any_port = (Ipv4Addr::LOCALHOST, 0);
    let received = UdpSocket::bind(any_port).expect("the shared socket");
    // As the supervisor makes it, so a receive that gets through returns.
    received.set_nonblocking(true).expect("non-blocking");
    let viewer = UdpSocket::bind(any_port).expect("a viewer");
    let camera = UdpSocket::bind(any_port).expect("a camera's socket");
    let profile = Profile::Worker {
        connect_ports: vec![554],
    };
    let report =
        lotse_sandbox::apply(&profile, &SandboxConfig::default()).expect("worker profile applies");
    println!(
        "{}",
        serde_json::to_string(&report).expect("report serializes")
    );
    let pinned = rustix::io::fcntl_dupfd_cloexec(&received, lotse_sandbox::WORKER_SHARED_UDP_FD)
        .expect("the shared socket's number is free");
    println!("pinned:{}", pinned.as_raw_fd());
    drop(received);
    let shared = UdpSocket::from(pinned);
    let viewer_address = viewer.local_addr().expect("viewer address");
    let sent = shared.send_to(b"media", viewer_address);
    println!("send:{sent:?}");
    viewer
        .send_to(b"rtp", camera.local_addr().expect("camera address"))
        .expect("the camera's packet");
    let mut buf = [0_u8; 16];
    let got = rustix::net::recvmsg(
        &camera,
        &mut [IoSliceMut::new(&mut buf)],
        &mut RecvAncillaryBuffer::default(),
        RecvFlags::empty(),
    )
    .map(|message| message.bytes);
    println!("camera_recv:{got:?}");
    let act = act.to_str().expect("act is UTF-8");
    match act {
        "recv" => println!("recv:{:?}", shared.recv_from(&mut buf)),
        "read" => println!("read:{:?}", rustix::io::read(&shared, &mut buf)),
        "connect" => println!("connect:{:?}", shared.connect(viewer_address)),
        "shutdown" => println!(
            "shutdown:{:?}",
            rustix::net::shutdown(&shared, rustix::net::Shutdown::Both)
        ),
        "setsockopt" => println!("setsockopt:{:?}", shared.set_ttl(1)),
        "blocking" => println!("blocking:{:?}", shared.set_nonblocking(false)),
        "dup" => println!("dup:{:?}", shared.try_clone().map(drop)),
        "close" => {
            drop(shared);
            println!("close:Ok(())");
        }
        _ => {
            assert_eq!(act, "pass", "unknown act");
            let (ours, theirs) = UnixStream::pair().expect("a socketpair of its own");
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            let fds = [shared.as_fd()];
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
            let passed = rustix::net::sendmsg(
                &ours,
                &[IoSlice::new(b"x")],
                &mut ancillary,
                SendFlags::empty(),
            );
            println!("pass:{passed:?}");
            drop(theirs);
        }
    }
}

/// Runs this test binary's probe child `test` with `variable` set to
/// `value` and returns its report, stdout, stderr and exit status.
#[expect(
    clippy::disallowed_methods,
    reason = "spawns this test binary as the probe child"
)]
fn run_probe(
    test: &str,
    variable: &str,
    value: &str,
) -> (SandboxReport, String, String, ExitStatus) {
    let output = Command::new(std::env::current_exe().expect("own path"))
        .args(["--exact", test, "--nocapture"])
        .env(variable, value)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("child runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let report_line = stdout
        .lines()
        .find(|line| line.starts_with('{'))
        .unwrap_or_else(|| panic!("no report in child output\nstdout: {stdout}\nstderr: {stderr}"));
    let report: SandboxReport = serde_json::from_str(report_line).expect("report parses");
    (report, stdout, stderr, output.status)
}

/// Regression for SBX-1 (reproduced 2026-10-07 on Linux 7.0): the
/// supervisor's domain, which every worker inherits, denied the
/// `/dev/null` a worker's spawn opens and every TCP `bind`, so no worker
/// started and none could bind its loopback relay; its seccomp filter,
/// also inherited, killed the supervisor at `pidfd_open` and a worker at
/// its first Landlock call.
#[test]
fn a_supervisor_can_spawn_and_its_workers_bind_an_ephemeral_port_only() {
    let (report, stdout, stderr, status) =
        run_probe("supervisor_probe_child", SUPERVISOR_PROBE, "1");
    assert!(status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(report.mode, Mode::On);
    assert!(report.no_new_privs);
    assert!(
        stdout.contains("null_write:Ok(())"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("bind_any:Ok(())"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    let denied = |probe: &str, enforced: bool| {
        let expected = if enforced {
            format!("{probe}:Err(PermissionDenied)")
        } else {
            format!("{probe}:Ok(())")
        };
        assert!(
            stdout.contains(&expected),
            "stdout: {stdout}\nstderr: {stderr}"
        );
    };
    denied("null_read", report.landlock.fs == LayerStatus::Enforced);
    denied("bind_fixed", report.landlock.net == LayerStatus::Enforced);
    assert!(
        stdout.contains("pidfd:Ok(())"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    let worker_line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("worker:"))
        .unwrap_or_else(|| panic!("no worker report\nstdout: {stdout}\nstderr: {stderr}"));
    let worker: SandboxReport = serde_json::from_str(worker_line).expect("report parses");
    assert_eq!(
        (worker.seccomp, worker.landlock.fs, worker.landlock.net),
        (report.seccomp, report.landlock.fs, report.landlock.net),
        "the worker enforces what the supervisor does"
    );
    assert!(
        stdout.contains("relay_connect:Ok(())"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn a_worker_cannot_read_files_or_spawn_processes() {
    let (report, stdout, stderr, status) = run_probe("probe_child", PROBE, "1");
    assert_eq!(report.mode, Mode::On);
    assert!(report.no_new_privs);
    assert_eq!(
        report.landlock.abi > 0,
        report.landlock.fs == LayerStatus::Enforced
    );

    if report.landlock.fs == LayerStatus::Enforced {
        assert!(
            stdout.contains("open:Err(PermissionDenied)"),
            "landlock should deny the read\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
    if report.seccomp == LayerStatus::Enforced {
        assert!(
            !stdout.contains("spawn:"),
            "execve should have killed the child\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(
            status.signal(),
            Some(SIGSYS),
            "killed by SIGSYS\nstdout: {stdout}\nstderr: {stderr}"
        );
    } else {
        assert!(
            stdout.contains("spawn:"),
            "stdout: {stdout}\nstderr: {stderr}"
        );
    }
}

/// Regression for SBX-3: every lotse process runs as one uid, so a worker's
/// unconditional `prlimit64` reached the supervisor (prlimit(2): the same
/// real and saved ids suffice) and its unconditional `prctl` could undo
/// `PR_SET_DUMPABLE` or clear `PR_SET_PDEATHSIG`. Under the worker's
/// allowlist each of these acts ends the worker with `SIGSYS`, while the
/// thread naming and the read of its own limits that its runtime does
/// still work. A coverage build lets the profiler runtime clear the
/// parent-death signal (`seccomp.rs`), so there that act gets through. (`tgkill` on another pid is
/// checked against the compiled filter in `seccomp.rs`: no safe wrapper
/// makes the call.)
#[test]
fn a_worker_cannot_reach_the_supervisor_or_undo_its_sandbox() {
    for act in ["prlimit_parent", "dumpable", "pdeathsig", "getppid"] {
        let (report, stdout, stderr, status) = run_probe("escape_probe_child", ESCAPE_PROBE, act);
        let context = format!("act {act}\nstdout: {stdout}\nstderr: {stderr}");
        assert!(
            stdout.contains("thread_name:Ok(Ok(\"lotse-probe\"))"),
            "{context}"
        );
        assert!(stdout.contains("nofile:Some(256)"), "{context}");
        let profiler_needs_it = act == "pdeathsig" && cfg!(coverage);
        if report.seccomp == LayerStatus::Enforced && !profiler_needs_it {
            assert!(!stdout.contains(&format!("{act}:")), "{context}");
            assert_eq!(status.signal(), Some(SIGSYS), "{context}");
        } else {
            assert!(stdout.contains(&format!("{act}:")), "{context}");
        }
    }
}

/// Regression for SBX-4 and WRK-8: a worker's copy of the shared socket
/// let it receive every viewer's datagrams in the supervisor's place,
/// `connect` or `shutdown` the one open file description every process
/// sends on, reconfigure it, or give it a number the filter does not
/// name. Under the worker's allowlist each act ends the worker with
/// `SIGSYS`, while sending on the socket, receiving on its camera's socket
/// and closing its copy (which a debug build precedes with
/// `fcntl(F_GETFD)`) still work.
#[test]
fn a_worker_can_only_send_on_the_shared_udp_socket() {
    for act in [
        "recv",
        "read",
        "connect",
        "shutdown",
        "setsockopt",
        "blocking",
        "dup",
        "pass",
        "close",
    ] {
        let (report, stdout, stderr, status) = run_probe("shared_probe_child", SHARED_PROBE, act);
        let context = format!("act {act}, {status}\nstdout: {stdout}\nstderr: {stderr}");
        assert!(
            stdout.contains(&format!("pinned:{}", lotse_sandbox::WORKER_SHARED_UDP_FD)),
            "{context}"
        );
        assert!(stdout.contains("send:Ok(5)"), "{context}");
        assert!(stdout.contains("camera_recv:Ok(3)"), "{context}");
        let acted = stdout
            .lines()
            .any(|line| line.starts_with(&format!("{act}:")));
        if act == "close" || report.seccomp != LayerStatus::Enforced {
            assert!(acted, "{context}");
            assert!(status.success(), "{context}");
        } else {
            assert!(!acted, "{context}");
            assert_eq!(status.signal(), Some(SIGSYS), "{context}");
        }
    }
}
