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

use std::io::{BufRead as _, BufReader, IoSlice, IoSliceMut, Read as _};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use lotse_sandbox::{LayerStatus, Mode, Profile, SandboxConfig, SandboxReport, StateDir};
use rustix::net::{
    RecvAncillaryBuffer, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use rustix::process::{DumpableBehavior, Resource, Rlimit};

/// The variable that turns this binary into the probe child.
const PROBE: &str = "LOTSE_SANDBOX_PROBE";

/// The variable that turns this binary into the supervisor probe child;
/// its value is the state directory to make.
const SUPERVISOR_PROBE: &str = "LOTSE_SANDBOX_SUPERVISOR_PROBE";

/// The variable that turns this binary into the escape probe child; its
/// value names the one call that reaches beyond the worker, tried last.
const ESCAPE_PROBE: &str = "LOTSE_SANDBOX_ESCAPE_PROBE";

/// The variable that turns this binary into the shared-socket probe child;
/// its value names the one call on the shared socket, tried last.
const SHARED_PROBE: &str = "LOTSE_SANDBOX_SHARED_PROBE";

/// The variable that turns this binary into the priority probe child.
const NICE_PROBE: &str = "LOTSE_SANDBOX_NICE_PROBE";

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

/// The priority probe child: sandbox itself as a worker, start a thread,
/// print its own thread's and the new thread's ids, and keep both alive
/// until its stdin closes, so the parent reads each one's nice value from
/// `/proc`, which the worker's Landlock domain keeps from it.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the probe child reads the variable that marks it"
)]
fn nice_probe_child() {
    if std::env::var_os(NICE_PROBE).is_none() {
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
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let started = std::thread::spawn(move || {
        tid_tx
            .send(rustix::thread::gettid().as_raw_nonzero())
            .expect("tid sent");
        // Until the main thread hangs up.
        let _closed = done_rx.recv();
    });
    let thread = tid_rx.recv().expect("the thread's tid");
    println!(
        "tids:{} {thread}",
        rustix::thread::gettid().as_raw_nonzero()
    );
    let mut rest = Vec::new();
    std::io::stdin()
        .read_to_end(&mut rest)
        .expect("stdin until it closes");
    drop(done_tx);
    started.join().expect("thread joins");
}

/// The nice value of thread `tid` of process `pid`: field 19 of its
/// `stat` (proc(5), `/proc/pid/stat`), counted after the closing
/// parenthesis of the `comm` field, which may hold spaces.
fn nice_of(pid: u32, tid: &str) -> i32 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat")).expect("stat");
    let (_, fields) = stat.rsplit_once(')').expect("comm ends");
    fields
        .split_whitespace()
        .nth(19 - 3)
        .expect("field 19")
        .parse()
        .expect("a nice value")
}

/// Where the supervisor probe child moves the state directory it opened,
/// before it makes another at its path.
fn checked_state(state: &Path) -> PathBuf {
    PathBuf::from(format!("{}-checked", state.display()))
}

/// The supervisor probe child: sandbox itself as the supervisor, print the
/// report, then try what spawning a worker needs from the inherited domain
/// (`/dev/null` for its stdout, a pidfd to reap it, a TCP listener on port
/// 0 for its relay) and what it does not (reading `/dev/null`, a fixed TCP
/// port). It writes in the state directory it opened, which was swapped
/// for another before the sandbox, and in the one at its path now. Last,
/// it does what a worker does under the supervisor's inherited filter and
/// domain: bind its relay, apply the worker profile, and connect to the
/// relay.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the probe child reads the variable that marks it"
)]
fn supervisor_probe_child() {
    let Some(state) = std::env::var_os(SUPERVISOR_PROBE).map(PathBuf::from) else {
        return;
    };
    // The state directory, opened as the daemon opens it, then swapped for
    // another by someone who may rename in its parent. Both are open to
    // everyone, so only Landlock decides, whatever uid the drop leaves.
    let open_to_all = |dir: &Path| {
        std::fs::create_dir(dir).expect("state directory");
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o777)).expect("mode");
    };
    open_to_all(&state);
    let fd = OwnedFd::from(std::fs::File::open(&state).expect("state directory opens"));
    let checked = checked_state(&state);
    std::fs::rename(&state, &checked).expect("swapped out");
    open_to_all(&state);
    // A port that was free a moment ago, found before the sandbox.
    let fixed = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
        .port();
    let profile = Profile::Supervisor {
        binary: std::env::current_exe().expect("own path"),
        state_dir: Some(StateDir {
            path: state.clone(),
            fd,
        }),
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
    let state_write = kind(std::fs::write(checked.join("pins"), b""));
    println!("state_write:{state_write:?}");
    let swapped_write = kind(std::fs::write(state.join("pins"), b""));
    println!("swapped_write:{swapped_write:?}");
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
/// limits, make itself dumpable again, clear its parent-death signal, ask
/// for its parent's pid, create a memory file, resize a file, write a
/// regular file it opened before its sandbox or raise its scheduling
/// priority again. An act after [`WITHOUT_SECCOMP`] is tried
/// with the seccomp layer unavailable.
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
    let act = act.to_str().expect("act is UTF-8");
    let act = match act.strip_prefix(WITHOUT_SECCOMP) {
        Some(act) => {
            refuse_seccomp();
            act
        }
        None => act,
    };
    // Opened before the sandbox, which lets a worker open no file; a
    // worker's standard error, the one regular file it may hold, is the
    // harness's pipe here. Unlinked at once, so nothing is left behind.
    let file = (act == "write_file").then(|| {
        let path = std::env::temp_dir().join(format!("lotse-probe-fsize-{}", std::process::id()));
        let file = std::fs::File::create(&path).expect("file created");
        std::fs::remove_file(&path).expect("file unlinked");
        file
    });
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
    let nice = rustix::process::getrlimit(Resource::Nice);
    println!("nice_limit:{:?}", (nice.current, nice.maximum));
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
        "memfd" => {
            let created =
                rustix::fs::memfd_create("lotse-probe", rustix::fs::MemfdFlags::CLOEXEC).map(drop);
            println!("memfd:{created:?}");
        }
        "ftruncate" => {
            // stdout is the harness's pipe: the call fails with `EINVAL`
            // should it get through.
            let resized = rustix::fs::ftruncate(std::io::stdout(), 0);
            println!("ftruncate:{resized:?}");
        }
        "write_file" => {
            let fsize = rustix::process::getrlimit(Resource::Fsize);
            println!("fsize_limit:{:?}", (fsize.current, fsize.maximum));
            let mut file = file.expect("opened for the act");
            let written = std::io::Write::write(&mut file, b"x").map_err(|e| e.raw_os_error());
            println!("write_file:{written:?}");
        }
        "setpriority" => {
            // Back to nice 0: should the call get through, refused
            // (`EACCES`) for want of `CAP_SYS_NICE` and of an `RLIMIT_NICE`
            // above 0 (setpriority(2)).
            let raised = rustix::process::setpriority_process(None, 0)
                .map_err(|errno| std::io::Error::from(errno).kind());
            println!("setpriority:{raised:?}");
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
    let status = finished(output.status, &stdout);
    let report_line = stdout
        .lines()
        .find(|line| line.starts_with('{'))
        .unwrap_or_else(|| panic!("no report in child output\nstdout: {stdout}\nstderr: {stderr}"));
    let report: SandboxReport = serde_json::from_str(report_line).expect("report parses");
    (report, stdout, stderr, status)
}

/// The exit status of a probe child that applied the worker profile, with
/// a coverage build's end after its test passed counted as exit 0. libtest
/// runs the test on a thread of its own, so the privilege drop, Landlock
/// and seccomp bind that thread alone, but `RLIMIT_FSIZE` binds the whole
/// process (setrlimit(2)): the profiler runtime writes the profile from the
/// main thread at exit, and the worker's limit of 0 ends it with
/// `SIGXFSZ`. A worker sandboxes its main thread before any other exists,
/// so there Landlock refuses to open the profile and nothing is written.
fn finished(status: ExitStatus, stdout: &str) -> ExitStatus {
    let profile_refused = cfg!(coverage)
        && status.signal() == Some(libc::SIGXFSZ)
        && stdout.contains("test result: ok.");
    if profile_refused {
        ExitStatus::from_raw(0)
    } else {
        status
    }
}

/// Regression for SBX-1 (reproduced 2026-10-07 on Linux 7.0): the
/// supervisor's domain, which every worker inherits, denied the
/// `/dev/null` a worker's spawn opens and every TCP `bind`, so no worker
/// started and none could bind its loopback relay; its seccomp filter,
/// also inherited, killed the supervisor at `pidfd_open` and a worker at
/// its first Landlock call. The supervisor writes in the state directory
/// it was given open, never in one swapped in at its path.
#[test]
fn a_supervisor_can_spawn_and_its_workers_bind_an_ephemeral_port_only() {
    let state = std::env::temp_dir().join(format!("lotse-probe-state-{}", std::process::id()));
    let checked = checked_state(&state);
    for dir in [&state, &checked] {
        let _gone = std::fs::remove_dir_all(dir);
    }
    let (report, stdout, stderr, status) = run_probe(
        "supervisor_probe_child",
        SUPERVISOR_PROBE,
        state.to_str().expect("a UTF-8 temporary directory"),
    );
    for dir in [&state, &checked] {
        std::fs::remove_dir_all(dir).expect("the probe's state directories");
    }
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
    // Regression: the rule was made from the state directory's path, so
    // the directory swapped in got the rights and the checked one none.
    assert!(
        stdout.contains("state_write:Ok(())"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    denied("swapped_write", report.landlock.fs == LayerStatus::Enforced);
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
        let profiler_needs_it = act == "pdeathsig" && cfg!(coverage);
        assert_escape_is_killed(act, profiler_needs_it);
    }
}

/// Regression for SBX-20: a worker could create a memfd and fill it with
/// shmem pages that `RLIMIT_AS` does not count (`memfd_create(2)`), until
/// the host ran out of memory. Under the worker's allowlist creating or
/// resizing one ends the worker with `SIGSYS`.
#[test]
fn a_worker_cannot_fill_memory_outside_its_address_space() {
    for act in ["memfd", "ftruncate"] {
        assert_escape_is_killed(act, false);
    }
}

/// Regression for SBX-20: a worker could grow regular files, up to
/// filling the disk where Landlock, which lets it open none, is missing
/// (Linux before 5.13) and the dropped uid may write somewhere. With its
/// standard error a pipe a worker's `RLIMIT_FSIZE` is 0, so its first write
/// call on a regular file ends it with `SIGXFSZ` (getrlimit(2)), whether or
/// not seccomp is enforced: the allowlist keeps `write`. A shared writable
/// mapping is beyond the limit ([`lotse_sandbox::WORKER_MAX_FILE_SIZE`]).
#[test]
fn setrlimit2_a_worker_cannot_write_a_regular_file() {
    let (report, stdout, stderr, status) =
        run_probe("escape_probe_child", ESCAPE_PROBE, "write_file");
    let context = format!("{status}\nstdout: {stdout}\nstderr: {stderr}");
    assert_eq!(report.mode, Mode::On, "{context}");
    assert!(stdout.contains("nofile:Some(256)"), "{context}");
    assert!(
        stdout.contains("fsize_limit:(Some(0), Some(0))"),
        "{context}"
    );
    assert!(!stdout.contains("write_file:"), "{context}");
    assert_eq!(status.signal(), Some(libc::SIGXFSZ), "{context}");
}

/// Regression for SBX-25: a worker's threads ran at the supervisor's nice
/// value, so one that spun took the supervisor's CPU share (sched(7)). A
/// worker runs at [`lotse_sandbox::WORKER_NICE_INCREMENT`] above the nice
/// value it inherits, clamped at 19 (setpriority(2)), on the thread that
/// sandboxed itself and on a thread it starts afterwards; the nice value is
/// per thread on Linux, so both are read.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "spawns this test binary as the probe child"
)]
fn a_worker_and_every_thread_it_starts_run_at_a_lower_priority() {
    let inherited = rustix::process::getpriority_process(None).expect("own nice value");
    let expected = (inherited + lotse_sandbox::WORKER_NICE_INCREMENT).min(19);
    let mut child = Command::new(std::env::current_exe().expect("own path"))
        .args(["--exact", "nice_probe_child", "--nocapture"])
        .env(NICE_PROBE, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("child runs");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut lines = String::new();
    let tids = loop {
        let mut line = String::new();
        let read = stdout.read_line(&mut line).expect("child output");
        assert_ne!(read, 0, "no tids in child output\nstdout: {lines}");
        if let Some(tids) = line.strip_prefix("tids:") {
            break tids
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
        }
        lines.push_str(&line);
    };
    let nices: Vec<i32> = tids.iter().map(|tid| nice_of(child.id(), tid)).collect();
    drop(child.stdin.take());
    stdout.read_to_string(&mut lines).expect("child output");
    let output = child.wait_with_output().expect("child exits");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = format!("stdout: {lines}\nstderr: {stderr}");
    let status = finished(output.status, &lines);
    assert!(status.success(), "{status}\n{context}");
    let report_line = lines
        .lines()
        .find(|line| line.starts_with('{'))
        .unwrap_or_else(|| panic!("no report\n{context}"));
    let report: SandboxReport = serde_json::from_str(report_line).expect("report parses");
    assert_eq!(report.mode, Mode::On);
    assert_eq!(nices, [expected, expected], "{context}");
}

/// The prefix of an escape probe act that the child tries with the seccomp
/// layer unavailable, as under a container profile that refuses
/// seccomp(2): the worker profile applies in `on` mode and reports it.
const WITHOUT_SECCOMP: &str = "without-seccomp:";

/// A filter on the calling thread that answers seccomp(2) with `EPERM`,
/// so the worker profile installs no filter of its own (seccomp(2): a
/// filter applies to the calling thread, without
/// `SECCOMP_FILTER_FLAG_TSYNC`).
fn refuse_seccomp() {
    let arch = seccompiler::TargetArch::try_from(std::env::consts::ARCH).expect("an arch");
    let rules = std::collections::BTreeMap::from([(libc::SYS_seccomp, Vec::new())]);
    let eperm = u32::try_from(libc::EPERM).expect("EPERM");
    let refuse: seccompiler::BpfProgram = seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::Allow,
        seccompiler::SeccompAction::Errno(eperm),
        arch,
    )
    .and_then(TryInto::try_into)
    .expect("the filter builds");
    seccompiler::apply_filter(&refuse).expect("the filter installs");
}

/// Regression for SBX-25: a worker could undo its lower priority. Under
/// its allowlist `setpriority` ends it with `SIGSYS`. Without the seccomp
/// layer, which `on` mode only reports, the dropped uid is refused all the
/// same: its `RLIMIT_NICE` is 0 (setpriority(2), getrlimit(2)). At the
/// default limit of 0 this holds without the pin as well; CI's Sandbox
/// isolation job starts its container with `--ulimit nice=20:20` and checks
/// that the pin took the raised limit away (`scripts/sandbox-isolation.sh`).
#[test]
fn a_worker_cannot_raise_its_priority_again() {
    assert_escape_is_killed("setpriority", false);
    let act = format!("{WITHOUT_SECCOMP}setpriority");
    let (report, stdout, stderr, status) = run_probe("escape_probe_child", ESCAPE_PROBE, &act);
    let context = format!("{status}\nstdout: {stdout}\nstderr: {stderr}");
    assert_eq!(report.seccomp, LayerStatus::Unavailable, "{context}");
    assert!(
        stdout.contains("nice_limit:(Some(0), Some(0))"),
        "{context}"
    );
    assert!(
        stdout.contains("setpriority:Err(PermissionDenied)"),
        "{context}"
    );
    assert!(status.success(), "{context}");
}

/// Runs the escape probe child with `act` and checks that the worker's
/// runtime still works and that the act ends it with `SIGSYS` where
/// seccomp is enforced, unless the coverage `profiler_needs_it`.
fn assert_escape_is_killed(act: &str, profiler_needs_it: bool) {
    let (report, stdout, stderr, status) = run_probe("escape_probe_child", ESCAPE_PROBE, act);
    let context = format!("act {act}\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("thread_name:Ok(Ok(\"lotse-probe\"))"),
        "{context}"
    );
    assert!(stdout.contains("nofile:Some(256)"), "{context}");
    assert!(
        stdout.contains("nice_limit:(Some(0), Some(0))"),
        "{context}"
    );
    if report.seccomp == LayerStatus::Enforced && !profiler_needs_it {
        assert!(!stdout.contains(&format!("{act}:")), "{context}");
        assert_eq!(status.signal(), Some(SIGSYS), "{context}");
    } else {
        assert!(stdout.contains(&format!("{act}:")), "{context}");
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
