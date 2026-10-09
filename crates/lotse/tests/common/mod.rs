//! Helpers shared by the subprocess tests: the binary with a clean
//! environment, a private socket directory, a running daemon with its log
//! lines, and JSON log parsing. The directory and the daemon clean up
//! after themselves when dropped, so a test that panics leaves neither a
//! running `lotse serve` nor a temp directory behind.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    dead_code,
    reason = "test code shared by several test binaries; each uses a subset"
)]

use std::io::{BufRead as _, BufReader};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

/// How long the daemon may stay silent between two log lines while a test
/// waits for one.
pub(crate) const STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// The binary with a clean environment, so the host's `LOTSE_*` and
/// `RUST_LOG` cannot leak into the test.
#[expect(
    clippy::disallowed_methods,
    reason = "the test drives the real binary; only the supervisor spawns processes in production"
)]
pub(crate) fn lotse() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lotse"));
    command.env_clear();
    command
}

/// A private 0700 directory for the socket path of one test, as the
/// control socket's bind requires. It is removed when the guard drops,
/// whether the test passed or panicked.
pub(crate) fn socket_dir(test: &str) -> SocketDir {
    use std::os::unix::fs::DirBuilderExt as _;
    let dir = std::env::temp_dir().join(format!("lotse-cli-{test}-{}", std::process::id()));
    let _stale = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("temp dir");
    SocketDir(dir)
}

/// The directory [`socket_dir`] created, removed with everything in it on
/// drop. Declare it before the [`Daemon`] that binds a socket in it, so
/// the daemon is stopped first.
pub(crate) struct SocketDir(PathBuf);

impl Deref for SocketDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _gone = std::fs::remove_dir_all(&self.0);
    }
}

/// A running `lotse serve` with its stderr lines streamed to the test.
/// Dropping it before [`Daemon::terminate`], as a panicking test does,
/// kills the daemon: a dropped [`Child`] is never killed by `std`, and
/// nextest does not kill a test's process group when the test fails.
pub(crate) struct Daemon {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Daemon {
    pub(crate) fn start(args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut command = lotse();
        command
            .arg("serve")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().expect("daemon starts");
        let stderr = child.stderr.take().expect("stderr piped");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Reads lines until one contains `needle`, or fails once the daemon
    /// stays silent for the timeout.
    pub(crate) fn wait_for(&mut self, needle: &str) -> String {
        loop {
            match self.lines.recv_timeout(STEP_TIMEOUT) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(needle) {
                        return line;
                    }
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    panic!(
                        "no line containing {needle:?}\nseen:\n{}",
                        self.seen.join("\n")
                    );
                }
            }
        }
    }

    /// Sends `SIGTERM`, waits for the exit and returns the code with every
    /// line logged after the last `wait_for`.
    pub(crate) fn terminate(mut self) -> (Option<i32>, Vec<String>) {
        rustix::process::kill_process(
            rustix::process::Pid::from_child(&self.child),
            rustix::process::Signal::TERM,
        )
        .expect("SIGTERM delivered");
        let status = self.child.wait().expect("daemon exits");
        let mut rest = Vec::new();
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(2)) {
            rest.push(line);
        }
        (status.code(), rest)
    }
}

impl Drop for Daemon {
    /// `SIGKILL` and reap, unless [`Daemon::terminate`] already reaped it
    /// (then `kill` sends nothing). The workers follow on their own: each
    /// stops once the supervisor's end of its control channel closes.
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

/// The JSON object of one log line.
pub(crate) fn json(line: &str) -> serde_json::Value {
    serde_json::from_str(line).unwrap_or_else(|err| panic!("not a JSON log line: {line}: {err}"))
}
