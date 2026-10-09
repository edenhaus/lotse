//! The listener: the private Unix socket with its directory, umask and
//! peer-credential checks.
//!
//! Implements unix(7) `SO_PEERCRED` (through tokio's `peer_cred`, which is
//! `getpeereid(2)` on macOS): the peer's uid is read and checked at accept,
//! and a peer that is not allowed is closed before a byte of its request
//! is read. An allowed peer's credentials are carried as its [`PeerInfo`].

use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::Path;
use std::sync::Arc;

use lotse_core::backoff::AcceptBackoff;
use lotse_core::clock::Clock;
use rustix::fs::Mode;
use tokio::net::{UnixListener, UnixStream};

/// What the listener learned about an allowed peer at accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// The peer's uid, one of the allowed ones.
    pub uid: u32,
    /// The peer's pid, where the platform reports it.
    pub pid: Option<i32>,
}

/// Why a listener could not be bound.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// The path is in the abstract namespace, which has no permissions.
    #[error("abstract-namespace sockets are refused; use a path in a private directory")]
    AbstractNamespace,
    /// The path has no parent directory.
    #[error("socket path {0} has no parent directory")]
    NoParent(String),
    /// The parent directory is missing or unreadable.
    #[error("socket directory {path}: {source}")]
    Directory {
        /// The directory.
        path: String,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The parent is not a directory.
    #[error("socket directory {0} is not a directory")]
    NotADirectory(String),
    /// The parent directory's mode is not 0700.
    #[error("socket directory {path} is mode {mode:04o}, must be 0700")]
    Mode {
        /// The directory.
        path: String,
        /// Its permission bits.
        mode: u32,
    },
    /// The parent directory is owned by someone else.
    #[error("socket directory {path} is owned by uid {owner}, not {expected}")]
    Owner {
        /// The directory.
        path: String,
        /// Its owner.
        owner: u32,
        /// The uid the daemon started as.
        expected: u32,
    },
    /// The socket could not be bound.
    #[error("binding {path}: {source}")]
    Bind {
        /// The path.
        path: String,
        /// The error.
        #[source]
        source: io::Error,
    },
}

/// Binds the Unix socket after checking its directory, with umask 0177 so
/// it is 0600 from the moment it exists. A stale socket file from an
/// earlier run is removed first.
pub(crate) fn bind_unix(
    path: &Path,
    owner_uid: u32,
) -> Result<std::os::unix::net::UnixListener, BindError> {
    let text = path.display().to_string();
    if text.starts_with('\0') || text.starts_with('@') {
        return Err(BindError::AbstractNamespace);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| BindError::NoParent(text.clone()))?;
    let parent_text = parent.display().to_string();
    let meta = std::fs::metadata(parent).map_err(|source| BindError::Directory {
        path: parent_text.clone(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(BindError::NotADirectory(parent_text));
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o700 {
        return Err(BindError::Mode {
            path: parent_text,
            mode,
        });
    }
    if meta.uid() != owner_uid {
        return Err(BindError::Owner {
            path: parent_text,
            owner: meta.uid(),
            expected: owner_uid,
        });
    }
    if let Ok(existing) = std::fs::symlink_metadata(path)
        && existing.file_type().is_socket()
    {
        tracing::warn!(socket = %text, "removing a stale socket file");
        let _removed = std::fs::remove_file(path);
    }

    let previous = rustix::process::umask(Mode::from_bits_truncate(0o177));
    let bound = std::os::unix::net::UnixListener::bind(path)
        .and_then(|listener| listener.set_nonblocking(true).map(|()| listener));
    let _restored = rustix::process::umask(previous);
    let listener = bound.map_err(|source| BindError::Bind { path: text, source })?;
    tracing::info!(socket = %path.display(), "control socket bound");
    Ok(listener)
}

/// The Unix listener, checking each peer's credentials at accept.
#[derive(Debug)]
pub(crate) struct CheckedUnix {
    /// The listener.
    inner: UnixListener,
    /// The uids that may connect: the one the daemon started as and
    /// `--allow-uid`.
    allowed: [u32; 2],
    /// Times the pause after a failed `accept`.
    clock: Arc<dyn Clock>,
    /// The pauses after failed `accept`s in a row.
    backoff: AcceptBackoff,
}

impl CheckedUnix {
    /// Registers a bound listener with the runtime; only peers whose uid
    /// is in `allowed` get past [`CheckedUnix::accept`]. `clock` times the
    /// pause after a failed `accept`.
    pub(crate) fn new(
        listener: std::os::unix::net::UnixListener,
        allowed: [u32; 2],
        clock: Arc<dyn Clock>,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: UnixListener::from_std(listener)?,
            allowed,
            clock,
            backoff: AcceptBackoff::new(),
        })
    }

    /// The next allowed peer. A peer whose uid is not allowed is closed
    /// here without a response and before anything it sent is read.
    /// A failed `accept`, or one whose peer's credentials cannot be read
    /// (`SO_PEERCRED`, which `unix(7)` fills at `connect`; the peer is
    /// closed), is retried after a pause on the clock, the
    /// [`AcceptBackoff`] schedule, reset by the next success.
    pub(crate) async fn accept(&mut self) -> (UnixStream, PeerInfo) {
        loop {
            let accepted = self.inner.accept().await.and_then(|(stream, _addr)| {
                let cred = stream.peer_cred()?;
                Ok((stream, cred))
            });
            match accepted {
                Ok((stream, cred)) => {
                    self.backoff.reset();
                    let peer = PeerInfo {
                        uid: cred.uid(),
                        pid: cred.pid(),
                    };
                    if !self.allowed.contains(&peer.uid) {
                        tracing::warn!(uid = peer.uid, pid = ?peer.pid, "control connection refused: peer uid not allowed");
                        continue;
                    }
                    return (stream, peer);
                }
                Err(err) => {
                    let pause = self.backoff.next_delay();
                    let backoff_ms = pause.as_millis();
                    tracing::warn!(
                        error = %err,
                        backoff_ms,
                        "accept on the control socket failed; retrying after a pause"
                    );
                    self.clock.sleep(pause).await;
                }
            }
        }
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
    use std::os::unix::fs::DirBuilderExt as _;
    use std::sync::Mutex;
    use std::time::Duration;

    use lotse_core::clock::FakeClock;
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    use super::*;

    fn private_dir(name: &str, mode: u32) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("lotse-api-{name}-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(mode).create(&dir).unwrap();
        dir
    }

    #[test]
    fn binds_in_a_private_directory_with_a_0600_socket() {
        let dir = private_dir("bind", 0o700);
        let path = dir.join("lotse.sock");
        let uid = rustix::process::getuid().as_raw();
        let listener = bind_unix(&path, uid).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600, "umask 0177 at bind");
        drop(listener);
        // A stale socket file is replaced on the next bind.
        assert!(bind_unix(&path, uid).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_peer_whose_uid_is_not_allowed_is_closed_before_its_request_is_read() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let dir = private_dir("refuse", 0o700);
        let path = dir.join("lotse.sock");
        let uid = rustix::process::getuid().as_raw();
        let mut listener = CheckedUnix::new(
            bind_unix(&path, uid).unwrap(),
            [uid.wrapping_add(1), uid.wrapping_add(2)],
            Arc::new(FakeClock::default()),
        )
        .unwrap();
        // Only the peer info leaves the task: a stream handed on by mistake
        // is closed at once, and the task is then finished.
        let accepting =
            lotse_core::task::spawn_named("test.accept", async move { listener.accept().await.1 });
        let mut client = UnixStream::connect(&path).await.unwrap();
        let _written = client.write_all(b"GET /v0/ws HTTP/1.1\r\n\r\n").await;
        let mut answer = Vec::new();
        let _read = client.read_to_end(&mut answer).await;
        assert!(answer.is_empty(), "no response: {answer:?}");
        accepting.abort();
        let refused = accepting.await;
        assert!(
            refused
                .as_ref()
                .is_err_and(tokio::task::JoinError::is_cancelled),
            "the refused peer is never handed on: {refused:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn an_allowed_peer_is_handed_on_with_its_credentials() {
        use tokio::io::AsyncReadExt as _;

        let dir = private_dir("allow", 0o700);
        let path = dir.join("lotse.sock");
        let uid = rustix::process::getuid().as_raw();
        let mut listener = CheckedUnix::new(
            bind_unix(&path, uid).unwrap(),
            [uid.wrapping_add(1), uid],
            Arc::new(FakeClock::default()),
        )
        .unwrap();
        let mut client = UnixStream::connect(&path).await.unwrap();
        let mut byte = [0_u8; 1];
        let (_stream, peer) = tokio::select! {
            accepted = listener.accept() => accepted,
            closed = client.read(&mut byte) => panic!("refused: {closed:?}"),
        };
        assert_eq!(peer.uid, uid);
        // Linux reports the pid (`SO_PEERCRED`).
        let pid = peer.pid.map(|pid| u32::try_from(pid).unwrap());
        assert_eq!(pid, Some(std::process::id()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A log writer that keeps every line.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        /// The pauses of the failed accepts logged so far, in ms.
        fn pauses(&self) -> Vec<u64> {
            let logs = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
            logs.lines()
                .filter(|line| line.contains("accept on the control socket failed"))
                .map(|line| {
                    let (_, after) = line.split_once("backoff_ms=").unwrap();
                    after.split_whitespace().next().unwrap().parse().unwrap()
                })
                .collect()
        }
    }

    /// Lowers this process's descriptor limit to its lowest free
    /// descriptor, so the next `accept` fails with `EMFILE` and leaves the
    /// connection queued; returns the limit to restore. nextest runs each
    /// test in its own process.
    fn starve_descriptors() -> Rlimit {
        let limit = getrlimit(Resource::Nofile);
        let probe = std::fs::File::open("/dev/null").unwrap();
        let lowest = u64::try_from(probe.as_raw_fd()).unwrap();
        drop(probe);
        let starved = Rlimit {
            current: Some(lowest),
            maximum: limit.maximum,
        };
        setrlimit(Resource::Nofile, starved).unwrap();
        limit
    }

    /// Polls `accept` for `rounds` scheduler turns; its output if it
    /// finished.
    async fn drive<F: Future + Unpin>(accept: &mut F, rounds: usize) -> Option<F::Output> {
        for _ in 0..rounds {
            tokio::select! {
                biased;
                out = &mut *accept => return Some(out),
                () = tokio::task::yield_now() => {}
            }
        }
        None
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failing_accept_backs_off_on_the_clock_doubling_to_1_s_and_resets_on_success() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _logs = tracing::subscriber::set_default(subscriber);
        // The subscriber never flushes its writer, whose flush does nothing.
        io::Write::flush(&mut captured.clone()).unwrap();
        let dir = private_dir("emfile", 0o700);
        let path = dir.join("lotse.sock");
        let uid = rustix::process::getuid().as_raw();
        let clock = Arc::new(FakeClock::default());
        let mut listener = CheckedUnix::new(
            bind_unix(&path, uid).unwrap(),
            [uid, uid],
            Arc::<FakeClock>::clone(&clock),
        )
        .unwrap();

        // Linux keeps a connection queued when `accept` fails with
        // `EMFILE`; macOS drops it (observed 2026-10, macOS 27), so every
        // failure there needs one of its own.
        let mut queued = Vec::new();
        for _ in 0..12 {
            queued.push(UnixStream::connect(&path).await.unwrap());
        }
        let limit = starve_descriptors();
        let mut accept = Box::pin(listener.accept());
        assert!(drive(&mut accept, 50).await.is_none());
        assert_eq!(captured.pauses(), [10], "one failure per pause, no spin");
        clock.advance(Duration::from_millis(9));
        assert!(drive(&mut accept, 50).await.is_none());
        assert_eq!(captured.pauses(), [10]);
        let mut expected = vec![10];
        let mut last = 10;
        for pause in [20, 40, 80, 160, 320, 640, 1000, 1000] {
            clock.advance(Duration::from_millis(last));
            assert!(drive(&mut accept, 50).await.is_none());
            expected.push(pause);
            assert_eq!(captured.pauses(), expected);
            last = pause;
        }
        setrlimit(Resource::Nofile, limit).unwrap();
        clock.advance(Duration::from_millis(last));
        let (_stream, peer) = drive(&mut accept, 50).await.expect("accepted");
        assert_eq!(peer.uid, uid);
        drop(accept);

        // A success resets the pause.
        for _ in 0..2 {
            queued.push(UnixStream::connect(&path).await.unwrap());
        }
        let limit = starve_descriptors();
        let mut accept = Box::pin(listener.accept());
        assert!(drive(&mut accept, 50).await.is_none());
        assert_eq!(captured.pauses().last(), Some(&10));
        setrlimit(Resource::Nofile, limit).unwrap();
        clock.advance(Duration::from_millis(10));
        assert!(drive(&mut accept, 50).await.is_some());
        drop(accept);
        assert_eq!(queued.len(), 14, "the clients stayed connected until here");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_the_wrong_directory_or_namespace() {
        let uid = rustix::process::getuid().as_raw();
        assert!(matches!(
            bind_unix(Path::new("@lotse"), uid).unwrap_err(),
            BindError::AbstractNamespace
        ));
        assert!(matches!(
            bind_unix(Path::new("lotse.sock"), uid).unwrap_err(),
            BindError::NoParent(_)
        ));
        assert!(matches!(
            bind_unix(Path::new("/nonexistent-lotse/lotse.sock"), uid).unwrap_err(),
            BindError::Directory { .. }
        ));
        let open = private_dir("open", 0o755);
        let err = bind_unix(&open.join("lotse.sock"), uid).unwrap_err();
        assert!(matches!(err, BindError::Mode { mode: 0o755, .. }), "{err}");
        assert!(err.to_string().contains("0755"));
        let private = private_dir("owner", 0o700);
        let err = bind_unix(&private.join("lotse.sock"), uid.wrapping_add(1)).unwrap_err();
        assert!(matches!(err, BindError::Owner { .. }), "{err}");
        let file = private.join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(matches!(
            bind_unix(&file.join("lotse.sock"), uid).unwrap_err(),
            BindError::NotADirectory(_)
        ));
        // A file in the socket's place is not a stale socket: it stays,
        // and the bind fails.
        let err = bind_unix(&file, uid).unwrap_err();
        assert!(matches!(err, BindError::Bind { .. }), "{err}");
        assert!(file.is_file());
        std::fs::remove_dir_all(&open).unwrap();
        std::fs::remove_dir_all(&private).unwrap();
    }
}
