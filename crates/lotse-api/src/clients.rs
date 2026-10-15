//! The control TLS listener's allowed clients: the fixed pins of the
//! configuration and the pins enrolled by pairing, which persist across
//! restarts in `<data-dir>/clients/pins`.
//!
//! Enrollment happens at runtime, after the privilege drop and under the
//! sandbox, so the enrolled pins live in a directory of their own that the
//! daemon makes before the drop, owned by the uid it drops to and mode
//! 0700; the sandbox lets the supervisor write beneath it and nowhere
//! else. The data directory itself and the identity in it stay the
//! starting uid's. The directory is opened before the drop and every write
//! is relative to that descriptor (`openat`, `renameat`), so the dropped
//! uid needs no access to the directories above it. The directory is
//! held under an exclusive `flock` for the store's lifetime, so a second
//! daemon on the same data directory is refused rather than overwriting
//! the enrollments of the first. The pins file is one pin per line,
//! replaced whole on every change: written to a new file with mode 0600,
//! synced, renamed into place and the directory synced, so a crash leaves
//! the old list or the new one. The rename is the change: once it is done
//! the new list is the one in force, even if the directory sync after it
//! fails. Pins are public; the file is private so nobody else can read who
//! is enrolled.
//!
//! The store also knows which control connections each pin has open, so
//! removing an enrolled pin closes them at once; its next handshake is
//! refused because sessions are never resumed. A connection registers
//! itself and checks its pin under the connections' lock, and a removal
//! changes the pins before it looks for connections under that lock: a
//! connection that authenticated just before its pin was removed is closed
//! either way. A removal holds the lock that orders changes until its
//! connections are closed, so a new enrollment of the same pin waits and
//! its fresh connection is never closed by the removal before it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};

use lotse_api_types::clients::{ClientList, ControlClient};
use lotse_core::fingerprint::Fingerprint;
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use tokio_util::sync::CancellationToken;

use crate::ConnectionId;

/// The enrolled clients' directory in the data directory.
pub(crate) const CLIENTS_DIR: &str = "clients";

/// The enrolled pins in [`CLIENTS_DIR`], one per line.
pub(crate) const PINS_FILE: &str = "pins";

/// Where an update writes before the rename to [`PINS_FILE`].
const PARTIAL_FILE: &str = "pins.partial";

/// Why the enrolled clients could not be read or their directory made.
#[derive(Debug, thiserror::Error)]
pub enum ClientsError {
    /// Making, reading or checking a path failed.
    #[error("enrolled clients {path}: {source}")]
    Io {
        /// The path.
        path: String,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The directory or the file is not what it should be.
    #[error("enrolled clients {path} is not a {expected}")]
    Kind {
        /// The path.
        path: String,
        /// `directory` or `regular file`.
        expected: &'static str,
    },
    /// The group or others may read or write it.
    #[error("enrolled clients {path} is mode {mode:04o}; the group and others must have no access")]
    Mode {
        /// The path.
        path: String,
        /// Its permission bits.
        mode: u32,
    },
    /// It belongs to someone other than the uid the daemon runs as.
    #[error("enrolled clients {path} is owned by uid {owner}, not {expected}")]
    Owner {
        /// The path.
        path: String,
        /// Its owner.
        owner: u32,
        /// The uid the daemon runs as after the privilege drop.
        expected: u32,
    },
    /// A line is not a pin.
    #[error("enrolled clients {path}, line {line}: not a certificate pin")]
    Pin {
        /// The file.
        path: String,
        /// The line, from 1.
        line: usize,
    },
    /// Another daemon holds the directory.
    #[error("enrolled clients {0} are in use by another lotse daemon on the same data directory")]
    InUse(String),
}

/// Syncs [`CLIENTS_DIR`] after a rename in it.
type SyncDir = fn(&OwnedFd) -> io::Result<()>;

/// `fsync` of the directory, as every store but a test's does it.
fn fsync_dir(dir: &OwnedFd) -> io::Result<()> {
    Ok(rustix::fs::fsync(dir)?)
}

/// What [`ClientStore::remove`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Removal {
    /// The pin was enrolled; it is not any more, and this many of its
    /// connections were told to close.
    Removed {
        /// The connections closed.
        closed: usize,
    },
    /// The pin was not enrolled: nothing to do.
    Unknown,
    /// The pin is the configuration's, which only the configuration
    /// changes.
    Fixed,
}

/// Who may connect: the fixed pins and the enrolled ones.
#[derive(Debug)]
pub(crate) struct ClientStore {
    /// The configuration's pins, which no enrollment changes.
    fixed: HashSet<Fingerprint>,
    /// The enrolled pins, as [`PINS_FILE`] holds them. Its lock is only
    /// ever held to read or to replace the set, never across a write to
    /// disk: the TLS verifier reads it on the runtime's threads.
    enrolled: RwLock<BTreeSet<Fingerprint>>,
    /// Held across a whole change of [`PINS_FILE`], so changes are written
    /// one at a time and each starts from the set the last one left.
    writing: Mutex<()>,
    /// [`CLIENTS_DIR`].
    dir: PathBuf,
    /// [`CLIENTS_DIR`], opened before the privilege drop and locked for
    /// the store's lifetime; every write is relative to it.
    dir_fd: OwnedFd,
    /// Syncs [`CLIENTS_DIR`] after the rename: [`fsync_dir`], or a test's
    /// fault.
    sync_dir: SyncDir,
    /// The open control connections over the TLS listener: each one's pin
    /// and the token that closes it.
    connections: Mutex<HashMap<ConnectionId, (Fingerprint, CancellationToken)>>,
}

impl ClientStore {
    /// Makes [`CLIENTS_DIR`] in the data directory `data` (opened and
    /// checked by the caller; `data_dir` only names it) if it is missing,
    /// owned by `runtime` (the uid and gid the daemon runs as after the
    /// drop) and mode 0700, checks it, locks it, and reads the enrolled
    /// pins. Every step goes through a descriptor: [`CLIENTS_DIR`] is made
    /// and opened in `data`, [`PINS_FILE`] in [`CLIENTS_DIR`], neither
    /// through a link, and each is checked as opened, so no path is looked
    /// up twice. Runs before the drop.
    pub(crate) fn open(
        data: &File,
        data_dir: &Path,
        fixed: &[Fingerprint],
        runtime: (u32, u32),
    ) -> Result<Self, ClientsError> {
        let dir = data_dir.join(CLIENTS_DIR);
        let text = dir.display().to_string();
        let io = |source: io::Error| io_error(&text, source);
        // A directory that exists already, or could not be made, is
        // judged by the checks below.
        let made = rustix::fs::mkdirat(data, CLIENTS_DIR, Mode::RWXU).is_ok();
        let handle = rustix::fs::openat(data, CLIENTS_DIR, OPEN, Mode::empty())
            .map_err(io::Error::from)
            .map_err(io)?;
        let handle = File::from(handle);
        if made {
            // mkdir(2) takes the umask's bits off the mode (umask(2)), and
            // a umask such as 0200 would leave the daemon a directory it
            // cannot write: the mode is set whole through the descriptor.
            rustix::fs::fchmod(&handle, Mode::RWXU)
                .map_err(io::Error::from)
                .map_err(io)?;
            std::os::unix::fs::fchown(&handle, Some(runtime.0), Some(runtime.1)).map_err(io)?;
            // Its entry in the data directory survives a crash too, or the
            // first enrollment synced inside it could vanish with it.
            data.sync_all().map_err(io)?;
        }
        check(
            &text,
            &handle.metadata().map_err(io)?,
            "directory",
            runtime.0,
        )?;
        match rustix::fs::flock(&handle, FlockOperation::NonBlockingLockExclusive) {
            Err(err) if err == Errno::WOULDBLOCK => return Err(ClientsError::InUse(text.clone())),
            locked => locked.map_err(io::Error::from).map_err(io)?,
        }
        let enrolled = read_pins(&handle, &dir.join(PINS_FILE), runtime.0)?;
        // Close-on-exec, as `OPEN` asks: no worker inherits it.
        let dir_fd = OwnedFd::from(handle);
        tracing::info!(
            fixed = fixed.len(),
            enrolled = enrolled.len(),
            "control TLS clients loaded"
        );
        Ok(Self {
            fixed: fixed.iter().copied().collect(),
            enrolled: RwLock::new(enrolled),
            writing: Mutex::new(()),
            dir,
            dir_fd,
            sync_dir: fsync_dir,
            connections: Mutex::default(),
        })
    }

    /// This store with `sync_dir` in place of `fsync`, to fail or hold the
    /// sync after the rename.
    #[cfg(test)]
    pub(crate) fn with_sync_dir(self, sync_dir: SyncDir) -> Self {
        Self { sync_dir, ..self }
    }

    /// The directory the daemon writes at runtime, for the sandbox: its
    /// path, and the descriptor it was checked and is locked through.
    pub(crate) fn dir(&self) -> (&Path, BorrowedFd<'_>) {
        (&self.dir, self.dir_fd.as_fd())
    }

    /// Whether `pin` may connect.
    pub(crate) fn allows(&self, pin: &Fingerprint) -> bool {
        self.fixed.contains(pin)
            || self
                .enrolled
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(pin)
    }

    /// Whether no client may connect yet.
    pub(crate) fn is_empty(&self) -> bool {
        self.fixed.is_empty()
            && self
                .enrolled
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
    }

    /// Enrolls `pin`: the file first, then the set, so a pin is allowed
    /// only once it is on disk. An error means nothing changed. Once the
    /// new file is renamed into place the pin is enrolled; a failed sync of
    /// the directory after that is logged, as a crash could still lose the
    /// enrollment. Blocking: run it off the runtime's threads.
    pub(crate) fn enroll(&self, pin: Fingerprint) -> io::Result<()> {
        let writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = self
            .enrolled
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        next.insert(pin);
        write_pins(&self.dir_fd, &next)?;
        *self
            .enrolled
            .write()
            .unwrap_or_else(PoisonError::into_inner) = next;
        self.sync_after_rename(pin, "enrolled");
        drop(writing);
        Ok(())
    }

    /// Syncs [`CLIENTS_DIR`] after [`PINS_FILE`] was renamed into place
    /// for a `change` of `pin`. A failure is logged, not returned: the
    /// change is made, and only a crash could still undo it.
    fn sync_after_rename(&self, pin: Fingerprint, change: &'static str) {
        if let Err(err) = (self.sync_dir)(&self.dir_fd) {
            tracing::warn!(
                path = %self.dir.display(),
                client_pin = %pin,
                change,
                error = %err,
                "enrolled clients changed, but syncing their directory failed: a crash may undo the change"
            );
        }
    }

    /// The open connections; a poisoned lock is still usable, the map
    /// holds no invariant a panicking holder could have broken halfway.
    fn connections(
        &self,
    ) -> MutexGuard<'_, HashMap<ConnectionId, (Fingerprint, CancellationToken)>> {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers connection `id`, authenticated with `pin`, and returns the
    /// token cancelled when `pin` is removed: already cancelled when it was
    /// removed after the handshake.
    pub(crate) fn attach(&self, id: ConnectionId, pin: Fingerprint) -> CancellationToken {
        let token = CancellationToken::new();
        let mut open = self.connections();
        open.insert(id, (pin, token.clone()));
        if !self.allows(&pin) {
            token.cancel();
        }
        drop(open);
        token
    }

    /// Forgets connection `id`, which closed.
    pub(crate) fn detach(&self, id: ConnectionId) {
        self.connections().remove(&id);
    }

    /// Every allowed pin, ordered, whether it is fixed and whether it has a
    /// connection open.
    pub(crate) fn list(&self) -> ClientList {
        let connected: HashSet<Fingerprint> =
            self.connections().values().map(|(pin, _)| *pin).collect();
        let mut pins: BTreeMap<Fingerprint, bool> = self
            .enrolled
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|pin| (*pin, false))
            .collect();
        pins.extend(self.fixed.iter().map(|pin| (*pin, true)));
        let clients = pins
            .into_iter()
            .map(|(pin, fixed)| ControlClient {
                pin: pin.to_string(),
                fixed,
                connected: connected.contains(&pin),
            })
            .collect();
        ClientList { clients }
    }

    /// Removes the enrolled `pin`, as connection `by` asked: the file first,
    /// then the set, then every connection it has open is told to close,
    /// then the directory is synced. All of it holds `writing`, so a new
    /// enrollment of `pin` waits until its old connections are closed and
    /// never has one of its own closed by this removal; closing before the
    /// sync keeps a slow disk from keeping a removed client connected. `by`
    /// itself is left open, counted among the closed, for it to close once
    /// it has answered: a client removing itself gets the result first,
    /// while any other connection of `pin` closes without waiting for
    /// whatever it is answering. A fixed pin stays. Blocking: run it off
    /// the runtime's threads.
    pub(crate) fn remove(&self, pin: Fingerprint, by: ConnectionId) -> io::Result<Removal> {
        if self.fixed.contains(&pin) {
            return Ok(Removal::Fixed);
        }
        let writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = self
            .enrolled
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if !next.remove(&pin) {
            return Ok(Removal::Unknown);
        }
        write_pins(&self.dir_fd, &next)?;
        *self
            .enrolled
            .write()
            .unwrap_or_else(PoisonError::into_inner) = next;
        let mut closed: usize = 0;
        for (id, (open, token)) in self.connections().iter() {
            if *open == pin {
                if *id != by {
                    token.cancel();
                }
                closed = closed.saturating_add(1);
            }
        }
        self.sync_after_rename(pin, "removed");
        drop(writing);
        Ok(Removal::Removed { closed })
    }
}

/// An I/O error on `path`.
fn io_error(path: &str, source: io::Error) -> ClientsError {
    ClientsError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Refuses `meta` of `path` unless it is a `kind` (`directory` or `regular
/// file`), owned by `owner` and closed to the group and others.
fn check(
    path: &str,
    meta: &std::fs::Metadata,
    kind: &'static str,
    owner: u32,
) -> Result<(), ClientsError> {
    let right_kind = if kind == "directory" {
        meta.is_dir()
    } else {
        meta.is_file()
    };
    if !right_kind {
        return Err(ClientsError::Kind {
            path: path.to_owned(),
            expected: kind,
        });
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ClientsError::Mode {
            path: path.to_owned(),
            mode,
        });
    }
    if meta.uid() != owner {
        return Err(ClientsError::Owner {
            path: path.to_owned(),
            owner: meta.uid(),
            expected: owner,
        });
    }
    Ok(())
}

/// How [`ClientStore::open`] opens [`CLIENTS_DIR`] and [`read_pins`]
/// [`PINS_FILE`]: read-only, a link in its place refused rather than
/// followed, a FIFO opened without waiting for a writer (POSIX.1-2024
/// `open()`) so the check after the open refuses it, close-on-exec.
const OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// The pins in [`PINS_FILE`] in the directory `dir`, which `path` names,
/// none when it does not exist. Blank lines are skipped; anything else
/// must be a pin.
fn read_pins(dir: &File, path: &Path, owner: u32) -> Result<BTreeSet<Fingerprint>, ClientsError> {
    let text = path.display().to_string();
    let io = |source: io::Error| io_error(&text, source);
    let mut file = match rustix::fs::openat(dir, PINS_FILE, OPEN, Mode::empty()) {
        Err(err) if err == Errno::NOENT => return Ok(BTreeSet::new()),
        opened => File::from(opened.map_err(io::Error::from).map_err(io)?),
    };
    check(&text, &file.metadata().map_err(io)?, "regular file", owner)?;
    let mut content = String::new();
    io::Read::read_to_string(&mut file, &mut content).map_err(io)?;
    let mut pins = BTreeSet::new();
    for (index, line) in content.lines().enumerate() {
        let line_number = index.saturating_add(1);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let pin = Fingerprint::parse(line).map_err(|_| ClientsError::Pin {
            path: text.clone(),
            line: line_number,
        })?;
        pins.insert(pin);
    }
    Ok(pins)
}

/// How [`write_pins`] makes its file: write-only, new (`EXCL` also refuses a
/// link in its place), close-on-exec.
const CREATE: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::CLOEXEC);

/// The new file's mode: 0600.
const PRIVATE: Mode = Mode::RUSR.union(Mode::WUSR);

/// Replaces [`PINS_FILE`] in the directory `dir` with `pins`: a new file
/// with mode 0600, synced and renamed into place; the caller syncs the
/// directory. A partial file a crash left behind is replaced. An error
/// means [`PINS_FILE`] is unchanged.
fn write_pins(dir: &OwnedFd, pins: &BTreeSet<Fingerprint>) -> io::Result<()> {
    let _stale = rustix::fs::unlinkat(dir, PARTIAL_FILE, AtFlags::empty());
    let fd = rustix::fs::openat(dir, PARTIAL_FILE, CREATE, PRIVATE)?;
    let mut file = File::from(fd);
    let mut content = String::new();
    for pin in pins {
        content.push_str(&pin.to_string());
        content.push('\n');
    }
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);
    rustix::fs::renameat(dir, PARTIAL_FILE, dir, PINS_FILE)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    use super::*;

    fn data_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lotse-clients-{name}-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }

    /// The store in the data directory `dir`, opened as the caller does.
    fn open(
        dir: &Path,
        fixed: &[Fingerprint],
        runtime: (u32, u32),
    ) -> Result<ClientStore, ClientsError> {
        ClientStore::open(&File::open(dir).unwrap(), dir, fixed, runtime)
    }

    fn runtime() -> (u32, u32) {
        (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
    }

    #[test]
    fn the_directory_is_made_private_and_enrolled_pins_survive_a_restart() {
        let dir = data_dir("enroll");
        let fixed = Fingerprint::of(b"fixed");
        let store = open(&dir, &[fixed], runtime()).unwrap();
        let clients = dir.join(CLIENTS_DIR);
        let meta = std::fs::metadata(&clients).unwrap();
        let (path, fd) = store.dir();
        assert_eq!(path, clients);
        // A copy shares the lock (flock(2)): this one is closed at once.
        let opened = File::from(fd.try_clone_to_owned().unwrap());
        assert_eq!(opened.metadata().unwrap().ino(), meta.ino());
        drop(opened);
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert!(store.allows(&fixed));
        assert!(!store.is_empty(), "a fixed pin is a client");
        let enrolled = Fingerprint::of(b"enrolled");
        assert!(!store.allows(&enrolled));
        std::fs::write(clients.join(PARTIAL_FILE), b"left by a crash").unwrap();
        store.enroll(enrolled).unwrap();
        store.enroll(enrolled).unwrap();
        assert!(store.allows(&enrolled));
        let file = clients.join(PINS_FILE);
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("{enrolled}\n")
        );
        assert!(!clients.join(PARTIAL_FILE).exists());

        drop(store);
        let again = open(&dir, &[], runtime()).unwrap();
        assert!(again.allows(&enrolled), "read back after a restart");
        assert!(
            !again.allows(&fixed),
            "fixed pins come from the configuration only"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Regression: under umask 0200 the directory was made 0500, which the
    /// check passes, and every enrollment failed. Nextest runs each test in
    /// a process of its own, and the umask is put back anyway.
    #[test]
    fn umask2_the_directory_is_0700_whatever_the_umask_and_takes_an_enrollment() {
        let dir = data_dir("umask");
        let previous = rustix::process::umask(Mode::WUSR);
        let opened = open(&dir, &[], runtime());
        let enrolled = opened
            .as_ref()
            .ok()
            .map(|store| store.enroll(Fingerprint::of(b"pin")));
        rustix::process::umask(previous);
        let store = opened.unwrap();
        enrolled.unwrap().unwrap();
        let clients = dir.join(CLIENTS_DIR);
        let meta = std::fs::metadata(&clients).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert!(store.allows(&Fingerprint::of(b"pin")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_pins_means_empty_and_blank_lines_are_skipped() {
        let dir = data_dir("empty");
        let store = open(&dir, &[], runtime()).unwrap();
        assert!(store.is_empty());
        let file = dir.join(CLIENTS_DIR).join(PINS_FILE);
        let pin = Fingerprint::of(b"pin");
        let mut options = std::fs::OpenOptions::new();
        std::os::unix::fs::OpenOptionsExt::mode(options.write(true).create_new(true), 0o600);
        let mut out = options.open(&file).unwrap();
        write!(out, "\n  {pin}  \n\n").unwrap();
        drop(store);
        let store = open(&dir, &[], runtime()).unwrap();
        assert!(store.allows(&pin));
        assert!(!store.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_directory_or_file_others_can_reach_or_someone_else_owns_is_refused() {
        let dir = data_dir("refuse");
        let clients = dir.join(CLIENTS_DIR);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&clients)
            .unwrap();
        std::fs::set_permissions(&clients, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(
            matches!(err, ClientsError::Mode { mode: 0o750, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("0750"), "{err}");
        std::fs::set_permissions(&clients, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = runtime();
        let err = open(&dir, &[], (uid.wrapping_add(1), gid)).unwrap_err();
        assert!(matches!(err, ClientsError::Owner { .. }), "{err}");

        let file = clients.join(PINS_FILE);
        std::fs::write(&file, b"").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(
            matches!(err, ClientsError::Mode { mode: 0o644, .. }),
            "{err}"
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&file, b"\xff not UTF-8\n").unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(matches!(err, ClientsError::Io { .. }), "{err}");
        std::fs::write(&file, b"not a pin\n").unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(matches!(err, ClientsError::Pin { line: 1, .. }), "{err}");
        assert!(err.to_string().contains("line 1"), "{err}");

        std::fs::remove_file(&file).unwrap();
        std::fs::DirBuilder::new().create(&file).unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(
            matches!(
                err,
                ClientsError::Kind {
                    expected: "regular file",
                    ..
                }
            ),
            "{err}"
        );
        std::fs::remove_dir(&file).unwrap();
        // A link in its place is refused, not followed, even to a valid
        // list.
        let elsewhere = data_dir("refuse-target");
        let valid = elsewhere.join(PINS_FILE);
        std::fs::write(&valid, b"").unwrap();
        std::fs::set_permissions(&valid, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&valid, &file).unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(matches!(err, ClientsError::Io { .. }), "{err}");
        // So is one in the directory's place.
        std::fs::remove_dir_all(&clients).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &clients).unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(matches!(err, ClientsError::Io { .. }), "{err}");
        assert!(!elsewhere.join(PARTIAL_FILE).exists());
        std::fs::remove_file(&clients).unwrap();
        std::fs::remove_dir_all(&elsewhere).unwrap();

        std::fs::write(&clients, b"").unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(
            matches!(
                err,
                ClientsError::Kind {
                    expected: "directory",
                    ..
                }
            ),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_store_is_made_in_the_data_directory_checked_not_the_one_its_path_names_now() {
        let dir = data_dir("swap");
        let data = File::open(&dir).unwrap();
        // Someone who may rename in the parent swaps another directory in.
        let checked = PathBuf::from(format!("{}-checked", dir.display()));
        let _gone = std::fs::remove_dir_all(&checked);
        std::fs::rename(&dir, &checked).unwrap();
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let store = ClientStore::open(&data, &dir, &[], runtime()).unwrap();
        store.enroll(Fingerprint::of(b"pin")).unwrap();
        assert!(!dir.join(CLIENTS_DIR).exists(), "not made in the swap");
        assert!(checked.join(CLIENTS_DIR).join(PINS_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&checked).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn posix_open_a_fifo_as_the_pins_is_refused_not_waited_on() {
        let dir = data_dir("fifo");
        drop(open(&dir, &[], runtime()).unwrap());
        let clients = File::open(dir.join(CLIENTS_DIR)).unwrap();
        rustix::fs::mkfifoat(&clients, PINS_FILE, PRIVATE).unwrap();
        // No writer ever opens it: without `O_NONBLOCK` this would hang.
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(
            matches!(
                err,
                ClientsError::Kind {
                    expected: "regular file",
                    ..
                }
            ),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_second_store_on_the_directory_is_refused_while_the_first_lives() {
        let dir = data_dir("in-use");
        let first = open(&dir, &[], runtime()).unwrap();
        let err = open(&dir, &[], runtime()).unwrap_err();
        assert!(matches!(err, ClientsError::InUse(_)), "{err}");
        assert!(err.to_string().contains("another lotse daemon"), "{err}");
        drop(first);
        open(&dir, &[], runtime()).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn removing_an_enrolled_pin_persists_and_closes_its_connections_and_no_other() {
        let dir = data_dir("remove");
        let fixed = Fingerprint::of(b"fixed");
        let store = open(&dir, &[fixed], runtime()).unwrap();
        let (gone, kept) = (Fingerprint::of(b"gone"), Fingerprint::of(b"kept"));
        store.enroll(gone).unwrap();
        store.enroll(kept).unwrap();
        let first = store.attach(ConnectionId(1), gone);
        let second = store.attach(ConnectionId(2), gone);
        let other = store.attach(ConnectionId(3), kept);
        let closed = store.attach(ConnectionId(4), fixed);
        store.detach(ConnectionId(4));
        let listed = store.list().clients;
        let mut expected = vec![
            ControlClient {
                pin: fixed.to_string(),
                fixed: true,
                connected: false,
            },
            ControlClient {
                pin: gone.to_string(),
                fixed: false,
                connected: true,
            },
            ControlClient {
                pin: kept.to_string(),
                fixed: false,
                connected: true,
            },
        ];
        expected.sort_by_key(|client| Fingerprint::parse(&client.pin).unwrap());
        assert_eq!(listed, expected);

        assert_eq!(
            store.remove(fixed, ConnectionId(9)).unwrap(),
            Removal::Fixed
        );
        assert!(store.allows(&fixed));
        assert_eq!(
            store
                .remove(Fingerprint::of(b"unknown"), ConnectionId(9))
                .unwrap(),
            Removal::Unknown
        );
        // The second asked: it closes itself once it has answered.
        assert_eq!(
            store.remove(gone, ConnectionId(2)).unwrap(),
            Removal::Removed { closed: 2 }
        );
        assert!(first.is_cancelled() && !second.is_cancelled());
        assert!(!other.is_cancelled() && !closed.is_cancelled());
        assert!(!store.allows(&gone));
        assert_eq!(
            store.remove(gone, ConnectionId(9)).unwrap(),
            Removal::Unknown,
            "idempotent"
        );
        let file = dir.join(CLIENTS_DIR).join(PINS_FILE);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{kept}\n"));
        // A connection of a pin removed since its handshake closes at once.
        assert!(store.attach(ConnectionId(5), gone).is_cancelled());
        assert!(!store.attach(ConnectionId(6), fixed).is_cancelled());

        drop(store);
        let again = open(&dir, &[], runtime()).unwrap();
        assert!(!again.allows(&gone), "removed for good");
        assert!(again.allows(&kept));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_sync_after_the_rename_keeps_the_enrollment_and_says_so() {
        let (logs, _guard) = crate::pairing::test_support::capture();
        let dir = data_dir("sync-fails");
        let store = open(&dir, &[], runtime())
            .unwrap()
            .with_sync_dir(|_| Err(io::Error::other("disk")));
        let pin = Fingerprint::of(b"pin");
        store.enroll(pin).unwrap();
        assert!(store.allows(&pin), "the renamed file is the list in force");
        let file = dir.join(CLIENTS_DIR).join(PINS_FILE);
        assert_eq!(std::fs::read_to_string(file).unwrap(), format!("{pin}\n"));
        assert!(logs.text().contains("a crash may undo the change"));
        assert!(logs.text().contains("change=\"enrolled\""));
        assert_eq!(
            store.remove(pin, ConnectionId(9)).unwrap(),
            Removal::Removed { closed: 0 }
        );
        assert!(!store.allows(&pin));
        assert!(logs.text().contains("change=\"removed\""));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Both sides of a sync held open by
    /// `a_write_in_progress_does_not_hold_up_the_readers`.
    static SYNCING: std::sync::Barrier = std::sync::Barrier::new(2);

    #[test]
    fn a_write_in_progress_does_not_hold_up_the_readers() {
        let dir = data_dir("readers");
        let store = open(&dir, &[], runtime()).unwrap().with_sync_dir(|_| {
            SYNCING.wait();
            SYNCING.wait();
            Ok(())
        });
        let pin = Fingerprint::of(b"pin");
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| store.enroll(pin));
            SYNCING.wait();
            // The write is still going: the verifier's reads answer anyway.
            assert!(store.allows(&pin));
            assert!(!store.is_empty());
            SYNCING.wait();
            writer.join().unwrap().unwrap();
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Both sides of each sync held open by
    /// `a_reenrollment_waits_for_the_removal_to_close_its_connections`.
    static REMOVING: std::sync::Barrier = std::sync::Barrier::new(2);

    #[test]
    fn a_reenrollment_waits_for_the_removal_to_close_its_connections() {
        let dir = data_dir("reenroll");
        let store = open(&dir, &[], runtime()).unwrap();
        let pin = Fingerprint::of(b"pin");
        store.enroll(pin).unwrap();
        let old = store.attach(ConnectionId(1), pin);
        let store = store.with_sync_dir(|_| {
            REMOVING.wait();
            REMOVING.wait();
            Ok(())
        });
        std::thread::scope(|scope| {
            let removal = scope.spawn(|| store.remove(pin, ConnectionId(9)));
            REMOVING.wait();
            // Syncing: the connection is already closed, and the next
            // change has to wait for the removal to end.
            assert!(old.is_cancelled());
            assert!(!store.allows(&pin));
            assert!(store.writing.try_lock().is_err());
            let enrollment = scope.spawn(|| store.enroll(pin));
            REMOVING.wait();
            assert_eq!(
                removal.join().unwrap().unwrap(),
                Removal::Removed { closed: 1 }
            );
            REMOVING.wait();
            REMOVING.wait();
            enrollment.join().unwrap().unwrap();
        });
        assert!(store.allows(&pin));
        assert!(!store.attach(ConnectionId(2), pin).is_cancelled());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_removal_keeps_the_pin_and_its_connection() {
        let dir = data_dir("remove-fails");
        let store = open(&dir, &[], runtime()).unwrap();
        let pin = Fingerprint::of(b"pin");
        store.enroll(pin).unwrap();
        let token = store.attach(ConnectionId(1), pin);
        std::fs::DirBuilder::new()
            .create(dir.join(CLIENTS_DIR).join(PARTIAL_FILE))
            .unwrap();
        assert!(store.remove(pin, ConnectionId(9)).is_err());
        assert!(store.allows(&pin));
        assert!(!token.is_cancelled());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_write_keeps_the_pin_out() {
        let dir = data_dir("write-fails");
        let store = open(&dir, &[], runtime()).unwrap();
        // A directory where the partial file goes: it can be neither
        // removed as a file nor created.
        std::fs::DirBuilder::new()
            .create(dir.join(CLIENTS_DIR).join(PARTIAL_FILE))
            .unwrap();
        let pin = Fingerprint::of(b"pin");
        assert!(store.enroll(pin).is_err());
        assert!(!store.allows(&pin));
        assert!(store.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
