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
//! uid needs no access to the directories above it. The pins file is one
//! pin per line, replaced whole on every change: written to a new file with
//! mode 0600, synced, renamed into place and the directory synced, so a
//! crash leaves the old list or the new one. Pins are public; the file is
//! private so nobody else can read who is enrolled.

use std::collections::{BTreeSet, HashSet};
use std::io::{self, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

use lotse_core::fingerprint::Fingerprint;
use rustix::fs::{AtFlags, Mode, OFlags};

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
}

/// Who may connect: the fixed pins and the enrolled ones.
#[derive(Debug)]
pub(crate) struct ClientStore {
    /// The configuration's pins, which no enrollment changes.
    fixed: HashSet<Fingerprint>,
    /// The enrolled pins, as [`PINS_FILE`] holds them.
    enrolled: RwLock<BTreeSet<Fingerprint>>,
    /// [`CLIENTS_DIR`].
    dir: PathBuf,
    /// [`CLIENTS_DIR`], opened before the privilege drop; every write is
    /// relative to it.
    dir_fd: OwnedFd,
}

impl ClientStore {
    /// Makes `<data_dir>/clients` if it is missing, owned by `runtime`
    /// (the uid and gid the daemon runs as after the drop) and mode 0700,
    /// checks it, and reads the enrolled pins. Runs before the drop.
    pub(crate) fn open(
        data_dir: &Path,
        fixed: &[Fingerprint],
        runtime: (u32, u32),
    ) -> Result<Self, ClientsError> {
        let dir = data_dir.join(CLIENTS_DIR);
        let text = dir.display().to_string();
        let io = |source: io::Error| io_error(&text, source);
        // A directory that exists already, or could not be made, is
        // judged by the check below.
        if std::fs::DirBuilder::new().mode(0o700).create(&dir).is_ok() {
            std::os::unix::fs::chown(&dir, Some(runtime.0), Some(runtime.1)).map_err(io)?;
        }
        check(
            &text,
            &std::fs::symlink_metadata(&dir).map_err(io)?,
            "directory",
            runtime.0,
        )?;
        // Close-on-exec, as `std` opens every file: no worker inherits it.
        let dir_fd = OwnedFd::from(std::fs::File::open(&dir).map_err(io)?);
        let enrolled = read_pins(&dir.join(PINS_FILE), runtime.0)?;
        tracing::info!(
            fixed = fixed.len(),
            enrolled = enrolled.len(),
            "control TLS clients loaded"
        );
        Ok(Self {
            fixed: fixed.iter().copied().collect(),
            enrolled: RwLock::new(enrolled),
            dir,
            dir_fd,
        })
    }

    /// The directory the daemon writes at runtime, for the sandbox.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
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
    /// only once it is on disk. Blocking: run it off the runtime's threads.
    pub(crate) fn enroll(&self, pin: Fingerprint) -> io::Result<()> {
        let mut enrolled = self
            .enrolled
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let mut next = enrolled.clone();
        next.insert(pin);
        write_pins(&self.dir_fd, &next)?;
        *enrolled = next;
        drop(enrolled);
        Ok(())
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

/// The pins in `path`, none when it does not exist. Blank lines are
/// skipped; anything else must be a pin.
fn read_pins(path: &Path, owner: u32) -> Result<BTreeSet<Fingerprint>, ClientsError> {
    let text = path.display().to_string();
    let io = |source: io::Error| io_error(&text, source);
    let meta = match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        found => found.map_err(io)?,
    };
    check(&text, &meta, "regular file", owner)?;
    let content = std::fs::read_to_string(path).map_err(io)?;
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
/// with mode 0600, synced, renamed into place, the directory synced. A
/// partial file a crash left behind is replaced.
fn write_pins(dir: &OwnedFd, pins: &BTreeSet<Fingerprint>) -> io::Result<()> {
    let _stale = rustix::fs::unlinkat(dir, PARTIAL_FILE, AtFlags::empty());
    let fd = rustix::fs::openat(dir, PARTIAL_FILE, CREATE, PRIVATE)?;
    let mut file = std::fs::File::from(fd);
    let mut content = String::new();
    for pin in pins {
        content.push_str(&pin.to_string());
        content.push('\n');
    }
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);
    rustix::fs::renameat(dir, PARTIAL_FILE, dir, PINS_FILE)?;
    rustix::fs::fsync(dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn data_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lotse-clients-{name}-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
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
        let store = ClientStore::open(&dir, &[fixed], runtime()).unwrap();
        let clients = dir.join(CLIENTS_DIR);
        assert_eq!(store.dir(), clients);
        let meta = std::fs::metadata(&clients).unwrap();
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

        let again = ClientStore::open(&dir, &[], runtime()).unwrap();
        assert!(again.allows(&enrolled), "read back after a restart");
        assert!(
            !again.allows(&fixed),
            "fixed pins come from the configuration only"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_pins_means_empty_and_blank_lines_are_skipped() {
        let dir = data_dir("empty");
        let store = ClientStore::open(&dir, &[], runtime()).unwrap();
        assert!(store.is_empty());
        let file = dir.join(CLIENTS_DIR).join(PINS_FILE);
        let pin = Fingerprint::of(b"pin");
        let mut options = std::fs::OpenOptions::new();
        std::os::unix::fs::OpenOptionsExt::mode(options.write(true).create_new(true), 0o600);
        let mut out = options.open(&file).unwrap();
        write!(out, "\n  {pin}  \n\n").unwrap();
        let store = ClientStore::open(&dir, &[], runtime()).unwrap();
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
        let err = ClientStore::open(&dir, &[], runtime()).unwrap_err();
        assert!(
            matches!(err, ClientsError::Mode { mode: 0o750, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("0750"), "{err}");
        std::fs::set_permissions(&clients, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = runtime();
        let err = ClientStore::open(&dir, &[], (uid.wrapping_add(1), gid)).unwrap_err();
        assert!(matches!(err, ClientsError::Owner { .. }), "{err}");

        let file = clients.join(PINS_FILE);
        std::fs::write(&file, b"").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = ClientStore::open(&dir, &[], runtime()).unwrap_err();
        assert!(
            matches!(err, ClientsError::Mode { mode: 0o644, .. }),
            "{err}"
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&file, b"\xff not UTF-8\n").unwrap();
        let err = ClientStore::open(&dir, &[], runtime()).unwrap_err();
        assert!(matches!(err, ClientsError::Io { .. }), "{err}");
        std::fs::write(&file, b"not a pin\n").unwrap();
        let err = ClientStore::open(&dir, &[], runtime()).unwrap_err();
        assert!(matches!(err, ClientsError::Pin { line: 1, .. }), "{err}");
        assert!(err.to_string().contains("line 1"), "{err}");

        std::fs::remove_file(&file).unwrap();
        std::fs::DirBuilder::new().create(&file).unwrap();
        let err = ClientStore::open(&dir, &[], runtime()).unwrap_err();
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
        std::os::unix::fs::symlink(&file, &file).unwrap();
        let err = ClientStore::open(&dir, &[], runtime()).unwrap_err();
        assert!(
            matches!(err, ClientsError::Kind { .. }),
            "a link is not a file: {err}"
        );

        std::fs::remove_dir_all(&clients).unwrap();
        std::fs::write(&clients, b"").unwrap();
        let err = ClientStore::open(&dir, &[], runtime()).unwrap_err();
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
        let err = ClientStore::open(&dir.join("missing"), &[], runtime()).unwrap_err();
        assert!(matches!(err, ClientsError::Io { .. }), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_write_keeps_the_pin_out() {
        let dir = data_dir("write-fails");
        let store = ClientStore::open(&dir, &[], runtime()).unwrap();
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
