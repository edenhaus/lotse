//! The control listener's server identity: a P-256 key and a self-signed
//! certificate, generated into the data directory on the first start with
//! a listener and read from there on every later one, in the main thread
//! before the privilege drop. Clients pin the certificate by its SHA-256
//! ([`Fingerprint`]), which every start logs.
//!
//! The key and the certificate share one PEM file, so a generation is one
//! atomic rename and a crash leaves either no identity or a whole one. The
//! file is written with mode 0600 from its creation (`O_EXCL`, then
//! `rename`) and is refused when its mode lets the group or others read
//! it, or when it belongs to anyone but the uid the daemon started as. The
//! directory holding it must belong to that uid too and must not be
//! writable by the group or others, so nobody else can replace the file.
//! Starts sharing the directory take turns under an exclusive `flock` on
//! it, so concurrent first starts agree on one identity.
//!
//! Standards: RFC 5280 §4.1.2.5 (validity: `notAfter` 99991231235959Z, "no
//! well-defined expiration date"), RFC 5958 (PKCS #8 private keys), RFC
//! 7468 (PEM), FIPS 186-4 (P-256 ECDSA).

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use lotse_core::fingerprint::Fingerprint;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SignatureAlgorithm};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The identity's file in the data directory: the PKCS #8 key, then the
/// certificate, both PEM.
pub const IDENTITY_FILE: &str = "control-identity.pem";

/// Where a generation writes before the rename to [`IDENTITY_FILE`].
const PARTIAL_FILE: &str = "control-identity.pem.partial";

/// The certificate's subject and issuer common name.
const CERTIFICATE_NAME: &str = "lotse control";

/// The daemon's control identity: its certificate, the key, and the pin
/// clients check. The key never leaves the process: `Debug` redacts it.
pub struct ServerIdentity {
    /// The DER certificate.
    pub(crate) certificate: CertificateDer<'static>,
    /// The private key.
    pub(crate) key: PrivateKeyDer<'static>,
    /// The certificate's SHA-256.
    pin: Fingerprint,
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("pin", &self.pin)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Why the identity could not be read or made.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The data directory is missing or unreadable.
    #[error("data directory {path}: {source}")]
    Directory {
        /// The directory.
        path: String,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The data directory is not a directory.
    #[error("data directory {0} is not a directory")]
    NotADirectory(String),
    /// The group or others may write to the data directory.
    #[error("data directory {path} is mode {mode:04o}; the group and others must not write to it")]
    DirectoryMode {
        /// The directory.
        path: String,
        /// Its permission bits.
        mode: u32,
    },
    /// The data directory belongs to someone else.
    #[error("data directory {path} is owned by uid {owner}, not {expected}")]
    DirectoryOwner {
        /// The directory.
        path: String,
        /// Its owner.
        owner: u32,
        /// The uid the daemon started as.
        expected: u32,
    },
    /// No identity has been made in the directory yet.
    #[error(
        "no control identity in {0} yet; the daemon makes one on its first start with a control listener"
    )]
    Missing(String),
    /// The identity is not a regular file.
    #[error("control identity {0} is not a regular file")]
    NotAFile(String),
    /// The group or others may read the identity.
    #[error("control identity {path} is mode {mode:04o}, must be 0600 or stricter")]
    FileMode {
        /// The file.
        path: String,
        /// Its permission bits.
        mode: u32,
    },
    /// The identity belongs to someone else.
    #[error("control identity {path} is owned by uid {owner}, not {expected}")]
    FileOwner {
        /// The file.
        path: String,
        /// Its owner.
        owner: u32,
        /// The uid the daemon started as.
        expected: u32,
    },
    /// Reading or writing a file failed.
    #[error("control identity {path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The file holds no usable key or certificate.
    #[error("control identity {path}: {what}")]
    Pem {
        /// The file.
        path: String,
        /// What is missing or malformed.
        what: String,
    },
    /// The key or the certificate could not be made.
    #[error("generating the control identity: {0}")]
    Generate(#[source] rcgen::Error),
}

impl ServerIdentity {
    /// The certificate's SHA-256, the pin clients check.
    pub const fn pin(&self) -> Fingerprint {
        self.pin
    }

    /// The identity in `dir`, made there first when there is none. `dir`
    /// and the file must belong to `owner_uid`, the uid the daemon
    /// started as.
    pub fn load_or_create(dir: &Path, owner_uid: u32) -> Result<Self, IdentityError> {
        let _locked = lock_directory(dir, owner_uid)?;
        match Self::load(dir, owner_uid) {
            Err(IdentityError::Missing(_)) => {
                let pem = generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
                write_new(dir, &pem)?;
                let identity = Self::load(dir, owner_uid)?;
                tracing::info!(
                    event = "control_identity_created",
                    path = %dir.join(IDENTITY_FILE).display(),
                    server_pin = %identity.pin,
                    "control identity generated"
                );
                Ok(identity)
            }
            loaded => loaded,
        }
    }

    /// The identity in `dir`, which must exist, be a regular file that
    /// only `owner_uid` can read, and hold a key and a certificate.
    pub fn load(dir: &Path, owner_uid: u32) -> Result<Self, IdentityError> {
        let path = dir.join(IDENTITY_FILE);
        let text = path.display().to_string();
        let io = |source: io::Error| io_error(&text, source);
        let mut file = match std::fs::File::open(&path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(IdentityError::Missing(dir.display().to_string()));
            }
            opened => opened.map_err(io)?,
        };
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file() {
            return Err(IdentityError::NotAFile(text.clone()));
        }
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(IdentityError::FileMode {
                path: text.clone(),
                mode,
            });
        }
        if meta.uid() != owner_uid {
            return Err(IdentityError::FileOwner {
                path: text.clone(),
                owner: meta.uid(),
                expected: owner_uid,
            });
        }
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut file, &mut bytes).map_err(io)?;
        let pem = |what: &str, err: rustls::pki_types::pem::Error| IdentityError::Pem {
            path: text.clone(),
            what: format!("{what}: {err}"),
        };
        let key = PrivateKeyDer::from_pem_slice(&bytes).map_err(|err| pem("private key", err))?;
        let certificate =
            CertificateDer::from_pem_slice(&bytes).map_err(|err| pem("certificate", err))?;
        let pin = Fingerprint::of(&certificate);
        Ok(Self {
            certificate,
            key,
            pin,
        })
    }
}

/// An I/O error on `path`.
fn io_error(path: &str, source: io::Error) -> IdentityError {
    IdentityError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Refuses a data directory that is missing, not a directory, writable by
/// the group or others, or not `owner_uid`'s, and takes an exclusive
/// `flock` on it, held until the returned handle drops: two daemons
/// sharing the directory make and read the identity one at a time, so
/// neither removes the other's partial file or renames over the identity
/// the other already serves.
fn lock_directory(dir: &Path, owner_uid: u32) -> Result<std::fs::File, IdentityError> {
    let text = dir.display().to_string();
    let directory = |source| IdentityError::Directory {
        path: text.clone(),
        source,
    };
    let meta = std::fs::metadata(dir).map_err(directory)?;
    if !meta.is_dir() {
        return Err(IdentityError::NotADirectory(text));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(IdentityError::DirectoryMode { path: text, mode });
    }
    if meta.uid() != owner_uid {
        return Err(IdentityError::DirectoryOwner {
            path: text,
            owner: meta.uid(),
            expected: owner_uid,
        });
    }
    let handle = std::fs::File::open(dir).map_err(directory)?;
    handle.lock().map_err(directory)?;
    Ok(handle)
}

/// A fresh key for `alg` and its self-signed certificate, as the PEM text
/// of [`IDENTITY_FILE`]. Valid from 2000-01-01 and without expiry (RFC
/// 5280 §4.1.2.5), so neither a wrong clock at boot nor a date turns into
/// an outage: replacing the identity is a decision, not a deadline. The
/// serial is derived from the public key, so nothing reads a clock.
fn generate(alg: &'static SignatureAlgorithm) -> Result<String, IdentityError> {
    let key = KeyPair::generate_for(alg).map_err(IdentityError::Generate)?;
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, CERTIFICATE_NAME);
    params.distinguished_name = name;
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    // RFC 5280 §4.1.2.5: 99991231235959Z, no well-defined expiration date.
    // The components are in range, so the fallback (the same day's first
    // second, as good for the purpose) is never taken.
    let last_day = rcgen::date_time_ymd(9999, 12, 31);
    params.not_after = last_day
        .replace_hour(23)
        .and_then(|at| at.replace_minute(59))
        .and_then(|at| at.replace_second(59))
        .unwrap_or(last_day);
    let certificate = params.self_signed(&key).map_err(IdentityError::Generate)?;
    Ok(format!("{}{}", key.serialize_pem(), certificate.pem()))
}

/// Writes `pem` as [`IDENTITY_FILE`] in `dir`: to a new file created with
/// mode 0600, synced, renamed into place, and the directory synced. A
/// partial file a crash left behind is replaced.
fn write_new(dir: &Path, pem: &str) -> Result<(), IdentityError> {
    let partial: PathBuf = dir.join(PARTIAL_FILE);
    let text = partial.display().to_string();
    let _stale = std::fs::remove_file(&partial);
    let io = |source: io::Error| io_error(&text, source);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&partial)
        .map_err(io)?;
    file.write_all(pem.as_bytes()).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    std::fs::rename(&partial, dir.join(IDENTITY_FILE)).map_err(io)?;
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(io)
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

    fn data_dir(name: &str, mode: u32) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lotse-identity-{name}-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(mode).create(&dir).unwrap();
        // The umask may have taken bits the test asked for.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    fn uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn the_first_start_makes_a_0600_identity_and_later_starts_read_it() {
        let dir = data_dir("create", 0o700);
        std::fs::write(dir.join(PARTIAL_FILE), b"left by a crash").unwrap();
        let made = ServerIdentity::load_or_create(&dir, uid()).unwrap();
        let path = dir.join(IDENTITY_FILE);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert!(!dir.join(PARTIAL_FILE).exists(), "renamed into place");
        assert_eq!(made.pin(), Fingerprint::of(&made.certificate));
        let again = ServerIdentity::load_or_create(&dir, uid()).unwrap();
        assert_eq!(again.pin(), made.pin(), "kept across starts");
        let shown = format!("{made:?}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(!shown.contains("PRIVATE"), "{shown}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_first_starts_agree_on_one_identity() {
        // Each thread opens the directory itself, so each holds its own
        // lock, as two daemons would.
        let dir = data_dir("concurrent", 0o700);
        let starts = 8;
        let barrier = std::sync::Barrier::new(starts);
        let pins: Vec<Fingerprint> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..starts)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        ServerIdentity::load_or_create(&dir, uid()).map(|made| made.pin())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap().unwrap())
                .collect()
        });
        let kept = ServerIdentity::load(&dir, uid()).unwrap().pin();
        assert!(pins.iter().all(|pin| *pin == kept), "{pins:?} vs {kept}");
        assert!(!dir.join(PARTIAL_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_certificate_never_expires_rfc5280_4_1_2_5() {
        let dir = data_dir("validity", 0o700);
        let made = ServerIdentity::load_or_create(&dir, uid()).unwrap();
        let der = made.certificate.as_ref();
        // RFC 5280 §4.1.2.5.1/.2: UTCTime before 2050, GeneralizedTime from it on.
        let utc_2000 = b"\x17\x0d000101000000Z";
        let general_9999 = b"\x18\x0f99991231235959Z";
        assert!(der.windows(utc_2000.len()).any(|w| w == utc_2000));
        assert!(der.windows(general_9999.len()).any(|w| w == general_9999));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_backend_that_cannot_make_the_key_is_an_error() {
        // `ring` signs with RSA keys but cannot generate them.
        let err = generate(&rcgen::PKCS_RSA_SHA256).unwrap_err();
        assert!(matches!(err, IdentityError::Generate(_)), "{err}");
        assert!(
            err.to_string()
                .starts_with("generating the control identity")
        );
    }

    #[test]
    fn a_directory_others_can_write_or_someone_else_owns_is_refused() {
        let missing = std::env::temp_dir().join("lotse-identity-missing-dir");
        let err = ServerIdentity::load_or_create(&missing, uid()).unwrap_err();
        assert!(matches!(err, IdentityError::Directory { .. }), "{err}");
        let open = data_dir("open", 0o770);
        let err = ServerIdentity::load_or_create(&open, uid()).unwrap_err();
        assert!(
            matches!(err, IdentityError::DirectoryMode { mode: 0o770, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("0770"), "{err}");
        let private = data_dir("dir-owner", 0o750);
        let err = ServerIdentity::load_or_create(&private, uid().wrapping_add(1)).unwrap_err();
        assert!(matches!(err, IdentityError::DirectoryOwner { .. }), "{err}");
        let file = private.join("file");
        std::fs::write(&file, b"").unwrap();
        let err = ServerIdentity::load_or_create(&file, uid()).unwrap_err();
        assert!(matches!(err, IdentityError::NotADirectory(_)), "{err}");
        std::fs::remove_dir_all(&open).unwrap();
        std::fs::remove_dir_all(&private).unwrap();
    }

    #[test]
    fn an_identity_others_can_read_or_someone_else_owns_is_refused() {
        let dir = data_dir("file", 0o700);
        let err = ServerIdentity::load(&dir, uid()).unwrap_err();
        assert!(matches!(err, IdentityError::Missing(_)), "{err}");
        assert!(err.to_string().contains("first start"), "{err}");
        ServerIdentity::load_or_create(&dir, uid()).unwrap();
        let path = dir.join(IDENTITY_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = ServerIdentity::load_or_create(&dir, uid()).unwrap_err();
        assert!(
            matches!(err, IdentityError::FileMode { mode: 0o640, .. }),
            "{err}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let err = ServerIdentity::load(&dir, uid().wrapping_add(1)).unwrap_err();
        assert!(matches!(err, IdentityError::FileOwner { .. }), "{err}");
        assert!(
            ServerIdentity::load(&dir, uid()).is_ok(),
            "0400 is stricter"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::DirBuilder::new().create(&path).unwrap();
        let err = ServerIdentity::load(&dir, uid()).unwrap_err();
        assert!(matches!(err, IdentityError::NotAFile(_)), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_without_a_key_or_a_certificate_or_unreadable_is_refused() {
        let dir = data_dir("pem", 0o700);
        let path = dir.join(IDENTITY_FILE);
        let made = generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let (key, certificate) = made.split_at(made.find("-----BEGIN CERTIFICATE").unwrap());
        for (content, what) in [(certificate, "private key"), (key, "certificate")] {
            let _gone = std::fs::remove_file(&path);
            write_new(&dir, content).unwrap();
            let err = ServerIdentity::load(&dir, uid()).unwrap_err();
            assert!(
                matches!(&err, IdentityError::Pem { what: w, .. } if w.starts_with(what)),
                "{err}"
            );
        }
        // A link to itself: the open fails, and not as a missing file.
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&path, &path).unwrap();
        let err = ServerIdentity::load(&dir, uid()).unwrap_err();
        assert!(matches!(err, IdentityError::Io { .. }), "{err}");
        // A directory as the partial file cannot be replaced or opened.
        std::fs::remove_file(&path).unwrap();
        std::fs::DirBuilder::new()
            .create(dir.join(PARTIAL_FILE))
            .unwrap();
        let err = write_new(&dir, &made).unwrap_err();
        assert!(matches!(err, IdentityError::Io { .. }), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
