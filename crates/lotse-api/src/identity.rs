//! The control listener's server identity: a P-256 key and a self-signed
//! certificate, generated into the data directory on the first start with
//! a listener and read from there on every later one, in the main thread
//! before the privilege drop. Clients pin the certificate by its SHA-256
//! ([`Fingerprint`]), which every start logs.
//!
//! A generated certificate names [`SERVER_NAME`] as a DNS name in its
//! subject alternative names, so a client whose TLS stack verifies by name
//! can trust it as its own root and verify it by that name: Go's x509
//! never matches a name against the Common Name (from Go 1.15), so an
//! identity without the name is refused (observed with Prometheus 3.16.0,
//! `server_name: lotse`, on 2026-11-15: "x509: certificate is not valid
//! for any names, but wanted to match lotse"), and Go accepts a leaf that
//! is itself in the root pool as a chain of one, which amounts to pinning
//! it (the same Prometheus scraped the reissued identity). An
//! identity made before the name keeps working as it is: the pin is the
//! SHA-256 of the whole certificate, so a new certificate is a new pin
//! and every client pairs again. Only [`ServerIdentity::reissue`] makes
//! one, from the same key, when the operator asks.
//!
//! The key and the certificate share one PEM file, so a generation is one
//! atomic rename and a crash leaves either no identity or a whole one. The
//! file is written with mode 0600 from its creation (`O_EXCL`, then
//! `rename`) and is refused when its mode lets the group or others read
//! it, or when it belongs to anyone but the uid the daemon started as or,
//! started as root, the uid it drops to ([`Owners`]). The directory holding
//! it must belong to one of those too and give the group and others no
//! access at all, so nobody else can replace the file, list the directory
//! or reach anything in it by name.
//! The directory is opened once, then checked, locked and used through
//! that descriptor (`openat`, `renameat`), so a directory swapped in at
//! its path after the checks is never read or written. Starts sharing the
//! directory take turns under an exclusive `flock` on it, so concurrent
//! first starts agree on one identity.
//!
//! Standards: RFC 5280 §4.1.2.5 (validity: `notAfter` 99991231235959Z, "no
//! well-defined expiration date"), §4.1.2.2 (a serial unique per
//! certificate of an issuer), §4.2.1.6 (the subject alternative name's
//! `dNSName`), RFC 6125 §6.4.4 (a client checks the Common Name only
//! without a DNS name in the subject alternative names), RFC 5958 (PKCS #8
//! private keys), RFC 7468 (PEM, §5 the certificate's), FIPS 186-4 (P-256
//! ECDSA).

use std::fmt;
use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use lotse_core::fingerprint::Fingerprint;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData as _, SerialNumber,
    SignatureAlgorithm,
};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use crate::owners::Owners;

/// The identity's file in the data directory: the PKCS #8 key, then the
/// certificate, both PEM.
pub const IDENTITY_FILE: &str = "control-identity.pem";

/// Where a generation writes before the rename to [`IDENTITY_FILE`].
const PARTIAL_FILE: &str = "control-identity.pem.partial";

/// The certificate's subject and issuer common name.
const CERTIFICATE_NAME: &str = "lotse control";

/// The DNS name a generated certificate names in its subject alternative
/// names (RFC 5280 §4.2.1.6), fixed whatever host the daemon runs on: a
/// client that verifies by name trusts the certificate itself and gives
/// this name as the server's (Prometheus' `server_name`).
pub const SERVER_NAME: &str = "lotse";

/// The serial's longest length (RFC 5280 §4.1.2.2: "MUST NOT use
/// serialNumber values longer than 20 octets").
const SERIAL_BYTES: usize = 20;

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
    /// The group or others may read, write or search the data directory.
    #[error("data directory {path} is mode {mode:04o}; the group and others must have no access")]
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
        /// The uids that may own it.
        expected: Owners,
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
        /// The uids that may own it.
        expected: Owners,
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

    /// The certificate alone as PEM (RFC 7468 §5), never the key: what a
    /// client trusts as its CA file to verify the daemon by
    /// [`SERVER_NAME`].
    pub fn certificate_pem(&self) -> String {
        let block = pem::Pem::new("CERTIFICATE", self.certificate.as_ref());
        pem::encode_config(
            &block,
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        )
    }

    /// Whether the certificate names [`SERVER_NAME`] as a DNS name in its
    /// subject alternative names, as every certificate made since does: a
    /// client that verifies by name (RFC 6125 §6.4.4: not by the Common
    /// Name once a DNS name is there; Go's x509 never by it) accepts
    /// only such a one. An identity made before has none until
    /// [`Self::reissue`].
    pub fn names_server(&self) -> bool {
        ServerName::try_from(SERVER_NAME).is_ok_and(|name| {
            webpki::EndEntityCert::try_from(&self.certificate).is_ok_and(|certificate| {
                certificate.verify_is_valid_for_subject_name(&name).is_ok()
            })
        })
    }

    /// A new certificate for the identity in `dir`, from the same key and
    /// naming [`SERVER_NAME`], in place of the old one, which `dir` must
    /// hold; checked and locked as [`Self::load_or_create`] does it, and
    /// written as atomically. The pin changes, so every client pairs
    /// again; a running daemon serves the old certificate until it
    /// restarts. Asked for by the operator only, never on a start.
    pub fn reissue(dir: &Path, owners: Owners) -> Result<Self, IdentityError> {
        let locked = checked_directory(dir, owners, true)?;
        let old = Self::load_in(&locked, dir, owners)?;
        let key = KeyPair::try_from(&old.key).map_err(IdentityError::Generate)?;
        let pem = certify(&key)?;
        write_new(&locked, dir, &pem)?;
        let identity = Self::load_in(&locked, dir, owners)?;
        tracing::info!(
            event = "control_identity_reissued",
            path = %dir.join(IDENTITY_FILE).display(),
            old_pin = %old.pin,
            server_pin = %identity.pin,
            "control identity reissued: every client must pair again"
        );
        Ok(identity)
    }

    /// The identity in `dir`, made there first when there is none. `dir`
    /// and the file must belong to one of `owners`: the uid the daemon
    /// started as or, started as root, the uid it drops to.
    pub fn load_or_create(dir: &Path, owners: Owners) -> Result<Self, IdentityError> {
        let locked = checked_directory(dir, owners, true)?;
        Self::load_or_create_in(&locked, dir, owners)
    }

    /// [`Self::load_or_create`] in `handle`, `dir` opened, checked and
    /// locked by [`checked_directory`]; `dir` only names it in messages.
    fn load_or_create_in(handle: &File, dir: &Path, owners: Owners) -> Result<Self, IdentityError> {
        match Self::load_in(handle, dir, owners) {
            Err(IdentityError::Missing(_)) => {
                let pem = generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
                write_new(handle, dir, &pem)?;
                let identity = Self::load_in(handle, dir, owners)?;
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
    /// only its owner, one of `owners`, can read, and hold a key and a
    /// certificate. `dir` is checked as [`Self::load_or_create`] checks it,
    /// so this reads only an identity a start would serve.
    pub fn load(dir: &Path, owners: Owners) -> Result<Self, IdentityError> {
        let handle = checked_directory(dir, owners, false)?;
        Self::load_in(&handle, dir, owners)
    }

    /// [`Self::load`] in `handle`, `dir` opened; `dir` only names it in
    /// messages. A link in the file's place is refused, not followed, and
    /// a FIFO is refused, not waited on.
    fn load_in(handle: &File, dir: &Path, owners: Owners) -> Result<Self, IdentityError> {
        let text = dir.join(IDENTITY_FILE).display().to_string();
        let io = |source: io::Error| io_error(&text, source);
        // POSIX.1-2024 open(): without `O_NONBLOCK`, opening a FIFO for
        // reading blocks until it has a writer, before the type check
        // below can refuse it. On a regular file the flag changes nothing.
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let mut file = match rustix::fs::openat(handle, IDENTITY_FILE, flags, Mode::empty()) {
            Err(err) if err == Errno::NOENT => {
                return Err(IdentityError::Missing(dir.display().to_string()));
            }
            opened => File::from(opened.map_err(io::Error::from).map_err(io)?),
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
        if !owners.accepts(meta.uid()) {
            return Err(IdentityError::FileOwner {
                path: text.clone(),
                owner: meta.uid(),
                expected: owners,
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

/// `dir` opened as a directory, for every later step to go through. A
/// link in its path is followed: the path is the operator's choice, and
/// what is checked is the directory the descriptor holds.
fn open_directory(dir: &Path) -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    Ok(File::from(rustix::fs::open(dir, flags, Mode::empty())?))
}

/// `dir` opened, refused when it is missing, not a directory, open to the
/// group or others in any way (read, write or search), or owned by none of
/// `owners` (the starting uid or, started as root, the uid the daemon
/// drops to: [`Owners`] says why the second widens nothing), so nobody
/// else can have put or replaced what is in it,
/// or list it or reach a file in it by name. With `lock`, it is held under an exclusive
/// `flock` until the returned handle drops: two daemons sharing the
/// directory make and read the identity one at a time, so neither removes
/// the other's partial file or renames over the identity the other
/// already serves.
pub(crate) fn checked_directory(
    dir: &Path,
    owners: Owners,
    lock: bool,
) -> Result<File, IdentityError> {
    let text = dir.display().to_string();
    let directory = |source| directory_error(&text, source);
    let handle = open_directory(dir).map_err(directory)?;
    let meta = handle.metadata().map_err(directory)?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::DirectoryMode {
            path: text.clone(),
            mode,
        });
    }
    if !owners.accepts(meta.uid()) {
        return Err(IdentityError::DirectoryOwner {
            path: text.clone(),
            owner: meta.uid(),
            expected: owners,
        });
    }
    if lock {
        handle.lock().map_err(directory)?;
    }
    Ok(handle)
}

/// An error on the data directory `path`, which is not a directory when
/// `source` says so.
fn directory_error(path: &str, source: io::Error) -> IdentityError {
    if source.raw_os_error() == Some(Errno::NOTDIR.raw_os_error()) {
        IdentityError::NotADirectory(path.to_owned())
    } else {
        IdentityError::Directory {
            path: path.to_owned(),
            source,
        }
    }
}

/// A fresh key for `alg` and its self-signed certificate ([`certify`]),
/// as the PEM text of [`IDENTITY_FILE`].
fn generate(alg: &'static SignatureAlgorithm) -> Result<String, IdentityError> {
    let key = KeyPair::generate_for(alg).map_err(IdentityError::Generate)?;
    certify(&key)
}

/// `key`'s self-signed certificate naming [`SERVER_NAME`], with the key
/// before it, as the PEM text of [`IDENTITY_FILE`]. Valid from 2000-01-01
/// and without expiry (RFC 5280 §4.1.2.5), so neither a wrong clock at
/// boot nor a date turns into an outage: replacing the identity is a
/// decision, not a deadline. The serial is derived from the public key
/// and the name ([`serial`]), so nothing reads a clock.
fn certify(key: &KeyPair) -> Result<String, IdentityError> {
    let mut params =
        CertificateParams::new(vec![SERVER_NAME.to_owned()]).map_err(IdentityError::Generate)?;
    params.serial_number = Some(serial(key));
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
    let certificate = params.self_signed(key).map_err(IdentityError::Generate)?;
    Ok(format!("{}{}", key.serialize_pem(), certificate.pem()))
}

/// The serial of `key`'s certificate: the first 20 bytes (RFC 5280
/// §4.1.2.2) of the SHA-256 of [`SERVER_NAME`] and the public key, the
/// top bit clear so the integer is positive. An identity made before the
/// name has rcgen's serial, the hash of the key alone, so its reissue,
/// the same issuer with the same key, never repeats its serial.
fn serial(key: &KeyPair) -> SerialNumber {
    let mut named = SERVER_NAME.as_bytes().to_vec();
    named.extend_from_slice(&key.subject_public_key_info());
    let mut bytes = Fingerprint::of(&named).as_bytes().to_vec();
    bytes.truncate(SERIAL_BYTES);
    if let Some(first) = bytes.first_mut() {
        *first &= 0x7f;
    }
    SerialNumber::from(bytes)
}

/// Writes `pem` as [`IDENTITY_FILE`] in `handle`, the directory `dir`
/// opened: to a new file created with mode 0600, synced, renamed into
/// place, and the directory synced. A partial file a crash left behind is
/// replaced.
fn write_new(handle: &File, dir: &Path, pem: &str) -> Result<(), IdentityError> {
    let text = dir.join(PARTIAL_FILE).display().to_string();
    let io = |source: io::Error| io_error(&text, source);
    let _stale = rustix::fs::unlinkat(handle, PARTIAL_FILE, AtFlags::empty());
    let write_only = OFlags::WRONLY; // codespell:ignore wronly
    let flags = write_only | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let created = rustix::fs::openat(handle, PARTIAL_FILE, flags, Mode::RUSR | Mode::WUSR);
    let mut file = File::from(created.map_err(io::Error::from).map_err(io)?);
    file.write_all(pem.as_bytes()).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    rustix::fs::renameat(handle, PARTIAL_FILE, handle, IDENTITY_FILE)
        .map_err(io::Error::from)
        .map_err(io)?;
    handle.sync_all().map_err(io)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::path::PathBuf;

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

    /// The test's own uid, the one owner a start as it accepts.
    fn me() -> Owners {
        Owners::only(uid())
    }

    /// The owners of a start as someone else.
    fn someone_else() -> Owners {
        Owners::only(uid().wrapping_add(1))
    }

    #[test]
    fn the_first_start_makes_a_0600_identity_and_later_starts_read_it() {
        let dir = data_dir("create", 0o700);
        std::fs::write(dir.join(PARTIAL_FILE), b"left by a crash").unwrap();
        let made = ServerIdentity::load_or_create(&dir, me()).unwrap();
        let path = dir.join(IDENTITY_FILE);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert!(!dir.join(PARTIAL_FILE).exists(), "renamed into place");
        assert_eq!(made.pin(), Fingerprint::of(&made.certificate));
        let again = ServerIdentity::load_or_create(&dir, me()).unwrap();
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
                        ServerIdentity::load_or_create(&dir, me()).map(|made| made.pin())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap().unwrap())
                .collect()
        });
        let kept = ServerIdentity::load(&dir, me()).unwrap().pin();
        assert!(pins.iter().all(|pin| *pin == kept), "{pins:?} vs {kept}");
        assert!(!dir.join(PARTIAL_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_directory_swapped_in_after_the_checks_is_never_used() {
        let dir = data_dir("swap", 0o700);
        let locked = checked_directory(&dir, me(), true).unwrap();
        // Someone who may rename in the parent swaps another directory in.
        let checked = PathBuf::from(format!("{}-checked", dir.display()));
        let _gone = std::fs::remove_dir_all(&checked);
        std::fs::rename(&dir, &checked).unwrap();
        std::fs::DirBuilder::new().mode(0o777).create(&dir).unwrap();
        let made = ServerIdentity::load_or_create_in(&locked, &dir, me()).unwrap();
        assert!(!dir.join(IDENTITY_FILE).exists(), "not written to the swap");
        let kept = ServerIdentity::load(&checked, me()).unwrap();
        assert_eq!(kept.pin(), made.pin(), "written where checked");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&checked).unwrap();
    }

    #[test]
    fn the_certificate_never_expires_rfc5280_4_1_2_5() {
        let dir = data_dir("validity", 0o700);
        let made = ServerIdentity::load_or_create(&dir, me()).unwrap();
        let der = made.certificate.as_ref();
        // RFC 5280 §4.1.2.5.1/.2: UTCTime before 2050, GeneralizedTime from it on.
        let utc_2000 = b"\x17\x0d000101000000Z";
        let general_9999 = b"\x18\x0f99991231235959Z";
        assert!(der.windows(utc_2000.len()).any(|w| w == utc_2000));
        assert!(der.windows(general_9999.len()).any(|w| w == general_9999));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An identity as lotse made it before its certificate named
    /// [`SERVER_NAME`]: the Common Name alone, rcgen's serial.
    fn legacy_pem() -> String {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, CERTIFICATE_NAME);
        params.distinguished_name = name;
        let certificate = params.self_signed(&key).unwrap();
        format!("{}{}", key.serialize_pem(), certificate.pem())
    }

    /// The DER of the public key in the identity `pem`'s key.
    fn public_key(pem: &str) -> Vec<u8> {
        KeyPair::from_pem(pem).unwrap().subject_public_key_info()
    }

    #[test]
    fn a_new_certificate_names_lotse_as_its_dns_name_rfc5280_4_2_1_6() {
        let dir = data_dir("san", 0o700);
        let made = ServerIdentity::load_or_create(&dir, me()).unwrap();
        assert!(made.names_server());
        // The name is in the subject alternative names as a dNSName ([2]
        // IA5String, RFC 5280 §4.2.1.6), not only in the Common Name.
        let san = b"\x82\x05lotse";
        let der = made.certificate.as_ref();
        assert!(der.windows(san.len()).any(|w| w == san));
        assert_eq!(SERVER_NAME, "lotse");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_serial_is_the_hash_of_the_name_and_key_positive_and_20_bytes_rfc5280_4_1_2_2() {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut named = b"lotse".to_vec();
        named.extend_from_slice(&key.subject_public_key_info());
        let mut expected = Fingerprint::of(&named).as_bytes()[..20].to_vec();
        expected[0] &= 0x7f;
        let serial = serial(&key);
        assert_eq!(serial.as_ref(), expected.as_slice());
        assert!(serial.as_ref()[0] < 0x80, "positive");
        // In the certificate as a DER INTEGER of 20 bytes, or 21 with a
        // zero byte before a top bit that is set.
        let pem = certify(&key).unwrap();
        let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        let mut encoded = vec![0x02, 20];
        encoded.extend_from_slice(&expected);
        assert!(der.windows(encoded.len()).any(|w| w == encoded.as_slice()));
    }

    #[test]
    fn an_identity_without_the_name_keeps_working_untouched() {
        let dir = data_dir("legacy", 0o700);
        let legacy = legacy_pem();
        write_new(&open_directory(&dir).unwrap(), &dir, &legacy).unwrap();
        let loaded = ServerIdentity::load_or_create(&dir, me()).unwrap();
        assert!(!loaded.names_server());
        assert_eq!(
            std::fs::read_to_string(dir.join(IDENTITY_FILE)).unwrap(),
            legacy,
            "a start never replaces it"
        );
        assert_eq!(
            ServerIdentity::load(&dir, me()).unwrap().pin(),
            loaded.pin()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reissue_names_lotse_from_the_same_key_and_changes_the_pin_and_serial() {
        let (logs, _guard) = crate::pairing::test_support::capture();
        let dir = data_dir("reissue", 0o700);
        let err = ServerIdentity::reissue(&dir, me()).unwrap_err();
        assert!(matches!(err, IdentityError::Missing(_)), "{err}");
        let err = ServerIdentity::reissue(&dir, someone_else()).unwrap_err();
        assert!(matches!(err, IdentityError::DirectoryOwner { .. }), "{err}");
        let legacy = legacy_pem();
        write_new(&open_directory(&dir).unwrap(), &dir, &legacy).unwrap();
        let old = ServerIdentity::load(&dir, me()).unwrap();
        let new = ServerIdentity::reissue(&dir, me()).unwrap();
        assert!(new.names_server());
        assert_ne!(new.pin(), old.pin());
        let path = dir.join(IDENTITY_FILE);
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(public_key(&written), public_key(&legacy), "the same key");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(ServerIdentity::load(&dir, me()).unwrap().pin(), new.pin());
        // rcgen's serial of the old one is the hash of the key alone.
        let key = KeyPair::from_pem(&legacy).unwrap();
        let key_hash = Fingerprint::of(key.der_bytes());
        let rcgen_serial = &key_hash.as_bytes()[1..20];
        let contains = |der: &[u8]| der.windows(19).any(|w| w == rcgen_serial);
        assert!(contains(old.certificate.as_ref()));
        assert!(!contains(new.certificate.as_ref()), "a serial of its own");
        let text = logs.text();
        assert!(text.contains("control identity reissued"), "{text}");
        assert!(text.contains(&format!("old_pin={}", old.pin())), "{text}");
        assert!(
            text.contains(&format!("server_pin={}", new.pin())),
            "{text}"
        );
        assert!(!dir.join(PARTIAL_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_certificate_pem_is_the_certificate_alone_rfc7468_5() {
        let dir = data_dir("certificate-pem", 0o700);
        let made = ServerIdentity::load_or_create(&dir, me()).unwrap();
        let pem = made.certificate_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"), "{pem}");
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"), "{pem}");
        assert!(!pem.contains('\r'), "LF line endings");
        assert!(!pem.contains("PRIVATE"), "never the key");
        let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        assert_eq!(der, made.certificate);
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
    fn a_data_directory_others_can_search_is_refused() {
        // Without write, the group or others could still list the
        // directory or reach a file in it by name.
        for mode in [0o711, 0o701, 0o750, 0o704] {
            let dir = data_dir(&format!("search-{mode:o}"), mode);
            let err = ServerIdentity::load_or_create(&dir, me()).unwrap_err();
            assert!(
                matches!(err, IdentityError::DirectoryMode { mode: m, .. } if m == mode),
                "{mode:04o}: {err}"
            );
            assert!(
                err.to_string().ends_with(&format!(
                    "is mode {mode:04o}; the group and others must have no access"
                )),
                "{err}"
            );
            assert!(!dir.join(IDENTITY_FILE).exists(), "{mode:04o}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn a_directory_others_can_write_or_someone_else_owns_is_refused() {
        let missing = std::env::temp_dir().join("lotse-identity-missing-dir");
        let err = ServerIdentity::load_or_create(&missing, me()).unwrap_err();
        assert!(matches!(err, IdentityError::Directory { .. }), "{err}");
        let open = data_dir("open", 0o770);
        let err = ServerIdentity::load_or_create(&open, me()).unwrap_err();
        assert!(
            matches!(err, IdentityError::DirectoryMode { mode: 0o770, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("0770"), "{err}");
        // Reading checks the directory as a start does, even with an
        // identity in it.
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        ServerIdentity::load_or_create(&open, me()).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = ServerIdentity::load(&open, me()).unwrap_err();
        assert!(
            matches!(err, IdentityError::DirectoryMode { mode: 0o770, .. }),
            "{err}"
        );
        let private = data_dir("dir-owner", 0o700);
        let err = ServerIdentity::load_or_create(&private, someone_else()).unwrap_err();
        assert!(matches!(err, IdentityError::DirectoryOwner { .. }), "{err}");
        let err = ServerIdentity::load(&private, someone_else()).unwrap_err();
        assert!(matches!(err, IdentityError::DirectoryOwner { .. }), "{err}");
        let file = private.join("file");
        std::fs::write(&file, b"").unwrap();
        let err = ServerIdentity::load_or_create(&file, me()).unwrap_err();
        assert!(matches!(err, IdentityError::NotADirectory(_)), "{err}");
        std::fs::remove_dir_all(&open).unwrap();
        std::fs::remove_dir_all(&private).unwrap();
    }

    #[test]
    fn a_start_as_root_takes_the_directory_and_identity_of_the_uid_it_drops_to() {
        let dir = data_dir("drop-owner", 0o700);
        let root = Owners {
            starting: 0,
            drop_to: uid(),
        };
        let made = ServerIdentity::load_or_create(&dir, root).unwrap();
        assert_eq!(ServerIdentity::load(&dir, root).unwrap().pin(), made.pin());
        // Any other start drops to nobody: its drop target owns nothing,
        // neither the directory nor, past it, the file.
        let other = Owners {
            starting: uid().wrapping_add(1),
            drop_to: uid(),
        };
        let err = ServerIdentity::load_or_create(&dir, other).unwrap_err();
        assert!(
            matches!(err, IdentityError::DirectoryOwner { owner, expected, .. } if owner == uid() && expected == other),
            "{err}"
        );
        let handle = open_directory(&dir).unwrap();
        let err = ServerIdentity::load_in(&handle, &dir, other).unwrap_err();
        assert!(
            matches!(err, IdentityError::FileOwner { owner, expected, .. } if owner == uid() && expected == other),
            "{err}"
        );
        assert!(
            err.to_string()
                .ends_with(&format!("is owned by uid {}, not {other}", uid())),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_identity_others_can_read_or_someone_else_owns_is_refused() {
        let missing = std::env::temp_dir().join("lotse-identity-load-missing-dir");
        let err = ServerIdentity::load(&missing, me()).unwrap_err();
        assert!(matches!(err, IdentityError::Directory { .. }), "{err}");
        let dir = data_dir("file", 0o700);
        let err = ServerIdentity::load(&dir, me()).unwrap_err();
        assert!(matches!(err, IdentityError::Missing(_)), "{err}");
        assert!(err.to_string().contains("first start"), "{err}");
        ServerIdentity::load_or_create(&dir, me()).unwrap();
        let path = dir.join(IDENTITY_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = ServerIdentity::load_or_create(&dir, me()).unwrap_err();
        assert!(
            matches!(err, IdentityError::FileMode { mode: 0o640, .. }),
            "{err}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        // The directory's owner is checked first; past it, the file's.
        let handle = open_directory(&dir).unwrap();
        let err = ServerIdentity::load_in(&handle, &dir, someone_else()).unwrap_err();
        assert!(matches!(err, IdentityError::FileOwner { .. }), "{err}");
        assert!(ServerIdentity::load(&dir, me()).is_ok(), "0400 is stricter");
        std::fs::remove_file(&path).unwrap();
        std::fs::DirBuilder::new().create(&path).unwrap();
        let err = ServerIdentity::load(&dir, me()).unwrap_err();
        assert!(matches!(err, IdentityError::NotAFile(_)), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn posix_open_a_fifo_as_the_identity_is_refused_not_waited_on() {
        let dir = data_dir("fifo", 0o700);
        let handle = open_directory(&dir).unwrap();
        rustix::fs::mkfifoat(&handle, IDENTITY_FILE, Mode::RUSR | Mode::WUSR).unwrap();
        // No writer ever opens it: without `O_NONBLOCK` both would hang.
        let err = ServerIdentity::load(&dir, me()).unwrap_err();
        assert!(matches!(err, IdentityError::NotAFile(_)), "{err}");
        let err = ServerIdentity::load_or_create(&dir, me()).unwrap_err();
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
            write_new(&open_directory(&dir).unwrap(), &dir, content).unwrap();
            let err = ServerIdentity::load(&dir, me()).unwrap_err();
            assert!(
                matches!(&err, IdentityError::Pem { what: w, .. } if w.starts_with(what)),
                "{err}"
            );
        }
        // A link in its place is refused, not followed, even to a valid
        // identity, and not taken for a missing file.
        let elsewhere = data_dir("pem-link-target", 0o700);
        ServerIdentity::load_or_create(&elsewhere, me()).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(elsewhere.join(IDENTITY_FILE), &path).unwrap();
        let err = ServerIdentity::load(&dir, me()).unwrap_err();
        assert!(matches!(err, IdentityError::Io { .. }), "{err}");
        std::fs::remove_dir_all(&elsewhere).unwrap();
        // A directory as the partial file cannot be replaced or opened.
        std::fs::remove_file(&path).unwrap();
        std::fs::DirBuilder::new()
            .create(dir.join(PARTIAL_FILE))
            .unwrap();
        let err = write_new(&open_directory(&dir).unwrap(), &dir, &made).unwrap_err();
        assert!(matches!(err, IdentityError::Io { .. }), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
