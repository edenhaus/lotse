//! TLS to an `rtsps://` camera: the client configuration, the certificate
//! check the source options choose, and how a failed handshake becomes a
//! [`SourceError`].
//!
//! Implements RFC 7826 §19.2 (RTSP over TLS, which follows RFC 2818 for
//! the server's identity) over RFC 8446 (TLS 1.3) and RFC 5246 (TLS 1.2,
//! which many cameras are limited to), with RFC 6066 §3 server name
//! indication (sent for a host name, never for an address literal). rustls
//! with the `ring` provider does the protocol; this module only decides
//! whom to trust:
//!
//! - **Roots** (the default): the chain must end in an embedded
//!   `webpki-roots` anchor and the certificate must name the URL's host
//!   (RFC 2818 §3.1, RFC 6125 through `webpki`).
//! - **Pin** (`tls_fingerprint`): the leaf certificate's SHA-256 must equal
//!   the pin. Chain, validity period and host name are not checked: a
//!   self-signed camera certificate rarely names the host it is reached
//!   by, and the pin names exactly one certificate.
//! - **Insecure** (`insecure_tls`): any certificate.
//!
//! In every mode the handshake signature is verified with the presented
//! certificate's key, so a peer that copied a certificate without its key
//! fails.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

pub use lotse_core::fingerprint::{Fingerprint, FingerprintError};
use lotse_core::source::SourceError;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, OtherError, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Whom an `rtsps` connection trusts, from the source options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trust {
    /// The embedded roots and the host name.
    Roots,
    /// Exactly the certificate with this fingerprint.
    Pin(Fingerprint),
    /// Any certificate (`insecure_tls`).
    Insecure,
}

/// Where an `rtsps` connection goes and whom it trusts; built when the
/// source is validated, so a host that cannot be a TLS server name fails
/// at `stream/put`.
#[derive(Debug, Clone)]
pub(crate) struct TlsTarget {
    /// The URL's host: the SNI and the name the certificate must carry
    /// with [`Trust::Roots`].
    pub(crate) server_name: ServerName<'static>,
    /// The certificate check.
    pub(crate) trust: Trust,
}

impl TlsTarget {
    /// The target for `host` as `SourceUrl::host` spells it (an IPv6
    /// literal in brackets).
    pub(crate) fn new(host: &str, trust: Trust) -> Result<Self, String> {
        let bare = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        let server_name = ServerName::try_from(bare.to_owned())
            .map_err(|err| format!("{host:?} cannot be a TLS server name: {err}"))?;
        Ok(Self { server_name, trust })
    }
}

/// The embedded root certificates.
fn embedded_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Why the certificate check refused the camera, as the message of a
/// `source_auth_failed` error.
#[derive(Debug, thiserror::Error)]
enum CertificateRejected {
    /// The pin does not match.
    #[error(
        "the camera's certificate does not match tls_fingerprint {expected}; it presented {presented}"
    )]
    PinMismatch {
        /// The pin.
        expected: Fingerprint,
        /// The leaf certificate's fingerprint.
        presented: Fingerprint,
    },
    /// The chain or the name failed against the embedded roots.
    #[error(
        "the camera's certificate is not trusted ({reason}); its SHA-256 fingerprint is {presented}"
    )]
    Untrusted {
        /// What `webpki` found wrong.
        reason: String,
        /// The leaf certificate's fingerprint, for a pin if the camera is
        /// meant to be trusted.
        presented: Fingerprint,
    },
}

impl From<CertificateRejected> for rustls::Error {
    fn from(rejected: CertificateRejected) -> Self {
        Self::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(rejected))))
    }
}

/// The certificate check of one connection.
#[derive(Debug)]
struct CameraVerifier {
    /// The mode, with the root verifier for [`Trust::Roots`].
    check: Check,
    /// The provider's signature algorithms, for the handshake signature.
    algorithms: WebPkiSupportedAlgorithms,
}

/// [`Trust`] with what each mode needs at handshake time.
#[derive(Debug)]
enum Check {
    /// Chain and name through `webpki`.
    Roots(Arc<WebPkiServerVerifier>),
    /// The pin.
    Pin(Fingerprint),
    /// Nothing.
    Insecure,
}

impl ServerCertVerifier for CameraVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = Fingerprint::of(end_entity);
        match &self.check {
            Check::Pin(expected) if *expected != presented => {
                Err(CertificateRejected::PinMismatch {
                    expected: *expected,
                    presented,
                }
                .into())
            }
            // SPEC-DEVIATION(RFC 2818 §3.1): with a pin or `insecure_tls`
            // the host name is not checked against the certificate (nor the
            // chain or validity period); the pin names one certificate, and
            // self-signed cameras rarely name the address they are reached
            // by. gate: rtsps_plays_with_a_pinned_certificate_rfc7826_19_2
            Check::Pin(_) | Check::Insecure => Ok(ServerCertVerified::assertion()),
            Check::Roots(roots) => roots
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .map_err(|err| {
                    CertificateRejected::Untrusted {
                        reason: err.to_string(),
                        presented,
                    }
                    .into()
                }),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A client configuration rustls refused, as the attempt's protocol
/// error. One function for every refusal: the protocol versions the
/// `ring` provider always supports cannot be refused, the verifier's
/// roots can.
fn tls_failed(err: impl fmt::Display) -> SourceError {
    SourceError::Protocol(format!("tls: {err}"))
}

/// The client configuration: the `ring` provider, TLS 1.3 and 1.2, the
/// check `trust` asks for (against `roots` in [`Trust::Roots`]), no client
/// certificate.
fn client_config(trust: Trust, roots: RootCertStore) -> Result<ClientConfig, SourceError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let check = match trust {
        Trust::Roots => Check::Roots(
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(tls_failed)?,
        ),
        Trust::Pin(pin) => Check::Pin(pin),
        Trust::Insecure => Check::Insecure,
    };
    let verifier = CameraVerifier {
        check,
        algorithms: provider.signature_verification_algorithms,
    };
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(tls_failed)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// How a failed handshake reads as a [`SourceError`]: a refused
/// certificate is `auth_failed` (the camera did not authenticate itself),
/// any other TLS failure `protocol`, and an I/O failure underneath
/// `unreachable`.
pub(crate) fn classify(err: &io::Error) -> SourceError {
    match err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(CertificateError::Other(other))) => {
            SourceError::AuthFailed(format!("tls: {}", other.0))
        }
        Some(tls) => SourceError::Protocol(format!("tls: handshake failed: {tls}")),
        None => SourceError::Unreachable(format!("tls: handshake failed: {err}")),
    }
}

/// Connects to `addr` and completes the handshake for `target`, verifying
/// against the embedded roots when the target trusts them.
pub(crate) async fn connect(
    addr: SocketAddr,
    target: &TlsTarget,
) -> Result<TlsStream<TcpStream>, SourceError> {
    connect_with_roots(addr, target, embedded_roots()).await
}

/// [`connect`] against `roots`, so tests can trust their own anchor.
async fn connect_with_roots(
    addr: SocketAddr,
    target: &TlsTarget,
    roots: RootCertStore,
) -> Result<TlsStream<TcpStream>, SourceError> {
    let config = client_config(target.trust, roots)?;
    let tcp = crate::relay::tcp(addr).await?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(target.server_name.clone(), tcp)
        .await
        .map_err(|err| classify(&err))?;
    let (_, session) = stream.get_ref();
    let presented = session
        .peer_certificates()
        .and_then(<[CertificateDer<'_>]>::first)
        .map(|leaf| Fingerprint::of(leaf).to_string());
    let version = session
        .protocol_version()
        .and_then(|version| version.as_str());
    if target.trust == Trust::Insecure {
        tracing::warn!(
            fingerprint = presented.as_deref(),
            "rtsps: insecure_tls: the camera's certificate is not verified; pin it with tls_fingerprint"
        );
    }
    tracing::info!(
        trust = ?target.trust,
        version,
        fingerprint = presented.as_deref(),
        "rtsps: TLS established"
    );
    Ok(stream)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn a_verifier_without_roots_is_refused_as_protocol() {
        let err = client_config(Trust::Roots, RootCertStore::empty()).unwrap_err();
        assert!(
            matches!(&err, SourceError::Protocol(m) if m.starts_with("tls: ")),
            "{err:?}"
        );
    }

    #[test]
    fn targets_take_host_names_and_bracketed_addresses_rfc6066_3() {
        let named = TlsTarget::new("camera.local", Trust::Roots).unwrap();
        assert_eq!(named.server_name.to_str(), "camera.local");
        let v6 = TlsTarget::new("[fe80::1]", Trust::Insecure).unwrap();
        assert!(matches!(v6.server_name, ServerName::IpAddress(_)));
        let v4 = TlsTarget::new("192.168.1.10", Trust::Insecure).unwrap();
        assert!(matches!(v4.server_name, ServerName::IpAddress(_)));
        let err = TlsTarget::new("a!b", Trust::Roots).unwrap_err();
        assert!(err.contains("cannot be a TLS server name"), "{err}");
    }

    #[test]
    fn handshake_failures_are_classified() {
        let pin = CertificateRejected::PinMismatch {
            expected: Fingerprint::of(b"a"),
            presented: Fingerprint::of(b"b"),
        };
        let wrapped = io::Error::new(io::ErrorKind::InvalidData, rustls::Error::from(pin));
        let refused = classify(&wrapped);
        assert!(
            matches!(&refused, SourceError::AuthFailed(m) if m.starts_with("tls: the camera's certificate does not match")),
            "{refused:?}"
        );
        let alert = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure),
        );
        let alerted = classify(&alert);
        assert!(
            matches!(&alerted, SourceError::Protocol(m) if m.starts_with("tls: handshake failed")),
            "{alerted:?}"
        );
        let reset = io::Error::from(io::ErrorKind::ConnectionReset);
        assert!(matches!(classify(&reset), SourceError::Unreachable(_)));
        let other = io::Error::other("not tls");
        assert!(matches!(classify(&other), SourceError::Unreachable(_)));
    }

    /// The handshake against a TLS fake camera whose own certificate is the
    /// one trust anchor.
    async fn with_own_anchor(names: &[&str], server_name: &str) -> Result<(), SourceError> {
        use lotse_core::clock::SystemClock;
        use lotse_testing::fake_camera::CameraTls;
        use lotse_testing::{CameraConfig, FakeCamera};

        let tls = CameraTls::self_signed(names).unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(tls.certificate_der().to_vec()))
            .unwrap();
        let cam = FakeCamera::start(
            CameraConfig {
                tls: Some(tls),
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let target = TlsTarget::new(server_name, Trust::Roots).unwrap();
        let result = connect_with_roots(cam.addr(), &target, roots)
            .await
            .map(drop);
        cam.stop().await;
        result
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roots_check_the_chain_and_the_host_name_rfc2818_3_1() {
        with_own_anchor(&["camera.test"], "camera.test")
            .await
            .unwrap();
        with_own_anchor(&["127.0.0.1"], "127.0.0.1").await.unwrap();
        let err = with_own_anchor(&["camera.test"], "other.test")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, SourceError::AuthFailed(m) if m.contains("not trusted") && m.contains("not valid for name")),
            "{err:?}"
        );
    }

    #[test]
    fn the_embedded_roots_are_mozillas() {
        assert!(embedded_roots().len() > 100);
    }
}
