//! TLS to a source's server (an `rtsps://` camera, an `https://` stream):
//! the client configuration, the certificate check the source options
//! choose, and how a failed handshake becomes a [`SourceError`].
//!
//! Runs in a worker, inside a source crate's connection attempt. Depends on
//! `lotse-core` only (for [`SourceError`]), never on a source crate or a
//! protocol engine: a source connects its own TCP stream, hands it to
//! [`connect`] with the ALPN protocols of its scheme, and speaks its
//! protocol over the stream it gets back.
//!
//! Standards: RFC 8446 (TLS 1.3) and RFC 5246 (TLS 1.2, which many cameras
//! are limited to) through rustls, RFC 6066 §3 server name indication (sent
//! for a host name, never for an address literal), RFC 7301 (ALPN, offered
//! when the caller names protocols), RFC 5280 path validation and the
//! RFC 2818 §3.1 / RFC 6125 host name check through `webpki`. RFC 7826
//! §19.2 (`rtsps`) and RFC 9110 §4.3.4 (`https`) both take the server's
//! identity from RFC 2818. rustls with the `ring` provider does the
//! protocol; this crate only decides whom to trust:
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
use std::sync::Arc;

pub use lotse_core::fingerprint::{Fingerprint, FingerprintError};
use lotse_core::source::SourceError;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, OtherError, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
pub use tokio_rustls::client::TlsStream;

/// Whom a TLS connection trusts, from the source options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// The embedded roots and the host name.
    Roots,
    /// Exactly the certificate with this fingerprint.
    Pin(Fingerprint),
    /// Any certificate (`insecure_tls`).
    Insecure,
}

/// Where a TLS connection goes and whom it trusts; built when the source
/// is validated, so a host that cannot be a TLS server name fails at
/// `stream/put`.
#[derive(Debug, Clone)]
pub struct TlsTarget {
    /// The URL's host: the SNI and the name the certificate must carry
    /// with [`Trust::Roots`].
    pub server_name: ServerName<'static>,
    /// The certificate check.
    pub trust: Trust,
}

impl TlsTarget {
    /// The target for `host` as `SourceUrl::host` spells it (an IPv6
    /// literal in brackets).
    pub fn new(host: &str, trust: Trust) -> Result<Self, String> {
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
            // by. gate: a_pin_accepts_exactly_its_certificate_whatever_it_names,
            // rtsps_plays_with_a_pinned_certificate_rfc7826_19_2 (lotse-rtsp)
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
/// check `trust` asks for (against `roots` in [`Trust::Roots`]), the
/// `alpn` protocols offered in preference order (RFC 7301 §3.1; none
/// leaves the extension out), no client certificate.
fn client_config(
    trust: Trust,
    roots: RootCertStore,
    alpn: &[&[u8]],
) -> Result<ClientConfig, SourceError> {
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
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(tls_failed)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(config)
}

/// How a failed handshake reads as a [`SourceError`]: a refused
/// certificate is `auth_failed` (the camera did not authenticate itself),
/// any other TLS failure `protocol`, and an I/O failure underneath
/// `unreachable`.
pub fn classify(err: &io::Error) -> SourceError {
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

/// Completes the handshake for `target` over `io`, a stream the caller
/// connected, offering the `alpn` protocols (none for `rtsps`, which has
/// never offered any), and verifying against the embedded roots
/// when the target trusts them.
pub async fn connect<Io>(
    io: Io,
    target: &TlsTarget,
    alpn: &[&[u8]],
) -> Result<TlsStream<Io>, SourceError>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    connect_with_roots(io, target, alpn, embedded_roots()).await
}

/// [`connect`] against `roots`, so tests can trust their own anchor.
async fn connect_with_roots<Io>(
    io: Io,
    target: &TlsTarget,
    alpn: &[&[u8]],
    roots: RootCertStore,
) -> Result<TlsStream<Io>, SourceError>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    let config = client_config(target.trust, roots, alpn)?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(target.server_name.clone(), io)
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
            "tls: insecure_tls: the camera's certificate is not verified; pin it with tls_fingerprint"
        );
    }
    tracing::info!(
        trust = ?target.trust,
        version,
        alpn = session.alpn_protocol().map(String::from_utf8_lossy).as_deref(),
        fingerprint = presented.as_deref(),
        "tls: established"
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

    use lotse_core::clock::SystemClock;
    use lotse_testing::fake_camera::CameraTls;
    use lotse_testing::{CameraConfig, FakeCamera};
    use tokio::net::TcpStream;

    use super::*;

    #[test]
    fn a_verifier_without_roots_is_refused_as_protocol() {
        let err = client_config(Trust::Roots, RootCertStore::empty(), &[]).unwrap_err();
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

    /// A TLS fake camera serving `tls`.
    async fn camera(tls: CameraTls) -> FakeCamera {
        FakeCamera::start(
            CameraConfig {
                tls: Some(tls),
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap()
    }

    /// The handshake with `cam` for `server_name` and `trust`, against
    /// `roots`; the negotiated version.
    async fn handshake(
        cam: &FakeCamera,
        server_name: &str,
        trust: Trust,
        roots: RootCertStore,
    ) -> Result<Option<rustls::ProtocolVersion>, SourceError> {
        let tcp = TcpStream::connect(cam.addr()).await.unwrap();
        let target = TlsTarget::new(server_name, trust).unwrap();
        let stream = connect_with_roots(tcp, &target, &[], roots).await?;
        Ok(stream.get_ref().1.protocol_version())
    }

    /// The handshake against a TLS fake camera whose own certificate is the
    /// one trust anchor.
    async fn with_own_anchor(names: &[&str], server_name: &str) -> Result<(), SourceError> {
        let tls = CameraTls::self_signed(names).unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(tls.certificate_der().to_vec()))
            .unwrap();
        let cam = camera(tls).await;
        let result = handshake(&cam, server_name, Trust::Roots, roots)
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pin_accepts_exactly_its_certificate_whatever_it_names() {
        let tls = CameraTls::self_signed(&["elsewhere.test"]).unwrap();
        let pin = Fingerprint::of(tls.certificate_der());
        let cam = camera(tls).await;
        let version = handshake(&cam, "camera.test", Trust::Pin(pin), embedded_roots())
            .await
            .unwrap();
        assert_eq!(version, Some(rustls::ProtocolVersion::TLSv1_3));
        let wrong = Fingerprint::of(b"another certificate");
        let err = handshake(&cam, "camera.test", Trust::Pin(wrong), embedded_roots())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, SourceError::AuthFailed(m) if m.contains(&format!("does not match tls_fingerprint {wrong}; it presented {pin}"))),
            "{err:?}"
        );
        cam.stop().await;
    }

    /// A log writer that keeps every line.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

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
        /// Every line written so far, flushed first.
        fn text(&self) -> String {
            io::Write::flush(&mut self.clone()).unwrap();
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn insecure_accepts_any_certificate_over_tls_1_2_and_warns_rfc5246() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .finish();
        let _logs = tracing::subscriber::set_default(subscriber);
        let tls = CameraTls::tls12_only(&["elsewhere.test"]).unwrap();
        let presented = Fingerprint::of(tls.certificate_der()).to_string();
        let cam = camera(tls).await;
        let tcp = TcpStream::connect(cam.addr()).await.unwrap();
        let target = TlsTarget::new("camera.test", Trust::Insecure).unwrap();
        let stream = connect(tcp, &target, &[b"http/1.1"]).await.unwrap();
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
        drop(stream);
        cam.stop().await;
        let logs = captured.text();
        let warnings: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("insecure_tls"))
            .collect();
        assert_eq!(warnings.len(), 1, "{logs}");
        assert!(
            warnings[0].contains("WARN") && warnings[0].contains(&presented),
            "{logs}"
        );
        assert!(
            logs.lines()
                .any(|l| l.contains("tls: established") && l.contains("Insecure")),
            "{logs}"
        );
    }

    #[test]
    fn the_alpn_protocols_are_offered_in_order_rfc7301_3_1() {
        let offered = client_config(
            Trust::Insecure,
            RootCertStore::empty(),
            &[b"h2", b"http/1.1"],
        )
        .unwrap();
        assert_eq!(
            offered.alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let none = client_config(Trust::Insecure, RootCertStore::empty(), &[]).unwrap();
        assert!(none.alpn_protocols.is_empty());
    }

    #[test]
    fn the_embedded_roots_are_mozillas() {
        assert!(embedded_roots().len() > 100);
    }
}
