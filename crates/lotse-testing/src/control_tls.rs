//! A client of the control API's mutual-TLS listener, as a remote client
//! connects: it pins the daemon's certificate by its SHA-256, trusts
//! nothing else, verifies the server's handshake signature, and presents a
//! certificate of its own. Also the misbehaving clients the listener must
//! refuse: none, a certificate with someone else's key, a signature in a
//! scheme the server did not offer, TLS 1.2 only.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use lotse_core::fingerprint::Fingerprint;
use rustls::client::ResolvesClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureAlgorithm, SignatureScheme,
    SupportedProtocolVersion,
};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// A client's key and self-signed certificate, as a client generates its
/// own before it is enrolled.
#[derive(Debug)]
pub struct ClientIdentity {
    /// The DER certificate.
    pub certificate: CertificateDer<'static>,
    /// The PKCS #8 key.
    key: PrivateKeyDer<'static>,
    /// The certificate's SHA-256, the pin the daemon allows.
    pub pin: Fingerprint,
}

impl ClientIdentity {
    /// A P-256 key and its certificate.
    pub fn generate() -> io::Result<Self> {
        Self::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
    }

    /// A key for `alg` and its certificate.
    pub fn generate_for(alg: &'static rcgen::SignatureAlgorithm) -> io::Result<Self> {
        let key = rcgen::KeyPair::generate_for(alg).map_err(io::Error::other)?;
        let certificate = rcgen::CertificateParams::new(vec!["lotse-client".into()])
            .and_then(|params| params.self_signed(&key))
            .map_err(io::Error::other)?;
        let certificate = certificate.der().clone();
        Ok(Self {
            pin: Fingerprint::of(&certificate),
            certificate,
            key: PrivateKeyDer::try_from(key.serialize_der()).map_err(io::Error::other)?,
        })
    }

    /// The signing key of this identity's key.
    fn signing_key(&self) -> io::Result<Arc<dyn SigningKey>> {
        provider()
            .key_provider
            .load_private_key(self.key.clone_key())
            .map_err(io::Error::other)
    }
}

/// The certificate a client presents.
#[derive(Debug, Clone, Copy)]
pub enum ClientCert<'a> {
    /// None.
    None,
    /// Its own, with its own key.
    Own(&'a ClientIdentity),
    /// `presented`'s certificate, signed with `signing`'s key: someone
    /// who copied a public certificate.
    WrongKey {
        /// The certificate shown.
        presented: &'a ClientIdentity,
        /// The key that signs.
        signing: &'a ClientIdentity,
    },
    /// Its own (a P-384 one), signing with ECDSA P-384 whatever the server
    /// offered.
    UnofferedScheme(&'a ClientIdentity),
}

/// The ring provider, as the daemon uses.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The protocol versions the listener speaks: TLS 1.3 alone.
pub const TLS13: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// A client configuration that trusts exactly the server certificate with
/// `server_pin`, offers `versions`, and presents `cert`. Session resumption
/// stays on, as rustls has it by default, so a test can see the server
/// refuse it.
pub fn client_config(
    server_pin: Fingerprint,
    cert: ClientCert<'_>,
    versions: &[&'static SupportedProtocolVersion],
) -> io::Result<Arc<ClientConfig>> {
    let provider = provider();
    let verifier = Arc::new(PinnedServer {
        pin: server_pin,
        algorithms: provider.signature_verification_algorithms,
    });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let config = match cert {
        ClientCert::None => builder.with_no_client_auth(),
        ClientCert::Own(identity) => {
            builder.with_client_cert_resolver(Fixed::new(identity, identity.signing_key()?))
        }
        ClientCert::WrongKey { presented, signing } => {
            builder.with_client_cert_resolver(Fixed::new(presented, signing.signing_key()?))
        }
        ClientCert::UnofferedScheme(identity) => builder.with_client_cert_resolver(Fixed::new(
            identity,
            Arc::new(IgnoreOffer(identity.signing_key()?)),
        )),
    };
    Ok(Arc::new(config))
}

/// Connects to `addr` and runs the handshake.
pub async fn connect(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
) -> io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    handshake(tcp, config).await
}

/// Connects to `addr` from the local address `from` (on Linux any
/// 127.0.0.0/8 address is the loopback) and runs the handshake.
pub async fn connect_from(
    from: IpAddr,
    addr: SocketAddr,
    config: Arc<ClientConfig>,
) -> io::Result<TlsStream<TcpStream>> {
    handshake(tcp_from(from, addr).await?, config).await
}

/// A plain TCP connection to `addr` from the local address `from`.
pub async fn tcp_from(from: IpAddr, addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = match from {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(SocketAddr::new(from, 0))?;
    socket.connect(addr).await
}

/// The client half of the handshake on `tcp`.
async fn handshake(tcp: TcpStream, config: Arc<ClientConfig>) -> io::Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from("lotse").map_err(io::Error::other)?;
    TlsConnector::from(config).connect(name, tcp).await
}

/// Trusts exactly one server certificate, by its SHA-256, and verifies the
/// server's handshake signature with its key.
#[derive(Debug)]
struct PinnedServer {
    /// The pin.
    pin: Fingerprint,
    /// The provider's signature algorithms.
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if Fingerprint::of(end_entity) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("not the pinned server".into()))
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

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Presents one certificate with one key, whatever the server asks.
#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl Fixed {
    /// `identity`'s certificate with `key`, which need not be its own.
    fn new(identity: &ClientIdentity, key: Arc<dyn SigningKey>) -> Arc<Self> {
        Arc::new(Self(Arc::new(CertifiedKey::new(
            vec![identity.certificate.clone()],
            key,
        ))))
    }
}

impl ResolvesClientCert for Fixed {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Signs with ECDSA P-384 whatever the server offered.
struct IgnoreOffer(Arc<dyn SigningKey>);

impl fmt::Debug for IgnoreOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IgnoreOffer")
    }
}

impl SigningKey for IgnoreOffer {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

/// A [`DigitallySignedStruct`], which only rustls can make: a server's
/// `CertificateVerify`, captured from an in-memory TLS 1.3 handshake.
pub fn server_signature() -> io::Result<DigitallySignedStruct> {
    let server = ClientIdentity::generate()?;
    let server_config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![server.certificate.clone()], server.key.clone_key())
        .map_err(io::Error::other)?;
    let capture = Arc::new(Capture::default());
    let verifier: Arc<dyn ServerCertVerifier> = Arc::<Capture>::clone(&capture);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let name = ServerName::try_from("lotse").map_err(io::Error::other)?;
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), name).map_err(io::Error::other)?;
    let mut server =
        rustls::ServerConnection::new(Arc::new(server_config)).map_err(io::Error::other)?;
    while client.is_handshaking() || server.is_handshaking() {
        let mut buf = Vec::new();
        client.write_tls(&mut buf)?;
        server.read_tls(&mut buf.as_slice())?;
        server.process_new_packets().map_err(io::Error::other)?;
        let mut buf = Vec::new();
        server.write_tls(&mut buf)?;
        client.read_tls(&mut buf.as_slice())?;
        client.process_new_packets().map_err(io::Error::other)?;
    }
    let captured = capture
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    captured.ok_or_else(|| io::Error::other("no CertificateVerify seen"))
}

/// Accepts any server and keeps the signature it saw.
#[derive(Debug, Default)]
struct Capture(Mutex<Option<DigitallySignedStruct>>);

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.3 only".into()))
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(dss.clone());
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}
