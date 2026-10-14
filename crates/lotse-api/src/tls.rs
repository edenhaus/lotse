//! The control API's TCP listener with mutual TLS 1.3: the opt-in way to
//! reach a daemon that runs in its own container or on another host. The
//! Unix socket stays, unchanged, next to it.
//!
//! Both ends authenticate on every connection, before a byte of HTTP is
//! read. The server presents its [`ServerIdentity`]; the client must present
//! a certificate whose SHA-256 is on the allowlist ([`TlsConfig::clients`])
//! and prove it holds the key with the handshake signature, which is always
//! verified (RFC 8446 §4.4.3): pins and certificates are public, so the
//! signature is what keeps a copied certificate out. Only TLS 1.3 is
//! offered, with the client signature schemes limited to ECDSA P-256 and
//! Ed25519, and sessions are never resumed (no tickets, no session cache),
//! so every connection checks its pin again. After the handshake the
//! connection joins the Unix socket's path: the same upgrade limits,
//! deadline and WebSocket API, its place among the
//! [`MAX_PENDING_UPGRADES`](crate::MAX_PENDING_UPGRADES) taken and its [`UPGRADE_TIMEOUT`] started the
//! moment it authenticates. While a pairing code is open ([`pairing`]),
//! an unknown certificate passes too, still with its signature verified,
//! but its connection reaches nothing but the pairing request.
//!
//! The handshake runs before anything is known about the peer, so it has
//! its own budget, apart from the upgrade's: [`MAX_PENDING_HANDSHAKES`] at
//! once, [`MAX_HANDSHAKES_PER_ADDRESS`] per source address (per /64 for
//! IPv6), each closed after [`HANDSHAKE_TIMEOUT`] on the injected clock, and
//! [`RESERVED_HANDSHAKES`] more for addresses that authenticated before, so
//! a peer that holds the pool cannot keep the client from reconnecting.
//! Refusals are logged rate-limited; every authenticated client is logged
//! with its pin and address.
//!
//! Standards: RFC 8446 (TLS 1.3: §4.3.2 the `CertificateRequest`'s
//! `signature_algorithms`, §4.4.2 `Certificate`, §4.4.3
//! `CertificateVerify`, §4.6.1 `NewSessionTicket`, §2.2 resumption), RFC 5280 §4.1.2.5 (validity),
//! RFC 4291 §2.5.4 (the 64-bit interface identifier), NIST SP 800-207 §2.1
//! (tenets 1, 3, 5 and 6: every connection authenticated and encrypted,
//! wherever it comes from, before any resource is reached).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use lotse_core::backoff::AcceptBackoff;
use lotse_core::clock::Clock;
use lotse_core::fingerprint::Fingerprint;
use lotse_core::task::{BoxFuture, spawn_named};
use lotse_core::throttle::Throttle;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::NoServerSessionStorage;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, PeerIncompatible,
    PeerMisbehaved, ServerConfig, SignatureScheme,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::clients::ClientStore;
use crate::identity::ServerIdentity;
use crate::listener::{BindError, PeerInfo, accept_retrying};
use crate::pairing::{self, CODE_LIFETIME, PairContext, Pairing};
use crate::{UPGRADE_TIMEOUT, upgrade_slot};

/// From accept to the end of the TLS handshake: 3 s. A TLS 1.3 handshake
/// is one round trip and the client's flight.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// TLS handshakes in progress at once: 16. One more is closed at accept,
/// unless [`RESERVED_HANDSHAKES`] lets it in.
pub const MAX_PENDING_HANDSHAKES: usize = 16;

/// Handshakes beyond [`MAX_PENDING_HANDSHAKES`] for addresses that
/// authenticated before: 4.
pub const RESERVED_HANDSHAKES: usize = 4;

/// TLS handshakes in progress from one source address at once: 2. An IPv6
/// address counts by its /64, which one host commonly holds whole.
pub const MAX_HANDSHAKES_PER_ADDRESS: u16 = 2;

/// Addresses remembered as having authenticated, for
/// [`RESERVED_HANDSHAKES`]: 32. Only an authenticated client adds one, and
/// once full no more are added.
pub const MAX_KNOWN_ADDRESSES: usize = 32;

/// The client signature schemes offered (RFC 8446 §4.3.2) and accepted:
/// ECDSA P-256 with SHA-256, and Ed25519.
const VERIFY_SCHEMES: [SignatureScheme; 2] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ED25519,
];

/// The TLS listener's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// The address to listen on.
    pub listen: SocketAddr,
    /// The pins of the client certificates the configuration allows. They
    /// are fixed: pairing adds pins of its own and removes none of these.
    pub clients: Vec<Fingerprint>,
    /// Where the [`ServerIdentity`] and the enrolled clients are kept.
    pub data_dir: PathBuf,
    /// The uid and gid the daemon runs as after the privilege drop (the
    /// starting ones when there is none), which own the enrolled clients'
    /// directory because the daemon writes it at runtime.
    pub state_owner: (u32, u32),
}

/// The listener bound, with what its handshakes are configured from once
/// the clock is known.
#[derive(Debug)]
pub(crate) struct BoundTls {
    /// The listener, non-blocking.
    pub(crate) listener: std::net::TcpListener,
    /// The server's certificate and key, checked to match.
    certified: Arc<CertifiedKey>,
    /// The certificate's pin, the pairing code's first part.
    server_pin: Fingerprint,
    /// Who may connect.
    pub(crate) store: Arc<ClientStore>,
}

/// Loads (or makes) the server identity in `settings.data_dir`, which
/// `owner_uid` must own, opens the client allowlist, and binds the
/// listener. Without any client the listener still starts: only pairing
/// is reachable then, and only while a code is open.
pub(crate) fn bind(settings: &TlsConfig, owner_uid: u32) -> Result<BoundTls, BindError> {
    let identity = ServerIdentity::load_or_create(&settings.data_dir, owner_uid)?;
    let certified = CertifiedKey::from_der(
        vec![identity.certificate.clone()],
        identity.key.clone_key(),
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(BindError::Tls)?;
    // Checked as the identity's was, and used through this descriptor
    // from here on.
    let data = crate::identity::checked_directory(&settings.data_dir, owner_uid, false)?;
    let store = ClientStore::open(
        &data,
        &settings.data_dir,
        &settings.clients,
        settings.state_owner,
    )?;
    let tcp = |source| BindError::TlsListen {
        addr: settings.listen,
        source,
    };
    let listener = std::net::TcpListener::bind(settings.listen)
        .and_then(|listener| listener.set_nonblocking(true).map(|()| listener))
        .map_err(tcp)?;
    let local = listener.local_addr().unwrap_or(settings.listen);
    tracing::info!(
        addr = %local,
        server_pin = %identity.pin(),
        clients = settings.clients.len(),
        "control TLS listener bound"
    );
    Ok(BoundTls {
        listener,
        certified: Arc::new(certified),
        server_pin: identity.pin(),
        store: Arc::new(store),
    })
}

impl BoundTls {
    /// The pairing state for this listener, on `clock`.
    pub(crate) fn pairing(&self, clock: Arc<dyn Clock>) -> Arc<Pairing> {
        Arc::new(Pairing::new(
            self.server_pin,
            clock,
            rustls::crypto::ring::default_provider().secure_random,
        ))
    }

    /// The rustls configuration: TLS 1.3 only, the identity as the
    /// server's certificate, [`PinVerifier`] for the client's with
    /// `pairing` letting unknown ones through while a code is open, no
    /// resumption.
    pub(crate) fn server_config(
        &self,
        pairing: Arc<Pairing>,
    ) -> Result<ServerConfig, rustls::Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinVerifier {
            store: Arc::clone(&self.store),
            pairing,
            algorithms: provider.signature_verification_algorithms,
        });
        let resolver = Arc::new(SingleCertAndKey::from(Arc::clone(&self.certified)));
        let versions = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13]);
        let mut config = versions?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);
        // A resumed session restores the client's certificate without asking
        // the verifier (rustls 0.23.45, `server/tls13.rs`); the connection is
        // long-lived, so resumption would buy nothing and could outlive a pin.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(config)
    }
}

/// A client certificate not on the allowlist, as the handshake error
/// carries it to the log.
#[derive(Debug, thiserror::Error)]
#[error("client certificate {0} is not allowed")]
struct UnknownClient(Fingerprint);

/// Accepts a client certificate by its pin, or any while a pairing code is
/// open, and always by its handshake signature.
#[derive(Debug)]
struct PinVerifier {
    /// Who may connect.
    store: Arc<ClientStore>,
    /// Whether a code is open.
    pairing: Arc<Pairing>,
    /// The provider's signature algorithms, for the signature check.
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// The pin of the end-entity certificate must be allowed, or a pairing
    /// code open, which lets the connection pair and do nothing else;
    /// intermediates are ignored.
    ///
    /// SPEC-DEVIATION: RFC 5280 §4.1.2.5 validity is not checked. The pin
    /// names exactly one certificate and is the authority, so a client is
    /// removed by removing its pin, never by a date or a wrong clock.
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let pin = Fingerprint::of(end_entity);
        if self.store.allows(&pin) || self.pairing.is_open() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(UnknownClient(pin))),
            )))
        }
    }

    /// Never reached: only TLS 1.3 is offered.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered,
        ))
    }

    /// The `CertificateVerify` signature (RFC 8446 §4.4.3) with the
    /// certificate's key, in one of [`VERIFY_SCHEMES`]: rustls passes on
    /// whatever scheme the client used, offered or not.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if !VERIFY_SCHEMES.contains(&dss.scheme) {
            return Err(rustls::Error::PeerMisbehaved(
                PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        VERIFY_SCHEMES.to_vec()
    }
}

/// The address a peer is counted under: an IPv4 address (an IPv4-mapped
/// IPv6 one included) as it is, an IPv6 address by its /64 (RFC 4291
/// §2.5.4).
fn address_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
            || IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & !u128::from(u64::MAX))),
            IpAddr::V4,
        ),
    }
}

/// The pre-authentication budget, shared by the accept loop and the
/// handshakes.
#[derive(Debug, Default)]
pub(crate) struct Gate {
    /// The counts.
    state: Mutex<GateState>,
}

/// [`Gate`]'s counts.
#[derive(Debug, Default)]
struct GateState {
    /// Handshakes in the main pool.
    pending: usize,
    /// Handshakes in the reserve.
    reserved: usize,
    /// Handshakes per [`address_key`]; an address without any has no entry.
    per_address: HashMap<IpAddr, u16>,
    /// Addresses that authenticated.
    known: HashSet<IpAddr>,
    /// Rate limit of the log line for connections refused at accept.
    refused: Throttle,
    /// Rate limit of the log line for failed handshakes.
    failed: Throttle,
}

/// Why a connection was refused at accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// [`MAX_HANDSHAKES_PER_ADDRESS`] from this address are in progress.
    Address,
    /// The pool is full, and the reserve is full or not for this address.
    Pool,
}

impl Refusal {
    /// The reason in the log.
    const fn reason(self) -> &'static str {
        match self {
            Self::Address => "too many handshakes from this address",
            Self::Pool => "too many handshakes",
        }
    }
}

/// A handshake's place in the [`Gate`], given back when dropped.
#[derive(Debug)]
struct Ticket {
    /// The gate.
    gate: Arc<Gate>,
    /// The address it counts under.
    key: IpAddr,
    /// Whether it is in the reserve.
    reserved: bool,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut state = self.gate.lock();
        if self.reserved {
            state.reserved = state.reserved.saturating_sub(1);
        } else {
            state.pending = state.pending.saturating_sub(1);
        }
        let left = state
            .per_address
            .get(&self.key)
            .map_or(0, |count| count.saturating_sub(1));
        if left == 0 {
            state.per_address.remove(&self.key);
        } else {
            state.per_address.insert(self.key, left);
        }
    }
}

impl Gate {
    /// The counts; a poisoned lock is still usable, they hold no invariant
    /// a panicking holder could have broken halfway.
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A place for a handshake from `ip`, or why there is none.
    fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<Ticket, Refusal> {
        let key = address_key(ip);
        let mut state = self.lock();
        if state.per_address.get(&key).copied().unwrap_or(0) >= MAX_HANDSHAKES_PER_ADDRESS {
            return Err(Refusal::Address);
        }
        let reserved = if state.pending < MAX_PENDING_HANDSHAKES {
            state.pending = state.pending.saturating_add(1);
            false
        } else if state.reserved < RESERVED_HANDSHAKES && state.known.contains(&key) {
            state.reserved = state.reserved.saturating_add(1);
            true
        } else {
            return Err(Refusal::Pool);
        };
        let count = state.per_address.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        drop(state);
        Ok(Ticket {
            gate: Arc::clone(self),
            key,
            reserved,
        })
    }

    /// Remembers that `ip` authenticated, while there is room.
    fn authenticated(&self, ip: IpAddr) {
        let mut state = self.lock();
        if state.known.len() < MAX_KNOWN_ADDRESSES {
            state.known.insert(address_key(ip));
        }
    }

    /// Counts a refusal at accept at `now`: the count to log, when due.
    fn refused(&self, now: Instant) -> Option<u64> {
        self.lock().refused.hit(now)
    }

    /// Counts a failed handshake at `now`: the count to log, when due.
    fn failed(&self, now: Instant) -> Option<u64> {
        self.lock().failed.hit(now)
    }
}

/// While no client may connect, opens a pairing code and logs it, the one
/// secret the daemon logs: useless once used, and expired after
/// [`CODE_LIFETIME`], when the log says how to get another if still no
/// client is enrolled. Once a client is enrolled nothing secret is logged
/// at startup; later clients pair with `pairing/create`.
pub(crate) fn announce_first_code(
    pairing: &Pairing,
    store: &Arc<ClientStore>,
    clock: &Arc<dyn Clock>,
    shutdown: &CancellationToken,
) {
    if !store.is_empty() {
        return;
    }
    let Some(code) = pairing.open() else {
        tracing::error!("no pairing code: the system provides no randomness");
        return;
    };
    tracing::info!(
        event = "pairing_code",
        code = %code.reveal(),
        expires_in_s = CODE_LIFETIME.as_secs(),
        "pairing code for the first client"
    );
    spawn_named(
        "api.pairing_expiry",
        first_code_expired(Arc::downgrade(store), Arc::clone(clock), shutdown.clone()),
    );
}

/// After the first code's lifetime, tells how to get a new one if still
/// no client is enrolled. It holds the store only weakly: waiting, it
/// keeps neither the store nor its directory's lock alive past the server.
async fn first_code_expired(
    store: Weak<ClientStore>,
    clock: Arc<dyn Clock>,
    shutdown: CancellationToken,
) {
    tokio::select! {
        () = clock.sleep(CODE_LIFETIME) => {
            if store.upgrade().is_some_and(|store| store.is_empty()) {
                tracing::info!("no control client paired and the first pairing code expired; get a new one with `lotse pair`");
            }
        }
        () = shutdown.cancelled() => {}
    }
}

/// A connection that finished its handshake, for the serve loop, with
/// the upgrade's slot and deadline it took when it authenticated.
pub(crate) struct Authenticated {
    /// The authenticated stream.
    pub(crate) stream: TlsStream<TcpStream>,
    /// Who it is.
    pub(crate) peer: PeerInfo,
    /// Its place among the connections awaiting the upgrade.
    pub(crate) slot: OwnedSemaphorePermit,
    /// [`UPGRADE_TIMEOUT`] from authentication.
    pub(crate) deadline: BoxFuture<'static, ()>,
}

/// What every handshake needs.
#[derive(Clone)]
pub(crate) struct Handshakes {
    /// Runs the handshake.
    pub(crate) acceptor: TlsAcceptor,
    /// The pre-authentication budget.
    pub(crate) gate: Arc<Gate>,
    /// Times the deadline and the rate limits.
    pub(crate) clock: Arc<dyn Clock>,
    /// Cancelled on graceful shutdown.
    pub(crate) shutdown: CancellationToken,
    /// The places of the connections awaiting the upgrade, shared with
    /// the Unix socket.
    pub(crate) upgrades: Arc<Semaphore>,
    /// Where an authenticated connection goes.
    pub(crate) admitted: mpsc::Sender<Authenticated>,
    /// Who may connect.
    pub(crate) store: Arc<ClientStore>,
    /// The open pairing code, for a connection that may only pair.
    pub(crate) pairing: Arc<Pairing>,
}

/// Accepts TCP connections until shutdown, each into a handshake of its
/// own if the [`Gate`] has room, else closed at once.
pub(crate) async fn accept_loop(listener: TcpListener, handshakes: Handshakes) {
    let mut backoff = AcceptBackoff::new();
    loop {
        let (tcp, addr) = tokio::select! {
            accepted = accept_retrying(&mut backoff, &*handshakes.clock, "tls", || listener.accept()) => accepted,
            () = handshakes.shutdown.cancelled() => break,
        };
        match handshakes.gate.admit(addr.ip()) {
            Ok(ticket) => {
                spawn_named(
                    "api.tls_handshake",
                    handshake(tcp, addr, ticket, handshakes.clone()),
                );
            }
            Err(refusal) => {
                if let Some(refused) = handshakes.gate.refused(handshakes.clock.now()) {
                    tracing::info!(
                        %addr,
                        reason = refusal.reason(),
                        refused,
                        "control TLS connection refused before the handshake"
                    );
                }
            }
        }
    }
    tracing::debug!("control TLS listener stopped accepting");
}

/// Runs one handshake within [`HANDSHAKE_TIMEOUT`] and hands an
/// authenticated connection on. The ticket is given back when the
/// handshake ends, whatever its outcome.
async fn handshake(tcp: TcpStream, addr: SocketAddr, ticket: Ticket, h: Handshakes) {
    // Control frames are small and wait on each other: no Nagle delay.
    let _nodelay = tcp.set_nodelay(true);
    let accepted = tokio::select! {
        accepted = h.acceptor.accept(tcp) => accepted,
        () = h.clock.sleep(HANDSHAKE_TIMEOUT) => {
            if let Some(refused) = h.gate.failed(h.clock.now()) {
                let timeout_ms = HANDSHAKE_TIMEOUT.as_millis();
                tracing::info!(%addr, timeout_ms, refused, "control TLS connection closed: no handshake before the deadline");
            }
            return;
        }
        () = h.shutdown.cancelled() => return,
    };
    match accepted {
        Ok(stream) => {
            let Some(pin) = pin_of(&stream) else { return };
            if !h.store.allows(&pin) {
                // In only because a code is open: it may pair and do
                // nothing else, within the budget its ticket holds.
                tracing::info!(%addr, client_pin = %pin, "pairing connection opened");
                let context =
                    PairContext::new(Arc::clone(&h.pairing), Arc::clone(&h.store), pin, addr);
                pairing::serve(stream, context, h.clock, h.shutdown).await;
                drop(ticket);
                return;
            }
            drop(ticket);
            h.gate.authenticated(addr.ip());
            tracing::info!(
                event = "control_client_authenticated",
                client_pin = %pin,
                %addr,
                "control client authenticated"
            );
            let peer = PeerInfo::Tls { pin, addr };
            let Some(slot) = upgrade_slot(&h.upgrades, &peer) else {
                return;
            };
            let deadline = h.clock.sleep(UPGRADE_TIMEOUT);
            let tls = Authenticated {
                stream,
                peer,
                slot,
                deadline,
            };
            let _closed = h.admitted.send(tls).await;
        }
        Err(err) => {
            let Some(refused) = h.gate.failed(h.clock.now()) else {
                return;
            };
            if let Some(pin) = refused_pin(&err) {
                tracing::info!(
                    %addr,
                    refused_client = %pin,
                    refused,
                    "control TLS handshake refused: client certificate not allowed"
                );
            } else {
                tracing::info!(%addr, error = %err, refused, "control TLS handshake failed");
            }
        }
    }
}

/// The pin of the certificate the client authenticated with; always
/// there after a handshake, which requires one.
fn pin_of(stream: &TlsStream<TcpStream>) -> Option<Fingerprint> {
    let certificate = stream.get_ref().1.peer_certificates()?.first()?;
    Some(Fingerprint::of(certificate))
}

/// The pin of a client certificate the verifier refused, if that is why
/// the handshake failed.
fn refused_pin(err: &io::Error) -> Option<Fingerprint> {
    match err.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::InvalidCertificate(CertificateError::Other(other)) => other
            .0
            .downcast_ref::<UnknownClient>()
            .map(|unknown| unknown.0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::net::Ipv4Addr;

    use super::*;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn ipv6_counts_by_its_64_and_mapped_ipv4_as_ipv4_rfc4291_2_5_4() {
        let host: IpAddr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        assert_eq!(
            address_key(host),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(address_key(mapped), v4(7));
        assert_eq!(address_key(v4(7)), v4(7));
    }

    #[test]
    fn one_address_gets_two_handshakes_and_its_count_is_given_back() {
        let gate = Arc::new(Gate::default());
        let first = gate.admit(v4(1)).unwrap();
        let second = gate.admit(v4(1)).unwrap();
        assert_eq!(gate.admit(v4(1)).unwrap_err(), Refusal::Address);
        let other = gate.admit(v4(2)).unwrap();
        drop(first);
        assert_eq!(gate.lock().per_address.get(&v4(1)), Some(&1));
        let third = gate.admit(v4(1)).unwrap();
        drop((second, third, other));
        let state = gate.lock();
        assert!(state.per_address.is_empty(), "{:?}", state.per_address);
        assert_eq!((state.pending, state.reserved), (0, 0));
    }

    #[test]
    fn a_full_pool_leaves_a_reserve_for_addresses_that_authenticated() {
        let gate = Arc::new(Gate::default());
        let held: Vec<Ticket> = (0..MAX_PENDING_HANDSHAKES)
            .map(|i| gate.admit(v4(u8::try_from(10 + i / 2).unwrap())).unwrap())
            .collect();
        assert_eq!(gate.admit(v4(200)).unwrap_err(), Refusal::Pool);
        gate.authenticated(v4(200));
        let reserve: Vec<Ticket> = (0..RESERVED_HANDSHAKES)
            .map(|i| {
                let ip = v4(200 + u8::try_from(i).unwrap());
                gate.authenticated(ip);
                gate.admit(ip).unwrap()
            })
            .collect();
        assert!(reserve.iter().all(|ticket| ticket.reserved));
        gate.authenticated(v4(250));
        assert_eq!(
            gate.admit(v4(250)).unwrap_err(),
            Refusal::Pool,
            "reserve full"
        );
        drop(reserve);
        assert_eq!(gate.lock().reserved, 0);
        assert_eq!(gate.lock().pending, MAX_PENDING_HANDSHAKES);
        drop(held);
        assert_eq!(gate.lock().pending, 0);
        assert_eq!(Refusal::Pool.reason(), "too many handshakes");
        assert_eq!(
            Refusal::Address.reason(),
            "too many handshakes from this address"
        );
    }

    #[test]
    fn only_so_many_addresses_are_remembered() {
        let gate = Gate::default();
        for i in 0..=MAX_KNOWN_ADDRESSES {
            gate.authenticated(v4(u8::try_from(i).unwrap()));
        }
        let last = v4(u8::try_from(MAX_KNOWN_ADDRESSES).unwrap());
        let (known, has_last) = {
            let state = gate.lock();
            (state.known.len(), state.known.contains(&last))
        };
        assert_eq!(known, MAX_KNOWN_ADDRESSES);
        assert!(!has_last);
    }

    /// A listener bound in a fresh data directory, without clients.
    fn bound(name: &str) -> (BoundTls, PathBuf) {
        use std::os::unix::fs::DirBuilderExt as _;

        let dir = std::env::temp_dir().join(format!("lotse-tls-{name}-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let settings = TlsConfig {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            clients: vec![],
            data_dir: dir.clone(),
            state_owner: (
                rustix::process::getuid().as_raw(),
                rustix::process::getgid().as_raw(),
            ),
        };
        (
            bind(&settings, rustix::process::getuid().as_raw()).unwrap(),
            dir,
        )
    }

    #[test]
    fn the_listener_is_close_on_exec_so_no_worker_inherits_it() {
        let (bound, dir) = bound("cloexec");
        let flags = rustix::io::fcntl_getfd(&bound.listener).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_verifier_refuses_tls_1_2_and_hints_no_names() {
        let (bound, dir) = bound("verifier");
        // A real DigitallySignedStruct, which only rustls can make: a
        // server's CertificateVerify, captured from a handshake.
        let dss = lotse_testing::control_tls::server_signature().unwrap();
        let verifier = PinVerifier {
            store: Arc::clone(&bound.store),
            pairing: bound.pairing(Arc::new(lotse_core::clock::FakeClock::default())),
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        };
        let err = verifier
            .verify_tls12_signature(b"", &CertificateDer::from(vec![]), &dss)
            .unwrap_err();
        assert_eq!(
            err,
            rustls::Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered)
        );
        assert!(verifier.root_hint_subjects().is_empty());
        assert_eq!(verifier.supported_verify_schemes(), VERIFY_SCHEMES);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_waiting_first_code_expiry_keeps_neither_the_store_nor_its_lock() {
        let (captured, _guard) = pairing::test_support::capture();
        let (bound, dir) = bound("expiry");
        let fake = Arc::new(lotse_core::clock::FakeClock::default());
        let clock: Arc<dyn Clock> = Arc::<lotse_core::clock::FakeClock>::clone(&fake);
        let pairing = bound.pairing(Arc::clone(&clock));
        let shutdown = CancellationToken::new();
        announce_first_code(&pairing, &bound.store, &clock, &shutdown);
        tokio::task::yield_now().await;
        // The server is gone, its expiry still waiting: a restart in this
        // runtime gets the directory at once.
        drop(bound);
        let runtime = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let data = std::fs::File::open(&dir).unwrap();
        ClientStore::open(&data, &dir, &[], runtime).unwrap();
        fake.advance(CODE_LIFETIME);
        tokio::task::yield_now().await;
        assert!(!captured.text().contains("first pairing code expired"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn the_first_code_is_announced_only_while_no_client_may_connect() {
        let (captured, _guard) = pairing::test_support::capture();
        let (bound, dir) = bound("announce");
        let clock: Arc<dyn Clock> = Arc::new(lotse_core::clock::FakeClock::default());
        let pairing = bound.pairing(Arc::clone(&clock));
        let shutdown = CancellationToken::new();
        announce_first_code(&pairing, &bound.store, &clock, &shutdown);
        assert!(pairing.is_open());
        assert_eq!(captured.text().matches("LOTSE1-").count(), 1);
        bound.store.enroll(Fingerprint::of(b"client")).unwrap();
        let later = bound.pairing(Arc::clone(&clock));
        announce_first_code(&later, &bound.store, &clock, &shutdown);
        assert!(!later.is_open(), "a client is enrolled");
        assert_eq!(captured.text().matches("LOTSE1-").count(), 1);
        shutdown.cancel();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn without_randomness_no_first_code_is_announced() {
        let (captured, _guard) = pairing::test_support::capture();
        let (bound, dir) = bound("no-random");
        let clock: Arc<dyn Clock> = Arc::new(lotse_core::clock::FakeClock::default());
        let pairing = Pairing::new(
            Fingerprint::of(b"server"),
            Arc::clone(&clock),
            &pairing::test_support::NO_RANDOM,
        );
        announce_first_code(&pairing, &bound.store, &clock, &CancellationToken::new());
        assert!(!pairing.is_open());
        let logs = captured.text();
        assert!(logs.contains("no pairing code"), "{logs}");
        assert!(!logs.contains("LOTSE1"), "{logs}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
