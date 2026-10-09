//! A fake TURN server: allocations, permissions and channel bindings
//! behind the long-term credential, on loopback UDP and TCP, with knobs
//! for what real servers do to a client: stale nonces, credentials that
//! expire, lost requests and restarts.
//!
//! Its own STUN codec, written apart from the supervisor's (which this
//! crate may not depend on, `.cargo/layering.toml`), so a misreading of a
//! clause shows up as a disagreement instead of agreeing with itself.
//! Implements the server side of RFC 8489 §5 and §14 (the message and the
//! attributes it needs), §9.2.4 (the long-term credential, MD5 keys, no
//! nonce cookie, like coturn) and RFC 8656 §5 (one allocation per 5-tuple,
//! 437 for a second Allocate, 441 for another username), §7.2, §8.2,
//! §10.2 and §12.2. Relayed addresses are made up (RFC 5737 TEST-NET-3),
//! so no peer reaches them: a test plays the peer with
//! [`FakeTurnServer::relay_to_client`], which the server relays as it
//! would a datagram arriving at the relayed address, as `ChannelData` on the
//! peer's channel or in a Data indication (§11.3, §12.7). Started with
//! [`FakeTurnServer::start_relaying`], allocations over UDP and TCP relay
//! on real loopback sockets instead: what a peer sends to one reaches the
//! client that way, on its TCP connection for a TCP allocation, and
//! `ChannelData` from the client on a bound channel goes to its peer
//! (§12.6), so a viewer can reach a session through the relay alone. Time comes from the injected clock, so an allocation expires
//! when a test moves it. [`FakeTurn`] is the I/O-free core;
//! [`FakeTurnServer`] serves it.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac as _};
use lotse_core::clock::Clock;
use lotse_core::task::spawn_named;
use md5::{Digest as _, Md5};
use sha1::Sha1;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// The magic cookie (RFC 8489 §5).
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// The STUN header (§5).
const HEADER_LEN: usize = 20;

/// Allocate (RFC 8656 §17).
pub const ALLOCATE: u16 = 0x003;
/// Refresh (§17).
pub const REFRESH: u16 = 0x004;
/// `CreatePermission` (§17).
pub const CREATE_PERMISSION: u16 = 0x008;
/// `ChannelBind` (§17).
pub const CHANNEL_BIND: u16 = 0x009;
/// Data (§17).
const DATA: u16 = 0x007;

/// The class bits of a request (RFC 8489 §5).
const CLASS_REQUEST: u16 = 0b00;
/// Of an indication.
const CLASS_INDICATION: u16 = 0b01;
/// Of a success response.
const CLASS_SUCCESS: u16 = 0b10;
/// Of an error response.
const CLASS_ERROR: u16 = 0b11;

/// USERNAME (RFC 8489 §14.3).
const USERNAME: u16 = 0x0006;
/// MESSAGE-INTEGRITY (§14.5).
const MESSAGE_INTEGRITY: u16 = 0x0008;
/// ERROR-CODE (§14.8).
const ERROR_CODE: u16 = 0x0009;
/// REALM (§14.9).
const REALM: u16 = 0x0014;
/// NONCE (§14.10).
const NONCE: u16 = 0x0015;
/// XOR-MAPPED-ADDRESS (§14.2).
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// CHANNEL-NUMBER (RFC 8656 §18.1).
const CHANNEL_NUMBER: u16 = 0x000C;
/// LIFETIME (§18.2).
const LIFETIME: u16 = 0x000D;
/// XOR-PEER-ADDRESS (§18.3).
const XOR_PEER_ADDRESS: u16 = 0x0012;
/// DATA (§18.4).
const DATA_ATTRIBUTE: u16 = 0x0013;
/// XOR-RELAYED-ADDRESS (§18.5).
const XOR_RELAYED_ADDRESS: u16 = 0x0016;
/// REQUESTED-TRANSPORT (§18.8).
const REQUESTED_TRANSPORT: u16 = 0x0019;

/// How long a permission lasts (RFC 8656 §9).
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);

/// A parsed request; values borrow the bytes.
#[derive(Debug)]
struct Request<'a> {
    /// The method.
    method: u16,
    /// The class bits.
    class: u16,
    /// The transaction id.
    id: [u8; 12],
    /// The attributes in order.
    attributes: Vec<(u16, &'a [u8])>,
    /// Where MESSAGE-INTEGRITY starts.
    integrity_at: Option<usize>,
    /// The whole message.
    raw: &'a [u8],
}

impl<'a> Request<'a> {
    /// The first attribute of `kind`.
    fn get(&self, kind: u16) -> Option<&'a [u8]> {
        self.attributes
            .iter()
            .find(|(t, _)| *t == kind)
            .map(|(_, v)| *v)
    }

    /// An attribute as text.
    fn text(&self, kind: u16) -> Option<&'a str> {
        std::str::from_utf8(self.get(kind)?).ok()
    }
}

/// Reads a STUN message (RFC 8489 §5, §14).
fn parse(bytes: &[u8]) -> Option<Request<'_>> {
    let header = bytes.get(..HEADER_LEN)?;
    let kind = u16::from_be_bytes([*header.first()?, *header.get(1)?]);
    if kind & 0xC000 != 0 || header.get(4..8)? != MAGIC_COOKIE.to_be_bytes() {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([*header.get(2)?, *header.get(3)?]));
    if bytes.len() != HEADER_LEN.checked_add(length)? {
        return None;
    }
    let id: [u8; 12] = header.get(8..20)?.try_into().ok()?;
    let method = (kind & 0x000F) | ((kind & 0x00E0) >> 1) | ((kind & 0x3E00) >> 2);
    let class = ((kind & 0x0010) >> 4) | ((kind & 0x0100) >> 7);
    let mut attributes = Vec::new();
    let mut integrity_at = None;
    let mut at = HEADER_LEN;
    while at < bytes.len() {
        let kind = u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at.checked_add(1)?)?]);
        let len = usize::from(u16::from_be_bytes([
            *bytes.get(at.checked_add(2)?)?,
            *bytes.get(at.checked_add(3)?)?,
        ]));
        let start = at.checked_add(4)?;
        let value = bytes.get(start..start.checked_add(len)?)?;
        if kind == MESSAGE_INTEGRITY {
            integrity_at = Some(at);
        }
        attributes.push((kind, value));
        at = start.checked_add(len.div_ceil(4).checked_mul(4)?)?;
    }
    Some(Request {
        method,
        class,
        id,
        attributes,
        integrity_at,
        raw: bytes,
    })
}

/// A response being built (RFC 8489 §5).
struct Response {
    /// The bytes so far.
    bytes: Vec<u8>,
    /// The transaction id, for XOR addresses.
    id: [u8; 12],
}

impl Response {
    /// A response of `class` to `method`.
    fn new(method: u16, class: u16, id: [u8; 12]) -> Self {
        let kind = (method & 0x000F)
            | ((method & 0x0070) << 1)
            | ((method & 0x0F80) << 2)
            | ((class & 0b01) << 4)
            | ((class & 0b10) << 7);
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&id);
        Self { bytes, id }
    }

    /// Appends an attribute, padded (§14).
    fn attribute(mut self, kind: u16, value: &[u8]) -> Self {
        self.bytes.extend_from_slice(&kind.to_be_bytes());
        let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(value);
        let padded = value.len().div_ceil(4).saturating_mul(4);
        self.bytes.resize(
            self.bytes
                .len()
                .saturating_add(padded.saturating_sub(value.len())),
            0,
        );
        self.set_length(0);
        self
    }

    /// Appends an address XOR-encoded (§14.2).
    fn xor_address(self, kind: u16, addr: SocketAddr) -> Self {
        let value = xor_encode(addr, self.id);
        self.attribute(kind, &value)
    }

    /// Appends ERROR-CODE (§14.8), with no reason phrase when `reason` is
    /// empty.
    fn error(self, code: u16, reason: &str) -> Self {
        let class = u8::try_from(code / 100).unwrap_or(0);
        let number = u8::try_from(code % 100).unwrap_or(0);
        let mut value = vec![0, 0, class, number];
        value.extend_from_slice(reason.as_bytes());
        self.attribute(ERROR_CODE, &value)
    }

    /// Appends MESSAGE-INTEGRITY under `key` (§14.5).
    fn integrity(mut self, key: &[u8]) -> Self {
        self.set_length(24);
        let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(key) else {
            return self;
        };
        mac.update(&self.bytes);
        let digest = mac.finalize().into_bytes();
        self.attribute(MESSAGE_INTEGRITY, &digest)
    }

    /// Sets the header's length to the attributes plus `extra`.
    fn set_length(&mut self, extra: usize) {
        let len = self
            .bytes
            .len()
            .saturating_sub(HEADER_LEN)
            .saturating_add(extra);
        let len = u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes();
        if let Some(field) = self.bytes.get_mut(2..4) {
            field.copy_from_slice(&len);
        }
    }
}

/// The XOR encoding of `addr` (RFC 8489 §14.2).
fn xor_encode(addr: SocketAddr, id: [u8; 12]) -> Vec<u8> {
    let port = addr.port() ^ 0x2112;
    let mut value = vec![0];
    match addr.ip() {
        IpAddr::V4(ip) => {
            value.push(0x01);
            value.extend_from_slice(&port.to_be_bytes());
            value.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            value.push(0x02);
            value.extend_from_slice(&port.to_be_bytes());
            let key = MAGIC_COOKIE.to_be_bytes().into_iter().chain(id);
            value.extend(ip.octets().into_iter().zip(key).map(|(a, k)| a ^ k));
        }
    }
    value
}

/// The address an XOR-encoded value carries (§14.2).
fn xor_decode(value: &[u8], id: [u8; 12]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]) ^ 0x2112;
    let ip = match value.get(1)? {
        0x01 => {
            let raw: [u8; 4] = value.get(4..8)?.try_into().ok()?;
            IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(raw) ^ MAGIC_COOKIE))
        }
        0x02 => {
            let raw: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            let key = MAGIC_COOKIE.to_be_bytes().into_iter().chain(id);
            let mut octets = [0; 16];
            for ((out, a), k) in octets.iter_mut().zip(raw).zip(key) {
                *out = a ^ k;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// One request as the server saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    /// The method.
    pub method: u16,
    /// Who it was signed as; `None` for an unsigned one.
    pub username: Option<String>,
    /// The error code of the answer, `None` for success; dropped requests
    /// are not logged.
    pub error: Option<u16>,
    /// It came over TCP.
    pub tcp: bool,
}

/// An allocation as the server holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeAllocation {
    /// The client's address on its 5-tuple.
    pub client: SocketAddr,
    /// It was made over TCP.
    pub tcp: bool,
    /// Its username.
    pub username: String,
    /// The relayed address handed out.
    pub relayed: SocketAddr,
    /// Peer IPs with a live permission.
    pub permissions: Vec<IpAddr>,
    /// Channel numbers and their peers.
    pub channels: Vec<(u16, SocketAddr)>,
    /// Refreshes with a nonzero lifetime.
    pub refreshes: u32,
}

/// An allocation, inside.
#[derive(Debug)]
struct Allocation {
    /// Its username (RFC 8656 §5).
    username: String,
    /// The relayed address.
    relayed: SocketAddr,
    /// When it expires.
    expires: Instant,
    /// The Allocate that made it, whose retransmission is answered again
    /// (§7.2).
    made_by: [u8; 12],
    /// Permissions by peer IP, with their expiry.
    permissions: BTreeMap<IpAddr, Instant>,
    /// Channel bindings.
    channels: BTreeMap<u16, SocketAddr>,
    /// Refreshes so far.
    refreshes: u32,
}

/// The server's state.
#[derive(Debug)]
struct State {
    /// Passwords by username, and whether the credential expired.
    users: HashMap<String, (String, bool)>,
    /// The current nonce.
    nonce: String,
    /// Nonces issued.
    nonces: u32,
    /// Allocations by (over TCP, client address).
    allocations: HashMap<(bool, SocketAddr), Allocation>,
    /// Requests seen.
    log: Vec<Logged>,
    /// Requests still to drop unanswered.
    drop: usize,
    /// Requests dropped.
    dropped: usize,
    /// Relayed ports handed out.
    relays: u16,
    /// Peer IPs the server refuses permissions for.
    forbidden: Vec<IpAddr>,
    /// Data indications sent, which number their transaction ids.
    indications: u32,
    /// Real relayed addresses for allocations, handed out in order; past
    /// them, made-up ones.
    relay_pool: Vec<SocketAddr>,
}

/// The I/O-free server; see the module documentation.
#[derive(Debug)]
pub struct FakeTurn {
    /// The clock allocations expire on.
    clock: Arc<dyn Clock>,
    /// The realm.
    realm: String,
    /// The lifetime granted (RFC 8656 §7.2, §8.2).
    lifetime: Duration,
    /// Everything that changes.
    state: Mutex<State>,
}

impl FakeTurn {
    /// A server in `realm` granting `lifetime`, with no users.
    pub fn new(clock: Arc<dyn Clock>, realm: &str, lifetime: Duration) -> Self {
        Self {
            clock,
            realm: realm.to_owned(),
            lifetime,
            state: Mutex::new(State {
                users: HashMap::new(),
                nonce: "nonce-0".to_owned(),
                nonces: 0,
                allocations: HashMap::new(),
                log: Vec::new(),
                drop: 0,
                dropped: 0,
                relays: 0,
                forbidden: Vec::new(),
                indications: 0,
                relay_pool: Vec::new(),
            }),
        }
    }

    /// The state, through a poisoned lock too.
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds a user.
    pub fn add_user(&self, username: &str, password: &str) {
        self.state()
            .users
            .insert(username.to_owned(), (password.to_owned(), false));
    }

    /// The user's credential expired: every request signed with it gets a
    /// 401, a fresh nonce or not, as a server that checks expiry on every
    /// request does.
    pub fn expire_user(&self, username: &str) {
        if let Some(user) = self.state().users.get_mut(username) {
            user.1 = true;
        }
    }

    /// Issues a new nonce: requests signed with the old one get a 438
    /// (RFC 8489 §9.2.4).
    pub fn rotate_nonce(&self) {
        let mut state = self.state();
        state.nonces = state.nonces.saturating_add(1);
        state.nonce = format!("nonce-{}", state.nonces);
    }

    /// The next `count` requests go unanswered, as if lost.
    pub fn drop_requests(&self, count: usize) {
        self.state().drop = count;
    }

    /// Refuses permissions and channels for `peer` with 403 (RFC 8656
    /// §10.2, §12.2: the server's policy).
    pub fn forbid(&self, peer: IpAddr) {
        self.state().forbidden.push(peer);
    }

    /// Allocations get these relayed addresses, each once, before the
    /// made-up ones.
    pub fn relay_on(&self, addrs: Vec<SocketAddr>) {
        self.state().relay_pool = addrs;
    }

    /// The client of the live allocation relaying from `relayed`, and
    /// whether it came over TCP.
    pub fn client_of(&self, relayed: SocketAddr) -> Option<(bool, SocketAddr)> {
        let now = self.clock.now();
        self.state()
            .allocations
            .iter()
            .find(|(_, a)| a.relayed == relayed && a.expires > now)
            .map(|(key, _)| *key)
    }

    /// What the server does with `ChannelData` from `client` (over TCP
    /// when `tcp`): the data, the relayed address it leaves from and the
    /// peer, when the channel is bound on a live allocation and the peer's
    /// permission lives (RFC 8656 §12.6); `None`, silently discarded,
    /// otherwise.
    pub fn relay_to_peer(
        &self,
        client: SocketAddr,
        tcp: bool,
        bytes: &[u8],
    ) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
        let (&[c0, c1, l0, l1], rest) = bytes.split_first_chunk::<4>()?;
        let channel = u16::from_be_bytes([c0, c1]);
        let data = rest.get(..usize::from(u16::from_be_bytes([l0, l1])))?;
        let now = self.clock.now();
        let state = self.state();
        let found = state
            .allocations
            .get(&(tcp, client))
            .filter(|a| a.expires > now)
            .and_then(|allocation| {
                let peer = *allocation.channels.get(&channel)?;
                let permitted = allocation
                    .permissions
                    .get(&peer.ip())
                    .is_some_and(|until| *until > now);
                Some((allocation.relayed, peer, permitted))
            });
        drop(state);
        let (relayed, peer, permitted) = found?;
        permitted.then(|| (relayed, peer, data.to_vec()))
    }

    /// How many requests were dropped.
    pub fn dropped(&self) -> usize {
        self.state().dropped
    }

    /// Forgets every allocation, as a restarted server would.
    pub fn forget_allocations(&self) {
        self.state().allocations.clear();
    }

    /// The requests seen so far.
    pub fn requests(&self) -> Vec<Logged> {
        self.state().log.clone()
    }

    /// The live allocations, oldest relayed port first.
    pub fn allocations(&self) -> Vec<FakeAllocation> {
        let now = self.clock.now();
        let state = self.state();
        let mut all: Vec<FakeAllocation> = state
            .allocations
            .iter()
            .filter(|(_, a)| a.expires > now)
            .map(|((tcp, client), a)| FakeAllocation {
                client: *client,
                tcp: *tcp,
                username: a.username.clone(),
                relayed: a.relayed,
                permissions: a
                    .permissions
                    .iter()
                    .filter(|(_, until)| **until > now)
                    .map(|(ip, _)| *ip)
                    .collect(),
                channels: a.channels.iter().map(|(c, p)| (*c, *p)).collect(),
                refreshes: a.refreshes,
            })
            .collect();
        drop(state);
        all.sort_by_key(|a| a.relayed.port());
        all
    }

    /// What the server sends `client` (over TCP when `tcp`) when `peer`
    /// sends `data` to the relayed address of its allocation: nothing
    /// without a live permission for the peer's IP (RFC 8656 §9), else
    /// `ChannelData` on a channel bound to the peer (§12.7, padded on TCP,
    /// §12.5), else a Data indication (§11.3).
    pub fn relay_from_peer(
        &self,
        client: SocketAddr,
        tcp: bool,
        peer: SocketAddr,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let now = self.clock.now();
        let mut state = self.state();
        let allocation = state
            .allocations
            .get(&(tcp, client))
            .filter(|a| a.expires > now)?;
        if allocation
            .permissions
            .get(&peer.ip())
            .is_none_or(|until| *until <= now)
        {
            return None;
        }
        let channel = allocation
            .channels
            .iter()
            .find(|(_, p)| **p == peer)
            .map(|(c, _)| *c);
        if let Some(channel) = channel {
            let length = u16::try_from(data.len()).ok()?;
            let mut message = Vec::with_capacity(data.len().saturating_add(8));
            message.extend_from_slice(&channel.to_be_bytes());
            message.extend_from_slice(&length.to_be_bytes());
            message.extend_from_slice(data);
            if tcp {
                message.resize(4_usize.saturating_add(data.len().next_multiple_of(4)), 0);
            }
            return Some(message);
        }
        state.indications = state.indications.saturating_add(1);
        let mut id = [0xD7; 12];
        if let Some(tail) = id.get_mut(8..) {
            tail.copy_from_slice(&state.indications.to_be_bytes());
        }
        drop(state);
        Some(
            Response::new(DATA, CLASS_INDICATION, id)
                .xor_address(XOR_PEER_ADDRESS, peer)
                .attribute(DATA_ATTRIBUTE, data)
                .bytes,
        )
    }

    /// Answers one message from `client` (over TCP when `tcp`); `None`
    /// for anything that is not a request, and for a dropped one.
    pub fn handle(&self, client: SocketAddr, tcp: bool, bytes: &[u8]) -> Option<Vec<u8>> {
        let request = parse(bytes)?;
        if request.class != CLASS_REQUEST {
            return None;
        }
        let now = self.clock.now();
        let mut state = self.state();
        state.allocations.retain(|_, a| a.expires > now);
        if state.drop > 0 {
            state.drop = state.drop.saturating_sub(1);
            state.dropped = state.dropped.saturating_add(1);
            return None;
        }
        let (response, username, error) = self.answer(&mut state, now, (tcp, client), &request);
        state.log.push(Logged {
            method: request.method,
            username,
            error,
            tcp,
        });
        drop(state);
        Some(response)
    }

    /// The answer, who it was signed as, and its error code.
    fn answer(
        &self,
        state: &mut State,
        now: Instant,
        key: (bool, SocketAddr),
        request: &Request<'_>,
    ) -> (Vec<u8>, Option<String>, Option<u16>) {
        // Without a reason phrase, as coturn 4.18.0 challenges (observed
        // 2026-10-02); the rejections below keep theirs, so tests see that
        // a client carries the phrase into its errors.
        let challenge = |code: u16, nonce: &str| {
            Response::new(request.method, CLASS_ERROR, request.id)
                .error(code, "")
                .attribute(REALM, self.realm.as_bytes())
                .attribute(NONCE, nonce.as_bytes())
                .bytes
        };
        // RFC 8489 §9.2.4: no integrity, a challenge.
        let Some(integrity_at) = request.integrity_at else {
            return (challenge(401, &state.nonce), None, Some(401));
        };
        let (Some(username), Some(realm), Some(nonce)) = (
            request.text(USERNAME),
            request.text(REALM),
            request.text(NONCE),
        ) else {
            let bad = Response::new(request.method, CLASS_ERROR, request.id)
                .error(400, "Bad Request")
                .bytes;
            return (bad, None, Some(400));
        };
        let user = Some(username.to_owned());
        if nonce != state.nonce || realm != self.realm {
            return (challenge(438, &state.nonce), user, Some(438));
        }
        let password = match state.users.get(username) {
            Some((password, false)) => password.clone(),
            _ => return (challenge(401, &state.nonce), user, Some(401)),
        };
        let key_bytes = Md5::digest(format!("{username}:{}:{password}", self.realm)).to_vec();
        if !integrity_ok(request, integrity_at, &key_bytes) {
            return (challenge(401, &state.nonce), user, Some(401));
        }
        let (response, error) = self.serve(state, now, key, request, username);
        (response.integrity(&key_bytes).bytes, user, error)
    }

    /// Serves an authenticated request (RFC 8656 §7.2, §8.2, §10.2,
    /// §12.2).
    fn serve(
        &self,
        state: &mut State,
        now: Instant,
        key: (bool, SocketAddr),
        request: &Request<'_>,
        username: &str,
    ) -> (Response, Option<u16>) {
        let reject = |code: u16, reason: &str| {
            (
                Response::new(request.method, CLASS_ERROR, request.id).error(code, reason),
                Some(code),
            )
        };
        let success = Response::new(request.method, CLASS_SUCCESS, request.id);
        if request.method == ALLOCATE {
            return match self.allocate(state, now, key, request, username) {
                Ok(relayed) => (self.allocated(success, relayed, key.1), None),
                Err(437) => reject(437, "Allocation Mismatch"),
                Err(code) => reject(code, "Bad Request"),
            };
        }
        let forbidden = state.forbidden.clone();
        let Some(allocation) = state.allocations.get_mut(&key) else {
            return reject(437, "Allocation Mismatch");
        };
        if allocation.username != username {
            return reject(441, "Wrong Credentials");
        }
        match request.method {
            REFRESH => {
                let asked = request
                    .get(LIFETIME)
                    .and_then(|v| <[u8; 4]>::try_from(v).ok())
                    .map_or(self.lifetime, |v| {
                        Duration::from_secs(u64::from(u32::from_be_bytes(v)))
                    });
                if asked.is_zero() {
                    state.allocations.remove(&key);
                    return (success.attribute(LIFETIME, &[0; 4]), None);
                }
                let granted = asked.min(self.lifetime);
                allocation.expires = now.checked_add(granted).unwrap_or(now);
                allocation.refreshes = allocation.refreshes.saturating_add(1);
                let seconds = u32::try_from(granted.as_secs()).unwrap_or(u32::MAX);
                (success.attribute(LIFETIME, &seconds.to_be_bytes()), None)
            }
            CREATE_PERMISSION => {
                let peers: Vec<SocketAddr> = request
                    .attributes
                    .iter()
                    .filter(|(t, _)| *t == XOR_PEER_ADDRESS)
                    .filter_map(|(_, v)| xor_decode(v, request.id))
                    .collect();
                if peers.is_empty() {
                    return reject(400, "Bad Request");
                }
                if peers.iter().any(|peer| forbidden.contains(&peer.ip())) {
                    return reject(403, "Forbidden");
                }
                let until = now.checked_add(PERMISSION_LIFETIME).unwrap_or(now);
                for peer in peers {
                    allocation.permissions.insert(peer.ip(), until);
                }
                (success, None)
            }
            CHANNEL_BIND => {
                let channel = request
                    .get(CHANNEL_NUMBER)
                    .and_then(|v| Some(u16::from_be_bytes([*v.first()?, *v.get(1)?])));
                let peer = request
                    .get(XOR_PEER_ADDRESS)
                    .and_then(|v| xor_decode(v, request.id));
                let (Some(channel), Some(peer)) = (channel, peer) else {
                    return reject(400, "Bad Request");
                };
                if forbidden.contains(&peer.ip()) {
                    return reject(403, "Forbidden");
                }
                let taken = allocation
                    .channels
                    .iter()
                    .any(|(c, p)| (*c == channel) != (*p == peer));
                if !(0x4000..=0x4FFF).contains(&channel) || taken {
                    return reject(400, "Bad Request");
                }
                allocation.channels.insert(channel, peer);
                let until = now.checked_add(PERMISSION_LIFETIME).unwrap_or(now);
                allocation.permissions.insert(peer.ip(), until);
                (success, None)
            }
            _ => reject(400, "Bad Request"),
        }
    }

    /// Makes the allocation of `key`, or finds the one this request made
    /// before (a retransmission); the error code otherwise (RFC 8656
    /// §7.2).
    fn allocate(
        &self,
        state: &mut State,
        now: Instant,
        key: (bool, SocketAddr),
        request: &Request<'_>,
        username: &str,
    ) -> Result<SocketAddr, u16> {
        if let Some(existing) = state.allocations.get(&key) {
            return if existing.made_by == request.id {
                Ok(existing.relayed)
            } else {
                Err(437)
            };
        }
        if request.get(REQUESTED_TRANSPORT).and_then(<[u8]>::first) != Some(&17) {
            return Err(400);
        }
        state.relays = state.relays.saturating_add(1);
        let made_up = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            49_152_u16.saturating_add(state.relays),
        );
        let relayed = if state.relay_pool.is_empty() {
            made_up
        } else {
            state.relay_pool.remove(0)
        };
        state.allocations.insert(
            key,
            Allocation {
                username: username.to_owned(),
                relayed,
                expires: now.checked_add(self.lifetime).unwrap_or(now),
                made_by: request.id,
                permissions: BTreeMap::new(),
                channels: BTreeMap::new(),
                refreshes: 0,
            },
        );
        Ok(relayed)
    }

    /// An Allocate success response (RFC 8656 §7.2).
    fn allocated(&self, success: Response, relayed: SocketAddr, client: SocketAddr) -> Response {
        let seconds = u32::try_from(self.lifetime.as_secs()).unwrap_or(u32::MAX);
        success
            .xor_address(XOR_RELAYED_ADDRESS, relayed)
            .attribute(LIFETIME, &seconds.to_be_bytes())
            .xor_address(XOR_MAPPED_ADDRESS, client)
    }
}

/// Whether the MESSAGE-INTEGRITY at `at` verifies under `key` (RFC 8489
/// §14.5): the HMAC over the message up to it, with the length as if it
/// ended right after the attribute.
fn integrity_ok(request: &Request<'_>, at: usize, key: &[u8]) -> bool {
    let (Some(expected), Some(covered)) = (request.get(MESSAGE_INTEGRITY), request.raw.get(..at))
    else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(key) else {
        return false;
    };
    let length = at.saturating_sub(HEADER_LEN).saturating_add(24);
    let length = u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes();
    let mut covered = covered.to_vec();
    if let Some(field) = covered.get_mut(2..4) {
        field.copy_from_slice(&length);
    }
    mac.update(&covered);
    mac.verify_slice(expected).is_ok()
}

/// [`FakeTurn`] on loopback UDP and TCP.
#[derive(Debug)]
pub struct FakeTurnServer {
    /// The server.
    turn: Arc<FakeTurn>,
    /// The UDP socket, shared with its loop.
    socket: Arc<UdpSocket>,
    /// The UDP address.
    udp: SocketAddr,
    /// The TCP address.
    tcp: SocketAddr,
    /// Stops the UDP loops and the listener.
    cancel: CancellationToken,
    /// The TCP connections being served.
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// What to write to each TCP client, by its address.
    streams: Streams,
}

/// The TCP connections' outgoing messages, by client address.
type Streams = Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>;

/// The relaying sockets by relayed address.
type RelaySockets = Arc<HashMap<SocketAddr, Arc<UdpSocket>>>;

impl FakeTurnServer {
    /// Serves `turn` on loopback ports.
    pub async fn start(turn: Arc<FakeTurn>) -> io::Result<Self> {
        Self::start_relaying(turn, 0).await
    }

    /// Serves `turn` on loopback ports, its first `relays` allocations
    /// relaying on loopback sockets of their own (see the module
    /// documentation).
    pub async fn start_relaying(turn: Arc<FakeTurn>, relays: usize) -> io::Result<Self> {
        let udp = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let (udp_addr, tcp_addr) = (udp.local_addr()?, listener.local_addr()?);
        let cancel = CancellationToken::new();
        let connections = Arc::new(Mutex::new(Vec::new()));
        let mut sockets = HashMap::new();
        for _ in 0..relays {
            let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
            sockets.insert(socket.local_addr()?, socket);
        }
        let mut pool: Vec<SocketAddr> = sockets.keys().copied().collect();
        pool.sort_unstable();
        turn.relay_on(pool);
        let sockets = Arc::new(sockets);
        let streams = Streams::default();
        for socket in sockets.values() {
            let _relay = spawn_named(
                "fake_turn.relay",
                serve_relay(
                    Arc::clone(socket),
                    Arc::clone(&udp),
                    Arc::clone(&streams),
                    Arc::clone(&turn),
                    cancel.clone(),
                ),
            );
        }
        let _udp = spawn_named(
            "fake_turn.udp",
            serve_udp(
                Arc::clone(&udp),
                Arc::clone(&turn),
                Arc::clone(&sockets),
                cancel.clone(),
            ),
        );
        let _tcp = spawn_named(
            "fake_turn.accept",
            accept(
                listener,
                Tcp {
                    turn: Arc::clone(&turn),
                    relays: sockets,
                    streams: Arc::clone(&streams),
                },
                cancel.clone(),
                Arc::clone(&connections),
            ),
        );
        Ok(Self {
            turn,
            socket: udp,
            udp: udp_addr,
            tcp: tcp_addr,
            cancel,
            connections,
            streams,
        })
    }

    /// The server.
    pub fn turn(&self) -> &FakeTurn {
        &self.turn
    }

    /// The UDP address.
    pub const fn udp_addr(&self) -> SocketAddr {
        self.udp
    }

    /// The TCP address.
    pub const fn tcp_addr(&self) -> SocketAddr {
        self.tcp
    }

    /// `peer` sends `data` to the relayed address of `client`'s UDP
    /// allocation: what the server makes of it
    /// ([`FakeTurn::relay_from_peer`]) goes to the client from the
    /// server's UDP address. `false` when the server drops it.
    pub async fn relay_to_client(
        &self,
        client: SocketAddr,
        peer: SocketAddr,
        data: &[u8],
    ) -> io::Result<bool> {
        let Some(message) = self.turn.relay_from_peer(client, false, peer, data) else {
            return Ok(false);
        };
        self.socket.send_to(&message, client).await?;
        Ok(true)
    }

    /// Sends `bytes` to `client` from the server's UDP address as they
    /// are: what a server relays late, or gets wrong.
    pub async fn send_raw(&self, client: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        self.socket.send_to(bytes, client).await.map(drop)
    }

    /// Writes `bytes` to the TCP connection of `client` as they are;
    /// `false` when there is no such connection.
    pub fn send_raw_tcp(&self, client: SocketAddr, bytes: &[u8]) -> bool {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&client)
            .is_some_and(|stream| stream.send(bytes.to_vec()).is_ok())
    }

    /// The clients connected over TCP.
    pub fn tcp_clients(&self) -> Vec<SocketAddr> {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }

    /// Closes every TCP connection.
    pub fn disconnect_tcp(&self) {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        for connection in self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            connection.abort();
        }
    }
}

impl Drop for FakeTurnServer {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.disconnect_tcp();
    }
}

/// Relays what peers send to one relayed socket to its allocation's
/// client, from the server's UDP address or on the client's TCP
/// connection (RFC 8656 §11.3, §12.7), until cancelled.
async fn serve_relay(
    relayed: Arc<UdpSocket>,
    server: Arc<UdpSocket>,
    streams: Streams,
    turn: Arc<FakeTurn>,
    cancel: CancellationToken,
) {
    let Ok(local) = relayed.local_addr() else {
        return;
    };
    let mut buf = vec![0; 2048];
    loop {
        let (len, peer) = tokio::select! {
            received = relayed.recv_from(&mut buf) => match received {
                Ok(received) => received,
                Err(err) => {
                    tracing::debug!(error = %err, "fake turn: relay receive failed");
                    continue;
                }
            },
            () = cancel.cancelled() => return,
        };
        let Some(data) = buf.get(..len) else {
            continue;
        };
        let Some(((tcp, client), message)) = turn.client_of(local).and_then(|(tcp, client)| {
            Some((
                (tcp, client),
                turn.relay_from_peer(client, tcp, peer, data)?,
            ))
        }) else {
            continue;
        };
        if tcp {
            let stream = streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&client)
                .cloned();
            if stream.is_none_or(|stream| stream.send(message).is_err()) {
                tracing::debug!(%client, "fake turn: relay to a gone tcp client");
            }
        } else if let Err(err) = server.send_to(&message, client).await {
            tracing::debug!(error = %err, "fake turn: relay to the client failed");
        }
    }
}

/// Answers datagrams until cancelled; `ChannelData` on a bound channel
/// leaves the allocation's relayed socket for its peer (RFC 8656 §12.6).
async fn serve_udp(
    socket: Arc<UdpSocket>,
    turn: Arc<FakeTurn>,
    relays: Arc<HashMap<SocketAddr, Arc<UdpSocket>>>,
    cancel: CancellationToken,
) {
    let mut buf = vec![0; 2048];
    loop {
        let (len, from) = tokio::select! {
            received = socket.recv_from(&mut buf) => match received {
                Ok(received) => received,
                Err(err) => {
                    tracing::debug!(error = %err, "fake turn: udp receive failed");
                    continue;
                }
            },
            () = cancel.cancelled() => return,
        };
        let Some(request) = buf.get(..len) else {
            continue;
        };
        if request
            .first()
            .is_some_and(|first| (0x40..0x50).contains(first))
        {
            let relayed = turn
                .relay_to_peer(from, false, request)
                .and_then(|(relayed, peer, data)| Some((relays.get(&relayed)?, peer, data)));
            if let Some((relayed, peer, data)) = relayed
                && let Err(err) = relayed.send_to(&data, peer).await
            {
                tracing::debug!(error = %err, "fake turn: relay to the peer failed");
            }
            continue;
        }
        if let Some(response) = turn.handle(from, false, request)
            && let Err(err) = socket.send_to(&response, from).await
        {
            tracing::debug!(error = %err, "fake turn: udp send failed");
        }
    }
}

/// What every TCP connection shares.
#[derive(Debug, Clone)]
struct Tcp {
    /// The server.
    turn: Arc<FakeTurn>,
    /// The relaying sockets.
    relays: RelaySockets,
    /// The connections' outgoing messages.
    streams: Streams,
}

/// Accepts TCP connections until cancelled.
async fn accept(
    listener: TcpListener,
    tcp: Tcp,
    cancel: CancellationToken,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    tracing::debug!(error = %err, "fake turn: accept failed");
                    continue;
                }
            },
            () = cancel.cancelled() => return,
        };
        let connection = spawn_named("fake_turn.connection", serve_tcp(stream, peer, tcp.clone()));
        connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(connection);
    }
}

/// Answers the STUN messages of one TCP connection (RFC 8656 §5: STUN
/// frames itself on a stream; `ChannelData` is padded, §12.5) and relays
/// its `ChannelData` on a bound channel to the peer (§12.6); what the
/// server relays to the client goes on the same connection.
async fn serve_tcp(stream: tokio::net::TcpStream, peer: SocketAddr, tcp: Tcp) {
    let (mut reader, mut writer) = stream.into_split();
    let (outgoing, mut queued) = mpsc::unbounded_channel::<Vec<u8>>();
    tcp.streams
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(peer, outgoing);
    let mut buffer = Vec::new();
    let mut chunk = vec![0; 2048];
    'connection: loop {
        while let Some(&[first, _, high, low]) = buffer.first_chunk::<4>() {
            let length = usize::from(u16::from_be_bytes([high, low]));
            let channel_data = first >= 0x40;
            let frame = if channel_data {
                4_usize.saturating_add(length.next_multiple_of(4))
            } else {
                HEADER_LEN.saturating_add(length)
            };
            if buffer.len() < frame {
                break;
            }
            let message: Vec<u8> = buffer.drain(..frame).collect();
            if channel_data {
                let relayed = tcp
                    .turn
                    .relay_to_peer(peer, true, &message)
                    .and_then(|(relayed, to, data)| Some((tcp.relays.get(&relayed)?, to, data)));
                if let Some((relayed, to, data)) = relayed
                    && let Err(err) = relayed.send_to(&data, to).await
                {
                    tracing::debug!(error = %err, "fake turn: relay to the peer failed");
                }
            } else if let Some(response) = tcp.turn.handle(peer, true, &message)
                && writer.write_all(&response).await.is_err()
            {
                break 'connection;
            }
        }
        tokio::select! {
            read = reader.read(&mut chunk) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => buffer.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            },
            Some(message) = queued.recv() => if writer.write_all(&message).await.is_err() {
                break;
            },
        }
    }
    tcp.streams
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&peer);
}
