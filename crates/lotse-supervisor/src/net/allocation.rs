//! One TURN allocation, for one (server, transport), as an I/O-free state
//! machine: it creates the allocation with the first session's credential,
//! answers the server's 401 and 438 challenges, retransmits on UDP,
//! refreshes a minute before the lifetime ends, installs and refreshes the
//! permissions and channel bindings its sessions hold, re-creates the
//! allocation under the newest credential when the server rejects a
//! Refresh, and deletes it when the last session leaves.
//!
//! The driver (`turn_client`) feeds it the server's responses
//! ([`Allocation::handle_input`]) and the time ([`Allocation::handle_timeout`],
//! at [`Allocation::poll_timeout`]), sends what [`Allocation::poll_transmit`]
//! returns and acts on [`Allocation::poll_event`]; nothing here reads a
//! clock or touches a socket, so every path runs on test time.
//!
//! Implements RFC 8656 §5 (one allocation per 5-tuple, the same username
//! for its life), §7.1 and §7.3 (Allocate and its success response), §7.4
//! (437: an allocation of an earlier run holds the 5-tuple), §8 (Refresh
//! before the lifetime ends, LIFETIME 0 deletes; §8.3: 437 means it is
//! gone), §9 and §10 (permissions per peer IP, 300 s), §12 and §12.1
//! (channel bindings, 600 s, a number not rebound for 5 minutes), on RFC
//! 8489 §5 (random transaction ids), §6.2.1 (UDP retransmission: `RTO`,
//! `Rc`, `Rm`), §6.2.2 (reliable transports: `Ti`), §9.2 (the long-term
//! credential, via `credential`) and §9.2.5 (responses to signed requests
//! count only when their integrity verifies).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use super::credential::{
    Authenticator, Challenge, ChallengeError, Credentials, ERROR_STALE_NONCE, ERROR_UNAUTHENTICATED,
};
use super::stun::{self, Class, Message};
use super::turn::{self, Channel};

/// 437 (Allocation Mismatch) (RFC 8656 §19).
pub const ERROR_ALLOCATION_MISMATCH: u16 = 437;

/// 441 (Wrong Credentials) (RFC 8656 §19).
pub const ERROR_WRONG_CREDENTIALS: u16 = 441;

/// How long a permission lasts unless refreshed (RFC 8656 §9: 300 s).
pub const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);

/// How long a channel binding lasts unless refreshed (RFC 8656 §12:
/// 10 minutes).
pub const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);

/// How long a channel number stays bound to its peer after the binding
/// ended, for both of them (RFC 8656 §12: the client waits 5 minutes
/// before binding either to another).
pub const CHANNEL_REBIND_WAIT: Duration = Duration::from_secs(300);

/// The lifetime assumed when a success response carries no LIFETIME,
/// which it must (RFC 8656 §7.3): the server default of §7.2, 10 minutes.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);

/// How often a signed request is signed again for a new challenge before
/// it fails: a 401 that a fresh nonce does not cure is a credential the
/// server refuses, and a server that keeps
/// answering 438 is not followed forever. Not from the RFCs, which leave
/// the bound to the client (RFC 8489 §9.2.5).
const MAX_RESIGNS: u8 = 2;

/// The transport to the TURN server (RFC 8656 §3.1); the relay is UDP
/// either way (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    /// The shared UDP socket.
    Udp,
    /// A TCP connection of its own.
    Tcp,
}

impl Transport {
    /// The name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// The tunables, with the defaults of the RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationConfig {
    /// The first retransmission timeout on UDP (RFC 8489 §6.2.1: 500 ms).
    pub rto: Duration,
    /// Transmissions of a request on UDP (§6.2.1 `Rc`: 7).
    pub attempts: u32,
    /// The wait after the last transmission, in `rto`s (§6.2.1 `Rm`: 16).
    pub last_wait: u32,
    /// How long a transaction on TCP waits (§6.2.2 `Ti`: 39.5 s).
    pub reliable_timeout: Duration,
    /// The lifetime a Refresh asks for (RFC 8656 §8.1; 600 s is the
    /// server default of §7.2).
    pub lifetime: Duration,
    /// How long before an allocation, permission or binding ends it is
    /// refreshed: a minute; at most half the
    /// lifetime the server granted.
    pub refresh_margin: Duration,
}

impl Default for AllocationConfig {
    fn default() -> Self {
        Self {
            rto: Duration::from_millis(500),
            attempts: 7,
            last_wait: 16,
            reliable_timeout: Duration::from_millis(39_500),
            lifetime: DEFAULT_LIFETIME,
            refresh_margin: Duration::from_secs(60),
        }
    }
}

/// A session's hold on the allocation, from [`Allocation::add_session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeaseId(u64);

#[cfg(test)]
impl LeaseId {
    /// An id no allocation gives out, for a lease on none.
    pub(crate) const fn detached() -> Self {
        Self(u64::MAX)
    }
}

/// Why one transaction failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionError {
    /// No response within the retransmissions (RFC 8489 §6.2.1) or `Ti`
    /// (§6.2.2).
    #[error("no response from the turn server")]
    Timeout,
    /// An error response, or a challenge the request was already signed
    /// for too often.
    #[error("turn server error {code}: {reason}")]
    Rejected {
        /// The ERROR-CODE; 0 when the response carries none.
        code: u16,
        /// Its reason phrase.
        reason: String,
    },
    /// A challenge that is not answered (RFC 8489 §9.2.5).
    #[error("unanswerable challenge: {0}")]
    Challenge(ChallengeError),
}

/// Why the allocation ended or could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllocationError {
    /// The Allocate failed.
    #[error("allocate: {0}")]
    Allocate(TransactionError),
    /// An allocation of an earlier run holds the 5-tuple (437) and could
    /// not be deleted (RFC 8656 §7.4).
    #[error("an earlier allocation holds the 5-tuple: {0}")]
    Mismatch(TransactionError),
    /// The Allocate success response names no relayed address (§7.3).
    #[error("allocate response without a relayed address")]
    NoRelayedAddress,
    /// A Refresh failed and no newer credential could re-create it.
    #[error("refresh: {0}")]
    Refresh(TransactionError),
    /// The TCP connection to the server failed or closed.
    #[error("connection to the turn server lost")]
    Connection,
    /// The lease is not one of this allocation's sessions.
    #[error("unknown lease")]
    UnknownLease,
    /// Every channel number is bound or waiting out its 5 minutes (§12).
    #[error("no channel number free")]
    ChannelsExhausted,
}

/// What the driver learns from the allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The allocation exists, at `relayed` (RFC 8656 §7.3); again after a
    /// re-creation, at a new address.
    Allocated {
        /// The relayed transport address.
        relayed: SocketAddr,
    },
    /// The server ended the allocation at `relayed`; it is re-created, so
    /// a later `Allocated` follows unless `Closed` does. Permissions and
    /// channels went with it.
    Lost {
        /// The address that is gone.
        relayed: SocketAddr,
    },
    /// A permission was installed for the first time, or failed.
    Permission {
        /// The peer IP.
        peer: IpAddr,
        /// The outcome.
        result: Result<(), TransactionError>,
    },
    /// A channel binding was installed for the first time, or failed.
    Channel {
        /// The peer.
        peer: SocketAddr,
        /// Its channel.
        channel: Channel,
        /// The outcome.
        result: Result<(), TransactionError>,
    },
    /// The allocation is over: deleted after its last session (`None`) or
    /// failed. Terminal.
    Closed {
        /// Why, when it failed.
        error: Option<AllocationError>,
    },
}

/// What the server may relay to an allocation, as the demux needs it to
/// unwrap what arrives from the server (RFC 8656 §11.4, §12.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// The relayed transport address, the local address of what the
    /// server relays.
    pub relayed: SocketAddr,
    /// The channels held, bound or being bound, and their peers: the
    /// server sends `ChannelData` on a channel as soon as it bound it,
    /// which may be before its success response is read.
    pub channels: BTreeMap<Channel, SocketAddr>,
    /// The peer IPs with a permission held, installed or being installed.
    pub permissions: BTreeSet<IpAddr>,
}

/// A message for the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// The transaction it belongs to; a retransmission repeats it.
    pub transaction_id: [u8; 12],
    /// The message.
    pub bytes: Vec<u8>,
}

/// What a transaction is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// Allocate (§7.1).
    Allocate,
    /// Refresh with lifetime 0 for an earlier run's allocation (§7.4).
    ClearStale,
    /// Refresh (§8.1) of the allocation at `relayed`, which ends at
    /// `expires` unless refreshed.
    Refresh {
        /// Its relayed address.
        relayed: SocketAddr,
        /// When it ends.
        expires: Instant,
    },
    /// Refresh with lifetime 0 after the last session (§8.1).
    Delete,
    /// `CreatePermission` for one IP (§10.1).
    Permission(IpAddr),
    /// `ChannelBind` (§12.1).
    Channel(Channel, SocketAddr),
}

/// An outstanding request.
#[derive(Debug)]
struct Transaction {
    /// What it is for.
    purpose: Purpose,
    /// The message, for retransmission.
    bytes: Vec<u8>,
    /// It carries the long-term credential.
    signed: bool,
    /// How often its purpose was signed again for a new challenge.
    resigns: u8,
    /// Transmissions so far.
    sends: u32,
    /// When it is retransmitted or times out.
    next: Instant,
}

/// A permission some sessions hold (§9).
#[derive(Debug, Default)]
struct Permission {
    /// The sessions that hold it; never empty.
    holders: BTreeSet<LeaseId>,
    /// When to refresh it; `None` until installed.
    refresh_at: Option<Instant>,
    /// A `CreatePermission` is outstanding.
    in_flight: bool,
    /// It failed; retried only when a session asks again.
    failed: bool,
}

/// A channel binding some sessions hold (§12).
#[derive(Debug)]
struct Binding {
    /// The channel number.
    channel: Channel,
    /// The sessions that hold it; never empty.
    holders: BTreeSet<LeaseId>,
    /// When to refresh it; `None` until installed.
    refresh_at: Option<Instant>,
    /// When the server drops it.
    expires: Option<Instant>,
    /// A `ChannelBind` is outstanding.
    in_flight: bool,
    /// It failed; retried only when a session asks again.
    failed: bool,
}

/// A channel number whose binding ended (§12).
#[derive(Debug, Clone, Copy)]
struct Released {
    /// The peer it was bound to, which may have it back at once.
    peer: SocketAddr,
    /// From when another peer may have it.
    reusable_at: Instant,
}

/// Where the allocation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The Allocate is outstanding.
    Allocating,
    /// After a 437: deleting an earlier run's allocation (§7.4).
    ClearingStale,
    /// After a rejected Refresh: the old allocation holds the 5-tuple
    /// until it expires, then the new one is made.
    Waiting {
        /// When the old one is gone.
        until: Instant,
    },
    /// The allocation exists.
    Allocated {
        /// The relayed transport address.
        relayed: SocketAddr,
        /// When the server drops it.
        expires: Instant,
        /// When to refresh it.
        refresh_at: Instant,
        /// A Refresh is outstanding.
        refreshing: bool,
    },
    /// The deleting Refresh is outstanding.
    Deleting,
    /// Over.
    Closed,
}

/// Transaction ids: SHA-256 of a secret seed and a counter, the first 96
/// bits. Uniform and unpredictable to anyone without the seed, as RFC 8489
/// §5 asks, and infallible once seeded.
#[derive(Debug)]
struct TransactionIds {
    /// From the OS entropy source, once per allocation.
    seed: [u8; 32],
    /// Ids handed out.
    counter: u64,
}

impl TransactionIds {
    /// The next id.
    fn next(&mut self) -> [u8; 12] {
        let digest = Sha256::new()
            .chain_update(self.seed)
            .chain_update(self.counter.to_be_bytes())
            .finalize();
        self.counter = self.counter.wrapping_add(1);
        let mut id = [0; 12];
        id.iter_mut()
            .zip(digest)
            .for_each(|(out, byte)| *out = byte);
        id
    }
}

/// `now` plus `by`; `now` on the overflow no clock reaches.
fn after(now: Instant, by: Duration) -> Instant {
    now.checked_add(by).unwrap_or(now)
}

/// How long to wait after the `sends`th transmission of a request over
/// `transport`: `RTO` doubling on UDP, `Rm` times the first `RTO` after
/// the last (RFC 8489 §6.2.1); `Ti` on TCP (§6.2.2).
fn wait_after(transport: Transport, config: &AllocationConfig, sends: u32) -> Duration {
    match transport {
        Transport::Tcp => config.reliable_timeout,
        Transport::Udp if sends >= config.attempts => config.rto.saturating_mul(config.last_wait),
        Transport::Udp => config.rto.saturating_mul(
            1_u32
                .checked_shl(sends.saturating_sub(1))
                .unwrap_or(u32::MAX),
        ),
    }
}

/// How long after a grant of `lifetime` to refresh: `margin` before it
/// ends, and at the latest halfway.
fn refresh_delay(lifetime: Duration, margin: Duration) -> Duration {
    lifetime.saturating_sub(margin.min(lifetime.checked_div(2).unwrap_or_default()))
}

/// The error of an error response (RFC 8489 §14.8).
fn rejected(message: &Message<'_>) -> TransactionError {
    let (code, reason) = message.error_code().unwrap_or((0, ""));
    TransactionError::Rejected {
        code,
        reason: reason.to_owned(),
    }
}

/// One allocation; see the module documentation.
#[derive(Debug)]
pub struct Allocation {
    /// The server's transport address.
    server: SocketAddr,
    /// How it is reached.
    transport: Transport,
    /// The tunables.
    config: AllocationConfig,
    /// The credential the allocation is (being) made with, which signs
    /// every request of its life (§5).
    credentials: Credentials,
    /// The newest other credential a session brought; it re-creates the
    /// allocation when the server rejects a Refresh.
    newest: Option<Credentials>,
    /// The signer for the server's latest challenge.
    auth: Option<Authenticator>,
    /// Where it is.
    state: State,
    /// The last session left while the Allocate was outstanding: delete
    /// it once made.
    closing: bool,
    /// An earlier run's allocation was deleted once already.
    cleared_stale: bool,
    /// Transaction ids.
    ids: TransactionIds,
    /// Outstanding requests by transaction id.
    transactions: HashMap<[u8; 12], Transaction>,
    /// The sessions.
    sessions: BTreeSet<LeaseId>,
    /// The next lease id.
    next_lease: u64,
    /// Permissions by peer IP.
    permissions: BTreeMap<IpAddr, Permission>,
    /// Channel bindings by peer.
    channels: BTreeMap<SocketAddr, Binding>,
    /// Channel numbers whose bindings ended.
    released: BTreeMap<Channel, Released>,
    /// The next never-used channel number.
    next_channel: u16,
    /// Messages for the server.
    outbox: VecDeque<Transmit>,
    /// Events for the driver.
    events: VecDeque<Event>,
}

impl Allocation {
    /// Starts allocating on `server` over `transport` with `credentials`,
    /// the first session's: the first Allocate is queued, unsigned (RFC
    /// 8489 §9.2.3.1). `seed` keys the transaction ids and must come from
    /// the OS entropy source. Sessions join with [`Self::add_session`].
    pub fn new(
        server: SocketAddr,
        transport: Transport,
        credentials: Credentials,
        config: AllocationConfig,
        seed: [u8; 32],
        now: Instant,
    ) -> Self {
        let mut allocation = Self {
            server,
            transport,
            config,
            credentials,
            newest: None,
            auth: None,
            state: State::Allocating,
            closing: false,
            cleared_stale: false,
            ids: TransactionIds { seed, counter: 0 },
            transactions: HashMap::new(),
            sessions: BTreeSet::new(),
            next_lease: 0,
            permissions: BTreeMap::new(),
            channels: BTreeMap::new(),
            released: BTreeMap::new(),
            next_channel: Channel::MIN.number(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        };
        tracing::debug!(server = %server, transport = transport.name(), "turn allocation started");
        allocation.start(now, Purpose::Allocate, 0);
        allocation
    }

    /// The relayed address, while the allocation exists.
    pub const fn relayed(&self) -> Option<SocketAddr> {
        match self.state {
            State::Allocated { relayed, .. } => Some(relayed),
            _ => None,
        }
    }

    /// What the server may relay while the allocation exists: the
    /// channels and permissions its sessions hold, those the server
    /// refused left out (it relays nothing on them); `None` otherwise.
    pub fn relay(&self) -> Option<Relay> {
        let relayed = self.relayed()?;
        let channels = self
            .channels
            .iter()
            .filter(|(_, binding)| !binding.failed)
            .map(|(peer, binding)| (binding.channel, *peer))
            .collect();
        let permissions = self
            .permissions
            .iter()
            .filter(|(_, permission)| !permission.failed)
            .map(|(peer, _)| *peer)
            .collect();
        Some(Relay {
            relayed,
            channels,
            permissions,
        })
    }

    /// Whether the allocation is over.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Whether `lease` is one of the allocation's sessions.
    pub fn has_session(&self, lease: LeaseId) -> bool {
        self.sessions.contains(&lease)
    }

    /// Whether `lease` holds the binding of `channel` (§12), refused or
    /// not; what the server relays on it is [`Self::relay`]'s to say.
    pub fn holds_channel(&self, lease: LeaseId, channel: Channel) -> bool {
        self.channels
            .values()
            .any(|binding| binding.channel == channel && binding.holders.contains(&lease))
    }

    /// Whether a response to `transaction_id` is still awaited.
    pub fn is_pending(&self, transaction_id: &[u8; 12]) -> bool {
        self.transactions.contains_key(transaction_id)
    }

    /// A session joins with its credential, which is remembered as the
    /// newest when it differs from the allocation's; not sent. `None` once the allocation is being deleted
    /// or is over: the session waits for it to close and starts a new one.
    pub fn add_session(&mut self, credentials: &Credentials) -> Option<LeaseId> {
        if matches!(self.state, State::Deleting | State::Closed) {
            return None;
        }
        let lease = LeaseId(self.next_lease);
        self.next_lease = self.next_lease.wrapping_add(1);
        self.sessions.insert(lease);
        self.closing = false;
        if credentials != &self.credentials {
            tracing::debug!(server = %self.server, transport = self.transport.name(), "newer turn credential remembered");
            self.newest = Some(credentials.clone());
        }
        Some(lease)
    }

    /// A session leaves: its permissions and channels are released, and
    /// with the last session the allocation is deleted (RFC 8656 §8.1,
    /// LIFETIME 0). An unknown lease is ignored.
    pub fn remove_session(&mut self, now: Instant, lease: LeaseId) {
        if !self.sessions.remove(&lease) {
            return;
        }
        self.permissions.retain(|_, permission| {
            permission.holders.remove(&lease);
            !permission.holders.is_empty()
        });
        let channels = std::mem::take(&mut self.channels);
        for (peer, mut binding) in channels {
            binding.holders.remove(&lease);
            if binding.holders.is_empty() {
                let expires = binding
                    .expires
                    .unwrap_or_else(|| after(now, CHANNEL_LIFETIME));
                self.released.insert(
                    binding.channel,
                    Released {
                        peer,
                        reusable_at: after(expires, CHANNEL_REBIND_WAIT),
                    },
                );
            } else {
                self.channels.insert(peer, binding);
            }
        }
        if !self.sessions.is_empty() {
            return;
        }
        match self.state {
            State::Allocated { .. } => self.delete(now),
            State::Allocating | State::ClearingStale => self.closing = true,
            State::Waiting { .. } => self.close(None),
            State::Deleting | State::Closed => {}
        }
    }

    /// `lease` needs a permission for `peer` (RFC 8656 §9): installed now
    /// or once the allocation exists, refreshed while any session holds
    /// it. `true` when it is installed already; otherwise an
    /// [`Event::Permission`] follows. A failed one is tried again.
    pub fn permit(
        &mut self,
        now: Instant,
        lease: LeaseId,
        peer: IpAddr,
    ) -> Result<bool, AllocationError> {
        if !self.sessions.contains(&lease) {
            return Err(AllocationError::UnknownLease);
        }
        let permission = self.permissions.entry(peer).or_default();
        permission.holders.insert(lease);
        permission.failed = false;
        let installed = permission.refresh_at.is_some();
        self.reconcile(now);
        Ok(installed)
    }

    /// `lease` needs a channel to `peer` (RFC 8656 §12), and with it the
    /// permission for the peer's IP, which the binding does not outlive.
    /// The channel number is known at once and stays the peer's while any
    /// session holds it; `true` when the binding is installed already,
    /// otherwise an [`Event::Channel`] follows.
    pub fn bind_channel(
        &mut self,
        now: Instant,
        lease: LeaseId,
        peer: SocketAddr,
    ) -> Result<(Channel, bool), AllocationError> {
        self.permit(now, lease, peer.ip())?;
        if let Some(binding) = self.channels.get_mut(&peer) {
            binding.holders.insert(lease);
            binding.failed = false;
            let bound = (binding.channel, binding.refresh_at.is_some());
            self.reconcile(now);
            return Ok(bound);
        }
        let channel = self
            .free_channel(now, peer)
            .ok_or(AllocationError::ChannelsExhausted)?;
        self.channels.insert(
            peer,
            Binding {
                channel,
                holders: BTreeSet::from([lease]),
                refresh_at: None,
                expires: None,
                in_flight: false,
                failed: false,
            },
        );
        self.reconcile(now);
        Ok((channel, false))
    }

    /// A channel number for `peer`: the one it had, if it was released;
    /// else a never-used one; else one released at least 5 minutes after
    /// its binding ended (§12).
    fn free_channel(&mut self, now: Instant, peer: SocketAddr) -> Option<Channel> {
        let previous = self
            .released
            .iter()
            .find(|(_, released)| released.peer == peer)
            .map(|(channel, _)| *channel);
        if let Some(channel) = previous {
            self.released.remove(&channel);
            return Some(channel);
        }
        if let Some(channel) = Channel::new(self.next_channel) {
            self.next_channel = self.next_channel.saturating_add(1);
            return Some(channel);
        }
        let reusable = self
            .released
            .iter()
            .find(|(_, released)| released.reusable_at <= now)
            .map(|(channel, _)| *channel)?;
        self.released.remove(&reusable);
        Some(reusable)
    }

    /// The TCP connection is gone, and the allocation with it (RFC 8656
    /// §3.1: the 5-tuple is the connection).
    pub fn connection_lost(&mut self) {
        if self.state != State::Closed {
            self.close(Some(AllocationError::Connection));
        }
    }

    /// The next message for the server.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.outbox.pop_front()
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When [`Self::handle_timeout`] is due next; `None` once the
    /// allocation is over. Never a refresh already under way, which would
    /// be a deadline in the past. Permissions and channels have a refresh
    /// time only while installed, so only while the allocation exists.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let transactions = self.transactions.values().map(|tx| tx.next);
        let state = match self.state {
            State::Waiting { until } => Some(until),
            State::Allocated {
                refresh_at,
                refreshing: false,
                ..
            } => Some(refresh_at),
            _ => None,
        };
        let permissions = self
            .permissions
            .values()
            .filter(|p| !p.in_flight)
            .filter_map(|p| p.refresh_at);
        let channels = self
            .channels
            .values()
            .filter(|b| !b.in_flight)
            .filter_map(|b| b.refresh_at);
        transactions
            .chain(state)
            .chain(permissions)
            .chain(channels)
            .min()
    }

    /// Time passed: retransmissions and timeouts, the re-creation after a
    /// rejected Refresh, and the refreshes that are due.
    pub fn handle_timeout(&mut self, now: Instant) {
        let mut expired = Vec::new();
        let (transport, config, server) = (self.transport, self.config, self.server);
        let outbox = &mut self.outbox;
        self.transactions.retain(|id, tx| {
            if tx.next > now {
                return true;
            }
            if transport == Transport::Udp && tx.sends < config.attempts {
                tx.sends = tx.sends.saturating_add(1);
                tx.next = after(now, wait_after(transport, &config, tx.sends));
                tracing::debug!(%server, purpose = ?tx.purpose, sends = tx.sends, "turn request retransmitted");
                outbox.push_back(Transmit {
                    transaction_id: *id,
                    bytes: tx.bytes.clone(),
                });
                return true;
            }
            expired.push(tx.purpose);
            false
        });
        // One that ends the allocation leaves nothing for the rest to
        // change: it clears the permissions and channels too.
        for purpose in expired {
            tracing::debug!(server = %self.server, ?purpose, "turn request timed out");
            self.finish(now, purpose, Err(TransactionError::Timeout));
        }
        if let State::Waiting { until } = self.state
            && until <= now
        {
            tracing::info!(server = %self.server, transport = self.transport.name(), "re-creating the turn allocation under the newest credential");
            self.state = State::Allocating;
            self.start(now, Purpose::Allocate, 0);
        }
        self.reconcile(now);
    }

    /// A message from the server. `false` when it is not a response to
    /// an outstanding request, which the caller handles otherwise (or
    /// drops). A response to a signed request whose integrity does not
    /// verify is consumed and ignored, so the retransmissions go on (RFC
    /// 8489 §9.2.5).
    pub fn handle_input(&mut self, now: Instant, bytes: &[u8]) -> bool {
        let Ok(message) = stun::parse(bytes) else {
            return false;
        };
        if !matches!(message.class, Class::Success | Class::Error) {
            return false;
        }
        let Some(tx) = self.transactions.remove(&message.transaction_id) else {
            return false;
        };
        let code = message.error_code().map(|(code, _)| code);
        let challenged = message.class == Class::Error
            && matches!(code, Some(ERROR_UNAUTHENTICATED | ERROR_STALE_NONCE));
        if !challenged
            && tx.signed
            && !self
                .auth
                .as_ref()
                .is_some_and(|auth| auth.verify(&message, bytes))
        {
            tracing::debug!(server = %self.server, "turn response without valid integrity ignored");
            self.transactions.insert(message.transaction_id, tx);
            return true;
        }
        if challenged {
            self.challenged(now, &tx, &message);
        } else if message.class == Class::Error {
            self.finish(now, tx.purpose, Err(rejected(&message)));
        } else {
            self.finish(now, tx.purpose, Ok(&message));
        }
        true
    }

    /// A 401 or 438 answered `tx`: sign its purpose for the new challenge
    /// and send it again (RFC 8489 §9.2.5), or fail it.
    fn challenged(&mut self, now: Instant, tx: &Transaction, message: &Message<'_>) {
        if tx.signed && tx.resigns >= MAX_RESIGNS {
            tracing::debug!(server = %self.server, purpose = ?tx.purpose, "turn credential refused");
            self.finish(now, tx.purpose, Err(rejected(message)));
            return;
        }
        match Challenge::from_response(message) {
            Err(err) => self.finish(now, tx.purpose, Err(TransactionError::Challenge(err))),
            Ok(challenge) => {
                tracing::debug!(server = %self.server, purpose = ?tx.purpose, realm = challenge.realm, "turn challenge answered");
                self.auth = Some(Authenticator::new(&self.credentials, challenge));
                let resigns = if tx.signed {
                    tx.resigns.saturating_add(1)
                } else {
                    tx.resigns
                };
                self.start(now, tx.purpose, resigns);
            }
        }
    }

    /// Sends a new request for `purpose`, signed when a challenge is
    /// known.
    fn start(&mut self, now: Instant, purpose: Purpose, resigns: u8) {
        let id = self.ids.next();
        let builder = match purpose {
            Purpose::Allocate => turn::allocate(id, false),
            Purpose::ClearStale | Purpose::Delete => turn::refresh(id, Duration::ZERO),
            Purpose::Refresh { .. } => turn::refresh(id, self.config.lifetime),
            Purpose::Permission(peer) => turn::create_permission(id, &[SocketAddr::new(peer, 0)]),
            Purpose::Channel(channel, peer) => turn::channel_bind(id, channel, peer),
        };
        let (bytes, signed) = match &self.auth {
            Some(auth) => (auth.sign(builder).build(), true),
            None => (builder.build(), false),
        };
        self.outbox.push_back(Transmit {
            transaction_id: id,
            bytes: bytes.clone(),
        });
        self.transactions.insert(
            id,
            Transaction {
                purpose,
                bytes,
                signed,
                resigns,
                sends: 1,
                next: after(now, wait_after(self.transport, &self.config, 1)),
            },
        );
    }

    /// A transaction ended with `outcome`.
    fn finish(
        &mut self,
        now: Instant,
        purpose: Purpose,
        outcome: Result<&Message<'_>, TransactionError>,
    ) {
        match purpose {
            Purpose::Allocate => self.allocated(now, outcome),
            Purpose::ClearStale => self.cleared(now, outcome),
            Purpose::Refresh { relayed, expires } => self.refreshed(now, relayed, expires, outcome),
            Purpose::Delete => self.close(None),
            Purpose::Permission(peer) => self.permitted(now, peer, outcome),
            Purpose::Channel(channel, peer) => self.bound(now, channel, peer, outcome),
        }
    }

    /// The Allocate ended (RFC 8656 §7.3, §7.4).
    fn allocated(&mut self, now: Instant, outcome: Result<&Message<'_>, TransactionError>) {
        match outcome {
            Ok(message) => {
                let Some(relayed) = turn::relayed_address(message) else {
                    self.close(Some(AllocationError::NoRelayedAddress));
                    return;
                };
                let lifetime = turn::lifetime(message).unwrap_or(DEFAULT_LIFETIME);
                tracing::info!(server = %self.server, transport = self.transport.name(), %relayed, lifetime_s = lifetime.as_secs(), "turn allocation made");
                self.state = State::Allocated {
                    relayed,
                    expires: after(now, lifetime),
                    refresh_at: after(now, refresh_delay(lifetime, self.config.refresh_margin)),
                    refreshing: false,
                };
                self.events.push_back(Event::Allocated { relayed });
                if self.closing {
                    self.delete(now);
                } else {
                    self.reconcile(now);
                }
            }
            Err(TransactionError::Rejected {
                code: ERROR_ALLOCATION_MISMATCH,
                ..
            }) if !self.cleared_stale => {
                tracing::info!(server = %self.server, transport = self.transport.name(), "an earlier turn allocation holds the 5-tuple; deleting it");
                self.cleared_stale = true;
                self.state = State::ClearingStale;
                self.start(now, Purpose::ClearStale, 0);
            }
            Err(err) => self.close(Some(AllocationError::Allocate(err))),
        }
    }

    /// The deletion of an earlier run's allocation ended: allocate again,
    /// unless the last session left meanwhile (§7.4). A 437 says there was
    /// none any more.
    fn cleared(&mut self, now: Instant, outcome: Result<&Message<'_>, TransactionError>) {
        match outcome {
            Ok(_)
            | Err(TransactionError::Rejected {
                code: ERROR_ALLOCATION_MISMATCH,
                ..
            }) => {
                if self.closing {
                    self.close(None);
                } else {
                    self.state = State::Allocating;
                    self.start(now, Purpose::Allocate, 0);
                }
            }
            Err(err) => self.close(Some(AllocationError::Mismatch(err))),
        }
    }

    /// A Refresh ended (RFC 8656 §8.3): the allocation lives on, is gone
    /// (437, re-created now), was refused (re-created under the newest
    /// credential once the old one expired), or fails.
    fn refreshed(
        &mut self,
        now: Instant,
        relayed: SocketAddr,
        expires: Instant,
        outcome: Result<&Message<'_>, TransactionError>,
    ) {
        // Every state change clears the transactions, so a Refresh ends
        // only while the allocation it refreshes exists.
        match outcome {
            Ok(message) => {
                let lifetime = turn::lifetime(message).unwrap_or(self.config.lifetime);
                self.state = State::Allocated {
                    relayed,
                    expires: after(now, lifetime),
                    refresh_at: after(now, refresh_delay(lifetime, self.config.refresh_margin)),
                    refreshing: false,
                };
                tracing::debug!(server = %self.server, lifetime_s = lifetime.as_secs(), "turn allocation refreshed");
            }
            Err(TransactionError::Rejected {
                code: ERROR_ALLOCATION_MISMATCH,
                ..
            }) => self.lost(now, relayed, now),
            Err(
                err @ TransactionError::Rejected {
                    code: ERROR_UNAUTHENTICATED | ERROR_WRONG_CREDENTIALS,
                    ..
                },
            ) if self.newest.is_none() => self.close(Some(AllocationError::Refresh(err))),
            Err(TransactionError::Rejected {
                code: ERROR_UNAUTHENTICATED | ERROR_WRONG_CREDENTIALS,
                ..
            }) => self.lost(now, relayed, expires),
            Err(err) => self.close(Some(AllocationError::Refresh(err))),
        }
    }

    /// The server ended the allocation: forget its permissions and
    /// channels and make a new one under the newest credential, at
    /// `until` when the old one, at `relayed`, holds the 5-tuple until
    /// then.
    fn lost(&mut self, now: Instant, relayed: SocketAddr, until: Instant) {
        tracing::warn!(server = %self.server, transport = self.transport.name(), %relayed, "turn allocation lost");
        self.events.push_back(Event::Lost { relayed });
        if let Some(newest) = self.newest.take() {
            self.credentials = newest;
        }
        self.auth = None;
        self.cleared_stale = false;
        self.transactions.clear();
        self.permissions.clear();
        self.channels.clear();
        self.released.clear();
        self.next_channel = Channel::MIN.number();
        if until > now {
            self.state = State::Waiting { until };
        } else {
            self.state = State::Allocating;
            self.start(now, Purpose::Allocate, 0);
        }
    }

    /// A `CreatePermission` ended (RFC 8656 §10.3).
    fn permitted(
        &mut self,
        now: Instant,
        peer: IpAddr,
        outcome: Result<&Message<'_>, TransactionError>,
    ) {
        let refresh_in = refresh_delay(PERMISSION_LIFETIME, self.config.refresh_margin);
        let Some(permission) = self.permissions.get_mut(&peer) else {
            return;
        };
        permission.in_flight = false;
        let first = permission.refresh_at.is_none();
        match outcome {
            Ok(_) => {
                permission.refresh_at = Some(after(now, refresh_in));
                if first {
                    tracing::debug!(server = %self.server, %peer, "turn permission installed");
                    self.events.push_back(Event::Permission {
                        peer,
                        result: Ok(()),
                    });
                }
            }
            Err(err) => {
                tracing::warn!(server = %self.server, %peer, error = %err, "turn permission failed");
                permission.failed = true;
                permission.refresh_at = None;
                self.events.push_back(Event::Permission {
                    peer,
                    result: Err(err),
                });
            }
        }
    }

    /// A `ChannelBind` ended (RFC 8656 §12.3).
    fn bound(
        &mut self,
        now: Instant,
        channel: Channel,
        peer: SocketAddr,
        outcome: Result<&Message<'_>, TransactionError>,
    ) {
        let refresh_in = refresh_delay(CHANNEL_LIFETIME, self.config.refresh_margin);
        let Some(binding) = self
            .channels
            .get_mut(&peer)
            .filter(|binding| binding.channel == channel)
        else {
            return;
        };
        binding.in_flight = false;
        let first = binding.refresh_at.is_none();
        match outcome {
            Ok(_) => {
                binding.refresh_at = Some(after(now, refresh_in));
                binding.expires = Some(after(now, CHANNEL_LIFETIME));
                if first {
                    tracing::debug!(server = %self.server, %peer, channel = channel.number(), "turn channel bound");
                    self.events.push_back(Event::Channel {
                        peer,
                        channel,
                        result: Ok(()),
                    });
                }
            }
            Err(err) => {
                tracing::warn!(server = %self.server, %peer, channel = channel.number(), error = %err, "turn channel binding failed");
                binding.failed = true;
                binding.refresh_at = None;
                self.events.push_back(Event::Channel {
                    peer,
                    channel,
                    result: Err(err),
                });
            }
        }
    }

    /// Sends what is due while the allocation exists: its Refresh, and the
    /// permissions and bindings not installed yet or due for a refresh.
    fn reconcile(&mut self, now: Instant) {
        let State::Allocated {
            relayed,
            expires,
            refresh_at,
            refreshing,
        } = &mut self.state
        else {
            return;
        };
        let refreshes = Purpose::Refresh {
            relayed: *relayed,
            expires: *expires,
        };
        let refresh = !*refreshing && *refresh_at <= now;
        if refresh {
            *refreshing = true;
        }
        let due = |refresh_at: Option<Instant>, in_flight: bool, failed: bool| {
            !in_flight && !failed && refresh_at.is_none_or(|at| at <= now)
        };
        let mut purposes = Vec::new();
        for (peer, permission) in &mut self.permissions {
            if due(
                permission.refresh_at,
                permission.in_flight,
                permission.failed,
            ) {
                permission.in_flight = true;
                purposes.push(Purpose::Permission(*peer));
            }
        }
        for (peer, binding) in &mut self.channels {
            if due(binding.refresh_at, binding.in_flight, binding.failed) {
                binding.in_flight = true;
                purposes.push(Purpose::Channel(binding.channel, *peer));
            }
        }
        if refresh {
            purposes.push(refreshes);
        }
        for purpose in purposes {
            self.start(now, purpose, 0);
        }
    }

    /// Deletes the allocation after its last session (RFC 8656 §8.1).
    fn delete(&mut self, now: Instant) {
        tracing::info!(server = %self.server, transport = self.transport.name(), "turn allocation deleted after its last session");
        self.transactions.clear();
        self.permissions.clear();
        self.channels.clear();
        self.state = State::Deleting;
        self.start(now, Purpose::Delete, 0);
    }

    /// The allocation is over.
    fn close(&mut self, error: Option<AllocationError>) {
        if let Some(err) = &error {
            tracing::warn!(server = %self.server, transport = self.transport.name(), error = %err, "turn allocation failed");
        }
        self.transactions.clear();
        self.permissions.clear();
        self.channels.clear();
        self.state = State::Closed;
        self.events.push_back(Event::Closed { error });
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::sync::Arc;

    use lotse_core::clock::{Clock as _, FakeClock};
    use lotse_core::secret::Secret;
    use lotse_testing::fake_turn::{
        ALLOCATE, CHANNEL_BIND, CREATE_PERMISSION, FakeTurn, Logged, REFRESH,
    };

    use super::super::credential::{Key, PasswordAlgorithm};
    use super::super::stun::{ATTR_ERROR_CODE, ATTR_MESSAGE_INTEGRITY, ATTR_REALM, Builder};
    use super::*;

    const REALM: &str = "lotse.test";
    const SECOND: Duration = Duration::from_secs(1);

    fn creds(user: &str) -> Credentials {
        Credentials {
            username: user.to_owned(),
            password: Secret::new(format!("{user}-pw")),
        }
    }

    fn server_addr() -> SocketAddr {
        "192.0.2.1:3478".parse().unwrap()
    }

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::new("192.0.2.50".parse().unwrap(), port)
    }

    fn channel(number: u16) -> Channel {
        Channel::new(number).unwrap()
    }

    /// The state machine wired to the fake server, without sockets.
    struct Rig {
        clock: Arc<FakeClock>,
        server: FakeTurn,
        client: SocketAddr,
        transport: Transport,
        machine: Allocation,
        lease: LeaseId,
        events: Vec<Event>,
        sent: Vec<(Instant, Transmit)>,
    }

    impl Rig {
        fn new(transport: Transport) -> Self {
            Self::with_lifetime(transport, Duration::from_secs(600))
        }

        fn with_lifetime(transport: Transport, lifetime: Duration) -> Self {
            let clock = Arc::new(FakeClock::default());
            let server = FakeTurn::new(clock.clone(), REALM, lifetime);
            server.add_user("alice", "alice-pw");
            server.add_user("bob", "bob-pw");
            let mut machine = Allocation::new(
                server_addr(),
                transport,
                creds("alice"),
                AllocationConfig::default(),
                [7; 32],
                clock.now(),
            );
            let lease = machine.add_session(&creds("alice")).unwrap();
            Self {
                clock,
                server,
                client: "198.51.100.7:18556".parse().unwrap(),
                transport,
                machine,
                lease,
                events: Vec::new(),
                sent: Vec::new(),
            }
        }

        fn now(&self) -> Instant {
            self.clock.now()
        }

        /// A restart: a new machine for `user` on the same 5-tuple.
        fn restart(&mut self, user: &str) {
            self.machine = Allocation::new(
                server_addr(),
                self.transport,
                creds(user),
                AllocationConfig::default(),
                [8; 32],
                self.now(),
            );
            self.lease = self.machine.add_session(&creds(user)).unwrap();
        }

        /// One transmission, as sent.
        fn next(&mut self) -> Transmit {
            let transmit = self.machine.poll_transmit().unwrap();
            self.sent.push((self.now(), transmit.clone()));
            transmit
        }

        /// One transmission through the fake server and its answer back.
        fn step(&mut self) {
            let transmit = self.next();
            let tcp = self.transport == Transport::Tcp;
            if let Some(answer) = self.server.handle(self.client, tcp, &transmit.bytes) {
                assert!(self.machine.handle_input(self.now(), &answer));
            }
        }

        /// Every transmission through the server until quiet.
        fn pump(&mut self) {
            let mut sent = 0;
            while !self.machine.outbox.is_empty() {
                sent += 1;
                assert!(sent < 20_000, "the machine never stops sending");
                self.step();
            }
            self.collect();
        }

        fn collect(&mut self) {
            while let Some(event) = self.machine.poll_event() {
                self.events.push(event);
            }
        }

        fn advance(&mut self, by: Duration) {
            self.clock.advance(by);
            self.machine.handle_timeout(self.now());
            self.pump();
        }

        /// Advances by `by`, waking at every deadline on the way.
        fn run_for(&mut self, by: Duration) {
            let until = self.now() + by;
            let mut wakes = 0;
            while let Some(at) = self.machine.poll_timeout().filter(|at| *at <= until) {
                wakes += 1;
                assert!(wakes < 1_000, "the deadline does not move");
                self.advance(at.saturating_duration_since(self.now()));
            }
            self.advance(until - self.now());
        }

        fn events(&mut self) -> Vec<Event> {
            self.collect();
            std::mem::take(&mut self.events)
        }

        fn log(&self) -> Vec<(u16, Option<String>, Option<u16>)> {
            self.server
                .requests()
                .into_iter()
                .map(
                    |Logged {
                         method,
                         username,
                         error,
                         ..
                     }| (method, username, error),
                )
                .collect()
        }

        fn allocated(&mut self) -> SocketAddr {
            self.pump();
            let relayed = self.machine.relayed().unwrap();
            assert_eq!(self.events(), [Event::Allocated { relayed }]);
            relayed
        }
    }

    /// A response signed as `user`.
    fn signed(user: &str, builder: Builder) -> Vec<u8> {
        let key = Key::derive(PasswordAlgorithm::Md5, user, REALM, &format!("{user}-pw"));
        builder.integrity(key.expose_secret()).build()
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "the server log's username of a signed request"
    )]
    fn ok(user: &str) -> Option<String> {
        Some(user.to_owned())
    }

    fn error_code(code: u16) -> [u8; 5] {
        [
            0,
            0,
            u8::try_from(code / 100).unwrap(),
            u8::try_from(code % 100).unwrap(),
            b'x',
        ]
    }

    fn rejected(code: u16, reason: &str) -> TransactionError {
        TransactionError::Rejected {
            code,
            reason: reason.to_owned(),
        }
    }

    #[test]
    fn rfc8489_9_2_5_the_first_allocate_is_challenged_then_signed() {
        let mut rig = Rig::new(Transport::Udp);
        let relayed = rig.allocated();
        assert_eq!(
            rig.log(),
            [(ALLOCATE, None, Some(401)), (ALLOCATE, ok("alice"), None)]
        );
        assert_eq!(rig.server.allocations()[0].relayed, relayed);
        assert_eq!(rig.machine.relayed(), Some(relayed));
        assert!(!rig.machine.is_closed());
        let ids: Vec<_> = rig.sent.iter().map(|(_, t)| t.transaction_id).collect();
        assert_ne!(ids[0], ids[1]);
        assert!(!rig.machine.is_pending(&ids[1]));
    }

    #[test]
    fn rfc8489_5_transaction_ids_are_keyed_by_the_seed() {
        let mut first = TransactionIds {
            seed: [1; 32],
            counter: 0,
        };
        let mut again = TransactionIds {
            seed: [1; 32],
            counter: 0,
        };
        let mut other = TransactionIds {
            seed: [2; 32],
            counter: 0,
        };
        let a = first.next();
        assert_eq!(a, again.next());
        assert_ne!(a, other.next());
        assert_ne!(a, first.next());
    }

    #[test]
    fn rfc8489_6_2_1_udp_retransmits_with_a_doubling_rto_then_waits_rm() {
        let mut rig = Rig::new(Transport::Udp);
        let start = rig.now();
        rig.server.drop_requests(usize::MAX);
        rig.pump();
        let mut wakes = 0;
        while let Some(at) = rig.machine.poll_timeout() {
            wakes += 1;
            assert!(wakes < 100, "the deadline does not move");
            rig.advance(at - rig.now());
        }
        let offsets: Vec<u128> = rig
            .sent
            .iter()
            .map(|(at, _)| (*at - start).as_millis())
            .collect();
        assert_eq!(offsets, [0, 500, 1_500, 3_500, 7_500, 15_500, 31_500]);
        assert!(rig.sent.iter().all(|(_, t)| t == &rig.sent[0].1));
        assert_eq!((rig.now() - start).as_millis(), 39_500);
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Allocate(TransactionError::Timeout))
            }]
        );
        assert!(rig.machine.is_closed());
        assert_eq!(rig.machine.poll_timeout(), None);
    }

    #[test]
    fn rfc8489_6_2_2_tcp_waits_ti_and_never_retransmits() {
        let mut rig = Rig::new(Transport::Tcp);
        let start = rig.now();
        rig.server.drop_requests(usize::MAX);
        rig.pump();
        assert_eq!(
            rig.machine.poll_timeout(),
            Some(start + Duration::from_millis(39_500))
        );
        rig.advance(Duration::from_millis(39_499));
        assert!(rig.events().is_empty());
        rig.advance(Duration::from_millis(1));
        assert_eq!(rig.sent.len(), 1);
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Allocate(TransactionError::Timeout))
            }]
        );
    }

    #[test]
    fn rfc8656_8_the_allocation_is_refreshed_a_minute_before_it_ends() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        let start = rig.now();
        assert_eq!(rig.machine.poll_timeout(), Some(start + 540 * SECOND));
        rig.advance(539 * SECOND);
        assert_eq!(rig.log().len(), 2);
        rig.advance(SECOND);
        assert_eq!(rig.log()[2], (REFRESH, ok("alice"), None));
        assert_eq!(rig.server.allocations()[0].refreshes, 1);
        assert_eq!(rig.machine.poll_timeout(), Some(rig.now() + 540 * SECOND));
        rig.advance(540 * SECOND);
        assert_eq!(rig.server.allocations()[0].refreshes, 2);
        assert!(rig.events().is_empty());
    }

    #[test]
    fn rfc8656_8_a_short_lifetime_is_refreshed_halfway() {
        let mut rig = Rig::with_lifetime(Transport::Udp, 60 * SECOND);
        rig.allocated();
        assert_eq!(rig.machine.poll_timeout(), Some(rig.now() + 30 * SECOND));
    }

    #[test]
    fn rfc8489_9_2_5_a_stale_nonce_is_answered_with_the_new_one() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.server.rotate_nonce();
        rig.advance(540 * SECOND);
        assert_eq!(
            rig.log()[2..],
            [
                (REFRESH, ok("alice"), Some(438)),
                (REFRESH, ok("alice"), None)
            ]
        );
        assert!(rig.events().is_empty());
    }

    #[test]
    fn rfc8489_9_2_5_a_server_that_keeps_challenging_fails_after_two_resigns() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.clock.advance(540 * SECOND);
        rig.machine.handle_timeout(rig.now());
        for _ in 0..3 {
            rig.server.rotate_nonce();
            rig.step();
        }
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Refresh(rejected(438, "")))
            }]
        );
        assert!(rig.machine.poll_transmit().is_none());
    }

    #[test]
    fn rfc8656_8_3_a_refused_refresh_re_creates_under_the_newest_credential_once_the_old_ends() {
        let mut rig = Rig::new(Transport::Udp);
        let start = rig.now();
        let first = rig.allocated();
        // Bob's session joins with a newer credential, which is not sent.
        let bob = rig.machine.add_session(&creds("bob")).unwrap();
        assert_ne!(bob, rig.lease);
        rig.machine.permit(rig.now(), bob, peer(1).ip()).unwrap();
        rig.pump();
        assert_eq!(rig.events().len(), 1);
        rig.server.expire_user("alice");
        rig.advance(540 * SECOND);
        let refused: Vec<_> = rig
            .log()
            .into_iter()
            .filter(|(method, ..)| *method == REFRESH)
            .collect();
        assert_eq!(refused, vec![(REFRESH, ok("alice"), Some(401)); 3]);
        assert_eq!(rig.events().last(), Some(&Event::Lost { relayed: first }));
        assert_eq!(rig.machine.relayed(), None);
        assert!(rig.machine.permissions.is_empty());
        // The old allocation holds the 5-tuple until it ends.
        assert_eq!(rig.machine.poll_timeout(), Some(start + 600 * SECOND));
        rig.advance(60 * SECOND);
        let second = rig.machine.relayed().unwrap();
        assert_eq!(rig.events(), [Event::Allocated { relayed: second }]);
        assert_ne!(first, second);
        let allocations = rig.server.allocations();
        assert_eq!(allocations.len(), 1);
        assert_eq!(allocations[0].username, "bob");
        assert_eq!(allocations[0].relayed, second);
    }

    #[test]
    fn rfc8656_8_3_a_refused_refresh_without_a_newer_credential_fails() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        // A session with the same credential brings nothing newer.
        rig.machine.add_session(&creds("alice")).unwrap();
        rig.server.expire_user("alice");
        rig.advance(540 * SECOND);
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Refresh(rejected(401, "")))
            }]
        );
    }

    #[test]
    fn rfc8656_8_3_a_refresh_answered_441_re_creates_too() {
        let mut rig = Rig::new(Transport::Udp);
        let first = rig.allocated();
        rig.machine.add_session(&creds("bob")).unwrap();
        rig.clock.advance(540 * SECOND);
        rig.machine.handle_timeout(rig.now());
        let refresh = rig.next();
        let answer = signed(
            "alice",
            Builder::new(Class::Error, METHOD_REFRESH_TEST, refresh.transaction_id)
                .attribute(ATTR_ERROR_CODE, &error_code(441)),
        );
        assert!(rig.machine.handle_input(rig.now(), &answer));
        assert_eq!(rig.events(), [Event::Lost { relayed: first }]);
    }

    const METHOD_REFRESH_TEST: u16 = turn::METHOD_REFRESH;

    #[test]
    fn rfc8656_8_3_a_437_to_a_refresh_re_creates_at_once() {
        let mut rig = Rig::new(Transport::Udp);
        let first = rig.allocated();
        rig.server.forget_allocations();
        rig.advance(540 * SECOND);
        let events = rig.events();
        assert_eq!(events[0], Event::Lost { relayed: first });
        assert!(matches!(events[1], Event::Allocated { relayed } if relayed != first));
        assert_eq!(rig.server.allocations()[0].username, "alice");
    }

    #[test]
    fn rfc8656_8_3_a_refresh_that_times_out_fails() {
        let mut rig = Rig::new(Transport::Tcp);
        rig.allocated();
        rig.server.drop_requests(1);
        rig.advance(540 * SECOND);
        rig.advance(Duration::from_millis(39_500));
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Refresh(TransactionError::Timeout))
            }]
        );
    }

    #[test]
    fn rfc8656_7_4_an_earlier_runs_allocation_is_deleted_then_replaced() {
        let mut rig = Rig::new(Transport::Udp);
        let first = rig.allocated();
        rig.restart("alice");
        let second = rig.allocated();
        assert_ne!(first, second);
        assert_eq!(
            rig.log()[2..],
            [
                (ALLOCATE, None, Some(401)),
                (ALLOCATE, ok("alice"), Some(437)),
                (REFRESH, ok("alice"), None),
                (ALLOCATE, ok("alice"), None),
            ]
        );
    }

    #[test]
    fn rfc8656_7_4_an_earlier_allocation_of_another_user_is_a_mismatch() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.restart("bob");
        rig.pump();
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Mismatch(rejected(
                    441,
                    "Wrong Credentials"
                )))
            }]
        );
    }

    #[test]
    fn rfc8656_7_4_a_second_437_after_clearing_fails() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.restart("alice");
        // Unsigned 401, signed 437, the clearing Refresh.
        for _ in 0..3 {
            rig.step();
        }
        let allocate = rig.next();
        let answer = signed(
            "alice",
            Builder::new(Class::Error, turn::METHOD_ALLOCATE, allocate.transaction_id)
                .attribute(ATTR_ERROR_CODE, &error_code(437)),
        );
        assert!(rig.machine.handle_input(rig.now(), &answer));
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Allocate(rejected(437, "x")))
            }]
        );
    }

    #[test]
    fn rfc8656_7_4_clearing_answered_437_means_it_was_gone_already() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.restart("alice");
        rig.step();
        rig.step();
        // The earlier allocation expires before the clearing Refresh lands.
        rig.server.forget_allocations();
        rig.pump();
        assert!(matches!(rig.events().as_slice(), [Event::Allocated { .. }]));
        assert_eq!(rig.log()[4], (REFRESH, ok("alice"), Some(437)));
    }

    /// The machine with its signed Allocate in hand, unanswered.
    fn signed_allocate(rig: &mut Rig) -> Transmit {
        rig.step();
        rig.next()
    }

    #[test]
    fn rfc8656_7_3_an_allocate_error_fails_the_allocation() {
        let mut rig = Rig::new(Transport::Udp);
        let allocate = signed_allocate(&mut rig);
        let answer = signed(
            "alice",
            Builder::new(Class::Error, turn::METHOD_ALLOCATE, allocate.transaction_id)
                .attribute(ATTR_ERROR_CODE, &error_code(486)),
        );
        assert!(rig.machine.handle_input(rig.now(), &answer));
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Allocate(rejected(486, "x")))
            }]
        );
    }

    #[test]
    fn rfc8489_14_8_an_error_without_a_code_is_code_zero() {
        let mut rig = Rig::new(Transport::Udp);
        let allocate = signed_allocate(&mut rig);
        let answer = signed(
            "alice",
            Builder::new(Class::Error, turn::METHOD_ALLOCATE, allocate.transaction_id),
        );
        assert!(rig.machine.handle_input(rig.now(), &answer));
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Allocate(rejected(0, "")))
            }]
        );
    }

    #[test]
    fn rfc8656_7_3_a_success_without_a_relayed_address_fails() {
        let mut rig = Rig::new(Transport::Udp);
        let allocate = signed_allocate(&mut rig);
        let answer = signed(
            "alice",
            Builder::new(
                Class::Success,
                turn::METHOD_ALLOCATE,
                allocate.transaction_id,
            ),
        );
        assert!(rig.machine.handle_input(rig.now(), &answer));
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::NoRelayedAddress)
            }]
        );
    }

    #[test]
    fn rfc8656_7_3_a_success_without_lifetime_assumes_ten_minutes() {
        let mut rig = Rig::new(Transport::Udp);
        let allocate = signed_allocate(&mut rig);
        let answer = signed(
            "alice",
            Builder::new(
                Class::Success,
                turn::METHOD_ALLOCATE,
                allocate.transaction_id,
            )
            .xor_address(turn::ATTR_XOR_RELAYED_ADDRESS, peer(9)),
        );
        assert!(rig.machine.handle_input(rig.now(), &answer));
        assert_eq!(rig.events(), [Event::Allocated { relayed: peer(9) }]);
        assert_eq!(rig.machine.poll_timeout(), Some(rig.now() + 540 * SECOND));
    }

    #[test]
    fn rfc8489_9_2_5_a_response_without_valid_integrity_is_ignored() {
        let mut rig = Rig::new(Transport::Udp);
        let allocate = signed_allocate(&mut rig);
        let forged = Builder::new(
            Class::Success,
            turn::METHOD_ALLOCATE,
            allocate.transaction_id,
        )
        .xor_address(turn::ATTR_XOR_RELAYED_ADDRESS, peer(9))
        .build();
        assert!(rig.machine.handle_input(rig.now(), &forged));
        let wrong_key = signed(
            "bob",
            Builder::new(
                Class::Success,
                turn::METHOD_ALLOCATE,
                allocate.transaction_id,
            )
            .xor_address(turn::ATTR_XOR_RELAYED_ADDRESS, peer(9)),
        );
        assert!(rig.machine.handle_input(rig.now(), &wrong_key));
        assert!(rig.machine.is_pending(&allocate.transaction_id));
        assert!(rig.events().is_empty());
        // The retransmission reaches the server.
        rig.advance(Duration::from_millis(500));
        assert!(
            matches!(rig.events().as_slice(), [Event::Allocated { relayed }] if *relayed != peer(9))
        );
    }

    #[test]
    fn what_is_not_a_response_to_an_outstanding_request_is_passed_on() {
        let mut rig = Rig::new(Transport::Udp);
        let allocate = rig.next();
        let now = rig.now();
        assert!(!rig.machine.handle_input(now, b"not stun"));
        let indication = Builder::new(
            Class::Indication,
            turn::METHOD_DATA,
            allocate.transaction_id,
        )
        .build();
        assert!(!rig.machine.handle_input(now, &indication));
        let request = Builder::new(
            Class::Request,
            turn::METHOD_ALLOCATE,
            allocate.transaction_id,
        )
        .build();
        assert!(!rig.machine.handle_input(now, &request));
        let unknown = Builder::new(Class::Success, turn::METHOD_ALLOCATE, [0; 12]).build();
        assert!(!rig.machine.handle_input(now, &unknown));
        assert!(rig.machine.is_pending(&allocate.transaction_id));
    }

    #[test]
    fn rfc8489_9_2_5_an_unanswerable_challenge_fails() {
        let mut rig = Rig::new(Transport::Udp);
        let allocate = rig.next();
        let challenge = Builder::new(Class::Error, turn::METHOD_ALLOCATE, allocate.transaction_id)
            .attribute(ATTR_ERROR_CODE, &error_code(401))
            .build();
        assert!(rig.machine.handle_input(rig.now(), &challenge));
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Allocate(TransactionError::Challenge(
                    ChallengeError::Realm
                )))
            }]
        );
    }

    #[test]
    fn rfc8489_9_2_a_server_without_authentication_is_used_unsigned() {
        let mut rig = Rig::new(Transport::Udp);
        let allocate = rig.next();
        let answer = Builder::new(
            Class::Success,
            turn::METHOD_ALLOCATE,
            allocate.transaction_id,
        )
        .xor_address(turn::ATTR_XOR_RELAYED_ADDRESS, peer(9))
        .attribute(turn::ATTR_LIFETIME, &600_u32.to_be_bytes())
        .build();
        assert!(rig.machine.handle_input(rig.now(), &answer));
        assert_eq!(rig.events(), [Event::Allocated { relayed: peer(9) }]);
        rig.clock.advance(540 * SECOND);
        rig.machine.handle_timeout(rig.now());
        let refresh = rig.next();
        let message = stun::parse(&refresh.bytes).unwrap();
        assert_eq!(message.method, turn::METHOD_REFRESH);
        assert_eq!(message.attribute(ATTR_MESSAGE_INTEGRITY), None);
        assert_eq!(message.attribute(ATTR_REALM), None);
    }

    #[test]
    fn rfc8656_9_permissions_are_installed_once_allocated_and_refreshed_within_five_minutes() {
        let mut rig = Rig::new(Transport::Udp);
        let ip = peer(1).ip();
        assert_eq!(rig.machine.permit(rig.now(), rig.lease, ip), Ok(false));
        rig.pump();
        let events = rig.events();
        assert!(matches!(events[0], Event::Allocated { .. }));
        assert_eq!(
            events[1..],
            [Event::Permission {
                peer: ip,
                result: Ok(())
            }]
        );
        assert_eq!(rig.server.allocations()[0].permissions, [ip]);
        assert_eq!(rig.machine.permit(rig.now(), rig.lease, ip), Ok(true));
        assert!(rig.machine.poll_transmit().is_none());
        assert_eq!(rig.machine.poll_timeout(), Some(rig.now() + 240 * SECOND));
        rig.advance(240 * SECOND);
        let permissions = rig
            .log()
            .iter()
            .filter(|(method, ..)| *method == CREATE_PERMISSION)
            .count();
        assert_eq!(permissions, 2);
        // A refresh says nothing new.
        assert!(rig.events().is_empty());
    }

    /// A channel is held by the sessions that bound it, not by every
    /// session of the allocation, so the TCP relay writes a session's
    /// frames only on its own channels.
    #[test]
    fn rfc8656_12_a_channel_is_held_by_the_sessions_that_bound_it() {
        let mut rig = Rig::new(Transport::Tcp);
        rig.allocated();
        let other = rig.machine.add_session(&creds("alice")).unwrap();
        assert!(rig.machine.has_session(rig.lease) && rig.machine.has_session(other));
        let (mine, _) = rig
            .machine
            .bind_channel(rig.now(), rig.lease, peer(1))
            .unwrap();
        let (theirs, _) = rig.machine.bind_channel(rig.now(), other, peer(2)).unwrap();
        assert_ne!(mine, theirs);
        assert!(rig.machine.holds_channel(rig.lease, mine));
        assert!(!rig.machine.holds_channel(rig.lease, theirs));
        assert!(rig.machine.holds_channel(other, theirs));
        // Shared once both bind the peer; released with the session.
        rig.machine.bind_channel(rig.now(), other, peer(1)).unwrap();
        assert!(rig.machine.holds_channel(other, mine));
        rig.machine.remove_session(rig.now(), other);
        assert!(!rig.machine.has_session(other));
        assert!(!rig.machine.holds_channel(other, mine));
        assert!(rig.machine.holds_channel(rig.lease, mine));
    }

    #[test]
    fn a_request_under_way_is_not_sent_twice() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        let other = rig.machine.add_session(&creds("alice")).unwrap();
        rig.machine
            .permit(rig.now(), rig.lease, peer(1).ip())
            .unwrap();
        rig.machine
            .bind_channel(rig.now(), rig.lease, peer(1))
            .unwrap();
        rig.machine.permit(rig.now(), other, peer(1).ip()).unwrap();
        rig.machine.bind_channel(rig.now(), other, peer(1)).unwrap();
        assert_eq!(rig.machine.outbox.len(), 2);
    }

    #[test]
    fn rfc8489_9_2_5_the_first_challenge_does_not_count_against_the_resigns() {
        let mut rig = Rig::new(Transport::Udp);
        // Unsigned, 401; signed, then two stale nonces; then allocated.
        rig.step();
        for _ in 0..2 {
            rig.server.rotate_nonce();
            rig.step();
        }
        rig.pump();
        assert!(matches!(rig.events().as_slice(), [Event::Allocated { .. }]));
        let errors: Vec<_> = rig.log().into_iter().map(|(.., error)| error).collect();
        assert_eq!(errors, [Some(401), Some(438), Some(438), None]);
    }

    #[test]
    fn a_refresh_under_way_sets_no_deadline_in_the_past() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.machine
            .permit(rig.now(), rig.lease, peer(1).ip())
            .unwrap();
        rig.machine
            .bind_channel(rig.now(), rig.lease, peer(2))
            .unwrap();
        rig.pump();
        rig.events();
        // The permission's refresh goes out at 240 s and is lost; the
        // channel's is due at 540 s.
        rig.server.drop_requests(1);
        rig.run_for(240 * SECOND);
        assert_eq!(rig.server.dropped(), 1);
        assert_eq!(
            rig.machine.poll_timeout(),
            Some(rig.now() + Duration::from_millis(500))
        );
        // The channel's and the allocation's refreshes at 540 s, lost too.
        rig.run_for(299 * SECOND);
        rig.server.drop_requests(2);
        rig.advance(SECOND);
        assert_eq!(rig.server.dropped(), 3);
        assert_eq!(
            rig.machine.poll_timeout(),
            Some(rig.now() + Duration::from_millis(500))
        );
        // Deleting forgets them: only the deleting Refresh is timed.
        let lease = rig.lease;
        rig.server.drop_requests(1);
        rig.machine.remove_session(rig.now(), lease);
        rig.pump();
        assert_eq!(
            rig.machine.poll_timeout(),
            Some(rig.now() + Duration::from_millis(500))
        );
    }

    #[test]
    fn rfc8656_10_3_a_failed_permission_is_reported_and_tried_again_on_request() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.server.forget_allocations();
        let ip = peer(1).ip();
        assert_eq!(rig.machine.permit(rig.now(), rig.lease, ip), Ok(false));
        rig.pump();
        let failed = Event::Permission {
            peer: ip,
            result: Err(rejected(437, "Allocation Mismatch")),
        };
        assert_eq!(rig.events(), std::slice::from_ref(&failed));
        // Not retried on its own.
        assert_eq!(rig.machine.poll_timeout(), Some(rig.now() + 540 * SECOND));
        rig.machine.handle_timeout(rig.now());
        assert!(rig.machine.poll_transmit().is_none());
        assert_eq!(rig.machine.permit(rig.now(), rig.lease, ip), Ok(false));
        rig.pump();
        assert_eq!(rig.events(), [failed]);
    }

    #[test]
    fn rfc8656_12_channels_are_bound_from_0x4000_and_refreshed_within_ten_minutes() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        let bound = rig.machine.bind_channel(rig.now(), rig.lease, peer(1));
        assert_eq!(bound, Ok((channel(0x4000), false)));
        rig.pump();
        assert_eq!(
            rig.events(),
            [
                Event::Permission {
                    peer: peer(1).ip(),
                    result: Ok(())
                },
                Event::Channel {
                    peer: peer(1),
                    channel: channel(0x4000),
                    result: Ok(())
                }
            ]
        );
        assert_eq!(rig.server.allocations()[0].channels, [(0x4000, peer(1))]);
        let again = rig.machine.bind_channel(rig.now(), rig.lease, peer(1));
        assert_eq!(again, Ok((channel(0x4000), true)));
        let bob = rig.machine.add_session(&creds("alice")).unwrap();
        let shared = rig.machine.bind_channel(rig.now(), bob, peer(1));
        assert_eq!(shared, Ok((channel(0x4000), true)));
        let next = rig.machine.bind_channel(rig.now(), bob, peer(2));
        assert_eq!(next, Ok((channel(0x4001), false)));
        rig.pump();
        rig.events();
        // Bob leaves; peer 1 stays bound for the first session, and the
        // permission they shared stays.
        rig.machine.remove_session(rig.now(), bob);
        assert_eq!(rig.machine.channels.len(), 1);
        assert_eq!(rig.machine.permissions.len(), 1);
        rig.advance(540 * SECOND);
        let binds = rig
            .log()
            .iter()
            .filter(|(method, ..)| *method == CHANNEL_BIND)
            .count();
        assert_eq!(binds, 3);
        assert!(rig.events().is_empty());
    }

    #[test]
    fn rfc8656_12_a_channel_goes_to_another_peer_only_five_minutes_after_its_binding_ended() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        let keeper = rig.machine.add_session(&creds("alice")).unwrap();
        for port in 0..4096 {
            let (bound, _) = rig
                .machine
                .bind_channel(rig.now(), rig.lease, peer(port))
                .unwrap();
            assert_eq!(bound.number(), 0x4000 + port);
        }
        rig.pump();
        assert_eq!(rig.server.allocations()[0].channels.len(), 4096);
        rig.events();
        let full = rig.machine.bind_channel(rig.now(), keeper, peer(5000));
        assert_eq!(full, Err(AllocationError::ChannelsExhausted));
        // Every binding is released; each ends 600 s after it was made.
        let lease = rig.lease;
        rig.machine.remove_session(rig.now(), lease);
        // Its own peer gets its number back at once.
        let back = rig.machine.bind_channel(rig.now(), keeper, peer(0));
        assert_eq!(back, Ok((channel(0x4000), false)));
        rig.pump();
        rig.events();
        rig.run_for(899 * SECOND);
        let early = rig.machine.bind_channel(rig.now(), keeper, peer(5000));
        assert_eq!(early, Err(AllocationError::ChannelsExhausted));
        rig.advance(SECOND);
        let reused = rig.machine.bind_channel(rig.now(), keeper, peer(5000));
        assert_eq!(reused, Ok((channel(0x4001), false)));
    }

    #[test]
    fn rfc8656_12_a_binding_released_before_it_was_made_waits_out_a_full_lifetime() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        let keeper = rig.machine.add_session(&creds("alice")).unwrap();
        for port in 0..4096 {
            rig.machine
                .bind_channel(rig.now(), keeper, peer(port))
                .unwrap();
        }
        rig.pump();
        rig.events();
        // The other session binds nothing new, only shares one, and leaves
        // with requests in flight.
        let lease = rig.lease;
        rig.machine
            .permit(rig.now(), lease, peer(9999).ip())
            .unwrap();
        rig.machine.remove_session(rig.now(), keeper);
        // The keeper's bindings and the permission's answers arrive for
        // nobody.
        rig.pump();
        assert!(
            rig.events()
                .iter()
                .all(|e| matches!(e, Event::Permission { .. }))
        );
        let early = rig.machine.bind_channel(rig.now(), lease, peer(5000));
        assert_eq!(early, Err(AllocationError::ChannelsExhausted));
    }

    #[test]
    fn responses_for_released_permissions_and_channels_are_dropped() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        let other = rig.machine.add_session(&creds("alice")).unwrap();
        rig.machine.bind_channel(rig.now(), other, peer(1)).unwrap();
        rig.machine.remove_session(rig.now(), other);
        rig.pump();
        assert!(rig.events().is_empty());
        // The number waits out a full lifetime since the binding was never
        // confirmed, but its peer gets it back.
        let again = rig.machine.bind_channel(rig.now(), rig.lease, peer(1));
        assert_eq!(again, Ok((channel(0x4000), false)));
    }

    #[test]
    fn rfc8656_12_6_the_relay_names_the_held_channels_and_permissions_while_allocated() {
        let mut rig = Rig::new(Transport::Udp);
        assert_eq!(rig.machine.relay(), None);
        let relayed = rig.allocated();
        let empty = Relay {
            relayed,
            channels: BTreeMap::new(),
            permissions: BTreeSet::new(),
        };
        assert_eq!(rig.machine.relay(), Some(empty));
        // A channel counts from its request: the server may use it as soon
        // as it bound it, before its answer is read.
        rig.machine
            .bind_channel(rig.now(), rig.lease, peer(1))
            .unwrap();
        let held = Relay {
            relayed,
            channels: [(channel(0x4000), peer(1))].into(),
            permissions: [peer(1).ip()].into(),
        };
        assert_eq!(rig.machine.relay().as_ref(), Some(&held));
        rig.pump();
        assert_eq!(rig.machine.relay().as_ref(), Some(&held));
        // What the server refused it relays nothing on.
        let forbidden: IpAddr = "192.0.2.51".parse().unwrap();
        rig.server.forbid(forbidden);
        rig.machine
            .bind_channel(rig.now(), rig.lease, SocketAddr::new(forbidden, 9))
            .unwrap();
        rig.pump();
        assert_eq!(rig.machine.channels.len(), 2);
        assert_eq!(rig.machine.permissions.len(), 2);
        assert_eq!(rig.machine.relay().as_ref(), Some(&held));
        // Gone with the allocation.
        rig.machine.remove_session(rig.now(), rig.lease);
        assert_eq!(rig.machine.relay(), None);
    }

    #[test]
    fn rfc8656_12_3_a_failed_binding_is_reported_and_tried_again_on_request() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.server.forget_allocations();
        rig.machine
            .bind_channel(rig.now(), rig.lease, peer(1))
            .unwrap();
        rig.pump();
        let failed = Event::Channel {
            peer: peer(1),
            channel: channel(0x4000),
            result: Err(rejected(437, "Allocation Mismatch")),
        };
        let events = rig.events();
        assert_eq!(events[1], failed);
        // Not retried on its own.
        rig.machine.handle_timeout(rig.now());
        assert!(rig.machine.poll_transmit().is_none());
        let again = rig.machine.bind_channel(rig.now(), rig.lease, peer(1));
        assert_eq!(again, Ok((channel(0x4000), false)));
        rig.pump();
        assert_eq!(rig.events()[1], failed);
    }

    #[test]
    fn rfc8656_8_1_the_last_session_deletes_the_allocation() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        let other = rig.machine.add_session(&creds("alice")).unwrap();
        let now = rig.now();
        rig.machine.remove_session(now, other);
        rig.machine.remove_session(now, other);
        assert!(rig.machine.poll_transmit().is_none());
        let lease = rig.lease;
        rig.machine.remove_session(now, lease);
        rig.pump();
        assert_eq!(rig.log()[2], (REFRESH, ok("alice"), None));
        assert!(rig.server.allocations().is_empty());
        assert_eq!(rig.events(), [Event::Closed { error: None }]);
        assert!(rig.machine.is_closed());
        assert_eq!(rig.machine.add_session(&creds("alice")), None);
        rig.machine.remove_session(now, lease);
        assert!(rig.events().is_empty());
    }

    #[test]
    fn a_delete_that_times_out_still_closes() {
        let mut rig = Rig::new(Transport::Tcp);
        rig.allocated();
        rig.server.drop_requests(1);
        let lease = rig.lease;
        rig.machine.remove_session(rig.now(), lease);
        rig.pump();
        assert_eq!(rig.machine.add_session(&creds("alice")), None);
        rig.advance(Duration::from_millis(39_500));
        assert_eq!(rig.events(), [Event::Closed { error: None }]);
    }

    #[test]
    fn the_last_session_leaving_during_the_allocate_deletes_it_once_made() {
        let mut rig = Rig::new(Transport::Udp);
        let lease = rig.lease;
        rig.machine.remove_session(rig.now(), lease);
        rig.pump();
        assert!(matches!(
            rig.events().as_slice(),
            [Event::Allocated { .. }, Event::Closed { error: None }]
        ));
        assert!(rig.server.allocations().is_empty());
    }

    #[test]
    fn a_session_joining_during_the_allocate_keeps_it() {
        let mut rig = Rig::new(Transport::Udp);
        let lease = rig.lease;
        rig.machine.remove_session(rig.now(), lease);
        rig.machine.add_session(&creds("alice")).unwrap();
        rig.pump();
        assert!(matches!(rig.events().as_slice(), [Event::Allocated { .. }]));
    }

    #[test]
    fn leaving_while_an_earlier_allocation_is_cleared_closes_after() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        rig.restart("alice");
        rig.step();
        rig.step();
        let lease = rig.lease;
        rig.machine.remove_session(rig.now(), lease);
        rig.pump();
        assert_eq!(rig.events(), [Event::Closed { error: None }]);
        assert_eq!(rig.log().last().unwrap().0, REFRESH);
    }

    #[test]
    fn leaving_while_waiting_to_re_create_closes() {
        let mut rig = Rig::new(Transport::Udp);
        rig.allocated();
        let bob = rig.machine.add_session(&creds("bob")).unwrap();
        rig.server.expire_user("alice");
        rig.advance(540 * SECOND);
        assert!(matches!(rig.events().as_slice(), [Event::Lost { .. }]));
        let lease = rig.lease;
        rig.machine.remove_session(rig.now(), lease);
        rig.machine.remove_session(rig.now(), bob);
        assert_eq!(rig.events(), [Event::Closed { error: None }]);
        assert_eq!(rig.machine.poll_timeout(), None);
    }

    #[test]
    fn permits_and_channels_need_a_lease() {
        let mut rig = Rig::new(Transport::Udp);
        let stranger = LeaseId(99);
        assert_eq!(
            rig.machine.permit(rig.now(), stranger, peer(1).ip()),
            Err(AllocationError::UnknownLease)
        );
        assert_eq!(
            rig.machine.bind_channel(rig.now(), stranger, peer(1)),
            Err(AllocationError::UnknownLease)
        );
    }

    #[test]
    fn rfc8656_3_1_a_lost_connection_ends_the_allocation_once() {
        let mut rig = Rig::new(Transport::Tcp);
        rig.allocated();
        rig.machine.connection_lost();
        rig.machine.connection_lost();
        let lease = rig.lease;
        rig.machine.remove_session(rig.now(), lease);
        assert_eq!(
            rig.events(),
            [Event::Closed {
                error: Some(AllocationError::Connection)
            }]
        );
        assert!(rig.machine.poll_transmit().is_none());
    }

    #[test]
    fn transports_are_named_for_logs() {
        assert_eq!(Transport::Udp.name(), "udp");
        assert_eq!(Transport::Tcp.name(), "tcp");
    }
}
