//! The TURN client: the supervisor's allocations, one per (server,
//! transport) and shared by every session that names the server, each run
//! by a task that drives its [`Allocation`] state machine over the shared
//! UDP socket (responses come back through the demux by transaction id) or
//! over a TCP connection of its own.
//!
//! A TCP allocation is also one per generation of host addresses
//! (`host_cache`): an allocation is bound to its 5-tuple (RFC 8656 §5),
//! and a connection made before the host addresses changed keeps the
//! source address it was made from, so a session on the new ones leases
//! from an allocation connected after the change. One of an older
//! generation keeps serving the leases it has and is deleted with its
//! last, as any. A UDP allocation stays one per server across
//! generations: its 5-tuple is the shared socket's, which a second
//! allocation could not have (§5; the server answers 437 and the old one
//! would be cleared, §7.4). A change may have moved the socket's source
//! address, and with it the 5-tuple, so the first lease of a newer
//! generation waits for a Refresh sent at once (§8): its success confirms
//! the allocation on the new 5-tuple, and a 437 means the server knows
//! none there, so the allocation is re-created (§8.3) and the lease gets
//! the new one ([`Allocation::confirm`]). Leases of the confirmed
//! generation or an older one are granted at once.
//!
//! A session asks with [`TurnClient::lease`] and gets a [`Lease`]: the
//! relayed address, permissions and channel bindings, and a watch on the
//! address (gone when the server ended the allocation). Dropping the lease
//! releases what it held; the last one deletes the allocation. The task
//! hands over the lease itself, so one granted to a session that stopped
//! waiting is released as it is dropped unread, wherever it was. A later
//! session's credential for the same server is remembered as the newest,
//! for a re-creation after a rejected Refresh.
//!
//! A UDP allocation's task publishes what its server may relay (the
//! relayed address, the channels and permissions held) to the demux
//! whenever that changes, and withdraws it when the allocation ends, so
//! the demux unwraps what the server relays as the peers' datagrams.
//!
//! A TCP allocation's task owns its connection both ways. What the server
//! relays on it, `ChannelData` on a channel the allocation holds or a Data
//! indication from a peer with a permission, it unwraps and routes as the
//! peer's datagram at the relayed address, as the demux does for UDP
//! ([`Peers`]). What sessions send from its relay candidates arrives
//! framed by their workers ([`uplink`]), and the task writes a frame to
//! the stream only when it is one whole padded `ChannelData` message on a
//! channel a lease of the sending worker holds, so a worker cannot put the
//! stream out of step nor write on another session's channel. A worker is
//! known by the [`RelayOwner`] its uplink stamps on every frame; a lease
//! is granted to it ([`LeaseGrant`]) when its relay candidate goes to
//! that worker. The uplink finds the task by the server and the relayed
//! address the frame names, in an index each TCP allocation's task keeps
//! its entry of while it relays at that address (`Routes`).
//!
//! Implements RFC 8656 §5 (the 5-tuple: the shared socket, or one TCP
//! connection per allocation, §3.1), on TCP the stream framing of STUN
//! and `ChannelData` (RFC 8489 §6.2.2, RFC 8656 §12.5) and the unwrapping
//! of §11.4 and §12.6; the protocol itself is the state machine's.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lotse_core::clock::Clock;
use lotse_core::task::spawn_named;
use lotse_ipc::datagram;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpStream, UnixDatagram};
use tokio::sync::{mpsc, oneshot, watch};

use super::allocation::{
    Allocation, AllocationConfig, AllocationError, Event, LeaseId, Relay, TransactionError,
    Transmit, Transport,
};
use super::credential::Credentials;
use super::demux::{
    Demux, DemuxStats, Peers, RawReply, Registrations, Relayed, Relays, StunResponses, canonical,
    unwrap_relayed,
};
use super::stun_client::egress;
use super::turn::{self, Channel};

/// Responses queued for one allocation's task; a full queue drops, and
/// the request is sent again (RFC 8489 §6.2.1).
const INBOUND_QUEUE: usize = 32;

/// Frames queued for one TCP allocation's server; a full queue drops, as a
/// full socket buffer would.
const OUTBOUND_QUEUE: usize = 256;

/// How long the task sleeps when nothing is timed; the state machine
/// always has a deadline while it lives, so this only bounds a sleep.
const IDLE: Duration = Duration::from_secs(3600);

/// Why a lease, permission or channel was not had.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TurnError {
    /// The allocation failed or ended.
    #[error(transparent)]
    Allocation(#[from] AllocationError),
    /// The server refused the permission (RFC 8656 §10.3).
    #[error("permission: {0}")]
    Permission(TransactionError),
    /// The server refused the channel binding (RFC 8656 §12.3).
    #[error("channel binding: {0}")]
    Channel(TransactionError),
    /// The server ended the allocation the request was for.
    #[error("the turn allocation was lost")]
    Lost,
    /// The allocation's task is gone.
    #[error("the turn allocation is closed")]
    Closed,
    /// The allocation is being deleted; a new one follows.
    #[error("the turn allocation is being deleted")]
    Closing,
    /// No entropy for the transaction ids.
    #[error("transaction id entropy: {0}")]
    Entropy(getrandom::Error),
}

/// Where a joining session's lease goes. It travels as the [`Lease`]
/// itself, so one nobody reads is dropped with the channel and released,
/// whether the session stopped waiting before the grant or after it.
type LeaseReply = oneshot::Sender<Result<Lease, TurnError>>;

/// Where a channel's number goes once bound.
type ChannelReply = oneshot::Sender<Result<Channel, TurnError>>;

/// A worker as the TCP allocations know it: the uplink reading its
/// datagram channel stamps every frame with it, and the leases of its
/// sessions are granted to it, so its frames go out only on their
/// channels. Unique in the process: a restarted worker is a new owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayOwner(u64);

impl RelayOwner {
    /// An owner no other worker of this process has had.
    pub fn next() -> Self {
        /// The next owner's number.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// What a session sends from a relay candidate on a TCP allocation, as its
/// worker framed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// The worker it came from, as its uplink knows it.
    pub owner: RelayOwner,
    /// The relayed address it leaves from.
    pub relayed: SocketAddr,
    /// The `ChannelData` message, padded (RFC 8656 §12.5).
    pub frame: Vec<u8>,
}

/// What a lease or the client asks of an allocation's task.
#[derive(Debug)]
enum Command {
    /// A session joins.
    Add {
        /// Its credential for the server.
        credentials: Credentials,
        /// The generation of host addresses it is on
        /// ([`Allocation::confirm`]).
        generation: u64,
        /// Its lease and the relayed address, once allocated.
        reply: LeaseReply,
    },
    /// A session leaves.
    Remove {
        /// Its lease.
        lease: LeaseId,
    },
    /// A session's relay candidate went to the worker `owner`, which may
    /// now write on the lease's channels.
    Grant {
        /// Its lease.
        lease: LeaseId,
        /// The worker.
        owner: RelayOwner,
    },
    /// A session needs a permission.
    Permit {
        /// Its lease.
        lease: LeaseId,
        /// The peer IP.
        peer: IpAddr,
        /// Once installed.
        reply: oneshot::Sender<Result<(), TurnError>>,
    },
    /// A session needs a channel.
    Bind {
        /// Its lease.
        lease: LeaseId,
        /// The peer.
        peer: SocketAddr,
        /// The channel, once bound.
        reply: ChannelReply,
    },
}

/// The client's way to an allocation's task.
#[derive(Debug, Clone)]
struct Handle {
    /// Commands; closed once the task ended.
    commands: mpsc::UnboundedSender<Command>,
    /// What the server answered: [`Driver::answered`].
    answered: Arc<AtomicU64>,
}

/// The queues of the TCP allocations for what sessions send from their
/// relay candidates, by (server, relayed address), both canonical: one
/// lookup per frame. Each allocation's task keeps its own entry while it
/// relays at the address ([`Route`]); a relayed address is one
/// allocation's at a time on its server (RFC 8656 §7.2).
type Routes = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Outbound>>>>;

/// A TCP allocation's entry in the [`Routes`].
#[derive(Debug)]
struct Route {
    /// The index.
    routes: Routes,
    /// The allocation's queue.
    queue: mpsc::Sender<Outbound>,
    /// Where it is entered, while the allocation relays.
    at: Option<(SocketAddr, SocketAddr)>,
}

impl Route {
    /// Moves the entry to `relayed` on `server`, or removes it for `None`.
    /// An entry at the old address is removed only while it is still this
    /// allocation's: the server may have given the address to a new
    /// allocation (RFC 8656 §7.2) before this one's task learned it lost
    /// it, and the new one's entry stays.
    fn set(&mut self, server: SocketAddr, relayed: Option<SocketAddr>) {
        let at = relayed.map(|relayed| (server, canonical(relayed)));
        let mut routes = self.routes.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(old) = self.at.take()
            && routes
                .get(&old)
                .is_some_and(|queue| queue.same_channel(&self.queue))
        {
            routes.remove(&old);
        }
        if let Some(at) = at {
            routes.insert(at, self.queue.clone());
        }
        drop(routes);
        self.at = at;
    }
}

/// Which allocation a lease shares: the server, the transport, and for
/// TCP the generation of host addresses its connection was made on; UDP
/// allocations share the socket's 5-tuple across generations
/// ([module docs](self)).
type Key = (SocketAddr, Transport, Option<u64>);

/// The [`Key`] of a lease on `server` over `transport` by a session on
/// the host addresses of `generation`.
const fn key(server: SocketAddr, transport: Transport, generation: u64) -> Key {
    match transport {
        Transport::Udp => (server, transport, None),
        Transport::Tcp => (server, transport, Some(generation)),
    }
}

/// The allocations; see the module documentation.
#[derive(Debug)]
pub struct TurnClient {
    /// The shared socket, for UDP allocations.
    socket: Arc<UdpSocket>,
    /// Where the demux delivers responses.
    responses: Arc<StunResponses>,
    /// Where UDP allocations publish their relays for the demux.
    relays: Relays,
    /// The sessions, which TCP allocations route what they relay to.
    registrations: Arc<Registrations>,
    /// The demux's counters, which TCP allocations count in too.
    stats: Arc<DemuxStats>,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// The tunables.
    config: AllocationConfig,
    /// The tasks by [`Key`]; finished ones are pruned.
    allocations: Mutex<HashMap<Key, Handle>>,
    /// The TCP allocations' queues by relayed address.
    routes: Routes,
}

impl TurnClient {
    /// A client allocating on `socket` (UDP), whose `demux` delivers the
    /// responses and unwraps what the servers relay, or on connections of
    /// its own (TCP), routing what those relay to the demux's sessions.
    pub fn new(
        socket: Arc<UdpSocket>,
        demux: &Demux,
        clock: Arc<dyn Clock>,
        config: AllocationConfig,
    ) -> Self {
        Self {
            socket,
            responses: demux.responses(),
            relays: demux.relays(),
            registrations: demux.registrations(),
            stats: demux.stats(),
            clock,
            config,
            allocations: Mutex::new(HashMap::new()),
            routes: Arc::default(),
        }
    }

    /// The queue of the TCP allocation on `server` relaying at `relayed`
    /// for what sessions send from its relay candidates; `None` when there
    /// is none. Allocations of several generations may share the server
    /// ([module docs](self)); each relays at its own address.
    fn outbound(&self, server: SocketAddr, relayed: SocketAddr) -> Option<mpsc::Sender<Outbound>> {
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(canonical(server), canonical(relayed)))
            .cloned()
    }

    /// Whether the server of the allocation a session on the host
    /// addresses of `generation` leases on `server` over `transport` (the
    /// generation's own for TCP, the one shared for UDP) answered
    /// any of its requests, a 401 challenge included (RFC 8656 §7.2, RFC
    /// 8489 §9.2): proof that the path to it carries that transport.
    /// `false` while it has answered none, and when there is no such
    /// allocation. A lost allocation starts over (§8.3): `false` again
    /// until the server answers its re-creation. One being deleted (§8.1,
    /// LIFETIME 0) is `false` too, its deletion's answer included: a
    /// session joining then waits for a new allocation, which has answered
    /// nothing yet. One whose task ended (its TCP connection dropped, a
    /// Refresh timed out) is no allocation, though its handle stays until
    /// the next lease prunes it. An answer counts only for the generation
    /// its request was sent on and the older ones (RFC 8489 §6.2: a
    /// retransmission keeps its transaction's), as the 5-tuple of a newer
    /// one may differ (RFC 8656 §5): a UDP allocation, shared across
    /// generations, counts as answered for a session of a newer generation
    /// once the server answered a request sent after it joined, the Refresh
    /// that confirms the allocation on its 5-tuple (§8) or a later one, and
    /// late answers to requests sent before do not. For TCP the key fixes
    /// the generation, and the same rule holds.
    pub fn answered(&self, server: SocketAddr, transport: Transport, generation: u64) -> bool {
        self.allocations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key(canonical(server), transport, generation))
            .is_some_and(|handle| {
                !handle.commands.is_closed() && handle.answered.load(Ordering::Relaxed) > generation
            })
    }

    /// A lease on the allocation for `server` over `transport` of a
    /// session on the host addresses of `generation` (which a TCP
    /// allocation is bound to and a UDP one confirmed on, [module
    /// docs](self)), made with `credentials` if there is none yet; waits
    /// until it exists. One being deleted is waited out and a new one made.
    pub async fn lease(
        &self,
        server: SocketAddr,
        transport: Transport,
        generation: u64,
        credentials: &Credentials,
    ) -> Result<Lease, TurnError> {
        let key = key(canonical(server), transport, generation);
        match self.try_lease(key, generation, credentials).await {
            Err(TurnError::Closing) => self.try_lease(key, generation, credentials).await,
            other => other,
        }
    }

    /// One attempt of [`Self::lease`]; `Closing` once the old task ended,
    /// when it was deleting the allocation or ended before it read the
    /// request.
    async fn try_lease(
        &self,
        key: Key,
        generation: u64,
        credentials: &Credentials,
    ) -> Result<Lease, TurnError> {
        let handle = self.handle(key, generation, credentials)?;
        let (reply, answer) = oneshot::channel();
        // Fails only for a task that ended since; dropping the failed
        // command drops the reply, which the match below takes as such.
        drop(handle.commands.send(Command::Add {
            credentials: credentials.clone(),
            generation,
            reply,
        }));
        match answer.await {
            Ok(Ok(lease)) => Ok(lease),
            // Being deleted, or ended before it read the command.
            Ok(Err(TurnError::Closing)) | Err(_) => {
                handle.commands.closed().await;
                Err(TurnError::Closing)
            }
            Ok(Err(err)) => Err(err),
        }
    }

    /// The task for `key`, started with `credentials` on the host
    /// addresses of `generation` when there is none.
    fn handle(
        &self,
        key: Key,
        generation: u64,
        credentials: &Credentials,
    ) -> Result<Handle, TurnError> {
        let (server, transport, _) = key;
        let mut allocations = self
            .allocations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        allocations.retain(|_, handle| !handle.commands.is_closed());
        if let Some(handle) = allocations.get(&key) {
            return Ok(handle.clone());
        }
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).map_err(TurnError::Entropy)?;
        let machine = Allocation::new(
            server,
            transport,
            credentials.clone(),
            self.config,
            seed,
            self.clock.now(),
            generation,
        );
        let (mut driver, handle) = Driver::new(machine, server, Arc::clone(&self.clock));
        match transport {
            Transport::Udp => {
                let local = self.socket.local_addr().ok();
                let (queue, inbound) = mpsc::channel(INBOUND_QUEUE);
                let link = Link::Udp {
                    socket: Arc::clone(&self.socket),
                    to: egress(local, server),
                    responses: Arc::clone(&self.responses),
                    queue,
                    registered: HashSet::new(),
                    relays: self.relays.clone(),
                    published: None,
                };
                let _task = spawn_named("turn.allocation", driver.run(link, inbound));
            }
            Transport::Tcp => {
                let (queue, frames) = mpsc::channel(OUTBOUND_QUEUE);
                driver.route = Some(Route {
                    routes: Arc::clone(&self.routes),
                    queue,
                    at: None,
                });
                let peers = Peers::new(
                    Arc::clone(&self.registrations),
                    Arc::clone(&self.stats),
                    Arc::clone(&self.clock),
                );
                let timeout = self.config.reliable_timeout;
                let _task = spawn_named("turn.allocation", driver.run_tcp(timeout, peers, frames));
            }
        }
        allocations.insert(key, handle.clone());
        drop(allocations);
        Ok(handle)
    }
}

/// A session's hold on a shared allocation; dropping it releases its
/// permissions and channels, and the last one deletes the allocation.
#[derive(Debug)]
pub struct Lease {
    /// Its id in the allocation.
    id: LeaseId,
    /// The relayed address it was granted.
    relayed: SocketAddr,
    /// The allocation's task.
    commands: mpsc::UnboundedSender<Command>,
    /// The allocation's current relayed address.
    status: watch::Receiver<Option<SocketAddr>>,
}

impl Lease {
    /// The relayed transport address, the relay candidate's (RFC 8656
    /// §7.3).
    pub const fn relayed(&self) -> SocketAddr {
        self.relayed
    }

    /// The allocation's relayed address as it changes: `None` once the
    /// server ended it or it closed, a new address after a re-creation,
    /// which this lease does not move to.
    pub fn status(&self) -> watch::Receiver<Option<SocketAddr>> {
        self.status.clone()
    }

    /// A permission for `peer` (RFC 8656 §9), refreshed while the lease
    /// holds it; returns once installed.
    pub async fn permit(&self, peer: IpAddr) -> Result<(), TurnError> {
        let (reply, answer) = oneshot::channel();
        // A task that ended drops the command, and the reply with it.
        drop(self.commands.send(Command::Permit {
            lease: self.id,
            peer,
            reply,
        }));
        answer.await.unwrap_or(Err(TurnError::Closed))
    }

    /// What grants this lease's channels to the worker its relay candidate
    /// goes to.
    pub fn grant(&self) -> LeaseGrant {
        LeaseGrant {
            id: self.id,
            commands: self.commands.clone(),
        }
    }

    /// A channel to `peer` with its permission (RFC 8656 §12), refreshed
    /// while the lease holds it; returns its number once bound.
    pub async fn bind_channel(&self, peer: SocketAddr) -> Result<Channel, TurnError> {
        let (reply, answer) = oneshot::channel();
        // A task that ended drops the command, and the reply with it.
        drop(self.commands.send(Command::Bind {
            lease: self.id,
            peer,
            reply,
        }));
        answer.await.unwrap_or(Err(TurnError::Closed))
    }
}

/// Grants a lease's channels on a TCP allocation to one worker
/// ([`Lease::grant`]); holds nothing, so it may outlive the lease, and a
/// grant for a lease that is gone is ignored.
#[derive(Debug, Clone)]
pub struct LeaseGrant {
    /// The lease.
    id: LeaseId,
    /// The allocation's task.
    commands: mpsc::UnboundedSender<Command>,
}

impl LeaseGrant {
    /// Lets the worker `owner` write on the lease's channels, from the
    /// next frame the allocation's task reads on.
    pub fn to(&self, owner: RelayOwner) {
        // A task that ended has nothing left to grant.
        drop(self.commands.send(Command::Grant {
            lease: self.id,
            owner,
        }));
    }
}

#[cfg(test)]
impl Lease {
    /// A lease at `relayed` on no allocation: every request on it fails
    /// with [`TurnError::Closed`], for tests of what sessions keep.
    pub(crate) fn detached(relayed: SocketAddr) -> Self {
        let (commands, _gone) = mpsc::unbounded_channel();
        let (_gone, status) = watch::channel(None);
        Self {
            id: LeaseId::detached(),
            relayed,
            commands,
            status,
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // A task that ended has nothing left to release.
        drop(self.commands.send(Command::Remove { lease: self.id }));
    }
}

/// The sending half of a byte stream to the server.
type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// How an allocation reaches its server.
enum Link {
    /// The shared UDP socket.
    Udp {
        /// The socket.
        socket: Arc<UdpSocket>,
        /// The server as the socket addresses it.
        to: SocketAddr,
        /// Where the demux delivers responses by transaction id.
        responses: Arc<StunResponses>,
        /// This allocation's queue, which the demux delivers to.
        queue: mpsc::Sender<RawReply>,
        /// Transaction ids registered with the demux.
        registered: HashSet<[u8; 12]>,
        /// Where the demux learns what the server relays.
        relays: Relays,
        /// What it was told last.
        published: Option<Relay>,
    },
    /// A byte stream: a TCP connection, or a test's.
    Stream {
        /// The sending half.
        writer: Writer,
        /// Where what the server relays goes.
        peers: Peers,
        /// What the server may relay now.
        published: Option<Relay>,
        /// What sessions send from the relay candidates.
        frames: mpsc::Receiver<Outbound>,
    },
}

impl Link {
    /// Sends one message; on UDP its response is expected from the demux,
    /// and a failed send is left to the retransmission.
    async fn send(&mut self, transmit: Transmit) -> io::Result<()> {
        match self {
            Self::Udp {
                socket,
                to,
                responses,
                queue,
                registered,
                ..
            } => {
                responses.expect_raw(transmit.transaction_id, queue.clone());
                registered.insert(transmit.transaction_id);
                if let Err(err) = socket.send_to(&transmit.bytes, *to) {
                    tracing::debug!(server = %to, error = %err, "sending to the turn server failed");
                }
                Ok(())
            }
            Self::Stream { writer, .. } => writer.write_all(&transmit.bytes).await,
        }
    }

    /// The next frame a session sends from a relay candidate, with the
    /// stream to write it to and what the server may relay now; never on
    /// UDP, where workers send to the server themselves, and `None` once
    /// the queue closed.
    async fn outbound(&mut self) -> Option<(Outbound, &mut Writer, Option<&Relay>)> {
        match self {
            Self::Udp { .. } => std::future::pending().await,
            Self::Stream {
                frames,
                writer,
                published,
                ..
            } => {
                let outbound = frames.recv().await?;
                Some((outbound, writer, published.as_ref()))
            }
        }
    }

    /// Forgets the demux registrations of transactions `machine` no
    /// longer waits for.
    fn prune(&mut self, machine: &Allocation) {
        if let Self::Udp {
            responses,
            registered,
            ..
        } = self
        {
            registered.retain(|id| {
                let pending = machine.is_pending(id);
                if !pending {
                    responses.forget(id);
                }
                pending
            });
        }
    }

    /// Keeps what `server` may relay to `machine` when that changed,
    /// nothing once the allocation is over; on UDP the demux, which reads
    /// the server's datagrams, is told.
    fn publish(&mut self, server: SocketAddr, machine: &Allocation) {
        let relay = machine.relay();
        match self {
            Self::Udp {
                relays, published, ..
            } => {
                if relay != *published {
                    relays.publish(server, relay.clone());
                    *published = relay;
                }
            }
            Self::Stream { published, .. } => *published = relay,
        }
    }
}

/// One allocation's task.
#[derive(Debug)]
struct Driver {
    /// The state machine.
    machine: Allocation,
    /// The server, in canonical form.
    server: SocketAddr,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// Commands from the client and the leases.
    commands: mpsc::UnboundedReceiver<Command>,
    /// Keeps `commands` open, so it only ends with the task; each lease
    /// granted gets a clone.
    sender: mpsc::UnboundedSender<Command>,
    /// The relayed address, published.
    status: watch::Sender<Option<SocketAddr>>,
    /// One more than the newest generation of host addresses a request
    /// the server answered was sent on ([`Allocation::handle_input`]),
    /// saturating; 0 while it answered none, and reset to 0 when the
    /// allocation is lost and once it is being deleted
    /// ([`TurnClient::answered`]: answered for a generation below it).
    answered: Arc<AtomicU64>,
    /// A TCP allocation's entry in the client's index; `None` on UDP.
    route: Option<Route>,
    /// Sessions waiting for the allocation, or for it to be confirmed on
    /// the generation of host addresses they are on.
    adds: Vec<(LeaseId, u64, LeaseReply)>,
    /// Sessions waiting for a permission.
    permits: Vec<(IpAddr, oneshot::Sender<Result<(), TurnError>>)>,
    /// Sessions waiting for a channel.
    binds: Vec<(SocketAddr, ChannelReply)>,
    /// Why the allocation failed, once it did.
    failure: Option<AllocationError>,
    /// The worker each lease is granted to; its frames go out only on
    /// the channels its leases hold.
    owners: HashMap<LeaseId, RelayOwner>,
}

impl Driver {
    /// The task for `machine` and the handle to it.
    fn new(machine: Allocation, server: SocketAddr, clock: Arc<dyn Clock>) -> (Self, Handle) {
        let (commands, receiver) = mpsc::unbounded_channel();
        let (status, _) = watch::channel(None);
        let answered = Arc::new(AtomicU64::new(0));
        let driver = Self {
            machine,
            server,
            clock,
            commands: receiver,
            sender: commands.clone(),
            status,
            answered: Arc::clone(&answered),
            route: None,
            adds: Vec::new(),
            permits: Vec::new(),
            binds: Vec::new(),
            failure: None,
            owners: HashMap::new(),
        };
        (driver, Handle { commands, answered })
    }

    /// Connects to the server, then runs over the connection, routing what
    /// it relays to `peers` and writing what sessions send on `frames`; a
    /// connection that fails or takes longer than `timeout` fails the
    /// allocation.
    async fn run_tcp(mut self, timeout: Duration, peers: Peers, frames: mpsc::Receiver<Outbound>) {
        let connected = tokio::select! {
            connected = TcpStream::connect(self.server) => connected,
            () = self.clock.sleep(timeout) => Err(io::ErrorKind::TimedOut.into()),
        };
        match connected {
            Ok(stream) => {
                let (reader, writer) = stream.into_split();
                self.run_stream(reader, writer, peers, frames).await;
            }
            Err(err) => {
                tracing::warn!(server = %self.server, error = %err, "connecting to the turn server failed");
                self.machine.connection_lost();
                self.dispatch();
                self.drain();
            }
        }
    }

    /// Runs over a byte stream to the server, read by a task of its own.
    async fn run_stream(
        self,
        reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
        peers: Peers,
        frames: mpsc::Receiver<Outbound>,
    ) {
        let (queue, inbound) = mpsc::channel(INBOUND_QUEUE);
        let reader = Box::new(reader);
        let _reader = spawn_named("turn.tcp_reader", read_stream(reader, self.server, queue));
        let link = Link::Stream {
            writer: Box::new(writer),
            peers,
            published: None,
            frames,
        };
        self.run(link, inbound).await;
    }

    /// Drives the machine until the allocation is over: commands, the
    /// server's messages and the timers.
    async fn run(mut self, mut link: Link, mut inbound: mpsc::Receiver<RawReply>) {
        loop {
            self.settle(&mut link).await;
            link.prune(&self.machine);
            if self.machine.is_closed() {
                break;
            }
            let now = self.clock.now();
            let wait = self
                .machine
                .poll_timeout()
                .map_or(IDLE, |at| at.saturating_duration_since(now));
            let sleep = self.clock.sleep(wait);
            tokio::select! {
                Some(command) = self.commands.recv() => self.command(command),
                reply = inbound.recv() => match reply {
                    Some(reply) => self.input(&mut link, &reply),
                    None => self.machine.connection_lost(),
                },
                Some((outbound, writer, published)) = link.outbound() => {
                    self.relay_out(writer, published, outbound).await;
                }
                () = sleep => self.machine.handle_timeout(self.clock.now()),
            }
        }
        link.prune(&self.machine);
        self.drain();
    }

    /// Answers what was asked before the allocation ended: a joining
    /// session gets its failure, or `Closing` after a deletion, so it makes
    /// a new one; later requests find the task gone.
    fn drain(&mut self) {
        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            self.command(command);
        }
    }

    /// Sends what the machine has and answers its events, until neither is
    /// left; a stream that fails to write ends the allocation. What the
    /// server may relay is published before a session hears of it and
    /// before each request goes out, so the demux knows a channel or
    /// permission before the server can use it.
    async fn settle(&mut self, link: &mut Link) {
        loop {
            link.publish(self.server, &self.machine);
            self.dispatch();
            let Some(transmit) = self.machine.poll_transmit() else {
                return;
            };
            if let Err(err) = link.send(transmit).await {
                tracing::warn!(server = %self.server, error = %err, "writing to the turn server failed");
                self.machine.connection_lost();
            }
        }
    }

    /// A message from the server: on UDP the demux hands over only
    /// responses; on TCP what the server relays from a peer is unwrapped
    /// and routed as the peer's datagram, or discarded (RFC 8656 §11.4,
    /// §12.6), and the rest is the server's own. A response to one of the
    /// allocation's requests marks the server as having answered
    /// ([`Self::track_answer`]).
    fn input(&mut self, link: &mut Link, reply: &RawReply) {
        if let Link::Stream {
            peers,
            published: Some(relay),
            ..
        } = link
        {
            match unwrap_relayed(relay, &reply.bytes) {
                Relayed::Peer { peer, data } => {
                    peers.relayed(data, peer, relay.relayed);
                    return;
                }
                Relayed::Discard(reason) => {
                    peers.discard(self.server, reason);
                    return;
                }
                Relayed::Server => {}
            }
        }
        if reply.from == self.server {
            let answer = self.machine.handle_input(self.clock.now(), &reply.bytes);
            self.track_answer(answer);
        }
    }

    /// Keeps [`TurnClient::answered`] in step with the machine after
    /// `answer`, the generation of host addresses of the request the
    /// server just answered, if it answered one: raised to that
    /// generation, never lowered by an older one's late answer (RFC 8656
    /// §5), and reset once the allocation is being deleted or over (§8.1),
    /// so neither the old allocation's answers nor its deletion's hold
    /// back the TCP twin of a session that waits for the next one.
    fn track_answer(&self, answer: Option<u64>) {
        if self.machine.is_ending() {
            self.answered.store(0, Ordering::Relaxed);
        } else if let Some(generation) = answer {
            self.answered
                .fetch_max(generation.saturating_add(1), Ordering::Relaxed);
        }
    }

    /// Writes what a session sends from the relay candidate to the server
    /// when it is one whole `ChannelData` message, padded (RFC 8656
    /// §12.5), from the relayed address, on a channel the server relays
    /// that a lease granted to the sending worker holds; anything else is
    /// dropped, so the stream stays in step and a worker writes on its own
    /// sessions' channels only. A write that fails ends the allocation.
    async fn relay_out(
        &mut self,
        writer: &mut Writer,
        published: Option<&Relay>,
        outbound: Outbound,
    ) {
        let held = published.is_some_and(|relay| {
            relay.relayed == canonical(outbound.relayed)
                && turn::stream_frame_len(&outbound.frame) == Ok(Some(outbound.frame.len()))
                && turn::parse_channel_data(&outbound.frame).is_ok_and(|message| {
                    relay.channels.contains_key(&message.channel)
                        && self.owns(outbound.owner, message.channel)
                })
        });
        if !held {
            tracing::trace!(server = %self.server, relayed = %outbound.relayed, len = outbound.frame.len(), "relayed frame not on a channel the worker holds; dropped");
            return;
        }
        if let Err(err) = writer.write_all(&outbound.frame).await {
            tracing::warn!(server = %self.server, error = %err, "writing to the turn server failed");
            self.machine.connection_lost();
        }
    }

    /// Whether a lease granted to `owner` holds `channel`.
    fn owns(&self, owner: RelayOwner, channel: Channel) -> bool {
        self.owners
            .iter()
            .any(|(lease, to)| *to == owner && self.machine.holds_channel(*lease, channel))
    }

    /// One command.
    fn command(&mut self, command: Command) {
        let now = self.clock.now();
        match command {
            Command::Add {
                credentials,
                generation,
                reply,
            } => match self.machine.add_session(&credentials) {
                None => {
                    let error = self
                        .failure
                        .clone()
                        .map_or(TurnError::Closing, TurnError::Allocation);
                    let _sent = reply.send(Err(error));
                }
                Some(lease) => {
                    self.adds.push((lease, generation, reply));
                    self.machine.confirm(now, generation);
                    self.grant_confirmed();
                }
            },
            Command::Remove { lease } => {
                self.owners.remove(&lease);
                self.machine.remove_session(now, lease);
                // The last session leaving starts the deletion.
                self.track_answer(None);
            }
            Command::Grant { lease, owner } => {
                if self.machine.has_session(lease) {
                    self.owners.insert(lease, owner);
                    tracing::debug!(server = %self.server, ?owner, "turn lease granted to its worker");
                }
            }
            Command::Permit { lease, peer, reply } => match self.machine.permit(now, lease, peer) {
                Ok(true) => {
                    let _sent = reply.send(Ok(()));
                }
                Ok(false) => self.permits.push((peer, reply)),
                Err(err) => {
                    let _sent = reply.send(Err(err.into()));
                }
            },
            Command::Bind { lease, peer, reply } => {
                match self.machine.bind_channel(now, lease, peer) {
                    Ok((channel, true)) => {
                        let _sent = reply.send(Ok(channel));
                    }
                    Ok((_, false)) => self.binds.push((peer, reply)),
                    Err(err) => {
                        let _sent = reply.send(Err(err.into()));
                    }
                }
            }
        }
    }

    /// Hands the waiting sessions their leases while the allocation exists
    /// and is confirmed on their generation of host addresses or a newer
    /// one ([`Allocation::confirmed`]); the others wait for the Refresh
    /// that confirms it or for the re-creation.
    fn grant_confirmed(&mut self) {
        let Some(relayed) = self.machine.relayed() else {
            return;
        };
        let confirmed = self.machine.confirmed();
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.adds)
            .into_iter()
            .partition(|(_, generation, _)| *generation <= confirmed);
        self.adds = waiting;
        for (lease, _, reply) in ready {
            self.grant(lease, relayed, reply);
        }
    }

    /// Publishes the relayed address, `None` while there is none, and
    /// keeps a TCP allocation's entry in the client's index with it.
    fn relay_at(&mut self, relayed: Option<SocketAddr>) {
        self.status.send_replace(relayed);
        if let Some(route) = &mut self.route {
            route.set(self.server, relayed);
        }
    }

    /// Hands a session its lease. When the session stopped waiting, the
    /// lease comes back here, or is dropped with the channel when it stops
    /// before reading it: either way [`Lease`]'s drop queues its release.
    fn grant(&self, lease: LeaseId, relayed: SocketAddr, reply: LeaseReply) {
        let lease = Lease {
            id: lease,
            relayed,
            commands: self.sender.clone(),
            status: self.status.subscribe(),
        };
        if reply.send(Ok(lease)).is_err() {
            tracing::debug!(server = %self.server, "turn lease no longer wanted; released");
        }
    }

    /// Answers the waiters the machine's events decide, then the
    /// sessions the allocation is confirmed for.
    fn dispatch(&mut self) {
        while let Some(event) = self.machine.poll_event() {
            match event {
                Event::Allocated { relayed } => self.relay_at(Some(relayed)),
                Event::Lost { .. } => {
                    // The re-creation's own answers count (§8.3), before
                    // anyone hears of the loss.
                    self.answered.store(0, Ordering::Relaxed);
                    self.relay_at(None);
                    self.fail_requests(&TurnError::Lost);
                }
                Event::Permission { peer, result } => {
                    let (answered, waiting) = std::mem::take(&mut self.permits)
                        .into_iter()
                        .partition(|(ip, _)| *ip == peer);
                    self.permits = waiting;
                    for (_, reply) in answered {
                        let _sent = reply.send(result.clone().map_err(TurnError::Permission));
                    }
                }
                Event::Channel {
                    peer,
                    channel,
                    result,
                } => {
                    // A peer keeps its channel while any session holds it.
                    let (answered, waiting) = std::mem::take(&mut self.binds)
                        .into_iter()
                        .partition(|(to, _)| *to == peer);
                    self.binds = waiting;
                    for (_, reply) in answered {
                        let _sent = reply
                            .send(result.clone().map(|()| channel).map_err(TurnError::Channel));
                    }
                }
                Event::Closed { error } => {
                    self.relay_at(None);
                    self.failure.clone_from(&error);
                    let error = error.map_or(TurnError::Closed, TurnError::Allocation);
                    for (_, _, reply) in std::mem::take(&mut self.adds) {
                        let _sent = reply.send(Err(error.clone()));
                    }
                    self.fail_requests(&TurnError::Closed);
                }
            }
        }
        self.grant_confirmed();
    }

    /// Fails every waiting permission and channel with `error`.
    fn fail_requests(&mut self, error: &TurnError) {
        for (_, reply) in std::mem::take(&mut self.permits) {
            let _sent = reply.send(Err(error.clone()));
        }
        for (_, reply) in std::mem::take(&mut self.binds) {
            let _sent = reply.send(Err(error.clone()));
        }
    }
}

/// Reads a worker's datagram channel, the supervisor's end, for what its
/// sessions send from relay candidates on TCP allocations: each frame
/// names the relayed address as its source and the server as its
/// destination, and goes on the queue of that server's TCP allocation
/// relaying at that address, stamped with the worker's `owner`, whose
/// task checks it before writing it. A frame for no such allocation,
/// one that does not decode, and one whose queue is full are dropped, as a
/// full socket buffer would; the reading ends with the channel.
pub async fn uplink(client: Arc<TurnClient>, datagrams: UnixDatagram, owner: RelayOwner) {
    let mut buf = vec![
        0;
        datagram::MAX_DATAGRAM_PAYLOAD
            .saturating_add(datagram::HEADER_LEN)
            .saturating_add(datagram::MAX_UFRAG_LEN)
            .saturating_add(1)
    ];
    loop {
        let len = match datagrams.recv(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(len) => len,
        };
        let Ok(frame) = datagram::decode(buf.get(..len).unwrap_or_default()) else {
            tracing::trace!(len, "malformed relay frame from a worker; dropped");
            continue;
        };
        let server = canonical(frame.destination);
        let Some(queue) = client.outbound(server, frame.source) else {
            tracing::trace!(%server, "relay frame for no tcp allocation; dropped");
            continue;
        };
        let outbound = Outbound {
            owner,
            relayed: frame.source,
            frame: frame.payload.to_vec(),
        };
        if queue.try_send(outbound).is_err() {
            tracing::trace!(%server, "tcp relay queue full or closed; frame dropped");
        }
    }
}

/// Splits the stream from the server into messages (STUN by its length,
/// RFC 8489 §6.2.2; `ChannelData` padded, RFC 8656 §12.5) and queues them
/// for the task; ends with the stream, on a message neither is (§12), or
/// with the task.
async fn read_stream(
    mut reader: Box<dyn AsyncRead + Send + Unpin>,
    server: SocketAddr,
    queue: mpsc::Sender<RawReply>,
) {
    let mut buffer = Vec::new();
    let mut chunk = vec![0; 4096];
    loop {
        loop {
            match turn::stream_frame_len(&buffer) {
                Ok(Some(len)) if buffer.len() >= len => {
                    let bytes = buffer.drain(..len).collect();
                    if queue
                        .send(RawReply {
                            from: server,
                            bytes,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(_) => break,
                Err(err) => {
                    tracing::warn!(%server, error = %err, "turn stream out of step; closing it");
                    return;
                }
            }
        }
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(chunk.get(..read).unwrap_or_default()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::unix::net::UnixDatagram as StdUnixDatagram;
    use std::pin::{Pin, pin};

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::secret::Secret;
    use lotse_testing::fake_turn::{FakeTurn, FakeTurnServer, REFRESH};

    use super::super::demux::test_support::MemorySink;
    use super::super::demux::{Demux, DemuxStats};
    use super::super::stun::{Builder, Class, METHOD_BINDING};
    use super::super::udp::bind_udp;
    use super::*;

    const REALM: &str = "lotse.test";

    fn creds(user: &str) -> Credentials {
        Credentials {
            username: user.to_owned(),
            password: Secret::new(format!("{user}-pw")),
        }
    }

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::new("192.0.2.50".parse().unwrap(), port)
    }

    fn channel(number: u16) -> Channel {
        Channel::new(number).unwrap()
    }

    struct Setup {
        clock: Arc<FakeClock>,
        server: FakeTurnServer,
        client: Arc<TurnClient>,
        socket: Arc<UdpSocket>,
        demux: Demux,
        local: SocketAddr,
    }

    impl Setup {
        async fn new() -> Self {
            Self::with(AllocationConfig::default()).await
        }

        async fn with(config: AllocationConfig) -> Self {
            Self::serving(config, 0).await
        }

        /// The first `relays` allocations relay on loopback sockets.
        async fn relaying(relays: usize) -> Self {
            Self::serving(AllocationConfig::default(), relays).await
        }

        async fn serving(config: AllocationConfig, relays: usize) -> Self {
            let clock = Arc::new(FakeClock::default());
            let turn = Arc::new(FakeTurn::new(
                clock.clone(),
                REALM,
                Duration::from_secs(600),
            ));
            turn.add_user("alice", "alice-pw");
            turn.add_user("bob", "bob-pw");
            let server = FakeTurnServer::start_relaying(turn, relays).await.unwrap();
            let bound = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
            let local = bound.local;
            let demux =
                Demux::start(Arc::clone(&bound.socket), local, vec![local], clock.clone()).unwrap();
            let client = Arc::new(TurnClient::new(
                Arc::clone(&bound.socket),
                &demux,
                clock.clone(),
                config,
            ));
            Self {
                clock,
                server,
                client,
                socket: bound.socket,
                demux,
                local,
            }
        }

        fn turn(&self) -> &FakeTurn {
            self.server.turn()
        }

        async fn lease(&self, transport: Transport, user: &str) -> Result<Lease, TurnError> {
            self.lease_on(transport, user, 0).await
        }

        /// A lease of a session on the host addresses of `generation`.
        async fn lease_on(
            &self,
            transport: Transport,
            user: &str,
            generation: u64,
        ) -> Result<Lease, TurnError> {
            let server = match transport {
                Transport::Udp => self.server.udp_addr(),
                Transport::Tcp => self.server.tcp_addr(),
            };
            self.client
                .lease(server, transport, generation, &creds(user))
                .await
        }

        /// A second client on the same socket: a restarted supervisor.
        fn restarted(&self) -> TurnClient {
            TurnClient::new(
                Arc::clone(&self.socket),
                &self.demux,
                self.clock.clone(),
                AllocationConfig::default(),
            )
        }

        /// Moves the fake clock until `future` completes.
        async fn drive<T>(&self, future: impl Future<Output = T>, step: Duration) -> T {
            let mut future = pin!(future);
            loop {
                tokio::select! {
                    done = &mut future => return done,
                    () = SystemClock.sleep(Duration::from_millis(5)) => self.clock.advance(step),
                }
            }
        }
    }

    /// Runs a test body on real time for at most 10 seconds, so a hang
    /// fails instead of stalling the suite.
    async fn bounded(test: impl Future<Output = ()>) {
        let finished = tokio::select! {
            () = test => true,
            () = SystemClock.sleep(Duration::from_secs(10)) => false,
        };
        assert!(finished, "the test hung");
    }

    /// Polls `done` on real time for up to five seconds.
    async fn eventually(mut done: impl FnMut() -> bool) {
        let mut tries = 0;
        while !done() {
            assert!(tries < 1_000, "condition not reached");
            tries += 1;
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
    }

    /// Waits until the server dropped `count` requests, while `pending`
    /// must not complete.
    async fn until_dropped<T>(
        turn: &FakeTurn,
        count: usize,
        pending: Pin<&mut impl Future<Output = T>>,
    ) {
        tokio::select! {
            _ = pending => panic!("answered without the dropped request"),
            () = eventually(|| turn.dropped() == count) => {}
        }
    }

    #[tokio::test]
    async fn rfc8656_5_udp_sessions_share_one_allocation_until_the_last_leaves() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let first = setup.lease(Transport::Udp, "alice").await.unwrap();
            let allocations = turn.allocations();
            assert_eq!(allocations.len(), 1);
            assert_eq!(allocations[0].client, setup.local);
            assert!(!allocations[0].tcp);
            assert_eq!(allocations[0].relayed, first.relayed());
            assert_eq!(*first.status().borrow(), Some(first.relayed()));
            // A forbidden peer next to an allowed one: each answer reaches
            // its own request.
            let forbidden: IpAddr = "192.0.2.51".parse().unwrap();
            turn.forbid(forbidden);
            let (one, two) = tokio::join!(first.permit(peer(1).ip()), first.permit(forbidden));
            let refused = TransactionError::Rejected {
                code: 403,
                reason: "Forbidden".to_owned(),
            };
            assert_eq!(
                (one, two),
                (Ok(()), Err(TurnError::Permission(refused.clone())))
            );
            let (bound, denied) = tokio::join!(
                first.bind_channel(peer(4)),
                first.bind_channel(SocketAddr::new(forbidden, 4))
            );
            assert_eq!(bound, Ok(channel(0x4000)));
            assert_eq!(denied, Err(TurnError::Channel(refused)));
            assert_eq!(first.permit(peer(1).ip()).await, Ok(()));
            assert_eq!(first.bind_channel(peer(1)).await, Ok(channel(0x4002)));
            assert_eq!(first.bind_channel(peer(1)).await, Ok(channel(0x4002)));
            let (a, b) = tokio::join!(first.bind_channel(peer(2)), first.bind_channel(peer(3)));
            assert_eq!((a, b), (Ok(channel(0x4003)), Ok(channel(0x4004))));
            let allocation = &turn.allocations()[0];
            assert_eq!(allocation.permissions, [peer(1).ip()]);
            assert_eq!(allocation.channels.len(), 4);
            // Bob's session shares it; his credential is not sent.
            let second = setup.lease(Transport::Udp, "bob").await.unwrap();
            assert_eq!(second.relayed(), first.relayed());
            drop(first);
            // Commands run in order: after this answer, the first lease is gone.
            assert_eq!(second.permit(peer(1).ip()).await, Ok(()));
            let allocations = turn.allocations();
            assert_eq!(allocations.len(), 1);
            assert_eq!(allocations[0].username, "alice");
            assert!(
                turn.requests()
                    .iter()
                    .all(|r| r.username.as_deref() != Some("bob"))
            );
            drop(second);
            eventually(|| turn.allocations().is_empty()).await;
            assert_eq!(turn.requests().last().unwrap().method, REFRESH);
        })
        .await;
    }

    /// A browser's connectivity check for the session `relay`.
    fn check(id: u8) -> Vec<u8> {
        Builder::new(Class::Request, METHOD_BINDING, [id; 12])
            .username("relay:browser")
            .integrity(b"relay-pw")
            .fingerprint()
            .build()
    }

    #[tokio::test]
    async fn rfc8656_11_4_and_12_6_what_the_server_relays_reaches_the_session_as_the_peers() {
        bounded(async {
            let setup = Setup::new().await;
            let sink = Arc::new(MemorySink::default());
            setup
                .demux
                .registrations()
                .register("relay", b"relay-pw".to_vec(), sink.clone());
            let stats = setup.demux.stats();
            let lease = setup.lease(Transport::Udp, "alice").await.unwrap();
            let relayed = lease.relayed();
            let browser = peer(7);
            let frames = || sink.frames.lock().unwrap().clone();
            // Without a permission the server relays nothing (RFC 8656 §9).
            assert!(
                !setup
                    .server
                    .relay_to_client(setup.local, browser, b"x")
                    .await
                    .unwrap()
            );
            // With one, a Data indication: the browser's check arrives
            // as its own, at the relayed address, and teaches its address.
            lease.permit(browser.ip()).await.unwrap();
            assert!(
                setup
                    .server
                    .relay_to_client(setup.local, browser, &check(1))
                    .await
                    .unwrap()
            );
            eventually(|| frames().len() == 1).await;
            assert_eq!(frames()[0], (browser, relayed, check(1)));
            assert_eq!(DemuxStats::get(&stats.addresses_learned), 1);
            // With a channel, ChannelData, read by its number.
            let channel = lease.bind_channel(browser).await.unwrap();
            assert_eq!(
                setup.turn().allocations()[0].channels,
                [(channel.number(), browser)]
            );
            let late = setup
                .turn()
                .relay_from_peer(setup.local, false, browser, b"late")
                .unwrap();
            assert_eq!(late.first(), Some(&0x40), "channeldata");
            assert!(
                setup
                    .server
                    .relay_to_client(setup.local, browser, b"media")
                    .await
                    .unwrap()
            );
            eventually(|| frames().len() == 2).await;
            assert_eq!(frames()[1], (browser, relayed, b"media".to_vec()));
            assert_eq!(DemuxStats::get(&stats.relayed), 2);
            // The last session leaves: the allocation and its relay are
            // gone, so what the server still sends is not unwrapped.
            drop(lease);
            eventually(|| setup.turn().allocations().is_empty()).await;
            let unroutable = DemuxStats::get(&stats.unroutable);
            setup.server.send_raw(setup.local, &late).await.unwrap();
            eventually(|| DemuxStats::get(&stats.unroutable) == unroutable + 1).await;
            assert_eq!(frames().len(), 2);
            assert_eq!(DemuxStats::get(&stats.relay_discarded), 0);
        })
        .await;
    }

    /// A worker's datagram channel, the supervisor's end read by
    /// [`uplink`] for `client` as `owner`'s, and the worker's end.
    fn worker_channel(
        client: &Arc<TurnClient>,
        owner: RelayOwner,
    ) -> (StdUnixDatagram, tokio::task::JoinHandle<()>) {
        let (ours, theirs) = datagram::datagram_pair().unwrap();
        let ours = StdUnixDatagram::from(ours);
        ours.set_nonblocking(true).unwrap();
        let task = spawn_named(
            "test.uplink",
            uplink(
                Arc::clone(client),
                UnixDatagram::from_std(ours).unwrap(),
                owner,
            ),
        );
        (StdUnixDatagram::from(theirs), task)
    }

    /// What a worker hands over for `server`: `payload` leaving `relayed`.
    fn uplink_frame(relayed: SocketAddr, server: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        datagram::encode("relay", relayed, server, payload, &mut frame);
        frame
    }

    /// One datagram on `socket` within five seconds.
    async fn received(socket: &tokio::net::UdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
        tokio::select! {
            got = socket.recv_from(buf) => got.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no datagram"),
        }
    }

    fn padded(channel: Channel, data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        turn::frame_channel_data(channel, data, true, &mut frame).unwrap();
        frame
    }

    #[tokio::test]
    async fn rfc8656_12_5_a_tcp_allocation_carries_what_is_relayed_both_ways() {
        bounded(async {
            let setup = Setup::relaying(1).await;
            let sink = Arc::new(MemorySink::default());
            setup
                .demux
                .registrations()
                .register("relay", b"relay-pw".to_vec(), sink.clone());
            let stats = setup.demux.stats();
            let lease = setup.lease(Transport::Tcp, "alice").await.unwrap();
            let relayed = lease.relayed();
            // Its relay candidate goes to a worker, before any channel is
            // bound (the commands are read in order).
            let owner = RelayOwner::next();
            lease.grant().to(owner);
            let browser = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = browser.local_addr().unwrap();
            let frames = || sink.frames.lock().unwrap().clone();
            // With a permission, a Data indication on the connection: the
            // browser's check arrives as its own, at the relayed address.
            lease.permit(peer.ip()).await.unwrap();
            browser.send_to(&check(1), relayed).await.unwrap();
            eventually(|| frames().len() == 1).await;
            assert_eq!(frames()[0], (peer, relayed, check(1)));
            assert_eq!(DemuxStats::get(&stats.addresses_learned), 1);
            // With a channel, ChannelData, padded on the stream.
            let bound = lease.bind_channel(peer).await.unwrap();
            browser.send_to(b"media", relayed).await.unwrap();
            eventually(|| frames().len() == 2).await;
            assert_eq!(frames()[1], (peer, relayed, b"media".to_vec()));
            assert_eq!(DemuxStats::get(&stats.relayed), 2);
            // ChannelData on a channel not held is discarded.
            let client = setup.server.tcp_clients()[0];
            assert!(
                setup
                    .server
                    .send_raw_tcp(client, &[0x4F, 0xFF, 0, 1, 9, 0, 0, 0])
            );
            eventually(|| DemuxStats::get(&stats.relay_discarded) == 1).await;
            // The other way: what the worker frames reaches the peer only
            // when it is whole, padded, on the channel, from the relayed
            // address, for a TCP allocation's server, and on a channel a
            // lease granted to that worker holds.
            let server = setup.server.tcp_addr();
            let (worker, task) = worker_channel(&setup.client, owner);
            // Another worker's session on the same allocation, with a
            // channel of its own to another peer, cannot write on the first
            // session's: that frame is dropped, its own goes out after it,
            // on the one queue.
            let other_browser = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let other_peer = other_browser.local_addr().unwrap();
            let other_lease = setup.lease(Transport::Tcp, "bob").await.unwrap();
            assert_eq!(other_lease.relayed(), relayed, "one shared allocation");
            let other_owner = RelayOwner::next();
            assert_ne!(other_owner, owner);
            other_lease.grant().to(other_owner);
            let other_bound = other_lease.bind_channel(other_peer).await.unwrap();
            assert_ne!(other_bound, bound);
            let (other_worker, other_task) = worker_channel(&setup.client, other_owner);
            for frame in [
                uplink_frame(relayed, server, &padded(bound, b"not yours")),
                uplink_frame(relayed, server, &padded(other_bound, b"bob")),
            ] {
                other_worker.send(&frame).unwrap();
            }
            let mut buf = [0_u8; 64];
            let (len, from) = received(&other_browser, &mut buf).await;
            assert_eq!((&buf[..len], from), (&b"bob"[..], relayed));
            let mut unpadded = Vec::new();
            turn::frame_channel_data(bound, b"abc", false, &mut unpadded).unwrap();
            let elsewhere: SocketAddr = "203.0.113.9:1".parse().unwrap();
            for frame in [
                uplink_frame(relayed, setup.server.udp_addr(), &padded(bound, b"udp")),
                vec![9],
                uplink_frame(relayed, server, &unpadded),
                uplink_frame(relayed, server, &padded(channel(0x4FFF), b"unbound")),
                uplink_frame(elsewhere, server, &padded(bound, b"elsewhere")),
                uplink_frame(relayed, server, &padded(other_bound, b"not yours either")),
                uplink_frame(relayed, server, &padded(bound, b"hello")),
                uplink_frame(relayed, server, &padded(bound, b"again")),
            ] {
                worker.send(&frame).unwrap();
            }
            for expected in [&b"hello"[..], b"again"] {
                let (len, from) = received(&browser, &mut buf).await;
                assert_eq!((&buf[..len], from), (expected, relayed));
            }
            // Once the connection is gone, frames for it are dropped.
            setup.server.disconnect_tcp();
            lease.status().wait_for(Option::is_none).await.unwrap();
            worker
                .send(&uplink_frame(relayed, server, &padded(bound, b"late")))
                .unwrap();
            // An empty message ends the reading, as the worker's end
            // closing does on SEQPACKET.
            worker.send(&[]).unwrap();
            task.await.unwrap();
            other_worker.send(&[]).unwrap();
            other_task.await.unwrap();
            let mut other_buf = [0_u8; 64];
            tokio::select! {
                _ = browser.recv_from(&mut buf) => panic!("a frame after the connection ended"),
                _ = other_browser.recv_from(&mut other_buf) => panic!("a frame on another worker's channel"),
                () = SystemClock.sleep(Duration::from_millis(50)) => {}
            }
        })
        .await;
    }

    #[test]
    fn rfc8656_7_2_a_lost_allocation_leaves_the_route_a_new_one_took_over() {
        let routes = Routes::default();
        let server: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let relayed: SocketAddr = "192.0.2.1:50000".parse().unwrap();
        let (old_queue, _old_frames) = mpsc::channel(1);
        let (new_queue, _new_frames) = mpsc::channel(1);
        let route = |queue| Route {
            routes: Arc::clone(&routes),
            queue,
            at: None,
        };
        let (mut old, mut new) = (route(old_queue), route(new_queue.clone()));
        old.set(server, Some(relayed));
        // The server gave the address to a new allocation before the old
        // one's task learned it lost it.
        new.set(server, Some(relayed));
        old.set(server, None);
        let entries = routes.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[&(server, relayed)].same_channel(&new_queue));
        drop(entries);
        // The new one's own removal still removes it.
        new.set(server, None);
        assert!(routes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rfc8656_5_a_tcp_lease_after_a_host_address_change_gets_an_allocation_of_its_own() {
        bounded(async {
            let setup = Setup::relaying(2).await;
            let turn = setup.turn();
            let old = setup.lease(Transport::Tcp, "alice").await.unwrap();
            // The host addresses changed: a session on the new ones leases
            // from a new connection, the old lease keeps its own.
            let new = setup.lease_on(Transport::Tcp, "bob", 1).await.unwrap();
            assert_ne!(new.relayed(), old.relayed());
            assert_eq!(turn.allocations().len(), 2);
            assert_eq!(setup.server.tcp_clients().len(), 2);
            // Another session on the new ones shares the new allocation.
            let shared = setup.lease_on(Transport::Tcp, "alice", 1).await.unwrap();
            assert_eq!(shared.relayed(), new.relayed());
            // UDP stays one allocation: its 5-tuple is the shared socket's.
            let udp = setup.lease(Transport::Udp, "alice").await.unwrap();
            let udp_after = setup.lease_on(Transport::Udp, "bob", 1).await.unwrap();
            assert_eq!(udp_after.relayed(), udp.relayed());
            assert_eq!(turn.allocations().len(), 3);
            // What each session's worker sends goes out on its own
            // allocation's connection, from its own relayed address.
            let browser = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = browser.local_addr().unwrap();
            let owner = RelayOwner::next();
            old.grant().to(owner);
            new.grant().to(owner);
            let (old_channel, new_channel) =
                tokio::join!(old.bind_channel(peer), new.bind_channel(peer));
            let (old_channel, new_channel) = (old_channel.unwrap(), new_channel.unwrap());
            let server = setup.server.tcp_addr();
            let (worker, task) = worker_channel(&setup.client, owner);
            let mut buf = [0_u8; 64];
            for (relayed, channel, payload) in [
                (old.relayed(), old_channel, &b"old"[..]),
                (new.relayed(), new_channel, b"new"),
            ] {
                worker
                    .send(&uplink_frame(relayed, server, &padded(channel, payload)))
                    .unwrap();
                let (len, from) = received(&browser, &mut buf).await;
                assert_eq!((&buf[..len], from), (payload, relayed));
            }
            worker.send(&[]).unwrap();
            task.await.unwrap();
            // The old allocation goes with its last lease, and its frames
            // with it; the new stays and keeps its own.
            let old_relayed = old.relayed();
            drop(old);
            eventually(|| setup.client.outbound(server, old_relayed).is_none()).await;
            let relayed: Vec<_> = turn.allocations().iter().map(|a| a.relayed).collect();
            assert_eq!(relayed.len(), 2);
            assert!(relayed.contains(&new.relayed()));
            assert!(!relayed.contains(&old_relayed));
            assert!(setup.client.outbound(server, new.relayed()).is_some());
            // Only the TCP allocation left is indexed; UDP's never is.
            assert_eq!(setup.client.routes.lock().unwrap().len(), 1);
            assert_eq!(new.permit(peer.ip()).await, Ok(()));
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_8_a_udp_lease_of_a_newer_generation_waits_for_a_refresh() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let refreshes = || {
                let requests = turn.requests();
                requests.iter().filter(|r| r.method == REFRESH).count()
            };
            let first = setup.lease(Transport::Udp, "alice").await.unwrap();
            // The same generation shares it at once.
            let same = setup.lease(Transport::Udp, "bob").await.unwrap();
            assert_eq!(same.relayed(), first.relayed());
            assert_eq!(refreshes(), 0);
            // A newer one gets it once a Refresh confirmed the 5-tuple.
            let newer = setup.lease_on(Transport::Udp, "bob", 1).await.unwrap();
            assert_eq!(newer.relayed(), first.relayed());
            assert_eq!(refreshes(), 1);
            assert_eq!(turn.allocations()[0].refreshes, 1);
            // Confirmed on it: neither that generation nor an older one
            // asks again.
            let again = setup.lease_on(Transport::Udp, "alice", 1).await.unwrap();
            let older = setup.lease(Transport::Udp, "alice").await.unwrap();
            assert_eq!(again.relayed(), first.relayed());
            assert_eq!(older.relayed(), first.relayed());
            assert_eq!(refreshes(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_8_3_a_newer_udp_lease_gets_the_allocation_re_created_after_a_437() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let old = setup.lease(Transport::Udp, "alice").await.unwrap();
            // The server holds no allocation on the 5-tuple any more, as
            // when the host addresses moved the socket's source address.
            turn.forget_allocations();
            let new = setup.lease_on(Transport::Udp, "alice", 1).await.unwrap();
            assert_ne!(new.relayed(), old.relayed());
            assert_eq!(turn.allocations()[0].relayed, new.relayed());
            assert_eq!(*old.status().borrow(), Some(new.relayed()));
            let requests = turn.requests();
            let refresh = requests.iter().find(|r| r.method == REFRESH).unwrap();
            assert_eq!(refresh.error, Some(437));
            // The new lease is on the re-created allocation.
            assert_eq!(new.permit(peer(1).ip()).await, Ok(()));
            assert_eq!(turn.allocations()[0].permissions, [peer(1).ip()]);
        })
        .await;
    }

    #[tokio::test]
    async fn a_frame_for_a_full_tcp_queue_is_dropped_and_the_uplink_reads_on() {
        bounded(async {
            let setup = Setup::new().await;
            let server = setup.server.tcp_addr();
            let relayed: SocketAddr = "203.0.113.1:49152".parse().unwrap();
            // An allocation relaying at `relayed` whose task reads nothing:
            // its queue holds one frame.
            let (outbound, mut queued) = mpsc::channel(1);
            setup
                .client
                .routes
                .lock()
                .unwrap()
                .insert((server, relayed), outbound);
            let owner = RelayOwner::next();
            let (worker, task) = worker_channel(&setup.client, owner);
            for payload in [&b"first"[..], b"second"] {
                worker
                    .send(&uplink_frame(relayed, server, payload))
                    .unwrap();
            }
            worker.send(&[]).unwrap();
            task.await.unwrap();
            let first = queued.recv().await.unwrap();
            assert_eq!((first.owner, first.relayed), (owner, relayed));
            assert_eq!(first.frame, b"first");
            assert!(queued.try_recv().is_err(), "the second was dropped");
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_3_1_tcp_allocations_live_on_their_own_connection() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let tcp = setup.lease(Transport::Tcp, "alice").await.unwrap();
            let udp = setup.lease(Transport::Udp, "alice").await.unwrap();
            assert_ne!(tcp.relayed(), udp.relayed());
            let allocations = turn.allocations();
            assert_eq!(allocations.len(), 2);
            assert!(
                allocations
                    .iter()
                    .any(|a| a.tcp && a.relayed == tcp.relayed())
            );
            assert_eq!(tcp.permit(peer(1).ip()).await, Ok(()));
            assert_eq!(tcp.bind_channel(peer(1)).await, Ok(channel(0x4000)));
            assert!(!turn.requests().iter().any(|r| r.tcp && r.method == REFRESH));
            setup.server.disconnect_tcp();
            let mut status = tcp.status();
            status.wait_for(Option::is_none).await.unwrap();
            assert_eq!(tcp.permit(peer(1).ip()).await, Err(TurnError::Closed));
            assert_eq!(tcp.bind_channel(peer(1)).await, Err(TurnError::Closed));
            // The UDP allocation is untouched; a new TCP lease connects again.
            assert_eq!(*udp.status().borrow(), Some(udp.relayed()));
            let again = setup.lease(Transport::Tcp, "alice").await.unwrap();
            assert_ne!(again.relayed(), tcp.relayed());
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_8_the_allocation_is_refreshed_on_the_injected_clock() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let _lease = setup.lease(Transport::Udp, "alice").await.unwrap();
            // A stale nonce on the way is answered with the new one.
            turn.rotate_nonce();
            setup.clock.advance(Duration::from_secs(540));
            eventually(|| turn.allocations()[0].refreshes == 1).await;
            let errors: Vec<_> = turn.requests().iter().map(|r| r.error).collect();
            assert_eq!(errors, [Some(401), None, Some(438), None]);
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8489_6_2_1_a_lost_request_is_sent_again_after_the_rto() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            turn.drop_requests(1);
            let mut lease = pin!(setup.lease(Transport::Udp, "alice"));
            until_dropped(turn, 1, lease.as_mut()).await;
            setup.clock.advance(Duration::from_millis(500));
            let lease = lease.await.unwrap();
            assert_eq!(turn.allocations()[0].relayed, lease.relayed());
        })
        .await;
    }

    #[tokio::test]
    async fn a_lease_nobody_waits_for_any_more_is_released() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            turn.drop_requests(1);
            {
                let mut lease = pin!(setup.lease(Transport::Udp, "alice"));
                until_dropped(turn, 1, lease.as_mut()).await;
            }
            setup.clock.advance(Duration::from_millis(500));
            eventually(|| {
                turn.requests().iter().any(|r| r.method == REFRESH) && turn.allocations().is_empty()
            })
            .await;
        })
        .await;
    }

    #[tokio::test]
    async fn a_lease_granted_but_never_read_is_released() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let alice = creds("alice");
            // A UDP attempt and its TCP twin, both granted before either
            // answer is read.
            let mut answers = Vec::new();
            for (server, transport) in [
                (setup.server.udp_addr(), Transport::Udp),
                (setup.server.tcp_addr(), Transport::Tcp),
            ] {
                let handle = setup
                    .client
                    .handle(key(canonical(server), transport, 0), 0, &alice)
                    .unwrap();
                let (reply, answer) = oneshot::channel();
                handle
                    .commands
                    .send(Command::Add {
                        credentials: alice.clone(),
                        generation: 0,
                        reply,
                    })
                    .unwrap();
                answers.push(answer);
            }
            eventually(|| answers.iter().all(|answer| !answer.is_empty())).await;
            assert_eq!(turn.allocations().len(), 2);
            let [udp, tcp] = <[_; 2]>::try_from(answers).unwrap();
            let kept = udp.await.unwrap().unwrap();
            // The loser's grant goes unread: its allocation is deleted.
            drop(tcp);
            eventually(|| turn.allocations().len() == 1).await;
            let allocations = turn.allocations();
            assert!(!allocations[0].tcp);
            assert_eq!(allocations[0].relayed, kept.relayed());
            assert!(turn.requests().iter().any(|r| r.tcp && r.method == REFRESH));
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_7_2_an_allocation_knows_once_its_server_answered_even_the_challenge() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let udp = setup.server.udp_addr();
            assert!(
                !setup.client.answered(udp, Transport::Udp, 0),
                "no allocation"
            );
            // The first Allocate is lost: nothing answered yet.
            turn.drop_requests(1);
            let mut lease = pin!(setup.lease(Transport::Udp, "alice"));
            until_dropped(turn, 1, lease.as_mut()).await;
            assert!(!setup.client.answered(udp, Transport::Udp, 0));
            // The retransmission's 401 is an answer.
            setup.clock.advance(Duration::from_millis(500));
            let _lease = lease.await.unwrap();
            assert!(setup.client.answered(udp, Transport::Udp, 0));
            assert!(
                !setup.client.answered(udp, Transport::Tcp, 0),
                "another transport"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_8_a_udp_allocation_has_no_answer_for_a_new_generation_until_its_confirmation_is_answered()
     {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let udp = setup.server.udp_addr();
            let _first = setup.lease(Transport::Udp, "alice").await.unwrap();
            // Another session of the confirmed generation keeps the answer.
            let _same = setup.lease(Transport::Udp, "bob").await.unwrap();
            assert!(setup.client.answered(udp, Transport::Udp, 0));
            // A session of a newer generation: the confirming Refresh is
            // lost, and the answers over the old 5-tuple no longer count.
            turn.drop_requests(1);
            let mut newer = pin!(setup.lease_on(Transport::Udp, "bob", 1));
            until_dropped(turn, 1, newer.as_mut()).await;
            assert!(!setup.client.answered(udp, Transport::Udp, 1));
            // They still count for the generation they were sent on.
            assert!(setup.client.answered(udp, Transport::Udp, 0));
            // The retransmission's answer confirms it, and counts.
            setup.clock.advance(Duration::from_millis(500));
            let _newer = newer.await.unwrap();
            assert!(setup.client.answered(udp, Transport::Udp, 1));
            assert_eq!(turn.allocations()[0].refreshes, 1);
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_5_a_challenge_answered_before_a_new_generation_joined_does_not_count_for_it() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let udp = setup.server.udp_addr();
            // The unsigned Allocate is challenged and the signed one lost,
            // while a session on changed host addresses joins.
            turn.drop_requests_after(1, 1);
            let mut both = pin!(async {
                tokio::join!(
                    setup.lease(Transport::Udp, "alice"),
                    setup.lease_on(Transport::Udp, "bob", 1)
                )
            });
            until_dropped(turn, 1, both.as_mut()).await;
            assert!(setup.client.answered(udp, Transport::Udp, 0));
            assert!(!setup.client.answered(udp, Transport::Udp, 1));
            // The retransmission's answer, then the confirmation on
            // generation 1 the allocation needs, count for it.
            setup.clock.advance(Duration::from_millis(500));
            let (first, newer) = both.await;
            let (first, newer) = (first.unwrap(), newer.unwrap());
            assert_eq!(first.relayed(), newer.relayed());
            assert!(setup.client.answered(udp, Transport::Udp, 1));
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_5_a_late_answer_sent_before_a_new_generation_joined_does_not_count_for_it() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let udp = setup.server.udp_addr();
            let first = setup.lease(Transport::Udp, "alice").await.unwrap();
            // A permission on generation 0 is lost, then the Refresh that
            // confirms the allocation for a session on generation 1, a
            // quarter RTO later.
            turn.drop_requests(2);
            let mut permit = pin!(first.permit(peer(1).ip()));
            until_dropped(turn, 1, permit.as_mut()).await;
            setup.clock.advance(Duration::from_millis(250));
            let mut newer = pin!(setup.lease_on(Transport::Udp, "bob", 1));
            until_dropped(turn, 2, newer.as_mut()).await;
            assert!(!setup.client.answered(udp, Transport::Udp, 1));
            // The permission's retransmission is answered first: it
            // proves generation 0's path only.
            setup.clock.advance(Duration::from_millis(250));
            assert_eq!(permit.await, Ok(()));
            assert!(setup.client.answered(udp, Transport::Udp, 0));
            assert!(!setup.client.answered(udp, Transport::Udp, 1));
            // The Refresh's retransmission is answered: it counts.
            setup.clock.advance(Duration::from_millis(250));
            let _newer = newer.await.unwrap();
            assert!(setup.client.answered(udp, Transport::Udp, 1));
            assert_eq!(turn.allocations()[0].refreshes, 1);
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8489_6_2_1_a_send_that_fails_is_left_to_the_retransmissions() {
        bounded(async {
            let setup = Setup::new().await;
            // An IPv6 server from an IPv4 socket: every send fails.
            let server: SocketAddr = "[::1]:3478".parse().unwrap();
            let alice = creds("alice");
            let lease = setup.client.lease(server, Transport::Udp, 0, &alice);
            let result = setup.drive(lease, Duration::from_secs(5)).await;
            assert_eq!(
                result.unwrap_err(),
                TurnError::Allocation(AllocationError::Allocate(TransactionError::Timeout))
            );
            // The demux forgets the transactions given up on.
            let responses = setup.demux.responses();
            eventually(|| responses.outstanding() == 0).await;
        })
        .await;
    }

    #[tokio::test]
    async fn a_refused_tcp_connection_fails_the_lease() {
        bounded(async {
            let setup = Setup::new().await;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = listener.local_addr().unwrap();
            drop(listener);
            let result = setup
                .client
                .lease(closed, Transport::Tcp, 0, &creds("alice"))
                .await;
            assert_eq!(
                result.unwrap_err(),
                TurnError::Allocation(AllocationError::Connection)
            );
        })
        .await;
    }

    #[tokio::test]
    async fn a_lease_during_the_deletion_waits_for_a_new_allocation() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let first = setup.lease(Transport::Udp, "alice").await.unwrap();
            let relayed = first.relayed();
            // The deleting Refresh is lost, so the deletion is still going on
            // when the next session asks.
            turn.drop_requests(1);
            drop(first);
            let mut again = pin!(setup.lease(Transport::Udp, "alice"));
            until_dropped(turn, 1, again.as_mut()).await;
            let again = setup
                .drive(again, Duration::from_millis(500))
                .await
                .unwrap();
            assert_ne!(again.relayed(), relayed);
            assert_eq!(turn.allocations().len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_8_1_an_allocation_being_deleted_has_no_answer_even_once_its_deletion_is_answered()
     {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let udp = setup.server.udp_addr();
            let lease = setup.lease(Transport::Udp, "alice").await.unwrap();
            assert!(setup.client.answered(udp, Transport::Udp, 0));
            // The deleting Refresh is lost: the allocation is being
            // deleted, and its answers no longer count.
            turn.drop_requests(1);
            drop(lease);
            eventually(|| turn.dropped() == 1).await;
            assert!(!setup.client.answered(udp, Transport::Udp, 0));
            // The retransmission's answer ends the deletion and the task,
            // whose handle stays until the next lease; it does not count.
            setup.clock.advance(Duration::from_millis(500));
            eventually(|| {
                let allocations = setup.client.allocations.lock().unwrap();
                allocations
                    .values()
                    .all(|handle| handle.commands.is_closed())
            })
            .await;
            assert_eq!(turn.allocations().len(), 0, "deleted");
            assert!(!setup.client.answered(udp, Transport::Udp, 0));
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_3_1_an_allocation_whose_connection_dropped_has_no_answer() {
        bounded(async {
            let setup = Setup::new().await;
            let tcp = setup.server.tcp_addr();
            let lease = setup.lease(Transport::Tcp, "alice").await.unwrap();
            assert!(setup.client.answered(tcp, Transport::Tcp, 0));
            // The connection drops: the task ends without a deletion, and
            // its handle stays until the next lease.
            setup.server.disconnect_tcp();
            let mut status = lease.status();
            status.wait_for(Option::is_none).await.unwrap();
            eventually(|| {
                let allocations = setup.client.allocations.lock().unwrap();
                allocations
                    .values()
                    .all(|handle| handle.commands.is_closed())
            })
            .await;
            assert_eq!(setup.client.allocations.lock().unwrap().len(), 1);
            assert!(!setup.client.answered(tcp, Transport::Tcp, 0));
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_8_3_a_refused_refresh_re_creates_under_the_newest_credential() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let alice = setup.lease(Transport::Udp, "alice").await.unwrap();
            let _bob = setup.lease(Transport::Udp, "bob").await.unwrap();
            let mut status = alice.status();
            turn.expire_user("alice");
            setup.clock.advance(Duration::from_secs(540));
            status.wait_for(Option::is_none).await.unwrap();
            setup.clock.advance(Duration::from_secs(60));
            let relayed = status.wait_for(Option::is_some).await.unwrap().unwrap();
            assert_ne!(relayed, alice.relayed());
            let allocations = turn.allocations();
            assert_eq!(allocations.len(), 1);
            assert_eq!(allocations[0].username, "bob");
            assert_eq!(allocations[0].relayed, relayed);
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_8_3_a_lost_allocation_has_no_answer_until_its_re_creation_is_answered() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let udp = setup.server.udp_addr();
            let alice = setup.lease(Transport::Udp, "alice").await.unwrap();
            let _bob = setup.lease(Transport::Udp, "bob").await.unwrap();
            assert!(setup.client.answered(udp, Transport::Udp, 0));
            let mut status = alice.status();
            // The refused Refresh loses it; the re-creation waits for the
            // old allocation to expire.
            turn.expire_user("alice");
            setup.clock.advance(Duration::from_secs(540));
            status.wait_for(Option::is_none).await.unwrap();
            assert!(!setup.client.answered(udp, Transport::Udp, 0));
            setup.clock.advance(Duration::from_secs(60));
            status.wait_for(Option::is_some).await.unwrap();
            assert!(setup.client.answered(udp, Transport::Udp, 0));
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_8_3_requests_waiting_when_the_allocation_is_lost_fail_with_it() {
        bounded(async {
            // Retransmissions far off, so only the Refresh decides.
            let setup = Setup::with(AllocationConfig {
                rto: Duration::from_secs(3600),
                ..AllocationConfig::default()
            })
            .await;
            let turn = setup.turn();
            let lease = setup.lease(Transport::Udp, "alice").await.unwrap();
            turn.drop_requests(2);
            let mut permit = pin!(lease.permit(peer(1).ip()));
            until_dropped(turn, 1, permit.as_mut()).await;
            let mut bind = pin!(lease.bind_channel(peer(2)));
            until_dropped(turn, 2, bind.as_mut()).await;
            turn.forget_allocations();
            setup.clock.advance(Duration::from_secs(540));
            assert_eq!(permit.await, Err(TurnError::Lost));
            assert_eq!(bind.await, Err(TurnError::Lost));
            // Re-created at once after the 437.
            let mut status = lease.status();
            let relayed = status.wait_for(Option::is_some).await.unwrap().unwrap();
            assert_ne!(relayed, lease.relayed());
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_10_3_refused_permissions_and_channels_are_reported() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let lease = setup.lease(Transport::Udp, "alice").await.unwrap();
            turn.forget_allocations();
            let mismatch = TransactionError::Rejected {
                code: 437,
                reason: "Allocation Mismatch".to_owned(),
            };
            assert_eq!(
                lease.permit(peer(1).ip()).await,
                Err(TurnError::Permission(mismatch.clone()))
            );
            assert_eq!(
                lease.bind_channel(peer(1)).await,
                Err(TurnError::Channel(mismatch))
            );
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_3_1_requests_waiting_when_the_connection_drops_fail() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let lease = setup.lease(Transport::Tcp, "alice").await.unwrap();
            turn.drop_requests(2);
            let mut permit = pin!(lease.permit(peer(1).ip()));
            until_dropped(turn, 1, permit.as_mut()).await;
            let mut bind = pin!(lease.bind_channel(peer(2)));
            until_dropped(turn, 2, bind.as_mut()).await;
            setup.server.disconnect_tcp();
            assert_eq!(permit.await, Err(TurnError::Closed));
            assert_eq!(bind.await, Err(TurnError::Closed));
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_7_4_a_restart_clears_its_own_earlier_allocation_but_not_anothers() {
        bounded(async {
            let setup = Setup::new().await;
            let turn = setup.turn();
            let before = setup.lease(Transport::Udp, "alice").await.unwrap();
            let restarted = setup.restarted();
            let server = setup.server.udp_addr();
            let refused = restarted
                .lease(server, Transport::Udp, 0, &creds("bob"))
                .await;
            assert_eq!(
                refused.unwrap_err(),
                TurnError::Allocation(AllocationError::Mismatch(TransactionError::Rejected {
                    code: 441,
                    reason: "Wrong Credentials".to_owned()
                }))
            );
            let after = restarted
                .lease(server, Transport::Udp, 0, &creds("alice"))
                .await
                .unwrap();
            assert_ne!(after.relayed(), before.relayed());
            assert_eq!(turn.allocations()[0].relayed, after.relayed());
        })
        .await;
    }

    /// What a stream's task needs besides the stream: no sessions.
    fn stream_parts() -> (Peers, mpsc::Sender<Outbound>, mpsc::Receiver<Outbound>) {
        let (out, frames) = mpsc::channel(4);
        let peers = Peers::new(
            Arc::new(Registrations::default()),
            Arc::new(DemuxStats::default()),
            Arc::new(SystemClock),
        );
        (peers, out, frames)
    }

    fn driver() -> (Driver, Handle, SocketAddr) {
        let server: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let clock = Arc::new(FakeClock::default());
        let machine = Allocation::new(
            server,
            Transport::Tcp,
            creds("alice"),
            AllocationConfig::default(),
            [3; 32],
            clock.now(),
            0,
        );
        let (driver, handle) = Driver::new(machine, server, clock);
        (driver, handle, server)
    }

    #[tokio::test]
    async fn a_stream_that_fails_to_write_ends_the_allocation() {
        bounded(async {
            let (driver, handle, _) = driver();
            let (reply, answer) = oneshot::channel();
            handle
                .commands
                .send(Command::Add {
                    credentials: creds("alice"),
                    generation: 0,
                    reply,
                })
                .unwrap();
            let (reader, _server) = tokio::io::duplex(64);
            // A stream whose other end is gone fails every write.
            let (writer, gone) = tokio::io::duplex(64);
            drop(gone);
            let (peers, _out, frames) = stream_parts();
            driver.run_stream(reader, writer, peers, frames).await;
            assert_eq!(
                answer.await.unwrap().unwrap_err(),
                TurnError::Allocation(AllocationError::Connection)
            );
            assert!(handle.commands.is_closed());
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8656_12_5_a_stream_is_split_into_messages_and_closed_when_out_of_step() {
        bounded(async {
            let (driver, handle, server) = driver();
            let status = driver.status.subscribe();
            let turn = FakeTurn::new(
                Arc::new(FakeClock::default()),
                REALM,
                Duration::from_secs(600),
            );
            turn.add_user("alice", "alice-pw");
            let (client_side, mut server_side) = tokio::io::duplex(4096);
            let (reader, writer) = tokio::io::split(client_side);
            // Nobody sends from a relay candidate: the closed queue is
            // ignored.
            let (peers, out, frames) = stream_parts();
            drop(out);
            let task = spawn_named(
                "test.turn_driver",
                driver.run_stream(reader, writer, peers, frames),
            );
            let (reply, answer) = oneshot::channel();
            handle
                .commands
                .send(Command::Add {
                    credentials: creds("alice"),
                    generation: 0,
                    reply,
                })
                .unwrap();
            // Two requests, each answered in two pieces, a ChannelData message
            // in between.
            let mut buffer = vec![0; 2048];
            for _ in 0..2 {
                let read = server_side.read(&mut buffer).await.unwrap();
                let answer = turn.handle(server, true, &buffer[..read]).unwrap();
                let (head, tail) = answer.split_at(10);
                server_side.write_all(head).await.unwrap();
                server_side.write_all(&[]).await.unwrap();
                SystemClock.sleep(Duration::from_millis(5)).await;
                server_side.write_all(tail).await.unwrap();
                server_side
                    .write_all(&[0x40, 0x00, 0x00, 0x01, 0xAA, 0, 0, 0])
                    .await
                    .unwrap();
            }
            let lease = answer.await.unwrap().unwrap();
            assert_eq!(turn.allocations()[0].relayed, lease.relayed());
            // Neither STUN nor ChannelData: the stream is out of step.
            server_side.write_all(&[0x80, 0, 0, 0]).await.unwrap();
            task.await.unwrap();
            assert!(handle.commands.is_closed());
            assert_eq!(*status.borrow(), None);
        })
        .await;
    }

    /// Answers every request on the stream until `done` completes.
    async fn serve<T>(
        turn: &FakeTurn,
        server: SocketAddr,
        requests: &mut tokio::io::DuplexStream,
        answers: &mut tokio::io::DuplexStream,
        done: impl Future<Output = T>,
    ) -> T {
        let mut done = pin!(done);
        let mut buffer = Vec::new();
        let mut chunk = vec![0; 2048];
        loop {
            while let Ok(Some(len)) = turn::stream_frame_len(&buffer)
                && buffer.len() >= len
            {
                let request: Vec<u8> = buffer.drain(..len).collect();
                let answer = turn.handle(server, true, &request).unwrap();
                answers.write_all(&answer).await.unwrap();
            }
            tokio::select! {
                read = requests.read(&mut chunk) => buffer.extend_from_slice(&chunk[..read.unwrap()]),
                result = &mut done => return result,
            }
        }
    }

    #[tokio::test]
    async fn a_relayed_frame_that_fails_to_write_ends_the_allocation() {
        bounded(async {
            let (driver, handle, server) = driver();
            let status = driver.status.subscribe();
            let turn = FakeTurn::new(
                Arc::new(FakeClock::default()),
                REALM,
                Duration::from_secs(600),
            );
            turn.add_user("alice", "alice-pw");
            // The server's answers on one stream, the requests on another,
            // so the requests' end can go while answers still arrive.
            let (reader, mut answers) = tokio::io::duplex(4096);
            let (writer, mut requests) = tokio::io::duplex(4096);
            let (peers, out, frames) = stream_parts();
            let task = spawn_named(
                "test.turn_driver",
                driver.run_stream(reader, writer, peers, frames),
            );
            let (reply, added) = oneshot::channel();
            handle
                .commands
                .send(Command::Add {
                    credentials: creds("alice"),
                    generation: 0,
                    reply,
                })
                .unwrap();
            let granted = serve(&turn, server, &mut requests, &mut answers, added)
                .await
                .unwrap()
                .unwrap();
            let (relayed, lease) = (granted.relayed(), granted.id);
            // Granted before the binding, so read before the frame: the
            // commands are read in order, the frames on a queue of their own.
            let owner = RelayOwner::next();
            handle
                .commands
                .send(Command::Grant { lease, owner })
                .unwrap();
            let (reply, bound) = oneshot::channel();
            handle
                .commands
                .send(Command::Bind {
                    lease,
                    peer: peer(1),
                    reply,
                })
                .unwrap();
            let channel = serve(&turn, server, &mut requests, &mut answers, bound)
                .await
                .unwrap()
                .unwrap();
            drop(requests);
            out.send(Outbound {
                owner,
                relayed,
                frame: padded(channel, b"media"),
            })
            .await
            .unwrap();
            task.await.unwrap();
            assert!(handle.commands.is_closed());
            assert_eq!(*status.borrow(), None);
        })
        .await;
    }

    #[tokio::test]
    async fn the_stream_reader_ends_with_its_task() {
        bounded(async {
            let (queue, inbound) = mpsc::channel(1);
            drop(inbound);
            let (reader, mut server) = tokio::io::duplex(64);
            let message = turn::refresh([1; 12], Duration::ZERO).build();
            server.write_all(&message).await.unwrap();
            read_stream(Box::new(reader), "192.0.2.1:3478".parse().unwrap(), queue).await;
        })
        .await;
    }

    #[tokio::test]
    async fn requests_for_a_lease_the_allocation_does_not_know_are_refused() {
        bounded(async {
            let (mut driver, _handle, _) = driver();
            let stale = driver.machine.add_session(&creds("alice")).unwrap();
            driver.machine.add_session(&creds("alice")).unwrap();
            driver.machine.remove_session(driver.clock.now(), stale);
            // A grant that arrives after its lease went is ignored.
            driver.command(Command::Grant {
                lease: stale,
                owner: RelayOwner::next(),
            });
            assert!(driver.owners.is_empty());
            let (reply, permit) = oneshot::channel();
            driver.command(Command::Permit {
                lease: stale,
                peer: peer(1).ip(),
                reply,
            });
            assert_eq!(
                permit.await.unwrap(),
                Err(TurnError::Allocation(AllocationError::UnknownLease))
            );
            let (reply, bind) = oneshot::channel();
            driver.command(Command::Bind {
                lease: stale,
                peer: peer(1),
                reply,
            });
            assert_eq!(
                bind.await.unwrap(),
                Err(TurnError::Allocation(AllocationError::UnknownLease))
            );
        })
        .await;
    }
}
