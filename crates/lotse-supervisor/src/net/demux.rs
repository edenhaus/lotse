//! The demux: one dedicated receive thread on the shared UDP socket routes
//! every inbound datagram to the session it belongs to, in its worker,
//! without a lock on the packet path.
//!
//! In order: what a TURN server of a UDP allocation relays, `ChannelData`
//! on a channel bound to a peer (RFC 8656 §12.6) or a Data indication from
//! a peer with a permission (§11.4), unwrapped and routed on as the peer's
//! datagram arriving at the relayed address, from the next step but one;
//! STUN responses to the supervisor's own requests by transaction id (the
//! STUN client's, and the TURN allocations' whole messages); a known
//! remote address, unless it sends a Binding Request naming another
//! session; a STUN Binding Request by its USERNAME's local ufrag,
//! verified with that session's password before the address is learned
//! or moved to that session (RFC 8445 §7.2.2, §7.3, RFC 8489 §9.1); otherwise
//! dropped and counted. Forwarding is a non-blocking send on the worker's
//! datagram channel; a full channel drops the datagram, so one stuck
//! worker never slows the others.
//!
//! The TURN client publishes each UDP allocation's [`Relay`] through
//! [`Relays`], a channel the receive thread drains before every datagram,
//! so the table is the thread's own and the packet path takes no lock.
//!
//! The thread waits with `poll(2)` and a timeout before every read, never
//! on the socket's blocking mode: workers get the socket to send from, and
//! the blocking mode is a flag of the open file description every copy
//! shares (fcntl(2) `O_NONBLOCK`), so a copy set non-blocking would turn a
//! blocking read into a spin. It reads through `quinn-udp`: up to
//! [`quinn_udp::BATCH_SIZE`] datagrams per `recvmmsg(2)` (32 on Linux, one
//! on macOS), a GRO batch (Linux `UDP_GRO`) split back into the datagrams
//! it merged, and each datagram's destination address from its
//! `IP_PKTINFO` (RFC 3542 §6.1 `IPV6_PKTINFO` on IPv6, macOS
//! `IP_RECVDSTADDR` on IPv4) control message.
//!
//! A dual-stack socket reports an IPv4 peer as IPv4-mapped (RFC 4291
//! §2.5.5.2); the demux hands it on as the IPv4 address it is. The local
//! address it names is where the datagram arrived, in the same canonical
//! form, so a session answers from the address the browser sent to (RFC
//! 8445 §7.2.5.2.1: a response from any other fails the check); without
//! that control message it is the host address of the peer's family.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;
use lotse_core::throttle::Throttle;
use lotse_ipc::datagram;
use quinn_udp::{RecvMeta, UdpSocketState};
use tokio::sync::{mpsc, oneshot};

pub use super::allocation::Relay;
use super::stun;
use super::turn;
use super::udp::RECV_TIMEOUT;

/// Remote addresses one session may be reached from at once.
pub const MAX_ADDRS_PER_SESSION: usize = 8;

/// A learned address that carried nothing for this long gives way when
/// its session is at [`MAX_ADDRS_PER_SESSION`] and verifies another: RFC
/// 7675 §5.1's consent timeout. A browser sends a consent check on the
/// pair it uses every 4 to 6 s (§5.1), so an address silent this long is
/// on no pair it uses, and one that comes back is learned again from its
/// next check. Without this, checks replayed from spoofed sources (the
/// integrity covers the message, not the IP header) filled the session's
/// addresses for its life.
pub const ADDR_IDLE_EXPIRY: Duration = Duration::from_secs(30);

/// Log every this many dropped datagrams from unknown addresses.
const UNROUTABLE_LOG_EVERY: u64 = 1_000;

/// One read's receive buffer per datagram: any UDP datagram fits (65,507
/// bytes of IPv4 payload, 65,527 of IPv6, RFC 768 and RFC 8200 §4.5 without
/// jumbograms), and so does any GRO batch, which Linux merges only while
/// the result stays below 64 KiB.
const RECV_SLOT: usize = 1 << 16;

/// Where a session's uplink goes: its worker.
pub trait DatagramSink: Send + Sync + fmt::Debug {
    /// Hands one encoded datagram frame to the worker without waiting;
    /// `false` when it was dropped.
    fn forward(&self, frame: &[u8]) -> bool;

    /// Hands an ICE-TCP connection over; `false` when it could not be.
    fn ice_tcp(&self, stream: OwnedFd, peer: SocketAddr, first_frame: Vec<u8>) -> bool {
        let _ = (stream, peer, first_frame);
        false
    }
}

/// A worker's datagram channel as a sink.
#[derive(Debug)]
pub struct WorkerSink {
    /// The supervisor's end, non-blocking.
    pub datagrams: Arc<UnixDatagram>,
}

impl DatagramSink for WorkerSink {
    fn forward(&self, frame: &[u8]) -> bool {
        match self.datagrams.send(frame) {
            Ok(_) => true,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => false,
            Err(err) => {
                tracing::debug!(error = %err, "datagram channel send failed");
                false
            }
        }
    }
}

/// One registered session.
#[derive(Debug)]
pub struct Registration {
    /// The local ufrag, the key.
    pub local_ufrag: String,
    /// The ICE password STUN requests must prove.
    pub password: Vec<u8>,
    /// Its worker.
    pub sink: Arc<dyn DatagramSink>,
    /// Addresses learned so far.
    addrs: AtomicUsize,
    /// When the ICE-TCP acceptor last handed it connections, oldest first,
    /// as many as its budget allows (`tcp::MAX_HAND_OFFS`).
    pub(super) hand_offs: Mutex<VecDeque<Instant>>,
    /// Unregistered; the receive thread forgets its addresses lazily.
    closed: AtomicBool,
}

impl Registration {
    /// Whether the session is gone.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// The sessions by local ufrag, shared with the ICE-TCP acceptor; taken
/// on the packet path only for a STUN request from an unknown address.
#[derive(Debug, Default)]
pub struct Registrations {
    /// By local ufrag.
    by_ufrag: RwLock<HashMap<String, Arc<Registration>>>,
}

impl Registrations {
    /// Registers a session; a second registration of the ufrag replaces
    /// the first.
    pub fn register(
        &self,
        local_ufrag: &str,
        password: Vec<u8>,
        sink: Arc<dyn DatagramSink>,
    ) -> Arc<Registration> {
        let registration = Arc::new(Registration {
            local_ufrag: local_ufrag.to_owned(),
            password,
            sink,
            addrs: AtomicUsize::new(0),
            hand_offs: Mutex::default(),
            closed: AtomicBool::new(false),
        });
        let previous = self
            .by_ufrag
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(local_ufrag.to_owned(), Arc::clone(&registration));
        if let Some(previous) = previous {
            previous.closed.store(true, Ordering::Release);
        }
        tracing::debug!(ufrag = local_ufrag, "session registered with the demux");
        registration
    }

    /// Unregisters a session.
    pub fn unregister(&self, local_ufrag: &str) {
        let gone = self
            .by_ufrag
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(local_ufrag);
        if let Some(gone) = gone {
            gone.closed.store(true, Ordering::Release);
            tracing::debug!(ufrag = local_ufrag, "session unregistered from the demux");
        }
    }

    /// The session behind a local ufrag.
    pub fn get(&self, local_ufrag: &str) -> Option<Arc<Registration>> {
        self.by_ufrag
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(local_ufrag)
            .cloned()
    }

    /// How many sessions are registered.
    pub fn len(&self) -> usize {
        self.by_ufrag
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// No session is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A STUN response to one of the supervisor's own requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunReply {
    /// Who answered.
    pub from: SocketAddr,
    /// XOR-MAPPED-ADDRESS, on success.
    pub mapped: Option<SocketAddr>,
    /// ERROR-CODE, on failure.
    pub error: Option<(u16, String)>,
}

/// A response to one of the TURN client's requests, whole: the client
/// checks its integrity and reads its attributes itself (RFC 8489 §9.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawReply {
    /// Who answered, in canonical form.
    pub from: SocketAddr,
    /// The message.
    pub bytes: Vec<u8>,
}

/// Who waits for a response.
#[derive(Debug)]
enum Waiter {
    /// The STUN client: the reply's mapped address or error, once.
    Reply(oneshot::Sender<StunReply>),
    /// A TURN allocation: the whole message, on the allocation's queue.
    Raw(mpsc::Sender<RawReply>),
}

/// The supervisor's outstanding STUN transactions.
#[derive(Debug, Default)]
pub struct StunResponses {
    /// By transaction id.
    pending: Mutex<HashMap<[u8; 12], Waiter>>,
}

impl StunResponses {
    /// Expects a response for `transaction_id`.
    pub fn expect(&self, transaction_id: [u8; 12]) -> oneshot::Receiver<StunReply> {
        let (tx, rx) = oneshot::channel();
        self.insert(transaction_id, Waiter::Reply(tx));
        rx
    }

    /// Expects a response for `transaction_id` on `queue`, the whole
    /// message; a full queue drops it, as if the network had (the request
    /// is retransmitted, RFC 8489 §6.2.1).
    pub fn expect_raw(&self, transaction_id: [u8; 12], queue: mpsc::Sender<RawReply>) {
        self.insert(transaction_id, Waiter::Raw(queue));
    }

    /// Registers a waiter.
    fn insert(&self, transaction_id: [u8; 12], waiter: Waiter) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(transaction_id, waiter);
    }

    /// Gives up on `transaction_id`.
    pub fn forget(&self, transaction_id: &[u8; 12]) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(transaction_id);
    }

    /// How many transactions are waited for; a client that gave up on
    /// one forgets it, so this falls back to zero.
    pub fn outstanding(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Delivers the response `message`, received as `bytes` from `from`;
    /// `false` when nobody waits for it.
    fn deliver(&self, message: &stun::Message<'_>, bytes: &[u8], from: SocketAddr) -> bool {
        let waiter = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&message.transaction_id);
        match waiter {
            None => false,
            Some(Waiter::Reply(tx)) => tx
                .send(StunReply {
                    from,
                    mapped: message.xor_mapped_address(),
                    error: message
                        .error_code()
                        .map(|(code, reason)| (code, reason.to_owned())),
                })
                .is_ok(),
            Some(Waiter::Raw(queue)) => queue
                .try_send(RawReply {
                    from,
                    bytes: bytes.to_vec(),
                })
                .is_ok(),
        }
    }
}

/// One change to the relay table: a TURN server's allocation as it now
/// is, or `None` once it is gone.
type RelayUpdate = (SocketAddr, Option<Relay>);

/// The TURN client's way to the receive thread's relay table; cheap to
/// clone, and sending never waits.
#[derive(Debug, Clone)]
pub struct Relays {
    /// The receive thread's end is [`RelayUpdates`].
    updates: std::sync::mpsc::Sender<RelayUpdate>,
}

impl Relays {
    /// A table's two ends: the publisher and what a [`Router`] drains.
    pub fn channel() -> (Self, RelayUpdates) {
        let (updates, receiver) = std::sync::mpsc::channel();
        (Self { updates }, RelayUpdates { updates: receiver })
    }

    /// What the allocation on `server` lets its server relay now; `None`
    /// once it is gone. A router that stopped is not told.
    pub fn publish(&self, server: SocketAddr, relay: Option<Relay>) {
        tracing::debug!(%server, relayed = ?relay.as_ref().map(|r| r.relayed), channels = relay.as_ref().map_or(0, |r| r.channels.len()), permissions = relay.as_ref().map_or(0, |r| r.permissions.len()), "turn relay published to the demux");
        // A stopped receive thread has no table left to update.
        drop(self.updates.send((canonical(server), relay)));
    }
}

/// The receive thread's end of [`Relays`].
#[derive(Debug)]
pub struct RelayUpdates {
    /// Updates in the order they were published.
    updates: std::sync::mpsc::Receiver<RelayUpdate>,
}

/// What the demux counted; `metrics/get` reads it.
#[derive(Debug, Default)]
pub struct DemuxStats {
    /// Datagrams read.
    pub received: AtomicU64,
    /// Datagrams handed to a worker.
    pub forwarded: AtomicU64,
    /// Datagrams from unknown addresses that were not a usable STUN request.
    pub unroutable: AtomicU64,
    /// STUN requests with an unknown ufrag or a wrong password.
    pub stun_rejected: AtomicU64,
    /// Addresses learned through verified STUN requests.
    pub addresses_learned: AtomicU64,
    /// Datagrams dropped because the worker's channel was full.
    pub worker_full: AtomicU64,
    /// Responses to the supervisor's own STUN requests.
    pub responses: AtomicU64,
    /// Datagrams a TURN server relayed from a peer, unwrapped and routed
    /// on as the peer's; each also lands in one of the counters a peer's
    /// datagram does.
    pub relayed: AtomicU64,
    /// From a TURN server and discarded: `ChannelData` on a channel not
    /// bound or cut short, a Data indication from a peer without a
    /// permission or without data, or neither STUN nor `ChannelData` (RFC
    /// 8656 §11.4, §12.6, Table 3).
    pub relay_discarded: AtomicU64,
    /// Wake-ups without a datagram: about one per `RECV_TIMEOUT` while
    /// idle; a busy receive loop shows as a count that races ahead.
    pub idle_wakeups: AtomicU64,
}

impl DemuxStats {
    /// The value of one counter.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// One counter.
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// How [`Demux`] starts its receive thread: [`std::thread::Builder::spawn`]
/// on the named builder and the thread's body.
type SpawnThread = fn(std::thread::Builder, Box<dyn FnOnce() + Send>) -> io::Result<JoinHandle<()>>;

/// The receive thread and what it shares.
#[derive(Debug)]
pub struct Demux {
    /// The sessions.
    registrations: Arc<Registrations>,
    /// The supervisor's STUN transactions.
    responses: Arc<StunResponses>,
    /// The TURN allocations' relays.
    relays: Relays,
    /// The counters.
    stats: Arc<DemuxStats>,
    /// Set to stop the thread.
    stop: Arc<AtomicBool>,
    /// The thread.
    thread: Option<JoinHandle<()>>,
}

impl Demux {
    /// Starts the receive thread on `socket`, bound at `local`, whose
    /// datagrams arrive on `hosts` (the default-route one of each family
    /// first). It sets the socket up for `quinn-udp` first: non-blocking
    /// (the thread polls), destination addresses, GRO where the kernel has
    /// it, and the don't-fragment bit on what every copy of the socket
    /// sends. `clock` times the rate limit of its log lines.
    pub fn start(
        socket: Arc<UdpSocket>,
        local: SocketAddr,
        hosts: Vec<SocketAddr>,
        clock: Arc<dyn Clock>,
    ) -> io::Result<Self> {
        Self::start_with(socket, local, hosts, clock, std::thread::Builder::spawn)
    }

    /// [`Self::start`], with `spawn` starting the receive thread: the seam
    /// a test makes fail, as a process at its thread limit would see it,
    /// whatever user runs the test.
    fn start_with(
        socket: Arc<UdpSocket>,
        local: SocketAddr,
        hosts: Vec<SocketAddr>,
        clock: Arc<dyn Clock>,
        spawn: SpawnThread,
    ) -> io::Result<Self> {
        let socket_state = UdpSocketState::new((&*socket).into())?;
        let registrations = Arc::new(Registrations::default());
        let responses = Arc::new(StunResponses::default());
        let stats = Arc::new(DemuxStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (relays, updates) = Relays::channel();
        let thread = spawn(
            std::thread::Builder::new().name("lotse-demux".into()),
            Box::new({
                let registrations = Arc::clone(&registrations);
                let responses = Arc::clone(&responses);
                let stats = Arc::clone(&stats);
                let stop = Arc::clone(&stop);
                move || {
                    let mut router = Router::new(
                        registrations,
                        responses,
                        updates,
                        stats,
                        clock,
                        local,
                        &hosts,
                    );
                    receive_loop(&socket, &socket_state, &mut router, &stop);
                }
            }),
        )?;
        Ok(Self {
            registrations,
            responses,
            relays,
            stats,
            stop,
            thread: Some(thread),
        })
    }

    /// The sessions.
    pub fn registrations(&self) -> Arc<Registrations> {
        Arc::clone(&self.registrations)
    }

    /// The supervisor's STUN transactions.
    pub fn responses(&self) -> Arc<StunResponses> {
        Arc::clone(&self.responses)
    }

    /// Where the TURN client publishes its UDP allocations' relays.
    pub fn relays(&self) -> Relays {
        self.relays.clone()
    }

    /// The counters.
    pub fn stats(&self) -> Arc<DemuxStats> {
        Arc::clone(&self.stats)
    }

    /// Stops the thread and waits for it (at most one receive timeout).
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

impl Drop for Demux {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// The local address a datagram arrived on: where it was sent, when the
/// socket says, else the host address of the peer's family.
#[derive(Debug, Clone, Copy)]
struct Locals {
    /// For IPv4 peers.
    v4: SocketAddr,
    /// For IPv6 peers.
    v6: SocketAddr,
    /// The port every datagram arrives on, the bound one.
    port: u16,
}

impl Locals {
    /// The first host address of each family, else the bound address.
    fn new(bound: SocketAddr, hosts: &[SocketAddr]) -> Self {
        let v4 = hosts.iter().find(|h| h.is_ipv4()).copied();
        let v6 = hosts.iter().find(|h| h.is_ipv6()).copied();
        Self {
            v4: v4.unwrap_or(bound),
            v6: v6.unwrap_or(bound),
            port: bound.port(),
        }
    }

    /// The local address for a datagram from `source` (canonical) sent to
    /// `destination`, if the socket reported it: that address in canonical
    /// form on the bound port, else the host address of the peer's family.
    fn at(&self, source: SocketAddr, destination: Option<IpAddr>) -> SocketAddr {
        match (destination, source) {
            (Some(ip), _) => SocketAddr::new(ip.to_canonical(), self.port),
            (None, SocketAddr::V4(_)) => self.v4,
            (None, SocketAddr::V6(_)) => self.v6,
        }
    }
}

/// The peer as the ICE agent knows it: IPv4-mapped IPv6 is IPv4, every
/// other address unchanged. The UDP demux and the ICE-TCP acceptor both
/// apply it where they learn a peer.
pub(super) fn canonical(source: SocketAddr) -> SocketAddr {
    SocketAddr::new(source.ip().to_canonical(), source.port())
}

/// The thread: read a batch, route each datagram, repeat. The buffers are
/// allocated once, [`RECV_SLOT`] bytes per datagram of a batch; the kernel
/// touches only the pages it writes.
fn receive_loop(
    socket: &UdpSocket,
    state: &UdpSocketState,
    router: &mut Router,
    stop: &AtomicBool,
) {
    let mut buf = vec![0_u8; RECV_SLOT.saturating_mul(quinn_udp::BATCH_SIZE)];
    let mut slots: Vec<IoSliceMut<'_>> = buf.chunks_mut(RECV_SLOT).map(IoSliceMut::new).collect();
    let batch = slots.len();
    let mut metas = vec![RecvMeta::default(); batch];
    let gro_segments = state.gro_segments();
    tracing::info!(v4 = %router.local.v4, v6 = %router.local.v6, batch, gro_segments, "demux receive thread started");
    while !stop.load(Ordering::Acquire) {
        if !readable(socket) {
            DemuxStats::bump(&router.stats.idle_wakeups);
            continue;
        }
        let read = state.recv(socket.into(), &mut slots, &mut metas);
        route_read(read, &slots, &metas, router);
    }
    tracing::info!("demux receive thread stopped");
}

/// Routes the datagrams of one read into `slots`, described by `metas`.
/// A read that found nothing (a copy of the shared socket took the
/// datagram first) counts as an idle wake-up, and one that failed is
/// logged; the thread reads on after either.
fn route_read(
    read: io::Result<usize>,
    slots: &[IoSliceMut<'_>],
    metas: &[RecvMeta],
    router: &mut Router,
) {
    let read = match read {
        Ok(read) => read,
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            DemuxStats::bump(&router.stats.idle_wakeups);
            return;
        }
        Err(err) => {
            tracing::warn!(error = %err, "udp receive failed");
            return;
        }
    };
    for (slot, meta) in slots.iter().zip(metas).take(read) {
        // `len` never exceeds the slot it was read into.
        let filled = slot.get(..meta.len).into_iter();
        for payload in filled.flat_map(|data| segments(data, meta.stride)) {
            router.route(payload, meta.addr, meta.dst_ip);
        }
    }
}

/// The datagrams of one read: a GRO batch is `stride` bytes per datagram
/// but the last, which may be shorter; an empty datagram is one datagram
/// too, and a stride of zero (an empty read) splits nothing.
fn segments(data: &[u8], stride: usize) -> impl Iterator<Item = &[u8]> {
    let empty = data.is_empty().then_some(data);
    data.chunks(stride.max(1)).chain(empty)
}

/// Waits up to `RECV_TIMEOUT` for a datagram, whatever the socket's
/// blocking mode; `false` on the timeout or an interrupted wait.
fn readable(socket: &UdpSocket) -> bool {
    let timeout = rustix::event::Timespec::try_from(RECV_TIMEOUT).ok();
    let mut fds = [rustix::event::PollFd::new(
        socket,
        rustix::event::PollFlags::IN,
    )];
    matches!(rustix::event::poll(&mut fds, timeout.as_ref()), Ok(ready) if ready > 0)
}

/// The routing state of one receive thread: every datagram the thread
/// reads goes through [`Router::route`], which is also what the
/// `rtp_demux` fuzz target drives without a socket.
/// The addresses it learned and the relay table are its own; the
/// sessions, the transactions and the counters are shared with the rest of
/// the supervisor.
#[derive(Debug)]
pub struct Router {
    /// The supervisor's STUN transactions.
    responses: Arc<StunResponses>,
    /// Changes to `relays`, drained before every datagram.
    updates: RelayUpdates,
    /// The UDP allocations by their server, in canonical form.
    relays: HashMap<SocketAddr, Relay>,
    /// The counters.
    stats: Arc<DemuxStats>,
    /// The local address per peer family.
    local: Locals,
    /// The peers' routes: steps 3 to 5.
    peers: Peers,
}

impl Router {
    /// A router for datagrams that arrive on a socket bound at `bound`,
    /// reached on `hosts` (the default-route one of each family first),
    /// that has learned no address yet; `clock` times the rate limit of its
    /// log lines.
    #[expect(
        clippy::too_many_arguments,
        reason = "what the router shares with the supervisor and where it is bound; a struct would only rename them"
    )]
    pub fn new(
        registrations: Arc<Registrations>,
        responses: Arc<StunResponses>,
        updates: RelayUpdates,
        stats: Arc<DemuxStats>,
        clock: Arc<dyn Clock>,
        bound: SocketAddr,
        hosts: &[SocketAddr],
    ) -> Self {
        Self {
            responses,
            updates,
            relays: HashMap::new(),
            peers: Peers::new(registrations, Arc::clone(&stats), clock),
            stats,
            local: Locals::new(bound, hosts),
        }
    }

    /// Routes one datagram from `source` to `destination`, both as the
    /// socket reported them (IPv4-mapped included; `None` when the socket
    /// did not say where it arrived), and counts it in exactly one of
    /// `responses`, `forwarded`, `worker_full`, `stun_rejected`,
    /// `relay_discarded` and `unroutable`.
    pub fn route(&mut self, payload: &[u8], source: SocketAddr, destination: Option<IpAddr>) {
        DemuxStats::bump(&self.stats.received);
        let source = canonical(source);
        while let Ok((server, relay)) = self.updates.updates.try_recv() {
            match relay {
                Some(relay) => self.relays.insert(server, relay),
                None => self.relays.remove(&server),
            };
        }
        // 1. What a TURN server relays from a peer.
        if let Some(relay) = self.relays.get(&source) {
            match unwrap_relayed(relay, payload) {
                Relayed::Peer { peer, data } => {
                    self.peers.relayed(data, peer, relay.relayed);
                    return;
                }
                Relayed::Discard(reason) => {
                    self.peers.discard(source, reason);
                    return;
                }
                Relayed::Server => {}
            }
        }
        let local = self.local.at(source, destination);
        let message = if stun::is_stun(payload) {
            stun::parse(payload).ok()
        } else {
            None
        };
        // 2. Responses to the supervisor's own requests.
        if let Some(message) = &message
            && matches!(message.class, stun::Class::Success | stun::Class::Error)
            && self.responses.deliver(message, payload, source)
        {
            DemuxStats::bump(&self.stats.responses);
            return;
        }
        self.peers.route(payload, source, local, message.as_ref());
    }
}

/// Steps 3 to 5 for a peer's datagram, direct or relayed: the sessions,
/// the addresses learned and the counters. The receive thread has one;
/// so has each TCP allocation's task, for what its server relays on the
/// connection, which the receive thread never reads.
/// Each learns its own addresses; a session's cap counts them all.
#[derive(Debug)]
pub struct Peers {
    /// The sessions.
    registrations: Arc<Registrations>,
    /// The counters.
    stats: Arc<DemuxStats>,
    /// Learned addresses: only verified STUN requests add one, or move
    /// one to the session they name. A closed
    /// session's go when one of them sends again or the next address is
    /// learned, whichever comes first, so the map never grows with the
    /// sessions that came and went; a live session's go when they were
    /// silent for [`ADDR_IDLE_EXPIRY`] and it needs the room.
    by_addr: HashMap<SocketAddr, Learned>,
    /// The frame being encoded for a worker, reused.
    frame: Vec<u8>,
    /// Times the addresses' silence and the rate limit of the log lines.
    clock: Arc<dyn Clock>,
    /// The rejected STUN requests' log line: the first, then a summary
    /// per [`lotse_core::throttle::SUMMARY_INTERVAL`], so a flood of them
    /// does not flood the log.
    rejected_log: Throttle,
    /// The same for verified requests refused because their session has
    /// no room for another address.
    full_log: Throttle,
}

/// One learned address.
#[derive(Debug)]
struct Learned {
    /// The session it belongs to.
    registration: Arc<Registration>,
    /// When a datagram last came from it, on the clock.
    last_seen: Instant,
}

impl Peers {
    /// Routes for `registrations`, counted in `stats`, with no address
    /// learned yet; `clock` times the addresses' silence and the rate
    /// limit of the log lines.
    pub fn new(
        registrations: Arc<Registrations>,
        stats: Arc<DemuxStats>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            registrations,
            stats,
            clock,
            rejected_log: Throttle::default(),
            full_log: Throttle::default(),
            by_addr: HashMap::new(),
            frame: Vec::with_capacity(
                datagram::MAX_DATAGRAM_PAYLOAD.saturating_add(datagram::HEADER_LEN),
            ),
        }
    }

    /// Routes `data`, which a TURN server relayed from `peer` (canonical)
    /// as arriving at `relayed`, as the peer's datagram (RFC 8656 §11.4,
    /// §12.6): counted as `relayed` and in one of the counters a peer's
    /// datagram lands in.
    pub fn relayed(&mut self, data: &[u8], peer: SocketAddr, relayed: SocketAddr) {
        DemuxStats::bump(&self.stats.relayed);
        let message = if stun::is_stun(data) {
            stun::parse(data).ok()
        } else {
            None
        };
        self.route(data, peer, relayed, message.as_ref());
    }

    /// Counts what `server` sent that is not to be delivered, for
    /// `reason` (RFC 8656 §11.4, §12.6, Table 3).
    pub fn discard(&self, server: SocketAddr, reason: &'static str) {
        tracing::trace!(%server, reason, "relayed datagram discarded");
        DemuxStats::bump(&self.stats.relay_discarded);
    }

    /// Routes a datagram from the peer `source` that arrived at `local`,
    /// directly or relayed, `message` its STUN reading if it is STUN.
    fn route(
        &mut self,
        payload: &[u8],
        source: SocketAddr,
        local: SocketAddr,
        message: Option<&stun::Message<'_>>,
    ) {
        // 3. A known address, unless a Binding Request names another
        // session: step 4 checks it, and if it verifies the address is
        // that session's now. The integrity proves which session the
        // sender holds, the source of a UDP datagram nothing (RFC 8445
        // §7.3, RFC 8489 §9.1.3).
        let named = message
            .filter(|message| message.is_binding_request())
            .and_then(stun::Message::local_ufrag);
        if let Some(learned) = self.by_addr.get_mut(&source) {
            if learned.registration.is_closed() {
                self.by_addr.remove(&source);
            } else if named.is_none_or(|ufrag| ufrag == learned.registration.local_ufrag) {
                learned.last_seen = self.clock.now();
                forward(
                    &learned.registration,
                    source,
                    local,
                    payload,
                    &self.stats,
                    &mut self.frame,
                );
                return;
            }
        }
        // 4. A STUN Binding Request naming a session, with the right password.
        if let Some(message) = message
            && message.is_binding_request()
        {
            let registration = message
                .local_ufrag()
                .and_then(|ufrag| self.registrations.get(ufrag))
                .filter(|r| !r.is_closed());
            match registration {
                Some(registration)
                    if message.verify_integrity(payload, &registration.password)
                        && message.fingerprint_ok(payload) =>
                {
                    let now = self.clock.now();
                    if !self.claim(&registration, now) {
                        DemuxStats::bump(&self.stats.stun_rejected);
                        if let Some(refused) = self.full_log.hit(now) {
                            tracing::warn!(%source, ufrag = registration.local_ufrag, refused, "session has too many addresses; verified stun request dropped");
                        }
                        return;
                    }
                    tracing::info!(%source, ufrag = registration.local_ufrag, "address learned from a verified stun request");
                    DemuxStats::bump(&self.stats.addresses_learned);
                    // A closed session's address is dropped when it sends
                    // again, which a browser's ephemeral port never does:
                    // sweeping here keeps the map at the live sessions'
                    // addresses plus those closed since the last learn.
                    self.by_addr
                        .retain(|_, learned| !learned.registration.is_closed());
                    forward(
                        &registration,
                        source,
                        local,
                        payload,
                        &self.stats,
                        &mut self.frame,
                    );
                    let ufrag = registration.local_ufrag.clone();
                    let previous = self.by_addr.insert(
                        source,
                        Learned {
                            registration,
                            last_seen: now,
                        },
                    );
                    if let Some(previous) = previous {
                        previous.registration.addrs.fetch_sub(1, Ordering::AcqRel);
                        tracing::info!(%source, from = previous.registration.local_ufrag, to = ufrag, "address moved to the session a verified stun request named");
                    }
                }
                _ => {
                    // No per-address limit before the check: sources are
                    // forged freely on UDP.
                    DemuxStats::bump(&self.stats.stun_rejected);
                    if let Some(rejected) = self.rejected_log.hit(self.clock.now()) {
                        tracing::debug!(%source, ufrag = ?message.local_ufrag(), rejected, "stun requests rejected: unknown ufrag or wrong password");
                    }
                }
            }
            return;
        }
        // 5. Nothing to do with it.
        let dropped = self
            .stats
            .unroutable
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if dropped.is_multiple_of(UNROUTABLE_LOG_EVERY) || dropped == 1 {
            tracing::warn!(%source, dropped, "unroutable datagrams");
        }
    }

    /// Counts one more address for `registration`; at the cap, first
    /// forgets this table's addresses of it that were silent for
    /// [`ADDR_IDLE_EXPIRY`] at `now`. `false` when it is still full. The
    /// count is the session's across every table; each forgets only its
    /// own.
    fn claim(&mut self, registration: &Arc<Registration>, now: Instant) -> bool {
        if claim_one(registration) {
            return true;
        }
        self.by_addr.retain(|addr, learned| {
            let idle = now.saturating_duration_since(learned.last_seen);
            let expired =
                Arc::ptr_eq(&learned.registration, registration) && idle >= ADDR_IDLE_EXPIRY;
            if expired {
                registration.addrs.fetch_sub(1, Ordering::AcqRel);
                let idle_ms = idle.as_millis();
                tracing::info!(%addr, ufrag = registration.local_ufrag, idle_ms, "idle address forgotten to make room for another");
            }
            !expired
        });
        claim_one(registration)
    }
}

/// Counts one more address for `registration` unless it has
/// [`MAX_ADDRS_PER_SESSION`]; `false` when it has.
fn claim_one(registration: &Registration) -> bool {
    let learned = registration.addrs.fetch_add(1, Ordering::AcqRel);
    if learned >= MAX_ADDRS_PER_SESSION {
        registration.addrs.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    true
}

/// What a datagram from a TURN server is.
#[derive(Debug)]
pub(super) enum Relayed<'a> {
    /// Relayed from `peer`: its `data`.
    Peer {
        /// The peer, in canonical form.
        peer: SocketAddr,
        /// The peer's datagram.
        data: &'a [u8],
    },
    /// Relayed, but not to be delivered, for the reason given.
    Discard(&'static str),
    /// The server's own STUN message: a response, or nothing.
    Server,
}

/// Reads what `relay`'s server sent: `ChannelData` names its peer by a
/// bound channel and is discarded on any other (RFC 8656 §12.6, which also
/// discards one shorter than its length); a Data indication names its
/// peer, whose IP must hold a permission (§11.4, the SHOULD followed); any
/// other STUN message is the server's own, and what is neither is dropped
/// (§12, Table 3).
pub(super) fn unwrap_relayed<'a>(relay: &Relay, payload: &'a [u8]) -> Relayed<'a> {
    let Some(first) = payload.first() else {
        return Relayed::Discard("empty");
    };
    match turn::kind(*first) {
        turn::Kind::ChannelData => match turn::parse_channel_data(payload) {
            Ok(message) => match relay.channels.get(&message.channel) {
                Some(peer) => Relayed::Peer {
                    peer: canonical(*peer),
                    data: message.data,
                },
                None => Relayed::Discard("channel not bound"),
            },
            Err(_) => Relayed::Discard("malformed channeldata"),
        },
        turn::Kind::Stun => {
            let Some(message) = stun::parse(payload)
                .ok()
                .filter(|m| m.class == stun::Class::Indication && m.method == turn::METHOD_DATA)
            else {
                return Relayed::Server;
            };
            match turn::data_indication(&message) {
                Some((peer, data)) if relay.permissions.contains(&peer.ip().to_canonical()) => {
                    Relayed::Peer {
                        peer: canonical(peer),
                        data,
                    }
                }
                Some(_) => Relayed::Discard("no permission for the peer"),
                None => Relayed::Discard("data indication without peer or data"),
            }
        }
        turn::Kind::Other => Relayed::Discard("neither stun nor channeldata"),
    }
}

/// Encodes and hands one datagram to the session's worker.
fn forward(
    registration: &Registration,
    source: SocketAddr,
    local: SocketAddr,
    payload: &[u8],
    stats: &DemuxStats,
    frame: &mut Vec<u8>,
) {
    datagram::encode(&registration.local_ufrag, source, local, payload, frame);
    if registration.sink.forward(frame) {
        DemuxStats::bump(&stats.forwarded);
    } else {
        DemuxStats::bump(&stats.worker_full);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! An in-memory sink for the tests of this crate.
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use std::sync::Mutex;

    use super::*;

    /// Collects what a worker would receive.
    #[derive(Debug, Default)]
    pub(crate) struct MemorySink {
        pub(crate) frames: Mutex<Vec<(SocketAddr, SocketAddr, Vec<u8>)>>,
        pub(crate) tcp: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
        pub(crate) full: AtomicBool,
    }

    impl DatagramSink for MemorySink {
        fn forward(&self, frame: &[u8]) -> bool {
            if self.full.load(Ordering::Relaxed) {
                return false;
            }
            let frame = datagram::decode(frame).expect("a frame");
            self.frames.lock().expect("lock").push((
                frame.source,
                frame.destination,
                frame.payload.to_vec(),
            ));
            true
        }

        fn ice_tcp(&self, stream: OwnedFd, peer: SocketAddr, first_frame: Vec<u8>) -> bool {
            drop(stream);
            if self.full.load(Ordering::Relaxed) {
                return false;
            }
            self.tcp.lock().expect("lock").push((peer, first_frame));
            true
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

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::let_assert;
    use lotse_core::throttle::SUMMARY_INTERVAL;

    use super::super::udp::test_support::bind_dual_stack;
    use super::test_support::MemorySink;
    use super::*;
    use crate::net::stun::{Builder, Class, METHOD_BINDING};
    use crate::test_support::Captured;

    /// Polls `done` for up to five seconds: generous, because the receive
    /// thread competes with the rest of a full test run.
    fn wait_for(mut done: impl FnMut() -> bool) -> bool {
        // Each look comes after a 5 ms pause, the first one too.
        (0..1_000).any(|_| {
            let until = SystemClock.now() + Duration::from_millis(5);
            while SystemClock.now() < until {
                std::thread::yield_now();
            }
            done()
        })
    }

    fn demux() -> (Demux, SocketAddr) {
        let bound = super::super::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = bound.local;
        (
            Demux::start(bound.socket, local, bound.hosts, Arc::new(SystemClock)).unwrap(),
            local,
        )
    }

    #[test]
    fn an_ipv4_peer_of_a_dual_stack_socket_is_forwarded_as_ipv4() {
        let bound = bind_dual_stack();
        let port = bound.local.port();
        // The host address the candidates carry; loopback here.
        let host: SocketAddr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let v6_host: SocketAddr = SocketAddr::new("::1".parse().unwrap(), port);
        let demux = Demux::start(
            bound.socket,
            bound.local,
            vec![host, v6_host],
            Arc::new(SystemClock),
        )
        .unwrap();
        let sink = Arc::new(MemorySink::default());
        demux
            .registrations()
            .register("dual", b"pw".to_vec(), sink.clone());
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let request = Builder::new(Class::Request, METHOD_BINDING, [4; 12])
            .username("dual:x")
            .integrity(b"pw")
            .fingerprint()
            .build();
        client.send_to(&request, host).unwrap();
        assert!(wait_for(|| sink.frames.lock().unwrap().len() == 1));
        let (source, destination, _) = sink.frames.lock().unwrap()[0].clone();
        assert_eq!(source, client.local_addr().unwrap(), "not ::ffff:127.0.0.1");
        assert_eq!(destination, host);
        // The learned address is the canonical one: later datagrams match.
        client.send_to(b"rtcp-ish", host).unwrap();
        assert!(wait_for(|| sink.frames.lock().unwrap().len() == 2));
        demux.stop();
        // Without host addresses the bound address stands in.
        let locals = Locals::new("[::]:7".parse().unwrap(), &[]);
        assert_eq!(
            locals.at("192.0.2.1:1".parse().unwrap(), None),
            "[::]:7".parse().unwrap()
        );
        assert_eq!(
            locals.at("[2001:db8::1]:1".parse().unwrap(), None),
            "[::]:7".parse().unwrap()
        );
        // A known destination is named on the bound port, in canonical
        // form, whatever the hosts and the peer's family.
        let locals = Locals::new(
            "[::]:7".parse().unwrap(),
            &["192.0.2.10:7".parse().unwrap()],
        );
        assert_eq!(
            locals.at(
                "192.0.2.1:1".parse().unwrap(),
                Some("::ffff:198.51.100.1".parse().unwrap())
            ),
            "198.51.100.1:7".parse().unwrap()
        );
        assert_eq!(
            locals.at(
                "[2001:db8::1]:1".parse().unwrap(),
                Some("2001:db8::7".parse().unwrap())
            ),
            "[2001:db8::7]:7".parse().unwrap()
        );
        assert_eq!(
            locals.at("192.0.2.1:1".parse().unwrap(), None),
            "192.0.2.10:7".parse().unwrap()
        );
        assert_eq!(
            canonical("[::ffff:192.0.2.1]:5".parse().unwrap()),
            "192.0.2.1:5".parse().unwrap()
        );
        assert_eq!(
            canonical("[2001:db8::1]:5".parse().unwrap()),
            "[2001:db8::1]:5".parse().unwrap()
        );
    }

    /// A STUN Binding Request for `ufrag` proving `password`.
    fn binding_request(ufrag: &str, password: &[u8], id: u8) -> Vec<u8> {
        Builder::new(Class::Request, METHOD_BINDING, [id; 12])
            .username(&format!("{ufrag}:x"))
            .integrity(password)
            .fingerprint()
            .build()
    }

    /// The session's check succeeds only when its response leaves from the
    /// address the request went to (RFC 8445 §7.2.5.2.1), so the demux
    /// names where each datagram arrived, from its `IP_PKTINFO` or
    /// `IPV6_PKTINFO` (RFC 3542 §6.1), not the host address of its family:
    /// here the hosts are addresses the socket never sees.
    #[test]
    fn rfc8445_7_2_5_2_1_the_local_address_is_where_the_datagram_arrived() {
        for bind in ["[::]:0", "0.0.0.0:0"] {
            let bound = if bind == "[::]:0" {
                bind_dual_stack()
            } else {
                super::super::udp::bind_udp(bind.parse().unwrap()).unwrap()
            };
            let port = bound.local.port();
            let hosts = vec![
                SocketAddr::new("192.0.2.10".parse().unwrap(), port),
                SocketAddr::new("2001:db8::10".parse().unwrap(), port),
            ];
            let dual = bound.dual_stack;
            let demux =
                Demux::start(bound.socket, bound.local, hosts, Arc::new(SystemClock)).unwrap();
            let sink = Arc::new(MemorySink::default());
            demux
                .registrations()
                .register("arrived", b"pw".to_vec(), sink.clone());
            let mut targets = vec![("127.0.0.1:0", "127.0.0.1")];
            if dual {
                targets.push(("[::1]:0", "::1"));
            }
            for (i, (from, to)) in targets.iter().enumerate() {
                let client = UdpSocket::bind(from).unwrap();
                let to = SocketAddr::new(to.parse().unwrap(), port);
                client
                    .send_to(&binding_request("arrived", b"pw", 7), to)
                    .unwrap();
                assert!(wait_for(|| sink.frames.lock().unwrap().len() == i + 1));
                let (source, destination, _) = sink.frames.lock().unwrap()[i].clone();
                assert_eq!(
                    (source, destination),
                    (client.local_addr().unwrap(), to),
                    "{bind}"
                );
            }
            demux.stop();
        }
    }

    #[test]
    fn a_read_splits_into_its_datagrams() {
        let split =
            |data: &[u8], stride| segments(data, stride).map(<[u8]>::len).collect::<Vec<_>>();
        // One datagram: the stride is its length.
        assert_eq!(split(&[1; 30], 30), [30]);
        // A GRO batch: whole strides, then a shorter last one.
        assert_eq!(split(&[1; 340], 100), [100, 100, 100, 40]);
        assert_eq!(split(&[1; 200], 100), [100, 100]);
        // An empty datagram is one datagram; a zero stride never panics.
        assert_eq!(split(&[], 0), [0]);
        assert_eq!(split(&[1; 3], 0), [1, 1, 1]);
    }

    /// Linux merges a burst from one peer into one read when the socket
    /// asks for GRO (`UDP_GRO`, set by `quinn-udp`); a GSO send over
    /// loopback arrives merged, and each datagram still reaches the worker
    /// as itself.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_gro_batch_reaches_the_worker_datagram_by_datagram() {
        let (demux, local) = demux();
        let sink = Arc::new(MemorySink::default());
        demux
            .registrations()
            .register("gro", b"pw".to_vec(), sink.clone());
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&binding_request("gro", b"pw", 8), local)
            .unwrap();
        assert!(wait_for(|| sink.frames.lock().unwrap().len() == 1));
        let state = UdpSocketState::new((&client).into()).unwrap();
        let burst: Vec<u8> = (0..340_u32)
            .map(|i| u8::try_from(i / 100).unwrap())
            .collect();
        state
            .try_send(
                (&client).into(),
                &quinn_udp::Transmit {
                    destination: local,
                    ecn: None,
                    contents: &burst,
                    segment_size: Some(100),
                    src_ip: None,
                },
            )
            .unwrap();
        assert!(wait_for(|| sink.frames.lock().unwrap().len() == 5));
        let payloads: Vec<Vec<u8>> = sink.frames.lock().unwrap()[1..]
            .iter()
            .map(|(_, _, payload)| payload.clone())
            .collect();
        assert_eq!(
            payloads,
            [vec![0; 100], vec![1; 100], vec![2; 100], vec![3; 40]]
        );
        demux.stop();
    }

    #[test]
    fn verified_stun_requests_teach_addresses_and_the_rest_is_counted() {
        let (demux, local) = demux();
        let sink = Arc::new(MemorySink::default());
        let registrations = demux.registrations();
        registrations.register("abcd", b"the-password".to_vec(), sink.clone());
        assert_eq!(registrations.len(), 1);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let stats = demux.stats();
        // Not STUN, unknown address: dropped.
        client.send_to(b"hello", local).unwrap();
        assert!(wait_for(|| DemuxStats::get(&stats.unroutable) == 1));
        assert!(sink.frames.lock().unwrap().is_empty());
        // A request with the wrong password: rejected.
        let bad = Builder::new(Class::Request, METHOD_BINDING, [1; 12])
            .username("abcd:remote")
            .integrity(b"wrong")
            .fingerprint()
            .build();
        client.send_to(&bad, local).unwrap();
        assert!(wait_for(|| DemuxStats::get(&stats.stun_rejected) == 1));
        // An unknown ufrag: rejected too.
        let unknown = Builder::new(Class::Request, METHOD_BINDING, [2; 12])
            .username("zzzz:remote")
            .integrity(b"the-password")
            .fingerprint()
            .build();
        client.send_to(&unknown, local).unwrap();
        assert!(wait_for(|| DemuxStats::get(&stats.stun_rejected) == 2));
        // The right one: forwarded, and the address is learned.
        let good = Builder::new(Class::Request, METHOD_BINDING, [3; 12])
            .username("abcd:remote")
            .integrity(b"the-password")
            .fingerprint()
            .build();
        client.send_to(&good, local).unwrap();
        assert!(wait_for(|| sink.frames.lock().unwrap().len() == 1));
        assert_eq!(DemuxStats::get(&stats.addresses_learned), 1);
        let (source, destination, payload) = sink.frames.lock().unwrap()[0].clone();
        assert_eq!(source, client.local_addr().unwrap());
        assert_eq!(destination, local);
        assert_eq!(payload, good);
        // From now on anything from that address goes through.
        client.send_to(b"media-ish", local).unwrap();
        assert!(wait_for(|| sink.frames.lock().unwrap().len() == 2));
        assert_eq!(sink.frames.lock().unwrap()[1].2, b"media-ish");
        // A full worker channel drops and counts.
        sink.full.store(true, Ordering::Relaxed);
        client.send_to(b"more", local).unwrap();
        assert!(wait_for(|| DemuxStats::get(&stats.worker_full) == 1));
        sink.full.store(false, Ordering::Relaxed);
        // Unregistered: the learned address is forgotten.
        registrations.unregister("abcd");
        assert!(registrations.is_empty());
        client.send_to(b"late", local).unwrap();
        assert!(wait_for(|| DemuxStats::get(&stats.unroutable) == 2));
        assert_eq!(sink.frames.lock().unwrap().len(), 2);
        assert_eq!(DemuxStats::get(&stats.forwarded), 2);
        demux.stop();
    }

    #[test]
    fn a_closed_sessions_addresses_are_forgotten_when_the_next_one_is_learned() {
        // Every browser session comes from a new port, and a closed
        // session's address never sends again: without a sweep each one
        // stayed in the map with its registration, found by the soak
        // as the supervisor's memory creeping per
        // session.
        let registrations = Arc::new(Registrations::default());
        let mut peers = Peers::new(
            Arc::clone(&registrations),
            Arc::new(DemuxStats::default()),
            Arc::new(SystemClock),
        );
        let local: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let learn = |peers: &mut Peers, ufrag: &str, port: u16| {
            let request = Builder::new(Class::Request, METHOD_BINDING, [9; 12])
                .username(&format!("{ufrag}:x"))
                .integrity(b"pw")
                .fingerprint()
                .build();
            let message = stun::parse(&request).unwrap();
            let source = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
            peers.route(&request, source, local, Some(&message));
        };
        let sink = Arc::new(MemorySink::default());
        for (index, ufrag) in ["s1", "s2", "s3"].into_iter().enumerate() {
            registrations.register(ufrag, b"pw".to_vec(), sink.clone());
            learn(&mut peers, ufrag, 50_000 + u16::try_from(index).unwrap());
        }
        assert_eq!(peers.by_addr.len(), 3, "live sessions keep their addresses");
        registrations.unregister("s1");
        registrations.unregister("s2");
        assert_eq!(
            peers.by_addr.len(),
            3,
            "forgotten lazily, not on unregister"
        );
        registrations.register("s4", b"pw".to_vec(), sink.clone());
        learn(&mut peers, "s4", 50_010);
        let mut left: Vec<&str> = peers
            .by_addr
            .values()
            .map(|learned| learned.registration.local_ufrag.as_str())
            .collect();
        left.sort_unstable();
        assert_eq!(left, ["s3", "s4"]);
        assert_eq!(sink.frames.lock().unwrap().len(), 4);
    }

    /// The integrity of a request proves which session's password its
    /// sender holds (RFC 8445 §7.3, RFC 8489 §9.1.3), and the source of a
    /// UDP datagram proves nothing: a verified request naming another
    /// session than the one an address was learned for moves the address
    /// to it. Before, the first session to verify from an address owned
    /// it for its life, so a viewer spoofing another browser's source
    /// ahead of its first check kept that browser from ever connecting.
    #[test]
    fn rfc8445_7_3_a_verified_request_naming_another_session_moves_the_address_to_it() {
        let registrations = Arc::new(Registrations::default());
        let stats = Arc::new(DemuxStats::default());
        let mut peers = Peers::new(
            Arc::clone(&registrations),
            Arc::clone(&stats),
            Arc::new(SystemClock),
        );
        let local: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let shared: SocketAddr = "192.0.2.7:50000".parse().unwrap();
        let send = |peers: &mut Peers, payload: &[u8], source: SocketAddr| {
            let message = stun::parse(payload).ok();
            peers.route(payload, source, local, message.as_ref());
        };
        let attacker_sink = Arc::new(MemorySink::default());
        let victim_sink = Arc::new(MemorySink::default());
        let attacker = registrations.register("attacker", b"pa".to_vec(), attacker_sink.clone());
        let victim = registrations.register("victim", b"pv".to_vec(), victim_sink.clone());
        // The attacker verifies first from the victim's address.
        send(&mut peers, &binding_request("attacker", b"pa", 1), shared);
        assert_eq!(attacker_sink.frames.lock().unwrap().len(), 1);
        assert_eq!(attacker.addrs.load(Ordering::Acquire), 1);
        // A request naming the victim without its password moves nothing.
        send(&mut peers, &binding_request("victim", b"pa", 2), shared);
        send(&mut peers, &binding_request("nobody", b"pa", 3), shared);
        assert_eq!(DemuxStats::get(&stats.stun_rejected), 2);
        assert!(victim_sink.frames.lock().unwrap().is_empty());
        assert_eq!(attacker_sink.frames.lock().unwrap().len(), 1);
        // The victim's own check moves the address to the victim.
        let check = binding_request("victim", b"pv", 4);
        send(&mut peers, &check, shared);
        assert_eq!(victim_sink.frames.lock().unwrap().len(), 1);
        assert_eq!(victim_sink.frames.lock().unwrap()[0].2, check);
        assert_eq!(DemuxStats::get(&stats.addresses_learned), 2);
        assert_eq!(attacker.addrs.load(Ordering::Acquire), 0, "given back");
        assert_eq!(victim.addrs.load(Ordering::Acquire), 1);
        // From now on the address's datagrams and checks are the victim's.
        send(&mut peers, b"media", shared);
        send(&mut peers, &binding_request("victim", b"pv", 5), shared);
        assert_eq!(victim_sink.frames.lock().unwrap().len(), 3);
        assert_eq!(attacker_sink.frames.lock().unwrap().len(), 1);
        assert_eq!(DemuxStats::get(&stats.addresses_learned), 2);
        // A session with no room for another address does not take it.
        for port in 1..=MAX_ADDRS_PER_SESSION {
            let other = SocketAddr::new(shared.ip(), u16::try_from(port).unwrap());
            send(&mut peers, &binding_request("attacker", b"pa", 6), other);
        }
        assert_eq!(
            attacker.addrs.load(Ordering::Acquire),
            MAX_ADDRS_PER_SESSION
        );
        let before = DemuxStats::get(&stats.stun_rejected);
        send(&mut peers, &binding_request("attacker", b"pa", 10), shared);
        assert_eq!(DemuxStats::get(&stats.stun_rejected), before + 1);
        send(&mut peers, b"media", shared);
        assert_eq!(
            victim_sink.frames.lock().unwrap().last().unwrap().2,
            b"media",
            "still the victim's"
        );
        assert_eq!(victim.addrs.load(Ordering::Acquire), 1);
    }

    #[test]
    fn responses_reach_the_waiting_transaction_and_addresses_are_capped() {
        let (demux, local) = demux();
        let responses = demux.responses();
        let stats = demux.stats();
        let mut rx = responses.expect([7; 12]);
        assert_eq!(responses.outstanding(), 1);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mapped: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let reply = Builder::new(Class::Success, METHOD_BINDING, [7; 12])
            .xor_mapped_address(mapped)
            .build();
        client.send_to(&reply, local).unwrap();
        let mut got = None;
        assert!(wait_for(|| {
            got = got.take().or_else(|| rx.try_recv().ok());
            got.is_some()
        }));
        let got = got.unwrap();
        assert_eq!(got.mapped, Some(mapped));
        assert_eq!(got.from, client.local_addr().unwrap());
        assert!(wait_for(|| DemuxStats::get(&stats.responses) == 1));
        // A response nobody waits for is unroutable.
        client.send_to(&reply, local).unwrap();
        assert!(wait_for(|| DemuxStats::get(&stats.unroutable) == 1));
        let forgotten = responses.expect([8; 12]);
        responses.forget(&[8; 12]);
        assert!(forgotten.blocking_recv().is_err());
        // Nine addresses for one session: the ninth is refused.
        let sink = Arc::new(MemorySink::default());
        demux
            .registrations()
            .register("cap", b"pw".to_vec(), sink.clone());
        for i in 0..9_u8 {
            let from = UdpSocket::bind("127.0.0.1:0").unwrap();
            let request = Builder::new(Class::Request, METHOD_BINDING, [10 + i; 12])
                .username("cap:x")
                .integrity(b"pw")
                .fingerprint()
                .build();
            from.send_to(&request, local).unwrap();
            let expected = usize::from(i.min(7)) + 1;
            assert!(wait_for(|| sink.frames.lock().unwrap().len() == expected));
        }
        assert!(wait_for(|| DemuxStats::get(&stats.stun_rejected) == 1));
        assert_eq!(DemuxStats::get(&stats.addresses_learned), 8);
        // Re-registering a ufrag closes the previous registration.
        let again = demux.registrations().register("cap", b"pw2".to_vec(), sink);
        assert!(!again.is_closed());
        demux.stop();
    }

    #[tokio::test]
    async fn the_receive_thread_waits_when_a_worker_made_the_socket_non_blocking() {
        let bound = super::super::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        // A worker's copy shares the open file description, blocking mode
        // included (fcntl(2) O_NONBLOCK).
        let workers_copy = bound.socket.try_clone().unwrap();
        workers_copy.set_nonblocking(true).unwrap();
        let demux = Demux::start(
            bound.socket,
            bound.local,
            bound.hosts,
            Arc::new(SystemClock),
        )
        .unwrap();
        let stats = demux.stats();
        SystemClock.sleep(Duration::from_millis(600)).await;
        let wakeups = DemuxStats::get(&stats.idle_wakeups);
        assert!(
            (1..=8).contains(&wakeups),
            "{wakeups} wake-ups in 600 ms: the thread must wait for datagrams, not spin"
        );
        // Datagrams still arrive.
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(b"not stun", bound.local).unwrap();
        assert!(wait_for(|| DemuxStats::get(&stats.unroutable) == 1));
        demux.stop();
    }

    /// The router without a socket, as the `rtp_demux` fuzz target drives
    /// it: every datagram lands in exactly one counter, and an IPv4-mapped
    /// source is learned as the IPv4 address it is (RFC 4291 §2.5.5.2).
    #[test]
    fn the_router_counts_every_datagram_once_rfc8445_7_2_2() {
        let registrations = Arc::new(Registrations::default());
        let responses = Arc::new(StunResponses::default());
        let stats = Arc::new(DemuxStats::default());
        let host: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let mut router = Router::new(
            Arc::clone(&registrations),
            Arc::clone(&responses),
            Relays::channel().1,
            Arc::clone(&stats),
            Arc::new(SystemClock),
            "[::]:3478".parse().unwrap(),
            &[host],
        );
        let sink = Arc::new(MemorySink::default());
        registrations.register("r1", b"pw".to_vec(), sink.clone());
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:5000".parse().unwrap();
        let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let request = |password: &[u8]| {
            Builder::new(Class::Request, METHOD_BINDING, [9; 12])
                .username("r1:x")
                .integrity(password)
                .fingerprint()
                .build()
        };
        router.route(b"junk", peer, None);
        router.route(&request(b"nope"), peer, None);
        router.route(&request(b"pw"), mapped, None);
        router.route(b"media", peer, None);
        let _waiting = responses.expect([5; 12]);
        let reply = Builder::new(Class::Success, METHOD_BINDING, [5; 12]).build();
        router.route(&reply, peer, None);
        let get = DemuxStats::get;
        assert_eq!(get(&stats.received), 5);
        assert_eq!(
            (
                get(&stats.unroutable),
                get(&stats.stun_rejected),
                get(&stats.forwarded),
                get(&stats.responses)
            ),
            (1, 1, 2, 1)
        );
        let frames = sink.frames.lock().unwrap();
        assert_eq!(
            frames
                .iter()
                .map(|(source, destination, payload)| (*source, *destination, payload.len()))
                .collect::<Vec<_>>(),
            [(peer, host, request(b"pw").len()), (peer, host, 5)]
        );
    }

    fn channel_data(number: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        turn::frame_channel_data(turn::Channel::new(number).unwrap(), data, false, &mut out)
            .unwrap();
        out
    }

    fn data_indication(peer: SocketAddr, data: Option<&[u8]>) -> Vec<u8> {
        let builder = Builder::new(Class::Indication, turn::METHOD_DATA, [3; 12])
            .xor_address(turn::ATTR_XOR_PEER_ADDRESS, peer);
        match data {
            Some(data) => builder.attribute(turn::ATTR_DATA, data),
            None => builder,
        }
        .build()
    }

    /// What a TURN server relays is the peer's datagram at the relayed
    /// address, routed as one from there on; the rest it sends is
    /// discarded, or its own responses, and nobody else's datagrams are
    /// unwrapped.
    #[test]
    fn rfc8656_11_4_and_12_6_a_turn_servers_datagrams_are_unwrapped_as_the_peers() {
        let registrations = Arc::new(Registrations::default());
        let responses = Arc::new(StunResponses::default());
        let stats = Arc::new(DemuxStats::default());
        let (relays, updates) = Relays::channel();
        let host: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let mut router = Router::new(
            Arc::clone(&registrations),
            Arc::clone(&responses),
            updates,
            Arc::clone(&stats),
            Arc::new(SystemClock),
            "[::]:3478".parse().unwrap(),
            &[host],
        );
        let sink = Arc::new(MemorySink::default());
        registrations.register("r1", b"pw".to_vec(), sink.clone());
        let server: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        let mapped_server: SocketAddr = "[::ffff:198.51.100.1]:3478".parse().unwrap();
        let relayed: SocketAddr = "203.0.113.1:50000".parse().unwrap();
        let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let mapped_peer: SocketAddr = "[::ffff:192.0.2.1]:5000".parse().unwrap();
        let stranger: SocketAddr = "192.0.2.2:6000".parse().unwrap();
        // Published under the IPv4-mapped form: the table is canonical.
        relays.publish(
            mapped_server,
            Some(Relay {
                relayed,
                channels: [
                    (turn::Channel::new(0x4000).unwrap(), peer),
                    (turn::Channel::new(0x4002).unwrap(), mapped_peer),
                ]
                .into(),
                permissions: [peer.ip()].into(),
            }),
        );
        let check = Builder::new(Class::Request, METHOD_BINDING, [9; 12])
            .username("r1:x")
            .integrity(b"pw")
            .fingerprint()
            .build();
        // The peer's check in a Data indication: learned, at the relayed address.
        router.route(&data_indication(peer, Some(&check)), mapped_server, None);
        // ChannelData on a bound channel, and an IPv4-mapped peer either way.
        router.route(&channel_data(0x4000, b"media"), server, None);
        router.route(&channel_data(0x4002, b"mapped"), server, None);
        router.route(
            &data_indication(mapped_peer, Some(b"indicated")),
            server,
            None,
        );
        // A response relayed from the peer is the peer's datagram, never
        // the answer to the supervisor's request.
        let _relayed_reply = responses.expect([6; 12]);
        let reply = Builder::new(Class::Success, METHOD_BINDING, [6; 12]).build();
        router.route(&data_indication(peer, Some(&reply)), server, None);
        assert_eq!(responses.outstanding(), 1);
        // Discarded: an unbound channel, ChannelData cut short, a peer
        // without a permission, an indication without data, nothing, and
        // what is neither STUN nor ChannelData.
        router.route(&channel_data(0x4001, b"x"), server, None);
        router.route(&channel_data(0x4000, b"xyz")[..5], server, None);
        router.route(&data_indication(stranger, Some(b"x")), server, None);
        router.route(&data_indication(peer, None), server, None);
        router.route(b"", server, None);
        router.route(&[0x80, 0, 0, 0], server, None);
        // The server's own response reaches its transaction, and its other
        // indications are its own too: unroutable, not discarded.
        let _waiting = responses.expect([5; 12]);
        router.route(
            &Builder::new(Class::Success, METHOD_BINDING, [5; 12]).build(),
            server,
            None,
        );
        router.route(
            &Builder::new(Class::Indication, METHOD_BINDING, [4; 12]).build(),
            server,
            None,
        );
        // ChannelData from anyone else is not unwrapped.
        router.route(&channel_data(0x4000, b"x"), stranger, None);
        // Withdrawn: the server's datagrams are no longer unwrapped.
        relays.publish(server, None);
        router.route(&channel_data(0x4000, b"late"), server, None);
        let get = DemuxStats::get;
        assert_eq!(get(&stats.received), 15);
        assert_eq!(
            (
                get(&stats.relayed),
                get(&stats.forwarded),
                get(&stats.relay_discarded),
                get(&stats.responses),
                get(&stats.unroutable),
                get(&stats.addresses_learned),
            ),
            (5, 5, 6, 1, 3, 1)
        );
        assert_eq!(
            *sink.frames.lock().unwrap(),
            [
                (peer, relayed, check),
                (peer, relayed, b"media".to_vec()),
                (peer, relayed, b"mapped".to_vec()),
                (peer, relayed, b"indicated".to_vec()),
                (peer, relayed, reply),
            ]
        );
        // A stopped router is not told.
        drop(router);
        relays.publish(server, None);
    }

    #[test]
    fn a_published_relay_is_logged_with_the_size_of_its_tables() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (relays, _updates) = Relays::channel();
        let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        relays.publish(
            "198.51.100.1:3478".parse().unwrap(),
            Some(Relay {
                relayed: "203.0.113.1:50000".parse().unwrap(),
                channels: [(turn::Channel::new(0x4000).unwrap(), peer)].into(),
                permissions: [peer.ip()].into(),
            }),
        );
        let published = captured.lines("turn relay published to the demux");
        assert!(
            published[0].contains("channels=1 permissions=1"),
            "{published:?}"
        );
    }

    #[test]
    fn the_worker_sink_reports_a_full_channel() {
        let (ours, theirs) = datagram::datagram_pair().unwrap();
        let ours = UnixDatagram::from(ours);
        ours.set_nonblocking(true).unwrap();
        let sink = WorkerSink {
            datagrams: Arc::new(ours),
        };
        let frame = vec![1_u8; 1200];
        let sent = (0..=100_000).take_while(|_| sink.forward(&frame)).count();
        assert!(sent > 0 && sent <= 100_000, "{sent} frames until full");
        drop(theirs);
        assert!(!sink.forward(&frame), "a closed peer is a drop too");
        // A worker takes its ICE-TCP connections through its driver, not
        // through this sink.
        let tcp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        assert!(!sink.ice_tcp(OwnedFd::from(tcp), peer, vec![1]));
    }

    #[test]
    fn a_read_that_found_nothing_or_failed_is_counted_or_logged_and_routes_nothing() {
        let captured = Captured::default();
        let _logs = captured.install();
        let stats = Arc::new(DemuxStats::default());
        let mut router = Router::new(
            Arc::new(Registrations::default()),
            Arc::new(StunResponses::default()),
            Relays::channel().1,
            Arc::clone(&stats),
            Arc::new(SystemClock),
            "127.0.0.1:3478".parse().unwrap(),
            &[],
        );
        let mut buf = *b"junk";
        let slots = [IoSliceMut::new(&mut buf)];
        let mut meta = RecvMeta::default();
        meta.addr = "192.0.2.1:5000".parse().unwrap();
        meta.len = 4;
        meta.stride = 4;
        let metas = [meta];
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            route_read(Err(kind.into()), &slots, &metas, &mut router);
        }
        assert_eq!(DemuxStats::get(&stats.idle_wakeups), 2);
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        route_read(Err(refused), &slots, &metas, &mut router);
        assert_eq!(captured.lines("udp receive failed").len(), 1);
        assert_eq!(DemuxStats::get(&stats.received), 0);
        route_read(Ok(1), &slots, &metas, &mut router);
        assert_eq!(DemuxStats::get(&stats.unroutable), 1, "the read is routed");
    }

    /// A receive thread that cannot start (as at the process's thread
    /// limit, `EAGAIN`) is the caller's error.
    #[test]
    fn a_receive_thread_that_cannot_start_is_an_error() {
        let bound = super::super::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let started = Demux::start_with(
            bound.socket,
            bound.local,
            vec![],
            Arc::new(SystemClock),
            |_, _| Err(io::ErrorKind::WouldBlock.into()),
        );
        let_assert!(Err(err) = started, "no thread at the limit");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock, "{err}");
    }

    /// A flood of rejected STUN requests is counted request by request
    /// but logged as the first, then one summary per 10 s on the clock
    /// with the count since the last line; there is no
    /// per-address limit, so every source is rejected the same way.
    #[test]
    fn rejected_stun_requests_are_logged_rate_limited_on_the_clock() {
        let captured = Captured::default();
        let _logs = captured.install();
        let clock = Arc::new(FakeClock::default());
        let registrations = Arc::new(Registrations::default());
        let stats = Arc::new(DemuxStats::default());
        let sink = Arc::new(MemorySink::default());
        registrations.register("r1", b"pw".to_vec(), sink.clone());
        let mut peers = Peers::new(
            Arc::clone(&registrations),
            Arc::clone(&stats),
            Arc::<FakeClock>::clone(&clock),
        );
        let local: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let mut reject = |port: u16| {
            let request = binding_request("r1", b"wrong", 1);
            let message = stun::parse(&request).unwrap();
            let source = SocketAddr::new("192.0.2.1".parse().unwrap(), port);
            peers.route(&request, source, local, Some(&message));
        };
        for port in 1..=100 {
            reject(port);
        }
        let lines = || captured.lines("stun requests rejected");
        assert_eq!(lines().len(), 1);
        assert_eq!(SUMMARY_INTERVAL, Duration::from_secs(10));
        assert!(lines()[0].ends_with("rejected=1"), "{:?}", lines());
        clock.advance(Duration::from_millis(9_999));
        reject(101);
        assert_eq!(lines().len(), 1, "no line before the interval is up");
        clock.advance(Duration::from_millis(1));
        reject(102);
        let summary = lines();
        assert_eq!(summary.len(), 2);
        assert!(
            summary[1].ends_with("source=192.0.2.1:102 ufrag=Some(\"r1\") rejected=101"),
            "{summary:?}"
        );
        assert_eq!(DemuxStats::get(&stats.stun_rejected), 102);
        assert!(sink.frames.lock().unwrap().is_empty());
    }

    /// MESSAGE-INTEGRITY covers the message, not the IP header, so an
    /// on-path observer can replay a browser's verified check from spoofed
    /// sources and fill the session's 8 addresses; the browser's next real
    /// address (srflx after host, a network change) was then refused for
    /// the session's life. An address silent for RFC 7675 §5.1's 30 s
    /// consent timeout is forgotten when the session needs the room, and
    /// one that carries traffic, or another session's, is kept.
    #[test]
    fn rfc7675_5_1_replayed_checks_from_spoofed_sources_give_way_after_30_s_of_silence() {
        let captured = Captured::default();
        let _logs = captured.install();
        let clock = Arc::new(FakeClock::default());
        let registrations = Arc::new(Registrations::default());
        let stats = Arc::new(DemuxStats::default());
        let sink = Arc::new(MemorySink::default());
        let other_sink = Arc::new(MemorySink::default());
        registrations.register("s", b"pw".to_vec(), sink.clone());
        registrations.register("o", b"pw".to_vec(), other_sink.clone());
        let mut peers = Peers::new(
            Arc::clone(&registrations),
            Arc::clone(&stats),
            Arc::<FakeClock>::clone(&clock),
        );
        let local: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let at = |last: u8, port: u16| SocketAddr::new([198, 51, 100, last].into(), port);
        let check = binding_request("s", b"pw", 1);
        let send = |peers: &mut Peers, payload: &[u8], source: SocketAddr| {
            let message = stun::parse(payload).ok();
            peers.route(payload, source, local, message.as_ref());
        };
        let browser = at(1, 40_000);
        let srflx = at(2, 50_000);
        let other = at(3, 40_000);
        send(&mut peers, &binding_request("o", b"pw", 2), other);
        send(&mut peers, &check, browser);
        // The same captured check, replayed from seven spoofed sources.
        for port in 1..=7 {
            send(&mut peers, &check, at(66, port));
        }
        assert_eq!(DemuxStats::get(&stats.addresses_learned), 9);
        // The browser's next address is refused while the table is full,
        // the warning logged once.
        for _ in 0..5 {
            send(&mut peers, &binding_request("s", b"pw", 3), srflx);
        }
        assert_eq!(DemuxStats::get(&stats.stun_rejected), 5);
        assert_eq!(captured.lines("too many addresses").len(), 1);
        // The browser's own address keeps carrying media.
        clock.advance(Duration::from_secs(20));
        send(&mut peers, b"media", browser);
        clock.advance(Duration::from_millis(9_999));
        send(&mut peers, &binding_request("s", b"pw", 4), srflx);
        assert_eq!(DemuxStats::get(&stats.stun_rejected), 6, "silent 29.999 s");
        // 30 s after the replays: they are forgotten, the browser's
        // addresses and the other session's are not.
        clock.advance(Duration::from_millis(1));
        send(&mut peers, &binding_request("s", b"pw", 5), srflx);
        assert_eq!(DemuxStats::get(&stats.stun_rejected), 6);
        assert_eq!(DemuxStats::get(&stats.addresses_learned), 10);
        let mut kept: Vec<SocketAddr> = peers.by_addr.keys().copied().collect();
        kept.sort_unstable();
        assert_eq!(kept, [browser, srflx, other]);
        send(&mut peers, b"after", srflx);
        send(&mut peers, b"replayed media", at(66, 1));
        let sources: Vec<SocketAddr> = sink.frames.lock().unwrap().iter().map(|f| f.0).collect();
        assert_eq!(sources[sources.len() - 2..], [srflx, srflx]);
        assert_eq!(DemuxStats::get(&stats.unroutable), 1, "a forgotten source");
        assert_eq!(captured.lines("idle address forgotten").len(), 7);
        // Room for six more: the count went down with the forgotten ones.
        for port in 1..=6 {
            send(&mut peers, &check, at(77, port));
        }
        assert_eq!(DemuxStats::get(&stats.addresses_learned), 16);
        send(&mut peers, &check, at(77, 7));
        assert_eq!(DemuxStats::get(&stats.stun_rejected), 7);
        assert_eq!(other_sink.frames.lock().unwrap().len(), 1);
    }
}
