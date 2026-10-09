//! The ICE-TCP passive listener (RFC 6544): a connection is held until its
//! first RFC 4571 frame is a STUN Binding Request that names a registered
//! session and proves its password, then the connection is handed to that
//! session's worker; limits keep unauthenticated connections cheap, and a
//! budget per session ([`MAX_HAND_OFFS`] in [`HAND_OFF_WINDOW`]) the
//! verified ones, which anyone holding the session's password, or a
//! replayed check, can open. A peer of the dual-stack listener is taken in
//! canonical form, an IPv4-mapped address (RFC 4291 §2.5.5.2) as IPv4, as
//! the UDP demux does.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use lotse_core::backoff::AcceptBackoff;
use lotse_core::clock::Clock;
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use super::demux::{
    ADDR_IDLE_EXPIRY, MAX_ADDRS_PER_SESSION, Registration, Registrations, canonical,
};
use super::stun;

/// Connections handed to one session within [`HAND_OFF_WINDOW`]; a
/// verified connection past them is closed. The session's address budget:
/// each connection is one more address its worker serves it on, and the
/// worker holds a few of them at once and closes the silent ones, so a
/// browser's handful of pairs fits while a flood never reaches the worker.
pub const MAX_HAND_OFFS: usize = MAX_ADDRS_PER_SESSION;

/// The window [`MAX_HAND_OFFS`] counts in: RFC 7675 §5.1's consent
/// timeout, after which the worker closes a connection that carried
/// nothing.
pub const HAND_OFF_WINDOW: Duration = ADDR_IDLE_EXPIRY;

impl Registration {
    /// Counts an ICE-TCP hand-off at `now` unless the session had
    /// [`MAX_HAND_OFFS`] within the [`HAND_OFF_WINDOW`] before it; `false`
    /// when it had.
    fn claim_hand_off(&self, now: Instant) -> bool {
        let mut hand_offs = self
            .hand_offs
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while hand_offs
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= HAND_OFF_WINDOW)
        {
            hand_offs.pop_front();
        }
        if hand_offs.len() >= MAX_HAND_OFFS {
            return false;
        }
        hand_offs.push_back(now);
        true
    }
}

/// The listener's limits on unauthenticated connections and the deadline
/// for their first frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IceTcpConfig {
    /// Unauthenticated connections held at once.
    pub max_pending: usize,
    /// Of those, from one source address.
    pub max_per_ip: usize,
    /// How long the first frame may take.
    pub first_frame_deadline: Duration,
}

impl Default for IceTcpConfig {
    fn default() -> Self {
        Self {
            max_pending: 64,
            max_per_ip: 4,
            first_frame_deadline: Duration::from_secs(2),
        }
    }
}

/// The largest first frame accepted: a STUN request is far smaller.
const MAX_FIRST_FRAME: usize = 1500;

/// What the acceptor counted.
#[derive(Debug, Default)]
pub struct IceTcpStats {
    /// Connections accepted.
    pub accepted: AtomicU64,
    /// Refused at accept for a limit.
    pub refused: AtomicU64,
    /// Handed to a worker.
    pub handed_off: AtomicU64,
    /// Closed for a missing, late, unverifiable or foreign first frame.
    pub rejected: AtomicU64,
    /// Verified, but closed: the session had its [`MAX_HAND_OFFS`].
    pub over_budget: AtomicU64,
    /// `accept` calls that failed (descriptors exhausted), each followed
    /// by a pause.
    pub accept_failed: AtomicU64,
}

impl IceTcpStats {
    /// The value of one counter.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// The pending-connection accounting.
#[derive(Debug, Default)]
struct Pending {
    /// In total.
    total: AtomicUsize,
    /// Per source address.
    per_ip: Mutex<HashMap<IpAddr, usize>>,
}

impl Pending {
    /// Counts one more pending connection for `ip` unless it is at the
    /// limit; `true` when over.
    fn claim_ip(per_ip: &mut HashMap<IpAddr, usize>, ip: IpAddr, max_per_ip: usize) -> bool {
        let for_ip = per_ip.entry(ip).or_insert(0);
        if *for_ip >= max_per_ip {
            return true;
        }
        *for_ip = for_ip.saturating_add(1);
        false
    }
}

/// Releases a pending slot when dropped.
struct Slot {
    /// The accounting.
    pending: Arc<Pending>,
    /// The source address.
    ip: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.pending.total.fetch_sub(1, Ordering::AcqRel);
        let mut per_ip = self
            .pending
            .per_ip
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // A slot's address is counted until its last slot drops.
        let left = per_ip.get_mut(&self.ip).map(|count| {
            *count = count.saturating_sub(1);
            *count
        });
        if left == Some(0) {
            per_ip.remove(&self.ip);
        }
    }
}

impl Pending {
    /// Takes a slot for `ip`, if the limits allow.
    fn take(self: &Arc<Self>, ip: IpAddr, config: &IceTcpConfig) -> Option<Slot> {
        let total = self.total.fetch_add(1, Ordering::AcqRel);
        if total >= config.max_pending {
            self.total.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        let over_ip = Self::claim_ip(
            &mut self.per_ip.lock().unwrap_or_else(PoisonError::into_inner),
            ip,
            config.max_per_ip,
        );
        if over_ip {
            self.total.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Slot {
            pending: Arc::clone(self),
            ip,
        })
    }
}

/// What every pending connection shares.
struct Acceptor {
    /// The sessions.
    registrations: Arc<Registrations>,
    /// The limits and the deadline.
    config: IceTcpConfig,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// The counters.
    stats: Arc<IceTcpStats>,
    /// The log line for verified connections over their session's budget:
    /// the first, then a summary per
    /// [`lotse_core::throttle::SUMMARY_INTERVAL`].
    over_budget_log: Mutex<Throttle>,
}

/// Accepts connections until cancelled. A failed `accept` is retried
/// after a pause on `clock`, the [`AcceptBackoff`] schedule (10 ms doubling
/// to 1 s), reset by the next success.
pub async fn accept_loop(
    listener: TcpListener,
    registrations: Arc<Registrations>,
    config: IceTcpConfig,
    clock: Arc<dyn Clock>,
    stats: Arc<IceTcpStats>,
    cancel: CancellationToken,
) {
    let pending = Arc::new(Pending::default());
    let acceptor = Arc::new(Acceptor {
        registrations,
        config,
        clock,
        stats,
        over_budget_log: Mutex::default(),
    });
    let mut backoff = AcceptBackoff::new();
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => {
                    backoff.reset();
                    accepted
                }
                Err(err) => {
                    // `EMFILE` and the like leave the connection queued and
                    // the listener readable: retrying at once would spin.
                    acceptor.stats.accept_failed.fetch_add(1, Ordering::Relaxed);
                    let pause = backoff.next_delay();
                    let backoff_ms = pause.as_millis();
                    tracing::warn!(error = %err, backoff_ms, "ice-tcp accept failed; retrying after a pause");
                    tokio::select! {
                        () = acceptor.clock.sleep(pause) => {}
                        () = cancel.cancelled() => return,
                    }
                    continue;
                }
            },
            () = cancel.cancelled() => return,
        };
        // A dual-stack listener reports IPv4 peers IPv4-mapped; from here
        // on (limits, logs, the hand-off and the worker's ICE agent) the
        // peer is the address the UDP path and the host candidates use.
        let peer = canonical(peer);
        acceptor.stats.accepted.fetch_add(1, Ordering::Relaxed);
        let Some(slot) = pending.take(peer.ip(), &acceptor.config) else {
            acceptor.stats.refused.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, "ice-tcp connection refused: pending limit");
            drop(stream);
            continue;
        };
        let _task = spawn_named(
            "ice_tcp.pending",
            first_frame(stream, peer, slot, Arc::clone(&acceptor)),
        );
    }
}

/// Reads the first RFC 4571 frame within the deadline and hands the
/// connection over when it names a session with budget left.
async fn first_frame(mut stream: TcpStream, peer: SocketAddr, slot: Slot, acceptor: Arc<Acceptor>) {
    let deadline = acceptor.config.first_frame_deadline;
    let read = async {
        let mut len = [0_u8; 2];
        stream.read_exact(&mut len).await.ok()?;
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 || len > MAX_FIRST_FRAME {
            return None;
        }
        let mut frame = vec![0_u8; len];
        stream.read_exact(&mut frame).await.ok()?;
        Some(frame)
    };
    let frame = tokio::select! {
        frame = read => frame,
        () = acceptor.clock.sleep(deadline) => None,
    };
    drop(slot);
    let verified = frame.and_then(|frame| {
        verified_session(&frame, &acceptor.registrations).map(|registration| (frame, registration))
    });
    let Some((frame, registration)) = verified else {
        acceptor.stats.rejected.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(%peer, "ice-tcp connection closed without a verified first frame");
        return;
    };
    let now = acceptor.clock.now();
    if !registration.claim_hand_off(now) {
        acceptor.stats.over_budget.fetch_add(1, Ordering::Relaxed);
        let due = acceptor
            .over_budget_log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hit(now);
        if let Some(refused) = due {
            tracing::warn!(%peer, ufrag = registration.local_ufrag, refused, max = MAX_HAND_OFFS, "session had its ice-tcp connections; verified connection closed");
        }
        return;
    }
    let handed = stream.into_std().is_ok_and(|std_stream| {
        registration
            .sink
            .ice_tcp(OwnedFd::from(std_stream), peer, frame)
    });
    if handed {
        acceptor.stats.handed_off.fetch_add(1, Ordering::Relaxed);
        tracing::info!(%peer, "ice-tcp connection handed to its worker");
    } else {
        acceptor.stats.rejected.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(%peer, "ice-tcp connection closed: its worker could not take it");
    }
}

/// The live session a first frame names, when it is a Binding Request
/// that proves the session's password (RFC 8489 §14.5) and carries a
/// valid fingerprint (§14.7).
fn verified_session(frame: &[u8], registrations: &Registrations) -> Option<Arc<Registration>> {
    let message = stun::parse(frame).ok()?;
    if !message.is_binding_request() {
        return None;
    }
    message
        .local_ufrag()
        .and_then(|ufrag| registrations.get(ufrag))
        .filter(|registration| {
            !registration.is_closed()
                && message.verify_integrity(frame, &registration.password)
                && message.fingerprint_ok(frame)
        })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::fd::AsRawFd as _;

    use lotse_core::clock::{FakeClock, SystemClock};
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    use tokio::io::AsyncWriteExt as _;

    use super::super::demux::test_support::MemorySink;
    use super::*;
    use crate::net::stun::{Builder, Class, METHOD_BINDING};

    struct Running {
        addr: SocketAddr,
        registrations: Arc<Registrations>,
        stats: Arc<IceTcpStats>,
        cancel: CancellationToken,
    }

    fn start(config: IceTcpConfig) -> Running {
        let std_listener = super::super::udp::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        start_on(TcpListener::from_std(std_listener).unwrap(), config)
    }

    /// The listener on `[::]`, which a probe from `127.0.0.1` reaches.
    /// Linux, where the tests run, never shares the port with another
    /// listener on `127.0.0.1` (macOS did, observed 2026-10-07).
    async fn dual_stack_listener() -> TcpListener {
        let std_listener = super::super::udp::bind_tcp("[::]:0".parse().unwrap()).unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();
        let port = listener.local_addr().unwrap().port();
        let probe = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (_accepted, from) = listener.accept().await.unwrap();
        assert_eq!(from.port(), probe.local_addr().unwrap().port());
        listener
    }

    fn start_on(listener: TcpListener, config: IceTcpConfig) -> Running {
        start_with_clock(listener, config, Arc::new(SystemClock))
    }

    fn start_with_clock(
        listener: TcpListener,
        config: IceTcpConfig,
        clock: Arc<dyn Clock>,
    ) -> Running {
        let addr = listener.local_addr().unwrap();
        let registrations = Arc::new(Registrations::default());
        let stats = Arc::new(IceTcpStats::default());
        let cancel = CancellationToken::new();
        let _task = spawn_named(
            "test.ice_tcp",
            accept_loop(
                listener,
                Arc::clone(&registrations),
                config,
                clock,
                Arc::clone(&stats),
                cancel.clone(),
            ),
        );
        Running {
            addr,
            registrations,
            stats,
            cancel,
        }
    }

    /// Waits up to two seconds for `counter` to reach `expected`, looking
    /// after each 10 ms.
    async fn settle(stats: &IceTcpStats, counter: impl Fn(&IceTcpStats) -> u64, expected: u64) {
        let mut seen = None;
        let mut looks = 0;
        while seen != Some(expected) && looks < 200 {
            SystemClock.sleep(Duration::from_millis(10)).await;
            looks += 1;
            seen = Some(counter(stats));
        }
        assert_eq!(seen, Some(expected));
    }

    #[test]
    fn a_slot_is_refused_over_the_total_or_the_per_address_limit() {
        let pending = Arc::new(Pending::default());
        let config = IceTcpConfig {
            max_pending: 2,
            max_per_ip: 1,
            first_frame_deadline: Duration::from_secs(1),
        };
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let first = pending.take(a, &config).unwrap();
        assert!(
            pending.take(a, &config).is_none(),
            "over the per-address limit"
        );
        let second = pending.take(b, &config).unwrap();
        assert!(
            pending
                .take("192.0.2.3".parse().unwrap(), &config)
                .is_none(),
            "over the total"
        );
        assert_eq!(pending.total.load(Ordering::Acquire), 2);
        drop((first, second));
        assert_eq!(pending.total.load(Ordering::Acquire), 0);
        assert!(pending.per_ip.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_verified_first_frame_hands_the_connection_over() {
        let running = start(IceTcpConfig::default());
        let sink = Arc::new(MemorySink::default());
        running
            .registrations
            .register("tcpu", b"tcp-pass".to_vec(), sink.clone());
        let request = Builder::new(Class::Request, METHOD_BINDING, [5; 12])
            .username("tcpu:peer")
            .integrity(b"tcp-pass")
            .fingerprint()
            .build();
        let mut client = TcpStream::connect(running.addr).await.unwrap();
        let mut framed = u16::try_from(request.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&request);
        client.write_all(&framed).await.unwrap();
        settle(&running.stats, |s| IceTcpStats::get(&s.handed_off), 1).await;
        {
            let handed = sink.tcp.lock().unwrap();
            assert_eq!(handed.len(), 1);
            assert_eq!(handed[0].0, client.local_addr().unwrap());
            assert_eq!(handed[0].1, request);
        }
        // A wrong password, a non-STUN frame and an oversize length are closed.
        let wrong = Builder::new(Class::Request, METHOD_BINDING, [6; 12])
            .username("tcpu:peer")
            .integrity(b"nope")
            .fingerprint()
            .build();
        for frame in [wrong, b"GET / HTTP/1.1".to_vec()] {
            let mut client = TcpStream::connect(running.addr).await.unwrap();
            let mut framed = u16::try_from(frame.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&frame);
            client.write_all(&framed).await.unwrap();
        }
        let mut oversize = TcpStream::connect(running.addr).await.unwrap();
        oversize.write_all(&0xffff_u16.to_be_bytes()).await.unwrap();
        settle(&running.stats, |s| IceTcpStats::get(&s.rejected), 3).await;
        assert_eq!(IceTcpStats::get(&running.stats.handed_off), 1);
        running.cancel.cancel();
    }

    /// A Binding Request for `tcpu` in its RFC 4571 frame.
    fn framed_request(id: u8) -> Vec<u8> {
        let request = Builder::new(Class::Request, METHOD_BINDING, [id; 12])
            .username("tcpu:peer")
            .integrity(b"tcp-pass")
            .fingerprint()
            .build();
        let mut framed = u16::try_from(request.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&request);
        framed
    }

    /// A Binding Request for `ufrag` under `password` in its RFC 4571
    /// frame.
    fn framed_for(ufrag: &str, password: &[u8], id: u8) -> Vec<u8> {
        let request = Builder::new(Class::Request, METHOD_BINDING, [id; 12])
            .username(&format!("{ufrag}:peer"))
            .integrity(password)
            .fingerprint()
            .build();
        let mut framed = u16::try_from(request.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&request);
        framed
    }

    /// Whether the acceptor closed `client`'s connection.
    async fn closed(client: &mut TcpStream) -> bool {
        let mut buf = [0_u8; 1];
        tokio::select! {
            read = client.read(&mut buf) => matches!(read, Ok(0)),
            () = SystemClock.sleep(Duration::from_secs(5)) => false,
        }
    }

    #[tokio::test]
    async fn a_session_gets_max_hand_offs_per_window_and_the_rest_are_closed() {
        // WRK-20: every verified connection used to reach the worker, so a
        // session's viewer, or a replayer of its checks, could hand it
        // hundreds. Past the budget they are closed here; an unverified
        // one costs no budget, and each session has its own.
        let clock = Arc::new(FakeClock::default());
        let std_listener = super::super::udp::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let running = start_with_clock(
            TcpListener::from_std(std_listener).unwrap(),
            IceTcpConfig::default(),
            clock.clone(),
        );
        let flooded = Arc::new(MemorySink::default());
        let other = Arc::new(MemorySink::default());
        running
            .registrations
            .register("tcpu", b"tcp-pass".to_vec(), flooded.clone());
        running
            .registrations
            .register("other", b"other-pass".to_vec(), other.clone());
        let send = async |frame: Vec<u8>| {
            let mut client = TcpStream::connect(running.addr).await.unwrap();
            client.write_all(&frame).await.unwrap();
            client
        };
        let mut kept = Vec::new();
        for id in 0..MAX_HAND_OFFS {
            kept.push(send(framed_request(u8::try_from(id).unwrap())).await);
            let handed = u64::try_from(id + 1).unwrap();
            settle(&running.stats, |s| IceTcpStats::get(&s.handed_off), handed).await;
        }
        for id in 0..3 {
            let mut over = send(framed_request(100 + id)).await;
            assert!(closed(&mut over).await);
        }
        assert_eq!(IceTcpStats::get(&running.stats.over_budget), 3);
        assert_eq!(flooded.tcp.lock().unwrap().len(), MAX_HAND_OFFS);
        // A wrong password, or a STUN message other than a Binding
        // Request, is rejected before the budget is consulted.
        let mut wrong = send(framed_for("tcpu", b"nope", 7)).await;
        assert!(closed(&mut wrong).await);
        let indication = Builder::new(Class::Indication, METHOD_BINDING, [9; 12])
            .username("tcpu:peer")
            .integrity(b"tcp-pass")
            .fingerprint()
            .build();
        let mut framed = u16::try_from(indication.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&indication);
        let mut indication = send(framed).await;
        assert!(closed(&mut indication).await);
        assert_eq!(IceTcpStats::get(&running.stats.rejected), 2);
        assert_eq!(IceTcpStats::get(&running.stats.over_budget), 3);
        // Another session's budget is its own.
        let _other = send(framed_for("other", b"other-pass", 8)).await;
        settle(&running.stats, |s| IceTcpStats::get(&s.handed_off), 9).await;
        assert_eq!(other.tcp.lock().unwrap().len(), 1);
        // Just short of the window nothing has expired; at it, the oldest
        // hand-offs have and the session may take connections again.
        clock.advance(
            HAND_OFF_WINDOW
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        );
        let mut over = send(framed_request(110)).await;
        assert!(closed(&mut over).await);
        assert_eq!(IceTcpStats::get(&running.stats.over_budget), 4);
        clock.advance(Duration::from_millis(1));
        let _again = send(framed_request(111)).await;
        settle(&running.stats, |s| IceTcpStats::get(&s.handed_off), 10).await;
        assert_eq!(flooded.tcp.lock().unwrap().len(), MAX_HAND_OFFS + 1);
        drop(kept);
        running.cancel.cancel();
    }

    #[tokio::test]
    async fn a_connection_its_worker_cannot_take_is_closed_and_counted_rejected() {
        let running = start(IceTcpConfig::default());
        let sink = Arc::new(MemorySink::default());
        sink.full.store(true, Ordering::Relaxed);
        running
            .registrations
            .register("tcpu", b"tcp-pass".to_vec(), sink.clone());
        let mut client = TcpStream::connect(running.addr).await.unwrap();
        client.write_all(&framed_request(1)).await.unwrap();
        assert!(closed(&mut client).await);
        settle(&running.stats, |s| IceTcpStats::get(&s.rejected), 1).await;
        assert_eq!(IceTcpStats::get(&running.stats.handed_off), 0);
        running.cancel.cancel();
    }

    #[tokio::test]
    async fn a_dual_stack_listener_hands_mapped_peers_over_as_ipv4_rfc_4291_2_5_5_2() {
        // The dual-stack listener reports an IPv4 client as `::ffff:a.b.c.d`
        // (RFC 4291 §2.5.5.2); it is handed over as the IPv4 address it is,
        // the form the UDP path and the host candidates use, so logs and the
        // engine see one address per peer. A real IPv6 client stays IPv6.
        let running = start_on(dual_stack_listener().await, IceTcpConfig::default());
        let sink = Arc::new(MemorySink::default());
        running
            .registrations
            .register("tcpu", b"tcp-pass".to_vec(), sink.clone());
        let port = running.addr.port();
        let mut v4 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        v4.write_all(&framed_request(1)).await.unwrap();
        settle(&running.stats, |s| IceTcpStats::get(&s.handed_off), 1).await;
        let mut v6 = TcpStream::connect(("::1", port)).await.unwrap();
        v6.write_all(&framed_request(2)).await.unwrap();
        settle(&running.stats, |s| IceTcpStats::get(&s.handed_off), 2).await;
        let handed: Vec<SocketAddr> = sink.tcp.lock().unwrap().iter().map(|h| h.0).collect();
        let v4_peer = v4.local_addr().unwrap();
        let v6_peer = v6.local_addr().unwrap();
        assert!(v4_peer.is_ipv4() && v6_peer.is_ipv6());
        assert_eq!(handed, [v4_peer, v6_peer]);
        running.cancel.cancel();
    }

    #[tokio::test]
    async fn silent_connections_time_out_and_limits_refuse_the_excess() {
        let running = start(IceTcpConfig {
            max_pending: 3,
            max_per_ip: 2,
            first_frame_deadline: Duration::from_millis(100),
        });
        let first = TcpStream::connect(running.addr).await.unwrap();
        let second = TcpStream::connect(running.addr).await.unwrap();
        // The third from the same address is over the per-address limit.
        let third = TcpStream::connect(running.addr).await.unwrap();
        settle(&running.stats, |s| IceTcpStats::get(&s.refused), 1).await;
        // The silent ones are closed after the deadline.
        settle(&running.stats, |s| IceTcpStats::get(&s.rejected), 2).await;
        drop((first, second, third));
        assert_eq!(IceTcpStats::get(&running.stats.accepted), 3);
        running.cancel.cancel();
    }

    /// Lowers this process's descriptor limit to its lowest free
    /// descriptor, so the next `accept` fails with `EMFILE`; returns the
    /// limit to restore. nextest runs each test in its own process.
    fn starve_descriptors() -> Rlimit {
        let limit = getrlimit(Resource::Nofile);
        let probe = std::fs::File::open("/dev/null").unwrap();
        let lowest = u64::try_from(probe.as_raw_fd()).unwrap();
        drop(probe);
        let starved = Rlimit {
            current: Some(lowest),
            maximum: limit.maximum,
        };
        setrlimit(Resource::Nofile, starved).unwrap();
        limit
    }

    /// Polls `future` for `rounds` scheduler turns; its output if it
    /// finished.
    async fn drive<F: Future + Unpin>(future: &mut F, rounds: usize) -> Option<F::Output> {
        for _ in 0..rounds {
            tokio::select! {
                biased;
                out = &mut *future => return Some(out),
                () = tokio::task::yield_now() => {}
            }
        }
        None
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failing_accept_backs_off_on_the_clock_and_resets_on_success() {
        let std_listener = super::super::udp::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();
        let addr = listener.local_addr().unwrap();
        let clock = Arc::new(FakeClock::default());
        let stats = Arc::new(IceTcpStats::default());
        let cancel = CancellationToken::new();
        let failed = || IceTcpStats::get(&stats.accept_failed);
        // Linux keeps a connection queued when `accept` fails with
        // `EMFILE`; macOS may drop it, so every failure there needs one of
        // its own.
        let mut queued = Vec::new();
        for _ in 0..8 {
            queued.push(TcpStream::connect(addr).await.unwrap());
        }
        let mut accepting = Box::pin(accept_loop(
            listener,
            Arc::new(Registrations::default()),
            IceTcpConfig::default(),
            Arc::<FakeClock>::clone(&clock),
            Arc::clone(&stats),
            cancel.clone(),
        ));
        let limit = starve_descriptors();
        assert!(drive(&mut accepting, 50).await.is_none());
        assert_eq!(failed(), 1, "one failure per pause, no spin");
        // 10 ms, then 20 ms.
        clock.advance(Duration::from_millis(9));
        assert!(drive(&mut accepting, 50).await.is_none());
        assert_eq!(failed(), 1);
        clock.advance(Duration::from_millis(1));
        assert!(drive(&mut accepting, 50).await.is_none());
        assert_eq!(failed(), 2);
        clock.advance(Duration::from_millis(19));
        assert!(drive(&mut accepting, 50).await.is_none());
        assert_eq!(failed(), 2);
        clock.advance(Duration::from_millis(1));
        assert!(drive(&mut accepting, 50).await.is_none());
        assert_eq!(failed(), 3);
        setrlimit(Resource::Nofile, limit).unwrap();
        clock.advance(Duration::from_millis(40));
        assert!(drive(&mut accepting, 50).await.is_none());
        let accepted = IceTcpStats::get(&stats.accepted);
        assert!(accepted >= 1, "the queue drains once descriptors are free");

        // A success resets the pause to 10 ms.
        for _ in 0..4 {
            queued.push(TcpStream::connect(addr).await.unwrap());
        }
        let limit = starve_descriptors();
        assert!(drive(&mut accepting, 50).await.is_none());
        assert_eq!(failed(), 4);
        clock.advance(Duration::from_millis(9));
        assert!(drive(&mut accepting, 50).await.is_none());
        assert_eq!(failed(), 4);
        clock.advance(Duration::from_millis(1));
        assert!(drive(&mut accepting, 50).await.is_none());
        assert_eq!(failed(), 5);
        // Cancelled during a pause, the loop ends at once.
        cancel.cancel();
        assert_eq!(drive(&mut accepting, 50).await, Some(()));
        setrlimit(Resource::Nofile, limit).unwrap();
        assert_eq!(IceTcpStats::get(&stats.accepted), accepted);
        assert_eq!(queued.len(), 12, "the clients stayed connected until here");
    }
}
