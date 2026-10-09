//! A session's ICE-TCP connections: the passive side of RFC 6544 with RFC
//! 4571 framing. The supervisor accepted each connection, verified its
//! first STUN request and passed the descriptor on; here one reader task
//! turns frames into the session's inbound datagrams, and one writer task
//! frames what the engine sends.
//!
//! RFC 4571 §2: every frame is a 16-bit big-endian length and that many
//! bytes, so no frame exceeds 65535 bytes and a reader never allocates more
//! than that. The engine never waits on a connection: a full writer queue
//! drops the datagram, as a full UDP socket buffer does. The engine's own
//! datagram goes into the queue, and the writer frames it in a buffer it
//! reuses, so a datagram costs no allocation here.
//!
//! A session holds at most [`MAX_LINKS`] connections, and one that
//! delivers no frame for [`LINK_IDLE`] is closed, as is one the browser
//! ended: a viewer's flood of connections costs the worker a bounded number
//! of descriptors and tasks, never all of them.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::Clock;
use lotse_core::session::Transport;
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::sessions::Inbound;

/// Frames a connection's writer holds before the engine's sends drop.
const WRITE_QUEUE: usize = 256;

/// Connections one session holds at once; the next one is closed. A
/// browser opens one per candidate pair it checks over TCP (RFC 6544
/// §7.1), the pairs of its active candidates with this session's passive
/// ones of the same family, and uses the one it nominates: one or two in
/// practice, so four leave room while sixteen sessions of a camera hold
/// at most 64 of the worker's descriptors.
pub(crate) const MAX_LINKS: usize = 4;

/// A connection that delivered no frame for this long is closed: RFC 7675
/// §5.1's consent timeout. A browser sends a consent check on the pair it
/// uses every 4 to 6 s (§5.1), so a connection silent this long carries no
/// pair it uses.
pub(crate) const LINK_IDLE: Duration = Duration::from_secs(30);

/// One connection; dropping it ends both of its tasks.
#[derive(Debug)]
struct Link {
    /// The writer's queue of datagrams, each at most a frame long.
    frames: mpsc::Sender<Vec<u8>>,
    /// The reader task; finished once the connection ended.
    reader: JoinHandle<()>,
    /// The writer task.
    writer: JoinHandle<()>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

/// A session's ICE-TCP connections by the browser's address; dropping it
/// ends them all.
///
/// Every address here is in canonical form (IPv4-mapped IPv6 as IPv4): the
/// supervisor hands peers over canonical and [`Links::attach`] makes the
/// local side so, the forms of the host candidates. The engine's
/// transmissions name the same form, so they find their connection, and an
/// IPv6 peer stays IPv6 throughout.
#[derive(Debug)]
pub(crate) struct Links {
    /// By peer, canonical; at most [`MAX_LINKS`] whose reader runs.
    by_peer: HashMap<SocketAddr, Link>,
    /// Times the connections' silence and the rate limit of the log line.
    clock: Arc<dyn Clock>,
    /// The log line for connections closed at the cap: the first, then a
    /// summary per [`lotse_core::throttle::SUMMARY_INTERVAL`].
    full_log: Throttle,
}

impl Links {
    /// No connection yet; `clock` times their silence.
    pub(crate) fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            by_peer: HashMap::new(),
            clock,
            full_log: Throttle::default(),
        }
    }

    /// Takes a connection from `peer`, canonical as the supervisor hands
    /// it over: frames read from it go to `inbound` as TCP datagrams.
    /// Returns the connection's local address in canonical form, the
    /// destination of its datagrams; `None` when the session already holds
    /// [`MAX_LINKS`] live connections from other peers, and this one was
    /// closed. A new connection from a known peer replaces its old one.
    pub(crate) fn attach(
        &mut self,
        stream: std::net::TcpStream,
        peer: SocketAddr,
        inbound: mpsc::Sender<Inbound>,
    ) -> io::Result<Option<SocketAddr>> {
        // Ended connections give their place up first.
        self.by_peer.retain(|_, link| !link.reader.is_finished());
        if self.by_peer.len() >= MAX_LINKS && !self.by_peer.contains_key(&peer) {
            if let Some(refused) = self.full_log.hit(self.clock.now()) {
                tracing::warn!(%peer, refused, max = MAX_LINKS, "session has too many ice-tcp connections; connection closed");
            }
            return Ok(None);
        }
        stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(stream)?;
        let local = stream.local_addr()?;
        let local = SocketAddr::new(local.ip().to_canonical(), local.port());
        let (read, write) = stream.into_split();
        let (frames, queue) = mpsc::channel(WRITE_QUEUE);
        // The reader's end ends the writer, and with both halves gone the
        // descriptor closes.
        let ended = CancellationToken::new();
        let reader = spawn_named(
            "ice_tcp.read",
            read_frames(
                read,
                Endpoints { peer, local },
                inbound,
                Arc::clone(&self.clock),
                ended.clone().drop_guard(),
            ),
        );
        let writer = spawn_named("ice_tcp.write", write_frames(write, queue, ended));
        self.by_peer.insert(
            peer,
            Link {
                frames,
                reader,
                writer,
            },
        );
        tracing::info!(%peer, %local, links = self.by_peer.len(), "ice-tcp connection attached");
        Ok(Some(local))
    }

    /// Queues `payload` as one frame for the connection to `peer`; `false`
    /// when there is none, it is full or gone, or the payload exceeds a
    /// frame.
    pub(crate) fn send(&self, peer: SocketAddr, payload: Vec<u8>) -> bool {
        let (Ok(_), Some(link)) = (u16::try_from(payload.len()), self.by_peer.get(&peer)) else {
            return false;
        };
        link.frames.try_send(payload).is_ok()
    }
}

/// The two ends of a connection, canonical.
#[derive(Debug, Clone, Copy)]
struct Endpoints {
    /// The browser's.
    peer: SocketAddr,
    /// Ours.
    local: SocketAddr,
}

/// Reads frames until the connection ends, the session goes or a frame
/// takes [`LINK_IDLE`] to arrive, handing each to the session. `_ended`
/// stops the writer when this returns or is aborted.
async fn read_frames(
    mut read: OwnedReadHalf,
    ends: Endpoints,
    inbound: mpsc::Sender<Inbound>,
    clock: Arc<dyn Clock>,
    _ended: DropGuard,
) {
    let Endpoints { peer, local } = ends;
    let ended = loop {
        let frame = async {
            let len = usize::from(read.read_u16().await?);
            let mut payload = vec![0_u8; len];
            read.read_exact(&mut payload).await?;
            Ok::<_, io::Error>(payload)
        };
        // Cancelling a read mid-frame loses its bytes; it happens only
        // when the connection closes anyway.
        let payload = tokio::select! {
            frame = frame => match frame {
                Ok(payload) => payload,
                Err(err) => break err,
            },
            () = clock.sleep(LINK_IDLE) => {
                let idle_s = LINK_IDLE.as_secs();
                tracing::info!(%peer, idle_s, "ice-tcp connection silent for the consent timeout; closed");
                return;
            }
        };
        let datagram = Inbound {
            transport: Transport::Tcp,
            source: peer,
            destination: local,
            payload,
        };
        // A full queue drops, like the UDP router; a closed one means the
        // session ended.
        if let Err(mpsc::error::TrySendError::Closed(_)) = inbound.try_send(datagram) {
            return;
        }
    };
    tracing::debug!(%peer, error = %ended, "ice-tcp connection ended");
}

/// Writes queued frames until the queue closes, the connection fails or
/// its reader ended (`ended`).
async fn write_frames(
    mut write: OwnedWriteHalf,
    mut queue: mpsc::Receiver<Vec<u8>>,
    ended: CancellationToken,
) {
    let writing = async {
        let mut frame = Vec::new();
        while let Some(payload) = queue.recv().await {
            // `send` let only payloads that fit the length through.
            let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
            frame.clear();
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&payload);
            if let Err(err) = write.write_all(&frame).await {
                tracing::debug!(error = %err, "ice-tcp write failed");
                return;
            }
        }
    };
    tokio::select! {
        () = writing => {}
        () = ended.cancelled() => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::Duration;

    use lotse_core::clock::{FakeClock, SystemClock};
    use tokio::net::TcpListener;

    use super::*;

    /// A connected pair: the worker's end as std, the browser's as tokio.
    async fn pair() -> (std::net::TcpStream, TcpStream) {
        pair_on("127.0.0.1:0", "127.0.0.1").await
    }

    /// A pair whose worker end was accepted on a listener bound at `bind`,
    /// the browser connecting to `ip` at its port. The connection must
    /// arrive here: macOS picks `[::]:0`'s port among the IPv6 ports only,
    /// and std's `SO_REUSEADDR` lets it share one with another process's
    /// `127.0.0.1` listener, which then takes the IPv4 connection
    /// (observed 2026-10-07), so such a port is given up for another.
    async fn pair_on(bind: &str, ip: &str) -> (std::net::TcpStream, TcpStream) {
        let mut tries = 0;
        loop {
            tries += 1;
            assert!(tries <= 100, "no port at {bind} that {ip} reaches");
            let std_listener = std::net::TcpListener::bind(bind).unwrap();
            std_listener.set_nonblocking(true).unwrap();
            let listener = TcpListener::from_std(std_listener).unwrap();
            let port = listener.local_addr().unwrap().port();
            let browser = TcpStream::connect((ip, port)).await.unwrap();
            let ours = tokio::select! {
                accepted = listener.accept() => Some(accepted.unwrap().0),
                () = SystemClock.sleep(Duration::from_secs(1)) => None,
            };
            if let Some(ours) = ours.filter(|ours| {
                ours.peer_addr().unwrap().port() == browser.local_addr().unwrap().port()
            }) {
                return (ours.into_std().unwrap(), browser);
            }
        }
    }

    /// Attaches the worker end of `ours` for `peer` and checks that a frame
    /// each way arrives with canonical addresses of `peer`'s family.
    async fn frames_flow(ours: std::net::TcpStream, mut browser: TcpStream, peer: SocketAddr) {
        let (inbound, mut rx) = mpsc::channel(8);
        let mut links = Links::new(Arc::new(SystemClock));
        let local = links.attach(ours, peer, inbound).unwrap().unwrap();
        assert_eq!(local, browser.peer_addr().unwrap());
        assert_eq!(local.is_ipv4(), peer.is_ipv4(), "{local} for {peer}");
        browser.write_all(&[0, 2, b'i', b'n']).await.unwrap();
        let got = rx.recv().await.unwrap();
        assert_eq!(
            (got.transport, got.source, got.destination, &got.payload[..]),
            (Transport::Tcp, peer, local, &b"in"[..])
        );
        assert!(links.send(peer, b"out".to_vec()));
        let mut buf = [0_u8; 5];
        within(browser.read_exact(&mut buf)).await.unwrap();
        assert_eq!(&buf, b"\x00\x03out");
        // The connection is known by the canonical form only.
        if let std::net::IpAddr::V4(v4) = peer.ip() {
            let mapped = SocketAddr::new(v4.to_ipv6_mapped().into(), peer.port());
            assert!(!links.send(mapped, b"out".to_vec()));
        }
    }

    #[tokio::test]
    async fn a_mapped_ipv4_peer_on_a_dual_stack_listener_is_ipv4_throughout() {
        // The worker's end is IPv6 with both addresses IPv4-mapped; the
        // supervisor hands the peer over canonical, the local side is made
        // canonical here, and the engine's replies to the IPv4 peer find
        // their connection.
        let (ours, browser) = pair_on("[::]:0", "127.0.0.1").await;
        let raw = ours.peer_addr().unwrap();
        assert_eq!(raw.ip().to_string(), "::ffff:127.0.0.1");
        assert!(ours.local_addr().unwrap().is_ipv6());
        let peer = SocketAddr::new(raw.ip().to_canonical(), raw.port());
        assert_eq!(peer, browser.local_addr().unwrap());
        frames_flow(ours, browser, peer).await;
    }

    #[tokio::test]
    async fn a_native_ipv6_peer_stays_ipv6() {
        for bind in ["[::]:0", "[::1]:0"] {
            let (ours, browser) = pair_on(bind, "::1").await;
            let peer = browser.local_addr().unwrap();
            assert_eq!(peer.ip(), std::net::Ipv6Addr::LOCALHOST);
            frames_flow(ours, browser, peer).await;
        }
    }

    #[tokio::test]
    async fn frames_both_ways_per_rfc_4571_2() {
        let (ours, mut browser) = pair().await;
        let peer = browser.local_addr().unwrap();
        let (inbound, mut rx) = mpsc::channel(8);
        let mut links = Links::new(Arc::new(SystemClock));
        let local = links.attach(ours, peer, inbound).unwrap().unwrap();
        assert_eq!(local, browser.peer_addr().unwrap());

        // In: two frames in one write, an empty one between them.
        browser
            .write_all(&[0, 3, b'a', b'b', b'c', 0, 0, 0, 1, b'z'])
            .await
            .unwrap();
        for expected in [&b"abc"[..], b"", b"z"] {
            let got = rx.recv().await.unwrap();
            assert_eq!(got.payload, expected);
            assert_eq!(
                (got.transport, got.source, got.destination),
                (Transport::Tcp, peer, local)
            );
        }

        // Out: framed with the length first.
        assert!(links.send(peer, b"hello".to_vec()));
        let mut buf = [0_u8; 7];
        within(browser.read_exact(&mut buf)).await.unwrap();
        assert_eq!(&buf, b"\x00\x05hello");
        // Nothing for an unknown peer or above a frame.
        let max = usize::from(u16::MAX);
        assert!(!links.send("192.0.2.1:1".parse().unwrap(), vec![1]));
        assert!(!links.send(peer, vec![0; max + 1]));
        assert!(links.send(peer, vec![7; max]));
        let mut big = vec![0_u8; max + 2];
        within(browser.read_exact(&mut big)).await.unwrap();
        assert_eq!(&big[..2], &[0xff, 0xff]);

        // The browser leaves mid-frame: the reader ends; a reconnect
        // replaces the link.
        browser.write_all(&[0, 5, b'a']).await.unwrap();
        drop(browser);
        let (ours, browser) = pair().await;
        links
            .attach(ours, peer, mpsc::channel(1).0)
            .unwrap()
            .unwrap();
        assert_eq!(links.by_peer.len(), 1);
        drop(links);
        drop(browser);
    }

    #[tokio::test]
    async fn a_closed_session_ends_the_reader_and_a_dead_peer_the_writer() {
        let (ours, mut browser) = pair().await;
        let peer = browser.local_addr().unwrap();
        let (inbound, rx) = mpsc::channel(8);
        drop(rx);
        let mut links = Links::new(Arc::new(SystemClock));
        links.attach(ours, peer, inbound).unwrap().unwrap();
        browser.write_all(&[0, 1, b'x']).await.unwrap();
        // The reader returns on the closed queue; the browser sees EOF once
        // the writer goes too.
        drop(browser);
        let link = links.by_peer.get(&peer).unwrap();
        for _ in 0..10_000 {
            if link.reader.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(link.reader.is_finished());
        // Writes to the gone browser fail; the writer ends and sends drop.
        let mut refused = false;
        for _ in 0..10_000 {
            if !links.send(peer, vec![1; 1024]) {
                refused = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(refused, "sends to a dead peer stop being accepted");
    }

    #[tokio::test]
    async fn dropping_the_links_ends_their_tasks() {
        let (ours, browser) = pair().await;
        let peer = browser.local_addr().unwrap();
        let (inbound, mut rx) = mpsc::channel(8);
        let mut links = Links::new(Arc::new(SystemClock));
        links.attach(ours, peer, inbound).unwrap().unwrap();
        // The browser stays silent; only the abort ends the reader, and with
        // it the last sender of the session's queue.
        drop(links);
        tokio::select! {
            got = rx.recv() => assert!(got.is_none()),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("the reader outlived its links"),
        }
        drop(browser);
    }

    /// `future`'s output, or a failed test after five seconds of real time.
    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::select! {
            output = future => output,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
        }
    }

    /// Polls until `done` holds, yielding to the tasks in between.
    async fn until(mut done: impl FnMut() -> bool) {
        let mut turns = 0;
        while !done() {
            assert!(turns < 10_000, "not within 10 000 turns");
            turns += 1;
            tokio::task::yield_now().await;
        }
    }

    /// Whether the worker's side closed the browser's connection.
    async fn closed(browser: &mut TcpStream) -> bool {
        let mut buf = [0_u8; 1];
        tokio::select! {
            read = browser.read(&mut buf) => matches!(read, Ok(0)),
            () = SystemClock.sleep(Duration::from_secs(5)) => false,
        }
    }

    #[tokio::test]
    async fn a_session_holds_at_most_max_links_and_an_ended_one_gives_its_place_up() {
        // WRK-20: past the cap a connection is closed at once, so a flood
        // of them costs no descriptor; a known peer may still reconnect.
        let mut links = Links::new(Arc::new(SystemClock));
        let (inbound, _rx) = mpsc::channel(8);
        let mut browsers = Vec::new();
        for _ in 0..MAX_LINKS {
            let (ours, browser) = pair().await;
            let peer = browser.local_addr().unwrap();
            assert!(links.attach(ours, peer, inbound.clone()).unwrap().is_some());
            browsers.push(browser);
        }
        let (ours, mut over) = pair().await;
        let over_peer = over.local_addr().unwrap();
        assert_eq!(
            links.attach(ours, over_peer, inbound.clone()).unwrap(),
            None
        );
        assert!(closed(&mut over).await);
        assert!(!links.send(over_peer, b"x".to_vec()));
        assert_eq!(links.by_peer.len(), MAX_LINKS);

        // The same peer again replaces its connection, at the cap too.
        let known = browsers[0].local_addr().unwrap();
        let (ours, _again) = pair().await;
        assert!(
            links
                .attach(ours, known, inbound.clone())
                .unwrap()
                .is_some()
        );
        assert!(closed(&mut browsers[0]).await, "the replaced one is closed");
        assert_eq!(links.by_peer.len(), MAX_LINKS);

        // A browser leaves: its reader ends, and its place is free.
        let gone = browsers.pop().unwrap();
        let gone_peer = gone.local_addr().unwrap();
        drop(gone);
        until(|| links.by_peer[&gone_peer].reader.is_finished()).await;
        let (ours, browser) = pair().await;
        let peer = browser.local_addr().unwrap();
        assert!(links.attach(ours, peer, inbound).unwrap().is_some());
        assert!(!links.by_peer.contains_key(&gone_peer));
        assert_eq!(links.by_peer.len(), MAX_LINKS);
    }

    #[tokio::test]
    async fn rfc7675_5_1_a_connection_silent_for_the_consent_timeout_is_closed() {
        let clock = Arc::new(FakeClock::default());
        let mut links = Links::new(clock.clone());
        let (ours, mut browser) = pair().await;
        let peer = browser.local_addr().unwrap();
        let (inbound, mut rx) = mpsc::channel(8);
        links.attach(ours, peer, inbound).unwrap().unwrap();
        // A frame within the timeout restarts it.
        clock.advance(LINK_IDLE.checked_sub(Duration::from_secs(1)).unwrap());
        browser.write_all(&[0, 1, b'a']).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().payload, b"a");
        clock.advance(LINK_IDLE.checked_sub(Duration::from_secs(1)).unwrap());
        tokio::task::yield_now().await;
        assert!(links.send(peer, b"still".to_vec()));
        let mut buf = [0_u8; 7];
        within(browser.read_exact(&mut buf)).await.unwrap();
        assert_eq!(&buf, b"\x00\x05still");
        // Silent for the whole timeout: the reader ends, the writer with
        // it, and the browser sees the connection close.
        clock.advance(Duration::from_secs(1));
        assert!(closed(&mut browser).await);
        let link = &links.by_peer[&peer];
        until(|| link.reader.is_finished() && link.writer.is_finished()).await;
        assert!(!links.send(peer, b"gone".to_vec()));
    }

    #[tokio::test]
    async fn a_writer_stuck_on_a_peer_that_reads_nothing_ends_with_its_reader() {
        // A browser that neither reads nor writes: the writer blocks once
        // the socket buffers fill, and still ends when the reader gives up.
        let clock = Arc::new(FakeClock::default());
        let mut links = Links::new(clock.clone());
        let (ours, browser) = pair().await;
        let peer = browser.local_addr().unwrap();
        links
            .attach(ours, peer, mpsc::channel(8).0)
            .unwrap()
            .unwrap();
        let mut queued = 0;
        while links.send(peer, vec![0; usize::from(u16::MAX)]) {
            queued += 1;
            assert!(queued < 10_000, "the queue never filled");
            tokio::task::yield_now().await;
        }
        let link = &links.by_peer[&peer];
        assert!(!link.writer.is_finished());
        clock.advance(LINK_IDLE);
        until(|| link.reader.is_finished() && link.writer.is_finished()).await;
        drop(browser);
    }

    #[tokio::test]
    async fn the_writer_ends_when_a_write_fails_or_its_queue_closes() {
        // Our own write side shut: the first frame fails, the writer ends.
        let (ours, _browser) = pair().await;
        ours.shutdown(std::net::Shutdown::Write).unwrap();
        ours.set_nonblocking(true).unwrap();
        let (_read, write) = TcpStream::from_std(ours).unwrap().into_split();
        let (frames, queue) = mpsc::channel(1);
        frames.try_send(b"x".to_vec()).unwrap();
        write_frames(write, queue, CancellationToken::new()).await;
        // No more frames will come: the writer ends.
        let (ours, _browser) = pair().await;
        ours.set_nonblocking(true).unwrap();
        let (_read, write) = TcpStream::from_std(ours).unwrap().into_split();
        let (frames, queue) = mpsc::channel(1);
        drop(frames);
        write_frames(write, queue, CancellationToken::new()).await;
    }
}
