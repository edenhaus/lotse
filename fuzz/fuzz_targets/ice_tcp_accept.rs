//! `ice_tcp_accept`: the supervisor's passive ICE-TCP acceptor reads the
//! first RFC 4571 frame of a connection from anyone on the network and
//! never panics or hangs on it; it hands a connection to a session's worker
//! only when that frame is 1 to 1500 bytes and a STUN Binding Request that
//! names the session and proves its password with a correct fingerprint,
//! hands over exactly that frame, never reads past it, and settles every
//! connection once, handed off or rejected (RFC 4571 §2, RFC 6544 §4.5,
//! RFC 8445 §7.2.2, RFC 8489 §14.5 and §14.7). Covers the RFC 4571
//! framing of the frame the supervisor reads; the worker's later frames
//! are `u16`-length reads that cannot exceed 65535 bytes.
//! Run with `cargo +nightly fuzz run ice_tcp_accept` from the repository
//! root.
//!
//! The input is `[mode]` then bytes: mode bit 0 puts a framed Binding
//! Request in front of them (bit 1: the wrong password, bit 2: another
//! ufrag, bit 3: no fingerprint, bit 4: a transaction id from the input).

#![no_main]

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use lotse_core::clock::{Clock, SystemClock};
use lotse_supervisor::net::demux::{DatagramSink, Registrations};
use lotse_supervisor::net::stun::{self, Builder, Class, METHOD_BINDING};
use lotse_supervisor::net::tcp::{IceTcpConfig, IceTcpStats, accept_loop};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// The session's ufrag.
const UFRAG: &str = "sess";
/// Its ICE password.
const PASSWORD: &[u8] = b"session-password-0123";

/// The worker's side: the connections handed to it.
#[derive(Debug, Default)]
struct Sink {
    /// Peer and first frame of each hand-off; the descriptor is kept so
    /// the connection stays open until the harness closes it.
    handed: Mutex<Vec<(SocketAddr, Vec<u8>, OwnedFd)>>,
    /// Datagrams forwarded (none here).
    datagrams: AtomicU64,
}

impl DatagramSink for Sink {
    fn forward(&self, _frame: &[u8]) -> bool {
        self.datagrams.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn ice_tcp(&self, stream: OwnedFd, peer: SocketAddr, first_frame: Vec<u8>) -> bool {
        self.handed
            .lock()
            .unwrap()
            .push((peer, first_frame, stream));
        true
    }
}

/// Whether `frame` is what the acceptor may hand off.
fn proves(frame: &[u8]) -> bool {
    stun::parse(frame).is_ok_and(|message| {
        message.is_binding_request()
            && message.local_ufrag() == Some(UFRAG)
            && message.verify_integrity(frame, PASSWORD)
            && message.fingerprint_ok(frame)
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut bytes = Vec::new();
    if mode & 1 != 0 {
        let mut id = [7_u8; 12];
        if mode & 0x10 != 0 {
            for (slot, b) in id.iter_mut().zip(rest) {
                *slot = *b;
            }
        }
        let ufrag = if mode & 4 == 0 { UFRAG } else { "other" };
        let password = if mode & 2 == 0 { PASSWORD } else { b"nope" };
        let builder = Builder::new(Class::Request, METHOD_BINDING, id)
            .username(&format!("{ufrag}:remote"))
            .integrity(password);
        let request = if mode & 8 == 0 {
            builder.fingerprint()
        } else {
            builder
        }
        .build();
        let len = u16::try_from(request.len()).expect("a small request");
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&request);
    }
    bytes.extend_from_slice(rest);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        let registrations = Arc::new(Registrations::default());
        let sink = Arc::new(Sink::default());
        registrations.register(UFRAG, PASSWORD.to_vec(), sink.clone());
        let stats = Arc::new(IceTcpStats::default());
        let cancel = CancellationToken::new();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let acceptor = tokio::spawn(accept_loop(
            listener,
            Arc::clone(&registrations),
            IceTcpConfig {
                first_frame_deadline: Duration::from_secs(5),
                ..IceTcpConfig::default()
            },
            clock,
            Arc::clone(&stats),
            cancel.clone(),
        ));
        let first = bytes
            .split_first_chunk::<2>()
            .map(|(len, tail)| (usize::from(u16::from_be_bytes(*len)), tail));
        // Whether the acceptor decides on the bytes alone: a whole first
        // frame, or a length it refuses outright.
        let decidable =
            first.is_some_and(|(len, tail)| !(1..=1500).contains(&len) || tail.len() >= len);
        let client = TcpStream::connect(addr)
            .await
            .expect("the acceptor listens");
        let local = client.local_addr().expect("the client's address");
        // Closed with a reset, never a FIN: tens of thousands of
        // connections a minute in TIME_WAIT would run out of ports.
        let _ = client.set_zero_linger();
        let mut client = Some(client);
        if let Some(stream) = client.as_mut() {
            // The peer may write more than the acceptor reads; the write
            // may fail once the acceptor closed.
            let _ = stream.write_all(&bytes).await;
        }
        if !decidable {
            // A peer that leaves mid-frame: the acceptor's read fails.
            drop(client.take());
        }
        let settled = || IceTcpStats::get(&stats.handed_off) + IceTcpStats::get(&stats.rejected);
        let mut spins = 0_u32;
        while settled() == 0 {
            spins += 1;
            assert!(
                spins < 1_000_000,
                "the acceptor never settled the connection"
            );
            tokio::task::yield_now().await;
        }
        assert_eq!(settled(), 1, "one connection, one outcome");
        assert_eq!(IceTcpStats::get(&stats.accepted), 1);
        let handed = std::mem::take(&mut *sink.handed.lock().unwrap());
        let first = first
            .filter(|(len, _)| (1..=1500).contains(len))
            .and_then(|(len, tail)| tail.get(..len));
        match handed.as_slice() {
            [] => assert!(
                !first.is_some_and(proves),
                "a verified first frame is handed off"
            ),
            [(peer, frame, _)] => {
                assert_eq!(*peer, local, "the peer as accepted");
                assert_eq!(Some(frame.as_slice()), first, "exactly the first frame");
                assert!(proves(frame), "only a verified request is handed off");
            }
            _ => panic!("one connection, at most one hand-off"),
        }
        drop(handed);
        drop(client);
        cancel.cancel();
        let _ = acceptor.await;
    });
});
