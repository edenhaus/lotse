//! Microbenchmarks of the supervisor's receive path: the demux routing a
//! browser's datagram to its session's worker, which every media and
//! RTCP datagram of every viewer passes on the one receive thread, and
//! the STUN connectivity check it verifies before it learns an address
//! (RFC 8445 §7.3, RFC 8489 §14.5 `MESSAGE-INTEGRITY` and §14.7
//! `FINGERPRINT`).
//!
//! Run with `mise run bench`; divan's harness, not libtest's.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    reason = "benchmark code, held to the tests' rules: a failed setup is a panic"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use divan::Bencher;
use divan::counter::BytesCount;
use lotse_core::clock::SystemClock;
use lotse_supervisor::net::demux::{
    DatagramSink, DemuxStats, Registrations, Relays, Router, StunResponses,
};
use lotse_supervisor::net::stun::{self, Builder, Class, METHOD_BINDING};

/// The session's local ufrag, as the worker registers it.
const UFRAG: &str = "abcd";

/// The session's ICE password, the `MESSAGE-INTEGRITY` key (RFC 8489
/// §9.1.1, short-term credentials): random, as RFC 8445 §5.3 has it, and
/// as long as the shortest password RFC 8839 §5.4 allows.
fn password() -> Vec<u8> {
    let mut password = vec![0; 22];
    getrandom::fill(&mut password).unwrap();
    password
}

/// A worker that takes every frame and keeps none.
#[derive(Debug, Default)]
struct Counting(AtomicUsize);

impl DatagramSink for Counting {
    fn forward(&self, _frame: &[u8]) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// A browser's connectivity check for the session: a Binding Request
/// with `USERNAME`, `MESSAGE-INTEGRITY` and `FINGERPRINT` (RFC 8445
/// §7.2.2).
fn binding_request(password: &[u8]) -> Vec<u8> {
    Builder::new(Class::Request, METHOD_BINDING, [3; 12])
        .username(&format!("{UFRAG}:remote"))
        .integrity(password)
        .fingerprint()
        .build()
}

/// What the demux does with a connectivity check: parse it, verify its
/// `MESSAGE-INTEGRITY` (HMAC-SHA1, RFC 8489 §14.5) and `FINGERPRINT`
/// (CRC-32, §14.7).
#[divan::bench]
fn stun_check(bencher: Bencher<'_, '_>) {
    let password = password();
    let request = binding_request(&password);
    let check = || {
        let message = stun::parse(divan::black_box(&request)).unwrap();
        message.is_binding_request()
            && message.local_ufrag() == Some(UFRAG)
            && message.verify_integrity(&request, &password)
            && message.fingerprint_ok(&request)
    };
    assert!(check(), "the check passes, as the demux's does");
    bencher
        .counter(BytesCount::new(request.len()))
        .bench_local(check);
}

/// The demux routing a datagram from an address a verified check taught
/// it, framed for the session's worker: an SRTP or DTLS-sized datagram,
/// the receive thread's work per packet.
#[divan::bench(args = [100, 1_200])]
fn route_learned(bencher: Bencher<'_, '_>, len: usize) {
    let local: SocketAddr = "192.0.2.10:18556".parse().unwrap();
    let browser: SocketAddr = "192.0.2.20:40000".parse().unwrap();
    let registrations = Arc::new(Registrations::default());
    let worker = Arc::new(Counting::default());
    let password = password();
    registrations.register(UFRAG, password.clone(), worker);
    let (_relays, updates) = Relays::channel();
    let stats = Arc::new(DemuxStats::default());
    let mut router = Router::new(
        registrations,
        Arc::new(StunResponses::default()),
        updates,
        Arc::clone(&stats),
        Arc::new(SystemClock),
        local,
        &[local],
    );
    router.route(&binding_request(&password), browser, None);
    assert_eq!(DemuxStats::get(&stats.addresses_learned), 1);
    // The first byte of an RTP or RTCP packet (RFC 7983 §7).
    let datagram = vec![0x80; len];
    bencher.counter(BytesCount::new(len)).bench_local(|| {
        router.route(divan::black_box(&datagram), browser, None);
    });
    // The binding request and every datagram after it reached the worker.
    assert_eq!(
        DemuxStats::get(&stats.forwarded),
        DemuxStats::get(&stats.received)
    );
}

/// Runs the benchmarks of this file with divan's command line (`--help`).
fn main() {
    divan::main();
}
