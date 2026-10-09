//! Allocation counts of the demux's routing: no allocation on the hot path.
//!
//! Linking `allocation-counter` makes its counting allocator this test
//! binary's global allocator; it counts the calling thread's allocations,
//! so the router runs on the test's own thread, as on the receive thread.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lotse_core::clock::SystemClock;
use lotse_supervisor::net::demux::{
    DatagramSink, DemuxStats, Registrations, Relays, Router, StunResponses,
};
use lotse_supervisor::net::stun::{Builder, Class, METHOD_BINDING};

/// A worker that takes every frame and keeps none.
#[derive(Debug, Default)]
struct Counting(AtomicUsize);

impl DatagramSink for Counting {
    fn forward(&self, _frame: &[u8]) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// A browser's datagrams from an address a verified STUN request taught
/// the router reach its worker without an allocation: the frame for the
/// worker is encoded into a buffer the router reuses.
#[test]
fn a_learned_address_s_datagrams_are_forwarded_without_an_allocation() {
    let local: SocketAddr = "192.0.2.10:18556".parse().unwrap();
    let browser: SocketAddr = "192.0.2.20:40000".parse().unwrap();
    let registrations = Arc::new(Registrations::default());
    let worker = Arc::new(Counting::default());
    registrations.register("abcd", b"the-password".to_vec(), worker.clone());
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
    let request = Builder::new(Class::Request, METHOD_BINDING, [3; 12])
        .username("abcd:remote")
        .integrity(b"the-password")
        .fingerprint()
        .build();
    router.route(&request, browser, None);
    assert_eq!(DemuxStats::get(&stats.addresses_learned), 1);
    // RTCP and DTLS-sized datagrams, the largest first so the buffer has
    // grown to its size before the count starts.
    let datagrams: Vec<Vec<u8>> = (0..1_000_usize)
        .map(|i| vec![0x80; 1_200 - (i % 7) * 100])
        .collect();
    router.route(&datagrams[0], browser, None);
    let counted = allocation_counter::measure(|| {
        for datagram in &datagrams {
            router.route(datagram, browser, None);
        }
    });
    assert_eq!(worker.0.load(Ordering::Relaxed), 1 + 1 + 1_000);
    assert_eq!(counted.count_total, 0, "{counted:?}");
}
