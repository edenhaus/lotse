//! Allocation counts of the relay path's framer.
//!
//! Linking `allocation-counter` makes its counting allocator this test
//! binary's global allocator; it counts the calling thread's allocations.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::net::SocketAddr;

use lotse_worker::relay::{Egress, Relays};

/// What leaves a relay candidate is framed as `ChannelData` (RFC 8656
/// §12.4, §12.5) in the session's own buffer: once it has grown to the
/// largest datagram, a frame costs no allocation, over UDP or TCP.
#[test]
fn rfc8656_12_4_a_relayed_datagram_is_framed_without_an_allocation() {
    let peer: SocketAddr = "192.0.2.9:50000".parse().unwrap();
    let server: SocketAddr = "192.0.2.3:3478".parse().unwrap();
    for tcp in [false, true] {
        let relayed: SocketAddr = "203.0.113.1:49153".parse().unwrap();
        let mut relays = Relays::default();
        assert!(relays.add(relayed, server, tcp));
        assert!(relays.bind(relayed, peer, 0x4000));
        let datagrams: Vec<Vec<u8>> = (0..1_000_usize)
            .map(|i| vec![0x80; 1_200 - (i % 7) * 100])
            .collect();
        let mut framed = 0;
        let mut frame =
            |relays: &mut Relays, datagram: &[u8]| match relays.egress(relayed, peer, datagram) {
                Egress::Relay { frame, .. } | Egress::Uplink { frame, .. } => {
                    framed += usize::from(frame.len() >= datagram.len() + 4);
                }
                other => panic!("{other:?}"),
            };
        frame(&mut relays, &datagrams[0]);
        let counted = allocation_counter::measure(|| {
            for datagram in &datagrams {
                frame(&mut relays, datagram);
            }
        });
        assert_eq!(framed, 1_001, "tcp {tcp}");
        assert_eq!(counted.count_total, 0, "tcp {tcp}: {counted:?}");
    }
}
