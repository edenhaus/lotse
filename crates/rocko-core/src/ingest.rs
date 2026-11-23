//! What a source connection lost or refused before its packets reached a
//! track: RTP sequence gaps, packets dropped as duplicates or as late, and
//! datagrams refused before they were read as RTP.
//!
//! One set of counters per [`crate::source::TrackSet`], so it lives as long
//! as the connection's tracks and counts across its reconnects. Sources
//! count; the worker reports the snapshot with its other counters. RFC
//! 3550 §6.4.1 defines the loss count as packets expected minus packets
//! received; here "received" is what reached the track.

use std::sync::atomic::{AtomicU64, Ordering};

/// A snapshot of [`IngestCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IngestStats {
    /// RTP packets the sequence numbers say never arrived (RFC 3550
    /// §6.4.1): datagrams lost on the network, or packets a camera dropped
    /// itself.
    pub packets_lost: u64,
    /// RTP packets dropped because they arrived again or after a later
    /// one: duplicates and reordered datagrams. Their gap was counted as
    /// lost when the later packet passed.
    pub packets_out_of_order: u64,
    /// Datagrams dropped before they were read as RTP or RTCP: from an
    /// address other than the camera's media ports, not RTP version 2, or
    /// from another synchronization source.
    pub datagrams_rejected: u64,
}

/// The live counters behind [`IngestStats`], shared by the source's tasks.
#[derive(Debug, Default)]
pub struct IngestCounters {
    /// See [`IngestStats::packets_lost`].
    packets_lost: AtomicU64,
    /// See [`IngestStats::packets_out_of_order`].
    packets_out_of_order: AtomicU64,
    /// See [`IngestStats::datagrams_rejected`].
    datagrams_rejected: AtomicU64,
}

impl IngestCounters {
    /// Adds `count` packets that never arrived.
    pub fn count_lost(&self, count: u64) {
        self.packets_lost.fetch_add(count, Ordering::Relaxed);
    }

    /// Counts one packet dropped as a duplicate or as late.
    pub fn count_out_of_order(&self) {
        self.packets_out_of_order.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one datagram refused before it was read.
    pub fn count_rejected(&self) {
        self.datagrams_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// The counters now.
    pub fn snapshot(&self) -> IngestStats {
        IngestStats {
            packets_lost: self.packets_lost.load(Ordering::Relaxed),
            packets_out_of_order: self.packets_out_of_order.load(Ordering::Relaxed),
            datagrams_rejected: self.datagrams_rejected.load(Ordering::Relaxed),
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

    use super::*;

    #[test]
    fn rfc3550_6_4_1_each_counter_counts_on_its_own() {
        let counters = IngestCounters::default();
        assert_eq!(counters.snapshot(), IngestStats::default());
        counters.count_lost(3);
        counters.count_lost(2);
        counters.count_out_of_order();
        counters.count_rejected();
        counters.count_rejected();
        assert_eq!(
            counters.snapshot(),
            IngestStats {
                packets_lost: 5,
                packets_out_of_order: 1,
                datagrams_rejected: 2,
            }
        );
    }
}
