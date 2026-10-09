//! Allocation counts of the live fan-out.
//!
//! Linking `allocation-counter` makes its counting allocator this test
//! binary's global allocator; it counts the calling thread's allocations,
//! so every measurement runs on the test's own thread.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use allocation_counter::AllocationInfo;
use lotse_core::clock::{Clock as _, SystemClock};
use lotse_core::codec::{Codec, Kind};
use lotse_core::media::{MediaPacket, RtpHeaderFields};
use lotse_core::source::TrackSet;
use lotse_core::track::{PacketSubscription, Track, TrackLimits};

/// Packets per measurement.
const PACKETS: usize = 2_000;

fn packets(now: Instant, count: usize) -> Vec<MediaPacket> {
    let payload: Arc<[u8]> = Arc::from(vec![7_u8; 1_200]);
    (0..count)
        .map(|i| MediaPacket {
            arrival: now,
            rtp: RtpHeaderFields {
                pt: 96,
                seq: u16::try_from(i % 65_536).unwrap(),
                ts: 90_000 + u32::try_from(i / 10).unwrap() * 3_000,
                marker: i % 10 == 9,
                ssrc: 1,
            },
            frame_start: i % 10 == 0,
            keyframe_start: i == 0,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::clone(&payload),
        })
        .collect()
}

/// Publishes `batch` packet by packet, each read at once by every
/// subscription; the allocations of the publishing and of the reading.
fn fan_out(
    track: &Track,
    subscriptions: &mut [PacketSubscription],
    batch: Vec<MediaPacket>,
) -> (AllocationInfo, AllocationInfo, usize) {
    let mut publish = AllocationInfo::default();
    let mut receive = AllocationInfo::default();
    let mut received = 0;
    for packet in batch {
        publish += allocation_counter::measure(|| track.publish_packet(packet));
        receive += allocation_counter::measure(|| {
            for subscription in subscriptions.iter_mut() {
                while let Ok(Some(_packet)) = subscription.try_recv() {
                    received += 1;
                }
            }
        });
    }
    (publish, receive, received)
}

/// The ingest allocates once per packet, the shared `Arc` every viewer
/// gets a reference to, so a viewer more costs no allocation; reading
/// costs none. The first pass round the broadcast ring is a warm-up: on
/// macOS each slot's lock is a lazily boxed pthread mutex.
#[test]
fn a_published_packet_costs_one_allocation_whatever_the_viewers_and_reading_costs_none() {
    for viewers in [1, 8] {
        let now = SystemClock.now();
        let limits = TrackLimits::default();
        let set = TrackSet::new(limits, now);
        let track = set.publisher().declare(
            Kind::Video,
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
        );
        let mut subscriptions: Vec<_> = (0..viewers).map(|_| track.subscribe_packets()).collect();
        let warm_up = packets(now, limits.packet_capacity + 1);
        let (_, _, received) = fan_out(&track, &mut subscriptions, warm_up);
        assert_eq!(received, (limits.packet_capacity + 1) * viewers);
        let (publish, receive, received) =
            fan_out(&track, &mut subscriptions, packets(now, PACKETS));
        assert_eq!(received, PACKETS * viewers);
        assert_eq!(
            publish.count_total, PACKETS as u64,
            "{viewers} viewers: {publish:?}"
        );
        assert_eq!(receive.count_total, 0, "{viewers} viewers: {receive:?}");
    }
}
