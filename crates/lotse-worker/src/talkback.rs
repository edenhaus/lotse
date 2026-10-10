//! A session's talk-back in the worker: the uplink packets its engine
//! hands on, published on the session's uplink track for the connection's
//! backchannel.
//!
//! A session has an uplink track from its first talk-back packet on, one
//! per codec: a browser that switches codec gets a new track (the old one
//! closes), since the clock rate and the chain that reads it differ. No
//! talker is claimed here yet: [`receive`] creates a track before
//! publishing its first packet, which is where the connection's arbiter is
//! to take it, so a chain subscribed then misses nothing. The track
//! carries both branches the backchannel needs: the live path for a
//! camera that takes the codec as it is (Opus to Opus), the side branch
//! for the `ToG711` transcoder the binary hands over.

use lotse_core::uplink::{UplinkPacket, UplinkTrack};

/// Publishes `packet` on the session's `uplink` track, opening one first
/// for the session's first packet or a packet in another codec than the
/// track's.
pub(crate) fn receive(uplink: &mut Option<UplinkTrack>, packet: UplinkPacket) {
    let UplinkPacket { codec, packet } = packet;
    let track = match uplink.take() {
        Some(track) if track.codec() == codec => track,
        previous => {
            let to = codec.name();
            if let Some(old) = previous.map(|track| track.codec()) {
                let from = old.name();
                tracing::info!(from, to, "talk-back uplink changed codec; new uplink track");
            } else {
                tracing::info!(codec = to, "talk-back uplink track opened");
            }
            // The talker arbitration attaches here: a new track, before
            // its first packet.
            UplinkTrack::new(codec, packet.arrival)
        }
    };
    uplink.insert(track).publish(packet);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use std::sync::Arc;
    use std::time::Duration;

    use lotse_core::clock::{Clock as _, SystemClock};
    use lotse_core::codec::Codec;
    use lotse_core::media::{MediaPacket, RtpHeaderFields};
    use lotse_core::track::Unit;
    use lotse_core::uplink::UplinkCodec;

    use super::*;

    fn packet(codec: UplinkCodec, ts: u32) -> UplinkPacket {
        UplinkPacket {
            codec,
            packet: MediaPacket {
                arrival: SystemClock.now(),
                rtp: RtpHeaderFields {
                    pt: 0,
                    seq: 1,
                    ts,
                    marker: false,
                    ssrc: 5,
                },
                frame_start: true,
                keyframe_start: false,
                epoch: 0,
                lateness: Duration::ZERO,
                payload: Arc::from(&[0xff_u8; 160][..]),
            },
        }
    }

    #[tokio::test]
    async fn the_first_packet_opens_the_uplink_track_and_a_codec_change_another() {
        let mut uplink = None;
        receive(&mut uplink, packet(UplinkCodec::Pcmu, 0));
        let first = Arc::clone(uplink.as_ref().unwrap().track());
        assert_eq!(*first.codec(), Codec::Pcmu);
        assert_eq!(first.stats().packets, 1, "the first packet went out on it");
        assert_eq!(first.stats().frames, 1);
        let mut sink = first.subscribe(Unit::Packets);
        // The same codec: the same track.
        receive(&mut uplink, packet(UplinkCodec::Pcmu, 160));
        assert!(Arc::ptr_eq(uplink.as_ref().unwrap().track(), &first));
        assert_eq!(first.stats().packets, 2);
        // Another codec: a new track, and the old one ends.
        receive(&mut uplink, packet(UplinkCodec::Opus, 960));
        let second = Arc::clone(uplink.as_ref().unwrap().track());
        assert!(!Arc::ptr_eq(&second, &first));
        assert_eq!(*second.codec(), Codec::Opus { channels: 1 });
        assert_eq!(second.stats().packets, 1);
        assert!(first.is_closed());
        assert!(sink.next().await.is_none(), "the old track's sink ends");
    }
}
