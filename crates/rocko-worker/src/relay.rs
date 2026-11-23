//! A session's side of the TURN relay path: the relay candidates the
//! supervisor allocated, the channels it bound on them, and the
//! `ChannelData` framer that sends what the engine sends from a relay
//! candidate to the allocation's server.
//!
//! Implements RFC 8656 §12.4 (the `ChannelData` message: the channel
//! number, the length, the data), unpadded on UDP and padded to four bytes
//! for a TCP allocation (§12.5), and §12 (a channel per peer, numbers
//! 0x4000 to 0x4FFF). The supervisor owns the allocations and unwraps what
//! the server relays; the worker only frames the other direction, as each
//! process owns one direction of RFC 4571 framing on ICE-TCP. A frame for
//! a UDP allocation leaves the shared socket for the server; one for a TCP
//! allocation goes to the supervisor, which owns the connection and writes
//! it to the stream. A peer without a channel yet is asked for once, and
//! what is sent to it until the binding arrives is dropped: ICE
//! retransmits its checks. Frames are built in a buffer the session
//! keeps, so a relayed datagram costs no allocation.
//!
//! Public for the `relay_framer` fuzz target, which drives [`Relays`] and
//! [`channel_data`] against a model and reads every frame back with the
//! supervisor's reader;
//! nothing outside the worker uses it otherwise.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

/// The channel numbers a client may bind (RFC 8656 §12).
const CHANNELS: std::ops::RangeInclusive<u16> = 0x4000..=0x4FFF;

/// The `ChannelData` header: channel number and length (RFC 8656 §12.4).
const CHANNEL_DATA_HEADER: usize = 4;

/// One relay candidate.
#[derive(Debug)]
struct Relay {
    /// The allocation's server, which `ChannelData` goes to.
    server: SocketAddr,
    /// The allocation reaches its server over TCP: frames are padded and
    /// go through the supervisor.
    tcp: bool,
    /// The channel bound to each peer.
    channels: HashMap<SocketAddr, u16>,
    /// Peers asked for, so each is asked for once.
    wanted: HashSet<SocketAddr>,
}

/// What to do with a datagram the engine sends over UDP. A frame is
/// borrowed from the [`Relays`] buffer it was built in, until the next
/// datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Egress<'a> {
    /// It leaves no relay candidate: send it as it is.
    Direct,
    /// Send `frame` to the allocation's server from the shared socket.
    Relay {
        /// The server.
        to: SocketAddr,
        /// The `ChannelData` message.
        frame: &'a [u8],
    },
    /// Hand `frame` to the supervisor, for the TCP allocation on `server`.
    Uplink {
        /// The relayed address it leaves from.
        relayed: SocketAddr,
        /// The server.
        server: SocketAddr,
        /// The `ChannelData` message, padded.
        frame: &'a [u8],
    },
    /// The peer has no channel yet: ask the supervisor for one; the
    /// datagram is dropped.
    Want {
        /// The relayed address it leaves from.
        relayed: SocketAddr,
        /// The peer, canonical.
        peer: SocketAddr,
    },
    /// Dropped: the channel was asked for already, or the datagram is too
    /// long for `ChannelData`.
    Dropped,
}

/// The session's relay candidates by relayed address.
#[derive(Debug, Default)]
pub struct Relays {
    /// The candidates.
    relays: HashMap<SocketAddr, Relay>,
    /// The frame being built, reused from datagram to datagram.
    frame: Vec<u8>,
}

impl Relays {
    /// A relay candidate at `relayed` on `server`'s allocation, reached
    /// over TCP when `tcp`; `false` when the session has it already.
    pub fn add(&mut self, relayed: SocketAddr, server: SocketAddr, tcp: bool) -> bool {
        let relayed = canonical(relayed);
        if self.relays.contains_key(&relayed) {
            return false;
        }
        self.relays.insert(
            relayed,
            Relay {
                server: canonical(server),
                tcp,
                channels: HashMap::new(),
                wanted: HashSet::new(),
            },
        );
        true
    }

    /// `channel` is bound to `peer` on the relay candidate at `relayed`;
    /// `false`, and nothing changes, for an unknown candidate or a number
    /// outside 0x4000 to 0x4FFF (RFC 8656 §12).
    pub fn bind(&mut self, relayed: SocketAddr, peer: SocketAddr, channel: u16) -> bool {
        match self.relays.get_mut(&canonical(relayed)) {
            Some(relay) if CHANNELS.contains(&channel) => {
                relay.channels.insert(canonical(peer), channel);
                true
            }
            _ => false,
        }
    }

    /// What to do with `payload`, which the engine sends from `source` to
    /// `destination`.
    pub fn egress(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Egress<'_> {
        let Some(relay) = self.relays.get_mut(&canonical(source)) else {
            return Egress::Direct;
        };
        let peer = canonical(destination);
        match relay.channels.get(&peer) {
            Some(&channel) => {
                if !channel_data(channel, payload, relay.tcp, &mut self.frame) {
                    Egress::Dropped
                } else if relay.tcp {
                    Egress::Uplink {
                        relayed: canonical(source),
                        server: relay.server,
                        frame: &self.frame,
                    }
                } else {
                    Egress::Relay {
                        to: relay.server,
                        frame: &self.frame,
                    }
                }
            }
            None if relay.wanted.insert(peer) => Egress::Want {
                relayed: canonical(source),
                peer,
            },
            None => Egress::Dropped,
        }
    }
}

/// `data` as `ChannelData` on `channel` (RFC 8656 §12.4) into `frame`,
/// which it replaces, padded with zeros to a multiple of four bytes when
/// `pad`, as a TCP stream needs, and unpadded as UDP allows (§12.5);
/// `false`, and `frame` left as it was, when the length does not fit its
/// 16 bits. `frame` grows only past the largest frame it held.
pub fn channel_data(channel: u16, data: &[u8], pad: bool, frame: &mut Vec<u8>) -> bool {
    let Ok(length) = u16::try_from(data.len()) else {
        return false;
    };
    let body = if pad {
        data.len().next_multiple_of(4)
    } else {
        data.len()
    };
    frame.clear();
    frame.extend_from_slice(&channel.to_be_bytes());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(data);
    frame.resize(body.saturating_add(CHANNEL_DATA_HEADER), 0);
    true
}

/// `addr` with an IPv4-mapped IPv6 address as IPv4, the form the
/// supervisor names peers and servers in.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    const RELAYED: &str = "203.0.113.1:49153";
    const SERVER: &str = "192.0.2.3:3478";
    const PEER: &str = "192.0.2.9:50000";

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// `data` framed into a fresh buffer; `None` when it does not fit.
    fn framed(channel: u16, data: &[u8], pad: bool) -> Option<Vec<u8>> {
        let mut frame = b"left over".to_vec();
        channel_data(channel, data, pad, &mut frame).then_some(frame)
    }

    #[test]
    fn rfc8656_12_4_channel_data_is_the_number_the_length_and_the_data() {
        assert_eq!(
            framed(0x4001, b"abcde", false).unwrap(),
            b"\x40\x01\x00\x05abcde"
        );
        assert_eq!(framed(0x4FFF, b"", false).unwrap(), b"\x4F\xFF\x00\x00");
        assert_eq!(
            framed(0x4000, &vec![0; 65_535], false).unwrap().len(),
            65_539
        );
        assert_eq!(framed(0x4000, &vec![0; 65_536], false), None);
        assert_eq!(framed(0x4000, &vec![0; 65_536], true), None);
        // A refused one leaves the buffer as it was.
        let mut frame = b"kept".to_vec();
        assert!(!channel_data(0x4000, &vec![0; 65_536], false, &mut frame));
        assert_eq!(frame, b"kept");
    }

    #[test]
    fn rfc8656_12_5_channel_data_on_tcp_is_padded_to_four_bytes() {
        assert_eq!(
            framed(0x4001, b"abcde", true).unwrap(),
            b"\x40\x01\x00\x05abcde\0\0\0"
        );
        assert_eq!(
            framed(0x4001, b"abcd", true).unwrap(),
            b"\x40\x01\x00\x04abcd"
        );
        assert_eq!(framed(0x4FFF, b"", true).unwrap(), b"\x4F\xFF\x00\x00");
        assert_eq!(
            framed(0x4000, &vec![1; 65_535], true).unwrap().len(),
            65_540
        );
    }

    #[test]
    fn rfc8656_12_what_leaves_a_relay_candidate_goes_to_its_server_on_the_peers_channel() {
        let mut relays = Relays::default();
        let (relayed, peer) = (addr(RELAYED), addr(PEER));
        assert_eq!(relays.egress(relayed, peer, b"x"), Egress::Direct);
        assert!(relays.add(relayed, addr("[::ffff:192.0.2.3]:3478"), false));
        assert!(!relays.add(addr("[::ffff:203.0.113.1]:49153"), addr(SERVER), true));
        // A host candidate's datagram is not the relay's.
        assert_eq!(
            relays.egress(addr("192.0.2.1:18556"), peer, b"x"),
            Egress::Direct
        );
        // No channel yet: asked for once, dropped until bound.
        assert_eq!(
            relays.egress(relayed, addr("[::ffff:192.0.2.9]:50000"), b"x"),
            Egress::Want { relayed, peer }
        );
        assert_eq!(relays.egress(relayed, peer, b"x"), Egress::Dropped);
        // Out of range or for another candidate: ignored.
        assert!(!relays.bind(relayed, peer, 0x3FFF));
        assert!(!relays.bind(relayed, peer, 0x5000));
        assert!(!relays.bind(addr("203.0.113.1:1"), peer, 0x4000));
        assert_eq!(relays.egress(relayed, peer, b"x"), Egress::Dropped);
        assert!(relays.bind(relayed, addr("[::ffff:192.0.2.9]:50000"), 0x4000));
        assert!(relays.bind(addr("203.0.113.1:49153"), addr("192.0.2.9:50001"), 0x4FFF));
        assert_eq!(
            relays.egress(relayed, peer, b"stun"),
            Egress::Relay {
                to: addr(SERVER),
                frame: b"\x40\x00\x00\x04stun"
            }
        );
        assert_eq!(
            relays.egress(relayed, addr("192.0.2.9:50001"), b"y"),
            Egress::Relay {
                to: addr(SERVER),
                frame: b"\x4F\xFF\x00\x01y"
            }
        );
        // Longer than `ChannelData` carries.
        assert_eq!(
            relays.egress(relayed, peer, &vec![0; 65_536]),
            Egress::Dropped
        );
    }

    #[test]
    fn rfc8656_12_5_what_leaves_a_tcp_relay_candidate_goes_to_the_supervisor_padded() {
        let mut relays = Relays::default();
        let (relayed, peer) = (addr(RELAYED), addr(PEER));
        assert!(relays.add(addr("[::ffff:203.0.113.1]:49153"), addr(SERVER), true));
        assert_eq!(
            relays.egress(relayed, peer, b"x"),
            Egress::Want { relayed, peer }
        );
        assert!(relays.bind(relayed, peer, 0x4000));
        assert_eq!(
            relays.egress(addr("[::ffff:203.0.113.1]:49153"), peer, b"stun!"),
            Egress::Uplink {
                relayed,
                server: addr(SERVER),
                frame: b"\x40\x00\x00\x05stun!\0\0\0"
            }
        );
        assert_eq!(
            relays.egress(relayed, peer, &vec![0; 65_536]),
            Egress::Dropped
        );
    }
}
