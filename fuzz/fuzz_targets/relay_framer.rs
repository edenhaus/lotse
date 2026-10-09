//! `relay_framer`: the worker's side of the TURN relay path never panics
//! and agrees with a model of it: a datagram leaves a relay candidate as
//! `ChannelData` exactly when its destination (in canonical form) has a
//! channel in 0x4000 to 0x4FFF on that candidate and the data fits the
//! 16-bit length, for the candidate's server, from the shared socket on a
//! UDP allocation and through the supervisor on a TCP one; a peer without a
//! channel is asked for once; every frame parses back with the
//! supervisor's reader to its channel and data, unpadded on UDP and padded
//! with zeros to four bytes on TCP, where the supervisor's stream splitter
//! takes it whole (RFC 8656 §12, §12.4, §12.5).
//! Run with `cargo +nightly fuzz run relay_framer` from the repository root.

#![no_main]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use lotse_supervisor::net::turn::{CHANNEL_DATA_HEADER_LEN, parse_channel_data, stream_frame_len};
use lotse_worker::relay::{Egress, Relays, channel_data};

/// The largest data a `ChannelData` length field carries.
const MAX_DATA: usize = 65_535;

/// One of eight addresses: two IPv4 hosts, one of them also in its
/// IPv4-mapped IPv6 form, and an IPv6 host, each on two ports.
fn addr(byte: u8) -> SocketAddr {
    let ip = match byte % 4 {
        0 => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        1 => IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()),
        2 => IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        _ => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    };
    SocketAddr::new(ip, 3478 + u16::from(byte / 4 % 2))
}

/// The form the worker names addresses in.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// One relay candidate as the model holds it.
#[derive(Default)]
struct Model {
    /// The allocation's server.
    server: Option<SocketAddr>,
    /// Over TCP.
    tcp: bool,
    /// Channels by peer.
    channels: HashMap<SocketAddr, u16>,
    /// Peers asked for.
    wanted: HashSet<SocketAddr>,
}

/// Checks `frame` against the channel and data it must carry.
fn check_frame(frame: &[u8], channel: u16, data: &[u8], padded: bool) {
    assert_eq!(&frame[..2], &channel.to_be_bytes());
    assert_eq!(&frame[2..4], &(data.len() as u16).to_be_bytes());
    assert_eq!(&frame[4..4 + data.len()], data);
    let tail = &frame[CHANNEL_DATA_HEADER_LEN + data.len()..];
    if padded {
        assert_eq!(frame.len() % 4, 0, "padded to four bytes");
        assert!(
            tail.len() < 4 && tail.iter().all(|b| *b == 0),
            "only zero padding"
        );
    } else {
        assert!(tail.is_empty(), "no padding on udp");
    }
    if (0x4000..=0x4FFF).contains(&channel) {
        let message = parse_channel_data(frame).expect("a frame on a bindable channel parses");
        assert_eq!((message.channel.number(), message.data), (channel, data));
        if padded {
            assert_eq!(
                stream_frame_len(frame),
                Ok(Some(frame.len())),
                "the splitter takes it whole"
            );
        }
    } else {
        assert!(
            parse_channel_data(frame).is_err(),
            "a reserved channel is refused"
        );
    }
}

fuzz_target!(|bytes: &[u8]| {
    let mut relays = Relays::default();
    let mut model: HashMap<SocketAddr, Model> = HashMap::new();
    for op in bytes.chunks(6) {
        let &[kind, a, b, c, d, e] = op else {
            break;
        };
        match kind % 4 {
            0 => {
                let (relayed, server, tcp) = (addr(a), addr(b), c % 2 == 1);
                let fresh = !model.contains_key(&canonical(relayed));
                assert_eq!(relays.add(relayed, server, tcp), fresh);
                if fresh {
                    model.insert(
                        canonical(relayed),
                        Model {
                            server: Some(canonical(server)),
                            tcp,
                            ..Model::default()
                        },
                    );
                }
            }
            1 => {
                let (relayed, peer) = (addr(a), addr(b));
                let channel = u16::from_be_bytes([c, d]);
                let taken = model.get_mut(&canonical(relayed)).and_then(|relay| {
                    (0x4000..=0x4FFF)
                        .contains(&channel)
                        .then(|| relay.channels.insert(canonical(peer), channel))
                });
                assert_eq!(relays.bind(relayed, peer, channel), taken.is_some());
            }
            2 => {
                let (source, destination) = (addr(a), addr(b));
                // Up to past what the length field carries.
                let len = (usize::from(c) << 9) | (usize::from(d) << 1) | usize::from(e & 1);
                let payload = vec![e; len];
                let got = relays.egress(source, destination, &payload);
                let Some(relay) = model.get_mut(&canonical(source)) else {
                    assert_eq!(got, Egress::Direct);
                    continue;
                };
                let peer = canonical(destination);
                let server = relay.server.expect("a server");
                match relay.channels.get(&peer).copied() {
                    Some(_) if len > MAX_DATA => assert_eq!(got, Egress::Dropped),
                    Some(channel) => match got {
                        Egress::Relay { to, frame } if !relay.tcp => {
                            assert_eq!(to, server);
                            check_frame(frame, channel, &payload, false);
                        }
                        Egress::Uplink {
                            relayed,
                            server: to,
                            frame,
                        } if relay.tcp => {
                            assert_eq!((relayed, to), (canonical(source), server));
                            check_frame(frame, channel, &payload, true);
                        }
                        other => panic!("a frame for the server, got {other:?}"),
                    },
                    None if relay.wanted.insert(peer) => assert_eq!(
                        got,
                        Egress::Want {
                            relayed: canonical(source),
                            peer
                        }
                    ),
                    None => assert_eq!(got, Egress::Dropped),
                }
            }
            _ => {
                let channel = u16::from_be_bytes([a, b]);
                let len = (usize::from(c) << 9) | (usize::from(d) << 1) | usize::from(e & 1);
                let data = vec![e; len];
                let padded = channel % 2 == 1;
                // Into a buffer that held a frame before, as the session's does.
                let mut frame = vec![0xAA; usize::from(e)];
                let before = frame.clone();
                if channel_data(channel, &data, padded, &mut frame) {
                    assert!(len <= MAX_DATA);
                    check_frame(&frame, channel, &data, padded);
                } else {
                    assert!(len > MAX_DATA);
                    assert_eq!(frame, before, "a refused frame leaves the buffer");
                }
            }
        }
    }
});
