//! `rtp_demux`: the supervisor's demux never panics on any sequence of
//! datagrams from any address, counts every datagram in exactly one
//! bucket (a response to a waiting transaction, forwarded, dropped on a
//! full worker, a rejected STUN request, discarded from a TURN server,
//! unroutable), and hands a session's worker only what comes from an
//! address that session learned and no other session took since, or is a
//! STUN Binding Request that proves the session's password with a correct
//! fingerprint, never more than [`MAX_ADDRS_PER_SESSION`] addresses per
//! session, and every frame exactly
//! as it arrived, its source canonical and its destination where the
//! socket said it arrived, canonical on the bound port, or else the host
//! address of the source's family (RFC 8445 §7.2.2 and §7.2.5.2.1, RFC
//! 8489 §14.5 and §14.7, RFC 4291 §2.5.5.2). What the TURN server of a
//! published relay sends is unwrapped exactly when it is `ChannelData` on a
//! channel the relay holds (whole) or a Data indication from a peer whose
//! IP holds a permission, and is then routed as the peer's datagram,
//! canonical, at the relayed address; the rest it sends that is not STUN is
//! discarded (RFC 8656 §11.4, §12.6, Table 3).
//! Run with `cargo +nightly fuzz run rtp_demux` from the repository root.

#![no_main]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use lotse_core::clock::SystemClock;
use lotse_ipc::datagram;
use lotse_supervisor::net::demux::{
    DatagramSink, DemuxStats, MAX_ADDRS_PER_SESSION, Registrations, Relay, Relays, Router,
    StunResponses,
};
use lotse_supervisor::net::stun::{self, Builder, Class, METHOD_BINDING};
use lotse_supervisor::net::turn::{self, Channel};

/// A worker's channel: the frames it got, or full.
#[derive(Debug, Default)]
struct Sink {
    /// Decoded frames: source, destination, payload.
    frames: Mutex<Vec<(SocketAddr, SocketAddr, Vec<u8>)>>,
    /// Refuses frames, as a full channel does.
    full: AtomicBool,
}

impl DatagramSink for Sink {
    fn forward(&self, frame: &[u8]) -> bool {
        if self.full.load(Ordering::Relaxed) {
            return false;
        }
        let frame = datagram::decode(frame).expect("the demux encodes what it forwards");
        self.frames
            .lock()
            .unwrap()
            .push((frame.source, frame.destination, frame.payload.to_vec()));
        true
    }
}

/// The two sessions: ufrag and password.
const SESSIONS: [(&str, &[u8]); 2] = [("alpha", b"alpha-password"), ("beta", b"beta-password")];

/// Where the datagrams come from, IPv4-mapped forms included.
const SOURCES: [&str; 12] = [
    "192.0.2.1:1000",
    "192.0.2.1:1001",
    "192.0.2.2:1000",
    "[::ffff:192.0.2.1]:1000",
    "[::ffff:192.0.2.3]:4000",
    "[2001:db8::1]:1000",
    "[2001:db8::2]:2000",
    "198.51.100.1:3478",
    "198.51.100.2:3478",
    "198.51.100.3:3478",
    "198.51.100.4:3478",
    "[2001:db8::3]:9",
];

/// The TURN server, one of the sources.
const SERVER: &str = "198.51.100.1:3478";
/// Its IPv4-mapped form, as a dual-stack socket reports it.
const MAPPED_SERVER: &str = "[::ffff:198.51.100.1]:3478";
/// The relayed address of the allocation on it.
const RELAYED: &str = "203.0.113.1:50000";

/// The host addresses the candidates carry.
const HOST_V4: &str = "192.0.2.10:3478";
/// The IPv6 one.
const HOST_V6: &str = "[2001:db8::10]:3478";

/// Where the socket may say a datagram arrived, besides not saying:
/// IPv4-mapped, as a dual-stack socket's `IPV6_PKTINFO` names an IPv4
/// destination, and IPv6; neither is a host address.
const DESTINATIONS: [&str; 2] = ["::ffff:192.0.2.77", "2001:db8::77"];

/// Takes `N` bytes off the front of `rest`.
fn take<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>()?;
    *rest = tail;
    Some(*head)
}

/// Takes a `[len:u8]` and that many bytes off the front of `rest`.
fn bytes<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let [len] = take::<1>(rest)?;
    let (body, tail) = rest.split_at_checked(usize::from(len))?;
    *rest = tail;
    Some(body)
}

/// What the TURN server may relay, as the fuzzer published it: channel
/// numbers with their peers, and the permitted peer IPs.
type Model = (BTreeMap<u16, SocketAddr>, BTreeSet<std::net::IpAddr>);

/// What the demux must make of a datagram.
enum Expect {
    /// Routed as it arrived.
    Direct,
    /// Unwrapped: the peer's datagram.
    Relayed(SocketAddr, Vec<u8>),
    /// Discarded as the server's.
    Discarded,
}

/// The model of RFC 8656 §11.4 and §12.6 (and Table 3) for `payload`
/// from `from` (canonical), written apart from the router: ChannelData by
/// its header, STUN by the supervisor's codec, which `stun_message` and
/// `turn_message` fuzz on their own.
fn expect(payload: &[u8], from: SocketAddr, server: SocketAddr, relay: Option<&Model>) -> Expect {
    let Some((channels, permissions)) = relay.filter(|_| from == server) else {
        return Expect::Direct;
    };
    let canonical = |a: SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    match payload.first() {
        None => Expect::Discarded,
        Some(64..=79) => {
            let number = u16::from_be_bytes([payload[0], *payload.get(1).unwrap_or(&0)]);
            let length = payload
                .get(2..4)
                .map(|l| usize::from(u16::from_be_bytes([l[0], l[1]])));
            let data = length.and_then(|length| payload.get(4..4 + length));
            match (channels.get(&number), data) {
                (Some(peer), Some(data)) => Expect::Relayed(canonical(*peer), data.to_vec()),
                _ => Expect::Discarded,
            }
        }
        Some(0..=3) => match stun::parse(payload) {
            Ok(message)
                if message.class == Class::Indication && message.method == turn::METHOD_DATA =>
            {
                match turn::data_indication(&message) {
                    Some((peer, data)) if permissions.contains(&peer.ip().to_canonical()) => {
                        Expect::Relayed(canonical(peer), data.to_vec())
                    }
                    _ => Expect::Discarded,
                }
            }
            _ => Expect::Direct,
        },
        Some(_) => Expect::Discarded,
    }
}

/// Whether `payload` is a Binding Request for session `index` that
/// proves its password with a correct fingerprint.
fn proves(payload: &[u8], index: usize) -> bool {
    let (ufrag, password) = SESSIONS[index];
    stun::is_stun(payload)
        && stun::parse(payload).is_ok_and(|message| {
            message.is_binding_request()
                && message.local_ufrag() == Some(ufrag)
                && message.verify_integrity(payload, password)
                && message.fingerprint_ok(payload)
        })
}

fuzz_target!(|data: &[u8]| {
    let registrations = Arc::new(Registrations::default());
    let responses = Arc::new(StunResponses::default());
    let stats = Arc::new(DemuxStats::default());
    let host_v4: SocketAddr = HOST_V4.parse().unwrap();
    let host_v6: SocketAddr = HOST_V6.parse().unwrap();
    let server: SocketAddr = SERVER.parse().unwrap();
    let mapped_server: SocketAddr = MAPPED_SERVER.parse().unwrap();
    let relayed: SocketAddr = RELAYED.parse().unwrap();
    let (relays, updates) = Relays::channel();
    let mut relay: Option<Model> = None;
    let mut router = Router::new(
        Arc::clone(&registrations),
        Arc::clone(&responses),
        updates,
        Arc::clone(&stats),
        Arc::new(SystemClock),
        "[::]:3478".parse().unwrap(),
        &[host_v4, host_v6],
    );
    let sources: Vec<SocketAddr> = SOURCES.iter().map(|s| s.parse().unwrap()).collect();
    let canonical = |a: SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    // Each session's sink and generation (re-registering starts a new one).
    let mut sinks: Vec<(Arc<Sink>, u32)> = Vec::new();
    for (ufrag, password) in SESSIONS {
        let sink = Arc::new(Sink::default());
        registrations.register(ufrag, password.to_vec(), sink.clone());
        sinks.push((sink, 0));
    }
    let mut live = [true; SESSIONS.len()];
    // What each session learned: canonical address → generation.
    let mut learned: Vec<HashMap<SocketAddr, u32>> = vec![HashMap::new(); SESSIONS.len()];
    let mut waiting = Vec::new();
    let mut routed = 0_u64;
    let mut rest = data;
    while let (Some([op]), Some([pick])) = (take::<1>(&mut rest), take::<1>(&mut rest)) {
        let mut source = sources[usize::from(pick) % sources.len()];
        let index = usize::from(pick >> 4) % SESSIONS.len();
        let payload: Vec<u8> = match op % 10 {
            // Arbitrary bytes.
            0..=2 => {
                let Some(body) = bytes(&mut rest) else { break };
                body.to_vec()
            }
            // A Binding Request for a session, built right or subtly wrong.
            3 | 4 => {
                let Some(id) = take::<12>(&mut rest) else {
                    break;
                };
                let (ufrag, password) = SESSIONS[index];
                let builder = Builder::new(Class::Request, METHOD_BINDING, id)
                    .username(&format!("{ufrag}:remote"))
                    .integrity(if op & 0x10 == 0 { password } else { b"wrong" });
                if op & 0x20 == 0 {
                    builder.fingerprint()
                } else {
                    builder
                }
                .build()
            }
            // A response the supervisor may be waiting for.
            5 => {
                let Some(id) = take::<12>(&mut rest) else {
                    break;
                };
                if op & 0x10 != 0 {
                    waiting.push(responses.expect(id));
                }
                Builder::new(Class::Success, METHOD_BINDING, id)
                    .xor_mapped_address(source)
                    .build()
            }
            // A session goes, or comes back as a new one.
            6 => {
                let (ufrag, password) = SESSIONS[index];
                if live[index] {
                    registrations.unregister(ufrag);
                } else {
                    let sink = Arc::new(Sink::default());
                    registrations.register(ufrag, password.to_vec(), sink.clone());
                    sinks[index] = (sink, sinks[index].1 + 1);
                }
                live[index] = !live[index];
                continue;
            }
            // A worker's channel fills up or drains.
            7 => {
                let full = &sinks[index].0.full;
                full.store(!full.load(Ordering::Relaxed), Ordering::Relaxed);
                continue;
            }
            // The TURN client publishes the relay, or withdraws it.
            8 => {
                let Some([mask, held]) = take::<2>(&mut rest) else {
                    break;
                };
                if mask == 0 {
                    relays.publish(server, None);
                    relay = None;
                    continue;
                }
                let channels: BTreeMap<u16, SocketAddr> = (0..4_u16)
                    .filter(|k| held & (1 << k) != 0)
                    .map(|k| {
                        let peer = usize::from(held >> 4) + usize::from(k) * 3;
                        (0x4000 + k, sources[peer % sources.len()])
                    })
                    .collect();
                let permissions: BTreeSet<_> = sources
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << (i % 8)) != 0)
                    .map(|(_, a)| a.ip().to_canonical())
                    .collect();
                let published = if op & 0x10 == 0 {
                    server
                } else {
                    mapped_server
                };
                relays.publish(
                    published,
                    Some(Relay {
                        relayed,
                        channels: channels
                            .iter()
                            .map(|(n, p)| (Channel::new(*n).unwrap(), *p))
                            .collect(),
                        permissions: permissions.clone(),
                    }),
                );
                relay = Some((channels, permissions));
                continue;
            }
            // The TURN server relays a datagram from a peer: a check for a
            // session (right or wrong) or any bytes, as ChannelData or in a
            // Data indication, whole or not.
            _ => {
                let Some([kind, channel]) = take::<2>(&mut rest) else {
                    break;
                };
                let inner = if kind & 1 == 0 {
                    let Some(body) = bytes(&mut rest) else { break };
                    body.to_vec()
                } else {
                    let Some(id) = take::<12>(&mut rest) else {
                        break;
                    };
                    let (ufrag, password) = SESSIONS[index];
                    Builder::new(Class::Request, METHOD_BINDING, id)
                        .username(&format!("{ufrag}:remote"))
                        .integrity(if kind & 2 == 0 { password } else { b"wrong" })
                        .fingerprint()
                        .build()
                };
                let mut message = Vec::new();
                if kind & 4 == 0 {
                    let number = Channel::new(0x4000 + u16::from(channel % 6)).unwrap();
                    turn::frame_channel_data(number, &inner, kind & 8 != 0, &mut message).unwrap();
                    if kind & 0x40 != 0 {
                        message
                            .truncate(message.len().saturating_sub(1 + usize::from(channel >> 4)));
                    }
                } else {
                    let builder = Builder::new(Class::Indication, turn::METHOD_DATA, [kind; 12])
                        .xor_address(turn::ATTR_XOR_PEER_ADDRESS, source);
                    message = if kind & 8 == 0 {
                        builder.attribute(turn::ATTR_DATA, &inner)
                    } else {
                        builder
                    }
                    .build();
                }
                source = if kind & 0x80 == 0 {
                    server
                } else {
                    mapped_server
                };
                message
            }
        };
        let before: Vec<usize> = sinks
            .iter()
            .map(|(s, _)| s.frames.lock().unwrap().len())
            .collect();
        let learned_before = DemuxStats::get(&stats.addresses_learned);
        let relayed_before = DemuxStats::get(&stats.relayed);
        let discarded_before = DemuxStats::get(&stats.relay_discarded);
        let destination: Option<IpAddr> = match (op / 10) % 3 {
            0 => None,
            choice => Some(DESTINATIONS[usize::from(choice) - 1].parse().unwrap()),
        };
        router.route(&payload, source, destination);
        routed += 1;
        let get = DemuxStats::get;
        assert_eq!(
            get(&stats.received),
            routed,
            "every datagram is counted as received"
        );
        assert_eq!(
            get(&stats.responses)
                + get(&stats.forwarded)
                + get(&stats.worker_full)
                + get(&stats.stun_rejected)
                + get(&stats.relay_discarded)
                + get(&stats.unroutable),
            routed,
            "every datagram lands in exactly one bucket"
        );
        // What the datagram is once a TURN server's wrapping is off:
        // the peer, the local address it arrived at and its bytes, or
        // nothing for one discarded.
        let expected = expect(&payload, canonical(source), server, relay.as_ref());
        let counted = (
            DemuxStats::get(&stats.relayed) - relayed_before,
            DemuxStats::get(&stats.relay_discarded) - discarded_before,
        );
        let routed_as = match expected {
            Expect::Direct => {
                assert_eq!(counted, (0, 0), "not the server's: routed as it arrived");
                let from = canonical(source);
                let local = match destination {
                    Some(ip) => SocketAddr::new(ip.to_canonical(), host_v4.port()),
                    None if from.is_ipv4() => host_v4,
                    None => host_v6,
                };
                Some((from, local, payload))
            }
            Expect::Relayed(peer, data) => {
                assert_eq!(counted, (1, 0), "unwrapped");
                Some((peer, relayed, data))
            }
            Expect::Discarded => {
                assert_eq!(counted, (0, 1), "discarded as the server's");
                None
            }
        };
        let Some((from, local, payload)) = routed_as else {
            for (i, (sink, _)) in sinks.iter().enumerate() {
                assert_eq!(
                    sink.frames.lock().unwrap().len(),
                    before[i],
                    "a discarded datagram reaches no worker"
                );
            }
            assert_eq!(DemuxStats::get(&stats.addresses_learned), learned_before);
            continue;
        };
        if DemuxStats::get(&stats.addresses_learned) > learned_before {
            // Learned even when the worker's channel was full.
            let i = (0..SESSIONS.len())
                .find(|&i| proves(&payload, i))
                .expect("only a proof teaches an address");
            assert!(live[i], "a session that is gone learns nothing");
            // An address another session learned moves to this one, and
            // stops counting against that one's cap (RFC 8445 §7.3).
            for other in &mut learned {
                other.remove(&from);
            }
            learned[i].insert(from, sinks[i].1);
        }
        for (i, (sink, generation)) in sinks.iter().enumerate() {
            let frames = sink.frames.lock().unwrap();
            let new = &frames[before[i]..];
            assert!(new.len() <= 1, "one datagram, one frame");
            let Some((got_source, destination, got)) = new.first() else {
                continue;
            };
            assert!(live[i], "a session that is gone gets nothing");
            assert_eq!(*got_source, from, "the source is canonical");
            assert_eq!(
                *destination, local,
                "the destination is the family's host, or the relayed address"
            );
            assert_eq!(got, &payload, "forwarded as it arrived, or as relayed");
            let known = learned[i].get(&from) == Some(generation);
            assert!(
                known,
                "only learned addresses and the proof that taught one pass"
            );
            let current = learned[i].values().filter(|g| *g == generation).count();
            assert!(
                current <= MAX_ADDRS_PER_SESSION,
                "at most {MAX_ADDRS_PER_SESSION} addresses"
            );
        }
    }
});
