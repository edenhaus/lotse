//! `webrtc_session`: a connected session never panics on whatever a viewer
//! or a stranger sends it, and what it writes keeps the rewrite contract.
//! The headless viewer of `lotse-testing` connects to a real `Session` in
//! memory (ICE, DTLS, SRTP), then the input drives both sides: datagrams of
//! arbitrary bytes from the viewer's address and from an unknown one (STUN,
//! DTLS records into `dimpl`, SRTP and SRTCP into str0m: the DTLS record
//! layer only, since the handshake is done before any fuzzed byte
//! arrives), trickled candidates, keyframe requests, skips, time, and live
//! video and audio packets with arbitrary camera timestamps, epochs, flags,
//! ages and lateness. What the viewer receives must keep the rewrite
//! contract: per stream, sequence numbers continuous across skips (RFC 3550
//! §5.1), and every packet's timestamp the camera's plus one constant per
//! epoch.
//! Run with `cargo +nightly fuzz run webrtc_session` from the repository
//! root.

#![no_main]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use libfuzzer_sys::fuzz_target;
use lotse_core::Orientation;
use lotse_core::codec::Codec;
use lotse_core::media::{MediaPacket, RtpHeaderFields};
use lotse_core::session::{
    IceCredentials, SessionEngine as _, SessionEvent, SessionLimits, SessionOutput, SessionRequest,
    Transport,
};
use lotse_testing::viewer::{Outgoing, Viewer};
use lotse_webrtc::Session;

/// The viewer's address.
const BROWSER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    50_000,
);
/// The daemon's host candidate.
const DAEMON: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
    18_556,
);
/// Someone else on the network.
const STRANGER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
    40_000,
);

/// A packet the session wrote, as the camera stamped it.
#[derive(Debug, Clone)]
struct Written {
    /// The camera's RTP timestamp.
    ts: u32,
    /// The epoch.
    epoch: u32,
    /// The payload, which identifies it at the viewer.
    payload: Vec<u8>,
}

/// The session and the viewer, with the datagrams between them.
struct Pair {
    /// The session under test.
    session: Session,
    /// The headless viewer.
    viewer: Viewer,
    /// Simulated time.
    now: Instant,
    /// Datagrams for the viewer.
    to_viewer: Vec<(SocketAddr, Vec<u8>)>,
    /// Datagrams for the session.
    to_daemon: Vec<Outgoing>,
    /// The session reported `Connected`.
    connected: bool,
}

impl Pair {
    /// Takes everything the session has; joins on `Connected`.
    fn drain(&mut self) {
        // Bounded: a session that never runs dry is a finding too.
        for _ in 0..100_000 {
            match self.session.poll() {
                SessionOutput::Transmit {
                    source, payload, ..
                } => self.to_viewer.push((source, payload)),
                SessionOutput::Event(SessionEvent::Connected) => {
                    self.connected = true;
                    self.session.join(self.now, None);
                }
                SessionOutput::Event(_) | SessionOutput::Uplink(_) => {}
                SessionOutput::Timeout(_) => return,
            }
        }
        panic!("the session never stops producing output");
    }

    /// Lets `advance` pass and moves the datagrams in flight.
    fn step(&mut self, advance: Duration) {
        self.now += advance;
        self.session.handle_timeout(self.now);
        self.drain();
        self.viewer.timeout(self.now, &mut self.to_daemon);
        for (source, bytes) in std::mem::take(&mut self.to_viewer) {
            self.viewer
                .receive(self.now, source, &bytes, &mut self.to_daemon);
        }
        for datagram in std::mem::take(&mut self.to_daemon) {
            self.session.handle_datagram(
                self.now,
                Transport::Udp,
                datagram.source,
                datagram.destination,
                &datagram.payload,
            );
            self.drain();
        }
    }

    /// One datagram into the session.
    fn datagram(&mut self, from: SocketAddr, bytes: &[u8]) {
        self.session
            .handle_datagram(self.now, Transport::Udp, from, DAEMON, bytes);
        self.drain();
    }
}

/// Whether two media sections of `offer` carry one `a=mid`.
fn duplicate_mids(offer: &str) -> bool {
    let mut mids: Vec<&str> = offer
        .lines()
        .filter_map(|l| l.strip_prefix("a=mid:"))
        .collect();
    let all = mids.len();
    mids.sort_unstable();
    mids.dedup();
    mids.len() != all
}

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

/// Checks that `received`, the packets of one stream as the viewer got
/// them, keep the rewrite contract against `written`: every packet the
/// session wrote has the next sequence number, whether or not the viewer
/// got the ones before, and the camera's timestamp plus one offset per
/// epoch. Packets that carry no written payload (retransmissions, padding)
/// are not the stream's own and are passed over.
fn check_rewrite(kind: &str, written: &[Written], received: &[(u16, u32, Vec<u8>)]) {
    let mut offsets: Vec<(u32, u32)> = Vec::new();
    let mut first: Option<(usize, u16)> = None;
    let mut from = 0;
    for (seq, ts, payload) in received {
        let Some(at) = written[from..].iter().position(|w| &w.payload == payload) else {
            continue;
        };
        let index = from + at;
        from = index + 1;
        let source = &written[index];
        match first {
            None => first = Some((index, *seq)),
            Some((first_index, first_seq)) => assert_eq!(
                *seq,
                first_seq.wrapping_add(u16::try_from((index - first_index) % 65_536).unwrap()),
                "{kind}: sequence numbers continue across skips"
            ),
        }
        let offset = ts.wrapping_sub(source.ts);
        match offsets.iter().find(|(epoch, _)| *epoch == source.epoch) {
            Some((_, known)) => {
                assert_eq!(offset, *known, "{kind}: one timestamp offset per epoch");
            }
            None => offsets.push((source.epoch, offset)),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    lotse_webrtc::install_crypto_provider();
    let mut rest = data;
    let Some([setup]) = take::<1>(&mut rest) else {
        return;
    };
    // Bit 0 of the setup byte adds audio; bits 1 to 3 pick the stream's
    // orientation, which the writer marks when the offer negotiates CVO.
    let audio = setup & 1 != 0;
    let t0 = Instant::now();
    let viewer = if audio {
        Viewer::new_with_audio(BROWSER, t0)
    } else {
        Viewer::new(BROWSER, t0)
    }
    .expect("a viewer");
    let request = SessionRequest {
        offer: viewer.offer().to_owned(),
        ice: IceCredentials {
            ufrag: "fuzzufrag".into(),
            pass: "fuzzpassword0123456789abc".into(),
        },
        candidates: vec![DAEMON],
        tcp_candidates: vec![],
        video: Arc::new(Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        }),
        audio: audio.then(|| Arc::new(Codec::Pcmu)),
        backchannel: None,
        orientation: Orientation::ALL[usize::from((setup >> 1) & 7)],
        limits: SessionLimits::default(),
        wall: SystemTime::UNIX_EPOCH,
    };
    let (session, answer) = match Session::answer(&request, t0) {
        Ok(answered) => answered,
        // str0m 0.24's offerer can draw one random mid for two media added
        // in one change (observed 2026-10-01); the session refuses that
        // offer, rightly. The viewer is test code: start over.
        Err(_) if duplicate_mids(&request.offer) => return,
        Err(err) => panic!("the viewer's offer is answered: {err:?}\n{}", request.offer),
    };
    let mut pair = Pair {
        session,
        viewer,
        now: t0,
        to_viewer: Vec::new(),
        to_daemon: Vec::new(),
        connected: false,
    };
    pair.viewer
        .accept_answer(&answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.drain();
    for _ in 0..500 {
        if pair.connected && pair.viewer.is_connected() {
            break;
        }
        pair.step(Duration::from_millis(5));
    }
    assert!(
        pair.connected && pair.viewer.is_connected(),
        "connects in memory"
    );

    let mut video: Vec<Written> = Vec::new();
    let mut voice: Vec<Written> = Vec::new();
    let mut ts = 0_u32;
    let mut seq = 0_u16;
    let mut packet_id = 0_u32;
    let mut epoch = 0_u32;
    while let Some([op]) = take::<1>(&mut rest) {
        match op % 8 {
            0 | 1 => {
                let Some(body) = bytes(&mut rest) else { break };
                pair.datagram(if op % 8 == 0 { BROWSER } else { STRANGER }, body);
            }
            2 | 3 => {
                // [flags][ts delta:u16][age ms][lateness ms][len][payload]
                let (Some([flags]), Some(delta), Some([age]), Some([late]), Some(body)) = (
                    take::<1>(&mut rest),
                    take::<2>(&mut rest),
                    take::<1>(&mut rest),
                    take::<1>(&mut rest),
                    bytes(&mut rest),
                ) else {
                    break;
                };
                // Back by up to 32768 ticks, or ahead.
                ts = ts
                    .wrapping_add(u32::from(u16::from_le_bytes(delta)))
                    .wrapping_sub(1 << 15);
                seq = seq.wrapping_add(1);
                packet_id = packet_id.wrapping_add(1);
                // Unique payloads, so the viewer's packets map back.
                let mut payload = packet_id.to_be_bytes().to_vec();
                payload.extend_from_slice(body);
                // Epochs only move forward, as a track stamps them.
                if flags & 0x20 != 0 {
                    epoch = epoch.wrapping_add(1);
                }
                let packet = MediaPacket {
                    arrival: pair
                        .now
                        .checked_sub(Duration::from_millis(u64::from(age)))
                        .unwrap_or(pair.now),
                    rtp: RtpHeaderFields {
                        pt: 96,
                        seq,
                        ts,
                        marker: flags & 1 != 0,
                        ssrc: 1,
                    },
                    frame_start: flags & 2 != 0,
                    keyframe_start: flags & 4 != 0,
                    epoch,
                    lateness: Duration::from_millis(u64::from(late) * 4),
                    payload: Arc::from(payload.as_slice()),
                };
                let before = pair.session.stats();
                if op % 8 == 2 {
                    pair.session.write_video(pair.now, &packet, pair.now);
                    if pair.session.stats().packets > before.packets {
                        video.push(Written { ts, epoch, payload });
                    }
                } else {
                    pair.session.write_audio(pair.now, &packet, pair.now);
                    if pair.session.stats().audio_packets > before.audio_packets {
                        voice.push(Written { ts, epoch, payload });
                    }
                }
                pair.drain();
            }
            4 => {
                let Some([ms]) = take::<1>(&mut rest) else {
                    break;
                };
                pair.step(Duration::from_millis(u64::from(ms)));
            }
            5 => pair.session.skip_to_keyframe("fuzz"),
            6 => {
                pair.viewer.request_keyframe(&mut pair.to_daemon);
                pair.step(Duration::ZERO);
            }
            _ => {
                let Some(body) = bytes(&mut rest) else { break };
                pair.session
                    .add_remote_candidate(pair.now, &String::from_utf8_lossy(body));
                pair.drain();
            }
        }
    }
    for _ in 0..10 {
        pair.step(Duration::from_millis(10));
    }
    let seen = |packets: &[str0m::rtp::RtpPacket]| -> Vec<(u16, u32, Vec<u8>)> {
        packets
            .iter()
            .map(|p| {
                (
                    p.header.sequence_number,
                    p.header.timestamp,
                    p.payload.to_vec(),
                )
            })
            .collect()
    };
    check_rewrite("video", &video, &seen(pair.viewer.packets()));
    check_rewrite("audio", &voice, &seen(pair.viewer.audio_packets()));
});
