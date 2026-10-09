//! The M1 spike: what str0m's RTP mode gives the cut-through design. Two
//! `Rtc`s are connected in memory: the daemon side (RTP mode, ICE
//! credentials supplied from outside, `playout-delay`, RTX) and a browser
//! stand-in that offers `recvonly` video. Every assertion is a finding.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use lotse_core::clock::{Clock as _, SystemClock};
use str0m::format::Codec;
use str0m::media::{Direction, Frequency, KeyframeRequestKind, MediaKind, MediaTime, Mid, Pt};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{
    Extension, ExtensionMap, ExtensionValues, RawPacket, RtpHeader, RtpPacket, RtpWrite, Ssrc,
};
use str0m::{Candidate, CandidateKind, Event, IceCreds, Input, Output, Rtc};

/// TEST-NET-1 addresses: str0m refuses loopback and link-local candidates.
const DAEMON_ADDR: &str = "192.0.2.10:18556";
const BROWSER_ADDR: &str = "192.0.2.20:40000";

fn creds() -> IceCreds {
    IceCreds {
        ufrag: "lotseufrag".into(),
        pass: "lotsepassword0123456789ab".into(),
    }
}

/// One end of the in-memory link.
struct Side {
    rtc: Rtc,
    addr: SocketAddr,
    events: Vec<Event>,
    rtp: Vec<RtpPacket>,
    rtcp_rx: Vec<Rtcp>,
    rtp_tx: Vec<RtpHeader>,
    rtp_rx: Vec<RtpHeader>,
    timeout: Option<Instant>,
}

type Datagram = (SocketAddr, SocketAddr, Vec<u8>);

impl Side {
    fn new(rtc: Rtc, addr: &str) -> Self {
        let mut side = Self {
            rtc,
            addr: addr.parse().unwrap(),
            events: Vec::new(),
            rtp: Vec::new(),
            rtcp_rx: Vec::new(),
            rtp_tx: Vec::new(),
            rtp_rx: Vec::new(),
            timeout: None,
        };
        let host = Candidate::host(side.addr, "udp").unwrap();
        assert!(side.rtc.add_local_candidate(host).is_some());
        side
    }

    /// Polls until the next timeout, collecting transmits and events.
    fn drain(&mut self, out: &mut Vec<Datagram>) {
        loop {
            match self.rtc.poll_output().unwrap() {
                Output::Timeout(at) => {
                    self.timeout = Some(at);
                    break;
                }
                Output::Transmit(t) => out.push((t.source, t.destination, t.contents.to_vec())),
                Output::Event(Event::RtpPacket(packet)) => self.rtp.push(packet),
                Output::Event(Event::RawPacket(raw)) => match *raw {
                    RawPacket::RtcpRx(rtcp) => self.rtcp_rx.push(rtcp),
                    RawPacket::RtpTx(header, _) => self.rtp_tx.push(header),
                    RawPacket::RtpRx(header, _) => self.rtp_rx.push(header),
                    RawPacket::RtcpTx(_) => {}
                },
                Output::Event(event) => self.events.push(event),
            }
        }
    }

    fn receive(&mut self, now: Instant, datagram: &Datagram, out: &mut Vec<Datagram>) {
        let (source, destination, bytes) = datagram;
        let contents = DatagramRecv::try_from(bytes.as_slice()).unwrap();
        self.rtc
            .handle_input(Input::Receive(
                now,
                Receive {
                    proto: Protocol::Udp,
                    source: *source,
                    destination: *destination,
                    contents,
                },
            ))
            .unwrap();
        self.drain(out);
    }
}

/// The daemon (`l`) and the browser (`r`) with the datagrams in flight.
struct Pair {
    l: Side,
    r: Side,
    now: Instant,
    to_r: Vec<Datagram>,
    to_l: Vec<Datagram>,
    /// Drop the next daemon → browser datagram longer than this.
    drop_to_r_over: Option<usize>,
    dropped: usize,
}

impl Pair {
    fn new() -> Self {
        lotse_webrtc::install_crypto_provider();
        let now = SystemClock.now();
        let daemon = lotse_webrtc::session_config(creds())
            .enable_raw_packets(true)
            .build(now);
        // The stand-in offers what Chrome offers: the standard extensions
        // plus playout-delay; an answerer can only echo what was offered.
        let mut offered = ExtensionMap::standard();
        offered.set(lotse_webrtc::PLAYOUT_DELAY_EXT_ID, Extension::PlayoutDelay);
        let browser = Rtc::builder()
            .set_rtp_mode(true)
            .set_extension_map(offered)
            .enable_raw_packets(true)
            .build(now);
        Self {
            l: Side::new(daemon, DAEMON_ADDR),
            r: Side::new(browser, BROWSER_ADDR),
            now,
            to_r: Vec::new(),
            to_l: Vec::new(),
            drop_to_r_over: None,
            dropped: 0,
        }
    }

    /// The browser offers `recvonly` video, the daemon answers; runs until
    /// both are connected. Returns the mid and the answer.
    fn connect(&mut self) -> (Mid, String) {
        let mut offer_api = self.r.rtc.sdp_api();
        let mid = offer_api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
        let (offer, pending) = offer_api.apply().unwrap();
        let answer = self.l.rtc.sdp_api().accept_offer(offer).unwrap();
        let sdp = answer.to_sdp_string();
        self.r.rtc.sdp_api().accept_answer(pending, answer).unwrap();
        self.run_until(
            |p| p.l.rtc.is_connected() && p.r.rtc.is_connected(),
            5_000,
            "ice and dtls",
        );
        (mid, sdp)
    }

    /// Advances time by at most 10 ms (to the next timeout when sooner),
    /// fires the timeouts and delivers what was in flight.
    fn step(&mut self) {
        let earliest = [self.l.timeout, self.r.timeout].into_iter().flatten().min();
        let floor = self.now + Duration::from_millis(1);
        let cap = self.now + Duration::from_millis(10);
        self.now = earliest.map_or(cap, |at| at.clamp(floor, cap));
        self.l.rtc.handle_input(Input::Timeout(self.now)).unwrap();
        self.l.drain(&mut self.to_r);
        self.r.rtc.handle_input(Input::Timeout(self.now)).unwrap();
        self.r.drain(&mut self.to_l);
        for datagram in std::mem::take(&mut self.to_r) {
            if self
                .drop_to_r_over
                .is_some_and(|over| datagram.2.len() > over)
            {
                self.drop_to_r_over = None;
                self.dropped += 1;
                continue;
            }
            self.r.receive(self.now, &datagram, &mut self.to_l);
        }
        for datagram in std::mem::take(&mut self.to_l) {
            self.l.receive(self.now, &datagram, &mut self.to_r);
        }
    }

    fn run_until(&mut self, done: impl Fn(&Self) -> bool, max_steps: usize, what: &str) {
        for _ in 0..max_steps {
            if done(self) {
                return;
            }
            self.step();
        }
        panic!(
            "{what}: not reached after {max_steps} steps; browser events {:?}",
            self.r.events
        );
    }

    /// The transmit stream the answer declared for `mid`, with the SSRC
    /// and RTX SSRC str0m allocated. Finding: the answerer allocates them
    /// (`a=ssrc-group:FID` in the answer); declaring a second stream for
    /// the mid with `declare_stream_tx` makes a duplicate that
    /// `stream_tx_by_mid` may return instead, so sessions must take the
    /// negotiated one.
    fn negotiated_ssrcs(&mut self, mid: Mid) -> (Ssrc, Ssrc) {
        let mut api = self.l.rtc.direct_api();
        let stream = api
            .stream_tx_by_mid(mid, None)
            .expect("the answer declared a stream");
        (stream.ssrc(), stream.rtx().expect("rtx was negotiated"))
    }

    fn video_pt(&self) -> Pt {
        self.l
            .rtc
            .codec_config()
            .params()
            .iter()
            .find(|p| p.spec().codec == Codec::H264 && p.resend().is_some())
            .expect("an H.264 payload type with RTX")
            .pt()
    }

    /// Writes one packet the way the cut-through writer will: our
    /// sequence number, the camera's timestamp, the wallclock from the
    /// clock map, `playout-delay` 0/0, nackable.
    fn write(&mut self, mid: Mid, pt: Pt, seq: u64, ts: u32, payload: &[u8]) {
        let ext_vals = ExtensionValues {
            play_delay_min: Some(MediaTime::new(0, Frequency::HUNDREDTHS)),
            play_delay_max: Some(MediaTime::new(0, Frequency::HUNDREDTHS)),
            ..ExtensionValues::default()
        };
        let write = RtpWrite::new(pt, seq.into(), ts, self.now, payload)
            .marker(true)
            .nackable(true)
            .ext_vals(ext_vals);
        self.l
            .rtc
            .direct_api()
            .stream_tx_by_mid(mid, None)
            .expect("declared stream")
            .write_rtp(write);
    }
}

#[test]
fn rtp_mode_cuts_packets_through_with_our_credentials_and_playout_delay() {
    let mut pair = Pair::new();
    let (mid, answer) = pair.connect();
    // Finding: the answer carries the credentials the supervisor chose,
    // H.264 with packetization-mode 1, RTX and the playout-delay extension.
    assert!(answer.contains("a=ice-ufrag:lotseufrag"), "{answer}");
    assert!(
        answer.contains("a=ice-pwd:lotsepassword0123456789ab"),
        "{answer}"
    );
    assert!(answer.contains("packetization-mode=1"), "{answer}");
    assert!(answer.contains(" rtx/90000"), "{answer}");
    assert!(answer.contains("playout-delay"), "{answer}");

    let pt = pair.video_pt();
    let (ssrc, rtx) = pair.negotiated_ssrcs(mid);
    assert!(
        answer.contains(&format!("a=ssrc-group:FID {} {}", *ssrc, *rtx)),
        "{answer}"
    );
    let payload = [0x65_u8; 400]; // an IDR slice NAL, as far as RTP mode cares
    for i in 0..10_u32 {
        pair.write(mid, pt, 1000 + u64::from(i), 90_000 + i * 3_000, &payload);
        for _ in 0..3 {
            pair.step();
        }
    }
    pair.run_until(|p| p.r.rtp.len() >= 10, 500, "ten packets at the browser");
    // Finding: sequence numbers, timestamps, marker, SSRC and the payload
    // arrive as written; the payload is handed over as `Arc<[u8]>`, so the
    // only copy per viewer is SRTP's.
    for (i, packet) in pair.r.rtp.iter().take(10).enumerate() {
        let i = u32::try_from(i).unwrap();
        assert_eq!(*packet.seq_no, 1000 + u64::from(i));
        assert_eq!(packet.header.timestamp, 90_000 + i * 3_000);
        assert!(packet.header.marker);
        assert_eq!(packet.header.ssrc, ssrc);
        assert_eq!(&packet.payload[..], &payload[..]);
        assert_eq!(
            packet.header.ext_vals.play_delay_min,
            Some(MediaTime::new(0, Frequency::HUNDREDTHS))
        );
        assert_eq!(
            packet.header.ext_vals.play_delay_max,
            Some(MediaTime::new(0, Frequency::HUNDREDTHS))
        );
    }
}

#[test]
fn a_lost_packet_is_nacked_and_resent_over_rtx() {
    let mut pair = Pair::new();
    let (mid, _) = pair.connect();
    let pt = pair.video_pt();
    let (_, rtx) = pair.negotiated_ssrcs(mid);
    let payload = [0x41_u8; 400];
    for seq in 0..20_u64 {
        if seq == 5 {
            // Drop the datagram carrying this packet on its way out.
            pair.drop_to_r_over = Some(300);
        }
        pair.write(mid, pt, seq, u32::try_from(seq).unwrap() * 3_000, &payload);
        for _ in 0..3 {
            pair.step();
        }
    }
    assert_eq!(pair.dropped, 1, "one datagram was dropped");
    pair.run_until(
        |p| p.r.rtp.iter().any(|packet| *packet.seq_no == 5),
        2_000,
        "the lost packet after retransmission",
    );
    // Finding: the browser side asked with a NACK, and the daemon answered
    // on the RTX SSRC; the repaired packet is indistinguishable at the
    // receiver.
    assert!(
        pair.l
            .rtcp_rx
            .iter()
            .any(|rtcp| matches!(rtcp, Rtcp::Nack(_))),
        "no NACK reached the daemon: {:?}",
        pair.l.rtcp_rx
    );
    assert!(
        pair.r.rtp_rx.iter().any(|h| h.ssrc == rtx),
        "no retransmission on the RTX SSRC; sent {:?}, received {:?}",
        pair.l
            .rtp_tx
            .iter()
            .map(|h| (h.ssrc, h.sequence_number))
            .collect::<Vec<_>>(),
        pair.r
            .rtp_rx
            .iter()
            .map(|h| (h.ssrc, h.sequence_number))
            .collect::<Vec<_>>()
    );
    let seqs: Vec<u64> = pair.r.rtp.iter().map(|p| *p.seq_no).collect();
    assert!((0..20).all(|seq| seqs.contains(&seq)), "{seqs:?}");
}

#[test]
fn sender_reports_follow_the_wallclock_we_write_and_plis_reach_us() {
    let mut pair = Pair::new();
    let (mid, _) = pair.connect();
    let pt = pair.video_pt();
    let (ssrc, _) = pair.negotiated_ssrcs(mid);
    let payload = [0x41_u8; 200];
    let start = pair.now;
    // Three hundred packets whose RTP timestamps follow the simulated
    // wallclock at 90 kHz, as the clock map will stamp them.
    for i in 0..300_u64 {
        let ts = u32::try_from((pair.now - start).as_micros() * 9 / 100).unwrap();
        pair.write(mid, pt, i, ts, &payload);
        for _ in 0..4 {
            pair.step();
        }
    }
    assert!(
        pair.r.rtp.len() >= 250,
        "{} packets sent, {} received",
        pair.l.rtp_tx.len(),
        pair.r.rtp.len()
    );
    let reports: Vec<_> = pair
        .r
        .rtcp_rx
        .iter()
        .filter_map(|rtcp| match rtcp {
            // A report from before the first packet carries no timing.
            Rtcp::SenderReport(sr)
                if sr.sender_info.ssrc == ssrc && sr.sender_info.sender_packet_count > 0 =>
            {
                Some(sr.sender_info)
            }
            _ => None,
        })
        .collect();
    assert!(reports.len() >= 2, "sender reports: {reports:?}");
    // Finding: str0m derives the SR's NTP and RTP time from the wallclock
    // and timestamp of the packets we write, so the browser syncs on the
    // camera's clock map: between two reports, NTP advances as RTP does.
    let first = &reports[0];
    let last = &reports[reports.len() - 1];
    let ntp = last
        .ntp_time
        .duration_since(first.ntp_time)
        .unwrap()
        .as_secs_f64();
    // A parsed report carries raw ticks (its `MediaTime` has no clock rate).
    let ticks = last.rtp_time.numer().saturating_sub(first.rtp_time.numer());
    let rtp = f64::from(u32::try_from(ticks).unwrap()) / 90_000.0;
    assert!(ntp > 1.0, "reports span {ntp} s");
    assert!(
        (ntp - rtp).abs() < 0.05,
        "ntp advanced {ntp} s, rtp {rtp} s; first {first:?} last {last:?}"
    );
    let elapsed = (pair.now - start).as_secs_f64();
    assert!(elapsed >= 5.0, "{elapsed} s simulated");

    // Finding: a PLI from the browser surfaces as a keyframe request event.
    pair.r
        .rtc
        .direct_api()
        .stream_rx_by_mid(mid, None)
        .expect("receive stream")
        .request_keyframe(KeyframeRequestKind::Pli);
    pair.run_until(
        |p| {
            p.l.events.iter().any(
                |e| matches!(e, Event::KeyframeRequest(r) if r.kind == KeyframeRequestKind::Pli),
            )
        },
        200,
        "the keyframe request",
    );
}

#[test]
fn relay_candidates_are_accepted_and_transmits_name_their_source() {
    let mut pair = Pair::new();
    let relay: SocketAddr = "198.51.100.7:3478".parse().unwrap();
    let relayed = Candidate::relayed(relay, pair.l.addr, "udp").unwrap();
    assert_eq!(relayed.kind(), CandidateKind::Relayed);
    // Finding: str0m takes a relayed local candidate; the answer lists it.
    assert!(pair.l.rtc.add_local_candidate(relayed).is_some());
    let (_, answer) = pair.connect();
    assert!(answer.contains("typ relay"), "{answer}");
    // Finding: every transmit names the local address it leaves from, which
    // is what the worker needs to pick the shared socket or the TURN
    // channel.
    let mut out = Vec::new();
    pair.l.drain(&mut out);
    let daemon_addr = pair.l.addr;
    assert!(
        out.iter()
            .all(|(source, _, _)| *source == daemon_addr || *source == relay),
        "{:?}",
        out.iter().map(|d| (d.0, d.1)).collect::<Vec<_>>()
    );
}
