//! The WebRTC ingest: the engine against a str0m camera that answers, in
//! memory, through every way an attempt goes and ends; then the source
//! over loopback UDP, its signaling played by the test through
//! `FakeSignaling`.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::unchecked_time_subtraction,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::format_collect,
    clippy::type_complexity,
    clippy::needless_pass_by_value,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_codec::h264::test_data;
use lotse_core::clock::{Clock, FakeClock, SystemClock};
use lotse_core::clock_map::ClockMapper;
use lotse_core::codec::{Codec, Kind};
use lotse_core::ingest::{IngestCounters, IngestStats};
use lotse_core::keyframe::KeyframeOutcome;
use lotse_core::signaling::{
    LocalSignal, RemoteSignal, SignalCandidate, SignalClose, SignalingOpener, SignalingRelay, close,
};
use lotse_core::source::{
    BackchannelSlot, ClockInput, ClockReport, ResolvedPeer, SignaledSourceFactory as _, SourceCtx,
    SourceError, SyncHint, TrackSet,
};
use lotse_core::task::spawn_named;
use lotse_core::test_util::FakeSignaling;
use lotse_core::track::TrackLimits;
use lotse_webrtc::ingest::engine::{
    ANSWER_TIMEOUT, ATTEMPT_BUDGET, CONNECT_BY, CONNECT_TIMEOUT, MAX_OFFER_BYTES, PLI_INTERVAL,
    STARTUP_PLIS,
};
use lotse_webrtc::ingest::source::MAX_HOSTS;
use lotse_webrtc::ingest::{
    IngestEngine, IngestOutput, IngestTrack, WebRtcOptions, WebRtcSourceFactory,
};
use str0m::change::SdpOffer;
use str0m::channel::ChannelId;
use str0m::format::Codec as EngineCodec;
use str0m::media::{Mid, Pt};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::rtp::{ExtensionValues, RtpWrite, SeqNo, Ssrc};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// The engine's host candidate (TEST-NET-1).
const ENGINE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 5_000);
/// The camera's.
const CAMERA: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 6_000);

/// Every log line's fields evaluated (and dropped) on this thread while
/// the guard lives: what the engine logs is exercised.
fn logs() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::sink)
            .finish(),
    )
}

fn nest() -> WebRtcOptions {
    WebRtcOptions {
        data_channel: Some("dataSendChannel".into()),
    }
}

/// No data channel: the offer has the audio and the video m-line.
fn media_only() -> WebRtcOptions {
    WebRtcOptions { data_channel: None }
}

/// A camera's str0m: H.264, with Opus when `audio`.
fn camera_config(audio: bool) -> RtcConfig {
    let config = Rtc::builder()
        .set_rtp_mode(true)
        .clear_codecs()
        .enable_h264(true);
    if audio {
        config.enable_opus(true, false)
    } else {
        config
    }
}

/// `answer` with the camera as the DTLS client (`a=setup:active`, RFC 5763
/// §5) rather than str0m's passive, so the engine is the DTLS server: it
/// sends no flight before a `ClientHello` and so never gives the handshake
/// up for time (dimpl 0.9 arms no timer before one). The tests of the
/// connection's deadline use it on a cut link, where the engine as the
/// client would give up after its jittered retransmissions (23 to 39 s)
/// and sometimes before the deadline.
fn camera_dtls_client(answer: String) -> String {
    assert!(answer.contains("a=setup:passive"), "{answer}");
    answer.replace("a=setup:passive", "a=setup:active")
}

/// A datagram between the two.
type Datagram = (SocketAddr, SocketAddr, Vec<u8>);

/// The camera: a str0m answerer that sends H.264 in RTP mode.
struct Camera {
    rtc: Rtc,
    addr: SocketAddr,
    out: Vec<Datagram>,
    connected: bool,
    closed: bool,
    keyframe_requests: usize,
    channels: Vec<(ChannelId, String)>,
    audio: Option<Mid>,
    video: Option<Mid>,
    seq: u16,
    ts: u32,
}

impl Camera {
    /// Answers `offer` from `addr` with `config` at `now`.
    fn answer(offer: &str, addr: SocketAddr, config: RtcConfig, now: Instant) -> (Self, String) {
        lotse_webrtc::install_crypto_provider();
        let mut rtc = config.build(now);
        rtc.add_local_candidate(Candidate::host(addr, "udp").unwrap());
        let answer = rtc
            .sdp_api()
            .accept_offer(SdpOffer::from_sdp_string(offer).unwrap())
            .unwrap()
            .to_sdp_string();
        let video = offer
            .split("m=video")
            .nth(1)
            .and_then(|section| section.lines().find_map(|line| line.strip_prefix("a=mid:")))
            .map(Mid::from);
        let audio = offer
            .split("m=audio")
            .nth(1)
            .and_then(|section| section.lines().find_map(|line| line.strip_prefix("a=mid:")))
            .map(Mid::from);
        let mut camera = Self {
            rtc,
            addr,
            audio,
            out: Vec::new(),
            connected: false,
            closed: false,
            keyframe_requests: 0,
            channels: Vec::new(),
            video,
            seq: 0,
            ts: 90_000,
        };
        camera.drain();
        (camera, answer)
    }

    fn drain(&mut self) {
        loop {
            match self.rtc.poll_output() {
                Ok(Output::Transmit(t)) => {
                    self.out
                        .push((t.source, t.destination, Vec::from(t.contents)));
                }
                Ok(Output::Event(event)) => match event {
                    Event::Connected => self.connected = true,
                    Event::KeyframeRequest(_) => self.keyframe_requests += 1,
                    Event::ChannelOpen(id, label) => self.channels.push((id, label)),
                    Event::Closed => self.closed = true,
                    _ => {}
                },
                Ok(Output::Timeout(_)) | Err(_) => return,
            }
        }
    }

    /// One datagram from `source`, whatever pair it came on: an agent
    /// receives data on any of the candidates exchanged (RFC 8445 §12).
    /// Behind `Rtc::accepts`, str0m 0.25 would drop the engine's first
    /// DTLS flight when it comes before the camera's own check of the pair
    /// succeeded, a race on loopback (observed 2026-11-08).
    fn receive(&mut self, now: Instant, source: SocketAddr, bytes: &[u8]) {
        let Ok(contents) = DatagramRecv::try_from(bytes) else {
            return;
        };
        let input = Input::Receive(
            now,
            Receive {
                proto: Protocol::Udp,
                source,
                destination: self.addr,
                contents,
            },
        );
        if self.rtc.handle_input(input).is_ok() {
            self.drain();
        }
    }

    fn timeout(&mut self, now: Instant) {
        if self.rtc.handle_input(Input::Timeout(now)).is_ok() {
            self.drain();
        }
    }

    /// The payload types the camera may send H.264 in, its answer's order.
    fn h264_pts(&self) -> Vec<Pt> {
        self.pts(self.video.unwrap(), EngineCodec::H264)
    }

    /// The payload types the camera may send `codec` in on `mid`, its
    /// answer's order.
    fn pts(&self, mid: Mid, codec: EngineCodec) -> Vec<Pt> {
        let media = self.rtc.media(mid).unwrap();
        let config = self.rtc.codec_config();
        media
            .remote_pts()
            .iter()
            .copied()
            .filter(|pt| {
                config
                    .find(|params| params.pt() == *pt)
                    .is_some_and(|params| params.spec().codec == codec)
            })
            .collect()
    }

    /// One RTP packet of the video in payload type `pt`.
    fn write(&mut self, now: Instant, pt: Pt, marker: bool, payload: &[u8]) {
        let mid = self.video.unwrap();
        self.write_on(mid, now, pt, marker, payload);
    }

    /// One RTP packet on `mid`.
    fn write_on(&mut self, mid: Mid, now: Instant, pt: Pt, marker: bool, payload: &[u8]) {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let mut api = self.rtc.direct_api();
        let stream = api.stream_tx_by_mid(mid, None).unwrap();
        stream.write_rtp(
            RtpWrite::new(
                pt,
                SeqNo::from(u64::from(seq)),
                self.ts,
                now,
                Arc::<[u8]>::from(payload),
            )
            .marker(marker)
            // RFC 9143 §15: the mid header extension, as libwebrtc sends
            // it, so a receiver maps the SSRC without `a=ssrc`.
            .ext_vals(ExtensionValues {
                mid: Some(mid),
                ..ExtensionValues::default()
            }),
        );
        self.drain();
    }

    /// The video's stream sends from `ssrc` (and its repairs from the
    /// next) from now on, as after an encoder restart.
    fn new_ssrc(&mut self, ssrc: u32) {
        let mid = self.video.unwrap();
        self.rtc
            .direct_api()
            .reset_stream_tx(mid, None, Ssrc::from(ssrc), Some(Ssrc::from(ssrc + 1)))
            .unwrap();
    }

    /// One access unit: the parameter sets and an IDR, or a P slice.
    fn frame(&mut self, now: Instant, keyframe: bool) {
        let pt = self.h264_pts()[0];
        self.ts = self.ts.wrapping_add(3_000);
        if keyframe {
            self.write(now, pt, false, &test_data::sps(640, 480));
            self.write(now, pt, false, &test_data::pps());
            self.write(now, pt, true, &[0x65, 0x88, 0x84, 0x00, 0x10]);
        } else {
            self.write(now, pt, true, &[0x41, 0x9a, 0x02, 0x04]);
        }
    }

    /// Sends `message` on the first data channel it saw open.
    fn send_data(&mut self, message: &[u8]) {
        let (id, _) = self.channels[0];
        self.rtc.channel(id).unwrap().write(true, message).unwrap();
        self.drain();
    }
}

/// The engine and the camera, with the time and the link between them.
struct Pair {
    engine: IngestEngine,
    camera: Option<Camera>,
    now: Instant,
    outputs: Vec<IngestOutput>,
    /// Datagrams go through; `false` cuts the link both ways.
    link: bool,
    /// DTLS records go through (RFC 7983 §7: first byte 20 to 63); `false`
    /// lets only the rest pass.
    dtls: bool,
}

impl Pair {
    fn offer(options: &WebRtcOptions) -> Self {
        Self::offer_on(options, &[ENGINE])
    }

    /// The offer gathered on `hosts`; only [`ENGINE`] reaches the camera.
    fn offer_on(options: &WebRtcOptions, hosts: &[SocketAddr]) -> Self {
        let now = SystemClock.now();
        let mut pair = Self {
            engine: IngestEngine::offer(options, hosts, now, now).unwrap(),
            camera: None,
            now,
            outputs: Vec::new(),
            link: true,
            dtls: true,
        };
        pair.drain();
        pair
    }

    /// The camera answers with `config`; `edit` rewrites the answer
    /// before the engine takes it.
    fn answer(&mut self, config: RtcConfig, edit: impl FnOnce(String) -> String) -> String {
        let (camera, answer) = Camera::answer(self.engine.offer_sdp(), CAMERA, config, self.now);
        self.camera = Some(camera);
        let answer = edit(answer);
        self.engine.accept_answer(self.now, &answer);
        self.drain();
        answer
    }

    fn camera(&mut self) -> &mut Camera {
        self.camera.as_mut().unwrap()
    }

    fn drain(&mut self) {
        for _ in 0..100_000 {
            match self.engine.poll() {
                IngestOutput::Timeout(_) => return,
                IngestOutput::Transmit {
                    source,
                    destination,
                    payload,
                } => {
                    if self.link
                        && (self.dtls || !(20..64).contains(&payload[0]))
                        && source == ENGINE
                        && destination == CAMERA
                        && let Some(camera) = self.camera.as_mut()
                    {
                        camera.receive(self.now, source, &payload);
                    }
                }
                output => self.outputs.push(output),
            }
        }
        panic!("the engine never stops producing output");
    }

    /// Lets `advance` pass and moves the datagrams in flight.
    fn step(&mut self, advance: Duration) {
        self.now += advance;
        self.engine.handle_timeout(self.now);
        self.drain();
        if let Some(camera) = self.camera.as_mut() {
            camera.timeout(self.now);
        }
        self.deliver();
    }

    /// The camera's datagrams into the engine.
    fn deliver(&mut self) {
        let Some(camera) = self.camera.as_mut() else {
            return;
        };
        let out = std::mem::take(&mut camera.out);
        if !self.link {
            return;
        }
        for (source, destination, payload) in out {
            if destination != ENGINE || !self.dtls && (20..64).contains(&payload[0]) {
                continue;
            }
            self.engine.receive(self.now, source, destination, &payload);
            self.drain();
        }
    }

    fn run(&mut self, total: Duration) {
        let tick = Duration::from_millis(10);
        let mut passed = Duration::ZERO;
        while passed < total {
            self.step(tick);
            passed += tick;
        }
    }

    fn connect(&mut self) {
        for _ in 0..1_000 {
            if self.engine.is_connected() && self.camera().connected {
                return;
            }
            self.step(Duration::from_millis(5));
        }
        panic!("never connected: {:?}", self.engine);
    }

    fn frame(&mut self, keyframe: bool) {
        let now = self.now;
        self.camera().frame(now, keyframe);
        // Through the camera's pacer.
        self.step(Duration::ZERO);
    }

    fn tracks(&self) -> Vec<IngestTrack> {
        self.outputs
            .iter()
            .find_map(|output| match output {
                IngestOutput::Tracks(tracks) => Some(tracks.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    fn rtp(&self) -> Vec<(usize, u16, bool)> {
        self.outputs
            .iter()
            .filter_map(|output| match output {
                IngestOutput::Rtp { index, packet, .. } => {
                    Some((*index, packet.seq, packet.marker))
                }
                _ => None,
            })
            .collect()
    }

    fn ended(&self) -> Option<(SourceError, &'static str, String)> {
        self.outputs.iter().find_map(|output| match output {
            IngestOutput::Ended(end) => Some((end.error.clone(), end.close, end.message.clone())),
            _ => None,
        })
    }
}

fn media_lines(sdp: &str) -> Vec<&str> {
    sdp.lines().filter(|line| line.starts_with("m=")).collect()
}

#[test]
fn rfc8829_5_2_1_the_offer_has_audio_video_and_the_data_channel_in_that_order() {
    let _logs = logs();
    lotse_webrtc::install_crypto_provider();
    let now = SystemClock.now();
    let engine = IngestEngine::offer(&nest(), &[ENGINE], now, now).unwrap();
    let offer = engine.offer_sdp();
    assert!(offer.starts_with("v=0\r\n"), "{offer}");
    let lines = media_lines(offer);
    assert_eq!(lines.len(), 3, "{offer}");
    assert!(lines[0].starts_with("m=audio "), "{offer}");
    assert!(lines[1].starts_with("m=video "), "{offer}");
    assert!(lines[2].starts_with("m=application "), "{offer}");
    // RFC 5763 §5, RFC 8842 §5.2: the offerer is actpass.
    assert!(offer.contains("a=setup:actpass"), "{offer}");
    assert!(!offer.contains("a=setup:active"), "{offer}");
    assert_eq!(offer.matches("a=recvonly").count(), 2, "{offer}");
    // RFC 8838 §4: the offerer trickles.
    assert!(offer.contains("a=ice-options:trickle"), "{offer}");
    for codec in [
        "H264/90000",
        "H265/90000",
        "opus/48000/2",
        "PCMU/8000",
        "PCMA/8000",
    ] {
        assert!(offer.contains(codec), "{codec}: {offer}");
    }
    // H.264 in packetization modes 1 and 0 (RFC 6184 §8.1), several
    // profiles.
    assert!(offer.contains("packetization-mode=1"), "{offer}");
    assert!(offer.contains("packetization-mode=0"), "{offer}");
    for profile in ["42001f", "42e01f", "4d001f", "64001f"] {
        assert!(offer.contains(profile), "{profile}: {offer}");
    }
    // The host candidate is in the offer, for integrations that read no
    // trickled one (Nest).
    let host = offer
        .lines()
        .find_map(|line| line.strip_prefix("a=candidate:"))
        .unwrap();
    assert!(host.contains("192.0.2.10 5000 typ host"), "{host}");
    assert!(
        offer.len() <= 16 * 1024,
        "within the supervisor's offer budget"
    );

    // RFC 8838 §8 and §13: trickled as well, then the end of candidates,
    // each of the first media section, its index always set.
    let first_mid = offer
        .lines()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .unwrap();
    let candidates = engine.local_candidates();
    assert_eq!(candidates.len(), 2);
    assert!(candidates[0].candidate.starts_with("candidate:"));
    assert!(candidates[0].candidate.contains("192.0.2.10 5000 typ host"));
    assert!(candidates[1].is_end_of_candidates());
    for candidate in &candidates {
        assert_eq!(candidate.sdp_mid.as_deref(), Some(first_mid));
        assert_eq!(candidate.sdp_mline_index, Some(0));
    }
    assert!(!engine.answered());
    assert!(!engine.is_connected());
    assert!(!engine.is_ended());
    assert!(format!("{engine:?}").contains("Offered"));
}

#[test]
fn rfc8829_5_2_1_without_a_data_channel_the_offer_is_audio_then_video() {
    let _logs = logs();
    lotse_webrtc::install_crypto_provider();
    let engine = IngestEngine::offer(
        &media_only(),
        &[ENGINE],
        SystemClock.now(),
        SystemClock.now(),
    )
    .unwrap();
    let offer = engine.offer_sdp();
    let lines = media_lines(offer);
    assert_eq!(lines.len(), 2, "{offer}");
    assert!(lines[0].starts_with("m=audio "), "{offer}");
    assert!(lines[1].starts_with("m=video "), "{offer}");
    assert_eq!(offer.matches("a=recvonly").count(), 2, "{offer}");
    let audio_mid = offer
        .lines()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .unwrap();
    assert_eq!(
        engine.local_candidates()[0].sdp_mid.as_deref(),
        Some(audio_mid)
    );
}

#[test]
fn rfc8445_5_1_1_without_a_usable_host_address_no_offer_is_made() {
    let _logs = logs();
    lotse_webrtc::install_crypto_provider();
    let now = SystemClock.now();
    let err = IngestEngine::offer(&nest(), &[], now, now).unwrap_err();
    assert_eq!(err, "no usable host candidate among []");
    // IPv4 link-local, which the agent does not gather on.
    let link_local: SocketAddr = "169.254.1.1:5000".parse().unwrap();
    let err = IngestEngine::offer(&nest(), &[link_local], now, now).unwrap_err();
    assert!(err.starts_with("no usable host candidate"), "{err}");
}

#[test]
fn rfc8445_6_1_1_the_offerer_controls_connects_and_carries_the_negotiated_tracks() {
    let _logs = logs();
    let mut pair = Pair::offer(&nest());
    let answer = pair.answer(camera_config(true), |answer| answer);
    // The camera answered as the passive DTLS side or active; either
    // way the engine takes it (actpass).
    assert!(answer.contains("a=setup:"), "{answer}");
    assert!(pair.engine.answered());
    let tracks = pair.tracks();
    assert_eq!(tracks.len(), 2, "{tracks:?}");
    assert_eq!(tracks[0].index, 0);
    assert_eq!(tracks[0].declared.kind, Kind::Audio);
    assert_eq!(tracks[0].declared.codec, Codec::Opus { channels: 2 });
    assert_eq!(tracks[0].declared.clock_rate, 48_000);
    assert_eq!(tracks[1].index, 1);
    assert_eq!(tracks[1].declared.kind, Kind::Video);
    assert!(matches!(tracks[1].declared.codec, Codec::H264 { .. }));
    assert_eq!(
        tracks[1].declared.sets,
        lotse_codec::rtp_ingest::Sprop::H264(lotse_codec::h264::ParameterSets::default())
    );
    assert_eq!(pair.camera().h264_pts()[0], Pt::from(tracks[1].pt));
    assert!(
        !pair.outputs.contains(&IngestOutput::Connected),
        "not ready before ICE and DTLS are up"
    );
    pair.connect();
    assert!(pair.engine.answered());
    // Ready once connected: once, after the tracks.
    let tracks_at = pair
        .outputs
        .iter()
        .position(|output| matches!(output, IngestOutput::Tracks(_)))
        .unwrap();
    let connected: Vec<usize> = pair
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| **output == IngestOutput::Connected)
        .map(|(at, _)| at)
        .collect();
    assert_eq!(connected.len(), 1, "{:?}", pair.outputs);
    assert!(connected[0] > tracks_at);

    // RFC 4585 §6.3.1: a PLI as soon as connected.
    pair.step(Duration::from_millis(50));
    assert_eq!(pair.engine.stats().plis, 1);
    assert_eq!(pair.camera().keyframe_requests, 1);

    pair.frame(true);
    pair.frame(false);
    let rtp = pair.rtp();
    assert_eq!(rtp.len(), 4, "{rtp:?}");
    assert!(rtp.iter().all(|(index, _, _)| *index == 1));
    assert_eq!(
        rtp.iter().map(|(_, seq, _)| *seq).collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(
        rtp.iter().map(|(_, _, marker)| *marker).collect::<Vec<_>>(),
        [false, false, true, true]
    );
    assert_eq!(pair.engine.stats().rtp_packets, 4);
    // An Opus packet on the audio m-line (RFC 7587 §4.2) under index 0.
    let (now, audio, opus) = (
        pair.now,
        pair.camera().audio.unwrap(),
        Pt::from(tracks[0].pt),
    );
    pair.camera()
        .write_on(audio, now, opus, true, &[0xfc, 0xff, 0xfe]);
    // The video's numbers go on without a gap.
    pair.camera().seq -= 1;
    pair.step(Duration::ZERO);
    assert_eq!(pair.rtp().last().unwrap().0, 0);
    assert_eq!(pair.engine.stats().rtp_packets, 5);
    pair.engine.keyframe_seen();
    // The engine's keyframe is seen once; a second call changes nothing.
    pair.engine.keyframe_seen();

    // RFC 3550 §6.4.1: the camera's Sender Reports, one each, from here
    // on. A str0m 0.25 camera's first report of a stream is due at once
    // (`StreamTx::sender_report_at`, read 2026-11-08), before its first
    // packet and so with an RTP time of 0; whether it reaches the engine
    // depends on when SRTP is up (observed 2026-11-08 in about one run of
    // seven), so the reports before these are left out.
    let (before, counted) = (pair.outputs.len(), pair.engine.stats().sender_reports);
    for _ in 0..20 {
        pair.frame(false);
        pair.step(Duration::from_millis(250));
    }
    let reports: Vec<(usize, u64, u32)> = pair.outputs[before..]
        .iter()
        .filter_map(|output| match output {
            IngestOutput::SenderReport {
                index, ntp, rtp_ts, ..
            } => Some((*index, *ntp, *rtp_ts)),
            _ => None,
        })
        .collect();
    assert_ne!(reports, []);
    assert_eq!(
        pair.engine.stats().sender_reports - counted,
        reports.len() as u64
    );
    assert!(
        reports.iter().any(|(index, _, _)| *index == 1),
        "the video's"
    );
    for (index, ntp, rtp_ts) in &reports {
        assert!(*index <= 1, "{index}");
        // An NTP time of this century (RFC 5905 §6: seconds since 1900).
        assert!(ntp >> 32 > 3_900_000_000, "{ntp:#x}");
        if *index == 1 {
            assert!(*rtp_ts >= 90_000, "{rtp_ts}");
        }
    }
    // No more PLIs: the keyframe came.
    assert_eq!(pair.engine.stats().plis, 1);

    // RFC 8831 §6: the data channel is open at the camera with the label
    // asked for; what it sends is counted and dropped.
    assert_eq!(pair.camera().channels.len(), 1);
    assert_eq!(pair.camera().channels[0].1, "dataSendChannel");
    assert!(pair.engine.stats().data_channel_open);
    pair.camera().send_data(b"hello");
    pair.deliver();
    pair.step(Duration::from_millis(10));
    assert_eq!(pair.engine.stats().data_messages, 1);
    assert_eq!(pair.engine.stats().data_bytes, 5);
    let id = pair.camera().channels[0].0;
    pair.camera().rtc.direct_api().close_data_channel(id);
    pair.camera().drain();
    // The close reaches the engine about 190 ms later between two str0m
    // 0.25 peers, within 100 ms between two of 0.24 (observed 2026-11-08).
    pair.run(Duration::from_millis(500));
    assert!(!pair.engine.stats().data_channel_open);
    // One the camera opens itself is not the offer's: it opens nothing
    // the engine counts (RFC 8832 §6, no renegotiation for a second).
    let mut api = pair.camera().rtc.sdp_api();
    let theirs = api.add_channel("camera".into());
    assert!(api.apply().is_none());
    pair.camera().drain();
    pair.run(Duration::from_millis(100));
    assert!(
        pair.camera().rtc.channel(theirs).is_some(),
        "open at the camera"
    );
    assert!(!pair.engine.stats().data_channel_open);
    assert!(pair.ended().is_none(), "a closed data channel ends nothing");
    // A repeated answer changes nothing.
    pair.engine.accept_answer(pair.now, &answer);
    pair.drain();
    assert_eq!(pair.tracks().len(), 2);
    assert!(pair.engine.is_connected());
}

#[test]
fn rfc4585_6_3_1_startup_plis_every_second_until_a_keyframe_at_most_five() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    let tracks = pair.tracks();
    assert_eq!(tracks.len(), 1);
    assert_eq!(tracks[0].index, 1, "the video is the second m-line");
    // The first as the connection is up.
    pair.connect();
    assert_eq!(pair.engine.stats().plis, 1);
    pair.step(PLI_INTERVAL - Duration::from_millis(1));
    assert_eq!(pair.engine.stats().plis, 1, "not before the interval");
    pair.step(Duration::from_millis(1));
    assert_eq!(pair.engine.stats().plis, 2, "on the interval");
    pair.run(Duration::from_secs(10));
    assert_eq!(pair.engine.stats().plis, u64::from(STARTUP_PLIS));
    assert_eq!(pair.camera().keyframe_requests, STARTUP_PLIS as usize);
}

#[test]
fn rfc4585_6_3_1_a_keyframe_stops_the_startup_plis_and_a_loss_asks_again_rate_limited() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    assert_eq!(pair.engine.stats().plis, 1);
    pair.frame(true);
    pair.engine.keyframe_seen();
    pair.run(Duration::from_secs(3));
    assert_eq!(pair.engine.stats().plis, 1, "the keyframe came");

    // Lost packets: the camera skips two sequence numbers.
    pair.camera().seq += 2;
    pair.frame(false);
    assert_eq!(pair.engine.stats().plis, 2);
    // Again within the interval: no second one.
    pair.camera().seq += 1;
    pair.frame(false);
    assert_eq!(pair.engine.stats().plis, 2);
    // A packet from before (reordered: one of the lost) is no loss, and
    // late: dropped.
    pair.camera().seq -= 4;
    let before = pair.rtp().len();
    pair.frame(false);
    assert_eq!(pair.rtp().len(), before, "dropped");
    assert_eq!(pair.engine.stats().late_packets, 1);
    pair.camera().seq += 3;
    pair.step(PLI_INTERVAL);
    // The next in order after the highest: no loss either.
    pair.frame(false);
    assert_eq!(pair.engine.stats().plis, 2);
    pair.camera().seq += 5;
    pair.frame(false);
    assert_eq!(pair.engine.stats().plis, 3);
    // In order: nothing.
    pair.frame(false);
    pair.frame(false);
    pair.step(PLI_INTERVAL * 2);
    assert_eq!(pair.engine.stats().plis, 3);
}

#[test]
fn rfc3550_6_4_1_losses_late_packets_and_rejected_datagrams_reach_the_connection_s_counters() {
    const A: u32 = 0x0a00;
    const B: u32 = 0x0b00;
    let captured = Captured::default();
    let writer = captured.clone();
    let _logs = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let mut pair = Pair::offer(&media_only());
    let ingest = Arc::new(IngestCounters::default());
    pair.engine.count_into(Arc::clone(&ingest));
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    // One packet `seq` at timestamp `ts`, through to the engine.
    let send = |pair: &mut Pair, seq: u16, ts: u32| {
        pair.camera().seq = seq;
        pair.camera().ts = ts.wrapping_sub(3_000);
        pair.frame(false);
    };
    pair.camera().new_ssrc(A);
    send(&mut pair, 100, 9_000);
    // Three numbers skipped: three packets lost, the gap's size.
    send(&mut pair, 104, 12_000);
    // One of them late: out of order.
    send(&mut pair, 102, 10_000);
    // An encoder restart; then a packet of the former source from before
    // it, stale: out of order too. B's first is no loss.
    pair.camera().new_ssrc(B);
    send(&mut pair, 7, 900_000);
    pair.camera().new_ssrc(A);
    send(&mut pair, 105, 15_000);
    // A datagram nothing reads (RFC 7983 §7), and media from a stranger.
    pair.engine
        .receive(pair.now, CAMERA, ENGINE, &[0xff, 1, 2, 3]);
    let stranger: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    let mut rtp = vec![0x80, 0x60, 0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 2];
    rtp.extend_from_slice(&[0; 20]);
    pair.engine.receive(pair.now, stranger, ENGINE, &rtp);
    assert_eq!(
        ingest.snapshot(),
        IngestStats {
            packets_lost: 3,
            packets_out_of_order: 2,
            datagrams_rejected: 2,
        }
    );
    let stats = pair.engine.stats();
    assert_eq!(
        (
            stats.lost_packets,
            stats.late_packets,
            stats.stale_packets,
            stats.bad_datagrams
        ),
        (3, 1, 1, 2)
    );
    // One line for the one gap, with its size; packets in order log none.
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let gaps: Vec<&str> = logs
        .lines()
        .filter(|line| line.contains("RTP sequence gap"))
        .collect();
    assert_eq!(gaps.len(), 1, "{logs}");
    assert!(gaps[0].contains("lost=3"), "{logs}");
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
}

/// The track's viewers' keyframe requests, coalesced by core, become
/// PLIs under the spacing the startup and loss PLIs keep: at most one per
/// interval for all three causes together.
#[test]
fn rfc4585_6_3_1_a_viewer_s_keyframe_request_is_a_pli_rate_limited_with_the_startup_and_loss_plis()
{
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
    pair.answer(camera_config(false), |answer| answer);
    // Before the connection: no stream to ask on yet.
    assert!(!pair.engine.request_keyframe(pair.now));
    pair.connect();
    pair.step(Duration::from_millis(1));
    assert_eq!(pair.engine.stats().plis, 1, "the first startup PLI");
    // While the startup PLIs run, a viewer's request adds none.
    assert!(!pair.engine.request_keyframe(pair.now));
    pair.step(Duration::from_millis(1));
    assert_eq!(pair.engine.stats().plis, 1);
    pair.frame(true);
    pair.engine.keyframe_seen();
    // Within the interval of the startup PLI: none.
    assert!(!pair.engine.request_keyframe(pair.now));
    pair.step(PLI_INTERVAL);
    // Past it: one, which reaches the camera.
    assert!(pair.engine.request_keyframe(pair.now));
    pair.step(Duration::from_millis(50));
    assert_eq!(pair.engine.stats().plis, 2);
    assert_eq!(pair.camera().keyframe_requests, 2);
    // A loss within the interval of the viewer's asks nothing more.
    pair.camera().seq += 3;
    pair.frame(false);
    assert_eq!(pair.engine.stats().plis, 2);
    // A viewer's within the interval of a loss's neither.
    pair.step(PLI_INTERVAL);
    pair.camera().seq += 3;
    pair.frame(false);
    assert_eq!(pair.engine.stats().plis, 3, "the loss's");
    assert!(!pair.engine.request_keyframe(pair.now));
    pair.step(PLI_INTERVAL - Duration::from_millis(1));
    assert!(!pair.engine.request_keyframe(pair.now), "to the tick");
    pair.step(Duration::from_millis(1));
    assert!(pair.engine.request_keyframe(pair.now));
    pair.step(Duration::from_millis(50));
    assert_eq!(pair.engine.stats().plis, 4);
    assert_eq!(pair.camera().keyframe_requests, 4);
}

#[test]
fn rfc4585_6_3_1_a_loss_before_the_first_keyframe_is_left_to_the_startup_plis() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    pair.frame(false);
    pair.camera().seq += 4;
    pair.frame(false);
    assert_eq!(pair.engine.stats().plis, 1);
}

#[test]
fn rfc9143_without_a_ssrc_the_first_pli_waits_for_the_first_packet() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| {
        answer
            .lines()
            .filter(|line| !line.starts_with("a=ssrc") && !line.starts_with("a=msid"))
            .map(|line| format!("{line}\r\n"))
            .collect()
    });
    pair.connect();
    pair.step(Duration::from_millis(1));
    assert_eq!(
        pair.engine.stats().plis,
        0,
        "the camera's SSRC is not known yet"
    );
    // The mid header extension (RFC 9143 §15) maps its first packet.
    pair.frame(false);
    assert_eq!(pair.engine.stats().rtp_packets, 1);
    assert_eq!(pair.engine.stats().plis, 1);
}

#[test]
fn rfc3264_7_every_accepted_h264_format_goes_to_the_video_track_and_others_are_dropped() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    let pts = pair.camera().h264_pts();
    assert!(pts.len() > 1, "{pts:?}");
    assert_eq!(Pt::from(pair.tracks()[0].pt), pts[0]);
    let now = pair.now;
    // Another H.264 profile or packetization mode the answer accepted:
    // the same codec, the same track, no switch.
    pair.camera().write(now, pts[1], true, &[0x41, 0x00]);
    pair.camera().write(now, pts[0], true, &[0x41, 0x01]);
    pair.camera().write(now, pts[1], true, &[0x41, 0x02]);
    pair.step(Duration::ZERO);
    assert_eq!(pair.engine.stats().rtp_packets, 3);
    // Index 1, the video's m-line: the audio's, rejected, is the first.
    assert_eq!(
        pair.rtp()
            .iter()
            .map(|(index, _, _)| *index)
            .collect::<Vec<_>>(),
        [1, 1, 1]
    );
    // A payload type the answer did not accept: not handed on.
    pair.camera().write(now, Pt::from(50), true, &[0x41, 0x03]);
    pair.step(Duration::ZERO);
    assert_eq!(pair.engine.stats().rtp_packets, 3);
}

#[test]
fn rfc3550_a_1_a_packet_of_another_accepted_codec_is_received_so_no_loss() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    let ingest = Arc::new(IngestCounters::default());
    pair.engine.count_into(Arc::clone(&ingest));
    pair.answer(camera_config(false).enable_h265(true), |answer| answer);
    pair.connect();
    let video = pair.camera().video.unwrap();
    let h264 = pair.camera().pts(video, EngineCodec::H264)[0];
    let h265 = pair.camera().pts(video, EngineCodec::H265)[0];
    // Past the first keyframe and the PLI spacing: a loss would ask for
    // one now.
    pair.frame(true);
    pair.engine.keyframe_seen();
    pair.step(PLI_INTERVAL);
    let plis = pair.engine.stats().plis;
    let before = pair.rtp().len();
    // n carried, n + 1 in H.265 (dropped from the H.264 track), n + 2
    // carried.
    let n = pair.camera().seq;
    let now = pair.now;
    pair.camera().write(now, h264, true, &[0x41, 0x00]);
    pair.camera().write(now, h265, true, &[0x02, 0x01, 0x00]);
    pair.camera().write(now, h264, true, &[0x41, 0x00]);
    pair.step(Duration::ZERO);
    let stats = pair.engine.stats();
    assert_eq!(stats.other_codec_packets, 1);
    assert_eq!(stats.lost_packets, 0);
    assert_eq!(ingest.snapshot().packets_lost, 0);
    assert_eq!(stats.plis, plis, "no loss, no keyframe request");
    assert_eq!(
        pair.rtp()[before..]
            .iter()
            .map(|(_, seq, _)| *seq)
            .collect::<Vec<_>>(),
        [n, n + 2]
    );
    // A real gap before a packet in the other codec is still a loss, and
    // asks for a keyframe.
    pair.camera().seq = n + 5;
    pair.camera().write(now, h265, true, &[0x02, 0x01, 0x00]);
    pair.step(Duration::ZERO);
    assert_eq!(pair.engine.stats().lost_packets, 2);
    assert_eq!(pair.engine.stats().plis, plis + 1);
    assert_eq!(pair.engine.stats().other_codec_packets, 2);
}

#[test]
fn rfc3550_8_2_another_source_s_packet_in_another_codec_moves_no_carried_timeline() {
    const A: u32 = 0x0a00;
    const B: u32 = 0x0b00;
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false).enable_h265(true), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    let video = pair.camera().video.unwrap();
    let h264 = pair.camera().pts(video, EngineCodec::H264)[0];
    let h265 = pair.camera().pts(video, EngineCodec::H265)[0];
    let send = |pair: &mut Pair, pt: Pt, seq: u16, ts: u32| {
        pair.camera().seq = seq;
        pair.camera().ts = ts;
        let now = pair.now;
        pair.camera().write(now, pt, true, &[0x41, 0x00]);
        pair.step(Duration::ZERO);
    };
    // A/100 in H.264, B/5 in H.265 on another timeline (dropped from the
    // H.264 track), A/101 in H.264 on A's.
    pair.camera().new_ssrc(A);
    send(&mut pair, h264, 100, 900_000);
    pair.camera().new_ssrc(B);
    send(&mut pair, h265, 5, 3_000);
    pair.camera().new_ssrc(A);
    send(&mut pair, h264, 101, 903_000);
    let stats = pair.engine.stats();
    assert_eq!(stats.other_codec_packets, 1);
    assert_eq!(
        (stats.stale_packets, stats.late_packets, stats.lost_packets),
        (0, 0, 0)
    );
    assert_eq!(
        pair.rtp()
            .iter()
            .map(|(_, seq, _)| *seq)
            .collect::<Vec<_>>(),
        [100, 101]
    );
    // A goes on, and its Sender Reports are the ones handed on.
    for n in 2..60_u16 {
        send(&mut pair, h264, 100 + n, 900_000 + 3_000 * u32::from(n));
        pair.step(Duration::from_millis(100));
        if pair.engine.stats().sender_reports > 0 {
            break;
        }
    }
    assert!(pair.engine.stats().sender_reports > 0);
    assert_eq!(pair.engine.stats().other_source_reports, 0);
    assert_eq!(pair.engine.stats().stale_packets, 0);
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
}

#[test]
fn rfc3264_7_a_packet_of_another_accepted_codec_is_dropped_not_switched() {
    let captured = Captured::default();
    let writer = captured.clone();
    let _logs = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(true).enable_h265(true), |answer| answer);
    pair.connect();
    let video = pair.camera().video.unwrap();
    let audio = pair.camera().audio.unwrap();
    let h264 = pair.camera().pts(video, EngineCodec::H264)[0];
    let h265 = pair.camera().pts(video, EngineCodec::H265);
    let opus = pair.camera().pts(audio, EngineCodec::Opus)[0];
    assert!(!h265.is_empty(), "the answer takes H.265 too");
    assert!(matches!(
        pair.tracks()[1].declared.codec,
        Codec::H264 { .. }
    ));
    let now = pair.now;
    // H.265 on the H.264 track, again and again: dropped, one warning.
    for _ in 0..10 {
        pair.camera().write(now, h265[0], true, &[0x02, 0x01, 0x00]);
    }
    pair.camera().write(now, h264, true, &[0x41, 0x00]);
    pair.step(Duration::ZERO);
    assert_eq!(pair.engine.stats().other_codec_packets, 10);
    assert_eq!(pair.engine.stats().rtp_packets, 1);
    assert_eq!(pair.rtp().len(), 1);
    // Opus on the video's m-line is no format of it: foreign.
    for _ in 0..2 {
        pair.camera()
            .write_on(video, now, opus, true, &[0xfc, 0xff, 0xfe]);
    }
    pair.step(Duration::ZERO);
    assert_eq!(pair.engine.stats().foreign_packets, 2);
    assert_eq!(pair.engine.stats().other_codec_packets, 10);
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        logs.matches("RTP in another codec than its track's dropped")
            .count(),
        1,
        "{logs}"
    );
}

#[test]
fn rfc3550_8_2_a_new_synchronization_source_s_losses_count_from_its_own_numbers() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    pair.frame(true);
    pair.engine.keyframe_seen();
    pair.camera().seq = 1_000;
    pair.frame(false);
    pair.run(Duration::from_millis(50));
    // Past the spacing of keyframe requests.
    pair.step(PLI_INTERVAL);
    let plis = pair.engine.stats().plis;
    // The camera's encoder restarted under a new SSRC, its numbers from
    // 5: no loss at 5, one at the gap after it.
    pair.camera().new_ssrc(0x5eed);
    pair.camera().seq = 5;
    pair.frame(false);
    pair.run(Duration::from_millis(50));
    assert_eq!(pair.engine.stats().plis, plis, "a new source is no loss");
    pair.camera().seq = 9;
    pair.frame(false);
    pair.run(Duration::from_millis(50));
    assert_eq!(pair.engine.stats().plis, plis + 1, "its own gap is");
    assert_eq!(
        pair.rtp()
            .iter()
            .map(|(_, seq, _)| *seq)
            .collect::<Vec<_>>()[3..],
        [1_000, 5, 9]
    );
}

/// RFC 3550 §5.1: a late packet sent before the camera's timestamps
/// jumped, delayed or retransmitted past the jump, is dropped: handed on,
/// it would start a new timeline back and the next packet another one
/// forward, and a few of them would end the attempt
/// (`RtpTracks`' `MAX_TIMELINES`). One merely late on the current
/// timeline is still handed on.
#[test]
fn rfc3550_5_1_a_late_packet_from_before_a_timestamp_jump_is_dropped() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    // One packet `seq` at timestamp `ts`, through to the engine.
    let send = |pair: &mut Pair, seq: u16, ts: u32| {
        pair.camera().seq = seq;
        pair.camera().ts = ts.wrapping_sub(3_000);
        pair.frame(false);
    };
    // 1 001 to 1 005 delayed on the way, or lost and repaired later.
    send(&mut pair, 1_000, 900_000);
    // The camera's timestamps jumped back 10 s; its numbers went on.
    send(&mut pair, 1_006, 3_000);
    for n in 1..=5 {
        // The packets from before arrive, among the new ones (str0m
        // drops a repeated number itself).
        send(&mut pair, 1_000 + n, 900_000 + 3_000 * u32::from(n));
        send(&mut pair, 1_006 + 2 * n, 3_000 + 6_000 * u32::from(n));
    }
    // A late one of the new timeline: dropped too, but as late, not
    // stale.
    send(&mut pair, 1_009, 9_000);
    assert_eq!(pair.engine.stats().stale_packets, 5);
    assert_eq!(pair.engine.stats().late_packets, 1);
    assert_eq!(
        pair.rtp()
            .iter()
            .map(|(_, seq, _)| *seq)
            .collect::<Vec<_>>(),
        [1_000, 1_006, 1_008, 1_010, 1_012, 1_014, 1_016]
    );
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
}

/// The source's receive path without its sockets: the engine's outputs
/// carried into `RtpTracks` as `Attempt::drain` carries them, onto a
/// track set.
struct Receiver {
    tracks: Arc<TrackSet>,
    rtp: lotse_codec::rtp_ingest::RtpTracks,
    ctx: SourceCtx,
    /// The engine outputs carried so far.
    taken: usize,
}

impl Receiver {
    fn new(now: Instant) -> Self {
        let tracks = TrackSet::new(TrackLimits::default(), now);
        let (clock, _reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let ctx = SourceCtx {
            peer: ResolvedPeer {
                host: String::new(),
                addrs: vec![],
            },
            tracks: tracks.publisher(),
            clock,
            time: Arc::new(SystemClock),
            backchannel: BackchannelSlot::default(),
            signaling: None,
            cancel: CancellationToken::new(),
        };
        Self {
            tracks,
            rtp: lotse_codec::rtp_ingest::RtpTracks::new("webrtc"),
            ctx,
            taken: 0,
        }
    }

    /// Carries the pair's outputs since the last call.
    fn carry(&mut self, pair: &Pair) {
        for output in &pair.outputs[self.taken..] {
            match output {
                IngestOutput::Tracks(tracks) => {
                    for negotiated in tracks {
                        let declared = &negotiated.declared;
                        let track = self.ctx.tracks.declare(
                            declared.kind,
                            declared.codec.clone(),
                            declared.clock_rate,
                        );
                        self.rtp
                            .carry(negotiated.index, track, negotiated.pt, declared);
                    }
                }
                IngestOutput::Rtp {
                    index,
                    packet,
                    arrival,
                } => self
                    .rtp
                    .receive(*index, packet.clone(), *arrival, &self.ctx)
                    .unwrap(),
                _ => {}
            }
        }
        self.taken = pair.outputs.len();
    }
}

/// The camera's datagrams of what `write` sends, held back from the
/// engine.
fn held(pair: &mut Pair, write: impl FnOnce(&mut Camera, Instant)) -> Vec<Datagram> {
    let now = pair.now;
    write(pair.camera(), now);
    pair.camera().timeout(now);
    std::mem::take(&mut pair.camera().out)
}

/// RFC 6184 §5.8: a FU-A of a non-IDR slice (type 1), its start, a middle
/// part or its end.
fn fu_a(start: bool, end: bool) -> Vec<u8> {
    let header = (u8::from(start) << 7) | (u8::from(end) << 6) | 1;
    vec![0x7c, header, 0x9a, 0x02, 0x04]
}

#[test]
fn rfc6184_5_8_a_reordered_packet_damages_no_later_access_unit() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    let mut receiver = Receiver::new(pair.now);
    receiver.carry(&pair);
    let video = receiver.tracks.tracks()[0].clone();
    assert_eq!(video.kind(), Kind::Video);
    // A keyframe, in order.
    let keyframe = held(&mut pair, |camera, now| camera.frame(now, true));
    pair.camera().out = keyframe;
    pair.deliver();
    receiver.carry(&pair);
    assert_eq!((video.stats().frames, video.stats().keyframes), (1, 1));
    // Single-packet units: the third arrives before the second.
    let units: Vec<_> = (0..4)
        .map(|_| held(&mut pair, |camera, now| camera.frame(now, false)))
        .collect();
    for at in [0, 2, 1, 3] {
        pair.camera().out = units[at].clone();
        pair.deliver();
    }
    receiver.carry(&pair);
    // The second is lost to its late arrival and the third follows a
    // gap; the fourth follows the third, complete.
    assert_eq!(pair.engine.stats().late_packets, 1);
    assert_eq!(video.stats().frames, 3, "the first and the fourth");
    // Fragmented units (FU-A), the second's middle part late; the third
    // follows it in order.
    let pt = pair.camera().h264_pts()[0];
    let mut fragmented = Vec::new();
    for _ in 0..3 {
        let packets = held(&mut pair, |camera, now| {
            camera.ts = camera.ts.wrapping_add(3_000);
            camera.write(now, pt, false, &fu_a(true, false));
            camera.write(now, pt, false, &fu_a(false, false));
            camera.write(now, pt, true, &fu_a(false, true));
        });
        assert_eq!(packets.len(), 3);
        fragmented.push(packets);
    }
    let order = [
        (0, 0),
        (0, 1),
        (0, 2),
        (1, 0),
        (1, 2),
        (1, 1),
        (2, 0),
        (2, 1),
        (2, 2),
    ];
    for (unit, part) in order {
        pair.camera().out = vec![fragmented[unit][part].clone()];
        pair.deliver();
    }
    receiver.carry(&pair);
    assert_eq!(pair.engine.stats().late_packets, 2);
    assert_eq!(video.stats().frames, 5, "the first and the third");
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
}

#[test]
fn rfc3550_8_2_a_former_source_s_packets_off_the_new_timeline_are_dropped() {
    const A: u32 = 0x0a00;
    const B: u32 = 0x0b00;
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    // One packet `seq` of `ssrc` at timestamp `ts`, through to the engine.
    let send = |pair: &mut Pair, ssrc: u32, seq: u16, ts: u32| {
        pair.camera().new_ssrc(ssrc);
        pair.camera().seq = seq;
        pair.camera().ts = ts.wrapping_sub(3_000);
        pair.frame(false);
    };
    send(&mut pair, A, 1_000, 900_000);
    // The encoder restarted: a new source on a new timeline.
    send(&mut pair, B, 5, 3_000);
    for n in 1..=5 {
        // A's packets sent before the restart arrive after it, never seen
        // before, ahead in A's own numbering, among B's.
        send(&mut pair, A, 1_000 + n, 900_000 + 3_000 * u32::from(n));
        send(&mut pair, B, 5 + n, 3_000 + 3_000 * u32::from(n));
    }
    assert_eq!(pair.engine.stats().stale_packets, 5);
    assert_eq!(
        pair.rtp()
            .iter()
            .map(|(_, seq, _)| *seq)
            .collect::<Vec<_>>(),
        [1_000, 5, 6, 7, 8, 9, 10]
    );
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
}

/// A camera that keeps changing its SSRC (RFC 3550 §8.2) among more
/// than the stream keeps the numbers of: every packet is a new source's
/// first, logged at most once per summary interval.
#[test]
fn rfc3550_8_2_new_synchronization_sources_are_logged_once_per_interval() {
    let captured = Captured::default();
    let writer = captured.clone();
    let _logs = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.step(Duration::from_millis(1));
    for round in 0..4_u32 {
        for ssrc in 0..5_u32 {
            pair.camera().new_ssrc(0x1000 + 2 * ssrc);
            pair.camera().seq = u16::try_from(round).unwrap();
            pair.frame(false);
        }
    }
    assert_eq!(pair.engine.stats().rtp_packets, 20);
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        logs.matches("webrtc: a new synchronization source").count(),
        1,
        "{logs}"
    );
}

#[test]
fn an_offer_over_what_the_relay_takes_is_not_made() {
    let _logs = logs();
    lotse_webrtc::install_crypto_provider();
    let now = SystemClock.now();
    let hosts = |count: u16| -> Vec<SocketAddr> {
        (1..=count)
            .map(|n| {
                format!("[2001:db8:ffff:ffff:ffff:ffff:ffff:{n:x}]:65535")
                    .parse()
                    .unwrap()
            })
            .collect()
    };
    // The most hosts a source gathers on, of the longest lines: well
    // within.
    let engine = IngestEngine::offer(&nest(), &hosts(16), now, now).unwrap();
    assert!(
        engine.offer_sdp().len() < MAX_OFFER_BYTES / 2,
        "{}",
        engine.offer_sdp().len()
    );
    let err = IngestEngine::offer(&nest(), &hosts(400), now, now).unwrap_err();
    assert!(
        err.ends_with(" bytes, over the 16384 the relay takes"),
        "{err}"
    );
}

#[test]
fn rfc3264_7_an_accepted_audio_codec_other_than_the_track_s_is_dropped() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    let config = camera_config(true).enable_pcmu(true, false);
    pair.answer(config, |answer| answer);
    pair.connect();
    let audio = pair.camera().audio.unwrap();
    let opus = pair.camera().pts(audio, EngineCodec::Opus);
    let pcmu = pair.camera().pts(audio, EngineCodec::PCMU);
    assert!(!pcmu.is_empty(), "the answer takes PCMU too");
    assert_eq!(Pt::from(pair.tracks()[0].pt), opus[0]);
    let now = pair.now;
    // PCMU is another codec than the Opus track's: dropped.
    for _ in 0..2 {
        pair.camera()
            .write_on(audio, now, pcmu[0], true, &[0xff; 160]);
    }
    pair.camera()
        .write_on(audio, now, opus[0], true, &[0xfc, 0xff, 0xfe]);
    pair.step(Duration::ZERO);
    assert_eq!(pair.engine.stats().other_codec_packets, 2);
    assert_eq!(pair.engine.stats().foreign_packets, 0);
    assert_eq!(pair.engine.stats().rtp_packets, 1);
}

#[test]
fn rfc3264_6_a_camera_without_audio_rejects_its_m_line_and_still_sends_video() {
    let _logs = logs();
    for options in [nest(), media_only()] {
        let mut pair = Pair::offer(&options);
        let answer = pair.answer(camera_config(false), |answer| answer);
        // RFC 3264 §6: the audio m-line rejected with port 0.
        let lines = media_lines(&answer);
        assert!(lines[0].starts_with("m=audio 0 "), "{answer}");
        assert!(lines[1].starts_with("m=video 9 "), "{answer}");
        let tracks = pair.tracks();
        assert_eq!(tracks.len(), 1, "{tracks:?} {:?} {answer}", pair.outputs);
        assert_eq!(tracks[0].index, 1, "the video keeps its m-line's index");
        assert_eq!(tracks[0].declared.kind, Kind::Video);
        pair.connect();
        pair.frame(true);
        let rtp = pair.rtp();
        assert!(!rtp.is_empty(), "{:?}", pair.outputs);
        assert!(rtp.iter().all(|(index, _, _)| *index == 1), "{rtp:?}");
    }
}

#[test]
fn rfc8829_5_3_answers_the_engine_cannot_take_end_the_attempt_as_invalid() {
    let _logs = logs();
    let cases: [(&str, fn(String) -> String, &str); 5] = [
        (
            "an m-line short",
            |answer| answer[..answer.find("m=application").unwrap()].to_owned(),
            // str0m 0.25 counts the answer's BUNDLE group against its
            // m-lines first.
            "a=group mid count doesn't match m-line count 3 != 2",
        ),
        (
            "garbage",
            |_| "v=0\r\nnonsense\r\n".to_owned(),
            "webrtc: invalid answer: ",
        ),
        (
            "a payload type with two codecs",
            |answer| {
                // The video's first payload type renamed in the audio
                // m-line's rtpmap.
                let pt = answer
                    .lines()
                    .find_map(|line| line.strip_prefix("m=video 9 UDP/TLS/RTP/SAVPF "))
                    .unwrap()
                    .split(' ')
                    .next()
                    .unwrap()
                    .to_owned();
                answer
                    .replace(
                        "a=rtpmap:111 opus/48000/2",
                        &format!("a=rtpmap:{pt} opus/48000/2"),
                    )
                    .replace(
                        "m=audio 9 UDP/TLS/RTP/SAVPF 111",
                        &format!("m=audio 9 UDP/TLS/RTP/SAVPF {pt}"),
                    )
            },
            "payload type",
        ),
        (
            "the video rejected",
            |answer| answer.replace("m=video 9 ", "m=video 0 "),
            "no video m-line the camera sends in H.264 or H.265",
        ),
        (
            "the video inactive",
            |answer| {
                let video = answer.find("m=video").unwrap();
                let (head, tail) = answer.split_at(video);
                format!("{head}{}", tail.replacen("a=sendonly", "a=inactive", 1))
            },
            "no video m-line the camera sends in H.264 or H.265",
        ),
    ];
    for (what, edit, reason) in cases {
        let mut pair = Pair::offer(&nest());
        pair.answer(camera_config(true), edit);
        let (error, code, message) = pair
            .ended()
            .unwrap_or_else(|| panic!("{what}: {:?}", pair.outputs));
        assert!(matches!(error, SourceError::Protocol(_)), "{what}: {error}");
        assert_eq!(code, close::INVALID_ANSWER, "{what}");
        assert!(message.contains(reason), "{what}: {message}");
        assert!(pair.tracks().is_empty(), "{what}");
        assert!(pair.engine.is_ended());
        assert!(!pair.engine.answered());
        // Inert from now on.
        pair.step(ANSWER_TIMEOUT);
        pair.engine.receive(pair.now, CAMERA, ENGINE, &[0; 20]);
        assert_eq!(pair.engine.stats().bad_datagrams, 0);
        pair.engine.close();
        assert!(matches!(pair.engine.poll(), IngestOutput::Timeout(_)));
    }
}

#[test]
fn rfc8866_5_14_a_format_less_rejected_m_line_beside_payload_type_0_reaches_no_engine_panic() {
    let _logs = logs();
    let mut pair = Pair::offer(&nest());
    // A camera without audio rejects the audio m-line listing no format
    // (as str0m 0.24 wrote it; 0.25 writes `0` there); its video's first
    // payload type renamed 0, `a=rtpmap:0 H264/90000`. The format the
    // rejected m-line gets must not give 0 a second codec: str0m 0.25
    // panics on that.
    let answer = pair.answer(camera_config(false), |answer| {
        let video = answer
            .lines()
            .find_map(|line| line.strip_prefix("m=video 9 UDP/TLS/RTP/SAVPF "))
            .unwrap()
            .to_owned();
        let pt = video.split(' ').next().unwrap().to_owned();
        let renamed = |line: &str| {
            line.replace(&format!(":{pt} "), ":0 ")
                .replace(&format!("SAVPF {pt}"), "SAVPF 0")
                .replace(&format!("apt={pt}"), "apt=0")
        };
        answer
            .lines()
            .map(|line| format!("{}\r\n", renamed(line)))
            .collect::<String>()
            .replace(
                "m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
                "m=audio 0 UDP/TLS/RTP/SAVPF\r\n",
            )
    });
    assert!(
        answer
            .lines()
            .any(|line| line.trim_end() == "m=audio 0 UDP/TLS/RTP/SAVPF"),
        "{answer}"
    );
    assert!(answer.contains("a=rtpmap:0 H264/90000"), "{answer}");
    // The video on payload type 0, the rejected audio on another.
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
    let tracks = pair.tracks();
    assert_eq!(tracks.len(), 1);
    assert_eq!(tracks[0].pt, 0);
    assert!(matches!(tracks[0].declared.codec, Codec::H264 { .. }));
    pair.connect();
}

#[test]
fn rfc8829_5_2_no_answer_within_20_s_ends_the_attempt_as_answer_timeout() {
    let _logs = logs();
    let mut pair = Pair::offer(&nest());
    let started = pair.now;
    pair.engine.handle_timeout(started);
    match pair.engine.poll() {
        IngestOutput::Timeout(at) => assert!(at <= started + ANSWER_TIMEOUT),
        other => panic!("{other:?}"),
    }
    pair.step(ANSWER_TIMEOUT - Duration::from_millis(1));
    assert!(pair.ended().is_none());
    pair.step(Duration::from_millis(1));
    let (error, code, message) = pair.ended().unwrap();
    assert_eq!(
        error,
        SourceError::Timeout("webrtc: no answer within 20 s".into())
    );
    assert_eq!(code, close::ANSWER_TIMEOUT);
    assert_eq!(message, "webrtc: no answer within 20 s");
    // An answer after the end is not taken.
    pair.answer(camera_config(true), |answer| answer);
    assert_eq!(pair.tracks(), []);
}

#[test]
fn rfc8445_8_not_connected_in_the_attempt_s_budget_ends_as_ice_failed_before_the_runner_s_timeout()
{
    let _logs = logs();
    // Both of the attempt's deadlines end it before the runner's ready
    // timeout would cancel it as not ready.
    assert!(
        ANSWER_TIMEOUT + CONNECT_TIMEOUT > ATTEMPT_BUDGET,
        "the cap is reached"
    );
    assert!(CONNECT_BY < ATTEMPT_BUDGET);
    assert!(ATTEMPT_BUDGET < lotse_core::runner::DEFAULT_READY_TIMEOUT);
    // (when the answer came, when the attempt ends): by 27 s into it,
    // 10 s after a later answer, at 28 s at the latest. The engine is the
    // DTLS server, so only the deadline ends the attempt; the client's
    // giving up is rfc8445_8_a_dtls_client_that_gives_up_before_the_
    // deadline_ends_as_not_connected_too.
    for (answer_ms, end_ms) in [(0, 27_000), (17_500, 27_500), (19_000, 28_000)] {
        let mut pair = Pair::offer(&media_only());
        pair.link = false;
        pair.run(Duration::from_millis(answer_ms));
        pair.answer(camera_config(false), camera_dtls_client);
        assert_eq!(pair.tracks().len(), 1, "{answer_ms}");
        pair.run(Duration::from_millis(end_ms - answer_ms - 10));
        assert!(pair.ended().is_none(), "{answer_ms}: {:?}", pair.ended());
        pair.run(Duration::from_millis(10));
        let (error, code, _) = pair.ended().unwrap();
        assert_eq!(
            error,
            SourceError::Timeout(format!(
                "webrtc: not connected {end_ms} ms into the attempt"
            )),
            "{answer_ms}"
        );
        assert_eq!(code, close::ICE_FAILED);
    }
}

#[test]
fn rfc8829_5_2_the_answer_deadline_counts_from_the_attempt_s_start() {
    let _logs = logs();
    lotse_webrtc::install_crypto_provider();
    let started = SystemClock.now();
    // The offer made 9 s into the attempt (a client came late): the
    // answer is due 11 s later.
    let now = started + Duration::from_secs(9);
    let mut engine = IngestEngine::offer(&media_only(), &[ENGINE], started, now).unwrap();
    engine.handle_timeout(started + ANSWER_TIMEOUT - Duration::from_millis(1));
    loop {
        match engine.poll() {
            IngestOutput::Timeout(_) => break,
            IngestOutput::Ended(end) => panic!("ended early: {end:?}"),
            _ => {}
        }
    }
    engine.handle_timeout(started + ANSWER_TIMEOUT);
    assert!(engine.is_ended());
}

#[test]
fn rfc8445_8_an_answer_or_a_handshake_completing_at_its_deadline_is_not_taken() {
    let _logs = logs();
    // The answer at its deadline, the timeout not handled yet.
    let mut pair = Pair::offer(&media_only());
    pair.now += ANSWER_TIMEOUT;
    pair.answer(camera_config(false), |answer| answer);
    assert_eq!(pair.tracks(), []);
    let (error, code, _) = pair.ended().unwrap();
    assert_eq!(
        error,
        SourceError::Timeout("webrtc: no answer within 20 s".into())
    );
    assert_eq!(code, close::ANSWER_TIMEOUT);

    // The camera's last handshake flight at the connect deadline. The
    // camera is the DTLS server (str0m answers `actpass` passive): once
    // its own handshake is done, what it sends then completes the
    // engine's.
    let mut pair = Pair::offer(&media_only());
    let started = pair.now;
    pair.answer(camera_config(false), |answer| answer);
    for _ in 0..1_000 {
        pair.now += Duration::from_millis(5);
        pair.engine.handle_timeout(pair.now);
        pair.drain();
        let now = pair.now;
        pair.camera().timeout(now);
        if pair.camera().connected {
            break;
        }
        pair.deliver();
    }
    assert!(pair.camera().connected);
    assert!(!pair.engine.is_connected());
    assert_ne!(pair.camera().out, []);
    pair.now = started + CONNECT_BY;
    pair.deliver();
    assert!(!pair.engine.is_connected());
    let (error, code, _) = pair.ended().unwrap();
    assert_eq!(
        error,
        SourceError::Timeout("webrtc: not connected 27000 ms into the attempt".into())
    );
    assert_eq!(code, close::ICE_FAILED);
}

#[test]
fn rfc8445_8_a_dtls_client_that_gives_up_before_the_deadline_ends_as_not_connected_too() {
    let _logs = logs();
    // The engine is the DTLS client (str0m answers `actpass` passive) on
    // a cut link: dimpl 0.9 gives its unanswered handshake up 23 to 39 s
    // after the answer, at random (its retransmissions' jitter), and the
    // deadline is at 27 s. Whichever comes first, the attempt ends as not
    // connected (`ice_failed`), never as the engine's internal error.
    for _ in 0..8 {
        let mut pair = Pair::offer(&media_only());
        pair.link = false;
        pair.answer(camera_config(false), |answer| answer);
        pair.run(Duration::from_secs(20));
        assert!(pair.ended().is_none(), "{:?}", pair.ended());
        pair.run(CONNECT_BY - Duration::from_secs(20));
        let (error, code, message) = pair.ended().unwrap();
        let SourceError::Timeout(reason) = &error else {
            panic!("{error:?}");
        };
        assert!(reason.starts_with("webrtc: not connected "), "{reason}");
        assert_eq!(*reason, message);
        assert_eq!(code, close::ICE_FAILED);
    }
}

#[test]
fn rfc8445_8_ice_up_without_dtls_and_then_lost_is_ice_failed_at_the_deadline() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.dtls = false;
    pair.answer(camera_config(false), camera_dtls_client);
    // STUN only (RFC 7983 §7: first byte 0 to 3): ICE pairs, DTLS never
    // gets through; then the link goes altogether. Not connected, the
    // attempt ends at the connection deadline; str0m 0.25's agent going
    // Disconnected meanwhile ends nothing. (The engine is the DTLS
    // server, so its handshake never gives up first.)
    pair.run(Duration::from_secs(1));
    assert!(!pair.engine.is_connected());
    pair.link = false;
    pair.run(CONNECT_BY - Duration::from_millis(1_100));
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
    pair.run(Duration::from_millis(200));
    let (error, code, _) = pair.ended().unwrap();
    assert!(matches!(error, SourceError::Timeout(_)), "{error}");
    assert_eq!(code, close::ICE_FAILED);
}

#[test]
fn rfc7675_5_1_a_camera_that_stops_answering_consent_ends_as_consent_lost() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.link = false;
    pair.run(Duration::from_secs(40));
    let (error, code, _) = pair.ended().unwrap();
    assert_eq!(
        error,
        SourceError::Ended("webrtc: the camera stopped answering consent checks".into())
    );
    assert_eq!(code, close::CONSENT_LOST);
}

#[test]
fn rfc6347_4_2_7_the_camera_s_close_notify_ends_as_peer_closed() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.camera().rtc.close().unwrap();
    pair.camera().drain();
    pair.deliver();
    pair.step(Duration::from_millis(10));
    let (error, code, _) = pair.ended().unwrap();
    assert_eq!(
        error,
        SourceError::Ended("webrtc: the camera closed the connection".into())
    );
    assert_eq!(code, close::PEER_CLOSED);
}

#[test]
fn rfc6347_4_2_7_a_close_from_outside_sends_close_notify_and_ends_nothing_else() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.engine.close();
    pair.drain();
    assert!(pair.engine.is_ended());
    assert!(!pair.engine.answered());
    assert!(pair.ended().is_none(), "the caller knows why");
    let now = pair.now;
    pair.camera().timeout(now);
    assert!(pair.camera().closed, "the camera got the close_notify");
    // Closing twice is closing once.
    pair.engine.close();
}

#[test]
fn rfc5763_5_a_wrong_fingerprint_fails_the_handshake_as_an_engine_error() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| {
        let line = answer
            .lines()
            .find(|line| line.starts_with("a=fingerprint:sha-256 "))
            .unwrap()
            .to_owned();
        let wrong = format!("a=fingerprint:sha-256 {}", ["00"; 32].join(":"));
        answer.replace(&line, &wrong)
    });
    pair.run(Duration::from_secs(2));
    let (error, code, message) = pair.ended().unwrap();
    assert!(matches!(error, SourceError::Protocol(_)), "{error}");
    assert_eq!(code, close::INTERNAL_ERROR);
    assert!(message.starts_with("webrtc engine: "), "{message}");
}

#[test]
fn rfc8445_8_a_candidate_at_a_deadline_ends_the_attempt_first_and_is_not_taken() {
    let _logs = logs();
    let candidate = |line: &str| SignalCandidate {
        candidate: line.to_owned(),
        sdp_mid: Some("0".into()),
        sdp_mline_index: Some(0),
    };
    let line = "candidate:2 1 udp 2130706431 192.0.2.20 6001 typ host";
    // The answer's deadline, the timeout not handled yet: a candidate just
    // before it is held, the end-of-candidates indication at it ends the
    // attempt.
    let mut pair = Pair::offer(&media_only());
    let started = pair.now;
    pair.engine.add_remote_candidate(
        started + ANSWER_TIMEOUT - Duration::from_millis(1),
        &candidate(line),
    );
    pair.drain();
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
    pair.engine.add_remote_candidate(
        started + ANSWER_TIMEOUT,
        &SignalCandidate::end_of_candidates(None, Some(0)),
    );
    pair.drain();
    let (error, code, _) = pair.ended().unwrap();
    assert_eq!(
        error,
        SourceError::Timeout("webrtc: no answer within 20 s".into())
    );
    assert_eq!(code, close::ANSWER_TIMEOUT);

    // The connection's deadline: a candidate just before it goes to the
    // agent, one at it ends the attempt and is not taken.
    let mut pair = Pair::offer(&media_only());
    let started = pair.now;
    pair.link = false;
    pair.answer(camera_config(false), |answer| answer);
    let taken = pair.engine.stats().remote_candidates;
    pair.engine.add_remote_candidate(
        started + CONNECT_BY - Duration::from_millis(1),
        &candidate(line),
    );
    pair.drain();
    assert_eq!(pair.engine.stats().remote_candidates, taken + 1);
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
    pair.engine
        .add_remote_candidate(started + CONNECT_BY, &candidate(line));
    pair.drain();
    assert_eq!(pair.engine.stats().remote_candidates, taken + 1);
    let (error, code, _) = pair.ended().unwrap();
    assert_eq!(
        error,
        SourceError::Timeout("webrtc: not connected 27000 ms into the attempt".into())
    );
    assert_eq!(code, close::ICE_FAILED);
}

#[test]
fn rfc8838_10_trickled_candidates_connect_and_bad_ones_are_refused() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    let candidate = |line: &str| SignalCandidate {
        candidate: line.to_owned(),
        sdp_mid: Some("0".into()),
        sdp_mline_index: Some(0),
    };
    let camera_line = "candidate:1 1 udp 2130706431 192.0.2.20 6000 typ host";
    // Before the answer: held until it comes, `a=` as some integrations
    // keep it.
    pair.engine
        .add_remote_candidate(pair.now, &candidate(&format!("a={camera_line}")));
    assert_eq!(pair.engine.stats().refused_candidates, 0);
    assert_eq!(pair.engine.stats().remote_candidates, 0);
    // The answer without its candidates: they come trickled.
    pair.answer(camera_config(false), |answer| {
        answer
            .lines()
            .filter(|line| !line.starts_with("a=candidate"))
            .map(|line| format!("{line}\r\n"))
            .collect()
    });
    assert_eq!(pair.engine.stats().remote_candidates, 1, "the held one");
    for refused in [
        // RFC 8445 §6.1.2.2 as the viewer sessions apply it: loopback
        // without a loopback host candidate of ours.
        "candidate:2 1 udp 2130706431 127.0.0.1 6000 typ host",
        // An mDNS name (draft-ietf-mmusic-mdns-ice-candidates §3.2.1).
        "candidate:3 1 udp 2130706431 0a1b2c3d.local 6000 typ host",
        "nonsense",
    ] {
        pair.engine
            .add_remote_candidate(pair.now, &candidate(refused));
    }
    assert_eq!(pair.engine.stats().refused_candidates, 3);
    pair.engine
        .add_remote_candidate(pair.now, &SignalCandidate::end_of_candidates(None, Some(0)));
    assert_eq!(pair.engine.stats().refused_candidates, 3);
    // One trickled after the answer goes to the agent.
    pair.engine.add_remote_candidate(
        pair.now,
        &candidate("candidate:4 1 udp 2130706431 192.0.2.20 6001 typ host"),
    );
    assert_eq!(pair.engine.stats().remote_candidates, 2);
    pair.connect();
    pair.engine.close();
    pair.engine
        .add_remote_candidate(pair.now, &candidate(camera_line));
    assert_eq!(pair.engine.stats().refused_candidates, 4, "after the end");
}

#[test]
fn rfc8838_10_at_most_64_candidates_are_held_until_the_answer() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    for port in 0..=64 {
        let line = format!(
            "candidate:{port} 1 udp 2130706431 192.0.2.30 {} typ host",
            7_000 + port
        );
        pair.engine.add_remote_candidate(
            pair.now,
            &SignalCandidate {
                candidate: line,
                sdp_mid: None,
                sdp_mline_index: Some(0),
            },
        );
    }
    assert_eq!(pair.engine.stats().refused_candidates, 1);
    pair.answer(camera_config(false), |answer| answer);
    // The answer's own and the 64 held.
    assert_eq!(pair.engine.stats().remote_candidates, 65);
    pair.connect();
}

#[test]
fn rfc7983_datagrams_that_are_not_the_engine_s_are_counted_and_dropped() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    // Nothing the demultiplexing reads (RFC 7983 §7).
    pair.engine
        .receive(pair.now, CAMERA, ENGINE, &[0xff, 1, 2, 3]);
    assert_eq!(pair.engine.stats().bad_datagrams, 1);
    // A STUN binding request for someone else's ufrag.
    let mut stun = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42];
    stun.extend_from_slice(&[7; 12]);
    let stranger: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    pair.engine.receive(pair.now, stranger, ENGINE, &stun);
    assert_eq!(pair.engine.stats().bad_datagrams, 2);
    pair.connect();
}

#[test]
fn rfc8445_5_1_3_a_host_address_given_twice_is_one_candidate() {
    let _logs = logs();
    let engine = IngestEngine::offer(
        &media_only(),
        &[ENGINE, ENGINE],
        SystemClock.now(),
        SystemClock.now(),
    )
    .unwrap();
    assert_eq!(engine.local_candidates().len(), 2, "one host and the end");
    assert_eq!(engine.offer_sdp().matches("a=candidate:").count(), 1);
}

#[test]
fn rfc7983_7_media_from_a_stranger_is_not_taken() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    let stranger: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    let mut rtp = vec![0x80, 0x60, 0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 2];
    rtp.extend_from_slice(&[0; 20]);
    pair.engine.receive(pair.now, stranger, ENGINE, &rtp);
    assert_eq!(pair.engine.stats().bad_datagrams, 1);
    assert!(pair.engine.is_connected());
}

#[test]
fn rfc6347_4_2_7_a_close_drops_what_was_queued_and_not_polled() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    let (_camera, answer) = Camera::answer(
        pair.engine.offer_sdp(),
        CAMERA,
        camera_config(false),
        pair.now,
    );
    // The answer's tracks queued, never polled, then the close.
    pair.engine.accept_answer(pair.now, &answer);
    assert!(pair.engine.answered());
    pair.engine.close();
    loop {
        match pair.engine.poll() {
            IngestOutput::Timeout(_) => break,
            IngestOutput::Transmit { .. } => {}
            other => panic!("after the close: {other:?}"),
        }
    }
}

#[test]
fn rfc6347_4_2_7_a_close_queues_its_close_notify() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    pair.engine.close();
    let mut transmits = 0;
    while let IngestOutput::Transmit { destination, .. } = pair.engine.poll() {
        assert_eq!(destination, CAMERA);
        transmits += 1;
    }
    assert!(transmits >= 1, "close_notify, BYE");
}

/// The camera's candidate lines of `answer`, and the answer without
/// them.
fn without_candidates(answer: &str) -> (Vec<String>, String) {
    let (candidates, rest): (Vec<&str>, Vec<&str>) = answer
        .lines()
        .partition(|line| line.starts_with("a=candidate"));
    (
        candidates.iter().map(|line| (*line).to_owned()).collect(),
        rest.iter().map(|line| format!("{line}\r\n")).collect(),
    )
}

#[test]
fn rfc8445_2_2_an_ice_lite_camera_with_its_candidates_in_the_answer_connects() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    // An ICE-lite camera (Nest-like) sends no checks of its own: the
    // engine pairs with the answer's candidate and checks it.
    pair.answer(camera_config(false).set_ice_lite(true), |answer| {
        assert!(answer.contains("a=ice-lite"), "{answer}");
        assert!(answer.contains("a=candidate"), "{answer}");
        answer
    });
    assert_eq!(pair.engine.stats().remote_candidates, 1);
    pair.connect();
    pair.frame(true);
    assert_eq!(pair.engine.stats().rtp_packets, 3);
}

#[test]
fn rfc8838_10_an_ice_lite_camera_whose_candidates_come_only_trickled_connects() {
    let _logs = logs();
    for early in [false, true] {
        let mut pair = Pair::offer(&media_only());
        let (camera, answer) = Camera::answer(
            pair.engine.offer_sdp(),
            CAMERA,
            camera_config(false).set_ice_lite(true),
            pair.now,
        );
        pair.camera = Some(camera);
        let (candidates, answer) = without_candidates(&answer);
        assert_eq!(candidates.len(), 1);
        let trickle = |pair: &mut Pair| {
            for line in &candidates {
                pair.engine.add_remote_candidate(
                    pair.now,
                    &SignalCandidate {
                        candidate: line.clone(),
                        sdp_mid: None,
                        sdp_mline_index: Some(0),
                    },
                );
            }
        };
        if early {
            trickle(&mut pair);
        }
        pair.engine.accept_answer(pair.now, &answer);
        pair.drain();
        if !early {
            pair.run(Duration::from_millis(500));
            assert!(!pair.engine.is_connected(), "no candidate to check yet");
            trickle(&mut pair);
        }
        assert_eq!(pair.engine.stats().remote_candidates, 1, "early: {early}");
        pair.connect();
        pair.frame(true);
        assert_eq!(pair.engine.stats().rtp_packets, 3, "early: {early}");
    }
}

#[test]
fn rfc8445_6_1_2_2_an_answer_whose_candidates_pair_with_none_connects_by_the_camera_s_checks() {
    let _logs = logs();
    let mut pair = Pair::offer(&media_only());
    // An IPv6 candidate alone against the engine's IPv4 host: no pair, so
    // str0m's agent reports Disconnected before the connection; that ends
    // nothing, and the camera's own checks make a peer-reflexive pair
    // (RFC 8445 §7.3.1.3).
    pair.link = false;
    pair.answer(camera_config(false), |answer| {
        answer.replace("192.0.2.20 6000 typ host", "2001:db8::20 6000 typ host")
    });
    assert_eq!(pair.engine.stats().remote_candidates, 1);
    pair.run(Duration::from_millis(100));
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
    pair.link = true;
    pair.connect();
    assert!(pair.ended().is_none());
}

#[test]
fn rfc8445_8_a_second_host_address_that_reaches_nothing_ends_nothing_once_connected() {
    let _logs = logs();
    let dead: SocketAddr = "192.0.2.11:5000".parse().unwrap();
    let mut pair = Pair::offer_on(&media_only(), &[ENGINE, dead]);
    assert_eq!(
        pair.engine.local_candidates().len(),
        3,
        "two hosts and the end"
    );
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    // The dead address's pair fails meanwhile; str0m's agent goes on from
    // Connected (to Completed), which ends nothing.
    for _ in 0..30 {
        pair.frame(false);
        pair.run(Duration::from_secs(1));
    }
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
    assert!(pair.engine.is_connected());
}

/// A log writer the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The source over loopback UDP.
mod source {
    use super::*;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// A source attempt in a task, with what the test watches.
    struct Running {
        run: JoinHandle<SourceError>,
        set: Arc<TrackSet>,
        reports: mpsc::Receiver<ClockReport>,
        cancel: CancellationToken,
    }

    fn start(
        options: serde_json::Value,
        signaling: Option<Arc<dyn SignalingOpener>>,
        clock: Arc<dyn Clock>,
    ) -> Running {
        lotse_webrtc::install_crypto_provider();
        let source = WebRtcSourceFactory.validate(&options).unwrap();
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (input, reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let cancel = CancellationToken::new();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: String::new(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock: input,
            time: clock,
            backchannel: BackchannelSlot::default(),
            signaling,
            cancel: cancel.clone(),
        });
        Running {
            run: spawn_named("test.webrtc_source", run),
            set,
            reports,
            cancel,
        }
    }

    async fn within<F: Future>(future: F) -> F::Output {
        tokio::select! {
            output = future => output,
            () = SystemClock.sleep(Duration::from_secs(20)) => panic!("timed out"),
        }
    }

    /// Reads the offer and the trickled candidates up to the end of
    /// candidates.
    async fn read_offer(relay: &mut SignalingRelay) -> (String, Vec<SignalCandidate>) {
        let Some(LocalSignal::Offer(offer)) = within(relay.outgoing.recv()).await else {
            panic!("no offer first");
        };
        let mut candidates = Vec::new();
        loop {
            match within(relay.outgoing.recv()).await {
                Some(LocalSignal::Candidate(candidate)) => {
                    let end = candidate.is_end_of_candidates();
                    candidates.push(candidate);
                    if end {
                        return (offer, candidates);
                    }
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// A camera on a loopback UDP socket.
    struct Live {
        camera: Camera,
        socket: UdpSocket,
        buf: Vec<u8>,
    }

    impl Live {
        async fn answer(offer: &str, audio: bool) -> (Self, String) {
            Self::answer_with(offer, camera_config(audio)).await
        }

        async fn answer_with(offer: &str, config: RtcConfig) -> (Self, String) {
            let socket = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
            let addr = socket.local_addr().unwrap();
            let (camera, answer) = Camera::answer(offer, addr, config, SystemClock.now());
            (
                Self {
                    camera,
                    socket,
                    buf: vec![0; 4_096],
                },
                answer,
            )
        }

        async fn flush(&mut self) {
            for (_, destination, payload) in std::mem::take(&mut self.camera.out) {
                self.socket.send_to(&payload, destination).await.unwrap();
            }
        }

        /// Runs the camera for `span`: datagrams in and out, its timers.
        async fn pump(&mut self, span: Duration) {
            let until = SystemClock.now() + span;
            loop {
                self.flush().await;
                let now = SystemClock.now();
                if now >= until {
                    return;
                }
                tokio::select! {
                    received = self.socket.recv_from(&mut self.buf) => {
                        let (len, from) = received.unwrap();
                        let bytes = self.buf[..len].to_vec();
                        self.camera.receive(SystemClock.now(), from, &bytes);
                    }
                    () = SystemClock.sleep(Duration::from_millis(5)) => {
                        self.camera.timeout(SystemClock.now());
                    }
                }
            }
        }

        async fn connect(&mut self) {
            for _ in 0..1_000 {
                if self.camera.connected {
                    return;
                }
                self.pump(Duration::from_millis(10)).await;
            }
            panic!("the camera never connected");
        }

        /// Sends a frame every 40 ms until `done`.
        async fn stream_until(&mut self, mut done: impl FnMut() -> bool) {
            let mut sent = 0;
            while !done() {
                assert!(sent < 500, "gave up after {sent} frames");
                self.camera.frame(SystemClock.now(), sent % 25 == 0);
                sent += 1;
                self.pump(Duration::from_millis(40)).await;
            }
        }
    }

    async fn closed(relay: SignalingRelay) -> SignalClose {
        within(relay.closed.wait()).await
    }

    #[tokio::test]
    async fn without_a_relay_or_with_the_open_refused_the_source_is_unreachable() {
        let _logs = logs();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let running = start(serde_json::json!({}), None, Arc::clone(&clock));
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Unreachable("webrtc: no signaling relay to the client".into())
        );
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        signaling.refuse_next("no_signaling_client", "nobody relays it");
        let running = start(serde_json::json!({}), Some(signaling.clone()), clock);
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Unreachable(
                "webrtc: signaling refused: no_signaling_client: nobody relays it".into()
            )
        );
        assert_eq!(signaling.opens(), 1);
    }

    #[tokio::test]
    async fn a_cancel_before_the_channel_opens_ends_at_once() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        running.cancel.cancel();
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Ended("webrtc: cancelled".into())
        );
    }

    #[tokio::test]
    async fn rfc8445_5_1_1_without_a_bindable_host_address_the_attempt_is_unreachable() {
        let _logs = logs();
        // TEST-NET-1: no interface has it.
        let signaling = FakeSignaling::new(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let relay = within(signaling.next_signal()).await.unwrap();
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Unreachable("webrtc: no usable host candidate among []".into())
        );
        assert_eq!(
            closed(relay).await,
            SignalClose {
                code: close::ICE_FAILED,
                message: "no usable host candidate among []".into(),
            }
        );
    }

    #[tokio::test]
    async fn rfc8829_a_camera_over_loopback_goes_live_reports_and_ends_on_its_failure() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let mut running = start(
            serde_json::json!({ "data_channel": "dataSendChannel" }),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, candidates) = read_offer(&mut relay).await;
        assert_eq!(media_lines(&offer).len(), 3);
        assert_eq!(candidates.len(), 2, "one host and the end of candidates");
        assert!(
            candidates[0].candidate.contains("127.0.0.1"),
            "{candidates:?}"
        );
        let (mut camera, answer) = Live::answer(&offer, true).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        // A trickled candidate and the camera's end of candidates on top.
        relay
            .incoming
            .send(RemoteSignal::Candidate(SignalCandidate::end_of_candidates(
                None,
                Some(0),
            )))
            .await
            .unwrap();
        // Declared at the answer, ready once connected.
        within(async {
            while running.set.tracks().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        let tracks = running.set.tracks();
        assert_eq!(tracks[0].kind(), Kind::Audio);
        assert_eq!(tracks[1].kind(), Kind::Video);
        assert!(!*running.set.ready().borrow());
        camera.connect().await;
        let ready = running.set.ready();
        within(async {
            while !*ready.borrow() {
                camera.pump(Duration::from_millis(10)).await;
            }
        })
        .await;
        let video = Arc::clone(&tracks[1]);
        within(camera.stream_until(|| video.stats().keyframes >= 2)).await;
        assert!(video.stats().packets > 0);
        assert!(matches!(&*video.codec(), Codec::H264 { sps: Some(_), .. }));
        // The Sender Reports reach the clock mapper as sync hints.
        let mut report = None;
        within(camera.stream_until(|| {
            report = report.or_else(|| running.reports.try_recv().ok());
            report.is_some()
        }))
        .await;
        let report = report.unwrap();
        assert_eq!(report.track, video.id());
        assert!(matches!(report.hint, SyncHint::RtcpSenderReport { .. }));
        // The keyframe asked for once, as the camera's first came at once.
        assert!(camera.camera.keyframe_requests >= 1);
        assert_eq!(camera.camera.channels.len(), 1);

        relay
            .incoming
            .send(RemoteSignal::Failed {
                code: "webrtc_session_ended".into(),
                message: "the camera ended the session".into(),
            })
            .await
            .unwrap();
        let what = "camera: webrtc_session_ended: the camera ended the session";
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Ended(what.into())
        );
        assert_eq!(
            closed(relay).await,
            SignalClose {
                code: close::CAMERA_ERROR,
                message: what.into(),
            }
        );
        // Its close_notify reached the camera.
        within(async {
            while !camera.camera.closed {
                camera.pump(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn rfc4585_6_3_1_the_source_stops_asking_for_a_keyframe_once_one_arrived() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, _) = read_offer(&mut relay).await;
        let (mut camera, answer) = Live::answer(&offer, false).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        camera.connect().await;
        let video = Arc::clone(&running.set.tracks()[0]);
        // Delta frames alone for 2.5 s: a request a second meanwhile.
        for _ in 0..25 {
            camera.camera.frame(SystemClock.now(), false);
            camera.pump(Duration::from_millis(100)).await;
        }
        assert!(video.stats().packets > 0);
        assert_eq!(video.stats().keyframes, 0);
        let asked = camera.camera.keyframe_requests;
        assert!(asked >= 2, "{asked}");
        // The keyframe: the requests stop.
        while video.stats().keyframes == 0 {
            camera.camera.frame(SystemClock.now(), true);
            camera.pump(Duration::from_millis(100)).await;
        }
        let asked = camera.camera.keyframe_requests;
        for _ in 0..25 {
            camera.camera.frame(SystemClock.now(), false);
            camera.pump(Duration::from_millis(100)).await;
        }
        assert_eq!(camera.camera.keyframe_requests, asked);
        running.cancel.cancel();
        within(running.run).await.unwrap();
    }

    /// A request on the video track, a viewer's that the GOP cache could
    /// not serve, reaches the camera as one PLI through the running
    /// source; the requests of more viewers within the interval fold into
    /// it, and the keyframe that comes answers them all.
    #[tokio::test]
    async fn rfc4585_6_3_1_viewers_keyframe_requests_reach_the_camera_as_one_pli() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({ "audio": false }),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, _) = read_offer(&mut relay).await;
        let (mut camera, answer) = Live::answer(&offer, false).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        camera.connect().await;
        let video = Arc::clone(&running.set.tracks()[0]);
        while video.stats().keyframes == 0 {
            camera.camera.frame(SystemClock.now(), true);
            camera.pump(Duration::from_millis(100)).await;
        }
        // Past the startup PLI's interval.
        for _ in 0..12 {
            camera.camera.frame(SystemClock.now(), false);
            camera.pump(Duration::from_millis(100)).await;
        }
        let asked = camera.camera.keyframe_requests;

        assert_eq!(
            video.request_keyframe(SystemClock.now()),
            KeyframeOutcome::Forwarded
        );
        for _ in 0..5 {
            assert_eq!(
                video.request_keyframe(SystemClock.now()),
                KeyframeOutcome::Coalesced
            );
        }
        for _ in 0..3 {
            camera.camera.frame(SystemClock.now(), false);
            camera.pump(Duration::from_millis(100)).await;
        }
        assert_eq!(camera.camera.keyframe_requests, asked + 1, "one PLI");
        // The camera answers: nothing more goes out, past the interval too.
        camera.camera.frame(SystemClock.now(), true);
        camera.pump(Duration::from_millis(100)).await;
        for _ in 0..12 {
            camera.camera.frame(SystemClock.now(), false);
            camera.pump(Duration::from_millis(100)).await;
        }
        assert_eq!(camera.camera.keyframe_requests, asked + 1);
        let stats = video.stats();
        assert_eq!(
            (stats.keyframe_requests, stats.keyframe_requests_forwarded),
            (6, 1)
        );
        running.cancel.cancel();
        within(running.run).await.unwrap();
    }

    /// The source counts into its connection's ingest counters, which the
    /// worker and the API show: a sequence gap's size as lost, a late
    /// packet as out of order, a datagram nothing reads as rejected, as
    /// the RTSP source counts them.
    #[tokio::test]
    async fn rfc3550_6_4_1_the_source_reports_its_losses_in_the_connection_s_ingest_counters() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, candidates) = read_offer(&mut relay).await;
        let fields: Vec<&str> = candidates[0].candidate.split_whitespace().collect();
        let host = SocketAddr::new(fields[4].parse().unwrap(), fields[5].parse().unwrap());
        let (mut camera, answer) = Live::answer(&offer, false).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        camera.connect().await;
        let video = Arc::clone(&running.set.tracks()[0]);
        let frame = |camera: &mut Live| camera.camera.frame(SystemClock.now(), false);
        frame(&mut camera);
        camera.pump(Duration::from_millis(50)).await;
        within(async {
            while video.stats().packets == 0 {
                camera.pump(Duration::from_millis(10)).await;
            }
        })
        .await;
        // Three numbers skipped; then one of them, late; then on in order.
        let next = camera.camera.seq;
        camera.camera.seq = next + 3;
        frame(&mut camera);
        camera.pump(Duration::from_millis(50)).await;
        camera.camera.seq = next + 1;
        frame(&mut camera);
        camera.pump(Duration::from_millis(50)).await;
        camera.camera.seq = next + 4;
        frame(&mut camera);
        // A datagram nothing reads (RFC 7983 §7).
        camera.socket.send_to(&[0xff, 1, 2, 3], host).await.unwrap();
        let expected = IngestStats {
            packets_lost: 3,
            packets_out_of_order: 1,
            datagrams_rejected: 1,
        };
        within(async {
            while running.set.ingest() != expected {
                camera.pump(Duration::from_millis(10)).await;
            }
        })
        .await;
        running.cancel.cancel();
        within(running.run).await.unwrap();
        assert_eq!(running.set.ingest(), expected);
    }

    /// A reconnect whose answer takes another audio codec than the last
    /// one's: the audio track is declared again under its id at the new
    /// clock rate (core's `TrackSet::declare`, a new epoch), so its RTP
    /// timestamps, its Sender Reports and the timeline guard all read the
    /// codec this attempt negotiated.
    #[tokio::test]
    async fn rfc3264_a_reconnect_that_takes_pcmu_after_opus_redeclares_the_audio_at_8_khz() {
        let _logs = logs();
        lotse_webrtc::install_crypto_provider();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let source = WebRtcSourceFactory
            .validate(&serde_json::json!({}))
            .unwrap();
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let pcmu = Rtc::builder()
            .set_rtp_mode(true)
            .clear_codecs()
            .enable_h264(true)
            .enable_pcmu(true, false);
        let cases: [(RtcConfig, fn(&Codec) -> bool, u32); 2] = [
            (
                camera_config(true),
                |codec| matches!(codec, Codec::Opus { .. }),
                48_000,
            ),
            (pcmu, |codec| matches!(codec, Codec::Pcmu), 8_000),
        ];
        let mut epochs = Vec::new();
        for (config, is_codec, clock_rate) in cases {
            let signaling = FakeSignaling::new(vec![LOOPBACK]);
            let (input, _reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
            let cancel = CancellationToken::new();
            let run = spawn_named(
                "test.webrtc_source",
                source.run(SourceCtx {
                    peer: ResolvedPeer {
                        host: String::new(),
                        addrs: vec![],
                    },
                    tracks: set.publisher(),
                    clock: input,
                    time: Arc::clone(&clock),
                    backchannel: BackchannelSlot::default(),
                    signaling: Some(signaling.clone()),
                    cancel: cancel.clone(),
                }),
            );
            let mut relay = within(signaling.next_signal()).await.unwrap();
            let (offer, _) = read_offer(&mut relay).await;
            let (_camera, answer) = Live::answer_with(&offer, config).await;
            relay
                .incoming
                .send(RemoteSignal::Answer(answer))
                .await
                .unwrap();
            // Declared at the answer.
            within(async {
                while set
                    .tracks()
                    .first()
                    .is_none_or(|audio| !is_codec(&audio.codec()))
                {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            let tracks = set.tracks();
            assert_eq!(tracks.len(), 2, "the same two tracks");
            assert_eq!(tracks[0].kind(), Kind::Audio);
            assert_eq!(tracks[0].clock_rate(), clock_rate);
            epochs.push(tracks[0].epoch());
            cancel.cancel();
            within(run).await.unwrap();
        }
        assert!(
            epochs[1] > epochs[0],
            "a new epoch at the new rate: {epochs:?}"
        );
    }

    #[tokio::test]
    async fn a_camera_failure_before_its_answer_is_unreachable() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        read_offer(&mut relay).await;
        relay
            .incoming
            .send(RemoteSignal::Failed {
                code: "offline".into(),
                message: "the camera is offline".into(),
            })
            .await
            .unwrap();
        let what = "camera: offline: the camera is offline";
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Unreachable(what.into())
        );
        assert_eq!(closed(relay).await.code, close::CAMERA_ERROR);
    }

    #[tokio::test]
    async fn a_signal_the_relay_refused_is_lotse_s_fault_not_the_camera_s() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        read_offer(&mut relay).await;
        relay
            .incoming
            .send(RemoteSignal::Failed {
                code: lotse_core::signaling::REJECTED.into(),
                message: "the offer is too long".into(),
            })
            .await
            .unwrap();
        let what = "webrtc: the relay refused a signal: the offer is too long";
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Protocol(what.into())
        );
        assert_eq!(
            closed(relay).await,
            SignalClose {
                code: close::INTERNAL_ERROR,
                message: what.into(),
            }
        );
    }

    #[tokio::test]
    async fn the_client_gone_ends_the_attempt_as_signaling_lost() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        read_offer(&mut relay).await;
        let SignalingRelay {
            incoming, closed, ..
        } = relay;
        drop(incoming);
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Ended("signaling client gone".into())
        );
        let close = within(closed.wait()).await;
        assert_eq!(close.code, close::SIGNALING_LOST);
        assert_eq!(close.message, "the signaling client is gone");
    }

    #[tokio::test]
    async fn a_cancel_while_live_closes_the_connection_and_the_channel() {
        let captured = Captured::default();
        let writer = captured.clone();
        let _logs = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .finish(),
        );
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, _) = read_offer(&mut relay).await;
        // Audio and video, the camera's audio rejected (RFC 3264 §6).
        assert_eq!(media_lines(&offer).len(), 2);
        let (mut camera, answer) = Live::answer(&offer, false).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        camera.connect().await;
        // Live on the source's side too: media arrived.
        let video = Arc::clone(&running.set.tracks()[0]);
        within(camera.stream_until(|| video.stats().packets > 0)).await;
        let started = SystemClock.now();
        running.cancel.cancel();
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Ended("webrtc: cancelled".into())
        );
        assert!(SystemClock.now() - started < Duration::from_millis(100));
        assert_eq!(
            closed(relay).await,
            SignalClose {
                code: close::SOURCE_STOPPED,
                message: "cancelled".into(),
            }
        );
        // Every datagram of the attempt left, its close_notify among them.
        let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let over = logs
            .lines()
            .find(|line| line.contains("webrtc: attempt over"))
            .unwrap_or_else(|| panic!("{logs}"));
        assert!(over.contains("dropped=0"), "{over}");
        within(async {
            while !camera.camera.closed {
                camera.pump(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn rfc8829_5_2_no_answer_on_the_injected_clock_ends_as_answer_timeout() {
        let _logs = logs();
        let clock = Arc::new(FakeClock::from_system());
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            clock.clone(),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        read_offer(&mut relay).await;
        let mut run = running.run;
        for _ in 0..21 {
            // Let the source reach its wait before the clock moves.
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            clock.advance(Duration::from_secs(1));
            if run.is_finished() {
                break;
            }
        }
        assert_eq!(
            within(&mut run).await.unwrap(),
            SourceError::Timeout("webrtc: no answer within 20 s".into())
        );
        assert_eq!(closed(relay).await.code, close::ANSWER_TIMEOUT);
    }

    #[tokio::test]
    async fn a_cancel_goes_before_a_deadline_due_at_the_same_time() {
        let _logs = logs();
        let clock = Arc::new(FakeClock::from_system());
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            clock.clone(),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        read_offer(&mut relay).await;
        settle().await;
        // Both before the source runs again.
        clock.advance(ANSWER_TIMEOUT);
        running.cancel.cancel();
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Ended("webrtc: cancelled".into())
        );
        assert_eq!(closed(relay).await.code, close::SOURCE_STOPPED);
    }

    #[tokio::test]
    async fn rfc8829_5_2_an_answer_or_a_failure_at_the_answer_deadline_ends_the_attempt_by_it() {
        let _logs = logs();
        for answering in [true, false] {
            let clock = Arc::new(FakeClock::from_system());
            let signaling = FakeSignaling::new(vec![LOOPBACK]);
            let running = start(
                serde_json::json!({}),
                Some(signaling.clone()),
                clock.clone(),
            );
            let mut relay = within(signaling.next_signal()).await.unwrap();
            let (offer, _) = read_offer(&mut relay).await;
            let (_camera, answer) = Live::answer(&offer, true).await;
            let signal = if answering {
                RemoteSignal::Answer(answer)
            } else {
                RemoteSignal::Failed {
                    code: "offline".into(),
                    message: "gone".into(),
                }
            };
            settle().await;
            // Both before the source runs again: the deadline, then the
            // signal.
            clock.advance(ANSWER_TIMEOUT);
            relay.incoming.try_send(signal).unwrap();
            assert_eq!(
                within(running.run).await.unwrap(),
                SourceError::Timeout("webrtc: no answer within 20 s".into()),
                "answering: {answering}"
            );
            assert_eq!(closed(relay).await.code, close::ANSWER_TIMEOUT);
        }
    }

    #[tokio::test]
    async fn rfc8829_5_3_an_answer_that_is_no_sdp_ends_as_invalid_answer() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        read_offer(&mut relay).await;
        relay
            .incoming
            .send(RemoteSignal::Answer("not sdp".into()))
            .await
            .unwrap();
        let error = within(running.run).await.unwrap();
        assert!(matches!(error, SourceError::Protocol(_)), "{error}");
        assert_eq!(closed(relay).await.code, close::INVALID_ANSWER);
    }

    #[tokio::test]
    async fn rfc8445_5_1_1_an_attempt_gathers_on_at_most_16_host_addresses_handed_over_at_once() {
        let _logs = logs();
        // More host addresses than an offer carries: the first 16 (all of
        // one class), and all the signals queued at once, the relay
        // reading none.
        let hosts: Vec<IpAddr> = (1..=20)
            .map(|n| IpAddr::V4(Ipv4Addr::new(127, 0, 0, n)))
            .collect();
        let signaling = FakeSignaling::new(hosts);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        within(async {
            while relay.outgoing.len() < MAX_HOSTS + 2 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        const { assert!(MAX_HOSTS + 2 <= lotse_core::signaling::OUTGOING_CAPACITY) };
        let (offer, candidates) = read_offer(&mut relay).await;
        assert_eq!(candidates.len(), MAX_HOSTS + 1, "the hosts and the end");
        assert_eq!(offer.matches("a=candidate:").count(), MAX_HOSTS);
        for n in 1..=16 {
            assert!(offer.contains(&format!(" 127.0.0.{n} ")), "{n}: {offer}");
        }
        assert!(!offer.contains(" 127.0.0.17 "), "{offer}");
        assert!(offer.len() <= MAX_OFFER_BYTES);
        running.cancel.cancel();
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Ended("webrtc: cancelled".into())
        );
        assert_eq!(closed(relay).await.code, close::SOURCE_STOPPED);
    }

    #[tokio::test]
    async fn rfc3550_5_1_a_camera_whose_timestamps_keep_jumping_ends_the_attempt() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, _) = read_offer(&mut relay).await;
        let (mut camera, answer) = Live::answer(&offer, false).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        camera.connect().await;
        let run = running.run;
        within(async {
            let mut keyframe = true;
            while !run.is_finished() {
                // Half the clock away each frame: a new timeline every
                // time (RFC 3550 §5.1).
                camera.camera.ts = camera.camera.ts.wrapping_add(0x4000_0000);
                camera.camera.frame(SystemClock.now(), keyframe);
                keyframe = false;
                camera.pump(Duration::from_millis(20)).await;
            }
        })
        .await;
        let error = run.await.unwrap();
        assert!(matches!(error, SourceError::Protocol(_)), "{error}");
        let close = closed(relay).await;
        assert_eq!(close.code, close::INTERNAL_ERROR);
        assert_eq!(close.message, error.to_string());
    }

    /// Lets the source run up to its next wait.
    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn without_a_host_address_no_offer_is_made_and_the_reason_says_why() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let reason = "no host address to gather on: the WebRTC UDP front door is off";
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Unreachable(format!("webrtc: {reason}"))
        );
        assert!(relay.outgoing.try_recv().is_err(), "no offer");
        let close = closed(relay).await;
        assert_eq!(close.code, close::INTERNAL_ERROR);
        assert_eq!(close.message, reason);
    }

    /// An opener that opens `inner`'s channel `delay` late on `clock`, as
    /// the supervisor does while no client subscribed.
    #[derive(Debug)]
    struct LateOpener {
        inner: Arc<FakeSignaling>,
        clock: Arc<FakeClock>,
        delay: Duration,
    }

    impl SignalingOpener for LateOpener {
        fn open(
            &self,
        ) -> lotse_core::task::BoxFuture<
            'static,
            Result<
                lotse_core::signaling::SignalingChannel,
                lotse_core::signaling::SignalingRefused,
            >,
        > {
            let wait = self.clock.sleep(self.delay);
            let inner = Arc::clone(&self.inner);
            Box::pin(async move {
                wait.await;
                inner.open().await
            })
        }
    }

    /// A source runner with the default configuration on `clock`, its
    /// channels opened by `opener`: its task, its tracks, its events and
    /// its cancel.
    fn runner(
        clock: &Arc<FakeClock>,
        opener: Arc<dyn SignalingOpener>,
    ) -> (
        JoinHandle<()>,
        Arc<TrackSet>,
        mpsc::Receiver<lotse_core::runner::RunnerEvent>,
        CancellationToken,
    ) {
        use lotse_core::backoff::ReconnectBackoff;
        use lotse_core::runner::{ConnectGate, RunnerConfig, SourceRunner};

        let source = WebRtcSourceFactory
            .validate(&serde_json::json!({}))
            .unwrap();
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (events, reports) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let runner = SourceRunner::new(
            source,
            ResolvedPeer {
                host: String::new(),
                addrs: vec![],
            },
            Arc::clone(&set),
            Arc::new(ClockMapper::new()),
            BackchannelSlot::default(),
            Some(opener),
            clock.clone(),
            RunnerConfig::default(),
            ReconnectBackoff::new(7),
            events,
            ConnectGate::open(),
            cancel.clone(),
        );
        (
            spawn_named("test.webrtc_runner", runner.run()),
            set,
            reports,
            cancel,
        )
    }

    /// Lets `span` pass on `clock` in steps, the tasks running between.
    async fn pass(clock: &FakeClock, span: Duration) {
        let step = Duration::from_millis(100);
        let mut passed = Duration::ZERO;
        while passed < span {
            settle().await;
            clock.advance(step);
            passed += step;
        }
        settle().await;
    }

    /// Advances `clock` with the wall's until dropped.
    fn ticking(clock: &Arc<FakeClock>) -> JoinHandle<()> {
        let clock = clock.clone();
        spawn_named("test.ticker", async move {
            loop {
                SystemClock.sleep(Duration::from_millis(5)).await;
                clock.advance(Duration::from_millis(5));
            }
        })
    }

    #[tokio::test]
    async fn rfc8445_a_camera_slower_to_connect_than_the_stall_timeout_goes_live_under_the_runner()
    {
        use lotse_core::runner::{RunnerConfig, RunnerEvent};

        let _logs = logs();
        let clock = Arc::new(FakeClock::from_system());
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let config = RunnerConfig::default();
        let (runner, set, mut reports, cancel) = runner(&clock, signaling.clone());
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, _) = read_offer(&mut relay).await;
        let (mut camera, answer) = Live::answer(&offer, false).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        // The camera takes longer than the video stall timeout to answer
        // a check: the tracks are declared, the source is not live, the
        // runner waits under its ready timeout.
        pass(&clock, config.stall_video + Duration::from_secs(2)).await;
        assert_eq!(set.tracks().len(), 1, "declared at the answer");
        assert!(!*set.ready().borrow(), "not ready before the connection");
        let mut seen = Vec::new();
        while let Ok(event) = reports.try_recv() {
            seen.push(event);
        }
        assert!(
            matches!(seen.as_slice(), [RunnerEvent::Connecting { attempt: 1 }]),
            "{seen:?}"
        );
        // Now the camera connects, the clock running as the wall's.
        let ticking = ticking(&clock);
        camera.connect().await;
        let video = Arc::clone(&set.tracks()[0]);
        within(camera.stream_until(|| video.stats().keyframes >= 1)).await;
        let live = within(async {
            loop {
                match reports.recv().await.unwrap() {
                    RunnerEvent::Live => return true,
                    RunnerEvent::Stable => {}
                    other => panic!("{other:?}"),
                }
            }
        })
        .await;
        assert!(live);
        // Live for longer than the stall timeout: no stall, no retry.
        let until = SystemClock.now() + config.stall_video + Duration::from_secs(1);
        within(camera.stream_until(|| SystemClock.now() >= until)).await;
        while let Ok(event) = reports.try_recv() {
            assert!(matches!(event, RunnerEvent::Stable), "{event:?}");
        }
        assert_eq!(signaling.opens(), 1, "one attempt");
        cancel.cancel();
        within(runner).await.unwrap();
        ticking.abort();
    }

    /// The runner's events up to its first `Backoff` or `Live`, that one
    /// included.
    async fn first_outcome(
        reports: &mut mpsc::Receiver<lotse_core::runner::RunnerEvent>,
    ) -> lotse_core::runner::RunnerEvent {
        use lotse_core::runner::RunnerEvent;

        within(async {
            loop {
                match reports.recv().await.unwrap() {
                    RunnerEvent::Connecting { .. } => {}
                    other => return other,
                }
            }
        })
        .await
    }

    #[tokio::test]
    async fn rfc8829_a_late_client_and_a_late_answer_still_connect_within_the_runner_s_timeout() {
        use lotse_core::runner::RunnerEvent;

        let _logs = logs();
        let clock = Arc::new(FakeClock::from_system());
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let opener = Arc::new(LateOpener {
            inner: signaling.clone(),
            clock: clock.clone(),
            delay: Duration::from_secs(9),
        });
        let (runner, set, mut reports, cancel) = runner(&clock, opener);
        // A client 9 s late, the answer 10 s after the offer, the camera
        // connecting 7 s after that: 26 s into the attempt.
        pass(&clock, Duration::from_secs(9)).await;
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, _) = read_offer(&mut relay).await;
        pass(&clock, Duration::from_secs(10)).await;
        let (mut camera, answer) = Live::answer(&offer, false).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        pass(&clock, Duration::from_secs(7)).await;
        let ticking = ticking(&clock);
        camera.connect().await;
        let video = Arc::clone(&set.tracks()[0]);
        within(camera.stream_until(|| video.stats().packets > 0)).await;
        assert!(matches!(
            first_outcome(&mut reports).await,
            RunnerEvent::Live
        ));
        cancel.cancel();
        within(runner).await.unwrap();
        ticking.abort();
    }

    #[tokio::test]
    async fn rfc8829_5_2_a_late_client_s_attempt_ends_with_its_own_reason_before_the_runner_s_timeout()
     {
        use lotse_core::runner::RunnerEvent;

        let _logs = logs();
        // (when the answer comes, if at all; the attempt's error)
        let cases = [
            (
                None,
                SourceError::Timeout("webrtc: no answer within 20 s".into()),
                close::ANSWER_TIMEOUT,
            ),
            (
                Some(Duration::from_secs(10)),
                SourceError::Timeout("webrtc: not connected 28000 ms into the attempt".into()),
                close::ICE_FAILED,
            ),
        ];
        for (answer_after, expected, code) in cases {
            let clock = Arc::new(FakeClock::from_system());
            let signaling = FakeSignaling::new(vec![LOOPBACK]);
            let opener = Arc::new(LateOpener {
                inner: signaling.clone(),
                clock: clock.clone(),
                delay: Duration::from_secs(9),
            });
            let (runner, _set, mut reports, cancel) = runner(&clock, opener);
            pass(&clock, Duration::from_secs(9)).await;
            let mut relay = within(signaling.next_signal()).await.unwrap();
            let (offer, _) = read_offer(&mut relay).await;
            // A camera that never answers a check.
            let _camera = if let Some(after) = answer_after {
                pass(&clock, after).await;
                let (camera, answer) = Live::answer(&offer, false).await;
                relay
                    .incoming
                    .send(RemoteSignal::Answer(answer))
                    .await
                    .unwrap();
                Some(camera)
            } else {
                None
            };
            pass(&clock, Duration::from_secs(21)).await;
            let outcome = first_outcome(&mut reports).await;
            let RunnerEvent::Backoff { error, .. } = outcome else {
                panic!("{outcome:?}");
            };
            assert_eq!(error, expected);
            assert_eq!(within(relay.closed.wait()).await.code, code);
            cancel.cancel();
            within(runner).await.unwrap();
        }
    }

    #[tokio::test]
    async fn rfc8829_5_2_a_relay_that_reads_no_signal_holds_neither_the_answer_deadline_nor_a_failure()
     {
        let _logs = logs();
        // A failure while the signals wait unread.
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let relay = within(signaling.next_signal()).await.unwrap();
        relay
            .incoming
            .send(RemoteSignal::Failed {
                code: "offline".into(),
                message: "gone".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Unreachable("camera: offline: gone".into())
        );
        assert_eq!(relay.outgoing.len(), 3, "the offer, a candidate, the end");
        assert_eq!(closed(relay).await.code, close::CAMERA_ERROR);

        // The answer deadline while they wait, and once the relay stopped
        // reading altogether.
        for stop_reading in [false, true] {
            let clock = Arc::new(FakeClock::from_system());
            let signaling = FakeSignaling::new(vec![LOOPBACK]);
            let running = start(
                serde_json::json!({}),
                Some(signaling.clone()),
                clock.clone(),
            );
            let SignalingRelay {
                outgoing,
                incoming,
                closed: on_close,
                ..
            } = within(signaling.next_signal()).await.unwrap();
            let outgoing = (!stop_reading).then_some(outgoing);
            let mut run = running.run;
            for _ in 0..21 {
                settle().await;
                clock.advance(Duration::from_secs(1));
                if run.is_finished() {
                    break;
                }
            }
            assert_eq!(
                within(&mut run).await.unwrap(),
                SourceError::Timeout("webrtc: no answer within 20 s".into()),
                "stop reading: {stop_reading}"
            );
            assert_eq!(within(on_close.wait()).await.code, close::ANSWER_TIMEOUT);
            drop((outgoing, incoming));
        }
    }

    #[tokio::test]
    async fn rfc8829_5_2_a_deadline_that_is_due_goes_before_the_signals_waiting() {
        let _logs = logs();
        let clock = Arc::new(FakeClock::from_system());
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            clock.clone(),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        read_offer(&mut relay).await;
        settle().await;
        // In one step: the answer deadline passes, then two signals
        // arrive. The source takes the first in the wait under way, then
        // the deadline, before the camera's failure.
        clock.advance(ANSWER_TIMEOUT);
        relay
            .incoming
            .try_send(RemoteSignal::Candidate(SignalCandidate::end_of_candidates(
                None,
                Some(0),
            )))
            .unwrap();
        relay
            .incoming
            .try_send(RemoteSignal::Failed {
                code: "offline".into(),
                message: "gone".into(),
            })
            .unwrap();
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Timeout("webrtc: no answer within 20 s".into())
        );
        assert_eq!(closed(relay).await.code, close::ANSWER_TIMEOUT);
    }

    #[tokio::test]
    async fn rfc3264_7_h265_on_an_h264_track_leaves_the_track_as_it_is() {
        use lotse_codec::h265::test_data as h265_data;

        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({}),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, _) = read_offer(&mut relay).await;
        let (mut camera, answer) =
            Live::answer_with(&offer, camera_config(false).enable_h265(true)).await;
        relay
            .incoming
            .send(RemoteSignal::Answer(answer))
            .await
            .unwrap();
        camera.connect().await;
        let video = Arc::clone(&running.set.tracks()[0]);
        assert!(matches!(&*video.codec(), Codec::H264 { .. }));
        let mid = camera.camera.video.unwrap();
        let pt = camera.camera.pts(mid, EngineCodec::H265)[0];
        for _ in 0..5 {
            camera.camera.ts = camera.camera.ts.wrapping_add(3_000);
            let now = SystemClock.now();
            for unit in [h265_data::vps(), h265_data::sps(640, 480), h265_data::pps()] {
                camera.camera.write(now, pt, false, &unit);
            }
            let idr = h265_data::unit(19, &[0xaf, 0x08, 0x40, 0x10]);
            camera.camera.write(now, pt, true, &idr);
            camera.pump(Duration::from_millis(40)).await;
        }
        // Not one of them on the track, which is still H.264 and takes
        // the camera's H.264.
        assert_eq!(video.stats().packets, 0);
        assert!(matches!(&*video.codec(), Codec::H264 { sps: None, .. }));
        within(camera.stream_until(|| video.stats().keyframes >= 1)).await;
        assert!(matches!(&*video.codec(), Codec::H264 { sps: Some(_), .. }));
        running.cancel.cancel();
        within(running.run).await.unwrap();
    }
}
