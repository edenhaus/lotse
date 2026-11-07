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
use lotse_core::signaling::{
    LocalSignal, RemoteSignal, SignalCandidate, SignalClose, SignalingOpener, SignalingRelay, close,
};
use lotse_core::source::{
    BackchannelSlot, ClockInput, ClockReport, ResolvedPeer, SourceCtx, SourceError,
    SourceFactory as _, SyncHint, TrackSet,
};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_core::test_util::FakeSignaling;
use lotse_core::track::TrackLimits;
use lotse_webrtc::ingest::engine::{
    ANSWER_TIMEOUT, CONNECT_TIMEOUT, INTERNAL_ERROR, PLI_INTERVAL, STARTUP_PLIS,
};
use lotse_webrtc::ingest::{
    IngestEngine, IngestOutput, IngestTrack, WebRtcOptions, WebRtcSourceFactory,
};
use str0m::change::SdpOffer;
use str0m::channel::ChannelId;
use str0m::format::Codec as EngineCodec;
use str0m::media::{Mid, Pt};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::rtp::{ExtensionValues, RtpWrite, SeqNo};
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
        audio: true,
    }
}

fn video_only() -> WebRtcOptions {
    WebRtcOptions {
        data_channel: None,
        audio: false,
    }
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
        if self.rtc.accepts(&input) && self.rtc.handle_input(input).is_ok() {
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
        let media = self.rtc.media(self.video.unwrap()).unwrap();
        let config = self.rtc.codec_config();
        media
            .remote_pts()
            .iter()
            .copied()
            .filter(|pt| {
                config
                    .find(|params| params.pt() == *pt)
                    .is_some_and(|params| params.spec().codec == EngineCodec::H264)
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
        let now = SystemClock.now();
        let mut pair = Self {
            engine: IngestEngine::offer(options, &[ENGINE], now).unwrap(),
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
            if !self.dtls && (20..64).contains(&payload[0]) {
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
    let engine = IngestEngine::offer(&nest(), &[ENGINE], now).unwrap();
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
fn rfc8829_5_2_1_without_audio_or_data_channel_the_offer_is_video_alone() {
    let _logs = logs();
    lotse_webrtc::install_crypto_provider();
    let engine = IngestEngine::offer(&video_only(), &[ENGINE], SystemClock.now()).unwrap();
    let lines = media_lines(engine.offer_sdp());
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("m=video "));
    let video_mid = engine
        .offer_sdp()
        .lines()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .unwrap();
    assert_eq!(
        engine.local_candidates()[0].sdp_mid.as_deref(),
        Some(video_mid)
    );
}

#[test]
fn rfc8445_5_1_1_without_a_usable_host_address_no_offer_is_made() {
    let _logs = logs();
    lotse_webrtc::install_crypto_provider();
    let now = SystemClock.now();
    let err = IngestEngine::offer(&nest(), &[], now).unwrap_err();
    assert_eq!(err, "no usable host candidate among []");
    // IPv4 link-local, which the agent does not gather on.
    let link_local: SocketAddr = "169.254.1.1:5000".parse().unwrap();
    let err = IngestEngine::offer(&nest(), &[link_local], now).unwrap_err();
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
    pair.connect();
    assert!(pair.engine.answered());

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

    // RFC 3550 §6.4.1: the camera's Sender Reports, one each.
    for _ in 0..20 {
        pair.frame(false);
        pair.step(Duration::from_millis(250));
    }
    let reports: Vec<(usize, u64, u32)> = pair
        .outputs
        .iter()
        .filter_map(|output| match output {
            IngestOutput::SenderReport {
                index, ntp, rtp_ts, ..
            } => Some((*index, *ntp, *rtp_ts)),
            _ => None,
        })
        .collect();
    assert!(!reports.is_empty());
    assert_eq!(pair.engine.stats().sender_reports, reports.len() as u64);
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
    pair.run(Duration::from_millis(100));
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
    let mut pair = Pair::offer(&video_only());
    pair.answer(camera_config(false), |answer| answer);
    let tracks = pair.tracks();
    assert_eq!(tracks.len(), 1);
    assert_eq!(tracks[0].index, 0, "the video is the first m-line");
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
    let mut pair = Pair::offer(&video_only());
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
    // A packet from before (reordered: one of the lost) is no loss.
    pair.camera().seq -= 4;
    let before = pair.rtp().len();
    pair.frame(false);
    assert_eq!(pair.rtp().len(), before + 1, "it arrives");
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
fn rfc4585_6_3_1_a_loss_before_the_first_keyframe_is_left_to_the_startup_plis() {
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
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
    let mut pair = Pair::offer(&video_only());
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
fn rfc3550_5_1_packets_of_another_payload_type_are_dropped() {
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
    pair.answer(camera_config(false), |answer| answer);
    pair.connect();
    let pts = pair.camera().h264_pts();
    assert!(pts.len() > 1, "{pts:?}");
    let now = pair.now;
    pair.camera().write(now, pts[1], true, &[0x41, 0x00]);
    pair.camera().write(now, pts[1], true, &[0x41, 0x01]);
    pair.step(Duration::ZERO);
    assert_eq!(pair.engine.stats().foreign_packets, 2);
    assert_eq!(pair.engine.stats().rtp_packets, 0);
    assert!(pair.rtp().is_empty());
}

#[test]
fn rfc8829_5_3_a_camera_without_a_carried_audio_codec_still_sends_video() {
    let _logs = logs();
    let mut pair = Pair::offer(&nest());
    let answer = pair.answer(camera_config(false), |answer| answer);
    let tracks = pair.tracks();
    assert_eq!(tracks.len(), 1, "{tracks:?} {:?} {answer}", pair.outputs);
    assert_eq!(tracks[0].index, 1, "the video keeps its m-line's index");
    assert_eq!(tracks[0].declared.kind, Kind::Video);
}

#[test]
fn rfc8829_5_3_answers_the_engine_cannot_take_end_the_attempt_as_invalid() {
    let _logs = logs();
    let cases: [(&str, fn(String) -> String, &str); 4] = [
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
    assert!(pair.tracks().is_empty());
}

#[test]
fn rfc8445_8_not_connected_within_10_s_of_the_answer_ends_as_ice_failed() {
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
    pair.link = false;
    pair.answer(camera_config(false), |answer| answer);
    assert_eq!(pair.tracks().len(), 1);
    pair.run(CONNECT_TIMEOUT - Duration::from_millis(20));
    assert!(pair.ended().is_none());
    pair.run(Duration::from_millis(40));
    let (error, code, _) = pair.ended().unwrap();
    assert_eq!(
        error,
        SourceError::Timeout("webrtc: not connected within 10 s of the answer".into())
    );
    assert_eq!(code, close::ICE_FAILED);
}

#[test]
fn rfc8445_8_ice_up_without_dtls_and_then_lost_is_ice_failed_at_10_s() {
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
    pair.dtls = false;
    pair.answer(camera_config(false), |answer| answer);
    // STUN only (RFC 7983 §7: first byte 0 to 3): ICE pairs, DTLS never
    // gets through; then the link goes altogether. Not connected, the
    // attempt ends at the connection deadline (str0m 0.24's agent takes
    // longer to give the pair up).
    pair.run(Duration::from_secs(1));
    assert!(!pair.engine.is_connected());
    pair.link = false;
    pair.run(CONNECT_TIMEOUT - Duration::from_millis(1_100));
    assert!(pair.ended().is_none(), "{:?}", pair.ended());
    pair.run(Duration::from_millis(200));
    let (error, code, _) = pair.ended().unwrap();
    assert!(matches!(error, SourceError::Timeout(_)), "{error}");
    assert_eq!(code, close::ICE_FAILED);
}

#[test]
fn rfc7675_5_1_a_camera_that_stops_answering_consent_ends_as_consent_lost() {
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
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
    let mut pair = Pair::offer(&video_only());
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
    let mut pair = Pair::offer(&video_only());
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
    let mut pair = Pair::offer(&video_only());
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
    assert_eq!(code, INTERNAL_ERROR);
    assert!(message.starts_with("webrtc engine: "), "{message}");
}

#[test]
fn rfc8838_10_trickled_candidates_connect_and_bad_ones_are_refused() {
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
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
    let mut pair = Pair::offer(&video_only());
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
    let mut pair = Pair::offer(&video_only());
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
    let engine = IngestEngine::offer(&video_only(), &[ENGINE, ENGINE], SystemClock.now()).unwrap();
    assert_eq!(engine.local_candidates().len(), 2, "one host and the end");
    assert_eq!(engine.offer_sdp().matches("a=candidate:").count(), 1);
}

#[test]
fn rfc7983_7_media_from_a_stranger_is_not_taken() {
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
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
fn rfc6347_4_2_7_a_close_queues_its_close_notify() {
    let _logs = logs();
    let mut pair = Pair::offer(&video_only());
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
        let source = WebRtcSourceFactory
            .validate(
                &SourceUrl::parse("webrtc://camera.front_door").unwrap(),
                &options,
            )
            .unwrap();
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (input, reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let cancel = CancellationToken::new();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: "camera.front_door".into(),
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
            let socket = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
            let addr = socket.local_addr().unwrap();
            let (camera, answer) =
                Camera::answer(offer, addr, camera_config(audio), SystemClock.now());
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
        let running = start(serde_json::Value::Null, None, Arc::clone(&clock));
        assert_eq!(
            within(running.run).await.unwrap(),
            SourceError::Unreachable("webrtc: no signaling relay to the client".into())
        );
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        signaling.refuse_next("no_signaling_client", "nobody relays it");
        let running = start(serde_json::Value::Null, Some(signaling.clone()), clock);
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
            serde_json::Value::Null,
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
            serde_json::Value::Null,
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
        let mut ready = running.set.ready();
        within(ready.wait_for(|ready| *ready)).await.unwrap();
        let tracks = running.set.tracks();
        assert_eq!(tracks.len(), 2);
        assert_eq!(tracks[0].kind(), Kind::Audio);
        assert_eq!(tracks[1].kind(), Kind::Video);
        camera.connect().await;
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

    #[tokio::test]
    async fn a_camera_failure_before_its_answer_is_unreachable() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::Value::Null,
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
    async fn the_client_gone_ends_the_attempt_as_signaling_lost() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::Value::Null,
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
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::json!({ "audio": false }),
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let mut relay = within(signaling.next_signal()).await.unwrap();
        let (offer, _) = read_offer(&mut relay).await;
        assert_eq!(media_lines(&offer).len(), 1);
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
            serde_json::Value::Null,
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
    async fn rfc8829_5_3_an_answer_that_is_no_sdp_ends_as_invalid_answer() {
        let _logs = logs();
        let signaling = FakeSignaling::new(vec![LOOPBACK]);
        let running = start(
            serde_json::Value::Null,
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
    async fn a_cancel_while_the_relay_takes_no_signal_ends_the_offer() {
        let _logs = logs();
        // More host addresses than the channel holds signals: the offer
        // waits for the relay, which never reads.
        let hosts: Vec<IpAddr> = (1..=40)
            .map(|n| IpAddr::V4(Ipv4Addr::new(127, 0, 0, n)))
            .collect();
        let signaling = FakeSignaling::new(hosts);
        let running = start(
            serde_json::Value::Null,
            Some(signaling.clone()),
            Arc::new(SystemClock),
        );
        let relay = within(signaling.next_signal()).await.unwrap();
        within(async {
            while relay.outgoing.len() < lotse_core::signaling::OUTGOING_CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await;
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
        assert_eq!(close.code, INTERNAL_ERROR);
        assert_eq!(close.message, error.to_string());
    }
}
