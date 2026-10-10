//! The session against the headless viewer, in memory: negotiation, state,
//! cut-through, age gate, join burst and still, PLI and close.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::field_reassign_with_default,
    clippy::useless_asref,
    clippy::format_collect,
    clippy::unchecked_time_subtraction,
    clippy::manual_range_contains,
    clippy::duration_suboptimal_units,
    reason = "test code"
)]

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use lotse_codec::h264::{
    DEFAULT_MAX_PAYLOAD, LIBWEBRTC_MAX_FRAME_PACKETS, PacketNormalizer, ParameterSets, test_data,
};
use lotse_core::Orientation;
use lotse_core::clock::{Clock as _, SystemClock};
use lotse_core::codec::{Codec, Kind};
use lotse_core::media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields};
use lotse_core::output::OutputFactory as _;
use lotse_core::session::{
    IceCredentials, SessionEngine, SessionEvent, SessionLimits, SessionOpenError, SessionOutput,
    SessionRequest, Transport,
};
use lotse_core::source::TrackSet;
use lotse_core::track::{Track, TrackLimits};
use lotse_core::uplink::{UplinkCodec, UplinkPacket};
use lotse_testing::viewer::{
    Direction, Outgoing, Viewer, capture_seconds, with_audio_codecs, with_video_codecs,
};
use lotse_webrtc::{Session, State, WebRtcFactory};
use str0m::rtp::{AbsCaptureTime, VideoOrientation};

const DAEMON: &str = "192.0.2.10:18556";
const DAEMON_TCP: &str = "192.0.2.10:18557";
const BROWSER: &str = "192.0.2.20:40000";

fn h264(profile: Option<[u8; 3]>) -> Arc<Codec> {
    Arc::new(Codec::H264 {
        profile_level_id: profile,
        sps: None,
        pps: None,
    })
}

fn request(offer: &str, video: Arc<Codec>) -> SessionRequest {
    SessionRequest {
        offer: offer.to_owned(),
        ice: IceCredentials {
            ufrag: "lotseufrag".into(),
            pass: "lotsepassword0123456789ab".into(),
        },
        candidates: vec![DAEMON.parse().unwrap()],
        tcp_candidates: vec![DAEMON_TCP.parse().unwrap()],
        video,
        audio: None,
        backchannel: None,
        orientation: Orientation::default(),
        limits: SessionLimits::default(),
        wall: SystemClock.wall_now(),
    }
}

/// The daemon's session and the viewer with the datagrams in flight.
struct Pair {
    session: Session,
    viewer: Viewer,
    now: Instant,
    events: Vec<SessionEvent>,
    to_viewer: Vec<(Transport, SocketAddr, SocketAddr, Vec<u8>)>,
    /// Datagrams the daemon sent over each transport.
    sent: (usize, usize),
    /// The local addresses the daemon sent from.
    sources: BTreeSet<SocketAddr>,
    /// Every datagram the daemon sent, with whether it was marked audio.
    marked: Vec<(bool, Vec<u8>)>,
    to_daemon: Vec<Outgoing>,
    session_timeout: Option<Instant>,
    /// The talk-back packets the session handed on.
    uplink: Vec<UplinkPacket>,
}

impl Pair {
    fn new(video: Arc<Codec>) -> (Self, String) {
        let now = SystemClock.now();
        lotse_webrtc::install_crypto_provider();
        Self::with_viewer(
            video,
            Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer"),
            now,
        )
    }

    /// A pair whose viewer offers only an active ICE-TCP candidate.
    fn new_tcp(video: Arc<Codec>) -> (Self, String) {
        let now = SystemClock.now();
        lotse_webrtc::install_crypto_provider();
        let viewer = Viewer::new_tcp(BROWSER.parse().unwrap(), now).expect("a viewer");
        Self::with_viewer(video, viewer, now)
    }

    /// A pair whose viewer also receives audio, of the stream's `audio`.
    fn with_audio(video: Arc<Codec>, audio: Arc<Codec>) -> (Self, String) {
        let now = SystemClock.now();
        lotse_webrtc::install_crypto_provider();
        let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
        let mut request = request(viewer.offer(), video);
        request.audio = Some(audio);
        Self::with_request(&request, viewer, now)
    }

    fn with_viewer(video: Arc<Codec>, viewer: Viewer, now: Instant) -> (Self, String) {
        Self::with_request(&request(viewer.offer(), video), viewer, now)
    }

    /// A pair whose viewer's offer was edited to `offer`; the viewer still
    /// applies the answer.
    fn with_viewer_offer(
        video: Arc<Codec>,
        viewer: Viewer,
        offer: &str,
        now: Instant,
    ) -> (Self, String) {
        Self::with_request(&request(offer, video), viewer, now)
    }

    fn with_request(request: &SessionRequest, viewer: Viewer, now: Instant) -> (Self, String) {
        let (session, answer) = Session::answer(request, now).expect("an answer");
        let mut pair = Self {
            session,
            viewer,
            now,
            events: Vec::new(),
            to_viewer: Vec::new(),
            sent: (0, 0),
            sources: BTreeSet::new(),
            marked: Vec::new(),
            to_daemon: Vec::new(),
            session_timeout: None,
            uplink: Vec::new(),
        };
        pair.drain();
        (pair, answer)
    }

    fn drain(&mut self) {
        loop {
            match self.session.poll() {
                SessionOutput::Transmit {
                    transport,
                    source,
                    destination,
                    payload,
                    audio,
                } => {
                    self.marked.push((audio, payload.clone()));
                    if transport == Transport::Udp {
                        self.sent.0 += 1;
                    } else {
                        self.sent.1 += 1;
                    }
                    self.sources.insert(source);
                    self.to_viewer
                        .push((transport, source, destination, payload));
                }
                SessionOutput::Event(event) => self.events.push(event),
                SessionOutput::Uplink(packet) => self.uplink.push(packet),
                SessionOutput::Timeout(at) => {
                    self.session_timeout = Some(at);
                    return;
                }
            }
        }
    }

    fn connect(&mut self, answer: &str) {
        self.viewer
            .accept_answer(answer, &mut self.to_daemon)
            .expect("the answer applies");
        self.run_until(
            |p| p.session.state() == State::Connected && p.viewer.is_connected(),
            5_000,
            "connected",
        );
        // The join with an empty cache: nothing to send, wait for a keyframe.
        self.session.join(self.now, None);
        self.drain();
    }

    /// Advances at most 10 ms, to the next timeout when sooner, and moves
    /// what is in flight.
    fn step(&mut self) {
        let earliest = [self.session_timeout, self.viewer.next_timeout()]
            .into_iter()
            .flatten()
            .min();
        let floor = self.now + Duration::from_millis(1);
        let cap = self.now + Duration::from_millis(10);
        self.now = earliest.map_or(cap, |at| at.clamp(floor, cap));
        self.session.handle_timeout(self.now);
        self.drain();
        self.viewer.timeout(self.now, &mut self.to_daemon);
        for (_, source, _, bytes) in std::mem::take(&mut self.to_viewer) {
            self.viewer
                .receive(self.now, source, &bytes, &mut self.to_daemon);
        }
        for datagram in std::mem::take(&mut self.to_daemon) {
            let transport = if datagram.tcp {
                Transport::Tcp
            } else {
                Transport::Udp
            };
            self.session.handle_datagram(
                self.now,
                transport,
                datagram.source,
                datagram.destination,
                &datagram.payload,
            );
            self.drain();
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
            "{what}: not reached after {max_steps} steps; events {:?}",
            self.events
        );
    }

    fn closed_code(&self) -> Option<&str> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::Closed { code, .. } => Some(code.as_ref()),
            _ => None,
        })
    }
}

/// An access unit in Annex B: the parameter sets and an IDR, or one P
/// slice, `bytes` long.
fn access_unit(keyframe: bool, bytes: usize, frame: u8) -> Bytes {
    let mut out = Vec::new();
    if keyframe {
        for nal in [test_data::sps(640, 480), test_data::pps()] {
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(&nal);
        }
    }
    out.extend_from_slice(&[0, 0, 0, 1]);
    out.push(if keyframe { 0x65 } else { 0x41 });
    out.extend(std::iter::repeat_n(frame, bytes));
    Bytes::from(out)
}

/// The packets of one access unit as the RTSP source publishes them.
fn packets(
    normalizer: &mut PacketNormalizer,
    seq: &mut u16,
    ts: u32,
    keyframe: bool,
    bytes: usize,
    arrival: Instant,
) -> Vec<MediaPacket> {
    let mut out = Vec::new();
    let mut result = Vec::new();
    // 0x88 reads as `first_mb_in_slice` 0: each slice starts its picture
    // for a receiver that parses it (`lotse_testing::libwebrtc`).
    let au = access_unit(keyframe, bytes, 0x88);
    let units: Vec<&[u8]> = lotse_codec::h264::annex_b_units(&au);
    for (index, unit) in units.iter().enumerate() {
        let marker = index + 1 == units.len();
        normalizer
            .normalize(ts, marker, &Bytes::copy_from_slice(unit), &mut out)
            .expect("valid NAL");
        for packet in out.drain(..) {
            result.push(MediaPacket {
                arrival,
                rtp: RtpHeaderFields {
                    pt: 96,
                    seq: *seq,
                    ts,
                    marker: packet.marker,
                    ssrc: 1,
                },
                frame_start: packet.frame_start,
                keyframe_start: packet.keyframe_start,
                epoch: 0,
                lateness: Duration::ZERO,
                payload: Arc::from(packet.payload.as_ref()),
            });
            *seq = seq.wrapping_add(1);
        }
    }
    result
}

fn normalizer() -> PacketNormalizer {
    let mut sets = ParameterSets::default();
    sets.sps = Some(Bytes::from(test_data::sps(640, 480)));
    sets.pps = Some(Bytes::from(test_data::pps()));
    PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, sets)
}

/// A track with `frames` frames cached: a keyframe at `start` then P
/// frames 33 ms apart.
fn track_with_gop(now: Instant, start: Instant, frames: usize) -> Arc<Track> {
    track_with_frames(now, start, &vec![500; frames])
}

/// A track with a keyframe at `start` then P frames 33 ms apart cached,
/// of `sizes` bytes.
fn track_with_frames(now: Instant, start: Instant, sizes: &[usize]) -> Arc<Track> {
    let set = TrackSet::new(TrackLimits::default(), now);
    let mut publisher = set.publisher();
    let track = publisher.declare(Kind::Video, (*h264(None)).clone(), 90_000);
    for (i, &bytes) in sizes.iter().enumerate() {
        let at = start + Duration::from_millis(33 * i as u64);
        let frame = MediaFrame {
            ts: MediaTime::from_ticks(90_000 + i as i64 * 3_000),
            wallclock: at,
            arrival: at,
            keyframe: i == 0,
            discontinuity: i == 0,
            epoch: 0,
            payload: access_unit(i == 0, bytes, u8::try_from(i).unwrap()),
        };
        assert!(track.publish_frame(frame));
    }
    track
}

#[test]
fn the_answer_carries_credentials_h264_candidates_and_playout_delay_rfc8829() {
    let (mut pair, answer) = Pair::new(h264(Some([0x42, 0xc0, 0x28])));
    assert!(answer.contains("a=ice-ufrag:lotseufrag"), "{answer}");
    assert!(answer.contains("packetization-mode=1"), "{answer}");
    assert!(answer.contains(" rtx/90000"), "{answer}");
    assert!(answer.contains("playout-delay"), "{answer}");
    assert!(answer.contains("192.0.2.10 18556 typ host"), "{answer}");
    let candidates: Vec<_> = pair
        .events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Candidate { candidate, mid } => Some((candidate.clone(), mid.clone())),
            _ => None,
        })
        .collect();
    // UDP first, then the passive ICE-TCP one (RFC 6544 §4.5), then
    // end-of-candidates.
    assert_eq!(candidates.len(), 3, "{candidates:?}");
    assert!(
        candidates[0].0.contains(" udp ") && candidates[0].0.contains("192.0.2.10 18556 typ host")
    );
    assert!(candidates[0].1.is_some());
    assert!(
        candidates[1].0.contains(" tcp ")
            && candidates[1]
                .0
                .contains("192.0.2.10 18557 typ host tcptype passive"),
        "{candidates:?}"
    );
    assert_eq!(candidates[2], (String::new(), None));
    assert!(pair.events.contains(&SessionEvent::State {
        ice: "new",
        dtls: "new"
    }));
    assert_eq!(pair.session.state(), State::Gathering);
    pair.connect(&answer);
    assert!(pair.events.contains(&SessionEvent::State {
        ice: "connected",
        dtls: "connected"
    }));
    assert!(pair.events.contains(&SessionEvent::Connected));
    // The viewer hangs up: the transport closes, the session reports it.
    pair.viewer.close(&mut pair.to_daemon);
    pair.run_until(|p| p.closed_code().is_some(), 3_000, "peer closed");
    assert_eq!(pair.closed_code(), Some("peer_closed"));
    assert_eq!(pair.session.state(), State::Closed);
    // Inert afterwards.
    pair.session.write_video(
        pair.now,
        &packets(&mut normalizer(), &mut 0, 0, true, 100, pair.now)[0],
        pair.now,
    );
    pair.session
        .add_remote_candidate(pair.now, "candidate:1 1 udp 1 192.0.2.30 1 typ host");
    pair.session.close(pair.now, "again", String::new());
    pair.drain();
    assert_eq!(
        pair.events
            .iter()
            .filter(|e| matches!(e, SessionEvent::Closed { .. }))
            .count(),
        1
    );
}

#[test]
fn rfc9143_9_1_1_a_payload_type_with_two_codecs_is_invalid_sdp_not_a_crash() {
    // Opus on 109, which the video m-line of the same BUNDLE group uses for
    // H.264's retransmissions: str0m 0.24 locked 109 twice and panicked,
    // which aborts the worker. Refused before it sees the offer, whether
    // the session sends audio or not.
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = with_audio_codecs(viewer.offer(), "a=rtpmap:109 opus/48000/2\n");
    for audio in [None, Some(Arc::new(Codec::Opus { channels: 2 }))] {
        let mut request = request(&offer, h264(None));
        request.audio = audio;
        let err = Session::answer(&request, now).err();
        let Some(SessionOpenError::InvalidSdp(message)) = &err else {
            panic!("{err:?}");
        };
        assert!(
            message.starts_with("payload type 109 is audio opus/48000/2 in m-line 0")
                && message.contains("video rtx/90000 (apt=108) in m-line 1")
                && message.ends_with("(RFC 9143 §9.1.1)"),
            "{message}"
        );
        assert_eq!(err.map(|err| err.code()), Some("invalid_sdp"));
    }
}

#[test]
fn negotiation_errors_map_to_codes_rfc6184_8_2_2() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let bad = Session::answer(&request("v=0\r\nnot sdp", h264(None)), now).err();
    assert!(
        matches!(bad, Some(SessionOpenError::InvalidSdp(_))),
        "{bad:?}"
    );
    let no_video = viewer.offer().replace("m=video", "m=audio");
    let err = Session::answer(&request(&no_video, h264(None)), now).err();
    assert!(
        matches!(err, Some(SessionOpenError::NoVideoTrack)),
        "{err:?}"
    );
    let err = Session::answer(&request(viewer.offer(), Arc::new(Codec::Mjpeg)), now).err();
    assert!(
        matches!(err, Some(SessionOpenError::VideoCodecUnsupported(_))),
        "{err:?}"
    );
    // Only packetization-mode 0 offered: nothing to send under.
    let mode0 = viewer
        .offer()
        .replace("packetization-mode=1", "packetization-mode=0");
    let err = Session::answer(&request(&mode0, h264(None)), now).err();
    assert!(
        matches!(err, Some(SessionOpenError::VideoCodecUnsupported(_))),
        "{err:?}"
    );
    // The factory opens the same session, and a High 4.0 stream against an
    // offer with only Constrained Baseline gets the deviation warning.
    let baseline_only: String = viewer
        .offer()
        .lines()
        .filter(|line| {
            !line.contains("profile-level-id=4d") && !line.contains("profile-level-id=64")
        })
        .map(|line| format!("{line}\r\n"))
        .collect();
    let (mut engine, answer) = WebRtcFactory
        .open_session(request(&baseline_only, h264(Some([0x64, 0x00, 0x28]))), now)
        .expect("answered under a lower profile");
    assert!(answer.contains("profile-level-id=42"), "{answer}");
    let mut warning = None;
    loop {
        match engine.poll() {
            SessionOutput::Event(SessionEvent::Warning { code, message }) => {
                warning = Some((code, message));
            }
            SessionOutput::Timeout(_) => break,
            _ => {}
        }
    }
    let (code, message) = warning.expect("a warning");
    assert_eq!(code, "h264_profile_mismatch");
    assert!(message.contains("640028"), "{message}");
    // Audio the daemon cannot carry is a warning, never an error.
    let mut with_audio = request(viewer.offer(), h264(None));
    with_audio.audio = Some(Arc::new(Codec::AacLc {
        sample_rate: 48_000,
        channels: 2,
        config: Bytes::new(),
    }));
    let (mut session, _) = Session::answer(&with_audio, now).expect("video still answered");
    let mut codes = Vec::new();
    loop {
        match session.poll() {
            SessionOutput::Event(SessionEvent::Warning { code, .. }) => codes.push(code),
            SessionOutput::Timeout(_) => break,
            _ => {}
        }
    }
    assert_eq!(codes, ["audio_codec_unsupported"]);
    let mut with_opus = request(viewer.offer(), h264(None));
    with_opus.audio = Some(Arc::new(Codec::Opus { channels: 2 }));
    assert!(Session::answer(&with_opus, now).is_ok());
    assert!(format!("{session:?}").contains("Gathering"));
}

/// Safari's video codec lines: its H.264 payload types are Constrained
/// High and Constrained Baseline, both `packetization-mode=1`, no plain
/// High. Reconstructed from `WebKit`'s codec list; PT 98 as Constrained
/// Baseline matches a Safari session observed on 2026-09-30.
const SAFARI_VIDEO: &str = include_str!("fixtures/safari-video-codecs.sdp");

/// The warnings an engine queued at open.
fn warnings(engine: &mut dyn SessionEngine) -> Vec<&'static str> {
    let mut codes = Vec::new();
    loop {
        match engine.poll() {
            SessionOutput::Event(SessionEvent::Warning { code, .. }) => codes.push(code),
            SessionOutput::Timeout(_) => return codes,
            _ => {}
        }
    }
}

#[test]
fn rfc6184_8_1_safari_gets_a_high_camera_under_its_constrained_high_payload_type() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let safari = with_video_codecs(viewer.offer(), SAFARI_VIDEO);
    // The camera of the 2026-09-30 session: High, level 5.1.
    let (mut engine, answer) = WebRtcFactory
        .open_session(request(&safari, h264(Some([0x64, 0x00, 0x33]))), now)
        .expect("answered");
    assert!(answer.contains("a=rtpmap:96 H264/90000"), "{answer}");
    assert!(answer.contains("profile-level-id=640c1f"), "{answer}");
    // The answer lists every payload type both sides can do; the one sent
    // under is Constrained High, since only a lower one warns.
    assert!(
        !warnings(engine.as_mut()).contains(&"h264_profile_mismatch"),
        "the same profile, no deviation"
    );
    // A Constrained Baseline camera still gets Safari's Baseline type.
    let (mut engine, answer) = WebRtcFactory
        .open_session(request(&safari, h264(Some([0x42, 0xe0, 0x1f]))), now)
        .expect("answered");
    assert!(answer.contains("profile-level-id=42e01f"), "{answer}");
    assert!(warnings(engine.as_mut()).is_empty());
}

#[test]
fn rfc6184_8_1_a_high_camera_prefers_plain_high_when_both_are_offered() {
    // Chrome offers High and Constrained High: the exact constraints win,
    // either way round.
    let chrome = "a=rtpmap:102 H264/90000\na=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f\na=rtpmap:104 H264/90000\na=fmtp:104 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f\na=rtpmap:106 H264/90000\na=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\n";
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = with_video_codecs(viewer.offer(), chrome);
    for (camera, expected) in [
        ([0x64, 0x00, 0x33], "64001f"),
        ([0x64, 0x0c, 0x28], "640c1f"),
    ] {
        let (mut engine, answer) = WebRtcFactory
            .open_session(request(&offer, h264(Some(camera))), now)
            .expect("answered");
        assert!(
            answer.contains(&format!("profile-level-id={expected}")),
            "{camera:02x?}: {answer}"
        );
        assert!(warnings(engine.as_mut()).is_empty(), "{camera:02x?}");
    }
}

#[test]
fn cut_through_renumbers_and_the_age_gate_skips_to_a_keyframe() {
    let (mut pair, answer) = Pair::new(h264(Some([0x42, 0xc0, 0x28])));
    pair.connect(&answer);
    let mut normalizer = normalizer();
    let mut seq = 1000;
    // A P frame before any keyframe is dropped: nothing to decode it with.
    for packet in packets(&mut normalizer, &mut seq, 90_000, false, 300, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    assert_eq!(pair.session.stats().packets, 0);
    assert!(pair.session.stats().dropped_waiting > 0);
    // Then a GOP of three frames flows.
    let mut sent = 0;
    for frame in 0..3_u32 {
        let ts = 93_000 + frame * 3_000;
        for packet in packets(&mut normalizer, &mut seq, ts, frame == 0, 1_500, pair.now) {
            pair.session.write_video(pair.now, &packet, pair.now);
            sent += 1;
        }
        pair.drain();
        for _ in 0..3 {
            pair.step();
        }
    }
    // The standalone SPS and PPS packets of the keyframe are dropped: the
    // synthetic STAP-A before the IDR is the keyframe start and carries
    // them.
    let stats = pair.session.stats();
    assert_eq!(stats.packets, sent as u64 - 2);
    assert_eq!(stats.dropped_waiting, 3);
    let sent = stats.packets as usize;
    pair.run_until(|p| p.viewer.packets().len() >= sent, 500, "all packets");
    let received = pair.viewer.packets();
    // Our sequence space, from zero, contiguous; the camera's timestamps;
    // markers where the camera set them; the keyframe first.
    for (i, packet) in received.iter().enumerate() {
        assert_eq!(*packet.seq_no, i as u64, "{:?}", packet.header);
    }
    assert_eq!(received[0].header.timestamp, 93_000);
    assert!(pair.viewer.keyframe_starts() >= 1);
    assert_eq!(received.iter().filter(|p| p.header.marker).count(), 3);

    // A packet older than max_packet_age is dropped, the session skips
    // to the next keyframe and asks upstream for one.
    let events_before = pair.events.len();
    let stale = pair.now - Duration::from_millis(200);
    for packet in packets(&mut normalizer, &mut seq, 102_000, false, 300, stale) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    pair.drain();
    assert!(pair.session.stats().dropped_old >= 1);
    assert!(pair.events[events_before..].contains(&SessionEvent::KeyframeRequest));
    // Fresh P frames stay dropped until a keyframe.
    for packet in packets(&mut normalizer, &mut seq, 105_000, false, 300, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    let packets_before = pair.session.stats().packets;
    assert_eq!(pair.session.stats().packets, packets_before);
    // A gap does the same, and an explicit skip is idempotent.
    pair.session.skip_to_keyframe("gap");
    pair.session.skip_to_keyframe("gap");
    assert!(pair.session.stats().skips >= 3);
    // A new epoch starts on a keyframe: the timestamp offset continues
    // the session clock rather than jumping with the camera's.
    let mut epoch_packets = packets(&mut normalizer, &mut seq, 5_000, true, 300, pair.now);
    for packet in &mut epoch_packets {
        packet.epoch = 1;
        pair.session.write_video(pair.now, packet, pair.now);
    }
    pair.drain();
    let written = pair.session.stats().packets;
    pair.run_until(
        |p| p.viewer.packets().len() as u64 >= written,
        500,
        "epoch packets",
    );
    let last = pair.viewer.packets().last().unwrap();
    assert!(last.header.timestamp > 99_000, "{}", last.header.timestamp);
    assert!(
        last.header.timestamp < 99_000 + 90 * 2_000,
        "{}",
        last.header.timestamp
    );
    // A stale packet while already waiting does not ask again.
    pair.session.skip_to_keyframe("gap");
    let events_before = pair.events.len();
    for packet in packets(&mut normalizer, &mut seq, 9_000, false, 300, stale) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    pair.drain();
    assert!(pair.session.stats().dropped_old >= 2);
    assert!(!pair.events[events_before..].contains(&SessionEvent::KeyframeRequest));
}

#[test]
fn a_frame_late_after_an_ingest_stall_skips_to_a_timely_keyframe() {
    let (_logs, captured) = capture_logs(tracing::Level::DEBUG);
    let (mut pair, answer) = Pair::new(h264(Some([0x42, 0xc0, 0x28])));
    pair.connect(&answer);
    let mut normalizer = normalizer();
    let mut seq = 1000;
    let write = |pair: &mut Pair, packets: &[MediaPacket]| {
        for packet in packets {
            pair.session.write_video(pair.now, packet, pair.now);
        }
        pair.drain();
    };
    let late = |mut packets: Vec<MediaPacket>, ms: u64| {
        for packet in &mut packets {
            packet.lateness = Duration::from_millis(ms);
        }
        packets
    };
    let keyframe = packets(&mut normalizer, &mut seq, 90_000, true, 300, pair.now);
    write(&mut pair, &keyframe);
    let live = pair.session.stats().packets;
    assert!(live > 0);

    // The burst after a stall: fresh by arrival, late by the camera's
    // clock. Dropped, one skip, and upstream is asked for a keyframe.
    let events_before = pair.events.len();
    let burst = late(
        packets(&mut normalizer, &mut seq, 93_000, false, 300, pair.now),
        201,
    );
    write(&mut pair, &burst);
    let stats = pair.session.stats();
    assert_eq!(stats.packets, live);
    assert_eq!(stats.dropped_late, burst.len() as u64);
    assert_eq!(stats.dropped_old, 0, "not an age drop");
    assert_eq!(stats.ingest_late_skips, 1);
    assert!(pair.events[events_before..].contains(&SessionEvent::KeyframeRequest));
    let logged = captured.text();
    assert!(
        logged.contains("frame arrived late after an ingest stall lateness_ms=201 limit_ms=200"),
        "{logged}"
    );

    // A late keyframe does not resume either; the stall still counts once
    // and asks once.
    let events_before = pair.events.len();
    let late_keyframe = late(
        packets(&mut normalizer, &mut seq, 96_000, true, 300, pair.now),
        250,
    );
    write(&mut pair, &late_keyframe);
    let stats = pair.session.stats();
    assert_eq!(stats.packets, live);
    assert_eq!(
        stats.dropped_late,
        (burst.len() + late_keyframe.len()) as u64
    );
    assert_eq!(stats.ingest_late_skips, 1);
    assert!(!pair.events[events_before..].contains(&SessionEvent::KeyframeRequest));

    // A keyframe at the limit is timely: cut-through resumes on it.
    let timely = late(
        packets(&mut normalizer, &mut seq, 99_000, true, 300, pair.now),
        200,
    );
    write(&mut pair, &timely);
    assert!(pair.session.stats().packets > live);
}

#[test]
fn a_fresh_gop_is_burst_before_the_live_edge_and_live_resumes_after_it() {
    let (mut pair, answer) = Pair::new(h264(None));
    pair.viewer
        .accept_answer(&answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.run_until(
        |p| p.session.state() == State::Connected,
        5_000,
        "connected",
    );
    // Four cached frames, the keyframe 200 ms old: a burst.
    let start = pair.now - Duration::from_millis(200);
    let track = track_with_gop(pair.now, start, 4);
    let gop = track.gop().expect("a cache");
    pair.session.join(pair.now, Some(&gop));
    pair.drain();
    let stats = pair.session.stats();
    assert_eq!(stats.join_frames, 4);
    assert!(stats.packets >= 4);
    assert!(!pair.events.contains(&SessionEvent::KeyframeRequest));
    pair.run_until(
        |p| p.viewer.packets().len() as u64 >= stats.packets,
        500,
        "burst",
    );
    let received = pair.viewer.packets();
    assert!(pair.viewer.keyframe_starts() >= 1);
    // Re-stamped 1 ms apart, ending at the last frame's timestamp.
    let last_ts = 90_000 + 3 * 3_000;
    assert_eq!(received.last().unwrap().header.timestamp, last_ts);
    assert_eq!(received[0].header.timestamp, last_ts - 3 * 90);
    // Live packets of the frames already burst are dropped; the next
    // frame resumes cut-through.
    let mut normalizer = normalizer();
    let mut seq = 0;
    for packet in packets(&mut normalizer, &mut seq, last_ts, false, 300, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    assert_eq!(pair.session.stats().packets, stats.packets);
    let next = packets(
        &mut normalizer,
        &mut seq,
        last_ts + 3_000,
        false,
        1_500,
        pair.now,
    );
    assert!(next.len() > 1);
    // A mid-frame packet first (its start was lost) is not a resume point.
    pair.session
        .write_video(pair.now, &next[next.len() - 1], pair.now);
    assert_eq!(pair.session.stats().packets, stats.packets);
    for packet in &next {
        pair.session.write_video(pair.now, packet, pair.now);
    }
    assert_eq!(
        pair.session.stats().packets,
        stats.packets + next.len() as u64
    );
    pair.drain();
}

#[test]
fn an_old_gop_gives_a_still_and_p_frames_wait_for_the_next_keyframe() {
    let (_logs, captured) = capture_logs(tracing::Level::INFO);
    let (mut pair, answer) = Pair::new(h264(None));
    pair.viewer
        .accept_answer(&answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.run_until(
        |p| p.session.state() == State::Connected,
        5_000,
        "connected",
    );
    let start = pair.now - Duration::from_secs(2);
    let track = track_with_gop(pair.now, start, 3);
    let gop = track.gop().expect("a cache");
    pair.session.join(pair.now, Some(&gop));
    pair.drain();
    assert_eq!(pair.session.stats().join_frames, 1);
    assert!(pair.events.contains(&SessionEvent::KeyframeRequest));
    let logged = captured.text();
    assert!(
        logged.contains("join: keyframe still age_ms=2000 truncated=false"),
        "{logged}"
    );
    let still_packets = pair.session.stats().packets;
    pair.run_until(
        |p| p.viewer.packets().len() as u64 >= still_packets,
        500,
        "still",
    );
    // Projected to now on the camera clock: about 2 s of 90 kHz ahead.
    let ts = pair.viewer.packets()[0].header.timestamp;
    assert!(
        ts >= 90_000 + 2 * 90_000 - 9_000 && ts <= 90_000 + 3 * 90_000,
        "{ts}"
    );
    let mut normalizer = normalizer();
    let mut seq = 0;
    for packet in packets(&mut normalizer, &mut seq, 400_000, false, 300, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    assert_eq!(pair.session.stats().packets, still_packets);
    for packet in packets(&mut normalizer, &mut seq, 403_000, true, 300, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    assert!(pair.session.stats().packets > still_packets);
    // A burst after an epoch change continues from a keyframe only.
    let track = track_with_gop(pair.now, pair.now - Duration::from_millis(100), 2);
    let gop = track.gop().expect("a cache");
    pair.session.join(pair.now, Some(&gop));
    let after_burst = pair.session.stats().packets;
    let mut other_epoch = packets(&mut normalizer, &mut seq, 500_000, false, 300, pair.now);
    for packet in &mut other_epoch {
        packet.epoch = 7;
        pair.session.write_video(pair.now, packet, pair.now);
    }
    assert_eq!(pair.session.stats().packets, after_burst);
    let mut keyframe = packets(&mut normalizer, &mut seq, 503_000, true, 300, pair.now);
    for packet in &mut keyframe {
        packet.epoch = 7;
        pair.session.write_video(pair.now, packet, pair.now);
    }
    assert!(pair.session.stats().packets > after_burst);
    // A keyframe of a new epoch first after a burst resumes at once.
    let track = track_with_gop(pair.now, pair.now - Duration::from_millis(100), 2);
    let gop = track.gop().expect("a cache");
    pair.session.join(pair.now, Some(&gop));
    let after_burst = pair.session.stats().packets;
    let keyframe: Vec<MediaPacket> =
        packets(&mut normalizer, &mut seq, 600_000, true, 300, pair.now)
            .into_iter()
            .skip_while(|packet| !packet.keyframe_start)
            .map(|packet| MediaPacket { epoch: 8, ..packet })
            .collect();
    for packet in &keyframe {
        pair.session.write_video(pair.now, packet, pair.now);
    }
    assert_eq!(
        pair.session.stats().packets,
        after_burst + keyframe.len() as u64
    );
    pair.drain();
}

/// An IDR this large takes more packets at the datagram target than some
/// libwebrtc receivers assemble.
const OVER_LIMIT: usize = (LIBWEBRTC_MAX_FRAME_PACKETS + 100) * (DEFAULT_MAX_PAYLOAD - 2);

/// The `frame_over_browser_limit` warnings among `events`.
fn over_limit_warnings(events: &[SessionEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            SessionEvent::Warning {
                code: "frame_over_browser_limit",
                message,
            } => Some(message.clone()),
            _ => None,
        })
        .collect()
}

/// How many keyframe requests are among `events`.
fn keyframe_requests(events: &[SessionEvent]) -> usize {
    events
        .iter()
        .filter(|event| **event == SessionEvent::KeyframeRequest)
        .count()
}

#[test]
fn libwebrtc_max_frame_packets_a_larger_frame_is_sent_whole_counted_and_warned_about_once() {
    let (mut pair, answer) = Pair::new(h264(None));
    pair.connect(&answer);
    let requests = keyframe_requests(&pair.events);
    let mut normalizer = normalizer();
    let mut seq = 0;
    // A group of pictures that fits, one whose keyframe does not, one
    // that fits again: every packet of every frame goes out.
    let mut written = 0;
    let mut sizes = Vec::new();
    for (gop, idr_bytes) in [(0_u32, 5_000), (1, OVER_LIMIT), (2, 5_000)] {
        for frame in 0..3_u32 {
            let ts = 90_000 + (gop * 3 + frame) * 3_000;
            let bytes = if frame == 0 { idr_bytes } else { 800 };
            let live = packets(&mut normalizer, &mut seq, ts, frame == 0, bytes, pair.now);
            sizes.push((ts, live.len()));
            for packet in live {
                pair.session.write_video(pair.now, &packet, pair.now);
            }
            pair.drain();
            let sent = pair.session.stats().packets;
            if sent > written {
                pair.run_until(|p| p.viewer.packets().len() as u64 >= sent, 5_000, "frame");
                written = sent;
            }
        }
    }
    // The camera's own parameter sets before the first keyframe are dropped
    // while the session waits for the normalizer's (`keyframe_start`).
    let received = pair.viewer.packets();
    for &(ts, count) in &sizes[1..] {
        let of: Vec<_> = received
            .iter()
            .filter(|p| p.header.timestamp == ts)
            .collect();
        assert_eq!(of.len(), count, "frame {ts}");
        assert!(of.last().unwrap().header.marker, "frame {ts} ended");
    }
    let big = sizes[3].1;
    assert!(big > LIBWEBRTC_MAX_FRAME_PACKETS, "{big} packets");
    // Nothing skipped, no keyframe asked for: the frame is the camera's.
    let stats = pair.session.stats();
    assert_eq!((stats.frames_over_browser_limit, stats.skips), (1, 0));
    assert_eq!(keyframe_requests(&pair.events), requests);
    let warnings = over_limit_warnings(&pair.events);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains(&format!("needed {big} RTP packets"))
            && warnings[0].contains("(2047)")
            && warnings[0].contains("sent whole")
            && warnings[0].contains("substream"),
        "{}",
        warnings[0]
    );
    // A second one is counted, not warned about again; a frame of exactly
    // the limit is neither.
    let exact = LIBWEBRTC_MAX_FRAME_PACKETS * (DEFAULT_MAX_PAYLOAD - 2);
    for (index, bytes) in [OVER_LIMIT, exact].into_iter().enumerate() {
        let ts = 90_000 + (9 + index as u32) * 3_000;
        let live = packets(&mut normalizer, &mut seq, ts, false, bytes, pair.now);
        if bytes == exact {
            assert_eq!(live.len(), LIBWEBRTC_MAX_FRAME_PACKETS);
        }
        for packet in &live {
            pair.session.write_video(pair.now, packet, pair.now);
        }
        pair.drain();
    }
    assert_eq!(pair.session.stats().frames_over_browser_limit, 2);
    assert_eq!(over_limit_warnings(&pair.events).len(), 1);
}

#[test]
fn libwebrtc_max_frame_packets_a_larger_cached_frame_is_joined_with_whole() {
    // A burst sends every cached frame, one over the limit included.
    let (mut pair, answer) = Pair::new(h264(None));
    pair.viewer
        .accept_answer(&answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.run_until(
        |p| p.session.state() == State::Connected,
        5_000,
        "connected",
    );
    let fresh = pair.now - Duration::from_millis(100);
    let track = track_with_frames(pair.now, fresh, &[500, OVER_LIMIT, 500]);
    let over =
        lotse_codec::h264::packetize(&access_unit(false, OVER_LIMIT, 1), DEFAULT_MAX_PAYLOAD).len();
    pair.session
        .join(pair.now, Some(&track.gop().expect("a cache")));
    pair.drain();
    let stats = pair.session.stats();
    assert_eq!((stats.join_frames, stats.frames_over_browser_limit), (3, 1));
    assert!(stats.packets as usize > over, "{} packets", stats.packets);
    let warnings = over_limit_warnings(&pair.events);
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].contains(&format!("needed {over} RTP packets")),
        "{}",
        warnings[0]
    );
    // The live packets after the burst go on.
    let mut normalizer = normalizer();
    let mut seq = 0;
    let before = stats.packets;
    for packet in packets(
        &mut normalizer,
        &mut seq,
        90_000 + 3 * 3_000,
        false,
        300,
        pair.now,
    ) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    assert!(pair.session.stats().packets > before, "P frames follow");
    // A still over the limit is sent whole too; one of exactly 2047
    // packets (its SPS, its PPS, the IDR in FU-A fragments) is not counted.
    for (bytes, counted) in [
        (OVER_LIMIT, 1),
        (
            (LIBWEBRTC_MAX_FRAME_PACKETS - 2) * (DEFAULT_MAX_PAYLOAD - 2),
            0,
        ),
    ] {
        let (mut pair, answer) = Pair::new(h264(None));
        pair.connect(&answer);
        let track = track_with_frames(pair.now, pair.now - Duration::from_secs(2), &[bytes]);
        let whole =
            lotse_codec::h264::packetize(&access_unit(true, bytes, 0), DEFAULT_MAX_PAYLOAD).len();
        pair.session
            .join(pair.now, Some(&track.gop().expect("a cache")));
        pair.drain();
        let stats = pair.session.stats();
        assert_eq!(
            (
                stats.packets,
                stats.join_frames,
                stats.frames_over_browser_limit
            ),
            (whole as u64, 1, counted)
        );
        assert_eq!(over_limit_warnings(&pair.events).len(), counted as usize);
    }
}

#[test]
fn a_pli_becomes_a_keyframe_request_and_close_reports_the_code() {
    let (mut pair, answer) = Pair::new(h264(None));
    pair.connect(&answer);
    let before = pair.events.len();
    pair.viewer.request_keyframe(&mut pair.to_daemon);
    pair.run_until(
        |p| p.events[before..].contains(&SessionEvent::KeyframeRequest),
        300,
        "the keyframe request",
    );
    assert_eq!(pair.session.stats().keyframe_requests, 1);
    // A trickled candidate is taken; a malformed one is a warning.
    pair.session.add_remote_candidate(
        pair.now,
        "candidate:1 1 udp 2130706431 192.0.2.21 40001 typ host",
    );
    pair.session.add_remote_candidate(pair.now, "");
    pair.session
        .add_remote_candidate(pair.now, "candidate:garbage");
    pair.drain();
    assert!(pair.events.iter().any(|e| matches!(
        e,
        SessionEvent::Warning {
            code: "invalid_candidate",
            ..
        }
    )));
    pair.session
        .close(pair.now, "session_closed", "unsubscribed".into());
    pair.drain();
    let closing = &pair.events[pair.events.len() - 2..];
    assert_eq!(
        closing[0],
        SessionEvent::State {
            ice: "closed",
            dtls: "closed"
        }
    );
    assert_eq!(
        closing[1],
        SessionEvent::Closed {
            code: "session_closed",
            message: "unsubscribed".into()
        }
    );
    // Idle from now on.
    let idle = pair.session.poll();
    assert!(
        matches!(idle, SessionOutput::Timeout(at) if at > pair.now + Duration::from_secs(3_000))
    );
    pair.session
        .handle_timeout(pair.now + Duration::from_secs(1));
    pair.session.join(pair.now, None);
}

/// What the session hands out until it first asks for a timeout, which
/// it returns too: whatever a close sends comes before it, at one instant.
fn until_timeout(session: &mut Session) -> (Vec<SessionOutput>, Instant) {
    let mut outputs = Vec::new();
    loop {
        match session.poll() {
            SessionOutput::Timeout(at) => return (outputs, at),
            output => outputs.push(output),
        }
    }
}

/// A DTLS record of content type alert (RFC 6347 §4.1, RFC 5246 §6.2.1:
/// 21), whose encrypted body is the `close_notify`.
fn is_dtls_alert(payload: &[u8]) -> bool {
    payload.first() == Some(&21)
}

/// The SSRC of an SRTCP BYE (RFC 3550 §6.6: packet type 203, the first
/// SSRC in the clear header, RFC 3711 §3.4), else `None`.
fn bye_ssrc(payload: &[u8]) -> Option<u32> {
    (payload.len() >= 8 && payload[0] >> 6 == 2 && payload[1] == 203)
        .then(|| u32::from_be_bytes(payload[4..8].try_into().unwrap()))
}

/// The datagrams among `outputs`.
fn transmitted(outputs: &[SessionOutput]) -> Vec<&[u8]> {
    outputs
        .iter()
        .filter_map(|output| match output {
            SessionOutput::Transmit { payload, .. } => Some(payload.as_slice()),
            SessionOutput::Event(_) | SessionOutput::Uplink(_) | SessionOutput::Timeout(_) => None,
        })
        .collect()
}

#[test]
fn rfc6347_4_2_7_and_rfc3550_6_6_close_sends_close_notify_and_bye_before_closed() {
    let (mut pair, answer) = Pair::new(h264(None));
    pair.connect(&answer);
    let mut normalizer = normalizer();
    let mut seq = 0;
    for packet in packets(&mut normalizer, &mut seq, 90_000, true, 500, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    pair.drain();
    pair.run_until(|p| !p.viewer.packets().is_empty(), 300, "the keyframe");
    let ssrc = *pair.viewer.packets()[0].header.ssrc;
    // A keyframe request still inside the engine when the close comes:
    // the viewer's PLI goes out on its next timeout, and the session takes
    // it in without being drained.
    pair.viewer.request_keyframe(&mut pair.to_daemon);
    while pair.to_daemon.is_empty() {
        pair.now += Duration::from_millis(1);
        pair.viewer.timeout(pair.now, &mut pair.to_daemon);
    }
    for datagram in std::mem::take(&mut pair.to_daemon) {
        pair.session.handle_datagram(
            pair.now,
            Transport::Udp,
            datagram.source,
            datagram.destination,
            &datagram.payload,
        );
    }
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    let logs = tracing::subscriber::set_default(subscriber);
    pair.session
        .close(pair.now, "session_closed", "unsubscribed".into());
    let (outputs, idle) = until_timeout(&mut pair.session);
    drop(logs);
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    // The close output first, then the final state and `closed`, without
    // the clock moving; the engine's pending keyframe request is dropped.
    assert!(
        !outputs.contains(&SessionOutput::Event(SessionEvent::KeyframeRequest)),
        "{outputs:?}"
    );
    let datagrams = transmitted(&outputs);
    assert_eq!(datagrams.len(), outputs.len() - 2, "{outputs:?}");
    assert_eq!(
        outputs[outputs.len() - 2..],
        [
            SessionOutput::Event(SessionEvent::State {
                ice: "closed",
                dtls: "closed"
            }),
            SessionOutput::Event(SessionEvent::Closed {
                code: "session_closed",
                message: "unsubscribed".into()
            }),
        ]
    );
    assert!(idle > pair.now + Duration::from_secs(3_000));
    assert_eq!(
        datagrams.iter().filter(|d| is_dtls_alert(d)).count(),
        1,
        "{outputs:?}"
    );
    assert!(
        datagrams.iter().any(|d| bye_ssrc(d) == Some(ssrc)),
        "a BYE for {ssrc}: {outputs:?}"
    );
    assert!(
        logged(&logs, "close output queued", "drained=true"),
        "{logs}"
    );
    // The viewer reads the alert as the end of the transport.
    assert!(!pair.viewer.is_closed());
    for datagram in &datagrams {
        pair.viewer.receive(
            pair.now,
            DAEMON.parse().unwrap(),
            datagram,
            &mut pair.to_daemon,
        );
    }
    assert!(pair.viewer.is_closed());
}

#[test]
fn rfc6347_4_2_7_a_close_after_consent_loss_sends_close_notify_without_waiting() {
    let (mut pair, answer) = Pair::new(h264(None));
    pair.connect(&answer);
    // The path is stuck: nothing the session sends arrives, nothing comes
    // back, until consent is lost (RFC 7675 §5.1).
    for _ in 0..600 {
        if pair.session.state() == State::Disconnected {
            break;
        }
        pair.now += Duration::from_millis(100);
        pair.session.handle_timeout(pair.now);
        pair.drain();
        pair.to_viewer.clear();
    }
    assert_eq!(pair.session.state(), State::Disconnected);
    pair.session
        .close(pair.now, "session_closed", "unsubscribed".into());
    let (outputs, idle) = until_timeout(&mut pair.session);
    // Handed out at once, then `closed`: the close waits for nobody.
    assert!(
        transmitted(&outputs).iter().any(|d| is_dtls_alert(d)),
        "{outputs:?}"
    );
    assert_eq!(
        outputs.last(),
        Some(&SessionOutput::Event(SessionEvent::Closed {
            code: "session_closed",
            message: "unsubscribed".into()
        }))
    );
    assert!(idle > pair.now + Duration::from_secs(3_000));
}

#[test]
fn rfc6347_4_2_7_a_close_before_the_handshake_sends_nothing_and_closes_at_once() {
    let (mut pair, _) = Pair::new(h264(None));
    pair.session
        .close(pair.now, "session_closed", "early".into());
    let (outputs, _) = until_timeout(&mut pair.session);
    assert!(transmitted(&outputs).is_empty(), "{outputs:?}");
    assert_eq!(
        outputs.last(),
        Some(&SessionOutput::Event(SessionEvent::Closed {
            code: "session_closed",
            message: "early".into()
        }))
    );
}

#[test]
fn no_connection_within_the_deadline_is_ice_failed() {
    let (mut pair, _) = Pair::new(h264(None));
    // Never apply the answer: the viewer stays silent.
    let deadline = pair.now + SessionLimits::default().connect_timeout;
    assert!(pair.session_timeout.is_some_and(|at| at <= deadline));
    pair.session
        .handle_timeout(deadline - Duration::from_millis(1));
    pair.drain();
    assert!(pair.closed_code().is_none());
    pair.session.handle_timeout(deadline);
    pair.drain();
    assert_eq!(pair.closed_code(), Some("ice_failed"));
    // A candidate before the answer moves the state along.
    let (mut pair, _) = Pair::new(h264(None));
    pair.session.add_remote_candidate(
        pair.now,
        "candidate:1 1 udp 2130706431 192.0.2.21 40001 typ host",
    );
    assert_eq!(pair.session.state(), State::Connecting);
    // Garbage on the socket is counted, not fatal.
    pair.session.handle_datagram(
        pair.now,
        Transport::Udp,
        BROWSER.parse().unwrap(),
        DAEMON.parse().unwrap(),
        &[0xff; 3],
    );
    assert_eq!(pair.session.stats().bad_datagrams, 1);
}

/// Remote candidate addresses the session refuses, one per class and
/// family: unspecified, loopback, link-local, multicast, broadcast and
/// IPv4-mapped.
const REFUSED: [&str; 10] = [
    "0.0.0.0",
    "127.0.0.1",
    "169.254.1.1",
    "224.0.0.251",
    "255.255.255.255",
    "::",
    "::1",
    "fe80::1",
    "ff02::fb",
    "::ffff:127.0.0.1",
];

/// A request with an IPv6 host candidate next to the IPv4 ones, so remote
/// candidates of both families pair (RFC 8445 §6.1.2.2).
fn dual_stack_request(offer: &str) -> SessionRequest {
    let mut request = request(offer, h264(None));
    request
        .candidates
        .push("[2001:db8::10]:18556".parse().unwrap());
    request
}

/// Advances the session alone, 10 ms at a time for `millis`, and returns
/// where it sent to; nothing reaches the viewer.
fn destinations(pair: &mut Pair, millis: u64) -> BTreeSet<SocketAddr> {
    let end = pair.now + Duration::from_millis(millis);
    let mut sent = BTreeSet::new();
    while pair.now < end {
        pair.now += Duration::from_millis(10);
        pair.session.handle_timeout(pair.now);
        pair.drain();
        sent.extend(pair.to_viewer.drain(..).map(|(_, _, to, _)| to));
    }
    sent
}

/// Whether the session sent anything to `ip`, IPv4-mapped or not.
fn sent_to(sent: &BTreeSet<SocketAddr>, ip: &str) -> bool {
    let ip = ip.parse::<IpAddr>().unwrap().to_canonical();
    sent.iter().any(|to| to.ip().to_canonical() == ip)
}

#[test]
fn rfc8445_6_1_2_2_remote_candidates_of_refused_address_classes_get_no_checks() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let (mut pair, _) = Pair::with_request(&dual_stack_request(viewer.offer()), viewer, now);
    let before = pair.events.len();
    for (n, ip) in REFUSED.iter().enumerate() {
        pair.session.add_remote_candidate(
            pair.now,
            &format!("candidate:{n} 1 udp 2130706431 {ip} 40001 typ host"),
        );
    }
    // An mDNS one is ignored without a warning (draft-ietf-mmusic-mdns-ice-
    // candidates §3.2.1), as Chrome trickles them routinely.
    pair.session.add_remote_candidate(
        pair.now,
        "candidate:20 1 udp 2130706431 4f2c1a3e-5b6d-4e7f-8a9b-0c1d2e3f4a5b.local 40001 typ host",
    );
    pair.drain();
    assert_eq!(pair.session.state(), State::Gathering, "nothing was taken");
    assert_eq!(pair.events[before..], [], "refusals are not warnings");
    // Private and public candidates of both families are taken.
    let accepted = ["192.168.1.21", "203.0.113.21", "fd00::21", "2001:db8::21"];
    for (n, ip) in accepted.iter().enumerate() {
        pair.session.add_remote_candidate(
            pair.now,
            &format!("candidate:{} 1 udp 2130706431 {ip} 40001 typ host", n + 30),
        );
    }
    assert_eq!(pair.session.state(), State::Connecting);
    let sent = destinations(&mut pair, 3_000);
    for ip in accepted {
        assert!(sent_to(&sent, ip), "{ip} checked: {sent:?}");
    }
    for ip in REFUSED {
        assert!(!sent_to(&sent, ip), "{ip} never checked: {sent:?}");
    }
}

#[test]
fn rfc8445_6_1_2_2_a_daemon_bound_to_loopback_checks_loopback_candidates_alone() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let mut request = request(viewer.offer(), h264(None));
    request.candidates = vec!["127.0.0.1:18556".parse().unwrap()];
    request.tcp_candidates.clear();
    let (mut pair, _) = Pair::with_request(&request, viewer, now);
    pair.session.add_remote_candidate(
        pair.now,
        "candidate:2 1 udp 2130706431 169.254.1.1 40001 typ host",
    );
    assert_eq!(pair.session.state(), State::Gathering);
    pair.session.add_remote_candidate(
        pair.now,
        "candidate:1 1 udp 2130706431 127.0.0.1 40001 typ host",
    );
    assert_eq!(pair.session.state(), State::Connecting);
    let sent = destinations(&mut pair, 3_000);
    assert!(
        sent.contains(&"127.0.0.1:40001".parse().unwrap()),
        "{sent:?}"
    );
    assert!(!sent_to(&sent, "169.254.1.1"), "{sent:?}");
}

#[test]
fn rfc8445_6_1_2_2_the_offers_candidates_pass_the_same_policy() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let own = viewer
        .offer()
        .lines()
        .find(|line| line.starts_with("a=candidate:"))
        .expect("the viewer's candidate")
        .to_owned();
    let mut extra = vec![own.clone()];
    for (n, ip) in REFUSED.iter().enumerate() {
        extra.push(format!(
            "a=candidate:{n} 1 udp 2130706431 {ip} 40001 typ host"
        ));
    }
    extra.push("a=candidate:20 1 UDP 2130706431 viewer.local 40001 typ host".into());
    extra.push("a=candidate:21 1 udp 2130706431 192.168.1.22 40001 typ host".into());
    extra.push("a=candidate:22 1 udp 2130706431 2001:db8::22 40001 typ host".into());
    let offer = viewer.offer().replacen(&own, &extra.join("\r\n"), 1);
    let (mut pair, _) = Pair::with_request(&dual_stack_request(&offer), viewer, now);
    assert_eq!(pair.session.state(), State::Gathering);
    assert!(
        !pair
            .events
            .iter()
            .any(|e| matches!(e, SessionEvent::Warning { .. })),
        "{:?}",
        pair.events
    );
    let sent = destinations(&mut pair, 3_000);
    assert!(sent.contains(&BROWSER.parse().unwrap()), "{sent:?}");
    assert!(sent_to(&sent, "192.168.1.22"), "{sent:?}");
    assert!(sent_to(&sent, "2001:db8::22"), "{sent:?}");
    for ip in REFUSED {
        assert!(!sent_to(&sent, ip), "{ip} never checked: {sent:?}");
    }

    // A malformed one in the offer is a warning, as a trickled one is.
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = viewer.offer().replacen(
        "\r\na=candidate:",
        "\r\na=candidate:garbage\r\na=candidate:",
        1,
    );
    let (pair, _) = Pair::with_request(&dual_stack_request(&offer), viewer, now);
    assert!(
        pair.events.iter().any(|e| matches!(
            e,
            SessionEvent::Warning {
                code: "invalid_candidate",
                ..
            }
        )),
        "{:?}",
        pair.events
    );
}

#[test]
fn an_unusable_host_address_is_refused_not_answered() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let mut request = request(viewer.offer(), h264(None));
    request.tcp_candidates = vec!["0.0.0.0:18557".parse().unwrap()];
    let (_session, answer) = Session::answer(&request, now).expect("an answer");
    assert!(!answer.contains("tcptype passive"), "{answer}");
    assert!(answer.contains("192.0.2.10 18556 typ host"), "{answer}");
}

#[test]
fn a_viewer_behind_a_udp_block_connects_over_passive_ice_tcp_rfc_6544() {
    let (mut pair, answer) = Pair::new_tcp(h264(None));
    let tcp: SocketAddr = DAEMON_TCP.parse().unwrap();
    assert!(
        answer.contains(&format!(
            "{} {} typ host tcptype passive",
            tcp.ip(),
            tcp.port()
        )),
        "{answer}"
    );
    pair.connect(&answer);
    // The only pair the viewer can use is TCP: every daemon datagram went
    // over it.
    assert!(pair.viewer.is_connected());
    assert_eq!(pair.sent.0, 0, "nothing over UDP");
    assert!(pair.sent.1 > 0);
}

#[test]
fn rfc8445_5_1_1_2_a_viewer_connects_through_the_relay_candidate_alone() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let mut request = request(viewer.offer(), h264(None));
    request.candidates.clear();
    request.tcp_candidates.clear();
    let (mut pair, answer) = Pair::with_request(&request, viewer, now);
    let relayed: SocketAddr = "203.0.113.1:49153".parse().unwrap();
    let local: SocketAddr = DAEMON.parse().unwrap();
    let line = pair
        .session
        .add_relay_candidate(now, relayed, local)
        .expect("a relay candidate");
    // RFC 8839 §5.1, with str0m's priority for a UDP relay (type
    // preference 2, as libwebrtc) and its related address withheld.
    assert!(
        line.contains(" 1 udp 37748479 203.0.113.1 49153 typ relay raddr 0.0.0.0 rport 0"),
        "{line}"
    );
    // RFC 8445 §5.1.3: a second one at the same address ranks lower.
    assert_eq!(pair.session.add_relay_candidate(now, relayed, local), None);
    let unspecified = "0.0.0.0:49154".parse().unwrap();
    assert_eq!(
        pair.session.add_relay_candidate(now, unspecified, local),
        None
    );
    pair.viewer
        .accept_answer(&answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.viewer.add_remote_candidate(&line, &mut pair.to_daemon);
    pair.run_until(
        |p| p.session.state() == State::Connected && p.viewer.is_connected(),
        5_000,
        "connected through the relay",
    );
    assert!(pair.sent.0 > 0);
    assert_eq!(
        pair.sources.into_iter().collect::<Vec<_>>(),
        [relayed],
        "everything left the relay candidate"
    );
    pair.session.close(now, "session_closed", "done".into());
    assert_eq!(
        pair.session
            .add_relay_candidate(now, "203.0.113.1:49155".parse().unwrap(), local),
        None,
        "closed"
    );
}

/// A G.711 packet of 20 ms (160 samples at 8 kHz) of `epoch`.
fn audio_packet(seq: u16, ts: u32, epoch: u32, arrival: Instant) -> MediaPacket {
    MediaPacket {
        arrival,
        rtp: RtpHeaderFields {
            pt: 0,
            seq,
            ts,
            marker: false,
            ssrc: 2,
        },
        frame_start: true,
        keyframe_start: false,
        epoch,
        lateness: Duration::ZERO,
        payload: Arc::from(&[0xff_u8; 160][..]),
    }
}

#[test]
fn pcmu_audio_is_cut_through_in_one_sync_group_with_video() {
    let (mut pair, answer) = Pair::with_audio(h264(None), Arc::new(Codec::Pcmu));
    // RFC 8830 §2 and RFC 3550 §6.5.1: one stream id and one CNAME, so the
    // browser plays both tracks in one synchronized stream.
    let streams: BTreeSet<&str> = answer
        .lines()
        .filter_map(|line| line.strip_prefix("a=msid:"))
        .filter_map(|msid| msid.split(' ').next())
        .collect();
    assert_eq!(streams.len(), 1, "{answer}");
    let cnames: BTreeSet<&str> = answer
        .lines()
        .filter_map(|line| line.split_once(" cname:").map(|(_, cname)| cname))
        .collect();
    assert_eq!(cnames.len(), 1, "{answer}");
    assert!(answer.contains("a=rtpmap:0 PCMU/8000"), "{answer}");
    assert!(
        section(&answer, "audio").contains(&"a=sendonly"),
        "{answer}"
    );

    // Nothing goes out before the session connects.
    let early = audio_packet(1, 1_000, 0, pair.now);
    pair.session.write_audio(pair.now, &early, pair.now);
    assert_eq!(pair.session.stats().audio_dropped, 1);
    pair.connect(&answer);
    assert_eq!(pair.viewer.audio_direction(), Some(Direction::RecvOnly));

    let mut seq = 2;
    for i in 0..50_u32 {
        let packet = audio_packet(seq, 1_160 + i * 160, 0, pair.now);
        pair.session.write_audio(pair.now, &packet, pair.now);
        seq += 1;
    }
    // Exactly at the bounds is still live: max_packet_age old, and
    // max_ingest_lateness late.
    let limits = SessionLimits::default();
    let at_age = audio_packet(seq, 1_160 + 50 * 160, 0, pair.now - limits.max_packet_age);
    pair.session.write_audio(pair.now, &at_age, pair.now);
    let mut at_lateness = audio_packet(seq + 1, 1_160 + 51 * 160, 0, pair.now);
    at_lateness.lateness = limits.max_ingest_lateness;
    pair.session.write_audio(pair.now, &at_lateness, pair.now);
    seq += 2;
    // Too old, and late after an ingest stall: dropped, never queued.
    let old = audio_packet(seq, 99_000, 0, pair.now - Duration::from_secs(1));
    pair.session.write_audio(pair.now, &old, pair.now);
    let mut late = audio_packet(seq, 99_160, 0, pair.now);
    late.lateness = Duration::from_millis(300);
    pair.session.write_audio(pair.now, &late, pair.now);
    // A reconnect: the camera's clock restarts, the session's continues.
    pair.now += Duration::from_millis(20);
    for i in 0..10_u32 {
        let packet = audio_packet(seq, 7 + i * 160, 1, pair.now);
        pair.session.write_audio(pair.now, &packet, pair.now);
        seq += 1;
    }
    pair.drain();
    pair.run_until(|p| p.viewer.audio_packets().len() >= 62, 500, "audio");

    let stats = pair.session.stats();
    assert_eq!((stats.audio_packets, stats.audio_dropped), (62, 3));
    assert_eq!(stats.audio_bytes, 62 * 160);
    let received = pair.viewer.audio_packets();
    assert!(received.iter().all(|p| *p.header.payload_type == 0));
    for (i, packet) in received.iter().enumerate() {
        assert_eq!(*packet.seq_no, i as u64, "one sequence space from zero");
    }
    let steps: Vec<u32> = received
        .windows(2)
        .map(|w| w[1].header.timestamp.wrapping_sub(w[0].header.timestamp))
        .collect();
    assert!(steps[..51].iter().all(|step| *step == 160), "{steps:?}");
    assert!(
        steps[51] > 0 && steps[51] <= 8_000,
        "the epoch continues the clock: {}",
        steps[51]
    );
    assert!(steps[52..].iter().all(|step| *step == 160), "{steps:?}");
    assert!(pair.viewer.packets().is_empty(), "no video was written");
}

/// RFC 3550 §5.1 and §6.4.1: a reconnect's new epoch continues each
/// session timestamp by the capture time that passed, however long the
/// camera was gone, so the timestamps keep one line with the capture
/// times the Sender Reports carry. Advanced by the packets' arrival, and
/// by at most 1 s, the line stepped at every reconnect longer than that,
/// and Chrome, which fits each stream's Sender Reports by regression,
/// played audio and video up to 150 ms apart for 20 s after a camera
/// came back 1.1 s later (found 2026-10-07 by the browser test's
/// `reconnect` case).
#[test]
fn rfc3550_5_1_a_new_epoch_continues_the_timestamps_by_the_capture_time() {
    let (mut pair, answer) = Pair::with_audio(h264(None), Arc::new(Codec::Pcmu));
    pair.connect(&answer);
    let mut normalizer = normalizer();
    let mut seq = 1000;
    let start = pair.now;
    // Epoch 0: a keyframe and a packet of audio, captured 5 ms before
    // they arrive.
    let captured = start - Duration::from_millis(5);
    for packet in packets(&mut normalizer, &mut seq, 90_000, true, 300, start) {
        pair.session.write_video(pair.now, &packet, captured);
    }
    let audio = audio_packet(1, 8_000, 0, start);
    pair.session.write_audio(pair.now, &audio, captured);
    // The camera comes back 2.5 s later on a new timeline, the packets
    // captured 40 ms before they arrive: 2.465 s of capture time passed.
    pair.now = start + Duration::from_millis(2_500);
    let captured = pair.now - Duration::from_millis(40);
    let mut video = packets(&mut normalizer, &mut seq, 5_000, true, 300, pair.now);
    for packet in &mut video {
        packet.epoch = 1;
        pair.session.write_video(pair.now, packet, captured);
    }
    let audio = audio_packet(2, 77, 1, pair.now);
    pair.session.write_audio(pair.now, &audio, captured);
    pair.drain();
    let written = pair.session.stats().packets;
    pair.run_until(
        |p| p.viewer.packets().len() as u64 >= written && p.viewer.audio_packets().len() >= 2,
        500,
        "both epochs",
    );
    let video = pair.viewer.packets();
    let (first, last) = (video.first().unwrap(), video.last().unwrap());
    assert_eq!(
        last.header.timestamp.wrapping_sub(first.header.timestamp),
        2_465 * 90,
        "video"
    );
    let audio = pair.viewer.audio_packets();
    assert_eq!(
        audio[1]
            .header
            .timestamp
            .wrapping_sub(audio[0].header.timestamp),
        2_465 * 8,
        "audio"
    );
}

/// The SSRC of an RTP datagram as the engine sent it (RFC 3550 §5.1; in
/// the clear under SRTP, RFC 3711 §3.1), or `None` for anything else.
fn rtp_ssrc(datagram: &[u8]) -> Option<u32> {
    let rtp = (128..=191).contains(datagram.first()?) && !(192..=223).contains(datagram.get(1)?);
    let ssrc = u32::from_be_bytes(datagram.get(8..12)?.try_into().ok()?);
    rtp.then_some(ssrc)
}

#[test]
fn rfc8837_5_the_audio_tracks_rtp_is_marked_audio_and_nothing_else() {
    let (mut pair, answer) = Pair::with_audio(h264(None), Arc::new(Codec::Pcmu));
    pair.connect(&answer);
    let mut normalizer = normalizer();
    let mut seq = 1000;
    for packet in packets(&mut normalizer, &mut seq, 93_000, true, 1_500, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    for i in 0..10_u32 {
        let packet = audio_packet(1 + i as u16, 1_000 + i * 160, 0, pair.now);
        pair.session.write_audio(pair.now, &packet, pair.now);
    }
    pair.drain();
    pair.run_until(
        |p| p.viewer.audio_packets().len() >= 10 && !p.viewer.packets().is_empty(),
        500,
        "audio and video",
    );
    let audio = *pair.viewer.audio_packets()[0].header.ssrc;
    let video = *pair.viewer.packets()[0].header.ssrc;
    let marked: Vec<Option<u32>> = pair
        .marked
        .iter()
        .filter(|(audio, _)| *audio)
        .map(|(_, datagram)| rtp_ssrc(datagram))
        .collect();
    assert!(marked.len() >= 10, "{} marked", marked.len());
    assert!(marked.iter().all(|ssrc| *ssrc == Some(audio)), "{marked:?}");
    let unmarked: Vec<Option<u32>> = pair
        .marked
        .iter()
        .filter(|(audio, _)| !*audio)
        .map(|(_, datagram)| rtp_ssrc(datagram))
        .collect();
    assert!(unmarked.contains(&Some(video)), "video goes unmarked");
    assert!(unmarked.contains(&None), "so do STUN, DTLS and RTCP");
    assert!(!unmarked.contains(&Some(audio)), "{unmarked:?}");
}

#[test]
fn playout_delay_0_0_only_without_audio_so_the_browser_can_hold_video_for_lip_sync() {
    // With audio, playout-delay max 0 caps the browser's lip-sync hold, and
    // Chrome and Safari played audio 113–156 ms behind video (2026-10-01).
    let zero = Some(str0m::media::MediaTime::new(
        0,
        str0m::media::Frequency::HUNDREDTHS,
    ));
    for (audio, expected) in [(None, zero), (Some(Codec::Pcmu), None)] {
        let video = h264(Some([0x42, 0xc0, 0x28]));
        let (mut pair, answer) = match audio {
            None => Pair::new(video),
            Some(codec) => Pair::with_audio(video, Arc::new(codec)),
        };
        pair.connect(&answer);
        let mut normalizer = normalizer();
        let mut seq = 1000;
        for packet in packets(&mut normalizer, &mut seq, 90_000, true, 1_500, pair.now) {
            pair.session.write_video(pair.now, &packet, pair.now);
        }
        pair.drain();
        pair.run_until(|p| !p.viewer.packets().is_empty(), 500, "video");
        for packet in pair.viewer.packets() {
            assert_eq!(packet.header.ext_vals.play_delay_min, expected);
            assert_eq!(packet.header.ext_vals.play_delay_max, expected);
        }
    }
}

#[test]
fn stream_audio_without_an_offered_audio_line_warns_and_plays_video() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let mut request = request(viewer.offer(), h264(None));
    request.audio = Some(Arc::new(Codec::Pcmu));
    let (mut session, answer) = Session::answer(&request, now).expect("video still answered");
    assert!(!answer.contains("m=audio"), "{answer}");
    assert_eq!(warnings(&mut session), ["audio_codec_unsupported"]);
    session.write_audio(now, &audio_packet(1, 160, 0, now), now);
    assert_eq!(session.stats().audio_dropped, 1);
}

/// Chrome's audio codec lines, reconstructed from libwebrtc's default
/// list (Safari's, also libwebrtc, are the same); captured offers replace
/// them as they are taken with the dev viewer's *Copy offer SDP*.
const CHROME_AUDIO: &str = include_str!("fixtures/chrome-audio-codecs.sdp");

/// Firefox's audio codec lines, reconstructed from its default list.
const FIREFOX_AUDIO: &str = include_str!("fixtures/firefox-audio-codecs.sdp");

/// Firefox's H.264 lines, reconstructed likewise: its payload types do not
/// clash with its audio ones, the headless viewer's do.
const FIREFOX_VIDEO: &str = "a=rtpmap:126 H264/90000\na=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\na=rtpmap:127 rtx/90000\na=fmtp:127 apt=126\na=rtpmap:97 H264/90000\na=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1\na=rtpmap:98 rtx/90000\na=fmtp:98 apt=97\n";

/// The lines of the m-section of `kind` (`audio`, `video`) in `sdp`, its
/// `m=` line first.
fn section<'a>(sdp: &'a str, kind: &str) -> Vec<&'a str> {
    let mut lines = Vec::new();
    for line in sdp.lines() {
        if line.starts_with("m=") {
            if !lines.is_empty() {
                break;
            }
            if !line.starts_with(&format!("m={kind} ")) {
                continue;
            }
        }
        if line.starts_with("m=") || !lines.is_empty() {
            lines.push(line);
        }
    }
    lines
}

/// The payload types an m-section's `m=` line lists.
fn payload_types(section: &[&str]) -> Vec<String> {
    section[0].split(' ').skip(3).map(str::to_owned).collect()
}

/// Asserts that `answer` answers the offer's audio m-line `inactive`
/// (RFC 8829 §5.3.1, RFC 3264 §6.1) the way browsers accept it: a non-zero
/// port, the offer's mid, still in the BUNDLE group (RFC 9143), payload
/// types the offer listed, and no SSRC, so nothing is ever sent on it.
fn assert_inactive_audio(offer: &str, answer: &str) {
    let offered = section(offer, "audio");
    let answered = section(answer, "audio");
    assert!(!answered.is_empty(), "an audio m-line: {answer}");
    let port = answered[0].split(' ').nth(1).unwrap();
    assert_ne!(port, "0", "not rejected: {answer}");
    assert!(answered.contains(&"a=inactive"), "{answer}");
    for direction in ["a=sendonly", "a=recvonly", "a=sendrecv"] {
        assert!(!answered.contains(&direction), "{answer}");
    }
    let mid = offered
        .iter()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .unwrap();
    assert!(
        answered.contains(&format!("a=mid:{mid}").as_str()),
        "{answer}"
    );
    let bundle = answer
        .lines()
        .find_map(|line| line.strip_prefix("a=group:BUNDLE "))
        .unwrap();
    assert!(bundle.split(' ').any(|m| m == mid), "{answer}");
    let pts = payload_types(&answered);
    assert!(!pts.is_empty(), "{answer}");
    let offered_pts = payload_types(&offered);
    assert!(
        pts.iter().all(|pt| offered_pts.contains(pt)),
        "{pts:?} from {offered_pts:?}: {answer}"
    );
    assert!(
        !answered.iter().any(|line| line.starts_with("a=ssrc:")),
        "{answer}"
    );
}

/// The warnings an engine queued at open, with their messages.
fn warning_messages(engine: &mut dyn SessionEngine) -> Vec<(&'static str, String)> {
    let mut found = Vec::new();
    loop {
        match engine.poll() {
            SessionOutput::Event(SessionEvent::Warning { code, message }) => {
                found.push((code, message));
            }
            SessionOutput::Timeout(_) => return found,
            _ => {}
        }
    }
}

#[test]
fn rfc8829_5_3_1_without_stream_audio_the_audio_m_line_is_answered_inactive() {
    // No audio track, or `audio: "off"`: the session gets no audio and says
    // nothing (the worker warns for a missing track, `off` is no warning).
    let now = SystemClock.now();
    for codecs in [
        None,
        Some((CHROME_AUDIO, None)),
        Some((FIREFOX_AUDIO, Some(FIREFOX_VIDEO))),
    ] {
        lotse_webrtc::install_crypto_provider();
        let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
        let offer = codecs.map_or_else(
            || viewer.offer().to_owned(),
            |(audio, video)| {
                let offer = with_audio_codecs(viewer.offer(), audio);
                // A browser's payload types are unique across its bundled
                // m-lines (RFC 9143 §7.5): Firefox's audio ones need its
                // video ones.
                video.map_or_else(|| offer.clone(), |video| with_video_codecs(&offer, video))
            },
        );
        let (mut session, answer) =
            Session::answer(&request(&offer, h264(None)), now).expect("answered");
        assert_inactive_audio(&offer, &answer);
        assert!(warnings(&mut session).is_empty(), "{answer}");
        // Video is answered as before.
        assert!(
            section(&answer, "video").contains(&"a=sendonly"),
            "{answer}"
        );
    }
}

#[test]
fn rfc3264_6_1_stream_audio_the_daemon_cannot_carry_is_answered_inactive_with_a_warning() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
    let unsupported = Codec::Unsupported {
        kind: Kind::Audio,
        name: "l16".into(),
    };
    // AAC when no transcoder runs: the request carries the native codec.
    let aac = Codec::AacLc {
        sample_rate: 16_000,
        channels: 1,
        config: Bytes::new(),
    };
    for codec in [unsupported, aac] {
        let mut request = request(viewer.offer(), h264(None));
        request.audio = Some(Arc::new(codec.clone()));
        let (mut session, answer) = Session::answer(&request, now).expect("answered");
        assert_inactive_audio(viewer.offer(), &answer);
        let found = warning_messages(&mut session);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "audio_codec_unsupported");
        assert!(
            found[0].1.contains(codec.name()) && found[0].1.contains("answered inactive"),
            "{found:?}"
        );
    }
}

#[test]
fn rfc3264_6_1_an_offer_without_the_stream_audio_codec_gets_inactive_audio_and_a_warning() {
    // A G.722 camera and an offer of Opus and PCMU only.
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = with_audio_codecs(
        viewer.offer(),
        "a=rtpmap:111 opus/48000/2\na=rtpmap:0 PCMU/8000\n",
    );
    let mut request = request(&offer, h264(None));
    request.audio = Some(Arc::new(Codec::G722));
    let (mut session, answer) = Session::answer(&request, now).expect("answered");
    assert_inactive_audio(&offer, &answer);
    let found = warning_messages(&mut session);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "audio_codec_unsupported");
    assert!(found[0].1.contains("video only"), "{found:?}");
    session.write_audio(now, &audio_packet(1, 160, 0, now), now);
    assert_eq!(session.stats().audio_dropped, 1);
}

#[test]
fn rfc3264_6_an_audio_m_line_without_a_known_codec_is_still_rejected() {
    // Nothing the engine knows to name in an inactive answer: port 0. (A
    // number the video m-line leaves free: RFC 9143 §9.1.1.)
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = with_audio_codecs(viewer.offer(), "a=rtpmap:104 iLBC/8000\n");
    let (mut session, answer) =
        Session::answer(&request(&offer, h264(None)), now).expect("answered");
    assert!(
        section(&answer, "audio")[0].starts_with("m=audio 0 "),
        "{answer}"
    );
    assert!(warnings(&mut session).is_empty());
    // An offer that names the stream's codec in a form the engine does not
    // match (two-channel PCMU): rejected too, and the stream audio warns.
    let offer = with_audio_codecs(viewer.offer(), "a=rtpmap:0 PCMU/8000/2\n");
    let mut request = request(&offer, h264(None));
    request.audio = Some(Arc::new(Codec::Pcmu));
    let (mut session, answer) = Session::answer(&request, now).expect("answered");
    assert!(
        section(&answer, "audio")[0].starts_with("m=audio 0 "),
        "{answer}"
    );
    assert_eq!(warnings(&mut session), ["audio_codec_unsupported"]);
}

#[test]
fn rfc8829_5_3_1_each_carried_audio_codec_is_answered_alone_and_sendonly() {
    let now = SystemClock.now();
    for (codec, encoding) in [
        (Codec::Opus { channels: 2 }, "opus/48000/2"),
        (Codec::Pcmu, "PCMU/8000"),
        (Codec::Pcma, "PCMA/8000"),
        (Codec::G722, "G722/8000"),
    ] {
        lotse_webrtc::install_crypto_provider();
        let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
        let mut request = request(viewer.offer(), h264(None));
        request.audio = Some(Arc::new(codec));
        let (mut session, answer) = Session::answer(&request, now).expect("answered");
        let audio = section(&answer, "audio");
        assert!(audio.contains(&"a=sendonly"), "{answer}");
        let pts = payload_types(&audio);
        assert_eq!(pts.len(), 1, "{answer}");
        assert!(
            audio.contains(&format!("a=rtpmap:{} {encoding}", pts[0]).as_str()),
            "{answer}"
        );
        assert!(warnings(&mut session).is_empty(), "{answer}");
    }
}

#[test]
fn rfc8829_5_3_1_the_viewer_plays_video_beside_an_inactive_audio_m_line() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
    let request = request(viewer.offer(), h264(None));
    let (mut pair, answer) = Pair::with_request(&request, viewer, now);
    assert_eq!(pair.viewer.audio_direction(), None, "before the answer");
    pair.connect(&answer);
    assert_eq!(pair.viewer.audio_direction(), Some(Direction::Inactive));
    let mut normalizer = normalizer();
    let mut frame = 0;
    for packet in packets(&mut normalizer, &mut frame, 0, true, 3_000, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    // Audio handed in anyway goes nowhere.
    pair.session
        .write_audio(pair.now, &audio_packet(1, 160, 0, pair.now), pair.now);
    pair.drain();
    pair.run_until(|p| !p.viewer.packets().is_empty(), 500, "video");
    for _ in 0..50 {
        pair.step();
    }
    assert!(pair.viewer.audio_packets().is_empty());
    assert_eq!(pair.session.stats().audio_dropped, 1);
}

/// The audio m-sections of `sdp`, in order, each with its `m=` line
/// first.
fn audio_sections(sdp: &str) -> Vec<Vec<&str>> {
    let mut sections: Vec<Vec<&str>> = Vec::new();
    let mut inside = false;
    for line in sdp.lines() {
        if line.starts_with("m=") {
            inside = line.starts_with("m=audio ");
            if inside {
                sections.push(Vec::new());
            }
        }
        if inside {
            sections.last_mut().unwrap().push(line);
        }
    }
    sections
}

/// The encoding an m-section names first in its format list: the codec
/// the offerer sends with on it (RFC 3264 §6.1).
fn first_encoding<'a>(section: &[&'a str]) -> &'a str {
    let pt = &payload_types(section)[0];
    section
        .iter()
        .find_map(|line| line.strip_prefix(&format!("a=rtpmap:{pt} ")))
        .unwrap()
}

/// The fixture matrix, {dedicated talk-back m-line,
/// `sendrecv` downlink m-line} × {backchannel present, absent}, with a
/// PCMU stream and a PCMA backchannel: talk-back is received only with a
/// backchannel, in its codec first; the downlink plays either way. The
/// request carries no talker, so whether another session talks cannot
/// change the answer.
#[test]
fn rfc8829_5_3_1_talk_back_is_answered_by_offer_shape_and_backchannel() {
    use lotse_testing::viewer::TalkbackOffer;

    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    for (shape, backchannel, downlink, talkback, viewer_downlink, viewer_talkback) in [
        (
            TalkbackOffer::Dedicated,
            Some(Codec::Pcma),
            "a=sendonly",
            "a=recvonly",
            Direction::RecvOnly,
            Direction::SendOnly,
        ),
        (
            TalkbackOffer::Dedicated,
            None,
            "a=sendonly",
            "a=inactive",
            Direction::RecvOnly,
            Direction::Inactive,
        ),
        (
            TalkbackOffer::SendRecv,
            Some(Codec::Pcma),
            "a=sendrecv",
            "a=sendrecv",
            Direction::SendRecv,
            Direction::SendRecv,
        ),
        (
            TalkbackOffer::SendRecv,
            None,
            "a=sendonly",
            "a=sendonly",
            Direction::RecvOnly,
            Direction::RecvOnly,
        ),
    ] {
        let what = format!("{shape:?} with {backchannel:?}");
        let viewer =
            Viewer::new_with_talkback(BROWSER.parse().unwrap(), now, shape).expect("a viewer");
        let mut request = request(viewer.offer(), h264(None));
        request.audio = Some(Arc::new(Codec::Pcmu));
        request.backchannel = backchannel.clone();
        let (mut pair, answer) = Pair::with_request(&request, viewer, now);
        // `session/get` reports the codec the answer named first.
        assert_eq!(
            pair.session.talkback(),
            backchannel.as_ref().map(|_| UplinkCodec::Pcma),
            "{what}"
        );
        let sections = audio_sections(&answer);
        let dedicated = shape == TalkbackOffer::Dedicated;
        assert_eq!(
            sections.len(),
            if dedicated { 2 } else { 1 },
            "{what}: {answer}"
        );
        let (down, up) = (&sections[0], sections.last().unwrap());
        assert!(down.contains(&downlink), "{what}: {answer}");
        assert!(up.contains(&talkback), "{what}: {answer}");
        // The session sends PCMU on the downlink m-line in every case.
        assert!(down.contains(&"a=rtpmap:0 PCMU/8000"), "{what}: {answer}");
        if backchannel.is_some() {
            assert_eq!(first_encoding(up), "PCMA/8000", "{what}: {answer}");
        }
        if dedicated && backchannel.is_none() {
            assert_inactive_audio(
                &request.offer.replacen("m=audio", "m=audiox", 1),
                &answer.replacen("m=audio", "m=audiox", 1),
            );
        }
        // No SSRC on the talk-back m-line: the daemon sends nothing there.
        if dedicated {
            assert!(
                !up.iter().any(|line| line.starts_with("a=ssrc:")),
                "{what}: {answer}"
            );
        }

        pair.connect(&answer);
        assert!(
            !pair
                .events
                .iter()
                .any(|event| matches!(event, SessionEvent::Warning { .. })),
            "{what}: {:?}",
            pair.events
        );
        assert_eq!(
            pair.viewer.audio_direction(),
            Some(viewer_downlink),
            "{what}"
        );
        assert_eq!(
            pair.viewer.talkback_direction(),
            Some(viewer_talkback),
            "{what}"
        );
        for seq in 0..5_u16 {
            let packet = audio_packet(seq, u32::from(seq) * 160, 0, pair.now);
            pair.session.write_audio(pair.now, &packet, pair.now);
        }
        pair.drain();
        pair.run_until(|p| p.viewer.audio_packets().len() >= 5, 500, &what);
        assert!(
            pair.viewer
                .audio_packets()
                .iter()
                .all(|packet| *packet.header.payload_type == 0),
            "{what}"
        );
    }
}

/// A connected pair whose viewer offers talk-back in `shape`, for a PCMU
/// stream and a backchannel of `backchannel`.
fn talkback_pair(
    shape: lotse_testing::viewer::TalkbackOffer,
    backchannel: Option<Codec>,
) -> (Pair, String) {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new_with_talkback(BROWSER.parse().unwrap(), now, shape).expect("a viewer");
    let mut request = request(viewer.offer(), h264(None));
    request.audio = Some(Arc::new(Codec::Pcmu));
    request.backchannel = backchannel;
    let (mut pair, answer) = Pair::with_request(&request, viewer, now);
    pair.connect(&answer);
    (pair, answer)
}

/// Sends `packets` (payload type, payload) on the viewer's talk-back
/// m-line, 20 ms apart, the first with the marker, and moves them.
fn talk(pair: &mut Pair, packets: &[(u8, &[u8])]) {
    for (k, (pt, payload)) in packets.iter().enumerate() {
        let k = k as u16;
        pair.viewer
            .send_talkback(
                pair.now,
                (*pt, 100 + k, 1_000 + u32::from(k) * 160, k == 0),
                payload,
                &mut pair.to_daemon,
            )
            .expect("a talk-back send stream");
        pair.step();
    }
    pair.settle_talkback();
}

impl Pair {
    /// Steps until the datagrams in flight have arrived.
    fn settle_talkback(&mut self) {
        for _ in 0..5 {
            self.step();
        }
    }
}

/// What the viewer sends on the talk-back m-line,
/// on either offer shape, is handed on as uplink packets with the header
/// fields as sent, taken by payload type: the backchannel's PCMA the
/// answer names first, and the stream's PCMU that the m-line lists too
/// (RFC 3264 §6.1, §5.1: the browser may send any listed codec).
#[test]
fn rfc3264_6_1_talk_back_rtp_is_handed_on_by_payload_type_in_any_listed_codec() {
    use lotse_testing::viewer::TalkbackOffer;

    for shape in [TalkbackOffer::Dedicated, TalkbackOffer::SendRecv] {
        let (mut pair, _) = talkback_pair(shape, Some(Codec::Pcma));
        let a_law = [0xd5_u8; 160];
        let mu_law = [0xff_u8; 160];
        talk(&mut pair, &[(8, &a_law), (8, &a_law), (0, &mu_law)]);
        let got: Vec<_> = pair
            .uplink
            .iter()
            .map(|up| {
                (
                    up.codec,
                    up.packet.rtp.pt,
                    up.packet.rtp.seq,
                    up.packet.rtp.ts,
                    up.packet.rtp.marker,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (UplinkCodec::Pcma, 8, 100, 1_000, true),
                (UplinkCodec::Pcma, 8, 101, 1_160, false),
                (UplinkCodec::Pcmu, 0, 102, 1_320, false),
            ],
            "{shape:?}"
        );
        assert_eq!(&pair.uplink[2].packet.payload[..], &mu_law[..]);
        let ssrc = pair.uplink[0].packet.rtp.ssrc;
        assert!(pair.uplink.iter().all(|up| up.packet.rtp.ssrc == ssrc));
        assert!(pair.uplink.iter().all(|up| up.packet.frame_start));
        let stats = pair.session.stats();
        assert_eq!(
            (stats.uplink_packets, stats.uplink_refused),
            (3, 0),
            "{shape:?}"
        );
    }
}

/// An Opus backchannel: talk-back in Opus, whose packets are checked
/// against RFC 6716 §3.4 before they go on; one that breaks it is
/// refused and counted, and the next goes on.
#[test]
fn rfc6716_3_4_an_opus_talk_back_packet_that_is_no_packet_is_refused() {
    use lotse_testing::viewer::TalkbackOffer;

    let (mut pair, _) = talkback_pair(TalkbackOffer::Dedicated, Some(Codec::Opus { channels: 2 }));
    // A CELT 20 ms code 0 packet, a code 1 packet of an odd length (R3),
    // and another good one.
    talk(
        &mut pair,
        &[(111, &[0xf8, 1, 2]), (111, &[0xf9, 1]), (111, &[0xf8, 3])],
    );
    let got: Vec<_> = pair
        .uplink
        .iter()
        .map(|up| (up.codec, up.packet.rtp.seq, up.packet.payload.to_vec()))
        .collect();
    assert_eq!(
        got,
        [
            (UplinkCodec::Opus, 100, vec![0xf8, 1, 2]),
            (UplinkCodec::Opus, 102, vec![0xf8, 3]),
        ]
    );
    let stats = pair.session.stats();
    assert_eq!((stats.uplink_packets, stats.uplink_refused), (2, 1));
}

/// RTP the viewer sends that is no talk-back is refused and counted,
/// never handed on: on a talk-back m-line answered `inactive` (no
/// backchannel; a browser sends on it anyway once it has a track), on a
/// `sendrecv` one answered `sendonly`, and in a payload type of no
/// talk-back codec (the video's) on the talk-back m-line itself.
#[test]
fn rfc3264_6_1_rtp_that_is_no_talk_back_is_refused_and_counted() {
    use lotse_testing::viewer::TalkbackOffer;

    for shape in [TalkbackOffer::Dedicated, TalkbackOffer::SendRecv] {
        let (mut pair, _) = talkback_pair(shape, None);
        talk(&mut pair, &[(0, &[0xff; 160]), (0, &[0xff; 160])]);
        assert!(pair.uplink.is_empty(), "{shape:?}");
        let stats = pair.session.stats();
        assert_eq!(
            (stats.uplink_packets, stats.uplink_refused),
            (0, 2),
            "{shape:?}"
        );
    }
    let (mut pair, answer) = talkback_pair(TalkbackOffer::Dedicated, Some(Codec::Pcma));
    let h264 = section(&answer, "video")
        .iter()
        .find_map(|line| line.strip_prefix("a=rtpmap:")?.strip_suffix(" H264/90000"))
        .unwrap()
        .parse()
        .unwrap();
    talk(&mut pair, &[(h264, &[0x65; 10]), (8, &[0xd5; 160])]);
    assert_eq!(pair.uplink.len(), 1);
    assert_eq!(pair.uplink[0].packet.rtp.seq, 101, "the PCMA one");
    let stats = pair.session.stats();
    assert_eq!((stats.uplink_packets, stats.uplink_refused), (1, 1));
}

#[test]
fn a_capture_time_ahead_of_now_never_zeroes_the_sender_report() {
    // str0m derives a Sender Report's RTP time from the last packet's
    // wallclock and sends RTP time 0 when that lies in its future, which
    // put a stream 15 s off in the browser (2026-09-30). The writers clamp.
    let (mut pair, answer) = Pair::with_audio(h264(None), Arc::new(Codec::Pcmu));
    pair.connect(&answer);
    // Eight seconds of audio, 20 ms apart, each stamped half a second
    // ahead: Sender Reports go out meanwhile.
    let end = pair.now + Duration::from_secs(8);
    let (mut seq, mut ts) = (1_u16, 1_000_000_u32);
    while pair.now < end {
        let ahead = pair.now + Duration::from_millis(500);
        let packet = audio_packet(seq, ts, 0, pair.now);
        pair.session.write_audio(pair.now, &packet, ahead);
        pair.drain();
        (seq, ts) = (seq.wrapping_add(1), ts.wrapping_add(160));
        let next = pair.now + Duration::from_millis(20);
        while pair.now < next {
            pair.step();
        }
    }
    let with_sr = pair
        .viewer
        .audio_packets()
        .iter()
        .rev()
        .find_map(|p| p.last_sender_info)
        .expect("a sender report within six seconds");
    assert!(
        with_sr.rtp_time.numer() >= 1_000_000,
        "the report's RTP time follows the stream: {:?}",
        with_sr.rtp_time
    );
}

/// The write path's allocations once a session is up:
/// the cut-through writer allocates nothing, packet after packet; str0m
/// 0.24 allocates one `Vec` per datagram it sends, the SRTP output of
/// `SrtpContext::protect_rtp` that its `DatagramSend` owns, and more for
/// its RTCP reports. Linking `allocation-counter` makes its allocator this
/// test binary's; it counts the test thread's allocations only.
#[test]
fn the_cut_through_writer_allocates_nothing_and_str0m_one_vec_per_datagram() {
    let (mut pair, answer) = Pair::new(h264(Some([0x42, 0xc0, 0x28])));
    pair.connect(&answer);
    let mut normalizer = normalizer();
    let mut seq = 1000;
    for packet in packets(&mut normalizer, &mut seq, 93_000, true, 1_500, pair.now) {
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    // Ten frames of warm-up, then fifty measured: three packets a frame,
    // written at once, then 33 ms of the engine's pacing and sending.
    let (mut written, mut writing, mut sent, mut sending) = (0, 0, 0, 0);
    for frame in 0..60_u32 {
        let ts = 96_000 + frame * 3_000;
        let batch = packets(&mut normalizer, &mut seq, ts, false, 3_000, pair.now);
        let mut now = pair.now;
        let session = &mut pair.session;
        let writing_now = allocation_counter::measure(|| {
            for packet in &batch {
                session.write_video(now, packet, now);
            }
        });
        let mut datagrams = 0;
        let engine_now = allocation_counter::measure(|| {
            for _ in 0..33 {
                now += Duration::from_millis(1);
                session.handle_timeout(now);
                loop {
                    match session.poll() {
                        SessionOutput::Transmit { .. } => datagrams += 1,
                        SessionOutput::Event(_) | SessionOutput::Uplink(_) => {}
                        SessionOutput::Timeout(_) => break,
                    }
                }
            }
        });
        pair.now = now;
        pair.step();
        if frame >= 10 {
            written += batch.len();
            writing += writing_now.count_total;
            sent += datagrams;
            sending += engine_now.count_total;
        }
    }
    assert_eq!(written, 150);
    assert_eq!(writing, 0, "the writer allocated");
    // At least str0m's one `Vec` per datagram, the media's and its RTCP's;
    // a str0m that sends from a reused buffer fails this, and the bound is
    // then to be tightened.
    assert!(sent >= written, "{sent} datagrams for {written} packets");
    assert!(
        (sent as u64..=2 * sent as u64).contains(&sending),
        "{sending} allocations for {sent} datagrams"
    );
}

/// An H.265 stream of the test parameter sets: Main (profile 1, which
/// conforms to Main 10) or Main 10 (2), level 4.0.
fn h265(profile: u32) -> Arc<Codec> {
    h265_in_tier(profile, false)
}

/// An H.265 stream of `profile`, in the High tier when `high_tier`.
fn h265_in_tier(profile: u32, high_tier: bool) -> Arc<Codec> {
    use lotse_codec::h265::test_data;
    Arc::new(Codec::H265 {
        vps: Some(Bytes::from(test_data::vps_of_tier(high_tier))),
        sps: Some(Bytes::from(test_data::sps_of_tier(
            profile, high_tier, 640, 480,
        ))),
        pps: Some(Bytes::from(test_data::pps())),
    })
}

/// Writes one live H.265 keyframe as the RTSP source publishes it to a
/// connected pair; returns the payload types the viewer received.
fn play_h265_keyframe(pair: &mut Pair) -> Vec<u8> {
    let au = h265_access_unit(true, 3_000, 1);
    let payloads = lotse_codec::h265::packetize(&au, DEFAULT_MAX_PAYLOAD);
    let count = payloads.len();
    for (index, payload) in payloads.iter().enumerate() {
        let packet = MediaPacket {
            arrival: pair.now,
            rtp: RtpHeaderFields {
                pt: 96,
                seq: u16::try_from(index).unwrap(),
                ts: 96_000,
                marker: index + 1 == count,
                ssrc: 1,
            },
            frame_start: index == 0,
            keyframe_start: index == 0,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(payload.as_ref()),
        };
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    let written = pair.session.stats().packets;
    assert_eq!(written, count as u64);
    pair.run_until(
        |p| p.viewer.packets().len() as u64 >= written,
        500,
        "received",
    );
    pair.viewer
        .packets()
        .iter()
        .map(|p| *p.header.payload_type)
        .collect()
}

/// An H.265 access unit in Annex B: VPS, SPS, PPS and an IDR, or one
/// `TRAIL_R` slice, `bytes` long (ITU-T H.265 Table 7-1).
fn h265_access_unit(keyframe: bool, bytes: usize, frame: u8) -> Bytes {
    use lotse_codec::h265::test_data;
    let mut out = Vec::new();
    if keyframe {
        for unit in [test_data::vps(), test_data::sps(640, 480), test_data::pps()] {
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(&unit);
        }
    }
    out.extend_from_slice(&[0, 0, 0, 1]);
    // IDR_W_RADL (19) or TRAIL_R (1), layer 0, temporal id 0.
    out.extend_from_slice(if keyframe {
        &[0x26, 0x01]
    } else {
        &[0x02, 0x01]
    });
    out.extend(std::iter::repeat_n(frame, bytes));
    Bytes::from(out)
}

/// The lines of `answer`'s video m-section naming `codec`: its `rtpmap`
/// and `fmtp` lines by payload type.
fn codec_lines<'a>(answer: &'a str, codec: &str) -> Vec<&'a str> {
    let video = section(answer, "video");
    let pts: Vec<&str> = video
        .iter()
        .filter_map(|line| line.strip_prefix("a=rtpmap:"))
        .filter(|rest| rest.ends_with(&format!(" {codec}/90000")))
        .filter_map(|rest| rest.split(' ').next())
        .collect();
    video
        .into_iter()
        .filter(|line| {
            pts.iter().any(|pt| {
                line.starts_with(&format!("a=rtpmap:{pt} "))
                    || line.starts_with(&format!("a=fmtp:{pt} "))
            })
        })
        .collect()
}

#[test]
fn rfc7798_7_2_2_an_h265_camera_is_answered_in_its_offered_profile_and_plays() {
    // The viewer offers str0m's H.265 entry next to H.264, VP8 and VP9:
    // Main, Main tier, level 6.0.
    let (mut pair, answer) = Pair::new(h265(1));
    assert!(codec_lines(&answer, "H264").is_empty(), "{answer}");
    let lines = codec_lines(&answer, "H265");
    assert_eq!(lines.len(), 2, "{answer}");
    // RFC 7798 §7.2.2: the offered profile and tier, and a level no higher
    // than the offer's.
    let fmtp = lines[1];
    for param in ["profile-id=1", "tier-flag=0", "level-id=180"] {
        assert!(fmtp.contains(param), "{fmtp}");
    }
    let pt: u8 = lines[0]["a=rtpmap:".len()..]
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    pair.viewer
        .accept_answer(&answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.run_until(
        |p| p.session.state() == State::Connected,
        5_000,
        "connected",
    );
    // A cached keyframe and a P frame, packetized per RFC 7798.
    let set = TrackSet::new(TrackLimits::default(), pair.now);
    let mut publisher = set.publisher();
    let track = publisher.declare(Kind::Video, (*h265(1)).clone(), 90_000);
    for i in 0..2_u8 {
        let at = pair.now - Duration::from_millis(100) + Duration::from_millis(33 * u64::from(i));
        assert!(track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(90_000 + i64::from(i) * 3_000),
            wallclock: at,
            arrival: at,
            keyframe: i == 0,
            discontinuity: i == 0,
            epoch: 0,
            payload: h265_access_unit(i == 0, 2_000, i),
        }));
    }
    let gop = track.gop().expect("a cache");
    pair.session.join(pair.now, Some(&gop));
    pair.drain();
    assert_eq!(pair.session.stats().join_frames, 2);
    // A live P frame after it, as the RTSP source publishes it.
    let au = h265_access_unit(false, 3_000, 9);
    let payloads = lotse_codec::h265::packetize(&au, DEFAULT_MAX_PAYLOAD);
    let count = payloads.len();
    for (index, payload) in payloads.iter().enumerate() {
        let packet = MediaPacket {
            arrival: pair.now,
            rtp: RtpHeaderFields {
                pt: 96,
                seq: u16::try_from(index).unwrap(),
                ts: 96_000,
                marker: index + 1 == count,
                ssrc: 1,
            },
            frame_start: index == 0,
            keyframe_start: false,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(payload.as_ref()),
        };
        pair.session.write_video(pair.now, &packet, pair.now);
    }
    let written = pair.session.stats().packets;
    pair.run_until(
        |p| p.viewer.packets().len() as u64 >= written,
        500,
        "received",
    );
    let received = pair.viewer.packets();
    assert!(received.iter().all(|p| *p.header.payload_type == pt));
    let types: Vec<u8> = received
        .iter()
        .map(|p| lotse_codec::h265::nal::nal_type(p.payload[0]))
        .collect();
    // VPS, SPS and PPS as single NAL units (§4.4.1), then the slices in
    // fragmentation units (§4.4.3), the marker on each frame's last.
    assert_eq!(types[..3], [32, 33, 34], "{types:?}");
    assert!(types[3..].iter().all(|&t| t == 49), "{types:?}");
    assert_eq!(received.iter().filter(|p| p.header.marker).count(), 3);
    assert_eq!(
        &received.last().unwrap().payload[..],
        &payloads[count - 1][..]
    );
}

#[test]
fn rfc7798_7_2_2_the_stream_profile_picks_among_the_offered_ones() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let main_and_10 = with_video_codecs(
        viewer.offer(),
        "a=rtpmap:49 H265/90000\na=fmtp:49 level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST\na=rtpmap:50 rtx/90000\na=fmtp:50 apt=49\na=rtpmap:51 H265/90000\na=fmtp:51 level-id=180;profile-id=2;tier-flag=0;tx-mode=SRST\na=rtpmap:52 rtx/90000\na=fmtp:52 apt=51\n",
    );
    // A Main stream may go under either; a Main 10 one only under Main 10.
    let (_, answer) = Session::answer(&request(&main_and_10, h265(1)), now).expect("Main");
    let lines = codec_lines(&answer, "H265");
    assert!(lines.contains(&"a=rtpmap:49 H265/90000"), "{answer}");
    assert!(lines.contains(&"a=rtpmap:51 H265/90000"), "{answer}");
    let (_, answer) = Session::answer(&request(&main_and_10, h265(2)), now).expect("Main 10");
    assert_eq!(
        codec_lines(&answer, "H265"),
        [
            "a=rtpmap:51 H265/90000",
            "a=fmtp:51 profile-id=2;tier-flag=0;level-id=180"
        ],
        "{answer}"
    );
    // Only Main 10 offered: the Main stream conforms to it (H.265 A.3.2).
    let main_10_only = with_video_codecs(
        viewer.offer(),
        "a=rtpmap:51 H265/90000\na=fmtp:51 profile-id=2\n",
    );
    let (_, answer) = Session::answer(&request(&main_10_only, h265(1)), now).expect("Main as 10");
    assert_eq!(
        codec_lines(&answer, "H265"),
        ["a=rtpmap:51 H265/90000", "a=fmtp:51 profile-id=2"],
        "{answer}"
    );
    // Only Main offered: no Main 10 stream goes there.
    let main_only = with_video_codecs(viewer.offer(), "a=rtpmap:49 H265/90000\n");
    let err = Session::answer(&request(&main_only, h265(2)), now).err();
    let Some(SessionOpenError::VideoCodecUnsupported(message)) = err else {
        panic!("{err:?}");
    };
    assert_eq!(
        message,
        "no offered h265 payload type with profile-id in [2]"
    );
}

#[test]
fn rfc7798_7_2_2_a_level_above_the_offer_is_sent_anyway() {
    // A level 4.0 camera, a viewer that offers level 3.1: answered at 3.1
    // and played (SPEC-DEVIATION).
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = with_video_codecs(
        viewer.offer(),
        "a=rtpmap:49 H265/90000\na=fmtp:49 level-id=93;profile-id=1;tier-flag=0\n",
    );
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    let logs = tracing::subscriber::set_default(subscriber);
    let (mut pair, answer) = Pair::with_viewer_offer(h265(1), viewer, &offer, now);
    drop(logs);
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("h265 stream level above the offered level-id")
            && logs.contains("level_id=120")
            && logs.contains("offered_level=93"),
        "{logs}"
    );
    assert!(
        answer.contains("a=fmtp:49 profile-id=1;tier-flag=0;level-id=93"),
        "{answer}"
    );
    pair.connect(&answer);
    assert!(pair.closed_code().is_none(), "{:?}", pair.events);
}

#[test]
fn an_h265_camera_and_a_browser_without_h265_is_video_codec_unsupported() {
    // A client can fall back to HLS on the code.
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    for codecs in [
        FIREFOX_VIDEO,
        // Main 10 only, which a Main stream conforms to, in the High tier
        // without a level-id: str0m would answer it without its tier-flag.
        "a=rtpmap:51 H265/90000\na=fmtp:51 profile-id=2;tier-flag=1\n",
    ] {
        let offer = with_video_codecs(viewer.offer(), codecs);
        let err = WebRtcFactory
            .open_session(request(&offer, h265(1)), now)
            .err();
        let Some(SessionOpenError::VideoCodecUnsupported(message)) = err else {
            panic!("{err:?}");
        };
        assert_eq!(
            message,
            "no offered h265 payload type with profile-id in [1, 2]"
        );
        assert_eq!(
            SessionOpenError::VideoCodecUnsupported(message).code(),
            "video_codec_unsupported"
        );
    }
}

#[test]
fn itu_t_h265_a_4_1_a_main_tier_stream_plays_under_a_high_tier_only_offer() {
    // A receiver that offers only the High tier decodes the Main tier
    // too: the answer keeps the offered tier-flag (RFC 7798 §7.2.2) and
    // the stream plays under it.
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new_h265(BROWSER.parse().unwrap(), now, &[(1, 1, 153)]).expect("a viewer");
    let (mut pair, answer) = Pair::with_viewer(h265(1), viewer, now);
    assert_eq!(
        codec_lines(&answer, "H265"),
        [
            "a=rtpmap:96 H265/90000",
            "a=fmtp:96 profile-id=1;tier-flag=1;level-id=153"
        ],
        "{answer}"
    );
    pair.connect(&answer);
    let pts = play_h265_keyframe(&mut pair);
    assert!(!pts.is_empty() && pts.iter().all(|&pt| pt == 96), "{pts:?}");
    assert!(pair.closed_code().is_none(), "{:?}", pair.events);
}

#[test]
fn itu_t_h265_a_4_1_a_high_tier_stream_goes_only_under_a_high_tier_payload_type() {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    // What Chrome offers (Main and Main 10, Main tier) and Safari (no
    // fmtp: Main, Main tier, level 3.1): no High tier decoder, refused.
    for codecs in [
        "a=rtpmap:49 H265/90000\na=fmtp:49 level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST\na=rtpmap:51 H265/90000\na=fmtp:51 level-id=180;profile-id=2;tier-flag=0;tx-mode=SRST\n",
        "a=rtpmap:49 H265/90000\n",
    ] {
        let offer = with_video_codecs(viewer.offer(), codecs);
        let err = WebRtcFactory
            .open_session(request(&offer, h265_in_tier(1, true)), now)
            .err();
        let Some(SessionOpenError::VideoCodecUnsupported(message)) = err else {
            panic!("{err:?}");
        };
        assert_eq!(
            message,
            "no offered h265 payload type with profile-id in [1, 2] and tier-flag=1"
        );
    }
    // Both tiers offered: the High tier one, and it plays.
    let viewer = Viewer::new_h265(BROWSER.parse().unwrap(), now, &[(1, 0, 180), (1, 1, 150)])
        .expect("a viewer");
    let (mut pair, answer) = Pair::with_viewer(h265_in_tier(1, true), viewer, now);
    assert_eq!(
        codec_lines(&answer, "H265"),
        [
            "a=rtpmap:98 H265/90000",
            "a=fmtp:98 profile-id=1;tier-flag=1;level-id=150"
        ],
        "{answer}"
    );
    pair.connect(&answer);
    let pts = play_h265_keyframe(&mut pair);
    assert!(!pts.is_empty() && pts.iter().all(|&pt| pt == 98), "{pts:?}");
}

#[test]
fn itu_t_h265_7_4_4_a_new_sps_outside_the_negotiated_profile_or_tier_closes_stream_changed() {
    use lotse_core::codec::CodecFamily;
    use lotse_core::session::apply_track_event;
    use lotse_core::track::TrackEvent;

    // A Main camera under Chrome's Main type: the rule that answered the
    // offer judges every new SPS.
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let chrome = with_video_codecs(
        viewer.offer(),
        "a=rtpmap:49 H265/90000\na=fmtp:49 level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST\n",
    );
    let (mut session, _) = Session::answer(&request(&chrome, h265(1)), now).expect("answered");
    // Main again (a new size, say), no SPS, or one that does not parse:
    // the session goes on.
    let unknown = |sps: Option<Vec<u8>>| Codec::H265 {
        vps: None,
        sps: sps.map(Bytes::from),
        pps: None,
    };
    for codec in [
        (*h265(1)).clone(),
        unknown(None),
        unknown(Some(vec![0x42, 0x01])),
    ] {
        assert_eq!(session.check_video_change(&codec), Ok(()));
    }
    // Main 10 does not conform to Main, the High tier needs a High tier
    // type (A.4.1).
    assert_eq!(
        session.check_video_change(&h265(2)),
        Err(
            "h265 is now profile-id 2 in the main tier, outside payload type 49 (profile-id 1, tier-flag 0)"
                .to_owned()
        )
    );
    assert_eq!(
        session.check_video_change(&h265_in_tier(1, true)),
        Err(
            "h265 is now profile-id 1 in the high tier, outside payload type 49 (profile-id 1, tier-flag 0)"
                .to_owned()
        )
    );
    apply_track_event(
        &mut session,
        now,
        CodecFamily::H265,
        Some(TrackEvent::TrackChanged(h265(2))),
        |_| now,
    );
    let closed = std::iter::from_fn(|| match session.poll() {
        SessionOutput::Timeout(_) => None,
        output => Some(output),
    })
    .find_map(|output| match output {
        SessionOutput::Event(SessionEvent::Closed { code, .. }) => Some(code),
        _ => None,
    });
    assert_eq!(closed, Some("stream_changed"));

    // Under a High tier type the High tier fits too.
    let high = with_video_codecs(
        viewer.offer(),
        "a=rtpmap:49 H265/90000\na=fmtp:49 level-id=153;profile-id=1;tier-flag=1\n",
    );
    let (session, _) = Session::answer(&request(&high, h265(1)), now).expect("answered");
    assert_eq!(session.check_video_change(&h265_in_tier(1, true)), Ok(()));
    // H.264 is answered whatever its profile, and goes on whatever it
    // becomes (RFC 6184 §8.2.2 deviation).
    let (session, _) = Session::answer(&request(viewer.offer(), h264(None)), now).expect("h264");
    assert_eq!(
        session.check_video_change(&h264(Some([0x64, 0x00, 0x33]))),
        Ok(())
    );
}

/// A log writer that keeps every line.
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

impl Captured {
    /// What was written, as text.
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Captures what this thread logs at `level` and above until the guard
/// drops: the log lines' fields are evaluated as in production.
fn capture_logs(level: tracing::Level) -> (tracing::subscriber::DefaultGuard, Captured) {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(level)
        .with_ansi(false)
        .finish();
    (tracing::subscriber::set_default(subscriber), captured)
}

/// The `a=extmap` URI of CVO (3GPP TS 26.114 §6.2.3.3).
const CVO_URI: &str = "urn:3gpp:video-orientation";

/// A pair whose stream is turned `orientation`, the viewer's offer (which
/// lists CVO, as Chrome's and Safari's do) passed through `edit`, with
/// the answer and what the session logged while answering.
fn oriented(orientation: Orientation, edit: impl Fn(&str) -> String) -> (Pair, String, String) {
    let now = SystemClock.now();
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    assert!(viewer.offer().contains(CVO_URI), "{}", viewer.offer());
    let mut request = request(&edit(viewer.offer()), h264(None));
    request.orientation = orientation;
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    let logs = tracing::subscriber::set_default(subscriber);
    let (pair, answer) = Pair::with_request(&request, viewer, now);
    drop(logs);
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    (pair, answer, logs)
}

/// Connects `pair`, joins it with a fresh cached GOP of three frames (the
/// join's own packetizer) and writes one live frame of two full packets
/// after it (the cut-through path); returns the packets the viewer got.
fn join_and_play(pair: &mut Pair, answer: &str) -> Vec<str0m::rtp::RtpPacket> {
    join_and_turn(pair, answer, &[])
}

/// [`join_and_play`], with one more live frame after each of `turns`,
/// which the session is given before it.
fn join_and_turn(
    pair: &mut Pair,
    answer: &str,
    turns: &[Orientation],
) -> Vec<str0m::rtp::RtpPacket> {
    pair.viewer
        .accept_answer(answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.run_until(
        |p| p.session.state() == State::Connected,
        5_000,
        "connected",
    );
    let track = track_with_gop(pair.now, pair.now - Duration::from_millis(100), 3);
    let gop = track.gop().expect("a cache");
    pair.session.join(pair.now, Some(&gop));
    let mut normalizer = normalizer();
    let mut seq = 0;
    let frames = std::iter::once(None).chain(turns.iter().copied().map(Some));
    for (frame, turn) in (3..).zip(frames) {
        if let Some(turn) = turn {
            pair.session.set_orientation(turn);
        }
        // A P frame whose bytes fill two FU-A packets to the brim.
        let live = packets(
            &mut normalizer,
            &mut seq,
            90_000 + frame * 3_000,
            false,
            2 * (DEFAULT_MAX_PAYLOAD - 2),
            pair.now,
        );
        assert_eq!(live.len(), 2);
        for packet in &live {
            pair.session.write_video(pair.now, packet, pair.now);
        }
        pair.drain();
    }
    let sent = pair.session.stats().packets;
    pair.run_until(
        |p| p.viewer.packets().len() as u64 >= sent,
        500,
        "the frames",
    );
    pair.viewer.take_packets()
}

/// The CVO value of each frame's last packet in `packets`, in order.
fn frame_orientations(packets: &[str0m::rtp::RtpPacket]) -> Vec<Option<VideoOrientation>> {
    packets
        .iter()
        .filter(|p| p.header.marker)
        .map(|p| p.header.ext_vals.video_orientation)
        .collect()
}

/// What the session logs at `info` while `f` runs.
fn logs_of(f: impl FnOnce()) -> String {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(captured.0.lock().unwrap().clone()).unwrap()
}

#[test]
fn ts_26_114_7_4_5_cvo_rides_the_last_packet_of_every_frame_when_offered() {
    let (mut pair, answer, logs) = oriented(Orientation::RotateLeft, str::to_owned);
    assert!(
        logs.contains("video orientation negotiated")
            && logs.contains("orientation=\"rotate_left\"")
            && logs.contains("extension_id=13 cvo=3 sent=Deg90"),
        "{logs}"
    );
    // RFC 8285 §6: answered under the offered id.
    assert!(
        answer.contains(&format!("a=extmap:13 {CVO_URI}")),
        "{answer}"
    );
    let received = join_and_play(&mut pair, &answer);
    // Three join frames and the live one, each ending on a marker.
    assert_eq!(received.iter().filter(|p| p.header.marker).count(), 4);
    for packet in &received {
        // R = 11: the receiver turns the picture 90° counterclockwise.
        let expected = packet.header.marker.then_some(VideoOrientation::Deg90);
        assert_eq!(
            packet.header.ext_vals.video_orientation, expected,
            "seq {}",
            *packet.seq_no
        );
    }
    // The live frame's last packet is a full one, with CVO beside
    // `playout-delay`, mid, abs-send-time and transport-cc. As an RTP
    // packet it fits libwebrtc's 1200 bytes (`kVideoMtu`) with room for a
    // mid of 16 bytes (12 more than this one's 3, the block padded to 4)
    // and RTX's original sequence number (2): the bound DEFAULT_MAX_PAYLOAD
    // is derived from. Its datagram adds only the SRTP tag (16).
    let last = received.last().unwrap();
    assert!(last.header.marker);
    assert_eq!(last.payload.len(), DEFAULT_MAX_PAYLOAD);
    assert!(last.header.ext_vals.play_delay_max.is_some());
    let rtp = last.header.header_len + last.payload.len();
    assert_eq!(rtp + 12 + 2, 1_200, "{rtp}-byte RTP packet");
    let largest = pair.marked.iter().map(|(_, d)| d.len()).max().unwrap();
    assert_eq!(largest, rtp + 16, "{largest}-byte datagram");
}

#[test]
fn ts_26_114_6_2_3_3_no_cvo_unless_offered_and_none_sent_without_an_orientation() {
    let without_cvo = |offer: &str| {
        offer
            .split("\r\n")
            .filter(|line| !line.ends_with(CVO_URI))
            .collect::<Vec<_>>()
            .join("\r\n")
    };
    // Not offered: not answered (§6.2.3.3), and nothing marked.
    let (mut pair, answer, logs) = oriented(Orientation::RotateRight, without_cvo);
    assert!(
        logs.contains("the offer has no video orientation extension")
            && logs.contains("orientation=\"rotate_right\""),
        "{logs}"
    );
    assert!(!answer.contains(CVO_URI), "{answer}");
    let received = join_and_play(&mut pair, &answer);
    assert!(received.iter().any(|p| p.header.marker));
    assert!(
        received
            .iter()
            .all(|p| p.header.ext_vals.video_orientation.is_none())
    );
    // Offered but the stream is not turned: the answer is what it always
    // was, and no packet carries a value.
    let (mut pair, answer, logs) = oriented(Orientation::NoTransform, str::to_owned);
    assert!(!logs.contains("orientation"), "{logs}");
    assert!(answer.contains(CVO_URI), "{answer}");
    let received = join_and_play(&mut pair, &answer);
    assert!(received.iter().any(|p| p.header.marker));
    assert!(
        received
            .iter()
            .all(|p| p.header.ext_vals.video_orientation.is_none())
    );
}

#[test]
fn ts_26_114_7_4_5_a_mirrored_orientation_sends_its_rotation_without_the_flip_bit() {
    // SPEC-DEVIATION: str0m 0.24 carries R1 R0 only.
    let (mut pair, answer, logs) = oriented(Orientation::RotateRightAndFlip, str::to_owned);
    assert!(logs.contains("cvo=7 sent=Deg90"), "{logs}");
    let received = join_and_play(&mut pair, &answer);
    let last = received.last().unwrap();
    assert_eq!(
        last.header.ext_vals.video_orientation,
        Some(VideoOrientation::Deg90)
    );
}

#[test]
fn ts_26_114_7_4_5_an_orientation_change_turns_the_next_frame_and_a_turn_back_says_so() {
    use VideoOrientation::{Deg0, Deg90, Deg270};
    // Turned at the answer, then turned the other way: the frame after the
    // change says so, without a new session.
    let (mut pair, answer, _) = oriented(Orientation::RotateLeft, str::to_owned);
    let mut received = Vec::new();
    let logs =
        logs_of(|| received = join_and_turn(&mut pair, &answer, &[Orientation::RotateRight]));
    assert!(
        logs.contains("video orientation changed")
            && logs.contains("orientation=\"rotate_right\" extension_id=13 cvo=1 sent=Deg270"),
        "{logs}"
    );
    assert_eq!(
        frame_orientations(&received),
        [
            Some(Deg90),
            Some(Deg90),
            Some(Deg90),
            Some(Deg90),
            Some(Deg270)
        ]
    );
    // Not turned at the answer, which still negotiated CVO, then turned,
    // then turned back: 0 is said, as a receiver keeps the last value.
    let (mut pair, answer, _) = oriented(Orientation::NoTransform, str::to_owned);
    let turns = [Orientation::RotateLeft, Orientation::NoTransform];
    let received = join_and_turn(&mut pair, &answer, &turns);
    assert_eq!(
        frame_orientations(&received),
        [None, None, None, None, Some(Deg90), Some(Deg0)]
    );
}

#[test]
fn ts_26_114_6_2_3_3_an_orientation_change_without_cvo_offered_changes_nothing() {
    let without_cvo = |offer: &str| {
        offer
            .split("\r\n")
            .filter(|line| !line.ends_with(CVO_URI))
            .collect::<Vec<_>>()
            .join("\r\n")
    };
    let (mut pair, answer, _) = oriented(Orientation::NoTransform, without_cvo);
    let mut received = Vec::new();
    let logs = logs_of(|| received = join_and_turn(&mut pair, &answer, &[Orientation::Rotate180]));
    assert!(
        logs.contains("orientation changed, but the offer had no video orientation extension")
            && logs.contains("orientation=\"rotate_180\""),
        "{logs}"
    );
    assert_eq!(frame_orientations(&received), [None; 5]);
}

/// The `a=extmap` URI of `abs-capture-time` (webrtc.org experiments,
/// observed 2026-10-07).
const ABS_CAPTURE_TIME_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time";

/// A pair with video and PCMU audio whose viewer's offer (which lists
/// `abs-capture-time`, as Chrome's does for a page that asks for it) went
/// through `edit`; with the answer, what the session logged at `debug`
/// while answering, and the session's wall-clock anchor (the `now` it
/// opened at and the request's wall clock).
fn timed(edit: impl Fn(&str) -> String) -> (Pair, String, String, (Instant, SystemTime)) {
    // Read together, as the worker reads them, before the viewer's
    // certificate takes its time.
    let (now, wall) = (SystemClock.now(), SystemClock.wall_now());
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new_with_audio(BROWSER.parse().unwrap(), now).expect("a viewer");
    assert!(
        viewer.offer().contains(ABS_CAPTURE_TIME_URI),
        "{}",
        viewer.offer()
    );
    let mut request = request(&edit(viewer.offer()), h264(None));
    request.audio = Some(Arc::new(Codec::Pcmu));
    request.wall = wall;
    let anchor = (now, wall);
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    let logs = tracing::subscriber::set_default(subscriber);
    let (pair, answer) = Pair::with_request(&request, viewer, now);
    drop(logs);
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    (pair, answer, logs, anchor)
}

/// The capture time of a video frame `n` frames into the play (30 fps) or
/// of an audio packet as many 20 ms packets in.
fn captured_at(start: Instant, n: u32, per_second: u32) -> Instant {
    start + Duration::from_nanos(u64::from(n) * 1_000_000_000 / u64::from(per_second))
}

/// Connects `pair` and plays it for `frames` video frames at 30 fps and
/// the audio beside them, 20 ms PCMU packets, each written 20 ms after its
/// capture. The keyframe comes first; every P frame is a full FU-A packet
/// and a short one. Returns the capture times' origin.
fn play_timed(pair: &mut Pair, answer: &str, frames: u32) -> Instant {
    pair.viewer
        .accept_answer(answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.run_until(
        |p| p.session.state() == State::Connected,
        5_000,
        "connected",
    );
    let start = pair.now;
    let mut normalizer = normalizer();
    let (mut seq, mut audio_seq, mut audio) = (0, 0, 0);
    for n in 0..frames {
        let capture = captured_at(start, n, 30);
        while pair.now < capture + Duration::from_millis(20) {
            pair.step();
        }
        while captured_at(start, audio, 50) <= capture {
            let at = captured_at(start, audio, 50);
            let packet = audio_packet(audio_seq, audio * 160, 0, at);
            pair.session.write_audio(pair.now, &packet, at);
            (audio, audio_seq) = (audio + 1, audio_seq + 1);
        }
        let bytes = if n == 0 {
            300
        } else {
            DEFAULT_MAX_PAYLOAD - 2 + 100
        };
        for packet in packets(&mut normalizer, &mut seq, n * 3_000, n == 0, bytes, capture) {
            pair.session.write_video(pair.now, &packet, capture);
        }
        pair.drain();
    }
    let (video, audio) = (
        pair.session.stats().packets,
        pair.session.stats().audio_packets,
    );
    pair.run_until(
        |p| {
            p.viewer.packets().len() as u64 >= video
                && p.viewer.audio_packets().len() as u64 >= audio
        },
        500,
        "the play",
    );
    start
}

/// The packets that carry `abs-capture-time`, with their value.
fn carriers(packets: &[str0m::rtp::RtpPacket]) -> Vec<(&str0m::rtp::RtpPacket, AbsCaptureTime)> {
    packets
        .iter()
        .filter_map(|p| p.header.ext_vals.abs_capture_time.map(|value| (p, value)))
        .collect()
}

/// Whether a line of `logs` has both `message` and `fields`.
fn logged(logs: &str, message: &str, fields: &str) -> bool {
    logs.lines()
        .any(|line| line.contains(message) && line.contains(fields))
}

/// How far apart two wall times are.
fn apart(a: SystemTime, b: SystemTime) -> Duration {
    a.duration_since(b).unwrap_or_else(|err| err.duration())
}

#[test]
fn abs_capture_time_carries_the_written_capture_time_on_the_session_wall_clock_once_a_second() {
    let (mut pair, answer, logs, (opened, wall)) = timed(str::to_owned);
    for kind in ["video", "audio"] {
        assert!(
            logged(
                &logs,
                "abs-capture-time negotiated",
                &format!("kind=\"{kind}\" extension_id=12")
            ),
            "{logs}"
        );
    }
    // RFC 8285 §6: answered under the offered id, in both m-lines.
    for kind in ["video", "audio"] {
        assert!(
            section(&answer, kind)
                .contains(&format!("a=extmap:12 {ABS_CAPTURE_TIME_URI}").as_str()),
            "{answer}"
        );
    }
    // 2.3 s of play.
    let start = play_timed(&mut pair, &answer, 70);
    let on_wall = |capture: Instant| wall + capture.duration_since(opened);
    for (kind, packets, per_tick) in [
        ("video", pair.viewer.packets(), 90_000_u64),
        ("audio", pair.viewer.audio_packets(), 8_000),
    ] {
        let sent = carriers(packets);
        // libwebrtc's sender: the first packet, then once more than a
        // second has passed; 2.3 s hold three.
        assert_eq!(
            sent.len(),
            3,
            "{kind}: {:?}",
            sent.iter().map(|(p, _)| *p.seq_no).collect::<Vec<_>>()
        );
        assert_eq!(
            sent[0].0.seq_no, packets[0].seq_no,
            "{kind}: the first packet"
        );
        for pair in sent.windows(2) {
            let ticks = u64::from(
                pair[1]
                    .0
                    .header
                    .timestamp
                    .wrapping_sub(pair[0].0.header.timestamp),
            );
            let gap = Duration::from_nanos(ticks * 1_000_000_000 / per_tick);
            assert!(
                gap > Duration::from_secs(1) && gap < Duration::from_millis(1_100),
                "{kind}: {gap:?} apart"
            );
        }
        for (packet, value) in &sent {
            // The capture time written, on the session's wall clock; the
            // NTP timestamp rounds to the nanosecond.
            let ticks = u64::from(
                packet
                    .header
                    .timestamp
                    .wrapping_sub(packets[0].header.timestamp),
            );
            let n =
                u32::try_from(ticks * if kind == "video" { 30 } else { 50 } / per_tick).unwrap();
            let capture = captured_at(start, n, if kind == "video" { 30 } else { 50 });
            assert!(
                apart(value.capture_time, on_wall(capture)) <= Duration::from_micros(1),
                "{kind}: {:?} for {:?}",
                value.capture_time,
                on_wall(capture)
            );
            // The extended form, the offset 0: lotse is the capture system.
            assert_eq!(value.clock_offset, Some(0), "{kind}");
            // On the clock of the Sender Reports, where one came before
            // (SPEC-DEVIATION: str0m's anchor is its own).
            if let Some(by_report) = capture_seconds(packet) {
                let ours = value
                    .capture_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64();
                assert!(
                    (ours - by_report).abs() < 0.001,
                    "{kind}: {ours} against {by_report}"
                );
            }
        }
        // str0m's first video report comes within the first second.
        assert!(
            kind == "audio" || sent.iter().any(|(p, _)| capture_seconds(p).is_some()),
            "{kind}: no Sender Report before a capture time"
        );
    }
    // A P frame's first packet is full: its capture time waits for the
    // short one after it, which has room for the 17 bytes.
    let video = pair.viewer.packets();
    for (packet, _) in carriers(video).iter().skip(1) {
        assert!(
            packet.payload.len() + 16 <= DEFAULT_MAX_PAYLOAD,
            "{}",
            packet.payload.len()
        );
        assert!(packet.header.marker, "the frame's short last packet");
        let first = video
            .iter()
            .find(|p| p.header.timestamp == packet.header.timestamp)
            .unwrap();
        assert_eq!(first.payload.len(), DEFAULT_MAX_PAYLOAD);
        assert!(first.header.ext_vals.abs_capture_time.is_none());
    }
}

#[test]
fn rfc8285_6_abs_capture_time_is_answered_under_chromes_id_and_not_unless_offered() {
    // Chrome offers it under 13 (observed 2026-10-07, Chrome 154), the id
    // str0m's own map gives CVO: the offer's ids are followed.
    let chrome_ids = |offer: &str| {
        offer
            .replace(&format!("a=extmap:13 {CVO_URI}"), &format!("a=extmap:3 {CVO_URI}"))
            .replace(
                "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
                "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
            )
            .replace(
                "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid",
                "a=extmap:9 urn:ietf:params:rtp-hdrext:sdes:mid",
            )
            .replace(
                &format!("a=extmap:12 {ABS_CAPTURE_TIME_URI}"),
                &format!("a=extmap:13 {ABS_CAPTURE_TIME_URI}"),
            )
    };
    let (_, answer, logs, _) = timed(chrome_ids);
    assert!(
        logged(
            &logs,
            "abs-capture-time negotiated",
            "kind=\"video\" extension_id=13"
        ),
        "{logs}"
    );
    let video = section(&answer, "video");
    assert!(
        video.contains(&format!("a=extmap:13 {ABS_CAPTURE_TIME_URI}").as_str()),
        "{answer}"
    );
    assert!(
        video.contains(&format!("a=extmap:3 {CVO_URI}").as_str()),
        "{answer}"
    );

    // Not offered: not answered, and no packet carries it.
    let without = |offer: &str| {
        offer
            .split("\r\n")
            .filter(|line| !line.ends_with(ABS_CAPTURE_TIME_URI))
            .collect::<Vec<_>>()
            .join("\r\n")
    };
    let (mut pair, answer, logs, _) = timed(without);
    for kind in ["video", "audio"] {
        assert!(
            logged(
                &logs,
                "the offer has no abs-capture-time extension",
                &format!("kind=\"{kind}\"")
            ),
            "{logs}"
        );
    }
    assert!(!answer.contains(ABS_CAPTURE_TIME_URI), "{answer}");
    play_timed(&mut pair, &answer, 40);
    assert!(!pair.viewer.packets().is_empty() && !pair.viewer.audio_packets().is_empty());
    assert!(carriers(pair.viewer.packets()).is_empty());
    assert!(carriers(pair.viewer.audio_packets()).is_empty());
}

/// The viewer's offer with every line `edit` maps, lines it drops left out.
fn edited_offer(viewer: &Viewer, edit: impl Fn(&str) -> Option<String>) -> String {
    viewer
        .offer()
        .split_inclusive("\r\n")
        .filter_map(|line| edit(line.trim_end_matches("\r\n")))
        .map(|line| line + "\r\n")
        .collect()
}

#[test]
fn rfc8842_5_an_offer_without_a_fingerprint_is_invalid_sdp() {
    lotse_webrtc::install_crypto_provider();
    let now = SystemClock.now();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = edited_offer(&viewer, |line| {
        (!line.starts_with("a=fingerprint:")).then(|| line.to_owned())
    });
    let Err(SessionOpenError::InvalidSdp(reason)) =
        Session::answer(&request(&offer, h264(None)), now)
    else {
        panic!()
    };
    assert!(reason.contains("fingerprint"), "{reason}");
}

#[test]
fn rfc3264_6_1_a_video_m_line_the_viewer_only_sends_on_is_invalid_sdp() {
    lotse_webrtc::install_crypto_provider();
    let now = SystemClock.now();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = edited_offer(&viewer, |line| {
        Some(
            if line == "a=recvonly" {
                "a=sendonly"
            } else {
                line
            }
            .to_owned(),
        )
    });
    let Err(SessionOpenError::InvalidSdp(reason)) =
        Session::answer(&request(&offer, h264(None)), now)
    else {
        panic!()
    };
    assert_eq!(
        reason,
        "the answer declared no send stream for the video m-line"
    );
}

#[test]
fn rfc5246_7_2_a_fatal_dtls_alert_closes_the_session_as_internal_error() {
    let (mut pair, _) = Pair::new(h264(None));
    // A fatal `handshake_failure` alert (RFC 5246 §7.2) in a DTLS record
    // (RFC 6347 §4.1).
    let alert = [21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 9, 0, 2, 2, 40];
    pair.session.handle_datagram(
        pair.now,
        Transport::Udp,
        BROWSER.parse().unwrap(),
        DAEMON.parse().unwrap(),
        &alert,
    );
    pair.drain();
    assert_eq!(pair.closed_code(), Some("internal_error"));
}

#[test]
fn rfc8122_5_a_certificate_other_than_the_offers_fingerprint_closes_the_session() {
    lotse_webrtc::install_crypto_provider();
    let now = SystemClock.now();
    let viewer = Viewer::new(BROWSER.parse().unwrap(), now).expect("a viewer");
    let offer = edited_offer(&viewer, |line| {
        Some(match line.split_once(' ') {
            Some((name, hash)) if name.starts_with("a=fingerprint:") => {
                format!(
                    "{name} {}",
                    hash.replace(|c: char| c.is_ascii_hexdigit(), "0")
                )
            }
            _ => line.to_owned(),
        })
    });
    let (mut pair, answer) = Pair::with_viewer_offer(h264(None), viewer, &offer, now);
    pair.viewer
        .accept_answer(&answer, &mut pair.to_daemon)
        .expect("the answer applies");
    pair.run_until(|p| p.closed_code().is_some(), 5_000, "closed");
    assert_eq!(pair.closed_code(), Some("internal_error"));
}

#[test]
fn rfc7675_5_1_consent_regained_reconnects_and_consent_lost_for_the_timeout_is_ice_failed() {
    let (mut pair, answer) = Pair::new(h264(None));
    pair.connect(&answer);
    // Nothing the session sends arrives, nothing comes back.
    let stall = |pair: &mut Pair, until: &dyn Fn(&Pair) -> bool| {
        for _ in 0..600 {
            if until(pair) {
                return;
            }
            pair.now += Duration::from_millis(100);
            pair.session.handle_timeout(pair.now);
            pair.drain();
            pair.to_viewer.clear();
        }
        panic!("stalled for a minute; events {:?}", pair.events);
    };
    stall(&mut pair, &|p| p.session.state() == State::Disconnected);
    // The path comes back: consent is regained.
    pair.run_until(
        |p| p.session.state() == State::Connected,
        5_000,
        "consent regained",
    );
    assert_eq!(pair.closed_code(), None);
    // Lost again, for longer than the disconnect timeout.
    stall(&mut pair, &|p| p.session.state() == State::Disconnected);
    let lost_at = pair.now;
    stall(&mut pair, &|p| p.closed_code().is_some());
    assert_eq!(pair.closed_code(), Some("ice_failed"));
    assert!(pair.now >= lost_at + SessionLimits::default().disconnect_timeout);
}

#[test]
fn rfc8445_7_3_a_check_before_the_agent_started_its_own_moves_the_session_to_connecting() {
    let (mut pair, answer) = Pair::new(h264(None));
    assert_eq!(pair.session.state(), State::Gathering);
    pair.viewer
        .accept_answer(&answer, &mut pair.to_daemon)
        .expect("the answer applies");
    // The viewer's first datagram, before any timeout of the session.
    for _ in 0..1_000 {
        if !pair.to_daemon.is_empty() {
            break;
        }
        pair.now += Duration::from_millis(1);
        pair.viewer.timeout(pair.now, &mut pair.to_daemon);
    }
    let first = pair.to_daemon.remove(0);
    pair.session.handle_datagram(
        pair.now,
        Transport::Udp,
        first.source,
        first.destination,
        &first.payload,
    );
    assert_eq!(pair.session.state(), State::Connecting);
}

#[test]
fn rfc8445_8_1_2_once_no_other_pair_can_succeed_the_session_reports_ice_completed() {
    let (mut pair, answer) = Pair::new(h264(None));
    pair.connect(&answer);
    let completed = |p: &Pair| {
        p.events.iter().any(|event| {
            matches!(
                event,
                SessionEvent::State {
                    ice: "completed",
                    ..
                }
            )
        })
    };
    pair.run_until(completed, 6_000, "completed");
    assert_eq!(pair.session.state(), State::Connected);
}
