//! A fake WebRTC camera, as Home Assistant's native WebRTC cameras are one
//! (Nest, Ring, Matter): the answerer of the offer a `webrtc://` source
//! makes, on a real loopback UDP socket. The test plays the client that
//! relays the signaling: it hands the offer to [`FakeWebRtcCamera::answer`],
//! relays the answer and its candidates back over `signaling/*`, and hands
//! the source's trickled candidates to
//! [`FakeWebRtcCamera::add_remote_candidate`].
//!
//! Once connected (ICE as the controlled agent, RFC 8445 §6.1.1; DTLS-SRTP,
//! RFC 5764) the camera streams the fake RTSP camera's synthetic H.264
//! access units ([`crate::fake_camera`]: STAP-A parameter sets and FU-A
//! fragments, RFC 6184 §5.7.1 and §5.8) and, when configured, Opus (RFC
//! 7587) or PCMU (RFC 3551 §4.5.14) audio in 20 ms packets, each RTP packet
//! with the RFC 9143 `mid` header extension as libwebrtc sends it (unless
//! configured without, then not negotiated either); str0m sends the Sender Reports (RFC 3550 §6.4.1). A
//! Picture Loss Indication (RFC 4585 §6.3.1) makes the next picture a
//! keyframe.
//!
//! Knobs model the integrations' habits: candidates in the answer, trickled
//! after it, or both (RFC 8838); an ICE lite agent (RFC 8445 §2.5) that
//! sends no connectivity check and only answers the source's; the source's
//! trickled candidates dropped, as Home Assistant's Nest integration drops
//! them (Google's Smart Device Management API takes the offer's SDP only,
//! `GenerateWebRtcStream`, its reference as read 2026-11); an offer without
//! an `application` m-line refused, as Nest refuses one (observed in
//! go2rtc's Nest client, 2026-10); and a trickled candidate without
//! `sdpMLineIndex` refused, as Ring's integration needs it. The test closes
//! the connection (DTLS `close_notify`, RFC 6347 §4.2.7) when it wants a
//! camera that ends its session ([`FakeWebRtcCamera::close`]); dropping the
//! camera's handle closes it too.
//!
//! It runs on str0m's process-default crypto provider, which the caller
//! installs first with `lotse_webrtc::install_crypto_provider` (this crate
//! cannot depend on `lotse-webrtc`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;
use lotse_core::task::spawn_named;
use str0m::change::SdpOffer;
use str0m::crypto::CryptoProvider;
use str0m::format::Codec as EngineCodec;
use str0m::media::{Mid, Pt};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::rtp::{Extension, ExtensionMap, ExtensionValues, RtpWrite, SeqNo};
use str0m::{Candidate, Event, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::fake_camera::{CameraConfig, CameraVideo};

/// The audio a camera sends beside its video.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcCameraAudio {
    /// Opus (RFC 7587): a 20 ms CELT silence frame per packet.
    Opus,
    /// PCMU (RFC 3551 §4.5.14): 20 ms of µ-law silence per packet.
    Pcmu,
}

impl WebRtcCameraAudio {
    /// The engine's codec.
    const fn codec(self) -> EngineCodec {
        match self {
            Self::Opus => EngineCodec::Opus,
            Self::Pcmu => EngineCodec::PCMU,
        }
    }

    /// RTP timestamp ticks per 20 ms packet: Opus's clock is 48 kHz
    /// whatever it carries (RFC 7587 §4.1), PCMU's 8 kHz.
    const fn ticks(self) -> u32 {
        match self {
            Self::Opus => 960,
            Self::Pcmu => 160,
        }
    }

    /// One packet's payload.
    fn payload(self) -> Vec<u8> {
        match self {
            // RFC 6716 §3.1: TOC config 31 (CELT fullband, 20 ms), mono,
            // one frame; then a silent frame.
            Self::Opus => vec![0xf8, 0xff, 0xfe],
            // G.711 µ-law silence, one byte per sample.
            Self::Pcmu => vec![0xff; 160],
        }
    }
}

/// Where the camera's candidates go (RFC 8838).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CandidateDelivery {
    /// In the answer only, as Nest's integration answers.
    #[default]
    InAnswer,
    /// In the answer, and trickled after it as well.
    Both,
    /// Trickled only: the answer carries none.
    Trickled,
}

/// An error the camera's integration answers with instead of an answer,
/// as Home Assistant's `WebRTCError(code, message)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraRefusal {
    /// The code, for `signaling/error`.
    pub code: String,
    /// What went wrong.
    pub message: String,
}

impl CameraRefusal {
    /// A refusal with `code` and `message`.
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
        }
    }
}

/// How the camera behaves.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent knobs, each an integration's habit a test turns on alone"
)]
pub struct WebRtcCameraConfig {
    /// Frames per second.
    pub fps: u32,
    /// Frames per group of pictures: a keyframe every this many, and on a
    /// Picture Loss Indication.
    pub gop: u32,
    /// The audio, `None` for video only (its audio m-line rejected).
    pub audio: Option<WebRtcCameraAudio>,
    /// Where its candidates go.
    pub candidates: CandidateDelivery,
    /// Refuse an offer without an `application` m-line, as Nest does.
    pub require_application: bool,
    /// Refuse a trickled candidate without `sdpMLineIndex`, as Ring's
    /// integration does.
    pub require_mline_index: bool,
    /// Run ICE lite (RFC 8445 §2.5): no connectivity check of its own, it
    /// only answers the source's, so the source must reach it through the
    /// candidates the camera gave (a media server's habit).
    pub ice_lite: bool,
    /// Drop the source's trickled candidates instead of handing them to its
    /// ICE agent, as Home Assistant's Nest integration does.
    pub drop_remote_candidates: bool,
    /// Answer the RFC 9143 `mid` header extension and send it, as
    /// libwebrtc does; without it the answer has no `a=extmap` for it and
    /// the source finds each stream's m-line by the answer's `a=ssrc` (RFC
    /// 5576 §4.1) alone.
    pub mid_extension: bool,
    /// The address it binds, loopback by default.
    pub ip: IpAddr,
}

impl Default for WebRtcCameraConfig {
    fn default() -> Self {
        Self {
            fps: 25,
            gop: 25,
            audio: Some(WebRtcCameraAudio::Opus),
            candidates: CandidateDelivery::InAnswer,
            require_application: false,
            require_mline_index: false,
            ice_lite: false,
            drop_remote_candidates: false,
            mid_extension: true,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }
}

/// A candidate the camera trickles, as `signaling/candidate` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrickledCandidate {
    /// The `candidate:` line, without `a=`.
    pub candidate: String,
    /// The media section's `mid`.
    pub sdp_mid: Option<String>,
    /// The media section's index.
    pub sdp_mline_index: Option<u16>,
}

/// The camera's answer to an offer: the SDP, and the candidates to
/// trickle after it ([`CandidateDelivery`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRtcAnswer {
    /// The answer's SDP.
    pub sdp: String,
    /// The candidates to trickle, empty when the answer carries them all.
    pub candidates: Vec<TrickledCandidate>,
}

/// What the camera saw and did, for assertions.
#[derive(Debug, Default)]
pub struct WebRtcCameraStats {
    /// ICE and DTLS connected.
    pub connected: AtomicBool,
    /// Video RTP packets sent.
    pub video_packets: AtomicU64,
    /// Audio RTP packets sent.
    pub audio_packets: AtomicU64,
    /// Keyframe requests received.
    pub keyframe_requests: AtomicU64,
    /// The source's candidates handed to its ICE agent.
    pub remote_candidates: AtomicU64,
    /// The source's candidates dropped ([`WebRtcCameraConfig::drop_remote_candidates`]).
    pub dropped_candidates: AtomicU64,
    /// The camera closed the connection itself.
    pub closed: AtomicBool,
    /// The source closed it (its `close_notify` arrived).
    pub peer_closed: AtomicBool,
    /// The labels of the data channels the source opened.
    data_channels: Mutex<Vec<String>>,
}

impl WebRtcCameraStats {
    /// The value of `flag`.
    pub fn get(flag: &AtomicBool) -> bool {
        flag.load(Ordering::Relaxed)
    }

    /// The value of `counter`.
    pub fn count(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// The labels of the data channels the source opened.
    pub fn data_channels(&self) -> Vec<String> {
        self.data_channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Adds one to `counter`.
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// A camera that answered an offer and runs its connection until it ends,
/// it is closed or stopped, or its handle is dropped.
#[derive(Debug)]
pub struct FakeWebRtcCamera {
    /// Its socket's address, its one host candidate.
    addr: SocketAddr,
    /// What it saw.
    stats: Arc<WebRtcCameraStats>,
    /// The source's trickled candidates, into the connection's task.
    candidates: mpsc::UnboundedSender<Candidate>,
    /// Refuse a candidate without `sdpMLineIndex`.
    require_mline_index: bool,
    /// Drop the source's candidates.
    drop_remote_candidates: bool,
    /// Closes the connection and ends its task.
    cancel: CancellationToken,
    /// The connection's task.
    task: JoinHandle<()>,
}

/// `answer` with its `a=candidate` and `a=end-of-candidates` lines left
/// out.
fn without_candidates(answer: &str) -> String {
    answer
        .split("\r\n")
        .filter(|line| !line.starts_with("a=candidate:") && *line != "a=end-of-candidates")
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// The first `a=mid` of `sdp`: the media section a BUNDLE's candidates
/// belong to (RFC 9143).
fn first_mid(sdp: &str) -> Option<String> {
    sdp.lines()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .map(str::to_owned)
}

/// The mid of the first `m=<kind>` section of `sdp`.
fn mid_of(sdp: &str, kind: &str) -> Option<Mid> {
    sdp.split(&format!("m={kind}"))
        .nth(1)
        .and_then(|section| {
            section
                .lines()
                .take_while(|line| !line.starts_with("m="))
                .find_map(|line| line.strip_prefix("a=mid:"))
        })
        .map(Mid::from)
}

/// str0m's standard header extensions without the RFC 9143 `mid`.
fn without_mid() -> ExtensionMap {
    let mut map = ExtensionMap::empty();
    for (id, extension) in ExtensionMap::standard().iter() {
        if *extension != Extension::RtpMid {
            map.set(id, extension.clone());
        }
    }
    map
}

/// The camera's str0m, `config`'s codecs, with its host candidate at
/// `addr`, and its answer to `offer` at `now`.
fn negotiate(
    offer: &str,
    config: &WebRtcCameraConfig,
    addr: SocketAddr,
    now: Instant,
) -> Result<(Rtc, WebRtcAnswer), CameraRefusal> {
    let failed = |message: String| CameraRefusal::new("webrtc_offer_failed", message);
    let mut builder = Rtc::builder()
        .set_rtp_mode(true)
        .set_ice_lite(config.ice_lite)
        .clear_codecs()
        .enable_h264(true);
    if !config.mid_extension {
        builder = builder.set_extension_map(without_mid());
    }
    builder = match config.audio {
        Some(WebRtcCameraAudio::Opus) => builder.enable_opus(true, false),
        Some(WebRtcCameraAudio::Pcmu) => builder.enable_pcmu(true, false),
        None => builder,
    };
    let mut rtc = builder.build(now);
    let host = Candidate::host(addr, "udp").map_err(|err| failed(err.to_string()))?;
    let line = rtc
        .add_local_candidate(host)
        .map(Candidate::to_sdp_string)
        .ok_or_else(|| failed("the host candidate was not taken".into()))?;
    let parsed = SdpOffer::from_sdp_string(offer).map_err(|err| failed(err.to_string()))?;
    let sdp = rtc
        .sdp_api()
        .accept_offer(parsed)
        .map_err(|err| failed(err.to_string()))?
        .to_sdp_string();
    let trickled = TrickledCandidate {
        candidate: line,
        sdp_mid: first_mid(&sdp),
        sdp_mline_index: Some(0),
    };
    let answer = match config.candidates {
        CandidateDelivery::InAnswer => WebRtcAnswer {
            sdp,
            candidates: Vec::new(),
        },
        CandidateDelivery::Both => WebRtcAnswer {
            sdp,
            candidates: vec![trickled],
        },
        CandidateDelivery::Trickled => WebRtcAnswer {
            sdp: without_candidates(&sdp),
            candidates: vec![trickled],
        },
    };
    Ok((rtc, answer))
}

impl FakeWebRtcCamera {
    /// Answers `offer` as `config` says, on a socket of its own, and runs
    /// the connection on the time of `clock`.
    ///
    /// # Errors
    ///
    /// The camera's refusal: an offer without an `application` m-line when
    /// one is required, or an offer it cannot apply (code
    /// `webrtc_offer_failed`, as Home Assistant's own).
    pub async fn answer(
        offer: &str,
        config: WebRtcCameraConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, WebRtcAnswer), CameraRefusal> {
        let failed = |message: String| CameraRefusal::new("webrtc_offer_failed", message);
        if config.require_application && !offer.contains("m=application") {
            return Err(failed(
                "the offer has no application m-line (data channel)".into(),
            ));
        }
        if CryptoProvider::get_default().is_none() {
            return Err(failed(
                "no crypto provider: call lotse_webrtc::install_crypto_provider() first".into(),
            ));
        }
        let socket = UdpSocket::bind((config.ip, 0))
            .await
            .map_err(|err| failed(format!("bind: {err}")))?;
        let addr = socket
            .local_addr()
            .map_err(|err| failed(format!("local address: {err}")))?;
        let (rtc, answer) = negotiate(offer, &config, addr, clock.now())?;
        tracing::debug!(%addr, "fake webrtc camera: answered");
        let stats = Arc::new(WebRtcCameraStats::default());
        let (candidates, incoming) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let require_mline_index = config.require_mline_index;
        let drop_remote_candidates = config.drop_remote_candidates;
        let connection = Connection {
            video_mid: mid_of(offer, "video"),
            audio_mid: mid_of(offer, "audio"),
            rtc,
            socket,
            addr,
            config,
            stats: Arc::clone(&stats),
            clock,
            incoming,
            cancel: cancel.clone(),
            video: None,
            audio: None,
            frames: 0,
            video_seq: 0,
            audio_seq: 0,
            video_ts: 90_000,
            audio_ts: 0,
            next_frame: None,
            next_audio: None,
            keyframe_wanted: false,
            packets: 0,
        };
        let task = spawn_named("fake_webrtc_camera.connection", connection.run());
        Ok((
            Self {
                addr,
                stats,
                candidates,
                require_mline_index,
                drop_remote_candidates,
                cancel,
                task,
            },
            answer,
        ))
    }

    /// Its socket's address.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// What it saw.
    pub fn stats(&self) -> &WebRtcCameraStats {
        &self.stats
    }

    /// A candidate the source trickled, as the client relays it: the
    /// end-of-candidates indication (empty, RFC 8838 §13) is taken and
    /// ignored, and so is every candidate when the camera drops them.
    ///
    /// # Errors
    ///
    /// Without `sdp_mline_index` when the camera requires it, or a line
    /// that does not parse (RFC 8839 §5.1).
    pub fn add_remote_candidate(
        &self,
        candidate: &str,
        sdp_mline_index: Option<u64>,
    ) -> Result<(), String> {
        if self.require_mline_index && sdp_mline_index.is_none() {
            return Err("a candidate without sdpMLineIndex".to_owned());
        }
        if candidate.is_empty() {
            return Ok(());
        }
        let line = candidate.strip_prefix("a=").unwrap_or(candidate);
        let parsed = Candidate::from_sdp_string(line).map_err(|err| err.to_string())?;
        if self.drop_remote_candidates {
            WebRtcCameraStats::bump(&self.stats.dropped_candidates);
            return Ok(());
        }
        WebRtcCameraStats::bump(&self.stats.remote_candidates);
        // A connection that ended takes no more; nothing to tell.
        let _ended = self.candidates.send(parsed);
        Ok(())
    }

    /// Closes the connection (DTLS `close_notify`, RFC 6347 §4.2.7, and an
    /// RTCP BYE) when it is still up, as a camera that ends its session,
    /// and ends its task; its stats stay.
    pub fn close(&self) {
        self.cancel.cancel();
    }

    /// [`FakeWebRtcCamera::close`], and waits for its task.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        let _joined = (&mut self.task).await;
    }
}

impl Drop for FakeWebRtcCamera {
    /// A dropped handle closes the connection, so its task ends.
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// The connection's task: str0m, the socket and the media timers.
struct Connection {
    /// str0m.
    rtc: Rtc,
    /// The socket.
    socket: UdpSocket,
    /// Its address.
    addr: SocketAddr,
    /// How it behaves.
    config: WebRtcCameraConfig,
    /// What it saw.
    stats: Arc<WebRtcCameraStats>,
    /// The time.
    clock: Arc<dyn Clock>,
    /// The source's trickled candidates; closed once the camera's handle
    /// is gone.
    incoming: mpsc::UnboundedReceiver<Candidate>,
    /// The stop.
    cancel: CancellationToken,
    /// The offer's video m-line.
    video_mid: Option<Mid>,
    /// The offer's audio m-line.
    audio_mid: Option<Mid>,
    /// The video's m-line and payload type, once connected.
    video: Option<(Mid, Pt)>,
    /// The audio's, once connected, when it sends any.
    audio: Option<(Mid, Pt, WebRtcCameraAudio)>,
    /// Pictures sent.
    frames: u32,
    /// The video's next sequence number.
    video_seq: u64,
    /// The audio's next sequence number.
    audio_seq: u64,
    /// The video's RTP timestamp.
    video_ts: u32,
    /// The audio's RTP timestamp.
    audio_ts: u32,
    /// When the next picture is due.
    next_frame: Option<Instant>,
    /// When the next audio packet is due.
    next_audio: Option<Instant>,
    /// A keyframe was asked for.
    keyframe_wanted: bool,
    /// RTP packets sent.
    packets: u64,
}

/// What woke the connection.
enum Woke {
    /// The close, or the camera's handle gone.
    Stopped,
    /// A trickled candidate.
    Candidate(Candidate),
    /// A datagram.
    Datagram(io::Result<(usize, SocketAddr)>),
    /// A timer.
    Timer,
}

impl Connection {
    /// Runs until the connection ends or is closed: by the test, or by
    /// the camera's handle dropped (its candidate channel closed).
    async fn run(mut self) {
        let mut buf = vec![0_u8; 2_048];
        loop {
            let Some(timeout) = self.drain().await else {
                break;
            };
            let now = self.clock.now();
            let due = [Some(timeout), self.next_frame, self.next_audio]
                .into_iter()
                .flatten()
                .fold(timeout, Instant::min);
            let sleep = self.clock.sleep(due.saturating_duration_since(now));
            let event = tokio::select! {
                biased;
                () = self.cancel.cancelled() => Woke::Stopped,
                candidate = self.incoming.recv() => candidate.map_or(Woke::Stopped, Woke::Candidate),
                received = self.socket.recv_from(&mut buf) => Woke::Datagram(received),
                () = sleep => Woke::Timer,
            };
            let now = self.clock.now();
            match event {
                Woke::Stopped => {
                    self.close().await;
                    break;
                }
                Woke::Candidate(candidate) => {
                    self.rtc.add_remote_candidate(candidate);
                }
                Woke::Datagram(Ok((len, source))) => {
                    let bytes = buf.get(..len).unwrap_or_default();
                    self.receive(now, source, bytes);
                }
                Woke::Datagram(Err(err)) => {
                    tracing::debug!(error = %err, "fake webrtc camera: receive failed");
                }
                Woke::Timer => {
                    self.input(Input::Timeout(now));
                    self.media(now);
                }
            }
        }
        tracing::debug!(
            packets = self.packets,
            "fake webrtc camera: connection over"
        );
    }

    /// One datagram from `source`.
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
        if self.rtc.accepts(&input) {
            self.input(input);
        }
    }

    /// Hands `input` to str0m; an error ends the connection.
    fn input(&mut self, input: Input<'_>) {
        if let Err(err) = self.rtc.handle_input(input) {
            tracing::debug!(error = %err, "fake webrtc camera: engine error");
            self.rtc.disconnect();
        }
    }

    /// Sends what str0m wants sent and takes its events; its next timeout,
    /// `None` once the connection is over.
    async fn drain(&mut self) -> Option<Instant> {
        loop {
            if !self.rtc.is_alive() {
                return None;
            }
            match self.rtc.poll_output() {
                Ok(Output::Timeout(at)) => return Some(at),
                Ok(Output::Transmit(transmit)) => {
                    let sent = self
                        .socket
                        .send_to(&transmit.contents, transmit.destination)
                        .await;
                    if let Err(err) = sent {
                        tracing::debug!(error = %err, "fake webrtc camera: send failed");
                    }
                }
                Ok(Output::Event(event)) => self.on_event(event),
                Err(err) => {
                    tracing::debug!(error = %err, "fake webrtc camera: engine error");
                    return None;
                }
            }
        }
    }

    /// One str0m event.
    fn on_event(&mut self, event: Event) {
        match event {
            Event::Connected => {
                self.stats.connected.store(true, Ordering::Relaxed);
                self.video = self
                    .video_mid
                    .and_then(|mid| Some((mid, self.pt(mid, EngineCodec::H264)?)));
                self.audio = self
                    .audio_mid
                    .zip(self.config.audio)
                    .and_then(|(mid, audio)| Some((mid, self.pt(mid, audio.codec())?, audio)));
                let now = self.clock.now();
                self.next_frame = self.video.map(|_| now);
                self.next_audio = self.audio.map(|_| now);
                tracing::debug!(video = ?self.video, audio = ?self.audio, "fake webrtc camera: connected");
            }
            Event::KeyframeRequest(_) => {
                WebRtcCameraStats::bump(&self.stats.keyframe_requests);
                self.keyframe_wanted = true;
            }
            Event::ChannelOpen(_, label) => {
                self.stats
                    .data_channels
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(label);
            }
            Event::Closed => self.stats.peer_closed.store(true, Ordering::Relaxed),
            _ => {}
        }
    }

    /// The first payload type of `codec` the answer negotiated on `mid`:
    /// the one the source carries.
    fn pt(&self, mid: Mid, codec: EngineCodec) -> Option<Pt> {
        let media = self.rtc.media(mid)?;
        let config = self.rtc.codec_config();
        media.remote_pts().iter().copied().find(|pt| {
            config
                .find(|params| params.pt() == *pt)
                .is_some_and(|params| params.spec().codec == codec)
        })
    }

    /// Sends the media due at `now`.
    fn media(&mut self, now: Instant) {
        if let (Some(due), Some((mid, pt))) = (self.next_frame, self.video)
            && due <= now
        {
            self.frame(mid, pt, now);
            let interval = Duration::from_secs(1)
                .checked_div(self.config.fps.max(1))
                .unwrap_or(Duration::from_millis(40));
            self.next_frame = due.checked_add(interval);
        }
        if let (Some(due), Some((mid, pt, audio))) = (self.next_audio, self.audio)
            && due <= now
        {
            self.audio_ts = self.audio_ts.wrapping_add(audio.ticks());
            let seq = self.audio_seq;
            self.audio_seq = self.audio_seq.wrapping_add(1);
            self.write(mid, pt, seq, self.audio_ts, now, true, audio.payload());
            WebRtcCameraStats::bump(&self.stats.audio_packets);
            self.next_audio = due.checked_add(Duration::from_millis(20));
        }
        // Through str0m's pacer at once.
        self.input(Input::Timeout(now));
    }

    /// One picture: a keyframe at the start of every group of pictures or
    /// when one was asked for, else a P picture.
    fn frame(&mut self, mid: Mid, pt: Pt, now: Instant) {
        let gop = self.config.gop.max(1);
        let keyframe = self.keyframe_wanted || self.frames.checked_rem(gop) == Some(0);
        self.keyframe_wanted = false;
        let ticks = 90_000_u32
            .checked_div(self.config.fps.max(1))
            .unwrap_or(3_600);
        self.video_ts = self.video_ts.wrapping_add(ticks);
        let shape = CameraConfig {
            fps: self.config.fps,
            gop,
            // Below str0m's MTU with SRTP's and the extension's overhead.
            mtu: 1_000,
            ..CameraConfig::default()
        };
        let payloads = CameraVideo::H264.access_unit(keyframe, &shape, self.frames);
        let last = payloads.len().saturating_sub(1);
        for (i, payload) in payloads.into_iter().enumerate() {
            let seq = self.video_seq;
            self.video_seq = self.video_seq.wrapping_add(1);
            self.write(
                mid,
                pt,
                seq,
                self.video_ts,
                now,
                i == last,
                payload.to_vec(),
            );
            WebRtcCameraStats::bump(&self.stats.video_packets);
        }
        self.frames = self.frames.wrapping_add(1);
    }

    /// One RTP packet on `mid`, with the RFC 9143 `mid` header extension
    /// when it was negotiated (str0m writes only those).
    #[expect(
        clippy::too_many_arguments,
        reason = "an RTP header's fields, one call site per media kind"
    )]
    fn write(
        &mut self,
        mid: Mid,
        pt: Pt,
        seq: u64,
        ts: u32,
        now: Instant,
        marker: bool,
        payload: Vec<u8>,
    ) {
        let mut api = self.rtc.direct_api();
        let Some(stream) = api.stream_tx_by_mid(mid, None) else {
            return;
        };
        stream.write_rtp(
            RtpWrite::new(pt, SeqNo::from(seq), ts, now, Arc::<[u8]>::from(payload))
                .marker(marker)
                .ext_vals(ExtensionValues {
                    mid: Some(mid),
                    ..ExtensionValues::default()
                }),
        );
        self.packets = self.packets.saturating_add(1);
    }

    /// Closes the connection: its DTLS `close_notify` (RFC 6347 §4.2.7)
    /// and RTCP BYE sent, then str0m inert.
    async fn close(&mut self) {
        if !self.rtc.is_alive() {
            return;
        }
        if let Err(err) = self.rtc.close() {
            tracing::debug!(error = %err, "fake webrtc camera: close");
        }
        self.stats.closed.store(true, Ordering::Relaxed);
        // A closing str0m sends its alert and its BYE, then times out.
        while let Ok(Output::Transmit(transmit)) = self.rtc.poll_output() {
            let sent = self
                .socket
                .send_to(&transmit.contents, transmit.destination)
                .await;
            if let Err(err) = sent {
                tracing::debug!(error = %err, "fake webrtc camera: send failed");
            }
        }
        self.rtc.disconnect();
        tracing::debug!(packets = self.packets, "fake webrtc camera: closed");
    }
}
