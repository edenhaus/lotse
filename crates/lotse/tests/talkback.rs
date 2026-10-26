//! Two-way audio end to end: headless str0m viewers negotiate the dedicated talk-back m-line and send
//! a real tone, Opus from libopus or G.711 in either law, towards a camera whose
//! backchannel is the fake source's.
//!
//! Two layers. The tone tests serve a worker in-process
//! (`lotse_worker::serve`) behind the supervisor's real demux, speaking the
//! supervisor's end of its channel, with the WebRTC output, the talk-back
//! transcoder the binary registers and a capturing fake source
//! (`FakeSourceFactory::capturing`), so the test reads what reaches the
//! backchannel handle and when. The claim-and-hold and activation tests go
//! through the control API: the supervisor in-process with the real demux
//! and a real `lotse worker` subprocess, whose fake source declares a
//! backchannel, the talker read from `talker_changed`, `session/get` and
//! `stream/get`. The RTSP tests serve the same in-process worker with
//! the RTSP source against the fake camera, whose ONVIF backchannel
//! (ONVIF Streaming Specification §5.3) records what arrives: the tone,
//! its `a=ptime` framing, a reconnect under a talker, and the downlink's
//! A/V sync while talking; one goes through the control API to a real
//! worker process running the RTSP source, whose backchannel session is
//! torn down before the process exits at the daemon's shutdown; one more
//! runs that worker under its sandbox, an Opus tone transcoded to the
//! camera's μ-law on the way; and through the control API, a stream
//! opting in and out while a viewer plays the camera.
//! Needs the `source-fake` feature (on with `--all-features`) and
//! `output-webrtc` (a default); the RTSP tests `source-rtsp` (a default)
//! too.

#![cfg(all(feature = "source-fake", feature = "output-webrtc"))]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::net::SocketAddr;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_api_types::command::parse_command;
use lotse_api_types::info::{BuildInfo, LandlockInfo, SandboxInfo};
use lotse_codec::g711::Law;
use lotse_codec::opus::Encoder;
use lotse_codec::transcode::uplink::ToG711Factory;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::registry::Registries;
use lotse_core::runner::RunnerConfig;
use lotse_core::session::SessionLimits;
use lotse_core::source::SourceFactory;
use lotse_core::task::spawn_named;
use lotse_core::test_util::{BackchannelCapture, Captured, FakeSourceFactory};
use lotse_core::track::TrackLimits;
use lotse_ipc::{
    Channel, SessionEvent, SessionSpec, SourceSpec, SourceState, TalkerChange, ToSupervisor,
    ToWorker,
};
use lotse_supervisor::api::{ConnectionId, Event, Handler as _, Outcome};
use lotse_supervisor::net::demux::{Demux, Registration, WorkerSink};
use lotse_supervisor::net::udp::bind_udp;
use lotse_supervisor::worker::WorkerConfig;
use lotse_supervisor::{Environment, FrontDoor, Identity, Limits, Settings, Supervisor};
#[cfg(feature = "source-rtsp")]
use lotse_testing::fake_camera::{
    BackchannelCodec, BackchannelRtp, BackchannelSetup, CameraAudio, CameraBackchannel,
    ConnectionLog, Stats,
};
#[cfg(feature = "source-rtsp")]
use lotse_testing::viewer::capture_seconds;
use lotse_testing::viewer::{Outgoing, Reoffer, TalkbackOffer, Viewer, with_audio_codecs};
#[cfg(feature = "source-rtsp")]
use lotse_testing::{CameraConfig, FakeCamera};
use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// The talk-back packet duration a browser sends, and the camera's frame.
const FRAME: Duration = Duration::from_millis(20);

/// The tone's frequency.
const TONE_HZ: f64 = 1_000.0;

/// The tone's peak, of full scale.
const TONE_LEVEL: f64 = 0.5;

/// Silent packets before the first burst.
const LEAD: u32 = 10;

/// Packets of tone in a burst, then of silence after it.
const BURST: (u32, u32) = (15, 10);

/// Bursts in a tone test, each an onset to time.
const BURSTS: u32 = 5;

/// Packets a tone test sends.
const TONE_PACKETS: u32 = LEAD + BURSTS * (BURST.0 + BURST.1);

/// The daemon's share of the uplink latency, from the browser handing a
/// packet to its socket to the camera taking the frame it completes, for
/// 20 ms packets into 20 ms G.711 frames: a median, so one late wake of a
/// loaded machine cannot fail it. The chain adds no wait there
/// (`ToG711::delay` is zero: no playout buffer, each frame leaves with its
/// packet), so this covers the path alone, with margin for a loaded
/// machine: SRTP and the depacketizer, the talker's route, the transcoder
/// task, the backchannel handle, and for the RTSP source retina's
/// interleaved write and the camera's read.
const UPLINK_LATENCY: Duration = Duration::from_millis(10);

/// How long a tone test keeps listening after the camera took a frame for
/// every packet: no frame may follow, the talker having stopped.
const QUIET: Duration = Duration::from_millis(200);

/// The packet of the PCMU tone test the network loses: in the silence
/// after the first burst.
const LOST: u32 = LEAD + BURST.0 + 5;

/// Whether packet `index` of a tone test carries the tone.
const fn tone_on(index: u32) -> bool {
    index >= LEAD && (index - LEAD) % (BURST.0 + BURST.1) < BURST.0
}

/// The packets of a tone test that start a burst.
fn onsets() -> Vec<u32> {
    (0..BURSTS)
        .map(|burst| LEAD + burst * (BURST.0 + BURST.1))
        .collect()
}

/// Sample `n` of the tone at `rate`, scaled to `[-1, 1]`; silence outside
/// a burst. The phase runs on across packets.
fn tone_sample(n: u64, rate: u32, packet: u32) -> f64 {
    if tone_on(packet) {
        TONE_LEVEL * (2.0 * std::f64::consts::PI * TONE_HZ * n as f64 / f64::from(rate)).sin()
    } else {
        0.0
    }
}

/// What a talking viewer's microphone encodes.
enum MicCodec {
    /// G.711 of this law at 8 kHz with lotse-codec's G.711 (ITU-T G.711),
    /// as a browser sends it natively.
    G711(Law),
    /// Opus at 48 kHz from libopus (RFC 6716), through lotse-codec's
    /// encoder: never a hand-written one.
    Opus(Box<Encoder>),
}

/// A viewer's microphone track: one packet every [`FRAME`] of the tone
/// schedule ([`tone_on`]), stamped with when each left.
struct Mic {
    /// The encoder.
    codec: MicCodec,
    /// The next packet's index.
    index: u32,
    /// The next packet's sequence number and timestamp (RFC 3550 §5.1),
    /// and whether it starts a talk spurt (the marker, RFC 3551 §4.1).
    seq: u16,
    ts: u32,
    marker: bool,
    /// When the next packet is due.
    next: Instant,
    /// The time between packets: [`FRAME`], real time, unless it floods.
    pace: Duration,
    /// When each packet was handed to the socket, by index; for a lost
    /// one, when it would have been.
    sent: Vec<Instant>,
    /// The packets the network loses, by index: their sequence numbers
    /// and timestamps pass, but they never reach the socket.
    lost: Vec<u32>,
    /// Every packet's payload, by index.
    payloads: Vec<Vec<u8>>,
}

impl Mic {
    fn new(codec: MicCodec) -> Self {
        Self {
            codec,
            index: 0,
            seq: 0x1000,
            ts: 0x0010_0000,
            marker: true,
            next: clock().now(),
            pace: FRAME,
            sent: Vec::new(),
            lost: Vec::new(),
            payloads: Vec::new(),
        }
    }

    /// The same microphone sending a packet every `pace`: faster than
    /// real time when under [`FRAME`].
    fn every(mut self, pace: Duration) -> Self {
        self.pace = pace;
        self
    }

    /// The same microphone behind a network that loses packet `index`.
    fn losing(mut self, index: u32) -> Self {
        self.lost.push(index);
        self
    }

    /// The packets that reach the socket, of those sent so far.
    fn delivered(&self) -> usize {
        self.sent.len() - self.lost.len()
    }

    fn pcmu() -> Self {
        Self::new(MicCodec::G711(Law::Mu))
    }

    fn pcma() -> Self {
        Self::new(MicCodec::G711(Law::A))
    }

    fn opus() -> Self {
        Self::new(MicCodec::Opus(Box::new(Encoder::new(1).expect("libopus"))))
    }

    /// Its `a=rtpmap` encoding (RFC 8866 §6.6; RFC 3551 §4.5.14, RFC
    /// 7587 §7).
    const fn encoding(&self) -> &'static str {
        match self.codec {
            MicCodec::G711(Law::Mu) => "PCMU/8000",
            MicCodec::G711(Law::A) => "PCMA/8000",
            MicCodec::Opus(_) => "opus/48000/2",
        }
    }

    /// The sampling rate of its timestamps.
    const fn rate(&self) -> u32 {
        match self.codec {
            MicCodec::G711(_) => 8_000,
            MicCodec::Opus(_) => 48_000,
        }
    }

    /// The next packet's payload and the timestamp step after it.
    fn encode(&mut self) -> (Vec<u8>, u32) {
        let packet = self.index;
        match &mut self.codec {
            MicCodec::G711(law) => {
                let law = *law;
                let first = u64::from(packet) * 160;
                let payload = (first..first + 160)
                    .map(|n| law.encode((tone_sample(n, 8_000, packet) * 32_767.0).round() as i16))
                    .collect();
                (payload, 160)
            }
            MicCodec::Opus(encoder) => {
                let first = u64::from(packet) * 960;
                let pcm: Vec<f32> = (first..first + 960)
                    .map(|n| tone_sample(n, 48_000, packet) as f32)
                    .collect();
                (encoder.encode(&pcm).expect("encodes").to_vec(), 960)
            }
        }
    }
}

/// A headless viewer on its own UDP socket, driven by polling: what it
/// receives, its timers and, while it talks, its microphone.
struct Peer {
    viewer: Viewer,
    socket: UdpSocket,
    /// The offer as sent, which may differ from the viewer's own in its
    /// audio codecs.
    offer: String,
    /// The payload type the answer named first on the talk-back m-line.
    pt: Option<u8>,
    /// Its encoding, as the answer's `a=rtpmap` names it.
    encoding: Option<String>,
    /// The microphone, while talking.
    mic: Option<Mic>,
    out: Vec<Outgoing>,
}

impl Peer {
    /// A viewer offering the dedicated talk-back m-line; `audio_codecs`
    /// replaces the codecs of its audio m-lines in the offer it sends.
    async fn new(audio_codecs: Option<&str>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
        lotse_webrtc::install_crypto_provider();
        let viewer = Viewer::new_with_talkback(
            socket.local_addr().unwrap(),
            clock().now(),
            TalkbackOffer::Dedicated,
        )
        .expect("a viewer");
        let offer = audio_codecs.map_or_else(
            || viewer.offer().to_owned(),
            |codecs| with_audio_codecs(viewer.offer(), codecs),
        );
        Self {
            viewer,
            socket,
            offer,
            pt: None,
            encoding: None,
            mic: None,
            out: Vec::new(),
        }
    }

    /// A viewer receiving audio and video without offering talk-back,
    /// which a re-offer may add later.
    async fn new_silent() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
        lotse_webrtc::install_crypto_provider();
        let viewer =
            Viewer::new_with_audio(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
        let offer = viewer.offer().to_owned();
        Self {
            viewer,
            socket,
            offer,
            pt: None,
            encoding: None,
            mic: None,
            out: Vec::new(),
        }
    }

    /// A client that only talks back: one `sendonly` audio m-line and
    /// no video.
    async fn new_talk_only() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
        lotse_webrtc::install_crypto_provider();
        let viewer =
            Viewer::new_talk_only(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
        let offer = viewer.offer().to_owned();
        Self {
            viewer,
            socket,
            offer,
            pt: None,
            encoding: None,
            mic: None,
            out: Vec::new(),
        }
    }

    /// The viewer's host candidate, as the browser trickles it.
    fn candidate(&self) -> String {
        let addr = self.socket.local_addr().unwrap();
        format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            addr.ip(),
            addr.port()
        )
    }

    fn on_answer(&mut self, sdp: &str) {
        self.viewer
            .accept_answer(sdp, &mut self.out)
            .expect("the answer applies");
        self.pt = talkback_pt(sdp);
        self.encoding = self.pt.and_then(|pt| talkback_encoding(sdp, pt));
    }

    fn on_candidate(&mut self, candidate: &str) {
        if !candidate.is_empty() {
            self.viewer.add_remote_candidate(candidate, &mut self.out);
        }
    }

    /// Starts sending `mic`'s packets, the first one now: the `replaceTrack`
    /// of a browser putting its microphone on the talk-back transceiver.
    /// A microphone that talked before resumes as a browser's does: a new
    /// talk spurt, its timestamp run on by the time that passed.
    fn talk(&mut self, mut mic: Mic) {
        let now = clock().now();
        if let Some(&last) = mic.sent.last() {
            let paused = now.duration_since(last).saturating_sub(FRAME);
            let ticks = paused.as_micros() * u128::from(mic.rate()) / 1_000_000;
            mic.ts = mic.ts.wrapping_add(ticks as u32);
        }
        mic.marker = true;
        mic.next = now;
        self.mic = Some(mic);
    }

    /// Stops the microphone and returns it, with what it sent.
    fn mute(&mut self) -> Mic {
        self.mic.take().expect("talking")
    }

    /// One turn: what arrived, the timers, a microphone packet if one is
    /// due, then everything the viewer wants sent.
    fn poll(&mut self) {
        let mut buf = [0_u8; 2_000];
        while let Ok((len, source)) = self.socket.try_recv_from(&mut buf) {
            self.viewer
                .receive(clock().now(), source, &buf[..len], &mut self.out);
        }
        let now = clock().now();
        if self.viewer.next_timeout().is_none_or(|at| at <= now) {
            self.viewer.timeout(now, &mut self.out);
        }
        if let (Some(mic), Some(pt)) = (self.mic.as_mut(), self.pt)
            && mic.next <= now
        {
            // A browser sends the codec the answer names first (RFC 3264
            // §7), never one codec's bytes under another's payload type:
            // a mismatch is the daemon's answer, which fails here, not as
            // talk-back that never arrives.
            let named = self.encoding.as_deref().unwrap_or("no codec");
            assert!(
                named.eq_ignore_ascii_case(mic.encoding()),
                "the answer names {named} first on the talk-back m-line; the mic sends {}",
                mic.encoding()
            );
            let (payload, step) = mic.encode();
            if !mic.lost.contains(&mic.index) {
                self.viewer
                    .send_talkback(
                        now,
                        (pt, mic.seq, mic.ts, mic.marker),
                        &payload,
                        &mut self.out,
                    )
                    .expect("a send stream on the talk-back m-line");
            }
            mic.sent.push(now);
            mic.payloads.push(payload);
            mic.index += 1;
            mic.marker = false;
            mic.seq = mic.seq.wrapping_add(1);
            mic.ts = mic.ts.wrapping_add(step);
            mic.next += mic.pace;
        }
        for datagram in self.out.drain(..) {
            let _sent = self
                .socket
                .try_send_to(&datagram.payload, datagram.destination);
        }
    }

    /// Packets sent so far.
    fn sent(&self) -> u32 {
        self.mic.as_ref().map_or(0, |mic| mic.index)
    }
}

/// The payload type an answer names first on its last audio m-line, the
/// dedicated talk-back one (after the video): what the browser sends
/// (RFC 3264 §6.1).
fn talkback_pt(sdp: &str) -> Option<u8> {
    sdp.lines()
        .rev()
        .find_map(|line| line.strip_prefix("m=audio "))
        .and_then(|rest| rest.split(' ').nth(2))
        .and_then(|pt| pt.trim().parse().ok())
}

/// The encoding of the payload type `pt` on an answer's last audio m-line
/// (its `a=rtpmap`, RFC 8866 §6.6).
fn talkback_encoding(sdp: &str, pt: u8) -> Option<String> {
    let (_, section) = sdp.rsplit_once("m=audio ")?;
    let prefix = format!("a=rtpmap:{pt} ");
    section
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(|encoding| encoding.trim().to_owned())
}

/// The root mean square of `samples`, of full scale.
fn rms(samples: &[i16]) -> f64 {
    let energy: f64 = samples.iter().map(|&s| f64::from(s).powi(2)).sum();
    (energy / samples.len() as f64).sqrt() / 32_768.0
}

/// The share of `samples`' energy at `hz` (8 kHz sampling), by the
/// Goertzel algorithm: 1 for a pure tone at `hz` over whole periods, near
/// 0 for one at another frequency.
fn tone_share(samples: &[i16], hz: f64) -> f64 {
    let coefficient = 2.0 * (2.0 * std::f64::consts::PI * hz / 8_000.0).cos();
    let (mut s1, mut s2) = (0.0_f64, 0.0_f64);
    for &sample in samples {
        let s0 = coefficient.mul_add(s1, f64::from(sample)) - s2;
        s2 = s1;
        s1 = s0;
    }
    let power = coefficient.mul_add(-s1 * s2, s1.mul_add(s1, s2 * s2));
    let energy: f64 = samples.iter().map(|&s| f64::from(s).powi(2)).sum();
    2.0 * power / (samples.len() as f64 * energy)
}

/// The `p`th percentile of `values`, nearest rank.
fn percentile(values: &[Duration], p: usize) -> Duration {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

// ---------------------------------------------------------------------
// The in-process worker of the tone tests.
// ---------------------------------------------------------------------

/// A worker served in-process behind the demux: the capturing fake source,
/// the WebRTC output and the talk-back transcoder, on the system clock.
struct InProcess {
    tx: lotse_ipc::Sender,
    messages: mpsc::Receiver<ToSupervisor>,
    demux: Demux,
    local: SocketAddr,
    datagrams: Arc<UnixDatagram>,
    registrations: Vec<Arc<Registration>>,
    worker: tokio::task::JoinHandle<Result<lotse_worker::ExitReason, lotse_worker::Error>>,
    /// Every session event, in order.
    events: Vec<(String, SessionEvent)>,
    /// Every change of the talker, in order.
    talkers: Vec<TalkerChange>,
    live: bool,
}

impl InProcess {
    async fn start(capture: &BackchannelCapture, options: &str) -> Self {
        let factory = Arc::new(FakeSourceFactory::capturing(&["fake"], capture.clone()));
        Self::start_with(factory, "fake://cam/", options, vec![]).await
    }

    /// The worker running the RTSP source against `camera`, opted in to
    /// its backchannel.
    #[cfg(feature = "source-rtsp")]
    async fn rtsp(camera: &FakeCamera) -> Self {
        let factory = Arc::new(lotse_rtsp::RtspFactory::default());
        Self::start_with(
            factory,
            &camera.url(),
            r#"{"backchannel": true}"#,
            vec![camera.addr()],
        )
        .await
    }

    /// The worker running `url` with `options` from `factory`, resolved
    /// to `peer_addrs`, until the source is live.
    async fn start_with(
        factory: Arc<dyn SourceFactory>,
        url: &str,
        options: &str,
        peer_addrs: Vec<SocketAddr>,
    ) -> Self {
        let mut registries = Registries::default();
        registries.sources.register(factory).unwrap();
        registries
            .outputs
            .register(Arc::new(lotse_webrtc::WebRtcFactory))
            .unwrap();
        registries.uplink = Some(Arc::new(ToG711Factory::new(clock())));
        let (ours, theirs) = Channel::pair().unwrap();
        let channel = Channel::from_fd(theirs).unwrap();
        let settings = lotse_worker::Settings {
            worker_threads: 1,
            limits: TrackLimits::default(),
            runner: RunnerConfig::default(),
            session: SessionLimits::default(),
            max_sessions: 256,
            shared_udp_fd: None,
            clip: lotse_worker::ClipSettings::default(),
        };
        let registries = Arc::new(registries);
        let worker = spawn_named("test.worker", async move {
            lotse_worker::serve(channel, registries, clock(), &settings, None).await
        });
        let (mut tx, mut rx) = ours.split();
        let (forward, messages) = mpsc::channel(1_024);
        spawn_named("test.worker_messages", async move {
            while let Ok(Some((message, _fds))) = rx.recv_msg::<ToSupervisor>().await {
                if forward.send(message).await.is_err() {
                    break;
                }
            }
        });
        let bound = bind_udp("127.0.0.1:0".parse().unwrap()).expect("the shared socket");
        let demux = Demux::start(Arc::clone(&bound.socket), bound.local, bound.hosts, clock())
            .expect("the demux");
        let (datagrams, worker_end) = lotse_ipc::datagram::datagram_pair().unwrap();
        let datagrams = UnixDatagram::from(datagrams);
        datagrams.set_nonblocking(true).unwrap();
        tx.send_msg(
            &ToWorker::Sockets,
            &[bound.socket.as_fd(), worker_end.as_fd()],
        )
        .await
        .unwrap();
        tx.send_msg(
            &ToWorker::RunSource(SourceSpec {
                connection_id: "c1".into(),
                url: url.into(),
                options: options.into(),
                peer_host: "cam".into(),
                peer_addrs,
                backoff: lotse_ipc::BackoffPosition::default(),
                preroll_ms: 0,
            }),
            &[],
        )
        .await
        .unwrap();
        let mut worker = Self {
            tx,
            messages,
            demux,
            local: bound.local,
            datagrams: Arc::new(datagrams),
            registrations: Vec::new(),
            worker,
            events: Vec::new(),
            talkers: Vec::new(),
            live: false,
        };
        worker.pump(&mut [], |w, _| w.live).await;
        worker
    }

    /// Opens session `id` on `offer`, registered with the demux under its
    /// own credentials.
    async fn open(&mut self, id: &str, offer: &str) {
        self.open_with(id, offer, false).await;
    }

    /// [`Self::open`], with the camera's `audio` asked for.
    async fn open_with(&mut self, id: &str, offer: &str, audio: bool) {
        let ufrag = format!("ufrag{id}");
        let pass = "talkbackpassword01234567";
        self.registrations.push(self.demux.registrations().register(
            &ufrag,
            pass.as_bytes().to_vec(),
            Arc::new(WorkerSink {
                datagrams: Arc::clone(&self.datagrams),
            }),
        ));
        self.tx
            .send_msg(
                &ToWorker::OpenSession(SessionSpec {
                    session_id: id.into(),
                    kind: "webrtc".into(),
                    offer: offer.to_owned(),
                    ice_ufrag: ufrag,
                    ice_pass: pass.into(),
                    candidates: vec![self.local],
                    tcp_candidates: vec![],
                    audio,
                    orientation: 1,
                }),
                &[],
            )
            .await
            .unwrap();
    }

    /// A re-offer for session `id`, whose answer [`Self::pump`] applies
    /// to its peer.
    async fn renegotiate(&mut self, id: &str, sdp: &str) {
        self.tx
            .send_msg(
                &ToWorker::Renegotiate {
                    session_id: id.into(),
                    sdp: sdp.into(),
                },
                &[],
            )
            .await
            .unwrap();
    }

    /// Polls the worker and `peers` (session `i` is `peers[i]`'s, named by
    /// its index) until `done`; twenty seconds without fail the test.
    async fn pump(&mut self, peers: &mut [&mut Peer], done: impl Fn(&Self, &[&mut Peer]) -> bool) {
        let deadline = clock().now() + Duration::from_secs(20);
        while !done(self, peers) {
            assert!(
                clock().now() < deadline,
                "timed out; events {:?}",
                self.events
            );
            while let Ok(message) = self.messages.try_recv() {
                match message {
                    ToSupervisor::SourceState(
                        SourceState::Connecting { .. } | SourceState::Reconnecting { .. },
                    ) => {
                        self.tx
                            .send_msg(&ToWorker::ConnectGranted, &[])
                            .await
                            .unwrap();
                    }
                    ToSupervisor::ProbeConnecting { probe } => {
                        self.tx
                            .send_msg(&ToWorker::ProbeConnectGranted { probe }, &[])
                            .await
                            .unwrap();
                    }
                    ToSupervisor::SourceState(SourceState::Live) => self.live = true,
                    ToSupervisor::Talker(change) => self.talkers.push(change),
                    ToSupervisor::Session { session_id, event } => {
                        let index: usize = session_id.parse().expect("sessions named by index");
                        let peer = &mut *peers[index];
                        match &event {
                            SessionEvent::Answer { sdp, .. } => {
                                peer.on_answer(sdp);
                                self.tx
                                    .send_msg(
                                        &ToWorker::RemoteCandidate {
                                            session_id: session_id.clone(),
                                            candidate: peer.candidate(),
                                        },
                                        &[],
                                    )
                                    .await
                                    .unwrap();
                            }
                            SessionEvent::Candidate { candidate, .. } => {
                                peer.on_candidate(candidate);
                            }
                            SessionEvent::Renegotiated { sdp, .. } => peer.on_answer(sdp),
                            _ => {}
                        }
                        self.events.push((session_id, event));
                    }
                    _ => {}
                }
            }
            for peer in peers.iter_mut() {
                peer.poll();
            }
            clock().sleep(Duration::from_millis(1)).await;
        }
    }

    /// Closes session `id`, as the supervisor does for its client.
    #[cfg(feature = "source-rtsp")]
    async fn close(&mut self, id: &str) {
        self.tx
            .send_msg(
                &ToWorker::CloseSession {
                    session_id: id.into(),
                    code: "session_closed".into(),
                    message: "bye".into(),
                },
                &[],
            )
            .await
            .unwrap();
    }

    /// Frees the backchannel from its talker (`backchannel/release`).
    #[cfg(feature = "source-rtsp")]
    async fn release(&mut self) {
        self.tx
            .send_msg(&ToWorker::ReleaseBackchannel { session_id: None }, &[])
            .await
            .unwrap();
    }

    async fn stop(mut self) {
        self.tx
            .send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        let exit = self.worker.await.unwrap().unwrap();
        assert_eq!(exit, lotse_worker::ExitReason::Shutdown);
        self.demux.stop();
    }
}

impl ToneRun {
    /// What the camera's backchannel took.
    fn frames(&self) -> Vec<Frame> {
        self.captured.iter().map(Frame::from).collect()
    }
}

/// What a tone test measured.
struct ToneRun {
    /// Every packet the camera's backchannel took, in order.
    captured: Vec<Captured>,
    /// The microphone, with what it sent and when.
    mic: Mic,
    /// The payload type the browser sent in.
    pt: u8,
    /// The talk-back codec the answer named, as the worker reported it.
    talkback: Option<String>,
}

/// One viewer negotiates talk-back with a camera whose backchannel takes
/// `camera` (`pcmu`, `pcma`), offering `audio_codecs` (all of str0m's when
/// `None`), and talks the tone schedule through `mic` until the camera
/// has taken every packet's frame.
async fn tone_run(camera: &str, audio_codecs: Option<&str>, mic: Mic) -> ToneRun {
    let capture = BackchannelCapture::default();
    let mut worker = InProcess::start(&capture, &format!(r#"{{"backchannel": "{camera}"}}"#)).await;
    let mut peer = Peer::new(audio_codecs).await;
    worker.open("0", &peer.offer).await;
    worker
        .pump(&mut [&mut peer], |_, peers| peers[0].viewer.is_connected())
        .await;
    let talkback = worker.events.iter().find_map(|(_, event)| match event {
        SessionEvent::Answer { talkback, .. } => talkback.clone(),
        _ => None,
    });
    assert_eq!(
        peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::SendOnly),
        "talk-back answered recvonly"
    );
    peer.talk(mic);
    worker
        .pump(&mut [&mut peer], |_, peers| peers[0].sent() >= TONE_PACKETS)
        .await;
    let mic = peer.mute();
    // Every delivered packet's frame, then a while for anything after it.
    let delivered = mic.delivered();
    worker
        .pump(&mut [&mut peer], |_, _| {
            capture.packets().len() >= delivered
        })
        .await;
    let quiet = clock().now() + QUIET;
    worker
        .pump(&mut [&mut peer], |_, _| clock().now() >= quiet)
        .await;
    let pt = peer.pt.expect("a talk-back payload type");
    worker.stop().await;
    ToneRun {
        captured: capture.captured(),
        mic,
        pt,
        talkback,
    }
}

/// One frame as the camera's backchannel took it: the RTP header fields
/// that matter, the payload, and when it arrived.
struct Frame {
    pt: u8,
    seq: u16,
    ts: u32,
    marker: bool,
    payload: Vec<u8>,
    at: Instant,
}

impl From<&Captured> for Frame {
    fn from(captured: &Captured) -> Self {
        let rtp = captured.packet.rtp;
        Self {
            pt: rtp.pt,
            seq: rtp.seq,
            ts: rtp.ts,
            marker: rtp.marker,
            payload: captured.packet.payload.to_vec(),
            at: captured.at,
        }
    }
}

#[cfg(feature = "source-rtsp")]
impl From<&BackchannelRtp> for Frame {
    fn from(rtp: &BackchannelRtp) -> Self {
        Self {
            pt: rtp.payload_type,
            seq: rtp.sequence_number,
            ts: rtp.timestamp,
            marker: rtp.marker,
            payload: rtp.payload.clone(),
            at: rtp.arrival,
        }
    }
}

/// The frames of one talk spurt as the camera took them from `mic`'s
/// packets, `frame` to a frame (a whole number of [`FRAME`]s): whole G.711
/// frames of the camera's `pt` and `frame`'s samples, the marker on the
/// first only (RFC 3551 §4.1), sequence numbers one apart, and timestamps
/// that put each frame where its audio sat on the browser's timeline, so
/// they run on over a lost packet (RFC 3550 §5.1). No pacing: each frame
/// leaves after the browser sent the last packet it carries, never before
/// (the camera gets no audio the browser did not send, no burst ahead of
/// it), and within [`UPLINK_LATENCY`] of it in the median. Returns each
/// frame's slot: the index of its first packet, `frame` apart.
fn check_frames(frames: &[Frame], pt: u8, frame: Duration, mic: &Mic) -> Vec<usize> {
    let per_frame = usize::try_from(frame.as_millis() / FRAME.as_millis()).unwrap();
    let samples = u32::try_from(frame.as_millis() * 8).unwrap();
    // The frames the delivered packets fill, by slot.
    let mut slots: Vec<usize> = (0..mic.sent.len())
        .filter(|&index| !mic.lost.contains(&(index as u32)))
        .map(|index| index / per_frame * per_frame)
        .collect();
    slots.dedup();
    assert!(
        frames.len() <= slots.len(),
        "{} frames from the audio of {} packets",
        frames.len(),
        mic.delivered()
    );
    let mut lags = Vec::new();
    for (i, (packet, &slot)) in frames.iter().zip(&slots).enumerate() {
        // RFC 3551 §4.5.14: 8000 Hz, a frame of `samples`.
        assert_eq!(packet.pt, pt, "frame {i}");
        assert_eq!(packet.payload.len(), samples as usize, "frame {i}");
        assert_eq!(packet.marker, i == 0, "frame {i}");
        assert_eq!(packet.seq.wrapping_sub(frames[0].seq), i as u16);
        assert_eq!(
            packet.ts.wrapping_sub(frames[0].ts),
            (slot - slots[0]) as u32 * 160,
            "frame {i} on the browser's timeline"
        );
        let last = mic.sent[slot + per_frame - 1];
        assert!(
            packet.at >= last,
            "frame {i} left before the browser sent its audio"
        );
        lags.push(packet.at.duration_since(last));
    }
    let median = percentile(&lags, 50);
    assert!(
        median <= UPLINK_LATENCY,
        "frames {median:?} after their last packet in the median: {lags:?}"
    );
    slots.truncate(frames.len());
    slots
}

/// The checks every tone run passes:
/// whole 20 ms G.711 frames of the camera's law on the browser's
/// timeline, each right after its packet ([`check_frames`]), one per
/// delivered packet and none after; the tone at its frequency in every
/// burst; and the daemon's share of the latency, onset in to onset out at
/// the camera. Returns the latency of each onset.
fn check_tone(frames: &[Frame], mic: &Mic, law: Law) -> Vec<Duration> {
    let slots = check_frames(frames, law.payload_type(), FRAME, mic);
    assert_eq!(
        frames.len(),
        mic.delivered(),
        "a frame for each packet the browser delivered, nothing more"
    );
    // Each packet's audio by its index; a lost one's is silence.
    let mut pcm = vec![vec![0_i16; 160]; TONE_PACKETS as usize];
    let mut at = vec![None; TONE_PACKETS as usize];
    for ((frame, samples), &slot) in frames.iter().zip(decode(frames, law)).zip(&slots) {
        pcm[slot] = samples;
        at[slot] = Some(frame.at);
    }

    // The tone survives at its frequency: in each burst's inner frames
    // (its edges carry the onset and the decay), nearly all of the energy
    // is at 1 kHz, next to none at the neighbours.
    for (burst, &onset) in onsets().iter().enumerate() {
        let inner: Vec<i16> = pcm[onset as usize + 1..(onset + BURST.0) as usize - 1]
            .iter()
            .flatten()
            .copied()
            .collect();
        let level = rms(&inner);
        assert!(level > 0.25, "burst {burst} at {level:.3} of full scale");
        let at_tone = tone_share(&inner, TONE_HZ);
        assert!(
            at_tone > 0.8,
            "burst {burst}: {at_tone:.3} of the energy at 1 kHz"
        );
        for other in [500.0, 1_500.0, 2_000.0, 3_000.0] {
            let share = tone_share(&inner, other);
            assert!(share < 0.02, "burst {burst}: {share:.3} at {other} Hz");
        }
    }
    // Silence stays silent between bursts.
    for gap in onsets().iter().map(|onset| onset + BURST.0 + 2) {
        let level = rms(&pcm[gap as usize]);
        assert!(level < 0.01, "frame {gap} at {level:.3}");
    }

    // The onset: the first frame out loud after a quiet one, against when
    // the browser sent the first packet of the burst. Both on the system
    // clock, the worker's injected one.
    let loud: Vec<bool> = pcm.iter().map(|samples| rms(samples) > 0.05).collect();
    let onsets_out: Vec<usize> = (1..loud.len())
        .filter(|&i| loud[i] && !loud[i - 1])
        .collect();
    assert_eq!(
        onsets_out.len(),
        BURSTS as usize,
        "one onset per burst: {loud:?}"
    );
    onsets()
        .iter()
        .zip(&onsets_out)
        .map(|(&onset_in, &onset_out)| {
            at[onset_out]
                .expect("a loud frame arrived")
                .saturating_duration_since(mic.sent[onset_in as usize])
        })
        .collect()
}

/// The samples of each of `frames` in `law`.
fn decode(frames: &[Frame], law: Law) -> Vec<Vec<i16>> {
    frames
        .iter()
        .map(|frame| frame.payload.iter().map(|&code| law.decode(code)).collect())
        .collect()
}

/// The latency gate on a run's onsets: their median, so one late wake of
/// a loaded machine cannot fail it, within [`UPLINK_LATENCY`]. Returns the
/// median.
fn check_latency(latencies: &[Duration]) -> Duration {
    let median = percentile(latencies, 50);
    assert!(
        median <= UPLINK_LATENCY,
        "the daemon added {median:?} to the uplink: {latencies:?}"
    );
    median
}

/// The reverse chain: a browser that offers only Opus talks to a PCMU
/// camera. libopus's packets go through the depacketizer, the talker's
/// route and `ToG711` (Opus decoded at 8 kHz, μ-law encoded, each frame
/// sent as its packet completes it) into the backchannel handle as the
/// tone, in time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc6716_an_opus_tone_reaches_a_pcmu_camera_at_its_frequency_within_10_ms() {
    let run = tone_run(
        "pcmu",
        Some("a=rtpmap:111 opus/48000/2\na=fmtp:111 minptime=10;useinbandfec=1"),
        Mic::opus(),
    )
    .await;
    assert_eq!(run.pt, 111, "the browser sends Opus");
    assert_eq!(run.talkback.as_deref(), Some("opus"));
    let latencies = check_tone(&run.frames(), &run.mic, Law::Mu);
    let median = check_latency(&latencies);
    println!("Opus to PCMU: uplink latency per onset {latencies:?}, median {median:?}");
}

/// The reverse chain, G.711 in and out: the browser offers PCMU and
/// the camera wants PCMU, so the answer names PCMU and the codes pass
/// through untouched; only the RTP header changes. The network loses one
/// packet: nothing is sent in its place, and the timestamps run on over
/// it (RFC 3550 §5.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3551_4_5_14_a_pcmu_tone_passes_through_to_a_pcmu_camera_within_10_ms() {
    let run = tone_run("pcmu", None, Mic::pcmu().losing(LOST)).await;
    assert_eq!(run.pt, 0, "the browser sends PCMU (RFC 3551 Table 4)");
    assert_eq!(run.talkback.as_deref(), Some("pcmu"));
    let latencies = check_tone(&run.frames(), &run.mic, Law::Mu);
    // The frames are the browser's delivered packets, code for code.
    let delivered: Vec<&Vec<u8>> = run
        .mic
        .payloads
        .iter()
        .enumerate()
        .filter(|&(index, _)| index as u32 != LOST)
        .map(|(_, payload)| payload)
        .collect();
    let identical = run
        .captured
        .iter()
        .zip(&delivered)
        .filter(|(frame, sent)| *frame.packet.payload == sent[..])
        .count();
    assert_eq!(identical, delivered.len(), "frames as sent");
    let frames = run.frames();
    let after = &frames[LOST as usize];
    let before = &frames[LOST as usize - 1];
    assert_eq!(after.ts.wrapping_sub(before.ts), 320, "RFC 3550 §5.1");
    assert_eq!(after.seq.wrapping_sub(before.seq), 1);
    assert!(!after.marker, "a lost packet does not end the spurt");
    let median = check_latency(&latencies);
    println!("PCMU to PCMU: uplink latency per onset {latencies:?}, median {median:?}");
}

/// The cross-law rows: a browser that leaves the camera's G.711 law out
/// of its talk-back m-line, offering the other law and Opus, sends the
/// other law (RFC 7874 §3 has every browser implement both), and the
/// reverse chain converts each code by G.711's tables (ITU-T G.711
/// Tables 3 and 4): the camera gets its own law, code for code the
/// table's image of what the browser sent, as the tone, in time.
async fn cross_law(camera: &str, offered: &str, mic: Mic, from: Law, to: Law) -> Duration {
    let codecs =
        format!("a=rtpmap:111 opus/48000/2\na=fmtp:111 minptime=10;useinbandfec=1\n{offered}");
    let run = tone_run(camera, Some(&codecs), mic).await;
    assert_eq!(
        run.pt,
        from.payload_type(),
        "the browser sends its own law (RFC 3551 Table 4)"
    );
    assert_eq!(run.talkback.as_deref(), Some(from.codec().name()));
    let latencies = check_tone(&run.frames(), &run.mic, to);
    let converted = run
        .captured
        .iter()
        .zip(&run.mic.payloads)
        .filter(|(frame, sent)| {
            let table: Vec<u8> = sent.iter().map(|&code| to.transcode(from, code)).collect();
            *frame.packet.payload == table[..]
        })
        .count();
    assert_eq!(
        converted,
        run.mic.payloads.len(),
        "frames converted code for code"
    );
    check_latency(&latencies)
}

/// PCMU from the browser to a PCMA camera (G.711 Table 3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g711_table_3_a_pcmu_tone_reaches_a_pcma_camera_converted_within_10_ms() {
    let median = cross_law("pcma", "a=rtpmap:0 PCMU/8000", Mic::pcmu(), Law::Mu, Law::A).await;
    println!("PCMU to PCMA: uplink latency median {median:?}");
}

/// PCMA from the browser to a PCMU camera (G.711 Table 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g711_table_4_a_pcma_tone_reaches_a_pcmu_camera_converted_within_10_ms() {
    let median = cross_law("pcmu", "a=rtpmap:8 PCMA/8000", Mic::pcma(), Law::A, Law::Mu).await;
    println!("PCMA to PCMU: uplink latency median {median:?}");
}

// ---------------------------------------------------------------------
// The RTSP source, in the in-process worker, against the fake camera's
// ONVIF backchannel.
// ---------------------------------------------------------------------

/// A fake camera with video, `audio` and an ONVIF backchannel in `codec`
/// that asks for `ptime` ms packets (`a=ptime`, RFC 8866 §6.4).
#[cfg(feature = "source-rtsp")]
async fn rtsp_camera(
    audio: Option<CameraAudio>,
    codec: BackchannelCodec,
    ptime: u32,
) -> FakeCamera {
    let config = CameraConfig {
        audio,
        backchannel: Some(CameraBackchannel {
            ptime: Some(ptime),
            ..CameraBackchannel::new(codec)
        }),
        keep_open_on_teardown: true,
        ..CameraConfig::default()
    };
    FakeCamera::start(config, clock())
        .await
        .expect("the camera")
}

/// Session 0 of `worker`: a viewer that negotiates talk-back, the
/// camera's audio asked for when `audio`, and talks `mic`.
#[cfg(feature = "source-rtsp")]
async fn talking(worker: &mut InProcess, audio: bool, mic: Mic) -> Peer {
    let mut peer = Peer::new(None).await;
    worker.open_with("0", &peer.offer, audio).await;
    worker
        .pump(&mut [&mut peer], |_, peers| peers[0].viewer.is_connected())
        .await;
    peer.talk(mic);
    peer
}

/// Everything `camera`'s backchannel took, once it took `count` packets.
#[cfg(feature = "source-rtsp")]
async fn camera_frames(
    worker: &mut InProcess,
    peer: &mut Peer,
    camera: &FakeCamera,
    count: u64,
) -> Vec<Frame> {
    worker
        .pump(&mut [peer], |_, _| {
            Stats::get(&camera.stats().backchannel_packets) >= count
        })
        .await;
    camera
        .stats()
        .backchannel()
        .iter()
        .map(Frame::from)
        .collect()
}

/// The browser's PCMU tone through the RTSP source to the camera
/// (ONVIF Streaming Specification §5.3): retina sends the talk-back
/// chain's frames on the backchannel's interleaved channel, and the
/// camera takes them in its payload type and `a=ptime`, continuous, each
/// right after its packet, and within the daemon's 10 ms.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_a_pcmu_tone_through_the_rtsp_source_reaches_the_camera_within_10_ms() {
    let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 20).await;
    let mut worker = InProcess::rtsp(&camera).await;
    let mut peer = talking(&mut worker, false, Mic::pcmu()).await;
    worker
        .pump(&mut [&mut peer], |_, peers| peers[0].sent() >= TONE_PACKETS)
        .await;
    let mic = peer.mute();
    camera_frames(&mut worker, &mut peer, &camera, TONE_PACKETS.into()).await;
    let quiet = clock().now() + QUIET;
    worker
        .pump(&mut [&mut peer], |_, _| clock().now() >= quiet)
        .await;
    let frames = camera_frames(&mut worker, &mut peer, &camera, TONE_PACKETS.into()).await;
    let latencies = check_tone(&frames, &mic, Law::Mu);
    assert_eq!(Stats::get(&camera.stats().backchannel_refused), 0);
    let median = check_latency(&latencies);
    println!("PCMU through RTSP: uplink latency per onset {latencies:?}, median {median:?}");
    worker.stop().await;
    camera.stop().await;
}

/// A browser floods the talk-back uplink to an RTSP camera taking
/// `codec`: `mic`'s 20 ms packets every 4 ms for a second, five times real
/// time. What the camera's backchannel took, how many packets the browser
/// sent, and for how long.
#[cfg(feature = "source-rtsp")]
async fn rtsp_flood(codec: BackchannelCodec, mic: Mic) -> (Vec<Frame>, usize, Duration) {
    let camera = rtsp_camera(None, codec, 20).await;
    let mut worker = InProcess::rtsp(&camera).await;
    let mic = mic.every(Duration::from_millis(4));
    let mut peer = talking(&mut worker, false, mic).await;
    let start = clock().now();
    worker
        .pump(&mut [&mut peer], |_, _| {
            clock().now() >= start + Duration::from_secs(1)
        })
        .await;
    let mic = peer.mute();
    let talked = clock().now().duration_since(start);
    let quiet = clock().now() + QUIET;
    worker
        .pump(&mut [&mut peer], |_, _| clock().now() >= quiet)
        .await;
    let frames = camera
        .stats()
        .backchannel()
        .iter()
        .map(Frame::from)
        .collect();
    worker.stop().await;
    camera.stop().await;
    (frames, mic.sent.len(), talked)
}

/// What an RTSP camera took of a flood (`rtsp_flood`) at its clock
/// `rate`: the session's pace let through no more than real time and its
/// lead, and the camera's timestamps never ran ahead of the packets'
/// arrivals by more than the packetizer's lead (250 ms), with margin for
/// a loaded machine's late wakes; unbounded, they run seconds ahead
/// within the second (RFC 3550 §5.1: timestamps follow the sampling
/// clock, which runs in real time).
#[cfg(feature = "source-rtsp")]
fn check_flood(frames: &[Frame], sent: usize, talked: Duration, rate: u32) {
    let real_time = (talked.as_millis() / FRAME.as_millis()) as usize;
    assert!(
        sent >= 2 * real_time,
        "the browser flooded: {sent} packets in {talked:?}"
    );
    assert!(
        frames.len() <= real_time + 8,
        "{} frames in {talked:?}: at most real time",
        frames.len()
    );
    let first = frames
        .first()
        .expect("the camera took the flood's first packets");
    let ahead = frames
        .iter()
        .map(|frame| {
            let ticks = u64::from(frame.ts.wrapping_sub(first.ts));
            let audio = Duration::from_micros(ticks * 1_000_000 / u64::from(rate));
            audio.saturating_sub(frame.at.duration_since(first.at))
        })
        .max()
        .unwrap();
    assert!(
        ahead <= Duration::from_millis(500),
        "{} frames of {sent} packets: timestamps up to {ahead:?} ahead",
        frames.len()
    );
}

/// The talk-back chain's route: the pace drops what runs ahead, the chain
/// bridges the dropped packets' spans as gaps, and the packetizer keeps
/// the camera's timestamps to the wall clock over them.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3550_5_1_a_pcmu_flood_reaches_an_rtsp_camera_on_wall_clock_timestamps() {
    let (frames, sent, talked) = Box::pin(rtsp_flood(BackchannelCodec::Pcmu, Mic::pcmu())).await;
    check_flood(&frames, sent, talked, 8_000);
}

/// Opus to an Opus camera, forwarded as received: no chain, so the
/// packetizer alone keeps the survivors' timestamps, 100 ms apart on the
/// browser's timeline, to the wall clock.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc7587_4_1_an_opus_flood_forwarded_to_an_opus_camera_keeps_to_the_wall_clock() {
    let (frames, sent, talked) = Box::pin(rtsp_flood(BackchannelCodec::Opus, Mic::opus())).await;
    check_flood(&frames, sent, talked, 48_000);
}

/// A viewer playing the camera re-offers talk-back (`webrtc/renegotiate`
/// through the worker): the re-offer claims the backchannel, its answer
/// takes the dedicated m-line in the camera's PCMU, and the browser's
/// packets reach the camera through the RTSP source as frames in its
/// payload type (ONVIF Streaming Specification §5.3), as they do for an
/// offer that asked from the start; a re-offer that drops talk-back lets
/// go, and nothing more reaches the camera.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_a_re_offer_adds_talk_back_whose_tone_reaches_the_camera() {
    let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 20).await;
    let mut worker = InProcess::rtsp(&camera).await;
    let mut peer = Peer::new_silent().await;
    worker.open("0", &peer.offer).await;
    worker
        .pump(&mut [&mut peer], |_, peers| peers[0].viewer.is_connected())
        .await;
    assert_eq!(peer.viewer.talkback_direction(), None);
    assert!(worker.talkers.is_empty());
    let reoffer = peer
        .viewer
        .reoffer(Reoffer::Talkback(TalkbackOffer::Dedicated))
        .expect("a re-offer");
    worker.renegotiate("0", &reoffer).await;
    let renegotiated = |events: &[(String, SessionEvent)]| {
        events.iter().any(|(_, event)| {
            matches!(event, SessionEvent::Renegotiated { talkback: Some(codec), .. } if codec == "pcmu")
        })
    };
    // ONVIF Streaming Specification §5.3: the answer waits for the
    // backchannel session's `PLAY`, on a connection of its own.
    worker
        .pump(&mut [&mut peer], |w, _| {
            let answered = renegotiated(&w.events);
            assert!(
                !answered || backchannel_session(&camera).is_some_and(|log| log.played),
                "answered before the backchannel session played"
            );
            answered
        })
        .await;
    let log = backchannel_session(&camera).unwrap();
    assert_eq!(log.describes, [true]);
    assert_eq!(log.setups, ["backchannel"]);
    assert_eq!(peer.pt, Some(0), "the camera's PCMU");
    assert_eq!(
        peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::SendOnly)
    );
    peer.talk(Mic::pcmu());
    worker
        .pump(&mut [&mut peer], |_, peers| peers[0].sent() >= 25)
        .await;
    let mic = peer.mute();
    let frames = camera_frames(&mut worker, &mut peer, &camera, 25).await;
    check_frames(&frames[..25], 0, FRAME, &mic);
    // Dropped: let go, and what the browser sends after it goes nowhere.
    let reoffer = peer.viewer.reoffer(Reoffer::Drop).expect("a re-offer");
    let answered = worker.events.len();
    worker.renegotiate("0", &reoffer).await;
    worker
        .pump(&mut [&mut peer], |w, _| {
            w.events[answered..].iter().any(|(_, event)| {
                matches!(event, SessionEvent::Renegotiated { talkback: None, .. })
            })
        })
        .await;
    let taken = Stats::get(&camera.stats().backchannel_packets);
    peer.talk(mic);
    let quiet = clock().now() + Duration::from_millis(500);
    worker
        .pump(&mut [&mut peer], |_, _| clock().now() >= quiet)
        .await;
    assert_eq!(Stats::get(&camera.stats().backchannel_packets), taken);
    let changes: Vec<(&str, &str)> = worker
        .talkers
        .iter()
        .map(|change| (change.session_id.as_str(), change.reason.as_str()))
        .collect();
    assert_eq!(changes, [("0", "claimed"), ("0", "renegotiated")]);
    // The release tore the session down with `Require` and closed its
    // connection.
    let log = backchannel_session(&camera).unwrap();
    assert_eq!(log.teardown, Some(true));
    assert!(log.closed_by_client, "{log:?}");
    worker.stop().await;
    camera.stop().await;
}

/// RFC 8866 §6.4: a camera whose backchannel asks for `a=ptime:40` takes
/// 40 ms frames of 320 samples, each as the browser's second 20 ms packet
/// for it arrives, the tone in them.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8866_6_4_a_cameras_ptime_of_40_ms_frames_the_tone_in_40_ms_packets() {
    let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 40).await;
    let mut worker = InProcess::rtsp(&camera).await;
    let mut peer = talking(&mut worker, false, Mic::pcmu()).await;
    worker
        .pump(&mut [&mut peer], |_, peers| peers[0].sent() >= TONE_PACKETS)
        .await;
    let mic = peer.mute();
    let count = TONE_PACKETS / 2;
    let frames = camera_frames(&mut worker, &mut peer, &camera, count.into()).await;
    let frames = &frames[..count as usize];
    check_frames(frames, Law::Mu.payload_type(), FRAME * 2, &mic);
    // Two of the browser's packets a frame: the first burst's inner
    // frames carry the tone.
    let pcm = decode(frames, Law::Mu);
    let onset = (LEAD / 2) as usize;
    for (i, samples) in pcm.iter().enumerate().take(onset + 5).skip(onset + 1) {
        let share = tone_share(samples, TONE_HZ);
        assert!(share > 0.8, "frame {i}: {share:.3} of the energy at 1 kHz");
    }
    worker.stop().await;
    camera.stop().await;
}

/// The connection log of `camera`'s last backchannel session, if any.
#[cfg(feature = "source-rtsp")]
fn backchannel_session(camera: &FakeCamera) -> Option<ConnectionLog> {
    camera
        .stats()
        .connection_log()
        .into_iter()
        .rev()
        .find(ConnectionLog::backchannel_only)
}

/// The talker changes of `worker` so far, as `(session, reason)`.
#[cfg(feature = "source-rtsp")]
fn changes(worker: &InProcess) -> Vec<(String, String)> {
    worker
        .talkers
        .iter()
        .map(|change| (change.session_id.clone(), change.reason.clone()))
        .collect()
}

/// A viewing reconnect under a talker: the camera drops the viewing
/// session's connection, the source reconnects and probes again, and the
/// talker's backchannel session, a connection of its own, carries on: one
/// RTP stream (RFC 3550 §5.1), one claim, nothing declined.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_a_viewing_reconnect_leaves_the_talkers_backchannel_session_alone() {
    let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 20).await;
    let mut worker = InProcess::rtsp(&camera).await;
    let mut peer = talking(&mut worker, false, Mic::pcmu()).await;
    let before = camera_frames(&mut worker, &mut peer, &camera, 25)
        .await
        .len();
    camera.hang_up_where(|log| !log.backchannel_only());
    worker
        .pump(&mut [&mut peer], |_, _| {
            let log = camera.stats().connection_log();
            // The viewing session's again, and the probe's again.
            log.iter()
                .filter(|log| log.setups.contains(&"track0".to_owned()))
                .count()
                == 2
                && log
                    .iter()
                    .filter(|log| log.describes == [true] && log.setups.is_empty())
                    .count()
                    == 2
                && Stats::get(&camera.stats().backchannel_packets) >= before as u64 + 25
        })
        .await;
    let _mic = peer.mute();
    let recorded = camera.stats().backchannel();
    assert!(
        recorded
            .iter()
            .all(|packet| packet.ssrc == recorded[0].ssrc),
        "one RTP stream"
    );
    for pair in recorded.windows(2) {
        assert_eq!(
            pair[1].sequence_number,
            pair[0].sequence_number.wrapping_add(1)
        );
    }
    assert_eq!(Stats::get(&camera.stats().backchannel_setups), 1);
    assert!(!backchannel_session(&camera).unwrap().closed);
    assert_eq!(changes(&worker), [("0".into(), "claimed".into())]);
    assert!(
        !worker
            .events
            .iter()
            .any(|(_, event)| matches!(event, SessionEvent::TalkbackDeclined { .. })),
        "{:?}",
        worker.events
    );
    worker.stop().await;
    camera.stop().await;
}

/// RFC 2326 §11.3.3: the camera refuses the backchannel session with
/// `453` (another app holds its one backchannel): the answer declines
/// talk-back, the session gets one `refused` warning with the status, and
/// the claim is not kept; once the camera's backchannel is free, the
/// user's next re-offer claims it and its tone reaches the camera.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_11_3_3_a_refused_backchannel_session_declines_and_the_next_re_offer_claims() {
    let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 20).await;
    camera.set_backchannel_setup(BackchannelSetup::Refuse(453));
    let mut worker = InProcess::rtsp(&camera).await;
    let mut peer = Peer::new_silent().await;
    worker.open("0", &peer.offer).await;
    worker
        .pump(&mut [&mut peer], |_, peers| peers[0].viewer.is_connected())
        .await;
    let reoffer = peer
        .viewer
        .reoffer(Reoffer::Talkback(TalkbackOffer::Dedicated))
        .expect("a re-offer");
    worker.renegotiate("0", &reoffer).await;
    let declined = |w: &InProcess| {
        w.events.iter().any(|(_, event)| {
            matches!(event, SessionEvent::TalkbackDeclined { reason, status: Some(453), .. } if reason == "refused")
        })
    };
    worker.pump(&mut [&mut peer], |w, _| declined(w)).await;
    assert!(
        worker
            .events
            .iter()
            .any(|(_, event)| matches!(event, SessionEvent::Renegotiated { talkback: None, .. }))
    );
    assert_eq!(
        peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::Inactive),
        "declined per RFC 3264 §6.1, not port 0"
    );
    assert_eq!(
        changes(&worker),
        [
            ("0".into(), "claimed".into()),
            ("0".into(), "refused".into())
        ]
    );
    // The camera's backchannel is free again: the next press claims it.
    camera.set_backchannel_setup(BackchannelSetup::Accept);
    let reoffer = peer
        .viewer
        .reoffer(Reoffer::Talkback(TalkbackOffer::Dedicated))
        .expect("a re-offer");
    let answered = worker.events.len();
    worker.renegotiate("0", &reoffer).await;
    worker
        .pump(&mut [&mut peer], |w, _| {
            w.events[answered..].iter().any(|(_, event)| {
                matches!(
                    event,
                    SessionEvent::Renegotiated {
                        talkback: Some(_),
                        ..
                    }
                )
            })
        })
        .await;
    peer.talk(Mic::pcmu());
    let frames = camera_frames(&mut worker, &mut peer, &camera, 10).await;
    assert!(frames.len() >= 10);
    assert_eq!(changes(&worker).len(), 3, "claimed again");
    worker.stop().await;
    camera.stop().await;
}

/// The backchannel session's connection drops while the viewer talks:
/// the claim is released (`talker_changed` `refused`) and the session gets
/// one `refused` warning; what it sends meanwhile is dropped, and its
/// m-line stays as answered.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_a_lost_backchannel_connection_releases_the_talker_with_one_warning() {
    let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 20).await;
    let mut worker = InProcess::rtsp(&camera).await;
    let mut peer = talking(&mut worker, false, Mic::pcmu()).await;
    camera_frames(&mut worker, &mut peer, &camera, 10).await;
    camera.hang_up_backchannel();
    let warned = |w: &InProcess| {
        w.events
            .iter()
            .filter(|(_, event)| {
                matches!(event, SessionEvent::TalkbackDeclined { reason, .. } if reason == "refused")
            })
            .count()
    };
    worker.pump(&mut [&mut peer], |w, _| warned(w) == 1).await;
    let quiet = clock().now() + Duration::from_millis(300);
    worker
        .pump(&mut [&mut peer], |_, _| clock().now() >= quiet)
        .await;
    assert_eq!(warned(&worker), 1, "once");
    assert_eq!(
        changes(&worker),
        [
            ("0".into(), "claimed".into()),
            ("0".into(), "refused".into())
        ]
    );
    assert_eq!(
        Stats::get(&camera.stats().backchannel_setups),
        1,
        "nothing opened again"
    );
    worker.stop().await;
    camera.stop().await;
}

/// The release closes the backchannel session, whatever releases it: the
/// talker's session closing, `backchannel/release`, and the stream's
/// deletion, which stops the worker. Each time the camera sees its
/// `TEARDOWN` with `Require`, and the connection is closed.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_every_release_tears_the_backchannel_session_down_and_closes_it() {
    for release in ["session_closed", "released", "stream_deleted"] {
        let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 20).await;
        let mut worker = InProcess::rtsp(&camera).await;
        let mut peer = talking(&mut worker, false, Mic::pcmu()).await;
        camera_frames(&mut worker, &mut peer, &camera, 5).await;
        match release {
            "session_closed" => worker.close("0").await,
            "released" => worker.release().await,
            _ => {}
        }
        let running = if release == "stream_deleted" {
            worker.stop().await;
            None
        } else {
            let reason = release;
            worker
                .pump(&mut [&mut peer], |w, _| {
                    w.talkers.iter().any(|change| change.reason == reason)
                })
                .await;
            Some(worker)
        };
        let deadline = clock().now() + Duration::from_secs(5);
        while !backchannel_session(&camera).unwrap().closed {
            assert!(clock().now() < deadline, "{release}: never closed");
            clock().sleep(Duration::from_millis(5)).await;
        }
        let log = backchannel_session(&camera).unwrap();
        assert_eq!(log.teardown, Some(true), "{release}: TEARDOWN with Require");
        assert!(log.closed_by_client, "{release}: {log:?}");
        if let Some(worker) = running {
            worker.stop().await;
        }
        camera.stop().await;
    }
}

/// The daemon stops while a viewer holds the camera's backchannel, through
/// a real `lotse worker` process: before the process exits, its
/// backchannel session is torn down (RFC 2326 §10.7), the camera sees the
/// `TEARDOWN` with `Require` (ONVIF Streaming Specification §5.3), and the
/// connection is closed; the worker's runtime does not drop the session's
/// task halfway at its exit.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_7_a_worker_process_tears_the_backchannel_session_down_before_it_exits() {
    let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 20).await;
    let mut api = Api::start_with(
        Arc::new(lotse_rtsp::RtspFactory::default()),
        &camera.url(),
        &json!({ "backchannel": true }),
        "off",
    )
    .await;
    let mut a = ApiPeer::offer(&api, "a").await;
    pump(&mut api, &mut [&mut a], |_, _| {
        backchannel_session(&camera).is_some_and(|log| log.played)
    })
    .await;
    api.stop().await;
    // The worker is gone: what it sent before its exit is all the camera
    // reads before the connection's end.
    let deadline = clock().now() + Duration::from_secs(5);
    while !backchannel_session(&camera).unwrap().closed {
        assert!(clock().now() < deadline, "never closed");
        clock().sleep(Duration::from_millis(5)).await;
    }
    let log = backchannel_session(&camera).unwrap();
    assert_eq!(log.teardown, Some(true), "TEARDOWN with Require: {log:?}");
    assert!(log.closed_by_client, "{log:?}");
    camera.stop().await;
}

/// The talk-back path under the worker's sandbox (Landlock and seccomp on
/// Linux, as `lotse serve --sandbox on` applies them): a real worker
/// process runs the RTSP source, a browser that offers only Opus talks
/// the tone, and the worker decodes it, encodes it in the camera's μ-law
/// (`ToG711`, RFC 6716 to G.711) and sends it on the backchannel's
/// interleaved channel (ONVIF Streaming Specification §5.3), where the
/// camera takes it at its frequency; at the daemon's shutdown the
/// sandboxed worker still tears the backchannel session down
/// (RFC 2326 §10.7) before it exits. A syscall or a path the uplink needs
/// that the sandbox denies fails this test. On macOS the sandbox is a
/// no-op and this checks the same path in a worker process.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_a_sandboxed_worker_process_transcodes_an_opus_tone_onto_the_rtsp_backchannel() {
    let camera = rtsp_camera(None, BackchannelCodec::Pcmu, 20).await;
    let mut api = Api::start_with(
        Arc::new(lotse_rtsp::RtspFactory::default()),
        &camera.url(),
        &json!({ "backchannel": true }),
        "on",
    )
    .await;
    let opus = Peer::new(Some(
        "a=rtpmap:111 opus/48000/2\na=fmtp:111 minptime=10;useinbandfec=1",
    ))
    .await;
    let mut a = ApiPeer::open(&api, "a", Box::new(opus)).await;
    pump(&mut api, &mut [&mut a], |_, peers| {
        peers[0].peer.viewer.is_connected()
    })
    .await;
    assert_eq!(a.peer.pt, Some(111), "the browser sends Opus");
    a.peer.talk(Mic::opus());
    pump(&mut api, &mut [&mut a], |_, peers| {
        peers[0].peer.sent() >= TONE_PACKETS
    })
    .await;
    let mic = a.peer.mute();
    pump(&mut api, &mut [&mut a], |_, _| {
        Stats::get(&camera.stats().backchannel_packets) >= u64::from(TONE_PACKETS)
    })
    .await;
    pump_for(&mut api, &mut [&mut a], QUIET).await;
    let frames: Vec<Frame> = camera
        .stats()
        .backchannel()
        .iter()
        .map(Frame::from)
        .collect();
    let latencies = check_tone(&frames, &mic, Law::Mu);
    assert_eq!(Stats::get(&camera.stats().backchannel_refused), 0);
    println!("Opus to PCMU in a sandboxed worker: uplink latency per onset {latencies:?}");
    api.stop().await;
    let deadline = clock().now() + Duration::from_secs(5);
    while !backchannel_session(&camera).unwrap().closed {
        assert!(clock().now() < deadline, "never closed");
        clock().sleep(Duration::from_millis(5)).await;
    }
    let log = backchannel_session(&camera).unwrap();
    assert_eq!(log.teardown, Some(true), "TEARDOWN with Require: {log:?}");
    assert!(log.closed_by_client, "{log:?}");
    camera.stop().await;
}

/// Downlink A/V sync with talk-back active, which needs audio, video and
/// a backchannel on one source: while the viewer talks, the daemon's
/// Sender Reports (RFC 3550 §6.4.1) still put the camera's audio within
/// 40 ms of its video, which the camera captured together.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3550_6_4_1_downlink_audio_stays_in_sync_with_video_while_talking() {
    let camera = rtsp_camera(Some(CameraAudio::Pcmu), BackchannelCodec::Pcmu, 20).await;
    let mut worker = InProcess::rtsp(&camera).await;
    let mut peer = talking(&mut worker, true, Mic::pcmu()).await;
    // Three seconds of audio with talk-back flowing all along: long
    // enough for Sender Reports of both.
    worker
        .pump(&mut [&mut peer], |_, peers| {
            let viewer = &peers[0].viewer;
            Stats::get(&camera.stats().backchannel_packets) >= 100
                && viewer.audio_packets().len() >= 150
                && viewer
                    .audio_packets()
                    .last()
                    .is_some_and(|packet| packet.last_sender_info.is_some())
                && viewer
                    .packets()
                    .last()
                    .is_some_and(|packet| packet.last_sender_info.is_some())
        })
        .await;
    assert!(peer.sent() >= 100, "talking all along");
    let viewer = &peer.viewer;
    let audio_at = capture_seconds(viewer.audio_packets().last().unwrap()).expect("an audio SR");
    let video_at = capture_seconds(viewer.packets().last().unwrap()).expect("a video SR");
    let offset_ms = (audio_at - video_at) * 1_000.0;
    println!("A/V offset while talking: {offset_ms:.1} ms");
    assert!(
        offset_ms.abs() < 40.0,
        "audio {offset_ms:.1} ms from video by the daemon's Sender Reports"
    );
    worker.stop().await;
    camera.stop().await;
}

// ---------------------------------------------------------------------
// The control API, with a `lotse worker` subprocess.
// ---------------------------------------------------------------------

/// The supervisor and its demux, the fake source declaring a backchannel
/// on both sides of the worker channel (the binary registers it so).
struct Api {
    supervisor: Supervisor,
    demux: Demux,
    stream_events: mpsc::Receiver<Event>,
    /// Every `stream/subscribe` event, in order.
    stream_seen: Vec<Value>,
}

impl Api {
    async fn start(options: &Value) -> Self {
        let factory = Arc::new(FakeSourceFactory::with_backchannel(&["fake"]));
        Self::start_with(factory, "fake://127.0.0.1/", options, "off").await
    }

    /// The supervisor and its demux, with stream `door` on `url` and
    /// `options`, its scheme validated by `factory` (the worker process
    /// registers the binary's own), its workers in `sandbox` mode.
    async fn start_with(
        factory: Arc<dyn SourceFactory>,
        url: &str,
        options: &Value,
        sandbox: &str,
    ) -> Self {
        let bound = bind_udp("127.0.0.1:0".parse().unwrap()).expect("the shared socket");
        let demux = Demux::start(
            Arc::clone(&bound.socket),
            bound.local,
            bound.hosts.clone(),
            clock(),
        )
        .expect("the demux");
        let settings = Settings {
            socket: PathBuf::from("/nonexistent/lotse.sock"),
            owner_uid: 0,
            allow_uid: 0,
            control_tls: None,
            udp_listen: bound.local,
            tcp_listen: None,
            limits: Limits {
                max_connections: 8,
                max_streams: 8,
                max_sessions: 256,
                max_sessions_per_stream: 16,
                session_grace: Duration::from_secs(10),
                worker_threads: 1,
                worker_address_space: 1 << 30,
            },
            linger: Duration::from_millis(200),
            connect_concurrency: lotse_supervisor::DEFAULT_CONNECT_CONCURRENCY,
            shutdown_budget: Duration::from_secs(2),
        };
        let mut registries = Registries::default();
        registries
            .outputs
            .register(Arc::new(lotse_webrtc::WebRtcFactory))
            .unwrap();
        registries.sources.register(factory).unwrap();
        registries.uplink = Some(Arc::new(ToG711Factory::new(clock())));
        let environment = Environment {
            registries,
            worker: WorkerConfig {
                binary: PathBuf::from(env!("CARGO_BIN_EXE_lotse")),
                log_format: "json".into(),
                log_level: "info".into(),
                sandbox: sandbox.into(),
                worker_threads: 1,
                worker_address_space: 1 << 30,
                max_sessions: 256,
            },
            udp: Some(Arc::clone(&bound.socket)),
            front_door: Some(FrontDoor {
                registrations: demux.registrations(),
                hosts: bound.hosts,
                tcp_hosts: vec![],
                stun: None,
                turn: None,
                demux: Some(demux.stats()),
            }),
            identity: Identity {
                version: "0.0.0-test".into(),
                build: BuildInfo {
                    target: "test".into(),
                    rustc: "test".into(),
                },
                sandbox: SandboxInfo {
                    mode: "off".into(),
                    uid: 0,
                    gid: 0,
                    no_new_privs: false,
                    seccomp: "off".into(),
                    landlock: LandlockInfo {
                        fs: "off".into(),
                        net: "off".into(),
                        abi: 0,
                    },
                    notes: vec![],
                },
            },
        };
        let supervisor = Supervisor::new(settings, environment, clock());
        let info = result(call(&supervisor, &json!({ "id": 1, "type": "info" })).await);
        assert!(
            info["features"]
                .as_array()
                .unwrap()
                .contains(&json!("two_way_audio")),
            "{info}"
        );
        result(
            call(
                &supervisor,
                &json!({ "id": 2, "type": "stream/put", "stream_id": "door",
                         "sources": [{ "url": url, "options": options }] }),
            )
            .await,
        );
        let stream_events = subscription(
            call(
                &supervisor,
                &json!({ "id": 3, "type": "stream/subscribe", "stream_id": "door" }),
            )
            .await,
        );
        Self {
            supervisor,
            demux,
            stream_events,
            stream_seen: Vec::new(),
        }
    }

    async fn call(&self, command: &Value) -> Value {
        result(call(&self.supervisor, command).await)
    }

    async fn session(&self, id: &str) -> Value {
        self.call(&json!({ "id": 10, "type": "session/get", "session_id": id }))
            .await
    }

    async fn stream(&self) -> Value {
        self.call(&json!({ "id": 11, "type": "stream/get", "stream_id": "door" }))
            .await
    }

    /// `talker_changed` events so far: (session, reason, talker).
    fn talker_changes(&self) -> Vec<(String, String, Value)> {
        self.stream_seen
            .iter()
            .filter(|event| event["type"] == "talker_changed")
            .map(|event| {
                assert_eq!(event["stream_id"], "door");
                (
                    event["session_id"].as_str().unwrap().to_owned(),
                    event["reason"].as_str().unwrap().to_owned(),
                    event["talker"].clone(),
                )
            })
            .collect()
    }

    async fn stop(self) {
        self.supervisor.shutdown().await;
        self.demux.stop();
    }
}

async fn call(supervisor: &Supervisor, command: &Value) -> Outcome {
    let command = parse_command(&command.to_string()).expect("a command");
    supervisor.handle(ConnectionId(1), command).await
}

fn result(outcome: Outcome) -> Value {
    match outcome {
        Outcome::Result(value) => value,
        Outcome::Error(err) => panic!("error {err}"),
        Outcome::Subscribed(_) | Outcome::SubscribedWith { .. } => panic!("subscription"),
    }
}

fn subscription(outcome: Outcome) -> mpsc::Receiver<Event> {
    match outcome {
        Outcome::Subscribed(rx) => rx,
        other => panic!("not a subscription: {other:?}"),
    }
}

/// A viewer signaled through `webrtc/offer`, as the client relays a browser.
struct ApiPeer {
    id: &'static str,
    peer: Peer,
    events: mpsc::Receiver<Event>,
    /// Its session's events, in order.
    seen: Vec<Value>,
}

impl ApiPeer {
    async fn offer(api: &Api, id: &'static str) -> Self {
        Self::open(api, id, Box::new(Peer::new(None).await)).await
    }

    /// A viewer that offers no talk-back, through `webrtc/offer`.
    async fn offer_silent(api: &Api, id: &'static str) -> Self {
        Self::open(api, id, Box::new(Peer::new_silent().await)).await
    }

    /// A client that only talks back, through `webrtc/offer`.
    async fn offer_talk_only(api: &Api, id: &'static str) -> Self {
        Self::open(api, id, Box::new(Peer::new_talk_only().await)).await
    }

    /// `peer`'s offer as it sends it, through `webrtc/offer`; boxed, so
    /// the future holds no viewer.
    async fn open(api: &Api, id: &'static str, peer: Box<Peer>) -> Self {
        let events = subscription(
            call(
                &api.supervisor,
                &json!({ "id": 4, "type": "webrtc/offer", "stream_id": "door",
                         "session_id": id, "sdp": peer.offer }),
            )
            .await,
        );
        Self {
            id,
            peer: *peer,
            events,
            seen: Vec::new(),
        }
    }

    /// A re-offer of `what` through `webrtc/renegotiate`, its answer
    /// applied: the command's result.
    async fn renegotiate(&mut self, api: &Api, what: Reoffer) -> Value {
        let sdp = self.peer.viewer.reoffer(what).expect("a re-offer");
        let result = api
            .call(&json!({ "id": 20, "type": "webrtc/renegotiate", "session_id": self.id, "sdp": sdp }))
            .await;
        self.peer
            .on_answer(result["sdp"].as_str().expect("the answer"));
        result
    }

    /// Its `warning` events with `code`.
    fn warnings(&self, code: &str) -> usize {
        self.seen
            .iter()
            .filter(|event| event["type"] == "warning" && event["code"] == code)
            .count()
    }
}

/// Polls the API's events and `peers` until `done`; twenty seconds
/// without fail the test.
async fn pump(
    api: &mut Api,
    peers: &mut [&mut ApiPeer],
    done: impl Fn(&Api, &[&mut ApiPeer]) -> bool,
) {
    let deadline = clock().now() + Duration::from_secs(20);
    while !done(api, peers) {
        assert!(
            clock().now() < deadline,
            "timed out; stream events {:?}, sessions {:?}",
            api.stream_seen,
            peers.iter().map(|p| &p.seen).collect::<Vec<_>>()
        );
        for peer in peers.iter_mut() {
            while let Ok(event) = peer.events.try_recv() {
                let event = event.payload;
                match event["type"].as_str() {
                    Some("answer") => {
                        peer.peer.on_answer(event["sdp"].as_str().unwrap());
                        let candidate = peer.peer.candidate();
                        result(
                            call(
                                &api.supervisor,
                                &json!({ "id": 5, "type": "webrtc/candidate",
                                         "session_id": peer.id, "candidate": candidate }),
                            )
                            .await,
                        );
                    }
                    Some("candidate") => {
                        peer.peer.on_candidate(event["candidate"].as_str().unwrap());
                    }
                    _ => {}
                }
                peer.seen.push(event);
            }
            peer.peer.poll();
        }
        while let Ok(event) = api.stream_events.try_recv() {
            api.stream_seen.push(event.payload);
        }
        clock().sleep(Duration::from_millis(1)).await;
    }
}

/// [`pump`] for `duration`.
async fn pump_for(api: &mut Api, peers: &mut [&mut ApiPeer], duration: Duration) {
    let until = clock().now() + duration;
    pump(api, peers, |_, _| clock().now() >= until).await;
}

/// Pumps until `session/get` of `id` satisfies `want`, which the worker's
/// counters reach within a stats push or two.
async fn session_where(
    api: &mut Api,
    peers: &mut [&mut ApiPeer],
    id: &str,
    want: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = clock().now() + Duration::from_secs(10);
    loop {
        let session = api.session(id).await;
        if want(&session["backchannel"]) {
            return session["backchannel"].clone();
        }
        assert!(clock().now() < deadline, "session {id}: {session}");
        pump_for(api, peers, Duration::from_millis(100)).await;
    }
}

/// Pumps until `stream/get`'s source backchannel satisfies `want`, which
/// the worker's counters reach within a stats push or two.
async fn source_where(api: &mut Api, peers: &mut [&mut ApiPeer], want: &Value) -> Value {
    let deadline = clock().now() + Duration::from_secs(10);
    loop {
        let stream = api.stream().await;
        if stream["sources"][0]["backchannel"] == *want {
            return stream;
        }
        assert!(clock().now() < deadline, "{stream}");
        pump_for(api, peers, Duration::from_millis(100)).await;
    }
}

/// Talker arbitration through the control API: two viewers offer
/// talk-back; the first offer claims the backchannel and is answered
/// `recvonly`, the second is declined `busy`, answered `inactive` with
/// one `backchannel_declined`; the holder going silent keeps it; closing
/// the holder's session frees it for the next re-offer
/// (`webrtc/renegotiate`), and so does `backchannel/release`, unless it
/// names a session that no longer holds it; a re-offer that drops
/// talk-back lets go. Each change is a `talker_changed`, and
/// `session/get` and `stream/get` say who holds it; `stream/get`'s source
/// says the camera's codec and whether the backchannel is in use. A
/// re-offer is taken from the session's owner only, for an answered
/// session only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_viewers_claim_hold_and_free_the_backchannel_through_the_control_api() {
    let mut api = Api::start(&json!({ "backchannel": "pcmu" })).await;
    let mut a = ApiPeer::offer(&api, "a").await;
    let mut b = ApiPeer::offer(&api, "b").await;
    pump(&mut api, &mut [&mut a, &mut b], |_, peers| {
        peers.iter().all(|p| p.peer.viewer.is_connected())
    })
    .await;
    // a's offer claimed it: answered recvonly in the camera's PCMU; b's
    // was declined: answered inactive, and told why.
    assert_eq!(
        a.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::SendOnly)
    );
    assert_eq!(a.peer.pt, Some(0));
    assert_eq!(
        b.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::Inactive)
    );
    pump(&mut api, &mut [&mut a, &mut b], |api, peers| {
        peers[1].warnings("backchannel_declined") > 0 && !api.talker_changes().is_empty()
    })
    .await;
    let declined = b
        .seen
        .iter()
        .find(|event| event["code"] == "backchannel_declined")
        .unwrap();
    assert_eq!(declined["reason"], "busy");
    assert_eq!(
        declined["message"],
        "talk-back declined: session a holds the camera's backchannel"
    );
    assert_eq!(
        api.talker_changes(),
        [("a".to_owned(), "claimed".to_owned(), json!("a"))]
    );
    let claim = api
        .stream_seen
        .iter()
        .find(|event| event["type"] == "talker_changed")
        .unwrap()
        .clone();
    assert_eq!(
        api.stream().await["backchannel"],
        json!({ "talker": "a", "since": claim["since"] })
    );
    assert_eq!(
        api.session("a").await["backchannel"],
        json!({ "negotiated": true, "talker": true, "codec": "pcmu", "packets_received": 0,
                "packets_dropped_busy": 0, "bytes_sent": 0 })
    );
    assert_eq!(
        api.session("b").await["backchannel"],
        json!({ "negotiated": false, "talker": false, "codec": null, "packets_received": 0,
                "packets_dropped_busy": 0, "bytes_sent": 0 })
    );
    let stream = source_where(
        &mut api,
        &mut [&mut a, &mut b],
        &json!({ "codec": "pcmu", "state": "in_use" }),
    )
    .await;
    assert_eq!(stream["sources"][0]["state"], "live");

    // a talks, then goes silent: it still holds the backchannel, and a
    // re-offer of b's that asks again is declined again, once more.
    a.peer.talk(Mic::pcmu());
    let holder = session_where(&mut api, &mut [&mut a, &mut b], "a", |bc| {
        bc["bytes_sent"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(holder["talker"], true);
    assert_eq!(holder["packets_dropped_busy"], 0);
    a.peer.mute();
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_millis(300)).await;
    assert_eq!(api.talker_changes().len(), 1, "{:?}", api.stream_seen);
    let answer = b
        .renegotiate(&api, Reoffer::Talkback(TalkbackOffer::Dedicated))
        .await;
    assert!(answer["sdp"].as_str().unwrap().starts_with("v=0"));
    assert_eq!(
        b.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::Inactive)
    );
    pump(&mut api, &mut [&mut a, &mut b], |_, peers| {
        peers[1].warnings("backchannel_declined") == 2
    })
    .await;
    assert_eq!(api.stream().await["backchannel"]["talker"], "a");

    // Closing a's session frees it; b's next re-offer claims it, and
    // b's packets reach the camera.
    api.call(&json!({ "id": 6, "type": "session/close", "session_id": "a" }))
        .await;
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        api.talker_changes().len() >= 2
    })
    .await;
    b.renegotiate(&api, Reoffer::Talkback(TalkbackOffer::Dedicated))
        .await;
    assert_eq!(
        b.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::SendOnly)
    );
    assert_eq!(b.peer.pt, Some(0));
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        api.talker_changes().len() >= 3
    })
    .await;
    assert_eq!(
        api.talker_changes(),
        [
            ("a".to_owned(), "claimed".to_owned(), json!("a")),
            ("a".to_owned(), "session_closed".to_owned(), Value::Null),
            ("b".to_owned(), "claimed".to_owned(), json!("b")),
        ]
    );
    b.peer.talk(Mic::pcmu());
    let talking = session_where(&mut api, &mut [&mut a, &mut b], "b", |bc| {
        bc["bytes_sent"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(
        (&talking["negotiated"], &talking["talker"]),
        (&json!(true), &json!(true))
    );

    // The client releases the backchannel: free, and it stays free until
    // an offer asks; what b still sends meanwhile is dropped and counted.
    // The release waits until b's last packets are through.
    let mut b_mic = b.peer.mute();
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_millis(300)).await;
    let released = api
        .call(&json!({ "id": 7, "type": "backchannel/release", "stream_id": "door" }))
        .await;
    assert_eq!(released, json!({ "talker": "b" }));
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        api.talker_changes().len() >= 4
    })
    .await;
    assert_eq!(
        api.talker_changes()[3],
        ("b".to_owned(), "released".to_owned(), Value::Null)
    );
    let sent_before = u64::from(b_mic.index);
    b.peer.talk(b_mic);
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_millis(500)).await;
    b_mic = b.peer.mute();
    let dropped = u64::from(b_mic.index) - sent_before;
    assert!(dropped > 0);
    let refused = |bc: &Value| {
        bc["packets_received"].as_u64() == Some(u64::from(b_mic.index))
            && bc["packets_dropped_busy"].as_u64() == Some(dropped)
    };
    let idle = session_where(&mut api, &mut [&mut a, &mut b], "b", refused).await;
    assert_eq!(idle["talker"], false);
    assert_eq!(api.stream().await["backchannel"]["talker"], Value::Null);
    assert_eq!(api.talker_changes().len(), 4, "{:?}", api.stream_seen);
    // The released session's next re-offer claims again, and its packets
    // flow again.
    let bytes_before = idle["bytes_sent"].as_u64().unwrap();
    b.renegotiate(&api, Reoffer::Talkback(TalkbackOffer::Dedicated))
        .await;
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        api.talker_changes().len() >= 5
    })
    .await;
    assert_eq!(
        api.talker_changes()[4],
        ("b".to_owned(), "claimed".to_owned(), json!("b"))
    );
    b.peer.talk(b_mic);
    session_where(&mut api, &mut [&mut a, &mut b], "b", |bc| {
        bc["bytes_sent"].as_u64().unwrap() > bytes_before
    })
    .await;
    // A release for a session that no longer holds it, as a viewer that
    // stops talking sends, frees nothing of b's.
    let stale = api
        .call(&json!({ "id": 8, "type": "backchannel/release", "stream_id": "door", "session_id": "a" }))
        .await;
    assert_eq!(stale, json!({ "talker": "b" }));
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_millis(300)).await;
    assert_eq!(api.talker_changes().len(), 5, "{:?}", api.stream_seen);
    assert_eq!(api.stream().await["backchannel"]["talker"], "b");
    // b's re-offer drops talk-back: let go, and a viewer that never
    // offered talk-back takes it with its re-offer. What b counted, once
    // its last packets are through, stays in `session/get` after the
    // stats pushes that follow: the counters never go back.
    let b_mic = b.peer.mute();
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_millis(300)).await;
    let counted = session_where(&mut api, &mut [&mut a, &mut b], "b", |bc| {
        bc["packets_received"].as_u64() == Some(u64::from(b_mic.index))
    })
    .await;
    b.renegotiate(&api, Reoffer::Drop).await;
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        api.talker_changes().len() >= 6
    })
    .await;
    assert_eq!(
        api.talker_changes()[5],
        ("b".to_owned(), "renegotiated".to_owned(), Value::Null)
    );
    pump_for(
        &mut api,
        &mut [&mut a, &mut b],
        lotse_worker::STATS_INTERVAL * 3,
    )
    .await;
    assert_eq!(
        api.session("b").await["backchannel"],
        json!({ "negotiated": false, "talker": false, "codec": null,
                "packets_received": counted["packets_received"],
                "packets_dropped_busy": counted["packets_dropped_busy"],
                "bytes_sent": counted["bytes_sent"] })
    );
    assert!(counted["bytes_sent"].as_u64().unwrap() > 0, "{counted}");
    let mut c = ApiPeer::offer_silent(&api, "c").await;
    pump(&mut api, &mut [&mut a, &mut b, &mut c], |_, peers| {
        peers[2].peer.viewer.is_connected()
    })
    .await;
    assert_eq!(c.peer.viewer.talkback_direction(), None);
    c.renegotiate(&api, Reoffer::Talkback(TalkbackOffer::Dedicated))
        .await;
    assert_eq!(
        c.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::SendOnly)
    );
    pump(&mut api, &mut [&mut a, &mut b, &mut c], |api, _| {
        api.talker_changes().len() >= 7
    })
    .await;
    assert_eq!(
        api.talker_changes()[6],
        ("c".to_owned(), "claimed".to_owned(), json!("c"))
    );
    c.peer.talk(Mic::pcmu());
    session_where(&mut api, &mut [&mut a, &mut b, &mut c], "c", |bc| {
        bc["bytes_sent"].as_u64().unwrap() > 0
    })
    .await;
    // A re-offer is the owner's, for an answered session: another
    // connection's, or one for no session, is `session_not_found`.
    let sdp = c.peer.viewer.offer().to_owned();
    for (connection, session) in [(2, "c"), (1, "ghost")] {
        let command = parse_command(
            &json!({ "id": 30, "type": "webrtc/renegotiate", "session_id": session, "sdp": sdp })
                .to_string(),
        )
        .unwrap();
        let outcome = api
            .supervisor
            .handle(ConnectionId(connection), command)
            .await;
        let Outcome::Error(err) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(
            err.code.as_str(),
            "session_not_found",
            "{connection} {session}"
        );
    }
    // Exactly two declines in all of it, both to b, one per offer.
    assert_eq!(a.warnings("backchannel_declined"), 0);
    assert_eq!(b.warnings("backchannel_declined"), 2, "{:?}", b.seen);
    assert_eq!(c.warnings("backchannel_declined"), 0);
    api.stop().await;
}

/// A talker whose re-offer stops its talk-back m-line, port 0 and out of
/// the BUNDLE group, but keeps the m-line's `a=sendonly` and codecs, asks
/// for no talk-back: the stream is disabled (RFC 3264 §8.2) whatever
/// direction the m-line names. The m-line is answered with port 0, the
/// talker lets go, and another viewer's re-offer claims the backchannel
/// without a `busy` decline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3264_8_2_a_re_offer_that_stops_talk_back_with_its_direction_kept_frees_the_backchannel()
{
    let mut api = Api::start(&json!({ "backchannel": "pcmu" })).await;
    let mut a = ApiPeer::offer(&api, "a").await;
    let mut b = ApiPeer::offer_silent(&api, "b").await;
    pump(&mut api, &mut [&mut a, &mut b], |api, peers| {
        peers.iter().all(|p| p.peer.viewer.is_connected()) && !api.talker_changes().is_empty()
    })
    .await;
    assert_eq!(
        api.talker_changes(),
        [("a".to_owned(), "claimed".to_owned(), json!("a"))]
    );

    // a stops its talk-back m-line, the stopped section keeping its
    // `a=sendonly` where the viewer wrote `a=inactive`.
    let offered = a.peer.viewer.reoffer(Reoffer::Stop).expect("a re-offer");
    let (head, stopped) = offered.split_once("m=audio 0 ").expect("a stopped m-line");
    assert!(!stopped.contains("m="), "the last m-line: {offered}");
    assert!(stopped.contains("a=rtpmap:0 PCMU/8000"), "{offered}");
    let sdp = format!(
        "{head}m=audio 0 {}",
        stopped.replacen("a=inactive", "a=sendonly", 1)
    );
    assert!(sdp.ends_with("\r\n") && sdp.contains("a=sendonly"), "{sdp}");
    let result = api
        .call(&json!({ "id": 20, "type": "webrtc/renegotiate", "session_id": "a", "sdp": sdp }))
        .await;
    let answer = result["sdp"].as_str().expect("the answer");
    let (_, answered) = answer.rsplit_once("m=audio ").expect("an audio m-line");
    assert!(answered.starts_with("0 "), "rejected: {answer}");
    a.peer.on_answer(answer);
    assert_eq!(a.peer.viewer.talkback_direction(), None, "rejected");
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        api.talker_changes().len() >= 2
    })
    .await;
    assert_eq!(
        api.talker_changes()[1],
        ("a".to_owned(), "renegotiated".to_owned(), Value::Null)
    );
    assert_eq!(api.stream().await["backchannel"]["talker"], Value::Null);
    assert_eq!(api.session("a").await["backchannel"]["negotiated"], false);

    // b asks for talk-back and claims it.
    b.renegotiate(&api, Reoffer::Talkback(TalkbackOffer::Dedicated))
        .await;
    assert_eq!(
        b.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::SendOnly)
    );
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        api.talker_changes().len() >= 3
    })
    .await;
    assert_eq!(
        api.talker_changes()[2],
        ("b".to_owned(), "claimed".to_owned(), json!("b"))
    );
    assert_eq!(api.stream().await["backchannel"]["talker"], "b");
    assert_eq!(b.warnings("backchannel_declined"), 0, "{:?}", b.seen);
    api.stop().await;
}

/// `sdp` with its last audio m-line, the dedicated talk-back one after
/// the video, offering two-channel PCMU, under a payload type no other
/// m-line of the bundle uses (RFC 9143 §9.1.1), and G.722, which does
/// not reach a G.711 backchannel: no codec talk-back can take, and one
/// the engine answers the m-line `inactive` with. (Without one, str0m
/// 0.24.0 rejects the m-line with an empty format list, which its own
/// parser, the viewer's, refuses: RFC 8866 §5.14 wants a format.)
fn two_channel_talkback(sdp: &str) -> String {
    let at = sdp.rfind("m=audio ").expect("a talk-back m-line");
    format!(
        "{}{}",
        &sdp[..at],
        with_audio_codecs(
            &sdp[at..],
            "a=rtpmap:104 PCMU/8000/2\na=rtpmap:9 G722/8000\n"
        )
    )
}

/// Talk-back offered only in two-channel PCMU, which the engine does not
/// carry (it carries G.711 mono, RFC 3551 §4.5.14), so it answers it no
/// format (RFC 3264 §6): the offer is declined `unsupported` and does
/// not claim the backchannel, which another viewer's offer then claims
/// without a `busy` decline; and a talker's re-offer that asks for
/// talk-back only in it lets go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3551_4_5_14_talk_back_only_in_two_channel_pcmu_neither_claims_nor_keeps_the_backchannel()
 {
    let mut api = Api::start(&json!({ "backchannel": "pcmu" })).await;
    let mut stereo = Box::new(Peer::new(None).await);
    stereo.offer = two_channel_talkback(&stereo.offer);
    assert!(stereo.offer.contains("a=sendonly"), "{}", stereo.offer);
    let mut a = ApiPeer::open(&api, "a", stereo).await;
    let mut b = ApiPeer::offer(&api, "b").await;
    pump(&mut api, &mut [&mut a, &mut b], |api, peers| {
        peers.iter().all(|p| p.peer.viewer.is_connected())
            && peers[0].warnings("backchannel_declined") > 0
            && !api.talker_changes().is_empty()
    })
    .await;
    let declined = a
        .seen
        .iter()
        .find(|event| event["code"] == "backchannel_declined")
        .unwrap();
    assert_eq!(declined["reason"], "unsupported");
    assert_eq!(
        api.talker_changes(),
        [("b".to_owned(), "claimed".to_owned(), json!("b"))]
    );
    assert_eq!(b.warnings("backchannel_declined"), 0, "{:?}", b.seen);
    assert_eq!(api.session("a").await["backchannel"]["negotiated"], false);

    // b re-offers its talk-back m-line `sendonly` in two-channel PCMU
    // only: it lets go.
    let dropped = b.peer.viewer.reoffer(Reoffer::Drop).expect("a re-offer");
    let at = dropped.rfind("m=audio ").expect("the talk-back m-line");
    let sdp = two_channel_talkback(&format!(
        "{}{}",
        &dropped[..at],
        dropped[at..].replacen("a=inactive", "a=sendonly", 1)
    ));
    assert!(sdp[at..].contains("a=sendonly"), "{sdp}");
    api.call(&json!({ "id": 20, "type": "webrtc/renegotiate", "session_id": "b", "sdp": sdp }))
        .await;
    pump(&mut api, &mut [&mut a, &mut b], |api, peers| {
        api.talker_changes().len() >= 2 && peers[1].warnings("backchannel_declined") > 0
    })
    .await;
    assert_eq!(
        api.talker_changes()[1],
        ("b".to_owned(), "renegotiated".to_owned(), Value::Null)
    );
    assert_eq!(api.stream().await["backchannel"]["talker"], Value::Null);
    let declined = b
        .seen
        .iter()
        .find(|event| event["code"] == "backchannel_declined")
        .unwrap();
    assert_eq!(declined["reason"], "unsupported");
    api.stop().await;
}

/// The downlink frames a viewer received in `window`, by arrival: their
/// largest gap, and the RTP timestamp steps between them.
fn video_in(viewer: &Viewer, window: (Instant, Instant)) -> (Duration, Vec<u32>, usize) {
    let frames: Vec<_> = viewer
        .packets()
        .iter()
        .filter(|packet| packet.timestamp >= window.0 && packet.timestamp < window.1)
        .collect();
    let gap = frames
        .windows(2)
        .map(|pair| pair[1].timestamp.duration_since(pair[0].timestamp))
        .max()
        .unwrap_or(Duration::MAX);
    let steps = frames
        .windows(2)
        .map(|pair| {
            pair[1]
                .header
                .timestamp
                .wrapping_sub(pair[0].header.timestamp)
        })
        .collect();
    (gap, steps, frames.len())
}

/// A client that only talks back opens a session of its own beside a
/// viewer's: its offer has one `sendonly` audio m-line and no video, which
/// claims the backchannel as a viewer's offer does and is answered
/// `recvonly` (RFC 8829 §5.3.1), and its tone reaches the camera, while
/// the viewer, which offered no talk-back, plays on and the talker gets
/// no media. A second such client is declined `busy` (RFC 3264 §6.1:
/// answered `inactive`); closing the talker frees the backchannel for
/// its re-offer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8829_5_3_1_a_talk_only_session_beside_a_viewer_talks_to_the_camera() {
    let mut api = Api::start(&json!({ "backchannel": "pcmu", "video": true })).await;
    let mut v = ApiPeer::offer_silent(&api, "v").await;
    let mut t = ApiPeer::offer_talk_only(&api, "t").await;
    assert!(!t.peer.offer.contains("m=video"), "{}", t.peer.offer);
    pump(&mut api, &mut [&mut v, &mut t], |api, peers| {
        peers.iter().all(|p| p.peer.viewer.is_connected()) && !api.talker_changes().is_empty()
    })
    .await;
    assert_eq!(
        t.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::SendOnly)
    );
    assert_eq!(t.peer.pt, Some(0));
    assert_eq!(v.peer.viewer.talkback_direction(), None);
    assert_eq!(
        api.talker_changes(),
        [("t".to_owned(), "claimed".to_owned(), json!("t"))]
    );

    t.peer.talk(Mic::pcmu());
    let talker = session_where(&mut api, &mut [&mut v, &mut t], "t", |bc| {
        bc["bytes_sent"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(talker["talker"], true);
    assert_eq!(talker["codec"], "pcmu");
    let video = v.peer.viewer.packets().len();
    pump_for(&mut api, &mut [&mut v, &mut t], Duration::from_millis(500)).await;
    assert!(v.peer.viewer.packets().len() > video, "the viewer plays on");
    assert!(v.peer.viewer.packets().len() >= 15, "{video}");
    assert!(t.peer.viewer.packets().is_empty());
    assert!(t.peer.viewer.audio_packets().is_empty());

    let mut u = ApiPeer::offer_talk_only(&api, "u").await;
    pump(&mut api, &mut [&mut v, &mut t, &mut u], |_, peers| {
        peers[2].peer.viewer.is_connected() && peers[2].warnings("backchannel_declined") == 1
    })
    .await;
    assert_eq!(
        u.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::Inactive)
    );

    api.call(&json!({ "id": 6, "type": "session/close", "session_id": "t" }))
        .await;
    pump(&mut api, &mut [&mut v, &mut t, &mut u], |api, _| {
        api.talker_changes().len() >= 2
    })
    .await;
    u.renegotiate(&api, Reoffer::Talkback(TalkbackOffer::Dedicated))
        .await;
    assert_eq!(
        u.peer.viewer.talkback_direction(),
        Some(lotse_testing::viewer::Direction::SendOnly)
    );
    pump(&mut api, &mut [&mut v, &mut u], |api, _| {
        api.talker_changes().len() >= 3
    })
    .await;
    assert_eq!(api.talker_changes()[2].0, "u");
    api.stop().await;
}

/// Pressing the microphone (the
/// viewer starts sending on its talk-back m-line, `replaceTrack`) claims
/// the backchannel without disturbing the downlink: video frames keep
/// arriving at the camera's 30 fps, no gap, and their timeline goes on
/// without a jump, since the backchannel opens in a session of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activating_talk_back_leaves_no_gap_in_the_video() {
    let mut api = Api::start(&json!({ "backchannel": "pcmu", "video": true })).await;
    let mut v = ApiPeer::offer(&api, "v").await;
    // Playing: past the first keyframe and a second of video.
    pump(&mut api, &mut [&mut v], |_, peers| {
        peers[0].peer.viewer.is_connected() && peers[0].peer.viewer.packets().len() >= 30
    })
    .await;
    pump_for(&mut api, &mut [&mut v], Duration::from_secs(1)).await;
    let activation = clock().now();
    v.peer.talk(Mic::pcmu());
    pump(&mut api, &mut [&mut v], |api, _| {
        !api.talker_changes().is_empty()
    })
    .await;
    pump_for(&mut api, &mut [&mut v], Duration::from_secs(1)).await;
    let end = clock().now();
    assert_eq!(
        api.talker_changes(),
        [("v".to_owned(), "claimed".to_owned(), json!("v"))]
    );
    let talking = api.session("v").await["backchannel"].clone();
    assert_eq!(talking["talker"], true);

    let second = Duration::from_secs(1);
    let (before_gap, _, before) = video_in(
        &v.peer.viewer,
        (activation.checked_sub(second).unwrap(), activation),
    );
    let (gap, steps, after) = video_in(
        &v.peer.viewer,
        (activation.checked_sub(second / 2).unwrap(), end),
    );
    println!(
        "video around activation: largest gap {gap:?} (before {before_gap:?}), {before} frames in the second before"
    );
    // A frame every 33 ms: a gap of three frames would be a visible stall.
    assert!(
        gap <= Duration::from_millis(100),
        "a {gap:?} gap across activation"
    );
    assert!(before >= 25, "{before} frames in the second before");
    assert!(
        after as f64 >= 0.85 * 30.0 * (end - activation + second / 2).as_secs_f64(),
        "{after} frames from half a second before activation"
    );
    // RFC 3550 §5.1: one frame's ticks apart, the session's timeline
    // never reset.
    assert!(steps.iter().all(|&step| step == 3_000), "{steps:?}");
    let stream = api.stream().await;
    assert_eq!(stream["state"], "live");
    assert_eq!(stream["sources"][0]["connection"]["worker"]["restarts"], 0);
    api.stop().await;
}

/// ONVIF Streaming Specification §5.3.1: opting a stream in and out, twice,
/// while a viewer plays restarts nothing. The camera serves one viewing
/// session throughout (one `DESCRIBE` without `Require`, one `SETUP`
/// each, one `PLAY`), and the viewer's video goes on without a gap or a
/// new timeline. Each opt-in probes on a connection of its own and offers
/// the backchannel, which the viewer's re-offer claims; each opt-out
/// drops the offer (`stream/get`'s `sources[].backchannel` gone) and frees
/// the talker (`talker_changed` `opted_out`), whose backchannel session
/// the camera sees torn down with `Require` and closed.
#[cfg(feature = "source-rtsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_1_opting_in_and_out_leaves_the_video_alone_and_frees_the_talker() {
    let camera = FakeCamera::start(
        CameraConfig {
            fps: 30,
            gop: 10,
            backchannel: Some(CameraBackchannel::new(BackchannelCodec::Pcmu)),
            keep_open_on_teardown: true,
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let put = |options: Value| {
        json!({ "id": 2, "type": "stream/put", "stream_id": "door",
                "sources": [{ "url": camera.url(), "options": options }] })
    };
    let mut api = Api::start_with(
        Arc::new(lotse_rtsp::RtspFactory::default()),
        &camera.url(),
        &json!({}),
        "off",
    )
    .await;
    let mut v = ApiPeer::offer_silent(&api, "v").await;
    // Playing: past the first keyframe and a second of video.
    pump(&mut api, &mut [&mut v], |_, peers| {
        peers[0].peer.viewer.is_connected() && peers[0].peer.viewer.packets().len() >= 30
    })
    .await;
    pump_for(&mut api, &mut [&mut v], Duration::from_secs(1)).await;
    let start = clock().now();
    for round in 1..=2 {
        api.call(&put(json!({ "backchannel": true }))).await;
        source_where(
            &mut api,
            &mut [&mut v],
            &json!({ "codec": "pcmu", "state": "available" }),
        )
        .await;
        v.renegotiate(&api, Reoffer::Talkback(TalkbackOffer::Dedicated))
            .await;
        assert_eq!(
            v.peer.viewer.talkback_direction(),
            Some(lotse_testing::viewer::Direction::SendOnly),
            "round {round}: claimed"
        );
        if round == 1 {
            v.peer.talk(Mic::pcmu());
        }
        pump(&mut api, &mut [&mut v], |_, _| {
            backchannel_session(&camera).is_some_and(|log| log.backchannel_packets > 0)
                && camera
                    .stats()
                    .connection_log()
                    .iter()
                    .filter(|log| log.backchannel_only())
                    .count()
                    == round
        })
        .await;
        api.call(&put(json!({}))).await;
        pump(&mut api, &mut [&mut v], |api, _| {
            api.talker_changes()
                .iter()
                .filter(|change| **change == ("v".to_owned(), "opted_out".to_owned(), Value::Null))
                .count()
                == round
                && backchannel_session(&camera).is_some_and(|log| log.closed)
        })
        .await;
        let log = backchannel_session(&camera).unwrap();
        assert_eq!(
            log.teardown,
            Some(true),
            "round {round}: TEARDOWN with Require"
        );
        assert!(log.closed_by_client, "round {round}: {log:?}");
        let stream = source_where(&mut api, &mut [&mut v], &Value::Null).await;
        assert_eq!(
            stream["backchannel"]["talker"],
            Value::Null,
            "round {round}"
        );
    }
    pump_for(&mut api, &mut [&mut v], Duration::from_millis(500)).await;
    let end = clock().now();
    let changes: Vec<String> = api
        .talker_changes()
        .into_iter()
        .map(|(session, reason, _)| format!("{session} {reason}"))
        .collect();
    assert_eq!(
        changes,
        ["v claimed", "v opted_out", "v claimed", "v opted_out"]
    );
    let (gap, steps, frames) = video_in(&v.peer.viewer, (start, end));
    println!("video across two opt-ins and opt-outs: largest gap {gap:?}, {frames} packets");
    // A frame every 33 ms: a gap of three frames would be a visible stall.
    assert!(gap <= Duration::from_millis(100), "a {gap:?} gap");
    // RFC 3550 §5.1: a frame's ticks apart, or a frame's packets together;
    // the session's timeline never reset.
    assert!(
        steps.iter().all(|&step| step == 0 || step == 3_000),
        "{steps:?}"
    );
    let logs = camera.stats().connection_log();
    let viewing: Vec<_> = logs
        .iter()
        .filter(|log| log.setups.iter().any(|setup| setup == "track0"))
        .collect();
    assert_eq!(viewing.len(), 1, "one viewing session: {logs:?}");
    assert_eq!(viewing[0].describes, [false]);
    assert!(viewing[0].played && !viewing[0].closed);
    let probes = logs
        .iter()
        .filter(|log| log.describes == [true] && log.setups.is_empty())
        .count();
    assert_eq!(probes, 2, "one probe per opt-in: {logs:?}");
    let stream = api.stream().await;
    assert_eq!(stream["state"], "live");
    assert_eq!(stream["sources"][0]["connection"]["worker"]["restarts"], 0);
    api.stop().await;
    camera.stop().await;
}
