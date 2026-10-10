//! Two-way audio end to end: headless str0m viewers negotiate the dedicated talk-back m-line and send
//! a real tone, Opus from libopus or PCMU, towards a camera whose
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
//! `stream/get`. The RTSP source cannot send yet (retina cannot; an
//! upstream need).
//! Needs the `source-fake` feature (on with `--all-features`) and
//! `output-webrtc` (a default).

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
use lotse_core::task::spawn_named;
use lotse_core::test_util::{BackchannelCapture, Captured, FakeSourceFactory};
use lotse_core::track::TrackLimits;
use lotse_ipc::{
    Channel, SessionEvent, SessionSpec, SourceSpec, SourceState, ToSupervisor, ToWorker,
};
use lotse_supervisor::api::{ConnectionId, Event, Handler as _, Outcome};
use lotse_supervisor::net::demux::{Demux, Registration, WorkerSink};
use lotse_supervisor::net::udp::bind_udp;
use lotse_supervisor::worker::WorkerConfig;
use lotse_supervisor::{Environment, FrontDoor, Identity, Limits, Settings, Supervisor};
use lotse_testing::viewer::{Outgoing, TalkbackOffer, Viewer, with_audio_codecs};
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

/// The daemon's share of the uplink latency, onset in to
/// onset out at the backchannel handle, for 20 ms G.711 frames.
const UPLINK_LATENCY: Duration = Duration::from_millis(40);

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
    /// PCMU at 8 kHz with lotse-codec's G.711 (ITU-T G.711), as a browser
    /// sends it natively.
    Pcmu,
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
    /// When each packet was handed to the socket, by index.
    sent: Vec<Instant>,
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
            sent: Vec::new(),
            payloads: Vec::new(),
        }
    }

    fn pcmu() -> Self {
        Self::new(MicCodec::Pcmu)
    }

    fn opus() -> Self {
        Self::new(MicCodec::Opus(Box::new(Encoder::new(1).expect("libopus"))))
    }

    /// The sampling rate of its timestamps.
    const fn rate(&self) -> u32 {
        match self.codec {
            MicCodec::Pcmu => 8_000,
            MicCodec::Opus(_) => 48_000,
        }
    }

    /// The next packet's payload and the timestamp step after it.
    fn encode(&mut self) -> (Vec<u8>, u32) {
        let packet = self.index;
        match &mut self.codec {
            MicCodec::Pcmu => {
                let first = u64::from(packet) * 160;
                let payload = (first..first + 160)
                    .map(|n| {
                        Law::Mu.encode((tone_sample(n, 8_000, packet) * 32_767.0).round() as i16)
                    })
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
            let (payload, step) = mic.encode();
            self.viewer
                .send_talkback(
                    now,
                    (pt, mic.seq, mic.ts, mic.marker),
                    &payload,
                    &mut self.out,
                )
                .expect("a send stream on the talk-back m-line");
            mic.sent.push(now);
            mic.payloads.push(payload);
            mic.index += 1;
            mic.marker = false;
            mic.seq = mic.seq.wrapping_add(1);
            mic.ts = mic.ts.wrapping_add(step);
            mic.next += FRAME;
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
    live: bool,
}

impl InProcess {
    async fn start(capture: &BackchannelCapture, options: &str) -> Self {
        let mut registries = Registries::default();
        registries
            .sources
            .register(Arc::new(FakeSourceFactory::capturing(
                &["fake"],
                capture.clone(),
            )))
            .unwrap();
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
                url: "fake://cam/".into(),
                options: options.into(),
                peer_host: "cam".into(),
                peer_addrs: vec![],
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
            live: false,
        };
        worker.pump(&mut [], |w, _| w.live).await;
        worker
    }

    /// Opens session `id` on `offer`, registered with the demux under its
    /// own credentials.
    async fn open(&mut self, id: &str, offer: &str) {
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
                    audio: false,
                    orientation: 1,
                }),
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
                    ToSupervisor::SourceState(SourceState::Live) => self.live = true,
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
    // Every packet's frame, and the playout buffer's one frame after it.
    worker
        .pump(&mut [&mut peer], |_, _| {
            capture.packets().len() >= TONE_PACKETS as usize
        })
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

/// The checks every tone run passes:
/// whole G.711 frames of the camera's law with continuous timestamps,
/// paced at the frame duration; the tone at its frequency in every burst;
/// and the daemon's share of the latency, onset in to onset out at the
/// handle. Returns the latency of each onset.
fn check_tone(run: &ToneRun, law: Law) -> Vec<Duration> {
    let frames = &run.captured[..TONE_PACKETS as usize];
    // RFC 3551 §4.5.14: the law's static payload type, 8000 Hz, 20 ms
    // frames of 160 samples; RFC 3550 §5.1: one sequence number and 160
    // timestamp ticks apart, the marker on the spurt's first only
    // (RFC 3551 §4.1).
    for (i, frame) in frames.iter().enumerate() {
        let packet = &frame.packet;
        assert_eq!(packet.rtp.pt, law.payload_type(), "frame {i}");
        assert_eq!(packet.payload.len(), 160, "frame {i}");
        assert_eq!(packet.rtp.marker, i == 0, "frame {i}");
        if let Some(next) = frames.get(i + 1) {
            assert_eq!(
                next.packet.rtp.ts.wrapping_sub(packet.rtp.ts),
                160,
                "continuous timestamps after frame {i}"
            );
            assert_eq!(next.packet.rtp.seq.wrapping_sub(packet.rtp.seq), 1);
        }
    }
    // Paced on an absolute schedule: no drift over the run, each frame
    // near its slot (a loaded machine may wake the camera's task late).
    let first = frames[0].at;
    let span = frames[frames.len() - 1].at.duration_since(first);
    let mean = span / (frames.len() as u32 - 1);
    assert!(
        mean.abs_diff(FRAME) <= Duration::from_micros(500),
        "frames every {mean:?} on average"
    );
    let off_grid: Vec<Duration> = frames
        .iter()
        .enumerate()
        .map(|(i, frame)| frame.at.duration_since(first).abs_diff(FRAME * i as u32))
        .collect();
    let p95 = percentile(&off_grid, 95);
    assert!(
        p95 <= Duration::from_millis(5),
        "p95 {p95:?} off the 20 ms grid"
    );

    // The tone survives at its frequency: in each burst's inner frames
    // (its edges carry the onset and the decay), nearly all of the energy
    // is at 1 kHz, next to none at the neighbours.
    let pcm: Vec<Vec<i16>> = frames
        .iter()
        .map(|frame| {
            frame
                .packet
                .payload
                .iter()
                .map(|&code| law.decode(code))
                .collect()
        })
        .collect();
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
            frames[onset_out]
                .at
                .saturating_duration_since(run.mic.sent[onset_in as usize])
        })
        .collect()
}

/// The latency gate on a run's onsets: their median, so one late wake of
/// a loaded machine cannot fail it, within 40 ms. Returns the median.
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
/// route and `ToG711` (Opus decoded at 8 kHz, μ-law encoded, one-frame
/// playout) into the backchannel handle as the tone, paced and in time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc6716_an_opus_tone_reaches_a_pcmu_camera_at_its_frequency_paced_within_40_ms() {
    let run = tone_run(
        "pcmu",
        Some("a=rtpmap:111 opus/48000/2\na=fmtp:111 minptime=10;useinbandfec=1"),
        Mic::opus(),
    )
    .await;
    assert_eq!(run.pt, 111, "the browser sends Opus");
    assert_eq!(run.talkback.as_deref(), Some("opus"));
    let latencies = check_tone(&run, Law::Mu);
    let median = check_latency(&latencies);
    println!("Opus to PCMU: uplink latency per onset {latencies:?}, median {median:?}");
}

/// The reverse chain, G.711 in and out: the browser offers PCMU and
/// the camera wants PCMU, so the answer names PCMU and the codes pass
/// through untouched; only framing and pacing apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3551_4_5_14_a_pcmu_tone_passes_through_to_a_pcmu_camera_paced_within_40_ms() {
    let run = tone_run("pcmu", None, Mic::pcmu()).await;
    assert_eq!(run.pt, 0, "the browser sends PCMU (RFC 3551 Table 4)");
    assert_eq!(run.talkback.as_deref(), Some("pcmu"));
    let latencies = check_tone(&run, Law::Mu);
    // The frames are the browser's packets, code for code; at most a
    // packet late for its slot (concealed) and the one it displaced differ.
    let identical = run
        .captured
        .iter()
        .zip(&run.mic.payloads)
        .filter(|(frame, sent)| *frame.packet.payload == sent[..])
        .count();
    assert!(
        identical + 2 >= TONE_PACKETS as usize,
        "{identical} of {TONE_PACKETS} frames as sent"
    );
    let median = check_latency(&latencies);
    println!("PCMU to PCMU: uplink latency per onset {latencies:?}, median {median:?}");
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
        registries
            .sources
            .register(Arc::new(FakeSourceFactory::with_backchannel(&["fake"])))
            .unwrap();
        registries.uplink = Some(Arc::new(ToG711Factory::new(clock())));
        let environment = Environment {
            registries,
            worker: WorkerConfig {
                binary: PathBuf::from(env!("CARGO_BIN_EXE_lotse")),
                log_format: "json".into(),
                log_level: "info".into(),
                sandbox: "off".into(),
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
                    git_sha: None,
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
                         "sources": [{ "url": "fake://127.0.0.1/", "options": options }] }),
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
        Outcome::Subscribed(_) => panic!("subscription"),
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
        let peer = Peer::new(None).await;
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
            peer,
            events,
            seen: Vec::new(),
        }
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

/// Talker arbitration through the control API: two viewers negotiate
/// talk-back; neither holds the backchannel until it sends; the first
/// sender claims it, the second gets exactly one `backchannel_busy` and its
/// packets are dropped; the holder going silent keeps it; closing the
/// holder's session frees it, and so does `backchannel/release`. Each
/// change is a `talker_changed`, and `session/get` and `stream/get` say
/// who holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_viewers_claim_hold_and_free_the_backchannel_through_the_control_api() {
    let mut api = Api::start(&json!({ "backchannel": "pcmu" })).await;
    let mut a = ApiPeer::offer(&api, "a").await;
    let mut b = ApiPeer::offer(&api, "b").await;
    pump(&mut api, &mut [&mut a, &mut b], |_, peers| {
        peers.iter().all(|p| p.peer.viewer.is_connected())
    })
    .await;
    // Both answered recvonly in the camera's PCMU; nobody talks yet.
    for peer in [&a, &b] {
        assert_eq!(
            peer.peer.viewer.talkback_direction(),
            Some(lotse_testing::viewer::Direction::SendOnly)
        );
        assert_eq!(peer.peer.pt, Some(0));
        let backchannel = api.session(peer.id).await["backchannel"].clone();
        assert_eq!(
            backchannel,
            json!({ "negotiated": true, "talker": false, "codec": "pcmu", "packets_received": 0,
                    "packets_dropped_busy": 0, "bytes_sent": 0 }),
            "{}",
            peer.id
        );
    }
    assert_eq!(
        api.stream().await["backchannel"],
        json!({ "talker": null, "since": null })
    );
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_millis(300)).await;
    assert!(api.talker_changes().is_empty(), "{:?}", api.stream_seen);

    // a sends first and claims it.
    a.peer.talk(Mic::pcmu());
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        !api.talker_changes().is_empty()
    })
    .await;
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

    // b sends while a holds it: one warning, every packet dropped. The
    // counters are read once b paused and its packets are through: the
    // worker pushes them once a second, and two counters read while
    // packets arrive may be a packet apart.
    b.peer.talk(Mic::pcmu());
    pump(&mut api, &mut [&mut a, &mut b], |_, peers| {
        peers[1].warnings("backchannel_busy") > 0
    })
    .await;
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_millis(500)).await;
    let mut b_mic = b.peer.mute();
    let b_sent = u64::from(b_mic.index);
    let refused = |bc: &Value| {
        bc["packets_received"].as_u64() == Some(b_sent)
            && bc["packets_dropped_busy"] == bc["packets_received"]
    };
    let busy = session_where(&mut api, &mut [&mut a, &mut b], "b", refused).await;
    assert_eq!(busy["talker"], false);
    assert_eq!(busy["bytes_sent"], 0, "none of b's reached the camera");
    let holder = api.session("a").await["backchannel"].clone();
    assert_eq!(holder["talker"], true);
    assert_eq!(holder["packets_dropped_busy"], 0);
    assert!(holder["bytes_sent"].as_u64().unwrap() > 0, "{holder}");

    // a goes silent: it still holds the backchannel, b is still refused,
    // and b hears about it only the once.
    a.peer.mute();
    b.peer.talk(b_mic);
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_secs(1)).await;
    assert_eq!(api.talker_changes().len(), 1, "{:?}", api.stream_seen);
    assert_eq!(api.stream().await["backchannel"]["talker"], "a");
    b_mic = b.peer.mute();
    let b_sent = u64::from(b_mic.index);
    let refused = |bc: &Value| {
        bc["packets_received"].as_u64() == Some(b_sent)
            && bc["packets_dropped_busy"] == bc["packets_received"]
    };
    let busy = session_where(&mut api, &mut [&mut a, &mut b], "b", refused).await;
    assert_eq!(busy["bytes_sent"], 0);
    assert_eq!(b.warnings("backchannel_busy"), 1, "{:?}", b.seen);
    b.peer.talk(b_mic);

    // Closing a's session frees it; b's next packet claims it.
    api.call(&json!({ "id": 6, "type": "session/close", "session_id": "a" }))
        .await;
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
    let talking = session_where(&mut api, &mut [&mut a, &mut b], "b", |bc| {
        bc["bytes_sent"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(talking["talker"], true);

    // b goes silent and the client releases the backchannel: free, and it stays
    // free until someone sends. The release waits until b's last packets
    // are through, or one still on its way would claim it back.
    let b_mic = b.peer.mute();
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
    pump_for(&mut api, &mut [&mut a, &mut b], Duration::from_millis(300)).await;
    assert_eq!(api.stream().await["backchannel"]["talker"], Value::Null);
    assert_eq!(api.session("b").await["backchannel"]["talker"], false);
    // The released talker may claim it again by sending.
    b.peer.talk(b_mic);
    pump(&mut api, &mut [&mut a, &mut b], |api, _| {
        api.talker_changes().len() >= 5
    })
    .await;
    assert_eq!(
        api.talker_changes()[4],
        ("b".to_owned(), "claimed".to_owned(), json!("b"))
    );
    // Exactly one busy warning in all of it, to the second sender.
    assert_eq!(a.warnings("backchannel_busy"), 0);
    assert_eq!(b.warnings("backchannel_busy"), 1, "{:?}", b.seen);
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

/// Pressing the microphone (the
/// viewer starts sending on its talk-back m-line, `replaceTrack`) claims
/// the backchannel without disturbing the downlink: video frames keep
/// arriving at the camera's 30 fps, no gap, and their timeline goes on
/// without a jump, since the backchannel was set up with the stream.
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
