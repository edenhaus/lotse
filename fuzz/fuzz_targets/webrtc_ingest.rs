//! `webrtc_ingest`: the WebRTC ingest engine never panics on whatever a
//! camera, its integration or a stranger sends it, and keeps its output
//! contract. The engine makes its offer; the answer is either arbitrary
//! text or a str0m camera's real answer with arbitrary bytes spliced in
//! (so the fuzzer reaches the engine past str0m's SDP parser), and then
//! the input drives trickled candidates, datagrams of arbitrary bytes from
//! the camera's address and from an unknown one, the camera's own
//! datagrams when there is a camera, the camera's RTP (any payload type,
//! sequence number and payload, on either m-line; its Sender Reports come
//! with it), time, keyframes and the close. The contract: at most one
//! `Tracks`, video among them; `Connected` at most once, after them; a
//! switch and RTP only of the indices declared; at most one `Ended`, and
//! after it nothing but close datagrams and timeouts; `poll` always comes
//! to a timeout.
//! Run with `cargo +nightly fuzz run webrtc_ingest` from the repository
//! root.

#![no_main]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use lotse_core::codec::Kind;
use lotse_core::signaling::SignalCandidate;
use lotse_webrtc::ingest::{IngestEngine, IngestOutput, WebRtcOptions};
use str0m::change::SdpOffer;
use str0m::media::{Mid, Pt};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::rtp::{ExtensionValues, RtpWrite, SeqNo};
use str0m::{Candidate, Input, Output, Rtc};

/// The engine's host candidate.
const ENGINE: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
    5_000,
);
/// The camera's.
const CAMERA: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20)),
    6_000,
);
/// Someone else on the network.
const STRANGER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
    40_000,
);

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

/// What the engine said so far, checked against its contract.
#[derive(Default)]
struct Seen {
    /// The indices of the tracks declared, once declared.
    tracks: Option<Vec<usize>>,
    /// It said it connected.
    connected: bool,
    /// It ended.
    ended: bool,
}

/// The engine, a camera if one answered, the time and the datagrams.
struct Run {
    engine: IngestEngine,
    camera: Option<Rtc>,
    now: Instant,
    to_camera: Vec<(SocketAddr, Vec<u8>)>,
    seen: Seen,
    /// The offer's audio m-line, if any.
    audio: Option<Mid>,
    /// The offer's video m-line.
    video: Option<Mid>,
}

impl Run {
    /// Takes everything the engine has, checking the contract.
    fn drain(&mut self) {
        // Bounded: an engine that never runs dry is a finding too.
        for _ in 0..100_000 {
            match self.engine.poll() {
                IngestOutput::Timeout(_) => return,
                IngestOutput::Transmit {
                    source,
                    destination,
                    payload,
                } => {
                    assert_eq!(source, ENGINE, "only from the host candidate");
                    if destination == CAMERA {
                        self.to_camera.push((source, payload));
                    }
                }
                IngestOutput::Tracks(tracks) => {
                    assert!(!self.seen.ended, "no tracks after the end");
                    assert!(self.seen.tracks.is_none(), "tracks declared once");
                    assert!(
                        tracks.iter().any(|t| t.declared.kind == Kind::Video),
                        "video among the tracks"
                    );
                    self.seen.tracks = Some(tracks.iter().map(|t| t.index).collect());
                }
                IngestOutput::Connected => {
                    assert!(!self.seen.ended, "not connected after the end");
                    assert!(!self.seen.connected, "connected once");
                    assert!(self.seen.tracks.is_some(), "connected after the answer");
                    self.seen.connected = true;
                }
                IngestOutput::Switched(track) => {
                    assert!(!self.seen.ended, "no switch after the end");
                    let declared = self.seen.tracks.as_deref().unwrap_or_default();
                    assert!(
                        declared.contains(&track.index),
                        "a switch of a declared track"
                    );
                }
                IngestOutput::Rtp { index, .. } | IngestOutput::SenderReport { index, .. } => {
                    assert!(!self.seen.ended, "no media after the end");
                    let declared = self.seen.tracks.as_deref().unwrap_or_default();
                    assert!(declared.contains(&index), "media of a declared track");
                }
                IngestOutput::Ended(_) => {
                    assert!(!self.seen.ended, "one end");
                    self.seen.ended = true;
                }
            }
        }
        panic!("the engine never stops producing output");
    }

    /// The camera writes one RTP packet on the m-line `video` picks, of
    /// payload type `pt`, number `seq` and timestamp `ts`, with the RFC
    /// 9143 `mid` header extension; nothing without a camera or before it
    /// knows its stream.
    fn write(&mut self, video: bool, pt: u8, seq: u16, ts: u32, payload: &[u8]) {
        let now = self.now;
        let Some(camera) = self.camera.as_mut() else {
            return;
        };
        let Some(mid) = (if video { self.video } else { self.audio }) else {
            return;
        };
        let mut api = camera.direct_api();
        let Some(stream) = api.stream_tx_by_mid(mid, None) else {
            return;
        };
        let _ = stream.write_rtp(
            RtpWrite::new(
                Pt::from(pt),
                SeqNo::from(u64::from(seq)),
                ts,
                now,
                Arc::<[u8]>::from(payload),
            )
            .marker(seq & 1 == 0)
            .ext_vals(ExtensionValues {
                mid: Some(mid),
                ..ExtensionValues::default()
            }),
        );
    }

    /// Moves the camera's datagrams into the engine and the engine's into
    /// the camera, `advance` later.
    fn step(&mut self, advance: Duration) {
        self.now += advance;
        self.engine.handle_timeout(self.now);
        self.drain();
        let Some(camera) = self.camera.as_mut() else {
            self.to_camera.clear();
            return;
        };
        for (source, payload) in std::mem::take(&mut self.to_camera) {
            if let Ok(contents) = DatagramRecv::try_from(payload.as_slice()) {
                let _ = camera.handle_input(Input::Receive(
                    self.now,
                    Receive {
                        proto: Protocol::Udp,
                        source,
                        destination: CAMERA,
                        contents,
                    },
                ));
            }
        }
        let _ = camera.handle_input(Input::Timeout(self.now));
        let mut out = Vec::new();
        for _ in 0..10_000 {
            match camera.poll_output() {
                Ok(Output::Transmit(t)) => out.push(Vec::from(t.contents)),
                Ok(Output::Event(_)) => {}
                Ok(Output::Timeout(_)) | Err(_) => break,
            }
        }
        for payload in out {
            self.engine.receive(self.now, CAMERA, ENGINE, &payload);
            self.drain();
        }
    }
}

/// The mid of the offer's first `m=<kind>` section.
fn mid_of(offer: &str, kind: &str) -> Option<Mid> {
    offer
        .split(&format!("m={kind}"))
        .nth(1)?
        .lines()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .map(Mid::from)
}

/// A str0m camera's answer to `offer`, and the camera: H.264, H.265 and
/// Opus.
fn camera_answer(offer: &str, now: Instant) -> Option<(Rtc, String)> {
    let mut rtc = Rtc::builder()
        .set_rtp_mode(true)
        .clear_codecs()
        .enable_h264(true)
        .enable_h265(true)
        .enable_opus(true, false)
        .build(now);
    rtc.add_local_candidate(Candidate::host(CAMERA, "udp").ok()?);
    let offer = SdpOffer::from_sdp_string(offer).ok()?;
    let answer = rtc.sdp_api().accept_offer(offer).ok()?;
    Some((rtc, answer.to_sdp_string()))
}

fuzz_target!(|data: &[u8]| {
    lotse_webrtc::install_crypto_provider();
    let mut rest = data;
    let Some([setup]) = take::<1>(&mut rest) else {
        return;
    };
    // Bit 0: audio; bit 1: the data channel; bit 2: a camera answers.
    let options = WebRtcOptions {
        data_channel: (setup & 2 != 0).then(|| "dataSendChannel".to_owned()),
        audio: setup & 1 != 0,
    };
    let t0 = Instant::now();
    let Ok(engine) = IngestEngine::offer(&options, &[ENGINE], t0, t0) else {
        // str0m 0.24 can draw one mid twice; the engine refuses that offer.
        return;
    };
    assert!(engine.offer_sdp().len() <= 16 * 1024, "the offer budget");
    let audio = mid_of(engine.offer_sdp(), "audio");
    let video = mid_of(engine.offer_sdp(), "video");
    let mut run = Run {
        engine,
        camera: None,
        now: t0,
        to_camera: Vec::new(),
        seen: Seen::default(),
        audio,
        video,
    };
    run.drain();
    if setup & 4 != 0 {
        let Some((camera, answer)) = camera_answer(run.engine.offer_sdp(), t0) else {
            return;
        };
        // [offset:u16][splice] spliced into the real answer.
        let mut answer = answer.into_bytes();
        if let (Some(at), Some(splice)) = (take::<2>(&mut rest), bytes(&mut rest)) {
            let at = usize::from(u16::from_le_bytes(at)) % (answer.len() + 1);
            let end = (at + splice.len()).min(answer.len());
            answer.splice(at..end, splice.iter().copied());
        }
        run.camera = Some(camera);
        run.engine
            .accept_answer(run.now, &String::from_utf8_lossy(&answer));
        run.drain();
    }
    while let Some([op]) = take::<1>(&mut rest) {
        match op % 9 {
            0 => {
                let Some(body) = bytes(&mut rest) else { break };
                run.engine
                    .accept_answer(run.now, &String::from_utf8_lossy(body));
                run.drain();
            }
            1 => {
                let (Some([mline]), Some(body)) = (take::<1>(&mut rest), bytes(&mut rest)) else {
                    break;
                };
                let candidate = SignalCandidate {
                    candidate: String::from_utf8_lossy(body).into_owned(),
                    sdp_mid: (mline & 1 != 0).then(|| "0".to_owned()),
                    sdp_mline_index: (mline & 2 != 0).then_some(u16::from(mline >> 2)),
                };
                run.engine.add_remote_candidate(run.now, &candidate);
                run.drain();
            }
            2 | 3 => {
                let Some(body) = bytes(&mut rest) else { break };
                let from = if op % 8 == 2 { CAMERA } else { STRANGER };
                run.engine.receive(run.now, from, ENGINE, body);
                run.drain();
            }
            4 => {
                let Some(ms) = take::<2>(&mut rest) else {
                    break;
                };
                run.step(Duration::from_millis(u64::from(u16::from_le_bytes(ms))));
            }
            5 => {
                run.engine.keyframe_seen();
                run.drain();
            }
            6 => {
                run.engine.close();
                run.drain();
                assert!(run.engine.is_ended());
                run.seen.ended = true;
            }
            7 => {
                // [m-line:u8][pt:u8][seq:u16][ts:u32][payload]
                let (Some([mline]), Some([pt]), Some(seq), Some(ts), Some(payload)) = (
                    take::<1>(&mut rest),
                    take::<1>(&mut rest),
                    take::<2>(&mut rest),
                    take::<4>(&mut rest),
                    bytes(&mut rest),
                ) else {
                    break;
                };
                run.write(
                    mline & 1 != 0,
                    pt & 0x7f,
                    u16::from_le_bytes(seq),
                    u32::from_le_bytes(ts),
                    payload,
                );
                // Through the camera's pacer, its Sender Reports when due.
                run.step(Duration::ZERO);
            }
            _ => run.step(Duration::from_millis(5)),
        }
    }
    for _ in 0..10 {
        run.step(Duration::from_millis(10));
    }
    let _stats = run.engine.stats();
});
