//! The sans-I/O engine of one WebRTC ingest attempt: lotse makes the offer
//! to a camera, applies its answer and candidates, and receives its media.
//! No socket and no clock: the caller hands it datagrams and the time, and
//! takes what it wants sent, the tracks the answer negotiated, the RTP and
//! Sender Reports of those tracks, its deadlines and how it ended
//! ([`IngestOutput`]).
//!
//! The offer (RFC 8829 §5.2.1): an `audio` m-line `recvonly` when the
//! options ask for audio, a `video` m-line `recvonly`, then an
//! `application` m-line when a data channel is configured, the order the
//! cameras' integrations take (Nest refuses an offer without the data
//! channel's m-line; observed in go2rtc's Nest client, 2026-10). Codecs:
//! H.264 in several profiles and both packetization modes (RFC 6184
//! §8.1), H.265 (RFC 7798 §7.1), Opus (RFC 7587), PCMU and PCMA (RFC 3551
//! §4.5.14). The host candidates are in the offer, for integrations that
//! read no trickled candidate, and are trickled after it too (RFC 8838
//! §8), then the end-of-candidates indication (RFC 8838 §13), each with
//! its `sdpMid` and `sdpMLineIndex` set: one BUNDLE transport (RFC 9143),
//! so all of them belong to the first media section.
//!
//! The offerer is the controlling ICE agent (RFC 8445 §6.1.1) and offers
//! `a=setup:actpass` (RFC 5763 §5, RFC 8842 §5.2), so the camera picks its
//! DTLS role; DTLS-SRTP keys the media (RFC 5764). Media is received in
//! str0m's RTP mode: each packet goes to the caller as it arrived, mapped
//! to the stream index its m-line has. Picture Loss Indications (RFC 4585
//! §6.3.1) ask the camera for a keyframe once connected, every
//! [`PLI_INTERVAL`] until one arrived (at most [`STARTUP_PLIS`]), and after
//! a gap in the video's sequence numbers, rate-limited. Consent freshness
//! (RFC 7675) is str0m's: its agent going disconnected after the
//! connection ends the attempt (`SPEC-DEVIATION`, at
//! `IngestEngine::on_event`: seconds without an answer, not RFC 7675
//! §5.1's 30 s). The data channel (RFC 8831, RFC 8832) is opened, its
//! messages counted and dropped.
//!
//! Every format the answer accepts on an m-line in a codec lotse carries
//! is the camera's to send in (RFC 3264 §7): a packet in another of them
//! than the one declared goes to the same track when it is the same codec
//! (another H.264 profile or packetization mode, which the in-band
//! parameter sets describe), else the track switches to its codec
//! ([`IngestOutput::Switched`]).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use lotse_codec::rtp_ingest::{Declared, RtpPacket, Sprop};
use lotse_codec::{h264, h265};
use lotse_core::codec::{Codec, Kind};
use lotse_core::runner::DEFAULT_READY_TIMEOUT;
use lotse_core::signaling::{SignalCandidate, close};
use lotse_core::source::SourceError;
use lotse_core::throttle::Throttle;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::format::{Codec as EngineCodec, CodecSpec};
use str0m::media::{Direction, KeyframeRequestKind, MediaKind, Mid, SenderFeedback};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig, RtcError};

use super::options::WebRtcOptions;
use crate::sdp::{Sdp, Section, check_payload_types};
use crate::session::{Scope, is_mdns, refused_address, scope, split_candidates};

/// How long the camera has to answer, from the attempt's start: the wait
/// for a client to relay the offer included, so the attempt ends with its
/// own reason well before the runner's ready timeout
/// ([`DEFAULT_READY_TIMEOUT`], 30 s) cancels it.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);

/// When ICE and DTLS must be up, from the attempt's start, for an answer
/// that came by [`CONNECT_TIMEOUT`] before: 3 s under the runner's ready
/// timeout ([`DEFAULT_READY_TIMEOUT`]), which bounds an attempt until it is
/// ready.
pub const CONNECT_BY: Duration = DEFAULT_READY_TIMEOUT.saturating_sub(Duration::from_secs(3));

/// The least time ICE and DTLS have after a late answer, as far as
/// [`ATTEMPT_BUDGET`] allows.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The attempt's last deadline, from its start, however late its answer:
/// 2 s under the runner's ready timeout ([`DEFAULT_READY_TIMEOUT`]), so an
/// attempt that does not connect ends as `ice_failed`, never cancelled by
/// the runner as not ready.
pub const ATTEMPT_BUDGET: Duration = DEFAULT_READY_TIMEOUT.saturating_sub(Duration::from_secs(2));

/// The most bytes of an offer: what the supervisor relays of a worker's
/// offer (`lotse_ipc::MAX_SIGNAL_OFFER_BYTES`, 16 KiB; lotse-webrtc does
/// not depend on lotse-ipc, so the number is repeated here). The source
/// bounds its host addresses so its offer stays well under it.
pub const MAX_OFFER_BYTES: usize = 16 * 1024;

/// The spacing of the Picture Loss Indications asked for until the first
/// keyframe, and the least spacing of those after a loss. RFC 4585 §6.3.1
/// leaves the timing to the receiver; one a second is what a decoder
/// waiting for a picture needs, not a storm.
pub const PLI_INTERVAL: Duration = Duration::from_secs(1);

/// At most this many Picture Loss Indications ask for the first keyframe;
/// a camera that sends none after them follows its own GOP.
pub const STARTUP_PLIS: u32 = 5;

/// How many of the camera's candidates are held until its answer: the
/// control API's bound on a client's candidates per signal.
pub const MAX_EARLY_CANDIDATES: usize = 64;

/// How many outputs a close may queue (its DTLS `close_notify`, the RTCP
/// BYE); the rest is not waited for.
const CLOSE_OUTPUTS: usize = 64;

/// The timeout reported once the attempt ended: nothing is due.
const IDLE: Duration = Duration::from_secs(3_600);

/// RFC 5905 §6: seconds from the NTP era's start (1900) to the Unix epoch.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// One track the answer negotiated: the stream index the caller carries
/// it under, its payload type and what core declares it as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestTrack {
    /// The stream index, its m-line's position in the offer.
    pub index: usize,
    /// The payload type the camera sends it under.
    pub pt: u8,
    /// What it is.
    pub declared: Declared,
}

/// How an attempt ended: the source's error and the code its signaling
/// channel closes with ([`close`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestEnd {
    /// What the source returns.
    pub error: SourceError,
    /// The signaling channel's close code.
    pub close: &'static str,
    /// What happened, for the close: the error's own text.
    pub message: String,
}

/// What the engine wants of its caller, from [`IngestEngine::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutput {
    /// A datagram to send from the local `source` to `destination`.
    Transmit {
        /// The local host candidate's address it leaves from.
        source: SocketAddr,
        /// The camera's address.
        destination: SocketAddr,
        /// The datagram.
        payload: Vec<u8>,
    },
    /// The answer was applied: the tracks to declare. The source is not
    /// ready yet: ICE and DTLS still connect ([`IngestOutput::Connected`]).
    Tracks(Vec<IngestTrack>),
    /// ICE and DTLS are up: the source is ready, its media due.
    Connected,
    /// The camera sends the track under `index` in another of the
    /// formats the answer accepted on its m-line, of another codec than
    /// the one carried (RFC 3264 §7): the track carries `declared` in
    /// payload type `pt` from this packet on, which follows.
    Switched(IngestTrack),
    /// An RTP packet of the track carried under `index`, arrived at
    /// `arrival`.
    Rtp {
        /// The track's stream index.
        index: usize,
        /// The packet.
        packet: RtpPacket,
        /// When it arrived.
        arrival: Instant,
    },
    /// An RTCP Sender Report of the track under `index` (RFC 3550
    /// §6.4.1): its NTP and RTP timestamps of one instant.
    SenderReport {
        /// The track's stream index.
        index: usize,
        /// The 64-bit NTP timestamp.
        ntp: u64,
        /// The RTP timestamp.
        rtp_ts: u32,
        /// When it arrived.
        arrival: Instant,
    },
    /// The attempt ended; nothing but close output follows.
    Ended(IngestEnd),
    /// Nothing more until this time, a datagram, a signal or a call.
    Timeout(Instant),
}

/// The engine's counters, for tests and logs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestStats {
    /// RTP packets handed on.
    pub rtp_packets: u64,
    /// RTP packets of no negotiated track or payload type, dropped.
    pub foreign_packets: u64,
    /// RTP packets of another format than the track carries that came
    /// late (older than the newest of their source), dropped: they do not
    /// switch the track back.
    pub late_packets: u64,
    /// The times the camera switched a track's codec.
    pub switches: u64,
    /// Sender Reports handed on.
    pub sender_reports: u64,
    /// Sender Reports without a wallclock time, dropped.
    pub unusable_reports: u64,
    /// Picture Loss Indications sent.
    pub plis: u64,
    /// Data channel messages received and dropped.
    pub data_messages: u64,
    /// Their bytes.
    pub data_bytes: u64,
    /// The offer's data channel is open (RFC 8832 §6: its
    /// `DATA_CHANNEL_OPEN` acknowledged) and not closed since.
    pub data_channel_open: bool,
    /// Remote candidates handed to the agent.
    pub remote_candidates: u64,
    /// Remote candidates refused or unreadable.
    pub refused_candidates: u64,
    /// Datagrams that were neither for the engine nor readable.
    pub bad_datagrams: u64,
}

/// Where the attempt is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The offer is out; no answer yet.
    Offered,
    /// The answer is applied; ICE and DTLS connect.
    Answered,
    /// Connected: media flows.
    Connected,
    /// Ended or closed.
    Ended,
}

/// One negotiated stream.
#[derive(Debug, Clone)]
struct Stream {
    /// Its m-line's mid.
    mid: Mid,
    /// The caller's index.
    index: usize,
    /// The payload type the track carries now: the first of `formats`
    /// until the camera switches.
    pt: u8,
    /// Every format of the answer's m-line lotse carries on this track
    /// (its kind and clock rate), in the answer's order, with what each
    /// is declared as.
    formats: Vec<(u8, Declared)>,
    /// Video, whose losses ask for a keyframe.
    video: bool,
    /// The synchronization source of the packets seen (RFC 3550 §3).
    ssrc: Option<u32>,
    /// The highest sequence number seen of it.
    highest: Option<u16>,
}

/// One WebRTC ingest attempt, from the offer to its end.
pub struct IngestEngine {
    /// str0m.
    rtc: Rtc,
    /// The offer until the answer is applied.
    pending: Option<SdpPendingOffer>,
    /// The offer's SDP.
    offer: String,
    /// The first media section's mid, which the candidates name.
    first_mid: String,
    /// The audio m-line, when offered.
    audio_mid: Option<Mid>,
    /// The video m-line.
    video_mid: Mid,
    /// The data channel, when offered, and its label.
    channel: Option<(ChannelId, String)>,
    /// The host candidates' `candidate:` lines.
    local: Vec<String>,
    /// The scopes of the host candidates, for the remote candidates'
    /// address check.
    scopes: Vec<Scope>,
    /// The camera's candidates that came before its answer.
    early: Vec<String>,
    /// Where the attempt is.
    phase: Phase,
    /// When the attempt started: the deadlines count from it.
    started: Instant,
    /// The last time handed in.
    now: Instant,
    /// The answer's deadline while offered, the connection's once
    /// answered.
    deadline: Option<Instant>,
    /// The negotiated streams.
    streams: Vec<Stream>,
    /// The first keyframe arrived.
    keyframe: bool,
    /// Startup Picture Loss Indications sent.
    startup_plis: u32,
    /// When the next startup one is due.
    pli_due: Option<Instant>,
    /// The last startup one could not go out: the next packet sends it.
    pli_blocked: bool,
    /// When the last one went out.
    last_pli: Option<Instant>,
    /// Outputs queued ahead of the engine's.
    queued: VecDeque<IngestOutput>,
    /// The rate limit of the foreign packets' log line.
    foreign: Throttle,
    /// The rate limit of the unusable Sender Reports' log line.
    unusable: Throttle,
    /// The rate limit of the codec switches' log line.
    switch_log: Throttle,
    /// The counters.
    stats: IngestStats,
}

impl std::fmt::Debug for IngestEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestEngine")
            .field("phase", &self.phase)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// str0m's configuration of an ingest attempt: RTP mode, and the codecs
/// lotse carries in its order of preference, H.264 (its default set of
/// profiles, each in packetization modes 1 and 0) ahead of H.265, then
/// Opus, PCMU and PCMA. RED is not offered: the source reads RTP as sent.
fn config() -> RtcConfig {
    Rtc::builder()
        .set_rtp_mode(true)
        .clear_codecs()
        .enable_h264(true)
        .enable_h265(true)
        .enable_opus(true, false)
        .enable_pcmu(true, false)
        .enable_pcma(true, false)
}

/// Whether the media sections of `offer` carry distinct mids: str0m 0.24
/// draws each m-line's mid at random and can draw one twice within one
/// offer (observed 2026-10-01, see the `webrtc_session` fuzz target).
fn check_offer_mids(offer: &str) -> Result<(), String> {
    let mut mids: Vec<&str> = offer
        .lines()
        .filter_map(|line| line.strip_prefix("a=mid:"))
        .collect();
    let all = mids.len();
    mids.sort_unstable();
    mids.dedup();
    if mids.len() == all {
        Ok(())
    } else {
        Err("the engine drew one mid for two media sections".to_owned())
    }
}

/// `answer` with a format on every `m=` line of port 0 that lists none,
/// so str0m parses it. RFC 8866 §5.14 has at least one format on every
/// `m=` line, and RFC 3264 §6 lets a rejected one list any; str0m 0.24
/// itself answers a rejected m-line without one (observed 2026-11-06) and
/// refuses to parse that, so a camera on str0m (or any other that writes
/// it so) would have its whole answer refused for an audio m-line it
/// declined. The format added, `0`, is never used: the m-line is stopped.
// SPEC-DEVIATION(RFC 8866 §5.14): an answer that lists no format on a
// rejected m-line breaks the grammar and is taken anyway, as str0m 0.24
// writes such answers itself; a live m-line without formats is still
// refused (by str0m);
// gate: rfc8866_5_14_a_rejected_m_line_without_formats_gets_one
fn with_formats(answer: &str) -> String {
    let mut out = String::with_capacity(answer.len().saturating_add(8));
    for line in answer.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let empty = matches!(fields.as_slice(), [media, port, _] if media.starts_with("m=") && *port == "0");
        out.push_str(line.trim_end());
        if empty {
            out.push_str(" 0");
        }
        out.push_str("\r\n");
    }
    out
}

/// What core declares a negotiated payload of `spec` as, `None` for a
/// codec lotse does not carry. Video starts from empty parameter sets: a
/// WebRTC answer carries none, the camera sends them in band.
fn declared(spec: &CodecSpec) -> Option<Declared> {
    let (kind, codec, sets) = match spec.codec {
        EngineCodec::H264 => (
            Kind::Video,
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            Sprop::H264(h264::ParameterSets::default()),
        ),
        EngineCodec::H265 => (
            Kind::Video,
            Codec::H265 {
                vps: None,
                sps: None,
                pps: None,
            },
            Sprop::H265(h265::ParameterSets::default()),
        ),
        // RFC 7587 §7: `opus/48000/2` whatever the camera sends.
        EngineCodec::Opus => (
            Kind::Audio,
            Codec::Opus {
                channels: spec.channels.unwrap_or(2),
            },
            Sprop::None,
        ),
        EngineCodec::PCMU => (Kind::Audio, Codec::Pcmu, Sprop::None),
        EngineCodec::PCMA => (Kind::Audio, Codec::Pcma, Sprop::None),
        _ => return None,
    };
    Some(Declared {
        kind,
        codec,
        clock_rate: spec.clock_rate.get(),
        sets,
    })
}

/// `time` as a 64-bit NTP timestamp (RFC 5905 §6, RFC 3550 §4): seconds
/// since 1900 in the high word, the fraction in the low one; the era wraps
/// as NTP's does. str0m hands a Sender Report's NTP timestamp over as a
/// `SystemTime` through a 64-bit float, so this is the camera's to within
/// a microsecond. `None` at or before the Unix epoch: str0m 0.24 makes
/// every NTP timestamp before 1970 the epoch itself, the zero of a sender
/// without a wallclock (RFC 3550 §6.4.1) among them, which names no
/// instant.
pub fn ntp64(time: SystemTime) -> Option<u64> {
    let since = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .filter(|since| !since.is_zero())?;
    let secs = since.as_secs().wrapping_add(NTP_UNIX_OFFSET);
    let fraction = (u64::from(since.subsec_nanos()) << 32)
        .checked_div(1_000_000_000)
        .unwrap_or_default();
    Some(secs.wrapping_shl(32) | fraction)
}

/// The low 32 bits of `value`: an RTP timestamp out of str0m's extended
/// one (RFC 3550 §5.1 timestamps wrap).
fn low32(value: u64) -> u32 {
    let [a, b, c, d, ..] = value.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

impl IngestEngine {
    /// The offer of an attempt with `options` that `started` (before its
    /// signaling channel opened: the deadlines count from then), gathering
    /// on the local `hosts` (each a bound socket's address), at `now`.
    ///
    /// # Errors
    ///
    /// Why no offer can be made: str0m took none of the host candidates,
    /// drew one mid twice, or wrote an offer over [`MAX_OFFER_BYTES`].
    pub fn offer(
        options: &WebRtcOptions,
        hosts: &[SocketAddr],
        started: Instant,
        now: Instant,
    ) -> Result<Self, String> {
        crate::install_crypto_provider();
        let mut rtc = config().build(now);
        let mut local = Vec::new();
        let mut scopes = Vec::new();
        for addr in hosts {
            match Candidate::host(*addr, "udp") {
                Ok(candidate) => {
                    if let Some(added) = rtc.add_local_candidate(candidate) {
                        local.push(added.to_sdp_string());
                        scopes.extend(scope(added.addr().ip()));
                    } else {
                        tracing::debug!(%addr, "webrtc: host candidate not taken by the agent");
                    }
                }
                Err(err) => tracing::debug!(%addr, error = %err, "webrtc: host candidate refused"),
            }
        }
        if local.is_empty() {
            return Err(format!("no usable host candidate among {hosts:?}"));
        }
        let mut api = rtc.sdp_api();
        let audio_mid = options
            .audio
            .then(|| api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None));
        let video_mid = api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
        let channel = options
            .data_channel
            .as_ref()
            .map(|label| (api.add_channel(label.clone()), label.clone()));
        let (offer, pending) = api.apply().ok_or("the engine made no offer")?;
        let offer = offer.to_sdp_string();
        check_offer_mids(&offer)?;
        if offer.len() > MAX_OFFER_BYTES {
            return Err(format!(
                "an offer of {} bytes, over the {MAX_OFFER_BYTES} the relay takes",
                offer.len()
            ));
        }
        let first_mid = audio_mid.unwrap_or(video_mid).to_string();
        tracing::debug!(
            candidates = local.len(),
            audio = audio_mid.is_some(),
            data_channel = channel.is_some(),
            "webrtc: offer made"
        );
        Ok(Self {
            rtc,
            pending: Some(pending),
            offer,
            first_mid,
            audio_mid,
            video_mid,
            channel,
            local,
            scopes,
            early: Vec::new(),
            phase: Phase::Offered,
            started,
            now,
            deadline: started.checked_add(ANSWER_TIMEOUT),
            streams: Vec::new(),
            keyframe: false,
            startup_plis: 0,
            pli_due: None,
            pli_blocked: false,
            last_pli: None,
            queued: VecDeque::new(),
            foreign: Throttle::default(),
            unusable: Throttle::default(),
            switch_log: Throttle::default(),
            stats: IngestStats::default(),
        })
    }

    /// The offer's SDP (RFC 8829 §5.2), the host candidates in it.
    pub fn offer_sdp(&self) -> &str {
        &self.offer
    }

    /// The host candidates to trickle after the offer (RFC 8838 §8), then
    /// the end-of-candidates indication (§13), each of the first media
    /// section: its mid and index 0, which some integrations need.
    pub fn local_candidates(&self) -> Vec<SignalCandidate> {
        let mid = || Some(self.first_mid.clone());
        self.local
            .iter()
            .map(|line| SignalCandidate {
                candidate: line.clone(),
                sdp_mid: mid(),
                sdp_mline_index: Some(0),
            })
            .chain(std::iter::once(SignalCandidate::end_of_candidates(
                mid(),
                Some(0),
            )))
            .collect()
    }

    /// The counters.
    pub const fn stats(&self) -> IngestStats {
        self.stats
    }

    /// Whether the attempt has ended.
    pub fn is_ended(&self) -> bool {
        self.phase == Phase::Ended
    }

    /// Whether ICE and DTLS are up and media flows.
    pub fn is_connected(&self) -> bool {
        self.phase == Phase::Connected
    }

    /// Whether the camera's answer was applied (and the attempt has not
    /// ended since).
    pub fn answered(&self) -> bool {
        matches!(self.phase, Phase::Answered | Phase::Connected)
    }

    /// Applies the camera's answer (RFC 8829 §5.3) at `now`. A repeated
    /// answer is ignored. One the engine cannot apply, or without a video
    /// m-line it receives in a carried codec, ends the attempt as a
    /// protocol error closing `invalid_answer`; else the negotiated tracks
    /// are output ([`IngestOutput::Tracks`]) and ICE starts, the answer's
    /// candidates through the same check as trickled ones.
    pub fn accept_answer(&mut self, now: Instant, sdp: &str) {
        self.now = now;
        if self.phase != Phase::Offered {
            tracing::debug!("webrtc: repeated answer ignored");
            return;
        }
        if let Err(reason) = self.apply_answer(sdp) {
            self.end(
                SourceError::Protocol,
                close::INVALID_ANSWER,
                format!("webrtc: invalid answer: {reason}"),
            );
        }
    }

    /// [`IngestEngine::accept_answer`]'s work, the reason it failed in
    /// `Err`.
    fn apply_answer(&mut self, sdp: &str) -> Result<(), String> {
        // str0m 0.24 panics on a payload type reused across media
        // sections ("Pt locked multiple times"), so the check comes first.
        check_payload_types(sdp)?;
        let parsed = Sdp::parse(sdp);
        let stopped: Vec<&str> = parsed
            .media()
            .iter()
            .filter(|section| parsed.stopped(section))
            .filter_map(Section::mid)
            .collect();
        let (rest, candidates) = split_candidates(sdp);
        let rest = with_formats(&rest);
        let answer = SdpAnswer::from_sdp_string(&rest).map_err(|err| err.to_string())?;
        let pending = self.pending.take().ok_or("no offer pending")?;
        self.rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .map_err(|err| err.to_string())?;
        let mut tracks = Vec::new();
        let rejected = |mid: Mid| stopped.contains(&mid.to_string().as_str());
        if let Some(audio) = self.audio_mid {
            let audio = (!rejected(audio))
                .then(|| self.negotiated(audio, 0))
                .flatten();
            if audio.is_none() {
                tracing::info!("webrtc: the camera sends no audio the source carries");
            }
            tracks.extend(audio);
        }
        let video_index = usize::from(self.audio_mid.is_some());
        let video = (!rejected(self.video_mid))
            .then(|| self.negotiated(self.video_mid, video_index))
            .flatten()
            .ok_or("no video m-line the camera sends in H.264 or H.265")?;
        tracks.push(video);
        for track in &tracks {
            tracing::info!(
                index = track.index,
                pt = track.pt,
                codec = track.declared.codec.name(),
                "webrtc: track negotiated"
            );
        }
        for line in candidates {
            self.add_remote(line);
        }
        for line in std::mem::take(&mut self.early) {
            self.add_remote(&line);
        }
        self.phase = Phase::Answered;
        self.deadline = self.connect_deadline();
        self.queued.push_back(IngestOutput::Tracks(tracks));
        Ok(())
    }

    /// When ICE and DTLS must be up, the answer applied now: by
    /// [`CONNECT_BY`] from the attempt's start, or [`CONNECT_TIMEOUT`]
    /// after a later answer, but never past [`ATTEMPT_BUDGET`].
    fn connect_deadline(&self) -> Option<Instant> {
        let by = self.started.checked_add(CONNECT_BY)?;
        let last = self.started.checked_add(ATTEMPT_BUDGET)?;
        let after_answer = self.now.checked_add(CONNECT_TIMEOUT)?;
        Some(by.max(after_answer).min(last))
    }

    /// The track the answer negotiated on `mid`, carried under `index`:
    /// declared as the first payload type of the camera's that lotse
    /// carries, `None` when the m-line does not send or has none. (A
    /// rejected m-line, port 0, is the caller's to leave out: str0m 0.24
    /// keeps it live.) The camera may send in any format the answer
    /// accepted (RFC 3264 §7), so the stream takes each one lotse carries
    /// of the first one's kind and clock rate, which a track keeps.
    fn negotiated(&mut self, mid: Mid, index: usize) -> Option<IngestTrack> {
        let media = self.rtc.media(mid)?;
        if media.disabled() || !media.direction().is_receiving() {
            return None;
        }
        let config = self.rtc.codec_config();
        let carried: Vec<(u8, Declared)> = media
            .remote_pts()
            .iter()
            .filter_map(|pt| {
                let params = config.find(|params| params.pt() == *pt)?;
                Some((**pt, declared(&params.spec())?))
            })
            .collect();
        let (pt, declared) = carried.first()?.clone();
        let formats: Vec<(u8, Declared)> = carried
            .into_iter()
            .filter(|(_, format)| {
                format.kind == declared.kind && format.clock_rate == declared.clock_rate
            })
            .collect();
        let pts: Vec<u8> = formats.iter().map(|(pt, _)| *pt).collect();
        tracing::debug!(index, ?pts, "webrtc: the formats the track takes");
        self.streams.push(Stream {
            mid,
            index,
            pt,
            formats,
            video: declared.kind == Kind::Video,
            ssrc: None,
            highest: None,
        });
        Some(IngestTrack {
            index,
            pt,
            declared,
        })
    }

    /// A candidate the camera trickled (RFC 8838 §10), at `now`. Its
    /// end-of-candidates indication is noted only. One that arrives
    /// before the answer is held (at most [`MAX_EARLY_CANDIDATES`]) and
    /// handed to the agent with the answer, as the camera's ICE
    /// credentials come with it: a relay may pass on the camera's
    /// candidates ahead of its answer (RFC 8838 §10 lets them arrive in
    /// any order). After the end, one is ignored.
    pub fn add_remote_candidate(&mut self, now: Instant, candidate: &SignalCandidate) {
        self.now = now;
        if candidate.is_end_of_candidates() {
            tracing::debug!("webrtc: the camera's end of candidates");
            return;
        }
        let line = candidate.candidate.as_str();
        let line = line.strip_prefix("a=").unwrap_or(line);
        match self.phase {
            Phase::Offered if self.early.len() < MAX_EARLY_CANDIDATES => {
                self.early.push(line.to_owned());
            }
            Phase::Answered | Phase::Connected => self.add_remote(line),
            Phase::Offered | Phase::Ended => {
                self.stats.refused_candidates = self.stats.refused_candidates.saturating_add(1);
                tracing::debug!(phase = ?self.phase, "webrtc: remote candidate ignored: too many before the answer, or after the end");
            }
        }
    }

    /// Hands one remote candidate line to the agent unless the viewer
    /// sessions' policy refuses its address
    /// ([`crate::session`]'s `refused_address`, RFC 8445 §6.1.2.2); an
    /// mDNS name is ignored (draft-ietf-mmusic-mdns-ice-candidates §3.2.1,
    /// without a resolver), as is a line that does not parse.
    fn add_remote(&mut self, line: &str) {
        let refused = match Candidate::from_sdp_string(line) {
            Ok(candidate) => {
                let addr = candidate.addr();
                if let Some(reason) = refused_address(addr.ip(), &self.scopes) {
                    tracing::debug!(%addr, reason, "webrtc: remote candidate refused");
                    true
                } else {
                    tracing::debug!(kind = ?candidate.kind(), %addr, "webrtc: remote candidate");
                    self.rtc.add_remote_candidate(candidate);
                    false
                }
            }
            Err(err) => {
                let mdns = is_mdns(line);
                tracing::debug!(error = %err, mdns, "webrtc: remote candidate ignored");
                true
            }
        };
        if refused {
            self.stats.refused_candidates = self.stats.refused_candidates.saturating_add(1);
        } else {
            self.stats.remote_candidates = self.stats.remote_candidates.saturating_add(1);
        }
    }

    /// A datagram from `source` to the local `destination`, at `now`.
    pub fn receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        bytes: &[u8],
    ) {
        self.now = now;
        if self.phase == Phase::Ended {
            return;
        }
        let Ok(contents) = DatagramRecv::try_from(bytes) else {
            self.stats.bad_datagrams = self.stats.bad_datagrams.saturating_add(1);
            return;
        };
        let input = Input::Receive(
            now,
            Receive {
                proto: Protocol::Udp,
                source,
                destination,
                contents,
            },
        );
        if !self.rtc.accepts(&input) {
            self.stats.bad_datagrams = self.stats.bad_datagrams.saturating_add(1);
            return;
        }
        self.input(input);
    }

    /// Time passed: the deadlines, the startup keyframe requests and the
    /// engine's timers.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        let overdue = self.deadline.is_some_and(|deadline| now >= deadline);
        match self.phase {
            Phase::Offered if overdue => {
                let secs = ANSWER_TIMEOUT.as_secs();
                self.end(
                    SourceError::Timeout,
                    close::ANSWER_TIMEOUT,
                    format!("webrtc: no answer within {secs} s"),
                );
                return;
            }
            Phase::Answered if overdue => {
                let ms = now.saturating_duration_since(self.started).as_millis();
                self.end(
                    SourceError::Timeout,
                    close::ICE_FAILED,
                    format!("webrtc: not connected {ms} ms into the attempt"),
                );
                return;
            }
            // Once ended, str0m is inert and nothing is due.
            _ => {}
        }
        self.startup_pli(false);
        self.input(Input::Timeout(now));
    }

    /// The first keyframe arrived: no more startup keyframe requests, and
    /// a loss asks for one from now on. Called once per attempt.
    pub fn keyframe_seen(&mut self) {
        tracing::info!(plis = self.startup_plis, "webrtc: first keyframe");
        self.keyframe = true;
        self.pli_due = None;
    }

    /// Ends the attempt from outside (cancelled, the client gone, the
    /// camera failed): the DTLS `close_notify` and the RTCP BYE are
    /// queued as transmits, then the engine is inert (`rtc.disconnect()`).
    /// No [`IngestOutput::Ended`] follows: the caller knows why.
    pub fn close(&mut self) {
        if self.phase == Phase::Ended {
            return;
        }
        self.phase = Phase::Ended;
        self.drain_close();
    }

    /// The next output. Call until it is [`IngestOutput::Timeout`].
    pub fn poll(&mut self) -> IngestOutput {
        loop {
            if let Some(output) = self.queued.pop_front() {
                return output;
            }
            if self.phase == Phase::Ended {
                return IngestOutput::Timeout(self.now.checked_add(IDLE).unwrap_or(self.now));
            }
            match self.rtc.poll_output() {
                Ok(Output::Timeout(at)) => {
                    let at = [self.deadline, self.pli_due]
                        .into_iter()
                        .flatten()
                        .fold(at, Instant::min);
                    return IngestOutput::Timeout(at);
                }
                Ok(Output::Transmit(transmit)) => {
                    return IngestOutput::Transmit {
                        source: transmit.source,
                        destination: transmit.destination,
                        payload: Vec::from(transmit.contents),
                    };
                }
                Ok(Output::Event(event)) => self.on_event(event),
                Err(err) => self.check(Err(err)),
            }
        }
    }

    /// Hands `input` to str0m; an error ends the attempt.
    fn input(&mut self, input: Input<'_>) {
        let handled = self.rtc.handle_input(input);
        self.check(handled);
    }

    /// Ends the attempt as a protocol error when str0m failed: a DTLS
    /// handshake that failed (a fingerprint that does not match, RFC 5763
    /// §5), or another engine error.
    fn check(&mut self, result: Result<(), RtcError>) {
        if let Err(err) = result {
            self.end(
                SourceError::Protocol,
                close::INTERNAL_ERROR,
                format!("webrtc engine: {err}"),
            );
        }
    }

    /// One str0m event.
    fn on_event(&mut self, event: Event) {
        match event {
            Event::Connected => {
                tracing::info!("webrtc: connected to the camera");
                self.phase = Phase::Connected;
                self.deadline = None;
                self.queued.push_back(IngestOutput::Connected);
                self.pli_due = Some(self.now);
                self.startup_pli(false);
            }
            Event::IceConnectionStateChange(state) => {
                tracing::debug!(?state, "webrtc: ICE state");
                // SPEC-DEVIATION(RFC 7675 §5.1): consent expires 30 s after
                // the last answered check; str0m 0.24's agent goes
                // Disconnected once its nominated pair has gone unanswered
                // for a few seconds and offers no 30 s timer, so the
                // attempt ends then: a camera that answers no check for
                // seconds sends no media either, and the runner
                // reconnects. Before the connection the agent can go
                // Disconnected too (no remote candidate pairs yet), which
                // ends nothing: the connect deadline does;
                // gate: rfc7675_5_1_a_camera_that_stops_answering_consent_ends_as_consent_lost
                if state == IceConnectionState::Disconnected && self.phase == Phase::Connected {
                    self.end(
                        SourceError::Ended,
                        close::CONSENT_LOST,
                        "webrtc: the camera stopped answering consent checks".to_owned(),
                    );
                }
            }
            Event::RtpPacket(packet) => self.on_rtp(packet),
            Event::SenderFeedback(feedback) => self.on_sender_report(&feedback),
            Event::ChannelOpen(id, label) => {
                let ours = self.is_ours(id);
                self.stats.data_channel_open |= ours;
                tracing::info!(label, ours, "webrtc: data channel open");
            }
            Event::ChannelData(data) => {
                let bytes = u64::try_from(data.data.len()).unwrap_or(u64::MAX);
                self.stats.data_messages = self.stats.data_messages.saturating_add(1);
                self.stats.data_bytes = self.stats.data_bytes.saturating_add(bytes);
            }
            Event::ChannelClose(id) => {
                let ours = self.is_ours(id);
                self.stats.data_channel_open &= !ours;
                tracing::info!(ours, "webrtc: data channel closed");
            }
            Event::Closed => self.end(
                SourceError::Ended,
                close::PEER_CLOSED,
                "webrtc: the camera closed the connection".to_owned(),
            ),
            _ => {}
        }
    }

    /// A Sender Report (RFC 3550 §6.4.1) of a negotiated stream, handed on
    /// as its NTP and RTP timestamps; one whose NTP timestamp is zero, a
    /// sender without a wallclock (§6.4.1), names no instant and is
    /// dropped, as is one before 1970 (str0m 0.24 hands NTP zero over as
    /// the Unix epoch).
    fn on_sender_report(&mut self, feedback: &SenderFeedback) {
        let Some(stream) = self.streams.iter().find(|s| s.mid == feedback.mid) else {
            return;
        };
        let Some(ntp) = ntp64(feedback.sender_info.ntp_time) else {
            self.stats.unusable_reports = self.stats.unusable_reports.saturating_add(1);
            if let Some(count) = self.unusable.hit(self.now) {
                tracing::debug!(
                    index = stream.index,
                    count,
                    "webrtc: Sender Report without a wallclock time dropped"
                );
            }
            return;
        };
        self.stats.sender_reports = self.stats.sender_reports.saturating_add(1);
        self.queued.push_back(IngestOutput::SenderReport {
            index: stream.index,
            ntp,
            rtp_ts: low32(feedback.sender_info.rtp_time.numer()),
            arrival: feedback.received_at,
        });
    }

    /// Whether `id` is the data channel the offer opened.
    fn is_ours(&self, id: ChannelId) -> bool {
        self.channel.as_ref().is_some_and(|(ours, _)| *ours == id)
    }

    /// One RTP packet: handed on under its stream's index when it is of a
    /// negotiated m-line (str0m maps its SSRC by `a=ssrc` or the RFC 9143
    /// `mid` header extension) in one of the formats its track takes,
    /// else counted and dropped. A format of another codec than the one
    /// carried switches the track first ([`IngestOutput::Switched`]). A
    /// forward gap in the video's sequence numbers (RFC 3550 §A.1) is a
    /// lost picture, which asks for a keyframe.
    fn on_rtp(&mut self, packet: str0m::rtp::RtpPacket) {
        let header = &packet.header;
        let mid = self
            .rtc
            .direct_api()
            .stream_rx(&header.ssrc)
            .map(|stream| stream.mid());
        let pt = *header.payload_type;
        let seq = header.sequence_number;
        let Some(stream) = self.streams.iter_mut().find(|stream| {
            Some(stream.mid) == mid && stream.formats.iter().any(|(format, _)| *format == pt)
        }) else {
            self.stats.foreign_packets = self.stats.foreign_packets.saturating_add(1);
            if let Some(count) = self.foreign.hit(self.now) {
                tracing::debug!(
                    pt,
                    ssrc = *header.ssrc,
                    count,
                    "webrtc: RTP of no negotiated track dropped"
                );
            }
            return;
        };
        let index = stream.index;
        let ssrc = *header.ssrc;
        if stream.ssrc != Some(ssrc) {
            // A new synchronization source numbers its packets anew (RFC
            // 3550 §5.1, §8.2): none of it is late.
            tracing::debug!(index, ssrc, "webrtc: a new synchronization source");
            stream.ssrc = Some(ssrc);
            stream.highest = None;
        }
        let ahead = stream
            .highest
            .map_or(1, |highest| seq.wrapping_sub(highest));
        let forward = (1..0x8000).contains(&ahead);
        let switched = {
            let declared = |pt: u8| {
                stream
                    .formats
                    .iter()
                    .find(|(format, _)| *format == pt)
                    .map(|(_, declared)| declared)
            };
            let format = declared(pt);
            (format != declared(stream.pt))
                .then(|| format.cloned())
                .flatten()
        };
        if let Some(declared) = switched {
            if !forward {
                // Older than the newest packet: one of the codec before a
                // switch (or after it) that came late. The receive path
                // carries the other codec now, and switching back would
                // restart it.
                self.stats.late_packets = self.stats.late_packets.saturating_add(1);
                tracing::trace!(
                    index,
                    pt,
                    seq,
                    "webrtc: late packet of another format dropped"
                );
                return;
            }
            self.stats.switches = self.stats.switches.saturating_add(1);
            tracing::trace!(index, from = stream.pt, to = pt, "webrtc: codec switched");
            if let Some(count) = self.switch_log.hit(self.now) {
                tracing::info!(
                    index,
                    from = stream.pt,
                    to = pt,
                    codec = declared.codec.name(),
                    count,
                    "webrtc: the camera switched the track's codec"
                );
            }
            stream.pt = pt;
            self.queued.push_back(IngestOutput::Switched(IngestTrack {
                index,
                pt,
                declared,
            }));
        }
        let lost = stream.video && forward && ahead > 1 && stream.highest.is_some();
        stream.highest = if forward { Some(seq) } else { stream.highest };
        self.stats.rtp_packets = self.stats.rtp_packets.saturating_add(1);
        self.queued.push_back(IngestOutput::Rtp {
            index,
            packet: RtpPacket {
                seq,
                ts: header.timestamp,
                ssrc,
                marker: header.marker,
                payload: Bytes::from_owner(packet.payload),
            },
            arrival: packet.timestamp,
        });
        if lost && self.keyframe {
            let spaced = self
                .last_pli
                .is_none_or(|last| self.now.saturating_duration_since(last) >= PLI_INTERVAL);
            if spaced {
                self.request_pli("video packets lost");
            }
        }
        self.startup_pli(true);
    }

    /// Sends the startup keyframe request when one is due: until the
    /// first keyframe, every [`PLI_INTERVAL`], at most [`STARTUP_PLIS`]
    /// sent. One that cannot go out yet (str0m knows the camera's SSRC
    /// only from the answer's `a=ssrc` or its first packet) is due again
    /// on the next packet (`on_packet`) or interval.
    fn startup_pli(&mut self, on_packet: bool) {
        let Some(due) = self.pli_due else { return };
        if self.now < due && !(on_packet && self.pli_blocked) {
            return;
        }
        let sent = self.request_pli("waiting for the first keyframe");
        self.pli_blocked = !sent;
        if sent {
            self.startup_plis = self.startup_plis.saturating_add(1);
        }
        self.pli_due = (self.startup_plis < STARTUP_PLIS)
            .then(|| self.now.checked_add(PLI_INTERVAL))
            .flatten();
    }

    /// Asks the camera for a keyframe with a Picture Loss Indication (RFC
    /// 4585 §6.3.1) on the video stream; `false` while str0m does not know
    /// the stream yet.
    fn request_pli(&mut self, reason: &'static str) -> bool {
        let mut api = self.rtc.direct_api();
        let Some(stream) = api.stream_rx_by_mid(self.video_mid, None) else {
            return false;
        };
        stream.request_keyframe(KeyframeRequestKind::Pli);
        self.stats.plis = self.stats.plis.saturating_add(1);
        self.last_pli = Some(self.now);
        tracing::debug!(reason, "webrtc: keyframe requested");
        true
    }

    /// Ends the attempt with the error `as_error` makes of `message`,
    /// closing the signal with `code` and `message`: the close output,
    /// then [`IngestOutput::Ended`]. Called once: nothing reaches the
    /// engine's events or deadlines once it ended.
    fn end(&mut self, as_error: fn(String) -> SourceError, code: &'static str, message: String) {
        tracing::info!(code, %message, "webrtc: attempt ended");
        self.phase = Phase::Ended;
        self.drain_close();
        let error = as_error(message.clone());
        self.queued.push_back(IngestOutput::Ended(IngestEnd {
            error,
            close: code,
            message,
        }));
    }

    /// Closes str0m gracefully and queues what that sends, the DTLS
    /// `close_notify` alert (RFC 6347 §4.2.7) and an RTCP BYE (RFC 3550
    /// §6.6), at most [`CLOSE_OUTPUTS`] and up to its first timeout, then
    /// drops it to inert, as a viewer session closes.
    fn drain_close(&mut self) {
        self.deadline = None;
        self.pli_due = None;
        let started = self.rtc.close();
        for _ in 0..CLOSE_OUTPUTS {
            // A closing str0m reports no events; its first timeout or
            // error ends what it has to send.
            let Ok(Output::Transmit(transmit)) = self.rtc.poll_output() else {
                break;
            };
            self.queued.push_back(IngestOutput::Transmit {
                source: transmit.source,
                destination: transmit.destination,
                payload: Vec::from(transmit.contents),
            });
        }
        tracing::debug!(close = ?started, "webrtc: engine closed");
        self.rtc.disconnect();
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::UNIX_EPOCH;

    use str0m::format::FormatParams;
    use str0m::media::Frequency;

    use super::*;

    fn spec(codec: EngineCodec, clock: Frequency, channels: Option<u8>) -> CodecSpec {
        CodecSpec {
            codec,
            clock_rate: clock,
            channels,
            format: FormatParams::default(),
        }
    }

    #[test]
    fn rfc5905_6_ntp_timestamps_count_from_1900_with_a_32_bit_fraction() {
        let half = UNIX_EPOCH + Duration::from_millis(1_500);
        assert_eq!(
            ntp64(half),
            Some(((NTP_UNIX_OFFSET + 1) << 32) | 0x8000_0000)
        );
        assert_eq!(
            ntp64(UNIX_EPOCH + Duration::from_nanos(1)),
            Some((NTP_UNIX_OFFSET << 32) | 4)
        );
        assert_eq!(low32(0x1_2345_6789), 0x2345_6789);
    }

    #[test]
    fn rfc3550_6_4_1_an_ntp_time_of_zero_or_before_1970_names_no_instant() {
        // str0m 0.24 reads NTP 0 (a sender without a wallclock) as the
        // epoch.
        assert_eq!(ntp64(UNIX_EPOCH), None);
        assert_eq!(ntp64(UNIX_EPOCH - Duration::from_secs(1)), None);
    }

    #[test]
    fn rfc3550_6_4_1_a_sender_report_without_a_wallclock_is_dropped() {
        let addr = "192.0.2.10:5000".parse().unwrap();
        let now = lotse_core::clock::Clock::now(&lotse_core::clock::SystemClock);
        let mut engine = IngestEngine::offer(
            &WebRtcOptions {
                data_channel: None,
                audio: false,
            },
            &[addr],
            now,
            now,
        )
        .unwrap();
        let mid = engine.video_mid;
        engine.streams.push(Stream {
            mid,
            index: 3,
            pt: 96,
            formats: Vec::new(),
            video: true,
            ssrc: None,
            highest: None,
        });
        let report = |ntp_time| {
            Event::SenderFeedback(SenderFeedback {
                mid,
                rid: None,
                received_at: now,
                sender_info: str0m::rtp::rtcp::SenderInfo {
                    ssrc: 1.into(),
                    ntp_time,
                    rtp_time: str0m::media::MediaTime::new(0x1_0000_0007, Frequency::NINETY_KHZ),
                    sender_packet_count: 0,
                    sender_octet_count: 0,
                },
            })
        };
        engine.on_event(report(UNIX_EPOCH));
        engine.on_event(report(UNIX_EPOCH));
        assert!(engine.queued.is_empty());
        assert_eq!(engine.stats.unusable_reports, 2);
        assert_eq!(engine.stats.sender_reports, 0);
        let later = UNIX_EPOCH + Duration::from_secs(1);
        engine.on_event(report(later));
        assert_eq!(
            engine.queued.pop_front(),
            Some(IngestOutput::SenderReport {
                index: 3,
                ntp: (NTP_UNIX_OFFSET + 1) << 32,
                rtp_ts: 7,
                arrival: now,
            })
        );
        assert_eq!(engine.stats.sender_reports, 1);
        // Another m-line's: no stream, nothing.
        let mut other = report(later);
        if let Event::SenderFeedback(feedback) = &mut other {
            feedback.mid = Mid::from("x");
        }
        engine.on_event(other);
        assert!(engine.queued.is_empty());
        assert_eq!(engine.stats.unusable_reports, 2);
    }

    #[test]
    fn rfc6184_rfc7798_rfc7587_negotiated_codecs_map_onto_core() {
        let h264 = declared(&spec(EngineCodec::H264, Frequency::NINETY_KHZ, None)).unwrap();
        assert_eq!(h264.kind, Kind::Video);
        assert_eq!(h264.clock_rate, 90_000);
        assert_eq!(h264.sets, Sprop::H264(h264::ParameterSets::default()));
        let h265 = declared(&spec(EngineCodec::H265, Frequency::NINETY_KHZ, None)).unwrap();
        assert_eq!(h265.sets, Sprop::H265(h265::ParameterSets::default()));
        assert!(matches!(h265.codec, Codec::H265 { .. }));
        let opus = declared(&spec(
            EngineCodec::Opus,
            Frequency::FORTY_EIGHT_KHZ,
            Some(2),
        ))
        .unwrap();
        assert_eq!(opus.codec, Codec::Opus { channels: 2 });
        assert_eq!(opus.clock_rate, 48_000);
        let mono = declared(&spec(EngineCodec::Opus, Frequency::FORTY_EIGHT_KHZ, None)).unwrap();
        assert_eq!(mono.codec, Codec::Opus { channels: 2 });
        let pcmu = declared(&spec(EngineCodec::PCMU, Frequency::EIGHT_KHZ, None)).unwrap();
        assert_eq!(
            (pcmu.kind, pcmu.codec, pcmu.clock_rate),
            (Kind::Audio, Codec::Pcmu, 8_000)
        );
        let a_law = declared(&spec(EngineCodec::PCMA, Frequency::EIGHT_KHZ, None)).unwrap();
        assert_eq!(a_law.codec, Codec::Pcma);
        assert_eq!(
            declared(&spec(EngineCodec::Vp8, Frequency::NINETY_KHZ, None)),
            None
        );
    }

    #[test]
    fn rfc8866_5_14_a_rejected_m_line_without_formats_gets_one() {
        let answer = "v=0\r\nm=audio 0 UDP/TLS/RTP/SAVPF \r\na=mid:a\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nm=video 0 UDP/TLS/RTP/SAVPF 97\r\n";
        assert_eq!(
            with_formats(answer),
            "v=0\r\nm=audio 0 UDP/TLS/RTP/SAVPF 0\r\na=mid:a\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nm=video 0 UDP/TLS/RTP/SAVPF 97\r\n"
        );
        // Only a stopped one: a live m-line without formats stays as
        // written, for str0m to refuse.
        assert_eq!(
            with_formats("m=video 9 UDP/TLS/RTP/SAVPF\n"),
            "m=video 9 UDP/TLS/RTP/SAVPF\r\n"
        );
    }

    #[test]
    fn rfc8843_7_1_an_offer_with_one_mid_twice_is_refused() {
        assert!(check_offer_mids("v=0\r\na=mid:a\r\na=mid:b\r\n").is_ok());
        assert_eq!(
            check_offer_mids("v=0\r\na=mid:a\r\na=mid:a\r\n").unwrap_err(),
            "the engine drew one mid for two media sections"
        );
    }
}
