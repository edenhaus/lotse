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
//! to the stream index its m-line has, in sequence order: a late or
//! repeated one is dropped, as the RTSP source's reorderer drops it, and so
//! is one from before the camera's timestamps jumped (RFC 3550 §5.1), late
//! or of a former source. Picture Loss Indications (RFC 4585 §6.3.1)
//! ask the camera for a keyframe once connected, every
//! [`PLI_INTERVAL`] until one arrived (at most [`STARTUP_PLIS`]), and after
//! a gap in the video's sequence numbers, rate-limited. Consent freshness
//! (RFC 7675) is str0m's: its agent going disconnected after the
//! connection ends the attempt (`SPEC-DEVIATION`, at
//! `IngestEngine::on_event`: seconds without an answer, not RFC 7675
//! §5.1's 30 s). The data channel (RFC 8831, RFC 8832) is opened, its
//! messages counted and dropped.
//!
//! Every format the answer accepts on an m-line is the camera's to send in
//! (RFC 3264 §7). A track carries one codec, the one the answer accepted
//! first that lotse carries: a packet in another accepted format of that
//! codec (another H.264 profile or packetization mode, which the in-band
//! parameter sets describe) goes to the same track; one in another codec
//! is dropped, counted and logged (`SPEC-DEVIATION`, at
//! `IngestEngine::negotiated`).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use dimpl::TimeoutError;
use lotse_codec::rtp_ingest::{Declared, RtpPacket, Sprop};
use lotse_codec::{h264, h265};
use lotse_core::codec::{Codec, Kind};
use lotse_core::discontinuity::MAX_TIMESTAMP_JUMP;
use lotse_core::ingest::IngestCounters;
use lotse_core::runner::DEFAULT_READY_TIMEOUT;
use lotse_core::signaling::{SignalCandidate, close};
use lotse_core::source::SourceError;
use lotse_core::throttle::Throttle;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::crypto::{CryptoError, DtlsError};
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
    /// RTP packets in a format the answer accepted of another codec than
    /// their track's, dropped.
    pub other_codec_packets: u64,
    /// RTP packets from before the camera's timestamps jumped, late or
    /// of a former source, more than a second of media time off the
    /// newest packet's, dropped (RFC 3550 §5.1).
    pub stale_packets: u64,
    /// RTP packets the sequence numbers say never arrived (RFC 3550
    /// §6.4.1): the numbers each source skipped.
    pub lost_packets: u64,
    /// Other late or repeated RTP packets (reordered or repaired on the
    /// way), dropped: the depacketizers take packets in sequence order.
    pub late_packets: u64,
    /// Sender Reports handed on.
    pub sender_reports: u64,
    /// Sender Reports without a wallclock time, dropped.
    pub unusable_reports: u64,
    /// Sender Reports of a source other than the stream's newest packet's
    /// (a former one, or one that has sent no packet yet), dropped.
    pub other_source_reports: u64,
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
    /// The payload types of the answer's m-line in the track's codec.
    pts: Vec<u8>,
    /// Those in another codec lotse carries, which the track does not
    /// take.
    others: Vec<u8>,
    /// Video, whose losses ask for a keyframe.
    video: bool,
    /// The track's RTP clock rate, ticks per second.
    clock_rate: u32,
    /// The synchronization sources of the packets seen (RFC 3550 §3),
    /// the latest first, each with the highest sequence number seen of
    /// it and that packet's timestamp: at most [`MAX_SOURCES`].
    sources: Vec<(u32, u16, u32)>,
}

/// Why a remote candidate is not handed to the agent
/// ([`IngestEngine::remote_candidate`]); logged.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refused {
    /// Its connection-address is an mDNS name.
    Mdns,
    /// It does not parse: str0m's error.
    Unreadable(String),
    /// The viewer sessions' policy refuses its address, for the reason.
    Address(SocketAddr, &'static str),
}

/// What a packet is to its stream's numbering ([`Stream::sequence`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Ahead of the highest of its source: `lost` the numbers it skips
    /// (RFC 3550 §A.1), `new_source` when it is its source's first.
    Ahead {
        /// How many numbers were skipped: packets lost.
        lost: u16,
        /// The first packet of a synchronization source.
        new_source: bool,
    },
    /// Late or repeated within its source's numbering, near the newest
    /// packet's timestamp: reordered or repaired on the way. Dropped, as
    /// the RTSP source's reorderer drops a packet that arrives after a
    /// later one (retina's `Reorderer` with `max_delay` zero, its
    /// `Pushed::Late`; `lotse_rtsp`'s `udp_options`), so both sources hand
    /// `RtpTracks` packets in sequence order: handed on, it would set a
    /// depacketizer's last sequence number back (RFC 6184 §5.8 reassembles
    /// by consecutive numbers), and the next unit, complete, would read
    /// as following a gap and be dropped too.
    Late,
    /// Late or repeated, or of a former source (one the stream knows
    /// that is not the newest packet's), with a timestamp more than
    /// [`MAX_TIMESTAMP_JUMP`] of media time from the newest packet's: it
    /// was sent before the camera's timestamps jumped (an encoder restart,
    /// RFC 3550 §5.1, §8.2) and arrived after, delayed or retransmitted;
    /// a former source's packet may be ahead in its own numbering, never
    /// having arrived before. Dropped, and its source's numbers left as
    /// they were: handed on, it would take the stream back to its old
    /// timeline and the next packet forward again, a new timeline each
    /// (`lotse_codec::rtp_ingest::RtpTracks`).
    Stale,
}

/// How many synchronization sources a stream keeps the numbers of: the
/// one a camera sends from, and a few before it whose delayed packets may
/// still arrive (an encoder restart starts a new one, RFC 3550 §8.2).
/// A late packet of one of them leaves the others' numbers alone; a
/// camera that keeps changing its SSRC holds no more than this.
const MAX_SOURCES: usize = 4;

impl Stream {
    /// Notes packet `seq` of synchronization source `ssrc`, timestamp
    /// `ts`. Each source numbers its packets on its own (RFC 3550 §5.1,
    /// §8.2), so a source's first packet is no loss, and a late or
    /// repeated one (no more than half the sequence space behind) changes
    /// nothing. It is [`Seen::Stale`] when its timestamp is off the newest
    /// packet's timeline (the latest source's highest) and it is late or
    /// of a former source: only the newest source moves the timeline (its
    /// own jump is the camera's, RFC 3550 §5.1), and a source never seen
    /// (or forgotten) starts its own (an encoder restart, RFC 3550 §8.2).
    fn sequence(&mut self, ssrc: u32, seq: u16, ts: u32) -> Seen {
        let highest = self
            .sources
            .iter()
            .find(|(seen, _, _)| *seen == ssrc)
            .map(|(_, highest, _)| *highest);
        let ahead = highest.map_or(1, |highest| seq.wrapping_sub(highest));
        let late = !(1..0x8000).contains(&ahead);
        let newest = self.sources.first().copied();
        let former = highest.is_some() && newest.is_some_and(|(newest, _, _)| newest != ssrc);
        let off = newest.is_some_and(|(_, _, newest)| self.off_timeline(ts, newest));
        if off && (late || former) {
            return Seen::Stale;
        }
        if late {
            return Seen::Late;
        }
        self.sources.retain(|(seen, _, _)| *seen != ssrc);
        self.sources.insert(0, (ssrc, seq, ts));
        self.sources.truncate(MAX_SOURCES);
        Seen::Ahead {
            lost: ahead.wrapping_sub(1),
            new_source: highest.is_none(),
        }
    }

    /// Whether `ssrc` is the source of the stream's newest packet, the one
    /// whose timeline the stream carries.
    fn is_newest(&self, ssrc: u32) -> bool {
        self.sources
            .first()
            .is_some_and(|(newest, _, _)| *newest == ssrc)
    }

    /// Whether `ts` is more than [`MAX_TIMESTAMP_JUMP`] of media time
    /// from `newest`, either way, 32-bit wrap included (RFC 3550 §5.1):
    /// as far as `TimestampGuard` lets a timeline move back.
    fn off_timeline(&self, ts: u32, newest: u32) -> bool {
        let ticks = i32::from_ne_bytes(ts.wrapping_sub(newest).to_ne_bytes()).unsigned_abs();
        u128::from(ticks).saturating_mul(1_000)
            > u128::from(self.clock_rate).saturating_mul(MAX_TIMESTAMP_JUMP.as_millis())
    }
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
    /// The rate limit of the other codecs' packets' log line.
    other_codec: Throttle,
    /// The rate limit of the new synchronization sources' log line.
    new_source: Throttle,
    /// The rate limit of the stale packets' log line.
    stale: Throttle,
    /// The rate limit of the late packets' log line.
    late: Throttle,
    /// The rate limit of the lost packets' log line.
    loss: Throttle,
    /// The connection's ingest counters, which the source shows
    /// (`TrackSet::ingest`): packets lost, packets dropped out of order,
    /// datagrams rejected, counted as the RTSP source counts them
    /// ([`Self::count_into`]).
    ingest: Arc<IngestCounters>,
    /// The rate limit of the other sources' Sender Reports' log line.
    other_source: Throttle,
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

/// Whether `err` is dimpl giving up a DTLS handshake for time: its
/// retransmissions exhausted, its handshake deadline passed, or an Auto
/// `ClientHello` unresolved ([`TimeoutError`]). str0m 0.25 hands every
/// dimpl error on as text, `CryptoError::Other("DTLS error: {err}")`
/// (its `dtls.rs`, read 2026-11-08; observed as "DTLS error: timeout:
/// handshake" the same day), so the timeout is told by that text, made
/// with dimpl's own `Display`.
fn dtls_timed_out(err: &RtcError) -> bool {
    let RtcError::Dtls(DtlsError::CryptoError(CryptoError::Other(message))) = err else {
        return false;
    };
    [
        TimeoutError::HybridClientHello,
        TimeoutError::Connect,
        TimeoutError::Handshake,
    ]
    .into_iter()
    .any(|timeout| *message == format!("DTLS error: {}", dimpl::Error::Timeout(timeout)))
}

/// Whether the media sections of `offer` carry distinct mids: str0m 0.24
/// drew each m-line's mid at random and could draw one twice within one
/// offer (observed 2026-10-01); str0m 0.25 draws none twice (its
/// changelog, #1092), and the check stays as the guard of that.
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

/// Whether the relay takes `offer`: at most [`MAX_OFFER_BYTES`].
fn check_offer_size(offer: &str) -> Result<(), String> {
    if offer.len() <= MAX_OFFER_BYTES {
        Ok(())
    } else {
        Err(format!(
            "an offer of {} bytes, over the {MAX_OFFER_BYTES} the relay takes",
            offer.len()
        ))
    }
}

/// `answer` with a format on every `m=` line of port 0 that lists none,
/// so str0m parses it. RFC 8866 §5.14 has at least one format on every
/// `m=` line, and RFC 3264 §6 lets a rejected one list any; str0m 0.24
/// itself answered a rejected m-line without one (observed 2026-11-06) and
/// refused to parse that, so a camera on str0m 0.24 (or any other that
/// writes it so) would have had its whole answer refused for an audio
/// m-line it declined. str0m 0.25 writes `0` there and parses one without
/// (`MediaLine`'s `Display` and consistency check, read 2026-11-08). The
/// format added is never used (the m-line is stopped): the lowest payload
/// type the answer names nowhere, so it gives no other m-line's payload
/// type a second codec (`0` unless the answer uses 0), mapped to PCMU;
/// `Err` when the answer names every one.
// SPEC-DEVIATION(RFC 8866 §5.14): an answer that lists no format on a
// rejected m-line breaks the grammar and is taken anyway, as str0m 0.24
// wrote such answers itself; a live m-line without formats is still
// refused (by str0m);
// gate: rfc8866_5_14_a_rejected_m_line_without_formats_gets_one
fn with_formats(answer: &str) -> Result<String, String> {
    let named = named_payload_types(answer);
    let placeholder = (0..=127_u8).find(|pt| !named.contains(pt));
    let mut out = String::with_capacity(answer.len().saturating_add(32));
    // The added format's `a=rtpmap`, written at the end of its media
    // section: str0m 0.25 refuses a format above the static ones without
    // one, and reads the `a=mid` only where the section has it.
    let mut rtpmap: Option<String> = None;
    for line in answer.lines() {
        if line.starts_with("m=") {
            out.push_str(&rtpmap.take().unwrap_or_default());
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let empty = matches!(fields.as_slice(), [media, port, _] if media.starts_with("m=") && *port == "0");
        out.push_str(line.trim_end());
        if empty {
            let pt = placeholder.ok_or(
                "a rejected m-line without formats, and no payload type left to name on it",
            )?;
            out.push(' ');
            out.push_str(&pt.to_string());
            rtpmap = Some(format!("a=rtpmap:{pt} PCMU/8000\r\n"));
        }
        out.push_str("\r\n");
    }
    out.push_str(&rtpmap.unwrap_or_default());
    Ok(out)
}

/// The payload types `sdp` names anywhere: as formats of its `m=` lines
/// and in its `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` attributes.
fn named_payload_types(sdp: &str) -> Vec<u8> {
    let mut named = Vec::new();
    for line in sdp.lines() {
        if let Some(media) = line.strip_prefix("m=") {
            named.extend(
                media
                    .split_whitespace()
                    .skip(3)
                    .filter_map(|format| format.parse::<u8>().ok()),
            );
        } else if let Some(value) = ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        {
            named.extend(
                value
                    .split_whitespace()
                    .next()
                    .and_then(|pt| pt.parse::<u8>().ok()),
            );
        }
    }
    named
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
/// a microsecond. `None` at or before the Unix epoch: str0m 0.25 makes
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
        check_offer_size(&offer)?;
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
            other_codec: Throttle::default(),
            new_source: Throttle::default(),
            stale: Throttle::default(),
            late: Throttle::default(),
            loss: Throttle::default(),
            ingest: Arc::default(),
            other_source: Throttle::default(),
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

    /// Counts into `ingest`, the connection's counters, from now on, as
    /// the RTSP source counts into them: the packets a sequence gap says
    /// were lost (RFC 3550 §6.4.1), its size; a packet dropped late,
    /// repeated or stale as out of order, one that arrived after a later
    /// one; a datagram the engine could not read, or that str0m's session
    /// does not take (not STUN, DTLS, RTP or RTCP by RFC 7983 §7, or not
    /// on one of its candidate pairs), as rejected, as RTSP rejects one
    /// that is not RTP or not from the camera's media port.
    pub fn count_into(&mut self, ingest: Arc<IngestCounters>) {
        self.ingest = ingest;
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

    /// Applies the camera's answer (RFC 8829 §5.3) at `now`. One at or
    /// after the answer's deadline ends the attempt by the deadline; a
    /// repeated answer is ignored. One the engine cannot apply, or without a video
    /// m-line it receives in a carried codec, ends the attempt as a
    /// protocol error closing `invalid_answer`; else the negotiated tracks
    /// are output ([`IngestOutput::Tracks`]) and ICE starts, the answer's
    /// candidates through the same check as trickled ones.
    pub fn accept_answer(&mut self, now: Instant, sdp: &str) {
        self.now = now;
        if self.expired(now) {
            return;
        }
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
        let parsed = Sdp::parse(sdp);
        let stopped: Vec<&str> = parsed
            .media()
            .iter()
            .filter(|section| parsed.stopped(section))
            .filter_map(Section::mid)
            .collect();
        let (rest, candidates) = split_candidates(sdp);
        let rest = with_formats(&rest)?;
        // str0m 0.25 panics on a payload type reused across media
        // sections ("Pt locked multiple times"), so the check comes first,
        // of exactly what str0m parses.
        check_payload_types(&rest)?;
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
    /// rejected m-line, port 0, is the caller's to leave out: str0m 0.25
    /// keeps it live.) The track takes every payload type of the answer's
    /// m-line in that codec; those of another codec it does not.
    // SPEC-DEVIATION(RFC 3264 §7): the camera may change among the formats
    // the answer accepted at any time, another codec among them; a track
    // has one codec, so lotse carries the codec the answer accepted first
    // and drops (counts and logs) packets in another one, rather than
    // switch the track mid-stream. Observed behavior: Home Assistant's
    // native WebRTC cameras send one codec for a session;
    // gate: rfc3264_7_a_packet_of_another_accepted_codec_is_dropped_not_switched
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
        let mut pts = Vec::new();
        let mut others = Vec::new();
        for (format_pt, format) in &carried {
            if *format == declared {
                pts.push(*format_pt);
            } else {
                others.push(*format_pt);
            }
        }
        tracing::debug!(
            index,
            ?pts,
            ?others,
            "webrtc: the payload types the track takes, and not"
        );
        self.streams.push(Stream {
            mid,
            index,
            pts,
            others,
            video: declared.kind == Kind::Video,
            clock_rate: declared.clock_rate,
            sources: Vec::new(),
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
    /// any order). After the end, one is ignored. At or after the
    /// answer's or the connection's deadline, the attempt ends by it
    /// first, as for an answer or a datagram, and the candidate is not
    /// taken.
    pub fn add_remote_candidate(&mut self, now: Instant, candidate: &SignalCandidate) {
        self.now = now;
        if self.expired(now) {
            return;
        }
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

    /// Hands one remote candidate line to the agent unless
    /// [`Self::remote_candidate`] refuses it.
    fn add_remote(&mut self, line: &str) {
        match self.remote_candidate(line) {
            Ok(candidate) => {
                let addr = candidate.addr();
                tracing::debug!(kind = ?candidate.kind(), %addr, "webrtc: remote candidate");
                self.rtc.add_remote_candidate(candidate);
                self.stats.remote_candidates = self.stats.remote_candidates.saturating_add(1);
            }
            Err(refused) => {
                tracing::debug!(?refused, "webrtc: remote candidate ignored");
                self.stats.refused_candidates = self.stats.refused_candidates.saturating_add(1);
            }
        }
    }

    /// The candidate of one remote candidate line, or why it is not taken:
    /// an mDNS name, told before the line is parsed, so whatever str0m
    /// makes of the name it is ignored
    /// (draft-ietf-mmusic-mdns-ice-candidates §3.2.1, without a resolver);
    /// a line that does not parse; an address the viewer sessions' policy
    /// refuses ([`crate::session`]'s `refused_address`, RFC 8445 §6.1.2.2).
    fn remote_candidate(&self, line: &str) -> Result<Candidate, Refused> {
        if is_mdns(line) {
            return Err(Refused::Mdns);
        }
        let candidate =
            Candidate::from_sdp_string(line).map_err(|err| Refused::Unreadable(err.to_string()))?;
        let addr = candidate.addr();
        match refused_address(addr.ip(), &self.scopes) {
            Some(reason) => Err(Refused::Address(addr, reason)),
            None => Ok(candidate),
        }
    }

    /// A datagram from `source` to the local `destination`, at `now`; at
    /// or after the connection's deadline, the attempt ends by it first.
    pub fn receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        bytes: &[u8],
    ) {
        self.now = now;
        if self.phase == Phase::Ended || self.expired(now) {
            return;
        }
        let Ok(contents) = DatagramRecv::try_from(bytes) else {
            self.reject();
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
            self.reject();
            return;
        }
        self.input(input);
    }

    /// Counts a datagram the engine rejects.
    fn reject(&mut self) {
        self.stats.bad_datagrams = self.stats.bad_datagrams.saturating_add(1);
        self.ingest.count_rejected();
    }

    /// Time passed: the deadlines, the startup keyframe requests and the
    /// engine's timers.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        if self.expired(now) {
            return;
        }
        // Once ended, str0m is inert and nothing is due.
        self.startup_pli(false);
        self.input(Input::Timeout(now));
    }

    /// Ends the attempt when its deadline passed by `now`, the answer's or
    /// the connection's; `true` then. The calls that take the camera's
    /// input check it first: an answer or a datagram that comes at or
    /// after its deadline is not taken, whether or not the timeout was
    /// handled before.
    fn expired(&mut self, now: Instant) -> bool {
        let overdue = self.deadline.is_some_and(|deadline| now >= deadline);
        match self.phase {
            Phase::Offered if overdue => {
                let secs = ANSWER_TIMEOUT.as_secs();
                self.end(
                    SourceError::Timeout,
                    close::ANSWER_TIMEOUT,
                    format!("webrtc: no answer within {secs} s"),
                );
                true
            }
            Phase::Answered if overdue => {
                let message = self.not_connected();
                self.end(SourceError::Timeout, close::ICE_FAILED, message);
                true
            }
            _ => false,
        }
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

    /// Why an attempt that is not connected ends, at [`Self::now`]: how
    /// far into the attempt.
    fn not_connected(&self) -> String {
        let ms = self.now.saturating_duration_since(self.started).as_millis();
        format!("webrtc: not connected {ms} ms into the attempt")
    }

    /// Ends the attempt as a protocol error when str0m failed: a DTLS
    /// handshake that failed (a fingerprint that does not match, RFC 5763
    /// §5), or another engine error. A DTLS handshake that timed out
    /// before the connection ends it as not connected instead, as the
    /// connection's deadline does (`ice_failed`): dimpl 0.9's
    /// retransmissions of an unanswered flight (1 s doubling, 4 retries,
    /// each ±25 %, so 23 to 39 s; its `Config::handshake_timeout` docs,
    /// read 2026-11-08) can give up before [`CONNECT_BY`], and a camera
    /// that never answered the handshake is a connection that never came
    /// up, not lotse's internal error. Once connected, a DTLS error keeps
    /// its protocol ending.
    fn check(&mut self, result: Result<(), RtcError>) {
        let Err(err) = result else {
            return;
        };
        if self.phase == Phase::Answered && dtls_timed_out(&err) {
            let message = format!("{}: {err}", self.not_connected());
            self.end(SourceError::Timeout, close::ICE_FAILED, message);
        } else {
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
                // the last answered check; str0m 0.25's agent goes
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
    /// dropped, as is one before 1970 (str0m 0.25 hands NTP zero over as
    /// the Unix epoch).
    ///
    /// Only the reports of the stream's newest source are handed on (str0m
    /// 0.25 keys a report by its sender's SSRC, `SenderInfo::ssrc`): the
    /// report maps the timeline of the packets the stream carries, which
    /// is that source's. A former source's report, delayed past an encoder
    /// restart (RFC 3550 §8.2), maps the old timeline; after the new
    /// source's jump reset the clock mapping it would be the first anchor
    /// and misplace the current media. A report of a source that has sent
    /// no packet yet is dropped too: until its first packet the stream
    /// carries the former timeline, and its next report (RFC 3550 §6.2,
    /// every few seconds) anchors the new one. A sender sends reports only
    /// once it sends packets (§6.4), so the first anchor of an attempt
    /// waits at most one report.
    fn on_sender_report(&mut self, feedback: &SenderFeedback) {
        let Some(stream) = self.streams.iter().find(|s| s.mid == feedback.mid) else {
            return;
        };
        let ssrc = *feedback.sender_info.ssrc;
        if !stream.is_newest(ssrc) {
            self.stats.other_source_reports = self.stats.other_source_reports.saturating_add(1);
            if let Some(count) = self.other_source.hit(self.now) {
                tracing::debug!(
                    index = stream.index,
                    ssrc,
                    count,
                    "webrtc: Sender Report of a source other than the newest packet's dropped"
                );
            }
            return;
        }
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

    /// Counts what packet `seq` of source `ssrc` on stream `index` is to
    /// its stream's numbering ([`Seen`]), in the engine's stats and the
    /// connection's ingest counters ([`Self::count_into`]), with
    /// rate-limited lines: `Some` when it is handed on, `true` when
    /// numbers before it were lost; `None` when it is dropped, late or
    /// stale, counted as out of order.
    fn counted(&mut self, seen: Seen, index: usize, ssrc: u32, seq: u16) -> Option<bool> {
        let (stale, log) = match seen {
            Seen::Ahead { lost, new_source } => {
                if new_source && let Some(count) = self.new_source.hit(self.now) {
                    tracing::debug!(index, ssrc, count, "webrtc: a new synchronization source");
                }
                if lost > 0 {
                    self.stats.lost_packets =
                        self.stats.lost_packets.saturating_add(u64::from(lost));
                    self.ingest.count_lost(u64::from(lost));
                    if let Some(count) = self.loss.hit(self.now) {
                        tracing::debug!(
                            index,
                            ssrc,
                            lost,
                            count,
                            "webrtc: RTP sequence gap; packets lost"
                        );
                    }
                }
                return Some(lost > 0);
            }
            Seen::Late => {
                self.stats.late_packets = self.stats.late_packets.saturating_add(1);
                (false, self.late.hit(self.now))
            }
            Seen::Stale => {
                self.stats.stale_packets = self.stats.stale_packets.saturating_add(1);
                (true, self.stale.hit(self.now))
            }
        };
        self.ingest.count_out_of_order();
        if let Some(count) = log {
            if stale {
                tracing::debug!(
                    index,
                    ssrc,
                    seq,
                    count,
                    "webrtc: a packet from before the camera's timestamps jumped dropped"
                );
            } else {
                tracing::debug!(
                    index,
                    ssrc,
                    seq,
                    count,
                    "webrtc: a late or repeated packet dropped"
                );
            }
        }
        None
    }

    /// Whether `id` is the data channel the offer opened.
    fn is_ours(&self, id: ChannelId) -> bool {
        self.channel.as_ref().is_some_and(|(ours, _)| *ours == id)
    }

    /// One RTP packet: handed on under its stream's index when it is of a
    /// negotiated m-line (str0m maps its SSRC by `a=ssrc` or the RFC 9143
    /// `mid` header extension) in a payload type of its track's codec,
    /// else counted and dropped, one in another codec the answer accepted
    /// with a warning. A forward gap in the video's sequence numbers of
    /// one synchronization source (RFC 3550 §A.1) is a lost picture, which
    /// asks for a keyframe. A late or repeated packet is dropped
    /// ([`Seen::Late`]), as an RTSP source's reorderer drops every late
    /// packet (retina's `Reorderer`), and so is one from before the
    /// camera's timestamps jumped, or one of a former source off the
    /// newest source's timeline ([`Seen::Stale`]). New sources, late and
    /// stale packets are logged at most once per summary interval.
    fn on_rtp(&mut self, packet: str0m::rtp::RtpPacket) {
        let header = &packet.header;
        let mid = self
            .rtc
            .direct_api()
            .stream_rx(&header.ssrc)
            .map(|stream| stream.mid());
        let pt = *header.payload_type;
        let seq = header.sequence_number;
        let Some(stream) = self
            .streams
            .iter_mut()
            .find(|stream| Some(stream.mid) == mid && stream.pts.contains(&pt))
        else {
            let other = self
                .streams
                .iter()
                .any(|stream| Some(stream.mid) == mid && stream.others.contains(&pt));
            if other {
                self.other_codec(pt);
                return;
            }
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
        let video = stream.video;
        let seen = stream.sequence(ssrc, seq, header.timestamp);
        let Some(lost) = self.counted(seen, index, ssrc, seq) else {
            return;
        };
        let lost = lost && video;
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

    /// A packet in payload type `pt`, which the answer accepted in another
    /// codec than its track's: dropped, counted, and logged as a warning
    /// at most once per summary interval.
    fn other_codec(&mut self, pt: u8) {
        self.stats.other_codec_packets = self.stats.other_codec_packets.saturating_add(1);
        if let Some(count) = self.other_codec.hit(self.now) {
            tracing::warn!(
                pt,
                count,
                "webrtc: RTP in another codec than its track's dropped; the track carries the codec the answer accepted first"
            );
        }
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

    /// Drops what was queued and closes str0m gracefully, queuing what
    /// that sends, the DTLS
    /// `close_notify` alert (RFC 6347 §4.2.7) and an RTCP BYE (RFC 3550
    /// §6.6), at most [`CLOSE_OUTPUTS`] and up to its first timeout, then
    /// drops it to inert, as a viewer session closes.
    fn drain_close(&mut self) {
        // What was queued and not polled yet (the tracks of an answer, a
        // connection, media) is of an attempt that ended: only the close
        // goes out now.
        self.queued.clear();
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
    fn rfc3550_a_1_each_synchronization_source_keeps_its_own_numbers() {
        const A: u32 = 0xa;
        const B: u32 = 0xb;
        let ahead = |lost, new_source| Seen::Ahead { lost, new_source };
        // `lost` counts the numbers skipped.
        let mut stream = video_stream();
        // All on one timeline: the timestamps play no part here.
        let ts = 90_000;
        assert_eq!(
            stream.sequence(A, 1_000, ts),
            ahead(0, true),
            "a source's first packet"
        );
        assert_eq!(
            stream.sequence(B, 5, ts),
            ahead(0, true),
            "a new source's first packet"
        );
        // A packet of the former source, delayed: B's numbers stay.
        assert_eq!(stream.sequence(A, 999, ts), Seen::Late);
        assert_eq!(stream.sequence(B, 9, ts), ahead(3, false), "B's own gap");
        assert_eq!(stream.sequence(B, 10, ts), ahead(0, false));
        assert_eq!(stream.sequence(B, 10, ts), Seen::Late, "a repeat");
        assert_eq!(stream.sequence(B, 8, ts), Seen::Late, "a late one");
        // A's numbers are kept too: its gap after it comes back.
        assert_eq!(stream.sequence(A, 1_002, ts), ahead(1, false));
        assert_eq!(stream.sources, [(A, 1_002, ts), (B, 10, ts)]);
        // Half the sequence space ahead is still ahead; more is behind.
        assert_eq!(
            stream.sequence(A, 1_002_u16.wrapping_add(0x7fff), ts),
            ahead(0x7ffe, false)
        );
        assert_eq!(
            stream.sequence(A, 1_002_u16.wrapping_add(0x7fff).wrapping_add(0x8000), ts),
            Seen::Late
        );
        // At most MAX_SOURCES, the oldest forgotten: B, then a new source
        // again.
        for ssrc in 1..u32::try_from(MAX_SOURCES).unwrap() {
            assert_eq!(stream.sequence(0x100 + ssrc, 1, ts), ahead(0, true));
        }
        assert_eq!(stream.sources.len(), MAX_SOURCES);
        assert!(!stream.sources.iter().any(|(ssrc, _, _)| *ssrc == B));
        assert_eq!(stream.sequence(B, 2_000, ts), ahead(0, true));
    }

    /// A video stream of no payload types, at 90 kHz.
    fn video_stream() -> Stream {
        Stream {
            mid: Mid::from("v"),
            index: 0,
            pts: Vec::new(),
            others: Vec::new(),
            video: true,
            clock_rate: 90_000,
            sources: Vec::new(),
        }
    }

    #[test]
    fn draft_ietf_mmusic_mdns_ice_candidates_3_2_1_an_mdns_name_is_refused_before_parsing() {
        let addr = "192.0.2.10:5000".parse().unwrap();
        let now = lotse_core::clock::Clock::now(&lotse_core::clock::SystemClock);
        let options = WebRtcOptions {
            data_channel: None,
            audio: false,
        };
        let engine = IngestEngine::offer(&options, &[addr], now, now).unwrap();
        // Told by the name alone, whatever str0m makes of the line.
        for mdns in [
            "candidate:3 1 udp 2130706431 0a1b2c3d.local 6000 typ host",
            "candidate:3 1 udp 2130706431 0a1b2c3d.LOCAL 6000 typ host",
            "candidate:3 1 udp 2130706431 0a1b2c3d.local 6000 typ host generation 0",
        ] {
            assert_eq!(
                engine.remote_candidate(mdns).unwrap_err(),
                Refused::Mdns,
                "{mdns}"
            );
        }
        assert!(matches!(
            engine.remote_candidate("nonsense"),
            Err(Refused::Unreadable(_))
        ));
        assert!(matches!(
            engine.remote_candidate("candidate:2 1 udp 2130706431 127.0.0.1 6000 typ host"),
            Err(Refused::Address(_, _))
        ));
        let taken = engine
            .remote_candidate("candidate:4 1 udp 2130706431 192.0.2.20 6001 typ host")
            .unwrap();
        assert_eq!(taken.addr(), "192.0.2.20:6001".parse().unwrap());
    }

    #[test]
    fn rfc3550_5_1_a_late_packet_off_the_newest_packet_s_timeline_is_stale() {
        const A: u32 = 0xa;
        const B: u32 = 0xb;
        let mut stream = video_stream();
        assert!(matches!(
            stream.sequence(A, 100, 900_000),
            Seen::Ahead { .. }
        ));
        // The camera's timestamps jumped back 10 s, its numbers went on.
        assert!(matches!(stream.sequence(A, 101, 0), Seen::Ahead { .. }));
        // A late packet of the old timeline: stale, either way of the
        // newest and across the 32-bit wrap.
        assert_eq!(stream.sequence(A, 99, 900_000), Seen::Stale);
        assert_eq!(stream.sequence(A, 99, u32::MAX - 90_000), Seen::Stale);
        // Within MAX_TIMESTAMP_JUMP (1 s at 90 kHz) of the newest, either
        // way: reordered or repaired.
        assert_eq!(stream.sequence(A, 99, 90_000), Seen::Late);
        assert_eq!(stream.sequence(A, 99, u32::MAX - 89_999), Seen::Late);
        assert_eq!(stream.sequence(A, 99, 90_001), Seen::Stale);
        // A new source after an encoder restart (RFC 3550 §8.2): a late
        // packet of the former one is measured against the newest source.
        assert!(matches!(
            stream.sequence(B, 7, 45_000_000),
            Seen::Ahead { .. }
        ));
        assert_eq!(stream.sequence(A, 100, 1_000), Seen::Stale);
        assert_eq!(stream.sequence(A, 100, 45_000_000 - 90_000), Seen::Late);
        assert_eq!(stream.sources, [(B, 7, 45_000_000), (A, 101, 0)]);
        // Audio at 8 kHz: one second is 8000 ticks.
        let mut audio = Stream {
            clock_rate: 8_000,
            video: false,
            ..video_stream()
        };
        assert!(matches!(audio.sequence(A, 2, 16_000), Seen::Ahead { .. }));
        assert_eq!(audio.sequence(A, 1, 8_000), Seen::Late);
        assert_eq!(audio.sequence(A, 1, 7_999), Seen::Stale);
    }

    #[test]
    fn rfc3550_8_2_a_former_source_s_packet_off_the_newest_timeline_is_stale_even_ahead() {
        const A: u32 = 0xa;
        const B: u32 = 0xb;
        let mut stream = video_stream();
        assert!(matches!(stream.sequence(A, 101, 0), Seen::Ahead { .. }));
        // An encoder restart (RFC 3550 §8.2): a new source, a new timeline.
        assert!(matches!(
            stream.sequence(B, 7, 45_000_000),
            Seen::Ahead { .. }
        ));
        // A packet of the former source never seen before, ahead in its
        // own numbering, off the newest source's timeline: stale, its
        // source's numbers kept and the newest source still the newest.
        assert_eq!(stream.sequence(A, 102, 3_000), Seen::Stale);
        assert_eq!(stream.sequence(A, 105, 6_000), Seen::Stale);
        assert_eq!(stream.sources, [(B, 7, 45_000_000), (A, 101, 0)]);
        assert_eq!(
            stream.sequence(B, 8, 45_003_000),
            Seen::Ahead {
                lost: 0,
                new_source: false
            }
        );
        // On the newest source's timeline, the former source comes back
        // as the newest, its own gap a loss (RFC 3550 §A.1).
        assert_eq!(
            stream.sequence(A, 103, 45_006_000),
            Seen::Ahead {
                lost: 1,
                new_source: false
            }
        );
        assert_eq!(stream.sources, [(A, 103, 45_006_000), (B, 8, 45_003_000)]);
        // The newest source's own jump moves the timeline (RFC 3550 §5.1),
        // and a source never seen starts its own (RFC 3550 §8.2).
        assert!(matches!(stream.sequence(A, 104, 0), Seen::Ahead { .. }));
        assert_eq!(
            stream.sequence(0xc, 1, 90_000_000),
            Seen::Ahead {
                lost: 0,
                new_source: true
            }
        );
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
        // str0m 0.25 reads NTP 0 (a sender without a wallclock) as the
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
            // Source 1's packets: its reports are the ones handed on.
            sources: vec![(1, 0, 7)],
            ..video_stream()
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
    fn rfc3550_8_2_a_former_source_s_sender_report_after_a_restart_is_dropped() {
        const A: u32 = 0xa;
        const B: u32 = 0xb;
        const C: u32 = 0xc;
        let addr = "192.0.2.10:5000".parse().unwrap();
        let now = lotse_core::clock::Clock::now(&lotse_core::clock::SystemClock);
        let options = WebRtcOptions {
            data_channel: None,
            audio: false,
        };
        let mut engine = IngestEngine::offer(&options, &[addr], now, now).unwrap();
        let mid = engine.video_mid;
        engine.streams.push(Stream {
            mid,
            index: 1,
            ..video_stream()
        });
        let wallclock = UNIX_EPOCH + Duration::from_secs(1);
        let report = |ssrc: u32, rtp_time: u64| {
            Event::SenderFeedback(SenderFeedback {
                mid,
                rid: None,
                received_at: now,
                sender_info: str0m::rtp::rtcp::SenderInfo {
                    ssrc: ssrc.into(),
                    ntp_time: wallclock,
                    rtp_time: str0m::media::MediaTime::new(rtp_time, Frequency::NINETY_KHZ),
                    sender_packet_count: 0,
                    sender_octet_count: 0,
                },
            })
        };
        let forwarded = |rtp_ts| IngestOutput::SenderReport {
            index: 1,
            ntp: (NTP_UNIX_OFFSET + 1) << 32,
            rtp_ts,
            arrival: now,
        };
        // Before any packet: no timeline carried yet, no anchor.
        engine.on_event(report(A, 900_000));
        assert_eq!(engine.queued.pop_front(), None);
        // A's packets, then its report: handed on.
        engine.streams[0].sequence(A, 1_000, 900_000);
        engine.on_event(report(A, 900_000));
        assert_eq!(engine.queued.pop_front(), Some(forwarded(900_000)));
        // The encoder restarted: B's packets on a new timeline. A report
        // of A delayed past it, and one of C that has sent no packet, are
        // dropped; B's is handed on.
        engine.streams[0].sequence(B, 5, 3_000);
        engine.on_event(report(A, 903_000));
        engine.on_event(report(C, 6_000));
        assert_eq!(engine.queued.pop_front(), None);
        engine.on_event(report(B, 6_000));
        assert_eq!(engine.queued.pop_front(), Some(forwarded(6_000)));
        assert_eq!(engine.stats.other_source_reports, 3);
        assert_eq!(engine.stats.sender_reports, 2);
    }

    /// str0m 0.25's error for dimpl's `err` (its `dtls.rs`).
    fn str0m_dtls(err: impl std::fmt::Display) -> RtcError {
        RtcError::Dtls(DtlsError::CryptoError(CryptoError::Other(format!(
            "DTLS error: {err}"
        ))))
    }

    #[test]
    fn rfc6347_4_2_4_a_dtls_handshake_that_timed_out_is_told_from_other_errors() {
        for timeout in [
            TimeoutError::HybridClientHello,
            TimeoutError::Connect,
            TimeoutError::Handshake,
        ] {
            assert!(
                dtls_timed_out(&str0m_dtls(dimpl::Error::Timeout(timeout))),
                "{timeout}"
            );
        }
        // As observed from str0m 0.25 with dimpl 0.9, 2026-11-08.
        assert!(dtls_timed_out(&str0m_dtls("timeout: handshake")));
        assert!(!dtls_timed_out(&str0m_dtls(dimpl::Error::ReceiveQueueFull)));
        assert!(!dtls_timed_out(&str0m_dtls("timeout: handshake, and more")));
        assert!(!dtls_timed_out(&RtcError::Dtls(DtlsError::CryptoError(
            CryptoError::Other("timeout: handshake".into())
        ))));
        assert!(!dtls_timed_out(&RtcError::Dtls(DtlsError::Io(
            std::io::Error::other("DTLS error: timeout: handshake")
        ))));
        assert!(!dtls_timed_out(&RtcError::RemoteSdp(
            "DTLS error: timeout: handshake".into()
        )));
    }

    #[test]
    fn rfc8445_8_a_dtls_handshake_that_times_out_before_the_connection_ends_as_ice_failed() {
        let addr = "192.0.2.10:5000".parse().unwrap();
        let started = lotse_core::clock::Clock::now(&lotse_core::clock::SystemClock);
        let ended = |phase, err| {
            let options = WebRtcOptions {
                data_channel: None,
                audio: false,
            };
            let mut engine = IngestEngine::offer(&options, &[addr], started, started).unwrap();
            engine.phase = phase;
            engine.now = started + Duration::from_millis(23_456);
            engine.check(Err(err));
            assert!(engine.is_ended());
            // The close's transmits, if any, then the end, last.
            engine.queued.pop_back()
        };
        // No error, no end. (This binary's `check` then runs every line on
        // its own: llvm-cov's summary counts a function's lines by its
        // best-covered binary, not by all of them together.)
        let mut engine = IngestEngine::offer(
            &WebRtcOptions {
                data_channel: None,
                audio: false,
            },
            &[addr],
            started,
            started,
        )
        .unwrap();
        engine.phase = Phase::Answered;
        let queued = engine.queued.len();
        engine.check(Ok(()));
        assert!(!engine.is_ended());
        assert_eq!(engine.queued.len(), queued);
        let timeout = || str0m_dtls(dimpl::Error::Timeout(TimeoutError::Handshake));
        // Before the connection: not connected, as at the deadline.
        assert_eq!(
            ended(Phase::Answered, timeout()),
            Some(IngestOutput::Ended(IngestEnd {
                error: SourceError::Timeout(
                    "webrtc: not connected 23456 ms into the attempt: \
                     DTLS error: timeout: handshake"
                        .into()
                ),
                close: close::ICE_FAILED,
                message: "webrtc: not connected 23456 ms into the attempt: \
                          DTLS error: timeout: handshake"
                    .into(),
            }))
        );
        // Once connected, and any other DTLS error: the engine's error.
        for (phase, err) in [
            (Phase::Connected, timeout()),
            (Phase::Answered, str0m_dtls(dimpl::Error::ReceiveQueueFull)),
        ] {
            let end = ended(phase, err);
            assert!(
                matches!(
                    &end,
                    Some(IngestOutput::Ended(IngestEnd {
                        error: SourceError::Protocol(_),
                        close: close::INTERNAL_ERROR,
                        message,
                    })) if message.starts_with("webrtc engine: DTLS error: ")
                ),
                "{end:?}"
            );
        }
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
            with_formats(answer).unwrap(),
            "v=0\r\nm=audio 0 UDP/TLS/RTP/SAVPF 0\r\na=mid:a\r\na=rtpmap:0 PCMU/8000\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nm=video 0 UDP/TLS/RTP/SAVPF 97\r\n"
        );
        // Only a stopped one: a live m-line without formats stays as
        // written, for str0m to refuse.
        assert_eq!(
            with_formats("m=video 9 UDP/TLS/RTP/SAVPF\n").unwrap(),
            "m=video 9 UDP/TLS/RTP/SAVPF\r\n"
        );
    }

    #[test]
    fn rfc8866_5_14_the_format_added_is_one_the_answer_names_nowhere() {
        // 0 on the video (its rtpmap), 1 in an fmtp, 2 in an rtcp-fb: 3.
        let answer = "m=audio 0 UDP/TLS/RTP/SAVPF\r\nm=video 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 H264/90000\r\na=fmtp:1 apt=0\r\na=rtcp-fb:2 nack\r\na=rtcp-fb:* nack\r\n";
        assert_eq!(named_payload_types(answer), [0, 0, 1, 2]);
        assert!(
            with_formats(answer)
                .unwrap()
                .starts_with("m=audio 0 UDP/TLS/RTP/SAVPF 3\r\na=rtpmap:3 PCMU/8000\r\nm=video ")
        );
        // A rejected m-line last: its rtpmap closes the description.
        assert_eq!(
            with_formats(
                "m=video 9 UDP/TLS/RTP/SAVPF 96\r\nm=audio 0 UDP/TLS/RTP/SAVPF\r\na=mid:a\r\n"
            )
            .unwrap(),
            "m=video 9 UDP/TLS/RTP/SAVPF 96\r\nm=audio 0 UDP/TLS/RTP/SAVPF 0\r\na=mid:a\r\na=rtpmap:0 PCMU/8000\r\n"
        );
        // Every payload type named: none to add.
        let all: String = (0..=127_u8)
            .flat_map(|pt| [" ".to_owned(), pt.to_string()])
            .collect();
        let full = format!("m=audio 0 UDP/TLS/RTP/SAVPF\r\nm=video 9 UDP/TLS/RTP/SAVPF{all}\r\n");
        assert_eq!(
            with_formats(&full).unwrap_err(),
            "a rejected m-line without formats, and no payload type left to name on it"
        );
        // But nothing to add, nothing missing.
        assert!(with_formats(&format!("m=video 9 UDP/TLS/RTP/SAVPF{all}\r\n")).is_ok());
    }

    #[test]
    fn an_offer_of_up_to_16_kib_is_taken() {
        assert!(check_offer_size(&"a".repeat(MAX_OFFER_BYTES)).is_ok());
        assert_eq!(
            check_offer_size(&"a".repeat(MAX_OFFER_BYTES + 1)).unwrap_err(),
            "an offer of 16385 bytes, over the 16384 the relay takes"
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
