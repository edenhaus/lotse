//! One viewer session on str0m: the answer, the transports' input, the
//! state machine and the events.
//!
//! Sans-IO: the worker's session task owns it and drains [`Session::poll`]
//! after every call. Standards: RFC 8829 §5.3 (the answer; §5.3.1 its
//! directions), RFC 3264 §6 (rejected m-lines) and §6.1 (`inactive`
//! m-lines), RFC 6184 §8.2.2 (H.264 negotiation), RFC 7798 §7.1 and
//! §7.2.2 (H.265 `profile-id`, `tier-flag` and `level-id` in offer and
//! answer), RFC 9143 §9.1.1 (one
//! codec configuration per payload type, checked by [`crate::sdp`] before
//! the engine sees the offer), RFC 8838 §13 (end-of-candidates), RFC 7675
//! (consent), RFC 8837 §5 (the audio track's RTP is told apart for its
//! DSCP, by RFC 7983 §7, RFC 5761 §4 and RFC 3550 §5.1), 3GPP TS 26.114
//! §6.2.3.3 (video orientation answered only when offered, `crate::cvo`),
//! RFC 8285 §6 (`abs-capture-time` answered only when offered,
//! `crate::capture_time`), RFC 8445 §6.1.2.2 and RFC 8839 §5.1 (remote
//! candidates, offered or trickled, refused by address class),
//! draft-ietf-mmusic-mdns-ice-candidates §3.2.1 (`.local` ones ignored),
//! RFC 6347 §4.2.7 with RFC 5246 §7.2.1 (`close_notify` on close) and
//! RFC 3550 §6.6 (BYE on close) and §5.1 (the talk-back RTP header
//! fields handed on as sent).

use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use lotse_codec::h264::LIBWEBRTC_MAX_FRAME_PACKETS;
use lotse_core::codec::{Codec, CodecFamily};
use lotse_core::media::{MediaPacket, RtpHeaderFields};
use lotse_core::orientation::Orientation;
use lotse_core::session::{
    SessionEngine, SessionEvent, SessionLimits, SessionOpenError, SessionOutput, SessionRequest,
    SessionStats, Transport,
};
use lotse_core::throttle::Throttle;
use lotse_core::track::GopSnapshot;
use lotse_core::uplink::{UplinkCodec, UplinkPacket};
use str0m::change::SdpOffer;
use str0m::format::{Codec as EngineCodec, PayloadParams};
use str0m::media::{Media, MediaKind, Mid};
use str0m::net::{DatagramRecv, Protocol, Receive, TcpType, Transmit};
use str0m::rtp::RtpPacket;
use str0m::{Candidate, Event, IceConnectionState, IceCreds, Input, Output, Rtc, RtcConfig};

use crate::audio::{self, AudioPlan, Talkback};
use crate::capture_time::{CaptureTimeSender, WallAnchor};
use crate::cvo::Cvo;
use crate::sdp::{Sdp, Section, check_payload_types};
use crate::talkback::{Depacketizer, Refused};
use crate::video::{NegotiatedVideo, VideoPlan};
use crate::writer::{AudioWriter, RTX_CACHE_PACKETS, VideoWriter};
use crate::{install_crypto_provider, session_config};

/// The video RTP clock rate (RFC 6184 §8.2.1, RFC 7798 §7.1: 90 kHz).
const VIDEO_CLOCK_RATE: u32 = 90_000;

/// How long a closed session reports as its next timeout: nothing will
/// happen, the owner stops on `Closed`.
const IDLE: Duration = Duration::from_secs(3_600);

/// The most engine outputs a close takes from str0m. Its graceful close
/// queues a DTLS `close_notify` alert (RFC 6347 §4.2.7, RFC 5246 §7.2.1)
/// and an RTCP BYE per 31 send SSRCs (RFC 3550 §6.6) and hands them out
/// without time passing (str0m 0.24 `Rtc::close`), so the drain ends at
/// the engine's first timeout; the bound keeps a close from looping on an
/// engine that never gets there.
const CLOSE_OUTPUTS: usize = 64;

/// The state of a session; `Negotiating` ends inside [`Session::answer`]
/// and `Orphaned` is a signaling state the supervisor keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The answer is out with the host candidates.
    Gathering,
    /// Remote candidates or checks arrived.
    Connecting,
    /// ICE and DTLS are up.
    Connected,
    /// Consent lost; `disconnect_timeout` runs.
    Disconnected,
    /// Over.
    Closed,
}

/// The browser's name for an ICE state (`RTCIceConnectionState`).
const fn ice_name(state: IceConnectionState) -> &'static str {
    match state {
        IceConnectionState::New => "new",
        IceConnectionState::Checking => "checking",
        IceConnectionState::Connected => "connected",
        IceConnectionState::Completed => "completed",
        IceConnectionState::Disconnected => "disconnected",
    }
}

/// One session.
pub struct Session {
    /// The engine.
    rtc: Rtc,
    /// The tunables.
    limits: SessionLimits,
    /// Where the session is.
    state: State,
    /// The last ICE state name reported.
    ice: &'static str,
    /// The last DTLS state name reported.
    dtls: &'static str,
    /// The cut-through writer.
    writer: VideoWriter,
    /// Whether the answer negotiated CVO, which decides whether an
    /// orientation change reaches the browser.
    cvo: Cvo,
    /// The video the answer negotiated, which judges the stream's codec
    /// changes.
    video: NegotiatedVideo,
    /// The audio writer, when the answer carries audio.
    audio: Option<AudioWriter>,
    /// A `frame_over_browser_limit` warning went out; it goes out once per
    /// session.
    warned_over_limit: bool,
    /// The SSRC of the audio send stream, when the answer carries audio:
    /// its RTP is marked for DSCP EF.
    audio_ssrc: Option<u32>,
    /// Talk-back, when the answer receives it.
    talkback: Option<TalkbackRx>,
    /// Rate-limits the log line for RTP the viewer sent that is no
    /// talk-back.
    refused: Throttle,
    /// Outputs to serve before asking the engine.
    pending: VecDeque<SessionOutput>,
    /// When `ice_failed` fires while unconnected.
    connect_deadline: Option<Instant>,
    /// When `ice_failed` fires while consent is lost.
    disconnect_deadline: Option<Instant>,
    /// The last instant handed in.
    now: Instant,
    /// The scopes of the session's own host candidates, which let a remote
    /// candidate of the same scope pair ([`refused_address`]).
    scopes: Vec<Scope>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("state", &self.state)
            .field("ice", &self.ice)
            .field("dtls", &self.dtls)
            .field("stats", &self.writer.stats)
            .finish_non_exhaustive()
    }
}

/// The `a=mid` of the first video m-line of an SDP (RFC 8829 §5.2.1:
/// every m-line carries one), or `None`.
fn video_mid(sdp: &str) -> Option<&str> {
    first_mid(sdp, "video")
}

/// The `a=mid` of the first m-line of `kind` (`audio`, `video`) that has
/// one.
fn first_mid<'a>(sdp: &'a str, kind: &str) -> Option<&'a str> {
    Sdp::parse(sdp)
        .media()
        .iter()
        .filter(|section| section.is(kind))
        .find_map(Section::mid)
}

/// The engine configuration of a session: the stream's video codec
/// (the entries its [`VideoPlan`] lists), and the audio `codecs` in their
/// order of preference ([`AudioPlan::codecs`]).
pub(crate) fn build_config(
    request: &SessionRequest,
    video: &VideoPlan,
    codecs: &[CodecFamily],
) -> RtcConfig {
    let mut config = session_config(IceCreds {
        ufrag: request.ice.ufrag.clone(),
        pass: request.ice.pass.clone(),
    })
    .clear_codecs();
    video.configure(config.codec_config(), &request.offer);
    audio_config(config, codecs)
}

/// `offer` without its `a=candidate` lines (RFC 8839 §5.1, session level
/// or in any m-line), the text str0m answers from, and those candidates
/// without their `a=`, in order. str0m hands every candidate of an offer
/// it parses to the agent; taken out, they reach it through
/// [`Session::add_remote`], under the same policy as trickled ones.
fn split_candidates(offer: &str) -> (String, Vec<&str>) {
    let mut rest = String::with_capacity(offer.len());
    let mut candidates = Vec::new();
    for line in offer.lines() {
        match line.strip_prefix("a=") {
            Some(candidate) if candidate.starts_with("candidate:") => candidates.push(candidate),
            _ => {
                rest.push_str(line);
                rest.push_str("\r\n");
            }
        }
    }
    (rest, candidates)
}

/// The classes of address a remote candidate is refused for
/// ([`refused_address`]); any other, private, shared, public or unique
/// local, is paired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressClass {
    /// `0.0.0.0`, `::`: no one's address.
    Unspecified,
    /// `127.0.0.0/8`, `::1`: the host's own services.
    Loopback,
    /// `169.254.0.0/16`, `fe80::/10`: only the local link.
    LinkLocal,
    /// `224.0.0.0/4`, `ff00::/8`: a group, not one agent.
    Multicast,
    /// `255.255.255.255`: the local link, every host on it.
    Broadcast,
    /// `::ffff:0:0/96` (RFC 4291 §2.5.5.2), whatever IPv4 address it
    /// maps: the dual-stack socket would reach that address as IPv4.
    Ipv4Mapped,
}

impl AddressClass {
    /// The class of `ip`, `None` for an address a session pairs.
    const fn of(ip: IpAddr) -> Option<Self> {
        match ip {
            IpAddr::V4(ip) => {
                if ip.is_unspecified() {
                    Some(Self::Unspecified)
                } else if ip.is_loopback() {
                    Some(Self::Loopback)
                } else if ip.is_link_local() {
                    Some(Self::LinkLocal)
                } else if ip.is_multicast() {
                    Some(Self::Multicast)
                } else if ip.is_broadcast() {
                    Some(Self::Broadcast)
                } else {
                    None
                }
            }
            IpAddr::V6(ip) => {
                if ip.to_ipv4_mapped().is_some() {
                    Some(Self::Ipv4Mapped)
                } else if ip.is_unspecified() {
                    Some(Self::Unspecified)
                } else if ip.is_loopback() {
                    Some(Self::Loopback)
                } else if ip.is_unicast_link_local() {
                    Some(Self::LinkLocal)
                } else if ip.is_multicast() {
                    Some(Self::Multicast)
                } else {
                    None
                }
            }
        }
    }

    /// Its name, the reason a refusal logs.
    const fn name(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Ipv4Mapped => "IPv4-mapped",
        }
    }
}

/// A scope an address reaches no further than, with its family (`true`
/// for IPv4): the host (loopback) or the link (link-local).
type Scope = (AddressClass, bool);

/// The scope of `ip`, `None` when it is not loopback or link-local.
fn scope(ip: IpAddr) -> Option<Scope> {
    AddressClass::of(ip)
        .filter(|class| matches!(class, AddressClass::Loopback | AddressClass::LinkLocal))
        .map(|class| (class, ip.is_ipv4()))
}

/// Why the session refuses a remote candidate at `ip`, or `None` for one
/// it pairs.
/// The address is the browser's text, relayed by the client, and the agent sends
/// its checks to every remote candidate (RFC 8445 §6.1.2.2, §6.1.4) from
/// the daemon's socket: unfiltered, a viewer could aim them at the host's
/// own services or the local link (RFC 8445 §19.5.1). A loopback or
/// link-local candidate pairs when `scopes`, those of the session's own
/// host candidates, hold its scope, as RFC 8445 §6.1.2.2 pairs IPv6
/// link-local only with link-local; the session has a loopback host
/// candidate only when the daemon was bound to loopback explicitly, and
/// a link-local one never by default.
// SPEC-DEVIATION(RFC 8445 §6.1.2.2): unspecified, multicast, broadcast and
// IPv4-mapped remote candidates are not paired, nor are loopback and IPv4
// link-local ones without a host candidate of their scope; a conforming
// agent gathers no loopback or IPv4-mapped one (§5.1.1.1), the others name
// no one agent's transport address or reach only the link, and a
// browser's own checks still yield a peer-reflexive candidate for its real
// address (§7.3.1.3);
// gate: rfc8445_6_1_2_2_remote_candidates_of_refused_address_classes_get_no_checks
fn refused_address(ip: IpAddr, scopes: &[Scope]) -> Option<&'static str> {
    let class = AddressClass::of(ip)?;
    if scope(ip).is_some_and(|scope| scopes.contains(&scope)) {
        return None;
    }
    Some(class.name())
}

/// Whether a candidate's connection-address (the fifth field, RFC 8839
/// §5.1) is an mDNS name: one label and `.local`
/// (draft-ietf-mmusic-mdns-ice-candidates §3.2.1, step 1).
fn is_mdns(candidate: &str) -> bool {
    candidate
        .split_ascii_whitespace()
        .nth(4)
        .and_then(|address| address.split_once('.'))
        .is_some_and(|(name, domain)| !name.is_empty() && domain.eq_ignore_ascii_case("local"))
}

/// `config` with the audio `codecs` enabled in their order, which str0m
/// keeps as its order of preference; a family it does not carry is
/// skipped.
fn audio_config(config: RtcConfig, codecs: &[CodecFamily]) -> RtcConfig {
    codecs.iter().fold(config, |config, family| match family {
        CodecFamily::Opus => config.enable_opus(true, false),
        CodecFamily::Pcmu => config.enable_pcmu(true, false),
        CodecFamily::Pcma => config.enable_pcma(true, false),
        CodecFamily::G722 => config.enable_g722(true, false),
        _ => config,
    })
}

/// The answer with every media in the video's sync group: its `a=msid`
/// stream id (RFC 8830 §2; browsers synchronize the tracks of one stream)
/// and its CNAME (RFC 3550 §6.5.1; one per participant). str0m, as the
/// answerer, makes both up per media, since a browser's `recvonly`
/// m-lines name no stream, and does not let them be set, so the answer's
/// text is rewritten. The CNAME in str0m's RTCP SDES for the audio stays
/// its own; browsers group by the SDP's stream id.
fn one_sync_group(answer: &str) -> String {
    let sdp = Sdp::parse(answer);
    let video = sdp.first("video");
    let stream = video.and_then(|section| {
        section
            .attribute("msid")
            .next()
            .and_then(|msid| msid.split(' ').next())
    });
    let cname = video.and_then(|section| {
        section
            .attribute("ssrc")
            .find_map(|ssrc| ssrc.split_once(" cname:").map(|(_, cname)| cname))
    });
    let (Some(stream), Some(cname)) = (stream, cname) else {
        return answer.to_owned();
    };
    let mut out = String::with_capacity(answer.len());
    for line in answer.split_inclusive("\r\n") {
        let body = line.trim_end_matches("\r\n");
        let rewritten = if body.starts_with("a=msid-semantic:") {
            Some(format!("a=msid-semantic: WMS {stream}"))
        } else if let Some(msid) = body.strip_prefix("a=msid:") {
            msid.split_once(' ')
                .map(|(_, track)| format!("a=msid:{stream} {track}"))
        } else if body.starts_with("a=ssrc:") {
            body.split_once(" cname:")
                .map(|(ssrc, _)| format!("{ssrc} cname:{cname}"))
        } else {
            None
        };
        match rewritten {
            Some(text) => {
                out.push_str(&text);
                out.push_str("\r\n");
            }
            None => out.push_str(line),
        }
    }
    out
}

/// str0m's codec for an audio family the session cuts through.
fn audio_engine_codec(family: CodecFamily) -> Option<EngineCodec> {
    match family {
        CodecFamily::Opus => Some(EngineCodec::Opus),
        CodecFamily::Pcmu => Some(EngineCodec::PCMU),
        CodecFamily::Pcma => Some(EngineCodec::PCMA),
        CodecFamily::G722 => Some(EngineCodec::G722),
        _ => None,
    }
}

/// The audio writer for `codec` and the SSRC it sends with: the downlink
/// m-line `downlink`, if the engine accepted it with the codec's payload
/// type. str0m keeps the send stream of an m-line it rejected for lack of
/// a common codec, so a rejected one is refused here.
fn audio_writer(
    rtc: &mut Rtc,
    downlink: Option<&str>,
    codec: &Codec,
    limits: SessionLimits,
    anchor: WallAnchor,
) -> Option<(AudioWriter, u32)> {
    let engine_codec = audio_engine_codec(codec.family())?;
    let mid = downlink.map(Mid::from).filter(|mid| {
        rtc.media(*mid)
            .is_some_and(|media| media.kind() == MediaKind::Audio && !media.disabled())
    })?;
    let pt = rtc
        .codec_config()
        .params()
        .iter()
        .find(|params| params.spec().codec == engine_codec)
        .map(PayloadParams::pt)?;
    let ssrc = *rtc.direct_api().stream_tx_by_mid(mid, None)?.ssrc();
    tracing::info!(mid = %mid, pt = *pt, ssrc, codec = codec.name(), "session answered with audio");
    let clock_rate = audio::clock_rate(codec.family());
    let capture_time = CaptureTimeSender::negotiate(rtc, mid, "audio", clock_rate, anchor);
    Some((
        AudioWriter::new(pt, mid, clock_rate, limits).with_capture_time(capture_time),
        ssrc,
    ))
}

/// Talk-back as the session receives it: the m-line it comes on and how
/// its packets are taken.
#[derive(Debug)]
struct TalkbackRx {
    /// The talk-back m-line: the dedicated one, or the `sendrecv`
    /// downlink one.
    mid: Mid,
    /// Takes its RTP by payload type.
    depacketizer: Depacketizer,
    /// The codec the answer named first on the m-line, which the browser
    /// sends.
    negotiated: UplinkCodec,
    /// The codec of the last packet handed on, `None` before the first:
    /// the start of talk-back and a change of codec are logged.
    codec: Option<UplinkCodec>,
}

impl TalkbackRx {
    /// The talk-back packet of an RTP packet the engine mapped to the
    /// m-line `mid`, with header fields `rtp` and `payload`, received at
    /// `arrival`; or why it is none. Logs the start of talk-back and a
    /// change of codec.
    fn take(
        &mut self,
        mid: Option<Mid>,
        rtp: RtpHeaderFields,
        payload: std::sync::Arc<[u8]>,
        arrival: Instant,
    ) -> Result<UplinkPacket, &'static str> {
        if mid != Some(self.mid) {
            return Err("not on the talk-back m-line");
        }
        let uplink = self
            .depacketizer
            .depacketize(rtp, payload, arrival)
            .map_err(Refused::reason)?;
        let codec = uplink.codec.name();
        let (pt, ssrc) = (rtp.pt, rtp.ssrc);
        match self.codec.replace(uplink.codec) {
            None => tracing::info!(mid = %self.mid, pt, ssrc, codec, "talk-back uplink started"),
            Some(old) if old == uplink.codec => {}
            Some(old) => {
                let from = old.name();
                tracing::info!(mid = %self.mid, pt, ssrc, from, to = codec, "talk-back uplink changed codec");
            }
        }
        Ok(uplink)
    }
}

/// The audio family of one of str0m's codecs, the reverse of
/// [`audio_engine_codec`].
fn engine_family(codec: EngineCodec) -> Option<CodecFamily> {
    match codec {
        EngineCodec::Opus => Some(CodecFamily::Opus),
        EngineCodec::PCMU => Some(CodecFamily::Pcmu),
        EngineCodec::PCMA => Some(CodecFamily::Pcma),
        EngineCodec::G722 => Some(CodecFamily::G722),
        _ => None,
    }
}

/// How the session receives talk-back on the m-line `mid` the plan
/// negotiated it on: by the payload types the engine settled on with the
/// offer (str0m takes the offer's numbers), every talk-back codec among
/// them, since the browser may send any codec the m-line lists.
/// `codec` is the one the answer named first; the plan negotiates
/// talk-back codecs only, so it is always one, and `None` never comes.
fn talkback_rx(rtc: &Rtc, mid: &str, codec: CodecFamily) -> Option<TalkbackRx> {
    let negotiated = UplinkCodec::of(codec)?;
    let params = rtc
        .codec_config()
        .params()
        .iter()
        .filter_map(|params| Some((*params.pt(), engine_family(params.spec().codec)?)));
    Some(TalkbackRx {
        mid: Mid::from(mid),
        depacketizer: Depacketizer::new(params),
        negotiated,
        codec: None,
    })
}

/// Whether `datagram`, as the engine sends it, is an RTP packet of the
/// SSRC `audio`: a first byte in 128 to 191 is RTP or RTCP (RFC 7983 §7),
/// a second byte in 192 to 223 RTCP (RFC 5761 §4), and the SSRC follows
/// the timestamp in the clear (RFC 3550 §5.1, RFC 3711 §3.1). RTCP, STUN
/// and DTLS keep the socket's marking.
fn is_audio_rtp(datagram: &[u8], audio: Option<u32>) -> bool {
    let Some(audio) = audio else {
        return false;
    };
    let rtp =
        matches!(datagram.first(), Some(128..=191)) && !matches!(datagram.get(1), Some(192..=223));
    rtp && datagram
        .get(8..12)
        .and_then(|ssrc| <[u8; 4]>::try_from(ssrc).ok())
        .is_some_and(|ssrc| u32::from_be_bytes(ssrc) == audio)
}

/// Whether the answer rejected the m-line with mid `mid` (port 0,
/// RFC 3264 §6) rather than answering it, which str0m does when it lists
/// no codec the engine knows.
fn rejected(rtc: &Rtc, mid: &str) -> bool {
    rtc.media(Mid::from(mid)).is_none_or(Media::disabled)
}

/// The session sends no audio: warns when the stream has audio
/// (`audio_codec_unsupported`) and logs what the answer did with the
/// offer's downlink audio m-line.
fn no_audio(
    rtc: &Rtc,
    request: &SessionRequest,
    plan: &AudioPlan<'_>,
    pending: &mut VecDeque<SessionOutput>,
) {
    if let Some(codec) = request.audio.as_deref() {
        let message = if audio_engine_codec(codec.family()).is_some() {
            format!(
                "the offer has no audio m-line that takes {}; video only",
                codec.name()
            )
        } else {
            format!(
                "stream audio is {}; the audio m-line is answered inactive",
                codec.name()
            )
        };
        pending.push_back(SessionOutput::Event(SessionEvent::Warning {
            code: "audio_codec_unsupported",
            message,
        }));
    }
    let reason = if request.audio.is_some() {
        "no audio codec in common"
    } else {
        "no stream audio requested"
    };
    if let Some(mid) = plan.downlink {
        if rejected(rtc, mid) {
            tracing::info!(
                mid,
                reason,
                "audio m-line rejected: no codec in common with the engine"
            );
        } else {
            let answered = plan.answer(Some(mid)).attribute();
            tracing::info!(
                mid,
                reason,
                answered,
                "audio m-line carries no stream audio"
            );
        }
    }
}

/// Queues what a session reports as it opens: its host `candidates` on
/// the video m-line `mid`, end-of-candidates (an empty candidate without a
/// mid) and the first state.
fn push_opening_events(pending: &mut VecDeque<SessionOutput>, candidates: Vec<String>, mid: Mid) {
    for candidate in candidates {
        pending.push_back(SessionOutput::Event(SessionEvent::Candidate {
            candidate,
            mid: Some(mid.to_string()),
        }));
    }
    pending.push_back(SessionOutput::Event(SessionEvent::Candidate {
        candidate: String::new(),
        mid: None,
    }));
    pending.push_back(SessionOutput::Event(SessionEvent::State {
        ice: "new",
        dtls: "new",
    }));
}

/// Logs what the answer did with talk-back: the m-line and codec it is
/// received in, or why it is not.
fn log_talkback(plan: &AudioPlan<'_>, backchannel: Option<&Codec>) {
    match plan.talkback {
        Talkback::Negotiated {
            mid,
            codec,
            dedicated,
        } => {
            let m_line = if dedicated { "dedicated" } else { "sendrecv" };
            let backchannel = backchannel.map(Codec::name);
            let codec = codec.name();
            tracing::info!(mid, codec, backchannel, m_line, "talk-back negotiated");
        }
        Talkback::Off(reason) => tracing::info!(reason, "talk-back not negotiated"),
    }
}

impl Session {
    /// The first frame the writer sent over the libwebrtc packet limit
    /// becomes the session's one `frame_over_browser_limit` warning, with
    /// the advice a client can show; the session's stats count every one. The
    /// frame went out whole all the same.
    fn warn_over_limit(&mut self) {
        let Some(frame) = self.writer.take_over_limit() else {
            return;
        };
        if self.warned_over_limit {
            return;
        }
        self.warned_over_limit = true;
        let codec = self.video.name();
        tracing::info!(
            codec,
            packets = frame.packets,
            bytes = frame.bytes,
            limit = LIBWEBRTC_MAX_FRAME_PACKETS,
            "warning frame_over_browser_limit"
        );
        self.pending
            .push_back(SessionOutput::Event(SessionEvent::Warning {
                code: "frame_over_browser_limit",
                message: format!(
                    "a {codec} frame needed {} RTP packets ({} bytes), more than some libwebrtc \
                     receivers (Chrome, Edge, Safari, apps' web views, depending on version) \
                     assemble ({LIBWEBRTC_MAX_FRAME_PACKETS}); it was sent whole, and those viewers may \
                     freeze until a keyframe that fits. Lower the camera's bitrate or use its \
                     substream",
                    frame.packets, frame.bytes
                ),
            }));
    }

    /// Answers `request.offer`: the session and its SDP answer, or why
    /// there is none. Emits the host candidates, end-of-candidates and the
    /// first state.
    pub fn answer(
        request: &SessionRequest,
        now: Instant,
    ) -> Result<(Self, String), SessionOpenError> {
        install_crypto_provider();
        // The audio m-lines: the stream's audio down on the first the
        // browser receives on, when it lists its codec; talk-back up on
        // the dedicated or `sendrecv` one when the stream has a
        // backchannel; every other one `inactive`.
        let plan = AudioPlan::new(
            &request.offer,
            request.audio.as_deref(),
            request.backchannel.as_ref(),
        );
        let send = request
            .audio
            .as_deref()
            .filter(|codec| plan.send == Some(codec.family()));
        let directed = plan.engine_offer(&request.offer);
        // The offer's candidates pass the same policy as trickled ones,
        // after the answer; str0m would add every one it parses.
        let (rewritten, offered) = split_candidates(&directed);
        let offer = SdpOffer::from_sdp_string(&rewritten)
            .map_err(|err| SessionOpenError::InvalidSdp(err.to_string()))?;
        // Before the engine sees it: str0m 0.24 panics on a payload type
        // with two codec configurations, which would abort the worker.
        check_payload_types(&rewritten).map_err(|reason| {
            tracing::debug!(reason, "offer refused: payload types conflict");
            SessionOpenError::InvalidSdp(reason)
        })?;
        let video = VideoPlan::for_codec(&request.video)?;

        let mut pending = VecDeque::new();
        let mut rtc = build_config(request, &video, &plan.codecs()).build(now);

        let (candidates, scopes) = add_host_candidates(&mut rtc, request);
        let answer = rtc
            .sdp_api()
            .accept_offer(offer)
            .map_err(|err| SessionOpenError::InvalidSdp(err.to_string()))?;

        // The video m-line: str0m reports `MediaAdded` only once SRTP is
        // up, so the mid comes from the offer itself.
        let mid = video_mid(&request.offer)
            .map(Mid::from)
            .filter(|mid| {
                rtc.media(*mid)
                    .is_some_and(|media| media.kind() == MediaKind::Video)
            })
            .ok_or(SessionOpenError::NoVideoTrack)?;
        let negotiated = video.negotiate(&rtc, &request.offer, &mut pending)?;
        let pt = negotiated.pt();
        let (cvo, orientation) = Cvo::negotiate(&rtc, mid, request.orientation);
        let anchor = WallAnchor::new(now, request.wall);
        let capture_time =
            CaptureTimeSender::negotiate(&rtc, mid, "video", VIDEO_CLOCK_RATE, anchor);
        {
            let mut api = rtc.direct_api();
            let Some(stream) = api.stream_tx_by_mid(mid, None) else {
                return Err(SessionOpenError::InvalidSdp(
                    "the answer declared no send stream for the video m-line".to_owned(),
                ));
            };
            stream.set_rtx_cache(RTX_CACHE_PACKETS, request.limits.max_packet_age, None);
        }

        let (audio, audio_ssrc) = send
            .and_then(|codec| audio_writer(&mut rtc, plan.downlink, codec, request.limits, anchor))
            .unzip();
        if audio.is_none() {
            no_audio(&rtc, request, &plan, &mut pending);
        }
        log_talkback(&plan, request.backchannel.as_ref());
        let talkback = match plan.talkback {
            Talkback::Negotiated { mid, codec, .. } => talkback_rx(&rtc, mid, codec),
            Talkback::Off(_) => None,
        };

        push_opening_events(&mut pending, candidates, mid);
        tracing::info!(mid = %mid, pt = *pt, "session answered");
        let mut session = Self {
            rtc,
            limits: request.limits,
            state: State::Gathering,
            ice: "new",
            dtls: "new",
            // `playout-delay` caps every delay the browser adds to video,
            // its lip-sync hold included (Chrome and Safari, 2026-10-01:
            // audio 113–156 ms behind video with it, in sync without), so
            // only a session without audio asks for render-on-decode.
            writer: VideoWriter::new(
                pt,
                mid,
                negotiated.packetizer(),
                request.limits,
                audio.is_none(),
                orientation,
            )
            .with_capture_time(capture_time),
            cvo,
            video: negotiated,
            audio,
            warned_over_limit: false,
            audio_ssrc,
            talkback,
            refused: Throttle::default(),
            pending,
            connect_deadline: Some(
                now.checked_add(request.limits.connect_timeout)
                    .unwrap_or(now),
            ),
            disconnect_deadline: None,
            now,
            scopes,
        };
        for line in offered {
            session.add_remote(line);
        }
        Ok((session, one_sync_group(&answer.to_sdp_string())))
    }

    /// Where the session is.
    pub const fn state(&self) -> State {
        self.state
    }

    /// Feeds the engine and closes on its errors.
    fn input(&mut self, input: Input<'_>) {
        if self.state == State::Closed {
            return;
        }
        if let Err(err) = self.rtc.handle_input(input) {
            self.close(self.now, "internal_error", format!("engine: {err}"));
        }
    }

    /// Emits a state event and remembers it.
    fn report_state(&mut self, ice: &'static str, dtls: &'static str) {
        self.ice = ice;
        self.dtls = dtls;
        self.pending
            .push_back(SessionOutput::Event(SessionEvent::State { ice, dtls }));
    }

    /// An engine event.
    fn on_event(&mut self, event: &Event) {
        match event {
            Event::Connected => {
                tracing::info!("session connected");
                self.state = State::Connected;
                self.connect_deadline = None;
                self.disconnect_deadline = None;
                self.report_state("connected", "connected");
                self.pending
                    .push_back(SessionOutput::Event(SessionEvent::Connected));
            }
            Event::IceConnectionStateChange(ice) => {
                let ice = *ice;
                match ice {
                    IceConnectionState::Disconnected if self.state == State::Connected => {
                        tracing::warn!("consent lost");
                        self.state = State::Disconnected;
                        self.disconnect_deadline =
                            self.now.checked_add(self.limits.disconnect_timeout);
                    }
                    // `Connected` or `Completed`, in one guard: the or-pattern
                    // with a guard counts no coverage for its guard (rustc
                    // 1.98, observed 2026-10-10).
                    _ if ice.is_connected() && self.state == State::Disconnected => {
                        tracing::info!("consent regained");
                        self.state = State::Connected;
                        self.disconnect_deadline = None;
                    }
                    IceConnectionState::Checking if self.state == State::Gathering => {
                        self.state = State::Connecting;
                    }
                    _ => {}
                }
                let dtls = if self.state == State::Connected || self.state == State::Disconnected {
                    "connected"
                } else if ice.is_connected() {
                    "connecting"
                } else {
                    self.dtls
                };
                self.report_state(ice_name(ice), dtls);
            }
            Event::KeyframeRequest(request) => {
                tracing::debug!(kind = ?request.kind, "viewer asked for a keyframe");
                self.writer.stats.keyframe_requests =
                    self.writer.stats.keyframe_requests.saturating_add(1);
                self.pending
                    .push_back(SessionOutput::Event(SessionEvent::KeyframeRequest));
            }
            _ => {}
        }
    }

    /// Hands one remote candidate (`candidate:` and the RFC 8839 §5.1
    /// grammar), offered or trickled, to the agent unless the policy of
    /// [`refused_address`] refuses it; whether the agent got it. An mDNS
    /// candidate is ignored quietly
    /// (draft-ietf-mmusic-mdns-ice-candidates §3.2.1, step 5 without a
    /// resolver); any other that does not parse is an `invalid_candidate`
    /// warning.
    fn add_remote(&mut self, line: &str) -> bool {
        match Candidate::from_sdp_string(line) {
            Ok(candidate) => {
                let addr = candidate.addr();
                if let Some(reason) = refused_address(addr.ip(), &self.scopes) {
                    // At most 64 per session (the supervisor's cap), so the
                    // log needs no rate limit.
                    tracing::debug!(kind = ?candidate.kind(), %addr, reason, "remote candidate refused");
                    return false;
                }
                tracing::debug!(kind = ?candidate.kind(), %addr, "remote candidate");
                self.rtc.add_remote_candidate(candidate);
                true
            }
            Err(_) if is_mdns(line) => {
                tracing::debug!("remote mDNS candidate ignored");
                false
            }
            Err(err) => {
                tracing::debug!(error = %err, "remote candidate ignored");
                self.pending
                    .push_back(SessionOutput::Event(SessionEvent::Warning {
                        code: "invalid_candidate",
                        message: err.to_string(),
                    }));
                false
            }
        }
    }

    /// An RTP packet the viewer sent: a talk-back packet when it came on
    /// the talk-back m-line in a talk-back codec, handed on as
    /// [`SessionOutput::Uplink`] and counted; anything else is refused,
    /// counted and logged, rate-limited. The m-line is the one str0m
    /// mapped the packet's SSRC to (by `a=ssrc` or the RFC 8843 `mid`
    /// header extension), which it does without regard to direction.
    fn on_rtp(&mut self, packet: RtpPacket) {
        let ssrc = *packet.header.ssrc;
        let mid = self
            .rtc
            .direct_api()
            .stream_rx(&packet.header.ssrc)
            .map(|stream| stream.mid());
        let rtp = RtpHeaderFields {
            pt: *packet.header.payload_type,
            seq: packet.header.sequence_number,
            ts: packet.header.timestamp,
            marker: packet.header.marker,
            ssrc,
        };
        let taken = match self.talkback.as_mut() {
            Some(talkback) => talkback.take(mid, rtp, packet.payload, packet.timestamp),
            None => Err("talk-back not negotiated"),
        };
        let stats = &mut self.writer.stats;
        match taken {
            Ok(uplink) => {
                stats.uplink_packets = stats.uplink_packets.saturating_add(1);
                self.pending.push_back(SessionOutput::Uplink(uplink));
            }
            Err(reason) => {
                stats.uplink_refused = stats.uplink_refused.saturating_add(1);
                if let Some(count) = self.refused.hit(self.now) {
                    let mid = mid.map(|mid| mid.to_string());
                    tracing::debug!(reason, count, pt = rtp.pt, ssrc, mid, "viewer RTP refused");
                }
            }
        }
    }

    /// What the session hands the worker for one of the engine's
    /// datagrams.
    fn transmit(&self, transmit: Transmit) -> SessionOutput {
        SessionOutput::Transmit {
            // Host and relay candidates are UDP, the passive ones TCP; the
            // worker relays what leaves a relay candidate, which `source`
            // names.
            transport: if transmit.proto == Protocol::Udp {
                Transport::Udp
            } else {
                Transport::Tcp
            },
            source: transmit.source,
            destination: transmit.destination,
            audio: is_audio_rtp(&transmit.contents, self.audio_ssrc),
            payload: Vec::from(transmit.contents),
        }
    }

    /// Closes the engine gracefully and queues what that sends ahead of
    /// the `closed` event: the DTLS `close_notify` alert (RFC 6347 §4.2.7,
    /// RFC 5246 §7.2.1) and an RTCP BYE for the session's send SSRCs
    /// (RFC 3550 §6.6), so the browser ends the stream at once instead of
    /// after its consent check fails. Never waits: the drain stops at the
    /// engine's first timeout or error and after [`CLOSE_OUTPUTS`], and
    /// the worker's sends do not block, so neither a silent peer nor a
    /// stuck transmit path holds the close up. Then the engine is dropped
    /// to inert. Events the engine still had are not reported.
    fn drain_close(&mut self) {
        let started = self.rtc.close();
        let mut sent: usize = 0;
        for _ in 0..CLOSE_OUTPUTS {
            match self.rtc.poll_output() {
                Ok(Output::Transmit(transmit)) => {
                    sent = sent.saturating_add(1);
                    let output = self.transmit(transmit);
                    self.pending.push_back(output);
                }
                // A closed session reports nothing more of the engine's.
                Ok(Output::Event(_)) => {}
                Ok(Output::Timeout(_)) | Err(_) => break,
            }
        }
        // `false` when str0m kept close output it had no way to send.
        let drained = !self.rtc.is_alive();
        tracing::debug!(close = ?started, sent, drained, "close output queued");
        self.rtc.disconnect();
    }

    /// The earliest of the engine's timeout and the session's deadlines.
    fn next_timeout(&self, engine: Instant) -> Instant {
        [self.connect_deadline, self.disconnect_deadline]
            .into_iter()
            .flatten()
            .fold(engine, Instant::min)
    }
}

/// Adds the host candidates to `rtc` and returns their `candidate` lines:
/// UDP first, then the passive ICE-TCP ones (RFC 6544 §4.5); the engine's
/// priorities put UDP ahead either way. Also the scopes of those the
/// engine took ([`scope`]).
fn add_host_candidates(rtc: &mut Rtc, request: &SessionRequest) -> (Vec<String>, Vec<Scope>) {
    let udp = request
        .candidates
        .iter()
        .map(|addr| (*addr, Candidate::host(*addr, "udp")));
    let tcp = request.tcp_candidates.iter().map(|addr| {
        (
            *addr,
            Candidate::builder()
                .tcp()
                .host(*addr)
                .tcptype(TcpType::Passive)
                .build(),
        )
    });
    let mut lines = Vec::new();
    let mut scopes = Vec::new();
    for (addr, candidate) in udp.chain(tcp) {
        match candidate {
            Ok(candidate) => {
                if let Some(added) = rtc.add_local_candidate(candidate) {
                    lines.push(added.to_sdp_string());
                    scopes.extend(scope(added.addr().ip()));
                }
            }
            Err(err) => tracing::warn!(%addr, error = %err, "host candidate refused"),
        }
    }
    (lines, scopes)
}

impl SessionEngine for Session {
    fn handle_datagram(
        &mut self,
        now: Instant,
        transport: Transport,
        source: SocketAddr,
        destination: SocketAddr,
        bytes: &[u8],
    ) {
        self.now = now;
        let Ok(contents) = DatagramRecv::try_from(bytes) else {
            self.writer.stats.bad_datagrams = self.writer.stats.bad_datagrams.saturating_add(1);
            return;
        };
        if self.state == State::Gathering {
            self.state = State::Connecting;
        }
        self.input(Input::Receive(
            now,
            Receive {
                proto: match transport {
                    Transport::Udp => Protocol::Udp,
                    Transport::Tcp => Protocol::Tcp,
                },
                source,
                destination,
                contents,
            },
        ));
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        if let Some(deadline) = self.connect_deadline
            && now >= deadline
            && matches!(self.state, State::Gathering | State::Connecting)
        {
            let secs = self.limits.connect_timeout.as_secs();
            self.close(now, "ice_failed", format!("no connection within {secs} s"));
            return;
        }
        if let Some(deadline) = self.disconnect_deadline
            && now >= deadline
            && self.state == State::Disconnected
        {
            let secs = self.limits.disconnect_timeout.as_secs();
            self.close(now, "ice_failed", format!("consent lost for {secs} s"));
            return;
        }
        self.input(Input::Timeout(now));
    }

    fn add_remote_candidate(&mut self, now: Instant, candidate: &str) {
        self.now = now;
        if self.state == State::Closed {
            return;
        }
        if candidate.is_empty() {
            tracing::debug!("end of remote candidates");
            return;
        }
        if self.add_remote(candidate) && self.state == State::Gathering {
            self.state = State::Connecting;
        }
    }

    fn add_relay_candidate(
        &mut self,
        now: Instant,
        relayed: SocketAddr,
        local: SocketAddr,
    ) -> Option<String> {
        self.now = now;
        if self.state == State::Closed {
            return None;
        }
        let candidate = match Candidate::relayed(relayed, local, "udp") {
            Ok(candidate) => candidate,
            Err(err) => {
                tracing::warn!(%relayed, error = %err, "relay candidate refused");
                return None;
            }
        };
        // The agent refuses one it holds already (RFC 8445 §5.1.3).
        let Some(added) = self.rtc.add_local_candidate(candidate) else {
            tracing::debug!(%relayed, "relay candidate redundant");
            return None;
        };
        let line = added.to_sdp_string();
        tracing::info!(%relayed, %local, "relay candidate added");
        Some(line)
    }

    fn join(&mut self, now: Instant, gop: Option<&GopSnapshot>) {
        self.now = now;
        if !matches!(self.state, State::Connected | State::Disconnected) {
            return;
        }
        if self.writer.join(&mut self.rtc, now, gop) {
            self.pending
                .push_back(SessionOutput::Event(SessionEvent::KeyframeRequest));
        }
        self.warn_over_limit();
    }

    fn write_video(&mut self, now: Instant, packet: &MediaPacket, wallclock: Instant) {
        self.now = now;
        if !matches!(self.state, State::Connected | State::Disconnected) {
            self.writer.stats.dropped_waiting = self.writer.stats.dropped_waiting.saturating_add(1);
            return;
        }
        if self.writer.write(&mut self.rtc, now, packet, wallclock) {
            self.pending
                .push_back(SessionOutput::Event(SessionEvent::KeyframeRequest));
        }
        self.warn_over_limit();
    }

    fn write_audio(&mut self, now: Instant, packet: &MediaPacket, wallclock: Instant) {
        self.now = now;
        let stats = &mut self.writer.stats;
        let written = match self.audio.as_mut() {
            Some(audio) if matches!(self.state, State::Connected | State::Disconnected) => {
                audio.write(&mut self.rtc, now, packet, wallclock)
            }
            _ => false,
        };
        if written {
            stats.audio_packets = stats.audio_packets.saturating_add(1);
            let len = u64::try_from(packet.payload.len()).unwrap_or(u64::MAX);
            stats.audio_bytes = stats.audio_bytes.saturating_add(len);
        } else {
            stats.audio_dropped = stats.audio_dropped.saturating_add(1);
        }
    }

    /// The rule that chose the payload type, applied to the new codec
    /// (`NegotiatedVideo::check_change`).
    fn check_video_change(&self, codec: &Codec) -> Result<(), String> {
        self.video.check_change(codec)
    }

    fn skip_to_keyframe(&mut self, reason: &'static str) {
        self.writer.skip(reason);
    }

    /// The browser turns each frame by the CVO on its last packet
    /// (`crate::cvo`), so the change needs neither a keyframe nor a new
    /// answer; without CVO negotiated nothing changes.
    fn set_orientation(&mut self, orientation: Orientation) {
        self.writer.set_orientation(self.cvo.change(orientation));
    }

    fn close(&mut self, now: Instant, code: &'static str, message: String) {
        self.now = now;
        if self.state == State::Closed {
            return;
        }
        tracing::info!(code, message, "session closed");
        self.state = State::Closed;
        self.connect_deadline = None;
        self.disconnect_deadline = None;
        self.drain_close();
        self.report_state("closed", "closed");
        self.pending
            .push_back(SessionOutput::Event(SessionEvent::Closed { code, message }));
    }

    fn poll(&mut self) -> SessionOutput {
        loop {
            if let Some(output) = self.pending.pop_front() {
                return output;
            }
            if self.state == State::Closed {
                return SessionOutput::Timeout(self.now.checked_add(IDLE).unwrap_or(self.now));
            }
            match self.rtc.poll_output() {
                Ok(Output::Timeout(at)) => {
                    if !self.rtc.is_alive() {
                        self.close(self.now, "peer_closed", "the transport closed".to_owned());
                        continue;
                    }
                    return SessionOutput::Timeout(self.next_timeout(at));
                }
                Ok(Output::Transmit(transmit)) => return self.transmit(transmit),
                Ok(Output::Event(Event::RtpPacket(packet))) => self.on_rtp(packet),
                Ok(Output::Event(event)) => self.on_event(&event),
                Err(err) => self.close(self.now, "internal_error", format!("engine: {err}")),
            }
        }
    }

    fn stats(&self) -> SessionStats {
        self.writer.stats
    }

    fn talkback(&self) -> Option<UplinkCodec> {
        self.talkback.as_ref().map(|talkback| talkback.negotiated)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    /// A 12-byte header with first byte `v`, second byte `pt` and SSRC
    /// `ssrc`.
    fn header(v: u8, pt: u8, ssrc: u32) -> Vec<u8> {
        let mut bytes = vec![v, pt, 0, 1, 0, 0, 0, 2];
        bytes.extend_from_slice(&ssrc.to_be_bytes());
        bytes
    }

    #[test]
    fn rfc8837_5_only_rtp_of_the_audio_ssrc_is_audio_by_rfc7983_7_and_rfc5761_4() {
        let audio = Some(0x0102_0304);
        // RTP version 2 with any first-byte flags, payload types either
        // side of the RTCP range.
        for (v, pt) in [(128, 0), (191, 0), (128, 191), (144, 224), (128, 127)] {
            assert!(is_audio_rtp(&header(v, pt, 0x0102_0304), audio), "{v} {pt}");
        }
        // The video's SSRC, no audio, RTCP (even with the audio SSRC where
        // RTP carries it), STUN, DTLS and cut headers.
        assert!(!is_audio_rtp(&header(128, 96, 0x0102_0305), audio));
        assert!(!is_audio_rtp(&header(128, 0, 0x0102_0304), None));
        for pt in [192, 200, 223] {
            assert!(!is_audio_rtp(&header(128, pt, 0x0102_0304), audio), "{pt}");
        }
        for v in [0, 3, 20, 63, 127, 192] {
            assert!(!is_audio_rtp(&header(v, 0, 0x0102_0304), audio), "{v}");
        }
        assert!(!is_audio_rtp(&header(128, 0, 0x0102_0304)[..11], audio));
        assert!(!is_audio_rtp(&[128], audio));
        assert!(!is_audio_rtp(&[], audio));
    }

    #[test]
    fn rfc8830_2_every_media_joins_the_video_sync_group() {
        let answer = "v=0\r\na=msid-semantic: WMS audiostream videostream\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=msid:audiostream atrack\r\na=ssrc:1 cname:audiocname\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=msid:videostream vtrack\r\na=ssrc:2 cname:videocname\r\na=ssrc:3 cname:videocname\r\n";
        assert_eq!(
            one_sync_group(answer),
            "v=0\r\na=msid-semantic: WMS videostream\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=msid:videostream atrack\r\na=ssrc:1 cname:videocname\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=msid:videostream vtrack\r\na=ssrc:2 cname:videocname\r\na=ssrc:3 cname:videocname\r\n"
        );
        // Without a video stream id or CNAME there is nothing to join.
        let audio_only = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=msid:s t\r\n";
        assert_eq!(one_sync_group(audio_only), audio_only);
        let no_cname = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=msid:s t\r\n";
        assert_eq!(one_sync_group(no_cname), no_cname);
    }

    #[test]
    fn rfc8839_5_1_the_offer_reaches_the_engine_without_its_candidates() {
        let offer = "v=0\r\na=candidate:0 1 udp 1 192.0.2.1 1 typ host\r\nm=video 9 x 96\r\na=mid:v\r\na=candidate:1 1 udp 1 192.0.2.2 2 typ host\na=candidates:x\r\na=end-of-candidates\r\n";
        let (rest, candidates) = split_candidates(offer);
        assert_eq!(
            rest,
            "v=0\r\nm=video 9 x 96\r\na=mid:v\r\na=candidates:x\r\na=end-of-candidates\r\n"
        );
        assert_eq!(
            candidates,
            [
                "candidate:0 1 udp 1 192.0.2.1 1 typ host",
                "candidate:1 1 udp 1 192.0.2.2 2 typ host"
            ]
        );
    }

    #[test]
    fn rfc8445_6_1_2_2_remote_addresses_by_class() {
        for (ip, reason) in [
            ("0.0.0.0", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("127.1.2.3", "loopback"),
            ("169.254.1.1", "link-local"),
            ("224.0.0.251", "multicast"),
            ("239.255.255.250", "multicast"),
            ("255.255.255.255", "broadcast"),
            ("::", "unspecified"),
            ("::1", "loopback"),
            ("fe80::1", "link-local"),
            ("febf::1", "link-local"),
            ("ff02::fb", "multicast"),
            ("ff0e::1", "multicast"),
            ("::ffff:127.0.0.1", "IPv4-mapped"),
            ("::ffff:192.168.1.20", "IPv4-mapped"),
        ] {
            assert_eq!(
                refused_address(ip.parse().unwrap(), &[]),
                Some(reason),
                "{ip}"
            );
        }
        // Private, shared, public and unique local addresses are paired,
        // as RFC 8828 §5.2 has a browser offer them.
        for ip in [
            "10.0.0.20",
            "172.16.0.20",
            "192.168.1.20",
            "100.64.0.20",
            "203.0.113.20",
            "8.8.8.8",
            "192.168.1.255",
            "2001:db8::20",
            "fd00::20",
            "fec0::20",
            "2a00:1450::1",
        ] {
            assert_eq!(refused_address(ip.parse().unwrap(), &[]), None, "{ip}");
        }
    }

    #[test]
    fn rfc8445_6_1_2_2_loopback_and_link_local_pair_within_a_host_candidates_scope() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(scope(ip("127.0.0.2")), Some((AddressClass::Loopback, true)));
        assert_eq!(scope(ip("::1")), Some((AddressClass::Loopback, false)));
        assert_eq!(
            scope(ip("169.254.1.1")),
            Some((AddressClass::LinkLocal, true))
        );
        assert_eq!(scope(ip("fe80::1")), Some((AddressClass::LinkLocal, false)));
        for other in [
            "0.0.0.0",
            "224.0.0.251",
            "255.255.255.255",
            "::ffff:127.0.0.1",
            "192.168.1.20",
        ] {
            assert_eq!(scope(ip(other)), None, "{other}");
        }
        // A daemon bound to IPv4 loopback pairs IPv4 loopback alone.
        let loopback = [(AddressClass::Loopback, true)];
        assert_eq!(refused_address(ip("127.0.0.1"), &loopback), None);
        assert_eq!(refused_address(ip("::1"), &loopback), Some("loopback"));
        assert_eq!(
            refused_address(ip("169.254.1.1"), &loopback),
            Some("link-local")
        );
        assert_eq!(
            refused_address(ip("0.0.0.0"), &loopback),
            Some("unspecified")
        );
        assert_eq!(
            refused_address(ip("::ffff:127.0.0.1"), &loopback),
            Some("IPv4-mapped")
        );
        // An IPv6 link-local host candidate pairs IPv6 link-local
        // (RFC 8445 §6.1.2.2).
        let link = [(AddressClass::LinkLocal, false)];
        assert_eq!(refused_address(ip("fe80::1"), &link), None);
        assert_eq!(
            refused_address(ip("169.254.1.1"), &link),
            Some("link-local")
        );
        assert_eq!(refused_address(ip("::1"), &link), Some("loopback"));
    }

    #[test]
    fn mdns_ice_candidates_3_2_1_a_local_name_is_one_label_and_local() {
        for candidate in [
            "candidate:1 1 udp 2122260223 4f2c1a3e-5b6d-4e7f-8a9b-0c1d2e3f4a5b.local 50000 typ host",
            "candidate:1 1 UDP 2122260223 host.LOCAL 50000 typ host",
        ] {
            assert!(is_mdns(candidate), "{candidate}");
        }
        for candidate in [
            "candidate:1 1 udp 2122260223 192.168.1.20 50000 typ host",
            "candidate:1 1 udp 2122260223 a.b.local 50000 typ host",
            "candidate:1 1 udp 2122260223 .local 50000 typ host",
            "candidate:1 1 udp 2122260223 host.localdomain 50000 typ host",
            "candidate:1 1 udp 2122260223",
            "candidate:1 1 udp x.local",
        ] {
            assert!(!is_mdns(candidate), "{candidate}");
        }
    }

    #[test]
    fn rfc3264_6_a_media_without_a_common_codec_is_rejected() {
        use lotse_core::clock::{Clock as _, SystemClock};
        use lotse_core::session::IceCredentials;

        let now = SystemClock.now();
        install_crypto_provider();
        let viewer =
            lotse_testing::Viewer::new_with_audio("192.0.2.20:40000".parse().unwrap(), now)
                .unwrap();
        let audio_mid = first_mid(viewer.offer(), "audio").unwrap().to_owned();
        let answer = |offer: &str, codecs: &[CodecFamily]| {
            let request = SessionRequest {
                offer: offer.to_owned(),
                ice: IceCredentials {
                    ufrag: "ufrag".into(),
                    pass: "passwordpasswordpassword".into(),
                },
                candidates: vec![],
                tcp_candidates: vec![],
                video: std::sync::Arc::new(Codec::H264 {
                    profile_level_id: None,
                    sps: None,
                    pps: None,
                }),
                audio: None,
                backchannel: None,
                orientation: Orientation::default(),
                limits: SessionLimits::default(),
                wall: std::time::SystemTime::UNIX_EPOCH,
            };
            let video = VideoPlan::for_codec(&request.video).unwrap();
            let mut rtc = build_config(&request, &video, codecs).build(now);
            rtc.sdp_api()
                .accept_offer(SdpOffer::from_sdp_string(offer).unwrap())
                .unwrap();
            rtc
        };
        // Every audio codec enabled: the viewer's audio m-line is answered.
        assert!(!rejected(
            &answer(viewer.offer(), &audio::EVERY_CODEC),
            &audio_mid
        ));
        // Only an iLBC payload type offered: nothing in common.
        let ilbc =
            lotse_testing::viewer::with_audio_codecs(viewer.offer(), "a=rtpmap:97 iLBC/8000\n");
        assert!(rejected(&answer(&ilbc, &audio::EVERY_CODEC), &audio_mid));
        // No audio codec the engine carries enabled (AAC is skipped):
        // nothing in common either.
        assert!(rejected(
            &answer(viewer.offer(), &[CodecFamily::AacLc]),
            &audio_mid
        ));
        // A mid the offer does not have counts as rejected.
        assert!(rejected(
            &answer(viewer.offer(), &audio::EVERY_CODEC),
            "nope"
        ));
    }

    #[test]
    fn rfc9143_9_1_1_str0m_0_24_panics_on_the_offers_the_check_refuses() {
        use lotse_core::clock::{Clock as _, SystemClock};
        use lotse_core::session::IceCredentials;

        // The engine alone, without the check: the payload type conflict
        // reaches its "Pt locked multiple times" assert. When an str0m
        // upgrade turns this into an error, the check stays (the offer is
        // still invalid) but this test is to be inverted.
        let now = SystemClock.now();
        install_crypto_provider();
        let viewer =
            lotse_testing::Viewer::new_with_audio("192.0.2.20:40000".parse().unwrap(), now)
                .unwrap();
        let offer =
            lotse_testing::viewer::with_audio_codecs(viewer.offer(), "a=rtpmap:109 opus/48000/2\n");
        let request = SessionRequest {
            offer: offer.clone(),
            ice: IceCredentials {
                ufrag: "ufrag".into(),
                pass: "passwordpasswordpassword".into(),
            },
            candidates: vec![],
            tcp_candidates: vec![],
            video: std::sync::Arc::new(Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            }),
            audio: None,
            backchannel: None,
            orientation: Orientation::default(),
            limits: SessionLimits::default(),
            wall: std::time::SystemTime::UNIX_EPOCH,
        };
        let panicked = std::panic::catch_unwind(|| {
            let video = VideoPlan::for_codec(&request.video).unwrap();
            let mut rtc = build_config(&request, &video, &audio::EVERY_CODEC).build(now);
            let offer = AudioPlan::new(&offer, None, None).engine_offer(&offer);
            let offer = SdpOffer::from_sdp_string(&offer).unwrap();
            let _answer = rtc.sdp_api().accept_offer(offer);
        })
        .unwrap_err();
        let message = panicked.downcast_ref::<String>().unwrap();
        assert_eq!(message, "Pt locked multiple times: 109");
        assert!(check_payload_types(&offer).is_err());
    }

    #[test]
    fn audio_families_map_to_engine_codecs_and_mids_are_read() {
        assert_eq!(
            audio_engine_codec(CodecFamily::Opus),
            Some(EngineCodec::Opus)
        );
        assert_eq!(
            audio_engine_codec(CodecFamily::Pcmu),
            Some(EngineCodec::PCMU)
        );
        assert_eq!(
            audio_engine_codec(CodecFamily::Pcma),
            Some(EngineCodec::PCMA)
        );
        assert_eq!(
            audio_engine_codec(CodecFamily::G722),
            Some(EngineCodec::G722)
        );
        assert_eq!(audio_engine_codec(CodecFamily::AacLc), None);
        assert_eq!(
            first_mid(
                "m=audio 9 x 0\r\na=mid:a\r\nm=video 9 x 96\r\na=mid:v\r\n",
                "audio"
            ),
            Some("a")
        );
        assert_eq!(first_mid("m=audiox 9 x 0\r\na=mid:a\r\n", "audio"), None);
    }

    #[test]
    fn engine_codecs_map_back_to_audio_families() {
        for family in audio::EVERY_CODEC {
            assert_eq!(
                audio_engine_codec(family).and_then(engine_family),
                Some(family)
            );
        }
        assert_eq!(engine_family(EngineCodec::H264), None);
    }

    #[test]
    fn talk_back_is_only_what_the_engine_mapped_to_the_talk_back_m_line() {
        use lotse_core::clock::{Clock as _, SystemClock};

        let now = SystemClock.now();
        let mut talkback = TalkbackRx {
            mid: Mid::from("2"),
            depacketizer: Depacketizer::new([(0, CodecFamily::Pcmu), (111, CodecFamily::Opus)]),
            negotiated: UplinkCodec::Pcmu,
            codec: None,
        };
        let rtp = |pt| RtpHeaderFields {
            pt,
            seq: 1,
            ts: 160,
            marker: false,
            ssrc: 3,
        };
        let payload = || std::sync::Arc::<[u8]>::from(&[0xf8_u8, 1][..]);
        // Another m-line, or one the engine could not tell.
        for mid in [Some(Mid::from("0")), None] {
            assert_eq!(
                talkback.take(mid, rtp(0), payload(), now),
                Err("not on the talk-back m-line")
            );
        }
        assert_eq!(talkback.codec, None);
        // The talk-back m-line: taken, and the codec remembered for the
        // log of a change.
        let mid = Some(Mid::from("2"));
        assert!(talkback.take(mid, rtp(0), payload(), now).is_ok());
        assert_eq!(talkback.codec, Some(UplinkCodec::Pcmu));
        assert!(talkback.take(mid, rtp(0), payload(), now).is_ok());
        assert_eq!(
            talkback.take(mid, rtp(8), payload(), now),
            Err("payload type of no talk-back codec")
        );
        assert_eq!(
            talkback.codec,
            Some(UplinkCodec::Pcmu),
            "a refusal is no change"
        );
        assert!(talkback.take(mid, rtp(111), payload(), now).is_ok());
        assert_eq!(talkback.codec, Some(UplinkCodec::Opus));
    }

    #[test]
    fn ice_names_and_the_video_mid_are_read() {
        for (state, name) in [
            (IceConnectionState::New, "new"),
            (IceConnectionState::Checking, "checking"),
            (IceConnectionState::Connected, "connected"),
            (IceConnectionState::Completed, "completed"),
            (IceConnectionState::Disconnected, "disconnected"),
        ] {
            assert_eq!(ice_name(state), name);
        }
        assert_eq!(
            video_mid(
                "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\n"
            ),
            Some("1")
        );
        assert_eq!(
            video_mid("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\n"),
            None
        );
        assert_eq!(video_mid("m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"), None);
    }
}
