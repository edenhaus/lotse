//! The offer's audio m-lines: the one the stream's audio goes down on,
//! the one talk-back comes up on, the direction each is answered with and
//! the audio codecs the engine is configured with.
//!
//! A pure function of the offer, the stream's audio codec, its
//! backchannel ([`TalkbackTarget`]) and the worker's claim of it for the
//! session ([`TalkbackClaim`]): the offer claims the backchannel, one
//! talker per stream, and the answer carries the outcome, so the plan is
//! made again for every re-offer.
//!
//! The talk-back m-line is answered with the codecs that reach the camera
//! ([`TalkbackTarget::takes`], which the worker derives from the routes it
//! can build) and nothing else, but for the stream audio's codec when
//! the same `sendrecv` m-line also carries the downlink: the browser may
//! send any codec the answer lists (RFC 3264 §7), so a listed codec the
//! route cannot take would lose the talker's audio. Every other audio
//! m-line is answered without the codecs no talk-back could arrive in,
//! as a re-offer may ask for talk-back there. An m-line the engine
//! answered before keeps the codecs of that answer, and talk-back on it
//! is received in the first of them the re-offer lists, or not at all
//! when the browser may send one of them the camera never gets
//! ([`AudioPlan::kept`]); the stream's audio goes down it only in a
//! codec it kept, or not at all ([`AudioPlan::kept_downlink`]).
//!
//! Standards: RFC 8866 §6.7 (direction attributes, `sendrecv` when an
//! m-line has none), §6.6 (`a=rtpmap`) and §6.15 (`a=fmtp`), RFC 4585
//! §4.2 (`a=rtcp-fb`), RFC 3551 §6 (static payload types, Table 4),
//! RFC 4855 §3 (encoding names compare case-insensitively), RFC 8829
//! §5.3.1 (an answer's direction is the offered one reversed, intersected
//! with what the answerer does), RFC 3264 §6.1 (an m-line answered
//! `inactive` keeps its place and lists formats of the offer; what a
//! `sendrecv` one lists) and §7 (the offerer sends the answer's first
//! format, and may switch to any other it lists), RFC 7874 §3 (a WebRTC
//! endpoint implements Opus, PCMA and PCMU).

use lotse_core::codec::{Codec, CodecFamily};
use lotse_core::output::TalkbackRequest;
use lotse_core::session::{TalkbackClaim, TalkbackTarget};
use lotse_core::uplink::UplinkCodec;

use crate::sdp::{Sdp, Section, static_encoding};

/// Every audio codec the engine carries, in the session's order of
/// preference.
pub(crate) const EVERY_CODEC: [CodecFamily; 4] = [
    CodecFamily::Opus,
    CodecFamily::Pcmu,
    CodecFamily::Pcma,
    CodecFamily::G722,
];

/// A media direction attribute (RFC 8866 §6.7), from the side of whoever
/// wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// `a=sendrecv`.
    SendRecv,
    /// `a=sendonly`.
    SendOnly,
    /// `a=recvonly`.
    RecvOnly,
    /// `a=inactive`.
    Inactive,
}

impl Direction {
    /// The direction of a side that sends when `send` and receives when
    /// `receive`.
    pub(crate) const fn new(send: bool, receive: bool) -> Self {
        match (send, receive) {
            (true, true) => Self::SendRecv,
            (true, false) => Self::SendOnly,
            (false, true) => Self::RecvOnly,
            (false, false) => Self::Inactive,
        }
    }

    /// The direction an SDP line states, or `None` for any other line.
    pub(crate) fn parse(line: &str) -> Option<Self> {
        match line {
            "a=sendrecv" => Some(Self::SendRecv),
            "a=sendonly" => Some(Self::SendOnly),
            "a=recvonly" => Some(Self::RecvOnly),
            "a=inactive" => Some(Self::Inactive),
            _ => None,
        }
    }

    /// The direction a media section states, `sendrecv` when it states
    /// none (RFC 8866 §6.7). A session-level attribute is not read: JSEP
    /// puts one in every m-line (RFC 8829 §5.2.1).
    pub(crate) fn of(section: &Section<'_>) -> Self {
        section
            .lines()
            .iter()
            .find_map(|line| Self::parse(line))
            .unwrap_or(Self::SendRecv)
    }

    /// Whether this side sends.
    pub(crate) const fn sends(self) -> bool {
        matches!(self, Self::SendRecv | Self::SendOnly)
    }

    /// Whether this side receives.
    pub(crate) const fn receives(self) -> bool {
        matches!(self, Self::SendRecv | Self::RecvOnly)
    }

    /// The same media seen from the other side.
    const fn reversed(self) -> Self {
        Self::new(self.receives(), self.sends())
    }

    /// The attribute line, without its line ending.
    pub(crate) const fn attribute(self) -> &'static str {
        match self {
            Self::SendRecv => "a=sendrecv",
            Self::SendOnly => "a=sendonly",
            Self::RecvOnly => "a=recvonly",
            Self::Inactive => "a=inactive",
        }
    }
}

/// The `a=rtpmap` encoding name of an audio family the engine carries:
/// RFC 7587 §7 (`opus`), RFC 3551 §4.5.14 (`PCMU`, `PCMA`) and §4.5.2
/// (`G722`).
pub(crate) const fn encoding_name(family: CodecFamily) -> Option<&'static str> {
    match family {
        CodecFamily::Opus => Some("opus"),
        CodecFamily::Pcmu => Some("PCMU"),
        CodecFamily::Pcma => Some("PCMA"),
        CodecFamily::G722 => Some("G722"),
        _ => None,
    }
}

/// The RTP clock of an audio family: 48 kHz for Opus (RFC 7587 §4.1),
/// 8 kHz for G.711 and for G.722, whose RTP clock stays 8 kHz although it
/// samples at 16 kHz (RFC 3551 §4.5.2).
pub(crate) const fn clock_rate(family: CodecFamily) -> u32 {
    match family {
        CodecFamily::Opus => 48_000,
        _ => 8_000,
    }
}

/// Whether an `a=rtpmap` encoding of `family` with the channel count
/// `channels` (its encoding parameters, RFC 8866 §6.6; `None` when it
/// has none) is the one the engine is configured with: str0m 0.24.0
/// matches an offered format to its own only at the same channel count
/// (`PayloadParams::match_score`, read 2026-10-17). It carries Opus at
/// two channels, the only count RFC 7587 §7 allows (`opus/48000/2`), and
/// G.711 and G.722 mono (RFC 3551 §4.5.14, §4.5.2, Table 4) at none
/// (`enable_pcmu`, `enable_pcma`, `enable_g722`), which for G.722 it
/// also reads from `/1` (`From<RtpMap> for CodecSpec`). So an offer's
/// two-channel G.711 is no codec the engine carries, and the plan takes
/// neither talk-back nor the downlink in it.
///
/// `SPEC-DEVIATION` (RFC 8866 §6.6: an audio encoding without encoding
/// parameters has one channel, so `PCMU/8000/1` names the codec
/// `PCMU/8000` does): a G.711 encoding that writes its one channel is
/// not matched, since str0m 0.24.0 answers no format for it; the plan
/// follows the engine, so it never counts on a codec the answer leaves
/// out.
const fn engine_channels(family: CodecFamily, channels: Option<u8>) -> bool {
    match family {
        CodecFamily::Opus => matches!(channels, Some(2)),
        CodecFamily::G722 => matches!(channels, None | Some(1)),
        _ => channels.is_none(),
    }
}

/// The audio family the engine carries that an `a=rtpmap` encoding
/// (`<name>/<clock>[/<channels>]`, RFC 8866 §6.6) names: its encoding
/// name, case-insensitive (RFC 4855 §3), at its RTP clock rate and with
/// the channel count the engine carries it at ([`engine_channels`]);
/// `None` for any other codec. The engine matches the rest.
fn encoding_family(encoding: &str) -> Option<CodecFamily> {
    let mut parts = encoding.split('/');
    let name = parts.next()?;
    let clock = parts.next().and_then(|clock| clock.parse::<u32>().ok())?;
    let channels = parts.next().map(str::parse::<u8>).transpose().ok()?;
    EVERY_CODEC.into_iter().find(|family| {
        encoding_name(*family).is_some_and(|known| known.eq_ignore_ascii_case(name))
            && clock_rate(*family) == clock
            && engine_channels(*family, channels)
    })
}

/// The audio m-lines of `sdp` a plan reads, in order, each with its mid
/// and its direction as offered: those with a mid (RFC 8829 §5.2.1) that
/// are not stopped ([`Sdp::stopped`]).
fn live_lines<'s, 'a>(sdp: &'s Sdp<'a>) -> Vec<(&'s Section<'a>, &'a str, Direction)> {
    sdp.media()
        .iter()
        .filter(|section| section.is("audio") && !sdp.stopped(section))
        .filter_map(|section| Some((section, section.mid()?, Direction::of(section))))
        .collect()
}

/// Whether `offer` has an audio m-line a plan reads ([`live_lines`]).
pub(crate) fn offers_audio(offer: &str) -> bool {
    !live_lines(&Sdp::parse(offer)).is_empty()
}

/// Whether `offer` has an audio m-line a plan reads ([`live_lines`]) that
/// the browser receives on (`recvonly` or `sendrecv`, RFC 8866 §6.7): the
/// only kind the stream's audio can go down.
pub(crate) fn receives_audio(offer: &str) -> bool {
    live_lines(&Sdp::parse(offer))
        .iter()
        .any(|(_, _, offered)| offered.receives())
}

/// Whether `section` lists `family` in an `a=rtpmap` (RFC 8866 §6.6), by
/// [`encoding_family`].
fn lists(section: &Section<'_>, family: CodecFamily) -> bool {
    section
        .attribute("rtpmap")
        .filter_map(|rtpmap| rtpmap.split_once(' '))
        .any(|(_, encoding)| encoding_family(encoding) == Some(family))
}

/// Whether `line` is the `a=rtpmap` (RFC 8866 §6.6), `a=fmtp` (§6.15) or
/// `a=rtcp-fb` (RFC 4585 §4.2) line of one of the payload types `pts`.
/// A wildcard `a=rtcp-fb:*` is of none.
fn describes(line: &str, pts: &[u8]) -> bool {
    ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"]
        .into_iter()
        .filter_map(|prefix| line.strip_prefix(prefix))
        .any(|rest| {
            rest.split(' ')
                .next()
                .and_then(|pt| pt.parse::<u8>().ok())
                .is_some_and(|pt| pts.contains(&pt))
        })
}

/// `m_line` without the formats `pts` (RFC 8866 §5.14: `m=<media>
/// <port> <proto> <fmt> ...`); without any, `m_line` as it is.
fn without_formats(m_line: &str, pts: &[u8]) -> String {
    let mut fields = m_line.split(' ');
    let head: Vec<&str> = fields.by_ref().take(3).collect();
    let kept = fields.filter(|format| !format.parse::<u8>().is_ok_and(|pt| pts.contains(&pt)));
    head.into_iter().chain(kept).collect::<Vec<_>>().join(" ")
}

/// `m_line` with its port field (RFC 8866 §5.14: `m=<media>
/// <port>[/<number of ports>] <proto> <fmt> ...`) written `0`, the one
/// form of port zero str0m 0.24.0 reads as a disabled m-line (its
/// `media_parser` in `sdp/parser.rs`, read 2026-10-17). A number of
/// ports goes with it: str0m reads `0/2` as a live port, and a stopped
/// m-line uses no port it could count (RFC 3264 §8.2).
fn with_port_zero(m_line: &str) -> String {
    m_line
        .split(' ')
        .enumerate()
        .map(|(field, value)| if field == 1 { "0" } else { value })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The payload types of `section` whose codec the engine carries and
/// `dropped` says to leave out. A format is read by its `a=rtpmap`, else
/// as a static payload type (RFC 3551 §6, Table 4), the way str0m reads
/// it, which also reads an `a=rtpmap` the format list leaves out.
fn formats_of(section: &Section<'_>, dropped: impl Fn(CodecFamily) -> bool) -> Vec<u8> {
    let mut families: Vec<(u8, Option<CodecFamily>)> = section
        .attribute("rtpmap")
        .filter_map(|rtpmap| {
            let (pt, encoding) = rtpmap.split_once(' ')?;
            Some((pt.parse().ok()?, encoding_family(encoding)))
        })
        .collect();
    for pt in section.formats() {
        if !families.iter().any(|(mapped, _)| *mapped == pt) {
            families.push((pt, static_encoding(pt).and_then(encoding_family)));
        }
    }
    families
        .into_iter()
        .filter(|(_, family)| family.is_some_and(&dropped))
        .map(|(pt, _)| pt)
        .collect()
}

/// Whether `section` offers a format of `family`, read as the engine
/// reads it ([`formats_of`]): by its `a=rtpmap`, else as a static
/// payload type.
fn offers(section: &Section<'_>, family: CodecFamily) -> bool {
    !formats_of(section, |listed| listed == family).is_empty()
}

/// The other G.711 law of `family` (ITU-T G.711; PCMU and PCMA at 8 kHz,
/// the static payload types 0 and 8 of RFC 3551 Table 4, §4.5.14), which
/// talk-back converts to the backchannel's law; `None` for any other
/// family.
const fn other_law(family: CodecFamily) -> Option<CodecFamily> {
    match family {
        CodecFamily::Pcmu => Some(CodecFamily::Pcma),
        CodecFamily::Pcma => Some(CodecFamily::Pcmu),
        _ => None,
    }
}

/// The audio codecs the engine is configured with, in its order of
/// preference, for a session whose stream's backchannel takes
/// `backchannel` (`None` without one) and whose stream's audio is
/// `stream` (`None` without any): with a backchannel, its codec, then
/// for a G.711 one the other law, then Opus; then the stream audio's
/// codec; then the rest of [`EVERY_CODEC`]. Fixed when the session
/// opens: str0m answers every m-line, of the offer and of every
/// re-offer, with this one list in this order, narrowed to what the
/// m-line offered when it first answered it (there is no list per
/// m-line, an upstream need; and str0m 0.24.0 keeps an m-line's payload
/// types from its first answer, `Media::set_remote_pts`, read
/// 2026-10-24), so [`AudioPlan::engine_offer`] narrows each new m-line's
/// formats, and the order puts the codec talk-back is received in first
/// on the talk-back m-line, which the browser sends (RFC 3264 §7): the
/// backchannel's own, else the other law, else Opus
/// ([`AudioPlan::new`]); talk-back on an m-line answered before is
/// received in the first codec it kept that the re-offer lists
/// ([`AudioPlan::kept`]). Without a
/// backchannel the stream audio's codec comes first, so the downlink
/// m-line names first the codec the session sends on it, the default
/// format of the m-line (RFC 8866 §5.14: the first format listed SHOULD
/// be the session's default). Every codec is
/// enabled so a re-offer can add talk-back in any of them.
pub(crate) fn engine_codecs(
    backchannel: Option<CodecFamily>,
    stream: Option<CodecFamily>,
) -> Vec<CodecFamily> {
    let talkback = backchannel
        .into_iter()
        .chain(backchannel.and_then(other_law))
        .chain(backchannel.map(|_| CodecFamily::Opus));
    let mut codecs = Vec::with_capacity(EVERY_CODEC.len());
    for family in talkback.chain(stream).chain(EVERY_CODEC) {
        if EVERY_CODEC.contains(&family) && !codecs.contains(&family) {
            codecs.push(family);
        }
    }
    codecs
}

/// Talk-back as the answer has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Talkback<'a> {
    /// Received on the m-line `mid` in `codec`: the browser's own
    /// `sendonly` m-line when `dedicated`, else its `sendrecv` downlink
    /// one.
    Negotiated {
        /// The m-line's mid.
        mid: &'a str,
        /// The codec the answer lists first on it, which the browser
        /// sends (RFC 3264 §7).
        codec: CodecFamily,
        /// A dedicated talk-back m-line rather than the downlink one.
        dedicated: bool,
    },
    /// Requested and not negotiated, and why: an audio m-line the
    /// browser offers to send on (`sendonly` or `sendrecv`, RFC 8866
    /// §6.7) asks for two-way audio, which the session cannot receive.
    Off(&'static str),
    /// Requested, and the backchannel would take it, but another session
    /// holds the backchannel ([`TalkbackClaim::Busy`]): declined, the
    /// m-line answered as one the session cannot receive on (RFC 3264
    /// §6.1), with the codecs it would be negotiated with
    /// ([`AudioPlan::engine_offer`]): str0m keeps an m-line's formats
    /// from its first answer, so a later re-offer the claim is granted
    /// to names the same codec first.
    Busy {
        /// The m-line's mid.
        mid: &'a str,
        /// The codec talk-back would be received in, which the answer
        /// lists first on it.
        codec: CodecFamily,
    },
    /// Not requested: no audio m-line with a mid the browser offers to
    /// send on.
    NotRequested,
}

impl Talkback<'_> {
    /// What talk-back planned with the backchannel held asks of it
    /// ([`TalkbackRequest`]): negotiable where it is received, or
    /// would be but for another session's claim; requested in vain,
    /// and why, where it is off.
    pub(crate) fn request(self) -> TalkbackRequest {
        match self {
            Self::NotRequested => TalkbackRequest::NotRequested,
            Self::Negotiated { .. } | Self::Busy { .. } => TalkbackRequest::Negotiable,
            Self::Off(reason) => TalkbackRequest::Unsupported(reason.to_owned()),
        }
    }
}

/// The mid of the audio m-line of `offer` that talk-back comes up on
/// when the plan negotiates it ([`AudioPlan::new`]): the first live one
/// the browser offers `sendonly`, else the first it offers `sendrecv`;
/// `None` when it offers to send on none, and asks for no talk-back.
pub(crate) fn talkback_mid(offer: &str) -> Option<&str> {
    uplink(&live_lines(&Sdp::parse(offer))).map(|((_, mid, _), _)| *mid)
}

/// The m-line of `lines` ([`live_lines`]) talk-back comes up on, and
/// whether it is a dedicated one: the first the browser offers
/// `sendonly`, or else the first it offers `sendrecv` (RFC 8866 §6.7:
/// the browser offers to send there).
fn uplink<'l, 's, 'a>(
    lines: &'l [(&'s Section<'a>, &'a str, Direction)],
) -> Option<(&'l (&'s Section<'a>, &'a str, Direction), bool)> {
    let dedicated = lines
        .iter()
        .find(|(_, _, offered)| *offered == Direction::SendOnly);
    dedicated.map(|line| (line, true)).or_else(|| {
        lines
            .iter()
            .find(|(_, _, offered)| *offered == Direction::SendRecv)
            .map(|line| (line, false))
    })
}

/// What the session does with the offer's audio m-lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AudioPlan<'a> {
    /// The m-line the stream's audio goes down on: the first audio m-line
    /// with a mid, not stopped ([`Sdp::stopped`]), that the browser
    /// receives on (`recvonly` or `sendrecv`).
    pub(crate) downlink: Option<&'a str>,
    /// The stream audio's family, when the engine carries it and the
    /// downlink m-line lists it.
    pub(crate) send: Option<CodecFamily>,
    /// Where talk-back comes up.
    pub(crate) talkback: Talkback<'a>,
    /// The families of the uplink codecs that reach the backchannel
    /// ([`TalkbackTarget::takes`]), which decide what talk-back takes
    /// ([`AudioPlan::takes`]); empty without one.
    reaching: Vec<CodecFamily>,
    /// The engine's codecs in its order of preference
    /// ([`engine_codecs`]), which [`AudioPlan::engine_offer`] keeps the
    /// talk-back codec first under.
    order: Vec<CodecFamily>,
}

impl<'a> AudioPlan<'a> {
    /// The plan for `offer`, the stream's audio codec (`audio`), its
    /// backchannel (`backchannel`), the worker's `claim` of it for the
    /// session and the engine's codec `order` ([`engine_codecs`]).
    ///
    /// Talk-back goes on the first audio m-line the browser offers
    /// `sendonly` (the dedicated one), or else on the first it offers
    /// `sendrecv`, the downlink m-line as a rule, never on both: a session
    /// has one uplink. Either requests it (RFC 8866 §6.7: the browser
    /// offers to send there). It takes, of the codecs that m-line lists
    /// and that reach the backchannel ([`TalkbackTarget::takes`]), the
    /// backchannel's own (its codes pass through), else for a G.711
    /// backchannel the other law (converted code by code, ITU-T G.711
    /// Tables 3 and 4), else Opus (decoded and encoded in the
    /// backchannel's law, or forwarded as received to an Opus one): a
    /// browser implements all three (RFC 7874 §3), so a G.711 camera keeps
    /// G.711 from a browser that leaves its law out. A backchannel no
    /// uplink codec reaches, in a codec no route feeds or without the
    /// reverse chain it needs, is off. The answer names the codec first on
    /// that m-line, which the browser sends (RFC 3264 §6.1). Talk-back the
    /// backchannel would take is declined all the same while another
    /// session holds the backchannel ([`TalkbackClaim::Busy`]).
    ///
    /// Talk-back on the downlink m-line itself, offered `sendrecv`, is off
    /// while the stream audio's codec, which the session sends there, does
    /// not reach the backchannel (an Opus backchannel under G.711 stream
    /// audio, a G.711 one under G.722): an m-line answered `sendrecv`
    /// lists at least one codec the answerer both sends and receives
    /// (RFC 3264 §6.1), and that m-line has one format list for both
    /// directions. It is answered `sendonly` instead, as RFC 3264 §6.1
    /// lets a `sendrecv` offer be, so the stream's audio still goes down;
    /// a dedicated `sendonly` m-line gets talk-back.
    ///
    /// A stopped m-line ([`Sdp::stopped`]: a zero port, not a bundled
    /// `bundle-only` one) carries neither: its stream is disabled
    /// (RFC 3264 §8.2), whatever direction it still names, so it neither
    /// requests talk-back nor takes the stream's audio.
    pub(crate) fn new(
        offer: &'a str,
        audio: Option<&Codec>,
        backchannel: Option<&TalkbackTarget>,
        claim: TalkbackClaim,
        order: &[CodecFamily],
    ) -> Self {
        let sdp = Sdp::parse(offer);
        let lines = live_lines(&sdp);
        let downlink = lines.iter().find(|(_, _, offered)| offered.receives());
        let send = audio
            .map(Codec::family)
            .filter(|family| downlink.is_some_and(|(section, _, _)| lists(section, *family)));
        let uplink = uplink(&lines);
        let reaching: Vec<CodecFamily> = backchannel
            .map(|backchannel| {
                backchannel
                    .takes
                    .iter()
                    .map(|codec| codec.family())
                    .collect()
            })
            .unwrap_or_default();
        let talkback = match (
            uplink,
            backchannel.map(|backchannel| backchannel.codec.family()),
        ) {
            (None, _) => Talkback::NotRequested,
            (Some(_), None) => Talkback::Off("the camera offers no backchannel"),
            (Some(_), Some(_)) if reaching.is_empty() => {
                Talkback::Off("the backchannel takes a codec talk-back cannot feed")
            }
            (Some(((section, mid, _), dedicated)), Some(family)) => {
                // Only a `sendrecv` m-line is both: a dedicated one is
                // `sendonly`, never the downlink.
                let one_way = downlink.is_some_and(|(_, downlink, _)| downlink == mid)
                    && send.is_some_and(|sent| !reaching.contains(&sent));
                match [Some(family), other_law(family), Some(CodecFamily::Opus)]
                    .into_iter()
                    .flatten()
                    .find(|family| reaching.contains(family) && lists(section, *family))
                {
                    Some(_) if one_way => Talkback::Off(
                        "the stream audio's codec on its sendrecv m-line does not reach the backchannel; talk-back needs a sendonly m-line",
                    ),
                    Some(codec) if claim == TalkbackClaim::Busy => Talkback::Busy { mid, codec },
                    Some(codec) => Talkback::Negotiated {
                        mid,
                        codec,
                        dedicated,
                    },
                    None => Talkback::Off(
                        "the talk-back m-line lists no codec that reaches the backchannel",
                    ),
                }
            }
        };
        Self {
            downlink: downlink.map(|(_, mid, _)| *mid),
            send,
            talkback,
            reaching,
            order: order.to_vec(),
        }
    }

    /// Whether talk-back the browser sends in `family` is taken: talk-back
    /// is negotiated and `family` reaches its backchannel
    /// ([`TalkbackTarget::takes`]).
    pub(crate) fn takes(&self, family: CodecFamily) -> bool {
        matches!(self.talkback, Talkback::Negotiated { .. }) && self.reaching.contains(&family)
    }

    /// The plan for an engine that answered some of the m-lines of
    /// `offer`, the offer the plan was made for, before: `kept(mid)`
    /// gives the codecs the engine answers the m-line `mid` with, in its
    /// order: those of its first answer, or none for an m-line it never
    /// answered. Of those, the browser may send the ones the offer lists
    /// on that m-line (RFC 3264 §7; read as the engine reads formats,
    /// [`offers`]). Talk-back negotiated on an m-line that kept codecs is
    /// received in the first of these, which the browser sends, when
    /// every one of them reaches the backchannel, and is off otherwise:
    /// the browser could send what the camera never gets, while the
    /// session reported talk-back. It is off too when the offer lists
    /// none of them: the browser could send nothing the answer names.
    ///
    /// `SPEC-DEVIATION` (RFC 3264 §8.3.2: a new offer may change an
    /// m-line's formats, and the answer to it lists the formats the
    /// answerer now takes, of those offered, §6.1): str0m 0.24.0 keeps an
    /// m-line's payload types from its first answer and answers every
    /// later offer with them, in its own order (`Media::set_remote_pts`,
    /// `Media::remote_pts`, read 2026-10-24), and lets no codec be
    /// dropped from a live engine (`Rtc::codec_config` is read-only), so
    /// the narrowed offer ([`AudioPlan::engine_offer`]) no longer reaches
    /// an m-line it answered. Such an answer can list a codec talk-back
    /// does not take, which declines talk-back where an answerer that
    /// narrows the m-line would grant it, and a codec the re-offer no
    /// longer lists (a format the offer does not have, against §6.1),
    /// which the plan ignores, as the browser cannot send it. A first
    /// answer therefore lists only codecs talk-back could
    /// arrive in ([`AudioPlan::unroutable`]): a declined talk-back m-line
    /// those it would be negotiated with ([`Talkback::Busy`]), every
    /// other audio m-line those that reach the backchannel, or any
    /// talk-back can arrive in without one, so a later re-offer finds
    /// them; one answered for another backchannel keeps what it was
    /// answered with then.
    pub(crate) fn kept<I>(mut self, offer: &str, kept: impl FnOnce(&str) -> I) -> Self
    where
        I: IntoIterator<Item = CodecFamily>,
    {
        let Talkback::Negotiated { mid, dedicated, .. } = self.talkback else {
            return self;
        };
        let mut kept = kept(mid).into_iter().peekable();
        if kept.peek().is_none() {
            return self;
        }
        let sdp = Sdp::parse(offer);
        let section = sdp
            .media()
            .iter()
            .find(|section| section.is("audio") && section.mid() == Some(mid));
        let mut sendable =
            kept.filter(|family| section.is_some_and(|section| offers(section, *family)));
        let reaches = |family: &CodecFamily| self.reaching.contains(family);
        self.talkback = match sendable.next() {
            Some(first) if reaches(&first) && sendable.all(|family| reaches(&family)) => {
                Talkback::Negotiated {
                    mid,
                    codec: first,
                    dedicated,
                }
            }
            Some(_) => Talkback::Off(
                "the talk-back m-line keeps the codecs of its first answer, and the browser may send one that does not reach the backchannel",
            ),
            None => Talkback::Off(
                "the talk-back m-line keeps the codecs of its first answer, and the re-offer lists none of them",
            ),
        };
        self
    }

    /// The plan for an engine that answered the downlink m-line before:
    /// `kept(mid)` gives the codecs the engine kept on the m-line `mid`
    /// from its first answer, none for an m-line it never answered
    /// ([`AudioPlan::kept`]). The stream's audio goes down an m-line that
    /// kept codecs only when its codec is among them, as the engine
    /// answers the m-line with those and the session sends only a format
    /// the answer lists (RFC 3264 §6.1); else the m-line carries no stream
    /// audio, and is answered without sending. A downlink a re-offer moves
    /// to an m-line first answered without the stream audio's codec meets
    /// this: one talk-back could arrive on lists only codecs it could
    /// arrive in ([`AudioPlan::unroutable`]), so that a later re-offer
    /// asking for talk-back there finds no codec that cannot reach the
    /// camera, and a browser may first offer an m-line without it.
    pub(crate) fn kept_downlink<I>(mut self, kept: impl FnOnce(&str) -> I) -> Self
    where
        I: IntoIterator<Item = CodecFamily>,
    {
        let (Some(mid), Some(send)) = (self.downlink, self.send) else {
            return self;
        };
        let mut kept = kept(mid).into_iter().peekable();
        if kept.peek().is_some() && !kept.any(|family| family == send) {
            self.send = None;
        }
        self
    }

    /// The payload types of `section` the engine is not offered: on the
    /// talk-back m-line, negotiated or declined busy ([`Talkback::Busy`],
    /// whose answer the engine keeps for a later re-offer the claim is
    /// granted to, [`AudioPlan::kept`]), those of an audio codec the
    /// engine carries that does not reach the backchannel
    /// ([`TalkbackTarget::takes`]), and of one that does but the engine
    /// prefers to the codec talk-back is received in (before it in the
    /// engine's order, which was fixed for the backchannel the session
    /// opened with and may not fit the one a re-offer meets), but for the
    /// stream audio's when that m-line is the downlink too. On every
    /// other audio m-line, those of a codec no talk-back could arrive in
    /// (one that does not reach the backchannel, or without one that no
    /// uplink codec is, [`UplinkCodec::of`]), but for the stream audio's
    /// on the downlink m-line, which the session sends there; and none
    /// when that would leave the m-line no codec the engine carries: the
    /// engine keeps an m-line's formats from its first answer
    /// ([`AudioPlan::kept`]), so a later re-offer that asks for talk-back
    /// on it, a downlink m-line turned `sendrecv` among them (a
    /// subsequent offer lists the codecs negotiated first, then the
    /// others it has, RFC 8829 §5.2.2), finds only codecs it can be
    /// received in. The stream audio's codec is not kept on any but the
    /// downlink: an m-line ready for talk-back later cannot carry it as
    /// well, and a re-offer that moves the downlink to one without it
    /// sends no audio there ([`AudioPlan::kept_downlink`]). A format is read by its
    /// `a=rtpmap`, else as a static payload type (RFC 3551 §6, Table 4),
    /// the way str0m reads it, which also reads an `a=rtpmap` the format
    /// list leaves out. Formats of no codec the engine carries stay: the
    /// engine answers none of them.
    ///
    /// Talk-back's own codec always reaches the backchannel and is
    /// listed, so the talk-back m-line keeps a format.
    ///
    /// On a `sendrecv` m-line that carries both, the stream audio's codec
    /// reaches the camera, or talk-back is off there ([`AudioPlan::new`]),
    /// so the answer lists a codec the session both sends and receives
    /// (RFC 3264 §6.1). It stays where the engine prefers it to
    /// talk-back's, and the browser then sends it (the Opus of an Opus
    /// stream to a G.711 backchannel, after a re-offer on a session that
    /// opened with an Opus backchannel).
    fn unroutable(&self, section: &Section<'_>) -> Vec<u8> {
        if !section.is("audio") {
            return Vec::new();
        }
        let sent = self
            .send
            .filter(|_| self.downlink.is_some() && self.downlink == section.mid());
        if let Talkback::Negotiated { mid, codec, .. } | Talkback::Busy { mid, codec } =
            self.talkback
            && section.mid() == Some(mid)
        {
            let preferred = self
                .order
                .iter()
                .position(|family| *family == codec)
                .unwrap_or_default();
            let before = self.order.get(..preferred).unwrap_or_default();
            return formats_of(section, |family| {
                (!self.reaching.contains(&family) || before.contains(&family))
                    && Some(family) != sent
            });
        }
        let arrives = |family: CodecFamily| {
            if self.reaching.is_empty() {
                UplinkCodec::of(family).is_some()
            } else {
                self.reaching.contains(&family)
            }
        };
        let dropped = formats_of(section, |family| !arrives(family) && Some(family) != sent);
        if dropped.len() == formats_of(section, |_| true).len() {
            return Vec::new();
        }
        dropped
    }

    /// The direction the session answers the audio m-line `mid` with: it
    /// sends on the downlink m-line when it carries stream audio, and
    /// receives on the talk-back one (RFC 8829 §5.3.1). Every other audio
    /// m-line, one without a mid included, is `inactive` (RFC 3264 §6.1).
    pub(crate) fn answer(&self, mid: Option<&str>) -> Direction {
        let send = self.send.is_some() && mid.is_some() && mid == self.downlink;
        let receive = matches!(self.talkback, Talkback::Negotiated { mid: talkback, .. } if mid == Some(talkback));
        Direction::new(send, receive)
    }

    /// `offer` with each audio m-line's direction replaced, where it
    /// differs, by the one str0m answers with [`AudioPlan::answer`]'s:
    /// the answer's reversed. str0m answers each m-line with the offered
    /// direction reversed and lets no local direction be set before the
    /// answer is generated, while RFC 8829 §5.3.1 intersects the offered
    /// direction with the local one. Rewriting the offer, not the answer,
    /// keeps the engine's own state in line with the answer: an inactive
    /// or receive-only m-line declares no send stream and no SSRC, so no
    /// RTP can go out on it, and an m-line answered `inactive` keeps its
    /// port, mid and BUNDLE membership.
    ///
    /// The talk-back m-line also loses the formats talk-back does not take
    /// or the engine would prefer, and every other audio m-line those no
    /// talk-back could arrive in ([`AudioPlan::unroutable`]), with their
    /// `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` lines: str0m answers an m-line
    /// with the codecs it is configured with that the offered m-line
    /// lists, and has one list for all m-lines ([`engine_codecs`]), so
    /// only the offer narrows one m-line, and only the first offer of
    /// it, whose formats str0m keeps ([`AudioPlan::kept`]). An answer
    /// lists formats of the offer (RFC 3264 §6.1), and the browser may
    /// send any it lists (RFC 3264 §7).
    ///
    /// A stopped audio m-line ([`Sdp::stopped`]: a zero port, not a
    /// bundled `bundle-only` one, whose port stays as offered) has its
    /// port written `0` ([`with_port_zero`]): str0m reads a zero-padded
    /// port, or one with a number of ports, as live and would answer it
    /// with a nonzero one, where RFC 3264 §6 answers a zero port with
    /// zero.
    pub(crate) fn engine_offer(&self, offer: &str) -> String {
        let sdp = Sdp::parse(offer);
        let mut out = String::with_capacity(offer.len().saturating_add(64));
        let mut push = |line: &str| {
            out.push_str(line);
            out.push_str("\r\n");
        };
        for line in sdp.session() {
            push(line);
        }
        for section in sdp.media() {
            let offered = Direction::of(section);
            let rewrite = section
                .is("audio")
                .then(|| self.answer(section.mid()).reversed())
                .filter(|wanted| *wanted != offered);
            let dropped = self.unroutable(section);
            let m_line = without_formats(section.m_line(), &dropped);
            if section.is("audio") && sdp.stopped(section) {
                push(&with_port_zero(&m_line));
            } else {
                push(&m_line);
            }
            for line in section.lines() {
                if (rewrite.is_none() || Direction::parse(line).is_none())
                    && !describes(line, &dropped)
                {
                    push(line);
                }
            }
            if let Some(wanted) = rewrite {
                push(wanted.attribute());
            }
        }
        out
    }

    /// The codecs the engine answers the m-line `mid` of `offer` with,
    /// in its order: those of the engine's order the engine's offer
    /// ([`AudioPlan::engine_offer`]) lists there.
    #[cfg(test)]
    pub(crate) fn answered(&self, offer: &str, mid: &str) -> Vec<CodecFamily> {
        let engine = self.engine_offer(offer);
        let sdp = Sdp::parse(&engine);
        let section = sdp
            .media()
            .iter()
            .find(|section| section.mid() == Some(mid));
        self.order
            .iter()
            .copied()
            .filter(|family| section.is_some_and(|section| lists(section, *family)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use lotse_core::uplink::UplinkCodec;

    use super::*;

    /// Downlink audio, video and a dedicated talk-back m-line, as a
    /// talk-back capable frontend offers them, each audio m-line with
    /// Opus, PCMU and PCMA.
    const DEDICATED: &str = "v=0\r\na=group:BUNDLE 0 1 2\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:0\r\na=recvonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=recvonly\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n";

    /// The downlink audio m-line turned `sendrecv`, as a player that sends
    /// talk-back on its downlink m-line offers it (observed 2026-10-07).
    fn sendrecv() -> String {
        DEDICATED
            .replacen("a=recvonly", "a=sendrecv", 1)
            .split("m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2")
            .next()
            .unwrap()
            .replace("a=group:BUNDLE 0 1 2", "a=group:BUNDLE 0 1")
    }

    /// `codec`'s backchannel as a worker with the reverse chain installed
    /// routes to it (`Arbiter::takes` over `ToG711`): Opus and both G.711
    /// laws to a G.711 camera, Opus forwarded as received to an Opus one,
    /// nothing to any other.
    fn reaching(codec: &Codec) -> TalkbackTarget {
        let takes = match codec.family() {
            CodecFamily::Pcmu | CodecFamily::Pcma => UplinkCodec::ALL.to_vec(),
            CodecFamily::Opus => vec![UplinkCodec::Opus],
            _ => Vec::new(),
        };
        TalkbackTarget {
            codec: codec.clone(),
            takes,
        }
    }

    /// Whether talk-back in `from` reaches `backchannel` by [`reaching`].
    fn routable(from: CodecFamily, backchannel: &Codec) -> bool {
        reaching(backchannel)
            .takes
            .iter()
            .any(|codec| codec.family() == from)
    }

    /// The plan of `offer` for a session that holds `backchannel`, on an
    /// engine configured for it ([`engine_codecs`]).
    fn plan_for<'a>(
        offer: &'a str,
        audio: Option<&Codec>,
        backchannel: Option<&TalkbackTarget>,
    ) -> AudioPlan<'a> {
        let order = engine_codecs(
            backchannel.map(|backchannel| backchannel.codec.family()),
            audio.map(Codec::family),
        );
        AudioPlan::new(offer, audio, backchannel, TalkbackClaim::Granted, &order)
    }

    fn negotiated(mid: &str, codec: CodecFamily, dedicated: bool) -> Talkback<'_> {
        Talkback::Negotiated {
            mid,
            codec,
            dedicated,
        }
    }

    #[test]
    fn rfc8866_6_7_directions_parse_reverse_and_default_to_sendrecv() {
        for direction in [
            Direction::SendRecv,
            Direction::SendOnly,
            Direction::RecvOnly,
            Direction::Inactive,
        ] {
            assert_eq!(Direction::parse(direction.attribute()), Some(direction));
            assert_eq!(
                Direction::new(direction.sends(), direction.receives()),
                direction
            );
            assert_eq!(direction.reversed().reversed(), direction);
        }
        assert_eq!(Direction::SendOnly.reversed(), Direction::RecvOnly);
        assert_eq!(Direction::SendRecv.reversed(), Direction::SendRecv);
        assert_eq!(Direction::Inactive.reversed(), Direction::Inactive);
        assert_eq!(Direction::parse("a=rtcp-mux"), None);
        let sdp = Sdp::parse("m=audio 9 x 0\r\na=mid:a\r\nm=audio 9 x 0\r\na=inactive\r\n");
        assert_eq!(Direction::of(&sdp.media()[0]), Direction::SendRecv);
        assert_eq!(Direction::of(&sdp.media()[1]), Direction::Inactive);
    }

    #[test]
    fn rfc8866_6_6_an_audio_m_line_lists_a_codec_by_encoding_name_and_clock() {
        let sdp = Sdp::parse(
            "m=audio 9 x 111 9 0\r\na=rtpmap:111 OPUS/48000/2\r\na=rtpmap:9 G722/16000\r\na=rtpmap:0\r\n",
        );
        let audio = &sdp.media()[0];
        // Case-insensitive name (RFC 4855 §3), clock rate as offered.
        assert!(lists(audio, CodecFamily::Opus));
        // G.722's RTP clock is 8 kHz (RFC 3551 §4.5.2): 16000 is not it.
        assert!(!lists(audio, CodecFamily::G722));
        // An `a=rtpmap` without an encoding names nothing.
        assert!(!lists(audio, CodecFamily::Pcmu));
        assert!(!lists(audio, CodecFamily::AacLc));
        assert_eq!(encoding_name(CodecFamily::Pcma), Some("PCMA"));
        assert_eq!(encoding_name(CodecFamily::G722), Some("G722"));
        assert_eq!(encoding_name(CodecFamily::Mjpeg), None);
        // RFC 7587 §4.1; RFC 3551 §4.5.2.
        assert_eq!(clock_rate(CodecFamily::Opus), 48_000);
        assert_eq!(clock_rate(CodecFamily::G722), 8_000);
        assert_eq!(clock_rate(CodecFamily::Pcmu), 8_000);
    }

    /// An encoding names a codec the engine carries only at the channel
    /// count the engine carries it at (str0m 0.24.0): Opus at two
    /// (RFC 7587 §7), G.711 and G.722 mono (RFC 3551 §4.5.14, §4.5.2),
    /// G.722 with or without its `/1`; G.711 only without it
    /// (`SPEC-DEVIATION`, [`engine_channels`]). A count that is no number
    /// names nothing.
    #[test]
    fn rfc7587_7_rfc3551_4_5_14_an_encoding_names_a_carried_codec_only_at_its_channel_count() {
        use CodecFamily::{G722, Opus, Pcma, Pcmu};
        for (encoding, family) in [
            ("opus/48000/2", Some(Opus)),
            ("opus/48000", None),
            ("opus/48000/1", None),
            ("PCMU/8000", Some(Pcmu)),
            ("PCMU/8000/1", None),
            ("PCMU/8000/2", None),
            ("PCMA/8000", Some(Pcma)),
            ("PCMA/8000/2", None),
            ("G722/8000", Some(G722)),
            ("G722/8000/1", Some(G722)),
            ("G722/8000/2", None),
            ("PCMU/8000/x", None),
        ] {
            assert_eq!(encoding_family(encoding), family, "{encoding}");
        }
    }

    /// Talk-back offered only in a format the engine does not carry
    /// (two-channel PCMU to a PCMU backchannel) is off, not negotiated:
    /// the engine answers no format for it (RFC 3264 §6), so a plan that
    /// took it would have the session hold the backchannel without
    /// talk-back. A downlink m-line that offers the stream's PCMU only in
    /// two channels carries no stream audio either.
    #[test]
    fn rfc3264_6_talk_back_in_a_format_the_engine_does_not_carry_is_off() {
        let offer = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:0\r\na=recvonly\r\na=rtpmap:0 PCMU/8000/2\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=recvonly\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:2\r\na=sendonly\r\na=rtpmap:0 PCMU/8000/2\r\n";
        let pcmu = reaching(&Codec::Pcmu);
        let plan = plan_for(offer, Some(&Codec::Pcmu), Some(&pcmu));
        assert_eq!(
            plan.talkback,
            Talkback::Off("the talk-back m-line lists no codec that reaches the backchannel")
        );
        assert_eq!(plan.send, None);
        // The same m-lines in the engine's mono PCMU: both carried.
        let mono = offer.replace("PCMU/8000/2", "PCMU/8000");
        let plan = plan_for(&mono, Some(&Codec::Pcmu), Some(&pcmu));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Pcmu, true));
        assert_eq!(plan.send, Some(CodecFamily::Pcmu));
    }

    /// The fixture matrix: {dedicated talk-back m-line,
    /// `sendrecv` downlink m-line} × {backchannel present, absent}.
    #[test]
    fn rfc8829_5_3_1_talk_back_is_received_only_with_a_backchannel() {
        let opus = Codec::Opus { channels: 2 };
        let sendrecv = sendrecv();
        // Dedicated, with a PCMU backchannel the browser offers: received
        // in PCMU on `2`, the downlink still sends Opus.
        let plan = plan_for(DEDICATED, Some(&opus), Some(&reaching(&Codec::Pcmu)));
        assert_eq!(plan.downlink, Some("0"));
        assert_eq!(plan.send, Some(CodecFamily::Opus));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Pcmu, true));
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        assert_eq!(plan.answer(Some("2")), Direction::RecvOnly);
        assert_eq!(plan.answer(Some("1")), Direction::Inactive, "not audio's");
        assert_eq!(plan.answer(None), Direction::Inactive);
        assert_eq!(
            plan.answered(DEDICATED, "2"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus],
            "talk-back's first"
        );
        assert_eq!(
            plan.answered(DEDICATED, "0"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus],
            "the downlink's, as offered, in the engine's order"
        );
        // Dedicated, without a backchannel: inactive.
        let plan = plan_for(DEDICATED, Some(&opus), None);
        assert_eq!(
            plan.talkback,
            Talkback::Off("the camera offers no backchannel")
        );
        assert_eq!(plan.answer(Some("2")), Direction::Inactive);
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        assert_eq!(
            plan.answered(DEDICATED, "0"),
            [CodecFamily::Opus, CodecFamily::Pcmu, CodecFamily::Pcma]
        );
        // `sendrecv` downlink, with a backchannel: `sendrecv`, talk-back in
        // the backchannel's codec on the downlink m-line.
        let plan = plan_for(&sendrecv, Some(&opus), Some(&reaching(&Codec::Pcma)));
        assert_eq!(plan.talkback, negotiated("0", CodecFamily::Pcma, false));
        assert_eq!(plan.answer(Some("0")), Direction::SendRecv);
        assert_eq!(
            plan.answered(&sendrecv, "0"),
            [CodecFamily::Pcma, CodecFamily::Pcmu, CodecFamily::Opus]
        );
        // `sendrecv` downlink, without one: `sendonly`.
        let plan = plan_for(&sendrecv, Some(&opus), None);
        assert_eq!(
            plan.talkback,
            Talkback::Off("the camera offers no backchannel")
        );
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        // A downlink that carries no stream audio still takes talk-back
        // (`recvonly`), or is `inactive` without a backchannel.
        let plan = plan_for(&sendrecv, None, Some(&reaching(&Codec::Pcmu)));
        assert_eq!(plan.send, None);
        assert_eq!(plan.answer(Some("0")), Direction::RecvOnly);
        assert_eq!(
            plan.answered(&sendrecv, "0"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus]
        );
        let plan = plan_for(&sendrecv, None, None);
        assert_eq!(plan.answer(Some("0")), Direction::Inactive);
        assert_eq!(
            plan.answered(&sendrecv, "0"),
            [CodecFamily::Opus, CodecFamily::Pcmu, CodecFamily::Pcma],
            "as offered"
        );
    }

    /// The engine's order: the backchannel's codec, its other law, Opus,
    /// then the stream audio's codec, then the rest, every codec once;
    /// without a backchannel the stream audio's codec first.
    #[test]
    fn rfc3264_7_the_engine_prefers_the_backchannels_codec_then_the_other_law_then_opus() {
        use CodecFamily::{G722, Opus, Pcma, Pcmu};
        assert_eq!(engine_codecs(None, None), EVERY_CODEC);
        assert_eq!(engine_codecs(Some(Pcmu), None), [Pcmu, Pcma, Opus, G722]);
        assert_eq!(engine_codecs(Some(Pcma), None), [Pcma, Pcmu, Opus, G722]);
        assert_eq!(engine_codecs(Some(Opus), None), [Opus, Pcmu, Pcma, G722]);
        assert_eq!(engine_codecs(Some(G722), None), [G722, Opus, Pcmu, Pcma]);
        // A backchannel in a codec the engine does not carry changes nothing.
        assert_eq!(engine_codecs(Some(CodecFamily::AacLc), None), EVERY_CODEC);
        // The stream audio's codec after the talk-back ones: Opus, the
        // last of them, stays ahead of it.
        assert_eq!(
            engine_codecs(Some(Pcmu), Some(G722)),
            [Pcmu, Pcma, Opus, G722]
        );
        assert_eq!(
            engine_codecs(Some(Opus), Some(Pcma)),
            [Opus, Pcma, Pcmu, G722]
        );
        assert_eq!(
            engine_codecs(Some(Pcmu), Some(Opus)),
            [Pcmu, Pcma, Opus, G722]
        );
    }

    /// Without a backchannel the engine prefers the stream audio's codec,
    /// so the downlink m-line names it first, the m-line's default format
    /// (RFC 8866 §5.14), whatever the offer lists first; the rest follow
    /// as offered, in the engine's order.
    #[test]
    fn rfc8866_5_14_the_downlink_m_line_names_the_stream_audios_codec_first() {
        use CodecFamily::{G722, Opus, Pcma, Pcmu};
        assert_eq!(engine_codecs(None, Some(Pcmu)), [Pcmu, Opus, Pcma, G722]);
        assert_eq!(engine_codecs(None, Some(G722)), [G722, Opus, Pcmu, Pcma]);
        // A stream codec the engine does not carry changes nothing.
        assert_eq!(engine_codecs(None, Some(CodecFamily::AacLc)), EVERY_CODEC);
        for codec in [Codec::Pcmu, Codec::Pcma, Codec::Opus { channels: 2 }] {
            let plan = plan_for(DEDICATED, Some(&codec), None);
            let answered = plan.answered(DEDICATED, "0");
            assert_eq!(answered.first(), Some(&codec.family()), "{codec:?}");
            assert_eq!(answered.len(), 3, "every codec offered: {answered:?}");
        }
    }

    /// While another session holds the backchannel, talk-back the
    /// backchannel would take is declined: the m-line is answered as one
    /// the session cannot receive on (RFC 3264 §6.1), with the codecs it
    /// would be negotiated with, the one talk-back would be received in
    /// first (RFC 3264 §7), and nothing is taken; what the backchannel
    /// would not take anyway keeps its own reason.
    #[test]
    fn rfc3264_6_1_a_busy_backchannel_declines_talk_back_the_offer_asks_for() {
        let opus = Codec::Opus { channels: 2 };
        let pcmu = reaching(&Codec::Pcmu);
        let order = engine_codecs(Some(CodecFamily::Pcmu), Some(CodecFamily::Opus));
        let busy = AudioPlan::new(
            DEDICATED,
            Some(&opus),
            Some(&pcmu),
            TalkbackClaim::Busy,
            &order,
        );
        assert_eq!(
            busy.talkback,
            Talkback::Busy {
                mid: "2",
                codec: CodecFamily::Pcmu
            }
        );
        assert_eq!(busy.answer(Some("2")), Direction::Inactive);
        assert_eq!(busy.answer(Some("0")), Direction::SendOnly);
        assert!(!busy.takes(CodecFamily::Pcmu));
        assert_eq!(
            busy.answered(DEDICATED, "2"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus],
            "each reaches the camera"
        );
        let sendrecv = sendrecv();
        let busy = AudioPlan::new(
            &sendrecv,
            Some(&opus),
            Some(&pcmu),
            TalkbackClaim::Busy,
            &order,
        );
        assert_eq!(
            busy.talkback,
            Talkback::Busy {
                mid: "0",
                codec: CodecFamily::Pcmu
            }
        );
        assert_eq!(busy.answer(Some("0")), Direction::SendOnly);
        assert_eq!(
            busy.answered(&sendrecv, "0"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus],
            "each reaches the camera"
        );
        // An engine that prefers Opus, opened before the camera offered
        // the backchannel: the declined m-line drops it, which ranks
        // before PCMU, and G.722, which reaches no camera, as the granted
        // one does.
        let every = talking_in(&["opus", "PCMU", "PCMA", "G722"]);
        for claim in [TalkbackClaim::Busy, TalkbackClaim::Granted] {
            let plan = AudioPlan::new(&every, None, Some(&pcmu), claim, &EVERY_CODEC);
            assert_eq!(
                plan.answered(&every, "2"),
                [CodecFamily::Pcmu, CodecFamily::Pcma],
                "{claim:?}"
            );
        }
        let g722 = talking_in(&["G722"]);
        let busy = AudioPlan::new(&g722, None, Some(&pcmu), TalkbackClaim::Busy, &order);
        assert_eq!(
            busy.talkback,
            Talkback::Off("the talk-back m-line lists no codec that reaches the backchannel")
        );
        let busy = AudioPlan::new(DEDICATED, None, None, TalkbackClaim::Busy, &order);
        assert_eq!(
            busy.talkback,
            Talkback::Off("the camera offers no backchannel")
        );
        let silent = AudioPlan::new(
            "v=0\r\nm=video 9 x 96\r\na=mid:v\r\n",
            None,
            Some(&pcmu),
            TalkbackClaim::Busy,
            &order,
        );
        assert_eq!(silent.talkback, Talkback::NotRequested);
    }

    /// A stopped audio m-line (a zero port, out of the BUNDLE group) is a
    /// disabled stream (RFC 3264 §8.2) whatever direction it still names:
    /// a talk-back m-line stopped with its `a=sendonly` kept requests no
    /// talk-back, and is answered `inactive`, so the next m-line the
    /// browser sends on takes it, a zero-padded port as a `0`; a stopped
    /// downlink m-line carries no stream audio. A `bundle-only` m-line
    /// the group lists keeps its zero port (RFC 9143 §6) and its
    /// talk-back.
    #[test]
    fn rfc3264_8_2_a_stopped_audio_m_line_carries_neither_talk_back_nor_the_downlink() {
        let opus = Codec::Opus { channels: 2 };
        let pcmu = reaching(&Codec::Pcmu);
        let dedicated = "m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2";
        let stopped_talkback = DEDICATED
            .replace(dedicated, "m=audio 0 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2")
            .replace("a=group:BUNDLE 0 1 2", "a=group:BUNDLE 0 1");
        assert!(stopped_talkback.contains("a=mid:2\r\na=sendonly"));
        let plan = plan_for(&stopped_talkback, Some(&opus), Some(&pcmu));
        assert_eq!(plan.talkback, Talkback::NotRequested);
        assert_eq!(plan.answer(Some("2")), Direction::Inactive);
        assert!(!plan.takes(CodecFamily::Pcmu));
        assert_eq!(plan.downlink, Some("0"));
        assert_eq!(plan.send, Some(CodecFamily::Opus));
        let engine = plan.engine_offer(&stopped_talkback);
        let rewritten = Sdp::parse(&engine);
        assert!(
            with_mid(&rewritten, "2").lines().contains(&"a=inactive"),
            "{engine}"
        );

        // The downlink m-line turned `sendrecv` beside it takes talk-back.
        let shared = stopped_talkback.replacen("a=recvonly", "a=sendrecv", 1);
        let plan = plan_for(&shared, Some(&opus), Some(&pcmu));
        assert_eq!(plan.talkback, negotiated("0", CodecFamily::Pcmu, false));
        assert_eq!(plan.answer(Some("2")), Direction::Inactive);

        // A stopped downlink m-line carries no stream audio.
        let stopped_downlink = DEDICATED
            .replacen(
                "m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:0",
                "m=audio 0 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:0",
                1,
            )
            .replace("a=group:BUNDLE 0 1 2", "a=group:BUNDLE 1 2");
        let plan = plan_for(&stopped_downlink, Some(&opus), Some(&pcmu));
        assert_eq!(plan.downlink, None);
        assert_eq!(plan.send, None);
        assert_eq!(plan.answer(Some("0")), Direction::Inactive);
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Pcmu, true));

        // A zero-padded port is port zero (RFC 8866 §9, `1*DIGIT`).
        for port in ["00", "000/2"] {
            let padded = stopped_talkback.replace(
                "m=audio 0 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2",
                &format!("m=audio {port} UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2"),
            );
            assert_ne!(padded, stopped_talkback);
            let plan = plan_for(&padded, Some(&opus), Some(&pcmu));
            assert_eq!(plan.talkback, Talkback::NotRequested, "{port}");
            assert_eq!(plan.answer(Some("2")), Direction::Inactive, "{port}");
        }

        // Bundle-only and listed in the group: not stopped.
        let bundle_only = DEDICATED.replace(
            dedicated,
            "m=audio 0 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2\r\na=bundle-only",
        );
        let plan = plan_for(&bundle_only, Some(&opus), Some(&pcmu));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Pcmu, true));
    }

    /// The engine is offered a stopped audio m-line (RFC 3264 §8.2) with
    /// the port `0`, the one form str0m reads as port zero, so it answers
    /// it with zero (RFC 3264 §6): a zero-padded port (RFC 8866 §9,
    /// `1*DIGIT`) and a number of ports (RFC 8866 §5.14) go. A live
    /// m-line, a `bundle-only` one the group lists (RFC 9143 §6) and a
    /// stopped m-line of another kind keep their port as offered.
    #[test]
    fn rfc3264_6_a_stopped_audio_m_line_is_offered_to_the_engine_with_port_zero() {
        let opus = Codec::Opus { channels: 2 };
        let pcmu = reaching(&Codec::Pcmu);
        let dedicated = "m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2";
        for port in ["0", "00", "000/2", "0/2"] {
            let stopped = DEDICATED
                .replace(
                    dedicated,
                    &format!("m=audio {port} UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2"),
                )
                .replace("a=group:BUNDLE 0 1 2", "a=group:BUNDLE 0 1");
            let plan = plan_for(&stopped, Some(&opus), Some(&pcmu));
            let engine = plan.engine_offer(&stopped);
            let rewritten = Sdp::parse(&engine);
            assert_eq!(
                with_mid(&rewritten, "2").m_line(),
                "m=audio 0 UDP/TLS/RTP/SAVPF 111 0 8",
                "{port}: {engine}"
            );
            assert_eq!(
                with_mid(&rewritten, "0").m_line(),
                "m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8",
                "{port}: {engine}"
            );

            // Bundle-only and listed in the group: not stopped.
            let bundle_only = DEDICATED.replace(
                dedicated,
                &format!("m=audio {port} UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2\r\na=bundle-only"),
            );
            let plan = plan_for(&bundle_only, Some(&opus), Some(&pcmu));
            let engine = plan.engine_offer(&bundle_only);
            assert_eq!(
                with_mid(&Sdp::parse(&engine), "2").m_line(),
                format!("m=audio {port} UDP/TLS/RTP/SAVPF 111 0 8"),
                "{port}: {engine}"
            );

            // A stopped video m-line is no audio plan's to rewrite.
            let video = DEDICATED
                .replace("m=video 9 ", &format!("m=video {port} "))
                .replace("a=group:BUNDLE 0 1 2", "a=group:BUNDLE 0 2");
            let plan = plan_for(&video, Some(&opus), Some(&pcmu));
            let engine = plan.engine_offer(&video);
            assert_eq!(
                with_mid(&Sdp::parse(&engine), "1").m_line(),
                format!("m=video {port} UDP/TLS/RTP/SAVPF 96"),
                "{port}: {engine}"
            );
        }
    }

    /// The engine's order was fixed for the backchannel the session
    /// opened with: on a re-offer that meets another, the talk-back
    /// m-line loses the codecs the engine would prefer to the one
    /// talk-back is received in, so that one stays first (RFC 3264 §7);
    /// the stream audio's stays on a shared m-line all the same.
    #[test]
    fn rfc3264_7_a_re_offer_on_another_backchannel_keeps_the_talk_back_codec_first() {
        use CodecFamily::{Opus, Pcma, Pcmu};
        let opened_with_opus = engine_codecs(Some(Opus), None);
        let offer = talking_in(&["opus", "PCMU", "PCMA", "G722"]);
        let plan = AudioPlan::new(
            &offer,
            None,
            Some(&reaching(&Codec::Pcma)),
            TalkbackClaim::Granted,
            &opened_with_opus,
        );
        assert_eq!(plan.talkback, negotiated("2", Pcma, true));
        assert_eq!(plan.answered(&offer, "2"), [Pcma]);
        let shared = shared_in(&["opus", "PCMU", "PCMA", "G722"]);
        let plan = AudioPlan::new(
            &shared,
            Some(&Codec::Opus { channels: 2 }),
            Some(&reaching(&Codec::Pcmu)),
            TalkbackClaim::Granted,
            &opened_with_opus,
        );
        assert_eq!(plan.talkback, negotiated("0", Pcmu, false));
        assert_eq!(
            plan.answered(&shared, "0"),
            [Opus, Pcmu, Pcma],
            "Opus is sent there, PCMA ranks after"
        );
    }

    /// On an m-line the engine answered before, talk-back is received in
    /// the first codec it kept that the offer still lists, which the
    /// browser sends (RFC 3264 §7), when every kept codec the offer lists
    /// reaches the camera; it is off when one does not, since the browser
    /// may send any of them, and when the offer lists none of them. A
    /// kept codec the offer no longer lists is ignored: the browser
    /// cannot send it. An m-line that kept nothing, and talk-back that is
    /// not negotiated, are planned as they are.
    #[test]
    fn rfc3264_7_talk_back_on_a_kept_m_line_is_received_in_its_first_codec_the_offer_lists() {
        use CodecFamily::{G722, Opus, Pcma, Pcmu};
        fn plan<'o>(
            offer: &'o str,
            backchannel: &TalkbackTarget,
            claim: TalkbackClaim,
            kept: &[CodecFamily],
        ) -> AudioPlan<'o> {
            AudioPlan::new(offer, None, Some(backchannel), claim, &EVERY_CODEC).kept(offer, |mid| {
                assert_eq!(mid, "2", "asked for the talk-back m-line");
                kept.to_vec()
            })
        }
        let offer = talking_in(&["opus", "PCMU", "PCMA", "G722"]);
        let pcmu = reaching(&Codec::Pcmu);
        let granted = TalkbackClaim::Granted;
        assert_eq!(
            plan(&offer, &pcmu, granted, &[]).talkback,
            negotiated("2", Pcmu, true),
            "never answered"
        );
        assert_eq!(
            plan(&offer, &pcmu, granted, &[Pcmu, Pcma]).talkback,
            negotiated("2", Pcmu, true)
        );
        assert_eq!(
            plan(&offer, &pcmu, granted, &[Opus, Pcmu, Pcma]).talkback,
            negotiated("2", Opus, true),
            "the first kept, not the plan's own"
        );
        // A kept codec that does not reach the camera, first or not.
        let unreaching = Talkback::Off(
            "the talk-back m-line keeps the codecs of its first answer, and the browser may send one that does not reach the backchannel",
        );
        for kept in [&[Opus, Pcmu, Pcma, G722][..], &[G722, Opus, Pcmu, Pcma]] {
            let off = plan(&offer, &pcmu, granted, kept);
            assert_eq!(off.talkback, unreaching, "{kept:?}");
            assert_eq!(off.answer(Some("2")), Direction::Inactive);
            assert!(!off.takes(Pcmu));
        }
        let forwarded = TalkbackTarget {
            codec: Codec::Pcmu,
            takes: vec![UplinkCodec::Pcmu],
        };
        assert_eq!(
            plan(&offer, &forwarded, granted, &[Pcmu, Pcma]).talkback,
            unreaching,
            "PCMA reaches no forwarded PCMU camera"
        );
        // A re-offer that narrows the m-line: what it no longer lists is
        // ignored, G.722 among it, and read as the engine reads a static
        // payload type without its `a=rtpmap`.
        let narrowed = talking_in(&["PCMU", "PCMA"]);
        assert_eq!(
            plan(&narrowed, &pcmu, granted, &[Opus, Pcmu, Pcma, G722]).talkback,
            negotiated("2", Pcmu, true),
            "Opus is no longer offered"
        );
        let unmapped = narrowed.replace(
            "m=audio 9 UDP/TLS/RTP/SAVPF 0 8",
            "m=audio 9 UDP/TLS/RTP/SAVPF 0 8 9",
        );
        assert!(unmapped.contains(" 0 8 9\r\n"), "{unmapped}");
        assert_eq!(
            plan(&unmapped, &pcmu, granted, &[Opus, Pcmu, Pcma, G722]).talkback,
            unreaching,
            "payload type 9 is G.722 (RFC 3551 Table 4)"
        );
        let other = talking_in(&["PCMA"]);
        assert_eq!(
            plan(&other, &pcmu, granted, &[Opus, Pcmu]).talkback,
            Talkback::Off(
                "the talk-back m-line keeps the codecs of its first answer, and the re-offer lists none of them"
            )
        );
        assert_eq!(
            plan(&offer, &pcmu, TalkbackClaim::Busy, &[G722]).talkback,
            Talkback::Busy {
                mid: "2",
                codec: Pcmu
            }
        );
        // Not negotiated: nothing is asked; negotiated: the talk-back
        // m-line only.
        let mut asked = Vec::new();
        let mut ask = |mid: &str| {
            asked.push(mid.to_owned());
            [Pcmu]
        };
        let silent =
            AudioPlan::new(DEDICATED, None, None, granted, &EVERY_CODEC).kept(DEDICATED, &mut ask);
        assert_eq!(
            silent.talkback,
            Talkback::Off("the camera offers no backchannel")
        );
        let talking =
            AudioPlan::new(&offer, None, Some(&pcmu), granted, &EVERY_CODEC).kept(&offer, &mut ask);
        assert_eq!(talking.talkback, negotiated("2", Pcmu, true));
        assert_eq!(asked, ["2"]);
        // Planned for another offer, whose m-line the plan's is not.
        assert_eq!(
            AudioPlan::new(&offer, None, Some(&pcmu), granted, &EVERY_CODEC)
                .kept(DEDICATED.replace("a=mid:2", "a=mid:3").as_str(), |_| [Pcmu])
                .talkback,
            Talkback::Off(
                "the talk-back m-line keeps the codecs of its first answer, and the re-offer lists none of them"
            )
        );
    }

    /// The talk-back m-line comes up where the plan negotiates it: the
    /// first `sendonly` m-line, else the first `sendrecv` one (RFC 8866
    /// §6.7), as [`AudioPlan::new`] picks it; none in an offer that sends
    /// on none.
    #[test]
    fn rfc8866_6_7_the_talk_back_mid_is_the_plans() {
        assert_eq!(talkback_mid(DEDICATED), Some("2"));
        assert_eq!(talkback_mid(&sendrecv()), Some("0"));
        let silent = DEDICATED.replace("a=sendonly", "a=inactive");
        assert_eq!(talkback_mid(&silent), None);
    }

    /// What a plan's talk-back asks of the backchannel: negotiable where
    /// it is received or declined busy, unsupported with the reason where
    /// it is off, nothing where it is not requested.
    #[test]
    fn talk_back_requests_follow_the_plan() {
        assert_eq!(
            negotiated("2", CodecFamily::Pcmu, true).request(),
            TalkbackRequest::Negotiable
        );
        assert_eq!(
            Talkback::Busy {
                mid: "2",
                codec: CodecFamily::Pcmu
            }
            .request(),
            TalkbackRequest::Negotiable
        );
        assert_eq!(
            Talkback::Off("why").request(),
            TalkbackRequest::Unsupported("why".into())
        );
        assert_eq!(
            Talkback::NotRequested.request(),
            TalkbackRequest::NotRequested
        );
    }

    /// The format list and the attribute lines of an audio m-line listing
    /// `codecs` (`opus`, `PCMU`, `PCMA`, `G722`), in that order, as
    /// browsers write them: Opus with its `a=fmtp` and `a=rtcp-fb`.
    fn formats(codecs: &[&str]) -> (String, String) {
        let (pts, lines): (Vec<&str>, Vec<String>) = codecs
            .iter()
            .map(|codec| {
                let (pt, encoding, more) = match *codec {
                    "opus" => (
                        "111",
                        "opus/48000/2",
                        "a=fmtp:111 minptime=10;useinbandfec=1\r\na=rtcp-fb:111 transport-cc\r\n",
                    ),
                    "PCMU" => ("0", "PCMU/8000", ""),
                    "PCMA" => ("8", "PCMA/8000", ""),
                    _ => ("9", "G722/8000", ""),
                };
                (pt, format!("a=rtpmap:{pt} {encoding}\r\n{more}"))
            })
            .unzip();
        (pts.join(" "), lines.concat())
    }

    /// [`DEDICATED`] with its talk-back m-line listing only `codecs`
    /// (`opus`, `PCMU`, `PCMA`, `G722`), in that order.
    fn talking_in(codecs: &[&str]) -> String {
        let (pts, lines) = formats(codecs);
        // The talk-back m-line is the offer's last.
        let (before, _) = DEDICATED
            .split_once("m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2")
            .unwrap();
        format!("{before}m=audio 9 UDP/TLS/RTP/SAVPF {pts}\r\na=mid:2\r\na=sendonly\r\n{lines}")
    }

    /// One `sendrecv` audio m-line (mid `0`) listing `codecs`, downlink and
    /// talk-back in one, beside video.
    fn shared_in(codecs: &[&str]) -> String {
        let (pts, lines) = formats(codecs);
        format!(
            "v=0\r\na=group:BUNDLE 0 1\r\nm=audio 9 UDP/TLS/RTP/SAVPF {pts}\r\na=mid:0\r\na=sendrecv\r\n{lines}m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=recvonly\r\n"
        )
    }

    /// The section of the m-line `mid` in `sdp`.
    fn with_mid<'a>(sdp: &'a Sdp<'a>, mid: &str) -> &'a Section<'a> {
        sdp.media()
            .iter()
            .find(|section| section.mid() == Some(mid))
            .unwrap()
    }

    /// The codec talk-back is received in on the dedicated m-line for a
    /// backchannel in `camera` when that m-line lists `codecs`, or why it
    /// is off.
    fn talkback_for(camera: &Codec, codecs: &[&str]) -> Result<CodecFamily, &'static str> {
        let offer = talking_in(codecs);
        let talkback = plan_for(
            &offer,
            Some(&Codec::Opus { channels: 2 }),
            Some(&reaching(camera)),
        )
        .talkback;
        if let Talkback::Off(reason) = talkback {
            return Err(reason);
        }
        EVERY_CODEC
            .into_iter()
            .find(|codec| talkback == negotiated("2", *codec, true))
            .ok_or("not on the dedicated m-line")
    }

    #[test]
    fn rfc3264_6_1_rfc7874_3_a_g711_camera_takes_its_law_then_the_other_law_then_opus() {
        const NONE: &str = "the talk-back m-line lists no codec that reaches the backchannel";
        for (camera, law, other, other_name) in [
            (Codec::Pcmu, CodecFamily::Pcmu, CodecFamily::Pcma, "PCMA"),
            (Codec::Pcma, CodecFamily::Pcma, CodecFamily::Pcmu, "PCMU"),
        ] {
            let name = encoding_name(law).unwrap();
            // The camera's law first, wherever the offer puts it.
            for codecs in [
                &["opus", "PCMU", "PCMA"][..],
                &["PCMA", "PCMU", "opus"],
                &[name, "opus"],
                &[name],
            ] {
                assert_eq!(
                    talkback_for(&camera, codecs),
                    Ok(law),
                    "{camera:?} {codecs:?}"
                );
            }
            // Without it, the other law (ITU-T G.711 Tables 3 and 4), still
            // before Opus.
            for codecs in [
                &["opus", other_name][..],
                &[other_name, "opus"],
                &[other_name],
            ] {
                assert_eq!(
                    talkback_for(&camera, codecs),
                    Ok(other),
                    "{camera:?} {codecs:?}"
                );
            }
            // Opus only when neither law is offered.
            for codecs in [&["opus"][..], &["G722", "opus"]] {
                assert_eq!(
                    talkback_for(&camera, codecs),
                    Ok(CodecFamily::Opus),
                    "{camera:?} {codecs:?}"
                );
            }
            // Nothing the uplink chain takes: off, for the same reason.
            assert_eq!(talkback_for(&camera, &["G722"]), Err(NONE), "{camera:?}");
        }
        // The other law goes first on the talk-back m-line, beside the
        // downlink's Opus.
        let offer = talking_in(&["opus", "PCMU"]);
        let plan = plan_for(
            &offer,
            Some(&Codec::Opus { channels: 2 }),
            Some(&reaching(&Codec::Pcma)),
        );
        assert_eq!(
            plan.answered(&offer, "2"),
            [CodecFamily::Pcmu, CodecFamily::Opus]
        );
        assert_eq!(plan.answer(Some("2")), Direction::RecvOnly);
        let g722 = talking_in(&["G722"]);
        let plan = plan_for(&g722, None, Some(&reaching(&Codec::Pcma)));
        assert_eq!(plan.answer(Some("2")), Direction::Inactive);
        assert_eq!(other_law(CodecFamily::Opus), None);
        assert_eq!(other_law(CodecFamily::G722), None);
    }

    #[test]
    fn rfc7587_an_opus_camera_takes_opus_only_and_the_off_reasons_stay() {
        let opus = Codec::Opus { channels: 2 };
        // An Opus backchannel: Opus, forwarded without a transcode; G.711
        // from the browser is never taken for it.
        let plan = plan_for(DEDICATED, Some(&Codec::Pcmu), Some(&reaching(&opus)));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Opus, true));
        assert_eq!(plan.answered(DEDICATED, "2"), [CodecFamily::Opus]);
        // The downlink m-line keeps what may carry talk-back to it later,
        // and the stream audio's PCMU, which goes down there.
        assert_eq!(
            plan.answered(DEDICATED, "0"),
            [CodecFamily::Opus, CodecFamily::Pcmu]
        );
        assert_eq!(
            talkback_for(&opus, &["PCMU", "PCMA"]),
            Err("the talk-back m-line lists no codec that reaches the backchannel")
        );
        // Talk-back in the stream audio's own codec: listed once.
        let plan = plan_for(DEDICATED, Some(&Codec::Pcmu), Some(&reaching(&Codec::Pcmu)));
        assert_eq!(
            plan.answered(DEDICATED, "2"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus]
        );
        assert_eq!(
            plan.answered(DEDICATED, "0"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus]
        );
        // A backchannel in a codec the uplink chain cannot produce.
        for codec in [
            Codec::G722,
            Codec::H265 {
                vps: None,
                sps: None,
                pps: None,
            },
        ] {
            let plan = plan_for(DEDICATED, Some(&Codec::Pcmu), Some(&reaching(&codec)));
            assert_eq!(
                plan.talkback,
                Talkback::Off("the backchannel takes a codec talk-back cannot feed"),
                "{codec:?}"
            );
        }
        // No backchannel at all.
        let plan = plan_for(DEDICATED, Some(&Codec::Pcmu), None);
        assert_eq!(
            plan.talkback,
            Talkback::Off("the camera offers no backchannel")
        );
    }

    #[test]
    fn one_uplink_per_session_and_the_m_line_roles_follow_the_offered_directions() {
        let pcmu = Codec::Pcmu;
        // A `sendrecv` downlink and a dedicated m-line: talk-back on the
        // dedicated one, the downlink only sends.
        let both = DEDICATED.replacen("a=recvonly", "a=sendrecv", 1);
        let plan = plan_for(&both, Some(&pcmu), Some(&reaching(&pcmu)));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Pcmu, true));
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        assert_eq!(plan.answer(Some("2")), Direction::RecvOnly);
        // No talk-back m-line at all.
        let plan = plan_for(
            DEDICATED
                .split("m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2")
                .next()
                .unwrap(),
            Some(&pcmu),
            Some(&reaching(&pcmu)),
        );
        assert_eq!(plan.talkback, Talkback::NotRequested);
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        // The downlink is the first audio m-line the browser receives on:
        // a `sendonly` or `inactive` one before it is not, nor one without
        // a mid; a second receiving one is idle.
        let offer = "v=0\r\nm=audio 9 x 0\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:i\r\na=inactive\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:t\r\na=sendonly\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:d\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:e\r\na=recvonly\r\na=rtpmap:0 PCMU/8000\r\n";
        let plan = plan_for(offer, Some(&pcmu), Some(&reaching(&pcmu)));
        assert_eq!(plan.downlink, Some("d"), "no attribute: sendrecv");
        assert_eq!(plan.talkback, negotiated("t", CodecFamily::Pcmu, true));
        assert_eq!(plan.answer(Some("d")), Direction::SendOnly);
        assert_eq!(plan.answer(Some("e")), Direction::Inactive);
        assert_eq!(plan.answer(Some("i")), Direction::Inactive);
        // Stream audio the downlink does not list, or none: nothing sent.
        let plan = plan_for(offer, Some(&Codec::Pcma), None);
        assert_eq!(plan.send, None);
        assert_eq!(plan.answer(Some("d")), Direction::Inactive);
        // A `sendrecv` m-line after a `recvonly` downlink requests talk-back
        // too (RFC 8866 §6.7): it comes up there, the downlink only sends.
        let offer = "v=0\r\nm=audio 9 x 0\r\na=mid:d\r\na=recvonly\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:s\r\na=sendrecv\r\na=rtpmap:0 PCMU/8000\r\n";
        let plan = plan_for(offer, Some(&pcmu), Some(&reaching(&pcmu)));
        assert_eq!(plan.downlink, Some("d"));
        assert_eq!(plan.talkback, negotiated("s", CodecFamily::Pcmu, false));
        assert_eq!(plan.answer(Some("d")), Direction::SendOnly);
        assert_eq!(plan.answer(Some("s")), Direction::RecvOnly);
        let plan = plan_for(offer, Some(&pcmu), None);
        assert_eq!(
            plan.talkback,
            Talkback::Off("the camera offers no backchannel")
        );
        // No audio m-line the browser receives on.
        let plan = plan_for("v=0\r\nm=video 9 x 96\r\na=mid:v\r\n", Some(&pcmu), None);
        assert_eq!((plan.downlink, plan.send), (None, None));
        assert_eq!(plan.answer(None), Direction::Inactive);
    }

    #[test]
    fn rfc8829_5_3_1_the_engine_is_offered_each_audio_m_line_as_the_answer_reverses_it() {
        let pcmu = Codec::Pcmu;
        // Nothing to change: the offer as it was, line endings normalized.
        let plan = plan_for(DEDICATED, Some(&pcmu), Some(&reaching(&pcmu)));
        assert_eq!(plan.engine_offer(DEDICATED), DEDICATED);
        // Without a backchannel the talk-back m-line becomes inactive; its
        // other lines, the downlink's formats and the video's, stay.
        let plan = plan_for(DEDICATED, Some(&pcmu), None);
        assert_eq!(
            plan.engine_offer(DEDICATED),
            DEDICATED.replace(
                "a=mid:2\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n",
                "a=mid:2\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=inactive\r\n"
            )
        );
        // Without stream audio the downlink m-line keeps its formats and
        // is offered `inactive`.
        let plan = plan_for(DEDICATED, None, Some(&reaching(&pcmu)));
        assert_eq!(
            plan.engine_offer(DEDICATED),
            DEDICATED.replace(
                "a=mid:0\r\na=recvonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n",
                "a=mid:0\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=inactive\r\n"
            )
        );
        // A `sendrecv` downlink the session only sends on is offered to
        // the engine `recvonly`, which answers it `sendonly`.
        let sendrecv = sendrecv();
        let plan = plan_for(&sendrecv, Some(&pcmu), None);
        let rewritten = plan.engine_offer(&sendrecv);
        assert!(!rewritten.contains("a=sendrecv"), "{rewritten}");
        assert!(
            rewritten.contains("a=rtpmap:8 PCMA/8000\r\na=recvonly\r\nm=video"),
            "{rewritten}"
        );
        // With talk-back on it, as offered.
        let plan = plan_for(&sendrecv, Some(&pcmu), Some(&reaching(&pcmu)));
        assert_eq!(plan.engine_offer(&sendrecv), sendrecv);
        // An m-line without a mid and one without an attribute, which
        // counts as `sendrecv`, are written out `inactive`.
        let offer = "v=0\r\nm=audio 9 x 8\r\na=sendrecv\r\nm=audio 9 x 0\r\na=mid:a\n";
        let plan = plan_for(offer, None, None);
        assert_eq!(
            plan.engine_offer(offer),
            "v=0\r\nm=audio 9 x 8\r\na=inactive\r\nm=audio 9 x 0\r\na=mid:a\r\na=inactive\r\n"
        );
    }

    /// Without the reverse chain (`Registries::uplink` unset), only the
    /// backchannel's own codec reaches it: talk-back is answered in it
    /// alone, every other codec dropped from the talk-back m-line, and
    /// off when the offer does not list it, never answered in a codec no
    /// route takes (RFC 3264 §7).
    #[test]
    fn rfc3264_7_without_the_reverse_chain_talk_back_takes_only_the_backchannel_codec() {
        use CodecFamily::{Opus, Pcmu};
        let offer = talking_in(&["opus", "PCMU", "PCMA", "G722"]);
        let forwarded = |codec: Codec| TalkbackTarget {
            takes: UplinkCodec::of(codec.family()).into_iter().collect(),
            codec,
        };
        for (backchannel, expected) in [(Codec::Pcmu, Pcmu), (Codec::Opus { channels: 2 }, Opus)] {
            let target = forwarded(backchannel);
            let plan = plan_for(&offer, None, Some(&target));
            assert_eq!(plan.talkback, negotiated("2", expected, true));
            assert_eq!(plan.answered(&offer, "2"), [expected]);
            for family in EVERY_CODEC {
                assert_eq!(plan.takes(family), family == expected, "{family:?}");
            }
        }
        // An Opus-only offer to a PCMU camera: nothing reaches it.
        let opus_only = talking_in(&["opus"]);
        let target = forwarded(Codec::Pcmu);
        let plan = plan_for(&opus_only, None, Some(&target));
        assert_eq!(
            plan.talkback,
            Talkback::Off("the talk-back m-line lists no codec that reaches the backchannel")
        );
        // A backchannel no uplink codec reaches is off whatever its codec.
        let none = TalkbackTarget {
            codec: Codec::Pcmu,
            takes: Vec::new(),
        };
        assert_eq!(
            plan_for(&offer, None, Some(&none)).talkback,
            Talkback::Off("the backchannel takes a codec talk-back cannot feed")
        );
    }

    /// The offered-codec matrix of a dedicated talk-back m-line that lists
    /// Opus, PCMU, PCMA and G.722: for each backchannel and stream audio,
    /// the answer lists only codecs that reach the camera there,
    /// talk-back's first, which the browser sends (RFC 3264 §7); the
    /// downlink m-line keeps those and the stream audio's codec.
    #[test]
    fn rfc3264_7_a_dedicated_talk_back_m_line_lists_only_codecs_that_reach_the_camera() {
        use CodecFamily::{G722, Opus, Pcma, Pcmu};
        let offer = talking_in(&["opus", "PCMU", "PCMA", "G722"]);
        let opus = Codec::Opus { channels: 2 };
        for (backchannel, audio, expected) in [
            (Codec::Pcmu, Some(&opus), &[Pcmu, Pcma, Opus][..]),
            (Codec::Pcmu, Some(&Codec::Pcmu), &[Pcmu, Pcma, Opus]),
            (Codec::Pcmu, None, &[Pcmu, Pcma, Opus]),
            (Codec::Pcma, Some(&opus), &[Pcma, Pcmu, Opus]),
            (Codec::Pcma, Some(&Codec::Pcmu), &[Pcma, Pcmu, Opus]),
            (Codec::Pcma, None, &[Pcma, Pcmu, Opus]),
            // The finding's case: PCMU down, Opus up; PCMU is not listed
            // for talk-back, nor G.722 without stream audio.
            (opus.clone(), Some(&opus), &[Opus]),
            (opus.clone(), Some(&Codec::Pcmu), &[Opus]),
            (opus.clone(), None, &[Opus]),
        ] {
            let what = format!("{backchannel:?} up, {audio:?} down");
            let plan = plan_for(&offer, audio, Some(&reaching(&backchannel)));
            assert_eq!(plan.answered(&offer, "2"), expected, "{what}");
            // The downlink m-line is answered with what it offers (no
            // G.722 there) that reaches the camera, and the stream
            // audio's codec, in the engine's order.
            let offered_down: Vec<CodecFamily> =
                engine_codecs(Some(backchannel.family()), audio.map(Codec::family))
                    .into_iter()
                    .filter(|family| {
                        *family != G722
                            && (routable(*family, &backchannel)
                                || audio.map(Codec::family) == Some(*family))
                    })
                    .collect();
            assert_eq!(plan.answered(&offer, "0"), offered_down, "{what}");
            // The engine is never offered a codec talk-back does not take
            // on that m-line, nor its attribute lines.
            let engine = plan.engine_offer(&offer);
            let sdp = Sdp::parse(&engine);
            let talkback = with_mid(&sdp, "2");
            for family in EVERY_CODEC {
                assert_eq!(
                    lists(talkback, family),
                    routable(family, &backchannel),
                    "{what}: {family:?} in {engine}"
                );
            }
            assert!(
                talkback.formats().all(|pt| talkback
                    .attribute("rtpmap")
                    .any(|rtpmap| rtpmap.starts_with(&format!("{pt} ")))),
                "{what}: {engine}"
            );
            // Opus reaches every backchannel: its a=fmtp and a=rtcp-fb stay.
            for line in [
                "a=fmtp:111 minptime=10;useinbandfec=1",
                "a=rtcp-fb:111 transport-cc",
            ] {
                assert!(talkback.lines().contains(&line), "{what}: {engine}");
            }
            // The video m-line as offered.
            let offered = Sdp::parse(&offer);
            assert_eq!(
                with_mid(&sdp, "1").m_line(),
                with_mid(&offered, "1").m_line(),
                "{what}"
            );
            assert!(
                with_mid(&sdp, "1")
                    .attribute("rtpmap")
                    .eq(with_mid(&offered, "1").attribute("rtpmap")),
                "{what}"
            );
        }
    }

    /// A `sendrecv` m-line that carries the downlink and talk-back lists
    /// the codecs that reach the camera, the stream audio's among them,
    /// which the session sends there, so one codec goes both ways
    /// (RFC 3264 §6.1); talk-back's comes first, which the browser sends
    /// (RFC 3264 §7).
    #[test]
    fn rfc3264_6_1_a_shared_sendrecv_m_line_keeps_the_stream_audio_beside_talk_back() {
        use CodecFamily::{Opus, Pcma, Pcmu};
        let offer = shared_in(&["opus", "PCMU", "PCMA", "G722"]);
        let opus = Codec::Opus { channels: 2 };
        for (backchannel, audio, expected) in [
            (Codec::Pcmu, Some(&opus), &[Pcmu, Pcma, Opus][..]),
            (Codec::Pcmu, Some(&Codec::Pcmu), &[Pcmu, Pcma, Opus]),
            (Codec::Pcmu, Some(&Codec::Pcma), &[Pcmu, Pcma, Opus]),
            (Codec::Pcmu, None, &[Pcmu, Pcma, Opus]),
            (opus.clone(), Some(&opus), &[Opus]),
            (opus.clone(), None, &[Opus]),
        ] {
            let what = format!("{backchannel:?} up, {audio:?} down");
            let plan = plan_for(&offer, audio, Some(&reaching(&backchannel)));
            assert_eq!(
                plan.talkback,
                negotiated("0", backchannel.family(), false),
                "{what}"
            );
            assert_eq!(plan.answered(&offer, "0"), expected, "{what}");
            let send = audio.map(Codec::family);
            for family in EVERY_CODEC {
                assert_eq!(
                    plan.takes(family),
                    routable(family, &backchannel),
                    "{what}: {family:?}"
                );
                let listed = lists(
                    with_mid(&Sdp::parse(&plan.engine_offer(&offer)), "0"),
                    family,
                );
                assert_eq!(
                    listed,
                    plan.takes(family) || send == Some(family),
                    "{what}: {family:?}"
                );
            }
            assert!(send.is_none_or(|sent| plan.takes(sent)), "{what}");
        }
        // A `sendrecv` m-line after the downlink one carries talk-back
        // alone: the stream audio's goes down elsewhere and is dropped
        // there like any other codec talk-back does not take.
        let offer = "v=0\r\nm=audio 9 x 0 111\r\na=mid:d\r\na=recvonly\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:111 opus/48000/2\r\nm=audio 9 x 111 0\r\na=mid:s\r\na=sendrecv\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\n";
        let plan = plan_for(offer, Some(&Codec::Pcmu), Some(&reaching(&opus)));
        assert_eq!(plan.talkback, negotiated("s", Opus, false));
        assert_eq!(plan.answered(offer, "s"), [Opus]);
        assert_eq!(plan.answered(offer, "d"), [Opus, Pcmu], "as offered");
        assert_eq!(
            plan.engine_offer(offer),
            "v=0\r\nm=audio 9 x 0 111\r\na=mid:d\r\na=recvonly\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:111 opus/48000/2\r\nm=audio 9 x 111\r\na=mid:s\r\na=rtpmap:111 opus/48000/2\r\na=sendonly\r\n"
        );
    }

    /// A `sendrecv` m-line that carries the downlink, whose stream audio's
    /// codec does not reach the camera (G.711 down to an Opus backchannel,
    /// G.722 down to a G.711 one), has no codec the session both sends
    /// and receives there, which an m-line answered `sendrecv` must list
    /// (RFC 3264 §6.1): talk-back is off with the reason, whoever holds
    /// the backchannel, and the m-line is answered `sendonly` (RFC 3264
    /// §6.1 lets a `sendrecv` offer be answered so), so the stream's audio
    /// still goes down, with the stream audio's codec and those that
    /// reach the camera. A dedicated `sendonly` m-line of the same offer
    /// gets talk-back.
    #[test]
    fn rfc3264_6_1_a_shared_m_line_whose_stream_audio_cannot_come_back_is_answered_sendonly() {
        const ONE_WAY: &str = "the stream audio's codec on its sendrecv m-line does not reach the backchannel; talk-back needs a sendonly m-line";
        let offer = shared_in(&["opus", "PCMU", "PCMA", "G722"]);
        let opus = Codec::Opus { channels: 2 };
        for (backchannel, audio) in [
            (opus.clone(), Codec::Pcmu),
            (opus.clone(), Codec::Pcma),
            (opus, Codec::G722),
            (Codec::Pcmu, Codec::G722),
            (Codec::Pcma, Codec::G722),
        ] {
            let what = format!("{backchannel:?} up, {audio:?} down");
            let target = reaching(&backchannel);
            let order = engine_codecs(Some(backchannel.family()), Some(audio.family()));
            for claim in [TalkbackClaim::Granted, TalkbackClaim::Busy] {
                let plan = AudioPlan::new(&offer, Some(&audio), Some(&target), claim, &order);
                assert_eq!(plan.talkback, Talkback::Off(ONE_WAY), "{what}");
                assert_eq!(plan.send, Some(audio.family()), "{what}");
                assert_eq!(plan.answer(Some("0")), Direction::SendOnly, "{what}");
                for family in EVERY_CODEC {
                    assert!(!plan.takes(family), "{what}: {family:?}");
                }
                // Offered to the engine `recvonly`, without what neither
                // goes down nor reaches the camera.
                let engine = plan.engine_offer(&offer);
                let sdp = Sdp::parse(&engine);
                assert_eq!(
                    Direction::of(with_mid(&sdp, "0")),
                    Direction::RecvOnly,
                    "{what}"
                );
                let down: Vec<CodecFamily> = order
                    .iter()
                    .copied()
                    .filter(|family| routable(*family, &backchannel) || *family == audio.family())
                    .collect();
                assert_eq!(plan.answered(&offer, "0"), down, "{what}");
            }
            // Talk-back on a dedicated m-line beside it is negotiated.
            let both = talking_in(&["opus", "PCMU", "PCMA", "G722"]).replacen(
                "a=recvonly",
                "a=sendrecv",
                1,
            );
            let plan = plan_for(&both, Some(&audio), Some(&target));
            assert!(
                matches!(
                    plan.talkback,
                    Talkback::Negotiated {
                        mid: "2",
                        dedicated: true,
                        ..
                    }
                ),
                "{what}"
            );
            assert_eq!(plan.answer(Some("2")), Direction::RecvOnly, "{what}");
            // The downlink sends what it lists (no G.722 there).
            let sends = audio.family() != CodecFamily::G722;
            assert_eq!(
                plan.answer(Some("0")),
                Direction::new(sends, false),
                "{what}"
            );
        }
    }

    /// The formats str0m reads on the talk-back m-line are the ones
    /// narrowed: static payload types listed without an `a=rtpmap`
    /// (RFC 3551 §6, Table 4) and an `a=rtpmap` the format list leaves
    /// out. A format of no codec the engine carries stays (the engine
    /// answers none), and so does a wildcard `a=rtcp-fb`.
    #[test]
    fn rfc3551_6_static_payload_types_and_unlisted_rtpmaps_are_narrowed_too() {
        let offer = "v=0\r\nm=audio 9 x 111 9 0 13 101\r\na=mid:t\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=rtcp-fb:* nack\r\na=fmtp:9\r\n";
        let plan = plan_for(offer, None, Some(&reaching(&Codec::Opus { channels: 2 })));
        assert_eq!(plan.talkback, negotiated("t", CodecFamily::Opus, true));
        assert_eq!(
            plan.engine_offer(offer),
            "v=0\r\nm=audio 9 x 111 13 101\r\na=mid:t\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=rtcp-fb:* nack\r\n"
        );
        assert_eq!(encoding_family("opus"), None, "no clock rate");
        assert_eq!(encoding_family("pcma/8000"), Some(CodecFamily::Pcma));
        assert_eq!(encoding_family("telephone-event/8000"), None);
        assert!(describes("a=rtcp-fb:9 nack", &[9]));
        assert!(!describes("a=rtcp-fb:90 nack", &[9]));
        assert!(!describes("a=mid:9", &[9]));
        assert_eq!(without_formats("m=audio 9 x 0 8", &[0, 8]), "m=audio 9 x");
        assert_eq!(without_formats("m=audio 9 x 0 8", &[]), "m=audio 9 x 0 8");
    }

    /// An m-line that carries no talk-back keeps of the formats it offers
    /// those talk-back could arrive in (RFC 3264 §6.1: an answer lists
    /// formats of the offer), as the engine keeps them for a later
    /// re-offer ([`AudioPlan::kept`]): those that reach the backchannel,
    /// or without one any of an uplink codec; and every one when none of
    /// them is, so it still lists one.
    #[test]
    fn rfc3264_6_1_m_lines_without_talk_back_keep_the_formats_talk_back_could_arrive_in() {
        let opus = Codec::Opus { channels: 2 };
        let offer = talking_in(&["opus", "PCMU", "PCMA", "G722"]);
        // No backchannel, or one talk-back cannot feed: the talk-back
        // m-line is inactive with what any uplink codec is, no G.722.
        for backchannel in [None, Some(&Codec::G722)] {
            let plan = plan_for(
                &offer,
                Some(&Codec::Pcmu),
                backchannel.map(reaching).as_ref(),
            );
            assert!(!plan.takes(CodecFamily::Pcmu), "{backchannel:?}");
            let engine = plan.engine_offer(&offer);
            assert!(
                engine.contains("m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2\r\n"),
                "{engine}"
            );
            assert!(!engine.contains("a=rtpmap:9 G722/8000\r\n"), "{engine}");
            let uplink: Vec<CodecFamily> =
                engine_codecs(backchannel.map(Codec::family), Some(CodecFamily::Pcmu))
                    .into_iter()
                    .filter(|family| *family != CodecFamily::G722)
                    .collect();
            assert_eq!(plan.answered(&offer, "2"), uplink, "inactive");
        }
        // A talk-back m-line that lists nothing talk-back takes: off, and
        // inactive with that, its one format kept.
        let g722 = talking_in(&["G722"]);
        let plan = plan_for(&g722, None, Some(&reaching(&opus)));
        assert!(!plan.takes(CodecFamily::Opus));
        assert_eq!(plan.answered(&g722, "2"), [CodecFamily::G722]);
        assert_eq!(plan.engine_offer(&g722).matches("G722").count(), 1);
        // A downlink m-line keeps the stream audio's G.722, which goes
        // down there, beside what reaches the camera; without stream
        // audio, only those.
        let down = shared_in(&["opus", "PCMU", "PCMA", "G722"]).replace("a=sendrecv", "a=recvonly");
        let pcmu = reaching(&Codec::Pcmu);
        let plan = plan_for(&down, Some(&Codec::G722), Some(&pcmu));
        assert_eq!(
            plan.answered(&down, "0"),
            [
                CodecFamily::Pcmu,
                CodecFamily::Pcma,
                CodecFamily::Opus,
                CodecFamily::G722
            ]
        );
        let plan = plan_for(&down, None, Some(&pcmu));
        assert_eq!(
            plan.answered(&down, "0"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus]
        );
    }

    /// The stream's audio goes down a downlink m-line the engine answered
    /// before only in a codec it kept, as the engine answers it with those
    /// and the session sends only a format the answer lists (RFC 3264
    /// §6.1): without one, the m-line carries no stream audio and is
    /// answered without sending. An m-line never answered keeps the
    /// plan's codec, and a plan without a downlink or without stream audio
    /// on it asks for nothing.
    #[test]
    fn rfc3264_6_1_stream_audio_goes_down_a_kept_m_line_only_in_a_codec_it_kept() {
        use CodecFamily::{Opus, Pcma, Pcmu};
        let pcmu = Codec::Pcmu;
        let plan = |kept: &[CodecFamily]| {
            plan_for(DEDICATED, Some(&pcmu), None).kept_downlink(|mid| {
                assert_eq!(mid, "0", "asked for the downlink m-line");
                kept.to_vec()
            })
        };
        let off = plan(&[Opus, Pcma]);
        assert_eq!(off.send, None);
        assert_eq!(off.answer(Some("0")), Direction::Inactive);
        let engine = off.engine_offer(DEDICATED);
        let sdp = Sdp::parse(&engine);
        assert_eq!(Direction::of(with_mid(&sdp, "0")), Direction::Inactive);
        for kept in [&[Opus, Pcmu][..], &[]] {
            let on = plan(kept);
            assert_eq!(on.send, Some(Pcmu), "{kept:?}");
            assert_eq!(on.answer(Some("0")), Direction::SendOnly, "{kept:?}");
        }
        // Without a downlink or stream audio on it: nothing is asked; with
        // both, the downlink m-line only.
        let mut asked = Vec::new();
        let mut ask = |mid: &str| {
            asked.push(mid.to_owned());
            [Pcmu]
        };
        let no_downlink = DEDICATED.replacen("a=recvonly", "a=inactive", 1);
        let plan = plan_for(&no_downlink, Some(&pcmu), None).kept_downlink(&mut ask);
        assert_eq!((plan.downlink, plan.send), (None, None));
        for audio in [None, Some(&Codec::G722)] {
            let plan = plan_for(DEDICATED, audio, None).kept_downlink(&mut ask);
            assert_eq!((plan.downlink, plan.send), (Some("0"), None), "{audio:?}");
        }
        let plan = plan_for(DEDICATED, Some(&pcmu), None).kept_downlink(&mut ask);
        assert_eq!(plan.send, Some(Pcmu));
        assert_eq!(asked, ["0"]);
    }
}
