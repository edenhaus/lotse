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
//! route cannot take would lose the talker's audio.
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
use lotse_core::session::{TalkbackClaim, TalkbackTarget};

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

/// The audio family the engine carries that an `a=rtpmap` encoding
/// (`<name>/<clock>[/<channels>]`, RFC 8866 §6.6) names: its encoding
/// name, case-insensitive (RFC 4855 §3), at its RTP clock rate; `None`
/// for any other codec. The engine matches the rest.
fn encoding_family(encoding: &str) -> Option<CodecFamily> {
    let mut parts = encoding.split('/');
    let name = parts.next()?;
    let clock = parts.next().and_then(|clock| clock.parse::<u32>().ok())?;
    EVERY_CODEC.into_iter().find(|family| {
        encoding_name(*family).is_some_and(|known| known.eq_ignore_ascii_case(name))
            && clock_rate(*family) == clock
    })
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
/// m-line offers (there is no list per m-line, an upstream need), so
/// [`AudioPlan::engine_offer`] narrows each m-line's formats, and the
/// order puts the codec talk-back is received in first on the
/// talk-back m-line, which the browser sends (RFC 3264 §7): the
/// backchannel's own, else the other law, else Opus
/// ([`AudioPlan::new`]). Without a backchannel the stream audio's codec
/// comes first, so the downlink m-line names first the codec the session
/// sends on it, the default format of the m-line (RFC 8866 §5.14: the
/// first format listed SHOULD be the session's default). Every codec is
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
    /// §6.1).
    Busy,
    /// Not requested: no audio m-line with a mid the browser offers to
    /// send on.
    NotRequested,
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
        let lines: Vec<(&Section<'a>, &'a str, Direction)> = sdp
            .media()
            .iter()
            .filter(|section| section.is("audio") && !sdp.stopped(section))
            .filter_map(|section| Some((section, section.mid()?, Direction::of(section))))
            .collect();
        let downlink = lines.iter().find(|(_, _, offered)| offered.receives());
        let send = audio
            .map(Codec::family)
            .filter(|family| downlink.is_some_and(|(section, _, _)| lists(section, *family)));
        let dedicated = lines
            .iter()
            .find(|(_, _, offered)| *offered == Direction::SendOnly);
        let uplink = dedicated.map(|line| (line, true)).or_else(|| {
            lines
                .iter()
                .find(|(_, _, offered)| *offered == Direction::SendRecv)
                .map(|line| (line, false))
        });
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
                match [Some(family), other_law(family), Some(CodecFamily::Opus)]
                    .into_iter()
                    .flatten()
                    .find(|family| reaching.contains(family) && lists(section, *family))
                {
                    Some(_) if claim == TalkbackClaim::Busy => Talkback::Busy,
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

    /// The payload types of `section` the engine is not offered: on the
    /// talk-back m-line, those of an audio codec the engine carries that
    /// talk-back does not take ([`AudioPlan::takes`]), and of one it
    /// takes but the engine prefers to the codec talk-back is received
    /// in (before it in the engine's order, which was fixed for the
    /// backchannel the session opened with and may not fit the one a
    /// re-offer meets), but for the stream audio's when that m-line is
    /// the downlink too; none on any other m-line: a downlink m-line
    /// keeps every codec it offers, so a re-offer that turns it
    /// `sendrecv` can still name any of them (a subsequent offer lists
    /// the codecs negotiated, RFC 8829 §5.2.2). A format is read by its `a=rtpmap`, else as a static
    /// payload type (RFC 3551 §6, Table 4), the way str0m reads it, which
    /// also reads an `a=rtpmap` the format list leaves out. Formats of no
    /// codec the engine carries stay: the engine answers none of them.
    ///
    /// Talk-back's own codec is always taken and listed, so the m-line
    /// keeps a format.
    ///
    /// `SPEC-DEVIATION` (RFC 3264 §6.1: an m-line answered `sendrecv`
    /// lists at least one codec the answerer both sends and receives):
    /// on a `sendrecv` m-line that carries both, a stream audio codec
    /// that does not reach the camera (G.711 or G.722 to an Opus
    /// backchannel, G.722 to a G.711 one) stays listed beside talk-back's,
    /// since the session sends it there, and an m-line has one format list
    /// for both directions. The session then sends one codec and receives
    /// another, neither both ways. Dropping either would lose the stream's
    /// audio or talk-back, and no uplink chain produces Opus from G.711.
    /// The browser sends talk-back's, first in the answer (RFC 3264 §7);
    /// a packet in the other is refused on receipt, never routed. The
    /// stream audio's codec also stays where the engine prefers it to
    /// talk-back's, and the browser then sends it when the session can
    /// take it (the Opus of an Opus stream to a G.711 backchannel, after
    /// a re-offer on a session that opened with an Opus backchannel).
    fn unroutable(&self, section: &Section<'_>) -> Vec<u8> {
        if !section.is("audio") {
            return Vec::new();
        }
        let Talkback::Negotiated { mid, codec, .. } = self.talkback else {
            return Vec::new();
        };
        if section.mid() != Some(mid) {
            return Vec::new();
        }
        let sent = self.send.filter(|_| self.downlink == Some(mid));
        let preferred = self
            .order
            .iter()
            .position(|family| *family == codec)
            .unwrap_or_default();
        formats_of(section, |family| {
            let before = self.order.get(..preferred).unwrap_or_default();
            (!self.takes(family) || before.contains(&family)) && Some(family) != sent
        })
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
    /// or the engine would prefer ([`AudioPlan::unroutable`]), with their
    /// `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` lines: str0m answers an m-line
    /// with the codecs it is configured with that the offered m-line
    /// lists, and has one list for all m-lines ([`engine_codecs`]), so
    /// only the offer narrows one m-line. An answer lists formats of the
    /// offer (RFC 3264 §6.1), and the browser may send any it lists
    /// (RFC 3264 §7).
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
    /// the session cannot receive on (RFC 3264 §6.1), the codecs listed
    /// as offered, and nothing is taken; what the backchannel would not
    /// take anyway keeps its own reason.
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
        assert_eq!(busy.talkback, Talkback::Busy);
        assert_eq!(busy.answer(Some("2")), Direction::Inactive);
        assert_eq!(busy.answer(Some("0")), Direction::SendOnly);
        assert!(!busy.takes(CodecFamily::Pcmu));
        assert_eq!(
            busy.answered(DEDICATED, "2"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus],
            "as offered"
        );
        let sendrecv = sendrecv();
        let busy = AudioPlan::new(
            &sendrecv,
            Some(&opus),
            Some(&pcmu),
            TalkbackClaim::Busy,
            &order,
        );
        assert_eq!(busy.talkback, Talkback::Busy);
        assert_eq!(busy.answer(Some("0")), Direction::SendOnly);
        assert_eq!(
            busy.answered(&sendrecv, "0"),
            [CodecFamily::Pcmu, CodecFamily::Pcma, CodecFamily::Opus],
            "as offered"
        );
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
        assert_eq!(
            plan.answered(DEDICATED, "0"),
            [CodecFamily::Opus, CodecFamily::Pcmu, CodecFamily::Pcma]
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
    /// downlink m-line keeps its own list.
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
            // G.722 there) in the engine's order, the stream audio's
            // codec among them.
            let offered_down: Vec<CodecFamily> =
                engine_codecs(Some(backchannel.family()), audio.map(Codec::family))
                    .into_iter()
                    .filter(|family| *family != G722)
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
    /// the codecs that reach the camera and the stream audio's, which the
    /// session sends there. When the stream audio's does not reach the
    /// camera it stays all the same (the `SPEC-DEVIATION` of
    /// [`AudioPlan::unroutable`]), after talk-back's, which the browser
    /// sends (RFC 3264 §7).
    #[test]
    fn rfc3264_6_1_a_shared_sendrecv_m_line_keeps_the_stream_audio_beside_talk_back() {
        use CodecFamily::{G722, Opus, Pcma, Pcmu};
        let offer = shared_in(&["opus", "PCMU", "PCMA", "G722"]);
        let opus = Codec::Opus { channels: 2 };
        for (backchannel, audio, expected) in [
            (Codec::Pcmu, Some(&opus), &[Pcmu, Pcma, Opus][..]),
            (Codec::Pcmu, Some(&Codec::Pcmu), &[Pcmu, Pcma, Opus]),
            (Codec::Pcmu, None, &[Pcmu, Pcma, Opus]),
            (opus.clone(), Some(&opus), &[Opus]),
            (opus.clone(), None, &[Opus]),
            // The residual cases: sent down, not taken up.
            (opus.clone(), Some(&Codec::Pcmu), &[Opus, Pcmu]),
            (Codec::Pcma, Some(&Codec::G722), &[Pcma, Pcmu, Opus, G722]),
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

    /// m-lines that carry no talk-back keep every format they offer, so an
    /// `inactive` one still lists formats of the offer (RFC 3264 §6.1).
    #[test]
    fn rfc3264_6_1_m_lines_without_talk_back_keep_their_formats() {
        let opus = Codec::Opus { channels: 2 };
        let offer = talking_in(&["opus", "PCMU", "PCMA", "G722"]);
        // No backchannel, or one talk-back cannot feed: the talk-back
        // m-line is inactive with what it offered.
        for backchannel in [None, Some(&Codec::G722)] {
            let plan = plan_for(
                &offer,
                Some(&Codec::Pcmu),
                backchannel.map(reaching).as_ref(),
            );
            assert!(!plan.takes(CodecFamily::Pcmu), "{backchannel:?}");
            let engine = plan.engine_offer(&offer);
            assert!(
                engine.contains("m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8 9\r\na=mid:2\r\n"),
                "{engine}"
            );
            assert!(engine.contains("a=rtpmap:9 G722/8000\r\n"), "{engine}");
            assert_eq!(
                plan.answered(&offer, "2"),
                engine_codecs(backchannel.map(Codec::family), Some(CodecFamily::Pcmu)),
                "inactive, with every format of the offer"
            );
        }
        // A talk-back m-line that lists nothing talk-back takes: off, and
        // inactive with that.
        let g722 = talking_in(&["G722"]);
        let plan = plan_for(&g722, None, Some(&reaching(&opus)));
        assert!(!plan.takes(CodecFamily::Opus));
        assert_eq!(plan.answered(&g722, "2"), [CodecFamily::G722]);
        assert_eq!(plan.engine_offer(&g722).matches("G722").count(), 1);
    }
}
