//! The offer's audio m-lines: the one the stream's audio goes down on,
//! the one talk-back comes up on, the direction each is answered with and
//! the audio codecs the engine is configured with.
//!
//! A pure function of the offer, the stream's audio codec and the codec of
//! its backchannel, never of whether another session talks: the talker is
//! claimed by the first uplink packet, not by the SDP.
//!
//! Standards: RFC 8866 §6.7 (direction attributes, `sendrecv` when an
//! m-line has none) and §6.6 (`a=rtpmap`), RFC 4855 §3 (encoding names
//! compare case-insensitively), RFC 8829 §5.3.1 (an answer's direction is
//! the offered one reversed, intersected with what the answerer does),
//! RFC 3264 §6.1 (an m-line answered `inactive` keeps its place and lists
//! formats of the offer).

use lotse_core::codec::{Codec, CodecFamily};

use crate::sdp::{Sdp, Section};

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
    fn of(section: &Section<'_>) -> Self {
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

/// Whether `section` lists `family` in an `a=rtpmap` (RFC 8866 §6.6): its
/// encoding name, case-insensitive (RFC 4855 §3), and RTP clock rate. The
/// engine matches the rest.
fn lists(section: &Section<'_>, family: CodecFamily) -> bool {
    let Some(name) = encoding_name(family) else {
        return false;
    };
    let clock = clock_rate(family);
    section
        .attribute("rtpmap")
        .filter_map(|rtpmap| rtpmap.split_once(' '))
        .any(|(_, encoding)| {
            let mut parts = encoding.split('/');
            parts.next().is_some_and(|n| n.eq_ignore_ascii_case(name))
                && parts.next().and_then(|c| c.parse::<u32>().ok()) == Some(clock)
        })
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
        /// sends (RFC 3264 §6.1).
        codec: CodecFamily,
        /// A dedicated talk-back m-line rather than the downlink one.
        dedicated: bool,
    },
    /// Not negotiated, and why.
    Off(&'static str),
}

/// What the session does with the offer's audio m-lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AudioPlan<'a> {
    /// The m-line the stream's audio goes down on: the first audio m-line
    /// with a mid that the browser receives on (`recvonly` or
    /// `sendrecv`).
    pub(crate) downlink: Option<&'a str>,
    /// The stream audio's family, when the engine carries it and the
    /// downlink m-line lists it.
    pub(crate) send: Option<CodecFamily>,
    /// Where talk-back comes up.
    pub(crate) talkback: Talkback<'a>,
}

impl<'a> AudioPlan<'a> {
    /// The plan for `offer`, the stream's audio codec (`audio`) and its
    /// backchannel's (`backchannel`).
    ///
    /// Talk-back goes on the first audio m-line the browser offers
    /// `sendonly` (the dedicated one), or else on a `sendrecv` downlink
    /// m-line, never on both: a session has one uplink. It takes the
    /// backchannel's codec when that m-line lists it (G.711 from the
    /// browser, no transcode), else Opus; a backchannel in another codec
    /// is one no uplink chain feeds.
    pub(crate) fn new(offer: &'a str, audio: Option<&Codec>, backchannel: Option<&Codec>) -> Self {
        let sdp = Sdp::parse(offer);
        let lines: Vec<(&Section<'a>, &'a str, Direction)> = sdp
            .media()
            .iter()
            .filter(|section| section.is("audio"))
            .filter_map(|section| Some((section, section.mid()?, Direction::of(section))))
            .collect();
        let downlink = lines.iter().find(|(_, _, offered)| offered.receives());
        let send = audio
            .map(Codec::family)
            .filter(|family| downlink.is_some_and(|(section, _, _)| lists(section, *family)));
        let dedicated = lines
            .iter()
            .find(|(_, _, offered)| *offered == Direction::SendOnly);
        let uplink = match (dedicated, downlink) {
            (Some(line), _) => Some((line, true)),
            (None, Some(line)) if line.2 == Direction::SendRecv => Some((line, false)),
            _ => None,
        };
        let talkback = match (uplink, backchannel.map(Codec::family)) {
            (None, _) => Talkback::Off("the offer has no talk-back m-line"),
            (Some(_), None) => Talkback::Off("the stream has no backchannel"),
            (Some(_), Some(family))
                if !matches!(
                    family,
                    CodecFamily::Opus | CodecFamily::Pcmu | CodecFamily::Pcma
                ) =>
            {
                Talkback::Off("the backchannel takes a codec talk-back cannot feed")
            }
            (Some(((section, mid, _), dedicated)), Some(family)) => {
                match [family, CodecFamily::Opus]
                    .into_iter()
                    .find(|family| lists(section, *family))
                {
                    Some(codec) => Talkback::Negotiated {
                        mid,
                        codec,
                        dedicated,
                    },
                    None => Talkback::Off(
                        "the talk-back m-line lists neither the backchannel's codec nor Opus",
                    ),
                }
            }
        };
        Self {
            downlink: downlink.map(|(_, mid, _)| *mid),
            send,
            talkback,
        }
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
            push(section.m_line());
            for line in section.lines() {
                if rewrite.is_none() || Direction::parse(line).is_none() {
                    push(line);
                }
            }
            if let Some(wanted) = rewrite {
                push(wanted.attribute());
            }
        }
        out
    }

    /// The audio codecs the engine is configured with, in its order of
    /// preference: talk-back's first, then the stream audio's, or every
    /// codec the engine carries when it sends none (so an `inactive`
    /// m-line still lists formats of the offer, RFC 3264 §6.1, instead of
    /// being rejected for lack of one).
    ///
    /// str0m answers every m-line with this one list, narrowed to what
    /// that m-line offers, in this order: there is no list per m-line (an
    /// upstream need).
    /// Talk-back's codec first makes it the first on the talk-back m-line,
    /// the one the browser sends (RFC 3264 §6.1); on the downlink m-line
    /// it is listed beside the stream audio's, which is what the session
    /// sends.
    pub(crate) fn codecs(&self) -> Vec<CodecFamily> {
        let mut codecs = Vec::with_capacity(EVERY_CODEC.len());
        if let Talkback::Negotiated { codec, .. } = self.talkback {
            codecs.push(codec);
        }
        let rest = match self.send {
            Some(send) => &[send][..],
            None => &EVERY_CODEC[..],
        };
        for family in rest {
            if !codecs.contains(family) {
                codecs.push(*family);
            }
        }
        codecs
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

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
        let plan = AudioPlan::new(DEDICATED, Some(&opus), Some(&Codec::Pcmu));
        assert_eq!(plan.downlink, Some("0"));
        assert_eq!(plan.send, Some(CodecFamily::Opus));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Pcmu, true));
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        assert_eq!(plan.answer(Some("2")), Direction::RecvOnly);
        assert_eq!(plan.answer(Some("1")), Direction::Inactive, "not audio's");
        assert_eq!(plan.answer(None), Direction::Inactive);
        assert_eq!(
            plan.codecs(),
            [CodecFamily::Pcmu, CodecFamily::Opus],
            "talk-back's first"
        );
        // Dedicated, without a backchannel: inactive.
        let plan = AudioPlan::new(DEDICATED, Some(&opus), None);
        assert_eq!(
            plan.talkback,
            Talkback::Off("the stream has no backchannel")
        );
        assert_eq!(plan.answer(Some("2")), Direction::Inactive);
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        assert_eq!(plan.codecs(), [CodecFamily::Opus]);
        // `sendrecv` downlink, with a backchannel: `sendrecv`, talk-back in
        // the backchannel's codec on the downlink m-line.
        let plan = AudioPlan::new(&sendrecv, Some(&opus), Some(&Codec::Pcma));
        assert_eq!(plan.talkback, negotiated("0", CodecFamily::Pcma, false));
        assert_eq!(plan.answer(Some("0")), Direction::SendRecv);
        assert_eq!(plan.codecs(), [CodecFamily::Pcma, CodecFamily::Opus]);
        // `sendrecv` downlink, without one: `sendonly`.
        let plan = AudioPlan::new(&sendrecv, Some(&opus), None);
        assert_eq!(
            plan.talkback,
            Talkback::Off("the stream has no backchannel")
        );
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        // A downlink that carries no stream audio still takes talk-back
        // (`recvonly`), or is `inactive` without a backchannel.
        let plan = AudioPlan::new(&sendrecv, None, Some(&Codec::Pcmu));
        assert_eq!(plan.send, None);
        assert_eq!(plan.answer(Some("0")), Direction::RecvOnly);
        assert_eq!(
            plan.codecs(),
            [
                CodecFamily::Pcmu,
                CodecFamily::Opus,
                CodecFamily::Pcma,
                CodecFamily::G722
            ]
        );
        let plan = AudioPlan::new(&sendrecv, None, None);
        assert_eq!(plan.answer(Some("0")), Direction::Inactive);
        assert_eq!(plan.codecs(), EVERY_CODEC);
    }

    #[test]
    fn talk_back_takes_the_backchannels_codec_else_opus_else_none() {
        let pcmu = Codec::Pcmu;
        // An Opus backchannel: Opus, forwarded without a transcode.
        let plan = AudioPlan::new(DEDICATED, Some(&pcmu), Some(&Codec::Opus { channels: 2 }));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Opus, true));
        assert_eq!(plan.codecs(), [CodecFamily::Opus, CodecFamily::Pcmu]);
        // Talk-back in the stream audio's own codec: listed once.
        let plan = AudioPlan::new(DEDICATED, Some(&pcmu), Some(&pcmu));
        assert_eq!(plan.codecs(), [CodecFamily::Pcmu]);
        // A talk-back m-line without PCMA: Opus, transcoded to PCMA.
        let only_opus = DEDICATED.replacen(
            "m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000",
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:2\r\na=sendonly\r\na=rtpmap:111 opus/48000/2",
            1,
        );
        assert_ne!(only_opus, DEDICATED);
        let plan = AudioPlan::new(&only_opus, Some(&pcmu), Some(&Codec::Pcma));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Opus, true));
        // Neither the backchannel's codec nor Opus: off.
        let only_pcmu = only_opus.replace(
            "111\r\na=mid:2\r\na=sendonly\r\na=rtpmap:111 opus/48000/2",
            "0\r\na=mid:2\r\na=sendonly\r\na=rtpmap:0 PCMU/8000",
        );
        assert_ne!(only_pcmu, only_opus);
        let plan = AudioPlan::new(&only_pcmu, Some(&pcmu), Some(&Codec::Pcma));
        assert_eq!(
            plan.talkback,
            Talkback::Off("the talk-back m-line lists neither the backchannel's codec nor Opus")
        );
        assert_eq!(plan.answer(Some("2")), Direction::Inactive);
        // A backchannel in a codec the uplink chain cannot produce.
        for codec in [
            Codec::G722,
            Codec::H265 {
                vps: None,
                sps: None,
                pps: None,
            },
        ] {
            let plan = AudioPlan::new(DEDICATED, Some(&pcmu), Some(&codec));
            assert_eq!(
                plan.talkback,
                Talkback::Off("the backchannel takes a codec talk-back cannot feed"),
                "{codec:?}"
            );
        }
    }

    #[test]
    fn one_uplink_per_session_and_the_m_line_roles_follow_the_offered_directions() {
        let pcmu = Codec::Pcmu;
        // A `sendrecv` downlink and a dedicated m-line: talk-back on the
        // dedicated one, the downlink only sends.
        let both = DEDICATED.replacen("a=recvonly", "a=sendrecv", 1);
        let plan = AudioPlan::new(&both, Some(&pcmu), Some(&pcmu));
        assert_eq!(plan.talkback, negotiated("2", CodecFamily::Pcmu, true));
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        assert_eq!(plan.answer(Some("2")), Direction::RecvOnly);
        // No talk-back m-line at all.
        let plan = AudioPlan::new(
            DEDICATED
                .split("m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=mid:2")
                .next()
                .unwrap(),
            Some(&pcmu),
            Some(&pcmu),
        );
        assert_eq!(
            plan.talkback,
            Talkback::Off("the offer has no talk-back m-line")
        );
        assert_eq!(plan.answer(Some("0")), Direction::SendOnly);
        // The downlink is the first audio m-line the browser receives on:
        // a `sendonly` or `inactive` one before it is not, nor one without
        // a mid; a second receiving one is idle.
        let offer = "v=0\r\nm=audio 9 x 0\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:i\r\na=inactive\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:t\r\na=sendonly\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:d\r\na=rtpmap:0 PCMU/8000\r\nm=audio 9 x 0\r\na=mid:e\r\na=recvonly\r\na=rtpmap:0 PCMU/8000\r\n";
        let plan = AudioPlan::new(offer, Some(&pcmu), Some(&pcmu));
        assert_eq!(plan.downlink, Some("d"), "no attribute: sendrecv");
        assert_eq!(plan.talkback, negotiated("t", CodecFamily::Pcmu, true));
        assert_eq!(plan.answer(Some("d")), Direction::SendOnly);
        assert_eq!(plan.answer(Some("e")), Direction::Inactive);
        assert_eq!(plan.answer(Some("i")), Direction::Inactive);
        // Stream audio the downlink does not list, or none: nothing sent.
        let plan = AudioPlan::new(offer, Some(&Codec::Pcma), None);
        assert_eq!(plan.send, None);
        assert_eq!(plan.answer(Some("d")), Direction::Inactive);
        // No audio m-line the browser receives on.
        let plan = AudioPlan::new("v=0\r\nm=video 9 x 96\r\na=mid:v\r\n", Some(&pcmu), None);
        assert_eq!((plan.downlink, plan.send), (None, None));
        assert_eq!(plan.answer(None), Direction::Inactive);
    }

    #[test]
    fn rfc8829_5_3_1_the_engine_is_offered_each_audio_m_line_as_the_answer_reverses_it() {
        let pcmu = Codec::Pcmu;
        // Nothing to change: the offer as it was, line endings normalized.
        let plan = AudioPlan::new(DEDICATED, Some(&pcmu), Some(&pcmu));
        assert_eq!(plan.engine_offer(DEDICATED), DEDICATED);
        // Without a backchannel the talk-back m-line becomes inactive; its
        // other lines, and the video's, stay.
        let plan = AudioPlan::new(DEDICATED, Some(&pcmu), None);
        assert_eq!(
            plan.engine_offer(DEDICATED),
            DEDICATED.replace(
                "a=mid:2\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n",
                "a=mid:2\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=inactive\r\n"
            )
        );
        // A `sendrecv` downlink the session only sends on is offered to
        // the engine `recvonly`, which answers it `sendonly`.
        let sendrecv = sendrecv();
        let plan = AudioPlan::new(&sendrecv, Some(&pcmu), None);
        let rewritten = plan.engine_offer(&sendrecv);
        assert!(!rewritten.contains("a=sendrecv"), "{rewritten}");
        assert!(
            rewritten.contains("a=rtpmap:8 PCMA/8000\r\na=recvonly\r\nm=video"),
            "{rewritten}"
        );
        // With talk-back on it, as offered.
        let plan = AudioPlan::new(&sendrecv, Some(&pcmu), Some(&pcmu));
        assert_eq!(plan.engine_offer(&sendrecv), sendrecv);
        // An m-line without a mid and one without an attribute, which
        // counts as `sendrecv`, are written out `inactive`.
        let offer = "v=0\r\nm=audio 9 x 8\r\na=sendrecv\r\nm=audio 9 x 0\r\na=mid:a\n";
        let plan = AudioPlan::new(offer, None, None);
        assert_eq!(
            plan.engine_offer(offer),
            "v=0\r\nm=audio 9 x 8\r\na=inactive\r\nm=audio 9 x 0\r\na=mid:a\r\na=inactive\r\n"
        );
    }
}
