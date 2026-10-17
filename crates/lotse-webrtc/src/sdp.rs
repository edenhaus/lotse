//! The SDP text a session reads, split in one place: the session part and
//! the media sections (RFC 8866 §5), a section's media type, `a=mid`
//! (RFC 5888 §4) and attributes, the BUNDLE groups (RFC 9143 §5), and the
//! payload type check every offer passes before the engine sees it
//! (RFC 9143 §9.1.1; RFC 8866 §6.6 and §6.15; RFC 3551 §6).
//!
//! str0m 0.24 keeps one payload type table per session and asserts that no
//! number is locked twice: an offer that gives one number two codec
//! configurations reaches that assert, and with `panic = "abort"` the
//! camera's worker dies with every viewer on it. [`check_payload_types`]
//! refuses such an offer first. The browser's text its reason quotes is
//! capped (`BROWSER_TEXT_BYTES`): the session logs the reason and the
//! API returns it.

use std::fmt;

/// The most bytes of one piece of the browser's text (a mid, a media type,
/// an encoding, an `a=fmtp` value, a parameter name) a refusal or a log
/// line carries: the session logs a refusal's reason and the API returns
/// it, and the offer may hold any of them at the control API's offer cap.
pub(crate) const BROWSER_TEXT_BYTES: usize = 200;

/// A piece of the browser's `text` as a refusal or a log line carries it:
/// on one line, control characters replaced, cut to [`BROWSER_TEXT_BYTES`].
pub(crate) fn browser_text(text: &str) -> String {
    lotse_core::text::plain(text, BROWSER_TEXT_BYTES)
}

/// An SDP split at its `m=` lines (RFC 8866 §5), each line without its
/// line ending. Borrowed from the text; nothing is validated.
#[derive(Debug)]
pub(crate) struct Sdp<'a> {
    /// The lines before the first `m=` line.
    session: Vec<&'a str>,
    /// The media sections, in order.
    media: Vec<Section<'a>>,
}

/// One media section: its `m=` line and the lines up to the next one.
#[derive(Debug)]
pub(crate) struct Section<'a> {
    /// The `m=` line.
    m_line: &'a str,
    /// The lines after it.
    lines: Vec<&'a str>,
}

impl<'a> Sdp<'a> {
    /// Splits `text`; lines end in LF or CRLF, trailing whitespace is
    /// dropped.
    pub(crate) fn parse(text: &'a str) -> Self {
        let mut session = Vec::new();
        let mut media: Vec<Section<'a>> = Vec::new();
        for line in text.lines().map(str::trim_end) {
            if line.starts_with("m=") {
                media.push(Section {
                    m_line: line,
                    lines: Vec::new(),
                });
            } else if let Some(section) = media.last_mut() {
                section.lines.push(line);
            } else {
                session.push(line);
            }
        }
        Self { session, media }
    }

    /// The lines before the first `m=` line.
    pub(crate) fn session(&self) -> &[&'a str] {
        &self.session
    }

    /// The media sections, in order.
    pub(crate) fn media(&self) -> &[Section<'a>] {
        &self.media
    }

    /// The first media section of `kind` (`audio`, `video`).
    pub(crate) fn first(&self, kind: &str) -> Option<&Section<'a>> {
        self.media.iter().find(|section| section.is(kind))
    }

    /// Whether `section` is stopped: its port is zero (RFC 3264 §8.2: the
    /// stream is disabled; RFC 8829 §5.2.2: the m-line of a stopped
    /// transceiver), unless it is a `bundle-only` one (RFC 9143 §6) that
    /// a BUNDLE group lists (RFC 9143 §5), whose zero port only says it
    /// shares the group's transport. The port is the `m=` line's second
    /// field, without a `/<number of ports>` (RFC 8866 §5.14), and is
    /// zero by its value ([`zero_port`]), so `00` and `000/2` stop an
    /// m-line as `0` does.
    ///
    /// str0m 0.24.0 reads only a literal `0` as a disabled m-line (its
    /// `media_parser` in `sdp/parser.rs`, read 2026-10-17): a zero-padded
    /// port, or one with a number of ports, it would keep live and answer
    /// with a nonzero one, where RFC 3264 §6 answers a zero port with
    /// zero. lotse goes by the value, so the engine never acts on such an
    /// m-line: a re-offer that stops the video one is refused before it,
    /// and a stopped audio one is planned and answered `inactive`
    /// ([`crate::audio::AudioPlan::new`]), its port written `0` in the
    /// offer the engine answers ([`crate::audio::AudioPlan::engine_offer`]).
    pub(crate) fn stopped(&self, section: &Section<'_>) -> bool {
        let zero = section
            .m_line
            .split(' ')
            .nth(1)
            .and_then(|port| port.split('/').next())
            .is_some_and(zero_port);
        let bundled = section.lines.contains(&"a=bundle-only")
            && section.mid().is_some_and(|mid| {
                self.session
                    .iter()
                    .filter_map(|line| line.strip_prefix("a=group:BUNDLE "))
                    .any(|mids| mids.split_whitespace().any(|listed| listed == mid))
            });
        zero && !bundled
    }

    /// Whether one `a=group:BUNDLE` line (RFC 9143 §5) lists both mids.
    fn bundled(&self, a: Option<&str>, b: Option<&str>) -> bool {
        let (Some(a), Some(b)) = (a, b) else {
            return false;
        };
        self.session
            .iter()
            .filter_map(|line| line.strip_prefix("a=group:BUNDLE "))
            .any(|mids| {
                mids.split_whitespace().any(|mid| mid == a)
                    && mids.split_whitespace().any(|mid| mid == b)
            })
    }
}

/// Whether `port`, an `m=` line's port field without its
/// `/<number of ports>`, is port zero. The grammar makes a port
/// `1*DIGIT` (RFC 8866 §9), a decimal number whose leading zeros change
/// nothing: it is zero when it is digits, at least one, all of them `0`.
/// Checking the digits instead of parsing them keeps it total: no
/// overflow on a long run of zeros, and no sign (`+0`, which
/// `str::parse` takes) passes. A field that is no `1*DIGIT` (empty, a
/// sign, a letter) is malformed and not zero, so the m-line is not
/// stopped and is left to the engine, which reads it the same way; a
/// nonzero port out of range (`70000`) is not zero either.
fn zero_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|digit| digit == b'0')
}

impl<'a> Section<'a> {
    /// The `m=` line.
    pub(crate) const fn m_line(&self) -> &'a str {
        self.m_line
    }

    /// The lines after the `m=` line.
    pub(crate) fn lines(&self) -> &[&'a str] {
        &self.lines
    }

    /// Whether the media type is `kind` (`audio`, `video`).
    pub(crate) fn is(&self, kind: &str) -> bool {
        self.m_line
            .strip_prefix("m=")
            .and_then(|rest| rest.strip_prefix(kind))
            .is_some_and(|rest| rest.starts_with(' '))
    }

    /// The media type, the `m=` line's first field (RFC 8866 §5.14).
    fn media_type(&self) -> &'a str {
        let rest = self.m_line.get(2..).unwrap_or_default();
        rest.split(' ').next().unwrap_or_default()
    }

    /// The `a=mid` value (RFC 5888 §4), or `None`.
    pub(crate) fn mid(&self) -> Option<&'a str> {
        self.attribute("mid").next().map(str::trim)
    }

    /// The values of the section's `a=<name>:` lines, in order.
    pub(crate) fn attribute<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'a str> + 's {
        self.lines.iter().filter_map(move |line| {
            line.strip_prefix("a=")
                .and_then(|rest| rest.strip_prefix(name))
                .and_then(|rest| rest.strip_prefix(':'))
        })
    }

    /// The payload type numbers of the `m=` line's format list
    /// (RFC 8866 §5.14); fields that are not one are skipped.
    pub(crate) fn formats(&self) -> impl Iterator<Item = u8> + '_ {
        self.m_line
            .split(' ')
            .skip(3)
            .filter_map(|format| format.parse().ok())
    }
}

/// What one payload type number stands for in one media section: the
/// parts of a codec configuration RFC 9143 §9.1.1 requires to be identical
/// wherever a BUNDLE group reuses the number ("the same media type,
/// encoding name, clock rate, and any parameter that can affect the codec
/// configuration and packetization"). Displayed for a refusal with each
/// piece as [`browser_text`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Configuration<'a> {
    /// The section's media type.
    media: &'a str,
    /// The `a=rtpmap` encoding, or a static type's (RFC 3551 §6): see
    /// [`encoding`].
    encoding: String,
    /// The `a=fmtp` parameters as written, empty without one. Compared as
    /// text: only the codec knows which differences are harmless, so two
    /// orders of the same parameters count as different.
    parameters: &'a str,
}

impl fmt::Display for Configuration<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let media = browser_text(self.media);
        let encoding = browser_text(&self.encoding);
        write!(f, "{media} {encoding}")?;
        if !self.parameters.is_empty() {
            write!(f, " ({})", browser_text(self.parameters))?;
        }
        Ok(())
    }
}

/// An `a=rtpmap` encoding (`<name>/<clock>[/<channels>]`, RFC 8866 §6.6)
/// for comparison: lowercased, since encoding names are case-insensitive
/// (RFC 4855 §3), and without a channel count of one, which may be omitted
/// (RFC 8866 §6.6).
fn encoding(rtpmap: &str) -> String {
    let lower = rtpmap.trim().to_ascii_lowercase();
    match lower.strip_suffix("/1") {
        Some(base) if base.matches('/').count() == 1 => base.to_owned(),
        _ => lower,
    }
}

/// The encoding of a static payload type a format list names without an
/// `a=rtpmap` (RFC 3551 §6, Table 4): the ones str0m 0.24 assigns too
/// (`CodecSpec::from_static_pt`), so it can lock them. The rest it ignores.
pub(crate) const fn static_encoding(pt: u8) -> Option<&'static str> {
    match pt {
        0 => Some("pcmu/8000"),
        8 => Some("pcma/8000"),
        9 => Some("g722/8000"),
        13 => Some("cn/8000"),
        _ => None,
    }
}

/// A payload type number as an `a=rtpmap` or `a=fmtp` line writes it: the
/// RTP field is seven bits (RFC 3550 §5.1), so str0m reads a larger one as
/// no payload type at all.
fn payload_type(text: &str) -> Option<u8> {
    text.parse().ok().filter(|pt| *pt <= 127)
}

/// The first parameter name an `a=fmtp` value lists twice, compared
/// case-insensitively. Each name has one value; for `apt` a second one
/// would make one retransmission payload type repair two originals
/// (RFC 4588 §8.1 gives it one), which str0m locks twice.
fn repeated_parameter(parameters: &str) -> Option<&str> {
    let mut seen: Vec<&str> = Vec::new();
    for parameter in parameters.split(';') {
        let name = parameter
            .split_once('=')
            .map_or(parameter, |(name, _)| name)
            .trim();
        if seen.iter().any(|other| other.eq_ignore_ascii_case(name)) {
            return Some(name);
        }
        seen.push(name);
    }
    None
}

/// Where a payload type is defined: `m-line <index> (mid <mid>)`, the
/// mid as [`browser_text`].
fn place(index: usize, mid: Option<&str>) -> String {
    match mid {
        Some(mid) => format!("m-line {index} (mid {})", browser_text(mid)),
        None => format!("m-line {index}"),
    }
}

/// The payload types `section` (the `index`th) defines, each with its
/// configuration: every `a=rtpmap`, listed in the format list or not, as
/// str0m reads them all, and the static types listed without one. `Err`
/// names a number mapped twice (RFC 8866 §6.6 allows one `a=rtpmap`,
/// §6.15 one `a=fmtp` per format) or a parameter named twice.
fn payload_types<'a>(
    section: &Section<'a>,
    index: usize,
) -> Result<Vec<(u8, Configuration<'a>)>, String> {
    let mut maps: Vec<(u8, String)> = Vec::new();
    for value in section.attribute("rtpmap") {
        let Some((pt, rtpmap)) = value.split_once(' ') else {
            continue;
        };
        let Some(pt) = payload_type(pt) else {
            continue;
        };
        if maps.iter().any(|(seen, _)| *seen == pt) {
            return Err(format!(
                "payload type {pt} has two a=rtpmap lines in {} (RFC 8866 §6.6)",
                place(index, section.mid())
            ));
        }
        maps.push((pt, encoding(rtpmap)));
    }
    for pt in section.formats() {
        if let Some(encoding) = static_encoding(pt)
            && !maps.iter().any(|(seen, _)| *seen == pt)
        {
            maps.push((pt, encoding.to_owned()));
        }
    }
    let mut fmtps: Vec<(u8, &'a str)> = Vec::new();
    for value in section.attribute("fmtp") {
        let (pt, parameters) = value.split_once(' ').unwrap_or((value, ""));
        let Some(pt) = payload_type(pt) else {
            continue;
        };
        if fmtps.iter().any(|(seen, _)| *seen == pt) {
            return Err(format!(
                "payload type {pt} has two a=fmtp lines in {} (RFC 8866 §6.15)",
                place(index, section.mid())
            ));
        }
        if let Some(name) = repeated_parameter(parameters) {
            return Err(format!(
                "a=fmtp:{pt} in {} sets {} twice (RFC 4588 §8.1 for apt)",
                place(index, section.mid()),
                browser_text(name)
            ));
        }
        fmtps.push((pt, parameters));
    }
    Ok(maps
        .into_iter()
        .map(|(pt, encoding)| {
            let parameters = fmtps
                .iter()
                .find(|(seen, _)| *seen == pt)
                .map_or("", |(_, parameters)| parameters);
            let configuration = Configuration {
                media: section.media_type(),
                encoding,
                parameters,
            };
            (pt, configuration)
        })
        .collect())
}

/// Where a payload type number was first defined, and as what.
#[derive(Debug)]
struct Defined<'a> {
    /// The number.
    pt: u8,
    /// Its configuration there.
    configuration: Configuration<'a>,
    /// The section's index.
    index: usize,
    /// The section's mid.
    mid: Option<&'a str>,
}

/// Checks that every payload type number of `offer` stands for one codec
/// configuration across its media sections (RFC 9143 §9.1.1), and that no
/// section maps a number twice (RFC 8866 §6.6, §6.15) or names a format
/// parameter twice. `Err` says which number, where, and as what.
///
/// Sections outside one BUNDLE group may reuse a number for another codec
/// (each media description maps its own, RFC 8866 §6.6), but str0m keeps
/// one table per session and panics on them too, so they are refused as
/// well (`SPEC-DEVIATION`).
///
/// # Errors
///
/// The reason the offer is refused, for `invalid_sdp`.
pub fn check_payload_types(offer: &str) -> Result<(), String> {
    let sdp = Sdp::parse(offer);
    let mut defined: Vec<Defined<'_>> = Vec::new();
    for (index, section) in sdp.media().iter().enumerate() {
        for (pt, configuration) in payload_types(section, index)? {
            let Some(first) = defined.iter().find(|first| first.pt == pt) else {
                defined.push(Defined {
                    pt,
                    configuration,
                    index,
                    mid: section.mid(),
                });
                continue;
            };
            if first.configuration == configuration {
                continue;
            }
            let both = format!(
                "payload type {pt} is {} in {} and {configuration} in {}",
                first.configuration,
                place(first.index, first.mid),
                place(index, section.mid())
            );
            return Err(if sdp.bundled(first.mid, section.mid()) {
                format!(
                    "{both}, one BUNDLE group: a payload type keeps one codec configuration across it (RFC 9143 §9.1.1)"
                )
            } else {
                // SPEC-DEVIATION(RFC 8866 §6.6): unbundled media
                // descriptions map payload types each on their own, but
                // str0m keeps one table per session and panics on a reuse
                // across them too; gate:
                // rfc9143_9_1_1_one_payload_type_two_codecs_in_one_bundle_group_is_refused.
                format!(
                    "{both}, not bundled together: the engine keeps one payload type table per session (SPEC-DEVIATION, RFC 8866 §6.6)"
                )
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    /// An audio and a video section in one BUNDLE group, the shape a web
    /// player offers, with the codec lines a test puts in.
    fn offer(audio: &str, video: &str) -> String {
        format!(
            "v=0\r\na=group:BUNDLE a v\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:a\r\n{audio}m=video 9 UDP/TLS/RTP/SAVPF 109\r\na=mid:v\r\n{video}"
        )
    }

    #[test]
    fn rfc8866_5_the_sdp_splits_at_m_lines() {
        let sdp = Sdp::parse(
            "v=0\na=group:BUNDLE 0\r\nm=audio 9 x 0  \r\na=mid: 0 \r\na=rtpmap:0 PCMU/8000\nm=video 9 x 96\r\n",
        );
        assert_eq!(sdp.session(), ["v=0", "a=group:BUNDLE 0"]);
        assert_eq!(sdp.media().len(), 2);
        let (audio, video) = (&sdp.media()[0], &sdp.media()[1]);
        assert_eq!(audio.m_line(), "m=audio 9 x 0");
        assert_eq!(audio.lines(), ["a=mid: 0", "a=rtpmap:0 PCMU/8000"]);
        assert_eq!(audio.mid(), Some("0"));
        assert_eq!(audio.media_type(), "audio");
        assert_eq!(audio.formats().collect::<Vec<_>>(), [0]);
        assert_eq!(
            audio.attribute("rtpmap").collect::<Vec<_>>(),
            ["0 PCMU/8000"]
        );
        assert_eq!(audio.attribute("rtp").count(), 0);
        assert_eq!(video.mid(), None);
        assert!(video.lines().is_empty());
        assert!(video.is("video") && !video.is("vide") && !video.is("audio"));
        assert_eq!(
            sdp.first("video").map(Section::m_line),
            Some("m=video 9 x 96")
        );
        assert!(sdp.first("application").is_none());
        // A format list field that is no number is skipped.
        let odd = Sdp::parse("m=application 9 UDP/DTLS/SCTP webrtc-datachannel 5000\r\n");
        assert_eq!(
            odd.media()[0].formats().collect::<Vec<_>>(),
            Vec::<u8>::new()
        );
        assert_eq!(odd.media()[0].media_type(), "application");
    }

    #[test]
    fn rfc9143_5_bundled_means_one_group_lists_both_mids() {
        let sdp = Sdp::parse("a=group:BUNDLE a b\r\na=group:BUNDLE c\r\na=group:LS a c\r\n");
        assert!(sdp.bundled(Some("a"), Some("b")));
        assert!(sdp.bundled(Some("b"), Some("a")));
        assert!(!sdp.bundled(Some("a"), Some("c")), "two groups");
        assert!(!sdp.bundled(Some("a"), None));
        assert!(!sdp.bundled(None, Some("a")));
    }

    #[test]
    fn rfc3264_8_2_a_zero_port_stops_an_m_line_unless_bundle_only_in_a_bundle_rfc9143_6() {
        let stopped = |sdp: &str| {
            let sdp = Sdp::parse(sdp);
            sdp.stopped(&sdp.media()[0])
        };
        assert!(!stopped(
            "a=group:BUNDLE v\r\nm=video 9 x 96\r\na=mid:v\r\n"
        ));
        // Stopped: out of the BUNDLE group (RFC 8829 §5.2.2), or in it
        // without `bundle-only`, or `bundle-only` outside it.
        assert!(stopped("a=group:BUNDLE a\r\nm=video 0 x 96\r\na=mid:v\r\n"));
        assert!(stopped("a=group:BUNDLE v\r\nm=video 0 x 96\r\na=mid:v\r\n"));
        assert!(stopped(
            "a=group:BUNDLE a\r\nm=video 0 x 96\r\na=mid:v\r\na=bundle-only\r\n"
        ));
        assert!(stopped("m=video 0/2 x 96\r\na=bundle-only\r\n"), "no mid");
        // Bundled only: in the group, on its transport.
        assert!(!stopped(
            "a=group:BUNDLE a v\r\nm=video 0 x 96\r\na=mid:v\r\na=bundle-only\r\n"
        ));
        assert!(!stopped("m=video 10 x 96\r\n"));
        assert!(!stopped("m=video\r\n"), "no port at all");
    }

    /// A port is `1*DIGIT` (RFC 8866 §9), zero by its value: leading
    /// zeros, with or without a number of ports, stop the m-line as `0`
    /// does, and the bundle-only exception (RFC 9143 §6) holds for them
    /// too. A field that is no `1*DIGIT` is not zero.
    #[test]
    fn rfc8866_9_a_zero_padded_port_is_port_zero_and_stops_the_m_line() {
        let stopped = |sdp: &str| {
            let sdp = Sdp::parse(sdp);
            sdp.stopped(&sdp.media()[0])
        };
        for port in ["00", "000/2", "0000000000000000000000000000"] {
            assert!(stopped(&format!("m=video {port} x 96\r\n")), "{port}");
            assert!(
                stopped(&format!(
                    "a=group:BUNDLE a\r\nm=video {port} x 96\r\na=mid:v\r\na=bundle-only\r\n"
                )),
                "{port}: bundle-only outside the group"
            );
            assert!(
                !stopped(&format!(
                    "a=group:BUNDLE a v\r\nm=video {port} x 96\r\na=mid:v\r\na=bundle-only\r\n"
                )),
                "{port}: bundle-only in the group"
            );
        }
        for port in [
            "01", "10/2", "007", "70000", "+0", "-0", "0x0", "x", "/2", "",
        ] {
            assert!(!stopped(&format!("m=video {port} x 96\r\n")), "{port}");
        }
        assert!(zero_port("0"));
        assert!(zero_port("000"));
        assert!(!zero_port(""));
        assert!(!zero_port("+0"));
        assert!(!zero_port("0 "));
    }

    /// The browser's text in a refusal, which the session logs and the
    /// API returns, is capped: the mid, the media type, the encoding, the
    /// format parameters and a parameter's name, each at
    /// [`BROWSER_TEXT_BYTES`] and on one line.
    #[test]
    fn rfc9143_9_1_1_the_browser_s_text_in_a_refusal_is_capped() {
        let long = "x".repeat(10_000);
        let shown = &long[..BROWSER_TEXT_BYTES];
        let section = |lines: &str| format!("m=audio 9 x 96\r\na=mid:{long}\r\n{lines}");
        assert_eq!(
            check_payload_types(&section("a=rtpmap:96 a/1\r\na=rtpmap:96 b/1\r\n")).unwrap_err(),
            format!(
                "payload type 96 has two a=rtpmap lines in m-line 0 (mid {shown}) (RFC 8866 §6.6)"
            )
        );
        assert_eq!(
            check_payload_types(&section("a=fmtp:96 a=1\r\na=fmtp:96 a=2\r\n")).unwrap_err(),
            format!(
                "payload type 96 has two a=fmtp lines in m-line 0 (mid {shown}) (RFC 8866 §6.15)"
            )
        );
        assert_eq!(
            check_payload_types(&section(&format!("a=fmtp:96 {long}=1;{long}=2\r\n"))).unwrap_err(),
            format!(
                "a=fmtp:96 in m-line 0 (mid {shown}) sets {shown} twice (RFC 4588 §8.1 for apt)"
            )
        );
        let err = check_payload_types(&format!(
            "m={long} 9 x 96\r\na=mid:{long}\r\na=rtpmap:96 {long}/1\r\na=fmtp:96 {long}\r\nm=video 9 x 96\r\na=mid:v\r\na=rtpmap:96 H264/90000\r\n"
        ))
        .unwrap_err();
        assert!(
            err.starts_with(&format!(
                "payload type 96 is {shown} {shown} ({shown}) in m-line 0 (mid {shown}) and video h264/90000 in m-line 1 (mid v), not bundled together"
            )),
            "{err}"
        );
        assert!(err.len() < 6 * BROWSER_TEXT_BYTES, "{err}");
    }

    #[test]
    fn rfc9143_9_1_1_one_payload_type_two_codecs_in_one_bundle_group_is_refused() {
        // Firefox's Opus number on the video's H.264.
        let err = check_payload_types(&offer(
            "a=rtpmap:109 opus/48000/2\r\na=fmtp:109 minptime=10\r\n",
            "a=rtpmap:109 H264/90000\r\na=fmtp:109 packetization-mode=1\r\n",
        ))
        .unwrap_err();
        assert_eq!(
            err,
            "payload type 109 is audio opus/48000/2 (minptime=10) in m-line 0 (mid a) and video h264/90000 (packetization-mode=1) in m-line 1 (mid v), one BUNDLE group: a payload type keeps one codec configuration across it (RFC 9143 §9.1.1)"
        );
        // Same encoding, other parameters: another configuration.
        let err = check_payload_types(&offer(
            "",
            "a=rtpmap:96 H264/90000\r\na=fmtp:96 profile-level-id=42e01f\r\nm=video 9 x 96\r\na=mid:w\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 profile-level-id=640c1f\r\n",
        ))
        .unwrap_err();
        assert!(err.starts_with("payload type 96 is video h264/90000 (profile-level-id=42e01f) in m-line 1 (mid v) and video h264/90000 (profile-level-id=640c1f) in m-line 2 (mid w), not bundled together"), "{err}");
        // Same encoding in another media type.
        assert!(
            check_payload_types(&offer("a=rtpmap:96 x/90000\r\n", "a=rtpmap:96 x/90000\r\n"))
                .unwrap_err()
                .contains("audio x/90000 in m-line 0 (mid a) and video x/90000")
        );
        // A retransmission type repairing another original.
        assert!(
            check_payload_types(&offer(
                "",
                "a=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\nm=video 9 x 97\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=98\r\n"
            ))
            .unwrap_err()
            .contains("video rtx/90000 (apt=98) in m-line 2,")
        );
    }

    #[test]
    fn rfc3551_6_a_static_payload_type_without_rtpmap_keeps_its_codec() {
        // PT 0 listed bare in the audio section is PCMU; H.264 on 0 in the
        // video section conflicts with it.
        let bare = "v=0\r\na=group:BUNDLE a v\r\nm=audio 9 x 0 8 9 13 3\r\na=mid:a\r\nm=video 9 x 96\r\na=mid:v\r\n";
        let err = check_payload_types(&format!("{bare}a=rtpmap:0 H264/90000\r\n")).unwrap_err();
        assert!(
            err.starts_with("payload type 0 is audio pcmu/8000 in m-line 0"),
            "{err}"
        );
        for (pt, encoding) in [(8, "pcma/8000"), (9, "g722/8000"), (13, "cn/8000")] {
            let err =
                check_payload_types(&format!("{bare}a=rtpmap:{pt} H264/90000\r\n")).unwrap_err();
            assert!(
                err.starts_with(&format!("payload type {pt} is audio {encoding} ")),
                "{err}"
            );
            assert_eq!(static_encoding(pt), Some(encoding));
        }
        // A static type str0m does not assign is not checked.
        assert_eq!(
            check_payload_types(&format!("{bare}a=rtpmap:3 H264/90000\r\n")),
            Ok(())
        );
        // Its explicit rtpmap matches the static one, whatever the case and
        // with a channel count of one.
        assert_eq!(
            check_payload_types("m=audio 9 x 0\r\nm=audio 9 x 0\r\na=rtpmap:0 PCMU/8000/1\r\n"),
            Ok(())
        );
        // An explicit rtpmap overrides the static assignment.
        assert_eq!(
            check_payload_types(
                "m=audio 9 x 0\r\na=rtpmap:0 opus/48000/2\r\nm=audio 9 x 0\r\na=rtpmap:0 OPUS/48000/2\r\n"
            ),
            Ok(())
        );
    }

    #[test]
    fn rfc8866_6_6_one_rtpmap_and_6_15_one_fmtp_per_payload_type() {
        let err = check_payload_types(&offer(
            "a=rtpmap:111 opus/48000/2\r\na=rtpmap:111 PCMU/8000\r\n",
            "",
        ))
        .unwrap_err();
        assert_eq!(
            err,
            "payload type 111 has two a=rtpmap lines in m-line 0 (mid a) (RFC 8866 §6.6)"
        );
        let err = check_payload_types(&offer(
            "",
            "a=rtpmap:121 rtx/90000\r\na=fmtp:121 apt=127\r\na=fmtp:121 apt=108\r\n",
        ))
        .unwrap_err();
        assert_eq!(
            err,
            "payload type 121 has two a=fmtp lines in m-line 1 (mid v) (RFC 8866 §6.15)"
        );
        // An fmtp without parameters still counts.
        assert!(check_payload_types("m=video 9 x 96\r\na=fmtp:96\r\na=fmtp:96 x=1\r\n").is_err());
    }

    #[test]
    fn rfc4588_8_1_a_retransmission_type_has_one_original() {
        let err = check_payload_types(&offer(
            "",
            "a=rtpmap:121 rtx/90000\r\na=fmtp:121 apt=127; APT=108\r\n",
        ))
        .unwrap_err();
        assert_eq!(
            err,
            "a=fmtp:121 in m-line 1 (mid v) sets APT twice (RFC 4588 §8.1 for apt)"
        );
        assert_eq!(repeated_parameter("a=1;b=2;c"), None);
        assert_eq!(repeated_parameter("0-15;0-15"), Some("0-15"));
    }

    #[test]
    fn what_browsers_offer_passes() {
        // The same codec under the same number in two sections, rtcp-fb
        // lines that differ, rtpmaps for types the format list lacks, and
        // numbers str0m does not read as payload types.
        let same = offer(
            "a=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10\r\na=rtcp-fb:111 transport-cc\r\na=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:109 H264/90000\r\na=rtcp-fb:109 nack\r\nm=audio 9 x 111\r\na=mid:t\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10\r\na=rtpmap:200 PCMU/8000\r\na=rtpmap:x PCMU/8000\r\na=rtpmap:96\r\na=fmtp:200 a=1\r\na=fmtp:200 a=1\r\na=fmtp:x\r\n",
        );
        assert_eq!(check_payload_types(&same), Ok(()));
        assert_eq!(check_payload_types(""), Ok(()));
        assert_eq!(payload_type("127"), Some(127));
        assert_eq!(payload_type("128"), None);
    }

    #[test]
    fn rfc8866_6_6_encodings_compare_case_insensitively_without_one_channel() {
        assert_eq!(encoding(" PCMU/8000/1 "), "pcmu/8000");
        assert_eq!(encoding("opus/48000/2"), "opus/48000/2");
        assert_eq!(encoding("x/1"), "x/1");
        assert_eq!(encoding("L16/8000/11"), "l16/8000/11");
        assert_eq!(encoding("a/b/c/1"), "a/b/c/1");
        assert_eq!(place(2, None), "m-line 2");
    }
}
