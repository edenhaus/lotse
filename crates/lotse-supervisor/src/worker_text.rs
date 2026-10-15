//! The check on the text a worker reports for the browser: its SDP answer
//! and its `candidate:` lines go out on the control API as they are, so
//! the supervisor, which treats a worker as possibly compromised,
//! forwards only a bounded answer made of well-formed SDP lines and
//! candidate lines of RFC 8839's grammar. A report that fails the check
//! closes its session; the reason is logged, never the text.
//!
//! The check is syntactic: it bounds what a worker can make the client and
//! the browser parse, not which addresses its candidates name, which a web
//! page can choose for a browser as freely.
//!
//! The rest of a worker's text, a warning's or a close's message, a source
//! error, a track's names, is for humans and logs:
//! [`plain`](lotse_core::text::plain) caps it at [`MAX_MESSAGE_BYTES`] or
//! [`MAX_NAME_BYTES`] and replaces its control characters, so a worker can
//! neither forge log lines nor make the client carry more than a sentence.
//!
//! Standards: RFC 8866 §5 (an SDP line is `<type>=<value>`, the first is
//! `v=0` (§5.1), lines end in CRLF) and §9 (`token`, `byte-string`),
//! RFC 8839 §5.1 (`candidate-attribute`), RFC 5888 §4 (`a=mid`), RFC 6544
//! §4.5 (`tcptype`).

use std::net::IpAddr;
use std::str::FromStr;

use lotse_api_types::limits::{MAX_SDP_CHARS, MAX_TEXT_CHARS};
use lotse_ipc::SessionEvent as WorkerSessionEvent;

/// The longest answer, in bytes: the offer's cap, which is the control
/// API's frame;
/// str0m's answers are a few KiB.
pub(crate) const MAX_ANSWER_BYTES: usize = MAX_SDP_CHARS;

/// The longest candidate line or `mid`, in bytes: the cap on the
/// browser's (`MAX_TEXT_CHARS`).
pub(crate) const MAX_LINE_BYTES: usize = MAX_TEXT_CHARS;

/// The longest message a worker's warning, close or source error carries
/// on, in bytes: the worker's own are a sentence or two (the longest,
/// `frame_over_browser_limit`'s, about 300 bytes).
pub(crate) const MAX_MESSAGE_BYTES: usize = 512;

/// The longest name a worker reports, in bytes: a track's id, kind, codec
/// or sync, an error code; the worker's own are a word.
pub(crate) const MAX_NAME_BYTES: usize = 64;

/// The longest `foundation` (RFC 8839 §5.1: `1*32ice-char`).
const MAX_FOUNDATION: usize = 32;

/// The most digits of a `component-id` (RFC 8839 §5.1: `1*3DIGIT`).
const COMPONENT_DIGITS: usize = 3;

/// The highest `component-id` (RFC 8839 §5.1: "between 1 and 256").
const MAX_COMPONENT: u16 = 256;

/// The most digits of a `priority` (RFC 8839 §5.1: `1*10DIGIT`).
const PRIORITY_DIGITS: usize = 10;

/// The most digits of a `port` (RFC 8866 §9: `1*5DIGIT`).
const PORT_DIGITS: usize = 5;

/// The candidate types of RFC 8839 §5.1 (`candidate-types`); the grammar
/// also allows extension tokens, which no lotse worker writes.
const CANDIDATE_TYPES: [&str; 4] = ["host", "srflx", "prflx", "relay"];

/// Checks what of a worker's session report goes to the browser as text:
/// the answer, a candidate line and its `mid`, a relay candidate's line.
/// The error is the reason, for the log.
pub(crate) fn check(report: &WorkerSessionEvent) -> Result<(), &'static str> {
    match report {
        WorkerSessionEvent::Answer { sdp, .. } => check_answer(sdp),
        WorkerSessionEvent::Candidate { candidate, mid } => {
            if !candidate.is_empty() {
                check_candidate(candidate)?;
            }
            mid.as_deref().map_or(Ok(()), check_mid)
        }
        WorkerSessionEvent::Relayed {
            candidate: Some(candidate),
            ..
        } => check_candidate(candidate),
        _ => Ok(()),
    }
}

/// An SDP answer: at most [`MAX_ANSWER_BYTES`], `v=0` first, every line
/// `<type>=<value>` with a lowercase type letter (RFC 8866 §5), CRLF
/// between lines and optionally after the last, no control character but
/// a tab in a value (stricter than §9's `byte-string`, which admits all
/// but NUL, CR and LF), and its `a=candidate` and `a=mid` lines as
/// [`check_candidate`] and [`check_mid`] take them.
fn check_answer(sdp: &str) -> Result<(), &'static str> {
    if sdp.len() > MAX_ANSWER_BYTES {
        return Err("answer too long");
    }
    let body = sdp.strip_suffix("\r\n").unwrap_or(sdp);
    let mut lines = body.split("\r\n");
    if lines.next() != Some("v=0") {
        return Err("answer does not start with v=0");
    }
    for line in lines {
        let Some((head, value)) = line.split_at_checked(2) else {
            return Err("answer line too short");
        };
        let attribute = match head.as_bytes() {
            [b'a', b'='] => true,
            [letter, b'='] if letter.is_ascii_lowercase() => false,
            _ => return Err("answer line not <type>=<value>"),
        };
        if value.chars().any(|c| c.is_control() && c != '\t') {
            return Err("control character in an answer line");
        }
        if !attribute {
            continue;
        }
        if value.starts_with("candidate:") {
            check_candidate(value)?;
        } else if let Some(mid) = value.strip_prefix("mid:") {
            check_mid(mid)?;
        }
    }
    Ok(())
}

/// A `candidate:` line (RFC 8839 §5.1): at most [`MAX_LINE_BYTES`],
/// fields one space apart, `foundation`, `component-id`, `transport`,
/// `priority`, an IP `connection-address` (the grammar's FQDN form is
/// refused: a worker names addresses), `port`, `typ` and a known type,
/// then name-value pairs: `raddr` an IP address, `rport` a port, any
/// other a `token` with a value of visible characters.
fn check_candidate(line: &str) -> Result<(), &'static str> {
    if line.len() > MAX_LINE_BYTES {
        return Err("candidate too long");
    }
    let mut fields = line
        .strip_prefix("candidate:")
        .ok_or("candidate line without candidate:")?
        .split(' ');
    let mut field = || fields.next().unwrap_or_default();
    let foundation = field();
    if foundation.is_empty()
        || foundation.len() > MAX_FOUNDATION
        || !foundation.bytes().all(is_ice_char)
    {
        return Err("candidate foundation malformed");
    }
    if !number::<u16>(field(), COMPONENT_DIGITS).is_some_and(|c| (1..=MAX_COMPONENT).contains(&c)) {
        return Err("candidate component malformed");
    }
    if !is_token(field()) {
        return Err("candidate transport malformed");
    }
    if number::<u32>(field(), PRIORITY_DIGITS).is_none() {
        return Err("candidate priority malformed");
    }
    if field().parse::<IpAddr>().is_err() {
        return Err("candidate address not an IP address");
    }
    if number::<u16>(field(), PORT_DIGITS).is_none() {
        return Err("candidate port malformed");
    }
    if field() != "typ" || !CANDIDATE_TYPES.contains(&field()) {
        return Err("candidate type malformed");
    }
    // Name-value pairs to the end (RFC 8839 §5.1: `rel-addr`, `rel-port`,
    // `cand-extension`), each field non-empty.
    let rest: Vec<&str> = fields.collect();
    for pair in rest.chunks(2) {
        let valid = match pair {
            ["raddr", value] => value.parse::<IpAddr>().is_ok(),
            ["rport", value] => number::<u16>(value, PORT_DIGITS).is_some(),
            [name, value] => {
                is_token(name) && !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic())
            }
            _ => false,
        };
        if !valid {
            return Err("candidate extension malformed");
        }
    }
    Ok(())
}

/// A `mid` (RFC 5888 §4: `identification-tag = token`), at most
/// [`MAX_LINE_BYTES`].
fn check_mid(mid: &str) -> Result<(), &'static str> {
    if mid.len() <= MAX_LINE_BYTES && is_token(mid) {
        Ok(())
    } else {
        Err("mid malformed")
    }
}

/// `field` as a number of 1 to `digits` decimal digits that fits `T`;
/// an empty field does not parse.
fn number<T: FromStr>(field: &str, digits: usize) -> Option<T> {
    // `parse` alone would take a sign.
    if field.len() > digits || !field.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

/// RFC 8839 §5.1 `ice-char`: `ALPHA / DIGIT / "+" / "/"`.
const fn is_ice_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// RFC 8866 §9 `token`: one or more `token-char`s.
fn is_token(field: &str) -> bool {
    !field.is_empty() && field.bytes().all(is_token_char)
}

/// RFC 8866 §9 `token-char`: `%x21 / %x23-27 / %x2A-2B / %x2D-2E /
/// %x30-39 / %x41-5A / %x5E-7E`.
const fn is_token_char(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x27 | 0x2A..=0x2B | 0x2D..=0x2E | 0x30..=0x39 | 0x41..=0x5A | 0x5E..=0x7E)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    /// An answer as str0m 0.24 writes it for a Chrome offer (trimmed).
    const ANSWER: &str = "v=0\r\n\
o=str0m-1234 5678 2 IN IP4 0.0.0.0\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic: WMS\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
a=ice-ufrag:Ab3dEf7h\r\n\
a=ice-pwd:0123456789abcdefABCDEFgh\r\n\
a=fingerprint:sha-256 0A:1B:2C\r\n\
a=setup:passive\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 H264/90000\r\n\
a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n\
a=candidate:4f2c1a3e 1 udp 2130706175 192.0.2.1 18556 typ host\r\n\
a=candidate:5a6b 1 tcp 1684798975 2001:db8::1 18557 typ host tcptype passive\r\n\
a=end-of-candidates\r\n";

    fn answer(sdp: &str) -> Result<(), &'static str> {
        check(&WorkerSessionEvent::Answer {
            sdp: sdp.into(),
            talkback: None,
        })
    }

    fn candidate(line: &str) -> Result<(), &'static str> {
        check(&WorkerSessionEvent::Candidate {
            candidate: line.into(),
            mid: None,
        })
    }

    #[test]
    fn rfc8866_5_a_worker_s_answer_passes_line_by_line() {
        assert_eq!(answer(ANSWER), Ok(()));
        assert_eq!(
            answer("v=0"),
            Ok(()),
            "the CRLF after the last line is optional"
        );
        assert_eq!(answer("v=0\r\na=x:\ttab\r\n"), Ok(()));
        assert_eq!(answer("v=0\r\na=mid:audio\r\nm=audio 0 x 0"), Ok(()));
    }

    #[test]
    fn rfc8866_5_an_answer_is_bounded_and_starts_with_v0() {
        let at_cap = format!("v=0\r\na={}\r\n", "x".repeat(MAX_ANSWER_BYTES - 9));
        assert_eq!(at_cap.len(), MAX_ANSWER_BYTES);
        assert_eq!(answer(&at_cap), Ok(()));
        assert_eq!(answer(&format!("{at_cap}a")), Err("answer too long"));
        assert_eq!(answer(""), Err("answer does not start with v=0"));
        assert_eq!(answer("v=1\r\n"), Err("answer does not start with v=0"));
        assert_eq!(answer("v=0 answer"), Err("answer does not start with v=0"));
        assert_eq!(
            answer("o=x\r\nv=0\r\n"),
            Err("answer does not start with v=0")
        );
    }

    #[test]
    fn rfc8866_5_every_line_is_a_type_letter_and_a_value_without_controls() {
        assert_eq!(answer("v=0\r\n\r\n"), Err("answer line too short"));
        assert_eq!(answer("v=0\r\na\r\n"), Err("answer line too short"));
        assert_eq!(answer("v=0\r\na=\r\n"), Ok(()), "an empty value");
        assert_eq!(
            answer("v=0\r\nA=x\r\n"),
            Err("answer line not <type>=<value>")
        );
        assert_eq!(
            answer("v=0\r\n1=x\r\n"),
            Err("answer line not <type>=<value>")
        );
        assert_eq!(
            answer("v=0\r\naa=x\r\n"),
            Err("answer line not <type>=<value>")
        );
        assert_eq!(
            answer("v=0\r\né=x\r\n"),
            Err("answer line not <type>=<value>")
        );
        for control in ["\n", "\r", "\0", "\u{1b}", "\u{7f}", "\u{85}"] {
            assert_eq!(
                answer(&format!("v=0\r\ns=a{control}b\r\n")),
                Err("control character in an answer line"),
                "{control:?}"
            );
        }
        assert_eq!(
            answer("v=0\ns=-\n"),
            Err("answer does not start with v=0"),
            "LF only"
        );
        assert_eq!(answer("v=0\r\ns=é\r\n"), Ok(()), "UTF-8 text");
    }

    #[test]
    fn rfc8839_5_1_an_answer_s_candidates_and_mids_are_checked_too() {
        assert_eq!(
            answer("v=0\r\na=candidate:1 1 udp 1 example.org 9 typ host\r\n"),
            Err("candidate address not an IP address")
        );
        assert_eq!(answer("v=0\r\na=mid:a b\r\n"), Err("mid malformed"));
        assert_eq!(answer("v=0\r\na=mid:\r\n"), Err("mid malformed"));
        assert_eq!(
            answer("v=0\r\na=candidates:x\r\n"),
            Ok(()),
            "another attribute"
        );
        assert_eq!(
            answer("v=0\r\ns=candidate:x mid:a b\r\n"),
            Ok(()),
            "not an attribute"
        );
    }

    #[test]
    fn rfc8839_5_1_the_candidates_lotse_writes_pass() {
        for line in [
            "candidate:4f2c1a3e 1 udp 2130706175 192.0.2.1 18556 typ host",
            "candidate:5a6b 1 tcp 1684798975 2001:db8::1 18557 typ host tcptype passive",
            "candidate:s2 1 udp 1694498815 203.0.113.7 40000 typ srflx raddr 192.168.1.2 rport 18556",
            "candidate:r+/ 1 udp 16777215 198.51.100.4 49152 typ relay raddr 0.0.0.0 rport 0 ufrag x-Y_z",
            "candidate:1 256 UDP 4294967295 ::1 65535 typ prflx",
            "candidate:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 udp 0 192.0.2.1 1 typ host",
        ] {
            assert_eq!(candidate(line), Ok(()), "{line}");
        }
        assert_eq!(candidate(""), Ok(()), "end-of-candidates");
    }

    /// Each of `lines` is refused for `reason`.
    fn refused(reason: &str, lines: &[&str]) {
        for line in lines {
            assert_eq!(candidate(line), Err(reason), "{line}");
        }
    }

    #[test]
    fn rfc8839_5_1_each_field_of_a_candidate_is_checked() {
        refused(
            "candidate line without candidate:",
            &[
                "1 1 udp 1 192.0.2.1 9 typ host",
                "a=candidate:1 1 udp 1 192.0.2.1 9 typ host",
            ],
        );
        refused(
            "candidate foundation malformed",
            &[
                "candidate: 1 udp 1 192.0.2.1 9 typ host",
                "candidate:a-b 1 udp 1 192.0.2.1 9 typ host",
                "candidate:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 udp 1 192.0.2.1 9 typ host",
            ],
        );
        refused(
            "candidate component malformed",
            &[
                "candidate:1 0 udp 1 192.0.2.1 9 typ host",
                "candidate:1 257 udp 1 192.0.2.1 9 typ host",
                "candidate:1 0001 udp 1 192.0.2.1 9 typ host",
                "candidate:1 +1 udp 1 192.0.2.1 9 typ host",
            ],
        );
        refused(
            "candidate transport malformed",
            &[
                "candidate:1 1 u\"dp 1 192.0.2.1 9 typ host",
                "candidate:1 1  1 192.0.2.1 9 typ host",
            ],
        );
        refused(
            "candidate priority malformed",
            &[
                "candidate:1 1 udp 4294967296 192.0.2.1 9 typ host",
                "candidate:1 1 udp 00000000001 192.0.2.1 9 typ host",
                "candidate:1 1 udp -1 192.0.2.1 9 typ host",
            ],
        );
        refused(
            "candidate address not an IP address",
            &[
                "candidate:1 1 udp 1 host.local 9 typ host",
                "candidate:1 1 udp 1 [::1] 9 typ host",
            ],
        );
        refused(
            "candidate port malformed",
            &[
                "candidate:1 1 udp 1 192.0.2.1 65536 typ host",
                "candidate:1 1 udp 1 192.0.2.1 000001 typ host",
            ],
        );
        refused(
            "candidate type malformed",
            &[
                "candidate:1 1 udp 1 192.0.2.1 9 type host",
                "candidate:1 1 udp 1 192.0.2.1 9 typ hots",
                "candidate:1 1 udp 1 192.0.2.1 9 typ",
                "candidate:1 1 udp 1 192.0.2.1 9",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host\tufrag x",
            ],
        );
    }

    #[test]
    fn rfc8839_5_1_a_candidate_ends_in_name_value_pairs() {
        refused(
            "candidate extension malformed",
            &[
                "candidate:1 1 udp 1 192.0.2.1 9 typ host ",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host ufrag ",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host  ufrag x",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host raddr",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host raddr x rport 1",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host rport 70000",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host ufrag",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host u(frag x",
                "candidate:1 1 udp 1 192.0.2.1 9 typ host ufrag \u{e9}",
            ],
        );
    }

    #[test]
    fn a_candidate_and_a_mid_are_bounded() {
        let head = "candidate:1 1 udp 1 192.0.2.1 9 typ host ufrag ";
        let at_cap = format!("{head}{}", "x".repeat(MAX_LINE_BYTES - head.len()));
        assert_eq!(candidate(&at_cap), Ok(()));
        assert_eq!(candidate(&format!("{at_cap}x")), Err("candidate too long"));
        let mid = |mid: String| {
            check(&WorkerSessionEvent::Candidate {
                candidate: String::new(),
                mid: Some(mid),
            })
        };
        assert_eq!(mid("x".repeat(MAX_LINE_BYTES)), Ok(()));
        assert_eq!(mid("x".repeat(MAX_LINE_BYTES + 1)), Err("mid malformed"));
        assert_eq!(mid("0".into()), Ok(()));
        assert_eq!(mid("a\"b".into()), Err("mid malformed"));
    }

    #[test]
    fn a_relay_candidate_is_checked_and_other_reports_carry_no_browser_text() {
        let relayed = "198.51.100.4:49152".parse().unwrap();
        assert_eq!(
            check(&WorkerSessionEvent::Relayed {
                relayed,
                candidate: Some("candidate:1 1 udp 1 198.51.100.4 49152 typ relay".into()),
            }),
            Ok(())
        );
        assert_eq!(
            check(&WorkerSessionEvent::Relayed {
                relayed,
                candidate: Some("candidate:1".into()),
            }),
            Err("candidate component malformed")
        );
        assert_eq!(
            check(&WorkerSessionEvent::Relayed {
                relayed,
                candidate: None,
            }),
            Ok(())
        );
        assert_eq!(
            check(&WorkerSessionEvent::Candidate {
                candidate: "candidate:1".into(),
                mid: Some("0".into()),
            }),
            Err("candidate component malformed")
        );
        assert_eq!(
            check(&WorkerSessionEvent::State {
                ice: "\0".into(),
                dtls: String::new(),
            }),
            Ok(())
        );
    }

    #[test]
    fn rfc8866_9_token_chars_are_the_grammar_s() {
        let tokens: String = (0_u8..=0x7F)
            .filter(|b| is_token_char(*b))
            .map(char::from)
            .collect();
        assert_eq!(
            tokens,
            "!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz{|}~"
        );
        assert!((0x80_u8..=0xFF).all(|b| !is_token_char(b)));
    }
}
