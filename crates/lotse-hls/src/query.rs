//! The Delivery Directives of a playlist request (draft-pantos-hls-rfc8216bis-22
//! §6.2.5): the `_HLS_msn` and `_HLS_part` query parameters of a Blocking
//! Playlist Reload (§6.2.5.2), parsed strictly from the request's query.
//!
//! A query is untrusted. Its parameters are `&`-separated `name=value`
//! pairs, compared byte for byte, never percent-decoded (a directive's name
//! and value need no escaping). Parameters other than the two are ignored:
//! a cache buster, and `_HLS_skip`, which §6.2.5.1 says a server MUST ignore
//! when its playlist has no `CAN-SKIP-UNTIL` (this one never does). A value
//! is a decimal-integer (§4.2), and a directive given twice is refused,
//! since nothing says which one to take. An `_HLS_part` without an
//! `_HLS_msn` is refused, as §6.2.5.2 says ("MUST return Bad Request").
//! The work is linear in the query's length, and nothing is allocated.

/// The name of the directive that asks for a Media Sequence Number
/// (draft-pantos-hls-rfc8216bis-22 §6.2.5.2).
pub const MSN_DIRECTIVE: &str = "_HLS_msn";

/// The name of the directive that asks for a Part Index (§6.2.5.2).
pub const PART_DIRECTIVE: &str = "_HLS_part";

/// The longest a decimal-integer is: "from 1 to 20 characters long"
/// (draft-pantos-hls-rfc8216bis-22 §4.2).
const MAX_DECIMAL_INTEGER_DIGITS: usize = 20;

/// What a playlist request waits for before the playlist is sent
/// (draft-pantos-hls-rfc8216bis-22 §6.2.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Blocking {
    /// No directive: the playlist as it is, at once.
    None,
    /// `_HLS_msn=M` alone: a playlist that holds the Media Segment `M` or a
    /// later one.
    Segment {
        /// The Media Sequence Number `M`.
        msn: u64,
    },
    /// `_HLS_msn=M&_HLS_part=N`: a playlist that holds the Partial Segment
    /// `N` of the Parent Segment `M`, or a later one.
    Part {
        /// The Media Sequence Number `M`.
        msn: u64,
        /// The Part Index `N`.
        part: u64,
    },
}

/// Why a playlist request's directives are refused: each is a Bad Request
/// (draft-pantos-hls-rfc8216bis-22 §6.2.5.2, "such as HTTP 400").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DirectiveError {
    /// A directive's value is not a decimal-integer (§4.2), or it has none.
    #[error("{0} is not a decimal-integer")]
    Invalid(&'static str),
    /// A directive is given more than once.
    #[error("{0} is given more than once")]
    Repeated(&'static str),
    /// `_HLS_part` without `_HLS_msn` (§6.2.5.2: "the Server MUST return Bad
    /// Request").
    #[error("_HLS_part without _HLS_msn")]
    PartWithoutMsn,
}

impl Blocking {
    /// The directives of a playlist request's `query`, the part of its URI
    /// after the `?` (empty without one).
    pub fn parse(query: &str) -> Result<Self, DirectiveError> {
        let mut msn = None;
        let mut part = None;
        for parameter in query.split('&') {
            let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
            let (directive, slot) = match name {
                MSN_DIRECTIVE => (MSN_DIRECTIVE, &mut msn),
                PART_DIRECTIVE => (PART_DIRECTIVE, &mut part),
                _ => continue,
            };
            if slot.is_some() {
                return Err(DirectiveError::Repeated(directive));
            }
            *slot = Some(decimal_integer(value).ok_or(DirectiveError::Invalid(directive))?);
        }
        match (msn, part) {
            (None, None) => Ok(Self::None),
            (Some(msn), None) => Ok(Self::Segment { msn }),
            (Some(msn), Some(part)) => Ok(Self::Part { msn, part }),
            (None, Some(_)) => Err(DirectiveError::PartWithoutMsn),
        }
    }
}

/// The value of a decimal-integer (draft-pantos-hls-rfc8216bis-22 §4.2):
/// "an unquoted string of characters from the set [0-9] ... in the range
/// from 0 to 2^64-1", "from 1 to 20 characters long". Leading zeros are
/// part of that grammar and taken; `None` for anything else.
pub fn decimal_integer(value: &str) -> Option<u64> {
    let digits = !value.is_empty()
        && value.len() <= MAX_DECIMAL_INTEGER_DIGITS
        && value.bytes().all(|byte| byte.is_ascii_digit());
    // All digits: `parse` fails only past 2^64-1.
    digits.then(|| value.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn rfc8216bis_4_2_a_decimal_integer_is_1_to_20_digits_up_to_2_pow_64_minus_1() {
        assert_eq!(decimal_integer("0"), Some(0));
        assert_eq!(decimal_integer("42"), Some(42));
        assert_eq!(decimal_integer("007"), Some(7));
        assert_eq!(
            decimal_integer("18446744073709551615"),
            Some(u64::MAX),
            "20 digits, 2^64-1"
        );
        assert_eq!(
            decimal_integer("00000000000000000001"),
            Some(1),
            "20 digits"
        );
        assert_eq!(decimal_integer("000000000000000000001"), None, "21 digits");
        assert_eq!(decimal_integer("18446744073709551616"), None, "2^64");
        for value in ["", "+1", "-1", " 1", "1 ", "1.0", "0x1", "١", "%31"] {
            assert_eq!(decimal_integer(value), None, "{value:?}");
        }
    }

    #[test]
    fn rfc8216bis_6_2_5_2_no_directive_is_a_request_for_the_playlist_as_it_is() {
        assert_eq!(Blocking::parse(""), Ok(Blocking::None));
        assert_eq!(Blocking::parse("t=123&x"), Ok(Blocking::None));
    }

    #[test]
    fn rfc8216bis_6_2_5_2_hls_msn_alone_asks_for_a_segment() {
        assert_eq!(
            Blocking::parse("_HLS_msn=12"),
            Ok(Blocking::Segment { msn: 12 })
        );
    }

    #[test]
    fn rfc8216bis_6_2_5_2_hls_msn_and_hls_part_ask_for_a_part_in_either_order() {
        let part = Ok(Blocking::Part { msn: 12, part: 3 });
        assert_eq!(Blocking::parse("_HLS_msn=12&_HLS_part=3"), part);
        assert_eq!(Blocking::parse("_HLS_part=3&_HLS_msn=12"), part);
        assert_eq!(Blocking::parse("a=b&_HLS_part=3&c&_HLS_msn=12&"), part);
    }

    #[test]
    fn rfc8216bis_6_2_5_2_hls_part_without_hls_msn_is_a_bad_request() {
        assert_eq!(
            Blocking::parse("_HLS_part=3"),
            Err(DirectiveError::PartWithoutMsn)
        );
    }

    #[test]
    fn rfc8216bis_6_2_5_1_hls_skip_is_ignored_without_can_skip_until() {
        assert_eq!(
            Blocking::parse("_HLS_skip=YES&_HLS_msn=1"),
            Ok(Blocking::Segment { msn: 1 })
        );
    }

    #[test]
    fn a_directive_that_is_not_a_decimal_integer_is_refused() {
        assert_eq!(
            Blocking::parse("_HLS_msn"),
            Err(DirectiveError::Invalid(MSN_DIRECTIVE))
        );
        assert_eq!(
            Blocking::parse("_HLS_msn="),
            Err(DirectiveError::Invalid(MSN_DIRECTIVE))
        );
        assert_eq!(
            Blocking::parse("_HLS_msn=1&_HLS_part=-1"),
            Err(DirectiveError::Invalid(PART_DIRECTIVE))
        );
        assert_eq!(
            Blocking::parse("_HLS_msn=1=2"),
            Err(DirectiveError::Invalid(MSN_DIRECTIVE))
        );
    }

    #[test]
    fn a_directive_given_twice_is_refused() {
        assert_eq!(
            Blocking::parse("_HLS_msn=1&_HLS_msn=1"),
            Err(DirectiveError::Repeated(MSN_DIRECTIVE))
        );
        assert_eq!(
            Blocking::parse("_HLS_msn=1&_HLS_part=1&_HLS_part=2"),
            Err(DirectiveError::Repeated(PART_DIRECTIVE))
        );
    }

    #[test]
    fn directive_names_are_compared_byte_for_byte() {
        assert_eq!(
            Blocking::parse("_hls_msn=1&%5FHLS_msn=2"),
            Ok(Blocking::None)
        );
    }

    #[test]
    fn the_errors_say_what_was_refused() {
        assert_eq!(
            DirectiveError::Invalid(MSN_DIRECTIVE).to_string(),
            "_HLS_msn is not a decimal-integer"
        );
        assert_eq!(
            DirectiveError::Repeated(PART_DIRECTIVE).to_string(),
            "_HLS_part is given more than once"
        );
        assert_eq!(
            DirectiveError::PartWithoutMsn.to_string(),
            "_HLS_part without _HLS_msn"
        );
    }
}
