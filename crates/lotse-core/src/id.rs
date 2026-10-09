//! The identifiers a client and the daemon exchange: [`StreamId`] and
//! [`SessionId`]. Both match `^[A-Za-z0-9._-]{1,128}$`,
//! checked on construction so an invalid id never exists inside the daemon.
//! The API maps [`IdError`] to `invalid_stream_id` or `invalid_request`.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

/// The longest identifier accepted, in characters.
pub const MAX_LEN: usize = 128;

/// Why a string is not a valid identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// The string is empty.
    #[error("identifier is empty")]
    Empty,
    /// The string is longer than [`MAX_LEN`] characters.
    #[error("identifier is {len} characters long, the maximum is {max}", max = MAX_LEN)]
    TooLong {
        /// The length found.
        len: usize,
    },
    /// The string contains a character outside `[A-Za-z0-9._-]`.
    #[error(
        "identifier contains {ch:?} at position {index}; allowed are A-Z, a-z, 0-9, '.', '_' and '-'"
    )]
    InvalidChar {
        /// The offending character.
        ch: char,
        /// Its position, counted in characters from zero.
        index: usize,
    },
}

/// Checks `s` against the identifier pattern.
fn validate(s: &str) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    let mut len = 0;
    for (index, ch) in s.chars().enumerate() {
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')) {
            return Err(IdError::InvalidChar { ch, index });
        }
        len = index.saturating_add(1);
    }
    if len > MAX_LEN {
        return Err(IdError::TooLong { len });
    }
    Ok(())
}

/// Declares a validated identifier newtype over a shared string.
macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Validates `s` against `^[A-Za-z0-9._-]{1,128}$`.
            pub fn new(s: &str) -> Result<Self, IdError> {
                validate(s)?;
                Ok(Self(Arc::from(s)))
            }

            /// The identifier as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

identifier! {
    /// The id of a stream in the client's desired state (`stream_id` in the API).
    /// Cheap to clone; it is carried in every log span of that stream.
    StreamId
}

identifier! {
    /// The id of a WebRTC session (`session_id` in the API). The client
    /// passes its own; the daemon generates a ULID when it does not.
    SessionId
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
    fn accepts_the_documented_character_set() {
        for id in ["front", "reolink_1234.main-sub", "A", "0", "-", "_", "."] {
            assert_eq!(StreamId::new(id).unwrap().as_str(), id);
            assert_eq!(SessionId::new(id).unwrap().as_str(), id);
        }
    }

    #[test]
    fn accepts_128_characters_and_rejects_129() {
        let ok = "a".repeat(MAX_LEN);
        assert!(StreamId::new(&ok).is_ok());
        let long = "a".repeat(MAX_LEN + 1);
        assert_eq!(
            StreamId::new(&long).unwrap_err(),
            IdError::TooLong { len: MAX_LEN + 1 }
        );
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(StreamId::new("").unwrap_err(), IdError::Empty);
    }

    #[test]
    fn rejects_other_characters_with_their_position() {
        assert_eq!(
            StreamId::new("front door").unwrap_err(),
            IdError::InvalidChar { ch: ' ', index: 5 }
        );
        assert_eq!(
            SessionId::new("ünicode").unwrap_err(),
            IdError::InvalidChar { ch: 'ü', index: 0 }
        );
        assert_eq!(
            StreamId::new("a/b").unwrap_err(),
            IdError::InvalidChar { ch: '/', index: 1 }
        );
    }

    #[test]
    fn counts_characters_not_bytes() {
        // 129 characters in 129 bytes fails on length before any character
        // check would matter; a multibyte character fails on the character.
        let mixed = format!("{}é", "a".repeat(MAX_LEN));
        assert_eq!(
            StreamId::new(&mixed).unwrap_err(),
            IdError::InvalidChar {
                ch: 'é',
                index: MAX_LEN
            }
        );
    }

    #[test]
    fn round_trips_through_display_and_from_str() {
        let id: StreamId = "front".parse().unwrap();
        assert_eq!(id.to_string(), "front");
        assert_eq!(id.as_ref(), "front");
        assert_eq!(format!("{id:?}"), "StreamId(\"front\")");
        assert_eq!("front".parse::<StreamId>().unwrap(), id);
    }

    #[test]
    fn error_messages_name_the_rule() {
        assert_eq!(
            IdError::TooLong { len: 200 }.to_string(),
            "identifier is 200 characters long, the maximum is 128"
        );
        assert_eq!(
            IdError::InvalidChar { ch: ' ', index: 5 }.to_string(),
            "identifier contains ' ' at position 5; allowed are A-Z, a-z, 0-9, '.', '_' and '-'"
        );
        assert_eq!(IdError::Empty.to_string(), "identifier is empty");
    }
}
