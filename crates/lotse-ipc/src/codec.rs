//! Message encoding: `postcard` with a hard size cap in both directions.
//!
//! Decoding is total over arbitrary bytes: it never panics and never
//! allocates beyond what the bytes describe, which the `ipc_message` fuzz
//! target checks.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The largest message either side accepts or sends, encoded: 256 KiB.
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// What can go wrong on the channel.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The message is larger than [`MAX_MESSAGE_BYTES`].
    #[error("message of {len} bytes exceeds the {max}-byte limit")]
    TooLarge {
        /// The size found.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// The message does not encode (a bug: every message type encodes).
    #[error("message does not encode: {0}")]
    Encode(String),
    /// The bytes are not a message of the expected type.
    #[error("message does not decode: {0}")]
    Decode(String),
    /// The bytes decode but continue past the message.
    #[error("message has {0} trailing bytes")]
    Trailing(usize),
    /// The peer closed the channel inside a frame.
    #[error("peer closed the channel mid-frame after {have} of {want} bytes")]
    Truncated {
        /// Bytes received.
        have: usize,
        /// Bytes the frame announced.
        want: usize,
    },
    /// More descriptors than a message may carry.
    #[error("message carries {0} descriptors, the maximum is {max}", max = super::channel::MAX_FDS)]
    TooManyFds(usize),
    /// The kernel discarded descriptors the message carried: no free slot
    /// in this process's descriptor table, or more in one write than the
    /// ancillary buffer holds.
    #[error("the kernel discarded descriptors the message carried")]
    FdsTruncated,
    /// The socket failed.
    #[error("channel i/o failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Encodes `message`, refusing one that would exceed the cap.
pub fn encode<T: Serialize + ?Sized>(message: &T) -> Result<Vec<u8>, IpcError> {
    let bytes = postcard::to_allocvec(message).map_err(|err| IpcError::Encode(err.to_string()))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(IpcError::TooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    Ok(bytes)
}

/// Decodes exactly one message from `bytes`.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, IpcError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(IpcError::TooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    let (message, rest) =
        postcard::take_from_bytes(bytes).map_err(|err| IpcError::Decode(err.to_string()))?;
    if !rest.is_empty() {
        return Err(IpcError::Trailing(rest.len()));
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::message::{SourceState, ToSupervisor};

    #[test]
    fn round_trips_a_message() {
        let message = ToSupervisor::SourceState(SourceState::Backoff {
            code: "source_timeout".into(),
            message: "stall".into(),
            retry_ms: 1_000,
        });
        let bytes = encode(&message).unwrap();
        assert_eq!(decode::<ToSupervisor>(&bytes).unwrap(), message);
    }

    #[test]
    fn rejects_trailing_garbage_and_truncation() {
        let mut bytes = encode(&ToSupervisor::Ready { pid: 7 }).unwrap();
        bytes.push(0);
        assert!(matches!(
            decode::<ToSupervisor>(&bytes).unwrap_err(),
            IpcError::Trailing(1)
        ));
        let short = &bytes[..bytes.len() - 2];
        assert!(matches!(
            decode::<ToSupervisor>(short).unwrap_err(),
            IpcError::Decode(_)
        ));
        assert!(matches!(
            decode::<ToSupervisor>(&[0xff, 0xff, 0xff, 0xff, 0xff]).unwrap_err(),
            IpcError::Decode(_)
        ));
    }

    #[test]
    fn caps_the_size_in_both_directions() {
        let big = vec![0_u8; MAX_MESSAGE_BYTES + 1];
        let err = encode(&big).unwrap_err();
        assert!(matches!(err, IpcError::TooLarge { .. }), "{err}");
        assert_eq!(
            err.to_string(),
            format!(
                "message of {} bytes exceeds the {MAX_MESSAGE_BYTES}-byte limit",
                MAX_MESSAGE_BYTES + 1 + 3 // the elements plus a three-byte varint length
            )
        );
        let err = decode::<Vec<u8>>(&big).unwrap_err();
        assert!(matches!(err, IpcError::TooLarge { .. }));
        let fits = vec![1_u8; MAX_MESSAGE_BYTES - 8];
        assert_eq!(decode::<Vec<u8>>(&encode(&fits).unwrap()).unwrap(), fits);
    }

    #[test]
    fn errors_display() {
        assert_eq!(
            IpcError::Truncated { have: 3, want: 10 }.to_string(),
            "peer closed the channel mid-frame after 3 of 10 bytes"
        );
        assert_eq!(
            IpcError::TooManyFds(9).to_string(),
            "message carries 9 descriptors, the maximum is 8"
        );
        assert_eq!(
            IpcError::FdsTruncated.to_string(),
            "the kernel discarded descriptors the message carried"
        );
        assert_eq!(
            IpcError::Encode("x".into()).to_string(),
            "message does not encode: x"
        );
        let io: IpcError = std::io::Error::other("boom").into();
        assert_eq!(io.to_string(), "channel i/o failed: boom");
    }
}
