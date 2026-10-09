//! Frames one side of the relay's byte stream into whole RTSP messages
//! (RFC 2326 §4, and §10.12 interleaved frames) with the parser retina reads
//! them with (`retina::rtsp::parse`, public but unstable, pinned by
//! `Cargo.lock`), so the relay finds the same messages retina does.
//!
//! The UDP side ([`crate::udp`]) frames both directions with it, the TCP
//! relay what retina writes, so a receiver report ([`crate::rtcp`]) goes
//! to the camera between whole requests, and the camera's interleaved
//! stream ([`crate::tap`]) its RTSP messages between the frames. It holds
//! at most one message of [`MAX_MESSAGE`] bytes.

use std::fmt;

use retina::rtsp::msg::Message;
use retina::rtsp::parse::{FeedError, Parser};

/// The most bytes of one RTSP message, head and body, the relay frames and
/// retina reads (its `SessionOptions::max_message_size`): the bound on an
/// RTSP response and its SDP. Interleaved frames are bounded by their
/// 16-bit length (RFC 2326 §10.12) instead.
pub(crate) const MAX_MESSAGE: usize = 65_536;

/// One whole RTSP message as it was framed: its head, its bytes, and how
/// many of them at the end are its body.
#[derive(Debug)]
pub(crate) struct Framed {
    /// The head retina's parser read.
    pub(crate) head: Message,
    /// The whole message.
    pub(crate) raw: Vec<u8>,
    /// The body's length.
    pub(crate) body_len: usize,
}

impl Framed {
    /// The body: the last [`Self::body_len`] bytes.
    pub(crate) fn body(&self) -> &[u8] {
        let at = self.raw.len().saturating_sub(self.body_len);
        self.raw.get(at..).unwrap_or_default()
    }
}

/// Frames one side's byte stream into whole RTSP messages with retina's
/// parser, holding at most one message of [`MAX_MESSAGE`] bytes.
#[derive(Default)]
pub(crate) struct Framer {
    /// The parser, which keeps its place in the message it is reading.
    parser: Parser,
    /// The bytes not yet framed into a whole message.
    pub(crate) pending: Vec<u8>,
    /// The bytes of `pending` the parser has taken already.
    taken: usize,
}

impl fmt::Debug for Framer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // retina's parser has no `Debug`.
        f.debug_struct("Framer")
            .field("pending", &self.pending.len())
            .field("taken", &self.taken)
            .finish_non_exhaustive()
    }
}

impl Framer {
    /// The next whole message of what was pushed, `None` until there is
    /// one; an error for bytes retina's parser cannot read or a message
    /// over the bound.
    pub(crate) fn next(&mut self) -> Result<Option<Framed>, String> {
        let rest = self.pending.get(self.taken..).unwrap_or_default();
        let mut input: &[u8] = rest;
        let fed = self
            .parser
            .feed(&mut input)
            .map(|framed| framed.map(|(head, body)| (head, body.len())));
        let end = self
            .taken
            .saturating_add(rest.len().saturating_sub(input.len()));
        match fed {
            Ok(Some((head, body_len))) => {
                let raw = self.pending.drain(..end).collect();
                self.taken = 0;
                Ok(Some(Framed {
                    head,
                    raw,
                    body_len,
                }))
            }
            Ok(None) => Ok(None),
            Err(FeedError::Incomplete(_)) => {
                self.taken = end;
                if self.pending.len() > MAX_MESSAGE {
                    return Err(format!("an RTSP message exceeds {MAX_MESSAGE} bytes"));
                }
                Ok(None)
            }
            Err(FeedError::Invalid(err)) => Err(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    const DESCRIBED: &[u8] =
        b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: 5\r\n\r\nv=0\r\n";

    #[test]
    fn the_framer_holds_one_message_and_refuses_what_retina_cannot_read() {
        let mut framer = Framer::default();
        assert!(format!("{framer:?}").starts_with("Framer"));
        assert!(framer.next().unwrap().is_none());
        framer.pending.extend_from_slice(&DESCRIBED[..20]);
        assert!(framer.next().unwrap().is_none());
        framer.pending.extend_from_slice(&DESCRIBED[20..]);
        framer.pending.extend_from_slice(b"$\x00\x00\x01z");
        let unit = framer.next().unwrap().unwrap();
        assert_eq!((unit.raw.as_slice(), unit.body_len), (DESCRIBED, 5));
        assert_eq!(unit.body(), b"v=0\r\n");
        let unit = framer.next().unwrap().unwrap();
        assert!(matches!(unit.head, Message::Data(_)));
        assert_eq!(unit.body(), b"z");
        assert!(framer.next().unwrap().is_none());
        // One message at the bound is held; one byte over is refused.
        let mut framer = Framer::default();
        framer
            .pending
            .extend_from_slice(b"RTSP/1.0 200 OK\r\nContent-Length: 100000\r\n\r\n");
        framer.pending.resize(MAX_MESSAGE, b'x');
        assert!(framer.next().unwrap().is_none());
        framer.pending.push(b'x');
        assert!(framer.next().unwrap_err().contains("exceeds"));
        let mut framer = Framer::default();
        framer
            .pending
            .extend_from_slice(b"\x01\x02 not rtsp\r\n\r\n");
        assert!(framer.next().is_err());
    }
}
