//! Reads along the camera's side of a TCP interleaved session for the
//! receiver reports ([`crate::rtcp`]): the relay forwards every byte at
//! once, and the tap finds the interleaved frames in it (RFC 2326 §10.12:
//! `$`, the channel, a 16-bit length, the packet), hands the first
//! [`HEAD`] bytes of each to the statistics, and skips the rest without
//! holding it.
//! The RTSP messages between the frames go through a [`Framer`], which
//! holds one at most, so the tap learns from each successful `SETUP`
//! answer (§12.39 `interleaved=N-M`) which channel a stream takes.
//!
//! It sees the stream exactly as retina does, so it stays in step with
//! retina's own parser. Bytes the framer cannot
//! read end retina's session too; the tap stops reading along then, and
//! the stream's reports with it.

use std::time::Instant;

use retina::rtsp::msg::Message;

use crate::framer::{Framed, Framer};
use crate::rtcp::{HEAD, ReceiverReports};

/// The first channel of an `interleaved` parameter in a `Transport`
/// header (RFC 2326 §12.39), when it names one.
pub(crate) fn interleaved(transport: &str) -> Option<u8> {
    transport
        .split(';')
        .find_map(|param| param.trim().strip_prefix("interleaved="))
        .and_then(|range| range.split('-').next())
        .and_then(|first| first.trim().parse().ok())
}

/// Where the tap is in the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Between messages and frames.
    Boundary,
    /// In a frame's 4-byte header, `have` of them read.
    Header {
        /// The header so far.
        bytes: [u8; 4],
        /// How many.
        have: usize,
    },
    /// In a frame's packet.
    Packet {
        /// Its channel.
        channel: u8,
        /// Its bytes still to come.
        remaining: usize,
        /// Its first bytes.
        head: [u8; HEAD],
        /// How many of them.
        have: usize,
    },
    /// In an RTSP message, which the framer holds.
    Message,
}

/// What one step did with its input.
enum Step {
    /// Took this many bytes of it.
    Took(usize),
    /// Took all of it; these bytes, left over after a message, come next.
    Rest(Vec<u8>),
}

/// The tap on one connection.
#[derive(Debug)]
pub(crate) struct Tap {
    /// Where it is.
    state: State,
    /// The RTSP message it is in.
    framer: Framer,
    /// It lost the stream's framing and reads along no more.
    lost: bool,
}

impl Default for Tap {
    fn default() -> Self {
        Self {
            state: State::Boundary,
            framer: Framer::default(),
            lost: false,
        }
    }
}

impl Tap {
    /// Reads along `bytes`, which arrived at `now`, into `reports`; `true`
    /// when a report moved earlier.
    pub(crate) fn feed(
        &mut self,
        bytes: &[u8],
        now: Instant,
        reports: &mut ReceiverReports,
    ) -> bool {
        let mut moved = false;
        if self.lost {
            return moved;
        }
        let mut rest: Option<Vec<u8>> = None;
        let mut at = 0_usize;
        // Every other step at least takes a byte or drops a whole message
        // from the framer, so twice the bytes there are bound the steps:
        // no input can hold the relay in this loop.
        let steps = bytes
            .len()
            .saturating_add(self.framer.pending.len())
            .saturating_mul(2)
            .saturating_add(2);
        for _ in 0..steps {
            let source = rest.as_deref().unwrap_or(bytes);
            let input = source.get(at..).unwrap_or_default();
            if input.is_empty() {
                break;
            }
            match self.step(input, now, reports, &mut moved) {
                Step::Took(n) => at = at.saturating_add(n),
                Step::Rest(left) => {
                    rest = Some(left);
                    at = 0;
                }
            }
        }
        moved
    }

    /// One step on `input`, which is not empty.
    fn step(
        &mut self,
        input: &[u8],
        now: Instant,
        reports: &mut ReceiverReports,
        moved: &mut bool,
    ) -> Step {
        match &mut self.state {
            State::Boundary => {
                self.state = if input.first() == Some(&b'$') {
                    State::Header {
                        bytes: [0; 4],
                        have: 0,
                    }
                } else {
                    State::Message
                };
                Step::Took(0)
            }
            State::Header { bytes, have } => {
                let took = copy_into(bytes, have, input);
                if *have < bytes.len() {
                    return Step::Took(took);
                }
                let [_, channel, high, low] = *bytes;
                let remaining = usize::from(u16::from_be_bytes([high, low]));
                self.state = State::Packet {
                    channel,
                    remaining,
                    head: [0; HEAD],
                    have: 0,
                };
                if remaining == 0 {
                    *moved |= reports.packet(channel, &[], now);
                    self.state = State::Boundary;
                }
                Step::Took(took)
            }
            State::Packet {
                channel,
                remaining,
                head,
                have,
            } => {
                let took = input.len().min(*remaining);
                let before = *have;
                copy_into(head, have, input.get(..took).unwrap_or_default());
                *remaining = remaining.saturating_sub(took);
                // Read once, when its head is complete or it ends short.
                let complete = *have == HEAD || *remaining == 0;
                if complete && (before < HEAD) {
                    *moved |= reports.packet(*channel, head.get(..*have).unwrap_or_default(), now);
                }
                if *remaining == 0 {
                    self.state = State::Boundary;
                }
                Step::Took(took)
            }
            State::Message => {
                self.framer.pending.extend_from_slice(input);
                match self.framer.next() {
                    Ok(Some(framed)) => {
                        *moved |= read(&framed, now, reports);
                        self.state = State::Boundary;
                        Step::Rest(std::mem::take(&mut self.framer.pending))
                    }
                    Ok(None) => Step::Took(input.len()),
                    Err(why) => {
                        tracing::debug!(error = %why, "rtsp rtcp: the camera's stream is unreadable; no more receiver reports");
                        self.lost = true;
                        Step::Took(input.len())
                    }
                }
            }
        }
    }
}

/// Copies from `input` into `into` after its first `have` bytes, as many
/// as fit, and returns how many.
fn copy_into(into: &mut [u8], have: &mut usize, input: &[u8]) -> usize {
    let free = into.get_mut(*have..).unwrap_or_default();
    let n = free.len().min(input.len());
    if let (Some(to), Some(from)) = (free.get_mut(..n), input.get(..n)) {
        to.copy_from_slice(from);
    }
    *have = have.saturating_add(n);
    n
}

/// One whole message the framer found: a successful `SETUP` answer sets a
/// stream up, a frame (one that followed stray line ends, which the parser
/// skips) is read like any; `true` when a report moved earlier.
fn read(framed: &Framed, now: Instant, reports: &mut ReceiverReports) -> bool {
    match &framed.head {
        Message::Response(response) if response.status_code.is_success() => {
            let channel = response
                .headers
                .get("Transport")
                .and_then(|transport| interleaved(transport));
            if let Some(channel) = channel {
                reports.set_up(channel);
            }
            false
        }
        Message::Data(data) => {
            let body = framed.body();
            reports.packet(data.channel_id, body.get(..HEAD).unwrap_or(body), now)
        }
        Message::Response(_) | Message::Request(_) => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::sync::Arc;
    use std::time::Duration;

    use lotse_core::clock::{Clock as _, FakeClock};

    use super::*;
    use crate::rtcp::{Seed, SetupRates};

    const SETUP_ANSWER: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3\r\n\r\n";

    fn reports() -> ReceiverReports {
        let rates = Arc::new(SetupRates::default());
        rates.push(90_000);
        ReceiverReports::new(rates, Seed::random())
    }

    fn frame(channel: u8, packet: &[u8]) -> Vec<u8> {
        let mut out = vec![b'$', channel];
        out.extend_from_slice(&u16::try_from(packet.len()).unwrap().to_be_bytes());
        out.extend_from_slice(packet);
        out
    }

    fn rtp(seq: u16) -> Vec<u8> {
        let mut packet = vec![0x80, 96];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
        packet.extend_from_slice(&[0xaa; 40]);
        packet
    }

    #[test]
    fn rfc2326_12_39_interleaved_names_the_first_channel() {
        assert_eq!(interleaved("RTP/AVP/TCP;unicast;interleaved=2-3"), Some(2));
        assert_eq!(interleaved("RTP/AVP/TCP; interleaved= 4"), Some(4));
        assert_eq!(interleaved("RTP/AVP;unicast;client_port=5000-5001"), None);
        assert_eq!(interleaved("RTP/AVP/TCP;interleaved=x"), None);
    }

    #[test]
    fn rfc2326_10_12_the_tap_finds_every_frame_in_any_split_and_the_setup_answer() {
        let at = FakeClock::from_system().now();
        let mut stream = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 5\r\n\r\nv=0\r\n".to_vec();
        stream.extend_from_slice(SETUP_ANSWER);
        stream.extend_from_slice(b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 1\r\n\r\n");
        for seq in 1..=3 {
            stream.extend_from_slice(&frame(2, &rtp(seq)));
        }
        // An empty frame, a frame of another channel, a keepalive answer,
        // an SR and a frame after a stray line end.
        stream.extend_from_slice(&frame(0, &[]));
        stream.extend_from_slice(&frame(6, &rtp(1)));
        stream.extend_from_slice(b"RTSP/1.0 200 OK\r\nCSeq: 5\r\n\r\n");
        let mut sr = vec![
            0x80, 200, 0, 6, 0, 0, 0, 5, 0, 0, 0x12, 0x34, 0x56, 0x78, 0, 0,
        ];
        sr.extend_from_slice(&[0; 12]);
        stream.extend_from_slice(&frame(3, &sr));
        stream.extend_from_slice(b"\r\n");
        stream.extend_from_slice(&frame(2, &rtp(4)));
        stream.extend_from_slice(&frame(2, &rtp(5)[..10]));
        for split in [1, 2, 3, 7, 16, 61, stream.len()] {
            let mut tap = Tap::default();
            let mut reports = reports();
            let mut moved = 0;
            for chunk in stream.chunks(split) {
                moved += usize::from(tap.feed(chunk, at, &mut reports));
            }
            assert_eq!(moved, 1, "split {split}");
            assert_eq!(tap.state, State::Boundary, "split {split}");
            let due = reports.due().unwrap();
            let report = &reports.take_due(due + Duration::from_secs(1))[0];
            assert_eq!(report.channel, 2);
            // seq 2..=4 counted after probation, the short one not read.
            let extended = u32::from_be_bytes(report.packet[16..20].try_into().unwrap());
            let lsr = u32::from_be_bytes(report.packet[24..28].try_into().unwrap());
            assert_eq!((extended, lsr), (4, 0x1234_5678), "split {split}");
            // Each packet read once: nothing lost, nothing counted twice.
            assert_eq!(report.packet[13..16], [0, 0, 0], "split {split}");
        }
    }

    #[test]
    fn unreadable_bytes_stop_the_tap_and_refused_setups_set_nothing_up() {
        let at = FakeClock::from_system().now();
        let mut tap = Tap::default();
        let mut reports = reports();
        assert!(format!("{tap:?}").starts_with("Tap"));
        tap.feed(b"RTSP/1.0 461 Unsupported Transport\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n", at, &mut reports);
        tap.feed(b"OPTIONS * RTSP/1.0\r\nCSeq: 9\r\n\r\n", at, &mut reports);
        tap.feed(b"RTSP/1.0 200 OK\r\nCSeq: 4\r\n\r\n", at, &mut reports);
        assert!(!tap.feed(&frame(0, &rtp(1)), at, &mut reports));
        tap.feed(b"\x01\x02 junk\r\n\r\n", at, &mut reports);
        assert!(tap.lost);
        tap.feed(SETUP_ANSWER, at, &mut reports);
        assert!(!tap.feed(&frame(2, &rtp(1)), at, &mut reports));
        assert_eq!(reports.due(), None);
    }
}
