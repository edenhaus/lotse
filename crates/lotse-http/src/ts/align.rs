//! Packet alignment in front of the demultiplexer: bytes in any pieces
//! become runs of whole 188-byte transport packets, each beginning with
//! the sync byte (ISO/IEC 13818-1 §2.4.3.2, `sync_byte` 0x47).
//!
//! mpeg2ts-reader's `Demultiplex::push` takes whole packets only: it drops
//! a partial packet at the end of a buffer and stops at the first packet
//! without the sync byte, ignoring the rest of the buffer. This module
//! keeps the partial packet for the next push and finds the packet
//! boundary again after bytes were lost or inserted.
//!
//! Sync is acquired where three sync bytes 188 bytes apart begin
//! ([`CONFIRM`]): one sync byte alone matches a payload byte in one of 256
//! positions, three in one of 16.7 million. Once acquired, it holds while
//! every packet begins with the sync byte; the first one that does not
//! loses it, and the search starts again at the next byte. Packets of 192
//! (M2TS) or 204 bytes (with Reed-Solomon parity) are not read: HLS
//! segments are ISO/IEC 13818-1 transport streams (RFC 8216 §3.2), and
//! MPEG-TS over HTTP is the same stream.

/// The size of a transport packet (ISO/IEC 13818-1 §2.4.3.2).
pub(super) const PACKET: usize = 188;

/// The `sync_byte` every transport packet begins with (ISO/IEC 13818-1
/// §2.4.3.2).
const SYNC: u8 = 0x47;

/// Sync bytes, [`PACKET`] bytes apart, that acquire sync.
const CONFIRM: usize = 3;

/// The bytes needed to confirm sync at a position: the first byte of
/// each of [`CONFIRM`] packets.
const WINDOW: usize = PACKET * (CONFIRM - 1) + 1;

/// What the aligner counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct AlignStats {
    /// Whole packets handed on.
    pub(super) packets: u64,
    /// Bytes skipped looking for sync.
    pub(super) skipped_bytes: u64,
    /// Times a packet did not begin with the sync byte.
    pub(super) sync_losses: u64,
}

/// The aligner of one byte stream.
#[derive(Debug, Default)]
pub(super) struct Aligner {
    /// Bytes not handed on yet: a partial packet while in sync, the
    /// candidate position and what follows it while searching. Fewer than
    /// [`WINDOW`] bytes between pushes.
    pending: Vec<u8>,
    /// Whether the next byte begins a packet.
    synced: bool,
    /// Counters.
    stats: AlignStats,
}

/// Whether sync can be acquired at the start of `bytes`: `Some(true)` if
/// [`CONFIRM`] packets begin there, `Some(false)` if one cannot, `None`
/// while too few bytes are there to tell.
fn confirmed(bytes: &[u8]) -> Option<bool> {
    let mut available = true;
    for k in 0..CONFIRM {
        match bytes.get(k.saturating_mul(PACKET)) {
            Some(&SYNC) => {}
            Some(_) => return Some(false),
            None => available = false,
        }
    }
    available.then_some(true)
}

impl Aligner {
    /// The counters.
    pub(super) const fn stats(&self) -> AlignStats {
        self.stats
    }

    /// Bytes held for the next push: fewer than [`WINDOW`].
    pub(super) const fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Takes the next bytes of the stream and hands each run of whole,
    /// aligned packets they complete to `feed`.
    pub(super) fn push(&mut self, data: &[u8], feed: &mut impl FnMut(&[u8])) {
        let mut rest = data;
        // The held bytes first, joined with at most a window of new ones.
        // A scan of the held bytes and a full window gets past the held
        // ones, so new bytes are held again only when all of them fit the
        // window.
        if !self.pending.is_empty() {
            let held = self.pending.len();
            let (window, beyond) = rest.split_at(rest.len().min(WINDOW));
            let mut joined = std::mem::take(&mut self.pending);
            joined.extend_from_slice(window);
            let used = self.scan(&joined, feed);
            let Some(past) = used.checked_sub(held) else {
                joined.drain(..used);
                joined.extend_from_slice(beyond);
                self.pending = joined;
                return;
            };
            rest = rest.get(past..).unwrap_or_default();
        }
        let used = self.scan(rest, feed);
        self.pending = rest.get(used..).unwrap_or_default().to_vec();
    }

    /// Hands on the aligned packets at the start of `bytes` and returns
    /// how many bytes it used: what follows is a partial packet, or a
    /// position where sync may still be acquired once more bytes come.
    /// Every turn of its loop uses a byte or acquires sync.
    fn scan(&mut self, bytes: &[u8], feed: &mut impl FnMut(&[u8])) -> usize {
        let mut position = 0_usize;
        while let Some(rest) = bytes.get(position..).filter(|rest| !rest.is_empty()) {
            if self.synced {
                let whole = rest
                    .as_chunks::<PACKET>()
                    .0
                    .iter()
                    .take_while(|packet| packet.first() == Some(&SYNC))
                    .count();
                let run = whole.saturating_mul(PACKET);
                if let Some(packets) = rest.get(..run).filter(|run| !run.is_empty()) {
                    feed(packets);
                    self.stats.packets = self
                        .stats
                        .packets
                        .saturating_add(u64::try_from(whole).unwrap_or(u64::MAX));
                }
                position = position.saturating_add(run);
                match rest.get(run) {
                    Some(&byte) if byte != SYNC => {
                        // That byte begins no packet: skipped at once.
                        self.synced = false;
                        self.stats.sync_losses = self.stats.sync_losses.saturating_add(1);
                        self.stats.skipped_bytes = self.stats.skipped_bytes.saturating_add(1);
                        position = position.saturating_add(1);
                    }
                    _ => return position,
                }
            } else {
                match confirmed(rest) {
                    Some(true) => self.synced = true,
                    None => return position,
                    Some(false) => {
                        self.stats.skipped_bytes = self.stats.skipped_bytes.saturating_add(1);
                        position = position.saturating_add(1);
                    }
                }
            }
        }
        position
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

    /// `count` packets, each its index in every byte after the sync byte.
    fn packets(count: u8) -> Vec<u8> {
        (0..count)
            .flat_map(|i| std::iter::once(SYNC).chain(std::iter::repeat_n(i, PACKET - 1)))
            .collect()
    }

    /// The packets `chunks` hand on, pushed one after the other.
    fn run(aligner: &mut Aligner, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in chunks {
            aligner.push(chunk, &mut |run: &[u8]| {
                assert_eq!(run.len() % PACKET, 0);
                assert!(run.chunks(PACKET).all(|p| p[0] == SYNC));
                out.extend_from_slice(run);
            });
            assert!(aligner.buffered() < WINDOW);
        }
        out
    }

    #[test]
    fn iso13818_1_2_4_3_2_aligned_packets_pass_whole() {
        let stream = packets(5);
        let mut aligner = Aligner::default();
        assert_eq!(run(&mut aligner, &[&stream]), stream);
        assert_eq!(
            aligner.stats(),
            AlignStats {
                packets: 5,
                ..AlignStats::default()
            }
        );
        assert_eq!(aligner.buffered(), 0);
    }

    #[test]
    fn iso13818_1_2_4_3_2_any_cut_gives_the_same_packets() {
        let stream = packets(6);
        for size in [1, 2, 100, 187, 188, 189, 376, 377, 500] {
            let mut aligner = Aligner::default();
            let chunks: Vec<&[u8]> = stream.chunks(size).collect();
            assert_eq!(run(&mut aligner, &chunks), stream, "pieces of {size}");
            assert_eq!(aligner.stats().packets, 6, "pieces of {size}");
            assert_eq!(aligner.buffered(), 0, "pieces of {size}");
        }
    }

    #[test]
    fn iso13818_1_2_4_3_2_a_trailing_partial_packet_waits_for_its_rest() {
        let stream = packets(4);
        let mut aligner = Aligner::default();
        assert_eq!(
            run(&mut aligner, &[&stream[..3 * PACKET + 10]]),
            stream[..3 * PACKET]
        );
        assert_eq!(aligner.buffered(), 10);
        assert_eq!(
            run(&mut aligner, &[&stream[3 * PACKET + 10..]]),
            stream[3 * PACKET..]
        );
        assert_eq!(aligner.buffered(), 0);
    }

    #[test]
    fn iso13818_1_2_4_3_2_garbage_before_the_first_packet_is_skipped() {
        let stream = packets(4);
        let mut input = vec![SYNC, 1, 2, 3, SYNC];
        input.extend_from_slice(&stream);
        let mut aligner = Aligner::default();
        assert_eq!(run(&mut aligner, &[&input]), stream);
        assert_eq!(aligner.stats().skipped_bytes, 5);
        assert_eq!(aligner.stats().sync_losses, 0);
    }

    #[test]
    fn iso13818_1_2_4_3_2_a_packet_without_the_sync_byte_loses_sync_until_three_follow() {
        let stream = packets(8);
        let mut input = stream[..2 * PACKET].to_vec();
        // Two bytes lost in the third packet, which no longer ends where
        // the fourth begins.
        input.extend_from_slice(&stream[2 * PACKET..3 * PACKET - 2]);
        input.extend_from_slice(&stream[3 * PACKET..]);
        for size in [1, 50, 188, input.len()] {
            let mut aligner = Aligner::default();
            let chunks: Vec<&[u8]> = input.chunks(size).collect();
            let out = run(&mut aligner, &chunks);
            // The short third packet still begins with the sync byte and
            // passes with the fourth's first bytes; the fourth, which then
            // does not, is the one lost.
            let mut expected = input[..3 * PACKET].to_vec();
            expected.extend_from_slice(&stream[4 * PACKET..]);
            assert_eq!(out, expected, "pieces of {size}");
            assert_eq!(aligner.stats().sync_losses, 1, "pieces of {size}");
            assert_eq!(aligner.stats().skipped_bytes, PACKET as u64 - 2);
            assert_eq!(aligner.stats().packets, 7);
        }
    }

    #[test]
    fn iso13818_1_2_4_3_2_sync_waits_for_three_packets_and_a_lone_sync_byte_is_skipped() {
        let stream = packets(3);
        let mut aligner = Aligner::default();
        // Two packets and the third's sync byte missing: nothing is
        // confirmed yet.
        assert!(run(&mut aligner, &[&stream[..2 * PACKET]]).is_empty());
        assert_eq!(aligner.buffered(), 2 * PACKET);
        assert_eq!(run(&mut aligner, &[&stream[2 * PACKET..]]), stream);
        // Out of sync, a sync byte without its successors is skipped.
        let mut aligner = Aligner::default();
        let mut input = vec![SYNC; 1];
        input.extend_from_slice(&[0; PACKET]);
        assert!(run(&mut aligner, &[&input]).is_empty());
        assert_eq!(aligner.stats().skipped_bytes, PACKET as u64 + 1);
        assert_eq!(aligner.buffered(), 0);
    }

    #[test]
    fn iso13818_1_2_4_3_2_held_bytes_rejected_against_new_ones_are_dropped_in_order() {
        // A candidate held from one push is refuted by the next: the held
        // bytes go first, then the new ones are scanned on their own.
        let stream = packets(4);
        let mut aligner = Aligner::default();
        let mut first = vec![SYNC];
        first.extend_from_slice(&[9; 10]);
        assert!(run(&mut aligner, &[&first]).is_empty());
        assert_eq!(aligner.buffered(), 11);
        let mut second = vec![9; WINDOW + 3];
        second.extend_from_slice(&stream);
        assert_eq!(run(&mut aligner, &[&second]), stream);
        assert_eq!(aligner.stats().skipped_bytes, 11 + WINDOW as u64 + 3);
    }

    #[test]
    fn iso13818_1_2_4_3_2_held_bytes_still_short_of_a_window_stay_held() {
        // One byte at a time: the candidate stays held with every byte
        // until the window is complete.
        let stream = packets(3);
        let mut aligner = Aligner::default();
        let chunks: Vec<&[u8]> = stream[..WINDOW - 1].chunks(1).collect();
        assert!(run(&mut aligner, &chunks).is_empty());
        assert_eq!(aligner.buffered(), WINDOW - 1);
        assert_eq!(aligner.stats().skipped_bytes, 0);
    }
}
