//! The records a framed live output writes into its pipe: the init segment
//! and each fragment behind a fixed header that says what it is, whether it
//! starts with a keyframe and how long its video lasts, so the supervisor
//! can cut LL-HLS parts and segments without parsing a byte of the media.
//!
//! The worker writes them ([`header`]); the supervisor reads them
//! ([`Decoder`]) as untrusted input: every header field is checked, a record
//! is at most [`MAX_RECORD_BYTES`], and the decoder never holds more than one
//! record and one header, so a worker cannot make the supervisor buffer
//! without bound. The first record that breaks the format ends the stream
//! ([`RecordError`]).
//!
//! The header, [`HEADER_BYTES`] bytes, big-endian: the magic `LF`, the
//! version (1), the kind (0 the init segment, 1 a fragment), the flags (bit
//! 0: the fragment starts with a keyframe; every other bit 0), three zero
//! bytes, the video's duration in microseconds (`u32`, 0 for the init
//! segment and for a fragment of audio alone, at most
//! [`MAX_DURATION_US`]) and the record's length (`u32`).

use std::time::Duration;

use bytes::{Buf as _, Bytes, BytesMut};

/// The header's length.
pub const HEADER_BYTES: usize = 16;

/// The largest record: far above a fragment of one frame of
/// `limits.max_frame_bytes` (4 MiB by default) and its audio.
pub const MAX_RECORD_BYTES: u32 = 64 * 1024 * 1024;

/// The longest video duration a record may say: a frame of a camera that
/// sends one a minute.
pub const MAX_DURATION_US: u32 = 60_000_000;

/// The header's first two bytes.
const MAGIC: [u8; 2] = *b"LF";

/// The format's version.
const VERSION: u8 = 1;

/// The flag of a fragment that starts with a keyframe.
const INDEPENDENT: u8 = 0x01;

/// What a record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// The init segment.
    Init,
    /// A fragment.
    Fragment {
        /// It starts with a video keyframe.
        independent: bool,
        /// How long its video lasts; zero for audio alone.
        duration: Duration,
    },
}

/// One record: what it is and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// What it holds.
    pub kind: RecordKind,
    /// Its bytes.
    pub bytes: Bytes,
}

/// Why a stream of records is broken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The header does not start with the magic and the version.
    #[error("not a live record header")]
    Header,
    /// An unknown kind, a flag or a reserved byte set where none may be,
    /// or a duration on an init segment.
    #[error("a live record header with a field out of its range")]
    Field,
    /// A record longer than [`MAX_RECORD_BYTES`], or a duration longer
    /// than [`MAX_DURATION_US`].
    #[error("a live record over its bound")]
    TooLarge,
}

/// The header of a record of `kind` and `len` bytes; `None` when `len` or
/// the duration is over its bound, which no record of a working output is.
pub fn header(kind: RecordKind, len: usize) -> Option<[u8; HEADER_BYTES]> {
    let len = u32::try_from(len)
        .ok()
        .filter(|len| *len <= MAX_RECORD_BYTES)?;
    let (kind, flags, duration) = match kind {
        RecordKind::Init => (0, 0, 0),
        RecordKind::Fragment {
            independent,
            duration,
        } => {
            let micros = u32::try_from(duration.as_micros())
                .ok()
                .filter(|micros| *micros <= MAX_DURATION_US)?;
            (1, if independent { INDEPENDENT } else { 0 }, micros)
        }
    };
    let [m0, m1] = MAGIC;
    let [d0, d1, d2, d3] = duration.to_be_bytes();
    let [l0, l1, l2, l3] = len.to_be_bytes();
    Some([
        m0, m1, VERSION, kind, flags, 0, 0, 0, d0, d1, d2, d3, l0, l1, l2, l3,
    ])
}

/// The kind and length a header says, checked.
fn parse(header: [u8; HEADER_BYTES]) -> Result<(RecordKind, u32), RecordError> {
    let [
        m0,
        m1,
        version,
        kind,
        flags,
        r0,
        r1,
        r2,
        d0,
        d1,
        d2,
        d3,
        l0,
        l1,
        l2,
        l3,
    ] = header;
    if [m0, m1] != MAGIC || version != VERSION {
        return Err(RecordError::Header);
    }
    let duration = u32::from_be_bytes([d0, d1, d2, d3]);
    let len = u32::from_be_bytes([l0, l1, l2, l3]);
    if [r0, r1, r2] != [0; 3] || flags & !INDEPENDENT != 0 {
        return Err(RecordError::Field);
    }
    if len > MAX_RECORD_BYTES || duration > MAX_DURATION_US {
        return Err(RecordError::TooLarge);
    }
    let kind = match kind {
        0 if flags == 0 && duration == 0 => RecordKind::Init,
        1 => RecordKind::Fragment {
            independent: flags & INDEPENDENT != 0,
            duration: Duration::from_micros(u64::from(duration)),
        },
        _ => return Err(RecordError::Field),
    };
    Ok((kind, len))
}

/// Reads records from the bytes of a pipe as they come.
#[derive(Debug, Default)]
pub struct Decoder {
    /// Bytes taken that complete no record yet: at most a header and one
    /// record's bytes.
    buffer: BytesMut,
    /// The header of the record whose bytes are coming, once read.
    pending: Option<(RecordKind, usize)>,
}

impl Decoder {
    /// A decoder at the start of a stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many bytes the next call of [`Self::push`] may usefully take:
    /// what the record or header in progress lacks, so the caller reads no
    /// more than one record ahead.
    pub fn wants(&self) -> usize {
        let need = self.pending.map_or(HEADER_BYTES, |(_, len)| len);
        need.saturating_sub(self.buffer.len()).max(1)
    }

    /// Takes `bytes` from the stream and returns the records they complete,
    /// in order; the first broken header ends the stream with its error.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Record>, RecordError> {
        self.buffer.extend_from_slice(bytes);
        let mut records = Vec::new();
        loop {
            match self.pending {
                None => {
                    let Some(head) = self.buffer.get(..HEADER_BYTES) else {
                        return Ok(records);
                    };
                    let mut header = [0; HEADER_BYTES];
                    header.copy_from_slice(head);
                    let (kind, len) = parse(header)?;
                    self.buffer.advance(HEADER_BYTES);
                    self.pending = Some((kind, usize::try_from(len).unwrap_or(usize::MAX)));
                }
                Some((kind, len)) => {
                    if self.buffer.len() < len {
                        return Ok(records);
                    }
                    let bytes = self.buffer.split_to(len).freeze();
                    self.pending = None;
                    records.push(Record { kind, bytes });
                }
            }
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

    fn fragment(independent: bool, ms: u64) -> RecordKind {
        RecordKind::Fragment {
            independent,
            duration: Duration::from_millis(ms),
        }
    }

    fn framed(kind: RecordKind, bytes: &[u8]) -> Vec<u8> {
        let mut out = header(kind, bytes.len()).unwrap().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn records_round_trip_whatever_the_reads_split_them_into() {
        let stream = [
            framed(RecordKind::Init, b"ftypmoov"),
            framed(fragment(true, 40), b"moof-key"),
            framed(fragment(false, 33), b""),
        ]
        .concat();
        assert_eq!(
            &stream[..HEADER_BYTES],
            b"LF\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08"
        );
        let expected = vec![
            Record {
                kind: RecordKind::Init,
                bytes: Bytes::from_static(b"ftypmoov"),
            },
            Record {
                kind: fragment(true, 40),
                bytes: Bytes::from_static(b"moof-key"),
            },
            Record {
                kind: fragment(false, 33),
                bytes: Bytes::new(),
            },
        ];
        for step in [1, 3, HEADER_BYTES, stream.len()] {
            let mut decoder = Decoder::new();
            let mut got = Vec::new();
            for chunk in stream.chunks(step) {
                assert!(decoder.wants() >= 1);
                got.extend(decoder.push(chunk).unwrap());
            }
            assert_eq!(got, expected, "reads of {step}");
        }
    }

    #[test]
    fn the_decoder_wants_what_the_header_or_record_in_progress_lacks() {
        let mut decoder = Decoder::new();
        assert_eq!(decoder.wants(), HEADER_BYTES);
        assert_eq!(
            decoder.push(&framed(RecordKind::Init, b"abcd")[..10]),
            Ok(Vec::new())
        );
        assert_eq!(decoder.wants(), HEADER_BYTES - 10);
        let rest = &framed(RecordKind::Init, b"abcd")[10..];
        assert_eq!(decoder.push(&rest[..7]), Ok(Vec::new()));
        assert_eq!(decoder.wants(), 3);
        assert_eq!(decoder.push(&rest[7..]).unwrap().len(), 1);
        let empty = framed(fragment(false, 1), b"");
        let mut decoder = Decoder::new();
        decoder.push(&empty[..HEADER_BYTES - 1]).unwrap();
        assert_eq!(decoder.wants(), 1);
    }

    #[test]
    fn a_header_out_of_its_format_breaks_the_stream() {
        let good = header(fragment(true, 40), 4).unwrap();
        let broken = |at: usize, value: u8| {
            let mut header = good;
            header[at] = value;
            Decoder::new().push(&header).unwrap_err()
        };
        assert_eq!(broken(0, b'X'), RecordError::Header);
        assert_eq!(broken(2, 2), RecordError::Header, "another version");
        assert_eq!(broken(3, 2), RecordError::Field, "an unknown kind");
        assert_eq!(broken(4, 0x03), RecordError::Field, "an unknown flag");
        for at in 5..8 {
            assert_eq!(broken(at, 1), RecordError::Field, "reserved byte {at}");
        }
        let mut init = header(RecordKind::Init, 4).unwrap();
        init[4] = INDEPENDENT;
        assert_eq!(Decoder::new().push(&init).unwrap_err(), RecordError::Field);
        let mut init = header(RecordKind::Init, 4).unwrap();
        init[11] = 1;
        assert_eq!(
            Decoder::new().push(&init).unwrap_err(),
            RecordError::Field,
            "an init segment has no duration"
        );
        let mut long = good;
        long[12..].copy_from_slice(&(MAX_RECORD_BYTES + 1).to_be_bytes());
        assert_eq!(
            Decoder::new().push(&long).unwrap_err(),
            RecordError::TooLarge
        );
        let mut slow = good;
        slow[8..12].copy_from_slice(&(MAX_DURATION_US + 1).to_be_bytes());
        assert_eq!(
            Decoder::new().push(&slow).unwrap_err(),
            RecordError::TooLarge
        );
        let mut edge = good;
        edge[8..12].copy_from_slice(&MAX_DURATION_US.to_be_bytes());
        edge[12..].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            Decoder::new().push(&edge).unwrap().len(),
            1,
            "the bounds are in"
        );
        assert_eq!(
            RecordError::TooLarge.to_string(),
            "a live record over its bound"
        );
    }

    #[test]
    fn a_header_is_made_only_within_the_bounds() {
        let max = usize::try_from(MAX_RECORD_BYTES).unwrap();
        assert_eq!(max, 64 << 20, "64 MiB, as documented");
        assert!(header(RecordKind::Init, max).is_some());
        assert!(header(RecordKind::Init, max + 1).is_none());
        let longest = RecordKind::Fragment {
            independent: false,
            duration: Duration::from_micros(u64::from(MAX_DURATION_US)),
        };
        assert!(header(longest, 0).is_some());
        let too_long = RecordKind::Fragment {
            independent: false,
            duration: Duration::from_micros(u64::from(MAX_DURATION_US) + 1),
        };
        assert!(header(too_long, 0).is_none());
    }
}
