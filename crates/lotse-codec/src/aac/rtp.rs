//! AAC in RTP, on the side branch: RFC 3640 AAC-hbr payloads in, one raw
//! AAC frame per access unit out, for the AAC-LC → Opus transcoder.
//!
//! Implements RFC 3640 §3.2.1 (AU header section: the 16-bit
//! `AU-headers-length` in bits, then one header per unit), §3.2.3 (access
//! units, fragments of one unit across packets with the marker on the
//! last), §3.3.6 (AAC-hbr: 13-bit `AU-size`, 3-bit `AU-Index` and
//! `AU-Index-delta`) and §3.2.3.2 (units of one packet are consecutive, the
//! timestamp of the first plus one frame each). retina accepts only this
//! mode, so it is the one parsed. Interleaving (a non-zero index) is not
//! seen on cameras and is dropped. A camera that wraps units in ADTS
//! headers (ISO/IEC 13818-7 §6.2) gets them stripped.

use bytes::Bytes;

use super::config::FRAME_SAMPLES;

/// Bits of one AAC-hbr AU header: 13 size plus 3 index (RFC 3640 §3.3.6).
const HEADER_BITS: usize = 16;

/// The ADTS header without CRC (ISO/IEC 13818-7 §6.2.1).
const ADTS_HEADER: usize = 7;

/// The ADTS header with its 16-bit CRC.
const ADTS_HEADER_CRC: usize = 9;

/// One raw AAC frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AacFrame {
    /// Its RTP timestamp: the packet's plus one frame per unit before it.
    pub ts: u32,
    /// The raw `raw_data_block`, no ADTS header.
    pub payload: Bytes,
}

/// A payload that breaks RFC 3640 AAC-hbr; the packet is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AacPayloadError {
    /// Shorter than its header section says.
    #[error("payload truncated")]
    Truncated,
    /// `AU-headers-length` not a whole number of 16-bit headers, or zero.
    #[error("AU-headers-length {0} is not a multiple of 16 bits")]
    HeaderLength(u16),
    /// A non-zero `AU-Index` or `AU-Index-delta`: interleaving.
    #[error("interleaved access units are not supported")]
    Interleaved,
    /// A fragment with more than one AU header, or units that do not fill
    /// the payload exactly.
    #[error("AU sizes do not match the payload")]
    Sizes,
}

/// What the depacketizer counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AacStats {
    /// Frames emitted.
    pub frames: u64,
    /// Units dropped because a fragment was lost.
    pub dropped_lost: u64,
    /// Units dropped as larger than the limit.
    pub dropped_oversize: u64,
    /// Payloads that violated RFC 3640.
    pub violations: u64,
    /// Units that came wrapped in ADTS and were unwrapped.
    pub adts_stripped: u64,
}

/// A unit that spans packets.
#[derive(Debug)]
struct Fragmented {
    /// Its timestamp.
    ts: u32,
    /// The size its header announced.
    size: usize,
    /// The next sequence number expected.
    next_seq: u16,
    /// The bytes so far.
    data: Vec<u8>,
}

/// The side-branch depacketizer of one AAC track.
#[derive(Debug)]
pub struct AacDepacketizer {
    /// The largest unit kept (`limits.max_frame_bytes`).
    max_frame_bytes: usize,
    /// A unit under reassembly.
    fragment: Option<Fragmented>,
    /// Counters.
    stats: AacStats,
}

/// One AU header's size, and whether its index is zero.
fn header(bits: u16) -> (usize, bool) {
    (usize::from(bits >> 3), bits.trailing_zeros() >= 3)
}

/// The unit without an ADTS header, if it carries one whose length says
/// it wraps exactly this unit.
fn strip_adts(unit: &[u8]) -> Option<&[u8]> {
    let (&[b0, b1, _, b3, b4, b5, _], _) = unit.split_first_chunk::<ADTS_HEADER>()?;
    // syncword 0xFFF and layer 00 (ISO/IEC 13818-7 §6.2.1).
    if b0 != 0xff || b1 & 0xf6 != 0xf0 {
        return None;
    }
    let protection_absent = b1 & 0x01 == 1;
    let frame_length = usize::from(b3 & 0x03) << 11 | usize::from(b4) << 3 | usize::from(b5 >> 5);
    if frame_length != unit.len() {
        return None;
    }
    let header = if protection_absent {
        ADTS_HEADER
    } else {
        ADTS_HEADER_CRC
    };
    unit.get(header..)
}

impl AacDepacketizer {
    /// A depacketizer keeping units up to `max_frame_bytes`.
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self {
            max_frame_bytes,
            fragment: None,
            stats: AacStats {
                frames: 0,
                dropped_lost: 0,
                dropped_oversize: 0,
                violations: 0,
                adts_stripped: 0,
            },
        }
    }

    /// The counters.
    pub const fn stats(&self) -> AacStats {
        self.stats
    }

    /// Takes one RTP packet and appends the frames it completes to `out`.
    /// A violation drops the packet (and a unit under reassembly) and is
    /// counted.
    pub fn push(
        &mut self,
        seq: u16,
        ts: u32,
        marker: bool,
        payload: &[u8],
        out: &mut Vec<AacFrame>,
    ) -> Result<(), AacPayloadError> {
        let result = self.parse(seq, ts, marker, payload, out);
        if result.is_err() {
            self.stats.violations = self.stats.violations.saturating_add(1);
            self.drop_fragment();
        }
        result
    }

    /// Drops a unit under reassembly as lost.
    fn drop_fragment(&mut self) {
        if self.fragment.take().is_some() {
            self.stats.dropped_lost = self.stats.dropped_lost.saturating_add(1);
        }
    }

    /// [`Self::push`] without the bookkeeping of violations.
    fn parse(
        &mut self,
        seq: u16,
        ts: u32,
        marker: bool,
        payload: &[u8],
        out: &mut Vec<AacFrame>,
    ) -> Result<(), AacPayloadError> {
        let (length, rest) = payload
            .split_first_chunk::<2>()
            .ok_or(AacPayloadError::Truncated)?;
        let header_bits = u16::from_be_bytes(*length);
        if header_bits == 0 || usize::from(header_bits) % HEADER_BITS != 0 {
            return Err(AacPayloadError::HeaderLength(header_bits));
        }
        let (headers, data) = rest
            .split_at_checked(usize::from(header_bits) / 8)
            .ok_or(AacPayloadError::Truncated)?;
        let sizes: Vec<(usize, bool)> = headers
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| header(u16::from_be_bytes(*pair)))
            .collect();
        if sizes.iter().any(|(_, zero)| !zero) {
            return Err(AacPayloadError::Interleaved);
        }

        // A continuation: same timestamp, next sequence number, one header
        // announcing the same unit (§3.2.3). On a mismatch the unit stays
        // put so `push` counts it lost.
        if let Some(fragment) = self.fragment.as_mut()
            && fragment.ts == ts
            && fragment.next_seq == seq
        {
            let &[(size, _)] = sizes.as_slice() else {
                return Err(AacPayloadError::Sizes);
            };
            if size != fragment.size || fragment.data.len().saturating_add(data.len()) > size {
                return Err(AacPayloadError::Sizes);
            }
            fragment.data.extend_from_slice(data);
            fragment.next_seq = seq.wrapping_add(1);
            if (marker || fragment.data.len() == size)
                && let Some(done) = self.fragment.take()
            {
                self.complete(done.ts, &done.data, out)?;
            }
            return Ok(());
        }
        self.drop_fragment();

        let total: usize = sizes.iter().map(|(size, _)| size).sum();
        if let &[(size, _)] = sizes.as_slice()
            && size > data.len()
        {
            // The first fragment of a unit larger than the packet.
            if size > self.max_frame_bytes {
                self.stats.dropped_oversize = self.stats.dropped_oversize.saturating_add(1);
                return Ok(());
            }
            self.fragment = Some(Fragmented {
                ts,
                size,
                next_seq: seq.wrapping_add(1),
                data: data.to_vec(),
            });
            return Ok(());
        }
        if total != data.len() {
            return Err(AacPayloadError::Sizes);
        }
        let mut rest = data;
        let mut unit_ts = ts;
        for (size, _) in sizes {
            let (unit, after) = rest.split_at_checked(size).ok_or(AacPayloadError::Sizes)?;
            rest = after;
            self.complete(unit_ts, unit, out)?;
            // §3.2.3.2: consecutive units, one frame apart.
            unit_ts = unit_ts.wrapping_add(FRAME_SAMPLES);
        }
        Ok(())
    }

    /// Emits one complete unit, unwrapped from ADTS if it came wrapped.
    fn complete(
        &mut self,
        ts: u32,
        unit: &[u8],
        out: &mut Vec<AacFrame>,
    ) -> Result<(), AacPayloadError> {
        let unit = match strip_adts(unit) {
            Some(inner) => {
                self.stats.adts_stripped = self.stats.adts_stripped.saturating_add(1);
                inner
            }
            None => unit,
        };
        if unit.is_empty() {
            return Err(AacPayloadError::Sizes);
        }
        if unit.len() > self.max_frame_bytes {
            self.stats.dropped_oversize = self.stats.dropped_oversize.saturating_add(1);
            return Ok(());
        }
        self.stats.frames = self.stats.frames.saturating_add(1);
        out.push(AacFrame {
            ts,
            payload: Bytes::copy_from_slice(unit),
        });
        Ok(())
    }
}

/// Builds an RFC 3640 AAC-hbr payload carrying `units` whole, for tests
/// and the fake camera.
#[cfg(any(test, feature = "test-util"))]
pub fn packetize(units: &[&[u8]]) -> Vec<u8> {
    let count = u16::try_from(units.len()).unwrap_or(u16::MAX);
    let mut payload = count.saturating_mul(16).to_be_bytes().to_vec();
    for unit in units {
        let size = u16::try_from(unit.len()).unwrap_or(0);
        payload.extend_from_slice(&(size << 3).to_be_bytes());
    }
    for unit in units {
        payload.extend_from_slice(unit);
    }
    payload
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    /// A fragment payload: one header announcing `size`, then `data`.
    fn fragment(size: u16, data: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x00, 0x10];
        payload.extend_from_slice(&(size << 3).to_be_bytes());
        payload.extend_from_slice(data);
        payload
    }

    fn push(
        d: &mut AacDepacketizer,
        seq: u16,
        ts: u32,
        marker: bool,
        payload: &[u8],
    ) -> (Result<(), AacPayloadError>, Vec<AacFrame>) {
        let mut out = Vec::new();
        let result = d.push(seq, ts, marker, payload, &mut out);
        (result, out)
    }

    #[test]
    fn rfc3640_3_3_6_one_unit_per_packet() {
        let mut d = AacDepacketizer::new(1024);
        let (result, out) = push(&mut d, 1, 5000, true, &packetize(&[b"\x21\x10abc"]));
        result.unwrap();
        assert_eq!(
            out,
            vec![AacFrame {
                ts: 5000,
                payload: Bytes::from_static(b"\x21\x10abc")
            }]
        );
        assert_eq!(d.stats().frames, 1);
    }

    #[test]
    fn rfc3640_3_2_3_2_units_of_one_packet_are_one_frame_apart() {
        let mut d = AacDepacketizer::new(1024);
        let (result, out) = push(
            &mut d,
            1,
            u32::MAX - 100,
            true,
            &packetize(&[b"one", b"two!", b"three"]),
        );
        result.unwrap();
        let got: Vec<(u32, &[u8])> = out.iter().map(|f| (f.ts, &f.payload[..])).collect();
        assert_eq!(
            got,
            vec![
                (u32::MAX - 100, &b"one"[..]),
                (923, &b"two!"[..]),
                (1947, &b"three"[..])
            ]
        );
    }

    #[test]
    fn rfc3640_3_2_3_fragments_reassemble_up_to_the_marker() {
        let mut d = AacDepacketizer::new(1024);
        let (r, out) = push(&mut d, 65_535, 7, false, &fragment(9, b"abcd"));
        r.unwrap();
        assert!(out.is_empty());
        let (r, out) = push(&mut d, 0, 7, false, &fragment(9, b"ef"));
        r.unwrap();
        assert!(out.is_empty());
        let (r, out) = push(&mut d, 1, 7, true, &fragment(9, b"ghi"));
        r.unwrap();
        assert_eq!(out[0].payload, Bytes::from_static(b"abcdefghi"));
        assert_eq!(out[0].ts, 7);
        // Complete by size even when a camera forgets the marker.
        let (r, _) = push(&mut d, 2, 8, false, &fragment(4, b"ab"));
        r.unwrap();
        let (r, out) = push(&mut d, 3, 8, false, &fragment(4, b"cd"));
        r.unwrap();
        assert_eq!(out[0].payload, Bytes::from_static(b"abcd"));
    }

    #[test]
    fn rfc3640_3_2_3_a_lost_fragment_drops_the_unit() {
        let mut d = AacDepacketizer::new(1024);
        push(&mut d, 1, 7, false, &fragment(9, b"abcd")).0.unwrap();
        // Sequence 2 is lost; 3 carries a new unit.
        let (r, out) = push(&mut d, 3, 1031, true, &packetize(&[b"next"]));
        r.unwrap();
        assert_eq!(out[0].payload, Bytes::from_static(b"next"));
        assert_eq!(d.stats().dropped_lost, 1);
        // A new timestamp with the right sequence also ends it.
        push(&mut d, 4, 2055, false, &fragment(9, b"abcd"))
            .0
            .unwrap();
        push(&mut d, 5, 3079, true, &packetize(&[b"x"])).0.unwrap();
        assert_eq!(d.stats().dropped_lost, 2);
    }

    #[test]
    fn rfc3640_3_2_3_a_continuation_must_match_the_announced_unit() {
        let mut d = AacDepacketizer::new(1024);
        push(&mut d, 1, 7, false, &fragment(9, b"abcd")).0.unwrap();
        // Another size.
        let (r, _) = push(&mut d, 2, 7, true, &fragment(8, b"efghi"));
        assert_eq!(r, Err(AacPayloadError::Sizes));
        assert_eq!(d.stats().dropped_lost, 1);
        // More bytes than announced.
        push(&mut d, 3, 8, false, &fragment(5, b"abcd")).0.unwrap();
        assert_eq!(
            push(&mut d, 4, 8, true, &fragment(5, b"ef")).0,
            Err(AacPayloadError::Sizes)
        );
        // Two headers in a continuation.
        push(&mut d, 5, 9, false, &fragment(5, b"abcd")).0.unwrap();
        let mut two = vec![0x00, 0x20, 0x00, 0x08, 0x00, 0x08];
        two.extend_from_slice(b"ef");
        assert_eq!(
            push(&mut d, 6, 9, true, &two).0,
            Err(AacPayloadError::Sizes)
        );
        assert_eq!(d.stats().violations, 3);
    }

    #[test]
    fn rfc3640_3_2_1_malformed_header_sections_are_violations() {
        let mut d = AacDepacketizer::new(1024);
        let cases: [(&[u8], AacPayloadError); 6] = [
            (&[0x00], AacPayloadError::Truncated),
            (&[0x00, 0x00], AacPayloadError::HeaderLength(0)),
            (&[0x00, 0x0d, 0x00], AacPayloadError::HeaderLength(13)),
            (&[0x00, 0x20, 0x00, 0x08], AacPayloadError::Truncated),
            (
                &[0x00, 0x10, 0x00, 0x09, b'a'],
                AacPayloadError::Interleaved,
            ),
            (
                &[0x00, 0x20, 0x00, 0x08, 0x00, 0x08, b'a'],
                AacPayloadError::Sizes,
            ),
        ];
        for (payload, err) in cases {
            assert_eq!(
                push(&mut d, 1, 0, true, payload).0,
                Err(err),
                "{payload:02x?}"
            );
        }
        assert_eq!(d.stats().violations, 6);
        // Units shorter than the data left over are a violation too.
        assert_eq!(
            push(&mut d, 1, 0, true, &[0x00, 0x10, 0x00, 0x08, b'a', b'b']).0,
            Err(AacPayloadError::Sizes)
        );
        // An empty unit carries nothing.
        assert_eq!(
            push(&mut d, 1, 0, true, &[0x00, 0x10, 0x00, 0x00]).0,
            Err(AacPayloadError::Sizes)
        );
    }

    #[test]
    fn oversize_units_are_dropped_and_counted() {
        let mut d = AacDepacketizer::new(4);
        let (r, out) = push(&mut d, 1, 0, true, &packetize(&[b"12345", b"1234"]));
        r.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ts, 1024);
        // A fragment announcing more than the limit is not reassembled.
        let (r, out) = push(&mut d, 2, 2048, false, &fragment(9, b"abc"));
        r.unwrap();
        assert!(out.is_empty());
        assert_eq!(d.stats().dropped_oversize, 2);
        assert_eq!(d.stats().dropped_lost, 0);
        // A unit of exactly the limit is kept, whole or fragmented.
        let (r, out) = push(&mut d, 3, 3072, true, &packetize(&[b"1234"]));
        r.unwrap();
        assert_eq!(out.len(), 1);
        push(&mut d, 4, 4096, false, &fragment(4, b"ab")).0.unwrap();
        let (r, out) = push(&mut d, 5, 4096, true, &fragment(4, b"cd"));
        r.unwrap();
        assert_eq!(out[0].payload, Bytes::from_static(b"abcd"));
    }

    #[test]
    fn iso13818_7_6_2_adts_frame_length_uses_all_13_bits() {
        // 2100 bytes: bit 11 of aac_frame_length is set.
        let raw = vec![0x21_u8; 2093];
        let len = 7 + raw.len();
        let mut adts = vec![
            0xff,
            0xf1,
            0x60,
            0x40 | u8::try_from(len >> 11).unwrap(),
            u8::try_from((len >> 3) & 0xff).unwrap(),
            u8::try_from((len & 0x7) << 5).unwrap() | 0x1f,
            0xfc,
        ];
        adts.extend_from_slice(&raw);
        let mut d = AacDepacketizer::new(4096);
        let (r, out) = push(&mut d, 1, 0, true, &packetize(&[&adts]));
        r.unwrap();
        assert_eq!(out[0].payload.len(), raw.len());
    }

    #[test]
    fn iso13818_7_6_2_adts_wrapped_units_are_stripped() {
        let raw = b"\x21\x10\x05\x00";
        let len = 7 + raw.len();
        // syncword, MPEG-4, layer 0, protection absent; LC, 16 kHz, mono.
        let mut adts = vec![
            0xff,
            0xf1,
            0x60,
            0x40 | u8::try_from(len >> 11).unwrap(),
            u8::try_from((len >> 3) & 0xff).unwrap(),
            u8::try_from((len & 0x7) << 5).unwrap() | 0x1f,
            0xfc,
        ];
        adts.extend_from_slice(raw);
        let mut d = AacDepacketizer::new(1024);
        let (r, out) = push(&mut d, 1, 0, true, &packetize(&[&adts]));
        r.unwrap();
        assert_eq!(&out[0].payload[..], raw);
        assert_eq!(d.stats().adts_stripped, 1);

        // With a CRC (protection_absent 0) the header is 9 bytes.
        let len = 9 + raw.len();
        let mut crc = adts[..7].to_vec();
        crc[1] = 0xf0;
        crc[4] = u8::try_from((len >> 3) & 0xff).unwrap();
        crc[5] = u8::try_from((len & 0x7) << 5).unwrap() | 0x1f;
        crc.extend_from_slice(&[0x12, 0x34]);
        crc.extend_from_slice(raw);
        let (r, out) = push(&mut d, 2, 1024, true, &packetize(&[&crc]));
        r.unwrap();
        assert_eq!(&out[0].payload[..], raw);

        // A length that does not match, a wrong layer, and short units
        // are raw AAC and kept whole.
        let mut wrong_len = adts.clone();
        wrong_len.push(0);
        let mut wrong_layer = adts.clone();
        wrong_layer[1] = 0xf3;
        for unit in [
            &wrong_len[..],
            &wrong_layer[..],
            b"\xff\xf1",
            b"\xfe\xf1\x60\x40\x01\x7f\xfc",
        ] {
            let (r, out) = push(&mut d, 3, 0, true, &packetize(&[unit]));
            r.unwrap();
            assert_eq!(&out[0].payload[..], unit);
        }
        assert_eq!(d.stats().adts_stripped, 2);
    }

    #[test]
    fn errors_say_what_was_wrong() {
        assert_eq!(AacPayloadError::Truncated.to_string(), "payload truncated");
        assert_eq!(
            AacPayloadError::HeaderLength(13).to_string(),
            "AU-headers-length 13 is not a multiple of 16 bits"
        );
        assert_eq!(
            AacPayloadError::Interleaved.to_string(),
            "interleaved access units are not supported"
        );
        assert_eq!(
            AacPayloadError::Sizes.to_string(),
            "AU sizes do not match the payload"
        );
    }
}
