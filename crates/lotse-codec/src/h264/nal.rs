//! NAL units as RTP carries them: the header byte of ISO/IEC 14496-10
//! §7.3.1, the payload structures of RFC 6184 §5.2 for packetization mode
//! 1 (single NAL unit, STAP-A, FU-A), the Annex B byte stream, and the
//! parameter sets a stream needs before every IDR.
//!
//! Implements RFC 6184 §5.3 (NAL unit header in RTP), §5.6 (single NAL
//! unit packet), §5.7.1 (STAP-A) and §5.8 (FU-A), ISO/IEC 14496-10
//! Table 7-1 (NAL unit types) and Annex B (byte stream start codes), and
//! the length-prefixed samples of ISO/IEC 14496-15 §5.3.2 (AVC) and
//! §8.3.2 (HEVC), which MP4 carries, into that byte stream.

use bytes::{BufMut as _, Bytes, BytesMut};

/// Coded slice of a non-IDR picture (Table 7-1).
pub const NAL_SLICE: u8 = 1;
/// Coded slice of an IDR picture (Table 7-1).
pub const NAL_IDR: u8 = 5;
/// Supplemental enhancement information (Table 7-1).
pub const NAL_SEI: u8 = 6;
/// Sequence parameter set (Table 7-1).
pub const NAL_SPS: u8 = 7;
/// Picture parameter set (Table 7-1).
pub const NAL_PPS: u8 = 8;
/// Access unit delimiter (Table 7-1).
pub const NAL_AUD: u8 = 9;
/// Filler data (Table 7-1); dropped everywhere.
pub const NAL_FILLER: u8 = 12;

/// A parameter set: SPS or PPS (Table 7-1).
pub const fn is_parameter_set(nal_type: u8) -> bool {
    nal_type == NAL_SPS || nal_type == NAL_PPS
}
/// Single-time aggregation packet A (RFC 6184 §5.7.1).
pub const STAP_A: u8 = 24;
/// Single-time aggregation packet B (RFC 6184 §5.7.1); not in mode 1.
pub const STAP_B: u8 = 25;
/// Multi-time aggregation packet, 16-bit offsets (RFC 6184 §5.7.2); not in mode 1.
pub const MTAP16: u8 = 26;
/// Multi-time aggregation packet, 24-bit offsets (RFC 6184 §5.7.2); not in mode 1.
pub const MTAP24: u8 = 27;
/// Fragmentation unit A (RFC 6184 §5.8).
pub const FU_A: u8 = 28;
/// Fragmentation unit B (RFC 6184 §5.8); not in mode 1.
pub const FU_B: u8 = 29;

/// The Annex B start code before every NAL unit of a frame.
pub const START_CODE: [u8; 4] = [0, 0, 0, 1];

/// The `nal_unit_type` of a header byte (§7.3.1).
pub const fn nal_type(header: u8) -> u8 {
    header & 0x1f
}

/// The `nal_ref_idc` of a header byte (§7.3.1).
pub const fn nri(header: u8) -> u8 {
    (header >> 5) & 0x03
}

/// The `forbidden_zero_bit` of a header byte (§7.3.1), set on a corrupt unit.
pub const fn forbidden_bit(header: u8) -> bool {
    header & 0x80 != 0
}

/// A NAL unit type that starts a video coding layer unit: a slice of any
/// picture (types 1 to 5).
pub const fn is_vcl(nal_type: u8) -> bool {
    nal_type >= NAL_SLICE && nal_type <= NAL_IDR
}

/// Why an RTP payload is not a mode 1 H.264 payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// No bytes at all.
    #[error("empty payload")]
    Empty,
    /// The forbidden bit of a header is set (§7.3.1).
    #[error("forbidden_zero_bit set")]
    ForbiddenBit,
    /// A payload type packetization mode 1 does not allow (RFC 6184 §5.4)
    /// or a reserved NAL unit type.
    #[error("nal unit type {0} is not allowed in packetization mode 1")]
    UnsupportedType(u8),
    /// An aggregate or fragment ends before its declared size.
    #[error("truncated payload")]
    Truncated,
    /// A fragment claims to carry an aggregate or another fragment.
    #[error("fragment of nal unit type {0}")]
    BadFragmentType(u8),
}

/// The NAL units of a STAP-A, each with its header (RFC 6184 §5.7.1).
#[derive(Debug, Clone)]
pub struct StapA<'a> {
    /// What is left to read: `[size:16][nal]...`.
    rest: &'a [u8],
}

impl<'a> Iterator for StapA<'a> {
    type Item = Result<&'a [u8], PayloadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let Some((size, after)) = self.rest.split_at_checked(2) else {
            self.rest = &[];
            return Some(Err(PayloadError::Truncated));
        };
        let len = usize::from(u16::from_be_bytes([
            size.first().copied().unwrap_or(0),
            size.get(1).copied().unwrap_or(0),
        ]));
        let Some((nal, rest)) = after.split_at_checked(len) else {
            self.rest = &[];
            return Some(Err(PayloadError::Truncated));
        };
        if nal.is_empty() {
            self.rest = &[];
            return Some(Err(PayloadError::Truncated));
        }
        self.rest = rest;
        Some(Ok(nal))
    }
}

/// One RTP payload, as RFC 6184 §5.2 structures it in packetization mode 1.
#[derive(Debug, Clone)]
pub enum Payload<'a> {
    /// One NAL unit with its header (§5.6).
    Single(&'a [u8]),
    /// Several NAL units of one time (§5.7.1).
    StapA(StapA<'a>),
    /// A fragment of one NAL unit (§5.8).
    FuA {
        /// The NAL header the fragments reconstruct (F and NRI from the FU
        /// indicator, the type from the FU header).
        nal_header: u8,
        /// The first fragment.
        start: bool,
        /// The last fragment.
        end: bool,
        /// The fragment's bytes, without the two FU bytes.
        fragment: &'a [u8],
    },
}

/// Parses an RTP payload.
pub fn parse(payload: &[u8]) -> Result<Payload<'_>, PayloadError> {
    let Some((&indicator, rest)) = payload.split_first() else {
        return Err(PayloadError::Empty);
    };
    if forbidden_bit(indicator) {
        return Err(PayloadError::ForbiddenBit);
    }
    match nal_type(indicator) {
        1..=23 => Ok(Payload::Single(payload)),
        STAP_A => Ok(Payload::StapA(StapA { rest })),
        FU_A => {
            let Some((&fu_header, fragment)) = rest.split_first() else {
                return Err(PayloadError::Truncated);
            };
            let inner = nal_type(fu_header);
            if !(1..=23).contains(&inner) {
                return Err(PayloadError::BadFragmentType(inner));
            }
            Ok(Payload::FuA {
                nal_header: (indicator & 0xe0) | inner,
                start: fu_header & 0x80 != 0,
                end: fu_header & 0x40 != 0,
                fragment,
            })
        }
        other => Err(PayloadError::UnsupportedType(other)),
    }
}

/// Builds a STAP-A carrying `nals` (each with its header): the indicator
/// takes the highest NRI of the units (§5.7.1).
pub fn stap_a(nals: &[&[u8]]) -> Bytes {
    let total: usize = nals
        .iter()
        .map(|nal| nal.len().saturating_add(2))
        .fold(1, usize::saturating_add);
    let mut out = BytesMut::with_capacity(total);
    let nri = nals
        .iter()
        .filter_map(|nal| nal.first().map(|&h| nri(h)))
        .max()
        .unwrap_or(0);
    out.put_u8((nri << 5) | STAP_A);
    for nal in nals {
        out.put_u16(u16::try_from(nal.len()).unwrap_or(u16::MAX));
        out.put_slice(nal);
    }
    out.freeze()
}

/// Splits one NAL unit (with its header) into FU-A payloads of at most
/// `max_payload` bytes each (§5.8). A unit that fits is returned as a
/// single NAL unit payload. `max_payload` below three bytes is raised to
/// three, so every fragment carries at least one byte.
pub fn fragment(nal: &[u8], max_payload: usize) -> Vec<Bytes> {
    let Some((&header, body)) = nal.split_first() else {
        return Vec::new();
    };
    if nal.len() <= max_payload {
        return vec![Bytes::copy_from_slice(nal)];
    }
    let chunk = max_payload.saturating_sub(2).max(1);
    let count = body.len().div_ceil(chunk).max(1);
    body.chunks(chunk)
        .enumerate()
        .map(|(i, part)| fu_part(header, i == 0, i.saturating_add(1) == count, part))
        .collect()
}

/// One FU-A payload of a unit with `nal_header` (§5.8): the FU indicator
/// with the header's F and NRI, the FU header with the start and end bits
/// as given and the unit's type, then the fragment `part`.
pub(crate) fn fu_part(nal_header: u8, start: bool, end: bool, part: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(part.len().saturating_add(2));
    out.put_u8((nal_header & 0xe0) | FU_A);
    out.put_u8((u8::from(start) << 7) | (u8::from(end) << 6) | nal_type(nal_header));
    out.put_slice(part);
    out.freeze()
}

/// Appends `nal` to an Annex B byte stream (4-byte start code).
pub fn annex_b_append(out: &mut Vec<u8>, nal: &[u8]) {
    out.extend_from_slice(&START_CODE);
    out.extend_from_slice(nal);
}

/// Why a length-prefixed sample cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LengthPrefixError {
    /// The configuration's NAL unit length size is not 1 to 4 bytes
    /// (ISO/IEC 14496-15 §5.3.3.2, `lengthSizeMinusOne`).
    #[error("a NAL unit length of {0} bytes")]
    LengthSize(u8),
    /// A length field or the unit it counts runs past the sample's end.
    #[error("a NAL unit runs past the end of its sample")]
    Truncated,
}

/// Appends the NAL units of one MP4 sample to `out` as an Annex B byte
/// stream (4-byte start codes). The sample is a sequence of NAL units,
/// each after its length in `length_size` big-endian bytes (ISO/IEC
/// 14496-15 §5.3.2 for AVC, §8.3.2 for HEVC; the `avcC` or `hvcC` gives
/// the size, §5.3.3, §8.3.3). Empty units are skipped, as
/// [`annex_b_units`] skips them. The NAL unit header is not read, so it
/// serves H.265 as well.
///
/// # Errors
///
/// A length size outside 1 to 4 bytes, or a unit running past the end of
/// the sample; `out` is then left as it was.
pub fn length_prefixed_to_annex_b(
    sample: &[u8],
    length_size: u8,
    out: &mut Vec<u8>,
) -> Result<(), LengthPrefixError> {
    let field_len = match length_size {
        1..=4 => usize::from(length_size),
        other => return Err(LengthPrefixError::LengthSize(other)),
    };
    let start = out.len();
    let mut rest = sample;
    while !rest.is_empty() {
        let Some((field, after)) = rest.split_at_checked(field_len) else {
            out.truncate(start);
            return Err(LengthPrefixError::Truncated);
        };
        let length = field.iter().fold(0_usize, |length, &byte| {
            length.saturating_mul(256).saturating_add(usize::from(byte))
        });
        let Some((unit, next)) = after.split_at_checked(length) else {
            out.truncate(start);
            return Err(LengthPrefixError::Truncated);
        };
        if !unit.is_empty() {
            annex_b_append(out, unit);
        }
        rest = next;
    }
    Ok(())
}

/// The NAL units of an Annex B byte stream (three- or four-byte start
/// codes), without their start codes; empty units are skipped.
pub fn annex_b_units(stream: &[u8]) -> Vec<&[u8]> {
    let mut units = Vec::new();
    let mut start: Option<usize> = None;
    let mut i = 0;
    while let Some(window) = stream.get(i..) {
        let Some(code_len) = start_code_at(window) else {
            if window.is_empty() {
                break;
            }
            i = i.saturating_add(1);
            continue;
        };
        if let Some(from) = start
            && let Some(unit) = stream.get(from..i)
            && !unit.is_empty()
        {
            units.push(unit);
        }
        i = i.saturating_add(code_len);
        start = Some(i);
    }
    if let Some(from) = start
        && let Some(unit) = stream.get(from..)
        && !unit.is_empty()
    {
        units.push(unit);
    }
    units
}

/// The length of the start code at the head of `bytes`, if any.
fn start_code_at(bytes: &[u8]) -> Option<usize> {
    match bytes {
        [0, 0, 0, 1, ..] => Some(4),
        [0, 0, 1, ..] => Some(3),
        _ => None,
    }
}

/// Packetizes an Annex B access unit for RTP (RFC 6184 §5.6 and §5.8):
/// one payload per NAL unit that fits `max_payload`, FU-A fragments for
/// the rest, in order. The last payload ends the access unit (the marker
/// is the caller's to set).
pub fn packetize(access_unit: &[u8], max_payload: usize) -> Vec<Bytes> {
    let mut out = Vec::new();
    for unit in annex_b_units(access_unit) {
        out.extend(fragment(unit, max_payload));
    }
    out
}

/// The latest sequence and picture parameter sets of a stream, as NAL
/// units with their headers: from the SDP (`sprop-parameter-sets`) at
/// first, then from the stream itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParameterSets {
    /// The sequence parameter set (type 7).
    pub sps: Option<Bytes>,
    /// The picture parameter set (type 8).
    pub pps: Option<Bytes>,
}

impl ParameterSets {
    /// Both sets are known.
    pub const fn complete(&self) -> bool {
        self.sps.is_some() && self.pps.is_some()
    }

    /// Records `nal` if it is a parameter set; returns whether a set
    /// changed.
    pub fn observe(&mut self, nal: &[u8]) -> bool {
        let Some(&header) = nal.first() else {
            return false;
        };
        let slot = match nal_type(header) {
            NAL_SPS => &mut self.sps,
            NAL_PPS => &mut self.pps,
            _ => return false,
        };
        if slot.as_deref() == Some(nal) {
            return false;
        }
        *slot = Some(Bytes::copy_from_slice(nal));
        true
    }

    /// A STAP-A carrying both sets, once both are known.
    pub fn stap_a(&self) -> Option<Bytes> {
        match (&self.sps, &self.pps) {
            (Some(sps), Some(pps)) => Some(stap_a(&[sps, pps])),
            _ => None,
        }
    }

    /// Appends both sets to an Annex B stream, once both are known.
    pub fn annex_b_append(&self, out: &mut Vec<u8>) -> bool {
        match (&self.sps, &self.pps) {
            (Some(sps), Some(pps)) => {
                annex_b_append(out, sps);
                annex_b_append(out, pps);
                true
            }
            _ => false,
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

    const SPS: &[u8] = &[0x67, 0x42, 0xc0, 0x1e, 0xda];
    const PPS: &[u8] = &[0x68, 0xce, 0x3c, 0x80];

    #[test]
    fn iso14496_15_5_3_2_length_prefixed_units_become_annex_b() {
        for length_size in 1..=4_u8 {
            let mut sample = Vec::new();
            for unit in [SPS, &[][..], PPS] {
                let length = unit.len().to_be_bytes();
                sample.extend_from_slice(&length[length.len() - usize::from(length_size)..]);
                sample.extend_from_slice(unit);
            }
            let mut out = vec![0xaa];
            length_prefixed_to_annex_b(&sample, length_size, &mut out).unwrap();
            let mut expected = vec![0xaa];
            annex_b_append(&mut expected, SPS);
            annex_b_append(&mut expected, PPS);
            assert_eq!(out, expected, "length size {length_size}");
            assert_eq!(annex_b_units(&out[1..]), [SPS, PPS]);
        }
        let mut out = Vec::new();
        length_prefixed_to_annex_b(&[], 4, &mut out).unwrap();
        assert!(out.is_empty());
        // A unit longer than one length byte counts: 0x012c = 300 bytes.
        let long = [0x65; 300];
        for field in [&[0x01, 0x2c][..], &[0, 0, 0x01, 0x2c]] {
            let mut sample = field.to_vec();
            sample.extend_from_slice(&long);
            let size = u8::try_from(field.len()).unwrap();
            length_prefixed_to_annex_b(&sample, size, &mut out).unwrap();
            assert_eq!(annex_b_units(&out), [&long[..]]);
            out.clear();
        }
    }

    #[test]
    fn iso14496_15_5_3_2_a_length_past_the_sample_leaves_the_output_as_it_was() {
        let mut out = vec![0xaa];
        // A whole first unit, then a length running past the end.
        let sample = [0, 0, 0, 1, 0x09, 0, 0, 0, 3, 0x65, 0x88];
        assert_eq!(
            length_prefixed_to_annex_b(&sample, 4, &mut out),
            Err(LengthPrefixError::Truncated)
        );
        assert_eq!(out, [0xaa]);
        // A length field cut short.
        assert_eq!(
            length_prefixed_to_annex_b(&[0, 0, 0, 1, 0x09, 0, 0], 4, &mut out),
            Err(LengthPrefixError::Truncated)
        );
        assert_eq!(out, [0xaa]);
        // A unit exactly as long as its length is not cut.
        length_prefixed_to_annex_b(&[0, 2, 0x65, 0x88], 2, &mut out).unwrap();
        assert_eq!(out, [0xaa, 0, 0, 0, 1, 0x65, 0x88]);
    }

    #[test]
    fn iso14496_15_5_3_3_2_a_length_size_beyond_one_to_four_bytes_is_refused() {
        let mut out = Vec::new();
        for size in [0, 5, 255] {
            assert_eq!(
                length_prefixed_to_annex_b(&[0, 1, 0x65], size, &mut out),
                Err(LengthPrefixError::LengthSize(size))
            );
        }
        assert!(out.is_empty());
        assert_eq!(
            LengthPrefixError::LengthSize(5).to_string(),
            "a NAL unit length of 5 bytes"
        );
        assert_eq!(
            LengthPrefixError::Truncated.to_string(),
            "a NAL unit runs past the end of its sample"
        );
    }

    #[test]
    fn header_bits_follow_14496_10_7_3_1() {
        assert_eq!(nal_type(0x65), NAL_IDR);
        assert_eq!(nri(0x65), 3);
        assert!(!forbidden_bit(0x65));
        assert!(forbidden_bit(0xe5));
        assert!(is_vcl(NAL_SLICE) && is_vcl(NAL_IDR) && !is_vcl(NAL_SPS));
    }

    #[test]
    fn single_stap_a_and_fu_a_payloads_parse_rfc6184_5_2() {
        assert!(matches!(parse(&[0x65, 1, 2]), Ok(Payload::Single(_))));
        let stap = stap_a(&[SPS, PPS]);
        assert_eq!(stap[0], 0x78, "NRI 3 from the SPS, type 24");
        lotse_core::let_assert!(Ok(Payload::StapA(units)) = parse(&stap));
        let units: Vec<&[u8]> = units.map(Result::unwrap).collect();
        assert_eq!(units, [SPS, PPS]);
        let fu = [0x7c, 0x85, 0xaa];
        lotse_core::let_assert!(
            Ok(Payload::FuA {
                nal_header,
                start,
                end,
                fragment
            }) = parse(&fu)
        );
        assert_eq!(
            (nal_header, start, end, fragment),
            (0x65, true, false, &[0xaa][..])
        );
        assert!(matches!(parse(&[]), Err(PayloadError::Empty)));
    }

    #[test]
    fn broken_payloads_are_errors_not_panics() {
        assert!(matches!(parse(&[]), Err(PayloadError::Empty)));
        assert!(matches!(parse(&[0xe5]), Err(PayloadError::ForbiddenBit)));
        assert!(matches!(
            parse(&[STAP_B]),
            Err(PayloadError::UnsupportedType(STAP_B))
        ));
        assert!(matches!(
            parse(&[0x00]),
            Err(PayloadError::UnsupportedType(0))
        ));
        assert!(matches!(parse(&[0x7c]), Err(PayloadError::Truncated)));
        assert!(matches!(
            parse(&[0x7c, 0x80 | STAP_A]),
            Err(PayloadError::BadFragmentType(STAP_A))
        ));
        // A STAP-A whose size runs past the end, and one with a zero size.
        lotse_core::let_assert!(Ok(Payload::StapA(mut units)) = parse(&[0x78, 0x00, 0x09, 0x67]));
        assert_eq!(units.next(), Some(Err(PayloadError::Truncated)));
        assert_eq!(units.next(), None);
        lotse_core::let_assert!(Ok(Payload::StapA(mut units)) = parse(&[0x78, 0x00, 0x00]));
        assert_eq!(units.next(), Some(Err(PayloadError::Truncated)));
        lotse_core::let_assert!(Ok(Payload::StapA(mut units)) = parse(&[0x78, 0x00]));
        assert_eq!(units.next(), Some(Err(PayloadError::Truncated)));
        assert_eq!(fragment(&[], 10), Vec::<Bytes>::new());
    }

    #[test]
    fn fragmentation_round_trips_rfc6184_5_8() {
        let nal: Vec<u8> = std::iter::once(0x65).chain(0..=255).collect();
        let parts = fragment(&nal, 100);
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.len() <= 100));
        let mut rebuilt = vec![];
        for (i, part) in parts.iter().enumerate() {
            lotse_core::let_assert!(
                Ok(Payload::FuA {
                    nal_header,
                    start,
                    end,
                    fragment
                }) = parse(part)
            );
            assert_eq!(nal_header, 0x65);
            assert_eq!(start, i == 0);
            assert_eq!(end, i == 2);
            if start {
                rebuilt.push(nal_header);
            }
            rebuilt.extend_from_slice(fragment);
        }
        assert_eq!(rebuilt, nal);
        assert_eq!(fragment(&nal, 1000), [Bytes::copy_from_slice(&nal)]);
        // One fragment with the header's F and NRI, its type and the start
        // and end bits as asked.
        let part = fu_part(0xe5, false, true, &[7, 8]);
        assert_eq!(&part[..], [0xe0 | FU_A, 0x40 | NAL_IDR, 7, 8]);
        let part = fu_part(0x65, true, false, &[]);
        assert_eq!(&part[..], [0x60 | FU_A, 0x80 | NAL_IDR]);
        // The minimum payload size still moves one byte per fragment.
        assert_eq!(fragment(&nal, 1).len(), 256);
    }

    #[test]
    fn annex_b_splits_and_packetizes_rfc6184_5_6() {
        let mut stream = vec![0, 0, 1];
        stream.extend_from_slice(SPS);
        stream.extend_from_slice(&START_CODE);
        stream.extend_from_slice(PPS);
        stream.extend_from_slice(&START_CODE);
        let idr: Vec<u8> = std::iter::once(0x65)
            .chain((0..300).map(|i| u8::try_from(i % 200).unwrap() + 1))
            .collect();
        stream.extend_from_slice(&idr);
        let units = annex_b_units(&stream);
        assert_eq!(units, [SPS, PPS, idr.as_slice()]);
        assert!(annex_b_units(&[]).is_empty());
        assert!(annex_b_units(&[0, 0, 0, 1]).is_empty());
        assert_eq!(
            annex_b_units(&[0x65, 1]),
            Vec::<&[u8]>::new(),
            "no start code, no unit"
        );
        let packets = packetize(&stream, 100);
        assert_eq!(packets.len(), 2 + 4, "two singles and four fragments");
        assert!(packets.iter().all(|p| p.len() <= 100));
        assert_eq!(packets[0].as_ref(), SPS);
        assert_eq!(nal_type(packets[2][0]), FU_A);
        assert!(packetize(&[], 100).is_empty());
    }

    #[test]
    fn parameter_sets_are_tracked_and_emitted_before_idrs() {
        let mut sets = ParameterSets::default();
        assert!(!sets.complete());
        assert!(sets.stap_a().is_none());
        let mut out = vec![];
        assert!(!sets.annex_b_append(&mut out));
        assert!(sets.observe(SPS));
        assert!(!sets.observe(SPS), "unchanged");
        assert!(!sets.observe(&[0x65, 0]), "not a parameter set");
        assert!(!sets.observe(&[]));
        assert!(sets.observe(PPS));
        assert!(sets.complete());
        assert_eq!(sets.stap_a().unwrap(), stap_a(&[SPS, PPS]));
        assert!(sets.annex_b_append(&mut out));
        let mut expected = vec![];
        annex_b_append(&mut expected, SPS);
        annex_b_append(&mut expected, PPS);
        assert_eq!(out, expected);
        assert!(sets.observe(&[0x67, 1]), "a new SPS replaces the old one");
    }
}
