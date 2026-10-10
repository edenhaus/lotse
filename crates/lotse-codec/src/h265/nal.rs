//! NAL units as RTP carries them for H.265: the two-byte header of ITU-T
//! H.265 §7.3.1.2, the payload structures of RFC 7798 §4.4 without
//! decoding order numbers (single NAL unit, aggregation packet,
//! fragmentation unit), and the parameter sets a stream needs before every
//! IRAP picture.
//!
//! Implements RFC 7798 §1.1.4 (NAL unit header), §4.4.1 (single NAL unit
//! packet), §4.4.2 (aggregation packet) and §4.4.3 (fragmentation unit),
//! and ITU-T H.265 Table 7-1 (NAL unit types). The Annex B byte stream is
//! the one of [`crate::h264::nal`]: start codes do not depend on the codec.
//!
//! Decoding order numbers (DONL, DOND) are present only when the camera's
//! SDP sets `sprop-max-don-diff` above 0 (RFC 7798 §4.4, §7.1), which no
//! camera was seen to do; such payloads are not supported, and
//! `lotse-rtsp` declares such a stream unsupported before any of its
//! packets reach this module.

use bytes::{BufMut as _, Bytes, BytesMut};

/// The last type of a video coding layer NAL unit (Table 7-1: 0 to 31).
const LAST_VCL: u8 = 31;
/// Coded slice of a skipped leading picture, non-reference (Table 7-1).
pub const RASL_N: u8 = 8;
/// Coded slice of a skipped leading picture, reference (Table 7-1).
pub const RASL_R: u8 = 9;
/// Coded slice of a broken link access picture with leading pictures
/// (Table 7-1); the first of the IRAP types.
pub const BLA_W_LP: u8 = 16;
/// Coded slice of an IDR picture with decodable leading pictures (Table 7-1).
pub const IDR_W_RADL: u8 = 19;
/// Coded slice of an IDR picture without leading pictures (Table 7-1).
pub const IDR_N_LP: u8 = 20;
/// Coded slice of a clean random access picture (Table 7-1).
pub const CRA_NUT: u8 = 21;
/// Video parameter set (Table 7-1).
pub const VPS_NUT: u8 = 32;
/// Sequence parameter set (Table 7-1).
pub const SPS_NUT: u8 = 33;
/// Picture parameter set (Table 7-1).
pub const PPS_NUT: u8 = 34;
/// Access unit delimiter (Table 7-1).
pub const AUD_NUT: u8 = 35;
/// Filler data (Table 7-1); dropped everywhere.
pub const FD_NUT: u8 = 38;
/// Supplemental enhancement information that precedes the picture (Table 7-1).
pub const PREFIX_SEI_NUT: u8 = 39;
/// Aggregation packet (RFC 7798 §4.4.2).
pub const AP: u8 = 48;
/// Fragmentation unit (RFC 7798 §4.4.3).
pub const FU: u8 = 49;
/// Payload content information (RFC 7798 §4.4.4); not supported.
pub const PACI: u8 = 50;

/// The size of the NAL unit header and of the RTP payload header (§1.1.4).
pub const HEADER_LEN: usize = 2;

/// The `nal_unit_type` of a header's first byte (§7.3.1.2).
pub const fn nal_type(first: u8) -> u8 {
    (first >> 1) & 0x3f
}

/// The `forbidden_zero_bit` of a header's first byte (§7.3.1.2), set on a
/// corrupt unit.
pub const fn forbidden_bit(first: u8) -> bool {
    first & 0x80 != 0
}

/// The `nuh_layer_id` of a header (§7.3.1.2): six bits across both bytes.
pub const fn layer_id(header: [u8; 2]) -> u8 {
    ((header[0] & 0x01) << 5) | (header[1] >> 3)
}

/// The `nuh_temporal_id_plus1` of a header (§7.3.1.2); zero is forbidden
/// (§7.4.2.2).
pub const fn tid_plus1(header: [u8; 2]) -> u8 {
    header[1] & 0x07
}

/// A video coding layer unit: a slice of any picture (types 0 to 31).
pub const fn is_vcl(nal_type: u8) -> bool {
    nal_type <= LAST_VCL
}

/// An intra random access point picture (§3.73, types 16 to 23: BLA, IDR,
/// CRA and the two reserved IRAP types).
pub const fn is_irap(nal_type: u8) -> bool {
    nal_type >= BLA_W_LP && nal_type <= 23
}

/// A skipped leading picture (§3.117), not decodable after a join at the
/// CRA it belongs to.
pub const fn is_rasl(nal_type: u8) -> bool {
    nal_type == RASL_N || nal_type == RASL_R
}

/// A parameter set: VPS, SPS or PPS (§7.4.2.2).
pub const fn is_parameter_set(nal_type: u8) -> bool {
    nal_type == VPS_NUT || nal_type == SPS_NUT || nal_type == PPS_NUT
}

/// The two header bytes of a unit, if it has them.
pub fn header(unit: &[u8]) -> Option<[u8; 2]> {
    unit.first_chunk::<2>().copied()
}

/// The NAL unit type of a whole unit, if it has a header.
pub fn unit_type(unit: &[u8]) -> Option<u8> {
    unit.first().map(|&first| nal_type(first))
}

/// Why an RTP payload is not an RFC 7798 payload lotse can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// No bytes at all.
    #[error("empty payload")]
    Empty,
    /// The forbidden bit of a header is set (§7.3.1.2).
    #[error("forbidden_zero_bit set")]
    ForbiddenBit,
    /// `nuh_temporal_id_plus1` is zero (§7.4.2.2).
    #[error("nuh_temporal_id_plus1 is zero")]
    ZeroTemporalId,
    /// PACI (RFC 7798 §4.4.4) or a type RFC 7798 leaves unspecified
    /// (51 to 63).
    #[error("nal unit type {0} is not supported in an rtp payload")]
    UnsupportedType(u8),
    /// A header, an aggregate or a fragment ends before its declared size.
    #[error("truncated payload")]
    Truncated,
    /// A fragment claims to carry an aggregate, a fragment or PACI
    /// (RFC 7798 §4.4.3: `FuType` MUST NOT be 48 or 49).
    #[error("fragment of nal unit type {0}")]
    BadFragmentType(u8),
}

/// The NAL units of an aggregation packet, each with its header
/// (RFC 7798 §4.4.2, without DONL and DOND).
#[derive(Debug, Clone)]
pub struct Aggregate<'a> {
    /// What is left to read: `[size:16][nal]...`.
    rest: &'a [u8],
}

impl<'a> Iterator for Aggregate<'a> {
    type Item = Result<&'a [u8], PayloadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let Some((size, after)) = self.rest.split_first_chunk::<2>() else {
            self.rest = &[];
            return Some(Err(PayloadError::Truncated));
        };
        let len = usize::from(u16::from_be_bytes(*size));
        let Some((nal, rest)) = after.split_at_checked(len) else {
            self.rest = &[];
            return Some(Err(PayloadError::Truncated));
        };
        if nal.len() < HEADER_LEN {
            self.rest = &[];
            return Some(Err(PayloadError::Truncated));
        }
        self.rest = rest;
        Some(Ok(nal))
    }
}

/// One RTP payload, as RFC 7798 §4.4 structures it without decoding order
/// numbers.
#[derive(Debug, Clone)]
pub enum Payload<'a> {
    /// One NAL unit with its header (§4.4.1).
    Single(&'a [u8]),
    /// Several NAL units of one time (§4.4.2).
    Aggregate(Aggregate<'a>),
    /// A fragment of one NAL unit (§4.4.3).
    Fragment {
        /// The NAL header the fragments reconstruct: F, layer and temporal
        /// id from the payload header, the type from the FU header.
        nal_header: [u8; 2],
        /// The first fragment.
        start: bool,
        /// The last fragment.
        end: bool,
        /// The fragment's bytes, without the three header bytes.
        fragment: &'a [u8],
    },
}

/// Parses an RTP payload.
pub fn parse(payload: &[u8]) -> Result<Payload<'_>, PayloadError> {
    let Some(&first) = payload.first() else {
        return Err(PayloadError::Empty);
    };
    let Some((&header, rest)) = payload.split_first_chunk::<2>() else {
        return Err(PayloadError::Truncated);
    };
    if forbidden_bit(first) {
        return Err(PayloadError::ForbiddenBit);
    }
    if tid_plus1(header) == 0 {
        return Err(PayloadError::ZeroTemporalId);
    }
    match nal_type(first) {
        AP => Ok(Payload::Aggregate(Aggregate { rest })),
        FU => {
            let Some((&fu_header, fragment)) = rest.split_first() else {
                return Err(PayloadError::Truncated);
            };
            let inner = fu_header & 0x3f;
            if inner >= AP {
                return Err(PayloadError::BadFragmentType(inner));
            }
            Ok(Payload::Fragment {
                nal_header: [(header[0] & 0x81) | (inner << 1), header[1]],
                start: fu_header & 0x80 != 0,
                end: fu_header & 0x40 != 0,
                fragment,
            })
        }
        other if other >= PACI => Err(PayloadError::UnsupportedType(other)),
        _ => Ok(Payload::Single(payload)),
    }
}

/// Builds an aggregation packet carrying `nals` (each with its header):
/// the payload header's F bit is set if any unit's is, its layer and
/// temporal id are the lowest of the units' (§4.4.2).
pub fn aggregate(nals: &[&[u8]]) -> Bytes {
    let total: usize = nals
        .iter()
        .map(|nal| nal.len().saturating_add(2))
        .fold(HEADER_LEN, usize::saturating_add);
    let mut out = BytesMut::with_capacity(total);
    let headers = || nals.iter().filter_map(|nal| header(nal));
    let forbidden = headers().any(|h| forbidden_bit(h[0]));
    let layer = headers().map(layer_id).min().unwrap_or(0);
    let tid = headers().map(tid_plus1).min().unwrap_or(1);
    out.put_u8((u8::from(forbidden) << 7) | (AP << 1) | (layer >> 5));
    out.put_u8(((layer & 0x1f) << 3) | tid);
    for nal in nals {
        out.put_u16(u16::try_from(nal.len()).unwrap_or(u16::MAX));
        out.put_slice(nal);
    }
    out.freeze()
}

/// The payload header of a fragmentation unit of a unit with `nal_header`
/// (§4.4.3): its F, layer and temporal id, type 49.
const fn fu_indicator(nal_header: [u8; 2]) -> [u8; 2] {
    [(nal_header[0] & 0x81) | (FU << 1), nal_header[1]]
}

/// One fragmentation unit payload.
fn fu(indicator: [u8; 2], start: bool, end: bool, unit_type: u8, part: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(part.len().saturating_add(3));
    out.put_slice(&indicator);
    out.put_u8((u8::from(start) << 7) | (u8::from(end) << 6) | unit_type);
    out.put_slice(part);
    out.freeze()
}

/// One fragmentation unit of a unit with `nal_header` (§4.4.3): the
/// fragment `part`, with the start and end bits as given.
pub(crate) fn fu_part(nal_header: [u8; 2], start: bool, end: bool, part: &[u8]) -> Bytes {
    fu(
        fu_indicator(nal_header),
        start,
        end,
        nal_type(nal_header[0]),
        part,
    )
}

/// Splits one NAL unit (with its header) into fragmentation units of at
/// most `max_payload` bytes each (§4.4.3). A unit that fits is returned as
/// a single NAL unit payload. `max_payload` below four bytes is raised to
/// four, so every fragment carries at least one byte; a unit without a
/// whole header yields nothing.
pub fn fragment(nal: &[u8], max_payload: usize) -> Vec<Bytes> {
    let Some((&nal_header, body)) = nal.split_first_chunk::<2>() else {
        return Vec::new();
    };
    if nal.len() <= max_payload {
        return vec![Bytes::copy_from_slice(nal)];
    }
    let indicator = fu_indicator(nal_header);
    let unit_type = nal_type(nal_header[0]);
    let chunk = max_payload.saturating_sub(3).max(1);
    let count = body.len().div_ceil(chunk).max(1);
    body.chunks(chunk)
        .enumerate()
        .map(|(i, part)| {
            let end = i.saturating_add(1) == count;
            fu(indicator, i == 0, end, unit_type, part)
        })
        .collect()
}

/// Packetizes an Annex B access unit for RTP (RFC 7798 §4.4.1 and §4.4.3):
/// one payload per NAL unit that fits `max_payload`, fragmentation units
/// for the rest, in order. The last payload ends the access unit (the
/// marker is the caller's to set, §4.1).
pub fn packetize(access_unit: &[u8], max_payload: usize) -> Vec<Bytes> {
    let mut out = Vec::new();
    for unit in crate::h264::annex_b_units(access_unit) {
        out.extend(fragment(unit, max_payload));
    }
    out
}

/// The latest video, sequence and picture parameter sets of a stream, as
/// NAL units with their headers: from the SDP (`sprop-vps`, `sprop-sps`,
/// `sprop-pps`, RFC 7798 §7.1) at first, then from the stream itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParameterSets {
    /// The video parameter set (type 32).
    pub vps: Option<Bytes>,
    /// The sequence parameter set (type 33).
    pub sps: Option<Bytes>,
    /// The picture parameter set (type 34).
    pub pps: Option<Bytes>,
}

impl ParameterSets {
    /// All three sets are known.
    pub const fn complete(&self) -> bool {
        self.vps.is_some() && self.sps.is_some() && self.pps.is_some()
    }

    /// Records `nal` if it is a parameter set; returns whether a set
    /// changed.
    pub fn observe(&mut self, nal: &[u8]) -> bool {
        let slot = match unit_type(nal) {
            Some(VPS_NUT) => &mut self.vps,
            Some(SPS_NUT) => &mut self.sps,
            Some(PPS_NUT) => &mut self.pps,
            _ => return false,
        };
        if slot.as_deref() == Some(nal) {
            return false;
        }
        *slot = Some(Bytes::copy_from_slice(nal));
        true
    }

    /// The three sets in decoding order (§7.4.2.4.4: VPS, SPS, PPS), once
    /// all are known.
    pub fn units(&self) -> Option<[&[u8]; 3]> {
        match (&self.vps, &self.sps, &self.pps) {
            (Some(vps), Some(sps), Some(pps)) => Some([vps, sps, pps]),
            _ => None,
        }
    }

    /// An aggregation packet carrying the three sets, once all are known.
    pub fn aggregate(&self) -> Option<Bytes> {
        self.units().map(|units| aggregate(&units))
    }

    /// Appends the three sets to an Annex B stream, once all are known.
    pub fn annex_b_append(&self, out: &mut Vec<u8>) -> bool {
        let Some(units) = self.units() else {
            return false;
        };
        for unit in units {
            crate::h264::nal::annex_b_append(out, unit);
        }
        true
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

    const VPS: &[u8] = &[0x40, 0x01, 0x0c, 0x01];
    const SPS: &[u8] = &[0x42, 0x01, 0x01, 0x01];
    const PPS: &[u8] = &[0x44, 0x01, 0xc0];
    /// An `IDR_W_RADL` header: type 19, layer 0, tid 1.
    const IDR: [u8; 2] = [0x26, 0x01];

    #[test]
    fn header_fields_follow_h265_7_3_1_2() {
        assert_eq!(nal_type(0x26), IDR_W_RADL);
        assert_eq!(nal_type(0x40), VPS_NUT);
        assert!(!forbidden_bit(0x26) && forbidden_bit(0xa6));
        assert_eq!(layer_id([0x01, 0xf9]), 0x3f);
        assert_eq!(layer_id([0x00, 0x09]), 1);
        assert_eq!(tid_plus1([0x26, 0x03]), 3);
        assert!(is_vcl(0) && is_vcl(CRA_NUT) && is_vcl(31) && !is_vcl(VPS_NUT));
        assert!(!is_irap(15) && is_irap(BLA_W_LP) && is_irap(CRA_NUT) && is_irap(23));
        assert!(!is_irap(24));
        assert!(is_rasl(RASL_N) && is_rasl(RASL_R) && !is_rasl(7) && !is_rasl(10));
        assert_eq!(header(&[1]), None);
        assert_eq!(unit_type(&[]), None);
        assert_eq!(unit_type(VPS), Some(VPS_NUT));
    }

    #[test]
    fn single_aggregate_and_fragment_payloads_parse_rfc7798_4_4() {
        assert!(matches!(parse(&[0x26, 0x01, 0xaa]), Ok(Payload::Single(_))));
        let ap = aggregate(&[VPS, SPS, PPS]);
        assert_eq!(&ap[..2], &[0x60, 0x01], "type 48, layer 0, tid 1");
        lotse_core::let_assert!(Ok(Payload::Aggregate(units)) = parse(&ap));
        let units: Vec<&[u8]> = units.map(Result::unwrap).collect();
        assert_eq!(units, [VPS, SPS, PPS]);
        // A unit of a header alone is a unit.
        let lone = aggregate(&[&IDR]);
        lotse_core::let_assert!(Ok(Payload::Aggregate(mut units)) = parse(&lone));
        assert_eq!(units.next(), Some(Ok(&IDR[..])));
        let fu = [0x62, 0x01, 0x80 | IDR_W_RADL, 0xbb];
        lotse_core::let_assert!(
            Ok(Payload::Fragment {
                nal_header,
                start,
                end,
                fragment
            }) = parse(&fu)
        );
        assert_eq!(
            (nal_header, start, end, fragment),
            (IDR, true, false, &[0xbb][..])
        );
    }

    #[test]
    fn the_aggregate_header_takes_the_lowest_layer_and_tid_rfc7798_4_4_2() {
        // Layer 33 and tid 3, layer 34 and tid 2, a corrupt unit.
        let a = [0x41, 0x0b, 0x00];
        let b = [0xc3, 0x12, 0x00];
        let ap = aggregate(&[&a, &b]);
        assert!(forbidden_bit(ap[0]));
        assert_eq!(nal_type(ap[0]), AP);
        assert_eq!(layer_id([ap[0], ap[1]]), 33);
        assert_eq!(tid_plus1([ap[0], ap[1]]), 2);
        assert_eq!(&aggregate(&[])[..], &[0x60, 0x01]);
    }

    #[test]
    fn broken_payloads_are_errors_not_panics() {
        assert_eq!(parse(&[]).err(), Some(PayloadError::Empty));
        assert_eq!(parse(&[0x26]).err(), Some(PayloadError::Truncated));
        assert_eq!(parse(&[0xa6, 0x01]).err(), Some(PayloadError::ForbiddenBit));
        assert_eq!(
            parse(&[0x26, 0x00]).err(),
            Some(PayloadError::ZeroTemporalId)
        );
        assert_eq!(
            parse(&[PACI << 1, 0x01]).err(),
            Some(PayloadError::UnsupportedType(PACI))
        );
        assert_eq!(
            parse(&[63 << 1, 0x01]).err(),
            Some(PayloadError::UnsupportedType(63))
        );
        assert_eq!(parse(&[0x62, 0x01]).err(), Some(PayloadError::Truncated));
        assert_eq!(
            parse(&[0x62, 0x01, 0x80 | AP]).err(),
            Some(PayloadError::BadFragmentType(AP))
        );
        assert_eq!(
            parse(&[0x62, 0x01, 0x80 | 0x2f]).ok().map(|_| ()),
            Some(()),
            "the last type a fragment may carry"
        );
        // An aggregate whose size runs past the end, one with a unit
        // shorter than a header, and one with half a size field.
        for bytes in [
            &[0x60, 0x01, 0x00, 0x09, 0x40][..],
            &[0x60, 0x01, 0x00, 0x01, 0x40],
            &[0x60, 0x01, 0x00],
        ] {
            lotse_core::let_assert!(Ok(Payload::Aggregate(mut units)) = parse(bytes));
            assert_eq!(units.next(), Some(Err(PayloadError::Truncated)));
            assert_eq!(units.next(), None);
        }
        assert_eq!(fragment(&[0x26], 10), Vec::<Bytes>::new());
    }

    #[test]
    fn fragmentation_round_trips_rfc7798_4_4_3() {
        let nal: Vec<u8> = IDR.into_iter().chain(0..=255).collect();
        let parts = fragment(&nal, 100);
        assert_eq!(parts.len(), 3, "97 bytes of body per fragment");
        assert!(parts.iter().all(|p| p.len() <= 100));
        let mut rebuilt = vec![];
        for (i, part) in parts.iter().enumerate() {
            lotse_core::let_assert!(
                Ok(Payload::Fragment {
                    nal_header,
                    start,
                    end,
                    fragment
                }) = parse(part)
            );
            assert_eq!(nal_header, IDR);
            assert_eq!((start, end), (i == 0, i == 2));
            if start {
                rebuilt.extend_from_slice(&nal_header);
            }
            rebuilt.extend_from_slice(fragment);
        }
        assert_eq!(rebuilt, nal);
        assert_eq!(fragment(&nal, 1000), [Bytes::copy_from_slice(&nal)]);
        // One fragment with the header's F, layer and temporal id, its
        // type and the start and end bits as asked.
        let part = fu_part([0x80 | (IDR_W_RADL << 1) | 1, 0x0a], false, true, &[7, 8]);
        let expected = [0x80 | (FU << 1) | 1, 0x0a, 0x40 | IDR_W_RADL, 7, 8];
        assert_eq!(&part[..], expected);
        let part = fu_part(IDR, true, false, &[]);
        let expected = [FU << 1, IDR[1], 0x80 | IDR_W_RADL];
        assert_eq!(&part[..], expected);
        // The minimum payload size still moves one byte per fragment.
        assert_eq!(fragment(&nal, 1).len(), 256);
    }

    #[test]
    fn annex_b_access_units_packetize_rfc7798_4_4_1() {
        let mut stream = Vec::new();
        let idr: Vec<u8> = IDR.into_iter().chain([0x5a; 300]).collect();
        for unit in [VPS, SPS, PPS, &idr] {
            crate::h264::nal::annex_b_append(&mut stream, unit);
        }
        let packets = packetize(&stream, 100);
        assert_eq!(packets.len(), 3 + 4, "three singles and four fragments");
        assert!(packets.iter().all(|p| p.len() <= 100));
        assert_eq!(packets[0].as_ref(), VPS);
        assert_eq!(nal_type(packets[3][0]), FU);
        assert!(packetize(&[], 100).is_empty());
    }

    #[test]
    fn parameter_sets_are_tracked_and_emitted_before_irap_pictures() {
        let mut sets = ParameterSets::default();
        assert!(!sets.complete());
        assert!(sets.aggregate().is_none());
        let mut out = vec![];
        assert!(!sets.annex_b_append(&mut out));
        assert!(sets.observe(VPS));
        assert!(sets.observe(SPS));
        assert!(!sets.complete(), "no PPS yet");
        assert!(!sets.observe(SPS), "unchanged");
        assert!(!sets.observe(&IDR), "not a parameter set");
        assert!(!sets.observe(&[]));
        assert!(sets.observe(PPS));
        assert!(sets.complete());
        assert_eq!(sets.aggregate().unwrap(), aggregate(&[VPS, SPS, PPS]));
        assert!(sets.annex_b_append(&mut out));
        let mut expected = vec![];
        for unit in [VPS, SPS, PPS] {
            crate::h264::nal::annex_b_append(&mut expected, unit);
        }
        assert_eq!(out, expected);
        assert!(
            sets.observe(&[0x42, 0x01, 0x02]),
            "a new SPS replaces the old one"
        );
        let only_sps = ParameterSets {
            sps: sets.sps.clone(),
            ..ParameterSets::default()
        };
        assert!(!only_sps.complete() && only_sps.units().is_none());
        let no_vps = ParameterSets {
            vps: None,
            ..sets.clone()
        };
        assert!(!no_vps.complete());
    }
}
