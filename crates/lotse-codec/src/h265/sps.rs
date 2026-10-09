//! What the side branch and the negotiation read out of H.265 bitstream
//! syntax: the profile, tier, level and picture size of a sequence
//! parameter set, and recovery-point SEI messages. No maintained pure-Rust
//! H.265 parser covers this, so this is a small one of our own, fuzzed by
//! the `h265_ptl` target.
//!
//! Implements ITU-T H.265 §7.3.1.1 and §7.4.2 (emulation prevention),
//! §7.3.2.2.1 (SPS up to the conformance window), §7.3.3
//! (`profile_tier_level`), §7.4.3.2.1 (cropping by `SubWidthC` and
//! `SubHeightC`, Table 6-1), §7.3.5 (`sei_message`), §9.2 (`ue(v)`) and
//! D.2.8 / D.3.8 (recovery point SEI); RFC 7798 §7.1 names the
//! `profile_tier_level` fields `profile-space`, `profile-id`, `tier-flag`
//! and `level-id`.

use super::nal::{self, HEADER_LEN};

/// The most sub-layers a `profile_tier_level` describes (§7.4.3.2.1:
/// `sps_max_sub_layers_minus1` is at most 6).
const MAX_SUB_LAYERS: u32 = 7;

/// The `payloadType` of a recovery point SEI message (D.2.1).
const RECOVERY_POINT: usize = 6;

/// What a sequence parameter set says about the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpsInfo {
    /// `general_profile_space` (RFC 7798 `profile-space`); 0 in every
    /// profile H.265 defines.
    pub profile_space: u8,
    /// `general_tier_flag` (RFC 7798 `tier-flag`): the High tier.
    pub high_tier: bool,
    /// `general_profile_idc` (RFC 7798 `profile-id`): 1 Main, 2 Main 10.
    pub profile_idc: u8,
    /// `general_profile_compatibility_flag[j]`, flag 0 in the most
    /// significant bit: bit `31 - j` set means the stream conforms to
    /// profile `j` too (§7.4.4).
    pub compatibility: u32,
    /// `general_level_idc` (RFC 7798 `level-id`): 30 times the level.
    pub level_idc: u8,
    /// Picture width in luma samples, the conformance window applied.
    pub width: u32,
    /// Picture height in luma samples, the conformance window applied.
    pub height: u32,
}

impl SpsInfo {
    /// Whether the stream conforms to profile `profile_idc`: it is the
    /// stream's own, or its compatibility flag is set (§7.4.4).
    pub const fn conforms_to(&self, profile_idc: u8) -> bool {
        if profile_idc == self.profile_idc {
            return true;
        }
        match 0x8000_0000_u32.checked_shr(profile_idc as u32) {
            Some(flag) => self.compatibility & flag != 0,
            None => false,
        }
    }
}

/// Why an SPS could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SpsError {
    /// The unit is not a sequence parameter set.
    #[error("not a sequence parameter set")]
    NotSps,
    /// The syntax ends early (§7.3.2.2.1).
    #[error("sps ends early")]
    Truncated,
    /// A value outside its range (§7.4.3.2.1): an Exp-Golomb code longer
    /// than 32 bits, `sps_max_sub_layers_minus1` above 6, or
    /// `chroma_format_idc` above 3.
    #[error("sps value out of range")]
    OutOfRange,
    /// The conformance window takes the whole picture: §7.4.3.2.1 keeps it
    /// inside.
    #[error("cropping leaves no picture")]
    EmptyPicture,
}

/// Removes the emulation prevention bytes of a NAL unit's payload
/// (§7.4.2: a `0x03` after two zero bytes is dropped).
fn unescape(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    let mut zeros = 0_u8;
    for &byte in payload {
        if zeros >= 2 && byte == 0x03 {
            zeros = 0;
            continue;
        }
        zeros = if byte == 0 {
            zeros.saturating_add(1)
        } else {
            0
        };
        out.push(byte);
    }
    out
}

/// Reads bits most significant first from an RBSP (§7.2).
struct Bits<'a> {
    /// The bytes.
    data: &'a [u8],
    /// The next bit's index.
    pos: usize,
}

impl<'a> Bits<'a> {
    /// A reader at the first bit of `data`.
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// One bit.
    fn bit(&mut self) -> Result<bool, SpsError> {
        let byte = self.data.get(self.pos / 8).ok_or(SpsError::Truncated)?;
        let set = byte & (0x80 >> (self.pos % 8)) != 0;
        self.pos = self.pos.saturating_add(1);
        Ok(set)
    }

    /// `u(n)` for `n` up to 32 (§7.2).
    fn bits(&mut self, count: u32) -> Result<u32, SpsError> {
        let mut value = 0_u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.bit()?);
        }
        Ok(value)
    }

    /// Skips `count` bits.
    fn skip(&mut self, count: usize) -> Result<(), SpsError> {
        let end = self.pos.saturating_add(count);
        if end > self.data.len().saturating_mul(8) {
            return Err(SpsError::Truncated);
        }
        self.pos = end;
        Ok(())
    }

    /// `ue(v)` (§9.2): up to 31 leading zeros, so the value fits a `u32`.
    fn ue(&mut self) -> Result<u32, SpsError> {
        let mut zeros = 0_u32;
        while !self.bit()? {
            zeros = zeros.saturating_add(1);
            if zeros > 31 {
                return Err(SpsError::OutOfRange);
            }
        }
        let suffix = self.bits(zeros)?;
        // 2^zeros - 1 + suffix, at most 2^32 - 1 for 31 zeros.
        let value = (1_u64 << zeros)
            .saturating_sub(1)
            .saturating_add(u64::from(suffix));
        Ok(u32::try_from(value).unwrap_or(u32::MAX))
    }
}

/// The general part of a `profile_tier_level` (§7.3.3) with its sub-layer
/// parts skipped.
fn profile_tier_level(
    bits: &mut Bits<'_>,
    max_sub_layers_minus1: u32,
) -> Result<(u8, bool, u8, u32, u8), SpsError> {
    let profile_space = u8::try_from(bits.bits(2)?).unwrap_or(0);
    let high_tier = bits.bit()?;
    let profile_idc = u8::try_from(bits.bits(5)?).unwrap_or(0);
    let compatibility = bits.bits(32)?;
    // progressive_source_flag, interlaced_source_flag,
    // non_packed_constraint_flag, frame_only_constraint_flag, the 43
    // constraint bits and general_inbld_flag or its reserved bit.
    bits.skip(48)?;
    let level_idc = u8::try_from(bits.bits(8)?).unwrap_or(0);
    let mut profile_present = [false; 8];
    let mut level_present = [false; 8];
    let sub_layers = usize::try_from(max_sub_layers_minus1).unwrap_or(0);
    for (profile, level) in profile_present
        .iter_mut()
        .zip(level_present.iter_mut())
        .take(sub_layers)
    {
        *profile = bits.bit()?;
        *level = bits.bit()?;
    }
    if max_sub_layers_minus1 > 0 {
        // reserved_zero_2bits for i from sps_max_sub_layers_minus1 to 7.
        let reserved = 8_u32
            .saturating_sub(max_sub_layers_minus1)
            .saturating_mul(2);
        bits.skip(usize::try_from(reserved).unwrap_or(0))?;
    }
    for (profile, level) in profile_present.iter().zip(level_present) {
        if *profile {
            bits.skip(88)?;
        }
        if level {
            bits.skip(8)?;
        }
    }
    Ok((
        profile_space,
        high_tier,
        profile_idc,
        compatibility,
        level_idc,
    ))
}

/// `SubWidthC` and `SubHeightC` of a `chroma_format_idc` (Table 6-1);
/// 4:4:4 with separate colour planes is monochrome-like, (1, 1).
const fn chroma_subsampling(chroma_format_idc: u32) -> (u32, u32) {
    match chroma_format_idc {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    }
}

/// Reads an SPS NAL unit (header included) up to its conformance window.
pub fn parse_sps(unit: &[u8]) -> Result<SpsInfo, SpsError> {
    if nal::unit_type(unit) != Some(nal::SPS_NUT) {
        return Err(SpsError::NotSps);
    }
    let rbsp = unescape(unit.get(HEADER_LEN..).ok_or(SpsError::Truncated)?);
    let mut bits = Bits::new(&rbsp);
    // sps_video_parameter_set_id.
    bits.skip(4)?;
    let max_sub_layers_minus1 = bits.bits(3)?;
    if max_sub_layers_minus1 >= MAX_SUB_LAYERS {
        return Err(SpsError::OutOfRange);
    }
    // sps_temporal_id_nesting_flag.
    bits.skip(1)?;
    let (profile_space, high_tier, profile_idc, compatibility, level_idc) =
        profile_tier_level(&mut bits, max_sub_layers_minus1)?;
    // sps_seq_parameter_set_id.
    bits.ue()?;
    let chroma_format_idc = bits.ue()?;
    if chroma_format_idc > 3 {
        return Err(SpsError::OutOfRange);
    }
    let (sub_width, sub_height) = if chroma_format_idc == 3 && bits.bit()? {
        (1, 1)
    } else {
        chroma_subsampling(chroma_format_idc)
    };
    let pic_width = bits.ue()?;
    let pic_height = bits.ue()?;
    let (mut crop_x, mut crop_y) = (0_u64, 0_u64);
    if bits.bit()? {
        let left = u64::from(bits.ue()?);
        let right = u64::from(bits.ue()?);
        let top = u64::from(bits.ue()?);
        let bottom = u64::from(bits.ue()?);
        crop_x = left
            .saturating_add(right)
            .saturating_mul(u64::from(sub_width));
        crop_y = top
            .saturating_add(bottom)
            .saturating_mul(u64::from(sub_height));
    }
    let width = u64::from(pic_width).saturating_sub(crop_x);
    let height = u64::from(pic_height).saturating_sub(crop_y);
    if width == 0 || height == 0 {
        return Err(SpsError::EmptyPicture);
    }
    Ok(SpsInfo {
        profile_space,
        high_tier,
        profile_idc,
        compatibility,
        level_idc,
        width: u32::try_from(width).unwrap_or(u32::MAX),
        height: u32::try_from(height).unwrap_or(u32::MAX),
    })
}

/// Whether a prefix SEI NAL unit (header included) carries a recovery
/// point message (D.2.8), which marks a random access point on cameras
/// that refresh intra without IRAP pictures. Anything unreadable is
/// `false`.
pub fn has_recovery_point(unit: &[u8]) -> bool {
    if nal::unit_type(unit) != Some(nal::PREFIX_SEI_NUT) {
        return false;
    }
    let rbsp = unescape(unit.get(HEADER_LEN..).unwrap_or_default());
    let mut pos = 0_usize;
    // A message's type or size (§7.3.5): a run of `0xff` bytes and a last
    // byte, summed. Every read moves past at least one byte.
    let read = |pos: &mut usize| {
        let mut value = 0_usize;
        loop {
            let byte = *rbsp.get(*pos)?;
            *pos = pos.saturating_add(1);
            value = value.saturating_add(usize::from(byte));
            if byte != 0xff {
                return Some(value);
            }
        }
    };
    // Messages until the trailing bits (`0x80`) or the end.
    while rbsp.get(pos).is_some_and(|&byte| byte != 0x80) {
        let (Some(payload_type), Some(size)) = (read(&mut pos), read(&mut pos)) else {
            return false;
        };
        let end = pos.saturating_add(size);
        if end > rbsp.len() {
            return false;
        }
        if payload_type == RECOVERY_POINT && size > 0 {
            return true;
        }
        pos = end;
    }
    false
}

/// Hand-assembled H.265 bitstream pieces for tests: this crate's and,
/// behind the `test-util` feature, the fake camera's. Every set is
/// complete to its trailing bits, so other parsers (retina's, a decoder)
/// read it too.
#[cfg(any(test, feature = "test-util"))]
pub mod test_data {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        clippy::missing_panics_doc,
        clippy::unwrap_used,
        reason = "test code"
    )]

    use crate::h264::test_data::Bits;

    /// The level the sets declare: 4.0, `general_level_idc` 120 (A.4.1).
    pub const LEVEL_IDC: u8 = 120;

    /// Inserts emulation prevention bytes (§7.4.2): a `0x03` before any
    /// byte up to `0x03` that follows two zero bytes.
    pub fn escape(rbsp: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(rbsp.len() + 4);
        let mut zeros = 0;
        for &byte in rbsp {
            if zeros >= 2 && byte <= 0x03 {
                out.push(0x03);
                zeros = 0;
            }
            zeros = if byte == 0 { zeros + 1 } else { 0 };
            out.push(byte);
        }
        out
    }

    /// A NAL unit of `unit_type` (layer 0, temporal id 0) around `rbsp`.
    pub fn unit(unit_type: u8, rbsp: &[u8]) -> Vec<u8> {
        let mut nal = vec![unit_type << 1, 0x01];
        nal.extend(escape(rbsp));
        nal
    }

    /// `profile_tier_level(1, 0)` (§7.3.3): `profile_idc` (Main is
    /// compatible with Main and Main 10), the Main or the High tier,
    /// progressive, frame only, [`LEVEL_IDC`].
    fn profile_tier_level(b: &mut Bits, profile_idc: u32, high_tier: bool) {
        b.bits(0, 2) // general_profile_space
            .bit(high_tier) // general_tier_flag
            .bits(profile_idc, 5)
            // general_profile_compatibility_flag: Main streams conform to
            // Main 10 too (A.3.2), other profiles to themselves.
            .bits(
                if profile_idc == 1 {
                    0x6000_0000
                } else {
                    0x8000_0000 >> profile_idc
                },
                32,
            )
            .bit(true) // general_progressive_source_flag
            .bit(false) // general_interlaced_source_flag
            .bit(false) // general_non_packed_constraint_flag
            .bit(true) // general_frame_only_constraint_flag
            .bits(0, 32) // general_reserved_zero_43bits, first 32
            .bits(0, 11) // and the other 11
            .bit(false) // general_reserved_zero_bit
            .bits(u32::from(LEVEL_IDC), 8);
    }

    /// A VPS for the SPS below: one layer, one sub-layer, no timing.
    pub fn vps() -> Vec<u8> {
        vps_of_tier(false)
    }

    /// As [`vps`], in the High tier when `high_tier` (A.4.1: the High
    /// tier exists from level 4 on, which [`LEVEL_IDC`] is).
    pub fn vps_of_tier(high_tier: bool) -> Vec<u8> {
        let mut b = Bits::default();
        b.bits(0, 4) // vps_video_parameter_set_id
            .bit(true) // vps_base_layer_internal_flag
            .bit(true) // vps_base_layer_available_flag
            .bits(0, 6) // vps_max_layers_minus1
            .bits(0, 3) // vps_max_sub_layers_minus1
            .bit(true) // vps_temporal_id_nesting_flag
            .bits(0xffff, 16); // vps_reserved_0xffff_16bits
        profile_tier_level(&mut b, 1, high_tier);
        b.bit(true) // vps_sub_layer_ordering_info_present_flag
            .ue(1) // vps_max_dec_pic_buffering_minus1
            .ue(0) // vps_max_num_reorder_pics
            .ue(0) // vps_max_latency_increase_plus1
            .bits(0, 6) // vps_max_layer_id
            .ue(0) // vps_num_layer_sets_minus1
            .bit(false) // vps_timing_info_present_flag
            .bit(false); // vps_extension_flag
        unit(super::nal::VPS_NUT, &b.finish())
    }

    /// A Main profile SPS for `width` × `height` luma samples (multiples
    /// of 8), 4:2:0, 8 bits, no conformance window, no VUI.
    pub fn sps(width: u32, height: u32) -> Vec<u8> {
        sps_of(1, width, height)
    }

    /// As [`sps`], of profile `profile_idc` (1 Main, 2 Main 10), with
    /// 8-bit samples, which Main 10 allows too (A.3.3).
    pub fn sps_of(profile_idc: u32, width: u32, height: u32) -> Vec<u8> {
        sps_of_tier(profile_idc, false, width, height)
    }

    /// As [`sps_of`], in the High tier when `high_tier` (A.4.1).
    pub fn sps_of_tier(profile_idc: u32, high_tier: bool, width: u32, height: u32) -> Vec<u8> {
        let mut b = Bits::default();
        b.bits(0, 4) // sps_video_parameter_set_id
            .bits(0, 3) // sps_max_sub_layers_minus1
            .bit(true); // sps_temporal_id_nesting_flag
        profile_tier_level(&mut b, profile_idc, high_tier);
        b.ue(0) // sps_seq_parameter_set_id
            .ue(1) // chroma_format_idc: 4:2:0
            .ue(width)
            .ue(height)
            .bit(false) // conformance_window_flag
            .ue(0) // bit_depth_luma_minus8
            .ue(0) // bit_depth_chroma_minus8
            .ue(4) // log2_max_pic_order_cnt_lsb_minus4
            .bit(true) // sps_sub_layer_ordering_info_present_flag
            .ue(1) // sps_max_dec_pic_buffering_minus1
            .ue(0) // sps_max_num_reorder_pics
            .ue(0) // sps_max_latency_increase_plus1
            .ue(0) // log2_min_luma_coding_block_size_minus3
            .ue(3) // log2_diff_max_min_luma_coding_block_size
            .ue(0) // log2_min_luma_transform_block_size_minus2
            .ue(3) // log2_diff_max_min_luma_transform_block_size
            .ue(1) // max_transform_hierarchy_depth_inter
            .ue(1) // max_transform_hierarchy_depth_intra
            .bit(false) // scaling_list_enabled_flag
            .bit(false) // amp_enabled_flag
            .bit(true) // sample_adaptive_offset_enabled_flag
            .bit(false) // pcm_enabled_flag
            .ue(0) // num_short_term_ref_pic_sets
            .bit(false) // long_term_ref_pics_present_flag
            .bit(true) // sps_temporal_mvp_enabled_flag
            .bit(true) // strong_intra_smoothing_enabled_flag
            .bit(false) // vui_parameters_present_flag
            .bit(false); // sps_extension_present_flag
        unit(super::nal::SPS_NUT, &b.finish())
    }

    /// A PPS for the SPS above.
    pub fn pps() -> Vec<u8> {
        let mut b = Bits::default();
        b.ue(0) // pps_pic_parameter_set_id
            .ue(0) // pps_seq_parameter_set_id
            .bit(false) // dependent_slice_segments_enabled_flag
            .bit(false) // output_flag_present_flag
            .bits(0, 3) // num_extra_slice_header_bits
            .bit(false) // sign_data_hiding_enabled_flag
            .bit(false) // cabac_init_present_flag
            .ue(0) // num_ref_idx_l0_default_active_minus1
            .ue(0) // num_ref_idx_l1_default_active_minus1
            .ue(0) // init_qp_minus26 (se: 0)
            .bit(false) // constrained_intra_pred_flag
            .bit(false) // transform_skip_enabled_flag
            .bit(false) // cu_qp_delta_enabled_flag
            .ue(0) // pps_cb_qp_offset (se: 0)
            .ue(0) // pps_cr_qp_offset (se: 0)
            .bit(false) // pps_slice_chroma_qp_offsets_present_flag
            .bit(false) // weighted_pred_flag
            .bit(false) // weighted_bipred_flag
            .bit(false) // transquant_bypass_enabled_flag
            .bit(false) // tiles_enabled_flag
            .bit(false) // entropy_coding_sync_enabled_flag
            .bit(true) // pps_loop_filter_across_slices_enabled_flag
            .bit(false) // deblocking_filter_control_present_flag
            .bit(false) // pps_scaling_list_data_present_flag
            .bit(false) // lists_modification_present_flag
            .ue(0) // log2_parallel_merge_level_minus2
            .bit(false) // slice_segment_header_extension_present_flag
            .bit(false); // pps_extension_present_flag
        unit(super::nal::PPS_NUT, &b.finish())
    }

    /// A prefix SEI with one recovery point message (D.2.8):
    /// `recovery_poc_cnt = 0`, `exact_match_flag`, no broken link.
    pub fn recovery_point_sei() -> Vec<u8> {
        let mut payload = Bits::default();
        // se(v) 0 is ue(v) 0; then the two flags, then payload alignment.
        payload.ue(0).bit(true).bit(false);
        let payload = payload.finish();
        let mut rbsp = vec![6, u8::try_from(payload.len()).unwrap()];
        rbsp.extend(payload);
        rbsp.push(0x80); // rbsp_trailing_bits of the SEI
        unit(super::nal::PREFIX_SEI_NUT, &rbsp)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::test_data::{
        LEVEL_IDC, escape, pps, recovery_point_sei, sps, sps_of, sps_of_tier, unit, vps,
        vps_of_tier,
    };
    use super::*;
    use crate::h264::test_data::Bits as Writer;

    #[test]
    fn an_sps_yields_profile_tier_level_and_size_h265_7_3_3() {
        let info = parse_sps(&sps(640, 480)).unwrap();
        assert_eq!(
            info,
            SpsInfo {
                profile_space: 0,
                high_tier: false,
                profile_idc: 1,
                compatibility: 0x6000_0000,
                level_idc: LEVEL_IDC,
                width: 640,
                height: 480,
            }
        );
        assert!(info.conforms_to(1) && info.conforms_to(2) && !info.conforms_to(3));
        assert!(!info.conforms_to(32) && !info.conforms_to(0));
        let main10 = parse_sps(&sps_of(2, 3840, 2160)).unwrap();
        assert_eq!((main10.profile_idc, main10.compatibility), (2, 0x2000_0000));
        assert!(main10.conforms_to(2) && !main10.conforms_to(1));
        assert_eq!((main10.width, main10.height), (3840, 2160));
        let high = parse_sps(&sps_of_tier(1, true, 640, 480)).unwrap();
        assert_eq!((high.high_tier, high.profile_idc), (true, 1));
        assert_eq!(high.compatibility, 0x6000_0000);
        assert_ne!(vps_of_tier(true), vps());
    }

    /// An SPS with `sub_layers` sub-layers whose profile and level are
    /// present on every other one, a conformance window, 4:2:2 or 4:4:4
    /// with separate planes.
    fn sps_with(sub_layers: u32, chroma: u32, separate: bool, crop: [u32; 4]) -> Vec<u8> {
        let mut b = Writer::default();
        b.bits(0, 4).bits(sub_layers - 1, 3).bit(true);
        b.bits(1, 2).bit(true).bits(4, 5).bits(0x0800_0000, 32);
        b.bits(0, 32).bits(0, 16).bits(153, 8);
        for i in 0..sub_layers - 1 {
            b.bit(i % 2 == 0).bit(i % 2 == 0);
        }
        if sub_layers > 1 {
            for _ in sub_layers - 1..8 {
                b.bits(0, 2);
            }
        }
        for i in 0..sub_layers - 1 {
            if i % 2 == 0 {
                b.bits(0, 32).bits(0, 32).bits(0, 24).bits(0, 8);
            }
        }
        b.ue(0).ue(chroma);
        if chroma == 3 {
            b.bit(separate);
        }
        b.ue(1920).ue(1088).bit(true);
        for offset in crop {
            b.ue(offset);
        }
        unit(nal::SPS_NUT, &b.finish())
    }

    #[test]
    fn sub_layers_and_the_conformance_window_are_read_h265_7_4_3_2_1() {
        let info = parse_sps(&sps_with(4, 1, false, [0, 0, 0, 4])).unwrap();
        assert_eq!(
            (info.profile_space, info.high_tier, info.profile_idc),
            (1, true, 4)
        );
        assert_eq!(info.level_idc, 153);
        assert_eq!((info.width, info.height), (1920, 1080), "4:2:0 crops by 2");
        let info = parse_sps(&sps_with(1, 2, false, [1, 1, 1, 1])).unwrap();
        assert_eq!((info.width, info.height), (1916, 1086), "4:2:2: 2 and 1");
        let info = parse_sps(&sps_with(7, 3, false, [1, 0, 0, 0])).unwrap();
        assert_eq!((info.width, info.height), (1919, 1088), "4:4:4: 1 and 1");
        let info = parse_sps(&sps_with(2, 3, true, [0, 1, 1, 0])).unwrap();
        assert_eq!((info.width, info.height), (1919, 1087), "separate planes");
        let info = parse_sps(&sps_with(1, 0, false, [0, 0, 0, 1])).unwrap();
        assert_eq!(info.height, 1087, "monochrome");
        assert_eq!(chroma_subsampling(1), (2, 2));
        assert_eq!(chroma_subsampling(2), (2, 1));
        assert_eq!(chroma_subsampling(3), (1, 1));
    }

    #[test]
    fn broken_or_foreign_units_are_errors() {
        assert_eq!(parse_sps(&pps()), Err(SpsError::NotSps));
        assert_eq!(parse_sps(&[]), Err(SpsError::NotSps));
        assert_eq!(parse_sps(&[0x42]), Err(SpsError::Truncated));
        assert_eq!(parse_sps(&[0x42, 0x01]), Err(SpsError::Truncated));
        let whole = sps(640, 480);
        for len in 0..whole.len() {
            let _no_panic = parse_sps(&whole[..len]);
        }
        assert_eq!(parse_sps(&whole[..10]), Err(SpsError::Truncated));
        // sps_max_sub_layers_minus1 = 7.
        assert_eq!(
            parse_sps(&[0x42, 0x01, 0x0e, 0x00]),
            Err(SpsError::OutOfRange)
        );
        let mut b = Writer::default();
        b.bits(0, 8);
        b.bits(0, 32).bits(0, 32).bits(0, 32);
        b.ue(0).ue(4);
        assert_eq!(
            parse_sps(&unit(nal::SPS_NUT, &b.finish())),
            Err(SpsError::OutOfRange),
            "chroma_format_idc 4"
        );
        assert_eq!(SpsError::NotSps.to_string(), "not a sequence parameter set");
    }

    #[test]
    fn cropping_must_leave_a_picture_h265_7_4_3_2_1() {
        let gone = sps_with(1, 1, false, [480, 480, 0, 0]);
        assert_eq!(parse_sps(&gone), Err(SpsError::EmptyPicture));
        let gone = sps_with(1, 1, false, [0, 0, 300, 300]);
        assert_eq!(parse_sps(&gone), Err(SpsError::EmptyPicture));
        assert_eq!(
            SpsError::EmptyPicture.to_string(),
            "cropping leaves no picture"
        );
    }

    #[test]
    fn exp_golomb_codes_longer_than_32_bits_are_out_of_range_h265_9_2() {
        let mut bits = Bits::new(&[0x00, 0x00, 0x00, 0x00, 0x80]);
        assert_eq!(bits.ue(), Err(SpsError::OutOfRange));
        let mut bits = Bits::new(&[0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(bits.ue(), Ok(u32::MAX - 1), "31 zeros, then 31 ones");
        let mut bits = Bits::new(&[0b0010_0000]);
        assert_eq!(bits.ue(), Ok(3));
        let mut bits = Bits::new(&[0b0100_0000]);
        assert_eq!(bits.ue(), Ok(1));
        assert_eq!(bits.skip(5), Ok(()));
        assert_eq!(bits.skip(1), Err(SpsError::Truncated));
    }

    #[test]
    fn emulation_prevention_round_trips_h265_7_4_2() {
        let rbsp = [0, 0, 0, 0, 0, 1, 0, 0, 2, 0, 0, 3, 0, 0, 4];
        let escaped = escape(&rbsp);
        assert_eq!(
            escaped,
            [0, 0, 3, 0, 0, 3, 0, 1, 0, 0, 3, 2, 0, 0, 3, 3, 0, 0, 4]
        );
        assert_eq!(unescape(&escaped), rbsp);
        assert_eq!(unescape(&[0, 3, 0, 0, 0x03]), [0, 3, 0, 0]);
    }

    #[test]
    fn recovery_point_sei_is_recognized_h265_d_2_8() {
        assert!(has_recovery_point(&recovery_point_sei()));
        // User data unregistered (5) then a recovery point.
        let both = unit(nal::PREFIX_SEI_NUT, &[5, 1, 0xaa, 6, 1, 0x80, 0x80]);
        assert!(has_recovery_point(&both));
        // A type and size beyond one byte each: 255 + 1 = 256, size 255 + 0.
        let mut long = vec![0xff, 1, 0xff, 0];
        long.extend([0x11; 255]);
        long.push(0x80);
        assert!(!has_recovery_point(&unit(nal::PREFIX_SEI_NUT, &long)));
        long.splice(..0, [6, 1, 0x80]);
        assert!(has_recovery_point(&unit(nal::PREFIX_SEI_NUT, &long)));
        // Not one: other types, empty messages, broken sizes, other units.
        assert!(!has_recovery_point(&unit(
            nal::PREFIX_SEI_NUT,
            &[5, 1, 0xaa, 0x80]
        )));
        assert!(!has_recovery_point(&unit(
            nal::PREFIX_SEI_NUT,
            &[6, 0, 0x80]
        )));
        assert!(!has_recovery_point(&unit(
            nal::PREFIX_SEI_NUT,
            &[6, 9, 0x00]
        )));
        // A message that ends where the bytes do, without trailing bits.
        assert!(has_recovery_point(&unit(
            nal::PREFIX_SEI_NUT,
            &[6, 1, 0x00]
        )));
        assert!(!has_recovery_point(&unit(nal::PREFIX_SEI_NUT, &[6])));
        assert!(!has_recovery_point(&unit(nal::PREFIX_SEI_NUT, &[0xff])));
        assert!(!has_recovery_point(&unit(nal::PREFIX_SEI_NUT, &[])));
        assert!(!has_recovery_point(&[nal::PREFIX_SEI_NUT << 1]));
        assert!(!has_recovery_point(&sps(640, 480)));
        assert!(!has_recovery_point(&[]));
        // The sets the fake camera sends are what they say.
        assert_eq!(nal::unit_type(&vps()), Some(nal::VPS_NUT));
        assert_eq!(nal::unit_type(&pps()), Some(nal::PPS_NUT));
    }
}
