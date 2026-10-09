//! What the side branch reads out of the bitstream syntax: the profile,
//! level and picture size of a sequence parameter set, and recovery-point
//! SEI messages, through `h264-reader`.
//!
//! Implements ISO/IEC 14496-10 §7.3.2.1 (SPS: `profile_idc`,
//! `constraint_set` flags, `level_idc`, picture size), §7.4.1 (emulation
//! prevention) and D.2.7 (recovery point SEI); RFC 6184 §8.1
//! `profile-level-id` is the three SPS bytes in order.

use h264_reader::nal::sei::recovery_point::RecoveryPoint;
use h264_reader::nal::sei::{HeaderType, SeiReader};
use h264_reader::nal::sps::SeqParameterSet;
use h264_reader::rbsp::{BitReader, decode_nal};

/// What a sequence parameter set says about the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpsInfo {
    /// `profile_idc`, the constraint flags byte and `level_idc`, the
    /// three bytes RFC 6184 §8.1 spells as `profile-level-id`.
    pub profile_level_id: [u8; 3],
    /// Picture width in pixels, cropping applied.
    pub width: u32,
    /// Picture height in pixels, cropping applied.
    pub height: u32,
}

/// Why an SPS could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpsError {
    /// The unit is not a sequence parameter set.
    #[error("not a sequence parameter set")]
    NotSps,
    /// The emulation-prevention bytes are malformed (§7.4.1).
    #[error("invalid emulation prevention")]
    EmulationPrevention,
    /// The syntax could not be parsed (§7.3.2.1).
    #[error("sps syntax: {0}")]
    Syntax(String),
    /// The frame cropping offsets take the whole picture: §7.4.2.1.1 keeps
    /// them below its width and height.
    #[error("cropping leaves no picture")]
    EmptyPicture,
}

/// Reads an SPS NAL unit (header included).
pub fn parse_sps(nal: &[u8]) -> Result<SpsInfo, SpsError> {
    if nal
        .first()
        .is_none_or(|&h| super::nal::nal_type(h) != super::nal::NAL_SPS)
    {
        return Err(SpsError::NotSps);
    }
    let rbsp = decode_nal(nal).map_err(|_| SpsError::EmulationPrevention)?;
    let sps = SeqParameterSet::from_bits(BitReader::new(rbsp.as_ref()))
        .map_err(|err| SpsError::Syntax(format!("{err:?}")))?;
    let (width, height) = sps
        .pixel_dimensions()
        .map_err(|err| SpsError::Syntax(format!("{err:?}")))?;
    if width == 0 || height == 0 {
        return Err(SpsError::EmptyPicture);
    }
    Ok(SpsInfo {
        profile_level_id: [
            sps.profile().profile_idc(),
            u8::from(sps.constraint_flags),
            sps.level_idc,
        ],
        width,
        height,
    })
}

/// Whether an SEI NAL unit (header included) carries a recovery point
/// message (D.2.7), which marks a random access point on cameras that
/// refresh intra without IDR pictures. Anything unreadable is `false`.
pub fn has_recovery_point(nal: &[u8]) -> bool {
    if nal
        .first()
        .is_none_or(|&h| super::nal::nal_type(h) != super::nal::NAL_SEI)
    {
        return false;
    }
    let Ok(rbsp) = decode_nal(nal) else {
        return false;
    };
    let mut scratch = Vec::new();
    let mut reader = SeiReader::from_rbsp_bytes(rbsp.as_ref(), &mut scratch);
    while let Ok(Some(message)) = reader.next() {
        if message.payload_type == HeaderType::RecoveryPoint
            && RecoveryPoint::read(&message).is_ok()
        {
            return true;
        }
    }
    false
}

/// Hand-assembled bitstream pieces for tests: this crate's and, behind
/// the `test-util` feature, the fake camera's.
#[cfg(any(test, feature = "test-util"))]
pub mod test_data {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
        clippy::missing_panics_doc,
        clippy::unwrap_used,
        reason = "test code"
    )]

    /// A minimal bit writer for building parameter sets.
    #[derive(Debug, Default)]
    pub struct Bits {
        bytes: Vec<u8>,
        used: u32,
    }

    impl Bits {
        /// Appends one bit.
        pub fn bit(&mut self, value: bool) -> &mut Self {
            if self.used.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if value {
                let index = (self.used / 8) as usize;
                let shift = 7 - (self.used % 8);
                self.bytes[index] |= 1 << shift;
            }
            self.used += 1;
            self
        }

        /// Appends the low `count` bits of `value`, most significant first.
        pub fn bits(&mut self, value: u32, count: u32) -> &mut Self {
            for i in (0..count).rev() {
                self.bit((value >> i) & 1 == 1);
            }
            self
        }

        /// Exp-Golomb `ue(v)` (§9.1).
        pub fn ue(&mut self, value: u32) -> &mut Self {
            let code = value + 1;
            let len = 32 - code.leading_zeros();
            self.bits(0, len - 1);
            self.bits(code, len)
        }

        /// `rbsp_trailing_bits`: a one, then zeros to the byte boundary.
        pub fn finish(&mut self) -> Vec<u8> {
            self.bit(true);
            while !self.used.is_multiple_of(8) {
                self.bit(false);
            }
            std::mem::take(&mut self.bytes)
        }
    }

    /// A Baseline profile, level 4.0 SPS for `width` × `height` pixels
    /// (multiples of 16, up to 1080p: the reader checks the level's frame
    /// size limit), `frame_mbs_only`, no cropping, no VUI.
    pub fn sps(width: u32, height: u32) -> Vec<u8> {
        let mut b = Bits::default();
        b.bits(66, 8) // profile_idc: Baseline
            .bits(0xc0, 8) // constraint_set0 and 1
            .bits(40, 8) // level_idc 4.0
            .ue(0) // seq_parameter_set_id
            .ue(0) // log2_max_frame_num_minus4
            .ue(2) // pic_order_cnt_type
            .ue(1) // max_num_ref_frames
            .bit(false) // gaps_in_frame_num_value_allowed_flag
            .ue(width / 16 - 1)
            .ue(height / 16 - 1)
            .bit(true) // frame_mbs_only_flag
            .bit(true) // direct_8x8_inference_flag
            .bit(false) // frame_cropping_flag
            .bit(false); // vui_parameters_present_flag
        let mut nal = vec![0x67];
        nal.extend(b.finish());
        nal
    }

    /// A PPS for the SPS above.
    pub fn pps() -> Vec<u8> {
        let mut b = Bits::default();
        b.ue(0) // pic_parameter_set_id
            .ue(0) // seq_parameter_set_id
            .bit(false) // entropy_coding_mode_flag
            .bit(false) // bottom_field_pic_order_in_frame_present_flag
            .ue(0) // num_slice_groups_minus1
            .ue(0) // num_ref_idx_l0_default_active_minus1
            .ue(0) // num_ref_idx_l1_default_active_minus1
            .bit(false) // weighted_pred_flag
            .bits(0, 2) // weighted_bipred_idc
            .ue(0) // pic_init_qp_minus26 (se: 0)
            .ue(0) // pic_init_qs_minus26
            .ue(0) // chroma_qp_index_offset
            .bit(true) // deblocking_filter_control_present_flag
            .bit(false) // constrained_intra_pred_flag
            .bit(false); // redundant_pic_cnt_present_flag
        let mut nal = vec![0x68];
        nal.extend(b.finish());
        nal
    }

    /// A recovery point SEI: payload type 6, one byte of
    /// `recovery_frame_cnt = 0`, `exact_match_flag`, `broken_link_flag`,
    /// `changing_slice_group_idc` and trailing bits.
    pub fn recovery_point_sei() -> Vec<u8> {
        let mut payload = Bits::default();
        payload.ue(0).bit(true).bit(false).bits(0, 2);
        let payload = payload.finish();
        let mut nal = vec![0x06, 6, u8::try_from(payload.len()).unwrap()];
        nal.extend(payload);
        nal.push(0x80); // rbsp trailing bits of the SEI
        nal
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::test_data::{pps, recovery_point_sei, sps};
    use super::*;

    #[test]
    fn an_sps_yields_profile_level_id_and_dimensions_14496_10_7_3_2_1() {
        let info = parse_sps(&sps(640, 480)).unwrap();
        assert_eq!(info.profile_level_id, [0x42, 0xc0, 0x28]);
        assert_eq!((info.width, info.height), (640, 480));
        let info = parse_sps(&sps(1920, 1088)).unwrap();
        assert_eq!((info.width, info.height), (1920, 1088));
    }

    #[test]
    fn broken_or_foreign_units_are_errors() {
        assert_eq!(parse_sps(&pps()), Err(SpsError::NotSps));
        assert_eq!(parse_sps(&[]), Err(SpsError::NotSps));
        assert!(matches!(parse_sps(&[0x67]), Err(SpsError::Syntax(_))));
        assert!(matches!(
            parse_sps(&[0x67, 0x42, 0xc0]),
            Err(SpsError::Syntax(_))
        ));
        assert_eq!(
            parse_sps(&[0x67, 0x00, 0x00, 0x00, 0x01]),
            Err(SpsError::EmulationPrevention)
        );
        assert_eq!(SpsError::NotSps.to_string(), "not a sequence parameter set");
    }

    /// Found by the `h264_sps` fuzz target: an SPS whose cropping takes
    /// the whole picture, which h264-reader reads as a zero size.
    #[test]
    fn cropping_must_leave_a_picture_14496_10_7_4_2_1_1() {
        let cropped_away = [0x47, 0x31, 0x47, 0x25, 0xff, 0x1e, 0x25];
        assert_eq!(parse_sps(&cropped_away), Err(SpsError::EmptyPicture));
        assert_eq!(
            SpsError::EmptyPicture.to_string(),
            "cropping leaves no picture"
        );
    }

    #[test]
    fn recovery_point_sei_is_recognized_d_2_7() {
        assert!(has_recovery_point(&recovery_point_sei()));
        // Another SEI type (user data unregistered, 5) is not a recovery point.
        let other = [0x06, 5, 1, 0x00, 0x80];
        assert!(!has_recovery_point(&other));
        assert!(!has_recovery_point(&sps(640, 480)));
        assert!(!has_recovery_point(&[]));
        assert!(!has_recovery_point(&[0x06, 0x00, 0x00, 0x00, 0x01]));
        assert!(!has_recovery_point(&[0x06]));
    }
}
