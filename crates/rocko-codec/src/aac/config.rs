//! The `AudioSpecificConfig` of an AAC stream: what the decoder needs and
//! whether the daemon can decode it at all.
//!
//! Implements ISO/IEC 14496-3 §1.6.2.1 (`AudioSpecificConfig`), §1.6.3.3
//! and Table 1.18 (sampling frequency index), Table 1.19 (channel
//! configuration), §1.6.5 (explicit SBR/PS signaling) and §4.4.1
//! (`GASpecificConfig`, `frameLengthFlag`). Only AAC-LC with 1024-sample
//! frames in mono or stereo is decodable; everything else is reported so
//! negotiation can say why the stream has no audio.

use std::fmt;

/// Audio object type 2: AAC-LC (ISO/IEC 14496-3 Table 1.1).
pub const AOT_AAC_LC: u8 = 2;

/// Audio object type 5: SBR, HE-AAC (ISO/IEC 14496-3 Table 1.1).
const AOT_SBR: u8 = 5;

/// Audio object type 29: PS, HE-AAC v2 (ISO/IEC 14496-3 Table 1.1).
const AOT_PS: u8 = 29;

/// The escape value of the 5-bit audio object type: 6 more bits follow
/// (ISO/IEC 14496-3 §1.6.2.1, `GetAudioObjectType`).
const AOT_ESCAPE: u8 = 31;

/// The sampling frequency index that says an explicit 24-bit frequency
/// follows (ISO/IEC 14496-3 §1.6.3.3).
const FREQUENCY_ESCAPE: u8 = 0xf;

/// Samples per channel in an AAC-LC frame with `frameLengthFlag` 0
/// (ISO/IEC 14496-3 §4.4.1, §4.5.1.1).
pub const FRAME_SAMPLES: u32 = 1024;

/// Table 1.18 of ISO/IEC 14496-3: sampling frequency by index; 0xd and
/// 0xe are reserved.
const FREQUENCIES: [u32; 13] = [
    96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
    7_350,
];

/// A decodable AAC-LC configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AacConfig {
    /// The sampling frequency in Hz.
    pub sample_rate: u32,
    /// 1 (mono) or 2 (stereo).
    pub channels: u8,
}

/// Why a configuration is unreadable or not decodable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The configuration ended before a field.
    #[error("AudioSpecificConfig truncated at {0}")]
    Truncated(&'static str),
    /// A reserved sampling frequency index (0xd, 0xe) or a frequency of 0.
    #[error("reserved or zero sampling frequency")]
    Frequency,
    /// HE-AAC (SBR) or HE-AAC v2 (PS): out of scope.
    #[error("HE-AAC (audio object type {0}) is not supported")]
    HighEfficiency(u8),
    /// Another object type than AAC-LC.
    #[error("audio object type {0} is not AAC-LC")]
    ObjectType(u8),
    /// A channel configuration other than mono or stereo, or one given by
    /// a program config element (0).
    #[error("channel configuration {0} is not mono or stereo")]
    Channels(u8),
    /// 960-sample frames (`frameLengthFlag` 1), which the decoder lacks.
    #[error("960-sample frames are not supported")]
    FrameLength,
}

impl ConfigError {
    /// The name an unsupported codec descriptor carries for this stream:
    /// `aac_he` for SBR and PS, `aac` for any other AAC the daemon cannot
    /// decode.
    pub const fn codec_name(self) -> &'static str {
        match self {
            Self::HighEfficiency(_) => "aac_he",
            _ => "aac",
        }
    }
}

/// Reads bits MSB first from a byte slice, never past its end.
pub(crate) struct BitReader<'a> {
    /// The bytes.
    data: &'a [u8],
    /// The next bit to read, counted from the first byte's MSB.
    position: usize,
}

impl fmt::Debug for BitReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitReader")
            .field("len", &self.data.len())
            .field("position", &self.position)
            .finish()
    }
}

impl<'a> BitReader<'a> {
    /// A reader at the first bit of `data`.
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// The next `count` (at most 32) bits as an unsigned number, or `None`
    /// past the end.
    pub(crate) fn read(&mut self, count: u8) -> Option<u32> {
        debug_assert!(count <= 32, "at most 32 bits at once");
        let mut value = 0_u32;
        for _ in 0..count {
            let byte = self.data.get(self.position.checked_div(8)?)?;
            let shift = 7_usize.checked_sub(self.position.checked_rem(8)?)?;
            let bit = u32::from(byte.checked_shr(u32::try_from(shift).ok()?)? & 1);
            value = value.checked_shl(1)? | bit;
            self.position = self.position.checked_add(1)?;
        }
        Some(value)
    }

    /// The next `count` (at most 8) bits as a byte.
    pub(crate) fn read_u8(&mut self, count: u8) -> Option<u8> {
        debug_assert!(count <= 8, "at most 8 bits into a byte");
        self.read(count).and_then(|v| u8::try_from(v).ok())
    }
}

/// `GetAudioObjectType()` of ISO/IEC 14496-3 §1.6.2.1: 5 bits, escaped
/// to 32 + 6 bits.
fn object_type(bits: &mut BitReader<'_>) -> Result<u8, ConfigError> {
    let aot = bits
        .read_u8(5)
        .ok_or(ConfigError::Truncated("audioObjectType"))?;
    if aot != AOT_ESCAPE {
        return Ok(aot);
    }
    let ext = bits
        .read_u8(6)
        .ok_or(ConfigError::Truncated("audioObjectTypeExt"))?;
    Ok(ext.saturating_add(32))
}

/// A sampling frequency index and, when escaped, the explicit frequency
/// (ISO/IEC 14496-3 §1.6.2.1, Table 1.18).
fn frequency(bits: &mut BitReader<'_>) -> Result<u32, ConfigError> {
    let index = bits
        .read_u8(4)
        .ok_or(ConfigError::Truncated("samplingFrequencyIndex"))?;
    let rate = if index == FREQUENCY_ESCAPE {
        bits.read(24)
            .ok_or(ConfigError::Truncated("samplingFrequency"))?
    } else {
        *FREQUENCIES
            .get(usize::from(index))
            .ok_or(ConfigError::Frequency)?
    };
    if rate == 0 {
        return Err(ConfigError::Frequency);
    }
    Ok(rate)
}

/// Parses an `AudioSpecificConfig` and checks that the AAC-LC decoder can
/// take it.
pub fn parse_config(data: &[u8]) -> Result<AacConfig, ConfigError> {
    let mut bits = BitReader::new(data);
    let aot = object_type(&mut bits)?;
    let sample_rate = frequency(&mut bits)?;
    let channels = bits
        .read_u8(4)
        .ok_or(ConfigError::Truncated("channelConfiguration"))?;
    // §1.6.5.2 explicit hierarchical signaling: the first object type says
    // SBR or PS, and the core type follows the extension frequency.
    if aot == AOT_SBR || aot == AOT_PS {
        return Err(ConfigError::HighEfficiency(aot));
    }
    if aot != AOT_AAC_LC {
        return Err(ConfigError::ObjectType(aot));
    }
    if !matches!(channels, 1 | 2) {
        return Err(ConfigError::Channels(channels));
    }
    // GASpecificConfig (§4.4.1): frameLengthFlag first. It is always
    // present in whole bytes: 13 or 37 bits precede it, in 16 or 40.
    if bits.read_u8(1) != Some(0) {
        return Err(ConfigError::FrameLength);
    }
    // Backward-compatible (implicit) SBR signaling may follow; an LC
    // decoder plays the core and ignores it (§1.6.5.1).
    Ok(AacConfig {
        sample_rate,
        channels,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn iso14496_3_1_6_2_1_lc_16khz_mono() {
        // 00010 1000 0001 000: AOT 2, index 8 (16 kHz), mono, 1024 samples.
        assert_eq!(
            parse_config(&[0x14, 0x08]),
            Ok(AacConfig {
                sample_rate: 16_000,
                channels: 1
            })
        );
    }

    #[test]
    fn iso14496_3_table_1_18_every_frequency_index() {
        for (index, rate) in FREQUENCIES.iter().enumerate() {
            let index = u16::try_from(index).unwrap();
            // AOT 2 (5 bits), index (4 bits), stereo (4 bits), flag 0.
            let word = (2 << 11) | (index << 7) | (2 << 3);
            let config = parse_config(&word.to_be_bytes()).unwrap();
            assert_eq!(config.sample_rate, *rate);
            assert_eq!(config.channels, 2);
        }
    }

    #[test]
    fn iso14496_3_1_6_3_3_reserved_frequencies_are_refused() {
        for index in [0xd_u16, 0xe] {
            let word = (2 << 11) | (index << 7) | (1 << 3);
            assert_eq!(
                parse_config(&word.to_be_bytes()),
                Err(ConfigError::Frequency)
            );
        }
    }

    #[test]
    fn iso14496_3_1_6_2_1_escaped_frequency_is_read_explicitly() {
        // AOT 2, index 0xf, 24-bit 12 345 Hz, mono, flag 0.
        let bits: u64 = (2 << 35) | (0xf << 31) | (12_345 << 7) | (1 << 3);
        let bytes = bits.to_be_bytes();
        let config = parse_config(&bytes[3..]).unwrap();
        assert_eq!(config.sample_rate, 12_345);
        // An explicit 0 Hz is no frequency.
        let bits: u64 = (2 << 35) | (0xf << 31) | (1 << 3);
        assert_eq!(
            parse_config(&bits.to_be_bytes()[3..]),
            Err(ConfigError::Frequency)
        );
    }

    #[test]
    fn iso14496_3_1_6_5_he_aac_is_named_aac_he() {
        // AOT 5 (SBR), 24 kHz, mono.
        let word: u16 = (5 << 11) | (6 << 7) | (1 << 3);
        let err = parse_config(&word.to_be_bytes()).unwrap_err();
        assert_eq!(err, ConfigError::HighEfficiency(5));
        assert_eq!(err.codec_name(), "aac_he");
        let word: u16 = (29 << 11) | (6 << 7) | (2 << 3);
        assert_eq!(
            parse_config(&word.to_be_bytes()),
            Err(ConfigError::HighEfficiency(29))
        );
    }

    #[test]
    fn iso14496_3_1_6_2_1_escaped_object_types_are_not_lc() {
        // AOT 31 escape, ext 10 → 42, then index 8 and mono.
        let bits: u32 = (31 << 27) | (10 << 21) | (8 << 17) | (1 << 13);
        let err = parse_config(&bits.to_be_bytes()).unwrap_err();
        assert_eq!(err, ConfigError::ObjectType(42));
        assert_eq!(err.codec_name(), "aac");
    }

    #[test]
    fn other_object_types_and_layouts_are_refused() {
        let main: u16 = (1 << 11) | (8 << 7) | (1 << 3);
        assert_eq!(
            parse_config(&main.to_be_bytes()),
            Err(ConfigError::ObjectType(1))
        );
        for channels in [0_u16, 3, 6] {
            let word = (2 << 11) | (8 << 7) | (channels << 3);
            assert_eq!(
                parse_config(&word.to_be_bytes()),
                Err(ConfigError::Channels(u8::try_from(channels).unwrap()))
            );
        }
        let short_frames: u16 = (2 << 11) | (8 << 7) | (1 << 3) | (1 << 2);
        assert_eq!(
            parse_config(&short_frames.to_be_bytes()),
            Err(ConfigError::FrameLength)
        );
    }

    #[test]
    fn truncated_configs_name_the_missing_field() {
        let cases: [(&[u8], &str); 5] = [
            (&[], "audioObjectType"),
            (&[0xf8], "audioObjectTypeExt"),
            (&[0x10], "samplingFrequencyIndex"),
            (&[0x17, 0x80], "samplingFrequency"),
            // Escaped object type 32, index 0: 15 bits, the channels cut.
            (&[0xf8, 0x00], "channelConfiguration"),
        ];
        for (data, field) in cases {
            assert_eq!(
                parse_config(data),
                Err(ConfigError::Truncated(field)),
                "{data:02x?}"
            );
        }
    }

    #[test]
    fn the_bit_reader_stops_at_the_end() {
        let mut reader = BitReader::new(&[0xa5]);
        assert_eq!(reader.read(3), Some(0b101));
        assert_eq!(reader.read_u8(5), Some(0b00101));
        assert_eq!(reader.read(1), None);
        assert_eq!(reader.read_u8(0), Some(0));
    }

    #[test]
    fn errors_say_what_was_wrong() {
        assert_eq!(
            ConfigError::Truncated("x").to_string(),
            "AudioSpecificConfig truncated at x"
        );
        assert_eq!(
            ConfigError::Frequency.to_string(),
            "reserved or zero sampling frequency"
        );
        assert_eq!(
            ConfigError::HighEfficiency(5).to_string(),
            "HE-AAC (audio object type 5) is not supported"
        );
        assert_eq!(
            ConfigError::ObjectType(1).to_string(),
            "audio object type 1 is not AAC-LC"
        );
        assert_eq!(
            ConfigError::Channels(6).to_string(),
            "channel configuration 6 is not mono or stereo"
        );
        assert_eq!(
            ConfigError::FrameLength.to_string(),
            "960-sample frames are not supported"
        );
        assert!(format!("{:?}", BitReader::new(&[1, 2])).contains("len: 2"));
    }
}
