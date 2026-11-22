//! Recorded AAC-LC for tests: this crate's decoder and transcoder tests
//! and, behind the `test-util` feature, the fake camera's AAC track.
//!
//! Each fixture is one second of a 1 kHz sine at half scale, mono, encoded
//! by macOS `afconvert -f adts -d aac@<rate> -c 1 -b 32000` on 2026-10-01
//! and stored as ADTS (ISO/IEC 13818-7 §6.2), which [`frames`] unwraps.

#![allow(
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

/// One second of a 1 kHz sine, AAC-LC, 16 kHz mono, ADTS.
pub const SINE_16K_MONO: &[u8] = include_bytes!("testdata/sine_1k_16k_mono.adts");

/// One second of a 1 kHz sine, AAC-LC, 48 kHz mono, ADTS.
pub const SINE_48K_MONO: &[u8] = include_bytes!("testdata/sine_1k_48k_mono.adts");

/// The `AudioSpecificConfig` of [`SINE_16K_MONO`]: AAC-LC, 16 kHz, mono.
pub const CONFIG_16K_MONO: [u8; 2] = [0x14, 0x08];

/// The `AudioSpecificConfig` of [`SINE_48K_MONO`]: AAC-LC, 48 kHz, mono.
pub const CONFIG_48K_MONO: [u8; 2] = [0x11, 0x88];

/// The raw AAC frames of an ADTS stream, headers (and CRCs) stripped.
/// Panics on a malformed stream: the fixtures are known good.
pub fn frames(adts: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = adts;
    while !rest.is_empty() {
        assert_eq!(rest[0], 0xff, "ADTS syncword");
        let header = if rest[1] & 0x01 == 1 { 7 } else { 9 };
        let length = usize::from(rest[3] & 0x03) << 11
            | usize::from(rest[4]) << 3
            | usize::from(rest[5] >> 5);
        out.push(&rest[header..length]);
        rest = &rest[length..];
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;
    use crate::aac::{AacConfig, parse_config};

    #[test]
    fn the_fixtures_are_about_one_second_of_frames() {
        // 1 s at 16 kHz is 15.6 frames of 1024; the encoder adds priming.
        assert!((16..=20).contains(&frames(SINE_16K_MONO).len()));
        assert!((47..=51).contains(&frames(SINE_48K_MONO).len()));
        assert!(frames(SINE_16K_MONO).iter().all(|f| !f.is_empty()));
    }

    #[test]
    fn the_configs_describe_the_fixtures() {
        assert_eq!(
            parse_config(&CONFIG_16K_MONO),
            Ok(AacConfig {
                sample_rate: 16_000,
                channels: 1
            })
        );
        assert_eq!(
            parse_config(&CONFIG_48K_MONO),
            Ok(AacConfig {
                sample_rate: 48_000,
                channels: 1
            })
        );
    }

    #[test]
    fn crc_protected_headers_are_nine_bytes() {
        let stream = [
            0xff, 0xf0, 0x60, 0x40, 0x01, 0x60, 0xfc, 0x12, 0x34, 0xab, 0xcd,
        ];
        assert_eq!(frames(&stream), vec![&[0xab, 0xcd][..]]);
    }
}
