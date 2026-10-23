//! ITU-T G.722 (7 kHz audio coding within 64 kbit/s): one octet per two
//! samples at 16 kHz, decoded to 16-bit linear PCM.
//!
//! The decoder is `nanoaudio-g722`'s, at 64 kbit/s (mode 1, the full 6-bit
//! lower sub-band code), the mode RTP carries (RFC 3551 §4.5.2). Its
//! receive path is the sub-band ADPCM decoder and the receive QMF of
//! G.722 §4, bit-exact with the ITU-T reference decoder: this module's
//! test decodes a fixture and compares it with what the reference made of
//! it. Every octet is a valid code word (G.722 §1.4.4: the high sub-band's
//! 2 bits, then the low sub-band's 6), so decoding never fails, whatever a
//! camera sends.
//!
//! RTP stamps G.722 with an 8000 Hz clock although it samples at 16 kHz,
//! an error of RFC 1890 that RFC 3551 §4.5.2 keeps: one tick per octet.
//!
//! Implements ITU-T G.722 (11/88) §1.4.4 (the octet's layout) and §4 (the
//! receive path), at the RTP clock rate of RFC 3551 §4.5.2.

#[cfg(any(test, feature = "test-util"))]
pub mod test_data;

use nanoaudio_g722::{G722BitRate, G722Decoder};

/// The G.722 sampling rate (G.722 §1.1: 16 kHz).
pub const SAMPLE_RATE: u32 = 16_000;

/// The RTP clock rate of G.722 (RFC 3551 §4.5.2): 8000, one tick per
/// octet, although it samples at [`SAMPLE_RATE`].
pub const CLOCK_RATE: u32 = 8_000;

/// Samples at [`SAMPLE_RATE`] in one octet: one code word for each of the
/// two sub-bands, which the receive QMF turns into two samples (G.722
/// §1.4.4, §4.4).
pub const SAMPLES_PER_OCTET: usize = 2;

/// Samples at [`SAMPLE_RATE`] between a sample going into a G.722 encoder
/// and the same sample coming out of the decoder: the transmit QMF's and
/// the receive QMF's delay together (G.722 §3.1, §4.4; two 24-tap
/// filters). Every encoder has the transmit QMF, so a stream's content
/// lies this far behind its timestamps. Measured on this decoder and its
/// crate's encoder: the cross-correlation of a 300 Hz tone, a 1 kHz tone
/// and white noise with their round trip peaks at 22 samples.
pub const CODEC_DELAY: u32 = 22;

/// One G.722 decoder for one stream. Keeps the ADPCM predictors' and the
/// QMF's state between octets, so the octets of one stream go through one
/// decoder in order.
#[derive(Debug, Clone)]
pub struct Decoder {
    /// The 64 kbit/s decoder.
    inner: G722Decoder,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// A decoder at 64 kbit/s (mode 1) in the reset state of G.722 §6.2.
    pub const fn new() -> Self {
        Self {
            inner: G722Decoder::new(G722BitRate::Rate64000),
        }
    }

    /// Back to the reset state, for a stream that restarted: its encoder
    /// starts from the reset state too.
    pub fn reset(&mut self) {
        self.inner.reset();
    }

    /// Decodes `octets`, appending [`SAMPLES_PER_OCTET`] samples of each to
    /// `pcm`.
    pub fn decode(&mut self, octets: &[u8], pcm: &mut Vec<i16>) {
        pcm.reserve(octets.len().saturating_mul(SAMPLES_PER_OCTET));
        for octet in octets {
            pcm.extend_from_slice(&self.inner.decode_byte(*octet));
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

    use super::test_data::{SWEEP_NOISE, SWEEP_NOISE_REFERENCE, encode, tone};
    use super::*;

    fn decode(octets: &[u8]) -> Vec<i16> {
        let mut pcm = Vec::new();
        Decoder::new().decode(octets, &mut pcm);
        pcm
    }

    #[test]
    fn itu_t_g722_4_the_receive_path_matches_the_itu_t_reference_decoder_bit_for_bit() {
        let reference: Vec<i16> = SWEEP_NOISE_REFERENCE
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_le_bytes(*pair))
            .collect();
        let pcm = decode(SWEEP_NOISE);
        assert_eq!(pcm.len(), SWEEP_NOISE.len() * SAMPLES_PER_OCTET);
        assert_eq!(pcm, reference);
    }

    #[test]
    fn itu_t_g722_1_4_4_every_octet_decodes_to_two_samples() {
        let every: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&every).len(), 512);
        assert!(decode(&[]).is_empty());
    }

    #[test]
    fn a_reset_decoder_decodes_as_a_new_one() {
        let octets = encode(&tone(1_000, 1_600));
        let mut decoder = Decoder::default();
        let mut first = Vec::new();
        decoder.decode(&octets, &mut first);
        let mut again = Vec::new();
        decoder.decode(&octets, &mut again);
        assert_ne!(first, again, "the state carries over");
        decoder.reset();
        let mut reset = Vec::new();
        decoder.decode(&octets, &mut reset);
        assert_eq!(first, reset);
    }

    #[test]
    fn itu_t_g722_3_and_4_a_round_trip_lags_by_the_codec_delay() {
        let input = tone(300, 16_000);
        let output = decode(&encode(&input));
        let correlation = |lag: usize| -> f64 {
            (2_000..14_000)
                .map(|i| f64::from(input[i]) * f64::from(output[i + lag]))
                .sum()
        };
        let best = (0..60)
            .max_by(|a, b| correlation(*a).total_cmp(&correlation(*b)))
            .unwrap();
        assert_eq!(best, usize::try_from(CODEC_DELAY).unwrap());
    }

    #[test]
    fn rfc3551_4_5_2_g722_samples_at_16_khz_on_an_8000_clock() {
        assert_eq!(
            SAMPLE_RATE,
            CLOCK_RATE * u32::try_from(SAMPLES_PER_OCTET).unwrap()
        );
        assert_eq!(
            lotse_core::codec::Codec::G722.sample_rate(),
            Some(SAMPLE_RATE)
        );
        assert_eq!(
            lotse_core::codec::Codec::G722.rtp_clock_rate(),
            Some(CLOCK_RATE)
        );
    }
}
