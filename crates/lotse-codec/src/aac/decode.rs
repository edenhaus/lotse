//! The AAC-LC decoder at the head of the AAC-LC → Opus chain: one raw AAC
//! frame in, 1024 samples per channel of interleaved `f32` PCM out.
//!
//! Wraps symphonia's pure-Rust AAC-LC decoder (MPL-2.0). It runs on camera
//! bytes in the worker; the `aac_decode` fuzz target drives it. The
//! configuration is checked by [`super::parse_config`] first, so only what
//! symphonia can decode reaches it.
//!
//! Implements ISO/IEC 14496-3 §4 (AAC-LC `raw_data_block`); the output of a
//! frame is the overlap-add of its MDCT with the previous one (§4.6.11.3.1),
//! so it describes the samples one frame earlier: [`DECODER_DELAY`].

use symphonia_codec_aac::AacDecoder as Inner;
use symphonia_core::codecs::audio::well_known::CODEC_ID_AAC;
use symphonia_core::codecs::audio::{AudioCodecParameters, AudioDecoder, AudioDecoderOptions};
use symphonia_core::packet::PacketRef;
use symphonia_core::units::{Duration, Timestamp};

use super::config::{ConfigError, FRAME_SAMPLES, parse_config};

/// Samples per channel between a PCM sample going into an AAC-LC encoder's
/// MDCT and the same sample leaving the decoder: one frame of overlap-add
/// (ISO/IEC 14496-3 §4.6.11.3.1). The camera encoder's own priming is on
/// the camera's side of its timestamps and not ours to guess.
pub const DECODER_DELAY: u32 = FRAME_SAMPLES;

/// Why the decoder could not be built or a frame not decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The configuration is not decodable AAC-LC.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// symphonia refused the configuration or a frame.
    #[error("AAC decoder: {0}")]
    Decoder(String),
}

/// One AAC-LC decoder for one track. Keeps the overlap between frames, so
/// frames of one stream go through one decoder in order.
pub struct AacDecoder {
    /// symphonia's decoder.
    inner: Inner,
    /// 1 or 2.
    channels: u8,
    /// The sampling rate in Hz.
    sample_rate: u32,
    /// The last frame's interleaved PCM.
    pcm: Vec<f32>,
}

impl std::fmt::Debug for AacDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AacDecoder")
            .field("channels", &self.channels)
            .field("sample_rate", &self.sample_rate)
            .finish_non_exhaustive()
    }
}

impl AacDecoder {
    /// A decoder for the `AudioSpecificConfig` `config`.
    pub fn new(config: &[u8]) -> Result<Self, DecodeError> {
        let parsed = parse_config(config)?;
        let mut params = AudioCodecParameters::new();
        params
            .for_codec(CODEC_ID_AAC)
            .with_extra_data(config.into());
        let inner = Inner::try_new(&params, &AudioDecoderOptions::default())
            .map_err(|err| DecodeError::Decoder(err.to_string()))?;
        Ok(Self {
            inner,
            channels: parsed.channels,
            sample_rate: parsed.sample_rate,
            pcm: Vec::new(),
        })
    }

    /// 1 or 2.
    pub const fn channels(&self) -> u8 {
        self.channels
    }

    /// The sampling rate in Hz.
    pub const fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Decodes one raw AAC frame into interleaved PCM in `[-1.0, 1.0]`,
    /// [`FRAME_SAMPLES`] per channel, describing the samples
    /// [`DECODER_DELAY`] before the frame's timestamp. A frame that does
    /// not decode leaves the decoder usable for the next.
    pub fn decode(&mut self, frame: &[u8]) -> Result<&[f32], DecodeError> {
        let packet = PacketRef::new(
            0,
            Timestamp::new(0),
            Duration::new(u64::from(FRAME_SAMPLES)),
            frame,
        );
        let decoded = self
            .inner
            .decode_ref(&packet)
            .map_err(|err| DecodeError::Decoder(err.to_string()))?;
        // symphonia renders every frame whole, silence where a channel
        // element is missing.
        decoded.copy_to_vec_interleaved(&mut self.pcm);
        Ok(&self.pcm)
    }

    /// Forgets the overlap, for a new epoch: the next frame starts clean.
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::suboptimal_flops,
        reason = "test code; signal math in floats"
    )]

    use super::*;
    use crate::aac::test_data::{
        CONFIG_16K_MONO, CONFIG_48K_MONO, SINE_16K_MONO, SINE_48K_MONO, frames,
    };

    /// Decodes every frame of a fixture into one PCM stream.
    fn decode_all(config: &[u8], adts: &[u8]) -> Vec<f32> {
        let mut decoder = AacDecoder::new(config).unwrap();
        let mut pcm = Vec::new();
        for frame in frames(adts) {
            pcm.extend_from_slice(decoder.decode(frame).unwrap());
        }
        pcm
    }

    /// The first sample index whose magnitude exceeds `level`.
    fn onset(pcm: &[f32], level: f32) -> usize {
        pcm.iter().position(|s| s.abs() > level).unwrap()
    }

    /// Estimates the frequency of `pcm` at `rate` from its zero crossings.
    fn frequency(pcm: &[f32], rate: u32) -> f64 {
        let crossings = pcm.windows(2).filter(|w| w[0] <= 0.0 && w[1] > 0.0).count();
        crossings as f64 * f64::from(rate) / pcm.len() as f64
    }

    #[test]
    fn iso14496_3_4_a_sine_decodes_to_a_sine_of_the_same_pitch() {
        for (config, adts, rate) in [
            (&CONFIG_16K_MONO, SINE_16K_MONO, 16_000),
            (&CONFIG_48K_MONO, SINE_48K_MONO, 48_000),
        ] {
            let pcm = decode_all(config, adts);
            let start = onset(&pcm, 0.1) + rate as usize / 10;
            let steady = &pcm[start..start + rate as usize / 2];
            let f = frequency(steady, rate);
            assert!((f - 1000.0).abs() < 10.0, "{rate} Hz: {f:.1} Hz");
            let peak = steady.iter().fold(0.0_f32, |m, s| m.max(s.abs()));
            assert!((0.4..0.6).contains(&peak), "{rate} Hz: peak {peak}");
        }
    }

    #[test]
    fn iso14496_3_4_6_11_3_1_output_lags_the_input_by_the_overlap() {
        // afconvert primes with 2112 samples (Apple's documented AAC
        // priming), of which the decoder's overlap is one frame: the tone
        // starts at 2112 in the output.
        let pcm = decode_all(&CONFIG_16K_MONO, SINE_16K_MONO);
        let start = onset(&pcm, 0.05);
        assert!((2080..=2140).contains(&start), "onset {start}");
        assert_eq!(DECODER_DELAY, 1024);
    }

    #[test]
    fn reset_forgets_the_overlap() {
        let sine = frames(SINE_16K_MONO);
        let mut fresh = AacDecoder::new(&CONFIG_16K_MONO).unwrap();
        let clean = fresh.decode(sine[8]).unwrap().to_vec();
        let mut decoder = AacDecoder::new(&CONFIG_16K_MONO).unwrap();
        for frame in &sine[..8] {
            decoder.decode(frame).unwrap();
        }
        let _ = decoder.decode(sine[7]).unwrap();
        // Without a reset the previous frame's tail is mixed in.
        assert_ne!(decoder.decode(sine[8]).unwrap(), &clean[..]);
        decoder.reset();
        assert_eq!(decoder.decode(sine[8]).unwrap(), &clean[..]);
    }

    #[test]
    fn stereo_frames_interleave_two_channels() {
        let mut decoder = AacDecoder::new(&[0x11, 0x90]).unwrap();
        assert_eq!((decoder.channels(), decoder.sample_rate()), (2, 48_000));
        assert_eq!(decoder.decode(&[0xe0]).unwrap().len(), 2048);
    }

    #[test]
    fn a_frame_is_1024_samples_per_channel() {
        let mut decoder = AacDecoder::new(&CONFIG_16K_MONO).unwrap();
        assert_eq!((decoder.channels(), decoder.sample_rate()), (1, 16_000));
        let first = frames(SINE_16K_MONO)[0];
        assert_eq!(decoder.decode(first).unwrap().len(), 1024);
    }

    #[test]
    fn a_broken_frame_is_an_error_and_the_decoder_carries_on() {
        let mut decoder = AacDecoder::new(&CONFIG_16K_MONO).unwrap();
        // ID_CCE (coupling channel element) is refused by the decoder.
        assert!(matches!(
            decoder.decode(&[0x40, 0x00, 0x00]),
            Err(DecodeError::Decoder(_))
        ));
        // ID_END alone decodes to a frame of silence.
        assert!(decoder.decode(&[0xe0]).unwrap().iter().all(|s| *s == 0.0));
        decoder.reset();
        for frame in frames(SINE_16K_MONO) {
            assert_eq!(decoder.decode(frame).unwrap().len(), 1024);
        }
    }

    #[test]
    fn undecodable_configs_are_refused() {
        assert_eq!(
            AacDecoder::new(&[0x2b, 0x08]).unwrap_err(),
            DecodeError::Config(ConfigError::HighEfficiency(5))
        );
        assert_eq!(
            DecodeError::Config(ConfigError::HighEfficiency(5)).to_string(),
            "HE-AAC (audio object type 5) is not supported"
        );
        assert_eq!(
            DecodeError::Decoder("x".into()).to_string(),
            "AAC decoder: x"
        );
        assert!(format!("{:?}", AacDecoder::new(&CONFIG_16K_MONO).unwrap()).contains("16000"));
    }
}
