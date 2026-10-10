//! The resampler of the AAC-LC → Opus chain: one decoded frame of PCM at
//! the camera's rate in, the same span at Opus's 48 kHz out.
//!
//! Wraps rubato's windowed-sinc resampler with a short filter (64 taps,
//! Blackman-Harris², automatic cutoff), the lowest delay that keeps a
//! tone above 40 dB SNR at every AAC rate: half the filter, 32 input
//! samples, so 4 ms at 8 kHz and under 1 ms at 44.1 kHz. It
//! takes exactly one decoded frame per call, so nothing waits for input to
//! pile up. At 48 kHz it passes the PCM through untouched.

use std::ops::RangeInclusive;

use rubato::audioadapter_buffers::direct::InterleavedSlice;
use rubato::{
    Async, FixedAsync, Resampler as _, SincInterpolationParameters, SincInterpolationType,
    WindowFunction,
};

/// The rate every stream is resampled to: Opus's RTP clock (RFC 7587 §4.1).
pub const TARGET_RATE: u32 = crate::opus::SAMPLE_RATE;

/// The input rates the resampler takes: the span of ISO/IEC 14496-3
/// Table 1.18, 7.35 to 96 kHz. A config may state any other frequency
/// explicitly (§1.6.3.3); it is refused before rubato sizes its buffers
/// by the ratio, which at 1 Hz would be 48 000 times the chunk.
pub const RATES: RangeInclusive<u32> = 7_350..=96_000;

/// Taps of the sinc filter: its delay is half of it, in input samples.
const SINC_LEN: usize = 64;

/// Why the resampler could not be built or a chunk not resampled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResampleError {
    /// An input rate outside [`RATES`].
    #[error("{0} Hz is outside the resampler's 7350 to 96000 Hz")]
    Rate(u32),
    /// rubato refused the parameters or a buffer.
    #[error("resampler: {0}")]
    Library(String),
    /// A chunk that is not exactly one frame of interleaved samples.
    #[error("{got} samples, a chunk is {expected}")]
    ChunkLength {
        /// Interleaved samples passed in.
        got: usize,
        /// Interleaved samples in one chunk.
        expected: usize,
    },
}

/// One resampler for one derived track. Keeps the filter's history between
/// chunks, so chunks of one stream go through one resampler in order.
pub struct Resampler {
    /// rubato's resampler; `None` at 48 kHz, where PCM passes through.
    inner: Option<Async<f32>>,
    /// Channels, interleaved.
    channels: usize,
    /// Samples per channel in one chunk.
    chunk: usize,
    /// The output of the last chunk, interleaved.
    out: Vec<f32>,
}

impl std::fmt::Debug for Resampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resampler")
            .field("resampling", &self.inner.is_some())
            .field("channels", &self.channels)
            .field("chunk", &self.chunk)
            .finish_non_exhaustive()
    }
}

/// A rubato refusal as [`ResampleError::Library`].
fn library_error(err: impl std::fmt::Display) -> ResampleError {
    ResampleError::Library(err.to_string())
}

impl Resampler {
    /// A resampler from `from_rate` to [`TARGET_RATE`] for `channels`
    /// interleaved channels, taking `chunk` samples per channel per call.
    pub fn new(from_rate: u32, channels: u8, chunk: usize) -> Result<Self, ResampleError> {
        if !RATES.contains(&from_rate) {
            return Err(ResampleError::Rate(from_rate));
        }
        let channels = usize::from(channels);
        if from_rate == TARGET_RATE {
            return Ok(Self {
                inner: None,
                channels,
                chunk,
                out: Vec::new(),
            });
        }
        let params = SincInterpolationParameters::new(SINC_LEN, WindowFunction::BlackmanHarris2)
            .oversampling_factor(128)
            .interpolation(SincInterpolationType::Linear);
        let ratio = f64::from(TARGET_RATE) / f64::from(from_rate);
        let inner = Async::<f32>::new_sinc(ratio, 1.0, &params, chunk, channels, FixedAsync::Input)
            .map_err(library_error)?;
        let out = vec![0.0; inner.output_frames_max().saturating_mul(channels)];
        Ok(Self {
            inner: Some(inner),
            channels,
            chunk,
            out,
        })
    }

    /// Samples at 48 kHz between a sample going in and the same sample
    /// coming out: the filter's half length, 0 when passing through.
    pub fn delay(&self) -> u32 {
        self.inner.as_ref().map_or(0, |inner| {
            u32::try_from(inner.output_delay()).unwrap_or(u32::MAX)
        })
    }

    /// Forgets the filter's history, for a new timeline: the next chunk
    /// comes out as it would from a new resampler, delay included.
    pub fn reset(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.reset();
        }
    }

    /// Resamples one chunk of interleaved PCM. The output length varies by
    /// a sample between calls when the ratio is not an integer.
    pub fn process<'a>(&'a mut self, pcm: &'a [f32]) -> Result<&'a [f32], ResampleError> {
        let expected = self.chunk.saturating_mul(self.channels);
        if pcm.len() != expected {
            return Err(ResampleError::ChunkLength {
                got: pcm.len(),
                expected,
            });
        }
        let Some(inner) = self.inner.as_mut() else {
            return Ok(pcm);
        };
        let frames_out = self.out.len().checked_div(self.channels).unwrap_or(0);
        let input = InterleavedSlice::new(pcm, self.channels, self.chunk).map_err(library_error)?;
        let mut output = InterleavedSlice::new_mut(&mut self.out, self.channels, frames_out)
            .map_err(library_error)?;
        let (_, written) = inner
            .process_into_buffer(&input, &mut output, None)
            .map_err(library_error)?;
        Ok(self
            .out
            .get(..written.saturating_mul(self.channels))
            .unwrap_or(&[]))
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

    /// `seconds` of a 1 kHz sine at half scale, `channels` interleaved.
    fn sine(rate: u32, channels: usize, frames: usize) -> Vec<f32> {
        (0..frames)
            .flat_map(|n| {
                let x = (std::f64::consts::TAU * 1000.0 * n as f64 / f64::from(rate)).sin() * 0.5;
                std::iter::repeat_n(x as f32, channels)
            })
            .collect()
    }

    /// Resamples `frames` of a sine in chunks of 1024 and returns the
    /// output of channel 0 and the resampler's delay.
    fn run(rate: u32, channels: u8) -> (Vec<f32>, u32) {
        let ch = usize::from(channels);
        let input = sine(rate, ch, 1024 * 40);
        let mut r = Resampler::new(rate, channels, 1024).unwrap();
        let mut out = Vec::new();
        for chunk in input.chunks(1024 * ch) {
            out.extend(r.process(chunk).unwrap().iter().step_by(ch));
        }
        (out, r.delay())
    }

    /// The tone's share of `out` against everything else, in dB: a least
    /// squares fit of a 1 kHz sine over whole periods, whatever its phase.
    fn tone_snr(out: &[f32]) -> f64 {
        let w = std::f64::consts::TAU * 1000.0 / 48_000.0;
        let n = out.len() / 48 * 48;
        let (mut a, mut b) = (0.0, 0.0);
        for (i, y) in out[..n].iter().enumerate() {
            a += f64::from(*y) * (w * i as f64).sin();
            b += f64::from(*y) * (w * i as f64).cos();
        }
        let (a, b) = (2.0 * a / n as f64, 2.0 * b / n as f64);
        let (mut signal, mut noise) = (0.0, 0.0);
        for (i, y) in out[..n].iter().enumerate() {
            let fit = a * (w * i as f64).sin() + b * (w * i as f64).cos();
            signal += fit * fit;
            noise += (f64::from(*y) - fit).powi(2);
        }
        10.0 * (signal / noise).log10()
    }

    #[test]
    fn every_aac_rate_resamples_a_tone_cleanly_to_48_khz() {
        for rate in [8_000, 11_025, 16_000, 22_050, 24_000, 32_000, 44_100] {
            let (out, _) = run(rate, 1);
            // The output spans the input's duration at 48 kHz, give or take
            // the first chunk's rounding.
            let expected = 1024 * 40 * 48_000 / rate as usize;
            assert!(out.len().abs_diff(expected) <= 16, "{rate}: {}", out.len());
            let snr = tone_snr(&out[4_800..out.len() - 4_800]);
            assert!(snr > 40.0, "{rate} Hz: SNR {snr:.1} dB");
        }
    }

    #[test]
    fn the_reported_delay_is_where_an_impulse_comes_out() {
        for rate in [8_000, 16_000, 44_100] {
            let mut input = vec![0.0_f32; 1024 * 4];
            let at = 1024 + 100;
            input[at] = 1.0;
            let mut r = Resampler::new(rate, 1, 1024).unwrap();
            let mut out = Vec::new();
            for chunk in input.chunks(1024) {
                out.extend_from_slice(r.process(chunk).unwrap());
            }
            let peak = out
                .iter()
                .enumerate()
                .max_by(|x, y| x.1.total_cmp(y.1))
                .unwrap()
                .0;
            let ideal = at as f64 * 48_000.0 / f64::from(rate) + f64::from(r.delay());
            assert!(
                (peak as f64 - ideal).abs() <= 2.0,
                "{rate} Hz: peak {peak}, ideal {ideal:.1}"
            );
            // Half the filter, in input samples: 4 ms at 8 kHz at most.
            let delay_ms = u64::from(r.delay()) * 1000 / 48_000;
            assert!(delay_ms <= 4, "{rate} Hz: {delay_ms} ms");
        }
    }

    #[test]
    fn stereo_keeps_both_channels() {
        let input = sine(16_000, 2, 1024);
        let mut r = Resampler::new(16_000, 2, 1024).unwrap();
        let out = r.process(&input).unwrap();
        assert!(out.len().abs_diff(3072 * 2) <= 32, "{}", out.len());
        assert!(
            out.chunks(2)
                .all(|pair| pair[0].to_bits() == pair[1].to_bits())
        );
    }

    #[test]
    fn reset_starts_over_like_a_new_resampler() {
        let input = sine(16_000, 1, 2048);
        let (first, second) = input.split_at(1024);
        let fresh = Resampler::new(16_000, 1, 1024)
            .unwrap()
            .process(second)
            .unwrap()
            .to_vec();
        let mut r = Resampler::new(16_000, 1, 1024).unwrap();
        r.process(first).unwrap();
        // Without a reset the history of the first chunk shapes the second.
        assert_ne!(r.process(second).unwrap(), &fresh[..]);
        r.reset();
        assert_eq!(r.process(second).unwrap(), &fresh[..]);
        let mut passthrough = Resampler::new(48_000, 1, 1024).unwrap();
        passthrough.reset();
        assert_eq!(passthrough.process(second).unwrap(), second);
    }

    #[test]
    fn at_48_khz_pcm_passes_through() {
        let input = sine(48_000, 1, 1024);
        let mut r = Resampler::new(48_000, 1, 1024).unwrap();
        assert_eq!(r.delay(), 0);
        assert_eq!(r.process(&input).unwrap(), &input[..]);
        assert!(format!("{r:?}").contains("resampling: false"));
    }

    #[test]
    fn a_chunk_must_be_exactly_one_frame() {
        let mut r = Resampler::new(16_000, 1, 1024).unwrap();
        assert_eq!(
            r.process(&[0.0; 1000]).unwrap_err(),
            ResampleError::ChunkLength {
                got: 1000,
                expected: 1024
            }
        );
        let mut passthrough = Resampler::new(48_000, 2, 1024).unwrap();
        assert!(passthrough.process(&[0.0; 1024]).is_err());
    }

    #[test]
    fn iso14496_3_table_1_18_rates_only() {
        for rate in [7_350, 96_000] {
            assert!(Resampler::new(rate, 1, 1024).is_ok(), "{rate}");
        }
        for rate in [0, 1, 7_349, 96_001] {
            assert_eq!(
                Resampler::new(rate, 1, 1024).unwrap_err(),
                ResampleError::Rate(rate)
            );
        }
        assert_eq!(
            ResampleError::Rate(1).to_string(),
            "1 Hz is outside the resampler's 7350 to 96000 Hz"
        );
    }

    #[test]
    fn rubato_errors_are_reported() {
        // An empty chunk is no resampler.
        let err = Resampler::new(16_000, 1, 0).unwrap_err();
        assert!(matches!(err, ResampleError::Library(_)), "{err}");
        assert!(err.to_string().starts_with("resampler: "));
        assert_eq!(
            ResampleError::ChunkLength {
                got: 1,
                expected: 2
            }
            .to_string(),
            "1 samples, a chunk is 2"
        );
    }
}
