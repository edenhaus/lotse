//! G.722 for tests: this crate's decoder and transcoder tests and, behind
//! the `test-util` feature, other crates' clip tests, the benchmarks and
//! the fuzz target.
//!
//! [`SWEEP_NOISE`] is half a second at 16 kHz, mono: a sine sweeping from
//! 100 Hz up at 0.9 of full scale for 0.25 s, then white noise at 0.7,
//! encoded by ffmpeg 9.0.2's `g722` encoder on 2026-10-23
//! (`ffmpeg -f lavfi -i "aevalsrc=0.9*sin(2*PI*(100+7000*t)*t)*lt(t\,0.25)
//! +0.7*(2*random(0)-1)*gte(t\,0.25):s=16000:d=0.5" -c:a g722 -f g722`).
//! [`SWEEP_NOISE_REFERENCE`] is what the ITU-T reference decoder made of
//! it: the ITU-T Software Tool Library's (G.191) `g722demo -dec -mode 1`,
//! built from openitu/STL at cbacae9 (2026-06-10), its octets fed as one
//! 16-bit word each; ffmpeg 9.0.2 decodes the same samples. [`encode`]
//! makes G.722 of any PCM with the decoder crate's encoder.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use nanoaudio_g722::G722Encoder;

use super::SAMPLE_RATE;

/// Half a second of a sweep, then noise, G.722 at 64 kbit/s.
pub const SWEEP_NOISE: &[u8] = include_bytes!("testdata/sweep_noise.g722");

/// The ITU-T reference decoder's 16 kHz output for [`SWEEP_NOISE`],
/// 16-bit little-endian.
pub const SWEEP_NOISE_REFERENCE: &[u8] = include_bytes!("testdata/sweep_noise_itu.s16le");

/// `samples` of a `frequency` Hz sine at a quarter of full scale, at
/// [`SAMPLE_RATE`].
pub fn tone(frequency: u32, samples: usize) -> Vec<i16> {
    (0..samples)
        .map(|index| {
            let phase = std::f64::consts::TAU * f64::from(frequency) * index as f64
                / f64::from(SAMPLE_RATE);
            (8_192.0 * phase.sin()) as i16
        })
        .collect()
}

/// `pcm` at [`SAMPLE_RATE`] as G.722 at 64 kbit/s, from the reset state;
/// an odd last sample is dropped.
pub fn encode(pcm: &[i16]) -> Vec<u8> {
    let mut encoder = G722Encoder::new();
    pcm.as_chunks::<2>()
        .0
        .iter()
        .map(|[first, second]| encoder.encode_pair(*first, *second))
        .collect()
}
