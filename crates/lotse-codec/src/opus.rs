//! The Opus encoder at the end of the AAC-LC → Opus chain: 48 kHz PCM in,
//! one RTP-ready Opus packet per 20 ms frame out.
//!
//! Wraps libopus through the `opus` crate's safe API. libopus only ever
//! sees PCM that the Rust decoder and resampler produced, never camera
//! bytes. The encoder runs `RESTRICTED_LOWDELAY` (CELT only, 2.5 ms
//! look-ahead, no in-band FEC) at 32 kbit/s mono or 64 kbit/s stereo.
//!
//! Implements RFC 6716 (the Opus codec; §3.1 TOC byte, §3.2 frame size
//! limit) at the RTP clock rate of RFC 7587 §4.1 (48 kHz).

use std::time::Duration;

use ::opus as libopus;
use bytes::Bytes;

/// The encoder's sample rate: the Opus RTP clock rate is always 48 kHz
/// (RFC 7587 §4.1), so the chain resamples to it before encoding.
pub const SAMPLE_RATE: u32 = 48_000;

/// Samples per channel in one frame at [`SAMPLE_RATE`]: 960, a 20 ms
/// frame (RFC 6716 §2.1.4 allows 2.5, 5, 10, 20, 40 and 60 ms). 20 ms
/// adds at most 10 ms over 10 ms frames, against half the packets per
/// viewer and better coding at the same bitrate. The one place the frame
/// size is chosen: [`FRAME_DURATION`], the RTP timestamp step and the
/// pacer's spacing all follow from it.
pub const FRAME_SAMPLES: usize = 960;

/// [`FRAME_SAMPLES`] at [`SAMPLE_RATE`] as a duration: 20 ms, the media
/// time one packet carries (RFC 7587 §4.2, one frame per packet).
pub const FRAME_DURATION: Duration =
    Duration::from_micros(FRAME_SAMPLES as u64 * 1_000_000 / SAMPLE_RATE as u64);

/// The largest packet the encoder can emit for one frame: the TOC byte
/// plus a frame of at most 1275 bytes (RFC 6716 §3.2.1).
pub const MAX_PACKET: usize = 1276;

/// Why a frame could not be encoded or the encoder not built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpusError {
    /// A channel count other than mono or stereo.
    #[error("{0} channels, the encoder takes 1 or 2")]
    Channels(u8),
    /// A frame that is not exactly [`FRAME_SAMPLES`] per channel of
    /// interleaved samples.
    #[error("{got} samples, a 20 ms frame is {expected}")]
    FrameLength {
        /// Interleaved samples passed in.
        got: usize,
        /// Interleaved samples in one frame for this channel count.
        expected: usize,
    },
    /// libopus refused a call.
    #[error("libopus {function}: {reason}")]
    Library {
        /// The libopus function that failed.
        function: &'static str,
        /// libopus's description of the error code.
        reason: &'static str,
    },
}

impl From<libopus::Error> for OpusError {
    fn from(err: libopus::Error) -> Self {
        Self::Library {
            function: err.function(),
            reason: err.description(),
        }
    }
}

/// One Opus encoder for one derived track. Keeps libopus's state between
/// frames, so frames of one stream go through one encoder in order.
#[derive(Debug)]
pub struct Encoder {
    /// The libopus encoder, configured once in [`Encoder::new`].
    inner: libopus::Encoder,
    /// Interleaved samples in one frame: [`FRAME_SAMPLES`] times the
    /// channel count.
    frame_len: usize,
    /// Samples at 48 kHz the encoder delays its output by (the Opus
    /// pre-skip), which the transcoder subtracts from timestamps.
    lookahead: u32,
}

impl Encoder {
    /// A `RESTRICTED_LOWDELAY` encoder for `channels` (1 or 2) at 48 kHz,
    /// 32 kbit/s per channel.
    pub fn new(channels: u8) -> Result<Self, OpusError> {
        let (layout, bitrate, frame_len) = match channels {
            1 => (libopus::Channels::Mono, 32_000, FRAME_SAMPLES),
            2 => (libopus::Channels::Stereo, 64_000, FRAME_SAMPLES * 2),
            other => return Err(OpusError::Channels(other)),
        };
        let mut inner = libopus::Encoder::new(SAMPLE_RATE, layout, libopus::Application::LowDelay)?;
        inner.set_bitrate(libopus::Bitrate::Bits(bitrate))?;
        let lookahead = u32::try_from(inner.get_lookahead()?).unwrap_or(0);
        Ok(Self {
            inner,
            frame_len,
            lookahead,
        })
    }

    /// Samples at 48 kHz between a PCM sample going in and the same sample
    /// coming out of a decoder: 120 (2.5 ms) in `RESTRICTED_LOWDELAY`.
    pub const fn lookahead(&self) -> u32 {
        self.lookahead
    }

    /// Encodes one 20 ms frame of interleaved PCM in `[-1.0, 1.0]` into one
    /// Opus packet (a TOC byte and one frame, RFC 6716 §3.2.2 code 0).
    pub fn encode(&mut self, pcm: &[f32]) -> Result<Bytes, OpusError> {
        if pcm.len() != self.frame_len {
            return Err(OpusError::FrameLength {
                got: pcm.len(),
                expected: self.frame_len,
            });
        }
        Ok(Bytes::from(self.inner.encode_vec_float(pcm, MAX_PACKET)?))
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

    /// `len` samples of a 1 kHz mono sine at half scale.
    fn sine(len: u16) -> Vec<f32> {
        (0..len)
            .map(|n| (std::f32::consts::TAU * 1000.0 * f32::from(n) / 48_000.0).sin() * 0.5)
            .collect()
    }

    #[test]
    fn rfc6716_s3_1_mono_packets_are_celt_only_fullband_20ms_code_0() {
        let mut enc = Encoder::new(1).unwrap();
        let packet = enc.encode(&vec![0.0; FRAME_SAMPLES]).unwrap();
        let toc = packet[0];
        // Table 2: config 31 is CELT-only, fullband, 20 ms.
        assert_eq!(toc >> 3, 31);
        assert_eq!(toc & 0x04, 0, "s bit: mono");
        assert_eq!(toc & 0x03, 0, "code 0: one frame");
    }

    #[test]
    fn rfc6716_s3_1_stereo_packets_set_the_stereo_bit() {
        let mut enc = Encoder::new(2).unwrap();
        let packet = enc.encode(&vec![0.0; FRAME_SAMPLES * 2]).unwrap();
        assert_eq!(packet[0] >> 3, 31);
        assert_eq!(packet[0] & 0x04, 0x04, "s bit: stereo");
    }

    #[test]
    fn bitrate_is_32_kbits_per_channel() {
        let mut mono = Encoder::new(1).unwrap();
        assert_eq!(
            mono.inner.get_bitrate().unwrap(),
            libopus::Bitrate::Bits(32_000)
        );
        let mut stereo = Encoder::new(2).unwrap();
        assert_eq!(
            stereo.inner.get_bitrate().unwrap(),
            libopus::Bitrate::Bits(64_000)
        );
    }

    #[test]
    fn restricted_low_delay_looks_ahead_2_5_ms() {
        assert_eq!(Encoder::new(1).unwrap().lookahead(), 120);
        assert_eq!(Encoder::new(2).unwrap().lookahead(), 120);
    }

    #[test]
    fn a_sine_survives_the_round_trip_after_the_lookahead() {
        let input = sine(20 * 960);
        let mut enc = Encoder::new(1).unwrap();
        let mut dec = libopus::Decoder::new(SAMPLE_RATE, libopus::Channels::Mono).unwrap();
        let mut output = vec![0.0f32; input.len()];
        for (pcm, out) in input
            .chunks(FRAME_SAMPLES)
            .zip(output.chunks_mut(FRAME_SAMPLES))
        {
            let packet = enc.encode(pcm).unwrap();
            assert!(packet.len() <= MAX_PACKET);
            assert_eq!(
                dec.decode_float(&packet, out, false).unwrap(),
                FRAME_SAMPLES
            );
        }
        // Skip the first frames (encoder start-up), align by the lookahead,
        // and compare: CELT at 32 kbit/s keeps a pure tone well above 20 dB.
        let delay = enc.lookahead() as usize;
        let start = FRAME_SAMPLES * 4;
        let (mut signal, mut noise) = (0.0f64, 0.0f64);
        for n in start..input.len() - delay {
            let (x, y) = (f64::from(input[n]), f64::from(output[n + delay]));
            signal = x.mul_add(x, signal);
            noise = (x - y).mul_add(x - y, noise);
        }
        let snr = 10.0 * (signal / noise).log10();
        assert!(snr > 20.0, "SNR {snr:.1} dB");
    }

    #[test]
    fn only_mono_and_stereo() {
        assert_eq!(Encoder::new(0).unwrap_err(), OpusError::Channels(0));
        assert_eq!(Encoder::new(3).unwrap_err(), OpusError::Channels(3));
    }

    #[test]
    fn rfc6716_s2_1_4_a_frame_is_20_ms_960_samples_at_48_khz() {
        assert_eq!(FRAME_SAMPLES, 960);
        assert_eq!(FRAME_DURATION, Duration::from_millis(20));
        assert_eq!(
            FRAME_DURATION.as_micros() * u128::from(SAMPLE_RATE),
            FRAME_SAMPLES as u128 * 1_000_000,
            "no rounding"
        );
    }

    #[test]
    fn a_frame_must_be_exactly_20_ms() {
        let mut mono = Encoder::new(1).unwrap();
        assert_eq!(
            mono.encode(&[0.0; FRAME_SAMPLES - 1]).unwrap_err(),
            OpusError::FrameLength {
                got: FRAME_SAMPLES - 1,
                expected: FRAME_SAMPLES
            }
        );
        let mut stereo = Encoder::new(2).unwrap();
        assert_eq!(
            stereo.encode(&[0.0; FRAME_SAMPLES]).unwrap_err(),
            OpusError::FrameLength {
                got: FRAME_SAMPLES,
                expected: FRAME_SAMPLES * 2
            }
        );
    }

    #[test]
    fn library_errors_keep_the_function_and_reason() {
        // 12 345 Hz is not an Opus rate, so libopus refuses it.
        let err = OpusError::from(
            libopus::Encoder::new(
                12_345,
                libopus::Channels::Mono,
                libopus::Application::LowDelay,
            )
            .unwrap_err(),
        );
        assert_eq!(
            err,
            OpusError::Library {
                function: "opus_encoder_create",
                reason: "invalid argument"
            }
        );
        assert_eq!(
            err.to_string(),
            "libopus opus_encoder_create: invalid argument"
        );
    }

    #[test]
    fn errors_say_what_was_wrong() {
        assert_eq!(
            OpusError::Channels(3).to_string(),
            "3 channels, the encoder takes 1 or 2"
        );
        assert_eq!(
            OpusError::FrameLength {
                got: 959,
                expected: 960
            }
            .to_string(),
            "959 samples, a 20 ms frame is 960"
        );
    }
}
