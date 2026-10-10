//! ITU-T G.711 μ-law (PCMU) and A-law (PCMA): one 8-bit code per sample at
//! 8 kHz, encoded from and decoded to 16-bit linear PCM.
//!
//! Pure Rust and table-free: the segment (exponent) is the position of the
//! highest set bit, the step within it the next four bits. The arithmetic
//! is the one of the reference implementation in the ITU-T Software Tool
//! Library (G.191, `g711.c`): μ-law biases the 14-bit magnitude by 33
//! (132 at 16 bits) and clips at 8158 (32 635), A-law drops to 13 bits and
//! codes the first two segments with the same step. Both decode to the
//! middle of the step, and both invert the code bits on the wire: all bits
//! for μ-law, the even bits (`0x55`) for A-law.
//!
//! Implements ITU-T G.711 (11/88) §2 (A-law, Tables 1a/1b) and §3 (μ-law,
//! Tables 2a/2b), with the RTP payload types of RFC 3551 §4.5.14 and
//! Table 4.

use lotse_core::codec::Codec;

/// The G.711 sample rate, which is also its RTP clock rate
/// (RFC 3551 §4.5.14, Table 4).
pub const SAMPLE_RATE: u32 = 8_000;

/// μ-law's bias at 16 bits: 33 at 14 bits (G.711 §3, Table 2a, the
/// decision value offset), shifted up two bits. Adding it makes every
/// segment start on a power of two.
const MU_BIAS: i32 = 0x84;

/// The largest μ-law magnitude at 16 bits before the bias: 8158 at 14
/// bits (G.711 Table 2a, the last decision value), shifted up two bits.
/// Louder samples take the loudest code.
const MU_CLIP: i32 = 32_635;

/// Which companding law: the two G.711 variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Law {
    /// μ-law, RTP `PCMU` (G.711 §3).
    Mu,
    /// A-law, RTP `PCMA` (G.711 §2).
    A,
}

impl Law {
    /// The law of a G.711 codec descriptor; `None` for any other codec.
    pub const fn of(codec: &Codec) -> Option<Self> {
        match codec {
            Codec::Pcmu => Some(Self::Mu),
            Codec::Pcma => Some(Self::A),
            _ => None,
        }
    }

    /// The codec descriptor of this law.
    pub const fn codec(self) -> Codec {
        match self {
            Self::Mu => Codec::Pcmu,
            Self::A => Codec::Pcma,
        }
    }

    /// The static RTP payload type: 0 for PCMU, 8 for PCMA
    /// (RFC 3551 §6, Table 4).
    pub const fn payload_type(self) -> u8 {
        match self {
            Self::Mu => 0,
            Self::A => 8,
        }
    }

    /// The code of a zero sample: what a gap is filled with.
    pub const fn silence(self) -> u8 {
        match self {
            Self::Mu => 0xff,
            Self::A => 0xd5,
        }
    }

    /// Encodes one 16-bit linear sample.
    pub fn encode(self, sample: i16) -> u8 {
        match self {
            Self::Mu => mu_encode(sample),
            Self::A => a_encode(sample),
        }
    }

    /// Decodes one code to 16-bit linear, the middle of its step.
    pub fn decode(self, code: u8) -> i16 {
        match self {
            Self::Mu => mu_decode(code),
            Self::A => a_decode(code),
        }
    }

    /// Re-encodes a code of law `from` in this law, through linear: the
    /// identity when the laws match.
    pub fn transcode(self, from: Self, code: u8) -> u8 {
        if from == self {
            code
        } else {
            self.encode(from.decode(code))
        }
    }
}

/// The highest set bit of `value`, 0 for 0 or 1.
fn top_bit(value: i32) -> u32 {
    value.checked_ilog2().unwrap_or(0)
}

/// μ-law encode (G.711 §3, Table 2a): sign, a 3-bit segment, a 4-bit step,
/// every bit inverted.
fn mu_encode(sample: i16) -> u8 {
    let pcm = i32::from(sample);
    let sign = if pcm < 0 { 0x80 } else { 0x00 };
    // 132..=32767: segment `s` covers [128·2^s, 256·2^s).
    let magnitude = pcm.saturating_abs().min(MU_CLIP).saturating_add(MU_BIAS);
    let segment = top_bit(magnitude).saturating_sub(7);
    let step = magnitude.wrapping_shr(segment.saturating_add(3)) & 0x0f;
    let segment_bits = u8::try_from(segment).unwrap_or(7).wrapping_shl(4);
    !(sign | segment_bits | u8::try_from(step).unwrap_or(0x0f))
}

/// μ-law decode (G.711 §3, Table 2b).
fn mu_decode(code: u8) -> i16 {
    let code = !code;
    let segment = u32::from(code.wrapping_shr(4) & 0x07);
    let step = i32::from(code & 0x0f);
    // At most (15·8 + 132)·2^7 − 132 = 32 124.
    let magnitude = step
        .wrapping_shl(3)
        .wrapping_add(MU_BIAS)
        .wrapping_shl(segment)
        .wrapping_sub(MU_BIAS);
    let value = if code & 0x80 == 0 {
        magnitude
    } else {
        magnitude.wrapping_neg()
    };
    i16::try_from(value).unwrap_or(0)
}

/// A-law encode (G.711 §2, Table 1a): the 13-bit magnitude (one's
/// complement for negatives), a 3-bit segment, a 4-bit step; the sign bit
/// set for positives, the even bits inverted.
fn a_encode(sample: i16) -> u8 {
    let pcm = i32::from(sample).wrapping_shr(3);
    let (mask, magnitude) = if pcm >= 0 { (0xd5, pcm) } else { (0x55, !pcm) };
    // 0..=4095: segments 0 and 1 share a step of 2, then it doubles.
    let segment = top_bit(magnitude).max(4).saturating_sub(4);
    let step = magnitude.wrapping_shr(segment.max(1)) & 0x0f;
    let segment_bits = u8::try_from(segment).unwrap_or(7).wrapping_shl(4);
    (segment_bits | u8::try_from(step).unwrap_or(0x0f)) ^ mask
}

/// A-law decode (G.711 §2, Table 1b).
fn a_decode(code: u8) -> i16 {
    let code = code ^ 0x55;
    let step = i32::from(code & 0x0f).wrapping_shl(4);
    let segment = u32::from(code.wrapping_shr(4) & 0x07);
    // At most (0xf0 + 0x108)·2^6 = 32 256.
    let magnitude = match segment {
        0 => step.wrapping_add(8),
        _ => step
            .wrapping_add(0x108)
            .wrapping_shl(segment.saturating_sub(1)),
    };
    let value = if code & 0x80 == 0 {
        magnitude.wrapping_neg()
    } else {
        magnitude
    };
    i16::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    const LAWS: [Law; 2] = [Law::Mu, Law::A];

    #[test]
    fn g711_s3_table_2_mu_law_reference_codes() {
        // Zero is the all-ones code, full scale the extremes of the sign.
        assert_eq!(Law::Mu.encode(0), 0xff);
        assert_eq!(Law::Mu.encode(-1), 0x7f, "negative zero");
        assert_eq!(Law::Mu.encode(i16::MAX), 0x80);
        assert_eq!(Law::Mu.encode(i16::MIN), 0x00);
        assert_eq!(Law::Mu.decode(0x80), 32_124);
        assert_eq!(Law::Mu.decode(0x00), -32_124);
        assert_eq!(Law::Mu.decode(0xff), 0);
        assert_eq!(Law::Mu.decode(0x7f), 0);
        // The first step of segment 0 and of segment 1 (Table 2a: decision
        // values 1 and 31 at 14 bits, so 4 and 124 at 16).
        assert_eq!(Law::Mu.decode(0xfe), 8);
        assert_eq!(Law::Mu.decode(0xef), 132);
        assert_eq!(Law::Mu.encode(-132), 0x6f);
    }

    #[test]
    fn g711_s2_table_1_a_law_reference_codes() {
        // Even bits inverted: zero is 0xd5, its negative neighbour 0x55.
        assert_eq!(Law::A.encode(0), 0xd5);
        assert_eq!(Law::A.encode(-1), 0x55);
        assert_eq!(Law::A.encode(i16::MAX), 0xaa);
        assert_eq!(Law::A.encode(i16::MIN), 0x2a);
        assert_eq!(Law::A.decode(0xaa), 32_256);
        assert_eq!(Law::A.decode(0x2a), -32_256);
        assert_eq!(Law::A.decode(0xd5), 8);
        assert_eq!(Law::A.decode(0x55), -8);
        // Segments 0 and 1 share a step (Table 1a): 16 apart at 16 bits.
        assert_eq!(Law::A.decode(0xd4), 24);
        assert_eq!(Law::A.decode(0xc5), 264);
        assert_eq!(Law::A.encode(264), 0xc5);
        assert_eq!(Law::A.encode(-264), 0x45);
    }

    #[test]
    fn g711_every_code_survives_decode_and_encode() {
        for law in LAWS {
            for code in 0..=u8::MAX {
                // μ-law has two zeros; the positive one is canonical.
                let expected = if law == Law::Mu && code == 0x7f {
                    0xff
                } else {
                    code
                };
                assert_eq!(
                    law.encode(law.decode(code)),
                    expected,
                    "{law:?} {code:#04x}"
                );
            }
        }
    }

    #[test]
    fn g711_decoding_is_monotonic_in_the_code() {
        // Positive codes, in increasing magnitude, decode in increasing order.
        let mu: Vec<i16> = (0x80..=0xff_u8).rev().map(|c| Law::Mu.decode(c)).collect();
        assert!(mu.windows(2).all(|w| w[0] < w[1]), "{mu:?}");
        let a: Vec<i16> = (0..0x80_u8)
            .map(|c| Law::A.decode((c | 0x80) ^ 0x55))
            .collect();
        assert!(a.windows(2).all(|w| w[0] < w[1]), "{a:?}");
    }

    #[test]
    fn g711_quantization_error_is_half_a_step() {
        for sample in i16::MIN..=i16::MAX {
            let x = i32::from(sample);
            // μ-law: the step is 1/16 of the biased magnitude's segment,
            // so half of it is at most 1/32 of the magnitude.
            let clipped = x.clamp(-MU_CLIP, MU_CLIP);
            let mu = i32::from(Law::Mu.decode(Law::Mu.encode(sample)));
            assert!(
                (mu - clipped).abs() <= (clipped.abs() + MU_BIAS) / 32,
                "μ {sample}: {mu}"
            );
            // A-law: 13 bits lose up to 7, then half a step of at least 16.
            let a = i32::from(Law::A.decode(Law::A.encode(sample)));
            assert!(
                (a - x).abs() <= (x.abs() / 32).max(8) + 8,
                "A {sample}: {a}"
            );
        }
    }

    #[test]
    fn rfc3551_table_4_payload_types_and_codecs() {
        assert_eq!(Law::Mu.payload_type(), 0);
        assert_eq!(Law::A.payload_type(), 8);
        assert_eq!(SAMPLE_RATE, 8_000);
        for law in LAWS {
            assert_eq!(Law::of(&law.codec()), Some(law));
            assert_eq!(law.encode(0), law.silence());
        }
        assert_eq!(Law::of(&Codec::G722), None);
        assert_eq!(Law::of(&Codec::Opus { channels: 1 }), None);
    }

    #[test]
    fn transcoding_between_laws_goes_through_linear() {
        for code in 0..=u8::MAX {
            assert_eq!(Law::Mu.transcode(Law::Mu, code), code);
            assert_eq!(Law::A.transcode(Law::A, code), code);
            assert_eq!(
                Law::A.transcode(Law::Mu, code),
                Law::A.encode(Law::Mu.decode(code))
            );
        }
        assert_eq!(Law::A.transcode(Law::Mu, 0xff), 0xd5);
        assert_eq!(Law::Mu.transcode(Law::A, 0xaa), 0x80);
    }
}
