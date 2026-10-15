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
//! A code goes from one law to the other by G.711's conversion tables,
//! not by a decode and an encode: through linear, 44 of the 256 μ-law
//! codes and 32 of the A-law ones land one step off the tables.
//!
//! Implements ITU-T G.711 (11/88) §2 (A-law, Tables 1a/1b), §3 (μ-law,
//! Tables 2a/2b) and the conversions between them (Table 3, μ-law to
//! A-law; Table 4, A-law to μ-law), with the RTP payload types of
//! RFC 3551 §4.5.14 and Table 4.

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

/// G.711 Table 3, μ-law to A-law: the A-law magnitude of each μ-law one.
/// A magnitude is a code's seven bits after its sign, the transmission
/// inversion undone (all bits for μ-law, the even ones for A-law): the
/// segment, then the step, 0 the quietest. The sign carries over.
#[rustfmt::skip]
const MU_TO_A: [u8; 128] = [
      0,   0,   1,   1,   2,   2,   3,   3,   4,   4,   5,   5,   6,   6,   7,   7,
      8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,
     24,  26,  28,  30,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,
     45,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,
     63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,
     79,  81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,
     96,  97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
];

/// G.711 Table 4, A-law to μ-law: the μ-law magnitude of each A-law one,
/// magnitudes as in [`MU_TO_A`].
#[rustfmt::skip]
const A_TO_MU: [u8; 128] = [
      1,   3,   5,   7,   9,  11,  13,  15,  16,  17,  18,  19,  20,  21,  22,  23,
     24,  25,  26,  27,  28,  29,  30,  31,  32,  32,  33,  33,  34,  34,  35,  35,
     36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  48,  49,  49,
     50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  64,
     65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,
     80,  81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,
     96,  97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
];

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

    /// Converts a code of law `from` to this law by G.711's conversion
    /// tables (Table 3, μ-law to A-law; Table 4, A-law to μ-law), sign
    /// kept: the identity when the laws match. As transmitted, the sign
    /// bit is set for a positive code in both laws; the magnitude bits are
    /// inverted, all of them in μ-law and the even ones in A-law.
    pub fn transcode(self, from: Self, code: u8) -> u8 {
        let positive = code & 0x80 != 0;
        match (from, self) {
            (Self::Mu, Self::A) => {
                let magnitude = convert(&MU_TO_A, !code & 0x7f);
                magnitude ^ if positive { 0xd5 } else { 0x55 }
            }
            (Self::A, Self::Mu) => {
                let magnitude = convert(&A_TO_MU, (code ^ 0x55) & 0x7f);
                magnitude ^ if positive { 0xff } else { 0x7f }
            }
            (Self::Mu, Self::Mu) | (Self::A, Self::A) => code,
        }
    }
}

/// The entry of a conversion table for a 7-bit `magnitude`; every one has
/// an entry, so the fallback is never taken.
fn convert(table: &[u8; 128], magnitude: u8) -> u8 {
    table.get(usize::from(magnitude)).copied().unwrap_or(0)
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

    /// G.711 Table 3 (μ-law to A-law) over every code as transmitted,
    /// from spandsp 0.0.6 (`ulaw_to_alaw`, "copied from the CCITT G.711
    /// specification"), whose entries match the Sun reference `g711.c`
    /// tables with their published corrections.
    #[rustfmt::skip]
    const TABLE_3: [u8; 256] = [
        0x2a, 0x2b, 0x28, 0x29, 0x2e, 0x2f, 0x2c, 0x2d, 0x22, 0x23, 0x20, 0x21, 0x26, 0x27, 0x24, 0x25,
        0x3a, 0x3b, 0x38, 0x39, 0x3e, 0x3f, 0x3c, 0x3d, 0x32, 0x33, 0x30, 0x31, 0x36, 0x37, 0x34, 0x35,
        0x0a, 0x0b, 0x08, 0x09, 0x0e, 0x0f, 0x0c, 0x0d, 0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x1a,
        0x1b, 0x18, 0x19, 0x1e, 0x1f, 0x1c, 0x1d, 0x12, 0x13, 0x10, 0x11, 0x16, 0x17, 0x14, 0x15, 0x6a,
        0x68, 0x69, 0x6e, 0x6f, 0x6c, 0x6d, 0x62, 0x63, 0x60, 0x61, 0x66, 0x67, 0x64, 0x65, 0x7a, 0x78,
        0x7e, 0x7f, 0x7c, 0x7d, 0x72, 0x73, 0x70, 0x71, 0x76, 0x77, 0x74, 0x75, 0x4b, 0x49, 0x4f, 0x4d,
        0x42, 0x43, 0x40, 0x41, 0x46, 0x47, 0x44, 0x45, 0x5a, 0x5b, 0x58, 0x59, 0x5e, 0x5f, 0x5c, 0x5d,
        0x52, 0x52, 0x53, 0x53, 0x50, 0x50, 0x51, 0x51, 0x56, 0x56, 0x57, 0x57, 0x54, 0x54, 0x55, 0x55,
        0xaa, 0xab, 0xa8, 0xa9, 0xae, 0xaf, 0xac, 0xad, 0xa2, 0xa3, 0xa0, 0xa1, 0xa6, 0xa7, 0xa4, 0xa5,
        0xba, 0xbb, 0xb8, 0xb9, 0xbe, 0xbf, 0xbc, 0xbd, 0xb2, 0xb3, 0xb0, 0xb1, 0xb6, 0xb7, 0xb4, 0xb5,
        0x8a, 0x8b, 0x88, 0x89, 0x8e, 0x8f, 0x8c, 0x8d, 0x82, 0x83, 0x80, 0x81, 0x86, 0x87, 0x84, 0x9a,
        0x9b, 0x98, 0x99, 0x9e, 0x9f, 0x9c, 0x9d, 0x92, 0x93, 0x90, 0x91, 0x96, 0x97, 0x94, 0x95, 0xea,
        0xe8, 0xe9, 0xee, 0xef, 0xec, 0xed, 0xe2, 0xe3, 0xe0, 0xe1, 0xe6, 0xe7, 0xe4, 0xe5, 0xfa, 0xf8,
        0xfe, 0xff, 0xfc, 0xfd, 0xf2, 0xf3, 0xf0, 0xf1, 0xf6, 0xf7, 0xf4, 0xf5, 0xcb, 0xc9, 0xcf, 0xcd,
        0xc2, 0xc3, 0xc0, 0xc1, 0xc6, 0xc7, 0xc4, 0xc5, 0xda, 0xdb, 0xd8, 0xd9, 0xde, 0xdf, 0xdc, 0xdd,
        0xd2, 0xd2, 0xd3, 0xd3, 0xd0, 0xd0, 0xd1, 0xd1, 0xd6, 0xd6, 0xd7, 0xd7, 0xd4, 0xd4, 0xd5, 0xd5,
    ];

    /// G.711 Table 4 (A-law to μ-law) over every code as transmitted,
    /// from the same sources as [`TABLE_3`] (`alaw_to_ulaw`).
    #[rustfmt::skip]
    const TABLE_4: [u8; 256] = [
        0x2a, 0x2b, 0x28, 0x29, 0x2e, 0x2f, 0x2c, 0x2d, 0x22, 0x23, 0x20, 0x21, 0x26, 0x27, 0x24, 0x25,
        0x39, 0x3a, 0x37, 0x38, 0x3d, 0x3e, 0x3b, 0x3c, 0x31, 0x32, 0x2f, 0x30, 0x35, 0x36, 0x33, 0x34,
        0x0a, 0x0b, 0x08, 0x09, 0x0e, 0x0f, 0x0c, 0x0d, 0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05,
        0x1a, 0x1b, 0x18, 0x19, 0x1e, 0x1f, 0x1c, 0x1d, 0x12, 0x13, 0x10, 0x11, 0x16, 0x17, 0x14, 0x15,
        0x62, 0x63, 0x60, 0x61, 0x66, 0x67, 0x64, 0x65, 0x5d, 0x5d, 0x5c, 0x5c, 0x5f, 0x5f, 0x5e, 0x5e,
        0x74, 0x76, 0x70, 0x72, 0x7c, 0x7e, 0x78, 0x7a, 0x6a, 0x6b, 0x68, 0x69, 0x6e, 0x6f, 0x6c, 0x6d,
        0x48, 0x49, 0x46, 0x47, 0x4c, 0x4d, 0x4a, 0x4b, 0x40, 0x41, 0x3f, 0x3f, 0x44, 0x45, 0x42, 0x43,
        0x56, 0x57, 0x54, 0x55, 0x5a, 0x5b, 0x58, 0x59, 0x4f, 0x4f, 0x4e, 0x4e, 0x52, 0x53, 0x50, 0x51,
        0xaa, 0xab, 0xa8, 0xa9, 0xae, 0xaf, 0xac, 0xad, 0xa2, 0xa3, 0xa0, 0xa1, 0xa6, 0xa7, 0xa4, 0xa5,
        0xb9, 0xba, 0xb7, 0xb8, 0xbd, 0xbe, 0xbb, 0xbc, 0xb1, 0xb2, 0xaf, 0xb0, 0xb5, 0xb6, 0xb3, 0xb4,
        0x8a, 0x8b, 0x88, 0x89, 0x8e, 0x8f, 0x8c, 0x8d, 0x82, 0x83, 0x80, 0x81, 0x86, 0x87, 0x84, 0x85,
        0x9a, 0x9b, 0x98, 0x99, 0x9e, 0x9f, 0x9c, 0x9d, 0x92, 0x93, 0x90, 0x91, 0x96, 0x97, 0x94, 0x95,
        0xe2, 0xe3, 0xe0, 0xe1, 0xe6, 0xe7, 0xe4, 0xe5, 0xdd, 0xdd, 0xdc, 0xdc, 0xdf, 0xdf, 0xde, 0xde,
        0xf4, 0xf6, 0xf0, 0xf2, 0xfc, 0xfe, 0xf8, 0xfa, 0xea, 0xeb, 0xe8, 0xe9, 0xee, 0xef, 0xec, 0xed,
        0xc8, 0xc9, 0xc6, 0xc7, 0xcc, 0xcd, 0xca, 0xcb, 0xc0, 0xc1, 0xbf, 0xbf, 0xc4, 0xc5, 0xc2, 0xc3,
        0xd6, 0xd7, 0xd4, 0xd5, 0xda, 0xdb, 0xd8, 0xd9, 0xcf, 0xcf, 0xce, 0xce, 0xd2, 0xd3, 0xd0, 0xd1,
    ];

    #[test]
    fn g711_tables_3_and_4_convert_every_code_between_the_laws() {
        for code in 0..=u8::MAX {
            let index = usize::from(code);
            assert_eq!(Law::Mu.transcode(Law::Mu, code), code);
            assert_eq!(Law::A.transcode(Law::A, code), code);
            assert_eq!(
                Law::A.transcode(Law::Mu, code),
                TABLE_3[index],
                "Table 3, μ {code:#04x}"
            );
            assert_eq!(
                Law::Mu.transcode(Law::A, code),
                TABLE_4[index],
                "Table 4, A {code:#04x}"
            );
        }
        // Silence: μ-law's zeros take A-law's smallest step of their sign,
        // and A-law's smallest positive step is μ-law's second.
        assert_eq!(Law::A.transcode(Law::Mu, 0xff), 0xd5);
        assert_eq!(Law::A.transcode(Law::Mu, 0x7f), 0x55);
        assert_eq!(Law::Mu.transcode(Law::A, 0xd5), 0xfe);
        assert_eq!(Law::Mu.transcode(Law::A, 0x55), 0x7e);
        // Full scale to full scale, both signs.
        assert_eq!(Law::A.transcode(Law::Mu, 0x80), 0xaa);
        assert_eq!(Law::A.transcode(Law::Mu, 0x00), 0x2a);
        assert_eq!(Law::Mu.transcode(Law::A, 0xaa), 0x80);
        assert_eq!(Law::Mu.transcode(Law::A, 0x2a), 0x00);
    }

    #[test]
    fn g711_tables_3_and_4_differ_from_the_path_through_linear() {
        // μ-law's loudest step of segment 5 (7932 at 16 bits) sits 4 below
        // the A-law decision value between steps 14 and 15 of its segment
        // 5: linear takes step 14, Table 3 step 15.
        assert_eq!(Law::A.encode(Law::Mu.decode(0x20)), 0x0b);
        assert_eq!(Law::A.transcode(Law::Mu, 0x20), 0x0a);
        // μ-law's negative zero stays negative by Table 3; through linear
        // it turns positive.
        assert_eq!(Law::A.encode(Law::Mu.decode(0x7f)), 0xd5);
        assert_eq!(Law::A.transcode(Law::Mu, 0x7f), 0x55);
        // Table 4 takes A-law's segment 5 one step louder than linear does.
        assert_eq!(Law::Mu.encode(Law::A.decode(0x80)), 0xa9);
        assert_eq!(Law::Mu.transcode(Law::A, 0x80), 0xaa);
    }

    #[test]
    fn g711_conversion_tables_are_monotonic_and_reach_full_scale() {
        assert!(MU_TO_A.windows(2).all(|w| w[0] <= w[1]));
        assert!(A_TO_MU.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(MU_TO_A[127], 127);
        assert_eq!(A_TO_MU[127], 127);
        assert_eq!(convert(&MU_TO_A, 0x7f), 127);
    }
}
