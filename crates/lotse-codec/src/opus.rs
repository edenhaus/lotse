//! libopus, through the `opus` crate's safe API, at both ends of audio
//! transcoding.
//!
//! The [`Encoder`] ends the AAC-LC → Opus chain: 48 kHz PCM in, one
//! RTP-ready Opus packet per 20 ms frame out. It only ever sees PCM that
//! the Rust decoder and resampler produced, never camera bytes, and runs
//! `RESTRICTED_LOWDELAY` (CELT only, 2.5 ms look-ahead, no in-band FEC) at
//! 32 kbit/s mono or 64 kbit/s stereo.
//!
//! The [`Decoder`] starts the talk-back chain: a browser's Opus packets in,
//! mono PCM out at the rate the chain needs (8 kHz for G.711), which
//! libopus produces itself, band-limited, so no resampler follows it. It
//! parses bytes from an untrusted peer; libopus is fuzzed upstream
//! (OSS-Fuzz) and runs in the camera's sandboxed worker. A lost packet is
//! concealed (packet loss concealment, PLC) instead of waited for.
//!
//! [`packet_samples`] checks a packet's framing before anything decodes
//! it: the talk-back depacketizer refuses a browser's packet that breaks
//! RFC 6716 §3.4 instead of passing it on.
//!
//! Implements RFC 6716 (the Opus codec; §3.1 TOC byte, §3.2 frame
//! packing and size limit, §3.4 packet requirements, §4.4 packet loss
//! concealment) at the RTP clock rate of RFC 7587 §4.1 (48 kHz).

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

/// The longest audio one packet may carry: 120 ms (RFC 6716 §3.2.5), so
/// the most a single decode or concealment call produces.
pub const MAX_PACKET_DURATION: Duration = Duration::from_millis(120);

/// The rates libopus decodes to (RFC 6716 §2: the decoder may run at 8,
/// 12, 16, 24 or 48 kHz whatever the coded bandwidth).
pub const DECODE_RATES: [u32; 5] = [8_000, 12_000, 16_000, 24_000, 48_000];

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
    /// An empty packet, which is no Opus packet (RFC 6716 §3.4 R1: at
    /// least one byte). libopus would conceal it; loss is concealed only
    /// on purpose, through [`Decoder::conceal`].
    #[error("an empty packet is no Opus packet")]
    Empty,
    /// A concealment span that is not a whole number of 2.5 ms steps up
    /// to [`MAX_PACKET_DURATION`] at the decoder's rate (RFC 6716 §4.4).
    #[error("{0} samples cannot be concealed: a multiple of 2.5 ms up to 120 ms")]
    Conceal(usize),
    /// A decode rate libopus does not produce (not in [`DECODE_RATES`]).
    #[error("{0} Hz is not an Opus decode rate")]
    Rate(u32),
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

/// The longest frame a packet may carry: 1275 bytes (RFC 6716 §3.2.1,
/// §3.4 R2).
const MAX_FRAME_BYTES: usize = 1275;

/// [`MAX_PACKET_DURATION`] in samples at [`SAMPLE_RATE`]: 5760.
const MAX_PACKET_SAMPLES: u32 = 5760;

/// Why bytes are no Opus packet: the requirement of RFC 6716 §3.4 they
/// break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    /// No bytes (R1: a packet has at least the TOC byte).
    #[error("an empty packet (RFC 6716 §3.4 R1)")]
    Empty,
    /// A frame longer than 1275 bytes (R2).
    #[error("a frame longer than 1275 bytes (RFC 6716 §3.4 R2)")]
    FrameTooLong,
    /// A code 1 packet whose two equal frames do not split its bytes
    /// (R3).
    #[error("a code 1 packet of an odd length (RFC 6716 §3.4 R3)")]
    OddLength,
    /// A frame length, frame count or padding that runs past the end of
    /// the packet (R4, R6, R7).
    #[error("a length past the end of the packet (RFC 6716 §3.4 R4, R6, R7)")]
    Truncated,
    /// A code 3 packet of no frames, or of more than 120 ms (R5).
    #[error("a code 3 packet of no frames or more than 120 ms (RFC 6716 §3.4 R5)")]
    FrameCount,
    /// A constant-bitrate code 3 packet whose bytes do not divide into
    /// its frames (R6).
    #[error("a CBR code 3 packet that does not divide into its frames (RFC 6716 §3.4 R6)")]
    Uneven,
}

/// Samples per frame at 48 kHz of a TOC configuration (RFC 6716 §3.1,
/// Table 2): SILK-only 10, 20, 40 or 60 ms (0 to 11), hybrid 10 or 20 ms
/// (12 to 15), CELT-only 2.5, 5, 10 or 20 ms (16 to 31).
const fn frame_samples(config: u8) -> u32 {
    match config {
        0..=11 => match config % 4 {
            0 => 480,
            1 => 960,
            2 => 1920,
            _ => 2880,
        },
        12..=15 => match config % 2 {
            0 => 480,
            _ => 960,
        },
        _ => match config % 4 {
            0 => 120,
            1 => 240,
            2 => 480,
            _ => 960,
        },
    }
}

/// One frame length and the bytes after it (RFC 6716 §3.2.1): one byte
/// up to 251, else that byte plus four times the next.
fn frame_length(bytes: &[u8]) -> Result<(usize, &[u8]), PacketError> {
    match bytes {
        [first @ 0..=251, rest @ ..] => Ok((usize::from(*first), rest)),
        [first, second, rest @ ..] => Ok((
            usize::from(*second)
                .saturating_mul(4)
                .saturating_add(usize::from(*first)),
            rest,
        )),
        _ => Err(PacketError::Truncated),
    }
}

/// `len` as a frame length, if it is one (R2).
const fn frame(len: usize) -> Result<usize, PacketError> {
    if len > MAX_FRAME_BYTES {
        Err(PacketError::FrameTooLong)
    } else {
        Ok(len)
    }
}

/// The frame count of a code 3 packet, from what follows its TOC byte, of
/// frames of `samples` each (RFC 6716 §3.2.5).
fn code_3_frames(bytes: &[u8], samples: u32) -> Result<u32, PacketError> {
    let (&count, mut rest) = bytes.split_first().ok_or(PacketError::Truncated)?;
    let frames = count & 0x3f;
    if frames == 0 || samples.saturating_mul(u32::from(frames)) > MAX_PACKET_SAMPLES {
        return Err(PacketError::FrameCount);
    }
    let mut padding = 0_usize;
    if count & 0x40 != 0 {
        loop {
            let (&length, after) = rest.split_first().ok_or(PacketError::Truncated)?;
            rest = after;
            if length < 255 {
                padding = padding.saturating_add(usize::from(length));
                break;
            }
            padding = padding.saturating_add(254);
        }
    }
    let data = rest
        .len()
        .checked_sub(padding)
        .and_then(|len| rest.get(..len))
        .ok_or(PacketError::Truncated)?;
    if count & 0x80 == 0 {
        let size = data
            .len()
            .checked_div(usize::from(frames))
            .ok_or(PacketError::FrameCount)?;
        if data.len().checked_rem(usize::from(frames)) != Some(0) {
            return Err(PacketError::Uneven);
        }
        frame(size)?;
    } else {
        let mut left = data;
        let mut total = 0_usize;
        for _ in 1..frames {
            let (len, after) = frame_length(left)?;
            left = after;
            total = total.saturating_add(frame(len)?);
        }
        frame(
            left.len()
                .checked_sub(total)
                .ok_or(PacketError::Truncated)?,
        )?;
    }
    Ok(u32::from(frames))
}

/// The audio `packet` carries, in samples at 48 kHz, if it is an Opus
/// packet by RFC 6716 §3.4 (R1 to R7): its TOC byte (§3.1), its frame
/// count code (0 to 3, §3.2.2 to §3.2.5), the frame lengths that code
/// implies or states, each at most 1275 bytes, and any padding, all
/// within its bytes. Frames of zero bytes are allowed (§3.2.1: DTX or a
/// lost frame). The frames' contents are not looked at.
pub fn packet_samples(packet: &[u8]) -> Result<u32, PacketError> {
    let (&toc, rest) = packet.split_first().ok_or(PacketError::Empty)?;
    let samples = frame_samples(toc >> 3);
    let frames = match toc & 0x03 {
        0 => {
            frame(rest.len())?;
            1
        }
        1 => {
            if rest.len() % 2 != 0 {
                return Err(PacketError::OddLength);
            }
            frame(rest.len() / 2)?;
            2
        }
        2 => {
            let (first, after) = frame_length(rest)?;
            frame(first)?;
            frame(
                after
                    .len()
                    .checked_sub(first)
                    .ok_or(PacketError::Truncated)?,
            )?;
            2
        }
        _ => code_3_frames(rest, samples)?,
    };
    Ok(samples.saturating_mul(frames))
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

/// One mono Opus decoder for one uplink. Keeps libopus's state between
/// packets, so packets of one stream go through one decoder in order,
/// concealments in their place.
#[derive(Debug)]
pub struct Decoder {
    /// The libopus decoder, mono at `rate`.
    inner: libopus::Decoder,
    /// The output rate.
    rate: u32,
    /// Samples in 2.5 ms at `rate`, the concealment step.
    step: usize,
    /// The output of the last call: room for [`MAX_PACKET_DURATION`].
    pcm: Vec<i16>,
}

impl Decoder {
    /// A mono decoder producing PCM at `rate` (one of [`DECODE_RATES`]).
    /// Stereo packets are mixed down by libopus.
    pub fn new(rate: u32) -> Result<Self, OpusError> {
        if !DECODE_RATES.contains(&rate) {
            return Err(OpusError::Rate(rate));
        }
        let inner = libopus::Decoder::new(rate, libopus::Channels::Mono)?;
        let samples = |span: u32| usize::try_from(rate.saturating_mul(span) / 1_000).unwrap_or(0);
        Ok(Self {
            inner,
            rate,
            step: samples(5) / 2,
            pcm: vec![0; samples(120)],
        })
    }

    /// The output rate.
    pub const fn rate(&self) -> u32 {
        self.rate
    }

    /// Decodes one packet into its PCM, as many samples as the packet
    /// carries (RFC 6716 §3.2: 2.5 to 120 ms).
    pub fn decode(&mut self, packet: &[u8]) -> Result<&[i16], OpusError> {
        if packet.is_empty() {
            return Err(OpusError::Empty);
        }
        let samples = self.inner.decode(packet, &mut self.pcm, false)?;
        Ok(self.pcm.get(..samples).unwrap_or(&[]))
    }

    /// Conceals `samples` of lost audio (RFC 6716 §4.4): libopus continues
    /// the signal from its state and fades it out over a long loss. The
    /// next packet decodes as if the lost ones had arrived.
    pub fn conceal(&mut self, samples: usize) -> Result<&[i16], OpusError> {
        let whole_steps = samples.checked_rem(self.step) == Some(0);
        let out = self
            .pcm
            .get_mut(..samples)
            .filter(|_| whole_steps && samples > 0)
            .ok_or(OpusError::Conceal(samples))?;
        let samples = self.inner.decode(&[], out, false)?;
        Ok(self.pcm.get(..samples).unwrap_or(&[]))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        clippy::cast_precision_loss,
        reason = "test code; signal math in floats"
    )]

    use super::*;

    /// `len` samples of a 1 kHz mono sine at half scale.
    fn sine(len: u16) -> Vec<f32> {
        (0..len)
            .map(|n| (std::f32::consts::TAU * 1000.0 * f32::from(n) / 48_000.0).sin() * 0.5)
            .collect()
    }

    #[test]
    fn rfc6716_3_1_every_toc_configuration_has_its_frame_size() {
        // Table 2, one code 0 packet of an empty frame per configuration.
        let expected: [u32; 32] = [
            480, 960, 1920, 2880, 480, 960, 1920, 2880, 480, 960, 1920, 2880, // SILK
            480, 960, 480, 960, // hybrid
            120, 240, 480, 960, 120, 240, 480, 960, 120, 240, 480, 960, 120, 240, 480,
            960, // CELT
        ];
        for (config, samples) in (0_u8..32).zip(expected) {
            assert_eq!(packet_samples(&[config << 3]), Ok(samples), "{config}");
            // The stereo bit changes nothing about the duration.
            assert_eq!(packet_samples(&[config << 3 | 0x04, 1]), Ok(samples));
        }
    }

    #[test]
    fn rfc6716_3_4_r1_r2_code_0_is_one_frame_of_at_most_1275_bytes() {
        assert_eq!(packet_samples(&[]), Err(PacketError::Empty));
        let toc = 31 << 3; // CELT FB 20 ms
        let mut packet = vec![toc; 1276];
        assert_eq!(packet_samples(&packet), Ok(960));
        packet.push(0);
        assert_eq!(packet_samples(&packet), Err(PacketError::FrameTooLong));
    }

    #[test]
    fn rfc6716_3_4_r2_r3_code_1_is_two_equal_frames() {
        let toc = 31 << 3 | 1;
        assert_eq!(packet_samples(&[toc]), Ok(1920), "two empty frames");
        assert_eq!(packet_samples(&[toc, 1, 2]), Ok(1920));
        assert_eq!(packet_samples(&[toc, 1]), Err(PacketError::OddLength));
        let mut packet = vec![toc; 1 + 2 * 1275];
        assert_eq!(packet_samples(&packet), Ok(1920));
        packet.extend([0, 0]);
        assert_eq!(packet_samples(&packet), Err(PacketError::FrameTooLong));
    }

    #[test]
    fn rfc6716_3_2_1_and_3_4_r4_code_2_states_its_first_frame_length() {
        let toc = 31 << 3 | 2;
        // One byte: 3, then a first frame of three and a second of one.
        assert_eq!(packet_samples(&[toc, 3, 9, 9, 9, 9]), Ok(1920));
        // Exactly the first frame and an empty second.
        assert_eq!(packet_samples(&[toc, 2, 9, 9]), Ok(1920));
        // Zero: an empty first frame (DTX), the rest is the second.
        assert_eq!(packet_samples(&[toc, 0, 9]), Ok(1920));
        // A first frame longer than what is left.
        assert_eq!(packet_samples(&[toc, 3, 9, 9]), Err(PacketError::Truncated));
        // No length byte at all, or a two-byte length cut short.
        assert_eq!(packet_samples(&[toc]), Err(PacketError::Truncated));
        assert_eq!(packet_samples(&[toc, 252]), Err(PacketError::Truncated));
        // Two bytes: 252 + 4 × 1 = 256, followed by exactly that.
        let mut packet = vec![toc, 252, 1];
        packet.extend([0; 256]);
        assert_eq!(packet_samples(&packet), Ok(1920));
        // 255 + 4 × 255 = 1275, the longest; the second frame also at most
        // 1275 (R2).
        let mut packet = vec![toc, 255, 255];
        packet.extend([0; 1275 + 1275]);
        assert_eq!(packet_samples(&packet), Ok(1920));
        packet.push(0);
        assert_eq!(packet_samples(&packet), Err(PacketError::FrameTooLong));
        // 251 is still a one-byte length.
        let mut packet = vec![toc, 251];
        packet.extend([0; 251]);
        assert_eq!(packet_samples(&packet), Ok(1920));
    }

    #[test]
    fn rfc6716_3_2_5_and_3_4_r5_r6_code_3_cbr_frames() {
        let toc = 31 << 3 | 3; // 20 ms frames
        // R6: at least the frame count byte.
        assert_eq!(packet_samples(&[toc]), Err(PacketError::Truncated));
        // R5: at least one frame, at most 120 ms.
        assert_eq!(packet_samples(&[toc, 0]), Err(PacketError::FrameCount));
        assert_eq!(packet_samples(&[toc, 6]), Ok(5760));
        assert_eq!(packet_samples(&[toc, 7]), Err(PacketError::FrameCount));
        assert_eq!(packet_samples(&[16 << 3 | 3, 48]), Ok(5760), "48 × 2.5 ms");
        assert_eq!(
            packet_samples(&[16 << 3 | 3, 49]),
            Err(PacketError::FrameCount)
        );
        // CBR: the bytes divide evenly into the frames.
        assert_eq!(packet_samples(&[toc, 3, 1, 2, 3]), Ok(2880));
        assert_eq!(
            packet_samples(&[toc, 3, 1, 2, 3, 4]),
            Err(PacketError::Uneven)
        );
        let mut packet = vec![toc, 2];
        packet.extend([0; 2 * 1276]);
        assert_eq!(packet_samples(&packet), Err(PacketError::FrameTooLong));
    }

    #[test]
    fn rfc6716_3_2_5_and_3_4_r6_r7_code_3_padding_and_vbr_lengths() {
        let toc = 31 << 3 | 3;
        // Padding (0x40) of 2 bytes after one CBR frame of 3.
        assert_eq!(packet_samples(&[toc, 0x41, 2, 1, 2, 3, 0, 0]), Ok(960));
        // A padding length of 255 means 254 and another length byte.
        let mut packet = vec![toc, 0x41, 255, 1, 7];
        packet.extend([0; 255]);
        assert_eq!(packet_samples(&packet), Ok(960));
        // Two CBR frames of one byte after 254 + 1 bytes of padding: the
        // second length byte is a length, not data.
        let mut packet = vec![toc, 0x42, 255, 1, 7, 7];
        packet.extend([0; 255]);
        assert_eq!(packet_samples(&packet), Ok(1920));
        // Padding longer than the packet, or a padding length missing.
        assert_eq!(
            packet_samples(&[toc, 0x41, 9, 0]),
            Err(PacketError::Truncated)
        );
        assert_eq!(packet_samples(&[toc, 0x41]), Err(PacketError::Truncated));
        assert_eq!(
            packet_samples(&[toc, 0x41, 255]),
            Err(PacketError::Truncated)
        );
        // VBR (0x80): M - 1 lengths, the last frame takes the rest.
        assert_eq!(packet_samples(&[toc, 0x83, 1, 2, 9, 9, 9, 9]), Ok(2880));
        assert_eq!(
            packet_samples(&[toc, 0x83, 1, 2, 9, 9, 9]),
            Ok(2880),
            "last empty"
        );
        // R7: the stated lengths run past the end, or a length is missing.
        assert_eq!(
            packet_samples(&[toc, 0x83, 1, 2, 9, 9]),
            Err(PacketError::Truncated)
        );
        assert_eq!(packet_samples(&[toc, 0x83, 1]), Err(PacketError::Truncated));
        // R2 on a stated length and on the implied last one.
        let mut packet = vec![toc, 0x82, 255, 255];
        packet.extend([0; 1275 + 1275]);
        assert_eq!(packet_samples(&packet), Ok(1920));
        packet.push(0);
        assert_eq!(packet_samples(&packet), Err(PacketError::FrameTooLong));
        // VBR and padding together: the padding is not the last frame's.
        assert_eq!(packet_samples(&[toc, 0xc2, 1, 1, 9, 9, 0]), Ok(1920));
        assert_eq!(
            packet_samples(&[toc, 0xc2, 1, 2, 9, 0]),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn rfc6716_3_4_what_the_encoder_makes_is_a_packet() {
        let mut enc = Encoder::new(2).unwrap();
        let packet = enc.encode(&vec![0.0; FRAME_SAMPLES * 2]).unwrap();
        assert_eq!(packet_samples(&packet), Ok(960));
        assert_eq!(
            PacketError::FrameTooLong.to_string(),
            "a frame longer than 1275 bytes (RFC 6716 §3.4 R2)"
        );
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
    /// `frames` 20 ms Opus packets of a `freq` Hz sine at half scale,
    /// encoded by [`Encoder`] (mono).
    fn tone_packets(freq: f32, frames: usize) -> Vec<Bytes> {
        let mut enc = Encoder::new(1).unwrap();
        (0..frames)
            .map(|k| {
                let pcm: Vec<f32> = (0..FRAME_SAMPLES)
                    .map(|n| {
                        let t = (k * FRAME_SAMPLES + n) as f32 / 48_000.0;
                        (std::f32::consts::TAU * freq * t).sin() * 0.5
                    })
                    .collect();
                enc.encode(&pcm).unwrap()
            })
            .collect()
    }

    /// Decodes `packets` at 8 kHz into one stream.
    fn decode_8k(packets: &[Bytes]) -> Vec<i16> {
        let mut dec = Decoder::new(8_000).unwrap();
        packets
            .iter()
            .flat_map(|p| dec.decode(p).unwrap().to_vec())
            .collect()
    }

    /// The RMS of `pcm` relative to full scale.
    fn rms(pcm: &[i16]) -> f64 {
        let sum: f64 = pcm.iter().map(|s| f64::from(*s).powi(2)).sum();
        (sum / pcm.len() as f64).sqrt() / 32_768.0
    }

    #[test]
    fn rfc6716_s2_a_tone_decodes_at_8_khz() {
        let pcm = decode_8k(&tone_packets(1_000.0, 50));
        assert_eq!(pcm.len(), 50 * 160, "20 ms is 160 samples at 8 kHz");
        let steady = &pcm[1_600..];
        let crossings = steady.windows(2).filter(|w| w[0] <= 0 && w[1] > 0).count();
        let freq = crossings as f64 * 8_000.0 / steady.len() as f64;
        assert!((freq - 1_000.0).abs() < 10.0, "{freq:.1} Hz");
        // Half scale: an RMS of 0.5/√2.
        assert!((rms(steady) - 0.354).abs() < 0.05, "{}", rms(steady));
    }

    #[test]
    fn rfc6716_s2_decoding_at_8_khz_band_limits_instead_of_aliasing() {
        // 6 kHz is above the 4 kHz Nyquist: dropped, not folded to 2 kHz.
        let pcm = decode_8k(&tone_packets(6_000.0, 50));
        let level = 20.0 * rms(&pcm[1_600..]).log10();
        assert!(level < -40.0, "{level:.1} dBFS");
    }

    #[test]
    fn stereo_packets_are_mixed_down() {
        let mut enc = Encoder::new(2).unwrap();
        let packet = enc.encode(&vec![0.25; FRAME_SAMPLES * 2]).unwrap();
        let mut dec = Decoder::new(8_000).unwrap();
        assert_eq!(dec.decode(&packet).unwrap().len(), 160);
        assert_eq!(dec.rate(), 8_000);
    }

    #[test]
    fn rfc6716_s4_4_loss_is_concealed_in_2_5_ms_steps() {
        let packets = tone_packets(1_000.0, 20);
        let mut dec = Decoder::new(8_000).unwrap();
        for packet in &packets[..10] {
            dec.decode(packet).unwrap();
        }
        // PLC continues the tone where the stream left off.
        let concealed = dec.conceal(160).unwrap().to_vec();
        assert_eq!(concealed.len(), 160);
        assert!(rms(&concealed) > 0.1, "{}", rms(&concealed));
        assert_eq!(dec.conceal(20).unwrap().len(), 20, "2.5 ms");
        assert_eq!(dec.conceal(960).unwrap().len(), 960, "120 ms");
        for bad in [0, 10, 150, 980] {
            assert_eq!(dec.conceal(bad).unwrap_err(), OpusError::Conceal(bad));
        }
        // The next packet decodes as usual.
        assert_eq!(dec.decode(&packets[10]).unwrap().len(), 160);
        let mut wide = Decoder::new(48_000).unwrap();
        assert_eq!(wide.conceal(120).unwrap().len(), 120);
        assert_eq!(wide.conceal(100).unwrap_err(), OpusError::Conceal(100));
    }

    #[test]
    fn rfc6716_s3_4_empty_and_malformed_packets_are_refused() {
        let mut dec = Decoder::new(8_000).unwrap();
        assert_eq!(dec.decode(&[]).unwrap_err(), OpusError::Empty);
        // Code 3 (RFC 6716 §3.2.5) needs a frame count byte.
        let err = dec.decode(&[0xfb]).unwrap_err();
        assert!(
            matches!(
                err,
                OpusError::Library {
                    function: "opus_decode",
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            OpusError::Empty.to_string(),
            "an empty packet is no Opus packet"
        );
        assert_eq!(
            OpusError::Conceal(7).to_string(),
            "7 samples cannot be concealed: a multiple of 2.5 ms up to 120 ms"
        );
    }

    #[test]
    fn only_opus_decode_rates() {
        for rate in DECODE_RATES {
            assert_eq!(Decoder::new(rate).unwrap().rate(), rate);
        }
        for rate in [0, 44_100, 96_000] {
            assert_eq!(Decoder::new(rate).unwrap_err(), OpusError::Rate(rate));
        }
        assert_eq!(
            OpusError::Rate(44_100).to_string(),
            "44100 Hz is not an Opus decode rate"
        );
        assert_eq!(MAX_PACKET_DURATION, Duration::from_millis(120));
    }
}
