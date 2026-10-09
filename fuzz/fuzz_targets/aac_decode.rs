//! `aac_decode`: [`AacDecoder`], as the transcoder builds it from a
//! camera's `AudioSpecificConfig` and drives it on the camera's frames,
//! never panics on arbitrary configurations and frames, reports the rate
//! and channels `parse_config` read, and always yields one whole frame of
//! PCM for those channels or an error.
//! Run with `cargo +nightly fuzz run aac_decode` from the repository root.
//!
//! The input is `[pick][config...]` then frames `[len:u8][frame...]`. With
//! bit 7 of `pick` clear, the config is a well-formed AAC-LC one built from
//! `pick`: the sampling frequency index (low nibble, ISO/IEC 14496-3
//! §1.6.3.3, Table 1.18), whose escape 0xf takes the explicit 24-bit
//! frequency from the next three bytes, and stereo (bit 4). With bit 7 set,
//! the config is the next `pick & 0x7f` bytes as they are, the way the
//! camera's SDP `config=` hands them over.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::aac::{AacDecoder, FRAME_SAMPLES, parse_config};

/// Takes `n` bytes off the front of `rest`.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, tail) = rest.split_at_checked(n)?;
    *rest = tail;
    Some(head)
}

/// An AAC-LC `AudioSpecificConfig` (ISO/IEC 14496-3 §1.6.2.1): object type
/// 2, the frequency index (and the explicit frequency after the escape),
/// the channel configuration, then a `GASpecificConfig` (§4.4.1) of three
/// zero bits: 1024-sample frames, no core coder, no extension.
fn built(index: u8, frequency: u32, channels: u8) -> Vec<u8> {
    let mut bits: u64 = 2;
    let mut len = 5;
    let mut push = |value: u64, width: u32| {
        bits = (bits << width) | value;
        len += width;
    };
    push(u64::from(index), 4);
    if index == 0xf {
        push(u64::from(frequency & 0x00ff_ffff), 24);
    }
    push(u64::from(channels), 4);
    push(0, 3);
    // 16 or 40 bits: whole bytes, the last `len / 8` of the word.
    bits.to_be_bytes()[8 - len as usize / 8..].to_vec()
}

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let Some(&[pick]) = take(&mut rest, 1) else {
        return;
    };
    let config: Vec<u8> = if pick & 0x80 == 0 {
        let index = pick & 0x0f;
        let frequency = if index == 0xf {
            let Some(&[a, b, c]) = take(&mut rest, 3) else {
                return;
            };
            u32::from_be_bytes([0, a, b, c])
        } else {
            0
        };
        let channels = if pick & 0x10 != 0 { 2 } else { 1 };
        built(index, frequency, channels)
    } else {
        let Some(raw) = take(&mut rest, usize::from(pick & 0x7f)) else {
            return;
        };
        raw.to_vec()
    };
    let parsed = parse_config(&config);
    let Ok(mut decoder) = AacDecoder::new(&config) else {
        return;
    };
    // The decoder only exists for what `parse_config` accepted, and says
    // what it read.
    let parsed = parsed.expect("AacDecoder::new accepted a config parse_config refuses");
    assert_eq!(decoder.channels(), parsed.channels);
    assert_eq!(decoder.sample_rate(), parsed.sample_rate);
    assert!(matches!(parsed.channels, 1 | 2));
    let channels = usize::from(parsed.channels);
    while let Some(&[len]) = take(&mut rest, 1) {
        let Some(frame) = take(&mut rest, usize::from(len)) else {
            break;
        };
        if let Ok(pcm) = decoder.decode(frame) {
            assert_eq!(pcm.len(), FRAME_SAMPLES as usize * channels);
        }
    }
});
