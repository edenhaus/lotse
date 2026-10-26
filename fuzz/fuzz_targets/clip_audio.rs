//! `clip_audio`: the event clips' G.711 and G.722 → Opus transcode, as a
//! clip's task runs it on a camera's audio, never panics on arbitrary
//! payloads (every octet goes through the G.711 tables or the G.722
//! decoder), timestamps, epochs and discontinuities, and keeps its output
//! timeline: every packet is one 20 ms Opus packet (RFC 6716 §3.1, 960
//! samples at 48 kHz), and within one output epoch each is exactly one
//! packet (960 ticks, RFC 7587 §4.1) after the one before, so nothing
//! overlaps or leaves a hole inside an epoch.
//! Run with `cargo +nightly fuzz run clip_audio` from the repository root.
//!
//! The input is `[codec]` then frames `[flags][ts delta:i16 le][len][payload]`:
//! the codec byte picks PCMU, PCMA or G.722; a frame's timestamp moves by
//! its payload's length plus the delta (bit 4 of the flags: times 2^24),
//! bit 0 marks a discontinuity and bit 1 starts a new input epoch.

#![no_main]

use std::time::Duration;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use lotse_codec::opus::packet_samples;
use lotse_codec::transcode::clip::ToOpus;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::codec::Codec;
use lotse_core::media::{MediaFrame, MediaTime};

/// Takes `N` bytes off the front of `rest`.
fn take<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>()?;
    *rest = tail;
    Some(*head)
}

/// Ticks of one 20 ms Opus packet at 48 kHz.
const PACKET_TICKS: i64 = 960;

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let Some([pick]) = take::<1>(&mut rest) else {
        return;
    };
    let codec = match pick % 3 {
        0 => Codec::Pcmu,
        1 => Codec::Pcma,
        _ => Codec::G722,
    };
    let mut chain = ToOpus::new(&codec).expect("a transcoded codec");
    let t0 = SystemClock.now();
    let mut ts = 0_i64;
    let mut epoch = 0_u32;
    let mut last: Option<(u32, i64)> = None;
    while let (Some([flags]), Some(delta), Some([len])) = (
        take::<1>(&mut rest),
        take::<2>(&mut rest),
        take::<1>(&mut rest),
    ) {
        let Some((payload, tail)) = rest.split_at_checked(usize::from(len)) else {
            break;
        };
        rest = tail;
        let mut step = i64::from(i16::from_le_bytes(delta));
        if flags & 0x10 != 0 {
            step = step.saturating_mul(1 << 24);
        }
        if flags & 2 != 0 {
            epoch = epoch.wrapping_add(1);
        }
        let wallclock = t0
            .checked_add(Duration::from_millis(u64::from(flags) * 7))
            .unwrap_or(t0);
        let frame = MediaFrame {
            ts: MediaTime::from_ticks(ts),
            wallclock,
            arrival: wallclock,
            keyframe: true,
            discontinuity: flags & 1 != 0,
            epoch,
            payload: Bytes::copy_from_slice(payload),
        };
        ts = ts.saturating_add(i64::from(len)).saturating_add(step);
        for packet in chain.push(&frame).expect("a transcode of our own PCM") {
            assert_eq!(packet_samples(&packet.payload), Ok(960), "a 20 ms packet");
            let at = (packet.epoch, packet.ts.ticks());
            if let Some((epoch, previous)) = last
                && epoch == at.0
            {
                assert_eq!(
                    at.1.saturating_sub(previous),
                    PACKET_TICKS,
                    "one run within an epoch"
                );
            }
            last = Some(at);
        }
    }
});
