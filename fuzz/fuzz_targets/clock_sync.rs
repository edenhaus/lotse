//! `clock_sync`: the camera's timing as the RTSP source hands it to core,
//! RTCP Sender Reports into the clock mapper and RTP timestamps through the
//! discontinuity guard, never panics on arbitrary values and keeps its
//! promises: a track without a mapping is mapped by its arrival; one
//! report moves a mapping, at its own timestamp, by at most the slew limit
//! of the fit plus that of the offset unless it re-anchors the connection
//! (a rejected report moves nothing); and the guard reports only jumps
//! beyond [`MAX_TIMESTAMP_JUMP`] (RFC 3550 §5.1, §6.4.1).
//! Run with `cargo +nightly fuzz run clock_sync` from the repository root.

#![no_main]

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use lotse_core::clock_map::{ClockMapper, MAX_SLEW, SyncMode};
use lotse_core::codec::Kind;
use lotse_core::discontinuity::{MAX_TIMESTAMP_JUMP, TimestampGuard};
use lotse_core::source::{ClockReport, SyncHint};
use lotse_core::track::TrackId;

/// Takes `N` bytes off the front of `rest`.
fn take<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>()?;
    *rest = tail;
    Some(*head)
}

/// What `mapper` maps `rtp` of `track` to, or `None` when it falls back to
/// the arrival (two different arrivals tell).
fn mapped(mapper: &ClockMapper, track: TrackId, rtp: u32, t0: Instant) -> Option<Instant> {
    let a = t0 + Duration::from_secs(1_000_000);
    let b = a + Duration::from_secs(1);
    let at = mapper.map(track, rtp, a);
    (at == mapper.map(track, rtp, b)).then_some(at)
}

fuzz_target!(|data: &[u8]| {
    let t0 = Instant::now();
    let mapper = ClockMapper::new();
    let tracks = [
        (TrackId::new(Kind::Video, 0), 90_000_u32),
        (TrackId::new(Kind::Audio, 0), 8_000),
        (TrackId::new(Kind::Audio, 1), 48_000),
        (TrackId::new(Kind::Video, 1), 0),
    ];
    let mut guards = tracks.map(|(_, rate)| TimestampGuard::new(rate));
    let mut now = t0;
    let mut rest = data;
    // Each op: [op][track][advance:u16 ms]...; the op's low bits pick what.
    while let (Some([op]), Some([pick]), Some(advance)) = (
        take::<1>(&mut rest),
        take::<1>(&mut rest),
        take::<2>(&mut rest),
    ) {
        now += Duration::from_millis(u64::from(u16::from_le_bytes(advance)));
        let index = usize::from(pick) % tracks.len();
        let (track, clock_rate) = tracks[index];
        match op % 4 {
            0 => {
                let (Some(ntp), Some(rtp)) = (take::<8>(&mut rest), take::<4>(&mut rest)) else {
                    break;
                };
                let rtp = u32::from_le_bytes(rtp);
                let before = mapped(&mapper, track, rtp, t0);
                let rejected = mapper.hints_rejected(track);
                mapper.ingest(ClockReport {
                    track,
                    clock_rate,
                    hint: SyncHint::RtcpSenderReport {
                        ntp: u64::from_le_bytes(ntp),
                        rtp_ts: rtp,
                    },
                    arrival: now,
                });
                let after = mapped(&mapper, track, rtp, t0);
                if mapper.hints_rejected(track) == rejected
                    && let (Some(before), Some(after)) = (before, after)
                {
                    let moved = if after > before {
                        after - before
                    } else {
                        before - after
                    };
                    assert!(
                        moved <= MAX_SLEW * 2,
                        "one report moved the mapping by {moved:?}"
                    );
                }
            }
            1 => {
                let Some(rtp) = take::<4>(&mut rest) else {
                    break;
                };
                let rtp = u32::from_le_bytes(rtp);
                if mapper.mode(track) == SyncMode::Arrival {
                    assert_eq!(mapper.map(track, rtp, now), now, "no mapping: the arrival");
                }
                if let Some(jump) = guards[index].observe(rtp, now) {
                    let bound = i64::try_from(MAX_TIMESTAMP_JUMP.as_millis()).unwrap();
                    assert!(jump.abs() >= bound, "a {jump} ms step is no new timeline");
                    assert_ne!(clock_rate, 0, "a guard without a clock rate never fires");
                }
            }
            2 => {
                mapper.reset();
                for (track, _) in tracks {
                    assert_eq!(mapper.mode(track), SyncMode::Arrival);
                }
            }
            _ => guards[index].rebase(),
        }
        let _ = mapper.audio_withdrawn();
    }
});
