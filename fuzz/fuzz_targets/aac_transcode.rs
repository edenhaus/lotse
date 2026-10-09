//! `aac_transcode`: the AAC-LC → Opus transcoder, as a worker runs it on a
//! camera's AAC track, never panics on arbitrary frames, timestamps,
//! epochs, discontinuities and lags, and keeps its output timeline: within
//! one output epoch every Opus packet is at least one packet (960 ticks at
//! 48 kHz, RFC 7587 §4.1) after the one before, so a gap moves the
//! timeline forward and nothing ever overlaps.
//! Run with `cargo +nightly fuzz run aac_transcode` from the repository
//! root.
//!
//! The input is `[config]` then frames `[flags][ts delta:i16 le][len][payload]`:
//! the config byte picks the sampling frequency index (low nibble, ISO/IEC
//! 14496-3 §1.6.3.4), stereo (bit 4) or the recorded 16 kHz sine whose
//! frames the payload byte then indexes (bit 5).

#![no_main]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use lotse_codec::aac::test_data::{CONFIG_16K_MONO, SINE_16K_MONO, frames};
use lotse_codec::transcode::AacToOpus;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::codec::{Codec, Kind};
use lotse_core::media::{MediaFrame, MediaTime};
use lotse_core::track::{SubscriptionError, Track, TrackId, TrackLimits};
use lotse_core::transcode::Transcoder as _;

/// Takes `N` bytes off the front of `rest`.
fn take<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>()?;
    *rest = tail;
    Some(*head)
}

/// Lets the transcoder task run on the current-thread runtime.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

/// The 48 kHz rate of every Opus track (RFC 7587 §4.1).
const OPUS_RATE: u32 = 48_000;

/// Ticks of one 20 ms Opus packet at 48 kHz.
const PACKET_TICKS: i64 = 960;

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let Some([pick]) = take::<1>(&mut rest) else {
        return;
    };
    let recorded = pick & 0x20 != 0;
    let channels: u8 = if pick & 0x10 != 0 && !recorded { 2 } else { 1 };
    let index = pick & 0x0f;
    // AudioSpecificConfig: object type 2 (AAC-LC), the index, the channels.
    let config: [u8; 2] = if recorded {
        CONFIG_16K_MONO
    } else {
        [
            (2 << 3) | (index >> 1),
            ((index & 1) << 7) | (channels << 3),
        ]
    };
    let Ok(parsed) = lotse_codec::aac::parse_config(&config) else {
        return;
    };
    let sine = frames(SINE_16K_MONO);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async move {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let t0 = clock.now();
        let codec = Codec::AacLc {
            sample_rate: parsed.sample_rate,
            channels: parsed.channels,
            config: Bytes::copy_from_slice(&config),
        };
        let input = Arc::new(Track::new(
            TrackId::new(Kind::Audio, 0),
            codec.clone(),
            parsed.sample_rate,
            TrackLimits::default(),
            t0,
        ));
        let output = Arc::new(Track::new(
            TrackId::new(Kind::Audio, 1),
            Codec::Opus {
                channels: parsed.channels,
            },
            OPUS_RATE,
            TrackLimits::default(),
            t0,
        ));
        let mut out = output.subscribe_frames();
        let Ok(handle) = AacToOpus::new(Arc::clone(&clock)).spawn(
            input.subscribe_frames(),
            &codec,
            Arc::clone(&output),
        ) else {
            return;
        };
        let mut ts = 0_i64;
        let mut seen: Vec<(u32, i64)> = Vec::new();
        let mut collect = |out: &mut lotse_core::track::FrameSubscription| loop {
            match out.try_recv() {
                Ok(Some(frame)) => {
                    assert!(!frame.payload.is_empty(), "an Opus packet has a payload");
                    seen.push((frame.epoch, frame.ts.ticks()));
                }
                Ok(None) | Err(SubscriptionError::Closed) => break,
                Err(SubscriptionError::Lagged(_)) => {}
            }
        };
        while let (Some([flags]), Some(delta), Some([len])) = (
            take::<1>(&mut rest),
            take::<2>(&mut rest),
            take::<1>(&mut rest),
        ) {
            let payload: &[u8] = if recorded {
                sine.get(usize::from(len) % sine.len())
                    .copied()
                    .unwrap_or_default()
            } else {
                let Some((body, tail)) = rest.split_at_checked(usize::from(len)) else {
                    break;
                };
                rest = tail;
                body
            };
            let mut step = i64::from(i16::from_le_bytes(delta)) + 1024;
            if flags & 0x10 != 0 {
                // A jump far along the 64-bit timeline.
                step = step.saturating_mul(1 << 24);
            }
            ts = ts.saturating_add(step);
            let wallclock = t0
                .checked_add(Duration::from_millis(u64::from(flags) * 7))
                .unwrap_or(t0);
            // Bit 1: the camera's timeline restarted (the track stamps it).
            if flags & 2 != 0 {
                input.start_epoch();
            }
            input.publish_frame(MediaFrame {
                ts: MediaTime::from_ticks(ts),
                wallclock,
                arrival: wallclock,
                keyframe: true,
                discontinuity: flags & 1 != 0,
                epoch: 0,
                payload: Bytes::copy_from_slice(payload),
            });
            // Bit 5 holds the task back, so a long run makes it lag.
            if flags & 0x20 == 0 {
                settle().await;
            }
            collect(&mut out);
        }
        settle().await;
        drop(handle);
        settle().await;
        collect(&mut out);
        drop(input);
        for pair in seen.windows(2) {
            let ((epoch_a, ts_a), (epoch_b, ts_b)) = (pair[0], pair[1]);
            if epoch_a == epoch_b {
                assert!(
                    ts_b.saturating_sub(ts_a) >= PACKET_TICKS,
                    "packets overlap within an epoch: {ts_a} then {ts_b}"
                );
            }
        }
    });
});
