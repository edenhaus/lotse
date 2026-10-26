//! Microbenchmarks of the audio path on recorded AAC-LC: the RFC 3640
//! depacketizer every AAC packet of a camera passes, and the AAC-LC to
//! Opus chain of the transcoder (ISO/IEC 14496-3 decode, resampling to
//! 48 kHz, RFC 6716 encode), the most expensive work per frame a worker
//! does; and the event clips' G.711 and G.722 to Opus transcode (ITU-T
//! G.711 or G.722 decode, resampling to 48 kHz, RFC 6716 encode), which
//! each clip of such a camera runs on its audio.
//!
//! The input is one second of a recorded 1 kHz sine from this crate's
//! `test-util` fixtures (`aac::test_data`), and one second of a 1 kHz tone
//! encoded to G.711 or G.722 in 20 ms frames. Run with `mise run bench`;
//! divan's harness, not libtest's.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    reason = "benchmark code, held to the tests' rules: a failed setup is a panic"
)]

use bytes::Bytes;
use divan::Bencher;
use divan::counter::ItemsCount;
use lotse_codec::aac::test_data::{
    CONFIG_16K_MONO, CONFIG_48K_MONO, SINE_16K_MONO, SINE_48K_MONO, frames,
};
use lotse_codec::aac::{self, AacDecoder, AacDepacketizer};
use lotse_codec::g711::Law;
use lotse_codec::g722::test_data::{encode, tone};
use lotse_codec::opus::{self, Encoder};
use lotse_codec::resample::Resampler;
use lotse_codec::transcode::clip::ToOpus;
use lotse_core::clock::{Clock as _, FakeClock};
use lotse_core::codec::Codec;
use lotse_core::media::{MediaFrame, MediaTime};
use lotse_core::track::DEFAULT_MAX_FRAME_BYTES;

/// The recordings' sample rates: 16 kHz is resampled, 48 kHz (Opus's own
/// rate) passes the resampler through.
const RATES: [u32; 2] = [16_000, 48_000];

/// The recorded second at `rate`: its `AudioSpecificConfig` and ADTS.
fn recording(rate: u32) -> ([u8; 2], &'static [u8]) {
    match rate {
        16_000 => (CONFIG_16K_MONO, SINE_16K_MONO),
        _ => (CONFIG_48K_MONO, SINE_48K_MONO),
    }
}

/// The RFC 3640 AAC-hbr depacketizer on one second of packets, one frame
/// each (§3.2.1, §3.3.6).
#[divan::bench]
fn aac_depacketize(bencher: Bencher<'_, '_>) {
    let frames = frames(SINE_16K_MONO);
    let packets: Vec<Vec<u8>> = frames
        .iter()
        .map(|frame| aac::packetize(&[*frame]))
        .collect();
    let mut depacketizer = AacDepacketizer::new(DEFAULT_MAX_FRAME_BYTES);
    let mut out = Vec::new();
    let mut seq = 0_u16;
    let mut ts = 0_u32;
    bencher
        .counter(ItemsCount::new(packets.len()))
        .bench_local(|| {
            out.clear();
            for packet in &packets {
                seq = seq.wrapping_add(1);
                ts = ts.wrapping_add(aac::FRAME_SAMPLES);
                depacketizer.push(seq, ts, true, packet, &mut out).unwrap();
            }
            out.len()
        });
    assert_eq!(out.len(), packets.len(), "every frame comes out");
}

/// The transcoder's chain on one second of AAC-LC frames: each frame
/// decoded, resampled to 48 kHz, and every whole 20 ms of it encoded to an
/// Opus packet, as the transcoder's `process` does.
#[divan::bench(args = RATES)]
fn aac_to_opus(bencher: Bencher<'_, '_>, rate: u32) {
    let (config, adts) = recording(rate);
    let frames = frames(adts);
    let mut decoder = AacDecoder::new(&config).unwrap();
    let chunk = usize::try_from(aac::FRAME_SAMPLES).unwrap();
    let mut resampler = Resampler::new(rate, 1, chunk).unwrap();
    let mut encoder = Encoder::new(1).unwrap();
    let mut fifo: Vec<f32> = Vec::new();
    bencher
        .counter(ItemsCount::new(frames.len()))
        .bench_local(|| {
            let mut bytes = 0;
            for frame in &frames {
                let pcm = decoder.decode(frame).unwrap();
                fifo.extend_from_slice(resampler.process(pcm).unwrap());
                let mut start = 0;
                while let Some(pcm) = fifo.get(start..start + opus::FRAME_SAMPLES) {
                    bytes += encoder.encode(pcm).unwrap().len();
                    start += opus::FRAME_SAMPLES;
                }
                fifo.drain(..start);
            }
            bytes
        });
    assert!(
        fifo.len() < opus::FRAME_SAMPLES,
        "every whole frame is encoded"
    );
}

/// The codecs a clip transcodes, by their API names.
const CLIP_CODECS: [&str; 3] = ["pcmu", "pcma", "g722"];

/// One second of a 1 kHz tone in `codec`, as fifty 20 ms payloads.
fn narrowband_second(codec: &Codec) -> Vec<Bytes> {
    // A quarter of full scale at 16 kHz; every other sample at 8 kHz.
    let pcm = tone(1_000, 16_000);
    match Law::of(codec) {
        Some(law) => pcm
            .iter()
            .step_by(2)
            .map(|sample| law.encode(*sample))
            .collect::<Vec<u8>>()
            .chunks(160)
            .map(Bytes::copy_from_slice)
            .collect(),
        None => encode(&pcm)
            .chunks(160)
            .map(Bytes::copy_from_slice)
            .collect(),
    }
}

/// A clip's G.711 or G.722 to Opus transcode on one second of 20 ms
/// frames, the timeline going on from one iteration to the next as a
/// clip's does: decode, resampling to 48 kHz and one Opus packet per
/// 20 ms. The time for one second is the share of one core a clip of such
/// a camera spends on its audio.
#[divan::bench(args = CLIP_CODECS)]
fn clip_to_opus(bencher: Bencher<'_, '_>, name: &str) {
    let codec = match name {
        "pcmu" => Codec::Pcmu,
        "pcma" => Codec::Pcma,
        _ => Codec::G722,
    };
    let payloads = narrowband_second(&codec);
    let mut chain = ToOpus::new(&codec).unwrap();
    let at = FakeClock::default().now();
    let mut ts = 0_i64;
    bencher
        .counter(ItemsCount::new(payloads.len()))
        .bench_local(|| {
            let mut packets = 0;
            for payload in &payloads {
                let frame = MediaFrame {
                    ts: MediaTime::from_ticks(ts),
                    wallclock: at,
                    arrival: at,
                    keyframe: true,
                    discontinuity: false,
                    epoch: 0,
                    payload: payload.clone(),
                };
                ts += 160;
                packets += chain.push(&frame).unwrap().len();
            }
            packets
        });
}

/// Runs the benchmarks of this file with divan's command line (`--help`).
fn main() {
    divan::main();
}
