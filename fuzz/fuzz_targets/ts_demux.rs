//! `ts_demux`: the MPEG-TS demultiplexer never panics and never hangs on
//! arbitrary bytes, hands on the same events however the bytes are cut,
//! sends a layout before any unit, keeps every unit within the frame
//! limit and indexed into its layout, and its video units go through the
//! framed normalizer of their codec.
//!
//! The first input byte picks a prefix: nothing, or the SDT, PAT and PMT
//! packets (ISO/IEC 13818-1 §2.4.4) of one of the recorded streams, whose
//! CRC a fuzzer would rarely hit. Its low bit then picks how the rest is
//! read: as raw bytes (the aligner's input), or as records of one control
//! byte and 184 payload bytes, each made a transport packet (§2.4.3.2) on
//! a PID of those programs, with the payload unit start indicator and a
//! continuity counter that the control byte may skip. The byte's upper
//! bits pick where the stream is cut in two.
//! Run with `cargo +nightly fuzz run ts_demux` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::{h264, h265};
use lotse_core::Codec;
use lotse_http::media::{Event, Layout};
use lotse_http::ts::Demuxer;

/// The frame limit: small, so the limit is reached.
const MAX_FRAME: usize = 4096;

/// A transport packet and its payload without adaptation field.
const PACKET: usize = 188;
const PAYLOAD: usize = 184;

/// The PIDs records are sent on: the recorded streams' video, audio, PMTs,
/// PAT, SDT, and the null packet.
const PIDS: [u16; 8] = [0x100, 0x101, 0x102, 0x1000, 0x1001, 0x0000, 0x0011, 0x1fff];

const H264_AAC: &[u8] = include_bytes!("../../crates/lotse-http/testdata/h264_aac.m2t");
const H265: &[u8] = include_bytes!("../../crates/lotse-http/testdata/h265_v1.m2t");
const PROGRAMS: &[u8] = include_bytes!("../../crates/lotse-http/testdata/programs.m2t");

/// The rest of the input as transport packets, one per record.
fn packets(records: &[u8]) -> Vec<u8> {
    let mut counters = [0_u8; PIDS.len()];
    let mut out = Vec::new();
    for record in records.chunks(PAYLOAD + 1) {
        let Some((&control, payload)) = record.split_first() else {
            continue;
        };
        let which = usize::from(control & 0x07);
        let pid = PIDS[which];
        if control & 0x10 == 0 {
            counters[which] = counters[which].wrapping_add(1) & 0x0f;
        }
        out.push(0x47);
        out.push(u8::from(control & 0x08 != 0) << 6 | (pid >> 8) as u8);
        out.push(pid as u8);
        out.push(0x10 | counters[which]);
        out.extend_from_slice(payload);
        out.resize(out.len() + PAYLOAD - payload.len(), 0xff);
    }
    out
}

/// The events of `input` pushed in the given cuts, then flushed.
fn run(input: &[u8], cut: usize) -> (Vec<Event>, Demuxer) {
    let mut demuxer = Demuxer::new(MAX_FRAME);
    let mut events = Vec::new();
    let (first, second) = input.split_at(cut.min(input.len()));
    demuxer.push(first, &mut events);
    demuxer.push(second, &mut events);
    demuxer.flush(&mut events);
    (events, demuxer)
}

/// The normalizer of one track.
enum Normalizer {
    H264(h264::FramedNormalizer),
    H265(h265::FramedNormalizer),
    None,
}

fn normalizers(layout: &Layout) -> Vec<Normalizer> {
    layout
        .tracks
        .iter()
        .map(|track| match track.codec {
            Codec::H264 { .. } => Normalizer::H264(h264::FramedNormalizer::new(
                1_200,
                MAX_FRAME,
                h264::ParameterSets::default(),
            )),
            Codec::H265 { .. } => Normalizer::H265(h265::FramedNormalizer::new(
                1_200,
                MAX_FRAME,
                h265::ParameterSets::default(),
            )),
            _ => Normalizer::None,
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let prefix = match selector % 4 {
        0 => &[][..],
        1 => &H264_AAC[..3 * PACKET],
        2 => &H265[..3 * PACKET],
        _ => &PROGRAMS[..4 * PACKET],
    };
    let mut input = prefix.to_vec();
    if selector & 0x04 == 0 {
        input.extend_from_slice(rest);
    } else {
        input.extend_from_slice(&packets(rest));
    }
    let cut = usize::from(selector >> 3) * input.len() / 32;
    let (events, demuxer) = run(&input, input.len());
    let (pieces, cut_demuxer) = run(&input, cut);
    assert_eq!(events, pieces, "the cut changed the events");
    assert_eq!(demuxer.stats(), cut_demuxer.stats());

    let mut layout: Option<&Layout> = None;
    let mut normalizer = Vec::new();
    let mut packets = Vec::new();
    let mut h264_units = Vec::new();
    let mut h265_units = Vec::new();
    for event in &events {
        match event {
            Event::Layout(next) => {
                normalizer = normalizers(next);
                layout = Some(next);
            }
            Event::Unit(unit) => {
                let layout = layout.expect("a unit before the layout");
                assert!(unit.track < layout.tracks.len());
                assert!(layout.tracks[unit.track].codec.is_supported());
                assert!(unit.payload.len() <= MAX_FRAME);
                let ts = unit.ts as u32;
                match &mut normalizer[unit.track] {
                    Normalizer::H264(n) => n.push(ts, &unit.payload, &mut packets, &mut h264_units),
                    Normalizer::H265(n) => n.push(ts, &unit.payload, &mut packets, &mut h265_units),
                    Normalizer::None => {}
                }
            }
        }
    }
});
