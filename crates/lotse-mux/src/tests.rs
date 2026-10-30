#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_codec::aac::test_data::{CONFIG_16K_MONO, SINE_16K_MONO, frames};
use lotse_codec::h264::annex_b_units;
use lotse_codec::opus::Decoder;
use lotse_codec::transcode::clip::ToOpus;
use lotse_codec::{g711, g722, h264, h265};
use lotse_core::clip::{ClipError, ClipMuxer as _, ClipMuxerFactory as _, ClipPolicy, ClipTrack};
use lotse_core::clock::{Clock as _, FakeClock};
use lotse_core::{Codec, CodecFamily, Kind, MediaFrame, MediaTime};
use mp4_atom::{Any, Codec as SampleEntry, Decode as _, Ftyp, Moof, Moov};

use super::{Factory, Limits, MAX_FRAGMENT_BYTES, MAX_SAMPLE_BYTES, Muxer, State, encode_failed};
use crate::fragment::{Sample, duration_of, ticks};
use crate::init::{NON_SYNC_SAMPLE, SYNC_SAMPLE};

/// One H.264 frame at 25 fps in 90 kHz ticks.
const FRAME: i64 = 3600;

fn base() -> Instant {
    FakeClock::from_system().now()
}

fn ms(base: Instant, at: u64) -> Instant {
    base + Duration::from_millis(at)
}

fn frame(
    wallclock: Instant,
    ts: i64,
    keyframe: bool,
    epoch: u32,
    payload: Bytes,
) -> Arc<MediaFrame> {
    Arc::new(MediaFrame {
        ts: MediaTime::from_ticks(ts),
        wallclock,
        arrival: wallclock,
        keyframe,
        discontinuity: false,
        epoch,
        payload,
    })
}

fn annex_b(units: &[&[u8]]) -> Bytes {
    let mut out = Vec::new();
    for unit in units {
        out.extend([0, 0, 0, 1]);
        out.extend(*unit);
    }
    Bytes::from(out)
}

/// An H.264 access unit: the sets before a keyframe, then a slice.
fn h264_au(keyframe: bool, n: u8) -> Bytes {
    let slice = [if keyframe { 0x65 } else { 0x41 }, 0x88, n, n ^ 0x5a];
    if keyframe {
        annex_b(&[
            &h264::test_data::sps(320, 240),
            &h264::test_data::pps(),
            &slice,
        ])
    } else {
        annex_b(&[&slice])
    }
}

/// An H.265 access unit: the sets before a keyframe, then a slice.
fn h265_au(keyframe: bool, n: u8) -> Bytes {
    let unit_type = if keyframe { 19 } else { 1 };
    let slice = [unit_type << 1, 0x01, 0xaf, n];
    if keyframe {
        annex_b(&[
            &h265::test_data::vps(),
            &h265::test_data::sps(640, 480),
            &h265::test_data::pps(),
            &slice,
        ])
    } else {
        annex_b(&[&slice])
    }
}

/// The sample an access unit becomes: each NAL unit behind its 4-byte
/// length.
fn length_prefixed(au: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in annex_b_units(au) {
        out.extend(u32::try_from(unit.len()).unwrap().to_be_bytes());
        out.extend(unit);
    }
    out
}

fn h264_codec(sps: Vec<u8>) -> Codec {
    Codec::H264 {
        profile_level_id: None,
        sps: Some(Bytes::from(sps)),
        pps: Some(Bytes::from(h264::test_data::pps())),
    }
}

fn h264_track() -> ClipTrack {
    ClipTrack {
        codec: h264_codec(h264::test_data::sps(320, 240)),
        clock_rate: 90_000,
    }
}

fn h265_codec(sps: Vec<u8>) -> Codec {
    Codec::H265 {
        vps: Some(Bytes::from(h265::test_data::vps())),
        sps: Some(Bytes::from(sps)),
        pps: Some(Bytes::from(h265::test_data::pps())),
    }
}

fn h265_track() -> ClipTrack {
    ClipTrack {
        codec: h265_codec(h265::test_data::sps(640, 480)),
        clock_rate: 90_000,
    }
}

fn aac_codec(sample_rate: u32) -> Codec {
    Codec::AacLc {
        sample_rate,
        channels: 1,
        config: Bytes::from_static(&CONFIG_16K_MONO),
    }
}

fn aac_track() -> ClipTrack {
    ClipTrack {
        codec: aac_codec(16_000),
        clock_rate: 16_000,
    }
}

fn opus_track(channels: u8) -> ClipTrack {
    ClipTrack {
        codec: Codec::Opus { channels },
        clock_rate: 48_000,
    }
}

/// An Opus packet of one 20 ms CELT frame (RFC 6716 §3.1: config 31,
/// code 0).
fn opus_packet(n: u8) -> Bytes {
    Bytes::from(vec![0xf8, n, 0xfe])
}

fn policy(fragment_ms: u64) -> ClipPolicy {
    ClipPolicy {
        fragment: Duration::from_millis(fragment_ms),
        ..ClipPolicy::default()
    }
}

/// What a clip wrote: the whole file, and which pushes completed a
/// fragment.
struct Written {
    file: Vec<u8>,
    cuts: Vec<usize>,
}

fn run(
    muxer: &mut Muxer,
    video: &ClipTrack,
    audio: Option<&ClipTrack>,
    frames: &[(Kind, Arc<MediaFrame>)],
) -> Written {
    let mut file = Vec::new();
    let mut cuts = Vec::new();
    for piece in muxer.start(video, audio).unwrap() {
        file.extend_from_slice(&piece);
    }
    for (index, (kind, frame)) in frames.iter().enumerate() {
        let out = muxer.push(*kind, Arc::clone(frame)).unwrap();
        if !out.is_empty() {
            cuts.push(index);
        }
        for piece in out {
            file.extend_from_slice(&piece);
        }
    }
    for piece in muxer.finish().unwrap() {
        file.extend_from_slice(&piece);
    }
    Written { file, cuts }
}

/// The file read back with mp4-atom: every box, in order.
struct File {
    ftyp: Ftyp,
    moov: Moov,
    /// Each fragment and where its `moof` starts.
    fragments: Vec<(Moof, usize)>,
}

fn read(file: &[u8]) -> File {
    let mut rest = file;
    let (mut ftyp, mut moov, mut fragments) = (None, None, Vec::new());
    let mut mdats = 0;
    while !rest.is_empty() {
        let start = file.len() - rest.len();
        match Any::decode(&mut rest).unwrap() {
            Any::Ftyp(atom) => ftyp = Some(atom),
            Any::Moov(atom) => moov = Some(atom),
            Any::Moof(atom) => fragments.push((atom, start)),
            Any::Mdat(_) => mdats += 1,
            other => panic!("unexpected box {:?}", other.kind()),
        }
    }
    assert_eq!(mdats, fragments.len(), "one mdat per moof");
    File {
        ftyp: ftyp.unwrap(),
        moov: moov.unwrap(),
        fragments,
    }
}

/// One sample read back.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Read {
    fragment: usize,
    dts: u64,
    duration: u32,
    flags: Option<u32>,
    cts: i32,
    bytes: Vec<u8>,
}

fn samples(file: &[u8], track_id: u32) -> Vec<Read> {
    let parsed = read(file);
    let mut out = Vec::new();
    for (index, (moof, start)) in parsed.fragments.iter().enumerate() {
        for traf in moof
            .traf
            .iter()
            .filter(|traf| traf.tfhd.track_id == track_id)
        {
            assert!(traf.tfhd.default_base_is_moof);
            assert_eq!(traf.tfhd.base_data_offset, None);
            let mut dts = traf.tfdt.as_ref().unwrap().base_media_decode_time;
            assert_eq!(traf.trun.len(), 1);
            let trun = &traf.trun[0];
            let mut at = start + usize::try_from(trun.data_offset.unwrap()).unwrap();
            for entry in &trun.entries {
                let size = usize::try_from(entry.size.unwrap()).unwrap();
                let duration = entry.duration.unwrap();
                out.push(Read {
                    fragment: index,
                    dts,
                    duration,
                    flags: entry.flags,
                    cts: entry.cts.unwrap_or(0),
                    bytes: file[at..at + size].to_vec(),
                });
                at += size;
                dts += u64::from(duration);
            }
        }
    }
    out
}

/// The version byte of every box of `kind` in `file`.
fn versions(file: &[u8], kind: [u8; 4]) -> Vec<u8> {
    file.windows(5)
        .filter(|window| window[..4] == kind)
        .map(|window| window[4])
        .collect()
}

/// 20 video frames at 25 fps, a keyframe every 10, and 13 AAC frames
/// of 64 ms, in capture order (video first on a tie).
fn av_frames(base: Instant) -> Vec<(Kind, Arc<MediaFrame>)> {
    let aac = frames(SINE_16K_MONO);
    let mut frames = Vec::new();
    for i in 0..20_u8 {
        let key = i % 10 == 0;
        let at = u64::from(i) * 40;
        frames.push((
            at,
            0,
            Kind::Video,
            frame(ms(base, at), i64::from(i) * FRAME, key, 0, h264_au(key, i)),
        ));
    }
    for i in 0..13_u8 {
        let at = u64::from(i) * 64;
        let payload = Bytes::copy_from_slice(aac[usize::from(i)]);
        frames.push((
            at,
            1,
            Kind::Audio,
            frame(ms(base, at), i64::from(i) * 1024, true, 0, payload),
        ));
    }
    frames.sort_by_key(|(at, order, ..)| (*at, *order));
    frames
        .into_iter()
        .map(|(_, _, kind, frame)| (kind, frame))
        .collect()
}

#[test]
fn iso14496_12_8_8_7_default_base_is_moof_data_offsets_point_at_each_track_s_samples() {
    let base = base();
    let frames = av_frames(base);
    let written = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );
    let video: Vec<Vec<u8>> = frames
        .iter()
        .filter(|(kind, _)| *kind == Kind::Video)
        .map(|(_, frame)| length_prefixed(&frame.payload))
        .collect();
    let audio: Vec<Vec<u8>> = frames
        .iter()
        .filter(|(kind, _)| *kind == Kind::Audio)
        .map(|(_, frame)| frame.payload.to_vec())
        .collect();
    let read_video: Vec<Vec<u8>> = samples(&written.file, 1)
        .into_iter()
        .map(|s| s.bytes)
        .collect();
    let read_audio: Vec<Vec<u8>> = samples(&written.file, 2)
        .into_iter()
        .map(|s| s.bytes)
        .collect();
    assert_eq!(read_video, video);
    assert_eq!(read_audio, audio);
    // Two GOPs: the second keyframe ends the first fragment.
    let parsed = read(&written.file);
    assert_eq!(parsed.fragments.len(), 2);
    let sequence: Vec<u32> = parsed
        .fragments
        .iter()
        .map(|(moof, _)| moof.mfhd.sequence_number)
        .collect();
    assert_eq!(
        sequence,
        [1, 2],
        "ISO/IEC 14496-12 §8.8.5: from 1, increasing"
    );
    assert_eq!(written.cuts.len(), 1);
    let (kind, cut) = &frames[written.cuts[0]];
    assert_eq!(
        (*kind, cut.keyframe, cut.ts.ticks()),
        (Kind::Video, true, 10 * FRAME)
    );
}

#[test]
fn iso14496_15_5_3_2_video_samples_are_slices_of_the_frame_never_copies() {
    let base = base();
    let au = h264_au(true, 7);
    let mut muxer = Muxer::new(&policy(1000));
    muxer.start(&h264_track(), None).unwrap();
    assert!(
        muxer
            .push(Kind::Video, frame(base, 0, true, 0, au.clone()))
            .unwrap()
            .is_empty()
    );
    let out = muxer.finish().unwrap();
    // The moof and mdat header, then length and unit for each of the three units.
    assert_eq!(out.len(), 1 + 2 * 3);
    let range = au.as_ptr().addr()..au.as_ptr().addr() + au.len();
    for (index, piece) in out.iter().enumerate().skip(1) {
        let inside = range.contains(&piece.as_ptr().addr());
        assert_eq!(
            inside,
            index % 2 == 0,
            "piece {index}: a unit, else its length"
        );
    }
    let joined: Vec<u8> = out[1..].iter().flat_map(|piece| piece.to_vec()).collect();
    assert_eq!(joined, length_prefixed(&au));
}

#[test]
fn iso14496_12_8_8_12_tfdt_is_the_first_sample_s_decode_time_in_version_1() {
    let base = base();
    let frames = av_frames(base);
    let written = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );
    for track in [1, 2] {
        let samples = samples(&written.file, track);
        assert_eq!(samples[0].dts, 0);
        for pair in samples.windows(2) {
            assert_eq!(
                pair[1].dts,
                pair[0].dts + u64::from(pair[0].duration),
                "track {track}"
            );
        }
        assert!(
            samples.iter().any(|s| s.fragment == 1),
            "track {track} continues in fragment 2"
        );
    }
    let video = samples(&written.file, 1);
    assert!(video.iter().all(|s| s.duration == 3600));
    let audio = samples(&written.file, 2);
    assert!(audio.iter().all(|s| s.duration == 1024));
    assert_eq!(versions(&written.file, *b"tfdt"), [1; 4]);

    // A decode time past 32 bits: a second epoch 50 000 s after the first.
    let mut muxer = Muxer::new(&policy(1000));
    let late = base + Duration::from_secs(50_000);
    let frames = [
        (Kind::Video, frame(base, 0, true, 0, h264_au(true, 0))),
        (Kind::Video, frame(late, 0, true, 1, h264_au(true, 1))),
    ];
    let written = run(&mut muxer, &h264_track(), None, &frames);
    let video = samples(&written.file, 1);
    assert_eq!(video[1].dts, 4_500_000_000);
    assert_eq!(versions(&written.file, *b"tfdt"), [1, 1]);
}

#[test]
fn iso14496_12_8_8_8_1_negative_composition_offsets_time_reordered_video() {
    let base = base();
    // Decode order I0 P3 B1 B2 P6 B4 B5, captured at their presentation.
    let order = [0, 3, 1, 2, 6, 4, 5];
    let frames: Vec<_> = order
        .iter()
        .map(|&n: &u8| {
            let ts = i64::from(n) * FRAME;
            (
                Kind::Video,
                frame(
                    ms(base, u64::from(n) * 40),
                    ts,
                    n == 0,
                    0,
                    h264_au(n == 0, n),
                ),
            )
        })
        .collect();
    let written = run(&mut Muxer::new(&policy(1000)), &h264_track(), None, &frames);
    let samples = samples(&written.file, 1);
    let timing: Vec<(u64, i32)> = samples.iter().map(|s| (s.dts, s.cts)).collect();
    // In order until B1, whose timestamp goes back: from it on the decode
    // times step by the smallest distance seen (2, then 1 frame).
    let f = 3600;
    assert_eq!(
        timing,
        [
            (0, 0),
            (3 * f, 0),
            (5 * f, -4 * 3600),
            (6 * f, -4 * 3600),
            (7 * f, -3600),
            (8 * f, -4 * 3600),
            (9 * f, -4 * 3600),
        ]
    );
    // Presentation (decode time plus offset) is the capture order.
    let mut presented: Vec<(i64, u8)> = samples
        .iter()
        .zip(order)
        .map(|(s, n)| (i64::try_from(s.dts).unwrap() + i64::from(s.cts), n))
        .collect();
    presented.sort_unstable();
    assert_eq!(
        presented.iter().map(|(_, n)| *n).collect::<Vec<_>>(),
        [0, 1, 2, 3, 4, 5, 6]
    );
    assert_eq!(versions(&written.file, *b"trun"), [1]);
    assert_eq!(samples.last().unwrap().duration, u32::try_from(f).unwrap());
}

#[test]
fn iso14496_12_8_8_8_1_a_repeated_video_timestamp_is_decoded_a_tick_later() {
    let base = base();
    let frames = [
        (Kind::Video, frame(base, 0, true, 0, h264_au(true, 0))),
        (
            Kind::Video,
            frame(ms(base, 40), 0, false, 0, h264_au(false, 1)),
        ),
    ];
    let written = run(&mut Muxer::new(&policy(1000)), &h264_track(), None, &frames);
    let timing: Vec<(u64, u32, i32)> = samples(&written.file, 1)
        .iter()
        .map(|s| (s.dts, s.duration, s.cts))
        .collect();
    // No distance seen yet: the step is one tick.
    assert_eq!(timing, [(0, 1, 0), (1, 1, -1)]);
}

#[test]
fn iso14496_12_8_8_3_1_keyframes_are_sync_samples_and_the_rest_depend_on_others() {
    let base = base();
    let frames = av_frames(base);
    let written = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );
    let flags: Vec<Option<u32>> = samples(&written.file, 1).iter().map(|s| s.flags).collect();
    let expected: Vec<Option<u32>> = (0..20)
        .map(|i| {
            Some(if i % 10 == 0 {
                SYNC_SAMPLE
            } else {
                NON_SYNC_SAMPLE
            })
        })
        .collect();
    assert_eq!(flags, expected);
    assert_eq!((SYNC_SAMPLE, NON_SYNC_SAMPLE), (0x0200_0000, 0x0101_0000));
    // Audio samples carry none: the track's defaults say sync.
    assert!(samples(&written.file, 2).iter().all(|s| s.flags.is_none()));
    // A fragment of one video sample writes its flags as the first
    // sample's (§8.8.8: `first_sample_flags`).
    let one = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        None,
        &[(Kind::Video, frame(base, 0, true, 0, h264_au(true, 0)))],
    );
    assert_eq!(samples(&one.file, 1)[0].flags, Some(SYNC_SAMPLE));
}

#[test]
fn iso14496_12_8_2_1_the_init_segment_is_ftyp_and_moov_with_one_track_each() {
    let mut muxer = Muxer::new(&policy(1000));
    let init = muxer.start(&h264_track(), Some(&aac_track())).unwrap();
    assert_eq!(init.len(), 1);
    let file = read(&init[0]);
    assert_eq!(file.ftyp.major_brand, b"iso6".into());
    assert_eq!(
        file.ftyp.compatible_brands,
        [b"iso6".into(), b"mp41".into()]
    );
    let moov = &file.moov;
    assert_eq!((moov.mvhd.timescale, moov.mvhd.duration), (1000, 0));
    assert_eq!(moov.mvhd.rate.integer(), 1);
    assert_eq!(moov.mvhd.volume.integer(), 1);
    assert_eq!(moov.mvhd.next_track_id, 3);
    assert_eq!(moov.trak.len(), 2);
    let (video, audio) = (&moov.trak[0], &moov.trak[1]);
    assert_eq!((video.tkhd.track_id, audio.tkhd.track_id), (1, 2));
    assert!(video.tkhd.enabled && video.tkhd.in_movie);
    assert_eq!(
        (video.tkhd.width.integer(), video.tkhd.height.integer()),
        (320, 240)
    );
    assert_eq!(
        (video.tkhd.volume.integer(), audio.tkhd.volume.integer()),
        (0, 1)
    );
    assert_eq!(
        (audio.tkhd.width.integer(), audio.tkhd.height.integer()),
        (0, 0)
    );
}

#[test]
fn iso14496_12_8_4_each_track_has_its_media_header_handler_and_empty_sample_tables() {
    let mut muxer = Muxer::new(&policy(1000));
    let init = muxer.start(&h264_track(), Some(&aac_track())).unwrap();
    let moov = read(&init[0]).moov;
    let (video, audio) = (&moov.trak[0], &moov.trak[1]);
    assert_eq!(video.mdia.mdhd.timescale, 90_000);
    assert_eq!(audio.mdia.mdhd.timescale, 16_000);
    assert_eq!(video.mdia.mdhd.language, "und");
    assert_eq!(video.mdia.hdlr.handler, b"vide".into());
    assert_eq!(audio.mdia.hdlr.handler, b"soun".into());
    assert!(video.mdia.minf.vmhd.is_some() && video.mdia.minf.smhd.is_none());
    assert!(audio.mdia.minf.smhd.is_some() && audio.mdia.minf.vmhd.is_none());
    for trak in [video, audio] {
        let stbl = &trak.mdia.minf.stbl;
        assert_eq!(stbl.stsd.codecs.len(), 1);
        assert!(stbl.stts.entries.is_empty() && stbl.stsc.entries.is_empty());
        assert_eq!(stbl.stco.as_ref().unwrap().entries, Vec::<u32>::new());
        assert_eq!(trak.mdia.minf.dinf.dref.urls.len(), 1);
        assert_eq!(trak.mdia.minf.dinf.dref.urls[0].location, "");
    }
}

#[test]
fn iso14496_12_8_8_3_track_extends_give_each_track_s_defaults() {
    let mut muxer = Muxer::new(&policy(1000));
    let init = muxer.start(&h264_track(), Some(&aac_track())).unwrap();
    let moov = read(&init[0]).moov;
    let trex = &moov.mvex.as_ref().unwrap().trex;
    let defaults: Vec<(u32, u32, u32)> = trex
        .iter()
        .map(|t| {
            (
                t.track_id,
                t.default_sample_description_index,
                t.default_sample_flags,
            )
        })
        .collect();
    assert_eq!(defaults, [(1, 1, NON_SYNC_SAMPLE), (2, 1, SYNC_SAMPLE)]);
    assert!(
        trex.iter()
            .all(|t| t.default_sample_duration == 0 && t.default_sample_size == 0)
    );

    let init = Muxer::new(&policy(1000))
        .start(&h264_track(), None)
        .unwrap();
    let moov = read(&init[0]).moov;
    assert_eq!((moov.trak.len(), moov.mvhd.next_track_id), (1, 2));
    assert_eq!(moov.mvex.unwrap().trex.len(), 1);
}

fn entry(init: &[Bytes], track: usize) -> SampleEntry {
    let moov = read(&init[0]).moov;
    moov.trak[track].mdia.minf.stbl.stsd.codecs[0].clone()
}

#[test]
fn iso14496_15_5_3_3_1_avcc_carries_the_sets_profile_level_and_the_high_profiles_chroma() {
    let init = Muxer::new(&policy(1000))
        .start(&h264_track(), None)
        .unwrap();
    let SampleEntry::Avc1(avc1) = entry(&init, 0) else {
        panic!("not avc1");
    };
    assert_eq!((avc1.visual.width, avc1.visual.height), (320, 240));
    assert_eq!(avc1.visual.data_reference_index, 1);
    let record = &avc1.avcc;
    assert_eq!(record.configuration_version, 1);
    assert_eq!(
        (
            record.avc_profile_indication,
            record.profile_compatibility,
            record.avc_level_indication
        ),
        (0x42, 0xc0, 0x28)
    );
    assert_eq!(record.length_size, 4);
    assert_eq!(
        record.sequence_parameter_sets,
        [h264::test_data::sps(320, 240)]
    );
    assert_eq!(record.picture_parameter_sets, [h264::test_data::pps()]);
    assert_eq!(record.ext, None, "Baseline has no chroma fields");

    let high = ClipTrack {
        codec: h264_codec(h264::test_data::high_sps(122, 2, 2, 2)),
        clock_rate: 90_000,
    };
    let init = Muxer::new(&policy(1000)).start(&high, None).unwrap();
    let SampleEntry::Avc1(avc1) = entry(&init, 0) else {
        panic!("not avc1");
    };
    let ext = avc1.avcc.ext.unwrap();
    assert_eq!(
        (ext.chroma_format, ext.bit_depth_luma, ext.bit_depth_chroma),
        (2, 10, 10)
    );
    assert!(ext.sequence_parameter_sets_ext.is_empty());
    assert_eq!((avc1.visual.width, avc1.visual.height), (640, 480));
}

#[test]
fn iso14496_15_8_3_3_1_hvcc_carries_profile_tier_level_and_complete_parameter_set_arrays() {
    let init = Muxer::new(&policy(1000))
        .start(&h265_track(), None)
        .unwrap();
    let SampleEntry::Hvc1(hvc1) = entry(&init, 0) else {
        panic!("not hvc1");
    };
    assert_eq!((hvc1.visual.width, hvc1.visual.height), (640, 480));
    assert_eq!(hvc1.visual.data_reference_index, 1);
    let record = &hvc1.hvcc;
    assert_eq!(record.configuration_version, 1);
    assert_eq!(
        (
            record.general_profile_space,
            record.general_tier_flag,
            record.general_profile_idc
        ),
        (0, false, 1)
    );
    assert_eq!(record.general_profile_compatibility_flags, [0x60, 0, 0, 0]);
    assert_eq!(
        record.general_constraint_indicator_flags,
        [0x90, 0, 0, 0, 0, 0]
    );
    assert_eq!(record.general_level_idc, h265::test_data::LEVEL_IDC);
    assert_eq!(
        (
            record.chroma_format_idc,
            record.bit_depth_luma_minus8,
            record.bit_depth_chroma_minus8
        ),
        (1, 0, 0)
    );
    assert_eq!(
        (record.num_temporal_layers, record.temporal_id_nested),
        (1, true)
    );
    assert_eq!(record.length_size_minus_one, 3);
    let arrays: Vec<(bool, u8, Vec<Vec<u8>>)> = record
        .arrays
        .iter()
        .map(|array| (array.completeness, array.nal_unit_type, array.nalus.clone()))
        .collect();
    assert_eq!(
        arrays,
        [
            (true, 32, vec![h265::test_data::vps()]),
            (true, 33, vec![h265::test_data::sps(640, 480)]),
            (true, 34, vec![h265::test_data::pps()]),
        ]
    );
    // Its samples are the access units' NAL units behind their lengths.
    let base = base();
    let frames = [
        (Kind::Video, frame(base, 0, true, 0, h265_au(true, 0))),
        (
            Kind::Video,
            frame(ms(base, 40), FRAME, false, 0, h265_au(false, 1)),
        ),
    ];
    let written = run(&mut Muxer::new(&policy(1000)), &h265_track(), None, &frames);
    let read: Vec<Vec<u8>> = samples(&written.file, 1)
        .into_iter()
        .map(|s| s.bytes)
        .collect();
    // The keyframe's sets are the entry's: §8.4.1.1.2 keeps them out.
    let slice = annex_b_units(&frames[0].1.payload)[3].to_vec();
    let expected = vec![
        length_prefixed(&annex_b(&[&slice])),
        length_prefixed(&frames[1].1.payload),
    ];
    assert_eq!(read, expected);
}

#[test]
fn h265_parameter_sets_other_than_the_entry_s_stay_in_band_with_every_later_sample_s() {
    let base = base();
    // A pre-roll GOP from before the sets changed: another picture size
    // under the same SPS ID, which replaces the entry's in the decoder.
    // The GOPs after it bring the current sets back in band: a new
    // fragment does not reload `hvcC`, so without them they would decode
    // with the older SPS.
    let older = h265::test_data::sps(320, 240);
    let slice = [19 << 1, 0x01, 0xaf, 0];
    let older_gop = annex_b(&[
        &h265::test_data::vps(),
        &older,
        &h265::test_data::pps(),
        &slice,
    ]);
    let frames = [
        (Kind::Video, frame(base, 0, true, 0, older_gop)),
        (
            Kind::Video,
            frame(ms(base, 40), FRAME, false, 0, h265_au(false, 1)),
        ),
        (
            Kind::Video,
            frame(ms(base, 80), 2 * FRAME, true, 0, h265_au(true, 2)),
        ),
        (
            Kind::Video,
            frame(ms(base, 120), 3 * FRAME, true, 0, h265_au(true, 3)),
        ),
    ];
    let written = run(&mut Muxer::new(&policy(1000)), &h265_track(), None, &frames);
    let read: Vec<Vec<u8>> = samples(&written.file, 1)
        .into_iter()
        .map(|s| s.bytes)
        .collect();
    let expected: Vec<Vec<u8>> = frames
        .iter()
        .map(|(_, frame)| length_prefixed(&frame.payload))
        .collect();
    assert_eq!(read, expected);
    // H.264 keeps every set.
    let au = h264_au(true, 0);
    let frames = [(Kind::Video, frame(base, 0, true, 0, au.clone()))];
    let written = run(&mut Muxer::new(&policy(1000)), &h264_track(), None, &frames);
    assert_eq!(samples(&written.file, 1)[0].bytes, length_prefixed(&au));
}

/// An H.265 SPS up to its bit depths (ITU-T H.265 §7.3.2.2.1), 640 ×
/// 480 4:2:0, in `profile_space`, the High tier when `high_tier`, of
/// the bit depths minus 8 given.
fn h265_sps(profile_space: u32, high_tier: bool, luma_minus8: u32, chroma_minus8: u32) -> Vec<u8> {
    let mut b = h264::test_data::Bits::default();
    b.bits(0, 4).bits(0, 3).bit(true); // vps id, one sub-layer, nesting
    b.bits(profile_space, 2).bit(high_tier).bits(2, 5); // Main 10
    b.bits(0x2000_0000, 32).bits(0, 32).bits(0, 16).bits(120, 8);
    b.ue(0).ue(1).ue(640).ue(480).bit(false); // ids, 4:2:0, size, no window
    b.ue(luma_minus8).ue(chroma_minus8);
    h265::test_data::unit(h265::nal::SPS_NUT, &b.finish())
}

#[test]
fn iso14496_15_8_3_3_1_hvcc_carries_the_profile_space_tier_and_bit_depths() {
    let track = ClipTrack {
        codec: h265_codec(h265_sps(1, true, 2, 1)),
        clock_rate: 90_000,
    };
    let init = Muxer::new(&policy(1000)).start(&track, None).unwrap();
    let SampleEntry::Hvc1(hvc1) = entry(&init, 0) else {
        panic!("not hvc1");
    };
    let record = &hvc1.hvcc;
    assert_eq!(
        (
            record.general_profile_space,
            record.general_tier_flag,
            record.general_profile_idc
        ),
        (1, true, 2)
    );
    assert_eq!(
        (record.bit_depth_luma_minus8, record.bit_depth_chroma_minus8),
        (2, 1)
    );
}

#[test]
fn iso14496_14_5_6_esds_carries_the_audio_specific_config_as_mpeg4_audio() {
    let init = Muxer::new(&policy(1000))
        .start(&h264_track(), Some(&aac_track()))
        .unwrap();
    let SampleEntry::Mp4a(mp4a) = entry(&init, 1) else {
        panic!("not mp4a");
    };
    assert_eq!(mp4a.audio.data_reference_index, 1);
    assert_eq!((mp4a.audio.channel_count, mp4a.audio.sample_size), (1, 16));
    assert_eq!(mp4a.audio.sample_rate.integer(), 16_000);
    let config = &mp4a.esds.es_desc.dec_config;
    assert_eq!(
        (config.object_type_indication, config.stream_type),
        (0x40, 0x05)
    );
    assert_eq!(config.dec_specific.as_ref().unwrap().raw, CONFIG_16K_MONO);
    assert_eq!(mp4a.esds.es_desc.es_id, 0);

    // A rate past the 16.16 field is written as 0.
    let fast = ClipTrack {
        codec: aac_codec(96_000),
        clock_rate: 96_000,
    };
    let init = Muxer::new(&policy(1000))
        .start(&h264_track(), Some(&fast))
        .unwrap();
    let SampleEntry::Mp4a(mp4a) = entry(&init, 1) else {
        panic!("not mp4a");
    };
    assert_eq!(mp4a.audio.sample_rate.integer(), 0);
}

#[test]
fn opus_isobmff_4_3_2_dops_carries_the_channels_and_a_zero_pre_skip_at_48_khz() {
    for channels in [1, 2] {
        let init = Muxer::new(&policy(1000))
            .start(&h264_track(), Some(&opus_track(channels)))
            .unwrap();
        let SampleEntry::Opus(opus) = entry(&init, 1) else {
            panic!("not Opus");
        };
        assert_eq!(opus.audio.channel_count, u16::from(channels));
        assert_eq!(opus.audio.sample_rate.integer(), 48_000);
        assert_eq!(
            (
                opus.dops.output_channel_count,
                opus.dops.pre_skip,
                opus.dops.input_sample_rate,
                opus.dops.output_gain
            ),
            (channels, 0, 48_000, 0)
        );
    }
}

#[test]
fn fragments_end_at_the_latest_after_the_span() {
    let base = base();
    // One keyframe, then 59 frames 40 ms apart: 2.4 s of one GOP.
    let frames: Vec<_> = (0..60_u8)
        .map(|i| {
            let key = i == 0;
            (
                Kind::Video,
                frame(
                    ms(base, u64::from(i) * 40),
                    i64::from(i) * FRAME,
                    key,
                    0,
                    h264_au(key, i),
                ),
            )
        })
        .collect();
    let written = run(&mut Muxer::new(&policy(1000)), &h264_track(), None, &frames);
    // The frames at exactly 1 s and 2 s end the fragments before them.
    assert_eq!(written.cuts, [25, 50]);
    let samples = samples(&written.file, 1);
    let per_fragment: Vec<usize> = (0..3)
        .map(|f| samples.iter().filter(|s| s.fragment == f).count())
        .collect();
    assert_eq!(per_fragment, [25, 25, 10]);
    let first_of_second = samples.iter().find(|s| s.fragment == 1).unwrap();
    assert_eq!(first_of_second.flags, Some(NON_SYNC_SAMPLE));

    // The factory's muxer takes the policy's span.
    let mut muxer = Factory.muxer(&policy(500));
    muxer.start(&h264_track(), None).unwrap();
    let cut: Vec<bool> = frames[..15]
        .iter()
        .map(|(kind, frame)| !muxer.push(*kind, Arc::clone(frame)).unwrap().is_empty())
        .collect();
    assert_eq!(
        cut.iter().position(|c| *c),
        Some(13),
        "at 520 ms, the first frame past 500 ms"
    );
}

/// The span is measured on the track's decode times, which only move
/// forward, not on capture times. Regression: a frame whose Sender Report
/// mapping put it an hour ahead ended the fragment and began the next
/// span there; the frames after it, mapped back where they belong in the
/// same epoch, never reached that span, and only the next keyframe ended
/// the fragment.
#[test]
fn fragments_end_after_the_span_of_decode_time_whatever_the_capture_times() {
    let base = base();
    let frames: Vec<_> = (0..60_u8)
        .map(|i| {
            let key = i == 0;
            let at = if i == 1 {
                ms(base, 3_600_000)
            } else {
                ms(base, u64::from(i) * 40)
            };
            (
                Kind::Video,
                frame(at, i64::from(i) * FRAME, key, 0, h264_au(key, i)),
            )
        })
        .collect();
    let written = run(&mut Muxer::new(&policy(1000)), &h264_track(), None, &frames);
    assert_eq!(written.cuts, [25, 50], "as if every frame were on time");
    let dts: Vec<u64> = samples(&written.file, 1).iter().map(|s| s.dts).collect();
    let on_time: Vec<u64> = (0..60).map(|i| i * 3600).collect();
    assert_eq!(dts, on_time, "the epoch's timestamps time it");

    // Audio's decode time ends a fragment too, while no video comes.
    let mut frames = vec![(Kind::Video, frame(base, 0, true, 0, h264_au(true, 0)))];
    for i in 0..60_u8 {
        let at = ms(base, 20 * u64::from(i));
        frames.push((
            Kind::Audio,
            frame(at, 960 * i64::from(i), true, 0, opus_packet(i)),
        ));
    }
    let written = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        Some(&opus_track(1)),
        &frames,
    );
    // Cut 0 is the keyframe's own push, with nothing ready; the audio
    // frame at exactly 1 s (index 51) ends the first fragment.
    assert_eq!(written.cuts, [51]);
}

/// Each track's span counts on its own decode times, never against the
/// other track's, whose epochs are anchored apart. Regression: one shared
/// mark, set by the track whose frame last ended a fragment, so an audio
/// frame a Sender Report dated an hour ahead ended the fragment and moved
/// the mark an hour on, and the video after it, with no audio, never
/// reached it: only a keyframe ended a fragment again.
#[test]
fn each_track_s_span_counts_on_its_own_decode_times() {
    let base = base();
    let aac = Bytes::copy_from_slice(frames(SINE_16K_MONO)[0]);
    // One GOP of 2.4 s with an audio frame captured an hour ahead after its
    // second frame, then no audio.
    let mut frames: Vec<_> = (0..60_u8)
        .map(|i| {
            let key = i == 0;
            let at = ms(base, u64::from(i) * 40);
            (
                Kind::Video,
                frame(at, i64::from(i) * FRAME, key, 0, h264_au(key, i)),
            )
        })
        .collect();
    let ahead = frame(ms(base, 3_600_000), 0, true, 0, aac);
    frames.insert(2, (Kind::Audio, ahead));
    let written = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );
    // The video frames at 1 s and 2 s end the fragments before them, as
    // without the audio; the audio frame starts its own span.
    assert_eq!(written.cuts, [26, 51]);

    // The other way round: a video epoch an hour ahead, then audio alone.
    let mut frames = vec![
        (Kind::Video, frame(base, 0, true, 0, h264_au(true, 0))),
        (
            Kind::Video,
            frame(ms(base, 3_600_000), 0, true, 1, h264_au(true, 1)),
        ),
    ];
    for i in 0..110_u8 {
        let at = ms(base, 20 * u64::from(i));
        frames.push((
            Kind::Audio,
            frame(at, 960 * i64::from(i), true, 0, opus_packet(i)),
        ));
    }
    let written = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        Some(&opus_track(1)),
        &frames,
    );
    // The new epoch ends the first fragment; the audio at 1 s and 2 s,
    // counted from its own first frame, the next two.
    assert_eq!(written.cuts, [1, 52, 102]);
}

/// What a video sample of `units` NAL units from a frame of `payload`
/// bytes holds: the payload, a 4-byte length and two piece descriptors per
/// unit, and its own descriptor.
fn holds(payload: usize, units: usize) -> u64 {
    u64::try_from(payload + units * (4 + 2 * size_of::<Bytes>()) + size_of::<Sample>()).unwrap()
}

/// `count` video frames of `au` at 25 fps, the first a keyframe, under a
/// span far above them and a fragment bound of `fragment_bytes`: which
/// pushes completed a fragment.
fn cuts_at_the_bound(au: &Bytes, count: u8, fragment_bytes: u64) -> Written {
    let base = base();
    let frames: Vec<_> = (0..count)
        .map(|i| {
            (
                Kind::Video,
                frame(
                    ms(base, u64::from(i) * 40),
                    i64::from(i) * FRAME,
                    i == 0,
                    0,
                    au.clone(),
                ),
            )
        })
        .collect();
    let mut muxer = Muxer {
        limits: Limits {
            sample_bytes: MAX_SAMPLE_BYTES,
            fragment_bytes,
        },
        ..Muxer::new(&policy(10_000))
    };
    run(&mut muxer, &h264_track(), None, &frames)
}

/// Audio that goes on while video stalls ends a fragment a span after
/// its own first frame in it, not a span after the decode time of the
/// keyframe that began the fragment, which reordering puts after its
/// capture time. Regression: after `I0 P3 B1 B2 P6 B4 B5` at 25 fps, the
/// keyframe captured at 280 ms is decoded at 400 ms; that began the one
/// span mark both tracks shared, so with no more video the audio ended
/// the fragment only at its frame at 1408 ms, the first a second after
/// 400 ms.
#[test]
fn audio_after_a_reordered_gop_ends_the_fragment_a_span_after_its_own_first_frame() {
    let base = base();
    let aac = Bytes::copy_from_slice(frames(SINE_16K_MONO)[0]);
    // AAC frame `i`, 64 ms each.
    let audio = |i: u16| {
        let at = ms(base, u64::from(i) * 64);
        (
            Kind::Audio,
            frame(at, i64::from(i) * 1024, true, 0, aac.clone()),
        )
    };
    let mut frames = reordered_gop(base, 0, 0, 0);
    frames.extend((0..5).map(audio));
    // The next keyframe, in the same epoch: captured at 280 ms, decoded at
    // 400 ms after the reordering. Then the video stalls.
    let keyframe = frame(ms(base, 280), 7 * FRAME, true, 0, h264_au(true, 7));
    frames.push((Kind::Video, keyframe));
    frames.extend((5..25).map(audio));
    let written = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );
    let video = samples(&written.file, 1);
    assert_eq!((video[7].dts, video[7].cts), (36_000, -10_800));
    // The keyframe ends the first fragment; the audio's span then counts
    // from its first frame after it, at 320 ms, so its frame at 1344 ms,
    // the first a second later, ends the second.
    assert_eq!(written.cuts, [12, 29]);
    let (_, cutting) = &frames[29];
    assert_eq!(cutting.wallclock - base, Duration::from_millis(1344));
}

#[test]
fn fragments_end_once_what_their_samples_hold_reaches_the_bound() {
    // Samples of 25 bytes: a 4-byte length and a 21-byte unit.
    let au = annex_b(&[&[0x41; 21]]);
    let written = cuts_at_the_bound(&au, 10, 4 * holds(au.len(), 1));
    // Four samples reach the bound: the fifth frame's push ends the fragment.
    assert_eq!(written.cuts, [4, 8]);
    let samples = samples(&written.file, 1);
    assert!(samples.iter().all(|s| s.bytes.len() == 25));
    assert_eq!(MAX_FRAGMENT_BYTES, 1 << 30);
}

/// A frame of many tiny NAL units counts the descriptors of its pieces,
/// not only its media data. Regression: a sample counted only its bytes,
/// so a 4 MiB access unit of one-byte units, 838 860 of them, counted
/// 4 MiB against the 1 GiB bound while it held 54 MiB more in its
/// pieces' descriptors and lengths: a fragment of such frames, which
/// constant timestamps keep from its span, held about 15 GiB.
#[test]
fn a_frame_of_many_tiny_nal_units_counts_what_it_holds_against_the_bound() {
    let units = vec![[0x41_u8]; 1000];
    let units: Vec<&[u8]> = units.iter().map(<[u8; 1]>::as_slice).collect();
    let au = annex_b(&units);
    // 5000 bytes of media in each sample, 64 000 of descriptors.
    assert_eq!(au.len(), 5000);
    let written = cuts_at_the_bound(&au, 10, 2 * holds(au.len(), 1000));
    assert_eq!(written.cuts, [2, 4, 6, 8]);
    let samples = samples(&written.file, 1);
    assert!(samples.iter().all(|s| s.bytes.len() == 5000));
}

#[test]
fn a_new_epoch_starts_a_fragment_at_its_capture_time_leaving_the_hole() {
    let base = base();
    let frames = [
        (Kind::Video, frame(base, 0, true, 0, h264_au(true, 0))),
        (
            Kind::Video,
            frame(ms(base, 40), FRAME, false, 0, h264_au(false, 1)),
        ),
        (
            Kind::Video,
            frame(ms(base, 80), 2 * FRAME, false, 0, h264_au(false, 2)),
        ),
        // The camera reconnected 3 s in; its timestamps start over.
        (
            Kind::Video,
            frame(ms(base, 3000), 500, false, 1, h264_au(false, 3)),
        ),
        (
            Kind::Video,
            frame(ms(base, 3040), 500 + FRAME, false, 1, h264_au(false, 4)),
        ),
    ];
    let written = run(
        &mut Muxer::new(&policy(10_000)),
        &h264_track(),
        None,
        &frames,
    );
    assert_eq!(written.cuts, [3], "the new epoch's frame begins a fragment");
    let timing: Vec<(usize, u64, u32)> = samples(&written.file, 1)
        .iter()
        .map(|s| (s.fragment, s.dts, s.duration))
        .collect();
    assert_eq!(
        timing,
        [
            (0, 0, 3600),
            (0, 3600, 3600),
            (0, 7200, 3600),
            (1, 270_000, 3600),
            (1, 273_600, 3600)
        ]
    );

    // A capture time before the track's last sample began does not go
    // back: the epoch starts where that sample ends.
    let frames = [
        (Kind::Video, frame(base, 0, true, 0, h264_au(true, 0))),
        (
            Kind::Video,
            frame(ms(base, 40), FRAME, false, 0, h264_au(false, 1)),
        ),
        (
            Kind::Video,
            frame(ms(base, 30), 0, true, 1, h264_au(true, 2)),
        ),
    ];
    let written = run(
        &mut Muxer::new(&policy(10_000)),
        &h264_track(),
        None,
        &frames,
    );
    let dts: Vec<u64> = samples(&written.file, 1).iter().map(|s| s.dts).collect();
    assert_eq!(dts, [0, 3600, 7200]);
}

/// A new epoch captured after the track's last sample began but before it
/// ended, a reconnect quicker than a frame, starts at its capture time:
/// that sample is cut short to meet it (ISO/IEC 14496-12 §8.8.12: the
/// fragment's `tfdt` is the capture time), so the track keeps its capture
/// times, in sync with the other track, and a gap the clip reports from
/// capture times is where the file has it. The next epoch's last sample
/// takes the uncut duration. Regression: the end-to-end clip test's
/// camera reconnected within 4 ms of its last frame, and the file resumed
/// 36 ms after the gap's end, the rest of the video that much late.
#[test]
fn iso14496_12_8_8_12_an_epoch_inside_the_last_sample_cuts_it_short_at_its_capture_time() {
    let base = base();
    let frames = [
        (Kind::Video, frame(base, 0, true, 0, h264_au(true, 0))),
        (
            Kind::Video,
            frame(ms(base, 40), FRAME, false, 0, h264_au(false, 1)),
        ),
        // The camera is back 10 ms later, its timestamps started over.
        (
            Kind::Video,
            frame(ms(base, 50), 0, true, 1, h264_au(true, 2)),
        ),
    ];
    let written = run(
        &mut Muxer::new(&policy(10_000)),
        &h264_track(),
        None,
        &frames,
    );
    assert_eq!(written.cuts, [2], "the new epoch's frame begins a fragment");
    let timing: Vec<(u64, u32)> = samples(&written.file, 1)
        .iter()
        .map(|s| (s.dts, s.duration))
        .collect();
    assert_eq!(timing, [(0, 3600), (3600, 900), (4500, 3600)]);
}

/// Decode order `I0 P3 B1 B2 P6 B4 B5` of `epoch`, its timestamps from 0
/// and its payloads numbered from `first`, each frame captured at its
/// presentation, from `at_ms` on at 25 fps.
fn reordered_gop(base: Instant, at_ms: u64, epoch: u32, first: u8) -> Vec<(Kind, Arc<MediaFrame>)> {
    gop(&[0, 3, 1, 2, 6, 4, 5], base, at_ms, epoch, first)
}

/// [`reordered_gop`] in decode `order` (frame numbers, 0 the keyframe).
fn gop(
    order: &[u8],
    base: Instant,
    at_ms: u64,
    epoch: u32,
    first: u8,
) -> Vec<(Kind, Arc<MediaFrame>)> {
    order
        .iter()
        .map(|&n| {
            let at = ms(base, at_ms + u64::from(n) * 40);
            let payload = h264_au(n == 0, first + n);
            (
                Kind::Video,
                frame(at, i64::from(n) * FRAME, n == 0, epoch, payload),
            )
        })
        .collect()
}

/// A new epoch after reordered video is presented at its capture time,
/// in sync with the audio that goes on: its decode times start where the
/// last sample's decode ends, after its capture time, and each of its
/// samples carries the difference in its composition offset (ISO/IEC
/// 14496-12 §8.8.8.1, `trun` version 1). Regression: the epoch captured at
/// 280 ms after `I0 P3 B1 B2 P6 B4 B5` at 25 fps was presented at 400 ms,
/// where B5's decode ended, and the rest of the video 120 ms behind the
/// audio.
#[test]
fn iso14496_12_8_8_8_1_an_epoch_after_reordered_video_is_presented_at_its_capture_time() {
    let base = base();
    let aac = frames(SINE_16K_MONO);
    // AAC frame `n` of `epoch`, its `i`th: 64 ms each from `first_ms` on.
    let audio = |n: usize, epoch: u32, i: u16, first_ms: u64| {
        let at = ms(base, first_ms + u64::from(i) * 64);
        let payload = Bytes::copy_from_slice(aac[n]);
        (
            Kind::Audio,
            frame(at, i64::from(i) * 1024, true, epoch, payload),
        )
    };
    // The camera's timestamps start over 280 ms in, without a hole: the
    // next GOP and the next audio frame are captured where the last end.
    let mut frames = reordered_gop(base, 0, 0, 0);
    frames.extend((0..5).map(|i| audio(usize::from(i), 0, i, 0)));
    frames.extend(reordered_gop(base, 280, 1, 7));
    frames.extend((0..3).map(|i| audio(usize::from(5 + i), 1, i, 320)));
    let written = run(
        &mut Muxer::new(&policy(10_000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );

    // Every sample of both tracks is presented at its capture time.
    let captured = |kind: Kind| -> Vec<u64> {
        frames
            .iter()
            .filter(|(pushed, _)| *pushed == kind)
            .map(|(_, frame)| u64::try_from((frame.wallclock - base).as_millis()).unwrap())
            .collect()
    };
    let presented = |track_id: u32, rate: i64| -> Vec<u64> {
        samples(&written.file, track_id)
            .iter()
            .map(|s| {
                let ticks = i64::try_from(s.dts).unwrap() + i64::from(s.cts);
                u64::try_from(ticks * 1000 / rate).unwrap()
            })
            .collect()
    };
    assert_eq!(presented(1, 90_000), captured(Kind::Video));
    assert_eq!(presented(2, 16_000), captured(Kind::Audio));
    // The new epoch's I0 is decoded where B5's decode ends (400 ms) and
    // presented at its capture time (280 ms); its P3, still in order,
    // keeps that offset.
    let video = samples(&written.file, 1);
    let timing: Vec<(u64, i32)> = video[7..9].iter().map(|s| (s.dts, s.cts)).collect();
    assert_eq!(timing, [(36_000, -10_800), (46_800, -10_800)]);
    // Decode times never go back.
    assert!(
        video
            .windows(2)
            .all(|pair| pair[0].dts + u64::from(pair[0].duration) <= pair[1].dts)
    );
}

/// An epoch after a reordered GOP whose last frame in presentation order
/// was decoded two frames before the next is presented at its capture
/// time too: that frame is shown for the epoch's nominal frame duration,
/// not for the step of its decode time, which the frames after it stretch
/// over the reordering (ISO/IEC 14496-12 §8.8.8.1). Regression: after
/// `I0 P3 B1 B2` at 25 fps, P3, decoded at 120 ms and B1 at 200 ms, was
/// taken as shown until 200 ms, so the epoch captured at 160 ms, where
/// the four pictures end, was presented at 200 ms, and the rest of the
/// video 40 ms behind the audio.
#[test]
fn iso14496_12_8_8_8_1_an_epoch_after_a_short_reordered_gop_is_presented_at_its_capture_time() {
    let base = base();
    let aac = frames(SINE_16K_MONO);
    // AAC frame `i` of the audio's one epoch: 64 ms each.
    let audio = |i: u16| {
        let at = ms(base, u64::from(i) * 64);
        let payload = Bytes::copy_from_slice(aac[usize::from(i)]);
        (
            Kind::Audio,
            frame(at, i64::from(i) * 1024, true, 0, payload),
        )
    };
    // The camera's timestamps start over 160 ms in, without a hole; the
    // audio goes on.
    let mut frames = gop(&[0, 3, 1, 2], base, 0, 0, 0);
    frames.extend((0..3).map(audio));
    frames.extend(gop(&[0, 3, 1, 2], base, 160, 1, 4));
    frames.extend((3..6).map(audio));
    let written = run(
        &mut Muxer::new(&policy(10_000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );

    // Every sample of both tracks is presented at its capture time.
    let captured = |kind: Kind| -> Vec<u64> {
        frames
            .iter()
            .filter(|(pushed, _)| *pushed == kind)
            .map(|(_, frame)| u64::try_from((frame.wallclock - base).as_millis()).unwrap())
            .collect()
    };
    let presented = |track_id: u32, rate: i64| -> Vec<u64> {
        samples(&written.file, track_id)
            .iter()
            .map(|s| {
                let ticks = i64::try_from(s.dts).unwrap() + i64::from(s.cts);
                u64::try_from(ticks * 1000 / rate).unwrap()
            })
            .collect()
    };
    assert_eq!(presented(1, 90_000), captured(Kind::Video));
    assert_eq!(presented(2, 16_000), captured(Kind::Audio));
    // P3 still lasts its decode step of 80 ms; the new epoch's I0 is
    // decoded where B2's decode ends (280 ms) and presented at 160 ms.
    let video = samples(&written.file, 1);
    let timing: Vec<(u64, u32, i32)> = video.iter().map(|s| (s.dts, s.duration, s.cts)).collect();
    assert_eq!(
        [timing[1], timing[4]],
        [(10_800, 7200, 0), (25_200, 10_800, -10_800)]
    );
}

/// The presentation times of `file`'s track `track_id`, in its ticks: each
/// sample's decode time plus its composition offset.
fn presented_ticks(file: &[u8], track_id: u32) -> Vec<i64> {
    samples(file, track_id)
        .iter()
        .map(|s| i64::try_from(s.dts).unwrap() + i64::from(s.cts))
        .collect()
}

/// The capture times of `frames` of `kind` after `base`, in ticks of `rate`.
fn captured_ticks(
    frames: &[(Kind, Arc<MediaFrame>)],
    base: Instant,
    kind: Kind,
    rate: i64,
) -> Vec<i64> {
    frames
        .iter()
        .filter(|(pushed, _)| *pushed == kind)
        .map(|(_, frame)| {
            i64::try_from((frame.wallclock - base).as_millis()).unwrap() * rate / 1000
        })
        .collect()
}

/// An epoch after a reordered GOP cut short before any two pictures
/// decoded one after the other are a frame apart is presented at its
/// capture time too: the GOP's frame duration is the smallest distance
/// between any two of its presentation times, here B1's from I0, not only
/// between consecutive ones in decode order (ISO/IEC 14496-12 §8.8.8.1).
/// Regression: after `I0 P3 B1` at 25 fps, whose consecutive timestamps
/// are 120 ms and 80 ms apart, P3 was taken as shown until 200 ms, so the
/// epoch captured at 160 ms, where P3 ends, was presented at 200 ms, and
/// the rest of the video 40 ms behind the audio.
#[test]
fn iso14496_12_8_8_8_1_an_epoch_after_a_gop_cut_before_b2_is_presented_at_its_capture_time() {
    let base = base();
    let aac = frames(SINE_16K_MONO);
    // AAC frame `i` of the audio's one epoch: 64 ms each.
    let audio = |i: u16| {
        let at = ms(base, u64::from(i) * 64);
        let payload = Bytes::copy_from_slice(aac[usize::from(i)]);
        (
            Kind::Audio,
            frame(at, i64::from(i) * 1024, true, 0, payload),
        )
    };
    // The camera reconnects before B2 arrives; its timestamps start over
    // 160 ms in, where P3 ends, and the audio goes on.
    let mut frames = gop(&[0, 3, 1], base, 0, 0, 0);
    frames.extend((0..3).map(audio));
    frames.extend(gop(&[0, 3, 1, 2], base, 160, 1, 3));
    frames.extend((3..6).map(audio));
    let written = run(
        &mut Muxer::new(&policy(10_000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );

    // Every sample of both tracks is presented at its capture time.
    assert_eq!(
        presented_ticks(&written.file, 1),
        captured_ticks(&frames, base, Kind::Video, 90_000)
    );
    assert_eq!(
        presented_ticks(&written.file, 2),
        captured_ticks(&frames, base, Kind::Audio, 16_000)
    );
    // The new epoch's I0 is decoded where B1's decode ends (280 ms) and
    // presented at 160 ms.
    let video = samples(&written.file, 1);
    assert_eq!((video[3].dts, video[3].cts), (25_200, -10_800));
}

/// An epoch after any part of a reordered GOP, a reconnect at any point of
/// its decode order, is presented at its capture time whenever that is
/// where or after the GOP's last picture ends, a frame after it at 25 fps,
/// and decode times never go back (ISO/IEC 14496-12 §8.8.8.1): whichever
/// pictures the GOP lost, two of the ones it kept a frame apart give its
/// frame duration. Regression: `I0 P3 B1`, of both GOPs, ended at 200 ms.
#[test]
fn iso14496_12_8_8_8_1_an_epoch_after_any_part_of_a_reordered_gop_is_presented_at_its_capture_time()
{
    let base = base();
    // (GOP length, frames kept, capture time, where the epoch was
    // presented) of each new epoch presented elsewhere than captured.
    let mut misplaced = Vec::new();
    for order in [&[0, 3, 1, 2, 6, 4, 5][..], &[0, 3, 1, 2]] {
        for kept in 1..=order.len() {
            let gop_part = &order[..kept];
            let ends = u64::from(*gop_part.iter().max().unwrap()) * 40 + 40;
            for capture_ms in (ends..=ends + 80).step_by(10) {
                let mut frames = gop(gop_part, base, 0, 0, 0);
                frames.extend(gop(&[0, 3, 1, 2], base, capture_ms, 1, 10));
                let written = run(
                    &mut Muxer::new(&policy(10_000)),
                    &h264_track(),
                    None,
                    &frames,
                );
                let presented = presented_ticks(&written.file, 1);
                if presented != captured_ticks(&frames, base, Kind::Video, 90_000) {
                    misplaced.push((order.len(), kept, capture_ms, presented[kept] / 90));
                }
                let video = samples(&written.file, 1);
                assert!(
                    video
                        .windows(2)
                        .all(|pair| pair[0].dts + u64::from(pair[0].duration) <= pair[1].dts),
                    "decode times go back after {kept} of {order:?}, captured at {capture_ms} ms"
                );
            }
        }
    }
    assert_eq!(misplaced, []);
}

/// The frame duration of a GOP comes from the presentation times of its 17
/// latest pictures, which hold the neighbours of each new one as long as at
/// most 16 pictures decoded before it are presented after it: all H.264
/// allows (§E.2.1: `num_reorder_frames` at most `max_dec_frame_buffering`;
/// §A.3.1: at most `MaxDpbFrames`, at most 16) and more than H.265 does
/// (§7.4.3.2.1, §A.4.2: at most 15). Deeper reordering finds a longer one,
/// and what the muxer keeps stays bounded.
#[test]
fn h264_e_2_1_a_gop_s_frame_duration_comes_from_as_many_pictures_as_it_may_reorder() {
    let base = base();
    // I0, then `deep` pictures 80 ms apart, then a B-frame 20 ms after I0,
    // decoded after them all, and the next epoch captured 20 ms after the
    // last picture: where that epoch is presented, in ms.
    let presented = |deep: u8| -> i64 {
        let mut frames = vec![(Kind::Video, frame(base, 0, true, 0, h264_au(true, 0)))];
        frames.extend((1..=deep).map(|n| {
            let at = ms(base, u64::from(n) * 80);
            let ts = i64::from(n) * 2 * FRAME;
            (Kind::Video, frame(at, ts, false, 0, h264_au(false, n)))
        }));
        frames.push((
            Kind::Video,
            frame(ms(base, 20), FRAME / 2, false, 0, h264_au(false, 100)),
        ));
        let capture = ms(base, u64::from(deep) * 80 + 20);
        frames.push((Kind::Video, frame(capture, 0, true, 1, h264_au(true, 101))));
        let written = run(
            &mut Muxer::new(&policy(100_000)),
            &h264_track(),
            None,
            &frames,
        );
        presented_ticks(&written.file, 1).last().unwrap() / 90
    };
    // 16 deep: the B-frame's distance from I0, 20 ms, is the frame
    // duration, so the last picture ends 20 ms after it.
    assert_eq!(presented(16), 16 * 80 + 20);
    // 17 deep: I0 is no longer kept, and the B-frame's distance from the
    // picture after it, 60 ms, is the shortest the muxer sees.
    assert_eq!(presented(17), 17 * 80 + 60);
}

/// Consecutive reconnects after reordered video keep the video at its
/// capture times, in sync with the audio that goes on: an epoch captured
/// inside the presentation of the last sample, an epoch's only frame here,
/// cuts that sample short where its presentation, its decode time plus its
/// composition offset (ISO/IEC 14496-12 §8.8.8.1), meets the next epoch,
/// not its decode time, which its epoch's lead puts later. Regression: the
/// epoch captured at 280 ms after `I0 P3 B1 B2 P6 B4 B5` at 25 fps was
/// decoded at 400 ms, so a reconnect at 290 ms, measured against that,
/// left its frame uncut and the next epoch presented at 320 ms, 30 ms
/// behind the audio.
#[test]
fn iso14496_12_8_8_8_1_consecutive_reconnects_after_reordered_video_keep_the_capture_times() {
    let base = base();
    let aac = frames(SINE_16K_MONO);
    // AAC frame `n` of `epoch`, its `i`th: 64 ms each from `first_ms` on.
    let audio = |n: usize, epoch: u32, i: u16, first_ms: u64| {
        let at = ms(base, first_ms + u64::from(i) * 64);
        let payload = Bytes::copy_from_slice(aac[n]);
        (
            Kind::Audio,
            frame(at, i64::from(i) * 1024, true, epoch, payload),
        )
    };
    // The camera reconnects 280 ms in, sends one keyframe and reconnects
    // again 10 ms later; the audio goes on from 320 ms.
    let mut frames = reordered_gop(base, 0, 0, 0);
    frames.extend((0..5).map(|i| audio(usize::from(i), 0, i, 0)));
    frames.push((
        Kind::Video,
        frame(ms(base, 280), 0, true, 1, h264_au(true, 7)),
    ));
    frames.extend(reordered_gop(base, 290, 2, 8));
    frames.extend((0..3).map(|i| audio(usize::from(5 + i), 1, i, 320)));
    let written = run(
        &mut Muxer::new(&policy(10_000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );

    // Every sample of both tracks is presented at its capture time.
    let captured = |kind: Kind| -> Vec<u64> {
        frames
            .iter()
            .filter(|(pushed, _)| *pushed == kind)
            .map(|(_, frame)| u64::try_from((frame.wallclock - base).as_millis()).unwrap())
            .collect()
    };
    let presented = |track_id: u32, rate: i64| -> Vec<u64> {
        samples(&written.file, track_id)
            .iter()
            .map(|s| {
                let ticks = i64::try_from(s.dts).unwrap() + i64::from(s.cts);
                u64::try_from(ticks * 1000 / rate).unwrap()
            })
            .collect()
    };
    assert_eq!(presented(1, 90_000), captured(Kind::Video));
    assert_eq!(presented(2, 16_000), captured(Kind::Audio));
    // The lone keyframe, decoded at 400 ms and presented at 280 ms, lasts
    // the 10 ms until the next epoch; that epoch's I0 is decoded where the
    // keyframe's decode ends and presented at 290 ms.
    let video = samples(&written.file, 1);
    let timing: Vec<(u64, u32, i32)> = video[7..9]
        .iter()
        .map(|s| (s.dts, s.duration, s.cts))
        .collect();
    assert_eq!(timing, [(36_000, 900, -10_800), (36_900, 10_800, -10_800)]);
    // Decode times never go back.
    assert!(
        video
            .windows(2)
            .all(|pair| pair[0].dts + u64::from(pair[0].duration) <= pair[1].dts)
    );
}

/// Where a new epoch after reordered video begins, by its capture time:
/// the media time the muxer reports for its first frame (ISO/IEC 14496-12
/// §8.8.12), and that frame's decode time and composition offset
/// (§8.8.8.1). The last presented frame, P6, ends at 280 ms, the last
/// decoded, B5, at 400 ms.
#[test]
fn iso14496_12_8_8_8_1_a_new_epoch_is_presented_no_earlier_than_the_last_frame_ends() {
    let base = base();
    // The new epoch's first frame captured at `capture_ms`, and `more`
    // frames after it with its timestamp: where the muxer reports the
    // first, and each one's decode time and composition offset.
    let epoch = |capture_ms: u64, more: u8| -> (Duration, Vec<(u64, i32)>) {
        let mut muxer = Muxer::new(&policy(10_000));
        let mut file: Vec<u8> = muxer.start(&h264_track(), None).unwrap().concat();
        for (kind, frame) in reordered_gop(base, 0, 0, 0) {
            file.extend(muxer.push(kind, frame).unwrap().concat());
        }
        let first = frame(ms(base, capture_ms), 0, true, 1, h264_au(true, 7));
        file.extend(muxer.push(Kind::Video, first).unwrap().concat());
        let media_time = muxer.media_time(Kind::Video);
        for n in 0..more {
            let next = frame(ms(base, capture_ms), 0, false, 1, h264_au(false, 8 + n));
            file.extend(muxer.push(Kind::Video, next).unwrap().concat());
        }
        file.extend(muxer.finish().unwrap().concat());
        let timing = samples(&file, 1)[7..]
            .iter()
            .map(|s| (s.dts, s.cts))
            .collect();
        (media_time, timing)
    };
    let first = |capture_ms: u64| {
        let (media_time, timing) = epoch(capture_ms, 0);
        (media_time, timing[0].0, timing[0].1)
    };
    // Captured where P6 ends: presented there, decoded where B5 ends.
    assert_eq!(first(280), (Duration::from_millis(280), 36_000, -10_800));
    // Captured between the two ends.
    assert_eq!(first(360), (Duration::from_millis(360), 36_000, -3600));
    // Captured inside P6: presented where it ends, not over it.
    assert_eq!(first(200), (Duration::from_millis(280), 36_000, -10_800));
    // Captured inside B5, the last decoded, whose presentation P6 outlasts:
    // B5 is not cut, the epoch presented where P6 ends.
    assert_eq!(first(210), (Duration::from_millis(280), 36_000, -10_800));
    // Captured after B5's decode ends: decoded where presented.
    assert_eq!(first(1000), (Duration::from_millis(1000), 90_000, 0));
    // A frame repeating the first's timestamp is decoded a tick after it,
    // after B5's decode too.
    assert_eq!(epoch(280, 1).1, [(36_000, -10_800), (36_001, -10_801)]);
}

/// The media time the muxer gives the latest frame of a track is its
/// presentation time from the clip's origin, where the file has it (ISO/IEC
/// 14496-12 §8.8.12), an epoch moved off its capture time included; zero
/// before the first frame, for a track the clip lacks, and outside a clip.
#[test]
fn iso14496_12_8_8_12_the_media_time_is_where_the_latest_frame_of_a_track_is() {
    let base = base();
    let mut muxer = Muxer::new(&policy(10_000));
    assert_eq!(muxer.media_time(Kind::Video), Duration::ZERO, "no clip yet");
    muxer.start(&h264_track(), None).unwrap();
    assert_eq!(
        muxer.media_time(Kind::Video),
        Duration::ZERO,
        "no frame yet"
    );
    for (at, ts, key, epoch, index) in [(0, 0, true, 0, 0), (40, FRAME, false, 0, 1)] {
        let payload = h264_au(key, index);
        muxer
            .push(Kind::Video, frame(ms(base, at), ts, key, epoch, payload))
            .unwrap();
    }
    assert_eq!(muxer.media_time(Kind::Video), Duration::from_millis(40));
    // Captured before the last frame began: it starts where that one ends.
    let payload = h264_au(true, 2);
    muxer
        .push(Kind::Video, frame(ms(base, 30), 0, true, 1, payload))
        .unwrap();
    assert_eq!(muxer.media_time(Kind::Video), Duration::from_millis(80));
    assert_eq!(muxer.media_time(Kind::Audio), Duration::ZERO, "no audio");
    muxer.finish().unwrap();
    assert_eq!(muxer.media_time(Kind::Video), Duration::ZERO, "finished");

    let aac = frames(SINE_16K_MONO);
    let mut muxer = Muxer::new(&policy(10_000));
    muxer.start(&h264_track(), Some(&aac_track())).unwrap();
    muxer
        .push(Kind::Video, frame(base, 0, true, 0, h264_au(true, 0)))
        .unwrap();
    let payload = Bytes::copy_from_slice(aac[0]);
    muxer
        .push(Kind::Audio, frame(ms(base, 64), 0, true, 0, payload))
        .unwrap();
    assert_eq!(muxer.media_time(Kind::Audio), Duration::from_millis(64));
    // Ticks to time: nothing before 0 or at no rate, the longest past it.
    assert_eq!(duration_of(-1, 90_000), Duration::ZERO);
    assert_eq!(duration_of(90_000, 0), Duration::ZERO);
    assert_eq!(duration_of(i128::MAX, 1), Duration::MAX);
}

#[test]
fn audio_whose_timestamp_does_not_advance_starts_a_new_epoch() {
    let base = base();
    let aac = frames(SINE_16K_MONO);
    let audio = |at: u64, ts: i64, n: usize| {
        (
            Kind::Audio,
            frame(ms(base, at), ts, true, 0, Bytes::copy_from_slice(aac[n])),
        )
    };
    let frames = [
        (Kind::Video, frame(base, 0, true, 0, h264_au(true, 0))),
        audio(0, 0, 0),
        audio(64, 1024, 1),
        // The same timestamp again, 200 ms in.
        audio(200, 1024, 2),
        audio(264, 2048, 3),
    ];
    let written = run(
        &mut Muxer::new(&policy(10_000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );
    assert_eq!(written.cuts, [3]);
    let dts: Vec<(u64, u32)> = samples(&written.file, 2)
        .iter()
        .map(|s| (s.dts, s.duration))
        .collect();
    // 200 ms at 16 kHz is 3200.
    assert_eq!(dts, [(0, 1024), (1024, 1024), (3200, 1024), (4224, 1024)]);
}

#[test]
fn the_origin_is_the_first_frame_so_audio_captured_before_the_first_keyframe_starts_at_0() {
    let base = base();
    let aac = frames(SINE_16K_MONO);
    let frames = [
        (
            Kind::Audio,
            frame(base, 0, true, 0, Bytes::copy_from_slice(aac[0])),
        ),
        (
            Kind::Video,
            frame(ms(base, 16), 0, true, 0, h264_au(true, 0)),
        ),
        (
            Kind::Audio,
            frame(ms(base, 64), 1024, true, 0, Bytes::copy_from_slice(aac[1])),
        ),
    ];
    let written = run(
        &mut Muxer::new(&policy(1000)),
        &h264_track(),
        Some(&aac_track()),
        &frames,
    );
    assert_eq!(samples(&written.file, 2)[0].dts, 0);
    // 16 ms at 90 kHz.
    assert_eq!(samples(&written.file, 1)[0].dts, 1440);
}

/// A track's last sample, which no frame follows, lasts its frame's own
/// length where the codec states one, else the duration of the one
/// before it. Regression: an Opus packet of 40 ms after one of 20 ms
/// ended 20 ms early, at the length of the one before it.
#[test]
fn rfc6716_3_1_a_last_sample_takes_its_frame_length_else_the_duration_before_it() {
    let base = base();
    let last = |video: ClipTrack, audio: Option<(ClipTrack, Vec<Bytes>)>, video_frames: u8| {
        let mut frames: Vec<_> = (0..video_frames)
            .map(|i| {
                let key = i == 0;
                let at = ms(base, 40 * u64::from(i));
                (
                    Kind::Video,
                    frame(at, FRAME * i64::from(i), key, 0, h264_au(key, i)),
                )
            })
            .collect();
        let track = audio.as_ref().map(|(track, _)| track.clone());
        for (i, payload) in (0_u8..).zip(audio.into_iter().flat_map(|(_, payloads)| payloads)) {
            let at = ms(base, 20 * u64::from(i));
            frames.push((Kind::Audio, frame(at, 960 * i64::from(i), true, 0, payload)));
        }
        let written = run(
            &mut Muxer::new(&policy(1000)),
            &video,
            track.as_ref(),
            &frames,
        );
        let id = if track.is_some() { 2 } else { 1 };
        samples(&written.file, id).last().unwrap().duration
    };
    // Video alone in its track: one frame at 30 fps.
    assert_eq!(last(h264_track(), None, 1), 3000);
    assert_eq!(last(h264_track(), None, 2), 3600);
    // AAC: 1024 samples at its rate, on the track's clock.
    let one_aac = vec![Bytes::copy_from_slice(frames(SINE_16K_MONO)[0])];
    assert_eq!(
        last(h264_track(), Some((aac_track(), one_aac.clone())), 1),
        1024
    );
    let doubled = ClipTrack {
        codec: aac_codec(16_000),
        clock_rate: 32_000,
    };
    assert_eq!(last(h264_track(), Some((doubled, one_aac)), 1), 2048);
    // Its own 1024 samples, not the 960 ticks to it from the one before.
    let two_aac: Vec<Bytes> = frames(SINE_16K_MONO)[..2]
        .iter()
        .map(|frame| Bytes::copy_from_slice(frame))
        .collect();
    assert_eq!(last(h264_track(), Some((aac_track(), two_aac)), 1), 1024);
    // Opus: the packet's duration (RFC 6716 §3.1), else a fallback frame.
    assert_eq!(
        last(h264_track(), Some((opus_track(1), vec![opus_packet(0)])), 1),
        960
    );
    assert_eq!(
        last(h264_track(), Some((opus_track(1), vec![Bytes::new()])), 1),
        1600
    );
    // A 40 ms packet (code 1: two 20 ms frames) after a 20 ms one: its
    // own 1920 ticks, not the 960 before it.
    let longer = vec![opus_packet(0), Bytes::from_static(&[0xf8 | 1, 1, 1])];
    assert_eq!(last(h264_track(), Some((opus_track(1), longer)), 1), 1920);
    // The one before it, when its packet states no length.
    let unknown = vec![opus_packet(0), Bytes::new()];
    assert_eq!(last(h264_track(), Some((opus_track(1), unknown)), 1), 960);
}

/// The video's last sample lasts until the frame the clip ends the video
/// at, which stays out of the file, would be decoded, where the clip ends
/// its audio: after a hole in the frames (every 100 ms through 0.9 s, the
/// next at 1.4 s) the video ends at 1.4 s, not a frame after 0.9 s
/// (ISO/IEC 14496-12 §8.8.8: a sample lasts until the next one's decode
/// time). A frame of another epoch, a reconnect, leaves the hole as the
/// finish does, and so does one whose duration would not fit its field;
/// outside a running clip nothing happens. Regression: the video ended at
/// 1 s, the last frame's length the one before it, and the audio the
/// clip ran on to 1.4 s played 0.4 s past the video's end.
#[test]
fn iso14496_12_8_8_8_the_video_s_last_sample_lasts_until_the_frame_it_ends_at() {
    let base = base();
    let tenth = 9_000;
    let video: Vec<_> = (0..10_u8)
        .map(|i| {
            let key = i == 0;
            let at = ms(base, 100 * u64::from(i));
            (
                Kind::Video,
                frame(at, tenth * i64::from(i), key, 0, h264_au(key, i)),
            )
        })
        .collect();
    let last = |end: Option<Arc<MediaFrame>>| {
        let mut muxer = Muxer::new(&policy(10_000));
        let mut file = Vec::new();
        for piece in muxer.start(&h264_track(), None).unwrap() {
            file.extend_from_slice(&piece);
        }
        for (kind, frame) in &video {
            for piece in muxer.push(*kind, Arc::clone(frame)).unwrap() {
                file.extend_from_slice(&piece);
            }
        }
        // Ends at its date: in order, or not on its timeline.
        if let Some(end) = end {
            assert_eq!(muxer.end_video(&end), end.wallclock);
        }
        for piece in muxer.finish().unwrap() {
            file.extend_from_slice(&piece);
        }
        let last = samples(&file, 1).pop().unwrap();
        (last.dts, last.duration)
    };
    let at_1400 =
        |ts: i64, epoch: u32| frame(ms(base, 1_400), ts, false, epoch, h264_au(false, 10));
    assert_eq!(last(None), (81_000, 9_000), "a frame after 0.9 s");
    assert_eq!(
        last(Some(at_1400(14 * tenth, 0))),
        (81_000, 45_000),
        "until 1.4 s"
    );
    assert_eq!(last(Some(at_1400(0, 1))), (81_000, 9_000), "another epoch");
    let far = 9 * tenth + (1 << 33);
    assert_eq!(last(Some(at_1400(far, 0))), (81_000, 9_000), "past 32 bits");

    let mut idle = Muxer::new(&policy(1000));
    assert_eq!(idle.end_video(&at_1400(0, 0)), ms(base, 1_400));
    assert!(matches!(idle.state, State::Idle));
}

/// Where the file's media ends counts the video's last sample until the
/// frame the clip ended the video at (ISO/IEC 14496-12 §8.8.8: a sample
/// lasts until the next one's decode time): video-only, every 100 ms from
/// 0 to 0.9 s and the end frame at 1.4 s (a camera that stalled), 1.4 s.
/// Before the end, the latest frame's start; reordered video, where its
/// last presented picture ends (`P6` of `I0 P3 B1 B2 P6 B4 B5` at 25 fps,
/// 280 ms, after `B5`'s start); audio, where its latest frame ends when
/// later, its length known before the finish writes it (ISO/IEC 14496-3
/// §4.4.1: an AAC-LC frame's 1024 samples; RFC 6716 §3.1: an Opus packet's
/// frames): an Opus packet of 20 ms at 300 ms, 320 ms, where the file's
/// audio ends; AAC from 960 ms with the video ending at 1 s, 1.024 s; a
/// GOP cut short, where its last presented sample's written duration ends
/// (`P3` of `I0 P3 B1 B2` ended at `P6`, 200 ms, not 160 ms); outside a
/// running clip, zero. Regressions: the clip reported 900 ms, the
/// last frame's start, for the file of 1.4 s; and 300 ms and 1 s, the
/// audio's last frame left out before the finish.
#[test]
fn iso14496_12_8_8_8_the_media_end_counts_the_video_s_last_sample_until_its_end_frame() {
    let base = base();
    let tenth = 9_000;
    let mut muxer = Muxer::new(&policy(10_000));
    assert_eq!(muxer.media_end(), Duration::ZERO, "idle");
    muxer.start(&h264_track(), None).unwrap();
    for i in 0..10_u8 {
        let key = i == 0;
        let at = ms(base, 100 * u64::from(i));
        let video = frame(at, tenth * i64::from(i), key, 0, h264_au(key, i));
        muxer.push(Kind::Video, video).unwrap();
    }
    assert_eq!(
        muxer.media_end(),
        Duration::from_millis(900),
        "before the end"
    );
    let end = frame(ms(base, 1_400), 14 * tenth, false, 0, h264_au(false, 10));
    assert_eq!(muxer.end_video(&end), end.wallclock);
    assert_eq!(
        muxer.media_end(),
        Duration::from_millis(1_400),
        "until 1.4 s"
    );
    muxer.finish().unwrap();
    assert_eq!(muxer.media_end(), Duration::ZERO, "finished");

    let mut reordered = Muxer::new(&policy(10_000));
    let mut file = Vec::new();
    for piece in reordered
        .start(&h264_track(), Some(&opus_track(1)))
        .unwrap()
    {
        file.extend_from_slice(&piece);
    }
    for (kind, frame) in reordered_gop(base, 0, 0, 0) {
        assert!(reordered.push(kind, frame).unwrap().is_empty());
    }
    assert_eq!(
        reordered.media_end(),
        Duration::from_millis(280),
        "P6's end"
    );
    let audio = frame(ms(base, 300), 0, true, 0, opus_packet(0));
    assert!(reordered.push(Kind::Audio, audio).unwrap().is_empty());
    assert_eq!(
        reordered.media_end(),
        Duration::from_millis(320),
        "the audio's, its 20 ms packet held"
    );
    // The file's media ends there too, once its last fragment is out.
    for piece in reordered.finish().unwrap() {
        file.extend_from_slice(&piece);
    }
    let opus = samples(&file, 2).pop().unwrap();
    assert_eq!((opus.dts, opus.duration), (14_400, 960));

    // AAC-LC at 16 kHz: video to 1 s, its last frame of 1024 samples from
    // 960 ms, the file's media to 1.024 s.
    let mut aac = Muxer::new(&policy(10_000));
    aac.start(&h264_track(), Some(&aac_track())).unwrap();
    for i in 0..10_u8 {
        let key = i == 0;
        let at = ms(base, 100 * u64::from(i));
        let video = frame(at, tenth * i64::from(i), key, 0, h264_au(key, i));
        aac.push(Kind::Video, video).unwrap();
    }
    let end = frame(ms(base, 1_000), 10 * tenth, false, 0, h264_au(false, 10));
    assert_eq!(aac.end_video(&end), end.wallclock);
    let audio = frame(ms(base, 960), 0, true, 0, Bytes::from_static(&[0x21; 8]));
    aac.push(Kind::Audio, audio).unwrap();
    assert_eq!(
        aac.media_end(),
        Duration::from_millis(1_024),
        "the AAC's, its 1024 samples held"
    );

    // A GOP cut short: P3 written 80 ms long, so the video ends at 200 ms.
    let mut cut = Muxer::new(&policy(10_000));
    cut.start(&h264_track(), None).unwrap();
    for (kind, frame) in gop(&[0, 3, 1, 2], base, 0, 0, 0) {
        cut.push(kind, frame).unwrap();
    }
    let p6 = frame(ms(base, 240), 6 * FRAME, false, 0, h264_au(false, 6));
    assert_eq!(cut.end_video(&p6), ms(base, 200));
    assert_eq!(
        cut.media_end(),
        Duration::from_millis(200),
        "P3's written end"
    );
}

/// Reordered video ended at a frame is presented until its last presented
/// picture ends, which is not where that frame is presented, and the muxer
/// says where on that frame's date, so the clip ends its audio there too
/// (ISO/IEC 14496-12 §8.8.8.1: a sample is presented at its decode time
/// plus its composition offset; its duration is a step of the decode
/// times). Short of it by the pictures presented between them, decoded
/// after it and so left out with it: `I0 P3 B1 B2 P6 B4 B5` at 25 fps
/// ended at `P9`, captured at 360 ms, is presented until 280 ms, where
/// `P6`, the last presented, ends. Past it when that frame is presented
/// before pictures that went in, as an end by arrival leaves out the first
/// to arrive after the clip's end: `I0 P3 B1 B2 P6 B4` ended at `B5`,
/// captured at 200 ms, is presented until 280 ms too. Either way the Opus
/// captured before 280 ms ends there with it. In order, `I0 P1 .. P6` ended
/// at `P9` after a hole, the video lasts until it, 360 ms. Past it too when
/// the GOP is cut short: `I0 P3 B1 B2` ended at `P6` (240 ms) is presented
/// until 200 ms, where `P3`'s written duration (80 ms, a step of the decode
/// times) ends, not 160 ms, a frame after it, and the audio ends there
/// (ISO/IEC 14496-12 §8.6.1.4: the track's composition end is its last
/// presented sample's composition time plus duration). Regressions: the
/// clip ended the audio at 360 ms, 80 ms past the video, told nothing; and
/// at 200 ms for the excluded `B5`, 80 ms before the video, told only how
/// far before its end frame the video ends; and at 160 ms for the GOP cut
/// short at `P6`, 40 ms before the video.
#[test]
fn iso14496_12_8_8_8_1_reordered_video_ends_the_audio_where_its_presentation_ends() {
    let base = base();
    // Where the file's samples of `track_id` at `rate` are presented, in
    // ms: from the first one's start to where the last presented ends, as
    // a reader shows them (each its composition time for its duration).
    let presented = |file: &[u8], track_id: u32, rate: i64| -> (i64, i64) {
        let starts: Vec<(i64, i64)> = samples(file, track_id)
            .iter()
            .map(|s| {
                let pts = i64::try_from(s.dts).unwrap() + i64::from(s.cts);
                (pts, pts + i64::from(s.duration))
            })
            .collect();
        let first = starts.iter().map(|(pts, _)| *pts).min().unwrap();
        let (_, end) = starts.iter().max().unwrap();
        (first * 1000 / rate, end * 1000 / rate)
    };
    let clip = |order: &[u8], end: u8| {
        let video = gop(order, base, 0, 0, 0);
        let end_ms = u64::from(end) * 40;
        let end = frame(
            ms(base, end_ms),
            i64::from(end) * FRAME,
            false,
            0,
            h264_au(false, end),
        );
        let mut muxer = Muxer::new(&policy(10_000));
        let mut file = Vec::new();
        let mut put = |pieces: Vec<Bytes>| {
            for piece in pieces {
                file.extend_from_slice(&piece);
            }
        };
        put(muxer.start(&h264_track(), Some(&opus_track(1))).unwrap());
        for (kind, frame) in video {
            put(muxer.push(kind, frame).unwrap());
        }
        // The audio the clip lets in: captured before where the video ends.
        let end = muxer.end_video(&end).duration_since(base).as_millis();
        let end = u64::try_from(end).unwrap();
        for i in (0..).take_while(|i| i * 20 < end) {
            let at = ms(base, i * 20);
            let n = u8::try_from(i).unwrap();
            let ts = 960 * i64::from(n);
            put(muxer
                .push(Kind::Audio, frame(at, ts, true, 0, opus_packet(n)))
                .unwrap());
        }
        put(muxer.finish().unwrap());
        (
            end,
            presented(&file, 1, 90_000),
            presented(&file, 2, 48_000),
        )
    };
    assert_eq!(
        clip(&[0, 3, 1, 2, 6, 4, 5], 9),
        (280, (0, 280), (0, 280)),
        "reordered"
    );
    assert_eq!(
        clip(&[0, 1, 2, 3, 4, 5, 6], 9),
        (360, (0, 360), (0, 360)),
        "in order"
    );
    assert_eq!(
        clip(&[0, 3, 1, 2, 6, 4], 5),
        (280, (0, 280), (0, 280)),
        "B5 excluded"
    );
    assert_eq!(
        clip(&[0, 3, 1, 2], 6),
        (200, (0, 200), (0, 200)),
        "a GOP cut short at P6"
    );
    assert_eq!(
        clip(&[0, 4, 2, 1, 3], 8),
        (240, (0, 240), (0, 240)),
        "a pyramid cut short at P8"
    );
}

#[test]
fn calls_out_of_order_fail() {
    let base = base();
    let video = || frame(base, 0, true, 0, h264_au(true, 0));
    let mut muxer = Muxer::new(&policy(1000));
    let failed = |result: Result<Vec<Bytes>, ClipError>, call: &str| {
        assert_eq!(
            result,
            Err(ClipError::Failed(format!("{call} out of order")))
        );
    };
    failed(muxer.push(Kind::Video, video()), "push");
    muxer.start(&h264_track(), None).unwrap();
    failed(muxer.start(&h264_track(), None), "start");
    assert_eq!(
        muxer.finish(),
        Ok(Vec::new()),
        "nothing pushed: no fragment"
    );
    failed(muxer.push(Kind::Video, video()), "push");
    failed(muxer.finish(), "finish");
    failed(muxer.start(&h264_track(), None), "start");
    let mut idle = Muxer::new(&policy(1000));
    failed(idle.finish(), "finish");
    assert!(matches!(idle.state, State::Finished));
}

#[test]
fn an_audio_frame_without_an_audio_track_and_an_oversized_frame_fail() {
    let base = base();
    let mut muxer = Muxer::new(&policy(1000));
    muxer.start(&h264_track(), None).unwrap();
    assert_eq!(
        muxer.push(Kind::Audio, frame(base, 0, true, 0, opus_packet(0))),
        Err(ClipError::Failed(
            "an audio frame for a clip without audio".into()
        ))
    );
    let mut muxer = Muxer {
        limits: Limits {
            sample_bytes: 30,
            fragment_bytes: MAX_FRAGMENT_BYTES,
        },
        ..Muxer::new(&policy(1000))
    };
    muxer.start(&h264_track(), None).unwrap();
    let au = |len: usize| annex_b(&[&vec![0x41; len - 4]]);
    assert!(
        muxer
            .push(Kind::Video, frame(base, 0, true, 0, au(30)))
            .is_ok()
    );
    assert_eq!(
        muxer.push(Kind::Video, frame(base, FRAME, false, 0, au(31))),
        Err(ClipError::Failed(
            "a frame of 31 bytes is larger than a sample may be (30)".into()
        ))
    );
    assert_eq!(MAX_SAMPLE_BYTES, 256 << 20);
}

#[test]
fn tracks_without_a_sample_entry_are_unsupported() {
    let unsupported = |video: Codec, audio: Option<Codec>, family: CodecFamily| {
        let video = ClipTrack {
            codec: video,
            clock_rate: 90_000,
        };
        let audio = audio.map(|codec| ClipTrack {
            codec,
            clock_rate: 48_000,
        });
        let mut muxer = Muxer::new(&policy(1000));
        assert_eq!(
            muxer.start(&video, audio.as_ref()),
            Err(ClipError::Unsupported(family))
        );
        // A refused start leaves the muxer to start again.
        assert!(muxer.start(&h264_track(), None).is_ok());
    };
    let h264 = h264_track().codec;
    unsupported(Codec::Pcmu, None, CodecFamily::Pcmu);
    unsupported(aac_codec(16_000), None, CodecFamily::AacLc);
    unsupported(
        Codec::H264 {
            profile_level_id: None,
            sps: Some(Bytes::from(h264::test_data::sps(320, 240))),
            pps: None,
        },
        None,
        CodecFamily::H264,
    );
    unsupported(
        Codec::H265 {
            vps: None,
            sps: Some(Bytes::from(h265::test_data::sps(640, 480))),
            pps: Some(Bytes::from(h265::test_data::pps())),
        },
        None,
        CodecFamily::H265,
    );
    unsupported(h264.clone(), Some(Codec::Pcma), CodecFamily::Pcma);
    unsupported(h264.clone(), Some(h264.clone()), CodecFamily::H264);
    unsupported(
        h264.clone(),
        Some(Codec::AacLc {
            sample_rate: 16_000,
            channels: 1,
            config: Bytes::new(),
        }),
        CodecFamily::AacLc,
    );
    unsupported(
        h264.clone(),
        Some(Codec::Opus { channels: 3 }),
        CodecFamily::Opus,
    );
    unsupported(h264, Some(Codec::Opus { channels: 0 }), CodecFamily::Opus);
}

#[test]
fn sample_entries_the_sets_cannot_describe_fail_the_start() {
    let failed = |video: Codec, clock_rate: u32| {
        let track = ClipTrack {
            codec: video,
            clock_rate,
        };
        match Muxer::new(&policy(1000)).start(&track, None) {
            Err(ClipError::Failed(message)) => message,
            other => panic!("{other:?}"),
        }
    };
    assert!(failed(h264_codec(vec![0x67]), 90_000).starts_with("h264 sps: "));
    assert_eq!(
        failed(h265_codec(h265::test_data::pps()), 90_000),
        "h265 sps: not a sequence parameter set"
    );
    assert_eq!(
        failed(h265_codec(h265::test_data::sps(70_000, 480)), 90_000),
        "a picture of 70000x480 does not fit a sample entry"
    );
    assert_eq!(
        failed(h264_track().codec, 0),
        "track 1 has a clock rate of 0"
    );
    let audio = ClipTrack {
        codec: aac_codec(16_000),
        clock_rate: 0,
    };
    assert_eq!(
        Muxer::new(&policy(1000)).start(&h264_track(), Some(&audio)),
        Err(ClipError::Failed("track 2 has a clock rate of 0".into()))
    );
    // chroma_format_idc 4, which the record's two bits cannot hold.
    assert_eq!(
        failed(h264_codec(h264::test_data::high_sps(100, 4, 0, 0)), 90_000),
        encode_failed(mp4_atom::Error::InvalidSize)
            .to_string()
            .replace("clip muxing failed: ", "")
    );
}

#[test]
fn timestamps_a_field_cannot_hold_fail_the_push() {
    let base = base();
    let push_two = |first: Arc<MediaFrame>, second: Arc<MediaFrame>| {
        let mut muxer = Muxer::new(&policy(1000));
        muxer.start(&h264_track(), None).unwrap();
        muxer.push(Kind::Video, first).unwrap();
        muxer.push(Kind::Video, second)
    };
    let out_of_range = |what: &str, value: i128| {
        Err(ClipError::Failed(format!(
            "{what} of {value} ticks out of range"
        )))
    };
    // A duration past 32 bits.
    assert_eq!(
        push_two(
            frame(base, 0, true, 0, h264_au(true, 0)),
            frame(base, 1 << 33, false, 0, h264_au(false, 1))
        ),
        out_of_range("a sample duration", 1 << 33)
    );
    // A decode time past 64 bits: an epoch anchored 1 s in, then a
    // timestamp 2^64 - 1 ticks after its first.
    let mut muxer = Muxer::new(&policy(1000));
    muxer.start(&h264_track(), None).unwrap();
    muxer
        .push(Kind::Video, frame(base, 0, true, 0, h264_au(true, 0)))
        .unwrap();
    muxer
        .push(
            Kind::Video,
            frame(ms(base, 1000), i64::MIN, true, 1, h264_au(true, 1)),
        )
        .unwrap();
    let dts = 90_000 + i128::from(u64::MAX);
    assert_eq!(
        muxer.push(
            Kind::Video,
            frame(ms(base, 1040), i64::MAX, false, 1, h264_au(false, 2))
        ),
        out_of_range("a decode time", dts)
    );
    // A composition offset past 32 bits: reordered video going back 2^40.
    let back = -(1_i64 << 40);
    // Decoded a step (2^40) after the first, presented 2^40 before it.
    let cts = 2 * i128::from(back);
    assert_eq!(
        push_two(
            frame(base, 0, true, 0, h264_au(true, 0)),
            frame(base, back, false, 0, h264_au(false, 1))
        ),
        out_of_range("a composition offset", cts)
    );
}

#[test]
fn the_factory_accepts_the_four_codecs_with_what_their_entries_carry() {
    let sps = || Some(Bytes::from(h264::test_data::sps(320, 240)));
    let set = || Some(Bytes::from_static(b"set"));
    let cases = [
        (h264_track().codec, true),
        (
            Codec::H264 {
                profile_level_id: None,
                sps: sps(),
                pps: None,
            },
            false,
        ),
        (
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: set(),
            },
            false,
        ),
        (h265_track().codec, true),
        (
            Codec::H265 {
                vps: None,
                sps: set(),
                pps: set(),
            },
            false,
        ),
        (
            Codec::H265 {
                vps: set(),
                sps: None,
                pps: set(),
            },
            false,
        ),
        (
            Codec::H265 {
                vps: set(),
                sps: set(),
                pps: None,
            },
            false,
        ),
        (aac_track().codec, true),
        (
            Codec::AacLc {
                sample_rate: 16_000,
                channels: 1,
                config: Bytes::new(),
            },
            false,
        ),
        (Codec::Opus { channels: 1 }, true),
        (Codec::Opus { channels: 2 }, true),
        (Codec::Opus { channels: 0 }, false),
        (Codec::Opus { channels: 3 }, false),
        (Codec::Pcmu, false),
        (Codec::G722, false),
        (Codec::Mjpeg, false),
    ];
    for (codec, accepted) in cases {
        assert_eq!(Factory.accepts(&codec), accepted, "{codec:?}");
    }
}

#[test]
fn capture_times_become_ticks_rounded_down() {
    assert_eq!(ticks(Duration::from_millis(1500), 90_000), 135_000);
    assert_eq!(ticks(Duration::from_nanos(11_111), 90_000), 0);
    assert_eq!(ticks(Duration::from_nanos(11_112), 90_000), 1);
    assert_eq!(ticks(Duration::MAX, u32::MAX), u64::MAX);
    assert_eq!(
        encode_failed(mp4_atom::Error::InvalidSize),
        ClipError::Failed(format!("mp4 encoding: {}", mp4_atom::Error::InvalidSize))
    );
}

#[test]
fn an_origin_set_before_the_first_frame_is_media_time_0_and_one_set_otherwise_is_ignored() {
    let base = base();
    let key = || frame(ms(base, 10), 0, true, 0, h264_au(true, 0));
    let mut muxer = Muxer::new(&policy(1000));
    muxer.start(&h264_track(), None).unwrap();
    muxer.set_origin(base);
    muxer.push(Kind::Video, key()).unwrap();
    // After the first frame: the origin stays.
    muxer.set_origin(ms(base, 5));
    let mut file = muxer.finish().unwrap().concat();
    let mut init = Muxer::new(&policy(1000));
    let mut head = init.start(&h264_track(), None).unwrap().concat();
    head.append(&mut file);
    // 10 ms at 90 kHz.
    assert_eq!(samples(&head, 1)[0].dts, 900);

    // Before the start: nothing to set; the first frame is the origin.
    let mut muxer = Muxer::new(&policy(1000));
    muxer.set_origin(base);
    let mut file = muxer.start(&h264_track(), None).unwrap().concat();
    file.extend(muxer.push(Kind::Video, key()).unwrap().concat());
    file.extend(muxer.finish().unwrap().concat());
    assert_eq!(samples(&file, 1)[0].dts, 0);
}

/// `codec`'s 20 ms payloads of one second: `silence_ms` of silence, then
/// a 1 kHz tone at half scale.
fn narrowband_tone(codec: &Codec, silence_ms: u32) -> Vec<Bytes> {
    let rate = codec.sample_rate().unwrap();
    let per_frame = usize::try_from(rate / 50).unwrap();
    let silence = usize::try_from(rate / 1_000 * silence_ms).unwrap();
    let pcm: Vec<i16> = (0..usize::try_from(rate).unwrap())
        .map(|index| {
            let Some(at) = index.checked_sub(silence) else {
                return 0;
            };
            let phase = std::f64::consts::TAU * 1_000.0 * f64::from(u32::try_from(at).unwrap())
                / f64::from(rate);
            #[expect(clippy::cast_possible_truncation, reason = "within i16")]
            let sample = (16_384.0 * phase.sin()) as i16;
            sample
        })
        .collect();
    pcm.chunks(per_frame)
        .map(|chunk| match g711::Law::of(codec) {
            Some(law) => chunk.iter().map(|sample| law.encode(*sample)).collect(),
            None => g722::test_data::encode(chunk).into(),
        })
        .collect()
}

/// The media time, in seconds, where the tone in `audio`'s Opus starts:
/// its first decoded sample over a quarter of full scale, from the decode
/// time of the packet that holds it (each decodes to 960 samples).
fn tone_onset(audio: &[Read]) -> f64 {
    let mut opus = Decoder::new(48_000).unwrap();
    let mut pcm = Vec::new();
    for sample in audio {
        pcm.extend_from_slice(opus.decode(&sample.bytes).unwrap());
    }
    let at = pcm
        .iter()
        .position(|sample| sample.unsigned_abs() > 8_192)
        .unwrap();
    let ticks = audio[at / 960].dts + u64::try_from(at % 960).unwrap();
    #[expect(clippy::cast_precision_loss, reason = "ticks of a second")]
    let seconds = ticks as f64 / 48_000.0;
    seconds
}

/// Transcoded G.711 and G.722 audio keeps sync with its video (EBU R37:
/// sound at most 40 ms before the picture, at most 60 ms after): a tone
/// that starts at a capture time decodes from the file at the media time
/// the video gives that capture time, within half a millisecond. The audio
/// starts 10 ms before the first keyframe, as a pre-roll's does, and the
/// clip's origin is the transcode's delay before it, so its first packet
/// is not clamped; the packets are one run of 20 ms.
#[test]
fn ebu_r37_transcoded_g711_and_g722_audio_keeps_sync_with_its_video() {
    for codec in [Codec::Pcmu, Codec::Pcma, Codec::G722] {
        let base = base();
        let mut items: Vec<(Instant, u8, Kind, Arc<MediaFrame>)> = Vec::new();
        for (index, payload) in narrowband_tone(&codec, 300).into_iter().enumerate() {
            let index = u32::try_from(index).unwrap();
            let at = ms(base, u64::from(index) * 20);
            items.push((
                at,
                1,
                Kind::Audio,
                frame(at, i64::from(index) * 160, true, 0, payload),
            ));
        }
        for index in 0..25_u8 {
            let key = index % 10 == 0;
            let at = ms(base, 10 + u64::from(index) * 40);
            let video = frame(at, i64::from(index) * FRAME, key, 0, h264_au(key, index));
            items.push((at, 0, Kind::Video, video));
        }
        items.sort_by_key(|(at, order, ..)| (*at, *order));

        let mut chain = ToOpus::new(&codec).unwrap();
        let mut muxer = Muxer::new(&policy(1000));
        let mut file = muxer
            .start(&h264_track(), Some(&ToOpus::output()))
            .unwrap()
            .concat();
        muxer.set_origin(base.checked_sub(chain.delay()).unwrap());
        for (_, _, kind, frame) in items {
            let frames = match kind {
                Kind::Video => vec![frame],
                Kind::Audio => chain.push(&frame).unwrap(),
            };
            for frame in frames {
                file.extend(muxer.push(kind, frame).unwrap().concat());
            }
        }
        file.extend(muxer.finish().unwrap().concat());

        let audio = samples(&file, 2);
        assert_eq!(audio[0].dts, 0, "{codec:?}: the first packet at the origin");
        for pair in audio.windows(2) {
            assert_eq!(pair[1].dts, pair[0].dts + 960, "{codec:?}: one run");
        }
        // The tone starts at capture 300 ms; the first keyframe, captured at
        // 10 ms, is at its decode time, so 300 ms is 290 ms after it.
        let video = samples(&file, 1);
        #[expect(clippy::cast_precision_loss, reason = "ticks of a second")]
        let picture = video[0].dts as f64 / 90_000.0 + 0.290;
        let offset = tone_onset(&audio) - picture;
        assert!(
            (-0.040..=0.060).contains(&offset),
            "{codec:?}: sound {offset} s after the picture, outside EBU R37"
        );
        assert!(offset.abs() <= 0.000_5, "{codec:?}: {offset} s off");
    }
}

/// Transcoded audio keeps sync with its video (EBU R37) through a late
/// frame and a step of the capture times. Without Sender Reports a
/// frame's capture time is its arrival: the second audio frame comes
/// 100 ms late, and the audio's first packet stays at media time 0, where
/// its first frame puts it. At 400 ms the RTSP source starts a new epoch
/// on both tracks (the video's timestamps start over) and forgets its
/// clock mapping, so the capture times from there are a second later
/// while the audio's timestamps go on: its packets from there are a new
/// epoch at 1380 ms, and the tone captured at 600 ms, 1600 ms after the
/// step, decodes at the media time the video's new epoch gives 1600 ms,
/// within half a millisecond. Regressions: the first packet took the late
/// frame's capture time, 100 ms on; and the audio went on in its first
/// epoch, a second before the video.
#[test]
fn ebu_r37_transcoded_audio_keeps_sync_through_a_late_frame_and_a_capture_time_step() {
    for codec in [Codec::Pcmu, Codec::Pcma, Codec::G722] {
        let base = base();
        // What was captured `at` ms in: its capture time, a second later from
        // 400 ms on, and its epoch.
        let stepped = |at: u64| {
            if at >= 400 {
                (ms(base, at + 1_000), 1)
            } else {
                (ms(base, at), 0)
            }
        };
        let mut items: Vec<(u64, u8, Kind, Arc<MediaFrame>)> = Vec::new();
        for (index, payload) in narrowband_tone(&codec, 600).into_iter().enumerate() {
            let index = u32::try_from(index).unwrap();
            let at = u64::from(index) * 20;
            let (mut wallclock, epoch) = stepped(at);
            if index == 1 {
                wallclock += Duration::from_millis(100);
            }
            let audio = frame(wallclock, i64::from(index) * 160, true, epoch, payload);
            items.push((at, 1, Kind::Audio, audio));
        }
        for index in 0..25_u8 {
            let key = index % 10 == 0;
            let at = 10 + u64::from(index) * 40;
            let (wallclock, epoch) = stepped(at);
            let since = if epoch == 1 { index - 10 } else { index };
            let video = frame(
                wallclock,
                i64::from(since) * FRAME,
                key,
                epoch,
                h264_au(key, index),
            );
            items.push((at, 0, Kind::Video, video));
        }
        // In the order they were captured; the late frame keeps its place in its track.
        items.sort_by_key(|(at, order, ..)| (*at, *order));

        let mut chain = ToOpus::new(&codec).unwrap();
        let mut muxer = Muxer::new(&policy(1000));
        let mut file = muxer
            .start(&h264_track(), Some(&ToOpus::output()))
            .unwrap()
            .concat();
        muxer.set_origin(base.checked_sub(chain.delay()).unwrap());
        for (_, _, kind, frame) in items {
            let frames = match kind {
                Kind::Video => vec![frame],
                Kind::Audio => chain.push(&frame).unwrap(),
            };
            for frame in frames {
                file.extend(muxer.push(kind, frame).unwrap().concat());
            }
        }
        file.extend(muxer.finish().unwrap().concat());

        let audio = samples(&file, 2);
        // Frame 20, the new epoch's first, completes packet 19: captured
        // 1400 ms less 20 ms and the delay, 1380 ms after the origin.
        let dts: Vec<u64> = audio.iter().map(|sample| sample.dts).collect();
        let expected: Vec<u64> = (0..49)
            .map(|k| {
                if k < 19 {
                    960 * k
                } else {
                    66_240 + 960 * (k - 19)
                }
            })
            .collect();
        assert_eq!(dts, expected, "{codec:?}");
        // The tone at 1600 ms is 190 ms after the video's new epoch's first
        // frame, captured at 1410 ms.
        let video = samples(&file, 1);
        #[expect(clippy::cast_precision_loss, reason = "ticks of a second")]
        let picture = video[10].dts as f64 / 90_000.0 + 0.190;
        let offset = tone_onset(&audio) - picture;
        assert!(
            (-0.040..=0.060).contains(&offset),
            "{codec:?}: sound {offset} s after the picture, outside EBU R37"
        );
        assert!(offset.abs() <= 0.000_5, "{codec:?}: {offset} s off");
    }
}
