#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use lotse_codec::h264::annex_b_units;
use mp4_atom::{Edts, Elst, ElstEntry, FixedPoint, Tfhd, Traf, Trun, TrunEntry};

use super::test_data::{
    H264_AAC_0, H264_AAC_1, H264_AAC_INIT, H264_BFRAMES_0, H264_BFRAMES_INIT, H265_0, H265_INIT,
    OPUS_INIT, SPLIT_AUDIO_0, SPLIT_AUDIO_INIT, SPLIT_VIDEO_0, SPLIT_VIDEO_INIT,
};
use super::*;

/// The frame limit of the tests: `limits.max_frame_bytes`' default.
const MAX: usize = 4 << 20;

/// Where the box at `path` lies in `data`: its start and its body's
/// start. Each step is a box type and which box of that type it is;
/// `stsd`'s body begins with its version, flags and entry count.
fn locate(data: &[u8], path: &[(&[u8; 4], usize)]) -> (usize, usize) {
    let mut base = 0;
    let mut body = data;
    let mut found = (0, 0);
    for (kind, nth) in path {
        let placed = boxes(body)
            .unwrap()
            .into_iter()
            .filter(|placed| placed.kind == FourCC::new(kind))
            .nth(*nth)
            .unwrap_or_else(|| panic!("no {kind:?} #{nth}"));
        found = (base + placed.start, base + placed.body_start);
        let skip = if **kind == *b"stsd" { 8 } else { 0 };
        base = found.1 + skip;
        body = &data[base..base + placed.body.len() - skip];
    }
    found
}

/// The body start of the run of track fragment `traf` in the first
/// movie fragment of `segment`.
fn trun(segment: &[u8], traf: usize) -> usize {
    locate(segment, &[(b"moof", 0), (b"traf", traf), (b"trun", 0)]).1
}

/// `data` with `value` written at `at`.
fn patched(data: &[u8], at: usize, value: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out[at..at + value.len()].copy_from_slice(value);
    out
}

/// The position of `needle` in `data`.
fn find(data: &[u8], needle: &[u8]) -> usize {
    data.windows(needle.len())
        .position(|window| window == needle)
        .unwrap()
}

/// The units of `segments` read with the stream's init segment.
fn read(init: &[u8], segments: &[&[u8]], max_frame_bytes: usize) -> (Reader, Vec<Unit>) {
    let mut reader = Reader::new(init, max_frame_bytes).unwrap();
    let mut units = Vec::new();
    for segment in segments {
        reader.read_segment(segment, &mut units).unwrap();
    }
    (reader, units)
}

/// The error reading `segment` with `init`, after which nothing was
/// appended or counted.
fn segment_error(init: &[u8], segment: &[u8]) -> Fmp4Error {
    let mut reader = Reader::new(init, MAX).unwrap();
    let mut units = Vec::new();
    let err = reader.read_segment(segment, &mut units).unwrap_err();
    assert!(units.is_empty());
    assert_eq!(reader.stats(), Fmp4Stats::default());
    err
}

fn of_track(units: &[Unit], track: usize) -> Vec<&Unit> {
    units.iter().filter(|unit| unit.track == track).collect()
}

/// The NAL unit types of an H.264 Annex B access unit.
fn h264_types(unit: &Unit) -> Vec<u8> {
    annex_b_units(&unit.payload)
        .iter()
        .map(|nal| nal[0] & 0x1f)
        .collect()
}

fn unsupported_codec(kind: Kind, name: &str) -> Codec {
    Codec::Unsupported {
        kind,
        name: name.to_owned(),
    }
}

/// `segment` with its movie fragment decoded by mp4-atom, changed by
/// `change` (given the fragment's start) and encoded again in its place,
/// its runs' data offsets moved by the change of its size.
fn reencoded(segment: &[u8], change: impl FnOnce(&mut Moof, usize)) -> Vec<u8> {
    let placed = boxes(segment).unwrap();
    let fragment = placed.iter().find(|placed| placed.kind == MOOF).unwrap();
    let end = fragment.body_start + fragment.body.len();
    let mut moof = Moof::decode(&mut &segment[fragment.start..]).unwrap();
    change(&mut moof, fragment.start);
    let mut encoded = Vec::new();
    moof.encode(&mut encoded).unwrap();
    let grown =
        i32::try_from(encoded.len()).unwrap() - i32::try_from(end - fragment.start).unwrap();
    for traf in &mut moof.traf {
        for run in &mut traf.trun {
            if let Some(offset) = run.data_offset.as_mut() {
                *offset += grown;
            }
        }
    }
    encoded.clear();
    moof.encode(&mut encoded).unwrap();
    let mut out = segment[..fragment.start].to_vec();
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&segment[end..]);
    out
}

fn edits(entries: &[(u64, Option<u64>)]) -> Trak {
    Trak {
        edts: Some(Edts {
            elst: Some(Elst {
                entries: entries
                    .iter()
                    .map(|&(segment_duration, media_time)| ElstEntry {
                        segment_duration,
                        media_time,
                        media_rate: FixedPoint::new(1, 0),
                    })
                    .collect(),
            }),
        }),
        ..Trak::default()
    }
}

#[test]
fn rfc8216_4_3_2_5_the_init_segment_gives_the_layout_with_its_parameter_sets() {
    let reader = Reader::new(H264_AAC_INIT, MAX).unwrap();
    let layout = reader.layout();
    assert_eq!(layout.program_number, 0);
    assert_eq!(layout.tracks.len(), 2);
    let (video, audio) = (&layout.tracks[0], &layout.tracks[1]);
    assert_eq!(
        (video.id, video.stream_type, video.kind, video.clock_rate),
        (1, 0, Kind::Video, 90_000)
    );
    let Codec::H264 {
        profile_level_id,
        sps: Some(sps),
        pps: Some(pps),
    } = &video.codec
    else {
        panic!("H.264 with its sets: {:?}", video.codec);
    };
    // ISO/IEC 14496-15 §5.3.3: the avcC's sets; ffmpeg's `avc1.42c00a`.
    assert_eq!(*profile_level_id, Some([0x42, 0xc0, 0x0a]));
    assert_eq!(sps[0] & 0x1f, 7);
    assert_eq!(pps[0] & 0x1f, 8);
    assert_eq!(
        (audio.id, audio.kind, audio.clock_rate),
        (2, Kind::Audio, 48_000)
    );
    assert_eq!(
        audio.codec,
        Codec::AacLc {
            sample_rate: 48_000,
            channels: 1,
            // ISO/IEC 14496-3 §1.6.2.1, with the SBR sync extension ffmpeg
            // writes.
            config: Bytes::from_static(&[0x11, 0x88, 0x56, 0xe5, 0x00]),
        }
    );
    assert_eq!(reader.stats(), Fmp4Stats::default());
}

#[test]
fn iso14496_12_8_8_12_samples_are_timed_from_tfdt_on_one_90_khz_program_clock() {
    let (reader, units) = read(H264_AAC_INIT, &[H264_AAC_0, H264_AAC_1], MAX);
    let video = of_track(&units, 0);
    let audio = of_track(&units, 1);
    assert_eq!((video.len(), audio.len()), (20, 95));
    // Video: 1024 of 10240 a frame from tfdt 0 and 10240, after the
    // empty edit of 1026/48000 s = 218 ticks (§8.6.6): 9000 at 90 kHz.
    for (i, unit) in (0_i64..).zip(&video) {
        let ticks = 1024 * i + 218;
        let expected = ticks * 90_000 / 10_240;
        assert_eq!((unit.decode_time, unit.ts), (expected, expected), "{i}");
    }
    assert_eq!(video[0].decode_time, 1916);
    assert_eq!(video[10].decode_time, 91_916);
    // AAC: 1024 samples a frame at 48 kHz, from tfdt 0 and 49152.
    for (i, unit) in (0_i64..).zip(&audio) {
        assert_eq!(unit.ts, 1024 * i, "{i}");
        assert_eq!(unit.decode_time, 1920 * i, "{i}");
    }
    // One timeline, in decode order across the tracks.
    assert!(
        units
            .windows(2)
            .all(|pair| pair[0].decode_time <= pair[1].decode_time)
    );
    assert_eq!(units[0].track, 1, "the audio of decode time 0 first");
    assert_eq!(
        reader.stats(),
        Fmp4Stats {
            segments: 2,
            samples: 115,
            ..Fmp4Stats::default()
        }
    );
}

#[test]
fn iso14496_15_5_3_2_video_samples_become_annex_b_access_units_and_audio_stays_raw() {
    let (_, units) = read(H264_AAC_INIT, &[H264_AAC_0], MAX);
    let video = of_track(&units, 0);
    // The keyframe: SEI and IDR, its parameter sets out of band only.
    assert_eq!(h264_types(video[0]), [6, 5]);
    assert!(video[1..].iter().all(|unit| h264_types(unit) == [1]));
    // The first video sample at the run's data offset 420 from the moof
    // (at 128), 3206 bytes, each NAL unit after a 4-byte length.
    let sample = &H264_AAC_0[548..548 + 3206];
    let mut expected = Vec::new();
    length_prefixed_to_annex_b(sample, 4, &mut expected).unwrap();
    assert_eq!(video[0].payload, expected);
    // The first AAC frame at its run's data offset 11968, 143 bytes.
    let audio = of_track(&units, 1);
    assert_eq!(audio[0].payload, &H264_AAC_0[12_096..12_096 + 143]);
}

#[test]
fn iso14496_15_5_3_3_and_8_3_3_avc3_and_hev1_read_as_avc1_and_hvc1() {
    // The entries whose streams may carry parameter sets in band as well,
    // with the same decoder configuration: read the same way.
    let stsd = |init: &[u8], entry: &[u8; 4]| {
        locate(
            init,
            &[
                (b"moov", 0),
                (b"trak", 0),
                (b"mdia", 0),
                (b"minf", 0),
                (b"stbl", 0),
                (b"stsd", 0),
                (entry, 0),
            ],
        )
        .0
    };
    for (init, entry, other) in [
        (H264_AAC_INIT, b"avc1", b"avc3"),
        (H265_INIT, b"hvc1", b"hev1"),
    ] {
        let patched_init = patched(init, stsd(init, entry) + 4, other);
        assert_eq!(
            Reader::new(&patched_init, MAX).unwrap().layout(),
            Reader::new(init, MAX).unwrap().layout()
        );
    }
}

#[test]
fn iso14496_15_8_3_3_h265_gives_its_parameter_sets_and_access_units() {
    let (reader, units) = read(H265_INIT, &[H265_0], MAX);
    let Codec::H265 {
        vps: Some(vps),
        sps: Some(sps),
        pps: Some(pps),
    } = &reader.layout().tracks[0].codec
    else {
        panic!("H.265 with its sets");
    };
    // ITU-T H.265 Table 7-1: VPS 32, SPS 33, PPS 34.
    assert_eq!([vps[0] >> 1, sps[0] >> 1, pps[0] >> 1], [32, 33, 34]);
    assert_eq!(units.len(), 10);
    for (i, unit) in (0_i64..).zip(&units) {
        let expected = 9000 * i;
        assert_eq!((unit.decode_time, unit.ts), (expected, expected));
    }
    // IDR_N_LP first.
    let first: Vec<u8> = annex_b_units(&units[0].payload)
        .iter()
        .map(|nal| nal[0] >> 1)
        .collect();
    assert_eq!(first, [20]);
}

#[test]
fn iso14496_12_8_8_8_version_1_runs_carry_negative_composition_offsets() {
    let (_, units) = read(H264_BFRAMES_INIT, &[H264_BFRAMES_0], MAX);
    assert_eq!(units.len(), 10);
    // The empty edit of 200/1000 s delays the track by 2048 ticks.
    let decode: Vec<i64> = units.iter().map(|unit| unit.decode_time).collect();
    assert_eq!(
        decode,
        (0..10).map(|i| 18_000 + 9000 * i).collect::<Vec<_>>()
    );
    // Offsets 0, 2048, -1024, -1024, 2048, -1024, -1024, 1024, -1024, 0.
    let ts: Vec<i64> = units.iter().map(|unit| unit.ts).collect();
    assert_eq!(
        ts,
        [
            18_000, 45_000, 27_000, 36_000, 72_000, 54_000, 63_000, 90_000, 81_000, 99_000
        ]
    );
    assert!(
        ts[2] < decode[2],
        "a negative offset presents before decoding"
    );
    assert_eq!(h264_types(&units[0]), [6, 5]);
}

#[test]
fn iso14496_12_8_6_6_the_edit_list_shifts_the_media_timeline() {
    assert_eq!(shift(&Trak::default(), 1000, 10_240), 0, "no edit list");
    let no_elst = Trak {
        edts: Some(Edts { elst: None }),
        ..Trak::default()
    };
    assert_eq!(shift(&no_elst, 1000, 10_240), 0);
    // Empty edits delay, rounded down to the track's timescale.
    assert_eq!(
        shift(&edits(&[(1026, None), (0, Some(0))]), 48_000, 10_240),
        218
    );
    assert_eq!(
        shift(
            &edits(&[(100, None), (100, None), (0, Some(0))]),
            1000,
            10_240
        ),
        2048
    );
    // The first edit with media skips its media time; later ones are not
    // read.
    assert_eq!(
        shift(&edits(&[(5000, Some(1024)), (0, Some(9))]), 1000, 48_000),
        -1024
    );
    assert_eq!(
        shift(&edits(&[(200, None), (0, Some(1024))]), 1000, 10_240),
        1024
    );
    // Empty edits only; a movie timescale of zero gives no delay.
    assert_eq!(shift(&edits(&[(200, None)]), 1000, 10_240), 2048);
    assert_eq!(shift(&edits(&[(200, None), (0, Some(5))]), 0, 10_240), -5);
}

#[test]
fn rfc8216_4_3_4_2_1_a_separate_audio_rendition_shares_the_variant_timeline() {
    let (video_reader, video) = read(SPLIT_VIDEO_INIT, &[SPLIT_VIDEO_0], MAX);
    let (audio_reader, audio) = read(SPLIT_AUDIO_INIT, &[SPLIT_AUDIO_0], MAX);
    assert_eq!(video_reader.layout().tracks.len(), 1);
    assert_eq!(audio_reader.layout().tracks.len(), 1);
    assert_eq!(audio_reader.layout().tracks[0].kind, Kind::Audio);
    assert_eq!((video.len(), audio.len()), (10, 47));
    // Video 21 ms after the AAC priming, as in the multiplexed stream
    // (1916 there: ffmpeg rounds the edit in the movie timescale).
    assert_eq!(video[0].decode_time, 1889);
    assert_eq!(audio[0].decode_time, 0);
    // Joined as the caller joins them: the rendition's track after the
    // variant's, merged by decode time, as the multiplexed stream is.
    let offset = video_reader.layout().tracks.len();
    let mut merged: Vec<Unit> = video
        .into_iter()
        .chain(audio.into_iter().map(|unit| Unit {
            track: unit.track + offset,
            ..unit
        }))
        .collect();
    merged.sort_by_key(|unit| unit.decode_time);
    let (_, multiplexed) = read(H264_AAC_INIT, &[H264_AAC_0], MAX);
    let tracks = |units: &[Unit]| {
        units
            .iter()
            .map(|unit| unit.track)
            .take(57)
            .collect::<Vec<_>>()
    };
    assert_eq!(tracks(&merged), tracks(&multiplexed));
}

#[test]
fn iso14496_12_8_5_2_other_sample_entries_are_declared_unsupported_by_their_type() {
    // A known entry lotse does not read: Opus (`Opus`).
    let reader = Reader::new(OPUS_INIT, MAX).unwrap();
    assert_eq!(
        reader.layout().tracks[0],
        LayoutTrack {
            id: 1,
            stream_type: 0,
            kind: Kind::Audio,
            codec: unsupported_codec(Kind::Audio, "opus"),
            clock_rate: 90_000,
        }
    );
    // An entry mp4-atom does not know: `avc1` renamed `encv`. Its units
    // never come; the other track's do.
    let (entry, _) = locate(
        H264_AAC_INIT,
        &[
            (b"moov", 0),
            (b"trak", 0),
            (b"mdia", 0),
            (b"minf", 0),
            (b"stbl", 0),
            (b"stsd", 0),
            (b"avc1", 0),
        ],
    );
    let init = patched(H264_AAC_INIT, entry + 4, b"encv");
    let (reader, units) = read(&init, &[H264_AAC_0], MAX);
    assert_eq!(
        reader.layout().tracks[0].codec,
        unsupported_codec(Kind::Video, "encv")
    );
    assert_eq!(reader.layout().tracks[0].clock_rate, 90_000);
    assert_eq!(units.len(), 48);
    assert!(units.iter().all(|unit| unit.track == 1));
    assert_eq!(reader.stats().samples, 48);
    assert_eq!(reader.stats().dropped_outside, 0);
}

#[test]
fn iso14496_12_8_4_3_tracks_of_other_handlers_are_not_tracks() {
    let mut trak = Trak::default();
    trak.mdia.hdlr.handler = FourCC::new(b"text");
    assert!(track(&trak, 1000).unwrap().is_none());
    // A video track without a sample entry: unknown, its timescale of
    // zero no matter, as it is not read.
    trak.mdia.hdlr.handler = VIDE;
    let (_, entry) = track(&trak, 1000).unwrap().unwrap();
    assert_eq!(entry.codec, unsupported_codec(Kind::Video, "unknown"));
    assert_eq!(entry.clock_rate, 90_000);
    trak.mdia.hdlr.handler = SOUN;
    let (_, entry) = track(&trak, 1000).unwrap().unwrap();
    assert_eq!(entry.codec, unsupported_codec(Kind::Audio, "unknown"));
}

#[test]
fn iso14496_1_7_2_6_6_mp4a_is_aac_only_with_an_aac_object_type_and_its_config() {
    let audio = |init: &[u8]| Reader::new(init, MAX).unwrap().layout().tracks[1].clone();
    // objectTypeIndication 0x6B, MPEG-1 audio.
    let oti = find(H264_AAC_INIT, &[0x04, 0x80, 0x80, 0x80]) + 5;
    assert_eq!(H264_AAC_INIT[oti], 0x40);
    let mp3 = audio(&patched(H264_AAC_INIT, oti, &[0x6b]));
    assert_eq!(mp3.codec, unsupported_codec(Kind::Audio, "mp4a"));
    assert_eq!(mp3.clock_rate, 90_000);
    // MPEG-2 AAC (0x66 to 0x68) carries an AudioSpecificConfig too.
    for other in [0x66, 0x67, 0x68] {
        assert!(matches!(
            audio(&patched(H264_AAC_INIT, oti, &[other])).codec,
            Codec::AacLc { .. }
        ));
    }
    assert_eq!(
        audio(&patched(H264_AAC_INIT, oti, &[0x65])).codec,
        unsupported_codec(Kind::Audio, "mp4a")
    );
    // No DecoderSpecificInfo: its tag made an unknown one (0x07).
    let specific = find(H264_AAC_INIT, &[0x05, 0x80, 0x80, 0x80]);
    let none = audio(&patched(H264_AAC_INIT, specific, &[0x07]));
    assert_eq!(none.codec, unsupported_codec(Kind::Audio, "aac"));
    // ISO/IEC 14496-3 §1.6.2.1: audio object type 5, HE-AAC.
    let he = audio(&patched(H264_AAC_INIT, specific + 5, &[0x29]));
    assert_eq!(he.codec, unsupported_codec(Kind::Audio, "aac_he"));
}

#[test]
fn rfc8216_3_3_a_track_fragment_without_tfdt_is_refused() {
    let (tfdt, _) = locate(H264_AAC_0, &[(b"moof", 0), (b"traf", 1), (b"tfdt", 0)]);
    let segment = patched(H264_AAC_0, tfdt + 4, b"free");
    let err = segment_error(H264_AAC_INIT, &segment);
    assert_eq!(err, Fmp4Error::NoDecodeTime { track: 2 });
    assert_eq!(
        err.to_string(),
        "a fragment of track 2 has no base media decode time"
    );
}

#[test]
fn iso14496_12_8_8_8_a_huge_sample_count_is_refused_before_mp4_atom_reads_it() {
    let count = trun(H264_AAC_0, 0) + 4;
    let segment = patched(H264_AAC_0, count, &u32::MAX.to_be_bytes());
    let err = segment_error(H264_AAC_INIT, &segment);
    let declared = u64::from(u32::MAX) + 48;
    assert_eq!(err, Fmp4Error::TooManySamples { count: declared });
    assert_eq!(
        err.to_string(),
        format!("a movie fragment declares {declared} samples, more than 262144")
    );
    // Exactly the limit is read, and mp4-atom finds the run short.
    let at_limit = u32::try_from(MAX_SAMPLES - 48).unwrap();
    let segment = patched(H264_AAC_0, count, &at_limit.to_be_bytes());
    let err = segment_error(H264_AAC_INIT, &segment);
    assert!(
        matches!(
            &err,
            Fmp4Error::Box {
                what: "movie fragment",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn iso14496_12_8_1_1_samples_past_a_truncated_mdat_are_dropped() {
    let (_, whole) = read(H264_AAC_INIT, &[H264_AAC_0], MAX);
    let cut = &H264_AAC_0[..H264_AAC_0.len() - 1000];
    let (reader, units) = read(H264_AAC_INIT, &[cut], MAX);
    let dropped = reader.stats().dropped_outside;
    assert!(dropped > 0);
    assert_eq!(of_track(&units, 0).len(), 10);
    assert_eq!(of_track(&units, 1).len() as u64, 48 - dropped);
    assert_eq!(reader.stats().samples, 58 - dropped);
    // The units left are the whole segment's.
    assert!(units.iter().all(|unit| whole.contains(unit)));
}

#[test]
fn iso14496_12_8_8_8_samples_outside_the_mdat_are_dropped() {
    // The first video sample 1 MiB long: it and those after it lie past
    // the mdat.
    let size = trun(H264_AAC_0, 0) + 16;
    let segment = patched(H264_AAC_0, size, &(1_u32 << 20).to_be_bytes());
    let (reader, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(reader.stats().dropped_outside, 10);
    assert_eq!(units.len(), 48);
    // The audio run's data offset 0: its first samples in the moof and
    // the mdat's header, before its data (at 548).
    let offset = trun(H264_AAC_0, 1) + 8;
    let segment = patched(H264_AAC_0, offset, &[0; 4]);
    let (reader, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(reader.stats().dropped_outside, 4);
    assert_eq!(units.len(), 54);
}

#[test]
fn samples_over_the_frame_limit_empty_or_with_a_unit_past_their_end_are_dropped() {
    // Over the limit: the keyframe (3206 bytes) only.
    let (reader, units) = read(H264_AAC_INIT, &[H264_AAC_0], 3205);
    assert_eq!(reader.stats().dropped_oversize, 1);
    assert_eq!(units.len(), 57);
    let (reader, _) = read(H264_AAC_INIT, &[H264_AAC_0], 3206);
    assert_eq!(reader.stats().dropped_oversize, 0);
    // The last video sample empty.
    let size = trun(H264_AAC_0, 0) + 16 + 9 * 4;
    let segment = patched(H264_AAC_0, size, &[0; 4]);
    let (reader, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(reader.stats().dropped_empty, 1);
    assert_eq!(of_track(&units, 0).len(), 9);
    // The first NAL unit's length running past the sample (ISO/IEC
    // 14496-15 §5.3.2).
    let segment = patched(H264_AAC_0, 548, &u32::MAX.to_be_bytes());
    let (reader, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(reader.stats().dropped_malformed, 1);
    assert_eq!(of_track(&units, 0).len(), 9);
    assert_eq!(reader.stats().samples, 57);
}

#[test]
fn iso14496_12_8_8_7_1_the_base_data_offset_of_each_track_fragment() {
    let traf = |base_data_offset, default_base_is_moof| Traf {
        tfhd: Tfhd {
            base_data_offset,
            default_base_is_moof,
            ..Tfhd::default()
        },
        ..Traf::default()
    };
    // Explicit, else the moof with default-base-is-moof, else the moof
    // for the first and the end of the preceding one's data after.
    assert_eq!(base_offset(&traf(Some(7), true), 100, Some(900)), 7);
    assert_eq!(
        base_offset(&traf(Some(u64::MAX), false), 100, None),
        usize::MAX
    );
    assert_eq!(base_offset(&traf(None, true), 100, Some(900)), 100);
    assert_eq!(base_offset(&traf(None, false), 100, None), 100);
    assert_eq!(base_offset(&traf(None, false), 100, Some(900)), 900);
    // §8.8.8.3: a signed data offset; past either end, nowhere.
    assert_eq!(offset(100, -40), 60);
    assert_eq!(offset(100, 40), 140);
    assert_eq!(offset(10, -40), usize::MAX);
    assert_eq!(offset(usize::MAX, 1), usize::MAX);
}

#[test]
fn iso14496_12_8_8_7_1_without_default_base_is_moof_a_fragment_follows_the_one_before() {
    // Flags without default-base-is-moof (0x020000): the audio fragment's
    // base is the end of the video data, so its offset from there lands
    // past the segment.
    let flags = locate(H264_AAC_0, &[(b"moof", 0), (b"traf", 1), (b"tfhd", 0)]).1;
    let segment = patched(H264_AAC_0, flags + 1, &[0x00]);
    let (reader, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(units.len(), 10);
    assert_eq!(reader.stats().dropped_outside, 48);
    // The first fragment's base stays the moof.
    let flags = locate(H264_AAC_0, &[(b"moof", 0), (b"traf", 0), (b"tfhd", 0)]).1;
    let segment = patched(H264_AAC_0, flags + 1, &[0x00]);
    let (_, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(units.len(), 58);
}

#[test]
fn iso14496_12_8_8_7_and_8_8_8_explicit_bases_and_runs_without_offset_read_the_same_samples() {
    let (_, whole) = read(H264_AAC_INIT, &[H264_AAC_0], MAX);
    // Each fragment's base explicit, at the moof.
    let explicit = reencoded(H264_AAC_0, |moof, start| {
        for traf in &mut moof.traf {
            traf.tfhd.base_data_offset = Some(u64::try_from(start).unwrap());
            traf.tfhd.default_base_is_moof = false;
        }
    });
    let (reader, units) = read(H264_AAC_INIT, &[&explicit], MAX);
    assert_eq!(units, whole);
    assert_eq!(reader.stats().samples, 58);
    // The video run split in two, the second without a data offset: it
    // follows the first (§8.8.8.3), its decode times continuing.
    let split = reencoded(H264_AAC_0, |moof, _| {
        let runs = &mut moof.traf[0].trun;
        let rest: Vec<TrunEntry> = runs[0].entries.split_off(4);
        runs.push(Trun {
            data_offset: None,
            entries: rest,
        });
    });
    let (_, units) = read(H264_AAC_INIT, &[&split], MAX);
    assert_eq!(units, whole);
}

#[test]
fn iso14496_12_8_8_3_and_8_8_7_trex_and_tfhd_give_the_defaults() {
    // The audio run's sizes dropped: each frame takes the tfhd's default
    // (0x8f = 143 bytes), the durations its 1024.
    let tfhd_only = reencoded(H264_AAC_0, |moof, _| {
        for entry in &mut moof.traf[1].trun[0].entries {
            entry.size = None;
        }
    });
    // The mdat holds 4203 bytes of audio: 29 such frames.
    let (reader, units) = read(H264_AAC_INIT, &[&tfhd_only], MAX);
    let audio = of_track(&units, 1);
    assert_eq!(audio.len(), 29);
    assert_eq!(reader.stats().dropped_outside, 19);
    assert!(audio.iter().all(|unit| unit.payload.len() == 143));
    assert_eq!(audio[28].ts, 28 * 1024);
    // Without the tfhd's either: the trex's, which ffmpeg leaves 0.
    let neither = reencoded(H264_AAC_0, |moof, _| {
        moof.traf[1].tfhd.default_sample_size = None;
        moof.traf[1].tfhd.default_sample_duration = None;
        for entry in &mut moof.traf[1].trun[0].entries {
            entry.size = None;
        }
    });
    let (reader, units) = read(H264_AAC_INIT, &[&neither], MAX);
    assert_eq!(units.len(), 10);
    assert_eq!(reader.stats().dropped_empty, 48);
    // The trex's set: 1024 ticks and 77 bytes a sample.
    let trex = locate(H264_AAC_INIT, &[(b"moov", 0), (b"mvex", 0), (b"trex", 1)]).1;
    let init = patched(H264_AAC_INIT, trex + 12, &[0, 0, 4, 0, 0, 0, 0, 77]);
    let (_, units) = read(&init, &[&neither], MAX);
    let audio = of_track(&units, 1);
    assert_eq!(audio.len(), 48);
    assert!(audio.iter().all(|unit| unit.payload.len() == 77));
    assert_eq!(audio[47].ts, 47 * 1024);
}

#[test]
fn iso14496_12_8_8_7_a_fragment_of_an_unknown_track_is_counted_and_skipped() {
    let tfhd = locate(H264_AAC_0, &[(b"moof", 0), (b"traf", 1), (b"tfhd", 0)]).1;
    let segment = patched(H264_AAC_0, tfhd + 4, &9_u32.to_be_bytes());
    let (reader, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(units.len(), 10);
    assert_eq!(reader.stats().unknown_tracks, 1);
    assert_eq!(reader.stats().dropped_outside, 0);
}

#[test]
fn iso14496_12_4_2_a_box_size_of_zero_runs_to_the_end_and_bytes_too_few_for_a_header_end() {
    let (_, whole) = read(H264_AAC_INIT, &[H264_AAC_0], MAX);
    // The mdat's size 0: to the end of the segment.
    let mdat = locate(H264_AAC_0, &[(b"mdat", 0)]).0;
    let segment = patched(H264_AAC_0, mdat, &[0; 4]);
    let (_, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(units, whole);
    // Three bytes after the last box: no header, ignored.
    let mut segment = H264_AAC_0.to_vec();
    segment.extend_from_slice(&[0, 0, 1]);
    let (reader, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(units, whole);
    assert_eq!(reader.stats().segments, 1);
    // An empty segment has nothing.
    let (reader, units) = read(H264_AAC_INIT, &[&[]], MAX);
    assert!(units.is_empty());
    assert_eq!(reader.stats().segments, 1);
}

#[test]
fn unreadable_init_segments_are_refused() {
    assert_eq!(Reader::new(&[], MAX).unwrap_err(), Fmp4Error::NoMovie);
    assert_eq!(
        Reader::new(H264_AAC_0, MAX).unwrap_err(),
        Fmp4Error::NoMovie
    );
    assert_eq!(
        Fmp4Error::NoMovie.to_string(),
        "the init segment has no movie box"
    );
    // ISO/IEC 14496-12 §4.2: a size below the header's own.
    let err = Reader::new(&[0, 0, 0, 4, b'f', b't', b'y', b'p'], MAX).unwrap_err();
    assert!(
        matches!(
            &err,
            Fmp4Error::Box {
                what: "init segment",
                ..
            }
        ),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with("the init segment cannot be read: ")
    );
    // The movie box cut short.
    let err = Reader::new(&H264_AAC_INIT[..600], MAX).unwrap_err();
    assert!(
        matches!(
            &err,
            Fmp4Error::Box {
                what: "movie box",
                ..
            }
        ),
        "{err:?}"
    );
    // ISO/IEC 14496-12 §8.4.2.3: a video timescale of zero.
    let mdhd = locate(
        H264_AAC_INIT,
        &[(b"moov", 0), (b"trak", 0), (b"mdia", 0), (b"mdhd", 0)],
    )
    .1;
    let init = patched(H264_AAC_INIT, mdhd + 12, &[0; 4]);
    let err = Reader::new(&init, MAX).unwrap_err();
    assert_eq!(err, Fmp4Error::Timescale { track: 1 });
    assert_eq!(err.to_string(), "track 1 has a timescale of zero");
}

#[test]
fn unreadable_media_segments_are_refused_and_the_next_one_read() {
    let err = segment_error(H264_AAC_INIT, &[0, 0, 0, 4, b's', b't', b'y', b'p']);
    assert!(
        matches!(
            &err,
            Fmp4Error::Box {
                what: "media segment",
                ..
            }
        ),
        "{err:?}"
    );
    // The moof cut short.
    let moof = locate(H264_AAC_0, &[(b"moof", 0)]).0;
    let err = segment_error(H264_AAC_INIT, &H264_AAC_0[..moof + 200]);
    assert!(
        matches!(
            &err,
            Fmp4Error::Box {
                what: "movie fragment",
                ..
            }
        ),
        "{err:?}"
    );
    // A box in the moof with a size below its header's.
    let mfhd = locate(H264_AAC_0, &[(b"moof", 0), (b"mfhd", 0)]).0;
    let segment = patched(H264_AAC_0, mfhd, &[0, 0, 0, 4]);
    let err = segment_error(H264_AAC_INIT, &segment);
    assert!(
        matches!(
            &err,
            Fmp4Error::Box {
                what: "movie fragment",
                ..
            }
        ),
        "{err:?}"
    );
    let mut reader = Reader::new(H264_AAC_INIT, MAX).unwrap();
    let mut units = Vec::new();
    assert!(reader.read_segment(&segment, &mut units).is_err());
    reader.read_segment(H264_AAC_0, &mut units).unwrap();
    assert_eq!(units.len(), 58);
}

#[test]
fn iso14496_12_8_8_8_the_declared_samples_add_up_the_runs_of_every_track_fragment() {
    assert_eq!(declared_samples(&[]).unwrap(), 0);
    let moof = locate(H264_AAC_0, &[(b"moof", 0)]);
    let body = &H264_AAC_0[moof.1..moof.0 + 412];
    assert_eq!(declared_samples(body).unwrap(), 58);
    // A run too short for its count adds nothing: mp4-atom refuses it.
    let short_run = [
        0, 0, 0, 20, b't', b'r', b'a', b'f', 0, 0, 0, 12, b't', b'r', b'u', b'n', 0, 0, 0, 0,
    ];
    assert_eq!(declared_samples(&short_run).unwrap(), 0);
}
