#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use lotse_codec::h264::annex_b_units;
use mp4_atom::{Edts, Elst, ElstEntry, FixedPoint, Iref, Tfhd, Traf, Trun, TrunEntry, TrunSamples};

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
    assert_eq!(units, []);
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

/// The per-sample entries of `run`, which carries per-sample fields.
fn entries(run: &mut Trun) -> &mut Vec<TrunEntry> {
    let TrunSamples::Explicit(entries) = &mut run.samples else {
        panic!("a run with per-sample fields");
    };
    entries
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

/// ISO/IEC 14496-12 §8.8.8.2: `sample_composition_time_offset` is
/// unsigned in a version 0 run. The fixture's run retyped as version 0
/// reads its negative offsets as 2^32 ticks later, as mp4-atom 0.17.1
/// reads them (0.16.2 read every version signed).
#[test]
fn iso14496_12_8_8_8_version_0_runs_carry_unsigned_composition_offsets() {
    let (_, signed) = read(H264_BFRAMES_INIT, &[H264_BFRAMES_0], MAX);
    let version = trun(H264_BFRAMES_0, 0);
    assert_eq!(H264_BFRAMES_0[version], 1);
    let segment = patched(H264_BFRAMES_0, version, &[0]);
    let (_, units) = read(H264_BFRAMES_INIT, &[&segment], MAX);
    assert_eq!(units.len(), signed.len());
    // 2^32 ticks of 10 240 a second on the 90 kHz clock, exactly.
    let wrap = (1_i64 << 32) * 90_000 / 10_240;
    let mut wrapped = 0;
    for (unit, before) in units.iter().zip(&signed) {
        assert_eq!(unit.decode_time, before.decode_time);
        let negative = before.ts < before.decode_time;
        wrapped += usize::from(negative);
        let expected = if negative { wrap } else { 0 };
        assert_eq!(unit.ts - before.ts, expected);
    }
    assert_eq!(wrapped, 5);
}

/// A run without per-sample fields takes every sample's size and
/// duration from the defaults (ISO/IEC 14496-12 §8.8.8.1), however many
/// it declares: mp4-atom 0.17.1 reads it as a count, where 0.16.2
/// refused one of more than 4096 samples. The bound on a segment's
/// samples holds.
#[test]
fn iso14496_12_8_8_8_a_run_without_per_sample_fields_is_read_whatever_its_count() {
    let count = 5_000;
    let inherited = reencoded(H264_AAC_0, |moof, _| {
        moof.traf[1].trun[0].samples = TrunSamples::Inherited {
            count,
            first_flags: None,
        };
    });
    // The audio data, 4203 bytes, holds 29 of the tfhd's 143-byte frames.
    let (reader, units) = read(H264_AAC_INIT, &[&inherited], MAX);
    let audio = of_track(&units, 1);
    assert_eq!(audio.len(), 29);
    assert!(audio.iter().all(|unit| unit.payload.len() == 143));
    assert_eq!(audio[28].ts, 28 * 1024);
    assert_eq!(
        reader.stats().dropped_outside,
        u64::from(count) - 29,
        "the rest lie past the media data"
    );
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
        format!("a media segment declares {declared} samples, more than 262144")
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

/// Each sample may become a unit, so the bound holds for the whole
/// segment: movie fragments each under it are refused together, before
/// mp4-atom reads the first.
#[test]
fn iso14496_12_8_8_8_the_sample_bound_holds_over_all_the_movie_fragments() {
    let count = trun(H264_AAC_0, 0) + 4;
    let half = u32::try_from(MAX_SAMPLES / 2 + 1 - 48).unwrap();
    let fragment = patched(H264_AAC_0, count, &half.to_be_bytes());
    let segment = [&fragment[..], &fragment[..]].concat();
    let err = segment_error(H264_AAC_INIT, &segment);
    assert_eq!(
        err,
        Fmp4Error::TooManySamples {
            count: MAX_SAMPLES + 2
        }
    );
}

/// Runs pointing at the same bytes would copy them once per run: a
/// segment of a few kilobytes could become gigabytes of units. The
/// samples of a segment may cover its media data once.
#[test]
fn iso14496_12_8_8_8_samples_that_cover_more_than_the_media_data_overlap_and_are_refused() {
    // The video run a second time, at the same data offset.
    let segment = reencoded(H264_AAC_0, |moof, _| {
        let run = moof.traf[0].trun[0].clone();
        moof.traf[0].trun.push(run);
    });
    let (_, body) = locate(&segment, &[(b"mdat", 0)]);
    let media = segment.len() - body;
    let err = segment_error(H264_AAC_INIT, &segment);
    assert_eq!(err, Fmp4Error::OverlappingSamples { media });
    assert_eq!(
        err.to_string(),
        format!(
            "the samples of a media segment cover more than its {media} bytes of media data: they overlap"
        )
    );
    // The fixture's own samples cover its media data exactly: read whole,
    // and with its first video sample one byte longer (every sample still
    // inside the mdat, the video's last byte covered twice) refused.
    let (reader, _) = read(H264_AAC_INIT, &[H264_AAC_0], MAX);
    assert_eq!(reader.stats().samples, 58);
    let segment = reencoded(H264_AAC_0, |moof, _| {
        let run = &mut moof.traf[0].trun[0];
        if let Some(size) = entries(run).first_mut().unwrap().size.as_mut() {
            *size += 1;
        }
    });
    assert!(matches!(
        segment_error(H264_AAC_INIT, &segment),
        Fmp4Error::OverlappingSamples { .. }
    ));
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

/// A sample lies inside the media data box that holds it (ISO/IEC
/// 14496-12 §4.2, §8.1.1), whatever boxes come before it.
#[test]
fn iso14496_12_4_2_a_sample_is_inside_one_media_data_box_or_none() {
    let data = [10..20, 28..28, 36..50];
    for (range, expected) in [
        (10..20, true),
        (12..15, true),
        (36..50, true),
        (0..5, false),
        (9..12, false),
        (15..21, false),
        (20..21, false),
        (29..36, false),
        (40..51, false),
        (60..61, false),
    ] {
        assert_eq!(inside(&data, &range), expected, "{range:?}");
    }
    assert!(!inside(&[], &(0..1)));
}

/// Half a million empty media data boxes before the one with the samples
/// (a segment under 5 MiB): a box is found by binary search, so the
/// 131 072 one-byte samples take milliseconds where a scan of every box
/// for each would take over 68 billion steps and outlast the test's
/// three minutes (`.config/nextest.toml`).
#[test]
fn iso14496_12_4_2_many_media_data_boxes_cost_each_sample_a_logarithm() {
    const EMPTY: usize = 1 << 19;
    const SAMPLES: usize = 1 << 17;
    let mut data: Vec<Range<usize>> = (0..EMPTY).map(|box_| 8 * box_ + 8..8 * box_ + 8).collect();
    let start = 8 * EMPTY + 8;
    data.push(start..start + SAMPLES);
    let found = (0..SAMPLES)
        .filter(|&sample| inside(&data, &(start + sample..start + sample + 1)))
        .count();
    assert_eq!(found, SAMPLES);
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

/// A video sample of non-zero size whose NAL units are all empty (a
/// length field of 0, ISO/IEC 14496-15 §5.3.2) holds no access unit: it
/// is dropped as empty, not handed on without a payload. Regression:
/// the length-prefixed to Annex B conversion skips empty units, so such
/// a sample came out of it empty and was handed on (found by the
/// `fmp4_segment` fuzz target, which asserts every unit has a payload).
#[test]
fn iso14496_15_5_3_2_a_video_sample_of_only_empty_nal_units_is_dropped_as_empty() {
    let sizes = trun(H264_AAC_0, 0) + 16;
    let size = |sample: usize| {
        let at = sizes + 4 * sample;
        u32::from_be_bytes(H264_AAC_0[at..at + 4].try_into().unwrap()) as usize
    };
    // The first video sample starts at 548; the last is the tenth.
    let last = 548 + (0..9).map(size).sum::<usize>();
    let segment = patched(H264_AAC_0, sizes + 9 * 4, &8_u32.to_be_bytes());
    let segment = patched(&segment, last, &[0; 8]);
    let (reader, units) = read(H264_AAC_INIT, &[&segment], MAX);
    assert_eq!(reader.stats().dropped_empty, 1);
    assert_eq!(reader.stats().dropped_malformed, 0);
    assert_eq!(of_track(&units, 0).len(), 9);
    assert!(units.iter().all(|unit| !unit.payload.is_empty()));
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
        let rest: Vec<TrunEntry> = entries(&mut runs[0]).split_off(4);
        runs.push(Trun {
            data_offset: None,
            samples: rest.into(),
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
        for entry in entries(&mut moof.traf[1].trun[0]) {
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
        for entry in entries(&mut moof.traf[1].trun[0]) {
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
    assert_eq!(units, []);
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
    let declared = |body: &[u8]| check_boxes("movie fragment", body).unwrap();
    assert_eq!(declared(&[]), 0);
    let moof = locate(H264_AAC_0, &[(b"moof", 0)]);
    let body = &H264_AAC_0[moof.1..moof.0 + 412];
    assert_eq!(declared(body), 58);
    // A run too short for its count adds nothing: mp4-atom refuses it.
    let short_run = [
        0, 0, 0, 20, b't', b'r', b'a', b'f', 0, 0, 0, 12, b't', b'r', b'u', b'n', 0, 0, 0, 0,
    ];
    assert_eq!(declared(&short_run), 0);
    // Only the runs of the fragment's own track fragments give units: not
    // one in a track fragment inside another, nor one outside them.
    let run = boxed(b"trun", &[&[0; 4][..], &5_u32.to_be_bytes()].concat());
    assert_eq!(declared(&boxed(b"traf", &run)), 5);
    assert_eq!(declared(&boxed(b"traf", &boxed(b"traf", &run))), 0);
    assert_eq!(declared(&run), 0);
    // A run past the end of its track fragment is not read.
    let mut past_end = boxed(b"traf", &run);
    past_end[11] += 1;
    assert_eq!(declared(&past_end), 0);
}

/// `data` with `child` added as the last box of the box at `path`
/// ([`locate`]), it and the boxes around it grown by its size.
fn with_child(data: &[u8], path: &[(&[u8; 4], usize)], child: &[u8]) -> Vec<u8> {
    let grow = u32::try_from(child.len()).unwrap();
    let mut out = data.to_vec();
    let mut end = 0;
    for depth in 1..=path.len() {
        let start = locate(data, &path[..depth]).0;
        let size = u32::from_be_bytes(data[start..start + 4].try_into().unwrap());
        out[start..start + 4].copy_from_slice(&(size + grow).to_be_bytes());
        end = start + size as usize;
    }
    out.splice(end..end, child.iter().copied());
    out
}

/// `init` with `child` added as the last box of its movie box.
fn with_movie_child(init: &[u8], child: &[u8]) -> Vec<u8> {
    with_child(init, &[(b"moov", 0)], child)
}

/// An item reference box with one reference from `from` to items 2 and
/// 3, encoded by mp4-atom: version 1 when `from` needs 32 bits.
fn item_references(from: u32) -> Vec<u8> {
    let iref = Iref {
        references: vec![mp4_atom::Reference {
            reference_type: FourCC::new(b"dimg"),
            from_item_id: from,
            to_item_ids: vec![2, 3],
        }],
    };
    let mut encoded = Vec::new();
    iref.encode(&mut encoded).unwrap();
    encoded
}

/// The error mp4-atom gives for a reference whose size does not fit its
/// box, or its fields.
fn invalid_size(what: &'static str) -> Fmp4Error {
    Fmp4Error::Box {
        what,
        reason: "invalid size".to_owned(),
    }
}

/// The `fmp4_segment` fuzz target's crash (CI, 2026-10-24): the audio
/// rendition's run retyped as an item reference box whose references
/// claim more than it holds. mp4-atom 0.16.2 subtracted their sizes
/// unchecked and panicked in a debug build; 0.17.1 refuses the box
/// itself (its `Iref::decode_body_ext`).
#[test]
fn iso14496_12_8_11_12_an_item_reference_past_its_box_in_a_fragment_is_refused() {
    let mut patch = b"iref".to_vec();
    patch.extend_from_slice(&[0; 77]);
    patch.extend_from_slice(&[0xff, 0, 0, 0, 2]);
    let at = locate(SPLIT_AUDIO_0, &[(b"moof", 0), (b"traf", 0), (b"trun", 0)]).0 + 4;
    let segment = patched(SPLIT_AUDIO_0, at, &patch);
    let err = segment_error(SPLIT_AUDIO_INIT, &segment);
    assert_eq!(err, invalid_size("movie fragment"));
    assert_eq!(
        err.to_string(),
        "the movie fragment cannot be read: invalid size"
    );
}

/// mp4-atom reads an item reference box in every box it walks (ISO/IEC
/// 14496-12 §8.11.1 places it in a `meta`): the user data box retyped
/// as one claims the `meta` inside as a reference, whose size leaves
/// bytes its fields do not read.
#[test]
fn iso14496_12_8_11_12_an_item_reference_past_its_box_in_the_movie_is_refused() {
    let udta = locate(H264_AAC_INIT, &[(b"moov", 0), (b"udta", 0)]).0;
    let init = patched(H264_AAC_INIT, udta + 4, b"iref");
    assert_eq!(
        Reader::new(&init, MAX).unwrap_err(),
        invalid_size("movie box")
    );
}

/// A reference of version `version` (ISO/IEC 14496-12 §8.11.12.2):
/// `size`, then `reference_type`, `from_item_ID`, `reference_count` and
/// the IDs, each `id_size` bytes.
fn reference(size: u32, id_size: usize, ids: &[u32]) -> Vec<u8> {
    let mut out = size.to_be_bytes().to_vec();
    out.extend_from_slice(b"dimg");
    out.extend_from_slice(&1_u32.to_be_bytes()[4 - id_size..]);
    out.extend_from_slice(&u16::try_from(ids.len()).unwrap().to_be_bytes());
    for id in ids {
        out.extend_from_slice(&id.to_be_bytes()[4 - id_size..]);
    }
    out
}

/// mp4-atom 0.17.1 reads each reference of an item reference box
/// (ISO/IEC 14496-12 §8.11.12.2) within its size, in either version: the
/// sizes tiling the box exactly are read, and a size past the bytes
/// left, below its own, or past the fields it holds is refused.
#[test]
fn iso14496_12_8_11_12_each_reference_is_read_within_its_size() {
    let whole = Reader::new(H264_AAC_INIT, MAX).unwrap().layout().clone();
    for from in [1, 1 << 16] {
        let init = with_movie_child(H264_AAC_INIT, &item_references(from));
        assert_eq!(Reader::new(&init, MAX).unwrap().layout(), &whole);
    }
    let read = |version: u8, references: &[Vec<u8>]| {
        let iref = boxed(
            b"iref",
            &[&[version, 0, 0, 0][..], &references.concat()].concat(),
        );
        Reader::new(&with_movie_child(H264_AAC_INIT, &iref), MAX).map(|_| ())
    };
    for (version, id_size, own) in [(0_u8, 2, 14_u32), (1, 4, 18)] {
        let exact = [reference(own, id_size, &[2]), reference(own, id_size, &[3])];
        assert_eq!(read(version, &exact), Ok(()), "v{version}");
        // The second one byte longer than the bytes left.
        let past = [
            reference(own, id_size, &[2]),
            reference(own + 1, id_size, &[3]),
        ];
        // Size 0 is below the size field's own four bytes, and a size
        // one past the fields leaves a byte they do not read.
        let zero = [reference(0, id_size, &[2])];
        let loose = [[&reference(own + 1, id_size, &[2])[..], &[0]].concat()];
        for refused in [&past[..], &zero, &loose] {
            assert_eq!(
                read(version, refused),
                Err(invalid_size("movie box")),
                "v{version}"
            );
        }
    }
}

/// A box of type `kind`, four bytes, with `body` (ISO/IEC 14496-12 §4.2).
fn boxed(kind: &[u8], body: &[u8]) -> Vec<u8> {
    let size = u32::try_from(8 + body.len()).unwrap();
    [&size.to_be_bytes()[..], kind, body].concat()
}

/// An item reference box whose one reference claims a byte more than
/// the box holds.
fn past() -> Vec<u8> {
    boxed(b"iref", &[&[0; 4][..], &reference(13, 2, &[])].concat())
}

/// The walk of `body` as the body of a movie box.
fn walk(body: &[u8]) -> Result<u64, Fmp4Error> {
    check_boxes("movie box", body)
}

/// The steps of the walks `run` takes ([`step`]).
fn steps_of(run: impl FnOnce()) -> u64 {
    let before = STEPS.with(std::cell::Cell::get);
    run();
    STEPS.with(std::cell::Cell::get) - before
}

/// The refusal of a walk that reads boxes nested too deep.
fn too_deep() -> Result<u64, Fmp4Error> {
    Err(Fmp4Error::TooDeep { what: "movie box" })
}

/// The fields of an audio sample entry of `version`, its QTFF
/// extension included.
fn audio(version: u8) -> Vec<u8> {
    let extension = match version {
        1 => 16,
        2 => 36,
        _ => 0,
    };
    [&[0; 8][..], &[0, version], &[0; 18], &vec![0; extension]].concat()
}

/// Bodies of a movie box with `child`, a box, inside every box whose
/// boxes mp4-atom 0.17.1 reads by their type, after that box's own
/// fields.
fn holding(child: &[u8]) -> Vec<Vec<u8>> {
    let mut bodies = vec![child.to_vec()];
    for kind in [
        b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"mvex", b"moof", b"traf",
        b"mfra", b"iprp", b"ipco",
    ] {
        bodies.push(boxed(kind, child));
    }
    // ISO/IEC 14496-12 §8.11.1: after the version and flags, unless the
    // handler follows at once (Apple's QTFF); in a user data box too.
    let hdlr = boxed(b"hdlr", &[0; 25]);
    let meta = boxed(b"meta", &[&[0; 4][..], &hdlr, child].concat());
    bodies.push(meta.clone());
    bodies.push(boxed(b"meta", &[&hdlr[..], child].concat()));
    bodies.push(boxed(b"udta", &meta));
    // The sample entries, after their fields (§8.5.2.2, §12).
    bodies.push(boxed(b"stsd", &[&[0; 8][..], child].concat()));
    for kind in [
        b"avc1", b"avc3", b"hev1", b"hvc1", b"vp08", b"vp09", b"av01", b"jpeg", b"uncv",
    ] {
        bodies.push(boxed(kind, &[&[0; 78][..], child].concat()));
    }
    for kind in [
        b"mp4a", b"Opus", b"fLaC", b"ac-3", b"ec-3", b".mp3", b"sowt", b"twos", b"lpcm", b"ipcm",
        b"fpcm", b"in24", b"in32", b"fl32", b"fl64", b"s16l",
    ] {
        for version in 0..=2 {
            bodies.push(boxed(kind, &[&audio(version)[..], child].concat()));
        }
    }
    bodies.push(boxed(b"samr", &[&[0; 28][..], child].concat()));
    bodies.push(boxed(b"tx3g", &[&[0; 38][..], child].concat()));
    for kind in [b"wvtt", b"evte", b"mebx"] {
        bodies.push(boxed(kind, &[&[0; 8][..], child].concat()));
    }
    // After the label, a URI box (§12.3.3.2).
    let label = boxed(b"uri ", &[0; 5]);
    bodies.push(boxed(b"urim", &[&[0; 8][..], &label, child].concat()));
    bodies.push(boxed(b"mett", &[&[0; 8][..], b"text\0\0", child].concat()));
    bodies.push(boxed(b"metx", &[&[0; 8][..], b"a\0b\0c\0", child].concat()));
    // A `mebx`'s keys, each holding boxes.
    let keys = boxed(b"keys", &boxed(b"key1", child));
    bodies.push(boxed(b"mebx", &[&[0; 8][..], &keys].concat()));
    // A size of 0 runs to the end of the body around it; a large size
    // (`largesize`).
    bodies.push([&[0; 4][..], &child[4..]].concat());
    let large = u64::try_from(child.len() + 8).unwrap();
    bodies.push(
        [
            &1_u32.to_be_bytes()[..],
            &child[4..8],
            &large.to_be_bytes(),
            &child[8..],
        ]
        .concat(),
    );
    bodies
}

/// Boxes nested past the deepest are refused wherever mp4-atom reads
/// boxes by their type, and an edit box that holds none is read past.
#[test]
fn iso14496_12_4_2_boxes_are_walked_where_mp4_atom_reads_them() {
    for body in holding(&nested(MAX_DEPTH)) {
        assert_eq!(walk(&body), too_deep(), "{body:?}");
    }
    for body in holding(&nested(1)) {
        assert!(walk(&body).is_ok(), "{body:?}");
    }
}

/// Bytes mp4-atom 0.17.1 reads as data, fields or padding are not boxes,
/// whatever they hold, nor is a box it does not read: edit boxes nested
/// past the deepest there are not refused.
#[test]
fn iso14496_12_4_2_bytes_mp4_atom_reads_as_data_are_not_boxes() {
    let deep = nested(MAX_DEPTH);
    let mut bodies = vec![
        // §8.1.2: padding, here holding a box header of size 0.
        boxed(b"free", &[0, 0, 0, 0, b'e', b'd', b't', b's']),
        boxed(b"free", &deep),
        boxed(b"mdat", &deep),
        boxed(b"abcd", &deep),
        // A user data box reads its other boxes as data, and `keys` hold
        // boxes in a `mebx` alone.
        boxed(b"udta", &deep),
        boxed(b"keys", &boxed(b"key1", &deep)),
        // After a sample entry's fields in a version it refuses or a body
        // too short for one.
        boxed(b"mp4a", &[&audio(3)[..], &deep].concat()),
        boxed(b"mp4a", &[0; 9]),
        // The second string read to the first null, the first byte of
        // the boxes' size.
        boxed(b"mett", &[&[0; 8][..], b"text\0", &deep].concat()),
        boxed(b"metx", &[&[0; 8][..], b"abc"].concat()),
        // The spherical and stereo video boxes of a visual sample entry,
        // read by their headers, nothing in them by its type.
        boxed(b"avc1", &[&[0; 78][..], &boxed(b"vexu", &deep)].concat()),
        boxed(b"hvc1", &[&[0; 78][..], &boxed(b"sv3d", &deep)].concat()),
    ];
    // A box past the end of its body, a size below the header's, and too
    // few bytes for a header.
    let mut long = deep.clone();
    long[3] += 1;
    bodies.push(long);
    let mut short = deep.clone();
    short[3] = 7;
    bodies.push(short);
    bodies.push(deep[..7].to_vec());
    for body in &bodies {
        assert!(walk(body).is_ok(), "{body:?}");
    }
    // Inside a visual sample entry's fields: nothing past its header.
    let fields = boxed(b"avc1", &[&nested(9)[..], &[0; 6]].concat());
    assert_eq!(fields.len(), 8 + 78);
    assert_eq!(steps_of(|| assert_eq!(walk(&fields), Ok(0))), 1);
}

/// `n` edit boxes inside one another.
fn nested(n: usize) -> Vec<u8> {
    (0..n).fold(Vec::new(), |inner, _| boxed(b"edts", &inner))
}

#[test]
fn iso14496_12_4_2_boxes_nested_past_the_deepest_are_refused() {
    let deep = too_deep();
    // The movie box itself is the first.
    assert!(walk(&nested(MAX_DEPTH - 1)).is_ok());
    assert_eq!(walk(&nested(MAX_DEPTH)), deep);
    // A `mebx`, its keys and each key are boxes deeper.
    let keys = |more: usize| {
        let key = boxed(b"key1", &nested(MAX_DEPTH - 4 + more));
        boxed(b"mebx", &[&[0; 8][..], &boxed(b"keys", &key)].concat())
    };
    assert!(walk(&keys(0)).is_ok());
    assert_eq!(walk(&keys(1)), deep);
}

/// mp4-atom reads boxes nested in one another on the stack: a few
/// hundred overflowed it and aborted the process. The deepest it reads
/// is read as before.
#[test]
fn iso14496_12_4_2_boxes_nested_past_the_deepest_are_refused_before_mp4_atom_reads_them() {
    let whole = Reader::new(H264_AAC_INIT, MAX).unwrap().layout().clone();
    let init = with_movie_child(H264_AAC_INIT, &nested(MAX_DEPTH - 1));
    assert_eq!(Reader::new(&init, MAX).unwrap().layout(), &whole);
    for n in [MAX_DEPTH, 1_000] {
        let init = with_movie_child(H264_AAC_INIT, &nested(n));
        let err = Reader::new(&init, MAX).unwrap_err();
        assert_eq!(err, Fmp4Error::TooDeep { what: "movie box" });
        assert_eq!(
            err.to_string(),
            "the movie box nests boxes more than 16 deep"
        );
    }
    let segment = with_child(SPLIT_AUDIO_0, &[(b"moof", 0)], &nested(1_000));
    assert_eq!(
        segment_error(SPLIT_AUDIO_INIT, &segment),
        Fmp4Error::TooDeep {
            what: "movie fragment"
        }
    );
}

/// An item reference box is data to the walk: the review's input (PR
/// #81), whose references of size 0 each hold another box header, is
/// walked in a step, its header, however many it holds.
#[test]
fn iso14496_12_8_11_12_item_references_are_data_to_the_walk() {
    for n in [256_usize, 512] {
        let references: Vec<u8> = (0..n)
            .flat_map(|k| {
                let size = u32::try_from(8 + 4 + 24 * (n - 1 - k)).unwrap();
                let ids = [&size.to_be_bytes()[..], b"iref", &[0; 4]].concat();
                let mut reference = reference(0, 2, &[0; 6]);
                reference[12..].copy_from_slice(&ids);
                reference
            })
            .collect();
        let body = boxed(b"iref", &[&[0; 4][..], &references].concat());
        assert_eq!(
            body.windows(4).filter(|kind| kind == b"iref").count(),
            n + 1
        );
        let steps = steps_of(|| assert_eq!(walk(&body), Ok(0)));
        assert_eq!(steps, 1);
    }
}

/// An item reference box past its box inside a sample entry and inside
/// the user data box's meta box is refused as mp4-atom reads them; the
/// type inside padding is read past, and so are the spherical video
/// boxes of a visual sample entry whatever they hold.
#[test]
fn iso14496_12_8_11_12_item_references_in_the_movie_where_mp4_atom_reads_them() {
    let avc1 = [
        (b"moov", 0),
        (b"trak", 0),
        (b"mdia", 0),
        (b"minf", 0),
        (b"stbl", 0),
        (b"stsd", 0),
        (b"avc1", 0),
    ];
    let meta = [(b"moov", 0), (b"udta", 0), (b"meta", 0)];
    for path in [&avc1[..], &meta] {
        let init = with_child(H264_AAC_INIT, path, &past());
        assert_eq!(
            Reader::new(&init, MAX).unwrap_err(),
            invalid_size("movie box")
        );
    }
    let whole = Reader::new(H264_AAC_INIT, MAX).unwrap().layout().clone();
    let padding = boxed(b"free", &[0, 0, 0, 0, b'i', b'r', b'e', b'f']);
    for init in [
        with_movie_child(H264_AAC_INIT, &padding),
        with_child(H264_AAC_INIT, &avc1, &boxed(b"free", &past())),
        with_child(H264_AAC_INIT, &avc1, &boxed(b"vexu", &nested(1_000))),
    ] {
        assert_eq!(Reader::new(&init, MAX).unwrap().layout(), &whole);
    }
}

/// mp4-atom 0.16.2 counted a sample group description's entries
/// (ISO/IEC 14496-12 §8.9.3) unchecked: an `sgpd` of an unknown grouping
/// type, its first entry reading the box to its end, declared billions
/// of empty ones in 20 bytes, each allocated. 0.17.1 refuses a count
/// past the bytes left, in a track fragment and in the sample table
/// alike.
#[test]
fn iso14496_12_8_9_3_a_sample_group_count_past_its_box_is_refused() {
    let sgpd = boxed(
        b"sgpd",
        &[&[0; 4][..], b"test", &0xffff_ff00_u32.to_be_bytes()].concat(),
    );
    let refused = |what| Fmp4Error::Box {
        what,
        reason: "over decode: sgpd".to_owned(),
    };
    let segment = with_child(H264_AAC_0, &[(b"moof", 0), (b"traf", 0)], &sgpd);
    assert_eq!(
        segment_error(H264_AAC_INIT, &segment),
        refused("movie fragment")
    );
    let stbl = [
        (b"moov", 0),
        (b"trak", 0),
        (b"mdia", 0),
        (b"minf", 0),
        (b"stbl", 0),
    ];
    let init = with_child(H264_AAC_INIT, &stbl, &sgpd);
    assert_eq!(Reader::new(&init, MAX).unwrap_err(), refused("movie box"));
}

/// mp4-atom 0.16.2 read 65 535 extents of no bytes for each item of an
/// item location box whose sizes are all 0 (ISO/IEC 14496-12 §8.11.3):
/// six bytes declared some 1.5 MB. 0.17.1 refuses a second such extent.
#[test]
fn iso14496_12_8_11_3_repeated_item_extents_of_no_bytes_are_refused() {
    // Version 0, every size 0, 16 items of 65 535 extents.
    let items: Vec<u8> = (1..=16_u16)
        .flat_map(|id| [&id.to_be_bytes()[..], &[0, 0], &[0xff, 0xff]].concat())
        .collect();
    let iloc = boxed(b"iloc", &[&[0; 6][..], &[0, 16], &items].concat());
    let hdlr = boxed(b"hdlr", &[0; 25]);
    let meta = boxed(b"meta", &[&[0; 4][..], &hdlr, &iloc].concat());
    let init = with_movie_child(H264_AAC_INIT, &meta);
    assert_eq!(
        Reader::new(&init, MAX).unwrap_err(),
        Fmp4Error::Box {
            what: "movie box",
            reason: "over decode: iloc".to_owned(),
        }
    );
}

/// The audio sample entry of [`H264_AAC_INIT`].
const MP4A: [(&[u8; 4], usize); 7] = [
    (b"moov", 0),
    (b"trak", 1),
    (b"mdia", 0),
    (b"minf", 0),
    (b"stbl", 0),
    (b"stsd", 0),
    (b"mp4a", 0),
];

/// A descriptor's `sizeOfInstance` (ISO/IEC 14496-1 §8.3.3) in as few
/// bytes as it takes, most significant first.
fn size_of_instance(size: usize) -> Vec<u8> {
    let mut out = vec![u8::try_from(size & 0x7f).unwrap()];
    let mut rest = size >> 7;
    while rest > 0 {
        out.insert(0, u8::try_from(rest & 0x7f).unwrap() | 0x80);
        rest >>= 7;
    }
    out
}

/// A descriptor with `tag` and `body`.
fn descriptor_of(tag: u8, body: &[u8]) -> Vec<u8> {
    [&[tag][..], &size_of_instance(body.len()), body].concat()
}

/// `n` descriptors with `tag` inside one another, each after `fields`,
/// built from the inside out.
fn nested_descriptors(n: usize, tag: u8, fields: &[u8]) -> Vec<u8> {
    let mut bodies = Vec::with_capacity(n);
    let mut inner = 0;
    for _ in 0..n {
        let body = fields.len() + inner;
        bodies.push(body);
        inner = 1 + size_of_instance(body).len() + body;
    }
    let mut out = Vec::with_capacity(inner);
    for body in bodies.into_iter().rev() {
        out.push(tag);
        out.extend(size_of_instance(body));
        out.extend_from_slice(fields);
    }
    out
}

/// An `esds` holding `descriptors` after its version and flags (ISO/IEC
/// 14496-14 §3.1.2).
fn esds(descriptors: &[u8]) -> Vec<u8> {
    boxed(b"esds", &[&[0; 4][..], descriptors].concat())
}

#[test]
fn iso14496_1_8_3_3_descriptor_sizes_are_read_as_mp4_atom_reads_them() {
    fn read(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        descriptor(data).map(|it| (it.tag, it.body, it.after))
    }
    // One byte of size, and two of seven bits, most significant first.
    assert_eq!(read(&[5, 1, 9, 7]), Some((5, &[9][..], &[7][..])));
    let long = [&[4, 0x81, 0x00][..], &[0; 128], &[6]].concat();
    assert_eq!(read(&long), Some((4, &[0; 128][..], &[6][..])));
    assert_eq!(size_of_instance(128), [0x81, 0x00]);
    // At most four bytes, the fourth without `nextByte`.
    assert_eq!(
        read(&[3, 0x80, 0x80, 0x80, 0x01, 6]),
        Some((3, &[6][..], &[][..]))
    );
    // No tag, no size, a size cut short, a fourth byte with `nextByte`
    // set, a body past the end.
    for cut in [
        &[][..],
        &[3],
        &[3, 0x81],
        &[3, 0x80, 0x80, 0x80, 0x80, 6],
        &[3, 0x80, 0x80, 0x80, 0x81, 6],
        &[3, 2, 0],
    ] {
        assert_eq!(read(cut), None, "{cut:?}");
    }
}

/// mp4-atom 0.17.1 refuses a descriptor whose size runs to a fifth byte,
/// and reads nothing in it: the walk reads nothing there either.
#[test]
fn iso14496_1_8_3_3_a_size_of_five_bytes_is_refused_before_its_body() {
    let deep = nested_descriptors(MAX_DEPTH, 0x03, &[0; 3]);
    let five = [&[0x03, 0x80, 0x80, 0x80, 0x80, 0x00][..], &deep].concat();
    assert_eq!(walk(&esds(&five)), Ok(0));
    let init = with_movie_child(H264_AAC_INIT, &esds(&five));
    assert_eq!(
        Reader::new(&init, MAX).unwrap_err(),
        invalid_size("movie box")
    );
}

/// Where the descriptors of an `ES_Descriptor` begin: after the optional
/// fields its flags announce (ISO/IEC 14496-1 §7.2.6.5.1), as mp4-atom
/// 0.17.1 reads them.
#[test]
fn iso14496_1_7_2_6_5_1_the_descriptors_follow_the_optional_fields() {
    assert_eq!(es_fields(&[0, 1, 0]), 3);
    assert_eq!(es_fields(&[0, 1, 0x80, 0, 2]), 5);
    assert_eq!(es_fields(&[0, 1, 0x40, 2, b'a', b'b']), 6);
    assert_eq!(es_fields(&[0, 1, 0x20, 0, 3]), 5);
    assert_eq!(es_fields(&[0, 1, 0xe0, 0, 2, 1, b'a', 0, 3]), 9);
    // `streamPriority`, the low five bits, announces nothing.
    assert_eq!(es_fields(&[0, 1, 0x1f]), 3);
    // Too short for the flags, or for the URL's length: no descriptor.
    for short in [&[][..], &[0, 1], &[0, 1, 0x40]] {
        assert_eq!(es_fields(short), short.len(), "{short:?}");
    }
    // A URL past the body: none either.
    assert!(es_fields(&[0, 1, 0x40, 9, b'a']) > 5);
}

/// mp4-atom reads an `ES_Descriptor` or a `DecoderConfigDescriptor`
/// wherever it finds one, the descriptors in each on the stack: nested
/// past the deepest, boxes and descriptors counted alike, they are
/// refused; other descriptors are read as data, and so are the optional
/// fields of an `ES_Descriptor`.
#[test]
fn iso14496_1_7_2_6_5_descriptors_nested_past_the_deepest_are_refused() {
    let deep = too_deep();
    // The movie box and the `esds` are the first two.
    let es = |flags: &[u8]| [&[0, 1][..], flags].concat();
    for (tag, fields) in [
        (0x03, es(&[0])),
        (0x03, es(&[0x80, 0, 2])),
        (0x03, es(&[0x40, 2, b'a', b'b'])),
        (0x03, es(&[0x20, 0, 3])),
        (0x03, es(&[0xe0, 0, 2, 1, b'a', 0, 3])),
        (0x04, vec![0; 13]),
    ] {
        let fits = nested_descriptors(MAX_DEPTH - 2, tag, &fields);
        assert_eq!(walk(&esds(&fits)), Ok(0), "{fields:?}");
        let past = nested_descriptors(MAX_DEPTH - 1, tag, &fields);
        assert_eq!(walk(&esds(&past)), deep, "{fields:?}");
        // After another descriptor.
        assert_eq!(walk(&esds(&[&fits[..], &past].concat())), deep);
        // A `DecoderSpecificInfo`, an `SLConfigDescriptor` or a descriptor
        // mp4-atom does not know holds data.
        for data in [0x05, 0x06, 0x7f] {
            assert_eq!(walk(&esds(&descriptor_of(data, &past))), Ok(0));
        }
    }
    // A URL holding descriptors nested past the deepest is a string.
    let url = nested_descriptors(MAX_DEPTH, 0x03, &[0; 3]);
    let fields = [&es(&[0x40, u8::try_from(url.len()).unwrap()])[..], &url].concat();
    assert_eq!(walk(&esds(&descriptor_of(0x03, &fields))), Ok(0));
    // An `esds` too short for its version and flags.
    assert_eq!(walk(&boxed(b"esds", &[0; 3])), Ok(0));
}

/// `init` with its movie box decoded by mp4-atom, changed by `change` and
/// encoded again in its place.
fn reencoded_init(init: &[u8], change: impl FnOnce(&mut Moov)) -> Vec<u8> {
    let (start, _) = locate(init, &[(b"moov", 0)]);
    let size = u32::from_be_bytes(init[start..start + 4].try_into().unwrap()) as usize;
    let mut moov = Moov::decode(&mut &init[start..]).unwrap();
    change(&mut moov);
    let mut encoded = Vec::new();
    moov.encode(&mut encoded).unwrap();
    [&init[..start], &encoded, &init[start + size..]].concat()
}

/// The `esds` of the audio sample entry of `moov`.
fn audio_esds(moov: &mut Moov) -> &mut Esds {
    let SampleEntry::Mp4a(mp4a) = &mut moov.trak[1].mdia.minf.stbl.stsd.codecs[0] else {
        panic!("an mp4a");
    };
    &mut mp4a.esds
}

/// An `ES_Descriptor` with every optional field (ISO/IEC 14496-1
/// §7.2.6.5.1) gives the stream's AAC as one without: mp4-atom 0.16.2
/// read the fields as descriptors.
#[test]
fn iso14496_1_7_2_6_5_1_an_es_descriptor_with_optional_fields_is_read() {
    let whole = Reader::new(H264_AAC_INIT, MAX).unwrap().layout().clone();
    let init = reencoded_init(H264_AAC_INIT, |moov| {
        let es = &mut audio_esds(moov).es_desc;
        es.depends_on_es_id = Some(2);
        es.url = Some(b"a".to_vec());
        es.ocr_es_id = Some(3);
        es.stream_priority = 31;
    });
    assert_ne!(init, H264_AAC_INIT);
    assert_eq!(walk(&init[locate(&init, &[(b"moov", 0)]).1..]), Ok(0));
    assert_eq!(Reader::new(&init, MAX).unwrap().layout(), &whole);
}

/// The review's input (PR #81): an `esds` of 100 000 `ES_Descriptor`s one
/// inside another, some 700 KiB, which mp4-atom 0.16.2 read on the
/// stack: it overflowed and aborted the process. Refused before mp4-atom
/// reads it, wherever it reads one: in the movie box, in an `mp4a`, and
/// in a QTFF `wave` there.
#[test]
fn iso14496_1_7_2_6_5_descriptors_nested_past_the_deepest_are_refused_before_mp4_atom_reads_them() {
    let deep = esds(&nested_descriptors(100_000, 0x03, &[0; 3]));
    assert!(deep.len() > 600 << 10);
    for init in [
        with_movie_child(H264_AAC_INIT, &deep),
        with_child(H264_AAC_INIT, &MP4A, &deep),
        with_child(H264_AAC_INIT, &MP4A, &boxed(b"wave", &deep)),
    ] {
        let err = Reader::new(&init, MAX).unwrap_err();
        assert_eq!(err, Fmp4Error::TooDeep { what: "movie box" });
    }
}

/// The stream's own `esds` moved into a QTFF `wave` is read as before:
/// the deepest sample entries nest. mp4-atom 0.17.1 refuses a second
/// `esds` of one `mp4a`, in a `wave` or not (its `DuplicateBox`), which
/// 0.16.2 read over the first.
#[test]
fn qtff_the_esds_of_an_mp4a_in_a_wave_is_read_once() {
    let whole = Reader::new(H264_AAC_INIT, MAX).unwrap().layout().clone();
    let at = find(H264_AAC_INIT, b"esds") - 4;
    let size = u32::from_be_bytes(H264_AAC_INIT[at..at + 4].try_into().unwrap());
    let own = &H264_AAC_INIT[at..at + size as usize];
    let moved = patched(H264_AAC_INIT, at + 4, b"free");
    let init = with_child(&moved, &MP4A, &boxed(b"wave", own));
    assert_eq!(Reader::new(&init, MAX).unwrap().layout(), &whole);
    for init in [
        with_child(H264_AAC_INIT, &MP4A, &boxed(b"wave", own)),
        with_child(H264_AAC_INIT, &MP4A, own),
    ] {
        assert_eq!(
            Reader::new(&init, MAX).unwrap_err(),
            Fmp4Error::Box {
                what: "movie box",
                reason: "duplicate box: esds".to_owned()
            }
        );
    }
}

/// mp4-atom reads a QTFF `wave` in an `mp4a` for its `esds` alone (its
/// `decode_wave`), and none of size 0; a `wave` elsewhere is data.
#[test]
fn qtff_a_wave_in_an_mp4a_is_read_for_its_esds_alone() {
    let deep = esds(&nested_descriptors(MAX_DEPTH, 0x03, &[0; 3]));
    let mp4a = |wave: &[u8]| boxed(b"mp4a", &[&audio(0)[..], &boxed(b"wave", wave)].concat());
    let frma = boxed(b"frma", b"mp4a");
    assert_eq!(walk(&mp4a(&[&frma[..], &deep].concat())), too_deep());
    let mut size_0 = deep.clone();
    size_0[..4].copy_from_slice(&[0; 4]);
    for body in [
        mp4a(&nested(MAX_DEPTH)),
        mp4a(&size_0),
        boxed(b"wave", &deep),
        boxed(b"Opus", &[&audio(0)[..], &boxed(b"wave", &deep)].concat()),
    ] {
        assert_eq!(walk(&body), Ok(0), "{body:?}");
    }
}

/// Each descriptor is read once: a step per two bytes at most.
#[test]
fn iso14496_1_8_3_3_descriptors_are_read_once() {
    for n in [1_000_u64, 2_000] {
        let flat: Vec<u8> = (0..n).flat_map(|_| [0x05, 0]).collect();
        let body = esds(&flat);
        let steps = steps_of(|| assert_eq!(walk(&body), Ok(0)));
        assert_eq!(steps, 1 + n);
        assert!(steps <= body.len() as u64 / 2);
    }
}

/// mp4-atom reads the first box of a meta box as its handler (ISO/IEC
/// 14496-12 §8.11.1, its `Hdlr::decode`) and the label of a `urim` as its
/// URI box (§12.3.3.2, its `Uri::decode`): one of that type it reads as
/// fields, not by its type, and one of another type mp4-atom 0.17.1
/// refuses, reading no box after it. Edit boxes nested past the deepest
/// there are not refused by the walk.
#[test]
fn iso14496_12_8_11_1_and_12_3_3_2_a_box_read_as_a_fixed_type_is_not_read_by_its_own() {
    let edits = nested(1_000);
    let whole = Ok(Reader::new(H264_AAC_INIT, MAX).unwrap().layout().clone());
    let read = |child: &[u8]| {
        assert_eq!(walk(child), Ok(0), "{child:?}");
        let init = with_movie_child(H264_AAC_INIT, child);
        Reader::new(&init, MAX).map(|reader| reader.layout().clone())
    };
    let refused = |reason: &str| {
        Err(Fmp4Error::Box {
            what: "movie box",
            reason: reason.to_owned(),
        })
    };
    // A handler holding edit boxes: its name ends at the first null, the
    // rest skipped as padding.
    let hdlr = boxed(b"hdlr", &edits[8..]);
    assert_eq!(read(&boxed(b"meta", &[&[0; 4][..], &hdlr].concat())), whole);
    // A URI box holding them: its URI ends at the first null, short of
    // its box, which mp4-atom refuses.
    let uri = boxed(b"uri ", &edits[8..]);
    assert_eq!(
        read(&boxed(b"urim", &[&[0; 8][..], &uri].concat())),
        refused("under decode: uri ")
    );
    // The edit boxes themselves, or after a first box of another type.
    let iref = item_references(1);
    for label in [&edits[..], &[&iref[..], &edits].concat()] {
        let kind = String::from_utf8_lossy(&label[4..8]).into_owned();
        for child in [
            boxed(b"meta", &[&[0; 4][..], label].concat()),
            boxed(b"urim", &[&[0; 8][..], label].concat()),
        ] {
            assert_eq!(read(&child), refused(&format!("unexpected box: {kind}")));
        }
    }
    // Without one, mp4-atom refuses the box and reads nothing after it.
    for child in [
        boxed(b"meta", &[0; 4]),
        boxed(b"urim", &[&[0; 8][..], &past()[..9]].concat()),
    ] {
        assert_eq!(walk(&child), Ok(0));
    }
}

/// A `keys` holds keys in a `mebx` alone (ISO/IEC 14496-12 §12.8, as
/// mp4-atom cites it): in a key, even one whose `local_key_id` is
/// `mebx`, it is the flat keys table mp4-atom reads as fields; a `mebx`
/// in a key is read as one.
#[test]
fn iso14496_12_12_8_keys_hold_keys_in_a_mebx_alone() {
    let deep = nested(MAX_DEPTH);
    let keyd = boxed(b"keyd", b"mdtax");
    let mebx = |key: &[u8]| boxed(b"mebx", &[&[0; 8][..], &boxed(b"keys", key)].concat());
    // As a keys table: an entry count of 1, and the edit boxes' header
    // and body as its one entry.
    let table = boxed(b"keys", &boxed(&[0, 0, 0, 1], &deep));
    let in_key = mebx(&boxed(b"mebx", &[&keyd[..], &table].concat()));
    assert_eq!(walk(&in_key), Ok(0));
    let whole = Reader::new(H264_AAC_INIT, MAX).unwrap().layout().clone();
    let init = with_movie_child(H264_AAC_INIT, &in_key);
    assert_eq!(Reader::new(&init, MAX).unwrap().layout(), &whole);
    let inner = mebx(&boxed(b"key1", &deep));
    assert_eq!(
        walk(&mebx(&boxed(b"mebx", &[&keyd[..], &inner].concat()))),
        too_deep()
    );
}

/// Every movie fragment of a segment is walked before mp4-atom reads the
/// first: one it would refuse to read comes before a fragment whose
/// boxes nest too deep, and the walk's refusal is the error.
#[test]
fn iso14496_12_4_2_every_movie_fragment_is_walked_before_mp4_atom_reads_one() {
    let mfhd = locate(H264_AAC_0, &[(b"moof", 0), (b"mfhd", 0)]).0;
    let first = patched(H264_AAC_0, mfhd + 4, b"free");
    let err = segment_error(H264_AAC_INIT, &first);
    assert_eq!(
        err,
        Fmp4Error::Box {
            what: "movie fragment",
            reason: "missing box: mfhd".to_owned()
        }
    );
    let second = with_child(H264_AAC_0, &[(b"moof", 0)], &nested(1_000));
    let segment = [&first[..], &second].concat();
    assert_eq!(
        segment_error(H264_AAC_INIT, &segment),
        Fmp4Error::TooDeep {
            what: "movie fragment",
        }
    );
}
