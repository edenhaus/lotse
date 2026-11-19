#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_codec::aac::test_data::{SINE_16K_MONO, frames};
use lotse_codec::h264::annex_b_units;
use lotse_codec::{h264, h265};
use lotse_core::live::{LiveFragment, LiveMuxer as _, LiveMuxerFactory as _, LiveStep};
use lotse_core::recording::{RecordingError, RecordingTrack};
use lotse_core::{Codec, CodecFamily, Kind, MediaFrame};

use super::{AUDIO_FRAGMENT_BYTES, AUDIO_FRAGMENT_SPAN, Limits, LiveFactory, LiveWriter};
use crate::MAX_SAMPLE_BYTES;
use crate::fragment::Sample;
use crate::init::{NON_SYNC_SAMPLE, SYNC_SAMPLE, codecs};
use crate::tests::{
    FRAME, Read, aac_track, annex_b, base, frame, h264_au, h264_codec, h264_track, h265_au,
    h265_codec, h265_sps, h265_track, length_prefixed, ms, opus_track, read, samples,
};

/// One AAC-LC frame of the 16 kHz fixture: 1024 samples, 64 ms.
const AAC_FRAME: i64 = 1024;

/// What a live output wrote: its init segment and fragments as one file.
struct Output {
    writer: LiveWriter,
    file: Vec<u8>,
    fragments: Vec<LiveFragment>,
}

impl Output {
    fn start(video: &RecordingTrack, audio: Option<&RecordingTrack>) -> Self {
        Self::with(LiveWriter::new(), video, audio)
    }

    fn with(
        mut writer: LiveWriter,
        video: &RecordingTrack,
        audio: Option<&RecordingTrack>,
    ) -> Self {
        let init = writer.start(video, audio).unwrap();
        Self {
            writer,
            file: init.bytes.to_vec(),
            fragments: Vec::new(),
        }
    }

    fn keep(&mut self, fragment: LiveFragment) {
        for piece in &fragment.bytes {
            self.file.extend_from_slice(piece);
        }
        self.fragments.push(fragment);
    }

    fn push(&mut self, kind: Kind, frame: Arc<MediaFrame>) -> LiveStep {
        let step = self.writer.push(kind, frame).unwrap();
        if let LiveStep::Fragment(fragment) = &step {
            self.keep(fragment.clone());
        }
        step
    }

    /// Skips; true when held frames went out.
    fn skip(&mut self) -> bool {
        let fragment = self.writer.skip().unwrap();
        let some = fragment.is_some();
        if let Some(fragment) = fragment {
            self.keep(fragment);
        }
        some
    }
}

fn video(base: Instant, at: u64, ts: i64, key: bool, epoch: u32, n: u8) -> Arc<MediaFrame> {
    frame(ms(base, at), ts, key, epoch, h264_au(key, n))
}

fn aac(base: Instant, at: u64, ts: i64, epoch: u32, n: usize) -> Arc<MediaFrame> {
    let aac = frames(SINE_16K_MONO);
    let payload = Bytes::copy_from_slice(aac[n % aac.len()]);
    frame(ms(base, at), ts, true, epoch, payload)
}

fn is_fragment(step: &LiveStep) -> bool {
    matches!(step, LiveStep::Fragment(_))
}

/// A sample's presentation time: its decode time plus its composition
/// offset (ISO/IEC 14496-12 §8.8.8).
fn pts(sample: &Read) -> i64 {
    i64::try_from(sample.dts).unwrap() + i64::from(sample.cts)
}

/// Where a sample's presentation ends as written: its presentation time
/// plus its duration.
fn pts_end(sample: &Read) -> i64 {
    pts(sample) + i64::from(sample.duration)
}

/// The video's samples and the audio's, read back.
fn tracks(out: &Output) -> (Vec<Read>, Vec<Read>) {
    (samples(&out.file, 1), samples(&out.file, 2))
}

/// `ms` milliseconds of the 90 kHz video timescale.
fn video_ticks(ms: i64) -> i64 {
    ms * 90
}

/// `ms` milliseconds of the 16 kHz audio timescale.
fn audio_ticks(ms: i64) -> i64 {
    ms * 16
}

/// Checks the video at the keyframe at `index` that started it again:
/// presented where the samples before it end and decoded where their
/// decode ends, so no gap either way; returns its presentation time.
fn resumed_at(video: &[Read], index: usize) -> i64 {
    let key = &video[index];
    assert_eq!(key.flags, Some(SYNC_SAMPLE), "{video:?}");
    let before = &video[..index];
    let shown = before.iter().map(pts_end).max().unwrap();
    assert_eq!(pts(key), shown, "no hole in the presentation: {video:?}");
    let decoded = before.last().unwrap();
    assert_eq!(
        decoded.dts + u64::from(decoded.duration),
        key.dts,
        "no hole in the decode times: {video:?}"
    );
    pts(key)
}

#[test]
fn iso14496_12_8_8_4_each_video_frame_goes_out_in_a_fragment_of_its_own_once_the_next_arrives() {
    let base = base();
    let mut out = Output::start(&h264_track(), None);
    let aus: Vec<Bytes> = (0..4).map(|i| h264_au(i == 0, i)).collect();
    let steps: Vec<LiveStep> = (0..4_u8)
        .map(|i| {
            let au = aus[usize::from(i)].clone();
            let at = ms(base, u64::from(i) * 40);
            out.push(Kind::Video, frame(at, i64::from(i) * FRAME, i == 0, 0, au))
        })
        .collect();
    assert_eq!(
        steps[0],
        LiveStep::Held,
        "the first keyframe waits for its duration"
    );
    assert!(steps[1..].iter().all(is_fragment));
    let timing: Vec<(bool, Duration, Duration)> = out
        .fragments
        .iter()
        .map(|fragment| {
            (
                fragment.independent,
                fragment.decode_time,
                fragment.duration,
            )
        })
        .collect();
    let forty = Duration::from_millis(40);
    assert_eq!(
        timing,
        [
            (true, Duration::ZERO, forty),
            (false, forty, forty),
            (false, forty * 2, forty),
        ]
    );
    let read_back = samples(&out.file, 1);
    assert_eq!(read_back.len(), 3, "the last frame waits for the next");
    for (index, sample) in read_back.iter().enumerate() {
        assert_eq!(sample.fragment, index, "one sample per fragment");
        assert_eq!(
            sample.dts,
            u64::try_from(index).unwrap() * 3600,
            "decode times run on"
        );
        assert_eq!(sample.duration, 3600);
        let flags = if index == 0 {
            SYNC_SAMPLE
        } else {
            NON_SYNC_SAMPLE
        };
        assert_eq!(sample.flags, Some(flags));
        assert_eq!(sample.bytes, length_prefixed(&aus[index]));
    }
    // ISO/IEC 14496-12 §8.8.5: the sequence numbers count from 1.
    let sequences: Vec<u32> = read(&out.file)
        .fragments
        .iter()
        .map(|(moof, _)| moof.mfhd.sequence_number)
        .collect();
    assert_eq!(sequences, [1, 2, 3]);
}

#[test]
fn a_live_output_starts_at_a_video_keyframe_leaving_out_what_comes_before() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    assert!(!out.skip(), "nothing started: nothing to finish");
    assert_eq!(
        out.push(Kind::Audio, aac(base, 0, 0, 0, 0)),
        LiveStep::Dropped
    );
    assert_eq!(
        out.push(Kind::Video, video(base, 0, 0, false, 0, 0)),
        LiveStep::Dropped
    );
    assert_eq!(
        out.push(Kind::Video, video(base, 40, FRAME, true, 0, 1)),
        LiveStep::Held
    );
    assert!(is_fragment(
        &out.push(Kind::Video, video(base, 80, 2 * FRAME, false, 0, 2))
    ));
    let read_back = samples(&out.file, 1);
    assert_eq!(read_back.len(), 1);
    assert_eq!(read_back[0].dts, 0, "media time 0 is the first keyframe");
    assert_eq!(read_back[0].flags, Some(SYNC_SAMPLE));
}

#[test]
fn audio_goes_out_with_the_video_frame_after_it_finished_at_its_capture_time() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    let pushed = [
        (Kind::Video, video(base, 0, 0, true, 0, 0)),
        (Kind::Audio, aac(base, 0, 0, 0, 0)),
        (Kind::Video, video(base, 40, FRAME, false, 0, 1)),
        (Kind::Audio, aac(base, 64, AAC_FRAME, 0, 1)),
        (Kind::Video, video(base, 80, 2 * FRAME, false, 0, 2)),
        (Kind::Video, video(base, 120, 3 * FRAME, false, 0, 3)),
        (Kind::Audio, aac(base, 128, 2 * AAC_FRAME, 0, 2)),
        (Kind::Video, video(base, 160, 4 * FRAME, false, 0, 4)),
    ];
    let steps: Vec<bool> = pushed
        .iter()
        .map(|(kind, frame)| is_fragment(&out.push(*kind, Arc::clone(frame))))
        .collect();
    assert_eq!(
        steps,
        [false, false, true, false, true, true, false, true],
        "only a video frame completes a fragment"
    );
    let audio: Vec<(usize, u64, u32)> = samples(&out.file, 2)
        .iter()
        .map(|sample| (sample.fragment, sample.dts, sample.duration))
        .collect();
    assert_eq!(audio, [(1, 0, 1024), (3, 1024, 1024)]);
    assert_eq!(samples(&out.file, 1).len(), 4);
}

#[test]
fn a_skip_finishes_the_held_frames_and_the_next_keyframe_starts_where_the_video_ends() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    out.push(Kind::Video, video(base, 80, 2 * FRAME, false, 0, 2));
    assert!(out.skip(), "the held frame goes out");
    let skipped = out.fragments.last().unwrap().clone();
    assert_eq!(skipped.decode_time, Duration::from_millis(80));
    assert_eq!(
        skipped.duration,
        Duration::from_millis(40),
        "it lasts the duration of the frame before it"
    );
    assert!(!skipped.independent);
    assert!(!out.skip(), "waiting: nothing held");
    assert_eq!(
        out.push(Kind::Video, video(base, 120, 3 * FRAME, false, 0, 3)),
        LiveStep::Dropped
    );
    assert_eq!(
        out.push(Kind::Audio, aac(base, 120, 0, 0, 0)),
        LiveStep::Dropped
    );
    // Captured 2 s in, 1880 ms past the video's end at 120 ms: it is
    // decoded at 120 ms, and the origin moves 1880 ms on.
    let ts = 50 * FRAME;
    assert_eq!(
        out.push(Kind::Video, video(base, 2000, ts, true, 0, 4)),
        LiveStep::Held
    );
    out.push(Kind::Audio, aac(base, 2010, 40 * AAC_FRAME, 0, 1));
    out.push(Kind::Video, video(base, 2040, ts + FRAME, false, 0, 5));
    out.push(Kind::Audio, aac(base, 2074, 41 * AAC_FRAME, 0, 2));
    out.push(Kind::Video, video(base, 2080, ts + 2 * FRAME, false, 0, 6));
    let video_dts: Vec<(u64, u32)> = samples(&out.file, 1)
        .iter()
        .map(|sample| (sample.dts, sample.duration))
        .collect();
    assert_eq!(
        video_dts,
        [
            (0, 3600),
            (3600, 3600),
            (7200, 3600),
            (10_800, 3600),
            (14_400, 3600)
        ],
        "no hole in the decode times"
    );
    let resumed = &out.fragments[3];
    assert!(resumed.independent);
    assert_eq!(resumed.decode_time, Duration::from_millis(120));
    // The audio captured 10 ms after the keyframe: 130 ms, in 16 kHz ticks.
    let audio: Vec<u64> = samples(&out.file, 2)
        .iter()
        .map(|sample| sample.dts)
        .collect();
    assert_eq!(audio, [2080]);
}

#[test]
fn a_keyframe_captured_before_the_video_s_end_starts_right_after_it() {
    let base = base();
    let mut out = Output::start(&h264_track(), None);
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    assert!(out.skip());
    // Captured at 50 ms, before the video's end at 80 ms: no hole to leave
    // out, and the keyframe follows the video all the same.
    out.push(Kind::Video, video(base, 50, 9 * FRAME, true, 0, 2));
    out.push(Kind::Video, video(base, 90, 10 * FRAME, false, 0, 3));
    let video_dts: Vec<u64> = samples(&out.file, 1)
        .iter()
        .map(|sample| sample.dts)
        .collect();
    assert_eq!(video_dts, [0, 3600, 7200]);
}

#[test]
fn rfc3550_5_1_a_reconnect_starts_at_its_first_keyframe_where_the_video_ends() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Audio, aac(base, 0, 0, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 1000, 0, 1, 1)),
        LiveStep::Dropped,
        "audio of the new epoch waits for the video's keyframe"
    );
    assert_eq!(
        out.push(Kind::Video, video(base, 1000, 0, false, 1, 2)),
        LiveStep::Dropped,
        "the new epoch starts at a keyframe"
    );
    let step = out.push(Kind::Video, video(base, 1040, FRAME, true, 1, 3));
    let LiveStep::Fragment(ended) = step else {
        panic!("the epoch's held frames go out: {step:?}");
    };
    assert_eq!(ended.decode_time, Duration::from_millis(40));
    assert_eq!(ended.duration, Duration::from_millis(40));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 1050, 0, 1, 2)),
        LiveStep::Held,
        "the video started again: the audio follows"
    );
    out.push(Kind::Audio, aac(base, 1114, AAC_FRAME, 1, 3));
    out.push(Kind::Video, video(base, 1080, 2 * FRAME, false, 1, 4));
    let video_dts: Vec<u64> = samples(&out.file, 1)
        .iter()
        .map(|sample| sample.dts)
        .collect();
    assert_eq!(video_dts, [0, 3600, 7200]);
    assert!(out.fragments[2].independent);
    // The old epoch's audio went out with the break at its frame length;
    // the new epoch's is placed 10 ms after the keyframe, at 90 ms.
    let audio: Vec<(u64, u32)> = samples(&out.file, 2)
        .iter()
        .map(|sample| (sample.dts, sample.duration))
        .collect();
    assert_eq!(audio, [(0, 1024), (1440, 1024)]);
}

#[test]
fn iso14496_12_8_8_12_after_audio_went_out_alone_the_video_s_last_frame_lasts_until_it_ends() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Audio, aac(base, 0, 0, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    // The video stalls; the audio goes on, and out alone, until 640 ms.
    let alone = (1..10_u8)
        .filter(|&i| {
            let ts = i64::from(i) * AAC_FRAME;
            let at = u64::from(i) * 64;
            is_fragment(&out.push(Kind::Audio, aac(base, at, ts, 0, usize::from(i))))
        })
        .count();
    assert_eq!(alone, 1, "the audio went out alone once");
    assert!(out.skip());
    out.push(Kind::Video, video(base, 3000, 75 * FRAME, true, 0, 2));
    out.push(Kind::Audio, aac(base, 3010, 47 * AAC_FRAME, 0, 1));
    out.push(Kind::Video, video(base, 3040, 76 * FRAME, false, 0, 3));
    out.push(Kind::Audio, aac(base, 3074, 48 * AAC_FRAME, 0, 2));
    out.push(Kind::Video, video(base, 3080, 77 * FRAME, false, 0, 4));
    let (video, audio) = tracks(&out);
    let key = resumed_at(&video, 2);
    assert_eq!(
        key,
        video_ticks(640),
        "the video resumes where the audio ends"
    );
    assert_eq!(
        (video[1].dts, video[1].duration),
        (3600, 54_000),
        "the frame before the stall lasts until then"
    );
    assert_eq!(pts_end(&audio[9]), audio_ticks(640));
    assert_eq!(
        pts(&audio[10]),
        audio_ticks(640 + 10),
        "the audio is 10 ms after the keyframe, as captured"
    );
}

#[test]
fn iso14496_12_8_8_8_a_keyframe_after_reordered_video_is_presented_where_its_pictures_end() {
    let base = base();
    let mut out = Output::start(&h264_track(), None);
    // `I0 P3 B1 B2 P6 B4 B5` at 25 fps, each captured at its presentation:
    // decoded until 400 ms, presented until 280 ms, where `P6` ends.
    for (n, i) in [0_u8, 3, 1, 2, 6, 4, 5].into_iter().zip(0..) {
        let at = u64::from(n) * 40;
        out.push(
            Kind::Video,
            video(base, at, i64::from(n) * FRAME, n == 0, 0, i),
        );
    }
    assert!(out.skip());
    out.push(Kind::Video, video(base, 2000, 50 * FRAME, true, 0, 7));
    out.push(Kind::Video, video(base, 2040, 51 * FRAME, false, 0, 8));
    out.push(Kind::Video, video(base, 2080, 52 * FRAME, false, 0, 9));
    let (video, _) = tracks(&out);
    assert_eq!(resumed_at(&video, 7), video_ticks(280));
    let resumed: Vec<(u64, i32)> = video[7..]
        .iter()
        .map(|sample| (sample.dts, sample.cts))
        .collect();
    assert_eq!(
        resumed,
        [(36_000, -10_800), (39_600, -10_800)],
        "decoded where the video's decode ends, 120 ms after its presentation"
    );
}

#[test]
fn a_keyframe_captured_before_the_video_s_end_keeps_the_audio_after_it_by_capture_time() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Audio, aac(base, 0, 0, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    assert!(out.skip());
    // Captured at 50 ms, before the video's end at 80 ms: the keyframe
    // follows the video, and the audio 20 ms after it follows it.
    out.push(Kind::Video, video(base, 50, 9 * FRAME, true, 0, 2));
    out.push(Kind::Audio, aac(base, 70, 5 * AAC_FRAME, 0, 1));
    out.push(Kind::Video, video(base, 90, 10 * FRAME, false, 0, 3));
    out.push(Kind::Audio, aac(base, 134, 6 * AAC_FRAME, 0, 2));
    out.push(Kind::Video, video(base, 130, 11 * FRAME, false, 0, 4));
    let (video, audio) = tracks(&out);
    let key = resumed_at(&video, 2);
    assert_eq!(key, video_ticks(80));
    assert_eq!(pts(&audio[1]), audio_ticks(80 + 20));
}

#[test]
fn rfc3550_5_1_audio_of_a_reconnect_before_any_audio_keeps_its_place_by_capture_time() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    out.push(Kind::Video, video(base, 80, 2 * FRAME, false, 0, 2));
    // No audio before: the writer cannot tell the reconnect's from the
    // stream's first, which may come after the first keyframe.
    assert_eq!(
        out.push(Kind::Audio, aac(base, 1000, 0, 1, 0)),
        LiveStep::Held
    );
    out.push(Kind::Video, video(base, 1040, 0, true, 1, 3));
    out.push(Kind::Audio, aac(base, 1050, 10 * AAC_FRAME, 1, 1));
    out.push(Kind::Video, video(base, 1080, FRAME, false, 1, 4));
    out.push(Kind::Audio, aac(base, 1114, 11 * AAC_FRAME, 1, 2));
    out.push(Kind::Video, video(base, 1120, 2 * FRAME, false, 1, 5));
    let (video, audio) = tracks(&out);
    // The video's last frame lasts until that audio ends, at 1064 ms.
    let key = resumed_at(&video, 3);
    assert_eq!(key, video_ticks(1064));
    assert_eq!(pts(&audio[0]), audio_ticks(1000));
    assert_eq!(
        pts(&audio[1]),
        audio_ticks(1064 + 10),
        "the audio after the keyframe is 10 ms after it, as captured"
    );
}

#[test]
fn rfc3550_5_1_audio_of_a_reconnect_waits_for_the_video_when_the_audio_before_was_left_out() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 0, 0, 0, 0)),
        LiveStep::Dropped,
        "before the first keyframe"
    );
    out.push(Kind::Video, video(base, 16, 0, true, 0, 0));
    out.push(Kind::Video, video(base, 56, FRAME, false, 0, 1));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 1000, 0, 1, 1)),
        LiveStep::Dropped,
        "a new epoch: it waits for the video's"
    );
    out.push(Kind::Video, video(base, 1040, 0, true, 1, 2));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 1050, 2 * AAC_FRAME, 1, 2)),
        LiveStep::Held
    );
    out.push(Kind::Video, video(base, 1080, FRAME, false, 1, 3));
    let (written, audio) = tracks(&out);
    let key = resumed_at(&written, 2);
    assert_eq!(key, video_ticks(80));
    assert_eq!(audio.len(), 0, "the audio's frame is held");
    out.push(Kind::Audio, aac(base, 1114, 3 * AAC_FRAME, 1, 3));
    out.push(Kind::Video, video(base, 1120, 2 * FRAME, false, 1, 4));
    let (_, audio) = tracks(&out);
    assert_eq!(pts(&audio[0]), audio_ticks(80 + 10));
}

#[test]
fn rfc3550_5_1_audio_of_a_reconnect_after_a_resumed_skip_waits_for_the_video_s_keyframe() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Audio, aac(base, 0, 0, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    assert!(out.skip());
    // The video resumes in its epoch, and the audio of it with it.
    out.push(Kind::Video, video(base, 2000, 50 * FRAME, true, 0, 2));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 2010, 40 * AAC_FRAME, 0, 1)),
        LiveStep::Held
    );
    out.push(Kind::Video, video(base, 2040, 51 * FRAME, false, 0, 3));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 3000, 0, 1, 2)),
        LiveStep::Dropped,
        "a reconnect's audio before its video's keyframe"
    );
    out.push(Kind::Video, video(base, 3040, 0, true, 1, 4));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 3050, AAC_FRAME, 1, 3)),
        LiveStep::Held
    );
    out.push(Kind::Video, video(base, 3080, FRAME, false, 1, 5));
    out.push(Kind::Audio, aac(base, 3114, 2 * AAC_FRAME, 1, 4));
    out.push(Kind::Video, video(base, 3120, 2 * FRAME, false, 1, 6));
    let (video, audio) = tracks(&out);
    let key = resumed_at(&video, 4);
    assert_eq!(pts(&audio[2]), key / 90 * 16 + audio_ticks(10));
}

/// A reconnect whose video keyframe comes before its audio: the video has
/// started its new epoch already, so the new audio is taken from its first
/// frame, placed by capture time after the keyframe, not left out until
/// another start.
#[test]
fn rfc3550_5_1_audio_of_a_reconnect_whose_video_came_first_is_taken_at_once() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Audio, aac(base, 0, 0, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    // The reconnect: its keyframe first, then its audio.
    out.push(Kind::Video, video(base, 3000, 0, true, 1, 2));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 3010, 0, 1, 2)),
        LiveStep::Held,
        "the reconnect's audio, after its video's keyframe"
    );
    out.push(Kind::Video, video(base, 3040, FRAME, false, 1, 3));
    out.push(Kind::Audio, aac(base, 3074, AAC_FRAME, 1, 3));
    out.push(Kind::Video, video(base, 3080, 2 * FRAME, false, 1, 4));
    let (video, audio) = tracks(&out);
    let key = resumed_at(&video, 2);
    assert_eq!(
        audio.len(),
        2,
        "the old epoch's frame and the new one written so far"
    );
    assert_eq!(pts(&audio[1]), key / 90 * 16 + audio_ticks(10));
}

/// Two reconnects in a row whose audio comes before their video: the
/// first reconnect's keyframe placed its audio, so the second's audio
/// waits for its own keyframe again instead of joining the old timeline.
#[test]
fn rfc3550_5_1_audio_of_each_reconnect_whose_audio_came_first_waits_for_its_own_keyframe() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Audio, aac(base, 0, 0, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    for (epoch, at, n) in [(1, 1000, 2), (2, 3000, 4)] {
        assert_eq!(
            out.push(Kind::Audio, aac(base, at, 0, epoch, 1)),
            LiveStep::Dropped,
            "reconnect {epoch}'s audio before its keyframe"
        );
        out.push(Kind::Video, video(base, at + 40, 0, true, epoch, n));
        assert_eq!(
            out.push(Kind::Audio, aac(base, at + 50, AAC_FRAME, epoch, 2)),
            LiveStep::Held,
            "reconnect {epoch}'s audio after its keyframe"
        );
        out.push(
            Kind::Video,
            video(base, at + 80, FRAME, false, epoch, n + 1),
        );
    }
    out.push(Kind::Audio, aac(base, 3114, 2 * AAC_FRAME, 2, 3));
    out.push(Kind::Video, video(base, 3120, 2 * FRAME, false, 2, 6));
    let (video, audio) = tracks(&out);
    let key = resumed_at(&video, 4);
    assert_eq!(audio.len(), 3, "{audio:?}");
    assert_eq!(pts(&audio[2]), key / 90 * 16 + audio_ticks(10));
}

/// A reconnect whose video came first, then one whose audio came first:
/// the first's keyframe placed its audio, taken at once, so the second's
/// audio waits for its own keyframe.
#[test]
fn rfc3550_5_1_audio_of_a_reconnect_after_one_whose_video_came_first_waits_for_its_own_keyframe() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Audio, aac(base, 0, 0, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    out.push(Kind::Video, video(base, 1000, 0, true, 1, 2));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 1010, 0, 1, 1)),
        LiveStep::Held,
        "the first reconnect's audio, after its keyframe"
    );
    out.push(Kind::Video, video(base, 1040, FRAME, false, 1, 3));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 3000, 0, 2, 2)),
        LiveStep::Dropped,
        "the second reconnect's audio, before its keyframe"
    );
    out.push(Kind::Video, video(base, 3040, 0, true, 2, 4));
    assert_eq!(
        out.push(Kind::Audio, aac(base, 3050, AAC_FRAME, 2, 3)),
        LiveStep::Held
    );
}

/// Audio whose timestamp does not advance re-anchors at its capture time,
/// as a recording's (`audio_whose_timestamp_does_not_advance_starts_a_new_epoch`):
/// the samples before it go out at once, so the run they are in does not
/// carry it on from them.
#[test]
fn iso14496_12_8_8_8_audio_whose_timestamp_does_not_advance_begins_a_run_of_its_own() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Audio, aac(base, 0, 0, 0, 0));
    out.push(Kind::Audio, aac(base, 64, AAC_FRAME, 0, 1));
    // The same timestamp again, 200 ms in.
    assert!(is_fragment(
        &out.push(Kind::Audio, aac(base, 200, AAC_FRAME, 0, 2))
    ));
    out.push(Kind::Audio, aac(base, 264, 2 * AAC_FRAME, 0, 3));
    out.push(Kind::Video, video(base, 300, FRAME, false, 0, 1));
    let audio: Vec<(usize, u64, u32)> = samples(&out.file, 2)
        .iter()
        .map(|sample| (sample.fragment, sample.dts, sample.duration))
        .collect();
    // 200 ms at 16 kHz is 3200.
    assert_eq!(audio, [(0, 0, 1024), (0, 1024, 1024), (1, 3200, 1024)]);
}

#[test]
fn iso14496_12_8_8_8_the_video_s_last_frame_lasts_at_most_what_its_duration_field_holds() {
    let base = base();
    let mut out = Output::start(&h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Video, video(base, 40, FRAME, false, 0, 1));
    // The stream's first audio, captured 50 000 s on: past the 32 bits a
    // sample's duration has at 90 kHz (47 721 s).
    out.push(Kind::Audio, aac(base, 50_000_000, 0, 0, 0));
    assert!(out.skip());
    let (video, _) = tracks(&out);
    assert_eq!((video[1].dts, video[1].duration), (3600, u32::MAX));
}

fn audio_alone(limits: Limits, track: &RecordingTrack, count: usize) -> (Vec<usize>, Output) {
    let base = base();
    let mut out = Output::with(LiveWriter::with_limits(limits), &h264_track(), Some(track));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    let cuts = (0..count)
        .filter(|&i| {
            let n = u64::try_from(i).unwrap();
            let ts = i64::try_from(i).unwrap() * AAC_FRAME;
            is_fragment(&out.push(Kind::Audio, aac(base, n * 64, ts, 0, i)))
        })
        .collect();
    (cuts, out)
}

#[test]
fn audio_goes_out_alone_once_it_spans_the_bound_while_the_video_waits() {
    let limits = |audio_span| Limits {
        sample_bytes: MAX_SAMPLE_BYTES,
        audio_span,
        audio_bytes: AUDIO_FRAGMENT_BYTES,
    };
    // 7 finished frames span 448 ms, 8 span 512 ms: past 500 ms.
    let (cuts, out) = audio_alone(limits(AUDIO_FRAGMENT_SPAN), &aac_track(), 10);
    assert_eq!(cuts, [8]);
    let alone = &out.fragments[0];
    assert!(!alone.independent);
    assert_eq!(alone.duration, Duration::ZERO, "no video in it");
    assert_eq!(alone.decode_time, Duration::ZERO, "where the video ends");
    assert_eq!(samples(&out.file, 2).len(), 8);
    assert_eq!(samples(&out.file, 1), []);
    let (cuts, _) = audio_alone(limits(Duration::from_millis(512)), &aac_track(), 10);
    assert_eq!(cuts, [8], "a span of exactly the bound reaches it");
    assert_eq!(AUDIO_FRAGMENT_SPAN, Duration::from_millis(500));
}

/// Audio that goes out alone while the video waits is placed where the
/// video's decode ends (ISO/IEC 14496-12 §8.8.12: its `tfdt` is the track's
/// next decode time), not at the start of the media.
#[test]
fn iso14496_12_8_8_12_audio_out_alone_is_placed_where_the_video_s_decode_ends() {
    let base = base();
    let mut out = Output::with(LiveWriter::new(), &h264_track(), Some(&aac_track()));
    out.push(Kind::Video, video(base, 0, 0, true, 0, 0));
    out.push(Kind::Video, video(base, 40, 3_600, false, 0, 1));
    assert_eq!(out.fragments.len(), 1, "the keyframe, finished by the next");
    let mut alone = None;
    for i in 0..12 {
        let n = u64::try_from(i).unwrap();
        let ts = i64::try_from(i).unwrap() * AAC_FRAME;
        if is_fragment(&out.push(Kind::Audio, aac(base, n * 64, ts, 0, i))) {
            alone = out.fragments.last().cloned();
            break;
        }
    }
    let alone = alone.expect("the audio went out alone");
    assert!(!alone.independent);
    assert_eq!(alone.duration, Duration::ZERO, "no video in it");
    assert_eq!(
        alone.decode_time,
        Duration::from_millis(40),
        "where the video's decode ends"
    );
}

#[test]
fn audio_goes_out_alone_once_it_holds_the_bound() {
    // What a finished AAC frame holds: its payload, the one slice of it
    // and its sample's descriptor.
    let payload = frames(SINE_16K_MONO)[0].len();
    let holds = payload + size_of::<Bytes>() + size_of::<Sample>();
    let limits = |audio_bytes| Limits {
        sample_bytes: MAX_SAMPLE_BYTES,
        audio_span: AUDIO_FRAGMENT_SPAN,
        audio_bytes,
    };
    let (cuts, _) = audio_alone(limits(u64::try_from(holds).unwrap()), &aac_track(), 2);
    assert_eq!(cuts, [1], "one frame holding exactly the bound reaches it");
    let (cuts, _) = audio_alone(limits(u64::try_from(holds + 1).unwrap()), &aac_track(), 2);
    assert_eq!(
        cuts,
        Vec::<usize>::new(),
        "one frame short of the bound waits"
    );
    assert_eq!(AUDIO_FRAGMENT_BYTES, 1 << 20);
}

#[test]
fn iso14496_15_8_4_1_1_2_h265_live_samples_leave_the_entry_s_sets_out() {
    let base = base();
    let mut out = Output::start(&h265_track(), None);
    let key = h265_au(true, 0);
    out.push(Kind::Video, frame(base, 0, true, 0, key.clone()));
    out.push(
        Kind::Video,
        frame(ms(base, 40), FRAME, false, 0, h265_au(false, 1)),
    );
    let units = annex_b_units(&key);
    assert_eq!(
        samples(&out.file, 1)[0].bytes,
        length_prefixed(&annex_b(&[units[3]]))
    );
}

#[test]
fn rfc6381_3_3_the_mime_type_names_each_sample_entry_with_its_profile_and_level() {
    let mime = |video: &RecordingTrack, audio: Option<&RecordingTrack>| {
        LiveWriter::new().start(video, audio).unwrap().mime
    };
    // Baseline (66 = 0x42), constraint_set0 and 1 (0xc0), level 4.0 (40).
    assert_eq!(
        mime(&h264_track(), None),
        "video/mp4; codecs=\"avc1.42c028\""
    );
    assert_eq!(
        mime(&h264_track(), Some(&aac_track())),
        "video/mp4; codecs=\"avc1.42c028,mp4a.40.2\""
    );
    assert_eq!(
        mime(&h264_track(), Some(&opus_track(2))),
        "video/mp4; codecs=\"avc1.42c028,Opus\""
    );
    // ISO/IEC 14496-15 E.3: Main (1), conforming to Main and Main 10, so
    // flags 1 and 2, reversed 6; the Main tier at level 4 (120); the
    // progressive and frame-only flags, 0x90, and the five zero bytes
    // after them left out.
    assert_eq!(
        mime(&h265_track(), None),
        "video/mp4; codecs=\"hvc1.1.6.L120.90\""
    );
}

#[test]
fn iso14496_15_e_3_hvc1_names_the_profile_space_and_the_high_tier() {
    let entry = |profile_space: u32, high_tier: bool| {
        codecs(&h265_codec(h265_sps(profile_space, high_tier, 0, 0)), None).unwrap()
    };
    // Main 10 (2), compatible with itself only: flag 2, reversed 4; no
    // constraint flags at all.
    assert_eq!(entry(0, false), "hvc1.2.4.L120");
    assert_eq!(entry(1, true), "hvc1.A2.4.H120");
    assert_eq!(entry(2, false), "hvc1.B2.4.L120");
    assert_eq!(entry(3, false), "hvc1.C2.4.L120");
    let main = h265::test_data::sps_of_tier(1, true, 640, 480);
    assert_eq!(codecs(&h265_codec(main), None).unwrap(), "hvc1.1.6.H120.90");
}

#[test]
fn codecs_the_entries_cannot_name_fail() {
    let sps = h264::test_data::sps(320, 240);
    assert_eq!(
        codecs(&Codec::Pcmu, None),
        Err(RecordingError::Unsupported(CodecFamily::Pcmu))
    );
    assert_eq!(
        codecs(&h264_codec(sps), Some(&Codec::Pcma)),
        Err(RecordingError::Unsupported(CodecFamily::Pcma))
    );
    assert!(matches!(
        codecs(&h264_codec(vec![0x67]), None),
        Err(RecordingError::Failed(message)) if message.starts_with("h264 sps: ")
    ));
    assert!(matches!(
        codecs(&h265_codec(vec![0x42, 0x01]), None),
        Err(RecordingError::Failed(message)) if message.starts_with("h265 sps: ")
    ));
}

#[test]
fn calls_out_of_order_and_frames_the_output_cannot_take_fail() {
    let base = base();
    let failed = |call: &str| RecordingError::Failed(format!("{call} out of order"));
    let mut writer = LiveWriter::default();
    assert_eq!(
        writer.push(Kind::Video, video(base, 0, 0, true, 0, 0)),
        Err(failed("push"))
    );
    assert_eq!(writer.skip(), Err(failed("skip")));
    writer.start(&h264_track(), None).unwrap();
    assert_eq!(writer.start(&h264_track(), None), Err(failed("start")));
    assert_eq!(
        writer.push(Kind::Audio, aac(base, 0, 0, 0, 0)),
        Err(RecordingError::Failed(
            "an audio frame for a live output without audio".into()
        ))
    );
    let mut small = LiveWriter::with_limits(Limits {
        sample_bytes: 10,
        audio_span: AUDIO_FRAGMENT_SPAN,
        audio_bytes: AUDIO_FRAGMENT_BYTES,
    });
    small.start(&h264_track(), None).unwrap();
    assert_eq!(
        small.push(
            Kind::Video,
            frame(base, 0, true, 0, Bytes::from(vec![0; 10]))
        ),
        Ok(LiveStep::Held),
        "a frame of exactly the bound is a sample"
    );
    assert_eq!(
        small.push(
            Kind::Video,
            frame(base, 0, true, 0, Bytes::from(vec![0; 11]))
        ),
        Err(RecordingError::Failed(
            "a frame of 11 bytes is larger than a sample may be (10)".into()
        ))
    );
    let pcmu = RecordingTrack {
        codec: Codec::Pcmu,
        clock_rate: 8000,
    };
    assert_eq!(
        LiveWriter::new().start(&h264_track(), Some(&pcmu)),
        Err(RecordingError::Unsupported(CodecFamily::Pcmu))
    );
}

#[test]
fn the_live_factory_accepts_the_recording_s_codecs_and_makes_fresh_writers() {
    let factory = LiveFactory;
    assert!(factory.accepts(&h264_track().codec));
    assert!(factory.accepts(&aac_track().codec));
    assert!(!factory.accepts(&Codec::Pcmu));
    let mut writer = factory.muxer();
    assert!(writer.start(&h264_track(), None).is_ok());
    assert_eq!(
        writer.push(Kind::Video, video(base(), 0, 0, true, 0, 0)),
        Ok(LiveStep::Held)
    );
}
