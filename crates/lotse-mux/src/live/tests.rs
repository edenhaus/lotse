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
    FRAME, aac_track, annex_b, base, frame, h264_au, h264_codec, h264_track, h265_au, h265_codec,
    h265_sps, h265_track, length_prefixed, ms, opus_track, read, samples,
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

#[test]
fn a_codec_change_continues_the_output_only_while_the_init_segment_describes_it() {
    let mut writer = LiveWriter::new();
    assert!(
        !writer.continues(Kind::Video, &h264_track()),
        "nothing written yet"
    );
    writer.start(&h264_track(), Some(&aac_track())).unwrap();
    assert!(writer.continues(Kind::Video, &h264_track()));
    assert!(writer.continues(Kind::Audio, &aac_track()));
    let video = |codec: Codec, clock_rate: u32| RecordingTrack { codec, clock_rate };
    let resized = h264_codec(h264::test_data::sps(640, 480));
    assert!(
        !writer.continues(Kind::Video, &video(resized, 90_000)),
        "another picture size"
    );
    assert!(
        !writer.continues(Kind::Video, &h265_track()),
        "another codec"
    );
    assert!(
        !writer.continues(Kind::Video, &video(h264_track().codec, 48_000)),
        "another clock rate"
    );
    let unset = Codec::H264 {
        profile_level_id: None,
        sps: None,
        pps: None,
    };
    assert!(
        !writer.continues(Kind::Video, &video(unset, 90_000)),
        "no entry to write"
    );
    assert!(!writer.continues(Kind::Audio, &opus_track(1)));
    // RFC 6381 §3.3: the same `mp4a.40.2` at the same rate, but another
    // configuration than the `esds` carries.
    let stereo = RecordingTrack {
        codec: Codec::AacLc {
            sample_rate: 16_000,
            channels: 2,
            config: Bytes::from_static(&[0x14, 0x10]),
        },
        clock_rate: 16_000,
    };
    assert!(
        !writer.continues(Kind::Audio, &stereo),
        "another AAC configuration"
    );
    assert!(
        !writer.continues(Kind::Audio, &h264_track()),
        "video where the audio was"
    );
    let pcmu = RecordingTrack {
        codec: Codec::Pcmu,
        clock_rate: 8000,
    };
    assert!(!writer.continues(Kind::Audio, &pcmu), "nothing carries it");
    let mut silent = LiveWriter::new();
    silent.start(&h264_track(), None).unwrap();
    assert!(
        !silent.continues(Kind::Audio, &aac_track()),
        "no audio written"
    );
}
