#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use std::future::Future;
use std::os::fd::OwnedFd;

use lotse_core::clock::{FakeClock, SystemClock};
use lotse_core::codec::Codec;
use lotse_core::let_assert;
use lotse_core::media::MediaTime;
use lotse_core::source::TrackPublisher;
use lotse_core::test_util::{FakeLiveFailure, FakeLiveMuxerFactory, fake_aac};
use lotse_core::track::TrackLimits;
use tokio::io::AsyncReadExt as _;
use tracing::Level;

use super::*;
use crate::test_logs::Logs;

/// `future`, or a failed test after ten seconds of real time.
async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::select! {
        out = future => out,
        () = SystemClock.sleep(Duration::from_secs(10)) => panic!("nothing within 10 s"),
    }
}

/// Lets the tasks run until they wait.
async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

fn h264() -> Codec {
    Codec::H264 {
        profile_level_id: None,
        sps: None,
        pps: None,
    }
}

fn h265() -> Codec {
    Codec::H265 {
        vps: None,
        sps: None,
        pps: None,
    }
}

fn spec(audio: bool, buffer_bytes: u32) -> LiveSpec {
    LiveSpec {
        live_id: "l1".into(),
        audio,
        buffer_bytes,
    }
}

/// A connection's tracks on a fake clock, and the live outputs that read
/// them.
struct Rig {
    clock: Arc<FakeClock>,
    t0: Instant,
    set: Arc<TrackSet>,
    publisher: TrackPublisher,
    video: Option<Arc<Track>>,
    audio: Option<Arc<Track>>,
    lives: Lives,
    reports: mpsc::Receiver<(String, LiveReport)>,
}

impl Rig {
    /// The tracks of `video` and `audio` under `limits`, declared ready if
    /// `ready`; the outputs report on a channel of `capacity`.
    fn with(
        video: Option<Codec>,
        audio: Option<Codec>,
        ready: bool,
        limits: TrackLimits,
        capacity: usize,
    ) -> Self {
        let clock = Arc::new(FakeClock::default());
        let t0 = clock.now();
        let set = TrackSet::new(limits, t0);
        let mut publisher = set.publisher();
        let video = video.map(|codec| publisher.declare(Kind::Video, codec, 90_000));
        let audio = audio.map(|codec| {
            let rate = codec.rtp_clock_rate().unwrap_or(8_000);
            publisher.declare(Kind::Audio, codec, rate)
        });
        if ready {
            publisher.ready();
        }
        let (reports_tx, reports) = mpsc::channel(capacity);
        Self {
            clock,
            t0,
            set,
            publisher,
            video,
            audio,
            lives: Lives::new(reports_tx),
            reports,
        }
    }

    fn new(audio: Option<Codec>) -> Self {
        Self::with(Some(h264()), audio, true, TrackLimits::default(), 64)
    }

    fn video(&self) -> &Arc<Track> {
        self.video.as_ref().unwrap()
    }

    /// Video frame `index` of `len` bytes, captured and arriving at
    /// `index` × 40 ms, the clock moved there; whether the track took it.
    fn video_frame(&self, index: u32, keyframe: bool, len: usize) -> bool {
        let at = self.t0 + Duration::from_millis(u64::from(index) * 40);
        if at > self.clock.now() {
            self.clock.advance(at - self.clock.now());
        }
        let header = if keyframe { 0x65 } else { 0x41 };
        self.video().publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(i64::from(index) * 3_600),
            wallclock: at,
            arrival: at,
            keyframe,
            discontinuity: false,
            epoch: 0,
            payload: vec![header; len].into(),
        })
    }

    fn audio_frame(&self, index: u32) {
        let at = self.clock.now();
        assert!(self.audio.as_ref().unwrap().publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(i64::from(index) * 1_024),
            wallclock: at,
            arrival: at,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: vec![0xe0; 4].into(),
        }));
    }

    /// Starts `spec`'s output through `factory`; the read end of its pipe.
    fn start_with(&mut self, spec: LiveSpec, factory: FakeLiveMuxerFactory) -> pipe::Receiver {
        let (reader, writer) = io::pipe().unwrap();
        self.lives.start(LiveStart {
            spec,
            pipe: pipe::Sender::from_owned_fd(OwnedFd::from(writer)).unwrap(),
            tracks: Arc::clone(&self.set),
            factory: Arc::new(factory),
            settings: LiveSettings::default(),
            clock: self.clock.clone(),
        });
        pipe::Receiver::from_owned_fd(OwnedFd::from(reader)).unwrap()
    }

    fn start(&mut self, spec: LiveSpec) -> pipe::Receiver {
        self.start_with(spec, FakeLiveMuxerFactory::default())
    }

    async fn report(&mut self) -> LiveReport {
        let (live_id, report) = within(self.reports.recv()).await.unwrap();
        assert_eq!(live_id, "l1");
        report
    }

    /// The `Closed` report, the others before it skipped: its reason,
    /// bytes, dropped frames and drops.
    async fn closed(&mut self) -> (String, u64, u64, u32) {
        loop {
            if let LiveReport::Closed {
                reason,
                bytes,
                dropped_frames,
                drops,
            } = self.report().await
            {
                self.lives.ended("l1");
                return (reason, bytes, dropped_frames, drops);
            }
        }
    }

    /// The `Started` report.
    async fn started(&mut self) -> LiveReport {
        let report = self.report().await;
        assert!(matches!(report, LiveReport::Started { .. }), "{report:?}");
        report
    }

    /// Starts an output without audio, fetched; the read end of its pipe.
    async fn fetched(&mut self) -> pipe::Receiver {
        let reader = self.start(spec(false, 1 << 20));
        self.started().await;
        assert!(self.lives.fetch("l1"));
        settle().await;
        reader
    }
}

/// Everything the pipe holds now, without waiting for its end.
async fn available(reader: &pipe::Receiver) -> Vec<u8> {
    settle().await;
    let mut out = Vec::new();
    let mut buf = vec![0; 1 << 20];
    while let Ok(read) = reader.try_read(&mut buf) {
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read]);
    }
    out
}

/// Everything up to the end of the pipe.
async fn rest(mut reader: pipe::Receiver) -> Vec<u8> {
    let mut bytes = Vec::new();
    within(reader.read_to_end(&mut bytes)).await.unwrap();
    bytes
}

/// The fake container's lines, payloads skipped.
fn lines(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while let Some(end) = rest.iter().position(|byte| *byte == b'\n') {
        let line = String::from_utf8_lossy(&rest[..end]).into_owned();
        rest = &rest[end + 1..];
        if line.starts_with("frame ") {
            let len: usize = line.rsplit(' ').next().unwrap().parse().unwrap();
            rest = &rest[len..];
        }
        out.push(line);
    }
    out
}

#[tokio::test]
async fn an_output_writes_its_init_at_once_and_its_media_from_the_cached_keyframe_once_fetched() {
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::new(Some(fake_aac()));
    assert!(rig.video_frame(0, false, 3), "before any keyframe");
    assert!(rig.video_frame(1, true, 5));
    assert!(rig.video_frame(2, false, 4));
    let reader = rig.start(spec(true, 1 << 20));
    assert_eq!(
        rig.started().await,
        LiveReport::Started {
            mime: "video/fake; codecs=\"h264,aac_lc\"".into(),
            video: "h264".into(),
            audio: Some("aac_lc".into()),
        }
    );
    assert!(rig.video_frame(3, false, 6), "before the fetch: not sent");
    assert_eq!(
        lines(&available(&reader).await),
        ["init video=h264 audio=aac_lc"]
    );
    assert!(rig.lives.fetch("l1"));
    assert_eq!(
        lines(&available(&reader).await),
        [
            "frame v 0 3600 k 5",
            "frame v 0 7200 - 4",
            "frame v 0 10800 - 6",
        ],
        "at the fetch, the GOP from its keyframe, the frames since the start included"
    );
    assert!(rig.lives.fetch("l1"), "a second fetch changes nothing");
    settle().await;
    assert!(rig.video_frame(4, false, 7));
    rig.audio_frame(0);
    assert_eq!(
        lines(&available(&reader).await),
        ["frame v 0 14400 - 7", "frame a 0 0 k 4"],
        "then the live ones"
    );
    assert!(rig.lives.stop("l1", LiveEnd::Stopped));
    let (reason, bytes, dropped, drops) = rig.closed().await;
    assert_eq!((reason.as_str(), dropped, drops), ("stopped", 0, 0));
    assert_eq!(rest(reader).await, b"", "nothing more");
    assert!(bytes > 0);
    assert!(!rig.lives.fetch("l1"), "over: not running");
    assert!(!rig.lives.stop("l1", LiveEnd::Stopped));
    assert_eq!(rig.lives.len(), 0);
    assert_eq!(
        logs.count(Level::INFO, "live: fetched; joining at the cached keyframe"),
        1
    );
}

#[tokio::test]
async fn audio_the_container_cannot_carry_is_omitted_with_a_warning_and_unasked_audio_is_none() {
    let mut rig = Rig::new(Some(Codec::Pcmu));
    let reader = rig.start(spec(true, 1 << 20));
    let_assert!(LiveReport::Started { audio, mime, .. } = rig.started().await);
    assert_eq!(
        (audio, mime.as_str()),
        (None, "video/fake; codecs=\"h264\"")
    );
    let_assert!(LiveReport::Warning { code, message } = rig.report().await);
    assert_eq!(code, "audio_omitted");
    assert!(message.contains("pcmu"), "{message}");
    rig.lives.stop("l1", LiveEnd::Stopped);
    rig.closed().await;
    assert_eq!(lines(&rest(reader).await), ["init video=h264"]);

    let mut rig = Rig::new(Some(fake_aac()));
    let _reader = rig.start(spec(false, 1 << 20));
    let_assert!(LiveReport::Started { audio, .. } = rig.started().await);
    assert_eq!(audio, None, "not asked for");
    rig.lives.stop("l1", LiveEnd::Stopped);
    let_assert!(LiveReport::Closed { reason, .. } = rig.report().await);
    assert_eq!(reason, "stopped", "no warning before it");
}

#[tokio::test]
async fn an_output_without_video_tracks_in_time_or_a_codec_it_carries_ends() {
    let mut rig = Rig::with(None, Some(fake_aac()), true, TrackLimits::default(), 8);
    let _reader = rig.start(spec(true, 1 << 20));
    assert_eq!(rig.closed().await.0, "no_video_track");

    for (video, ready, why) in [
        (h264(), false, "never ready"),
        (Codec::Mjpeg, true, "nothing it carries"),
    ] {
        let mut rig = Rig::with(Some(video), None, ready, TrackLimits::default(), 8);
        let _reader = rig.start(spec(true, 1 << 20));
        settle().await;
        rig.clock.advance(DEFAULT_LIVE_START_TIMEOUT);
        assert_eq!(rig.closed().await.0, "source_not_live", "{why}");
    }
}

#[tokio::test]
async fn an_output_waits_for_the_tracks_and_for_a_video_codec_it_carries() {
    let mut rig = Rig::with(Some(Codec::Mjpeg), None, false, TrackLimits::default(), 8);
    let _reader = rig.start(spec(false, 1 << 20));
    settle().await;
    rig.publisher.ready();
    settle().await;
    rig.video().set_codec(h264());
    let_assert!(LiveReport::Started { video, .. } = rig.started().await);
    assert_eq!(video, "h264");
    rig.lives.stop("l1", LiveEnd::Stopped);
    rig.closed().await;
}

#[tokio::test]
async fn an_output_whose_reader_is_gone_or_that_is_stopped_before_its_fetch_ends() {
    let mut rig = Rig::with(Some(h264()), None, false, TrackLimits::default(), 8);
    drop(rig.start(spec(false, 1 << 20)));
    assert_eq!(
        rig.closed().await.0,
        "client_gone",
        "while it waits for the tracks"
    );

    let mut rig = Rig::new(None);
    let reader = rig.start(spec(false, 1 << 20));
    rig.started().await;
    drop(reader);
    assert_eq!(
        rig.closed().await.0,
        "client_gone",
        "while it waits for the fetch"
    );

    let mut rig = Rig::new(None);
    let _reader = rig.start(spec(false, 1 << 20));
    rig.started().await;
    rig.lives.stop("l1", LiveEnd::Stopped);
    assert_eq!(rig.closed().await.0, "stopped", "before its fetch");

    let mut rig = Rig::new(None);
    rig.video_frame(0, true, 1);
    drop(rig.fetched().await);
    rig.video_frame(1, false, 1);
    assert_eq!(rig.closed().await.0, "client_gone", "while it streams");
}

#[tokio::test]
async fn a_container_that_fails_ends_the_output_internal_error() {
    for (fail, fetch) in [
        (FakeLiveFailure::Start, false),
        (FakeLiveFailure::Push, true),
    ] {
        let mut rig = Rig::new(None);
        rig.video_frame(0, true, 1);
        let _reader = rig.start_with(
            spec(false, 1 << 20),
            FakeLiveMuxerFactory { fail: Some(fail) },
        );
        if fetch {
            rig.started().await;
            rig.lives.fetch("l1");
        }
        assert_eq!(rig.closed().await.0, "internal_error", "{fail:?}");
    }
}

#[tokio::test]
async fn a_container_that_fails_at_a_hole_ends_the_output_internal_error() {
    let limits = TrackLimits {
        max_frame_bytes: 100,
        ..TrackLimits::default()
    };
    let mut rig = Rig::with(Some(h264()), None, true, limits, 8);
    let _reader = rig.start_with(
        spec(false, 1 << 20),
        FakeLiveMuxerFactory {
            fail: Some(FakeLiveFailure::Skip),
        },
    );
    rig.started().await;
    assert!(rig.lives.fetch("l1"));
    settle().await;
    rig.video_frame(0, true, 1);
    settle().await;
    assert!(!rig.video_frame(1, false, 101), "lost: a hole");
    settle().await;
    rig.video_frame(2, false, 1);
    assert_eq!(rig.closed().await.0, "internal_error");
}

#[tokio::test]
async fn after_the_fetch_an_output_without_a_keyframe_in_time_ends() {
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::new(Some(fake_aac()));
    let _reader = rig.start(spec(true, 1 << 20));
    rig.started().await;
    assert!(rig.lives.fetch("l1"));
    settle().await;
    rig.video_frame(0, false, 1);
    rig.audio_frame(0);
    settle().await;
    rig.clock.advance(DEFAULT_LIVE_START_TIMEOUT);
    assert_eq!(rig.closed().await.0, "source_not_live");
    assert_eq!(
        logs.count(Level::INFO, "live: no keyframe after the fetch in time"),
        1
    );
}

#[tokio::test]
async fn a_gop_the_cache_cut_short_is_not_sent_and_the_next_keyframe_starts_the_media() {
    let limits = TrackLimits {
        gop_cache_frames: 1,
        ..TrackLimits::default()
    };
    let mut rig = Rig::with(Some(h264()), None, true, limits, 8);
    rig.video_frame(0, true, 1);
    rig.video_frame(1, false, 1);
    assert!(rig.video().gop().unwrap().truncated());
    let reader = rig.fetched().await;
    rig.video_frame(2, false, 2);
    rig.video_frame(3, true, 3);
    assert_eq!(
        lines(&available(&reader).await),
        ["init video=h264", "frame v 0 10800 k 3"]
    );
    rig.lives.stop("l1", LiveEnd::Stopped);
    rig.closed().await;
}

/// The GOP lost a frame over `max_frame_bytes` before the fetch, which the
/// output's subscription, taken at the fetch, never saw: the frames after
/// the hole may reference it, so the GOP is not sent.
#[tokio::test]
async fn a_gop_that_lost_a_frame_before_the_fetch_is_not_sent_and_the_next_keyframe_starts_the_media()
 {
    let limits = TrackLimits {
        max_frame_bytes: 100,
        ..TrackLimits::default()
    };
    let mut rig = Rig::with(Some(h264()), None, true, limits, 8);
    rig.video_frame(0, true, 1);
    assert!(!rig.video_frame(1, false, 101), "lost");
    rig.video_frame(2, false, 2);
    let reader = rig.fetched().await;
    rig.video_frame(3, false, 3);
    rig.video_frame(4, true, 4);
    assert_eq!(
        lines(&available(&reader).await),
        ["init video=h264", "frame v 0 14400 k 4"]
    );
    rig.lives.stop("l1", LiveEnd::Stopped);
    rig.closed().await;
}

/// An output started after a codec family change, before the new
/// family's first keyframe, writes the new family's init segment: the old
/// family's GOP is not sent under it.
#[tokio::test]
async fn an_output_started_after_a_codec_family_change_joins_at_the_new_family_s_first_keyframe() {
    let mut rig = Rig::new(None);
    rig.video_frame(0, true, 1);
    rig.video_frame(1, false, 2);
    rig.video().set_codec(h265());
    let reader = rig.fetched().await;
    rig.video_frame(2, false, 3);
    rig.video_frame(3, true, 4);
    assert_eq!(
        lines(&available(&reader).await),
        ["init video=h265", "frame v 0 10800 k 4"]
    );
    rig.lives.stop("l1", LiveEnd::Stopped);
    rig.closed().await;
}

/// A change within the family (another H.264 profile) keeps the GOP
/// cache: an output started after it writes the new profile's init
/// segment, so the cached GOP of the old one is not sent under it, and the
/// output joins at the new profile's first keyframe.
#[tokio::test]
async fn an_output_started_after_a_profile_change_does_not_send_the_old_profile_s_gop() {
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::new(None);
    rig.video_frame(0, true, 1);
    rig.video_frame(1, false, 2);
    rig.video().set_codec(Codec::H264 {
        profile_level_id: Some([0x42, 0xc0, 0x1f]),
        sps: None,
        pps: None,
    });
    assert!(rig.video().gop().is_some(), "the cache stays");
    let reader = rig.fetched().await;
    rig.video_frame(2, false, 3);
    rig.video_frame(3, true, 4);
    assert_eq!(
        lines(&available(&reader).await),
        ["init video=h264", "frame v 0 10800 k 4"]
    );
    assert_eq!(
        logs.count(
            Level::INFO,
            "live: fetched; the cached GOP's format is not the init segment's, joining at the next keyframe"
        ),
        1
    );
    rig.lives.stop("l1", LiveEnd::Stopped);
    rig.closed().await;
}

/// The video track closes while the output waits for a codec it carries:
/// the output ends `stream_deleted` at once, not at the start timeout,
/// and does not spin on the closed subscription meanwhile.
#[tokio::test]
async fn a_video_track_closed_before_its_codec_is_carried_ends_the_output_stream_deleted() {
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::with(Some(Codec::Mjpeg), None, true, TrackLimits::default(), 8);
    let _reader = rig.start(spec(false, 1 << 20));
    settle().await;
    rig.video().close();
    assert_eq!(rig.closed().await.0, "stream_deleted");
    assert_eq!(
        logs.count(
            Level::INFO,
            "live: the video track closed before the output started"
        ),
        1
    );
}

/// The video track closes after `Started` but before any fetch: the
/// output ends `stream_deleted` at once and frees its slot, and the frames
/// it watched for that close until then were not sent.
#[tokio::test]
async fn a_video_track_closed_before_the_fetch_ends_the_output_stream_deleted() {
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::new(None);
    let reader = rig.start(spec(false, 1 << 20));
    rig.started().await;
    rig.video_frame(0, true, 1);
    settle().await;
    assert_eq!(lines(&available(&reader).await), ["init video=h264"]);
    rig.video().close();
    assert_eq!(rig.closed().await.0, "stream_deleted");
    assert_eq!(
        logs.count(Level::INFO, "live: the video track closed before the fetch"),
        1
    );
    assert!(!rig.lives.runs("l1"));
}

/// The real container holds a keyframe until the next frame gives its
/// duration (the fake holds a frame without a payload): a keyframe taken
/// before the start timeout ends the wait for one, even when its fragment
/// comes after it.
#[tokio::test]
async fn a_keyframe_the_container_holds_across_the_start_timeout_keeps_the_output() {
    let mut rig = Rig::new(None);
    let reader = rig.fetched().await;
    rig.video_frame(249, true, 0);
    settle().await;
    rig.clock.advance(Duration::from_millis(80));
    settle().await;
    rig.video_frame(251, false, 1);
    assert_eq!(
        lines(&available(&reader).await),
        ["init video=h264", "frame v 0 903600 - 1"]
    );
    rig.lives.stop("l1", LiveEnd::Stopped);
    assert_eq!(rig.closed().await.0, "stopped");
}

#[tokio::test]
async fn a_reader_that_falls_behind_costs_it_the_frames_up_to_the_next_keyframe_and_never_the_track()
 {
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::new(None);
    let reader = rig.start(spec(false, 100 * 1024));
    rig.started().await;
    rig.lives.fetch("l1");
    settle().await;
    // The pipe takes 64 KiB; past them the queue fills, and the frame that
    // finds it over 100 KiB starts the drop.
    rig.video_frame(0, true, 40 * 1024);
    for index in 1..8 {
        assert!(
            rig.video_frame(index, false, 40 * 1024),
            "the track never waits"
        );
        settle().await;
    }
    // Read: the queue goes into the pipe up to the drop's mark, however
    // little a pipe takes at once (8 KiB once the user's pipe pages run
    // short), and the next keyframe starts the media again; the frames
    // before it are left out.
    let mut all = within(async {
        let mut all = Vec::new();
        // A frame read in part is no line yet: the mark is looked for in
        // the bytes.
        while !all.windows(5).any(|bytes| bytes == b"skip\n") {
            all.extend(available(&reader).await);
        }
        all
    })
    .await;
    for index in 8..12 {
        all.extend(available(&reader).await);
        rig.video_frame(index, index == 10, 10);
    }
    all.extend(available(&reader).await);
    let seen = lines(&all);
    let skip = seen.iter().position(|line| line == "skip").expect("a drop");
    assert_eq!(
        seen[skip + 1..],
        ["frame v 0 36000 k 10", "frame v 0 39600 - 10"],
        "{seen:?}"
    );
    rig.lives.stop("l1", LiveEnd::Stopped);
    let (reason, _, dropped, drops) = rig.closed().await;
    assert_eq!(reason, "stopped");
    assert_eq!(drops, 1);
    assert!(dropped >= 2, "{dropped}");
    assert_eq!(
        logs.count(Level::WARN, "live: dropping to the next keyframe"),
        1
    );
    assert_eq!(rig.video().stats().frames, 12);
}

/// The buffer bound is exclusive: with none at all, a reader that keeps up
/// with the pipe loses nothing, as nothing waits in the queue.
#[tokio::test]
async fn a_reader_that_keeps_up_costs_no_frame_even_without_a_buffer() {
    let mut rig = Rig::new(None);
    let reader = rig.start(spec(false, 0));
    rig.started().await;
    assert!(rig.lives.fetch("l1"));
    settle().await;
    for index in 0..4 {
        rig.video_frame(index, index == 0, 3);
        settle().await;
    }
    assert_eq!(
        lines(&available(&reader).await),
        [
            "init video=h264",
            "frame v 0 0 k 3",
            "frame v 0 3600 - 3",
            "frame v 0 7200 - 3",
            "frame v 0 10800 - 3"
        ]
    );
    rig.lives.stop("l1", LiveEnd::Stopped);
    let (_, _, dropped, drops) = rig.closed().await;
    assert_eq!((dropped, drops), (0, 0));
}

#[tokio::test]
async fn a_frame_the_subscription_lost_drops_to_the_next_keyframe() {
    let limits = TrackLimits {
        max_frame_bytes: 100,
        ..TrackLimits::default()
    };
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::with(Some(h264()), None, true, limits, 8);
    let reader = rig.fetched().await;
    rig.video_frame(0, true, 1);
    settle().await;
    assert!(
        !rig.video_frame(1, false, 101),
        "over max_frame_bytes: dropped"
    );
    settle().await;
    rig.video_frame(2, false, 1);
    rig.video_frame(3, true, 1);
    // A frame the container holds, and an epoch's start, change nothing.
    rig.video_frame(4, false, 0);
    let _epoch = rig.video().start_epoch();
    settle().await;
    assert!(!rig.video_frame(5, false, 101), "a second loss");
    rig.video_frame(6, true, 1);
    assert_eq!(
        lines(&available(&reader).await),
        [
            "init video=h264",
            "frame v 0 0 k 1",
            "skip",
            "frame v 0 10800 k 1",
            "skip",
            "frame v 1 21600 k 1"
        ]
    );
    rig.lives.stop("l1", LiveEnd::Stopped);
    let (_, _, dropped, drops) = rig.closed().await;
    assert_eq!(
        (dropped, drops),
        (3, 2),
        "the lost frames and the one after the first"
    );
    assert_eq!(
        logs.count(Level::WARN, "live: dropping to the next keyframe"),
        1,
        "the second within the first's interval"
    );
}

#[tokio::test]
async fn a_codec_change_ends_the_output_unless_its_init_segment_still_describes_it() {
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::new(None);
    let _reader = rig.fetched().await;
    rig.video().set_codec(Codec::H264 {
        profile_level_id: None,
        sps: Some(vec![0x67].into()),
        pps: None,
    });
    settle().await;
    assert_eq!(
        logs.count(
            Level::DEBUG,
            "live: the codec changed within what the init segment describes; going on"
        ),
        1
    );
    rig.video().set_codec(h265());
    assert_eq!(rig.closed().await.0, "codec_changed");

    let mut rig = Rig::new(None);
    let _reader = rig.start(spec(false, 1 << 20));
    rig.started().await;
    rig.video().set_codec(h265());
    rig.lives.fetch("l1");
    assert_eq!(rig.closed().await.0, "codec_changed", "before the fetch");
}

#[tokio::test]
async fn lost_control_events_end_the_output_stream_changed() {
    let mut rig = Rig::new(None);
    let _reader = rig.fetched().await;
    // More changes than the control channel holds while the output does
    // not run: it misses some.
    for n in 0..40_u8 {
        rig.video().set_codec(Codec::H264 {
            profile_level_id: None,
            sps: Some(vec![0x67, n].into()),
            pps: None,
        });
    }
    assert_eq!(rig.closed().await.0, "stream_changed");
}

#[tokio::test]
async fn a_closed_video_track_ends_the_output_and_a_closed_audio_track_leaves_the_video() {
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::new(Some(fake_aac()));
    let _reader = rig.start(spec(true, 1 << 20));
    rig.started().await;
    rig.lives.fetch("l1");
    settle().await;
    rig.audio.as_ref().unwrap().set_codec(fake_aac());
    rig.audio.as_ref().unwrap().close();
    settle().await;
    assert_eq!(
        logs.count(
            Level::INFO,
            "live: the audio track closed; video alone from here"
        ),
        1
    );
    rig.video().close();
    assert_eq!(rig.closed().await.0, "stream_deleted");
}

#[tokio::test]
async fn a_shutdown_ends_the_outputs_shutting_down_or_aborts_one_that_cannot_report() {
    let mut rig = Rig::new(None);
    let _reader = rig.start(spec(false, 1 << 20));
    rig.started().await;
    let clock: Arc<dyn Clock> = rig.clock.clone();
    let by = rig.clock.now() + SHUTDOWN_GRACE;
    rig.lives.shutdown(&clock, by).await;
    assert_eq!(rig.closed().await.0, "shutting_down");

    // A report channel of one, never read: the output's `Closed` cannot go.
    let (logs, _guard) = Logs::capture();
    let mut rig = Rig::with(Some(h264()), None, true, TrackLimits::default(), 1);
    let reader = rig.start(spec(false, 1 << 20));
    settle().await;
    let clock: Arc<dyn Clock> = rig.clock.clone();
    let by = rig.clock.now() + SHUTDOWN_GRACE;
    let shutdown = rig.lives.shutdown(&clock, by);
    tokio::pin!(shutdown);
    tokio::select! {
        () = &mut shutdown => panic!("the output cannot report"),
        () = settle() => {}
    }
    rig.clock.advance(SHUTDOWN_GRACE);
    within(shutdown).await;
    assert_eq!(
        logs.count(Level::WARN, "live output still ending at shutdown; aborted"),
        1
    );
    assert_eq!(lines(&rest(reader).await), ["init video=h264"]);
}

#[tokio::test]
async fn the_supervisor_gone_aborts_the_outputs() {
    let mut rig = Rig::new(None);
    let reader = rig.start(spec(false, 1 << 20));
    rig.started().await;
    assert!(rig.lives.runs("l1"));
    // The init goes out once the runtime polled the new pipe.
    settle().await;
    rig.lives.abort_all();
    assert_eq!(rig.lives.len(), 0);
    assert_eq!(lines(&rest(reader).await), ["init video=h264"]);
}

#[test]
fn ends_carry_the_api_s_names_and_the_defaults_are_the_documented_limits() {
    let names: Vec<&str> = [
        LiveEnd::Stopped,
        LiveEnd::ClientGone,
        LiveEnd::StreamDeleted,
        LiveEnd::CodecChanged,
        LiveEnd::StreamChanged,
        LiveEnd::NoVideoTrack,
        LiveEnd::SourceNotLive,
        LiveEnd::ShuttingDown,
        LiveEnd::InternalError,
    ]
    .into_iter()
    .map(LiveEnd::name)
    .collect();
    assert_eq!(
        names,
        [
            "stopped",
            "client_gone",
            "stream_deleted",
            "codec_changed",
            "stream_changed",
            "no_video_track",
            "source_not_live",
            "shutting_down",
            "internal_error"
        ]
    );
    assert_eq!(
        LiveSettings::default(),
        LiveSettings {
            start_timeout: Duration::from_secs(10),
            max_outputs: 8,
        }
    );
}

#[tokio::test]
async fn an_audio_codec_change_past_the_init_segment_ends_the_output() {
    let mut rig = Rig::new(Some(fake_aac()));
    let _reader = rig.start(spec(true, 1 << 20));
    rig.started().await;
    rig.lives.fetch("l1");
    settle().await;
    rig.audio
        .as_ref()
        .unwrap()
        .set_codec(Codec::Opus { channels: 2 });
    assert_eq!(rig.closed().await.0, "codec_changed");
}
