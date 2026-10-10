#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use std::fmt::Write as _;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use lotse_core::clock::{Clock, FakeClock, SystemClock};
use lotse_core::codec::CodecFamily;
use lotse_core::media::MediaFrame;
use lotse_core::source::{ResolvedPeer, Source, SourceError, SourceExit, TrackSet};
use lotse_core::source_url::SourceUrl;
use lotse_core::track::{FrameSubscription, Track};
use lotse_core::{Codec, Kind};
use lotse_testing::Harness;
use lotse_testing::fake_camera::CameraTls;
use lotse_testing::fake_http::{FakeHttp, Reply};
use lotse_tls::{Fingerprint, TlsTarget, Trust};

use super::test_data::{LIVE_0, LIVE_1, LIVE_2};
use super::*;
use crate::fmp4::test_data::{
    H264_AAC_0, H264_AAC_1, H264_AAC_INIT, SPLIT_AUDIO_0, SPLIT_AUDIO_INIT, SPLIT_VIDEO_0,
    SPLIT_VIDEO_INIT,
};
use crate::ts::test_data::{H264_AAC, H265_V1};

/// How far the fake clock moves per real millisecond while a test waits.
const STEP: Duration = Duration::from_millis(50);

const M3U8: &str = "application/vnd.apple.mpegurl";
const MP2T: &str = "video/mp2t";
const MP4: &str = "video/mp4";

/// A log writer that keeps every line.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// The lines logged so far that contain `needle`.
    fn lines(&self, needle: &str) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_owned)
            .collect()
    }

    /// Captures this thread's log lines, `debug` and up, which the
    /// current-thread runtime's tasks log on too.
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }
}

/// A fake server, the clock the source runs on, and the log.
struct Rig {
    server: FakeHttp,
    clock: Arc<FakeClock>,
    logs: Captured,
    _logging: tracing::subscriber::DefaultGuard,
}

impl Rig {
    async fn new() -> Self {
        Self::on(FakeHttp::start().await.unwrap())
    }

    fn on(server: FakeHttp) -> Self {
        let logs = Captured::default();
        Self {
            server,
            clock: Arc::new(FakeClock::from_system()),
            _logging: logs.install(),
            logs,
        }
    }

    fn source(&self, target: &str, options: HttpOptions, tls: Option<TlsTarget>) -> HttpSource {
        HttpSource::new(
            SourceUrl::parse(&self.server.url(target)).unwrap(),
            options,
            tls,
        )
    }

    fn run(&self, source: &HttpSource) -> Harness {
        let clock: Arc<dyn Clock> = Arc::<FakeClock>::clone(&self.clock);
        let peer = ResolvedPeer {
            host: "127.0.0.1".into(),
            addrs: vec![self.server.addr()],
        };
        Harness::start(source, peer, clock)
    }

    fn start(&self, target: &str) -> Harness {
        self.run(&self.source(target, options(), None))
    }

    fn body(&self, target: &str, content_type: &str, body: impl Into<Bytes>) {
        self.server.set(target, Reply::body(content_type, body));
    }

    fn playlist(&self, target: &str, text: &str) {
        self.body(target, M3U8, text.to_owned());
    }

    /// How many requests for `target` the server saw.
    fn seen(&self, target: &str) -> usize {
        self.server
            .requests()
            .iter()
            .filter(|seen| seen.target == target)
            .count()
    }

    fn targets(&self) -> Vec<String> {
        self.server
            .requests()
            .into_iter()
            .map(|seen| seen.target)
            .collect()
    }

    /// Waits in real time, the clock still, until `done` holds.
    async fn wait(&self, what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..3_000 {
            if done() {
                return;
            }
            SystemClock.sleep(Duration::from_millis(1)).await;
        }
        panic!("{what}: not reached");
    }

    /// Moves the clock [`STEP`] per real millisecond until `done` holds.
    async fn advance_until(&self, what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..3_000 {
            if done() {
                return;
            }
            self.clock.advance(STEP);
            SystemClock.sleep(Duration::from_millis(1)).await;
        }
        panic!("{what}: not reached");
    }

    /// Moves the clock [`STEP`] per real millisecond until the source
    /// exits: why.
    async fn exit(&self, harness: Harness) -> SourceError {
        let ticker = async {
            for _ in 0..3_000 {
                SystemClock.sleep(Duration::from_millis(1)).await;
                self.clock.advance(STEP);
            }
        };
        tokio::select! {
            exit = harness.finish() => ended(exit),
            () = ticker => panic!("the source did not exit"),
        }
    }

    async fn stop(self) {
        self.server.stop().await;
    }
}

/// Options with a timeout no test reaches by accident while the clock
/// runs fast.
fn options() -> HttpOptions {
    HttpOptions {
        timeout_ms: 3_600_000,
        ..HttpOptions::default()
    }
}

/// [`Harness::wait_ready`] within three seconds of real time.
trait ReadyWithin {
    async fn wait_ready_within(&mut self) -> bool;
}

impl ReadyWithin for Harness {
    async fn wait_ready_within(&mut self) -> bool {
        tokio::select! {
            ready = self.wait_ready() => ready,
            () = SystemClock.sleep(Duration::from_secs(3)) => panic!("not ready within 3 s"),
        }
    }
}

fn ended(exit: SourceExit) -> SourceError {
    let SourceExit::Ended(err) = exit else {
        panic!("{exit:?}");
    };
    err
}

/// Waits for the exit of a source the clock does not have to move for.
async fn exit_within(harness: Harness, real: Duration) -> SourceError {
    tokio::select! {
        exit = harness.finish() => ended(exit),
        () = SystemClock.sleep(real) => panic!("the source did not exit within {real:?}"),
    }
}

fn media_playlist(header: &str, entries: &[&str], end: bool) -> String {
    let mut text = format!("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n{header}");
    for entry in entries {
        if entry.starts_with('#') {
            text.push_str(entry);
            text.push('\n');
        } else {
            let _infallible = write!(text, "#EXTINF:1.000,\n{entry}\n");
        }
    }
    if end {
        text.push_str("#EXT-X-ENDLIST\n");
    }
    text
}

/// Serves `live_0` to `live_2` under `dir` and an ended playlist of them.
fn serve_vod(rig: &Rig, dir: &str) {
    for (i, body) in [LIVE_0, LIVE_1, LIVE_2].into_iter().enumerate() {
        rig.body(&format!("{dir}/live_{i}.m2t"), MP2T, body);
    }
    rig.playlist(
        &format!("{dir}/index.m3u8"),
        &media_playlist("", &["live_0.m2t", "live_1.m2t", "live_2.m2t"], true),
    );
}

fn tracks(set: &TrackSet) -> (Arc<Track>, Arc<Track>) {
    let tracks = set.tracks();
    assert_eq!(tracks.len(), 2, "{tracks:?}");
    let video = Arc::clone(&tracks[0]);
    let audio = Arc::clone(&tracks[1]);
    assert_eq!(video.id().kind(), Kind::Video);
    assert_eq!(video.codec().family(), CodecFamily::H264);
    assert_eq!(audio.id().kind(), Kind::Audio);
    assert!(
        matches!(*audio.codec(), Codec::AacLc { .. }),
        "{:?}",
        audio.codec()
    );
    (video, audio)
}

fn frames(sub: &mut FrameSubscription) -> Vec<Arc<MediaFrame>> {
    std::iter::from_fn(|| sub.try_recv().unwrap()).collect()
}

fn assert_ended_with(err: &SourceError, needle: &str) {
    assert!(
        matches!(err, SourceError::Ended(message) if message.contains(needle)),
        "{err:?}"
    );
}

fn assert_protocol(err: &SourceError, needle: &str) {
    assert!(
        matches!(err, SourceError::Protocol(message) if message.contains(needle)),
        "{err:?}"
    );
}

#[test]
fn iso13818_1_2_4_3_2_mpegts_is_three_sync_bytes_188_apart() {
    let mut packets = vec![0_u8; 377];
    for offset in [0, 188, 376] {
        packets[offset] = 0x47;
    }
    assert!(is_mpegts(&packets));
    assert!(is_mpegts(H264_AAC));
    for offset in [0, 188, 376] {
        let mut broken = packets.clone();
        broken[offset] = 0;
        assert!(!is_mpegts(&broken), "{offset}");
    }
    assert!(!is_mpegts(&packets[..376]));
    assert!(!is_mpegts(b"#EXTM3U"));
}

/// The queue as (track or barrier, decoding time).
fn queued(queue: &VecDeque<Item>) -> Vec<(char, i64)> {
    queue
        .iter()
        .map(|item| match item {
            Item::Unit(unit) => (if unit.track == 0 { 'v' } else { 'a' }, unit.decode_time),
            Item::Layout(_) => ('l', 0),
            Item::Epoch => ('e', 0),
        })
        .collect()
}

#[test]
fn iso13818_1_2_4_2_6_units_queue_in_decoding_order_within_one_second() {
    let unit = |track, decode_time| {
        Item::Unit(Unit {
            track,
            decode_time,
            ts: decode_time,
            payload: Bytes::new(),
        })
    };
    let mut queue = VecDeque::new();
    for item in [unit(0, 0), unit(0, 9_000), unit(0, 90_000), unit(1, 0)] {
        enqueue(&mut queue, item);
    }
    // The audio frame goes ahead of the video decoded after it, up to a
    // second after it, and behind the one decoded with it.
    assert_eq!(
        queued(&queue),
        [('v', 0), ('a', 0), ('v', 9_000), ('v', 90_000)]
    );
    // A unit more than a second before the last is another timeline.
    enqueue(&mut queue, unit(1, -1));
    assert_eq!(queue.back().map(Item::order), Some(Some(-1)));
    // Nothing moves ahead of a layout or an epoch.
    for barrier in [
        Item::Layout(Layout {
            program_number: 1,
            tracks: Vec::new(),
        }),
        Item::Epoch,
    ] {
        let mut queue = VecDeque::from([unit(0, 9_000)]);
        enqueue(&mut queue, barrier);
        enqueue(&mut queue, unit(1, 0));
        assert_eq!(queued(&queue)[2], ('a', 0));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_source_describes_itself_without_secrets() {
    let url = SourceUrl::parse("https://user:secret@camera.example/live.m3u8").unwrap();
    let source = HttpSource::new(
        url,
        HttpOptions {
            max_bandwidth: Some(1),
            ..HttpOptions::default()
        },
        None,
    );
    let described = source.describe();
    assert_eq!(described.protocol, "http");
    assert!(!described.url.to_string().contains("secret"));
    assert_eq!(described.options["max_bandwidth"], 1);
    assert_eq!(source.connection_options()["max_bandwidth"], 1);
    assert!(matches!(
        source.request_keyframe(),
        lotse_core::source::KeyframeRequest::Unsupported
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_3_4_an_ended_ts_playlist_plays_every_segment_at_its_time_and_ends() {
    let rig = Rig::new().await;
    serve_vod(&rig, "/vod");
    let start = rig.clock.now();
    let harness = rig.start("/vod/index.m3u8");
    let set = Arc::clone(&harness.tracks);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    assert!(err.to_string().contains("media playlist"), "{err}");
    let (video, audio) = tracks(&set);
    assert_eq!(video.stats().frames, 30);
    assert_eq!(video.stats().keyframes, 3);
    assert!(audio.stats().frames >= 140, "{:?}", audio.stats());
    assert_eq!(video.epoch(), 0);
    assert!(rig.logs.lines("layout repeated").is_empty());
    let playing = rig.logs.lines("http: playing");
    assert!(playing[0].contains("tracks=2 streams=1"), "{playing:?}");
    let fetched = rig.logs.lines("segment fetched");
    assert_eq!(fetched.len(), 3, "{fetched:?}");
    assert!(fetched[2].contains("sequence=2"), "{fetched:?}");
    assert!(
        fetched[2].contains(&format!("bytes={}", LIVE_2.len())),
        "{fetched:?}"
    );
    // Paced: the last of 30 frames at 10 per second leaves 2.9 s after
    // the first.
    let took = rig.clock.now().duration_since(start);
    assert!(took >= Duration::from_millis(2_900), "{took:?}");
    assert_eq!(
        rig.targets(),
        [
            "/vod/index.m3u8",
            "/vod/live_0.m2t",
            "/vod/live_1.m2t",
            "/vod/live_2.m2t"
        ]
    );
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_6_3_4_a_live_playlist_is_reloaded_and_its_new_segments_played() {
    let rig = Rig::new().await;
    rig.server.live("/live/index.m3u8", 3);
    rig.server
        .push_segment("/live/index.m3u8", "/live/0.m2t", 1.0, LIVE_0);
    rig.server
        .push_segment("/live/index.m3u8", "/live/1.m2t", 1.0, LIVE_1);
    let mut harness = rig.start("/live/index.m3u8");
    assert!(harness.wait_ready_within().await);
    let (video, _audio) = tracks(&harness.tracks);
    rig.advance_until("the first segment", || video.stats().frames >= 10)
        .await;
    rig.server
        .push_segment("/live/index.m3u8", "/live/2.m2t", 1.0, LIVE_2);
    rig.advance_until("every segment", || video.stats().frames == 30)
        .await;
    rig.server.end_playlist("/live/index.m3u8");
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    assert_eq!(video.epoch(), 0, "one timeline");
    assert!(rig.seen("/live/index.m3u8") >= 3);
    for segment in ["/live/0.m2t", "/live/1.m2t", "/live/2.m2t"] {
        assert_eq!(rig.seen(segment), 1, "{segment}");
    }
    rig.stop().await;
}

/// Waits until the server saw `count` loads of `target`, then moves the
/// clock by `by`.
async fn load_then_advance(rig: &Rig, target: &str, count: usize, by: Duration) {
    rig.wait("the reload", || rig.seen(target) == count).await;
    rig.clock.advance(by);
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_6_2_1_a_live_playlist_without_a_new_segment_for_three_target_durations_times_out()
{
    let rig = Rig::new().await;
    let playlist = "/stall/index.m3u8";
    rig.server.live(playlist, 3);
    rig.server
        .push_segment(playlist, "/stall/0.m2t", 1.0, LIVE_0);
    let harness = rig.start(playlist);
    rig.wait("the segment", || rig.seen("/stall/0.m2t") == 1)
        .await;
    // Loads at 0 s (a new segment: the next after the target duration),
    // then every half of it (RFC 8216 §6.3.4): 1, 1.5, 2, 2.5 and 3 s.
    load_then_advance(&rig, playlist, 1, Duration::from_secs(1)).await;
    for count in 2..=5 {
        load_then_advance(&rig, playlist, count, Duration::from_millis(500)).await;
    }
    let err = exit_within(harness, Duration::from_secs(3)).await;
    assert!(
        matches!(&err, SourceError::Timeout(message) if message.contains("added no segment in 3000 ms, 3 times")),
        "{err:?}"
    );
    assert_eq!(rig.seen(playlist), 6);
    let stalled = rig.logs.lines("stopped adding segments");
    assert!(
        stalled[0].contains("still_ms=3000 target_duration_ms=1000"),
        "{stalled:?}"
    );
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_3_4_an_ended_playlist_is_no_stall() {
    let rig = Rig::new().await;
    let playlist = "/late/index.m3u8";
    rig.server.live(playlist, 3);
    rig.server
        .push_segment(playlist, "/late/0.m2t", 1.0, LIVE_0);
    let harness = rig.start(playlist);
    rig.wait("the segment", || rig.seen("/late/0.m2t") == 1)
        .await;
    load_then_advance(&rig, playlist, 1, Duration::from_secs(1)).await;
    for count in 2..=4 {
        load_then_advance(&rig, playlist, count, Duration::from_millis(500)).await;
    }
    // The load at 3 s finds no new segment, but the end of the playlist.
    rig.wait("the load at 2.5 s", || rig.seen(playlist) == 5)
        .await;
    rig.server.end_playlist(playlist);
    rig.clock.advance(Duration::from_millis(500));
    let err = exit_within(harness, Duration::from_secs(3)).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    assert_eq!(rig.seen(playlist), 6);
    assert!(rig.logs.lines("stopped adding segments").is_empty());
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_6_3_2_segments_the_playlist_dropped_before_their_fetch_start_an_epoch() {
    let rig = Rig::new().await;
    let playlist = "/gap/index.m3u8";
    rig.server.live(playlist, 2);
    rig.server.push_segment(playlist, "/gap/0.m2t", 1.0, LIVE_0);
    rig.server.push_segment(playlist, "/gap/1.m2t", 1.0, LIVE_1);
    let mut harness = rig.start(playlist);
    assert!(harness.wait_ready_within().await);
    rig.wait("both segments", || rig.seen("/gap/1.m2t") == 1)
        .await;
    for (i, body) in [LIVE_2, LIVE_0, LIVE_1, LIVE_2].into_iter().enumerate() {
        rig.server
            .push_segment(playlist, &format!("/gap/{}.m2t", i + 2), 1.0, body);
    }
    rig.advance_until("the segments after the gap", || rig.seen("/gap/5.m2t") == 1)
        .await;
    rig.server.end_playlist(playlist);
    let set = Arc::clone(&harness.tracks);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    let (video, _audio) = tracks(&set);
    assert_eq!(video.epoch(), 1, "the gap starts one epoch");
    assert_eq!(rig.seen("/gap/2.m2t"), 0);
    assert_eq!(rig.seen("/gap/3.m2t"), 0);
    assert_eq!(rig.seen("/gap/4.m2t"), 1);
    assert_eq!(video.stats().frames, 40);
    let gap = rig.logs.lines("they are lost");
    assert!(gap[0].contains("lost=2"), "{gap:?}");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_6_3_2_a_playlist_whose_media_sequence_went_back_restarts_in_an_epoch() {
    let rig = Rig::new().await;
    let playlist = "/restart/index.m3u8";
    rig.body("/restart/a.m2t", MP2T, LIVE_0);
    rig.body("/restart/b.m2t", MP2T, LIVE_1);
    rig.body("/restart/c.m2t", MP2T, H264_AAC);
    rig.playlist(
        playlist,
        &media_playlist("#EXT-X-MEDIA-SEQUENCE:10\n", &["a.m2t", "b.m2t"], false),
    );
    let harness = rig.start(playlist);
    rig.wait("both segments", || rig.seen("/restart/b.m2t") == 1)
        .await;
    rig.playlist(
        playlist,
        &media_playlist("#EXT-X-MEDIA-SEQUENCE:0\n", &["c.m2t"], true),
    );
    let set = Arc::clone(&harness.tracks);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    let (video, _audio) = tracks(&set);
    assert_eq!(video.epoch(), 1, "the restart starts one epoch");
    assert_eq!(rig.logs.lines("the playlist restarted").len(), 1);
    assert_eq!(video.stats().frames, 30);
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_2_3_a_discontinuity_starts_an_epoch_with_a_fresh_demultiplexer() {
    let rig = Rig::new().await;
    serve_vod(&rig, "/d");
    rig.body("/d/other.m2t", MP2T, H264_AAC);
    rig.playlist(
        "/d/index.m3u8",
        &media_playlist(
            "",
            &[
                "live_0.m2t",
                "live_1.m2t",
                "#EXT-X-DISCONTINUITY",
                "other.m2t",
            ],
            true,
        ),
    );
    let harness = rig.start("/d/index.m3u8");
    let set = Arc::clone(&harness.tracks);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    let (video, _audio) = tracks(&set);
    assert_eq!(video.epoch(), 1);
    assert_eq!(video.stats().frames, 30);
    assert_eq!(video.stats().keyframes, 3, "the fresh reader starts clean");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_program_whose_tracks_change_ends_the_attempt() {
    let rig = Rig::new().await;
    serve_vod(&rig, "/c");
    rig.body("/c/h265.m2t", MP2T, H265_V1);
    rig.playlist(
        "/c/index.m3u8",
        &media_playlist(
            "",
            &["live_0.m2t", "#EXT-X-DISCONTINUITY", "h265.m2t"],
            true,
        ),
    );
    let harness = rig.start("/c/index.m3u8");
    let set = Arc::clone(&harness.tracks);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "the program's tracks changed from video h264");
    let (video, _audio) = tracks(&set);
    assert_eq!(video.stats().frames, 10);
    rig.stop().await;
}

fn serve_fmp4(rig: &Rig) {
    rig.body("/f/init.mp4", MP4, H264_AAC_INIT);
    rig.body("/f/same.mp4", MP4, H264_AAC_INIT);
    rig.body("/f/0.m4s", MP4, H264_AAC_0);
    rig.body("/f/1.m4s", MP4, H264_AAC_1);
    rig.body("/f/video.mp4", MP4, SPLIT_VIDEO_INIT);
    rig.body("/f/video.m4s", MP4, SPLIT_VIDEO_0);
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_3_3_fragmented_mp4_is_read_against_its_init_segment_fetched_once() {
    let rig = Rig::new().await;
    serve_fmp4(&rig);
    rig.playlist(
        "/f/index.m3u8",
        &media_playlist("#EXT-X-MAP:URI=\"init.mp4\"\n", &["0.m4s", "1.m4s"], true),
    );
    let harness = rig.start("/f/index.m3u8");
    let set = Arc::clone(&harness.tracks);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    let (video, audio) = tracks(&set);
    assert!(
        matches!(&*video.codec(), Codec::H264 { sps: Some(_), .. }),
        "the avcC sets: {:?}",
        video.codec()
    );
    assert_eq!(video.stats().frames, 20);
    assert_eq!(audio.stats().frames, 95);
    assert_eq!(rig.seen("/f/init.mp4"), 1);
    let fetched = rig.logs.lines("init segment fetched");
    assert_eq!(fetched.len(), 1, "{fetched:?}");
    assert!(fetched[0].contains("bytes=1335"), "{fetched:?}");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_2_5_a_new_map_is_fetched_and_the_same_init_keeps_the_reader() {
    let rig = Rig::new().await;
    serve_fmp4(&rig);
    rig.playlist(
        "/f/index.m3u8",
        &media_playlist(
            "",
            &[
                "#EXT-X-MAP:URI=\"init.mp4\"",
                "0.m4s",
                "#EXT-X-MAP:URI=\"same.mp4\"",
                "1.m4s",
            ],
            true,
        ),
    );
    let harness = rig.start("/f/index.m3u8");
    let set = Arc::clone(&harness.tracks);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    let (video, audio) = tracks(&set);
    assert_eq!(video.stats().frames, 20);
    assert_eq!(audio.stats().frames, 95);
    assert_eq!(video.epoch(), 0);
    assert_eq!((rig.seen("/f/init.mp4"), rig.seen("/f/same.mp4")), (1, 1));
    assert!(rig.logs.lines("layout repeated").is_empty(), "one reader");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_2_5_a_new_init_segment_with_other_tracks_ends_the_attempt() {
    let rig = Rig::new().await;
    serve_fmp4(&rig);
    rig.playlist(
        "/f/index.m3u8",
        &media_playlist(
            "",
            &[
                "#EXT-X-MAP:URI=\"init.mp4\"",
                "0.m4s",
                "#EXT-X-MAP:URI=\"video.mp4\"",
                "video.m4s",
            ],
            true,
        ),
    );
    let harness = rig.start("/f/index.m3u8");
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "the program's tracks changed");
    assert_eq!(rig.seen("/f/video.mp4"), 1);
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn iso14496_12_an_unreadable_init_or_media_segment_is_a_protocol_error() {
    let rig = Rig::new().await;
    serve_fmp4(&rig);
    rig.body("/f/bad.mp4", MP4, &b"\0\0\0\x08free"[..]);
    rig.body("/f/bad.m4s", MP4, &b"\0\0\0\x10moof\0\0\0\x08mfhd"[..]);
    rig.playlist(
        "/f/bad-init.m3u8",
        &media_playlist("#EXT-X-MAP:URI=\"bad.mp4\"\n", &["0.m4s"], true),
    );
    rig.playlist(
        "/f/bad-segment.m3u8",
        &media_playlist("#EXT-X-MAP:URI=\"init.mp4\"\n", &["bad.m4s"], true),
    );
    let err = rig.exit(rig.start("/f/bad-init.m3u8")).await;
    assert_protocol(&err, "fmp4: the init segment has no movie box");
    let err = rig.exit(rig.start("/f/bad-segment.m3u8")).await;
    assert_protocol(&err, "fmp4: the movie fragment cannot be read");
    rig.stop().await;
}

const MULTIVARIANT: &str = "#EXTM3U
#EXT-X-VERSION:7
#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",NAME=\"audio\",DEFAULT=YES,AUTOSELECT=YES,URI=\"audio.m3u8\"
#EXT-X-STREAM-INF:BANDWIDTH=300000,CODECS=\"avc1.42c00c,mp4a.40.2\",AUDIO=\"aud\"
video.m3u8
";

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_4_1_a_separate_audio_rendition_plays_with_the_variant_on_one_timeline() {
    let rig = Rig::new().await;
    rig.body("/m/video.mp4", MP4, SPLIT_VIDEO_INIT);
    rig.body("/m/video.m4s", MP4, SPLIT_VIDEO_0);
    rig.body("/m/audio.mp4", MP4, SPLIT_AUDIO_INIT);
    rig.body("/m/audio.m4s", MP4, SPLIT_AUDIO_0);
    rig.playlist("/m/index.m3u8", MULTIVARIANT);
    rig.playlist(
        "/m/video.m3u8",
        &media_playlist("#EXT-X-MAP:URI=\"video.mp4\"\n", &["video.m4s"], true),
    );
    rig.playlist(
        "/m/audio.m3u8",
        &media_playlist("#EXT-X-MAP:URI=\"audio.mp4\"\n", &["audio.m4s"], true),
    );
    let mut harness = rig.start("/m/index.m3u8");
    assert!(harness.wait_ready_within().await);
    let (video, audio) = tracks(&harness.tracks);
    let mut video_frames = video.subscribe_frames();
    let mut audio_frames = audio.subscribe_frames();
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    assert_eq!(video.stats().frames, 10);
    assert_eq!(audio.stats().frames, 47);
    // Merged by decoding time: the audio interleaves with the video
    // instead of following it.
    let video_frames = frames(&mut video_frames);
    let audio_frames = frames(&mut audio_frames);
    let last_video = video_frames.iter().map(|f| f.arrival).max().unwrap();
    let first_audio = audio_frames.iter().map(|f| f.arrival).min().unwrap();
    assert!(first_audio < last_video, "{first_audio:?} {last_video:?}");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_4_2_the_variant_is_chosen_by_max_bandwidth() {
    let rig = Rig::new().await;
    serve_vod(&rig, "/low");
    rig.playlist(
        "/v/index.m3u8",
        "#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=100000
/low/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=900000
/high/index.m3u8
",
    );
    for max_bandwidth in [Some(500_000), Some(50_000)] {
        let source = rig.source(
            "/v/index.m3u8",
            HttpOptions {
                max_bandwidth,
                ..options()
            },
            None,
        );
        let err = rig.exit(rig.run(&source)).await;
        assert_ended_with(&err, "the variant playlist ended");
    }
    assert_eq!(rig.seen("/high/index.m3u8"), 0);
    assert_eq!(rig.seen("/low/index.m3u8"), 2);
    let chosen = rig.logs.lines("chose a variant");
    assert_eq!(chosen.len(), 2, "{chosen:?}");
    assert!(
        chosen[0].contains("variants=2 bandwidth=100000"),
        "{chosen:?}"
    );
    assert_eq!(rig.logs.lines("no variant fits max_bandwidth").len(), 1);
    // Uncapped, the highest: here a 404.
    let err = rig.exit(rig.start("/v/index.m3u8")).await;
    assert_protocol(&err, "404");
    assert_eq!(rig.seen("/high/index.m3u8"), 1);
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_4_2_a_variant_that_is_no_media_playlist_or_none_playable_is_refused() {
    let rig = Rig::new().await;
    rig.playlist(
        "/n/index.m3u8",
        "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\n/n/index.m3u8\n",
    );
    rig.playlist(
        "/n/opus.m3u8",
        "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1,CODECS=\"opus\"\n/n/index.m3u8\n",
    );
    let err = rig.exit(rig.start("/n/index.m3u8")).await;
    assert_protocol(&err, "the variant playlist is a multivariant playlist");
    let err = rig.exit(rig.start("/n/opus.m3u8")).await;
    assert_protocol(&err, "none of the 1 variants");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_4_3_2_4_an_unplayable_playlist_is_a_protocol_error() {
    let rig = Rig::new().await;
    rig.playlist(
        "/k/index.m3u8",
        "#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXT-X-KEY:METHOD=AES-128,URI=\"k\",IV=0x00000000000000000000000000000000\n#EXTINF:1,\na.m2t\n",
    );
    let err = rig.exit(rig.start("/k/index.m3u8")).await;
    assert_protocol(&err, "encrypted");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9110_15_5_5_a_missing_segment_ends_the_attempt_without_its_path() {
    let rig = Rig::new().await;
    rig.playlist(
        "/x/index.m3u8",
        &media_playlist("", &["secret-token.m2t"], true),
    );
    let err = rig.exit(rig.start("/x/index.m3u8")).await;
    assert_protocol(&err, "404");
    assert!(!err.to_string().contains("secret-token"), "{err}");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc8216_3_4_a_segment_neither_mpegts_nor_fmp4_is_refused() {
    let rig = Rig::new().await;
    rig.body("/p/0.aac", "audio/aac", vec![0xFF_u8; 400]);
    rig.playlist("/p/index.m3u8", &media_playlist("", &["0.aac"], true));
    let err = rig.exit(rig.start("/p/index.m3u8")).await;
    assert_protocol(&err, "segment 0 of the media playlist is neither MPEG-TS");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9110_15_4_a_redirected_playlist_resolves_its_segments_against_its_final_url() {
    let rig = Rig::new().await;
    serve_vod(&rig, "/hls");
    rig.server.set(
        "/start",
        Reply::Redirect {
            status: 302,
            location: "/hls/index.m3u8".into(),
        },
    );
    let err = rig.exit(rig.start("/start")).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    assert_eq!(
        rig.targets(),
        [
            "/start",
            "/hls/index.m3u8",
            "/hls/live_0.m2t",
            "/hls/live_1.m2t",
            "/hls/live_2.m2t"
        ]
    );
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc2046_5_1_mjpeg_is_refused_by_its_content_type() {
    let rig = Rig::new().await;
    for (i, content_type) in [
        "multipart/x-mixed-replace",
        "Multipart/X-Mixed-Replace; boundary=frame",
    ]
    .into_iter()
    .enumerate()
    {
        let target = format!("/mjpeg/{i}");
        rig.body(&target, content_type, &b"--frame\r\n"[..]);
        let err = rig.exit(rig.start(&target)).await;
        assert_protocol(&err, "MJPEG");
    }
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9110_8_3_anything_else_is_refused_naming_its_content_type_only() {
    let rig = Rig::new().await;
    rig.body("/page?token=secret", "text/html", &b"<html></html>"[..]);
    rig.server
        .set("/plain", Reply::Close(Bytes::from_static(b"hello")));
    rig.body("/short", MP2T, &[0x47_u8; 300][..]);
    let err = rig.exit(rig.start("/page?token=secret")).await;
    assert_protocol(
        &err,
        "nor MPEG-TS (ISO/IEC 13818-1 §2.4.3.2): Content-Type text/html",
    );
    assert!(!err.to_string().contains("secret"), "{err}");
    let err = rig.exit(rig.start("/plain")).await;
    assert_protocol(&err, "no Content-Type");
    let err = rig.exit(rig.start("/short")).await;
    assert_protocol(&err, "Content-Type video/mp2t");
    rig.stop().await;
}

/// `bytes` without the `nth` transport packet of `pid` that does not start
/// a PES packet.
fn drop_packet(bytes: &[u8], pid: u16, nth: usize) -> Vec<u8> {
    let mut seen = 0;
    let mut out = Vec::new();
    for packet in bytes.chunks(188) {
        let this = (u16::from(packet[1] & 0x1F) << 8) | u16::from(packet[2]);
        let start = packet[1] & 0x40 != 0;
        if this == pid && !start {
            seen += 1;
            if seen == nth {
                continue;
            }
        }
        out.extend_from_slice(packet);
    }
    out
}

#[tokio::test(flavor = "current_thread")]
async fn iso13818_1_a_raw_mpegts_body_is_streamed_until_the_server_ends_it() {
    let rig = Rig::new().await;
    let feed = rig.server.stream("/raw.ts");
    let mut harness = rig.start("/raw.ts");
    let body = drop_packet(H264_AAC, 0x100, 20);
    // The first pieces end one byte short of the third packet's sync
    // byte: the sniff reads on.
    for piece in [&body[..100], &body[100..376]] {
        feed.send(Bytes::copy_from_slice(piece)).await.unwrap();
        SystemClock.sleep(Duration::from_millis(20)).await;
    }
    feed.send(Bytes::copy_from_slice(&body[376..]))
        .await
        .unwrap();
    assert!(harness.wait_ready_within().await);
    let (video, _audio) = tracks(&harness.tracks);
    let set = Arc::clone(&harness.tracks);
    drop(feed);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "the server ended the MPEG-TS stream");
    assert!(video.stats().frames >= 8, "{:?}", video.stats());
    assert!(set.ingest().packets_lost >= 1, "{:?}", set.ingest());
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_raw_mpegts_body_without_a_program_is_refused_when_it_ends() {
    let rig = Rig::new().await;
    let mut null = vec![0xFF_u8; 3 * 188];
    for packet in null.chunks_mut(188) {
        packet[..4].copy_from_slice(&[0x47, 0x1F, 0xFF, 0x10]);
    }
    rig.body("/null.ts", MP2T, null);
    let err = rig.exit(rig.start("/null.ts")).await;
    assert_protocol(&err, "the program has no video or audio stream");
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_ends_the_attempt_within_100_ms_whatever_it_waits_for() {
    let rig = Rig::new().await;
    serve_vod(&rig, "/vod");
    rig.server.set("/hang", Reply::Hang);
    rig.server.set("/vod/hang.m2t", Reply::Hang);
    rig.playlist(
        "/vod/starved.m3u8",
        &media_playlist("", &["hang.m2t"], true),
    );
    // Pacing with the clock never moving; the first GET; a segment.
    let mut pacing = rig.start("/vod/index.m3u8");
    assert!(pacing.wait_ready_within().await);
    let first_get = rig.start("/hang");
    let starved = rig.start("/vod/starved.m3u8");
    rig.wait("the requests", || {
        rig.seen("/hang") == 1 && rig.seen("/vod/hang.m2t") == 1
    })
    .await;
    for harness in [pacing, first_get, starved] {
        harness.cancel();
        let err = exit_within(harness, Duration::from_millis(100)).await;
        assert_eq!(err, SourceError::Ended("cancelled".into()));
    }
    rig.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn rfc9110_4_2_2_https_plays_with_a_pinned_certificate_and_refuses_another() {
    let tls = CameraTls::self_signed(&["127.0.0.1"]).unwrap();
    let rig = Rig::on(FakeHttp::start_tls(&tls).await.unwrap());
    serve_vod(&rig, "/s");
    let pinned = TlsTarget::new(
        "127.0.0.1",
        Trust::Pin(Fingerprint::of(tls.certificate_der())),
    )
    .unwrap();
    let source = rig.source("/s/index.m3u8", options(), Some(pinned));
    assert!(source.describe().url.to_string().starts_with("https://"));
    let harness = rig.run(&source);
    let set = Arc::clone(&harness.tracks);
    let err = rig.exit(harness).await;
    assert_ended_with(&err, "EXT-X-ENDLIST");
    let (video, _audio) = tracks(&set);
    assert_eq!(video.stats().frames, 30);
    let other = TlsTarget::new("127.0.0.1", Trust::Pin(Fingerprint::of(b"other"))).unwrap();
    let source = rig.source("/s/index.m3u8", options(), Some(other));
    let err = rig.exit(rig.run(&source)).await;
    assert!(matches!(err, SourceError::AuthFailed(_)), "{err:?}");
    rig.stop().await;
}
