//! Fakes for core's own contracts, behind the `test-util` feature: a source
//! factory and source, an output factory, a session output whose engine
//! echoes, a transcoder and a clip container that do nothing but honor the
//! contracts, and the tests' `let_assert!`. `lotse-testing` cannot hold them because it
//! depends on this crate.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::clip::{ClipError, ClipMuxer, ClipMuxerFactory, ClipPolicy, ClipTrack};
use crate::clock::Clock;
use crate::codec::{Codec, CodecFamily, Kind};
use crate::media::{MediaFrame, MediaPacket, MediaTime};
use crate::orientation::Orientation;
use crate::output::{OutputFactory, TalkbackRequest, TrackRequest};
use crate::session::{
    RenegotiateError, SessionEngine, SessionEvent, SessionOpenError, SessionOutput, SessionRequest,
    SessionStats, TalkbackClaim, TalkbackTarget, Transport,
};
use crate::source::{
    BackchannelOffer, BackchannelOpener, BackchannelRefused, BackchannelSession, BackchannelSlot,
    ProbeMark, Source, SourceCapabilities, SourceConfigError, SourceCtx, SourceDescriptor,
    SourceError, SourceFactory,
};
use crate::source_url::SourceUrl;
use crate::task::BoxFuture;
use crate::track::{FrameSubscription, GopSnapshot, Track, Unit};
use crate::transcode::{TrackHandle, TranscodeError, Transcoder};
use crate::uplink::{UplinkCodec, UplinkPacket};

/// `let $pattern = $value else { panic!(..) };` for tests, the one such
/// macro of the workspace: binds the pattern's names, or fails the test
/// with the value that did not match (and the message, if one follows).
/// A test's `let`-`else` leaves its `panic!` on a line of its own that a
/// passing test never runs; here the failure arm sits on the macro call's
/// lines, which the binding runs, so the line-coverage gate sees them as
/// executed. Written `let_assert!(pattern = value)`, in the order of the
/// `let` it stands for; rustfmt lays the call out as the assignment it
/// parses as, or keeps it as written when the pattern is no expression
/// (`mut`, `ref`), and the failure arm stays on the call either way.
#[macro_export]
macro_rules! let_assert {
    ($pattern:pat = $value:expr) => {
        let value = $value;
        let $pattern = value else {
            panic!("`{}` does not match {value:?}", stringify!($pattern));
        };
    };
    ($pattern:pat = $value:expr, $($message:tt)+) => {
        let value = $value;
        let $pattern = value else {
            panic!("`{}` does not match {value:?}: {}", stringify!($pattern), format_args!($($message)+));
        };
    };
}

/// A source factory for the given schemes. Options must be `null`, an
/// empty object, `{"crash": true}` for the crash-injection test,
/// `{"ready_after_ms": n}` to go live only after `n` ms on the injected
/// clock (a cancel meanwhile ends the run at once, as the ingest contract
/// asks), `{"audio": true}` to carry a PCMU track too,
/// `{"audio": "aac"}` to carry an AAC-LC track (side branch only), or
/// `{"audio": "aac_drifting"}` for that and Sender Reports whose audio
/// clock runs 2 % fast, so the skew watchdog withdraws its audio,
/// `{"audio": "aac_steady"}` for that and Sender Reports whose clocks
/// agree, so the tracks stay mapped from them, or
/// `{"backchannel": "pcmu" | "pcma" | "opus"}` to offer a backchannel
/// taking that codec in 20 ms frames once it runs, each claim opening a
/// session of it at once (whose packets go into the factory's
/// [`BackchannelCapture`], if it has one, else nowhere),
/// `{"video": true}` to publish 30 fps H.264 on the video track
/// (`video_packet`), or both of the last two together, the doorbell a
/// talk-back test watches while it talks; anything else is rejected, so
/// tests can see the validation error path. Beside any of these,
/// `{"talk": true}` has the source ask for the device's backchannel
/// ([`Source::wants_backchannel`]), left out of its connection options as
/// RTSP's `backchannel` is.
#[derive(Debug)]
pub struct FakeSourceFactory {
    /// The schemes it claims.
    schemes: &'static [&'static str],
    /// What a crashing source calls once ready: aborts the process.
    abort: fn() -> !,
    /// The protocol can carry audio back (`SourceCapabilities::backchannel`).
    backchannel: bool,
    /// Where its sources' backchannels put what they receive.
    capture: Option<BackchannelCapture>,
}

impl FakeSourceFactory {
    /// A factory claiming `schemes`, whose protocol has no backchannel and
    /// whose crashing sources abort the process: `abort`, not `panic`,
    /// because the test profile ignores `panic = "abort"`, and the point is
    /// the process dying, not the unwinding.
    pub const fn new(schemes: &'static [&'static str]) -> Self {
        Self {
            schemes,
            abort: std::process::abort,
            backchannel: false,
            capture: None,
        }
    }

    /// A factory claiming `schemes` whose protocol declares a backchannel,
    /// as the RTSP source will once it can send.
    pub const fn with_backchannel(schemes: &'static [&'static str]) -> Self {
        Self {
            schemes,
            abort: std::process::abort,
            backchannel: true,
            capture: None,
        }
    }

    /// This factory with its crashing sources calling `abort` instead of
    /// aborting the process: the seam the crash path's own test needs, as
    /// an aborted process cannot report on it (its coverage included).
    #[must_use]
    pub fn aborting_with(self, abort: fn() -> !) -> Self {
        Self { abort, ..self }
    }

    /// [`FakeSourceFactory::with_backchannel`], whose sources' backchannels
    /// put every packet they receive into `capture`: the camera's end of
    /// talk-back, for tests that follow it there.
    pub const fn capturing(schemes: &'static [&'static str], capture: BackchannelCapture) -> Self {
        Self {
            schemes,
            abort: std::process::abort,
            backchannel: true,
            capture: Some(capture),
        }
    }
}

/// What the backchannels of a capturing [`FakeSourceFactory`] received, in
/// order, across runs and sessions: the packets as the worker sent them
/// to the device, each with when it arrived, and how many backchannel
/// sessions were opened and closed.
#[derive(Debug, Clone)]
pub struct BackchannelCapture {
    /// The packets; a waiter sees each one arrive.
    packets: Arc<tokio::sync::watch::Sender<Vec<Captured>>>,
    /// The sessions opened and closed so far.
    sessions: Arc<tokio::sync::watch::Sender<FakeSessions>>,
}

/// How many backchannel sessions a [`BackchannelCapture`]'s fake device
/// opened and closed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FakeSessions {
    /// Opened for a claim.
    pub opened: u64,
    /// Closed by their holder.
    pub closed: u64,
}

/// One packet a [`BackchannelCapture`] took.
#[derive(Debug, Clone)]
pub struct Captured {
    /// When the fake camera took it off its backchannel, on the source's
    /// injected clock: where a talk-back latency ends.
    pub at: Instant,
    /// The packet as the worker sent it.
    pub packet: MediaPacket,
}

impl Default for BackchannelCapture {
    fn default() -> Self {
        Self {
            packets: Arc::new(tokio::sync::watch::Sender::new(Vec::new())),
            sessions: Arc::new(tokio::sync::watch::Sender::new(FakeSessions::default())),
        }
    }
}

impl BackchannelCapture {
    /// Every packet received so far.
    pub fn packets(&self) -> Vec<MediaPacket> {
        Self::bare(&self.captured())
    }

    /// Every packet received so far, with when each arrived.
    pub fn captured(&self) -> Vec<Captured> {
        self.packets.borrow().clone()
    }

    /// Waits until at least `count` packets arrived, and returns them all.
    pub async fn wait_for(&self, count: usize) -> Vec<MediaPacket> {
        let mut packets = self.packets.subscribe();
        packets
            .wait_for(|packets| packets.len() >= count)
            .await
            .map(|packets| Self::bare(&packets))
            .unwrap_or_default()
    }

    /// The packets of `captured`, without their arrival.
    fn bare(captured: &[Captured]) -> Vec<MediaPacket> {
        captured
            .iter()
            .map(|captured| captured.packet.clone())
            .collect()
    }

    /// Records one packet that arrived `at`.
    fn push(&self, at: Instant, packet: MediaPacket) {
        self.packets
            .send_modify(|packets| packets.push(Captured { at, packet }));
    }

    /// The sessions opened and closed so far.
    pub fn sessions(&self) -> FakeSessions {
        *self.sessions.borrow()
    }

    /// Waits until the sessions opened and closed are `want`.
    pub async fn wait_sessions(&self, want: FakeSessions) {
        let mut sessions = self.sessions.subscribe();
        // The capture holds the sender, so the wait never fails.
        let _reached = sessions.wait_for(|sessions| *sessions == want).await;
    }
}

/// The fake device's backchannel: every claim opens a session at once,
/// taking `codec` in 20 ms frames, whose packets go into `capture` if
/// there is one, stamped on `time`.
#[derive(Debug)]
struct FakeOpener {
    /// The codec it takes.
    codec: Codec,
    /// Where its packets go.
    capture: Option<BackchannelCapture>,
    /// The clock that stamps them.
    time: Arc<dyn Clock>,
}

impl BackchannelOpener for FakeOpener {
    fn open(&self) -> BoxFuture<'static, Result<BackchannelSession, BackchannelRefused>> {
        let (sender, uplink) = tokio::sync::mpsc::channel(8);
        let (on_loss, lost) = tokio::sync::oneshot::channel();
        let close = tokio_util::sync::CancellationToken::new();
        let session = BackchannelSession::new(
            self.codec.clone(),
            BackchannelOffer::DEFAULT_FRAME,
            sender,
            lost,
            close.clone(),
        );
        if let Some(capture) = &self.capture {
            capture.sessions.send_modify(|sessions| {
                sessions.opened = sessions.opened.saturating_add(1);
            });
        }
        let drain = drain(
            uplink,
            self.capture.clone(),
            Arc::clone(&self.time),
            (close, on_loss),
        );
        let _drain = crate::task::spawn_named("fake_source.backchannel", drain);
        Box::pin(std::future::ready(Ok(session)))
    }
}

/// One fake backchannel session until its holder closes it: what arrives
/// on `uplink` goes into `capture` if there is one, stamped on `time`.
/// Its loss is never reported, so the sender is kept until the close.
async fn drain(
    mut uplink: tokio::sync::mpsc::Receiver<MediaPacket>,
    capture: Option<BackchannelCapture>,
    time: Arc<dyn Clock>,
    (close, _on_loss): (
        tokio_util::sync::CancellationToken,
        tokio::sync::oneshot::Sender<BackchannelRefused>,
    ),
) {
    loop {
        tokio::select! {
            Some(packet) = uplink.recv() => {
                if let Some(capture) = &capture {
                    capture.push(time.now(), packet);
                }
            }
            () = close.cancelled() => break,
        }
    }
    if let Some(capture) = &capture {
        capture.sessions.send_modify(|sessions| {
            sessions.closed = sessions.closed.saturating_add(1);
        });
    }
}

/// The `backchannel` and `video` options of a fake source, when `options`
/// holds one or both of them and nothing else, each valid: the codec of
/// the backchannel to offer, if any, and whether to publish video.
fn doorbell(options: &serde_json::Value) -> Option<(Option<Codec>, bool)> {
    let serde_json::Value::Object(map) = options else {
        return None;
    };
    let backchannel = match map.get("backchannel") {
        Some(name) => Some(fake_backchannel(name.as_str()?)?),
        None => None,
    };
    let video = match map.get("video") {
        Some(video) => video.as_bool().filter(|video| *video)?,
        None => false,
    };
    let known = usize::from(backchannel.is_some()).saturating_add(usize::from(video));
    (known != 0 && known == map.len()).then_some((backchannel, video))
}

/// The backchannel codec a fake source's `backchannel` option names.
fn fake_backchannel(name: &str) -> Option<Codec> {
    match name {
        "pcmu" => Some(Codec::Pcmu),
        "pcma" => Some(Codec::Pcma),
        "opus" => Some(Codec::Opus { channels: 2 }),
        _ => None,
    }
}

impl SourceFactory for FakeSourceFactory {
    fn schemes(&self) -> &'static [&'static str] {
        self.schemes
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            backchannel: self.backchannel,
        }
    }

    fn validate(
        &self,
        url: &SourceUrl,
        options: &serde_json::Value,
    ) -> Result<Box<dyn Source>, SourceConfigError> {
        let scheme = self.schemes.first().copied().unwrap_or("fake");
        let Some((talk, options)) = take_talk(options) else {
            return Err(SourceConfigError::InvalidOptions {
                scheme,
                message: "fake source's talk must be true or false".to_owned(),
            });
        };
        let options = &options;
        let one = |key: &str| match options {
            serde_json::Value::Object(map) if map.len() == 1 => map.get(key),
            _ => None,
        };
        let audio_name = one("audio").and_then(serde_json::Value::as_str);
        let keyframes_every = one("keyframes_every_ms")
            .and_then(serde_json::Value::as_u64)
            .map(Duration::from_millis);
        let doorbell = doorbell(options);
        let (crash, ready_after, audio) = match options {
            serde_json::Value::Null => (false, Duration::ZERO, FakeAudio::None),
            serde_json::Value::Object(map) if map.is_empty() => {
                (false, Duration::ZERO, FakeAudio::None)
            }
            _ if keyframes_every.is_some() => (false, Duration::ZERO, FakeAudio::None),
            _ if one("crash").and_then(serde_json::Value::as_bool) == Some(true) => {
                (true, Duration::ZERO, FakeAudio::None)
            }
            _ if let Some(ms) = one("ready_after_ms").and_then(serde_json::Value::as_u64) => {
                (false, Duration::from_millis(ms), FakeAudio::None)
            }
            _ if one("audio").and_then(serde_json::Value::as_bool) == Some(true) => {
                (false, Duration::ZERO, FakeAudio::Pcmu)
            }
            _ if audio_name == Some("aac") => (false, Duration::ZERO, FakeAudio::Aac),
            _ if audio_name == Some("aac_drifting") => {
                (false, Duration::ZERO, FakeAudio::AacDrifting)
            }
            _ if audio_name == Some("aac_steady") => (false, Duration::ZERO, FakeAudio::AacSteady),
            _ if doorbell.is_some() => (false, Duration::ZERO, FakeAudio::None),
            other => {
                return Err(SourceConfigError::InvalidOptions {
                    scheme,
                    message: format!(
                        "fake source takes no options but {{\"crash\": true}}, {{\"ready_after_ms\": n}}, {{\"keyframes_every_ms\": n}}, {{\"audio\": true | \"aac\" | \"aac_drifting\" | \"aac_steady\"}}, {{\"backchannel\": \"pcmu\" | \"pcma\" | \"opus\"}} and {{\"video\": true}}, got {other}"
                    ),
                });
            }
        };
        let (backchannel, video) = doorbell.unwrap_or((None, false));
        Ok(Box::new(FakeSource {
            protocol: scheme,
            url: url.clone(),
            crash,
            abort: self.abort,
            ready_after,
            audio,
            keyframes_every,
            video,
            backchannel,
            capture: self.capture.clone(),
            talk,
        }))
    }
}

/// A fake source's `talk` option taken out of `options`: whether it asks
/// for the backchannel (absent: no), and the options without it; `None`
/// when it is not a bool.
fn take_talk(options: &serde_json::Value) -> Option<(bool, serde_json::Value)> {
    let serde_json::Value::Object(map) = options else {
        return Some((false, options.clone()));
    };
    let mut rest = map.clone();
    let talk = match rest.remove("talk") {
        Some(talk) => talk.as_bool()?,
        None => false,
    };
    Some((talk, serde_json::Value::Object(rest)))
}

/// The audio track a [`FakeSource`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeAudio {
    /// None.
    None,
    /// PCMU, a 20 ms packet every 20 ms on the live path.
    Pcmu,
    /// AAC-LC 16 kHz mono ([`FAKE_AAC_CONFIG`]), a 1024-sample frame every
    /// 64 ms on the side branch, as the RTSP source frames it.
    Aac,
    /// [`FakeAudio::Aac`], and every second the Sender Reports of
    /// [`sender_reports`], audio's running 2 % fast.
    AacDrifting,
    /// [`FakeAudio::Aac`], and every second the Sender Reports of
    /// [`sender_reports`], whose clocks agree.
    AacSteady,
}

impl FakeAudio {
    /// The name in the connection options.
    const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pcmu => "pcmu",
            Self::Aac => "aac",
            Self::AacDrifting => "aac_drifting",
            Self::AacSteady => "aac_steady",
        }
    }

    /// Whether the camera sends Sender Reports, every [`REPORT_INTERVAL`].
    const fn reports(self) -> bool {
        matches!(self, Self::AacDrifting | Self::AacSteady)
    }
}

/// How often a fake camera with Sender Reports sends them.
const REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// Reports the Sender Reports (RFC 3550 §6.4.1) a camera sends `elapsed`
/// after going live: video's claims the time that passed, and so does
/// audio's, unless `audio_kind` is [`FakeAudio::AacDrifting`], whose
/// clock runs 2 % fast against its NTP clock, when audio's claims 2 %
/// more. That mapping keeps falling behind beyond what a slew can follow,
/// which the skew watchdog cannot hold.
fn sender_reports(
    clock: &crate::source::ClockInput,
    video: &Track,
    audio: &Track,
    elapsed: Duration,
    arrival: Instant,
    audio_kind: FakeAudio,
) {
    let report = |track: &Track, claimed: Duration| crate::source::ClockReport {
        track: track.id(),
        clock_rate: track.clock_rate(),
        hint: crate::source::SyncHint::RtcpSenderReport {
            ntp: ntp_timestamp(claimed),
            rtp_ts: rtp_timestamp(elapsed, track.clock_rate()),
        },
        arrival,
    };
    let drift = if audio_kind == FakeAudio::AacDrifting {
        elapsed.checked_div(50).unwrap_or_default()
    } else {
        Duration::ZERO
    };
    let _video_sent = clock.report(report(video, elapsed));
    let _audio_sent = clock.report(report(audio, elapsed.saturating_add(drift)));
}

/// `since` the NTP era's start as a 32.32 fixed-point NTP timestamp
/// (RFC 3550 §4).
fn ntp_timestamp(since: Duration) -> u64 {
    let fraction = u64::from(since.subsec_nanos())
        .checked_shl(32)
        .and_then(|shifted| shifted.checked_div(1_000_000_000))
        .unwrap_or(0);
    since.as_secs().wrapping_shl(32) | fraction
}

/// `since` the timeline's start in ticks of `clock_rate`, wrapped to 32
/// bits (RFC 3550 §5.1).
fn rtp_timestamp(since: Duration, clock_rate: u32) -> u32 {
    let ticks = since
        .as_nanos()
        .saturating_mul(u128::from(clock_rate))
        .checked_div(1_000_000_000)
        .unwrap_or(0);
    u32::try_from(ticks & u128::from(u32::MAX)).unwrap_or(0)
}

/// The `AudioSpecificConfig` of the fake source's AAC-LC track: 16 kHz
/// mono (ISO/IEC 14496-3 §1.6.2.1).
pub const FAKE_AAC_CONFIG: [u8; 2] = [0x14, 0x08];

/// The codec of the fake source's AAC-LC track: 16 kHz mono with
/// [`FAKE_AAC_CONFIG`].
pub fn fake_aac() -> Codec {
    Codec::AacLc {
        sample_rate: 16_000,
        channels: 1,
        config: bytes::Bytes::from_static(&FAKE_AAC_CONFIG),
    }
}

/// A source that declares one H.264 video track, reports ready, and waits
/// for cancellation; or, with `crash`, aborts its process right after
/// reporting ready, as a camera-triggered memory-safety failure would.
/// With audio it also declares a PCMU track and publishes a 20 ms packet
/// of it every 20 ms on the injected clock, or an AAC-LC track and
/// publishes a frame of it every 64 ms, stamped with its capture time on
/// the 64 ms grid from the moment it went live; drifting or steady, it
/// also sends Sender Reports every second from a second after it went
/// live, whose audio clock runs 2 % fast when drifting. With a
/// backchannel it marks the slot probed before its tracks are ready, then
/// probes beside its run, as the RTSP source does: under a permit of the
/// slot's gate, which it asks for only once its tracks are ready, so a
/// probe never waits for the permit its own attempt holds until it is
/// live. It offers the backchannel in the slot once granted (20 ms
/// frames), whose sessions take what arrives on them into its capture, if
/// any, stamped with its arrival on the injected clock; the offer stands
/// when its run ends. With video it publishes a `video_packet` every
/// [`VIDEO_FRAME`] on the injected clock while it runs.
#[derive(Debug)]
pub struct FakeSource {
    /// The protocol name it reports.
    protocol: &'static str,
    /// Its URL.
    url: SourceUrl,
    /// Abort the process once ready.
    crash: bool,
    /// How it aborts: [`FakeSourceFactory::aborting_with`].
    abort: fn() -> !,
    /// How long it takes to go live.
    ready_after: Duration,
    /// The audio track it carries.
    audio: FakeAudio,
    /// Publish a video keyframe packet this often, without audio.
    keyframes_every: Option<Duration>,
    /// Whether it publishes video.
    video: bool,
    /// The codec of the backchannel it offers, if any.
    backchannel: Option<Codec>,
    /// Where its backchannel puts what it receives.
    capture: Option<BackchannelCapture>,
    /// Whether it asks for the device's backchannel (`talk`).
    talk: bool,
}

impl Source for FakeSource {
    fn describe(&self) -> SourceDescriptor {
        SourceDescriptor {
            protocol: self.protocol,
            url: self.url.clone(),
            options: serde_json::Value::Null,
        }
    }

    fn connection_options(&self) -> serde_json::Value {
        serde_json::json!({
            "crash": self.crash,
            "ready_after_ms": u64::try_from(self.ready_after.as_millis()).unwrap_or(u64::MAX),
            "audio": self.audio.name(),
            "keyframes_every_ms": self.keyframes_every.map(|every| u64::try_from(every.as_millis()).unwrap_or(u64::MAX)),
            "backchannel": self.backchannel.as_ref().map(Codec::name),
            "video": self.video,
        })
    }

    fn wants_backchannel(&self) -> bool {
        self.talk
    }

    fn run(&self, mut ctx: SourceCtx) -> BoxFuture<'static, SourceError> {
        let crash = self.crash;
        let abort = self.abort;
        let audio = self.audio;
        let keyframes_every = self.keyframes_every;
        let publishes_video = self.video;
        let backchannel = self.backchannel.clone().map(|codec| BackchannelOffer {
            codec: codec.clone(),
            frame: BackchannelOffer::DEFAULT_FRAME,
            opener: Arc::new(FakeOpener {
                codec,
                capture: self.capture.clone(),
                time: Arc::clone(&ctx.time),
            }),
        });
        let ready_after = ctx.time.sleep(self.ready_after);
        let live = async move {
            // The ingest contract holds while waiting to go live too: a
            // cancel ends the run at once, whether or not the clock moves.
            tokio::select! {
                () = ready_after => {}
                () = ctx.cancel.cancelled() => {
                    return SourceError::Ended("cancelled before live".into());
                }
            }
            let video: Arc<Track> = ctx.tracks.declare(
                Kind::Video,
                Codec::H264 {
                    profile_level_id: None,
                    sps: None,
                    pps: None,
                },
                90_000,
            );
            // Marked before the tracks are ready, so a claim that comes
            // with the first session waits for the probe.
            let probe = backchannel.map(|offer| {
                let mark = ctx.backchannel.probing();
                fake_probe(ctx.backchannel.clone(), mark, offer, ctx.cancel.clone())
            });
            let probe = async move {
                if let Some(probe) = probe {
                    probe.await;
                }
            };
            let run = async move {
                let (codec, clock_rate, step) = match audio {
                    FakeAudio::None => {
                        ctx.tracks.ready();
                        if crash {
                            tracing::error!("fake source: crashing the process as requested");
                            abort();
                        }
                        if publishes_video {
                            return fake_video(&video, &*ctx.time, &ctx.cancel).await;
                        }
                        return video_only(&ctx, &video, keyframes_every).await;
                    }
                    FakeAudio::Pcmu => (Codec::Pcmu, 8_000, Duration::from_millis(20)),
                    FakeAudio::Aac | FakeAudio::AacDrifting | FakeAudio::AacSteady => {
                        (fake_aac(), 16_000, Duration::from_millis(64))
                    }
                };
                let track = ctx.tracks.declare(Kind::Audio, codec, clock_rate);
                ctx.tracks.ready();
                let start = ctx.time.now();
                let (mut index, mut seq) = (0_u32, 0_u16);
                // A camera's first report follows its first packets (RFC 3550
                // §6.2), so the tracks are announced before it maps them.
                let mut next_report = REPORT_INTERVAL;
                loop {
                    let now = ctx.time.now();
                    let elapsed = now.saturating_duration_since(start);
                    if audio.reports() && elapsed >= next_report {
                        sender_reports(&ctx.clock, &video, &track, elapsed, now, audio);
                        next_report = next_report.saturating_add(REPORT_INTERVAL);
                    }
                    if audio == FakeAudio::Pcmu {
                        track.publish_packet(pcmu_packet(ctx.time.now(), seq));
                    } else {
                        // Captured on the frame grid, as a camera with Sender
                        // Reports maps them, however late the task wakes.
                        let wallclock = step
                            .checked_mul(index)
                            .and_then(|since| start.checked_add(since))
                            .unwrap_or(start);
                        track.publish_frame(MediaFrame {
                            ts: MediaTime::from_ticks(i64::from(index).saturating_mul(1024)),
                            wallclock,
                            arrival: now,
                            keyframe: true,
                            discontinuity: false,
                            epoch: 0,
                            // One `ID_END`: a silent AAC frame.
                            payload: bytes::Bytes::from_static(&[0xe0]),
                        });
                    }
                    index = index.wrapping_add(1);
                    seq = seq.wrapping_add(1);
                    tokio::select! {
                        () = ctx.time.sleep(step) => {}
                        () = ctx.cancel.cancelled() => {
                            return SourceError::Ended("cancelled".into());
                        }
                    }
                }
            };
            // The run goes first: its tracks are ready before the probe
            // asks for its permit.
            tokio::join!(biased; run, probe).0
        };
        // The offer stands after the run, as a probe's does across a
        // reconnect.
        Box::pin(live)
    }
}

/// A fake source's probe of its backchannel, which `slot` is marked for
/// with `mark`: under a connect permit of the slot's gate, as a
/// protocol's source probes the device, it offers `offer`; a cancel while
/// it waits for the permit abandons it, and the offer stays as it was.
async fn fake_probe(
    slot: BackchannelSlot,
    mark: ProbeMark,
    offer: BackchannelOffer,
    cancel: tokio_util::sync::CancellationToken,
) {
    let permit = tokio::select! {
        permit = slot.probes().permit() => permit,
        () = cancel.cancelled() => {
            slot.abandon_probe(mark);
            return;
        }
    };
    slot.settle(mark, Some(offer));
    drop(permit);
}

/// The run of a fake source without audio once it is live: until
/// cancelled, publishing a one-packet keyframe on `video` every `every`
/// if set, and the same keyframe as a frame on the side branch, a video
/// source a standby can switch in at and a clip can record.
async fn video_only(ctx: &SourceCtx, video: &Track, every: Option<Duration>) -> SourceError {
    let Some(every) = every else {
        ctx.cancel.cancelled().await;
        return SourceError::Ended("cancelled".into());
    };
    let mut seq = 0_u16;
    loop {
        let now = ctx.time.now();
        video.publish_packet(keyframe_packet(now, seq));
        let _published = video.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(i64::from(seq).saturating_mul(3_000)),
            wallclock: now,
            arrival: now,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: bytes::Bytes::from_static(&FAKE_KEYFRAME),
        });
        seq = seq.wrapping_add(1);
        tokio::select! {
            () = ctx.time.sleep(every) => {}
            () = ctx.cancel.cancelled() => {
                return SourceError::Ended("cancelled".into());
            }
        }
    }
}

/// How often a fake source with video publishes a frame: 30 fps.
pub const VIDEO_FRAME: Duration = Duration::from_micros(33_333);

/// The RTP timestamp step of one [`VIDEO_FRAME`] at 90 kHz (RFC 6184 §8.2.1).
const VIDEO_TS_STEP: u32 = 3_000;

/// How many frames a fake source's GOP holds: a keyframe every second.
const VIDEO_GOP: u32 = 30;

/// Publishes a [`video_packet`] every [`VIDEO_FRAME`] on `time` until
/// `cancel`, on a fixed grid from the first, as a camera's encoder does:
/// a late wake does not delay the frames after it, so the track never
/// takes the stream for one that stalled.
async fn fake_video(
    track: &Track,
    time: &dyn Clock,
    cancel: &tokio_util::sync::CancellationToken,
) -> SourceError {
    let start = time.now();
    let mut index = 0_u32;
    loop {
        track.publish_packet(video_packet(time.now(), index));
        index = index.wrapping_add(1);
        let due = VIDEO_FRAME
            .checked_mul(index)
            .and_then(|since| start.checked_add(since))
            .unwrap_or(start);
        tokio::select! {
            () = time.sleep(due.saturating_duration_since(time.now())) => {}
            () = cancel.cancelled() => {
                return SourceError::Ended("cancelled".into());
            }
        }
    }
}

/// The keyframe a fake source without audio publishes: an IDR slice
/// header and its padding, not decodable.
const FAKE_KEYFRAME: [u8; 32] = [0x65; 32];

/// The fake source's video packet `seq`: a whole keyframe in one packet.
fn keyframe_packet(arrival: Instant, seq: u16) -> MediaPacket {
    MediaPacket {
        arrival,
        rtp: crate::media::RtpHeaderFields {
            pt: 96,
            seq,
            ts: u32::from(seq).wrapping_mul(3_000),
            marker: true,
            ssrc: 3,
        },
        frame_start: true,
        keyframe_start: true,
        epoch: 0,
        lateness: Duration::ZERO,
        payload: Arc::from(&FAKE_KEYFRAME[..]),
    }
}

/// The fake source's video frame `index`, one RTP packet (RFC 6184 §5.6,
/// a single NAL unit) with the marker set: an IDR slice header on every
/// [`VIDEO_GOP`]th frame from the first, a non-IDR one between. The NAL
/// units are not decodable; what reaches a viewer is the timing.
fn video_packet(arrival: Instant, index: u32) -> MediaPacket {
    let keyframe = index.is_multiple_of(VIDEO_GOP);
    let payload: &[u8] = if keyframe {
        &[0x65, 0x88, 0x84, 0x00]
    } else {
        &[0x41, 0x9a, 0x02, 0x00]
    };
    MediaPacket {
        arrival,
        rtp: crate::media::RtpHeaderFields {
            pt: 96,
            // Wraps after 65,536 frames, as RTP's does (RFC 3550 §5.1).
            seq: u16::try_from(index & 0xffff).unwrap_or(0),
            ts: index.wrapping_mul(VIDEO_TS_STEP),
            marker: true,
            ssrc: 1,
        },
        frame_start: true,
        keyframe_start: keyframe,
        epoch: 0,
        lateness: Duration::ZERO,
        payload: Arc::from(payload),
    }
}

/// The fake source's PCMU packet `seq`, 20 ms of silence.
fn pcmu_packet(arrival: Instant, seq: u16) -> MediaPacket {
    MediaPacket {
        arrival,
        rtp: crate::media::RtpHeaderFields {
            pt: 0,
            seq,
            ts: u32::from(seq).wrapping_mul(160),
            marker: false,
            ssrc: 2,
        },
        frame_start: true,
        keyframe_start: false,
        epoch: 0,
        lateness: Duration::ZERO,
        payload: Arc::from(&[0xff_u8; 160][..]),
    }
}

/// An output factory with a fixed kind that wants no tracks and answers
/// no offer: it refuses every one as invalid SDP.
#[derive(Debug)]
pub struct FakeOutputFactory(pub &'static str);

impl OutputFactory for FakeOutputFactory {
    fn kind(&self) -> &'static str {
        self.0
    }

    fn open_session(
        &self,
        _request: SessionRequest,
        _now: Instant,
    ) -> Result<(Box<dyn SessionEngine>, String), SessionOpenError> {
        Err(SessionOpenError::InvalidSdp(format!(
            "the fake {} output answers no offer",
            self.0
        )))
    }
}

/// Where a [`FakeClipMuxerFactory`]'s muxers fail, if anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeClipFailure {
    /// `start` refuses the video's codec.
    Start,
    /// `push` fails on the first frame.
    Push,
    /// `finish` fails.
    Finish,
}

/// A clip container that writes a line a reader can parse instead of a
/// file: `init video=<codec>[ audio=<codec>]` at the start; per frame
/// `frame <v|a> <epoch> <ts> <k|-> <bytes>` followed by the payload
/// itself, as a real muxer hands the frame's own bytes out; `end` at the
/// finish (each line ends with `\n`). It carries H.264, H.265, AAC-LC and
/// Opus whatever their parameters, so a fake source's video without
/// parameter sets records too, and fails where it is told to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FakeClipMuxerFactory {
    /// Where its muxers fail.
    pub fail: Option<FakeClipFailure>,
}

impl ClipMuxerFactory for FakeClipMuxerFactory {
    fn accepts(&self, codec: &Codec) -> bool {
        matches!(
            codec.family(),
            CodecFamily::H264 | CodecFamily::H265 | CodecFamily::AacLc | CodecFamily::Opus
        )
    }

    fn muxer(&self, _policy: &ClipPolicy) -> Box<dyn ClipMuxer> {
        Box::new(FakeClipMuxer {
            fail: self.fail,
            origin: None,
            latest: [None; 2],
        })
    }
}

/// A [`FakeClipMuxerFactory`]'s muxer. Its media time is the capture time
/// from its origin, the one set or its first frame's.
#[derive(Debug)]
struct FakeClipMuxer {
    /// Where it fails.
    fail: Option<FakeClipFailure>,
    /// Media time 0.
    origin: Option<Instant>,
    /// The capture time of the latest video and audio frame taken.
    latest: [Option<Instant>; 2],
}

/// The slot of `track` in [`FakeClipMuxer::latest`].
const fn slot(track: Kind) -> usize {
    match track {
        Kind::Video => 0,
        Kind::Audio => 1,
    }
}

impl ClipMuxer for FakeClipMuxer {
    fn start(
        &mut self,
        video: &ClipTrack,
        audio: Option<&ClipTrack>,
    ) -> Result<Vec<bytes::Bytes>, ClipError> {
        if self.fail == Some(FakeClipFailure::Start) {
            return Err(ClipError::Unsupported(video.codec.family()));
        }
        let audio = audio.map_or(String::new(), |audio| {
            format!(" audio={}", audio.codec.name())
        });
        Ok(vec![
            format!("init video={}{audio}\n", video.codec.name()).into(),
        ])
    }

    /// Writes nothing; its media times count from `origin`, set before
    /// the first frame.
    fn set_origin(&mut self, origin: Instant) {
        self.origin.get_or_insert(origin);
    }

    fn push(
        &mut self,
        track: Kind,
        frame: Arc<MediaFrame>,
    ) -> Result<Vec<bytes::Bytes>, ClipError> {
        if self.fail == Some(FakeClipFailure::Push) {
            return Err(ClipError::Failed("the fake muxer fails every push".into()));
        }
        self.origin.get_or_insert(frame.wallclock);
        if let Some(latest) = self.latest.get_mut(slot(track)) {
            *latest = Some(frame.wallclock);
        }
        let kind = if track == Kind::Video { 'v' } else { 'a' };
        let key = if frame.keyframe { 'k' } else { '-' };
        let line = format!(
            "frame {kind} {} {} {key} {}\n",
            frame.epoch,
            frame.ts.ticks(),
            frame.payload.len()
        );
        Ok(vec![line.into(), frame.payload.clone()])
    }

    fn media_time(&self, track: Kind) -> Duration {
        let latest = self.latest.get(slot(track)).copied().flatten();
        match (latest, self.origin) {
            (Some(latest), Some(origin)) => latest.saturating_duration_since(origin),
            _ => Duration::ZERO,
        }
    }

    fn finish(&mut self) -> Result<Vec<bytes::Bytes>, ClipError> {
        if self.fail == Some(FakeClipFailure::Finish) {
            return Err(ClipError::Failed("the fake muxer fails its finish".into()));
        }
        Ok(vec![bytes::Bytes::from_static(b"end\n")])
    }
}

/// A `webrtc` session output whose engine echoes (see [`EchoEngine`]), so a
/// worker can run whole sessions without a WebRTC engine. It wants the
/// H.264 video track and Opus or PCMU audio, in that order, as the WebRTC
/// output does, but no video for an offer containing `no video`, as the
/// WebRTC output wants none for an offer without a video m-line; an offer
/// of `"refuse"` is refused as invalid SDP. The
/// answer is [`ECHO_ANSWER`], followed by ` audio=<codec>` with audio,
/// ` backchannel=<codec>` with a backchannel and ` orientation=<name>` for
/// a turned stream. An offer containing `talk` asks for talk-back
/// ([`OutputFactory::talkback_request`]), which the backchannel takes
/// when its codec is one a viewer can send and that reaches it; its
/// engine then reports talk-back negotiated in that codec when the
/// session holds the backchannel ([`TalkbackClaim::Granted`]). A re-offer
/// is answered [`ECHO_RENEGOTIATED`] the same way, but `refuse` is
/// invalid SDP and `no video` has no video m-line.
#[derive(Debug)]
pub struct EchoSessionFactory;

/// The answer [`EchoSessionFactory`] gives.
pub const ECHO_ANSWER: &str = "v=0 echo";

/// The answer [`EchoEngine`] gives a re-offer.
pub const ECHO_RENEGOTIATED: &str = "v=0 echo renegotiated";

/// The talk-back codec the echo negotiates for `offer` with
/// `backchannel` under `claim`: the backchannel's own codec, when the
/// offer asks for talk-back and the session holds the backchannel.
fn echo_talkback(
    offer: &str,
    backchannel: Option<&TalkbackTarget>,
    claim: TalkbackClaim,
) -> Option<UplinkCodec> {
    if !offer.contains("talk") || claim != TalkbackClaim::Granted {
        return None;
    }
    backchannel.and_then(|backchannel| {
        UplinkCodec::of(backchannel.codec.family())
            .filter(|codec| backchannel.takes.contains(codec))
    })
}

impl OutputFactory for EchoSessionFactory {
    fn kind(&self) -> &'static str {
        "webrtc"
    }

    fn session_tracks(&self, offer: &str, audio: bool) -> Vec<TrackRequest> {
        let mut requests = Vec::new();
        if !offer.contains("no video") {
            requests.push(TrackRequest {
                kind: Kind::Video,
                accept: vec![CodecFamily::H264],
                unit: Unit::Packets,
                required: true,
            });
        }
        if audio {
            requests.push(TrackRequest {
                kind: Kind::Audio,
                accept: vec![CodecFamily::Opus, CodecFamily::Pcmu],
                unit: Unit::Packets,
                required: false,
            });
        }
        requests
    }

    fn open_session(
        &self,
        request: SessionRequest,
        now: Instant,
    ) -> Result<(Box<dyn SessionEngine>, String), SessionOpenError> {
        if request.offer == "refuse" {
            return Err(SessionOpenError::InvalidSdp("refused by the echo".into()));
        }
        let audio = request
            .audio
            .as_ref()
            .map(|audio| format!("audio={}", audio.name()));
        let backchannel = request
            .backchannel
            .as_ref()
            .map(|backchannel| format!("backchannel={}", backchannel.codec.name()));
        let orientation = (request.orientation != Orientation::NoTransform)
            .then(|| format!("orientation={}", request.orientation.name()));
        let answer = std::iter::once(ECHO_ANSWER.to_owned())
            .chain(audio)
            .chain(backchannel)
            .chain(orientation)
            .collect::<Vec<_>>()
            .join(" ");
        let talkback = echo_talkback(&request.offer, request.backchannel.as_ref(), request.claim);
        Ok((
            Box::new(EchoEngine::new(now).with_talkback(talkback)),
            answer,
        ))
    }

    fn talkback_request(
        &self,
        offer: &str,
        _audio: Option<&Codec>,
        backchannel: Option<&TalkbackTarget>,
    ) -> TalkbackRequest {
        if !offer.contains("talk") {
            return TalkbackRequest::NotRequested;
        }
        match echo_talkback(offer, backchannel, TalkbackClaim::Granted) {
            Some(_) => TalkbackRequest::Negotiable,
            None if backchannel.is_none() => {
                TalkbackRequest::Unsupported("the camera offers no backchannel".to_owned())
            }
            None => TalkbackRequest::Unsupported(
                "the backchannel takes a codec talk-back cannot feed".to_owned(),
            ),
        }
    }
}

/// An engine that sends every datagram back where it came from, over the
/// transport it came on (a datagram starting `tcp:` goes back over ICE-TCP
/// whatever it came on, so a test can make a TCP send fail, and one
/// starting `audio:` goes back marked as the audio track's), hands on
/// what follows `talk:` in a datagram starting with it as a PCMU talk-back
/// packet (SSRC 1, 160 ticks after the last), reports
/// `Connected` on the first, counts the video packets and joins it gets,
/// reports the first audio packet with how long before its arrival it was
/// captured (an `echo_audio` warning), takes every relay candidate with a
/// specified address, takes every video change within the family unless
/// made [`EchoEngine::refusing_video_changes`], reports each orientation
/// change (an `echo_orientation` warning naming it), and closes when
/// asked.
#[derive(Debug)]
pub struct EchoEngine {
    /// Outputs not yet polled.
    out: VecDeque<SessionOutput>,
    /// The timeout it reports: an hour after the last datagram or
    /// timeout, so a fake clock run far ahead never finds it due on every
    /// poll.
    idle: Instant,
    /// `Connected` was reported.
    connected: bool,
    /// `Closed` was reported.
    closed: bool,
    /// The counters.
    stats: SessionStats,
    /// Every video change within the family is refused.
    refuse_video_changes: bool,
    /// The talk-back codec it reports negotiated.
    talkback: Option<UplinkCodec>,
}

impl EchoEngine {
    /// A fresh engine at `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            out: VecDeque::new(),
            idle: now.checked_add(Duration::from_secs(3600)).unwrap_or(now),
            connected: false,
            closed: false,
            stats: SessionStats::default(),
            refuse_video_changes: false,
            talkback: None,
        }
    }

    /// The engine, reporting talk-back negotiated in `codec`.
    #[must_use]
    pub const fn with_talkback(mut self, codec: Option<UplinkCodec>) -> Self {
        self.talkback = codec;
        self
    }

    /// The engine, refusing every video change within the family, as one
    /// whose negotiated payload type the new codec no longer fits.
    #[must_use]
    pub const fn refusing_video_changes(mut self) -> Self {
        self.refuse_video_changes = true;
        self
    }
}

impl SessionEngine for EchoEngine {
    fn handle_datagram(
        &mut self,
        now: Instant,
        transport: Transport,
        source: SocketAddr,
        destination: SocketAddr,
        bytes: &[u8],
    ) {
        self.idle = now.checked_add(Duration::from_secs(3600)).unwrap_or(now);
        let transport = if bytes.starts_with(b"tcp:") {
            Transport::Tcp
        } else {
            transport
        };
        self.out.push_back(SessionOutput::Transmit {
            transport,
            source: destination,
            destination: source,
            payload: bytes.to_vec(),
            audio: bytes.starts_with(b"audio:"),
        });
        if let Some(talk) = bytes.strip_prefix(b"talk:") {
            let count = self.stats.uplink_packets;
            let ts = u32::try_from(count % (1 << 32))
                .unwrap_or_default()
                .wrapping_mul(160);
            let seq = u16::try_from(count % (1 << 16)).unwrap_or_default();
            self.stats.uplink_packets = count.saturating_add(1);
            self.out.push_back(SessionOutput::Uplink(UplinkPacket {
                codec: UplinkCodec::Pcmu,
                packet: MediaPacket {
                    arrival: now,
                    rtp: crate::media::RtpHeaderFields {
                        pt: 0,
                        seq,
                        ts,
                        marker: false,
                        ssrc: 1,
                    },
                    frame_start: true,
                    keyframe_start: false,
                    epoch: 0,
                    lateness: Duration::ZERO,
                    payload: Arc::from(talk),
                },
                // PCMU: a sample per byte at 8 kHz.
                duration: Duration::from_micros(
                    u64::try_from(talk.len())
                        .unwrap_or(u64::MAX)
                        .saturating_mul(125),
                ),
            }));
        }
        if !self.connected {
            self.connected = true;
            self.out
                .push_back(SessionOutput::Event(SessionEvent::Connected));
        }
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.idle = now.checked_add(Duration::from_secs(3600)).unwrap_or(now);
    }

    fn add_remote_candidate(&mut self, _now: Instant, _candidate: &str) {}

    /// Takes any relayed address but an unspecified one, and names it in
    /// a line of its own making.
    fn add_relay_candidate(
        &mut self,
        _now: Instant,
        relayed: SocketAddr,
        _local: SocketAddr,
    ) -> Option<String> {
        (!relayed.ip().is_unspecified()).then(|| {
            format!(
                "candidate:echo 1 udp 1 {} {} typ relay",
                relayed.ip(),
                relayed.port()
            )
        })
    }

    fn join(&mut self, now: Instant, gop: Option<&GopSnapshot>) {
        let _ = (now, gop);
        self.stats.join_frames = self.stats.join_frames.saturating_add(1);
    }

    fn write_video(&mut self, now: Instant, packet: &MediaPacket, wallclock: Instant) {
        let _ = (now, packet, wallclock);
        self.stats.packets = self.stats.packets.saturating_add(1);
    }

    fn write_audio(&mut self, now: Instant, packet: &MediaPacket, wallclock: Instant) {
        let _ = now;
        if self.stats.audio_packets == 0 {
            let lead = packet.arrival.saturating_duration_since(wallclock);
            self.out
                .push_back(SessionOutput::Event(SessionEvent::Warning {
                    code: "echo_audio",
                    message: format!(
                        "the first audio packet arrived {} ms after its capture",
                        lead.as_millis()
                    ),
                }));
        }
        self.stats.audio_packets = self.stats.audio_packets.saturating_add(1);
    }

    fn skip_to_keyframe(&mut self, reason: &'static str) {
        let _ = reason;
        self.stats.skips = self.stats.skips.saturating_add(1);
    }

    /// Reports the change as an `echo_orientation` warning naming it.
    fn set_orientation(&mut self, orientation: Orientation) {
        self.out
            .push_back(SessionOutput::Event(SessionEvent::Warning {
                code: "echo_orientation",
                message: orientation.name().to_owned(),
            }));
    }

    fn check_video_change(&self, codec: &Codec) -> Result<(), String> {
        if self.refuse_video_changes {
            return Err(format!("the echo refuses {}", codec.name()));
        }
        Ok(())
    }

    fn close(&mut self, now: Instant, code: &'static str, message: String) {
        let _ = now;
        if !self.closed {
            self.closed = true;
            self.out
                .push_back(SessionOutput::Event(SessionEvent::Closed { code, message }));
        }
    }

    fn poll(&mut self) -> SessionOutput {
        self.out
            .pop_front()
            .unwrap_or(SessionOutput::Timeout(self.idle))
    }

    fn stats(&self) -> SessionStats {
        self.stats
    }

    fn talkback(&self) -> Option<UplinkCodec> {
        self.talkback
    }

    /// Answers [`ECHO_RENEGOTIATED`] with ` backchannel=<codec>` when
    /// talk-back is negotiated now, which [`SessionEngine::talkback`]
    /// reports from then on; `refuse` is invalid SDP, `no video` has no
    /// video m-line.
    fn renegotiate(
        &mut self,
        now: Instant,
        offer: &str,
        backchannel: Option<TalkbackTarget>,
        claim: TalkbackClaim,
    ) -> Result<String, RenegotiateError> {
        self.idle = now.checked_add(Duration::from_secs(3600)).unwrap_or(now);
        if offer == "refuse" {
            return Err(RenegotiateError::InvalidSdp("refused by the echo".into()));
        }
        if offer == "no video" {
            return Err(RenegotiateError::NoVideoTrack);
        }
        self.talkback = echo_talkback(offer, backchannel.as_ref(), claim);
        Ok(match self.talkback {
            Some(codec) => format!("{ECHO_RENEGOTIATED} backchannel={}", codec.name()),
            None => ECHO_RENEGOTIATED.to_owned(),
        })
    }
}

/// A transcoder from one family to another that never processes a frame.
/// Its handles report [`FakeTranscoder::DELAY`].
#[derive(Debug)]
pub struct FakeTranscoder {
    /// The family it accepts.
    from: CodecFamily,
    /// The family it produces.
    to: CodecFamily,
}

impl FakeTranscoder {
    /// The delay its handles report.
    pub const DELAY: Duration = Duration::from_millis(20);

    /// AAC-LC → Opus, the M2 chain.
    pub const fn aac_to_opus() -> Self {
        Self {
            from: CodecFamily::AacLc,
            to: CodecFamily::Opus,
        }
    }

    /// PCMU → Opus, which the daemon never needs (PCMU is cut through).
    pub const fn g711_to_opus() -> Self {
        Self {
            from: CodecFamily::Pcmu,
            to: CodecFamily::Opus,
        }
    }
}

impl Transcoder for FakeTranscoder {
    fn derive(&self, from: &Codec, to: CodecFamily) -> Option<Codec> {
        if from.family() != self.from || to != self.to {
            return None;
        }
        let channels = match from {
            Codec::AacLc { channels, .. } | Codec::Opus { channels } => *channels,
            _ => 1,
        };
        Some(Codec::Opus { channels })
    }

    fn spawn(
        &self,
        _input: FrameSubscription,
        from: &Codec,
        output: Arc<Track>,
    ) -> Result<TrackHandle, TranscodeError> {
        if self.derive(from, output.codec().family()).is_none() {
            return Err(TranscodeError::Unsupported {
                from: from.family(),
                to: output.codec().family(),
            });
        }
        Ok(TrackHandle {
            track: output,
            delay: Self::DELAY,
            stop: tokio_util::sync::CancellationToken::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use bytes::Bytes;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::clock::SystemClock;

    use crate::source::{BackchannelSlot, ClockInput, ResolvedPeer, TrackSet};
    use crate::track::{TrackId, TrackLimits};

    #[tokio::test]
    async fn fake_source_declares_a_video_track_and_ends_on_cancel() {
        let factory = FakeSourceFactory::new(&["fake"]);
        // The contract's defaults: no default port, no loopback relay.
        assert_eq!(factory.default_port("fake"), None);
        assert!(!factory.loopback_relay("fake"));
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = factory.validate(&url, &serde_json::Value::Null).unwrap();
        assert_eq!(source.describe().protocol, "fake");
        assert_eq!(source.describe().url, url);

        let set = TrackSet::new(TrackLimits::default(), SystemClock.now());
        let (clock, _reports) = ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
        let cancel = CancellationToken::new();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock,
            time: Arc::new(SystemClock),
            backchannel: BackchannelSlot::default(),
            cancel: cancel.clone(),
        });
        let mut ready = set.ready();
        let run = crate::task::spawn_named("test.fake_source", run);
        assert!(ready.changed().await.is_ok());
        assert_eq!(set.tracks().len(), 1);
        cancel.cancel();
        assert!(matches!(run.await.unwrap(), SourceError::Ended(_)));
    }

    /// The injected abort of `a_crashing_fake_source_aborts_once_ready`:
    /// it ends the source's task, not the test's process.
    fn crash() -> ! {
        panic!("the injected abort")
    }

    /// A fake source of `options` running on `clock`: its run, its track
    /// set and its cancel.
    fn run_fake(
        factory: &FakeSourceFactory,
        options: &serde_json::Value,
        clock: Arc<dyn Clock>,
    ) -> (
        tokio::task::JoinHandle<SourceError>,
        Arc<TrackSet>,
        CancellationToken,
    ) {
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = factory.validate(&url, options).unwrap();
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (input, _reports) = ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
        let cancel = CancellationToken::new();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock: input,
            time: clock,
            backchannel: BackchannelSlot::default(),
            cancel: cancel.clone(),
        });
        let run = crate::task::spawn_named("test.fake_source", run);
        (run, set, cancel)
    }

    #[tokio::test]
    async fn a_crashing_fake_source_aborts_once_ready() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let factory = FakeSourceFactory::new(&["fake"]).aborting_with(crash);
        let (run, set, _cancel) = run_fake(
            &factory,
            &serde_json::json!({"crash": true}),
            Arc::new(SystemClock),
        );
        let mut ready = set.ready();
        assert!(ready.changed().await.is_ok());
        // The crash follows the readiness in the same poll.
        let err = run.await.unwrap_err();
        assert!(err.is_panic());
        assert_eq!(
            err.into_panic().downcast_ref::<&str>(),
            Some(&"the injected abort")
        );
        assert_eq!(
            logs.count(
                tracing::Level::ERROR,
                "fake source: crashing the process as requested"
            ),
            1
        );
    }

    #[tokio::test]
    async fn a_fake_source_with_keyframes_publishes_one_every_interval() {
        use crate::clock::FakeClock;

        let factory = FakeSourceFactory::new(&["fake"]);
        let options = serde_json::json!({"keyframes_every_ms": 40});
        let url = SourceUrl::parse("fake://cam/").unwrap();
        assert_eq!(
            factory
                .validate(&url, &options)
                .unwrap()
                .connection_options()["keyframes_every_ms"],
            40
        );
        let clock = Arc::new(FakeClock::default());
        let (run, set, cancel) = run_fake(&factory, &options, clock.clone());
        let mut ready = set.ready();
        assert!(ready.changed().await.is_ok());
        let video = set.tracks().remove(0);
        let mut packets = video.subscribe(Unit::Packets);
        clock.advance(Duration::from_millis(40));
        crate::let_assert!(Some(crate::track::TrackEvent::Packet(packet)) = packets.next().await);
        assert!(packet.keyframe_start && packet.rtp.marker);
        assert_eq!(packet.rtp.seq, 1, "the second keyframe, 40 ms on");
        cancel.cancel();
        assert!(matches!(run.await.unwrap(), SourceError::Ended(_)));
    }

    #[tokio::test]
    async fn a_fake_source_with_a_backchannel_offers_it_while_it_runs() {
        assert!(!FakeSourceFactory::new(&["fake"]).capabilities().backchannel);
        let factory = FakeSourceFactory::with_backchannel(&["fake"]);
        assert!(factory.capabilities().backchannel);
        let url = SourceUrl::parse("fake://cam/").unwrap();
        for refused in [
            serde_json::json!({"backchannel": "g722"}),
            serde_json::json!({"backchannel": true}),
        ] {
            assert!(factory.validate(&url, &refused).is_err(), "{refused}");
        }
        let capture = BackchannelCapture::default();
        let capturing = FakeSourceFactory::capturing(&["fake"], capture.clone());
        assert!(capturing.capabilities().backchannel);
        for (name, codec, factory) in [
            ("pcmu", Codec::Pcmu, &factory),
            ("pcma", Codec::Pcma, &capturing),
            ("opus", Codec::Opus { channels: 2 }, &factory),
        ] {
            let source = factory
                .validate(&url, &serde_json::json!({ "backchannel": name }))
                .unwrap();
            let set = TrackSet::new(TrackLimits::default(), SystemClock.now());
            let (clock, _reports) =
                ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
            let cancel = CancellationToken::new();
            let slot = BackchannelSlot::default();
            let run = source.run(SourceCtx {
                peer: ResolvedPeer {
                    host: "cam".into(),
                    addrs: vec![],
                },
                tracks: set.publisher(),
                clock,
                time: Arc::new(SystemClock),
                backchannel: slot.clone(),
                cancel: cancel.clone(),
            });
            let mut ready = set.ready();
            let run = crate::task::spawn_named("test.fake_source", run);
            assert!(ready.changed().await.is_ok());
            // Offered before it went live, video only.
            let offer = slot.current().expect("offered");
            assert_eq!(offer.codec, codec);
            assert_eq!(offer.frame, BackchannelOffer::DEFAULT_FRAME);
            assert_eq!(set.tracks().len(), 1);
            // A claim opens a session at once, in the offer's codec.
            let session = offer.opener.open().await.unwrap();
            assert_eq!(session.codec, codec);
            assert_eq!(session.frame, BackchannelOffer::DEFAULT_FRAME);
            let before = capture.packets().len();
            for seq in 0..3 {
                assert!(
                    session
                        .sender
                        .try_send(pcmu_packet(SystemClock.now(), seq))
                        .is_ok()
                );
            }
            if name == "pcma" {
                let captured = tokio::select! {
                    captured = capture.wait_for(3) => captured,
                    () = SystemClock.sleep(Duration::from_secs(5)) => panic!("not captured"),
                };
                let seqs: Vec<u16> = captured.iter().map(|packet| packet.rtp.seq).collect();
                assert_eq!(seqs, [0, 1, 2], "in order");
                assert_eq!(capture.packets().len(), 3, "kept");
                assert_eq!(capture.sessions().opened, 1);
            } else {
                // Taken off the channel all the same, so it never fills.
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(session.sender.capacity(), 8);
                assert_eq!(capture.packets().len(), before, "nowhere to put them");
            }
            cancel.cancel();
            assert!(matches!(run.await.unwrap(), SourceError::Ended(_)));
            assert!(slot.current().is_some(), "the offer stands after the run");
            // The session is its holder's: open until dropped.
            assert!(!session.sender.is_closed());
            let sender = session.sender.clone();
            drop(session);
            if name == "pcma" {
                let both = FakeSessions {
                    opened: 1,
                    closed: 1,
                };
                within(capture.wait_sessions(both)).await;
                assert_eq!(capture.sessions(), both, "closed by its holder");
            }
            within(sender.closed()).await;
        }
    }

    /// The doorbell options: `backchannel` and `video`, alone or together
    /// and nothing else; video is 30 fps H.264 on the injected clock with
    /// a keyframe every second, and what the backchannel takes is stamped
    /// with its arrival on the same clock.
    #[tokio::test]
    async fn a_fake_doorbell_publishes_video_and_stamps_what_its_backchannel_takes() {
        use crate::clock::FakeClock;

        let capture = BackchannelCapture::default();
        let factory = FakeSourceFactory::capturing(&["fake"], capture.clone());
        let url = SourceUrl::parse("fake://cam/").unwrap();
        for refused in [
            serde_json::json!({"video": false}),
            serde_json::json!({"video": "yes"}),
            serde_json::json!({"video": true, "extra": 1}),
            serde_json::json!({"video": true, "backchannel": "g722"}),
            serde_json::json!({"video": true, "audio": true}),
        ] {
            assert!(factory.validate(&url, &refused).is_err(), "{refused}");
        }
        let video_only = factory
            .validate(&url, &serde_json::json!({"video": true}))
            .unwrap();
        assert_eq!(video_only.connection_options()["video"], true);
        let source = factory
            .validate(
                &url,
                &serde_json::json!({"backchannel": "pcmu", "video": true}),
            )
            .unwrap();
        let clock = Arc::new(FakeClock::default());
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (input, _reports) = ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
        let cancel = CancellationToken::new();
        let slot = BackchannelSlot::default();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock: input,
            time: clock.clone(),
            backchannel: slot.clone(),
            cancel: cancel.clone(),
        });
        let mut ready = set.ready();
        let mut packets = {
            let run = crate::task::spawn_named("test.fake_source", run);
            assert!(ready.changed().await.is_ok());
            let tracks = set.tracks();
            assert_eq!(tracks.len(), 1, "video only");
            (tracks[0].subscribe_packets(), run)
        };
        // Frame 0 went out as it went live, before the subscription; then
        // one per frame duration, and the GOP restarts on frame 30.
        let mut seen = Vec::new();
        for _ in 1..=31 {
            clock.advance(VIDEO_FRAME);
            seen.push(within(packets.0.recv()).await.unwrap());
        }
        for (index, packet) in (1_u32..).zip(&seen) {
            assert_eq!(u32::from(packet.rtp.seq), index);
            assert_eq!(packet.rtp.ts, index * 3_000, "90 kHz at 30 fps");
            assert!(packet.rtp.marker && packet.frame_start);
            assert_eq!(packet.keyframe_start, index % 30 == 0, "frame {index}");
            assert_eq!(
                packet.payload[0] & 0x1f,
                if index % 30 == 0 { 5 } else { 1 }
            );
        }
        let session = slot
            .current()
            .expect("offered")
            .opener
            .open()
            .await
            .unwrap();
        assert!(session.sender.try_send(pcmu_packet(clock.now(), 7)).is_ok());
        let captured = within(async {
            loop {
                if let Some(first) = capture.captured().first().cloned() {
                    return first;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert_eq!(captured.packet.rtp.seq, 7);
        assert_eq!(captured.at, clock.now(), "stamped on the injected clock");
        assert_eq!(capture.packets().len(), 1);
        cancel.cancel();
        assert!(matches!(packets.1.await.unwrap(), SourceError::Ended(_)));
        drop(session);
    }

    /// The ingest contract: a source honors `cancel` within 100 ms in every
    /// state, the wait to go live
    /// included. The clock never moves here, so only the cancel can end it.
    #[tokio::test]
    async fn fake_source_waiting_to_go_live_ends_on_cancel() {
        use crate::clock::FakeClock;

        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = FakeSourceFactory::new(&["fake"])
            .validate(&url, &serde_json::json!({"ready_after_ms": 1000}))
            .unwrap();
        let clock = Arc::new(FakeClock::default());
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (input, _reports) = ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
        let cancel = CancellationToken::new();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock: input,
            time: clock.clone(),
            backchannel: BackchannelSlot::default(),
            cancel: cancel.clone(),
        });
        let run = crate::task::spawn_named("test.fake_source", run);
        tokio::task::yield_now().await;
        cancel.cancel();
        assert!(matches!(within(run).await.unwrap(), SourceError::Ended(_)));
        assert!(set.tracks().is_empty(), "cancelled before it declared any");
    }

    /// A fake source with a backchannel marks its slot probed before its
    /// tracks are ready and probes beside its run under a permit of the
    /// slot's gate, which it asks for once they are: its readiness never
    /// waits for that permit, which with one connect permit its own
    /// attempt holds until it is live. A cancel while the probe waits
    /// abandons it.
    #[tokio::test]
    async fn a_fake_source_probes_its_backchannel_under_a_permit_once_ready() {
        use crate::runner::{ProbeAsk, ProbeGate};

        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = FakeSourceFactory::with_backchannel(&["fake"])
            .validate(&url, &serde_json::json!({"backchannel": "pcmu"}))
            .unwrap();
        for granted in [true, false] {
            let (gate, mut asks) = ProbeGate::closed();
            let slot = BackchannelSlot::gated(gate.clone());
            let set = TrackSet::new(TrackLimits::default(), SystemClock.now());
            let (input, _reports) =
                ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
            let cancel = CancellationToken::new();
            let run = source.run(SourceCtx {
                peer: ResolvedPeer {
                    host: "cam".into(),
                    addrs: vec![],
                },
                tracks: set.publisher(),
                clock: input,
                time: Arc::new(SystemClock),
                backchannel: slot.clone(),
                cancel: cancel.clone(),
            });
            let mut ready = set.ready();
            let run = crate::task::spawn_named("test.fake_source", run);
            assert!(
                within(ready.wait_for(|ready| *ready)).await.is_ok(),
                "ready without the probe's permit"
            );
            assert!(slot.is_probing(), "marked before the tracks were ready");
            assert_eq!(within(asks.recv()).await, Some(ProbeAsk::Connecting(1)));
            if granted {
                assert!(gate.grant(1));
                assert_eq!(within(asks.recv()).await, Some(ProbeAsk::Ended(1)));
                assert_eq!(slot.current().unwrap().codec, Codec::Pcmu);
            }
            cancel.cancel();
            assert!(matches!(within(run).await.unwrap(), SourceError::Ended(_)));
            assert!(!slot.is_probing(), "{granted}");
            assert_eq!(slot.current().is_some(), granted);
            if !granted {
                assert_eq!(within(asks.recv()).await, Some(ProbeAsk::Ended(1)));
            }
        }
    }

    /// `future`'s output, or a failed test after five seconds of real time.
    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::select! {
            output = future => output,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
        }
    }

    #[tokio::test]
    async fn fake_source_with_audio_declares_pcmu_and_publishes_every_20_ms() {
        use crate::clock::FakeClock;

        let factory = FakeSourceFactory::new(&["fake"]);
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = factory
            .validate(&url, &serde_json::json!({"audio": true}))
            .unwrap();
        let clock = Arc::new(FakeClock::default());
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (input, _reports) = ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
        let cancel = CancellationToken::new();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock: input,
            time: clock.clone(),
            backchannel: BackchannelSlot::default(),
            cancel: cancel.clone(),
        });
        let mut ready = set.ready();
        let run = crate::task::spawn_named("test.fake_source", run);
        assert!(ready.changed().await.is_ok());
        let tracks = set.tracks();
        assert_eq!(tracks.len(), 2);
        let audio = tracks.iter().find(|t| t.kind() == Kind::Audio).unwrap();
        assert_eq!(
            (audio.codec().as_ref(), audio.clock_rate()),
            (&Codec::Pcmu, 8_000)
        );
        let mut packets = audio.subscribe_packets();
        for step in 0..3 {
            clock.advance(Duration::from_millis(20));
            let packet = within(packets.recv()).await.unwrap();
            assert_eq!(packet.payload.len(), 160, "20 ms of G.711, step {step}");
            assert_eq!(packet.rtp.seq, step + 1);
            assert_eq!(packet.rtp.ts, 160 * u32::from(step + 1));
        }
        cancel.cancel();
        assert!(matches!(run.await.unwrap(), SourceError::Ended(_)));
    }

    #[tokio::test]
    async fn fake_source_with_aac_audio_frames_16_khz_aac_lc_every_64_ms() {
        use crate::clock::FakeClock;

        let factory = FakeSourceFactory::new(&["fake"]);
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = factory
            .validate(&url, &serde_json::json!({"audio": "aac"}))
            .unwrap();
        let clock = Arc::new(FakeClock::default());
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (input, mut reports) =
            ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
        let cancel = CancellationToken::new();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock: input,
            time: clock.clone(),
            backchannel: BackchannelSlot::default(),
            cancel: cancel.clone(),
        });
        let mut ready = set.ready();
        let run = crate::task::spawn_named("test.fake_source", run);
        assert!(ready.changed().await.is_ok());
        let audio = set
            .tracks()
            .into_iter()
            .find(|t| t.kind() == Kind::Audio)
            .unwrap();
        assert_eq!(
            (audio.codec().as_ref(), audio.clock_rate()),
            (&fake_aac(), 16_000)
        );
        let mut frames = audio.subscribe_frames();
        for step in 1..=2 {
            clock.advance(Duration::from_millis(64));
            let frame = within(frames.recv()).await.unwrap();
            assert_eq!(frame.ts.ticks(), 1024 * step, "one AAC-LC frame apart");
            assert_eq!(frame.wallclock, clock.now());
        }
        assert_eq!(audio.stats().packets, 0, "side branch only");
        // A frame past the second the reporting fakes send their first
        // Sender Reports at, it has sent none.
        for _ in 3..=17 {
            clock.advance(Duration::from_millis(64));
            within(frames.recv()).await.unwrap();
        }
        assert!(reports.try_recv().is_err(), "no Sender Reports");
        cancel.cancel();
        assert!(matches!(run.await.unwrap(), SourceError::Ended(_)));
    }

    /// What a fake source with `options` reports in its first Sender
    /// Reports, video's and audio's: track, clock rate and hint. Asserts
    /// that none comes within the first second, and that the pair comes
    /// at once after it, 1024 ms on the frame grid.
    async fn first_sender_reports(
        options: serde_json::Value,
    ) -> [(String, u32, crate::source::SyncHint); 2] {
        use crate::clock::FakeClock;
        use crate::source::ClockReport;

        let factory = FakeSourceFactory::new(&["fake"]);
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = factory.validate(&url, &options).unwrap();
        let clock = Arc::new(FakeClock::default());
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let (input, mut reports) =
            ClockInput::channel(Arc::new(crate::clock_map::ClockMapper::new()));
        let cancel = CancellationToken::new();
        let run = source.run(SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock: input,
            time: clock.clone(),
            backchannel: BackchannelSlot::default(),
            cancel: cancel.clone(),
        });
        let mut ready = set.ready();
        let run = crate::task::spawn_named("test.fake_source", run);
        assert!(ready.changed().await.is_ok());
        let live = clock.now();
        let hint = |report: ClockReport| (report.track.to_string(), report.clock_rate, report.hint);
        // None at once: the first pair once a second has passed.
        for _ in 0..15 {
            clock.advance(Duration::from_millis(64));
            tokio::task::yield_now().await;
        }
        assert!(
            reports.try_recv().is_err(),
            "no report within the first second"
        );
        clock.advance(Duration::from_millis(64));
        let report = within(reports.recv()).await.unwrap();
        assert_eq!(report.arrival, live + Duration::from_millis(1_024));
        let video = hint(report);
        let audio = hint(within(reports.recv()).await.unwrap());
        cancel.cancel();
        assert!(matches!(run.await.unwrap(), SourceError::Ended(_)));
        [video, audio]
    }

    /// A Sender Report's hint.
    fn sr(ntp: u64, rtp_ts: u32) -> crate::source::SyncHint {
        crate::source::SyncHint::RtcpSenderReport { ntp, rtp_ts }
    }

    #[tokio::test]
    async fn fake_source_with_drifting_aac_reports_audio_running_2_percent_fast() {
        let [video, audio] =
            first_sender_reports(serde_json::json!({"audio": "aac_drifting"})).await;
        assert_eq!(
            video,
            (
                "v0".into(),
                90_000,
                sr(ntp_timestamp(Duration::from_millis(1_024)), 92_160)
            )
        );
        assert_eq!(
            audio,
            (
                "a0".into(),
                16_000,
                sr(ntp_timestamp(Duration::from_micros(1_044_480)), 16_384)
            )
        );
        assert_eq!(
            ntp_timestamp(Duration::from_millis(1_500)),
            (1 << 32) | (1 << 31)
        );
        assert_eq!(
            rtp_timestamp(Duration::from_secs(1 << 20), 90_000),
            4_177_526_784
        );
    }

    #[tokio::test]
    async fn fake_source_with_steady_aac_reports_both_clocks_agreeing() {
        let [video, audio] = first_sender_reports(serde_json::json!({"audio": "aac_steady"})).await;
        let claimed = ntp_timestamp(Duration::from_millis(1_024));
        assert_eq!(video, ("v0".into(), 90_000, sr(claimed, 92_160)));
        assert_eq!(audio, ("a0".into(), 16_000, sr(claimed, 16_384)));
    }

    #[test]
    fn fake_source_factory_rejects_options() {
        let factory = FakeSourceFactory::new(&["fake"]);
        let url = SourceUrl::parse("fake://cam/").unwrap();
        assert!(factory.validate(&url, &serde_json::json!({})).is_ok());
        let err = factory
            .validate(&url, &serde_json::json!({"transport": "udp"}))
            .unwrap_err();
        assert_eq!(
            err,
            SourceConfigError::InvalidOptions {
                scheme: "fake",
                message: "fake source takes no options but {\"crash\": true}, {\"ready_after_ms\": n}, {\"keyframes_every_ms\": n}, {\"audio\": true | \"aac\" | \"aac_drifting\" | \"aac_steady\"}, {\"backchannel\": \"pcmu\" | \"pcma\" | \"opus\"} and {\"video\": true}, got {\"transport\":\"udp\"}"
                    .into()
            }
        );
        assert!(
            factory
                .validate(&url, &serde_json::json!({"crash": true}))
                .is_ok()
        );
        assert!(
            factory
                .validate(&url, &serde_json::json!({"crash": false}))
                .is_err()
        );
        for bad in [
            serde_json::json!({"crash": true, "extra": 1}),
            serde_json::json!({"ready_after_ms": 5, "extra": 1}),
            serde_json::json!({"ready_after_ms": "soon"}),
            serde_json::json!([]),
        ] {
            assert!(factory.validate(&url, &bad).is_err(), "{bad}");
        }
        assert!(
            factory
                .validate(&url, &serde_json::json!({"ready_after_ms": 5}))
                .is_ok()
        );
        assert_eq!(FakeSourceFactory::new(&[]).schemes().len(), 0);
        assert!(
            FakeSourceFactory::new(&[])
                .validate(&url, &serde_json::Value::Null)
                .is_ok()
        );
    }

    #[test]
    fn fake_source_connection_options_are_normalized_with_defaults() {
        let factory = FakeSourceFactory::new(&["fake"]);
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let key = |options: serde_json::Value| {
            factory
                .validate(&url, &options)
                .unwrap()
                .connection_options()
        };
        let defaults = serde_json::json!({"crash": false, "ready_after_ms": 0, "audio": "none", "keyframes_every_ms": null, "backchannel": null, "video": false});
        for same in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"ready_after_ms": 0}),
        ] {
            assert_eq!(key(same), defaults);
        }
        for (options, field, value) in [
            (
                serde_json::json!({"crash": true}),
                "crash",
                serde_json::json!(true),
            ),
            (
                serde_json::json!({"ready_after_ms": 5}),
                "ready_after_ms",
                serde_json::json!(5),
            ),
            (
                serde_json::json!({"audio": true}),
                "audio",
                serde_json::json!("pcmu"),
            ),
            (
                serde_json::json!({"audio": "aac"}),
                "audio",
                serde_json::json!("aac"),
            ),
            (
                serde_json::json!({"audio": "aac_drifting"}),
                "audio",
                serde_json::json!("aac_drifting"),
            ),
            (
                serde_json::json!({"audio": "aac_steady"}),
                "audio",
                serde_json::json!("aac_steady"),
            ),
            (
                serde_json::json!({"video": true}),
                "video",
                serde_json::json!(true),
            ),
        ] {
            let mut expected = defaults.clone();
            expected[field] = value;
            assert_eq!(key(options), expected);
        }
    }

    #[test]
    fn a_fake_source_asks_for_the_backchannel_only_with_talk_and_on_the_same_connection() {
        let factory = FakeSourceFactory::new(&["fake"]);
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = |options: serde_json::Value| factory.validate(&url, &options).unwrap();
        let quiet = source(serde_json::Value::Null);
        assert!(!quiet.wants_backchannel());
        for (options, talk) in [
            (serde_json::json!({"talk": false}), false),
            (serde_json::json!({"talk": true}), true),
        ] {
            let built = source(options);
            assert_eq!(built.wants_backchannel(), talk);
            assert_eq!(built.connection_options(), quiet.connection_options());
        }
        let slow = source(serde_json::json!({"talk": true, "ready_after_ms": 5}));
        assert!(slow.wants_backchannel());
        assert_eq!(slow.connection_options()["ready_after_ms"], 5);
        let err = factory
            .validate(&url, &serde_json::json!({"talk": "yes"}))
            .unwrap_err();
        assert!(err.to_string().contains("talk must be"), "{err}");
    }

    #[test]
    fn fake_transcoder_derives_and_spawns_only_its_conversion() {
        let aac = Codec::AacLc {
            sample_rate: 16_000,
            channels: 2,
            config: Bytes::new(),
        };
        let transcoder = FakeTranscoder::aac_to_opus();
        assert_eq!(
            transcoder.derive(&aac, CodecFamily::Opus),
            Some(Codec::Opus { channels: 2 })
        );
        assert_eq!(transcoder.derive(&aac, CodecFamily::Pcmu), None);
        assert_eq!(transcoder.derive(&Codec::Pcmu, CodecFamily::Opus), None);
        assert_eq!(
            FakeTranscoder::g711_to_opus().derive(&Codec::Pcmu, CodecFamily::Opus),
            Some(Codec::Opus { channels: 1 })
        );

        let input = Track::new(
            TrackId::new(Kind::Audio, 0),
            aac.clone(),
            16_000,
            TrackLimits::default(),
            SystemClock.now(),
        );
        let output = Arc::new(Track::new(
            TrackId::new(Kind::Audio, 1),
            Codec::Opus { channels: 2 },
            48_000,
            TrackLimits::default(),
            SystemClock.now(),
        ));
        let handle = transcoder
            .spawn(input.subscribe_frames(), &aac, Arc::clone(&output))
            .unwrap();
        assert!(Arc::ptr_eq(&handle.track, &output));
        assert_eq!(handle.delay, FakeTranscoder::DELAY);
        assert_eq!(
            transcoder
                .spawn(input.subscribe_frames(), &Codec::Pcmu, output)
                .unwrap_err(),
            TranscodeError::Unsupported {
                from: CodecFamily::Pcmu,
                to: CodecFamily::Opus
            }
        );
        assert_eq!(FakeOutputFactory("snapshot").kind(), "snapshot");
    }

    #[test]
    fn the_echo_engine_marks_what_starts_audio_as_audio() {
        let now = SystemClock.now();
        let daemon: SocketAddr = "192.0.2.1:18556".parse().unwrap();
        let browser: SocketAddr = "192.0.2.2:5000".parse().unwrap();
        let mut engine = EchoEngine::new(now);
        for (payload, audio) in [(&b"audio:x"[..], true), (&b"video"[..], false)] {
            engine.handle_datagram(now, Transport::Udp, browser, daemon, payload);
            assert_eq!(
                engine.poll(),
                SessionOutput::Transmit {
                    transport: Transport::Udp,
                    source: daemon,
                    destination: browser,
                    payload: payload.to_vec(),
                    audio,
                }
            );
            if audio {
                // The first datagram connects.
                assert_eq!(engine.poll(), SessionOutput::Event(SessionEvent::Connected));
            }
        }
    }

    #[test]
    fn the_echo_names_audio_the_backchannel_and_a_turn_in_its_answer_and_reports_turns() {
        let now = SystemClock.now();
        let turned = SessionRequest {
            offer: "v=0 talk".into(),
            ice: crate::session::IceCredentials {
                ufrag: "u".into(),
                pass: "p".into(),
            },
            candidates: vec![],
            tcp_candidates: vec![],
            video: Some(Arc::new(Codec::Pcmu)),
            audio: Some(Arc::new(Codec::Pcmu)),
            backchannel: Some(TalkbackTarget {
                codec: Codec::Pcma,
                takes: vec![UplinkCodec::Pcma],
            }),
            claim: TalkbackClaim::Granted,
            orientation: Orientation::Rotate180,
            limits: crate::session::SessionLimits::default(),
            wall: std::time::SystemTime::UNIX_EPOCH,
        };
        let (mut engine, answer) = EchoSessionFactory
            .open_session(turned.clone(), now)
            .unwrap();
        assert_eq!(
            answer,
            format!("{ECHO_ANSWER} audio=pcmu backchannel=pcma orientation=rotate_180")
        );
        engine.set_orientation(Orientation::RotateLeft);
        assert_eq!(
            engine.poll(),
            SessionOutput::Event(SessionEvent::Warning {
                code: "echo_orientation",
                message: "rotate_left".into()
            })
        );
        // Talk-back negotiated in the backchannel's codec, off without one.
        assert_eq!(engine.talkback(), Some(UplinkCodec::Pcma));
        // Nor when its codec does not reach the backchannel.
        let unroutable = SessionRequest {
            backchannel: Some(TalkbackTarget {
                codec: Codec::Pcma,
                takes: vec![UplinkCodec::Opus],
            }),
            ..turned.clone()
        };
        let (engine, _answer) = EchoSessionFactory.open_session(unroutable, now).unwrap();
        assert_eq!(engine.talkback(), None);
        let without = SessionRequest {
            backchannel: None,
            ..turned.clone()
        };
        let (engine, _answer) = EchoSessionFactory.open_session(without, now).unwrap();
        assert_eq!(engine.talkback(), None);
        // Nor for an offer that asks for none, or a session another
        // holds the backchannel against.
        let silent = SessionRequest {
            offer: "v=0".into(),
            ..turned.clone()
        };
        let (engine, _answer) = EchoSessionFactory.open_session(silent, now).unwrap();
        assert_eq!(engine.talkback(), None);
        let busy = SessionRequest {
            claim: TalkbackClaim::Busy,
            ..turned.clone()
        };
        let (engine, _answer) = EchoSessionFactory.open_session(busy, now).unwrap();
        assert_eq!(engine.talkback(), None);
        // What an offer asks for, as the worker arbitrates it.
        let target = turned.backchannel.as_ref();
        assert_eq!(
            EchoSessionFactory.talkback_request("v=0", None, target),
            TalkbackRequest::NotRequested
        );
        assert_eq!(
            EchoSessionFactory.talkback_request("v=0 talk", None, target),
            TalkbackRequest::Negotiable
        );
        assert_eq!(
            EchoSessionFactory.talkback_request("v=0 talk", None, None),
            TalkbackRequest::Unsupported("the camera offers no backchannel".into())
        );
        let unroutable = TalkbackTarget {
            codec: Codec::Pcma,
            takes: vec![UplinkCodec::Opus],
        };
        assert_eq!(
            EchoSessionFactory.talkback_request("v=0 talk", None, Some(&unroutable)),
            TalkbackRequest::Unsupported(
                "the backchannel takes a codec talk-back cannot feed".into()
            )
        );
    }

    #[test]
    fn the_echo_engine_answers_a_re_offer_and_negotiates_talk_back_from_it() {
        let now = SystemClock.now();
        let mut engine = EchoEngine::new(now);
        let target = TalkbackTarget {
            codec: Codec::Pcmu,
            takes: vec![UplinkCodec::Pcmu],
        };
        assert_eq!(
            engine.renegotiate(
                now,
                "v=0 talk",
                Some(target.clone()),
                TalkbackClaim::Granted
            ),
            Ok(format!("{ECHO_RENEGOTIATED} backchannel=pcmu"))
        );
        assert_eq!(engine.talkback(), Some(UplinkCodec::Pcmu));
        assert_eq!(
            engine.renegotiate(now, "v=0", Some(target.clone()), TalkbackClaim::Granted),
            Ok(ECHO_RENEGOTIATED.to_owned())
        );
        assert_eq!(engine.talkback(), None);
        assert_eq!(
            engine.renegotiate(now, "v=0 talk", Some(target), TalkbackClaim::Busy),
            Ok(ECHO_RENEGOTIATED.to_owned())
        );
        assert_eq!(
            engine.renegotiate(now, "refuse", None, TalkbackClaim::Granted),
            Err(RenegotiateError::InvalidSdp("refused by the echo".into()))
        );
        assert_eq!(
            engine.renegotiate(now, "no video", None, TalkbackClaim::Granted),
            Err(RenegotiateError::NoVideoTrack)
        );
        let later = now + Duration::from_secs(7200);
        engine
            .renegotiate(later, "v=0", None, TalkbackClaim::Granted)
            .unwrap();
        assert_eq!(
            engine.poll(),
            SessionOutput::Timeout(later + Duration::from_secs(3600)),
            "idle from the re-offer on"
        );
    }

    /// An offer without video wants no video track, as the WebRTC
    /// output's does.
    #[test]
    fn the_echo_factory_wants_no_video_for_an_offer_without_it() {
        let factory = EchoSessionFactory;
        let talk_only = factory.session_tracks("talk, no video", true);
        assert_eq!(talk_only.len(), 1);
        assert_eq!(talk_only[0].kind, Kind::Audio);
        assert!(factory.session_tracks("talk, no video", false).is_empty());
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one engine's whole contract")]
    fn the_echo_engine_sends_back_reports_once_and_counts() {
        let now = SystemClock.now();
        let request = |offer: &str| SessionRequest {
            offer: offer.into(),
            ice: crate::session::IceCredentials {
                ufrag: "u".into(),
                pass: "p".into(),
            },
            candidates: vec![],
            tcp_candidates: vec![],
            video: Some(Arc::new(Codec::Pcmu)),
            audio: None,
            backchannel: None,
            claim: TalkbackClaim::Granted,
            orientation: Orientation::default(),
            limits: crate::session::SessionLimits::default(),
            wall: std::time::SystemTime::UNIX_EPOCH,
        };
        let factory = EchoSessionFactory;
        assert_eq!(factory.kind(), "webrtc");
        let tracks = factory.session_tracks("offer", true);
        assert_eq!(tracks.len(), 2);
        assert!(tracks[0].required && tracks[0].accept == [CodecFamily::H264]);
        assert!(!tracks[1].required && tracks[1].accept == [CodecFamily::Opus, CodecFamily::Pcmu]);
        assert_eq!(
            factory.session_tracks("offer", false).len(),
            1,
            "video-first"
        );
        assert!(matches!(
            factory.open_session(request("refuse"), now),
            Err(SessionOpenError::InvalidSdp(_))
        ));
        assert_eq!(
            FakeOutputFactory("fake")
                .open_session(request("v=0"), now)
                .err(),
            Some(SessionOpenError::InvalidSdp(
                "the fake fake output answers no offer".into()
            ))
        );
        let (mut engine, answer) = factory.open_session(request("v=0"), now).unwrap();
        assert_eq!(answer, ECHO_ANSWER);
        assert_eq!(
            engine.poll(),
            SessionOutput::Timeout(now + Duration::from_secs(3600))
        );
        let browser: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let daemon: SocketAddr = "192.0.2.1:18556".parse().unwrap();
        let later = now + Duration::from_secs(7200);
        engine.handle_timeout(later);
        assert_eq!(
            engine.poll(),
            SessionOutput::Timeout(later + Duration::from_secs(3600)),
            "a timeout moves the next one on"
        );
        engine.add_remote_candidate(now, "");
        assert_eq!(
            engine.add_relay_candidate(now, "203.0.113.1:49153".parse().unwrap(), daemon),
            Some("candidate:echo 1 udp 1 203.0.113.1 49153 typ relay".to_owned())
        );
        assert_eq!(
            engine.add_relay_candidate(now, "0.0.0.0:1".parse().unwrap(), daemon),
            None
        );
        for _ in 0..2 {
            engine.handle_datagram(now, Transport::Tcp, browser, daemon, b"hi");
        }
        engine.handle_datagram(now, Transport::Udp, browser, daemon, b"tcp:x");
        let echo = SessionOutput::Transmit {
            transport: Transport::Tcp,
            source: daemon,
            destination: browser,
            payload: b"hi".to_vec(),
            audio: false,
        };
        assert_eq!(engine.poll(), echo);
        assert_eq!(engine.poll(), SessionOutput::Event(SessionEvent::Connected));
        assert_eq!(engine.poll(), echo, "connected once");
        assert_eq!(
            engine.poll(),
            SessionOutput::Transmit {
                transport: Transport::Tcp,
                source: daemon,
                destination: browser,
                payload: b"tcp:x".to_vec(),
                audio: false,
            },
            "`tcp:` goes back over TCP"
        );
        engine.join(now, None);
        let packet = MediaPacket {
            arrival: now,
            rtp: crate::media::RtpHeaderFields {
                pt: 96,
                seq: 0,
                ts: 0,
                marker: false,
                ssrc: 0,
            },
            frame_start: true,
            keyframe_start: true,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0_u8][..]),
        };
        engine.write_video(now, &packet, now);
        let heard = now + Duration::from_millis(78);
        engine.write_audio(
            heard,
            &MediaPacket {
                arrival: heard,
                ..packet.clone()
            },
            now,
        );
        engine.write_audio(heard, &packet, now);
        assert_eq!(
            engine.poll(),
            SessionOutput::Event(SessionEvent::Warning {
                code: "echo_audio",
                message: "the first audio packet arrived 78 ms after its capture".into()
            })
        );
        assert_eq!(engine.stats().audio_packets, 2);
        engine.skip_to_keyframe("gap");
        let stats = engine.stats();
        assert_eq!((stats.join_frames, stats.packets, stats.skips), (1, 1, 1));
        engine.close(now, "session_closed", "bye".into());
        engine.close(now, "session_closed", "again".into());
        assert_eq!(
            engine.poll(),
            SessionOutput::Event(SessionEvent::Closed {
                code: "session_closed",
                message: "bye".into()
            })
        );
        assert!(
            matches!(engine.poll(), SessionOutput::Timeout(_)),
            "closed once"
        );
    }

    #[test]
    fn the_echo_engine_hands_what_follows_talk_on_as_pcmu_talk_back() {
        use crate::clock::SystemClock;

        let now = SystemClock.now();
        let mut engine = EchoEngine::new(now);
        let browser: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let daemon: SocketAddr = "192.0.2.1:18556".parse().unwrap();
        engine.handle_datagram(now, Transport::Udp, browser, daemon, b"hi");
        assert!(matches!(engine.poll(), SessionOutput::Transmit { .. }));
        assert_eq!(engine.poll(), SessionOutput::Event(SessionEvent::Connected));
        for k in 0..2_u16 {
            engine.handle_datagram(now, Transport::Udp, browser, daemon, b"talk:\xff\xfe");
            assert!(matches!(engine.poll(), SessionOutput::Transmit { .. }));
            assert_eq!(
                engine.poll(),
                SessionOutput::Uplink(UplinkPacket {
                    codec: UplinkCodec::Pcmu,
                    packet: MediaPacket {
                        arrival: now,
                        rtp: crate::media::RtpHeaderFields {
                            pt: 0,
                            seq: k,
                            ts: 160 * u32::from(k),
                            marker: false,
                            ssrc: 1,
                        },
                        frame_start: true,
                        keyframe_start: false,
                        epoch: 0,
                        lateness: Duration::ZERO,
                        payload: Arc::from(&[0xff_u8, 0xfe][..]),
                    },
                    duration: Duration::from_micros(250),
                })
            );
        }
        assert_eq!(engine.stats().uplink_packets, 2);
    }
}
