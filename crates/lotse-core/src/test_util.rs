//! Fakes for core's own contracts, behind the `test-util` feature: a source
//! factory and source, an output factory, a session output whose engine
//! echoes, and a transcoder that do nothing but honor the contracts, and the
//! tests' `let_assert!`. `lotse-testing` cannot hold them because it
//! depends on this crate.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::codec::{Codec, CodecFamily, Kind};
use crate::media::{MediaFrame, MediaPacket, MediaTime};
use crate::orientation::Orientation;
use crate::output::{OutputFactory, OutputShape, TrackRequest};
use crate::session::{
    SessionEngine, SessionEvent, SessionOpenError, SessionOutput, SessionRequest, SessionStats,
    Transport,
};
use crate::source::{
    BackchannelHandle, Direction, Source, SourceCapabilities, SourceConfigError, SourceCtx,
    SourceDescriptor, SourceError, SourceExit, SourceFactory,
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
/// clock runs 2 % fast, so the skew watchdog withdraws its audio, or
/// `{"backchannel": "pcmu" | "pcma" | "opus"}` to offer a backchannel
/// taking that codec in 20 ms frames while it runs (whose packets go into
/// the factory's [`BackchannelCapture`], if it has one, else nowhere);
/// anything else is rejected, so tests can see the validation error path.
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
/// order, across runs: the packets as the worker sent them to the device.
#[derive(Debug, Clone)]
pub struct BackchannelCapture {
    /// The packets; a waiter sees each one arrive.
    packets: Arc<tokio::sync::watch::Sender<Vec<MediaPacket>>>,
}

impl Default for BackchannelCapture {
    fn default() -> Self {
        Self {
            packets: Arc::new(tokio::sync::watch::Sender::new(Vec::new())),
        }
    }
}

impl BackchannelCapture {
    /// Every packet received so far.
    pub fn packets(&self) -> Vec<MediaPacket> {
        self.packets.borrow().clone()
    }

    /// Waits until at least `count` packets arrived, and returns them all.
    pub async fn wait_for(&self, count: usize) -> Vec<MediaPacket> {
        let mut packets = self.packets.subscribe();
        packets
            .wait_for(|packets| packets.len() >= count)
            .await
            .map(|packets| packets.clone())
            .unwrap_or_default()
    }

    /// Records one packet.
    fn push(&self, packet: MediaPacket) {
        self.packets.send_modify(|packets| packets.push(packet));
    }
}

/// Runs `live` to its end, taking what the backchannel receives
/// meanwhile into `capture` if there is one.
async fn drain_while(
    live: impl Future<Output = SourceExit>,
    mut uplink: Option<tokio::sync::mpsc::Receiver<MediaPacket>>,
    capture: Option<BackchannelCapture>,
) -> SourceExit {
    let mut live = std::pin::pin!(live);
    loop {
        tokio::select! {
            exit = &mut live => return exit,
            Some(packet) = next_uplink(&mut uplink) => {
                if let Some(capture) = &capture {
                    capture.push(packet);
                }
            }
        }
    }
}

/// The next packet a fake backchannel receives; never without one.
async fn next_uplink(
    uplink: &mut Option<tokio::sync::mpsc::Receiver<MediaPacket>>,
) -> Option<MediaPacket> {
    match uplink {
        Some(uplink) => uplink.recv().await,
        None => std::future::pending().await,
    }
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
            direction: Direction::Pull,
            backchannel: self.backchannel,
            keyframe_request: false,
            snapshot_uri: false,
        }
    }

    fn validate(
        &self,
        url: &SourceUrl,
        options: &serde_json::Value,
    ) -> Result<Box<dyn Source>, SourceConfigError> {
        let scheme = self.schemes.first().copied().unwrap_or("fake");
        let one = |key: &str| match options {
            serde_json::Value::Object(map) if map.len() == 1 => map.get(key),
            _ => None,
        };
        let audio_name = one("audio").and_then(serde_json::Value::as_str);
        let keyframes_every = one("keyframes_every_ms")
            .and_then(serde_json::Value::as_u64)
            .map(Duration::from_millis);
        let backchannel = one("backchannel")
            .and_then(serde_json::Value::as_str)
            .and_then(fake_backchannel);
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
            _ if backchannel.is_some() => (false, Duration::ZERO, FakeAudio::None),
            other => {
                return Err(SourceConfigError::InvalidOptions {
                    scheme,
                    message: format!(
                        "fake source takes no options but {{\"crash\": true}}, {{\"ready_after_ms\": n}}, {{\"keyframes_every_ms\": n}}, {{\"audio\": true | \"aac\" | \"aac_drifting\"}} or {{\"backchannel\": \"pcmu\" | \"pcma\" | \"opus\"}}, got {other}"
                    ),
                });
            }
        };
        Ok(Box::new(FakeSource {
            protocol: scheme,
            url: url.clone(),
            crash,
            abort: self.abort,
            ready_after,
            audio,
            keyframes_every,
            backchannel,
            capture: self.capture.clone(),
        }))
    }
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
    /// [`drifting_reports`].
    AacDrifting,
}

impl FakeAudio {
    /// The name in the connection options.
    const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pcmu => "pcmu",
            Self::Aac => "aac",
            Self::AacDrifting => "aac_drifting",
        }
    }
}

/// How often a drifting fake camera sends its Sender Reports.
const DRIFTING_REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// Reports the Sender Reports (RFC 3550 §6.4.1) a camera sends `elapsed`
/// after going live when its audio clock runs 2 % fast against its NTP
/// clock: video's claims the time that passed, audio's 2 % more. Its
/// mapping keeps falling behind beyond what a slew can follow, which the
/// skew watchdog cannot hold.
fn drifting_reports(
    clock: &crate::source::ClockInput,
    video: &Track,
    audio: &Track,
    elapsed: Duration,
    arrival: Instant,
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
    let fast = elapsed.saturating_add(elapsed.checked_div(50).unwrap_or_default());
    let _video_sent = clock.report(report(video, elapsed));
    let _audio_sent = clock.report(report(audio, fast));
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
/// the 64 ms grid from the moment it went live; drifting, it also sends
/// Sender Reports every second from a second after it went live, whose
/// audio clock runs 2 % fast. With a backchannel it offers one in the slot
/// before it goes live (20 ms frames), takes what arrives on it into its
/// capture, if any, and withdraws it when its run ends.
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
    /// The codec of the backchannel it offers, if any.
    backchannel: Option<Codec>,
    /// Where its backchannel puts what it receives.
    capture: Option<BackchannelCapture>,
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
        })
    }

    fn run(&self, mut ctx: SourceCtx) -> BoxFuture<'static, SourceExit> {
        let crash = self.crash;
        let abort = self.abort;
        let audio = self.audio;
        let keyframes_every = self.keyframes_every;
        // The channel lives as long as the run: a worker's sender fails
        // once the run is over, as a camera session's would.
        let (backchannel, uplink) = self
            .backchannel
            .clone()
            .map(fake_backchannel_handle)
            .unzip();
        let capture = self.capture.clone();
        let slot = ctx.backchannel.clone();
        let ready_after = ctx.time.sleep(self.ready_after);
        let live = async move {
            // The ingest contract holds while waiting to go live too: a
            // cancel ends the run at once, whether or not the clock moves.
            tokio::select! {
                () = ready_after => {}
                () = ctx.cancel.cancelled() => {
                    return SourceExit::Ended(SourceError::Ended("cancelled before live".into()));
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
            if let Some(handle) = backchannel {
                ctx.backchannel.offer(handle);
            }
            let (codec, clock_rate, step) = match audio {
                FakeAudio::None => {
                    ctx.tracks.ready();
                    if crash {
                        tracing::error!("fake source: crashing the process as requested");
                        abort();
                    }
                    return video_only(&ctx, &video, keyframes_every).await;
                }
                FakeAudio::Pcmu => (Codec::Pcmu, 8_000, Duration::from_millis(20)),
                FakeAudio::Aac | FakeAudio::AacDrifting => {
                    (fake_aac(), 16_000, Duration::from_millis(64))
                }
            };
            let track = ctx.tracks.declare(Kind::Audio, codec, clock_rate);
            ctx.tracks.ready();
            let start = ctx.time.now();
            let (mut index, mut seq) = (0_u32, 0_u16);
            // A camera's first report follows its first packets (RFC 3550
            // §6.2), so the tracks are announced before it maps them.
            let mut next_report = DRIFTING_REPORT_INTERVAL;
            loop {
                let now = ctx.time.now();
                let elapsed = now.saturating_duration_since(start);
                if audio == FakeAudio::AacDrifting && elapsed >= next_report {
                    drifting_reports(&ctx.clock, &video, &track, elapsed, now);
                    next_report = next_report.saturating_add(DRIFTING_REPORT_INTERVAL);
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
                        return SourceExit::Ended(SourceError::Ended("cancelled".into()));
                    }
                }
            }
        };
        Box::pin(async move {
            let exit = drain_while(live, uplink, capture).await;
            // Gone with the run, as a source's backchannel is for the
            // reconnect.
            slot.withdraw();
            exit
        })
    }
}

/// The run of a fake source without audio once it is live: until
/// cancelled, publishing a one-packet keyframe on `video` every `every`
/// if set, a video source a standby can switch in at.
async fn video_only(ctx: &SourceCtx, video: &Track, every: Option<Duration>) -> SourceExit {
    let Some(every) = every else {
        ctx.cancel.cancelled().await;
        return SourceExit::Ended(SourceError::Ended("cancelled".into()));
    };
    let mut seq = 0_u16;
    loop {
        video.publish_packet(keyframe_packet(ctx.time.now(), seq));
        seq = seq.wrapping_add(1);
        tokio::select! {
            () = ctx.time.sleep(every) => {}
            () = ctx.cancel.cancelled() => {
                return SourceExit::Ended(SourceError::Ended("cancelled".into()));
            }
        }
    }
}

/// A fake backchannel taking `codec` in 20 ms frames: the handle a fake
/// source offers, and the receiving end of its queue.
fn fake_backchannel_handle(
    codec: Codec,
) -> (BackchannelHandle, tokio::sync::mpsc::Receiver<MediaPacket>) {
    let (sender, uplink) = tokio::sync::mpsc::channel(8);
    let handle = BackchannelHandle {
        codec,
        frame: BackchannelHandle::DEFAULT_FRAME,
        sender,
    };
    (handle, uplink)
}

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
        payload: Arc::from(&[0x65_u8; 32][..]),
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

/// An output factory with a fixed kind and shape.
#[derive(Debug)]
pub struct FakeOutputFactory(pub &'static str, pub OutputShape);

impl OutputFactory for FakeOutputFactory {
    fn kind(&self) -> &'static str {
        self.0
    }

    fn shape(&self) -> OutputShape {
        self.1
    }
}

/// A `webrtc` session output whose engine echoes (see [`EchoEngine`]), so a
/// worker can run whole sessions without a WebRTC engine. It wants the
/// H.264 video track and Opus or PCMU audio, in that order, as the WebRTC
/// output does; an offer of `"refuse"` is refused as invalid SDP. The
/// answer is [`ECHO_ANSWER`], followed by ` audio=<codec>` with audio,
/// ` backchannel=<codec>` with a backchannel and ` orientation=<name>` for
/// a turned stream. Its engine reports talk-back negotiated in the
/// backchannel's codec when that is one a viewer can send.
#[derive(Debug)]
pub struct EchoSessionFactory;

/// The answer [`EchoSessionFactory`] gives.
pub const ECHO_ANSWER: &str = "v=0 echo";

impl OutputFactory for EchoSessionFactory {
    fn kind(&self) -> &'static str {
        "webrtc"
    }

    fn shape(&self) -> OutputShape {
        OutputShape::Session
    }

    fn session_tracks(&self, audio: bool) -> Vec<TrackRequest> {
        let mut requests = vec![TrackRequest {
            kind: Kind::Video,
            accept: vec![CodecFamily::H264],
            unit: Unit::Packets,
            required: true,
        }];
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
            .map(|backchannel| format!("backchannel={}", backchannel.name()));
        let orientation = (request.orientation != Orientation::NoTransform)
            .then(|| format!("orientation={}", request.orientation.name()));
        let answer = std::iter::once(ECHO_ANSWER.to_owned())
            .chain(audio)
            .chain(backchannel)
            .chain(orientation)
            .collect::<Vec<_>>()
            .join(" ");
        let talkback = request
            .backchannel
            .as_ref()
            .and_then(|codec| UplinkCodec::of(codec.family()));
        Ok((
            Box::new(EchoEngine::new(now).with_talkback(talkback)),
            answer,
        ))
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
    use crate::clock::{Clock as _, SystemClock};
    use crate::source::{BackchannelSlot, ClockInput, ResolvedPeer, TrackSet};
    use crate::track::{TrackId, TrackLimits};

    #[tokio::test]
    async fn fake_source_declares_a_video_track_and_ends_on_cancel() {
        let factory = FakeSourceFactory::new(&["fake"]);
        assert_eq!(factory.capabilities().direction, Direction::Pull);
        // The contract's defaults: no default port, no loopback relay.
        assert_eq!(factory.default_port("fake"), None);
        assert!(!factory.loopback_relay("fake"));
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = factory.validate(&url, &serde_json::Value::Null).unwrap();
        assert_eq!(source.describe().protocol, "fake");
        assert_eq!(source.describe().url, url);
        assert!(matches!(
            source.request_keyframe(),
            crate::source::KeyframeRequest::Unsupported
        ));

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
        assert!(matches!(
            run.await.unwrap(),
            SourceExit::Ended(SourceError::Ended(_))
        ));
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
        clock: Arc<dyn crate::clock::Clock>,
    ) -> (
        tokio::task::JoinHandle<SourceExit>,
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
        assert!(matches!(
            run.await.unwrap(),
            SourceExit::Ended(SourceError::Ended(_))
        ));
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
            // Offered before it went live, video only, and open.
            let handle = slot.current().expect("offered");
            assert_eq!(handle.codec, codec);
            assert_eq!(handle.frame, BackchannelHandle::DEFAULT_FRAME);
            assert_eq!(set.tracks().len(), 1);
            let before = capture.packets().len();
            for seq in 0..3 {
                assert!(
                    handle
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
            } else {
                // Taken off the channel all the same, so it never fills.
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(handle.sender.capacity(), 8);
                assert_eq!(capture.packets().len(), before, "nowhere to put them");
            }
            cancel.cancel();
            assert!(matches!(
                run.await.unwrap(),
                SourceExit::Ended(SourceError::Ended(_))
            ));
            assert!(slot.current().is_none(), "withdrawn with the run");
            assert!(handle.sender.is_closed());
        }
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
        assert!(matches!(
            within(run).await.unwrap(),
            SourceExit::Ended(SourceError::Ended(_))
        ));
        assert!(set.tracks().is_empty(), "cancelled before it declared any");
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
        assert!(matches!(
            run.await.unwrap(),
            SourceExit::Ended(SourceError::Ended(_))
        ));
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
        cancel.cancel();
        assert!(matches!(
            run.await.unwrap(),
            SourceExit::Ended(SourceError::Ended(_))
        ));
    }

    #[tokio::test]
    async fn fake_source_with_drifting_aac_reports_audio_running_2_percent_fast() {
        use crate::clock::FakeClock;
        use crate::source::{ClockReport, SyncHint};

        let factory = FakeSourceFactory::new(&["fake"]);
        let url = SourceUrl::parse("fake://cam/").unwrap();
        let source = factory
            .validate(&url, &serde_json::json!({"audio": "aac_drifting"}))
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
        let live = clock.now();
        let hint = |report: ClockReport| (report.track.to_string(), report.clock_rate, report.hint);
        let sr = |ntp, rtp_ts| SyncHint::RtcpSenderReport { ntp, rtp_ts };
        // None at once: the first pair once a second has passed, 1024 ms
        // on the frame grid.
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
        cancel.cancel();
        assert!(matches!(
            run.await.unwrap(),
            SourceExit::Ended(SourceError::Ended(_))
        ));
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
                message: "fake source takes no options but {\"crash\": true}, {\"ready_after_ms\": n}, {\"keyframes_every_ms\": n}, {\"audio\": true | \"aac\" | \"aac_drifting\"} or {\"backchannel\": \"pcmu\" | \"pcma\" | \"opus\"}, got {\"transport\":\"udp\"}"
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
        let defaults = serde_json::json!({"crash": false, "ready_after_ms": 0, "audio": "none", "keyframes_every_ms": null});
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
        ] {
            let mut expected = defaults.clone();
            expected[field] = value;
            assert_eq!(key(options), expected);
        }
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
        assert_eq!(
            FakeOutputFactory("snapshot", OutputShape::Request).kind(),
            "snapshot"
        );
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
            offer: "v=0".into(),
            ice: crate::session::IceCredentials {
                ufrag: "u".into(),
                pass: "p".into(),
            },
            candidates: vec![],
            tcp_candidates: vec![],
            video: Arc::new(Codec::Pcmu),
            audio: Some(Arc::new(Codec::Pcmu)),
            backchannel: Some(Codec::Pcma),
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
        let without = SessionRequest {
            backchannel: None,
            ..turned
        };
        let (engine, _answer) = EchoSessionFactory.open_session(without, now).unwrap();
        assert_eq!(engine.talkback(), None);
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
            video: Arc::new(Codec::Pcmu),
            audio: None,
            backchannel: None,
            orientation: Orientation::default(),
            limits: crate::session::SessionLimits::default(),
            wall: std::time::SystemTime::UNIX_EPOCH,
        };
        let factory = EchoSessionFactory;
        assert_eq!(
            (factory.kind(), factory.shape()),
            ("webrtc", OutputShape::Session)
        );
        let tracks = factory.session_tracks(true);
        assert_eq!(tracks.len(), 2);
        assert!(tracks[0].required && tracks[0].accept == [CodecFamily::H264]);
        assert!(!tracks[1].required && tracks[1].accept == [CodecFamily::Opus, CodecFamily::Pcmu]);
        assert_eq!(factory.session_tracks(false).len(), 1, "video-first");
        assert!(matches!(
            factory.open_session(request("refuse"), now),
            Err(SessionOpenError::InvalidSdp(_))
        ));
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
        use crate::clock::{Clock as _, SystemClock};

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
                })
            );
        }
        assert_eq!(engine.stats().uplink_packets, 2);
    }
}
