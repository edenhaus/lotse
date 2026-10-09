//! The camera of the browser and interop tests, made of third-party tools:
//! ffmpeg encodes a synthetic stream from `lavfi` sources and publishes it
//! over RTSP to MediaMTX, which serves it to the daemon over RTSP with RTP
//! interleaved on TCP or as UDP datagrams.
//!
//! The stream is not ours, so a test against it does not repeat our own
//! reading of RFC 2326, RFC 6184, RFC 3640, RFC 7587 or G.711. ffmpeg
//! cannot serve RTSP to a client itself (its RTSP muxer only publishes,
//! `ANNOUNCE` and `RECORD`, and `-rtsp_flags listen` receives), hence
//! MediaMTX in between.
//!
//! The picture is black, 640×480 at 30 fps, white for the first 100 ms (3
//! frames) of every second, with a keyframe forced on each flash and a
//! group of pictures of one second; the sound, when there is any, is a
//! 1 kHz sine at -12 dBFS over the same 100 ms, on the same `lavfi` clock:
//! the A/V sync marks the browser test's page measures.
//!
//! [`Camera::start`] runs `mediamtx` with the committed
//! `crates/lotse-testing/mediamtx.yml` on free loopback ports and
//! `ffmpeg` with [`ffmpeg_args`], both from `PATH` (`mise.toml` pins
//! them), waits until MediaMTX's API reports the path ready with every
//! track, and stops both when dropped; [`Camera::restart_publisher`]
//! restarts ffmpeg, a camera that reboots.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::AsFd as _;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::Clock;
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// The MediaMTX configuration, committed beside the crate's manifest.
pub const CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/mediamtx.yml");

/// The path ffmpeg publishes to and the daemon reads.
pub const PATH: &str = "cam";

/// The picture's width.
pub const WIDTH: u32 = 640;
/// The picture's height.
pub const HEIGHT: u32 = 480;
/// Frames per second; also the frames of a group of pictures (one second).
pub const FPS: u32 = 30;
/// Frames a flash lasts: 100 ms at [`FPS`].
pub const FLASH_FRAMES: u32 = 3;
/// The beep's frequency, Hz.
pub const BEEP_HZ: u32 = 1_000;
/// Audio frames a second the sine is generated in (20 ms each), so the
/// gate opens and closes on frame boundaries.
pub const AUDIO_FRAMES_PER_SECOND: u32 = 50;
/// Audio frames a beep lasts: 100 ms.
pub const BEEP_FRAMES: u32 = 5;

/// How long [`Camera::start`] waits for the path to be ready.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// How often it asks.
const POLL: Duration = Duration::from_millis(100);

/// The largest API answer read.
const MAX_ANSWER: u64 = 1 << 20;

/// The audio track ffmpeg publishes beside the video.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audio {
    /// Video only.
    None,
    /// AAC-LC from ffmpeg's native encoder, 16 kHz mono, as RFC 3640
    /// `MPEG4-GENERIC` (`AAC-hbr`).
    Aac,
    /// G.711 µ-law, 8 kHz mono, payload type 0 (RFC 3551 §4.5.14).
    Pcmu,
    /// Opus from libopus, 48 kHz mono, 20 ms frames (RFC 7587).
    Opus,
}

impl Audio {
    /// Every variant, video-only first.
    pub const ALL: [Self; 4] = [Self::None, Self::Aac, Self::Pcmu, Self::Opus];

    /// The variant named `name`: `none`, `aac`, `pcmu` or `opus`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|audio| audio.name() == name)
    }

    /// The variant's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aac => "aac",
            Self::Pcmu => "pcmu",
            Self::Opus => "opus",
        }
    }

    /// The sample rate the sine is generated and encoded at.
    pub const fn sample_rate(self) -> Option<u32> {
        match self {
            Self::None => None,
            Self::Aac => Some(16_000),
            Self::Pcmu => Some(8_000),
            Self::Opus => Some(48_000),
        }
    }

    /// The encoder's arguments.
    fn encoder(self) -> &'static [&'static str] {
        match self {
            Self::None => &[],
            // One access unit per RTP packet, as cameras send AAC: ffmpeg's
            // command line holds up to 0.7 s for a packet otherwise
            // (`-muxdelay`, ffmpeg-formats "Format Options" `max_delay`),
            // which its RTP muxer fills with up to ten AAC frames
            // (libavformat `rtpenc_aac.c`), 640 ms of audio at 16 kHz.
            Self::Aac => &["-c:a", "aac", "-b:a", "32k", "-ac", "1", "-muxdelay", "0"],
            Self::Pcmu => &["-c:a", "pcm_mulaw", "-ac", "1"],
            Self::Opus => &[
                "-c:a",
                "libopus",
                "-b:a",
                "32k",
                "-ac",
                "1",
                "-frame_duration",
                "20",
                "-application",
                "lowdelay",
            ],
        }
    }

    /// The codec MediaMTX's API names the track (`tracks2[].codec`).
    pub const fn mediamtx_codec(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Aac => Some("MPEG-4 Audio"),
            Self::Pcmu => Some("G711"),
            Self::Opus => Some("Opus"),
        }
    }

    /// The codec the daemon reports for the native track in `stream/get`.
    pub const fn lotse_codec(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Aac => Some("aac_lc"),
            Self::Pcmu => Some("pcmu"),
            Self::Opus => Some("opus"),
        }
    }

    /// Tracks the path has: the video and this audio.
    pub const fn tracks(self) -> usize {
        match self {
            Self::None => 1,
            Self::Aac | Self::Pcmu | Self::Opus => 2,
        }
    }
}

/// The `lavfi` filter graph: the flashing picture as `[out0]` and, with a
/// sample rate, the gated sine as `[out1]`. Frame counts, not times, gate
/// both, so no rounding moves an edge: video frames `n` with
/// `n mod 30 < 3`, audio frames of 20 ms with `n mod 50 < 5`. The sine
/// filter's amplitude is 1/8; the gate doubles it to 1/4 (-12 dBFS).
pub fn filter_graph(sample_rate: Option<u32>) -> String {
    let video = format!(
        "color=c=black:s={WIDTH}x{HEIGHT}:r={FPS},format=yuv420p,\
         drawbox=c=white:t=fill:enable='lt(mod(n,{FPS}),{FLASH_FRAMES})'[out0]"
    );
    match sample_rate {
        None => video,
        Some(rate) => {
            let per_frame = rate.checked_div(AUDIO_FRAMES_PER_SECOND).unwrap_or(rate);
            format!(
                "{video};sine=f={BEEP_HZ}:r={rate}:samples_per_frame={per_frame},\
                 volume=volume='2*lt(mod(n,{AUDIO_FRAMES_PER_SECOND}),{BEEP_FRAMES})':eval=frame[out1]"
            )
        }
    }
}

/// ffmpeg's arguments: read the graph in real time (`-re`), encode the
/// video with libx264 for low latency (`ultrafast`, `zerolatency`: no
/// B-frames, no lookahead), Baseline, a keyframe forced on every flash
/// and none between, the audio with [`Audio`]'s encoder, and publish to
/// `url` over RTSP with RTP interleaved on TCP.
pub fn ffmpeg_args(audio: Audio, url: &str) -> Vec<String> {
    let gop = FPS.to_string();
    let mut args: Vec<String> = [
        "-hide_banner",
        "-loglevel",
        "warning",
        "-nostdin",
        "-re",
        "-f",
        "lavfi",
        "-i",
    ]
    .map(str::to_owned)
    .to_vec();
    args.push(filter_graph(audio.sample_rate()));
    args.extend(
        [
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-tune",
            "zerolatency",
            "-profile:v",
            "baseline",
            "-g",
            &gop,
            "-keyint_min",
            &gop,
            "-sc_threshold",
            "0",
        ]
        .map(str::to_owned),
    );
    args.push("-force_key_frames".to_owned());
    args.push(format!("expr:eq(mod(n,{FPS}),0)"));
    args.extend(audio.encoder().iter().map(|arg| (*arg).to_owned()));
    args.extend(["-f", "rtsp", "-rtsp_transport", "tcp", url].map(str::to_owned));
    args
}

/// The addresses MediaMTX listens on, all on loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    /// RTSP over TCP.
    pub rtsp: u16,
    /// The server's RTP port for UDP; RTCP is the next one (RFC 3550
    /// §11: RTP on an even port, RTCP on the odd one above).
    pub rtp: u16,
    /// The HTTP API.
    pub api: u16,
}

impl Ports {
    /// Free ports, found by binding port 0 and letting go; another process
    /// could take one in between, which a test would see as a failed start.
    pub fn free() -> io::Result<Self> {
        Ok(Self {
            rtsp: free_tcp_port()?,
            rtp: free_udp_pair()?,
            api: free_tcp_port()?,
        })
    }

    /// MediaMTX's variables for them, which override its configuration
    /// file's keys of the same name.
    pub fn env(self) -> Vec<(&'static str, String)> {
        let at = |port: u16| format!("127.0.0.1:{port}");
        vec![
            ("MTX_RTSPADDRESS", at(self.rtsp)),
            ("MTX_RTPADDRESS", at(self.rtp)),
            ("MTX_RTCPADDRESS", at(self.rtp.saturating_add(1))),
            ("MTX_APIADDRESS", at(self.api)),
        ]
    }
}

/// A TCP port nothing listens on just now.
fn free_tcp_port() -> io::Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port())
}

/// An even UDP port whose odd neighbour is free too.
fn free_udp_pair() -> io::Result<u16> {
    for _ in 0..64 {
        let rtp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = rtp.local_addr()?.port();
        let Some(next) = port.checked_add(1) else {
            continue;
        };
        if port.is_multiple_of(2) && UdpSocket::bind((Ipv4Addr::LOCALHOST, next)).is_ok() {
            return Ok(port);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no free even/odd UDP port pair",
    ))
}

/// A command for `program`, its output on this process's stderr.
#[expect(
    clippy::disallowed_methods,
    reason = "a test camera outside the daemon: the tests start MediaMTX and ffmpeg, never the daemon's code"
)]
fn command(program: &str) -> io::Result<Command> {
    let mut command = Command::new(program);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(io::stderr().as_fd().try_clone_to_owned()?))
        .stderr(Stdio::from(io::stderr().as_fd().try_clone_to_owned()?));
    Ok(command)
}

/// Starts `command`, saying what is missing when its program is.
fn spawn(mut command: Command) -> Result<Child, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    command.spawn().map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            format!(
                "{program} is not on PATH: `mise install`, then run through mise (mise run interop)"
            )
        } else {
            format!("{program}: {err}")
        }
    })
}

/// A running camera: MediaMTX with ffmpeg publishing to it. Dropping it
/// stops both.
#[derive(Debug)]
pub struct Camera {
    /// MediaMTX.
    mediamtx: Child,
    /// ffmpeg, once started.
    ffmpeg: Option<Child>,
    /// Where it listens.
    ports: Ports,
    /// What ffmpeg publishes.
    audio: Audio,
}

impl Camera {
    /// Starts MediaMTX and ffmpeg with `audio`, and waits until the path
    /// is ready with all its tracks.
    pub async fn start(audio: Audio, clock: Arc<dyn Clock>) -> Result<Self, String> {
        let ports = Ports::free().map_err(|err| format!("free ports: {err}"))?;
        let mut mediamtx = command("mediamtx").map_err(|err| format!("mediamtx: {err}"))?;
        mediamtx.arg(CONFIG).envs(ports.env());
        let mut camera = Self {
            mediamtx: spawn(mediamtx)?,
            ffmpeg: None,
            ports,
            audio,
        };
        camera.wait_api(&*clock).await?;
        camera.publish(&*clock).await?;
        Ok(camera)
    }

    /// Starts ffmpeg publishing and waits until the path is ready.
    async fn publish(&mut self, clock: &dyn Clock) -> Result<(), String> {
        let mut ffmpeg = command("ffmpeg").map_err(|err| format!("ffmpeg: {err}"))?;
        ffmpeg.args(ffmpeg_args(self.audio, &self.url()));
        self.ffmpeg = Some(spawn(ffmpeg)?);
        self.wait_ready(clock).await
    }

    /// Restarts the publisher, as a camera that reboots: kills ffmpeg,
    /// waits until MediaMTX has dropped the path (which closes its
    /// readers, so the daemon reconnects), starts a new ffmpeg with new
    /// RTP timestamps and Sender Reports, and waits until the path is
    /// ready again.
    pub async fn restart_publisher(&mut self, clock: Arc<dyn Clock>) -> Result<(), String> {
        let mut ffmpeg = self.ffmpeg.take().ok_or("ffmpeg is not running")?;
        // Gone already is as good as stopped.
        let _killed = ffmpeg.kill();
        ffmpeg.wait().map_err(|err| format!("ffmpeg: {err}"))?;
        self.wait_gone(&*clock).await?;
        self.publish(&*clock).await
    }

    /// Waits until the path is no longer ready: nobody publishes.
    async fn wait_gone(&mut self, clock: &dyn Clock) -> Result<(), String> {
        let deadline = clock.now().checked_add(READY_TIMEOUT);
        loop {
            self.check_running()?;
            match self.path().await? {
                Some(path) if path.get("ready").and_then(Value::as_bool) == Some(true) => {}
                _ => return Ok(()),
            }
            if deadline.is_some_and(|at| clock.now() >= at) {
                return Err(format!(
                    "the path still ready {READY_TIMEOUT:?} after ffmpeg stopped"
                ));
            }
            clock.sleep(POLL).await;
        }
    }

    /// The URL ffmpeg publishes to and the daemon reads.
    pub fn url(&self) -> String {
        format!("rtsp://127.0.0.1:{}/{PATH}", self.ports.rtsp)
    }

    /// Where it listens.
    pub fn ports(&self) -> Ports {
        self.ports
    }

    /// What ffmpeg publishes.
    pub fn audio(&self) -> Audio {
        self.audio
    }

    /// The API's view of the path (`GET /v3/paths/get/cam`): its tracks,
    /// readers and byte counts; `None` while nobody publishes.
    pub async fn path(&self) -> Result<Option<Value>, String> {
        self.api(&format!("/v3/paths/get/{PATH}")).await
    }

    /// `GET` of the API's `endpoint` (`/v3/rtspsessions/list`) as JSON;
    /// `None` on 404.
    pub async fn api(&self, endpoint: &str) -> Result<Option<Value>, String> {
        let api = SocketAddr::from((Ipv4Addr::LOCALHOST, self.ports.api));
        let (status, body) = get(api, endpoint).await?;
        match status {
            200 => serde_json::from_str(&body)
                .map(Some)
                .map_err(|err| format!("{endpoint}: {err}: {body}")),
            404 => Ok(None),
            _ => Err(format!("{endpoint}: HTTP {status}: {body}")),
        }
    }

    /// Fails when a process has exited.
    fn check_running(&mut self) -> Result<(), String> {
        let exited = |name: &str, child: &mut Child| match child.try_wait() {
            Ok(Some(status)) => Err(format!("{name} exited: {status}")),
            Ok(None) => Ok(()),
            Err(err) => Err(format!("{name}: {err}")),
        };
        exited("mediamtx", &mut self.mediamtx)?;
        if let Some(ffmpeg) = self.ffmpeg.as_mut() {
            exited("ffmpeg", ffmpeg)?;
        }
        Ok(())
    }

    /// Waits until the API answers.
    async fn wait_api(&mut self, clock: &dyn Clock) -> Result<(), String> {
        let deadline = clock.now().checked_add(READY_TIMEOUT);
        loop {
            self.check_running()?;
            match self.path().await {
                Ok(_) => return Ok(()),
                Err(err) if deadline.is_some_and(|at| clock.now() >= at) => {
                    return Err(format!("mediamtx's API: {err}"));
                }
                Err(_) => clock.sleep(POLL).await,
            }
        }
    }

    /// Waits until the path is ready with every track.
    async fn wait_ready(&mut self, clock: &dyn Clock) -> Result<(), String> {
        let deadline = clock.now().checked_add(READY_TIMEOUT);
        let mut last = None;
        loop {
            self.check_running()?;
            let path = self.path().await?;
            if let Some(path) = &path
                && ready_with(path, self.audio)
            {
                return Ok(());
            }
            last = path.or(last);
            if deadline.is_some_and(|at| clock.now() >= at) {
                return Err(format!(
                    "the path not ready with {} track(s) in {READY_TIMEOUT:?}: {last:?}",
                    self.audio.tracks()
                ));
            }
            clock.sleep(POLL).await;
        }
    }

    /// Stops ffmpeg (`SIGSTOP`) without closing its connection: MediaMTX
    /// keeps the path and its description, but sends readers no media.
    pub fn pause(&self) -> Result<(), String> {
        self.signal("-STOP")
    }

    /// Lets a paused ffmpeg go on (`SIGCONT`).
    pub fn resume(&self) -> Result<(), String> {
        self.signal("-CONT")
    }

    /// Sends ffmpeg `signal` with `kill(1)`.
    fn signal(&self, signal: &str) -> Result<(), String> {
        let pid = self
            .ffmpeg
            .as_ref()
            .map(Child::id)
            .ok_or("ffmpeg is not running")?;
        let mut kill = command("kill").map_err(|err| format!("kill: {err}"))?;
        kill.args([signal, &pid.to_string()]);
        let status = spawn(kill)?
            .wait()
            .map_err(|err| format!("kill {signal}: {err}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("kill {signal} {pid}: {status}"))
        }
    }

    /// Stops both processes.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        for child in self
            .ffmpeg
            .iter_mut()
            .chain(std::iter::once(&mut self.mediamtx))
        {
            // Gone already is as good as stopped.
            let _killed = child.kill();
            let _reaped = child.wait();
        }
    }
}

/// Whether the API's `path` is ready with H.264 and `audio`'s track.
pub fn ready_with(path: &Value, audio: Audio) -> bool {
    let codecs: Vec<&str> = path
        .get("tracks2")
        .and_then(Value::as_array)
        .map(|tracks| {
            tracks
                .iter()
                .filter_map(|track| track.get("codec").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let wanted: Vec<&str> = std::iter::once("H264")
        .chain(audio.mediamtx_codec())
        .collect();
    path.get("ready").and_then(Value::as_bool) == Some(true) && codecs == wanted
}

/// `GET path` over HTTP/1.0 (RFC 1945 §5, §6): the status and the body,
/// which ends with the connection.
async fn get(addr: SocketAddr, path: &str) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("{addr}: {err}"))?;
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .map_err(|err| format!("{addr}: {err}"))?;
    let mut raw = Vec::new();
    stream
        .take(MAX_ANSWER)
        .read_to_end(&mut raw)
        .await
        .map_err(|err| format!("{addr}: {err}"))?;
    parse_answer(&raw)
}

/// Splits an HTTP/1.0 response into its status code and body.
fn parse_answer(raw: &[u8]) -> Result<(u16, String), String> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("no end of the header: {text}"))?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("no status: {head}"))?;
    Ok((status, body.to_owned()))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use serde_json::json;
    use tokio::net::TcpListener as AsyncListener;

    use super::*;

    #[test]
    fn variants_have_names_rates_and_codecs() {
        for audio in Audio::ALL {
            assert_eq!(Audio::parse(audio.name()), Some(audio));
        }
        assert_eq!(Audio::parse("mp3"), None);
        assert_eq!(Audio::None.sample_rate(), None);
        assert_eq!(Audio::Pcmu.sample_rate(), Some(8_000));
        assert_eq!(Audio::Aac.lotse_codec(), Some("aac_lc"));
        assert_eq!(Audio::Opus.mediamtx_codec(), Some("Opus"));
        assert_eq!((Audio::None.tracks(), Audio::Pcmu.tracks()), (1, 2));
        assert_eq!(Audio::None.lotse_codec(), None);
    }

    #[test]
    fn the_graph_gates_flash_and_beep_on_frame_counts() {
        assert_eq!(
            filter_graph(None),
            "color=c=black:s=640x480:r=30,format=yuv420p,\
             drawbox=c=white:t=fill:enable='lt(mod(n,30),3)'[out0]"
        );
        let with_audio = filter_graph(Some(48_000));
        assert!(
            with_audio.ends_with(
                ";sine=f=1000:r=48000:samples_per_frame=960,\
                 volume=volume='2*lt(mod(n,50),5)':eval=frame[out1]"
            ),
            "{with_audio}"
        );
        assert!(filter_graph(Some(8_000)).contains("samples_per_frame=160"));
    }

    #[test]
    fn ffmpeg_publishes_x264_with_a_keyframe_on_each_flash_and_the_audio_encoder() {
        let args = ffmpeg_args(Audio::Pcmu, "rtsp://127.0.0.1:1/cam");
        let line = args.join(" ");
        assert!(line.starts_with("-hide_banner -loglevel warning -nostdin -re -f lavfi -i color="));
        assert!(line.contains(
            "-c:v libx264 -preset ultrafast -tune zerolatency -profile:v baseline -g 30 -keyint_min 30 -sc_threshold 0 -force_key_frames expr:eq(mod(n,30),0) -c:a pcm_mulaw -ac 1"
        ), "{line}");
        assert!(line.ends_with("-f rtsp -rtsp_transport tcp rtsp://127.0.0.1:1/cam"));
        let video_only = ffmpeg_args(Audio::None, "rtsp://x/cam").join(" ");
        assert!(!video_only.contains("-c:a") && !video_only.contains("sine="));
        assert!(
            ffmpeg_args(Audio::Aac, "u")
                .join(" ")
                .contains("-c:a aac -b:a 32k -ac 1 -muxdelay 0 -f rtsp")
        );
        assert!(
            ffmpeg_args(Audio::Opus, "u")
                .join(" ")
                .contains("-c:a libopus -b:a 32k -ac 1 -frame_duration 20")
        );
    }

    #[test]
    fn free_ports_are_on_loopback_with_rtp_even() {
        let ports = Ports::free().unwrap();
        assert_eq!(ports.rtp % 2, 0);
        let env = ports.env();
        assert_eq!(
            env[0],
            ("MTX_RTSPADDRESS", format!("127.0.0.1:{}", ports.rtsp))
        );
        assert_eq!(
            env[2],
            ("MTX_RTCPADDRESS", format!("127.0.0.1:{}", ports.rtp + 1))
        );
        assert_eq!(env[3].0, "MTX_APIADDRESS");
    }

    #[test]
    fn a_path_is_ready_with_exactly_its_tracks() {
        let path = json!({ "ready": true, "tracks2": [{ "codec": "H264" }, { "codec": "G711" }] });
        assert!(ready_with(&path, Audio::Pcmu));
        assert!(!ready_with(&path, Audio::Opus));
        assert!(!ready_with(&path, Audio::None));
        let mut waiting = path;
        waiting["ready"] = json!(false);
        assert!(!ready_with(&waiting, Audio::Pcmu));
        assert!(!ready_with(&json!({}), Audio::None));
    }

    #[test]
    fn answers_split_into_status_and_body() {
        assert_eq!(
            parse_answer(b"HTTP/1.0 404 Not Found\r\nA: b\r\n\r\n{\"error\":1}").unwrap(),
            (404, "{\"error\":1}".to_owned())
        );
        assert!(parse_answer(b"HTTP/1.0 200").is_err());
        assert!(parse_answer(b"garbage\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn the_path_is_read_from_the_api() {
        let listener = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let api = listener.local_addr().unwrap().port();
        let serve = async move {
            for answer in [
                "HTTP/1.0 200 OK\r\n\r\n{\"ready\":true}",
                "HTTP/1.0 404 Not Found\r\n\r\n{}",
                "HTTP/1.0 500 Oops\r\n\r\nbroken",
                "HTTP/1.0 200 OK\r\n\r\nnot json",
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0_u8; 1024];
                let n = stream.read(&mut request).await.unwrap();
                assert!(request[..n].starts_with(b"GET /v3/paths/get/cam HTTP/1.0\r\n"));
                stream.write_all(answer.as_bytes()).await.unwrap();
            }
        };
        let client = async {
            let camera = Camera {
                mediamtx: spawn(command("true").unwrap()).unwrap(),
                ffmpeg: None,
                ports: Ports {
                    rtsp: 1,
                    rtp: 2,
                    api,
                },
                audio: Audio::None,
            };
            assert_eq!(camera.url(), "rtsp://127.0.0.1:1/cam");
            assert_eq!(camera.path().await.unwrap(), Some(json!({ "ready": true })));
            assert_eq!(camera.path().await.unwrap(), None);
            assert!(camera.path().await.unwrap_err().contains("HTTP 500"));
            assert!(camera.path().await.unwrap_err().contains("not json"));
            camera.stop();
        };
        tokio::join!(serve, client);
    }

    #[tokio::test]
    async fn a_restart_waits_until_the_path_is_gone() {
        let listener = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let api = listener.local_addr().unwrap().port();
        let serve = async move {
            for answer in [
                "HTTP/1.0 200 OK\r\n\r\n{\"ready\":true}",
                "HTTP/1.0 200 OK\r\n\r\n{\"ready\":false}",
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0_u8; 1024];
                let _read = stream.read(&mut request).await.unwrap();
                stream.write_all(answer.as_bytes()).await.unwrap();
            }
        };
        let client = async {
            let mut sleep = command("sleep").unwrap();
            sleep.arg("5");
            let mut camera = Camera {
                mediamtx: spawn(sleep).unwrap(),
                ffmpeg: None,
                ports: Ports {
                    rtsp: 1,
                    rtp: 2,
                    api,
                },
                audio: Audio::Pcmu,
            };
            let clock: Arc<dyn Clock> = Arc::new(lotse_core::clock::SystemClock);
            let err = camera
                .restart_publisher(Arc::clone(&clock))
                .await
                .unwrap_err();
            assert!(err.contains("ffmpeg is not running"), "{err}");
            // Ready once, then not: gone.
            camera.wait_gone(&*clock).await.unwrap();
            camera.stop();
        };
        tokio::join!(serve, client);
    }

    #[tokio::test]
    async fn a_missing_program_or_an_exited_one_fails_the_start() {
        let err = spawn(command("lotse-no-such-program").unwrap()).unwrap_err();
        assert!(err.contains("not on PATH"), "{err}");
        let mut camera = Camera {
            mediamtx: spawn(command("true").unwrap()).unwrap(),
            ffmpeg: None,
            ports: Ports::free().unwrap(),
            audio: Audio::Pcmu,
        };
        // Nothing answers on the API's port, and the process is gone soon.
        let err = camera
            .wait_api(&lotse_core::clock::SystemClock)
            .await
            .unwrap_err();
        assert!(err.contains("mediamtx exited"), "{err}");
    }
}
