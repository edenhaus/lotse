//! The browser test's Rust half: the camera and the page a real browser
//! plays, for the Selenium test in `tests/browser/` that drives the browser
//! and decides.
//!
//! The camera is ffmpeg publishing to MediaMTX ([`crate::mediamtx`]),
//! third-party tools, so the stream is not our own reading of the specs:
//! H.264 from libx264, black with a white flash and a keyframe every
//! second, and PCMU (or AAC, which the daemon transcodes to Opus) with a
//! beep on the same capture clock. A camera URL given instead plays that
//! camera, a real one say. The dev viewer serves
//! [`PAGE`] at [`PAGE_PATH`] and relays its WebSocket to the daemon's
//! control socket; the page signals, plays and measures what the browser
//! shows and plays, and returns it to the test as JSON.
//!
//! [`Served::start`] starts both and [`Ready`] is what the test reads
//! from the `lotse-browser` example: the page's URL, the camera's, and
//! the stream the camera sends, from [`crate::mediamtx`]'s constants, so
//! the test's expectations have one source. The daemon is started by the
//! test, the browser by Selenium.

pub mod args;

use std::path::PathBuf;
use std::sync::Arc;

use lotse_core::clock::Clock;
use lotse_core::task::spawn_named;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::dev_viewer;
use crate::mediamtx::{
    self, AUDIO_FRAMES_PER_SECOND, Audio, BEEP_FRAMES, BEEP_HZ, FLASH_FRAMES, FPS, HEIGHT, WIDTH,
};

/// The test page, served by the dev viewer at [`PAGE_PATH`].
pub const PAGE: &str = include_str!("page.html");

/// Where the dev viewer serves [`PAGE`].
pub const PAGE_PATH: &str = "/test";

/// The stream the synthetic camera sends, which the test's checks expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Stream {
    /// Picture width, pixels.
    pub width: u32,
    /// Picture height, pixels.
    pub height: u32,
    /// Frames a second.
    pub fps: u32,
    /// The first frames of each second that are white; the first is a
    /// keyframe.
    pub flash_frames: u32,
    /// The audio codec's name in SDP (`PCMU`, `MPEG4-GENERIC`).
    pub audio_codec: &'static str,
    /// Audio packets a second (20 ms each).
    pub audio_packets_per_second: u32,
    /// The beep's frequency, Hz.
    pub beep_hz: u32,
    /// The packets of each second that carry the beep (100 ms).
    pub beep_packets: u32,
    /// The beep's peak amplitude in thousandths of full scale (-12 dBFS).
    pub beep_peak_milli: u32,
}

/// The synthetic camera's stream with PCMU ([`mediamtx::filter_graph`]).
pub const STREAM: Stream = Stream {
    width: WIDTH,
    height: HEIGHT,
    fps: FPS,
    flash_frames: FLASH_FRAMES,
    audio_codec: "PCMU",
    audio_packets_per_second: AUDIO_FRAMES_PER_SECOND,
    beep_hz: BEEP_HZ,
    beep_packets: BEEP_FRAMES,
    beep_peak_milli: 250,
};

/// The synthetic camera's stream with `audio`: [`STREAM`] with the
/// audio codec's SDP name (RFC 3551 §6 `PCMU`, RFC 3640 §4.1
/// `MPEG4-GENERIC`, RFC 7587 §7 `opus`). The browser receives 50 audio
/// packets a second either way: PCMU as the camera sends it, AAC as the
/// transcoder's 20 ms Opus frames, Opus in ffmpeg's 20 ms frames.
pub const fn stream(audio: Audio) -> Stream {
    let audio_codec = match audio {
        Audio::None => "none",
        Audio::Pcmu => STREAM.audio_codec,
        Audio::Aac => "MPEG4-GENERIC",
        Audio::Opus => "opus",
    };
    Stream {
        audio_codec,
        ..STREAM
    }
}

/// What `lotse-browser` prints as one JSON line once it serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ready {
    /// The test page's URL.
    pub page: String,
    /// The camera's RTSP URL, which the page puts as the stream's source.
    pub camera: String,
    /// What the synthetic camera sends.
    pub stream: Stream,
}

/// What the test needs running besides the daemon and the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeConfig {
    /// The daemon's control socket, which the dev viewer relays to.
    pub socket: PathBuf,
    /// The camera to play; without one, MediaMTX and ffmpeg are started
    /// ([`mediamtx::Camera`]).
    pub camera: Option<String>,
    /// The synthetic camera's audio.
    pub audio: Audio,
}

/// The camera and the dev viewer, running until [`Served::stop`] or drop.
#[derive(Debug)]
pub struct Served {
    /// The synthetic camera, when one was started.
    camera: Option<mediamtx::Camera>,
    /// Ends the dev viewer.
    cancel: CancellationToken,
    /// What the test reads.
    ready: Ready,
}

impl Served {
    /// Starts the camera (unless `config.camera` names one) and the dev
    /// viewer on a free loopback port.
    pub async fn start(config: &ServeConfig, clock: Arc<dyn Clock>) -> Result<Self, String> {
        let (camera, url) = if let Some(url) = &config.camera {
            (None, url.clone())
        } else {
            let camera = mediamtx::Camera::start(config.audio, clock)
                .await
                .map_err(|err| format!("the camera: {err}"))?;
            let url = camera.url();
            (Some(camera), url)
        };
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|err| format!("the dev viewer: {err}"))?;
        let addr = listener
            .local_addr()
            .map_err(|err| format!("the dev viewer: {err}"))?;
        let cancel = CancellationToken::new();
        spawn_named(
            "browser.dev_viewer",
            dev_viewer::serve(listener, config.socket.clone(), cancel.clone()),
        );
        Ok(Self {
            camera,
            cancel,
            ready: Ready {
                page: format!("http://{addr}{PAGE_PATH}"),
                camera: url,
                stream: stream(config.audio),
            },
        })
    }

    /// Runs one command line from the test, as `lotse-browser` reads them
    /// on stdin, and returns the answer as one JSON value:
    /// `restart-camera` ([`Served::restart_camera`]) answers
    /// `{"restarted": true}`; a failure or an unknown command answers
    /// `{"error": "..."}`.
    pub async fn command(&mut self, line: &str, clock: Arc<dyn Clock>) -> serde_json::Value {
        let outcome = match line.trim() {
            "restart-camera" => self
                .restart_camera(clock)
                .await
                .map(|()| serde_json::json!({ "restarted": true })),
            other => Err(format!("unknown command {other:?}: restart-camera")),
        };
        outcome.unwrap_or_else(|err| serde_json::json!({ "error": err }))
    }

    /// Restarts the synthetic camera's publisher
    /// ([`mediamtx::Camera::restart_publisher`]): the daemon sees the
    /// camera hang up and come back with a new timeline.
    pub async fn restart_camera(&mut self, clock: Arc<dyn Clock>) -> Result<(), String> {
        self.camera
            .as_mut()
            .ok_or("no synthetic camera to restart: --camera names one")?
            .restart_publisher(clock)
            .await
    }

    /// What the test reads.
    pub fn ready(&self) -> &Ready {
        &self.ready
    }

    /// Stops the dev viewer and the camera.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.cancel.cancel();
        // Dropping the camera stops MediaMTX and ffmpeg.
        drop(self.camera.take());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    use super::*;

    #[test]
    fn the_stream_is_the_synthetic_cameras() {
        let json = serde_json::to_value(STREAM).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "width": 640, "height": 480, "fps": 30, "flash_frames": 3,
                "audio_codec": "PCMU", "audio_packets_per_second": 50,
                "beep_hz": 1000, "beep_packets": 5, "beep_peak_milli": 250,
            })
        );
        assert_eq!(stream(Audio::Pcmu), STREAM);
        assert_eq!(stream(Audio::Aac).audio_codec, "MPEG4-GENERIC");
        assert_eq!(stream(Audio::Opus).audio_codec, "opus");
        assert_eq!(stream(Audio::None).audio_codec, "none");
        assert_eq!(stream(Audio::Aac).audio_packets_per_second, 50);
        // The beep's peak is the filter graph's: a sine of 1/8 doubled.
        assert!(mediamtx::filter_graph(Some(8_000)).contains("volume=volume='2*"));
    }

    #[tokio::test]
    async fn a_given_camera_is_served_with_the_page() {
        let served = Served::start(
            &ServeConfig {
                socket: PathBuf::from("/nonexistent/lotse.sock"),
                camera: Some("rtsp://127.0.0.1:1/cam".to_owned()),
                audio: Audio::Aac,
            },
            Arc::new(lotse_core::clock::SystemClock),
        )
        .await
        .unwrap();
        let mut served = served;
        let clock: Arc<dyn Clock> = Arc::new(lotse_core::clock::SystemClock);
        let answer = served.command("restart-camera\n", Arc::clone(&clock)).await;
        assert!(
            answer["error"]
                .as_str()
                .unwrap()
                .contains("no synthetic camera"),
            "{answer}"
        );
        let answer = served.command("reboot", clock).await;
        assert!(
            answer["error"]
                .as_str()
                .unwrap()
                .contains("unknown command \"reboot\""),
            "{answer}"
        );
        let ready = served.ready().clone();
        assert_eq!(ready.camera, "rtsp://127.0.0.1:1/cam");
        assert_eq!(ready.stream, stream(Audio::Aac));
        let addr = ready
            .page
            .strip_prefix("http://")
            .and_then(|rest| rest.strip_suffix(PAGE_PATH))
            .unwrap()
            .to_owned();
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        stream
            .write_all(
                format!("GET {PAGE_PATH} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("window.lotseTest"));
        let json = serde_json::to_value(&ready).unwrap();
        assert_eq!(json["page"], ready.page.as_str());
        served.stop();
    }
}
