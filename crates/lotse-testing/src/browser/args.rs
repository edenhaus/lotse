//! The command line of `lotse-browser`
//! (`crates/lotse-testing/examples/lotse-browser.rs`).

use std::path::PathBuf;

use super::ServeConfig;
use crate::mediamtx::Audio;

/// The usage line.
pub const USAGE: &str =
    "usage: lotse-browser --socket PATH [--camera rtsp://...] [--audio pcmu|aac|opus]";

/// Parses the arguments after the program name.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<ServeConfig, String> {
    let mut socket = None;
    let mut camera = None;
    let mut audio = Audio::Pcmu;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--socket" => socket = Some(PathBuf::from(value)),
            "--camera" => camera = Some(value),
            // The page measures a beep, so the camera has audio.
            "--audio" => {
                audio = Audio::parse(&value)
                    .filter(|audio| *audio != Audio::None)
                    .ok_or_else(|| format!("--audio {value}: pcmu, aac or opus"))?;
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(ServeConfig {
        socket: socket.ok_or("--socket is required")?,
        camera,
        audio,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    fn args(list: &[&str]) -> Result<ServeConfig, String> {
        parse(list.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn flags_parse_with_defaults() {
        let parsed = args(&["--socket", "/s"]).unwrap();
        assert_eq!(parsed.socket, PathBuf::from("/s"));
        assert_eq!(parsed.camera, None);
        assert_eq!(parsed.audio, Audio::Pcmu);
        let parsed = args(&["--camera", "rtsp://cam/1", "--socket", "/s"]).unwrap();
        assert_eq!(parsed.camera.as_deref(), Some("rtsp://cam/1"));
        let parsed = args(&["--socket", "/s", "--audio", "aac"]).unwrap();
        assert_eq!(parsed.audio, Audio::Aac);
    }

    #[test]
    fn bad_command_lines_say_why() {
        assert!(
            args(&["--camera", "rtsp://cam/1"])
                .unwrap_err()
                .contains("--socket is required")
        );
        assert!(args(&["--socket"]).unwrap_err().contains("needs a value"));
        for audio in ["none", "mp3"] {
            let err = args(&["--socket", "/s", "--audio", audio]).unwrap_err();
            assert!(err.contains("pcmu, aac or opus"), "{err}");
        }
        assert!(
            args(&["--browser", "chrome"])
                .unwrap_err()
                .contains("unknown flag --browser")
        );
    }
}
