//! The command line of `lotse-load` (`crates/lotse-testing/examples/lotse-load.rs`).

use std::path::PathBuf;
use std::time::Duration;

use super::report::Tolerances;
use super::{CameraProfile, LoadConfig};

/// The usage line.
pub const USAGE: &str = "usage: lotse-load --socket PATH [--cameras N] [--viewers M] \
[--duration 60s] [--cycle D] [--drop] [--sample 1s] [--fps 30] [--gop 30] \
[--idr-bytes 120000] [--p-bytes 12000] [--memory-tolerance-kib 1024] \
[--latency-tolerance-ms 2] [--report PATH]";

/// A duration: a number with `ms`, `s`, `m` or `h`; a bare number is
/// seconds.
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let (number, unit) = text
        .find(|c: char| !c.is_ascii_digit())
        .map_or((text, ""), |at| text.split_at(at));
    let value: u64 = number
        .parse()
        .map_err(|_bad| format!("{text:?} is not a duration (60s, 5m, 72h)"))?;
    let secs = |factor: u64| {
        value
            .checked_mul(factor)
            .map(Duration::from_secs)
            .ok_or_else(|| format!("{text:?} is too long"))
    };
    match unit {
        "ms" => Ok(Duration::from_millis(value)),
        "" | "s" => secs(1),
        "m" => secs(60),
        "h" => secs(3_600),
        _ => Err(format!("{text:?}: the unit is ms, s, m or h")),
    }
}

/// A number.
fn number<T: std::str::FromStr>(flag: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_bad| format!("{flag} {value}: not a number"))
}

/// The parsed command line: what to run and where the JSON report goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// What to run.
    pub config: LoadConfig,
    /// Where the JSON report goes; stdout without one.
    pub report: Option<PathBuf>,
}

/// Parses the arguments after the program name.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut socket = None;
    let mut config = LoadConfig {
        socket: PathBuf::new(),
        cameras: 1,
        viewers: 1,
        cycle: Duration::ZERO,
        cycles: 1,
        drop_cameras: false,
        sample_every: Duration::from_secs(1),
        camera: CameraProfile::HD_4MBIT,
        tolerances: Tolerances {
            memory_bytes: 1024 * 1024,
            latency: Duration::from_millis(2),
        },
    };
    let mut duration = Duration::from_secs(60);
    let mut cycle = None;
    let mut report = None;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        if flag == "--drop" {
            config.drop_cameras = true;
            continue;
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--socket" => socket = Some(PathBuf::from(value)),
            "--cameras" => config.cameras = number(&flag, &value)?,
            "--viewers" => config.viewers = number(&flag, &value)?,
            "--duration" => duration = parse_duration(&value)?,
            "--cycle" => cycle = Some(parse_duration(&value)?),
            "--sample" => config.sample_every = parse_duration(&value)?,
            "--fps" => config.camera.fps = number(&flag, &value)?,
            "--gop" => config.camera.gop = number(&flag, &value)?,
            "--idr-bytes" => config.camera.idr_bytes = number(&flag, &value)?,
            "--p-bytes" => config.camera.p_bytes = number(&flag, &value)?,
            "--memory-tolerance-kib" => {
                config.tolerances.memory_bytes = number::<u64>(&flag, &value)?.saturating_mul(1024);
            }
            "--latency-tolerance-ms" => {
                config.tolerances.latency = Duration::from_millis(number(&flag, &value)?);
            }
            "--report" => report = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    config.socket =
        socket.ok_or("--socket is required: the path `lotse serve --socket` was given")?;
    if config.cameras == 0 || config.viewers == 0 {
        return Err("--cameras and --viewers are at least 1".to_owned());
    }
    if config.sample_every.is_zero() {
        return Err("--sample is more than zero".to_owned());
    }
    config.cycle = cycle.unwrap_or(duration);
    if config.cycle.is_zero() {
        return Err("--duration and --cycle are more than zero".to_owned());
    }
    config.cycles = u32::try_from(
        duration
            .as_millis()
            .checked_div(config.cycle.as_millis())
            .unwrap_or(1),
    )
    .unwrap_or(u32::MAX)
    .max(1);
    Ok(Args { config, report })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        parse(list.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn durations_take_a_unit_or_mean_seconds() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("72h"), Ok(Duration::from_hours(72)));
        assert!(parse_duration("h").unwrap_err().contains("not a duration"));
        assert!(parse_duration("5d").unwrap_err().contains("the unit"));
        assert!(
            parse_duration("18446744073709551615h")
                .unwrap_err()
                .contains("too long")
        );
    }

    #[test]
    fn a_load_run_is_one_cycle_of_the_duration_with_hd_cameras() {
        let parsed = args(&[
            "--socket",
            "/s",
            "--cameras",
            "3",
            "--viewers",
            "4",
            "--duration",
            "30s",
        ])
        .unwrap();
        let config = parsed.config;
        assert_eq!(config.socket, PathBuf::from("/s"));
        assert_eq!((config.cameras, config.viewers), (3, 4));
        assert_eq!((config.cycle, config.cycles), (Duration::from_secs(30), 1));
        assert_eq!(config.camera, CameraProfile::HD_4MBIT);
        assert_eq!(config.camera.bitrate(), 3_744_000);
        assert!(!config.drop_cameras);
        assert_eq!(parsed.report, None);
    }

    #[test]
    fn a_soak_is_cycles_of_the_cycle_length() {
        let parsed = args(&[
            "--socket",
            "/s",
            "--duration",
            "72h",
            "--cycle",
            "5m",
            "--drop",
            "--sample",
            "10s",
            "--fps",
            "25",
            "--gop",
            "50",
            "--idr-bytes",
            "1000",
            "--p-bytes",
            "100",
            "--memory-tolerance-kib",
            "2048",
            "--latency-tolerance-ms",
            "5",
            "--report",
            "/r.json",
        ])
        .unwrap();
        let config = parsed.config;
        assert_eq!(
            (config.cycle, config.cycles),
            (Duration::from_secs(300), 864)
        );
        assert!(config.drop_cameras);
        assert_eq!(config.sample_every, Duration::from_secs(10));
        assert_eq!(
            config.camera,
            CameraProfile {
                fps: 25,
                gop: 50,
                idr_bytes: 1000,
                p_bytes: 100
            }
        );
        assert_eq!(config.tolerances.memory_bytes, 2 << 20);
        assert_eq!(config.tolerances.latency, Duration::from_millis(5));
        assert_eq!(parsed.report, Some(PathBuf::from("/r.json")));
        let longer = args(&["--socket", "/s", "--duration", "1m", "--cycle", "5m"]).unwrap();
        assert_eq!(longer.config.cycles, 1, "at least one cycle");
    }

    #[test]
    fn bad_command_lines_say_why() {
        assert!(args(&[]).unwrap_err().contains("--socket is required"));
        assert!(args(&["--socket"]).unwrap_err().contains("needs a value"));
        assert!(args(&["--port", "1"]).unwrap_err().contains("unknown flag"));
        assert!(
            args(&["--socket", "/s", "--cameras", "x"])
                .unwrap_err()
                .contains("not a number")
        );
        assert!(
            args(&["--socket", "/s", "--viewers", "0"])
                .unwrap_err()
                .contains("at least 1")
        );
        assert!(
            args(&["--socket", "/s", "--sample", "0"])
                .unwrap_err()
                .contains("--sample")
        );
        assert!(
            args(&["--socket", "/s", "--duration", "0"])
                .unwrap_err()
                .contains("more than zero")
        );
        assert!(
            args(&["--socket", "/s", "--cycle", "x"])
                .unwrap_err()
                .contains("not a duration")
        );
    }
}
