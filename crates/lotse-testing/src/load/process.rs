//! What the load generator reads about the daemon's processes beyond
//! `metrics/get`: CPU time, open descriptors and whether a process is
//! still there.
//!
//! On Linux from `/proc` (proc(5)): `/proc/<pid>/stat` is readable for
//! every process of the user, a sandboxed (non-dumpable) worker included;
//! `/proc/<pid>/fd` only for a dumpable one, so a sandboxed daemon reports
//! no descriptor counts. Elsewhere (macOS, development only) CPU time and
//! RSS come from `ps(1)`, the one portable way to another process's
//! figures without `unsafe`; there are no descriptor counts.

use std::time::Duration;

/// One process's figures at one instant; `None` where the platform or the
/// process's sandbox hides one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Figures {
    /// User plus system CPU time since it started.
    pub cpu: Option<Duration>,
    /// Resident set size, where `metrics/get` has none (macOS).
    pub rss_bytes: Option<u64>,
    /// Open file descriptors.
    pub fds: Option<u64>,
}

/// Reads `pid`'s figures.
pub fn figures(pid: u32) -> Figures {
    platform::figures(pid)
}

/// Whether a process `pid` exists (kill(2) with signal 0; `EPERM` means it
/// exists under another user).
pub fn alive(pid: u32) -> bool {
    let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    match rustix::process::test_kill_process(pid) {
        Ok(()) => true,
        Err(err) => err == rustix::io::Errno::PERM,
    }
}

/// User plus system time from the contents of `/proc/<pid>/stat`
/// (proc(5): fields 14 `utime` and 15 `stime`, in clock ticks of
/// `ticks_per_second`). The command name, field 2, is in parentheses and
/// may contain spaces and parentheses itself, so the fields are counted
/// from after its last `)`.
pub fn parse_proc_stat(stat: &str, ticks_per_second: u64) -> Option<Duration> {
    let (_, rest) = stat.rsplit_once(')')?;
    // `rest` starts at field 3 (`state`): utime is the 12th from there.
    let mut fields = rest.split_whitespace().skip(11);
    let utime: u64 = fields.next()?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    let ticks = utime.checked_add(stime)?;
    let per_second = ticks_per_second.max(1);
    let secs = ticks.checked_div(per_second)?;
    let rest_ticks = ticks.checked_rem(per_second)?;
    let nanos = rest_ticks
        .checked_mul(1_000_000_000)?
        .checked_div(per_second)?;
    Some(Duration::from_secs(secs).saturating_add(Duration::from_nanos(nanos)))
}

/// CPU time and RSS from a `ps -o time=,rss=` line: `[[dd-]hh:]mm:ss.cc`
/// and KiB.
pub fn parse_ps(line: &str) -> Option<(Duration, u64)> {
    let mut fields = line.split_whitespace();
    let time = fields.next()?;
    let rss_kib: u64 = fields.next()?.parse().ok()?;
    let (days, clock) = match time.split_once('-') {
        Some((days, clock)) => (days.parse::<u64>().ok()?, clock),
        None => (0, time),
    };
    let mut secs = 0.0_f64;
    for part in clock.split(':') {
        let value: f64 = part.parse().ok()?;
        secs = secs.mul_add(60.0, value);
    }
    let days_secs = days.checked_mul(86_400)?;
    let cpu = Duration::try_from_secs_f64(secs)
        .ok()?
        .checked_add(Duration::from_secs(days_secs))?;
    Some((cpu, rss_kib.checked_mul(1024)?))
}

#[cfg(target_os = "linux")]
mod platform {
    //! `/proc`.

    use super::{Figures, parse_proc_stat};

    /// Reads `/proc/<pid>/stat` and counts `/proc/<pid>/fd`.
    pub(super) fn figures(pid: u32) -> Figures {
        let cpu = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| parse_proc_stat(&stat, rustix::param::clock_ticks_per_second()));
        let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .ok()
            .map(|entries| u64::try_from(entries.count()).unwrap_or(u64::MAX));
        Figures {
            cpu,
            rss_bytes: None,
            fds,
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    //! `ps(1)`.

    use super::{Figures, parse_ps};

    /// Runs `ps -o time=,rss= -p <pid>`.
    #[expect(
        clippy::disallowed_methods,
        reason = "the load generator is a development tool outside the daemon; without /proc, ps is how it reads another process's CPU time"
    )]
    pub(super) fn figures(pid: u32) -> Figures {
        let output = std::process::Command::new("ps")
            .args(["-o", "time=,rss=", "-p", &pid.to_string()])
            .output();
        let parsed = output
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|text| parse_ps(text.trim()));
        Figures {
            cpu: parsed.map(|(cpu, _)| cpu),
            rss_bytes: parsed.map(|(_, rss)| rss),
            fds: None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn proc_stat_sums_utime_and_stime_after_the_command_name_proc5() {
        let stat = "4711 (lotse (worker) x) S 1 4711 4711 0 -1 4194560 2263 0 0 0 250 37 0 0 20 0 9 0 1234 0 0";
        assert_eq!(
            parse_proc_stat(stat, 100),
            Some(Duration::from_millis(2_870))
        );
        assert_eq!(
            parse_proc_stat(stat, 1_000),
            Some(Duration::from_millis(287))
        );
        assert_eq!(parse_proc_stat("4711 (lotse) S 1 2", 100), None);
        assert_eq!(parse_proc_stat("no parenthesis", 100), None);
        assert_eq!(
            parse_proc_stat("1 (x) S 1 1 1 0 -1 0 0 0 0 0 nope 1", 100),
            None
        );
    }

    #[test]
    fn ps_time_and_rss_parse_in_every_shape() {
        assert_eq!(
            parse_ps("0:01.50  2048"),
            Some((Duration::from_millis(1_500), 2 << 20))
        );
        assert_eq!(
            parse_ps("1:02:03.00 1"),
            Some((Duration::from_secs(3_723), 1024))
        );
        assert_eq!(
            parse_ps("2-01:00:00 1"),
            Some((Duration::from_hours(49), 1024))
        );
        assert_eq!(parse_ps(""), None);
        assert_eq!(parse_ps("0:01.50"), None);
        assert_eq!(parse_ps("x:01 1"), None);
        assert_eq!(parse_ps("0:01 kib"), None);
    }

    #[test]
    fn this_process_is_alive_and_has_figures() {
        let me = std::process::id();
        assert!(alive(me));
        assert!(!alive(0), "no pid 0");
        assert!(!alive(u32::MAX), "not a pid");
        let figures = figures(me);
        assert!(figures.cpu.is_some(), "{figures:?}");
        if cfg!(target_os = "linux") {
            assert!(figures.fds.is_some_and(|n| n > 2), "{figures:?}");
        } else {
            assert!(figures.rss_bytes.is_some_and(|n| n > 0), "{figures:?}");
        }
    }
}
