//! The load generator's report and the checks that turn it into a verdict:
//! sharing (one camera connection and one worker per stream), every viewer
//! playing, nothing left behind, and for a soak no growth in memory, tasks
//! or descriptors and no latency creep.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use serde::Serialize;

use super::histogram::{Histogram, Percentiles};
use super::play::ViewerStats;

/// When in a cycle a sample was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Viewers playing.
    Load,
    /// Viewers gone, streams still live: the point the soak compares
    /// across cycles.
    Quiet,
}

/// One process at one sample.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessSample {
    /// `supervisor`, or the worker's connection id.
    pub name: String,
    /// Its pid.
    pub pid: u32,
    /// CPU time since it started, seconds.
    pub cpu_s: Option<f64>,
    /// RSS: `metrics/get`'s, or `ps`'s where that has none.
    pub rss_bytes: Option<u64>,
    /// PSS, from `metrics/get` (Linux).
    pub pss_bytes: Option<u64>,
    /// Live tokio tasks, from `metrics/get`.
    pub tasks: Option<u64>,
    /// Open descriptors, where readable.
    pub fds: Option<u64>,
}

impl ProcessSample {
    /// The memory figure the checks use: PSS, else RSS.
    pub const fn memory(&self) -> Option<u64> {
        match self.pss_bytes {
            Some(pss) => Some(pss),
            None => self.rss_bytes,
        }
    }
}

/// Every process at one instant.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Sample {
    /// Seconds since the run started.
    pub at_s: f64,
    /// The cycle.
    pub cycle: u32,
    /// Where in it.
    pub phase: Phase,
    /// Open sessions, per `metrics/get`.
    pub sessions: u32,
    /// Worker crash restarts so far.
    pub worker_restarts: u64,
    /// The supervisor first, then the workers.
    pub processes: Vec<ProcessSample>,
}

/// Viewer counters summed.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct ViewerTotals {
    /// Viewers started.
    pub viewers: u64,
    /// Viewers whose ICE and DTLS came up.
    pub connected: u64,
    /// Viewers that received a keyframe.
    pub played: u64,
    /// Video packets received.
    pub packets: u64,
    /// Their payload bytes.
    pub bytes: u64,
    /// Frames completed.
    pub frames: u64,
    /// Keyframe starts.
    pub keyframes: u64,
    /// Sequence gaps.
    pub lost: u64,
    /// `lost / (packets + lost)`.
    pub loss_ratio: f64,
}

impl ViewerTotals {
    /// Sums `viewers`.
    pub fn of(viewers: &[ViewerStats]) -> Self {
        let mut totals = Self::default();
        for viewer in viewers {
            totals.viewers = totals.viewers.saturating_add(1);
            totals.connected = totals
                .connected
                .saturating_add(u64::from(viewer.connected_after.is_some()));
            totals.played = totals
                .played
                .saturating_add(u64::from(viewer.keyframes > 0));
            totals.packets = totals.packets.saturating_add(viewer.packets);
            totals.bytes = totals.bytes.saturating_add(viewer.bytes);
            totals.frames = totals.frames.saturating_add(viewer.frames);
            totals.keyframes = totals.keyframes.saturating_add(viewer.keyframes);
            totals.lost = totals.lost.saturating_add(viewer.lost);
        }
        let all = totals.packets.saturating_add(totals.lost);
        totals.loss_ratio = ratio(totals.lost, all);
        totals
    }
}

/// `part / whole`, 0 for an empty whole.
#[expect(
    clippy::cast_precision_loss,
    reason = "a report figure: counts far below 2^52"
)]
fn ratio(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

/// One cycle: viewers join, play, the cameras may hang up once, the
/// viewers leave.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CycleReport {
    /// Its index.
    pub index: u32,
    /// Per camera, connections opened during the cycle.
    pub camera_connections: Vec<u64>,
    /// Hang-ups the cameras were told to do.
    pub drops: u64,
    /// The viewers.
    pub viewers: ViewerTotals,
    /// Daemon-added latency of the live stamped packets.
    pub latency_first_packet: Percentiles,
    /// Offer → answer.
    pub answer: Percentiles,
    /// Offer → first keyframe packet: time to first frame.
    pub first_frame: Percentiles,
    /// CPU per process while every viewer played, percent of one core.
    pub cpu_percent: BTreeMap<String, f64>,
    /// Their sum.
    pub cpu_percent_total: Option<f64>,
    /// PSS (else RSS) of every process at the last load sample.
    pub memory_bytes_total: Option<u64>,
    /// Workers at the last load sample.
    pub workers_at_load: usize,
    /// Sessions at the last load sample.
    pub sessions_at_load: u32,
}

/// Distributions over a cycle's viewers.
pub fn distributions(viewers: &[ViewerStats]) -> (Histogram, Histogram, Histogram) {
    let mut latency = Histogram::default();
    let mut answer = Histogram::default();
    let mut first_frame = Histogram::default();
    for viewer in viewers {
        latency.merge(&viewer.latency);
        if let Some(after) = viewer.answer_after {
            answer.record(after);
        }
        if let Some(after) = viewer.first_keyframe_after {
            first_frame.record(after);
        }
    }
    (latency, answer, first_frame)
}

/// CPU per process between the first load sample with every session open
/// and the last load sample of `cycle`, percent of one core; processes in
/// both samples only.
pub fn cpu_percent(samples: &[Sample], cycle: u32, sessions: u32) -> BTreeMap<String, f64> {
    let load: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.cycle == cycle && s.phase == Phase::Load)
        .collect();
    let first = load.iter().find(|s| s.sessions >= sessions);
    let (Some(first), Some(last)) = (first, load.last()) else {
        return BTreeMap::new();
    };
    let wall = last.at_s - first.at_s;
    if wall <= 0.0 {
        return BTreeMap::new();
    }
    let mut out = BTreeMap::new();
    for process in &last.processes {
        let before = first
            .processes
            .iter()
            .find(|p| p.pid == process.pid)
            .and_then(|p| p.cpu_s);
        if let (Some(before), Some(after)) = (before, process.cpu_s) {
            out.insert(process.name.clone(), (after - before) / wall * 100.0);
        }
    }
    out
}

/// One process's figures early and late in a soak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Drift {
    /// `supervisor` or the connection id.
    pub name: String,
    /// Median memory (PSS, else RSS) of the early quiet samples.
    pub memory_early: Option<u64>,
    /// Median memory of the late quiet samples.
    pub memory_late: Option<u64>,
    /// Most tasks in an early quiet sample.
    pub tasks_early: Option<u64>,
    /// Most tasks in a late quiet sample.
    pub tasks_late: Option<u64>,
    /// Most descriptors in an early quiet sample.
    pub fds_early: Option<u64>,
    /// Most descriptors in a late quiet sample.
    pub fds_late: Option<u64>,
}

/// The soak's comparison of early and late cycles.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Leaks {
    /// Quiet samples compared, the warm-up cycle's left out.
    pub compared: usize,
    /// Per process.
    pub processes: Vec<Drift>,
    /// Median of the early cycles' latency medians, ms.
    pub latency_p50_early_ms: Option<f64>,
    /// Median of the late cycles' latency medians, ms.
    pub latency_p50_late_ms: Option<f64>,
}

/// The median of `values`, the lower one of an even count.
fn median<T: Copy + PartialOrd>(mut values: Vec<T>) -> Option<T> {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len().checked_sub(1)?.checked_div(2)?;
    values.get(mid).copied()
}

/// Early and late thirds of `items` (at least one each).
fn thirds<T>(items: &[T]) -> (&[T], &[T]) {
    let third = items.len().div_ceil(3).max(1);
    let early = items.get(..third).unwrap_or_default();
    let late = items
        .get(items.len().saturating_sub(third)..)
        .unwrap_or_default();
    (early, late)
}

/// Compares the quiet samples after the first (the warm-up cycle) and the
/// cycles' latency medians; `None` with fewer than two to compare.
pub fn leaks(samples: &[Sample], cycle_latency_p50_ms: &[Option<f64>]) -> Option<Leaks> {
    let quiet: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.phase == Phase::Quiet)
        .skip(1)
        .collect();
    if quiet.len() < 2 {
        return None;
    }
    let (early, late) = thirds(&quiet);
    let names: Vec<&str> = quiet
        .first()
        .map(|s| s.processes.iter().map(|p| p.name.as_str()).collect())
        .unwrap_or_default();
    let figure = |samples: &[&Sample], name: &str, pick: fn(&ProcessSample) -> Option<u64>| {
        samples
            .iter()
            .filter_map(|s| s.processes.iter().find(|p| p.name == name).and_then(pick))
            .collect::<Vec<u64>>()
    };
    let processes = names
        .into_iter()
        .map(|name| Drift {
            name: name.to_owned(),
            memory_early: median(figure(early, name, ProcessSample::memory)),
            memory_late: median(figure(late, name, ProcessSample::memory)),
            tasks_early: figure(early, name, |p| p.tasks).into_iter().max(),
            tasks_late: figure(late, name, |p| p.tasks).into_iter().max(),
            fds_early: figure(early, name, |p| p.fds).into_iter().max(),
            fds_late: figure(late, name, |p| p.fds).into_iter().max(),
        })
        .collect();
    let latencies: Vec<f64> = cycle_latency_p50_ms
        .iter()
        .skip(1)
        .flatten()
        .copied()
        .collect();
    let (early_latency, late_latency) = thirds(&latencies);
    Some(Leaks {
        compared: quiet.len(),
        processes,
        latency_p50_early_ms: median(early_latency.to_vec()),
        latency_p50_late_ms: median(late_latency.to_vec()),
    })
}

/// What a soak may grow by before it fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tolerances {
    /// Memory growth of one process, early to late.
    pub memory_bytes: u64,
    /// Latency median growth, early to late cycles.
    pub latency: Duration,
}

impl Leaks {
    /// What grew past `tolerances`.
    pub fn failures(&self, tolerances: Tolerances) -> Vec<String> {
        let mut out = Vec::new();
        for drift in &self.processes {
            if let (Some(early), Some(late)) = (drift.memory_early, drift.memory_late)
                && late.saturating_sub(early) > tolerances.memory_bytes
            {
                out.push(format!(
                    "{}: memory grew from {early} to {late} bytes (tolerance {})",
                    drift.name, tolerances.memory_bytes
                ));
            }
            if let (Some(early), Some(late)) = (drift.tasks_early, drift.tasks_late)
                && late > early
            {
                out.push(format!("{}: tasks grew from {early} to {late}", drift.name));
            }
            if let (Some(early), Some(late)) = (drift.fds_early, drift.fds_late)
                && late > early
            {
                out.push(format!(
                    "{}: descriptors grew from {early} to {late}",
                    drift.name
                ));
            }
        }
        if let (Some(early), Some(late)) = (self.latency_p50_early_ms, self.latency_p50_late_ms) {
            let allowed = tolerances.latency.as_secs_f64() * 1e3;
            if late - early > allowed {
                out.push(format!(
                    "latency median crept from {early:.2} ms to {late:.2} ms (tolerance {allowed:.2} ms)"
                ));
            }
        }
        out
    }
}

/// The whole run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// Cameras, one stream each.
    pub cameras: usize,
    /// Viewers per stream.
    pub viewers_per_camera: usize,
    /// Cycles run.
    pub cycles: u32,
    /// Seconds each cycle's viewers played.
    pub cycle_s: f64,
    /// Every viewer of every cycle.
    pub viewers: ViewerTotals,
    /// Daemon-added latency over the run.
    pub latency_first_packet: Percentiles,
    /// Offer → answer over the run.
    pub answer: Percentiles,
    /// Offer → first keyframe packet over the run.
    pub first_frame: Percentiles,
    /// Per cycle.
    pub cycle_reports: Vec<CycleReport>,
    /// The soak comparison, from three cycles on.
    pub leaks: Option<Leaks>,
    /// `metrics/get`'s per-stream counters at the end, before the streams
    /// are deleted.
    pub streams: serde_json::Value,
    /// Every sample.
    pub samples: Vec<Sample>,
    /// What failed; empty for a pass.
    pub failures: Vec<String>,
}

/// Milliseconds, or `-`.
fn ms(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |ms| format!("{ms:.2} ms"))
}

/// Megabytes, or `-`.
#[expect(
    clippy::cast_precision_loss,
    reason = "a report figure: byte counts far below 2^52"
)]
fn mb(value: Option<u64>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |bytes| format!("{:.1} MB", bytes as f64 / 1e6),
    )
}

impl Report {
    /// The verdict and the headline figures, for a terminal.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        let v = &self.viewers;
        let _w = writeln!(
            out,
            "lotse-load: {} camera(s) x {} viewer(s), {} cycle(s) of {:.1} s",
            self.cameras, self.viewers_per_camera, self.cycles, self.cycle_s
        );
        let _w = writeln!(
            out,
            "viewers: {}/{} connected, {} played; {} packets, {} frames, {} lost ({:.4} %)",
            v.connected,
            v.viewers,
            v.played,
            v.packets,
            v.frames,
            v.lost,
            v.loss_ratio * 100.0
        );
        let l = &self.latency_first_packet;
        let _w = writeln!(
            out,
            "daemon-added latency, first packet ({} stamps): p50 {} p95 {} p99 {} max {}",
            l.count,
            ms(l.p50_ms),
            ms(l.p95_ms),
            ms(l.p99_ms),
            ms(l.max_ms)
        );
        let _w = writeln!(
            out,
            "answer: p50 {} p99 {}; first frame: p50 {} p99 {}",
            ms(self.answer.p50_ms),
            ms(self.answer.p99_ms),
            ms(self.first_frame.p50_ms),
            ms(self.first_frame.p99_ms)
        );
        for cycle in &self.cycle_reports {
            let cpu: Vec<String> = cycle
                .cpu_percent
                .iter()
                .map(|(name, pct)| format!("{name} {pct:.1} %"))
                .collect();
            let _w = writeln!(
                out,
                "cycle {}: CPU {} ({}), memory {}, {} worker(s), {} session(s), latency p50 {}",
                cycle.index,
                cycle
                    .cpu_percent_total
                    .map_or_else(|| "-".to_owned(), |pct| format!("{pct:.1} %")),
                cpu.join(", "),
                mb(cycle.memory_bytes_total),
                cycle.workers_at_load,
                cycle.sessions_at_load,
                ms(cycle.latency_first_packet.p50_ms),
            );
        }
        if let Some(leaks) = &self.leaks {
            for drift in &leaks.processes {
                let _w = writeln!(
                    out,
                    "soak {}: memory {} -> {}, tasks {:?} -> {:?}, fds {:?} -> {:?}",
                    drift.name,
                    mb(drift.memory_early),
                    mb(drift.memory_late),
                    drift.tasks_early,
                    drift.tasks_late,
                    drift.fds_early,
                    drift.fds_late
                );
            }
        }
        if self.failures.is_empty() {
            out.push_str("PASS\n");
        } else {
            for failure in &self.failures {
                let _w = writeln!(out, "FAIL: {failure}");
            }
        }
        out
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

    fn process(name: &str, pid: u32, cpu_s: f64, memory: u64, tasks: u64) -> ProcessSample {
        ProcessSample {
            name: name.to_owned(),
            pid,
            cpu_s: Some(cpu_s),
            rss_bytes: Some(memory * 2),
            pss_bytes: Some(memory),
            tasks: Some(tasks),
            fds: Some(10),
        }
    }

    fn sample(
        at_s: f64,
        cycle: u32,
        phase: Phase,
        sessions: u32,
        processes: Vec<ProcessSample>,
    ) -> Sample {
        Sample {
            at_s,
            cycle,
            phase,
            sessions,
            worker_restarts: 0,
            processes,
        }
    }

    #[test]
    fn cpu_is_measured_once_every_session_is_open() {
        let samples = vec![
            sample(
                0.0,
                0,
                Phase::Load,
                1,
                vec![process("supervisor", 1, 0.0, 0, 0)],
            ),
            sample(
                1.0,
                0,
                Phase::Load,
                4,
                vec![
                    process("supervisor", 1, 0.5, 0, 0),
                    process("c1", 2, 1.0, 0, 0),
                ],
            ),
            sample(
                3.0,
                0,
                Phase::Load,
                4,
                vec![
                    process("supervisor", 1, 0.6, 0, 0),
                    process("c1", 2, 1.5, 0, 0),
                    process("c2", 3, 0.1, 0, 0),
                ],
            ),
            sample(
                4.0,
                0,
                Phase::Quiet,
                0,
                vec![process("supervisor", 1, 9.0, 0, 0)],
            ),
        ];
        let cpu = cpu_percent(&samples, 0, 4);
        assert_eq!(cpu.len(), 2, "c2 was not in the first sample: {cpu:?}");
        assert!((cpu["supervisor"] - 5.0).abs() < 1e-9, "{cpu:?}");
        assert!((cpu["c1"] - 25.0).abs() < 1e-9, "{cpu:?}");
        assert!(cpu_percent(&samples, 1, 4).is_empty(), "no samples");
        assert!(
            cpu_percent(&samples[..2], 0, 4).is_empty(),
            "one sample has no interval"
        );
    }

    #[test]
    fn a_soak_compares_late_quiet_samples_with_early_ones_after_the_warm_up() {
        let quiet = |cycle, memory, tasks| {
            sample(
                f64::from(cycle),
                cycle,
                Phase::Quiet,
                0,
                vec![process("supervisor", 1, 0.0, memory, tasks)],
            )
        };
        // The warm-up cycle's sample (huge) is left out.
        let flat: Vec<Sample> = [
            (0, 99_000_000, 50),
            (1, 1_000_000, 8),
            (2, 1_000_100, 8),
            (3, 999_000, 8),
        ]
        .into_iter()
        .map(|(c, m, t)| quiet(c, m, t))
        .collect();
        let tolerances = Tolerances {
            memory_bytes: 1_000,
            latency: Duration::from_millis(2),
        };
        let flat_leaks = leaks(&flat, &[Some(9.0), Some(1.0), Some(1.5), Some(2.0)]).unwrap();
        assert_eq!(flat_leaks.compared, 3);
        assert_eq!(flat_leaks.processes[0].memory_early, Some(1_000_000));
        assert_eq!(flat_leaks.processes[0].memory_late, Some(999_000));
        assert_eq!(flat_leaks.latency_p50_early_ms, Some(1.0));
        assert_eq!(flat_leaks.latency_p50_late_ms, Some(2.0));
        assert!(
            flat_leaks.failures(tolerances).is_empty(),
            "{:?}",
            flat_leaks.failures(tolerances)
        );

        let growing: Vec<Sample> = [
            (0, 0, 0),
            (1, 1_000_000, 8),
            (2, 1_500_000, 9),
            (3, 2_000_000, 9),
        ]
        .into_iter()
        .map(|(c, m, t)| quiet(c, m, t))
        .collect();
        let failures = leaks(&growing, &[None, Some(1.0), Some(1.0), Some(9.0)])
            .unwrap()
            .failures(tolerances);
        assert_eq!(failures.len(), 3, "{failures:?}");
        assert!(
            failures[0].contains("memory grew from 1000000 to 2000000"),
            "{failures:?}"
        );
        assert!(
            failures[1].contains("tasks grew from 8 to 9"),
            "{failures:?}"
        );
        assert!(failures[2].contains("latency median crept"), "{failures:?}");

        assert!(
            leaks(&flat[..2], &[]).is_none(),
            "one sample after the warm-up"
        );
    }

    #[test]
    fn descriptors_that_grow_fail_the_soak() {
        let quiet = |cycle, fds| {
            let mut p = process("supervisor", 1, 0.0, 1, 1);
            p.fds = Some(fds);
            sample(0.0, cycle, Phase::Quiet, 0, vec![p])
        };
        let samples = vec![quiet(0, 1), quiet(1, 10), quiet(2, 11)];
        let tolerances = Tolerances {
            memory_bytes: 0,
            latency: Duration::ZERO,
        };
        assert_eq!(
            leaks(&samples, &[]).unwrap().failures(tolerances),
            vec!["supervisor: descriptors grew from 10 to 11"]
        );
    }

    #[test]
    fn helpers_split_and_pick_middles() {
        assert_eq!(median(Vec::<u64>::new()), None);
        assert_eq!(median(vec![3_u64, 1, 2]), Some(2));
        assert_eq!(median(vec![4_u64, 1, 3, 2]), Some(2));
        assert_eq!(thirds(&[1, 2]), (&[1][..], &[2][..]));
        assert_eq!(
            thirds(&[1, 2, 3, 4, 5, 6, 7]),
            (&[1, 2, 3][..], &[5, 6, 7][..])
        );
        assert!((ratio(1, 4) - 0.25).abs() < f64::EPSILON);
        assert!(ratio(1, 0).abs() < f64::EPSILON);
        let mut p = process("x", 1, 0.0, 5, 0);
        assert_eq!(p.memory(), Some(5));
        p.pss_bytes = None;
        assert_eq!(p.memory(), Some(10), "RSS where there is no PSS");
    }

    #[test]
    fn totals_sum_viewers_and_the_summary_names_the_verdict() {
        let viewer = ViewerStats {
            connected_after: Some(Duration::from_millis(5)),
            answer_after: Some(Duration::from_millis(2)),
            first_keyframe_after: Some(Duration::from_millis(50)),
            packets: 99,
            frames: 30,
            keyframes: 3,
            lost: 1,
            ..ViewerStats::default()
        };
        let totals = ViewerTotals::of(&[viewer.clone(), ViewerStats::default()]);
        assert_eq!((totals.viewers, totals.connected, totals.played), (2, 1, 1));
        assert_eq!((totals.packets, totals.lost), (99, 1));
        assert!((totals.loss_ratio - 0.01).abs() < 1e-12);
        let (latency, answer, first_frame) = distributions(&[viewer]);
        assert_eq!(
            (latency.count(), answer.count(), first_frame.count()),
            (0, 1, 1)
        );

        let mut report = Report {
            cameras: 1,
            viewers_per_camera: 2,
            cycles: 1,
            cycle_s: 3.0,
            viewers: totals,
            latency_first_packet: Percentiles::default(),
            answer: answer.summary(),
            first_frame: first_frame.summary(),
            cycle_reports: vec![CycleReport {
                index: 0,
                camera_connections: vec![0],
                drops: 0,
                viewers: totals,
                latency_first_packet: Percentiles::default(),
                answer: Percentiles::default(),
                first_frame: Percentiles::default(),
                cpu_percent: BTreeMap::from([("supervisor".to_owned(), 1.25)]),
                cpu_percent_total: Some(1.25),
                memory_bytes_total: Some(12_500_000),
                workers_at_load: 1,
                sessions_at_load: 2,
            }],
            leaks: None,
            streams: serde_json::Value::Null,
            samples: Vec::new(),
            failures: Vec::new(),
        };
        let summary = report.summary();
        assert!(summary.contains("1/2 connected"), "{summary}");
        assert!(
            summary.contains("CPU 1.2 % (supervisor 1.2 %), memory 12.5 MB"),
            "{summary}"
        );
        assert!(summary.ends_with("PASS\n"), "{summary}");
        report
            .failures
            .push("c1: tasks grew from 8 to 9".to_owned());
        assert!(
            report
                .summary()
                .ends_with("FAIL: c1: tasks grew from 8 to 9\n")
        );
    }
}
