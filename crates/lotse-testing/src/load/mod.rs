//! The load generator and soak: N fake cameras, M headless viewers per
//! camera, against a running daemon over its control socket.
//!
//! A run is a number of cycles. The cameras' streams are put once with
//! `preload`, so their workers live for the whole run, as a preloaded
//! camera's does. In each cycle every viewer offers,
//! plays and hangs up; with `drop_cameras` every camera hangs up a third of
//! the way in and the daemon reconnects. The generator samples
//! `metrics/get` and each process's CPU time while the viewers play, and
//! once more when they are gone and every stream is live again (the quiet
//! sample the soak compares). At
//! the end it deletes the streams and checks that no worker is left.
//!
//! One cycle is a load run; three or more make a soak, which compares the
//! late cycles' quiet samples with the early ones' ([`report::leaks`]).
//! The cameras stamp every access unit ([`crate::latency`]) and share the
//! viewers' clock, so the viewers measure what the daemon adds.

pub mod args;
pub mod control;
pub mod histogram;
pub mod play;
pub mod process;
pub mod report;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_api_types::Metrics;
use lotse_core::clock::Clock;
use lotse_core::task::spawn_named;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use self::control::Control;
use self::play::{Play, ViewerStats};
use self::report::{CycleReport, Phase, ProcessSample, Report, Sample, Tolerances, ViewerTotals};
use crate::{CameraConfig, FakeCamera};

/// How long the generator waits for the daemon to settle: streams live,
/// sessions gone, workers gone.
const SETTLE: Duration = Duration::from_secs(20);

/// How often it polls while it waits.
const POLL: Duration = Duration::from_millis(100);

/// How long the quiet sample waits after the workers report no session: a
/// worker pushes its counters (its task count among them) every second
/// (`lotse_worker::STATS_INTERVAL`), and the push that first shows no
/// session may still count a session task winding down; the next one
/// does not.
const COUNTERS_FRESH: Duration = Duration::from_millis(1_500);

/// The synthetic camera's stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CameraProfile {
    /// Frames per second.
    pub fps: u32,
    /// Frames per GOP.
    pub gop: u32,
    /// Bytes of an IDR slice.
    pub idr_bytes: usize,
    /// Bytes of a P slice.
    pub p_bytes: usize,
}

impl CameraProfile {
    /// Sized like the 1080p H.264 stream at 4 Mbit/s of the CPU targets:
    /// 30 fps, a keyframe a second, 120 kB IDR and 12 kB P slices
    /// (3.7 Mbit/s). The slices are opaque, which the daemon never
    /// decodes, so their size is what costs.
    pub const HD_4MBIT: Self = Self {
        fps: 30,
        gop: 30,
        idr_bytes: 120_000,
        p_bytes: 12_000,
    };

    /// Bits per second on the wire, payload only.
    pub fn bitrate(self) -> u64 {
        let gop = u64::from(self.gop.max(1));
        let per_gop = u64::try_from(self.idr_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(
                u64::try_from(self.p_bytes)
                    .unwrap_or(u64::MAX)
                    .saturating_mul(gop.saturating_sub(1)),
            );
        per_gop
            .saturating_mul(8)
            .saturating_mul(u64::from(self.fps))
            .checked_div(gop)
            .unwrap_or(0)
    }
}

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadConfig {
    /// The daemon's control socket.
    pub socket: PathBuf,
    /// Cameras, one stream each.
    pub cameras: usize,
    /// Viewers per stream.
    pub viewers: usize,
    /// How long the viewers play in each cycle.
    pub cycle: Duration,
    /// Cycles; one is a load run, three or more a soak.
    pub cycles: u32,
    /// Every camera hangs up once per cycle, a third of the way in. The
    /// daemon retries a connection that was live at once, and resets its
    /// backoff only after a minute of streaming (`stable_after`), so with
    /// cycles under a minute the retries back off to 5 s and more after
    /// five hang-ups and the checks fail.
    pub drop_cameras: bool,
    /// How often the generator samples while the viewers play.
    pub sample_every: Duration,
    /// The cameras' stream.
    pub camera: CameraProfile,
    /// What a soak may grow by.
    pub tolerances: Tolerances,
}

/// The run's state between its steps.
struct Run<'a> {
    /// What to run.
    config: &'a LoadConfig,
    /// The clock the cameras stamp with and everything waits on.
    clock: Arc<dyn Clock>,
    /// The cameras' stamp origin, also the run's start.
    origin: Instant,
    /// The client.
    control: Arc<Control>,
    /// The cameras, by stream index.
    cameras: Vec<FakeCamera>,
    /// Every sample so far.
    samples: Vec<Sample>,
    /// Everything that failed so far.
    failures: Vec<String>,
}

/// The stream id of camera `index`.
fn stream_id(index: usize) -> String {
    format!("load-{index}")
}

/// Runs `config` against the daemon on `config.socket`. `Err` when the run
/// could not start (no daemon, a camera that would not bind); a run that
/// started reports its failures in [`Report::failures`].
pub async fn run(config: &LoadConfig, clock: Arc<dyn Clock>) -> Result<Report, String> {
    let origin = clock.now();
    let mut cameras = Vec::with_capacity(config.cameras);
    for _ in 0..config.cameras {
        let camera = FakeCamera::start(
            CameraConfig {
                fps: config.camera.fps,
                gop: config.camera.gop,
                idr_bytes: config.camera.idr_bytes,
                p_bytes: config.camera.p_bytes,
                stamp_origin: Some(origin),
                ..CameraConfig::default()
            },
            Arc::clone(&clock),
        )
        .await
        .map_err(|err| format!("a fake camera: {err}"))?;
        cameras.push(camera);
    }
    let (control, _hello) = Control::connect(&config.socket).await?;
    let mut run = Run {
        config,
        clock,
        origin,
        control: Arc::new(control),
        cameras,
        samples: Vec::new(),
        failures: Vec::new(),
    };
    let report = run.all().await;
    let Run {
        control, cameras, ..
    } = run;
    if let Ok(control) = Arc::try_unwrap(control) {
        control.close().await;
    }
    for camera in cameras {
        camera.stop().await;
    }
    report
}

impl Run<'_> {
    /// Seconds since the start.
    fn elapsed(&self) -> f64 {
        self.clock
            .now()
            .saturating_duration_since(self.origin)
            .as_secs_f64()
    }

    /// `metrics/get`, typed.
    async fn metrics(&self) -> Result<Metrics, String> {
        let (_id, result) = self
            .control
            .command(json!({ "type": "metrics/get" }))
            .await
            .map_err(|err| format!("metrics/get: {err}"))?;
        serde_json::from_value(result).map_err(|err| format!("metrics/get: {err}"))
    }

    /// Samples every process; the metrics too, for the caller's checks.
    async fn sample(&mut self, cycle: u32, phase: Phase) -> Result<Metrics, String> {
        let metrics = self.metrics().await?;
        let mut processes = Vec::with_capacity(metrics.workers.len().saturating_add(1));
        let named = std::iter::once(("supervisor", &metrics.supervisor.process)).chain(
            metrics
                .workers
                .iter()
                .map(|(name, worker)| (name.as_str(), &worker.process)),
        );
        for (name, figures) in named {
            let read = process::figures(figures.pid);
            processes.push(ProcessSample {
                name: name.to_owned(),
                pid: figures.pid,
                cpu_s: read.cpu.map(|cpu| cpu.as_secs_f64()),
                rss_bytes: figures.rss_bytes.or(read.rss_bytes),
                pss_bytes: figures.pss_bytes,
                tasks: figures.tasks,
                fds: read.fds,
            });
        }
        self.samples.push(Sample {
            at_s: self.elapsed(),
            cycle,
            phase,
            sessions: metrics.sessions,
            worker_restarts: metrics.worker_restarts,
            processes,
        });
        Ok(metrics)
    }

    /// Polls `metrics/get` until `done` holds, or fails after [`SETTLE`].
    async fn settle(&self, what: &str, done: impl Fn(&Metrics) -> bool) -> Result<Metrics, String> {
        let deadline = self.clock.now().checked_add(SETTLE);
        loop {
            let metrics = self.metrics().await?;
            if done(&metrics) {
                return Ok(metrics);
            }
            if deadline.is_none_or(|deadline| self.clock.now() >= deadline) {
                return Err(format!(
                    "{what} within {SETTLE:?}: {} worker(s), {} session(s)",
                    metrics.workers.len(),
                    metrics.sessions
                ));
            }
            self.clock.sleep(POLL).await;
        }
    }

    /// The whole run: streams up, the cycles, streams down.
    async fn all(&mut self) -> Result<Report, String> {
        let config = self.config;
        for (index, camera) in self.cameras.iter().enumerate() {
            self.control
                .command(json!({
                    "type": "stream/put",
                    "stream_id": stream_id(index),
                    "sources": [{ "url": camera.url() }],
                    "preload": true,
                }))
                .await
                .map_err(|err| format!("stream/put: {err}"))?;
        }
        self.settle("one worker per camera", |m| {
            m.workers.len() == config.cameras
        })
        .await?;
        self.wait_live().await?;
        for (index, connections) in self.connections().into_iter().enumerate() {
            if connections != 1 {
                self.failures.push(format!(
                    "{}: {connections} camera connections before any viewer, not 1",
                    stream_id(index)
                ));
            }
        }
        let mut cycle_reports = Vec::new();
        let mut all_viewers = Vec::new();
        for cycle in 0..config.cycles {
            let (report, viewers) = self.cycle(cycle).await?;
            cycle_reports.push(report);
            all_viewers.extend(viewers);
        }
        let last = self.metrics().await?;
        let streams = serde_json::to_value(&last.streams).unwrap_or_default();
        self.teardown().await;
        let (latency, answer, first_frame) = report::distributions(&all_viewers);
        let medians: Vec<Option<f64>> = cycle_reports
            .iter()
            .map(|c| c.latency_first_packet.p50_ms)
            .collect();
        let leaks = report::leaks(&self.samples, &medians);
        if let Some(leaks) = &leaks {
            self.failures.extend(leaks.failures(config.tolerances));
        }
        Ok(Report {
            cameras: config.cameras,
            viewers_per_camera: config.viewers,
            cycles: config.cycles,
            cycle_s: config.cycle.as_secs_f64(),
            viewers: ViewerTotals::of(&all_viewers),
            latency_first_packet: latency.summary(),
            answer: answer.summary(),
            first_frame: first_frame.summary(),
            cycle_reports,
            leaks,
            streams,
            samples: std::mem::take(&mut self.samples),
            failures: std::mem::take(&mut self.failures),
        })
    }

    /// Waits until every stream is live.
    async fn wait_live(&self) -> Result<(), String> {
        let deadline = self.clock.now().checked_add(SETTLE);
        for index in 0..self.config.cameras {
            loop {
                let (_id, stream) = self
                    .control
                    .command(json!({ "type": "stream/get", "stream_id": stream_id(index) }))
                    .await
                    .map_err(|err| format!("stream/get: {err}"))?;
                if stream.get("state").and_then(serde_json::Value::as_str) == Some("live") {
                    break;
                }
                if deadline.is_none_or(|deadline| self.clock.now() >= deadline) {
                    return Err(format!(
                        "{} not live within {SETTLE:?}: {stream}",
                        stream_id(index)
                    ));
                }
                self.clock.sleep(POLL).await;
            }
        }
        Ok(())
    }

    /// One cycle: viewers in, sampling, a camera drop, viewers out, the
    /// quiet sample.
    async fn cycle(&mut self, cycle: u32) -> Result<(CycleReport, Vec<ViewerStats>), String> {
        let config = self.config;
        let before: Vec<u64> = self.connections();
        let stop = CancellationToken::new();
        let mut viewers = Vec::new();
        for camera in 0..config.cameras {
            for viewer in 0..config.viewers {
                let play = Play {
                    control: Arc::clone(&self.control),
                    stream_id: stream_id(camera),
                    session_id: format!("load-{cycle}-{camera}-{viewer}"),
                    clock: Arc::clone(&self.clock),
                    origin: self.origin,
                    audio: false,
                    stop: stop.clone(),
                };
                viewers.push(spawn_named("load.viewer", play::view(play)));
            }
        }
        let start = self.clock.now();
        let end = start.checked_add(config.cycle).unwrap_or(start);
        let drop_at = start
            .checked_add(config.cycle.checked_div(3).unwrap_or_default())
            .unwrap_or(start);
        let mut drops = 0_u64;
        let mut next_sample = start;
        let mut last_load = None;
        while self.clock.now() < end {
            if config.drop_cameras && drops == 0 && self.clock.now() >= drop_at {
                for camera in &self.cameras {
                    camera.drop_connections();
                }
                drops = 1;
            }
            if self.clock.now() >= next_sample {
                last_load = Some(self.sample(cycle, Phase::Load).await?);
                next_sample = next_sample.checked_add(config.sample_every).unwrap_or(end);
            }
            let now = self.clock.now();
            let mut wake = next_sample.min(end);
            if config.drop_cameras && drops == 0 {
                wake = wake.min(drop_at);
            }
            self.clock.sleep(wake.saturating_duration_since(now)).await;
        }
        stop.cancel();
        let mut stats = Vec::with_capacity(viewers.len());
        for viewer in viewers {
            stats.push(
                viewer
                    .await
                    .unwrap_or_else(|err| ViewerStats::failed(format!("the viewer task: {err}"))),
            );
        }
        self.settle("every session closed", |m| {
            m.sessions == 0 && m.workers.values().all(|w| w.sessions == 0)
        })
        .await?;
        self.clock.sleep(COUNTERS_FRESH).await;
        // A camera that hung up late in the cycle may still be reconnecting.
        self.wait_live().await?;
        let quiet = self.sample(cycle, Phase::Quiet).await?;
        let opened = self
            .connections()
            .iter()
            .zip(&before)
            .map(|(after, before)| after.saturating_sub(*before))
            .collect();
        let report = self.cycle_report(cycle, opened, drops, &stats, last_load.as_ref());
        self.check_cycle(&report, &stats, &quiet, drops);
        Ok((report, stats))
    }

    /// Connections each camera has accepted so far.
    fn connections(&self) -> Vec<u64> {
        self.cameras
            .iter()
            .map(|camera| crate::fake_camera::Stats::get(&camera.stats().connections))
            .collect()
    }

    /// The figures of one cycle.
    fn cycle_report(
        &self,
        cycle: u32,
        opened: Vec<u64>,
        drops: u64,
        stats: &[ViewerStats],
        last_load: Option<&Metrics>,
    ) -> CycleReport {
        let sessions = u32::try_from(self.config.cameras.saturating_mul(self.config.viewers))
            .unwrap_or(u32::MAX);
        let cpu = report::cpu_percent(&self.samples, cycle, sessions);
        let total = (!cpu.is_empty()).then(|| cpu.values().sum());
        let memory = self
            .samples
            .iter()
            .rev()
            .find(|s| s.cycle == cycle && s.phase == Phase::Load)
            .map(|s| s.processes.iter().filter_map(ProcessSample::memory).sum());
        let (latency, answer, first_frame) = report::distributions(stats);
        CycleReport {
            index: cycle,
            camera_connections: opened,
            drops,
            viewers: ViewerTotals::of(stats),
            latency_first_packet: latency.summary(),
            answer: answer.summary(),
            first_frame: first_frame.summary(),
            cpu_percent_total: total,
            cpu_percent: cpu,
            memory_bytes_total: memory,
            workers_at_load: last_load.map_or(0, |m| m.workers.len()),
            sessions_at_load: last_load.map_or(0, |m| m.sessions),
        }
    }

    /// Sharing, every viewer playing, the workers still there.
    fn check_cycle(
        &mut self,
        report: &CycleReport,
        stats: &[ViewerStats],
        quiet: &Metrics,
        drops: u64,
    ) {
        let cycle = report.index;
        for (index, opened) in report.camera_connections.iter().enumerate() {
            // Viewers share the one connection; a hang-up costs one more.
            if *opened != drops {
                self.failures.push(format!(
                    "cycle {cycle}: {} opened {opened} camera connection(s), expected {drops}",
                    stream_id(index)
                ));
            }
        }
        for viewer in stats {
            let problem = if let Some(error) = &viewer.error {
                Some(error.clone())
            } else if let Some(code) = &viewer.closed_by_daemon {
                Some(format!("closed by the daemon: {code}"))
            } else if viewer.keyframes == 0 {
                Some("no keyframe".to_owned())
            } else {
                None
            };
            if let Some(problem) = problem {
                self.failures
                    .push(format!("cycle {cycle}: a viewer: {problem}"));
            }
        }
        let expected = self.config.cameras;
        if report.workers_at_load != expected || quiet.workers.len() != expected {
            self.failures.push(format!(
                "cycle {cycle}: {} worker(s) under load and {} after, expected {expected}",
                report.workers_at_load,
                quiet.workers.len()
            ));
        }
        if quiet.worker_restarts > 0 {
            self.failures.push(format!(
                "cycle {cycle}: {} worker restart(s)",
                quiet.worker_restarts
            ));
        }
    }

    /// Deletes the streams and checks that every worker process is gone.
    async fn teardown(&mut self) {
        for index in 0..self.config.cameras {
            if let Err(err) = self
                .control
                .command(json!({ "type": "stream/delete", "stream_id": stream_id(index) }))
                .await
            {
                self.failures.push(format!("stream/delete: {err}"));
            }
        }
        if let Err(err) = self
            .settle("every worker gone", |m| {
                m.workers.is_empty() && m.sessions == 0
            })
            .await
        {
            self.failures.push(err);
        }
        let supervisor = self
            .samples
            .first()
            .and_then(|s| s.processes.first())
            .map(|p| p.pid);
        let mut workers: Vec<u32> = self
            .samples
            .iter()
            .flat_map(|s| s.processes.iter().map(|p| p.pid))
            .filter(|pid| Some(*pid) != supervisor)
            .collect();
        workers.sort_unstable();
        workers.dedup();
        // A worker reaped by the supervisor is gone at once; give an
        // exiting one the settle time.
        let deadline = self.clock.now().checked_add(SETTLE);
        let mut left: Vec<u32> = workers;
        while !left.is_empty() {
            left.retain(|pid| process::alive(*pid));
            if left.is_empty() || deadline.is_none_or(|d| self.clock.now() >= d) {
                break;
            }
            self.clock.sleep(POLL).await;
        }
        if !left.is_empty() {
            self.failures.push(format!(
                "worker processes left after the streams were deleted: {left:?}"
            ));
        }
    }
}
