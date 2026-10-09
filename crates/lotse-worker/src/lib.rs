//! Worker process: the IPC client, the source connection runner, the
//! derived tracks, the session manager and the once-per-second stats push,
//! for one camera connection.
//!
//! Everything a worker does apart from parsing protocols. It takes the factory
//! registries the binary filled, receives control messages from the
//! supervisor on the channel it inherited as stdin and runs `lotse-core` for
//! its `SourceConnection`. Kept out of the binary so it is a library with
//! tests; the counterpart of `lotse-supervisor`. A worker runs exactly one
//! source; a second `RunSource` is a protocol error.
//!
//! Standards: RFC 8837 §5 (the audio track's DSCP, `sendmsg`), RFC 3542
//! §6.1 and Linux `ip(7)` (the candidate's source address, `sendmsg`),
//! RFC 8656 §12.4 (the `ChannelData` it frames, [`relay`]).

mod derived;
mod ice_tcp;
pub mod relay;
mod sendmsg;
mod sessions;

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use lotse_core::backoff::ReconnectBackoff;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::clock_map::ClockMapper;
use lotse_core::registry::Registries;
use lotse_core::runner::{ConnectGate, RunnerConfig, RunnerEvent, SourceRunner};
use lotse_core::session::SessionLimits;
use lotse_core::source::{BackchannelSlot, ResolvedPeer, TrackSet};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use lotse_core::track::{Track, TrackId, TrackLimits};
use lotse_ipc::{
    Channel, Decoded, IpcError, Sender, SessionEvent, SessionSpec, SourceSpec, SourceState,
    ToSupervisor, ToWorker, TrackInfo, TrackStats, WorkerStats,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::derived::DerivedTracks;
use crate::sessions::SessionManager;

/// How often the worker pushes its counters.
pub const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// The worker's settings, passed by the supervisor as flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Tokio threads (`limits.worker_threads`).
    pub worker_threads: usize,
    /// The per-track bounds.
    pub limits: TrackLimits,
    /// The source runner's tunables.
    pub runner: RunnerConfig,
    /// The sessions' tunables (`webrtc.*`).
    pub session: SessionLimits,
    /// The most sessions the worker holds at once (`limits.max_sessions`):
    /// the supervisor never asks one worker for more, so this bounds only
    /// a supervisor that is wrong, not one that is right.
    pub max_sessions: usize,
    /// The descriptor number the shared UDP socket is moved to when it
    /// arrives, the one the worker's seccomp filter keeps it to sending
    /// on; `None` leaves it where it lands.
    pub shared_udp_fd: Option<RawFd>,
}

/// Why the worker stopped serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// The supervisor asked, and the source is torn down.
    Shutdown,
    /// The supervisor closed the channel (it is gone); the worker follows.
    SupervisorGone,
}

/// Why the worker failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The tokio runtime did not start.
    #[error("runtime failed to start: {0}")]
    Runtime(#[source] io::Error),
    /// Standard input is not the supervisor's channel.
    #[error("control channel on stdin: {0}")]
    Stdin(#[source] io::Error),
    /// The channel failed.
    #[error(transparent)]
    Channel(#[from] IpcError),
    /// The supervisor sent a source this worker cannot run. The supervisor
    /// validates specs before spawning, so this is a bug on its side.
    #[error("source rejected ({code}): {message}")]
    SourceRejected {
        /// The API code (`scheme_unsupported`, `invalid_request`).
        code: &'static str,
        /// What was wrong.
        message: String,
    },
    /// A second `RunSource` on a worker that runs one.
    #[error("a worker runs one source; a second RunSource is a protocol error")]
    SecondSource,
    /// A `SwitchSource` before any `RunSource`.
    #[error("a source switch before any source is a protocol error")]
    SwitchWithoutSource,
    /// The source did not stop within the shutdown deadline.
    #[error("the source did not stop within {0} ms")]
    ShutdownTimeout(u64),
}

/// Builds the runtime, opens the channel on stdin and serves until the
/// supervisor says stop or goes away. The sandbox must already be applied;
/// `memory` is the worker's `/proc/self/smaps_rollup`, opened before it.
pub fn run(
    settings: &Settings,
    registries: Registries,
    memory: Option<OwnedFd>,
) -> Result<ExitReason, Error> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(settings.worker_threads.max(1))
        .thread_name("lotse-worker")
        .enable_all()
        .build()
        .map_err(Error::Runtime)?;
    let process = tracing::info_span!("process", kind = "worker", pid = std::process::id());
    let reason = runtime.block_on(
        async {
            let channel = Channel::from_stdin().map_err(Error::Stdin)?;
            serve(
                channel,
                Arc::new(registries),
                Arc::new(SystemClock),
                settings,
                memory,
            )
            .await
        }
        .instrument(process),
    )?;
    runtime.shutdown_timeout(Duration::from_secs(1));
    Ok(reason)
}

/// The one source a worker runs.
struct Running {
    /// Stops the runner.
    cancel: CancellationToken,
    /// The connection's tracks, native and derived.
    tracks: Arc<DerivedTracks>,
    /// Fires when a derived track appears, goes or restarts.
    changes: watch::Receiver<()>,
    /// Fires when the tracks switched to a standby source
    /// ([`lotse_core::track::Feeds`]).
    switched: watch::Receiver<u8>,
    /// The connection's clock mapper.
    mapper: Arc<ClockMapper>,
    /// The runner task.
    task: JoinHandle<()>,
    /// Where the runner's attempts wait for the supervisor's grants.
    gate: ConnectGate,
    /// The tracks as last reported to the supervisor; empty until the
    /// source first went live.
    reported: Vec<TrackInfo>,
}

/// One source runner's handles.
struct Runner {
    /// Stops the runner.
    cancel: CancellationToken,
    /// Its clock mapper.
    mapper: Arc<ClockMapper>,
    /// The task.
    task: JoinHandle<()>,
    /// Where its attempts wait for the supervisor's grants.
    gate: ConnectGate,
}

/// The standby source a `SwitchSource` started: it declares into a staging
/// set and takes the tracks over at its first keyframe
/// ([`lotse_core::track::Feeds`]).
struct Standby {
    /// Its runner.
    runner: Runner,
    /// Its staging set, armed once it is live.
    staging: Arc<TrackSet>,
}

/// How long the old source gets to stop after the tracks switched, before
/// its task is aborted.
const SWITCH_STOP_GRACE: Duration = Duration::from_secs(1);

/// What the running source's watchers woke for.
enum RunningWake {
    /// A derived track appeared, went or restarted: the tracks to report.
    Tracks(Vec<TrackInfo>),
    /// The tracks switched to the standby with this tag.
    Switched(u8),
}

/// Serves the supervisor on `channel` until it says stop or goes away.
/// `memory`, the worker's `smaps_rollup`, goes to the supervisor with
/// `Ready`, the first message, and is closed here
/// ([`ToSupervisor::Ready`]).
pub async fn serve(
    channel: Channel,
    registries: Arc<Registries>,
    clock: Arc<dyn Clock>,
    settings: &Settings,
    memory: Option<OwnedFd>,
) -> Result<ExitReason, Error> {
    let (tx, mut rx) = channel.split();
    let (runner_tx, runner_rx) = mpsc::channel::<RunnerEvent>(64);
    let (standby_tx, standby_rx) = mpsc::channel::<RunnerEvent>(64);
    let (session_tx, mut session_rx) = mpsc::channel::<(String, SessionEvent)>(256);
    let mut serving = Serving {
        tx,
        registries,
        clock: Arc::clone(&clock),
        settings,
        runner_tx,
        runner_rx,
        standby_tx,
        standby_rx,
        session_tx,
        running: None,
        standby: None,
        sessions: None,
        lost_hand_offs: Throttle::default(),
    };
    let fds: Vec<BorrowedFd<'_>> = memory.iter().map(AsFd::as_fd).collect();
    serving
        .tx
        .send_msg(
            &ToSupervisor::Ready {
                pid: std::process::id(),
            },
            &fds,
        )
        .await?;
    drop(fds);
    tracing::info!(memory = memory.is_some(), "worker ready");
    drop(memory);

    let mut stats_tick = clock.sleep(STATS_INTERVAL);
    loop {
        tokio::select! {
            message = rx.recv_decoded::<ToWorker>() => match message? {
                None => return serving.on_supervisor_gone().await,
                Some(decoded) => {
                    if let Some(reason) = serving.on_decoded(decoded).await? {
                        // The last events of the sessions and the runner,
                        // `Stopped` included, are still queued.
                        while let Ok((session_id, event)) = session_rx.try_recv() {
                            serving.tx.send_msg(&ToSupervisor::Session { session_id, event }, &[]).await?;
                        }
                        while let Ok(event) = serving.runner_rx.try_recv() {
                            report(&mut serving.tx, event, None).await?;
                        }
                        return Ok(reason);
                    }
                }
            },
            Some(event) = serving.runner_rx.recv() => {
                report(&mut serving.tx, event, serving.running.as_mut()).await?;
            }
            Some(event) = serving.standby_rx.recv() => {
                serving.on_standby_event(event).await?;
            }
            Some((session_id, event)) = session_rx.recv() => {
                serving.tx.send_msg(&ToSupervisor::Session { session_id, event }, &[]).await?;
            }
            Some(wake) = watch_running(&mut serving.running) => {
                match wake {
                    RunningWake::Tracks(tracks) => {
                        serving.tx.send_msg(&ToSupervisor::Tracks(tracks), &[]).await?;
                    }
                    RunningWake::Switched(tag) => serving.on_switched(tag).await?,
                }
            }
            () = &mut stats_tick => {
                stats_tick = clock.sleep(STATS_INTERVAL);
                serving.push_stats().await?;
            }
        }
    }
}

/// What `serve` keeps between control messages.
struct Serving<'a> {
    /// The channel to the supervisor.
    tx: Sender,
    /// The factories.
    registries: Arc<Registries>,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// The settings.
    settings: &'a Settings,
    /// Where the source's runner reports.
    runner_tx: mpsc::Sender<RunnerEvent>,
    /// Its reports.
    runner_rx: mpsc::Receiver<RunnerEvent>,
    /// Where the standby's runner reports; swapped with the source's at
    /// the switch, so the new source reports as the source.
    standby_tx: mpsc::Sender<RunnerEvent>,
    /// Its reports.
    standby_rx: mpsc::Receiver<RunnerEvent>,
    /// Where sessions report.
    session_tx: mpsc::Sender<(String, SessionEvent)>,
    /// The source, once running.
    running: Option<Running>,
    /// The standby source, while one connects or waits for its keyframe.
    standby: Option<Standby>,
    /// The sessions, once the sockets arrived.
    sessions: Option<SessionManager>,
    /// The log line for hand-offs whose connection the kernel discarded,
    /// rate-limited: a flood of them must not flood the log.
    lost_hand_offs: Throttle,
}

impl Serving<'_> {
    /// One received message. A hand-off whose connection the kernel
    /// discarded, because this process had no free descriptor for it,
    /// costs that connection alone: the browser sees it close and tries
    /// another pair, and the camera's other viewers keep playing. Any
    /// other message that lost its descriptors ends the worker, as it
    /// cannot do its work without them.
    async fn on_decoded(
        &mut self,
        decoded: Decoded<ToWorker>,
    ) -> Result<Option<ExitReason>, Error> {
        if decoded.fds_truncated {
            let ToWorker::IceTcp { peer, .. } = &decoded.message else {
                return Err(IpcError::FdsTruncated.into());
            };
            if let Some(lost) = self.lost_hand_offs.hit(self.clock.now()) {
                tracing::warn!(%peer, lost, "ice-tcp hand-off arrived without its connection: no free descriptor; dropped");
            }
            return Ok(None);
        }
        self.on_message(decoded.message, decoded.fds).await
    }

    /// One control message; `Some` once the worker is done.
    async fn on_message(
        &mut self,
        message: ToWorker,
        fds: Vec<OwnedFd>,
    ) -> Result<Option<ExitReason>, Error> {
        match message {
            ToWorker::RunSource(spec) => {
                if self.running.is_some() {
                    return Err(Error::SecondSource);
                }
                self.running = Some(start_source(
                    &spec,
                    &self.registries,
                    &self.clock,
                    self.settings,
                    self.runner_tx.clone(),
                )?);
            }
            ToWorker::ConnectGranted => {
                if let Some(source) = &self.running {
                    source.gate.grant();
                } else {
                    tracing::debug!("connect grant without a source; ignored");
                }
            }
            ToWorker::SwitchSource(spec) => self.on_switch_source(&spec).await?,
            ToWorker::SwitchConnectGranted => {
                if let Some(standby) = &self.standby {
                    standby.runner.gate.grant();
                } else {
                    tracing::debug!("connect grant without a standby; ignored");
                }
            }
            ToWorker::Sockets => self.on_sockets(fds),
            ToWorker::IceTcp {
                local_ufrag,
                peer,
                first_frame,
            } => {
                if let (Some(stream), Some(manager)) = (fds.into_iter().next(), &self.sessions) {
                    manager.ice_tcp(&local_ufrag, stream, peer, first_frame);
                } else {
                    tracing::warn!(%peer, "ice-tcp hand-off without a descriptor or sessions; ignored");
                }
            }
            ToWorker::OpenSession(spec) => self.on_open_session(spec).await?,
            ToWorker::RemoteCandidate {
                session_id,
                candidate,
            } => {
                if let Some(manager) = &self.sessions {
                    manager.candidate(&session_id, candidate);
                }
            }
            ToWorker::RelayCandidate {
                session_id,
                relayed,
                server,
                local,
                tcp,
            } => {
                if let Some(manager) = &self.sessions {
                    manager.relay(&session_id, relayed, server, local, tcp);
                }
            }
            ToWorker::RelayChannel {
                session_id,
                relayed,
                peer,
                channel,
            } => {
                if let Some(manager) = &self.sessions {
                    manager.relay_channel(&session_id, relayed, peer, channel);
                }
            }
            ToWorker::SessionOrientation {
                session_id,
                orientation,
            } => {
                if let Some(manager) = &self.sessions {
                    manager.orientation(&session_id, orientation);
                }
            }
            ToWorker::CloseSession {
                session_id,
                code,
                message,
            } => {
                if let Some(manager) = &self.sessions {
                    manager.close(&session_id, sessions::close_code(&code), message);
                }
            }
            ToWorker::Shutdown { deadline_ms } => {
                return self.on_shutdown(deadline_ms).await.map(Some);
            }
        }
        Ok(None)
    }

    /// `Shutdown`: closes every session, stops the standby and the source
    /// within `deadline_ms`.
    async fn on_shutdown(&mut self, deadline_ms: u32) -> Result<ExitReason, Error> {
        let sessions = self.sessions.as_mut().map_or(0, SessionManager::len);
        tracing::info!(deadline_ms, sessions, "shutdown requested");
        if let Some(mut manager) = self.sessions.take() {
            manager
                .close_all("shutting_down", "the daemon is stopping")
                .await;
        }
        stop_standby(self.standby.take(), &self.clock).await;
        stop_source(
            self.running.take(),
            &self.clock,
            Duration::from_millis(u64::from(deadline_ms)),
        )
        .await?;
        Ok(ExitReason::Shutdown)
    }

    /// The supervisor closed the control channel: everything stops, with a
    /// second for the source.
    async fn on_supervisor_gone(&mut self) -> Result<ExitReason, Error> {
        tracing::warn!("supervisor closed the control channel; stopping");
        self.sessions.take();
        stop_standby(self.standby.take(), &self.clock).await;
        stop_source(self.running.take(), &self.clock, Duration::from_secs(1)).await?;
        Ok(ExitReason::SupervisorGone)
    }

    /// `SwitchSource`: connects `spec` as the standby of the running
    /// source, replacing a standby still on its way; a standby before any
    /// source is a protocol error.
    async fn on_switch_source(&mut self, spec: &SourceSpec) -> Result<(), Error> {
        let Some(running) = &self.running else {
            return Err(Error::SwitchWithoutSource);
        };
        if let Some(replaced) = self.standby.take() {
            tracing::info!("standby source replaced before it took over");
            replaced.staging.disarm();
            stop_runner(replaced.runner, &self.clock).await;
        }
        let staging = TrackSet::staging(running.tracks.tracks());
        let runner = start_runner(
            spec,
            &self.registries,
            &self.clock,
            self.settings,
            self.standby_tx.clone(),
            Arc::clone(&staging),
            "standby",
        )?;
        self.standby = Some(Standby { runner, staging });
        Ok(())
    }

    /// A standby runner's report: `Live` arms the switch at its next
    /// keyframe; every report goes to the supervisor as the standby's.
    async fn on_standby_event(&mut self, event: RunnerEvent) -> Result<(), Error> {
        if event == RunnerEvent::Live
            && let Some(standby) = &self.standby
        {
            standby.staging.arm_switch();
        }
        self.tx
            .send_msg(&ToSupervisor::SwitchState(source_state(event)), &[])
            .await?;
        Ok(())
    }

    /// The tracks switched to the standby `tag`: the old source is
    /// stopped, the standby becomes the source, and the supervisor hears
    /// of the switch and the tracks as they are now.
    async fn on_switched(&mut self, tag: u8) -> Result<(), Error> {
        let Some(standby) = self.standby.take() else {
            tracing::warn!(tag, "tracks switched without a standby; ignored");
            return Ok(());
        };
        let Some(running) = self.running.as_mut() else {
            return Ok(());
        };
        tracing::info!(
            tag,
            "tracks switched to the standby; stopping the old source"
        );
        running.cancel.cancel();
        let old = Runner {
            cancel: std::mem::replace(&mut running.cancel, standby.runner.cancel),
            mapper: std::mem::replace(&mut running.mapper, standby.runner.mapper),
            task: std::mem::replace(&mut running.task, standby.runner.task),
            gate: std::mem::replace(&mut running.gate, standby.runner.gate),
        };
        stop_runner(old, &self.clock).await;
        // The old runner's last reports, `Stopped` included, are not the
        // source's any more; the standby's channel is.
        while self.runner_rx.try_recv().is_ok() {}
        std::mem::swap(&mut self.runner_rx, &mut self.standby_rx);
        std::mem::swap(&mut self.runner_tx, &mut self.standby_tx);
        running.tracks.refresh();
        running.reported = track_infos(&running.tracks, &running.mapper);
        self.tx.send_msg(&ToSupervisor::Switched, &[]).await?;
        self.tx
            .send_msg(&ToSupervisor::Tracks(running.reported.clone()), &[])
            .await?;
        Ok(())
    }

    /// The shared UDP socket and the datagram channel: the session manager
    /// starts on them.
    fn on_sockets(&mut self, fds: Vec<OwnedFd>) {
        let mut fds = fds.into_iter();
        let (Some(udp), Some(datagrams)) = (fds.next(), fds.next()) else {
            tracing::warn!("sockets message without two descriptors; ignored");
            return;
        };
        tracing::info!("sockets received: shared udp and the datagram channel");
        match SessionManager::new(
            udp,
            self.settings.shared_udp_fd,
            datagrams,
            self.settings.max_sessions,
            Arc::clone(&self.clock),
            self.session_tx.clone(),
        ) {
            Ok(manager) => self.sessions = Some(manager),
            Err(err) => {
                tracing::error!(error = %err, "session manager not started; sessions refused");
            }
        }
    }

    /// A session to open, on the running source.
    async fn on_open_session(&mut self, spec: SessionSpec) -> Result<(), Error> {
        match (&mut self.sessions, &self.running) {
            (Some(manager), Some(source)) => {
                manager
                    .open(
                        spec,
                        Arc::clone(&source.tracks),
                        Arc::clone(&source.mapper),
                        &self.registries,
                        self.settings.session,
                    )
                    .await;
                Ok(())
            }
            (None, _) => {
                refuse_session(
                    &mut self.tx,
                    spec.session_id,
                    "internal_error",
                    "the worker holds no sockets",
                )
                .await
            }
            (_, None) => {
                refuse_session(
                    &mut self.tx,
                    spec.session_id,
                    "source_not_live",
                    "the worker runs no source",
                )
                .await
            }
        }
    }

    /// The once-per-second counters, after the tracks when their state
    /// moved since they were last reported: a track's `sync` changes with
    /// the camera's first Sender Report, which comes after the tracks went
    /// live, and with a new timeline.
    async fn push_stats(&mut self) -> Result<(), Error> {
        if let Some(source) = &mut self.running {
            let tracks = track_infos(&source.tracks, &source.mapper);
            if !source.reported.is_empty() && tracks != source.reported {
                tracing::debug!(tracks = tracks.len(), "track state moved; reported again");
                source.reported.clone_from(&tracks);
                self.tx.send_msg(&ToSupervisor::Tracks(tracks), &[]).await?;
            }
            let mut stats = worker_stats(&source.tracks, &source.mapper);
            if let Some(manager) = &mut self.sessions {
                stats.sessions = u32::try_from(manager.len()).unwrap_or(u32::MAX);
                stats.send_failures = manager.stats().send_failures.load(Ordering::Relaxed);
                stats.relay_unbound = manager.stats().relay_unbound.load(Ordering::Relaxed);
            }
            self.tx.send_msg(&ToSupervisor::Stats(stats), &[]).await?;
        }
        if let Some(manager) = &mut self.sessions {
            let sessions = manager.len();
            let stats = manager.stats();
            tracing::trace!(
                sessions,
                unroutable = stats.unroutable.load(Ordering::Relaxed),
                dropped = stats.dropped.load(Ordering::Relaxed),
                send_failures = stats.send_failures.load(Ordering::Relaxed),
                relay_unbound = stats.relay_unbound.load(Ordering::Relaxed),
                "session router counters"
            );
        }
        Ok(())
    }
}

/// Reports a session the worker cannot open at all.
async fn refuse_session(
    tx: &mut Sender,
    session_id: String,
    code: &str,
    message: &str,
) -> Result<(), Error> {
    tracing::warn!(session = %session_id, code, message, "session refused");
    tx.send_msg(
        &ToSupervisor::Session {
            session_id,
            event: SessionEvent::Closed {
                code: code.to_owned(),
                message: message.to_owned(),
            },
        },
        &[],
    )
    .await?;
    Ok(())
}

/// Validates `spec` against the registry and starts its runner on a new
/// track set.
fn start_source(
    spec: &SourceSpec,
    registries: &Registries,
    clock: &Arc<dyn Clock>,
    settings: &Settings,
    events: mpsc::Sender<RunnerEvent>,
) -> Result<Running, Error> {
    let native = TrackSet::new(settings.limits, clock.now());
    let runner = start_runner(
        spec,
        registries,
        clock,
        settings,
        events,
        Arc::clone(&native),
        "source",
    )?;
    let tracks = DerivedTracks::new(
        Arc::clone(&native),
        registries.transcoders.all().to_vec(),
        Arc::clone(clock),
    );
    let changes = tracks.changes();
    Ok(Running {
        cancel: runner.cancel,
        tracks,
        changes,
        switched: native.feeds().switched(),
        mapper: runner.mapper,
        task: runner.task,
        gate: runner.gate,
        reported: Vec::new(),
    })
}

/// Validates `spec` against the registry and starts its runner on
/// `native`, reporting to `events`; `role` names it in the log.
#[expect(
    clippy::too_many_arguments,
    reason = "wires one runner into the worker's shared parts; called from two places"
)]
fn start_runner(
    spec: &SourceSpec,
    registries: &Registries,
    clock: &Arc<dyn Clock>,
    settings: &Settings,
    events: mpsc::Sender<RunnerEvent>,
    native: Arc<TrackSet>,
    role: &'static str,
) -> Result<Runner, Error> {
    let url = SourceUrl::parse(&spec.url).map_err(|err| Error::SourceRejected {
        code: "invalid_request",
        message: err.to_string(),
    })?;
    let factory = registries
        .sources
        .get(url.scheme())
        .ok_or_else(|| Error::SourceRejected {
            code: "scheme_unsupported",
            message: format!("scheme {:?} is not compiled in", url.scheme()),
        })?;
    let options: serde_json::Value =
        serde_json::from_str(&spec.options).map_err(|err| Error::SourceRejected {
            code: "invalid_request",
            message: format!("options are not JSON: {err}"),
        })?;
    let source = factory
        .validate(&url, &options)
        .map_err(|err| Error::SourceRejected {
            code: "invalid_request",
            message: err.to_string(),
        })?;
    tracing::info!(
        connection = %spec.connection_id,
        url = %url,
        peer = %spec.peer_host,
        addrs = ?spec.peer_addrs,
        role,
        "running source"
    );

    let mapper = Arc::new(ClockMapper::new());
    let cancel = CancellationToken::new();
    let gate = ConnectGate::closed();
    let runner = SourceRunner::new(
        source,
        ResolvedPeer {
            host: spec.peer_host.clone(),
            addrs: spec.peer_addrs.clone(),
        },
        native,
        Arc::clone(&mapper),
        BackchannelSlot::default(),
        Arc::clone(clock),
        settings.runner,
        ReconnectBackoff::new(jitter_seed(clock.as_ref())),
        events,
        gate.clone(),
        cancel.clone(),
    );
    let task = spawn_named("source.runner", runner.run());
    Ok(Runner {
        cancel,
        mapper,
        task,
        gate,
    })
}

/// Cancels a runner and waits for it within [`SWITCH_STOP_GRACE`]; one
/// that does not stop in time is aborted, as nothing of the connection's
/// depends on it any more.
async fn stop_runner(runner: Runner, clock: &Arc<dyn Clock>) {
    runner.cancel.cancel();
    let mut task = runner.task;
    tokio::select! {
        _ = &mut task => {}
        () = clock.sleep(SWITCH_STOP_GRACE) => {
            tracing::warn!(
                grace_ms = SWITCH_STOP_GRACE.as_millis(),
                "the replaced source did not stop in time; aborted"
            );
            task.abort();
        }
    }
}

/// Stops the standby, if there is one.
async fn stop_standby(standby: Option<Standby>, clock: &Arc<dyn Clock>) {
    if let Some(standby) = standby {
        standby.staging.disarm();
        stop_runner(standby.runner, clock).await;
    }
}

/// A jitter seed from the wall clock and the pid: different per worker,
/// not secret.
fn jitter_seed(clock: &dyn Clock) -> u64 {
    let nanos = clock
        .wall_now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        });
    nanos ^ u64::from(std::process::id())
}

/// Cancels the runner and waits for it, within `deadline`; closes the tracks.
async fn stop_source(
    running: Option<Running>,
    clock: &Arc<dyn Clock>,
    deadline: Duration,
) -> Result<(), Error> {
    let Some(source) = running else {
        return Ok(());
    };
    source.cancel.cancel();
    let task = source.task;
    tokio::select! {
        _ = task => {}
        () = clock.sleep(deadline) => {
            return Err(Error::ShutdownTimeout(u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX)));
        }
    }
    let derived = source
        .tracks
        .derived()
        .into_iter()
        .map(|derived| derived.track);
    for track in source.tracks.tracks().tracks().into_iter().chain(derived) {
        track.close();
    }
    tracing::info!("source stopped");
    Ok(())
}

/// Forwards a runner event to the supervisor; `Live` also restarts derived
/// tracks whose source codec the reconnect changed, and carries the tracks.
async fn report(
    tx: &mut Sender,
    event: RunnerEvent,
    running: Option<&mut Running>,
) -> Result<(), Error> {
    let state = source_state(event);
    // The tracks go first, so a stream the supervisor shows as live always
    // has them.
    if state == SourceState::Live
        && let Some(source) = running
    {
        source.tracks.refresh();
        source.reported = track_infos(&source.tracks, &source.mapper);
        tx.send_msg(&ToSupervisor::Tracks(source.reported.clone()), &[])
            .await?;
    }
    tx.send_msg(&ToSupervisor::SourceState(state), &[]).await?;
    Ok(())
}

/// A runner event as the supervisor hears it.
fn source_state(event: RunnerEvent) -> SourceState {
    match event {
        RunnerEvent::Connecting { attempt } => SourceState::Connecting { attempt },
        RunnerEvent::Live => SourceState::Live,
        RunnerEvent::Reconnecting { error } => SourceState::Reconnecting {
            code: error.code().to_owned(),
            message: error.to_string(),
        },
        RunnerEvent::Backoff { error, retry_in } => SourceState::Backoff {
            code: error.code().to_owned(),
            message: error.to_string(),
            retry_ms: u32::try_from(retry_in.as_millis()).unwrap_or(u32::MAX),
        },
        RunnerEvent::Stopped => SourceState::Stopped,
    }
}

/// The tracks, native then derived, once one changed, or the switch to a
/// standby; never without a source.
async fn watch_running(running: &mut Option<Running>) -> Option<RunningWake> {
    let source = running.as_mut()?;
    tokio::select! {
        changed = source.changes.changed() => {
            changed.ok()?;
            source.reported = track_infos(&source.tracks, &source.mapper);
            Some(RunningWake::Tracks(source.reported.clone()))
        }
        changed = source.switched.changed() => {
            changed.ok()?;
            Some(RunningWake::Switched(*source.switched.borrow_and_update()))
        }
    }
}

/// The tracks as the API reports them, native then derived. A derived
/// track is synced as its source is, since its capture times come from
/// the source's.
fn track_infos(tracks: &DerivedTracks, mapper: &ClockMapper) -> Vec<TrackInfo> {
    let info = |track: &Track, from: Option<TrackId>, delay: Option<Duration>| TrackInfo {
        id: track.id().to_string(),
        kind: track.kind().name().to_owned(),
        codec: track.codec().name().to_owned(),
        clock_rate: track.clock_rate(),
        sync: mapper
            .mode(from.unwrap_or_else(|| track.id()))
            .name()
            .to_owned(),
        derived_from: from.map(|from| from.to_string()),
        audio_delay_ms: delay.map(|delay| u32::try_from(delay.as_millis()).unwrap_or(u32::MAX)),
    };
    let natives = tracks.tracks().tracks();
    let derived = tracks.derived();
    natives
        .iter()
        .map(|track| info(track, None, None))
        .chain(
            derived
                .iter()
                .map(|derived| info(&derived.track, Some(derived.from), Some(derived.delay))),
        )
        .collect()
}

/// The counters of every track, native then derived, and the source's.
fn worker_stats(tracks: &DerivedTracks, mapper: &ClockMapper) -> WorkerStats {
    let derived = tracks.derived().into_iter().map(|derived| derived.track);
    let ingest = tracks.tracks().ingest();
    WorkerStats {
        tracks: tracks
            .tracks()
            .tracks()
            .into_iter()
            .chain(derived)
            .map(|track| (track.id().to_string(), track_stats(&track)))
            .collect(),
        sessions: 0,
        send_failures: 0,
        av_sync_lost: u64::from(mapper.audio_withdrawn()),
        relay_unbound: 0,
        packets_lost: ingest.packets_lost,
        packets_out_of_order: ingest.packets_out_of_order,
        datagrams_rejected: ingest.datagrams_rejected,
        tasks: u64::try_from(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
        )
        .unwrap_or(u64::MAX),
    }
}

/// One track's counters in wire form.
fn track_stats(track: &Track) -> TrackStats {
    let stats = track.stats();
    TrackStats {
        packets: stats.packets,
        packet_bytes: stats.packet_bytes,
        frames: stats.frames,
        frame_bytes: stats.frame_bytes,
        keyframes: stats.keyframes,
        frames_dropped_oversize: stats.frames_dropped_oversize,
        frames_over_browser_limit: stats.frames_over_browser_limit,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::fd::OwnedFd;

    use lotse_core::clock::FakeClock;
    use lotse_core::output::OutputShape;
    use lotse_core::test_util::{
        ECHO_ANSWER, EchoSessionFactory, FakeOutputFactory, FakeSourceFactory,
    };
    use lotse_ipc::Receiver;

    use super::*;

    fn settings() -> Settings {
        Settings {
            worker_threads: 1,
            limits: TrackLimits::default(),
            runner: RunnerConfig::default(),
            session: SessionLimits::default(),
            max_sessions: 256,
            shared_udp_fd: None,
        }
    }

    /// [`settings`] for a fake source whose video is silent: no stall
    /// reconnects, so a test that steps the fake clock freely never takes
    /// the stream's tracks away from a session, and every track report
    /// comes from what the test does.
    fn quiet_settings() -> Settings {
        let mut quiet = settings();
        quiet.runner.stall_video = Duration::from_hours(24);
        quiet.runner.stall_audio = Duration::from_hours(24);
        quiet
    }

    fn registries() -> Arc<Registries> {
        let mut registries = Registries::default();
        registries
            .sources
            .register(Arc::new(FakeSourceFactory::new(&["fake"])))
            .unwrap();
        registries
            .outputs
            .register(Arc::new(FakeOutputFactory("webrtc", OutputShape::Session)))
            .unwrap();
        Arc::new(registries)
    }

    fn session_spec(id: &str) -> SessionSpec {
        SessionSpec {
            session_id: id.into(),
            kind: "webrtc".into(),
            offer: "v=0\r\n".into(),
            ice_ufrag: format!("ufrag-{id}"),
            ice_pass: "pass".into(),
            candidates: vec![],
            tcp_candidates: vec![],
            audio: false,
            orientation: 1,
        }
    }

    fn spec(url: &str, options: &str) -> SourceSpec {
        SourceSpec {
            connection_id: "c1".into(),
            url: url.into(),
            options: options.into(),
            peer_host: "cam".into(),
            peer_addrs: vec![],
        }
    }

    /// The supervisor's end of a worker served in-process.
    struct Harness {
        tx: Sender,
        rx: Receiver,
        clock: Arc<FakeClock>,
        worker: JoinHandle<Result<ExitReason, Error>>,
    }

    fn start() -> Harness {
        start_with(registries())
    }

    /// The fake source and the echoing session output.
    fn echo_registries() -> Arc<Registries> {
        let mut registries = Registries::default();
        registries
            .sources
            .register(Arc::new(FakeSourceFactory::new(&["fake"])))
            .unwrap();
        registries
            .outputs
            .register(Arc::new(EchoSessionFactory))
            .unwrap();
        Arc::new(registries)
    }

    fn start_with(registries: Arc<Registries>) -> Harness {
        start_with_settings(registries, settings())
    }

    fn start_with_settings(registries: Arc<Registries>, settings: Settings) -> Harness {
        let (ours, theirs) = Channel::pair().unwrap();
        let worker_channel = Channel::from_fd(theirs).unwrap();
        let clock = Arc::new(FakeClock::default());
        let worker_clock: Arc<dyn Clock> = clock.clone();
        let worker = spawn_named("test.worker", async move {
            serve(worker_channel, registries, worker_clock, &settings, None).await
        });
        let (tx, rx) = ours.split();
        Harness {
            tx,
            rx,
            clock,
            worker,
        }
    }

    impl Harness {
        /// The worker's next message; a worker that goes quiet for ten
        /// seconds of real time fails the test instead of hanging it.
        /// Grants every announced connection attempt at once, as the
        /// supervisor does with a permit free.
        async fn next(&mut self) -> ToSupervisor {
            let message = tokio::select! {
                message = self.rx.recv_msg::<ToSupervisor>() => message.unwrap().unwrap().0,
                () = SystemClock.sleep(Duration::from_secs(10)) => panic!("the worker sent nothing for 10 s"),
            };
            if matches!(
                message,
                ToSupervisor::SourceState(
                    SourceState::Connecting { .. } | SourceState::Reconnecting { .. }
                )
            ) {
                self.tx
                    .send_msg(&ToWorker::ConnectGranted, &[])
                    .await
                    .unwrap();
            }
            if matches!(
                message,
                ToSupervisor::SwitchState(
                    SourceState::Connecting { .. } | SourceState::Reconnecting { .. }
                )
            ) {
                self.tx
                    .send_msg(&ToWorker::SwitchConnectGranted, &[])
                    .await
                    .unwrap();
            }
            message
        }

        /// The next `closed` event: its session id and code.
        async fn next_closed(&mut self) -> (String, String) {
            loop {
                if let ToSupervisor::Session {
                    session_id,
                    event: SessionEvent::Closed { code, .. },
                } = self.next().await
                {
                    return (session_id, code);
                }
            }
        }
    }

    /// A loopback TCP connection: the browser's end, and the daemon's as
    /// the descriptor the supervisor would pass.
    fn tcp_pair() -> (std::net::TcpStream, OwnedFd, std::net::SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let browser = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (ours, peer) = listener.accept().unwrap();
        (browser, OwnedFd::from(ours), peer)
    }

    /// Whether the daemon closed the browser's connection: EOF, without
    /// blocking the runtime the worker runs on.
    async fn closed_by_daemon(browser: std::net::TcpStream) -> bool {
        use tokio::io::AsyncReadExt as _;
        browser.set_nonblocking(true).unwrap();
        let mut browser = tokio::net::TcpStream::from_std(browser).unwrap();
        matches!(browser.read(&mut [0_u8; 1]).await, Ok(0))
    }

    fn ice_tcp(ufrag: &str, peer: std::net::SocketAddr) -> ToWorker {
        ToWorker::IceTcp {
            local_ufrag: ufrag.into(),
            peer,
            first_frame: vec![0, 1],
        }
    }

    #[tokio::test]
    async fn a_switch_source_takes_the_tracks_over_at_the_standby_s_first_keyframe() {
        let mut h = start_with_settings(registries(), quiet_settings());
        h.tx.send_msg(&ToWorker::Sockets, &[]).await.unwrap();
        h.tx.send_msg(
            &ToWorker::RunSource(spec("fake://cam/", r#"{"keyframes_every_ms": 10}"#)),
            &[],
        )
        .await
        .unwrap();
        until_live(&mut h).await;
        // A standby for another URL: it reports as the standby, on its own
        // grant, while the source's state stands.
        let standby = spec("fake://cam2/", r#"{"keyframes_every_ms": 10}"#);
        h.tx.send_msg(&ToWorker::SwitchSource(standby.clone()), &[])
            .await
            .unwrap();
        // Replaced at once by the same spec again: the first standby's
        // `Stopped` is a standby report too.
        h.tx.send_msg(&ToWorker::SwitchSource(standby), &[])
            .await
            .unwrap();
        let mut seen = Vec::new();
        loop {
            match h.next().await {
                ToSupervisor::SwitchState(SourceState::Live) => break,
                ToSupervisor::SwitchState(state) => seen.push(state),
                ToSupervisor::Stats(_) => {}
                other => panic!("unexpected before the standby is live: {other:?}"),
            }
        }
        assert!(
            seen.iter()
                .any(|state| matches!(state, SourceState::Connecting { .. })),
            "{seen:?}"
        );
        // Its next keyframe, on the fake clock, switches: the worker says
        // so and reports the tracks as they are now; the old source's
        // `Stopped` is not the source's.
        let mut steps = 0;
        loop {
            h.clock.advance(Duration::from_millis(10));
            tokio::task::yield_now().await;
            let message = tokio::select! {
                message = h.rx.recv_msg::<ToSupervisor>() => message.unwrap().unwrap().0,
                () = SystemClock.sleep(Duration::from_millis(50)) => { steps += 1; assert!(steps < 100, "no switch"); continue; }
            };
            match message {
                ToSupervisor::Switched => break,
                ToSupervisor::SwitchState(SourceState::Stopped) | ToSupervisor::Stats(_) => {}
                other => panic!("unexpected before the switch: {other:?}"),
            }
        }
        let tracks = loop {
            match h.next().await {
                ToSupervisor::Tracks(tracks) => break tracks,
                ToSupervisor::Stats(_) => {}
                other => panic!("unexpected after the switch: {other:?}"),
            }
        };
        assert_eq!(tracks.len(), 1);
        assert_eq!(tracks[0].codec, "h264");
        // A second later: counters, and no `Stopped` from the old source.
        h.clock.advance(STATS_INTERVAL);
        loop {
            match h.next().await {
                ToSupervisor::Stats(stats) => {
                    let video = stats.tracks.iter().find(|(id, _)| id == "v0").unwrap();
                    assert!(video.1.packets >= 1, "{stats:?}");
                    break;
                }
                ToSupervisor::Tracks(_) => {}
                other => panic!("unexpected after the switch: {other:?}"),
            }
        }
        // A standby pending at shutdown stops with the rest.
        h.tx.send_msg(
            &ToWorker::SwitchSource(spec("fake://cam3/", r#"{"ready_after_ms": 60000}"#)),
            &[],
        )
        .await
        .unwrap();
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 1000 }, &[])
            .await
            .unwrap();
        loop {
            match h.next().await {
                ToSupervisor::SourceState(SourceState::Stopped) => break,
                ToSupervisor::SwitchState(_) | ToSupervisor::Stats(_) | ToSupervisor::Tracks(_) => {
                }
                other => panic!("unexpected at shutdown: {other:?}"),
            }
        }
        assert!(matches!(h.worker.await, Ok(Ok(ExitReason::Shutdown))));
    }

    #[tokio::test]
    async fn a_switch_before_any_source_is_a_protocol_error() {
        let mut h = start();
        h.tx.send_msg(&ToWorker::SwitchConnectGranted, &[])
            .await
            .unwrap();
        h.tx.send_msg(&ToWorker::SwitchSource(spec("fake://cam/", "{}")), &[])
            .await
            .unwrap();
        assert!(matches!(h.next().await, ToSupervisor::Ready { .. }));
        assert!(matches!(
            h.worker.await,
            Ok(Err(Error::SwitchWithoutSource))
        ));
    }

    /// Reads the worker's messages, granting the connection, until the
    /// source reports live, without moving the fake clock. Going live takes
    /// a fake source without `ready_after_ms` no fake time, so a test that
    /// steps the clock freely waits here first: stepped before the source
    /// declares its tracks, the clock outruns a worker a loaded machine
    /// starves and passes the sessions' 10 s ready timeout.
    async fn until_live(h: &mut Harness) {
        while !matches!(h.next().await, ToSupervisor::SourceState(SourceState::Live)) {}
    }

    /// Starts the session manager on fresh sockets and the fake source,
    /// and opens the echoing session `echo` (ufrag `ufrag-echo`) while the
    /// source is not live yet: it waits for the tracks, then answers.
    /// Returns the demux's end of the datagram channel and the shared
    /// socket's loopback address.
    async fn live_echo_session(
        h: &mut Harness,
    ) -> (std::os::unix::net::UnixDatagram, std::net::SocketAddr) {
        // Bound to the unspecified address as the supervisor's socket is by
        // default, so each echo leaves from the address its datagram
        // arrived on, the one the demux names.
        let shared = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let shared_addr = std::net::SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            shared.local_addr().unwrap().port(),
        );
        let (datagrams, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        h.tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(shared).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        h.tx.send_msg(
            &ToWorker::RunSource(spec("fake://cam/", r#"{"ready_after_ms": 1000}"#)),
            &[],
        )
        .await
        .unwrap();
        let mut spec = session_spec("echo");
        spec.offer = "v=0".into();
        h.tx.send_msg(&ToWorker::OpenSession(spec), &[])
            .await
            .unwrap();
        // The source's sleep starts when the runner gets to it, the
        // session's 10 s ready timeout when the session task does: step the
        // clock until the answer, paced in real time so a busy machine
        // cannot run the clock past the timeout before the runner starts.
        let mut steps = 0;
        let answered = loop {
            steps += 1;
            assert!(steps < 2_000, "no answer within 100 s of fake time");
            tokio::select! {
                event = next_session(h) => break event,
                () = SystemClock.sleep(Duration::from_millis(5)) => h.clock.advance(Duration::from_millis(50)),
            }
        };
        assert_eq!(
            answered,
            (
                "echo".to_owned(),
                SessionEvent::Answer {
                    sdp: ECHO_ANSWER.to_owned()
                }
            )
        );
        (
            std::os::unix::net::UnixDatagram::from(datagrams),
            shared_addr,
        )
    }

    /// The next session event, skipping stats.
    async fn next_session(h: &mut Harness) -> (String, SessionEvent) {
        loop {
            if let ToSupervisor::Session { session_id, event } = h.next().await {
                return (session_id, event);
            }
        }
    }

    /// Waits for a session's answer, moving the fake clock until the source
    /// is ready; the session events before it are skipped. Returns its SDP.
    async fn answered(h: &mut Harness) -> String {
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 2_000, "no answer within 100 s of fake time");
            tokio::select! {
                (_, event) = next_session(h) => if let SessionEvent::Answer { sdp } = event {
                    return sdp;
                },
                () = SystemClock.sleep(Duration::from_millis(5)) => {
                    h.clock.advance(Duration::from_millis(50));
                }
            }
        }
    }

    /// The worker's end, or a failed test after ten seconds of real time:
    /// a worker that ignores its `Shutdown` fails the test instead of
    /// hanging it.
    async fn ended(
        worker: JoinHandle<Result<ExitReason, Error>>,
    ) -> Result<Result<ExitReason, Error>, tokio::task::JoinError> {
        tokio::select! {
            ended = worker => ended,
            () = SystemClock.sleep(Duration::from_secs(10)) => panic!("the worker did not end within 10 s"),
        }
    }

    /// `future`'s output, or a failed test after five seconds of real time.
    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::select! {
            output = future => output,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
        }
    }

    /// Steps the fake clock 20 ms at a time until `want` holds for a
    /// session event, which it returns; ten seconds of real time fail the
    /// test instead of hanging it. The steps do not wait for the worker,
    /// so the clock may run far ahead of it: only for a live source with
    /// [`quiet_settings`] (see [`until_live`]), where no timeout it could
    /// pass changes what the test sees.
    async fn session_event_where(
        h: &mut Harness,
        want: impl Fn(&SessionEvent) -> bool,
    ) -> SessionEvent {
        let deadline = SystemClock.now() + Duration::from_secs(10);
        loop {
            assert!(
                SystemClock.now() < deadline,
                "no such session event within 10 s"
            );
            tokio::select! {
                (_, event) = next_session(h) => if want(&event) {
                    return event;
                },
                () = tokio::task::yield_now() => h.clock.advance(Duration::from_millis(20)),
            }
        }
    }

    // Multi-threaded, so a session task that never yields cannot keep the
    // test from failing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_gets_the_streams_audio_and_its_packets() {
        let mut h = start_with_settings(echo_registries(), quiet_settings());
        h.next().await;
        let shared = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_datagrams, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        h.tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(shared).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        h.tx.send_msg(
            &ToWorker::RunSource(spec("fake://cam/", r#"{"audio": true}"#)),
            &[],
        )
        .await
        .unwrap();
        until_live(&mut h).await;
        let mut session = session_spec("sound");
        session.audio = true;
        h.tx.send_msg(&ToWorker::OpenSession(session), &[])
            .await
            .unwrap();
        // Negotiation picked the PCMU track: the engine was opened with it.
        let answer =
            session_event_where(&mut h, |e| matches!(e, SessionEvent::Answer { .. })).await;
        assert_eq!(
            answer,
            SessionEvent::Answer {
                sdp: format!("{ECHO_ANSWER} audio=pcmu")
            }
        );
        // Its packets reach the engine; the echo reports the first.
        let first = session_event_where(
            &mut h,
            |e| matches!(e, SessionEvent::Warning { code, .. } if code == "echo_audio"),
        )
        .await;
        assert_eq!(
            first,
            SessionEvent::Warning {
                code: "echo_audio".into(),
                message: "the first audio packet arrived 0 ms after its capture".into()
            },
            "native audio maps through the clock mapper: by arrival here"
        );
    }

    // Multi-threaded, as above.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_orientation_change_reaches_the_answer_or_else_the_open_session() {
        let mut h = start_with(echo_registries());
        h.next().await;
        let shared = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_datagrams, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        h.tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(shared).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        h.tx.send_msg(
            &ToWorker::RunSource(spec("fake://cam/", r#"{"ready_after_ms": 1000}"#)),
            &[],
        )
        .await
        .unwrap();
        let turn = |orientation| ToWorker::SessionOrientation {
            session_id: "turn".into(),
            orientation,
        };
        // Changed while the session waits for the tracks: it answers with
        // the change, not with its spec's orientation.
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("turn")), &[])
            .await
            .unwrap();
        h.tx.send_msg(&turn(6), &[]).await.unwrap();
        assert_eq!(
            answered(&mut h).await,
            format!("{ECHO_ANSWER} orientation=rotate_left")
        );
        // Changed once answered: the engine turns the picture; an unknown
        // number is none, as at the open.
        for (code, name) in [(8, "rotate_right"), (0, "no_transform")] {
            h.tx.send_msg(&turn(code), &[]).await.unwrap();
            let warning = session_event_where(
                &mut h,
                |e| matches!(e, SessionEvent::Warning { code, .. } if code == "echo_orientation"),
            )
            .await;
            assert_eq!(
                warning,
                SessionEvent::Warning {
                    code: "echo_orientation".into(),
                    message: name.into()
                }
            );
        }
        // A change for no session is dropped.
        h.tx.send_msg(
            &ToWorker::SessionOrientation {
                session_id: "gone".into(),
                orientation: 3,
            },
            &[],
        )
        .await
        .unwrap();
        h.tx.send_msg(
            &ToWorker::CloseSession {
                session_id: "turn".into(),
                code: "session_closed".into(),
                message: String::new(),
            },
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            h.next_closed().await,
            ("turn".into(), "session_closed".into())
        );
    }

    /// Steps the fake clock 20 ms at a time until `want` holds for a
    /// message, which it returns; ten seconds of real time fail the test
    /// instead of hanging it. Unpaced, as [`session_event_where`].
    async fn message_where(h: &mut Harness, want: impl Fn(&ToSupervisor) -> bool) -> ToSupervisor {
        let deadline = SystemClock.now() + Duration::from_secs(10);
        loop {
            assert!(SystemClock.now() < deadline, "no such message within 10 s");
            tokio::select! {
                message = h.next() => if want(&message) {
                    return message;
                },
                () = tokio::task::yield_now() => h.clock.advance(Duration::from_millis(20)),
            }
        }
    }

    /// A worker with its sockets, running the fake source with an AAC
    /// track, the echo output and the forwarding AAC → Opus transcoder,
    /// which the test keeps to count its starts. Returns once the source
    /// is live, so the test may step the clock freely.
    async fn aac_worker() -> (Harness, Arc<derived::fake::Forwarding>) {
        aac_worker_with(
            derived::fake::Forwarding::default(),
            Arc::new(EchoSessionFactory),
        )
        .await
    }

    /// [`aac_worker`] with `transcoder` and `output`.
    async fn aac_worker_with(
        transcoder: derived::fake::Forwarding,
        output: Arc<dyn lotse_core::output::OutputFactory>,
    ) -> (Harness, Arc<derived::fake::Forwarding>) {
        aac_worker_on(r#"{"audio": "aac"}"#, transcoder, output).await
    }

    /// [`aac_worker_with`] running the fake source with `options`.
    async fn aac_worker_on(
        options: &str,
        transcoder: derived::fake::Forwarding,
        output: Arc<dyn lotse_core::output::OutputFactory>,
    ) -> (Harness, Arc<derived::fake::Forwarding>) {
        let transcoder = Arc::new(transcoder);
        let mut registries = Registries::default();
        registries
            .sources
            .register(Arc::new(FakeSourceFactory::new(&["fake"])))
            .unwrap();
        registries.outputs.register(output).unwrap();
        registries.transcoders.register(transcoder.clone());
        let mut h = start_with_settings(Arc::new(registries), quiet_settings());
        h.next().await;
        let shared = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_datagrams, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        h.tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(shared).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        h.tx.send_msg(&ToWorker::RunSource(spec("fake://cam/", options)), &[])
            .await
            .unwrap();
        until_live(&mut h).await;
        (h, transcoder)
    }

    fn has_track(message: &ToSupervisor, id: &str) -> Option<bool> {
        match message {
            ToSupervisor::Tracks(tracks) => Some(tracks.iter().any(|track| track.id == id)),
            _ => None,
        }
    }

    /// Steps the fake clock 20 ms at a time, keeping every message, until
    /// `done` holds for them; ten seconds of real time fail the test.
    /// Unpaced, as [`session_event_where`].
    async fn messages_until(
        h: &mut Harness,
        done: impl Fn(&[ToSupervisor]) -> bool,
    ) -> Vec<ToSupervisor> {
        let deadline = SystemClock.now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while !done(&seen) {
            assert!(SystemClock.now() < deadline, "not within 10 s: {seen:?}");
            tokio::select! {
                message = h.next() => seen.push(message),
                () = tokio::task::yield_now() => h.clock.advance(Duration::from_millis(20)),
            }
        }
        seen
    }

    /// The worker's messages until `done` holds for them, for at most 10 s,
    /// with the fake clock standing still: what the worker sends without
    /// any time passing. [`messages_until`] moves it while it waits.
    async fn messages_until_still(
        h: &mut Harness,
        done: impl Fn(&[ToSupervisor]) -> bool,
    ) -> Vec<ToSupervisor> {
        let mut seen = Vec::new();
        while !done(&seen) {
            tokio::select! {
                message = h.next() => seen.push(message),
                () = SystemClock.sleep(Duration::from_secs(10)) => panic!("not within 10 s: {seen:?}"),
            }
        }
        seen
    }

    /// The session events among `messages`.
    fn session_events(messages: &[ToSupervisor]) -> impl Iterator<Item = (&str, &SessionEvent)> {
        messages.iter().filter_map(|message| match message {
            ToSupervisor::Session { session_id, event } => Some((session_id.as_str(), event)),
            _ => None,
        })
    }

    fn answers(messages: &[ToSupervisor]) -> Vec<&SessionEvent> {
        session_events(messages)
            .filter(|(_, event)| matches!(event, SessionEvent::Answer { .. }))
            .map(|(_, event)| event)
            .collect()
    }

    fn closed(messages: &[ToSupervisor], id: &str) -> bool {
        session_events(messages)
            .any(|(session, event)| session == id && matches!(event, SessionEvent::Closed { .. }))
    }

    fn echo_audio(messages: &[ToSupervisor]) -> Option<&SessionEvent> {
        session_events(messages).map(|(_, event)| event).find(
            |event| matches!(event, SessionEvent::Warning { code, .. } if code == "echo_audio"),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[expect(clippy::too_many_lines, reason = "one derived track's whole life")]
    async fn an_aac_stream_gets_opus_from_one_transcoder_its_sessions_share() {
        let (mut h, transcoder) = aac_worker().await;
        // Two sessions open at once.
        for id in ["one", "two"] {
            let mut session = session_spec(id);
            session.audio = true;
            h.tx.send_msg(&ToWorker::OpenSession(session), &[])
                .await
                .unwrap();
        }
        let seen = messages_until(&mut h, |seen| {
            answers(seen).len() == 2
                && echo_audio(seen).is_some()
                && seen.iter().any(|m| has_track(m, "a1") == Some(true))
        })
        .await;
        // Negotiation picked the derived Opus track for the AAC one.
        for answer in answers(&seen) {
            assert_eq!(
                *answer,
                SessionEvent::Answer {
                    sdp: format!("{ECHO_ANSWER} audio=opus")
                }
            );
        }
        assert_eq!(transcoder.started(), 1, "one transcoder for both");

        // The derived packets reach the engine with the capture time of
        // their side-branch frame, not their arrival.
        assert_eq!(
            echo_audio(&seen),
            Some(&SessionEvent::Warning {
                code: "echo_audio".into(),
                message: format!(
                    "the first audio packet arrived {} ms after its capture",
                    derived::fake::SHIFT.as_millis()
                ),
            })
        );

        // Reported when it appeared: the derived track, what it came from,
        // its delay; then its counters.
        let Some(ToSupervisor::Tracks(tracks)) =
            seen.iter().find(|m| has_track(m, "a1") == Some(true))
        else {
            panic!("tracks");
        };
        let a1 = tracks.iter().find(|track| track.id == "a1").unwrap();
        assert_eq!(
            (
                a1.codec.as_str(),
                a1.clock_rate,
                a1.derived_from.as_deref(),
                a1.audio_delay_ms
            ),
            (
                "opus",
                48_000,
                Some("a0"),
                Some(u32::try_from(derived::fake::DELAY.as_millis()).unwrap())
            )
        );
        assert_eq!(a1.sync, "arrival", "its source's");
        let a0 = tracks.iter().find(|track| track.id == "a0").unwrap();
        assert_eq!(
            (
                a0.codec.as_str(),
                a0.derived_from.as_ref(),
                a0.audio_delay_ms
            ),
            ("aac_lc", None, None)
        );
        let ToSupervisor::Stats(stats) = message_where(&mut h, |m| {
            matches!(m, ToSupervisor::Stats(stats) if stats.tracks.iter().any(|(id, t)| id == "a1" && t.packets > 0))
        })
        .await
        else {
            panic!("stats");
        };
        assert_eq!(stats.sessions, 2);

        // The first to leave keeps it running; the last stops it.
        h.tx.send_msg(
            &ToWorker::CloseSession {
                session_id: "one".into(),
                code: "session_closed".into(),
                message: String::new(),
            },
            &[],
        )
        .await
        .unwrap();
        messages_until(&mut h, |seen| closed(seen, "one")).await;
        assert!(!transcoder.stopped(0));
        h.tx.send_msg(
            &ToWorker::CloseSession {
                session_id: "two".into(),
                code: "session_closed".into(),
                message: String::new(),
            },
            &[],
        )
        .await
        .unwrap();
        messages_until(&mut h, |seen| {
            closed(seen, "two") && seen.iter().any(|m| has_track(m, "a1") == Some(false))
        })
        .await;
        assert!(transcoder.stopped(0), "the last session left");
        assert_eq!(transcoder.started(), 1);
        // Closed sessions stop counting without another opening: the soak
        // waits for every worker to report none.
        let ToSupervisor::Stats(stats) = message_where(
            &mut h,
            |m| matches!(m, ToSupervisor::Stats(stats) if stats.sessions == 0),
        )
        .await
        else {
            panic!("stats");
        };
        assert_eq!(stats.sessions, 0);

        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_derived_track_is_reported_when_it_starts_not_with_the_next_counters() {
        let (mut h, _transcoder) = aac_worker_with(
            derived::fake::Forwarding::default(),
            Arc::new(EchoSessionFactory),
        )
        .await;
        let mut session = session_spec("transcoded");
        session.audio = true;
        h.tx.send_msg(&ToWorker::OpenSession(session), &[])
            .await
            .unwrap();
        // The fake clock stands still, so no counters come: the tracks come
        // with the transcoder.
        loop {
            let message = h.next().await;
            assert!(!matches!(message, ToSupervisor::Stats(_)), "{message:?}");
            if has_track(&message, "a1") == Some(true) {
                break;
            }
        }
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    /// The `sync` a `Tracks` message reports for track `id`.
    fn sync_of<'a>(message: &'a ToSupervisor, id: &str) -> Option<&'a str> {
        match message {
            ToSupervisor::Tracks(tracks) => tracks
                .iter()
                .find(|track| track.id == id)
                .map(|track| track.sync.as_str()),
            _ => None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc3550_6_4_1_tracks_synced_by_later_sender_reports_are_reported_again_once() {
        // The fake camera's first Sender Reports come a second after it
        // went live (RFC 3550 §6.4.1), after the tracks were reported.
        let mut h = start_with_settings(registries(), quiet_settings());
        assert!(matches!(h.next().await, ToSupervisor::Ready { .. }));
        h.tx.send_msg(
            &ToWorker::RunSource(spec("fake://cam/", r#"{"audio": "aac_drifting"}"#)),
            &[],
        )
        .await
        .unwrap();
        // Live with the fake clock standing still: moved while waiting, it
        // reached the first report's second before the worker's messages
        // arrived on a slow runner (GitHub's, 2026-10-09).
        let seen = messages_until_still(&mut h, |seen| {
            seen.contains(&ToSupervisor::SourceState(SourceState::Live))
        })
        .await;
        let announced = seen.iter().find(|m| sync_of(m, "v0").is_some()).unwrap();
        assert_eq!(sync_of(announced, "v0"), Some("arrival"));
        assert_eq!(sync_of(announced, "a0"), Some("arrival"));
        // Both map from the reports now, and the supervisor hears it.
        let seen = messages_until(&mut h, |seen| {
            seen.iter().any(|m| {
                sync_of(m, "v0") == Some("sender_reports")
                    && sync_of(m, "a0") == Some("sender_reports")
            })
        })
        .await;
        assert!(
            seen.iter()
                .all(|m| sync_of(m, "v0").is_none() || sync_of(m, "v0") == Some("sender_reports")),
            "{seen:?}"
        );
        // Nothing changes after: the next counters come without the tracks.
        let seen = messages_until(&mut h, |seen| {
            seen.iter()
                .filter(|m| matches!(m, ToSupervisor::Stats(_)))
                .count()
                >= 3
        })
        .await;
        assert!(
            seen.iter().all(|m| !matches!(m, ToSupervisor::Tracks(_))),
            "{seen:?}"
        );
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    fn av_sync_lost(messages: &[ToSupervisor], id: &str) -> bool {
        session_events(messages).any(|(session, event)| {
            session == id
                && matches!(event, SessionEvent::Warning { code, .. } if code == "av_sync_lost")
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn skew_watchdog_withdrawn_audio_stops_in_every_session_with_av_sync_lost() {
        // The camera's audio clock runs 2 % fast against its NTP clock.
        let (mut h, transcoder) = aac_worker_on(
            r#"{"audio": "aac_drifting"}"#,
            derived::fake::Forwarding::default(),
            Arc::new(EchoSessionFactory),
        )
        .await;
        let mut early = session_spec("early");
        early.audio = true;
        h.tx.send_msg(&ToWorker::OpenSession(early), &[])
            .await
            .unwrap();
        let seen = messages_until(&mut h, |seen| {
            echo_audio(seen).is_some() && seen.iter().any(|m| has_track(m, "a1") == Some(true))
        })
        .await;
        assert_eq!(
            answers(&seen),
            [&SessionEvent::Answer {
                sdp: format!("{ECHO_ANSWER} audio=opus")
            }]
        );
        assert!(!av_sync_lost(&seen, "early"));
        // Within a minute of drift the session hears it once, stops writing
        // audio and lets go of the transcoder, which no one else uses; the
        // stream's counter says so.
        let seen = messages_until(&mut h, |seen| {
            av_sync_lost(seen, "early")
                && seen.iter().any(|m| has_track(m, "a1") == Some(false))
                && seen
                    .iter()
                    .any(|m| matches!(m, ToSupervisor::Stats(stats) if stats.av_sync_lost == 1))
        })
        .await;
        assert!(!closed(&seen, "early"), "video goes on");
        assert!(transcoder.stopped(0));
        // A session opened now gets no audio: answered without it, told
        // why, and no transcoder starts.
        let mut late = session_spec("late");
        late.audio = true;
        h.tx.send_msg(&ToWorker::OpenSession(late), &[])
            .await
            .unwrap();
        let seen = messages_until(&mut h, |seen| {
            av_sync_lost(seen, "late") && !answers(seen).is_empty()
        })
        .await;
        assert_eq!(
            answers(&seen),
            [&SessionEvent::Answer {
                sdp: ECHO_ANSWER.to_owned()
            }]
        );
        assert_eq!(transcoder.started(), 1);
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transcoder_that_does_not_start_leaves_the_session_video_only_with_a_warning() {
        let refusing = derived::fake::Forwarding {
            refuse: true,
            ..derived::fake::Forwarding::default()
        };
        let (mut h, transcoder) = aac_worker_with(refusing, Arc::new(EchoSessionFactory)).await;
        let mut session = session_spec("mute");
        session.audio = true;
        h.tx.send_msg(&ToWorker::OpenSession(session), &[])
            .await
            .unwrap();
        let warning =
            session_event_where(&mut h, |e| matches!(e, SessionEvent::Warning { .. })).await;
        assert!(
            matches!(&warning, SessionEvent::Warning { code, .. } if code == "audio_codec_unsupported"),
            "{warning:?}"
        );
        let answer =
            session_event_where(&mut h, |e| matches!(e, SessionEvent::Answer { .. })).await;
        assert_eq!(
            answer,
            SessionEvent::Answer {
                sdp: ECHO_ANSWER.to_owned()
            },
            "video only"
        );
        assert_eq!(transcoder.started(), 0);
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    /// An echo output that wants H.265 video, which the fake source lacks.
    #[derive(Debug)]
    struct WantsH265;

    impl lotse_core::output::OutputFactory for WantsH265 {
        fn kind(&self) -> &'static str {
            "webrtc"
        }

        fn shape(&self) -> OutputShape {
            OutputShape::Session
        }

        fn session_tracks(&self, audio: bool) -> Vec<lotse_core::output::TrackRequest> {
            let mut requests = EchoSessionFactory.session_tracks(audio);
            requests[0].accept = vec![lotse_core::codec::CodecFamily::H265];
            requests
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unmet_video_request_closes_the_session_and_stops_what_audio_started() {
        let (mut h, transcoder) =
            aac_worker_with(derived::fake::Forwarding::default(), Arc::new(WantsH265)).await;
        let mut session = session_spec("h265");
        session.audio = true;
        h.tx.send_msg(&ToWorker::OpenSession(session), &[])
            .await
            .unwrap();
        let closed =
            session_event_where(&mut h, |e| matches!(e, SessionEvent::Closed { .. })).await;
        assert!(
            matches!(&closed, SessionEvent::Closed { code, .. } if code == "video_codec_unsupported"),
            "{closed:?}"
        );
        // The audio was negotiated together with the video: its transcoder
        // started and stopped with the session that never opened.
        assert_eq!(transcoder.started(), 1);
        assert!(transcoder.stopped(0));
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audio_off_on_an_aac_stream_starts_no_transcoder() {
        let (mut h, transcoder) = aac_worker().await;
        // `audio: "off"` on the stream: the session asks for video only.
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("quiet")), &[])
            .await
            .unwrap();
        let answer =
            session_event_where(&mut h, |e| matches!(e, SessionEvent::Answer { .. })).await;
        assert_eq!(
            answer,
            SessionEvent::Answer {
                sdp: ECHO_ANSWER.to_owned()
            },
            "no audio"
        );
        let ToSupervisor::Stats(stats) = message_where(
            &mut h,
            |m| matches!(m, ToSupervisor::Stats(stats) if stats.sessions == 1),
        )
        .await
        else {
            panic!("stats");
        };
        assert!(stats.tracks.iter().all(|(id, _)| id != "a1"));
        assert_eq!(transcoder.started(), 0);
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[expect(
        clippy::too_many_lines,
        reason = "one session's life over both transports"
    )]
    async fn a_live_session_answers_and_its_datagrams_round_trip_over_udp_and_ice_tcp() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut h = start_with(echo_registries());
        h.next().await;
        let (datagrams, shared_addr) = live_echo_session(&mut h).await;

        // UDP: the demux's frame in, the echo out on the shared socket.
        let browser = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut frame = Vec::new();
        lotse_ipc::datagram::encode(
            "ufrag-echo",
            browser.local_addr().unwrap(),
            shared_addr,
            b"over udp",
            &mut frame,
        );
        datagrams.send(&frame).unwrap();
        browser.set_nonblocking(true).unwrap();
        let browser = tokio::net::UdpSocket::from_std(browser).unwrap();
        let mut buf = [0_u8; 64];
        let (n, from) = tokio::select! {
            received = browser.recv_from(&mut buf) => received.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no echo over udp"),
        };
        assert_eq!((&buf[..n], from), (&b"over udp"[..], shared_addr));

        // A datagram that arrived on another of the host's addresses is
        // answered from that one (RFC 8445 §7.2.5.2.1), not from the one
        // the kernel routes from towards the browser; Linux has all of
        // 127.0.0.0/8 on `lo`, macOS 127.0.0.1 alone.
        #[cfg(target_os = "linux")]
        {
            let second = std::net::SocketAddr::new([127, 0, 0, 2].into(), shared_addr.port());
            lotse_ipc::datagram::encode(
                "ufrag-echo",
                browser.local_addr().unwrap(),
                second,
                b"to the second",
                &mut frame,
            );
            datagrams.send(&frame).unwrap();
            let (n, from) = within(browser.recv_from(&mut buf)).await.unwrap();
            assert_eq!((&buf[..n], from), (&b"to the second"[..], second));
        }

        // The audio track's packets leave marked EF (RFC 8837 §5), the rest
        // with the socket's own mark, none on this test socket.
        #[cfg(target_os = "linux")]
        {
            lotse_testing::dscp::report_marks(&browser).unwrap();
            for (payload, dscp) in [(&b"audio:x"[..], 46), (&b"video"[..], 0)] {
                lotse_ipc::datagram::encode(
                    "ufrag-echo",
                    browser.local_addr().unwrap(),
                    shared_addr,
                    payload,
                    &mut frame,
                );
                datagrams.send(&frame).unwrap();
                let (echoed, _, mark) = within(async {
                    loop {
                        browser.readable().await.unwrap();
                        if let Ok(received) = browser.try_io(tokio::io::Interest::READABLE, || {
                            Ok(lotse_testing::dscp::recv_marked(&browser)?)
                        }) {
                            break received;
                        }
                    }
                })
                .await;
                assert_eq!((&echoed[..], mark), (payload, Some(dscp)));
            }
        }

        // ICE-TCP: the first frame the supervisor read is answered on the
        // connection, then frames flow both ways.
        let (tcp_browser, fd, peer) = tcp_pair();
        h.tx.send_msg(
            &ToWorker::IceTcp {
                local_ufrag: "ufrag-echo".into(),
                peer,
                first_frame: b"first".to_vec(),
            },
            &[fd.as_fd()],
        )
        .await
        .unwrap();
        drop(fd);
        tcp_browser.set_nonblocking(true).unwrap();
        let mut tcp_browser = tokio::net::TcpStream::from_std(tcp_browser).unwrap();
        let mut echoed = [0_u8; 7];
        within(tcp_browser.read_exact(&mut echoed)).await.unwrap();
        assert_eq!(&echoed, b"\x00\x05first");
        tcp_browser.write_all(b"\x00\x03abc").await.unwrap();
        let mut echoed = [0_u8; 5];
        within(tcp_browser.read_exact(&mut echoed)).await.unwrap();
        assert_eq!(&echoed, b"\x00\x03abc");

        // An echo over ICE-TCP to an address with no connection: the send
        // fails and the stats count it, with the one open session.
        let mut frame = Vec::new();
        lotse_ipc::datagram::encode(
            "ufrag-echo",
            "192.0.2.77:5000".parse().unwrap(),
            shared_addr,
            b"tcp:nowhere",
            &mut frame,
        );
        datagrams.send(&frame).unwrap();
        let mut pushes = 0;
        let stats = loop {
            pushes += 1;
            assert!(pushes < 100, "no failed send within 100 stats pushes");
            tokio::task::yield_now().await;
            h.clock.advance(STATS_INTERVAL);
            if let ToSupervisor::Stats(stats) = h.next().await
                && stats.send_failures > 0
            {
                break stats;
            }
        };
        assert_eq!((stats.sessions, stats.send_failures), (1, 1));

        // Closed by the supervisor: the connection goes with the session.
        h.tx.send_msg(
            &ToWorker::CloseSession {
                session_id: "echo".into(),
                code: "session_closed".into(),
                message: "done".into(),
            },
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            h.next_closed().await,
            ("echo".to_owned(), "session_closed".to_owned())
        );
        assert!(matches!(tcp_browser.read(&mut [0_u8; 1]).await, Ok(0)));
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[expect(
        clippy::too_many_lines,
        reason = "one session's relay candidates, from before the answer to ChannelData"
    )]
    async fn rfc8656_12_4_what_leaves_a_relay_candidate_goes_to_its_server_as_channel_data() {
        let mut h = start_with(echo_registries());
        h.next().await;
        // Before the sockets there are no sessions to give a relay to.
        let relayed: std::net::SocketAddr = "203.0.113.1:49153".parse().unwrap();
        let relay = |session: &str, relayed, server| ToWorker::RelayCandidate {
            session_id: session.into(),
            relayed,
            server,
            local: "127.0.0.1:18556".parse().unwrap(),
            tcp: false,
        };
        let channel = |relayed, peer, channel| ToWorker::RelayChannel {
            session_id: "relay".into(),
            relayed,
            peer,
            channel,
        };
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        h.tx.send_msg(&relay("relay", relayed, server_addr), &[])
            .await
            .unwrap();
        h.tx.send_msg(&channel(relayed, server_addr, 0x4000), &[])
            .await
            .unwrap();
        let shared = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let shared_addr = shared.local_addr().unwrap();
        let (datagrams, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        h.tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(shared).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        h.tx.send_msg(
            &ToWorker::RunSource(spec("fake://cam/", r#"{"ready_after_ms": 1000}"#)),
            &[],
        )
        .await
        .unwrap();
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("relay")), &[])
            .await
            .unwrap();
        // Before the answer: the relay waits for the engine, a channel on
        // it is too early, and one for another session goes nowhere.
        h.tx.send_msg(&relay("relay", relayed, server_addr), &[])
            .await
            .unwrap();
        h.tx.send_msg(&channel(relayed, server_addr, 0x4000), &[])
            .await
            .unwrap();
        h.tx.send_msg(&relay("ghost", relayed, server_addr), &[])
            .await
            .unwrap();
        answered(&mut h).await;
        // The engine's line for the relay handed over early.
        assert_eq!(
            next_session(&mut h).await,
            (
                "relay".to_owned(),
                SessionEvent::Relayed {
                    relayed,
                    candidate: Some("candidate:echo 1 udp 1 203.0.113.1 49153 typ relay".into()),
                }
            )
        );
        // Once more at the same address, or one the engine refuses: no line.
        let refused: std::net::SocketAddr = "0.0.0.0:49154".parse().unwrap();
        for (again, server) in [(relayed, server_addr), (refused, server_addr)] {
            h.tx.send_msg(&relay("relay", again, server), &[])
                .await
                .unwrap();
            assert_eq!(
                next_session(&mut h).await,
                (
                    "relay".to_owned(),
                    SessionEvent::Relayed {
                        relayed: again,
                        candidate: None
                    }
                )
            );
        }

        // A peer's datagram at the relayed address: the echo leaves the
        // relay candidate, and its peer has no channel yet.
        let peer: std::net::SocketAddr = "192.0.2.9:50000".parse().unwrap();
        let datagrams = std::os::unix::net::UnixDatagram::from(datagrams);
        let send = |payload: &[u8]| {
            let mut frame = Vec::new();
            lotse_ipc::datagram::encode("ufrag-relay", peer, relayed, payload, &mut frame);
            datagrams.send(&frame).unwrap();
        };
        send(b"check");
        assert_eq!(
            next_session(&mut h).await,
            (
                "relay".to_owned(),
                SessionEvent::ChannelWanted { relayed, peer }
            )
        );
        // Asked for once; dropped until the binding arrives.
        send(b"again");
        // A direct echo behind it on the same queue: once it is back, the
        // session dropped "again".
        let browser = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut frame = Vec::new();
        lotse_ipc::datagram::encode(
            "ufrag-relay",
            browser.local_addr().unwrap(),
            shared_addr,
            b"sync",
            &mut frame,
        );
        datagrams.send(&frame).unwrap();
        let mut synced = [0_u8; 8];
        tokio::select! {
            received = browser.recv_from(&mut synced) => assert_eq!(&synced[..received.unwrap().0], b"sync"),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no direct echo"),
        }
        h.tx.send_msg(&channel(relayed, peer, 0x4001), &[])
            .await
            .unwrap();
        // The binding and the datagrams travel apart, so the datagram goes
        // again until one arrives after it, as ICE retransmits.
        let mut buf = [0_u8; 64];
        let mut attempts = 0;
        let (n, from) = loop {
            attempts += 1;
            assert!(attempts < 100, "no channel data");
            send(b"bound");
            tokio::select! {
                received = server.recv_from(&mut buf) => break received.unwrap(),
                () = SystemClock.sleep(Duration::from_millis(50)) => {}
            }
        };
        assert_eq!(
            (&buf[..n], from),
            (&b"\x40\x01\x00\x05bound"[..], shared_addr)
        );
        let stats = loop {
            tokio::task::yield_now().await;
            h.clock.advance(STATS_INTERVAL);
            if let ToSupervisor::Stats(stats) = h.next().await {
                break stats;
            }
        };
        assert_eq!((stats.sessions, stats.send_failures), (1, 0));
        // A server the IPv4 socket cannot send to: the relayed datagram
        // fails at the socket and is counted, as a full buffer would be.
        let unreachable: std::net::SocketAddr = "203.0.113.1:49155".parse().unwrap();
        h.tx.send_msg(
            &relay("relay", unreachable, "[::1]:3478".parse().unwrap()),
            &[],
        )
        .await
        .unwrap();
        h.tx.send_msg(&channel(unreachable, peer, 0x4002), &[])
            .await
            .unwrap();
        let mut frame = Vec::new();
        lotse_ipc::datagram::encode("ufrag-relay", peer, unreachable, b"x", &mut frame);
        let failures = loop {
            datagrams.send(&frame).unwrap();
            tokio::task::yield_now().await;
            h.clock.advance(STATS_INTERVAL);
            if let ToSupervisor::Stats(stats) = h.next().await
                && stats.send_failures > 0
            {
                break stats.send_failures;
            }
        };
        assert!(failures > 0);

        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc8656_12_5_what_leaves_a_tcp_relay_candidate_goes_to_the_supervisor_padded() {
        let mut h = start_with(echo_registries());
        h.next().await;
        let shared = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (datagrams, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        h.tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(shared).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        h.tx.send_msg(
            &ToWorker::RunSource(spec("fake://cam/", r#"{"ready_after_ms": 1000}"#)),
            &[],
        )
        .await
        .unwrap();
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("relay")), &[])
            .await
            .unwrap();
        answered(&mut h).await;
        let relayed: std::net::SocketAddr = "203.0.113.1:49156".parse().unwrap();
        let server: std::net::SocketAddr = "192.0.2.3:3478".parse().unwrap();
        let peer: std::net::SocketAddr = "192.0.2.9:50000".parse().unwrap();
        h.tx.send_msg(
            &ToWorker::RelayCandidate {
                session_id: "relay".into(),
                relayed,
                server,
                local: "127.0.0.1:18556".parse().unwrap(),
                tcp: true,
            },
            &[],
        )
        .await
        .unwrap();
        assert!(matches!(
            next_session(&mut h).await.1,
            SessionEvent::Relayed {
                candidate: Some(_),
                ..
            }
        ));
        h.tx.send_msg(
            &ToWorker::RelayChannel {
                session_id: "relay".into(),
                relayed,
                peer,
                channel: 0x4003,
            },
            &[],
        )
        .await
        .unwrap();
        // The echo leaves the relay candidate: padded, on the datagram
        // channel, named by the relayed address and the server.
        let datagrams = std::os::unix::net::UnixDatagram::from(datagrams);
        datagrams
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut frame = Vec::new();
        lotse_ipc::datagram::encode("ufrag-relay", peer, relayed, b"tcp", &mut frame);
        let mut uplink = vec![0_u8; 256];
        let len = (0..100)
            .find_map(|_| {
                datagrams.send(&frame).unwrap();
                datagrams.recv(&mut uplink).ok()
            })
            .expect("a frame for the supervisor");
        let decoded = lotse_ipc::datagram::decode(&uplink[..len]).unwrap();
        assert_eq!(
            (
                decoded.ufrag,
                decoded.source,
                decoded.destination,
                decoded.payload
            ),
            (
                "ufrag-relay",
                relayed,
                server,
                &b"\x40\x03\x00\x03tcp\0"[..]
            )
        );
        // A supervisor that does not read: once the channel is full, the
        // frames are dropped and counted.
        let mut big = Vec::new();
        lotse_ipc::datagram::encode("ufrag-relay", peer, relayed, &[7; 1_200], &mut big);
        loop {
            // The worker's end may fill too; what it refuses is not needed.
            let _sent = datagrams.send(&big);
            tokio::task::yield_now().await;
            h.clock.advance(STATS_INTERVAL);
            if let ToSupervisor::Stats(stats) = h.next().await
                && stats.send_failures > 0
            {
                break;
            }
        }
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test]
    async fn ice_tcp_hand_offs_reach_only_a_session_that_can_take_them() {
        let mut h = start();
        h.next().await;
        // No session manager yet: the connection is closed.
        let (browser, fd, peer) = tcp_pair();
        h.tx.send_msg(&ice_tcp("ufrag-x", peer), &[fd.as_fd()])
            .await
            .unwrap();
        drop(fd);
        assert!(closed_by_daemon(browser).await);
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_ours, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        h.tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(udp).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        // A hand-off without its descriptor is ignored.
        h.tx.send_msg(&ice_tcp("ufrag-x", "127.0.0.1:1".parse().unwrap()), &[])
            .await
            .unwrap();
        // A session still waiting for tracks has sent no answer, so no
        // browser can know its TCP candidate: closed.
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("waiting")), &[])
            .await
            .unwrap();
        let (browser, fd, peer) = tcp_pair();
        h.tx.send_msg(&ice_tcp("ufrag-waiting", peer), &[fd.as_fd()])
            .await
            .unwrap();
        drop(fd);
        assert!(closed_by_daemon(browser).await);
        // An unknown ufrag: closed.
        let (browser, fd, peer) = tcp_pair();
        h.tx.send_msg(&ice_tcp("ufrag-ghost", peer), &[fd.as_fd()])
            .await
            .unwrap();
        drop(fd);
        assert!(closed_by_daemon(browser).await);
        // The session ends; its task is gone: closed.
        h.clock.advance(Duration::from_secs(10));
        assert_eq!(
            h.next_closed().await,
            ("waiting".to_owned(), "source_not_live".to_owned())
        );
        let (browser, fd, peer) = tcp_pair();
        h.tx.send_msg(&ice_tcp("ufrag-waiting", peer), &[fd.as_fd()])
            .await
            .unwrap();
        drop(fd);
        assert!(closed_by_daemon(browser).await);
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    /// Lowers this process's descriptor limit to its lowest free
    /// descriptor, so the table has no room for another; returns the
    /// limit to restore. nextest runs each test in its own process.
    fn starve_descriptors() -> rustix::process::Rlimit {
        use std::os::fd::AsRawFd as _;
        let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        let probe = std::fs::File::open("/dev/null").unwrap();
        let lowest = u64::try_from(probe.as_raw_fd()).unwrap();
        drop(probe);
        let starved = rustix::process::Rlimit {
            current: Some(lowest),
            maximum: limit.maximum,
        };
        rustix::process::setrlimit(rustix::process::Resource::Nofile, starved).unwrap();
        limit
    }

    #[tokio::test]
    async fn a_hand_off_that_finds_no_free_descriptor_drops_its_connection_and_the_worker_lives() {
        // WRK-20: the worker's own descriptor table is full when an
        // ICE-TCP hand-off arrives; the kernel discards the connection
        // (Linux `MSG_CTRUNC`, macOS `EMFILE`). That costs the one
        // connection, never the worker and the camera's other viewers.
        let mut h = start();
        h.next().await;
        for _ in 0..2 {
            let (browser, fd, peer) = tcp_pair();
            let limit = starve_descriptors();
            h.tx.send_msg(&ice_tcp("ufrag-x", peer), &[fd.as_fd()])
                .await
                .unwrap();
            drop(fd);
            let closed = closed_by_daemon(browser).await;
            rustix::process::setrlimit(rustix::process::Resource::Nofile, limit).unwrap();
            assert!(closed);
        }
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test]
    async fn any_other_message_whose_descriptors_were_truncated_ends_the_worker() {
        // Only a hand-off can do without its descriptor: sockets the
        // sessions never got leave the worker unable to serve them.
        let h = start();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_ours, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        let mut tx = h.tx;
        let limit = starve_descriptors();
        tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(udp).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        let ended = within(h.worker).await.unwrap();
        rustix::process::setrlimit(rustix::process::Resource::Nofile, limit).unwrap();
        assert!(matches!(ended, Err(Error::Channel(IpcError::FdsTruncated))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flood_of_ice_tcp_hand_offs_keeps_the_worker_and_caps_the_sessions_connections() {
        // WRK-20: one session's viewer, or a replayer of its checks, has
        // hundreds of connections handed over. The session keeps the first
        // `MAX_LINKS` and closes the rest, so the worker's descriptors
        // last and the session's live connections keep working.
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut h = start_with(echo_registries());
        h.next().await;
        let _demux = live_echo_session(&mut h).await;
        let mut live = Vec::new();
        for n in 0..300 {
            let (browser, fd, peer) = tcp_pair();
            h.tx.send_msg(
                &ToWorker::IceTcp {
                    local_ufrag: "ufrag-echo".into(),
                    peer,
                    first_frame: b"first".to_vec(),
                },
                &[fd.as_fd()],
            )
            .await
            .unwrap();
            drop(fd);
            browser.set_nonblocking(true).unwrap();
            let mut browser = tokio::net::TcpStream::from_std(browser).unwrap();
            let mut echoed = [0_u8; 7];
            if n < ice_tcp::MAX_LINKS {
                within(browser.read_exact(&mut echoed)).await.unwrap();
                assert_eq!(&echoed, b"\x00\x05first");
                live.push(browser);
            } else {
                let read = within(browser.read(&mut echoed)).await;
                assert!(matches!(read, Ok(0)), "connection {n} is over the cap");
            }
        }
        for browser in &mut live {
            browser.write_all(b"\x00\x03abc").await.unwrap();
            let mut echoed = [0_u8; 5];
            within(browser.read_exact(&mut echoed)).await.unwrap();
            assert_eq!(&echoed, b"\x00\x03abc");
        }
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    /// The supervisor caps the daemon's sessions; the worker caps its own
    /// at that number too, rather than holding whatever it is sent.
    #[tokio::test]
    async fn a_session_beyond_the_workers_limit_is_refused() {
        let mut settings = settings();
        settings.max_sessions = 1;
        let mut h = start_with_settings(echo_registries(), settings);
        let _io = live_echo_session(&mut h).await;
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("second")), &[])
            .await
            .unwrap();
        assert_eq!(
            h.next_closed().await,
            ("second".to_owned(), "internal_error".to_owned())
        );
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test]
    async fn sessions_are_refused_with_codes_and_closed_on_shutdown() {
        let mut h = start();
        h.next().await;
        // Before the sockets: nothing to send on.
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("early")), &[])
            .await
            .unwrap();
        assert_eq!(
            h.next_closed().await,
            ("early".to_owned(), "internal_error".to_owned())
        );
        // A sockets message must carry two descriptors.
        h.tx.send_msg(&ToWorker::Sockets, &[]).await.unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (ours, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        h.tx.send_msg(
            &ToWorker::Sockets,
            &[OwnedFd::from(udp).as_fd(), theirs.as_fd()],
        )
        .await
        .unwrap();
        // Before a source runs.
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("nosource")), &[])
            .await
            .unwrap();
        assert_eq!(
            h.next_closed().await,
            ("nosource".to_owned(), "source_not_live".to_owned())
        );
        h.tx.send_msg(&ToWorker::RunSource(spec("fake://cam/", "null")), &[])
            .await
            .unwrap();
        // An output kind that is not compiled in.
        let mut hls = session_spec("hls");
        hls.kind = "hls".into();
        h.tx.send_msg(&ToWorker::OpenSession(hls), &[])
            .await
            .unwrap();
        assert_eq!(
            h.next_closed().await,
            ("hls".to_owned(), "internal_error".to_owned())
        );
        // The fake output wants no tracks, so negotiation finds no video.
        h.tx.send_msg(&ToWorker::OpenSession(session_spec("novideo")), &[])
            .await
            .unwrap();
        assert_eq!(
            h.next_closed().await,
            ("novideo".to_owned(), "no_video_track".to_owned())
        );
        // Unknown sessions are ignored; a malformed frame on the datagram
        // channel is counted, not fatal.
        h.tx.send_msg(
            &ToWorker::RemoteCandidate {
                session_id: "ghost".into(),
                candidate: String::new(),
            },
            &[],
        )
        .await
        .unwrap();
        h.tx.send_msg(
            &ToWorker::CloseSession {
                session_id: "ghost".into(),
                code: "session_closed".into(),
                message: String::new(),
            },
            &[],
        )
        .await
        .unwrap();
        let ours = std::os::unix::net::UnixDatagram::from(ours);
        ours.send(&[0xff, 0xff]).unwrap();
        h.clock.advance(STATS_INTERVAL);
        // The fake source's tracks and state, sent once its connect is
        // granted, may still be ahead of the report.
        while !matches!(h.next().await, ToSupervisor::Stats(_)) {}
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test]
    async fn ready_hands_the_memory_descriptor_over_and_the_worker_keeps_no_copy() {
        use tokio::io::AsyncReadExt as _;
        let (ours, theirs) = Channel::pair().unwrap();
        let worker_channel = Channel::from_fd(theirs).unwrap();
        let (memory, far_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let settings = settings();
        let worker = spawn_named("test.worker", async move {
            let clock: Arc<dyn Clock> = Arc::new(FakeClock::default());
            let memory = Some(OwnedFd::from(memory));
            serve(worker_channel, registries(), clock, &settings, memory).await
        });
        let (mut tx, mut rx) = ours.split();
        let (ready, fds) = rx.recv_msg::<ToSupervisor>().await.unwrap().unwrap();
        assert!(matches!(ready, ToSupervisor::Ready { .. }));
        assert_eq!(fds.len(), 1);
        // With the copy that arrived closed, none is left open anywhere.
        drop(fds);
        far_end.set_nonblocking(true).unwrap();
        let mut far_end = tokio::net::UnixStream::from_std(far_end).unwrap();
        assert_eq!(far_end.read(&mut [0_u8; 1]).await.unwrap(), 0);
        tx.send_msg(&ToWorker::Shutdown { deadline_ms: 1_000 }, &[])
            .await
            .unwrap();
        assert_eq!(within(worker).await.unwrap().unwrap(), ExitReason::Shutdown);
    }

    #[tokio::test]
    async fn runs_a_source_reports_its_states_and_tracks_and_stops_on_shutdown() {
        let mut h = start();
        assert!(matches!(h.next().await, ToSupervisor::Ready { .. }));
        h.tx.send_msg(&ToWorker::RunSource(spec("fake://cam/", "null")), &[])
            .await
            .unwrap();
        assert_eq!(
            h.next().await,
            ToSupervisor::SourceState(SourceState::Connecting { attempt: 1 })
        );
        let ToSupervisor::Tracks(tracks) = h.next().await else {
            panic!("tracks expected before live");
        };
        assert_eq!(h.next().await, ToSupervisor::SourceState(SourceState::Live));
        assert_eq!(tracks.len(), 1);
        assert_eq!(
            (tracks[0].id.as_str(), tracks[0].kind.as_str()),
            ("v0", "video")
        );
        assert_eq!(
            (tracks[0].codec.as_str(), tracks[0].clock_rate),
            ("h264", 90_000)
        );
        assert_eq!(tracks[0].sync, "arrival");

        h.clock.advance(STATS_INTERVAL);
        let ToSupervisor::Stats(stats) = h.next().await else {
            panic!("stats expected");
        };
        assert_eq!(stats.tracks.len(), 1);
        assert_eq!(stats.tracks[0].0, "v0");
        assert_eq!(stats.sessions, 0);

        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            h.next().await,
            ToSupervisor::SourceState(SourceState::Stopped)
        );
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
        assert!(
            h.rx.recv_msg::<ToSupervisor>().await.unwrap().is_none(),
            "channel closed"
        );
    }

    /// The worker's next message, read past the harness's grants.
    async fn raw(h: &mut Harness) -> ToSupervisor {
        h.rx.recv_msg::<ToSupervisor>().await.unwrap().unwrap().0
    }

    #[tokio::test]
    async fn the_source_connects_only_once_the_supervisor_grants_it() {
        let mut h = start();
        assert!(matches!(h.next().await, ToSupervisor::Ready { .. }));
        // A grant before there is a source is not kept for it.
        h.tx.send_msg(&ToWorker::ConnectGranted, &[]).await.unwrap();
        h.tx.send_msg(&ToWorker::RunSource(spec("fake://cam/", "null")), &[])
            .await
            .unwrap();
        // Read past the harness, which would grant at once.
        assert_eq!(
            raw(&mut h).await,
            ToSupervisor::SourceState(SourceState::Connecting { attempt: 1 })
        );
        tokio::select! {
            message = raw(&mut h) => panic!("connected without a grant: {message:?}"),
            () = SystemClock.sleep(Duration::from_millis(200)) => {}
        }
        h.tx.send_msg(&ToWorker::ConnectGranted, &[]).await.unwrap();
        assert!(matches!(raw(&mut h).await, ToSupervisor::Tracks(_)));
        assert_eq!(
            raw(&mut h).await,
            ToSupervisor::SourceState(SourceState::Live)
        );
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    fn source_state(message: &ToSupervisor) -> Option<&SourceState> {
        match message {
            ToSupervisor::SourceState(state) => Some(state),
            _ => None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_source_reports_reconnecting_then_backoff_with_their_codes() {
        let mut h = start();
        h.next().await;
        h.tx.send_msg(&ToWorker::RunSource(spec("fake://cam/", "null")), &[])
            .await
            .unwrap();
        // The fake video is silent: the watchdog drops the connection once
        // live, retries at once, and waits out the schedule the second time.
        let seen = messages_until(&mut h, |seen| {
            seen.iter()
                .any(|m| matches!(source_state(m), Some(SourceState::Backoff { .. })))
        })
        .await;
        let states: Vec<_> = seen.iter().filter_map(source_state).collect();
        let timeout = |code: &str, message: &str| {
            code == "source_timeout" && message.contains("no video for")
        };
        assert!(
            matches!(states.get(2), Some(SourceState::Reconnecting { code, message }) if timeout(code, message)),
            "connecting, live, reconnecting expected: {states:?}"
        );
        assert!(
            matches!(states.last(), Some(SourceState::Backoff { code, message, retry_ms })
                if timeout(code, message) && (800..=1_200).contains(retry_ms)),
            "backoff last: {states:?}"
        );
        h.tx.send_msg(&ToWorker::Shutdown { deadline_ms: 2_000 }, &[])
            .await
            .unwrap();
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::Shutdown
        );
    }

    #[tokio::test]
    async fn a_closed_channel_stops_the_worker() {
        let mut h = start();
        assert!(matches!(h.next().await, ToSupervisor::Ready { .. }));
        drop(h.tx);
        drop(h.rx);
        assert_eq!(
            ended(h.worker).await.unwrap().unwrap(),
            ExitReason::SupervisorGone
        );
    }

    #[tokio::test]
    async fn bad_specs_and_a_second_source_are_errors() {
        for (url, options, code) in [
            ("not a url", "null", "invalid_request"),
            ("rtsp://cam/", "null", "scheme_unsupported"),
            ("fake://cam/", "{not json", "invalid_request"),
            ("fake://cam/", "{\"transport\":\"udp\"}", "invalid_request"),
        ] {
            let mut h = start();
            h.next().await;
            h.tx.send_msg(&ToWorker::RunSource(spec(url, options)), &[])
                .await
                .unwrap();
            let err = within(h.worker).await.unwrap().unwrap_err();
            let Error::SourceRejected { code: got, .. } = err else {
                panic!("{url}: {err}");
            };
            assert_eq!(got, code, "{url}");
        }
        let mut h = start();
        h.next().await;
        h.tx.send_msg(&ToWorker::RunSource(spec("fake://cam/", "null")), &[])
            .await
            .unwrap();
        h.tx.send_msg(&ToWorker::RunSource(spec("fake://cam/", "null")), &[])
            .await
            .unwrap();
        assert!(matches!(
            within(h.worker).await.unwrap().unwrap_err(),
            Error::SecondSource
        ));
    }

    #[test]
    fn errors_display_and_seeds_differ_by_time() {
        assert_eq!(
            Error::SourceRejected {
                code: "scheme_unsupported",
                message: "x".into()
            }
            .to_string(),
            "source rejected (scheme_unsupported): x"
        );
        assert_eq!(
            Error::ShutdownTimeout(5).to_string(),
            "the source did not stop within 5 ms"
        );
        let clock = FakeClock::default();
        let a = jitter_seed(&clock);
        clock.advance(Duration::from_millis(1));
        assert_ne!(a, jitter_seed(&clock));
        assert_eq!(STATS_INTERVAL, Duration::from_secs(1));
    }
}
