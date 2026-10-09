//! The worker manager: the one place in the daemon that starts a process.
//! It re-executes the binary as `lotse worker` with an empty environment
//! and the control socketpair on stdin, relays the worker's reports, sees
//! its exit and stops it within the shutdown budget.
//!
//! A worker's messages are untrusted: every field is mapped onto a known
//! value here (an error code onto a `SourceError` variant, for example)
//! and never used as a path or a command, and what is kept is bounded
//! here: at most 32 tracks and track counters with short names, error
//! text cut and on one line. The frame cap alone would let a
//! worker hand the API a quarter MiB per `stream/get`.

use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::Clock;
use lotse_core::connection::WorkerReport;
use lotse_core::source::SourceError;
use lotse_core::task::spawn_named;
use lotse_core::text::plain;
use lotse_ipc::{Channel, IpcError, Receiver, Sender, SourceState, ToSupervisor, ToWorker};
pub use lotse_ipc::{SessionEvent, SessionSpec, SourceSpec, TrackInfo, WorkerStats};
use tokio::process::Child;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::task::AbortOnDropHandle;

use crate::memory::MemoryProbe;
use crate::net::turn_client::{RelayOwner, TurnClient, uplink};
use crate::worker_text::{MAX_MESSAGE_BYTES, MAX_NAME_BYTES};

/// The most tracks a worker may declare, and track counters it may report:
/// a camera declares a handful, a derived audio track adds one, and the
/// API copies each into every `stream/get` and `stream/list`.
pub(crate) const MAX_TRACKS: usize = 32;

/// How a worker is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConfig {
    /// The daemon's own executable, re-executed as `lotse worker`.
    pub binary: PathBuf,
    /// `--log-format` for the worker: `json` or `text`.
    pub log_format: String,
    /// `--log-level` for the worker.
    pub log_level: String,
    /// `--sandbox` for the worker: `on`, `require` or `off`.
    pub sandbox: String,
    /// `--worker-threads`.
    pub worker_threads: usize,
    /// `--worker-address-space`.
    pub worker_address_space: u64,
    /// `--max-sessions`: the daemon's `limits.max_sessions`, the most
    /// sessions one worker can be asked to hold.
    pub max_sessions: u32,
}

/// What a worker tells the supervisor, mapped onto trusted types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEvent {
    /// The worker is up and listening.
    Ready {
        /// The pid it reports; the supervisor knows it from the spawn.
        pid: u32,
        /// Its `smaps_rollup`, when it handed one over
        /// ([`memory`](crate::memory)).
        memory: Option<MemoryProbe>,
    },
    /// A source state the connection machine understands.
    Report(WorkerReport),
    /// The runner stopped (after a shutdown request).
    SourceStopped,
    /// The standby source's state; the connection's own is unchanged.
    SwitchReport(WorkerReport),
    /// The standby's runner stopped: replaced, or stopped with the worker.
    StandbyStopped,
    /// The tracks switched to the standby, which is the source now.
    Switched,
    /// The tracks, sent when the source goes live.
    Tracks(Vec<TrackInfo>),
    /// The once-per-second counters.
    Stats(WorkerStats),
    /// A session reported something.
    Session {
        /// The session.
        session_id: String,
        /// What happened.
        event: SessionEvent,
    },
    /// The worker closed its channel cleanly.
    ChannelClosed,
    /// The worker's channel failed: a malformed message or a broken pipe.
    ChannelError(String),
    /// The process exited, with this status.
    Exited(ExitStatus),
}

/// Why a worker could not be started.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// The socketpair could not be created.
    #[error("control socketpair: {0}")]
    Channel(#[source] io::Error),
    /// The datagram socketpair could not be created.
    #[error("datagram socketpair: {0}")]
    Datagrams(#[source] io::Error),
    /// The process could not be started.
    #[error("spawning {binary}: {source}")]
    Spawn {
        /// The executable.
        binary: PathBuf,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The child has no pid (it exited before it could be observed).
    #[error("the worker exited before it was observed")]
    Gone,
}

/// Starts and stops workers.
#[derive(Debug)]
pub struct WorkerManager {
    /// How workers are started.
    config: WorkerConfig,
    /// The shared WebRTC UDP socket every worker gets a duplicate of;
    /// `None` in tests that run no sessions.
    udp: Option<Arc<UdpSocket>>,
    /// The TURN client whose TCP allocations take what a worker's sessions
    /// send from their relay candidates, on its datagram channel.
    turn: Option<Arc<TurnClient>>,
}

impl WorkerManager {
    /// A manager starting workers as `config` says, handing each `udp`.
    pub const fn new(config: WorkerConfig, udp: Option<Arc<UdpSocket>>) -> Self {
        Self {
            config,
            udp,
            turn: None,
        }
    }

    /// Reads each worker's datagram channel for what its sessions send
    /// through `turn`'s TCP allocations ([`uplink`]).
    #[must_use]
    pub fn with_turn(mut self, turn: Option<Arc<TurnClient>>) -> Self {
        self.turn = turn;
        self
    }

    /// Starts a worker that may connect to `connect_ports` on its camera
    /// and, with `loopback_relay`, binds a loopback relay listener before
    /// its sandbox ([`SourceFactory::loopback_relay`](lotse_core::source::SourceFactory::loopback_relay)).
    /// Must run inside the runtime.
    #[expect(
        clippy::disallowed_methods,
        reason = "the one place that spawns a process"
    )]
    pub fn spawn(&self, connect_ports: &[u16], loopback_relay: bool) -> Result<Worker, SpawnError> {
        let (channel, theirs) = Channel::pair().map_err(SpawnError::Channel)?;
        let (datagrams_ours, datagrams_theirs) =
            lotse_ipc::datagram::datagram_pair().map_err(SpawnError::Datagrams)?;
        let datagrams = UnixDatagram::from(datagrams_ours);
        datagrams
            .set_nonblocking(true)
            .map_err(SpawnError::Datagrams)?;
        let relayed = match &self.turn {
            Some(turn) => Some((
                Arc::clone(turn),
                datagrams
                    .try_clone()
                    .and_then(tokio::net::UnixDatagram::from_std)
                    .map_err(SpawnError::Datagrams)?,
            )),
            None => None,
        };
        let mut command = tokio::process::Command::new(&self.config.binary);
        command
            .arg("worker")
            .arg("--log-format")
            .arg(&self.config.log_format)
            .arg("--log-level")
            .arg(&self.config.log_level)
            .arg("--sandbox")
            .arg(&self.config.sandbox)
            .arg("--worker-threads")
            .arg(self.config.worker_threads.to_string())
            .arg("--worker-address-space")
            .arg(self.config.worker_address_space.to_string())
            .arg("--max-sessions")
            .arg(self.config.max_sessions.to_string());
        if !connect_ports.is_empty() {
            let ports: Vec<String> = connect_ports.iter().map(u16::to_string).collect();
            command.arg("--connect-ports").arg(ports.join(","));
        }
        if loopback_relay {
            command.arg("--loopback-relay");
        }
        command
            .env_clear()
            .stdin(Stdio::from(theirs))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let child = command.spawn().map_err(|source| SpawnError::Spawn {
            binary: self.config.binary.clone(),
            source,
        })?;
        let pid = child.id().ok_or(SpawnError::Gone)?;
        let (control, rx) = channel.split();
        let (events_tx, events) = mpsc::channel(64);
        let reader = spawn_named("worker.relay", relay(rx, events_tx));
        let relay_owner = RelayOwner::next();
        let uplink = relayed.map(|(turn, ours)| {
            AbortOnDropHandle::new(spawn_named(
                "worker.uplink",
                uplink(turn, ours, relay_owner),
            ))
        });
        tracing::info!(pid, connect_ports = ?connect_ports, loopback_relay, "worker spawned");
        Ok(Worker {
            pid,
            child,
            control,
            events,
            reader,
            _uplink: uplink,
            relay_owner,
            datagrams: Arc::new(datagrams),
            pending_sockets: self
                .udp
                .as_ref()
                .map(|udp| (Arc::clone(udp), datagrams_theirs)),
            killed: false,
        })
    }
}

/// Reads the worker's messages and relays them as events until the
/// channel ends.
async fn relay(mut rx: Receiver, events: mpsc::Sender<WorkerEvent>) {
    // Only the first message may hand over a descriptor: it is sent before
    // the worker reads anything from the network ([`ToSupervisor::Ready`]).
    let mut first = true;
    loop {
        let event = match rx.recv_msg::<ToSupervisor>().await {
            Ok(Some((message, fds))) => {
                let memory = fds.into_iter().next().filter(|_| first);
                first = false;
                map_message(message, memory)
            }
            Ok(None) => WorkerEvent::ChannelClosed,
            Err(err) => WorkerEvent::ChannelError(err.to_string()),
        };
        let last = matches!(
            event,
            WorkerEvent::ChannelClosed | WorkerEvent::ChannelError(_)
        );
        if events.send(event).await.is_err() || last {
            break;
        }
    }
}

/// A worker message as a trusted event; `memory` is the descriptor that
/// came with it, kept only for `Ready` and closed otherwise.
fn map_message(message: ToSupervisor, memory: Option<OwnedFd>) -> WorkerEvent {
    match message {
        ToSupervisor::Ready { pid } => WorkerEvent::Ready {
            pid,
            memory: memory.map(MemoryProbe::from_fd),
        },
        ToSupervisor::SourceState(state) => match state {
            SourceState::Connecting { .. } => WorkerEvent::Report(WorkerReport::Connecting),
            SourceState::Live => WorkerEvent::Report(WorkerReport::Live),
            SourceState::Reconnecting { code, message } => {
                WorkerEvent::Report(WorkerReport::Reconnecting(source_error(&code, &message)))
            }
            SourceState::Backoff {
                code,
                message,
                retry_ms,
            } => WorkerEvent::Report(WorkerReport::Backoff {
                error: source_error(&code, &message),
                retry_in: Duration::from_millis(u64::from(retry_ms)),
            }),
            SourceState::Stopped => WorkerEvent::SourceStopped,
        },
        ToSupervisor::SwitchState(state) => match state {
            SourceState::Connecting { .. } => WorkerEvent::SwitchReport(WorkerReport::Connecting),
            SourceState::Live => WorkerEvent::SwitchReport(WorkerReport::Live),
            SourceState::Reconnecting { code, message } => {
                WorkerEvent::SwitchReport(WorkerReport::Reconnecting(source_error(&code, &message)))
            }
            SourceState::Backoff {
                code,
                message,
                retry_ms,
            } => WorkerEvent::SwitchReport(WorkerReport::Backoff {
                error: source_error(&code, &message),
                retry_in: Duration::from_millis(u64::from(retry_ms)),
            }),
            SourceState::Stopped => WorkerEvent::StandbyStopped,
        },
        ToSupervisor::Switched => WorkerEvent::Switched,
        ToSupervisor::Tracks(tracks) => WorkerEvent::Tracks(declared(tracks)),
        ToSupervisor::Stats(stats) => WorkerEvent::Stats(counted(stats)),
        ToSupervisor::Session { session_id, event } => WorkerEvent::Session { session_id, event },
    }
}

/// The tracks of a worker's declaration the supervisor keeps: the first
/// [`MAX_TRACKS`] whose names fit [`MAX_NAME_BYTES`].
fn declared(tracks: Vec<TrackInfo>) -> Vec<TrackInfo> {
    let declared = tracks.len();
    let kept: Vec<TrackInfo> = tracks
        .into_iter()
        .filter(|track| {
            [&track.id, &track.kind, &track.codec, &track.sync]
                .into_iter()
                .chain(track.derived_from.as_ref())
                .all(|name| name.len() <= MAX_NAME_BYTES)
        })
        .take(MAX_TRACKS)
        .collect();
    if kept.len() < declared {
        tracing::warn!(
            declared,
            kept = kept.len(),
            limit = MAX_TRACKS,
            "a worker declared too many tracks or over-long names; the rest dropped"
        );
    }
    kept
}

/// A worker's counters with at most [`MAX_TRACKS`] tracks whose ids fit
/// [`MAX_NAME_BYTES`].
fn counted(mut stats: WorkerStats) -> WorkerStats {
    let reported = stats.tracks.len();
    stats.tracks.retain(|(id, _)| id.len() <= MAX_NAME_BYTES);
    stats.tracks.truncate(MAX_TRACKS);
    if stats.tracks.len() < reported {
        tracing::warn!(
            reported,
            kept = stats.tracks.len(),
            limit = MAX_TRACKS,
            "a worker counted too many tracks or over-long ids; the rest dropped"
        );
    }
    stats
}

/// A reported code and message as a `SourceError`, both made [`plain`];
/// an unknown code is a protocol error that keeps the code in its message.
fn source_error(code: &str, message: &str) -> SourceError {
    let message = plain(message, MAX_MESSAGE_BYTES);
    match code {
        "source_unreachable" => SourceError::Unreachable(message),
        "source_auth_failed" => SourceError::AuthFailed(message),
        "source_timeout" => SourceError::Timeout(message),
        "source_ended" => SourceError::Ended(message),
        "source_protocol_error" => SourceError::Protocol(message),
        other => SourceError::Protocol(format!("{}: {message}", plain(other, MAX_NAME_BYTES))),
    }
}

/// A running worker.
#[derive(Debug)]
pub struct Worker {
    /// The process id.
    pid: u32,
    /// The process.
    child: Child,
    /// The sending half of the control channel.
    control: Sender,
    /// The relayed events.
    events: mpsc::Receiver<WorkerEvent>,
    /// The relay task.
    reader: JoinHandle<()>,
    /// The task reading the datagram channel for the TCP relays, which
    /// ends with the worker.
    _uplink: Option<AbortOnDropHandle<()>>,
    /// What its uplink stamps on its frames, which the leases of its
    /// sessions' relay candidates are granted to.
    relay_owner: RelayOwner,
    /// The supervisor's end of the datagram channel, non-blocking.
    datagrams: Arc<UnixDatagram>,
    /// The sockets to hand over with the first message, until sent.
    pending_sockets: Option<(Arc<UdpSocket>, OwnedFd)>,
    /// [`Worker::kill`] was called.
    killed: bool,
}

impl Worker {
    /// The process id.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Who its frames for TCP allocations come from: the owner its
    /// sessions' relay leases are granted to.
    pub const fn relay_owner(&self) -> RelayOwner {
        self.relay_owner
    }

    /// The supervisor's end of the worker's datagram channel, for the
    /// demux to write uplink datagrams to.
    pub fn datagrams(&self) -> Arc<UnixDatagram> {
        Arc::clone(&self.datagrams)
    }

    /// Hands the worker its sockets with the first message it gets, so
    /// they are there whatever comes first.
    async fn send_pending_sockets(&mut self) -> Result<(), IpcError> {
        if let Some((udp, theirs)) = self.pending_sockets.take() {
            self.control
                .send_msg(&ToWorker::Sockets, &[udp.as_fd(), theirs.as_fd()])
                .await?;
        }
        Ok(())
    }

    /// Tells the worker which source to run.
    pub async fn run_source(&mut self, spec: &SourceSpec) -> Result<(), IpcError> {
        self.send_pending_sockets().await?;
        self.control
            .send_msg(&ToWorker::RunSource(spec.clone()), &[])
            .await
    }

    /// Lets the connection attempt the worker announced go ahead: the
    /// driver holds a connect permit for it.
    pub async fn grant_connect(&mut self) -> Result<(), IpcError> {
        self.control.send_msg(&ToWorker::ConnectGranted, &[]).await
    }

    /// Tells the worker to connect `spec` as the standby of its source and
    /// switch to it at its first keyframe.
    pub async fn switch_source(&mut self, spec: &SourceSpec) -> Result<(), IpcError> {
        self.control
            .send_msg(&ToWorker::SwitchSource(spec.clone()), &[])
            .await
    }

    /// Lets the standby's announced attempt go ahead.
    pub async fn grant_switch_connect(&mut self) -> Result<(), IpcError> {
        self.control
            .send_msg(&ToWorker::SwitchConnectGranted, &[])
            .await
    }

    /// Hands the worker an ICE-TCP connection whose first frame named one
    /// of its sessions.
    pub async fn ice_tcp(
        &mut self,
        stream: OwnedFd,
        local_ufrag: &str,
        peer: std::net::SocketAddr,
        first_frame: Vec<u8>,
    ) -> Result<(), IpcError> {
        let message = ToWorker::IceTcp {
            local_ufrag: local_ufrag.to_owned(),
            peer,
            first_frame,
        };
        self.control.send_msg(&message, &[stream.as_fd()]).await
    }

    /// Opens a viewer session on the worker's source; the answer and the
    /// rest arrive as [`WorkerEvent::Session`] events.
    pub async fn open_session(&mut self, spec: &SessionSpec) -> Result<(), IpcError> {
        self.send_pending_sockets().await?;
        self.control
            .send_msg(&ToWorker::OpenSession(spec.clone()), &[])
            .await
    }

    /// Passes a trickled remote candidate to a session.
    pub async fn candidate(&mut self, session_id: &str, candidate: &str) -> Result<(), IpcError> {
        self.control
            .send_msg(
                &ToWorker::RemoteCandidate {
                    session_id: session_id.to_owned(),
                    candidate: candidate.to_owned(),
                },
                &[],
            )
            .await
    }

    /// Hands a session the relay candidate at `relayed`, on the
    /// allocation `server` serves, over TCP when `tcp`; `local` is the host
    /// address its traffic leaves from. The worker reports its line as
    /// [`SessionEvent::Relayed`].
    pub async fn relay_candidate(
        &mut self,
        session_id: &str,
        relayed: std::net::SocketAddr,
        server: std::net::SocketAddr,
        local: std::net::SocketAddr,
        tcp: bool,
    ) -> Result<(), IpcError> {
        let message = ToWorker::RelayCandidate {
            session_id: session_id.to_owned(),
            relayed,
            server,
            local,
            tcp,
        };
        self.control.send_msg(&message, &[]).await
    }

    /// Hands a session the channel bound to `peer` on its relay candidate
    /// at `relayed`.
    pub async fn relay_channel(
        &mut self,
        session_id: &str,
        relayed: std::net::SocketAddr,
        peer: std::net::SocketAddr,
        channel: u16,
    ) -> Result<(), IpcError> {
        let message = ToWorker::RelayChannel {
            session_id: session_id.to_owned(),
            relayed,
            peer,
            channel,
        };
        self.control.send_msg(&message, &[]).await
    }

    /// Tells a session its stream's orientation changed to the one
    /// numbered `orientation`.
    pub async fn session_orientation(
        &mut self,
        session_id: &str,
        orientation: u8,
    ) -> Result<(), IpcError> {
        let message = ToWorker::SessionOrientation {
            session_id: session_id.to_owned(),
            orientation,
        };
        self.control.send_msg(&message, &[]).await
    }

    /// Closes a session with this `closed` code.
    pub async fn close_session(
        &mut self,
        session_id: &str,
        code: &str,
        message: &str,
    ) -> Result<(), IpcError> {
        self.control
            .send_msg(
                &ToWorker::CloseSession {
                    session_id: session_id.to_owned(),
                    code: code.to_owned(),
                    message: message.to_owned(),
                },
                &[],
            )
            .await
    }

    /// The next event: a relayed message, or the exit. After `Exited`, every
    /// call returns `Exited` again.
    pub async fn next_event(&mut self) -> WorkerEvent {
        tokio::select! {
            biased;
            Some(event) = self.events.recv() => event,
            status = self.child.wait() => match status {
                Ok(status) => WorkerEvent::Exited(status),
                Err(err) => WorkerEvent::ChannelError(format!("waiting for the worker: {err}")),
            },
        }
    }

    /// Kills the process for `reason`, once: one whose channel ended, or
    /// that went silent, can no longer be told to stop. Its exit arrives as
    /// [`WorkerEvent::Exited`], which counts as a crash.
    pub fn kill(&mut self, reason: &'static str) {
        if self.killed {
            return;
        }
        self.killed = true;
        tracing::warn!(pid = self.pid, reason, "worker killed");
        // Fails only for a process already reaped, whose exit is there.
        let _already_gone = self.child.start_kill();
    }

    /// Asks the worker to shut down within `budget`, then kills it if it is
    /// still there. Returns how it exited.
    pub async fn stop(mut self, budget: Duration, clock: &Arc<dyn Clock>) -> ExitStatus {
        let deadline_ms = u32::try_from(budget.as_millis()).unwrap_or(u32::MAX);
        if let Err(err) = self
            .control
            .send_msg(&ToWorker::Shutdown { deadline_ms }, &[])
            .await
        {
            tracing::debug!(pid = self.pid, error = %err, "worker unreachable for shutdown; killing");
        }
        let status = tokio::select! {
            status = self.child.wait() => status,
            () = clock.sleep(budget) => {
                tracing::warn!(pid = self.pid, budget_ms = deadline_ms, "worker missed the shutdown budget; killing");
                let _already_gone = self.child.start_kill();
                self.child.wait().await
            }
        };
        self.reader.abort();
        match status {
            Ok(status) => {
                tracing::info!(pid = self.pid, code = status.code(), "worker exited");
                status
            }
            Err(err) => {
                tracing::error!(pid = self.pid, error = %err, "worker exit could not be observed");
                ExitStatus::default()
            }
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
    use crate::test_support::Captured;

    #[test]
    fn messages_map_onto_trusted_events() {
        assert_eq!(
            map_message(ToSupervisor::Ready { pid: 4 }, None),
            WorkerEvent::Ready {
                pid: 4,
                memory: None
            }
        );
        assert_eq!(
            map_message(
                ToSupervisor::SourceState(SourceState::Connecting { attempt: 3 }),
                None
            ),
            WorkerEvent::Report(WorkerReport::Connecting)
        );
        assert_eq!(
            map_message(ToSupervisor::SourceState(SourceState::Live), None),
            WorkerEvent::Report(WorkerReport::Live)
        );
    }

    #[test]
    fn standby_states_map_onto_switch_reports() {
        // The standby's states are its own reports, apart from the
        // connection's; a stopped standby and the switch have their events.
        for (state, report) in [
            (
                SourceState::Connecting { attempt: 1 },
                WorkerReport::Connecting,
            ),
            (SourceState::Live, WorkerReport::Live),
            (
                SourceState::Reconnecting {
                    code: "source_timeout".into(),
                    message: "stall".into(),
                },
                WorkerReport::Reconnecting(SourceError::Timeout("stall".into())),
            ),
            (
                SourceState::Backoff {
                    code: "source_unreachable".into(),
                    message: "refused".into(),
                    retry_ms: 500,
                },
                WorkerReport::Backoff {
                    error: SourceError::Unreachable("refused".into()),
                    retry_in: Duration::from_millis(500),
                },
            ),
        ] {
            assert_eq!(
                map_message(ToSupervisor::SwitchState(state), None),
                WorkerEvent::SwitchReport(report)
            );
        }
        assert_eq!(
            map_message(ToSupervisor::SwitchState(SourceState::Stopped), None),
            WorkerEvent::StandbyStopped
        );
        assert_eq!(
            map_message(ToSupervisor::Switched, None),
            WorkerEvent::Switched
        );
        assert_eq!(
            map_message(
                ToSupervisor::SourceState(SourceState::Reconnecting {
                    code: "source_timeout".into(),
                    message: "stall".into()
                }),
                None
            ),
            WorkerEvent::Report(WorkerReport::Reconnecting(SourceError::Timeout(
                "stall".into()
            )))
        );
        assert_eq!(
            map_message(
                ToSupervisor::SourceState(SourceState::Backoff {
                    code: "made_up".into(),
                    message: "x".into(),
                    retry_ms: 1500
                }),
                None
            ),
            WorkerEvent::Report(WorkerReport::Backoff {
                error: SourceError::Protocol("made_up: x".into()),
                retry_in: Duration::from_millis(1500)
            })
        );
        assert_eq!(
            map_message(ToSupervisor::SourceState(SourceState::Stopped), None),
            WorkerEvent::SourceStopped
        );
        assert_eq!(
            map_message(ToSupervisor::Tracks(vec![]), None),
            WorkerEvent::Tracks(vec![])
        );
        assert_eq!(
            map_message(ToSupervisor::Stats(WorkerStats::default()), None),
            WorkerEvent::Stats(WorkerStats::default())
        );
        for (code, expect) in [
            ("source_unreachable", SourceError::Unreachable("m".into())),
            ("source_auth_failed", SourceError::AuthFailed("m".into())),
            ("source_ended", SourceError::Ended("m".into())),
            ("source_protocol_error", SourceError::Protocol("m".into())),
        ] {
            assert_eq!(source_error(code, "m"), expect);
        }
    }

    fn track(id: &str) -> TrackInfo {
        TrackInfo {
            id: id.into(),
            kind: "video".into(),
            codec: "h264".into(),
            clock_rate: 90_000,
            sync: "arrival".into(),
            derived_from: None,
            audio_delay_ms: None,
        }
    }

    #[test]
    fn a_worker_s_tracks_and_counters_are_capped_with_short_names() {
        let long = "x".repeat(MAX_NAME_BYTES + 1);
        let named = "x".repeat(MAX_NAME_BYTES);
        let mut tracks: Vec<TrackInfo> =
            (0..MAX_TRACKS + 8).map(|n| track(&n.to_string())).collect();
        tracks[0].id.clone_from(&long);
        tracks[1].kind.clone_from(&long);
        tracks[2].codec.clone_from(&long);
        tracks[3].sync.clone_from(&long);
        tracks[4].derived_from = Some(long.clone());
        tracks[5].id.clone_from(&named);
        tracks[6].derived_from = Some(named.clone());
        let captured = Captured::default();
        let _logs = captured.install();
        assert_eq!(
            map_message(ToSupervisor::Tracks(tracks.clone()), None),
            WorkerEvent::Tracks(tracks[5..5 + MAX_TRACKS].to_vec())
        );
        let few = vec![track("v0"), track("a0")];
        assert_eq!(declared(few.clone()), few);
        let lines = captured.lines("declared too many tracks");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("declared=40 kept=32 limit=32"),
            "{lines:?}"
        );

        let stats = |ids: &[&str]| WorkerStats {
            tracks: ids
                .iter()
                .map(|id| {
                    let counters = lotse_ipc::TrackStats {
                        packets: 1,
                        packet_bytes: 2,
                        frames: 3,
                        frame_bytes: 4,
                        keyframes: 5,
                        frames_dropped_oversize: 6,
                        frames_over_browser_limit: 7,
                    };
                    ((*id).to_owned(), counters)
                })
                .collect(),
            ..WorkerStats::default()
        };
        let ids: Vec<String> = (0..MAX_TRACKS + 8).map(|n| n.to_string()).collect();
        let mut reported: Vec<&str> = ids.iter().map(String::as_str).collect();
        reported[0] = &long;
        reported[1] = &named;
        assert_eq!(
            map_message(ToSupervisor::Stats(stats(&reported)), None),
            WorkerEvent::Stats(stats(&reported[1..=MAX_TRACKS]))
        );
        assert_eq!(counted(stats(&["v0"])), stats(&["v0"]));
        let lines = captured.lines("counted too many tracks");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("reported=40 kept=32 limit=32"),
            "{lines:?}"
        );
    }

    #[test]
    fn a_worker_s_source_error_is_plain_and_capped() {
        assert_eq!(
            source_error("source_timeout", &format!("a\nb\u{1b}{}", "x".repeat(1000))),
            SourceError::Timeout(format!("a b\u{fffd}{}", "x".repeat(MAX_MESSAGE_BYTES - 6)))
        );
        assert_eq!(
            source_error(&format!("\u{1b}{}", "c".repeat(100)), "m"),
            SourceError::Protocol(format!("\u{fffd}{}: m", "c".repeat(MAX_NAME_BYTES - 3)))
        );
    }

    #[tokio::test]
    async fn only_the_first_message_hands_over_a_memory_descriptor() {
        let (ours, theirs) = Channel::pair().unwrap();
        let (mut tx, theirs_rx) = Channel::from_fd(theirs).unwrap().split();
        let (_control, rx) = ours.split();
        let (events_tx, mut events) = mpsc::channel(4);
        let reader = spawn_named("test.relay", relay(rx, events_tx));
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        for _ in 0..2 {
            tx.send_msg(&ToSupervisor::Ready { pid: 7 }, &[a.as_fd()])
                .await
                .unwrap();
        }
        let has_memory = |event: WorkerEvent| match event {
            WorkerEvent::Ready { memory, .. } => memory.is_some(),
            _ => false,
        };
        assert!(
            has_memory(events.recv().await.unwrap()),
            "the first message's descriptor is kept"
        );
        assert!(!has_memory(WorkerEvent::ChannelClosed));
        assert_eq!(
            events.recv().await.unwrap(),
            WorkerEvent::Ready {
                pid: 7,
                memory: None
            },
            "a later one is closed"
        );
        drop((tx, theirs_rx));
        assert_eq!(events.recv().await.unwrap(), WorkerEvent::ChannelClosed);
        reader.await.unwrap();
    }

    #[tokio::test]
    async fn spawning_a_missing_binary_is_an_error() {
        let manager = WorkerManager::new(
            WorkerConfig {
                binary: PathBuf::from("/nonexistent/lotse"),
                log_format: "json".into(),
                log_level: "info".into(),
                sandbox: "off".into(),
                worker_threads: 1,
                worker_address_space: 1 << 30,
                max_sessions: 256,
            },
            None,
        );
        let err = manager.spawn(&[554], false).unwrap_err();
        assert!(matches!(err, SpawnError::Spawn { .. }), "{err}");
        assert!(err.to_string().contains("/nonexistent/lotse"));
        assert_eq!(
            SpawnError::Gone.to_string(),
            "the worker exited before it was observed"
        );
        assert!(
            SpawnError::Datagrams(io::Error::other("x"))
                .to_string()
                .starts_with("datagram socketpair")
        );
    }
}
