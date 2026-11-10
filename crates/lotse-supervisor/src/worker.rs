//! The worker manager: the one place in the daemon that starts a process.
//! It re-executes the binary as `lotse worker` with an empty environment
//! and the control socketpair on stdin, relays the worker's reports, sees
//! its exit and stops it within the shutdown budget.
//!
//! A worker's messages are untrusted: every field is mapped onto a known
//! value here (an error code onto a `SourceError` variant, for example)
//! and never used as a path or a command, and what is kept is bounded
//! here: at most 32 tracks and track counters with short names, a
//! backchannel codec and talk-back session ids that are short names, error
//! text and a signal's close cut and on one line, signal ids short. The frame cap alone would let a
//! worker hand the API a quarter MiB per `stream/get`. A trim is logged
//! once per worker, so a worker repeating an over-long message cannot
//! flood the log either.
//!
//! The worker must not hold the supervisor up either: every message to it
//! goes out within [`CONTROL_WRITE_DEADLINE`] or not at all. A worker that stops reading its control channel
//! fills the socket's send buffer, and a write would then wait for good;
//! one that waited out the deadline gives up on the channel, so every later
//! write fails at once, and kills the worker, whose exit runs the crash
//! path. Whoever sends to a worker is thus held up by at most the deadline.

use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lotse_api_types::stream::TalkerReason;
use lotse_core::backoff::BackoffPosition;
use lotse_core::clock::Clock;
use lotse_core::connection::WorkerReport;
use lotse_core::source::SourceError;
use lotse_core::task::spawn_named;
use lotse_core::text::plain;
use lotse_ipc::{Channel, IpcError, Receiver, Sender, SourceState, ToSupervisor, ToWorker};
pub use lotse_ipc::{
    RecordingReport, RecordingSpec, SessionEvent, SessionSpec, SignalCommand, SignalReport,
    SourceSpec, TrackInfo, WorkerStats,
};
use tokio::process::Child;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::task::AbortOnDropHandle;

use crate::memory::MemoryProbe;
use crate::net::turn_client::{RelayOwner, TurnClient, uplink};
use crate::recording::RecordingLimits;
use crate::worker_text::{MAX_MESSAGE_BYTES, MAX_NAME_BYTES};

/// The most tracks a worker may declare, and track counters it may report:
/// a camera declares a handful, a derived audio track adds one, and the
/// API copies each into every `stream/get` and `stream/list`.
pub(crate) const MAX_TRACKS: usize = 32;

/// How long one message to a worker may wait for room in its control
/// socket before the supervisor gives up on the worker: the write fails
/// with [`IpcError::Stalled`], as does every later one, and the worker is
/// killed.
///
/// A healthy worker takes its control messages as its loop turns, and the
/// socket's send buffer holds a few hundred of the usual ones (about
/// 208 KiB, `net.core.wmem_default`, observed on Linux 6.18, 2026-11-08),
/// so a write waits only once that much went unread: the worker's loop
/// stopped turning, or it never reads. The deadline only has to cover a
/// scheduling hiccup or a worker's start, not a slow peer, and two seconds
/// is far beyond either. It is the default shutdown budget
/// ([`SHUTDOWN_BUDGET`](crate::SHUTDOWN_BUDGET)), the time a healthy worker
/// is given to take its `Shutdown` and finish everything, so a driver held
/// up by a write still stops within the time the supervisor waits for its
/// drivers at shutdown; and a fifth of the ten seconds after which a
/// worker that sends nothing is taken for hung (the driver's
/// `WORKER_SILENCE_LIMIT`).
pub const CONTROL_WRITE_DEADLINE: Duration = Duration::from_secs(2);

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
    /// The worker's share of the recording limits, the same values the
    /// supervisor checks against: `--max-prerecord-bytes`, `--max-recording-ms`,
    /// `--recording-queue-bytes`, `--recording-start-timeout-ms` and `--max-recordings`.
    pub recordings: RecordingLimits,
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
    /// The probe of the device's backchannel with this id waits for a
    /// connect permit.
    ProbeConnecting(u64),
    /// The probe with this id is over: its permit, or its wait for one,
    /// ends.
    ProbeEnded(u64),
    /// The talker of the connection's backchannel changed.
    Talker {
        /// The session it concerns.
        session_id: String,
        /// Why.
        reason: TalkerReason,
        /// When, on the worker's wall clock.
        at: SystemTime,
    },
    /// A signaled source's signaling, its signal id short and its close's
    /// code and message plain; the driver checks the rest.
    Signal(SignalReport),
    /// An event recording reported something, as the worker wrote it: checked
    /// against the recording the supervisor holds under `recording_id`, as a
    /// session's report is against its session.
    Recording {
        /// The recording.
        recording_id: String,
        /// What happened.
        event: RecordingReport,
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
    /// The clock every worker's write deadline and stop budget run on.
    clock: Arc<dyn Clock>,
    /// The shared WebRTC UDP socket every worker gets a duplicate of;
    /// `None` in tests that run no sessions.
    udp: Option<Arc<UdpSocket>>,
    /// The TURN client whose TCP allocations take what a worker's sessions
    /// send from their relay candidates, on its datagram channel.
    turn: Option<Arc<TurnClient>>,
}

impl WorkerManager {
    /// A manager starting workers as `config` says, handing each `udp`,
    /// their write deadlines and stop budgets running on `clock`.
    pub const fn new(
        config: WorkerConfig,
        udp: Option<Arc<UdpSocket>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            config,
            clock,
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

    /// Starts a worker that may connect to `connect_ports` on its camera.
    /// Must run inside the runtime.
    #[expect(
        clippy::disallowed_methods,
        reason = "the one place that spawns a process"
    )]
    pub fn spawn(&self, connect_ports: &[u16]) -> Result<Worker, SpawnError> {
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
        let recordings = &self.config.recordings;
        command
            .arg("--max-prerecord-bytes")
            .arg(recordings.max_prerecord_bytes.to_string())
            .arg("--max-recording-ms")
            .arg(recordings.max_recording_ms.to_string())
            .arg("--recording-queue-bytes")
            .arg(recordings.recording_queue_bytes.to_string())
            .arg("--recording-start-timeout-ms")
            .arg(recordings.start_timeout.as_millis().to_string())
            .arg("--max-recordings")
            .arg(recordings.max_recordings.to_string());
        if !connect_ports.is_empty() {
            let ports: Vec<String> = connect_ports.iter().map(u16::to_string).collect();
            command.arg("--connect-ports").arg(ports.join(","));
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
        tracing::info!(pid, connect_ports = ?connect_ports, "worker spawned");
        Ok(Worker {
            pid,
            child,
            control,
            stalled: false,
            clock: Arc::clone(&self.clock),
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

/// Which kinds of trim of one worker's messages were logged: each once,
/// since a worker repeating an over-long message would otherwise write a
/// line per message.
#[derive(Debug, Default)]
struct Trims {
    /// A declaration of tracks was trimmed ([`declared`]).
    tracks: bool,
    /// A report of track counters was trimmed ([`counted`]).
    stats: bool,
}

/// Reads the worker's messages and relays them as events until the
/// channel ends.
async fn relay(mut rx: Receiver, events: mpsc::Sender<WorkerEvent>) {
    // Only the first message may hand over a descriptor: it is sent before
    // the worker reads anything from the network ([`ToSupervisor::Ready`]).
    let mut first = true;
    let mut trims = Trims::default();
    loop {
        let event = match rx.recv_msg::<ToSupervisor>().await {
            Ok(Some((message, fds))) => {
                let memory = fds.into_iter().next().filter(|_| first);
                first = false;
                map_message(message, memory, &mut trims)
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

/// A source state as the connection machine takes it; `None` for a
/// runner that stopped.
fn source_report(state: SourceState) -> Option<WorkerReport> {
    Some(match state {
        SourceState::Connecting { .. } => WorkerReport::Connecting,
        SourceState::Live => WorkerReport::Live,
        SourceState::Stable => WorkerReport::Stable,
        SourceState::Reconnecting { code, message } => {
            WorkerReport::Reconnecting(source_error(&code, &message))
        }
        SourceState::Backoff {
            code,
            message,
            retry_ms,
            position,
        } => WorkerReport::Backoff {
            error: source_error(&code, &message),
            retry_in: Duration::from_millis(u64::from(retry_ms)),
            position: BackoffPosition {
                attempts: position.attempts,
                immediate_used: position.immediate_used,
            },
        },
        SourceState::Stopped => return None,
    })
}

/// A worker message as a trusted event; `memory` is the descriptor that
/// came with it, kept only for `Ready` and closed otherwise, and `trims`
/// what the worker's earlier messages logged.
fn map_message(message: ToSupervisor, memory: Option<OwnedFd>, trims: &mut Trims) -> WorkerEvent {
    match message {
        ToSupervisor::Ready { pid } => WorkerEvent::Ready {
            pid,
            memory: memory.map(MemoryProbe::from_fd),
        },
        ToSupervisor::SourceState(state) => {
            source_report(state).map_or(WorkerEvent::SourceStopped, WorkerEvent::Report)
        }
        ToSupervisor::SwitchState(state) => {
            source_report(state).map_or(WorkerEvent::StandbyStopped, WorkerEvent::SwitchReport)
        }
        ToSupervisor::Switched => WorkerEvent::Switched,
        ToSupervisor::Tracks(tracks) => WorkerEvent::Tracks(declared(tracks, &mut trims.tracks)),
        ToSupervisor::Stats(stats) => WorkerEvent::Stats(counted(stats, &mut trims.stats)),
        ToSupervisor::Session { session_id, event } => WorkerEvent::Session { session_id, event },
        ToSupervisor::Recording {
            recording_id,
            event,
        } => WorkerEvent::Recording {
            recording_id,
            event,
        },
        ToSupervisor::ProbeConnecting { probe } => WorkerEvent::ProbeConnecting(probe),
        ToSupervisor::ProbeEnded { probe } => WorkerEvent::ProbeEnded(probe),
        ToSupervisor::Talker(change) => match TalkerReason::parse(&change.reason) {
            Some(reason) => WorkerEvent::Talker {
                session_id: change.session_id,
                reason,
                at: UNIX_EPOCH
                    .checked_add(Duration::from_millis(change.at_ms))
                    .unwrap_or(UNIX_EPOCH),
            },
            None => WorkerEvent::ChannelError(format!(
                "talker change with an unknown reason {:?}",
                change.reason
            )),
        },
        ToSupervisor::Signal(report) => signal(report),
    }
}

/// A worker's signal report as the driver takes it: a close's code and
/// message made [`plain`]. A signal id the supervisor never gives (its
/// ids are ULIDs): empty, over [`MAX_NAME_BYTES`] or with a byte outside
/// [`is_signal_id`]'s set, fails the channel, as a broken protocol does;
/// so an id is safe to log as it is, with no line break or control
/// character to forge a log line with.
fn signal(report: SignalReport) -> WorkerEvent {
    let signal_id = match &report {
        SignalReport::Open { .. } | SignalReport::Cancel { .. } => None,
        SignalReport::Offer { signal_id, .. }
        | SignalReport::Candidate { signal_id, .. }
        | SignalReport::Closed { signal_id, .. } => Some(signal_id),
    };
    if let Some(signal_id) = signal_id.filter(|id| !is_signal_id(id)) {
        return WorkerEvent::ChannelError(format!(
            "signal report with a malformed {}-byte signal id",
            signal_id.len()
        ));
    }
    WorkerEvent::Signal(match report {
        SignalReport::Closed {
            signal_id,
            code,
            message,
        } => SignalReport::Closed {
            signal_id,
            code: plain(&code, MAX_NAME_BYTES),
            message: plain(&message, MAX_MESSAGE_BYTES),
        },
        report => report,
    })
}

/// Whether `id` could be a signal id the supervisor gave: 1 to
/// [`MAX_NAME_BYTES`] bytes of ASCII letters, digits, `.`, `_` and `-`, a
/// superset of a ULID's Crockford base32.
fn is_signal_id(id: &str) -> bool {
    (1..=MAX_NAME_BYTES).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The tracks of a worker's declaration the supervisor keeps: the first
/// [`MAX_TRACKS`] whose names fit [`MAX_NAME_BYTES`]. A trim is logged
/// unless `logged` says one was already, and sets it.
fn declared(tracks: Vec<TrackInfo>, logged: &mut bool) -> Vec<TrackInfo> {
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
    if kept.len() < declared && !std::mem::replace(logged, true) {
        tracing::warn!(
            declared,
            kept = kept.len(),
            limit = MAX_TRACKS,
            "a worker declared too many tracks or over-long names; the rest dropped, and later ones without a log"
        );
    }
    kept
}

/// A worker's counters with at most [`MAX_TRACKS`] tracks whose ids fit
/// [`MAX_NAME_BYTES`], and a backchannel codec and talk-back session ids
/// that are short names ([`is_signal_id`]): the codec goes into
/// `stream/get` as it is, so one that is no name is dropped whole. A trim
/// is logged unless `logged` says one was already, and sets it.
fn counted(mut stats: WorkerStats, logged: &mut bool) -> WorkerStats {
    let reported = stats.tracks.len();
    stats.tracks.retain(|(id, _)| id.len() <= MAX_NAME_BYTES);
    stats.tracks.truncate(MAX_TRACKS);
    let sessions = stats.talkback.len();
    stats.talkback.retain(|(id, _)| is_signal_id(id));
    let unnamed = sessions.saturating_sub(stats.talkback.len());
    let codec = stats.backchannel.take_if(|codec| !is_signal_id(codec));
    let trimmed = stats.tracks.len() < reported || unnamed > 0 || codec.is_some();
    if trimmed && !std::mem::replace(logged, true) {
        tracing::warn!(
            reported,
            kept = stats.tracks.len(),
            limit = MAX_TRACKS,
            talkback_dropped = unnamed,
            backchannel_dropped = codec.is_some(),
            "a worker counted too many tracks or over-long ids, or named a talk-back session or a backchannel codec with no short name; the rest dropped, and later ones without a log"
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
    /// The sending half of the control channel, written only through
    /// [`Worker::send`].
    control: Sender,
    /// A write waited out [`CONTROL_WRITE_DEADLINE`]: the channel is given
    /// up on, and nothing is written to it any more ([`IpcError::Stalled`]).
    stalled: bool,
    /// The clock the write deadline and the stop budget run on.
    clock: Arc<dyn Clock>,
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

    /// Sends `message` with `fds`: the one way anything reaches the
    /// worker, within [`CONTROL_WRITE_DEADLINE`] or not at all.
    ///
    /// The write waits only while the socket's send buffer is full, which
    /// a worker that reads nothing makes it (a non-blocking `sendmsg(2)` on
    /// a full `AF_UNIX` stream socket fails with `EAGAIN` and the runtime
    /// waits for room; observed on Linux 6.18, 2026-11-08). One that waits
    /// out the deadline is abandoned, possibly mid-frame, so the channel is
    /// given up on: this and every later write fail with
    /// [`IpcError::Stalled`] without touching the socket, and the worker,
    /// which can no longer be told anything, is killed. Its exit arrives
    /// as [`WorkerEvent::Exited`], which counts as a crash. A caller is
    /// thus held up by at most the deadline.
    async fn send(&mut self, message: &ToWorker, fds: &[BorrowedFd<'_>]) -> Result<(), IpcError> {
        let deadline_ms = crate::millis(CONTROL_WRITE_DEADLINE);
        if self.stalled {
            return Err(IpcError::Stalled { deadline_ms });
        }
        let deadline = self.clock.sleep(CONTROL_WRITE_DEADLINE);
        tokio::select! {
            biased;
            sent = self.control.send_msg(message, fds) => sent,
            () = deadline => {
                self.stalled = true;
                tracing::warn!(
                    pid = self.pid,
                    kind = message.name(),
                    deadline_ms,
                    "worker took no control message within the deadline; its channel is given up on"
                );
                self.kill("control write timed out");
                Err(IpcError::Stalled { deadline_ms })
            }
        }
    }

    /// Hands the worker its sockets with the first message it gets, so
    /// they are there whatever comes first.
    async fn send_pending_sockets(&mut self) -> Result<(), IpcError> {
        if let Some((udp, theirs)) = self.pending_sockets.take() {
            self.send(&ToWorker::Sockets, &[udp.as_fd(), theirs.as_fd()])
                .await?;
        }
        Ok(())
    }

    /// Tells the worker which source to run.
    pub async fn run_source(&mut self, spec: &SourceSpec) -> Result<(), IpcError> {
        self.send_pending_sockets().await?;
        self.send(&ToWorker::RunSource(spec.clone()), &[]).await
    }

    /// Lets the connection attempt the worker announced go ahead: the
    /// driver holds a connect permit for it.
    pub async fn grant_connect(&mut self) -> Result<(), IpcError> {
        self.send(&ToWorker::ConnectGranted, &[]).await
    }

    /// Tells the worker to connect `spec` as the standby of its source and
    /// switch to it at its first keyframe.
    pub async fn switch_source(&mut self, spec: &SourceSpec) -> Result<(), IpcError> {
        self.send(&ToWorker::SwitchSource(spec.clone()), &[]).await
    }

    /// Tells the worker whether its connection asks for the camera's
    /// backchannel from now on (`asks`): its sources turn their probe on
    /// or off, and nothing restarts.
    pub async fn backchannel(&mut self, asks: bool) -> Result<(), IpcError> {
        self.send(&ToWorker::Backchannel { asks }, &[]).await
    }

    /// Tells the worker its connection's pre-record window is `ms` from now
    /// on, 0 for none: its tracks keep or free their rings, and nothing
    /// reconnects.
    pub async fn prerecord(&mut self, ms: u32) -> Result<(), IpcError> {
        self.send(&ToWorker::Prerecord { ms }, &[]).await
    }

    /// Starts the event recording `spec` on the worker's tracks, its bytes going
    /// to `pipe`, the write end of the pipe whose read end the supervisor
    /// keeps. The descriptor is closed here once sent, so the worker's is
    /// the only write end and the reader sees the end of the recording when the
    /// worker closes it, or dies. The reports arrive as
    /// [`WorkerEvent::Recording`] events.
    pub async fn start_recording(
        &mut self,
        spec: &RecordingSpec,
        pipe: OwnedFd,
    ) -> Result<(), IpcError> {
        self.send(&ToWorker::StartRecording(spec.clone()), &[pipe.as_fd()])
            .await
    }

    /// Ends the recording `recording_id` cleanly; the worker ignores one it does not
    /// run.
    pub async fn stop_recording(&mut self, recording_id: &str) -> Result<(), IpcError> {
        let message = ToWorker::StopRecording {
            recording_id: recording_id.to_owned(),
        };
        self.send(&message, &[]).await
    }

    /// Lets the standby's announced attempt go ahead.
    pub async fn grant_switch_connect(&mut self) -> Result<(), IpcError> {
        self.send(&ToWorker::SwitchConnectGranted, &[]).await
    }

    /// Lets the probe `probe` the worker announced go ahead.
    pub async fn grant_probe_connect(&mut self, probe: u64) -> Result<(), IpcError> {
        self.send(&ToWorker::ProbeConnectGranted { probe }, &[])
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
        self.send(&message, &[stream.as_fd()]).await
    }

    /// Opens a viewer session on the worker's source; the answer and the
    /// rest arrive as [`WorkerEvent::Session`] events.
    pub async fn open_session(&mut self, spec: &SessionSpec) -> Result<(), IpcError> {
        self.send_pending_sockets().await?;
        self.send(&ToWorker::OpenSession(spec.clone()), &[]).await
    }

    /// Passes a trickled remote candidate to a session.
    pub async fn candidate(&mut self, session_id: &str, candidate: &str) -> Result<(), IpcError> {
        self.send(
            &ToWorker::RemoteCandidate {
                session_id: session_id.to_owned(),
                candidate: candidate.to_owned(),
            },
            &[],
        )
        .await
    }

    /// A re-offer for a session (`webrtc/renegotiate`); the worker
    /// answers with a `Renegotiated` or `RenegotiateRefused` report.
    pub async fn renegotiate(&mut self, session_id: &str, sdp: &str) -> Result<(), IpcError> {
        self.send(
            &ToWorker::Renegotiate {
                session_id: session_id.to_owned(),
                sdp: sdp.to_owned(),
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
        self.send(&message, &[]).await
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
        self.send(&message, &[]).await
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
        self.send(&message, &[]).await
    }

    /// Frees the connection's backchannel from its talker, or only from
    /// `session_id` when given (`backchannel/release`).
    pub async fn release_backchannel(
        &mut self,
        session_id: Option<String>,
    ) -> Result<(), IpcError> {
        self.send(&ToWorker::ReleaseBackchannel { session_id }, &[])
            .await
    }

    /// Tells the worker what the supervisor answers its signaled source's
    /// signaling with: an open's answer, or what the client relays.
    pub async fn signal(&mut self, command: &SignalCommand) -> Result<(), IpcError> {
        self.send(&ToWorker::Signal(command.clone()), &[]).await
    }

    /// Closes a session with this `closed` code.
    pub async fn close_session(
        &mut self,
        session_id: &str,
        code: &str,
        message: &str,
    ) -> Result<(), IpcError> {
        self.send(
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

    /// Kills the process for `reason`, once: one whose channel ended, that
    /// went silent, or that took no message within the write deadline
    /// ([`CONTROL_WRITE_DEADLINE`]) can no longer be told to stop. Its exit arrives as
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
    ///
    /// The budget covers the whole stop, the `Shutdown` message included:
    /// a worker that takes no message is killed when the budget or the
    /// write's own deadline ([`CONTROL_WRITE_DEADLINE`]) runs out,
    /// whichever comes first, and one whose channel was given up on gets no
    /// message at all.
    pub async fn stop(mut self, budget: Duration) -> ExitStatus {
        let deadline_ms = u32::try_from(budget.as_millis()).unwrap_or(u32::MAX);
        let pid = self.pid;
        let over = self.clock.sleep(budget);
        let status = tokio::select! {
            status = async {
                if let Err(err) = self.send(&ToWorker::Shutdown { deadline_ms }, &[]).await {
                    tracing::debug!(
                        pid,
                        error = %err,
                        "worker unreachable for shutdown; killed unless it exits within the budget"
                    );
                }
                self.child.wait().await
            } => status,
            () = over => {
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

    use std::os::unix::process::ExitStatusExt as _;

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::text::CUT_MARK;
    use lotse_ipc::TalkerChange;

    use super::*;
    use crate::test_support::Captured;

    #[test]
    fn messages_map_onto_trusted_events() {
        assert_eq!(
            mapped(ToSupervisor::Ready { pid: 4 }, None),
            WorkerEvent::Ready {
                pid: 4,
                memory: None
            }
        );
        assert_eq!(
            mapped(
                ToSupervisor::SourceState(SourceState::Connecting { attempt: 3 }),
                None
            ),
            WorkerEvent::Report(WorkerReport::Connecting)
        );
        assert_eq!(
            mapped(ToSupervisor::SourceState(SourceState::Live), None),
            WorkerEvent::Report(WorkerReport::Live)
        );
        assert_eq!(
            mapped(ToSupervisor::SourceState(SourceState::Stable), None),
            WorkerEvent::Report(WorkerReport::Stable)
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
            (SourceState::Stable, WorkerReport::Stable),
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
                    position: lotse_ipc::BackoffPosition {
                        attempts: 1,
                        immediate_used: true,
                    },
                },
                WorkerReport::Backoff {
                    error: SourceError::Unreachable("refused".into()),
                    retry_in: Duration::from_millis(500),
                    position: BackoffPosition {
                        attempts: 1,
                        immediate_used: true,
                    },
                },
            ),
        ] {
            assert_eq!(
                mapped(ToSupervisor::SwitchState(state), None),
                WorkerEvent::SwitchReport(report)
            );
        }
        assert_eq!(
            mapped(ToSupervisor::SwitchState(SourceState::Stopped), None),
            WorkerEvent::StandbyStopped
        );
    }

    #[test]
    fn the_other_messages_map_onto_their_events() {
        assert_eq!(mapped(ToSupervisor::Switched, None), WorkerEvent::Switched);
        assert_eq!(
            mapped(
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
            mapped(
                ToSupervisor::SourceState(SourceState::Backoff {
                    code: "made_up".into(),
                    message: "x".into(),
                    retry_ms: 1500,
                    position: lotse_ipc::BackoffPosition {
                        attempts: 7,
                        immediate_used: false
                    }
                }),
                None
            ),
            WorkerEvent::Report(WorkerReport::Backoff {
                error: SourceError::Protocol("made_up: x".into()),
                retry_in: Duration::from_millis(1500),
                position: BackoffPosition {
                    attempts: 7,
                    immediate_used: false
                }
            })
        );
        assert_eq!(
            mapped(ToSupervisor::SourceState(SourceState::Stopped), None),
            WorkerEvent::SourceStopped
        );
        assert_eq!(
            mapped(ToSupervisor::Tracks(vec![]), None),
            WorkerEvent::Tracks(vec![])
        );
        assert_eq!(
            mapped(ToSupervisor::Stats(WorkerStats::default()), None),
            WorkerEvent::Stats(WorkerStats::default())
        );
        assert_eq!(
            mapped(ToSupervisor::ProbeConnecting { probe: 3 }, None),
            WorkerEvent::ProbeConnecting(3)
        );
        assert_eq!(
            mapped(ToSupervisor::ProbeEnded { probe: 3 }, None),
            WorkerEvent::ProbeEnded(3)
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

    #[test]
    fn talker_changes_map_onto_talker_events_and_an_unknown_reason_fails_the_channel() {
        assert_eq!(
            mapped(
                ToSupervisor::Talker(TalkerChange {
                    session_id: "s1".into(),
                    reason: "released".into(),
                    at_ms: 1_500,
                }),
                None
            ),
            WorkerEvent::Talker {
                session_id: "s1".into(),
                reason: TalkerReason::Released,
                at: UNIX_EPOCH + Duration::from_millis(1_500),
            }
        );
        assert_eq!(
            mapped(
                ToSupervisor::Talker(TalkerChange {
                    session_id: "s1".into(),
                    reason: "stolen".into(),
                    at_ms: 0,
                }),
                None
            ),
            WorkerEvent::ChannelError("talker change with an unknown reason \"stolen\"".into())
        );
    }

    /// [`map_message`] as a worker's first message of its kind maps.
    fn mapped(message: ToSupervisor, memory: Option<OwnedFd>) -> WorkerEvent {
        map_message(message, memory, &mut Trims::default())
    }

    fn track(id: &str) -> TrackInfo {
        TrackInfo {
            id: id.into(),
            kind: "video".into(),
            codec: "h264".into(),
            sync: "arrival".into(),
            derived_from: None,
            audio_delay_ms: None,
            params: lotse_ipc::TrackParams::default(),
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
            mapped(ToSupervisor::Tracks(tracks.clone()), None),
            WorkerEvent::Tracks(tracks[5..5 + MAX_TRACKS].to_vec())
        );
        let few = vec![track("v0"), track("a0")];
        assert_eq!(declared(few.clone(), &mut false), few);
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
                        packet_bytes: 2,
                        frames: 3,
                        frame_bytes: 4,
                        frames_dropped_oversize: 6,
                        frames_over_browser_limit: 7,
                        prerecord: None,
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
            mapped(ToSupervisor::Stats(stats(&reported)), None),
            WorkerEvent::Stats(stats(&reported[1..=MAX_TRACKS]))
        );
        assert_eq!(counted(stats(&["v0"]), &mut false), stats(&["v0"]));
        let lines = captured.lines("counted too many tracks");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("reported=40 kept=32 limit=32"),
            "{lines:?}"
        );
    }

    /// Regression: `counted` trimmed the track counters alone, so the
    /// backchannel codec, which `stream/get` reports as the worker gave
    /// it, could be a quarter MiB of any characters, and so could a
    /// talk-back session's id.
    #[test]
    fn a_worker_s_backchannel_codec_and_talkback_sessions_are_short_names() {
        let talkback = lotse_ipc::TalkbackStats::default();
        let stats = |codec: Option<&str>, sessions: &[&str]| WorkerStats {
            talkback: sessions
                .iter()
                .map(|id| ((*id).to_owned(), talkback))
                .collect(),
            backchannel: codec.map(str::to_owned),
            ..WorkerStats::default()
        };
        let long = "x".repeat(MAX_NAME_BYTES + 1);
        let named = "x".repeat(MAX_NAME_BYTES);
        let captured = Captured::default();
        let _logs = captured.install();

        let kept = stats(Some("pcmu"), &["01JD0000000000000000000000", &named]);
        assert_eq!(counted(kept.clone(), &mut false), kept);
        assert_eq!(
            counted(stats(Some(&named), &[]), &mut false),
            stats(Some(&named), &[])
        );
        assert_eq!(captured.lines("counted too many tracks"), [""; 0]);

        for codec in [long.as_str(), "", "pcmu\nlevel=ERROR forged", "pc mu"] {
            let mut logged = false;
            assert_eq!(
                counted(stats(Some(codec), &["s1"]), &mut logged),
                stats(None, &["s1"]),
                "{codec:?}"
            );
            assert!(logged, "{codec:?}");
        }
        let lines = captured.lines("backchannel_dropped=true");
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].contains("talkback_dropped=0"), "{lines:?}");

        let mut logged = false;
        assert_eq!(
            counted(
                stats(Some("opus"), &["s1", &long, "", "s 2", "s2"]),
                &mut logged
            ),
            stats(Some("opus"), &["s1", "s2"])
        );
        assert!(logged);
        let lines = captured.lines("talkback_dropped=3");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("backchannel_dropped=false"), "{lines:?}");

        // Once per worker, as for the tracks.
        let mut logged = true;
        assert_eq!(
            counted(stats(Some(&long), &[&long]), &mut logged),
            stats(None, &[])
        );
        assert_eq!(captured.lines("talkback_dropped=1").len(), 0);
    }

    /// Regression for SUP-30: every trimmed declaration or counter report
    /// was a `warn` line, so a worker repeating one grew the log at its
    /// own rate.
    #[test]
    fn a_worker_s_repeated_trims_are_logged_once() {
        let tracks: Vec<TrackInfo> = (0..=MAX_TRACKS).map(|n| track(&n.to_string())).collect();
        let counters = lotse_ipc::TrackStats {
            packet_bytes: 2,
            frames: 3,
            frame_bytes: 4,
            frames_dropped_oversize: 6,
            frames_over_browser_limit: 7,
            prerecord: None,
        };
        let stats = WorkerStats {
            tracks: (0..=MAX_TRACKS)
                .map(|n| (n.to_string(), counters))
                .collect(),
            ..WorkerStats::default()
        };
        let captured = Captured::default();
        let _logs = captured.install();
        let mut trims = Trims::default();
        for _ in 0..100 {
            let _tracks = map_message(ToSupervisor::Tracks(tracks.clone()), None, &mut trims);
            let _stats = map_message(ToSupervisor::Stats(stats.clone()), None, &mut trims);
        }
        assert_eq!(captured.lines("declared too many tracks").len(), 1);
        assert_eq!(captured.lines("counted too many tracks").len(), 1);
    }

    #[test]
    fn a_worker_s_source_error_is_plain_and_capped() {
        assert_eq!(
            source_error("source_timeout", &format!("a\nb\u{1b}{}", "x".repeat(1000))),
            SourceError::Timeout(format!(
                "a b\u{fffd}{}{CUT_MARK}",
                "x".repeat(MAX_MESSAGE_BYTES - 6 - CUT_MARK.len())
            ))
        );
        assert_eq!(
            source_error(&format!("\u{1b}{}", "c".repeat(100)), "m"),
            SourceError::Protocol(format!(
                "\u{fffd}{}{CUT_MARK}: m",
                "c".repeat(MAX_NAME_BYTES - 3 - CUT_MARK.len())
            ))
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

    #[test]
    fn a_signal_report_maps_with_its_close_plain_and_a_long_signal_id_fails_the_channel() {
        let passed = [
            SignalReport::Open { request: 1 },
            SignalReport::Cancel { request: 1 },
            SignalReport::Offer {
                signal_id: "s".repeat(MAX_NAME_BYTES),
                sdp: "v=0\r\n".into(),
            },
            SignalReport::Candidate {
                signal_id: "01JSIG".into(),
                candidate: String::new(),
                mid: None,
                mline_index: Some(0),
            },
        ];
        for report in passed {
            assert_eq!(
                mapped(ToSupervisor::Signal(report.clone()), None),
                WorkerEvent::Signal(report)
            );
        }
        assert_eq!(
            mapped(
                ToSupervisor::Signal(SignalReport::Closed {
                    signal_id: "01JSIG".into(),
                    code: format!("ice_failed\n{}", "x".repeat(MAX_NAME_BYTES)),
                    message: format!("line\none{}", "y".repeat(MAX_MESSAGE_BYTES)),
                }),
                None
            ),
            WorkerEvent::Signal(SignalReport::Closed {
                signal_id: "01JSIG".into(),
                code: plain(
                    &format!("ice_failed {}", "x".repeat(MAX_NAME_BYTES)),
                    MAX_NAME_BYTES
                ),
                message: plain(
                    &format!("line one{}", "y".repeat(MAX_MESSAGE_BYTES)),
                    MAX_MESSAGE_BYTES
                ),
            })
        );
        let long = "s".repeat(MAX_NAME_BYTES + 1);
        for report in [
            SignalReport::Offer {
                signal_id: long.clone(),
                sdp: String::new(),
            },
            SignalReport::Candidate {
                signal_id: long.clone(),
                candidate: String::new(),
                mid: None,
                mline_index: None,
            },
            SignalReport::Closed {
                signal_id: long,
                code: String::new(),
                message: String::new(),
            },
        ] {
            assert_eq!(
                mapped(ToSupervisor::Signal(report), None),
                WorkerEvent::ChannelError(
                    "signal report with a malformed 65-byte signal id".into()
                )
            );
        }
    }

    /// A signal id is logged as it is, so one that could forge a log line
    /// (a line break, a control character) or that the supervisor never
    /// gives fails the channel.
    #[test]
    fn a_signal_id_outside_the_supervisor_s_charset_fails_the_channel() {
        for id in [
            "",
            "sig\nlevel=ERROR forged",
            "sig\r",
            "sig\u{1b}[31m",
            "sig id",
            "sig\"",
            "sigé",
            "sig/1",
        ] {
            assert_eq!(
                mapped(
                    ToSupervisor::Signal(SignalReport::Offer {
                        signal_id: id.into(),
                        sdp: String::new(),
                    }),
                    None
                ),
                WorkerEvent::ChannelError(format!(
                    "signal report with a malformed {}-byte signal id",
                    id.len()
                )),
                "{id:?}"
            );
        }
        for id in ["01JSIGABCDEFGHJKMNPQRSTVWX", "sig-1", "a.b_c-D9", "x"] {
            assert!(is_signal_id(id), "{id:?}");
        }
        assert!(is_signal_id(&"s".repeat(MAX_NAME_BYTES)));
    }

    #[test]
    fn a_session_message_maps_onto_its_session_s_event() {
        let event = SessionEvent::Answer {
            sdp: "v=0".into(),
            talkback: None,
        };
        assert_eq!(
            mapped(
                ToSupervisor::Session {
                    session_id: "s1".into(),
                    event: event.clone(),
                },
                None
            ),
            WorkerEvent::Session {
                session_id: "s1".into(),
                event
            }
        );
    }

    #[test]
    fn a_recording_message_maps_onto_its_recording_s_event() {
        let event = RecordingReport::Gap {
            reason: "overflow".into(),
            from_ms: 1_000,
            to_ms: 2_500,
        };
        assert_eq!(
            mapped(
                ToSupervisor::Recording {
                    recording_id: "k1".into(),
                    event: event.clone(),
                },
                None
            ),
            WorkerEvent::Recording {
                recording_id: "k1".into(),
                event
            }
        );
    }

    #[tokio::test]
    async fn a_message_that_does_not_decode_ends_the_relay_as_a_channel_error() {
        let (ours, theirs) = Channel::pair().unwrap();
        let (mut tx, _theirs_rx) = Channel::from_fd(theirs).unwrap().split();
        let (_control, rx) = ours.split();
        let (events_tx, mut events) = mpsc::channel(4);
        let reader = spawn_named("test.relay", relay(rx, events_tx));
        tx.send(&[0xff; 3], &[]).await.unwrap();
        let event = events.recv().await.unwrap();
        assert!(
            matches!(&event, WorkerEvent::ChannelError(message) if !message.is_empty()),
            "{event:?}"
        );
        reader.await.unwrap();
        assert!(events.recv().await.is_none(), "nothing after the error");
    }

    /// A worker script at `dir/worker.sh` that writes its arguments to
    /// `dir/args` and what it is sent to `dir/received`.
    fn recording_worker(dir: &std::path::Path) -> PathBuf {
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexec cat > {}\n",
                dir.join("args").display(),
                dir.join("received").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        script
    }

    /// The messages in `bytes`, up to a frame still being written.
    fn decode_all(bytes: &[u8]) -> Vec<ToWorker> {
        let mut messages = Vec::new();
        let mut rest = bytes;
        while let Some((prefix, tail)) = rest.split_at_checked(4)
            && let Ok(len) = usize::try_from(u32::from_le_bytes(prefix.try_into().unwrap()))
            && let Some((frame, tail)) = tail.split_at_checked(len)
        {
            messages.push(lotse_ipc::decode::<ToWorker>(frame).unwrap());
            rest = tail;
        }
        messages
    }

    /// What the recording worker received once it holds `count` messages,
    /// looking every 10 ms for up to five seconds.
    async fn received(dir: &std::path::Path, count: usize) -> Vec<ToWorker> {
        let mut messages = Vec::new();
        let mut looks = 0;
        while messages.len() < count && looks < 500 {
            SystemClock.sleep(Duration::from_millis(10)).await;
            looks += 1;
            messages = decode_all(&std::fs::read(dir.join("received")).unwrap_or_default());
        }
        messages
    }

    #[tokio::test]
    async fn a_worker_gets_its_sockets_first_and_its_flags_and_grants() {
        let dir = crate::test_support::private_dir("worker-recording");
        let mut config = crate::test_support::environment("/bin/sh").worker;
        config.binary = recording_worker(&dir);
        config.recordings = RecordingLimits {
            max_prerecord_bytes: 1 << 20,
            max_recording_ms: 45_000,
            recording_queue_bytes: 1 << 16,
            start_timeout: Duration::from_millis(2_500),
            max_recordings: 3,
            ..RecordingLimits::DEFAULT
        };
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let manager = WorkerManager::new(config, Some(udp), Arc::new(SystemClock));
        let mut worker = manager.spawn(&[554, 8554]).unwrap();
        let spec = SourceSpec {
            connection_id: "c1".into(),
            target: lotse_ipc::SourceTarget::Url("fake://cam/".into()),
            options: "{}".into(),
            peer_host: "cam".into(),
            peer_addrs: vec![],
            backoff: lotse_ipc::BackoffPosition::default(),
            prerecord_ms: 0,
        };
        worker.run_source(&spec).await.unwrap();
        worker.backchannel(true).await.unwrap();
        worker.grant_switch_connect().await.unwrap();
        worker.grant_probe_connect(4).await.unwrap();
        worker.prerecord(30_000).await.unwrap();
        let recording = RecordingSpec {
            recording_id: "k1".into(),
            prerecord_ms: 10_000,
            duration_ms: 20_000,
            audio: true,
        };
        let (mut recording_bytes, pipe) = io::pipe().unwrap();
        worker
            .start_recording(&recording, pipe.into())
            .await
            .unwrap();
        worker.stop_recording("k1").await.unwrap();
        let candidate = "candidate:1 1 udp 2130706431 192.0.2.1 9 typ host";
        worker.candidate("s1", candidate).await.unwrap();
        worker.close_session("s1", "gone", "bye").await.unwrap();
        assert_eq!(
            received(&dir, 10).await,
            [
                ToWorker::Sockets,
                ToWorker::RunSource(spec),
                ToWorker::Backchannel { asks: true },
                ToWorker::SwitchConnectGranted,
                ToWorker::ProbeConnectGranted { probe: 4 },
                ToWorker::Prerecord { ms: 30_000 },
                ToWorker::StartRecording(recording),
                ToWorker::StopRecording {
                    recording_id: "k1".into()
                },
                ToWorker::RemoteCandidate {
                    session_id: "s1".into(),
                    candidate: candidate.into(),
                },
                ToWorker::CloseSession {
                    session_id: "s1".into(),
                    code: "gone".into(),
                    message: "bye".into(),
                },
            ],
            "the sockets ride on the first message, once"
        );
        // The pipe's write end went with the message and the supervisor
        // kept none: once `cat` read the message and so discarded it, the
        // read end ends.
        let mut rest = Vec::new();
        io::Read::read_to_end(&mut recording_bytes, &mut rest).unwrap();
        assert_eq!(rest, b"");
        let args = std::fs::read_to_string(dir.join("args")).unwrap();
        assert!(args.contains("--connect-ports\n554,8554\n"), "{args}");
        assert!(
            args.contains(
                "--max-prerecord-bytes\n1048576\n--max-recording-ms\n45000\n--recording-queue-bytes\n65536\n\
                 --recording-start-timeout-ms\n2500\n--max-recordings\n3\n"
            ),
            "the recording limits as the supervisor holds them: {args}"
        );
        // A kill is sent once, however often it is asked for.
        let captured = Captured::default();
        let _logs = captured.install();
        worker.kill("silent");
        worker.kill("channel closed");
        assert_eq!(captured.lines("worker killed").len(), 1);
        // Its channel's end may come first.
        let mut event = WorkerEvent::ChannelClosed;
        while event == WorkerEvent::ChannelClosed {
            event = worker.next_event().await;
        }
        assert!(
            matches!(&event, WorkerEvent::Exited(status) if status.signal() == Some(9)),
            "{event:?}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// IPC-20: a worker starts with standard input, output and error and
    /// nothing else of the supervisor's. Standard input is its control
    /// channel (the worker's `lotse_sandbox::WORKER_CONTROL_FD`), output is
    /// `/dev/null` and error is the supervisor's; the datagram channel and
    /// the shared UDP socket come later, by `SCM_RIGHTS` with
    /// [`ToWorker::Sockets`]. The stand-in worker `exec`s `sleep`, which
    /// opens no descriptor, so what it holds once it runs is exactly what
    /// crossed the `execve(2)`: none of the supervisor's end of the control
    /// channel, the two ends of the datagram socketpair or the shared
    /// socket, which the supervisor holds meanwhile. The supervisor in turn
    /// keeps no copy of the worker's end.
    ///
    /// A descriptor the test process inherited without `FD_CLOEXEC` before
    /// the test began crosses every `execve(2)` it makes: the GitHub
    /// runner's test processes hold two such pipes (observed 2026-10-17 on
    /// `ubuntu-24.04-arm`, fds 142 and 145). Those are expected in the worker
    /// too, and nothing else is.
    #[tokio::test]
    async fn a_spawned_worker_holds_only_its_stdio_and_control_socket() {
        let inherited = inheritable(&descriptors(std::path::Path::new("/proc/self")));
        let dir = crate::test_support::private_dir("worker-descriptors");
        let script = dir.join("worker.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let mut config = crate::test_support::environment("/bin/sh").worker;
        config.binary = script;
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let manager = WorkerManager::new(config, Some(udp), Arc::new(SystemClock));
        let worker = manager.spawn(&[554]).unwrap();
        let proc = PathBuf::from(format!("/proc/{}", worker.pid()));
        // The shell holds its script open until it `exec`s `sleep`: look
        // every 10 ms for up to five seconds.
        let mut ran_sleep = false;
        let mut looks = 0;
        while !ran_sleep && looks < 500 {
            SystemClock.sleep(Duration::from_millis(10)).await;
            looks += 1;
            ran_sleep = std::fs::read_to_string(proc.join("comm")).unwrap_or_default() == "sleep\n";
        }
        assert!(ran_sleep, "the stand-in never ran `sleep`");
        let (stdio, rest): (Vec<_>, Vec<_>) =
            descriptors(&proc).into_iter().partition(|(fd, _)| *fd < 3);
        assert_eq!(rest, inherited, "only what the test process inherited");
        let numbers: Vec<u32> = stdio.iter().map(|(fd, _)| *fd).collect();
        assert_eq!(numbers, [0, 1, 2], "{stdio:?}");
        assert!(stdio[0].1.starts_with("socket:["), "{stdio:?}");
        assert_eq!(stdio[1].1, "/dev/null");
        let ours = descriptors(std::path::Path::new("/proc/self"));
        let stderr = ours.iter().find(|(fd, _)| *fd == 2).unwrap();
        assert_eq!(stdio[2].1, stderr.1);
        let kept: Vec<_> = ours
            .iter()
            .filter(|(_, target)| *target == stdio[0].1)
            .collect();
        assert!(
            kept.is_empty(),
            "the supervisor still holds the worker's end of the control channel: {kept:?}"
        );
        drop(worker);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The descriptors `proc` (a `/proc/<pid>` directory) holds, by number,
    /// with what each names (`proc(5)` `/proc/pid/fd/`).
    fn descriptors(proc: &std::path::Path) -> Vec<(u32, String)> {
        let mut held: Vec<(u32, String)> = std::fs::read_dir(proc.join("fd"))
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                // A descriptor closed between the listing and this read
                // (another test's, under `cargo test`) is skipped.
                let target = std::fs::read_link(entry.path()).ok()?;
                Some((
                    entry.file_name().to_str().unwrap().parse().unwrap(),
                    target.display().to_string(),
                ))
            })
            .collect();
        held.sort();
        held
    }

    /// `O_CLOEXEC` as `/proc/self/fdinfo/<fd>` `flags:` shows it, in octal
    /// (`proc(5)`; the generic value, which x86-64 and aarch64 share).
    const O_CLOEXEC: u32 = 0o2_000_000;

    /// Which of the test process's `held` descriptors above standard error
    /// lack `FD_CLOEXEC` (`proc(5)` `/proc/pid/fdinfo/`), so that every
    /// process it starts inherits them.
    fn inheritable(held: &[(u32, String)]) -> Vec<(u32, String)> {
        held.iter()
            .filter(|(fd, _)| {
                let info =
                    std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap_or_default();
                let flags = info
                    .lines()
                    .find_map(|line| line.strip_prefix("flags:"))
                    .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok());
                *fd > 2 && flags.is_some_and(|flags| flags & O_CLOEXEC == 0)
            })
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn a_worker_reaped_elsewhere_is_a_channel_error_and_stops_without_a_status() {
        use rustix::process::{Pid, WaitOptions, waitpid};
        // The fake clock never moves: the failed wait ends the stop.
        let manager = WorkerManager::new(
            crate::test_support::environment("/usr/bin/true").worker,
            None,
            Arc::new(FakeClock::default()),
        );
        let mut worker = manager.spawn(&[]).unwrap();
        // Reaped before the runtime looks: its wait fails with `ECHILD`.
        let pid = Pid::from_raw(i32::try_from(worker.pid()).unwrap()).unwrap();
        let (reaped, _status) = waitpid(Some(pid), WaitOptions::empty()).unwrap().unwrap();
        assert_eq!(reaped, pid);
        // Its channel's end may come first.
        let mut event = WorkerEvent::ChannelClosed;
        while event == WorkerEvent::ChannelClosed {
            event = worker.next_event().await;
        }
        assert!(
            matches!(&event, WorkerEvent::ChannelError(message) if message.starts_with("waiting for the worker: ")),
            "{event:?}"
        );
        let captured = Captured::default();
        let _logs = captured.install();
        let status = worker.stop(Duration::from_secs(1)).await;
        assert_eq!(status, ExitStatus::default());
        assert_eq!(
            captured.lines("worker unreachable for shutdown").len(),
            1,
            "its channel is gone"
        );
        assert_eq!(captured.lines("worker exit could not be observed").len(), 1);
    }

    /// A worker at `dir/worker.sh` that never reads its control channel,
    /// started on `clock`.
    fn deaf_worker(dir: &std::path::Path, clock: Arc<dyn Clock>) -> Worker {
        let script = dir.join("worker.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let mut config = crate::test_support::environment("/bin/sh").worker;
        config.binary = script;
        WorkerManager::new(config, None, clock).spawn(&[]).unwrap()
    }

    /// Regression: a worker that stopped reading its control channel held
    /// every write to it, and so its driver, for good. Once the socket's
    /// send buffer is full a write waits for room (a non-blocking
    /// `sendmsg(2)` on a full `AF_UNIX` stream socket fails with `EAGAIN`,
    /// observed on Linux 6.18, 2026-11-08); the deadline, on the injected
    /// clock, now ends the wait, kills the worker and gives its channel up,
    /// so every later write fails at once.
    #[tokio::test]
    async fn a_write_to_a_worker_that_reads_nothing_ends_at_its_deadline_and_kills_the_worker() {
        use crate::test_support::{fill_control, settled};
        let dir = crate::test_support::private_dir("worker-deaf");
        let clock = Arc::new(FakeClock::default());
        let mut worker = deaf_worker(&dir, clock.clone());
        fill_control(&mut worker).await;
        let captured = Captured::default();
        let _logs = captured.install();
        let deadline_ms = 2_000;
        assert_eq!(CONTROL_WRITE_DEADLINE, Duration::from_millis(deadline_ms));
        {
            let mut write = std::pin::pin!(worker.grant_connect());
            let real = Duration::from_millis(200);
            assert!(settled(&mut write, real).await.is_none(), "the write waits");
            clock.advance(
                CONTROL_WRITE_DEADLINE
                    .checked_sub(Duration::from_millis(1))
                    .unwrap(),
            );
            assert!(
                settled(&mut write, real).await.is_none(),
                "not before the deadline"
            );
            clock.advance(Duration::from_millis(1));
            let err = settled(&mut write, Duration::from_secs(5))
                .await
                .expect("the deadline ends the write")
                .unwrap_err();
            assert!(
                matches!(err, IpcError::Stalled { deadline_ms: 2_000 }),
                "{err}"
            );
        }
        let lines = captured.lines("worker took no control message within the deadline");
        assert_eq!(lines.len(), 1, "{lines:?}");
        let pid = worker.pid();
        for field in [
            format!("pid={pid}"),
            "kind=\"connect_granted\"".to_owned(),
            "deadline_ms=2000".to_owned(),
        ] {
            assert!(lines[0].contains(&field), "{field}: {lines:?}");
        }
        let killed = captured.lines("worker killed");
        assert_eq!(killed.len(), 1, "{killed:?}");
        assert!(killed[0].contains("control write timed out"), "{killed:?}");
        // Every later write fails at once, the clock standing still, and
        // the worker is killed only once.
        let signal = SignalCommand::Gone {
            signal_id: "01JSIG".into(),
        };
        {
            let mut write = std::pin::pin!(worker.signal(&signal));
            let err = settled(&mut write, Duration::from_secs(5))
                .await
                .expect("at once")
                .unwrap_err();
            assert!(
                matches!(err, IpcError::Stalled { deadline_ms: 2_000 }),
                "{err}"
            );
        }
        let err = worker.prerecord(0).await.unwrap_err();
        assert!(matches!(err, IpcError::Stalled { .. }), "{err}");
        assert_eq!(captured.lines("worker killed").len(), 1);
        assert_eq!(
            captured
                .lines("worker took no control message within the deadline")
                .len(),
            1
        );
        // Its exit counts as a crash.
        let mut event = WorkerEvent::ChannelClosed;
        while event == WorkerEvent::ChannelClosed {
            event = worker.next_event().await;
        }
        assert!(
            matches!(&event, WorkerEvent::Exited(status) if status.signal() == Some(9)),
            "{event:?}"
        );
        // A stop sends nothing on the given-up channel.
        let status = worker.stop(Duration::from_secs(1)).await;
        assert_eq!(status.signal(), Some(9));
        let unreachable = captured.lines("worker unreachable for shutdown");
        assert_eq!(unreachable.len(), 1, "{unreachable:?}");
        assert!(unreachable[0].contains("abandoned"), "{unreachable:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A stop's budget covers its `Shutdown` too: a worker that reads
    /// nothing is killed when the budget runs out, or the write's own
    /// deadline when that comes first, and the stop ends then.
    #[tokio::test]
    async fn a_stop_of_a_worker_that_reads_nothing_ends_within_its_budget() {
        use crate::test_support::{fill_control, settled};
        let dir = crate::test_support::private_dir("worker-deaf-stop");
        let captured = Captured::default();
        let _logs = captured.install();
        // A budget shorter than the write's deadline.
        let clock = Arc::new(FakeClock::default());
        let mut worker = deaf_worker(&dir, clock.clone());
        fill_control(&mut worker).await;
        let budget = Duration::from_millis(500);
        let mut stop = std::pin::pin!(worker.stop(budget));
        let real = Duration::from_millis(200);
        assert!(settled(&mut stop, real).await.is_none(), "the write waits");
        clock.advance(budget.checked_sub(Duration::from_millis(1)).unwrap());
        assert!(
            settled(&mut stop, real).await.is_none(),
            "within the budget"
        );
        clock.advance(Duration::from_millis(1));
        let status = settled(&mut stop, Duration::from_secs(5))
            .await
            .expect("the budget ends the stop");
        assert_eq!(status.signal(), Some(9));
        let missed = captured.lines("worker missed the shutdown budget");
        assert_eq!(missed.len(), 1, "{missed:?}");
        assert!(missed[0].contains("budget_ms=500"), "{missed:?}");
        assert!(
            captured.lines("worker killed").is_empty(),
            "the stop's own kill"
        );
        // A budget longer than it: the write's deadline kills the worker.
        let clock = Arc::new(FakeClock::default());
        let mut worker = deaf_worker(&dir, clock.clone());
        fill_control(&mut worker).await;
        let mut stop = std::pin::pin!(worker.stop(Duration::from_secs(5)));
        assert!(settled(&mut stop, real).await.is_none(), "the write waits");
        clock.advance(CONTROL_WRITE_DEADLINE);
        let status = settled(&mut stop, Duration::from_secs(5))
            .await
            .expect("the write's deadline ends the stop");
        assert_eq!(status.signal(), Some(9));
        let killed = captured.lines("worker killed");
        assert_eq!(killed.len(), 1, "{killed:?}");
        assert!(killed[0].contains("control write timed out"), "{killed:?}");
        let unreachable = captured.lines("worker unreachable for shutdown");
        assert_eq!(unreachable.len(), 1, "{unreachable:?}");
        assert_eq!(
            captured.lines("worker missed the shutdown budget").len(),
            1,
            "the second budget did not run out"
        );
        std::fs::remove_dir_all(dir).unwrap();
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
                recordings: RecordingLimits::DEFAULT,
            },
            None,
            Arc::new(SystemClock),
        );
        let err = manager.spawn(&[554]).unwrap_err();
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
