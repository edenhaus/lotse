//! A connection's driver: one task per `SourceConnection` that owns the
//! state machine and the worker process. It resolves the host, spawns and
//! stops the worker as the machine says, runs the linger and crash-backoff
//! timers on the injected clock and publishes snapshots to the registry.
//!
//! The machine sees resolution as part of connecting: a failed lookup is
//! reported as a `source_unreachable` backoff and retried on the reconnect
//! schedule, so `stream/get` shows it like any other connect failure.
//!
//! Session messages from the handler arrive on the driver's command queue
//! and go to the worker in order; while there is no worker (resolving,
//! backoff, restarting) they wait, and a session closed before its worker
//! got it just leaves the queue. A session is registered with the demux
//! as its offer goes to the worker, with a sink onto that worker's
//! datagram channel. When the worker exits, its sessions close with
//! `worker_crashed`.
//!
//! Every connection attempt the worker announces waits for a permit at
//! the connect gate; the driver sends the worker its grant once its slot
//! holds one, and gives the permit back when the attempt ends, the worker
//! exits or is stopped, or the driver stops ([`crate::connect`]). While a
//! viewer session is on the connection ([`Demand::viewers`]), its
//! attempts queue there ahead of those only preloads want.
//!
//! A stream that opts in to the camera's backchannel or out of it only
//! tells the running worker, whose source turns its probe on or off
//! ([`DriverCommand::Backchannel`]): the connection is never restarted for
//! it, and an offer that requests talk-back meanwhile goes to the worker
//! as any other, where it waits for the probe.
//!
//! A stream's pre-record window reaches the running worker the same way
//! ([`DriverCommand::Prerecord`]): its tracks keep or free their rings, and
//! nothing reconnects; the next worker starts with the window. An event
//! recording's start carries the write end of its pipe to the worker as the
//! message's descriptor; one that never reached a worker before it was
//! stopped ends here, as the worker would have ended it, and so does one
//! that waited `limits.recording_start_timeout_ms` for a worker
//! ([`Driver::recording_start_wait`]; `source_not_live`: the
//! host lookup keeps failing, or a backoff holds the next worker back),
//! one whose recording
//! ended meanwhile is dropped with its pipe (a start still queued when its
//! worker exited never reaches the next one, and one whose recording ended
//! after it was sent is not held for the next), and the recordings of a worker
//! that exits end `worker_crashed`. A start a worker gets after waiting
//! runs only what is left of its `duration_ms`, which counts from
//! `recording/create` ([`duration_left`]), and one whose end passed meanwhile ends
//! here `source_not_live`, as a worker ends one whose source showed
//! nothing before its end; its `prerecord_ms` stays, since the new worker's
//! ring holds nothing from before it. A worker stopped for want of demand
//! runs no recording, and the ids of the recordings it was finishing are free once
//! the driver lets go of it, since their reports reach no one.
//!
//! A signaled source's signaling (`lotse_core::signaling`) passes through
//! the driver both ways: its worker's reports are checked here, untrusted
//! (at most [`MAX_PENDING_OPENS`] opens waiting, each for at most
//! [`OPEN_EXPIRY`]; offers and candidates as [`worker_text::check_signal`]
//! takes them, a malformed one ending its signal with a
//! [`REJECTED`] failure to the worker and the signal's one close to the
//! registry), and handed to the registry ([`State::signal_report`]), whose
//! answers come back on the command queue ([`DriverCommand::Signal`]) and
//! go to the worker they are for if it still runs; one for a worker that
//! is gone is dropped, as its signal went with that worker. The driver
//! times each open's [`SIGNAL_WAIT`] for a subscription to take it, after
//! which the registry refuses it, and tells the registry when the
//! worker's signals end with it: `worker_gone` when it exits,
//! `source_stopped` when it is stopped. A signaled source has no host to
//! look up: its worker starts without a lookup and connects nowhere by
//! itself.
//!
//! [`State::signal_report`]: crate::registry::State::signal_report
//! [`worker_text::check_signal`]: crate::worker_text::check_signal
//!
//! A worker that can no longer be told what to do is killed, so its exit
//! runs the crash path and the machine restarts it with backoff: one whose
//! channel ended while it runs, and one that sent nothing for
//! [`WORKER_SILENCE_LIMIT`] (a worker sends its counters every second).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_api_types::recording::RecordingCloseReason;
use lotse_api_types::session::CloseCode;
use lotse_api_types::signaling::SignalCloseCode;
use lotse_core::backoff::{BackoffPosition, ReconnectBackoff};
use lotse_core::connection::{
    Action, ConnectionConfig, ConnectionError, ConnectionMachine, ConnectionState, Input,
    WorkerReport,
};
use lotse_core::signaling::{REJECTED, close};
use lotse_core::source::SourceError;
use lotse_core::task::{BoxFuture, spawn_named};
use lotse_core::throttle::Throttle;
use lotse_ipc::{
    RecordingReport, RecordingSpec, STOPPED_AS_ASKED, SessionSpec, SignalCommand, SignalReport,
    SourceSpec, SourceTarget,
};
use tokio::sync::{mpsc, watch};

use crate::connect::{CONNECT_LEASE, ConnectSlot, SlotWake};
use crate::net::demux::{DatagramSink, WorkerSink};
use crate::net::turn_client::LeaseGrant;
use crate::registry::{CloseBy, ConnectionSnapshot, Shared, WorkerProcess};
use crate::signaling::{
    LIMIT_REACHED, MAX_ENDED_SIGNALS, MAX_PENDING_OPENS, OPEN_EXPIRY, SIGNAL_WAIT, SignalFrom,
};
use crate::worker::{Worker, WorkerEvent};

/// Session messages a driver holds, queued or in flight, besides the
/// close each open session reserves (`SessionEntry::close_slot`): a
/// driver's queue holds this many and one more per session the daemon
/// allows, so the reserved closes never take room from the rest.
pub(crate) const COMMAND_QUEUE: usize = 256;

/// A worker that sent nothing for this long is killed: it sends its
/// counters once a second from the moment it runs its source, so ten
/// missed in a row is a worker that hangs, not one that is busy.
pub(crate) const WORKER_SILENCE_LIMIT: Duration = Duration::from_secs(10);

/// What is left of a recording's `duration_ms` once its start waited `waited`
/// for a worker: the API counts it from `recording/create` ("how long the
/// recording runs after now", `lotse_api_types::command::RecordingCreate`), a
/// worker from when it gets the start, so the worker gets the rest;
/// `None` when none is, the recording's end passed before a worker could
/// record it. Whole milliseconds are taken off, so the end comes at
/// most a millisecond late, never early.
fn duration_left(duration_ms: u32, waited: Duration) -> Option<u32> {
    let waited_ms = u32::try_from(waited.as_millis()).unwrap_or(u32::MAX);
    duration_ms.checked_sub(waited_ms).filter(|left| *left > 0)
}

/// Who wants a connection, as its registry counts them; the driver follows
/// it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Demand {
    /// The preloaded streams reading from the connection.
    pub(crate) preloads: u32,
    /// The viewer sessions on the connection: each waits for its answer
    /// or its media, so the connection's attempts come first at the
    /// connect gate while there is one.
    pub(crate) viewers: u32,
}

impl Demand {
    /// How many want the connection: the machine runs it while any does.
    pub(crate) const fn total(self) -> u32 {
        self.preloads.saturating_add(self.viewers)
    }
}

/// A message for the connection's worker.
#[derive(Debug)]
pub(crate) enum DriverCommand {
    /// Run this source from now on: a worker switches to it in place, the
    /// next worker starts with it.
    SwitchSource(DriverSpec),
    /// The connection's rule for the camera's backchannel changed (a
    /// stream on it opted in, or the last one out): run this spec, which
    /// asks as the rule now says, from the next connect on, and tell a
    /// running worker, whose sources turn their probe on or off without
    /// restarting.
    Backchannel(DriverSpec),
    /// The connection's pre-record window is `ms` from now on, 0 for none:
    /// tell a running worker, and start the next one with it.
    Prerecord {
        /// The window, in milliseconds.
        ms: u32,
    },
    /// Start this event recording, writing into `pipe`; handed to a worker
    /// only while the recording still runs ([`State::recording_start_wanted`]). Its
    /// `duration_ms` counts from `recording/create` ([`duration_left`]).
    ///
    /// [`State::recording_start_wanted`]: crate::registry::State::recording_start_wanted
    StartRecording {
        /// The recording.
        spec: RecordingSpec,
        /// Its serial in the registry: a start of an earlier recording under the
        /// same id is not this one.
        serial: u64,
        /// The write end of the recording's pipe, which goes to the worker.
        pipe: OwnedFd,
    },
    /// Stop this event recording cleanly.
    StopRecording {
        /// The recording.
        recording_id: String,
    },
    /// Open this session.
    OpenSession(SessionSpec),
    /// A trickled browser candidate.
    Candidate {
        /// The session.
        session_id: String,
        /// The candidate; empty is end-of-candidates.
        candidate: String,
    },
    /// A re-offer from the browser (`webrtc/renegotiate`).
    Renegotiate {
        /// The session.
        session_id: String,
        /// The SDP re-offer.
        sdp: String,
    },
    /// The session's stream changed its orientation to this number.
    Orientation {
        /// The session.
        session_id: String,
        /// The orientation by its number (`lotse_core::Orientation::code`).
        orientation: u8,
    },
    /// Close a session with this code.
    CloseSession {
        /// The session.
        session_id: String,
        /// The `closed` code.
        code: &'static str,
        /// The message.
        message: String,
    },
    /// A relay candidate for a session.
    RelayCandidate {
        /// The session.
        session_id: String,
        /// The relayed address.
        relayed: SocketAddr,
        /// The allocation's server.
        server: SocketAddr,
        /// The host address the allocation's traffic leaves from.
        local: SocketAddr,
        /// The allocation reaches its server over TCP.
        tcp: bool,
        /// Grants the lease's channels to the worker that gets the
        /// candidate, so on TCP only it writes on them.
        grant: LeaseGrant,
    },
    /// A channel bound on one of a session's relay candidates.
    RelayChannel {
        /// The session.
        session_id: String,
        /// The relayed address.
        relayed: SocketAddr,
        /// The peer.
        peer: SocketAddr,
        /// The channel number.
        channel: u16,
    },
    /// Free the backchannel from its talker (`backchannel/release`).
    ReleaseBackchannel {
        /// Only if this session holds it, which the worker decides.
        session_id: Option<String>,
    },
    /// Tell the worker this about its signaled source's signaling: the
    /// answer to an open, or what the client relays on a signal. Only the
    /// worker `worker` (the driver's serial of it,
    /// [`SignalFrom::worker`](crate::signaling::SignalFrom::worker)) is
    /// told: a worker's open ids restart at 1, so an answer queued for a
    /// worker that exited never reaches the next one.
    Signal {
        /// The serial of the worker it is for.
        worker: u64,
        /// What to tell it.
        command: SignalCommand,
    },
    /// An ICE-TCP connection the acceptor verified for one of the
    /// worker's sessions.
    IceTcp {
        /// The connection.
        stream: OwnedFd,
        /// The session's local ufrag.
        local_ufrag: String,
        /// The browser's address.
        peer: SocketAddr,
        /// The first RFC 4571 frame, already read.
        first_frame: Vec<u8>,
    },
}

impl DriverCommand {
    /// The session a message is about, if any.
    fn session_id(&self) -> Option<&str> {
        match self {
            Self::OpenSession(spec) => Some(&spec.session_id),
            Self::Candidate { session_id, .. }
            | Self::Renegotiate { session_id, .. }
            | Self::Orientation { session_id, .. }
            | Self::CloseSession { session_id, .. }
            | Self::RelayCandidate { session_id, .. }
            | Self::RelayChannel { session_id, .. } => Some(session_id),
            Self::IceTcp { .. }
            | Self::SwitchSource(_)
            | Self::Backchannel(_)
            | Self::Prerecord { .. }
            | Self::StartRecording { .. }
            | Self::StopRecording { .. }
            | Self::ReleaseBackchannel { .. }
            | Self::Signal { .. } => None,
        }
    }
}

/// A session's demux sink: uplink datagrams onto its worker's datagram
/// channel, ICE-TCP connections through the driver.
#[derive(Debug)]
pub(crate) struct SessionSink {
    /// The session's local ufrag, which names it to the worker.
    local_ufrag: String,
    /// The worker's datagram channel.
    worker: WorkerSink,
    /// The driver's command queue.
    commands: mpsc::Sender<DriverCommand>,
}

impl DatagramSink for SessionSink {
    fn forward(&self, frame: &[u8]) -> bool {
        self.worker.forward(frame)
    }

    fn ice_tcp(&self, stream: OwnedFd, peer: SocketAddr, first_frame: Vec<u8>) -> bool {
        self.commands
            .try_send(DriverCommand::IceTcp {
                stream,
                local_ufrag: self.local_ufrag.clone(),
                peer,
                first_frame,
            })
            .is_ok()
    }
}

/// What the driver needs to start a worker for its connection.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DriverSpec {
    /// The connection's id.
    pub(crate) connection_id: String,
    /// The full source URL, credentials included, or a signaled source's
    /// protocol.
    pub(crate) target: SourceTarget,
    /// The protocol's fields but the URL, as JSON text.
    pub(crate) options: String,
    /// The host to resolve, as the URL spells it; empty for a signaled
    /// source.
    pub(crate) host: String,
    /// The port, from the URL or the protocol's default.
    pub(crate) port: Option<u16>,
    /// The source asks the camera for its backchannel
    /// ([`Source::wants_backchannel`](lotse_core::source::Source::wants_backchannel)),
    /// as its options say.
    pub(crate) backchannel: bool,
}

impl DriverSpec {
    /// Whether the source's signaling is the control-API client's to
    /// relay: it has no host to look up and no port to connect to.
    pub(crate) const fn signaled(&self) -> bool {
        matches!(self.target, SourceTarget::Signaled(_))
    }

    /// The spec as the worker takes it, with the resolved addresses, where
    /// its reconnect schedule starts, and the connection's pre-record window.
    fn source_spec(
        &self,
        peer_addrs: Vec<SocketAddr>,
        backoff: BackoffPosition,
        prerecord_ms: u32,
    ) -> SourceSpec {
        SourceSpec {
            connection_id: self.connection_id.clone(),
            target: self.target.clone(),
            options: self.options.clone(),
            peer_host: self.host.clone(),
            peer_addrs,
            backoff: lotse_ipc::BackoffPosition {
                attempts: backoff.attempts,
                immediate_used: backoff.immediate_used,
            },
            prerecord_ms,
        }
    }
}

/// Prints the options by name only, as `SourceSpec` and `ConnectionKey`
/// do: a value may be a protocol's secret, and the spec is logged at info
/// on every driver start. Text that is not a JSON object prints as `****`.
impl fmt::Debug for DriverSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let options =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&self.options)
                .map(|options| options.keys().cloned().collect::<Vec<_>>());
        let mut out = f.debug_struct("DriverSpec");
        out.field("connection_id", &self.connection_id)
            .field("target", &self.target);
        match &options {
            Ok(names) => out.field("options", names),
            Err(_) => out.field("options", &"****"),
        };
        out.field("host", &self.host)
            .field("port", &self.port)
            .field("backchannel", &self.backchannel)
            .finish()
    }
}

/// What the driver waits for besides demand, the timers and the worker.
enum Pending {
    /// Nothing.
    Nothing,
    /// The host lookup.
    Resolving(BoxFuture<'static, Result<Vec<SocketAddr>, String>>),
    /// The wait before the lookup is retried.
    Retry(BoxFuture<'static, ()>),
    /// The lookup of a source the running worker is to switch to.
    ResolvingSwitch(BoxFuture<'static, Result<Vec<SocketAddr>, String>>),
    /// The wait before that lookup is retried.
    RetrySwitch(BoxFuture<'static, ()>),
}

impl Pending {
    /// Completes with what the pending work produced; never, when there
    /// is none.
    async fn wait(&mut self) -> Wake {
        match self {
            Self::Nothing => std::future::pending().await,
            Self::Resolving(lookup) => Wake::Resolved(lookup.await),
            Self::Retry(sleep) => {
                sleep.await;
                Wake::RetryResolve
            }
            Self::ResolvingSwitch(lookup) => Wake::SwitchResolved(lookup.await),
            Self::RetrySwitch(sleep) => {
                sleep.await;
                Wake::RetrySwitchResolve
            }
        }
    }
}

/// What woke the driver.
enum Wake {
    /// Demand changed, or the registry dropped the connection (`None`).
    Demand(Option<Demand>),
    /// The worker said something or exited.
    Worker(WorkerEvent),
    /// A session message for the worker.
    Command(DriverCommand),
    /// The linger timer fired.
    LingerExpired,
    /// The crash-backoff timer fired.
    CrashBackoffExpired,
    /// The backoff-window timer fired.
    BackoffWindowExpired,
    /// The worker sent nothing for [`WORKER_SILENCE_LIMIT`].
    WorkerSilent,
    /// The host lookup finished.
    Resolved(Result<Vec<SocketAddr>, String>),
    /// The lookup retry timer fired.
    RetryResolve,
    /// The lookup of the source to switch to finished.
    SwitchResolved(Result<Vec<SocketAddr>, String>),
    /// Its retry timer fired.
    RetrySwitchResolve,
    /// The connect slot has something for the worker.
    Connect(SlotWake),
    /// The standby's connect slot has something for the worker.
    SwitchConnect(SlotWake),
    /// The probe's connect slot has something for the worker.
    ProbeConnect(SlotWake),
    /// The oldest recording start in the queue may have waited
    /// [`Driver::recording_start_wait`].
    RecordingStartWaited,
    /// A signaling open may have waited [`SIGNAL_WAIT`].
    SignalWaited,
}

/// The worker's next event, or never while there is no worker.
async fn next_worker_event(worker: &mut Option<Worker>) -> WorkerEvent {
    match worker {
        Some(worker) => worker.next_event().await,
        None => std::future::pending().await,
    }
}

/// A timer's expiry, or never while it is not running.
async fn timer(slot: &mut Option<BoxFuture<'static, ()>>) {
    match slot {
        Some(sleep) => sleep.await,
        None => std::future::pending().await,
    }
}

/// A signaling open of the running worker's that the registry has not
/// answered yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingOpen {
    /// When the worker asked: its [`SIGNAL_WAIT`] runs from then, and it
    /// is forgotten [`OPEN_EXPIRY`] after.
    asked: Instant,
    /// Its [`SIGNAL_WAIT`] is still to end.
    waiting: bool,
}

impl PendingOpen {
    /// When its [`SIGNAL_WAIT`] ends, while that is still to come.
    fn wait_end(&self) -> Option<Instant> {
        self.waiting
            .then(|| self.asked.checked_add(SIGNAL_WAIT))
            .flatten()
    }
}

/// The driver of one connection.
pub(crate) struct Driver {
    /// What to run.
    spec: DriverSpec,
    /// The registry side.
    shared: Arc<Shared>,
    /// The demand to follow.
    demand: watch::Receiver<Demand>,
    /// Session messages from the handler.
    commands: mpsc::Receiver<DriverCommand>,
    /// The queue's sending side, for the sessions' demux sinks.
    commands_tx: mpsc::Sender<DriverCommand>,
    /// Messages waiting for a worker, in order.
    queued: Vec<DriverCommand>,
    /// When each recording start was queued, oldest first, with its recording's id
    /// and serial; one that left the queue meanwhile is skipped. Taken
    /// with the queue when a worker comes, each start running what is left
    /// of its `duration_ms`.
    recording_waits: VecDeque<(Instant, String, u64)>,
    /// Fires when the oldest of `recording_waits` has waited
    /// [`Self::recording_start_wait`]; `None` while none waits.
    recording_wait: Option<BoxFuture<'static, ()>>,
    /// The state machine.
    machine: ConnectionMachine,
    /// The running worker.
    worker: Option<Worker>,
    /// The linger timer.
    linger: Option<BoxFuture<'static, ()>>,
    /// The crash-backoff timer.
    crash: Option<BoxFuture<'static, ()>>,
    /// The backoff-window timer: until it fires, no new worker connects.
    window: Option<BoxFuture<'static, ()>>,
    /// The deadline for the running worker's next message; `None` while
    /// there is no worker, or its exit is expected.
    silence: Option<BoxFuture<'static, ()>>,
    /// The host lookup or its retry.
    pending: Pending,
    /// The connection's place at the connect gate.
    connect: ConnectSlot,
    /// The standby source's place at the connect gate, during a switch.
    switch_connect: ConnectSlot,
    /// The place at the connect gate of the worker's probe of the
    /// camera's backchannel, a connection beside the source's own.
    probe_connect: ConnectSlot,
    /// The id of the probe `probe_connect` is for: the one the worker
    /// announced last, which its grant names. The worker runs one probe at
    /// a time, so the end of any other is stale and releases nothing.
    probe: u64,
    /// The retry schedule of the host lookup.
    resolve_backoff: ReconnectBackoff,
    /// What the registry sees.
    snapshot: ConnectionSnapshot,
    /// Rate-limits the line of a declaration that changed the tracks: a
    /// worker can declare as fast as it likes, a repeated one is no change
    /// and logs nothing.
    track_lines: Throttle,
    /// The state and error last published, to detect a change.
    published: (ConnectionState, Option<ConnectionError>),
    /// A source switch is under way: the machine's reports are the old
    /// source's until the tracks switch, or until the host lookup of a
    /// new worker, which runs the source switched to.
    switching: bool,
    /// The failed attempt of the source to switch to, until its next one.
    switch_failure: Option<ConnectionError>,
    /// The connection's pre-record window, in milliseconds, which every
    /// worker it starts and every source it switches to gets.
    prerecord_ms: u32,
    /// The serial of the running worker, or of the last one: counts up at
    /// each start, so a signal command names the worker it is for.
    worker_serial: u64,
    /// The running worker's signaling opens the registry has not answered
    /// yet, by the worker's id: at most [`MAX_PENDING_OPENS`], each
    /// timed for its [`SIGNAL_WAIT`] and forgotten after [`OPEN_EXPIRY`],
    /// so an answer or a cancel lost on a full queue cannot hold its place.
    signal_opens: BTreeMap<u64, PendingOpen>,
    /// Fires at the earliest end of a wait of `signal_opens`; `None`
    /// while none is to come.
    signal_wait: Option<BoxFuture<'static, ()>>,
    /// The signals the driver ended itself, over a malformed offer or
    /// candidate, the latest last and at most [`MAX_ENDED_SIGNALS`]: the
    /// rest of their reports, the worker's close included, are dropped, as
    /// the registry already had their close.
    ended_signals: VecDeque<String>,
    /// Rate-limits the line of a worker's signaling open that breaks the
    /// contract, which a worker can repeat as fast as it likes.
    signal_open_lines: Throttle,
    /// Rate-limits the line of a worker's malformed offer or candidate.
    signal_text_lines: Throttle,
    /// Rate-limits the line of a signal command the worker's channel did
    /// not take: every command queued or held for it meets the same
    /// broken channel until the worker's exit is seen.
    signal_send_lines: Throttle,
}

impl Driver {
    /// A driver for `spec` following `demand` and taking `commands`, whose
    /// sending side is `commands_tx`, keeping a pre-record window of
    /// `prerecord_ms` until told another.
    pub(crate) fn new(
        (spec, prerecord_ms): (DriverSpec, u32),
        shared: Arc<Shared>,
        demand: watch::Receiver<Demand>,
        commands: (mpsc::Sender<DriverCommand>, mpsc::Receiver<DriverCommand>),
        config: ConnectionConfig,
    ) -> Self {
        let snapshot = ConnectionSnapshot::idle(shared.clock.wall_now());
        let connect = ConnectSlot::new(Arc::clone(&shared.clock), CONNECT_LEASE);
        let switch_connect = ConnectSlot::new(Arc::clone(&shared.clock), CONNECT_LEASE);
        let probe_connect = ConnectSlot::new(Arc::clone(&shared.clock), CONNECT_LEASE);
        let (commands_tx, commands) = commands;
        Self {
            spec,
            shared,
            demand,
            commands,
            commands_tx,
            queued: Vec::new(),
            recording_waits: VecDeque::new(),
            recording_wait: None,
            machine: ConnectionMachine::new(config),
            worker: None,
            linger: None,
            crash: None,
            window: None,
            silence: None,
            pending: Pending::Nothing,
            connect,
            switch_connect,
            probe_connect,
            probe: 0,
            resolve_backoff: ReconnectBackoff::new(0),
            snapshot,
            track_lines: Throttle::default(),
            published: (ConnectionState::Idle, None),
            switching: false,
            switch_failure: None,
            prerecord_ms,
            worker_serial: 0,
            signal_opens: BTreeMap::new(),
            signal_wait: None,
            ended_signals: VecDeque::new(),
            signal_open_lines: Throttle::default(),
            signal_text_lines: Throttle::default(),
            signal_send_lines: Throttle::default(),
        }
    }

    /// Runs until the registry drops the connection, then stops the worker
    /// within the shutdown budget.
    pub(crate) async fn run(mut self) {
        tracing::info!(spec = ?self.spec, "connection driver started");
        // No demand yet leaves the machine idle and the slots unwanted.
        let initial = *self.demand.borrow_and_update();
        self.follow(initial);
        self.publish();
        loop {
            let wake = self.wait().await;
            if matches!(wake, Wake::Demand(None)) {
                break;
            }
            self.handle(wake).await;
            self.publish();
        }
        self.stop_all().await;
    }

    /// Waits for the next thing to happen. A signaling wait that is over
    /// comes right after demand, ahead of the worker's events and the
    /// commands: those can be ready on every turn, and the biased select
    /// would otherwise keep the wait's timer from ever being polled, so an
    /// open without a subscriber would wait past [`SIGNAL_WAIT`].
    async fn wait(&mut self) -> Wake {
        let signal_due = self.signal_wait_due();
        let Self {
            demand,
            commands,
            worker,
            linger,
            crash,
            window,
            silence,
            pending,
            recording_wait,
            signal_wait,
            connect,
            switch_connect,
            probe_connect,
            ..
        } = self;
        tokio::select! {
            biased;
            changed = demand.changed() => {
                Wake::Demand(changed.ok().map(|()| *demand.borrow_and_update()))
            }
            () = std::future::ready(()), if signal_due => Wake::SignalWaited,
            event = next_worker_event(worker) => Wake::Worker(event),
            wake = connect.wait() => Wake::Connect(wake),
            wake = switch_connect.wait() => Wake::SwitchConnect(wake),
            wake = probe_connect.wait() => Wake::ProbeConnect(wake),
            Some(command) = commands.recv() => Wake::Command(command),
            () = timer(recording_wait) => Wake::RecordingStartWaited,
            () = timer(signal_wait) => Wake::SignalWaited,
            () = timer(linger) => Wake::LingerExpired,
            () = timer(crash) => Wake::CrashBackoffExpired,
            () = timer(window) => Wake::BackoffWindowExpired,
            () = timer(silence) => Wake::WorkerSilent,
            wake = pending.wait() => wake,
        }
    }

    /// Follows `demand`: the machine runs the connection while anyone wants
    /// it, and its attempts come first at the connect gate while a viewer
    /// does.
    fn follow(&mut self, demand: Demand) {
        let wanted = demand.viewers > 0;
        self.connect.want(wanted);
        self.switch_connect.want(wanted);
        self.probe_connect.want(wanted);
        self.feed(Input::Demand(demand.total()));
    }

    /// Acts on what happened; after a command, passes on what the
    /// registry held for the worker while the queue was full.
    async fn handle(&mut self, wake: Wake) {
        let command = matches!(wake, Wake::Command(_));
        self.act(wake).await;
        if command {
            self.release_held_signals().await;
        }
    }

    /// Acts on what happened.
    async fn act(&mut self, wake: Wake) {
        match wake {
            Wake::Demand(Some(demand)) => self.follow(demand),
            Wake::Demand(None)
            | Wake::Connect(SlotWake::LeaseExpired)
            | Wake::SwitchConnect(SlotWake::LeaseExpired)
            | Wake::ProbeConnect(SlotWake::LeaseExpired) => {}
            Wake::Worker(event) => self.on_worker_event(event),
            Wake::Command(DriverCommand::SwitchSource(spec)) => self.on_switch_source(spec),
            Wake::Command(DriverCommand::Backchannel(spec)) => self.on_backchannel(spec).await,
            Wake::Command(DriverCommand::Prerecord { ms }) => self.on_prerecord(ms).await,
            Wake::Command(DriverCommand::Signal { worker, command }) => {
                self.signal_worker(worker, command).await;
            }
            Wake::Command(command) => match self.worker.as_mut() {
                Some(worker) => {
                    Self::send(worker, &self.shared, &self.commands_tx, command).await;
                }
                None => self.queue(command),
            },
            Wake::RecordingStartWaited => self.end_waited_recordings(),
            Wake::SignalWaited => self.end_signal_waits(),
            Wake::LingerExpired => {
                self.linger = None;
                self.feed(Input::LingerExpired);
            }
            Wake::CrashBackoffExpired => {
                self.crash = None;
                self.feed(Input::CrashBackoffExpired);
            }
            Wake::BackoffWindowExpired => {
                self.window = None;
                self.feed(Input::BackoffWindowExpired);
            }
            Wake::WorkerSilent => {
                self.silence = None;
                if let Some(worker) = self.worker.as_mut() {
                    let silent_ms =
                        u64::try_from(WORKER_SILENCE_LIMIT.as_millis()).unwrap_or(u64::MAX);
                    tracing::warn!(
                        pid = worker.pid(),
                        silent_ms,
                        "worker sent nothing within the limit; killing it"
                    );
                    worker.kill("silent");
                }
            }
            Wake::Resolved(Ok(addrs)) => {
                self.pending = Pending::Nothing;
                self.end_switch();
                self.resolve_backoff.reset();
                self.spawn_worker(addrs).await;
            }
            Wake::Resolved(Err(message)) => {
                self.end_switch();
                let retry_in = self.resolve_backoff.next_delay(false);
                tracing::warn!(
                    host = self.spec.host,
                    error = %message,
                    retry_ms = u64::try_from(retry_in.as_millis()).unwrap_or(u64::MAX),
                    "host resolution failed; retrying"
                );
                self.pending = Pending::Retry(self.shared.clock.sleep(retry_in));
                self.feed(Input::Report(WorkerReport::Backoff {
                    error: SourceError::Unreachable(format!(
                        "resolving {}: {message}",
                        self.spec.host
                    )),
                    retry_in,
                    // The lookup is no step of the worker's schedule.
                    position: self.machine.backoff_position(),
                }));
            }
            Wake::Connect(SlotWake::Grant) => {
                if let Some(worker) = self.worker.as_mut()
                    && let Err(err) = worker.grant_connect().await
                {
                    // The exit follows and gives the permit back.
                    tracing::warn!(pid = worker.pid(), error = %err, "connect grant could not be sent to the worker");
                }
            }
            Wake::ProbeConnect(SlotWake::Grant) => {
                if let Some(worker) = self.worker.as_mut()
                    && let Err(err) = worker.grant_probe_connect(self.probe).await
                {
                    // The exit follows and gives the permit back.
                    tracing::warn!(pid = worker.pid(), error = %err, "probe connect grant could not be sent to the worker");
                }
            }
            Wake::RetryResolve => self.retry_resolving(),
            Wake::SwitchResolved(_)
            | Wake::RetrySwitchResolve
            | Wake::SwitchConnect(SlotWake::Grant) => self.handle_switch(wake).await,
        }
    }

    /// Acts on what happened to a switch in progress: the source to
    /// switch to resolved, or not, or the standby's attempt was granted.
    async fn handle_switch(&mut self, wake: Wake) {
        match wake {
            Wake::SwitchResolved(Ok(addrs)) => {
                self.pending = Pending::Nothing;
                self.resolve_backoff.reset();
                if let Some(worker) = self.worker.as_mut() {
                    // A source switched to has failed no attempt yet: its
                    // schedule starts at the first step.
                    let spec =
                        self.spec
                            .source_spec(addrs, BackoffPosition::default(), self.prerecord_ms);
                    if let Err(err) = worker.switch_source(&spec).await {
                        tracing::warn!(pid = worker.pid(), error = %err, "source switch could not be sent to the worker");
                    }
                } else {
                    tracing::debug!(
                        "source to switch to resolved without a worker; the next worker starts with it"
                    );
                }
            }
            Wake::SwitchResolved(Err(message)) => {
                let retry_in = self.resolve_backoff.next_delay(false);
                tracing::warn!(
                    host = self.spec.host,
                    error = %message,
                    retry_ms = u64::try_from(retry_in.as_millis()).unwrap_or(u64::MAX),
                    "host of the source to switch to could not be resolved; retrying"
                );
                let error = ConnectionError::Source(SourceError::Unreachable(format!(
                    "resolving {}: {message}",
                    self.spec.host
                )));
                self.snapshot.last_error = Some(error.clone());
                self.switch_failure = Some(error);
                self.pending = Pending::RetrySwitch(self.shared.clock.sleep(retry_in));
            }
            Wake::RetrySwitchResolve => {
                self.pending = Pending::Nothing;
                self.switch_failure = None;
                if self.worker.is_some() {
                    self.start_resolving_switch();
                }
            }
            Wake::SwitchConnect(SlotWake::Grant) => {
                if let Some(worker) = self.worker.as_mut()
                    && let Err(err) = worker.grant_switch_connect().await
                {
                    tracing::warn!(pid = worker.pid(), error = %err, "standby connect grant could not be sent to the worker");
                }
            }
            _ => {}
        }
    }

    /// `SwitchSource`: the connection runs `spec` from now on. A running
    /// worker switches to it in place once its host is resolved; without
    /// one, the next worker starts with it, a lookup under way is started
    /// over for the new host, and so is a lookup waiting to retry: its wait
    /// was the old host's, so the new one is looked up at once.
    fn on_switch_source(&mut self, spec: DriverSpec) {
        tracing::info!(spec = ?spec, "connection switches its source");
        self.spec = spec;
        self.switching = true;
        self.switch_failure = None;
        self.snapshot.switches = self.snapshot.switches.wrapping_add(1);
        self.machine.source_switched();
        if self.worker.is_some() {
            self.start_resolving_switch();
        } else {
            match self.pending {
                Pending::Resolving(_) => self.start_resolving(),
                Pending::Retry(_) => {
                    tracing::debug!(
                        host = self.spec.host,
                        "source switched while the lookup waited to retry; the new host is looked up at once"
                    );
                    self.retry_resolving();
                }
                Pending::Nothing | Pending::ResolvingSwitch(_) | Pending::RetrySwitch(_) => {}
            }
        }
    }

    /// Ends the wait before the host lookup is retried, which drops its
    /// timer, and looks the host up again: the connection is connecting
    /// once more.
    fn retry_resolving(&mut self) {
        self.pending = Pending::Nothing;
        self.feed(Input::Report(WorkerReport::Connecting));
        self.start_resolving();
    }

    /// `Backchannel`: the connection runs `spec` from now on, which differs
    /// from the last in whether it asks for the camera's backchannel
    /// (ONVIF Streaming Specification §5.3.1). A running worker is told,
    /// and its sources turn their probe on or off: an opt-in probes the
    /// camera at once while the stream plays, an opt-out drops what the
    /// probe found and frees the backchannel from its talker. Nothing
    /// restarts, so the viewers see no gap. Without a worker, the next one
    /// starts with `spec`.
    async fn on_backchannel(&mut self, spec: DriverSpec) {
        let asks = spec.backchannel;
        self.spec = spec;
        let reason = if asks {
            "a stream on the connection asks for the camera's backchannel"
        } else {
            "no stream on the connection asks for the camera's backchannel any more"
        };
        let Some(worker) = self.worker.as_mut() else {
            tracing::info!(
                backchannel = asks,
                reason,
                "no worker runs; the next connect asks for the backchannel as the connection's streams do"
            );
            return;
        };
        tracing::info!(
            pid = worker.pid(),
            backchannel = asks,
            reason,
            "backchannel probe turned on or off in the running worker; the source is not restarted"
        );
        if let Err(err) = worker.backchannel(asks).await {
            // The exit follows, and the next worker starts with the spec.
            tracing::warn!(pid = worker.pid(), error = %err, "backchannel change could not be sent to the worker");
        }
    }

    /// `Prerecord`: the connection keeps a window of `ms` from now on. A
    /// running worker is told, and its tracks keep or free their rings
    /// without reconnecting; without one, the next starts with it.
    async fn on_prerecord(&mut self, ms: u32) {
        self.prerecord_ms = ms;
        let Some(worker) = self.worker.as_mut() else {
            tracing::info!(
                prerecord_ms = ms,
                "no worker runs; the next one starts with the pre-record window"
            );
            return;
        };
        tracing::info!(
            pid = worker.pid(),
            prerecord_ms = ms,
            "pre-record window passed to the running worker; nothing reconnects"
        );
        if let Err(err) = worker.prerecord(ms).await {
            // The exit follows, and the next worker starts with the window.
            tracing::warn!(pid = worker.pid(), error = %err, "pre-record window could not be sent to the worker");
        }
    }

    /// Starts the host lookup of the source to switch to; the worker is
    /// told once it is done.
    fn start_resolving_switch(&mut self) {
        self.pending = Pending::ResolvingSwitch(self.lookup());
    }

    /// The lookup of the source's host, or, for a signaled source, which
    /// reaches its camera through the client's signaling and has no host
    /// to look up, no addresses at once.
    fn lookup(&self) -> BoxFuture<'static, Result<Vec<SocketAddr>, String>> {
        if self.spec.signaled() {
            tracing::debug!("signaled source: no host to look up");
            return Box::pin(std::future::ready(Ok(Vec::new())));
        }
        let host = self.spec.host.clone();
        let port = self.spec.port.unwrap_or(0);
        Box::pin(async move { crate::resolve::resolve(&host, port).await })
    }

    /// A worker's report on one of its recordings, stamped with its arrival
    /// on the wall clock.
    fn on_recording_report(&self, recording_id: &str, event: RecordingReport) {
        let at = self.shared.clock.wall_now();
        self.shared
            .lock()
            .recording_report(&self.spec.connection_id, recording_id, event, at);
    }

    /// The worker said something or exited.
    fn on_worker_event(&mut self, event: WorkerEvent) {
        match event {
            // The exit follows and runs the crash path.
            WorkerEvent::ChannelClosed | WorkerEvent::ChannelError(_) | WorkerEvent::Exited(_) => {
                self.silence = None;
            }
            _ => self.silence = Some(self.shared.clock.sleep(WORKER_SILENCE_LIMIT)),
        }
        match event {
            WorkerEvent::Ready { pid, memory } => {
                tracing::debug!(pid, memory = memory.is_some(), "worker ready");
                if let Some(worker) = &mut self.snapshot.worker {
                    worker.memory = memory;
                }
            }
            WorkerEvent::Report(report) => {
                match &report {
                    WorkerReport::Connecting => {
                        self.connect.request(&self.shared.connects, "connecting");
                    }
                    WorkerReport::Reconnecting(_) => {
                        self.snapshot.reconnects = self.snapshot.reconnects.saturating_add(1);
                        self.connect.request(&self.shared.connects, "reconnecting");
                    }
                    WorkerReport::Live => self.connect.release("live"),
                    WorkerReport::Backoff { .. } => self.connect.release("backoff"),
                    WorkerReport::Stable => {}
                }
                self.feed(Input::Report(report));
            }
            WorkerEvent::SourceStopped => {
                self.connect.release("source stopped");
                tracing::debug!("worker source stopped");
            }
            WorkerEvent::SwitchReport(_) | WorkerEvent::StandbyStopped | WorkerEvent::Switched => {
                self.on_standby_event(event);
            }
            WorkerEvent::Tracks(tracks) => {
                if tracks != self.snapshot.tracks {
                    if let Some(count) = self.track_lines.hit(self.shared.clock.now()) {
                        tracing::info!(tracks = tracks.len(), count, "tracks declared");
                    }
                    self.snapshot.tracks = tracks;
                }
            }
            WorkerEvent::Stats(stats) => self.snapshot.stats = Some(stats),
            WorkerEvent::ProbeConnecting(probe) => {
                self.probe = probe;
                self.probe_connect
                    .request(&self.shared.connects, "backchannel probe");
            }
            WorkerEvent::ProbeEnded(probe) if probe == self.probe => {
                self.probe_connect.release("backchannel probe over");
            }
            WorkerEvent::ProbeEnded(probe) => {
                tracing::debug!(
                    probe,
                    current = self.probe,
                    "end of a backchannel probe the probe permit is not for; ignored"
                );
            }
            WorkerEvent::Session { session_id, event } => {
                let now = self.shared.clock.now();
                self.shared.lock().session_report(
                    &self.spec.connection_id,
                    &session_id,
                    event,
                    now,
                );
            }
            WorkerEvent::Recording {
                recording_id,
                event,
            } => self.on_recording_report(&recording_id, event),
            WorkerEvent::Signal(report) => self.on_signal_report(report),
            WorkerEvent::Talker {
                session_id,
                reason,
                at,
            } => {
                let _talker = self.shared.lock().talker_changed(
                    &self.spec.connection_id,
                    &session_id,
                    reason,
                    at,
                );
            }
            WorkerEvent::ChannelClosed => {
                tracing::warn!("worker closed its channel; killing it");
                if let Some(worker) = self.worker.as_mut() {
                    worker.kill("channel closed");
                }
            }
            WorkerEvent::ChannelError(message) => {
                tracing::warn!(error = %message, "worker channel failed; killing it");
                if let Some(worker) = self.worker.as_mut() {
                    worker.kill("channel failed");
                }
            }
            WorkerEvent::Exited(status) => self.on_worker_exited(status),
        }
    }

    /// A signal report of the worker's, untrusted: checked, then handed to
    /// the registry. An open past [`MAX_PENDING_OPENS`] is refused at once,
    /// one the worker already waits for and a cancel of one answered are
    /// ignored, an offer or candidate that fails
    /// [`check_signal`](crate::worker_text::check_signal) ends its signal
    /// (the worker is told it was rejected, the registry that it closed),
    /// and what the worker reports on a signal ended so is dropped.
    fn on_signal_report(&mut self, report: SignalReport) {
        if let SignalReport::Offer { signal_id, .. }
        | SignalReport::Candidate { signal_id, .. }
        | SignalReport::Closed { signal_id, .. } = &report
            && self.ended_signals.contains(signal_id)
        {
            if matches!(report, SignalReport::Closed { .. }) {
                // The worker's last report of it.
                self.ended_signals.retain(|ended| ended != signal_id);
            }
            tracing::debug!(signal = %signal_id, "report on a signal the driver ended; dropped");
            return;
        }
        let report = match report {
            SignalReport::Open { request } => {
                self.expire_opens();
                if self.signal_opens.contains_key(&request) {
                    self.signal_misuse(request, "a second open under one id; ignored");
                    return;
                }
                if self.signal_opens.len() >= MAX_PENDING_OPENS {
                    self.signal_misuse(
                        request,
                        "more opens waiting than a worker may have; refused",
                    );
                    self.tell_worker(SignalCommand::Refused {
                        request,
                        code: LIMIT_REACHED.to_owned(),
                        message: format!(
                            "a worker may have {MAX_PENDING_OPENS} signaling opens waiting"
                        ),
                    });
                    return;
                }
                let asked = self.shared.clock.now();
                self.signal_opens.insert(
                    request,
                    PendingOpen {
                        asked,
                        waiting: true,
                    },
                );
                self.arm_signal_wait();
                SignalReport::Open { request }
            }
            SignalReport::Cancel { request } => {
                // One the driver no longer waits on (answered, or
                // forgotten after OPEN_EXPIRY) still goes to the registry,
                // which drops it unless it holds the open.
                if self.signal_opens.remove(&request).is_none() {
                    tracing::debug!(
                        request,
                        "cancel of a signaling open the driver does not wait on; passed on"
                    );
                }
                SignalReport::Cancel { request }
            }
            report => {
                if let SignalReport::Offer { signal_id, .. }
                | SignalReport::Candidate { signal_id, .. } = &report
                    && let Err(reason) = crate::worker_text::check_signal(&report)
                {
                    let signal_id = signal_id.clone();
                    self.malformed_signal(signal_id, reason)
                } else {
                    report
                }
            }
        };
        self.to_registry(report);
    }

    /// Hands the checked `report` to the registry.
    fn to_registry(&self, report: SignalReport) {
        let (now, wall) = (self.shared.clock.now(), self.shared.clock.wall_now());
        let from = self.signal_from();
        self.shared.lock().signal_report(&from, report, now, wall);
    }

    /// Where the running worker's signal reports come from: this
    /// connection's worker of the current serial.
    fn signal_from(&self) -> SignalFrom<'_> {
        SignalFrom {
            connection: &self.spec.connection_id,
            worker: self.worker_serial,
        }
    }

    /// Forgets the opens waiting longer than [`OPEN_EXPIRY`]: their answer
    /// or cancel was lost, as the attempt that asked is over by then. The
    /// registry forgets them too, as it does a cancel, so it holds no open
    /// the driver does not count.
    fn expire_opens(&mut self) {
        let now = self.shared.clock.now();
        let mut expired = Vec::new();
        self.signal_opens.retain(|request, open| {
            let waiting = now.saturating_duration_since(open.asked) < OPEN_EXPIRY;
            if !waiting {
                tracing::info!(
                    request,
                    expiry_ms = OPEN_EXPIRY.as_millis(),
                    "a signaling open got no answer in time; forgotten"
                );
                expired.push(*request);
            }
            waiting
        });
        for request in expired {
            self.to_registry(SignalReport::Cancel { request });
        }
    }

    /// Whether a wait of `signal_opens` is over now and still to be ended.
    fn signal_wait_due(&self) -> bool {
        let now = self.shared.clock.now();
        self.signal_opens
            .values()
            .filter_map(PendingOpen::wait_end)
            .any(|end| end <= now)
    }

    /// Times the earliest wait of `signal_opens` still to end; none when
    /// none is.
    fn arm_signal_wait(&mut self) {
        let now = self.shared.clock.now();
        self.signal_wait = self
            .signal_opens
            .values()
            .filter_map(PendingOpen::wait_end)
            .min()
            .map(|deadline| {
                self.shared
                    .clock
                    .sleep(deadline.saturating_duration_since(now))
            });
    }

    /// `SignalWaited`: every open whose [`SIGNAL_WAIT`] is over goes to
    /// the registry, which refuses it unless a subscription took it
    /// meanwhile. One the registry refuses stays among the opens until its
    /// answer passes here; one it no longer holds (taken, its answer on
    /// the way) is forgotten now, so no lost answer can hold its place.
    fn end_signal_waits(&mut self) {
        let now = self.shared.clock.now();
        let mut ended = Vec::new();
        for (request, open) in &mut self.signal_opens {
            if open.wait_end().is_some_and(|end| end <= now) {
                open.waiting = false;
                ended.push(*request);
            }
        }
        for request in ended {
            let from = self.signal_from();
            let refused = self.shared.lock().signal_wait_expired(&from, request, now);
            if !refused {
                self.signal_opens.remove(&request);
            }
        }
        self.arm_signal_wait();
    }

    /// The worker's signals are over, closing `code` with `message`: its
    /// opens and the signals the driver ended are forgotten, here and in
    /// the registry, and its signals closed.
    fn signals_ended(&mut self, code: SignalCloseCode, message: &str) {
        self.signal_opens.clear();
        self.signal_wait = None;
        self.ended_signals.clear();
        self.shared
            .lock()
            .signals_ended(&self.spec.connection_id, code, message);
    }

    /// Ends the signal `signal_id`, whose offer or candidate failed the
    /// check for `reason`: the worker is told the relay rejected it
    /// ([`REJECTED`]: its source's fault, not the camera's), and its close
    /// goes to the registry in the report's place, the only one it gets.
    fn malformed_signal(&mut self, signal_id: String, reason: &'static str) -> SignalReport {
        if let Some(count) = self.signal_text_lines.hit(self.shared.clock.now()) {
            tracing::warn!(signal = %signal_id, reason, count, "a worker's signaling offer or candidate is malformed; signal ended");
        }
        let message = "the worker's offer or candidate was malformed";
        self.tell_worker(SignalCommand::Failed {
            signal_id: signal_id.clone(),
            code: REJECTED.to_owned(),
            message: message.to_owned(),
        });
        if self.ended_signals.len() >= MAX_ENDED_SIGNALS {
            self.ended_signals.pop_front();
        }
        self.ended_signals.push_back(signal_id.clone());
        SignalReport::Closed {
            signal_id,
            code: close::INTERNAL_ERROR.to_owned(),
            message: message.to_owned(),
        }
    }

    /// Logs a worker's signaling open `request` that breaks the contract
    /// for `reason`, rate-limited.
    fn signal_misuse(&mut self, request: u64, reason: &'static str) {
        if let Some(count) = self.signal_open_lines.hit(self.shared.clock.now()) {
            tracing::warn!(
                request,
                reason,
                count,
                "a worker's signaling open breaks the contract"
            );
        }
    }

    /// Tells the running worker `command`, which the driver decided on its
    /// own, through the registry ([`State::tell_worker`]): queued behind
    /// the registry's commands, or held with them while the queue is full,
    /// so it is never lost and stays in order with them.
    ///
    /// [`State::tell_worker`]: crate::registry::State::tell_worker
    fn tell_worker(&self, command: SignalCommand) {
        self.shared
            .lock()
            .tell_worker(&self.spec.connection_id, self.worker_serial, command);
    }

    /// After a command, passes on the signal commands the registry held
    /// for the worker while the queue was full
    /// ([`State::take_held_signals`]), once the driver has handled those
    /// the queue held before them or the queue is empty: so they go after
    /// everything queued before them, and before anything the registry or
    /// the driver tells the worker after (the registry holds every later
    /// one while it holds any). The queue's emptiness is read under the
    /// registry's lock, under which every signal command is queued or
    /// held: read before it, another task could fill the queue and start a
    /// hold in between, and the hold would go ahead of what the queue
    /// still holds.
    ///
    /// [`State::take_held_signals`]: crate::registry::State::take_held_signals
    async fn release_held_signals(&mut self) {
        let held = {
            let mut state = self.shared.lock();
            let drained = self.commands.is_empty();
            state.take_held_signals(&self.spec.connection_id, drained)
        };
        for (worker, command) in held {
            self.signal_worker(worker, command).await;
        }
    }

    /// `Signal`: passes `command` to the running worker if it is the
    /// worker `worker` the command is for, an open's answer taking it off
    /// the opens waiting. Otherwise it is dropped: the signal it concerns
    /// went with the worker, and an open id of that worker's may name
    /// another open of the running one.
    async fn signal_worker(&mut self, worker: u64, command: SignalCommand) {
        let running = self
            .worker
            .as_mut()
            .filter(|_| worker == self.worker_serial);
        let Some(running) = running else {
            tracing::debug!(
                worker,
                running = self.worker_serial,
                ?command,
                "signal command for a worker that is gone; dropped with its signal"
            );
            return;
        };
        if let SignalCommand::Opened { request, .. } | SignalCommand::Refused { request, .. } =
            &command
        {
            self.signal_opens.remove(request);
        }
        if let Err(err) = running.signal(&command).await
            && let Some(count) = self.signal_send_lines.hit(self.shared.clock.now())
        {
            // The exit follows, and the signals go with the worker.
            tracing::warn!(pid = running.pid(), error = %err, count, "signal command could not be sent to the worker");
        }
    }

    /// The standby source's report, its stop, or its taking over: its
    /// connect permit and the last error.
    fn on_standby_event(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::SwitchReport(report) => match report {
                WorkerReport::Connecting => {
                    self.switch_failure = None;
                    self.switch_connect
                        .request(&self.shared.connects, "standby connecting");
                }
                WorkerReport::Reconnecting(_) => {
                    self.switch_failure = None;
                    self.switch_connect
                        .request(&self.shared.connects, "standby reconnecting");
                }
                WorkerReport::Live => {
                    self.switch_failure = None;
                    self.switch_connect.release("standby live");
                }
                WorkerReport::Backoff {
                    error, retry_in, ..
                } => {
                    self.switch_connect.release("standby backoff");
                    tracing::warn!(
                        error.code = error.code(),
                        error = %error,
                        retry_ms = u64::try_from(retry_in.as_millis()).unwrap_or(u64::MAX),
                        "the source to switch to failed; the old one keeps streaming"
                    );
                    let error = ConnectionError::Source(error);
                    self.snapshot.last_error = Some(error.clone());
                    self.switch_failure = Some(error);
                }
                // The standby's schedule is not the connection's: the
                // switched-to source starts its own at the first step.
                WorkerReport::Stable => {}
            },
            WorkerEvent::StandbyStopped => self.switch_connect.release("standby stopped"),
            WorkerEvent::Switched => {
                self.switch_connect.release("switched");
                self.snapshot.last_error = None;
                self.end_switch();
                tracing::info!("the tracks switched to the new source");
                // The tracks switch at a keyframe of the new source, which
                // is live; the old one's state is over.
                self.feed(Input::Report(WorkerReport::Live));
            }
            _ => {}
        }
    }

    /// The worker process exited: its sessions close, the permits go
    /// back, and the machine restarts it with backoff if it crashed.
    fn on_worker_exited(&mut self, status: ExitStatus) {
        self.worker = None;
        self.signals_ended(SignalCloseCode::WorkerGone, "the source's worker exited");
        self.connect.release("worker exited");
        self.switch_connect.release("worker exited");
        self.probe_connect.release("worker exited");
        self.snapshot.worker = None;
        self.talker_gone();
        self.queued.clear();
        // The old source and the standby went with the worker: the next
        // one runs the source switched to, and a crash is the failure an
        // offer meanwhile closes with.
        self.end_switch();
        let connection = self.spec.connection_id.clone();
        let mut state = self.shared.lock();
        state.close_sessions_where(
            |session| session.connection == connection,
            CloseCode::WorkerCrashed,
            "the camera's worker process exited",
            CloseBy::WorkerGone,
        );
        // The pipes' write ends died with it: the bodies are cut.
        state.recordings_worker_gone(&connection);
        drop(state);
        let crashes = self.machine.crashes();
        self.feed(Input::WorkerExited);
        if self.machine.crashes() > crashes {
            self.snapshot.crashes = self.machine.crashes();
            self.snapshot.last_crash = Some(self.shared.clock.wall_now());
            self.shared.count_crash();
            tracing::error!(
                code = status.code(),
                signal = status.signal(),
                crashes = self.snapshot.crashes,
                "worker crashed"
            );
        } else {
            tracing::info!(code = status.code(), "worker exited");
        }
    }

    /// The worker is gone, and the talker's session with it: the
    /// backchannel is free.
    fn talker_gone(&self) {
        let now = self.shared.clock.wall_now();
        self.shared
            .lock()
            .talker_gone(&self.spec.connection_id, now);
    }

    /// Feeds the machine and performs what it asks for, including the
    /// inputs those actions produce at once.
    fn feed(&mut self, input: Input) {
        let mut queue = vec![input];
        while let Some(input) = queue.pop() {
            let now = self.shared.clock.now();
            for action in self.machine.handle(input, now) {
                if let Some(follow_up) = self.perform(action) {
                    queue.push(follow_up);
                }
            }
        }
    }

    /// Performs one action; a stop yields the exit the machine then expects.
    fn perform(&mut self, action: Action) -> Option<Input> {
        match action {
            Action::SpawnWorker => {
                self.start_resolving();
                None
            }
            Action::StopWorker => {
                self.pending = Pending::Nothing;
                self.silence = None;
                self.connect.release("worker stopped");
                self.probe_connect.release("worker stopped");
                self.signals_ended(SignalCloseCode::SourceStopped, "the source stopped");
                if let Some(worker) = self.worker.take() {
                    self.snapshot.worker = None;
                    self.talker_gone();
                    // Its reports reach no one from here on: the recordings it
                    // was finishing hold their ids no longer. No recording it
                    // got runs: a recording is demand, and it is stopped for
                    // want of any.
                    self.shared
                        .lock()
                        .forget_stopping_recordings(&self.spec.connection_id);
                    let shared = Arc::clone(&self.shared);
                    let stop = async move {
                        let _status = worker.stop(shared.shutdown_budget, &shared.clock).await;
                    };
                    let _handle =
                        spawn_named("worker.stop", self.shared.tracker.track_future(stop));
                }
                Some(Input::WorkerExited)
            }
            Action::StartLinger(linger) => {
                self.linger = Some(self.shared.clock.sleep(linger));
                None
            }
            Action::CancelLinger => {
                self.linger = None;
                None
            }
            Action::StartCrashBackoff(delay) => {
                self.crash = Some(self.shared.clock.sleep(delay));
                None
            }
            Action::CancelCrashBackoff => {
                self.crash = None;
                None
            }
            Action::StartBackoffWindow(delay) => {
                self.window = Some(self.shared.clock.sleep(delay));
                None
            }
        }
    }

    /// Starts the host lookup; the worker follows once it is done.
    fn start_resolving(&mut self) {
        self.pending = Pending::Resolving(self.lookup());
    }

    /// Starts the worker and hands it the source; a failed start counts as
    /// a crash, so the machine retries with its backoff.
    async fn spawn_worker(&mut self, addrs: Vec<SocketAddr>) {
        let ports: Vec<u16> = self.spec.port.into_iter().collect();
        match self.shared.manager.spawn(&ports) {
            Ok(mut worker) => {
                self.worker_serial = self.worker_serial.wrapping_add(1);
                // The schedule continues where the last worker's left off.
                let spec = self.spec.source_spec(
                    addrs,
                    self.machine.backoff_position(),
                    self.prerecord_ms,
                );
                if let Err(err) = worker.run_source(&spec).await {
                    tracing::warn!(pid = worker.pid(), error = %err, "source could not be sent to the worker");
                }
                self.snapshot.worker = Some(WorkerProcess {
                    pid: worker.pid(),
                    started: self.shared.clock.now(),
                    memory: None,
                });
                // The queued starts leave with their waits: each runs what is left.
                let waits = std::mem::take(&mut self.recording_waits);
                self.recording_wait = None;
                let now = self.shared.clock.now();
                for command in std::mem::take(&mut self.queued) {
                    let Some(command) = self.after_the_wait(command, &waits, now) else {
                        continue;
                    };
                    Self::send(&mut worker, &self.shared, &self.commands_tx, command).await;
                }
                self.worker = Some(worker);
                self.silence = Some(self.shared.clock.sleep(WORKER_SILENCE_LIMIT));
            }
            Err(err) => {
                tracing::error!(error = %err, "worker could not be started");
                self.feed(Input::WorkerExited);
            }
        }
    }

    /// Holds a message until there is a worker. A close takes its session's
    /// messages out of the queue instead: the worker never saw it. A recording's
    /// start is held only while its recording runs ([`State::recording_start_wanted`]):
    /// a stale one (its recording ended after it was sent, and the id may name a
    /// later recording by now) is dropped with its pipe, so a stop behind it
    /// finds nothing to end here and never ends the later recording.
    ///
    /// [`State::recording_start_wanted`]: crate::registry::State::recording_start_wanted
    fn queue(&mut self, command: DriverCommand) {
        match command {
            DriverCommand::StartRecording {
                ref spec, serial, ..
            } => {
                let recording_id = spec.recording_id.clone();
                if self
                    .shared
                    .lock()
                    .recording_start_wanted(&recording_id, serial)
                {
                    self.recording_waits
                        .push_back((self.shared.clock.now(), recording_id, serial));
                    if self.recording_wait.is_none() {
                        self.recording_wait =
                            Some(self.shared.clock.sleep(self.recording_start_wait()));
                    }
                    self.queued.push(command);
                }
            }
            DriverCommand::CloseSession { session_id, .. } => {
                self.queued
                    .retain(|queued| queued.session_id() != Some(session_id.as_str()));
            }
            DriverCommand::IceTcp { peer, .. } => {
                tracing::debug!(%peer, "ice-tcp connection without a worker; closed");
            }
            DriverCommand::StopRecording { recording_id } => self.unqueue_recording(&recording_id),
            // Without a worker no session talks.
            DriverCommand::ReleaseBackchannel { session_id } => {
                tracing::debug!(
                    session.id = ?session_id,
                    "backchannel release without a worker; nothing held"
                );
            }
            command => self.queued.push(command),
        }
    }

    /// A recording stopped while it waits for a worker: its start leaves the
    /// queue with its pipe, and it ends here as its worker would have
    /// ended it, [`STOPPED_AS_ASKED`] with nothing written. One not queued went with
    /// the worker that had it, which ended it, or was dropped as stale
    /// ([`Self::queue`]). A start the queue holds is that of the recording that
    /// holds the id, running or ending, and a later recording's start comes
    /// after this stop, so the end is that recording's.
    fn unqueue_recording(&mut self, recording_id: &str) {
        if !self.unqueue_start(recording_id, None) {
            tracing::debug!(
                recording.id = recording_id,
                "recording stop without a worker for a recording none holds; dropped"
            );
            return;
        }
        tracing::debug!(
            recording.id = recording_id,
            "recording stopped before a worker got it; ended here"
        );
        self.end_unqueued(recording_id, STOPPED_AS_ASKED);
    }

    /// How long a recording's start waits in the queue for a worker: the
    /// configured `limits.recording_start_timeout_ms` ([`RecordingLimits::start_timeout`]),
    /// as long as a worker gives a recording to find a keyframe to start at. No
    /// worker runs the recording meanwhile, so none of its timeouts does, and the
    /// body's `GET` ends the only deadline the registry keeps: without this
    /// bound, a host lookup that keeps failing would hold the recording, its
    /// subscription and its pipe for good.
    ///
    /// [`RecordingLimits::start_timeout`]: crate::RecordingLimits::start_timeout
    fn recording_start_wait(&self) -> Duration {
        self.shared.lock().recording_limits.start_timeout
    }

    /// The recordings whose start waited [`Self::recording_start_wait`] for a worker
    /// and still waits end here as a worker ends one that finds no keyframe
    /// in time, `source_not_live` with nothing written; the timer then
    /// waits for the next oldest.
    fn end_waited_recordings(&mut self) {
        let now = self.shared.clock.now();
        let wait = self.recording_start_wait();
        let waited = self
            .recording_waits
            .iter()
            .take_while(|(queued, ..)| now.saturating_duration_since(*queued) >= wait)
            .count();
        let ended: Vec<(Instant, String, u64)> = self.recording_waits.drain(..waited).collect();
        for (_, recording_id, serial) in ended {
            if self.unqueue_start(&recording_id, Some(serial)) {
                tracing::info!(
                    recording.id = %recording_id,
                    serial,
                    waited_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                    "no worker took the recording's start in time; ended here source_not_live"
                );
                self.end_unqueued(&recording_id, RecordingCloseReason::SourceNotLive.as_str());
            }
        }
        self.recording_wait = self.recording_waits.front().map(|(queued, ..)| {
            let left = wait.saturating_sub(now.saturating_duration_since(*queued));
            self.shared.clock.sleep(left)
        });
    }

    /// Prepares a queued `command` for the worker that now comes, `now`
    /// being when it does and `waits` the queue's record of when each recording
    /// start was queued. Any command but a recording's start comes back
    /// unchanged. That start comes back with `duration_ms` set to
    /// what is left of it ([`duration_left`]), the wait being the one `waits`
    /// holds for its recording id and serial (none: no wait). With nothing left
    /// its end passed while it waited: it is dropped with its pipe, and if
    /// its recording still runs (`recording_start_wanted`, asked here only, since
    /// its false branch logs and frees the id) the recording ends here
    /// `source_not_live`, as a worker ends one whose source showed nothing
    /// before its end. A stale start (its recording ended while queued, the id
    /// possibly taken by a later serial) must not end that later recording,
    /// which a report matches by id alone: hence the guard. `prerecord_ms` is
    /// left alone: the new worker's ring holds nothing captured before it
    /// gets the start, so the recording begins at the first keyframe either
    /// way (`RecordingCreate`'s "the source not live yet").
    fn after_the_wait(
        &self,
        command: DriverCommand,
        waits: &VecDeque<(Instant, String, u64)>,
        now: Instant,
    ) -> Option<DriverCommand> {
        let DriverCommand::StartRecording {
            mut spec,
            serial,
            pipe,
        } = command
        else {
            return Some(command);
        };
        let duration_ms = spec.duration_ms;
        let waited = waits
            .iter()
            .find(|(_, recording_id, queued)| {
                *recording_id == spec.recording_id && *queued == serial
            })
            .map_or(Duration::ZERO, |(queued, ..)| {
                now.saturating_duration_since(*queued)
            });
        let waited_ms = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX);
        if let Some(left) = duration_left(duration_ms, waited) {
            spec.duration_ms = left;
            tracing::debug!(
                recording.id = %spec.recording_id,
                serial,
                waited_ms,
                duration_ms = left,
                "recording start handed to the new worker; it runs what is left of duration_ms"
            );
            return Some(DriverCommand::StartRecording { spec, serial, pipe });
        }
        drop(pipe);
        if self
            .shared
            .lock()
            .recording_start_wanted(&spec.recording_id, serial)
        {
            tracing::info!(
                recording.id = %spec.recording_id,
                serial,
                waited_ms,
                duration_ms,
                "the recording's end passed while its start waited for a worker; ended here source_not_live"
            );
            self.end_unqueued(
                &spec.recording_id,
                RecordingCloseReason::SourceNotLive.as_str(),
            );
        }
        None
    }

    /// Takes the start of recording `recording_id` out of the queue with its pipe,
    /// only `serial`'s when given; whether there was one.
    fn unqueue_start(&mut self, recording_id: &str, serial: Option<u64>) -> bool {
        let before = self.queued.len();
        self.queued.retain(|queued| {
            !matches!(
                queued,
                DriverCommand::StartRecording { spec, serial: queued, .. }
                    if spec.recording_id == recording_id && serial.is_none_or(|serial| serial == *queued)
            )
        });
        self.queued.len() < before
    }

    /// Ends recording `recording_id`, whose start no worker got, for `reason`, by
    /// the name its worker would have ended it with: nothing written, so
    /// its body ends empty.
    fn end_unqueued(&self, recording_id: &str, reason: &str) {
        let closed = RecordingReport::Closed {
            reason: reason.to_owned(),
            bytes: 0,
            duration_ms: 0,
            gaps: 0,
        };
        let at = self.shared.clock.wall_now();
        self.shared
            .lock()
            .recording_report(&self.spec.connection_id, recording_id, closed, at);
    }

    /// Passes a message to `worker`. An offer is registered with the demux
    /// first, with a sink whose ICE-TCP hand-offs come back on `commands`,
    /// unless its session closed in the meantime; a recording's start goes only
    /// while its recording runs, else its pipe is dropped.
    async fn send(
        worker: &mut Worker,
        shared: &Shared,
        commands: &mpsc::Sender<DriverCommand>,
        command: DriverCommand,
    ) {
        let session = command.session_id().map(str::to_owned);
        let sent = match command {
            // Handled by the driver itself, never queued for a worker.
            DriverCommand::SwitchSource(_)
            | DriverCommand::Backchannel(_)
            | DriverCommand::Prerecord { .. }
            | DriverCommand::Signal { .. } => return,
            DriverCommand::StartRecording { spec, serial, pipe } => {
                if !shared
                    .lock()
                    .recording_start_wanted(&spec.recording_id, serial)
                {
                    return;
                }
                worker.start_recording(&spec, pipe).await
            }
            DriverCommand::StopRecording { recording_id } => {
                worker.stop_recording(&recording_id).await
            }
            DriverCommand::OpenSession(spec) => {
                let sink = Arc::new(SessionSink {
                    local_ufrag: spec.ice_ufrag.clone(),
                    worker: WorkerSink {
                        datagrams: worker.datagrams(),
                    },
                    commands: commands.clone(),
                });
                if !shared.lock().register_session(&spec, sink) {
                    tracing::debug!(session.id = %spec.session_id, "session closed before its worker got it");
                    return;
                }
                worker.open_session(&spec).await
            }
            DriverCommand::Candidate {
                session_id,
                candidate,
            } => worker.candidate(&session_id, &candidate).await,
            DriverCommand::Renegotiate { session_id, sdp } => {
                worker.renegotiate(&session_id, &sdp).await
            }
            DriverCommand::Orientation {
                session_id,
                orientation,
            } => worker.session_orientation(&session_id, orientation).await,
            DriverCommand::CloseSession {
                session_id,
                code,
                message,
            } => worker.close_session(&session_id, code, &message).await,
            DriverCommand::RelayCandidate {
                session_id,
                relayed,
                server,
                local,
                tcp,
                grant,
            } => {
                grant.to(worker.relay_owner());
                worker
                    .relay_candidate(&session_id, relayed, server, local, tcp)
                    .await
            }
            DriverCommand::RelayChannel {
                session_id,
                relayed,
                peer,
                channel,
            } => {
                worker
                    .relay_channel(&session_id, relayed, peer, channel)
                    .await
            }
            DriverCommand::IceTcp {
                stream,
                local_ufrag,
                peer,
                first_frame,
            } => {
                worker
                    .ice_tcp(stream, &local_ufrag, peer, first_frame)
                    .await
            }
            DriverCommand::ReleaseBackchannel { session_id } => {
                worker.release_backchannel(session_id).await
            }
        };
        if let Err(err) = sent {
            // The exit follows and closes the sessions.
            tracing::warn!(pid = worker.pid(), session.id = ?session, error = %err, "session message could not be sent to the worker");
        }
    }

    /// The switch is over: the machine's reports are the current source's,
    /// whose schedule starts at the first step.
    fn end_switch(&mut self) {
        if self.switching {
            // The old source's reports during the switch moved the
            // position; the source switched to starts its own schedule.
            self.machine.source_switched();
        }
        self.switching = false;
        self.switch_failure = None;
    }

    /// The failure a viewer waiting for its answer closes with
    /// ([`ConnectionMachine::failure`]): during a switch, the old source's
    /// does not count, and only when neither source can answer does the
    /// new source's failed attempt.
    fn failure(&self) -> Option<ConnectionError> {
        if !self.switching {
            return self.machine.failure().cloned();
        }
        self.machine
            .failure()
            .and_then(|_| self.switch_failure.clone())
    }

    /// Publishes the snapshot; a state or error change also tells the
    /// subscribers. The last error is the failure waiting sessions close
    /// with when there is one: during a switch, the new source's, not the
    /// old one's the machine holds.
    fn publish(&mut self) {
        let state = self.machine.state();
        let failure = self.failure();
        let error = failure
            .clone()
            .or_else(|| self.machine.last_error().cloned());
        let changed = (state, error.as_ref()) != (self.published.0, self.published.1.as_ref());
        if changed {
            self.snapshot.since = self.shared.clock.wall_now();
            self.snapshot.state = state;
            self.snapshot.last_error.clone_from(&error);
            self.published = (state, error);
        }
        self.snapshot.failure = failure;
        self.shared
            .update_connection(&self.spec.connection_id, self.snapshot.clone(), changed);
    }

    /// The registry dropped the connection: stop the worker and exit.
    async fn stop_all(mut self) {
        self.pending = Pending::Nothing;
        self.linger = None;
        self.crash = None;
        self.window = None;
        if let Some(worker) = self.worker.take() {
            let _status = worker
                .stop(self.shared.shutdown_budget, &self.shared.clock)
                .await;
        }
        // The worker's close reports are not read any more: its signals
        // close here, as at any stop.
        self.signals_ended(SignalCloseCode::SourceStopped, "the source stopped");
        tracing::info!("connection driver stopped");
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::unix::net::UnixDatagram;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};

    use lotse_api::ConnectionId;
    use lotse_core::clock::{Clock, FakeClock, SystemClock};
    use lotse_core::let_assert;
    use tokio_util::task::TaskTracker;

    use super::*;
    use crate::net::demux::Registrations;
    use crate::registry::State;
    use crate::session::SessionEntry;
    use crate::test_support::{environment, private_dir};
    use crate::worker::WorkerManager;

    /// One preloaded stream wants the connection, no viewer.
    const PRELOAD: Demand = Demand {
        preloads: 1,
        viewers: 0,
    };

    fn shared(binary: &str) -> Arc<Shared> {
        shared_with(binary, Arc::new(SystemClock))
    }

    fn shared_with(binary: &str, clock: Arc<dyn Clock>) -> Arc<Shared> {
        let mut state = State::default();
        state.registrations = Some(Arc::new(Registrations::default()));
        Arc::new(Shared {
            clock,
            manager: WorkerManager::new(environment(binary).worker, None),
            tracker: TaskTracker::new(),
            shutdown_budget: Duration::from_millis(200),
            connects: crate::connect::ConnectPermits::new(crate::DEFAULT_CONNECT_CONCURRENCY),
            hosts: vec![],
            tcp_hosts: vec![],
            stun: None,
            turn: None,
            state: Mutex::new(state),
        })
    }

    fn spec(session_id: &str) -> SessionSpec {
        SessionSpec {
            session_id: session_id.into(),
            kind: "webrtc".into(),
            offer: "v=0".into(),
            ice_ufrag: format!("u{session_id}"),
            ice_pass: "p".repeat(24),
            candidates: vec![],
            tcp_candidates: vec![],
            audio: false,
            orientation: 1,
        }
    }

    fn candidate(session_id: &str) -> DriverCommand {
        DriverCommand::Candidate {
            session_id: session_id.into(),
            candidate: String::new(),
        }
    }

    fn fd() -> OwnedFd {
        OwnedFd::from(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
    }

    #[tokio::test]
    async fn a_session_sink_forwards_datagrams_and_hands_ice_tcp_to_the_driver() {
        let (ours, theirs) = lotse_ipc::datagram::datagram_pair().unwrap();
        let ours = UnixDatagram::from(ours);
        ours.set_nonblocking(true).unwrap();
        let (commands, mut rx) = mpsc::channel(1);
        let sink = SessionSink {
            local_ufrag: "abcd".into(),
            worker: WorkerSink {
                datagrams: Arc::new(ours),
            },
            commands,
        };
        assert!(sink.forward(b"frame"));
        let theirs = UnixDatagram::from(theirs);
        let mut buf = [0_u8; 8];
        assert_eq!(theirs.recv(&mut buf).unwrap(), 5);
        let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        assert!(sink.ice_tcp(fd(), peer, vec![1, 2]));
        assert!(!sink.ice_tcp(fd(), peer, vec![3]), "a full queue refuses");
        let_assert!(
            Some(DriverCommand::IceTcp {
                peer: got,
                local_ufrag,
                first_frame,
                ..
            }) = rx.recv().await,
            "an ice-tcp hand-off"
        );
        assert_eq!((got, first_frame), (peer, vec![1, 2]));
        assert_eq!(local_ufrag, "abcd", "the session the sink belongs to");
    }

    #[test]
    fn the_spec_logs_without_its_credentials() {
        let spec = DriverSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url("rtsps://admin:secret@cam/key?token=tok".into()),
            options: r#"{"user_agent":"secret/1"}"#.into(),
            host: "cam".into(),
            port: Some(322),
            backchannel: false,
        };
        let logged = format!("{spec:?}");
        for secret in ["secret", "key", "tok"] {
            assert!(!logged.contains(secret), "{logged}");
        }
        assert!(logged.contains(r#"options: ["user_agent"]"#), "{logged}");
        assert!(logged.contains("port: Some(322)"), "{logged}");
    }

    #[test]
    fn the_spec_logs_its_option_names_without_their_values() {
        let spec = |options: &str| DriverSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url("rtsp://cam/".into()),
            options: options.into(),
            host: "cam".into(),
            port: None,
            backchannel: false,
        };
        let logged = format!(
            "{:?}",
            spec(r#"{"transport":"secret-tcp","b":{"c":"secret"}}"#)
        );
        assert!(!logged.contains("secret"), "{logged}");
        assert!(
            logged.contains(r#"options: ["b", "transport"]"#),
            "{logged}"
        );
        assert!(format!("{:?}", spec("{}")).contains("options: []"));
        // Text that is not an object prints no part of itself.
        let logged = format!("{:?}", spec(r#""secret""#));
        assert!(logged.contains(r#"options: "****""#), "{logged}");
    }

    #[test]
    fn messages_wait_for_a_worker_and_a_close_withdraws_its_session() {
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = Driver::new(
            (
                DriverSpec {
                    connection_id: "c1".into(),
                    target: SourceTarget::Url("fake://h/".into()),
                    options: "{}".into(),
                    host: "h".into(),
                    port: None,
                    backchannel: false,
                },
                0,
            ),
            shared("/bin/sh"),
            demand,
            mpsc::channel(4),
            ConnectionConfig::default(),
        );
        driver.queue(DriverCommand::OpenSession(spec("a")));
        driver.queue(candidate("a"));
        driver.queue(DriverCommand::Renegotiate {
            session_id: "a".into(),
            sdp: "v=0".into(),
        });
        driver.queue(DriverCommand::OpenSession(spec("b")));
        driver.queue(DriverCommand::IceTcp {
            stream: fd(),
            local_ufrag: "u".into(),
            peer: "192.0.2.1:1".parse().unwrap(),
            first_frame: vec![],
        });
        driver.queue(DriverCommand::CloseSession {
            session_id: "a".into(),
            code: "session_closed",
            message: String::new(),
        });
        // Without a worker nobody talks: a release is not kept.
        driver.queue(DriverCommand::ReleaseBackchannel { session_id: None });
        driver.queue(DriverCommand::ReleaseBackchannel {
            session_id: Some("b".into()),
        });
        let left: Vec<Option<&str>> = driver
            .queued
            .iter()
            .map(DriverCommand::session_id)
            .collect();
        assert_eq!(left, [Some("b")]);
        drop(driver);
        drop(demand_tx);
    }

    #[tokio::test]
    async fn only_a_live_session_s_offer_reaches_the_worker() {
        // A worker that records what it is sent.
        let dir = std::env::temp_dir().join(format!("lotse-driver-send-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("received");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nexec cat > {}\n", out.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let shared = shared(script.to_str().unwrap());
        let mut worker = shared.manager.spawn(&[]).unwrap();
        let (commands, _rx) = mpsc::channel(4);
        let (events, _events) = mpsc::channel(1);
        shared.lock().sessions.insert(
            "livesession".into(),
            SessionEntry::new(
                1,
                "front".into(),
                "c1".into(),
                "ulivesession".into(),
                (ConnectionId(1), 1, events),
                Arc::new(SystemClock),
            ),
        );
        let mut gone = spec("gonesession");
        gone.offer = "gone-offer".into();
        Driver::send(
            &mut worker,
            &shared,
            &commands,
            DriverCommand::OpenSession(gone),
        )
        .await;
        let mut live = spec("livesession");
        live.offer = "live-offer".into();
        Driver::send(
            &mut worker,
            &shared,
            &commands,
            DriverCommand::OpenSession(live),
        )
        .await;
        Driver::send(
            &mut worker,
            &shared,
            &commands,
            DriverCommand::IceTcp {
                stream: fd(),
                local_ufrag: "tcp-handoff-ufrag".into(),
                peer: "192.0.2.1:1".parse().unwrap(),
                first_frame: vec![],
            },
        )
        .await;
        let mut received = Vec::new();
        for _ in 0..500 {
            received = std::fs::read(&out).unwrap_or_default();
            if received.windows(17).any(|w| w == b"tcp-handoff-ufrag") {
                break;
            }
            SystemClock.sleep(Duration::from_millis(10)).await;
        }
        assert!(
            received.windows(10).any(|w| w == b"live-offer"),
            "the live offer was sent"
        );
        assert!(
            !received.windows(10).any(|w| w == b"gone-offer"),
            "the closed one was not"
        );
        assert!(
            received.windows(17).any(|w| w == b"tcp-handoff-ufrag"),
            "the ice-tcp hand-off was sent"
        );
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `backchannel/release` reaches the worker as its own message, with
    /// the session it is conditional on.
    #[tokio::test]
    async fn a_release_reaches_the_worker() {
        let dir = private_dir("driver-release");
        let out = dir.join("received");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nexec cat > {}\n", out.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let shared = shared(script.to_str().unwrap());
        let mut worker = shared.manager.spawn(&[]).unwrap();
        let (commands, _rx) = mpsc::channel(1);
        Driver::send(
            &mut worker,
            &shared,
            &commands,
            DriverCommand::ReleaseBackchannel { session_id: None },
        )
        .await;
        // A release for one session takes the session along.
        Driver::send(
            &mut worker,
            &shared,
            &commands,
            DriverCommand::ReleaseBackchannel {
                session_id: Some("s1".into()),
            },
        )
        .await;
        // A re-offer reaches the worker as its own message too.
        Driver::send(
            &mut worker,
            &shared,
            &commands,
            DriverCommand::Renegotiate {
                session_id: "s1".into(),
                sdp: "v=0".into(),
            },
        )
        .await;
        // Each on the wire as its frame: the length, u32 little-endian,
        // then the message.
        let mut expected = Vec::new();
        let messages = [
            lotse_ipc::ToWorker::ReleaseBackchannel { session_id: None },
            lotse_ipc::ToWorker::ReleaseBackchannel {
                session_id: Some("s1".into()),
            },
            lotse_ipc::ToWorker::Renegotiate {
                session_id: "s1".into(),
                sdp: "v=0".into(),
            },
        ];
        for message in &messages {
            let message = lotse_ipc::encode(message).unwrap();
            expected.extend(u32::try_from(message.len()).unwrap().to_le_bytes());
            expected.extend(message);
        }
        // Polled until the file ends with them, at most 500 times.
        let mut received = Vec::new();
        let mut polls = 0;
        while !received.ends_with(&expected) && polls < 500 {
            polls += 1;
            SystemClock.sleep(Duration::from_millis(10)).await;
            received = std::fs::read(&out).unwrap_or_default();
        }
        assert!(received.ends_with(&expected), "{received:?}");
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
    }

    #[tokio::test]
    async fn sends_register_live_offers_only_and_survive_a_dead_worker() {
        let shared = shared("/usr/bin/true");
        let mut worker = shared.manager.spawn(&[]).unwrap();
        while !matches!(worker.next_event().await, WorkerEvent::Exited(_)) {}
        let (commands, _rx) = mpsc::channel(4);
        // A session that closed before its worker got it is not registered.
        Driver::send(
            &mut worker,
            &shared,
            &commands,
            DriverCommand::OpenSession(spec("gone")),
        )
        .await;
        let registrations = shared.lock().registrations.clone().unwrap();
        assert!(registrations.get("ugone").is_none());
        // A live one is, even though this worker is gone and the send fails.
        let (events, _events) = mpsc::channel(1);
        shared.lock().sessions.insert(
            "live".into(),
            SessionEntry::new(
                1,
                "front".into(),
                "c1".into(),
                "ulive".into(),
                (ConnectionId(1), 1, events),
                Arc::new(SystemClock),
            ),
        );
        Driver::send(
            &mut worker,
            &shared,
            &commands,
            DriverCommand::OpenSession(spec("live")),
        )
        .await;
        assert!(registrations.get("ulive").is_some());
        for command in [
            candidate("live"),
            DriverCommand::Orientation {
                session_id: "live".into(),
                orientation: 6,
            },
            DriverCommand::CloseSession {
                session_id: "live".into(),
                code: "session_closed",
                message: String::new(),
            },
            DriverCommand::IceTcp {
                stream: fd(),
                local_ufrag: "ulive".into(),
                peer: "192.0.2.1:1".parse().unwrap(),
                first_frame: vec![],
            },
            DriverCommand::ReleaseBackchannel {
                session_id: Some("live".into()),
            },
        ] {
            assert_eq!(
                command.session_id().is_none(),
                matches!(
                    command,
                    DriverCommand::IceTcp { .. } | DriverCommand::ReleaseBackchannel { .. }
                )
            );
            Driver::send(&mut worker, &shared, &commands, command).await;
        }
    }

    /// The worker's talker reports reach the registry, and its exit frees
    /// the backchannel: the talker's session is gone with it.
    #[tokio::test]
    async fn talker_reports_reach_the_registry_and_a_worker_exit_frees_the_backchannel() {
        use std::os::unix::process::ExitStatusExt as _;

        use lotse_api_types::stream::TalkerReason;

        let shared = shared("/bin/sh");
        let (demand_tx, demand) = watch::channel(Demand::default());
        let (commands, _commands) = mpsc::channel(1);
        let (events, _events) = mpsc::channel(1);
        {
            let mut state = shared.lock();
            state.connections.insert(
                "c1".into(),
                crate::registry::ConnectionEntry {
                    port: None,
                    backchannel: false,
                    prerecord_ms: 0,
                    key: crate::registry::ConnectionKey {
                        target: crate::registry::SourceTarget::Url(
                            lotse_core::source_url::SourceUrl::parse("fake://127.0.0.1/").unwrap(),
                        ),
                        options: serde_json::Value::Null,
                    },
                    demand: demand_tx,
                    snapshot: ConnectionSnapshot::idle(UNIX_EPOCH),
                    switches: 0,
                    streams: ["front".to_owned()].into(),
                    commands,
                    talker: crate::registry::Talker::default(),
                },
            );
            state.streams.insert(
                "front".into(),
                crate::registry::StreamEntry {
                    sources: vec![crate::registry::StreamSource {
                        spec: spec_of("fake://127.0.0.1/"),
                        target: crate::registry::SourceTarget::Url(
                            lotse_core::source_url::SourceUrl::parse("fake://127.0.0.1/").unwrap(),
                        ),
                        options: serde_json::Map::new(),
                        reported: serde_json::from_value(
                            serde_json::json!({ "protocol": "fake", "url": "fake://127.0.0.1/" }),
                        )
                        .unwrap(),
                        connection: "c1".into(),
                    }],
                    preload: false,
                    audio: lotse_api_types::stream::AudioMode::Auto,
                    orientation: lotse_api_types::stream::Orientation::NoTransform,
                    created: UNIX_EPOCH,
                    prerecord_ms: 0,
                    recordings: crate::recording::RecordingCounters::default(),
                },
            );
            state.sessions.insert(
                "s1".into(),
                SessionEntry::new(
                    1,
                    "front".into(),
                    "c1".into(),
                    "us1".into(),
                    (ConnectionId(1), 1, events),
                    Arc::new(SystemClock),
                ),
            );
        }
        let mut driver = driver_on(&shared, demand);
        let talker = |shared: &Shared| shared.lock().connections["c1"].talker.session.clone();
        driver.on_worker_event(WorkerEvent::Talker {
            session_id: "s1".into(),
            reason: TalkerReason::Claimed,
            at: UNIX_EPOCH,
        });
        assert_eq!(talker(&shared).as_deref(), Some("s1"));
        driver.on_worker_event(WorkerEvent::Exited(ExitStatus::from_raw(0)));
        drop(driver);
        assert_eq!(talker(&shared), None);
        assert!(shared.lock().connections["c1"].talker.since.is_some());
    }

    /// A worker's exit closes the sessions of its own connection and no
    /// other: another camera's session stays open.
    #[tokio::test]
    async fn a_worker_exit_closes_only_its_own_connection_s_sessions() {
        use std::os::unix::process::ExitStatusExt as _;

        let shared = shared("/bin/sh");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let (events, _events) = mpsc::channel(2);
        for (id, connection) in [("s1", "c1"), ("s2", "c2")] {
            shared.lock().sessions.insert(
                id.into(),
                SessionEntry::new(
                    1,
                    "front".into(),
                    connection.into(),
                    format!("u{id}"),
                    (ConnectionId(1), 1, events.clone()),
                    Arc::new(SystemClock),
                ),
            );
        }
        let mut driver = driver_on(&shared, demand);
        driver.on_worker_event(WorkerEvent::Exited(ExitStatus::from_raw(0)));
        drop(driver);
        assert!(!shared.lock().sessions.contains_key("s1"));
        assert!(shared.lock().sessions.contains_key("s2"));
    }

    /// The driver's next wake if one is ready now, `None` otherwise.
    async fn ready_wake(driver: &mut Driver) -> Option<Wake> {
        tokio::select! {
            biased;
            wake = driver.wait() => Some(wake),
            () = std::future::ready(()) => None,
        }
    }

    /// The driver's next wake; ten seconds without one fail the test, so
    /// a driver that never wakes fails it rather than hanging it.
    async fn next_wake(driver: &mut Driver) -> Wake {
        tokio::select! {
            wake = driver.wait() => wake,
            () = SystemClock.sleep(Duration::from_secs(10)) => panic!("no wake within 10 s"),
        }
    }

    /// Waits for the next wake and acts on it.
    async fn step(driver: &mut Driver) {
        let wake = next_wake(driver).await;
        driver.handle(wake).await;
    }

    /// A driver of `fake://127.0.0.1/` on `shared`, following `demand`.
    fn driver_on(shared: &Arc<Shared>, demand: watch::Receiver<Demand>) -> Driver {
        Driver::new(
            (
                DriverSpec {
                    connection_id: "c1".into(),
                    target: SourceTarget::Url("fake://127.0.0.1/".into()),
                    options: "{}".into(),
                    host: "127.0.0.1".into(),
                    port: None,
                    backchannel: false,
                },
                0,
            ),
            Arc::clone(shared),
            demand,
            mpsc::channel(4),
            ConnectionConfig::default(),
        )
    }

    /// A viewer that re-offers right after a failed attempt is no new
    /// camera login: inside the backoff window the connection publishes
    /// the failure an offer closes with, and demand starts no lookup and
    /// no worker; once the window ends the next worker starts, its
    /// reconnect schedule continuing where the last one's left off.
    #[tokio::test]
    async fn demand_inside_the_backoff_window_starts_no_worker_and_the_next_continues_the_schedule()
    {
        let dir = private_dir("driver-window");
        // Each worker records into a file of its own: a stopped one may
        // still write while the next runs.
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nn=$(ls {0} | grep -c '^received-')\nexec cat > {0}/received-$n\n",
                dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(script.to_str().unwrap(), clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let run = |attempts, immediate_used| {
            lotse_ipc::ToWorker::RunSource(SourceSpec {
                connection_id: "c1".into(),
                target: SourceTarget::Url("fake://127.0.0.1/".into()),
                options: "{}".into(),
                peer_host: "127.0.0.1".into(),
                peer_addrs: vec!["127.0.0.1:0".parse().unwrap()],
                backoff: lotse_ipc::BackoffPosition {
                    attempts,
                    immediate_used,
                },
                prerecord_ms: 0,
            })
        };
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        step(&mut driver).await;
        assert!(driver.worker.is_some());
        recorded(&dir.join("received-0"), &run(0, false)).await;
        // RFC 2326 §7.1.1: a 401 is a credential failure.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Backoff {
            error: SourceError::AuthFailed("401".into()),
            retry_in: Duration::from_secs(5),
            position: BackoffPosition {
                attempts: 1,
                immediate_used: true,
            },
        }));
        // The waiting viewer closed with it; its demand goes.
        demand_tx.send_replace(Demand::default());
        step(&mut driver).await;
        driver.publish();
        assert_eq!(driver.machine.state(), ConnectionState::Idle);
        assert!(driver.worker.is_none());
        assert_eq!(
            driver.snapshot.failure.as_ref().map(ConnectionError::code),
            Some("source_auth_failed"),
            "an offer now closes at once"
        );
        // Demand inside the window: no lookup, no worker.
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert!(matches!(driver.pending, Pending::Nothing));
        assert!(driver.worker.is_none());
        assert!(
            ready_wake(&mut driver).await.is_none(),
            "nothing before the end"
        );
        // The window ends: the demand connects, and the failure is over.
        clock.advance(Duration::from_secs(5));
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::BackoffWindowExpired));
        driver.handle(wake).await;
        driver.publish();
        assert_eq!(driver.snapshot.failure, None);
        assert!(matches!(driver.pending, Pending::Resolving(_)));
        step(&mut driver).await;
        recorded(&dir.join("received-1"), &run(1, true)).await;
        assert!(driver.worker.is_some());
        drop((driver, demand_tx));
        shared.tracker.close();
        while !shared.tracker.is_empty() {
            clock.advance(shared.shutdown_budget);
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A source switched to inside the backoff window has failed no
    /// attempt: its first worker's schedule starts at the first step. The
    /// window still holds: the camera sees no login before it ends.
    #[tokio::test]
    async fn a_switch_inside_the_backoff_window_starts_the_new_source_s_schedule_over() {
        let dir = private_dir("driver-window-switch");
        // Each worker records into a file of its own: a stopped one may
        // still write while the next runs.
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nn=$(ls {0} | grep -c '^received-')\nexec cat > {0}/received-$n\n",
                dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(script.to_str().unwrap(), clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        step(&mut driver).await;
        let first = lotse_ipc::ToWorker::RunSource(SourceSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url("fake://127.0.0.1/".into()),
            options: "{}".into(),
            peer_host: "127.0.0.1".into(),
            peer_addrs: vec!["127.0.0.1:0".parse().unwrap()],
            backoff: lotse_ipc::BackoffPosition::default(),
            prerecord_ms: 0,
        });
        recorded(&dir.join("received-0"), &first).await;
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Backoff {
            error: SourceError::AuthFailed("401".into()),
            retry_in: Duration::from_secs(5),
            position: BackoffPosition {
                attempts: 3,
                immediate_used: false,
            },
        }));
        demand_tx.send_replace(Demand::default());
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Idle);
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(DriverSpec {
                connection_id: "c1".into(),
                target: SourceTarget::Url("fake://127.0.0.1:2/".into()),
                options: "{}".into(),
                host: "127.0.0.1".into(),
                port: Some(2),
                backchannel: false,
            })))
            .await;
        assert_eq!(driver.machine.backoff_position().attempts, 0);
        // The window holds: demand starts no lookup before its end.
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert!(matches!(driver.pending, Pending::Nothing));
        clock.advance(Duration::from_secs(5));
        step(&mut driver).await;
        assert!(matches!(driver.pending, Pending::Resolving(_)));
        step(&mut driver).await;
        let run = lotse_ipc::ToWorker::RunSource(SourceSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url("fake://127.0.0.1:2/".into()),
            options: "{}".into(),
            peer_host: "127.0.0.1".into(),
            peer_addrs: vec!["127.0.0.1:2".parse().unwrap()],
            backoff: lotse_ipc::BackoffPosition::default(),
            prerecord_ms: 0,
        });
        recorded(&dir.join("received-1"), &run).await;
        assert!(driver.worker.is_some());
        drop((driver, demand_tx));
        shared.tracker.close();
        while !shared.tracker.is_empty() {
            clock.advance(shared.shutdown_budget);
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The accepted cost of not keeping a standby's retry state: a worker
    /// stopped while its standby waits out a delay leaves no window, so the
    /// next demand logs in to the source switched to once, at once, its
    /// schedule at the first step even though the old source's reports
    /// moved the position during the switch. That login's failure opens a
    /// window, and a re-offer inside it logs in to nothing.
    #[tokio::test]
    async fn a_stop_mid_switch_costs_at_most_one_login_to_the_source_switched_to() {
        let dir = private_dir("driver-switch-cost");
        // Each worker records into a file of its own.
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nn=$(ls {0} | grep -c '^received-')\nexec cat > {0}/received-$n\n",
                dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(script.to_str().unwrap(), clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        step(&mut driver).await;
        let first = driver.spec.source_spec(
            vec!["127.0.0.1:0".parse().unwrap()],
            BackoffPosition::default(),
            0,
        );
        recorded(
            &dir.join("received-0"),
            &lotse_ipc::ToWorker::RunSource(first),
        )
        .await;
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Live));
        driver.on_switch_source(spec_of("fake://127.0.0.1:2/"));
        driver.pending = Pending::Nothing;
        assert_eq!(
            driver.machine.backoff_position(),
            BackoffPosition::default()
        );
        // The old source drops and is back at once, its immediate attempt
        // used; the standby fails, and its delay is not kept.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Reconnecting(
            SourceError::Timeout("stall".into()),
        )));
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Live));
        assert!(driver.machine.backoff_position().immediate_used);
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Backoff {
            error: SourceError::Unreachable("refused".into()),
            retry_in: Duration::from_secs(60),
            position: BackoffPosition::default(),
        }));
        demand_tx.send_replace(Demand::default());
        step(&mut driver).await;
        clock.advance(lotse_core::connection::DEFAULT_LINGER);
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Idle);
        assert!(driver.window.is_none(), "no window of the standby's");
        // The next demand logs in to the source switched to, at once, its
        // schedule at the first step.
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert!(matches!(driver.pending, Pending::Resolving(_)));
        step(&mut driver).await;
        let switched = driver.spec.source_spec(
            vec!["127.0.0.1:1".parse().unwrap()],
            BackoffPosition::default(),
            0,
        );
        assert_eq!(
            switched.target,
            SourceTarget::Url("fake://127.0.0.1:2/".into())
        );
        recorded(
            &dir.join("received-1"),
            &lotse_ipc::ToWorker::RunSource(switched),
        )
        .await;
        // RFC 2326 §7.1.1: a 401 is a credential failure. Its window holds
        // the next re-offer back.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Backoff {
            error: SourceError::AuthFailed("401".into()),
            retry_in: Duration::from_secs(5),
            position: BackoffPosition {
                attempts: 1,
                immediate_used: false,
            },
        }));
        demand_tx.send_replace(Demand::default());
        step(&mut driver).await;
        driver.publish();
        assert_eq!(
            driver.snapshot.failure.as_ref().map(ConnectionError::code),
            Some("source_auth_failed")
        );
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert!(
            matches!(driver.pending, Pending::Nothing),
            "no second login"
        );
        assert!(driver.worker.is_none());
        drop((driver, demand_tx));
        shared.tracker.close();
        while !shared.tracker.is_empty() {
            clock.advance(shared.shutdown_budget);
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The source's stable streaming starts the connection's schedule
    /// over; the standby's is the standby's own and moves nothing.
    #[tokio::test]
    async fn only_the_source_s_stable_streaming_starts_the_schedule_over() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        driver.feed(Input::Demand(1));
        let at = BackoffPosition {
            attempts: 3,
            immediate_used: true,
        };
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Backoff {
            error: SourceError::Unreachable("refused".into()),
            retry_in: Duration::from_secs(1),
            position: at,
        }));
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Stable));
        assert_eq!(driver.machine.backoff_position(), at);
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Live));
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Stable));
        assert_eq!(
            driver.machine.backoff_position(),
            BackoffPosition::default()
        );
    }

    #[tokio::test]
    async fn every_announced_attempt_holds_a_connect_permit_until_it_ends() {
        let dir = private_dir("driver-connect");
        let script = dir.join("worker.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(script.to_str().unwrap(), clock.clone());
        let in_flight = || shared.connects.in_flight();
        let (demand_tx, demand) = watch::channel(Demand::default());
        let driver = &mut driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(driver).await;
        step(driver).await;
        assert!(driver.worker.is_some());
        // The worker announces its attempt: a permit, then the grant.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        assert_eq!(in_flight(), 1);
        let wake = next_wake(driver).await;
        assert!(matches!(wake, Wake::Connect(SlotWake::Grant)));
        driver.handle(wake).await;
        assert!(ready_wake(driver).await.is_none(), "one grant");
        // Live gives it back; a reconnect takes one again.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Live));
        assert_eq!(in_flight(), 0);
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Reconnecting(
            SourceError::Timeout("stall".into()),
        )));
        assert_eq!(in_flight(), 1);
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Backoff {
            error: SourceError::Unreachable("refused".into()),
            retry_in: Duration::from_secs(1),
            position: BackoffPosition::default(),
        }));
        assert_eq!(in_flight(), 0, "a failed attempt gives it back");
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        assert_eq!(in_flight(), 1);
        driver.on_worker_event(WorkerEvent::SourceStopped);
        assert_eq!(in_flight(), 0, "a stopped source gives it back");
        // A worker that crashes mid-attempt gives its permit back.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        assert_eq!(in_flight(), 1);
        driver.on_worker_event(WorkerEvent::Exited(ExitStatus::from_raw(9)));
        assert_eq!(in_flight(), 0, "a crashed worker gives it back");
        // A stopped one too: the crash backoff spawns a new worker, which
        // announces, and the demand goes.
        clock.advance(Duration::from_secs(1));
        step(driver).await;
        step(driver).await;
        assert!(driver.worker.is_some(), "restarted");
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        driver.on_worker_event(WorkerEvent::ProbeConnecting(1));
        assert_eq!(in_flight(), 2);
        demand_tx.send_replace(Demand::default());
        step(driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Idle);
        assert_eq!(in_flight(), 0, "a stopped worker gives both back");
        drop(demand_tx);
        shared.tracker.close();
        while !shared.tracker.is_empty() {
            clock.advance(shared.shutdown_budget);
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The messages a recording worker wrote to `out`, once `want` is
    /// among them; five seconds without it fail the test.
    async fn recorded(
        out: &std::path::Path,
        want: &lotse_ipc::ToWorker,
    ) -> Vec<lotse_ipc::ToWorker> {
        recorded_where(out, |message| message == want).await
    }

    /// The messages a recording worker wrote to `out`, once one of them
    /// is `wanted`; five seconds without one fail the test.
    async fn recorded_where(
        out: &std::path::Path,
        wanted: impl Fn(&lotse_ipc::ToWorker) -> bool,
    ) -> Vec<lotse_ipc::ToWorker> {
        let mut attempt = 0_u32;
        loop {
            let bytes = std::fs::read(out).unwrap_or_default();
            let mut messages = Vec::new();
            let mut rest = bytes.as_slice();
            // A frame still being written ends the parse until the next look.
            while let Some((prefix, tail)) = rest.split_at_checked(4)
                && let Ok(len) = usize::try_from(u32::from_le_bytes(prefix.try_into().unwrap()))
                && let Some((frame, tail)) = tail.split_at_checked(len)
            {
                messages.push(lotse_ipc::decode::<lotse_ipc::ToWorker>(frame).unwrap());
                rest = tail;
            }
            if messages.iter().any(&wanted) {
                return messages;
            }
            assert!(attempt < 500, "never received it: {messages:?}");
            attempt += 1;
            SystemClock.sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn the_grant_reaches_the_worker_once_its_permit_is_held() {
        let dir = private_dir("driver-grant");
        let out = dir.join("received");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nexec cat > {}\n", out.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let shared = shared(script.to_str().unwrap());
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        driver.worker = Some(shared.manager.spawn(&[]).unwrap());
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        // Bounded: a report the driver drops never wakes it.
        let wake = tokio::select! {
            wake = driver.wait() => Some(wake),
            () = SystemClock.sleep(Duration::from_secs(10)) => None,
        };
        assert!(matches!(wake, Some(Wake::Connect(SlotWake::Grant))));
        driver.handle(wake.unwrap()).await;
        let messages = recorded(&out, &lotse_ipc::ToWorker::ConnectGranted).await;
        assert_eq!(messages, [lotse_ipc::ToWorker::ConnectGranted]);
        let worker = driver.worker.take().unwrap();
        drop(driver);
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The slot's wake if one is ready within a few scheduler turns.
    async fn slot_ready(slot: &mut ConnectSlot) -> Option<SlotWake> {
        for _ in 0..10 {
            tokio::select! {
                biased;
                wake = slot.wait() => return Some(wake),
                () = tokio::task::yield_now() => {}
            }
        }
        None
    }

    /// Work list W3: once a viewer is on the connection, its attempt goes
    /// ahead of the preloads' queued at the connect gate; before, it
    /// queues behind them like any preload's.
    #[tokio::test]
    async fn a_viewer_on_the_connection_puts_its_attempt_ahead_of_queued_preload_retries() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        // Every permit is held, and two preloads' retries queue.
        let mut others: Vec<ConnectSlot> = (0..6)
            .map(|_| ConnectSlot::new(clock.clone(), CONNECT_LEASE))
            .collect();
        for (n, other) in others.iter_mut().enumerate() {
            other.request(&shared.connects, "reconnecting");
            let expected = (n < 4).then_some(SlotWake::Grant);
            assert_eq!(slot_ready(other).await, expected);
        }
        assert_eq!(shared.connects.in_flight(), 4);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        driver.handle(Wake::Demand(Some(PRELOAD))).await;
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        assert_eq!(slot_ready(&mut driver.connect).await, None);
        // Only a preload wants the connection: it waits its turn.
        others[0].release("live");
        assert_eq!(slot_ready(&mut others[4]).await, Some(SlotWake::Grant));
        assert_eq!(slot_ready(&mut driver.connect).await, None);
        // A viewer comes: the attempt goes before the other preload's.
        let viewer = Demand {
            preloads: 1,
            viewers: 1,
        };
        driver.handle(Wake::Demand(Some(viewer))).await;
        for slot in [
            &driver.connect,
            &driver.switch_connect,
            &driver.probe_connect,
        ] {
            assert!(format!("{slot:?}").contains("wanted: true"));
        }
        others[1].release("live");
        assert_eq!(slot_ready(&mut others[5]).await, None);
        assert_eq!(slot_ready(&mut driver.connect).await, Some(SlotWake::Grant));
        assert_eq!(shared.connects.in_flight(), 4);
        drop(driver);
        assert_eq!(slot_ready(&mut others[5]).await, Some(SlotWake::Grant));
    }

    /// A probe of the camera's backchannel takes a connect permit of its
    /// own beside the source's attempt, like any connection attempt: its
    /// grant reaches the worker once the permit is held, and its end, the
    /// worker's exit or its stop gives it back.
    #[tokio::test]
    async fn a_probe_holds_a_connect_permit_of_its_own_until_it_ends() {
        let dir = private_dir("driver-probe");
        let out = dir.join("received");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nexec cat > {}\n", out.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let shared = shared(script.to_str().unwrap());
        let in_flight = || shared.connects.in_flight();
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        driver.worker = Some(shared.manager.spawn(&[]).unwrap());
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::Connect(SlotWake::Grant)));
        driver.handle(wake).await;
        driver.on_worker_event(WorkerEvent::ProbeConnecting(1));
        assert_eq!(in_flight(), 2, "the attempt's and the probe's");
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::ProbeConnect(SlotWake::Grant)));
        driver.handle(wake).await;
        // The grant names the probe it is for.
        let granted = lotse_ipc::ToWorker::ProbeConnectGranted { probe: 1 };
        let messages = recorded(&out, &granted).await;
        assert_eq!(
            messages,
            [lotse_ipc::ToWorker::ConnectGranted, granted.clone()]
        );
        // The end of a probe the permit is not for releases nothing.
        driver.on_worker_event(WorkerEvent::ProbeEnded(2));
        assert_eq!(in_flight(), 2, "a stale end keeps the probe's permit");
        driver.on_worker_event(WorkerEvent::ProbeEnded(1));
        assert_eq!(in_flight(), 1, "the probe gave its back");
        // A lease that runs out changes nothing more.
        driver
            .handle(Wake::ProbeConnect(SlotWake::LeaseExpired))
            .await;
        driver.on_worker_event(WorkerEvent::ProbeConnecting(2));
        assert_eq!(in_flight(), 2);
        let worker = driver.worker.take().unwrap();
        // Without a worker the grant goes nowhere.
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::ProbeConnect(SlotWake::Grant)));
        driver.handle(wake).await;
        driver.on_worker_event(WorkerEvent::Exited(ExitStatus::from_raw(0)));
        assert_eq!(in_flight(), 0, "the worker's exit gives both back");
        drop(driver);
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_source_switch_reaches_a_running_worker_once_its_host_resolves() {
        let dir = private_dir("driver-switch");
        let out = dir.join("received");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nexec cat > {}\n", out.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let shared = shared(script.to_str().unwrap());
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let switch = |url: &str, host: &str| DriverSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url(url.into()),
            options: "{}".into(),
            host: host.into(),
            port: Some(1),
            backchannel: false,
        };
        // Without a worker the spec is taken for the next one, nothing more.
        let a = switch("fake://127.0.0.1:1/a", "127.0.0.1");
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(a.clone())))
            .await;
        assert_eq!(driver.spec.target, a.target);
        assert!(ready_wake(&mut driver).await.is_none(), "nothing pending");
        // While the old host resolves, the lookup starts over for the new.
        driver.start_resolving();
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(switch(
                "fake://127.0.0.1:1/b",
                "127.0.0.1",
            ))))
            .await;
        assert!(matches!(driver.pending, Pending::Resolving(_)));
        assert!(matches!(
            next_wake(&mut driver).await,
            Wake::Resolved(Ok(_))
        ));
        driver.pending = Pending::Nothing;
        // With a worker: the new host resolves, then the worker is told.
        driver.worker = Some(shared.manager.spawn(&[]).unwrap());
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(switch(
                "fake://127.0.0.1:1/c",
                "127.0.0.1",
            ))))
            .await;
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::SwitchResolved(Ok(_))), "resolved");
        driver.handle(wake).await;
        let want = lotse_ipc::ToWorker::SwitchSource(SourceSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url("fake://127.0.0.1:1/c".into()),
            options: "{}".into(),
            peer_host: "127.0.0.1".into(),
            peer_addrs: vec!["127.0.0.1:1".parse().unwrap()],
            backoff: lotse_ipc::BackoffPosition::default(),
            prerecord_ms: 0,
        });
        let messages = recorded(&out, &want).await;
        assert_eq!(messages, [want]);
        // A host that does not resolve is retried, and shows as the
        // stream's last error meanwhile; the switch resolves again after
        // the wait.
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(switch(
                "fake://nowhere.invalid:1/",
                "nowhere.invalid",
            ))))
            .await;
        let wake = next_wake(&mut driver).await;
        assert!(
            matches!(wake, Wake::SwitchResolved(Err(_))),
            "{}",
            driver.spec.host
        );
        driver.handle(wake).await;
        assert_eq!(
            driver
                .snapshot
                .last_error
                .as_ref()
                .map(ConnectionError::code),
            Some("source_unreachable")
        );
        assert!(matches!(driver.pending, Pending::RetrySwitch(_)));
        driver.handle(Wake::RetrySwitchResolve).await;
        assert!(matches!(driver.pending, Pending::ResolvingSwitch(_)));
        // The retry without a worker resolves nothing.
        driver.pending = Pending::Nothing;
        let worker = driver.worker.take().unwrap();
        driver.handle(Wake::RetrySwitchResolve).await;
        assert!(matches!(driver.pending, Pending::Nothing));
        // A lookup result that arrives after the worker went is nothing
        // to send.
        driver
            .handle(Wake::SwitchResolved(Ok(vec![
                "127.0.0.1:1".parse().unwrap(),
            ])))
            .await;
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        drop(driver);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// ONVIF Streaming Specification §5.3.1: a stream's opt-in or opt-out
    /// only tells the running worker, whose sources turn their probe on
    /// or off; nothing restarts, and a later connect runs the spec as it
    /// is then.
    #[tokio::test]
    async fn onvif_5_3_1_an_opt_in_or_out_tells_the_running_worker_and_restarts_nothing() {
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let dir = private_dir("driver-backchannel");
        let out = dir.join("received");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nexec cat > {}\n", out.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let shared = shared(script.to_str().unwrap());
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let spec = |options: &str, backchannel: bool| DriverSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url("fake://127.0.0.1:1/".into()),
            options: options.into(),
            host: "127.0.0.1".into(),
            port: Some(1),
            backchannel,
        };
        let source = |options: &str| SourceSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url("fake://127.0.0.1:1/".into()),
            options: options.into(),
            peer_host: "127.0.0.1".into(),
            peer_addrs: vec!["127.0.0.1:1".parse().unwrap()],
            backoff: lotse_ipc::BackoffPosition::default(),
            prerecord_ms: 0,
        };
        let backchannel = |options: &str, asks: bool| {
            Wake::Command(DriverCommand::Backchannel(spec(options, asks)))
        };
        // Without a worker the next one starts with the spec, nothing more.
        driver.handle(backchannel(r#"{"talk":true}"#, true)).await;
        assert!(driver.spec.backchannel);
        assert!(ready_wake(&mut driver).await.is_none(), "nothing pending");
        assert_eq!(captured.lines("no worker runs").len(), 1);
        driver
            .spawn_worker(vec!["127.0.0.1:1".parse().unwrap()])
            .await;
        let run = lotse_ipc::ToWorker::RunSource(source(r#"{"talk":true}"#));
        recorded(&out, &run).await;
        // Out and in again: the worker is told each time, and nothing
        // reconnects.
        driver.handle(backchannel("{}", false)).await;
        assert!(!driver.spec.backchannel, "the next connect's");
        assert!(ready_wake(&mut driver).await.is_none(), "no reconnect");
        let off = lotse_ipc::ToWorker::Backchannel { asks: false };
        recorded(&out, &off).await;
        driver.handle(backchannel(r#"{"talk":true}"#, true)).await;
        assert!(ready_wake(&mut driver).await.is_none(), "no reconnect");
        let on = lotse_ipc::ToWorker::Backchannel { asks: true };
        recorded(&out, &on).await;
        let told = captured.lines("backchannel probe turned on or off in the running worker");
        assert_eq!(told.len(), 2, "{told:?}");
        assert!(told[0].contains("backchannel=false"), "{told:?}");
        assert!(told[1].contains("backchannel=true"), "{told:?}");
        // The next connect, a source switch, runs the spec as it is then.
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(spec(
                r#"{"talk":true}"#,
                true,
            ))))
            .await;
        step(&mut driver).await;
        let switch = lotse_ipc::ToWorker::SwitchSource(source(r#"{"talk":true}"#));
        let messages = recorded(&out, &switch).await;
        assert!(
            messages.ends_with(&[run, off, on, switch]),
            "no restart: {messages:?}"
        );
        let worker = driver.worker.take().unwrap();
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        drop(driver);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The registry dropping the connection stops its driver: the lookup
    /// and the timers go, the worker is stopped within the shutdown
    /// budget, and the driver says so.
    #[tokio::test]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "`stop_all` consumes the driver, a move the lint does not see"
    )]
    async fn a_driver_that_stops_stops_its_worker_and_says_so() {
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        driver.worker = Some(dead_worker(&shared).await);
        driver.start_resolving();
        driver.stop_all().await;
        assert_eq!(captured.lines("connection driver stopped").len(), 1);
    }

    /// A worker's recording report names no recording the supervisor holds: it is
    /// dropped with a debug line whose id is plain and capped, and the
    /// driver goes on.
    #[tokio::test]
    async fn a_report_for_a_recording_the_supervisor_does_not_hold_is_dropped() {
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        driver.on_worker_event(WorkerEvent::Recording {
            recording_id: format!("k\n{}", "x".repeat(100)),
            event: RecordingReport::Closed {
                reason: "internal_error".into(),
                bytes: 0,
                duration_ms: 0,
                gaps: 0,
            },
        });
        assert!(driver.silence.is_some(), "a report is a sign of life");
        drop(driver);
        let lines = captured.lines("report for a recording the supervisor does not hold");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("recording.id=k x"), "{lines:?}");
        let cap = crate::worker_text::MAX_NAME_BYTES;
        assert!(!lines[0].contains(&"x".repeat(cap)), "{lines:?}");
    }

    #[tokio::test]
    async fn a_standby_s_attempts_hold_their_own_connect_permit() {
        let shared = shared("/usr/bin/true");
        let in_flight = || shared.connects.in_flight();
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        // The source's attempt and the standby's each hold one.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Connecting));
        assert_eq!(in_flight(), 2);
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::Connect(SlotWake::Grant)));
        driver.handle(wake).await;
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::SwitchConnect(SlotWake::Grant)));
        driver.handle(wake).await;
        driver
            .handle(Wake::SwitchConnect(SlotWake::LeaseExpired))
            .await;
        // The standby going live gives its permit back; a failed attempt
        // too, and is the stream's last error while the old source streams.
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Live));
        assert_eq!(in_flight(), 1);
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Reconnecting(
            SourceError::Timeout("stall".into()),
        )));
        assert_eq!(in_flight(), 2);
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Backoff {
            error: SourceError::AuthFailed("401".into()),
            retry_in: Duration::from_secs(1),
            position: BackoffPosition::default(),
        }));
        assert_eq!(in_flight(), 1);
        assert_eq!(
            driver
                .snapshot
                .last_error
                .as_ref()
                .map(ConnectionError::code),
            Some("source_auth_failed")
        );
        // The switch clears it; a stopped standby and a worker exit give
        // the permit back.
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Connecting));
        driver.on_worker_event(WorkerEvent::Switched);
        assert_eq!(in_flight(), 1);
        assert!(driver.snapshot.last_error.is_none());
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Connecting));
        driver.on_worker_event(WorkerEvent::StandbyStopped);
        assert_eq!(in_flight(), 1);
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Connecting));
        assert_eq!(in_flight(), 2);
        driver.on_worker_event(WorkerEvent::Exited(ExitStatus::from_raw(0)));
        assert_eq!(in_flight(), 0);
        drop(driver);
    }

    #[tokio::test]
    async fn a_grant_to_a_worker_that_is_gone_waits_for_its_exit() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let mut worker = shared.manager.spawn(&[]).unwrap();
        while !matches!(worker.next_event().await, WorkerEvent::Exited(_)) {}
        driver.worker = Some(worker);
        driver.handle(Wake::Connect(SlotWake::Grant)).await;
        driver.handle(Wake::Connect(SlotWake::LeaseExpired)).await;
        assert!(driver.worker.is_some(), "the exit, not the send, ends it");
        drop(driver);
    }

    /// The next wake, acted on, by name.
    async fn bounded_step(driver: &mut Driver) -> String {
        let wake = next_wake(driver).await;
        let name = match &wake {
            Wake::Worker(WorkerEvent::Exited(status)) => format!("exited:{:?}", status.signal()),
            Wake::Worker(event) => format!("{event:?}"),
            Wake::WorkerSilent => "silent".to_owned(),
            other => format!("resolved:{}", matches!(other, Wake::Resolved(Ok(_)))),
        };
        driver.handle(wake).await;
        name
    }

    /// Steps a killed worker to its exit, by name. Its channel's end may
    /// come first or not at all: the relay task races the reaper (the exit
    /// came first on Linux 7.0, the channel's end on macOS, 2026-10-09).
    async fn step_to_exit(driver: &mut Driver) -> String {
        let mut step = String::from("ChannelClosed");
        while step == "ChannelClosed" {
            step = bounded_step(driver).await;
        }
        step
    }

    /// A worker script at `dir/worker.sh` running `body`.
    fn worker_script(dir: &std::path::Path, body: &str) -> String {
        let script = dir.join("worker.sh");
        std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        script.to_str().unwrap().to_owned()
    }

    /// Drops the driver's demand and waits out its stopped workers.
    async fn wind_down(shared: &Arc<Shared>, clock: &FakeClock, dir: std::path::PathBuf) {
        shared.tracker.close();
        while !shared.tracker.is_empty() {
            clock.advance(shared.shutdown_budget);
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_worker_whose_channel_closes_is_killed_and_restarted() {
        // The worker closes its end of the channel and keeps running: before,
        // the supervisor stopped listening and left it there.
        let dir = private_dir("driver-channel-closed");
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(
            &worker_script(&dir, "exec 0<&-\nexec sleep 30"),
            clock.clone(),
        );
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut owned = driver_on(&shared, demand);
        let driver = &mut owned;
        demand_tx.send_replace(PRELOAD);
        step(driver).await;
        assert_eq!(bounded_step(driver).await, "resolved:true");
        assert!(driver.silence.is_some(), "a spawned worker is timed");
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        assert_eq!(bounded_step(driver).await, "ChannelClosed");
        assert!(driver.silence.is_none(), "its exit is expected now");
        assert_eq!(bounded_step(driver).await, "exited:Some(9)");
        assert_eq!(driver.machine.crashes(), 1);
        assert_eq!(driver.machine.state(), ConnectionState::Restarting);
        assert!(driver.silence.is_none());
        assert_eq!(captured.lines("worker killed").len(), 1);
        // A channel that fails is the same.
        clock.advance(Duration::from_secs(1));
        step(driver).await;
        assert_eq!(bounded_step(driver).await, "resolved:true");
        driver.on_worker_event(WorkerEvent::ChannelError("malformed".into()));
        assert!(driver.silence.is_none());
        assert_eq!(step_to_exit(driver).await, "exited:Some(9)");
        assert_eq!(driver.machine.crashes(), 2);
        assert_eq!(captured.lines("channel failed; killing it").len(), 1);
        drop((owned, demand_tx));
        wind_down(&shared, &clock, dir).await;
    }

    #[tokio::test]
    async fn a_worker_that_sends_nothing_for_ten_seconds_is_killed_and_restarted() {
        let dir = private_dir("driver-silent");
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(&worker_script(&dir, "exec sleep 30"), clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert_eq!(bounded_step(&mut driver).await, "resolved:true");
        let almost = WORKER_SILENCE_LIMIT
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        clock.advance(almost);
        assert!(ready_wake(&mut driver).await.is_none(), "not yet");
        // Any message restarts the count.
        driver.on_worker_event(WorkerEvent::Stats(lotse_ipc::WorkerStats::default()));
        clock.advance(almost);
        assert!(ready_wake(&mut driver).await.is_none(), "a fresh limit");
        clock.advance(Duration::from_millis(1));
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        assert_eq!(bounded_step(&mut driver).await, "silent");
        // Its channel ends with it; it is killed once.
        assert_eq!(step_to_exit(&mut driver).await, "exited:Some(9)");
        assert_eq!(captured.lines("worker killed").len(), 1);
        assert_eq!(driver.machine.crashes(), 1);
        assert_eq!(driver.machine.state(), ConnectionState::Restarting);
        // A worker that is stopped is not timed.
        clock.advance(Duration::from_secs(1));
        step(&mut driver).await;
        assert_eq!(bounded_step(&mut driver).await, "resolved:true");
        demand_tx.send_replace(Demand::default());
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Idle);
        assert!(driver.silence.is_none());
        drop((driver, demand_tx));
        wind_down(&shared, &clock, dir).await;
    }

    /// A worker that has exited, as the driver still holds it.
    async fn dead_worker(shared: &Shared) -> Worker {
        let mut worker = shared.manager.spawn(&[]).unwrap();
        while !matches!(worker.next_event().await, WorkerEvent::Exited(_)) {}
        worker
    }

    fn spec_of(url: &str) -> DriverSpec {
        DriverSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url(url.into()),
            options: "{}".into(),
            host: "127.0.0.1".into(),
            port: Some(1),
            backchannel: false,
        }
    }

    #[tokio::test]
    async fn a_failed_lookup_is_a_backoff_and_retried_on_the_clock() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert!(matches!(driver.pending, Pending::Resolving(_)));
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        driver
            .handle(Wake::Resolved(Err("no such host".into())))
            .await;
        assert_eq!(driver.machine.state(), ConnectionState::Backoff);
        assert_eq!(
            driver.machine.last_error().map(ConnectionError::code),
            Some("source_unreachable")
        );
        let logged = captured.lines("host resolution failed; retrying");
        assert!(
            logged[0].contains("error=no such host") && logged[0].contains("retry_ms="),
            "{logged:?}"
        );
        assert!(ready_wake(&mut driver).await.is_none(), "the retry waits");
        clock.advance(Duration::from_secs(120));
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::RetryResolve));
        driver.handle(wake).await;
        assert_eq!(driver.machine.state(), ConnectionState::Connecting);
        assert!(
            matches!(driver.pending, Pending::Resolving(_)),
            "looked up again"
        );
        drop((driver, demand_tx));
    }

    #[tokio::test]
    async fn a_switch_during_the_lookup_retry_looks_up_the_new_source_at_once() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        driver
            .handle(Wake::Resolved(Err("no such host".into())))
            .await;
        assert!(matches!(driver.pending, Pending::Retry(_)));
        assert_eq!(driver.machine.state(), ConnectionState::Backoff);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(DriverSpec {
                host: "127.0.0.2".into(),
                port: Some(7),
                ..spec_of("fake://127.0.0.2:7/")
            })))
            .await;
        assert_eq!(driver.machine.state(), ConnectionState::Connecting);
        assert!(
            matches!(driver.pending, Pending::Resolving(_)),
            "the new source is looked up without waiting out the old retry"
        );
        let logged = captured.lines("source switched while the lookup waited to retry");
        assert!(logged[0].contains(r#"host="127.0.0.2""#), "{logged:?}");
        // The old retry's wait is gone: past it, the wake is the new
        // source's lookup, not the old one's retry.
        clock.advance(Duration::from_secs(120));
        let new_source: SocketAddr = "127.0.0.2:7".parse().unwrap();
        let wake = next_wake(&mut driver).await;
        assert!(
            matches!(&wake, Wake::Resolved(Ok(addrs)) if addrs == &[new_source]),
            "the new source's lookup finishes first"
        );
        drop((driver, demand_tx));
    }

    #[tokio::test]
    async fn a_switch_whose_lookup_fails_waits_on_the_clock_and_a_dead_worker_is_not_told() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        driver
            .handle(Wake::SwitchResolved(Err("no such host".into())))
            .await;
        let logged = captured.lines("source to switch to could not be resolved");
        assert!(logged[0].contains("retry_ms="), "{logged:?}");
        assert!(ready_wake(&mut driver).await.is_none(), "the retry waits");
        clock.advance(Duration::from_secs(120));
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::RetrySwitchResolve));
        driver.handle(wake).await;
        assert!(
            matches!(driver.pending, Pending::Nothing),
            "no worker, no lookup"
        );
        // A worker that is gone cannot be told: the exit follows.
        driver.worker = Some(dead_worker(&shared).await);
        driver
            .handle(Wake::SwitchResolved(Ok(vec![
                "127.0.0.1:1".parse().unwrap(),
            ])))
            .await;
        assert_eq!(
            captured
                .lines("source switch could not be sent to the worker")
                .len(),
            1
        );
        driver.handle(Wake::SwitchConnect(SlotWake::Grant)).await;
        assert_eq!(
            captured
                .lines("standby connect grant could not be sent to the worker")
                .len(),
            1
        );
        driver.handle(Wake::ProbeConnect(SlotWake::Grant)).await;
        assert_eq!(
            captured
                .lines("probe connect grant could not be sent to the worker")
                .len(),
            1
        );
        driver
            .handle(Wake::Command(DriverCommand::Backchannel(spec_of(
                "fake://127.0.0.1:1/",
            ))))
            .await;
        assert_eq!(
            captured
                .lines("backchannel change could not be sent to the worker")
                .len(),
            1
        );
        // Nothing else is a switch's to handle, nor a standby's event.
        driver.handle_switch(Wake::LingerExpired).await;
        driver.on_standby_event(WorkerEvent::SourceStopped);
        assert!(driver.worker.is_some());
        // A switch message never goes to the worker itself.
        let (commands, _rx) = mpsc::channel(1);
        let worker = driver.worker.as_mut().unwrap();
        let switch = DriverCommand::SwitchSource(spec_of("fake://127.0.0.1:1/b"));
        Driver::send(worker, &shared, &commands, switch).await;
        drop(driver);
        assert!(
            captured
                .lines("session message could not be sent")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_worker_s_reports_reach_the_snapshot_and_the_log() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        // Ready before the snapshot has a worker, and after.
        driver.on_worker_event(WorkerEvent::Ready {
            pid: 7,
            memory: None,
        });
        driver.snapshot.worker = Some(WorkerProcess {
            pid: 7,
            started: shared.clock.now(),
            memory: None,
        });
        driver.on_worker_event(WorkerEvent::Ready {
            pid: 7,
            memory: None,
        });
        assert_eq!(captured.lines("worker ready").len(), 2);
        let track = lotse_ipc::TrackInfo {
            id: "v0".into(),
            kind: "video".into(),
            codec: "h264".into(),
            sync: "arrival".into(),
            derived_from: None,
            audio_delay_ms: None,
            params: lotse_ipc::TrackParams::default(),
        };
        driver.on_worker_event(WorkerEvent::Tracks(vec![track.clone()]));
        assert_eq!(driver.snapshot.tracks, [track]);
        assert_eq!(captured.lines("tracks declared").len(), 1);
        // A session event for a session that is gone changes nothing.
        driver.on_worker_event(WorkerEvent::Session {
            session_id: "gone".into(),
            event: lotse_ipc::SessionEvent::Answer {
                sdp: "v=0".into(),
                talkback: None,
            },
        });
        assert!(shared.lock().sessions.is_empty());
        driver.on_worker_event(WorkerEvent::SwitchReport(WorkerReport::Backoff {
            error: SourceError::AuthFailed("401".into()),
            retry_in: Duration::from_millis(1_500),
            position: BackoffPosition::default(),
        }));
        let logged = captured.lines("the source to switch to failed");
        assert!(
            logged[0].contains("error.code=\"source_auth_failed\"")
                && logged[0].contains("retry_ms=1500"),
            "{logged:?}"
        );
        // A stop without a worker is the exit at once.
        assert!(matches!(
            driver.perform(Action::StopWorker),
            Some(Input::WorkerExited)
        ));
        drop(driver);
        assert!(shared.tracker.is_empty(), "nothing to stop");
    }

    /// Regression for SUP-30: every `Tracks` message was an `info` line,
    /// so a worker repeating its declaration, or flipping between two,
    /// grew the log at its own rate.
    #[tokio::test]
    async fn a_worker_s_repeated_declaration_logs_nothing_and_a_changed_one_once_per_interval() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let track = |id: &str| lotse_ipc::TrackInfo {
            id: id.into(),
            kind: "video".into(),
            codec: "h264".into(),
            sync: "arrival".into(),
            derived_from: None,
            audio_delay_ms: None,
            params: lotse_ipc::TrackParams::default(),
        };
        for _ in 0..100 {
            driver.on_worker_event(WorkerEvent::Tracks(vec![track("v0")]));
        }
        assert_eq!(captured.lines("tracks declared").len(), 1);
        for _ in 0..50 {
            driver.on_worker_event(WorkerEvent::Tracks(vec![track("v1"), track("a1")]));
            driver.on_worker_event(WorkerEvent::Tracks(vec![track("v0")]));
        }
        driver.on_worker_event(WorkerEvent::Tracks(vec![track("v1"), track("a1")]));
        assert_eq!(
            driver.snapshot.tracks,
            [track("v1"), track("a1")],
            "every change is kept"
        );
        assert_eq!(
            captured.lines("tracks declared").len(),
            1,
            "within the interval"
        );
        clock.advance(lotse_core::throttle::SUMMARY_INTERVAL);
        driver.on_worker_event(WorkerEvent::Tracks(vec![track("v0")]));
        let lines = captured.lines("tracks declared");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains("tracks=1 count=102"), "{lines:?}");
        drop(driver);
    }

    #[tokio::test]
    async fn a_worker_that_cannot_start_counts_as_a_crash() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/nonexistent/lotse", clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut owned = driver_on(&shared, demand);
        let driver = &mut owned;
        demand_tx.send_replace(PRELOAD);
        step(driver).await;
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        driver
            .handle(Wake::Resolved(Ok(vec!["127.0.0.1:1".parse().unwrap()])))
            .await;
        assert!(driver.worker.is_none());
        assert_eq!(captured.lines("worker could not be started").len(), 1);
        assert_eq!(driver.machine.crashes(), 1);
        assert_eq!(driver.machine.state(), ConnectionState::Restarting);
        drop((owned, demand_tx));
    }

    /// Stream `front` on connection `c1` from `url`, as the registry
    /// keeps them, with session `s1` waiting for its answer on it; the
    /// session's events go to the receiver returned.
    fn waiting_session(shared: &Shared, url: &str) -> mpsc::Receiver<lotse_api::Event> {
        use lotse_api_types::stream::{AudioMode, Orientation};

        use crate::registry::{ConnectionEntry, ConnectionKey, StreamEntry, StreamSource, Talker};

        let spec = spec_of(url);
        let url: lotse_core::source_url::SourceUrl = url.parse().unwrap();
        let mut state = shared.lock();
        let switches = state
            .connections
            .get("c1")
            .map_or(0, |entry| entry.switches);
        state.streams.insert(
            "front".into(),
            StreamEntry {
                sources: vec![StreamSource {
                    spec,
                    target: crate::registry::SourceTarget::Url(url.clone()),
                    options: serde_json::Map::new(),
                    reported: serde_json::from_value(
                        serde_json::json!({ "protocol": "fake", "url": "fake://127.0.0.1/" }),
                    )
                    .unwrap(),
                    connection: "c1".into(),
                }],
                preload: false,
                audio: AudioMode::Auto,
                orientation: Orientation::NoTransform,
                created: UNIX_EPOCH,
                prerecord_ms: 0,
                recordings: crate::recording::RecordingCounters::default(),
            },
        );
        state.connections.insert(
            "c1".into(),
            ConnectionEntry {
                key: ConnectionKey {
                    target: crate::registry::SourceTarget::Url(url),
                    options: serde_json::json!({}),
                },
                port: None,
                backchannel: false,
                prerecord_ms: 0,
                demand: watch::channel(Demand {
                    preloads: 0,
                    viewers: 1,
                })
                .0,
                snapshot: ConnectionSnapshot::idle(UNIX_EPOCH),
                switches,
                streams: ["front".to_owned()].into(),
                commands: mpsc::channel(4).0,
                talker: Talker::default(),
            },
        );
        let (events, rx) = mpsc::channel(4);
        state.sessions.insert(
            "s1".into(),
            SessionEntry::new(
                1,
                "front".into(),
                "c1".into(),
                "us1".into(),
                (ConnectionId(1), 1, events),
                Arc::new(SystemClock),
            ),
        );
        rx
    }

    /// The driver takes a switch to the same source that the registry
    /// queued for connection `c1`: both count it.
    fn take_switch(shared: &Shared, driver: &mut Driver) {
        if let Some(entry) = shared.lock().connections.get_mut("c1") {
            entry.switches += 1;
        }
        driver.on_switch_source(driver.spec.clone());
    }

    #[tokio::test]
    async fn a_failed_lookup_closes_the_waiting_session_with_its_error_and_no_credentials() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = Driver::new(
            (
                DriverSpec {
                    connection_id: "c1".into(),
                    target: SourceTarget::Url("fake://admin:hunter2@cam.example/".into()),
                    options: "{}".into(),
                    host: "cam.example".into(),
                    port: None,
                    backchannel: false,
                },
                0,
            ),
            Arc::clone(&shared),
            demand,
            mpsc::channel(4),
            ConnectionConfig::default(),
        );
        let mut events = waiting_session(&shared, "fake://admin:hunter2@cam.example/");
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        driver.publish();
        assert!(shared.lock().sessions.contains_key("s1"), "connecting");
        driver
            .handle(Wake::Resolved(Err("no such host".into())))
            .await;
        driver.publish();
        let closed = events.try_recv().expect("closed at once").payload;
        assert_eq!(
            closed,
            serde_json::json!({ "type": "closed", "code": "source_unreachable",
                "message": "source unreachable: resolving cam.example: no such host" })
        );
        let text = closed.to_string();
        assert!(
            !text.contains("admin") && !text.contains("hunter2"),
            "{text}"
        );
        assert!(matches!(
            events.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(shared.lock().sessions.is_empty());
        drop((driver, demand_tx));
    }

    #[tokio::test]
    async fn a_worker_that_cannot_start_closes_the_waiting_session_with_worker_crashed() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/nonexistent/lotse", clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let mut events = waiting_session(&shared, "fake://127.0.0.1/");
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        driver
            .handle(Wake::Resolved(Ok(vec!["127.0.0.1:1".parse().unwrap()])))
            .await;
        assert_eq!(driver.machine.state(), ConnectionState::Restarting);
        driver.publish();
        assert_eq!(
            events.try_recv().expect("closed at once").payload,
            serde_json::json!({ "type": "closed", "code": "worker_crashed",
                "message": "worker crashed" })
        );
        assert!(shared.lock().sessions.is_empty());
        drop((driver, demand_tx));
    }

    #[tokio::test]
    async fn a_waiting_session_closes_only_with_a_failed_attempt_of_the_current_source() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let mut events = waiting_session(&shared, "fake://127.0.0.1/");
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        let on = |driver: &mut Driver, event| {
            driver.on_worker_event(event);
            driver.publish();
        };
        let backoff = |error| WorkerReport::Backoff {
            error,
            retry_in: Duration::from_secs(1),
            position: BackoffPosition::default(),
        };
        // A live source drops and its retry waits out a delay.
        on(&mut driver, WorkerEvent::Report(WorkerReport::Live));
        on(
            &mut driver,
            WorkerEvent::Report(backoff(SourceError::Ended("eof".into()))),
        );
        assert_eq!(driver.machine.state(), ConnectionState::Backoff);
        assert_eq!(driver.snapshot.failure, None, "a drop");
        // A switch while the old source streams: the new one failing
        // leaves the old one to answer.
        on(&mut driver, WorkerEvent::Report(WorkerReport::Live));
        take_switch(&shared, &mut driver);
        on(
            &mut driver,
            WorkerEvent::SwitchReport(backoff(SourceError::AuthFailed("401".into()))),
        );
        assert_eq!(driver.snapshot.failure, None, "the old source is live");
        on(&mut driver, WorkerEvent::SwitchReport(WorkerReport::Live));
        // The old source drops and its retry fails while the new one is
        // live: no failure, and the tracks switch to the new source.
        on(
            &mut driver,
            WorkerEvent::Report(WorkerReport::Reconnecting(SourceError::Timeout(
                "stall".into(),
            ))),
        );
        on(
            &mut driver,
            WorkerEvent::Report(backoff(SourceError::Unreachable("old".into()))),
        );
        assert_eq!(driver.snapshot.failure, None, "the new source is live");
        on(&mut driver, WorkerEvent::Switched);
        assert_eq!(driver.machine.state(), ConnectionState::Live);
        assert_eq!(driver.machine.failure(), None);
        // The switch is over: the source's own failed attempt counts.
        on(
            &mut driver,
            WorkerEvent::Report(WorkerReport::Reconnecting(SourceError::Timeout(
                "stall".into(),
            ))),
        );
        on(
            &mut driver,
            WorkerEvent::Report(backoff(SourceError::Timeout("new".into()))),
        );
        assert_eq!(
            events.try_recv().expect("closed").payload,
            serde_json::json!({ "type": "closed", "code": "source_timeout",
                "message": "source timed out: new" })
        );
        let mut events = waiting_session(&shared, "fake://127.0.0.1/");
        on(&mut driver, WorkerEvent::Report(WorkerReport::Live));
        // A switch away from a source whose attempt then fails: its
        // failure is not the new source's.
        take_switch(&shared, &mut driver);
        on(
            &mut driver,
            WorkerEvent::Report(WorkerReport::Reconnecting(SourceError::Timeout(
                "stall".into(),
            ))),
        );
        on(
            &mut driver,
            WorkerEvent::Report(backoff(SourceError::Unreachable("old".into()))),
        );
        assert!(driver.machine.failure().is_some());
        assert_eq!(driver.snapshot.failure, None, "the old source's");
        on(
            &mut driver,
            WorkerEvent::SwitchReport(WorkerReport::Connecting),
        );
        assert!(events.try_recv().is_err(), "still waiting");
        // Neither source can answer: the new one's failure closes it.
        on(
            &mut driver,
            WorkerEvent::SwitchReport(backoff(SourceError::AuthFailed("401".into()))),
        );
        assert_eq!(
            events.try_recv().expect("closed").payload,
            serde_json::json!({ "type": "closed", "code": "source_auth_failed",
                "message": "source authentication failed: 401" })
        );
        drop((driver, demand_tx));
    }

    #[tokio::test]
    async fn a_worker_crash_during_a_switch_is_the_failure_an_offer_closes_with() {
        let shared = shared("/usr/bin/true");
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Live));
        driver.on_switch_source(driver.spec.clone());
        driver.on_worker_event(WorkerEvent::Exited(ExitStatus::from_raw(9)));
        driver.publish();
        assert_eq!(driver.machine.state(), ConnectionState::Restarting);
        assert_eq!(
            driver.snapshot.failure,
            Some(ConnectionError::WorkerCrashed)
        );
        drop((driver, demand_tx));
    }

    #[tokio::test]
    async fn the_last_error_during_a_switch_is_the_failure_a_waiting_session_closes_with() {
        let shared = shared("/usr/bin/true");
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        let on = |driver: &mut Driver, event| {
            driver.on_worker_event(event);
            driver.publish();
        };
        on(&mut driver, WorkerEvent::Report(WorkerReport::Live));
        driver.on_switch_source(driver.spec.clone());
        assert_eq!(driver.snapshot.switches, 1, "the switch is counted");
        // The new source fails while the old one streams.
        let new = SourceError::AuthFailed("401".into());
        on(
            &mut driver,
            WorkerEvent::SwitchReport(WorkerReport::Backoff {
                error: new.clone(),
                retry_in: Duration::from_secs(1),
                position: BackoffPosition::default(),
            }),
        );
        // Then the old one drops and its retry fails.
        on(
            &mut driver,
            WorkerEvent::Report(WorkerReport::Reconnecting(SourceError::Timeout(
                "stall".into(),
            ))),
        );
        on(
            &mut driver,
            WorkerEvent::Report(WorkerReport::Backoff {
                error: SourceError::Unreachable("old".into()),
                retry_in: Duration::from_secs(1),
                position: BackoffPosition::default(),
            }),
        );
        let new = Some(ConnectionError::Source(new));
        assert_eq!(driver.snapshot.failure, new);
        assert_eq!(
            driver.snapshot.last_error, new,
            "the one sessions close with"
        );
        drop((driver, demand_tx));
    }

    #[tokio::test]
    async fn a_waiting_session_closes_with_the_failed_lookup_of_the_source_switched_to() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        // The old source's retry has failed, and the switch away from it
        // waits for the new host.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Live));
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Reconnecting(
            SourceError::Timeout("stall".into()),
        )));
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Backoff {
            error: SourceError::Unreachable("old".into()),
            retry_in: Duration::from_secs(1),
            position: BackoffPosition::default(),
        }));
        let mut events = waiting_session(&shared, "fake://127.0.0.1/");
        take_switch(&shared, &mut driver);
        driver.publish();
        assert!(events.try_recv().is_err(), "still waiting");
        // The new host does not resolve: neither source can answer.
        driver
            .handle(Wake::SwitchResolved(Err("no such host".into())))
            .await;
        driver.publish();
        assert_eq!(
            events.try_recv().expect("closed").payload,
            serde_json::json!({ "type": "closed", "code": "source_unreachable",
                "message": "source unreachable: resolving 127.0.0.1: no such host" })
        );
        // The next lookup is the new source's next attempt.
        driver.handle(Wake::RetrySwitchResolve).await;
        driver.publish();
        assert_eq!(driver.snapshot.failure, None);
        drop((driver, demand_tx));
    }

    #[tokio::test]
    async fn a_source_too_large_for_the_channel_still_leaves_the_worker_timed() {
        let dir = private_dir("driver-too-large");
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(&worker_script(&dir, "exec sleep 30"), clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        // Over the channel's message limit: the send fails before a write.
        driver.spec.target =
            SourceTarget::Url(format!("fake://127.0.0.1/{}", "x".repeat(300 * 1024)));
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        driver
            .handle(Wake::Resolved(Ok(vec!["127.0.0.1:1".parse().unwrap()])))
            .await;
        assert_eq!(
            captured
                .lines("source could not be sent to the worker")
                .len(),
            1
        );
        assert!(driver.worker.is_some() && driver.silence.is_some());
        drop((driver, demand_tx));
        wind_down(&shared, &clock, dir).await;
    }

    #[tokio::test]
    async fn the_silence_limit_without_a_worker_does_nothing() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        driver.handle(Wake::WorkerSilent).await;
        assert!(driver.worker.is_none());
        assert_eq!(driver.machine.crashes(), 0);
    }

    #[tokio::test]
    async fn preload_keeps_one_worker_through_source_failures_and_lingers_when_it_ends() {
        let dir = private_dir("driver-preload");
        let script = dir.join("worker.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(script.to_str().unwrap(), clock.clone());
        let linger = Duration::from_secs(5);
        let almost = Duration::from_millis(4_999);
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = Driver::new(
            (
                DriverSpec {
                    connection_id: "c1".into(),
                    target: SourceTarget::Url("fake://127.0.0.1/".into()),
                    options: "{}".into(),
                    host: "127.0.0.1".into(),
                    port: None,
                    backchannel: false,
                },
                0,
            ),
            Arc::clone(&shared),
            demand,
            mpsc::channel(4),
            ConnectionConfig {
                linger,
                ..ConnectionConfig::default()
            },
        );
        // `preload: true` is demand without a viewer: the worker starts.
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Connecting);
        step(&mut driver).await;
        let pid = driver.snapshot.worker.as_ref().expect("a worker runs").pid;
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Live));
        assert_eq!(driver.machine.state(), ConnectionState::Live);

        // The camera fails: the worker reconnects on its own schedule, as
        // often as it takes while preload wants the stream, and the
        // supervisor neither gives up nor replaces the worker.
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Reconnecting(
            SourceError::Timeout("stall".into()),
        )));
        assert_eq!(driver.machine.state(), ConnectionState::Reconnecting);
        assert_eq!(driver.snapshot.reconnects, 1);
        for _ in 0..30 {
            driver.on_worker_event(WorkerEvent::Report(WorkerReport::Backoff {
                error: SourceError::Unreachable("refused".into()),
                retry_in: Duration::from_secs(60),
                position: BackoffPosition::default(),
            }));
            assert_eq!(driver.machine.state(), ConnectionState::Backoff);
            driver.on_worker_event(WorkerEvent::Report(WorkerReport::Connecting));
        }
        assert_eq!(
            driver.machine.last_error().map(ConnectionError::code),
            Some("source_unreachable")
        );
        driver.on_worker_event(WorkerEvent::Report(WorkerReport::Live));
        assert_eq!(driver.machine.state(), ConnectionState::Live);
        assert_eq!(driver.machine.last_error(), None);
        assert_eq!(
            driver.snapshot.worker.as_ref().map(|w| w.pid),
            Some(pid),
            "the same worker"
        );

        // Preload off with no viewers: the linger runs, the worker stays.
        demand_tx.send_replace(Demand::default());
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Draining);
        clock.advance(almost);
        assert!(ready_wake(&mut driver).await.is_none(), "still lingering");
        // A viewer within the linger takes the warm worker.
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Live);
        assert!(driver.linger.is_none(), "the linger is cancelled");
        assert_eq!(driver.snapshot.worker.as_ref().map(|w| w.pid), Some(pid));
        // It leaves; this time the linger runs out and the worker stops.
        demand_tx.send_replace(Demand::default());
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Draining);
        clock.advance(almost);
        assert!(ready_wake(&mut driver).await.is_none(), "a fresh linger");
        clock.advance(Duration::from_millis(1));
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::LingerExpired));
        driver.handle(wake).await;
        assert_eq!(driver.machine.state(), ConnectionState::Idle);
        assert_eq!(driver.snapshot.worker, None);
        assert_eq!(driver.machine.crashes(), 0, "an expected exit");

        drop(demand_tx);
        assert!(matches!(next_wake(&mut driver).await, Wake::Demand(None)));
        drop(driver);
        // The stop sent the worker a shutdown it ignores; the budget runs
        // out on the fake clock and it is killed.
        shared.tracker.close();
        while !shared.tracker.is_empty() {
            clock.advance(shared.shutdown_budget);
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A recording worker's script under `dir`, writing what it gets to
    /// `received`.
    fn recording_script(dir: &std::path::Path) -> (String, std::path::PathBuf) {
        let out = dir.join("received");
        let script = dir.join("worker.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nexec cat > {}\n", out.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        (script.to_string_lossy().into_owned(), out)
    }

    fn recording_spec(recording_id: &str) -> RecordingSpec {
        RecordingSpec {
            recording_id: recording_id.into(),
            prerecord_ms: 10_000,
            duration_ms: 20_000,
            audio: true,
        }
    }

    /// Recording `recording_id`, `serial`, of `front` on `c1` in `shared`'s registry,
    /// and its events.
    fn hold_recording(
        shared: &Shared,
        recording_id: &str,
        serial: u64,
    ) -> mpsc::Receiver<lotse_api::Event> {
        let (events, rx) = mpsc::channel(4);
        let (written, report) = tokio::sync::oneshot::channel();
        let body = lotse_api::RecordingBody {
            reader: Box::new(tokio::io::empty()),
            written: report,
        };
        let owner = crate::recording::RecordingOwner {
            connection: ConnectionId(1),
            subscription: 1,
            events,
        };
        shared.lock().recordings.insert(
            recording_id.into(),
            crate::recording::RecordingEntry::new(
                serial,
                ("front".into(), "c1".into()),
                recording_spec(recording_id),
                owner,
                (body, written),
            ),
        );
        rx
    }

    /// A worker's `Started` is stamped on the wall clock when it reaches the
    /// driver, not when the recording was asked for: the worker counts
    /// `prerecord_ms` back from the moment it sends it, so `at − prerecord_ms` is
    /// the first keyframe's capture time.
    #[tokio::test]
    async fn a_started_report_is_stamped_on_its_arrival_which_prerecord_ms_counts_back_from() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let mut rx = hold_recording(&shared, "k1", 1);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        clock.advance(Duration::from_millis(1_100));
        let arrival = clock.wall_now();
        driver.on_worker_event(WorkerEvent::Recording {
            recording_id: "k1".into(),
            event: RecordingReport::Started {
                prerecord_ms: 400,
                video: "h264".into(),
                picture: None,
                audio: None,
            },
        });
        drop(driver);
        let started = rx.try_recv().unwrap().payload;
        assert_eq!(
            (&started["at"], &started["prerecord_ms"]),
            (
                &serde_json::json!(lotse_api_types::time::rfc3339(arrival)),
                &serde_json::json!(400)
            )
        );
    }

    /// The spec of a signaled source: no host to look up.
    fn signaled_spec() -> DriverSpec {
        DriverSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Signaled("webrtc".into()),
            options: "{}".into(),
            host: String::new(),
            port: None,
            backchannel: false,
        }
    }

    /// A driver of [`signaled_spec`] on `shared`, registered as connection
    /// `c1` with its own command queue, as the handler creates one.
    fn signaled_driver(shared: &Arc<Shared>, demand: watch::Receiver<Demand>) -> Driver {
        let (commands_tx, commands) = mpsc::channel(4);
        shared.lock().connections.insert(
            "c1".into(),
            crate::registry::ConnectionEntry {
                port: None,
                backchannel: false,
                prerecord_ms: 0,
                key: crate::registry::ConnectionKey {
                    target: crate::registry::SourceTarget::Signaled {
                        protocol: "webrtc",
                        stream: "front".into(),
                    },
                    options: serde_json::Value::Null,
                },
                demand: watch::channel(Demand::default()).0,
                snapshot: ConnectionSnapshot::idle(UNIX_EPOCH),
                switches: 0,
                streams: std::collections::BTreeSet::from(["door".to_owned()]),
                commands: commands_tx.clone(),
                talker: crate::registry::Talker::default(),
            },
        );
        Driver::new(
            (signaled_spec(), 0),
            Arc::clone(shared),
            demand,
            (commands_tx, commands),
            ConnectionConfig::default(),
        )
    }

    #[tokio::test]
    async fn a_signaled_source_s_worker_starts_without_a_lookup_and_its_switch_resolves_at_once() {
        let dir = private_dir("driver-signaled-lookup");
        let (script, out) = recording_script(&dir);
        let shared = shared(&script);
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        demand_tx.send_replace(PRELOAD);
        step(&mut driver).await;
        assert!(matches!(driver.pending, Pending::Resolving(_)));
        // No DNS: no host, no addresses, at once.
        let wake = next_wake(&mut driver).await;
        assert!(matches!(&wake, Wake::Resolved(Ok(addrs)) if addrs.is_empty()));
        driver.handle(wake).await;
        let run = driver
            .spec
            .source_spec(vec![], driver.machine.backoff_position(), 0);
        assert_eq!(run.peer_host, "", "no host");
        recorded(&out, &lotse_ipc::ToWorker::RunSource(run)).await;
        driver.start_resolving_switch();
        let wake = next_wake(&mut driver).await;
        assert!(matches!(&wake, Wake::SwitchResolved(Ok(addrs)) if addrs.is_empty()));
        let worker = driver.worker.take().unwrap();
        drop(driver);
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The refusal of open `request` no subscription took in time.
    fn no_client(request: u64) -> SignalCommand {
        SignalCommand::Refused {
            request,
            code: "no_signaling_client".into(),
            message: "no control-API client relays this source's signaling".into(),
        }
    }

    /// A signaling subscription for every stream, of control connection 1.
    fn subscribe_all(shared: &Shared) -> mpsc::Receiver<lotse_api::Event> {
        let owner = crate::signaling::Owner {
            connection: ConnectionId(1),
            subscription: 1,
        };
        let now = shared.clock.now();
        shared
            .lock()
            .signaling_subscribe(owner, None, (now, UNIX_EPOCH))
    }

    /// The next signaling event `events` holds now.
    fn signaling_event(events: &mut mpsc::Receiver<lotse_api::Event>) -> serde_json::Value {
        let event = events.try_recv().unwrap();
        assert_eq!(event.class, lotse_api::EventClass::Signaling);
        event.payload
    }

    /// The ids of the opens the driver holds as waiting.
    fn waiting(driver: &Driver) -> Vec<u64> {
        driver.signal_opens.keys().copied().collect()
    }

    /// `command` for the driver's running worker, as the queue holds it.
    fn for_worker(driver: &Driver, command: SignalCommand) -> Wake {
        Wake::Command(DriverCommand::Signal {
            worker: driver.worker_serial,
            command,
        })
    }

    #[tokio::test]
    async fn a_signaling_open_waits_for_a_subscription_up_to_its_wait_then_is_refused_no_signaling_client()
     {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        // No subscription takes the stream: each open waits, timed from
        // its arrival.
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 1 }));
        clock.advance(Duration::from_secs(4));
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 2 }));
        assert!(queued_signals(&mut driver).is_empty());
        clock.advance(Duration::from_millis(5_999));
        assert_eq!(SIGNAL_WAIT, Duration::from_secs(10));
        assert!(
            ready_wake(&mut driver).await.is_none(),
            "no wait is over yet"
        );
        clock.advance(Duration::from_millis(1));
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::SignalWaited));
        driver.handle(wake).await;
        // The first is refused, and is among the opens until its answer
        // passes here; the second waits on.
        let first = clock.now().checked_sub(SIGNAL_WAIT).unwrap();
        let second = PendingOpen {
            asked: first + Duration::from_secs(4),
            waiting: true,
        };
        assert_eq!(
            driver.signal_opens,
            BTreeMap::from([
                (
                    1,
                    PendingOpen {
                        asked: first,
                        waiting: false
                    }
                ),
                (2, second)
            ])
        );
        let queued = queued_signals(&mut driver);
        assert_eq!(queued, [no_client(1)]);
        driver.worker = Some(dead_worker(&shared).await);
        for command in queued {
            driver.handle(for_worker(&driver, command)).await;
        }
        let _dead = driver.worker.take();
        assert_eq!(driver.signal_opens, BTreeMap::from([(2, second)]));
        assert_eq!(
            captured
                .lines("no client subscribed to the stream's signaling in time")
                .len(),
            1
        );
        // A subscription in time serves the second with a signal.
        let mut events = subscribe_all(&shared);
        let queued = queued_signals(&mut driver);
        let_assert!(
            [SignalCommand::Opened {
                request: 2,
                signal_id,
                local_addrs
            }] = queued.as_slice()
        );
        assert!(local_addrs.is_empty(), "no front door, no hosts");
        assert_eq!(signal_id.len(), 26, "a ULID: {signal_id}");
        let signal_id = signal_id.clone();
        driver.worker = Some(dead_worker(&shared).await);
        driver.handle(for_worker(&driver, queued[0].clone())).await;
        let _dead = driver.worker.take();
        assert!(driver.signal_opens.is_empty());
        // Its wait's end then refuses nothing.
        clock.advance(Duration::from_secs(4));
        let wake = next_wake(&mut driver).await;
        assert!(matches!(wake, Wake::SignalWaited));
        driver.handle(wake).await;
        assert!(queued_signals(&mut driver).is_empty());
        assert!(driver.signal_wait.is_none());
        // Its offer goes to the subscription; the worker's exit closes it.
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Offer {
            signal_id: signal_id.clone(),
            sdp: lotse_core::test_util::FAKE_SIGNALED_OFFER.into(),
        }));
        let offer = signaling_event(&mut events);
        assert_eq!(offer["type"], "offer");
        assert_eq!(offer["signal_id"], signal_id.as_str());
        assert_eq!(offer["stream_id"], "door");
        driver.worker = Some(dead_worker(&shared).await);
        driver.on_worker_exited(ExitStatus::default());
        assert_eq!(
            signaling_event(&mut events),
            serde_json::json!({ "type": "closed", "signal_id": signal_id, "code": "worker_gone",
                                "message": "the source's worker exited" })
        );
        drop(driver);
    }

    #[tokio::test]
    async fn an_open_a_subscription_takes_reaches_the_worker_as_opened() {
        let dir = private_dir("driver-signal-opened");
        let (script, out) = recording_script(&dir);
        let shared = shared(&script);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let _events = subscribe_all(&shared);
        driver.spawn_worker(vec![]).await;
        assert_eq!(driver.worker_serial, 1);
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 2 }));
        let queued = queued_signals(&mut driver);
        let_assert!([opened @ SignalCommand::Opened { request: 2, .. }] = queued.as_slice());
        driver.handle(for_worker(&driver, opened.clone())).await;
        recorded(&out, &lotse_ipc::ToWorker::Signal(opened.clone())).await;
        assert!(driver.signal_opens.is_empty());
        let worker = driver.worker.take().unwrap();
        drop(driver);
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Regression: a signaling wait that is over ends ahead of commands
    /// ready in the queue (and so of worker events, polled before them),
    /// which the biased select would otherwise take on every turn while
    /// they keep coming; demand still comes first.
    #[tokio::test]
    async fn a_signal_wait_that_is_over_ends_before_ready_commands() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 1 }));
        clock.advance(SIGNAL_WAIT.checked_sub(Duration::from_millis(1)).unwrap());
        assert!(!driver.signal_wait_due(), "not over yet");
        clock.advance(Duration::from_millis(1));
        assert!(driver.signal_wait_due());
        driver
            .commands_tx
            .try_send(DriverCommand::Prerecord { ms: 0 })
            .unwrap();
        demand_tx.send_replace(PRELOAD);
        assert!(matches!(driver.wait().await, Wake::Demand(Some(_))));
        assert!(matches!(driver.wait().await, Wake::SignalWaited));
        driver.handle(Wake::SignalWaited).await;
        assert!(
            !driver.signal_opens[&1].waiting,
            "refused, its answer queued"
        );
        assert!(!driver.signal_wait_due());
        assert!(matches!(
            driver.wait().await,
            Wake::Command(DriverCommand::Prerecord { ms: 0 })
        ));
        drop(driver);
    }

    /// An open the registry no longer holds when its wait ends (a
    /// subscription took it; its answer is still on the way) is forgotten
    /// then, so no answer lost after it can hold its place.
    #[tokio::test]
    async fn an_open_taken_before_its_wait_ends_is_forgotten_at_its_end() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 1 }));
        let _events = subscribe_all(&shared);
        assert_eq!(waiting(&driver), [1], "its answer is queued");
        clock.advance(SIGNAL_WAIT);
        driver.end_signal_waits();
        assert!(waiting(&driver).is_empty());
        assert!(driver.signal_wait.is_none());
        // Its answer still reaches the worker.
        let queued = queued_signals(&mut driver);
        let_assert!([SignalCommand::Opened { request: 1, .. }] = queued.as_slice());
        drop(driver);
    }

    /// The supervisor reads nothing a stopping worker still reports, so a
    /// worker's stop closes its signals in the registry itself, as its
    /// exit does.
    #[tokio::test]
    async fn a_worker_s_stop_closes_its_signals_source_stopped() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let mut events = subscribe_all(&shared);
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 1 }));
        let queued = queued_signals(&mut driver);
        let_assert!([SignalCommand::Opened { signal_id, .. }] = queued.as_slice());
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Offer {
            signal_id: signal_id.clone(),
            sdp: lotse_core::test_util::FAKE_SIGNALED_OFFER.into(),
        }));
        assert_eq!(signaling_event(&mut events)["type"], "offer");
        driver.feed(Input::Demand(1));
        driver.feed(Input::Demand(0));
        driver.feed(Input::LingerExpired);
        assert_eq!(
            signaling_event(&mut events),
            serde_json::json!({ "type": "closed", "signal_id": signal_id, "code": "source_stopped",
                                "message": "the source stopped" })
        );
        assert!(shared.lock().signal_ids_for_tests().is_empty());
        drop(driver);
    }

    /// A driver that stops, at the shutdown once the registry dropped its
    /// connection, reads nothing its worker still reports: its signals
    /// close in the registry `source_stopped`, as at any stop.
    #[tokio::test]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "`stop_all` consumes the driver, a move the lint does not see"
    )]
    async fn a_driver_that_stops_closes_its_worker_s_signals_source_stopped() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let mut events = subscribe_all(&shared);
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 1 }));
        let queued = queued_signals(&mut driver);
        let_assert!([SignalCommand::Opened { signal_id, .. }] = queued.as_slice());
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Offer {
            signal_id: signal_id.clone(),
            sdp: lotse_core::test_util::FAKE_SIGNALED_OFFER.into(),
        }));
        assert_eq!(signaling_event(&mut events)["type"], "offer");
        let _dropped = shared.lock().connections.remove("c1");
        driver.worker = Some(dead_worker(&shared).await);
        driver.stop_all().await;
        assert_eq!(
            signaling_event(&mut events),
            serde_json::json!({ "type": "closed", "signal_id": signal_id, "code": "source_stopped",
                                "message": "the source stopped" })
        );
        assert!(shared.lock().signal_ids_for_tests().is_empty());
    }

    /// What the registry held while the queue was full reaches the worker
    /// once the driver has handled what the queue held before it.
    #[tokio::test]
    async fn an_answer_a_full_queue_could_not_take_reaches_the_worker_after_the_queue() {
        let dir = private_dir("driver-signal-held");
        let (script, out) = recording_script(&dir);
        let shared = shared(&script);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let _events = subscribe_all(&shared);
        driver.spawn_worker(vec![]).await;
        for ms in 1..=4 {
            driver
                .commands_tx
                .try_send(DriverCommand::Prerecord { ms })
                .unwrap();
        }
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 1 }));
        // The queue's own come first; the held answer waits for the last.
        for ms in 1..=4 {
            let wake = next_wake(&mut driver).await;
            assert!(
                matches!(wake, Wake::Command(DriverCommand::Prerecord { ms: got }) if got == ms)
            );
            driver.handle(wake).await;
            assert_eq!(waiting(&driver).is_empty(), ms == 4, "after {ms}");
        }
        // The held answer goes out after the command, so waiting for the
        // command alone may read the file before the answer is in it.
        let messages = recorded_where(&out, |message| {
            matches!(
                message,
                lotse_ipc::ToWorker::Signal(SignalCommand::Opened { request: 1, .. })
            )
        })
        .await;
        let opened = messages
            .iter()
            .position(|message| {
                matches!(
                    message,
                    lotse_ipc::ToWorker::Signal(SignalCommand::Opened { request: 1, .. })
                )
            })
            .unwrap();
        assert_eq!(
            messages.get(opened.checked_sub(1).unwrap()),
            Some(&lotse_ipc::ToWorker::Prerecord { ms: 4 })
        );
        assert!(shared.lock().take_held_signals("c1", true).is_empty());
        let worker = driver.worker.take().unwrap();
        drop(driver);
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Commands that keep the queue from emptying hold up what the
    /// registry held only until the driver has handled what the queue
    /// held before it, and one more it may have had in hand.
    #[tokio::test]
    async fn a_queue_that_never_empties_holds_up_a_held_answer_for_one_queue_at_most() {
        let dir = private_dir("driver-signal-starved");
        let (script, out) = recording_script(&dir);
        let shared = shared(&script);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let _events = subscribe_all(&shared);
        driver.spawn_worker(vec![]).await;
        for ms in 1..=4 {
            driver
                .commands_tx
                .try_send(DriverCommand::Prerecord { ms })
                .unwrap();
        }
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 1 }));
        // Each command handled, another takes its place.
        for handled in 1..=5 {
            let wake = next_wake(&mut driver).await;
            driver
                .commands_tx
                .try_send(DriverCommand::Prerecord { ms: handled + 4 })
                .unwrap();
            driver.handle(wake).await;
            assert!(!driver.commands.is_empty());
            assert_eq!(waiting(&driver).is_empty(), handled == 5, "after {handled}");
        }
        // The held answer goes out after the command, so waiting for the
        // command alone may read the file before the answer is in it.
        let messages = recorded_where(&out, |message| {
            matches!(
                message,
                lotse_ipc::ToWorker::Signal(SignalCommand::Opened { request: 1, .. })
            )
        })
        .await;
        let opened = messages
            .iter()
            .position(|message| {
                matches!(
                    message,
                    lotse_ipc::ToWorker::Signal(SignalCommand::Opened { request: 1, .. })
                )
            })
            .unwrap();
        assert_eq!(
            messages.get(opened.checked_sub(1).unwrap()),
            Some(&lotse_ipc::ToWorker::Prerecord { ms: 5 })
        );
        let worker = driver.worker.take().unwrap();
        drop(driver);
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A worker's open ids restart at 1, so an answer queued for the
    /// worker before it never reaches the running one, even under an id
    /// the running one waits on.
    #[tokio::test]
    async fn an_answer_for_an_earlier_worker_never_reaches_the_running_one() {
        let dir = private_dir("driver-signal-stale");
        let (script, out) = recording_script(&dir);
        let shared = shared(&script);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        driver.spawn_worker(vec![]).await;
        // As if it were the connection's second worker.
        driver.worker_serial = 2;
        driver.signal_opens.insert(
            1,
            PendingOpen {
                asked: shared.clock.now(),
                waiting: false,
            },
        );
        let refused = |request, code: &str| SignalCommand::Refused {
            request,
            code: code.into(),
            message: "m".into(),
        };
        // The first worker's answer to its open 1 is dropped, and the
        // second worker's open 1 still waits.
        for (worker, command) in [(1, refused(1, "stale")), (2, refused(1, "current"))] {
            driver
                .handle(Wake::Command(DriverCommand::Signal { worker, command }))
                .await;
            if worker == 1 {
                assert_eq!(waiting(&driver), [1]);
            }
        }
        assert!(waiting(&driver).is_empty());
        let seen = recorded(&out, &lotse_ipc::ToWorker::Signal(refused(1, "current"))).await;
        assert!(
            !seen.contains(&lotse_ipc::ToWorker::Signal(refused(1, "stale"))),
            "{seen:?}"
        );
        let stale =
            captured.lines("signal command for a worker that is gone; dropped with its signal");
        assert_eq!(stale.len(), 1, "{stale:?}");
        assert!(stale[0].contains("worker=1 running=2"), "{stale:?}");
        let worker = driver.worker.take().unwrap();
        drop(driver);
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The signal commands the driver's queue holds now, each for the
    /// driver's worker.
    fn queued_signals(driver: &mut Driver) -> Vec<SignalCommand> {
        let mut queued = Vec::new();
        while let Ok(DriverCommand::Signal { worker, command }) = driver.commands.try_recv() {
            assert_eq!(worker, driver.worker_serial);
            queued.push(command);
        }
        queued
    }

    #[tokio::test]
    async fn a_worker_may_have_two_signaling_opens_waiting_and_cancel_only_those() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        driver.worker_serial = 5;
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        // Two opens wait; a third is refused at once, a repeated one ignored.
        for request in [1, 2, 3, 1] {
            driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request }));
        }
        assert_eq!(waiting(&driver), [1, 2]);
        assert_eq!(
            queued_signals(&mut driver),
            [SignalCommand::Refused {
                request: 3,
                code: "limit_reached".into(),
                message: "a worker may have 2 signaling opens waiting".into(),
            }]
        );
        let misuse = captured.lines("a worker's signaling open breaks the contract");
        assert_eq!(misuse.len(), 1, "rate-limited: {misuse:?}");
        assert!(
            misuse[0].contains("more opens waiting than a worker may have"),
            "{misuse:?}"
        );
        // A cancel of a waiting open reaches the registry; of another, not.
        for request in [1, 9] {
            driver.on_worker_event(WorkerEvent::Signal(SignalReport::Cancel { request }));
        }
        assert_eq!(waiting(&driver), [2]);
        let at_registry = captured.lines("signaling open cancelled while it waited for a client");
        assert_eq!(at_registry.len(), 1, "{at_registry:?}");
        assert!(at_registry[0].contains("request=1"), "{at_registry:?}");
        let passed = captured.lines("cancel of a signaling open the driver does not wait on");
        assert_eq!(passed.len(), 1, "{passed:?}");
        assert!(passed[0].contains("request=9"), "{passed:?}");
        let dropped = captured.lines("signaling open cancelled; nothing holds it");
        assert_eq!(dropped.len(), 1, "the registry drops it: {dropped:?}");
        assert!(dropped[0].contains("request=9"), "{dropped:?}");
        // The worker's exit takes its waiting opens and the signals it
        // ended with it, here and in the registry, and so does its stop: a
        // subscription finds none.
        driver.ended_signals.push_back("ended".into());
        driver.worker = Some(dead_worker(&shared).await);
        driver.on_worker_exited(ExitStatus::default());
        assert!(waiting(&driver).is_empty());
        assert!(driver.signal_wait.is_none());
        assert!(driver.ended_signals.is_empty());
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 7 }));
        driver.ended_signals.push_back("ended".into());
        driver.feed(Input::Demand(1));
        driver.feed(Input::Demand(0));
        driver.feed(Input::LingerExpired);
        assert!(waiting(&driver).is_empty(), "a stop clears them too");
        assert!(driver.signal_wait.is_none());
        assert!(driver.ended_signals.is_empty(), "a stop clears them too");
        let _events = subscribe_all(&shared);
        assert!(queued_signals(&mut driver).is_empty());
        drop(driver);
    }

    /// An open whose answer or cancel a full queue lost holds its place
    /// only as long as the attempt that asked can last.
    #[tokio::test]
    async fn an_open_left_without_an_answer_is_forgotten_after_its_attempt() {
        let clock = Arc::new(FakeClock::default());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        // Their waits' ends are lost.
        for request in [1, 2] {
            driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request }));
        }
        assert!(queued_signals(&mut driver).is_empty());
        clock.advance(OPEN_EXPIRY.checked_sub(Duration::from_millis(1)).unwrap());
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 3 }));
        assert_eq!(waiting(&driver), [1, 2]);
        let queued = queued_signals(&mut driver);
        let_assert!([SignalCommand::Refused { code, .. }] = queued.as_slice());
        assert_eq!(code, "limit_reached");
        clock.advance(Duration::from_millis(1));
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 4 }));
        assert_eq!(waiting(&driver), [4]);
        let forgotten = captured.lines("a signaling open got no answer in time; forgotten");
        assert_eq!(forgotten.len(), 2, "{forgotten:?}");
        assert!(
            forgotten[0].contains("request=1 expiry_ms=35000"),
            "{forgotten:?}"
        );
        // The registry forgets them as well: a subscription serves only
        // the open the driver still counts.
        // (One line for both: they were forgotten at one time.)
        let cancelled = captured.lines("signaling open cancelled while it waited for a client");
        assert_eq!(cancelled.len(), 1, "{cancelled:?}");
        let _events = subscribe_all(&shared);
        let queued = queued_signals(&mut driver);
        let_assert!([SignalCommand::Opened { request: 4, .. }] = queued.as_slice());
        drop(driver);
    }

    #[tokio::test]
    async fn rfc8839_5_1_a_worker_s_malformed_offer_or_candidate_ends_its_signal() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        // A well-formed offer and candidate and a close reach the registry
        // as they are; a malformed offer or candidate ends its signal.
        for report in [
            SignalReport::Offer {
                signal_id: "sig".into(),
                sdp: "v=0\r\n".into(),
            },
            SignalReport::Candidate {
                signal_id: "sig".into(),
                candidate: String::new(),
                mid: Some("0".into()),
                mline_index: Some(0),
            },
            SignalReport::Closed {
                signal_id: "sig".into(),
                code: "source_stopped".into(),
                message: "stopped".into(),
            },
            SignalReport::Offer {
                signal_id: "bad-offer".into(),
                sdp: "v=0 offer".into(),
            },
            SignalReport::Candidate {
                signal_id: "bad-candidate".into(),
                candidate: "candidate:1 1 udp 1 cam.local 9 typ host".into(),
                mid: None,
                mline_index: Some(0),
            },
        ] {
            driver.on_worker_event(WorkerEvent::Signal(report));
        }
        let at_registry = || {
            captured.lines("a worker reported on a signal the supervisor does not hold; dropped")
        };
        assert_eq!(at_registry().len(), 5);
        let rejected = at_registry();
        assert!(
            rejected[3].contains("bad-offer") && rejected[4].contains("bad-candidate"),
            "{rejected:?}"
        );
        // The worker is told the relay rejected it, not the camera.
        let failed = |signal_id: &str| SignalCommand::Failed {
            signal_id: signal_id.into(),
            code: "signal_rejected".into(),
            message: "the worker's offer or candidate was malformed".into(),
        };
        assert_eq!(
            queued_signals(&mut driver),
            [failed("bad-offer"), failed("bad-candidate")]
        );
        let malformed = captured.lines("signaling offer or candidate is malformed; signal ended");
        assert_eq!(malformed.len(), 1, "rate-limited: {malformed:?}");
        assert!(
            malformed[0].contains("SDP does not start with v=0"),
            "{malformed:?}"
        );

        // What the worker still reports on them, its own close included,
        // reaches the registry no more: it had the signal's one close.
        let closed = |signal_id: &str| SignalReport::Closed {
            signal_id: signal_id.into(),
            code: "internal_error".into(),
            message: "the relay rejected the source's signal".into(),
        };
        for report in [
            SignalReport::Candidate {
                signal_id: "bad-offer".into(),
                candidate: String::new(),
                mid: None,
                mline_index: Some(0),
            },
            closed("bad-offer"),
            closed("bad-candidate"),
        ] {
            driver.on_worker_event(WorkerEvent::Signal(report));
        }
        assert_eq!(at_registry().len(), 5);
        assert_eq!(
            captured
                .lines("report on a signal the driver ended; dropped")
                .len(),
            3
        );
        // Their close was the last of them the driver waited for.
        assert!(driver.ended_signals.is_empty());
        driver.on_worker_event(WorkerEvent::Signal(closed("bad-offer")));
        assert_eq!(at_registry().len(), 6);
        drop(driver);
    }

    /// The driver remembers the signals it ended up to
    /// [`MAX_ENDED_SIGNALS`], the oldest forgotten first.
    #[tokio::test]
    async fn the_driver_remembers_the_latest_signals_it_ended() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        for n in 0..=MAX_ENDED_SIGNALS {
            driver.on_worker_event(WorkerEvent::Signal(SignalReport::Offer {
                signal_id: format!("bad-{n}"),
                sdp: String::new(),
            }));
            // The queue holds 4.
            let _commands = queued_signals(&mut driver);
        }
        let ended: Vec<String> = (1..=MAX_ENDED_SIGNALS)
            .map(|n| format!("bad-{n}"))
            .collect();
        assert_eq!(driver.ended_signals, ended);
        drop(driver);
    }

    /// What the driver tells a worker on its own waits out a full queue
    /// with the registry's answers, in order with them; only a worker that
    /// is gone cannot be told.
    #[tokio::test]
    async fn the_driver_s_own_signal_commands_wait_out_a_full_queue_and_a_gone_worker_takes_none() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = signaled_driver(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let _events = subscribe_all(&shared);
        for _ in 0..4 {
            driver
                .commands_tx
                .try_send(DriverCommand::Prerecord { ms: 0 })
                .unwrap();
        }
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 1 }));
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 2 }));
        driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request: 3 }));
        for request in 4..6 {
            driver.on_worker_event(WorkerEvent::Signal(SignalReport::Open { request }));
        }
        // The registry's two answers and the driver's three limit
        // refusals wait for the driver, in order.
        let held: Vec<_> = shared
            .lock()
            .take_held_signals("c1", true)
            .into_iter()
            .map(|(worker, command)| {
                assert_eq!(worker, driver.worker_serial);
                command
            })
            .collect();
        let_assert!(
            [
                SignalCommand::Opened { request: 1, .. },
                SignalCommand::Opened { request: 2, .. },
                SignalCommand::Refused {
                    request: 3,
                    code: limit,
                    ..
                },
                SignalCommand::Refused { request: 4, .. },
                SignalCommand::Refused { request: 5, .. },
            ] = held.as_slice(),
            "{held:?}"
        );
        assert_eq!(limit, LIMIT_REACHED);
        // A worker that is gone cannot be told: one line within the
        // summary interval, however many commands meet its channel.
        driver.worker = Some(dead_worker(&shared).await);
        for _ in 0..3 {
            driver
                .handle(Wake::Command(DriverCommand::Signal {
                    worker: 0,
                    command: SignalCommand::Gone {
                        signal_id: "sig".into(),
                    },
                }))
                .await;
        }
        drop(driver);
        let lines = captured.lines("signal command could not be sent to the worker");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("count=1"), "{lines:?}");
    }

    #[tokio::test]
    async fn the_pre_record_window_and_the_recording_messages_reach_the_worker_and_the_next_starts_with_it()
     {
        use std::io::Read as _;

        let dir = private_dir("driver-prerecord");
        let (script, out) = recording_script(&dir);
        let shared = shared(&script);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        // Without a worker the window waits for the next one.
        driver
            .handle(Wake::Command(DriverCommand::Prerecord { ms: 30_000 }))
            .await;
        assert_eq!(
            captured
                .lines("no worker runs; the next one starts with the pre-record window")
                .len(),
            1
        );
        let addrs = vec!["127.0.0.1:1".parse().unwrap()];
        driver.spawn_worker(addrs.clone()).await;
        let run = driver
            .spec
            .source_spec(addrs, driver.machine.backoff_position(), 30_000);
        recorded(&out, &lotse_ipc::ToWorker::RunSource(run)).await;
        driver
            .handle(Wake::Command(DriverCommand::Prerecord { ms: 0 }))
            .await;
        assert_eq!(
            captured
                .lines("pre-record window passed to the running worker; nothing reconnects")
                .len(),
            1
        );
        let (mut reader, writer) = std::io::pipe().unwrap();
        let _events = hold_recording(&shared, "k1", 1);
        driver
            .handle(Wake::Command(DriverCommand::StartRecording {
                spec: recording_spec("k1"),
                serial: 1,
                pipe: writer.into(),
            }))
            .await;
        driver
            .handle(Wake::Command(DriverCommand::StopRecording {
                recording_id: "k1".into(),
            }))
            .await;
        let stop = lotse_ipc::ToWorker::StopRecording {
            recording_id: "k1".into(),
        };
        let messages = recorded(&out, &stop).await;
        assert_eq!(
            messages[1..],
            [
                lotse_ipc::ToWorker::Prerecord { ms: 0 },
                lotse_ipc::ToWorker::StartRecording(recording_spec("k1")),
                stop
            ]
        );
        // The worker's write end was the only one: once the worker read the
        // message and discarded it, the read end is at its end.
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        let worker = driver.worker.take().unwrap();
        drop(driver);
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn recording_messages_to_a_dead_worker_are_logged_and_the_window_waits_for_the_next() {
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        driver.worker = Some(dead_worker(&shared).await);
        driver
            .handle(Wake::Command(DriverCommand::Prerecord { ms: 1_000 }))
            .await;
        assert_eq!(driver.prerecord_ms, 1_000);
        assert_eq!(
            captured
                .lines("pre-record window could not be sent to the worker")
                .len(),
            1
        );
        let (commands, _rx) = mpsc::channel(1);
        let worker = driver.worker.as_mut().unwrap();
        let (_reader, writer) = std::io::pipe().unwrap();
        let _events = hold_recording(&shared, "k1", 1);
        for command in [
            DriverCommand::StartRecording {
                spec: recording_spec("k1"),
                serial: 1,
                pipe: writer.into(),
            },
            DriverCommand::StopRecording {
                recording_id: "k1".into(),
            },
            // Never the worker's.
            DriverCommand::Prerecord { ms: 0 },
        ] {
            assert!(command.session_id().is_none());
            Driver::send(worker, &shared, &commands, command).await;
        }
        drop(driver);
        assert_eq!(captured.lines("session message could not be sent").len(), 2);
    }

    /// A start whose recording is gone when the driver hands it to a worker is
    /// dropped with its pipe: queued while its recording ran, the recording then
    /// ended before the worker came (and a new recording may have taken the id
    /// since), or ended holding its id, which is then free. Only the start
    /// of the recording that runs reaches the worker.
    #[tokio::test]
    async fn a_start_whose_recording_is_gone_never_reaches_a_worker_and_frees_the_id_it_held() {
        use std::io::Read as _;

        let dir = private_dir("driver-stale-recording");
        let (script, out) = recording_script(&dir);
        // A fake clock that stands still: on a real one, a slow run's wait
        // for the worker takes a millisecond off k1's `duration_ms`.
        let shared = shared_with(&script, Arc::new(FakeClock::from_system()));
        // k1 runs as serial 3: serial 1's start is an earlier recording's. k2
        // ended (serial 2) while its start waited, its id held.
        let _events = hold_recording(&shared, "k1", 3);
        shared.lock().stopping_recordings.insert(
            "k2".into(),
            crate::recording::StoppingRecording {
                connection: "c1".into(),
                serial: 2,
            },
        );
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let (mut stale, writer) = std::io::pipe().unwrap();
        // Queued while their recordings ran: `queue` holds no other.
        driver.queued.push(DriverCommand::StartRecording {
            spec: recording_spec("k1"),
            serial: 1,
            pipe: writer.into(),
        });
        driver.queued.push(DriverCommand::StartRecording {
            spec: recording_spec("k2"),
            serial: 2,
            pipe: fd(),
        });
        driver.queue(DriverCommand::StartRecording {
            spec: recording_spec("k1"),
            serial: 3,
            pipe: fd(),
        });
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let addrs = vec!["127.0.0.1:1".parse().unwrap()];
        driver.spawn_worker(addrs.clone()).await;
        // A stop behind the starts: once it is in, every start before it is.
        let end = lotse_ipc::ToWorker::StopRecording {
            recording_id: "end".into(),
        };
        driver
            .handle(Wake::Command(DriverCommand::StopRecording {
                recording_id: "end".into(),
            }))
            .await;
        let messages = recorded(&out, &end).await;
        assert_eq!(
            messages[1..],
            [
                lotse_ipc::ToWorker::StartRecording(recording_spec("k1")),
                end
            ],
            "k1's one start"
        );
        let mut rest = Vec::new();
        stale.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "the stale start's pipe went with it");
        assert!(!shared.lock().recording_id_in_use("k2"), "no worker got k2");
        assert!(shared.lock().recordings.contains_key("k1"));
        let dropped =
            captured.lines("recording ended before its worker got it; its start is dropped");
        assert_eq!(dropped.len(), 2, "{dropped:?}");
        assert!(dropped[0].contains("serial=1"), "{dropped:?}");
        // The id of a later recording is not freed by an earlier one's start.
        shared.lock().stopping_recordings.insert(
            "k3".into(),
            crate::recording::StoppingRecording {
                connection: "c1".into(),
                serial: 5,
            },
        );
        assert!(!shared.lock().recording_start_wanted("k3", 4));
        assert!(shared.lock().recording_id_in_use("k3"));
        let worker = driver.worker.take().unwrap();
        drop(driver);
        // The shared clock is fake: the stop's budget needs a real one.
        let real: Arc<dyn Clock> = Arc::new(SystemClock);
        let _status = worker.stop(Duration::from_millis(200), &real).await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A recording stopped while its start waits for a worker leaves the queue
    /// with its pipe and ends as its worker would have ended it, for the
    /// supervisor's reason.
    #[tokio::test]
    async fn a_recording_closed_before_a_worker_got_it_ends_here_with_nothing_written() {
        use std::io::Read as _;

        let shared = shared("/bin/sh");
        let mut rx = hold_recording(&shared, "k1", 1);
        let _k2 = hold_recording(&shared, "k2", 2);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let (mut reader, writer) = std::io::pipe().unwrap();
        driver.queue(DriverCommand::StartRecording {
            spec: recording_spec("k1"),
            serial: 1,
            pipe: writer.into(),
        });
        driver.queue(DriverCommand::StartRecording {
            spec: recording_spec("k2"),
            serial: 2,
            pipe: fd(),
        });
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        // The registry's stop, whose slot the test leaves out, says why.
        shared
            .lock()
            .stop_recording("k1", RecordingCloseReason::NotFetched);
        driver.queue(DriverCommand::StopRecording {
            recording_id: "k1".into(),
        });
        assert_eq!(driver.queued.len(), 1, "k2 waits on");
        // Before the read: a start still queued would keep the write end.
        assert!(matches!(
            driver.queued[0],
            DriverCommand::StartRecording { serial: 2, .. }
        ));
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "its pipe went with it");
        let closed = rx.try_recv().unwrap().payload;
        assert_eq!(
            (&closed["reason"], &closed["bytes"]),
            (&serde_json::json!("not_fetched"), &serde_json::json!(0))
        );
        assert!(!shared.lock().recordings.contains_key("k1"));
        // One not queued went with the worker that had it.
        driver.queue(DriverCommand::StopRecording {
            recording_id: "k3".into(),
        });
        assert_eq!(driver.queued.len(), 1);
        assert_eq!(
            captured
                .lines("recording stop without a worker for a recording none holds")
                .len(),
            1
        );
    }

    /// A start and a stop of a recording that ended `worker_crashed` (its worker
    /// exited with both still on their way) reach the driver after a new
    /// recording took the id, with no worker yet: the stale start is not held,
    /// so the stop finds nothing to end, and the new recording runs on and is
    /// the one start the next worker gets. Regression: the stale start was
    /// queued, and the stop took it out and ended the new recording `stopped`
    /// with nothing written.
    #[tokio::test]
    async fn a_stale_start_and_stop_after_a_worker_exit_never_end_the_recording_that_reuses_the_id()
    {
        use std::io::Read as _;

        let shared = shared("/bin/sh");
        let mut rx = hold_recording(&shared, "k1", 2);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let (mut stale, writer) = std::io::pipe().unwrap();
        for command in [
            DriverCommand::StartRecording {
                spec: recording_spec("k1"),
                serial: 1,
                pipe: writer.into(),
            },
            DriverCommand::StopRecording {
                recording_id: "k1".into(),
            },
            DriverCommand::StartRecording {
                spec: recording_spec("k1"),
                serial: 2,
                pipe: fd(),
            },
        ] {
            driver.handle(Wake::Command(command)).await;
        }
        assert!(rx.try_recv().is_err(), "k1 got no event");
        assert!(
            shared
                .lock()
                .recordings
                .get("k1")
                .is_some_and(|recording| recording.serial == 2)
        );
        assert_eq!(driver.queued.len(), 1, "k1's own start waits");
        assert!(matches!(
            driver.queued[0],
            DriverCommand::StartRecording { serial: 2, .. }
        ));
        drop(driver);
        let mut rest = Vec::new();
        stale.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "the stale start's pipe went with it");
        let dropped =
            captured.lines("recording ended before its worker got it; its start is dropped");
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert!(dropped[0].contains("serial=1"), "{dropped:?}");
        assert_eq!(
            captured
                .lines("recording stop without a worker for a recording none holds")
                .len(),
            1
        );
    }

    /// A recording that ended while its worker ran it holds its id until that
    /// worker's `Stopped`. When the connection loses its demand while
    /// connecting (a `stream/put` moved the stream's source to a fallback
    /// position, ending the recording `stream_changed`), the driver stops the
    /// worker at once, whose reports then reach no one: the id is free,
    /// and only this connection's. Regression: it stayed taken, and
    /// counted toward `max_recordings`, until the connection was released.
    #[tokio::test]
    async fn a_worker_stopped_for_want_of_demand_frees_the_ids_of_the_recordings_it_was_finishing()
    {
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        driver.follow(Demand {
            preloads: 0,
            viewers: 1,
        });
        driver.worker = Some(dead_worker(&shared).await);
        assert_eq!(driver.machine.state(), ConnectionState::Connecting);
        for (recording_id, connection) in [("k1", "c1"), ("k9", "c2")] {
            shared.lock().stopping_recordings.insert(
                recording_id.into(),
                crate::recording::StoppingRecording {
                    connection: connection.into(),
                    serial: 1,
                },
            );
        }
        driver.follow(Demand::default());
        assert!(driver.worker.is_none(), "stopped");
        assert!(!shared.lock().recording_id_in_use("k1"));
        assert!(
            shared.lock().recording_id_in_use("k9"),
            "another connection's"
        );
        assert_eq!(
            captured
                .lines("the worker of a recording that had ended is gone; its id is free")
                .len(),
            1
        );
        drop(driver);
        shared.tracker.close();
        shared.tracker.wait().await;
    }

    /// A recording whose start waits for a worker that does not come (its host
    /// lookup keeps failing, or a backoff holds the worker back) ends
    /// `source_not_live` once it waited [`Driver::recording_start_wait`], as a worker
    /// ends one that finds no keyframe in time: its body, fetched already,
    /// ends empty and whole, and its pipe goes with its start. A start
    /// queued later waits its own time, and one that left the queue meanwhile
    /// ends nothing. Regression: with its body fetched, nothing ended such
    /// a recording, which held its slot, subscription and pipe for good.
    #[tokio::test]
    async fn a_recording_start_no_worker_takes_in_time_ends_source_not_live_and_the_next_waits_its_own()
     {
        use std::io::Read as _;

        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/bin/sh", clock.clone());
        let mut k1 = hold_recording(&shared, "k1", 1);
        let mut k2 = hold_recording(&shared, "k2", 2);
        let _k3 = hold_recording(&shared, "k3", 3);
        let mut body = shared.lock().take_recording_body("k1").unwrap();
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let wait = shared.lock().recording_limits.start_timeout;
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let (mut reader, writer) = std::io::pipe().unwrap();
        driver.queue(DriverCommand::StartRecording {
            spec: recording_spec("k1"),
            serial: 1,
            pipe: writer.into(),
        });
        // k3's start leaves the queue with its stop.
        driver.queue(DriverCommand::StartRecording {
            spec: recording_spec("k3"),
            serial: 3,
            pipe: fd(),
        });
        driver.queue(DriverCommand::StopRecording {
            recording_id: "k3".into(),
        });
        clock.advance(wait / 2);
        driver.queue(DriverCommand::StartRecording {
            spec: recording_spec("k2"),
            serial: 2,
            pipe: fd(),
        });
        assert!(
            ready_wake(&mut driver).await.is_none(),
            "none waited long enough"
        );
        clock.advance(wait / 2);
        step(&mut driver).await;
        let closed = k1.try_recv().unwrap().payload;
        assert_eq!(
            (&closed["reason"], &closed["bytes"]),
            (&serde_json::json!("source_not_live"), &serde_json::json!(0))
        );
        assert_eq!(body.written.try_recv(), Ok(0), "the body ends whole");
        assert!(k2.try_recv().is_err(), "k2 waits on");
        // Before the read: a start still queued would keep the write end.
        assert_eq!(driver.queued.len(), 1);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "its pipe went with its start");
        assert!(ready_wake(&mut driver).await.is_none());
        clock.advance(wait / 2);
        step(&mut driver).await;
        let closed = k2.try_recv().unwrap().payload;
        assert_eq!(closed["reason"], "source_not_live");
        assert!(driver.queued.is_empty());
        assert!(driver.recording_wait.is_none(), "nothing left to wait for");
        assert!(shared.lock().recordings.is_empty());
        drop(driver);
        let ended = captured.lines("no worker took the recording's start in time");
        assert_eq!(ended.len(), 2, "{ended:?}");
        assert!(ended[0].contains("recording.id=k1"), "{ended:?}");
    }

    /// A queued recording start waits as long as the configured
    /// `limits.recording_start_timeout_ms`, not the default: one longer than
    /// 10 s holds the recording past 10 s and ends it at its own end.
    /// Regression: the driver waited a fixed 10 s, cutting such a recording
    /// short of what its worker would have given it.
    #[tokio::test]
    async fn a_recording_start_waits_the_configured_start_timeout() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/bin/sh", clock.clone());
        shared.lock().recording_limits.start_timeout = Duration::from_secs(25);
        let mut k1 = hold_recording(&shared, "k1", 1);
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        driver.queue(DriverCommand::StartRecording {
            spec: recording_spec("k1"),
            serial: 1,
            pipe: fd(),
        });
        clock.advance(Duration::from_secs(10));
        assert!(ready_wake(&mut driver).await.is_none(), "10 s is not 25 s");
        clock.advance(Duration::from_secs(15) - Duration::from_millis(1));
        assert!(ready_wake(&mut driver).await.is_none(), "nor is a ms short");
        clock.advance(Duration::from_millis(1));
        step(&mut driver).await;
        let closed = k1.try_recv().unwrap().payload;
        assert_eq!(closed["reason"], "source_not_live");
        assert!(driver.queued.is_empty());
        drop(driver);
        let ended = captured.lines("no worker took the recording's start in time");
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert!(ended[0].contains("waited_ms=25000"), "{ended:?}");
    }

    /// What a worker gets of a recording's `duration_ms` is what the wait for it
    /// left (`RecordingCreate`: "how long the recording runs after now"): the wait
    /// taken off in whole milliseconds, and nothing once none is left.
    #[test]
    fn after_left_takes_off_the_wait_and_none_once_the_recording_s_end_passed() {
        assert_eq!(duration_left(1_000, Duration::ZERO), Some(1_000));
        assert_eq!(duration_left(6_000, Duration::from_secs(5)), Some(1_000));
        assert_eq!(
            duration_left(1_000, Duration::from_micros(999_900)),
            Some(1)
        );
        assert_eq!(
            duration_left(1_000, Duration::from_secs(1)),
            None,
            "the end"
        );
        assert_eq!(duration_left(1_000, Duration::from_secs(5)), None);
        assert_eq!(duration_left(u32::MAX, Duration::MAX), None, "saturated");
    }

    /// The starts a new worker gets from the queue run what is left of
    /// their `duration_ms`, which counts from `recording/create`; one whose
    /// end passed while it waited never reaches the worker and ends
    /// `source_not_live` with its pipe and an empty body; a stale one (its
    /// recording ended, a later one holds the id) ends nothing; a later
    /// start that took a stale one's id counts its own wait from when it
    /// was queued.
    /// Regression: the worker counted `duration_ms` from the handoff, so a
    /// recording queued behind a backoff ran its whole `duration_ms` after it.
    #[tokio::test]
    async fn a_queued_recording_start_runs_what_is_left_of_duration_ms_and_one_whose_end_passed_ends_source_not_live()
     {
        use std::io::Read as _;

        let dir = private_dir("driver-recording-wait");
        let (script, out) = recording_script(&dir);
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with(&script, clock.clone());
        let _k1 = hold_recording(&shared, "k1", 1);
        let mut k2 = hold_recording(&shared, "k2", 2);
        let k4 = hold_recording(&shared, "k4", 4);
        let mut body = shared.lock().take_recording_body("k2").unwrap();
        let (_demand_tx, demand) = watch::channel(Demand::default());
        let mut driver = driver_on(&shared, demand);
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let (mut reader, writer) = std::io::pipe().unwrap();
        for (recording_id, serial, duration_ms, pipe) in [
            ("k1", 1, 6_000, fd()),
            ("k2", 2, 1_000, writer.into()),
            ("k4", 4, 1_000, fd()),
        ] {
            driver.queue(DriverCommand::StartRecording {
                spec: RecordingSpec {
                    duration_ms,
                    ..recording_spec(recording_id)
                },
                serial,
                pipe,
            });
        }
        // k4's recording ended while its start waited, and a later one took the id
        // and queued its own start 4 s on: it counts its own wait, not the
        // stale start's.
        drop(k4);
        let mut k4_later = hold_recording(&shared, "k4", 5);
        clock.advance(Duration::from_secs(4));
        driver.queue(DriverCommand::StartRecording {
            spec: RecordingSpec {
                duration_ms: 2_000,
                ..recording_spec("k4")
            },
            serial: 5,
            pipe: fd(),
        });
        clock.advance(Duration::from_secs(1));
        let addrs = vec!["127.0.0.1:1".parse().unwrap()];
        driver.spawn_worker(addrs).await;
        let end = lotse_ipc::ToWorker::StopRecording {
            recording_id: "end".into(),
        };
        driver
            .handle(Wake::Command(DriverCommand::StopRecording {
                recording_id: "end".into(),
            }))
            .await;
        let messages = recorded(&out, &end).await;
        assert_eq!(
            messages[1..],
            [
                lotse_ipc::ToWorker::StartRecording(RecordingSpec {
                    duration_ms: 1_000,
                    ..recording_spec("k1")
                }),
                lotse_ipc::ToWorker::StartRecording(RecordingSpec {
                    duration_ms: 1_000,
                    ..recording_spec("k4")
                }),
                end,
            ],
            "k1 and the later k4 run the rest, k2 and the stale k4 never reach the worker"
        );
        let closed = k2.try_recv().unwrap().payload;
        assert_eq!(
            (&closed["reason"], &closed["bytes"]),
            (&serde_json::json!("source_not_live"), &serde_json::json!(0))
        );
        assert_eq!(body.written.try_recv(), Ok(0), "the body ends whole");
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "k2's pipe went with its start");
        assert!(k4_later.try_recv().is_err(), "the later k4 is not ended");
        assert_eq!(shared.lock().recordings.get("k4").unwrap().serial, 5);
        let dropped =
            captured.lines("recording ended before its worker got it; its start is dropped");
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert!(dropped[0].contains("serial=4"), "{dropped:?}");
        let passed =
            captured.lines("the recording's end passed while its start waited for a worker");
        assert_eq!(passed.len(), 1, "{passed:?}");
        assert!(passed[0].contains("recording.id=k2"), "{passed:?}");
        let left = captured.lines("it runs what is left of duration_ms");
        assert_eq!(left.len(), 2, "{left:?}");
        assert!(left[0].contains("recording.id=k1"), "{left:?}");
        assert!(left[0].contains("duration_ms=1000"), "{left:?}");
        assert!(left[1].contains("recording.id=k4"), "{left:?}");
        assert!(left[1].contains("serial=5"), "{left:?}");
        assert!(left[1].contains("duration_ms=1000"), "{left:?}");
        assert!(driver.recording_waits.is_empty());
        assert!(driver.recording_wait.is_none());
        let worker = driver.worker.take().unwrap();
        drop(driver);
        // The shared clock is fake: the stop's budget needs a real one.
        let real: Arc<dyn Clock> = Arc::new(SystemClock);
        let _status = worker.stop(Duration::from_millis(200), &real).await;
        std::fs::remove_dir_all(dir).unwrap();
    }
}
