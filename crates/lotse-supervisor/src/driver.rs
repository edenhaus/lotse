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
//! exits or is stopped, or the driver stops ([`crate::connect`]).
//!
//! While a backchannel upgrade restarts the running source to ask for the
//! camera's backchannel, the driver holds the offers that request
//! talk-back on a stream that asked for it, with their later messages,
//! and hands them to the worker once the new source took over, so their
//! answers negotiate talk-back from the backchannel it offers; when the
//! upgrade fails they close with `backchannel_unavailable` and why. Every
//! end of the upgrade the worker reports releases them, and the
//! handler's `source_not_live` deadline bounds the wait besides.
//!
//! A worker that can no longer be told what to do is killed, so its exit
//! runs the crash path and the machine restarts it with backoff: one whose
//! channel ended while it runs, and one that sent nothing for
//! [`WORKER_SILENCE_LIMIT`] (a worker sends its counters every second).

use std::fmt;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;

use lotse_core::backoff::ReconnectBackoff;
use lotse_core::connection::{
    Action, ConnectionConfig, ConnectionError, ConnectionMachine, ConnectionState, Input,
    WorkerReport,
};
use lotse_core::source::SourceError;
use lotse_core::task::{BoxFuture, spawn_named};
use lotse_ipc::{SessionSpec, SourceSpec};
use tokio::sync::{mpsc, watch};

use crate::connect::{CONNECT_LEASE, ConnectSlot, SlotWake};
use crate::net::demux::{DatagramSink, WorkerSink};
use crate::net::turn_client::LeaseGrant;
use crate::registry::{CloseBy, ConnectionSnapshot, Shared, WorkerProcess};
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

/// A message for the connection's worker.
#[derive(Debug)]
pub(crate) enum DriverCommand {
    /// Run this source from now on: a worker switches to it in place, the
    /// next worker starts with it.
    SwitchSource(DriverSpec),
    /// The connection's rule for the camera's backchannel changed (a
    /// stream on it opted in, or the last one out): run this spec, which
    /// asks as the rule now says, from the next connect on. A running
    /// source that does not ask while the spec does is restarted once to
    /// ask (upgrade); one that asks while the spec does not keeps it until
    /// the connection next connects (downgrade deferred), as a reconnect
    /// for that alone would cost the viewers a gap for nothing.
    Backchannel(DriverSpec),
    /// Open this session.
    OpenSession(SessionSpec),
    /// A trickled browser candidate.
    Candidate {
        /// The session.
        session_id: String,
        /// The candidate; empty is end-of-candidates.
        candidate: String,
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
            | Self::Orientation { session_id, .. }
            | Self::CloseSession { session_id, .. }
            | Self::RelayCandidate { session_id, .. }
            | Self::RelayChannel { session_id, .. } => Some(session_id),
            Self::IceTcp { .. }
            | Self::SwitchSource(_)
            | Self::Backchannel(_)
            | Self::ReleaseBackchannel { .. } => None,
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

/// The `closed` code of a talk-back request the camera's backchannel
/// cannot meet on a stream that asked for it.
const BACKCHANNEL_UNAVAILABLE: &str = "backchannel_unavailable";

/// Whether `offer` requests talk-back: an audio m-line (RFC 8866 §5.14)
/// with a mid (RFC 5888 §4) whose direction attribute, the first in its
/// section, is `sendonly` or `sendrecv`, or that has none, which is
/// `sendrecv` (RFC 8866 §6.7): the browser offers to send audio there. The
/// rule the worker's WebRTC output answers talk-back by.
fn requests_talk_back(offer: &str) -> bool {
    /// One media section as far as read: whether it is audio, has a mid,
    /// and its first direction attribute.
    #[derive(Default)]
    struct Section<'a> {
        /// An `m=audio` section.
        audio: bool,
        /// It has an `a=mid`.
        mid: bool,
        /// Its first direction attribute, without `a=`.
        direction: Option<&'a str>,
    }
    impl Section<'_> {
        /// The section asks to send audio.
        fn sends_audio(&self) -> bool {
            self.audio && self.mid && matches!(self.direction, None | Some("sendrecv" | "sendonly"))
        }
    }
    let mut section: Option<Section<'_>> = None;
    for line in offer.lines() {
        if let Some(media) = line.strip_prefix("m=") {
            if section.as_ref().is_some_and(Section::sends_audio) {
                return true;
            }
            section = Some(Section {
                audio: media.split(' ').next() == Some("audio"),
                ..Section::default()
            });
        } else if let Some(current) = section.as_mut()
            && let Some(attribute) = line.strip_prefix("a=")
        {
            if attribute.starts_with("mid:") {
                current.mid = true;
            } else if current.direction.is_none()
                && matches!(attribute, "sendrecv" | "sendonly" | "recvonly" | "inactive")
            {
                current.direction = Some(attribute);
            }
        }
    }
    section.as_ref().is_some_and(Section::sends_audio)
}

/// A backchannel upgrade under way: the running source restarts to ask
/// for the camera's backchannel, and the talk-back requests that came
/// meanwhile wait for it.
#[derive(Debug, Default)]
struct Upgrade {
    /// The held sessions' messages in arrival order, each session's offer
    /// first.
    held: Vec<DriverCommand>,
}

impl Upgrade {
    /// Whether `session_id` is held.
    fn holds(&self, session_id: &str) -> bool {
        self.held.iter().any(|command| {
            matches!(command, DriverCommand::OpenSession(spec) if spec.session_id == session_id)
        })
    }

    /// The held sessions' ids, in arrival order.
    fn sessions(&self) -> Vec<&str> {
        self.held
            .iter()
            .filter_map(|command| match command {
                DriverCommand::OpenSession(spec) => Some(spec.session_id.as_str()),
                _ => None,
            })
            .collect()
    }
}

/// How a backchannel upgrade ended for the sessions it held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpgradeEnd {
    /// The new source took over: they open on it, and their answers
    /// negotiate talk-back from the backchannel it offers, or refuse them
    /// when it offers none.
    Switched,
    /// It failed, for this reason: they close with
    /// `backchannel_unavailable`.
    Failed,
    /// The worker stopped: they wait for the next one, which starts with
    /// the spec that asks for the backchannel.
    NextWorker,
}

/// What the driver needs to start a worker for its connection.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DriverSpec {
    /// The connection's id.
    pub(crate) connection_id: String,
    /// The full source URL, credentials included.
    pub(crate) url: String,
    /// The per-scheme options as JSON text.
    pub(crate) options: String,
    /// The host to resolve, as the URL spells it.
    pub(crate) host: String,
    /// The port, from the URL or the scheme's default.
    pub(crate) port: Option<u16>,
    /// The worker binds a loopback relay listener before its sandbox.
    pub(crate) loopback_relay: bool,
    /// The source asks the camera for its backchannel
    /// ([`Source::wants_backchannel`](lotse_core::source::Source::wants_backchannel)),
    /// as its options say.
    pub(crate) backchannel: bool,
}

impl DriverSpec {
    /// The spec as the worker takes it, with the resolved addresses.
    fn source_spec(&self, peer_addrs: Vec<SocketAddr>) -> SourceSpec {
        SourceSpec {
            connection_id: self.connection_id.clone(),
            url: self.url.clone(),
            options: self.options.clone(),
            peer_host: self.host.clone(),
            peer_addrs,
        }
    }
}

/// Prints the options by name only, as `SourceSpec` and `ConnectionKey`
/// do: a value may be a scheme's secret, and the spec is logged at info
/// on every driver start. Text that is not a JSON object prints as `****`.
impl fmt::Debug for DriverSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let options =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&self.options)
                .map(|options| options.keys().cloned().collect::<Vec<_>>());
        let mut out = f.debug_struct("DriverSpec");
        out.field("connection_id", &self.connection_id)
            .field("url", &"****");
        match &options {
            Ok(names) => out.field("options", names),
            Err(_) => out.field("options", &"****"),
        };
        out.field("host", &self.host)
            .field("port", &self.port)
            .field("loopback_relay", &self.loopback_relay)
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
    Demand(Option<u32>),
    /// The worker said something or exited.
    Worker(WorkerEvent),
    /// A session message for the worker.
    Command(DriverCommand),
    /// The linger timer fired.
    LingerExpired,
    /// The crash-backoff timer fired.
    CrashBackoffExpired,
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

/// The driver of one connection.
pub(crate) struct Driver {
    /// What to run.
    spec: DriverSpec,
    /// The registry side.
    shared: Arc<Shared>,
    /// The demand to follow.
    demand: watch::Receiver<u32>,
    /// Session messages from the handler.
    commands: mpsc::Receiver<DriverCommand>,
    /// The queue's sending side, for the sessions' demux sinks.
    commands_tx: mpsc::Sender<DriverCommand>,
    /// Messages waiting for a worker, in order.
    queued: Vec<DriverCommand>,
    /// The state machine.
    machine: ConnectionMachine,
    /// The running worker.
    worker: Option<Worker>,
    /// The linger timer.
    linger: Option<BoxFuture<'static, ()>>,
    /// The crash-backoff timer.
    crash: Option<BoxFuture<'static, ()>>,
    /// The deadline for the running worker's next message; `None` while
    /// there is no worker, or its exit is expected.
    silence: Option<BoxFuture<'static, ()>>,
    /// The host lookup or its retry.
    pending: Pending,
    /// The connection's place at the connect gate.
    connect: ConnectSlot,
    /// The standby source's place at the connect gate, during a switch.
    switch_connect: ConnectSlot,
    /// The retry schedule of the host lookup.
    resolve_backoff: ReconnectBackoff,
    /// What the registry sees.
    snapshot: ConnectionSnapshot,
    /// The state and error last published, to detect a change.
    published: (ConnectionState, Option<ConnectionError>),
    /// Whether the worker's source asks for the camera's backchannel: the
    /// spec's when the worker started it or last switched to it.
    /// Meaningless without a worker.
    running_backchannel: bool,
    /// The switch under way restarts the source (`RestartSource`) instead
    /// of connecting a standby beside it: an upgrade asked for it.
    restart: bool,
    /// The backchannel upgrade under way and the talk-back requests it
    /// holds; `None` without one. Only ever `Some` with a worker.
    upgrade: Option<Upgrade>,
    /// A source switch is under way: the machine's reports are the old
    /// source's until the tracks switch, or until the host lookup of a
    /// new worker, which runs the source switched to.
    switching: bool,
    /// The failed attempt of the source to switch to, until its next one.
    switch_failure: Option<ConnectionError>,
}

impl Driver {
    /// A driver for `spec` following `demand` and taking `commands`, whose
    /// sending side is `commands_tx`.
    pub(crate) fn new(
        spec: DriverSpec,
        shared: Arc<Shared>,
        demand: watch::Receiver<u32>,
        commands: (mpsc::Sender<DriverCommand>, mpsc::Receiver<DriverCommand>),
        config: ConnectionConfig,
    ) -> Self {
        let snapshot = ConnectionSnapshot::idle(shared.clock.wall_now());
        let connect = ConnectSlot::new(Arc::clone(&shared.clock), CONNECT_LEASE);
        let switch_connect = ConnectSlot::new(Arc::clone(&shared.clock), CONNECT_LEASE);
        let (commands_tx, commands) = commands;
        Self {
            spec,
            shared,
            demand,
            commands,
            commands_tx,
            queued: Vec::new(),
            machine: ConnectionMachine::new(config),
            worker: None,
            linger: None,
            crash: None,
            silence: None,
            pending: Pending::Nothing,
            connect,
            switch_connect,
            resolve_backoff: ReconnectBackoff::new(0),
            snapshot,
            published: (ConnectionState::Idle, None),
            running_backchannel: false,
            restart: false,
            upgrade: None,
            switching: false,
            switch_failure: None,
        }
    }

    /// Runs until the registry drops the connection, then stops the worker
    /// within the shutdown budget.
    pub(crate) async fn run(mut self) {
        tracing::info!(spec = ?self.spec, "connection driver started");
        let initial = *self.demand.borrow_and_update();
        if initial > 0 {
            self.feed(Input::Demand(initial));
        }
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

    /// Waits for the next thing to happen.
    async fn wait(&mut self) -> Wake {
        let Self {
            demand,
            commands,
            worker,
            linger,
            crash,
            silence,
            pending,
            connect,
            switch_connect,
            ..
        } = self;
        tokio::select! {
            biased;
            changed = demand.changed() => {
                Wake::Demand(changed.ok().map(|()| *demand.borrow_and_update()))
            }
            event = next_worker_event(worker) => Wake::Worker(event),
            wake = connect.wait() => Wake::Connect(wake),
            wake = switch_connect.wait() => Wake::SwitchConnect(wake),
            Some(command) = commands.recv() => Wake::Command(command),
            () = timer(linger) => Wake::LingerExpired,
            () = timer(crash) => Wake::CrashBackoffExpired,
            () = timer(silence) => Wake::WorkerSilent,
            wake = pending.wait() => wake,
        }
    }

    /// Acts on what happened.
    async fn handle(&mut self, wake: Wake) {
        match wake {
            Wake::Demand(Some(demand)) => self.feed(Input::Demand(demand)),
            Wake::Demand(None)
            | Wake::Connect(SlotWake::LeaseExpired)
            | Wake::SwitchConnect(SlotWake::LeaseExpired) => {}
            Wake::Worker(event) => self.on_worker_event(event),
            Wake::Command(DriverCommand::SwitchSource(spec)) => self.on_switch_source(spec),
            Wake::Command(DriverCommand::Backchannel(spec)) => self.on_backchannel(spec),
            Wake::Command(command) => match (self.hold(command), self.worker.as_mut()) {
                (None, _) => {}
                (Some(command), Some(worker)) => {
                    Self::send(worker, &self.shared, &self.commands_tx, command).await;
                }
                (Some(command), None) => self.queue(command),
            },
            Wake::LingerExpired => {
                self.linger = None;
                self.feed(Input::LingerExpired);
            }
            Wake::CrashBackoffExpired => {
                self.crash = None;
                self.feed(Input::CrashBackoffExpired);
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
            Wake::RetryResolve => {
                self.pending = Pending::Nothing;
                self.feed(Input::Report(WorkerReport::Connecting));
                self.start_resolving();
            }
            Wake::SwitchResolved(_)
            | Wake::RetrySwitchResolve
            | Wake::SwitchConnect(SlotWake::Grant) => self.handle_switch(wake).await,
        }
        // Released from a hold while the worker runs: theirs now.
        if let Some(worker) = self.worker.as_mut() {
            for command in std::mem::take(&mut self.queued) {
                Self::send(worker, &self.shared, &self.commands_tx, command).await;
            }
        }
    }

    /// Acts on what happened to a switch in progress: the source to
    /// switch to resolved, or not, or the standby's attempt was granted.
    async fn handle_switch(&mut self, wake: Wake) {
        match wake {
            Wake::SwitchResolved(Ok(addrs)) => {
                self.pending = Pending::Nothing;
                self.resolve_backoff.reset();
                let restart = std::mem::take(&mut self.restart);
                if let Some(worker) = self.worker.as_mut() {
                    let spec = self.spec.source_spec(addrs);
                    let sent = if restart {
                        worker.restart_source(&spec).await
                    } else {
                        worker.switch_source(&spec).await
                    };
                    if let Err(err) = sent {
                        tracing::warn!(pid = worker.pid(), error = %err, restart, "source switch could not be sent to the worker");
                    }
                    self.running_backchannel = self.spec.backchannel;
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
                let error =
                    SourceError::Unreachable(format!("resolving {}: {message}", self.spec.host));
                self.end_upgrade(
                    UpgradeEnd::Failed,
                    &format!(
                        "the camera's backchannel could not be set up: {}: {error}",
                        error.code()
                    ),
                );
                let error = ConnectionError::Source(error);
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
    /// one, the next worker starts with it, and a lookup under way is
    /// started over for the new host.
    fn on_switch_source(&mut self, spec: DriverSpec) {
        tracing::info!(spec = ?spec, "connection switches its source");
        self.spec = spec;
        self.switching = true;
        self.switch_failure = None;
        self.snapshot.switches = self.snapshot.switches.wrapping_add(1);
        if self.worker.is_some() {
            self.start_resolving_switch();
        } else if matches!(self.pending, Pending::Resolving(_)) {
            self.start_resolving();
        }
    }

    /// `Backchannel`: the connection runs `spec` from now on, which differs
    /// from the last in whether it asks for the camera's backchannel
    /// (ONVIF Streaming Specification §5.3.1). A running source that does
    /// not ask while `spec` does is restarted once, through the switch
    /// path with the running source stopped first (`RestartSource`), so
    /// the camera holds one session at a time. One that asks while `spec`
    /// does not keeps the backchannel until the connection next connects
    /// with `spec`: a new worker, a crash's restart, a source switch.
    /// Without a worker, the next one starts with `spec`.
    fn on_backchannel(&mut self, spec: DriverSpec) {
        let before = self.running_backchannel;
        let after = spec.backchannel;
        self.spec = spec;
        match (self.worker.is_some(), before, after) {
            (true, false, true) => {
                tracing::info!(
                    backchannel.before = before,
                    backchannel.after = after,
                    reason = "a stream on the connection asks for the camera's backchannel",
                    "backchannel upgrade: restarting the source once; talk-back requests wait for it"
                );
                self.restart = true;
                self.upgrade.get_or_insert_with(Upgrade::default);
                self.start_resolving_switch();
            }
            (true, true, false) => tracing::info!(
                backchannel.before = before,
                backchannel.after = after,
                reason = "no stream on the connection asks for the camera's backchannel any more",
                "backchannel downgrade deferred to next connect"
            ),
            (true, ..) => tracing::debug!(
                backchannel = after,
                "the running source already asks for the backchannel as the connection's streams do"
            ),
            (false, ..) => tracing::info!(
                backchannel = after,
                "no worker runs; the next connect asks for the backchannel as the connection's streams do"
            ),
        }
    }

    /// Starts the host lookup of the source to switch to; the worker is
    /// told once it is done.
    fn start_resolving_switch(&mut self) {
        let host = self.spec.host.clone();
        let port = self.spec.port.unwrap_or(0);
        self.pending = Pending::ResolvingSwitch(Box::pin(async move {
            crate::resolve::resolve(&host, port).await
        }));
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
                tracing::info!(tracks = tracks.len(), "tracks declared");
                self.snapshot.tracks = tracks;
            }
            WorkerEvent::Stats(stats) => self.snapshot.stats = Some(stats),
            WorkerEvent::Session { session_id, event } => {
                let now = self.shared.clock.now();
                self.shared.lock().session_report(
                    &self.spec.connection_id,
                    &session_id,
                    event,
                    now,
                );
            }
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

    /// The standby source's report, its stop, or its taking over: its
    /// connect permit, the last error, and the end of a backchannel
    /// upgrade under way.
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
                WorkerReport::Backoff { error, retry_in } => {
                    self.switch_connect.release("standby backoff");
                    tracing::warn!(
                        error.code = error.code(),
                        error = %error,
                        retry_ms = u64::try_from(retry_in.as_millis()).unwrap_or(u64::MAX),
                        "the source to switch to failed; the old one keeps streaming"
                    );
                    self.end_upgrade(
                        UpgradeEnd::Failed,
                        &format!(
                            "the camera's backchannel could not be set up: {}: {error}",
                            error.code()
                        ),
                    );
                    let error = ConnectionError::Source(error);
                    self.snapshot.last_error = Some(error.clone());
                    self.switch_failure = Some(error);
                }
            },
            WorkerEvent::StandbyStopped => {
                self.switch_connect.release("standby stopped");
                self.end_upgrade(
                    UpgradeEnd::Failed,
                    "the source asking for the camera's backchannel stopped before it took over",
                );
            }
            WorkerEvent::Switched => {
                self.switch_connect.release("switched");
                self.snapshot.last_error = None;
                self.end_switch();
                tracing::info!("the tracks switched to the new source");
                self.end_upgrade(UpgradeEnd::Switched, "the new source took over");
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
        self.end_upgrade(
            UpgradeEnd::Failed,
            "the camera's worker process exited before its backchannel was set up",
        );
        self.worker = None;
        self.connect.release("worker exited");
        self.switch_connect.release("worker exited");
        self.snapshot.worker = None;
        self.talker_gone();
        self.queued.clear();
        // The old source and the standby went with the worker: the next
        // one runs the source switched to, and a crash is the failure an
        // offer meanwhile closes with.
        self.end_switch();
        let connection = self.spec.connection_id.clone();
        self.shared.lock().close_sessions_where(
            |session| session.connection == connection,
            "worker_crashed",
            "the camera's worker process exited",
            CloseBy::WorkerGone,
        );
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
                self.end_upgrade(UpgradeEnd::NextWorker, "the worker stopped");
                self.pending = Pending::Nothing;
                self.silence = None;
                self.connect.release("worker stopped");
                if let Some(worker) = self.worker.take() {
                    self.snapshot.worker = None;
                    self.talker_gone();
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
        }
    }

    /// Starts the host lookup; the worker follows once it is done.
    fn start_resolving(&mut self) {
        let host = self.spec.host.clone();
        let port = self.spec.port.unwrap_or(0);
        self.pending = Pending::Resolving(Box::pin(async move {
            crate::resolve::resolve(&host, port).await
        }));
    }

    /// Starts the worker and hands it the source; a failed start counts as
    /// a crash, so the machine retries with its backoff.
    async fn spawn_worker(&mut self, addrs: Vec<SocketAddr>) {
        let ports: Vec<u16> = self.spec.port.into_iter().collect();
        match self.shared.manager.spawn(&ports, self.spec.loopback_relay) {
            Ok(mut worker) => {
                let spec = self.spec.source_spec(addrs);
                self.running_backchannel = self.spec.backchannel;
                self.restart = false;
                if let Err(err) = worker.run_source(&spec).await {
                    tracing::warn!(pid = worker.pid(), error = %err, "source could not be sent to the worker");
                }
                self.snapshot.worker = Some(WorkerProcess {
                    pid: worker.pid(),
                    started: self.shared.clock.now(),
                    memory: None,
                });
                for command in std::mem::take(&mut self.queued) {
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

    /// Holds `command` while a backchannel upgrade is under way when it is
    /// a talk-back request of a stream that asked for the backchannel
    /// ([`requests_talk_back`]), or a later message of a held session; a
    /// close of a held session takes its messages out instead. Returns
    /// any other message, to go on as ever: sessions that request no
    /// talk-back are not delayed.
    fn hold(&mut self, command: DriverCommand) -> Option<DriverCommand> {
        let Some(upgrade) = self.upgrade.as_mut() else {
            return Some(command);
        };
        match command {
            DriverCommand::OpenSession(spec)
                if spec.talkback_required && requests_talk_back(&spec.offer) =>
            {
                tracing::info!(
                    session.id = %spec.session_id,
                    held = upgrade.sessions().len().saturating_add(1),
                    reason = "a talk-back request while the source restarts to ask for the camera's backchannel",
                    "talk-back request held until the backchannel upgrade ends"
                );
                upgrade.held.push(DriverCommand::OpenSession(spec));
                None
            }
            DriverCommand::CloseSession { session_id, .. } if upgrade.holds(&session_id) => {
                upgrade
                    .held
                    .retain(|held| held.session_id() != Some(session_id.as_str()));
                tracing::info!(
                    session.id = %session_id,
                    held = upgrade.sessions().len(),
                    "held talk-back request closed before the backchannel upgrade ended"
                );
                None
            }
            command
                if command
                    .session_id()
                    .is_some_and(|session_id| upgrade.holds(session_id)) =>
            {
                upgrade.held.push(command);
                None
            }
            command => Some(command),
        }
    }

    /// Ends the backchannel upgrade under way, if any, as `end` says, for
    /// `reason`: its held sessions go to the worker ([`UpgradeEnd::Switched`],
    /// sent once the wake is handled) or the next one
    /// ([`UpgradeEnd::NextWorker`]), or close with `backchannel_unavailable`
    /// ([`UpgradeEnd::Failed`]).
    fn end_upgrade(&mut self, end: UpgradeEnd, reason: &str) {
        let Some(upgrade) = self.upgrade.take() else {
            return;
        };
        let sessions: Vec<String> = upgrade.sessions().into_iter().map(str::to_owned).collect();
        match end {
            UpgradeEnd::Switched | UpgradeEnd::NextWorker => {
                tracing::info!(
                    outcome = ?end,
                    reason,
                    held = sessions.len(),
                    session.ids = ?sessions,
                    backchannel = self.running_backchannel,
                    "backchannel upgrade ended; held talk-back requests released"
                );
                self.queued.extend(upgrade.held);
            }
            UpgradeEnd::Failed => {
                tracing::warn!(
                    outcome = ?end,
                    reason,
                    held = sessions.len(),
                    session.ids = ?sessions,
                    "backchannel upgrade failed; held talk-back requests close with backchannel_unavailable"
                );
                let message = format!("two-way audio unavailable: {reason}");
                let mut state = self.shared.lock();
                for session_id in &sessions {
                    let _closed = state.close_session(
                        session_id,
                        BACKCHANNEL_UNAVAILABLE,
                        &message,
                        CloseBy::Supervisor,
                    );
                }
            }
        }
    }

    /// Holds a message until there is a worker. A close takes its session's
    /// messages out of the queue instead: the worker never saw it.
    fn queue(&mut self, command: DriverCommand) {
        match command {
            DriverCommand::CloseSession { session_id, .. } => {
                self.queued
                    .retain(|queued| queued.session_id() != Some(session_id.as_str()));
            }
            DriverCommand::IceTcp { peer, .. } => {
                tracing::debug!(%peer, "ice-tcp connection without a worker; closed");
            }
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

    /// Passes a message to `worker`. An offer is registered with the demux
    /// first, with a sink whose ICE-TCP hand-offs come back on `commands`,
    /// unless its session closed in the meantime.
    async fn send(
        worker: &mut Worker,
        shared: &Shared,
        commands: &mpsc::Sender<DriverCommand>,
        command: DriverCommand,
    ) {
        let session = command.session_id().map(str::to_owned);
        let sent = match command {
            // Handled by the driver itself, never queued for a worker.
            DriverCommand::SwitchSource(_) | DriverCommand::Backchannel(_) => return,
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

    /// The switch is over: the machine's reports are the current source's.
    fn end_switch(&mut self) {
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
        if let Some(upgrade) = self.upgrade.take()
            && !upgrade.held.is_empty()
        {
            // Nothing references the connection any more: its streams,
            // and their sessions, are gone.
            tracing::info!(
                held = upgrade.sessions().len(),
                session.ids = ?upgrade.sessions(),
                reason = "the connection stopped",
                "backchannel upgrade ended; held talk-back requests dropped"
            );
        }
        self.pending = Pending::Nothing;
        self.linger = None;
        self.crash = None;
        if let Some(worker) = self.worker.take() {
            let _status = worker
                .stop(self.shared.shutdown_budget, &self.shared.clock)
                .await;
        }
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
            talkback_required: false,
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
            url: "rtsps://admin:secret@cam/key?token=tok".into(),
            options: r#"{"onvif":{"url":"http://admin:secret@cam/onvif","profile_token":"p"}}"#
                .into(),
            host: "cam".into(),
            port: Some(322),
            loopback_relay: true,
            backchannel: false,
        };
        let logged = format!("{spec:?}");
        for secret in ["secret", "key", "tok"] {
            assert!(!logged.contains(secret), "{logged}");
        }
        assert!(logged.contains(r#"options: ["onvif"]"#), "{logged}");
        assert!(
            logged.contains("port: Some(322)") && logged.contains("loopback_relay: true"),
            "{logged}"
        );
    }

    #[test]
    fn the_spec_logs_its_option_names_without_their_values() {
        let spec = |options: &str| DriverSpec {
            connection_id: "c1".into(),
            url: "rtsp://cam/".into(),
            options: options.into(),
            host: "cam".into(),
            port: None,
            loopback_relay: false,
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = Driver::new(
            DriverSpec {
                connection_id: "c1".into(),
                url: "fake://h/".into(),
                options: "{}".into(),
                host: "h".into(),
                port: None,
                loopback_relay: false,
                backchannel: false,
            },
            shared("/bin/sh"),
            demand,
            mpsc::channel(4),
            ConnectionConfig::default(),
        );
        driver.queue(DriverCommand::OpenSession(spec("a")));
        driver.queue(candidate("a"));
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
        let mut worker = shared.manager.spawn(&[], false).unwrap();
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
                UNIX_EPOCH,
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
        let mut worker = shared.manager.spawn(&[], false).unwrap();
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
        // Each on the wire as its frame: the length, u32 little-endian,
        // then the message.
        let mut expected = Vec::new();
        for session_id in [None, Some("s1".to_owned())] {
            let message =
                lotse_ipc::encode(&lotse_ipc::ToWorker::ReleaseBackchannel { session_id }).unwrap();
            expected.extend(u32::try_from(message.len()).unwrap().to_le_bytes());
            expected.extend(message);
        }
        let mut received = Vec::new();
        for _ in 0..500 {
            received = std::fs::read(&out).unwrap_or_default();
            if received.ends_with(&expected) {
                break;
            }
            SystemClock.sleep(Duration::from_millis(10)).await;
        }
        assert!(received.ends_with(&expected), "{received:?}");
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
    }

    #[tokio::test]
    async fn sends_register_live_offers_only_and_survive_a_dead_worker() {
        let shared = shared("/usr/bin/true");
        let mut worker = shared.manager.spawn(&[], false).unwrap();
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
                UNIX_EPOCH,
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
        let (demand_tx, demand) = watch::channel(0);
        let (commands, _commands) = mpsc::channel(1);
        let (events, _events) = mpsc::channel(1);
        {
            let mut state = shared.lock();
            state.connections.insert(
                "c1".into(),
                crate::registry::ConnectionEntry {
                    port: None,
                    loopback_relay: false,
                    backchannel: false,
                    key: crate::registry::ConnectionKey {
                        url: lotse_core::source_url::SourceUrl::parse("fake://127.0.0.1/").unwrap(),
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
                        url: lotse_core::source_url::SourceUrl::parse("fake://127.0.0.1/").unwrap(),
                        options: serde_json::Map::new(),
                        protocol: "fake",
                        connection: "c1".into(),
                    }],
                    preload: false,
                    audio: lotse_api_types::stream::AudioMode::Auto,
                    orientation: lotse_api_types::stream::Orientation::NoTransform,
                    created: UNIX_EPOCH,
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
                    UNIX_EPOCH,
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
    fn driver_on(shared: &Arc<Shared>, demand: watch::Receiver<u32>) -> Driver {
        Driver::new(
            DriverSpec {
                connection_id: "c1".into(),
                url: "fake://127.0.0.1/".into(),
                options: "{}".into(),
                host: "127.0.0.1".into(),
                port: None,
                loopback_relay: false,
                backchannel: false,
            },
            Arc::clone(shared),
            demand,
            mpsc::channel(4),
            ConnectionConfig::default(),
        )
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
        let (demand_tx, demand) = watch::channel(0);
        let driver = &mut driver_on(&shared, demand);
        demand_tx.send_replace(1);
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
        assert_eq!(in_flight(), 1);
        demand_tx.send_replace(0);
        step(driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Idle);
        assert_eq!(in_flight(), 0, "a stopped worker gives it back");
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
            if messages.contains(want) {
                return messages;
            }
            assert!(attempt < 500, "never received {want:?}: {messages:?}");
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
        let (_demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        driver.worker = Some(shared.manager.spawn(&[], false).unwrap());
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
        let (_demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        let switch = |url: &str, host: &str| DriverSpec {
            connection_id: "c1".into(),
            url: url.into(),
            options: "{}".into(),
            host: host.into(),
            port: Some(1),
            loopback_relay: false,
            backchannel: false,
        };
        // Without a worker the spec is taken for the next one, nothing more.
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(switch(
                "fake://127.0.0.1:1/a",
                "127.0.0.1",
            ))))
            .await;
        assert_eq!(driver.spec.url, "fake://127.0.0.1:1/a");
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
        driver.worker = Some(shared.manager.spawn(&[], false).unwrap());
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
            url: "fake://127.0.0.1:1/c".into(),
            options: "{}".into(),
            peer_host: "127.0.0.1".into(),
            peer_addrs: vec!["127.0.0.1:1".parse().unwrap()],
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

    #[tokio::test]
    async fn a_backchannel_upgrade_restarts_the_running_source_once_and_a_downgrade_waits() {
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
        let (_demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        let spec = |options: &str, backchannel: bool| DriverSpec {
            connection_id: "c1".into(),
            url: "fake://127.0.0.1:1/".into(),
            options: options.into(),
            host: "127.0.0.1".into(),
            port: Some(1),
            loopback_relay: false,
            backchannel,
        };
        let source = |options: &str| SourceSpec {
            connection_id: "c1".into(),
            url: "fake://127.0.0.1:1/".into(),
            options: options.into(),
            peer_host: "127.0.0.1".into(),
            peer_addrs: vec!["127.0.0.1:1".parse().unwrap()],
        };
        let backchannel = |options: &str, asks: bool| {
            Wake::Command(DriverCommand::Backchannel(spec(options, asks)))
        };
        // Without a worker the next one starts with the spec, nothing more.
        driver.handle(backchannel(r#"{"talk":true}"#, true)).await;
        assert!(driver.spec.backchannel);
        assert!(ready_wake(&mut driver).await.is_none(), "nothing pending");
        assert_eq!(captured.lines("no worker runs").len(), 1);
        assert!(driver.upgrade.is_none(), "nothing to hold without a worker");
        driver
            .spawn_worker(vec!["127.0.0.1:1".parse().unwrap()])
            .await;
        recorded(
            &out,
            &lotse_ipc::ToWorker::RunSource(source(r#"{"talk":true}"#)),
        )
        .await;
        // A source that asks keeps the backchannel when no stream asks any
        // more, until the connection next connects (downgrade deferred);
        // asked again meanwhile, it still has it.
        driver.handle(backchannel("{}", false)).await;
        assert!(!driver.spec.backchannel, "the next connect's");
        assert!(ready_wake(&mut driver).await.is_none(), "no reconnect");
        let deferred = captured.lines("backchannel downgrade deferred to next connect");
        assert_eq!(deferred.len(), 1);
        for field in ["backchannel.before=true", "backchannel.after=false"] {
            assert!(deferred[0].contains(field), "{field}: {deferred:?}");
        }
        driver.handle(backchannel(r#"{"talk":true}"#, true)).await;
        assert!(ready_wake(&mut driver).await.is_none(), "it asks already");
        // The next connect, a source switch, runs the spec as it is then.
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(spec(
                "{}", false,
            ))))
            .await;
        step(&mut driver).await;
        recorded(&out, &lotse_ipc::ToWorker::SwitchSource(source("{}"))).await;
        // Now a stream asks: the running source restarts once, through the
        // switch path with the old source stopped first (upgrade).
        driver.handle(backchannel(r#"{"talk":true}"#, true)).await;
        assert!(matches!(driver.pending, Pending::ResolvingSwitch(_)));
        assert_eq!(
            captured
                .lines("backchannel upgrade: restarting the source once")
                .len(),
            1
        );
        step(&mut driver).await;
        let restart = lotse_ipc::ToWorker::RestartSource(source(r#"{"talk":true}"#));
        recorded(&out, &restart).await;
        // Asked again, it asks already; a later switch is a plain one.
        driver.handle(backchannel(r#"{"talk":true}"#, true)).await;
        assert!(ready_wake(&mut driver).await.is_none(), "restarted once");
        driver
            .handle(Wake::Command(DriverCommand::SwitchSource(spec(
                r#"{"talk":true}"#,
                true,
            ))))
            .await;
        step(&mut driver).await;
        let switch = lotse_ipc::ToWorker::SwitchSource(source(r#"{"talk":true}"#));
        let messages = recorded(&out, &switch).await;
        assert_eq!(
            messages.iter().filter(|m| **m == restart).count(),
            1,
            "{messages:?}"
        );
        let worker = driver.worker.take().unwrap();
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        drop(driver);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An offer that requests talk-back on a dedicated `sendonly` audio
    /// m-line, as a talk-back capable frontend offers it.
    const TALK_BACK_OFFER: &str = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:0\r\na=recvonly\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=recvonly\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:2\r\na=sendonly\r\n";

    #[test]
    fn rfc8866_6_7_an_offer_requests_talk_back_with_an_audio_m_line_it_sends_on() {
        assert!(requests_talk_back(TALK_BACK_OFFER), "sendonly");
        assert!(requests_talk_back(
            "v=0\nm=audio 9 x 0\na=mid:a\na=sendrecv\n"
        ));
        // No direction attribute is `sendrecv`, in the last section too.
        assert!(requests_talk_back("v=0\r\nm=audio 9 x 0\r\na=mid:a\r\n"));
        assert!(requests_talk_back(
            "v=0\r\nm=audio 9 x 0\r\na=mid:a\r\nm=video 9 x 96\r\na=mid:v\r\na=recvonly\r\n"
        ));
        for (offer, why) in [
            (
                "v=0\r\nm=audio 9 x 0\r\na=mid:a\r\na=recvonly\r\n",
                "receives only",
            ),
            (
                "v=0\r\nm=audio 9 x 0\r\na=mid:a\r\na=inactive\r\nm=video 9 x 96\r\na=mid:v\r\na=sendrecv\r\n",
                "only video sends",
            ),
            (
                "v=0\r\nm=audio 9 x 0\r\na=sendonly\r\n",
                "no mid (RFC 5888 §4)",
            ),
            (
                "v=0\r\nm=audio 9 x 0\r\na=recvonly\r\na=mid:a\r\na=sendonly\r\n",
                "the first direction attribute counts",
            ),
            (
                "v=0\r\na=sendrecv\r\na=mid:x\r\n",
                "session-level lines are no section",
            ),
            ("v=0\r\nm=audiox 9 x 0\r\na=mid:a\r\n", "not audio"),
            ("", "empty"),
        ] {
            assert!(!requests_talk_back(offer), "{why}");
        }
    }

    /// `spec(id)` with an offer that requests talk-back, on a stream that
    /// asked for the backchannel.
    fn talk_spec(session_id: &str) -> SessionSpec {
        SessionSpec {
            offer: TALK_BACK_OFFER.into(),
            talkback_required: true,
            ..spec(session_id)
        }
    }

    /// Opens `ids` on the registry, as the handler does with their offers;
    /// each session's events' receiving end.
    fn open_sessions(shared: &Shared, ids: &[&str]) -> Vec<mpsc::Receiver<lotse_api::Event>> {
        ids.iter()
            .map(|id| {
                let (events, rx) = mpsc::channel(8);
                shared.lock().sessions.insert(
                    (*id).to_owned(),
                    SessionEntry::new(
                        1,
                        "front".into(),
                        "c1".into(),
                        format!("u{id}"),
                        (ConnectionId(1), 1, events),
                        UNIX_EPOCH,
                    ),
                );
                rx
            })
            .collect()
    }

    /// The `closed` event `events` got, as `(code, message)`.
    fn closed(events: &mut mpsc::Receiver<lotse_api::Event>) -> (String, String) {
        let event = events.try_recv().expect("a closed event").payload;
        assert_eq!(event["type"], "closed", "{event}");
        (
            event["code"].as_str().unwrap().to_owned(),
            event["message"].as_str().unwrap().to_owned(),
        )
    }

    /// The driver's spec with the backchannel asked for.
    fn asking() -> DriverCommand {
        DriverCommand::Backchannel(DriverSpec {
            backchannel: true,
            ..spec_of("fake://127.0.0.1:1/")
        })
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "the hold's life, message by message")]
    async fn onvif_5_3_1_a_talk_back_request_waits_for_the_backchannel_upgrade_and_opens_on_the_new_source()
     {
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let dir = private_dir("driver-hold");
        let out = dir.join("received");
        let shared = shared(&worker_script(
            &dir,
            &format!("exec cat > {}", out.display()),
        ));
        let (_demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        let _events = open_sessions(&shared, &["talk", "plain", "other", "gone", "late"]);
        driver.worker = Some(shared.manager.spawn(&[], false).unwrap());
        let command = |command| Wake::Command(command);
        driver.handle(command(asking())).await;
        assert!(driver.upgrade.is_some());
        // A talk-back request of a stream that asked for the backchannel
        // waits, with its later messages; the rest go on: an offer without
        // talk-back, one of a stream that did not ask, a close of a session
        // not held.
        driver
            .handle(command(DriverCommand::OpenSession(talk_spec("talk"))))
            .await;
        driver.handle(command(candidate("talk"))).await;
        let plain = SessionSpec {
            talkback_required: true,
            ..spec("plain")
        };
        driver
            .handle(command(DriverCommand::OpenSession(plain.clone())))
            .await;
        let other = SessionSpec {
            talkback_required: false,
            ..talk_spec("other")
        };
        driver
            .handle(command(DriverCommand::OpenSession(other.clone())))
            .await;
        // A held session that closes leaves the hold.
        driver
            .handle(command(DriverCommand::OpenSession(talk_spec("gone"))))
            .await;
        driver
            .handle(command(DriverCommand::CloseSession {
                session_id: "gone".into(),
                code: "session_closed",
                message: String::new(),
            }))
            .await;
        assert_eq!(
            captured
                .lines("held talk-back request closed before the backchannel upgrade ended")
                .len(),
            1
        );
        let close_plain = lotse_ipc::ToWorker::CloseSession {
            session_id: "plain".into(),
            code: "session_closed".into(),
            message: String::new(),
        };
        driver
            .handle(command(DriverCommand::CloseSession {
                session_id: "plain".into(),
                code: "session_closed",
                message: String::new(),
            }))
            .await;
        assert_eq!(driver.upgrade.as_ref().unwrap().sessions(), ["talk"]);
        let held = captured.lines("talk-back request held until the backchannel upgrade ends");
        assert_eq!(held.len(), 2, "{held:?}");
        assert!(
            held[0].contains("session.id=talk") && held[0].contains("held=1"),
            "{held:?}"
        );
        let messages = recorded(&out, &close_plain).await;
        let opened = |messages: &[lotse_ipc::ToWorker]| -> Vec<String> {
            messages
                .iter()
                .filter_map(|m| match m {
                    lotse_ipc::ToWorker::OpenSession(spec) => Some(spec.session_id.clone()),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(opened(&messages), ["plain", "other"]);
        // The restart goes out; the new source takes over, and the held
        // offer reaches the worker with its candidate, in order.
        step(&mut driver).await;
        driver.handle(Wake::Worker(WorkerEvent::Switched)).await;
        assert!(driver.upgrade.is_none() && driver.queued.is_empty());
        let talk_candidate = lotse_ipc::ToWorker::RemoteCandidate {
            session_id: "talk".into(),
            candidate: String::new(),
        };
        let messages = recorded(&out, &talk_candidate).await;
        assert_eq!(opened(&messages), ["plain", "other", "talk"]);
        let restart = messages
            .iter()
            .position(|m| matches!(m, lotse_ipc::ToWorker::RestartSource(_)))
            .unwrap();
        let talk = messages
            .iter()
            .position(|m| *m == lotse_ipc::ToWorker::OpenSession(talk_spec("talk")))
            .unwrap();
        assert!(restart < talk, "{messages:?}");
        assert_eq!(messages.last(), Some(&talk_candidate));
        let released = captured.lines("held talk-back requests released");
        for field in [
            "outcome=Switched",
            "held=1",
            r#"session.ids=["talk"]"#,
            "backchannel=true",
        ] {
            assert!(released[0].contains(field), "{field}: {released:?}");
        }
        // Once it ended, a talk-back request goes on at once.
        driver
            .handle(command(DriverCommand::OpenSession(talk_spec("late"))))
            .await;
        let late = lotse_ipc::ToWorker::OpenSession(talk_spec("late"));
        recorded(&out, &late).await;
        let worker = driver.worker.take().unwrap();
        let _status = worker.stop(Duration::from_millis(200), &shared.clock).await;
        drop(driver);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn onvif_5_3_1_every_failed_end_of_a_backchannel_upgrade_closes_its_held_talk_back_requests()
     {
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (_demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        let failures: [(&str, WorkerEvent, &str); 3] = [
            (
                "backoff",
                WorkerEvent::SwitchReport(WorkerReport::Backoff {
                    error: SourceError::AuthFailed("401 Unauthorized".into()),
                    retry_in: Duration::from_secs(1),
                }),
                "two-way audio unavailable: the camera's backchannel could not be set up: source_auth_failed: source authentication failed: 401 Unauthorized",
            ),
            (
                "stopped",
                WorkerEvent::StandbyStopped,
                "two-way audio unavailable: the source asking for the camera's backchannel stopped before it took over",
            ),
            (
                "exited",
                WorkerEvent::Exited(ExitStatus::from_raw(9)),
                "two-way audio unavailable: the camera's worker process exited before its backchannel was set up",
            ),
        ];
        for (id, failure, message) in failures {
            let mut events = open_sessions(&shared, &[id]);
            driver.worker = Some(dead_worker(&shared).await);
            driver.handle(Wake::Command(asking())).await;
            driver
                .handle(Wake::Command(DriverCommand::OpenSession(talk_spec(id))))
                .await;
            driver.on_worker_event(failure);
            assert!(driver.upgrade.is_none(), "{id}");
            assert!(!shared.lock().sessions.contains_key(id), "{id}");
            assert_eq!(
                closed(&mut events[0]),
                ("backchannel_unavailable".to_owned(), message.to_owned()),
                "{id}"
            );
        }
        // The host of the source to switch to does not resolve.
        let mut events = open_sessions(&shared, &["unresolved"]);
        driver.worker = Some(dead_worker(&shared).await);
        driver.handle(Wake::Command(asking())).await;
        driver
            .handle(Wake::Command(DriverCommand::OpenSession(talk_spec(
                "unresolved",
            ))))
            .await;
        driver
            .handle(Wake::SwitchResolved(Err("no such host".into())))
            .await;
        let (code, message) = closed(&mut events[0]);
        assert_eq!(code, "backchannel_unavailable");
        assert!(
            message.starts_with(
                "two-way audio unavailable: the camera's backchannel could not be set up: source_unreachable: "
            ) && message.ends_with("resolving 127.0.0.1: no such host"),
            "{message}"
        );
        let failed = captured.lines("backchannel upgrade failed");
        assert_eq!(failed.len(), 4, "{failed:?}");
        assert!(
            failed[0].contains(r#"session.ids=["backoff"]"#),
            "{failed:?}"
        );
        // A worker that stops leaves them to the next, which asks for the
        // backchannel from the start.
        driver.pending = Pending::Nothing;
        let _events = open_sessions(&shared, &["next"]);
        driver.handle(Wake::Command(asking())).await;
        driver
            .handle(Wake::Command(DriverCommand::OpenSession(talk_spec("next"))))
            .await;
        assert!(matches!(
            driver.perform(Action::StopWorker),
            Some(Input::WorkerExited)
        ));
        assert!(driver.upgrade.is_none() && driver.worker.is_none());
        let queued: Vec<Option<&str>> = driver
            .queued
            .iter()
            .map(DriverCommand::session_id)
            .collect();
        assert_eq!(queued, [Some("next")]);
        assert_eq!(captured.lines("outcome=NextWorker").len(), 1);
        // Nothing else is a standby's; an end without an upgrade is no end.
        driver.on_standby_event(WorkerEvent::SourceStopped);
        driver.on_worker_event(WorkerEvent::Switched);
        assert_eq!(captured.lines("backchannel upgrade ended").len(), 1);
        drop(driver);
        shared.tracker.close();
        while !shared.tracker.is_empty() {
            clock.advance(shared.shutdown_budget);
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
    }

    /// A connection that stops drops the talk-back requests it holds:
    /// nothing references it any more, so their sessions are gone.
    #[tokio::test]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "`stop_all` consumes the driver, a move the lint does not see"
    )]
    async fn a_connection_that_stops_drops_the_talk_back_requests_it_holds() {
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        let shared = shared("/usr/bin/true");
        let (_demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        let _events = open_sessions(&shared, &["dropped"]);
        driver.worker = Some(dead_worker(&shared).await);
        driver.handle(Wake::Command(asking())).await;
        driver
            .handle(Wake::Command(DriverCommand::OpenSession(talk_spec(
                "dropped",
            ))))
            .await;
        drop(driver.worker.take());
        driver.stop_all().await;
        let dropped = captured.lines("held talk-back requests dropped");
        assert!(
            dropped[0].contains(r#"session.ids=["dropped"]"#),
            "{dropped:?}"
        );
    }

    #[tokio::test]
    async fn a_standby_s_attempts_hold_their_own_connect_permit() {
        let shared = shared("/usr/bin/true");
        let in_flight = || shared.connects.in_flight();
        let (_demand_tx, demand) = watch::channel(0);
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
        let (_demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        let mut worker = shared.manager.spawn(&[], false).unwrap();
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
        let (demand_tx, demand) = watch::channel(0);
        let mut owned = driver_on(&shared, demand);
        let driver = &mut owned;
        demand_tx.send_replace(1);
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(1);
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
        demand_tx.send_replace(0);
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Idle);
        assert!(driver.silence.is_none());
        drop((driver, demand_tx));
        wind_down(&shared, &clock, dir).await;
    }

    /// A worker that has exited, as the driver still holds it.
    async fn dead_worker(shared: &Shared) -> Worker {
        let mut worker = shared.manager.spawn(&[], false).unwrap();
        while !matches!(worker.next_event().await, WorkerEvent::Exited(_)) {}
        worker
    }

    fn spec_of(url: &str) -> DriverSpec {
        DriverSpec {
            connection_id: "c1".into(),
            url: url.into(),
            options: "{}".into(),
            host: "127.0.0.1".into(),
            port: Some(1),
            loopback_relay: false,
            backchannel: false,
        }
    }

    #[tokio::test]
    async fn a_failed_lookup_is_a_backoff_and_retried_on_the_clock() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(1);
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
    async fn a_switch_whose_lookup_fails_waits_on_the_clock_and_a_dead_worker_is_not_told() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/usr/bin/true", clock.clone());
        let (_demand_tx, demand) = watch::channel(0);
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
        // Nothing else is a switch's to handle.
        driver.handle_switch(Wake::LingerExpired).await;
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
        let (_demand_tx, demand) = watch::channel(0);
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
            clock_rate: 90_000,
            sync: "arrival".into(),
            derived_from: None,
            audio_delay_ms: None,
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

    #[tokio::test]
    async fn a_worker_that_cannot_start_counts_as_a_crash() {
        let clock = Arc::new(FakeClock::from_system());
        let shared = shared_with("/nonexistent/lotse", clock.clone());
        let (demand_tx, demand) = watch::channel(0);
        let mut owned = driver_on(&shared, demand);
        let driver = &mut owned;
        demand_tx.send_replace(1);
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
                    url: url.clone(),
                    options: serde_json::Map::new(),
                    protocol: "fake",
                    connection: "c1".into(),
                }],
                preload: false,
                audio: AudioMode::Auto,
                orientation: Orientation::NoTransform,
                created: UNIX_EPOCH,
            },
        );
        state.connections.insert(
            "c1".into(),
            ConnectionEntry {
                key: ConnectionKey {
                    url,
                    options: serde_json::json!({}),
                },
                port: None,
                loopback_relay: false,
                backchannel: false,
                demand: watch::channel(1).0,
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
                UNIX_EPOCH,
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = Driver::new(
            DriverSpec {
                connection_id: "c1".into(),
                url: "fake://admin:hunter2@cam.example/".into(),
                options: "{}".into(),
                host: "cam.example".into(),
                port: None,
                loopback_relay: false,
                backchannel: false,
            },
            Arc::clone(&shared),
            demand,
            mpsc::channel(4),
            ConnectionConfig::default(),
        );
        let mut events = waiting_session(&shared, "fake://admin:hunter2@cam.example/");
        demand_tx.send_replace(1);
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        let mut events = waiting_session(&shared, "fake://127.0.0.1/");
        demand_tx.send_replace(1);
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        let mut events = waiting_session(&shared, "fake://127.0.0.1/");
        demand_tx.send_replace(1);
        step(&mut driver).await;
        let on = |driver: &mut Driver, event| {
            driver.on_worker_event(event);
            driver.publish();
        };
        let backoff = |error| WorkerReport::Backoff {
            error,
            retry_in: Duration::from_secs(1),
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(1);
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(1);
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        demand_tx.send_replace(1);
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = driver_on(&shared, demand);
        // Over the channel's message limit: the send fails before a write.
        driver.spec.url = format!("fake://127.0.0.1/{}", "x".repeat(300 * 1024));
        demand_tx.send_replace(1);
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
        let (_demand_tx, demand) = watch::channel(0);
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
        let (demand_tx, demand) = watch::channel(0);
        let mut driver = Driver::new(
            DriverSpec {
                connection_id: "c1".into(),
                url: "fake://127.0.0.1/".into(),
                options: "{}".into(),
                host: "127.0.0.1".into(),
                port: None,
                loopback_relay: false,
                backchannel: false,
            },
            Arc::clone(&shared),
            demand,
            mpsc::channel(4),
            ConnectionConfig {
                linger,
                ..ConnectionConfig::default()
            },
        );
        // `preload: true` is demand without a viewer: the worker starts.
        demand_tx.send_replace(1);
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
        demand_tx.send_replace(0);
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Draining);
        clock.advance(almost);
        assert!(ready_wake(&mut driver).await.is_none(), "still lingering");
        // A viewer within the linger takes the warm worker.
        demand_tx.send_replace(1);
        step(&mut driver).await;
        assert_eq!(driver.machine.state(), ConnectionState::Live);
        assert!(driver.linger.is_none(), "the linger is cancelled");
        assert_eq!(driver.snapshot.worker.as_ref().map(|w| w.pid), Some(pid));
        // It leaves; this time the linger runs out and the worker stops.
        demand_tx.send_replace(0);
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
}
