//! Supervisor process: stream registry and desired state, worker manager
//! (spawn, crash backoff), host resolution, the control API handler with
//! the viewer sessions' signaling (offer, trickle, orphaning and adoption),
//! the UDP receive and demux, ICE-TCP accept and srflx gathering with the
//! STUN client, the TURN client (the codec, the long-term credential and
//! the shared allocations over UDP and TCP, whose servers' relayed
//! datagrams the demux or the TCP allocation's task unwraps as the peers',
//! and the TCP allocations' writing of what workers frame); later snapshot
//! orchestration.
//!
//! The network front door. Parses no camera bytes: only JSON, STUN, TURN
//! and `ChannelData`, RFC 4571 framing and IPC, all fuzzed. Implements the
//! `lotse-api` handler trait and converts `lotse-core` state into
//! `lotse-api-types` DTOs. The binary binds
//! the control socket with [`bind`] before the sandbox, hands over the
//! resolved [`Settings`] and the [`Environment`], and [`run`] owns the
//! runtime until a shutdown signal.
//!
//! Standards: RFC 8489 (with Errata 6268 and 6290), RFC 8656, RFC 7983, RFC 4648 §4,
//! RFC 4571, RFC 6544, RFC 8445 §5.1 and §7.2.5.2.1, RFC 8839 §5.1 and §5.4, RFC 8866 §5
//! and §9, RFC 5888 §4, RFC 3542 §6.1,
//! RFC 4291 §2.5.1 and §2.5.5.2, RFC 6724 §5, RFC 7064, RFC 7065, the ULID spec,
//! `getaddrinfo(3)`, `getifaddrs(3)`.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::{Clock, SystemClock};
use lotse_core::task::spawn_named;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

mod connect;
mod driver;
mod gather;
mod handler;
pub mod memory;
pub mod net;
mod registry;
mod resolve;
mod session;
pub mod worker;
mod worker_text;

pub use handler::{Environment, FrontDoor, Identity, Supervisor};
pub use lotse_api::Server as ApiServer;

use crate::net::demux::Demux;
use crate::net::tcp::{IceTcpConfig, IceTcpStats};
use crate::net::udp::BoundUdp;

/// The control API's handler types, for driving a [`Supervisor`] in-process
/// without the socket (the binary's tests; only the supervisor links
/// `lotse-api`).
pub mod api {
    pub use lotse_api::{ConnectionId, Event, EventClass, Handler, Outcome};
}

/// The shutdown budget: after it the supervisor kills its workers and exits.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

/// Default of `sources.connect_concurrency`: four connection attempts at
/// once.
pub const DEFAULT_CONNECT_CONCURRENCY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(3);

/// Runtime threads for the control plane.
pub const RUNTIME_THREADS: usize = 2;

/// The limits from `limits.*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Control connections.
    pub max_connections: u32,
    /// Streams.
    pub max_streams: u32,
    /// Sessions in total.
    pub max_sessions: u32,
    /// Sessions per stream.
    pub max_sessions_per_stream: u32,
    /// How long an orphaned session outlives its control connection.
    pub session_grace: Duration,
    /// Tokio threads per worker.
    pub worker_threads: usize,
    /// `RLIMIT_AS` per worker.
    pub worker_address_space: u64,
}

/// The supervisor's effective settings, resolved by the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The control socket path.
    pub socket: PathBuf,
    /// The uid the daemon started as: owns the socket directory and may
    /// always connect.
    pub owner_uid: u32,
    /// The peer uid allowed on the control socket.
    pub allow_uid: u32,
    /// The shared WebRTC UDP socket.
    pub udp_listen: SocketAddr,
    /// The ICE-TCP listener, or `None` for `off`.
    pub tcp_listen: Option<SocketAddr>,
    /// The limits.
    pub limits: Limits,
    /// `stream.linger`.
    pub linger: Duration,
    /// `sources.connect_concurrency`: source connection attempts at once,
    /// across the daemon.
    pub connect_concurrency: NonZeroUsize,
    /// The shutdown budget.
    pub shutdown_budget: Duration,
}

/// Why the supervisor is shutting down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// `SIGTERM`, as a service manager or container runtime sends it.
    Sigterm,
    /// `SIGINT`, from a terminal.
    Sigint,
    /// Asked for in-process (tests).
    Requested,
}

impl ShutdownReason {
    /// The name in the logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sigterm => "sigterm",
            Self::Sigint => "sigint",
            Self::Requested => "requested",
        }
    }
}

/// Why a socket could not be bound.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// The control socket.
    #[error("control socket: {0}")]
    Control(#[from] lotse_api::BindError),
    /// The shared WebRTC UDP socket.
    #[error("webrtc udp socket {addr}: {source}")]
    Udp {
        /// The address asked for.
        addr: SocketAddr,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The ICE-TCP listener.
    #[error("ice-tcp listener {addr}: {source}")]
    Tcp {
        /// The address asked for.
        addr: SocketAddr,
        /// The error.
        #[source]
        source: io::Error,
    },
}

/// Everything bound before the privilege drop.
#[derive(Debug)]
pub struct Listeners {
    /// The control socket.
    pub api: ApiServer,
    /// The shared WebRTC UDP socket.
    pub udp: BoundUdp,
    /// The ICE-TCP listener, unless `off`.
    pub tcp: Option<std::net::TcpListener>,
}

/// Why the supervisor could not run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The tokio runtime did not start.
    #[error("runtime failed to start: {0}")]
    Runtime(#[source] io::Error),
    /// A signal handler did not install.
    #[error("signal handler failed to install: {0}")]
    Signals(#[source] io::Error),
    /// The demux thread or the ICE-TCP listener could not start.
    #[error("network front door: {0}")]
    FrontDoor(#[source] io::Error),
}

/// Binds the WebRTC UDP socket, the ICE-TCP listener and the control
/// socket (with the development listener) in the calling thread, before
/// the privilege drop.
pub fn bind(settings: &Settings) -> Result<Listeners, BindError> {
    let udp = net::udp::bind_udp(settings.udp_listen).map_err(|source| BindError::Udp {
        addr: settings.udp_listen,
        source,
    })?;
    let tcp = match settings.tcp_listen {
        Some(addr) => {
            Some(net::udp::bind_tcp(addr).map_err(|source| BindError::Tcp { addr, source })?)
        }
        None => None,
    };
    let api = ApiServer::bind(lotse_api::Config {
        socket: settings.socket.clone(),
        owner_uid: settings.owner_uid,
        allow_uid: settings.allow_uid,
        max_connections: settings.limits.max_connections,
        // One per session, one `stream/subscribe` per stream and one for
        // every stream: the cap never refuses what the other limits allow.
        max_subscriptions: settings
            .limits
            .max_sessions
            .saturating_add(settings.limits.max_streams)
            .saturating_add(1),
    })?;
    Ok(Listeners { api, udp, tcp })
}

/// Serves until `shutdown` resolves, then tears down in order (stop
/// accepting, stop the workers within the budget, wait) and returns the
/// reason. The `ready` event is the deployment's cue that the daemon is up,
/// next to the first `hello` on the control socket.
pub async fn serve(
    settings: &Settings,
    listeners: Listeners,
    mut environment: Environment,
    clock: Arc<dyn Clock>,
    shutdown: impl Future<Output = ShutdownReason> + Send,
) -> Result<ShutdownReason, Error> {
    let Listeners {
        api: server,
        udp,
        tcp,
    } = listeners;
    let udp_local = udp.local;
    let demux = Demux::start(
        Arc::clone(&udp.socket),
        udp.local,
        udp.hosts.clone(),
        Arc::clone(&clock),
    )
    .map_err(Error::FrontDoor)?;
    environment.udp = Some(Arc::clone(&udp.socket));
    let tcp_local = tcp.as_ref().and_then(|l| l.local_addr().ok());
    environment.front_door = Some(front_door(&udp, tcp_local, &demux, &clock));
    let supervisor = Arc::new(Supervisor::new(
        settings.clone(),
        environment,
        Arc::clone(&clock),
    ));
    let cancel = CancellationToken::new();
    let tcp_stats = Arc::new(IceTcpStats::default());
    let tcp_loop = match tcp {
        Some(listener) => {
            let listener = tokio::net::TcpListener::from_std(listener).map_err(Error::FrontDoor)?;
            Some(spawn_named(
                "ice_tcp.accept",
                net::tcp::accept_loop(
                    listener,
                    demux.registrations(),
                    IceTcpConfig::default(),
                    Arc::clone(&clock),
                    Arc::clone(&tcp_stats),
                    cancel.clone(),
                ),
            ))
        }
        None => None,
    };
    let api = spawn_named(
        "api.server",
        server.serve(Arc::clone(&supervisor), Arc::clone(&clock), cancel.clone()),
    );
    tracing::info!(
        event = "ready",
        socket = %settings.socket.display(),
        udp_listen = %udp_local,
        udp_dual_stack = udp.dual_stack,
        udp_recv_buffer = udp.recv_buffer,
        udp_send_buffer = udp.send_buffer,
        udp_hosts = ?udp.hosts,
        tcp_listen = ?tcp_local,
        max_streams = settings.limits.max_streams,
        max_sessions = settings.limits.max_sessions,
        linger_ms = millis(settings.linger),
        "supervisor ready"
    );
    let reason = shutdown.await;
    tracing::info!(
        reason = reason.name(),
        budget_ms = millis(settings.shutdown_budget),
        "shutting down"
    );
    // Sessions first, so their `closed` events go out with the goodbye.
    supervisor.close_sessions();
    cancel.cancel();
    supervisor.shutdown().await;
    if let Some(tcp_loop) = tcp_loop {
        let _stopped = tcp_loop.await;
    }
    let stats = demux.stats();
    tracing::info!(
        received = net::demux::DemuxStats::get(&stats.received),
        forwarded = net::demux::DemuxStats::get(&stats.forwarded),
        unroutable = net::demux::DemuxStats::get(&stats.unroutable),
        stun_rejected = net::demux::DemuxStats::get(&stats.stun_rejected),
        relayed = net::demux::DemuxStats::get(&stats.relayed),
        relay_discarded = net::demux::DemuxStats::get(&stats.relay_discarded),
        ice_tcp_accepted = IceTcpStats::get(&tcp_stats.accepted),
        ice_tcp_handed_off = IceTcpStats::get(&tcp_stats.handed_off),
        ice_tcp_over_budget = IceTcpStats::get(&tcp_stats.over_budget),
        "front door stopping"
    );
    let _joined = lotse_core::task::spawn_blocking_named("demux.stop", move || demux.stop()).await;
    api_stopped(api, clock.as_ref(), settings.shutdown_budget).await;
    tracing::info!(reason = reason.name(), "supervisor stopped");
    Ok(reason)
}

/// Waits up to `budget` for the control API server's task to end, and
/// logs it when the server failed, the task did, or the budget ran out.
async fn api_stopped(
    api: tokio::task::JoinHandle<Result<(), lotse_api::ServeError>>,
    clock: &dyn Clock,
    budget: Duration,
) {
    tokio::select! {
        result = api => match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(error = %err, "control API server failed"),
            Err(err) => tracing::error!(error = %err, "control API task failed"),
        },
        () = clock.sleep(budget) => {
            tracing::warn!("control API connections missed the shutdown budget");
        }
    }
}

/// What sessions need from the front door: the demux's registrations, the
/// host addresses for UDP and ICE-TCP, and a STUN and a TURN client on the
/// shared socket.
fn front_door(
    udp: &BoundUdp,
    tcp_local: Option<SocketAddr>,
    demux: &Demux,
    clock: &Arc<dyn Clock>,
) -> FrontDoor {
    FrontDoor {
        registrations: demux.registrations(),
        hosts: udp.hosts.clone(),
        tcp_hosts: tcp_hosts(&udp.hosts, tcp_local),
        stun: Some(Arc::new(net::stun_client::StunClient::new(
            Arc::clone(&udp.socket),
            demux.responses(),
            Arc::clone(clock),
            net::stun_client::StunClientConfig::default(),
        ))),
        turn: Some(Arc::new(net::turn_client::TurnClient::new(
            Arc::clone(&udp.socket),
            demux,
            Arc::clone(clock),
            net::allocation::AllocationConfig::default(),
        ))),
        demux: Some(demux.stats()),
    }
}

/// The passive ICE-TCP candidates' addresses: the listener's own address
/// when it names one, else each host address at the listener's port;
/// none with the listener off.
fn tcp_hosts(hosts: &[SocketAddr], listener: Option<SocketAddr>) -> Vec<SocketAddr> {
    match listener {
        None => Vec::new(),
        Some(local) if !local.ip().is_unspecified() => {
            vec![SocketAddr::new(local.ip().to_canonical(), local.port())]
        }
        Some(local) => hosts
            .iter()
            .filter(|host| local.is_ipv6() || host.is_ipv4())
            .map(|host| SocketAddr::new(host.ip(), local.port()))
            .collect(),
    }
}

/// Builds the control-plane runtime, installs the signal handlers and
/// serves until `SIGTERM` or `SIGINT`. Blocks the calling thread; the
/// sockets must be bound and the sandbox applied.
pub fn run(
    settings: &Settings,
    listeners: Listeners,
    environment: Environment,
) -> Result<ShutdownReason, Error> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(RUNTIME_THREADS)
        .thread_name("lotse-supervisor")
        .enable_all()
        .build()
        .map_err(Error::Runtime)?;
    let process = tracing::info_span!("process", kind = "supervisor", pid = std::process::id());
    let reason = runtime.block_on(
        async {
            let signals = signals()?;
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            serve(settings, listeners, environment, clock, signals).await
        }
        .instrument(process),
    )?;
    runtime.shutdown_timeout(settings.shutdown_budget);
    Ok(reason)
}

/// Milliseconds as a `u64`, which log fields carry natively (`u128` would
/// print as a string).
pub(crate) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Resolves at the first `SIGTERM` or `SIGINT`.
fn signals() -> Result<impl Future<Output = ShutdownReason> + Send, Error> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).map_err(Error::Signals)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(Error::Signals)?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => ShutdownReason::Sigterm,
            _ = interrupt.recv() => ShutdownReason::Sigint,
        }
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Builders shared by the crate's tests.
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::PathBuf;

    use lotse_api_types::info::{BuildInfo, LandlockInfo, SandboxInfo};
    use lotse_core::registry::Registries;
    use lotse_core::test_util::FakeSourceFactory;

    use super::*;
    use crate::worker::WorkerConfig;

    /// `let $pattern = $value else { panic!(...) };` as one statement
    /// whose first line holds `$value`: the `else` of a test's
    /// destructuring is on a line that runs, so a passing test leaves no
    /// line of it unrun (rustfmt keeps the layout, as it does not format
    /// the `=>`). Without a message the panic names the pattern.
    macro_rules! let_expect {
        ($value:expr => $pattern:pat) => {
            let $pattern = $value else {
                panic!(concat!("expected ", stringify!($pattern)))
            };
        };
        ($value:expr => $pattern:pat, $($message:tt)+) => {
            let $pattern = $value else {
                panic!($($message)+)
            };
        };
    }
    pub(crate) use let_expect;

    /// A private 0700 directory for one test's socket.
    pub(crate) fn private_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lotse-sup-{test}-{}", std::process::id()));
        let _existing = std::fs::remove_dir_all(&dir);
        let shown = dir.display().to_string();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect(&shown);
        dir
    }

    /// Settings for a socket whose 0700 directory the test created, so the
    /// owner uid is the directory's.
    pub(crate) fn settings(socket: PathBuf) -> Settings {
        use std::os::unix::fs::MetadataExt as _;
        let uid = socket
            .parent()
            .and_then(|dir| std::fs::metadata(dir).ok())
            .map_or(0, |meta| meta.uid());
        Settings {
            socket,
            owner_uid: uid,
            allow_uid: uid,
            udp_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            tcp_listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            limits: Limits {
                max_connections: 8,
                max_streams: 2,
                max_sessions: 256,
                max_sessions_per_stream: 16,
                session_grace: Duration::from_secs(10),
                worker_threads: 1,
                worker_address_space: 1 << 30,
            },
            linger: Duration::from_secs(5),
            connect_concurrency: DEFAULT_CONNECT_CONCURRENCY,
            shutdown_budget: Duration::from_secs(2),
        }
    }

    /// A log writer that keeps every line, in the text format.
    #[derive(Clone, Default)]
    pub(crate) struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        /// The lines logged so far that contain `needle`, after a flush.
        pub(crate) fn lines(&self, needle: &str) -> Vec<String> {
            io::Write::flush(&mut self.clone()).unwrap();
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .filter(|line| line.contains(needle))
                .map(str::to_owned)
                .collect()
        }

        /// Starts capturing this thread's log lines, `debug` and up.
        pub(crate) fn install(&self) -> tracing::subscriber::DefaultGuard {
            let writer = self.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::DEBUG)
                .finish();
            tracing::subscriber::set_default(subscriber)
        }
    }

    /// An environment whose workers are `binary`, with the fake source.
    pub(crate) fn environment(binary: &str) -> Environment {
        let mut registries = Registries::default();
        registries
            .sources
            .register(Arc::new(FakeSourceFactory::new(&["fake"])))
            .expect("the fake source registers");
        Environment {
            registries,
            worker: WorkerConfig {
                binary: PathBuf::from(binary),
                log_format: "json".into(),
                log_level: "debug".into(),
                sandbox: "off".into(),
                worker_threads: 1,
                worker_address_space: 1 << 30,
                max_sessions: 256,
            },
            udp: None,
            front_door: None,
            identity: Identity {
                version: "0.0.0-test".into(),
                build: BuildInfo {
                    target: "test".into(),
                    git_sha: None,
                    rustc: "test".into(),
                },
                sandbox: SandboxInfo {
                    mode: "off".into(),
                    uid: 0,
                    gid: 0,
                    no_new_privs: false,
                    seccomp: "off".into(),
                    landlock: LandlockInfo {
                        fs: "off".into(),
                        net: "off".into(),
                        abi: 0,
                    },
                    notes: vec![],
                },
            },
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

    use lotse_core::clock::FakeClock;

    use super::*;
    use crate::test_support::{Captured, environment, private_dir, settings};

    /// The shutdown the tests ask for: one future type, so one
    /// instantiation of `serve` runs every path the tests take.
    fn requested() -> std::future::Ready<ShutdownReason> {
        std::future::ready(ShutdownReason::Requested)
    }

    #[tokio::test]
    async fn serve_runs_until_the_shutdown_future_resolves() {
        let dir = private_dir("serve");
        let settings = settings(dir.join("lotse.sock"));
        let listeners = bind(&settings).unwrap();
        assert!(dir.join("lotse.sock").exists());
        assert!(listeners.udp.local.port() > 0);
        assert!(listeners.tcp.is_some());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let reason = serve(
            &settings,
            listeners,
            environment("/bin/sh"),
            clock,
            requested(),
        )
        .await
        .unwrap();
        assert_eq!(reason, ShutdownReason::Requested);
        // A port in use is a bind error naming the address.
        let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut busy = settings.clone();
        busy.udp_listen = taken.local_addr().unwrap();
        busy.socket = dir.join("other.sock");
        let err = bind(&busy).unwrap_err();
        assert!(matches!(err, BindError::Udp { .. }), "{err}");
        assert!(err.to_string().starts_with("webrtc udp socket 127.0.0.1:"));
        // So is a listening TCP port.
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut busy = settings.clone();
        busy.tcp_listen = Some(taken.local_addr().unwrap());
        busy.socket = dir.join("third.sock");
        let err = bind(&busy).unwrap_err();
        assert!(matches!(err, BindError::Tcp { .. }), "{err}");
        assert!(err.to_string().starts_with("ice-tcp listener 127.0.0.1:"));
        assert!(
            Error::FrontDoor(io::Error::other("x"))
                .to_string()
                .starts_with("network front door")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn serve_logs_its_start_and_stop_and_runs_without_ice_tcp() {
        let dir = private_dir("serve-logs");
        let mut settings = settings(dir.join("lotse.sock"));
        settings.tcp_listen = None;
        let listeners = bind(&settings).unwrap();
        assert!(listeners.tcp.is_none(), "ice-tcp off binds no listener");
        let captured = Captured::default();
        let _logs = captured.install();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let reason = serve(
            &settings,
            listeners,
            environment("/bin/sh"),
            clock,
            requested(),
        )
        .await
        .unwrap();
        assert_eq!(reason, ShutdownReason::Requested);
        let ready = captured.lines("supervisor ready");
        assert_eq!(ready.len(), 1, "{ready:?}");
        assert!(
            ready[0].contains("tcp_listen=None") && ready[0].contains("linger_ms=5000"),
            "{ready:?}"
        );
        let stopping = captured.lines("shutting down");
        assert!(
            stopping[0].contains("reason=\"requested\"") && stopping[0].contains("budget_ms=2000"),
            "{stopping:?}"
        );
        let front_door = captured.lines("front door stopping");
        assert!(
            front_door[0].contains("received=0") && front_door[0].contains("ice_tcp_accepted=0"),
            "{front_door:?}"
        );
        assert_eq!(captured.lines("supervisor stopped").len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn the_api_server_s_end_is_logged_and_waited_for_within_the_budget() {
        let captured = Captured::default();
        let _logs = captured.install();
        // The fake clock never moves: only a zero budget runs out.
        let clock = FakeClock::default();
        let budget = Duration::from_secs(1);
        api_stopped(spawn_named("test.api", async { Ok(()) }), &clock, budget).await;
        let failed = async {
            Err(lotse_api::ServeError::Register(io::Error::other(
                "no reactor",
            )))
        };
        api_stopped(spawn_named("test.api", failed), &clock, budget).await;
        let aborted = spawn_named("test.api", std::future::pending());
        aborted.abort();
        api_stopped(aborted, &clock, budget).await;
        let hanging = spawn_named("test.api", std::future::pending());
        api_stopped(hanging, &clock, Duration::ZERO).await;
        let server = captured.lines("control API server failed");
        assert_eq!(server.len(), 1, "{server:?}");
        assert!(server[0].contains("no reactor"), "{server:?}");
        let task = captured.lines("control API task failed");
        assert_eq!(task.len(), 1, "{task:?}");
        assert!(task[0].contains("cancelled"), "{task:?}");
        assert_eq!(
            captured
                .lines("control API connections missed the shutdown budget")
                .len(),
            1
        );
    }

    #[test]
    fn run_serves_until_sigterm_or_sigint() {
        use rustix::process::{Signal, getpid, kill_process};
        let dir = private_dir("run");
        for (n, (signal, expected)) in [
            (Signal::TERM, ShutdownReason::Sigterm),
            (Signal::INT, ShutdownReason::Sigint),
        ]
        .into_iter()
        .enumerate()
        {
            let settings = settings(dir.join(format!("{n}.sock")));
            let listeners = bind(&settings).unwrap();
            let captured = Captured::default();
            let logs = captured.clone();
            // `run` serves on the thread that calls it, so its lines reach
            // that thread's subscriber.
            let runner = std::thread::spawn(move || {
                let _logs = logs.install();
                run(&settings, listeners, environment("/bin/sh"))
            });
            // The handlers are installed before `ready` is logged, so the
            // signal reaches them, not the default action.
            let mut ready = Vec::new();
            let mut looks = 0;
            while ready.is_empty() && looks < 1_000 {
                std::thread::park_timeout(Duration::from_millis(10));
                looks += 1;
                ready = captured.lines("supervisor ready");
            }
            assert_eq!(ready.len(), 1, "ready once");
            kill_process(getpid(), signal).unwrap();
            assert_eq!(runner.join().unwrap().unwrap(), expected);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_listener_the_runtime_cannot_poll_ends_run_with_an_error() {
        let dir = private_dir("run-unpollable");
        let mut settings = settings(dir.join("lotse.sock"));
        settings.tcp_listen = None;
        let mut listeners = bind(&settings).unwrap();
        // A regular file in place of the ICE-TCP listener: epoll refuses it.
        let file = std::fs::File::create(dir.join("not-a-socket")).unwrap();
        let not_a_socket = std::net::TcpListener::from(std::os::fd::OwnedFd::from(file));
        // Non-blocking, as the runtime requires of what it registers.
        not_a_socket.set_nonblocking(true).unwrap();
        listeners.tcp = Some(not_a_socket);
        let err = run(&settings, listeners, environment("/bin/sh")).unwrap_err();
        assert!(matches!(err, Error::FrontDoor(_)), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn signal_handlers_install_on_a_runtime() {
        // Installing is the testable part; delivering a signal to the test
        // process is what the binary's subprocess test does.
        let pending = signals().unwrap();
        drop(pending);
    }

    #[test]
    fn tcp_candidates_follow_the_listener() {
        let hosts: Vec<SocketAddr> = vec![
            "192.168.1.2:18556".parse().unwrap(),
            "[2001:db8::2]:18556".parse().unwrap(),
        ];
        assert!(tcp_hosts(&hosts, None).is_empty(), "listener off");
        assert_eq!(
            tcp_hosts(&hosts, Some("[::]:18557".parse().unwrap())),
            vec![
                "192.168.1.2:18557".parse::<SocketAddr>().unwrap(),
                "[2001:db8::2]:18557".parse().unwrap()
            ]
        );
        assert_eq!(
            tcp_hosts(&hosts, Some("0.0.0.0:18557".parse().unwrap())),
            vec!["192.168.1.2:18557".parse::<SocketAddr>().unwrap()],
            "an IPv4 listener takes no IPv6 connections"
        );
        assert_eq!(
            tcp_hosts(&hosts, Some("127.0.0.1:9".parse().unwrap())),
            vec!["127.0.0.1:9".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn reasons_have_names_and_errors_display() {
        assert_eq!(ShutdownReason::Sigterm.name(), "sigterm");
        assert_eq!(ShutdownReason::Sigint.name(), "sigint");
        assert_eq!(ShutdownReason::Requested.name(), "requested");
        let err = Error::Runtime(io::Error::other("no threads"));
        assert_eq!(err.to_string(), "runtime failed to start: no threads");
        let err = Error::Signals(io::Error::other("no signals"));
        assert_eq!(
            err.to_string(),
            "signal handler failed to install: no signals"
        );
        assert_eq!(SHUTDOWN_BUDGET, Duration::from_secs(2));
        assert_eq!(RUNTIME_THREADS, 2);
        assert_eq!(millis(Duration::from_secs(3)), 3_000);
    }
}
