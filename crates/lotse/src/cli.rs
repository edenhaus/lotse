//! The command line: subcommands, flags and their `LOTSE_*` environment
//! variables, plus `RUST_LOG`. Flags alone are enough: everything has a
//! default except `--socket`.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use lotse_sandbox::Mode;

use crate::config::{LogFormat, TcpListen};
use crate::ctl::CtlArgs;

/// The one binary.
#[derive(Debug, Parser)]
#[command(
    name = "lotse",
    version,
    about = "Media daemon: RTSP cameras in, WebRTC to browsers out."
)]
pub(crate) struct Cli {
    /// What to run.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// The process kinds and tools.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run the supervisor: control API, workers and the WebRTC front door.
    Serve(Box<ServeArgs>),
    /// Run one camera connection; started by the supervisor, never by hand.
    #[command(hide = true)]
    Worker(WorkerArgs),
    /// Talk to a running daemon over its control socket; prints JSON.
    Ctl(CtlArgs),
}

/// `lotse worker`: the flags the supervisor passes. No environment, no
/// file: the worker starts with an empty environment.
#[derive(Debug, Args)]
pub(crate) struct WorkerArgs {
    /// Log lines as `json` or `text`.
    #[arg(long, value_name = "json|text", default_value = "json")]
    pub(crate) log_format: LogFormat,

    /// Log level or filter directive.
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    pub(crate) log_level: String,

    /// Process isolation, as for `serve`.
    #[arg(long, value_name = "on|require|off", default_value = "on")]
    pub(crate) sandbox: Mode,

    /// Tokio threads.
    #[arg(long, value_name = "N", default_value_t = 2)]
    pub(crate) worker_threads: usize,

    /// `RLIMIT_AS`, in bytes.
    #[arg(long, value_name = "BYTES", default_value_t = lotse_sandbox::DEFAULT_WORKER_ADDRESS_SPACE)]
    pub(crate) worker_address_space: u64,

    /// The most sessions at once: the daemon's `limits.max_sessions`, so
    /// the worker holds no more than the supervisor can have asked for.
    #[arg(long, value_name = "N", default_value_t = 256)]
    pub(crate) max_sessions: usize,

    /// The camera's TCP ports this worker may connect to.
    #[arg(long, value_name = "PORT,...", value_delimiter = ',')]
    pub(crate) connect_ports: Vec<u16>,

    /// Bind a loopback listener for the source's relay (`rtsps`) before the
    /// sandbox, and allow connecting to its port.
    #[arg(long)]
    pub(crate) loopback_relay: bool,
}

/// `lotse serve`. Every flag has a `LOTSE_*` variable; both override the
/// config file, which overrides the defaults.
#[derive(Debug, Args)]
pub(crate) struct ServeArgs {
    /// TOML file with the same settings, for standalone use and tests.
    #[arg(long, env = "LOTSE_CONFIG", value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,

    /// Path of the control socket. Its directory must exist, be 0700 and be
    /// owned by the uid the daemon starts as.
    #[arg(long, env = "LOTSE_SOCKET", value_name = "PATH")]
    pub(crate) socket: Option<PathBuf>,

    /// Numeric uid to drop to after binding, when started as root, in every
    /// sandbox mode.
    #[arg(long, env = "LOTSE_USER", value_name = "UID")]
    pub(crate) user: Option<u32>,

    /// Numeric gid to drop to after binding, when started as root, in every
    /// sandbox mode.
    #[arg(long, env = "LOTSE_GROUP", value_name = "GID")]
    pub(crate) group: Option<u32>,

    /// Peer uid allowed on the control socket; the starting uid by default.
    #[arg(long, env = "LOTSE_ALLOW_UID", value_name = "UID")]
    pub(crate) allow_uid: Option<u32>,

    /// Process isolation: `on` (best effort, reported), `require` (refuse to
    /// start without every layer) or `off` (debugging only: no Landlock or
    /// seccomp; the privilege drop still happens).
    #[arg(long, env = "LOTSE_SANDBOX", value_name = "on|require|off")]
    pub(crate) sandbox: Option<Mode>,

    /// The shared WebRTC UDP socket, dual-stack.
    #[arg(long, env = "LOTSE_WEBRTC_UDP_LISTEN", value_name = "ADDR")]
    pub(crate) webrtc_udp_listen: Option<SocketAddr>,

    /// The ICE-TCP listener, or `off`.
    #[arg(long, env = "LOTSE_WEBRTC_TCP_LISTEN", value_name = "ADDR|off")]
    pub(crate) webrtc_tcp_listen: Option<TcpListen>,

    /// Control connections at once.
    #[arg(long, env = "LOTSE_MAX_CONNECTIONS", value_name = "N")]
    pub(crate) max_connections: Option<u32>,

    /// Streams.
    #[arg(long, env = "LOTSE_MAX_STREAMS", value_name = "N")]
    pub(crate) max_streams: Option<u32>,

    /// Sessions in total.
    #[arg(long, env = "LOTSE_MAX_SESSIONS", value_name = "N")]
    pub(crate) max_sessions: Option<u32>,

    /// Sessions per stream.
    #[arg(long, env = "LOTSE_MAX_SESSIONS_PER_STREAM", value_name = "N")]
    pub(crate) max_sessions_per_stream: Option<u32>,

    /// How long an orphaned session outlives its control connection.
    #[arg(long, env = "LOTSE_SESSION_GRACE_MS", value_name = "MS")]
    pub(crate) session_grace_ms: Option<u64>,

    /// Tokio threads per worker.
    #[arg(long, env = "LOTSE_WORKER_THREADS", value_name = "N")]
    pub(crate) worker_threads: Option<usize>,

    /// `RLIMIT_AS` per worker, in bytes.
    #[arg(long, env = "LOTSE_WORKER_ADDRESS_SPACE", value_name = "BYTES")]
    pub(crate) worker_address_space: Option<u64>,

    /// Grace after the last viewer leaves before a camera connection closes.
    #[arg(long, env = "LOTSE_LINGER_MS", value_name = "MS")]
    pub(crate) linger_ms: Option<u64>,

    /// Source connection attempts at once, across every camera; at least 1.
    #[arg(long, env = "LOTSE_CONNECT_CONCURRENCY", value_name = "N")]
    pub(crate) connect_concurrency: Option<NonZeroUsize>,

    /// Log lines as `json` (one object per line, for a log collector) or `text`.
    #[arg(long, env = "LOTSE_LOG_FORMAT", value_name = "json|text")]
    pub(crate) log_format: Option<LogFormat>,

    /// Log level or filter directive, for the supervisor and its workers;
    /// a valid `RUST_LOG` overrides it.
    #[arg(long, env = "LOTSE_LOG_LEVEL", value_name = "LEVEL")]
    pub(crate) log_level: Option<String>,

    /// `RUST_LOG`, read here so the environment is read once. Hidden: the
    /// variable is the interface, the flag only gives clap a name for it.
    /// Raw bytes, so a value that is not UTF-8 is ignored like any other
    /// invalid filter instead of refusing to start.
    #[arg(long, env = "RUST_LOG", value_name = "FILTER", hide = true)]
    pub(crate) rust_log: Option<OsString>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn serve_parses_flags_and_typed_values() {
        let cli = Cli::try_parse_from([
            "lotse",
            "serve",
            "--socket",
            "/run/lotse.sock",
            "--sandbox",
            "require",
            "--webrtc-tcp-listen",
            "off",
            "--log-format",
            "text",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("serve expected");
        };
        assert_eq!(
            args.socket.as_deref(),
            Some(std::path::Path::new("/run/lotse.sock"))
        );
        assert_eq!(args.sandbox, Some(Mode::Require));
        assert_eq!(args.webrtc_tcp_listen, Some(TcpListen::Off));
        assert_eq!(args.log_format, Some(LogFormat::Text));
    }

    #[test]
    fn worker_parses_the_supervisors_flags() {
        let cli = Cli::try_parse_from([
            "lotse",
            "worker",
            "--log-format",
            "text",
            "--sandbox",
            "off",
            "--worker-threads",
            "3",
            "--max-sessions",
            "32",
            "--connect-ports",
            "554,80",
            "--loopback-relay",
        ])
        .unwrap();
        let Command::Worker(args) = cli.command else {
            panic!("worker expected");
        };
        assert_eq!(args.log_format, LogFormat::Text);
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sandbox, Mode::Off);
        assert_eq!(args.worker_threads, 3);
        assert_eq!(args.max_sessions, 32);
        assert_eq!(
            args.worker_address_space,
            lotse_sandbox::DEFAULT_WORKER_ADDRESS_SPACE
        );
        assert_eq!(args.connect_ports, [554, 80]);
        assert!(args.loopback_relay);
        let Command::Worker(bare) = Cli::try_parse_from(["lotse", "worker"]).unwrap().command
        else {
            panic!("worker expected");
        };
        assert!(bare.connect_ports.is_empty());
        assert!(!bare.loopback_relay);
        assert_eq!(bare.sandbox, Mode::On);
        assert_eq!(bare.max_sessions, 256);
    }

    #[test]
    fn ctl_parses_its_commands() {
        use crate::ctl::{CtlCommand, StreamCommand};
        let cli = Cli::try_parse_from([
            "lotse",
            "ctl",
            "--socket",
            "/run/lotse.sock",
            "--compact",
            "stream",
            "put",
            "front",
            "--url",
            "fake://cam/",
            "--preload",
            "--audio",
            "off",
            "--options",
            "{}",
        ])
        .unwrap();
        let Command::Ctl(args) = cli.command else {
            panic!("ctl expected");
        };
        assert_eq!(args.socket, PathBuf::from("/run/lotse.sock"));
        assert!(args.compact);
        let CtlCommand::Stream {
            command:
                StreamCommand::Put {
                    stream_id,
                    urls,
                    url_file,
                    options,
                    preload,
                    audio,
                },
        } = args.command
        else {
            panic!("stream put expected");
        };
        assert_eq!(
            (stream_id.as_str(), preload, audio.as_str()),
            ("front", true, "off")
        );
        assert_eq!(urls, ["fake://cam/"]);
        assert_eq!(url_file, None);
        assert_eq!(options.as_deref(), Some("{}"));
        let cli = Cli::try_parse_from([
            "lotse",
            "ctl",
            "--socket",
            "/s",
            "stream",
            "subscribe",
            "--limit",
            "2",
        ])
        .unwrap();
        let Command::Ctl(args) = cli.command else {
            panic!("ctl expected");
        };
        assert!(matches!(
            args.command,
            CtlCommand::Stream {
                command: StreamCommand::Subscribe {
                    stream_id: None,
                    limit: Some(2)
                }
            }
        ));
        let err = Cli::try_parse_from(["lotse", "ctl", "info"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn ctl_stream_put_takes_its_urls_from_url_or_url_file_never_both() {
        use crate::ctl::{CtlCommand, StreamCommand};
        let put = |args: &[&str]| {
            let base = ["lotse", "ctl", "--socket", "/s", "stream", "put", "front"];
            Cli::try_parse_from(base.iter().chain(args))
        };
        let Command::Ctl(args) = put(&["--url-file", "-"]).unwrap().command else {
            panic!("ctl expected");
        };
        let CtlCommand::Stream {
            command: StreamCommand::Put { urls, url_file, .. },
        } = args.command
        else {
            panic!("stream put expected");
        };
        assert!(urls.is_empty());
        assert_eq!(url_file, Some(PathBuf::from("-")));
        let err = put(&[]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        let err = put(&["--url", "fake://cam/", "--url-file", "-"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn bad_values_are_rejected() {
        let err = Cli::try_parse_from(["lotse", "serve", "--sandbox", "loud"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        let err =
            Cli::try_parse_from(["lotse", "serve", "--webrtc-tcp-listen", "nowhere"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        let err =
            Cli::try_parse_from(["lotse", "serve", "--connect-concurrency", "0"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        let err = Cli::try_parse_from(["lotse"]).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }
}
