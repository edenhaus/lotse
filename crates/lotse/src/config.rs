//! The effective settings, resolved from flags, `LOTSE_*` variables, the
//! TOML file and the defaults, in that precedence, with the source of every
//! value for the startup log.
//!
//! Configuration is read once, here; nothing else in the daemon reads the
//! environment. The file is strict: an unknown key is an error, so a typo
//! never silently falls back to a default.

use std::ffi::OsStr;
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use clap::ArgMatches;
use clap::parser::ValueSource;
use lotse_sandbox::{Mode, SandboxConfig};
use lotse_supervisor::{DEFAULT_CONNECT_CONCURRENCY, Limits, SHUTDOWN_BUDGET};
use serde::Deserialize;

use crate::cli::ServeArgs;

/// Where a setting's value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// A command-line flag.
    Flag,
    /// A `LOTSE_*` variable.
    Env,
    /// The TOML file.
    File,
    /// The built-in default.
    Default,
}

impl Source {
    /// The name in the startup log.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Env => "env",
            Self::File => "file",
            Self::Default => "default",
        }
    }
}

/// `log.format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LogFormat {
    /// One JSON object per line, for a log collector.
    Json,
    /// Human-readable lines.
    Text,
}

impl LogFormat {
    /// The setting's text.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
        }
    }
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a string is not a [`LogFormat`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("log format must be `json` or `text`, not {0:?}")]
pub(crate) struct ParseLogFormatError(String);

impl FromStr for LogFormat {
    type Err = ParseLogFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            other => Err(ParseLogFormatError(other.to_owned())),
        }
    }
}

/// `webrtc.tcp_listen`: an address, or `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpListen {
    /// No ICE-TCP listener.
    Off,
    /// Listen here.
    On(SocketAddr),
}

impl TcpListen {
    /// The address, if on.
    pub(crate) const fn address(self) -> Option<SocketAddr> {
        match self {
            Self::Off => None,
            Self::On(addr) => Some(addr),
        }
    }
}

impl fmt::Display for TcpListen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::On(addr) => write!(f, "{addr}"),
        }
    }
}

/// Why a string is not a [`TcpListen`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("tcp listen must be `off` or an address like `[::]:18556`, not {0:?}")]
pub(crate) struct ParseTcpListenError(String);

impl FromStr for TcpListen {
    type Err = ParseTcpListenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "off" {
            return Ok(Self::Off);
        }
        s.parse()
            .map(Self::On)
            .map_err(|_| ParseTcpListenError(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for TcpListen {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The logging settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogSettings {
    /// `log.format`.
    pub(crate) format: LogFormat,
    /// The effective filter: `RUST_LOG` when it is a valid filter
    /// directive, else `log.level`. The supervisor and every worker it
    /// starts (as `--log-level`) log with this one filter.
    pub(crate) level: String,
    /// A `RUST_LOG` that was set but is not a filter directive, and so was
    /// ignored; logged as a warning once logging runs.
    pub(crate) ignored_rust_log: Option<IgnoredRustLog>,
}

/// A `RUST_LOG` that was set but not used, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IgnoredRustLog {
    /// The variable's value, lossily decoded.
    pub(crate) value: String,
    /// Why it is not a filter directive.
    pub(crate) reason: String,
}

/// `RUST_LOG` as a filter directive: `Ok(None)` when unset, `Ok(Some)`
/// when it parses as one (with the same parser the subscriber uses), else
/// why it is ignored. An empty value parses (it means `error`), as it did
/// when the subscriber read the variable itself.
fn rust_log_filter(value: Option<&OsStr>) -> Result<Option<String>, IgnoredRustLog> {
    let Some(value) = value else {
        return Ok(None);
    };
    let ignored = |reason: String| IgnoredRustLog {
        value: value.to_string_lossy().into_owned(),
        reason,
    };
    let text = value
        .to_str()
        .ok_or_else(|| ignored("not UTF-8".to_owned()))?;
    match tracing_subscriber::EnvFilter::try_new(text) {
        Ok(_filter) => Ok(Some(text.to_owned())),
        Err(err) => Err(ignored(err.to_string())),
    }
}

/// Everything resolved, grouped by the crate that consumes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    /// For `lotse-sandbox`.
    pub(crate) sandbox: SandboxConfig,
    /// For the log subscriber.
    pub(crate) log: LogSettings,
    /// For `lotse-supervisor`.
    pub(crate) supervisor: lotse_supervisor::Settings,
}

/// One resolved setting and where it came from, for the startup log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Provenance {
    /// The setting's name as in the TOML file (`limits.max_streams`).
    pub(crate) name: &'static str,
    /// The effective value.
    pub(crate) value: String,
    /// Where it came from.
    pub(crate) source: Source,
}

/// Why the configuration could not be resolved.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// No socket path anywhere.
    #[error(
        "the control socket path is required: --socket, LOTSE_SOCKET, or `socket` in the config file"
    )]
    MissingSocket,
    /// The config file could not be read.
    #[error("config file {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The error.
        #[source]
        source: std::io::Error,
    },
    /// The config file is not valid.
    #[error("config file {path}: {source}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// The error, with the offending key or line.
        #[source]
        source: toml::de::Error,
    },
}

/// The TOML file. Every key optional, unknown keys refused.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    /// `socket`.
    socket: Option<PathBuf>,
    /// `user`.
    user: Option<u32>,
    /// `group`.
    group: Option<u32>,
    /// `allow_uid`.
    allow_uid: Option<u32>,
    /// `sandbox`.
    sandbox: Option<Mode>,
    /// `[webrtc]`.
    #[serde(default)]
    webrtc: WebrtcFile,
    /// `[limits]`.
    #[serde(default)]
    limits: LimitsFile,
    /// `[stream]`.
    #[serde(default)]
    stream: StreamFile,
    /// `[sources]`.
    #[serde(default)]
    sources: SourcesFile,
    /// `[log]`.
    #[serde(default)]
    log: LogFile,
}

/// `[webrtc]` in the file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebrtcFile {
    /// `webrtc.udp_listen`.
    udp_listen: Option<SocketAddr>,
    /// `webrtc.tcp_listen`.
    tcp_listen: Option<TcpListen>,
}

/// `[limits]` in the file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    /// `limits.max_connections`.
    max_connections: Option<u32>,
    /// `limits.max_streams`.
    max_streams: Option<u32>,
    /// `limits.max_sessions`.
    max_sessions: Option<u32>,
    /// `limits.max_sessions_per_stream`.
    max_sessions_per_stream: Option<u32>,
    /// `limits.session_grace_ms`.
    session_grace_ms: Option<u64>,
    /// `limits.worker_threads`.
    worker_threads: Option<usize>,
    /// `limits.worker_address_space`.
    worker_address_space: Option<u64>,
}

/// `[stream]` in the file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamFile {
    /// `stream.linger_ms`.
    linger_ms: Option<u64>,
}

/// `[sources]` in the file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcesFile {
    /// `sources.connect_concurrency`; zero is refused.
    connect_concurrency: Option<NonZeroUsize>,
}

/// `[log]` in the file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogFile {
    /// `log.format`.
    format: Option<LogFormat>,
    /// `log.level`.
    level: Option<String>,
}

impl FileConfig {
    /// Reads and parses `path`.
    fn read(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Picks each value by precedence and records where it came from.
struct Resolver<'a> {
    /// The parsed `serve` arguments, for the flag-versus-environment question.
    matches: &'a ArgMatches,
    /// What has been resolved so far.
    provenance: Vec<Provenance>,
}

impl Resolver<'_> {
    /// The value for `name`, whose clap id is `id`: the flag or variable if
    /// given, else the file's value, else `default`.
    fn pick<T: fmt::Display>(
        &mut self,
        name: &'static str,
        id: &str,
        given: Option<T>,
        file: Option<T>,
        default: T,
    ) -> T {
        let (value, source) = match (self.matches.value_source(id), given) {
            (Some(ValueSource::CommandLine), Some(value)) => (value, Source::Flag),
            (Some(ValueSource::EnvVariable), Some(value)) => (value, Source::Env),
            _ => match file {
                Some(value) => (value, Source::File),
                None => (default, Source::Default),
            },
        };
        self.provenance.push(Provenance {
            name,
            value: value.to_string(),
            source,
        });
        value
    }

    /// As [`Resolver::pick`] for a setting without a default.
    fn pick_required<T: fmt::Display>(
        &mut self,
        name: &'static str,
        id: &str,
        given: Option<T>,
        file: Option<T>,
    ) -> Option<T> {
        let (value, source) = match (self.matches.value_source(id), given) {
            (Some(ValueSource::CommandLine), Some(value)) => (value, Source::Flag),
            (Some(ValueSource::EnvVariable), Some(value)) => (value, Source::Env),
            _ => (file?, Source::File),
        };
        self.provenance.push(Provenance {
            name,
            value: value.to_string(),
            source,
        });
        Some(value)
    }
}

impl Resolver<'_> {
    /// Records a value that only a flag or a variable can set.
    fn record_given(&mut self, name: &'static str, id: &str, value: String) {
        self.provenance.push(Provenance {
            name,
            value,
            source: match self.matches.value_source(id) {
                Some(ValueSource::EnvVariable) => Source::Env,
                _ => Source::Flag,
            },
        });
    }

    /// The `[limits]` group.
    fn limits(&mut self, args: &ServeArgs, file: &LimitsFile) -> Limits {
        Limits {
            max_connections: self.pick(
                "limits.max_connections",
                "max_connections",
                args.max_connections,
                file.max_connections,
                8,
            ),
            max_streams: self.pick(
                "limits.max_streams",
                "max_streams",
                args.max_streams,
                file.max_streams,
                256,
            ),
            max_sessions: self.pick(
                "limits.max_sessions",
                "max_sessions",
                args.max_sessions,
                file.max_sessions,
                256,
            ),
            max_sessions_per_stream: self.pick(
                "limits.max_sessions_per_stream",
                "max_sessions_per_stream",
                args.max_sessions_per_stream,
                file.max_sessions_per_stream,
                16,
            ),
            session_grace: Duration::from_millis(self.pick(
                "limits.session_grace_ms",
                "session_grace_ms",
                args.session_grace_ms,
                file.session_grace_ms,
                10_000,
            )),
            worker_threads: self.pick(
                "limits.worker_threads",
                "worker_threads",
                args.worker_threads,
                file.worker_threads,
                2,
            ),
            worker_address_space: self.pick(
                "limits.worker_address_space",
                "worker_address_space",
                args.worker_address_space,
                file.worker_address_space,
                lotse_sandbox::DEFAULT_WORKER_ADDRESS_SPACE,
            ),
        }
    }

    /// The `[log]` group. A valid `RUST_LOG` beats every other source of
    /// `log.level`; an invalid one is ignored and reported.
    fn log(&mut self, args: &ServeArgs, file: LogFile) -> LogSettings {
        let format = self.pick(
            "log.format",
            "log_format",
            args.log_format,
            file.format,
            LogFormat::Json,
        );
        let (rust_log, ignored_rust_log) = match rust_log_filter(args.rust_log.as_deref()) {
            Ok(filter) => (filter, None),
            Err(ignored) => (None, Some(ignored)),
        };
        let level = match rust_log {
            Some(filter) => {
                self.record_given("log.level", "rust_log", filter.clone());
                filter
            }
            None => self.pick(
                "log.level",
                "log_level",
                args.log_level.clone(),
                file.level,
                "info".to_owned(),
            ),
        };
        LogSettings {
            format,
            level,
            ignored_rust_log,
        }
    }
}

/// Wraps a path so it prints for the provenance log.
struct DisplayPath(PathBuf);

impl fmt::Display for DisplayPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// Resolves the settings for `lotse serve`.
pub(crate) fn load(
    args: &ServeArgs,
    matches: &ArgMatches,
) -> Result<(Settings, Vec<Provenance>), ConfigError> {
    let file = match &args.config {
        Some(path) => FileConfig::read(path)?,
        None => FileConfig::default(),
    };
    let mut r = Resolver {
        matches,
        provenance: Vec::new(),
    };
    if let Some(path) = &args.config {
        r.record_given("config", "config", path.display().to_string());
    }

    let socket = r
        .pick_required(
            "socket",
            "socket",
            args.socket.clone().map(DisplayPath),
            file.socket.map(DisplayPath),
        )
        .ok_or(ConfigError::MissingSocket)?
        .0;
    let starting_uid = rustix::process::getuid().as_raw();
    let uid = r.pick(
        "user",
        "user",
        args.user,
        file.user,
        lotse_sandbox::DEFAULT_UID,
    );
    let gid = r.pick(
        "group",
        "group",
        args.group,
        file.group,
        lotse_sandbox::DEFAULT_GID,
    );
    let allow_uid = r.pick(
        "allow_uid",
        "allow_uid",
        args.allow_uid,
        file.allow_uid,
        starting_uid,
    );
    let mode = r.pick("sandbox", "sandbox", args.sandbox, file.sandbox, Mode::On);
    let udp_listen = r.pick(
        "webrtc.udp_listen",
        "webrtc_udp_listen",
        args.webrtc_udp_listen,
        file.webrtc.udp_listen,
        DEFAULT_LISTEN,
    );
    let tcp_listen = r.pick(
        "webrtc.tcp_listen",
        "webrtc_tcp_listen",
        args.webrtc_tcp_listen,
        file.webrtc.tcp_listen,
        TcpListen::On(DEFAULT_LISTEN),
    );
    let limits = r.limits(args, &file.limits);
    let linger = Duration::from_millis(r.pick(
        "stream.linger_ms",
        "linger_ms",
        args.linger_ms,
        file.stream.linger_ms,
        5_000,
    ));
    let connect_concurrency = r.pick(
        "sources.connect_concurrency",
        "connect_concurrency",
        args.connect_concurrency,
        file.sources.connect_concurrency,
        DEFAULT_CONNECT_CONCURRENCY,
    );
    let log = r.log(args, file.log);

    let settings = Settings {
        sandbox: SandboxConfig {
            mode,
            uid,
            gid,
            worker_address_space: limits.worker_address_space,
        },
        log,
        supervisor: lotse_supervisor::Settings {
            socket,
            owner_uid: starting_uid,
            allow_uid,
            udp_listen,
            tcp_listen: tcp_listen.address(),
            limits,
            linger,
            connect_concurrency,
            shutdown_budget: SHUTDOWN_BUDGET,
        },
    };
    Ok((settings, r.provenance))
}

/// The default of `webrtc.udp_listen` and `webrtc.tcp_listen`: dual-stack,
/// port 18556, so the daemon can run beside another WebRTC server that
/// holds 18555 on the same host.
const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    18_556,
);

/// Logs every effective setting with its source, at startup, and a
/// `RUST_LOG` that was ignored.
pub(crate) fn log_effective(provenance: &[Provenance], log: &LogSettings) {
    for setting in provenance {
        tracing::info!(
            setting = setting.name,
            value = %setting.value,
            source = setting.source.name(),
            "config"
        );
    }
    if let Some(ignored) = &log.ignored_rust_log {
        tracing::warn!(
            value = %ignored.value,
            reason = %ignored.reason,
            log_level = %log.level,
            "RUST_LOG is not a filter directive; ignored, log.level applies"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use clap::{CommandFactory as _, FromArgMatches as _};

    use super::*;
    use crate::cli::{Cli, Command};

    fn resolve(command_line: &[&str]) -> Result<(Settings, Vec<Provenance>), ConfigError> {
        let matches = Cli::command().try_get_matches_from(command_line).unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("serve expected");
        };
        let serve = matches.subcommand_matches("serve").unwrap();
        load(&args, serve)
    }

    fn source_of(provenance: &[Provenance], name: &str) -> (String, Source) {
        let p = provenance.iter().find(|p| p.name == name).unwrap();
        (p.value.clone(), p.source)
    }

    #[test]
    fn defaults_follow_the_documented_table() {
        let (settings, provenance) =
            resolve(&["lotse", "serve", "--socket", "/run/z.sock"]).unwrap();
        assert_eq!(settings.supervisor.socket, PathBuf::from("/run/z.sock"));
        assert_eq!(
            settings.supervisor.udp_listen,
            "[::]:18556".parse().unwrap()
        );
        assert_eq!(
            settings.supervisor.tcp_listen,
            Some("[::]:18556".parse().unwrap())
        );
        assert_eq!(settings.supervisor.limits.max_connections, 8);
        assert_eq!(settings.supervisor.limits.max_streams, 256);
        assert_eq!(settings.supervisor.limits.max_sessions, 256);
        assert_eq!(settings.supervisor.limits.max_sessions_per_stream, 16);
        assert_eq!(
            settings.supervisor.limits.session_grace,
            Duration::from_secs(10)
        );
        assert_eq!(settings.supervisor.limits.worker_threads, 2);
        assert_eq!(settings.supervisor.linger, Duration::from_secs(5));
        assert_eq!(settings.supervisor.connect_concurrency.get(), 4);
        assert_eq!(
            source_of(&provenance, "sources.connect_concurrency"),
            ("4".into(), Source::Default)
        );
        assert_eq!(
            settings.supervisor.allow_uid,
            rustix::process::getuid().as_raw()
        );
        assert_eq!(settings.sandbox.mode, Mode::On);
        assert_eq!((settings.sandbox.uid, settings.sandbox.gid), (65534, 65534));
        assert_eq!(settings.log.format, LogFormat::Json);
        assert_eq!(settings.log.level, "info");
        assert_eq!(settings.log.ignored_rust_log, None);
        assert_eq!(
            source_of(&provenance, "log.level"),
            ("info".into(), Source::Default)
        );
        assert_eq!(
            source_of(&provenance, "socket"),
            ("/run/z.sock".into(), Source::Flag)
        );
        assert_eq!(
            source_of(&provenance, "limits.max_streams"),
            ("256".into(), Source::Default)
        );
        assert_eq!(
            source_of(&provenance, "webrtc.tcp_listen"),
            ("[::]:18556".into(), Source::Default)
        );
    }

    #[test]
    fn the_socket_is_required() {
        let err = resolve(&["lotse", "serve"]).unwrap_err();
        assert!(matches!(err, ConfigError::MissingSocket), "{err}");
        assert!(err.to_string().contains("--socket"));
    }

    #[test]
    fn flags_beat_the_file_and_the_file_beats_defaults() {
        let dir = std::env::temp_dir().join(format!("lotse-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lotse.toml");
        std::fs::write(
            &path,
            "socket = \"/from/file.sock\"\nsandbox = \"off\"\n[webrtc]\ntcp_listen = \"off\"\n[limits]\nmax_streams = 4\n[stream]\nlinger_ms = 1234\n[sources]\nconnect_concurrency = 2\n[log]\nformat = \"text\"\nlevel = \"debug\"\n",
        )
        .unwrap();
        let config = path.to_str().unwrap();
        let (settings, provenance) =
            resolve(&["lotse", "serve", "--config", config, "--linger-ms", "42"]).unwrap();
        assert_eq!(settings.supervisor.socket, PathBuf::from("/from/file.sock"));
        assert_eq!(settings.sandbox.mode, Mode::Off);
        assert_eq!(settings.supervisor.tcp_listen, None);
        assert_eq!(settings.supervisor.limits.max_streams, 4);
        assert_eq!(settings.supervisor.linger, Duration::from_millis(42));
        assert_eq!(settings.supervisor.connect_concurrency.get(), 2);
        assert_eq!(
            source_of(&provenance, "sources.connect_concurrency"),
            ("2".into(), Source::File)
        );
        let (flagged, flagged_provenance) = resolve(&[
            "lotse",
            "serve",
            "--config",
            config,
            "--connect-concurrency",
            "8",
        ])
        .unwrap();
        assert_eq!(flagged.supervisor.connect_concurrency.get(), 8);
        assert_eq!(
            source_of(&flagged_provenance, "sources.connect_concurrency"),
            ("8".into(), Source::Flag)
        );
        assert_eq!(settings.log.format, LogFormat::Text);
        assert_eq!(settings.log.level, "debug");
        assert_eq!(
            source_of(&provenance, "config"),
            (config.to_owned(), Source::Flag)
        );
        assert_eq!(
            source_of(&provenance, "socket"),
            ("/from/file.sock".into(), Source::File)
        );
        assert_eq!(
            source_of(&provenance, "stream.linger_ms"),
            ("42".into(), Source::Flag)
        );
        assert_eq!(
            source_of(&provenance, "limits.max_streams"),
            ("4".into(), Source::File)
        );
        assert_eq!(
            source_of(&provenance, "limits.max_sessions"),
            ("256".into(), Source::Default)
        );
        assert_eq!(
            source_of(&provenance, "webrtc.tcp_listen"),
            ("off".into(), Source::File)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_valid_rust_log_is_the_effective_level_for_every_process() {
        // `RUST_LOG` itself arrives as `EnvVariable` (the subprocess test
        // in `tests/ctl.rs` covers that); the hidden flag is the same arg.
        let (settings, provenance) = resolve(&[
            "lotse",
            "serve",
            "--socket",
            "/s",
            "--log-level",
            "warn",
            "--rust-log",
            "info,lotse_codec=debug",
        ])
        .unwrap();
        assert_eq!(settings.log.level, "info,lotse_codec=debug");
        assert_eq!(settings.log.ignored_rust_log, None);
        assert_eq!(
            source_of(&provenance, "log.level"),
            ("info,lotse_codec=debug".into(), Source::Flag)
        );
        assert_eq!(
            provenance.iter().filter(|p| p.name == "log.level").count(),
            1,
            "one log.level line"
        );
    }

    #[test]
    fn an_invalid_rust_log_is_ignored_and_the_configured_level_applies() {
        let (settings, provenance) = resolve(&[
            "lotse",
            "serve",
            "--socket",
            "/s",
            "--log-level",
            "warn",
            "--rust-log",
            "lotse=loudest",
        ])
        .unwrap();
        assert_eq!(settings.log.level, "warn");
        assert_eq!(
            source_of(&provenance, "log.level"),
            ("warn".into(), Source::Flag)
        );
        let ignored = settings.log.ignored_rust_log.unwrap();
        assert_eq!(ignored.value, "lotse=loudest");
        assert!(
            ignored.reason.contains("error parsing level filter"),
            "{}",
            ignored.reason
        );
    }

    #[test]
    fn rust_log_parses_as_the_subscriber_would() {
        use std::os::unix::ffi::OsStrExt as _;
        assert_eq!(rust_log_filter(None), Ok(None));
        assert_eq!(
            rust_log_filter(Some(OsStr::new("debug"))),
            Ok(Some("debug".to_owned()))
        );
        // Empty parses and means `error`, as before.
        assert_eq!(
            rust_log_filter(Some(OsStr::new(""))),
            Ok(Some(String::new()))
        );
        assert_eq!(
            rust_log_filter(Some(OsStr::from_bytes(b"de\xffbug"))),
            Err(IgnoredRustLog {
                value: "de\u{fffd}bug".to_owned(),
                reason: "not UTF-8".to_owned(),
            })
        );
    }

    /// A writer the test reads back.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What [`log_effective`] logs for `log`.
    fn logged(log: &LogSettings) -> String {
        let mut captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let provenance = [Provenance {
            name: "log.level",
            value: log.level.clone(),
            source: Source::Flag,
        }];
        tracing::subscriber::with_default(subscriber, || log_effective(&provenance, log));
        std::io::Write::flush(&mut captured).unwrap();
        String::from_utf8(captured.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn an_ignored_rust_log_is_a_warning_naming_the_level_that_applies() {
        let mut log = LogSettings {
            format: LogFormat::Text,
            level: "warn".to_owned(),
            ignored_rust_log: None,
        };
        let quiet = logged(&log);
        assert!(quiet.contains("setting=\"log.level\""), "{quiet}");
        assert!(!quiet.contains("WARN"), "{quiet}");
        log.ignored_rust_log = Some(IgnoredRustLog {
            value: "lotse=loudest".to_owned(),
            reason: "bad level".to_owned(),
        });
        let warned = logged(&log);
        let line = warned
            .lines()
            .find(|line| line.contains("RUST_LOG is not a filter directive"))
            .unwrap_or_else(|| panic!("no warning in {warned}"));
        assert!(line.contains("WARN"), "{line}");
        assert!(line.contains("value=lotse=loudest"), "{line}");
        assert!(line.contains("reason=bad level"), "{line}");
        assert!(line.contains("log_level=warn"), "{line}");
    }

    #[test]
    fn a_bad_or_missing_file_is_an_error_with_its_path() {
        let dir = std::env::temp_dir().join(format!("lotse-badconfig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("missing.toml");
        let err = resolve(&["lotse", "serve", "--config", missing.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err}");
        assert!(err.to_string().contains("missing.toml"));

        let typo = dir.join("typo.toml");
        std::fs::write(&typo, "sockett = \"/x\"\n").unwrap();
        let err = resolve(&["lotse", "serve", "--config", typo.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
        assert!(err.to_string().contains("sockett"), "{err}");

        let bad_value = dir.join("bad.toml");
        std::fs::write(&bad_value, "[webrtc]\ntcp_listen = \"nowhere\"\n").unwrap();
        let err =
            resolve(&["lotse", "serve", "--config", bad_value.to_str().unwrap()]).unwrap_err();
        assert!(err.to_string().contains("tcp listen must be"), "{err}");

        let zero = dir.join("zero.toml");
        std::fs::write(&zero, "[sources]\nconnect_concurrency = 0\n").unwrap();
        let err = resolve(&["lotse", "serve", "--config", zero.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
        assert!(err.to_string().contains("connect_concurrency"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn typed_values_parse_print_and_refuse_garbage() {
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!(LogFormat::Text.to_string(), "text");
        assert_eq!(
            "xml".parse::<LogFormat>().unwrap_err().to_string(),
            "log format must be `json` or `text`, not \"xml\""
        );
        assert_eq!("off".parse::<TcpListen>().unwrap(), TcpListen::Off);
        assert_eq!(TcpListen::Off.address(), None);
        let on: TcpListen = "127.0.0.1:1".parse().unwrap();
        assert_eq!(on.to_string(), "127.0.0.1:1");
        assert_eq!(on.address(), Some("127.0.0.1:1".parse().unwrap()));
        assert!(
            "nowhere"
                .parse::<TcpListen>()
                .unwrap_err()
                .to_string()
                .contains("nowhere")
        );
        for (source, name) in [
            (Source::Flag, "flag"),
            (Source::Env, "env"),
            (Source::File, "file"),
            (Source::Default, "default"),
        ] {
            assert_eq!(source.name(), name);
        }
    }
}
