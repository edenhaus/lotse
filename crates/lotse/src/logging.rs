//! The log subscriber and the panic hook: JSON or text lines on stderr,
//! filtered by the effective level the configuration resolved (`RUST_LOG`
//! when valid, else `log.level`; workers get it as `--log-level`).
//!
//! Every process kind inherits stderr and tags its lines with the
//! `process` span (`kind`, `pid`). A panic is logged with its message and
//! location before `panic = "abort"` ends the process.
//!
//! The crates that log through the `log` facade instead of `tracing`
//! (retina, dimpl, sctp-proto, mpeg2ts-reader, symphonia, tungstenite) reach
//! the same subscriber through tracing-log, under the same filter, each call
//! site throttled like lotse's own repeating media-path conditions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use lotse_core::clock::Clock;
use lotse_core::throttle::Throttle;
use tracing_log::{AsLog as _, LogTracer};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::config::LogFormat;

/// Why logging could not start.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LoggingError {
    /// `log.level` is not a level or filter directive.
    #[error("log level {level:?} is not a level or filter directive: {source}")]
    Level {
        /// The offending text.
        level: String,
        /// The parser's error.
        #[source]
        source: tracing_subscriber::filter::ParseError,
    },
    /// A subscriber was already installed.
    #[error("a log subscriber is already installed")]
    AlreadySet,
    /// A `log` logger was already installed.
    #[error("a `log` logger is already installed")]
    LogAlreadySet,
}

/// Where a `log` record was logged: its module, file and line, `'static`
/// when the `log` macros made the record. Records built at run time without
/// them share one key.
type CallSite = (Option<&'static str>, Option<&'static str>, Option<u32>);

/// The `log` logger: forwards each record through tracing-log as a
/// `tracing` event with its target, module, file and line, so the filter
/// and output of lotse's own events apply to it. Several of these crates
/// log once per packet a camera, server or browser sent (an unknown RTCP
/// SSRC, an SCTP packet that does not parse, a damaged MPEG-TS packet), so
/// every call site is throttled: its first record is logged, then at most
/// one per [`lotse_core::throttle::SUMMARY_INTERVAL`] with the count.
struct Bridge {
    /// Applies the subscriber's filter to a record and forwards it.
    tracer: LogTracer,
    /// The time each record is counted at.
    clock: Arc<dyn Clock>,
    /// One throttle per call site; call sites are fixed in the code, so it
    /// stays small.
    throttles: Mutex<HashMap<CallSite, Throttle>>,
}

impl Bridge {
    /// A bridge counting time on `clock`, with no call site seen yet.
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            tracer: LogTracer::new(),
            clock,
            throttles: Mutex::default(),
        }
    }
}

impl log::Log for Bridge {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        self.tracer.enabled(metadata)
    }

    /// Forwards `record` when the filter takes it and its call site's
    /// throttle lets it through; a record the filter drops is not counted.
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let site = (
            record.module_path_static(),
            record.file_static(),
            record.line(),
        );
        let now = self.clock.now();
        let due = self
            .throttles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(site)
            .or_default()
            .hit(now);
        match due {
            None => {}
            Some(1) => self.tracer.log(record),
            Some(count) => self.tracer.log(
                &log::Record::builder()
                    .metadata(record.metadata().clone())
                    .module_path(record.module_path())
                    .file(record.file())
                    .line(record.line())
                    .args(format_args!(
                        "{} ({count} occurrences since the last line)",
                        record.args()
                    ))
                    .build(),
            ),
        }
    }

    fn flush(&self) {}
}

/// The subscriber [`init`] installs: `filter` as a layer of its own, then
/// JSON or text lines to `writer`. As its own layer the filter answers
/// `enabled`, which the [`Bridge`] asks with a record's target before it
/// counts the record; a per-layer filter would answer `true` there and drop
/// the event only later, so a filtered-out `log` record would still count.
fn subscriber<W>(
    format: LogFormat,
    filter: EnvFilter,
    writer: W,
) -> Box<dyn tracing::Subscriber + Send + Sync>
where
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    let lines = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_target(false);
    let registry = tracing_subscriber::registry().with(filter);
    match format {
        LogFormat::Json => Box::new(
            registry.with(
                lines
                    .json()
                    .flatten_event(true)
                    .with_current_span(false)
                    .with_span_list(true),
            ),
        ),
        LogFormat::Text => Box::new(registry.with(lines)),
    }
}

/// Installs the global subscriber: log lines filtered by `level`, and the
/// [`Bridge`] that brings the `log` records to it, throttled on `clock`.
/// Reads no environment: `RUST_LOG` is already folded into `level` by
/// [`crate::config`].
pub(crate) fn init(
    format: LogFormat,
    level: &str,
    clock: Arc<dyn Clock>,
) -> Result<(), LoggingError> {
    let filter = EnvFilter::try_new(level).map_err(|source| LoggingError::Level {
        level: level.to_owned(),
        source,
    })?;
    subscriber(format, filter, std::io::stderr)
        .try_init()
        .map_err(|_already| LoggingError::AlreadySet)?;
    log::set_boxed_logger(Box::new(Bridge::new(clock)))
        .map_err(|_already| LoggingError::LogAlreadySet)?;
    // `log` skips a record above this before asking the bridge, as cheap
    // as a disabled `tracing` event.
    log::set_max_level(tracing::level_filters::LevelFilter::current().as_log());
    Ok(())
}

/// A plain text subscriber for errors raised before [`init`] ran, or when
/// it failed. Does nothing if a subscriber exists.
pub(crate) fn ensure_fallback() {
    let _already_installed = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

/// Logs a panic's message and location before the process aborts.
pub(crate) fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_owned());
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()));
        tracing::error!(
            panic.message = %message,
            panic.location = location.as_deref().unwrap_or("unknown"),
            "panic; the process aborts"
        );
    }));
}

/// Runs `f` under a text subscriber of its own and returns the lines it
/// logged. They go through a pipe, whose read end sees the end once the
/// subscriber, holding every write end, is dropped with `f` done; a pipe
/// holds far more than a test logs.
#[cfg(test)]
pub(crate) fn capture_logs(f: impl FnOnce()) -> String {
    use std::io::Read as _;
    let (mut reader, writer) = std::io::pipe().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.try_clone().unwrap())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let mut logs = String::new();
    reader.read_to_string(&mut logs).unwrap();
    logs
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::Duration;

    use log::{Level, Log as _};
    use lotse_core::clock::FakeClock;
    use lotse_core::throttle::SUMMARY_INTERVAL;

    use super::*;

    /// A fake clock, shared with the bridge that counts on it.
    fn clock() -> Arc<FakeClock> {
        Arc::new(FakeClock::from_system())
    }

    /// The metadata of a `level` record of `target`.
    fn metadata(level: Level, target: &str) -> log::Metadata<'_> {
        log::Metadata::builder().level(level).target(target).build()
    }

    /// Logs `message` at `level` through `bridge`, from `line` of a stand-in
    /// for retina's RTP module, the way the `log` macros build a record.
    fn log_at(bridge: &Bridge, level: Level, line: u32, message: &str) {
        bridge.log(
            &log::Record::builder()
                .level(level)
                .target("retina::client::rtp")
                .module_path_static(Some("retina::client::rtp"))
                .file_static(Some("src/client/rtp.rs"))
                .line(Some(line))
                .args(format_args!("{message}"))
                .build(),
        );
    }

    #[test]
    fn a_log_call_site_is_logged_once_then_once_per_interval_with_the_count() {
        let clock = clock();
        let bridge = Bridge::new(clock.clone());
        let logs = capture_logs(|| {
            log_at(&bridge, Level::Warn, 312, "saw unknown rtcp ssrc");
            clock.advance(Duration::from_secs(1));
            log_at(&bridge, Level::Warn, 312, "saw unknown rtcp ssrc");
            // Another call site has a throttle of its own.
            log_at(&bridge, Level::Info, 187, "skipping out-of-order seq");
            clock.advance(SUMMARY_INTERVAL);
            log_at(&bridge, Level::Warn, 312, "saw unknown rtcp ssrc");
        });
        let lines: Vec<&str> = logs.lines().collect();
        assert_eq!(lines.len(), 3, "{logs}");
        assert!(lines[0].contains("WARN"), "{logs}");
        assert!(lines[0].contains("saw unknown rtcp ssrc"), "{logs}");
        assert!(!lines[0].contains("occurrences"), "{logs}");
        assert!(lines[0].contains("retina::client::rtp"), "{logs}");
        assert!(lines[1].contains("INFO"), "{logs}");
        assert!(lines[1].contains("skipping out-of-order seq"), "{logs}");
        assert!(
            lines[2].contains("saw unknown rtcp ssrc (2 occurrences since the last line)"),
            "{logs}"
        );
    }

    #[test]
    fn the_filter_applies_to_log_records_and_a_dropped_one_is_not_counted() {
        let bridge = Bridge::new(clock());
        let filtered = subscriber(
            LogFormat::Text,
            EnvFilter::new("info,retina=error"),
            std::io::sink,
        );
        tracing::subscriber::with_default(filtered, || {
            assert!(!bridge.enabled(&metadata(Level::Warn, "retina::client")));
            assert!(bridge.enabled(&metadata(Level::Error, "retina::client")));
            assert!(bridge.enabled(&metadata(Level::Warn, "sctp_proto")));
        });
        let logs = capture_logs(|| {
            log_at(&bridge, Level::Debug, 312, "below the level");
            log_at(&bridge, Level::Warn, 312, "first at the level");
        });
        assert!(!logs.contains("below the level"), "{logs}");
        assert!(logs.contains("first at the level"), "{logs}");
        assert!(!logs.contains("occurrences"), "{logs}");
    }

    #[test]
    fn a_log_logger_already_installed_is_refused() {
        // Under nextest every test is its own process, so the global
        // `log` logger is ours to install.
        log::set_boxed_logger(Box::new(Bridge::new(clock()))).unwrap();
        let err = init(LogFormat::Text, "info", clock()).err().unwrap();
        assert!(matches!(err, LoggingError::LogAlreadySet), "{err}");
        assert_eq!(err.to_string(), "a `log` logger is already installed");
    }

    #[test]
    fn a_bad_level_is_an_error_and_a_second_init_is_refused() {
        // Under nextest every test is its own process, so the global
        // subscriber is ours to install exactly once.
        // A bare word is a target filter; a bad level after `=` is the error.
        let err = init(LogFormat::Json, "lotse=loudest", clock())
            .err()
            .unwrap();
        assert!(matches!(err, LoggingError::Level { .. }), "{err}");
        assert!(err.to_string().contains("loudest"));
        init(LogFormat::Text, "debug", clock()).unwrap();
        // The bridge is the `log` logger, and `log` skips what the filter
        // would drop before asking it.
        assert_eq!(log::max_level(), log::LevelFilter::Debug);
        assert!(log::logger().enabled(&metadata(Level::Debug, "retina")));
        assert!(!log::logger().enabled(&metadata(Level::Trace, "retina")));
        log::logger().flush();
        let err = init(LogFormat::Json, "info", clock()).err().unwrap();
        assert!(matches!(err, LoggingError::AlreadySet), "{err}");
        assert_eq!(err.to_string(), "a log subscriber is already installed");
        ensure_fallback();
        install_panic_hook();
        tracing::info!("still logs after the hook is installed");
    }

    #[test]
    fn the_panic_hook_logs_the_message_and_location_of_every_payload() {
        // Tests unwind (Cargo ignores `panic = "abort"` for them), so the
        // hook runs and the panic is caught here.
        install_panic_hook();
        let logs = capture_logs(|| {
            let caught = [
                std::panic::catch_unwind(|| panic!("a static message")),
                std::panic::catch_unwind(|| panic!("a formatted message {}", 7)),
                std::panic::catch_unwind(|| std::panic::panic_any(7_u32)),
            ];
            assert!(caught.iter().all(Result::is_err));
        });
        drop(std::panic::take_hook());
        assert_eq!(
            logs.matches("panic; the process aborts").count(),
            3,
            "{logs}"
        );
        for message in [
            "panic.message=a static message",
            "panic.message=a formatted message 7",
            "panic.message=non-string panic payload",
        ] {
            assert!(logs.contains(message), "{message}: {logs}");
        }
        // Each line points at its `panic!` here.
        assert_eq!(logs.matches(file!()).count(), 3, "{logs}");
    }
}
