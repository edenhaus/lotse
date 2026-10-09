//! The log subscriber and the panic hook: JSON or text lines on stderr,
//! filtered by the effective level the configuration resolved (`RUST_LOG`
//! when valid, else `log.level`; workers get it as `--log-level`).
//!
//! Every process kind inherits stderr and tags its lines with the
//! `process` span (`kind`, `pid`). A panic is logged with its message and
//! location before `panic = "abort"` ends the process.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::{Layer as _, SubscriberExt as _};
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
}

/// Installs the global subscriber: log lines filtered by `level`. Reads no
/// environment: `RUST_LOG` is already folded into `level` by
/// [`crate::config`].
pub(crate) fn init(format: LogFormat, level: &str) -> Result<(), LoggingError> {
    let filter = EnvFilter::try_new(level).map_err(|source| LoggingError::Level {
        level: level.to_owned(),
        source,
    })?;
    let lines = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false);
    let registry = tracing_subscriber::registry();
    let installed = match format {
        LogFormat::Json => registry
            .with(
                lines
                    .json()
                    .flatten_event(true)
                    .with_current_span(false)
                    .with_span_list(true)
                    .with_filter(filter),
            )
            .try_init(),
        LogFormat::Text => registry.with(lines.with_filter(filter)).try_init(),
    };
    installed.map_err(|_already| LoggingError::AlreadySet)
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

    use super::*;

    #[test]
    fn a_bad_level_is_an_error_and_a_second_init_is_refused() {
        // Under nextest every test is its own process, so the global
        // subscriber is ours to install exactly once.
        // A bare word is a target filter; a bad level after `=` is the error.
        let err = init(LogFormat::Json, "lotse=loudest").err().unwrap();
        assert!(matches!(err, LoggingError::Level { .. }), "{err}");
        assert!(err.to_string().contains("loudest"));
        init(LogFormat::Text, "debug").unwrap();
        let err = init(LogFormat::Json, "info").err().unwrap();
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
