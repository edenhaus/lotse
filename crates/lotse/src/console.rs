//! `tokio-console` support for development.
//!
//! Only a build with the `console` feature and `--cfg tokio_unstable` has
//! a console: the supervisor's subscriber carries the console layer beside
//! its log lines, and the layer's gRPC server (console-subscriber's default,
//! `127.0.0.1:6669`) starts on a thread of its own once the sandbox is
//! applied, so the thread is under it. Landlock lets the supervisor bind
//! only the sockets it bound before, so on Linux the console needs
//! `--sandbox off`; a failed bind is logged and the daemon serves on.
//! Workers carry no console: they would all bind the same port. Every
//! other build has a stand-in that does nothing, apart from a warning when
//! the feature is on without the cfg.

#[cfg(all(feature = "console", tokio_unstable))]
pub(crate) use enabled::{Server, layer, start};
#[cfg(not(all(feature = "console", tokio_unstable)))]
pub(crate) use stand_in::{Server, layer, start};

/// The console of a `console` build with `--cfg tokio_unstable`.
#[cfg(all(feature = "console", tokio_unstable))]
mod enabled {
    use console_subscriber::ConsoleLayer;
    pub(crate) use console_subscriber::Server;
    use tracing_subscriber::Registry;
    use tracing_subscriber::filter::FilterFn;
    use tracing_subscriber::layer::Layer as _;

    /// The console layer and its server, when `wanted` (the supervisor).
    /// The layer sees the runtime's spans and events only, as
    /// console-subscriber's own `spawn` filters them, so it enables no
    /// other callsite.
    pub(crate) fn layer(
        wanted: bool,
    ) -> (
        Option<impl tracing_subscriber::Layer<Registry> + Send + Sync>,
        Option<Server>,
    ) {
        if !wanted {
            return (None, None);
        }
        let (layer, server) = ConsoleLayer::builder().build();
        let runtime = FilterFn::new(|meta: &tracing::Metadata<'_>| {
            if meta.is_event() {
                meta.target().starts_with("runtime") || meta.target().starts_with("tokio")
            } else {
                meta.name().starts_with("runtime.") || meta.target().starts_with("tokio")
            }
        });
        (Some(layer.with_filter(runtime)), Some(server))
    }

    /// Serves the console on a thread with its own runtime. Call it after
    /// the sandbox: a thread started before would escape it.
    pub(crate) fn start(server: Option<Server>) {
        let Some(server) = server else {
            return;
        };
        let started = std::thread::Builder::new()
            .name("lotse-console".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        tracing::warn!(error = %err, "tokio-console runtime did not start");
                        return;
                    }
                };
                if let Err(err) = runtime.block_on(server.serve()) {
                    tracing::warn!(error = %err, "tokio-console server stopped");
                }
            });
        match started {
            Ok(_thread) => tracing::info!(
                ip = %Server::DEFAULT_IP,
                port = Server::DEFAULT_PORT,
                "tokio-console server starting"
            ),
            Err(err) => tracing::warn!(error = %err, "tokio-console thread did not start"),
        }
    }
}

/// The stand-in of every other build.
#[cfg(not(all(feature = "console", tokio_unstable)))]
mod stand_in {
    use tracing_subscriber::layer::Identity;

    /// No server; never made.
    #[derive(Debug)]
    pub(crate) enum Server {}

    /// Neither a layer nor a server; [`Identity`] stands in for the layer's
    /// type.
    pub(crate) const fn layer(_wanted: bool) -> (Option<Identity>, Option<Server>) {
        (None, None)
    }

    /// Nothing to start; a `console` build without the cfg says why.
    pub(crate) fn start(server: Option<Server>) {
        if let Some(server) = server {
            match server {}
        }
        #[cfg(feature = "console")]
        tracing::warn!(
            "built with the console feature but without --cfg tokio_unstable: no tokio-console"
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

    use std::sync::{Arc, Mutex};

    use super::*;

    /// A log writer that keeps every line.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn only_a_console_build_without_the_cfg_warns_that_it_has_no_console() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || start(None));
        let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            logs.contains("without --cfg tokio_unstable: no tokio-console"),
            cfg!(all(feature = "console", not(tokio_unstable))),
            "{logs}"
        );
    }

    #[test]
    fn a_console_exists_only_when_wanted_in_a_console_build() {
        let (none, no_server) = layer(false);
        assert!(none.is_none() && no_server.is_none());
        start(no_server);
        let (console, server) = layer(true);
        let built = cfg!(all(feature = "console", tokio_unstable));
        assert_eq!((console.is_some(), server.is_some()), (built, built));
        // Never started here: it would bind the console's port.
    }
}
