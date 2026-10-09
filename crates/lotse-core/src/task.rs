//! Named task spawning: the one wrapper around `tokio::spawn`, so every task
//! carries a name in its logs and the `disallowed_methods` lint stops
//! everything else from spawning anonymously.
//!
//! The name becomes a `task` span around the future, so every event a task
//! logs says which task it came from. With the `console` feature and
//! `--cfg tokio_unstable`, the task is also spawned under its name through
//! `tokio::task::Builder`, so `tokio-console` lists it by name; that API
//! has no semver guarantee and never reaches a release build.

use std::future::Future;
use std::pin::Pin;

use tokio::task::JoinHandle;
use tracing::Instrument as _;

/// A boxed, sendable future: the return type of trait methods that must
/// stay object-safe (`Source::run`), since `async fn` in traits is not.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Spawns `future` on the current runtime under the name `name`.
///
/// The caller keeps the [`JoinHandle`] as the task's cancellation path, or
/// gives the future its own (a `CancellationToken`, a channel closing).
#[cfg_attr(
    not(all(feature = "console", tokio_unstable)),
    expect(
        clippy::disallowed_methods,
        reason = "the one wrapper around tokio::spawn"
    )
)]
pub fn spawn_named<F>(name: &'static str, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let future = future.instrument(tracing::debug_span!("task", task = name));
    #[cfg(all(feature = "console", tokio_unstable))]
    {
        console::spawn(name, future)
    }
    #[cfg(not(all(feature = "console", tokio_unstable)))]
    {
        tokio::spawn(future)
    }
}

/// Runs `f` on the blocking thread pool under the name `name`.
///
/// For work that blocks a thread (disk I/O, a long computation) and must
/// never run on a runtime worker.
#[cfg_attr(
    not(all(feature = "console", tokio_unstable)),
    expect(
        clippy::disallowed_methods,
        reason = "the one wrapper around tokio::task::spawn_blocking"
    )
)]
pub fn spawn_blocking_named<F, R>(name: &'static str, f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let span = tracing::debug_span!("task", task = name);
    let f = move || span.in_scope(f);
    #[cfg(all(feature = "console", tokio_unstable))]
    {
        console::spawn_blocking(name, f)
    }
    #[cfg(not(all(feature = "console", tokio_unstable)))]
    {
        tokio::task::spawn_blocking(f)
    }
}

/// The named spawns of the `console` feature: development builds with
/// `--cfg tokio_unstable` only.
#[cfg(all(feature = "console", tokio_unstable))]
mod console {
    use std::future::Future;

    use tokio::task::{Builder, JoinHandle};

    /// `future` as a task named `name`.
    #[expect(
        clippy::expect_used,
        reason = "Builder::spawn fails only outside a runtime, where tokio::spawn panics too; console builds are for development"
    )]
    pub(super) fn spawn<F>(name: &'static str, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        Builder::new()
            .name(name)
            .spawn(future)
            .expect("a runtime to spawn on")
    }

    /// `f` on the blocking pool as a task named `name`.
    #[expect(
        clippy::expect_used,
        reason = "Builder::spawn_blocking fails only outside a runtime, where spawn_blocking panics too; console builds are for development"
    )]
    pub(super) fn spawn_blocking<F, R>(name: &'static str, f: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        Builder::new()
            .name(name)
            .spawn_blocking(f)
            .expect("a runtime to spawn on")
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

    #[tokio::test]
    async fn spawn_named_runs_the_future_to_completion() {
        let handle = spawn_named("test.add", async { 40 + 2 });
        assert_eq!(handle.await.unwrap(), 42);
    }

    #[tokio::test]
    async fn spawn_blocking_named_runs_the_closure() {
        let handle = spawn_blocking_named("test.blocking", || "done".len());
        assert_eq!(handle.await.unwrap(), 4);
    }

    #[tokio::test]
    async fn spawn_named_handle_aborts_the_task() {
        let handle = spawn_named("test.pending", std::future::pending::<()>());
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
    }
}
