//! Named task spawning: the one wrapper around `tokio::spawn`, so every task
//! carries a name in its logs and the `disallowed_methods` lint stops
//! everything else from spawning anonymously.
//!
//! The name becomes a `task` span around the future, so every event a task
//! logs says which task it came from.

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
#[expect(
    clippy::disallowed_methods,
    reason = "the one wrapper around tokio::spawn"
)]
pub fn spawn_named<F>(name: &'static str, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future.instrument(tracing::debug_span!("task", task = name)))
}

/// Runs `f` on the blocking thread pool under the name `name`.
///
/// For work that blocks a thread (disk I/O, a long computation) and must
/// never run on a runtime worker.
#[expect(
    clippy::disallowed_methods,
    reason = "the one wrapper around tokio::task::spawn_blocking"
)]
pub fn spawn_blocking_named<F, R>(name: &'static str, f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let span = tracing::debug_span!("task", task = name);
    tokio::task::spawn_blocking(move || span.in_scope(f))
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
