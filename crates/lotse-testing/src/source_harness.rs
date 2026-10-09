//! Runs any [`Source`] the way core's runner does, for the conformance
//! tests of a protocol crate: a track set, a source context with the
//! connection's clock mapper, cancellation, and the exit.

use std::sync::Arc;

use lotse_core::clock::Clock;
use lotse_core::clock_map::ClockMapper;
use lotse_core::source::{
    BackchannelSlot, ClockInput, ClockReport, ResolvedPeer, Source, SourceCtx, SourceExit, TrackSet,
};
use lotse_core::task::spawn_named;
use lotse_core::track::TrackLimits;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// One connection attempt of a source, running in a task.
#[derive(Debug)]
pub struct Harness {
    /// The tracks the source declares.
    pub tracks: Arc<TrackSet>,
    /// The sync hints the source reported.
    pub reports: mpsc::Receiver<ClockReport>,
    /// The mapper the hints belong to.
    pub mapper: Arc<ClockMapper>,
    /// Ends the attempt.
    cancel: CancellationToken,
    /// The attempt.
    run: JoinHandle<SourceExit>,
}

impl Harness {
    /// Starts `source` against `peer`.
    pub fn start(source: &dyn Source, peer: ResolvedPeer, clock: Arc<dyn Clock>) -> Self {
        let tracks = TrackSet::new(TrackLimits::default(), clock.now());
        let mapper = Arc::new(ClockMapper::new());
        let (clock_input, reports) = ClockInput::channel(Arc::clone(&mapper));
        let cancel = CancellationToken::new();
        let ctx = SourceCtx {
            peer,
            tracks: tracks.publisher(),
            clock: clock_input,
            time: clock,
            backchannel: BackchannelSlot::default(),
            cancel: cancel.clone(),
        };
        let run = spawn_named("harness.source", source.run(ctx));
        Self {
            tracks,
            reports,
            mapper,
            cancel,
            run,
        }
    }

    /// Waits until the source reports ready; `false` if it exited first.
    pub async fn wait_ready(&mut self) -> bool {
        let mut ready = self.tracks.ready();
        loop {
            if *ready.borrow_and_update() {
                return true;
            }
            tokio::select! {
                changed = ready.changed() => {
                    if changed.is_err() {
                        return false;
                    }
                }
                () = std::future::poll_fn(|cx| {
                    if self.run.is_finished() {
                        std::task::Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                }) => return false,
            }
        }
    }

    /// Cancels the attempt.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Waits for the source to exit and returns how.
    pub async fn finish(self) -> SourceExit {
        self.run.await.unwrap_or_else(|err| {
            SourceExit::Ended(lotse_core::source::SourceError::Protocol(format!(
                "the source task failed: {err}"
            )))
        })
    }
}
