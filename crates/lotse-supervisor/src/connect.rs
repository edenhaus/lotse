//! The connect gate: at most `sources.connect_concurrency` source
//! connection attempts run at once across the daemon, so a client putting
//! many preloaded cameras at once, as on its restart, does not open every
//! camera connection in the same instant.
//!
//! A worker announces every attempt (`Connecting`, `Reconnecting`) and
//! waits for a grant before it connects. Its driver asks its
//! [`ConnectSlot`] for a permit from the daemon's [`ConnectPermits`]; once
//! the slot holds one, the driver sends the grant. The permit is held
//! while the attempt runs and given back when it ends (`Live`, `Backoff`),
//! when the worker exits or is stopped, when the driver goes, or when the
//! lease runs out, which bounds what a stuck or hostile worker can hold.
//! Waiters are served in order (the semaphore is fair), so no connection
//! starves.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;
use lotse_core::runner::DEFAULT_READY_TIMEOUT;
use lotse_core::task::BoxFuture;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

/// How long a permit may be held for one attempt: the runner gives up on
/// an attempt that is not live after its ready timeout, so a worker still
/// holding the permit later is stuck or hostile, and the permit goes back.
pub(crate) const CONNECT_LEASE: Duration =
    DEFAULT_READY_TIMEOUT.saturating_add(Duration::from_secs(5));

/// The daemon's connect permits, one per attempt that may run at once.
#[derive(Debug)]
pub(crate) struct ConnectPermits {
    /// The permits; never closed.
    semaphore: Arc<Semaphore>,
    /// How many there are.
    limit: usize,
}

impl ConnectPermits {
    /// `limit` permits.
    pub(crate) fn new(limit: NonZeroUsize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit.get())),
            limit: limit.get(),
        }
    }

    /// The attempts holding a permit now.
    pub(crate) fn in_flight(&self) -> usize {
        self.limit
            .saturating_sub(self.semaphore.available_permits())
    }
}

/// What a slot has for its driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotWake {
    /// A permit is held for the announced attempt: send the grant.
    Grant,
    /// The attempt held its permit past the lease; it was given back.
    LeaseExpired,
}

/// Where a slot is.
enum SlotState {
    /// No attempt is waiting or running under a permit.
    Free,
    /// An attempt waits for a permit.
    Waiting {
        /// The place in the semaphore's queue.
        acquire: BoxFuture<'static, Result<OwnedSemaphorePermit, AcquireError>>,
        /// When the wait began.
        since: Instant,
    },
    /// An attempt holds a permit.
    Held {
        /// The permit; dropping it gives it back.
        _permit: OwnedSemaphorePermit,
        /// The lease's end.
        lease: BoxFuture<'static, ()>,
        /// The grant for the current attempt went to the driver.
        granted: bool,
    },
}

/// One connection's place at the gate: at most one permit, for the
/// attempt its worker announced last.
pub(crate) struct ConnectSlot {
    /// Where it is.
    state: SlotState,
    /// The clock of the wait times and the lease.
    clock: Arc<dyn Clock>,
    /// How long a permit may be held for one attempt.
    lease: Duration,
}

impl std::fmt::Debug for ConnectSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &self.state {
            SlotState::Free => "free",
            SlotState::Waiting { .. } => "waiting",
            SlotState::Held { .. } => "held",
        };
        f.debug_struct("ConnectSlot")
            .field("state", &state)
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

impl ConnectSlot {
    /// A free slot whose permits are leased for `lease` on `clock`.
    pub(crate) fn new(clock: Arc<dyn Clock>, lease: Duration) -> Self {
        Self {
            state: SlotState::Free,
            clock,
            lease,
        }
    }

    /// Whether the slot holds a permit.
    #[cfg(test)]
    pub(crate) const fn holds(&self) -> bool {
        matches!(self.state, SlotState::Held { .. })
    }

    /// The worker announced an attempt (`reason`): take a permit for it, or
    /// queue for one. An attempt announced while a permit is held runs
    /// under that permit with a new grant but within the same lease, so
    /// announcing again never keeps a permit longer.
    pub(crate) fn request(&mut self, permits: &ConnectPermits, reason: &'static str) {
        match &mut self.state {
            SlotState::Free => {
                if let Ok(permit) = Arc::clone(&permits.semaphore).try_acquire_owned() {
                    let in_flight = permits.in_flight();
                    tracing::debug!(reason, in_flight, "connect permit taken");
                    self.hold(permit);
                } else {
                    tracing::info!(
                        reason,
                        limit = permits.limit,
                        "connect waits for a permit: sources.connect_concurrency attempts are in flight"
                    );
                    self.state = SlotState::Waiting {
                        acquire: Box::pin(Arc::clone(&permits.semaphore).acquire_owned()),
                        since: self.clock.now(),
                    };
                }
            }
            SlotState::Waiting { .. } => {
                tracing::debug!(reason, "connect already waits for a permit");
            }
            SlotState::Held { granted, .. } => {
                tracing::debug!(reason, "a new attempt under the held connect permit");
                *granted = false;
            }
        }
    }

    /// The attempt is over (`reason`): the permit goes back, or the wait
    /// for one ends.
    pub(crate) fn release(&mut self, reason: &'static str) {
        match std::mem::replace(&mut self.state, SlotState::Free) {
            SlotState::Free => {}
            SlotState::Waiting { .. } => {
                tracing::debug!(reason, "connect wait abandoned");
            }
            SlotState::Held { .. } => tracing::debug!(reason, "connect permit released"),
        }
    }

    /// Holds `permit` for an attempt whose grant is still to be sent.
    fn hold(&mut self, permit: OwnedSemaphorePermit) {
        self.state = SlotState::Held {
            _permit: permit,
            lease: self.clock.sleep(self.lease),
            granted: false,
        };
    }

    /// What the driver must act on next; never while the slot is free or
    /// the granted attempt runs within its lease. Cancel-safe: a waiting
    /// slot keeps its place in the queue.
    pub(crate) async fn wait(&mut self) -> SlotWake {
        loop {
            match &mut self.state {
                SlotState::Free => std::future::pending::<()>().await,
                SlotState::Waiting { acquire, since } => {
                    let since = *since;
                    match acquire.await {
                        Ok(permit) => {
                            let waited = self.clock.now().saturating_duration_since(since);
                            let waited_ms = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX);
                            tracing::info!(waited_ms, "connect permit granted after waiting");
                            self.hold(permit);
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "connect permits closed; the attempt is not granted");
                            self.state = SlotState::Free;
                        }
                    }
                }
                SlotState::Held { granted, .. } if !*granted => {
                    *granted = true;
                    return SlotWake::Grant;
                }
                SlotState::Held { lease, .. } => {
                    lease.await;
                    let lease_ms = u64::try_from(self.lease.as_millis()).unwrap_or(u64::MAX);
                    tracing::warn!(lease_ms, "connect permit held past its lease; given back");
                    self.state = SlotState::Free;
                    return SlotWake::LeaseExpired;
                }
            }
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

    fn slots(clock: &Arc<FakeClock>, count: usize) -> Vec<ConnectSlot> {
        (0..count)
            .map(|_| ConnectSlot::new(clock.clone(), CONNECT_LEASE))
            .collect()
    }

    /// The slot's wake if one is ready within a few scheduler turns.
    async fn ready(slot: &mut ConnectSlot) -> Option<SlotWake> {
        for _ in 0..10 {
            tokio::select! {
                biased;
                wake = slot.wait() => return Some(wake),
                () = tokio::task::yield_now() => {}
            }
        }
        None
    }

    fn permits(limit: usize) -> ConnectPermits {
        ConnectPermits::new(NonZeroUsize::new(limit).unwrap())
    }

    #[tokio::test]
    async fn six_connections_with_four_permits_connect_four_at_a_time_in_order() {
        let clock = Arc::new(FakeClock::default());
        let permits = permits(4);
        let mut slots = slots(&clock, 6);
        for slot in &mut slots {
            slot.request(&permits, "connecting");
        }
        assert_eq!(permits.in_flight(), 4);
        for slot in &mut slots[..4] {
            assert_eq!(ready(slot).await, Some(SlotWake::Grant));
            assert_eq!(ready(slot).await, None, "one grant per attempt");
        }
        for slot in &mut slots[4..] {
            assert_eq!(ready(slot).await, None, "the fifth and sixth wait");
            assert!(!slot.holds());
        }
        // The first goes live: the fifth starts, the sixth still waits.
        slots[0].release("live");
        assert_eq!(ready(&mut slots[4]).await, Some(SlotWake::Grant));
        assert_eq!(ready(&mut slots[5]).await, None);
        assert_eq!(permits.in_flight(), 4);
        // The second fails into its backoff: the sixth starts.
        slots[1].release("backoff");
        assert_eq!(ready(&mut slots[5]).await, Some(SlotWake::Grant));
        assert_eq!(permits.in_flight(), 4);
        // Never more than four: the first reconnecting waits in turn.
        slots[0].request(&permits, "reconnecting");
        assert_eq!(ready(&mut slots[0]).await, None);
        assert_eq!(permits.in_flight(), 4);
        slots[2].release("worker exited");
        assert_eq!(ready(&mut slots[0]).await, Some(SlotWake::Grant));
        for slot in &mut slots {
            slot.release("stopped");
        }
        assert_eq!(permits.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_slot_given_up_while_waiting_leaves_the_queue_and_dropping_one_frees_its_permit() {
        let clock = Arc::new(FakeClock::default());
        let permits = permits(1);
        let mut slots = slots(&clock, 3);
        slots[0].request(&permits, "connecting");
        slots[1].request(&permits, "connecting");
        slots[2].request(&permits, "connecting");
        // Another announcement while waiting changes nothing.
        slots[1].request(&permits, "connecting");
        // The second's worker is stopped while it waits.
        slots[1].release("worker stopped");
        // The first's driver goes away with its permit (a crashed or
        // deleted connection): the third is next.
        let first = slots.remove(0);
        assert!(first.holds());
        drop(first);
        assert_eq!(ready(&mut slots[1]).await, Some(SlotWake::Grant));
        assert_eq!(ready(&mut slots[0]).await, None);
        assert_eq!(permits.in_flight(), 1);
        drop(slots);
        assert_eq!(permits.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_new_attempt_under_a_held_permit_gets_a_new_grant_within_the_same_lease() {
        let clock = Arc::new(FakeClock::default());
        let permits = permits(1);
        let mut slot = ConnectSlot::new(clock.clone(), Duration::from_secs(10));
        slot.request(&permits, "connecting");
        assert_eq!(ready(&mut slot).await, Some(SlotWake::Grant));
        clock.advance(Duration::from_secs(9));
        assert_eq!(ready(&mut slot).await, None);
        // Announced again under the permit: a grant, but no longer lease,
        // so a worker that keeps announcing cannot keep the permit.
        slot.request(&permits, "reconnecting");
        assert_eq!(ready(&mut slot).await, Some(SlotWake::Grant));
        assert_eq!(ready(&mut slot).await, None);
        clock.advance(Duration::from_secs(1));
        assert_eq!(ready(&mut slot).await, Some(SlotWake::LeaseExpired));
        assert!(!slot.holds());
        assert_eq!(
            permits.in_flight(),
            0,
            "a stuck worker gives the permit back"
        );
        assert_eq!(ready(&mut slot).await, None);
        assert!(format!("{slot:?}").contains("free"));
        drop(slot);
    }

    #[tokio::test]
    async fn a_closed_gate_grants_nothing_to_a_waiting_slot() {
        let clock = Arc::new(FakeClock::default());
        let permits = permits(1);
        let mut slots = slots(&clock, 2);
        slots[0].request(&permits, "connecting");
        slots[1].request(&permits, "connecting");
        assert!(format!("{:?}", slots[1]).contains("waiting"));
        assert!(format!("{:?}", slots[0]).contains("held"));
        assert_eq!(CONNECT_LEASE, Duration::from_secs(35));
        clock.advance(Duration::from_millis(1500));
        permits.semaphore.close();
        assert_eq!(ready(&mut slots[1]).await, None);
        assert!(!slots[1].holds(), "nothing to grant once closed");
    }
}
