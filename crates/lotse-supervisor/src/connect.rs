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
//!
//! Attempts a viewer waits for come first: a slot whose connection has a
//! viewer session ([`ConnectSlot::want`]) queues ahead of every slot whose
//! connection only preloaded streams want, so a viewer's offer does not
//! wait behind a restart's worth of preload retries. Within each of the
//! two queues attempts are served in the order they queued. A queued slot
//! whose connection gains its first viewer moves to the viewers' queue,
//! and one whose last viewer leaves moves back, each by its original
//! place in line, so an attempt never loses its turn to one that queued
//! after it at the same priority. A preload retry waits while viewers'
//! attempts queue; those are bounded by the connections with viewers, and
//! each ends within its lease.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;
use lotse_core::runner::DEFAULT_READY_TIMEOUT;
use lotse_core::task::BoxFuture;

/// How long a permit may be held for one attempt or backchannel probe:
/// the runner gives up on an attempt that is not live after its ready
/// timeout, and a source on its probe after
/// [`PROBE_TIMEOUT`](lotse_core::runner::PROBE_TIMEOUT), so a worker
/// still holding the permit later is stuck or hostile, and the permit goes
/// back. The 5 s beyond either cover the grant's way to the worker and the
/// permit's way back.
pub(crate) const CONNECT_LEASE: Duration =
    DEFAULT_READY_TIMEOUT.saturating_add(Duration::from_secs(5));

/// The gate's books, kept under its lock. Invariant, after every change:
/// a permit is free only while no attempt queues, since freeing one grants
/// it to the next queued attempt at once.
#[derive(Debug)]
struct Books {
    /// Permits neither held nor granted.
    available: usize,
    /// The next ticket's number: tickets number the attempts in the order
    /// they queued.
    next: u64,
    /// The queued attempts a viewer waits for, by ticket, each with the
    /// waker of the driver that last waited on it.
    wanted: BTreeMap<u64, Option<Waker>>,
    /// The other queued attempts (preloads), the same way.
    background: BTreeMap<u64, Option<Waker>>,
    /// The tickets granted a permit their slot has not taken yet; each
    /// counts as held.
    granted: BTreeSet<u64>,
}

impl Books {
    /// Grants the free permits to the queued attempts, those a viewer
    /// waits for first, each queue in its order, and wakes their drivers.
    fn grant_queued(&mut self) {
        while self.available > 0 {
            let Some((ticket, waker)) = self
                .wanted
                .pop_first()
                .or_else(|| self.background.pop_first())
            else {
                return;
            };
            self.available = self.available.saturating_sub(1);
            self.granted.insert(ticket);
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    /// Gives a permit back and grants it to the next queued attempt.
    fn give_back(&mut self) {
        self.available = self.available.saturating_add(1);
        self.grant_queued();
    }
}

/// Locks `books`. A panic aborts the process (`panic = "abort"`), so a
/// poisoned lock cannot be seen; its books are taken as they are.
fn lock(books: &Mutex<Books>) -> MutexGuard<'_, Books> {
    books.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The daemon's connect permits, one per attempt that may run at once.
#[derive(Debug)]
pub(crate) struct ConnectPermits {
    /// The books every slot, ticket and permit shares.
    books: Arc<Mutex<Books>>,
    /// How many permits there are.
    limit: usize,
}

impl ConnectPermits {
    /// `limit` permits.
    pub(crate) fn new(limit: NonZeroUsize) -> Self {
        Self {
            books: Arc::new(Mutex::new(Books {
                available: limit.get(),
                next: 0,
                wanted: BTreeMap::new(),
                background: BTreeMap::new(),
                granted: BTreeSet::new(),
            })),
            limit: limit.get(),
        }
    }

    /// The attempts holding a permit now, granted ones not yet taken
    /// included.
    pub(crate) fn in_flight(&self) -> usize {
        self.limit.saturating_sub(lock(&self.books).available)
    }

    /// A free permit, if there is one; none is free while attempts queue.
    fn try_take(&self) -> Option<Permit> {
        let mut books = lock(&self.books);
        books.available = books.available.checked_sub(1)?;
        drop(books);
        Some(Permit {
            books: Arc::clone(&self.books),
        })
    }

    /// A place in the queue of attempts a viewer waits for (`wanted`) or
    /// of the others. A permit given back since the caller's failed
    /// [`try_take`](Self::try_take) found nobody queued; it is granted
    /// here, with the queue's order, so no attempt waits beside a free
    /// permit.
    fn queue(&self, wanted: bool) -> Ticket {
        let mut books = lock(&self.books);
        let number = books.next;
        books.next = books.next.wrapping_add(1);
        if wanted {
            books.wanted.insert(number, None);
        } else {
            books.background.insert(number, None);
        }
        books.grant_queued();
        drop(books);
        Ticket {
            books: Arc::clone(&self.books),
            number,
        }
    }
}

/// One permit held for an attempt; dropping it gives it back.
#[derive(Debug)]
#[clippy::has_significant_drop]
struct Permit {
    /// The books it goes back to.
    books: Arc<Mutex<Books>>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        lock(&self.books).give_back();
    }
}

/// An attempt's place in the gate's queue; dropping it leaves the queue,
/// and gives back a permit granted to it but not taken.
#[derive(Debug)]
struct Ticket {
    /// The books it queues in.
    books: Arc<Mutex<Books>>,
    /// Its number, its place in line.
    number: u64,
}

impl Ticket {
    /// Moves the ticket to the queue of attempts a viewer waits for
    /// (`wanted`) or to the other, at its place in line; a ticket already
    /// there, or granted, stays.
    fn set_wanted(&self, wanted: bool) {
        let mut books = lock(&self.books);
        let Books {
            wanted: viewers,
            background,
            ..
        } = &mut *books;
        let (from, to) = if wanted {
            (background, viewers)
        } else {
            (viewers, background)
        };
        if let Some(waker) = from.remove(&self.number) {
            to.insert(self.number, waker);
        }
        drop(books);
    }

    /// The permit once granted; until then the driver's waker is kept for
    /// the grant, under the same lock, so no grant goes unnoticed.
    fn poll_take(&self, cx: &Context<'_>) -> Poll<Permit> {
        let mut books = lock(&self.books);
        if books.granted.remove(&self.number) {
            drop(books);
            return Poll::Ready(Permit {
                books: Arc::clone(&self.books),
            });
        }
        let number = self.number;
        let Books {
            wanted, background, ..
        } = &mut *books;
        if let Some(waker) = wanted
            .get_mut(&number)
            .or_else(|| background.get_mut(&number))
        {
            *waker = Some(cx.waker().clone());
        }
        drop(books);
        Poll::Pending
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut books = lock(&self.books);
        books.wanted.remove(&self.number);
        books.background.remove(&self.number);
        if books.granted.remove(&self.number) {
            books.give_back();
        }
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
        /// The place in the gate's queue.
        ticket: Ticket,
        /// When the wait began.
        since: Instant,
    },
    /// An attempt holds a permit.
    Held {
        /// The permit; dropping it gives it back.
        _permit: Permit,
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
    /// A viewer waits for the connection: its attempts queue ahead of
    /// those nobody but a preload waits for.
    wanted: bool,
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
            .field("wanted", &self.wanted)
            .finish_non_exhaustive()
    }
}

impl ConnectSlot {
    /// A free slot whose permits are leased for `lease` on `clock`, wanted
    /// by no viewer.
    pub(crate) fn new(clock: Arc<dyn Clock>, lease: Duration) -> Self {
        Self {
            state: SlotState::Free,
            clock,
            lease,
            wanted: false,
        }
    }

    /// Whether the slot holds a permit.
    #[cfg(test)]
    pub(crate) const fn holds(&self) -> bool {
        matches!(self.state, SlotState::Held { .. })
    }

    /// Whether a viewer waits for the connection now: its next attempts
    /// queue ahead of the preloads', and an attempt queued now moves to
    /// its queue, at its place in line.
    pub(crate) fn want(&mut self, wanted: bool) {
        if self.wanted == wanted {
            return;
        }
        self.wanted = wanted;
        if let SlotState::Waiting { ticket, .. } = &self.state {
            ticket.set_wanted(wanted);
            tracing::info!(
                wanted,
                "connect wait changes queue: attempts a viewer waits for come before the preloads'"
            );
        }
    }

    /// The worker announced an attempt (`reason`): take a permit for it, or
    /// queue for one. An attempt announced while a permit is held runs
    /// under that permit with a new grant but within the same lease, so
    /// announcing again never keeps a permit longer.
    pub(crate) fn request(&mut self, permits: &ConnectPermits, reason: &'static str) {
        match &mut self.state {
            SlotState::Free => {
                if let Some(permit) = permits.try_take() {
                    let in_flight = permits.in_flight();
                    tracing::debug!(reason, in_flight, "connect permit taken");
                    self.hold(permit);
                } else {
                    tracing::info!(
                        reason,
                        limit = permits.limit,
                        wanted = self.wanted,
                        "connect waits for a permit: sources.connect_concurrency attempts are in flight"
                    );
                    self.state = SlotState::Waiting {
                        ticket: permits.queue(self.wanted),
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
    fn hold(&mut self, permit: Permit) {
        self.state = SlotState::Held {
            _permit: permit,
            lease: self.clock.sleep(self.lease),
            granted: false,
        };
    }

    /// What the driver must act on next; never while the slot is free or
    /// the granted attempt runs within its lease. Cancel-safe: a waiting
    /// slot keeps its place in the queue, and a permit granted meanwhile
    /// waits for it.
    pub(crate) async fn wait(&mut self) -> SlotWake {
        loop {
            match &mut self.state {
                SlotState::Free => std::future::pending::<()>().await,
                SlotState::Waiting { ticket, since } => {
                    let since = *since;
                    let permit = std::future::poll_fn(|cx| ticket.poll_take(cx)).await;
                    let waited = self.clock.now().saturating_duration_since(since);
                    let waited_ms = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX);
                    tracing::info!(
                        waited_ms,
                        wanted = self.wanted,
                        "connect permit granted after waiting"
                    );
                    self.hold(permit);
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
    use lotse_core::runner::PROBE_TIMEOUT;

    use super::*;

    /// A backchannel probe ends within `PROBE_TIMEOUT` of its grant, so it
    /// gives its permit back before the lease runs out, with the same 5 s
    /// to spare as an attempt has beyond its ready timeout.
    #[test]
    fn a_probe_ends_before_its_permits_lease_runs_out() {
        let spare = Duration::from_secs(5);
        assert_eq!(PROBE_TIMEOUT + spare, CONNECT_LEASE);
        assert_eq!(DEFAULT_READY_TIMEOUT + spare, CONNECT_LEASE);
    }

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

    /// A slot that found no free permit queues under a second lock; a
    /// permit given back between the two found nobody queued, so the queue
    /// grants it as the ticket joins, or the attempt would wait for a
    /// release that may never come.
    #[tokio::test]
    async fn a_permit_given_back_between_a_failed_take_and_the_queueing_goes_to_that_ticket() {
        let permits = permits(1);
        let held = permits.try_take().unwrap();
        assert!(permits.try_take().is_none());
        drop(held);
        let ticket = permits.queue(false);
        let waker = Waker::noop();
        let permit = ticket.poll_take(&Context::from_waker(waker));
        assert!(permit.is_ready(), "the free permit goes to the new ticket");
        assert_eq!(permits.in_flight(), 1);
        drop((permit, ticket));
        assert_eq!(permits.in_flight(), 0);
    }

    /// Work list W3: a viewer's offer waits for its camera's connect, so
    /// preload retries queued before it must not hold it back.
    #[tokio::test]
    async fn an_attempt_a_viewer_waits_for_is_granted_before_queued_preload_retries() {
        let clock = Arc::new(FakeClock::default());
        let permits = permits(1);
        let mut slots = slots(&clock, 5);
        slots[0].request(&permits, "connecting");
        assert_eq!(ready(&mut slots[0]).await, Some(SlotWake::Grant));
        // Each preload retry's driver waits on its slot, as drivers do.
        for slot in &mut slots[1..4] {
            slot.request(&permits, "reconnecting");
            assert_eq!(ready(slot).await, None);
        }
        slots[4].want(true);
        slots[4].request(&permits, "connecting");
        assert_eq!(ready(&mut slots[4]).await, None);
        slots[0].release("live");
        assert_eq!(ready(&mut slots[4]).await, Some(SlotWake::Grant));
        for slot in &mut slots[1..4] {
            assert_eq!(ready(slot).await, None, "the preload retries wait");
        }
        // The preload retries follow in the order they queued.
        slots[4].release("live");
        assert_eq!(ready(&mut slots[1]).await, Some(SlotWake::Grant));
        assert_eq!(ready(&mut slots[2]).await, None);
        slots[1].release("live");
        assert_eq!(ready(&mut slots[2]).await, Some(SlotWake::Grant));
        assert_eq!(ready(&mut slots[3]).await, None);
        assert_eq!(permits.in_flight(), 1);
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
    async fn a_permit_granted_to_a_slot_given_up_before_it_took_it_goes_to_the_next() {
        let clock = Arc::new(FakeClock::default());
        let permits = permits(1);
        let mut slots = slots(&clock, 3);
        slots[0].request(&permits, "connecting");
        slots[1].request(&permits, "connecting");
        slots[2].request(&permits, "connecting");
        assert!(format!("{:?}", slots[1]).contains("waiting"));
        assert!(format!("{:?}", slots[0]).contains("held"));
        assert!(format!("{:?}", slots[0]).contains("wanted: false"));
        assert_eq!(CONNECT_LEASE, Duration::from_secs(35));
        clock.advance(Duration::from_millis(1500));
        // Granted to the second, whose driver never waited on it yet; a
        // change of priority leaves a granted ticket where it is.
        slots[0].release("live");
        slots[1].want(true);
        assert_eq!(permits.in_flight(), 1, "granted counts as held");
        // The second's worker is stopped before its driver took the
        // permit: it goes to the third.
        slots[1].release("worker stopped");
        assert!(!slots[1].holds());
        assert_eq!(ready(&mut slots[2]).await, Some(SlotWake::Grant));
        assert_eq!(permits.in_flight(), 1);
        slots[2].release("live");
        assert_eq!(permits.in_flight(), 0);
        assert_eq!(ready(&mut slots[1]).await, None);
    }

    /// A queued attempt follows its connection's viewers: it moves ahead
    /// of the preloads' when a viewer comes, and back when the last one
    /// leaves, each time at its place in line.
    #[tokio::test]
    async fn a_queued_attempt_moves_ahead_when_a_viewer_comes_and_back_when_it_leaves() {
        let clock = Arc::new(FakeClock::default());
        let permits = permits(1);
        let mut slots = slots(&clock, 5);
        slots[0].request(&permits, "connecting");
        assert_eq!(ready(&mut slots[0]).await, Some(SlotWake::Grant));
        // A viewer for the holder changes nothing at the gate.
        slots[0].want(true);
        slots[0].want(true);
        assert!(slots[0].holds());
        for slot in &mut slots[1..4] {
            slot.request(&permits, "reconnecting");
            assert_eq!(ready(slot).await, None);
        }
        // A viewer comes to the third preload's connection: it goes first.
        slots[3].want(true);
        slots[0].release("live");
        assert_eq!(ready(&mut slots[1]).await, None);
        assert_eq!(ready(&mut slots[2]).await, None);
        assert_eq!(ready(&mut slots[3]).await, Some(SlotWake::Grant));
        // A viewer comes to the second's connection and leaves again, and
        // one comes to a connection queued after it: the second is back
        // behind the first, and the newcomer goes before both.
        slots[2].want(true);
        slots[4].want(true);
        slots[4].request(&permits, "connecting");
        assert_eq!(ready(&mut slots[4]).await, None);
        slots[2].want(false);
        slots[3].release("live");
        assert_eq!(ready(&mut slots[1]).await, None);
        assert_eq!(ready(&mut slots[2]).await, None);
        assert_eq!(ready(&mut slots[4]).await, Some(SlotWake::Grant));
        slots[4].release("live");
        assert_eq!(ready(&mut slots[2]).await, None);
        assert_eq!(ready(&mut slots[1]).await, Some(SlotWake::Grant));
        slots[1].release("live");
        assert_eq!(ready(&mut slots[2]).await, Some(SlotWake::Grant));
        assert_eq!(permits.in_flight(), 1);
    }
}
