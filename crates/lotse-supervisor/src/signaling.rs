//! The routing of signaled sources' signaling between their workers and
//! the control-API client that relays it: the registry's side.
//!
//! A worker's signaled source asks for a signaling channel per connection
//! attempt (`lotse_core::signaling`); its driver checks the worker's
//! reports, untrusted, and hands them here ([`State::signal_report`]),
//! and what the registry answers goes back to the worker through the
//! driver's queue as [`DriverCommand::Signal`], named for the worker that
//! asked ([`SignalFrom`]).
//!
//! The client takes signals with `signaling/subscribe`, for one stream
//! or for every stream: one subscription per scope, a later one
//! superseding the earlier (which gets `superseded` and ends), and one
//! for a stream taking that stream's new signals from the one for every
//! stream. An open finds the subscription for one of its connection's
//! streams (the first with its own, else the one for every stream, which
//! gets the first stream's id) and becomes a signal: the supervisor names
//! it with a ULID, new per attempt, tells the worker the host addresses
//! its source may gather on, and the signal belongs to that subscription
//! from then on. Its offer, candidates and close go to that subscription
//! only, and only that subscription's control connection may answer it,
//! trickle to it or fail it (`signaling/answer`, `signaling/candidate`,
//! `signaling/error`); another gets `signal_not_found`. An open no
//! subscription takes waits up to [`SIGNAL_WAIT`] for one (the driver
//! times it on the injected clock and asks [`State::signal_wait_expired`]),
//! then is refused [`NO_SIGNALING_CLIENT`]: the source's attempt ends
//! unreachable, and its connection backs off with that as its last error.
//!
//! A signal ends when its source closes it (`closed` with the source's
//! code, mapped onto the API's), when its worker exits (`worker_gone`) or
//! stops, or its connection goes (`source_stopped`), and at once, with no
//! `closed`, when its subscription ends (`unsubscribe`, the control
//! connection's close, a supersede): the worker is told the client is
//! gone, its source ends and connects again after its backoff, offering
//! to whichever subscription takes the stream then.
//!
//! What the registry or the driver tells a worker on its own (an open's
//! answer or refusal, the end of a signal) is never lost to a full driver
//! queue: it waits in the registry, ahead of anything later for that
//! worker, until the driver has handled the commands its queue held when
//! the first was held, and takes it ([`State::take_held_signals`]); a
//! queue that never empties cannot starve it. Only a client's command is
//! refused on a busy driver (`limit_reached`), for the client to send
//! again.
//!
//! A signal belongs to its stream: one whose stream no longer reads from
//! its connection (the stream deleted or moved to another source while
//! the connection serves others) ends as its subscription's end does, the
//! client told it closed `source_stopped`. An open waiting for a
//! subscription is offered again when a subscription opens or a stream
//! joins its connection.
//!
//! The worker is untrusted. A source connection holds at most
//! [`MAX_OPEN_SIGNALS`] signals and waiting opens at once, an open past
//! them refused `limit_reached`, so a worker cannot grow the registry's
//! signals (one that ends its signals and opens new ones in a loop still
//! offers once per signal, as a source that keeps failing does). Per
//! signal an offer is taken once, at most
//! [`MAX_WORKER_CANDIDATES`] candidates after it, an end-of-candidates
//! for at most [`MAX_ENDED_SECTIONS`] media sections, and no candidate for
//! a section after its end-of-candidates (RFC 8838 §8.2, §13); a report
//! past that ends the signal
//! (`internal_error` to the client, [`REJECTED`] to the worker), so a
//! signal cannot flood the client, whose signaling events are never shed:
//! a subscription without room for one ends, and the server disconnects
//! its client. The client's own commands are bounded too: one answer, at
//! most [`MAX_CLIENT_CANDIDATES`] candidates, one end-of-candidates per
//! media section for at most [`MAX_ENDED_SECTIONS`] sections, after which
//! that section takes no candidate, and one error per signal, after which
//! it takes no answer or candidate.
//!
//! End-of-candidates ends one media section's candidates, not the
//! signal's (RFC 8838 §8.2, §13): with BUNDLE (RFC 8843) one section
//! carries them all, but a camera's integration may end each `a=mid` on
//! its own and trickle another's after. A candidate's section is its
//! `a=mid` when it names one, else its index (RFC 8829 §3.5.2.1), else
//! the one unnamed section.
//!
//! Every line a worker's opens, cancels and reports can repeat (an open
//! that waits, is cancelled or refused; a signal opened, offered, closed
//! or ended over a breach) is rate-limited per source connection on the
//! injected clock, or is at debug level (a report on a signal the
//! registry does not hold, a candidate relayed).
//!
//! Standards: RFC 8829 (JSEP) and RFC 8838 (Trickle ICE), the exchange
//! the signals carry, as `lotse_core::signaling` cites them; ULID for the
//! signal ids.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use lotse_api::{ConnectionId, Event, EventClass};
use lotse_api_types::command::{SignalingAnswer, SignalingCandidate, SignalingError};
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::signaling::{SignalCloseCode, SignalingEvent};
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::signaling::{REJECTED, SignalCandidate};
use lotse_core::text::plain;
use lotse_core::throttle::Throttle;
use lotse_ipc::{SignalCommand, SignalReport};
use tokio::sync::mpsc;

use crate::connect::CONNECT_LEASE;
use crate::driver::{COMMAND_QUEUE, DriverCommand};
use crate::registry::State;
use crate::session::{MAX_WORKER_CANDIDATES, ulid};
use crate::worker_text::MAX_MESSAGE_BYTES;

/// The refusal code of an open no control-API client relays.
pub(crate) const NO_SIGNALING_CLIENT: &str = "no_signaling_client";

/// The refusal code of an open past a limit: the driver's
/// [`MAX_PENDING_OPENS`], or the registry's [`MAX_OPEN_SIGNALS`].
pub(crate) const LIMIT_REACHED: &str = "limit_reached";

/// The most opens a worker may have waiting for an answer: its source and
/// a standby open one each per connection attempt. One past them is
/// refused at once.
pub(crate) const MAX_PENDING_OPENS: usize = 2;

/// The most signals and waiting opens a source connection holds at once:
/// as many as its worker holds channels (the worker's `MAX_SIGNALS`), so
/// one attempt's signal and the next's overlap while the first closes. An
/// open past them is refused [`LIMIT_REACHED`].
pub(crate) const MAX_OPEN_SIGNALS: usize = 4;

/// How long an open waits for a `signaling/subscribe` that takes its
/// stream: long enough for a client that reconnects to subscribe again,
/// well under the 30 s a connection attempt may take to go live.
pub(crate) const SIGNAL_WAIT: Duration = Duration::from_secs(10);

/// How long the driver keeps an open waiting for its answer: as long as
/// the connection attempt that asked may take ([`CONNECT_LEASE`]), after
/// which the worker has abandoned it. An answer or a cancel lost on a full
/// queue so frees its place in [`MAX_PENDING_OPENS`] by then.
pub(crate) const OPEN_EXPIRY: Duration = CONNECT_LEASE;

/// The most signals a driver remembers having ended itself, so it drops
/// what their worker still reports on them: twice the channels a worker
/// holds at once.
pub(crate) const MAX_ENDED_SIGNALS: usize = 8;

/// Events a signaling subscription holds before the server's forwarder
/// drains them: a few signals' offers and candidates. On top of these
/// one slot is kept for [`EventClass::Overflowed`].
pub(crate) const SIGNALING_QUEUE: usize = 256;

/// The slot of a subscription's queue kept for [`EventClass::Overflowed`].
const OVERFLOW_SLOT: usize = 1;

/// The client's candidates a signal takes, its end-of-candidates aside: a
/// camera's host, reflexive and relay candidates on a few interfaces, with
/// room to spare.
pub(crate) const MAX_CLIENT_CANDIDATES: u32 = 64;

/// The media sections whose candidates one side of a signal may end
/// (RFC 8838 §8.2): an audio, a video and a data section each, unbundled,
/// with room to spare. It bounds the sections a signal remembers.
pub(crate) const MAX_ENDED_SECTIONS: usize = 8;

/// The most commands the registry holds for one worker while its driver's
/// queue is full ([`State::take_held_signals`]): an answer per open and an
/// end per signal, which [`MAX_PENDING_OPENS`] and [`MAX_OPEN_SIGNALS`]
/// keep to a few, with the room of a whole queue to spare.
pub(crate) const MAX_HELD_SIGNALS: usize = COMMAND_QUEUE;

/// Where a signal report comes from, and so where the registry's answer
/// goes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignalFrom<'a> {
    /// The connection whose worker reported it.
    pub(crate) connection: &'a str,
    /// The driver's serial of that worker: the answer is dropped unless it
    /// still runs ([`DriverCommand::Signal`]).
    pub(crate) worker: u64,
}

/// The subscription a scope or a signal belongs to: a control connection's
/// `signaling/subscribe`, by its command id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Owner {
    /// The control connection.
    pub(crate) connection: ConnectionId,
    /// The subscribing command's id.
    pub(crate) subscription: u64,
}

/// The subscription serving a scope.
#[derive(Debug)]
struct Subscriber {
    /// Whose it is.
    owner: Owner,
    /// Where its events go.
    events: mpsc::Sender<Event>,
}

/// An open no subscription took yet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WaitingOpen {
    /// The source connection whose worker asked.
    connection: String,
    /// The driver's serial of that worker.
    worker: u64,
    /// The worker's id of the open.
    request: u64,
}

/// An open signal: a connection attempt's channel to the client.
#[derive(Debug)]
struct Signal {
    /// The source connection whose worker opened it.
    connection: String,
    /// The driver's serial of that worker, which every command for the
    /// signal names.
    worker: u64,
    /// The stream it offers for: the one its subscription took it for.
    stream_id: String,
    /// Its source's protocol, which its offer names.
    protocol: &'static str,
    /// The subscription it belongs to.
    owner: Owner,
    /// Where its events go: its subscription's queue.
    events: mpsc::Sender<Event>,
    /// What its worker sent so far.
    worker_sent: WorkerSent,
    /// What its client sent so far.
    client_sent: ClientSent,
}

/// The media section a candidate or end-of-candidates belongs to, as one
/// is told from another for its end (RFC 8838 §8.2): by its `a=mid` when
/// the sender named one, else by its index (RFC 8829 §3.5.2.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    /// The section of this `a=mid` (RFC 8843 §7.1).
    Mid(String),
    /// The section of this index, 0 for the first, no `a=mid` named.
    Index(u16),
    /// Neither named: the one section a sender that names none has.
    Unnamed,
}

impl Section {
    /// The section a candidate naming `mid` and `mline_index` belongs to.
    fn of(mid: Option<&str>, mline_index: Option<u16>) -> Self {
        match (mid, mline_index) {
            (Some(mid), _) => Self::Mid(mid.to_owned()),
            (None, Some(index)) => Self::Index(index),
            (None, None) => Self::Unnamed,
        }
    }
}

/// What a signal's worker sent so far.
#[derive(Debug, Default)]
struct WorkerSent {
    /// Its offer, which went to the client: the client knows the signal.
    offer: bool,
    /// Its candidates, at most [`MAX_WORKER_CANDIDATES`].
    candidates: u32,
    /// The sections it sent end-of-candidates for, at most
    /// [`MAX_ENDED_SECTIONS`]: no candidate of theirs follows.
    ended: BTreeSet<Section>,
}

/// What a signal's client sent so far.
#[derive(Debug, Default)]
struct ClientSent {
    /// Its answer.
    answer: bool,
    /// Its error (`signaling/error`): the source's close follows, and the
    /// client sends nothing more on the signal.
    error: bool,
    /// Its candidates, the end-of-candidates aside: at most
    /// [`MAX_CLIENT_CANDIDATES`].
    candidates: u32,
    /// The sections it sent end-of-candidates for, at most
    /// [`MAX_ENDED_SECTIONS`]: no candidate of theirs follows.
    ended: BTreeSet<Section>,
}

impl ClientSent {
    /// Counts a candidate the client sent for `section`, or, `end`, the
    /// section's end-of-candidates.
    fn took_candidate(&mut self, section: Section, end: bool) {
        if end {
            self.ended.insert(section);
        } else {
            self.candidates = self.candidates.saturating_add(1);
        }
    }
}

/// The commands held for one worker while its driver's queue is full.
#[derive(Debug, Default)]
struct Held {
    /// The commands, oldest first, each with the worker's serial.
    commands: VecDeque<(u64, SignalCommand)>,
    /// The commands the driver is still to handle before it takes these:
    /// those its queue held when the first was held, and one more, which
    /// it may have taken off the queue then and not yet handled. As the
    /// queue is first in, first out, every command queued before the held
    /// ones is handled by then, whatever is queued after.
    ahead: usize,
}

/// The signaling the registry routes: the subscriptions, the opens
/// waiting for one, and the open signals.
#[derive(Debug)]
pub(crate) struct Signaling {
    /// The host addresses a source may gather candidates on: the front
    /// door's, enumerated before the sandbox.
    pub(crate) local_addrs: Vec<IpAddr>,
    /// The subscription of each scope: a stream's, or every stream's
    /// (`None`).
    scopes: BTreeMap<Option<String>, Subscriber>,
    /// The opens no subscription took yet, oldest first.
    waiting: Vec<WaitingOpen>,
    /// The open signals, by id.
    signals: BTreeMap<String, Signal>,
    /// The commands for each source connection's worker its driver's full
    /// queue did not take: they go before any later command for it, when
    /// the driver takes them ([`State::take_held_signals`]).
    held: BTreeMap<String, Held>,
    /// The signals opened so far, for an id when the ULID's randomness is
    /// unavailable.
    opened: u64,
    /// Rate-limits, per source connection and [`Line`], the lines a
    /// worker's opens, cancels and reports can repeat as fast as it sends
    /// them: one worker's flood hides no other's. A connection's go with
    /// it.
    lines: BTreeMap<(String, Line), Throttle>,
    /// The injected clock, for the lines [`State::tell_worker`]
    /// rate-limits: not all of its callers know the time.
    pub(crate) clock: Arc<dyn Clock>,
}

impl Default for Signaling {
    /// No subscription, open or signal, on the system clock until the
    /// supervisor injects its own.
    fn default() -> Self {
        Self {
            local_addrs: Vec::new(),
            scopes: BTreeMap::new(),
            waiting: Vec::new(),
            signals: BTreeMap::new(),
            held: BTreeMap::new(),
            opened: 0,
            lines: BTreeMap::new(),
            clock: Arc::new(SystemClock),
        }
    }
}

/// A line of the router's a worker can repeat as fast as it sends, each
/// rate-limited on the injected clock per source connection
/// ([`Signaling::line`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Line {
    /// An open refused past [`MAX_OPEN_SIGNALS`].
    Limit,
    /// An open that waits for a subscription.
    Waits,
    /// An open refused [`NO_SIGNALING_CLIENT`] at its wait's end.
    NoClient,
    /// A waiting open cancelled.
    Cancelled,
    /// A signal opened.
    Opened,
    /// A signal's offer relayed.
    Offered,
    /// A signal closed by its source.
    Closed,
    /// A signal ended over a worker's breach of the contract.
    Broke,
    /// A command for the worker dropped past [`MAX_HELD_SIGNALS`]: the
    /// driver's refusals of a worker's opens can repeat it.
    Dropped,
}

impl Signaling {
    /// The subscription that takes a signal of a connection with
    /// `streams`, with the stream it takes it for: the subscription of the
    /// first of them that has its own, else the one for every stream, for
    /// the first of them; either only while its queue is open.
    fn subscriber_for(&self, streams: &BTreeSet<String>) -> Option<(String, &Subscriber)> {
        let open = |subscriber: &&Subscriber| !subscriber.events.is_closed();
        streams
            .iter()
            .find_map(|stream| {
                let own = self.scopes.get(&Some(stream.clone())).filter(open)?;
                Some((stream.clone(), own))
            })
            .or_else(|| {
                let every = self.scopes.get(&None).filter(open)?;
                Some((streams.first()?.clone(), every))
            })
    }

    /// Counts one occurrence of `line` of `connection` at `now`:
    /// `Some(count)` when the line is due ([`Throttle::hit`]).
    fn line(&mut self, connection: &str, line: Line, now: Instant) -> Option<u64> {
        self.lines
            .entry((connection.to_owned(), line))
            .or_default()
            .hit(now)
    }

    /// The signals and waiting opens of `connection`.
    fn open_count(&self, connection: &str) -> usize {
        let signals = self
            .signals
            .values()
            .filter(|signal| signal.connection == connection)
            .count();
        let waiting = self
            .waiting
            .iter()
            .filter(|open| open.connection == connection)
            .count();
        signals.saturating_add(waiting)
    }
}

/// The API's close code for a worker's `code`, untrusted: one of
/// `lotse_core::signaling::close`, or `internal_error` for one the API
/// does not know.
fn close_code(code: &str) -> SignalCloseCode {
    SignalCloseCode::parse(code).unwrap_or(SignalCloseCode::InternalError)
}

/// The id of the `opened`th signal: its ULID, or, when the ULID's
/// randomness is unavailable (Linux's getrandom does not fail once the
/// kernel's pool is ready), the count, unique within the process.
fn signal_id(ulid: Result<String, getrandom::Error>, opened: u64) -> String {
    match ulid {
        Ok(id) => id,
        Err(error) => {
            tracing::warn!(%error, opened, "no randomness for a signal's ULID; its count names it");
            format!("{opened:026}")
        }
    }
}

/// Queues `event` on a signaling subscription's `events`, leaving the
/// overflow slot free. A signaling event is never dropped: without room
/// for it the subscription ends with [`EventClass::Overflowed`], after
/// which the server disconnects the client. False when the subscription
/// is over, by that or because its receiver is gone.
fn emit(events: &mpsc::Sender<Event>, event: &SignalingEvent) -> bool {
    let event = Event {
        class: EventClass::Signaling,
        payload: serde_json::to_value(event).unwrap_or_default(),
    };
    if events.capacity() > OVERFLOW_SLOT {
        return events.try_send(event).is_ok();
    }
    tracing::warn!(
        "signaling subscription queue full for an event that is never dropped; ending the subscription, and the client is disconnected"
    );
    let _ended = events.try_send(Event {
        class: EventClass::Overflowed,
        payload: serde_json::Value::Null,
    });
    false
}

/// `signal_not_found` for `signal_id`.
fn signal_not_found(signal_id: &str) -> ApiError {
    ApiError::new(
        ErrorCode::SignalNotFound,
        "no such signal on this connection",
    )
    .with_detail("signal_id", signal_id)
}

/// `invalid_request` for a command on `signal_id` its state refuses, with
/// `message` saying why.
fn signal_refused(signal_id: &str, message: &str) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest, message).with_detail("signal_id", signal_id)
}

impl State {
    /// The checked signal `report` of the worker `from`, at `now` on the
    /// injected clock (rate-limited lines) and `wall` on its wall clock (a
    /// new signal's ULID).
    pub(crate) fn signal_report(
        &mut self,
        from: &SignalFrom<'_>,
        report: SignalReport,
        now: Instant,
        wall: SystemTime,
    ) {
        let connection = from.connection;
        match report {
            SignalReport::Open { request } => self.signal_open(from, request, now, wall),
            SignalReport::Cancel { request } => {
                let open = WaitingOpen {
                    connection: connection.to_owned(),
                    worker: from.worker,
                    request,
                };
                let before = self.signaling.waiting.len();
                self.signaling.waiting.retain(|waiting| *waiting != open);
                if self.signaling.waiting.len() == before {
                    tracing::debug!(
                        connection.id = connection,
                        request,
                        "signaling open cancelled; nothing holds it"
                    );
                } else if let Some(count) = self.signaling.line(connection, Line::Cancelled, now) {
                    tracing::info!(
                        connection.id = connection,
                        request,
                        count,
                        "signaling open cancelled while it waited for a client"
                    );
                }
            }
            SignalReport::Offer { signal_id, sdp } => {
                let Some(mut signal) = self.take_signal(connection, &signal_id) else {
                    return;
                };
                if signal.worker_sent.offer {
                    self.worker_broke(&signal_id, &signal, "a second offer", now);
                    return;
                }
                signal.worker_sent.offer = true;
                let event = SignalingEvent::Offer {
                    signal_id: signal_id.clone(),
                    stream_id: signal.stream_id.clone(),
                    protocol: signal.protocol.to_owned(),
                    sdp,
                };
                if let Some(count) = self.signaling.line(connection, Line::Offered, now) {
                    tracing::info!(
                        signal.id = %signal_id,
                        connection.id = connection,
                        stream.id = %signal.stream_id,
                        count,
                        "signaling offer relayed to the subscription"
                    );
                }
                self.deliver(signal_id, signal, &event);
            }
            SignalReport::Candidate {
                signal_id,
                candidate,
                mid,
                mline_index,
            } => self.worker_candidate(
                connection,
                signal_id,
                SignalCandidate {
                    candidate,
                    sdp_mid: mid,
                    sdp_mline_index: mline_index,
                },
                now,
            ),
            SignalReport::Closed {
                signal_id,
                code,
                message,
            } => {
                let Some(signal) = self.take_signal(connection, &signal_id) else {
                    return;
                };
                let code = close_code(&code);
                if let Some(count) = self.signaling.line(connection, Line::Closed, now) {
                    tracing::info!(
                        signal.id = %signal_id,
                        connection.id = connection,
                        code = code.as_str(),
                        message = %message,
                        count,
                        "signal closed by its source"
                    );
                }
                self.close_signal(signal_id, &signal, code, message);
            }
        }
    }

    /// A candidate (or, its line empty, the end-of-candidates indication)
    /// of the worker of `connection` for its signal `signal_id`, at `now`:
    /// relayed within the signal's budget, else the signal ends.
    fn worker_candidate(
        &mut self,
        connection: &str,
        signal_id: String,
        SignalCandidate {
            candidate,
            sdp_mid: mid,
            sdp_mline_index: mline_index,
        }: SignalCandidate,
        now: Instant,
    ) {
        let Some(mut signal) = self.take_signal(connection, &signal_id) else {
            return;
        };
        // The first media section when the source named none: its BUNDLE
        // carries every candidate, and the client is told that index.
        let mline_index = mline_index.unwrap_or(0);
        let section = Section::of(mid.as_deref(), Some(mline_index));
        let end = candidate.is_empty();
        let broken = if !signal.worker_sent.offer {
            Some("a candidate before the offer")
        } else if signal.worker_sent.ended.contains(&section) {
            // RFC 8838 §13: no candidate of a media section follows its
            // end-of-candidates.
            Some("a candidate after its media section's end-of-candidates")
        } else if end && signal.worker_sent.ended.len() >= MAX_ENDED_SECTIONS {
            Some("more media sections ended than a signal allows")
        } else if !end && signal.worker_sent.candidates >= MAX_WORKER_CANDIDATES {
            Some("more candidates than a signal allows")
        } else {
            None
        };
        if let Some(reason) = broken {
            self.worker_broke(&signal_id, &signal, reason, now);
            return;
        }
        if end {
            signal.worker_sent.ended.insert(section);
        } else {
            signal.worker_sent.candidates = signal.worker_sent.candidates.saturating_add(1);
        }
        tracing::debug!(
            signal.id = %signal_id,
            end,
            "signaling candidate relayed to the subscription"
        );
        let event = SignalingEvent::Candidate {
            signal_id: signal_id.clone(),
            candidate,
            sdp_mid: mid,
            sdp_mline_index: mline_index,
        };
        self.deliver(signal_id, signal, &event);
    }

    /// Takes the signal `signal_id` off the open ones if the worker of
    /// `connection` opened it; a report on any other is dropped.
    fn take_signal(&mut self, connection: &str, signal_id: &str) -> Option<Signal> {
        match self.signaling.signals.entry(signal_id.to_owned()) {
            Entry::Occupied(entry) if entry.get().connection == connection => Some(entry.remove()),
            _ => {
                tracing::debug!(
                    connection.id = connection,
                    signal.id = signal_id,
                    "a worker reported on a signal the supervisor does not hold; dropped"
                );
                None
            }
        }
    }

    /// Puts `signal` back among the open ones and queues `event` of it on
    /// its subscription; one that cannot take it ends.
    fn deliver(&mut self, signal_id: String, signal: Signal, event: &SignalingEvent) {
        let (owner, events) = (signal.owner, signal.events.clone());
        self.signaling.signals.insert(signal_id, signal);
        if !emit(&events, event) {
            self.end_subscription(owner, "its queue is over");
        }
    }

    /// Ends `signal`, taken off the open ones, whose worker broke the
    /// contract for `reason` at `now`: the worker is told the relay
    /// rejected it ([`REJECTED`]: its source's fault, not the camera's),
    /// the client that it closed `internal_error`.
    fn worker_broke(
        &mut self,
        signal_id: &str,
        signal: &Signal,
        reason: &'static str,
        now: Instant,
    ) {
        if let Some(count) = self.signaling.line(&signal.connection, Line::Broke, now) {
            tracing::warn!(
                signal.id = signal_id,
                connection.id = %signal.connection,
                reason,
                count,
                "a worker's signaling breaks the contract; signal ended"
            );
        }
        let message = format!("the worker sent {reason}");
        self.tell_worker(
            &signal.connection,
            signal.worker,
            SignalCommand::Failed {
                signal_id: signal_id.to_owned(),
                code: REJECTED.to_owned(),
                message: message.clone(),
            },
        );
        self.close_signal(
            signal_id.to_owned(),
            signal,
            SignalCloseCode::InternalError,
            message,
        );
    }

    /// Ends `signal`, taken off the open ones: its subscription is told it
    /// closed with `code` if its offer went out, before which the client
    /// does not know it.
    fn close_signal(
        &mut self,
        signal_id: String,
        signal: &Signal,
        code: SignalCloseCode,
        message: String,
    ) {
        if !signal.worker_sent.offer {
            return;
        }
        let event = SignalingEvent::Closed {
            signal_id,
            code,
            message,
        };
        if !emit(&signal.events, &event) {
            self.end_subscription(signal.owner, "its queue is over");
        }
    }

    /// The worker `from` asks for a channel with its `request`, at `now`:
    /// past [`MAX_OPEN_SIGNALS`] it is refused, else the subscription for
    /// one of the connection's streams gets a new signal named at `wall`,
    /// or the open waits for one.
    fn signal_open(&mut self, from: &SignalFrom<'_>, request: u64, now: Instant, wall: SystemTime) {
        let connection = from.connection;
        if !self.connections.contains_key(connection) {
            tracing::debug!(
                connection.id = connection,
                request,
                "signaling open of a connection that is gone; dropped"
            );
            return;
        }
        if self.signaling.open_count(connection) >= MAX_OPEN_SIGNALS {
            if let Some(count) = self.signaling.line(connection, Line::Limit, now) {
                tracing::warn!(
                    connection.id = connection,
                    request,
                    limit = MAX_OPEN_SIGNALS,
                    count,
                    "signaling open refused: the connection holds as many signals as it may"
                );
            }
            self.tell_worker(
                connection,
                from.worker,
                SignalCommand::Refused {
                    request,
                    code: LIMIT_REACHED.to_owned(),
                    message: format!(
                        "a source connection may hold {MAX_OPEN_SIGNALS} signals and waiting opens"
                    ),
                },
            );
            return;
        }
        let open = WaitingOpen {
            connection: connection.to_owned(),
            worker: from.worker,
            request,
        };
        if !self.open_signal(&open, now, wall) {
            if let Some(count) = self.signaling.line(connection, Line::Waits, now) {
                tracing::info!(
                    connection.id = connection,
                    request,
                    wait_ms = crate::millis(SIGNAL_WAIT),
                    count,
                    "no signaling subscription takes the stream; the open waits for one"
                );
            }
            self.signaling.waiting.push(open);
        }
    }

    /// Opens a signal for `open` on the subscription that takes one of
    /// its connection's streams, if one does, at `now`, named at `wall`.
    /// True when one does: the worker is told.
    fn open_signal(&mut self, open: &WaitingOpen, now: Instant, wall: SystemTime) -> bool {
        let Some((protocol, (stream_id, subscriber))) =
            self.connections.get(&open.connection).and_then(|entry| {
                let protocol = entry.key.target.signaled_protocol()?;
                Some((protocol, self.signaling.subscriber_for(&entry.streams)?))
            })
        else {
            return false;
        };
        let (owner, events) = (subscriber.owner, subscriber.events.clone());
        self.signaling.opened = self.signaling.opened.wrapping_add(1);
        let opened = self.signaling.opened;
        let signal_id = signal_id(ulid(wall), opened);
        self.tell_worker(
            &open.connection,
            open.worker,
            SignalCommand::Opened {
                request: open.request,
                signal_id: signal_id.clone(),
                local_addrs: self.signaling.local_addrs.clone(),
            },
        );
        if let Some(count) = self.signaling.line(&open.connection, Line::Opened, now) {
            tracing::info!(
                signal.id = %signal_id,
                connection.id = %open.connection,
                stream.id = %stream_id,
                request = open.request,
                control.connection = owner.connection.0,
                subscription = owner.subscription,
                count,
                "signal opened; it belongs to the subscription that takes its stream"
            );
        }
        self.signaling.signals.insert(
            signal_id,
            Signal {
                connection: open.connection.clone(),
                worker: open.worker,
                stream_id,
                protocol,
                owner,
                events,
                worker_sent: WorkerSent::default(),
                client_sent: ClientSent::default(),
            },
        );
        true
    }

    /// The open `request` of the worker `from` waited [`SIGNAL_WAIT`]: if
    /// no subscription took it meanwhile, it is refused
    /// [`NO_SIGNALING_CLIENT`], and the source's attempt ends unreachable.
    /// True when it is; false when the registry no longer holds it (taken,
    /// or cancelled), so the driver need not wait for its answer. `now` on
    /// the injected clock rate-limits the line.
    pub(crate) fn signal_wait_expired(
        &mut self,
        from: &SignalFrom<'_>,
        request: u64,
        now: Instant,
    ) -> bool {
        let open = WaitingOpen {
            connection: from.connection.to_owned(),
            worker: from.worker,
            request,
        };
        let Some(index) = self
            .signaling
            .waiting
            .iter()
            .position(|waiting| *waiting == open)
        else {
            return false;
        };
        self.signaling.waiting.remove(index);
        if let Some(count) = self.signaling.line(from.connection, Line::NoClient, now) {
            tracing::info!(
                connection.id = from.connection,
                request,
                count,
                "signaling channel refused: no client subscribed to the stream's signaling in time"
            );
        }
        self.tell_worker(
            from.connection,
            from.worker,
            SignalCommand::Refused {
                request,
                code: NO_SIGNALING_CLIENT.to_owned(),
                message: "no control-API client relays this source's signaling".to_owned(),
            },
        );
        true
    }

    /// The signals of `connection` are over: its worker exited or
    /// stopped, or the connection went. The opens it had waiting and the
    /// commands held for it are forgotten, and each signal whose offer
    /// went out closes with `code`.
    pub(crate) fn signals_ended(&mut self, connection: &str, code: SignalCloseCode, message: &str) {
        self.signaling
            .waiting
            .retain(|waiting| waiting.connection != connection);
        let _forgotten = self.signaling.held.remove(connection);
        if !self.connections.contains_key(connection) {
            self.signaling
                .lines
                .retain(|(lines_of, _), _| lines_of != connection);
        }
        let (ended, open) = std::mem::take(&mut self.signaling.signals)
            .into_iter()
            .partition(|(_, signal)| signal.connection == connection);
        self.signaling.signals = open;
        for (signal_id, signal) in ended {
            tracing::info!(
                signal.id = %signal_id,
                connection.id = connection,
                code = code.as_str(),
                reason = message,
                "signal closed: its source's worker is gone or stopping"
            );
            self.close_signal(signal_id, &signal, code, message.to_owned());
        }
    }

    /// `signaling/subscribe` `owner` for `stream_id`, or every stream: it
    /// takes the scope from the subscription that had it, which gets
    /// `superseded` and ends, and serves the opens waiting for it, at
    /// `now` on the injected clock (rate-limited lines), their signals
    /// named at `wall` on its wall clock.
    pub(crate) fn signaling_subscribe(
        &mut self,
        owner: Owner,
        stream_id: Option<String>,
        (now, wall): (Instant, SystemTime),
    ) -> mpsc::Receiver<Event> {
        let (events, rx) = mpsc::channel(SIGNALING_QUEUE.saturating_add(OVERFLOW_SLOT));
        let scope = stream_id.as_deref().unwrap_or("*").to_owned();
        tracing::info!(
            control.connection = owner.connection.0,
            subscription = owner.subscription,
            stream.id = %scope,
            "signaling subscription opened"
        );
        let previous = self
            .signaling
            .scopes
            .insert(stream_id, Subscriber { owner, events });
        if let Some(previous) = previous {
            tracing::info!(
                control.connection = previous.owner.connection.0,
                subscription = previous.owner.subscription,
                stream.id = %scope,
                reason = "a later subscription took its scope",
                "signaling subscription superseded"
            );
            let _last = emit(&previous.events, &SignalingEvent::Superseded {});
            self.end_subscription(previous.owner, "superseded");
        }
        self.route_waiting(None, now, wall);
        rx
    }

    /// The streams of `connection` changed (a `stream/put`) at `now` on
    /// the injected clock: the opens it has waiting are offered again, as
    /// a stream that joined it may have a subscription of its own that
    /// takes them, their signals named at `wall` on its wall clock.
    pub(crate) fn route_waiting_opens(
        &mut self,
        connection: &str,
        (now, wall): (Instant, SystemTime),
    ) {
        self.route_waiting(Some(connection), now, wall);
    }

    /// Offers the waiting opens, of `connection` only if it is one, to the
    /// subscriptions at `now`, naming their signals at `wall`; those none
    /// takes wait on, in order.
    fn route_waiting(&mut self, connection: Option<&str>, now: Instant, wall: SystemTime) {
        let waiting = std::mem::take(&mut self.signaling.waiting);
        for open in waiting {
            if connection.is_none_or(|only| only == open.connection)
                && self.open_signal(&open, now, wall)
            {
                continue;
            }
            self.signaling.waiting.push(open);
        }
    }

    /// The streams of `connection`, which still serves some, changed:
    /// each of its signals whose stream no longer reads from it ends, as
    /// its subscription took it for that stream. Its worker is told the
    /// client is gone, so the attempt ends and its source connects again,
    /// offering to whichever subscription takes one of its streams then;
    /// the client is told it closed `source_stopped`.
    pub(crate) fn signals_left_streams(&mut self, connection: &str) {
        let Some(entry) = self.connections.get(connection) else {
            return;
        };
        let (ended, open): (BTreeMap<_, _>, _) = std::mem::take(&mut self.signaling.signals)
            .into_iter()
            .partition(|(_, signal)| {
                signal.connection == connection && !entry.streams.contains(&signal.stream_id)
            });
        self.signaling.signals = open;
        for (signal_id, signal) in ended {
            tracing::info!(
                signal.id = %signal_id,
                connection.id = connection,
                stream.id = %signal.stream_id,
                "signal ended: its stream no longer reads from its connection; its source reconnects"
            );
            self.tell_worker(
                connection,
                signal.worker,
                SignalCommand::Gone {
                    signal_id: signal_id.clone(),
                },
            );
            self.close_signal(
                signal_id,
                &signal,
                SignalCloseCode::SourceStopped,
                "the signal's stream no longer reads from its source".to_owned(),
            );
        }
    }

    /// Ends the subscription `owner`, for `reason`: it gives up its scope
    /// if it still has it, and its signals end at once, without a
    /// `closed`: their workers are told the client is gone, and their
    /// sources connect again after their backoff.
    fn end_subscription(&mut self, owner: Owner, reason: &'static str) {
        self.signaling
            .scopes
            .retain(|_, subscriber| subscriber.owner != owner);
        let (ended, open): (BTreeMap<_, _>, _) = std::mem::take(&mut self.signaling.signals)
            .into_iter()
            .partition(|(_, signal)| signal.owner == owner);
        self.signaling.signals = open;
        for (signal_id, signal) in ended {
            tracing::info!(
                signal.id = %signal_id,
                connection.id = %signal.connection,
                control.connection = owner.connection.0,
                subscription = owner.subscription,
                reason,
                "signal ended with its subscription; its source reconnects"
            );
            self.tell_worker(
                &signal.connection,
                signal.worker,
                SignalCommand::Gone { signal_id },
            );
        }
    }

    /// The daemon shuts down, ahead of its goodbye: every signal whose
    /// offer went out closes `source_stopped`, every signaling
    /// subscription ends, and the waiting opens and held commands are
    /// forgotten, as the workers stop next.
    pub(crate) fn signaling_shutdown(&mut self) {
        let signals = std::mem::take(&mut self.signaling.signals);
        tracing::info!(
            signals = signals.len(),
            subscriptions = self.signaling.scopes.len(),
            "signaling ends: the daemon is shutting down"
        );
        for (signal_id, signal) in signals {
            self.close_signal(
                signal_id,
                &signal,
                SignalCloseCode::SourceStopped,
                "the daemon is shutting down".to_owned(),
            );
        }
        self.signaling.scopes.clear();
        self.signaling.waiting.clear();
        self.signaling.held.clear();
    }

    /// `unsubscribe` of `subscription` of `connection`: true if it was a
    /// signaling subscription, which ends with its signals.
    pub(crate) fn signaling_unsubscribed(
        &mut self,
        connection: ConnectionId,
        subscription: u64,
    ) -> bool {
        let owner = Owner {
            connection,
            subscription,
        };
        let held = self
            .signaling
            .scopes
            .values()
            .any(|subscriber| subscriber.owner == owner);
        if held {
            self.end_subscription(owner, "unsubscribed");
        }
        held
    }

    /// The control connection `connection` closed: its signaling
    /// subscriptions end with their signals.
    pub(crate) fn signaling_connection_closed(&mut self, connection: ConnectionId) {
        let owners: Vec<Owner> = self
            .signaling
            .scopes
            .values()
            .map(|subscriber| subscriber.owner)
            .filter(|owner| owner.connection == connection)
            .collect();
        for owner in owners {
            self.end_subscription(owner, "its control connection closed");
        }
    }

    /// The signal `signal_id` for a command of `connection`: one whose
    /// offer went to a subscription of that connection, else
    /// `signal_not_found`; one the client failed already takes no more
    /// (`invalid_request`).
    fn owned_signal(
        &mut self,
        connection: ConnectionId,
        signal_id: &str,
    ) -> Result<&mut Signal, ApiError> {
        match self.signaling.signals.get_mut(signal_id) {
            Some(signal) if signal.worker_sent.offer && signal.owner.connection == connection => {
                if signal.client_sent.error {
                    return Err(signal_refused(signal_id, "the signal already failed"));
                }
                Ok(signal)
            }
            other => {
                tracing::debug!(
                    signal.id = signal_id,
                    control.connection = connection.0,
                    open = other.is_some(),
                    "signaling command refused: no signal this connection was offered"
                );
                Err(signal_not_found(signal_id))
            }
        }
    }

    /// Queues `command` for the worker `worker` of `connection` on behalf
    /// of the client: `limit_reached` when its driver's queue is full, or
    /// commands of the registry's wait to go before it.
    fn relay(&self, connection: &str, worker: u64, command: SignalCommand) -> Result<(), ApiError> {
        let held = self.signaling.held.contains_key(connection);
        self.connections
            .get(connection)
            .filter(|_| !held)
            .and_then(|entry| {
                entry
                    .commands
                    .try_send(DriverCommand::Signal { worker, command })
                    .ok()
            })
            .ok_or_else(|| {
                ApiError::new(ErrorCode::LimitReached, "the stream's connection is busy")
                    .with_detail("limit", "connection_queue")
            })
    }

    /// `signaling/answer` of `connection`: the camera's answer, once per
    /// signal, to its worker.
    pub(crate) fn signal_answer(
        &mut self,
        connection: ConnectionId,
        answer: &SignalingAnswer,
    ) -> Result<(), ApiError> {
        let signal = self.owned_signal(connection, &answer.signal_id)?;
        if signal.client_sent.answer {
            return Err(signal_refused(
                &answer.signal_id,
                "the signal is already answered",
            ));
        }
        let (worker, serial) = (signal.connection.clone(), signal.worker);
        self.relay(
            &worker,
            serial,
            SignalCommand::Answer {
                signal_id: answer.signal_id.clone(),
                sdp: answer.sdp.clone(),
            },
        )?;
        if let Some(signal) = self.signaling.signals.get_mut(&answer.signal_id) {
            signal.client_sent.answer = true;
        }
        tracing::info!(signal.id = %answer.signal_id, connection.id = %worker, "signaling answer relayed to the source");
        Ok(())
    }

    /// `signaling/candidate` of `connection`: a candidate of the camera's,
    /// at most [`MAX_CLIENT_CANDIDATES`] per signal, or a media section's
    /// end-of-candidates, once per section for at most
    /// [`MAX_ENDED_SECTIONS`], after which no candidate of that section
    /// follows (RFC 8838 §8.2, §13), to its worker.
    pub(crate) fn signal_candidate(
        &mut self,
        connection: ConnectionId,
        candidate: &SignalingCandidate,
    ) -> Result<(), ApiError> {
        let signal = self.owned_signal(connection, &candidate.signal_id)?;
        let end = candidate.candidate.is_empty();
        let section = Section::of(candidate.sdp_mid.as_deref(), candidate.sdp_mline_index);
        if signal.client_sent.ended.contains(&section) {
            return Err(signal_refused(
                &candidate.signal_id,
                "the media section's candidates already ended",
            ));
        }
        if end && signal.client_sent.ended.len() >= MAX_ENDED_SECTIONS {
            return Err(ApiError::new(
                ErrorCode::LimitReached,
                "too many media sections ended for the signal",
            )
            .with_detail("limit", "signal_sections"));
        }
        if !end && signal.client_sent.candidates >= MAX_CLIENT_CANDIDATES {
            return Err(ApiError::new(
                ErrorCode::LimitReached,
                "too many candidates for the signal",
            )
            .with_detail("limit", "signal_candidates"));
        }
        let (worker, serial) = (signal.connection.clone(), signal.worker);
        self.relay(
            &worker,
            serial,
            SignalCommand::Candidate {
                signal_id: candidate.signal_id.clone(),
                candidate: candidate.candidate.clone(),
                mid: candidate.sdp_mid.clone(),
                mline_index: candidate.sdp_mline_index,
            },
        )?;
        if let Some(signal) = self.signaling.signals.get_mut(&candidate.signal_id) {
            signal.client_sent.took_candidate(section, end);
        }
        tracing::debug!(signal.id = %candidate.signal_id, end, "signaling candidate relayed to the source");
        Ok(())
    }

    /// `signaling/error` of `connection`: the camera failed the signal,
    /// once; its worker is told, and its source's close ends it. The
    /// supervisor's own code for a rejection, [`REJECTED`], is not the
    /// client's to send (`invalid_request`), so a source never takes the
    /// camera's failure for its own fault.
    pub(crate) fn signal_error(
        &mut self,
        connection: ConnectionId,
        error: &SignalingError,
    ) -> Result<(), ApiError> {
        if error.code == REJECTED {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "the code is the supervisor's own",
            )
            .with_detail("code", REJECTED));
        }
        let signal = self.owned_signal(connection, &error.signal_id)?;
        let (worker, serial) = (signal.connection.clone(), signal.worker);
        self.relay(
            &worker,
            serial,
            SignalCommand::Failed {
                signal_id: error.signal_id.clone(),
                code: error.code.clone(),
                message: error.message.clone(),
            },
        )?;
        if let Some(signal) = self.signaling.signals.get_mut(&error.signal_id) {
            signal.client_sent.error = true;
        }
        tracing::info!(
            signal.id = %error.signal_id,
            connection.id = %worker,
            code = %error.code,
            message = %plain(&error.message, MAX_MESSAGE_BYTES),
            "the client failed the signal; its source ends the attempt"
        );
        Ok(())
    }

    /// Tells the worker `worker` of `connection` `command`, which the
    /// registry or the driver decided on its own and so must not be lost:
    /// through its driver's queue, or, while that is full or other
    /// commands are held before it, held until the driver takes it
    /// ([`State::take_held_signals`]). One for a connection that is gone,
    /// or past [`MAX_HELD_SIGNALS`], is dropped.
    pub(crate) fn tell_worker(&mut self, connection: &str, worker: u64, command: SignalCommand) {
        let Some(entry) = self.connections.get(connection) else {
            tracing::debug!(
                connection.id = connection,
                ?command,
                "signal command for a connection that is gone; dropped"
            );
            return;
        };
        if !self.signaling.held.contains_key(connection)
            && let Ok(permit) = entry.commands.try_reserve()
        {
            permit.send(DriverCommand::Signal { worker, command });
            return;
        }
        let queued = entry
            .commands
            .max_capacity()
            .saturating_sub(entry.commands.capacity());
        let full = self
            .signaling
            .held
            .get(connection)
            .is_some_and(|held| held.commands.len() >= MAX_HELD_SIGNALS);
        if full {
            let now = self.signaling.clock.now();
            if let Some(count) = self.signaling.line(connection, Line::Dropped, now) {
                tracing::error!(
                    connection.id = connection,
                    ?command,
                    limit = MAX_HELD_SIGNALS,
                    count,
                    "signal command dropped: its driver takes none of those held for it"
                );
            }
            return;
        }
        let held = self
            .signaling
            .held
            .entry(connection.to_owned())
            .or_insert_with(|| Held {
                commands: VecDeque::new(),
                ahead: queued.saturating_add(1),
            });
        tracing::debug!(
            connection.id = connection,
            ?command,
            "the driver's queue is full; signal command held until it takes it"
        );
        held.commands.push_back((worker, command));
    }

    /// The driver of `connection` handled a command, its queue now
    /// `drained` or not: the commands held for its worker while the queue
    /// was full, oldest first, each with the worker's serial, once it has
    /// handled those its queue held when the first was held
    /// ([`Held::ahead`]) or its queue is empty, else none yet. So they go
    /// after everything queued before them and before anything the
    /// registry or the driver tells the worker after, and a queue that
    /// other commands keep from emptying holds them up for at most one
    /// queue's worth.
    pub(crate) fn take_held_signals(
        &mut self,
        connection: &str,
        drained: bool,
    ) -> VecDeque<(u64, SignalCommand)> {
        let Entry::Occupied(mut held) = self.signaling.held.entry(connection.to_owned()) else {
            return VecDeque::new();
        };
        let ahead = held.get().ahead.saturating_sub(1);
        held.get_mut().ahead = ahead;
        if drained || ahead == 0 {
            held.remove().commands
        } else {
            VecDeque::new()
        }
    }
}

#[cfg(test)]
impl State {
    /// The ids of the open signals, in order, for other modules' tests.
    pub(crate) fn signal_ids_for_tests(&self) -> Vec<String> {
        self.signaling.signals.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::UNIX_EPOCH;

    use lotse_core::let_assert;
    use serde_json::{Value, json};
    use tokio::sync::watch;

    use super::*;
    use crate::registry::{
        ConnectionEntry, ConnectionKey, ConnectionSnapshot, SourceTarget, Talker,
    };
    use crate::test_support::Captured;

    /// The serial of the workers the tests' reports come from.
    const WORKER: u64 = 3;

    /// The driver queues of a test's connections.
    struct Queues(BTreeMap<String, mpsc::Receiver<DriverCommand>>);

    impl Queues {
        /// The signal commands `connection`'s driver got so far, with the
        /// serial of the worker each is for.
        fn take_for(&mut self, connection: &str) -> Vec<(u64, SignalCommand)> {
            let queue = self.0.get_mut(connection).unwrap();
            let mut taken = Vec::new();
            while let Ok(command) = queue.try_recv() {
                let_assert!(DriverCommand::Signal { worker, command } = command);
                taken.push((worker, command));
            }
            taken
        }

        /// The signal commands `connection`'s driver got so far, each for
        /// worker [`WORKER`].
        fn take(&mut self, connection: &str) -> Vec<SignalCommand> {
            self.take_for(connection)
                .into_iter()
                .map(|(worker, command)| {
                    assert_eq!(worker, WORKER, "{command:?}");
                    command
                })
                .collect()
        }
    }

    /// Worker [`WORKER`] of `connection`.
    fn from(connection: &str) -> SignalFrom<'_> {
        SignalFrom {
            connection,
            worker: WORKER,
        }
    }

    /// A time a summary interval after the one this gave before, so a
    /// test's lines are never rate-limited unless it means them to be.
    fn later() -> Instant {
        thread_local! {
            static CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
            static START: Instant = SystemClock.now();
        }
        let calls = CALLS.with(|calls| {
            calls.set(calls.get() + 1);
            calls.get()
        });
        START.with(|start| *start + lotse_core::throttle::SUMMARY_INTERVAL * calls)
    }

    /// `report` of worker [`WORKER`] of `connection`, [`later`].
    fn report(state: &mut State, connection: &str, report: SignalReport) {
        report_at(state, connection, report, later());
    }

    /// `report` of worker [`WORKER`] of `connection` at `now`.
    fn report_at(state: &mut State, connection: &str, report: SignalReport, now: Instant) {
        state.signal_report(&from(connection), report, now, UNIX_EPOCH);
    }

    /// A state with the signaled connections `c1` of stream `door` and
    /// `c2` of stream `yard`, whose drivers' queues hold `capacity`
    /// commands, and two local addresses.
    fn signaled_state(capacity: usize) -> (State, Queues) {
        let mut state = State::default();
        state.signaling.local_addrs = vec![[192, 0, 2, 7].into(), [0_u16; 8].into()];
        let mut drivers = BTreeMap::new();
        for (id, stream) in [("c1", "door"), ("c2", "yard")] {
            let (commands, queued) = mpsc::channel(capacity);
            state.connections.insert(
                id.into(),
                ConnectionEntry {
                    key: ConnectionKey {
                        target: SourceTarget::Signaled {
                            protocol: "webrtc",
                            stream: stream.into(),
                        },
                        options: Value::Null,
                    },
                    port: None,
                    backchannel: false,
                    prerecord_ms: 0,
                    demand: watch::channel(crate::driver::Demand::default()).0,
                    snapshot: ConnectionSnapshot::idle(UNIX_EPOCH),
                    switches: 0,
                    streams: [stream.to_owned()].into(),
                    commands,
                    talker: Talker::default(),
                },
            );
            drivers.insert(id.to_owned(), queued);
        }
        (state, Queues(drivers))
    }

    const fn owner(connection: u64, subscription: u64) -> Owner {
        Owner {
            connection: ConnectionId(connection),
            subscription,
        }
    }

    fn subscribe(
        state: &mut State,
        owner: Owner,
        stream_id: Option<&str>,
    ) -> mpsc::Receiver<Event> {
        state.signaling_subscribe(owner, stream_id.map(str::to_owned), (later(), UNIX_EPOCH))
    }

    /// The events `events` holds now, each a signaling one.
    fn events(events: &mut mpsc::Receiver<Event>) -> Vec<Value> {
        let mut taken = Vec::new();
        while let Ok(event) = events.try_recv() {
            assert_eq!(event.class, EventClass::Signaling);
            taken.push(event.payload);
        }
        taken
    }

    fn open(state: &mut State, connection: &str, request: u64) {
        report(state, connection, SignalReport::Open { request });
    }

    /// The signal id the worker of `connection` was told its open
    /// `request` got.
    fn opened(queues: &mut Queues, connection: &str, request: u64) -> String {
        let taken = queues.take(connection);
        let_assert!(
            [SignalCommand::Opened {
                request: got,
                signal_id,
                local_addrs
            }] = taken.as_slice(),
            "{taken:?}"
        );
        assert_eq!(*got, request);
        assert_eq!(
            *local_addrs,
            [IpAddr::from([192, 0, 2, 7]), IpAddr::from([0_u16; 8])]
        );
        signal_id.clone()
    }

    fn offer(state: &mut State, connection: &str, signal_id: &str) {
        report(
            state,
            connection,
            SignalReport::Offer {
                signal_id: signal_id.into(),
                sdp: "v=0\r\n".into(),
            },
        );
    }

    fn candidate(signal_id: &str, candidate: &str, mline_index: Option<u16>) -> SignalReport {
        SignalReport::Candidate {
            signal_id: signal_id.into(),
            candidate: candidate.into(),
            mid: mline_index.map(|_| "0".to_owned()),
            mline_index,
        }
    }

    /// A worker's candidate report for the media section `mid`, its index
    /// unnamed.
    fn candidate_of(signal_id: &str, candidate: &str, mid: &str) -> SignalReport {
        SignalReport::Candidate {
            signal_id: signal_id.into(),
            candidate: candidate.into(),
            mid: Some(mid.into()),
            mline_index: None,
        }
    }

    fn closed(signal_id: &str, code: &str) -> SignalReport {
        SignalReport::Closed {
            signal_id: signal_id.into(),
            code: code.into(),
            message: format!("{code} happened"),
        }
    }

    /// A signal of `c1` opened and offered to a subscription for every
    /// stream of control connection 1, with that subscription's events.
    fn offered() -> (State, Queues, String, mpsc::Receiver<Event>) {
        let (mut state, mut queues) = signaled_state(8);
        let mut subscription = subscribe(&mut state, owner(1, 1), None);
        open(&mut state, "c1", 1);
        let signal_id = opened(&mut queues, "c1", 1);
        offer(&mut state, "c1", &signal_id);
        assert_eq!(events(&mut subscription).len(), 1);
        (state, queues, signal_id, subscription)
    }

    /// A signal is named by its ULID; without randomness, by its count,
    /// with a warning.
    #[test]
    fn a_signal_without_randomness_for_its_ulid_is_named_by_its_count() {
        let captured = Captured::default();
        let _logs = captured.install();
        assert_eq!(
            signal_id(Ok("01ARYZ6S41TSV4RRFFQ69G5FAV".into()), 7),
            "01ARYZ6S41TSV4RRFFQ69G5FAV"
        );
        assert_eq!(captured.lines("no randomness"), Vec::<String>::new());
        assert_eq!(
            signal_id(Err(getrandom::Error::UNSUPPORTED), 7),
            "00000000000000000000000007"
        );
        assert_eq!(
            captured
                .lines("no randomness for a signal's ULID; its count names it")
                .len(),
            1
        );
    }

    #[test]
    fn rfc8838_a_subscription_gets_its_stream_s_offer_candidates_and_close() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues) = signaled_state(8);
        let mut all = subscribe(&mut state, owner(1, 1), None);
        open(&mut state, "c1", 4);
        let signal_id = opened(&mut queues, "c1", 4);
        assert_eq!(signal_id.len(), 26, "a ULID: {signal_id}");
        assert!(events(&mut all).is_empty(), "nothing before the offer");
        offer(&mut state, "c1", &signal_id);
        let host = "candidate:1 1 udp 2130706431 192.0.2.7 9 typ host";
        for signal in [
            candidate(&signal_id, host, Some(0)),
            // Unnamed, the media section is the first.
            candidate(&signal_id, host, None),
            candidate(&signal_id, "", Some(1)),
            closed(&signal_id, "ice_failed"),
        ] {
            report(&mut state, "c1", signal);
        }
        assert_eq!(
            events(&mut all),
            [
                // The stream and its source's protocol: a signaled
                // source has no address.
                json!({ "type": "offer", "signal_id": signal_id, "stream_id": "door",
                        "protocol": "webrtc", "sdp": "v=0\r\n" }),
                json!({ "type": "candidate", "signal_id": signal_id, "candidate": host,
                        "sdp_mid": "0", "sdp_mline_index": 0 }),
                json!({ "type": "candidate", "signal_id": signal_id, "candidate": host,
                        "sdp_mline_index": 0 }),
                json!({ "type": "candidate", "signal_id": signal_id, "candidate": "",
                        "sdp_mid": "0", "sdp_mline_index": 1 }),
                json!({ "type": "closed", "signal_id": signal_id, "code": "ice_failed",
                        "message": "ice_failed happened" }),
            ]
        );
        assert!(state.signaling.signals.is_empty());
        // A close code the API does not know is an internal error.
        open(&mut state, "c1", 5);
        let signal_id = opened(&mut queues, "c1", 5);
        offer(&mut state, "c1", &signal_id);
        report(&mut state, "c1", closed(&signal_id, "made_up"));
        let closing = events(&mut all).pop().unwrap();
        assert_eq!(closing["code"], "internal_error");
        assert_eq!(closing["message"], "made_up happened");
        // A signal closed before its offer is closed quietly, whatever
        // the code: a WebRTC source without a host address closes
        // `internal_error` before it offers.
        for (request, code) in [(6, "source_stopped"), (7, "internal_error")] {
            open(&mut state, "c1", request);
            let signal_id = opened(&mut queues, "c1", request);
            report(&mut state, "c1", closed(&signal_id, code));
            assert_eq!(events(&mut all), Vec::<Value>::new(), "{code}");
        }
        assert_eq!(captured.lines("signal closed by its source").len(), 4);
        assert_eq!(
            captured
                .lines("signal opened; it belongs to the subscription that takes its stream")
                .len(),
            4
        );
    }

    #[test]
    fn a_worker_reports_only_on_its_own_signals() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues, signal_id, mut all) = offered();
        // Another worker's report, or one on a signal that is gone, is
        // dropped.
        offer(&mut state, "c2", &signal_id);
        report(&mut state, "c2", candidate(&signal_id, "", None));
        report(&mut state, "c2", closed(&signal_id, "peer_closed"));
        offer(&mut state, "c1", "gone");
        assert_eq!(events(&mut all), Vec::<Value>::new());
        assert!(queues.take("c1").is_empty() && queues.take("c2").is_empty());
        assert_eq!(
            captured
                .lines("a worker reported on a signal the supervisor does not hold; dropped")
                .len(),
            4
        );
        assert!(state.signaling.signals.contains_key(&signal_id));
    }

    #[test]
    fn rfc8838_13_a_worker_past_its_signal_s_budget_ends_it_internal_error() {
        let captured = Captured::default();
        let _logs = captured.install();
        // The worker hears the relay rejected it: its source's fault.
        let failed = |signal_id: &str, reason: &str| {
            [SignalCommand::Failed {
                signal_id: signal_id.into(),
                code: "signal_rejected".into(),
                message: format!("the worker sent {reason}"),
            }]
        };
        let closing = |signal_id: &str, reason: &str| {
            json!({ "type": "closed", "signal_id": signal_id, "code": "internal_error",
                    "message": format!("the worker sent {reason}") })
        };
        // A second offer.
        let (mut state, mut queues, signal_id, mut all) = offered();
        offer(&mut state, "c1", &signal_id);
        assert_eq!(queues.take("c1"), failed(&signal_id, "a second offer"));
        assert_eq!(events(&mut all), [closing(&signal_id, "a second offer")]);
        assert!(state.signaling.signals.is_empty());
        // A second end-of-candidates for the same media section.
        let (mut state, mut queues, signal_id, mut all) = offered();
        report(&mut state, "c1", candidate(&signal_id, "", Some(0)));
        report(&mut state, "c1", candidate(&signal_id, "", Some(0)));
        let reason = "a candidate after its media section's end-of-candidates";
        assert_eq!(queues.take("c1"), failed(&signal_id, reason));
        assert_eq!(events(&mut all)[1], closing(&signal_id, reason));
        // More candidates than a signal takes; their end-of-candidates
        // is no candidate, and still fits.
        let (mut state, mut queues, signal_id, mut all) = offered();
        let host = "candidate:1 1 udp 1 192.0.2.7 9 typ host";
        for _ in 0..MAX_WORKER_CANDIDATES {
            report(&mut state, "c1", candidate(&signal_id, host, Some(0)));
        }
        report(&mut state, "c1", candidate(&signal_id, host, Some(0)));
        let reason = "more candidates than a signal allows";
        assert_eq!(queues.take("c1"), failed(&signal_id, reason));
        let got = events(&mut all);
        assert_eq!(got.len(), 65);
        assert_eq!(got[64], closing(&signal_id, reason));
        let (mut state, mut queues, signal_id, mut all) = offered();
        for _ in 0..MAX_WORKER_CANDIDATES {
            report(&mut state, "c1", candidate(&signal_id, host, Some(0)));
        }
        report(&mut state, "c1", candidate(&signal_id, "", Some(0)));
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        assert_eq!(events(&mut all).len(), 65);
        // A candidate before the offer: the client does not know the
        // signal, so only the worker hears of it.
        let (mut state, mut queues) = signaled_state(8);
        let mut all = subscribe(&mut state, owner(1, 1), None);
        open(&mut state, "c1", 1);
        let signal_id = opened(&mut queues, "c1", 1);
        report(&mut state, "c1", candidate(&signal_id, host, Some(0)));
        assert_eq!(
            queues.take("c1"),
            failed(&signal_id, "a candidate before the offer")
        );
        assert_eq!(events(&mut all), Vec::<Value>::new());
        assert_eq!(
            captured
                .lines("a worker's signaling breaks the contract; signal ended")
                .len(),
            4
        );
    }

    #[test]
    fn rfc8838_8_2_a_worker_s_end_of_candidates_ends_only_its_media_section() {
        let failed = |signal_id: &str, reason: &str| {
            [SignalCommand::Failed {
                signal_id: signal_id.into(),
                code: "signal_rejected".into(),
                message: format!("the worker sent {reason}"),
            }]
        };
        let closing = |signal_id: &str, reason: &str| {
            json!({ "type": "closed", "signal_id": signal_id, "code": "internal_error",
                    "message": format!("the worker sent {reason}") })
        };
        let host = "candidate:1 1 udp 1 192.0.2.7 9 typ host";
        // Section "0" ends and section "1" still trickles; the sections
        // up to the bound end, and a candidate of one more still goes.
        let (mut state, mut queues, signal_id, mut all) = offered();
        report(&mut state, "c1", candidate_of(&signal_id, "", "0"));
        report(&mut state, "c1", candidate_of(&signal_id, host, "1"));
        for mid in 1..MAX_ENDED_SECTIONS {
            report(
                &mut state,
                "c1",
                candidate_of(&signal_id, "", &mid.to_string()),
            );
        }
        report(&mut state, "c1", candidate_of(&signal_id, host, "8"));
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        let got = events(&mut all);
        assert_eq!(got.len(), MAX_ENDED_SECTIONS + 2);
        assert_eq!(
            got[1],
            json!({ "type": "candidate", "signal_id": signal_id, "candidate": host,
                    "sdp_mid": "1", "sdp_mline_index": 0 })
        );
        // One more section's end is past the bound.
        report(&mut state, "c1", candidate_of(&signal_id, "", "8"));
        let reason = "more media sections ended than a signal allows";
        assert_eq!(queues.take("c1"), failed(&signal_id, reason));
        assert_eq!(events(&mut all), [closing(&signal_id, reason)]);
        // A candidate of a section after its own end-of-candidates.
        let (mut state, mut queues, signal_id, mut all) = offered();
        report(&mut state, "c1", candidate_of(&signal_id, "", "0"));
        report(&mut state, "c1", candidate_of(&signal_id, host, "0"));
        let reason = "a candidate after its media section's end-of-candidates";
        assert_eq!(queues.take("c1"), failed(&signal_id, reason));
        assert_eq!(events(&mut all)[1], closing(&signal_id, reason));
    }

    #[test]
    fn an_open_no_subscription_takes_waits_and_is_refused_no_signaling_client_when_its_wait_ends() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues) = signaled_state(8);
        // A subscription for another stream takes none of `door`'s.
        let _yard = subscribe(&mut state, owner(1, 1), Some("yard"));
        open(&mut state, "c1", 1);
        open(&mut state, "c1", 2);
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        assert_eq!(
            captured
                .lines("no signaling subscription takes the stream; the open waits for one")
                .len(),
            2
        );
        assert!(state.signal_wait_expired(&from("c1"), 1, later()));
        assert_eq!(
            queues.take("c1"),
            [SignalCommand::Refused {
                request: 1,
                code: "no_signaling_client".into(),
                message: "no control-API client relays this source's signaling".into(),
            }]
        );
        // Once: an open answered, another worker's or another
        // connection's is not refused, and the driver is told it need
        // not wait for an answer.
        let earlier = SignalFrom {
            connection: "c1",
            worker: WORKER - 1,
        };
        assert!(!state.signal_wait_expired(&from("c1"), 1, later()));
        assert!(!state.signal_wait_expired(&earlier, 2, later()));
        assert!(!state.signal_wait_expired(&from("c2"), 2, later()));
        assert!(queues.take("c1").is_empty() && queues.take("c2").is_empty());
        // A cancel takes a waiting open back; a subscription finds none.
        report(&mut state, "c1", SignalReport::Cancel { request: 2 });
        report(&mut state, "c1", SignalReport::Cancel { request: 2 });
        assert_eq!(
            captured
                .lines("signaling open cancelled while it waited for a client")
                .len(),
            1
        );
        assert_eq!(
            captured
                .lines("signaling open cancelled; nothing holds it")
                .len(),
            1
        );
        let _door = subscribe(&mut state, owner(1, 2), Some("door"));
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        // The open of a connection that is gone is dropped.
        open(&mut state, "gone", 3);
        assert_eq!(state.signaling.waiting, Vec::<WaitingOpen>::new());
        assert_eq!(
            captured
                .lines("signaling open of a connection that is gone; dropped")
                .len(),
            1
        );
    }

    #[test]
    fn a_subscription_in_time_serves_the_opens_waiting_for_its_scope() {
        let (mut state, mut queues) = signaled_state(8);
        open(&mut state, "c1", 1);
        open(&mut state, "c2", 1);
        open(&mut state, "c1", 2);
        // `yard`'s subscription serves its open, the others wait on.
        let mut yard = subscribe(&mut state, owner(1, 1), Some("yard"));
        let yard_signal = opened(&mut queues, "c2", 1);
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        assert_eq!(
            state.signaling.waiting,
            [1, 2].map(|request| WaitingOpen {
                connection: "c1".into(),
                worker: WORKER,
                request
            })
        );
        // One for every stream serves the rest, in order.
        let mut all = subscribe(&mut state, owner(2, 1), None);
        let taken = queues.take("c1");
        let_assert!(
            [
                SignalCommand::Opened {
                    request: 1,
                    signal_id: first,
                    ..
                },
                SignalCommand::Opened {
                    request: 2,
                    signal_id: second,
                    ..
                },
            ] = taken.as_slice()
        );
        assert_ne!(first, second, "a new ULID per signal");
        assert_eq!(state.signaling.waiting, Vec::<WaitingOpen>::new());
        offer(&mut state, "c2", &yard_signal);
        offer(&mut state, "c1", first);
        assert_eq!(events(&mut yard)[0]["signal_id"], yard_signal.as_str());
        assert_eq!(events(&mut all)[0]["signal_id"], first.as_str());
        // Waiting opens of a connection that went are forgotten with it.
        open(&mut state, "c2", 2);
        let _gone = state.connections.remove("c2");
        state.signals_ended("c2", SignalCloseCode::SourceStopped, "gone");
        assert_eq!(state.signaling.waiting, Vec::<WaitingOpen>::new());
    }

    #[test]
    fn a_stream_s_subscription_beats_the_one_for_every_stream_and_a_later_one_supersedes_the_earlier()
     {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues) = signaled_state(8);
        let mut all = subscribe(&mut state, owner(1, 1), None);
        open(&mut state, "c1", 1);
        let kept = opened(&mut queues, "c1", 1);
        offer(&mut state, "c1", &kept);
        // `door`'s own subscription takes its new signals; the earlier
        // one keeps the signal it has, and every other stream.
        let mut door = subscribe(&mut state, owner(2, 1), Some("door"));
        assert!(queues.take("c1").is_empty(), "nothing ends");
        open(&mut state, "c1", 2);
        let taken = opened(&mut queues, "c1", 2);
        offer(&mut state, "c1", &taken);
        open(&mut state, "c2", 1);
        let yard = opened(&mut queues, "c2", 1);
        offer(&mut state, "c2", &yard);
        assert_eq!(events(&mut door)[0]["signal_id"], taken.as_str());
        let got = events(&mut all);
        assert_eq!(got[0]["signal_id"], kept.as_str());
        assert_eq!(got[1]["signal_id"], yard.as_str());
        // A later subscription for every stream supersedes the earlier:
        // `superseded` last, and its signals end without a `closed`.
        let mut later = subscribe(&mut state, owner(1, 2), None);
        assert_eq!(events(&mut all), [json!({ "type": "superseded" })]);
        assert!(all.try_recv().is_err() && all.is_closed(), "it ended");
        assert_eq!(
            queues.take("c1"),
            [SignalCommand::Gone {
                signal_id: kept.clone()
            }]
        );
        assert_eq!(
            queues.take("c2"),
            [SignalCommand::Gone {
                signal_id: yard.clone()
            }]
        );
        assert_eq!(
            captured
                .lines("signal ended with its subscription; its source reconnects")
                .len(),
            2
        );
        // `door`'s signal is its own subscription's, which stays.
        report(&mut state, "c1", candidate(&taken, "", None));
        assert_eq!(events(&mut door).len(), 1);
        assert_eq!(events(&mut later), Vec::<Value>::new());
        // So is a later one for `door`, which supersedes its earlier.
        let _door_later = subscribe(&mut state, owner(3, 1), Some("door"));
        assert_eq!(events(&mut door), [json!({ "type": "superseded" })]);
        assert_eq!(
            queues.take("c1"),
            [SignalCommand::Gone { signal_id: taken }]
        );
        assert_eq!(captured.lines("signaling subscription superseded").len(), 2);
    }

    #[test]
    fn unsubscribe_and_a_closed_control_connection_end_a_subscription_s_signals() {
        let (mut state, mut queues, signal_id, _all) = offered();
        // Not a signaling subscription, or not this connection's.
        assert!(!state.signaling_unsubscribed(ConnectionId(1), 9));
        assert!(!state.signaling_unsubscribed(ConnectionId(2), 1));
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        assert!(state.signaling_unsubscribed(ConnectionId(1), 1));
        assert_eq!(queues.take("c1"), [SignalCommand::Gone { signal_id }]);
        assert!(state.signaling.signals.is_empty() && state.signaling.scopes.is_empty());
        // The next open waits.
        open(&mut state, "c1", 2);
        assert_eq!(state.signaling.waiting.len(), 1);

        let (mut state, mut queues, signal_id, _all) = offered();
        let _other = subscribe(&mut state, owner(2, 1), Some("yard"));
        let _orphans = state.connection_closed(ConnectionId(1));
        assert_eq!(queues.take("c1"), [SignalCommand::Gone { signal_id }]);
        assert_eq!(
            state.signaling.scopes.len(),
            1,
            "another connection's stays"
        );
        state.signaling_connection_closed(ConnectionId(3));
        assert_eq!(state.signaling.scopes.len(), 1);
    }

    #[test]
    fn a_connection_s_signals_close_with_its_worker_or_its_release() {
        let (mut state, mut queues, signal_id, mut all) = offered();
        open(&mut state, "c1", 2);
        let quiet = opened(&mut queues, "c1", 2);
        open(&mut state, "c2", 1);
        let yard = opened(&mut queues, "c2", 1);
        offer(&mut state, "c2", &yard);
        let _offer = events(&mut all);
        state.signals_ended("c1", SignalCloseCode::WorkerGone, "the worker exited");
        // The one not offered yet closes quietly; another connection's
        // stays open.
        assert_eq!(
            events(&mut all),
            [
                json!({ "type": "closed", "signal_id": signal_id, "code": "worker_gone",
                     "message": "the worker exited" })
            ]
        );
        assert!(!state.signaling.signals.contains_key(&quiet));
        assert!(state.signaling.signals.contains_key(&yard));
        assert!(
            queues.take("c1").is_empty(),
            "the worker is gone: no one to tell"
        );
        // A connection released ends its signals `source_stopped`.
        state.streams.clear();
        state.refresh_connection("c2");
        assert_eq!(
            events(&mut all),
            [
                json!({ "type": "closed", "signal_id": yard, "code": "source_stopped",
                     "message": "the stream's source was removed" })
            ]
        );
    }

    #[test]
    fn rfc8829_5_3_only_the_owning_connection_answers_trickles_or_fails_a_signal() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues, signal_id, _all) = offered();
        let answer = |signal_id: &str| SignalingAnswer {
            id: 2,
            signal_id: signal_id.into(),
            sdp: "v=0\r\n".into(),
        };
        let candidate = |signal_id: &str| SignalingCandidate {
            id: 3,
            signal_id: signal_id.into(),
            candidate: String::new(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
        };
        let error = |signal_id: &str| SignalingError {
            id: 4,
            signal_id: signal_id.into(),
            code: "offline".into(),
            message: "the camera is offline".into(),
        };
        // Another connection, or a signal that is not open, gets
        // `signal_not_found`, and the worker hears nothing.
        for (connection, id) in [
            (ConnectionId(2), signal_id.as_str()),
            (ConnectionId(1), "gone"),
        ] {
            for refused in [
                state.signal_answer(connection, &answer(id)),
                state.signal_candidate(connection, &candidate(id)),
                state.signal_error(connection, &error(id)),
            ] {
                let error = refused.unwrap_err();
                assert_eq!(error.code, ErrorCode::SignalNotFound);
                assert_eq!(error.details["signal_id"], id);
            }
        }
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        // A signal whose offer has not gone out is no one's yet.
        open(&mut state, "c1", 2);
        let unoffered = opened(&mut queues, "c1", 2);
        let error_code = state
            .signal_answer(ConnectionId(1), &answer(&unoffered))
            .unwrap_err()
            .code;
        assert_eq!(error_code, ErrorCode::SignalNotFound);
        assert_eq!(
            captured
                .lines("signaling command refused: no signal this connection was offered")
                .len(),
            7
        );
        // The owner's reach the worker; one answer per signal.
        state
            .signal_answer(ConnectionId(1), &answer(&signal_id))
            .unwrap();
        state
            .signal_candidate(ConnectionId(1), &candidate(&signal_id))
            .unwrap();
        let again = state
            .signal_answer(ConnectionId(1), &answer(&signal_id))
            .unwrap_err();
        assert_eq!(again.code, ErrorCode::InvalidRequest);
        assert_eq!(again.message, "the signal is already answered");
        state
            .signal_error(ConnectionId(1), &error(&signal_id))
            .unwrap();
        assert_eq!(
            queues.take("c1"),
            [
                SignalCommand::Answer {
                    signal_id: signal_id.clone(),
                    sdp: "v=0\r\n".into(),
                },
                SignalCommand::Candidate {
                    signal_id: signal_id.clone(),
                    candidate: String::new(),
                    mid: Some("0".into()),
                    mline_index: Some(0),
                },
                SignalCommand::Failed {
                    signal_id: signal_id.clone(),
                    code: "offline".into(),
                    message: "the camera is offline".into(),
                },
            ]
        );
        // The source's close ends it.
        report(&mut state, "c1", closed(&signal_id, "camera_error"));
        let error_code = state
            .signal_error(ConnectionId(1), &error(&signal_id))
            .unwrap_err()
            .code;
        assert_eq!(error_code, ErrorCode::SignalNotFound);
    }

    #[test]
    fn a_signal_its_client_failed_takes_nothing_more_from_it() {
        let (mut state, mut queues, signal_id, _all) = offered();
        let answer = |signal_id: &str| SignalingAnswer {
            id: 2,
            signal_id: signal_id.into(),
            sdp: "v=0\r\n".into(),
        };
        let candidate = |signal_id: &str| SignalingCandidate {
            id: 3,
            signal_id: signal_id.into(),
            candidate: String::new(),
            sdp_mid: None,
            sdp_mline_index: None,
        };
        let error = |signal_id: &str| SignalingError {
            id: 4,
            signal_id: signal_id.into(),
            code: "offline".into(),
            message: "the camera is offline".into(),
        };
        state
            .signal_answer(ConnectionId(1), &answer(&signal_id))
            .unwrap();
        state
            .signal_error(ConnectionId(1), &error(&signal_id))
            .unwrap();
        assert_eq!(queues.take("c1").len(), 2);
        // Once failed, the signal takes no second error, answer or
        // candidate while its source's close is on the way.
        open(&mut state, "c1", 3);
        let fresh = opened(&mut queues, "c1", 3);
        offer(&mut state, "c1", &fresh);
        for refused in [
            state.signal_error(ConnectionId(1), &error(&signal_id)),
            state.signal_candidate(ConnectionId(1), &candidate(&signal_id)),
        ] {
            let refused = refused.unwrap_err();
            assert_eq!(refused.code, ErrorCode::InvalidRequest);
            assert_eq!(refused.message, "the signal already failed");
            assert_eq!(refused.details["signal_id"], signal_id.as_str());
        }
        state.signal_error(ConnectionId(1), &error(&fresh)).unwrap();
        let refused = state
            .signal_answer(ConnectionId(1), &answer(&fresh))
            .unwrap_err();
        assert_eq!(refused.message, "the signal already failed");
        assert_eq!(queues.take("c1").len(), 1, "the fresh one's error only");
    }

    /// `signal_rejected` is the supervisor's code for a rejection of the
    /// source's own signaling: a client's error under it would end the
    /// source as a protocol error of its own, so it is refused.
    #[test]
    fn a_client_s_error_never_reaches_a_source_as_the_supervisor_s_rejection() {
        let (mut state, mut queues, signal_id, _all) = offered();
        let refused = state
            .signal_error(
                ConnectionId(1),
                &SignalingError {
                    id: 2,
                    signal_id: signal_id.clone(),
                    code: REJECTED.into(),
                    message: "m".into(),
                },
            )
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidRequest);
        assert_eq!(refused.details["code"], "signal_rejected");
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        // The signal still takes the client's own code.
        state
            .signal_error(
                ConnectionId(1),
                &SignalingError {
                    id: 3,
                    signal_id,
                    code: "signal_rejected_by_camera".into(),
                    message: "m".into(),
                },
            )
            .unwrap();
        assert_eq!(queues.take("c1").len(), 1);
    }

    /// The client's message is logged on one line, so it cannot forge
    /// another.
    #[test]
    fn a_client_s_error_message_is_logged_plain() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, _queues, signal_id, _all) = offered();
        state
            .signal_error(
                ConnectionId(1),
                &SignalingError {
                    id: 2,
                    signal_id,
                    code: "offline".into(),
                    message: "gone\r\nlevel=ERROR forged".into(),
                },
            )
            .unwrap();
        let lines = captured.lines("the client failed the signal");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("gone  level=ERROR forged"), "{lines:?}");
        assert!(!lines[0].contains('\n'), "{lines:?}");
    }

    #[test]
    fn a_signal_takes_64_client_candidates_and_a_busy_driver_refuses_them_until_it_drains() {
        let (mut state, mut queues, signal_id, _all) = offered();
        let candidate = SignalingCandidate {
            id: 2,
            signal_id: signal_id.clone(),
            candidate: "candidate:1 1 udp 1 198.51.100.1 9 typ host".into(),
            sdp_mid: None,
            sdp_mline_index: None,
        };
        let answer = SignalingAnswer {
            id: 3,
            signal_id: signal_id.clone(),
            sdp: "v=0\r\n".into(),
        };
        // The driver's queue holds 8: what it cannot take is refused and
        // not counted, and the answer may come again.
        for _ in 0..8 {
            state.signal_candidate(ConnectionId(1), &candidate).unwrap();
        }
        let busy = state
            .signal_candidate(ConnectionId(1), &candidate)
            .unwrap_err();
        assert_eq!(busy.code, ErrorCode::LimitReached);
        assert_eq!(busy.details["limit"], "connection_queue");
        let busy = state.signal_answer(ConnectionId(1), &answer).unwrap_err();
        assert_eq!(busy.code, ErrorCode::LimitReached);
        let failure = SignalingError {
            id: 4,
            signal_id,
            code: "c".into(),
            message: "m".into(),
        };
        let busy = state.signal_error(ConnectionId(1), &failure).unwrap_err();
        assert_eq!(busy.code, ErrorCode::LimitReached);
        assert_eq!(queues.take("c1").len(), 8);
        state.signal_answer(ConnectionId(1), &answer).unwrap();
        let _answer = queues.take("c1");
        for sent in 8..MAX_CLIENT_CANDIDATES {
            state.signal_candidate(ConnectionId(1), &candidate).unwrap();
            if sent % 8 == 7 {
                let _drained = queues.take("c1");
            }
        }
        let over = state
            .signal_candidate(ConnectionId(1), &candidate)
            .unwrap_err();
        assert_eq!(over.code, ErrorCode::LimitReached);
        assert_eq!(over.details["limit"], "signal_candidates");
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        // RFC 8838 §13: the end-of-candidates is no candidate and still
        // fits, once; nothing follows it.
        let end = SignalingCandidate {
            candidate: String::new(),
            ..candidate.clone()
        };
        state.signal_candidate(ConnectionId(1), &end).unwrap();
        assert_eq!(
            queues.take("c1"),
            [SignalCommand::Candidate {
                signal_id: candidate.signal_id.clone(),
                candidate: String::new(),
                mid: None,
                mline_index: None,
            }]
        );
        for after in [&end, &candidate] {
            let refused = state.signal_candidate(ConnectionId(1), after).unwrap_err();
            assert_eq!(refused.code, ErrorCode::InvalidRequest);
            assert_eq!(
                refused.message,
                "the media section's candidates already ended"
            );
        }
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
    }

    #[test]
    fn rfc8838_8_2_a_client_s_end_of_candidates_ends_only_its_media_section() {
        let (mut state, mut queues, signal_id, _all) = offered();
        let sent =
            |candidate: &str, mid: Option<&str>, mline_index: Option<u16>| SignalingCandidate {
                id: 2,
                signal_id: signal_id.clone(),
                candidate: candidate.into(),
                sdp_mid: mid.map(Into::into),
                sdp_mline_index: mline_index,
            };
        let relayed = |candidate: &str, mid: Option<&str>, mline_index: Option<u16>| {
            SignalCommand::Candidate {
                signal_id: signal_id.clone(),
                candidate: candidate.into(),
                mid: mid.map(Into::into),
                mline_index,
            }
        };
        let host = "candidate:1 1 udp 1 198.51.100.1 9 typ host";
        // Section "0" ends; section "1" still trickles, and ends on its own.
        state
            .signal_candidate(ConnectionId(1), &sent("", Some("0"), Some(0)))
            .unwrap();
        state
            .signal_candidate(ConnectionId(1), &sent(host, Some("1"), Some(1)))
            .unwrap();
        // RFC 8838 §13: nothing of section "0" follows its end, not even
        // a second end.
        for after in [sent(host, Some("0"), Some(0)), sent("", Some("0"), None)] {
            let refused = state.signal_candidate(ConnectionId(1), &after).unwrap_err();
            assert_eq!(refused.code, ErrorCode::InvalidRequest);
            assert_eq!(
                refused.message,
                "the media section's candidates already ended"
            );
            assert_eq!(refused.details["signal_id"], signal_id.as_str());
        }
        state
            .signal_candidate(ConnectionId(1), &sent("", Some("1"), Some(1)))
            .unwrap();
        // Without a mid the index names the section, and without either
        // the one unnamed section is meant: each ends on its own.
        state
            .signal_candidate(ConnectionId(1), &sent("", None, Some(1)))
            .unwrap();
        let refused = state
            .signal_candidate(ConnectionId(1), &sent(host, None, Some(1)))
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidRequest);
        state
            .signal_candidate(ConnectionId(1), &sent(host, None, None))
            .unwrap();
        assert_eq!(
            queues.take("c1"),
            [
                relayed("", Some("0"), Some(0)),
                relayed(host, Some("1"), Some(1)),
                relayed("", Some("1"), Some(1)),
                relayed("", None, Some(1)),
                relayed(host, None, None),
            ]
        );
    }

    #[test]
    fn a_client_ends_the_candidates_of_at_most_8_media_sections_of_a_signal() {
        let (mut state, mut queues, signal_id, _all) = offered();
        let sent = |candidate: &str, mid: usize| SignalingCandidate {
            id: 2,
            signal_id: signal_id.clone(),
            candidate: candidate.into(),
            sdp_mid: Some(mid.to_string()),
            sdp_mline_index: None,
        };
        for mid in 0..MAX_ENDED_SECTIONS {
            state
                .signal_candidate(ConnectionId(1), &sent("", mid))
                .unwrap();
        }
        assert_eq!(queues.take("c1").len(), MAX_ENDED_SECTIONS);
        let over = state
            .signal_candidate(ConnectionId(1), &sent("", MAX_ENDED_SECTIONS))
            .unwrap_err();
        assert_eq!(over.code, ErrorCode::LimitReached);
        assert_eq!(over.message, "too many media sections ended for the signal");
        assert_eq!(over.details["limit"], "signal_sections");
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        // A candidate of one more section is no end, and still goes.
        let host = "candidate:1 1 udp 1 198.51.100.1 9 typ host";
        state
            .signal_candidate(ConnectionId(1), &sent(host, MAX_ENDED_SECTIONS))
            .unwrap();
        assert_eq!(queues.take("c1").len(), 1);
    }

    /// What the registry tells a worker on its own (an open's answer, a
    /// signal's end) waits out a full driver queue, in order: a live
    /// source always learns its client went.
    #[test]
    fn what_the_registry_tells_a_worker_waits_out_a_full_driver_queue_in_order() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues) = signaled_state(1);
        let _all = subscribe(&mut state, owner(1, 1), None);
        open(&mut state, "c1", 1);
        open(&mut state, "c1", 2);
        assert_eq!(state.signaling.signals.len(), 2, "both opened");
        let held = |state: &State| {
            state
                .signaling
                .held
                .get("c1")
                .map_or(0, |held| held.commands.len())
        };
        assert_eq!(held(&state), 1);
        let first = opened(&mut queues, "c1", 1);
        offer(&mut state, "c1", &first);
        // With commands held, the client's wait for them: refused, for the
        // client to send again.
        let answer = SignalingAnswer {
            id: 2,
            signal_id: first.clone(),
            sdp: "v=0\r\n".into(),
        };
        let busy = state.signal_answer(ConnectionId(1), &answer).unwrap_err();
        assert_eq!(busy.code, ErrorCode::LimitReached);
        assert!(queues.take("c1").is_empty(), "the queue has room again");
        // The subscription ends: its signals' ends are held behind the
        // open's answer, though the queue has room.
        assert!(state.signaling_unsubscribed(ConnectionId(1), 1));
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        let taken: Vec<_> = state.take_held_signals("c1", true).into_iter().collect();
        let_assert!(
            [
                (
                    WORKER,
                    SignalCommand::Opened {
                        request: 2,
                        signal_id: second,
                        ..
                    }
                ),
                (
                    WORKER,
                    SignalCommand::Gone {
                        signal_id: gone_first
                    }
                ),
                (
                    WORKER,
                    SignalCommand::Gone {
                        signal_id: gone_second
                    }
                ),
            ] = taken.as_slice(),
            "{taken:?}"
        );
        let mut ids = [first, second.clone()];
        ids.sort();
        assert_eq!([gone_first, gone_second], [&ids[0], &ids[1]]);
        assert!(state.take_held_signals("c1", true).is_empty(), "taken once");
        let held_lines =
            captured.lines("the driver's queue is full; signal command held until it takes it");
        assert_eq!(held_lines.len(), 3, "{held_lines:?}");
        // Nothing held, the queue takes the next.
        open(&mut state, "c1", 3);
        assert_eq!(state.signaling.waiting.len(), 1);
        assert!(state.signal_wait_expired(&from("c1"), 3, later()));
        assert_eq!(queues.take("c1").len(), 1);
        assert_eq!(held(&state), 0);
    }

    /// A driver that takes none has at most [`MAX_HELD_SIGNALS`] commands
    /// held for it; the line of those dropped is rate-limited on the
    /// injected clock, as a worker's reports can repeat it. The worker's
    /// end forgets what was held, and a connection that is gone takes no
    /// command.
    #[test]
    fn at_most_256_commands_are_held_and_the_line_of_those_dropped_is_rate_limited() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, _queues) = signaled_state(1);
        let held = |state: &State| {
            state
                .signaling
                .held
                .get("c1")
                .map_or(0, |held| held.commands.len())
        };
        let fake = Arc::new(lotse_core::clock::FakeClock::default());
        state.signaling.clock = fake.clone();
        let gone = SignalCommand::Gone {
            signal_id: "s".into(),
        };
        // The queue's one, the held ones, and 9 dropped.
        for _ in 0..MAX_HELD_SIGNALS + 10 {
            state.tell_worker("c1", WORKER, gone.clone());
        }
        assert_eq!(held(&state), MAX_HELD_SIGNALS);
        let dropped_lines =
            || captured.lines("signal command dropped: its driver takes none of those held for it");
        let dropped = dropped_lines();
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert!(dropped[0].contains("limit=256"), "{dropped:?}");
        assert!(dropped[0].contains("count=1"), "{dropped:?}");
        fake.advance(lotse_core::throttle::SUMMARY_INTERVAL);
        state.tell_worker("c1", WORKER, gone);
        let dropped = dropped_lines();
        assert_eq!(dropped.len(), 2, "{dropped:?}");
        assert!(dropped[1].contains("count=9"), "{dropped:?}");
        // The worker's end forgets what was held for it.
        state.signals_ended("c1", SignalCloseCode::WorkerGone, "exited");
        assert_eq!(held(&state), 0);
        // A connection that is gone takes no command.
        state.tell_worker(
            "gone",
            WORKER,
            SignalCommand::Gone {
                signal_id: "s".into(),
            },
        );
        assert!(!state.signaling.held.contains_key("gone"));
        assert_eq!(
            captured
                .lines("signal command for a connection that is gone; dropped")
                .len(),
            1
        );
    }

    /// A worker that opens signals in a loop holds at most
    /// [`MAX_OPEN_SIGNALS`], waiting opens counted: the rest are refused, with
    /// a rate-limited line.
    #[test]
    fn a_connection_holds_at_most_4_signals_and_waiting_opens() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues) = signaled_state(64);
        let refusal = |request| SignalCommand::Refused {
            request,
            code: "limit_reached".into(),
            message: "a source connection may hold 4 signals and waiting opens".into(),
        };
        // Waiting opens count.
        for request in 1..=4 {
            open(&mut state, "c1", request);
        }
        // The refusals' lines within one summary interval.
        let at = later();
        let refuse = |state: &mut State, connection, request| {
            report_at(state, connection, SignalReport::Open { request }, at);
        };
        refuse(&mut state, "c1", 5);
        assert_eq!(queues.take("c1"), [refusal(5)]);
        assert_eq!(state.signaling.waiting.len(), 4);
        // So do signals: a worker that opens and offers in a loop gets
        // no fifth.
        let mut all = subscribe(&mut state, owner(1, 1), None);
        let signals: Vec<String> = queues
            .take("c1")
            .into_iter()
            .map(|command| {
                let_assert!(SignalCommand::Opened { signal_id, .. } = command);
                signal_id
            })
            .collect();
        assert_eq!(signals.len(), 4);
        for signal_id in &signals {
            offer(&mut state, "c1", signal_id);
        }
        for request in 6..26 {
            refuse(&mut state, "c1", request);
            assert_eq!(queues.take("c1").last(), Some(&refusal(request)));
        }
        assert_eq!(state.signaling.signals.len(), 4);
        assert_eq!(events(&mut all).len(), 4, "one offer per signal");
        let lines = captured
            .lines("signaling open refused: the connection holds as many signals as it may");
        assert_eq!(lines.len(), 1, "rate-limited: {lines:?}");
        assert!(lines[0].contains("limit=4"), "{lines:?}");
        // Another connection's are its own, and so is its line's rate
        // limit; one that ends frees a place.
        for request in 1..=4 {
            open(&mut state, "c2", request);
        }
        let _yard = queues.take("c2");
        refuse(&mut state, "c2", 5);
        let lines = captured
            .lines("signaling open refused: the connection holds as many signals as it may");
        assert_eq!(lines.len(), 2, "one per connection: {lines:?}");
        assert!(lines[1].contains("connection.id=\"c2\""), "{lines:?}");
        report(&mut state, "c1", closed(&signals[0], "peer_closed"));
        open(&mut state, "c1", 26);
        let _fifth = opened(&mut queues, "c1", 26);
        assert_eq!(MAX_OPEN_SIGNALS, 4);
        // A worker's end keeps its connection's rate limit; the
        // connection's release forgets it.
        state.signals_ended("c1", SignalCloseCode::WorkerGone, "exited");
        let has_lines = |state: &State| state.signaling.lines.keys().any(|(of, _)| of == "c1");
        assert!(has_lines(&state));
        let _gone = state.connections.remove("c1");
        state.signals_ended("c1", SignalCloseCode::SourceStopped, "released");
        assert!(!has_lines(&state));
    }

    /// Every line a worker's opens, cancels and reports repeat is
    /// rate-limited per connection on the injected clock: a worker that
    /// opens, offers, closes, cancels and breaks the contract in a loop
    /// logs each once per summary interval, with the count.
    #[test]
    fn a_worker_s_repeated_lines_are_rate_limited_per_connection() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues) = signaled_state(64);
        let at = later();
        // Opens that wait, then are cancelled or refused at their wait's
        // end.
        for request in 1..=4 {
            report_at(&mut state, "c1", SignalReport::Open { request }, at);
        }
        report_at(&mut state, "c1", SignalReport::Cancel { request: 1 }, at);
        report_at(&mut state, "c1", SignalReport::Cancel { request: 2 }, at);
        assert!(state.signal_wait_expired(&from("c1"), 3, at));
        assert!(state.signal_wait_expired(&from("c1"), 4, at));
        assert_eq!(queues.take("c1").len(), 2);
        let _all = state.signaling_subscribe(owner(1, 1), None, (at, UNIX_EPOCH));
        // Signals opened, offered twice (a breach) or closed.
        for request in 5..=8 {
            report_at(&mut state, "c1", SignalReport::Open { request }, at);
            let signal_id = opened(&mut queues, "c1", request);
            let offer = SignalReport::Offer {
                signal_id: signal_id.clone(),
                sdp: "v=0\r\n".into(),
            };
            report_at(&mut state, "c1", offer.clone(), at);
            if request < 7 {
                report_at(&mut state, "c1", closed(&signal_id, "peer_closed"), at);
            } else {
                report_at(&mut state, "c1", offer, at);
                let _failed = queues.take("c1");
            }
        }
        for message in [
            "no signaling subscription takes the stream; the open waits for one",
            "signaling open cancelled while it waited for a client",
            "signal opened; it belongs to the subscription that takes its stream",
            "signaling offer relayed to the subscription",
            "a worker's signaling breaks the contract; signal ended",
        ] {
            let lines = captured.lines(message);
            assert_eq!(lines.len(), 1, "{message}: {lines:?}");
            assert!(lines[0].contains("count=1"), "{lines:?}");
        }
        for message in [
            "no client subscribed to the stream's signaling in time",
            "signal closed by its source",
        ] {
            assert_eq!(captured.lines(message).len(), 1, "{message}");
        }
        // A summary interval later, each says how many it covers.
        let at = at + lotse_core::throttle::SUMMARY_INTERVAL;
        report_at(&mut state, "c1", SignalReport::Open { request: 9 }, at);
        let lines = captured.lines("signal opened; it belongs to the subscription");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains("count=4"), "{lines:?}");
        // Another connection's lines are its own.
        report_at(&mut state, "c2", SignalReport::Open { request: 1 }, at);
        let _yard = opened(&mut queues, "c2", 1);
        assert_eq!(
            captured
                .lines("signal opened; it belongs to the subscription")
                .len(),
            3
        );
    }

    /// What the registry holds for a worker goes once the driver has
    /// handled what its queue held before it, and one more it may have had
    /// in hand, though the queue never empties; or at once once the queue
    /// is empty.
    #[test]
    fn held_commands_go_once_the_driver_handled_what_its_queue_held_before_them() {
        let (mut state, mut queues) = signaled_state(2);
        let gone = |n: u32| SignalCommand::Gone {
            signal_id: format!("s{n}"),
        };
        // Nothing held: nothing to take, and nothing counted.
        assert!(state.take_held_signals("c1", false).is_empty());
        for n in 0..3 {
            state.tell_worker("c1", WORKER, gone(n));
        }
        for handled in 1..=2 {
            assert!(
                state.take_held_signals("c1", false).is_empty(),
                "after {handled}"
            );
        }
        assert_eq!(
            Vec::from(state.take_held_signals("c1", false)),
            [(WORKER, gone(2))]
        );
        assert!(
            state.take_held_signals("c1", false).is_empty(),
            "taken once"
        );
        assert_eq!(queues.take("c1"), [gone(0), gone(1)]);
        // The queue empty, they go at once.
        for n in 3..6 {
            state.tell_worker("c1", WORKER, gone(n));
        }
        assert_eq!(
            Vec::from(state.take_held_signals("c1", true)),
            [(WORKER, gone(5))]
        );
        // Only the connection's own.
        state.tell_worker("c1", WORKER, gone(6));
        assert!(state.take_held_signals("c2", true).is_empty());
        assert_eq!(state.signaling.held["c1"].commands.len(), 1);
    }

    /// An open waiting for a subscription is offered again when a stream
    /// joins its connection: one with its own subscription takes it.
    /// Another connection's change leaves it waiting.
    #[test]
    fn a_waiting_open_is_offered_again_when_a_stream_with_a_subscription_joins_its_connection() {
        let (mut state, mut queues) = signaled_state(8);
        let mut porch = subscribe(&mut state, owner(1, 1), Some("porch"));
        open(&mut state, "c1", 1);
        open(&mut state, "c2", 1);
        assert_eq!(state.signaling.waiting.len(), 2);
        let _joined = state
            .connections
            .get_mut("c1")
            .unwrap()
            .streams
            .insert("porch".into());
        state.route_waiting_opens("c2", (later(), UNIX_EPOCH));
        assert_eq!(state.signaling.waiting.len(), 2);
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        state.route_waiting_opens("c1", (later(), UNIX_EPOCH));
        let signal_id = opened(&mut queues, "c1", 1);
        offer(&mut state, "c1", &signal_id);
        assert_eq!(events(&mut porch)[0]["stream_id"], "porch");
        let_assert!([WaitingOpen { connection, .. }] = state.signaling.waiting.as_slice());
        assert_eq!(connection, "c2");
    }

    /// A stream on connection `connection`, as the registry keeps it.
    fn stream_on(connection: &str) -> crate::registry::StreamEntry {
        crate::registry::StreamEntry {
            sources: vec![crate::registry::StreamSource {
                spec: crate::driver::DriverSpec {
                    connection_id: connection.into(),
                    target: lotse_ipc::SourceTarget::Signaled("webrtc".into()),
                    options: "{}".into(),
                    host: String::new(),
                    port: None,
                    backchannel: false,
                },
                target: SourceTarget::Signaled {
                    protocol: "webrtc",
                    stream: "door".into(),
                },
                options: serde_json::Map::new(),
                protocol: "webrtc",
                connection: connection.into(),
            }],
            preload: false,
            audio: lotse_api_types::stream::AudioMode::Auto,
            orientation: lotse_api_types::stream::Orientation::NoTransform,
            created: UNIX_EPOCH,
            prerecord_ms: 0,
            recordings: crate::recording::RecordingCounters::default(),
        }
    }

    /// A signal whose stream leaves a connection that serves others ends:
    /// its worker is told the client is gone, so its source connects
    /// again, and its subscription that it closed `source_stopped`; the
    /// other stream's stays open.
    #[test]
    fn a_signal_whose_stream_leaves_its_shared_connection_ends_source_stopped() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues) = signaled_state(8);
        let _joined = state
            .connections
            .get_mut("c1")
            .unwrap()
            .streams
            .insert("porch".into());
        for stream in ["door", "porch"] {
            state.streams.insert(stream.into(), stream_on("c1"));
        }
        let mut porch = subscribe(&mut state, owner(1, 1), Some("porch"));
        open(&mut state, "c1", 1);
        let at_porch = opened(&mut queues, "c1", 1);
        offer(&mut state, "c1", &at_porch);
        let mut door = subscribe(&mut state, owner(2, 1), Some("door"));
        open(&mut state, "c1", 2);
        let at_door = opened(&mut queues, "c1", 2);
        offer(&mut state, "c1", &at_door);
        let _offers = (events(&mut porch), events(&mut door));
        // Nothing left: nothing ends.
        state.refresh_connection("c1");
        assert_eq!(state.signaling.signals.len(), 2);
        assert_eq!(queues.take("c1"), Vec::<SignalCommand>::new());
        let _deleted = state.streams.remove("porch");
        state.refresh_connection("c1");
        assert_eq!(
            queues.take("c1"),
            [SignalCommand::Gone {
                signal_id: at_porch.clone()
            }]
        );
        assert_eq!(
            events(&mut porch),
            [
                json!({ "type": "closed", "signal_id": at_porch, "code": "source_stopped",
                     "message": "the signal's stream no longer reads from its source" })
            ]
        );
        assert_eq!(events(&mut door), Vec::<Value>::new());
        assert_eq!(state.signal_ids_for_tests(), [at_door]);
        assert_eq!(
            captured
                .lines("signal ended: its stream no longer reads from its connection")
                .len(),
            1
        );
        // A connection that is gone has none to end.
        state.signals_left_streams("gone");
        assert_eq!(state.signaling.signals.len(), 1);
    }

    /// At the shutdown every offered signal closes `source_stopped`, every
    /// signaling subscription ends, and nothing waits or is held.
    #[test]
    fn the_shutdown_closes_the_signals_and_ends_the_subscriptions() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (mut state, mut queues) = signaled_state(8);
        let mut door = subscribe(&mut state, owner(1, 1), Some("door"));
        open(&mut state, "c1", 1);
        let offered = opened(&mut queues, "c1", 1);
        offer(&mut state, "c1", &offered);
        let _offer = events(&mut door);
        open(&mut state, "c1", 2);
        let _quiet = opened(&mut queues, "c1", 2);
        // An open of `yard`, which no subscription takes, waits, and
        // commands are held for its full queue.
        open(&mut state, "c2", 1);
        for _ in 0..9 {
            state.tell_worker(
                "c2",
                WORKER,
                SignalCommand::Gone {
                    signal_id: "s".into(),
                },
            );
        }
        assert_eq!(state.signaling.waiting.len(), 1);
        assert_eq!(state.signaling.held.len(), 1);
        state.signaling_shutdown();
        // Only the offered signal's client knows it, and is told.
        assert_eq!(
            events(&mut door),
            [
                json!({ "type": "closed", "signal_id": offered, "code": "source_stopped",
                     "message": "the daemon is shutting down" })
            ]
        );
        assert!(door.is_closed(), "the subscription ended");
        assert_eq!(state.signal_ids_for_tests(), Vec::<String>::new());
        assert!(state.signaling.scopes.is_empty());
        assert_eq!(state.signaling.waiting, Vec::<WaitingOpen>::new());
        assert!(state.signaling.held.is_empty());
        let lines = captured.lines("signaling ends: the daemon is shutting down");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("signals=2 subscriptions=1"), "{lines:?}");
    }

    /// A connection several streams share offers to the subscription of
    /// the first of them that has its own, else to the one for every
    /// stream, under the first stream's id.
    #[test]
    fn a_shared_connection_offers_to_any_of_its_streams_subscriptions() {
        let (mut state, mut queues) = signaled_state(8);
        let _yard = state
            .connections
            .get_mut("c1")
            .unwrap()
            .streams
            .insert("porch".into());
        let mut all = subscribe(&mut state, owner(1, 1), None);
        let mut porch = subscribe(&mut state, owner(2, 1), Some("porch"));
        open(&mut state, "c1", 1);
        let signal_id = opened(&mut queues, "c1", 1);
        offer(&mut state, "c1", &signal_id);
        let got = events(&mut porch);
        assert_eq!(got[0]["stream_id"], "porch", "{got:?}");
        assert_eq!(events(&mut all), Vec::<Value>::new());
        // `door`, the first, wins once it has its own.
        let mut door = subscribe(&mut state, owner(3, 1), Some("door"));
        open(&mut state, "c1", 2);
        let signal_id = opened(&mut queues, "c1", 2);
        offer(&mut state, "c1", &signal_id);
        assert_eq!(events(&mut door)[0]["stream_id"], "door");
        // Without either, the one for every stream takes it for `door`.
        assert!(state.signaling_unsubscribed(ConnectionId(2), 1));
        assert!(state.signaling_unsubscribed(ConnectionId(3), 1));
        let _gone = queues.take("c1");
        open(&mut state, "c1", 3);
        let signal_id = opened(&mut queues, "c1", 3);
        offer(&mut state, "c1", &signal_id);
        assert_eq!(events(&mut all)[0]["stream_id"], "door");
    }

    #[test]
    fn a_subscription_whose_queue_is_over_ends_with_its_signals() {
        let captured = Captured::default();
        let _logs = captured.install();
        // Without room, the overflow marker ends the queue.
        let (events, mut rx) = mpsc::channel(2);
        assert!(emit(&events, &SignalingEvent::Superseded {}));
        assert!(!emit(&events, &SignalingEvent::Superseded {}));
        assert_eq!(rx.try_recv().unwrap().class, EventClass::Signaling);
        assert_eq!(rx.try_recv().unwrap().class, EventClass::Overflowed);
        assert_eq!(
            captured
                .lines("signaling subscription queue full for an event that is never dropped")
                .len(),
            1
        );
        drop(rx);
        assert!(!emit(&events, &SignalingEvent::Superseded {}), "closed");
        // A subscription whose receiver is gone takes no open; one that
        // goes once its signal opened ends it at its offer.
        let (mut state, mut queues) = signaled_state(8);
        drop(subscribe(&mut state, owner(1, 1), None));
        open(&mut state, "c1", 1);
        assert_eq!(state.signaling.waiting.len(), 1);
        let all = subscribe(&mut state, owner(1, 2), None);
        let signal_id = opened(&mut queues, "c1", 1);
        drop(all);
        offer(&mut state, "c1", &signal_id);
        assert_eq!(queues.take("c1"), [SignalCommand::Gone { signal_id }]);
        assert!(state.signaling.scopes.is_empty());
        // Or at its close.
        let (mut state, mut queues, signal_id, all) = offered();
        drop(all);
        report(&mut state, "c1", closed(&signal_id, "peer_closed"));
        assert!(state.signaling.scopes.is_empty());
        assert!(queues.take("c1").is_empty(), "the signal had closed");
    }

    #[test]
    fn every_close_code_a_source_uses_is_the_api_s() {
        use lotse_core::signaling::close;

        for code in [
            close::SOURCE_STOPPED,
            close::ANSWER_TIMEOUT,
            close::INVALID_ANSWER,
            close::ICE_FAILED,
            close::CONSENT_LOST,
            close::PEER_CLOSED,
            close::CAMERA_ERROR,
            close::SIGNALING_LOST,
            close::INTERNAL_ERROR,
        ] {
            assert_eq!(close_code(code).as_str(), code);
        }
        assert_eq!(close_code("x"), SignalCloseCode::InternalError);
    }
}
