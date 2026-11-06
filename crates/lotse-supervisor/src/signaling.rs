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
//! What the registry tells a worker on its own (an open's answer, the end
//! of a signal) is never lost to a full driver queue: it waits in the
//! registry, ahead of anything later for that worker, until the driver
//! has handled its queue and takes it ([`State::take_held_signals`]).
//! Only a client's command is refused on a busy driver (`limit_reached`),
//! for the client to send again.
//!
//! The worker is untrusted. A source connection holds at most
//! [`MAX_OPEN_SIGNALS`] signals and waiting opens at once, an open past
//! them refused `limit_reached`, so a worker cannot grow the registry's
//! signals (one that ends its signals and opens new ones in a loop still
//! offers once per signal, as a source that keeps failing does). Per
//! signal an offer is taken once, at most
//! [`MAX_WORKER_CANDIDATES`] candidates after it and none after its
//! end-of-candidates (RFC 8838 §13); a report past that ends the signal
//! (`internal_error` to the client, [`REJECTED`] to the worker), so a
//! signal cannot flood the client, whose signaling events are never shed:
//! a subscription without room for one ends, and the server disconnects
//! its client. The client's own commands are bounded too: one answer, at
//! most [`MAX_CLIENT_CANDIDATES`] candidates and one end-of-candidates,
//! and one error per signal, after which it takes no answer or candidate.
//!
//! Standards: RFC 8829 (JSEP) and RFC 8838 (Trickle ICE), the exchange
//! the signals carry, as `lotse_core::signaling` cites them; ULID for the
//! signal ids.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use lotse_api::{ConnectionId, Event, EventClass};
use lotse_api_types::command::{SignalingAnswer, SignalingCandidate, SignalingError};
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::signaling::{SignalCloseCode, SignalingEvent};
use lotse_core::signaling::REJECTED;
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
    /// The subscription it belongs to.
    owner: Owner,
    /// Where its events go: its subscription's queue.
    events: mpsc::Sender<Event>,
    /// What its worker sent so far.
    worker_sent: WorkerSent,
    /// What its client sent so far.
    client_sent: ClientSent,
}

/// What a signal's worker sent so far.
#[derive(Debug, Default)]
struct WorkerSent {
    /// Its offer, which went to the client: the client knows the signal.
    offer: bool,
    /// Its candidates, at most [`MAX_WORKER_CANDIDATES`].
    candidates: u32,
    /// Its end-of-candidates: no candidate follows.
    end: bool,
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
    /// Its end-of-candidates: no candidate follows.
    end: bool,
}

/// The signaling the registry routes: the subscriptions, the opens
/// waiting for one, and the open signals.
#[derive(Debug, Default)]
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
    /// queue did not take, oldest first, each with the worker's serial:
    /// they go before any later command for it, when the driver takes
    /// them ([`State::take_held_signals`]).
    held: BTreeMap<String, VecDeque<(u64, SignalCommand)>>,
    /// The signals opened so far, for an id when the ULID's randomness is
    /// unavailable.
    opened: u64,
    /// Rate-limits the line of an open refused past [`MAX_OPEN_SIGNALS`],
    /// which a worker can repeat as fast as its driver answers it.
    limit_lines: Throttle,
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
                } else {
                    tracing::info!(
                        connection.id = connection,
                        request,
                        "signaling open cancelled while it waited for a client"
                    );
                }
            }
            SignalReport::Offer { signal_id, sdp } => {
                let Some(mut signal) = self.take_signal(connection, &signal_id) else {
                    return;
                };
                if signal.worker_sent.offer {
                    self.worker_broke(&signal_id, &signal, "a second offer");
                    return;
                }
                signal.worker_sent.offer = true;
                let event = SignalingEvent::Offer {
                    signal_id: signal_id.clone(),
                    stream_id: signal.stream_id.clone(),
                    source: self
                        .connections
                        .get(connection)
                        .map(|entry| entry.key.url.redacted().to_string())
                        .unwrap_or_default(),
                    sdp,
                };
                tracing::info!(
                    signal.id = %signal_id,
                    connection.id = connection,
                    stream.id = %signal.stream_id,
                    "signaling offer relayed to the subscription"
                );
                self.deliver(signal_id, signal, &event);
            }
            SignalReport::Candidate {
                signal_id,
                candidate,
                mid,
                mline_index,
            } => self.worker_candidate(connection, signal_id, candidate, mid, mline_index),
            SignalReport::Closed {
                signal_id,
                code,
                message,
            } => {
                let Some(signal) = self.take_signal(connection, &signal_id) else {
                    return;
                };
                let code = close_code(&code);
                tracing::info!(
                    signal.id = %signal_id,
                    connection.id = connection,
                    code = code.as_str(),
                    message = %message,
                    "signal closed by its source"
                );
                self.close_signal(signal_id, &signal, code, message);
            }
        }
    }

    /// A candidate line (or, empty, the end-of-candidates indication) of
    /// the worker of `connection` for its signal `signal_id`, with its
    /// media section's `mid` and index: relayed within the signal's
    /// budget, else the signal ends.
    fn worker_candidate(
        &mut self,
        connection: &str,
        signal_id: String,
        candidate: String,
        mid: Option<String>,
        mline_index: Option<u16>,
    ) {
        let Some(mut signal) = self.take_signal(connection, &signal_id) else {
            return;
        };
        let broken = if !signal.worker_sent.offer {
            Some("a candidate before the offer")
        } else if signal.worker_sent.end {
            // RFC 8838 §13: no candidate follows end-of-candidates.
            Some("a candidate after its end-of-candidates")
        } else if !candidate.is_empty() && signal.worker_sent.candidates >= MAX_WORKER_CANDIDATES {
            Some("more candidates than a signal allows")
        } else {
            None
        };
        if let Some(reason) = broken {
            self.worker_broke(&signal_id, &signal, reason);
            return;
        }
        if candidate.is_empty() {
            signal.worker_sent.end = true;
        } else {
            signal.worker_sent.candidates = signal.worker_sent.candidates.saturating_add(1);
        }
        tracing::debug!(
            signal.id = %signal_id,
            end = candidate.is_empty(),
            "signaling candidate relayed to the subscription"
        );
        let event = SignalingEvent::Candidate {
            signal_id: signal_id.clone(),
            candidate,
            sdp_mid: mid,
            // The first media section when the source named none: its
            // BUNDLE carries every candidate.
            sdp_mline_index: mline_index.unwrap_or(0),
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
    /// contract for `reason`: the worker is told the relay rejected it
    /// ([`REJECTED`]: its source's fault, not the camera's), the client
    /// that it closed `internal_error`.
    fn worker_broke(&mut self, signal_id: &str, signal: &Signal, reason: &'static str) {
        tracing::warn!(
            signal.id = signal_id,
            connection.id = %signal.connection,
            reason,
            "a worker's signaling breaks the contract; signal ended"
        );
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
            if let Some(count) = self.signaling.limit_lines.hit(now) {
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
        if !self.open_signal(&open, wall) {
            tracing::info!(
                connection.id = connection,
                request,
                wait_ms = crate::millis(SIGNAL_WAIT),
                "no signaling subscription takes the stream; the open waits for one"
            );
            self.signaling.waiting.push(open);
        }
    }

    /// Opens a signal for `open` on the subscription that takes one of
    /// its connection's streams, if one does, named at `wall`. True when
    /// one does: the worker is told.
    fn open_signal(&mut self, open: &WaitingOpen, wall: SystemTime) -> bool {
        let Some((stream_id, subscriber)) = self
            .connections
            .get(&open.connection)
            .and_then(|entry| self.signaling.subscriber_for(&entry.streams))
        else {
            return false;
        };
        let (owner, events) = (subscriber.owner, subscriber.events.clone());
        self.signaling.opened = self.signaling.opened.wrapping_add(1);
        let opened = self.signaling.opened;
        // Linux's getrandom does not fail once the kernel's pool is ready;
        // the count stands in, unique within the process.
        let signal_id = ulid(wall).unwrap_or_else(|_| format!("{opened:026}"));
        self.tell_worker(
            &open.connection,
            open.worker,
            SignalCommand::Opened {
                request: open.request,
                signal_id: signal_id.clone(),
                local_addrs: self.signaling.local_addrs.clone(),
            },
        );
        tracing::info!(
            signal.id = %signal_id,
            connection.id = %open.connection,
            stream.id = %stream_id,
            request = open.request,
            control.connection = owner.connection.0,
            subscription = owner.subscription,
            "signal opened; it belongs to the subscription that takes its stream"
        );
        self.signaling.signals.insert(
            signal_id,
            Signal {
                connection: open.connection.clone(),
                worker: open.worker,
                stream_id,
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
    /// or cancelled), so the driver need not wait for its answer.
    pub(crate) fn signal_wait_expired(&mut self, from: &SignalFrom<'_>, request: u64) -> bool {
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
        tracing::info!(
            connection.id = from.connection,
            request,
            "signaling channel refused: no client subscribed to the stream's signaling in time"
        );
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
    /// `superseded` and ends, and serves the opens waiting for it. `now`
    /// on the wall clock names their signals.
    pub(crate) fn signaling_subscribe(
        &mut self,
        owner: Owner,
        stream_id: Option<String>,
        now: SystemTime,
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
        let waiting = std::mem::take(&mut self.signaling.waiting);
        for open in waiting {
            if self.open_signal(&open, now) {
                continue;
            }
            self.signaling.waiting.push(open);
        }
        rx
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
    /// at most [`MAX_CLIENT_CANDIDATES`] per signal, or its
    /// end-of-candidates, once, after which no candidate follows (RFC 8838
    /// §13), to its worker.
    pub(crate) fn signal_candidate(
        &mut self,
        connection: ConnectionId,
        candidate: &SignalingCandidate,
    ) -> Result<(), ApiError> {
        let signal = self.owned_signal(connection, &candidate.signal_id)?;
        let end = candidate.candidate.is_empty();
        if signal.client_sent.end {
            return Err(signal_refused(
                &candidate.signal_id,
                "the signal's candidates already ended",
            ));
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
            if end {
                signal.client_sent.end = true;
            } else {
                signal.client_sent.candidates = signal.client_sent.candidates.saturating_add(1);
            }
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
    /// registry decided on its own and so must not be lost: through its
    /// driver's queue, or, while that is full or other commands are held
    /// before it, held until the driver takes it
    /// ([`State::take_held_signals`]). One for a connection that is gone,
    /// or past [`MAX_HELD_SIGNALS`], is dropped.
    fn tell_worker(&mut self, connection: &str, worker: u64, command: SignalCommand) {
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
        let held = self
            .signaling
            .held
            .entry(connection.to_owned())
            .or_default();
        if held.len() >= MAX_HELD_SIGNALS {
            tracing::error!(
                connection.id = connection,
                ?command,
                limit = MAX_HELD_SIGNALS,
                "signal command dropped: its driver takes none of those held for it"
            );
            return;
        }
        tracing::debug!(
            connection.id = connection,
            ?command,
            "the driver's queue is full; signal command held until it takes it"
        );
        held.push_back((worker, command));
    }

    /// The commands held for the worker of `connection` while its driver's
    /// queue was full, oldest first, each with the worker's serial; the
    /// driver takes them once its queue is empty, so they go after
    /// everything queued before them and before anything queued after.
    pub(crate) fn take_held_signals(&mut self, connection: &str) -> VecDeque<(u64, SignalCommand)> {
        self.signaling.held.remove(connection).unwrap_or_default()
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

    use lotse_core::clock::{Clock as _, SystemClock};
    use lotse_core::let_assert;
    use lotse_core::source_url::SourceUrl;
    use serde_json::{Value, json};
    use tokio::sync::watch;

    use super::*;
    use crate::registry::{ConnectionEntry, ConnectionKey, ConnectionSnapshot, Talker};
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

    /// `report` of worker [`WORKER`] of `connection`, now.
    fn report(state: &mut State, connection: &str, report: SignalReport) {
        state.signal_report(&from(connection), report, SystemClock.now(), UNIX_EPOCH);
    }

    /// A state with the signaled connections `c1` of stream `door` (its
    /// URL with credentials) and `c2` of stream `yard`, whose drivers'
    /// queues hold `capacity` commands, and two local addresses.
    fn signaled_state(capacity: usize) -> (State, Queues) {
        let mut state = State::default();
        state.signaling.local_addrs = vec![[192, 0, 2, 7].into(), [0_u16; 8].into()];
        let mut drivers = BTreeMap::new();
        for (id, stream, url) in [
            ("c1", "door", "webrtc://user:secret@camera.front_door/"),
            ("c2", "yard", "webrtc://camera.yard"),
        ] {
            let (commands, queued) = mpsc::channel(capacity);
            state.connections.insert(
                id.into(),
                ConnectionEntry {
                    key: ConnectionKey {
                        url: SourceUrl::parse(url).unwrap(),
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
        state.signaling_subscribe(owner, stream_id.map(str::to_owned), UNIX_EPOCH)
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
                // The source redacted as `stream/get` shows it.
                json!({ "type": "offer", "signal_id": signal_id, "stream_id": "door",
                        "source": "webrtc://****@camera.front_door/", "sdp": "v=0\r\n" }),
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
        // A signal closed before its offer is closed quietly.
        open(&mut state, "c1", 6);
        let signal_id = opened(&mut queues, "c1", 6);
        report(&mut state, "c1", closed(&signal_id, "source_stopped"));
        assert!(events(&mut all).is_empty());
        assert_eq!(captured.lines("signal closed by its source").len(), 3);
        assert_eq!(
            captured
                .lines("signal opened; it belongs to the subscription that takes its stream")
                .len(),
            3
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
        assert!(events(&mut all).is_empty());
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
        // A candidate after end-of-candidates.
        let (mut state, mut queues, signal_id, mut all) = offered();
        report(&mut state, "c1", candidate(&signal_id, "", Some(0)));
        report(&mut state, "c1", candidate(&signal_id, "", Some(0)));
        let reason = "a candidate after its end-of-candidates";
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
        assert!(queues.take("c1").is_empty());
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
        assert!(events(&mut all).is_empty());
        assert_eq!(
            captured
                .lines("a worker's signaling breaks the contract; signal ended")
                .len(),
            4
        );
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
        assert!(queues.take("c1").is_empty());
        assert_eq!(
            captured
                .lines("no signaling subscription takes the stream; the open waits for one")
                .len(),
            2
        );
        assert!(state.signal_wait_expired(&from("c1"), 1));
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
        assert!(!state.signal_wait_expired(&from("c1"), 1));
        assert!(!state.signal_wait_expired(&earlier, 2));
        assert!(!state.signal_wait_expired(&from("c2"), 2));
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
        assert!(queues.take("c1").is_empty());
        // The open of a connection that is gone is dropped.
        open(&mut state, "gone", 3);
        assert!(state.signaling.waiting.is_empty());
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
        assert!(queues.take("c1").is_empty());
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
        assert!(state.signaling.waiting.is_empty());
        offer(&mut state, "c2", &yard_signal);
        offer(&mut state, "c1", first);
        assert_eq!(events(&mut yard)[0]["signal_id"], yard_signal.as_str());
        assert_eq!(events(&mut all)[0]["signal_id"], first.as_str());
        // Waiting opens of a connection that went are forgotten with it.
        open(&mut state, "c2", 2);
        let _gone = state.connections.remove("c2");
        state.signals_ended("c2", SignalCloseCode::SourceStopped, "gone");
        assert!(state.signaling.waiting.is_empty());
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
        assert!(events(&mut later).is_empty());
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
        assert!(queues.take("c1").is_empty());
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
        assert!(queues.take("c1").is_empty());
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
        assert!(queues.take("c1").is_empty());
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
        assert!(queues.take("c1").is_empty());
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
            assert_eq!(refused.message, "the signal's candidates already ended");
        }
        assert!(queues.take("c1").is_empty());
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
        let held = |state: &State| state.signaling.held.get("c1").map_or(0, VecDeque::len);
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
        assert!(queues.take("c1").is_empty());
        let taken: Vec<_> = state.take_held_signals("c1").into_iter().collect();
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
        assert!(state.take_held_signals("c1").is_empty(), "taken once");
        let held_lines =
            captured.lines("the driver's queue is full; signal command held until it takes it");
        assert_eq!(held_lines.len(), 3, "{held_lines:?}");
        // Nothing held, the queue takes the next.
        open(&mut state, "c1", 3);
        assert_eq!(state.signaling.waiting.len(), 1);
        assert!(state.signal_wait_expired(&from("c1"), 3));
        assert_eq!(queues.take("c1").len(), 1);
        assert_eq!(held(&state), 0);
        // A driver that takes none holds at most MAX_HELD_SIGNALS.
        for _ in 0..=MAX_HELD_SIGNALS + 1 {
            state.tell_worker(
                "c1",
                WORKER,
                SignalCommand::Gone {
                    signal_id: "s".into(),
                },
            );
        }
        assert_eq!(held(&state), MAX_HELD_SIGNALS);
        let dropped =
            captured.lines("signal command dropped: its driver takes none of those held for it");
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert!(dropped[0].contains("limit=256"), "{dropped:?}");
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
        open(&mut state, "c1", 5);
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
            open(&mut state, "c1", request);
            assert_eq!(queues.take("c1").last(), Some(&refusal(request)));
        }
        assert_eq!(state.signaling.signals.len(), 4);
        assert_eq!(events(&mut all).len(), 4, "one offer per signal");
        let lines = captured
            .lines("signaling open refused: the connection holds as many signals as it may");
        assert_eq!(lines.len(), 1, "rate-limited: {lines:?}");
        assert!(lines[0].contains("limit=4"), "{lines:?}");
        // Another connection's are its own; one that ends frees a place.
        open(&mut state, "c2", 1);
        let _yard = opened(&mut queues, "c2", 1);
        report(&mut state, "c1", closed(&signals[0], "peer_closed"));
        open(&mut state, "c1", 26);
        let _fifth = opened(&mut queues, "c1", 26);
        assert_eq!(MAX_OPEN_SIGNALS, 4);
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
        assert!(events(&mut all).is_empty());
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
        ] {
            assert_eq!(close_code(code).as_str(), code);
        }
        assert_eq!(close_code("x"), SignalCloseCode::InternalError);
    }
}
