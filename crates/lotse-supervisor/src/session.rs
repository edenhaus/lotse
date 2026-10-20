//! Viewer sessions as the supervisor keeps them: which stream and source
//! connection each belongs to, which control connection owns its
//! subscription, the events buffered while it is orphaned, and the mapping
//! of a worker's session reports onto the API's events.
//!
//! The worker runs the session; the supervisor owns its signaling. A
//! worker's report is untrusted: it is accepted only for a session of that
//! worker's own connection, and every code and state name is mapped onto a
//! known one. Media never passes here.
//!
//! Its reports are also budgeted, so a worker cannot fill the owning
//! control connection's outbound queue, whose signaling is never shed, and
//! have the client disconnected: one answer, at most
//! [`MAX_WORKER_CANDIDATES`] candidate lines and none after its
//! end-of-candidates (RFC 8838 §13), one warning per code, one answer
//! per re-offer handed to the worker (`webrtc/renegotiate`, answered
//! through the entry's [`SessionEntry::renegotiate`]), and one
//! `backchannel_declined` per offer or re-offer answered; the client
//! asked for each of these last three, so they are bounded by its
//! requests and not charged. Messages are cut to
//! [`MAX_MESSAGE_BYTES`], ending in [`CUT_MARK`](lotse_core::text::CUT_MARK)
//! where they were, and the rest of the worker's text, the
//! candidates and warnings, to [`MAX_REPORT_TEXT_BYTES`] over the
//! session's life. A report over the budget closes
//! the session; a repeated warning is dropped. A state goes on only when
//! it changed, and the outbox keeps the latest one per session, so a
//! worker repeating or flipping its state adds at most one frame to the
//! queue.
//!
//! A session holds a lease on the TURN allocation behind each of its relay
//! candidates, and the channels its worker asked for on them, at most
//! [`MAX_RELAY_CHANNELS`] (RFC 8656 §12); dropping the session releases
//! them.
//!
//! What a worker reports is logged within bounds too: a dropped warning
//! and a refused channel once per session, each (ICE, DTLS) state pair
//! and the events a full subscription drops at most once per
//! [`SUMMARY_INTERVAL`](lotse_core::throttle::SUMMARY_INTERVAL).
//!
//! Also the identifiers the supervisor chooses: the session's ULID when the
//! client passes none, and the ICE credentials the demux verifies (RFC 8839 §5.4).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use lotse_api::{ConnectionId, Event, EventClass};
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::session::{
    CloseCode, DeclineReason, Session, SessionBackchannel, SessionEvent, WarningCode,
};
use lotse_api_types::time::rfc3339;
use lotse_core::clock::Clock;
use lotse_core::connection::ConnectionError;
use lotse_core::source::SourceError;
use lotse_core::text::plain;
use lotse_core::throttle::Throttle;
use lotse_ipc::SessionEvent as WorkerSessionEvent;
use tokio::sync::mpsc::OwnedPermit;
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::net::turn_client::Lease;
use crate::worker_text::{MAX_MESSAGE_BYTES, MAX_NAME_BYTES};

/// Events a session subscription holds before the server's forwarder
/// drains them; signaling is a handful of events, so a full queue means
/// the control connection is not being read.
pub(crate) const SESSION_QUEUE: usize = 128;

/// Events kept for an orphaned session: its signaling only, since the
/// adopter's `state` snapshot stands for every state it missed.
pub(crate) const ORPHAN_BUFFER: usize = 64;

/// Browser candidates accepted before the answer.
pub(crate) const MAX_EARLY_CANDIDATES: u32 = 32;

/// Browser candidates accepted per session.
pub(crate) const MAX_REMOTE_CANDIDATES: u32 = 64;

/// Candidate lines a session's worker may report: its host candidates, one
/// per address of the shared socket and of the ICE-TCP listener, a handful
/// even on a host with many interfaces; the cap is the browser's
/// ([`MAX_REMOTE_CANDIDATES`]).
pub(crate) const MAX_WORKER_CANDIDATES: u32 = 64;

/// Bytes of text a session's worker may report over the session's life
/// besides its answer (bounded on its own by
/// [`MAX_ANSWER_BYTES`](crate::worker_text::MAX_ANSWER_BYTES)): candidate
/// lines, their `mid`s, warning messages. 16 KiB, three times what a
/// well-behaved worker reports with many interfaces and every warning. A
/// session's events then take a bounded share of the client's queue
/// however long its worker reports: this and the answer, at most twice
/// over once JSON escapes them, and a few KiB of framing.
pub(crate) const MAX_REPORT_TEXT_BYTES: usize = 16 * 1024;

/// Channels a session may ask for over all its relay candidates: one per
/// browser candidate the agent checks from the relay and per peer first
/// seen through it, which the demux caps at 8 addresses.
pub(crate) const MAX_RELAY_CHANNELS: usize = 16;

/// The `closed` code of a connection's error, which closes a session
/// still waiting for its answer when its connection fails: the same code
/// `stream/get` reports as `last_error`.
pub(crate) const fn close_code(error: &ConnectionError) -> CloseCode {
    match error {
        ConnectionError::WorkerCrashed => CloseCode::WorkerCrashed,
        ConnectionError::Source(SourceError::Unreachable(_)) => CloseCode::SourceUnreachable,
        ConnectionError::Source(SourceError::AuthFailed(_)) => CloseCode::SourceAuthFailed,
        ConnectionError::Source(SourceError::Timeout(_)) => CloseCode::SourceTimeout,
        ConnectionError::Source(SourceError::Protocol(_)) => CloseCode::SourceProtocolError,
        ConnectionError::Source(SourceError::Ended(_)) => CloseCode::SourceEnded,
    }
}

/// The error codes a worker may refuse a re-offer with; any other is an
/// `internal_error`.
const RENEGOTIATE_CODES: [(&str, ErrorCode); 2] = [
    ("invalid_sdp", ErrorCode::InvalidSdp),
    ("no_video_track", ErrorCode::NoVideoTrack),
];

/// The talk-back codecs a worker may report negotiated;
/// anything else is taken as not negotiated.
const TALKBACK_CODECS: [&str; 3] = ["opus", "pcmu", "pcma"];

/// `RTCIceConnectionState` names.
const ICE_STATES: [&str; 7] = [
    "new",
    "checking",
    "connected",
    "completed",
    "disconnected",
    "failed",
    "closed",
];

/// `RTCDtlsTransportState` names.
const DTLS_STATES: [&str; 5] = ["new", "connecting", "connected", "closed", "failed"];

/// The ICE characters (RFC 8839 §5.4 `ice-char` without `+` and `/`, so
/// the values survive every SDP and log unquoted).
const ICE_CHARS: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The ufrag length: 8 characters, about 47 random bits (RFC 8839 §5.4
/// asks for at least 24).
const UFRAG_LEN: usize = 8;

/// The password length: 24 characters, about 142 random bits (RFC 8839
/// §5.4 asks for at least 128).
const PASS_LEN: usize = 24;

/// Crockford's base32 alphabet, as ULIDs spell it.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Who holds a session's subscription.
#[derive(Debug)]
struct Owner {
    /// The control connection.
    connection: ConnectionId,
    /// The subscribing command's id (`webrtc/offer` or `session/adopt`).
    subscription: u64,
    /// Where the events go.
    events: mpsc::Sender<Event>,
}

/// One of a session's relay candidates.
#[derive(Debug)]
struct SessionRelay {
    /// The lease on its allocation, shared with the channel bindings in
    /// flight.
    lease: Arc<Lease>,
    /// Its gathering waits for the worker's report.
    pending: bool,
}

/// A channel to bind for a session: on the allocation `lease` holds, to
/// `peer`, for the relay candidate at `relayed`.
#[derive(Debug)]
pub(crate) struct ChannelRequest {
    /// The lease.
    pub(crate) lease: Arc<Lease>,
    /// The relayed address, which the worker's binding names.
    pub(crate) relayed: SocketAddr,
    /// The peer, canonical.
    pub(crate) peer: SocketAddr,
}

/// One session.
#[derive(Debug)]
pub(crate) struct SessionEntry {
    /// Unique over the daemon's lifetime, so a timer never acts on a later
    /// session that reuses the id.
    pub(crate) serial: u64,
    /// The stream it views.
    pub(crate) stream_id: String,
    /// The source connection whose worker runs it.
    pub(crate) connection: String,
    /// The local ICE ufrag, its demux key.
    pub(crate) ufrag: String,
    /// The subscription, while a control connection owns it.
    owner: Option<Owner>,
    /// Signaling kept while orphaned, oldest first.
    buffer: VecDeque<Event>,
    /// Counts orphanings, so a grace timer only expires its own.
    orphan_epoch: u64,
    /// The ICE state.
    ice: &'static str,
    /// The DTLS state.
    dtls: &'static str,
    /// The answer went out.
    pub(crate) answered: bool,
    /// The talk-back codec the answer negotiated, if any.
    talkback: Option<&'static str>,
    /// Browser candidates received so far.
    pub(crate) remote_candidates: u32,
    /// STUN gathers still running; end-of-candidates waits for them.
    gathers: usize,
    /// The worker sent its end-of-candidates.
    worker_done: bool,
    /// End-of-candidates went out; later candidates are dropped.
    candidates_done: bool,
    /// Candidate lines the worker reported, at most
    /// [`MAX_WORKER_CANDIDATES`].
    worker_candidates: u32,
    /// Bytes of the worker's text charged, at most
    /// [`MAX_REPORT_TEXT_BYTES`].
    report_bytes: usize,
    /// The warning codes forwarded, each once.
    warned: Vec<WarningCode>,
    /// The `backchannel_declined` reports still allowed: one per offer,
    /// or re-offer handed to the worker, answered, until it comes; a
    /// report that answers no request allows none.
    declines_due: u32,
    /// The re-offer handed to the worker whose answer or refusal has not
    /// come, with the way back to its `webrtc/renegotiate`. Held until
    /// that report, even once the command gave up or lost its client
    /// (the sender then closed), so a late report answers the re-offer
    /// it belongs to and never the next one.
    renegotiation: Option<oneshot::Sender<Result<String, ApiError>>>,
    /// Warnings dropped, repeated or unknown; only the first is logged,
    /// so a worker cannot flood the log either.
    warnings_dropped: u32,
    /// Candidate lines gathered before the answer: server-reflexive ones,
    /// and relay ones the worker made.
    held: Vec<String>,
    /// The answer's first media section, which the srflx candidates name.
    mid: Option<String>,
    /// The relay candidates handed to the worker.
    relays: Vec<SessionRelay>,
    /// The (relayed, peer) pairs a channel was asked for.
    channels: HashSet<(SocketAddr, SocketAddr)>,
    /// Channels refused over [`MAX_RELAY_CHANNELS`]; only the first is
    /// logged, so a worker cannot flood the log.
    channels_refused: u32,
    /// Rate-limits the line of each (ICE, DTLS) state pair the session
    /// reaches: a worker can report states as fast as it likes, but each
    /// pair is logged when first reached. At most one entry per pair of
    /// known names.
    state_lines: HashMap<(&'static str, &'static str), Throttle>,
    /// Rate-limits the line of the events a full subscription drops, which
    /// a worker can cause as fast as it reports.
    full_lines: Throttle,
    /// The injected clock, which [`Self::full_lines`] reads.
    clock: Arc<dyn Clock>,
    /// Channels the worker asked for that are still to bind.
    channel_requests: Vec<ChannelRequest>,
    /// When the offer arrived.
    since: SystemTime,
    /// Its one-shot timers (the gather deadline, grace), aborted when the
    /// entry is dropped: no timer task outlives its session.
    timers: Vec<AbortHandle>,
    /// The slot in its driver's queue reserved for its close at the
    /// offer, behind the offer: a full queue never drops the close, which
    /// the worker's session waits for without a deadline of its own.
    pub(crate) close_slot: Option<OwnedPermit<crate::driver::DriverCommand>>,
}

impl Drop for SessionEntry {
    fn drop(&mut self) {
        for timer in &self.timers {
            timer.abort();
        }
    }
}

impl SessionEntry {
    /// A session owned by `connection`'s subscription `subscription`,
    /// opened now on `clock`.
    pub(crate) fn new(
        serial: u64,
        stream_id: String,
        connection: String,
        ufrag: String,
        owner: (ConnectionId, u64, mpsc::Sender<Event>),
        clock: Arc<dyn Clock>,
    ) -> Self {
        let (connection_id, subscription, events) = owner;
        Self {
            serial,
            stream_id,
            connection,
            ufrag,
            owner: Some(Owner {
                connection: connection_id,
                subscription,
                events,
            }),
            buffer: VecDeque::new(),
            orphan_epoch: 0,
            ice: "new",
            dtls: "new",
            answered: false,
            talkback: None,
            remote_candidates: 0,
            gathers: 0,
            worker_done: false,
            candidates_done: false,
            worker_candidates: 0,
            report_bytes: 0,
            warned: Vec::new(),
            declines_due: 0,
            renegotiation: None,
            warnings_dropped: 0,
            held: Vec::new(),
            mid: None,
            relays: Vec::new(),
            channels: HashSet::new(),
            channels_refused: 0,
            state_lines: HashMap::new(),
            full_lines: Throttle::default(),
            channel_requests: Vec::new(),
            since: clock.wall_now(),
            clock,
            timers: Vec::new(),
            close_slot: None,
        }
    }

    /// Keeps `timer` until the session ends, dropping those that already
    /// fired.
    pub(crate) fn add_timer(&mut self, timer: AbortHandle) {
        self.timers.retain(|kept| !kept.is_finished());
        self.timers.push(timer);
    }

    /// Its timers still pending or running, for tests.
    #[cfg(test)]
    pub(crate) fn timers(&self) -> &[AbortHandle] {
        &self.timers
    }

    /// Whether `connection`'s subscription `subscription` owns it.
    pub(crate) fn owned_by(&self, connection: ConnectionId, subscription: u64) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|o| o.connection == connection && o.subscription == subscription)
    }

    /// Whether `connection` owns it.
    pub(crate) fn owned_by_connection(&self, connection: ConnectionId) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|o| o.connection == connection)
    }

    /// Whether some control connection owns it.
    pub(crate) const fn is_owned(&self) -> bool {
        self.owner.is_some()
    }

    /// The current orphaning, for the grace timer.
    pub(crate) const fn orphan_epoch(&self) -> u64 {
        self.orphan_epoch
    }

    /// Hands an event to the owner, or buffers it while orphaned (the
    /// oldest goes when the buffer is full). A full subscription queue
    /// drops the event: the control connection is not being read and is
    /// about to be disconnected for it; the drops are logged at most once
    /// per [`SUMMARY_INTERVAL`](lotse_core::throttle::SUMMARY_INTERVAL).
    /// An orphan keeps no `state` diagnostic: the adopter's snapshot
    /// carries the latest, so a worker flapping its state cannot push the
    /// buffered signaling out.
    pub(crate) fn deliver(&mut self, session_id: &str, event: Event) {
        if let Some(owner) = &self.owner {
            match owner.events.try_send(event) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(event)) => {
                    if let Some(count) = self.full_lines.hit(self.clock.now()) {
                        tracing::warn!(
                            session.id = session_id,
                            event = ?event.payload.get("type"),
                            count,
                            "session subscription full; event dropped"
                        );
                    }
                }
                // The forwarder ended; the connection's close orphans the
                // session next.
                Err(mpsc::error::TrySendError::Closed(event)) => {
                    tracing::debug!(session.id = session_id, event = ?event.payload.get("type"), "session subscription gone; event dropped");
                }
            }
        } else if event.class == EventClass::Diagnostic {
            tracing::trace!(
                session.id = session_id,
                "orphaned; the state is left to the adopter's snapshot"
            );
        } else {
            if self.buffer.len() >= ORPHAN_BUFFER {
                let _oldest = self.buffer.pop_front();
                tracing::debug!(
                    session.id = session_id,
                    "orphan buffer full; oldest event dropped"
                );
            }
            self.buffer.push_back(event);
        }
    }

    /// The control connection is gone: keep media, buffer the events,
    /// and return the epoch the grace timer must match.
    pub(crate) fn orphan(&mut self) -> u64 {
        self.owner = None;
        self.orphan_epoch = self.orphan_epoch.saturating_add(1);
        self.orphan_epoch
    }

    /// `session/adopt`: the new owner gets a `state` snapshot, then the
    /// buffered events, then live ones.
    pub(crate) fn adopt(
        &mut self,
        connection: ConnectionId,
        subscription: u64,
    ) -> mpsc::Receiver<Event> {
        let (events, rx) = mpsc::channel(SESSION_QUEUE.saturating_add(ORPHAN_BUFFER));
        // The snapshot is the first event of `session/adopt` (the API's
        // contract), so it is signaling: as a diagnostic, a live state
        // still queued with it would replace it at the back of the
        // outbox, behind the buffered events, and it could be dropped.
        // The states after it are diagnostics again.
        let snapshot = Event {
            class: EventClass::Signaling,
            ..api_event(&SessionEvent::State {
                ice: self.ice.to_owned(),
                dtls: self.dtls.to_owned(),
            })
        };
        let _queued = events.try_send(snapshot);
        for event in self.buffer.drain(..) {
            let _queued = events.try_send(event);
        }
        self.owner = Some(Owner {
            connection,
            subscription,
            events,
        });
        rx
    }

    /// Whether end-of-candidates went out, after which no candidate may
    /// follow (RFC 8838 §13).
    pub(crate) const fn candidates_done(&self) -> bool {
        self.candidates_done
    }

    /// Takes a `webrtc/renegotiate` for the session: `reply` gets the
    /// worker's answer or refusal ([`WorkerSessionEvent::Renegotiated`],
    /// [`WorkerSessionEvent::RenegotiateRefused`]). Refused before the
    /// answer (a browser cannot re-offer before it has one) and while the
    /// worker has not answered the last re-offer, even one whose command
    /// gave up or lost its client: the reports carry no request of their
    /// own, so only one re-offer may be out. The worker answers every
    /// re-offer it is handed, and its sessions close when it exits, so
    /// only a stuck worker keeps the next one out.
    pub(crate) fn renegotiate(
        &mut self,
        reply: oneshot::Sender<Result<String, ApiError>>,
    ) -> Result<(), ApiError> {
        if !self.answered {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "the session has no answer yet",
            ));
        }
        if self.renegotiation.is_some() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "a re-offer of the session is still being answered",
            ));
        }
        self.renegotiation = Some(reply);
        Ok(())
    }

    /// The re-offer [`Self::renegotiate`] took never reached the worker
    /// (its connection's queue was full): no answer comes for it.
    pub(crate) fn renegotiation_unsent(&mut self) {
        self.renegotiation = None;
    }

    /// Whether a re-offer waits for the worker's answer, for tests.
    #[cfg(test)]
    pub(crate) const fn renegotiating(&self) -> bool {
        self.renegotiation.is_some()
    }

    /// The re-offer a worker's answer or refusal answers: `None`, and the
    /// report dropped, when none is out.
    fn answered_renegotiation(&mut self) -> Option<oneshot::Sender<Result<String, ApiError>>> {
        let waiting = self.renegotiation.take();
        if waiting.is_none() {
            tracing::debug!(
                stream.id = %self.stream_id,
                "a worker answered a re-offer it was not handed; dropped"
            );
        }
        waiting
    }

    /// A relay candidate went to the worker on `lease`: its gathering
    /// ends with the worker's report ([`WorkerSessionEvent::Relayed`]).
    pub(crate) fn relay_handed_over(&mut self, lease: Lease) {
        self.relays.push(SessionRelay {
            lease: Arc::new(lease),
            pending: true,
        });
    }

    /// The channel requests the worker's reports raised, to bind.
    pub(crate) fn take_channel_requests(&mut self) -> Vec<ChannelRequest> {
        std::mem::take(&mut self.channel_requests)
    }

    /// The worker reported the relay candidate at `relayed`: its line ends
    /// that relay's gathering. A report for no relay waiting is the
    /// worker's mistake and changes nothing.
    fn relayed(&mut self, relayed: SocketAddr, candidate: Option<String>) -> Vec<SessionEvent> {
        let Some(relay) = self
            .relays
            .iter_mut()
            .find(|relay| relay.pending && relay.lease.relayed() == relayed)
        else {
            tracing::debug!(%relayed, "relay report for no relay waiting; ignored");
            return Vec::new();
        };
        relay.pending = false;
        self.gathered(candidate)
    }

    /// The worker's agent sends from the relay candidate at `relayed` to
    /// `peer`: a channel (with its permission) is to be bound, once per
    /// peer and at most [`MAX_RELAY_CHANNELS`] in all.
    fn channel_wanted(&mut self, relayed: SocketAddr, peer: SocketAddr) {
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        let Some(relay) = self
            .relays
            .iter()
            .find(|relay| relay.lease.relayed() == relayed)
        else {
            tracing::debug!(%relayed, %peer, "channel wanted on no relay of the session; ignored");
            return;
        };
        if self.channels.len() >= MAX_RELAY_CHANNELS {
            if self.channels_refused == 0 {
                tracing::warn!(
                    %relayed,
                    %peer,
                    limit = MAX_RELAY_CHANNELS,
                    "relay channel limit reached; peer not bound, and later ones without a log"
                );
            }
            self.channels_refused = self.channels_refused.saturating_add(1);
            return;
        }
        if self.channels.insert((relayed, peer)) {
            self.channel_requests.push(ChannelRequest {
                lease: Arc::clone(&relay.lease),
                relayed,
                peer,
            });
        }
    }

    /// `count` STUN and TURN gathers started; end-of-candidates waits for
    /// them.
    pub(crate) const fn gathering(&mut self, count: usize) {
        self.gathers = count;
    }

    /// A gather finished with `candidate`, or without one: the events to
    /// deliver. A candidate before the answer waits for it; one after
    /// end-of-candidates is too late and dropped.
    pub(crate) fn gathered(&mut self, candidate: Option<String>) -> Vec<SessionEvent> {
        self.gathers = self.gathers.saturating_sub(1);
        let mut out = Vec::new();
        if let Some(candidate) = candidate.filter(|_| !self.candidates_done) {
            if self.answered {
                out.push(self.gathered_event(candidate));
            } else {
                self.held.push(candidate);
            }
        }
        out.extend(self.finish_candidates());
        out
    }

    /// A gathered candidate as an event, naming the answer's first media
    /// section (BUNDLE: every section shares the transport).
    fn gathered_event(&self, candidate: String) -> SessionEvent {
        SessionEvent::Candidate {
            candidate,
            sdp_mid: self.mid.clone(),
            sdp_mline_index: self.mid.as_ref().map(|_| 0),
        }
    }

    /// The gather deadline passed: end-of-candidates waits no longer.
    pub(crate) fn gather_deadline(&mut self) -> Vec<SessionEvent> {
        self.gathers = 0;
        self.finish_candidates().into_iter().collect()
    }

    /// End-of-candidates, once the worker sent its own and no gather runs
    /// (RFC 8838 §13: after it, no candidate follows).
    fn finish_candidates(&mut self) -> Option<SessionEvent> {
        if !self.worker_done || self.gathers > 0 || self.candidates_done {
            return None;
        }
        self.candidates_done = true;
        Some(SessionEvent::Candidate {
            candidate: String::new(),
            sdp_mid: None,
            sdp_mline_index: None,
        })
    }

    /// Takes a worker's report: updates the session and returns the API
    /// events to deliver, in order, or why the report is over the
    /// session's budget (and changes nothing).
    pub(crate) fn apply(
        &mut self,
        report: WorkerSessionEvent,
    ) -> Result<Vec<SessionEvent>, &'static str> {
        match report {
            WorkerSessionEvent::Answer { sdp, talkback } => {
                if self.answered {
                    return Err("a second answer");
                }
                self.answered = true;
                self.declines_due = 1;
                self.talkback = talkback.and_then(|codec| known(&TALKBACK_CODECS, &codec));
                self.mid = sdp
                    .lines()
                    .find_map(|line| line.strip_prefix("a=mid:"))
                    .map(|mid| mid.trim().to_owned());
                let mut out = vec![SessionEvent::Answer { sdp }];
                let held = std::mem::take(&mut self.held);
                out.extend(held.into_iter().map(|line| self.gathered_event(line)));
                Ok(out)
            }
            WorkerSessionEvent::Candidate { candidate, .. } if candidate.is_empty() => {
                self.worker_done = true;
                Ok(self.finish_candidates().into_iter().collect())
            }
            WorkerSessionEvent::Candidate { candidate, mid } => {
                if self.worker_done {
                    // RFC 8838 §13: no candidate follows end-of-candidates.
                    return Err("a candidate after the worker's end-of-candidates");
                }
                if self.worker_candidates >= MAX_WORKER_CANDIDATES {
                    return Err("more candidates than a session allows");
                }
                self.charge(
                    candidate
                        .len()
                        .saturating_add(mid.as_ref().map_or(0, String::len)),
                )?;
                self.worker_candidates = self.worker_candidates.saturating_add(1);
                Ok(vec![SessionEvent::Candidate {
                    candidate,
                    sdp_mid: mid,
                    sdp_mline_index: None,
                }])
            }
            WorkerSessionEvent::Relayed { relayed, candidate } => {
                self.charge(candidate.as_ref().map_or(0, String::len))?;
                Ok(self.relayed(relayed, candidate))
            }
            WorkerSessionEvent::ChannelWanted { relayed, peer } => {
                self.channel_wanted(relayed, peer);
                Ok(Vec::new())
            }
            WorkerSessionEvent::State { ice, dtls } => {
                let before = (self.ice, self.dtls);
                if let Some(ice) = known(&ICE_STATES, &ice) {
                    self.ice = ice;
                }
                if let Some(dtls) = known(&DTLS_STATES, &dtls) {
                    self.dtls = dtls;
                }
                // The API sends `state` when ICE or DTLS changed: a
                // repeated one is no event, so it costs the queue nothing.
                if (self.ice, self.dtls) == before {
                    return Ok(Vec::new());
                }
                Ok(vec![SessionEvent::State {
                    ice: self.ice.to_owned(),
                    dtls: self.dtls.to_owned(),
                }])
            }
            // The client asked for each answer and refusal, so neither
            // counts against the worker's text budget; the answer is
            // bounded by `worker_text::check`, the message cut to size.
            // One that answers no re-offer is dropped and changes nothing.
            WorkerSessionEvent::Renegotiated { sdp, talkback } => {
                if !self.answered {
                    return Err("a re-offer answered before the offer");
                }
                let Some(waiting) = self.answered_renegotiation() else {
                    return Ok(Vec::new());
                };
                self.declines_due = 1;
                self.talkback = talkback.and_then(|codec| known(&TALKBACK_CODECS, &codec));
                reply(waiting, Ok(sdp));
                Ok(Vec::new())
            }
            WorkerSessionEvent::RenegotiateRefused { code, message } => {
                let Some(waiting) = self.answered_renegotiation() else {
                    return Ok(Vec::new());
                };
                let message = plain(&message, MAX_MESSAGE_BYTES);
                let code = RENEGOTIATE_CODES
                    .iter()
                    .find(|(name, _)| *name == code)
                    .map_or(ErrorCode::InternalError, |(_, code)| *code);
                reply(waiting, Err(ApiError::new(code, message)));
                Ok(Vec::new())
            }
            WorkerSessionEvent::TalkbackDeclined {
                reason,
                status,
                message,
            } => Ok(self.declined(&reason, status, &message)),
            WorkerSessionEvent::Warning { code, message } => self.warning(&code, &message),
            WorkerSessionEvent::Closed { code, message } => Ok(vec![closed_event(&code, &message)]),
        }
    }

    /// Whether the line of the session's state, just changed, is due at
    /// `now`: `Some` with the times the state reached that (ICE, DTLS) pair
    /// since its last line.
    pub(crate) fn state_line(&mut self, now: Instant) -> Option<u64> {
        self.state_lines
            .entry((self.ice, self.dtls))
            .or_default()
            .hit(now)
    }

    /// Charges `bytes` of the worker's text against
    /// [`MAX_REPORT_TEXT_BYTES`].
    fn charge(&mut self, bytes: usize) -> Result<(), &'static str> {
        let total = self.report_bytes.saturating_add(bytes);
        if total > MAX_REPORT_TEXT_BYTES {
            return Err("more text than a session allows");
        }
        self.report_bytes = total;
        Ok(())
    }

    /// A worker's warning: a known code once, its message made
    /// [`plain`]; a repeated or unknown one is dropped, and so is
    /// `backchannel_declined`, which comes as its own report
    /// ([`Self::declined`]).
    fn warning(&mut self, code: &str, message: &str) -> Result<Vec<SessionEvent>, &'static str> {
        let fresh = WarningCode::parse(code).filter(|known| {
            *known != WarningCode::BackchannelDeclined && !self.warned.contains(known)
        });
        let Some(code) = fresh else {
            if self.warnings_dropped == 0 {
                tracing::warn!(
                    stream.id = %self.stream_id,
                    code = ?plain(code, MAX_NAME_BYTES),
                    "a worker repeated a warning or named an unknown one; dropped, and later ones without a log"
                );
            }
            self.warnings_dropped = self.warnings_dropped.saturating_add(1);
            return Ok(Vec::new());
        };
        let message = plain(message, MAX_MESSAGE_BYTES);
        self.charge(message.len())?;
        self.warned.push(code);
        Ok(vec![SessionEvent::Warning {
            code,
            message,
            reason: None,
            status: None,
        }])
    }

    /// A worker's `backchannel_declined`: one per offer, or re-offer
    /// handed to the worker, answered, with a known `reason`, its message
    /// made [`plain`]; a second one for the same offer, or one with an
    /// unknown reason, is dropped like a repeated warning. Bounded by the
    /// client's offers, so not charged: a client that keeps asking for
    /// talk-back while it is declined does not use up the budget its
    /// session's other reports need.
    fn declined(&mut self, reason: &str, status: Option<u16>, message: &str) -> Vec<SessionEvent> {
        let reason = DeclineReason::parse(reason).filter(|_| self.declines_due > 0);
        let Some(reason) = reason else {
            if self.warnings_dropped == 0 {
                tracing::warn!(
                    stream.id = %self.stream_id,
                    "a worker declined talk-back twice for one offer or for an unknown reason; dropped, and later ones without a log"
                );
            }
            self.warnings_dropped = self.warnings_dropped.saturating_add(1);
            return Vec::new();
        };
        let message = plain(message, MAX_MESSAGE_BYTES);
        self.declines_due = self.declines_due.saturating_sub(1);
        vec![SessionEvent::Warning {
            code: WarningCode::BackchannelDeclined,
            message,
            reason: Some(reason),
            status,
        }]
    }

    /// The session as `session/get` returns it, with whether it holds its
    /// connection's backchannel (`talker`) and its worker's last talk-back
    /// counters.
    pub(crate) fn dto(
        &self,
        session_id: &str,
        talker: bool,
        counters: lotse_ipc::TalkbackStats,
    ) -> Session {
        Session {
            session_id: session_id.to_owned(),
            stream_id: self.stream_id.clone(),
            ice: self.ice.to_owned(),
            dtls: self.dtls.to_owned(),
            answered: self.answered,
            orphaned: self.owner.is_none(),
            since: rfc3339(self.since),
            backchannel: SessionBackchannel {
                negotiated: self.talkback.is_some(),
                talker,
                codec: self.talkback.map(str::to_owned),
                packets_received: counters.packets_received,
                packets_dropped_busy: counters.packets_dropped_busy,
                bytes_sent: counters.bytes_sent,
            },
        }
    }
}

/// `value` as the known `&'static` name it equals.
fn known(names: &[&'static str], value: &str) -> Option<&'static str> {
    let found = names.iter().find(|name| **name == value).copied();
    if found.is_none() {
        tracing::debug!(value, "unknown name in a worker's session report");
    }
    found
}

/// Hands a re-offer's answer or refusal to its `webrtc/renegotiate`,
/// which may have given up or lost its client meanwhile: then it goes
/// nowhere.
fn reply(waiting: oneshot::Sender<Result<String, ApiError>>, answer: Result<String, ApiError>) {
    if waiting.send(answer).is_err() {
        tracing::debug!("re-offer answered after its command gave up or lost its client; dropped");
    }
}

/// A worker's `closed` event, its message made [`plain`]; an unknown code
/// is an `internal_error`, logged and not passed on.
fn closed_event(code: &str, message: &str) -> SessionEvent {
    let message = plain(message, MAX_MESSAGE_BYTES);
    let code = CloseCode::parse(code).unwrap_or_else(|| {
        tracing::warn!(
            code = ?plain(code, MAX_NAME_BYTES),
            "a worker closed a session with an unknown code; internal_error"
        );
        CloseCode::InternalError
    });
    SessionEvent::Closed { code, message }
}

/// A session event as the server queues it: `state` is a diagnostic the
/// outbox coalesces per subscription, and so per session, and may shed
/// (but for the snapshot [`SessionEntry::adopt`] starts with); everything
/// else is signaling and never dropped.
pub(crate) fn api_event(event: &SessionEvent) -> Event {
    let class = match event {
        SessionEvent::State { .. } => EventClass::Diagnostic,
        _ => EventClass::Signaling,
    };
    Event {
        class,
        payload: serde_json::to_value(event).unwrap_or_default(),
    }
}

/// Random characters from [`ICE_CHARS`], without modulo bias.
fn random_chars(len: usize) -> Result<String, getrandom::Error> {
    let mut out = String::with_capacity(len);
    let mut pool = [0_u8; 64];
    while out.len() < len {
        getrandom::fill(&mut pool)?;
        for byte in pool {
            // 248 = 4 × 62: the bytes above it would favor the first chars.
            if byte < 248
                && out.len() < len
                && let Some(c) = ICE_CHARS.get(usize::from(byte % 62))
            {
                out.push(char::from(*c));
            }
        }
    }
    Ok(out)
}

/// A fresh ICE ufrag and password (RFC 8839 §5.4).
pub(crate) fn ice_credentials() -> Result<(String, String), getrandom::Error> {
    Ok((random_chars(UFRAG_LEN)?, random_chars(PASS_LEN)?))
}

/// A ULID for a session the client did not name: 48 bits of milliseconds since
/// the epoch, then 80 random bits, in Crockford's base32 (26 characters).
pub(crate) fn ulid(now: SystemTime) -> Result<String, getrandom::Error> {
    let mut random = [0_u8; 10];
    getrandom::fill(&mut random)?;
    let millis = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    Ok(encode_ulid(millis, random))
}

/// The ULID of `millis` (its low 48 bits) and `random`.
fn encode_ulid(millis: u64, random: [u8; 10]) -> String {
    let value = random
        .iter()
        .fold(u128::from(millis & 0xFFFF_FFFF_FFFF), |acc, byte| {
            (acc << 8) | u128::from(*byte)
        });
    let mut out = String::with_capacity(26);
    for index in (0..26_u32).rev() {
        let digit = (value >> index.saturating_mul(5)) & 0x1F;
        let c = CROCKFORD
            .get(usize::try_from(digit).unwrap_or(0))
            .copied()
            .unwrap_or(b'0');
        let _infallible = out.write_char(char::from(c));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::text::CUT_MARK;
    use lotse_core::throttle::SUMMARY_INTERVAL;
    use serde_json::json;

    use super::*;
    use crate::test_support::Captured;

    /// [`SessionEntry::apply`] for a report within the budget.
    trait Applied {
        fn applied(&mut self, report: WorkerSessionEvent) -> Vec<SessionEvent>;
    }

    impl Applied for SessionEntry {
        fn applied(&mut self, report: WorkerSessionEvent) -> Vec<SessionEvent> {
            self.apply(report).expect("within the budget")
        }
    }

    fn entry(events: mpsc::Sender<Event>) -> SessionEntry {
        entry_on(
            events,
            Arc::new(FakeClock::new(SystemClock.now(), UNIX_EPOCH)),
        )
    }

    fn entry_on(events: mpsc::Sender<Event>, clock: Arc<dyn Clock>) -> SessionEntry {
        SessionEntry::new(
            1,
            "front".into(),
            "c1".into(),
            "ufrag".into(),
            (ConnectionId(1), 7, events),
            clock,
        )
    }

    #[test]
    fn ulids_follow_the_spec_layout() {
        // The spec's example ULID 01ARYZ6S41TSV4RRFFQ69G5FAV has time 1469918176385.
        let id = encode_ulid(1_469_918_176_385, [0; 10]);
        assert_eq!(id, "01ARYZ6S410000000000000000");
        assert_eq!(encode_ulid(0, [0xFF; 10]), "0000000000ZZZZZZZZZZZZZZZZ");
        assert_eq!(encode_ulid(u64::MAX, [0; 10]), "7ZZZZZZZZZ0000000000000000");
        let fresh = ulid(SystemClock.wall_now()).unwrap();
        assert_eq!(fresh.len(), 26);
        assert!(fresh.bytes().all(|b| CROCKFORD.contains(&b)), "{fresh}");
        assert_ne!(fresh, ulid(SystemClock.wall_now()).unwrap());
        assert_eq!(&ulid(UNIX_EPOCH).unwrap()[..10], "0000000000");
    }

    #[test]
    fn ice_credentials_are_long_enough_and_ice_chars_only_rfc_8839_5_4() {
        let (ufrag, pass) = ice_credentials().unwrap();
        assert_eq!((ufrag.len(), pass.len()), (UFRAG_LEN, PASS_LEN));
        assert!(
            ufrag
                .bytes()
                .chain(pass.bytes())
                .all(|b| b.is_ascii_alphanumeric())
        );
        assert_ne!(ice_credentials().unwrap().0, ufrag);
        // Long outputs draw the pool more than once, and use the whole
        // alphabet: 2000 uniform draws miss one of 62 chars with p < 1e-12.
        let long = random_chars(2_000).unwrap();
        assert_eq!(long.len(), 2_000);
        let distinct: std::collections::BTreeSet<u8> = long.bytes().collect();
        assert_eq!(distinct.len(), 62);
    }

    /// A talk-back request never closes a session: its answer declines
    /// it. The code that once did is no longer known, so a worker that
    /// reported it would be an internal error.
    #[test]
    fn backchannel_unavailable_is_no_closed_code() {
        assert_eq!(
            closed_event("backchannel_unavailable", "m"),
            SessionEvent::Closed {
                code: CloseCode::InternalError,
                message: "m".into()
            }
        );
    }

    #[test]
    fn worker_reports_map_onto_known_events_only() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        assert!(!session.answered);
        assert_eq!(
            session.applied(WorkerSessionEvent::Answer {
                sdp: "v=0".into(),
                talkback: Some("pcma".into())
            }),
            vec![SessionEvent::Answer { sdp: "v=0".into() }]
        );
        assert!(session.answered);
        assert_eq!(
            session.applied(WorkerSessionEvent::Candidate {
                candidate: "candidate:1".into(),
                mid: Some("0".into())
            }),
            vec![SessionEvent::Candidate {
                candidate: "candidate:1".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: None
            }]
        );
        assert_eq!(
            session.applied(WorkerSessionEvent::State {
                ice: "connected".into(),
                dtls: "made-up".into()
            }),
            vec![SessionEvent::State {
                ice: "connected".into(),
                dtls: "new".into()
            }],
            "an unknown state name keeps the last known one"
        );
        assert_eq!(
            session.applied(WorkerSessionEvent::Warning {
                code: "h264_profile_mismatch".into(),
                message: "m".into(),
            }),
            vec![SessionEvent::Warning {
                code: WarningCode::H264ProfileMismatch,
                message: "m".into(),
                reason: None,
                status: None,
            }]
        );
        assert_eq!(
            session.applied(WorkerSessionEvent::Warning {
                code: "rm -rf".into(),
                message: "m".into(),
            }),
            vec![]
        );
        assert_eq!(
            session.applied(WorkerSessionEvent::Closed {
                code: "ice_failed".into(),
                message: "m".into()
            }),
            vec![SessionEvent::Closed {
                code: CloseCode::IceFailed,
                message: "m".into()
            }]
        );
        assert_eq!(
            closed_event("bogus", "m"),
            SessionEvent::Closed {
                code: CloseCode::InternalError,
                message: "m".into()
            }
        );
        let counters = lotse_ipc::TalkbackStats {
            packets_received: 9,
            packets_dropped_busy: 2,
            bytes_sent: 1_120,
        };
        let dto = session.dto("s1", true, counters);
        assert_eq!(
            (
                dto.ice.as_str(),
                dto.dtls.as_str(),
                dto.answered,
                dto.orphaned
            ),
            ("connected", "new", true, false)
        );
        assert_eq!(dto.since, "1970-01-01T00:00:00.000Z");
        assert_eq!(
            dto.backchannel,
            SessionBackchannel {
                negotiated: true,
                talker: true,
                codec: Some("pcma".into()),
                packets_received: 9,
                packets_dropped_busy: 2,
                bytes_sent: 1_120,
            }
        );
    }

    /// A worker names only a known talk-back codec; anything else, or
    /// none, is talk-back off.
    #[test]
    fn a_talk_back_codec_outside_the_known_ones_is_not_negotiated() {
        for (reported, codec) in [
            (Some("opus"), Some("opus")),
            (Some("pcmu"), Some("pcmu")),
            (Some("pcma"), Some("pcma")),
            (Some("g722"), None),
            (None, None),
        ] {
            let (tx, _rx) = mpsc::channel(8);
            let mut session = entry(tx);
            assert_eq!(
                session
                    .dto("s1", false, lotse_ipc::TalkbackStats::default())
                    .backchannel,
                SessionBackchannel::default(),
                "nothing negotiated before the answer"
            );
            let _events = session.apply(WorkerSessionEvent::Answer {
                sdp: "v=0".into(),
                talkback: reported.map(str::to_owned),
            });
            let dto = session.dto("s1", false, lotse_ipc::TalkbackStats::default());
            assert_eq!(
                (dto.backchannel.negotiated, dto.backchannel.codec.as_deref()),
                (codec.is_some(), codec),
                "{reported:?}"
            );
        }
    }

    #[test]
    fn a_worker_answers_once_and_a_second_answer_closes_the_session() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        session.applied(WorkerSessionEvent::Answer {
            sdp: "v=0\r\na=mid:0\r\n".into(),
            talkback: None,
        });
        assert_eq!(
            session.apply(WorkerSessionEvent::Answer {
                sdp: "v=0\r\na=mid:1\r\n".into(),
                talkback: None,
            }),
            Err("a second answer")
        );
        assert_eq!(session.mid.as_deref(), Some("0"), "nothing changed");
    }

    /// A decline passes once per offer answered, with a known reason,
    /// like a warning otherwise; a re-offer is answered to the command
    /// waiting for it, and `session/get` follows its talk-back.
    #[test]
    fn a_decline_passes_once_per_offer_answered_and_a_re_offer_is_answered() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        let declined = |reason: &str, status: Option<u16>| WorkerSessionEvent::TalkbackDeclined {
            reason: reason.into(),
            status,
            message: "why".into(),
        };
        // Before the answer: no re-offer, and no decline either.
        let (reply, _waiting) = oneshot::channel();
        assert_eq!(
            session.renegotiate(reply).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            session.apply(WorkerSessionEvent::Renegotiated {
                sdp: "v=0".into(),
                talkback: None,
            }),
            Err("a re-offer answered before the offer")
        );
        assert_eq!(session.applied(declined("busy", None)), vec![]);
        assert_eq!(session.warnings_dropped, 1);
        session.applied(WorkerSessionEvent::Answer {
            sdp: "v=0".into(),
            talkback: None,
        });
        // One decline per offer, with its reason; a second, or an unknown
        // reason, is dropped like a repeated warning.
        assert_eq!(
            session.applied(declined("busy", None)),
            vec![SessionEvent::Warning {
                code: WarningCode::BackchannelDeclined,
                message: "why".into(),
                reason: Some(DeclineReason::Busy),
                status: None,
            }]
        );
        assert_eq!(session.applied(declined("busy", None)), vec![]);
        assert_eq!(session.warnings_dropped, 2);
        assert_eq!(session.report_bytes, 0, "a decline is not charged");

        // An answer to a re-offer never handed to the worker is dropped:
        // it changes the talk-back no more than it allows a decline.
        assert_eq!(
            session.applied(WorkerSessionEvent::Renegotiated {
                sdp: "v=0".into(),
                talkback: Some("opus".into()),
            }),
            vec![]
        );
        assert_eq!(session.talkback, None);
        assert_eq!(session.applied(declined("busy", None)), vec![]);
        assert_eq!(session.warnings_dropped, 3);

        // A re-offer: answered to the command waiting, which `session/get`
        // follows; the next decline passes again.
        let (reply, mut waiting) = oneshot::channel();
        session.renegotiate(reply).unwrap();
        let (again, _again) = oneshot::channel();
        assert_eq!(
            session.renegotiate(again).unwrap_err().message,
            "a re-offer of the session is still being answered"
        );
        assert_eq!(
            session.applied(WorkerSessionEvent::Renegotiated {
                sdp: "v=0\r\na=mid:0\r\n".into(),
                talkback: Some("opus".into()),
            }),
            vec![]
        );
        assert_eq!(waiting.try_recv(), Ok(Ok("v=0\r\na=mid:0\r\n".into())));
        let dto = session.dto("s1", true, lotse_ipc::TalkbackStats::default());
        assert_eq!(dto.backchannel.codec.as_deref(), Some("opus"));
        assert_eq!(
            session.applied(declined("refused", Some(503))),
            vec![SessionEvent::Warning {
                code: WarningCode::BackchannelDeclined,
                message: "why".into(),
                reason: Some(DeclineReason::Refused),
                status: Some(503),
            }]
        );
        assert_eq!(session.applied(declined("tired", None)), vec![]);
        assert_eq!(session.warnings_dropped, 4);
    }

    /// A re-offer refused by the worker fails the command under a known
    /// code; a re-offer stays out until the worker answers it, even after
    /// its command gave up or lost its client, so a late answer never
    /// answers the next; one that never reached the worker is not in the
    /// way; a report that answers no re-offer is dropped.
    #[test]
    fn a_re_offer_stays_out_until_the_worker_answers_it() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        session.applied(WorkerSessionEvent::Answer {
            sdp: "v=0".into(),
            talkback: None,
        });
        // Refused under a known code, else as an internal error.
        for (code, expected) in [
            ("invalid_sdp", ErrorCode::InvalidSdp),
            ("no_video_track", ErrorCode::NoVideoTrack),
            ("made_up", ErrorCode::InternalError),
        ] {
            let (reply, mut waiting) = oneshot::channel();
            session.renegotiate(reply).unwrap();
            assert_eq!(
                session.applied(WorkerSessionEvent::RenegotiateRefused {
                    code: code.into(),
                    message: "no\nway".into(),
                }),
                vec![]
            );
            let error = waiting.try_recv().unwrap().unwrap_err();
            assert_eq!((error.code, error.message.as_str()), (expected, "no way"));
        }
        // A: its command gives up, or loses its client; B, the retry, is
        // refused until A's answer comes, which goes nowhere.
        for late in [
            WorkerSessionEvent::Renegotiated {
                sdp: "a".into(),
                talkback: None,
            },
            WorkerSessionEvent::RenegotiateRefused {
                code: "invalid_sdp".into(),
                message: "a".into(),
            },
        ] {
            let (reply, waiting) = oneshot::channel();
            session.renegotiate(reply).unwrap();
            drop(waiting);
            let (reply, _b) = oneshot::channel();
            assert_eq!(
                session.renegotiate(reply).unwrap_err().message,
                "a re-offer of the session is still being answered"
            );
            assert_eq!(session.applied(late), vec![]);
            assert!(!session.renegotiating());
            // B is answered with its own answer.
            let (reply, mut b) = oneshot::channel();
            session.renegotiate(reply).unwrap();
            session.applied(WorkerSessionEvent::Renegotiated {
                sdp: "b".into(),
                talkback: None,
            });
            assert_eq!(b.try_recv(), Ok(Ok("b".into())));
        }
        // A refusal that answers no re-offer is dropped, and the next one
        // still gets its own.
        assert_eq!(
            session.applied(WorkerSessionEvent::RenegotiateRefused {
                code: "invalid_sdp".into(),
                message: "none".into(),
            }),
            vec![]
        );
        // One that never reached the worker is not in the way.
        let (reply, _waiting) = oneshot::channel();
        session.renegotiate(reply).unwrap();
        session.renegotiation_unsent();
        assert!(!session.renegotiating());
        let (reply, mut waiting) = oneshot::channel();
        session.renegotiate(reply).unwrap();
        session.applied(WorkerSessionEvent::Renegotiated {
            sdp: "c".into(),
            talkback: None,
        });
        assert_eq!(waiting.try_recv(), Ok(Ok("c".into())));
    }

    /// The client asks for each re-offer's answer, refusal and decline,
    /// so none is charged against the worker's text budget: a session
    /// whose budget is full keeps being re-offered and declined
    /// talk-back, and its other text is still over the budget.
    #[test]
    fn re_offers_and_their_declines_are_free_of_the_text_budget() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        let declined = WorkerSessionEvent::TalkbackDeclined {
            reason: "busy".into(),
            status: None,
            message: "m".repeat(MAX_MESSAGE_BYTES * 2),
        };
        session.applied(WorkerSessionEvent::Answer {
            sdp: "v=0".into(),
            talkback: None,
        });
        assert_eq!(session.applied(declined.clone()).len(), 1);
        session.applied(line(MAX_REPORT_TEXT_BYTES));
        assert_eq!(session.report_bytes, MAX_REPORT_TEXT_BYTES);
        // More declines than the budget has bytes for, cut to size each.
        for _ in 0..=MAX_REPORT_TEXT_BYTES / MAX_MESSAGE_BYTES {
            let (reply, mut waiting) = oneshot::channel();
            session.renegotiate(reply).unwrap();
            assert_eq!(
                session.apply(WorkerSessionEvent::Renegotiated {
                    sdp: "v=0".into(),
                    talkback: None,
                }),
                Ok(vec![])
            );
            assert_eq!(waiting.try_recv(), Ok(Ok("v=0".into())));
            let events = session
                .apply(declined.clone())
                .expect("a decline is not charged");
            assert!(
                matches!(
                    events.as_slice(),
                    [SessionEvent::Warning { message, .. }] if message.len() <= MAX_MESSAGE_BYTES
                        && message.ends_with(CUT_MARK)
                ),
                "one warning, cut to size: {events:?}"
            );
            let (reply, mut waiting) = oneshot::channel();
            session.renegotiate(reply).unwrap();
            assert_eq!(
                session.apply(WorkerSessionEvent::RenegotiateRefused {
                    code: "invalid_sdp".into(),
                    message: "no way".into(),
                }),
                Ok(vec![])
            );
            assert_eq!(
                waiting.try_recv().unwrap().unwrap_err().code,
                ErrorCode::InvalidSdp
            );
        }
        assert_eq!(session.report_bytes, MAX_REPORT_TEXT_BYTES);
        assert_eq!(
            session.apply(WorkerSessionEvent::Warning {
                code: "av_sync_lost".into(),
                message: "x".into(),
            }),
            Err("more text than a session allows"),
            "the worker's own text still is"
        );
    }

    fn line(n: usize) -> WorkerSessionEvent {
        WorkerSessionEvent::Candidate {
            candidate: "c".repeat(n),
            mid: None,
        }
    }

    #[test]
    fn rfc_8838_13_a_worker_s_candidates_are_counted_and_none_follows_its_end() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        for _ in 0..MAX_WORKER_CANDIDATES {
            assert_eq!(session.applied(line(1)).len(), 1);
        }
        assert_eq!(
            session.apply(line(1)),
            Err("more candidates than a session allows")
        );
        assert_eq!(session.worker_candidates, MAX_WORKER_CANDIDATES);
        assert_eq!(session.report_bytes, 64, "the refused one is not charged");

        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        session.applied(line(1));
        session.applied(end());
        assert_eq!(
            session.apply(line(1)),
            Err("a candidate after the worker's end-of-candidates")
        );
        assert_eq!(session.worker_candidates, 1);
    }

    #[test]
    fn a_session_s_worker_text_is_charged_against_its_budget() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        // A line and its mid count; the answer does not.
        session.applied(WorkerSessionEvent::Answer {
            sdp: "v=0".repeat(1000),
            talkback: None,
        });
        session.applied(WorkerSessionEvent::Candidate {
            candidate: "c".repeat(1000),
            mid: Some("0".repeat(24)),
        });
        let relayed: SocketAddr = "203.0.113.1:49153".parse().unwrap();
        session.applied(WorkerSessionEvent::Relayed {
            relayed,
            candidate: Some("r".repeat(1000)),
        });
        session.applied(WorkerSessionEvent::Relayed {
            relayed,
            candidate: None,
        });
        assert_eq!(session.report_bytes, 2024);
        // To the byte: the budget is full, one more byte is over it.
        session.applied(line(MAX_REPORT_TEXT_BYTES - 2024 - 3));
        session.applied(WorkerSessionEvent::Warning {
            code: "av_sync_lost".into(),
            message: "abc".into(),
        });
        assert_eq!(session.report_bytes, MAX_REPORT_TEXT_BYTES);
        assert_eq!(
            session.apply(line(0)).map(|events| events.len()),
            Ok(1),
            "end-of-candidates is free"
        );
        let (tx, _rx) = mpsc::channel(8);
        let mut full = entry(tx);
        full.applied(line(MAX_REPORT_TEXT_BYTES));
        assert_eq!(full.apply(line(1)), Err("more text than a session allows"));
        assert_eq!(
            full.apply(WorkerSessionEvent::Relayed {
                relayed,
                candidate: Some("r".into())
            }),
            Err("more text than a session allows")
        );
        assert_eq!(
            full.apply(WorkerSessionEvent::Warning {
                code: "av_sync_lost".into(),
                message: "m".into(),
            }),
            Err("more text than a session allows")
        );
        assert_eq!(full.worker_candidates, 1, "a refused line is not counted");
        assert!(full.warned.is_empty(), "nor a refused warning");
    }

    #[test]
    fn a_warning_passes_once_per_known_code_with_a_plain_message() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        let warning = |code: &str, message: String| WorkerSessionEvent::Warning {
            code: code.into(),
            message,
        };
        assert_eq!(
            session.applied(warning("av_sync_lost", format!("a\nb{}", "x".repeat(1000)))),
            vec![SessionEvent::Warning {
                code: WarningCode::AvSyncLost,
                message: format!(
                    "a b{}{CUT_MARK}",
                    "x".repeat(MAX_MESSAGE_BYTES - 3 - CUT_MARK.len())
                ),
                reason: None,
                status: None,
            }]
        );
        assert_eq!(session.report_bytes, MAX_MESSAGE_BYTES);
        assert_eq!(session.warnings_dropped, 0);
        assert_eq!(
            session.applied(warning("av_sync_lost", "again".into())),
            vec![]
        );
        assert_eq!(session.warnings_dropped, 1);
        assert_eq!(session.applied(warning("made_up", "m".into())), vec![]);
        assert_eq!(session.warnings_dropped, 2);
        // A known code, but one that comes only as its own report, with
        // the reason a declined talk-back needs.
        assert_eq!(
            session.applied(warning("backchannel_declined", "m".into())),
            vec![]
        );
        assert_eq!(session.warnings_dropped, 3);
        assert_eq!(
            session.report_bytes, MAX_MESSAGE_BYTES,
            "dropped ones are free"
        );
        assert_eq!(
            session.applied(warning("invalid_candidate", "m".into())),
            vec![SessionEvent::Warning {
                code: WarningCode::InvalidCandidate,
                message: "m".into(),
                reason: None,
                status: None,
            }],
            "another code passes"
        );
        assert_eq!(
            session.warned,
            [WarningCode::AvSyncLost, WarningCode::InvalidCandidate]
        );
        let lines = captured.lines("repeated a warning");
        assert_eq!(lines.len(), 1, "logged once: {lines:?}");
        assert!(
            lines[0].contains(r#"stream.id=front code="av_sync_lost""#),
            "{lines:?}"
        );
    }

    #[test]
    fn every_connection_error_is_a_closed_code() {
        let errors = [
            ConnectionError::WorkerCrashed,
            ConnectionError::Source(SourceError::Unreachable("x".into())),
            ConnectionError::Source(SourceError::AuthFailed("x".into())),
            ConnectionError::Source(SourceError::Timeout("x".into())),
            ConnectionError::Source(SourceError::Protocol("x".into())),
            ConnectionError::Source(SourceError::Ended("x".into())),
        ];
        for error in errors {
            // The `closed` code is the one `last_error` reports.
            assert_eq!(close_code(&error).as_str(), error.code());
            assert_eq!(
                closed_event(error.code(), "m"),
                SessionEvent::Closed {
                    code: close_code(&error),
                    message: "m".into()
                }
            );
        }
    }

    #[test]
    fn a_close_never_echoes_an_unknown_code_and_its_message_is_plain() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        assert_eq!(
            session.applied(WorkerSessionEvent::Closed {
                code: "\u{1b}[31mforged".into(),
                message: format!("x\u{1b}\r\n{}", "y".repeat(1000)),
            }),
            vec![SessionEvent::Closed {
                code: CloseCode::InternalError,
                message: format!(
                    "x\u{fffd}  {}{CUT_MARK}",
                    "y".repeat(MAX_MESSAGE_BYTES - 6 - CUT_MARK.len())
                ),
            }]
        );
        let lines = captured.lines("unknown code");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("code=\"\u{fffd}[31mforged\""),
            "logged, plain and escaped: {lines:?}"
        );
        assert_eq!(
            closed_event("invalid_sdp", &"z".repeat(1000)),
            SessionEvent::Closed {
                code: CloseCode::InvalidSdp,
                message: format!(
                    "{}{CUT_MARK}",
                    "z".repeat(MAX_MESSAGE_BYTES - CUT_MARK.len())
                ),
            }
        );
    }

    fn candidate(line: &str, mid: Option<&str>) -> SessionEvent {
        SessionEvent::Candidate {
            candidate: line.into(),
            sdp_mid: mid.map(str::to_owned),
            sdp_mline_index: mid.map(|_| 0),
        }
    }

    fn end() -> WorkerSessionEvent {
        WorkerSessionEvent::Candidate {
            candidate: String::new(),
            mid: None,
        }
    }

    #[test]
    fn srflx_waits_for_the_answer_and_end_of_candidates_for_the_gathers_rfc_8838_13() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        session.gathering(3);
        // Gathered before the answer: held, then after it, with its mid.
        assert_eq!(session.gathered(Some("candidate:s0".into())), vec![]);
        assert_eq!(session.gathered(None), vec![]);
        let answered = session.applied(WorkerSessionEvent::Answer {
            sdp: "v=0\r\nm=audio 9\r\na=mid:0\r\nm=video 9\r\na=mid:1\r\n".into(),
            talkback: None,
        });
        assert_eq!(answered.len(), 2);
        assert_eq!(answered[1], candidate("candidate:s0", Some("0")));
        // The worker is done, one gather is not: end-of-candidates waits.
        assert_eq!(session.applied(end()), vec![]);
        assert_eq!(
            session.gathered(Some("candidate:s2".into())),
            vec![candidate("candidate:s2", Some("0")), candidate("", None)]
        );
        // Nothing after end-of-candidates, not even a second one.
        assert_eq!(session.gathered(Some("late".into())), vec![]);
        assert_eq!(session.gather_deadline(), vec![]);
        assert_eq!(session.applied(end()), vec![]);

        // The deadline releases end-of-candidates when a gather hangs.
        let (tx, _rx) = mpsc::channel(8);
        let mut slow = entry(tx);
        slow.gathering(1);
        assert_eq!(
            slow.applied(WorkerSessionEvent::Answer {
                sdp: "v=0".into(),
                talkback: None
            })
            .len(),
            1
        );
        assert_eq!(slow.applied(end()), vec![]);
        assert_eq!(slow.gather_deadline(), vec![candidate("", None)]);
        assert_eq!(slow.gathered(Some("late".into())), vec![]);
        // Before the worker is done, the deadline changes nothing yet; an
        // answer without a mid gives candidates without one.
        let (tx, _rx) = mpsc::channel(8);
        let mut early = entry(tx);
        early.gathering(1);
        assert_eq!(early.gather_deadline(), vec![]);
        early.applied(WorkerSessionEvent::Answer {
            sdp: "v=0".into(),
            talkback: None,
        });
        assert_eq!(early.gathered(Some("c".into())), vec![candidate("c", None)]);
        // Without gathers the worker's end-of-candidates passes at once.
        assert_eq!(early.applied(end()), vec![candidate("", None)]);
    }

    #[test]
    fn a_relay_gather_ends_with_the_workers_line_and_channels_are_asked_once_rfc_8656_12() {
        let captured = Captured::default();
        let _logs = captured.install();
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        session.gathering(2);
        let relayed: SocketAddr = "203.0.113.1:49153".parse().unwrap();
        let other: SocketAddr = "203.0.113.1:49154".parse().unwrap();
        session.relay_handed_over(Lease::detached(relayed));
        session.relay_handed_over(Lease::detached(other));
        session.applied(WorkerSessionEvent::Answer {
            sdp: "v=0\r\na=mid:0\r\n".into(),
            talkback: None,
        });
        assert_eq!(session.applied(end()), vec![]);
        assert!(!session.candidates_done());
        // A report for a relay never handed over changes nothing.
        let stray = WorkerSessionEvent::Relayed {
            relayed: "203.0.113.9:1".parse().unwrap(),
            candidate: Some("stray".into()),
        };
        assert_eq!(session.applied(stray), vec![]);
        assert_eq!(
            session.applied(WorkerSessionEvent::Relayed {
                relayed,
                candidate: Some("candidate:r1".into())
            }),
            vec![candidate("candidate:r1", Some("0"))]
        );
        // Once only: a second report for it is a stray one.
        let again = WorkerSessionEvent::Relayed {
            relayed,
            candidate: Some("again".into()),
        };
        assert_eq!(session.applied(again), vec![]);
        // Not taken by the engine: the gather ends without a line.
        assert_eq!(
            session.applied(WorkerSessionEvent::Relayed {
                relayed: other,
                candidate: None
            }),
            vec![candidate("", None)]
        );
        assert!(session.candidates_done());

        // Channels: per relay and peer once, canonical, on relays the
        // session holds, at most MAX_RELAY_CHANNELS.
        let want = |relayed, peer: &str| WorkerSessionEvent::ChannelWanted {
            relayed,
            peer: peer.parse().unwrap(),
        };
        assert_eq!(
            session.applied(want(relayed, "[::ffff:192.0.2.9]:5000")),
            vec![]
        );
        session.applied(want(relayed, "192.0.2.9:5000"));
        session.applied(want(other, "192.0.2.9:5000"));
        session.applied(want("203.0.113.9:1".parse().unwrap(), "192.0.2.9:5000"));
        let requests = session.take_channel_requests();
        let asked: Vec<(SocketAddr, SocketAddr)> =
            requests.iter().map(|r| (r.relayed, r.peer)).collect();
        let peer: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        assert_eq!(asked, [(relayed, peer), (other, peer)]);
        assert_eq!(requests[0].lease.relayed(), relayed);
        assert!(session.take_channel_requests().is_empty());
        for port in 0..20 {
            session.applied(want(relayed, &format!("192.0.2.10:{port}")));
        }
        assert_eq!(
            session.take_channel_requests().len(),
            MAX_RELAY_CHANNELS - 2
        );
        // Six refused, one line.
        let refused = captured.lines("relay channel limit reached");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(session.channels_refused, 6);
    }

    /// Regression for SUP-30: a worker repeating a state, or naming only
    /// unknown ones, made one `state` event per report, which filled the
    /// client's queue with diagnostics until its next signaling frame
    /// overflowed it. The API sends `state` when ICE or DTLS changed.
    #[test]
    fn a_worker_repeating_its_state_reports_no_event() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        let state = |ice: &str, dtls: &str| WorkerSessionEvent::State {
            ice: ice.into(),
            dtls: dtls.into(),
        };
        assert_eq!(
            session.applied(state("new", "new")),
            vec![],
            "the state a session starts in is no change"
        );
        assert_eq!(
            session.applied(state("checking", "new")),
            vec![SessionEvent::State {
                ice: "checking".into(),
                dtls: "new".into()
            }]
        );
        for _ in 0..1_000 {
            assert_eq!(session.applied(state("checking", "new")), vec![]);
            assert_eq!(session.applied(state("made-up", "bogus")), vec![]);
        }
        assert_eq!(
            session.applied(state("checking", "connecting")),
            vec![SessionEvent::State {
                ice: "checking".into(),
                dtls: "connecting".into()
            }]
        );
    }

    #[test]
    fn state_is_a_diagnostic_and_the_rest_is_signaling() {
        let state = api_event(&SessionEvent::State {
            ice: "new".into(),
            dtls: "new".into(),
        });
        assert_eq!(state.class, EventClass::Diagnostic);
        assert_eq!(
            state.payload,
            json!({ "type": "state", "ice": "new", "dtls": "new" })
        );
        let answer = api_event(&SessionEvent::Answer { sdp: "v=0".into() });
        assert_eq!(answer.class, EventClass::Signaling);
    }

    #[tokio::test]
    async fn an_orphan_buffers_then_the_adopter_gets_state_buffer_and_live_events() {
        let (tx, mut first) = mpsc::channel(8);
        let mut session = entry(tx);
        assert!(session.owned_by(ConnectionId(1), 7));
        assert!(!session.owned_by(ConnectionId(1), 8));
        assert!(session.owned_by_connection(ConnectionId(1)));
        assert!(session.is_owned());
        session.deliver("s1", api_event(&SessionEvent::Answer { sdp: "a".into() }));
        assert_eq!(first.recv().await.unwrap().payload["type"], "answer");

        let epoch = session.orphan();
        assert_eq!(epoch, session.orphan_epoch());
        assert!(
            !session.is_owned()
                && session
                    .dto("s1", false, lotse_ipc::TalkbackStats::default())
                    .orphaned
        );
        for n in 0..ORPHAN_BUFFER + 2 {
            session.deliver(
                "s1",
                api_event(&SessionEvent::Warning {
                    code: WarningCode::AvSyncLost,
                    message: n.to_string(),
                    reason: None,
                    status: None,
                }),
            );
        }
        let mut adopted = session.adopt(ConnectionId(2), 3);
        assert!(session.owned_by(ConnectionId(2), 3));
        let snapshot = adopted.recv().await.unwrap();
        assert_eq!(
            snapshot.payload,
            json!({ "type": "state", "ice": "new", "dtls": "new" })
        );
        let oldest = adopted.recv().await.unwrap();
        assert_eq!(
            oldest.payload["message"], "2",
            "the two oldest were dropped"
        );
        for _ in 1..ORPHAN_BUFFER {
            adopted.recv().await.unwrap();
        }
        session.deliver(
            "s1",
            api_event(&SessionEvent::Answer { sdp: "live".into() }),
        );
        assert_eq!(adopted.recv().await.unwrap().payload["sdp"], "live");
        // A second orphaning moves the epoch, so the first timer is stale.
        assert!(session.orphan() > epoch);
    }

    /// Regression for SUP-30: an orphan buffered a worker's `state` events
    /// with its signaling, so a worker flapping its state pushed the
    /// buffered answer out before the client could adopt the session.
    #[tokio::test]
    async fn an_orphan_keeps_its_signaling_and_leaves_the_state_to_the_adopter_s_snapshot() {
        let (tx, _first) = mpsc::channel(8);
        let mut session = entry(tx);
        let _epoch = session.orphan();
        session.deliver("s1", api_event(&SessionEvent::Answer { sdp: "a".into() }));
        for ice in ICE_STATES.iter().cycle().take(ORPHAN_BUFFER * 4) {
            session.deliver(
                "s1",
                api_event(&SessionEvent::State {
                    ice: (*ice).to_owned(),
                    dtls: "connected".into(),
                }),
            );
        }
        let mut adopted = session.adopt(ConnectionId(2), 3);
        assert_eq!(adopted.recv().await.unwrap().payload["type"], "state");
        assert_eq!(
            adopted.recv().await.unwrap().payload,
            json!({ "type": "answer", "sdp": "a" })
        );
        assert!(adopted.try_recv().is_err(), "no state was buffered");
    }

    /// Regression for SUP-30: the adoption's `state` snapshot was a
    /// diagnostic, so the outbox, which keeps one diagnostic per
    /// subscription, let a live state replace it behind the buffered
    /// events, and the adopter's first event was not the snapshot.
    #[tokio::test]
    async fn the_adoption_snapshot_is_signaling_and_the_live_states_after_it_diagnostics() {
        let (tx, _first) = mpsc::channel(8);
        let mut session = entry(tx);
        let _epoch = session.orphan();
        session.deliver("s1", api_event(&SessionEvent::Answer { sdp: "a".into() }));
        let mut adopted = session.adopt(ConnectionId(2), 3);
        let report = WorkerSessionEvent::State {
            ice: "connected".into(),
            dtls: "new".into(),
        };
        for event in session.applied(report) {
            session.deliver("s1", api_event(&event));
        }
        let mut got = Vec::new();
        while let Ok(event) = adopted.try_recv() {
            got.push((event.class, event.payload));
        }
        assert_eq!(
            got,
            [
                (
                    EventClass::Signaling,
                    json!({ "type": "state", "ice": "new", "dtls": "new" })
                ),
                (
                    EventClass::Signaling,
                    json!({ "type": "answer", "sdp": "a" })
                ),
                (
                    EventClass::Diagnostic,
                    json!({ "type": "state", "ice": "connected", "dtls": "new" })
                ),
            ]
        );
    }

    /// Regression for SUP-30: every event a full subscription dropped was
    /// a `warn` line, so a worker reporting faster than the client reads
    /// grew the log at its own rate.
    #[tokio::test]
    async fn a_full_subscription_logs_its_drops_once_per_interval() {
        let captured = Captured::default();
        let _logs = captured.install();
        let clock = Arc::new(FakeClock::from_system());
        let (tx, _rx) = mpsc::channel(1);
        let mut session = entry_on(tx, clock.clone());
        let answer = |sdp: &str| api_event(&SessionEvent::Answer { sdp: sdp.into() });
        session.deliver("s1", answer("queued"));
        for _ in 0..3 {
            session.deliver("s1", answer("dropped"));
        }
        let lines = captured.lines("session subscription full");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("count=1"), "{lines:?}");
        clock.advance(SUMMARY_INTERVAL);
        session.deliver("s1", answer("dropped"));
        let lines = captured.lines("session subscription full");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains("count=3"), "{lines:?}");
    }

    #[tokio::test]
    async fn a_full_or_gone_subscription_drops_rather_than_blocks() {
        let (tx, rx) = mpsc::channel(1);
        let mut session = entry(tx);
        session.deliver("s1", api_event(&SessionEvent::Answer { sdp: "1".into() }));
        session.deliver("s1", api_event(&SessionEvent::Answer { sdp: "2".into() }));
        drop(rx);
        session.deliver("s1", api_event(&SessionEvent::Answer { sdp: "3".into() }));
        assert!(
            session.is_owned(),
            "the connection's close orphans it, not a drop"
        );
    }
}
