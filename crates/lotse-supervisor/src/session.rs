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
//! end-of-candidates (RFC 8838 §13), one warning per code, messages cut to
//! [`MAX_MESSAGE_BYTES`], and [`MAX_REPORT_TEXT_BYTES`] of text besides
//! the answer over the session's life. A report over the budget closes the
//! session; a repeated warning is dropped.
//!
//! A session holds a lease on the TURN allocation behind each of its relay
//! candidates, and the channels its worker asked for on them, at most
//! [`MAX_RELAY_CHANNELS`] (RFC 8656 §12); dropping the session releases
//! them.
//!
//! What a worker reports is logged within bounds too: a dropped warning
//! and a refused channel once per session, each (ICE, DTLS) state pair
//! at most once per [`SUMMARY_INTERVAL`](lotse_core::throttle::SUMMARY_INTERVAL).
//!
//! Also the identifiers the supervisor chooses: the session's ULID when the
//! client passes none, and the ICE credentials the demux verifies (RFC 8839 §5.4).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lotse_api::{ConnectionId, Event, EventClass};
use lotse_api_types::session::{Session, SessionEvent};
use lotse_api_types::time::rfc3339;
use lotse_core::text::plain;
use lotse_core::throttle::Throttle;
use lotse_ipc::SessionEvent as WorkerSessionEvent;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::net::turn_client::Lease;
use crate::worker_text::{MAX_MESSAGE_BYTES, MAX_NAME_BYTES};

/// Events a session subscription holds before the server's forwarder
/// drains them; signaling is a handful of events, so a full queue means
/// the control connection is not being read.
pub(crate) const SESSION_QUEUE: usize = 128;

/// Events kept for an orphaned session.
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

/// A session without an answer this long after its offer closes with
/// `source_not_live`: the source declared no tracks.
pub(crate) const SOURCE_NOT_LIVE_AFTER: Duration = Duration::from_secs(10);

/// The `closed` codes of the API; anything else a worker reports is an
/// `internal_error`.
const CLOSED_CODES: [&str; 12] = [
    "peer_closed",
    "session_closed",
    "stream_deleted",
    "stream_changed",
    "worker_crashed",
    "source_not_live",
    "ice_failed",
    "invalid_sdp",
    "no_video_track",
    "video_codec_unsupported",
    "shutting_down",
    "internal_error",
];

/// The `warning` codes of the API; a worker's other warnings are dropped.
const WARNING_CODES: [&str; 7] = [
    "audio_codec_unsupported",
    "turn_unsupported",
    "backchannel_busy",
    "av_sync_lost",
    "h264_profile_mismatch",
    "invalid_candidate",
    "frame_over_browser_limit",
];

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
    /// Events kept while orphaned, oldest first.
    buffer: VecDeque<Event>,
    /// Counts orphanings, so a grace timer only expires its own.
    orphan_epoch: u64,
    /// The ICE state.
    ice: &'static str,
    /// The DTLS state.
    dtls: &'static str,
    /// The answer went out.
    pub(crate) answered: bool,
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
    warned: Vec<&'static str>,
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
    /// Channels the worker asked for that are still to bind.
    channel_requests: Vec<ChannelRequest>,
    /// When the offer arrived.
    since: SystemTime,
    /// Its one-shot timers (`source_not_live`, the gather deadline, grace),
    /// aborted when the entry is dropped: no timer task outlives its
    /// session.
    timers: Vec<AbortHandle>,
}

impl Drop for SessionEntry {
    fn drop(&mut self) {
        for timer in &self.timers {
            timer.abort();
        }
    }
}

impl SessionEntry {
    /// A session owned by `connection`'s subscription `subscription`.
    pub(crate) fn new(
        serial: u64,
        stream_id: String,
        connection: String,
        ufrag: String,
        owner: (ConnectionId, u64, mpsc::Sender<Event>),
        since: SystemTime,
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
            remote_candidates: 0,
            gathers: 0,
            worker_done: false,
            candidates_done: false,
            worker_candidates: 0,
            report_bytes: 0,
            warned: Vec::new(),
            warnings_dropped: 0,
            held: Vec::new(),
            mid: None,
            relays: Vec::new(),
            channels: HashSet::new(),
            channels_refused: 0,
            state_lines: HashMap::new(),
            channel_requests: Vec::new(),
            since,
            timers: Vec::new(),
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
    /// about to be disconnected for it.
    pub(crate) fn deliver(&mut self, session_id: &str, event: Event) {
        if let Some(owner) = &self.owner {
            match owner.events.try_send(event) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(event)) => {
                    tracing::warn!(session.id = session_id, event = ?event.payload.get("type"), "session subscription full; event dropped");
                }
                // The forwarder ended; the connection's close orphans the
                // session next.
                Err(mpsc::error::TrySendError::Closed(event)) => {
                    tracing::debug!(session.id = session_id, event = ?event.payload.get("type"), "session subscription gone; event dropped");
                }
            }
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
        let snapshot = api_event(&SessionEvent::State {
            ice: self.ice.to_owned(),
            dtls: self.dtls.to_owned(),
        });
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
            WorkerSessionEvent::Answer { sdp } => {
                if self.answered {
                    return Err("a second answer");
                }
                self.answered = true;
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
                if let Some(ice) = known(&ICE_STATES, &ice) {
                    self.ice = ice;
                }
                if let Some(dtls) = known(&DTLS_STATES, &dtls) {
                    self.dtls = dtls;
                }
                Ok(vec![SessionEvent::State {
                    ice: self.ice.to_owned(),
                    dtls: self.dtls.to_owned(),
                }])
            }
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
    /// [`plain`]; a repeated or unknown one is dropped.
    fn warning(&mut self, code: &str, message: &str) -> Result<Vec<SessionEvent>, &'static str> {
        let fresh = WARNING_CODES
            .iter()
            .find(|known| **known == code && !self.warned.contains(known));
        let Some(&code) = fresh else {
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
            code: code.to_owned(),
            message,
        }])
    }

    /// The session as `session/get` returns it.
    pub(crate) fn dto(&self, session_id: &str) -> Session {
        Session {
            session_id: session_id.to_owned(),
            stream_id: self.stream_id.clone(),
            ice: self.ice.to_owned(),
            dtls: self.dtls.to_owned(),
            answered: self.answered,
            orphaned: self.owner.is_none(),
            since: rfc3339(self.since),
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

/// A worker's `closed` event, its message made [`plain`]; an unknown code
/// is an `internal_error`, logged and not passed on.
fn closed_event(code: &str, message: &str) -> SessionEvent {
    let message = plain(message, MAX_MESSAGE_BYTES);
    let code = CLOSED_CODES
        .iter()
        .find(|known| **known == code)
        .copied()
        .unwrap_or_else(|| {
            tracing::warn!(
                code = ?plain(code, MAX_NAME_BYTES),
                "a worker closed a session with an unknown code; internal_error"
            );
            "internal_error"
        });
    SessionEvent::Closed {
        code: code.to_owned(),
        message,
    }
}

/// A session event as the server queues it: `state` is a diagnostic the
/// outbox may shed, everything else is signaling and never dropped.
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

    use lotse_core::clock::{Clock as _, SystemClock};
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
        SessionEntry::new(
            1,
            "front".into(),
            "c1".into(),
            "ufrag".into(),
            (ConnectionId(1), 7, events),
            UNIX_EPOCH,
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

    #[test]
    fn worker_reports_map_onto_known_events_only() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        assert!(!session.answered);
        assert_eq!(
            session.applied(WorkerSessionEvent::Answer { sdp: "v=0".into() }),
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
                message: "m".into()
            }),
            vec![SessionEvent::Warning {
                code: "h264_profile_mismatch".into(),
                message: "m".into()
            }]
        );
        assert_eq!(
            session.applied(WorkerSessionEvent::Warning {
                code: "rm -rf".into(),
                message: "m".into()
            }),
            vec![]
        );
        assert_eq!(
            session.applied(WorkerSessionEvent::Closed {
                code: "ice_failed".into(),
                message: "m".into()
            }),
            vec![SessionEvent::Closed {
                code: "ice_failed".into(),
                message: "m".into()
            }]
        );
        assert_eq!(
            closed_event("bogus", "m"),
            SessionEvent::Closed {
                code: "internal_error".into(),
                message: "m".into()
            }
        );
        let dto = session.dto("s1");
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
    }

    #[test]
    fn a_worker_answers_once_and_a_second_answer_closes_the_session() {
        let (tx, _rx) = mpsc::channel(8);
        let mut session = entry(tx);
        session.applied(WorkerSessionEvent::Answer {
            sdp: "v=0\r\na=mid:0\r\n".into(),
        });
        assert_eq!(
            session.apply(WorkerSessionEvent::Answer {
                sdp: "v=0\r\na=mid:1\r\n".into()
            }),
            Err("a second answer")
        );
        assert_eq!(session.mid.as_deref(), Some("0"), "nothing changed");
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
                message: "m".into()
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
                code: "av_sync_lost".into(),
                message: format!("a b{}", "x".repeat(MAX_MESSAGE_BYTES - 3)),
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
        assert_eq!(
            session.report_bytes, MAX_MESSAGE_BYTES,
            "dropped ones are free"
        );
        assert_eq!(
            session.applied(warning("invalid_candidate", "m".into())),
            vec![SessionEvent::Warning {
                code: "invalid_candidate".into(),
                message: "m".into(),
            }],
            "another code passes"
        );
        assert_eq!(session.warned, ["av_sync_lost", "invalid_candidate"]);
        let lines = captured.lines("repeated a warning");
        assert_eq!(lines.len(), 1, "logged once: {lines:?}");
        assert!(
            lines[0].contains(r#"stream.id=front code="av_sync_lost""#),
            "{lines:?}"
        );
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
                code: "internal_error".into(),
                message: format!("x\u{fffd}  {}", "y".repeat(MAX_MESSAGE_BYTES - 6)),
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
                code: "invalid_sdp".into(),
                message: "z".repeat(MAX_MESSAGE_BYTES),
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
            slow.applied(WorkerSessionEvent::Answer { sdp: "v=0".into() })
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
        early.applied(WorkerSessionEvent::Answer { sdp: "v=0".into() });
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
        assert!(!session.is_owned() && session.dto("s1").orphaned);
        for n in 0..ORPHAN_BUFFER + 2 {
            session.deliver(
                "s1",
                api_event(&SessionEvent::Warning {
                    code: "av_sync_lost".into(),
                    message: n.to_string(),
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
