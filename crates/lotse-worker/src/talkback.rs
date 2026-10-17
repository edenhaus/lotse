//! Talk-back in the worker: each session's uplink track, and the
//! connection's arbiter that lets one session at a time, the talker, reach
//! the backchannel.
//!
//! A connection has at most one backchannel and, at any time, at most one
//! talker. The worker holds every session that could talk to the camera,
//! so it arbitrates: one [`Arbiter`] per connection whose source protocol
//! can carry audio back, and one [`Talkback`] per session on it.
//!
//! - **Claim.** An offer that asks for talk-back the backchannel takes
//!   (`webrtc/offer` or `webrtc/renegotiate`, judged by the output's
//!   `talkback_request`) claims the channel for its session while nobody
//!   holds it ([`Claimant::claim`], [`ChangeReason::Claimed`]), before the
//!   engine answers, so the answer carries the outcome; first offer wins.
//!   The claim opens the device's backchannel session (the source's
//!   [`BackchannelOpener`](lotse_core::source::BackchannelOpener), RTSP's
//!   session of its own) and holds the answer until it is open, so the
//!   viewer sends nothing before the device takes it;
//!   [`BACKCHANNEL_OPEN_LIMIT`] bounds the wait. A claim that comes while
//!   the source probes the device waits for the probe. The claim opens
//!   the backchannel offered now only if it is the one its answer was
//!   negotiated with ([`Arbiter::target`]): one a probe replaced since
//!   with another codec would open a session the answer's talk-back
//!   cannot reach, so the claim is declined `refused` instead.
//! - **Declined.** An offer while another session holds it is answered
//!   without talk-back, and the session is told once per offer
//!   (`backchannel_declined`, `busy`); so is one whose backchannel session
//!   the device refused or did not open in time (`refused`, with the
//!   device's status), whose claim is not kept ([`ChangeReason::Refused`])
//!   and which nothing tries again: the user's next offer does. A packet
//!   from a session that does not hold the channel, declined or released,
//!   is dropped and counted.
//! - **Hold.** The talker keeps the channel, silent or muted, until its
//!   session closes ([`ChangeReason::SessionClosed`]; a deleted stream
//!   closes its sessions), its re-offer drops talk-back
//!   ([`Talkback::let_go`], [`ChangeReason::Renegotiated`]), the client
//!   releases it ([`Arbiter::release`], [`ChangeReason::Released`]): from
//!   whoever holds it, or only from the session the release names,
//!   decided against the claims under one lock; or no stream on the
//!   connection asks for the backchannel any more ([`Arbiter::ask`],
//!   [`ChangeReason::OptedOut`]). There is no timeout.
//!   Every release closes the device's backchannel session, one still
//!   opening included (its handshake abandoned). Free, the
//!   channel goes to the next offer that asks, from any session, the one
//!   that let go included.
//! - **Lost.** The device's backchannel session ending on its own while
//!   the talker holds it (its connection lost) releases the claim
//!   ([`ChangeReason::Refused`]), and the talker's session is told once
//!   (`backchannel_declined`, `refused`); its m-line stays as answered
//!   until it re-offers, and what it sends meanwhile is dropped and
//!   counted.
//! - **Reconnect.** The talker's backchannel session is its own: a
//!   reconnect of the source that plays the stream leaves it open, and
//!   the talker's re-offers negotiate with it ([`Arbiter::target`]),
//!   whatever the reconnect's probe offers since; the next claim opens
//!   what that probe offers, negotiated with it.
//! - **Opt-in and opt-out.** A stream that opts in has the source probe
//!   the device without restarting it, and an offer meanwhile waits for
//!   the probe; the last opt-out withdraws the offer and frees the channel
//!   from its talker ([`Arbiter::ask`]).
//!
//! The talker's route to the device starts on its uplink track before its
//! first packet is published, so nothing is missed: the reverse
//! chain (the binary's [`UplinkFactory`] transcoder, framed as the
//! [`BackchannelSession`] asks) when it converts the uplink to the device's
//! codec (any G.711 device), or the track's live path as it is for the
//! device's own codec otherwise (Opus to an Opus device). A forwarder task
//! puts each packet into the handle's sender without waiting; a full or
//! closed queue drops it. Every change of the talker is logged and sent as
//! a [`TalkerChanged`] event, under the lock that decided it, so the events
//! come in the order of the changes; the supervisor gets them through a
//! [`TalkerFeed`], which resynchronizes from the arbiter when it falls
//! behind.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lotse_core::clock::Clock;
use lotse_core::codec::Codec;
use lotse_core::media::MediaPacket;
use lotse_core::session::TalkbackTarget;
use lotse_core::source::{
    BACKCHANNEL_OPEN_LIMIT, BackchannelOffer, BackchannelRefused, BackchannelSession,
    BackchannelSlot,
};
use lotse_core::task::spawn_named;
use lotse_core::track::{Track, TrackEvent, TrackSubscription, Unit};
use lotse_core::transcode::{TrackHandle, TranscodeError, UplinkFactory};
use lotse_core::uplink::{UPLINK_TRACK, UplinkCodec, UplinkPacket, UplinkTrack};
use lotse_ipc::TalkerChange;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

/// How many talker changes a slow subscriber may fall behind by. Changes
/// come at human pace; one that lags skips the oldest, and a
/// [`TalkerFeed`] then resynchronizes from the arbiter's talker.
const EVENT_CAPACITY: usize = 16;

/// Why the talker changed: the `reason` of the talker-changed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangeReason {
    /// A session's offer asked for talk-back while nobody held the
    /// channel.
    Claimed,
    /// The talker's session closed.
    SessionClosed,
    /// The client released the channel (`backchannel/release`).
    Released,
    /// The talker's re-offer dropped talk-back (`webrtc/renegotiate`).
    Renegotiated,
    /// The device refused the talker's backchannel session, it did not
    /// open in time, or it ended on the device's side while held.
    Refused,
    /// No stream on the connection asks for the backchannel any more.
    OptedOut,
}

impl ChangeReason {
    /// The API name.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::SessionClosed => "session_closed",
            Self::Released => "released",
            Self::Renegotiated => "renegotiated",
            Self::Refused => "refused",
            Self::OptedOut => "opted_out",
        }
    }
}

/// A change of the connection's talker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TalkerChanged {
    /// The session it concerns: the new talker for
    /// [`ChangeReason::Claimed`], the one that let go otherwise (the
    /// channel is free then).
    pub(crate) session: String,
    /// Its claim: the new one, or the one that ended. A session that
    /// claims again gets another, so it tells two spells of one session
    /// apart.
    pub(crate) claim: u64,
    /// Why.
    pub(crate) reason: ChangeReason,
    /// When, on the wall clock: a claim's is the talker's `since`.
    pub(crate) at: SystemTime,
}

/// One session's talk-back counters: what it received, what it sent the
/// device and what it lost on the way. Shared with the forwarder of its
/// route, and with the session manager, which reports them
/// (`session/get`'s `backchannel`).
#[derive(Debug, Default)]
pub(crate) struct TalkbackStats {
    /// An answer of the session negotiated talk-back, its offer's or a
    /// re-offer's: only such a session is reported, and it stays reported
    /// once a re-offer drops talk-back, so its counters never go back.
    pub(crate) ever_negotiated: AtomicBool,
    /// Talk-back packets the engine took (`SessionStats::uplink_packets`,
    /// `session/get`'s `packets_received`).
    pub(crate) packets_received: AtomicU64,
    /// Packets dropped because the session did not hold the channel: its
    /// offer was declined, or it let go or was released since
    /// (`session/get`'s `packets_dropped_busy`).
    pub(crate) packets_dropped_busy: AtomicU64,
    /// Packets of the talker dropped on the way: no route to its codec,
    /// or its backchannel session's queue full or closed.
    pub(crate) packets_dropped: AtomicU64,
    /// Packets handed to the backchannel, after any transcode.
    pub(crate) packets_sent: AtomicU64,
    /// Their payload bytes (`session/get`'s `bytes_sent`).
    pub(crate) bytes_sent: AtomicU64,
}

impl TalkbackStats {
    /// One more in `counter`.
    fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The counters as the supervisor gets them, all the session counted
    /// so far; `None` when no answer of the session negotiated talk-back.
    pub(crate) fn report(&self) -> Option<lotse_ipc::TalkbackStats> {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        self.ever_negotiated
            .load(Ordering::Relaxed)
            .then(|| lotse_ipc::TalkbackStats {
                packets_received: load(&self.packets_received),
                packets_dropped_busy: load(&self.packets_dropped_busy),
                bytes_sent: load(&self.bytes_sent),
            })
    }
}

/// A talker change as the supervisor gets it.
pub(crate) fn talker_change(change: TalkerChanged) -> TalkerChange {
    let at_ms = change.at.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    });
    TalkerChange {
        session_id: change.session,
        reason: change.reason.code().to_owned(),
        at_ms,
    }
}

/// The talker changes of one arbiter as the supervisor gets them: each
/// one in order while the receiver keeps up. Once it falls behind, the
/// changes it skipped and the ones still queued give way to the one change
/// from the talker the supervisor was last told of to the arbiter's talker
/// now ([`Arbiter::resync`]), so the supervisor never keeps a talker that
/// let go, nor misses one that holds the channel.
#[derive(Debug)]
pub(crate) struct TalkerFeed {
    /// The arbiter, for a resynchronization; not kept alive by the feed,
    /// which ends with it.
    arbiter: Weak<Arbiter>,
    /// Its changes.
    events: broadcast::Receiver<TalkerChanged>,
    /// The claim the supervisor was last told of, while it holds; `None`
    /// once told the channel is free.
    told: Option<TalkerChanged>,
}

impl TalkerFeed {
    /// The changes of `arbiter` from now on.
    pub(crate) fn new(arbiter: &Arc<Arbiter>) -> Self {
        Self {
            arbiter: Arc::downgrade(arbiter),
            events: arbiter.subscribe(),
            told: None,
        }
    }

    /// The next change for the supervisor; `None` once the arbiter is gone.
    pub(crate) async fn next(&mut self) -> Option<TalkerChanged> {
        loop {
            let change = match self.events.recv().await {
                Ok(change) => change,
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    let arbiter = self.arbiter.upgrade()?;
                    let Some(change) = arbiter.resync(&mut self.events, self.told.as_ref()) else {
                        tracing::warn!(
                            skipped,
                            "talk-back: talker changes skipped for the supervisor; it holds the talker there is now"
                        );
                        continue;
                    };
                    let (session, reason) = (change.session.as_str(), change.reason.code());
                    tracing::warn!(
                        skipped,
                        session,
                        reason,
                        "talk-back: talker changes skipped for the supervisor; resynchronized from the arbiter's talker"
                    );
                    change
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            };
            self.told = (change.reason == ChangeReason::Claimed).then(|| change.clone());
            return Some(change);
        }
    }
}

/// The connection's arbiter of its one backchannel. Shared by every
/// session on the connection; its lock is held only to decide, never
/// across an await.
#[derive(Debug)]
pub(crate) struct Arbiter {
    /// The slot the running source offers its backchannel in; replaced
    /// when the connection switches to another source.
    slot: Mutex<BackchannelSlot>,
    /// Builds the reverse chain; `None` routes only an uplink in the
    /// device's codec.
    uplink: Option<Arc<dyn UplinkFactory>>,
    /// Stamps the routes' tracks and the events.
    clock: Arc<dyn Clock>,
    /// The talker.
    state: Mutex<State>,
    /// Where talker changes go.
    events: broadcast::Sender<TalkerChanged>,
}

/// The arbiter's decided state.
#[derive(Debug, Default)]
struct State {
    /// The talker, if any.
    talker: Option<Talker>,
    /// The id the next claim gets, so a session that lost the channel
    /// never takes a later claim for its own.
    next_claim: u64,
    /// The last change, recorded and sent under the lock with the change
    /// itself, so it always describes how the talker came to be what it
    /// is: the talker's claim, or the release that freed the channel.
    last: Option<TalkerChanged>,
}

/// The session holding the channel.
#[derive(Debug)]
struct Talker {
    /// Its session id.
    session: String,
    /// Its claim.
    claim: u64,
    /// The device's backchannel session, once open; `None` while it opens.
    /// A task watches it for its loss ([`Arbiter::watch`]) until it ends,
    /// lost or closed.
    open: Option<BackchannelSession>,
    /// Where the loss of that session is reported to the talker's own.
    losses: mpsc::Sender<BackchannelRefused>,
    /// The way its packets reach the device, once built for the session.
    route: Option<Route>,
    /// Dropped with the talker: a claim whose session still opens stops
    /// waiting for it ([`Arbiter::claim`]) and abandons the handshake, so
    /// a release frees the device's backchannel as well as the channel.
    _abandon: oneshot::Sender<Infallible>,
}

/// Why a claim does not hold the channel: the `backchannel_declined`
/// warning its offer gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaimError {
    /// Another session holds it: this one.
    Busy(String),
    /// The device's backchannel session did not open, and why.
    Refused(BackchannelRefused),
}

/// A claim the arbiter granted and opened, until the session adopts it
/// ([`Talkback::adopt`]): dropped before that (the session closed while
/// its answer was held), it lets go of the channel as a closed session's
/// claim does.
#[derive(Debug)]
pub(crate) struct Claim {
    /// The arbiter.
    arbiter: Arc<Arbiter>,
    /// The session that claimed.
    session: String,
    /// The claim's number; taken by the adoption.
    id: Option<u64>,
}

impl Claim {
    /// The claim's number, for the session to keep; nothing is let go any
    /// more.
    fn adopt(mut self) -> Option<u64> {
        self.id.take()
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if let Some(claim) = self.id.take() {
            self.arbiter
                .let_go(&self.session, claim, ChangeReason::SessionClosed);
        }
    }
}

/// What the arbiter decided for one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// The sender is the talker and its route is up: publish it.
    Send,
    /// The sender is the talker, but nothing takes its codec to the
    /// device's.
    Unroutable,
    /// The sender does not hold the channel: this session does, or
    /// nobody (the sender's offer was declined, or it let go since).
    NotTalker(Option<String>),
}

/// Where a session's talk-back stands after its last packet; changes are
/// logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// It has not sent yet.
    Idle,
    /// Its packets go to the device.
    Talking,
    /// It is the talker, and its codec has no route.
    Unroutable,
    /// It does not hold the channel.
    Refused,
}

impl Arbiter {
    /// The arbiter of `slot`, building reverse chains with `uplink`.
    pub(crate) fn new(
        slot: BackchannelSlot,
        uplink: Option<Arc<dyn UplinkFactory>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let (events, _none_yet) = broadcast::channel(EVENT_CAPACITY);
        Self {
            slot: Mutex::new(slot),
            uplink,
            clock,
            state: Mutex::default(),
            events,
        }
    }

    /// The backchannel the running source's probe found, if any.
    pub(crate) fn offered(&self) -> Option<BackchannelOffer> {
        self.slot().current()
    }

    /// The slot the running source offers its backchannel in.
    fn slot(&self) -> BackchannelSlot {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether a claim waits for the running source's probe of the device
    /// ([`Arbiter::settled`]): it probes, and nothing was offered before.
    /// An offer a reconnect kept is claimed at once, so the claim's open
    /// has the whole [`BACKCHANNEL_OPEN_LIMIT`] even while the new probe
    /// waits for a connect permit.
    pub(crate) fn awaits_probe(&self) -> bool {
        let slot = self.slot();
        let awaits = slot.awaits_probe();
        if !awaits && slot.is_probing() {
            tracing::debug!(
                "talk-back: the source probes the camera again; a claim takes the backchannel offered before without waiting for it"
            );
        }
        awaits
    }

    /// Waits until the running source's probe is over, at most
    /// [`BACKCHANNEL_OPEN_LIMIT`]: a probe still running then counts as
    /// having found nothing new. Returns what is left of the limit, for
    /// the claim that follows, so the offer's answer waits no longer than
    /// the limit for both.
    pub(crate) async fn settled(&self) -> Duration {
        let slot = self.slot();
        let started = self.clock.now();
        tokio::select! {
            _settled = slot.settled() => {}
            () = self.clock.sleep(BACKCHANNEL_OPEN_LIMIT) => {
                let limit_ms = BACKCHANNEL_OPEN_LIMIT.as_millis();
                tracing::info!(limit_ms, "talk-back: the probe of the camera's backchannel is still running; the offer is decided on what it found before");
            }
        }
        let waited = self.clock.now().saturating_duration_since(started);
        BACKCHANNEL_OPEN_LIMIT.saturating_sub(waited)
    }

    /// The backchannel a session whose claim is `held` negotiates talk-back
    /// with, with the uplink codecs that reach it (each one
    /// [`Arbiter::reaches`] routes to its codec), and whether `held` holds
    /// the channel now, decided under one lock. The talker negotiates with
    /// the device's backchannel session it has open, in the codec and
    /// frame its route converts to ([`Arbiter::route`]), which a probe
    /// again or a switch to another source leaves open whatever it offers
    /// now: an answer in a codec only the new offer takes would be routed
    /// nowhere. Any other session negotiates with the backchannel the
    /// running source offers now, which its claim opens.
    pub(crate) fn target(&self, held: Option<u64>) -> (Option<TalkbackTarget>, bool) {
        let offered = self.offered();
        let guard = self.lock();
        let talker = guard
            .talker
            .as_ref()
            .filter(|talker| Some(talker.claim) == held);
        let holds = talker.is_some();
        // A session adopts its claim once the session opened, so the
        // talker it names has one.
        let open = talker
            .and_then(|talker| talker.open.as_ref())
            .map(|open| (open.codec.clone(), open.frame));
        drop(guard);
        if let Some((codec, _frame)) = &open {
            let (open, offered) = (
                codec.name(),
                offered.as_ref().map(|offer| offer.codec.name()),
            );
            tracing::debug!(
                open,
                offered,
                "talk-back: the talker negotiates with its open backchannel session, not with what the source offers now"
            );
        }
        let Some((codec, frame)) = open.or_else(|| offered.map(|offer| (offer.codec, offer.frame)))
        else {
            return (None, holds);
        };
        (Some(self.target_of(codec, frame)), holds)
    }

    /// The target of a backchannel taking `codec` in `frame`: the uplink
    /// codecs that reach it, each one [`Arbiter::reaches`] routes to it.
    fn target_of(&self, codec: Codec, frame: Duration) -> TalkbackTarget {
        let takes = UplinkCodec::ALL
            .into_iter()
            .filter(|from| self.reaches(*from, &codec, frame))
            .collect();
        TalkbackTarget { codec, takes }
    }

    /// Whether [`Arbiter::route`] finds a path for an uplink in `from` to
    /// a device taking `codec` in `frame`: the reverse chain installed
    /// derives the device's codec from it, or it is the device's own codec,
    /// forwarded as received. Without a reverse chain (`uplink` unset) only
    /// the latter.
    fn reaches(&self, from: UplinkCodec, codec: &Codec, frame: Duration) -> bool {
        let to = codec.family();
        from.family() == to
            || self
                .uplink
                .as_ref()
                .is_some_and(|uplink| uplink.transcoder(frame).derive(&from.codec(), to).is_some())
    }

    /// Arbitrates `slot` from now on: the connection switched to a source
    /// that offers its backchannel there. The talker keeps the channel and
    /// its backchannel session; claims from now on open the new source's.
    pub(crate) fn follow(&self, slot: BackchannelSlot) {
        tracing::info!("talk-back: following the new source's backchannel");
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = slot;
    }

    /// The talker changes from now on, for the supervisor
    /// ([`TalkerFeed`]).
    fn subscribe(&self) -> broadcast::Receiver<TalkerChanged> {
        self.events.subscribe()
    }

    /// The change that brings a supervisor told of `told` (the claim it
    /// holds, `None` when it was told the channel is free) to the talker
    /// now, after its `events` fell behind; `None` when it holds that
    /// talker already. Decided under the lock every change is sent under,
    /// so the changes still queued on `events`, which are older, are
    /// dropped, and every one after is newer. With a talker, it is that
    /// talker's claim. With the channel free, it is a release of the
    /// talker the supervisor holds, at the time and for the reason the
    /// channel was freed: the session that let go last may be one whose
    /// claim the supervisor never heard of.
    fn resync(
        &self,
        events: &mut broadcast::Receiver<TalkerChanged>,
        told: Option<&TalkerChanged>,
    ) -> Option<TalkerChanged> {
        let state = self.lock();
        while !matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed)
        ) {}
        let now = state.talker.as_ref().map(|talker| talker.claim);
        let last = state.last.clone();
        drop(state);
        if now == told.map(|told| told.claim) {
            return None;
        }
        if now.is_some() {
            return last;
        }
        told.zip(last).map(|(told, last)| TalkerChanged {
            session: told.session.clone(),
            claim: told.claim,
            ..last
        })
    }

    /// Claims the channel for `session`'s offer, whose answer is
    /// negotiated with `negotiated` ([`Arbiter::target`]), and opens the
    /// device's backchannel session for it: `Ok(None)` when `held`, its
    /// claim, holds the channel already, `Ok` with the new claim once the
    /// session is open, [`ClaimError::Busy`] with the holder's session id
    /// when another session holds it, and [`ClaimError::Refused`] when the
    /// session did not open (the device refused it, no backchannel is
    /// offered, the one offered now is not `negotiated`, or it took longer
    /// than `limit`, what is left of [`BACKCHANNEL_OPEN_LIMIT`] for the
    /// offer), the claim not kept. The claim is decided under the
    /// lock a release takes, and whether it is new with it: a release just
    /// before makes the next claim a new one. The channel is the
    /// claimant's while its session opens; a loss of the session later is
    /// reported on `losses`.
    pub(crate) async fn claim(
        self: &Arc<Self>,
        session: &str,
        held: Option<u64>,
        negotiated: Option<&TalkbackTarget>,
        limit: Duration,
        losses: mpsc::Sender<BackchannelRefused>,
    ) -> Result<Option<Claim>, ClaimError> {
        let Some((offer, id, abandoned)) = self.start_claim(session, held, negotiated, losses)?
        else {
            return Ok(None);
        };
        // Lets go if this future is dropped before the session adopts it.
        let claim = Claim {
            arbiter: Arc::clone(self),
            session: session.to_owned(),
            id: Some(id),
        };
        // A session open at once wins over a limit used up already. A
        // release meanwhile drops the open, which abandons the handshake
        // (RTSP: the camera's `TEARDOWN`, RFC 2326 §10.7, once it set the
        // session up).
        let opened = tokio::select! {
            biased;
            opened = offer.opener.open() => opened,
            _released = abandoned => return Err(Self::abandoned(claim, id)),
            () = self.clock.sleep(limit) => Err(BackchannelRefused {
                status: None,
                message: format!(
                    "the camera's backchannel session did not open within {} ms",
                    limit.as_millis()
                ),
            }),
        };
        self.opened(claim, id, opened)
    }

    /// The claim of [`Arbiter::claim`], decided under the lock: `None`
    /// when `held` holds the channel already, else the offer to open, the
    /// new claim, which holds the channel from now on, and what resolves
    /// once it no longer does (a release while its session opens).
    ///
    /// The offer is read again here, after the answer was negotiated with
    /// `negotiated`: a probe may have replaced it since. It is opened only
    /// while its target is `negotiated` (a probe again that found the same
    /// backchannel replaced it by an equal one), and the device's session
    /// then opens in that codec, since the opener refuses a session in
    /// another one. Else the claim is declined
    /// before it takes the channel: a session in another codec would
    /// receive nothing the answer lets the viewer send (an Opus session
    /// takes no PCMU), and the viewer's next offer negotiates with the
    /// backchannel offered then.
    fn start_claim(
        &self,
        session: &str,
        held: Option<u64>,
        negotiated: Option<&TalkbackTarget>,
        losses: mpsc::Sender<BackchannelRefused>,
    ) -> Result<Option<(BackchannelOffer, u64, oneshot::Receiver<Infallible>)>, ClaimError> {
        let offer = self.offered().map(|offer| {
            let target = self.target_of(offer.codec.clone(), offer.frame);
            (offer, target)
        });
        let mut guard = self.lock();
        let state = &mut *guard;
        if let Some(talker) = &state.talker {
            if Some(talker.claim) == held {
                return Ok(None);
            }
            return Err(ClaimError::Busy(talker.session.clone()));
        }
        let Some((offer, target)) = offer else {
            drop(guard);
            tracing::info!(
                session,
                "talk-back: the claim finds no backchannel offered now; declined"
            );
            return Err(ClaimError::Refused(BackchannelRefused {
                status: None,
                message: "the camera offers no backchannel now".to_owned(),
            }));
        };
        if negotiated != Some(&target) {
            drop(guard);
            let negotiated = negotiated.map(|negotiated| negotiated.codec.name());
            let offered = target.codec.name();
            tracing::info!(
                session,
                negotiated,
                offered,
                "talk-back: the backchannel offered now is not the one the answer was negotiated with; declined"
            );
            return Err(ClaimError::Refused(BackchannelRefused {
                status: None,
                message: format!(
                    "the camera's backchannel changed to {offered} while the offer was negotiated"
                ),
            }));
        }
        let id = state.next_claim;
        state.next_claim = id.wrapping_add(1);
        self.emit(&mut state.last, session, id, ChangeReason::Claimed);
        let (abandon, abandoned) = oneshot::channel();
        state.talker = Some(Talker {
            session: session.to_owned(),
            claim: id,
            open: None,
            losses,
            route: None,
            _abandon: abandon,
        });
        drop(guard);
        let reason = ChangeReason::Claimed.code();
        tracing::info!(
            session,
            claim = id,
            reason,
            "talk-back: backchannel claimed by the offer; opening the camera's backchannel session, the answer waits for it"
        );
        Ok(Some((offer, id, abandoned)))
    }

    /// The claim numbered `id` was released while its session opened: the
    /// open is dropped, which abandons the handshake and closes what the
    /// device set up, before the next claim opens one; the offer is
    /// declined.
    fn abandoned(mut claim: Claim, id: u64) -> ClaimError {
        // The release took the channel: nothing to let go.
        claim.id = None;
        tracing::info!(
            session = claim.session,
            claim = id,
            "talk-back: the backchannel was released while its session opened; the handshake is abandoned and the offer declined"
        );
        ClaimError::Refused(BackchannelRefused {
            status: None,
            message: "the backchannel was released while its session opened".to_owned(),
        })
    }

    /// The device's backchannel session for `claim`, numbered `id`, opened,
    /// or did not: held by the talker while `id` still holds the channel,
    /// else closed again; a session that did not open lets the claim go.
    fn opened(
        self: &Arc<Self>,
        mut claim: Claim,
        id: u64,
        opened: Result<BackchannelSession, BackchannelRefused>,
    ) -> Result<Option<Claim>, ClaimError> {
        let session = claim.session.clone();
        let session = session.as_str();
        let mut guard = self.lock();
        let state = &mut *guard;
        let why = match opened {
            Ok(mut opened) => {
                if let Some(talker) = state.talker.as_mut().filter(|talker| talker.claim == id) {
                    let lost = std::mem::replace(&mut opened.lost, oneshot::channel().1);
                    let _watch = spawn_named(
                        "talkback.lost",
                        Self::watch(Arc::downgrade(self), session.to_owned(), id, lost),
                    );
                    talker.open = Some(opened);
                    drop(guard);
                    tracing::info!(
                        session,
                        claim = id,
                        "talk-back: the camera's backchannel session is open; the answer goes out"
                    );
                    return Ok(Some(claim));
                }
                drop(guard);
                // Released as it opened, before this claim saw the
                // release: closed again at once.
                drop(opened);
                claim.id = None;
                tracing::info!(
                    session,
                    claim = id,
                    "talk-back: the backchannel was released while its session opened; closed again, the offer is declined"
                );
                return Err(ClaimError::Refused(BackchannelRefused {
                    status: None,
                    message: "the backchannel was released while its session opened".to_owned(),
                }));
            }
            Err(why) => why,
        };
        // Not kept: the channel is free again.
        let freed = state.talker.take_if(|talker| talker.claim == id);
        if freed.is_some() {
            self.emit(&mut state.last, session, id, ChangeReason::Refused);
        }
        drop(guard);
        drop(freed);
        claim.id = None;
        let (reason, status) = (ChangeReason::Refused.code(), why.status);
        tracing::warn!(
            session,
            claim = id,
            reason,
            status,
            error = %why,
            "talk-back: the camera's backchannel session did not open; the claim is not kept and the offer is declined"
        );
        Err(ClaimError::Refused(why))
    }

    /// Watches the talker's backchannel session of `claim` for its loss:
    /// the device ended it (a lost connection, a refused keepalive), or its
    /// source's task went away without saying why. A session the talker
    /// let go of first ends too, and its claim holds nothing any more, so
    /// [`Arbiter::lost`] changes nothing then.
    async fn watch(
        arbiter: Weak<Self>,
        session: String,
        claim: u64,
        lost: oneshot::Receiver<BackchannelRefused>,
    ) {
        let why = lost.await.unwrap_or_else(|_gone| BackchannelRefused {
            status: None,
            message: "the camera's backchannel session ended".to_owned(),
        });
        if let Some(arbiter) = arbiter.upgrade() {
            arbiter.lost(&session, claim, &why);
        }
    }

    /// The talker's backchannel session of `claim` ended on the device's
    /// side: the claim is released ([`ChangeReason::Refused`]) and the
    /// talker's session told why, once.
    fn lost(&self, session: &str, claim: u64, why: &BackchannelRefused) {
        let mut guard = self.lock();
        let state = &mut *guard;
        let Some(talker) = state.talker.take_if(|talker| talker.claim == claim) else {
            return;
        };
        self.emit(&mut state.last, session, claim, ChangeReason::Refused);
        drop(guard);
        let told = talker.losses.try_send(why.clone()).is_ok();
        let (reason, status) = (ChangeReason::Refused.code(), why.status);
        tracing::warn!(
            session,
            claim,
            reason,
            status,
            told,
            error = %why,
            "talk-back: the camera's backchannel session was lost while the talker held it; backchannel free, its packets are dropped until it offers again"
        );
    }

    /// Frees the channel (`backchannel/release`) from whoever holds it,
    /// or, given `only`, only if that session holds it: decided under the
    /// lock a claim takes, so a release that names a session that already
    /// let go never frees the channel a later claim took. Its route stops
    /// at once, its backchannel session closes (one still opening is
    /// abandoned), and the next offer that asks for talk-back claims it,
    /// the released session's included; that claim's session opens once
    /// the released one closed on the device. Returns the session that
    /// held it when it was freed.
    pub(crate) fn release(&self, only: Option<&str>) -> Option<String> {
        self.free(only, ChangeReason::Released)
    }

    /// The connection asks for the device's backchannel from now on
    /// (`asks`: a stream on it opted in), or no longer, as its slot then
    /// says ([`BackchannelSlot::ask`]); the running source follows without
    /// restarting. An opt-in has it probe the device, and an offer that
    /// asks for talk-back waits for the probe ([`Arbiter::settled`]). An
    /// opt-out withdraws the offer and frees the channel from its talker
    /// ([`ChangeReason::OptedOut`]), whose backchannel session closes.
    pub(crate) fn ask(&self, asks: bool) {
        if !self.slot().ask(asks) {
            tracing::debug!(
                asks,
                "talk-back: the connection's ask for the backchannel is unchanged"
            );
            return;
        }
        if asks {
            tracing::info!(
                reason = "a stream on the connection opted in",
                "talk-back: the source probes the camera's backchannel; offers that ask for talk-back wait for it"
            );
        } else {
            tracing::info!(
                reason = "no stream on the connection asks for the backchannel any more",
                "talk-back: backchannel withdrawn; its talker, if any, is released"
            );
            let _freed = self.free(None, ChangeReason::OptedOut);
        }
    }

    /// Frees the channel for `reason` from whoever holds it, or, given
    /// `only`, only if that session holds it ([`Arbiter::release`]).
    /// Returns the session that held it when it was freed.
    fn free(&self, only: Option<&str>, reason: ChangeReason) -> Option<String> {
        let mut guard = self.lock();
        let state = &mut *guard;
        let freed = state
            .talker
            .take_if(|talker| only.is_none_or(|session| talker.session == session));
        if let Some(talker) = &freed {
            self.emit(&mut state.last, &talker.session, talker.claim, reason);
        }
        let kept = state.talker.as_ref().map(|talker| talker.session.clone());
        drop(guard);
        let reason = reason.code();
        let Some(talker) = freed else {
            if let Some(talker) = kept {
                tracing::info!(
                    session = only,
                    talker,
                    reason,
                    "talk-back: release for a session that does not hold the backchannel; the talker keeps it"
                );
            } else {
                tracing::debug!(
                    session = only,
                    reason,
                    "talk-back: release with the backchannel free; nothing to do"
                );
            }
            return None;
        };
        let session = talker.session.as_str();
        tracing::info!(
            session,
            reason,
            "talk-back: backchannel released; the next offer that asks for talk-back claims it"
        );
        Some(talker.session)
    }

    /// `session` let go of the channel for `reason`: its session closed,
    /// or its re-offer dropped talk-back. The channel is free if `claim`
    /// still held it; nothing changes otherwise.
    fn let_go(&self, session: &str, claim: u64, reason: ChangeReason) {
        let mut guard = self.lock();
        let state = &mut *guard;
        // Its route stops on return, outside the lock.
        let Some(_freed) = state.talker.take_if(|talker| talker.claim == claim) else {
            return;
        };
        self.emit(&mut state.last, session, claim, reason);
        drop(guard);
        let reason = reason.code();
        tracing::info!(
            session,
            reason,
            "talk-back: the talker let go; backchannel free"
        );
    }

    /// Decides one packet of a session's uplink `track` in `codec`:
    /// refuses it unless the session holds the channel, and for the
    /// talker makes sure its route serves the track towards its open
    /// backchannel session. `claim` is the session's, cleared here once it no
    /// longer holds the channel.
    fn decide(
        &self,
        claim: &mut Option<u64>,
        track: &Arc<Track>,
        codec: UplinkCodec,
        counters: &Arc<TalkbackStats>,
    ) -> Verdict {
        let mut guard = self.lock();
        let holder = guard.talker.as_ref().map(|talker| talker.session.clone());
        // A session adopts its claim once the session opened, so the talker
        // it names has one.
        let Some(Talker {
            route,
            open: Some(open),
            ..
        }) = guard
            .talker
            .as_mut()
            .filter(|talker| claim.is_some() && Some(talker.claim) == *claim)
        else {
            *claim = None;
            return Verdict::NotTalker(holder);
        };
        if !route.as_ref().is_some_and(|route| route.serves(track)) {
            // The old route stops before the new one starts.
            *route = None;
            *route = Some(self.route(track, codec, open, counters));
        }
        let verdict = if route.as_ref().is_some_and(|route| route.path.is_some()) {
            Verdict::Send
        } else {
            Verdict::Unroutable
        };
        drop(guard);
        verdict
    }

    /// The route of `track`, in `from`, to the device through `handle`,
    /// its backchannel session: through the reverse chain when it converts
    /// to the device's codec, the track's live path as it is for the
    /// device's own codec otherwise, no path when neither works.
    fn route(
        &self,
        track: &Arc<Track>,
        from: UplinkCodec,
        handle: &BackchannelSession,
        stats: &Arc<TalkbackStats>,
    ) -> Route {
        let input = from.codec();
        let to = handle.codec.clone();
        let (from_name, to_name) = (from.name(), to.name());
        let chain = self.uplink.as_ref().and_then(|uplink| {
            let transcoder = uplink.transcoder(handle.frame);
            let derived = transcoder.derive(&input, to.family())?;
            Some((transcoder, derived))
        });
        let path = if let Some((transcoder, derived)) = chain {
            let started = derived
                .rtp_clock_rate()
                .ok_or_else(|| {
                    TranscodeError::Failed(format!("{} has no RTP clock rate", derived.name()))
                })
                .and_then(|clock_rate| {
                    let output = Track::new(
                        UPLINK_TRACK,
                        derived,
                        clock_rate,
                        track.limits(),
                        self.clock.now(),
                    );
                    transcoder.spawn(track.subscribe_frames(), &input, Arc::new(output))
                });
            match started {
                Ok(chain) => {
                    let (frame_ms, delay_ms) = (handle.frame.as_millis(), chain.delay.as_millis());
                    tracing::info!(
                        from = from_name,
                        to = to_name,
                        frame_ms,
                        delay_ms,
                        "talk-back route: through the reverse chain"
                    );
                    let packets = chain.track.subscribe(Unit::Packets);
                    Some(Path::new(Some(chain), packets, handle, stats))
                }
                Err(err) => {
                    tracing::warn!(
                        from = from_name,
                        to = to_name,
                        error = %err,
                        "talk-back route: the reverse chain did not start; the talker's packets are dropped"
                    );
                    None
                }
            }
        } else if from.family() == to.family() {
            tracing::info!(codec = to_name, "talk-back route: forwarded as received");
            Some(Path::new(
                None,
                track.subscribe(Unit::Packets),
                handle,
                stats,
            ))
        } else {
            tracing::warn!(
                from = from_name,
                to = to_name,
                "talk-back route: no transcoder takes the uplink to the backchannel's codec; the talker's packets are dropped"
            );
            None
        };
        Route {
            track: Arc::clone(track),
            path,
        }
    }

    /// Records `session`'s change of `claim` as the `last` of the state,
    /// whose lock the caller holds, and sends it to the subscribers; with
    /// none it goes nowhere.
    fn emit(
        &self,
        last: &mut Option<TalkerChanged>,
        session: &str,
        claim: u64,
        reason: ChangeReason,
    ) {
        let change = TalkerChanged {
            session: session.to_owned(),
            claim,
            reason,
            at: self.clock.wall_now(),
        };
        *last = Some(change.clone());
        let _subscribers = self.events.send(change);
    }

    /// The state, even after a panic elsewhere (which aborts the process
    /// anyway).
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The talker's way to the device, built for one uplink track towards
/// its backchannel session, which a claim keeps; another track (a codec
/// change) builds another.
#[derive(Debug)]
struct Route {
    /// The uplink track it reads.
    track: Arc<Track>,
    /// What carries the packets; `None` when nothing converts them.
    path: Option<Path>,
}

impl Route {
    /// Whether it serves `track`.
    fn serves(&self, track: &Arc<Track>) -> bool {
        Arc::ptr_eq(&self.track, track)
    }
}

/// The running part of a route: the chain, if any, and the forwarder.
/// Dropping it stops both at once, so a talker that loses the channel
/// sends nothing more, not even what its chain still held.
#[derive(Debug)]
struct Path {
    /// The reverse chain; dropping it stops the task, and its output track
    /// is closed here, by its owner.
    chain: Option<TrackHandle>,
    /// The forwarder task.
    forward: JoinHandle<()>,
}

impl Path {
    /// Starts forwarding `packets` to `handle`'s sender.
    fn new(
        chain: Option<TrackHandle>,
        packets: TrackSubscription,
        handle: &BackchannelSession,
        stats: &Arc<TalkbackStats>,
    ) -> Self {
        let forward = spawn_named(
            "talkback.forward",
            forward(packets, handle.sender.clone(), Arc::clone(stats)),
        );
        Self { chain, forward }
    }
}

impl Drop for Path {
    fn drop(&mut self) {
        self.forward.abort();
        if let Some(chain) = &self.chain {
            chain.track.close();
        }
    }
}

/// Puts each packet of `packets` into the backchannel's `sender` without
/// waiting, counting what it took and what it did not, until the track
/// closes or the route stops.
async fn forward(
    mut packets: TrackSubscription,
    sender: mpsc::Sender<MediaPacket>,
    stats: Arc<TalkbackStats>,
) {
    while let Some(event) = packets.next().await {
        let TrackEvent::Packet(packet) = event else {
            continue;
        };
        let bytes = u64::try_from(packet.payload.len()).unwrap_or(u64::MAX);
        match sender.try_send(Arc::unwrap_or_clone(packet)) {
            Ok(()) => {
                TalkbackStats::count(&stats.packets_sent);
                stats.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            Err(err) => {
                TalkbackStats::count(&stats.packets_dropped);
                tracing::trace!(error = %err, "talk-back packet dropped: the backchannel did not take it");
            }
        }
    }
}

/// One session's talk-back: its uplink track, its claim on the
/// connection's backchannel, its counters. The claim is made for an
/// offer ([`Claimant::claim`], then [`Talkback::adopt`]) and let go for a
/// re-offer ([`Talkback::let_go`]); dropped with the session, which frees
/// the channel if it held it.
#[derive(Debug)]
pub(crate) struct Talkback {
    /// The connection's arbiter.
    arbiter: Arc<Arbiter>,
    /// The session id.
    session: String,
    /// The track its talk-back goes out on, from its first packet; one per
    /// codec.
    track: Option<UplinkTrack>,
    /// Its claim, while it believes it holds the channel.
    claim: Option<u64>,
    /// Where it stands.
    flow: Flow,
    /// The counters.
    stats: Arc<TalkbackStats>,
    /// Where the arbiter reports the loss of the session's backchannel
    /// session ([`Talkback::lost`]); the sending end goes with each claim.
    losses: (
        mpsc::Sender<BackchannelRefused>,
        mpsc::Receiver<BackchannelRefused>,
    ),
}

/// What one offer's claim needs, apart from the session it is made for:
/// the arbiter, the session id, its claim now and where a loss is
/// reported. Owned, so the claim can run while the session goes on.
#[derive(Debug)]
pub(crate) struct Claimant {
    /// The connection's arbiter.
    arbiter: Arc<Arbiter>,
    /// The session id.
    session: String,
    /// Its claim when the offer came.
    held: Option<u64>,
    /// Where a loss of its backchannel session is reported.
    losses: mpsc::Sender<BackchannelRefused>,
}

impl Claimant {
    /// The arbiter.
    pub(crate) const fn arbiter(&self) -> &Arc<Arbiter> {
        &self.arbiter
    }

    /// The backchannel the session negotiates talk-back with, and whether
    /// it holds it now ([`Arbiter::target`]): its own open one while it
    /// holds the channel, the one offered now otherwise.
    pub(crate) fn target(&self) -> (Option<TalkbackTarget>, bool) {
        self.arbiter.target(self.held)
    }

    /// Claims the backchannel for the offer, whose answer is negotiated
    /// with `negotiated` (what [`Claimant::target`] gave), and opens the
    /// device's backchannel session within `limit` ([`Arbiter::claim`]),
    /// only while the backchannel offered is still that one.
    pub(crate) async fn claim(
        self,
        negotiated: Option<TalkbackTarget>,
        limit: Duration,
    ) -> Result<Option<Claim>, ClaimError> {
        let Self {
            arbiter,
            session,
            held,
            losses,
        } = self;
        arbiter
            .claim(&session, held, negotiated.as_ref(), limit, losses)
            .await
    }
}

impl Talkback {
    /// The talk-back of `session` on the connection `arbiter` arbitrates,
    /// counting into `stats`.
    pub(crate) fn new(arbiter: Arc<Arbiter>, session: String, stats: Arc<TalkbackStats>) -> Self {
        Self {
            arbiter,
            session,
            track: None,
            claim: None,
            flow: Flow::Idle,
            stats,
            losses: mpsc::channel(1),
        }
    }

    /// What a claim for the session's offer needs ([`Claimant::claim`]).
    pub(crate) fn claimant(&self) -> Claimant {
        Claimant {
            arbiter: Arc::clone(&self.arbiter),
            session: self.session.clone(),
            held: self.claim,
            losses: self.losses.0.clone(),
        }
    }

    /// Keeps `claim`, which its offer's claim granted: the session holds
    /// the backchannel now.
    pub(crate) fn adopt(&mut self, claim: Claim) {
        if let Some(id) = claim.adopt() {
            self.claim = Some(id);
        }
    }

    /// The next loss of the session's backchannel session the arbiter
    /// reports, and why; pending until one comes.
    pub(crate) async fn lost(&mut self) -> Option<BackchannelRefused> {
        self.losses.1.recv().await
    }

    /// The session's re-offer dropped talk-back: lets go of the
    /// backchannel if the session holds it ([`ChangeReason::Renegotiated`]).
    pub(crate) fn let_go(&mut self) {
        if let Some(claim) = self.claim.take() {
            self.arbiter
                .let_go(&self.session, claim, ChangeReason::Renegotiated);
        }
    }

    /// Takes one uplink packet: opens a track for the first one or one in
    /// another codec, has the arbiter decide, and publishes it if the
    /// session is the talker with a way to the device; a packet of a
    /// session that does not hold the backchannel is dropped and counted.
    pub(crate) fn receive(&mut self, packet: UplinkPacket) {
        let UplinkPacket { codec, packet } = packet;
        let track = match self.track.take() {
            Some(track) if track.codec() == codec => track,
            previous => {
                let to = codec.name();
                if let Some(old) = previous.map(|track| track.codec()) {
                    let from = old.name();
                    tracing::info!(from, to, "talk-back uplink changed codec; new uplink track");
                } else {
                    tracing::info!(codec = to, "talk-back uplink track opened");
                }
                UplinkTrack::new(codec, packet.arrival)
            }
        };
        let track = self.track.insert(track);
        let verdict = self
            .arbiter
            .decide(&mut self.claim, track.track(), codec, &self.stats);
        change(&mut self.flow, &verdict);
        match verdict {
            Verdict::Send => track.publish(packet),
            Verdict::NotTalker(_) => TalkbackStats::count(&self.stats.packets_dropped_busy),
            Verdict::Unroutable => {
                TalkbackStats::count(&self.stats.packets_dropped);
            }
        }
    }
}

/// Moves a session's talk-back from `current` to where `verdict` puts
/// it, logging a change.
fn change(current: &mut Flow, verdict: &Verdict) {
    let flow = match verdict {
        Verdict::Send => Flow::Talking,
        Verdict::Unroutable => Flow::Unroutable,
        Verdict::NotTalker(_) => Flow::Refused,
    };
    if flow == *current {
        return;
    }
    *current = flow;
    log_change(verdict);
}

/// Logs a session's talk-back moving where `verdict` puts it: log-only,
/// the level and the message.
fn log_change(verdict: &Verdict) {
    match verdict {
        Verdict::Send => tracing::debug!("talk-back: packets flow to the backchannel"),
        Verdict::Unroutable => {
            tracing::debug!("talk-back: no route to the backchannel; packets are dropped");
        }
        Verdict::NotTalker(holder) => tracing::info!(
            holder,
            "talk-back refused: the session does not hold the backchannel; packets are dropped"
        ),
    }
}

impl Drop for Talkback {
    fn drop(&mut self) {
        if let Some(claim) = self.claim {
            self.arbiter
                .let_go(&self.session, claim, ChangeReason::SessionClosed);
        }
        self.log_end();
    }
}

impl Talkback {
    /// Logs what a session that sent talk-back sent and lost: log-only.
    fn log_end(&self) {
        if self.flow != Flow::Idle {
            let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
            let packets_sent = load(&self.stats.packets_sent);
            let bytes_sent = load(&self.stats.bytes_sent);
            let packets_dropped_busy = load(&self.stats.packets_dropped_busy);
            let packets_dropped = load(&self.stats.packets_dropped);
            tracing::info!(
                packets_sent,
                bytes_sent,
                packets_dropped_busy,
                packets_dropped,
                "talk-back ended with the session"
            );
        }
    }
}

/// Takes one uplink packet for a session's `talkback`. A session on a
/// connection without a backchannel has none and its packet is dropped:
/// its talk-back m-line was answered `inactive`, so a browser sends there
/// only against the answer.
pub(crate) fn receive(talkback: Option<&mut Talkback>, packet: UplinkPacket) {
    if let Some(talkback) = talkback {
        talkback.receive(packet);
    } else {
        let codec = packet.codec.name();
        tracing::trace!(
            codec,
            "talk-back packet dropped: the connection has no backchannel"
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

    use std::collections::VecDeque;
    use std::future::Future;

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::codec::{CodecFamily, Kind};
    use lotse_core::media::RtpHeaderFields;
    use lotse_core::source::BackchannelOpener;
    use lotse_core::task::BoxFuture;
    use lotse_core::track::FrameSubscription;
    use lotse_core::transcode::Transcoder;
    use tokio::sync::Notify;
    use tokio::sync::broadcast::error::TryRecvError;
    use tokio_util::sync::CancellationToken;
    use tracing::Level;

    use super::*;
    use crate::test_logs::Logs;

    /// A talk-back transcoder that hands each uplink frame on as one
    /// packet of the device's G.711 (PT 0, SSRC 9), recording the frames
    /// it is built for and the chains it starts.
    #[derive(Debug, Default)]
    struct FakeUplink {
        refuse: bool,
        clockless: bool,
        frames: Mutex<Vec<Duration>>,
        stops: Mutex<Vec<CancellationToken>>,
        outputs: Mutex<Vec<Arc<Track>>>,
    }

    #[derive(Debug)]
    struct FakeChain(Arc<FakeUplink>);

    #[derive(Debug)]
    struct Factory(Arc<FakeUplink>);

    impl UplinkFactory for Factory {
        fn transcoder(&self, frame: Duration) -> Arc<dyn Transcoder> {
            self.0.frames.lock().unwrap().push(frame);
            Arc::new(FakeChain(Arc::clone(&self.0)))
        }
    }

    impl Transcoder for FakeChain {
        fn derive(&self, from: &Codec, to: CodecFamily) -> Option<Codec> {
            UplinkCodec::of(from.family())?;
            let derived = match to {
                CodecFamily::Pcmu => Codec::Pcmu,
                CodecFamily::Pcma => Codec::Pcma,
                _ => return None,
            };
            Some(if self.0.clockless {
                Codec::Unsupported {
                    kind: Kind::Audio,
                    name: "clockless".into(),
                }
            } else {
                derived
            })
        }

        fn spawn(
            &self,
            mut input: FrameSubscription,
            _from: &Codec,
            output: Arc<Track>,
        ) -> Result<TrackHandle, TranscodeError> {
            if self.0.refuse {
                return Err(TranscodeError::Failed("refused".into()));
            }
            let stop = CancellationToken::new();
            self.0.stops.lock().unwrap().push(stop.clone());
            self.0.outputs.lock().unwrap().push(Arc::clone(&output));
            let track = Arc::clone(&output);
            let cancelled = stop.clone();
            let _task = spawn_named("test.uplink", async move {
                let mut seq = 0_u16;
                while let Some(Ok(frame)) = cancelled.run_until_cancelled(input.recv()).await {
                    track.publish_packet(MediaPacket {
                        arrival: frame.wallclock,
                        rtp: RtpHeaderFields {
                            pt: 0,
                            seq,
                            ts: u32::try_from(frame.ts.ticks()).unwrap(),
                            marker: false,
                            ssrc: 9,
                        },
                        frame_start: true,
                        keyframe_start: false,
                        epoch: 0,
                        lateness: Duration::ZERO,
                        payload: Arc::from(&frame.payload[..]),
                    });
                    seq += 1;
                }
            });
            Ok(TrackHandle {
                track: output,
                delay: Duration::from_millis(20),
                stop,
            })
        }
    }

    fn arbiter(uplink: Option<Arc<dyn UplinkFactory>>) -> (Arc<Arbiter>, BackchannelSlot) {
        let (arbiter, slot, _clock) = arbiter_on(uplink);
        (arbiter, slot)
    }

    fn arbiter_on(
        uplink: Option<Arc<dyn UplinkFactory>>,
    ) -> (Arc<Arbiter>, BackchannelSlot, Arc<FakeClock>) {
        let slot = BackchannelSlot::default();
        let clock = Arc::new(FakeClock::from_system());
        let arbiter = Arbiter::new(slot.clone(), uplink, clock.clone());
        (Arc::new(arbiter), slot, clock)
    }

    /// How the test device answers one open.
    #[derive(Debug)]
    enum Answer {
        /// Opens at once.
        Open,
        /// Opens once notified.
        Later(Arc<Notify>),
        /// Refuses.
        Refuse(BackchannelRefused),
        /// Never answers.
        Hang,
    }

    /// One session the test device opened: its packets, how the test
    /// ends it on the device's side, and whether its holder closed it.
    #[derive(Debug)]
    struct DeviceSession {
        packets: mpsc::Receiver<MediaPacket>,
        on_loss: Option<oneshot::Sender<BackchannelRefused>>,
        close: CancellationToken,
    }

    /// The test device's backchannel: opens a session per claim as the
    /// next scripted answer says (at once without one), each with room for
    /// `capacity` packets, handing it to the test.
    #[derive(Debug)]
    struct TestOpener {
        codec: Codec,
        frame: Duration,
        capacity: usize,
        answers: Mutex<VecDeque<Answer>>,
        opened: mpsc::UnboundedSender<DeviceSession>,
        opens: AtomicU64,
        /// Each open's close, opened or not.
        closes: Mutex<Vec<CancellationToken>>,
    }

    impl BackchannelOpener for TestOpener {
        fn open(&self) -> BoxFuture<'static, Result<BackchannelSession, BackchannelRefused>> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            let answer = self
                .answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Answer::Open);
            let (sender, packets) = mpsc::channel(self.capacity);
            let (on_loss, lost) = oneshot::channel();
            let close = CancellationToken::new();
            self.closes.lock().unwrap().push(close.clone());
            let session = BackchannelSession::new(
                self.codec.clone(),
                self.frame,
                sender,
                lost,
                close.clone(),
            );
            let opened = self.opened.clone();
            let device = DeviceSession {
                packets,
                on_loss: Some(on_loss),
                close,
            };
            Box::pin(async move {
                match answer {
                    Answer::Open => {}
                    Answer::Later(go) => go.notified().await,
                    Answer::Refuse(why) => return Err(why),
                    Answer::Hang => std::future::pending().await,
                }
                opened.send(device).unwrap();
                Ok(session)
            })
        }
    }

    /// The test's end of a device's backchannel.
    struct Device {
        opener: Arc<TestOpener>,
        sessions: mpsc::UnboundedReceiver<DeviceSession>,
        current: Option<DeviceSession>,
    }

    impl Device {
        /// The next packet of the session open now, or of the next one.
        async fn recv(&mut self) -> Option<MediaPacket> {
            loop {
                if let Some(session) = &mut self.current
                    && let Some(packet) = session.packets.recv().await
                {
                    return Some(packet);
                }
                self.current = Some(self.sessions.recv().await?);
            }
        }

        /// A packet waiting in the session open now, if any.
        fn try_recv(&mut self) -> Option<MediaPacket> {
            while let Ok(session) = self.sessions.try_recv() {
                self.current = Some(session);
            }
            self.current.as_mut()?.packets.try_recv().ok()
        }

        /// The session opened last, once it is.
        fn session(&mut self) -> &mut DeviceSession {
            while let Ok(session) = self.sessions.try_recv() {
                self.current = Some(session);
            }
            self.current.as_mut().unwrap()
        }

        /// Scripts the next open.
        fn answer(&self, answer: Answer) {
            self.opener.answers.lock().unwrap().push_back(answer);
        }

        /// How many sessions were asked for.
        fn opens(&self) -> u64 {
            self.opener.opens.load(Ordering::Relaxed)
        }

        /// Whether the session of the `nth` open, from 0, was closed or
        /// abandoned.
        fn closed(&self, nth: usize) -> bool {
            self.opener.closes.lock().unwrap()[nth].is_cancelled()
        }
    }

    /// Offers a backchannel of `codec` and `frame` whose sessions have
    /// room for `capacity` packets, replacing any before.
    fn offer(slot: &BackchannelSlot, codec: Codec, frame: Duration, capacity: usize) -> Device {
        let (handed, sessions) = mpsc::unbounded_channel();
        let test_opener = Arc::new(TestOpener {
            codec: codec.clone(),
            frame,
            capacity,
            answers: Mutex::default(),
            opened: handed,
            opens: AtomicU64::new(0),
            closes: Mutex::default(),
        });
        let opener: Arc<dyn BackchannelOpener> = test_opener.clone();
        slot.offer(BackchannelOffer {
            codec,
            frame,
            opener,
        });
        Device {
            opener: test_opener,
            sessions,
            current: None,
        }
    }

    fn pcmu(slot: &BackchannelSlot) -> Device {
        offer(slot, Codec::Pcmu, BackchannelOffer::DEFAULT_FRAME, 64)
    }

    fn packet(codec: UplinkCodec, ssrc: u32, seq: u16, payload: &[u8]) -> UplinkPacket {
        UplinkPacket {
            codec,
            packet: MediaPacket {
                arrival: SystemClock.now(),
                rtp: RtpHeaderFields {
                    pt: 0,
                    seq,
                    ts: u32::from(seq) * 160,
                    marker: false,
                    ssrc,
                },
                frame_start: true,
                keyframe_start: false,
                epoch: 0,
                lateness: Duration::ZERO,
                payload: Arc::from(payload),
            },
        }
    }

    fn talk(talkback: &mut Talkback, seq: u16) {
        talkback.receive(packet(UplinkCodec::Pcmu, 1, seq, &[0xff, 0xfe]));
    }

    /// The session's offer claims the channel and opens its session: its
    /// claim adopted, or why not.
    async fn claim(talkback: &mut Talkback) -> Result<(), ClaimError> {
        if let Some(claim) =
            within(negotiating(talkback.claimant(), BACKCHANNEL_OPEN_LIMIT)).await?
        {
            talkback.adopt(claim);
        }
        Ok(())
    }

    /// The claim of `claimant`'s offer, negotiated with the backchannel
    /// its target is now, opening it within `limit`.
    fn negotiating(
        claimant: Claimant,
        limit: Duration,
    ) -> impl Future<Output = Result<Option<Claim>, ClaimError>> + Send + 'static {
        let negotiated = claimant.target().0;
        claimant.claim(negotiated, limit)
    }

    /// The session's offer claims the channel, which must be free.
    async fn claims(talkback: &mut Talkback) {
        claim(talkback).await.expect("the channel is free");
    }

    fn holds(talkback: &Talkback) -> bool {
        talkback.claimant().target().1
    }

    fn busy(holder: &str) -> Result<(), ClaimError> {
        Err(ClaimError::Busy(holder.to_owned()))
    }

    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::select! {
            output = future => output,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
        }
    }

    async fn eventually(what: &str, holds: impl Fn() -> bool + Send + Sync) {
        within(async {
            while !holds() {
                SystemClock.sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
        assert!(holds(), "{what}");
    }

    fn load(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    fn change(events: &mut broadcast::Receiver<TalkerChanged>) -> (String, ChangeReason) {
        let change = events.try_recv().unwrap();
        (change.session, change.reason)
    }

    fn no_change(events: &mut broadcast::Receiver<TalkerChanged>) {
        assert_eq!(events.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    /// Whether `future` still waits after one poll.
    async fn waits(future: impl Future) -> bool {
        tokio::select! {
            biased;
            _ = future => false,
            () = std::future::ready(()) => true,
        }
    }

    #[test]
    fn change_reasons_carry_the_api_names() {
        assert_eq!(ChangeReason::Claimed.code(), "claimed");
        assert_eq!(ChangeReason::SessionClosed.code(), "session_closed");
        assert_eq!(ChangeReason::Released.code(), "released");
        assert_eq!(ChangeReason::Renegotiated.code(), "renegotiated");
        assert_eq!(ChangeReason::Refused.code(), "refused");
        assert_eq!(ChangeReason::OptedOut.code(), "opted_out");
    }

    /// The connection's opt-out withdraws the offer and frees the channel
    /// from its talker (`opted_out`), closing its device session; its
    /// opt-in makes a probe due, which an offer waits for; an unchanged
    /// ask changes nothing.
    #[tokio::test]
    async fn an_opt_out_frees_the_talker_and_an_opt_in_has_offers_wait_for_the_probe() {
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a).await;
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        arbiter.ask(false);
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::OptedOut));
        assert!(!holds(&a));
        assert!(device.session().close.is_cancelled(), "its session closed");
        assert!(arbiter.offered().is_none() && !arbiter.awaits_probe());
        arbiter.ask(false);
        no_change(&mut events);
        // Opted in again: a probe is due, which an offer waits for.
        arbiter.ask(true);
        assert!(arbiter.awaits_probe());
        let waiting = Arc::clone(&arbiter);
        let settled = spawn_named("test.settled", async move { waiting.settled().await });
        tokio::task::yield_now().await;
        assert!(!settled.is_finished(), "waits for the probe");
        let _found = pcmu(&slot);
        within(settled).await.unwrap();
        assert!(arbiter.offered().is_some());
        // Out again with nobody talking: nothing to free.
        arbiter.ask(false);
        no_change(&mut events);
    }

    #[test]
    fn without_a_backchannel_talk_back_goes_nowhere() {
        receive(None, packet(UplinkCodec::Opus, 1, 0, &[1]));
    }

    /// Claim and hold: the first offer claims, a second is declined with
    /// the holder's name and its packets go nowhere, and the holder keeps
    /// the channel, silent or not, until its session closes; then the
    /// next offer claims it.
    #[tokio::test]
    async fn the_first_offer_claims_a_second_is_declined_and_the_holder_keeps_it_until_it_closes() {
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        // Nobody holds the channel before an offer claims it: a packet
        // from either is refused and counted.
        assert!(!holds(&a) && !holds(&b));
        talk(&mut a, 0);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        no_change(&mut events);

        claims(&mut a).await;
        assert!(holds(&a));
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Claimed));
        // Claiming again is the same claim: no change.
        let again = within(negotiating(a.claimant(), BACKCHANNEL_OPEN_LIMIT)).await;
        assert!(again.unwrap().is_none(), "held already");
        no_change(&mut events);
        talk(&mut a, 0);
        let first = within(device.recv()).await.unwrap();
        assert_eq!((first.rtp.seq, &first.payload[..]), (0, &[0xff, 0xfe][..]));
        eventually("a's bytes counted", || load(&a.stats.bytes_sent) == 2).await;
        assert_eq!(load(&a.stats.packets_sent), 1);

        // The second offer is declined with the holder's name; its
        // packets are dropped and counted.
        assert_eq!(claim(&mut b).await, busy("a"));
        assert!(!holds(&b));
        for seq in 0..3 {
            talk(&mut b, seq);
        }
        assert_eq!(load(&b.stats.packets_dropped_busy), 3);
        no_change(&mut events);
        // The holder sends on, and only its packets reach the device.
        talk(&mut a, 1);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 1);
        // Silent, the holder keeps it: no timeout frees it.
        SystemClock.sleep(Duration::from_millis(20)).await;
        assert_eq!(claim(&mut b).await, busy("a"), "still held");
        talk(&mut b, 3);
        assert_eq!(load(&b.stats.packets_dropped_busy), 4);
        assert!(device.try_recv().is_none(), "nothing of b's");

        // The holder's session closes: the channel is free, and the next
        // offer claims it.
        drop(a);
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("a", ChangeReason::SessionClosed)
        );
        claims(&mut b).await;
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
        talk(&mut b, 4);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 4);
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert_eq!(claim(&mut c).await, busy("b"));
        drop(c);
        no_change(&mut events);
        drop(b);
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("b", ChangeReason::SessionClosed)
        );
    }

    /// A re-offer that drops talk-back lets go: the channel is free for
    /// the next offer, from any session, the one that let go included,
    /// and a packet the session still sends is refused meanwhile.
    #[tokio::test]
    async fn a_re_offer_that_drops_talk_back_lets_go_and_the_next_offer_claims() {
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        // Letting go without a claim changes nothing.
        a.let_go();
        no_change(&mut events);
        claims(&mut a).await;
        talk(&mut a, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);

        a.let_go();
        assert!(!holds(&a));
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("a", ChangeReason::Renegotiated)
        );
        talk(&mut a, 1);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        assert!(device.try_recv().is_none(), "the route stopped");
        // The same session's next offer claims again: another claim.
        claims(&mut a).await;
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Claimed));
        talk(&mut a, 2);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 2);
        // Or another session's, once a let go.
        a.let_go();
        assert_eq!(change(&mut events).1, ChangeReason::Renegotiated);
        claims(&mut b).await;
        assert_eq!(change(&mut events).0, "b");
        // a's stale claim is gone: letting go again, or closing, frees
        // nothing of b's.
        a.let_go();
        drop(a);
        no_change(&mut events);
        assert!(holds(&b));
    }

    /// Hold, until `backchannel/release`.
    #[tokio::test]
    async fn a_release_frees_the_channel_for_the_next_offer_and_stops_the_talkers_route() {
        let uplink = Arc::new(FakeUplink::default());
        let (arbiter, slot) = arbiter(Some(Arc::new(Factory(Arc::clone(&uplink)))));
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        assert_eq!(arbiter.release(None), None, "nobody holds it");
        no_change(&mut events);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a).await;
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        talk(&mut a, 0);
        assert_eq!(
            within(device.recv()).await.unwrap().rtp.ssrc,
            9,
            "through the chain"
        );

        assert_eq!(arbiter.release(None).as_deref(), Some("a"));
        assert!(!holds(&a));
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Released));
        assert!(
            uplink.stops.lock().unwrap()[0].is_cancelled(),
            "a's chain stopped at once"
        );
        assert!(uplink.outputs.lock().unwrap()[0].is_closed());
        // The next offer claims it; the released session, now refused,
        // loses what it still sends.
        claims(&mut b).await;
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
        talk(&mut a, 1);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        // A stale claim frees nothing: a's session closing leaves b the
        // talker.
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert_eq!(claim(&mut c).await, busy("b"));
        drop(c);
        drop(a);
        no_change(&mut events);
        assert!(holds(&b));
        // The released talker claims again when nobody else did.
        assert_eq!(arbiter.release(None).as_deref(), Some("b"));
        assert_eq!(change(&mut events).1, ChangeReason::Released);
        claims(&mut b).await;
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
    }

    /// Whether a claim is new is decided with the claim, under the lock a
    /// release takes: a session that held the channel and was released
    /// just before its re-offer claims gets a new claim, which a re-offer
    /// the engine refuses lets go again; one it still holds is no new
    /// claim, and nothing changes.
    #[tokio::test]
    async fn a_claim_after_a_release_is_a_new_one_for_the_session_that_held_it() {
        let (arbiter, slot) = arbiter(None);
        let _device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let new = within(negotiating(a.claimant(), BACKCHANNEL_OPEN_LIMIT)).await;
        a.adopt(new.unwrap().expect("a new claim"));
        let again = within(negotiating(a.claimant(), BACKCHANNEL_OPEN_LIMIT)).await;
        assert!(again.unwrap().is_none(), "held already");
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        no_change(&mut events);
        // Released while the session still has its claim: the next one is
        // new, though the session believed it held the channel.
        assert_eq!(arbiter.release(Some("a")).as_deref(), Some("a"));
        let renewed = within(negotiating(a.claimant(), BACKCHANNEL_OPEN_LIMIT)).await;
        a.adopt(renewed.unwrap().expect("released meanwhile: a new claim"));
        assert_eq!(change(&mut events).1, ChangeReason::Released);
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        assert!(holds(&a));
        a.let_go();
        assert_eq!(change(&mut events).1, ChangeReason::Renegotiated);
        assert!(!holds(&a), "the channel is free again");
    }

    /// A stale claim is not taken for a later one: a released talker that
    /// did not claim since cannot free the next talker's channel.
    #[tokio::test]
    async fn a_released_talker_closing_frees_nothing_of_the_next_talkers() {
        let (arbiter, slot) = arbiter(None);
        let _device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a).await;
        assert_eq!(arbiter.release(None).as_deref(), Some("a"));
        claims(&mut b).await;
        let _claimed_released_claimed = (0..3).map(|_| change(&mut events)).count();
        drop(a);
        no_change(&mut events);
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert_eq!(claim(&mut c).await, busy("b"), "b still holds it");
    }

    /// A release that names a session frees the channel only from that
    /// session: from the holder it frees it as an unconditional one does,
    /// from anyone else, or with nobody holding it, it changes nothing.
    #[tokio::test]
    async fn a_release_for_a_session_frees_the_channel_only_from_that_session() {
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        assert_eq!(arbiter.release(Some("a")), None, "nobody holds it");
        no_change(&mut events);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a).await;
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        talk(&mut a, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);

        // Another session's release leaves a the talker, its route up.
        assert_eq!(arbiter.release(Some("b")), None);
        no_change(&mut events);
        assert_eq!(claim(&mut b).await, busy("a"), "a still holds it");
        talk(&mut a, 1);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 1);

        // The holder's own release frees it for the next offer.
        assert_eq!(arbiter.release(Some("a")).as_deref(), Some("a"));
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Released));
        claims(&mut b).await;
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
    }

    /// The interleaving a client checking the talker before an
    /// unconditional release would lose: a's talker spell ends, b claims,
    /// and only then does a's release arrive. Named for a, it frees
    /// nothing of b's.
    #[tokio::test]
    async fn a_stale_release_for_the_previous_talker_never_evicts_the_next_one() {
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a).await;
        talk(&mut a, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);
        // Another client releases a, and b's offer claims the free
        // channel.
        assert_eq!(arbiter.release(None).as_deref(), Some("a"));
        claims(&mut b).await;
        talk(&mut b, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);
        let changes: Vec<(String, ChangeReason)> = (0..3).map(|_| change(&mut events)).collect();
        assert_eq!(
            changes,
            [
                ("a".to_owned(), ChangeReason::Claimed),
                ("a".to_owned(), ChangeReason::Released),
                ("b".to_owned(), ChangeReason::Claimed),
            ]
        );
        // a stops talking: its release, named for a, arrives late.
        assert_eq!(arbiter.release(Some("a")), None);
        no_change(&mut events);
        talk(&mut a, 1);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1, "b still holds it");
        talk(&mut b, 1);
        assert_eq!(
            within(device.recv()).await.unwrap().rtp.seq,
            1,
            "b's route is up"
        );
        assert!(device.try_recv().is_none(), "nothing of a's");
        drop(b);
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("b", ChangeReason::SessionClosed)
        );
    }

    /// The claim opens the device's backchannel session and its answer
    /// waits for it: the channel is the claimant's meanwhile (another
    /// offer is declined), and what it sends before the session is open is
    /// dropped, not queued. The session is the talker's alone: offers and
    /// withdrawals of the source's probe leave it open, and releasing the
    /// claim closes it.
    #[tokio::test]
    async fn a_claim_opens_the_devices_session_and_holds_until_it_is_open() {
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let go = Arc::new(Notify::new());
        device.answer(Answer::Later(Arc::clone(&go)));
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        let claimant = a.claimant();
        let claiming = spawn_named("test.claim", negotiating(claimant, BACKCHANNEL_OPEN_LIMIT));
        eventually("the open asked for", || device.opens() == 1).await;
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Claimed));
        assert!(!claiming.is_finished(), "the answer waits for the session");
        assert_eq!(
            claim(&mut b).await,
            busy("a"),
            "the channel is a's meanwhile"
        );
        // a's own packets before its claim is adopted are refused.
        talk(&mut a, 0);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        go.notify_one();
        let granted = within(claiming).await.unwrap().unwrap().unwrap();
        a.adopt(granted);
        talk(&mut a, 1);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 1);
        // The probe withdrawing the offer, or offering another, leaves the
        // talker's session alone.
        slot.withdraw();
        talk(&mut a, 2);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 2);
        let mut other = pcmu(&slot);
        talk(&mut a, 3);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 3);
        assert_eq!(other.opens(), 0, "nothing opened on the new offer");
        assert!(!device.session().close.is_cancelled());
        // Its re-offer dropping talk-back closes it.
        a.let_go();
        assert_eq!(
            change(&mut events),
            ("a".into(), ChangeReason::Renegotiated)
        );
        assert!(device.session().close.is_cancelled(), "closed");
        // The next claim opens a session on the offer there is now.
        claims(&mut b).await;
        assert_eq!(other.opens(), 1);
        talk(&mut b, 4);
        assert_eq!(within(other.recv()).await.unwrap().rtp.seq, 4);
        no_change(&mut {
            let _claimed = change(&mut events);
            events
        });
    }

    /// The device refuses the session (or no backchannel is offered when
    /// the claim comes): the offer is declined `refused` with why, the
    /// claim is not kept, and the next claim opens one again.
    #[tokio::test]
    async fn a_refused_session_declines_the_claim_and_keeps_nothing() {
        let (arbiter, slot) = arbiter(None);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        // Nothing offered: refused at once, nothing claimed.
        assert_eq!(
            claim(&mut a).await,
            Err(ClaimError::Refused(BackchannelRefused {
                status: None,
                message: "the camera offers no backchannel now".into(),
            }))
        );
        no_change(&mut events);
        let mut device = pcmu(&slot);
        let busy_now = BackchannelRefused {
            status: Some(453),
            message: "SETUP: 453 Not Enough Bandwidth".into(),
        };
        device.answer(Answer::Refuse(busy_now.clone()));
        assert_eq!(claim(&mut a).await, Err(ClaimError::Refused(busy_now)));
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Claimed));
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Refused));
        assert!(!holds(&a));
        talk(&mut a, 0);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1, "not the talker");
        // The user's next press is the next claim: it opens one again.
        claims(&mut a).await;
        assert_eq!(device.opens(), 2);
        talk(&mut a, 1);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 1);
    }

    /// The session does not open within the limit: declined `refused`,
    /// the claim not kept, and the half-open session closed.
    #[tokio::test]
    async fn a_session_that_does_not_open_in_time_declines_the_claim() {
        let (arbiter, slot, clock) = arbiter_on(None);
        let device = pcmu(&slot);
        device.answer(Answer::Hang);
        let mut events = arbiter.subscribe();
        let a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let claiming = spawn_named(
            "test.claim",
            negotiating(a.claimant(), BACKCHANNEL_OPEN_LIMIT),
        );
        eventually("the open asked for", || device.opens() == 1).await;
        clock.advance(BACKCHANNEL_OPEN_LIMIT);
        let refused = within(claiming).await.unwrap().unwrap_err();
        assert_eq!(
            refused,
            ClaimError::Refused(BackchannelRefused {
                status: None,
                message: "the camera's backchannel session did not open within 8000 ms".into(),
            })
        );
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Claimed));
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Refused));
        assert!(!holds(&a));
    }

    /// A release while the session opens frees the channel at once and
    /// abandons the open, so the device's session is closed before the
    /// next claim opens one, and the offer is declined; the claim that
    /// follows opens a new one, and so does a claim after a release while
    /// it plays. A session that opens just as the release comes, before
    /// its claim sees it, is closed again. A session that closes while
    /// its answer waits lets go and abandons the session.
    #[tokio::test]
    async fn a_release_or_a_close_while_the_session_opens_keeps_nothing() {
        let (logs, _guard) = Logs::capture();
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        device.answer(Answer::Hang);
        let a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let claiming = spawn_named(
            "test.claim",
            negotiating(a.claimant(), BACKCHANNEL_OPEN_LIMIT),
        );
        eventually("the open asked for", || device.opens() == 1).await;
        assert!(!device.closed(0));
        assert_eq!(arbiter.release(None).as_deref(), Some("a"));
        let released = ClaimError::Refused(BackchannelRefused {
            status: None,
            message: "the backchannel was released while its session opened".into(),
        });
        assert_eq!(within(claiming).await.unwrap().unwrap_err(), released);
        assert!(device.closed(0), "the open abandoned");
        assert_eq!(
            logs.count(
                Level::INFO,
                "talk-back: the backchannel was released while its session opened; the handshake is abandoned and the offer declined"
            ),
            1
        );
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Claimed));
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Released));
        no_change(&mut events);
        // Claimed again: a new session opens.
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut b).await;
        assert_eq!(device.opens(), 2);
        talk(&mut b, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);
        // Released while it plays and claimed again: closed, and another
        // one opens.
        assert_eq!(arbiter.release(None).as_deref(), Some("b"));
        assert!(device.closed(1));
        claims(&mut b).await;
        assert_eq!(device.opens(), 3);
        talk(&mut b, 1);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 1);
        assert_eq!(arbiter.release(None).as_deref(), Some("b"));
        for reason in [
            ChangeReason::Claimed,
            ChangeReason::Released,
            ChangeReason::Claimed,
            ChangeReason::Released,
        ] {
            assert_eq!(change(&mut events), ("b".into(), reason));
        }
        // The session opens and the release comes before the claim sees
        // it: the open wins the race, and the session is closed again.
        let go = Arc::new(Notify::new());
        device.answer(Answer::Later(Arc::clone(&go)));
        let claiming = spawn_named(
            "test.claim",
            negotiating(a.claimant(), BACKCHANNEL_OPEN_LIMIT),
        );
        eventually("the open asked for", || device.opens() == 4).await;
        go.notify_one();
        assert_eq!(arbiter.release(None).as_deref(), Some("a"));
        assert_eq!(within(claiming).await.unwrap().unwrap_err(), released);
        assert!(device.session().close.is_cancelled(), "closed again");
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Claimed));
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Released));
        no_change(&mut events);
        // The claim's future dropped mid-open (its session closed): the
        // channel is free again.
        device.answer(Answer::Hang);
        let claiming = spawn_named(
            "test.claim",
            negotiating(a.claimant(), BACKCHANNEL_OPEN_LIMIT),
        );
        eventually("the open asked for", || device.opens() == 5).await;
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Claimed));
        claiming.abort();
        assert!(claiming.await.unwrap_err().is_cancelled());
        assert_eq!(
            change(&mut events),
            ("a".into(), ChangeReason::SessionClosed)
        );
    }

    /// The device's session ends on its side while the talker holds it:
    /// the claim is released (`refused`), the talker's session told why
    /// once, and what it sends meanwhile is dropped and counted until its
    /// next claim, which opens a new session.
    #[tokio::test]
    async fn a_lost_session_releases_the_claim_and_tells_the_talker_once() {
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a).await;
        talk(&mut a, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);
        let lost = BackchannelRefused {
            status: None,
            message: "the camera closed the backchannel session".into(),
        };
        let on_loss = device.session().on_loss.take().unwrap();
        on_loss.send(lost.clone()).unwrap();
        assert_eq!(within(a.lost()).await, Some(lost.clone()));
        assert!(waits(a.lost()).await, "told once");
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Claimed));
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Refused));
        assert!(!holds(&a));
        talk(&mut a, 1);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        assert!(device.try_recv().is_none());
        // Its re-offer claims again: a new session.
        claims(&mut a).await;
        assert_eq!(device.opens(), 2);
        talk(&mut a, 2);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 2);
        // A session whose source's task goes away without a reason is
        // lost all the same.
        drop(device.session().on_loss.take());
        assert_eq!(
            within(a.lost()).await,
            Some(BackchannelRefused {
                status: None,
                message: "the camera's backchannel session ended".into(),
            })
        );
        // A loss after the talker let go changes nothing, nor one the
        // arbiter hears of for a claim that holds nothing.
        claims(&mut a).await;
        let on_loss = device.session().on_loss.take().unwrap();
        a.let_go();
        let mut events = arbiter.subscribe();
        arbiter.lost("a", 999, &lost);
        no_change(&mut events);
        let _unread = on_loss.send(lost);
        SystemClock.sleep(Duration::from_millis(10)).await;
        assert!(waits(a.lost()).await);
    }

    /// The source probes with nothing offered: a claim's arbitration
    /// waits for the probe, at most the limit; with an offer a reconnect
    /// kept, it does not wait, and says so. Without a probe it neither
    /// waits nor says anything.
    #[tokio::test]
    async fn the_arbiter_waits_for_the_probe_at_most_the_limit() {
        let (logs, _guard) = Logs::capture();
        let kept = || {
            logs.lines(
                Level::DEBUG,
                "talk-back: the source probes the camera again; a claim takes the backchannel offered before without waiting for it",
            )
            .len()
        };
        let (arbiter, slot, clock) = arbiter_on(None);
        assert!(!arbiter.awaits_probe());
        assert_eq!(kept(), 0, "no probe runs");
        assert_eq!(within(arbiter.settled()).await, BACKCHANNEL_OPEN_LIMIT);
        slot.probing();
        assert!(arbiter.awaits_probe());
        let waiting = Arc::clone(&arbiter);
        let settled = spawn_named("test.settled", async move { waiting.settled().await });
        SystemClock.sleep(Duration::from_millis(5)).await;
        assert!(!settled.is_finished());
        // Three seconds into the wait the probe ends: five are left for
        // the claim.
        clock.advance(Duration::from_secs(3));
        let _device = pcmu(&slot);
        assert_eq!(within(settled).await.unwrap(), Duration::from_secs(5));
        assert!(arbiter.offered().is_some());
        // A reconnect's probe with the offer kept: no wait.
        slot.probing();
        assert!(!arbiter.awaits_probe(), "the offer stands");
        assert_eq!(kept(), 1, "the kept offer is claimed at once");
        // A probe that never ends: the limit, and nothing left.
        slot.withdraw();
        slot.probing();
        let waiting = Arc::clone(&arbiter);
        let settled = spawn_named("test.settled", async move { waiting.settled().await });
        SystemClock.sleep(Duration::from_millis(5)).await;
        clock.advance(BACKCHANNEL_OPEN_LIMIT);
        assert_eq!(within(settled).await.unwrap(), Duration::ZERO);
        assert!(arbiter.awaits_probe(), "still probing");
        assert_eq!(kept(), 1, "nothing kept while the probe is awaited");
        // A session that opens at once still wins over a limit used up.
        let _second = pcmu(&slot);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let granted = within(negotiating(a.claimant(), Duration::ZERO)).await;
        a.adopt(granted.unwrap().unwrap());
        assert!(holds(&a));
    }

    /// The reverse chain: built for the device's frame, restarted on a
    /// new uplink track (a codec change) and for the session of a device
    /// that takes another codec or frame, stopped with the session.
    #[tokio::test]
    async fn the_talkers_uplink_takes_the_reverse_chain_framed_as_the_device_asks() {
        let uplink = Arc::new(FakeUplink::default());
        let (arbiter, slot) = arbiter(Some(Arc::new(Factory(Arc::clone(&uplink)))));
        // The frames chains were built for since the last call; a claim's
        // negotiation asks for transcoders too, which the test drops.
        let frames = || std::mem::take(&mut *uplink.frames.lock().unwrap());
        let forty = Duration::from_millis(40);
        let mut device = offer(&slot, Codec::Pcma, forty, 64);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a).await;
        frames();
        a.receive(packet(UplinkCodec::Opus, 1, 0, &[1, 2, 3]));
        let out = within(device.recv()).await.unwrap();
        assert_eq!((out.rtp.ssrc, &out.payload[..]), (9, &[1, 2, 3][..]));
        eventually("bytes after the chain", || load(&a.stats.bytes_sent) == 3).await;
        assert_eq!(frames(), [forty]);
        assert_eq!(*uplink.outputs.lock().unwrap()[0].codec(), Codec::Pcma);

        // Another codec: a new track, and the chain restarts on it.
        a.receive(packet(UplinkCodec::Pcmu, 1, 1, &[4]));
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[4]);
        assert!(uplink.stops.lock().unwrap()[0].is_cancelled());
        assert!(!uplink.stops.lock().unwrap()[1].is_cancelled());
        assert_eq!(frames(), [forty]);

        // A device that takes another frame or another law: the next
        // claim's session, a new chain.
        a.let_go();
        let sixty = Duration::from_millis(60);
        let mut device = offer(&slot, Codec::Pcma, sixty, 64);
        claims(&mut a).await;
        frames();
        a.receive(packet(UplinkCodec::Pcmu, 1, 2, &[5]));
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[5]);
        assert_eq!(frames(), [sixty]);
        a.let_go();
        let mut device = offer(&slot, Codec::Pcmu, sixty, 64);
        claims(&mut a).await;
        frames();
        a.receive(packet(UplinkCodec::Pcmu, 1, 3, &[6]));
        a.receive(packet(UplinkCodec::Pcmu, 1, 4, &[7]));
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[6]);
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[7]);
        assert_eq!(frames(), [sixty]);
        assert_eq!(*uplink.outputs.lock().unwrap()[3].codec(), Codec::Pcmu);

        // The session closes: its chain stops and its output closes.
        drop(a);
        assert!(
            uplink
                .stops
                .lock()
                .unwrap()
                .iter()
                .all(CancellationToken::is_cancelled)
        );
        assert!(
            uplink
                .outputs
                .lock()
                .unwrap()
                .iter()
                .all(|track| track.is_closed())
        );
    }

    /// Opus to an Opus device is forwarded as received: no chain, though
    /// the factory is there.
    #[tokio::test]
    async fn opus_to_an_opus_device_is_forwarded_as_received() {
        let uplink = Arc::new(FakeUplink::default());
        let (arbiter, slot) = arbiter(Some(Arc::new(Factory(Arc::clone(&uplink)))));
        let mut device = offer(
            &slot,
            Codec::Opus { channels: 2 },
            Duration::from_millis(20),
            64,
        );
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a).await;
        a.receive(packet(UplinkCodec::Opus, 7, 0, &[9, 9]));
        // A new SSRC starts an epoch on the track; the forwarder skips the
        // event and forwards the packet.
        a.receive(packet(UplinkCodec::Opus, 8, 1, &[8]));
        let first = within(device.recv()).await.unwrap();
        let second = within(device.recv()).await.unwrap();
        assert_eq!((first.rtp.ssrc, &first.payload[..]), (7, &[9, 9][..]));
        assert_eq!((second.rtp.ssrc, &second.payload[..]), (8, &[8][..]));
        assert!(uplink.stops.lock().unwrap().is_empty(), "no chain");
    }

    /// The talker negotiates with the backchannel session it has open, not
    /// with what a probe since offers: holding an Opus session while the
    /// camera now offers PCMU, it negotiates Opus alone (no chain produces
    /// Opus), which reaches its session, never PCMU, which would reach
    /// nothing. Any other session negotiates with what is offered now,
    /// and the next claim opens that.
    #[tokio::test]
    async fn the_talker_negotiates_with_its_open_session_and_others_with_the_offer_of_now() {
        let (logs, _guard) = Logs::capture();
        let uplink: Arc<dyn UplinkFactory> = Arc::new(Factory(Arc::default()));
        let (arbiter, slot) = arbiter(Some(uplink));
        let opus = Codec::Opus { channels: 2 };
        let mut opus_device = offer(&slot, opus.clone(), Duration::from_millis(20), 64);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a).await;
        // The probe again finds PCMU.
        let mut pcmu_device = pcmu(&slot);
        let opus_only = TalkbackTarget {
            codec: opus,
            takes: vec![UplinkCodec::Opus],
        };
        assert_eq!(a.claimant().target(), (Some(opus_only), true));
        assert_eq!(
            logs.lines(
                Level::DEBUG,
                "talk-back: the talker negotiates with its open backchannel session, not with what the source offers now"
            )
            .iter()
            .map(|line| line.fields.as_str())
            .collect::<Vec<_>>(),
            [" open=\"opus\" offered=\"pcmu\""]
        );
        // What it negotiates reaches its session, as received.
        a.receive(packet(UplinkCodec::Opus, 7, 0, &[9, 9]));
        let sent = within(opus_device.recv()).await.unwrap();
        assert_eq!(&sent.payload[..], &[9, 9][..]);
        assert_eq!(load(&a.stats.packets_dropped), 0);
        // PCMU, which the new offer takes, has no way to the Opus session.
        a.receive(packet(UplinkCodec::Pcmu, 7, 1, &[1]));
        assert_eq!(load(&a.stats.packets_dropped), 1);
        // b, and a session with no claim, get the offer of now.
        let now = TalkbackTarget {
            codec: Codec::Pcmu,
            takes: vec![UplinkCodec::Opus, UplinkCodec::Pcmu, UplinkCodec::Pcma],
        };
        assert_eq!(b.claimant().target(), (Some(now.clone()), false));
        assert_eq!(arbiter.target(None), (Some(now), false));
        // Released, a's next claim opens the PCMU session.
        arbiter.release(None);
        assert!(!holds(&a));
        claims(&mut a).await;
        talk(&mut a, 2);
        assert!(within(pcmu_device.recv()).await.is_some());
        assert_eq!(opus_device.opens(), 1);
    }

    /// A claim opens only the backchannel its offer's answer was
    /// negotiated with: a probe that replaced the PCMU offer with Opus
    /// since declines it `refused`, opening nothing and keeping nothing,
    /// since the answer's PCMU would reach no Opus session. One that found
    /// PCMU again opens the new offer, and the talker's PCMU reaches it.
    #[tokio::test]
    async fn a_claim_opens_only_the_backchannel_its_answer_was_negotiated_with() {
        let (logs, _guard) = Logs::capture();
        let uplink: Arc<dyn UplinkFactory> = Arc::new(Factory(Arc::default()));
        let (arbiter, slot) = arbiter(Some(uplink));
        let mut events = arbiter.subscribe();
        let first = pcmu(&slot);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let (negotiated, held) = a.claimant().target();
        assert!(!held);
        // The probe again finds Opus before the claim.
        let opus = offer(
            &slot,
            Codec::Opus { channels: 2 },
            Duration::from_millis(20),
            64,
        );
        let declined = within(
            a.claimant()
                .claim(negotiated.clone(), BACKCHANNEL_OPEN_LIMIT),
        )
        .await;
        assert_eq!(
            declined.unwrap_err(),
            ClaimError::Refused(BackchannelRefused {
                status: None,
                message: "the camera's backchannel changed to opus while the offer was negotiated"
                    .into(),
            })
        );
        assert_eq!((first.opens(), opus.opens()), (0, 0));
        assert!(!holds(&a));
        no_change(&mut events);
        assert_eq!(
            logs.lines(
                Level::INFO,
                "talk-back: the backchannel offered now is not the one the answer was negotiated with; declined"
            )
            .iter()
            .map(|line| line.fields.as_str())
            .collect::<Vec<_>>(),
            [" session=\"a\" negotiated=\"pcmu\" offered=\"opus\""]
        );
        // It finds PCMU again: the same backchannel, opened.
        let mut second = pcmu(&slot);
        let granted = within(a.claimant().claim(negotiated, BACKCHANNEL_OPEN_LIMIT)).await;
        a.adopt(granted.unwrap().unwrap());
        assert_eq!(change(&mut events), ("a".into(), ChangeReason::Claimed));
        assert_eq!((first.opens(), opus.opens(), second.opens()), (0, 0, 1));
        talk(&mut a, 0);
        assert!(within(second.recv()).await.is_some());
        assert_eq!(load(&a.stats.packets_dropped), 0);
    }

    /// No route: no factory for a conversion, or a chain that does not
    /// start. The talker keeps the channel; its packets are dropped.
    #[tokio::test]
    async fn without_a_route_the_talker_keeps_the_channel_and_its_packets_are_dropped() {
        let refusing = Arc::new(FakeUplink {
            refuse: true,
            ..FakeUplink::default()
        });
        let clockless = Arc::new(FakeUplink {
            clockless: true,
            ..FakeUplink::default()
        });
        let factories: [Option<Arc<dyn UplinkFactory>>; 3] = [
            None,
            Some(Arc::new(Factory(refusing))),
            Some(Arc::new(Factory(clockless))),
        ];
        for uplink in factories {
            let forwards_g711 = uplink.is_none();
            let (arbiter, slot) = arbiter(uplink);
            let mut device = pcmu(&slot);
            let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
            claims(&mut a).await;
            let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
            for seq in 0..2 {
                a.receive(packet(UplinkCodec::Opus, 1, seq, &[1]));
            }
            assert_eq!(load(&a.stats.packets_dropped), 2);
            assert_eq!(claim(&mut b).await, busy("a"), "a holds it all the same");
            talk(&mut a, 2);
            if forwards_g711 {
                // The device's own codec is forwarded as received.
                assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 2);
            } else {
                // A G.711 device always takes the chain, which fails.
                assert_eq!(load(&a.stats.packets_dropped), 3);
                assert!(device.try_recv().is_none());
            }
        }
    }

    /// A session negotiates talk-back in the uplink codecs a route
    /// reaches the device from, and in no other: every one through the
    /// reverse chain to a G.711 device, the device's own codec alone
    /// without the chain, Opus alone to an Opus device either way (no
    /// chain produces Opus), none to a device in another codec.
    #[tokio::test]
    async fn a_session_negotiates_only_the_uplink_codecs_a_route_reaches() {
        use UplinkCodec::{Opus, Pcma, Pcmu};
        let chain =
            || -> Option<Arc<dyn UplinkFactory>> { Some(Arc::new(Factory(Arc::default()))) };
        let opus = Codec::Opus { channels: 2 };
        for (uplink, device, takes) in [
            (chain(), Codec::Pcmu, &[Opus, Pcmu, Pcma][..]),
            (chain(), Codec::Pcma, &[Opus, Pcmu, Pcma]),
            (chain(), opus.clone(), &[Opus]),
            (chain(), Codec::G722, &[]),
            (None, Codec::Pcmu, &[Pcmu]),
            (None, Codec::Pcma, &[Pcma]),
            (None, opus, &[Opus]),
        ] {
            let what = format!("{device:?}, chain: {}", uplink.is_some());
            let (arbiter, slot) = arbiter(uplink);
            assert_eq!(
                arbiter.target(None),
                (None, false),
                "{what}: nothing offered"
            );
            let _device = offer(&slot, device.clone(), BackchannelOffer::DEFAULT_FRAME, 1);
            let target = arbiter.target(None).0.unwrap();
            assert_eq!(target.codec, device, "{what}");
            assert_eq!(target.takes, takes, "{what}");
            // The route agrees, codec by codec.
            for from in UplinkCodec::ALL {
                let track = UplinkTrack::new(from, SystemClock.now());
                let (sender, _packets) = mpsc::channel(1);
                let handle = BackchannelSession::new(
                    device.clone(),
                    BackchannelOffer::DEFAULT_FRAME,
                    sender,
                    oneshot::channel().1,
                    CancellationToken::new(),
                );
                let stats = Arc::new(TalkbackStats::default());
                let route = arbiter.route(track.track(), from, &handle, &stats);
                assert_eq!(
                    route.path.is_some(),
                    takes.contains(&from),
                    "{what}: {from:?}"
                );
            }
        }
    }

    /// The forwarder ends with its track.
    #[tokio::test]
    async fn the_forwarder_ends_with_its_track() {
        let track = UplinkTrack::new(UplinkCodec::Pcmu, SystemClock.now());
        let packets = track.track().subscribe(Unit::Packets);
        drop(track);
        let (sender, _device) = mpsc::channel(1);
        let stats = Arc::new(TalkbackStats::default());
        within(forward(packets, sender, Arc::clone(&stats))).await;
        assert_eq!(load(&stats.packets_sent), 0);
    }

    /// The forwarder never waits on the device: a full queue drops.
    #[tokio::test]
    async fn a_full_backchannel_drops_and_counts() {
        let (arbiter, slot) = arbiter(None);
        let _device = offer(&slot, Codec::Pcmu, BackchannelOffer::DEFAULT_FRAME, 1);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a).await;
        for seq in 0..3 {
            talk(&mut a, seq);
        }
        eventually("two dropped", || load(&a.stats.packets_dropped) == 2).await;
        assert_eq!(load(&a.stats.packets_sent), 1);
        assert_eq!(load(&a.stats.bytes_sent), 2);
    }

    /// `session/get`'s counters, only for a session an answer of which
    /// negotiated talk-back.
    #[test]
    fn only_a_negotiated_session_reports_its_counters() {
        let stats = TalkbackStats::default();
        assert_eq!(stats.report(), None);
        stats.ever_negotiated.store(true, Ordering::Relaxed);
        stats.packets_received.store(5, Ordering::Relaxed);
        TalkbackStats::count(&stats.packets_dropped_busy);
        TalkbackStats::count(&stats.packets_sent);
        stats.bytes_sent.store(160, Ordering::Relaxed);
        assert_eq!(
            stats.report(),
            Some(lotse_ipc::TalkbackStats {
                packets_received: 5,
                packets_dropped_busy: 1,
                bytes_sent: 160,
            })
        );
    }

    #[test]
    fn talker_changes_reach_the_supervisor_in_milliseconds_since_the_epoch() {
        let at = UNIX_EPOCH + Duration::from_millis(1_791_280_800_123);
        for (reason, name) in [
            (ChangeReason::Claimed, "claimed"),
            (ChangeReason::SessionClosed, "session_closed"),
            (ChangeReason::Released, "released"),
            (ChangeReason::Renegotiated, "renegotiated"),
            (ChangeReason::Refused, "refused"),
        ] {
            let change = talker_change(TalkerChanged {
                session: "a".into(),
                claim: 7,
                reason,
                at,
            });
            assert_eq!(
                change,
                TalkerChange {
                    session_id: "a".into(),
                    reason: name.into(),
                    at_ms: 1_791_280_800_123,
                }
            );
        }
        let before = talker_change(TalkerChanged {
            session: "a".into(),
            claim: 7,
            reason: ChangeReason::Claimed,
            at: UNIX_EPOCH - Duration::from_secs(1),
        });
        assert_eq!(before.at_ms, 0);
    }

    /// A feed that keeps up passes every change on in order, and ends
    /// with the arbiter.
    #[tokio::test]
    async fn a_feed_passes_every_change_on_in_order_and_ends_with_the_arbiter() {
        let (arbiter, slot) = arbiter(None);
        let _device = pcmu(&slot);
        let mut feed = TalkerFeed::new(&arbiter);
        assert!(waits(feed.next()).await, "nothing changed yet");
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a).await;
        assert_eq!(arbiter.release(None), Some("a".into()));
        claims(&mut a).await;
        let changes: Vec<(String, u64, ChangeReason)> = [
            within(feed.next()).await.unwrap(),
            within(feed.next()).await.unwrap(),
            within(feed.next()).await.unwrap(),
        ]
        .into_iter()
        .map(|change| (change.session, change.claim, change.reason))
        .collect();
        assert_eq!(
            changes,
            [
                ("a".into(), 0, ChangeReason::Claimed),
                ("a".into(), 0, ChangeReason::Released),
                ("a".into(), 1, ChangeReason::Claimed),
            ],
            "a second claim is another"
        );
        drop(a);
        assert_eq!(
            within(feed.next()).await.unwrap().reason,
            ChangeReason::SessionClosed
        );
        drop(arbiter);
        assert_eq!(within(feed.next()).await, None);
    }

    /// The talker the supervisor holds lets go, and others claim and let
    /// go more often than the feed holds: once it fell behind, the feed
    /// tells the supervisor the talker it holds let go, at the time the
    /// channel was freed, and nothing older after that.
    #[tokio::test]
    async fn a_feed_that_fell_behind_releases_the_talker_the_supervisor_holds() {
        let (arbiter, slot) = arbiter(None);
        let _device = pcmu(&slot);
        let mut feed = TalkerFeed::new(&arbiter);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a).await;
        let told = within(feed.next()).await.unwrap();
        assert_eq!(
            (told.session.as_str(), told.reason),
            ("a", ChangeReason::Claimed)
        );
        assert_eq!(arbiter.release(None), Some("a".into()));
        for _ in 0..u16::try_from(EVENT_CAPACITY).unwrap() {
            claims(&mut b).await;
            assert_eq!(arbiter.release(Some("b")), Some("b".into()));
        }
        let release = arbiter.lock().last.clone().unwrap();
        assert_eq!(
            (release.session.as_str(), release.reason),
            ("b", ChangeReason::Released)
        );
        let resynced = within(feed.next()).await.unwrap();
        assert_eq!(
            resynced,
            TalkerChanged {
                session: "a".into(),
                claim: told.claim,
                reason: ChangeReason::Released,
                at: release.at,
            }
        );
        assert!(waits(feed.next()).await, "nothing older follows");
        // In order again from here.
        claims(&mut b).await;
        let claimed = within(feed.next()).await.unwrap();
        assert_eq!(
            (claimed.session.as_str(), claimed.reason),
            ("b", ChangeReason::Claimed)
        );
    }

    /// Others claim and let go more often than the feed holds, and one
    /// holds the channel now: the feed tells the supervisor that claim,
    /// as the claim was made, and goes on from there.
    #[tokio::test]
    async fn a_feed_that_fell_behind_tells_the_claim_of_the_talker_there_is_now() {
        let (arbiter, slot) = arbiter(None);
        let _device = pcmu(&slot);
        let mut feed = TalkerFeed::new(&arbiter);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a).await;
        let told = within(feed.next()).await.unwrap();
        assert_eq!(told.reason, ChangeReason::Claimed);
        for _ in 1..=u16::try_from(EVENT_CAPACITY).unwrap() {
            assert_eq!(arbiter.release(None), Some("a".into()));
            claims(&mut a).await;
        }
        assert_eq!(arbiter.release(None), Some("a".into()));
        claims(&mut b).await;
        let claim = arbiter.lock().last.clone().unwrap();
        let resynced = within(feed.next()).await.unwrap();
        assert_eq!(resynced, claim);
        assert_eq!(
            (resynced.session.as_str(), resynced.reason),
            ("b", ChangeReason::Claimed)
        );
        assert!(waits(feed.next()).await, "nothing older follows");
        drop(b);
        let closed = within(feed.next()).await.unwrap();
        assert_eq!(
            (closed.session.as_str(), closed.claim, closed.reason),
            ("b", claim.claim, ChangeReason::SessionClosed)
        );
        // The same session again, after the feed fell behind: its new
        // claim is news to the supervisor.
        claims(&mut a).await;
        let again = within(feed.next()).await.unwrap();
        for _ in 100..100 + u16::try_from(EVENT_CAPACITY).unwrap() {
            assert_eq!(arbiter.release(None), Some("a".into()));
            claims(&mut a).await;
        }
        let resynced = within(feed.next()).await.unwrap();
        assert_eq!(resynced.session, "a");
        assert_ne!(resynced.claim, again.claim);
        assert_eq!(resynced, arbiter.lock().last.clone().unwrap());
    }

    /// A feed that fell behind while the supervisor already holds the
    /// talker there is now tells nothing; once the arbiter is gone it
    /// ends, behind or not.
    #[tokio::test]
    async fn a_feed_that_fell_behind_to_where_the_supervisor_is_tells_nothing() {
        let (arbiter, slot) = arbiter(None);
        let _device = pcmu(&slot);
        let mut feed = TalkerFeed::new(&arbiter);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        for _ in 0..u16::try_from(EVENT_CAPACITY).unwrap() {
            claims(&mut a).await;
            assert_eq!(arbiter.release(None), Some("a".into()));
        }
        assert!(waits(feed.next()).await, "free, as the supervisor was told");
        for _ in 0..u16::try_from(EVENT_CAPACITY).unwrap() {
            claims(&mut a).await;
            assert_eq!(arbiter.release(None), Some("a".into()));
        }
        drop(a);
        drop(arbiter);
        assert_eq!(within(feed.next()).await, None);
    }
}
