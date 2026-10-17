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
//!   holds it ([`Talkback::claim`], [`ChangeReason::Claimed`]), before the
//!   engine answers, so the answer carries the outcome; first offer wins.
//! - **Declined.** An offer while another session holds it is answered
//!   without talk-back, and the session is told once per offer
//!   (`backchannel_declined`, `busy`). A packet from a session that does
//!   not hold the channel, declined or released, is dropped and counted.
//! - **Hold.** The talker keeps the channel, silent or muted, until its
//!   session closes ([`ChangeReason::SessionClosed`]; a deleted stream
//!   closes its sessions), its re-offer drops talk-back
//!   ([`Talkback::let_go`], [`ChangeReason::Renegotiated`]) or the client
//!   releases it ([`Arbiter::release`], [`ChangeReason::Released`]): from
//!   whoever holds it, or only from the session the release names,
//!   decided against the claims under one lock. There is no timeout.
//!   Free, the channel goes to the next offer that asks, from any
//!   session, the one that let go included.
//! - **Reconnect.** The talker keeps the slot while the source withdraws
//!   its backchannel and offers it again; packets that arrive meanwhile
//!   are dropped, not buffered, and the route to the device is rebuilt on
//!   the new handle.
//!
//! The talker's route to the device starts on its uplink track before its
//! first packet is published, so nothing is missed: the reverse
//! chain (the binary's [`UplinkFactory`] transcoder, framed as the
//! [`BackchannelHandle`] asks) when it converts the uplink to the device's
//! codec (any G.711 device), or the track's live path as it is for the
//! device's own codec otherwise (Opus to an Opus device). A forwarder task
//! puts each packet into the handle's sender without waiting; a full or
//! closed queue drops it. Every change of the talker is logged and sent as
//! a [`TalkerChanged`] event, under the lock that decided it, so the events
//! come in the order of the changes; the supervisor gets them through a
//! [`TalkerFeed`], which resynchronizes from the arbiter when it falls
//! behind.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lotse_core::clock::Clock;
use lotse_core::codec::Codec;
use lotse_core::media::MediaPacket;
use lotse_core::session::TalkbackTarget;
use lotse_core::source::{BackchannelHandle, BackchannelSlot};
use lotse_core::task::spawn_named;
use lotse_core::track::{Track, TrackEvent, TrackSubscription, Unit};
use lotse_core::transcode::{TrackHandle, TranscodeError, UplinkFactory};
use lotse_core::uplink::{UPLINK_TRACK, UplinkCodec, UplinkPacket, UplinkTrack};
use lotse_ipc::TalkerChange;
use tokio::sync::{broadcast, mpsc};
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
}

impl ChangeReason {
    /// The API name.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::SessionClosed => "session_closed",
            Self::Released => "released",
            Self::Renegotiated => "renegotiated",
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
    /// The answer negotiated talk-back: only such a session is reported.
    pub(crate) negotiated: AtomicBool,
    /// Talk-back packets the engine took (`SessionStats::uplink_packets`,
    /// `session/get`'s `packets_received`).
    pub(crate) packets_received: AtomicU64,
    /// Packets dropped because the session did not hold the channel: its
    /// offer was declined, or it let go or was released since
    /// (`session/get`'s `packets_dropped_busy`).
    pub(crate) packets_dropped_busy: AtomicU64,
    /// Packets of the talker dropped on the way: the backchannel
    /// withdrawn, no route to its codec, or its queue full or closed.
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

    /// The counters as the supervisor gets them; `None` when the answer
    /// did not negotiate talk-back.
    pub(crate) fn report(&self) -> Option<lotse_ipc::TalkbackStats> {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        self.negotiated
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
    /// The way its packets reach the device, once built for a handle.
    route: Option<Route>,
}

/// What the arbiter decided for one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// The sender is the talker and its route is up: publish it.
    Send,
    /// The sender is the talker, but the source withdrew the backchannel
    /// for a reconnect.
    Withdrawn,
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
    /// It is the talker, and the backchannel is withdrawn.
    Withdrawn,
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

    /// The backchannel the running source offers now, if any.
    pub(crate) fn offered(&self) -> Option<BackchannelHandle> {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .current()
    }

    /// The backchannel the running source offers now, with the uplink
    /// codecs that reach it, for a session to negotiate talk-back with:
    /// each one [`Arbiter::reaches`] routes to its codec.
    pub(crate) fn target(&self) -> Option<TalkbackTarget> {
        let handle = self.offered()?;
        let takes = UplinkCodec::ALL
            .into_iter()
            .filter(|from| self.reaches(*from, &handle))
            .collect();
        Some(TalkbackTarget {
            codec: handle.codec,
            takes,
        })
    }

    /// Whether [`Arbiter::route`] finds a path for an uplink in `from` to
    /// `handle`'s device: the reverse chain installed derives the device's
    /// codec from it, or it is the device's own codec, forwarded as
    /// received. Without a reverse chain (`uplink` unset) only the latter.
    fn reaches(&self, from: UplinkCodec, handle: &BackchannelHandle) -> bool {
        let to = handle.codec.family();
        from.family() == to
            || self.uplink.as_ref().is_some_and(|uplink| {
                uplink
                    .transcoder(handle.frame)
                    .derive(&from.codec(), to)
                    .is_some()
            })
    }

    /// Arbitrates `slot` from now on: the connection switched to a source
    /// that offers its backchannel there. The talker keeps the channel,
    /// and its route moves to the new handle with its next packet, as
    /// across a reconnect.
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

    /// Claims the channel for `session`'s offer: `Ok` when it holds the
    /// channel now, with `claim` its claim, and `true` when this call
    /// made it a new one, `false` when it held it already; `Err` with the
    /// holder's session id when another session holds it. Decided under
    /// the lock a release takes, so whether the claim is new is decided
    /// with it: a release just before makes the next claim a new one.
    pub(crate) fn claim(&self, session: &str, claim: &mut Option<u64>) -> Result<bool, String> {
        let mut guard = self.lock();
        let state = &mut *guard;
        if let Some(talker) = &state.talker {
            if Some(talker.claim) == *claim {
                return Ok(false);
            }
            *claim = None;
            return Err(talker.session.clone());
        }
        let id = state.next_claim;
        state.next_claim = id.wrapping_add(1);
        *claim = Some(id);
        self.emit(&mut state.last, session, id, ChangeReason::Claimed);
        state.talker = Some(Talker {
            session: session.to_owned(),
            claim: id,
            route: None,
        });
        drop(guard);
        let reason = ChangeReason::Claimed.code();
        tracing::info!(
            session,
            claim = id,
            reason,
            "talk-back: backchannel claimed by the offer; this session is the talker"
        );
        Ok(true)
    }

    /// Whether `claim` holds the channel now.
    fn holds(&self, claim: Option<u64>) -> bool {
        claim.is_some() && self.lock().talker.as_ref().map(|talker| talker.claim) == claim
    }

    /// Frees the channel (`backchannel/release`) from whoever holds it,
    /// or, given `only`, only if that session holds it: decided under the
    /// lock a claim takes, so a release that names a session that already
    /// let go never frees the channel a later claim took. Its route stops
    /// at once, and the next offer that asks for talk-back claims it, the
    /// released session's included. Returns the session that held it when
    /// it was freed.
    pub(crate) fn release(&self, only: Option<&str>) -> Option<String> {
        let mut guard = self.lock();
        let state = &mut *guard;
        let freed = state
            .talker
            .take_if(|talker| only.is_none_or(|session| talker.session == session));
        if let Some(talker) = &freed {
            self.emit(
                &mut state.last,
                &talker.session,
                talker.claim,
                ChangeReason::Released,
            );
        }
        let kept = state.talker.as_ref().map(|talker| talker.session.clone());
        drop(guard);
        let Some(talker) = freed else {
            if let Some(talker) = kept {
                tracing::info!(
                    session = only,
                    talker,
                    "talk-back: release for a session that does not hold the backchannel; the talker keeps it"
                );
            } else {
                tracing::debug!(
                    session = only,
                    "talk-back: release with the backchannel free; nothing to do"
                );
            }
            return None;
        };
        let (session, reason) = (talker.session.as_str(), ChangeReason::Released.code());
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
    /// talker makes sure its route serves the track and the backchannel
    /// offered now. `claim` is the session's, cleared here once it no
    /// longer holds the channel.
    fn decide(
        &self,
        claim: &mut Option<u64>,
        track: &Arc<Track>,
        codec: UplinkCodec,
        counters: &Arc<TalkbackStats>,
    ) -> Verdict {
        let offered = self.offered();
        let mut guard = self.lock();
        let holder = guard.talker.as_ref().map(|talker| talker.session.clone());
        let Some(talker) = guard
            .talker
            .as_mut()
            .filter(|talker| claim.is_some() && Some(talker.claim) == *claim)
        else {
            *claim = None;
            return Verdict::NotTalker(holder);
        };
        let Some(handle) = offered else {
            // The source is reconnecting: nothing is buffered for it, and
            // the old handle's route goes.
            talker.route = None;
            return Verdict::Withdrawn;
        };
        if !talker
            .route
            .as_ref()
            .is_some_and(|route| route.serves(track, &handle))
        {
            // The old route stops before the new one starts.
            talker.route = None;
            talker.route = Some(self.route(track, codec, handle, counters));
        }
        let verdict = if talker
            .route
            .as_ref()
            .is_some_and(|route| route.path.is_some())
        {
            Verdict::Send
        } else {
            Verdict::Unroutable
        };
        drop(guard);
        verdict
    }

    /// The route of `track`, in `from`, to `handle`'s device: through the
    /// reverse chain when it converts to the device's codec, the track's
    /// live path as it is for the device's own codec otherwise, no path
    /// when neither works.
    fn route(
        &self,
        track: &Arc<Track>,
        from: UplinkCodec,
        handle: BackchannelHandle,
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
                    Some(Path::new(Some(chain), packets, &handle, stats))
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
                &handle,
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
            codec: to,
            frame: handle.frame,
            sender: handle.sender,
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

/// The talker's way to the device, built for one uplink track and one
/// offered backchannel; a change of either builds another.
#[derive(Debug)]
struct Route {
    /// The uplink track it reads.
    track: Arc<Track>,
    /// The device's codec when it was built.
    codec: Codec,
    /// The device's frame when it was built.
    frame: Duration,
    /// The backchannel it sends to.
    sender: mpsc::Sender<MediaPacket>,
    /// What carries the packets; `None` when nothing converts them.
    path: Option<Path>,
}

impl Route {
    /// Whether it serves `track` towards `handle` as offered now.
    fn serves(&self, track: &Arc<Track>, handle: &BackchannelHandle) -> bool {
        Arc::ptr_eq(&self.track, track)
            && self.codec == handle.codec
            && self.frame == handle.frame
            && self.sender.same_channel(&handle.sender)
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
        handle: &BackchannelHandle,
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
/// offer ([`Talkback::claim`]) and let go for a re-offer
/// ([`Talkback::let_go`]); dropped with the session, which frees the
/// channel if it held it.
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
        }
    }

    /// Claims the connection's backchannel for the session's offer
    /// ([`Arbiter::claim`]): `Ok` when the session holds it now, `true`
    /// when this offer claimed it anew; `Err` with the holder's session id
    /// when another session does.
    pub(crate) fn claim(&mut self) -> Result<bool, String> {
        self.arbiter.claim(&self.session, &mut self.claim)
    }

    /// Whether the session holds the backchannel now.
    pub(crate) fn holds(&self) -> bool {
        self.arbiter.holds(self.claim)
    }

    /// The backchannel the connection's source offers now, with the
    /// uplink codecs that reach it ([`Arbiter::target`]).
    pub(crate) fn target(&self) -> Option<TalkbackTarget> {
        self.arbiter.target()
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
            Verdict::Withdrawn | Verdict::Unroutable => {
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
        Verdict::Withdrawn => Flow::Withdrawn,
        Verdict::Unroutable => Flow::Unroutable,
        Verdict::NotTalker(_) => Flow::Refused,
    };
    if flow == *current {
        return;
    }
    let from = std::mem::replace(current, flow);
    log_change(from, verdict);
}

/// Logs a session's talk-back moving `from` where `verdict` puts it:
/// log-only, the level and the message.
fn log_change(from: Flow, verdict: &Verdict) {
    match verdict {
        Verdict::Send if from == Flow::Withdrawn => {
            tracing::info!("talk-back: the backchannel is offered again; packets flow");
        }
        Verdict::Send => tracing::debug!("talk-back: packets flow to the backchannel"),
        Verdict::Withdrawn => tracing::info!(
            "talk-back: the backchannel is withdrawn while the source reconnects; packets are dropped until it is offered again"
        ),
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

    use std::future::Future;

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::codec::{CodecFamily, Kind};
    use lotse_core::media::RtpHeaderFields;
    use lotse_core::track::FrameSubscription;
    use lotse_core::transcode::Transcoder;
    use tokio::sync::broadcast::error::TryRecvError;
    use tokio_util::sync::CancellationToken;

    use super::*;

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
        let slot = BackchannelSlot::default();
        let arbiter = Arbiter::new(slot.clone(), uplink, Arc::new(FakeClock::from_system()));
        (Arc::new(arbiter), slot)
    }

    /// Offers a backchannel of `codec` and `frame` with room for
    /// `capacity` packets, replacing any before.
    fn offer(
        slot: &BackchannelSlot,
        codec: Codec,
        frame: Duration,
        capacity: usize,
    ) -> mpsc::Receiver<MediaPacket> {
        let (sender, packets) = mpsc::channel(capacity);
        slot.offer(BackchannelHandle {
            codec,
            frame,
            sender,
        });
        packets
    }

    fn pcmu(slot: &BackchannelSlot) -> mpsc::Receiver<MediaPacket> {
        offer(slot, Codec::Pcmu, BackchannelHandle::DEFAULT_FRAME, 64)
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

    /// The session's offer claims the channel, which must be free.
    fn claims(talkback: &mut Talkback) {
        assert_eq!(talkback.claim(), Ok(true), "the channel is free");
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

    #[test]
    fn change_reasons_carry_the_api_names() {
        assert_eq!(ChangeReason::Claimed.code(), "claimed");
        assert_eq!(ChangeReason::SessionClosed.code(), "session_closed");
        assert_eq!(ChangeReason::Released.code(), "released");
        assert_eq!(ChangeReason::Renegotiated.code(), "renegotiated");
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
        assert!(!a.holds() && !b.holds());
        talk(&mut a, 0);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        no_change(&mut events);

        claims(&mut a);
        assert!(a.holds());
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Claimed));
        // Claiming again is the same claim: no change.
        assert_eq!(a.claim(), Ok(false));
        no_change(&mut events);
        talk(&mut a, 0);
        let first = within(device.recv()).await.unwrap();
        assert_eq!((first.rtp.seq, &first.payload[..]), (0, &[0xff, 0xfe][..]));
        eventually("a's bytes counted", || load(&a.stats.bytes_sent) == 2).await;
        assert_eq!(load(&a.stats.packets_sent), 1);

        // The second offer is declined with the holder's name; its
        // packets are dropped and counted.
        assert_eq!(b.claim(), Err("a".to_owned()));
        assert!(!b.holds());
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
        assert_eq!(b.claim(), Err("a".to_owned()), "still held");
        talk(&mut b, 3);
        assert_eq!(load(&b.stats.packets_dropped_busy), 4);
        assert!(device.try_recv().is_err(), "nothing of b's");

        // The holder's session closes: the channel is free, and the next
        // offer claims it.
        drop(a);
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("a", ChangeReason::SessionClosed)
        );
        claims(&mut b);
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
        talk(&mut b, 4);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 4);
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert_eq!(c.claim(), Err("b".to_owned()));
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
        claims(&mut a);
        talk(&mut a, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);

        a.let_go();
        assert!(!a.holds());
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("a", ChangeReason::Renegotiated)
        );
        talk(&mut a, 1);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        assert!(device.try_recv().is_err(), "the route stopped");
        // The same session's next offer claims again: another claim.
        claims(&mut a);
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Claimed));
        talk(&mut a, 2);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 2);
        // Or another session's, once a let go.
        a.let_go();
        assert_eq!(change(&mut events).1, ChangeReason::Renegotiated);
        claims(&mut b);
        assert_eq!(change(&mut events).0, "b");
        // a's stale claim is gone: letting go again, or closing, frees
        // nothing of b's.
        a.let_go();
        drop(a);
        no_change(&mut events);
        assert!(b.holds());
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
        claims(&mut a);
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        talk(&mut a, 0);
        assert_eq!(
            within(device.recv()).await.unwrap().rtp.ssrc,
            9,
            "through the chain"
        );

        assert_eq!(arbiter.release(None).as_deref(), Some("a"));
        assert!(!a.holds());
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Released));
        assert!(
            uplink.stops.lock().unwrap()[0].is_cancelled(),
            "a's chain stopped at once"
        );
        assert!(uplink.outputs.lock().unwrap()[0].is_closed());
        // The next offer claims it; the released session, now refused,
        // loses what it still sends.
        claims(&mut b);
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
        talk(&mut a, 1);
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        // A stale claim frees nothing: a's session closing leaves b the
        // talker.
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert_eq!(c.claim(), Err("b".to_owned()));
        drop(c);
        drop(a);
        no_change(&mut events);
        assert!(b.holds());
        // The released talker claims again when nobody else did.
        assert_eq!(arbiter.release(None).as_deref(), Some("b"));
        assert_eq!(change(&mut events).1, ChangeReason::Released);
        claims(&mut b);
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
        let (arbiter, _slot) = arbiter(None);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        assert_eq!(a.claim(), Ok(true));
        assert_eq!(a.claim(), Ok(false), "held already");
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        no_change(&mut events);
        // Released while the session still has its claim: the next one is
        // new, though the session believed it held the channel.
        assert_eq!(arbiter.release(Some("a")).as_deref(), Some("a"));
        assert_eq!(a.claim(), Ok(true), "released meanwhile");
        assert_eq!(change(&mut events).1, ChangeReason::Released);
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        a.let_go();
        assert_eq!(change(&mut events).1, ChangeReason::Renegotiated);
        assert!(!a.holds(), "the channel is free again");
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
        claims(&mut a);
        assert_eq!(arbiter.release(None).as_deref(), Some("a"));
        claims(&mut b);
        let _claimed_released_claimed = (0..3).map(|_| change(&mut events)).count();
        drop(a);
        no_change(&mut events);
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert_eq!(c.claim(), Err("b".to_owned()), "b still holds it");
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
        claims(&mut a);
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        talk(&mut a, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);

        // Another session's release leaves a the talker, its route up.
        assert_eq!(arbiter.release(Some("b")), None);
        no_change(&mut events);
        assert_eq!(b.claim(), Err("a".to_owned()), "a still holds it");
        talk(&mut a, 1);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 1);

        // The holder's own release frees it for the next offer.
        assert_eq!(arbiter.release(Some("a")).as_deref(), Some("a"));
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Released));
        claims(&mut b);
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
        claims(&mut a);
        talk(&mut a, 0);
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 0);
        // Another client releases a, and b's offer claims the free
        // channel.
        assert_eq!(arbiter.release(None).as_deref(), Some("a"));
        claims(&mut b);
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
        assert!(device.try_recv().is_err(), "nothing of a's");
        drop(b);
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("b", ChangeReason::SessionClosed)
        );
    }

    /// A source reconnect.
    #[tokio::test]
    async fn across_a_reconnect_the_talker_keeps_the_slot_and_what_it_sends_meanwhile_is_dropped() {
        let (arbiter, slot) = arbiter(None);
        let mut before = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a);
        talk(&mut a, 0);
        assert_eq!(within(before.recv()).await.unwrap().rtp.seq, 0);

        slot.withdraw();
        talk(&mut a, 1);
        talk(&mut a, 2);
        assert_eq!(load(&a.stats.packets_dropped), 2);
        // Nothing went to the old backchannel, and its route let go of it.
        assert!(within(before.recv()).await.is_none());
        assert_eq!(
            b.claim(),
            Err("a".to_owned()),
            "the talker still holds the slot"
        );

        let mut after = pcmu(&slot);
        talk(&mut a, 3);
        let resumed = within(after.recv()).await.unwrap();
        assert_eq!(
            resumed.rtp.seq, 3,
            "nothing buffered from the withdrawn spell"
        );
        // Offered again without a withdrawal (another handle): the route
        // follows it.
        let mut replaced = pcmu(&slot);
        talk(&mut a, 4);
        assert_eq!(within(replaced.recv()).await.unwrap().rtp.seq, 4);
        assert!(within(after.recv()).await.is_none(), "the old route let go");
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Claimed));
        no_change(&mut events);
    }

    /// The reverse chain: built for the device's frame, restarted on a
    /// new uplink track (a codec change) and on a backchannel offered with
    /// another codec or frame, stopped with the session.
    #[tokio::test]
    async fn the_talkers_uplink_takes_the_reverse_chain_framed_as_the_device_asks() {
        let uplink = Arc::new(FakeUplink::default());
        let (arbiter, slot) = arbiter(Some(Arc::new(Factory(Arc::clone(&uplink)))));
        let forty = Duration::from_millis(40);
        let mut device = offer(&slot, Codec::Pcma, forty, 64);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a);
        a.receive(packet(UplinkCodec::Opus, 1, 0, &[1, 2, 3]));
        let out = within(device.recv()).await.unwrap();
        assert_eq!((out.rtp.ssrc, &out.payload[..]), (9, &[1, 2, 3][..]));
        eventually("bytes after the chain", || load(&a.stats.bytes_sent) == 3).await;
        assert_eq!(*uplink.frames.lock().unwrap(), [forty]);
        assert_eq!(*uplink.outputs.lock().unwrap()[0].codec(), Codec::Pcma);

        // Another codec: a new track, and the chain restarts on it.
        a.receive(packet(UplinkCodec::Pcmu, 1, 1, &[4]));
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[4]);
        assert!(uplink.stops.lock().unwrap()[0].is_cancelled());
        assert!(!uplink.stops.lock().unwrap()[1].is_cancelled());

        // The same codec on another frame or another law: new chains.
        let sixty = Duration::from_millis(60);
        let mut device = offer(&slot, Codec::Pcma, sixty, 64);
        a.receive(packet(UplinkCodec::Pcmu, 1, 2, &[5]));
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[5]);
        let (sender, _) = mpsc::channel(1);
        slot.offer(BackchannelHandle {
            codec: Codec::Pcmu,
            frame: sixty,
            sender: sender.clone(),
        });
        // Same sender, same codec, same frame: one more chain only for the
        // law, none for an unchanged offer.
        let mut device = offer(&slot, Codec::Pcmu, sixty, 64);
        a.receive(packet(UplinkCodec::Pcmu, 1, 3, &[6]));
        a.receive(packet(UplinkCodec::Pcmu, 1, 4, &[7]));
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[6]);
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[7]);
        assert_eq!(*uplink.frames.lock().unwrap(), [forty, forty, sixty, sixty]);
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
        claims(&mut a);
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
            claims(&mut a);
            let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
            for seq in 0..2 {
                a.receive(packet(UplinkCodec::Opus, 1, seq, &[1]));
            }
            assert_eq!(load(&a.stats.packets_dropped), 2);
            assert_eq!(b.claim(), Err("a".to_owned()), "a holds it all the same");
            talk(&mut a, 2);
            if forwards_g711 {
                // The device's own codec is forwarded as received.
                assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 2);
            } else {
                // A G.711 device always takes the chain, which fails.
                assert_eq!(load(&a.stats.packets_dropped), 3);
                assert!(device.try_recv().is_err());
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
            assert_eq!(arbiter.target(), None, "{what}: nothing offered");
            let _device = offer(&slot, device.clone(), BackchannelHandle::DEFAULT_FRAME, 1);
            let target = arbiter.target().unwrap();
            assert_eq!(target.codec, device, "{what}");
            assert_eq!(target.takes, takes, "{what}");
            // The route agrees, codec by codec.
            for from in UplinkCodec::ALL {
                let track = UplinkTrack::new(from, SystemClock.now());
                let handle = arbiter.offered().unwrap();
                let stats = Arc::new(TalkbackStats::default());
                let route = arbiter.route(track.track(), from, handle, &stats);
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
        let _device = offer(&slot, Codec::Pcmu, BackchannelHandle::DEFAULT_FRAME, 1);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a);
        for seq in 0..3 {
            talk(&mut a, seq);
        }
        eventually("two dropped", || load(&a.stats.packets_dropped) == 2).await;
        assert_eq!(load(&a.stats.packets_sent), 1);
        assert_eq!(load(&a.stats.bytes_sent), 2);
    }

    /// `session/get`'s counters, only for a session whose answer
    /// negotiated talk-back.
    #[test]
    fn only_a_negotiated_session_reports_its_counters() {
        let stats = TalkbackStats::default();
        assert_eq!(stats.report(), None);
        stats.negotiated.store(true, Ordering::Relaxed);
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

    /// Whether `future` still waits after one poll.
    async fn waits(future: impl Future) -> bool {
        tokio::select! {
            biased;
            _ = future => false,
            () = std::future::ready(()) => true,
        }
    }

    /// A feed that keeps up passes every change on in order, and ends
    /// with the arbiter.
    #[tokio::test]
    async fn a_feed_passes_every_change_on_in_order_and_ends_with_the_arbiter() {
        let (arbiter, _slot) = arbiter(None);
        let mut feed = TalkerFeed::new(&arbiter);
        assert!(waits(feed.next()).await, "nothing changed yet");
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        claims(&mut a);
        assert_eq!(arbiter.release(None), Some("a".into()));
        claims(&mut a);
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
        let (arbiter, _slot) = arbiter(None);
        let mut feed = TalkerFeed::new(&arbiter);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a);
        let told = within(feed.next()).await.unwrap();
        assert_eq!(
            (told.session.as_str(), told.reason),
            ("a", ChangeReason::Claimed)
        );
        assert_eq!(arbiter.release(None), Some("a".into()));
        for _ in 0..u16::try_from(EVENT_CAPACITY).unwrap() {
            claims(&mut b);
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
        claims(&mut b);
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
        let (arbiter, _slot) = arbiter(None);
        let mut feed = TalkerFeed::new(&arbiter);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        claims(&mut a);
        let told = within(feed.next()).await.unwrap();
        assert_eq!(told.reason, ChangeReason::Claimed);
        for _ in 1..=u16::try_from(EVENT_CAPACITY).unwrap() {
            assert_eq!(arbiter.release(None), Some("a".into()));
            claims(&mut a);
        }
        assert_eq!(arbiter.release(None), Some("a".into()));
        claims(&mut b);
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
        claims(&mut a);
        let again = within(feed.next()).await.unwrap();
        for _ in 100..100 + u16::try_from(EVENT_CAPACITY).unwrap() {
            assert_eq!(arbiter.release(None), Some("a".into()));
            claims(&mut a);
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
        let (arbiter, _slot) = arbiter(None);
        let mut feed = TalkerFeed::new(&arbiter);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        for _ in 0..u16::try_from(EVENT_CAPACITY).unwrap() {
            claims(&mut a);
            assert_eq!(arbiter.release(None), Some("a".into()));
        }
        assert!(waits(feed.next()).await, "free, as the supervisor was told");
        for _ in 0..u16::try_from(EVENT_CAPACITY).unwrap() {
            claims(&mut a);
            assert_eq!(arbiter.release(None), Some("a".into()));
        }
        drop(a);
        drop(arbiter);
        assert_eq!(within(feed.next()).await, None);
    }
}
