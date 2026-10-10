//! Talk-back in the worker: each session's uplink track, and the
//! connection's arbiter that lets one session at a time, the talker, reach
//! the backchannel.
//!
//! A connection has at most one backchannel and, at any time, at most one
//! talker. The worker holds every session that could talk to the camera,
//! so it arbitrates: one [`Arbiter`] per connection whose source protocol
//! can carry audio back, and one [`Talkback`] per session on it.
//!
//! - **Claim.** The first uplink packet a session sends while nobody holds
//!   the channel makes it the talker ([`ChangeReason::Claimed`]).
//! - **Busy.** A packet from another session while one holds it is
//!   dropped and counted, and its session gets one `backchannel_busy`
//!   warning per spell of being refused.
//! - **Hold.** The talker keeps the channel, silent or muted, until its
//!   session closes ([`ChangeReason::SessionClosed`]; a deleted stream
//!   closes its sessions) or the client releases it ([`Arbiter::release`],
//!   [`ChangeReason::Released`]). There is no timeout.
//! - **Reconnect.** The talker keeps the slot while the source withdraws
//!   its backchannel and offers it again; packets that arrive meanwhile
//!   are dropped, not buffered, and the route to the device is rebuilt on
//!   the new handle.
//!
//! The talker's route to the device starts on its uplink track before the
//! packet that claimed it is published, so nothing is missed: the reverse
//! chain (the binary's [`UplinkFactory`] transcoder, framed as the
//! [`BackchannelHandle`] asks) when it converts the uplink to the device's
//! codec (any G.711 device), or the track's live path as it is for the
//! device's own codec otherwise (Opus to an Opus device). A forwarder task
//! puts each packet into the handle's sender without waiting; a full or
//! closed queue drops it. Every change of the talker is logged and sent as
//! a [`TalkerChanged`] event.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lotse_core::clock::Clock;
use lotse_core::codec::Codec;
use lotse_core::media::MediaPacket;
use lotse_core::source::{BackchannelHandle, BackchannelSlot};
use lotse_core::task::spawn_named;
use lotse_core::track::{Track, TrackEvent, TrackSubscription, Unit};
use lotse_core::transcode::{TrackHandle, TranscodeError, UplinkFactory};
use lotse_core::uplink::{UPLINK_TRACK, UplinkCodec, UplinkPacket, UplinkTrack};
use lotse_ipc::TalkerChange;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// The warning code a session gets when it sends while another holds the
/// backchannel.
pub(crate) const BACKCHANNEL_BUSY: &str = "backchannel_busy";

/// How many talker changes a slow subscriber may fall behind by. Changes
/// come at human pace; one that lags skips the oldest.
const EVENT_CAPACITY: usize = 16;

/// Why the talker changed: the `reason` of the talker-changed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangeReason {
    /// A session sent the first packet while nobody held the channel.
    Claimed,
    /// The talker's session closed.
    SessionClosed,
    /// The client released the channel (`backchannel/release`).
    Released,
}

impl ChangeReason {
    /// The API name.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::SessionClosed => "session_closed",
            Self::Released => "released",
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
    /// Packets dropped because another session held the channel
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

/// The next talker change on `events`. A receiver that fell behind skips
/// the oldest changes, logged, and goes on with the ones kept: each says
/// who holds the channel after it, so the last one is the state. `None`
/// once the arbiter is gone.
pub(crate) async fn next_change(
    events: &mut broadcast::Receiver<TalkerChanged>,
) -> Option<TalkerChanged> {
    loop {
        match events.recv().await {
            Ok(change) => return Some(change),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!(
                    skipped,
                    "talk-back: talker changes skipped for the supervisor; the latest follow"
                );
            }
            Err(broadcast::error::RecvError::Closed) => return None,
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
    /// Another session, this one, holds the channel.
    Busy(String),
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
    /// Another session holds the channel.
    Busy,
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

    /// Arbitrates `slot` from now on: the connection switched to a source
    /// that offers its backchannel there. The talker keeps the channel,
    /// and its route moves to the new handle with its next packet, as
    /// across a reconnect.
    pub(crate) fn follow(&self, slot: BackchannelSlot) {
        tracing::info!("talk-back: following the new source's backchannel");
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = slot;
    }

    /// The talker changes from now on, for `stream/subscribe`.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<TalkerChanged> {
        self.events.subscribe()
    }

    /// Frees the channel, whoever holds it (`backchannel/release`): its
    /// route stops at once, and the next session to send claims it, the
    /// released one included. Returns the session that held it.
    pub(crate) fn release(&self) -> Option<String> {
        let talker = self.lock().talker.take()?;
        let (session, reason) = (talker.session.as_str(), ChangeReason::Released.code());
        tracing::info!(
            session,
            reason,
            "talk-back: backchannel released; the next session to send claims it"
        );
        self.emit(&talker.session, ChangeReason::Released);
        Some(talker.session)
    }

    /// The session holding `claim` closed: the channel is free if it still
    /// held it.
    fn session_closed(&self, session: &str, claim: u64) {
        let talker = {
            let mut state = self.lock();
            if state.talker.as_ref().is_some_and(|t| t.claim == claim) {
                state.talker.take()
            } else {
                None
            }
        };
        if talker.is_some() {
            let reason = ChangeReason::SessionClosed.code();
            tracing::info!(
                session,
                reason,
                "talk-back: the talker's session closed; backchannel free"
            );
            self.emit(session, ChangeReason::SessionClosed);
        }
    }

    /// Decides one packet of `session`'s uplink `track` in `codec`:
    /// claims the channel if it is free, answers busy if another holds it,
    /// and for the talker makes sure its route serves the track and the
    /// backchannel offered now. `claim` is the session's, updated here.
    fn decide(
        &self,
        session: &str,
        claim: &mut Option<u64>,
        track: &Arc<Track>,
        codec: UplinkCodec,
        counters: &Arc<TalkbackStats>,
    ) -> Verdict {
        let offered = self.offered();
        let mut guard = self.lock();
        let state = &mut *guard;
        if let Some(talker) = &state.talker
            && Some(talker.claim) != *claim
        {
            *claim = None;
            return Verdict::Busy(talker.session.clone());
        }
        let next_claim = &mut state.next_claim;
        let talker = state.talker.get_or_insert_with(|| {
            let id = *next_claim;
            *next_claim = id.wrapping_add(1);
            *claim = Some(id);
            let reason = ChangeReason::Claimed.code();
            tracing::info!(
                session,
                reason,
                "talk-back: backchannel claimed; this session is the talker"
            );
            self.emit(session, ChangeReason::Claimed);
            Talker {
                session: session.to_owned(),
                claim: id,
                route: None,
            }
        });
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

    /// Sends a talker change to the subscribers; with none it goes nowhere.
    fn emit(&self, session: &str, reason: ChangeReason) {
        let _subscribers = self.events.send(TalkerChanged {
            session: session.to_owned(),
            reason,
            at: self.clock.wall_now(),
        });
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
/// connection's backchannel, its counters. Dropped with the session, which
/// frees the channel if it held it.
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

    /// Takes one uplink packet: opens a track for the first one or one in
    /// another codec, has the arbiter decide, and publishes it if the
    /// session is the talker with a way to the device. `true` when the
    /// session is to get its `backchannel_busy` warning now.
    pub(crate) fn receive(&mut self, packet: UplinkPacket) -> bool {
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
        let verdict = self.arbiter.decide(
            &self.session,
            &mut self.claim,
            track.track(),
            codec,
            &self.stats,
        );
        let warn = change(&mut self.flow, &verdict);
        match verdict {
            Verdict::Send => track.publish(packet),
            Verdict::Busy(_) => TalkbackStats::count(&self.stats.packets_dropped_busy),
            Verdict::Withdrawn | Verdict::Unroutable => {
                TalkbackStats::count(&self.stats.packets_dropped);
            }
        }
        warn
    }
}

/// Moves a session's talk-back from `current` to where `verdict` puts
/// it, logging a change;
/// `true` when it starts being refused.
fn change(current: &mut Flow, verdict: &Verdict) -> bool {
    let flow = match verdict {
        Verdict::Send => Flow::Talking,
        Verdict::Withdrawn => Flow::Withdrawn,
        Verdict::Unroutable => Flow::Unroutable,
        Verdict::Busy(_) => Flow::Busy,
    };
    if flow == *current {
        return false;
    }
    let from = std::mem::replace(current, flow);
    log_change(from, verdict);
    flow == Flow::Busy
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
        Verdict::Busy(holder) => tracing::info!(
            holder = %holder,
            code = BACKCHANNEL_BUSY,
            "talk-back refused: another session holds the backchannel; packets are dropped"
        ),
    }
}

impl Drop for Talkback {
    fn drop(&mut self) {
        if let Some(claim) = self.claim {
            self.arbiter.session_closed(&self.session, claim);
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
/// only against the answer. `true` when the session is to get its
/// `backchannel_busy` warning now.
pub(crate) fn receive(talkback: Option<&mut Talkback>, packet: UplinkPacket) -> bool {
    if let Some(talkback) = talkback {
        talkback.receive(packet)
    } else {
        let codec = packet.codec.name();
        tracing::trace!(
            codec,
            "talk-back packet dropped: the connection has no backchannel"
        );
        false
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

    fn talk(talkback: &mut Talkback, seq: u16) -> bool {
        talkback.receive(packet(UplinkCodec::Pcmu, 1, seq, &[0xff, 0xfe]))
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
        assert_eq!(BACKCHANNEL_BUSY, "backchannel_busy");
    }

    #[test]
    fn without_a_backchannel_talk_back_goes_nowhere() {
        assert!(!receive(None, packet(UplinkCodec::Opus, 1, 0, &[1])));
    }

    /// Claim and hold.
    #[tokio::test]
    async fn the_first_sender_claims_a_second_is_busy_once_and_the_holder_keeps_it_until_it_closes()
    {
        let (arbiter, slot) = arbiter(None);
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        // Neither holds the channel before it sends.
        no_change(&mut events);

        assert!(!talk(&mut a, 0), "the first sender is not refused");
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Claimed));
        let first = within(device.recv()).await.unwrap();
        assert_eq!((first.rtp.seq, &first.payload[..]), (0, &[0xff, 0xfe][..]));
        eventually("a's bytes counted", || load(&a.stats.bytes_sent) == 2).await;
        assert_eq!(load(&a.stats.packets_sent), 1);

        // The second sender: one warning, its packets dropped and counted.
        let warnings: Vec<bool> = (0..3).map(|seq| talk(&mut b, seq)).collect();
        assert_eq!(warnings, [true, false, false]);
        assert_eq!(load(&b.stats.packets_dropped_busy), 3);
        no_change(&mut events);
        // The holder sends on, and only its packets reach the device.
        assert!(!talk(&mut a, 1));
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 1);
        // Silent, the holder keeps it: no timeout frees it.
        SystemClock.sleep(Duration::from_millis(20)).await;
        assert!(!talk(&mut b, 3), "still refused, not warned again");
        assert_eq!(load(&b.stats.packets_dropped_busy), 4);
        assert!(device.try_recv().is_err(), "nothing of b's");

        // The holder's session closes: the channel is free, and the next
        // sender claims it.
        drop(a);
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("a", ChangeReason::SessionClosed)
        );
        assert!(!talk(&mut b, 4));
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
        assert_eq!(within(device.recv()).await.unwrap().rtp.seq, 4);
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert!(talk(&mut c, 0), "a new busy sender is warned");
        drop(c);
        no_change(&mut events);
        drop(b);
        let (session, reason) = change(&mut events);
        assert_eq!(
            (session.as_str(), reason),
            ("b", ChangeReason::SessionClosed)
        );
    }

    /// Hold, until `backchannel/release`.
    #[tokio::test]
    async fn a_release_frees_the_channel_for_the_next_sender_and_stops_the_talkers_route() {
        let uplink = Arc::new(FakeUplink::default());
        let (arbiter, slot) = arbiter(Some(Arc::new(Factory(Arc::clone(&uplink)))));
        let mut device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        assert_eq!(arbiter.release(), None, "nobody holds it");
        no_change(&mut events);
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        assert!(!talk(&mut a, 0));
        assert_eq!(change(&mut events).1, ChangeReason::Claimed);
        assert_eq!(
            within(device.recv()).await.unwrap().rtp.ssrc,
            9,
            "through the chain"
        );

        assert_eq!(arbiter.release().as_deref(), Some("a"));
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("a", ChangeReason::Released));
        assert!(
            uplink.stops.lock().unwrap()[0].is_cancelled(),
            "a's chain stopped at once"
        );
        assert!(uplink.outputs.lock().unwrap()[0].is_closed());
        // The next sender claims it; the released one, now refused, is
        // warned when it sends again.
        assert!(!talk(&mut b, 0));
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
        assert!(talk(&mut a, 1));
        assert_eq!(load(&a.stats.packets_dropped_busy), 1);
        // A stale claim frees nothing: a's session closing leaves b the
        // talker.
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert!(talk(&mut c, 0));
        drop(c);
        let mut d = Talkback::new(Arc::clone(&arbiter), "d".into(), Arc::default());
        drop(a);
        no_change(&mut events);
        assert!(talk(&mut d, 0), "b still holds it");
        // The released talker claims again when nobody else did.
        assert_eq!(arbiter.release().as_deref(), Some("b"));
        assert!(!talk(&mut b, 1));
        assert_eq!(change(&mut events).1, ChangeReason::Released);
        let (session, reason) = change(&mut events);
        assert_eq!((session.as_str(), reason), ("b", ChangeReason::Claimed));
    }

    /// A stale claim is not taken for a later one: a released talker that
    /// did not send since cannot free the next talker's channel.
    #[tokio::test]
    async fn a_released_talker_closing_frees_nothing_of_the_next_talkers() {
        let (arbiter, slot) = arbiter(None);
        let _device = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        assert!(!talk(&mut a, 0));
        assert_eq!(arbiter.release().as_deref(), Some("a"));
        assert!(!talk(&mut b, 0));
        let _claimed_released_claimed = (0..3).map(|_| change(&mut events)).count();
        drop(a);
        no_change(&mut events);
        let mut c = Talkback::new(Arc::clone(&arbiter), "c".into(), Arc::default());
        assert!(talk(&mut c, 0), "b still holds it");
    }

    /// A source reconnect.
    #[tokio::test]
    async fn across_a_reconnect_the_talker_keeps_the_slot_and_what_it_sends_meanwhile_is_dropped() {
        let (arbiter, slot) = arbiter(None);
        let mut before = pcmu(&slot);
        let mut events = arbiter.subscribe();
        let mut a = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::default());
        let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
        assert!(!talk(&mut a, 0));
        assert_eq!(within(before.recv()).await.unwrap().rtp.seq, 0);

        slot.withdraw();
        assert!(!talk(&mut a, 1));
        assert!(!talk(&mut a, 2));
        assert_eq!(load(&a.stats.packets_dropped), 2);
        // Nothing went to the old backchannel, and its route let go of it.
        assert!(within(before.recv()).await.is_none());
        assert!(talk(&mut b, 0), "the talker still holds the slot");

        let mut after = pcmu(&slot);
        assert!(!talk(&mut a, 3));
        let resumed = within(after.recv()).await.unwrap();
        assert_eq!(
            resumed.rtp.seq, 3,
            "nothing buffered from the withdrawn spell"
        );
        // Offered again without a withdrawal (another handle): the route
        // follows it.
        let mut replaced = pcmu(&slot);
        assert!(!talk(&mut a, 4));
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
        assert!(!a.receive(packet(UplinkCodec::Opus, 1, 0, &[1, 2, 3])));
        let out = within(device.recv()).await.unwrap();
        assert_eq!((out.rtp.ssrc, &out.payload[..]), (9, &[1, 2, 3][..]));
        eventually("bytes after the chain", || load(&a.stats.bytes_sent) == 3).await;
        assert_eq!(*uplink.frames.lock().unwrap(), [forty]);
        assert_eq!(*uplink.outputs.lock().unwrap()[0].codec(), Codec::Pcma);

        // Another codec: a new track, and the chain restarts on it.
        assert!(!a.receive(packet(UplinkCodec::Pcmu, 1, 1, &[4])));
        assert_eq!(&within(device.recv()).await.unwrap().payload[..], &[4]);
        assert!(uplink.stops.lock().unwrap()[0].is_cancelled());
        assert!(!uplink.stops.lock().unwrap()[1].is_cancelled());

        // The same codec on another frame or another law: new chains.
        let sixty = Duration::from_millis(60);
        let mut device = offer(&slot, Codec::Pcma, sixty, 64);
        assert!(!a.receive(packet(UplinkCodec::Pcmu, 1, 2, &[5])));
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
        assert!(!a.receive(packet(UplinkCodec::Pcmu, 1, 3, &[6])));
        assert!(!a.receive(packet(UplinkCodec::Pcmu, 1, 4, &[7])));
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
        assert!(!a.receive(packet(UplinkCodec::Opus, 7, 0, &[9, 9])));
        // A new SSRC starts an epoch on the track; the forwarder skips the
        // event and forwards the packet.
        assert!(!a.receive(packet(UplinkCodec::Opus, 8, 1, &[8])));
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
            let mut b = Talkback::new(Arc::clone(&arbiter), "b".into(), Arc::default());
            for seq in 0..2 {
                assert!(!a.receive(packet(UplinkCodec::Opus, 1, seq, &[1])));
            }
            assert_eq!(load(&a.stats.packets_dropped), 2);
            assert!(talk(&mut b, 0), "a holds it all the same");
            assert!(!talk(&mut a, 2));
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
        for seq in 0..3 {
            assert!(!talk(&mut a, seq));
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
        ] {
            let change = talker_change(TalkerChanged {
                session: "a".into(),
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
            reason: ChangeReason::Claimed,
            at: UNIX_EPOCH - Duration::from_secs(1),
        });
        assert_eq!(before.at_ms, 0);
    }

    /// A supervisor link that fell behind goes on with the latest changes,
    /// and ends with the arbiter.
    #[tokio::test]
    async fn a_lagging_receiver_skips_to_the_latest_changes_and_ends_with_the_arbiter() {
        let (arbiter, _slot) = arbiter(None);
        let mut events = arbiter.subscribe();
        for round in 0..=EVENT_CAPACITY {
            arbiter.emit(&format!("s{round}"), ChangeReason::Claimed);
        }
        let first = within(next_change(&mut events)).await.unwrap();
        assert_eq!(first.session, "s1", "the oldest change was skipped");
        let mut last = first;
        while let Ok(change) = events.try_recv() {
            last = change;
        }
        assert_eq!(last.session, format!("s{EVENT_CAPACITY}"));
        drop(arbiter);
        assert_eq!(within(next_change(&mut events)).await, None);
    }
}
