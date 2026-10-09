//! The output conformance suite: one set of checks, instantiated per
//! session output kind (WebRTC in M1), fed by a scripted track and read
//! back through the headless viewer.
//!
//! The session runs the way the worker runs it: live packets from a real
//! [`Track`] subscription, every track event through core's
//! [`apply_track_event`], the join from the GOP cache when the engine
//! reports `Connected`. Everything moves in memory on a simulated clock.
//! Each check returns the violation it found, so a new output kind is
//! merged when [`check_all`] finds none.
//!
//! A/V offset at the output (40 ms, EBU R37) joins the suite with audio
//! sessions in M2.

use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_codec::h264::{DEFAULT_MAX_PAYLOAD, PacketNormalizer, ParameterSets, test_data};
use lotse_core::codec::{Codec, CodecFamily, Kind};
use lotse_core::media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields};
use lotse_core::output::OutputFactory;
use lotse_core::session::{
    IceCredentials, SessionEngine, SessionEvent, SessionLimits, SessionOutput, SessionRequest,
    SessionStats, Transport, apply_track_event,
};
use lotse_core::source::TrackSet;
use lotse_core::track::{Track, TrackLimits, TrackSubscription, Unit};
use str0m::rtp::RtpPacket;

use crate::viewer::{Outgoing, Viewer, starts_keyframe};

/// The viewer's address.
const BROWSER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20)),
    40_000,
);

/// The daemon's host candidate.
const DAEMON: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
    18_556,
);

/// Ticks between frames: 30 fps at 90 kHz.
const FRAME_TICKS: u32 = 3_000;

/// The simulated time between frames.
const FRAME_INTERVAL: Duration = Duration::from_millis(33);

/// Steps a check may take to reach what it waits for.
const MAX_STEPS: usize = 2_000;

/// Steps that let everything in flight arrive: half a second simulated,
/// far beyond the pacer and the path.
const SETTLE_STEPS: usize = 15;

/// A check's outcome: `Err` names the violation.
pub type Check = Result<(), String>;

/// Publishes a scripted H.264 stream into a track: each access unit as the
/// RTSP source publishes it (normalized RFC 6184 packets on the live path)
/// and as a frame for the GOP cache. The camera's timestamps follow the
/// capture time at 90 kHz, a frame interval apart at least, so a frame is
/// only late when a check makes it so.
pub struct TrackDriver {
    /// Keeps the track's set alive.
    _set: Arc<TrackSet>,
    /// The video track.
    track: Arc<Track>,
    /// The packet-layer normalizer, as in the RTSP source.
    normalizer: PacketNormalizer,
    /// The next RTP sequence number.
    seq: u16,
    /// The next RTP timestamp, one frame after the last.
    ts: u32,
    /// The capture time and timestamp the camera's clock counts from;
    /// `None` until the first frame after a (re)start.
    anchor: Option<(Instant, u32)>,
}

impl std::fmt::Debug for TrackDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackDriver")
            .field("seq", &self.seq)
            .field("ts", &self.ts)
            .finish_non_exhaustive()
    }
}

/// The H.264 descriptor the driver declares.
fn h264() -> Codec {
    Codec::H264 {
        profile_level_id: Some([0x42, 0xc0, 0x28]),
        sps: None,
        pps: None,
    }
}

/// An access unit in Annex B: the parameter sets and an IDR, or a P slice.
fn access_unit(keyframe: bool, bytes: usize) -> Bytes {
    let mut out = Vec::new();
    if keyframe {
        for nal in [test_data::sps(640, 480), test_data::pps()] {
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(&nal);
        }
    }
    out.extend_from_slice(&[0, 0, 0, 1]);
    out.push(if keyframe { 0x65 } else { 0x41 });
    out.extend(std::iter::repeat_n(0x5a, bytes));
    Bytes::from(out)
}

impl TrackDriver {
    /// A driver of a fresh H.264 track with `limits`, created at `now`.
    pub fn new(limits: TrackLimits, now: Instant) -> Self {
        let set = TrackSet::new(limits, now);
        let mut publisher = set.publisher();
        let track = publisher.declare(Kind::Video, h264(), 90_000);
        publisher.ready();
        let sets = ParameterSets {
            sps: Some(Bytes::from(test_data::sps(640, 480))),
            pps: Some(Bytes::from(test_data::pps())),
        };
        Self {
            _set: set,
            track,
            normalizer: PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, sets),
            seq: 1_000,
            ts: 90_000,
            anchor: None,
        }
    }

    /// The track.
    pub const fn track(&self) -> &Arc<Track> {
        &self.track
    }

    /// Restarts the camera's RTP timestamps, as a reconnect does.
    pub const fn reset_timestamps(&mut self, ts: u32) {
        self.ts = ts;
        self.anchor = None;
    }

    /// Publishes one access unit captured and read at `arrival`; returns
    /// how many packets went out on the live path.
    pub fn frame(&mut self, keyframe: bool, arrival: Instant) -> usize {
        self.frame_captured(keyframe, arrival, arrival)
    }

    /// The camera's timestamp for a frame captured at `captured`: on its
    /// 90 kHz clock, and a frame interval after the last at least.
    fn timestamp(&mut self, captured: Instant) -> u32 {
        let Some((at, ts)) = self.anchor else {
            self.anchor = Some((captured, self.ts));
            return self.ts;
        };
        let elapsed = captured.saturating_duration_since(at).as_millis();
        let ticks = u32::try_from(elapsed.saturating_mul(90)).unwrap_or(u32::MAX);
        let paced = ts.wrapping_add(ticks);
        // RFC 1982 order: the paced timestamp when it is ahead.
        if paced.wrapping_sub(self.ts) < (1_u32 << 31) {
            paced
        } else {
            self.ts
        }
    }

    /// Publishes one access unit captured at `captured` that the source
    /// read at `arrival`, later when the ingest stalled; returns how many
    /// packets went out on the live path.
    pub fn frame_captured(&mut self, keyframe: bool, captured: Instant, arrival: Instant) -> usize {
        let ts = self.timestamp(captured);
        let unit = access_unit(keyframe, 1_500);
        let nals: Vec<&[u8]> = lotse_codec::h264::annex_b_units(&unit);
        let last = nals.len().saturating_sub(1);
        let mut out = Vec::new();
        let mut published = 0_usize;
        for (index, nal) in nals.iter().enumerate() {
            if self
                .normalizer
                .normalize(ts, index == last, &Bytes::copy_from_slice(nal), &mut out)
                .is_err()
            {
                continue;
            }
            for packet in out.drain(..) {
                self.track.publish_packet(MediaPacket {
                    arrival,
                    rtp: RtpHeaderFields {
                        pt: 96,
                        seq: self.seq,
                        ts,
                        marker: packet.marker,
                        ssrc: 1,
                    },
                    frame_start: packet.frame_start,
                    keyframe_start: packet.keyframe_start,
                    epoch: 0,
                    lateness: Duration::ZERO,
                    payload: Arc::from(packet.payload.as_ref()),
                });
                self.seq = self.seq.wrapping_add(1);
                published = published.saturating_add(1);
            }
        }
        let _cached = self.track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(i64::from(ts)),
            wallclock: arrival,
            arrival,
            keyframe,
            discontinuity: false,
            epoch: 0,
            payload: unit,
        });
        self.ts = ts.wrapping_add(FRAME_TICKS);
        published
    }
}

/// Polls `future` once: its output if it is ready now.
fn ready_now<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

/// One session of the output under test, driven the way the worker drives
/// it, with the headless viewer on the other side.
pub struct SessionUnderTest {
    /// The engine.
    engine: Box<dyn SessionEngine>,
    /// The video family the session opened with.
    family: CodecFamily,
    /// The track it serves.
    track: Arc<Track>,
    /// Its live packets and events.
    subscription: TrackSubscription,
    /// The viewer.
    viewer: Viewer,
    /// The simulated time.
    now: Instant,
    /// The engine's events, in order.
    events: Vec<SessionEvent>,
    /// Datagrams from the engine to the viewer.
    to_viewer: Vec<(SocketAddr, Vec<u8>)>,
    /// Datagrams from the viewer to the engine.
    to_daemon: Vec<Outgoing>,
    /// The engine's next timeout.
    timeout: Option<Instant>,
    /// The `closed` the engine reported.
    closed: Option<&'static str>,
}

impl std::fmt::Debug for SessionUnderTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionUnderTest")
            .field("events", &self.events)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl SessionUnderTest {
    /// Opens a session of `factory` on `track` at `now` and applies the
    /// answer to the viewer.
    pub fn open(
        factory: &dyn OutputFactory,
        track: &Arc<Track>,
        now: Instant,
    ) -> Result<Self, String> {
        let viewer = Viewer::new(BROWSER, now)?;
        let request = SessionRequest {
            offer: viewer.offer().to_owned(),
            ice: IceCredentials {
                ufrag: "suiteufrag".into(),
                pass: "suitepassword0123456789ab".into(),
            },
            candidates: vec![DAEMON],
            tcp_candidates: vec![],
            video: track.codec(),
            audio: None,
            orientation: lotse_core::Orientation::default(),
            limits: SessionLimits::default(),
            wall: std::time::SystemTime::UNIX_EPOCH,
        };
        let (engine, answer) = factory
            .open_session(request, now)
            .map_err(|err| format!("the output refused the session: {err}"))?;
        let mut session = Self {
            engine,
            family: track.codec().family(),
            track: Arc::clone(track),
            subscription: track.subscribe(Unit::Packets),
            viewer,
            now,
            events: Vec::new(),
            to_viewer: Vec::new(),
            to_daemon: Vec::new(),
            timeout: None,
            closed: None,
        };
        session
            .viewer
            .accept_answer(&answer, &mut session.to_daemon)?;
        session.drain();
        Ok(session)
    }

    /// Steps until the viewer is connected (and the join is done).
    pub fn connect(&mut self) -> Check {
        self.run_until(|s| s.viewer.is_connected(), "connected")
    }

    /// The simulated time now.
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// The RTP packets the viewer received, in order.
    pub fn received(&self) -> &[RtpPacket] {
        self.viewer.packets()
    }

    /// The engine's counters.
    pub fn stats(&self) -> SessionStats {
        self.engine.stats()
    }

    /// The `closed` code, once the engine reported one.
    pub const fn closed(&self) -> Option<&'static str> {
        self.closed
    }

    /// Ends the session as the supervisor would.
    pub fn close(&mut self) {
        self.engine
            .close(self.now, "session_closed", "suite".to_owned());
        self.drain();
    }

    /// Hands every track event that is ready to the engine.
    pub fn pump_track(&mut self) {
        while self.closed.is_none() {
            let Some(event) = ready_now(self.subscription.next()) else {
                break;
            };
            let ended = event.is_none();
            apply_track_event(
                self.engine.as_mut(),
                self.now,
                self.family,
                event,
                |packet| packet.arrival,
            );
            self.drain();
            if ended {
                break;
            }
        }
    }

    /// Advances at most one frame interval, to the next timeout when
    /// sooner, and moves the track's events and the datagrams in flight.
    pub fn step(&mut self) {
        let cap = self.now.checked_add(FRAME_INTERVAL).unwrap_or(self.now);
        let floor = self
            .now
            .checked_add(Duration::from_millis(1))
            .unwrap_or(self.now);
        let earliest = [self.timeout, self.viewer.next_timeout()]
            .into_iter()
            .flatten()
            .min();
        self.now = earliest.map_or(cap, |at| at.clamp(floor, cap));
        self.engine.handle_timeout(self.now);
        self.drain();
        self.pump_track();
        self.viewer.timeout(self.now, &mut self.to_daemon);
        for (source, bytes) in std::mem::take(&mut self.to_viewer) {
            self.viewer
                .receive(self.now, source, &bytes, &mut self.to_daemon);
        }
        for datagram in std::mem::take(&mut self.to_daemon) {
            self.engine.handle_datagram(
                self.now,
                Transport::Udp,
                datagram.source,
                datagram.destination,
                &datagram.payload,
            );
            self.drain();
        }
    }

    /// Steps until `done` holds.
    pub fn run_until(&mut self, done: impl Fn(&Self) -> bool, what: &str) -> Check {
        for _ in 0..MAX_STEPS {
            if done(self) {
                return Ok(());
            }
            self.step();
        }
        Err(format!("{what}: not reached; events {:?}", self.events))
    }

    /// Steps until what is in flight has arrived.
    pub fn settle(&mut self) {
        for _ in 0..SETTLE_STEPS {
            self.step();
        }
    }

    /// Takes everything the engine has: datagrams, events, the join on
    /// `Connected`, and its next timeout.
    fn drain(&mut self) {
        loop {
            match self.engine.poll() {
                SessionOutput::Transmit {
                    source, payload, ..
                } => self.to_viewer.push((source, payload)),
                SessionOutput::Event(SessionEvent::Connected) => {
                    let gop = self.track.gop();
                    self.engine.join(self.now, gop.as_deref());
                }
                SessionOutput::Event(SessionEvent::Closed { code, message }) => {
                    self.closed.get_or_insert(code);
                    self.events.push(SessionEvent::Closed { code, message });
                }
                SessionOutput::Event(event) => self.events.push(event),
                SessionOutput::Timeout(at) => {
                    self.timeout = Some(at);
                    return;
                }
            }
        }
    }
}

/// A connected session on a fresh track whose GOP cache holds a keyframe
/// and two P-frames.
fn connected(
    factory: &dyn OutputFactory,
    limits: TrackLimits,
    now: Instant,
) -> Result<(TrackDriver, SessionUnderTest), String> {
    let mut driver = TrackDriver::new(limits, now);
    let mut session = SessionUnderTest::open(factory, driver.track(), now)?;
    for keyframe in [true, false, false] {
        let _published = driver.frame(keyframe, session.now());
    }
    session.pump_track();
    session.connect()?;
    session.settle();
    Ok((driver, session))
}

/// Publishes a frame at the session's time and lets it arrive; `what`
/// fails when nothing new reached the viewer.
fn live_frame(
    driver: &mut TrackDriver,
    session: &mut SessionUnderTest,
    keyframe: bool,
    what: &str,
) -> Check {
    let before = session.received().len();
    let _published = driver.frame(keyframe, session.now());
    session.pump_track();
    session.settle();
    if session.received().len() > before {
        Ok(())
    } else {
        Err(format!("{what}: nothing reached the viewer"))
    }
}

/// Whether an RFC 6184 payload begins a keyframe: the parameter sets the
/// normalizer puts in front of every IDR (a single SPS or a STAP-A
/// starting with one, §5.7.1), or the IDR itself.
fn begins_keyframe(payload: &[u8]) -> bool {
    const SPS: u8 = 7;
    const STAP_A: u8 = 24;
    match payload.first().map(|b| b & 0x1f) {
        Some(SPS) => true,
        Some(STAP_A) => payload.get(3).is_some_and(|b| b & 0x1f == SPS) || starts_keyframe(payload),
        _ => starts_keyframe(payload),
    }
}

/// Whether the viewer's packets keep one sequence space without holes.
fn contiguous(packets: &[RtpPacket]) -> bool {
    packets
        .windows(2)
        .all(|pair| matches!(pair, [a, b] if *b.seq_no == (*a.seq_no).wrapping_add(1)))
}

/// Joins at the live edge: the first packet the viewer gets starts a
/// keyframe (a catch-up burst or a still from the GOP cache), live packets
/// follow in one contiguous sequence space.
pub fn joins_at_the_live_edge(factory: &dyn OutputFactory, now: Instant) -> Check {
    let (mut driver, mut session) = connected(factory, TrackLimits::default(), now)?;
    let first = session
        .received()
        .first()
        .map(|p| begins_keyframe(&p.payload));
    if first != Some(true) {
        return Err("the first packet of the join does not start a keyframe".into());
    }
    for keyframe in [false, false, true, false] {
        live_frame(&mut driver, &mut session, keyframe, "live packets")?;
    }
    if !contiguous(session.received()) {
        return Err("the sequence numbers are not contiguous".into());
    }
    Ok(())
}

/// Checks that the packets after `from` start with a keyframe: nothing of
/// the P-frames in between reached the viewer.
fn resumes_on_a_keyframe(session: &SessionUnderTest, from: usize, what: &str) -> Check {
    match session.received().get(from) {
        Some(packet) if begins_keyframe(&packet.payload) => Ok(()),
        Some(_) => Err(format!(
            "{what}: a P-frame reached the viewer before the keyframe"
        )),
        None => Err(format!("{what}: nothing reached the viewer after it")),
    }
}

/// A lagging session gets a `Gap` and skips to the next keyframe; the
/// producer published without waiting for it.
pub fn a_gap_skips_to_the_next_keyframe(factory: &dyn OutputFactory, now: Instant) -> Check {
    let limits = TrackLimits {
        packet_capacity: 4,
        ..TrackLimits::default()
    };
    let (mut driver, mut session) = connected(factory, limits, now)?;
    let before = session.received().len();
    // Far more than the subscription holds, without the session reading:
    // publishing never waits for a subscriber.
    for _ in 0..8 {
        let _published = driver.frame(false, session.now());
    }
    session.pump_track();
    if session.stats().skips == 0 {
        return Err("no skip after the subscription lagged".into());
    }
    let _published = driver.frame(false, session.now());
    live_frame(
        &mut driver,
        &mut session,
        true,
        "the keyframe after the gap",
    )?;
    resumes_on_a_keyframe(&session, before, "after a gap")
}

/// A new epoch (reconnect) waits for its keyframe, and the session's RTP
/// clock and sequence continue across it.
pub fn a_new_epoch_waits_for_its_keyframe_and_continues_the_clock(
    factory: &dyn OutputFactory,
    now: Instant,
) -> Check {
    let (mut driver, mut session) = connected(factory, TrackLimits::default(), now)?;
    live_frame(&mut driver, &mut session, false, "live before the epoch")?;
    let before = session.received().len();
    let last_ts = session.received().last().map_or(0, |p| p.header.timestamp);
    let _epoch = driver.track().start_epoch();
    // The camera restarts its clock, mid-GOP.
    driver.reset_timestamps(3_000);
    let _published = driver.frame(false, session.now());
    session.pump_track();
    live_frame(&mut driver, &mut session, true, "the new epoch's keyframe")?;
    resumes_on_a_keyframe(&session, before, "after a new epoch")?;
    let first_ts = session
        .received()
        .get(before)
        .map_or(0, |p| p.header.timestamp);
    if first_ts.wrapping_sub(last_ts) > 90_000 || first_ts == last_ts {
        return Err(format!(
            "the RTP clock jumped across the epoch: {last_ts} then {first_ts}"
        ));
    }
    if !contiguous(session.received()) {
        return Err("the sequence numbers are not contiguous across the epoch".into());
    }
    Ok(())
}

/// A codec change within the family keeps the session; another family
/// closes it with `stream_changed`.
pub fn a_codec_change_closes_only_on_another_family(
    factory: &dyn OutputFactory,
    now: Instant,
) -> Check {
    let (driver, mut session) = connected(factory, TrackLimits::default(), now)?;
    driver.track().set_codec(Codec::H264 {
        profile_level_id: Some([0x64, 0x00, 0x28]),
        sps: None,
        pps: None,
    });
    session.pump_track();
    if let Some(code) = session.closed() {
        return Err(format!("closed with {code} on a profile change"));
    }
    driver.track().set_codec(Codec::H265 {
        vps: None,
        sps: None,
        pps: None,
    });
    session.pump_track();
    match session.closed() {
        Some("stream_changed") => Ok(()),
        other => Err(format!("an H.265 track closed the session with {other:?}")),
    }
}

/// Losing and regaining the source keeps the session; media resumes with
/// the new epoch's keyframe.
pub fn source_loss_keeps_the_session(factory: &dyn OutputFactory, now: Instant) -> Check {
    let (mut driver, mut session) = connected(factory, TrackLimits::default(), now)?;
    driver.track().set_source_lost(true);
    for _ in 0..30 {
        session.step();
    }
    driver.track().set_source_lost(false);
    let _epoch = driver.track().start_epoch();
    session.pump_track();
    if let Some(code) = session.closed() {
        return Err(format!("closed with {code} while the source reconnected"));
    }
    let before = session.received().len();
    live_frame(&mut driver, &mut session, true, "media after the reconnect")?;
    resumes_on_a_keyframe(&session, before, "after the reconnect")
}

/// A closed track ends the session with `stream_deleted`.
pub fn a_closed_track_ends_the_session(factory: &dyn OutputFactory, now: Instant) -> Check {
    let (driver, mut session) = connected(factory, TrackLimits::default(), now)?;
    driver.track().close();
    session.pump_track();
    match session.closed() {
        Some("stream_deleted") => Ok(()),
        other => Err(format!("a closed track ended the session with {other:?}")),
    }
}

/// A live packet older than the age bound is dropped, and the session
/// waits for the next keyframe rather than falling behind.
pub fn live_packets_are_bounded_by_age(factory: &dyn OutputFactory, now: Instant) -> Check {
    let (mut driver, mut session) = connected(factory, TrackLimits::default(), now)?;
    let before = session.received().len();
    let stale = session
        .now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(|| session.now());
    let _published = driver.frame(false, stale);
    session.pump_track();
    if session.stats().dropped_old == 0 {
        return Err("a packet one second old was not dropped".into());
    }
    let _published = driver.frame(false, session.now());
    live_frame(
        &mut driver,
        &mut session,
        true,
        "the keyframe after the stale packet",
    )?;
    resumes_on_a_keyframe(&session, before, "after a stale packet")
}

/// How long the ingest stall of the lateness check lasts: well past
/// `max_ingest_lateness` (200 ms) for the frames it holds back.
const STALL: Duration = Duration::from_millis(400);

/// The frames an ingest stall held back arrive late in one burst: a live
/// session drops them and waits for a timely keyframe instead of falling
/// behind by the stall.
pub fn late_frames_after_an_ingest_stall_skip_to_a_timely_keyframe(
    factory: &dyn OutputFactory,
    now: Instant,
) -> Check {
    let (mut driver, mut session) = connected(factory, TrackLimits::default(), now)?;
    live_frame(&mut driver, &mut session, false, "live before the stall")?;
    let stalled_at = session.now();
    let resumed_at = stalled_at.checked_add(STALL).unwrap_or(stalled_at);
    session.run_until(|s| s.now() >= resumed_at, "the stall")?;
    let before = session.received().len();
    let mut captured = stalled_at;
    for _ in 0..3 {
        captured = captured.checked_add(FRAME_INTERVAL).unwrap_or(captured);
        let _published = driver.frame_captured(false, captured, session.now());
    }
    session.pump_track();
    session.settle();
    if session.stats().ingest_late_skips == 0 {
        return Err("frames held back by a stall were not skipped as late".into());
    }
    let _published = driver.frame(false, session.now());
    live_frame(
        &mut driver,
        &mut session,
        true,
        "the keyframe after the stall",
    )?;
    resumes_on_a_keyframe(&session, before, "after an ingest stall")
}

/// A close ends the session at once: `closed` on the same instant, well
/// within 100 ms.
pub fn a_close_is_immediate(factory: &dyn OutputFactory, now: Instant) -> Check {
    let (_driver, mut session) = connected(factory, TrackLimits::default(), now)?;
    session.close();
    match session.closed() {
        Some("session_closed") => Ok(()),
        other => Err(format!("close reported {other:?} without time passing")),
    }
}

/// One check: it opens its own sessions of the factory at the instant.
pub type CheckFn = fn(&dyn OutputFactory, Instant) -> Check;

/// Every check, by name.
pub const CHECKS: [(&str, CheckFn); 9] = [
    ("joins_at_the_live_edge", joins_at_the_live_edge),
    (
        "a_gap_skips_to_the_next_keyframe",
        a_gap_skips_to_the_next_keyframe,
    ),
    (
        "a_new_epoch_waits_for_its_keyframe_and_continues_the_clock",
        a_new_epoch_waits_for_its_keyframe_and_continues_the_clock,
    ),
    (
        "a_codec_change_closes_only_on_another_family",
        a_codec_change_closes_only_on_another_family,
    ),
    (
        "source_loss_keeps_the_session",
        source_loss_keeps_the_session,
    ),
    (
        "a_closed_track_ends_the_session",
        a_closed_track_ends_the_session,
    ),
    (
        "live_packets_are_bounded_by_age",
        live_packets_are_bounded_by_age,
    ),
    (
        "late_frames_after_an_ingest_stall_skip_to_a_timely_keyframe",
        late_frames_after_an_ingest_stall_skip_to_a_timely_keyframe,
    ),
    ("a_close_is_immediate", a_close_is_immediate),
];

/// Runs every check against `factory`; the violations, by check name.
pub fn check_all(factory: &dyn OutputFactory, now: Instant) -> Vec<(&'static str, String)> {
    CHECKS
        .iter()
        .filter_map(|(name, check)| check(factory, now).err().map(|err| (*name, err)))
        .collect()
}
