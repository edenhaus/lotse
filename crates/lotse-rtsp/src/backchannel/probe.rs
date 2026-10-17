//! The probe of the camera's backchannel: once the stream's session plays,
//! a connection that asks for it (a stream on it opted in) has the camera
//! asked, on a connection of its own, whether it has a backchannel, and
//! the answer offered on the connection's slot, where a talker's claim
//! finds it.
//!
//! One `DESCRIBE` with `Require: www.onvif.org/ver20/backchannel` (ONVIF
//! Streaming Specification §5.3.1), then the connection closes: a
//! `DESCRIBE` sets nothing up, so the camera holds nothing for it. The
//! answer's `a=sendonly` audio media (§5.3.2) gives the backchannel's
//! codec, payload type and `a=ptime` (RFC 8866 §6.4). A `551 Option not
//! supported` means the camera has none (§5.3.2), remembered for the
//! source ([`Probed`]); any other failure means none for this connection
//! attempt, and the next one asks again, as every connect does: a
//! rebooted camera may answer differently. The probe waits for a connect
//! permit (`sources.connect_concurrency`) like any connection attempt,
//! and ends within [`PROBE_TIMEOUT`] of its grant, connection and answer
//! included, whatever the source's `timeout_ms`: no probe holds a permit
//! past the lease the supervisor keeps on it.
//!
//! The connection turns the probe on and off as its streams opt in and out
//! ([`BackchannelSlot::ask`]), without the session that plays the stream
//! noticing: an opt-in while it plays probes at once, one while it is down
//! at its next connect; an opt-out drops what the probe found, and a probe
//! still running offers nothing.

use std::future::Future;
use std::sync::Arc;

use futures_util::FutureExt as _;
use lotse_core::runner::PROBE_TIMEOUT;
use lotse_core::source::{
    Asks, BackchannelOffer, BackchannelRefused, BackchannelSlot, ProbeMark, SourceError,
};
use retina::client::{Session, SessionGroup};
use tokio_util::sync::CancellationToken;

use super::BackchannelFormat;
use super::camera::{Camera, backchannel_stream};
use super::open::Opener;
use super::session::{Probed, refusal};
use crate::error::classify;
use crate::factory::BACKCHANNEL;
use crate::source::within_on;

/// A probe under way on a slot: claims wait for it until it settles the
/// slot, and one dropped first (its attempt ended) leaves what the slot
/// offered before. Both by its mark, so a probe whose aborted task ends
/// after the next attempt's probe started leaves that one's alone; and an
/// aborted attempt's follower that goes on after the next attempt started
/// starts none ([`BackchannelSlot::asks`]), so it holds no mark newer
/// than that one's.
struct Probing {
    /// The slot.
    slot: BackchannelSlot,
    /// The probe's mark on the slot.
    mark: ProbeMark,
    /// The probe offered or withdrew.
    settled: bool,
}

impl Probing {
    /// Marks `slot` as probed now, for the ask `asks` saw last: `None`
    /// once the connection's ask changed since, when the probe would be
    /// for an ask that no longer stands, or once a later connection
    /// attempt started, when it would be an ended attempt's; the slot
    /// stays as it is then ([`BackchannelSlot::probing_for`]).
    fn start(slot: &BackchannelSlot, asks: &Asks) -> Option<Self> {
        let mark = slot.probing_for(asks)?;
        Some(Self {
            slot: slot.clone(),
            mark,
            settled: false,
        })
    }

    /// The probe found `offer`.
    fn found(mut self, offer: BackchannelOffer) {
        self.slot.settle(self.mark, Some(offer));
        self.settled = true;
    }

    /// The probe found none.
    fn none(mut self) {
        self.slot.settle(self.mark, None);
        self.settled = true;
    }
}

impl Drop for Probing {
    fn drop(&mut self) {
        if !self.settled {
            self.slot.abandon_probe(self.mark);
            tracing::debug!(
                "rtsp: backchannel probe abandoned with its attempt; the offer stays as it was"
            );
        }
    }
}

/// The probes of `camera`'s backchannel for a connection attempt that
/// plays now. When the connection asks for the backchannel (as `slot`
/// says, else as the stream's option does) and the camera did not answer
/// `551` before (`probed`), `slot` is marked probed at once, before the
/// attempt reports its tracks ready, so a claim that comes with the first
/// session waits for the probe. The future probes, offers what it found
/// on `slot`, and then follows the connection's opt-ins and opt-outs
/// ([`follow`]). The attempt runs it as a task it aborts when it ends.
pub(crate) fn start(
    camera: Camera,
    slot: BackchannelSlot,
    probed: Probed,
) -> impl Future<Output = ()> + Send + 'static {
    let asks = slot.asks();
    let wanted = asks.now().unwrap_or(camera.options.backchannel);
    let first = due(wanted, &slot, &probed, &asks);
    follow(camera, slot, probed, asks, first)
}

/// The probe `wanted` makes due on `slot`, marked there, unless the camera
/// answered `551` before (`probed`): then the probe an opt-in made due
/// will not run, and `slot` stops awaiting it. Either only while the ask
/// is the one `asks` saw last ([`BackchannelSlot::probing_for`],
/// [`BackchannelSlot::forgo_probe`]): a newer one's probe stays due until
/// this source sees that ask, and none starts for the stale one, whose end
/// would end the wait the newer one began. And either only while `asks`
/// follows for the attempt that runs now: the follower of an attempt that
/// ended may go on after the next one started, as its abort only asks,
/// and the next attempt decides then. Not wanted, `slot` stays as it
/// is: the opt-out already ended what it had due
/// ([`BackchannelSlot::ask`]), and a stale one must not end the probe a
/// newer opt-in made due.
fn due(wanted: bool, slot: &BackchannelSlot, probed: &Probed, asks: &Asks) -> Option<Probing> {
    if probed.asks(BACKCHANNEL, wanted) {
        return Probing::start(slot, asks);
    }
    if wanted {
        slot.forgo_probe(asks);
    }
    None
}

/// Runs `first`, the probe due when the attempt played, then follows the
/// connection's ask (`asks`) until the attempt ends: an opt-in probes
/// again, an opt-out drops a probe still running, whose result the slot
/// would drop anyway ([`BackchannelSlot::settle`]).
async fn follow(
    camera: Camera,
    slot: BackchannelSlot,
    probed: Probed,
    mut asks: Asks,
    first: Option<Probing>,
) {
    let mut probing = first;
    loop {
        let asked = match probing.take() {
            Some(probe) => {
                tokio::select! {
                    () = run(&camera, probe, &probed) => asks.next().await,
                    asked = asks.next() => {
                        tracing::info!(
                            asked,
                            "rtsp: the connection's ask for the backchannel changed while it was probed; that probe is dropped"
                        );
                        asked
                    }
                }
            }
            None => asks.next().await,
        };
        if asked {
            tracing::info!(
                reason = "a stream on the connection opted in",
                "rtsp: probing the camera's backchannel now; the viewing session plays on"
            );
        } else {
            tracing::info!(
                reason = "no stream on the connection asks for the backchannel any more",
                "rtsp: no backchannel probe; what the last one found is dropped"
            );
        }
        probing = due(asked, &slot, &probed, &asks);
    }
}

/// Runs the probe [`start`] marked on its slot.
async fn run(camera: &Camera, probing: Probing, probed: &Probed) {
    tracing::info!(
        "rtsp: probing the camera's backchannel on a connection of its own; waiting for a connect permit"
    );
    let permit = probing.slot.probes().permit().await;
    tracing::info!("rtsp: connect permit for the backchannel probe granted");
    // Aborted with its attempt: nothing else cancels it.
    let described = Box::pin(describe(camera, &CancellationToken::new())).await;
    drop(permit);
    match described {
        Ok(Some(format)) => {
            let frame = format.ptime.unwrap_or(BackchannelOffer::DEFAULT_FRAME);
            let codec = format.codec.clone();
            let tasks = probing.slot.tasks().clone();
            tracing::info!(
                codec = codec.name(),
                payload_type = format.payload_type,
                frame_ms = frame.as_millis(),
                "rtsp: backchannel offered; a talker's claim opens it in a session of its own"
            );
            probing.found(BackchannelOffer {
                codec,
                frame,
                opener: Arc::new(Opener::new(camera.clone(), format.codec, tasks)),
            });
        }
        Ok(None) => {
            tracing::info!(
                "rtsp: the camera's answer to the probe offers no backchannel the talk-back chain can feed; none"
            );
            probing.none();
        }
        Err(why) => {
            if !probed.refused_with(why.status) {
                tracing::warn!(
                    status = why.status,
                    error = %why,
                    "rtsp: the backchannel probe failed; no backchannel for this connection attempt, the next one asks again"
                );
            }
            probing.none();
        }
    }
}

/// A probe the camera did not answer: its connection failed, timed out
/// or was cancelled.
#[expect(
    clippy::needless_pass_by_value,
    reason = "a `map_err` callback, which takes the error by value"
)]
pub(crate) fn unanswered(error: SourceError) -> BackchannelRefused {
    refusal(None, &error)
}

/// One `DESCRIBE` with `Require` on a connection of its own, all of it
/// within [`PROBE_TIMEOUT`], however long the source's `timeout_ms` lets
/// each step take: the backchannel's format, `None` when the answer has
/// none the talk-back chain can feed, or why it failed, with the camera's
/// status when it answered one.
async fn describe(
    camera: &Camera,
    cancel: &CancellationToken,
) -> Result<Option<BackchannelFormat>, BackchannelRefused> {
    let probe = ask(camera, cancel).map(Ok::<_, SourceError>);
    within_on(
        &*camera.time,
        cancel,
        PROBE_TIMEOUT,
        "backchannel probe",
        probe,
    )
    .await
    .map_err(unanswered)?
}

/// [`describe`]'s steps, each within the source's `timeout_ms`.
async fn ask(
    camera: &Camera,
    cancel: &CancellationToken,
) -> Result<Option<BackchannelFormat>, BackchannelRefused> {
    let deadline = camera.deadline();
    let (stream, listening, target) = camera
        .connect("backchannel probe", deadline, cancel)
        .await
        .map_err(unanswered)?;
    // Nothing is set up, so nothing is torn down: the group stays empty.
    let group = Arc::new(SessionGroup::default());
    let options = camera.session_options(&group);
    let describe = async {
        tracing::info!("rtsp: probe: DESCRIBE with the backchannel's Require header");
        let request = Session::describe(target, options).map(Ok::<_, SourceError>);
        let answered = within_on(&*camera.time, cancel, deadline, "probe DESCRIBE", request)
            .await
            .map_err(unanswered)?;
        let session =
            answered.map_err(|err| refusal(err.status_code(), &classify(&err, &camera.url)))?;
        Ok(backchannel_stream(&session).map(|(_, offer)| offer.format))
    };
    let probed = Box::pin(camera.relayed(stream, listening, describe))
        .await
        .map_err(unanswered)?;
    tracing::debug!("rtsp: probe over; its connection closes");
    probed
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::clock::{Clock, FakeClock, SystemClock};
    use lotse_core::source_url::SourceUrl;
    use std::time::Duration;

    use lotse_core::task::spawn_named;
    use lotse_testing::{CameraConfig, FakeCamera};

    use super::*;
    use crate::options::RtspOptions;
    use crate::relay::Listener;

    fn camera_at(addr: std::net::SocketAddr, timeout_ms: u64) -> Camera {
        timed(addr, timeout_ms, Arc::new(SystemClock))
    }

    fn timed(addr: std::net::SocketAddr, timeout_ms: u64, time: Arc<dyn Clock>) -> Camera {
        Camera {
            url: SourceUrl::parse(&format!("rtsp://{addr}/stream")).unwrap(),
            options: RtspOptions {
                backchannel: true,
                timeout_ms,
                ..RtspOptions::default()
            },
            tls: None,
            relay: Listener::default(),
            addr,
            time,
        }
    }

    /// The whole probe, connection and `DESCRIBE`, ends within
    /// `PROBE_TIMEOUT`, however long the source's `timeout_ms` lets each
    /// step wait: it gives its connect permit back in time.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_probe_ends_within_the_probe_timeout_whatever_the_read_deadline() {
        let silent = FakeCamera::start(
            CameraConfig {
                silent: true,
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let time = Arc::new(FakeClock::from_system());
        let camera = timed(silent.addr(), 60_000, time.clone());
        let probe = spawn_named("test.probe", async move {
            describe(&camera, &CancellationToken::new()).await
        });
        // Connected, so the probe's deadline runs.
        let mut waited = 0;
        while silent.stats().connection_log().is_empty() && waited < 500 {
            SystemClock.sleep(Duration::from_millis(10)).await;
            waited += 1;
        }
        assert_eq!(silent.stats().connection_log().len(), 1, "connected");
        time.advance(PROBE_TIMEOUT.checked_sub(Duration::from_millis(1)).unwrap());
        SystemClock.sleep(Duration::from_millis(100)).await;
        assert!(!probe.is_finished(), "not over yet");
        time.advance(Duration::from_millis(1));
        let refused = tokio::select! {
            done = probe => done.unwrap().unwrap_err(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("outlived its timeout"),
        };
        assert_eq!(refused.status, None);
        assert!(
            refused
                .message
                .contains("backchannel probe: no answer within 30000 ms"),
            "{refused:?}"
        );
        silent.stop().await;
    }

    /// A probe that cannot reach the camera, or that the camera never
    /// answers, finds nothing and says why, without a status.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_probe_unanswered_says_why_without_a_status() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let refused = describe(&camera_at(addr, 1_000), &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(refused.status, None);
        assert!(refused.message.contains("Unable to connect"), "{refused:?}");
        let silent = FakeCamera::start(
            CameraConfig {
                silent: true,
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let refused = describe(&camera_at(silent.addr(), 200), &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(refused.status, None);
        assert!(
            refused
                .message
                .contains("probe DESCRIBE: no answer within 200 ms"),
            "{refused:?}"
        );
        // A connection that does not ask leaves the slot unmarked.
        let slot = BackchannelSlot::default();
        let mut quiet = camera_at(silent.addr(), 200);
        quiet.options.backchannel = false;
        drop(start(quiet, slot.clone(), Probed::default()));
        assert!(!slot.is_probing());
        // One dropped before it settled abandons, and the slot waits no
        // more.
        let probe = start(
            camera_at(silent.addr(), 200),
            slot.clone(),
            Probed::default(),
        );
        assert!(slot.is_probing());
        drop(probe);
        assert!(!slot.is_probing());
        silent.stop().await;
    }

    /// The probe of an attempt that ended is aborted, and its task may be
    /// dropped only after the next attempt's probe marked the slot: then
    /// the slot still awaits the next probe, and a claim waits for it
    /// rather than declining at once.
    #[tokio::test]
    async fn a_probe_dropped_after_its_replacement_started_leaves_it_awaited() {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
        let slot = BackchannelSlot::default();
        let earlier = start(camera_at(addr, 200), slot.clone(), Probed::default());
        let later = start(camera_at(addr, 200), slot.clone(), Probed::default());
        drop(earlier);
        assert!(slot.awaits_probe(), "the replacement still runs");
        let waiting = slot.clone();
        let settled = spawn_named("test.settled", async move { waiting.settled().await });
        tokio::task::yield_now().await;
        assert!(!settled.is_finished(), "a claim waits for the replacement");
        drop(later);
        assert!(!slot.is_probing());
        let settled = tokio::select! {
            settled = settled => settled.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("still waiting"),
        };
        assert!(settled.is_none(), "nothing was offered");
    }

    /// The follower of an attempt that ended is aborted, but an abort only
    /// asks: one that took the connection's opt-in may go on only after
    /// the next attempt started and marked its probe (here: polled only
    /// then). It starts no probe of its own then, so its end abandons
    /// nothing and no result of it is offered: a claim waits for the next
    /// attempt's probe, whose result alone settles the slot.
    #[tokio::test]
    async fn a_follower_going_on_after_the_next_attempt_marked_its_probe_leaves_it_awaited() {
        use lotse_testing::fake_camera::{BackchannelCodec, CameraBackchannel};

        let fake = FakeCamera::start(
            CameraConfig {
                backchannel: Some(CameraBackchannel::new(BackchannelCodec::Pcmu)),
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let slot = BackchannelSlot::default();
        let probed = Probed::default();
        // The ended attempt's follower, which probed nothing at first: the
        // connection had not asked, and the stream's option does not.
        let mut unasked = camera_at(fake.addr(), 1_000);
        unasked.options.backchannel = false;
        let mut ended = Box::pin(start(unasked, slot.clone(), probed.clone()));
        assert!(!slot.is_probing());
        // A stream opts in, and the next attempt starts and marks its
        // probe before the ended attempt's follower takes the opt-in.
        assert!(slot.ask(true));
        let next = start(camera_at(fake.addr(), 1_000), slot.clone(), probed.clone());
        assert!(slot.awaits_probe(), "the next attempt's probe is marked");
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(ended.as_mut().poll(&mut cx).is_pending());
        drop(ended);
        assert!(slot.awaits_probe(), "the next attempt's probe is awaited");
        let waiting = slot.clone();
        let settled = spawn_named("test.settled", async move { waiting.settled().await });
        tokio::task::yield_now().await;
        assert!(!settled.is_finished(), "a claim waits for it");
        let next = spawn_named("test.next", next);
        let offered = bounded(settled).await.unwrap().expect("offered");
        assert_eq!(offered.codec, lotse_core::codec::Codec::Pcmu);
        assert!(!slot.is_probing());
        assert_eq!(
            fake.stats().connection_log().len(),
            1,
            "only the next attempt probed"
        );
        next.abort();
        fake.stop().await;
    }

    /// The source took an opt-out, and an opt-in came before it decided on
    /// that opt-out: the stale opt-out leaves the slot alone, so a claim
    /// waits for the probe the opt-in made due rather than being declined
    /// at once, and the source probes once it sees the opt-in. With the
    /// camera's `551` remembered, the probe due ends only for the ask the
    /// source saw: a newer one's stays due until the source sees it.
    #[tokio::test]
    async fn a_stale_ask_leaves_the_probe_a_newer_opt_in_made_due() {
        let slot = BackchannelSlot::default();
        let mut asks = slot.asks();
        let probed = Probed::default();
        // Not asked by the connection or the stream's option: a probe
        // marked by another stays as it is.
        let other = slot.probing();
        assert!(due(false, &slot, &probed, &asks).is_none());
        assert!(slot.awaits_probe(), "untouched");
        slot.abandon_probe(other);
        // Out, taken by the source; in before it decided.
        assert!(slot.ask(false));
        assert!(!bounded(asks.next()).await);
        assert!(slot.ask(true));
        assert!(due(false, &slot, &probed, &asks).is_none());
        assert!(slot.awaits_probe(), "the opt-in's probe stays due");
        let waiting = slot.clone();
        let settled = spawn_named("test.settled", async move { waiting.settled().await });
        tokio::task::yield_now().await;
        assert!(!settled.is_finished(), "a claim waits for it");
        assert!(bounded(asks.next()).await);
        let probe = due(true, &slot, &probed, &asks).expect("probes the opt-in");
        probe.none();
        assert!(bounded(settled).await.unwrap().is_none(), "found none");
        // The camera answered 551: in, taken by the source; out and in
        // before it decided.
        assert!(probed.refused_with(Some(551)));
        assert!(slot.ask(false) && slot.ask(true));
        assert!(bounded(asks.next()).await);
        assert!(slot.ask(false) && slot.ask(true));
        assert!(due(true, &slot, &probed, &asks).is_none());
        assert!(slot.awaits_probe(), "the newer opt-in's probe stays due");
        assert!(bounded(asks.next()).await);
        assert!(due(true, &slot, &probed, &asks).is_none());
        assert!(!slot.is_probing(), "settled once the source saw it");
    }

    /// The source took an opt-in, and an opt-out and another opt-in came
    /// before it started the probe, the camera's `551` not remembered: the
    /// stale opt-in starts no probe, so none of it is dropped once the
    /// source sees the newer one, which would end the wait that one began.
    /// A claim waits for the newer opt-in's probe rather than being
    /// declined at once, and the source probes once it sees that ask.
    #[tokio::test]
    async fn a_stale_opt_in_starts_no_probe_and_leaves_the_newer_ones_due() {
        let slot = BackchannelSlot::default();
        let mut asks = slot.asks();
        let probed = Probed::default();
        assert!(slot.ask(true));
        assert!(bounded(asks.next()).await);
        assert!(slot.ask(false) && slot.ask(true));
        assert!(
            due(true, &slot, &probed, &asks).is_none(),
            "the stale opt-in starts no probe"
        );
        assert!(slot.awaits_probe(), "the newer opt-in's probe stays due");
        let waiting = slot.clone();
        let settled = spawn_named("test.settled", async move { waiting.settled().await });
        tokio::task::yield_now().await;
        assert!(!settled.is_finished(), "a claim waits for it");
        assert!(bounded(asks.next()).await);
        let probe = due(true, &slot, &probed, &asks).expect("probes the newer opt-in");
        tokio::task::yield_now().await;
        assert!(!settled.is_finished(), "a claim still waits for it");
        probe.none();
        assert!(bounded(settled).await.unwrap().is_none(), "found none");
    }

    /// `future`'s output, or a failed test after five seconds.
    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::select! {
            output = future => output,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
        }
    }
}
