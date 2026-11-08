//! The backchannel in a session of its own: a talker's claim opens it, its
//! release closes it, and the session that plays the stream never carries
//! it, so the camera's one backchannel is free whenever nobody talks.
//!
//! The session runs on a connection of its own, retina's sans-I/O core
//! driven on it ([`crate::driver`]): `DESCRIBE` with `Require:
//! www.onvif.org/ver20/backchannel` (ONVIF Streaming Specification §5.3.1),
//! `SETUP` of the answer's `a=sendonly` audio media alone, TCP interleaved
//! on its own channel pair (§5.3.2; RFC 2326 §10.4: the client chooses
//! which media it sets up), and `PLAY` with `Require`, after whose answer
//! the camera takes data and not before (§5.3). The claim's answer waits
//! for that `PLAY`, bounded by the source's read deadline and
//! [`BACKCHANNEL_OPEN_LIMIT`]. The connection bypasses the connect gate
//! (`sources.connect_concurrency`): a talker waits for it, and there is at
//! most one per camera being talked to. Then every packet the talker's
//! route hands over is stamped ([`Packetizer`], with retina's
//! `rtp::Sender`: payload type, SSRC and sequence numbers, RFC 3550 §5.1)
//! and queued on the backchannel's channel, with the Sender Reports (RFC
//! 3550 §6.4.1), and retina writes them between its requests (RFC 2326
//! §10.12) and keepalives as the session is polled. Queueing never waits:
//! while more than [`MAX_QUEUED`] bytes wait for the camera to take them,
//! a packet is dropped, its sequence number skipped, rather than queued,
//! so the talk-back stays near real time and the session keeps reading.
//! The release ends the session: its `TEARDOWN` with `Require` goes out
//! within the source's teardown budget ([`Camera::tear_down`]), and the
//! connection closes, as a camera may stay in two-way mode until it does.
//! Should the camera end the session first (its connection lost, a
//! request refused), the loss is reported with why, before its
//! `TEARDOWN`, which may take the teardown budget's retries on fresh
//! connections; nothing is opened again until the next claim. A session
//! opens only once the one before it closed on the camera, its bounded
//! `TEARDOWN` included ([`BackchannelTasks::spawn`]): a camera with one
//! backchannel refuses a `SETUP` of it while another session holds it
//! (`453 Not Enough Bandwidth`, RFC 2326 §11.3.3), so the claim that
//! follows a release waits for that close rather than race it.

use std::time::Duration;

use futures_util::FutureExt as _;
use lotse_core::clock::Clock;
use lotse_core::codec::Codec;
use lotse_core::media::MediaPacket;
use lotse_core::source::{
    BACKCHANNEL_OPEN_LIMIT, BackchannelOffer, BackchannelOpener, BackchannelRefused,
    BackchannelSession, BackchannelTasks, SourceError,
};
use lotse_core::task::BoxFuture;
use lotse_core::throttle::Throttle;
use retina::rtp::SenderOptions;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::camera::{Camera, backchannel_stream};
use super::probe::unanswered;
use super::session::{QUEUE, refusal};
use super::{BackchannelFormat, Packetizer};
use crate::driver::{self, Driver};
use crate::source::{play_options, within_on};

/// Above this many bytes queued in the driver for the camera, a talker's
/// packet is dropped rather than queued: 4 KiB, a quarter second of
/// 128 kbit/s, twice G.711's rate (RFC 3551 §4.5.14) with room for its
/// headers. The driver's queue (`queued_len`) holds only what the
/// connection refused; the kernel's send buffer, and for `rtsps` rustls's
/// plaintext buffer, sit in front of it and fill first. So the bound
/// limits what lotse holds for a camera that takes data too slowly, not
/// how far behind the talk-back can fall end to end; waiting for room
/// instead would stop the session reading what the camera sends.
const MAX_QUEUED: usize = 4 * 1024;

/// What an open backchannel session hands its claim: the codec and frame
/// the camera takes on it, and where the talker's packets go.
type Opened = (Codec, Duration, mpsc::Sender<MediaPacket>);

/// Opens the camera's backchannel in a session of its own for each claim.
#[derive(Debug)]
pub(crate) struct Opener {
    /// The camera.
    camera: Camera,
    /// The codec the probe found, which the claim's answer is negotiated
    /// for: a session whose `DESCRIBE` offers another is refused.
    codec: Codec,
    /// Where each session's task is tracked: the worker's shutdown waits
    /// for it, so the session's `TEARDOWN` (RFC 2326 §10.7) goes out
    /// before the worker exits.
    tasks: BackchannelTasks,
}

impl Opener {
    /// An opener for `camera`'s backchannel in `codec`, as its probe
    /// found it, its sessions' tasks tracked in `tasks`.
    pub(crate) const fn new(camera: Camera, codec: Codec, tasks: BackchannelTasks) -> Self {
        Self {
            camera,
            codec,
            tasks,
        }
    }
}

impl BackchannelOpener for Opener {
    fn open(&self) -> BoxFuture<'static, Result<BackchannelSession, BackchannelRefused>> {
        let close = CancellationToken::new();
        let (opened, open) = oneshot::channel();
        let (on_loss, lost) = oneshot::channel();
        // Tracked, not joined: the claim's drop closes it, and the
        // worker's shutdown waits for the task to end. It starts once the
        // session before it closed on the camera.
        let _session = self.tasks.spawn(
            "rtsp.backchannel",
            &close,
            run(
                self.camera.clone(),
                self.codec.clone(),
                close.clone(),
                opened,
                on_loss,
            ),
        );
        // Dropped before the session opens, the claim abandons it.
        let guard = close.drop_guard();
        Box::pin(async move {
            let gone = BackchannelRefused {
                status: None,
                message: "the backchannel session's task ended".to_owned(),
            };
            let (codec, frame, sender) = open.await.unwrap_or(Err(gone))?;
            Ok(BackchannelSession::new(
                codec,
                frame,
                sender,
                lost,
                guard.disarm(),
            ))
        })
    }
}

/// One backchannel session in `codec`, from its connection until it is
/// closed (`close`, cancelled when its holder drops it or its claim gives
/// up) or lost: the session or why it did not open goes to `opened`, and
/// why it ended on the camera's side after that to `on_loss`.
pub(crate) async fn run(
    camera: Camera,
    codec: Codec,
    close: CancellationToken,
    opened: oneshot::Sender<Result<Opened, BackchannelRefused>>,
    on_loss: oneshot::Sender<BackchannelRefused>,
) {
    tracing::info!(
        addr = %camera.addr,
        "rtsp: opening the camera's backchannel in a session of its own; its connection bypasses sources.connect_concurrency, as a talker waits for it"
    );
    Box::pin(session(&camera, &codec, &close, opened, on_loss)).await;
}

/// Tells why the session ended, if it did not close: to `opened` while it
/// is still there (the session did not open), else to `on_loss` (it was
/// lost). `None` for a session that closed.
fn tell(
    ended: Option<BackchannelRefused>,
    opened: Option<oneshot::Sender<Result<Opened, BackchannelRefused>>>,
    on_loss: oneshot::Sender<BackchannelRefused>,
) {
    let Some(why) = ended else {
        return;
    };
    if let Some(opened) = opened {
        tracing::warn!(
            status = why.status,
            error = %why,
            "rtsp: the camera's backchannel session did not open"
        );
        let _told = opened.send(Err(why));
    } else {
        tracing::warn!(
            status = why.status,
            error = %why,
            "rtsp: the camera's backchannel session was lost"
        );
        let _told = on_loss.send(why);
    }
}

/// The hold a claim waits for its session at most: the source's read
/// deadline, at most [`BACKCHANNEL_OPEN_LIMIT`].
fn hold(camera: &Camera) -> Duration {
    camera.deadline().min(BACKCHANNEL_OPEN_LIMIT)
}

/// Connects, opens the session in `codec` and forwards until it is closed
/// or fails, then tells why it failed ([`tell`]): before its `TEARDOWN`,
/// so the talker hears of a loss at once rather than once the teardown's
/// retries on fresh connections ran their budget. However it ended, a
/// session the camera set up gets its `TEARDOWN` within the budget, and
/// the connection closes ([`Camera::tear_down`]).
async fn session(
    camera: &Camera,
    codec: &Codec,
    close: &CancellationToken,
    opened: oneshot::Sender<Result<Opened, BackchannelRefused>>,
    on_loss: oneshot::Sender<BackchannelRefused>,
) {
    let mut opened = Some(opened);
    let hold = hold(camera);
    let start = camera.time.now();
    let mut driver = match camera.connect("backchannel session", hold, close).await {
        Ok(driver) => driver,
        Err(err) => return tell(Some(unanswered(err)), opened, on_loss),
    };
    let left = hold.saturating_sub(camera.time.now().saturating_duration_since(start));
    let ended = talk(camera, codec, &mut driver, left, close, &mut opened).await;
    let why = ended.as_ref().map_or_else(
        || "the backchannel session closed".to_owned(),
        ToString::to_string,
    );
    let closed = ended.is_none();
    tell(ended, opened, on_loss);
    camera.tear_down(driver, &why).await;
    if closed {
        tracing::info!("rtsp: backchannel session closed: TEARDOWN sent and its connection closed");
    }
}

/// The session on `driver`: the handshake in `codec` within `left`, the
/// session handed to `opened`, and the talker's packets forwarded until
/// the close or the loss.
async fn talk(
    camera: &Camera,
    codec: &Codec,
    driver: &mut Driver,
    left: Duration,
    close: &CancellationToken,
    opened: &mut Option<oneshot::Sender<Result<Opened, BackchannelRefused>>>,
) -> Option<BackchannelRefused> {
    let handshake = handshake(camera, codec, driver).map(Ok::<_, SourceError>);
    let shaken = within_on(&*camera.time, close, left, "backchannel session", handshake).await;
    let shaken = match shaken {
        Ok(shaken) => shaken,
        Err(err) => Err(unanswered(err)),
    };
    let (index, format) = match shaken {
        Ok(playing) => playing,
        Err(why) => return Some(why),
    };
    let (sender, uplink) = mpsc::channel(QUEUE);
    let frame = format.ptime.unwrap_or(BackchannelOffer::DEFAULT_FRAME);
    // A claim that gave up meanwhile takes nothing, and its drop closed
    // the session already: `forward` ends at once.
    let handed = (format.codec.clone(), frame, sender);
    if let Some(opened) = opened.take() {
        let _handed = opened.send(Ok(handed));
    }
    tracing::info!(
        index,
        codec = format.codec.name(),
        payload_type = format.payload_type,
        frame_ms = frame.as_millis(),
        "rtsp: backchannel session playing; the talker's packets go to the camera"
    );
    forward(driver, index, &format, uplink, close, camera).await
}

/// `DESCRIBE` with `Require`, `SETUP` of the backchannel media alone, TCP
/// interleaved, and `PLAY` with `Require`, on `driver`: the index of the
/// retina stream it sends on and the camera's format, or why not, with
/// the camera's status when it refused. A `DESCRIBE` whose answer offers
/// the backchannel in another codec than `codec`, the probe's, is refused
/// before the `SETUP`: the claim's answer is negotiated for the probe's
/// codec, and the talker's uplink would reach no other.
async fn handshake(
    camera: &Camera,
    codec: &Codec,
    driver: &mut Driver,
) -> Result<(usize, BackchannelFormat), BackchannelRefused> {
    let refused = |err: driver::Error| refusal(err.status_code(), &err.source_error(&camera.url));
    tracing::info!("rtsp: backchannel session: DESCRIBE with the backchannel's Require header");
    driver.describe(camera.target()).await.map_err(refused)?;
    let Some((index, offer)) = backchannel_stream(driver) else {
        return Err(BackchannelRefused {
            status: None,
            message: "the camera's answer offers no backchannel the talk-back chain can feed"
                .to_owned(),
        });
    };
    as_probed(codec, &offer.format.codec)?;
    tracing::info!(
        index,
        "rtsp: backchannel session: SETUP of the backchannel alone, TCP interleaved"
    );
    driver.setup(index).await.map_err(refused)?;
    tracing::info!("rtsp: backchannel session: PLAY with the backchannel's Require header");
    driver.play(play_options()).await.map_err(refused)?;
    Ok((index, offer.format))
}

/// Whether a session's `DESCRIBE` offers the backchannel in `described`,
/// the codec its probe found (`probed`), which the claim's answer is
/// negotiated for; else why the session is refused before its `SETUP`.
fn as_probed(probed: &Codec, described: &Codec) -> Result<(), BackchannelRefused> {
    if described == probed {
        return Ok(());
    }
    let (probed, described) = (probed.name(), described.name());
    tracing::info!(
        probed,
        described,
        "rtsp: backchannel session: the camera's answer offers another codec than its probe found, which the answer is negotiated for; refused before SETUP"
    );
    Err(BackchannelRefused {
        status: None,
        message: format!(
            "the camera's backchannel takes {described} now, not the {probed} its probe found and talk-back was negotiated for; the next probe, at the stream's reconnect, offers what it takes"
        ),
    })
}

/// Sends the talker's packets from `uplink` on retina's stream `index`,
/// stamped for the camera's `format` (RFC 3550 §5.1, with a random SSRC,
/// sequence start and timestamp offset), and keeps polling the session,
/// which writes what is queued, sends the keepalives (RFC 2326 §10.8) and
/// notices its loss: `None` once closed, else why it ended. Nothing here
/// waits for the camera to take data ([`queue`]), so a release always
/// reaches the session's bounded `TEARDOWN` ([`Camera::tear_down`]). The
/// session is polled before the uplink, so what was queued is written
/// before more is.
async fn forward(
    driver: &mut Driver,
    index: usize,
    format: &BackchannelFormat,
    mut uplink: mpsc::Receiver<MediaPacket>,
    close: &CancellationToken,
    camera: &Camera,
) -> Option<BackchannelRefused> {
    let mut packetizer = Packetizer::new(format, SenderOptions::default());
    let mut dropped = Throttle::default();
    loop {
        // `Some` once the session ended, with why.
        let ended = tokio::select! {
            biased;
            () = close.cancelled() => return None,
            // The camera's RTCP, or what else retina hands up: nothing the
            // backchannel uses.
            item = driver.next_item() => item.err(),
            Some(packet) = uplink.recv() => {
                queue(driver, index, &mut packetizer, &packet, &*camera.time, &mut dropped).err()
            }
        };
        if let Some(error) = ended {
            return Some(lost(&error, camera));
        }
    }
}

/// Queues `packet` on `driver`'s stream `index`, stamped by `packetizer`,
/// and a Sender Report when one is due; or, while more than
/// [`MAX_QUEUED`] bytes wait for the camera, drops it, its sequence number
/// skipped (RFC 3550 §5.1), counted in `dropped`'s rate-limited line. The
/// error is retina's when the stream takes no data.
fn queue(
    driver: &mut Driver,
    index: usize,
    packetizer: &mut Packetizer,
    packet: &MediaPacket,
    time: &dyn Clock,
    dropped: &mut Throttle,
) -> Result<(), driver::Error> {
    let queued = driver.queued_len();
    if queued > MAX_QUEUED {
        packetizer.skip(packet);
        if let Some(count) = dropped.hit(packet.arrival) {
            tracing::warn!(
                queued,
                count,
                "rtsp: backchannel packet dropped: the camera takes data slower than the talker sends it"
            );
        }
        return Ok(());
    }
    packetizer
        .packetize(packet, |rtp| driver.queue_rtp(index, rtp))
        .unwrap_or(Ok(()))?;
    match packetizer.sender_report(time.now(), time.wall_now()) {
        Some(report) => driver.queue_rtcp(index, &report),
        None => Ok(()),
    }
}

/// Why the session ended on the camera's side: the camera closed it, or
/// `error` says why.
fn lost(error: &driver::Error, camera: &Camera) -> BackchannelRefused {
    match error {
        driver::Error::Closed => BackchannelRefused {
            status: None,
            message: "the camera closed the backchannel session".to_owned(),
        },
        err => refusal(err.status_code(), &err.source_error(&camera.url)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::sync::Arc;
    use std::time::Instant;

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::source_url::SourceUrl;
    use lotse_core::task::spawn_named;
    use lotse_testing::fake_camera::{
        BackchannelCodec, BackchannelSetup, CameraBackchannel, ConnectionLog, Stats,
    };
    use lotse_testing::{CameraConfig, FakeCamera};

    use super::*;
    use crate::options::{RtspOptions, defaults};

    fn camera_at(cam: &FakeCamera) -> Camera {
        Camera {
            url: SourceUrl::parse(&cam.url()).unwrap(),
            options: RtspOptions {
                backchannel: true,
                ..defaults()
            },
            tls: None,
            addr: cam.addr(),
            time: Arc::new(SystemClock),
        }
    }

    #[test]
    fn a_session_the_camera_closed_without_an_error_says_so() {
        let camera = Camera {
            url: SourceUrl::parse("rtsp://127.0.0.1:1/stream").unwrap(),
            options: defaults(),
            tls: None,
            addr: "127.0.0.1:1".parse().unwrap(),
            time: Arc::new(SystemClock),
        };
        assert_eq!(
            lost(&driver::Error::Closed, &camera),
            BackchannelRefused {
                status: None,
                message: "the camera closed the backchannel session".into(),
            }
        );
        assert_eq!(
            hold(&camera),
            Duration::from_secs(8),
            "the limit, under 10 s"
        );
    }

    /// The claim gave up while the session opened (its answer's wait
    /// ended, which closes it): the session that opened anyway is torn
    /// down at once and its connection closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc2326_10_7_a_session_whose_claim_gave_up_is_torn_down_at_once() {
        let cam = FakeCamera::start(
            CameraConfig {
                backchannel: Some(CameraBackchannel::new(BackchannelCodec::Pcmu)),
                keep_open_on_teardown: true,
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let (opened, open) = oneshot::channel();
        drop(open);
        let (on_loss, _lost) = oneshot::channel();
        let close = CancellationToken::new();
        let session = spawn_named(
            "test.backchannel",
            run(camera_at(&cam), Codec::Pcmu, close.clone(), opened, on_loss),
        );
        let deadline = SystemClock.now() + Duration::from_secs(5);
        first_logged(&cam, deadline, |log| log.played).await;
        close.cancel();
        session.await.unwrap();
        let log = first_logged(&cam, deadline, |log| log.closed).await;
        assert!(log.played, "{log:?}");
        assert_eq!(log.teardown, Some(true), "{log:?}");
        assert!(log.closed_by_client, "{log:?}");
        cam.stop().await;
    }

    /// The tasks an opener's sessions run on are tracked where it was
    /// told, and end only once the session's `TEARDOWN` (RFC 2326 §10.7)
    /// was answered: once the wait for them is over at a worker's
    /// shutdown, the camera has seen it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc2326_10_7_a_tracked_session_task_ends_once_its_teardown_is_answered() {
        let cam = FakeCamera::start(
            CameraConfig {
                backchannel: Some(CameraBackchannel::new(BackchannelCodec::Pcmu)),
                keep_open_on_teardown: true,
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let tasks = BackchannelTasks::default();
        let opener = Opener::new(camera_at(&cam), Codec::Pcmu, tasks.clone());
        let session = opener.open().await.unwrap();
        assert_eq!(session.codec, Codec::Pcmu);
        assert_eq!(tasks.running(), 1);
        drop(session);
        tokio::select! {
            () = tasks.ended() => {}
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("the session's task never ended"),
        }
        let log = cam.stats().connection_log();
        assert_eq!(log[0].teardown, Some(true), "{log:?}");
        cam.stop().await;
    }

    /// The probe found PCMU, which the claim's answer is negotiated for,
    /// and the camera's answer to the session's own `DESCRIBE` offers
    /// Opus now: the session is refused before its `SETUP`, so the camera
    /// never plays a backchannel the talker's uplink cannot reach, and
    /// the claim is declined with why.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn onvif_5_3_2_a_session_whose_describe_changed_the_probes_codec_is_refused_before_setup()
    {
        let cam = FakeCamera::start(
            CameraConfig {
                backchannel: Some(CameraBackchannel::new(BackchannelCodec::Opus)),
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let tasks = BackchannelTasks::default();
        let opener = Opener::new(camera_at(&cam), Codec::Pcmu, tasks.clone());
        let refused = opener.open().await.unwrap_err();
        assert_eq!(
            refused,
            BackchannelRefused {
                status: None,
                message: "the camera's backchannel takes opus now, not the pcmu its probe found and talk-back was negotiated for; the next probe, at the stream's reconnect, offers what it takes".into(),
            }
        );
        let deadline = SystemClock.now() + Duration::from_secs(5);
        let log = first_logged(&cam, deadline, |log| log.closed).await;
        assert_eq!(log.describes, [true], "{log:?}");
        assert!(log.setups.is_empty(), "no SETUP: {log:?}");
        assert!(!log.played, "{log:?}");
        tokio::select! {
            () = tasks.ended() => {}
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("the session's task never ended"),
        }
        cam.stop().await;
    }

    /// A camera with one PCMU backchannel ([`CameraBackchannel::single`])
    /// that answers its requests as `setup` says.
    async fn one_backchannel(setup: BackchannelSetup) -> FakeCamera {
        let backchannel = CameraBackchannel {
            setup,
            single: true,
            ..CameraBackchannel::new(BackchannelCodec::Pcmu)
        };
        let config = CameraConfig {
            backchannel: Some(backchannel),
            ..CameraConfig::default()
        };
        FakeCamera::start(config, Arc::new(SystemClock))
            .await
            .unwrap()
    }

    /// A camera with one backchannel holds it for the released session
    /// until that session's connection closes, its `TEARDOWN` left
    /// unanswered: the session a claim opens right after the release
    /// waits for that close, the end of the `TEARDOWN`'s budget (RFC 2326
    /// §10.7), rather than race it into a `453` (RFC 2326 §11.3.3).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc2326_11_3_3_a_session_opened_after_a_release_while_playing_waits_for_its_close() {
        let cam = one_backchannel(BackchannelSetup::Lingering).await;
        let tasks = BackchannelTasks::default();
        let opener = Opener::new(camera_at(&cam), Codec::Pcmu, tasks.clone());
        let first = opener.open().await.unwrap();
        drop(first);
        let second = opener.open().await.unwrap();
        assert_eq!(second.codec, Codec::Pcmu);
        let stats = cam.stats();
        assert_eq!(Stats::get(&stats.backchannel_busy), 0, "never refused");
        let log = stats.connection_log();
        assert_eq!(log[0].teardown, Some(true), "{log:?}");
        assert!(log[0].closed_by_client, "{log:?}");
        assert!(log[1].played, "{log:?}");
        drop(second);
        tokio::select! {
            () = tasks.ended() => {}
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("the sessions' tasks never ended"),
        }
        cam.stop().await;
    }

    /// A claim released while its session opens drops the open: the
    /// handshake is abandoned, its `SETUP` taken by the camera and never
    /// answered ending with its connection, and the session the next
    /// claim opens gets the camera's one backchannel (RFC 2326 §11.3.3)
    /// once the abandoned one closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc2326_11_3_3_a_session_opened_after_a_release_while_opening_gets_the_backchannel() {
        let cam = one_backchannel(BackchannelSetup::Silent).await;
        let tasks = BackchannelTasks::default();
        let opener = Opener::new(camera_at(&cam), Codec::Pcmu, tasks.clone());
        let opening = opener.open();
        let deadline = SystemClock.now() + Duration::from_secs(5);
        first_logged(&cam, deadline, |log| !log.setups.is_empty()).await;
        drop(opening);
        cam.set_backchannel_setup(BackchannelSetup::Accept);
        let session = opener.open().await.unwrap();
        let stats = cam.stats();
        assert_eq!(Stats::get(&stats.backchannel_busy), 0, "never refused");
        let log = stats.connection_log();
        assert!(!log[0].played, "{log:?}");
        assert!(log[0].closed_by_client, "{log:?}");
        assert!(log[1].played, "{log:?}");
        drop(session);
        tokio::select! {
            () = tasks.ended() => {}
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("the sessions' tasks never ended"),
        }
        cam.stop().await;
    }

    /// A camera that stops taking data once its backchannel plays: the
    /// talker's packets fill the TCP buffers, and those beyond
    /// [`MAX_QUEUED`] are dropped rather than queued, so the forwarding
    /// never waits on the camera, and the release ends the session within
    /// the teardown budget (RFC 2326 §10.7), its connection closed, rather
    /// than leaving the task waiting with the camera's connection open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc2326_10_7_a_release_while_the_camera_takes_no_data_ends_the_session() {
        let cam = FakeCamera::start(
            CameraConfig {
                backchannel: Some(CameraBackchannel {
                    setup: BackchannelSetup::Deaf,
                    ..CameraBackchannel::new(BackchannelCodec::Pcmu)
                }),
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let (opened, open) = oneshot::channel();
        let (on_loss, _lost) = oneshot::channel();
        let close = CancellationToken::new();
        let mut session = spawn_named(
            "test.backchannel",
            run(camera_at(&cam), Codec::Pcmu, close.clone(), opened, on_loss),
        );
        let (_codec, _frame, sender) = open.await.unwrap().unwrap();
        // 60 MB, packets as large as interleaved data carries (RFC 2326
        // §10.12): far more than the TCP buffers between retina and the
        // camera hold, and each is still taken at once.
        for ts in 0_u32..1_000 {
            tokio::select! {
                sent = sender.send(large(ts)) => sent.unwrap(),
                () = SystemClock.sleep(Duration::from_secs(1)) => panic!("the forwarding waited on the camera"),
            }
        }
        close.cancel();
        tokio::select! {
            ended = &mut session => ended.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(2)) => panic!("the session outlived the release"),
        }
        let log = cam.stats().connection_log();
        assert!(log[0].played, "{log:?}");
        assert_eq!(log[0].teardown, None, "the camera read nothing more");
        cam.stop().await;
    }

    /// A packet retina refuses to queue (here on a stream past the
    /// session's last) ends the forwarding with retina's error as the
    /// session's loss, as any other failure of the session does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_packet_retina_refuses_to_queue_ends_the_session_with_why() {
        let cam = FakeCamera::start(
            CameraConfig {
                backchannel: Some(CameraBackchannel::new(BackchannelCodec::Pcmu)),
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let camera = camera_at(&cam);
        let mut driver = connected(&camera).await;
        let (_index, format) = handshake(&camera, &Codec::Pcmu, &mut driver).await.unwrap();
        let streams = driver.streams().len();
        let (sender, uplink) = mpsc::channel(1);
        sender.send(large(0)).await.unwrap();
        let close = CancellationToken::new();
        let refused = forward(&mut driver, streams, &format, uplink, &close, &camera)
            .await
            .unwrap();
        assert_eq!(refused.status, None);
        assert!(
            refused.message.ends_with(&format!(
                "Invalid argument: can't send on stream {streams}: presentation has only {streams} streams"
            )),
            "{refused:?}"
        );
        camera.tear_down(driver, &"the test ended").await;
        cam.stop().await;
    }

    /// A driver connected to `camera`.
    async fn connected(camera: &Camera) -> Driver {
        camera
            .connect("test", Duration::from_secs(5), &CancellationToken::new())
            .await
            .unwrap()
    }

    /// A PCMU packet whose payload is as large as one interleaved frame
    /// carries after its RTP header.
    fn large(ts: u32) -> MediaPacket {
        pcmu(ts, 60_000)
    }

    /// The `ts`th 20 ms PCMU packet, with `len` bytes of payload.
    fn pcmu(ts: u32, len: usize) -> MediaPacket {
        MediaPacket {
            arrival: SystemClock.now(),
            rtp: lotse_core::media::RtpHeaderFields {
                pt: 0,
                seq: 0,
                ts: ts.wrapping_mul(160),
                marker: false,
                ssrc: 1,
            },
            frame_start: true,
            keyframe_start: false,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(vec![0xff_u8; len]),
        }
    }

    /// While more than [`MAX_QUEUED`] bytes wait for the camera, a packet
    /// is dropped rather than queued: the session, never polled here,
    /// writes nothing, and its queue stops growing at the first packet
    /// past the bound, while the dropped packets keep their sequence
    /// numbers, so the camera sees the gap (RFC 3550 §5.1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc3550_5_1_past_the_queue_bound_packets_are_dropped_with_their_sequence_numbers() {
        let cam = FakeCamera::start(
            CameraConfig {
                backchannel: Some(CameraBackchannel::new(BackchannelCodec::Pcmu)),
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let camera = camera_at(&cam);
        let mut driver = connected(&camera).await;
        let (index, format) = handshake(&camera, &Codec::Pcmu, &mut driver).await.unwrap();
        let options = SenderOptions::default().initial_sequence_number(0);
        let mut packetizer = Packetizer::new(&format, options);
        let mut dropped = Throttle::default();
        let mut queued = Vec::new();
        for ts in 0..100 {
            queue(
                &mut driver,
                index,
                &mut packetizer,
                &pcmu(ts, 160),
                &SystemClock,
                &mut dropped,
            )
            .unwrap();
            queued.push(driver.queued_len());
        }
        let over = queued.iter().position(|len| *len > MAX_QUEUED).unwrap();
        assert!(over > 10, "{queued:?}");
        assert!(
            queued[over..].iter().all(|len| *len == queued[over]),
            "{queued:?}"
        );
        let next = packetizer.packetize(&pcmu(100, 160), |rtp| rtp.header().sequence_number());
        assert_eq!(next, Some(100));
        camera.tear_down(driver, &"the test ended").await;
        cam.stop().await;
    }

    /// The bound is exceeded only past it: a packet is still queued while
    /// exactly [`MAX_QUEUED`] bytes wait, and the next is dropped. The
    /// clock stands still, so no Sender Report after the first is due.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_packet_is_queued_while_exactly_the_bound_waits() {
        let cam = FakeCamera::start(
            CameraConfig {
                backchannel: Some(CameraBackchannel::new(BackchannelCodec::Pcmu)),
                ..CameraConfig::default()
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let camera = camera_at(&cam);
        let mut driver = connected(&camera).await;
        let (index, format) = handshake(&camera, &Codec::Pcmu, &mut driver).await.unwrap();
        let mut packetizer = Packetizer::new(&format, SenderOptions::default());
        let mut dropped = Throttle::default();
        let clock = FakeClock::from_system();
        let mut send = |ts: u32, len: usize| {
            queue(
                &mut driver,
                index,
                &mut packetizer,
                &pcmu(ts, len),
                &clock,
                &mut dropped,
            )
            .unwrap();
            driver.queued_len()
        };
        let first = send(0, 160);
        let second = send(1, 160);
        let header = second - first - 160;
        assert_eq!(send(2, MAX_QUEUED - second - header), MAX_QUEUED);
        let past = send(3, 160);
        assert_eq!(past, MAX_QUEUED + header + 160);
        assert_eq!(send(4, 160), past);
        camera.tear_down(driver, &"the test ended").await;
        cam.stop().await;
    }

    /// What `cam` logged of its first connection once `done` holds for
    /// it, before `deadline`: one wait for every step of a test, so its
    /// polling runs whichever step has to wait.
    async fn first_logged(
        cam: &FakeCamera,
        deadline: Instant,
        done: impl Fn(&ConnectionLog) -> bool,
    ) -> ConnectionLog {
        loop {
            let log = cam.stats().connection_log();
            if let Some(first) = log.first().filter(|first| done(first)) {
                return first.clone();
            }
            assert!(SystemClock.now() < deadline, "{log:?}");
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
    }
}
