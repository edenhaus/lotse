//! The backchannel in a session of its own: a talker's claim opens it, its
//! release closes it, and the session that plays the stream never carries
//! it, so the camera's one backchannel is free whenever nobody talks.
//!
//! The session runs on a connection of its own: `DESCRIBE` with `Require:
//! www.onvif.org/ver20/backchannel` (ONVIF Streaming Specification §5.3.1),
//! `SETUP` of the answer's `a=sendonly` audio media alone, TCP interleaved
//! on its own channel pair (§5.3.2; RFC 2326 §10.4: the client chooses
//! which media it sets up), and `PLAY` with `Require`, after whose answer
//! the camera takes data and not before (§5.3). The claim's answer waits
//! for that `PLAY`, bounded by the source's read deadline and
//! [`BACKCHANNEL_OPEN_LIMIT`]. The connection bypasses the connect gate
//! (`sources.connect_concurrency`): a talker waits for it, and there is at
//! most one per camera being talked to. Then every packet the talker's
//! route hands over is stamped ([`Packetizer`]) and sent on the
//! backchannel's channel between retina's requests (RFC 2326 §10.12), with
//! retina's own SSRC, sequence numbers, Sender Reports (RFC 3550 §5.1,
//! §6.4.1) and keepalives. The release drops the session: retina sends its
//! `TEARDOWN` with `Require`, and the connection closes, as a camera may
//! stay in two-way mode until it does. Should the camera end the session
//! first (its connection lost, a request refused), the loss is reported
//! with why; nothing is opened again until the next claim.

use std::time::Duration;

use bytes::Bytes;
use futures_util::{FutureExt as _, SinkExt as _, StreamExt as _};
use lotse_core::codec::Codec;
use lotse_core::media::MediaPacket;
use lotse_core::source::{
    BACKCHANNEL_OPEN_LIMIT, BackchannelOffer, BackchannelOpener, BackchannelRefused,
    BackchannelSession, BackchannelTasks, SourceError,
};
use lotse_core::task::BoxFuture;
use retina::client::{
    Playing, Session, SessionGroup, SetupOptions, TcpTransportOptions, Transport,
};
use retina::rtp::SendingPacket;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::camera::{Camera, backchannel_stream};
use super::probe::unanswered;
use super::session::{QUEUE, refusal};
use super::{BackchannelFormat, BackchannelPacket, Initial, Packetizer};
use crate::error::classify;
use crate::source::{play_options, tear_down, within_on};

/// Where a backchannel session's [`Packetizer`] starts: retina assigns the
/// SSRC and the sequence numbers itself and adds a random offset to the
/// timestamps (RFC 3550 §5.1, §8.1), so a random start of the
/// packetizer's own ([`Initial::random`]) would add nothing. Its
/// timestamps count from zero, a starting point [`SendingPacket::new`]
/// leaves to the caller.
const FROM_ZERO: Initial = Initial {
    ssrc: 0,
    seq: 0,
    ts: 0,
};

/// What an open backchannel session hands its claim: the codec and frame
/// the camera takes on it, and where the talker's packets go.
type Opened = (Codec, Duration, mpsc::Sender<MediaPacket>);

/// Opens the camera's backchannel in a session of its own for each claim.
#[derive(Debug)]
pub(crate) struct Opener {
    /// The camera.
    camera: Camera,
    /// Where each session's task is tracked: the worker's shutdown waits
    /// for it, so the session's `TEARDOWN` (RFC 2326 §10.7) goes out
    /// before the worker exits.
    tasks: BackchannelTasks,
}

impl Opener {
    /// An opener for `camera`'s backchannel, its sessions' tasks tracked
    /// in `tasks`.
    pub(crate) const fn new(camera: Camera, tasks: BackchannelTasks) -> Self {
        Self { camera, tasks }
    }
}

impl BackchannelOpener for Opener {
    fn open(&self) -> BoxFuture<'static, Result<BackchannelSession, BackchannelRefused>> {
        let close = CancellationToken::new();
        let (opened, open) = oneshot::channel();
        let (on_loss, lost) = oneshot::channel();
        // Tracked, not joined: the claim's drop closes it, and the
        // worker's shutdown waits for the task to end.
        let _session = self.tasks.spawn(
            "rtsp.backchannel",
            run(self.camera.clone(), close.clone(), opened, on_loss),
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

/// One backchannel session, from its connection until it is closed
/// (`close`, cancelled when its holder drops it or its claim gives up) or
/// lost: the session or why it did not open goes to `opened`, and why it
/// ended on the camera's side after that to `on_loss`.
pub(crate) async fn run(
    camera: Camera,
    close: CancellationToken,
    opened: oneshot::Sender<Result<Opened, BackchannelRefused>>,
    on_loss: oneshot::Sender<BackchannelRefused>,
) {
    tracing::info!(
        addr = %camera.addr,
        "rtsp: opening the camera's backchannel in a session of its own; its connection bypasses sources.connect_concurrency, as a talker waits for it"
    );
    let mut opened = Some(opened);
    let Some(why) = Box::pin(session(&camera, &close, &mut opened)).await else {
        tracing::info!("rtsp: backchannel session closed: TEARDOWN sent and its connection closed");
        return;
    };
    if let Some(opened) = opened.take() {
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

/// Connects, opens the session and forwards until it is closed (`None`)
/// or fails: why, sent by [`run`] to `opened` while it is still there,
/// else reported as the session's loss.
async fn session(
    camera: &Camera,
    close: &CancellationToken,
    opened: &mut Option<oneshot::Sender<Result<Opened, BackchannelRefused>>>,
) -> Option<BackchannelRefused> {
    let hold = hold(camera);
    let start = camera.time.now();
    let (stream, listening, target) = match camera.connect("backchannel session", hold, close).await
    {
        Ok(connected) => connected,
        Err(err) => return Some(unanswered(err)),
    };
    let left = hold.saturating_sub(camera.time.now().saturating_duration_since(start));
    let talk = talk(camera, target, left, close, opened);
    let relayed = Box::pin(camera.relayed(stream, listening, talk)).await;
    relayed.map_err(unanswered).unwrap_or_else(Some)
}

/// retina's side of the session: the handshake within `left`, the
/// session handed to `opened`, the talker's packets forwarded until the
/// close or the loss, and the `TEARDOWN` awaited within its budget.
async fn talk(
    camera: &Camera,
    target: url::Url,
    left: Duration,
    close: &CancellationToken,
    opened: &mut Option<oneshot::Sender<Result<Opened, BackchannelRefused>>>,
) -> Option<BackchannelRefused> {
    let group = std::sync::Arc::new(SessionGroup::default());
    let handshake = handshake(camera, target, &group).map(Ok::<_, SourceError>);
    let shaken = within_on(&*camera.time, close, left, "backchannel session", handshake).await;
    let shaken = match shaken {
        Ok(shaken) => shaken,
        Err(err) => Err(unanswered(err)),
    };
    let (playing, index, format) = match shaken {
        Ok(playing) => playing,
        Err(why) => {
            // A session the camera set up gets its `TEARDOWN`.
            tear_down(&group, &*camera.time, &why).await;
            return Some(why);
        }
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
    let ended = forward(playing, index, &format, uplink, close, camera).await;
    tear_down(&group, &*camera.time, &"the backchannel session ended").await;
    ended
}

/// `DESCRIBE` with `Require`, `SETUP` of the backchannel media alone, TCP
/// interleaved, and `PLAY` with `Require`: the playing session, the index
/// of the retina stream it sends on and the camera's format, or why not,
/// with the camera's status when it refused.
async fn handshake(
    camera: &Camera,
    target: url::Url,
    group: &std::sync::Arc<SessionGroup>,
) -> Result<(Session<Playing>, usize, BackchannelFormat), BackchannelRefused> {
    let refused = |err: &retina::Error| refusal(err.status_code(), &classify(err, &camera.url));
    tracing::info!("rtsp: backchannel session: DESCRIBE with the backchannel's Require header");
    let options = camera.session_options(group);
    let mut session = Session::describe(target, options)
        .await
        .map_err(|err| refused(&err))?;
    let Some((index, offer)) = backchannel_stream(&session) else {
        return Err(BackchannelRefused {
            status: None,
            message: "the camera's answer offers no backchannel the talk-back chain can feed"
                .to_owned(),
        });
    };
    tracing::info!(
        index,
        "rtsp: backchannel session: SETUP of the backchannel alone, TCP interleaved"
    );
    let setup = SetupOptions::default().transport(Transport::Tcp(TcpTransportOptions::default()));
    session
        .setup(index, setup)
        .await
        .map_err(|err| refused(&err))?;
    tracing::info!("rtsp: backchannel session: PLAY with the backchannel's Require header");
    let playing = session
        .play(play_options())
        .await
        .map_err(|err| refused(&err))?;
    Ok((playing, index, offer.format))
}

/// Sends the talker's packets from `uplink` on retina's stream `index`,
/// stamped for the camera's `format` (RFC 3550 §5.1; retina sets the SSRC
/// and the sequence numbers), and keeps reading the session, which keeps
/// it alive and notices its loss: `None` once closed, else why it ended.
/// A send waits while the camera takes no data (its TCP buffers full);
/// the close ends that wait too, so a release always reaches the
/// session's bounded `TEARDOWN` ([`tear_down`]).
async fn forward(
    playing: Session<Playing>,
    index: usize,
    format: &BackchannelFormat,
    mut uplink: mpsc::Receiver<MediaPacket>,
    close: &CancellationToken,
    camera: &Camera,
) -> Option<BackchannelRefused> {
    let (mut sink, mut items) = playing.split();
    let mut packetizer = Packetizer::new(format, FROM_ZERO);
    loop {
        tokio::select! {
            Some(packet) = uplink.recv() => {
                let BackchannelPacket { rtp, payload } = packetizer.packetize(&packet);
                let sending = SendingPacket::new(index, rtp.ts, Bytes::from_owner(payload))
                    .mark(rtp.marker)
                    .payload_type(rtp.pt);
                let sent = tokio::select! {
                    sent = sink.send(sending) => sent,
                    () = close.cancelled() => {
                        tracing::info!(
                            "rtsp: backchannel session closed while a packet waited for the camera to take data"
                        );
                        return None;
                    }
                };
                if let Err(err) = sent {
                    return Some(refusal(err.status_code(), &classify(&err, &camera.url)));
                }
            }
            item = items.next() => match item {
                // The camera's RTCP, or what else retina hands up: nothing
                // the backchannel uses.
                Some(Ok(_)) => {}
                ended => return Some(lost(ended.and_then(Result::err).as_ref(), camera)),
            },
            () = close.cancelled() => return None,
        }
    }
}

/// Why the session ended on the camera's side: `error`, or without one
/// the camera closed it.
fn lost(error: Option<&retina::Error>, camera: &Camera) -> BackchannelRefused {
    match error {
        Some(err) => refusal(err.status_code(), &classify(err, &camera.url)),
        None => BackchannelRefused {
            status: None,
            message: "the camera closed the backchannel session".to_owned(),
        },
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

    use lotse_core::clock::{Clock as _, SystemClock};
    use lotse_core::source_url::SourceUrl;
    use lotse_core::task::spawn_named;
    use lotse_testing::fake_camera::{
        BackchannelCodec, BackchannelSetup, CameraBackchannel, ConnectionLog,
    };
    use lotse_testing::{CameraConfig, FakeCamera};

    use super::*;
    use crate::options::RtspOptions;
    use crate::relay::Listener;

    fn camera_at(cam: &FakeCamera) -> Camera {
        Camera {
            url: SourceUrl::parse(&cam.url()).unwrap(),
            options: RtspOptions {
                backchannel: true,
                ..RtspOptions::default()
            },
            tls: None,
            relay: Listener::default(),
            addr: cam.addr(),
            time: Arc::new(SystemClock),
        }
    }

    #[test]
    fn a_session_the_camera_closed_without_an_error_says_so() {
        let camera = Camera {
            url: SourceUrl::parse("rtsp://127.0.0.1:1/stream").unwrap(),
            options: RtspOptions::default(),
            tls: None,
            relay: Listener::default(),
            addr: "127.0.0.1:1".parse().unwrap(),
            time: Arc::new(SystemClock),
        };
        assert_eq!(
            lost(None, &camera),
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
            run(camera_at(&cam), close.clone(), opened, on_loss),
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
        let opener = Opener::new(camera_at(&cam), tasks.clone());
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

    /// A camera that stops taking data once its backchannel plays: the
    /// talker's packets fill the TCP buffers until retina's send waits,
    /// and the release still ends the session within the teardown budget
    /// (RFC 2326 §10.7), its connection closed, rather than leaving the
    /// task waiting with the camera's connection open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rfc2326_10_7_a_release_while_a_send_waits_on_a_camera_taking_no_data_ends_the_session()
    {
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
            run(camera_at(&cam), close.clone(), opened, on_loss),
        );
        let (_codec, _frame, sender) = open.await.unwrap().unwrap();
        // Packets as large as interleaved data carries (RFC 2326 §10.12)
        // until the queue stays full: the forwarding waits in its send.
        let deadline = SystemClock.now() + Duration::from_secs(20);
        let mut full_since = None;
        for ts in 0_u32.. {
            assert!(SystemClock.now() < deadline, "the send never waited");
            if sender.try_send(large(ts)).is_ok() {
                full_since = None;
                continue;
            }
            let since = *full_since.get_or_insert_with(|| SystemClock.now());
            if SystemClock.now().duration_since(since) >= Duration::from_millis(300) {
                break;
            }
            SystemClock.sleep(Duration::from_millis(10)).await;
        }
        close.cancel();
        tokio::select! {
            ended = &mut session => ended.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(2)) => {
                panic!("the session still waits in its send after the release")
            }
        }
        let log = cam.stats().connection_log();
        assert!(log[0].played, "{log:?}");
        assert_eq!(log[0].teardown, None, "the camera read nothing more");
        cam.stop().await;
    }

    /// A PCMU packet whose payload is as large as one interleaved frame
    /// carries after its RTP header.
    fn large(ts: u32) -> MediaPacket {
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
            payload: Arc::from(vec![0xff_u8; 60_000]),
        }
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
