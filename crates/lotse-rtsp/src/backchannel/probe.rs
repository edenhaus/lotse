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
//! permit (`sources.connect_concurrency`) like any connection attempt.
//!
//! The connection turns the probe on and off as its streams opt in and out
//! ([`BackchannelSlot::ask`]), without the session that plays the stream
//! noticing: an opt-in while it plays probes at once, one while it is down
//! at its next connect; an opt-out drops what the probe found, and a probe
//! still running offers nothing.

use std::future::Future;
use std::sync::Arc;

use futures_util::FutureExt as _;
use lotse_core::source::{
    Asks, BackchannelOffer, BackchannelRefused, BackchannelSlot, SourceError,
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
/// offered before.
struct Probing {
    /// The slot.
    slot: BackchannelSlot,
    /// The probe offered or withdrew.
    settled: bool,
}

impl Probing {
    /// Marks `slot` as probed now.
    fn start(slot: BackchannelSlot) -> Self {
        slot.probing();
        Self {
            slot,
            settled: false,
        }
    }

    /// The probe found `offer`.
    fn found(mut self, offer: BackchannelOffer) {
        self.slot.offer(offer);
        self.settled = true;
    }

    /// The probe found none.
    fn none(mut self) {
        self.slot.withdraw();
        self.settled = true;
    }
}

impl Drop for Probing {
    fn drop(&mut self) {
        if !self.settled {
            self.slot.abandon_probe();
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
    let first = due(wanted, &slot, &probed);
    follow(camera, slot, probed, asks, first)
}

/// The probe `wanted` makes due on `slot`, marked there, unless the camera
/// answered `551` before (`probed`): then a probe an opt-in marked due
/// will not run, and `slot` settles at once.
fn due(wanted: bool, slot: &BackchannelSlot, probed: &Probed) -> Option<Probing> {
    if probed.asks(BACKCHANNEL, wanted) {
        Some(Probing::start(slot.clone()))
    } else {
        slot.abandon_probe();
        None
    }
}

/// Runs `first`, the probe due when the attempt played, then follows the
/// connection's ask (`asks`) until the attempt ends: an opt-in probes
/// again, an opt-out drops a probe still running, whose result the slot
/// would drop anyway ([`BackchannelSlot::offer`]).
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
        probing = due(asked, &slot, &probed);
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
            tracing::info!(
                codec = codec.name(),
                payload_type = format.payload_type,
                frame_ms = frame.as_millis(),
                "rtsp: backchannel offered; a talker's claim opens it in a session of its own"
            );
            probing.found(BackchannelOffer {
                codec,
                frame,
                opener: Arc::new(Opener::new(camera.clone())),
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

/// One `DESCRIBE` with `Require` on a connection of its own: the
/// backchannel's format, `None` when the answer has none the talk-back
/// chain can feed, or why it failed, with the camera's status when it
/// answered one.
async fn describe(
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

    use lotse_core::clock::SystemClock;
    use lotse_core::source_url::SourceUrl;
    use lotse_testing::{CameraConfig, FakeCamera};

    use super::*;
    use crate::options::RtspOptions;
    use crate::relay::Listener;

    fn camera_at(addr: std::net::SocketAddr, timeout_ms: u64) -> Camera {
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
            time: Arc::new(SystemClock),
        }
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
}
