//! Keyframe requests from a track's viewers to the source feeding it.
//!
//! A viewer that joins with no usable keyframe in the GOP cache, or loses
//! its picture (a PLI or FIR, RFC 4585 §6.3.1, RFC 5104 §4.3.1), wants a
//! new keyframe. The session side asks the track
//! ([`Track::request_keyframe`]); the track coalesces and spaces the
//! requests of all its viewers and hands the few that remain to the
//! source currently feeding it, which asks the camera in its protocol's
//! way: the WebRTC ingest with a PLI. A source that cannot ask (RTSP,
//! HTTP) takes no [`KeyframeRequests`], and the requests are counted and
//! dropped: its viewers wait for the camera's next keyframe.
//!
//! Core owns the coalescing and the rate limit, so every source gets
//! them and many viewers never make a storm:
//!
//! - at most one request per track reaches the source per
//!   [`KEYFRAME_REQUEST_INTERVAL`];
//! - a request within that interval is folded into the one that went out,
//!   whose keyframe is still due: every waiting viewer takes the next
//!   keyframe off the live path, so one keyframe answers them all;
//! - a request folded in so is sent at the interval's end only if no
//!   keyframe arrived meanwhile (a camera that lost or ignored the first
//!   one is asked again, once); one that did arrive answered it, and the
//!   GOP cache now holds it for the joins after it.
//!
//! The spacing runs on the injected clock, as the callers read it: the
//! session's `now` for a request, a frame's `arrival` for one sent at the
//! interval's end. A live track a standby feeds since a switch
//! ([`Feeds`](crate::track::Feeds)) hands its requests to the standby's
//! source.
//!
//! A request is never answered from the cache here: the session decides
//! that before it asks, bursting a keyframe fresh enough
//! ([`SessionLimits::catchup_max_age`](crate::session::SessionLimits::catchup_max_age))
//! and asking only when it cannot.
//!
//! The source side is a [`watch`] counter per track: the track knows
//! whether any source holds its receiving end (a [`KeyframeRequests`]),
//! so a request with none is dropped and counted instead of lost
//! silently; any number of requests between two reads of the source wake
//! it once; and waiting on it is cancel-safe in a `select!` loop, which
//! is how the sources run. A `Notify` would coalesce too, but cannot say
//! whether anyone listens.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::track::Track;

/// The least time between two keyframe requests a track hands its source;
/// a request sent is due for as long. lotse's choice, not a protocol's:
/// the same spacing the WebRTC ingest keeps between its own PLIs, about
/// what a camera takes to answer one with a keyframe.
pub const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

/// What became of one keyframe request ([`Track::request_keyframe`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyframeOutcome {
    /// Handed to the source feeding the track.
    Forwarded,
    /// Folded into the request sent within the last
    /// [`KEYFRAME_REQUEST_INTERVAL`]: its keyframe is due, and unless one
    /// arrives first a request goes out once the interval ends.
    Coalesced,
    /// No source feeding the track takes requests (none attached between
    /// two connection attempts, or one whose protocol cannot ask): counted
    /// and dropped.
    Dropped,
}

/// The receiving end of a track's keyframe requests, held by the source
/// that feeds the track for one connection attempt
/// ([`Track::keyframe_requests`]). While it is held the track forwards
/// its requests here; once it is dropped they are dropped and counted.
#[derive(Debug)]
pub struct KeyframeRequests {
    /// Bumped once per request the track forwards.
    rx: watch::Receiver<u64>,
    /// Keeps the sending end alive, so the receiver never sees it closed.
    _track: Arc<Track>,
}

impl KeyframeRequests {
    /// The receiving end of `rx`, the counter of `track`, which it keeps.
    pub(crate) const fn new(rx: watch::Receiver<u64>, track: Arc<Track>) -> Self {
        Self { rx, _track: track }
    }

    /// Resolves once a request was forwarded since the last call returned
    /// (or since this was taken): however many were, one wake. Cancel-safe.
    pub async fn requested(&mut self) {
        // The track holds the sender and this holds the track, so the
        // channel never closes while it is awaited.
        let _open = self.rx.changed().await;
    }

    /// Whether a request was forwarded that [`Self::requested`] has not
    /// returned for yet.
    pub fn is_requested(&self) -> bool {
        self.rx.has_changed().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::Instant;

    use bytes::Bytes;
    use tracing::Level;

    use super::*;
    use crate::clock::{Clock as _, SystemClock};
    use crate::codec::{Codec, Kind};
    use crate::media::{MediaFrame, MediaTime};
    use crate::source::TrackSet;
    use crate::test_logs::Logs;
    use crate::track::TrackLimits;

    const DROPPED: &str = "keyframe request dropped: the source feeding the track cannot ask for one; viewers wait for its next keyframe";
    const FORWARDED: &str = "keyframe requested from the source";

    fn h264() -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        }
    }

    fn frame(keyframe: bool, arrival: Instant) -> MediaFrame {
        MediaFrame {
            ts: MediaTime::ZERO,
            wallclock: arrival,
            arrival,
            keyframe,
            discontinuity: false,
            epoch: 0,
            payload: Bytes::from_static(&[0; 10]),
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// A live set at `t0` with its video track declared.
    fn live(t0: Instant) -> (Arc<TrackSet>, Arc<Track>) {
        let set = TrackSet::new(TrackLimits::default(), t0);
        let video = set.publisher().declare(Kind::Video, h264(), 90_000);
        (set, video)
    }

    /// The counters: requested, forwarded, coalesced, dropped.
    fn counted(track: &Track) -> [u64; 4] {
        let stats = track.stats();
        [
            stats.keyframe_requests,
            stats.keyframe_requests_forwarded,
            stats.keyframe_requests_coalesced,
            stats.keyframe_requests_dropped,
        ]
    }

    #[tokio::test]
    async fn rfc4585_6_3_1_many_viewers_requests_reach_the_source_once_per_interval() {
        let (logs, _guard) = Logs::capture();
        let t0 = SystemClock.now();
        let (_set, video) = live(t0);
        let mut requests = video.keyframe_requests();
        assert!(!requests.is_requested());

        assert_eq!(video.request_keyframe(t0), KeyframeOutcome::Forwarded);
        for n in 1..10 {
            assert_eq!(
                video.request_keyframe(t0 + ms(n * 111)),
                KeyframeOutcome::Coalesced,
                "within the interval"
            );
        }
        assert_eq!(counted(&video), [10, 1, 9, 0]);
        // One wake for the source, however many asked.
        assert!(requests.is_requested());
        requests.requested().await;
        assert!(!requests.is_requested());
        assert_eq!(logs.count(Level::DEBUG, FORWARDED), 1);

        // The interval's end, to the tick: the next one goes out.
        assert_eq!(
            video.request_keyframe(t0 + KEYFRAME_REQUEST_INTERVAL),
            KeyframeOutcome::Forwarded
        );
        assert!(requests.is_requested());
        assert_eq!(counted(&video), [11, 2, 9, 0]);
    }

    #[test]
    fn a_request_folded_in_goes_out_at_the_interval_s_end_unless_a_keyframe_answers_it() {
        let t0 = SystemClock.now();
        let (_set, video) = live(t0);
        let requests = video.keyframe_requests();
        assert_eq!(video.request_keyframe(t0), KeyframeOutcome::Forwarded);
        // The camera answered; a viewer joins after it and asks again.
        assert!(video.publish_frame(frame(true, t0 + ms(100))));
        assert_eq!(
            video.request_keyframe(t0 + ms(300)),
            KeyframeOutcome::Coalesced
        );
        // Frames within the interval leave it folded in.
        assert!(video.publish_frame(frame(false, t0 + ms(999))));
        assert_eq!(counted(&video), [2, 1, 1, 0]);
        // The first frame at the interval's end sends it.
        assert!(video.publish_frame(frame(false, t0 + ms(1_000))));
        assert_eq!(counted(&video), [2, 2, 1, 0]);
        assert!(video.publish_frame(frame(false, t0 + ms(1_040))));
        assert_eq!(counted(&video), [2, 2, 1, 0], "sent once");

        // Folded in again, and a keyframe answers it before the interval
        // ends: nothing more goes out.
        assert_eq!(
            video.request_keyframe(t0 + ms(1_500)),
            KeyframeOutcome::Coalesced
        );
        assert!(video.publish_frame(frame(true, t0 + ms(1_600))));
        assert!(video.publish_frame(frame(false, t0 + ms(2_500))));
        assert_eq!(counted(&video), [3, 2, 2, 0]);
        drop(requests);
    }

    #[test]
    fn without_a_source_that_asks_requests_are_counted_dropped_and_logged_rate_limited() {
        let (logs, _guard) = Logs::capture();
        let t0 = SystemClock.now();
        let (_set, video) = live(t0);
        // No source took the requests: RTSP, HTTP, or between attempts.
        assert_eq!(video.request_keyframe(t0), KeyframeOutcome::Dropped);
        assert_eq!(
            video.request_keyframe(t0 + ms(10)),
            KeyframeOutcome::Dropped
        );
        assert_eq!(counted(&video), [2, 0, 0, 2]);
        assert_eq!(logs.count(Level::DEBUG, DROPPED), 1, "rate-limited");

        // A drop starts no interval: a source attached asks at once.
        let requests = video.keyframe_requests();
        assert_eq!(
            video.request_keyframe(t0 + ms(20)),
            KeyframeOutcome::Forwarded
        );
        assert!(requests.is_requested());
        // Its attempt ended: dropped again, and one folded in meanwhile is
        // dropped at the interval's end, never left pending.
        assert_eq!(
            video.request_keyframe(t0 + ms(30)),
            KeyframeOutcome::Coalesced
        );
        drop(requests);
        assert!(video.publish_frame(frame(false, t0 + ms(1_020))));
        assert_eq!(counted(&video), [4, 1, 1, 3]);
        assert!(video.publish_frame(frame(false, t0 + ms(1_060))));
        assert_eq!(counted(&video), [4, 1, 1, 3], "nothing left pending");
        assert_eq!(
            video.request_keyframe(t0 + ms(1_100)),
            KeyframeOutcome::Dropped
        );
        assert_eq!(
            logs.count(Level::DEBUG, DROPPED),
            1,
            "within the summary interval"
        );
    }

    #[test]
    fn during_a_standby_switch_requests_go_to_the_source_that_feeds_the_track() {
        let t0 = SystemClock.now();
        let set = TrackSet::new(TrackLimits::default(), t0);
        let mut publisher = set.publisher();
        let video = publisher.declare(Kind::Video, h264(), 90_000);
        let audio = publisher.declare(Kind::Audio, Codec::Pcmu, 8_000);
        let live_requests = video.keyframe_requests();

        // A standby with video only, armed but not switched to yet: the
        // live set's own source still feeds the track.
        let staging = TrackSet::staging(&set);
        let standby_video = staging.publisher().declare(Kind::Video, h264(), 90_000);
        let standby_requests = standby_video.keyframe_requests();
        staging.arm_switch();
        assert_eq!(video.request_keyframe(t0), KeyframeOutcome::Forwarded);
        assert!(live_requests.is_requested());
        assert!(!standby_requests.is_requested());
        let (mut live_requests, standby_requests) = (live_requests, standby_requests);
        live_requests.rx.mark_unchanged();

        // The standby's first keyframe switches: its source feeds the
        // track and takes the requests.
        assert!(standby_video.publish_frame(frame(true, t0 + ms(500))));
        assert!(staging.is_active());
        let mut standby_requests = standby_requests;
        assert_eq!(
            video.request_keyframe(t0 + ms(1_000)),
            KeyframeOutcome::Forwarded
        );
        assert!(standby_requests.is_requested());
        standby_requests.rx.mark_unchanged();
        // The live set's own source got only the one before the switch.
        assert!(!live_requests.is_requested());
        assert_eq!(counted(&video), [2, 2, 0, 0]);

        // The standby has no audio track: nothing feeds the live one's
        // requests (an audio track never asks, but the path is the same).
        assert_eq!(
            audio.request_keyframe(t0 + ms(1_000)),
            KeyframeOutcome::Dropped
        );
        // And once the standby set is gone, nothing feeds the video's.
        drop((staging, standby_video, standby_requests));
        assert_eq!(
            video.request_keyframe(t0 + ms(2_000)),
            KeyframeOutcome::Dropped
        );
    }
}
