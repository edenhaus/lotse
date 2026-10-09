//! The egress contract: what an output crate implements to consume tracks,
//! and the policies core applies on its behalf.
//!
//! Core has no branch per output. What differs between a WebRTC session, a
//! snapshot and a future recorder is policy, and policy is data a sink
//! declares: which tracks it wants, where it joins, how it is delivered.

use std::fmt;
use std::time::{Duration, Instant};

use crate::codec::{CodecFamily, Kind};
use crate::session::{SessionEngine, SessionOpenError, SessionRequest};
use crate::track::{TrackSubscription, Unit};

/// The shape of an output kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputShape {
    /// A subscription owned by a control connection (WebRTC session).
    Session,
    /// A one-shot request (snapshot).
    Request,
    /// Part of the stream's desired state, like `preload` (recording).
    Persistent,
    /// A listener the daemon opens (HLS, RTSP server).
    Served,
}

/// One output kind, registered at startup behind its Cargo feature.
pub trait OutputFactory: fmt::Debug + Send + Sync {
    /// The kind name (`webrtc`, `snapshot`; later `record`, `hls`).
    /// `info.outputs` is the list over the registry.
    fn kind(&self) -> &'static str;

    /// The kind's shape.
    fn shape(&self) -> OutputShape;

    /// The tracks a session of this kind wants, audio included when the
    /// viewer asked for it; empty for kinds that open no sessions.
    fn session_tracks(&self, audio: bool) -> Vec<TrackRequest> {
        let _ = audio;
        Vec::new()
    }

    /// Opens one session from a viewer's offer: the engine and its answer.
    /// Only [`OutputShape::Session`] kinds implement it
    /// ([`crate::session`]).
    fn open_session(
        &self,
        request: SessionRequest,
        now: Instant,
    ) -> Result<(Box<dyn SessionEngine>, String), SessionOpenError> {
        let _ = (request, now);
        Err(SessionOpenError::NotASession(self.kind()))
    }
}

/// One track a sink wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackRequest {
    /// Video or audio.
    pub kind: Kind,
    /// Acceptable codec families in preference order. A native track of
    /// any listed family beats a derived one.
    pub accept: Vec<CodecFamily>,
    /// Packets (live sinks) or frames (frame sinks).
    pub unit: Unit,
    /// Whether the sink cannot work without it. Video is required for a
    /// WebRTC session; audio is not.
    pub required: bool,
}

/// Where a sink starts in the track's timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinPolicy {
    /// At the live edge, with a catch-up burst or a keyframe still from the
    /// GOP cache (WebRTC).
    LiveEdge,
    /// One frame, the latest keyframe (snapshot).
    LatestKeyframe,
    /// From the next keyframe on (HLS, an RTSP server).
    NextKeyframe,
    /// The GOP cache and up to `max` of pre-roll, at original timestamps
    /// (recording).
    Preroll {
        /// How far back the pre-roll may reach.
        max: Duration,
    },
}

/// How items reach a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Bounded by age: a slow sink lags and skips to a keyframe.
    BestEffort,
    /// A bounded queue of the sink's own; overflow is an explicit `Gap`.
    Reliable {
        /// The queue's byte budget.
        buffer_bytes: usize,
    },
}

/// The tracks negotiation chose for a sink, one subscription per satisfied
/// request, in request order.
#[derive(Debug)]
pub struct StreamSubscription {
    /// The subscriptions.
    pub tracks: Vec<TrackSubscription>,
}

/// Why a sink refused to attach.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SinkError {
    /// The subscription does not carry what the sink needs.
    #[error("sink rejected the subscription: {0}")]
    Rejected(String),
    /// The sink is already closed.
    #[error("sink is closed")]
    Closed,
}

/// One instance of an output, attached to one stream.
pub trait Sink: fmt::Debug + Send {
    /// The tracks it wants, in preference order.
    fn wants(&self) -> Vec<TrackRequest>;

    /// Where it joins.
    fn join(&self) -> JoinPolicy;

    /// How it is delivered.
    fn delivery(&self) -> Delivery;

    /// Hands the sink its subscriptions. It must handle every
    /// [`crate::track::TrackEvent`] from then on.
    fn attach(&mut self, subscription: StreamSubscription) -> Result<(), SinkError>;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::clock::Clock as _;

    /// A factory of a kind that opens no sessions.
    #[derive(Debug)]
    struct Snapshots;

    impl OutputFactory for Snapshots {
        fn kind(&self) -> &'static str {
            "snapshot"
        }

        fn shape(&self) -> OutputShape {
            OutputShape::Request
        }
    }

    #[test]
    fn a_kind_without_sessions_wants_no_tracks_and_opens_none() {
        let factory = Snapshots;
        assert!(factory.session_tracks(true).is_empty());
        let request = SessionRequest {
            offer: String::new(),
            ice: crate::session::IceCredentials {
                ufrag: "u".into(),
                pass: "p".into(),
            },
            candidates: vec![],
            tcp_candidates: vec![],
            video: std::sync::Arc::new(crate::codec::Codec::Pcmu),
            audio: None,
            orientation: crate::Orientation::default(),
            limits: crate::session::SessionLimits::default(),
            wall: std::time::SystemTime::UNIX_EPOCH,
        };
        let err = factory
            .open_session(request, crate::clock::SystemClock.now())
            .err();
        assert_eq!(err, Some(SessionOpenError::NotASession("snapshot")));
    }

    #[test]
    fn policies_are_plain_data() {
        let request = TrackRequest {
            kind: Kind::Audio,
            accept: vec![CodecFamily::Opus, CodecFamily::Pcmu],
            unit: Unit::Packets,
            required: false,
        };
        assert_eq!(request.clone(), request);
        assert_eq!(
            JoinPolicy::Preroll {
                max: Duration::from_secs(5)
            },
            JoinPolicy::Preroll {
                max: Duration::from_secs(5)
            }
        );
        assert_ne!(
            Delivery::BestEffort,
            Delivery::Reliable {
                buffer_bytes: 1 << 20
            }
        );
        assert_eq!(OutputShape::Session, OutputShape::Session);
        assert_eq!(
            SinkError::Rejected("no video".into()).to_string(),
            "sink rejected the subscription: no video"
        );
        assert_eq!(SinkError::Closed.to_string(), "sink is closed");
    }
}
