//! The egress contract: what an output crate implements to serve a
//! stream's tracks to viewers.
//!
//! Core has no branch per output. An output kind declares the tracks a
//! session wants ([`TrackRequest`]), which core negotiates against the
//! stream's tracks, and opens one [`SessionEngine`] per viewer's offer.

use std::fmt;
use std::time::Instant;

use crate::codec::{Codec, CodecFamily, Kind};
use crate::session::{SessionEngine, SessionOpenError, SessionRequest, TalkbackTarget};
use crate::track::Unit;

/// One output kind, registered at startup behind its Cargo feature.
pub trait OutputFactory: fmt::Debug + Send + Sync {
    /// The kind name (`webrtc`, `snapshot`; later `record`, `hls`).
    /// `info.outputs` is the list over the registry.
    fn kind(&self) -> &'static str;

    /// The tracks a session of this kind wants, audio included when the
    /// viewer asked for it; none by default.
    fn session_tracks(&self, audio: bool) -> Vec<TrackRequest> {
        let _ = audio;
        Vec::new()
    }

    /// Opens one session from a viewer's offer: the engine and its answer
    /// ([`crate::session`]).
    fn open_session(
        &self,
        request: SessionRequest,
        now: Instant,
    ) -> Result<(Box<dyn SessionEngine>, String), SessionOpenError>;

    /// What `offer` (an offer or a re-offer) asks of the stream's
    /// backchannel, `backchannel` as the camera offers it now, for a
    /// session that sends the stream's audio in `audio` (`None` without
    /// any; [`SessionRequest::audio`]): the worker claims the backchannel
    /// for a session whose offer could receive talk-back before the
    /// engine answers it, so the answer carries the claim's outcome. A
    /// kind without talk-back never asks for it.
    fn talkback_request(
        &self,
        offer: &str,
        audio: Option<&Codec>,
        backchannel: Option<&TalkbackTarget>,
    ) -> TalkbackRequest {
        let _ = (offer, audio, backchannel);
        TalkbackRequest::NotRequested
    }
}

/// What an offer asks of the stream's backchannel
/// ([`OutputFactory::talkback_request`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TalkbackRequest {
    /// No talk-back: the offer has no m-line the viewer sends audio on.
    NotRequested,
    /// Talk-back the session could receive: the offer sends audio on an
    /// m-line in a codec that reaches the backchannel, so the worker
    /// claims it for the session.
    Negotiable,
    /// Talk-back the session cannot receive, and why: the camera offers
    /// no backchannel, the offer lists no codec that reaches it, or it
    /// asks for talk-back on an m-line whose stream audio cannot come
    /// back in the same codec. The m-line is answered without it, and
    /// nothing is claimed.
    Unsupported(String),
}

/// One track a session wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackRequest {
    /// Video or audio.
    pub kind: Kind,
    /// Acceptable codec families in preference order. A native track of
    /// any listed family beats a derived one.
    pub accept: Vec<CodecFamily>,
    /// Packets (live outputs) or frames (frame outputs).
    pub unit: Unit,
    /// Whether the session cannot work without it. Video is required for
    /// a WebRTC session; audio is not.
    pub required: bool,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::test_util::FakeOutputFactory;

    #[test]
    fn a_kind_by_default_wants_no_tracks_and_no_talkback() {
        let factory = FakeOutputFactory("fake");
        assert!(factory.session_tracks(true).is_empty());
        let target = TalkbackTarget {
            codec: Codec::Pcmu,
            takes: vec![crate::uplink::UplinkCodec::Pcmu],
        };
        assert_eq!(
            factory.talkback_request("a=sendonly", None, Some(&target)),
            TalkbackRequest::NotRequested,
            "a kind without talk-back asks for none"
        );
    }
}
