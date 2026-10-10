//! WebRTC session output on `str0m`: SDP negotiation, the RTP cut-through
//! writer, join catch-up and still, RTX, the transports, the session
//! state machine and the pure-Rust crypto provider str0m runs on.
//!
//! First implementation of the output contract; runs in a worker, which
//! drives it through `lotse_core::session` and never links this crate: the
//! binary registers [`WebRtcFactory`] behind the `output-webrtc` feature.
//! Depends on `lotse-core` and `lotse-codec` only, never on a source.
//!
//! Standards: RFC 8829 (JSEP), RFC 3264, RFC 8445 (ICE; §6.1.2.2 remote
//! candidates by address class), draft-ietf-mmusic-mdns-ice-candidates
//! §3.2.1 (`.local` candidates ignored), RFC 8489 (STUN),
//! RFC 8656 (TURN), RFC 5764 (DTLS-SRTP), RFC 3711 and RFC 7714 (SRTP,
//! the ciphers in `crypto`), RFC 4585 and RFC 5104
//! (feedback), RFC 4588 (RTX), RFC 6184 §8.2.2, RFC 7798 §7.2.2 (H.265
//! offer/answer), RFC 9143 (BUNDLE; §9.1.1 payload type reuse), RFC 8837
//! §5 (which datagrams are the audio track's, for their DSCP), 3GPP TS
//! 26.114 §7.4.5 and RFC 8285 (the video orientation extension), and the
//! webrtc.org `abs-capture-time` extension (observed behavior, not a
//! standard; `capture_time`).

mod audio;
mod capture_time;
mod crypto;
mod cvo;
pub mod sdp;
pub mod session;
mod video;
mod writer;

use std::time::{Duration, Instant};

use lotse_core::codec::{CodecFamily, Kind};
use lotse_core::output::{Delivery, JoinPolicy, OutputFactory, OutputShape, TrackRequest};
use lotse_core::session::{SessionEngine, SessionOpenError, SessionRequest};
use lotse_core::track::Unit;
use str0m::rtp::{Extension, ExtensionMap};
use str0m::{IceCreds, Rtc, RtcConfig};

pub use session::{Session, State};

/// The extension id the daemon offers `playout-delay` under.
/// Five is what Chrome uses; as the answerer the daemon follows the
/// offer's ids anyway.
pub const PLAYOUT_DELAY_EXT_ID: u8 = 5;

/// The extension id the daemon offers `abs-capture-time` under.
/// Chrome offers it under 13 when a page asks for it, which str0m's
/// standard map gives `urn:3gpp:video-orientation`; as the answerer the
/// daemon follows the offer's ids, so any free id does.
pub const ABS_CAPTURE_TIME_EXT_ID: u8 = 12;

/// Installs this crate's pure-Rust crypto provider (`dimpl` DTLS and
/// `RustCrypto` SRTP, see the `crypto` module) as str0m's process default.
/// Idempotent; the first session of a worker installs it, and a process
/// that builds an `Rtc` of its own (a test's viewer) calls it first.
pub fn install_crypto_provider() {
    crypto::provider().install_process_default();
}

/// The `Rtc` configuration of one viewer session:
/// RTP mode, so the cut-through writer hands str0m ready-made packets;
/// the ICE credentials the supervisor generated, so its demux can verify
/// STUN integrity; and the `playout-delay` and `abs-capture-time` header
/// extensions on top of the standard map, which has
/// `urn:3gpp:video-orientation` (`cvo`): str0m answers each only when the
/// offer lists it.
pub fn session_config(ice: IceCreds) -> RtcConfig {
    let mut extensions = ExtensionMap::standard();
    extensions.set(PLAYOUT_DELAY_EXT_ID, Extension::PlayoutDelay);
    extensions.set(ABS_CAPTURE_TIME_EXT_ID, Extension::AbsoluteCaptureTime);
    Rtc::builder()
        .set_rtp_mode(true)
        .set_local_ice_credentials(ice)
        .set_extension_map(extensions)
}

/// The policy a WebRTC session declares:
/// live packets at the live edge, best effort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Where it joins.
    pub join: JoinPolicy,
    /// How it is delivered.
    pub delivery: Delivery,
}

/// The policy of every WebRTC session.
pub const POLICY: Policy = Policy {
    join: JoinPolicy::LiveEdge,
    delivery: Delivery::BestEffort,
};

/// The tracks a session wants: H.264 or H.265 video, required (which one
/// the offer can take is the session's to find out); audio when asked for,
/// optional, preferring Opus, then PCMU, PCMA and G.722.
pub fn track_requests(audio: bool) -> Vec<TrackRequest> {
    let mut requests = vec![TrackRequest {
        kind: Kind::Video,
        accept: vec![CodecFamily::H264, CodecFamily::H265],
        unit: Unit::Packets,
        required: true,
    }];
    if audio {
        requests.push(TrackRequest {
            kind: Kind::Audio,
            accept: vec![
                CodecFamily::Opus,
                CodecFamily::Pcmu,
                CodecFamily::Pcma,
                CodecFamily::G722,
            ],
            unit: Unit::Packets,
            required: false,
        });
    }
    requests
}

/// The `webrtc` output kind: one [`Session`] per viewer.
#[derive(Debug, Default, Clone, Copy)]
pub struct WebRtcFactory;

impl OutputFactory for WebRtcFactory {
    fn kind(&self) -> &'static str {
        "webrtc"
    }

    fn shape(&self) -> OutputShape {
        OutputShape::Session
    }

    fn session_tracks(&self, audio: bool) -> Vec<TrackRequest> {
        track_requests(audio)
    }

    fn open_session(
        &self,
        request: SessionRequest,
        now: Instant,
    ) -> Result<(Box<dyn SessionEngine>, String), SessionOpenError> {
        let (session, answer) = Session::answer(&request, now)?;
        Ok((Box::new(session), answer))
    }
}

/// The pacer's target delay budget; exported for the settings until the
/// pacer is tuned.
pub const MAX_PACER_DELAY: Duration = Duration::from_millis(50);

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    #[test]
    fn the_factory_declares_its_kind_shape_and_tracks() {
        let factory = WebRtcFactory;
        assert_eq!(factory.kind(), "webrtc");
        assert_eq!(factory.shape(), OutputShape::Session);
        assert_eq!(factory.session_tracks(true), track_requests(true));
        assert_eq!(POLICY.join, JoinPolicy::LiveEdge);
        let video_only = track_requests(false);
        assert_eq!(video_only.len(), 1);
        assert!(video_only[0].required);
        assert_eq!(video_only[0].accept, [CodecFamily::H264, CodecFamily::H265]);
        let both = track_requests(true);
        assert_eq!(both.len(), 2);
        assert!(!both[1].required);
        assert_eq!(both[1].accept[0], CodecFamily::Opus);
        assert_eq!(MAX_PACER_DELAY, Duration::from_millis(50));
    }
}
