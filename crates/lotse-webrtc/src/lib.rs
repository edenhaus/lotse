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
//! 26.114 §7.4.5 and RFC 8285 (the video orientation extension), RFC 6716
//! §3.4 (talk-back packets checked, [`talkback`]), and the webrtc.org
//! `abs-capture-time` extension (observed behavior, not a standard;
//! `capture_time`).

mod audio;
mod capture_time;
mod crypto;
mod cvo;
pub mod sdp;
pub mod session;
pub mod talkback;
mod video;
mod writer;

use std::time::{Duration, Instant};

use lotse_core::codec::{Codec, CodecFamily, Kind};
use lotse_core::output::{OutputFactory, TalkbackRequest, TrackRequest};
use lotse_core::session::{
    SessionEngine, SessionOpenError, SessionRequest, TalkbackClaim, TalkbackTarget,
};
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

/// The tracks a session wants: H.264 or H.265 video when `video`,
/// required (which one the offer can take is the session's to find out);
/// audio when `audio`, optional, preferring Opus, then PCMU, PCMA and
/// G.722.
pub fn track_requests(video: bool, audio: bool) -> Vec<TrackRequest> {
    let mut requests = Vec::new();
    if video {
        requests.push(TrackRequest {
            kind: Kind::Video,
            accept: vec![CodecFamily::H264, CodecFamily::H265],
            unit: Unit::Packets,
            required: true,
        });
    }
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

    /// Video when the offer has a video m-line the session plays on, and
    /// the stream's audio when asked for: always beside video, where a
    /// re-offer may add the m-line it goes down on, and without video only
    /// when the offer receives audio, so a session that only sends
    /// talk-back subscribes to nothing.
    fn session_tracks(&self, offer: &str, audio: bool) -> Vec<TrackRequest> {
        let video = session::video_mid(offer).is_some();
        track_requests(video, audio && (video || audio::receives_audio(offer)))
    }

    fn open_session(
        &self,
        request: SessionRequest,
        now: Instant,
    ) -> Result<(Box<dyn SessionEngine>, String), SessionOpenError> {
        let (session, answer) = Session::answer(&request, now)?;
        Ok((Box::new(session), answer))
    }

    /// What the audio plan of `offer` would make of `backchannel` for a
    /// session that sends the stream's audio in `audio` and holds the
    /// backchannel (`AudioPlan`): talk-back is negotiable when the plan
    /// receives it, requested in vain when the plan says why not.
    fn talkback_request(
        &self,
        offer: &str,
        audio: Option<&Codec>,
        backchannel: Option<&TalkbackTarget>,
    ) -> TalkbackRequest {
        let order = audio::engine_codecs(
            backchannel.map(|backchannel| backchannel.codec.family()),
            audio.map(Codec::family),
        );
        match audio::AudioPlan::new(offer, audio, backchannel, TalkbackClaim::Granted, &order)
            .talkback
        {
            audio::Talkback::NotRequested => TalkbackRequest::NotRequested,
            audio::Talkback::Negotiated { .. } | audio::Talkback::Busy { .. } => {
                TalkbackRequest::Negotiable
            }
            audio::Talkback::Off(reason) => TalkbackRequest::Unsupported(reason.to_owned()),
        }
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
    fn the_factory_declares_its_kind_and_tracks() {
        let factory = WebRtcFactory;
        assert_eq!(factory.kind(), "webrtc");
        let video = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\na=recvonly\r\n";
        assert_eq!(
            factory.session_tracks(video, true),
            track_requests(true, true)
        );
        assert_eq!(
            factory.session_tracks(video, false),
            track_requests(true, false)
        );
        let video_only = track_requests(true, false);
        assert_eq!(video_only.len(), 1);
        assert!(video_only[0].required);
        assert_eq!(video_only[0].accept, [CodecFamily::H264, CodecFamily::H265]);
        let both = track_requests(true, true);
        assert_eq!(both.len(), 2);
        assert!(!both[1].required);
        assert_eq!(both[1].accept[0], CodecFamily::Opus);
        assert_eq!(track_requests(false, true), both[1..]);
        assert!(track_requests(false, false).is_empty());
        assert_eq!(MAX_PACER_DELAY, Duration::from_millis(50));
    }

    /// An offer without a video m-line wants no video track, and the
    /// stream's audio only
    /// when it has an audio m-line the browser receives on (RFC 8866
    /// §6.7): a client that only sends talk-back subscribes to nothing.
    #[test]
    fn rfc8866_6_7_an_offer_without_video_wants_only_the_audio_it_receives() {
        let factory = WebRtcFactory;
        let audio = |direction: &str| {
            format!(
                "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:0\r\na={direction}\r\na=rtpmap:0 PCMU/8000\r\n"
            )
        };
        assert!(factory.session_tracks(&audio("sendonly"), true).is_empty());
        assert!(factory.session_tracks(&audio("inactive"), true).is_empty());
        for receiving in ["recvonly", "sendrecv"] {
            assert_eq!(
                factory.session_tracks(&audio(receiving), true),
                track_requests(false, true),
                "{receiving}"
            );
            assert!(factory.session_tracks(&audio(receiving), false).is_empty());
        }
        // Stopped, its direction kept: it receives nothing.
        let stopped = audio("recvonly").replace("m=audio 9 ", "m=audio 0 ");
        assert!(factory.session_tracks(&stopped, true).is_empty());
        // Beside video the stream's audio is wanted whatever the audio
        // m-lines say: a re-offer may add the one it goes down on.
        let talking = format!(
            "{}m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=recvonly\r\n",
            audio("sendonly")
        );
        assert_eq!(
            factory.session_tracks(&talking, true),
            track_requests(true, true)
        );
    }

    /// What an offer asks of the backchannel, as the worker arbitrates
    /// it before the answer: a `sendonly` audio m-line in a codec that
    /// reaches the backchannel is negotiable, one the backchannel cannot
    /// take is requested in vain with the plan's reason, and an offer
    /// without one, or with it stopped, asks for nothing.
    #[test]
    fn rfc8866_6_7_the_factory_reads_what_an_offer_asks_of_the_backchannel() {
        use lotse_core::uplink::UplinkCodec;

        let factory = WebRtcFactory;
        let talking = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\na=recvonly\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:1\r\na=sendonly\r\na=rtpmap:0 PCMU/8000\r\n";
        let silent = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\na=recvonly\r\n";
        let pcmu = TalkbackTarget {
            codec: Codec::Pcmu,
            takes: vec![UplinkCodec::Pcmu],
        };
        let opus = TalkbackTarget {
            codec: Codec::Opus { channels: 2 },
            takes: vec![UplinkCodec::Opus],
        };
        assert_eq!(
            factory.talkback_request(talking, None, Some(&pcmu)),
            TalkbackRequest::Negotiable
        );
        assert_eq!(
            factory.talkback_request(talking, None, Some(&opus)),
            TalkbackRequest::Unsupported(
                "the talk-back m-line lists no codec that reaches the backchannel".into()
            )
        );
        assert_eq!(
            factory.talkback_request(talking, None, None),
            TalkbackRequest::Unsupported("the camera offers no backchannel".into())
        );
        assert_eq!(
            factory.talkback_request(silent, None, Some(&pcmu)),
            TalkbackRequest::NotRequested
        );
        // Only in two-channel PCMU, which the engine does not carry
        // (`audio::engine_channels`): requested in vain, so the worker
        // neither claims the backchannel for it nor keeps it.
        let stereo = talking.replace("PCMU/8000", "PCMU/8000/2");
        assert_eq!(
            factory.talkback_request(&stereo, None, Some(&pcmu)),
            TalkbackRequest::Unsupported(
                "the talk-back m-line lists no codec that reaches the backchannel".into()
            )
        );
        // Stopped with port 0 (RFC 3264 §8.2), its `a=sendonly` kept: it
        // asks for nothing, so a session that held the backchannel lets
        // go.
        let stopped = talking.replace("m=audio 9 ", "m=audio 0 ");
        assert_eq!(
            factory.talkback_request(&stopped, None, Some(&pcmu)),
            TalkbackRequest::NotRequested
        );
    }

    /// The stream's audio decides talk-back on a `sendrecv` m-line that
    /// also carries it down (RFC 3264 §6.1): requested in vain when its
    /// codec cannot come back to the backchannel, so the worker claims
    /// nothing, negotiable when it can, or when there is none.
    #[test]
    fn rfc3264_6_1_the_factory_weighs_the_stream_audio_on_a_shared_m_line() {
        use lotse_core::uplink::UplinkCodec;

        let factory = WebRtcFactory;
        let shared = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\na=recvonly\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\na=mid:1\r\na=sendrecv\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\n";
        let opus = Codec::Opus { channels: 2 };
        let target = TalkbackTarget {
            codec: opus.clone(),
            takes: vec![UplinkCodec::Opus],
        };
        assert_eq!(
            factory.talkback_request(shared, Some(&Codec::Pcmu), Some(&target)),
            TalkbackRequest::Unsupported(
                "the stream audio's codec on its sendrecv m-line does not reach the backchannel; talk-back needs a sendonly m-line".into()
            )
        );
        for audio in [Some(&opus), None] {
            assert_eq!(
                factory.talkback_request(shared, audio, Some(&target)),
                TalkbackRequest::Negotiable,
                "{audio:?}"
            );
        }
    }
}
