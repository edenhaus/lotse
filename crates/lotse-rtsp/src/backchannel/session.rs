//! The backchannel's decisions, apart from the connections they run on:
//! whether a connection attempt probes the camera, what a probe's `551`
//! means for the next attempts, which media of the `DESCRIBE` answer is
//! the backchannel and in which format, and what a camera's refusal of the
//! backchannel's session says.
//!
//! The probe and the backchannel's own sessions call each piece: retina
//! asks for the backchannel, sets it up and sends on it.
//!
//! Implements ONVIF Streaming Specification §5.3.1 (the `Require` tag on
//! `DESCRIBE`) and §5.3.2 (a server without the backchannel answers `551
//! Option not supported`, RFC 2326 §11.3.13; the backchannel media are
//! `a=sendonly`, and the client chooses which one it uses); RFC 2326
//! §11.3.11 (`461 Unsupported Transport`), with ONVIF Streaming
//! Specification §5.1.1.3 (a device *should* take RTP over RTSP over TCP
//! interleaved, the one transport lotse sends the backchannel on); RFC 8866
//! §5.14 (the first payload type of an `m=` line) and §6.7 (the direction
//! attribute, at media level, else at session level, else `sendrecv`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lotse_core::source::{BackchannelRefused, SourceError};

use super::{BackchannelFormat, backchannel_format};

/// The option tag of the ONVIF backchannel, which a client sends in a
/// `Require` header (RFC 2326 §12.32) to ask for it: ONVIF Streaming
/// Specification §5.3.1. retina adds it to the `DESCRIBE`, the `SETUP`,
/// the `PLAY` and the `TEARDOWN` of a session that asks for the
/// backchannel, by which the UDP relay knows the backchannel's `SETUP`.
pub const REQUIRE_TAG: &str = "www.onvif.org/ver20/backchannel";

/// RFC 2326 §11.3.13: `551 Option not supported`, the answer ONVIF
/// Streaming Specification §5.3.2 gives a server without the backchannel.
pub const OPTION_NOT_SUPPORTED: u16 = 551;

/// RFC 2326 §11.3.11: `461 Unsupported Transport`.
pub const UNSUPPORTED_TRANSPORT: u16 = 461;

/// How many packets a backchannel session's queue holds: 160 ms of 20 ms
/// frames. The talker's forwarder never waits on it and drops when it is
/// full, so it bounds the latency a slow send path can add.
pub const QUEUE: usize = 8;

/// What a source's probes of the camera's backchannel learned across its
/// connection attempts: once the camera answered a probe with `551 Option
/// not supported`, it has no backchannel (ONVIF Streaming Specification
/// §5.3.2), and later attempts do not ask again. Any other failure proves
/// nothing, and the next attempt asks again. Clones share the memory.
#[derive(Debug, Clone, Default)]
pub struct Probed {
    /// Set once a probe was answered with `551`.
    unsupported: Arc<AtomicBool>,
}

impl Probed {
    /// Whether this attempt probes the camera's backchannel with a
    /// `DESCRIBE` carrying `Require: www.onvif.org/ver20/backchannel`
    /// (ONVIF Streaming Specification §5.3.1): the source protocol can send
    /// on a backchannel (`capable`, the factory's
    /// `capabilities().backchannel`), the stream asks for one (`wanted`,
    /// its `backchannel` option), and the camera has not answered a probe
    /// with `551` before.
    pub fn asks(&self, capable: bool, wanted: bool) -> bool {
        if !(capable && wanted) {
            return false;
        }
        let unsupported = self.unsupported.load(Ordering::Relaxed);
        if unsupported {
            tracing::debug!("rtsp: no backchannel probe; the camera answered one with 551 before");
        }
        !unsupported
    }

    /// Whether a probe's failure with `status` proves the camera has no
    /// backchannel: `551 Option not supported` (ONVIF Streaming
    /// Specification §5.3.2), remembered for the source's later attempts.
    /// Anything else proves nothing.
    pub fn refused_with(&self, status: Option<u16>) -> bool {
        let unsupported = status == Some(OPTION_NOT_SUPPORTED);
        if unsupported && !self.unsupported.swap(true, Ordering::Relaxed) {
            tracing::info!(
                status,
                "rtsp: the camera answered the backchannel probe with 551 Option not supported; it has no backchannel, and the source does not ask again"
            );
        }
        unsupported
    }
}

/// Why the camera refused a request of the backchannel's (its `status`,
/// when it answered one) or its connection failed (`error`): the refusal
/// a declined talk-back reports. A `461 Unsupported Transport` is named as
/// such: lotse sends the backchannel TCP interleaved only, which ONVIF
/// Streaming Specification §5.1.1.3 has a device only *should* take.
pub fn refusal(status: Option<u16>, error: &SourceError) -> BackchannelRefused {
    let message = if status == Some(UNSUPPORTED_TRANSPORT) {
        tracing::warn!(
            status,
            error = %error,
            "rtsp: unsupported transport: the camera refuses the backchannel over TCP interleaved, the only transport lotse sends it on"
        );
        format!(
            "{error}: unsupported transport: the camera does not take the backchannel over TCP interleaved (ONVIF Streaming Specification §5.1.1.3 has a device only should)"
        )
    } else {
        error.to_string()
    };
    BackchannelRefused { status, message }
}

/// The camera's backchannel in its `DESCRIBE` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// Its position among the SDP's media descriptions.
    pub media: usize,
    /// The first payload type of its `m=` line: the `rtp_payload_type` of
    /// the retina stream that carries it, by which the source finds that
    /// stream, since retina's stream indices skip media it cannot parse.
    pub first_payload_type: u8,
    /// The format the talk-back chain sends it.
    pub format: BackchannelFormat,
}

/// The direction attributes (RFC 8866 §6.7).
const DIRECTIONS: [&str; 4] = ["sendrecv", "sendonly", "recvonly", "inactive"];

/// The first direction attribute among `attributes`, if any.
fn direction(attributes: &[sdp_types::Attribute]) -> Option<&str> {
    attributes
        .iter()
        .map(|attribute| attribute.attribute.as_str())
        .find(|name| DIRECTIONS.contains(name))
}

/// The backchannel of a `DESCRIBE` answer's SDP `sdp`, sent with the
/// `Require` header: the first media description that is `sendonly` (media
/// the client sends to the camera, ONVIF Streaming Specification §5.3.2;
/// RFC 8866 §6.7: its own direction attribute, else the session's), is
/// audio and has a format the talk-back chain produces
/// ([`backchannel_format`]). Of the backchannels a camera lists, the client
/// chooses which one it uses (§5.3.2), and talk-back uses audio. retina's
/// proposed `StreamDirection::Sending` reads the same direction
/// attributes. `None` also for an SDP that does not parse; the relay's
/// guard has refused one retina could not read.
pub fn offer(sdp: &[u8]) -> Option<Offer> {
    let session = match sdp_types::Session::parse(sdp) {
        Ok(session) => session,
        Err(err) => {
            tracing::debug!(error = %err, "backchannel: the SDP does not parse");
            return None;
        }
    };
    let default = direction(&session.attributes);
    let sendonly =
        |media: &sdp_types::Media| direction(&media.attributes).or(default) == Some("sendonly");
    let offer = session
        .medias
        .iter()
        .enumerate()
        .filter(|(_, media)| media.media.eq_ignore_ascii_case("audio") && sendonly(media))
        .find_map(|(index, media)| {
            let first_payload_type = media.fmt.split_ascii_whitespace().next()?.parse().ok()?;
            Some(Offer {
                media: index,
                first_payload_type,
                format: backchannel_format(media)?,
            })
        });
    match &offer {
        Some(offer) => tracing::info!(
            media = offer.media,
            codec = offer.format.codec.name(),
            payload_type = offer.format.payload_type,
            ptime_ms = offer.format.ptime.map(|ptime| ptime.as_millis()),
            "rtsp: the camera offers a backchannel"
        ),
        None => {
            tracing::info!("rtsp: the camera offers no backchannel the talk-back chain can feed");
        }
    }
    offer
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::Duration;

    use lotse_core::codec::Codec;
    use lotse_testing::CameraConfig;
    use lotse_testing::fake_camera::{BackchannelCodec, CameraAudio, CameraBackchannel};

    use super::*;

    const HEAD: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";

    fn sdp(lines: &[&str]) -> Vec<u8> {
        let mut sdp = String::from(HEAD);
        for line in lines {
            sdp.push_str(line);
            sdp.push_str("\r\n");
        }
        sdp.into_bytes()
    }

    fn pcmu(payload_type: u8) -> BackchannelFormat {
        BackchannelFormat {
            codec: Codec::Pcmu,
            payload_type,
            clock_rate: 8_000,
            ptime: None,
        }
    }

    #[test]
    fn onvif_5_3_1_a_probe_asks_only_when_capable_wanted_and_never_answered_551() {
        let probed = Probed::default();
        assert!(probed.asks(true, true));
        assert!(!probed.asks(false, true), "the protocol cannot send");
        assert!(!probed.asks(true, false), "the stream's backchannel option");
        assert!(!probed.asks(false, false));
        let shared = probed.clone();
        assert!(shared.refused_with(Some(OPTION_NOT_SUPPORTED)));
        assert!(!probed.asks(true, true), "clones share the memory");
        // Remembering twice changes nothing.
        assert!(probed.refused_with(Some(OPTION_NOT_SUPPORTED)));
        assert!(!shared.asks(true, true));
        assert_eq!(OPTION_NOT_SUPPORTED, 551, "RFC 2326 §11.3.13");
    }

    #[test]
    fn onvif_5_3_2_only_a_551_proves_the_camera_has_no_backchannel() {
        for status in [
            None,
            Some(400),
            Some(401),
            Some(404),
            Some(453),
            Some(461),
            Some(500),
        ] {
            let probed = Probed::default();
            assert!(!probed.refused_with(status), "{status:?}");
            assert!(probed.asks(true, true), "{status:?}: asked again");
        }
    }

    #[test]
    fn rfc2326_11_3_11_a_461_is_named_unsupported_transport_and_other_refusals_say_what_failed() {
        let error = SourceError::Protocol("SETUP: 461 Unsupported Transport".into());
        let refused = refusal(Some(UNSUPPORTED_TRANSPORT), &error);
        assert_eq!(refused.status, Some(461));
        assert!(
            refused
                .message
                .starts_with(&format!("{error}: unsupported transport: ")),
            "{refused:?}"
        );
        assert!(refused.message.contains("§5.1.1.3"), "{refused:?}");
        let busy = SourceError::Protocol("SETUP: 453 Not Enough Bandwidth".into());
        assert_eq!(
            refusal(Some(453), &busy),
            BackchannelRefused {
                status: Some(453),
                message: busy.to_string(),
            }
        );
        let gone = SourceError::Unreachable("Unable to connect".into());
        assert_eq!(refusal(None, &gone).status, None);
        assert_eq!(UNSUPPORTED_TRANSPORT, 461, "RFC 2326 §11.3.11");
    }

    /// A log sink the test reads back.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What `run` logs at `debug` and above.
    fn logged(run: impl FnOnce()) -> String {
        let mut captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        std::io::Write::flush(&mut captured).unwrap();
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn every_decision_is_logged_with_its_reason() {
        let probed = Probed::default();
        let log = logged(|| {
            assert!(probed.refused_with(Some(OPTION_NOT_SUPPORTED)));
            assert!(!probed.asks(true, true));
            let _named = refusal(Some(461), &SourceError::Protocol("461".into()));
            let answer = sdp(&[
                "m=video 0 RTP/AVP 96",
                "m=audio 0 RTP/AVP 0",
                "a=ptime:30",
                "a=sendonly",
            ]);
            assert!(offer(&answer).is_some());
            assert!(offer(&sdp(&["m=video 0 RTP/AVP 96"])).is_none());
        });
        for line in [
            "rtsp: the camera answered the backchannel probe with 551 Option not supported; it has no backchannel, and the source does not ask again status=551",
            "rtsp: no backchannel probe; the camera answered one with 551 before",
            "rtsp: unsupported transport: the camera refuses the backchannel over TCP interleaved",
            "rtsp: the camera offers a backchannel media=1 codec=\"pcmu\" payload_type=0 ptime_ms=30",
            "rtsp: the camera offers no backchannel the talk-back chain can feed",
        ] {
            assert!(log.contains(line), "{line} in {log}");
        }
        let again = logged(|| assert!(probed.refused_with(Some(551))));
        assert!(!again.contains("551 Option not supported"), "once: {again}");
    }

    #[test]
    fn onvif_5_3_2_the_backchannel_is_the_first_sendonly_audio_media() {
        let answer = sdp(&[
            "m=video 0 RTP/AVP 96",
            "a=rtpmap:96 H264/90000",
            "m=audio 0 RTP/AVP 0",
            "m=audio 0 RTP/AVP 97 8",
            "a=rtpmap:97 PCMA/8000",
            "a=ptime:40",
            "a=sendonly",
            "m=audio 0 RTP/AVP 0",
            "a=sendonly",
        ]);
        assert_eq!(
            offer(&answer),
            Some(Offer {
                media: 2,
                first_payload_type: 97,
                format: BackchannelFormat {
                    codec: Codec::Pcma,
                    ptime: Some(Duration::from_millis(40)),
                    ..pcmu(97)
                },
            })
        );
    }

    #[test]
    fn rfc8866_5_14_the_first_payload_type_is_the_m_lines_even_when_another_is_sent() {
        // G.722 first: retina's stream says 9, the chain sends PCMU.
        let answer = sdp(&[
            "m=video 0 RTP/AVP 96",
            "m=audio 0 RTP/AVP 9 0",
            "a=sendonly",
        ]);
        let offer = offer(&answer).unwrap();
        assert_eq!(offer.first_payload_type, 9);
        assert_eq!(offer.format, pcmu(0));
    }

    #[test]
    fn rfc8866_6_7_neither_recvonly_nor_sendrecv_nor_inactive_nor_video_is_a_backchannel() {
        for lines in [
            &["m=video 0 RTP/AVP 96", "m=audio 0 RTP/AVP 0"][..],
            &["m=video 0 RTP/AVP 96", "m=audio 0 RTP/AVP 0", "a=recvonly"],
            &["m=video 0 RTP/AVP 96", "m=audio 0 RTP/AVP 0", "a=sendrecv"],
            &["m=audio 0 RTP/AVP 0", "m=video 0 RTP/AVP 0", "a=sendonly"],
            &["m=video 0 RTP/AVP 96", "m=audio 0 RTP/AVP 0", "a=inactive"],
            &["a=recvonly", "m=video 0 RTP/AVP 96", "m=audio 0 RTP/AVP 0"],
            &[
                "a=sendonly",
                "m=video 0 RTP/AVP 96",
                "a=recvonly",
                "m=audio 0 RTP/AVP 0",
                "a=sendrecv",
            ],
        ] {
            assert_eq!(offer(&sdp(lines)), None, "{lines:?}");
        }
    }

    #[test]
    fn rfc8866_6_7_a_media_without_its_own_direction_takes_the_sessions() {
        let inherits = sdp(&[
            "a=sendonly",
            "m=video 0 RTP/AVP 96",
            "a=recvonly",
            "m=audio 0 RTP/AVP 0",
        ]);
        assert_eq!(offer(&inherits).map(|offer| offer.media), Some(1));
        // Every media sendonly, one of them by the session's attribute.
        let all = sdp(&[
            "a=sendonly",
            "m=video 0 RTP/AVP 96",
            "m=audio 0 RTP/AVP 0",
            "a=sendonly",
        ]);
        assert_eq!(offer(&all).map(|offer| offer.media), Some(1));
        let overridden = sdp(&[
            "a=recvonly",
            "m=video 0 RTP/AVP 96",
            "m=audio 0 RTP/AVP 0",
            "a=sendonly",
        ]);
        assert_eq!(offer(&overridden).map(|offer| offer.media), Some(1));
    }

    #[test]
    fn onvif_5_3_2_every_media_sendonly_still_offers_its_audio_backchannel() {
        let answer = sdp(&[
            "m=video 0 RTP/AVP 96",
            "a=sendonly",
            "m=audio 0 RTP/AVP 0",
            "a=sendonly",
        ]);
        assert_eq!(offer(&answer).map(|offer| offer.media), Some(1));
    }

    #[test]
    fn a_sendonly_audio_the_chain_cannot_feed_gives_way_to_the_next() {
        let answer = sdp(&[
            "m=video 0 RTP/AVP 96",
            "m=audio 0 RTP/AVP 9",
            "a=sendonly",
            "m=audio 0 RTP/AVP 0",
            "a=sendonly",
        ]);
        assert_eq!(offer(&answer).map(|offer| offer.media), Some(2));
        let none = sdp(&["m=video 0 RTP/AVP 96", "m=audio 0 RTP/AVP 9", "a=sendonly"]);
        assert_eq!(offer(&none), None);
        let no_format = sdp(&["m=video 0 RTP/AVP 96", "m=audio 0 RTP/AVP x", "a=sendonly"]);
        assert_eq!(offer(&no_format), None);
    }

    #[test]
    fn an_sdp_that_does_not_parse_offers_nothing() {
        assert_eq!(offer(b"not an sdp"), None);
    }

    #[test]
    fn onvif_5_3_the_fake_cameras_answer_offers_its_backchannel_and_without_require_none() {
        let config = CameraConfig {
            audio: Some(CameraAudio::Pcmu),
            backchannel: Some(CameraBackchannel {
                ptime: Some(30),
                ..CameraBackchannel::new(BackchannelCodec::Pcma)
            }),
            ..CameraConfig::default()
        };
        let base = "rtsp://127.0.0.1:1/stream/";
        let offered = offer(config.sdp(base, true).as_bytes()).unwrap();
        assert_eq!(offered.media, 2, "after the video and the audio");
        assert_eq!(offered.first_payload_type, 8);
        assert_eq!(offered.format.codec, Codec::Pcma);
        assert_eq!(offered.format.ptime, Some(Duration::from_millis(30)));
        assert_eq!(offer(config.sdp(base, false).as_bytes()), None);
    }
}
