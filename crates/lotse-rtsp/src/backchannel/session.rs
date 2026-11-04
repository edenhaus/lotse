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
//! attribute, at media level, else at session level, else `sendrecv`); RFC
//! 2326 §C.1.1 and §C.3 (each media's `a=control`, the URL its `SETUP`
//! names, by which the backchannel's retina stream is found when retina
//! skipped media).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lotse_core::source::{BackchannelRefused, SourceError};

use super::{BackchannelFormat, backchannel_format};

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
    /// Whether the camera's backchannel is probed now with a `DESCRIBE`
    /// carrying `Require: www.onvif.org/ver20/backchannel` (ONVIF
    /// Streaming Specification §5.3.1): the source protocol can send on a
    /// backchannel (`capable`, the factory's
    /// `capabilities().backchannel`), the connection asks for one
    /// (`wanted`: a stream on it opted in with its `backchannel` option),
    /// and the camera has not answered a probe with `551` before.
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
    /// How many media descriptions the SDP has: when retina parsed them
    /// all, its stream indices are the SDP's, and the stream at `media` is
    /// the backchannel's.
    pub medias: usize,
    /// The first payload type of its `m=` line: the `rtp_payload_type` of
    /// the retina stream that carries it, by which the source checks that
    /// stream. It is also the payload type retina stamps on every packet
    /// sent on that stream, so it equals `format.payload_type` ([`offer`]
    /// takes no other).
    pub first_payload_type: u8,
    /// The value of its `a=control` attribute as the camera wrote it (RFC
    /// 2326 §C.1.1: the URL a `SETUP` of this media names, relative to the
    /// presentation's, or absolute), the last one as retina reads it; `None`
    /// when it has none or one without a value. By it the source finds the
    /// media's retina stream when retina skipped media and its indices are
    /// no longer the SDP's. It is the camera's text, compared and never
    /// logged.
    pub control: Option<String>,
    /// The format the talk-back chain sends it.
    pub format: BackchannelFormat,
}

/// One retina stream as [`Offer::stream`] looks at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate<'a> {
    /// Whether retina sends on it: its direction is `Sending`.
    pub sending: bool,
    /// Its `rtp_payload_type`.
    pub payload_type: u8,
    /// Its control URL as retina resolved it (`Stream::control`), `None`
    /// when its media had none.
    pub control: Option<&'a str>,
}

/// The `a=control` value `*` (RFC 2326 §C.1.1): the presentation's own URL,
/// which names no one media.
const AGGREGATE_CONTROL: &str = "*";

/// Whether `url`, a stream's control URL as retina resolved it, is the
/// media's `control` value resolved: the absolute URL itself, or the base
/// URL, `/`, then the relative one, as retina joins them (its
/// `join_control`, the live555 and ffmpeg way rather than RFC 3986 §5,
/// observed in retina's source at e38c156, 2026-11-04).
fn resolves_to(url: &str, control: &str) -> bool {
    url == control
        || url
            .strip_suffix(control)
            .is_some_and(|base| base.ends_with('/'))
}

impl Offer {
    /// The index of the retina stream that carries this backchannel among
    /// `streams`, one [`Candidate`] per retina stream in its order.
    ///
    /// When retina parsed every media description, its indices are the
    /// SDP's, and the stream is the one at [`Offer::media`] if it sends with
    /// the first payload type. When it skipped some (a media it cannot
    /// parse), the indices shift, and neither a position nor a payload type
    /// proves which media survived: the stream is the one that sends with
    /// the first payload type on the media's control URL (RFC 2326 §C.3:
    /// each media of an aggregate presentation has its own), so that the
    /// chain's bytes never go out on another media's stream. `None` when
    /// the media has no control of its own (none, an empty one, or `*`),
    /// when no stream or several match it, or when retina's URL parser
    /// rewrote the control so that it no longer reads as the camera wrote
    /// it: an uncertain mapping is no backchannel, logged at info.
    pub fn stream(&self, streams: &[Candidate<'_>]) -> Option<usize> {
        let carries = |stream: &Candidate<'_>| {
            stream.sending && stream.payload_type == self.first_payload_type
        };
        if streams.len() == self.medias {
            return streams
                .get(self.media)
                .filter(|stream| carries(stream))
                .map(|_| self.media);
        }
        let Some(control) = self
            .control
            .as_deref()
            .filter(|control| !control.is_empty() && *control != AGGREGATE_CONTROL)
        else {
            tracing::info!(
                media = self.media,
                "rtsp: retina skipped a media description, and the backchannel's media has no control URL of its own to find its stream by; no backchannel"
            );
            return None;
        };
        let mut carrying = streams
            .iter()
            .enumerate()
            .filter(|(_, stream)| {
                carries(stream) && stream.control.is_some_and(|url| resolves_to(url, control))
            })
            .map(|(index, _)| index);
        let Some(first) = carrying.next() else {
            tracing::info!(
                media = self.media,
                payload_type = self.first_payload_type,
                "rtsp: retina skipped a media description, and no stream it sends on with the backchannel's payload type has its media's control URL; no backchannel"
            );
            return None;
        };
        if carrying.next().is_some() {
            tracing::info!(
                media = self.media,
                payload_type = self.first_payload_type,
                "rtsp: retina skipped a media description, and several streams it sends on with the backchannel's payload type have its media's control URL; no backchannel"
            );
            return None;
        }
        Some(first)
    }
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

/// The value of `media`'s `a=control` attribute (RFC 2326 §C.1.1), owned:
/// the last one, which retina keeps of several (observed in retina's
/// `parse_media` at e38c156, 2026-11-04); `None` when it has none, or the
/// last has no value.
fn control(media: &sdp_types::Media) -> Option<String> {
    media
        .attributes
        .iter()
        .rev()
        .find(|attribute| attribute.attribute == "control")
        .and_then(|attribute| attribute.value.clone())
}

/// The backchannel of a `DESCRIBE` answer's SDP `sdp`, sent with the
/// `Require` header: the first media description that is `sendonly` (media
/// the client sends to the camera, ONVIF Streaming Specification §5.3.2;
/// RFC 8866 §6.7: its own direction attribute, else the session's), is
/// audio and has a format the talk-back chain produces
/// ([`backchannel_format`]). Of the backchannels a camera lists, the client
/// chooses which one it uses (§5.3.2), and talk-back uses audio.
///
/// SPEC-DEVIATION: ONVIF §5.3.2 lets the client send any format an `m=`
/// line lists, but retina stamps a sending stream's packets with the
/// stream's `rtp_payload_type`, the line's first format, and the caller
/// cannot choose it. Until it can, only a media whose first format the
/// chain produces is taken; one that lists such a format later is no
/// backchannel (logged at info, the probe reports none), since its packets
/// would carry the first format's payload type over the chain's bytes. retina's
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
    let medias = session.medias.len();
    let offer = session
        .medias
        .iter()
        .enumerate()
        .filter(|(_, media)| media.media.eq_ignore_ascii_case("audio") && sendonly(media))
        .find_map(|(index, media)| {
            let first_payload_type = media.fmt.split_ascii_whitespace().next()?.parse().ok()?;
            let format = backchannel_format(media)?;
            if format.payload_type != first_payload_type {
                tracing::info!(
                    media = index,
                    first_payload_type,
                    payload_type = format.payload_type,
                    codec = format.codec.name(),
                    "rtsp: the camera's backchannel is not usable: retina sends the m-line's first payload type; the chain's format is listed later"
                );
                return None;
            }
            Some(Offer {
                media: index,
                medias,
                first_payload_type,
                control: control(media),
                format,
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
    use lotse_testing::fake_camera::{
        BACKCHANNEL_CONTROL, BackchannelCodec, CameraAudio, CameraBackchannel,
    };

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
                medias: 4,
                first_payload_type: 97,
                control: None,
                format: BackchannelFormat {
                    codec: Codec::Pcma,
                    ptime: Some(Duration::from_millis(40)),
                    ..pcmu(97)
                },
            })
        );
    }

    /// One retina stream that sends with `payload_type` on `control`.
    fn sends(payload_type: u8, control: Option<&str>) -> Candidate<'_> {
        Candidate {
            sending: true,
            payload_type,
            control,
        }
    }

    const TRACK1: &str = "rtsp://127.0.0.1:1/stream/track1";
    const TRACK2: &str = "rtsp://127.0.0.1:1/stream/track2";

    /// The backchannel's retina stream is its media's, not the first that
    /// sends with its payload type: two `sendonly` media may share one.
    #[test]
    fn onvif_5_3_2_the_backchannels_stream_is_its_medias_not_the_first_with_its_payload_type() {
        // G.722 at 96 first is no backchannel; PCMU at 96 after it is.
        let answer = sdp(&[
            "m=audio 0 RTP/AVP 96 0",
            "a=rtpmap:96 G722/8000",
            "a=sendonly",
            "m=audio 0 RTP/AVP 96",
            "a=rtpmap:96 PCMU/8000",
            "a=sendonly",
        ]);
        let offer = offer(&answer).unwrap();
        assert_eq!((offer.media, offer.medias), (1, 2));
        let not_sending = Candidate {
            sending: false,
            ..sends(96, None)
        };
        // retina parsed both: the stream at the media's index.
        assert_eq!(offer.stream(&[sends(96, None), sends(96, None)]), Some(1));
        assert_eq!(offer.stream(&[sends(96, None), not_sending]), None);
        assert_eq!(offer.stream(&[sends(96, None), sends(97, None)]), None);
    }

    /// RFC 2326 §C.3: when retina skipped a media, the backchannel's stream
    /// is the one on its media's control URL; a payload type alone could be
    /// another media's, whose stream would carry the chain's bytes.
    #[test]
    fn rfc2326_c_3_when_retina_skipped_media_the_backchannels_stream_is_the_one_on_its_control() {
        // A valueless `a=fmtp` on the PCMU media makes retina drop it; the
        // G.722 media at 96 survives.
        let answer = sdp(&[
            "m=audio 0 RTP/AVP 96 0",
            "a=rtpmap:96 G722/8000",
            "a=sendonly",
            "a=control:track1",
            "m=audio 0 RTP/AVP 96",
            "a=rtpmap:96 PCMU/8000",
            "a=fmtp",
            "a=sendonly",
            "a=control:track2",
        ]);
        let offer = offer(&answer).unwrap();
        assert_eq!((offer.media, offer.medias), (1, 2));
        assert_eq!(offer.control.as_deref(), Some("track2"));
        let three = Offer { medias: 3, ..offer };
        // The backchannel's media is the one skipped: no stream.
        let log = logged(|| assert_eq!(three.stream(&[sends(96, Some(TRACK1))]), None));
        assert!(
            log.contains("rtsp: retina skipped a media description, and no stream it sends on with the backchannel's payload type has its media's control URL; no backchannel media=1 payload_type=96"),
            "{log}"
        );
        // Another media was skipped: the stream on the relative control,
        // the base URL, `/`, then it.
        let skipped_other = [sends(96, Some(TRACK1)), sends(96, Some(TRACK2))];
        assert_eq!(three.stream(&skipped_other), Some(1));
        let not_sending = Candidate {
            sending: false,
            ..sends(96, Some(TRACK2))
        };
        assert_eq!(three.stream(&[sends(96, Some(TRACK1)), not_sending]), None);
        assert_eq!(
            three.stream(&[sends(96, Some(TRACK1)), sends(97, Some(TRACK2))]),
            None
        );
        assert_eq!(
            three.stream(&[sends(96, None)]),
            None,
            "a stream without a control"
        );
        // A suffix not after a `/` is another control.
        let longer = "rtsp://127.0.0.1:1/stream/xtrack2";
        assert_eq!(three.stream(&[sends(96, Some(longer))]), None);
        // An absolute control is the stream's URL itself.
        let absolute = Offer {
            control: Some(TRACK2.to_owned()),
            ..three.clone()
        };
        assert_eq!(
            absolute.stream(&[sends(96, Some(TRACK1)), sends(96, Some(TRACK2))]),
            Some(1)
        );
        assert_eq!(
            absolute.stream(&[sends(96, Some("rtsp://127.0.0.1:2/stream/track2"))]),
            None
        );
        // Of several streams on it, none is the backchannel's.
        let log = logged(|| {
            let twice = [
                sends(96, Some("rtsp://127.0.0.1:1/a/track2")),
                sends(96, Some("rtsp://127.0.0.1:1/b/track2")),
            ];
            assert_eq!(three.stream(&twice), None);
        });
        assert!(
            log.contains("several streams it sends on with the backchannel's payload type have its media's control URL; no backchannel media=1 payload_type=96"),
            "{log}"
        );
    }

    /// RFC 2326 §C.1.1: `*` is the presentation's own URL and names no one
    /// media; without a control of its own, a media cannot be found once
    /// retina's indices shifted.
    #[test]
    fn rfc2326_c_1_1_a_media_without_a_control_of_its_own_has_no_stream_once_retina_skipped_media()
    {
        for control in [None, Some(""), Some("*")] {
            let offer = Offer {
                media: 1,
                medias: 3,
                first_payload_type: 0,
                control: control.map(str::to_owned),
                format: pcmu(0),
            };
            let streams = [
                sends(0, Some("rtsp://127.0.0.1:1/stream/")),
                sends(0, Some("rtsp://127.0.0.1:1/stream/*")),
            ];
            let log = logged(|| assert_eq!(offer.stream(&streams), None, "{control:?}"));
            assert!(
                log.contains("the backchannel's media has no control URL of its own to find its stream by; no backchannel media=1"),
                "{control:?}: {log}"
            );
            // retina parsed every media: the index decides, control or not.
            let all = Offer { medias: 2, ..offer };
            assert_eq!(all.stream(&streams), Some(1), "{control:?}");
        }
    }

    #[test]
    fn rfc2326_c_1_1_the_offer_carries_its_medias_last_control_value() {
        let control = |lines: &[&str]| {
            let mut answer = vec!["m=audio 0 RTP/AVP 0", "a=sendonly"];
            answer.extend_from_slice(lines);
            offer(&sdp(&answer)).unwrap().control
        };
        assert_eq!(
            control(&["a=control:trackID=3"]).as_deref(),
            Some("trackID=3")
        );
        assert_eq!(
            control(&["a=control:rtsp://cam/a", "a=control:rtsp://cam/b"]).as_deref(),
            Some("rtsp://cam/b"),
            "the last, as retina"
        );
        assert_eq!(control(&["a=control:trackID=3", "a=control"]), None);
        assert_eq!(control(&[]), None);
        // The session's control is not the media's.
        let session_level = sdp(&["a=control:*", "m=audio 0 RTP/AVP 0", "a=sendonly"]);
        assert_eq!(offer(&session_level).unwrap().control, None);
    }

    #[test]
    fn rfc8866_5_14_a_chain_format_listed_after_the_first_payload_type_is_no_backchannel() {
        // G.722 first: retina would stamp 9 on the chain's PCMU bytes.
        let later = sdp(&[
            "m=video 0 RTP/AVP 96",
            "m=audio 0 RTP/AVP 9 0",
            "a=sendonly",
        ]);
        let log = logged(|| assert_eq!(offer(&later), None));
        assert!(
            log.contains(
                "retina sends the m-line's first payload type; the chain's format is listed later"
            ),
            "{log}"
        );
        // The next media is still looked at, and a first format the chain
        // produces is taken as before.
        let next = sdp(&[
            "m=audio 0 RTP/AVP 9 0",
            "a=sendonly",
            "m=audio 0 RTP/AVP 0 9",
            "a=sendonly",
        ]);
        let offer = offer(&next).unwrap();
        assert_eq!((offer.media, offer.first_payload_type), (1, 0));
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
        assert_eq!(
            offered.control,
            Some(format!("{base}{BACKCHANNEL_CONTROL}")),
            "its absolute control"
        );
        assert_eq!(offer(config.sdp(base, false).as_bytes()), None);
    }
}
