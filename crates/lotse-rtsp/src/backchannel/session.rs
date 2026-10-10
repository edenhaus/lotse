//! The backchannel's place in the RTSP session: whether a connection
//! attempt asks for it, what a camera's refusal of the `Require` header
//! means for this attempt and the next ones, which media of the
//! `DESCRIBE` answer is the backchannel and in which format, what a
//! refused `SETUP` of it means, and the handle a playing session offers
//! on the connection's [`BackchannelSlot`].
//!
//! Every piece is complete without a send path, and none is called by
//! [`crate::RtspSource`] yet: retina 0.4 can neither ask for the
//! backchannel, set it up nor send on it (an upstream need), and each one
//! hooks into the source once it can.
//!
//! Implements ONVIF Streaming Specification §5.3.1 (the `Require` tag on
//! `DESCRIBE`), §5.3.2 (the backchannel media, `a=sendonly` audio) and
//! §5.3.2.1 (a server without it answers `551 Option not supported`, RFC
//! 2326 §11.3.13); RFC 8866 §5.14 (the first payload type of an `m=`
//! line) and §6.7 (the direction attribute, at media level, else at
//! session level, else `sendrecv`). The `400 Bad Request` some Dahua and
//! Amcrest firmwares answer instead is observed behavior.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lotse_core::media::MediaPacket;
use lotse_core::source::{BackchannelHandle, BackchannelSlot};
use tokio::sync::mpsc;

use super::{BackchannelFormat, BackchannelPacket, Initial, Packetizer, backchannel_format};

/// RFC 2326 §11.3.13: `551 Option not supported`, the answer ONVIF
/// Streaming Specification §5.3.2.1 gives a server without the
/// backchannel.
pub const OPTION_NOT_SUPPORTED: u16 = 551;

/// `400 Bad Request`, which some Dahua and Amcrest firmwares answer to the
/// `Require` header instead (observed behavior).
pub const BAD_REQUEST: u16 = 400;

/// How many packets the backchannel's queue holds: 160 ms of 20 ms
/// frames. The talker's forwarder never waits on it and drops when it is
/// full, so it bounds the latency a slow send path can add.
pub const QUEUE: usize = 8;

/// The ONVIF backchannel's `Require` header across one source's connection
/// attempts: whether the next `DESCRIBE` carries it, and what a refusal
/// means. Kept by the source, so the memory outlives each attempt: once a
/// camera refused the header and played without it, later attempts leave
/// it out and spend no `DESCRIBE` on the refusal. Clones share the memory.
#[derive(Debug, Clone, Default)]
pub struct Require {
    /// Set once a `DESCRIBE` retried without the header was answered.
    refused: Arc<AtomicBool>,
}

impl Require {
    /// Whether the next `DESCRIBE` carries `Require:
    /// www.onvif.org/ver20/backchannel` (ONVIF Streaming Specification
    /// §5.3.1): the source protocol can send on a backchannel (`capable`,
    /// the factory's `capabilities().backchannel`), the stream asks for one
    /// (`wanted`, its `backchannel` option), and the camera has not refused
    /// the header before.
    pub fn send(&self, capable: bool, wanted: bool) -> bool {
        if !(capable && wanted) {
            return false;
        }
        let refused = self.refused.load(Ordering::Relaxed);
        if refused {
            tracing::debug!(
                "rtsp: DESCRIBE without the backchannel's Require header; the camera refused it before"
            );
        }
        !refused
    }

    /// Whether a failed `DESCRIBE` is retried without the header, on a
    /// fresh connection: it carried the header (`sent`) and the camera
    /// answered `551 Option not supported` (ONVIF Streaming Specification
    /// §5.3.2.1) or `400 Bad Request` (the Dahua and Amcrest quirk).
    /// Anything else, or a status without the header sent, is the
    /// attempt's error as it is.
    pub fn retry_without(sent: bool, status: Option<u16>) -> bool {
        let retry = sent && matches!(status, Some(OPTION_NOT_SUPPORTED | BAD_REQUEST));
        if retry {
            tracing::info!(
                status,
                "rtsp: the camera refused the backchannel's Require header; describing again without it"
            );
        }
        retry
    }

    /// The `DESCRIBE` retried without the header was answered, so the
    /// header was what the camera refused: later attempts leave it out,
    /// and the connection plays without a backchannel. A retry that fails
    /// as well proves nothing, and remembers nothing.
    pub fn refused(&self) {
        if !self.refused.swap(true, Ordering::Relaxed) {
            tracing::info!(
                "rtsp: the camera plays without the backchannel's Require header; talk-back is off for this connection"
            );
        }
    }
}

/// Whether the `SETUP` of the backchannel failing with `status` leaves the
/// attempt to play without it: any RTSP status does (some cameras take one
/// backchannel at a time and refuse a second client's, or refuse the
/// transport), since the backchannel is optional and the media streams
/// are already set up. Without a status the connection failed, and the
/// attempt ends with that error.
pub fn play_without(status: Option<u16>) -> bool {
    match status {
        Some(status) => {
            tracing::info!(
                status,
                "rtsp: the camera refused the backchannel's SETUP; playing without it"
            );
            true
        }
        None => false,
    }
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
/// `Require` header: the first media description that is audio, is
/// `sendonly` (the camera only receives on it, ONVIF Streaming
/// Specification §5.3.2; RFC 8866 §6.7: its own direction attribute, else
/// the session's) and has a format the talk-back chain produces
/// ([`backchannel_format`]). When every media description is `sendonly`,
/// the camera describes its own direction and none is a backchannel.
/// retina's proposed `StreamDirection::Sending` applies the same rule to
/// the media-level attribute only, so the source sets a backchannel up
/// only where both agree. `None` also for an SDP that does not parse; the
/// relay's guard has refused one retina could not read.
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
    if session.medias.iter().all(sendonly) {
        tracing::debug!("backchannel: every media is sendonly; the camera describes its own");
        return None;
    }
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

/// One playing session's backchannel: the handle offered on the
/// connection's slot, the queue it fills, and the session's one
/// [`Packetizer`]. Built once the backchannel is set up and the session
/// plays (one per `SETUP`, so a reconnect starts a fresh RTP stream);
/// dropping it withdraws the handle, which the talker's claim outlives.
#[derive(Debug)]
pub struct Backchannel {
    /// The slot the handle is offered on.
    slot: BackchannelSlot,
    /// The format the camera takes.
    format: BackchannelFormat,
    /// Stamps every packet for the camera.
    packetizer: Packetizer,
    /// The queue's receiving end; the handle's sender fills it.
    uplink: mpsc::Receiver<MediaPacket>,
}

impl Backchannel {
    /// Offers on `slot` a handle in the camera's `format`: its codec, the
    /// frame its `a=ptime` asks for (else
    /// [`BackchannelHandle::DEFAULT_FRAME`]), and a queue of [`QUEUE`]
    /// packets, stamped from `initial` on.
    pub fn offer(slot: BackchannelSlot, format: BackchannelFormat, initial: Initial) -> Self {
        let (sender, uplink) = mpsc::channel(QUEUE);
        let frame = format.ptime.unwrap_or(BackchannelHandle::DEFAULT_FRAME);
        tracing::info!(
            codec = format.codec.name(),
            payload_type = format.payload_type,
            frame_ms = frame.as_millis(),
            "rtsp: backchannel offered"
        );
        slot.offer(BackchannelHandle {
            codec: format.codec.clone(),
            frame,
            sender,
        });
        Self {
            slot,
            packetizer: Packetizer::new(&format, initial),
            format,
            uplink,
        }
    }

    /// The format the camera takes.
    pub const fn format(&self) -> &BackchannelFormat {
        &self.format
    }

    /// The next packet for the camera, stamped. Pending until the talker
    /// sends one; `None` only once the handle left the slot (withdrawn or
    /// replaced) and every sender is gone.
    pub async fn next(&mut self) -> Option<BackchannelPacket> {
        let packet = self.uplink.recv().await?;
        Some(self.packetizer.packetize(&packet))
    }
}

impl Drop for Backchannel {
    fn drop(&mut self) {
        self.slot.withdraw();
        tracing::info!("rtsp: backchannel withdrawn");
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::Duration;

    use lotse_core::clock::{Clock as _, SystemClock};
    use lotse_core::codec::Codec;
    use lotse_core::media::RtpHeaderFields;
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

    const INITIAL: Initial = Initial {
        ssrc: 0x0102_0304,
        seq: 100,
        ts: 5_000,
    };

    #[test]
    fn onvif_5_3_1_require_is_sent_only_when_capable_wanted_and_not_refused() {
        let require = Require::default();
        assert!(require.send(true, true));
        assert!(!require.send(false, true), "the protocol cannot send");
        assert!(
            !require.send(true, false),
            "the stream's backchannel option"
        );
        assert!(!require.send(false, false));
        let shared = require.clone();
        shared.refused();
        assert!(!require.send(true, true), "clones share the memory");
        assert!(!require.send(false, true));
        // Remembering twice changes nothing.
        require.refused();
        assert!(!shared.send(true, true));
    }

    #[test]
    fn onvif_5_3_2_1_a_551_or_400_to_the_require_header_is_retried_without_it() {
        for status in [OPTION_NOT_SUPPORTED, BAD_REQUEST] {
            assert!(Require::retry_without(true, Some(status)), "{status}");
            assert!(
                !Require::retry_without(false, Some(status)),
                "{status} without the header is the camera's own error"
            );
        }
        for status in [Some(401), Some(404), Some(454), Some(461), Some(500), None] {
            assert!(!Require::retry_without(true, status), "{status:?}");
        }
        assert_eq!(OPTION_NOT_SUPPORTED, 551, "RFC 2326 §11.3.13");
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
        let require = Require::default();
        let log = logged(|| {
            assert!(Require::retry_without(true, Some(OPTION_NOT_SUPPORTED)));
            require.refused();
            assert!(!require.send(true, true));
            assert!(play_without(Some(453)));
            let answer = sdp(&[
                "m=video 0 RTP/AVP 96",
                "m=audio 0 RTP/AVP 0",
                "a=ptime:30",
                "a=sendonly",
            ]);
            assert!(offer(&answer).is_some());
            assert!(offer(&sdp(&["m=video 0 RTP/AVP 96"])).is_none());
            let slot = BackchannelSlot::default();
            drop(Backchannel::offer(slot, pcmu(0), INITIAL));
        });
        for line in [
            "rtsp: the camera refused the backchannel's Require header; describing again without it status=551",
            "rtsp: DESCRIBE without the backchannel's Require header; the camera refused it before",
            "rtsp: the camera refused the backchannel's SETUP; playing without it status=453",
            "rtsp: the camera offers a backchannel media=1 codec=\"pcmu\" payload_type=0 ptime_ms=30",
            "rtsp: the camera offers no backchannel the talk-back chain can feed",
            "rtsp: backchannel offered codec=\"pcmu\" payload_type=0 frame_ms=20",
            "rtsp: backchannel withdrawn",
        ] {
            assert!(log.contains(line), "{line} in {log}");
        }
        assert_eq!(
            log.matches("talk-back is off for this connection").count(),
            1,
            "remembered once: {log}"
        );
        let again = logged(|| require.refused());
        assert!(!again.contains("talk-back is off"), "{again}");
    }

    #[test]
    fn a_refused_backchannel_setup_plays_without_it_and_a_lost_connection_ends() {
        for status in [400, 453, 455, 461, 551] {
            assert!(play_without(Some(status)), "{status}");
        }
        assert!(!play_without(None));
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
        assert_eq!(offer(&all), None);
        let overridden = sdp(&[
            "a=recvonly",
            "m=video 0 RTP/AVP 96",
            "m=audio 0 RTP/AVP 0",
            "a=sendonly",
        ]);
        assert_eq!(offer(&overridden).map(|offer| offer.media), Some(1));
    }

    #[test]
    fn a_server_whose_every_media_is_sendonly_describes_its_own_direction() {
        let answer = sdp(&[
            "m=video 0 RTP/AVP 96",
            "a=sendonly",
            "m=audio 0 RTP/AVP 0",
            "a=sendonly",
        ]);
        assert_eq!(offer(&answer), None);
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

    fn uplink(arrival: std::time::Instant, ts: u32, marker: bool) -> MediaPacket {
        MediaPacket {
            arrival,
            rtp: RtpHeaderFields {
                pt: 0,
                seq: 1,
                ts,
                marker,
                ssrc: 7,
            },
            frame_start: true,
            keyframe_start: false,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0x55_u8; 160][..]),
        }
    }

    #[tokio::test]
    async fn the_handle_names_the_cameras_codec_and_ptime_and_its_packets_come_out_stamped() {
        let slot = BackchannelSlot::default();
        let format = BackchannelFormat {
            ptime: Some(Duration::from_millis(40)),
            ..pcmu(97)
        };
        let mut backchannel = Backchannel::offer(slot.clone(), format.clone(), INITIAL);
        assert_eq!(backchannel.format(), &format);
        let handle = slot.current().unwrap();
        assert_eq!(handle.codec, Codec::Pcmu);
        assert_eq!(handle.frame, Duration::from_millis(40));
        assert_eq!(handle.sender.max_capacity(), QUEUE);
        let now = SystemClock.now();
        handle.sender.try_send(uplink(now, 0, true)).unwrap();
        handle.sender.try_send(uplink(now, 320, false)).unwrap();
        let first = backchannel.next().await.unwrap();
        assert_eq!(
            first.rtp,
            RtpHeaderFields {
                pt: 97,
                seq: 100,
                ts: 5_000,
                marker: true,
                ssrc: 0x0102_0304,
            }
        );
        assert_eq!(&first.payload[..], &[0x55_u8; 160][..]);
        let second = backchannel.next().await.unwrap();
        assert_eq!(
            (second.rtp.seq, second.rtp.ts, second.rtp.marker),
            (101, 5_320, false)
        );
    }

    #[tokio::test]
    async fn without_ptime_the_frame_is_20_ms_and_the_queue_drops_when_full() {
        let slot = BackchannelSlot::default();
        let _backchannel = Backchannel::offer(slot.clone(), pcmu(0), INITIAL);
        let handle = slot.current().unwrap();
        assert_eq!(handle.frame, BackchannelHandle::DEFAULT_FRAME);
        let now = SystemClock.now();
        let mut ts = 0;
        for _ in 0..QUEUE {
            handle.sender.try_send(uplink(now, ts, false)).unwrap();
            ts += 160;
        }
        assert!(handle.sender.try_send(uplink(now, 0, false)).is_err());
    }

    #[tokio::test]
    async fn dropping_the_backchannel_withdraws_the_handle_and_a_new_one_restarts_the_stream() {
        let slot = BackchannelSlot::default();
        let first = Backchannel::offer(slot.clone(), pcmu(0), INITIAL);
        let old = slot.current().unwrap();
        drop(first);
        assert!(slot.current().is_none(), "withdrawn with the session");
        let mut second = Backchannel::offer(slot.clone(), pcmu(0), Initial { seq: 9, ..INITIAL });
        let new = slot.current().unwrap();
        assert!(!new.sender.same_channel(&old.sender), "a fresh queue");
        assert!(old.sender.is_closed(), "nothing reads the old queue");
        new.sender
            .try_send(uplink(SystemClock.now(), 0, false))
            .unwrap();
        let packet = second.next().await.unwrap();
        assert_eq!(packet.rtp.seq, 9, "a fresh packetizer");
        assert!(packet.rtp.marker, "the new stream's first packet");
    }
}
