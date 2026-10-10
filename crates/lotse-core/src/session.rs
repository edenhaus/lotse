//! The session contract: what a session-shaped output (WebRTC now, WHEP
//! later) implements and what the worker's session task drives.
//!
//! The engine is sans-IO: the worker feeds it datagrams, timeouts, remote
//! candidates and live packets, and drains what it wants sent and what
//! happened. Core knows offers, answers and candidates only as opaque
//! strings, so the worker never links a WebRTC engine; the binary registers
//! the factory that opens sessions.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::codec::{Codec, CodecFamily};
use crate::media::MediaPacket;
use crate::orientation::Orientation;
use crate::track::{GopSnapshot, TrackEvent};

/// The ICE credentials the supervisor chose for a session, so its demux
/// can verify STUN integrity.
#[derive(Clone, PartialEq, Eq)]
pub struct IceCredentials {
    /// The local username fragment, the demux key.
    pub ufrag: String,
    /// The local password; redacted in `Debug`.
    pub pass: String,
}

impl fmt::Debug for IceCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceCredentials")
            .field("ufrag", &self.ufrag)
            .field("pass", &"<redacted>")
            .finish()
    }
}

/// The `webrtc.*` tunables a session applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    /// A live packet older than this is dropped and the session skips to
    /// the next keyframe (`webrtc.max_packet_age`).
    pub max_packet_age: Duration,
    /// A live video frame that arrived later than this against the track's
    /// recent best (an ingest stall) is dropped and the session skips to
    /// the next timely keyframe (`sources.max_ingest_lateness`).
    pub max_ingest_lateness: Duration,
    /// A cached keyframe up to this old gets a catch-up burst on join;
    /// older gets a still (`webrtc.catchup_max_age`).
    pub catchup_max_age: Duration,
    /// The `playout-delay` min and max, in milliseconds
    /// (`webrtc.playout_delay`).
    pub playout_delay_ms: (u16, u16),
    /// How long a session may stay unconnected before `ice_failed`.
    pub connect_timeout: Duration,
    /// How long consent may stay lost before `ice_failed`.
    pub disconnect_timeout: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_packet_age: Duration::from_millis(150),
            max_ingest_lateness: Duration::from_millis(200),
            catchup_max_age: Duration::from_millis(500),
            playout_delay_ms: (0, 0),
            connect_timeout: Duration::from_secs(10),
            disconnect_timeout: Duration::from_secs(10),
        }
    }
}

/// What a datagram travels on: the shared UDP socket, or an ICE-TCP
/// connection (RFC 6544) with RFC 4571 framing, which the worker frames and
/// unframes so the engine only sees whole datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP.
    Udp,
    /// ICE-TCP.
    Tcp,
}

/// What the worker hands an output factory to open one session.
#[derive(Debug, Clone)]
pub struct SessionRequest {
    /// The viewer's offer, verbatim.
    pub offer: String,
    /// The local ICE credentials.
    pub ice: IceCredentials,
    /// The host candidates: the shared socket's addresses.
    pub candidates: Vec<SocketAddr>,
    /// The passive ICE-TCP host candidates: the listener's addresses.
    pub tcp_candidates: Vec<SocketAddr>,
    /// The video track's codec.
    pub video: Arc<Codec>,
    /// The audio track's codec, when the stream has one and audio is on.
    pub audio: Option<Arc<Codec>>,
    /// The codec the connection's backchannel takes, when its source
    /// protocol can carry audio back (`SourceCapabilities::backchannel`,
    /// the feature's gate) and the source offers one now. `None` answers
    /// talk-back `inactive`. Never whether another session talks: the
    /// answer stays a function of the offer and this.
    pub backchannel: Option<Codec>,
    /// How the stream's picture is turned for display: the stream's
    /// `orientation`, which an output marks when the viewer can apply it.
    pub orientation: Orientation,
    /// The tunables.
    pub limits: SessionLimits,
    /// The wall clock, read with the `now` the session opens at: the
    /// anchor that puts the session's capture times, which are monotonic,
    /// on the wall clock a receiver compares them with (`abs-capture-time`).
    pub wall: SystemTime,
}

/// Why a session could not be opened; each maps to a `closed` code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionOpenError {
    /// The offer is not an SDP the engine accepts.
    #[error("invalid offer: {0}")]
    InvalidSdp(String),
    /// The offer has no video m-line.
    #[error("the offer has no video m-line")]
    NoVideoTrack,
    /// No offered video payload type carries the stream's codec.
    #[error("video codec unsupported: {0}")]
    VideoCodecUnsupported(String),
    /// The output kind does not open sessions.
    #[error("{0} outputs do not open sessions")]
    NotASession(&'static str),
}

impl SessionOpenError {
    /// The `closed` code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSdp(_) => "invalid_sdp",
            Self::NoVideoTrack => "no_video_track",
            Self::VideoCodecUnsupported(_) => "video_codec_unsupported",
            Self::NotASession(_) => "internal_error",
        }
    }
}

/// What a session reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// A local candidate; an empty string is end-of-candidates.
    Candidate {
        /// The `candidate:` line, or empty.
        candidate: String,
        /// The mid it belongs to.
        mid: Option<String>,
    },
    /// ICE or DTLS changed; the names are the browser's.
    State {
        /// The ICE state.
        ice: &'static str,
        /// The DTLS state.
        dtls: &'static str,
    },
    /// ICE and DTLS are up: the worker joins the track now.
    Connected,
    /// The viewer asked for a keyframe (PLI or FIR).
    KeyframeRequest,
    /// Non-fatal.
    Warning {
        /// The code.
        code: &'static str,
        /// For humans.
        message: String,
    },
    /// The last event.
    Closed {
        /// The code.
        code: &'static str,
        /// For humans.
        message: String,
    },
}

/// What the engine wants next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOutput {
    /// A datagram to send, on the shared socket or an ICE-TCP connection.
    Transmit {
        /// Which.
        transport: Transport,
        /// The local address it leaves from.
        source: SocketAddr,
        /// The peer.
        destination: SocketAddr,
        /// The datagram.
        payload: Vec<u8>,
        /// The datagram is an RTP packet of the audio track, which the
        /// worker marks DSCP EF instead of the socket's AF41 (RFC 8837 §5);
        /// `false` for video, RTCP, STUN and DTLS.
        audio: bool,
    },
    /// Something happened.
    Event(SessionEvent),
    /// Nothing more until `handle_timeout` at this instant, or until input.
    Timeout(Instant),
}

/// A session's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Packets written to the engine.
    pub packets: u64,
    /// Payload bytes of those packets.
    pub bytes: u64,
    /// Live packets dropped for exceeding `max_packet_age`.
    pub dropped_old: u64,
    /// Live packets dropped while waiting for a keyframe.
    pub dropped_waiting: u64,
    /// Live packets dropped for exceeding `max_ingest_lateness`.
    pub dropped_late: u64,
    /// Skips to the next keyframe because a frame arrived late after an
    /// ingest stall; one per stall, however many frames it delayed.
    pub ingest_late_skips: u64,
    /// Skips to the next keyframe.
    pub skips: u64,
    /// Frames sent in more RTP packets than some libwebrtc receivers
    /// assemble; each was sent whole.
    pub frames_over_browser_limit: u64,
    /// Keyframe requests from the viewer.
    pub keyframe_requests: u64,
    /// Frames written on join, burst or still.
    pub join_frames: u64,
    /// Audio packets written to the engine.
    pub audio_packets: u64,
    /// Payload bytes of those packets.
    pub audio_bytes: u64,
    /// Audio packets dropped: too old, arrived late after an ingest stall,
    /// or before the session connected. Audio has no keyframes, so a drop
    /// is only a drop.
    pub audio_dropped: u64,
    /// Datagrams that were not valid input.
    pub bad_datagrams: u64,
}

/// One session's engine. Every method is followed by a full `poll` drain
/// by the task that owns it; there is no other access.
pub trait SessionEngine: fmt::Debug + Send {
    /// A datagram the supervisor's demux routed here, or a frame off one of
    /// the session's ICE-TCP connections.
    fn handle_datagram(
        &mut self,
        now: Instant,
        transport: Transport,
        source: SocketAddr,
        destination: SocketAddr,
        bytes: &[u8],
    );

    /// The instant a [`SessionOutput::Timeout`] named has passed.
    fn handle_timeout(&mut self, now: Instant);

    /// A trickled remote candidate; empty means end-of-candidates.
    fn add_remote_candidate(&mut self, now: Instant, candidate: &str);

    /// A relay candidate (RFC 8445 §5.1.1.2): `relayed`, the address a
    /// TURN allocation relays from, whose own traffic leaves `local`, the
    /// shared socket. Returns its `candidate` line (RFC 8839 §5.1) for the
    /// viewer, or `None` when the engine does not take it. What the engine
    /// sends from `relayed` the worker relays through the allocation's
    /// server.
    fn add_relay_candidate(
        &mut self,
        now: Instant,
        relayed: SocketAddr,
        local: SocketAddr,
    ) -> Option<String>;

    /// Joins the video track once connected: a catch-up burst or a still
    /// from the GOP cache, or nothing when the cache is empty.
    fn join(&mut self, now: Instant, gop: Option<&GopSnapshot>);

    /// A live video packet, with its capture time from the clock map.
    fn write_video(&mut self, now: Instant, packet: &MediaPacket, wallclock: Instant);

    /// A live audio packet, with its capture time from the same clock map
    /// as the video's, so both tracks' Sender Reports share one base.
    fn write_audio(&mut self, now: Instant, packet: &MediaPacket, wallclock: Instant);

    /// Drops live packets until the next keyframe (a `Gap`).
    fn skip_to_keyframe(&mut self, reason: &'static str);

    /// The stream's orientation changed (a `stream/put`): the frames from
    /// the next one on carry `orientation` where the answer negotiated a
    /// way to say it, so the viewer turns the picture without a new
    /// session. Without one the picture goes on as it was.
    fn set_orientation(&mut self, orientation: Orientation);

    /// Whether the video can go on under the payload type the answer
    /// named now that its track's codec changed to `codec` within the
    /// family the session opened with: the rule that answered the offer
    /// judges the new codec too.
    /// `Err` says why not, and the session closes with `stream_changed`.
    fn check_video_change(&self, codec: &Codec) -> Result<(), String>;

    /// Ends the session: the transport is closed and `Closed` follows.
    fn close(&mut self, now: Instant, code: &'static str, message: String);

    /// The next output.
    fn poll(&mut self) -> SessionOutput;

    /// The counters now.
    fn stats(&self) -> SessionStats;
}

/// What a session does with one event of its video subscription, or with
/// its end (`None`): the reactions the output contract requires of every
/// event. `family` is the video family the session opened with;
/// `wallclock` maps a packet to its capture time.
///
/// - a packet is written;
/// - a `Gap` (the session lagged) and an `EpochStart` (a reconnect or a
///   timestamp discontinuity) skip to the next keyframe, so the viewer
///   never gets a P-frame whose reference it lacks;
/// - a `TrackChanged` closes with `stream_changed` when the family
///   changed, or when the engine finds the new codec outside the payload
///   type it negotiated ([`SessionEngine::check_video_change`]); else the
///   browser follows parameter-set changes in band;
/// - `SourceLost` and `SourceRestored` keep the session: the stream
///   reconnects, and media resumes with the new epoch's keyframe;
/// - the track's end closes with `stream_deleted`.
pub fn apply_track_event(
    engine: &mut dyn SessionEngine,
    now: Instant,
    family: CodecFamily,
    event: Option<TrackEvent>,
    wallclock: impl FnOnce(&MediaPacket) -> Instant,
) {
    match event {
        Some(TrackEvent::Packet(packet)) => {
            let at = wallclock(&packet);
            engine.write_video(now, &packet, at);
        }
        Some(TrackEvent::Gap { skipped }) => {
            tracing::warn!(skipped, "session lagged; skipping to the next keyframe");
            engine.skip_to_keyframe("gap");
        }
        Some(TrackEvent::EpochStart { epoch }) => {
            tracing::debug!(epoch, "new epoch; waiting for its keyframe");
            engine.skip_to_keyframe("epoch");
        }
        Some(TrackEvent::TrackChanged(codec)) if codec.family() != family => {
            engine.close(
                now,
                "stream_changed",
                format!("video is now {}", codec.name()),
            );
        }
        Some(TrackEvent::TrackChanged(codec)) => match engine.check_video_change(&codec) {
            Ok(()) => tracing::debug!(codec = codec.name(), "codec changed within the family"),
            Err(reason) => {
                tracing::info!(reason, "video outside its payload type; closing");
                engine.close(now, "stream_changed", reason);
            }
        },
        Some(TrackEvent::SourceLost) => tracing::info!("source lost; the session waits"),
        Some(TrackEvent::SourceRestored) => tracing::info!("source restored"),
        // A packet subscription yields no frames.
        Some(TrackEvent::Frame(_)) => {}
        None => engine.close(now, "stream_deleted", "the track closed".to_owned()),
    }
}

/// What a session does with one event of its audio subscription, or with
/// its end (`None`); returns whether to keep reading it.
///
/// - a packet is written; audio starts at the live edge and needs no
///   keyframe, so a `Gap` (the session lagged) loses packets and nothing
///   else, and an `EpochStart` needs nothing: the writer's timestamp
///   offset follows each packet's epoch;
/// - a `TrackChanged` closes with `stream_changed` only when the family
///   changed, since the answer named the old codec's payload type;
/// - `SourceLost` and `SourceRestored` keep the session;
/// - the track's end stops the audio; the video track's end closes the
///   session.
pub fn apply_audio_event(
    engine: &mut dyn SessionEngine,
    now: Instant,
    family: CodecFamily,
    event: Option<TrackEvent>,
    wallclock: impl FnOnce(&MediaPacket) -> Instant,
) -> bool {
    match event {
        Some(TrackEvent::Packet(packet)) => {
            let at = wallclock(&packet);
            engine.write_audio(now, &packet, at);
            true
        }
        Some(TrackEvent::Gap { skipped }) => {
            tracing::debug!(skipped, "audio lagged; packets lost");
            true
        }
        Some(TrackEvent::TrackChanged(codec)) if codec.family() != family => {
            engine.close(
                now,
                "stream_changed",
                format!("audio is now {}", codec.name()),
            );
            false
        }
        Some(
            TrackEvent::EpochStart { .. }
            | TrackEvent::TrackChanged(_)
            | TrackEvent::SourceLost
            | TrackEvent::SourceRestored
            | TrackEvent::Frame(_),
        ) => true,
        None => {
            tracing::info!("audio track closed; the session continues with video");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    /// The wallclock of every `apply_track_event` and `apply_audio_event`
    /// call here: one type, so one instantiation of each runs every arm,
    /// which is the one the line-coverage gate counts.
    type Wallclock<'a> = Box<dyn FnOnce(&MediaPacket) -> Instant + 'a>;

    /// A wallclock that answers `now`.
    fn at(now: Instant) -> Wallclock<'static> {
        Box::new(move |_| now)
    }

    #[test]
    fn credentials_redact_and_errors_map_to_codes() {
        let creds = IceCredentials {
            ufrag: "u".into(),
            pass: "secret".into(),
        };
        let debug = format!("{creds:?}");
        assert!(debug.contains("ufrag: \"u\"") && !debug.contains("secret"));
        assert_eq!(
            SessionOpenError::InvalidSdp("x".into()).code(),
            "invalid_sdp"
        );
        assert_eq!(SessionOpenError::NoVideoTrack.code(), "no_video_track");
        assert_eq!(
            SessionOpenError::VideoCodecUnsupported("h265".into()).code(),
            "video_codec_unsupported"
        );
        assert_eq!(SessionOpenError::NotASession("x").code(), "internal_error");
        assert_eq!(
            SessionLimits::default().max_packet_age,
            Duration::from_millis(150)
        );
        assert_eq!(
            SessionLimits::default().max_ingest_lateness,
            Duration::from_millis(200),
            "sources.max_ingest_lateness"
        );
    }

    #[test]
    fn a_codec_the_engine_no_longer_takes_within_the_family_closes_stream_changed() {
        use crate::clock::{Clock as _, SystemClock};
        use crate::test_util::EchoEngine;

        let now = SystemClock.now();
        let h264 = CodecFamily::H264;
        // A codec the engine's payload type no longer
        // takes closes with stream_changed and the engine's reason.
        let mut engine = EchoEngine::new(now).refusing_video_changes();
        let main = Codec::H264 {
            profile_level_id: Some([0x4d, 0, 0x28]),
            sps: None,
            pps: None,
        };
        apply_track_event(
            &mut engine,
            now,
            h264,
            Some(TrackEvent::TrackChanged(Arc::new(main))),
            at(now),
        );
        assert!(
            matches!(
                engine.poll(),
                SessionOutput::Event(SessionEvent::Closed {
                    code: "stream_changed",
                    message,
                }) if message == "the echo refuses h264"
            ),
            "the engine's reason"
        );
    }

    #[test]
    fn every_track_event_has_its_reaction() {
        use crate::clock::{Clock as _, SystemClock};
        use crate::media::RtpHeaderFields;
        use crate::test_util::EchoEngine;

        let now = SystemClock.now();
        let mut engine = EchoEngine::new(now);
        let packet = Arc::new(MediaPacket {
            arrival: now,
            rtp: RtpHeaderFields {
                pt: 96,
                seq: 1,
                ts: 3_000,
                marker: true,
                ssrc: 1,
            },
            frame_start: true,
            keyframe_start: true,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0x65_u8][..]),
        });
        let h264 = CodecFamily::H264;
        let mut mapped = None;
        let wallclock: Wallclock<'_> = Box::new(|p| {
            mapped = Some(p.rtp.ts);
            now
        });
        apply_track_event(
            &mut engine,
            now,
            h264,
            Some(TrackEvent::Packet(packet)),
            wallclock,
        );
        assert_eq!(mapped, Some(3_000), "the wallclock is asked for the packet");
        assert_eq!(engine.stats().packets, 1);
        for event in [
            TrackEvent::Gap { skipped: 4 },
            TrackEvent::EpochStart { epoch: 1 },
        ] {
            apply_track_event(&mut engine, now, h264, Some(event), at(now));
        }
        assert_eq!(
            engine.stats().skips,
            2,
            "a gap and a new epoch wait for a keyframe"
        );
        // Within the family, source loss, and a frame a packet
        // subscription never yields: the session stays.
        let high = Codec::H264 {
            profile_level_id: Some([0x64, 0, 0x28]),
            sps: None,
            pps: None,
        };
        let frame = crate::media::MediaFrame {
            ts: crate::media::MediaTime::ZERO,
            wallclock: now,
            arrival: now,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: bytes::Bytes::new(),
        };
        for event in [
            TrackEvent::TrackChanged(Arc::new(high)),
            TrackEvent::SourceLost,
            TrackEvent::SourceRestored,
            TrackEvent::Frame(Arc::new(frame)),
        ] {
            apply_track_event(&mut engine, now, h264, Some(event), at(now));
        }
        assert!(
            matches!(engine.poll(), SessionOutput::Timeout(_)),
            "nothing closed"
        );
        // Another family closes with stream_changed.
        let h265 = Codec::H265 {
            vps: None,
            sps: None,
            pps: None,
        };
        apply_track_event(
            &mut engine,
            now,
            h264,
            Some(TrackEvent::TrackChanged(Arc::new(h265))),
            at(now),
        );
        assert!(matches!(
            engine.poll(),
            SessionOutput::Event(SessionEvent::Closed {
                code: "stream_changed",
                ..
            })
        ));
        // The track's end closes with stream_deleted.
        let mut engine = EchoEngine::new(now);
        apply_track_event(&mut engine, now, h264, None, at(now));
        assert!(matches!(
            engine.poll(),
            SessionOutput::Event(SessionEvent::Closed {
                code: "stream_deleted",
                ..
            })
        ));
    }

    #[test]
    fn every_audio_event_has_its_reaction() {
        use crate::clock::{Clock as _, SystemClock};
        use crate::media::RtpHeaderFields;
        use crate::test_util::EchoEngine;

        let now = SystemClock.now();
        let mut engine = EchoEngine::new(now);
        let packet = Arc::new(MediaPacket {
            arrival: now,
            rtp: RtpHeaderFields {
                pt: 0,
                seq: 1,
                ts: 160,
                marker: false,
                ssrc: 2,
            },
            frame_start: true,
            keyframe_start: false,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0xff_u8; 160][..]),
        });
        let pcmu = CodecFamily::Pcmu;
        let mut mapped = None;
        let wallclock: Wallclock<'_> = Box::new(|p| {
            mapped = Some(p.rtp.ts);
            now
        });
        assert!(apply_audio_event(
            &mut engine,
            now,
            pcmu,
            Some(TrackEvent::Packet(packet)),
            wallclock,
        ));
        assert_eq!(mapped, Some(160), "the wallclock is asked for the packet");
        assert_eq!(engine.stats().audio_packets, 1);
        assert!(matches!(
            engine.poll(),
            SessionOutput::Event(SessionEvent::Warning {
                code: "echo_audio",
                ..
            })
        ));
        // Nothing waits for a keyframe, nothing closes.
        for event in [
            TrackEvent::Gap { skipped: 4 },
            TrackEvent::EpochStart { epoch: 1 },
            TrackEvent::TrackChanged(Arc::new(Codec::Pcmu)),
            TrackEvent::SourceLost,
            TrackEvent::SourceRestored,
        ] {
            assert!(apply_audio_event(
                &mut engine,
                now,
                pcmu,
                Some(event),
                at(now)
            ));
        }
        assert_eq!(engine.stats().skips, 0);
        assert!(matches!(engine.poll(), SessionOutput::Timeout(_)));
        // Another family closes with stream_changed.
        assert!(!apply_audio_event(
            &mut engine,
            now,
            pcmu,
            Some(TrackEvent::TrackChanged(Arc::new(Codec::Opus {
                channels: 2
            }))),
            at(now),
        ));
        assert!(matches!(
            engine.poll(),
            SessionOutput::Event(SessionEvent::Closed {
                code: "stream_changed",
                ..
            })
        ));
        // The track's end stops the audio and keeps the session.
        let mut engine = EchoEngine::new(now);
        assert!(!apply_audio_event(&mut engine, now, pcmu, None, at(now)));
        assert!(matches!(engine.poll(), SessionOutput::Timeout(_)));
    }
}
