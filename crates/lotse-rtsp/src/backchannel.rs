//! The camera's ONVIF backchannel (ONVIF Streaming Specification §5.3):
//! the format it takes, read from its SDP; the packetizer that stamps the
//! talk-back chain's packets with the camera's payload type and the
//! session's own sequence numbers, timestamps and SSRC; and the
//! connections of its own the backchannel lives on, apart from the
//! session that plays the stream.
//!
//! [`backchannel_format`] reads one SDP media description, and a
//! [`Packetizer`] turns the packets a talker's backchannel session receives
//! (the talk-back transcoder's G.711 frames, or a browser's Opus packets
//! forwarded as they are) into [`BackchannelPacket`]s, the RTP header
//! fields and the payload, without a wire format: retina serializes them
//! on the backchannel's interleaved channel with its own SSRC and sequence
//! numbers. [`session`] holds the decisions: the `Require` header, which
//! media of a `DESCRIBE` answer is the backchannel, what a probe's `551`
//! means for the source, and what a refusal says. The crate's `probe`
//! module asks the camera, once the stream's session plays, on a
//! connection of its own; its `open` module opens the backchannel in a
//! session of its own when a talker claims it and closes it at the
//! release; its `camera` module is how both reach the camera.
//!
//! Implements RFC 8866 §5.14 (the `m=` format list, in order of preference),
//! §6.4 (`a=ptime`) and §6.6 (`a=rtpmap`), with encoding names compared
//! case-insensitively (RFC 4855 §3); RFC 3551 Table 4 (the static payload
//! types 0 and 8) and §4.5.14 (G.711 at 8 kHz); RFC 7587 §7 (`opus/48000/2`);
//! RFC 3550 §5.1 (sequence numbers that count packets from a random start,
//! timestamps from a random offset that advance with the sampling clock
//! across silence, and never ahead of the wall clock by more than a
//! lead) and §8.1 (a random SSRC); RFC 3551 §4.1 (the marker on
//! the first packet of a talkspurt); ONVIF Streaming Specification §5.3 (the
//! backchannel media whose format this is).

pub(crate) mod camera;
pub(crate) mod open;
pub(crate) mod probe;
pub mod session;

use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_core::codec::Codec;
use lotse_core::media::{MediaPacket, RtpHeaderFields};
use lotse_core::throttle::Throttle;
use sdp_types::Media;

use crate::error::camera_text;

/// The G.711 RTP clock rate (RFC 3551 §4.5.14).
const G711_CLOCK_RATE: u32 = 8_000;

/// The Opus RTP clock rate (RFC 7587 §4.1).
const OPUS_CLOCK_RATE: u32 = 48_000;

/// The static payload type of PCMU (RFC 3551 Table 4).
const PCMU_STATIC_PT: u8 = 0;

/// The static payload type of PCMA (RFC 3551 Table 4).
const PCMA_STATIC_PT: u8 = 8;

/// The largest payload type: the field has seven bits (RFC 3550 §5.1).
const MAX_PAYLOAD_TYPE: u8 = 127;

/// Nanoseconds per second, for timestamps from elapsed time.
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// The format a camera takes on its backchannel: what the talk-back chain
/// produces and how the packetizer stamps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackchannelFormat {
    /// The codec the camera accepts: PCMU, PCMA or Opus.
    pub codec: Codec,
    /// The payload type the camera's SDP gives that codec, which may be a
    /// dynamic one: the camera matches what it receives against its own
    /// `a=rtpmap` fields (ONVIF Streaming Specification §5.3.2).
    pub payload_type: u8,
    /// The RTP clock rate: 8000 for G.711, 48000 for Opus.
    pub clock_rate: u32,
    /// The packet duration the camera asks for with `a=ptime` (RFC 8866
    /// §6.4), in whole milliseconds; `None` when it names none, and the
    /// talk-back chain's default applies.
    pub ptime: Option<Duration>,
}

/// The format of a camera's backchannel media: the first entry of its
/// `m=` format list (RFC 8866 §5.14, in order of preference) the talk-back
/// chain can produce, PCMU, PCMA or Opus, with the payload type the camera
/// gave it; `None` when the media is not audio or offers none of them.
///
/// A format is named by its `a=rtpmap` (RFC 8866 §6.6), else by its static
/// payload type (RFC 3551 Table 4: 0 is PCMU, 8 is PCMA). G.711 must run at
/// 8000 Hz, mono (RFC 3551 §4.5.14), Opus at 48000 Hz (RFC 7587 §7); other
/// formats (G.722, AAC, a G.711 at another rate) are skipped. The camera's
/// text reaches the log capped: the media name as `camera_text`, the
/// format list as one line of counts, however many tokens it has.
pub fn backchannel_format(media: &Media) -> Option<BackchannelFormat> {
    if !media.media.eq_ignore_ascii_case("audio") {
        tracing::debug!(media = %camera_text(&media.media), "backchannel: not an audio media");
        return None;
    }
    let ptime = media
        .get_first_attribute_value("ptime")
        .flatten()
        .and_then(parse_ptime);
    let mut not_payload_type: usize = 0;
    let mut unsupported: usize = 0;
    let mut chosen = None;
    for format in media.fmt.split_ascii_whitespace() {
        let Some(payload_type) = format
            .parse::<u8>()
            .ok()
            .filter(|pt| *pt <= MAX_PAYLOAD_TYPE)
        else {
            not_payload_type = not_payload_type.saturating_add(1);
            continue;
        };
        if let Some((codec, clock_rate)) = codec_of(payload_type, rtpmap(media, payload_type)) {
            chosen = Some(BackchannelFormat {
                codec,
                payload_type,
                clock_rate,
                ptime,
            });
            break;
        }
        unsupported = unsupported.saturating_add(1);
    }
    tracing::debug!(
        chosen = ?chosen.as_ref().map(|format| format.payload_type),
        not_payload_type,
        unsupported,
        "backchannel: format list read"
    );
    chosen
}

/// One `a=rtpmap` value, split: the encoding name, the clock rate and the
/// encoding parameters (the channel count for audio), as written.
type Rtpmap<'a> = (&'a str, &'a str, Option<&'a str>);

/// The `a=rtpmap` of `payload_type` in `media` (RFC 8866 §6.6:
/// `<payload type> <encoding name>/<clock rate>[/<encoding parameters>]`),
/// if it has one that parses.
fn rtpmap(media: &Media, payload_type: u8) -> Option<Rtpmap<'_>> {
    media.attributes.iter().find_map(|attribute| {
        if attribute.attribute != "rtpmap" {
            return None;
        }
        let (pt, encoding) = attribute.value.as_deref()?.trim().split_once(' ')?;
        if pt.parse::<u8>().ok()? != payload_type {
            return None;
        }
        let mut parts = encoding.trim().splitn(3, '/');
        let name = parts.next()?;
        let rate = parts.next()?;
        Some((name, rate, parts.next()))
    })
}

/// The codec and clock rate of `payload_type` the talk-back chain can
/// produce, from its rtpmap or, without one, its static assignment.
fn codec_of(payload_type: u8, rtpmap: Option<Rtpmap<'_>>) -> Option<(Codec, u32)> {
    let Some((name, rate, channels)) = rtpmap else {
        return match payload_type {
            PCMU_STATIC_PT => Some((Codec::Pcmu, G711_CLOCK_RATE)),
            PCMA_STATIC_PT => Some((Codec::Pcma, G711_CLOCK_RATE)),
            _ => None,
        };
    };
    let rate = rate.trim().parse::<u32>().ok()?;
    let channels = match channels {
        Some(channels) => Some(channels.trim().parse::<u8>().ok()?),
        None => None,
    };
    let g711 = rate == G711_CLOCK_RATE && matches!(channels, None | Some(1));
    if name.eq_ignore_ascii_case("pcmu") && g711 {
        Some((Codec::Pcmu, G711_CLOCK_RATE))
    } else if name.eq_ignore_ascii_case("pcma") && g711 {
        Some((Codec::Pcma, G711_CLOCK_RATE))
    } else if name.eq_ignore_ascii_case("opus")
        && rate == OPUS_CLOCK_RATE
        && matches!(channels, None | Some(1 | 2))
    {
        Some((
            Codec::Opus {
                channels: channels.unwrap_or(2),
            },
            OPUS_CLOCK_RATE,
        ))
    } else {
        None
    }
}

/// An `a=ptime` value (RFC 8866 §6.4) in whole milliseconds, above zero.
/// A fractional one is ignored, as no G.711 or Opus frame size is one.
fn parse_ptime(value: &str) -> Option<Duration> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
}

/// The first values of one backchannel session's RTP stream: random, as
/// RFC 3550 §5.1 (sequence number, timestamp) and §8.1 (SSRC) ask, so a
/// camera never takes a new session's packets for an old one's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initial {
    /// The synchronization source.
    pub ssrc: u32,
    /// The first packet's sequence number.
    pub seq: u16,
    /// The first packet's timestamp.
    pub ts: u32,
}

impl Initial {
    /// Fresh values from the operating system's entropy source.
    ///
    /// # Errors
    ///
    /// When the entropy source fails.
    pub fn random() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; 10];
        getrandom::fill(&mut bytes)?;
        let [s0, s1, s2, s3, q0, q1, t0, t1, t2, t3] = bytes;
        Ok(Self {
            ssrc: u32::from_be_bytes([s0, s1, s2, s3]),
            seq: u16::from_be_bytes([q0, q1]),
            ts: u32::from_be_bytes([t0, t1, t2, t3]),
        })
    }
}

/// One packet for the camera's backchannel: the RTP header fields (RFC 3550
/// §5.1) and the payload, for whatever send path serializes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackchannelPacket {
    /// The header: the camera's payload type, the session's SSRC, sequence
    /// number and timestamp, the marker on a talkspurt's first packet.
    pub rtp: RtpHeaderFields,
    /// The RTP payload, as the backchannel handle received it.
    pub payload: Arc<[u8]>,
}

/// What a [`Packetizer`] keeps of the last packet: the talkspurt it
/// belongs to and where it was sent.
#[derive(Debug, Clone, Copy)]
struct Last {
    /// The input's SSRC: another one is another sender.
    input_ssrc: u32,
    /// Added to an input timestamp of the talkspurt to get the output's.
    offset: u32,
    /// The input timestamp.
    input_ts: u32,
    /// The output timestamp.
    ts: u32,
    /// When it arrived.
    arrival: Instant,
}

/// A timestamp step at or above this is backwards: RTP timestamps wrap,
/// and the nearer reading wins (RFC 3550 §5.1).
const HALF_RANGE: u32 = 0x8000_0000;

/// How far a backchannel session's timestamps may run ahead of the wall
/// clock: 250 ms, a burst the talker's pace lets through (120 ms) and the
/// longest frame (120 ms), rounded up, so paced audio is never held.
const MAX_LEAD: Duration = Duration::from_millis(250);

/// Stamps a backchannel session's packets: the camera's payload type, one
/// SSRC, a sequence number one past the previous packet's, and timestamps
/// that advance with the sampling clock across silence (RFC 3550 §5.1),
/// whatever the input.
///
/// Within a talkspurt the output timestamps follow the input's at a fixed
/// offset, so the sender's timing (the transcoder's frames, a browser's
/// packets) is kept. A new talkspurt starts with an input packet that has
/// the marker (RFC 3551 §4.1), another SSRC (another sender, or a
/// talk-back chain restarted for a new talker, whose timestamps restart
/// too) or a timestamp further behind the last than reordering explains
/// (a discontinuity in the sender's timeline): its timestamp is the previous packet's advanced by the time
/// between their arrivals, at least by the last packet spacing so the two
/// never overlap, and it carries the marker.
///
/// Whatever the input's timestamps claim, the output's keep to the wall
/// clock: a timestamp more than 250 ms past where the first packet's
/// arrival puts the wall clock now is held there, and its talkspurt
/// follows on from it. The sampling clock the timestamps follow runs in
/// real time (RFC 3550 §5.1), so a sender whose timestamps run faster
/// (loss it claims, packets dropped ahead of real time, talkspurts
/// restarted on top of each other) moves the camera's timeline no further
/// than the wall clock. This is the one bound every route to the camera
/// meets: the talk-back chain's frames and Opus forwarded as received.
#[derive(Debug, Clone)]
pub struct Packetizer {
    /// The payload type every packet carries.
    payload_type: u8,
    /// The RTP clock rate, for timestamps from elapsed time.
    clock_rate: u32,
    /// The SSRC every packet carries.
    ssrc: u32,
    /// The next packet's sequence number.
    seq: u16,
    /// The first packet's timestamp.
    first_ts: u32,
    /// The last packet, once one was sent.
    last: Option<Last>,
    /// The last forward timestamp step inside a talkspurt: the packet
    /// duration, as far as the input shows it; zero before one was seen.
    step: u32,
    /// The first packet's timestamp and arrival: where the wall clock sits
    /// on the output timeline. `None` before the first packet.
    anchor: Option<(u32, Instant)>,
    /// [`MAX_LEAD`] in ticks of the clock rate.
    lead: u32,
    /// Timestamps held to the wall clock, for the log.
    held: Throttle,
    /// Talkspurts started, for the log: a sender can start one a packet.
    talkspurts: Throttle,
}

impl Packetizer {
    /// A packetizer for a camera's backchannel `format` whose stream starts
    /// at `initial`.
    pub fn new(format: &BackchannelFormat, initial: Initial) -> Self {
        Self {
            payload_type: format.payload_type,
            clock_rate: format.clock_rate,
            ssrc: initial.ssrc,
            seq: initial.seq,
            first_ts: initial.ts,
            last: None,
            step: 0,
            anchor: None,
            lead: ticks(MAX_LEAD, format.clock_rate),
            held: Throttle::default(),
            talkspurts: Throttle::default(),
        }
    }

    /// Whether input timestamp `ts` reads as more than [`MAX_LEAD`] behind
    /// `last`, the one before it from the same sender, on the nearer
    /// reading (RFC 3550 §5.1): no reordered packet but a discontinuity in
    /// the sender's timeline, which starts a talkspurt as a new sender
    /// would, on the wall clock, so the camera's timeline never jumps
    /// back. A step back within the lead is reordering and keeps the
    /// talkspurt.
    fn jumps_back(&self, ts: u32, last: u32) -> bool {
        let back = last.wrapping_sub(ts);
        back > self.lead && back <= HALF_RANGE
    }

    /// `ts` for a packet arriving at `arrival`, or the wall clock's limit
    /// when `ts` runs further ahead: [`MAX_LEAD`] past the first packet's
    /// timestamp advanced by the time since it arrived. Every packet is
    /// judged against that limit alone, on the nearer reading (RFC 3550
    /// §5.1), never against the packet before it, so no run of jumps that
    /// each read as backwards from the last can carry the timeline past
    /// it; a timestamp behind the limit (a reordered packet, a wrapped
    /// input) stands.
    fn hold(&mut self, ts: u32, arrival: Instant) -> u32 {
        let (first, since) = *self.anchor.get_or_insert((ts, arrival));
        let elapsed = ticks(arrival.saturating_duration_since(since), self.clock_rate);
        let limit = first.wrapping_add(elapsed).wrapping_add(self.lead);
        let ahead = ts.wrapping_sub(limit);
        if ahead == 0 || ahead >= HALF_RANGE {
            return ts;
        }
        if let Some(count) = self.held.hit(arrival) {
            tracing::debug!(
                ahead,
                count,
                "backchannel: timestamp held to the wall clock"
            );
        }
        limit
    }

    /// The backchannel packet for `packet`, one of the handle's input in
    /// the camera's codec.
    pub fn packetize(&mut self, packet: &MediaPacket) -> BackchannelPacket {
        let input = packet.rtp;
        let (ts, marker) = match self.last {
            Some(last)
                if !input.marker
                    && input.ssrc == last.input_ssrc
                    && !self.jumps_back(input.ts, last.input_ts) =>
            {
                let step = input.ts.wrapping_sub(last.input_ts);
                // A reordered packet's step is no packet duration.
                if step > 0 && step < HALF_RANGE {
                    self.step = step;
                }
                (input.ts.wrapping_add(last.offset), false)
            }
            Some(last) => {
                let elapsed = packet.arrival.saturating_duration_since(last.arrival);
                let advance = ticks(elapsed, self.clock_rate).max(self.step);
                let ts = last.ts.wrapping_add(advance);
                let sender_changed = input.ssrc != last.input_ssrc;
                let jumped_back = !input.marker && !sender_changed;
                if let Some(count) = self.talkspurts.hit(packet.arrival) {
                    tracing::debug!(
                        marker = input.marker,
                        sender_changed,
                        advance,
                        jumped_back,
                        count,
                        "backchannel: talkspurt"
                    );
                }
                (ts, true)
            }
            None => {
                tracing::debug!(
                    payload_type = self.payload_type,
                    ssrc = self.ssrc,
                    "backchannel: first talkspurt"
                );
                (self.first_ts, true)
            }
        };
        let ts = self.hold(ts, packet.arrival);
        let offset = ts.wrapping_sub(input.ts);
        self.last = Some(Last {
            input_ssrc: input.ssrc,
            offset,
            input_ts: input.ts,
            ts,
            arrival: packet.arrival,
        });
        let seq = self.seq;
        self.seq = seq.wrapping_add(1);
        tracing::trace!(seq, ts, marker, "backchannel: packet");
        BackchannelPacket {
            rtp: RtpHeaderFields {
                pt: self.payload_type,
                seq,
                ts,
                marker,
                ssrc: self.ssrc,
            },
            payload: Arc::clone(&packet.payload),
        }
    }
}

/// `elapsed` in ticks of `clock_rate`, modulo 2³² like any RTP timestamp
/// difference (RFC 3550 §5.1).
fn ticks(elapsed: Duration, clock_rate: u32) -> u32 {
    let ticks = elapsed
        .as_nanos()
        .saturating_mul(u128::from(clock_rate))
        .checked_div(NANOS_PER_SECOND)
        .unwrap_or(0);
    u32::try_from(ticks & u128::from(u32::MAX)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::clock::{Clock as _, SystemClock};

    use super::*;

    /// The first media description of a session whose media section is
    /// `lines` (CRLF added).
    fn media(lines: &[&str]) -> Media {
        let mut sdp = String::from("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n");
        for line in lines {
            sdp.push_str(line);
            sdp.push_str("\r\n");
        }
        sdp_types::Session::parse(sdp.as_bytes())
            .unwrap()
            .medias
            .remove(0)
    }

    fn format(lines: &[&str]) -> Option<BackchannelFormat> {
        backchannel_format(&media(lines))
    }

    fn g711(codec: Codec, payload_type: u8) -> BackchannelFormat {
        BackchannelFormat {
            codec,
            payload_type,
            clock_rate: 8_000,
            ptime: None,
        }
    }

    #[test]
    fn rfc3551_table_4_static_payload_types_without_rtpmap() {
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 0", "a=sendonly"]),
            Some(g711(Codec::Pcmu, 0))
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 8", "a=sendonly"]),
            Some(g711(Codec::Pcma, 8))
        );
    }

    #[test]
    fn rfc8866_6_6_a_dynamic_payload_type_is_named_by_its_rtpmap() {
        assert_eq!(
            format(&[
                "m=audio 0 RTP/AVP 97",
                "a=rtpmap:97 PCMA/8000",
                "a=sendonly"
            ]),
            Some(g711(Codec::Pcma, 97))
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 98", "a=rtpmap:98 PCMU/8000/1"]),
            Some(g711(Codec::Pcmu, 98))
        );
    }

    #[test]
    fn rfc8866_6_6_an_rtpmap_overrides_the_static_assignment() {
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 0", "a=rtpmap:0 PCMA/8000"]),
            Some(g711(Codec::Pcma, 0))
        );
    }

    #[test]
    fn rfc4855_3_encoding_and_media_names_are_case_insensitive() {
        assert_eq!(
            format(&["m=AUDIO 0 RTP/AVP 96", "a=rtpmap:96 pcmu/8000"]),
            Some(g711(Codec::Pcmu, 96))
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 96", "a=rtpmap:96 pCmA/8000"]),
            Some(g711(Codec::Pcma, 96))
        );
    }

    #[test]
    fn rfc8866_5_14_the_first_format_the_chain_produces_wins() {
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 0 8"]),
            Some(g711(Codec::Pcmu, 0))
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 8 0"]),
            Some(g711(Codec::Pcma, 8))
        );
        // G.722 (static 9) and AAC come first and are skipped.
        assert_eq!(
            format(&[
                "m=audio 0 RTP/AVP 9 96 8 0",
                "a=rtpmap:96 MPEG4-GENERIC/16000/1",
            ]),
            Some(g711(Codec::Pcma, 8))
        );
    }

    #[test]
    fn rfc3551_4_5_14_g711_at_another_rate_or_in_stereo_is_skipped() {
        assert_eq!(
            format(&[
                "m=audio 0 RTP/AVP 96 97 98 0",
                "a=rtpmap:96 PCMU/16000",
                "a=rtpmap:97 PCMU/8000/2",
                "a=rtpmap:98 PCMA/16000/1",
            ]),
            Some(g711(Codec::Pcmu, 0))
        );
    }

    #[test]
    fn rfc7587_7_opus_at_48000() {
        let opus = |channels| BackchannelFormat {
            codec: Codec::Opus { channels },
            payload_type: 111,
            clock_rate: 48_000,
            ptime: None,
        };
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 111", "a=rtpmap:111 opus/48000/2"]),
            Some(opus(2))
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 111", "a=rtpmap:111 OPUS/48000"]),
            Some(opus(2))
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 111", "a=rtpmap:111 opus/48000/1"]),
            Some(opus(1))
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 111", "a=rtpmap:111 opus/48000/3"]),
            None
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 111", "a=rtpmap:111 opus/8000"]),
            None
        );
    }

    #[test]
    fn onvif_5_3_the_fake_cameras_backchannel_media_gives_its_codec_payload_type_and_ptime() {
        use lotse_testing::fake_camera::{BackchannelCodec, CameraBackchannel};

        let cases = [
            (
                CameraBackchannel::new(BackchannelCodec::Pcmu),
                g711(Codec::Pcmu, 0),
            ),
            (
                CameraBackchannel {
                    payload_type: Some(97),
                    ptime: Some(40),
                    ..CameraBackchannel::new(BackchannelCodec::Pcma)
                },
                BackchannelFormat {
                    ptime: Some(Duration::from_millis(40)),
                    ..g711(Codec::Pcma, 97)
                },
            ),
            (
                CameraBackchannel::new(BackchannelCodec::Opus),
                BackchannelFormat {
                    codec: Codec::Opus { channels: 2 },
                    payload_type: 111,
                    clock_rate: 48_000,
                    ptime: None,
                },
            ),
        ];
        for (backchannel, expected) in cases {
            let config = lotse_testing::CameraConfig {
                audio: Some(lotse_testing::fake_camera::CameraAudio::Pcmu),
                backchannel: Some(backchannel),
                ..lotse_testing::CameraConfig::default()
            };
            let sdp = config.sdp("rtsp://127.0.0.1:1/stream/", true);
            let session = sdp_types::Session::parse(sdp.as_bytes()).unwrap();
            let sendonly: Vec<&Media> = session
                .medias
                .iter()
                .filter(|media| media.has_attribute("sendonly"))
                .collect();
            assert_eq!(sendonly.len(), 1);
            assert_eq!(backchannel_format(sendonly[0]), Some(expected));
        }
    }

    #[test]
    fn a_media_without_a_format_the_chain_produces_has_none() {
        assert_eq!(format(&["m=video 0 RTP/AVP 0"]), None);
        assert_eq!(format(&["m=audio 0 RTP/AVP 9"]), None);
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 96", "a=rtpmap:96 L16/8000"]),
            None
        );
    }

    #[test]
    fn rfc3550_5_1_formats_that_are_no_payload_type_are_skipped() {
        assert_eq!(
            format(&["m=audio 0 RTP/AVP x 200 128 0"]),
            Some(g711(Codec::Pcmu, 0))
        );
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 127", "a=rtpmap:127 PCMU/8000"]),
            Some(g711(Codec::Pcmu, 127))
        );
    }

    /// A camera's SDP may carry a format list or a media name of any
    /// length: the media name reaches the log as `camera_text`, cut to
    /// its cap and ending in the cut mark, and the formats skipped are one
    /// count per media, not one line per token.
    #[test]
    fn rfc8866_5_14_skipped_formats_are_one_count_per_media_and_the_media_name_is_capped() {
        use crate::error::CAMERA_TEXT_BYTES;
        use lotse_core::text::CUT_MARK;

        let tokens = "x ".repeat(5_000);
        let mut found = None;
        let logs = logged(|| {
            found = format(&[&format!("m=audio 0 RTP/AVP {tokens}200 9 96 0 8")]);
        });
        assert_eq!(found, Some(g711(Codec::Pcmu, 0)));
        let lines: Vec<&str> = logs.lines().collect();
        assert_eq!(lines.len(), 1, "{logs}");
        assert!(
            lines[0].ends_with(
                "backchannel: format list read chosen=Some(0) not_payload_type=5001 unsupported=2"
            ),
            "{logs}"
        );
        let logs = logged(|| found = format(&["m=audio 0 RTP/AVP 9"]));
        assert_eq!(found, None);
        assert!(
            logs.trim_end()
                .ends_with("chosen=None not_payload_type=0 unsupported=1"),
            "{logs}"
        );

        let name = "v".repeat(10_000);
        let logs = logged(|| found = format(&[&format!("m={name} 0 RTP/AVP 0")]));
        assert_eq!(found, None);
        let shown = format!("{}{CUT_MARK}", &name[..CAMERA_TEXT_BYTES - CUT_MARK.len()]);
        assert!(
            logs.trim_end()
                .ends_with(&format!("backchannel: not an audio media media={shown}")),
            "{logs}"
        );
        assert!(logs.len() < 2 * CAMERA_TEXT_BYTES, "{logs}");
    }

    #[test]
    fn rfc8866_6_6_rtpmaps_that_do_not_parse_name_nothing() {
        for rtpmap in [
            "a=rtpmap",
            "a=rtpmap:96",
            "a=rtpmap:x PCMU/8000",
            "a=rtpmap:96 PCMU",
            "a=rtpmap:96 PCMU/x",
            "a=rtpmap:96 PCMU/8000/x",
        ] {
            assert_eq!(format(&["m=audio 0 RTP/AVP 96", rtpmap]), None, "{rtpmap}");
        }
        // Another format's rtpmap and other attributes come first.
        assert_eq!(
            format(&[
                "m=audio 0 RTP/AVP 96",
                "a=sendonly",
                "a=rtpmap:97 PCMA/8000",
                "a=rtpmap:96 PCMU/8000",
            ]),
            Some(g711(Codec::Pcmu, 96))
        );
    }

    #[test]
    fn rfc8866_6_4_ptime_in_whole_milliseconds() {
        let ptime = |value: &str| {
            format(&["m=audio 0 RTP/AVP 0", &format!("a=ptime:{value}")])
                .unwrap()
                .ptime
        };
        assert_eq!(ptime("40"), Some(Duration::from_millis(40)));
        assert_eq!(ptime(" 30 "), Some(Duration::from_millis(30)));
        assert_eq!(ptime("20.5"), None);
        assert_eq!(ptime("0"), None);
        assert_eq!(
            format(&["m=audio 0 RTP/AVP 0", "a=ptime"]).unwrap().ptime,
            None
        );
    }

    const INITIAL: Initial = Initial {
        ssrc: 0x1234_5678,
        seq: 65_534,
        ts: 1_000,
    };

    fn packetizer(format: &BackchannelFormat) -> Packetizer {
        Packetizer::new(format, INITIAL)
    }

    fn packet(arrival: Instant, ts: u32, ssrc: u32, marker: bool) -> MediaPacket {
        MediaPacket {
            arrival,
            rtp: RtpHeaderFields {
                pt: 0,
                seq: 7,
                ts,
                marker,
                ssrc,
            },
            frame_start: true,
            keyframe_start: false,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0xff_u8; 160][..]),
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
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
    fn rfc3550_5_1_the_first_packet_carries_the_initial_values_and_the_camera_pt() {
        let mut p = packetizer(&g711(Codec::Pcmu, 97));
        let input = packet(SystemClock.now(), 0, 0x4737_3131, false);
        let out = p.packetize(&input);
        assert_eq!(
            out.rtp,
            RtpHeaderFields {
                pt: 97,
                seq: 65_534,
                ts: 1_000,
                marker: true,
                ssrc: 0x1234_5678,
            },
            "RFC 3551 §4.1: the first packet starts a talkspurt"
        );
        assert!(Arc::ptr_eq(&out.payload, &input.payload), "no copy");
    }

    #[test]
    fn rfc3550_5_1_sequence_numbers_count_packets_and_wrap() {
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        let seqs: Vec<u16> = (0_u32..4)
            .map(|k| {
                p.packetize(&packet(start + ms(20 * u64::from(k)), 160 * k, 1, false))
                    .rtp
                    .seq
            })
            .collect();
        assert_eq!(seqs, [65_534, 65_535, 0, 1]);
    }

    #[test]
    fn rfc3550_5_1_timestamps_follow_the_input_within_a_talkspurt_and_wrap() {
        let mut p = Packetizer::new(
            &g711(Codec::Pcmu, 0),
            Initial {
                ts: u32::MAX - 159,
                ..INITIAL
            },
        );
        let start = SystemClock.now();
        // Arrival jitter does not move the timestamps: the input's timing is kept.
        let out: Vec<(u32, bool)> = [(0, 0), (160, 25), (320, 38), (640, 80)]
            .into_iter()
            .map(|(ts, at)| {
                let rtp = p
                    .packetize(&packet(start + ms(at), 5_000 + ts, 1, false))
                    .rtp;
                (rtp.ts, rtp.marker)
            })
            .collect();
        assert_eq!(
            out,
            [
                (u32::MAX - 159, true),
                (0, false),
                (160, false),
                (480, false)
            ]
        );
    }

    #[test]
    fn rfc3551_4_1_a_marked_input_starts_a_talkspurt_advanced_by_the_time_that_passed() {
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        p.packetize(&packet(start, 0, 1, false));
        p.packetize(&packet(start + ms(20), 160, 1, false));
        // A restarted chain: timestamps from zero again, 500 ms later.
        let mut out = None;
        let logs = logged(|| out = Some(p.packetize(&packet(start + ms(520), 0, 1, true)).rtp));
        assert!(
            logs.contains("talkspurt marker=true sender_changed=false"),
            "{logs}"
        );
        assert!(logs.contains("jumped_back=false count=1"), "{logs}");
        let out = out.unwrap();
        assert!(out.marker);
        assert_eq!(out.ts, 1_000 + 160 + 4_000, "RFC 3550 §5.1");
        // The new talkspurt's offset carries on.
        let next = p.packetize(&packet(start + ms(540), 160, 1, false)).rtp;
        assert_eq!((next.ts, next.marker), (1_000 + 160 + 4_000 + 160, false));
    }

    #[test]
    fn rfc3551_4_1_another_sender_starts_a_talkspurt() {
        let mut p = packetizer(&g711(Codec::Pcma, 8));
        let start = SystemClock.now();
        p.packetize(&packet(start, 90_000, 1, false));
        let mut out = None;
        let logs = logged(|| out = Some(p.packetize(&packet(start + ms(1_000), 3, 2, false)).rtp));
        assert!(
            logs.contains("talkspurt marker=false sender_changed=true"),
            "{logs}"
        );
        let out = out.unwrap();
        assert!(out.marker);
        assert_eq!(out.ts, 1_000 + 8_000);
    }

    #[test]
    fn a_talkspurt_soon_after_the_last_packet_does_not_overlap_it() {
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        p.packetize(&packet(start, 0, 1, false));
        p.packetize(&packet(start + ms(20), 160, 1, false));
        // 5 ms later is 40 ticks, inside the last 160-sample packet.
        let out = p.packetize(&packet(start + ms(25), 0, 2, true)).rtp;
        assert_eq!(out.ts, 1_000 + 160 + 160);
        // An arrival before the last packet's counts as no time.
        let back = p.packetize(&packet(start, 0, 3, true)).rtp;
        assert_eq!(back.ts, 1_000 + 160 + 160 + 160);
    }

    #[test]
    fn the_packet_spacing_ignores_reordered_and_repeated_timestamps() {
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        for ts in [0, 320, 160, 160] {
            p.packetize(&packet(start, ts, 1, false));
        }
        // The spacing is 0 → 320; 320 → 160 runs back and 160 → 160 stands
        // still, so neither is a packet duration.
        let out = p.packetize(&packet(start, 0, 2, false)).rtp;
        assert_eq!(out.ts, 1_000 + 160 + 320);
    }

    #[test]
    fn rfc3550_5_1_a_step_of_half_the_range_is_backwards() {
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        p.packetize(&packet(start, 0, 1, false));
        p.packetize(&packet(start, 160, 1, false));
        // Behind the last packet's on the nearer reading, by more than the
        // lead: no packet spacing, and no reordering but a discontinuity,
        // a talkspurt one spacing on.
        let back = p.packetize(&packet(start, 160 + HALF_RANGE, 1, false)).rtp;
        assert_eq!((back.ts, back.marker), (1_000 + 160 + 160, true));
        // The next talkspurt steps the spacing before the jump on again.
        let out = p.packetize(&packet(start, 0, 2, false)).rtp;
        assert_eq!(out.ts, 1_000 + 160 + 160 + 160);
    }

    #[test]
    fn rfc7587_4_1_opus_talkspurts_advance_on_the_48_khz_clock() {
        let opus = BackchannelFormat {
            codec: Codec::Opus { channels: 2 },
            payload_type: 111,
            clock_rate: 48_000,
            ptime: None,
        };
        let mut p = packetizer(&opus);
        let start = SystemClock.now();
        p.packetize(&packet(start, 0, 1, false));
        let out = p.packetize(&packet(start + ms(100), 0, 2, false)).rtp;
        assert_eq!((out.pt, out.ts), (111, 1_000 + 4_800));
    }

    /// The packets' output timestamps against their arrivals: how far
    /// each runs ahead of the wall clock since the first, in ticks.
    fn leads(out: &[(u32, Instant)], start: Instant, rate: u32) -> Vec<u32> {
        out.iter()
            .map(|(ts, at)| {
                ts.wrapping_sub(INITIAL.ts)
                    .saturating_sub(ticks(at.saturating_duration_since(start), rate))
            })
            .collect()
    }

    #[test]
    fn rfc3550_5_1_restarted_talkspurts_stay_within_the_lead_of_the_wall_clock() {
        // A chain's output at real-time pace whose input claims 80 ms of
        // loss before every packet and restarts a talkspurt every other
        // one: each step 100 ms of timestamps per 20 ms of wall clock,
        // and each marker advanced by that step.
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        let mut out = Vec::new();
        let logs = logged(|| {
            for k in 0..50_u32 {
                let at = start + ms(20 * u64::from(k));
                let rtp = p.packetize(&packet(at, 800 * k, 1, k % 2 == 1)).rtp;
                out.push((rtp.ts, at));
            }
        });
        // At most MAX_LEAD (250 ms, 2,000 ticks) ahead, reached at once
        // and held there: 160 ticks per packet, the wall clock's pace.
        let leads = leads(&out, start, 8_000);
        assert!(leads.iter().all(|lead| *lead <= 2_000), "{leads:?}");
        assert_eq!(leads[49], 2_000);
        assert_eq!(out[49].0.wrapping_sub(out[48].0), 160);
        assert_eq!(
            logs.matches("backchannel: timestamp held to the wall clock")
                .count(),
            1,
            "rate-limited: {logs}"
        );
    }

    #[test]
    fn rfc7587_4_1_forwarded_opus_stays_within_the_lead_of_the_wall_clock() {
        // Opus forwarded as received, one talkspurt: the packets a paced
        // flood leaves, 20 ms apart on the wall clock and 100 ms on the
        // sender's 48 kHz timeline.
        let opus = BackchannelFormat {
            codec: Codec::Opus { channels: 2 },
            payload_type: 111,
            clock_rate: 48_000,
            ptime: None,
        };
        let mut p = packetizer(&opus);
        let start = SystemClock.now();
        let out: Vec<(u32, Instant)> = (0..50_u32)
            .map(|k| {
                let at = start + ms(20 * u64::from(k));
                (p.packetize(&packet(at, 4_800 * k, 1, false)).rtp.ts, at)
            })
            .collect();
        let leads = leads(&out, start, 48_000);
        assert!(leads.iter().all(|lead| *lead <= 12_000), "{leads:?}");
        assert_eq!(leads[49], 12_000);
    }

    #[test]
    fn rfc3550_5_1_backward_jumps_cannot_carry_a_talkspurt_past_the_wall_clock() {
        // Forwarded Opus, one talkspurt: a jump of half the range reads as
        // backwards, and a second jump from there would read backwards
        // again, ten seconds ahead of the wall clock.
        let opus = BackchannelFormat {
            codec: Codec::Opus { channels: 2 },
            payload_type: 111,
            clock_rate: 48_000,
            ptime: None,
        };
        let mut p = packetizer(&opus);
        let start = SystemClock.now();
        let mut out = Vec::new();
        let logs = logged(|| {
            for (ts, at) in [(0, 0), (HALF_RANGE, 20), (480_000, 40)] {
                let at = start + ms(at);
                out.push((p.packetize(&packet(at, ts, 1, false)).rtp.ts, at));
            }
        });
        assert!(
            logs.contains(
                "talkspurt marker=false sender_changed=false advance=960 jumped_back=true count=1"
            ),
            "{logs}"
        );
        // Each jump back is a discontinuity in the sender's timeline: a
        // talkspurt, on the wall clock, never a jump back on the camera's.
        let ts: Vec<u32> = out.iter().map(|(ts, _)| *ts).collect();
        assert_eq!(ts, [1_000, 1_000 + 960, 1_000 + 2 * 960]);
        let leads = leads(&out, start, 48_000);
        assert!(leads.iter().all(|lead| *lead <= 12_000), "{leads:?}");
    }

    #[test]
    fn rfc3550_5_1_a_reordered_packet_and_a_wrapping_input_stand() {
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        // An input timeline that wraps, at real-time pace, and one packet
        // that arrives after its successor, 20 ms behind it: within the
        // lead, so reordering, it keeps its place on the talkspurt's
        // timeline.
        let out: Vec<u32> = [
            (u32::MAX - 159, 0),
            (0, 20),
            (320, 40),
            (160, 41),
            (480, 60),
        ]
        .into_iter()
        .map(|(ts, at)| p.packetize(&packet(start + ms(at), ts, 1, false)).rtp.ts)
        .collect();
        assert_eq!(out, [1_000, 1_160, 1_480, 1_320, 1_640]);
    }

    #[test]
    fn rfc3550_5_1_a_step_back_of_the_lead_is_reordering_a_tick_more_a_discontinuity() {
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        p.packetize(&packet(start, 2_000, 1, false));
        // Exactly MAX_LEAD (2,000 ticks) back: reordering, in place.
        let reordered = p.packetize(&packet(start, 0, 1, false)).rtp;
        assert_eq!(
            (reordered.ts, reordered.marker),
            (1_000_u32.wrapping_sub(2_000), false)
        );
        // A tick more back from that one: a discontinuity, a talkspurt.
        let jumped = p
            .packetize(&packet(start, 0_u32.wrapping_sub(2_001), 1, false))
            .rtp;
        assert!(jumped.marker);
    }

    #[test]
    fn rfc3550_5_1_exactly_the_lead_ahead_stands_a_tick_more_is_held() {
        let mut p = packetizer(&g711(Codec::Pcmu, 0));
        let start = SystemClock.now();
        p.packetize(&packet(start, 0, 1, false));
        let at_lead = p.packetize(&packet(start, 2_000, 1, false)).rtp;
        assert_eq!(at_lead.ts, 1_000 + 2_000, "exactly MAX_LEAD ahead");
        let past = p.packetize(&packet(start, 2_001, 1, false)).rtp;
        assert_eq!(past.ts, 1_000 + 2_000, "held at the wall clock's limit");
        // The talkspurt follows on from where it was held.
        let next = p
            .packetize(&packet(start + ms(20), 2_001 + 160, 1, false))
            .rtp;
        assert_eq!((next.ts, next.marker), (1_000 + 2_000 + 160, false));
    }

    #[test]
    fn rfc3550_5_1_elapsed_ticks_wrap_modulo_2_32() {
        assert_eq!(ticks(Duration::from_secs(1), 8_000), 8_000);
        assert_eq!(ticks(ms(20), 48_000), 960);
        assert_eq!(ticks(Duration::from_micros(125), 8_000), 1);
        assert_eq!(ticks(Duration::from_micros(124), 8_000), 0);
        assert_eq!(ticks(ms((1 << 32) + 5), 1_000), 5);
    }

    #[test]
    fn rfc3550_8_1_initial_values_are_random() {
        let a = Initial::random().unwrap();
        let b = Initial::random().unwrap();
        // 80 random bits: equal only once in 2⁸⁰.
        assert_ne!(a, b);
    }
}
