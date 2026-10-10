//! A fake RTSP camera: DESCRIBE, SETUP (TCP interleaved, or RTP over UDP
//! when the client asks for `client_port`), PLAY, keepalives and TEARDOWN
//! over one TCP listener, streaming a synthetic H.264 or H.265
//! track whose access units are opaque IDR and P slices behind hand-built
//! parameter sets, plus RTCP Sender Reports.
//!
//! Implements enough of RFC 2326 (§10.1 OPTIONS, §10.2 DESCRIBE, §10.4
//! SETUP, §10.5 PLAY, §10.7 TEARDOWN, §10.8 `GET_PARAMETER`, §10.12
//! interleaved binary data), RFC 4566 (the SDP), RFC 3550 §5.1 (RTP
//! headers) and §6.4.1 (Sender Reports), RFC 6184 §5.7.1 and §5.8 (STAP-A
//! and FU-A), RFC 7798 §4.4.2, §4.4.3 and §7.1 (aggregation packets,
//! fragmentation units, `sprop-vps`, `sprop-sps` and `sprop-pps`) and
//! RFC 7617 (Basic authentication) for the source contract
//! to be exercised. Knobs model camera habits: no marker bits, a large
//! MTU, credentials, hanging up, never answering, a `PLAY` answer
//! without `rtptime` (RFC 2326 §12.33), a refused or unanswered `PLAY`,
//! or bytes that are not RTSP after it; over UDP (RFC 2326
//! §12.39, RFC 3550 §11) a `461` refusal, datagrams that never arrive, and
//! loss, reordering, duplicates and a foreign sender. It records the RTCP
//! a client sends it, interleaved or as datagrams, so tests can read its
//! Receiver Reports (RFC 3550 §6.4.2). In TLS mode it serves
//! `rtsps` (RFC 7826 §19.2) with a self-signed certificate generated at
//! test time, over TLS 1.3 and 1.2 or 1.2 only.
//!
//! With [`CameraBackchannel`] it offers the ONVIF backchannel (ONVIF
//! Streaming Specification §5.3) to a `DESCRIBE` with `Require:
//! www.onvif.org/ver20/backchannel` (RFC 2326 §12.32): a PCMU, PCMA (RFC
//! 3551 §4.5.14) or Opus (RFC 7587 §7) `a=sendonly` media with a chosen
//! payload type and `a=ptime` (RFC 8866 §6.4, §6.6), set up interleaved on
//! its own channel pair in the same session, whose RTP after `PLAY` it
//! parses (RFC 3550 §5.1) and records ([`Stats::backchannel`]), RTCP on the
//! odd channel counted. Quirk modes: the `Require` tag refused with `551`
//! (RFC 2326 §11.3.13) or `400`, and one payload type taken only.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_codec::h264::nal;
use lotse_codec::h264::test_data::{pps, sps};
use lotse_codec::h265;
use lotse_core::clock::Clock;
use lotse_core::task::spawn_named;
use rtsp_types::headers::{
    AUTHORIZATION, CONTENT_BASE, CONTENT_TYPE, CSEQ, PUBLIC, REQUIRE, RTP_INFO, SESSION, TRANSPORT,
    UNSUPPORTED, WWW_AUTHENTICATE,
};
use rtsp_types::{Data, Message, Method, ParseError, Request, Response, StatusCode, Version};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::base64;

/// The RTP payload type the SDP announces.
pub const PAYLOAD_TYPE: u8 = 96;
/// The SSRC of the video stream.
pub const SSRC: u32 = 0x1234_5678;
/// The SSRC of the audio stream.
pub const AUDIO_SSRC: u32 = 0x8765_4321;
/// The first RTP timestamp of the audio.
pub const AUDIO_FIRST_TIMESTAMP: u32 = 5_000;

/// The video codec a camera streams.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CameraVideo {
    /// H.264 Baseline (RFC 6184): `sprop-parameter-sets`, a STAP-A of SPS
    /// and PPS before every IDR.
    #[default]
    H264,
    /// H.265 Main (RFC 7798): `sprop-vps`, `sprop-sps` and `sprop-pps`, an
    /// aggregation packet of the three before every `IDR_W_RADL` picture,
    /// `TRAIL_R` pictures between.
    H265,
    /// As [`Self::H265`], in the High tier (ITU-T H.265 A.4.1, level 4.0):
    /// `general_tier_flag` set in the VPS and SPS, `tier-flag=1` in the
    /// `fmtp` (RFC 7798 §7.1).
    H265HighTier,
}

impl CameraVideo {
    /// The media description, the payload type's `rtpmap` and `fmtp` with
    /// the parameter sets and then `fmtp_extra`.
    fn sdp(self, base: &str, fmtp_extra: &str) -> String {
        let pt = PAYLOAD_TYPE;
        match self {
            Self::H264 => {
                let sps = sps(WIDTH, HEIGHT);
                let profile_level_id =
                    sps.get(1..4)
                        .unwrap_or(&[0, 0, 0])
                        .iter()
                        .fold(String::new(), |mut out, b| {
                            use std::fmt::Write as _;
                            let _infallible = write!(out, "{b:02x}");
                            out
                        });
                format!(
                    "m=video 0 RTP/AVP {pt}\r\na=rtpmap:{pt} H264/90000\r\n\
                     a=fmtp:{pt} packetization-mode=1;profile-level-id={profile_level_id};sprop-parameter-sets={},{}{fmtp_extra}\r\n\
                     a=control:{base}track0\r\n",
                    base64::encode(&sps),
                    base64::encode(&pps()),
                )
            }
            Self::H265 | Self::H265HighTier => {
                let (vps, sps) = self.h265_sets();
                format!(
                    "m=video 0 RTP/AVP {pt}\r\na=rtpmap:{pt} H265/90000\r\n\
                     a=fmtp:{pt} profile-id=1{};sprop-vps={};sprop-sps={};sprop-pps={}{fmtp_extra}\r\n\
                     a=control:{base}track0\r\n",
                    if self == Self::H265HighTier {
                        ";tier-flag=1"
                    } else {
                        ""
                    },
                    base64::encode(&vps),
                    base64::encode(&sps),
                    base64::encode(&h265::test_data::pps()),
                )
            }
        }
    }

    /// The H.265 VPS and SPS, in the stream's tier.
    fn h265_sets(self) -> (Vec<u8>, Vec<u8>) {
        let high_tier = self == Self::H265HighTier;
        (
            h265::test_data::vps_of_tier(high_tier),
            h265::test_data::sps_of_tier(1, high_tier, WIDTH, HEIGHT),
        )
    }

    /// The RTP payloads of the `index`th access unit: the parameter sets
    /// aggregated and the IDR fragmented to `mtu` on a keyframe, else the
    /// P slice fragmented; in `slices` slices each when the camera is
    /// configured so, the parameter sets before every IDR slice with
    /// `sets_before_every_slice`.
    fn access_unit(self, keyframe: bool, config: &CameraConfig, index: u32) -> Vec<Bytes> {
        let mut payloads = Vec::new();
        let idr_bytes = match config.alternate_idr_bytes {
            Some(bytes)
                if index
                    .checked_div(config.gop.max(1))
                    .is_some_and(|gop| gop % 2 == 1) =>
            {
                bytes
            }
            _ => config.idr_bytes,
        };
        let slices = config.slices.max(1);
        let bytes = if keyframe { idr_bytes } else { config.p_bytes }
            .checked_div(slices as usize)
            .unwrap_or(0)
            .max(1);
        for i in 0..slices {
            let with_sets = keyframe && (i == 0 || config.sets_before_every_slice);
            match self {
                Self::H264 => {
                    if with_sets {
                        payloads.push(nal::stap_a(&[&sps(WIDTH, HEIGHT), &pps()]));
                    }
                    let unit_type = if keyframe {
                        nal::NAL_IDR
                    } else {
                        nal::NAL_SLICE
                    };
                    payloads.extend(nal::fragment(&slice(unit_type, bytes, index), config.mtu));
                }
                Self::H265 | Self::H265HighTier => {
                    if with_sets {
                        let (vps, sps) = self.h265_sets();
                        payloads.push(h265::nal::aggregate(&[&vps, &sps, &h265::test_data::pps()]));
                    }
                    let unit_type = if keyframe {
                        h265::nal::IDR_W_RADL
                    } else {
                        TRAIL_R
                    };
                    payloads.extend(h265::nal::fragment(
                        &h265_slice(unit_type, bytes, index),
                        config.mtu,
                    ));
                }
            }
        }
        payloads
    }
}

/// Coded slice of a trailing picture, reference (ITU-T H.265 Table 7-1).
const TRAIL_R: u8 = 1;

/// The audio track a camera offers besides its video.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraAudio {
    /// PCMU, static payload type 0 (RFC 3551 §6): 20 ms packets of
    /// silence.
    Pcmu,
    /// AAC-LC, 16 kHz mono, RFC 3640 AAC-hbr on payload type 97: one frame
    /// (1024 samples, 64 ms) per packet, looping the recorded 1 kHz sine of
    /// [`lotse_codec::aac::test_data::SINE_16K_MONO`].
    Aac,
}

impl CameraAudio {
    /// The payload type the SDP announces.
    pub const fn payload_type(self) -> u8 {
        match self {
            Self::Pcmu => 0,
            Self::Aac => 97,
        }
    }

    /// RTP timestamp ticks (samples) per packet.
    pub const fn samples(self) -> u32 {
        match self {
            Self::Pcmu => 160,
            Self::Aac => lotse_codec::aac::FRAME_SAMPLES,
        }
    }

    /// How often a packet goes out.
    const fn interval(self) -> Duration {
        match self {
            Self::Pcmu => Duration::from_millis(20),
            Self::Aac => Duration::from_millis(64),
        }
    }

    /// A Sender Report every this many packets: about one a second.
    const fn sr_every(self) -> u64 {
        match self {
            Self::Pcmu => 50,
            Self::Aac => 16,
        }
    }

    /// The media description.
    fn sdp(self, base: &str) -> String {
        let pt = self.payload_type();
        match self {
            Self::Pcmu => format!(
                "m=audio 0 RTP/AVP {pt}\r\na=rtpmap:{pt} PCMU/8000\r\na=control:{base}track1\r\n"
            ),
            Self::Aac => format!(
                "m=audio 0 RTP/AVP {pt}\r\na=rtpmap:{pt} MPEG4-GENERIC/16000/1\r\n\
                 a=fmtp:{pt} streamtype=5;profile-level-id=15;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1408\r\n\
                 a=control:{base}track1\r\n"
            ),
        }
    }

    /// The payload of the `index`th packet.
    fn payload(self, index: u64) -> Vec<u8> {
        match self {
            // A PCMU silence byte per sample (G.711 µ-law 0xff).
            Self::Pcmu => vec![0xff_u8; 160],
            Self::Aac => {
                let frames =
                    lotse_codec::aac::test_data::frames(lotse_codec::aac::test_data::SINE_16K_MONO);
                let count = u64::try_from(frames.len()).unwrap_or(1).max(1);
                let pick = usize::try_from(index.checked_rem(count).unwrap_or(0)).unwrap_or(0);
                lotse_codec::aac::packetize(&[frames.get(pick).copied().unwrap_or(&[])])
            }
        }
    }
}

/// The `Require` option tag that asks for the ONVIF backchannel (ONVIF
/// Streaming Specification §5.3.1, RFC 2326 §12.32).
pub const BACKCHANNEL_REQUIRE: &str = "www.onvif.org/ver20/backchannel";

/// The codec of the ONVIF backchannel the camera receives on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BackchannelCodec {
    /// G.711 µ-law at 8000 Hz (RFC 3551 §4.5.14), static payload type 0.
    #[default]
    Pcmu,
    /// G.711 A-law at 8000 Hz (RFC 3551 §4.5.14), static payload type 8.
    Pcma,
    /// Opus, `opus/48000/2` (RFC 7587 §7), dynamic payload type 111 unless
    /// configured.
    Opus,
}

impl BackchannelCodec {
    /// The payload type the SDP announces when none is configured: the
    /// static one for G.711 (RFC 3551 Table 4), 111 for Opus.
    pub const fn default_payload_type(self) -> u8 {
        match self {
            Self::Pcmu => 0,
            Self::Pcma => 8,
            Self::Opus => 111,
        }
    }

    /// The `a=rtpmap` encoding (RFC 8866 §6.6).
    const fn rtpmap(self) -> &'static str {
        match self {
            Self::Pcmu => "PCMU/8000",
            Self::Pcma => "PCMA/8000",
            Self::Opus => "opus/48000/2",
        }
    }
}

/// How the camera answers a `DESCRIBE` that carries the backchannel's
/// `Require` tag. The refusals are a camera without the backchannel, and
/// the `400 Bad Request` some Dahua and Amcrest firmwares answer instead
/// (observed behavior).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RequireAnswer {
    /// The SDP, with the backchannel media added (ONVIF Streaming
    /// Specification §5.3.2).
    #[default]
    Honor,
    /// `551 Option not supported` with the tag in `Unsupported` (RFC 2326
    /// §11.3.13, §12.40), as ONVIF Streaming Specification §5.3.2.1 has a
    /// server without the backchannel answer.
    OptionNotSupported,
    /// `400 Bad Request`, as other firmwares answer instead.
    BadRequest,
}

/// The ONVIF backchannel the camera offers (ONVIF Streaming Specification
/// §5.3): with `Require: www.onvif.org/ver20/backchannel` on `DESCRIBE`,
/// an `a=sendonly` audio media after the others, set up TCP interleaved on
/// its own channel pair in the same session; a `SETUP` of it over UDP gets
/// `461`, as lotse sets it up interleaved only.
/// After `PLAY` the RTP that arrives on its channel is recorded
/// ([`Stats::backchannel`]) and RTCP on the next channel counted.
#[derive(Debug, Clone, Default)]
pub struct CameraBackchannel {
    /// The codec the media announces.
    pub codec: BackchannelCodec,
    /// The payload type it announces; the codec's default when `None`.
    pub payload_type: Option<u8>,
    /// Its `a=ptime` in milliseconds (RFC 8866 §6.4); none when `None`.
    pub ptime: Option<u32>,
    /// How a `DESCRIBE` with `Require` is answered.
    pub require: RequireAnswer,
    /// Record only RTP of this payload type and refuse the rest: the
    /// cameras that take only a fixed one (observed behavior); any payload
    /// type when `None`.
    pub accept_only: Option<u8>,
}

impl CameraBackchannel {
    /// A backchannel in `codec`, with its default payload type and no
    /// quirks.
    pub fn new(codec: BackchannelCodec) -> Self {
        Self {
            codec,
            ..Self::default()
        }
    }

    /// The payload type the SDP announces.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
            .unwrap_or_else(|| self.codec.default_payload_type())
    }

    /// The media description (RFC 8866 §5.14), `a=sendonly` in the
    /// camera's frame of reference (ONVIF Streaming Specification §5.3.2).
    fn sdp(&self, base: &str) -> String {
        let pt = self.payload_type();
        let ptime = self
            .ptime
            .map(|ms| format!("a=ptime:{ms}\r\n"))
            .unwrap_or_default();
        format!(
            "m=audio 0 RTP/AVP {pt}\r\na=rtpmap:{pt} {}\r\n{ptime}a=sendonly\r\na=control:{base}{BACKCHANNEL_CONTROL}\r\n",
            self.codec.rtpmap()
        )
    }
}

/// The last path segment of the backchannel media's control URL.
pub const BACKCHANNEL_CONTROL: &str = "backchannel";

/// One RTP packet the camera received on its backchannel (RFC 3550 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackchannelRtp {
    /// The payload type.
    pub payload_type: u8,
    /// The marker bit.
    pub marker: bool,
    /// The sequence number.
    pub sequence_number: u16,
    /// The RTP timestamp.
    pub timestamp: u32,
    /// The synchronization source.
    pub ssrc: u32,
    /// The payload, after the CSRC list and a header extension, without
    /// padding.
    pub payload: Vec<u8>,
    /// When the camera read it, on the camera's clock.
    pub arrival: Instant,
}

impl BackchannelRtp {
    /// Parses an RTP packet (RFC 3550 §5.1, §5.3.1): version 2, its CSRC
    /// list, header extension and padding skipped; `None` if malformed.
    fn parse(packet: &[u8], arrival: Instant) -> Option<Self> {
        let (header, rest) = packet.split_at_checked(12)?;
        let word =
            |at: usize| -> Option<[u8; 4]> { header.get(at..at.checked_add(4)?)?.try_into().ok() };
        let [first, second, seq_hi, seq_lo] = word(0)?;
        if first >> 6 != 2 {
            return None;
        }
        let csrcs = usize::from(first & 0x0f).checked_mul(4)?;
        let (_csrcs, mut rest) = rest.split_at_checked(csrcs)?;
        if first & 0x10 != 0 {
            let (extension, after) = rest.split_at_checked(4)?;
            let length = extension.get(2..4)?.try_into().ok()?;
            let words = usize::from(u16::from_be_bytes(length));
            let (_extension, after) = after.split_at_checked(words.checked_mul(4)?)?;
            rest = after;
        }
        if first & 0x20 != 0 {
            let padding = usize::from(*rest.last()?);
            rest = rest.get(..rest.len().checked_sub(padding)?)?;
        }
        Some(Self {
            payload_type: second & 0x7f,
            marker: second & 0x80 != 0,
            sequence_number: u16::from_be_bytes([seq_hi, seq_lo]),
            timestamp: u32::from_be_bytes(word(4)?),
            ssrc: u32::from_be_bytes(word(8)?),
            payload: rest.to_vec(),
            arrival,
        })
    }
}

/// Whether `packet` reads as RTCP (RFC 3550 §6.1, §12.1): version 2 and a
/// packet type from SR (200) to APP (204).
fn is_rtcp(packet: &[u8]) -> bool {
    matches!(packet, [first, kind, _, _, ..] if first >> 6 == 2 && (200..=204).contains(kind))
}

/// The camera's TLS mode: a self-signed certificate generated at test time
/// (`rcgen`, valid until 4096), so nothing ever expires and no key sits in
/// the repository.
#[derive(Clone)]
pub struct CameraTls {
    /// The server configuration.
    config: Arc<rustls::ServerConfig>,
    /// The certificate, DER.
    certificate: CertificateDer<'static>,
}

impl fmt::Debug for CameraTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CameraTls({})", self.fingerprint())
    }
}

impl CameraTls {
    /// A self-signed certificate naming `names` (host names or address
    /// literals), served over TLS 1.3 and 1.2.
    pub fn self_signed(names: &[&str]) -> io::Result<Self> {
        Self::build(names, &[&rustls::version::TLS13, &rustls::version::TLS12])
    }

    /// As [`Self::self_signed`], but TLS 1.2 only, as many cameras are.
    pub fn tls12_only(names: &[&str]) -> io::Result<Self> {
        Self::build(names, &[&rustls::version::TLS12])
    }

    /// The certificate and the configuration for `versions`.
    fn build(
        names: &[&str],
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> io::Result<Self> {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let generated = rcgen::generate_simple_self_signed(names).map_err(io::Error::other)?;
        let certificate = generated.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())
        .map_err(io::Error::other)?;
        Ok(Self {
            config: Arc::new(config),
            certificate,
        })
    }

    /// The certificate, DER-encoded.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    /// The certificate's SHA-256 as colon-separated uppercase hex pairs,
    /// the way `openssl x509 -fingerprint -sha256` prints it.
    pub fn fingerprint(&self) -> String {
        Sha256::digest(&self.certificate)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// The first RTP timestamp.
pub const FIRST_TIMESTAMP: u32 = 1_000_000;
/// The picture size the SPS declares.
pub const WIDTH: u32 = 640;
/// The picture size the SPS declares.
pub const HEIGHT: u32 = 480;

/// How the camera behaves.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent switches of a test camera's behavior, each set by the test that needs it"
)]
pub struct CameraConfig {
    /// Require these Basic credentials.
    pub auth: Option<(String, String)>,
    /// Set the marker bit on the last packet of an access unit.
    pub marker_bit: bool,
    /// The largest RTP payload the camera sends.
    pub mtu: usize,
    /// Frames per second.
    pub fps: u32,
    /// Frames per GOP.
    pub gop: u32,
    /// Bytes of an IDR slice.
    pub idr_bytes: usize,
    /// Every other IDR slice (the second group of pictures, the fourth,
    /// ...) has this many bytes instead: a camera whose busy scenes outgrow
    /// what a browser assembles.
    pub alternate_idr_bytes: Option<usize>,
    /// Bytes of a P slice.
    pub p_bytes: usize,
    /// A Sender Report every this many frames.
    pub sr_every: u32,
    /// Hang up after this many RTP packets.
    pub packets_before_close: Option<u64>,
    /// From this frame on, add these ticks to every timestamp: a camera
    /// that reset its clock mid-stream.
    pub timestamp_jump: Option<(u32, u32)>,
    /// Stamp every access unit with its send time since this origin, in a
    /// leading SEI NAL unit ([`crate::latency`]); H.264 only.
    pub stamp_origin: Option<Instant>,
    /// Wait this long between the packets of one frame, as a camera on a
    /// slow link delivers a large one.
    pub packet_spacing: Duration,
    /// Offer an audio track too, with Sender Reports from the same wall
    /// clock as the video's.
    pub audio: Option<CameraAudio>,
    /// Accept connections but never answer.
    pub silent: bool,
    /// The video codec.
    pub video: CameraVideo,
    /// Slices per picture, each a NAL unit of its share of the picture's
    /// bytes; 1 by default.
    pub slices: u32,
    /// Send the parameter sets again before every slice of an IDR
    /// picture, not only the first, as a Reolink camera's H.265 main
    /// stream does (observed 2026-10-09): between the slices they end the
    /// picture for a decoder (ITU-T H.265 §7.4.2.4.4).
    pub sets_before_every_slice: bool,
    /// Serve `rtsps`: TLS on every connection.
    pub tls: Option<CameraTls>,
    /// Lines added to the session part of the SDP, after `t=`, each
    /// ending in CRLF: a camera's own attributes, or its mistakes.
    pub sdp_session_lines: String,
    /// Parameters appended to the video's `fmtp`, each led by `;`: a
    /// camera's own format parameters (RFC 8866 §6.15).
    pub video_fmtp: String,
    /// The session timeout the `SETUP` answer announces, in seconds
    /// (RFC 2326 §12.37); clients keep the session alive within it.
    pub session_timeout_s: u32,
    /// How a `SETUP` that asks for RTP over UDP is served.
    pub udp: CameraUdp,
    /// Answer `PLAY` with `seq` but without `rtptime` in `RTP-Info`
    /// (RFC 2326 §12.33, where both are optional), as MediaMTX 1.21.1
    /// answers a path's first reader (observed 2026-10-06).
    pub omit_rtptime: bool,
    /// How `PLAY` is answered.
    pub play: PlayAnswer,
    /// The address it listens on and sends its datagrams from: a loopback
    /// address, `127.0.0.1` by default; `::1` makes the camera's endpoint
    /// differ from a client's own IPv4 loopback.
    pub ip: IpAddr,
    /// Offer an ONVIF backchannel to a `DESCRIBE` that asks for one; a
    /// `Require` tag is ignored without, as many cameras do.
    pub backchannel: Option<CameraBackchannel>,
}

/// How the camera answers `PLAY`; every other request is answered as
/// usual, `TEARDOWN` included.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PlayAnswer {
    /// `200 OK`, and the stream flows.
    #[default]
    Play,
    /// `503 Service Unavailable` (RFC 2326 §7.1.1), with the session it
    /// set up kept.
    Refuse,
    /// Never: the camera hangs at `PLAY`, which goes unanswered, and so
    /// does every request after it; a `TEARDOWN` is still counted.
    Never,
    /// `200 OK`, then bytes that are not RTSP on the control connection,
    /// as a camera whose firmware corrupts it.
    Unreadable,
}

/// Whether the camera serves RTP over UDP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UdpService {
    /// Yes.
    #[default]
    Serve,
    /// Refuse it with `461 Unsupported Transport` (RFC 2326 §11.3.11).
    Refuse,
    /// Answer it, then send no datagram at all: a firewall or NAT that
    /// drops them.
    Blackhole,
    /// Serve UDP only: a `SETUP` for TCP interleaved gets `461`.
    Only,
}

/// How the camera serves a `SETUP` that asks for RTP over UDP with
/// `client_port` (RFC 2326 §12.39): from its own RTP/RTCP port pair to the
/// client's, with these faults. Counted in sent order over every RTP
/// datagram of the connection, from 1.
#[derive(Debug, Clone, Default)]
pub struct CameraUdp {
    /// Whether it is served at all.
    pub service: UdpService,
    /// Leave `server_port` out of the answer.
    pub omit_server_port: bool,
    /// Name this address as `source` in the answer, the camera's own or
    /// another one it never sends from.
    pub announce_source: Option<IpAddr>,
    /// Never send every n-th RTP datagram: loss.
    pub drop_every: Option<u64>,
    /// Send every n-th RTP datagram after the one that follows it:
    /// reordering.
    pub swap_every: Option<u64>,
    /// Send every n-th RTP datagram twice: duplicates.
    pub duplicate_every: Option<u64>,
    /// Also send a copy of every n-th RTP datagram from another port, its
    /// sequence number 1000 ahead: a stray or spoofing sender on the LAN.
    pub foreign_every: Option<u64>,
}

impl Default for CameraConfig {
    fn default() -> Self {
        Self {
            auth: None,
            marker_bit: true,
            mtu: 1400,
            fps: 30,
            gop: 10,
            idr_bytes: 3000,
            alternate_idr_bytes: None,
            p_bytes: 600,
            sr_every: 30,
            packets_before_close: None,
            timestamp_jump: None,
            stamp_origin: None,
            packet_spacing: Duration::ZERO,
            audio: None,
            silent: false,
            video: CameraVideo::H264,
            slices: 1,
            sets_before_every_slice: false,
            tls: None,
            sdp_session_lines: String::new(),
            video_fmtp: String::new(),
            session_timeout_s: 60,
            udp: CameraUdp::default(),
            omit_rtptime: false,
            play: PlayAnswer::Play,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            backchannel: None,
        }
    }
}

/// What the camera saw, for assertions.
#[derive(Debug, Default)]
pub struct Stats {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// DESCRIBE requests answered.
    pub describes: AtomicU64,
    /// SETUP requests answered.
    pub setups: AtomicU64,
    /// PLAY requests, answered unless [`PlayAnswer::Never`].
    pub plays: AtomicU64,
    /// TEARDOWN requests, answered unless the camera hung
    /// ([`PlayAnswer::Never`]).
    pub teardowns: AtomicU64,
    /// `GET_PARAMETER` and OPTIONS requests while playing.
    pub keepalives: AtomicU64,
    /// Requests refused for missing or wrong credentials.
    pub unauthorized: AtomicU64,
    /// RTP packets sent.
    pub packets: AtomicU64,
    /// TLS handshakes that failed (TLS mode).
    pub tls_failures: AtomicU64,
    /// SETUP requests answered with RTP over UDP.
    pub udp_setups: AtomicU64,
    /// RTP and RTCP datagrams sent over UDP, foreign copies left out.
    pub datagrams: AtomicU64,
    /// Datagrams the camera's own UDP ports received: the client's
    /// firewall hole punches and RTCP.
    pub datagrams_received: AtomicU64,
    /// The RTCP the client sent, in arrival order.
    pub rtcp: Mutex<Vec<ClientRtcp>>,
    /// `DESCRIBE` requests answered with the backchannel media.
    pub backchannel_describes: AtomicU64,
    /// `DESCRIBE` requests refused for their backchannel `Require` tag
    /// ([`RequireAnswer`]).
    pub require_rejected: AtomicU64,
    /// `SETUP` requests of the backchannel answered (also in
    /// [`Self::setups`]).
    pub backchannel_setups: AtomicU64,
    /// RTP packets recorded from the backchannel.
    pub backchannel_packets: AtomicU64,
    /// RTCP packets received on the backchannel's odd channel.
    pub backchannel_rtcp: AtomicU64,
    /// Packets on the backchannel's channels refused: RTP before `PLAY`,
    /// malformed, or of a payload type the camera does not take.
    pub backchannel_refused: AtomicU64,
    /// The RTP recorded from the backchannel, in arrival order.
    received: Mutex<Vec<BackchannelRtp>>,
}

/// One RTCP compound packet the client sent the camera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRtcp {
    /// When it arrived, on the camera's clock.
    pub at: Instant,
    /// The RTCP channel of its stream: the interleaved channel it came on,
    /// or for a datagram the channel whose client port sent it (`None`
    /// for another sender).
    pub channel: Option<u8>,
    /// It came as a datagram, not interleaved.
    pub udp: bool,
    /// The packet.
    pub packet: Vec<u8>,
}

impl Stats {
    /// One counter.
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The value of one counter.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// The RTCP the client sent so far.
    pub fn rtcp_received(&self) -> Vec<ClientRtcp> {
        self.rtcp
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The RTP recorded from the backchannel so far, in arrival order.
    pub fn backchannel(&self) -> Vec<BackchannelRtp> {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Records one RTCP packet from the client.
    fn record_rtcp(&self, rtcp: ClientRtcp) {
        self.rtcp
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(rtcp);
    }

    /// Records one backchannel packet.
    fn record(&self, packet: BackchannelRtp) {
        Self::bump(&self.backchannel_packets);
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(packet);
    }
}

/// A running fake camera.
#[derive(Debug)]
pub struct FakeCamera {
    /// Where it listens.
    addr: SocketAddr,
    /// What it saw.
    stats: Arc<Stats>,
    /// Stops the listener and every connection.
    cancel: CancellationToken,
    /// Ends the connections open now, a child of `cancel` replaced on
    /// every [`FakeCamera::drop_connections`].
    hangup: Arc<Mutex<CancellationToken>>,
    /// The accept loop.
    accept: JoinHandle<()>,
    /// The credentials, for the URL.
    auth: Option<(String, String)>,
    /// `rtsps` or `rtsp`.
    scheme: &'static str,
}

impl FakeCamera {
    /// Binds a port on `config.ip` and serves `config` until stopped.
    pub async fn start(config: CameraConfig, clock: Arc<dyn Clock>) -> io::Result<Self> {
        let listener = TcpListener::bind((config.ip, 0)).await?;
        let addr = listener.local_addr()?;
        let stats = Arc::new(Stats::default());
        let cancel = CancellationToken::new();
        let hangup = Arc::new(Mutex::new(cancel.child_token()));
        let auth = config.auth.clone();
        let scheme = if config.tls.is_some() {
            "rtsps"
        } else {
            "rtsp"
        };
        let config = Arc::new(config);
        let accept = spawn_named(
            "fake_camera.accept",
            accept_loop(
                listener,
                config,
                Arc::clone(&stats),
                cancel.clone(),
                Arc::clone(&hangup),
                clock,
            ),
        );
        Ok(Self {
            addr,
            stats,
            cancel,
            hangup,
            accept,
            auth,
            scheme,
        })
    }

    /// The address.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The stream's URL, credentials included when the camera wants them;
    /// `rtsps` in TLS mode.
    pub fn url(&self) -> String {
        let scheme = self.scheme;
        match &self.auth {
            Some((user, pass)) => format!("{scheme}://{user}:{pass}@{}/stream", self.addr),
            None => format!("{scheme}://{}/stream", self.addr),
        }
    }

    /// What it saw so far.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Hangs up every open connection, as a camera that reboots or drops
    /// off the network does, and keeps listening: the client's reconnect
    /// is a new connection in [`Stats::connections`].
    pub fn drop_connections(&self) {
        let mut current = self.hangup.lock().unwrap_or_else(PoisonError::into_inner);
        current.cancel();
        *current = self.cancel.child_token();
    }

    /// Stops the camera.
    pub async fn stop(self) {
        self.cancel.cancel();
        let _joined = self.accept.await;
    }
}

/// Accepts connections until cancelled; each connection ends with
/// `cancel` or with the `hangup` token current when it was accepted.
async fn accept_loop(
    listener: TcpListener,
    config: Arc<CameraConfig>,
    stats: Arc<Stats>,
    cancel: CancellationToken,
    hangup: Arc<Mutex<CancellationToken>>,
    clock: Arc<dyn Clock>,
) {
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(err) => {
                    tracing::warn!(error = %err, "fake camera: accept failed");
                    continue;
                }
            },
            () = cancel.cancelled() => return,
        };
        // Each packet goes out when written: with Nagle's algorithm, Linux's
        // delayed ACKs held a frame's later packets for up to 40 ms and
        // skewed every timing the tests take (observed on Linux 7.0,
        // 2026-10-09; macOS did not hold them).
        if let Err(err) = stream.set_nodelay(true) {
            tracing::warn!(error = %err, "fake camera: TCP_NODELAY failed");
        }
        Stats::bump(&stats.connections);
        let config = Arc::clone(&config);
        let stats = Arc::clone(&stats);
        let cancel = hangup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let clock = Arc::clone(&clock);
        let _connection = spawn_named("fake_camera.connection", async move {
            let scheme = if config.tls.is_some() {
                "rtsps"
            } else {
                "rtsp"
            };
            let base = match stream.local_addr() {
                Ok(addr) => format!("{scheme}://{addr}/stream/"),
                Err(_) => format!("{scheme}://127.0.0.1/stream/"),
            };
            let peer = stream
                .peer_addr()
                .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |peer| peer.ip());
            let addresses = (base, peer);
            match config.tls.clone() {
                None => serve(stream, addresses, config, stats, cancel, clock).await,
                Some(tls) => match TlsAcceptor::from(tls.config).accept(stream).await {
                    Ok(stream) => serve(stream, addresses, config, stats, cancel, clock).await,
                    Err(err) => {
                        Stats::bump(&stats.tls_failures);
                        tracing::debug!(error = %err, "fake camera: TLS handshake failed");
                    }
                },
            }
        });
    }
}

/// The SDP for the stream, with `session_lines` after `t=`, `video_fmtp`
/// at the end of the video's `fmtp` and the backchannel media last.
fn sdp(
    base: &str,
    video: CameraVideo,
    audio: Option<CameraAudio>,
    session_lines: &str,
    video_fmtp: &str,
    backchannel: Option<&CameraBackchannel>,
) -> String {
    format!(
        "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=fake camera\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         {session_lines}a=control:{base}\r\n{}{}{}",
        video.sdp(base, video_fmtp),
        audio.map(|audio| audio.sdp(base)).unwrap_or_default(),
        backchannel
            .map(|backchannel| backchannel.sdp(base))
            .unwrap_or_default(),
    )
}

impl CameraConfig {
    /// The SDP a `DESCRIBE` of the presentation at `base` (its URL, ending
    /// in `/`) is answered with: with the backchannel media when
    /// `backchannel` and the camera offers one.
    pub fn sdp(&self, base: &str, backchannel: bool) -> String {
        sdp(
            base,
            self.video,
            self.audio,
            &self.sdp_session_lines,
            &self.video_fmtp,
            self.backchannel.as_ref().filter(|_| backchannel),
        )
    }
}

/// The state of one connection.
struct Connection {
    /// The camera's settings.
    config: Arc<CameraConfig>,
    /// The counters.
    stats: Arc<Stats>,
    /// The session id handed out at SETUP.
    session: Option<String>,
    /// PLAY was answered.
    playing: bool,
    /// The next frame index.
    frame: u32,
    /// The next sequence number.
    seq: u16,
    /// Packets sent on this connection.
    sent: u64,
    /// The base URL of the presentation.
    base: String,
    /// The interleaved RTP channel of the audio, once set up.
    audio_channel: Option<u8>,
    /// Audio packets sent so far.
    audio_sent: u64,
    /// The client's address, where datagrams go.
    peer: IpAddr,
    /// The UDP side, once a `SETUP` asked for it.
    udp: Option<UdpSide>,
    /// It hung at `PLAY` ([`PlayAnswer::Never`]) and answers nothing.
    hung: bool,
    /// The last `DESCRIBE` offered the backchannel media.
    backchannel_offered: bool,
    /// The interleaved RTP channel of the backchannel, once set up; RTCP
    /// on the next one.
    backchannel_channel: Option<u8>,
}

/// The camera's UDP side of one connection: its port pair, the client's
/// ports per channel, and the fault state.
struct UdpSide {
    /// Sends RTP (the even port).
    rtp: UdpSocket,
    /// Sends RTCP (the next port).
    rtcp: UdpSocket,
    /// Sends the foreign copies.
    foreign: UdpSocket,
    /// The RTP port.
    port: u16,
    /// Where each channel's datagrams go: the RTP channel (even) to the
    /// client's RTP port, the next one to its RTCP port.
    destinations: HashMap<u8, SocketAddr>,
    /// RTP datagrams sent so far, for the faults' schedule.
    rtp_count: u64,
    /// A datagram held back to go after the next one.
    held: Option<(SocketAddr, Vec<u8>)>,
}

impl UdpSide {
    /// An RTP/RTCP pair on `ip` (RFC 3550 §11) and the foreign sender.
    fn bind(ip: IpAddr) -> io::Result<Self> {
        for _ in 0..32 {
            let first = std::net::UdpSocket::bind((ip, 0))?;
            let port = first.local_addr()?.port();
            let Ok(neighbor) = std::net::UdpSocket::bind((ip, port ^ 1)) else {
                continue;
            };
            let (media, control) = if port & 1 == 0 {
                (first, neighbor)
            } else {
                (neighbor, first)
            };
            let port = media.local_addr()?.port();
            let foreign = std::net::UdpSocket::bind((ip, 0))?;
            for socket in [&media, &control, &foreign] {
                socket.set_nonblocking(true)?;
            }
            return Ok(Self {
                rtp: UdpSocket::from_std(media)?,
                rtcp: UdpSocket::from_std(control)?,
                foreign: UdpSocket::from_std(foreign)?,
                port,
                destinations: HashMap::new(),
                rtp_count: 0,
                held: None,
            });
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "no RTP/RTCP port pair",
        ))
    }

    /// Sends one packet of `channel` to the client, with the faults of
    /// `faults` on RTP; `false` when the channel is not a UDP one.
    async fn send(
        &mut self,
        channel: u8,
        packet: Vec<u8>,
        faults: &CameraUdp,
        stats: &Stats,
    ) -> bool {
        let Some(&to) = self.destinations.get(&channel) else {
            return false;
        };
        if faults.service == UdpService::Blackhole {
            return true;
        }
        if channel & 1 == 1 {
            Self::emit(&self.rtcp, &packet, to, stats).await;
            return true;
        }
        self.rtp_count = self.rtp_count.saturating_add(1);
        let nth =
            |every: Option<u64>| every.is_some_and(|n| n > 0 && self.rtp_count.is_multiple_of(n));
        if nth(faults.foreign_every) {
            let mut copy = packet.clone();
            if let Some(seq) = copy.get_mut(2..4) {
                let moved = u16::from_be_bytes([
                    seq.first().copied().unwrap_or(0),
                    seq.get(1).copied().unwrap_or(0),
                ])
                .wrapping_add(1000);
                seq.copy_from_slice(&moved.to_be_bytes());
            }
            let _sent = self.foreign.send_to(&copy, to).await;
        }
        if nth(faults.drop_every) {
            return true;
        }
        if nth(faults.swap_every) && self.held.is_none() {
            self.held = Some((to, packet));
            return true;
        }
        let twice = nth(faults.duplicate_every);
        Self::emit(&self.rtp, &packet, to, stats).await;
        if twice {
            Self::emit(&self.rtp, &packet, to, stats).await;
        }
        if let Some((held_to, held)) = self.held.take() {
            Self::emit(&self.rtp, &held, held_to, stats).await;
        }
        true
    }

    /// Sends one datagram and counts it.
    async fn emit(socket: &UdpSocket, packet: &[u8], to: SocketAddr, stats: &Stats) {
        if socket.send_to(packet, to).await.is_ok() {
            Stats::bump(&stats.datagrams);
        }
    }

    /// Counts what arrives on the camera's ports, and records what
    /// arrives on its RTCP port, until `cancel`.
    async fn count_received(&self, stats: &Stats, clock: &dyn Clock) {
        let (mut media, mut control) = ([0_u8; 2048], [0_u8; 2048]);
        loop {
            tokio::select! {
                received = self.rtp.recv_from(&mut media) => {
                    if received.is_ok() {
                        Stats::bump(&stats.datagrams_received);
                    }
                }
                received = self.rtcp.recv_from(&mut control) => {
                    if let Ok((len, from)) = received {
                        Stats::bump(&stats.datagrams_received);
                        let channel = self
                            .destinations
                            .iter()
                            .find(|(channel, to)| *channel & 1 == 1 && **to == from)
                            .map(|(channel, _)| *channel);
                        stats.record_rtcp(ClientRtcp {
                            at: clock.now(),
                            channel,
                            udp: true,
                            packet: control.get(..len).unwrap_or_default().to_vec(),
                        });
                    }
                }
            }
        }
    }
}

/// Serves one connection, plain or TLS: requests, then the stream once
/// playing. `base` is the presentation's base URL, `peer` the client's
/// address.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    (base, peer): (String, IpAddr),
    config: Arc<CameraConfig>,
    stats: Arc<Stats>,
    cancel: CancellationToken,
    clock: Arc<dyn Clock>,
) {
    if config.silent {
        cancel.cancelled().await;
        return;
    }
    let mut connection = Connection {
        config,
        stats,
        session: None,
        playing: false,
        frame: 0,
        seq: 1,
        sent: 0,
        base,
        audio_channel: None,
        audio_sent: 0,
        peer,
        udp: None,
        hung: false,
        backchannel_offered: false,
        backchannel_channel: None,
    };
    let frame_interval = Duration::from_secs(1)
        .checked_div(connection.config.fps.max(1))
        .unwrap_or(Duration::from_millis(33));
    let mut inbound = Vec::new();
    let mut read_buf = vec![0_u8; 4096];
    // Frames go out on a fixed grid from PLAY, as a camera's capture clock
    // runs: requests and slow writes never stretch the RTP clock.
    let mut next_frame_at: Option<Instant> = None;
    // The audio's grid starts with the video's.
    let mut audio_start: Option<Instant> = None;
    loop {
        if connection.playing && next_frame_at.is_none() {
            next_frame_at = Some(clock.now());
            audio_start = next_frame_at;
        }
        let wait = next_frame_at.map_or(frame_interval, |at| {
            at.saturating_duration_since(clock.now())
        });
        let mut tick = clock.sleep(wait);
        tokio::select! {
            () = async {
                match &connection.udp {
                    Some(udp) => udp.count_received(&connection.stats, &*clock).await,
                    None => std::future::pending().await,
                }
            } => {}
            read = stream.read(&mut read_buf) => {
                let n = match read {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                inbound.extend_from_slice(read_buf.get(..n).unwrap_or(&[]));
                if !connection.serve_inbound(&mut stream, &mut inbound, clock.now()).await {
                    return;
                }
            }
            () = &mut tick, if connection.playing => {
                next_frame_at = next_frame_at.and_then(|at| at.checked_add(frame_interval));
                let spacing = connection.config.packet_spacing;
                for (index, (channel, packet)) in connection.next_frame(&clock).into_iter().enumerate() {
                    if index > 0 && !spacing.is_zero() {
                        clock.sleep(spacing).await;
                    }
                    if connection.deliver(&mut stream, channel, packet).await.is_err() {
                        return;
                    }
                }
                if let Some(start) = audio_start {
                    for (channel, packet) in connection.due_audio(start, clock.now(), &clock) {
                        if connection.deliver(&mut stream, channel, packet).await.is_err() {
                            return;
                        }
                    }
                }
                if connection.config.packets_before_close.is_some_and(|limit| connection.sent >= limit) {
                    let _flushed = stream.shutdown().await;
                    return;
                }
            }
            () = cancel.cancelled() => return,
        }
    }
}

impl Connection {
    /// Handles every whole message in `inbound`, read at `arrival`:
    /// requests answered on `stream` (none once it hung at `PLAY`),
    /// interleaved frames handed to [`Self::receive`]; the rest stays for
    /// the next read. `false` when the connection ends: a write failed, a
    /// `TEARDOWN`, or bytes that are no RTSP.
    async fn serve_inbound<S: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        inbound: &mut Vec<u8>,
        arrival: Instant,
    ) -> bool {
        loop {
            let (message, consumed) = match Message::<Vec<u8>>::parse(inbound.as_slice()) {
                Ok(parsed) => parsed,
                Err(ParseError::Incomplete(_)) => return true,
                Err(ParseError::Error) => return false,
            };
            inbound.drain(..consumed);
            let request = match message {
                Message::Request(request) => request,
                Message::Data(data) => {
                    self.receive(data.channel_id(), data.as_slice(), arrival);
                    continue;
                }
                Message::Response(_) => continue,
            };
            let (response, close) = self.respond(&request);
            let Some(bytes) = response else {
                continue;
            };
            if stream.write_all(&bytes).await.is_err() {
                return false;
            }
            if close {
                let _flushed = stream.shutdown().await;
                return false;
            }
        }
    }

    /// Sends one packet of `channel`: as a datagram if the channel was set
    /// up over UDP, else interleaved on `stream` (RFC 2326 §10.12).
    async fn deliver<S: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        channel: u8,
        packet: Vec<u8>,
    ) -> io::Result<()> {
        if let Some(udp) = self.udp.as_mut()
            && udp
                .send(channel, packet.clone(), &self.config.udp, &self.stats)
                .await
        {
            return Ok(());
        }
        stream.write_all(&interleave(channel, &packet)).await
    }

    /// The audio packets due by `now` on the packet grid from `start`, a
    /// Sender Report about once a second, with their channels; none
    /// without audio.
    fn due_audio(
        &mut self,
        start: Instant,
        now: Instant,
        clock: &Arc<dyn Clock>,
    ) -> Vec<(u8, Vec<u8>)> {
        let (Some(channel), Some(audio)) = (self.audio_channel, self.config.audio) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        loop {
            let offset = u32::try_from(self.audio_sent)
                .ok()
                .and_then(|sent| audio.interval().checked_mul(sent));
            let Some(due) = offset
                .and_then(|offset| start.checked_add(offset))
                .filter(|due| *due <= now)
            else {
                return out;
            };
            let index = u32::try_from(self.audio_sent).unwrap_or(u32::MAX);
            let ts = AUDIO_FIRST_TIMESTAMP.wrapping_add(index.wrapping_mul(audio.samples()));
            if self.audio_sent.is_multiple_of(audio.sr_every()) {
                // The report goes out now, on a video tick, which can be
                // after the packet was due: its RTP timestamp is the one of
                // now, not the packet's (RFC 3550 §6.4.1).
                let late = now.saturating_duration_since(due).as_micros();
                let ticks = late
                    .saturating_mul(u128::from(audio.samples()))
                    .checked_div(audio.interval().as_micros())
                    .unwrap_or(0);
                let at_now = ts.wrapping_add(u32::try_from(ticks).unwrap_or(0));
                let report = sender_report_of(clock, AUDIO_SSRC, at_now, self.audio_sent);
                out.push((channel.saturating_add(1), report));
            }
            let seq = u16::try_from(self.audio_sent & 0xffff).unwrap_or(0);
            let payload = audio.payload(self.audio_sent);
            let packet = rtp_of(audio.payload_type(), AUDIO_SSRC, seq, ts, false, &payload);
            out.push((channel, packet));
            self.audio_sent = self.audio_sent.saturating_add(1);
        }
    }

    /// What to write in answer to one request, `None` for one left
    /// unanswered; `true` closes the connection afterwards.
    fn respond(&mut self, request: &Request<Vec<u8>>) -> (Option<Vec<u8>>, bool) {
        let (response, close) = self.answer(request);
        let mut bytes = Vec::new();
        if response.write(&mut bytes).is_err() {
            return (None, true);
        }
        if *request.method() == Method::Play {
            match self.config.play {
                PlayAnswer::Never => self.hung = true,
                PlayAnswer::Unreadable => bytes.extend_from_slice(UNREADABLE),
                PlayAnswer::Play | PlayAnswer::Refuse => {}
            }
        }
        if self.hung {
            return (None, false);
        }
        (Some(bytes), close)
    }

    /// The answer to one request; `true` closes the connection afterwards.
    fn answer(&mut self, request: &Request<Vec<u8>>) -> (Response<Vec<u8>>, bool) {
        let cseq = request
            .header(&CSEQ)
            .map(|v| v.as_str().to_owned())
            .unwrap_or_default();
        let method = request.method().clone();
        if matches!(method, Method::Describe | Method::Setup | Method::Play)
            && !self.authorized(request)
        {
            Stats::bump(&self.stats.unauthorized);
            return (
                reply(&cseq, StatusCode::Unauthorized)
                    .header(WWW_AUTHENTICATE, "Basic realm=\"fake camera\"")
                    .build(Vec::new()),
                false,
            );
        }
        match method {
            Method::Options => {
                if self.playing {
                    Stats::bump(&self.stats.keepalives);
                }
                (
                    reply(&cseq, StatusCode::Ok)
                        .header(
                            PUBLIC,
                            "OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, GET_PARAMETER",
                        )
                        .build(Vec::new()),
                    false,
                )
            }
            Method::Describe => (self.describe(request, &cseq), false),
            Method::Setup => (self.setup(request, &cseq), false),
            Method::Play => (self.play(&cseq), false),
            Method::GetParameter => {
                Stats::bump(&self.stats.keepalives);
                (reply(&cseq, StatusCode::Ok).build(Vec::new()), false)
            }
            Method::Teardown => {
                Stats::bump(&self.stats.teardowns);
                self.playing = false;
                (reply(&cseq, StatusCode::Ok).build(Vec::new()), true)
            }
            _ => (
                reply(&cseq, StatusCode::MethodNotAllowed).build(Vec::new()),
                false,
            ),
        }
    }

    /// Whether the request carries the configured Basic credentials
    /// (RFC 7617); always when none are configured.
    fn authorized(&self, request: &Request<Vec<u8>>) -> bool {
        let Some((user, pass)) = &self.config.auth else {
            return true;
        };
        let expected = format!(
            "Basic {}",
            base64::encode(format!("{user}:{pass}").as_bytes())
        );
        request
            .header(&AUTHORIZATION)
            .is_some_and(|given| given.as_str() == expected)
    }

    /// DESCRIBE: the SDP, with the backchannel media when the request
    /// carries its `Require` tag and the camera offers one (ONVIF Streaming
    /// Specification §5.3.1, §5.3.2), or the quirk's refusal.
    fn describe(&mut self, request: &Request<Vec<u8>>, cseq: &str) -> Response<Vec<u8>> {
        let asked = request.header(&REQUIRE).is_some_and(|tags| {
            tags.as_str()
                .split(',')
                .any(|tag| tag.trim() == BACKCHANNEL_REQUIRE)
        });
        let offered = match self.config.backchannel.as_ref().map(|b| b.require) {
            Some(RequireAnswer::Honor) => asked,
            Some(RequireAnswer::OptionNotSupported) if asked => {
                Stats::bump(&self.stats.require_rejected);
                return reply(cseq, StatusCode::OptionNotSupported)
                    .header(UNSUPPORTED, BACKCHANNEL_REQUIRE)
                    .build(Vec::new());
            }
            Some(RequireAnswer::BadRequest) if asked => {
                Stats::bump(&self.stats.require_rejected);
                return reply(cseq, StatusCode::BadRequest).build(Vec::new());
            }
            _ => false,
        };
        self.backchannel_offered = offered;
        Stats::bump(&self.stats.describes);
        if offered {
            Stats::bump(&self.stats.backchannel_describes);
        }
        reply(cseq, StatusCode::Ok)
            .header(CONTENT_TYPE, "application/sdp")
            .header(CONTENT_BASE, self.base.clone())
            .build(self.config.sdp(&self.base, offered).into_bytes())
    }

    /// One interleaved frame from the client (RFC 2326 §10.12): one on an
    /// odd channel is the client's RTCP, recorded; after `PLAY`, RTP on the
    /// backchannel's channel is recorded and RTCP on the next one counted,
    /// anything else on them refused. Frames on other channels are
    /// otherwise ignored.
    fn receive(&self, channel: u8, packet: &[u8], arrival: Instant) {
        if channel & 1 == 1 {
            self.stats.record_rtcp(ClientRtcp {
                at: arrival,
                channel: Some(channel),
                udp: false,
                packet: packet.to_vec(),
            });
        }
        let Some(rtp_channel) = self.backchannel_channel else {
            return;
        };
        if channel == rtp_channel.wrapping_add(1) {
            if is_rtcp(packet) {
                Stats::bump(&self.stats.backchannel_rtcp);
            } else {
                Stats::bump(&self.stats.backchannel_refused);
            }
            return;
        }
        if channel != rtp_channel {
            return;
        }
        let accept_only = self.config.backchannel.as_ref().and_then(|b| b.accept_only);
        match BackchannelRtp::parse(packet, arrival) {
            Some(rtp) if self.playing && accept_only.is_none_or(|pt| pt == rtp.payload_type) => {
                self.stats.record(rtp);
            }
            _ => Stats::bump(&self.stats.backchannel_refused),
        }
    }

    /// SETUP: TCP interleaved, or RTP over UDP to the `client_port` pair.
    fn setup(&mut self, request: &Request<Vec<u8>>, cseq: &str) -> Response<Vec<u8>> {
        let transport = request
            .header(&TRANSPORT)
            .map(|v| v.as_str().to_owned())
            .unwrap_or_default();
        let backchannel = request
            .request_uri()
            .is_some_and(|uri| uri.as_str().ends_with(BACKCHANNEL_CONTROL));
        if backchannel && !self.backchannel_offered {
            return reply(cseq, StatusCode::NotFound).build(Vec::new());
        }
        if backchannel && (transport.contains("client_port=") || !transport.contains("RTP/AVP/TCP"))
        {
            return reply(cseq, StatusCode::UnsupportedTransport).build(Vec::new());
        }
        if transport.contains("client_port=") && self.config.udp.service != UdpService::Refuse {
            return self.setup_udp(request, &transport, cseq);
        }
        if !transport.contains("RTP/AVP/TCP") || self.config.udp.service == UdpService::Only {
            return reply(cseq, StatusCode::UnsupportedTransport).build(Vec::new());
        }
        Stats::bump(&self.stats.setups);
        let session = "12345678".to_owned();
        self.session = Some(session.clone());
        // The channels the client asked for (RFC 2326 §12.39), the video's
        // 0-1 by default.
        let channel = transport
            .split(';')
            .find_map(|part| part.strip_prefix("interleaved="))
            .and_then(|range| range.split('-').next())
            .and_then(|first| first.parse::<u8>().ok())
            .unwrap_or(0);
        if request
            .request_uri()
            .is_some_and(|uri| uri.as_str().ends_with("track1"))
        {
            self.audio_channel = Some(channel);
        }
        if backchannel {
            Stats::bump(&self.stats.backchannel_setups);
            self.backchannel_channel = Some(channel);
        }
        reply(cseq, StatusCode::Ok)
            .header(
                TRANSPORT,
                format!(
                    "RTP/AVP/TCP;unicast;interleaved={channel}-{}",
                    channel.saturating_add(1)
                ),
            )
            .header(
                SESSION,
                format!("{session};timeout={}", self.config.session_timeout_s),
            )
            .build(Vec::new())
    }

    /// SETUP over UDP (RFC 2326 §12.39): the camera's pair, bound on the
    /// first such request, sends this stream (video on channels 0 and 1,
    /// audio on 2 and 3) to the client's pair.
    fn setup_udp(
        &mut self,
        request: &Request<Vec<u8>>,
        transport: &str,
        cseq: &str,
    ) -> Response<Vec<u8>> {
        let client_port = transport
            .split(';')
            .find_map(|part| part.trim().strip_prefix("client_port="))
            .and_then(|range| range.split('-').next())
            .and_then(|first| first.parse::<u16>().ok());
        let Some(client_port) = client_port else {
            return reply(cseq, StatusCode::BadRequest).build(Vec::new());
        };
        if self.udp.is_none() {
            match UdpSide::bind(self.config.ip) {
                Ok(udp) => self.udp = Some(udp),
                Err(_) => return reply(cseq, StatusCode::InternalServerError).build(Vec::new()),
            }
        }
        let Some(udp) = self.udp.as_mut() else {
            return reply(cseq, StatusCode::InternalServerError).build(Vec::new());
        };
        Stats::bump(&self.stats.setups);
        Stats::bump(&self.stats.udp_setups);
        let audio = request
            .request_uri()
            .is_some_and(|uri| uri.as_str().ends_with("track1"));
        let channel = if audio {
            self.audio_channel = Some(2);
            2
        } else {
            0
        };
        udp.destinations
            .insert(channel, SocketAddr::new(self.peer, client_port));
        udp.destinations.insert(
            channel.saturating_add(1),
            SocketAddr::new(self.peer, client_port.saturating_add(1)),
        );
        let ssrc = if audio { AUDIO_SSRC } else { SSRC };
        let server_port = if self.config.udp.omit_server_port {
            String::new()
        } else {
            format!(";server_port={}-{}", udp.port, udp.port.saturating_add(1))
        };
        let source = self
            .config
            .udp
            .announce_source
            .map_or_else(String::new, |source| format!(";source={source}"));
        let answer = format!(
            "RTP/AVP/UDP;unicast;client_port={client_port}-{}{server_port}{source};ssrc={ssrc:08X}",
            client_port.saturating_add(1)
        );
        let session = "12345678".to_owned();
        self.session = Some(session.clone());
        reply(cseq, StatusCode::Ok)
            .header(TRANSPORT, answer)
            .header(
                SESSION,
                format!("{session};timeout={}", self.config.session_timeout_s),
            )
            .build(Vec::new())
    }

    /// PLAY: from then on the stream flows.
    fn play(&mut self, cseq: &str) -> Response<Vec<u8>> {
        let Some(session) = self.session.clone() else {
            return reply(cseq, StatusCode::SessionNotFound).build(Vec::new());
        };
        Stats::bump(&self.stats.plays);
        if matches!(self.config.play, PlayAnswer::Refuse | PlayAnswer::Never) {
            // `respond` leaves it unanswered for `PlayAnswer::Never`.
            return reply(cseq, StatusCode::ServiceUnavailable).build(Vec::new());
        }
        self.playing = true;
        let rtptime = |ts: u32| {
            if self.config.omit_rtptime {
                String::new()
            } else {
                format!(";rtptime={ts}")
            }
        };
        let video = format!(
            "url={}track0;seq={}{}",
            self.base,
            self.seq,
            rtptime(FIRST_TIMESTAMP)
        );
        let rtp_info = if self.audio_channel.is_some() {
            format!(
                "{video},url={}track1;seq=1{}",
                self.base,
                rtptime(AUDIO_FIRST_TIMESTAMP)
            )
        } else {
            video
        };
        reply(cseq, StatusCode::Ok)
            .header(SESSION, session)
            .header(RTP_INFO, rtp_info)
            .build(Vec::new())
    }

    /// The packets of the next access unit with their channels (0 RTP, 1
    /// RTCP).
    fn next_frame(&mut self, clock: &Arc<dyn Clock>) -> Vec<(u8, Vec<u8>)> {
        let index = self.frame;
        self.frame = self.frame.wrapping_add(1);
        let ticks_per_frame = 90_000_u32
            .checked_div(self.config.fps.max(1))
            .unwrap_or(3_000);
        let jump = match self.config.timestamp_jump {
            Some((from, ticks)) if index >= from => ticks,
            _ => 0,
        };
        let ts = FIRST_TIMESTAMP
            .wrapping_add(index.wrapping_mul(ticks_per_frame))
            .wrapping_add(jump);
        let mut payloads: Vec<Bytes> = Vec::new();
        if let Some(origin) = self.config.stamp_origin
            && self.config.video == CameraVideo::H264
        {
            let sent = clock.now().saturating_duration_since(origin);
            payloads.push(Bytes::from(crate::latency::stamp_sei(sent)));
        }
        let keyframe = index.is_multiple_of(self.config.gop.max(1));
        payloads.extend(self.config.video.access_unit(keyframe, &self.config, index));
        let count = payloads.len();
        let mut out = Vec::with_capacity(count.saturating_add(1));
        if index.is_multiple_of(self.config.sr_every.max(1)) {
            out.push((1, sender_report(clock, ts, self.sent)));
        }
        for (i, payload) in payloads.into_iter().enumerate() {
            let marker = self.config.marker_bit && i.saturating_add(1) == count;
            out.push((0, rtp(self.seq, ts, marker, &payload)));
            self.seq = self.seq.wrapping_add(1);
            self.sent = self.sent.saturating_add(1);
            Stats::bump(&self.stats.packets);
        }
        out
    }
}

/// What [`PlayAnswer::Unreadable`] writes after its answer: no RTSP message
/// starts with these bytes, and nothing frames them as interleaved data.
const UNREADABLE: &[u8] = b"\xff\xfe not RTSP\r\n\r\n";

/// A response builder echoing the request's `CSeq`.
fn reply(cseq: &str, status: StatusCode) -> rtsp_types::ResponseBuilder {
    Response::builder(Version::V1_0, status).header(CSEQ, cseq.to_owned())
}

/// An opaque slice NAL unit of `len` bytes whose content varies per frame.
fn slice(unit_type: u8, len: usize, frame: u32) -> Vec<u8> {
    let header = 0x60 | unit_type;
    // The first byte reads as `first_mb_in_slice` 0 (ISO/IEC 14496-10
    // §7.3.3), so a receiver that parses it sees the slice start its
    // picture, as libwebrtc's depacketizer does.
    std::iter::once(header)
        .chain((0..len).map(|i| {
            if i == 0 {
                0x88
            } else {
                u8::try_from((i.wrapping_add(frame as usize)) % 251).unwrap_or(0)
            }
        }))
        .collect()
}

/// An opaque H.265 slice NAL unit of `len` bytes after its two-byte header
/// (layer 0, temporal id 0), varying per frame.
fn h265_slice(unit_type: u8, len: usize, frame: u32) -> Vec<u8> {
    [unit_type << 1, 0x01]
        .into_iter()
        .chain((0..len).map(|i| u8::try_from((i.wrapping_add(frame as usize)) % 251).unwrap_or(0)))
        .collect()
}

/// An RTP packet (RFC 3550 §5.1) around `payload`.
fn rtp(seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    rtp_of(PAYLOAD_TYPE, SSRC, seq, ts, marker, payload)
}

/// An RTP packet of payload type `pt` from `ssrc` (RFC 3550 §5.1).
fn rtp_of(pt: u8, ssrc: u32, seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(12));
    out.push(0x80);
    out.push((u8::from(marker) << 7) | pt);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&ssrc.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// An RTCP Sender Report (RFC 3550 §6.4.1) with no reception blocks.
fn sender_report(clock: &Arc<dyn Clock>, rtp_ts: u32, packets: u64) -> Vec<u8> {
    sender_report_of(clock, SSRC, rtp_ts, packets)
}

/// A Sender Report of `ssrc` (RFC 3550 §6.4.1): now on the wall clock, and
/// the RTP timestamp of the same instant.
fn sender_report_of(clock: &Arc<dyn Clock>, ssrc: u32, rtp_ts: u32, packets: u64) -> Vec<u8> {
    let since_epoch = clock
        .wall_now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    // NTP seconds start 70 years before Unix time.
    let ntp_secs = since_epoch.as_secs().saturating_add(2_208_988_800);
    let ntp_frac = u64::from(since_epoch.subsec_nanos()).saturating_mul(1 << 32) / 1_000_000_000;
    let mut out = Vec::with_capacity(28);
    out.push(0x80);
    out.push(200);
    out.extend_from_slice(&6_u16.to_be_bytes());
    out.extend_from_slice(&ssrc.to_be_bytes());
    out.extend_from_slice(
        &u32::try_from(ntp_secs & 0xffff_ffff)
            .unwrap_or(0)
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u32::try_from(ntp_frac & 0xffff_ffff)
            .unwrap_or(0)
            .to_be_bytes(),
    );
    out.extend_from_slice(&rtp_ts.to_be_bytes());
    out.extend_from_slice(&u32::try_from(packets).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    out
}

/// Frames `payload` as interleaved binary data on `channel` (RFC 2326 §10.12).
fn interleave(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(4));
    if Data::new(channel, payload).write(&mut out).is_err() {
        out.clear();
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn packets_and_reports_are_well_formed() {
        let packet = rtp(7, 90_000, true, &[1, 2, 3]);
        assert_eq!(packet.len(), 15);
        assert_eq!(packet[0], 0x80);
        assert_eq!(packet[1], 0x80 | PAYLOAD_TYPE);
        assert_eq!(&packet[2..4], &7_u16.to_be_bytes());
        assert_eq!(&packet[4..8], &90_000_u32.to_be_bytes());
        let clock: Arc<dyn Clock> = Arc::new(lotse_core::clock::SystemClock);
        let report = sender_report(&clock, 5, 9);
        assert_eq!(report.len(), 28);
        assert_eq!((report[0], report[1]), (0x80, 200));
        assert_eq!(&report[16..20], &5_u32.to_be_bytes());
        let framed = interleave(1, &report);
        assert_eq!(framed[0], b'$');
        assert_eq!(framed[1], 1);
        assert_eq!(&framed[2..4], &28_u16.to_be_bytes());
        let text = sdp(
            "rtsp://127.0.0.1:1/stream/",
            CameraVideo::H264,
            None,
            "",
            "",
            None,
        );
        assert!(text.contains("sprop-parameter-sets="));
        assert!(!text.contains("m=audio"));
        let with_audio = sdp(
            "rtsp://127.0.0.1:1/stream/",
            CameraVideo::H264,
            Some(CameraAudio::Pcmu),
            "",
            ";x-own=1",
            None,
        );
        assert!(with_audio.contains(";x-own=1\r\na=control:rtsp://127.0.0.1:1/stream/track0"));
        assert!(with_audio.contains("m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000"));
        assert!(with_audio.contains("a=control:rtsp://127.0.0.1:1/stream/track1"));
        let with_aac = sdp(
            "rtsp://127.0.0.1:1/stream/",
            CameraVideo::H264,
            Some(CameraAudio::Aac),
            "a=x-own:1\r\n",
            "",
            None,
        );
        assert!(with_aac.contains("t=0 0\r\na=x-own:1\r\na=control:"));
        assert!(with_aac.contains("a=rtpmap:97 MPEG4-GENERIC/16000/1"));
        assert!(
            with_aac.contains(
                "mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1408"
            )
        );
        assert!(text.contains("profile-level-id=42c028"));
        assert_eq!(slice(nal::NAL_IDR, 3, 0)[0], 0x65);
    }

    #[test]
    fn h265_access_units_aggregate_the_sets_and_fragment_the_slices_rfc7798_4_4() {
        let h265 = sdp(
            "rtsp://127.0.0.1:1/stream/",
            CameraVideo::H265,
            None,
            "",
            ";sprop-max-don-diff=2",
            None,
        );
        assert!(h265.contains("a=rtpmap:96 H265/90000\r\na=fmtp:96 profile-id=1;sprop-vps="));
        assert!(h265.contains(";sprop-max-don-diff=2\r\na=control:"));
        assert_eq!(h265_slice(h265::nal::IDR_W_RADL, 3, 0)[..2], [0x26, 0x01]);
        let config = CameraConfig {
            mtu: 500,
            ..CameraConfig::default()
        };
        let idr = CameraVideo::H265.access_unit(true, &config, 0);
        assert_eq!(h265::nal::nal_type(idr[0][0]), h265::nal::AP);
        assert!(
            idr[1..]
                .iter()
                .all(|p| h265::nal::nal_type(p[0]) == h265::nal::FU)
        );
        let p = CameraVideo::H265.access_unit(false, &config, 1);
        assert_eq!(p.len(), 2, "600 bytes in two fragments");
        // The High tier stream says so in its fmtp and its sets.
        let high = sdp(
            "rtsp://127.0.0.1:1/stream/",
            CameraVideo::H265HighTier,
            None,
            "",
            "",
            None,
        );
        assert!(high.contains("a=fmtp:96 profile-id=1;tier-flag=1;sprop-vps="));
        let (vps, sps) = CameraVideo::H265HighTier.h265_sets();
        assert!(h265::parse_sps(&sps).unwrap().high_tier);
        let idr = CameraVideo::H265HighTier.access_unit(true, &config, 0);
        assert_eq!(
            idr[0],
            h265::nal::aggregate(&[&vps, &sps, &h265::test_data::pps()])
        );
    }

    /// A raw RTSP client over TCP: requests written by hand, answers read
    /// with `rtsp-types`, interleaved frames from the camera skipped.
    struct Client {
        stream: tokio::net::TcpStream,
        inbound: Vec<u8>,
        cseq: u32,
        clock: Arc<dyn Clock>,
    }

    impl Client {
        async fn connect(camera: &FakeCamera) -> Self {
            Self {
                stream: tokio::net::TcpStream::connect(camera.addr()).await.unwrap(),
                inbound: Vec::new(),
                cseq: 0,
                clock: clock(),
            }
        }

        async fn request(
            &mut self,
            method: &str,
            uri: &str,
            headers: &[&str],
        ) -> Response<Vec<u8>> {
            self.cseq += 1;
            let mut text = format!("{method} {uri} RTSP/1.0\r\nCSeq: {}\r\n", self.cseq);
            for header in headers {
                text.push_str(header);
                text.push_str("\r\n");
            }
            text.push_str("\r\n");
            self.stream.write_all(text.as_bytes()).await.unwrap();
            let deadline = self.clock.sleep(Duration::from_secs(5));
            tokio::pin!(deadline);
            loop {
                match Message::<Vec<u8>>::parse(&self.inbound) {
                    Ok((message, consumed)) => {
                        self.inbound.drain(..consumed);
                        if let Message::Response(response) = message {
                            return response;
                        }
                        continue;
                    }
                    Err(ParseError::Incomplete(_)) => {}
                    Err(ParseError::Error) => panic!("unparsable answer"),
                }
                let mut buf = [0_u8; 4096];
                tokio::select! {
                    read = self.stream.read(&mut buf) => {
                        let n = read.unwrap();
                        assert!(n > 0, "the camera hung up");
                        self.inbound.extend_from_slice(&buf[..n]);
                    }
                    () = &mut deadline => panic!("no answer to {method}"),
                }
            }
        }

        async fn send(&mut self, channel: u8, packet: &[u8]) {
            self.stream
                .write_all(&interleave(channel, packet))
                .await
                .unwrap();
        }
    }

    fn clock() -> Arc<dyn Clock> {
        Arc::new(lotse_core::clock::SystemClock)
    }

    fn with_backchannel(backchannel: CameraBackchannel) -> CameraConfig {
        CameraConfig {
            // Few packets, so an unread socket never fills while the test
            // sends.
            fps: 5,
            backchannel: Some(backchannel),
            ..CameraConfig::default()
        }
    }

    async fn eventually(clock: &Arc<dyn Clock>, mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            if done() {
                return true;
            }
            clock.sleep(Duration::from_millis(10)).await;
        }
        done()
    }

    const REQUIRE_BACKCHANNEL: &str = "Require: www.onvif.org/ver20/backchannel";

    fn base(camera: &FakeCamera) -> String {
        format!("rtsp://{}/stream/", camera.addr())
    }

    fn body(response: &Response<Vec<u8>>) -> String {
        String::from_utf8(response.body().clone()).unwrap()
    }

    #[test]
    fn onvif_5_3_1_the_backchannel_media_is_sendonly_in_its_codec_payload_type_and_ptime() {
        let base = "rtsp://127.0.0.1:1/stream/";
        let mu_law = CameraBackchannel::new(BackchannelCodec::Pcmu).sdp(base);
        assert_eq!(
            mu_law,
            "m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n\
             a=control:rtsp://127.0.0.1:1/stream/backchannel\r\n"
        );
        let pcma = CameraBackchannel::new(BackchannelCodec::Pcma);
        assert_eq!(pcma.payload_type(), 8);
        assert!(
            pcma.sdp(base)
                .starts_with("m=audio 0 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
        );
        // RFC 7587 §7: always two channels in the rtpmap.
        let opus = CameraBackchannel::new(BackchannelCodec::Opus);
        assert_eq!(opus.payload_type(), 111);
        assert!(opus.sdp(base).contains("a=rtpmap:111 opus/48000/2\r\n"));
        let custom = CameraBackchannel {
            payload_type: Some(96),
            ptime: Some(40),
            ..CameraBackchannel::new(BackchannelCodec::Pcma)
        };
        assert!(custom.sdp(base).starts_with(
            "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 PCMA/8000\r\na=ptime:40\r\na=sendonly\r\n"
        ));
        // The whole SDP: the backchannel last, only when asked and offered.
        let config = CameraConfig {
            audio: Some(CameraAudio::Pcmu),
            backchannel: Some(custom),
            ..CameraConfig::default()
        };
        let offered = config.sdp(base, true);
        assert!(offered.ends_with(&config.backchannel.as_ref().unwrap().sdp(base)));
        assert!(offered.contains("track1\r\nm=audio 0 RTP/AVP 96"));
        assert!(!config.sdp(base, false).contains("a=sendonly"));
        assert!(
            !CameraConfig::default()
                .sdp(base, true)
                .contains("a=sendonly")
        );
    }

    #[test]
    fn rfc3550_5_1_backchannel_rtp_is_parsed_past_csrcs_extension_and_padding() {
        let at = clock().now();
        let plain = BackchannelRtp::parse(&rtp_of(8, 0xabcd, 7, 160, true, &[1, 2]), at).unwrap();
        assert_eq!(
            plain,
            BackchannelRtp {
                payload_type: 8,
                marker: true,
                sequence_number: 7,
                timestamp: 160,
                ssrc: 0xabcd,
                payload: vec![1, 2],
                arrival: at,
            }
        );
        let unmarked = BackchannelRtp::parse(&rtp_of(0, 1, 1, 1, false, &[]), at).unwrap();
        assert!(!unmarked.marker);
        assert!(unmarked.payload.is_empty());
        // Two CSRCs, a one-word extension and three bytes of padding
        // (RFC 3550 §5.1, §5.3.1).
        let mut full = rtp_of(0, 1, 2, 3, false, &[]);
        full[0] = 0x80 | 0x20 | 0x10 | 2;
        full.extend_from_slice(&[0; 8]);
        full.extend_from_slice(&[0xbe, 0xde, 0, 1, 9, 9, 9, 9]);
        full.extend_from_slice(&[5, 6, 0, 0, 3]);
        assert_eq!(
            BackchannelRtp::parse(&full, at).unwrap().payload,
            vec![5, 6]
        );
        let mut version1 = rtp_of(0, 1, 2, 3, false, &[1]);
        version1[0] = 0x40;
        assert_eq!(BackchannelRtp::parse(&version1, at), None);
        assert_eq!(BackchannelRtp::parse(&[0x80; 11], at), None);
        let mut short_csrc = rtp_of(0, 1, 2, 3, false, &[1]);
        short_csrc[0] = 0x82;
        assert_eq!(BackchannelRtp::parse(&short_csrc, at), None);
        let mut short_extension = rtp_of(0, 1, 2, 3, false, &[0xbe, 0xde, 0, 2, 0, 0, 0, 0]);
        short_extension[0] = 0x90;
        assert_eq!(BackchannelRtp::parse(&short_extension, at), None);
        let mut no_extension_header = rtp_of(0, 1, 2, 3, false, &[0xbe, 0xde]);
        no_extension_header[0] = 0x90;
        assert_eq!(BackchannelRtp::parse(&no_extension_header, at), None);
        let mut overpadded = rtp_of(0, 1, 2, 3, false, &[1, 9]);
        overpadded[0] = 0xa0;
        assert_eq!(BackchannelRtp::parse(&overpadded, at), None);
        let mut padding_only = rtp_of(0, 1, 2, 3, false, &[]);
        padding_only[0] = 0xa0;
        assert_eq!(BackchannelRtp::parse(&padding_only, at), None);
        // RTCP: version 2, SR to APP (RFC 3550 §12.1).
        assert!(is_rtcp(&[0x81, 201, 0, 1]));
        assert!(is_rtcp(&[0x80, 200, 0, 6, 0]));
        assert!(is_rtcp(&[0x80, 204, 0, 0]));
        assert!(!is_rtcp(&[0x80, 199, 0, 0]));
        assert!(!is_rtcp(&[0x80, 205, 0, 0]));
        assert!(!is_rtcp(&[0x40, 201, 0, 0]));
        assert!(!is_rtcp(&[0x80, 201, 0]));
    }

    #[tokio::test]
    async fn onvif_5_3_describe_with_require_offers_the_backchannel_and_without_it_nothing_changes()
    {
        let camera = FakeCamera::start(
            with_backchannel(CameraBackchannel::new(BackchannelCodec::Pcmu)),
            clock(),
        )
        .await
        .unwrap();
        let url = camera.url();
        let mut client = Client::connect(&camera).await;
        let plain = client.request("DESCRIBE", &url, &[]).await;
        assert_eq!(plain.status(), StatusCode::Ok);
        let config = with_backchannel(CameraBackchannel::new(BackchannelCodec::Pcmu));
        assert_eq!(body(&plain), config.sdp(&base(&camera), false));
        assert!(!body(&plain).contains("a=sendonly"));
        // Another option tag alongside (RFC 2326 §12.32 lists them comma-separated).
        let asked = client
            .request(
                "DESCRIBE",
                &url,
                &["Require: x-other, www.onvif.org/ver20/backchannel"],
            )
            .await;
        assert_eq!(asked.status(), StatusCode::Ok);
        assert_eq!(body(&asked), config.sdp(&base(&camera), true));
        assert!(body(&asked).contains("a=sendonly\r\na=control:"));
        // An unrelated tag alone is not the backchannel's.
        let other = client
            .request("DESCRIBE", &url, &["Require: x-other"])
            .await;
        assert!(!body(&other).contains("a=sendonly"));
        let stats = camera.stats();
        assert_eq!(Stats::get(&stats.describes), 3);
        assert_eq!(Stats::get(&stats.backchannel_describes), 1);
        assert_eq!(Stats::get(&stats.require_rejected), 0);
        // A camera without a backchannel ignores the tag.
        let without = FakeCamera::start(CameraConfig::default(), clock())
            .await
            .unwrap();
        let mut client = Client::connect(&without).await;
        let ignored = client
            .request("DESCRIBE", &without.url(), &[REQUIRE_BACKCHANNEL])
            .await;
        assert_eq!(ignored.status(), StatusCode::Ok);
        assert_eq!(
            body(&ignored),
            CameraConfig::default().sdp(&base(&without), false)
        );
        assert_eq!(Stats::get(&without.stats().backchannel_describes), 0);
        without.stop().await;
        camera.stop().await;
    }

    #[tokio::test]
    async fn onvif_5_3_the_backchannel_is_set_up_on_its_own_channels_and_records_rtp_after_play() {
        let clock = clock();
        let camera = FakeCamera::start(
            with_backchannel(CameraBackchannel::new(BackchannelCodec::Pcma)),
            Arc::clone(&clock),
        )
        .await
        .unwrap();
        let url = camera.url();
        let back = format!("{}{BACKCHANNEL_CONTROL}", base(&camera));
        let mut client = Client::connect(&camera).await;
        client
            .request("DESCRIBE", &url, &[REQUIRE_BACKCHANNEL])
            .await;
        let video = client
            .request(
                "SETUP",
                &format!("{}track0", base(&camera)),
                &["Transport: RTP/AVP/TCP;unicast;interleaved=0-1"],
            )
            .await;
        assert_eq!(video.status(), StatusCode::Ok);
        let setup = client
            .request(
                "SETUP",
                &back,
                &[
                    "Transport: RTP/AVP/TCP;unicast;interleaved=4-5",
                    "Session: 12345678",
                    REQUIRE_BACKCHANNEL,
                ],
            )
            .await;
        assert_eq!(setup.status(), StatusCode::Ok);
        assert_eq!(
            setup.header(&TRANSPORT).unwrap().as_str(),
            "RTP/AVP/TCP;unicast;interleaved=4-5"
        );
        assert!(
            setup
                .header(&SESSION)
                .unwrap()
                .as_str()
                .starts_with("12345678;")
        );
        // Before PLAY nothing is recorded.
        client
            .send(4, &rtp_of(8, 0x77, 1, 0, true, &[0xd5; 160]))
            .await;
        let play = client
            .request("PLAY", &url, &["Session: 12345678", REQUIRE_BACKCHANNEL])
            .await;
        assert_eq!(play.status(), StatusCode::Ok);
        let before = clock.now();
        client
            .send(4, &rtp_of(8, 0x77, 2, 160, true, &[0xd5; 160]))
            .await;
        client
            .send(4, &rtp_of(8, 0x77, 3, 320, false, &[0x55; 160]))
            .await;
        // A Receiver Report on the odd channel (RFC 3550 §6.4.2), then junk on both.
        client.send(5, &[0x80, 201, 0, 1, 0, 0, 0, 0x77]).await;
        client.send(5, &[1, 2, 3]).await;
        client.send(4, &[0x80, 8, 0]).await;
        // A client's report on the video's RTCP channel is not the backchannel's.
        client.send(1, &[0x80, 201, 0, 1, 0, 0, 0, 0x77]).await;
        let stats = camera.stats();
        assert!(eventually(&clock, || Stats::get(&stats.backchannel_refused) == 3).await);
        assert_eq!(Stats::get(&stats.backchannel_packets), 2);
        assert_eq!(Stats::get(&stats.backchannel_rtcp), 1);
        assert_eq!(Stats::get(&stats.backchannel_setups), 1);
        assert_eq!(Stats::get(&stats.setups), 2);
        let received = stats.backchannel();
        assert_eq!(received.len(), 2);
        let first = &received[0];
        assert_eq!(
            (
                first.payload_type,
                first.marker,
                first.sequence_number,
                first.timestamp,
                first.ssrc
            ),
            (8, true, 2, 160, 0x77)
        );
        assert_eq!(first.payload, vec![0xd5; 160]);
        assert_eq!(
            (received[1].sequence_number, received[1].marker),
            (3, false)
        );
        assert_eq!(received[1].payload, vec![0x55; 160]);
        assert!(first.arrival >= before);
        assert!(received[1].arrival >= first.arrival);
        // The video kept flowing to the client meanwhile.
        assert!(eventually(&clock, || Stats::get(&stats.packets) > 0).await);
        let teardown = client
            .request(
                "TEARDOWN",
                &url,
                &["Session: 12345678", REQUIRE_BACKCHANNEL],
            )
            .await;
        assert_eq!(teardown.status(), StatusCode::Ok);
        camera.stop().await;
    }

    #[tokio::test]
    async fn rfc2326_11_3_11_a_udp_setup_of_the_backchannel_is_refused_and_one_not_offered_is_not_found()
     {
        let camera = FakeCamera::start(
            with_backchannel(CameraBackchannel::new(BackchannelCodec::Pcmu)),
            clock(),
        )
        .await
        .unwrap();
        let back = format!("{}{BACKCHANNEL_CONTROL}", base(&camera));
        let mut client = Client::connect(&camera).await;
        // Not offered by this connection's DESCRIBE.
        client.request("DESCRIBE", &camera.url(), &[]).await;
        let unknown = client
            .request(
                "SETUP",
                &back,
                &["Transport: RTP/AVP/TCP;unicast;interleaved=2-3"],
            )
            .await;
        assert_eq!(unknown.status(), StatusCode::NotFound);
        client
            .request("DESCRIBE", &camera.url(), &[REQUIRE_BACKCHANNEL])
            .await;
        let udp = client
            .request(
                "SETUP",
                &back,
                &["Transport: RTP/AVP;unicast;client_port=5000-5001"],
            )
            .await;
        assert_eq!(udp.status(), StatusCode::UnsupportedTransport);
        let no_transport = client.request("SETUP", &back, &[]).await;
        assert_eq!(no_transport.status(), StatusCode::UnsupportedTransport);
        let stats = camera.stats();
        assert_eq!(Stats::get(&stats.setups), 0);
        assert_eq!(Stats::get(&stats.udp_setups), 0);
        assert_eq!(Stats::get(&stats.backchannel_setups), 0);
        // Frames on a channel nobody set up are ignored.
        client.send(4, &rtp_of(0, 1, 1, 0, true, &[0xff])).await;
        let options = client.request("OPTIONS", &camera.url(), &[]).await;
        assert_eq!(options.status(), StatusCode::Ok);
        assert_eq!(Stats::get(&stats.backchannel_refused), 0);
        camera.stop().await;
    }

    #[tokio::test]
    async fn dahua_require_is_refused_with_551_or_400_and_a_retry_without_it_plays_onvif_5_3_2_1() {
        for (answer, status) in [
            (
                RequireAnswer::OptionNotSupported,
                StatusCode::OptionNotSupported,
            ),
            (RequireAnswer::BadRequest, StatusCode::BadRequest),
        ] {
            let camera = FakeCamera::start(
                with_backchannel(CameraBackchannel {
                    require: answer,
                    ..CameraBackchannel::new(BackchannelCodec::Pcmu)
                }),
                clock(),
            )
            .await
            .unwrap();
            let mut client = Client::connect(&camera).await;
            let refused = client
                .request("DESCRIBE", &camera.url(), &[REQUIRE_BACKCHANNEL])
                .await;
            assert_eq!(refused.status(), status);
            let unsupported = refused.header(&UNSUPPORTED).map(|v| v.as_str().to_owned());
            if answer == RequireAnswer::OptionNotSupported {
                assert_eq!(unsupported.as_deref(), Some(BACKCHANNEL_REQUIRE));
            } else {
                assert_eq!(unsupported, None);
            }
            let retry = client.request("DESCRIBE", &camera.url(), &[]).await;
            assert_eq!(retry.status(), StatusCode::Ok);
            assert!(!body(&retry).contains("a=sendonly"));
            let stats = camera.stats();
            assert_eq!(Stats::get(&stats.require_rejected), 1);
            assert_eq!(Stats::get(&stats.describes), 1);
            assert_eq!(Stats::get(&stats.backchannel_describes), 0);
            camera.stop().await;
        }
    }

    #[tokio::test]
    async fn a_camera_that_takes_one_payload_type_refuses_rtp_of_another() {
        let clock = clock();
        let camera = FakeCamera::start(
            with_backchannel(CameraBackchannel {
                payload_type: Some(96),
                accept_only: Some(8),
                ..CameraBackchannel::new(BackchannelCodec::Pcma)
            }),
            Arc::clone(&clock),
        )
        .await
        .unwrap();
        let mut client = Client::connect(&camera).await;
        let described = client
            .request("DESCRIBE", &camera.url(), &[REQUIRE_BACKCHANNEL])
            .await;
        assert!(body(&described).contains("m=audio 0 RTP/AVP 96\r\na=rtpmap:96 PCMA/8000"));
        let back = format!("{}{BACKCHANNEL_CONTROL}", base(&camera));
        client
            .request(
                "SETUP",
                &back,
                &["Transport: RTP/AVP/TCP;unicast;interleaved=2-3"],
            )
            .await;
        client
            .request("PLAY", &camera.url(), &["Session: 12345678"])
            .await;
        client.send(2, &rtp_of(96, 1, 1, 0, true, &[0xd5])).await;
        client.send(2, &rtp_of(8, 1, 2, 160, false, &[0xd5])).await;
        let stats = camera.stats();
        assert!(eventually(&clock, || Stats::get(&stats.backchannel_packets) == 1).await);
        assert_eq!(Stats::get(&stats.backchannel_refused), 1);
        assert_eq!(stats.backchannel()[0].payload_type, 8);
        camera.stop().await;
    }
}
