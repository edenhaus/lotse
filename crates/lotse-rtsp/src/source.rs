//! The RTSP source: one retina session per connection attempt, TCP
//! interleaved or, opt-in, RTP over UDP through the relay, the H.264 and
//! H.265 normalizers of `lotse-codec` on its packets, RTCP Sender Reports
//! as sync hints.
//!
//! Implements RFC 2326 (RTSP 1.0: DESCRIBE, SETUP, PLAY, TEARDOWN through
//! retina), RFC 3550 §5.1 (packet header fields kept) and §6.4.1 (Sender
//! Reports), RFC 6184 (H.264) and RFC 7798 (H.265, §7.1 `sprop-vps`,
//! `sprop-sps` and `sprop-pps` read by retina, §7.2.3 a stream with
//! decoding order numbers declared unsupported through [`crate::fmtp`])
//! through `lotse-codec`,
//! RFC 3551 §6 (the
//! static audio payload types), RFC 7587 (Opus), RFC 3640 (AAC), and
//! RFC 7826 §19.2 for `rtsps` (the TLS stream in [`crate::tls`]), and
//! RFC 2326 §12.39 with RFC 3550 §11 for RTP over UDP ([`crate::udp`]). Every
//! connection reaches retina through [`crate::relay`], and retina reads at
//! most [`MAX_MESSAGE`] bytes of each RTSP message. The camera host is
//! never resolved here: the source connects to the first address the
//! supervisor resolved.

use std::convert::Infallible;
use std::future::Future;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{FutureExt as _, StreamExt as _};
use lotse_codec::aac::AacDepacketizer;
use lotse_codec::h264::{
    DEFAULT_MAX_PAYLOAD, Depacketizer, FrameOverLimit, LIBWEBRTC_MAX_FRAME_PACKETS,
    NormalizedPacket, PacketNormalizer, ParameterSets,
};
use lotse_codec::h265;
use lotse_core::codec::{Codec, Kind};
use lotse_core::discontinuity::TimestampGuard;
use lotse_core::ingest::IngestCounters;
use lotse_core::media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields, TimestampUnwrapper};
use lotse_core::source::{
    ClockReport, KeyframeRequest, Source, SourceCtx, SourceDescriptor, SourceError, SourceExit,
    SyncHint,
};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::BoxFuture;
use lotse_core::throttle::Throttle;
use lotse_core::track::Track;
use retina::client::{
    Credentials, InitialSequenceNumberPolicy, InitialTimestampPolicy, PacketItem, PlayOptions,
    Session, SessionGroup, SessionOptions, SetupOptions, Stream, TcpTransportOptions,
    TeardownPolicy, Transport,
};
use retina::codec::{ParametersRef, VideoParametersCodec};

use crate::error::{camera_text, classify};
use crate::factory::PROTOCOL;
use crate::framer::MAX_MESSAGE;
use crate::options::{RtspOptions, Transport as MediaTransport};
use crate::relay;
use crate::relay::{First, Media};
use crate::rtcp::{ReceiverReports, Seed, SetupRates};
use crate::tls::{self, TlsTarget};
use crate::udp::UdpRelay;
use tokio::io::{AsyncRead, AsyncWrite};

/// How long the teardown may take once the connection is cancelled.
const TEARDOWN_BUDGET: Duration = Duration::from_millis(100);

/// One validated `rtsp://` or `rtsps://` source.
#[derive(Debug)]
pub struct RtspSource {
    /// The URL, credentials inside.
    url: SourceUrl,
    /// The options.
    options: RtspOptions,
    /// For `rtsps`: the server name and the certificate check.
    tls: Option<TlsTarget>,
    /// The worker's pre-bound relay listener, if it has one.
    relay: Option<Arc<TcpListener>>,
}

impl RtspSource {
    /// A source for `url` with `options`; `tls` is set exactly for `rtsps`.
    pub(crate) const fn new(
        url: SourceUrl,
        options: RtspOptions,
        tls: Option<TlsTarget>,
        relay: Option<Arc<TcpListener>>,
    ) -> Self {
        Self {
            url,
            options,
            tls,
            relay,
        }
    }
}

impl Source for RtspSource {
    fn describe(&self) -> SourceDescriptor {
        SourceDescriptor {
            protocol: PROTOCOL,
            url: self.url.clone(),
            options: self.options.redacted(),
        }
    }

    fn connection_options(&self) -> serde_json::Value {
        self.options.connection_key()
    }

    fn run(&self, ctx: SourceCtx) -> BoxFuture<'static, SourceExit> {
        let url = self.url.clone();
        let options = self.options.clone();
        let tls = self.tls.clone();
        let relay = self.relay.clone();
        Box::pin(async move {
            let Some(addr) = ctx.peer.addrs.first().copied() else {
                return SourceExit::Ended(SourceError::Unreachable(format!(
                    "rtsp: no address resolved for {}",
                    ctx.peer.host
                )));
            };
            // `rtsps` with UDP is refused at validation: plain datagrams
            // would carry what the TLS session protects.
            // The relay reports to the camera (RFC 3550 §6.4.2), with the
            // clock rates `connect` hands over in `SETUP` order.
            let rates = Arc::new(SetupRates::default());
            let reports = ReceiverReports::new(Arc::clone(&rates), Seed::random());
            let media = if options.transport == MediaTransport::Udp {
                // `addr` is the endpoint the relay connects to, the media's
                // sender unless an answer names a `source` (RFC 2326
                // §12.39), never the relay's own loopback side.
                Media::Udp(Box::new(UdpRelay::new(
                    addr.ip(),
                    ctx.tracks.ingest(),
                    Arc::clone(&ctx.time),
                    reports,
                )))
            } else {
                Media::Interleaved(reports, Arc::clone(&ctx.time))
            };
            let attempt = Attempt {
                url,
                options,
                relay,
                media,
                rates,
                ctx,
            };
            match tls {
                None => {
                    tracing::info!(host = %attempt.ctx.peer.host, %addr, "rtsp: connecting");
                    // The relay's state makes the attempt large: on the heap.
                    Box::pin(attempt.run("TCP connect", || relay::tcp(addr))).await
                }
                Some(tls) => {
                    tracing::info!(host = %attempt.ctx.peer.host, %addr, "rtsps: connecting");
                    // The TLS stream makes the attempt large: on the heap.
                    let handshake = || {
                        let tls = tls.clone();
                        async move { tls::connect(addr, &tls).await }
                    };
                    Box::pin(attempt.run("TLS handshake", handshake)).await
                }
            }
        })
    }

    fn request_keyframe(&self) -> KeyframeRequest {
        KeyframeRequest::Unsupported
    }
}

/// The credentials retina sends, from the URL's userinfo.
fn credentials(url: &SourceUrl) -> Option<Credentials> {
    url.credentials().map(|c| Credentials {
        username: c.username().to_owned(),
        password: c
            .password()
            .map(|p| p.expose_secret().clone())
            .unwrap_or_default(),
    })
}

/// The raw 32-bit RTP timestamp of a packet, as the header carried it.
fn raw_timestamp(ts: retina::Timestamp) -> u32 {
    u32::try_from(ts.timestamp().rem_euclid(1_i64 << 32)).unwrap_or(0)
}

/// What the SDP said about one stream, as core wants it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declared {
    /// Video or audio.
    pub(crate) kind: Kind,
    /// The codec.
    pub(crate) codec: Codec,
    /// Ticks per second.
    pub(crate) clock_rate: u32,
    /// The parameter sets the SDP announced, if any.
    pub(crate) sets: Sprop,
}

/// The parameter sets a video stream's SDP announced: RFC 6184 §8.1
/// `sprop-parameter-sets`, or RFC 7798 §7.1 `sprop-vps`, `sprop-sps` and
/// `sprop-pps`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum Sprop {
    /// None, or not a codec that has them.
    #[default]
    None,
    /// H.264's SPS and PPS.
    H264(ParameterSets),
    /// H.265's VPS, SPS and PPS.
    H265(h265::ParameterSets),
}

/// Maps an SDP media description onto a codec.
pub(crate) fn declare(
    media: &str,
    encoding: &str,
    clock_rate: u32,
    channels: Option<u16>,
    sets: Sprop,
    extra_data: &[u8],
) -> Option<Declared> {
    let encoding_lower = encoding.to_ascii_lowercase();
    let (kind, codec, sets) = match (media, encoding_lower.as_str()) {
        ("video", "h264") => {
            let sets = match sets {
                Sprop::H264(sets) => sets,
                _ => ParameterSets::default(),
            };
            let profile_level_id = sets
                .sps
                .as_deref()
                .and_then(|sps| lotse_codec::h264::parse_sps(sps).ok())
                .map(|info| info.profile_level_id);
            let codec = Codec::H264 {
                profile_level_id,
                sps: sets.sps.clone(),
                pps: sets.pps.clone(),
            };
            (Kind::Video, codec, Sprop::H264(sets))
        }
        ("video", "h265") => {
            let sets = match sets {
                Sprop::H265(sets) => sets,
                _ => h265::ParameterSets::default(),
            };
            let codec = Codec::H265 {
                vps: sets.vps.clone(),
                sps: sets.sps.clone(),
                pps: sets.pps.clone(),
            };
            (Kind::Video, codec, Sprop::H265(sets))
        }
        ("video", "jpeg") => (Kind::Video, Codec::Mjpeg, Sprop::None),
        ("video", _) => (
            Kind::Video,
            Codec::Unsupported {
                kind: Kind::Video,
                name: camera_text(&encoding_lower),
            },
            Sprop::None,
        ),
        ("audio", "pcmu") => (Kind::Audio, Codec::Pcmu, Sprop::None),
        ("audio", "pcma") => (Kind::Audio, Codec::Pcma, Sprop::None),
        ("audio", "g722") => (Kind::Audio, Codec::G722, Sprop::None),
        ("audio", "opus") => (
            Kind::Audio,
            Codec::Opus {
                channels: u8::try_from(channels.unwrap_or(2)).unwrap_or(2),
            },
            Sprop::None,
        ),
        // retina reads the config only for AAC-hbr with the RTP clock at
        // the sampling rate, so one tick is one sample; without a config
        // (HE-AAC, another mode) there is nothing to decode.
        ("audio", "mpeg4-generic") => match lotse_codec::aac::parse_config(extra_data) {
            Ok(config) => (
                Kind::Audio,
                Codec::AacLc {
                    sample_rate: config.sample_rate,
                    channels: config.channels,
                    config: Bytes::copy_from_slice(extra_data),
                },
                Sprop::None,
            ),
            Err(err) => {
                tracing::warn!(error = %err, channels, "rtsp: AAC stream the transcoder cannot decode");
                (
                    Kind::Audio,
                    Codec::Unsupported {
                        kind: Kind::Audio,
                        name: err.codec_name().to_owned(),
                    },
                    Sprop::None,
                )
            }
        },
        ("audio", _) => (
            Kind::Audio,
            Codec::Unsupported {
                kind: Kind::Audio,
                name: camera_text(&encoding_lower),
            },
            Sprop::None,
        ),
        _ => return None,
    };
    Some(Declared {
        kind,
        codec,
        clock_rate,
        sets,
    })
}

/// The parameter sets and extra data retina parsed out of the SDP.
fn parameters(stream: &Stream) -> (Sprop, Vec<u8>) {
    let mut sets = Sprop::None;
    let mut extra = Vec::new();
    match stream.parameters() {
        Some(ParametersRef::Video(video)) => sets = video_sets(video.codec_params()),
        Some(ParametersRef::Audio(audio)) => extra.extend_from_slice(audio.extra_data()),
        Some(ParametersRef::Message(_)) | None => {}
    }
    (sets, extra)
}

/// The parameter sets retina read from a video stream's `fmtp`.
fn video_sets(codec: &VideoParametersCodec) -> Sprop {
    match codec {
        VideoParametersCodec::H264 { sps, pps } => {
            let mut sets = ParameterSets::default();
            sets.observe(sps);
            sets.observe(pps);
            Sprop::H264(sets)
        }
        VideoParametersCodec::H265 { vps, sps, pps } => {
            let mut sets = h265::ParameterSets::default();
            for set in [vps, sps, pps] {
                sets.observe(set);
            }
            Sprop::H265(sets)
        }
        // JPEG, and what retina may add.
        _ => Sprop::None,
    }
}

/// The name an H.265 stream whose payloads carry decoding order numbers
/// is declared [`Codec::Unsupported`] with.
const H265_DON: &str = "h265_don";

/// `declared`, or [`Codec::Unsupported`] named [`H265_DON`] when it is
/// H.265 and `sdp` makes its payloads carry decoding order numbers (DONL,
/// DOND; RFC 7798 §4.4.1), or leaves that unknown with a malformed
/// `sprop-max-don-diff` (§7.1). The `lotse-codec` normalizers read
/// payloads without them and would take a DONL for a size or unit bytes;
/// RFC 7798 §7.2.3 has an RTSP receiver that does not support a
/// parameter's value reject the session, and as unsupported the stream
/// is reported and never negotiated, as any other codec lotse cannot carry.
fn refuse_decoding_order(declared: Declared, sdp: &[u8]) -> Declared {
    if !matches!(declared.codec, Codec::H265 { .. }) {
        return declared;
    }
    let reason = match crate::fmtp::h265_max_don_diff(sdp) {
        Ok(0) => return declared,
        Ok(diff) => format!(
            "sprop-max-don-diff is {diff}, so its payloads carry DONL fields (RFC 7798 §4.4.1)"
        ),
        Err(crate::fmtp::MalformedDonDiff) => {
            "sprop-max-don-diff is not an integer from 0 to 32767 (RFC 7798 §7.1)".to_owned()
        }
    };
    tracing::warn!(
        reason = %reason,
        codec = H265_DON,
        "rtsp: H.265 stream with decoding order numbers, which lotse does not read; declared unsupported (RFC 7798 §7.2.3)"
    );
    Declared {
        codec: Codec::Unsupported {
            kind: Kind::Video,
            name: H265_DON.to_owned(),
        },
        sets: Sprop::None,
        ..declared
    }
}

/// Picks the first video and the first audio stream of the SDP; `sdp` is
/// the description retina parsed the streams from, read for what retina
/// does not expose.
fn select(streams: &[Stream], sdp: &[u8]) -> Vec<(usize, Declared)> {
    let mut chosen: Vec<(usize, Declared)> = Vec::new();
    for (index, stream) in streams.iter().enumerate() {
        let (sets, extra) = parameters(stream);
        let Some(declared) = declare(
            stream.media(),
            stream.encoding_name(),
            stream.clock_rate_hz(),
            stream.channels().map(std::num::NonZeroU16::get),
            sets,
            &extra,
        ) else {
            continue;
        };
        let declared = refuse_decoding_order(declared, sdp);
        if chosen.iter().any(|(_, d)| d.kind == declared.kind) {
            continue;
        }
        chosen.push((index, declared));
    }
    chosen
}

/// The two normalization layers of a video stream, with the side branch's
/// reused buffer of finished access units and what the stream's SPS says.
///
/// The track's codec follows an in-band SPS only when what it says
/// changes, and keeps the parameter sets of that change: a camera can send
/// a byte-different SPS with every frame, and each codec change is a
/// control event every session handles. What a session checks against
/// its payload type is what the SPS says, never its bytes.
enum Video {
    /// H.264 (RFC 6184).
    H264 {
        /// The live-path normalizer.
        normalizer: PacketNormalizer,
        /// The side-branch depacketizer.
        depacketizer: Depacketizer,
        /// Its finished units.
        units: Vec<lotse_codec::h264::AccessUnit>,
        /// What the SPS the track's codec was last set from says.
        sps: Option<lotse_codec::h264::SpsInfo>,
    },
    /// H.265 (RFC 7798).
    H265 {
        /// The live-path normalizer.
        normalizer: h265::PacketNormalizer,
        /// The side-branch depacketizer.
        depacketizer: h265::Depacketizer,
        /// Its finished units.
        units: Vec<h265::AccessUnit>,
        /// What the SPS the track's codec was last set from says.
        sps: Option<h265::SpsInfo>,
    },
}

impl Video {
    /// The layers for a declared stream, seeded with the SDP's sets; `None`
    /// for codecs without them.
    fn new(declared: &Declared, max_frame_bytes: usize) -> Option<Self> {
        match (&declared.codec, &declared.sets) {
            (Codec::H264 { .. }, Sprop::H264(sets)) => Some(Self::H264 {
                normalizer: PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, sets.clone()),
                depacketizer: Depacketizer::new(max_frame_bytes, sets.clone()),
                units: Vec::new(),
                sps: sets
                    .sps
                    .as_deref()
                    .and_then(|sps| lotse_codec::h264::parse_sps(sps).ok()),
            }),
            (Codec::H265 { .. }, Sprop::H265(sets)) => Some(Self::H265 {
                normalizer: h265::PacketNormalizer::new(DEFAULT_MAX_PAYLOAD, sets.clone()),
                depacketizer: h265::Depacketizer::new(max_frame_bytes, sets.clone()),
                units: Vec::new(),
                sps: sets
                    .sps
                    .as_deref()
                    .and_then(|sps| h265::parse_sps(sps).ok()),
            }),
            _ => None,
        }
    }
}

/// A stream the connection carries.
struct Carried {
    /// Its track.
    track: Arc<Track>,
    /// Its payload type in the SDP.
    pt: u8,
    /// The normalization layers, for H.264 and H.265.
    video: Option<Video>,
    /// The side-branch depacketizer, for AAC-LC.
    aac: Option<AacDepacketizer>,
    /// Cut-through audio codecs: every packet is a frame too.
    packet_frames: bool,
    /// Unwraps timestamps for the side branch.
    unwrapper: TimestampUnwrapper,
    /// The last timestamp, for frame boundaries of raw video.
    last_ts: Option<u32>,
    /// Watches the timestamps for a new timeline.
    guard: TimestampGuard,
    /// Payloads that violated the packetization, for one warning.
    violations: u64,
    /// The rate limit of the `frame_over_browser_limit` warning.
    over_limit: Throttle,
}

impl Carried {
    /// The state for a declared stream on `track`.
    fn new(track: Arc<Track>, pt: u8, declared: &Declared) -> Self {
        Self {
            pt,
            video: Video::new(declared, track.limits().max_frame_bytes),
            aac: matches!(declared.codec, Codec::AacLc { .. })
                .then(|| AacDepacketizer::new(track.limits().max_frame_bytes)),
            packet_frames: matches!(
                declared.codec,
                Codec::Pcmu | Codec::Pcma | Codec::G722 | Codec::Opus { .. }
            ),
            unwrapper: TimestampUnwrapper::new(),
            last_ts: None,
            guard: TimestampGuard::new(declared.clock_rate),
            violations: 0,
            over_limit: Throttle::default(),
            track,
        }
    }
}

/// Runs one RTSP request under the read deadline and cancellation; a
/// retina error is classified.
async fn bounded<T>(
    ctx: &SourceCtx,
    deadline: Duration,
    what: &str,
    future: impl Future<Output = Result<T, retina::Error>>,
) -> Result<T, SourceError> {
    within(ctx, deadline, what, async {
        future.await.map_err(|err| classify(&err))
    })
    .await
}

/// Runs `future` under the read deadline and cancellation.
async fn within<T>(
    ctx: &SourceCtx,
    deadline: Duration,
    what: &str,
    future: impl Future<Output = Result<T, SourceError>>,
) -> Result<T, SourceError> {
    tokio::select! {
        result = future => result,
        () = ctx.time.sleep(deadline) => Err(SourceError::Timeout(format!(
            "{what}: no answer within {} ms",
            deadline.as_millis()
        ))),
        () = ctx.cancel.cancelled() => Err(SourceError::Ended("cancelled".into())),
    }
}

/// A playing session with the streams it carries.
struct Connected {
    /// The session, a stream of packets.
    playing: Session<retina::client::Playing>,
    /// What each retina stream index maps to, if carried.
    carried: Vec<Option<Carried>>,
}

/// DESCRIBE, SETUP of the chosen streams, the track declarations and PLAY,
/// with retina connecting to `target`, the relay. A session that ends
/// here, after a `SETUP`, joins `group` for its `TEARDOWN`.
async fn connect(
    target: url::Url,
    url: &SourceUrl,
    options: &RtspOptions,
    ctx: &mut SourceCtx,
    group: &Arc<SessionGroup>,
    rates: &SetupRates,
) -> Result<Connected, SourceError> {
    let deadline = Duration::from_millis(options.timeout_ms);
    // retina talks TCP to the relay, so `Auto` tries one `TEARDOWN` on
    // that connection, which the relay carries to the camera; over UDP the
    // relay sends it on a fresh one once the camera's is gone.
    let session_options = SessionOptions::default()
        .creds(credentials(url))
        .user_agent(options.user_agent().to_owned())
        .teardown(TeardownPolicy::Auto)
        .max_message_size(MAX_MESSAGE)
        .session_group(Arc::clone(group));
    tracing::info!(host = %ctx.peer.host, addrs = ?ctx.peer.addrs, "rtsp: describing");
    let mut session = bounded(
        ctx,
        deadline,
        "DESCRIBE",
        Session::describe(target, session_options),
    )
    .await?;
    let chosen = select(session.streams(), session.sdp());
    if chosen.is_empty() {
        return Err(SourceError::Protocol(
            "the SDP describes no video or audio stream".into(),
        ));
    }
    for (index, declared) in &chosen {
        tracing::info!(index, kind = %declared.kind, codec = declared.codec.name(), clock_rate = declared.clock_rate, "rtsp: setting up");
        // The relay takes it at this stream's `SETUP` answer, which
        // retina waits for before the next `SETUP`.
        rates.push(declared.clock_rate);
        // Over UDP too: retina speaks TCP interleaved to the relay, which
        // asks the camera for UDP ([`crate::udp`]).
        let setup = session.setup(
            *index,
            SetupOptions::default().transport(Transport::Tcp(TcpTransportOptions::default())),
        );
        let udp = options.transport == MediaTransport::Udp;
        within(ctx, deadline, "SETUP", async {
            setup.await.map_err(|err| setup_error(&err, udp))
        })
        .await?;
    }
    let mut carried: Vec<Option<Carried>> = (0..session.streams().len()).map(|_| None).collect();
    for (index, declared) in &chosen {
        let track = ctx
            .tracks
            .declare(declared.kind, declared.codec.clone(), declared.clock_rate);
        let pt = session
            .streams()
            .get(*index)
            .map_or(0, Stream::rtp_payload_type);
        if let Some(slot) = carried.get_mut(*index) {
            *slot = Some(Carried::new(track, pt, declared));
        }
    }
    // Timestamps are not enforced by retina, which would end the session
    // on any backward step (B-frames included): core's guard turns a real
    // jump into an epoch instead. `rtptime` in `RTP-Info` (RFC 2326
    // §12.33, RFC 7826 §18.45) maps RTP time to normal play time, which
    // only retina's NPT uses; lotse reads the raw RTP timestamps and maps
    // them to the wall clock from Sender Reports (RFC 3550 §6.4.1), else
    // by arrival. So it is ignored: retina's default refuses a `PLAY`
    // answer without it for more than one stream, as MediaMTX 1.21.1
    // gives a path's first reader (observed 2026-10-06).
    let play = session.play(
        PlayOptions::default()
            .initial_seq(InitialSequenceNumberPolicy::IgnoreSuspiciousValues)
            .initial_timestamp(InitialTimestampPolicy::Ignore),
    );
    let playing = bounded(ctx, deadline, "PLAY", play).await?;
    Ok(Connected { playing, carried })
}

/// RFC 2326 §11.3.11: `461 Unsupported Transport`.
const UNSUPPORTED_TRANSPORT: u16 = 461;

/// A failed `SETUP` as a source error: a camera that refuses RTP over UDP
/// says how to repair it; nothing falls back to TCP on its own, because
/// the transport is part of the stream's options and its connection key.
fn setup_error(error: &retina::Error, udp: bool) -> SourceError {
    match classify(error) {
        SourceError::Protocol(message)
            if udp && error.status_code() == Some(UNSUPPORTED_TRANSPORT) =>
        {
            tracing::warn!(error = %message, "rtsp: the camera refuses RTP over UDP");
            SourceError::Protocol(format!(
                "{message}: the camera refuses RTP over UDP (461 Unsupported Transport, RFC 2326 §11.3.11); set the stream's transport to tcp"
            ))
        }
        other => other,
    }
}

/// No RTP datagram reached retina within the read deadline after `PLAY`:
/// the camera's media does not reach the daemon over UDP.
fn no_udp_media(deadline: Duration, rejected: u64) -> SourceError {
    tracing::warn!(
        deadline_ms = deadline.as_millis(),
        rejected,
        "rtsp: no RTP over UDP after PLAY"
    );
    SourceError::Timeout(format!(
        "no RTP datagram from the camera within {} ms of PLAY ({rejected} datagrams refused): a firewall or NAT between the camera and the daemon may drop them; set the stream's transport to tcp",
        deadline.as_millis()
    ))
}

/// One connection attempt before it reaches the camera.
struct Attempt {
    /// The source URL.
    url: SourceUrl,
    /// The options.
    options: RtspOptions,
    /// The worker's pre-bound relay listener, if it has one.
    relay: Option<Arc<TcpListener>>,
    /// How the media takes through the relay: interleaved, or its UDP
    /// side with `transport: "udp"`.
    media: Media,
    /// The clock rates `connect` hands the relay's receiver reports.
    rates: Arc<SetupRates>,
    /// The source's context.
    ctx: SourceCtx,
}

impl Attempt {
    /// Connects to the camera with `connect` (TCP, or TCP and the TLS
    /// handshake) under the read deadline, then runs the RTSP session
    /// through the loopback relay, which lives exactly as long as the
    /// session and its teardown. The relay refusing what a side sent ends
    /// the attempt with its error; over UDP so does the camera's
    /// connection going away, and the session, cancelled, still sends its
    /// `TEARDOWN`, which the relay carries on a fresh connection from
    /// `connect`. Otherwise the session decides the exit.
    async fn run<S, F>(self, what: &str, connect: impl Fn() -> F + Send + Sync) -> SourceExit
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        F: Future<Output = Result<S, SourceError>> + Send,
    {
        let Self {
            url,
            options,
            relay,
            media,
            rates,
            mut ctx,
        } = self;
        let deadline = Duration::from_millis(options.timeout_ms);
        let opened = within(&ctx, deadline, what, async {
            let camera = connect().await?;
            let listener = relay::listen(relay.as_deref()).await?;
            Ok((camera, listener))
        })
        .await;
        let (camera, (listener, local)) = match opened {
            Ok(opened) => opened,
            Err(err) => return SourceExit::Ended(err),
        };
        let target = relay::relay_url(&url, local);
        // The session's own stop, for a relay that ends it first.
        let stop = ctx.cancel.child_token();
        ctx.cancel = stop.clone();
        let session = run(target, url, options, ctx, rates);
        tokio::pin!(session);
        // The relay runs through the teardown; once the copy is over it
        // stays pending while retina's next read sees the closed
        // connection. A refusal is the exit: the session cannot see the
        // connection the refusal closes before the relay's end is seen.
        let pump = relay::pump(listener, camera, media);
        let ended = match relay::beside(pump, &mut session).await {
            First::Relay(ended) => ended,
            First::Session(exit) => return exit,
        };
        let Some(orphan) = ended.orphan else {
            return SourceExit::Ended(ended.error);
        };
        stop.cancel();
        // Carried until the session's teardown is over: done or not, the
        // relay's side is pending from then on.
        let forward =
            relay::teardown(orphan, &connect).then(|()| std::future::pending::<Infallible>());
        tokio::select! {
            biased;
            never = forward => match never {},
            _torn_down = session => {}
        }
        SourceExit::Ended(ended.error)
    }
}

/// One connection attempt: connect, go live, pump packets until the
/// camera or core ends it, then tear down within the budget, however it
/// ended: a session the camera set up gets its `TEARDOWN` (RFC 2326
/// §10.7, RFC 7826 §13.7) after a failed or cancelled `SETUP` or `PLAY`
/// too.
async fn run(
    target: url::Url,
    url: SourceUrl,
    options: RtspOptions,
    mut ctx: SourceCtx,
    rates: Arc<SetupRates>,
) -> SourceExit {
    let group = Arc::new(SessionGroup::default());
    let exit = match connect(target, &url, &options, &mut ctx, &group, &rates).await {
        Ok(connected) => play(connected, &options, &ctx).await,
        Err(err) => err,
    };
    tear_down(&group, &ctx, &exit).await;
    SourceExit::Ended(exit)
}

/// Waits, at most [`TEARDOWN_BUDGET`], for the `TEARDOWN` of every session
/// in `group`, which retina sends when a session is dropped; nothing when
/// the camera set none up.
async fn tear_down(group: &SessionGroup, ctx: &SourceCtx, exit: &SourceError) {
    tokio::select! {
        result = group.await_teardown() => tracing::debug!(?result, %exit, "rtsp: teardown over"),
        () = ctx.time.sleep(TEARDOWN_BUDGET) => {
            tracing::debug!(%exit, "rtsp: teardown still pending after the budget");
        }
    }
}

/// Plays a connected session until the camera or core ends it: why it
/// ended, with the session dropped, which starts its `TEARDOWN`.
async fn play(mut connected: Connected, options: &RtspOptions, ctx: &SourceCtx) -> SourceError {
    // Over TCP the session is live once PLAY is answered. Over UDP it is
    // live once the first RTP datagram arrived: a camera whose datagrams
    // never reach the daemon ends the attempt with why, not a stall.
    let deadline = Duration::from_millis(options.timeout_ms);
    let mut live = options.transport == MediaTransport::Tcp;
    if live {
        ctx.tracks.ready();
        tracing::info!("rtsp: playing");
    }
    let mut first_media = ctx.time.sleep(deadline);
    let ingest = ctx.tracks.ingest();
    let mut loss_log = Throttle::default();
    let mut normalized = Vec::new();
    let exit = loop {
        let item = tokio::select! {
            item = connected.playing.next() => item,
            () = &mut first_media, if !live => break no_udp_media(deadline, ingest.snapshot().datagrams_rejected),
            () = ctx.cancel.cancelled() => break SourceError::Ended("cancelled".into()),
        };
        match item {
            None => break SourceError::Ended("the camera closed the session".into()),
            Some(Err(err)) => break classify(&err),
            Some(Ok(PacketItem::Rtp(packet))) => {
                if !live {
                    live = true;
                    ctx.tracks.ready();
                    tracing::info!("rtsp: playing; RTP arrives over UDP");
                }
                let arrival = ctx.time.now();
                count_loss(&ingest, &mut loss_log, packet.loss(), arrival);
                let index = packet.stream_id();
                let ts = raw_timestamp(packet.timestamp());
                let jumped = connected
                    .carried
                    .get_mut(index)
                    .and_then(Option::as_mut)
                    .and_then(|entry| entry.guard.observe(ts, arrival));
                if let Some(moved_ms) = jumped {
                    new_timeline(&mut connected.carried, index, ctx, moved_ms);
                }
                if let Some(Some(entry)) = connected.carried.get_mut(index) {
                    on_rtp(entry, ctx, arrival, packet, &mut normalized);
                }
            }
            Some(Ok(PacketItem::Rtcp(compound))) => {
                let arrival = ctx.time.now();
                if let Some(Some(entry)) = connected.carried.get(compound.stream_id()) {
                    on_rtcp(entry, ctx, arrival, &compound);
                }
            }
            // retina may add item kinds; none of them carries media.
            Some(Ok(_)) => {}
        }
    };
    drop(connected);
    exit
}

/// Counts the `lost` packets an RTP packet's sequence number says are
/// missing before it (RFC 3550 §6.4.1), with a rate-limited line.
fn count_loss(ingest: &IngestCounters, log: &mut Throttle, lost: u16, arrival: Instant) {
    if lost == 0 {
        return;
    }
    ingest.count_lost(u64::from(lost));
    if let Some(count) = log.hit(arrival) {
        tracing::debug!(lost, count, "rtsp: RTP sequence gap; packets lost");
    }
}

/// The camera's timestamps left their timeline on stream `index`: one new
/// epoch for every track, the clock mapping forgotten, and every stream's
/// timestamp state restarted so the other tracks' own jumps are part of
/// the same epoch.
fn new_timeline(carried: &mut [Option<Carried>], index: usize, ctx: &SourceCtx, moved_ms: i64) {
    for (i, entry) in carried.iter_mut().enumerate() {
        let Some(entry) = entry.as_mut() else {
            continue;
        };
        if i == index {
            tracing::info!(track = %entry.track.id(), moved_ms, "rtsp: timestamps jumped; new epoch");
        } else {
            entry.guard.rebase();
        }
        entry.unwrapper = TimestampUnwrapper::new();
        entry.last_ts = None;
    }
    ctx.tracks.discontinuity();
    ctx.clock.reset();
}

/// Publishes the live path's packets of one source packet on `track`.
fn publish_normalized(
    track: &Track,
    arrival: Instant,
    rtp: RtpHeaderFields,
    normalized: &mut Vec<NormalizedPacket>,
) {
    for out in normalized.drain(..) {
        track.publish_packet(MediaPacket {
            arrival,
            rtp: RtpHeaderFields {
                marker: out.marker,
                ..rtp
            },
            frame_start: out.frame_start,
            keyframe_start: out.keyframe_start,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(out.payload.as_ref()),
        });
    }
}

/// Publishes one finished access unit of the side branch on `track`:
/// its timestamp, whether it is a keyframe, its Annex B bytes.
fn publish_unit(
    track: &Track,
    unwrapper: &mut TimestampUnwrapper,
    ctx: &SourceCtx,
    arrival: Instant,
    (ts, keyframe, payload): (u32, bool, Bytes),
) {
    let ticks = unwrapper.unwrap(ts);
    track.publish_frame(MediaFrame {
        ts: MediaTime::from_ticks(ticks),
        wallclock: ctx.clock.map(track.id(), ts, arrival),
        arrival,
        keyframe,
        discontinuity: false,
        epoch: 0,
        payload,
    });
}

/// A packet the normalizer cannot read: dropped, warned about once per
/// connection.
fn violation(track: &Track, violations: &mut u64, err: &dyn std::fmt::Display) {
    *violations = violations.saturating_add(1);
    if *violations == 1 {
        tracing::warn!(track = %track.id(), error = %err, "rtsp: packetization violation; packet dropped");
    }
}

/// A frame the live path carried in more packets than some libwebrtc
/// receivers assemble ([`LIBWEBRTC_MAX_FRAME_PACKETS`]): counted on the
/// track, and warned about at most once per summary interval. Every
/// session sends it whole all the same.
fn frame_over_limit(
    track: &Track,
    throttle: &mut Throttle,
    arrival: Instant,
    frame: Option<FrameOverLimit>,
) {
    let Some(frame) = frame else { return };
    track.count_frame_over_browser_limit();
    if let Some(count) = throttle.hit(arrival) {
        tracing::warn!(
            track = %track.id(),
            code = "frame_over_browser_limit",
            codec = track.codec().name(),
            bytes = frame.bytes,
            packets = frame.packets,
            limit = LIBWEBRTC_MAX_FRAME_PACKETS,
            keyframe = frame.keyframe,
            count,
            advice = "lower the camera's bitrate or use its substream",
            "rtsp: frame over the packet limit of some libwebrtc receivers (by version); sent whole, those viewers may freeze until a keyframe that fits"
        );
    }
}

/// One video packet through both normalization layers: the live path's
/// packets, then the side branch's finished units, with the track's codec
/// updated when a unit brings a new SPS.
fn on_video(
    entry: &mut Carried,
    ctx: &SourceCtx,
    arrival: Instant,
    rtp: RtpHeaderFields,
    payload: &Bytes,
    normalized: &mut Vec<NormalizedPacket>,
) {
    let Carried {
        track,
        video,
        unwrapper,
        violations,
        over_limit,
        ..
    } = entry;
    let RtpHeaderFields {
        seq, ts, marker, ..
    } = rtp;
    let Some(video) = video else { return };
    normalized.clear();
    match video {
        Video::H264 {
            normalizer,
            depacketizer,
            units,
            sps,
        } => {
            if let Err(err) = normalizer.normalize(ts, marker, payload, normalized) {
                violation(track, violations, &err);
            }
            frame_over_limit(
                track,
                over_limit,
                arrival,
                normalizer.take_frame_over_limit(),
            );
            publish_normalized(track, arrival, rtp, normalized);
            units.clear();
            let _violation = depacketizer.push(seq, ts, marker, payload, units);
            for unit in units.drain(..) {
                if let Some(info) = unit.sps.filter(|info| *sps != Some(*info)) {
                    *sps = Some(info);
                    let sets = depacketizer.parameter_sets();
                    track.set_codec(Codec::H264 {
                        profile_level_id: Some(info.profile_level_id),
                        sps: sets.sps.clone(),
                        pps: sets.pps.clone(),
                    });
                }
                publish_unit(
                    track,
                    unwrapper,
                    ctx,
                    arrival,
                    (unit.ts, unit.keyframe, unit.payload),
                );
            }
        }
        Video::H265 {
            normalizer,
            depacketizer,
            units,
            sps,
        } => {
            if let Err(err) = normalizer.normalize(ts, marker, payload, normalized) {
                violation(track, violations, &err);
            }
            frame_over_limit(
                track,
                over_limit,
                arrival,
                normalizer.take_frame_over_limit(),
            );
            publish_normalized(track, arrival, rtp, normalized);
            units.clear();
            let _violation = depacketizer.push(seq, ts, marker, payload, units);
            for unit in units.drain(..) {
                if let Some(info) = unit.sps.filter(|info| *sps != Some(*info)) {
                    *sps = Some(info);
                    let sets = depacketizer.parameter_sets();
                    track.set_codec(Codec::H265 {
                        vps: sets.vps.clone(),
                        sps: sets.sps.clone(),
                        pps: sets.pps.clone(),
                    });
                }
                publish_unit(
                    track,
                    unwrapper,
                    ctx,
                    arrival,
                    (unit.ts, unit.keyframe, unit.payload),
                );
            }
        }
    }
}

/// One RTP packet: cut through, and depacketized on the side branch.
fn on_rtp(
    entry: &mut Carried,
    ctx: &SourceCtx,
    arrival: Instant,
    packet: retina::rtp::ReceivedPacket,
    normalized: &mut Vec<NormalizedPacket>,
) {
    let ts = raw_timestamp(packet.timestamp());
    let marker = packet.mark();
    let seq = packet.sequence_number();
    let ssrc = packet.ssrc();
    let payload = packet.into_payload_bytes();
    let rtp = RtpHeaderFields {
        pt: entry.pt,
        seq,
        ts,
        marker,
        ssrc,
    };
    if entry.video.is_some() {
        on_video(entry, ctx, arrival, rtp, &payload, normalized);
        return;
    }
    // Raw cut-through: audio, and video codecs without a normalizer yet.
    let frame_start = entry.track.kind() == Kind::Audio || entry.last_ts != Some(ts);
    entry.last_ts = Some(ts);
    entry.track.publish_packet(MediaPacket {
        arrival,
        rtp,
        frame_start,
        keyframe_start: false,
        epoch: 0,
        lateness: Duration::ZERO,
        payload: Arc::from(payload.as_ref()),
    });
    if let Some(aac) = entry.aac.as_mut() {
        let id = entry.track.id();
        let stamp = |ts| (ctx.clock.map(id, ts, arrival), arrival);
        publish_aac(
            aac,
            &entry.track,
            &mut entry.unwrapper,
            stamp,
            rtp,
            &payload,
        );
    }
    if entry.packet_frames {
        let ticks = entry.unwrapper.unwrap(ts);
        entry.track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(ticks),
            wallclock: ctx.clock.map(entry.track.id(), ts, arrival),
            arrival,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload,
        });
    }
}

/// One AAC packet on the side branch: its RFC 3640 units become frames
/// on `track`, each stamped by `stamp` from its RTP timestamp with its
/// capture time and its arrival. A violation is warned about once per
/// connection.
fn publish_aac(
    aac: &mut AacDepacketizer,
    track: &Track,
    unwrapper: &mut TimestampUnwrapper,
    stamp: impl Fn(u32) -> (Instant, Instant),
    rtp: RtpHeaderFields,
    payload: &[u8],
) {
    let mut frames = Vec::new();
    if let Err(err) = aac.push(rtp.seq, rtp.ts, rtp.marker, payload, &mut frames)
        && aac.stats().violations == 1
    {
        tracing::warn!(track = %track.id(), error = %err, "rtsp: AAC payload violates RFC 3640; packet dropped");
    }
    for frame in frames {
        let ticks = unwrapper.unwrap(frame.ts);
        let (wallclock, arrival) = stamp(frame.ts);
        track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(ticks),
            wallclock,
            arrival,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: frame.payload,
        });
    }
}

/// One RTCP compound packet: Sender Reports become sync hints.
fn on_rtcp(
    entry: &Carried,
    ctx: &SourceCtx,
    arrival: Instant,
    compound: &retina::rtcp::ReceivedCompoundPacket,
) {
    for packet in compound.pkts() {
        if let Ok(Some(report)) = packet.as_sender_report() {
            ctx.clock.report(ClockReport {
                track: entry.track.id(),
                clock_rate: entry.track.clock_rate(),
                hint: SyncHint::RtcpSenderReport {
                    ntp: report.ntp_timestamp().0,
                    rtp_ts: report.rtp_timestamp(),
                },
                arrival,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::source::ResolvedPeer;

    use super::*;

    #[test]
    fn credentials_come_from_the_userinfo() {
        let url = SourceUrl::parse("rtsp://admin:secret@camera.local/h264?x=1").unwrap();
        let creds = credentials(&url).unwrap();
        assert_eq!(
            (creds.username.as_str(), creds.password.as_str()),
            ("admin", "secret")
        );
        assert!(credentials(&SourceUrl::parse("rtsp://cam/").unwrap()).is_none());
        let only_user = SourceUrl::parse("rtsp://admin@cam/").unwrap();
        assert_eq!(credentials(&only_user).unwrap().password, "");
    }

    #[test]
    fn media_descriptions_map_onto_the_codec_matrix() {
        let none = Sprop::None;
        let video = declare("video", "H264", 90_000, None, none.clone(), &[]).unwrap();
        assert_eq!(video.kind, Kind::Video);
        assert!(matches!(
            video.codec,
            Codec::H264 {
                profile_level_id: None,
                ..
            }
        ));
        let mut sets = ParameterSets::default();
        sets.observe(&[0x67, 0x42, 0xc0, 0x28, 0xda, 0x02, 0x80, 0xf6, 0x40]);
        sets.observe(&[0x68, 0xce, 0x38, 0x80]);
        let video = declare(
            "video",
            "h264",
            90_000,
            None,
            Sprop::H264(sets.clone()),
            &[],
        )
        .unwrap();
        assert_eq!(video.sets, Sprop::H264(sets.clone()));
        let Codec::H264 {
            profile_level_id,
            sps,
            pps,
        } = video.codec
        else {
            panic!("h264");
        };
        assert_eq!(profile_level_id, Some([0x42, 0xc0, 0x28]));
        assert_eq!(sps, sets.sps);
        assert_eq!(pps, sets.pps);
        assert_eq!(
            declare("video", "JPEG", 90_000, None, none.clone(), &[])
                .unwrap()
                .codec,
            Codec::Mjpeg
        );
        assert_eq!(
            declare("video", "VP8", 90_000, None, none.clone(), &[])
                .unwrap()
                .codec
                .name(),
            "vp8"
        );
        for (encoding, expected) in [
            ("PCMU", Codec::Pcmu),
            ("pcma", Codec::Pcma),
            ("G722", Codec::G722),
        ] {
            let audio = declare("audio", encoding, 8_000, Some(1), none.clone(), &[]).unwrap();
            assert_eq!(
                (audio.kind, audio.codec, audio.clock_rate),
                (Kind::Audio, expected, 8_000)
            );
        }
        assert_eq!(
            declare("audio", "opus", 48_000, Some(2), none.clone(), &[])
                .unwrap()
                .codec,
            Codec::Opus { channels: 2 }
        );
        assert_eq!(
            declare("audio", "L16", 44_100, Some(2), none.clone(), &[])
                .unwrap()
                .codec
                .name(),
            "l16"
        );
        assert!(declare("application", "vnd.onvif.metadata", 90_000, None, none, &[]).is_none());
    }

    #[test]
    fn retinas_parameter_sets_become_the_sprop_of_their_codec() {
        let (sps, pps) = (
            Bytes::from_static(&[0x67, 1]),
            Bytes::from_static(&[0x68, 2]),
        );
        let Sprop::H264(sets) = video_sets(&VideoParametersCodec::H264 {
            sps: sps.clone(),
            pps: pps.clone(),
        }) else {
            panic!("h264");
        };
        assert_eq!((sets.sps, sets.pps), (Some(sps), Some(pps)));
        let vps = Bytes::from(h265::test_data::vps());
        let sps = Bytes::from(h265::test_data::sps(640, 480));
        let pps = Bytes::from(h265::test_data::pps());
        let Sprop::H265(sets) = video_sets(&VideoParametersCodec::H265 {
            vps: vps.clone(),
            sps: sps.clone(),
            pps: pps.clone(),
        }) else {
            panic!("h265");
        };
        assert_eq!(sets.units(), Some([&vps[..], &sps[..], &pps[..]]));
        assert_eq!(video_sets(&VideoParametersCodec::Jpeg), Sprop::None);
    }

    #[test]
    fn rfc7798_7_1_h265_is_declared_with_its_sprop_parameter_sets() {
        let h265 = declare("video", "H265", 90_000, None, Sprop::None, &[]).unwrap();
        assert_eq!(
            (h265.codec, h265.sets),
            (
                Codec::H265 {
                    vps: None,
                    sps: None,
                    pps: None
                },
                Sprop::H265(h265::ParameterSets::default())
            )
        );
        // RFC 7798 §7.1: the sets retina read from sprop-vps, -sps and -pps.
        let mut sets = h265::ParameterSets::default();
        for set in [
            h265::test_data::vps(),
            h265::test_data::sps(640, 480),
            h265::test_data::pps(),
        ] {
            sets.observe(&set);
        }
        let h265 = declare(
            "video",
            "h265",
            90_000,
            None,
            Sprop::H265(sets.clone()),
            &[],
        )
        .unwrap();
        assert_eq!(
            h265.codec,
            Codec::H265 {
                vps: sets.vps.clone(),
                sps: sets.sps.clone(),
                pps: sets.pps.clone()
            }
        );
        // Another codec's sets are not taken.
        let crossed = declare("video", "h264", 90_000, None, Sprop::H265(sets), &[]).unwrap();
        assert_eq!(crossed.sets, Sprop::H264(ParameterSets::default()));
        let crossed = declare(
            "video",
            "h265",
            90_000,
            None,
            Sprop::H264(ParameterSets::default()),
            &[],
        )
        .unwrap();
        assert_eq!(crossed.sets, Sprop::H265(h265::ParameterSets::default()));
    }

    /// An H.265 description whose `fmtp` ends in `extra`.
    fn h265_sdp(extra: &str) -> String {
        format!(
            "v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n\
             a=fmtp:96 profile-id=1{extra}\r\n"
        )
    }

    #[test]
    fn rfc7798_7_1_h265_without_decoding_order_numbers_is_kept() {
        let mut sets = h265::ParameterSets::default();
        sets.observe(&h265::test_data::vps());
        let declared = declare("video", "H265", 90_000, None, Sprop::H265(sets), &[]).unwrap();
        for extra in [
            "",
            ";sprop-max-don-diff=0",
            ";sprop-max-don-diff=0;sprop-depack-buf-nalus=0",
        ] {
            assert_eq!(
                refuse_decoding_order(declared.clone(), h265_sdp(extra).as_bytes()),
                declared,
                "{extra:?}"
            );
        }
    }

    #[test]
    fn rfc7798_7_2_3_h265_with_decoding_order_numbers_is_declared_unsupported() {
        let mut sets = h265::ParameterSets::default();
        sets.observe(&h265::test_data::vps());
        let declared = declare("video", "H265", 90_000, None, Sprop::H265(sets), &[]).unwrap();
        for extra in [
            ";sprop-max-don-diff=1;sprop-depack-buf-nalus=1",
            ";sprop-max-don-diff=32767;sprop-depack-buf-nalus=4",
            // Malformed (RFC 7798 §7.1): whether DONL is present is unknown.
            ";sprop-max-don-diff=abc",
            ";sprop-max-don-diff=32768",
            ";sprop-max-don-diff=",
        ] {
            assert_eq!(
                refuse_decoding_order(declared.clone(), h265_sdp(extra).as_bytes()),
                Declared {
                    kind: Kind::Video,
                    codec: Codec::Unsupported {
                        kind: Kind::Video,
                        name: "h265_don".into()
                    },
                    clock_rate: 90_000,
                    sets: Sprop::None,
                },
                "{extra:?}"
            );
        }
    }

    #[test]
    fn rfc7798_4_4_1_only_h265_streams_are_refused_for_decoding_order_numbers() {
        // H.264's own sprop-max-don-diff (RFC 6184 §8.1, interleaved mode)
        // is not this check's, and the H.265 one of another description
        // does not touch an H.264 or audio stream.
        let sdp = h265_sdp(";sprop-max-don-diff=2");
        for declared in [
            declare("video", "h264", 90_000, None, Sprop::None, &[]).unwrap(),
            declare("audio", "pcmu", 8_000, None, Sprop::None, &[]).unwrap(),
        ] {
            assert_eq!(
                refuse_decoding_order(declared.clone(), sdp.as_bytes()),
                declared
            );
        }
    }

    #[test]
    fn rfc3640_aac_is_declared_from_its_audio_specific_config() {
        let none = Sprop::None;
        assert_eq!(
            declare(
                "audio",
                "mpeg4-generic",
                16_000,
                Some(1),
                none.clone(),
                &[0x14, 0x08]
            )
            .unwrap()
            .codec,
            Codec::AacLc {
                sample_rate: 16_000,
                channels: 1,
                config: Bytes::from_static(&[0x14, 0x08])
            }
        );
        // Without a config retina could read, or with HE-AAC, AAC is
        // reported as what it is and never decoded.
        for (config, name) in [
            (&[][..], "aac"),
            (&[0x2b, 0x08][..], "aac_he"),
            (&[0x14, 0x30][..], "aac"),
        ] {
            assert_eq!(
                declare("audio", "MPEG4-GENERIC", 16_000, None, none.clone(), config)
                    .unwrap()
                    .codec,
                Codec::Unsupported {
                    kind: Kind::Audio,
                    name: name.into()
                }
            );
        }
    }

    #[test]
    fn rfc8866_6_6_an_unknown_encoding_s_name_is_reported_capped_on_one_line() {
        let long = format!("X\u{1b}{}", "Y".repeat(64 * 1024));
        for media in ["video", "audio"] {
            let declared = declare(media, &long, 90_000, None, Sprop::None, &[]).unwrap();
            let name = declared.codec.name();
            assert_eq!(name.len(), crate::error::CAMERA_TEXT_BYTES, "{media}");
            assert!(name.starts_with("x\u{fffd}yyy"), "{media}: {name}");
        }
    }

    #[test]
    fn raw_timestamps_are_the_low_32_bits() {
        let ts =
            retina::Timestamp::new(0x1_0000_0005, std::num::NonZeroU32::new(90_000).unwrap(), 0)
                .unwrap();
        assert_eq!(raw_timestamp(ts), 5);
        let ts = retina::Timestamp::new(0xffff_fff0, std::num::NonZeroU32::new(90_000).unwrap(), 0)
            .unwrap();
        assert_eq!(raw_timestamp(ts), 0xffff_fff0);
    }

    #[test]
    fn a_new_timeline_starts_one_epoch_and_restarts_every_streams_timestamps() {
        use lotse_core::clock::{Clock as _, SystemClock};
        use lotse_core::clock_map::{ClockMapper, SyncMode};
        use lotse_core::source::{BackchannelSlot, ClockInput, TrackSet};
        use lotse_core::track::TrackLimits;

        let t0 = SystemClock.now();
        let set = TrackSet::new(TrackLimits::default(), t0);
        let mapper = Arc::new(ClockMapper::new());
        let (clock, _reports) = ClockInput::channel(Arc::clone(&mapper));
        let mut ctx = SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock,
            time: Arc::new(SystemClock),
            backchannel: BackchannelSlot::default(),
            cancel: tokio_util::sync::CancellationToken::new(),
        };
        let video = declare("video", "h264", 90_000, None, Sprop::None, &[]).unwrap();
        let audio = declare("audio", "pcmu", 8_000, None, Sprop::None, &[]).unwrap();
        let v0 = ctx.tracks.declare(video.kind, video.codec.clone(), 90_000);
        let a0 = ctx.tracks.declare(audio.kind, audio.codec.clone(), 8_000);
        let mut carried = vec![
            Some(Carried::new(Arc::clone(&v0), 96, &video)),
            None,
            Some(Carried::new(Arc::clone(&a0), 0, &audio)),
        ];
        for entry in carried.iter_mut().flatten() {
            assert_eq!(entry.guard.observe(1_000, t0), None);
            entry.unwrapper.unwrap(1_000);
            entry.last_ts = Some(1_000);
        }
        mapper.ingest(ClockReport {
            track: v0.id(),
            clock_rate: 90_000,
            hint: SyncHint::RtcpSenderReport {
                ntp: 1 << 32,
                rtp_ts: 1_000,
            },
            arrival: t0,
        });
        assert_eq!(mapper.mode(v0.id()), SyncMode::SenderReports);

        // Video jumped: its guard already holds the new timestamp.
        assert!(
            carried[0]
                .as_mut()
                .unwrap()
                .guard
                .observe(5_000_000, t0)
                .is_some()
        );
        new_timeline(&mut carried, 0, &ctx, 55);
        assert_eq!((v0.epoch(), a0.epoch()), (1, 1), "one epoch for all tracks");
        assert_eq!(mapper.mode(v0.id()), SyncMode::Arrival);
        let [Some(v), None, Some(a)] = carried.as_mut_slice() else {
            panic!("the streams stay");
        };
        assert_eq!(
            v.guard.observe(5_003_000, t0),
            None,
            "video continues its new timeline"
        );
        // Audio takes whatever comes next as its base: its own jump is part
        // of the same epoch.
        assert_eq!(a.guard.observe(9_999_999, t0), None);
        for entry in [v, a] {
            assert_eq!(entry.unwrapper.last(), None);
            assert_eq!(entry.last_ts, None);
        }
    }

    /// A source context on a fresh track set, for the video path tests.
    fn video_ctx() -> (Instant, Arc<lotse_core::source::TrackSet>, SourceCtx) {
        use lotse_core::clock::{Clock as _, SystemClock};
        use lotse_core::clock_map::ClockMapper;
        use lotse_core::source::{BackchannelSlot, ClockInput, TrackSet};
        use lotse_core::track::TrackLimits;

        let t0 = SystemClock.now();
        let set = TrackSet::new(TrackLimits::default(), t0);
        let (clock, _reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let ctx = SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock,
            time: Arc::new(SystemClock),
            backchannel: BackchannelSlot::default(),
            cancel: tokio_util::sync::CancellationToken::new(),
        };
        (t0, set, ctx)
    }

    /// The RTP fields of a video packet that ends its access unit.
    const fn video_rtp(seq: u16, ts: u32) -> RtpHeaderFields {
        RtpHeaderFields {
            pt: 96,
            seq,
            ts,
            marker: true,
            ssrc: 1,
        }
    }

    #[test]
    fn rfc7798_a_unit_with_a_new_sps_updates_the_codec_and_violations_drop() {
        let (t0, _set, mut ctx) = video_ctx();
        // No sprop parameters: the codec learns the sets from the stream.
        let video = declare("video", "h265", 90_000, None, Sprop::None, &[]).unwrap();
        let v0 = ctx.tracks.declare(video.kind, video.codec.clone(), 90_000);
        let mut entry = Carried::new(Arc::clone(&v0), 96, &video);
        let mut packets = v0.subscribe_packets();
        let mut frames = v0.subscribe_frames();
        let mut normalized = Vec::new();
        let (vps, sps, pps) = (
            h265::test_data::vps(),
            h265::test_data::sps(640, 480),
            h265::test_data::pps(),
        );
        let idr = [h265::nal::IDR_W_RADL << 1, 0x01, 0xaa];
        let ap = h265::nal::aggregate(&[&vps, &sps, &pps, &idr]);
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(2, 3_000),
            &ap,
            &mut normalized,
        );
        assert_eq!(
            v0.codec().as_ref(),
            &Codec::H265 {
                vps: Some(Bytes::from(vps)),
                sps: Some(Bytes::from(sps)),
                pps: Some(Bytes::from(pps)),
            }
        );
        let packet = packets.try_recv().unwrap().unwrap();
        assert!(packet.keyframe_start && packet.rtp.marker);
        let frame = frames.try_recv().unwrap().unwrap();
        assert!(frame.keyframe);
        assert_eq!(frame.ts.ticks(), 3_000);
        // A unit over the datagram target is re-split: only the last
        // packet carries the marker (RFC 7798 §4.1).
        let big: Vec<u8> = [1 << 1, 0x01].into_iter().chain([0x5a; 2_000]).collect();
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(3, 4_000),
            &Bytes::from(big),
            &mut normalized,
        );
        let first = packets.try_recv().unwrap().unwrap();
        let second = packets.try_recv().unwrap().unwrap();
        assert!(!first.rtp.marker && second.rtp.marker);
        // PACI is not read: dropped, counted.
        let paci = Bytes::from_static(&[h265::nal::PACI << 1, 0x01]);
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(4, 6_000),
            &paci,
            &mut normalized,
        );
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(5, 9_000),
            &paci,
            &mut normalized,
        );
        assert_eq!(entry.violations, 2, "warned once, counted twice");
        assert!(packets.try_recv().unwrap().is_none());
    }

    /// The codec changes announced to `sub` so far.
    fn codec_changes(sub: &mut lotse_core::track::TrackSubscription) -> Vec<Codec> {
        let mut changes = Vec::new();
        while let Some(Some(event)) = sub.next().now_or_never() {
            if let lotse_core::track::TrackEvent::TrackChanged(codec) = event {
                changes.push(Codec::clone(&codec));
            }
        }
        changes
    }

    /// The H.264 descriptor of `sps` and `pps`.
    fn h264_codec(sps: &[u8], pps: &[u8]) -> Codec {
        Codec::H264 {
            profile_level_id: Some(lotse_codec::h264::parse_sps(sps).unwrap().profile_level_id),
            sps: Some(Bytes::copy_from_slice(sps)),
            pps: Some(Bytes::copy_from_slice(pps)),
        }
    }

    #[test]
    fn rfc6184_the_codec_follows_what_an_sps_says_not_its_bytes() {
        use lotse_codec::h264::test_data;

        let (t0, _set, mut ctx) = video_ctx();
        let mut normalized = Vec::new();
        let (vga, hd, pps) = (
            test_data::sps(640, 480),
            test_data::sps(1280, 720),
            test_data::pps(),
        );
        // `test_data::sps(640, 480)` with two reference frames: other
        // bytes, the same profile, level and size.
        let mut bits = test_data::Bits::default();
        bits.bits(66, 8)
            .bits(0xc0, 8)
            .bits(40, 8)
            .ue(0)
            .ue(0)
            .ue(2)
            .ue(2)
            .bit(false);
        bits.ue(39).ue(29).bit(true).bit(true).bit(false).bit(false);
        let vga_again = [vec![0x67], bits.finish()].concat();
        assert_ne!(vga_again, vga);
        assert_eq!(
            lotse_codec::h264::parse_sps(&vga_again),
            lotse_codec::h264::parse_sps(&vga)
        );
        // The SDP's sprop SPS already says what the stream's does.
        let sets = ParameterSets {
            sps: Some(Bytes::from(vga.clone())),
            pps: Some(Bytes::from(pps.clone())),
        };
        let video = declare("video", "h264", 90_000, None, Sprop::H264(sets), &[]).unwrap();
        let v0 = ctx.tracks.declare(video.kind, video.codec.clone(), 90_000);
        let mut entry = Carried::new(Arc::clone(&v0), 96, &video);
        let mut sub = v0.subscribe(lotse_core::track::Unit::Packets);
        let mut seq = 0;
        let mut send = |sps: &[u8]| {
            seq += 1;
            let stap = lotse_codec::h264::nal::stap_a(&[sps, &pps, &[0x65, 0xaa]]);
            let rtp = video_rtp(seq, u32::from(seq) * 3_000);
            on_video(&mut entry, &ctx, t0, rtp, &stap, &mut normalized);
        };
        for _ in 0..3 {
            send(&vga_again);
            send(&vga);
        }
        assert_eq!(codec_changes(&mut sub), []);
        assert_eq!(*v0.codec(), h264_codec(&vga, &pps));
        send(&hd);
        send(&vga_again);
        send(&vga);
        assert_eq!(
            codec_changes(&mut sub),
            [h264_codec(&hd, &pps), h264_codec(&vga_again, &pps)]
        );
    }

    #[test]
    fn rfc7798_the_codec_follows_what_an_sps_says_not_its_bytes() {
        let (t0, _set, mut ctx) = video_ctx();
        let mut normalized = Vec::new();
        let (vps, pps) = (h265::test_data::vps(), h265::test_data::pps());
        let (vga, hd) = (
            h265::test_data::sps(640, 480),
            h265::test_data::sps(1280, 720),
        );
        // Other bytes, the same SPS to the reader: a trailing zero byte.
        let vga_again = [vga.clone(), vec![0]].concat();
        assert_eq!(h265::parse_sps(&vga_again), h265::parse_sps(&vga));
        let sets = h265::ParameterSets {
            vps: Some(Bytes::from(vps.clone())),
            sps: Some(Bytes::from(vga.clone())),
            pps: Some(Bytes::from(pps.clone())),
        };
        let video = declare("video", "h265", 90_000, None, Sprop::H265(sets), &[]).unwrap();
        let v0 = ctx.tracks.declare(video.kind, video.codec.clone(), 90_000);
        let mut entry = Carried::new(Arc::clone(&v0), 96, &video);
        let mut sub = v0.subscribe(lotse_core::track::Unit::Packets);
        let idr = [h265::nal::IDR_W_RADL << 1, 0x01, 0xaa];
        let mut seq = 0;
        let mut send = |sps: &[u8]| {
            seq += 1;
            let ap = h265::nal::aggregate(&[&vps, sps, &pps, &idr]);
            let rtp = video_rtp(seq, u32::from(seq) * 3_000);
            on_video(&mut entry, &ctx, t0, rtp, &ap, &mut normalized);
        };
        send(&vga_again);
        send(&vga);
        assert_eq!(codec_changes(&mut sub), []);
        send(&hd);
        let h265 = |sps: &[u8]| Codec::H265 {
            vps: Some(Bytes::from(vps.clone())),
            sps: Some(Bytes::copy_from_slice(sps)),
            pps: Some(Bytes::from(pps.clone())),
        };
        assert_eq!(codec_changes(&mut sub), [h265(&hd)]);
    }

    #[test]
    fn rfc6184_a_unit_with_a_new_sps_updates_the_codec_and_violations_drop() {
        // A STAP-A with a new SPS, then STAP-Bs, which packetization mode 1
        // does not allow.
        let (t0, _set, mut ctx) = video_ctx();
        let mut normalized = Vec::new();
        let video = declare("video", "h264", 90_000, None, Sprop::None, &[]).unwrap();
        let v1 = ctx.tracks.declare(video.kind, video.codec.clone(), 90_000);
        let mut entry = Carried::new(Arc::clone(&v1), 96, &video);
        let sps = [0x67, 0x42, 0xc0, 0x28, 0xda, 0x02, 0x80, 0xf6, 0x40];
        let pps = [0x68, 0xce, 0x38, 0x80];
        let stap = lotse_codec::h264::nal::stap_a(&[&sps, &pps, &[0x65, 0xaa]]);
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(1, 0),
            &stap,
            &mut normalized,
        );
        let Codec::H264 {
            profile_level_id, ..
        } = v1.codec().as_ref().clone()
        else {
            panic!("h264");
        };
        assert_eq!(profile_level_id, Some([0x42, 0xc0, 0x28]));
        let stap_b = Bytes::from_static(&[25, 0]);
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(2, 3_000),
            &stap_b,
            &mut normalized,
        );
        on_video(
            &mut entry,
            &ctx,
            t0,
            video_rtp(3, 6_000),
            &stap_b,
            &mut normalized,
        );
        assert_eq!(entry.violations, 2);
    }

    #[test]
    fn rfc3640_violations_drop_the_packet_and_good_units_become_frames() {
        use lotse_core::clock::{Clock as _, SystemClock};
        use lotse_core::clock_map::ClockMapper;
        use lotse_core::source::{BackchannelSlot, ClockInput, TrackSet};
        use lotse_core::track::TrackLimits;

        let t0 = SystemClock.now();
        let set = TrackSet::new(TrackLimits::default(), t0);
        let (clock, _reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let mut ctx = SourceCtx {
            peer: ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            tracks: set.publisher(),
            clock,
            time: Arc::new(SystemClock),
            backchannel: BackchannelSlot::default(),
            cancel: tokio_util::sync::CancellationToken::new(),
        };
        let audio = declare(
            "audio",
            "mpeg4-generic",
            16_000,
            Some(1),
            Sprop::None,
            &[0x14, 0x08],
        )
        .unwrap();
        let a0 = ctx.tracks.declare(audio.kind, audio.codec.clone(), 16_000);
        let mut entry = Carried::new(Arc::clone(&a0), 97, &audio);
        let mut frames = a0.subscribe_frames();
        let rtp = |seq, ts| RtpHeaderFields {
            pt: 97,
            seq,
            ts,
            marker: true,
            ssrc: 1,
        };
        let aac = entry.aac.as_mut().unwrap();
        // Two violations (one warning), then a good packet.
        for (seq, payload) in [(1, &[0x00_u8][..]), (2, &[0x00, 0x0d, 0x00][..])] {
            publish_aac(
                aac,
                &a0,
                &mut entry.unwrapper,
                |_| (t0, t0),
                rtp(seq, 0),
                payload,
            );
        }
        assert!(frames.try_recv().unwrap().is_none(), "dropped");
        let good = lotse_codec::aac::packetize(&[b"ab", b"cd"]);
        publish_aac(
            aac,
            &a0,
            &mut entry.unwrapper,
            |_| (t0, t0),
            rtp(3, 5_000),
            &good,
        );
        let first = frames.try_recv().unwrap().unwrap();
        let second = frames.try_recv().unwrap().unwrap();
        assert_eq!((first.ts.ticks(), &first.payload[..]), (5_000, &b"ab"[..]));
        assert_eq!(
            (second.ts.ticks(), &second.payload[..]),
            (6_024, &b"cd"[..])
        );
        assert_eq!(aac.stats().violations, 2);
    }
}
