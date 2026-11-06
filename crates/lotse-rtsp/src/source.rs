//! The RTSP source: one retina session per connection attempt on the
//! source's own connection to the camera, its media TCP interleaved or,
//! opt-in, RTP over UDP, the RTP receive path of `lotse-codec`
//! ([`lotse_codec::rtp_ingest`]: the H.264 and H.265 normalizers, the
//! side branch's depacketizers, the timelines) on its packets, RTCP Sender
//! Reports as sync hints.
//!
//! Implements RFC 2326 (RTSP 1.0: DESCRIBE, SETUP, PLAY, TEARDOWN through
//! retina), RFC 3550 §5.1 (packet header fields kept) and §6.4.1 (Sender
//! Reports), RFC 6184 (H.264) and RFC 7798 (H.265, §7.1 `sprop-vps`,
//! `sprop-sps` and `sprop-pps` read by retina, §7.2.3 a stream with
//! decoding order numbers declared unsupported through [`crate::fmtp`])
//! through `lotse-codec`,
//! RFC 3551 §6 (the
//! static audio payload types), RFC 7587 (Opus), RFC 3640 (AAC), and
//! RFC 7826 §19.2 for `rtsps` (the TLS stream from `lotse_tls`), and
//! RFC 2326 §12.39 with RFC 3550 §11 for RTP over UDP ([`crate::udp`]).
//! The source dials the camera, `rtsp` or `rtsps`, and drives retina's
//! sans-I/O core on that connection ([`crate::driver`]): the camera sees
//! the source URL itself as the Request-URI (RFC 2326 §6.1, RFC 7826
//! §19.2), and retina sends the receiver reports (RFC 3550 §6.4.2), TCP
//! interleaved (RFC 2326 §10.12) on the connection, over UDP from each
//! stream's RTCP port, the pairs the source binds and the driver reads.
//! retina reads at most [`MAX_MESSAGE`] bytes of each RTSP message. The
//! camera host is never resolved here: the source connects to the first
//! address the supervisor resolved.
//!
//! The ONVIF backchannel (ONVIF Streaming Specification §5.3) never rides
//! in this session, which never carries its `Require` header and never
//! sets up an `a=sendonly` media (§5.3.2) nor declares one as a track:
//! once the session plays, a connection that asks for it (a stream on it
//! opted in, `backchannel`, off by default) has the camera probed on a
//! connection of its own ([`crate::backchannel::probe`]), and a talker's
//! claim opens the backchannel in a session of its own
//! ([`crate::backchannel::open`]), which a reconnect of this one leaves
//! alone. A stream that opts in or out turns the probe on or off without
//! this session noticing.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_codec::h264::ParameterSets;
use lotse_codec::h265;
use lotse_codec::rtp_ingest::{Declared, RtpPacket, RtpTracks, Sprop};
use lotse_core::clock::Clock;
use lotse_core::codec::{Codec, Kind};
use lotse_core::ingest::IngestCounters;
use lotse_core::source::{Source, SourceCtx, SourceDescriptor, SourceError};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::{BoxFuture, spawn_named};
use lotse_core::throttle::Throttle;
use lotse_tls::TlsTarget;
use retina::client::{
    Credentials, InitialSequenceNumberPolicy, InitialTimestampPolicy, PlayOptions,
    ReceiverReportPolicy, SessionOptions, Stream, TeardownPolicy,
};
use retina::codec::{FrameFormat, ParametersRef};

use crate::backchannel::camera::Camera;
use crate::backchannel::probe;
use crate::backchannel::session::Probed;
use crate::driver::{Budget, Connection, Driver, Duplex, Item, Received};
use crate::error::camera_text;
use crate::factory::PROTOCOL;
use crate::options::{RtspOptions, Transport as MediaTransport};
use crate::udp::Pair;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// How long the teardown may take once the connection is cancelled, and
/// on the session's own connection: `Source::run`'s 100 ms to honor its
/// cancel.
pub(crate) const TEARDOWN_BUDGET: Duration = Duration::from_millis(100);

/// How long the TCP interleaved session's teardown may take, from its
/// start, once retina retries it on a fresh connection, as its `Auto`
/// policy does for a live555 camera with the stale TCP session bug: a
/// dial and, for `rtsps`, a TLS handshake do not fit in
/// [`TEARDOWN_BUDGET`] beyond loopback. It delays the attempt's end, and
/// so the next connection, only in that case, and never a cancelled one:
/// a cancellation, before the teardown or during its retries, leaves it
/// [`TEARDOWN_BUDGET`] from then on, and a session still set up then
/// expires on the camera by its timeout (RFC 2326 §12.37).
const FRESH_TEARDOWN_BUDGET: Duration = Duration::from_secs(2);

/// The teardown budget of every session the source drives on retina's
/// core: the TCP interleaved session's and the backchannel's
/// ([`crate::backchannel::camera::Camera::tear_down`]).
pub(crate) const TEARDOWN: Budget = Budget {
    own: TEARDOWN_BUDGET,
    fresh: FRESH_TEARDOWN_BUDGET,
};

/// One validated `rtsp://` or `rtsps://` source.
#[derive(Debug)]
pub struct RtspSource {
    /// The URL, credentials inside.
    url: SourceUrl,
    /// The options.
    options: RtspOptions,
    /// For `rtsps`: the server name and the certificate check.
    tls: Option<TlsTarget>,
    /// Whether the camera answered the backchannel's probe with `551`,
    /// remembered across the connection's attempts and its streams' opt-ins.
    probed: Probed,
}

impl RtspSource {
    /// A source for `url` with `options`; `tls` is set exactly for `rtsps`.
    pub(crate) fn new(url: SourceUrl, options: RtspOptions, tls: Option<TlsTarget>) -> Self {
        Self {
            url,
            options,
            tls,
            probed: Probed::default(),
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

    fn wants_backchannel(&self) -> bool {
        self.options.backchannel
    }

    fn run(&self, ctx: SourceCtx) -> BoxFuture<'static, SourceError> {
        let url = self.url.clone();
        let options = self.options.clone();
        let tls = self.tls.clone();
        let probed = self.probed.clone();
        Box::pin(async move {
            let mut ctx = ctx;
            let Some(addr) = ctx.peer.addrs.first().copied() else {
                return SourceError::Unreachable(format!(
                    "rtsp: no address resolved for {}",
                    ctx.peer.host
                ));
            };
            let ask = Ask {
                camera: Camera {
                    url,
                    options,
                    tls,
                    addr,
                    time: Arc::clone(&ctx.time),
                },
                probed,
            };
            let dialer = Dialer {
                addr,
                tls: ask.camera.tls.clone(),
            };
            let tls = dialer.tls.is_some();
            tracing::info!(host = %ctx.peer.host, %addr, tls, transport = ?ask.camera.options.transport, "rtsp: connecting");
            // The driver's buffers make the attempt large: on the heap.
            Box::pin(run_core(&dialer, &ask, &mut ctx)).await
        })
    }
}

/// The credentials retina sends, from the URL's userinfo.
pub(crate) fn credentials(url: &SourceUrl) -> Option<Credentials> {
    url.credentials().map(|c| Credentials {
        username: c.username().to_owned(),
        password: c
            .password()
            .map(|p| p.expose_secret().clone())
            .unwrap_or_default(),
    })
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
        Some(ParametersRef::Video(video)) => {
            let units: Vec<&[u8]> = video.parameter_sets().collect();
            sets = video_sets(stream.encoding_name(), &units);
        }
        // The raw `AudioSpecificConfig` of AAC (ISO/IEC 14496-3 §1.6.2.1),
        // as the MP4 framing has it, not ADTS's empty extra data.
        Some(ParametersRef::Audio(audio)) => {
            extra.extend_from_slice(audio.extra_data(FrameFormat::MP4));
        }
        Some(ParametersRef::Message(_)) | None => {}
    }
    (sets, extra)
}

/// The parameter sets retina read from a video stream's `fmtp`, raw NAL
/// units, as the sprop of the stream's `encoding` (retina's lowercase
/// encoding name): each set is recognized by its NAL unit header, so
/// their order does not matter.
fn video_sets(encoding: &str, units: &[&[u8]]) -> Sprop {
    match encoding {
        "h264" => {
            let mut sets = ParameterSets::default();
            for unit in units {
                sets.observe(unit);
            }
            Sprop::H264(sets)
        }
        "h265" => {
            let mut sets = h265::ParameterSets::default();
            for unit in units {
                sets.observe(unit);
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

/// Picks the first video and the first audio stream of the SDP the
/// camera sends; `sdp` is the description retina parsed the streams from,
/// read for what retina does not expose. The session never asks for the
/// backchannel, so the camera describes none (ONVIF Streaming
/// Specification §5.3.1) and every stream is one the camera sends.
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

/// Runs `future` under the read deadline and cancellation.
async fn within<T>(
    ctx: &SourceCtx,
    deadline: Duration,
    what: &str,
    future: impl Future<Output = Result<T, SourceError>>,
) -> Result<T, SourceError> {
    within_on(&*ctx.time, &ctx.cancel, deadline, what, future).await
}

/// Runs `future` under `deadline` on `time` and `cancel`.
pub(crate) async fn within_on<T>(
    time: &dyn Clock,
    cancel: &CancellationToken,
    deadline: Duration,
    what: &str,
    future: impl Future<Output = Result<T, SourceError>>,
) -> Result<T, SourceError> {
    tokio::select! {
        result = future => result,
        () = time.sleep(deadline) => Err(SourceError::Timeout(format!(
            "{what}: no answer within {} ms",
            deadline.as_millis()
        ))),
        () = cancel.cancelled() => Err(SourceError::Ended("cancelled".into())),
    }
}

/// The streams of the `DESCRIBE` answer to set up ([`select`]), or a
/// protocol error when there is none.
fn choose(streams: &[Stream], sdp: &[u8]) -> Result<Vec<(usize, Declared)>, SourceError> {
    let chosen = select(streams, sdp);
    if chosen.is_empty() {
        return Err(SourceError::Protocol(
            "the SDP describes no video or audio stream".into(),
        ));
    }
    for (index, declared) in &chosen {
        tracing::info!(index, kind = %declared.kind, codec = declared.codec.name(), clock_rate = declared.clock_rate, "rtsp: setting up");
    }
    Ok(chosen)
}

/// Declares a track for each of the `chosen` streams, set up by now:
/// the receive path of each, by its stream index of `streams`.
fn carry(streams: &[Stream], chosen: &[(usize, Declared)], ctx: &mut SourceCtx) -> RtpTracks {
    let mut carried = RtpTracks::new(PROTOCOL);
    for (index, declared) in chosen {
        let track = ctx
            .tracks
            .declare(declared.kind, declared.codec.clone(), declared.clock_rate);
        let pt = streams.get(*index).map_or(0, Stream::rtp_payload_type);
        carried.carry(*index, track, pt, declared);
    }
    carried
}

/// The session options every connection of the source shares: its
/// credentials and user agent, the `TEARDOWN` of a session it set up
/// (retina's `Auto` policy: once on the session's own connection over
/// TCP, on fresh ones over UDP and for a camera with the live555 bug of
/// stale TCP sessions), and the most bytes of an RTSP message it reads.
fn session_options(ask: &Ask) -> SessionOptions {
    let url = &ask.camera.url;
    SessionOptions::default()
        .creds(credentials(url))
        .user_agent(ask.camera.options.user_agent().to_owned())
        .teardown(TeardownPolicy::Auto)
        .max_message_size(MAX_MESSAGE)
}

/// DESCRIBE of the source URL itself, SETUP of the chosen streams TCP
/// interleaved or, with `transport: "udp"`, RTP over UDP to a pair bound
/// for each, the track declarations and PLAY, on `driver`, each under the
/// read deadline: the receive path of the streams carried. A camera
/// that refuses UDP is not asked for TCP instead ([`setup_error`]). The
/// `DESCRIBE` never carries the backchannel's `Require` header: the
/// backchannel has sessions of its own ([`crate::backchannel`]).
async fn set_up(
    driver: &mut Driver,
    ask: &Ask,
    ctx: &mut SourceCtx,
) -> Result<RtpTracks, SourceError> {
    let url = &ask.camera.url;
    let deadline = Duration::from_millis(ask.camera.options.timeout_ms);
    tracing::info!(host = %ctx.peer.host, addrs = ?ctx.peer.addrs, "rtsp: describing");
    let target = url.expose_url().clone();
    within(ctx, deadline, "DESCRIBE", async {
        driver
            .describe(target)
            .await
            .map_err(|err| err.source_error(url))
    })
    .await?;
    let chosen = choose(driver.streams(), driver.sdp())?;
    // `rtsps` with UDP is refused at validation: plain datagrams would
    // carry what the TLS session protects.
    let udp = ask.camera.options.transport == MediaTransport::Udp;
    for (index, _) in &chosen {
        within(ctx, deadline, "SETUP", async {
            let set_up = if udp {
                let pair = Pair::bind(ask.camera.addr.ip())?;
                driver.setup_udp(*index, pair).await
            } else {
                driver.setup(*index).await
            };
            set_up.map_err(|err| setup_error(err.source_error(url), err.status_code(), udp))
        })
        .await?;
    }
    let carried = carry(driver.streams(), &chosen, ctx);
    within(ctx, deadline, "PLAY", async {
        driver
            .play(play_options())
            .await
            .map_err(|err| err.source_error(url))
    })
    .await?;
    Ok(carried)
}

/// The options of a `PLAY`: nothing of `RTP-Info` (RFC 2326 §12.33, RFC
/// 7826 §18.45) is used, since lotse reads the raw stream from its first
/// packet on. retina does not enforce timestamps (it no longer can be
/// asked to): core's guard turns a real jump into an epoch instead.
/// `rtptime` maps RTP time to normal play time, which only retina's NPT
/// uses; lotse maps the raw RTP timestamps to the wall clock from Sender
/// Reports (RFC 3550 §6.4.1), else by arrival. So it is ignored: retina's
/// default refuses a `PLAY` answer without it for more than one stream,
/// as MediaMTX 1.21.1 gives a path's first reader (observed 2026-10-06).
/// `seq` is ignored too: retina's reorderer would otherwise drop every
/// packet before it as late, so a camera whose `seq` is ahead of its
/// stream would play nothing until the stream caught up.
pub(crate) fn play_options() -> PlayOptions {
    PlayOptions::default()
        .initial_seq(InitialSequenceNumberPolicy::Ignore)
        .initial_timestamp(InitialTimestampPolicy::Ignore)
}

/// RFC 2326 §11.3.11: `461 Unsupported Transport`.
const UNSUPPORTED_TRANSPORT: u16 = 461;

/// A failed `SETUP`, classified as `error` with the RTSP `status` it
/// was refused with, as a source error: a camera that refuses RTP over
/// UDP says how to repair it; nothing falls back to TCP on its own,
/// because the transport is part of the stream's options and its
/// connection key.
fn setup_error(error: SourceError, status: Option<u16>, udp: bool) -> SourceError {
    match error {
        SourceError::Protocol(message) if udp && status == Some(UNSUPPORTED_TRANSPORT) => {
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
///
/// A camera that answers a UDP `SETUP` with `interleaved=` (it chose TCP
/// after all, RFC 2326 §12.39) ends here too (retina 0.5 prototype
/// `97153f6`, its source read 2026-11-03, no camera seen doing it yet):
/// the loopback relay lotse ran until then passed such an answer on as
/// TCP, but retina's `parse_setup` does not tell it from a UDP answer
/// without `server_port`, so the camera's media comes interleaved on a
/// channel the session never assigned. retina logs one warning with up to
/// 128 bytes of the frame in hex (which [`crate::retina_log`] caps), and
/// no datagram arrives. When the camera's `a=tool` or `Server` names a
/// live555 version with the stale TCP session bug, retina's
/// `UnassignedChannelDataPolicy::Auto` ends the session at once with its
/// stale-session error instead. The hint to set the transport to tcp is
/// the repair either way; reported upstream.
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

/// What one connection attempt asks of the camera.
#[derive(Debug)]
struct Ask {
    /// The camera, which the backchannel's probe and sessions connect to
    /// as well.
    camera: Camera,
    /// What the probes of the camera's backchannel learned so far.
    probed: Probed,
}

/// The most bytes of one RTSP message from the camera, head and body,
/// retina reads (`SessionOptions::max_message_size`), on every connection
/// of the source: the bound on an answer and its SDP. Interleaved frames
/// are bounded by their 16-bit length (RFC 2326 §10.12) instead, and the
/// requests by what goes into them ([`crate::driver`]).
pub(crate) const MAX_MESSAGE: usize = 65_536;

/// Connects to the camera at `addr`, with Nagle's algorithm off
/// (`TCP_NODELAY`): every connection the crate dials ([`Dialer`]); a
/// failure is `unreachable`, worded as retina words its own. With Nagle
/// (RFC 1122 §4.2.3.4) a small write waits while an earlier one is
/// unacknowledged: the backchannel's packets, a few hundred bytes every
/// 20 ms, would wait for the camera's ACK, which a camera sending video
/// piggybacks on its next frame, tens of milliseconds late.
async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream, SourceError> {
    let connected = TcpStream::connect(addr).await;
    let stream = connected.and_then(|stream| stream.set_nodelay(true).map(|()| stream));
    stream.map_err(|err| SourceError::Unreachable(format!("Unable to connect to {addr}: {err}")))
}

/// The local address retina names in its errors when the socket cannot
/// say its own: the unspecified one.
const UNKNOWN_LOCAL: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::UNSPECIFIED,
    0,
));

/// How the source and its backchannel's connections reach the camera: TCP
/// to the address the supervisor resolved, with Nagle's algorithm off
/// ([`connect_tcp`]), and for `rtsps` the TLS handshake on it (RFC 7826
/// §19.2).
#[derive(Debug, Clone)]
pub(crate) struct Dialer {
    /// The camera's address.
    pub(crate) addr: SocketAddr,
    /// For `rtsps`: the server name and the certificate check.
    pub(crate) tls: Option<TlsTarget>,
}

impl Dialer {
    /// What a dial waits for, as its deadline's error names it.
    const fn what(&self) -> &'static str {
        if self.tls.is_some() {
            "TLS handshake"
        } else {
            "TCP connect"
        }
    }

    /// A connection to the camera, with the addresses of its ends; an
    /// unknown local address is [`UNKNOWN_LOCAL`].
    pub(crate) async fn dial(self) -> Result<Connection, SourceError> {
        let tcp = connect_tcp(self.addr).await?;
        let local = tcp.local_addr().unwrap_or(UNKNOWN_LOCAL);
        let stream: Box<dyn Duplex> = match &self.tls {
            None => Box::new(tcp),
            Some(tls) => Box::new(lotse_tls::connect(tcp, tls, &[]).await?),
        };
        Ok(Connection {
            stream,
            local,
            peer: self.addr,
        })
    }

    /// [`Dialer::dial`] as the driver's teardown dials.
    pub(crate) fn boxed(&self) -> BoxFuture<'static, Result<Connection, SourceError>> {
        Box::pin(self.clone().dial())
    }
}

/// One connection attempt: dials the camera under the read deadline,
/// drives retina's core on that connection through `DESCRIBE`, `SETUP`
/// and `PLAY`, plays until the camera or core ends it, then tears down,
/// however it ended: a session the camera set up gets its `TEARDOWN` (RFC
/// 2326 §10.7, RFC 7826 §13.7) after a failed or cancelled `SETUP` or
/// `PLAY` too, within [`TEARDOWN_BUDGET`] on its own connection and, when
/// retina's policy retries on fresh connections, as it does for a UDP
/// session whose connection is gone (RFC 2326 §1.1), within
/// [`FRESH_TEARDOWN_BUDGET`], unless cancelled: then within
/// [`TEARDOWN_BUDGET`] of the cancellation, which bounds a retry already
/// in progress too.
async fn run_core(dialer: &Dialer, ask: &Ask, ctx: &mut SourceCtx) -> SourceError {
    let url = &ask.camera.url;
    let deadline = Duration::from_millis(ask.camera.options.timeout_ms);
    let conn = match within(ctx, deadline, dialer.what(), dialer.clone().dial()).await {
        Ok(conn) => conn,
        Err(err) => return err,
    };
    // retina sends the receiver reports (RFC 3550 §6.4.2).
    let options = session_options(ask).receiver_reports(ReceiverReportPolicy::Always);
    let mut driver = Driver::new(conn, options, Arc::clone(&ctx.time));
    driver.count_udp_into(ctx.tracks.ingest());
    let exit = match set_up(&mut driver, ask, ctx).await {
        Ok(carried) => play(&mut driver, carried, ask, ctx).await,
        Err(err) => err,
    };
    // `classify` scrubbed retina's errors; the attempt's others (TLS, the
    // connection) are scrubbed here too, should one echo the URL.
    let exit = exit.scrubbed(url);
    let dial = || dialer.boxed();
    tracing::debug!(why = %exit, "rtsp: tearing down");
    driver.teardown(&dial, TEARDOWN, &ctx.cancel).await;
    exit
}

/// Plays a connected session until the camera or core ends it: why it
/// ended. Beside it, a connection that asks for the camera's backchannel
/// has it probed on a connection of its own, at once and whenever a
/// stream opts in again ([`probe::start`]), which ends with the session.
async fn play(
    driver: &mut Driver,
    mut carried: RtpTracks,
    ask: &Ask,
    ctx: &SourceCtx,
) -> SourceError {
    let (url, options) = (&ask.camera.url, &ask.camera.options);
    let probe = probe::start(
        ask.camera.clone(),
        ctx.backchannel.clone(),
        ask.probed.clone(),
    );
    let _probe = Aborting(spawn_named("rtsp.probe", probe));
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
    loop {
        let item = tokio::select! {
            item = driver.next_item() => item,
            () = &mut first_media, if !live => break no_udp_media(deadline, ingest.snapshot().datagrams_rejected),
            () = ctx.cancel.cancelled() => break SourceError::Ended("cancelled".into()),
        };
        match item {
            Err(err) => break err.source_error(url),
            Ok(Item::Rtp(packet)) => {
                if !live {
                    live = true;
                    ctx.tracks.ready();
                    tracing::info!("rtsp: playing; RTP arrives over UDP");
                }
                let arrival = ctx.time.now();
                count_loss(&ingest, &mut loss_log, packet.loss, arrival);
                let Received {
                    stream,
                    ts,
                    seq,
                    ssrc,
                    marker,
                    payload,
                    ..
                } = packet;
                let packet = RtpPacket {
                    seq,
                    ts,
                    ssrc,
                    marker,
                    payload,
                };
                if let Err(err) = carried.receive(stream, packet, arrival, ctx) {
                    break err;
                }
            }
            Ok(Item::Rtcp(compound)) => on_rtcp(&carried, ctx, ctx.time.now(), &compound),
        }
    }
}

/// A task aborted when dropped: the probes, which end with the session
/// that started them.
struct Aborting(tokio::task::JoinHandle<()>);

impl Drop for Aborting {
    fn drop(&mut self) {
        self.0.abort();
    }
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

/// One RTCP compound packet: its Sender Reports become sync hints of
/// its stream's track, if carried.
fn on_rtcp(
    carried: &RtpTracks,
    ctx: &SourceCtx,
    arrival: Instant,
    compound: &retina::rtcp::ReceivedCompoundPacket,
) {
    for packet in compound.pkts() {
        if let Ok(Some(report)) = packet.as_sender_report() {
            carried.sender_report(
                compound.stream_id(),
                report.ntp_timestamp().0,
                report.rtp_timestamp(),
                arrival,
                ctx,
            );
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

    use lotse_core::text::CUT_MARK;

    use super::*;

    #[tokio::test]
    async fn rfc1122_4_2_3_4_the_cameras_connection_has_nagle_off() {
        // With Nagle on, the backchannel's packets to the camera waited
        // for its ACK: 29 ms off their 20 ms grid at the 95th percentile
        // (Linux 7.0, 2026-10-11).
        let camera = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connected = connect_tcp(camera.local_addr().unwrap()).await.unwrap();
        assert!(connected.nodelay().unwrap());
    }

    #[tokio::test]
    async fn a_camera_that_cannot_be_reached_is_unreachable() {
        // A port nothing listens on: bound, then closed.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let err = connect_tcp(addr).await.unwrap_err();
        assert!(
            matches!(&err, SourceError::Unreachable(message) if message.starts_with("Unable to connect to")),
            "{err:?}"
        );
    }

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
        assert_eq!(
            video.codec,
            Codec::H264 {
                profile_level_id: Some([0x42, 0xc0, 0x28]),
                sps: sets.sps.clone(),
                pps: sets.pps.clone(),
            }
        );
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
        // In any order: each set is told by its NAL unit header.
        let sets = video_sets("h264", &[&pps[..], &sps[..]]);
        assert!(
            matches!(&sets, Sprop::H264(sets) if (&sets.sps, &sets.pps) == (&Some(sps), &Some(pps))),
            "{sets:?}"
        );
        let vps = Bytes::from(h265::test_data::vps());
        let sps = Bytes::from(h265::test_data::sps(640, 480));
        let pps = Bytes::from(h265::test_data::pps());
        let sets = video_sets("h265", &[&vps[..], &sps[..], &pps[..]]);
        assert!(
            matches!(&sets, Sprop::H265(sets) if sets.units() == Some([&vps[..], &sps[..], &pps[..]])),
            "{sets:?}"
        );
        assert_eq!(video_sets("jpeg", &[]), Sprop::None);
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
            assert!(name.ends_with(&format!("y{CUT_MARK}")), "{media}: {name}");
        }
    }
}
