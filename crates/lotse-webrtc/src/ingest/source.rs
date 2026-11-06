//! One `webrtc://` source and the I/O of its attempts: the signaling
//! channel opened through the client's relay, one UDP socket per host
//! address on an ephemeral port, the [`IngestEngine`] driven by datagrams,
//! signals and the injected clock, and what it outputs carried onto the
//! tracks through `lotse_codec`'s RTP receive path.
//!
//! How an attempt ends, and the code its signaling channel closes with:
//!
//! | what happened | the source's error | close code |
//! |---|---|---|
//! | no relay, or the open refused | `Unreachable` | (none opened) |
//! | no host address could be bound | `Unreachable` | `ice_failed` |
//! | no answer within 20 s | `Timeout` | `answer_timeout` |
//! | an answer the engine cannot apply | `Protocol` | `invalid_answer` |
//! | the camera failed before its answer | `Unreachable("camera: code: message")` | `camera_error` |
//! | the camera failed after it | `Ended("camera: code: message")` | `camera_error` |
//! | not connected within 10 s of the answer | `Timeout` | `ice_failed` |
//! | consent lost (RFC 7675) | `Ended` | `consent_lost` |
//! | the camera's DTLS `close_notify` | `Ended` | `peer_closed` |
//! | the relaying client went away | `Ended("signaling client gone")` | `signaling_lost` |
//! | cancelled | `Ended` | `source_stopped` |
//!
//! A cancel is honored at once: the engine closes (`close_notify`, RTCP
//! BYE) and is disconnected, its close datagrams sent without waiting.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use lotse_codec::rtp_ingest::RtpTracks;
use lotse_core::codec::Kind;
use lotse_core::signaling::{LocalSignal, RemoteSignal, SignalingChannel, close};
use lotse_core::source::{Source, SourceCtx, SourceDescriptor, SourceError};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::BoxFuture;
use lotse_core::track::Track;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use super::engine::{INTERNAL_ERROR, IngestEnd, IngestEngine, IngestOutput, IngestTrack};
use super::factory::SCHEME;
use super::options::WebRtcOptions;

/// The receive buffer: a datagram above the path MTU does not come from
/// a WebRTC peer, and one cut short fails its SRTP check.
const RECEIVE_BUFFER: usize = 2_048;

/// A validated `webrtc://` source.
#[derive(Debug, Clone)]
pub struct WebRtcSource {
    /// The URL, its label naming the camera to the client.
    url: SourceUrl,
    /// The options.
    options: WebRtcOptions,
}

impl WebRtcSource {
    /// The source of `url` with `options`, both checked by the factory.
    pub const fn new(url: SourceUrl, options: WebRtcOptions) -> Self {
        Self { url, options }
    }
}

impl Source for WebRtcSource {
    fn describe(&self) -> SourceDescriptor {
        SourceDescriptor {
            protocol: SCHEME,
            url: self.url.clone(),
            options: self.options.normalized(),
        }
    }

    /// Every option changes the offer, so the key is all of them.
    fn connection_options(&self) -> serde_json::Value {
        self.options.normalized()
    }

    fn run(&self, ctx: SourceCtx) -> BoxFuture<'static, SourceError> {
        Box::pin(attempt(self.options.clone(), ctx))
    }
}

/// One host socket: its address, the one its candidate names, and the
/// socket.
type Host = (SocketAddr, UdpSocket);

/// Binds one UDP socket on an ephemeral port per address of `addrs`; an
/// address that does not bind is logged and skipped.
async fn bind(addrs: &[IpAddr]) -> Vec<Host> {
    let mut hosts = Vec::new();
    for ip in addrs {
        let bound = UdpSocket::bind(SocketAddr::new(*ip, 0)).await;
        match bound.and_then(|socket| Ok((socket.local_addr()?, socket))) {
            Ok(host) => hosts.push(host),
            Err(err) => {
                tracing::warn!(%ip, error = %err, "webrtc: host address not bound; no candidate on it");
            }
        }
    }
    hosts
}

/// The next datagram on any of `hosts`, into `buf`: the index of the
/// socket it came in on, and its sender and length or the error.
fn recv_any<'a>(
    hosts: &'a [Host],
    buf: &'a mut [u8],
) -> impl Future<Output = (usize, io::Result<(SocketAddr, usize)>)> + 'a {
    std::future::poll_fn(move |cx| {
        for (index, (_, socket)) in hosts.iter().enumerate() {
            let mut read = ReadBuf::new(buf);
            if let Poll::Ready(received) = socket.poll_recv_from(cx, &mut read) {
                let len = read.filled().len();
                return Poll::Ready((index, received.map(|from| (from, len))));
            }
        }
        Poll::Pending
    })
}

impl Attempt {
    /// Sends `payload` from the host socket bound to `source` to
    /// `destination`, without waiting: a datagram that does not fit the
    /// socket's buffer now is lost, as on the wire, and counted.
    fn transmit(&mut self, source: SocketAddr, destination: SocketAddr, payload: &[u8]) {
        let socket = self.hosts.iter().find(|(addr, _)| *addr == source);
        let sent =
            socket.is_some_and(|(_, socket)| socket.try_send_to(payload, destination).is_ok());
        self.dropped = self.dropped.saturating_add(u64::from(!sent));
    }
}

/// What woke the attempt's loop.
enum Woke {
    /// The cancel.
    Cancelled,
    /// A signal from the client, `None` once it is gone.
    Signal(Option<RemoteSignal>),
    /// A datagram on host socket `.0`.
    Datagram(usize, io::Result<(SocketAddr, usize)>),
    /// The engine's timeout.
    Timer,
}

/// The end of an attempt by cancel.
fn cancelled() -> IngestEnd {
    IngestEnd {
        error: SourceError::Ended("webrtc: cancelled".into()),
        close: close::SOURCE_STOPPED,
        message: "cancelled".to_owned(),
    }
}

/// One attempt's engine and I/O.
struct Attempt {
    /// The engine.
    engine: IngestEngine,
    /// The host sockets.
    hosts: Vec<Host>,
    /// The RTP receive path.
    rtp: RtpTracks,
    /// The video's index, its track and its keyframes before this
    /// attempt, while the attempt waits for its first.
    waiting: Option<(usize, Arc<Track>, u64)>,
    /// The receive buffer.
    buf: Vec<u8>,
    /// Datagrams the sockets did not take.
    dropped: u64,
}

impl Attempt {
    /// Carries the engine's outputs until it waits: datagrams sent,
    /// tracks declared and the source ready, packets and Sender Reports
    /// through the RTP receive path. `Ok` with when it wants the time
    /// next; `Err` with how the attempt ended, by the engine or by the
    /// receive path (the camera's timestamps keep jumping).
    fn drain(&mut self, ctx: &mut SourceCtx) -> Result<Instant, IngestEnd> {
        loop {
            match self.engine.poll() {
                IngestOutput::Timeout(at) => return Ok(at),
                IngestOutput::Ended(end) => return Err(end),
                IngestOutput::Transmit {
                    source,
                    destination,
                    payload,
                } => self.transmit(source, destination, &payload),
                IngestOutput::Tracks(tracks) => self.declare(ctx, tracks),
                IngestOutput::Rtp {
                    index,
                    packet,
                    arrival,
                } => {
                    self.rtp
                        .receive(index, packet, arrival, ctx)
                        .map_err(|error| IngestEnd {
                            message: error.to_string(),
                            error,
                            close: INTERNAL_ERROR,
                        })?;
                    self.keyframe(index);
                }
                IngestOutput::SenderReport {
                    index,
                    ntp,
                    rtp_ts,
                    arrival,
                } => self.rtp.sender_report(index, ntp, rtp_ts, arrival, ctx),
            }
        }
    }

    /// Declares `tracks`, the ones the answer negotiated, carries each on
    /// the RTP receive path, and makes the source ready.
    fn declare(&mut self, ctx: &mut SourceCtx, tracks: Vec<IngestTrack>) {
        for negotiated in tracks {
            let declared = negotiated.declared;
            let track =
                ctx.tracks
                    .declare(declared.kind, declared.codec.clone(), declared.clock_rate);
            if declared.kind == Kind::Video {
                let before = track.stats().keyframes;
                self.waiting = Some((negotiated.index, Arc::clone(&track), before));
            }
            self.rtp
                .carry(negotiated.index, track, negotiated.pt, &declared);
        }
        ctx.tracks.ready();
    }

    /// After a packet of stream `index`: once the video track counted a
    /// keyframe of this attempt, the engine stops asking for the first
    /// one.
    fn keyframe(&mut self, index: usize) {
        if let Some((video, track, before)) = &self.waiting
            && *video == index
            && track.stats().keyframes > *before
        {
            self.engine.keyframe_seen();
            self.waiting = None;
        }
    }

    /// Takes what woke the loop at `now`; `Some` with how the attempt
    /// ended.
    fn woke(&mut self, event: Woke, now: Instant) -> Option<IngestEnd> {
        match event {
            Woke::Cancelled => return Some(cancelled()),
            Woke::Signal(Some(RemoteSignal::Answer(sdp))) => self.engine.accept_answer(now, &sdp),
            Woke::Signal(Some(RemoteSignal::Candidate(candidate))) => {
                self.engine.add_remote_candidate(now, &candidate);
            }
            Woke::Signal(Some(RemoteSignal::Failed { code, message })) => {
                let message = format!("camera: {code}: {message}");
                let error = if self.engine.answered() {
                    SourceError::Ended(message.clone())
                } else {
                    SourceError::Unreachable(message.clone())
                };
                return Some(IngestEnd {
                    error,
                    close: close::CAMERA_ERROR,
                    message,
                });
            }
            Woke::Signal(None) => {
                return Some(IngestEnd {
                    error: SourceError::Ended("signaling client gone".into()),
                    close: close::SIGNALING_LOST,
                    message: "the signaling client is gone".to_owned(),
                });
            }
            Woke::Datagram(index, received) => {
                let local = self.hosts.get(index).map(|(addr, _)| *addr);
                let received = received
                    .inspect_err(|err| tracing::debug!(error = %err, "webrtc: receive failed"));
                if let (Some(local), Ok((from, len))) = (local, received) {
                    let datagram = self.buf.get(..len).unwrap_or_default();
                    self.engine.receive(now, from, local, datagram);
                }
            }
            Woke::Timer => self.engine.handle_timeout(now),
        }
        None
    }

    /// Ends the attempt as `end` says: the engine closed and its close
    /// output sent, `channel` closed with the code and message, the error
    /// returned.
    fn finish(mut self, channel: SignalingChannel, end: IngestEnd) -> SourceError {
        self.engine.close();
        while let IngestOutput::Transmit {
            source,
            destination,
            payload,
        } = self.engine.poll()
        {
            self.transmit(source, destination, &payload);
        }
        tracing::debug!(
            dropped = self.dropped,
            code = end.close,
            "webrtc: attempt over"
        );
        channel.close(end.close, end.message);
        end.error
    }
}

/// Sends the offer on `channel`, then the host candidates and the
/// end-of-candidates indication; `false` once the attempt was
/// cancelled meanwhile.
async fn offer(engine: &IngestEngine, channel: &SignalingChannel, ctx: &SourceCtx) -> bool {
    let mut signals = vec![LocalSignal::Offer(engine.offer_sdp().to_owned())];
    signals.extend(
        engine
            .local_candidates()
            .into_iter()
            .map(LocalSignal::Candidate),
    );
    for signal in signals {
        tokio::select! {
            biased;
            () = ctx.cancel.cancelled() => return false,
            // A relay that stopped reading shows as the client gone on
            // `incoming`.
            _sent = channel.outgoing.send(signal) => {}
        }
    }
    true
}

/// One connection attempt of a source with `options`.
async fn attempt(options: WebRtcOptions, mut ctx: SourceCtx) -> SourceError {
    let Some(relay) = ctx.signaling.clone() else {
        return SourceError::Unreachable("webrtc: no signaling relay to the client".into());
    };
    let open = tokio::select! {
        biased;
        () = ctx.cancel.cancelled() => return SourceError::Ended("webrtc: cancelled".into()),
        open = relay.open() => open,
    };
    let channel = match open {
        Ok(channel) => channel,
        Err(refused) => {
            return SourceError::Unreachable(format!("webrtc: signaling refused: {refused}"));
        }
    };
    tracing::debug!(signal = %channel.id, addrs = ?channel.local_addrs, "webrtc: signaling channel open");
    let hosts = bind(&channel.local_addrs).await;
    let addrs: Vec<SocketAddr> = hosts.iter().map(|(addr, _)| *addr).collect();
    let engine = match IngestEngine::offer(&options, &addrs, ctx.time.now()) {
        Ok(engine) => engine,
        Err(reason) => {
            let error = SourceError::Unreachable(format!("webrtc: {reason}"));
            channel.close(close::ICE_FAILED, reason);
            return error;
        }
    };
    let attempt = Attempt {
        engine,
        hosts,
        rtp: RtpTracks::new(SCHEME),
        waiting: None,
        buf: vec![0_u8; RECEIVE_BUFFER],
        dropped: 0,
    };
    Box::pin(run(attempt, channel, &mut ctx)).await
}

/// Runs `attempt` on `channel` until it ends.
async fn run(
    mut attempt: Attempt,
    mut channel: SignalingChannel,
    ctx: &mut SourceCtx,
) -> SourceError {
    if !offer(&attempt.engine, &channel, ctx).await {
        return attempt.finish(channel, cancelled());
    }
    loop {
        let wake = match attempt.drain(ctx) {
            Ok(wake) => wake,
            Err(end) => return attempt.finish(channel, end),
        };
        // A new timer each time: str0m's next timeout moves with nearly
        // every datagram, so one kept would rarely be the one due.
        let mut sleeping = ctx
            .time
            .sleep(wake.saturating_duration_since(ctx.time.now()));
        let event = tokio::select! {
            biased;
            () = ctx.cancel.cancelled() => Woke::Cancelled,
            signal = channel.incoming.recv() => Woke::Signal(signal),
            (index, received) = recv_any(&attempt.hosts, &mut attempt.buf) => Woke::Datagram(index, received),
            () = &mut sleeping => Woke::Timer,
        };
        if let Some(end) = attempt.woke(event, ctx.time.now()) {
            return attempt.finish(channel, end);
        }
    }
}
