//! One headless viewer of the load: offers through the control client,
//! plays over its own loopback UDP socket until told to stop, hangs up as
//! a browser does, and keeps only counters and a latency histogram, so a
//! long run's memory stays flat.

use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;
use serde_json::{Value, json};
use str0m::rtp::RtpPacket;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::control::Control;
use super::histogram::Histogram;
use crate::latency::stamp_in_payload;
use crate::viewer::{Outgoing, Viewer, starts_keyframe};

/// The largest datagram read.
const MAX_DATAGRAM: usize = 2_048;

/// How long a viewer waits for a timer when the engine names none.
const IDLE_TICK: Duration = Duration::from_millis(50);

/// What one viewer saw.
#[derive(Debug, Clone, Default)]
pub struct ViewerStats {
    /// Offer sent → `answer` event.
    pub answer_after: Option<Duration>,
    /// Offer sent → ICE and DTLS up.
    pub connected_after: Option<Duration>,
    /// Offer sent → first video packet.
    pub first_packet_after: Option<Duration>,
    /// Offer sent → first packet of a keyframe.
    pub first_keyframe_after: Option<Duration>,
    /// Video RTP packets received.
    pub packets: u64,
    /// Their payload bytes.
    pub bytes: u64,
    /// Frames completed (marker packets, RFC 6184 §5.1).
    pub frames: u64,
    /// Packets that start a keyframe.
    pub keyframes: u64,
    /// Audio RTP packets received, when the viewer offered audio.
    pub audio_packets: u64,
    /// The audio codec the answer picked (`opus`, `pcmu`), lowercase;
    /// `None` without an audio m-line or a codec in it.
    pub audio_codec: Option<String>,
    /// Sequence numbers never received between the first and the last.
    pub lost: u64,
    /// The first extended sequence number.
    pub(super) first_seq: Option<u64>,
    /// The highest extended sequence number.
    pub(super) last_seq: Option<u64>,
    /// When the first packet arrived, since the camera's origin: stamps
    /// older than this are the join's catch-up, not cut-through.
    pub(super) live_from: Option<Duration>,
    /// When the last packet arrived.
    pub last_packet_at: Option<Instant>,
    /// Daemon-added latency of each stamped packet sent live: the camera's
    /// stamp → arrival ([`crate::latency`]).
    pub latency: Histogram,
    /// The `closed` code when the daemon ended the session itself.
    pub closed_by_daemon: Option<String>,
    /// A setup failure: the offer refused, no answer, an engine error.
    pub error: Option<String>,
}

/// What the accounting needs of one received video packet.
#[derive(Debug, Clone, Copy)]
pub struct Arrival<'a> {
    /// The extended sequence number.
    pub seq: u64,
    /// The marker bit: the frame's last packet (RFC 6184 §5.1).
    pub marker: bool,
    /// The payload.
    pub payload: &'a [u8],
    /// When it arrived.
    pub at: Instant,
}

impl<'a> From<&'a RtpPacket> for Arrival<'a> {
    fn from(packet: &'a RtpPacket) -> Self {
        Self {
            seq: *packet.seq_no,
            marker: packet.header.marker,
            payload: &packet.payload,
            at: packet.timestamp,
        }
    }
}

impl ViewerStats {
    /// A viewer that never played, for `error`.
    pub fn failed(error: String) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }

    /// Accounts the packets received since the last call, against the
    /// cameras' stamp `origin` and the instant the offer went out.
    pub fn account<'a>(
        &mut self,
        packets: impl IntoIterator<Item = Arrival<'a>>,
        origin: Instant,
        offered_at: Instant,
    ) {
        for packet in packets {
            let since_offer = packet.at.saturating_duration_since(offered_at);
            self.first_packet_after.get_or_insert(since_offer);
            let live_from = *self
                .live_from
                .get_or_insert_with(|| packet.at.saturating_duration_since(origin));
            self.packets = self.packets.saturating_add(1);
            self.bytes = self
                .bytes
                .saturating_add(u64::try_from(packet.payload.len()).unwrap_or(u64::MAX));
            if packet.marker {
                self.frames = self.frames.saturating_add(1);
            }
            if starts_keyframe(packet.payload) {
                self.keyframes = self.keyframes.saturating_add(1);
                self.first_keyframe_after.get_or_insert(since_offer);
            }
            self.first_seq = Some(
                self.first_seq
                    .map_or(packet.seq, |first| first.min(packet.seq)),
            );
            self.last_seq = Some(
                self.last_seq
                    .map_or(packet.seq, |last| last.max(packet.seq)),
            );
            if let Some(sent) = stamp_in_payload(packet.payload).filter(|sent| *sent >= live_from) {
                let arrived = packet.at.saturating_duration_since(origin);
                self.latency.record(arrived.saturating_sub(sent));
            }
            self.last_packet_at = Some(packet.at);
        }
        let expected = match (self.first_seq, self.last_seq) {
            (Some(first), Some(last)) => last.saturating_sub(first).saturating_add(1),
            _ => 0,
        };
        self.lost = expected.saturating_sub(self.packets);
    }
}

/// Where a viewer plays and against what.
#[derive(Debug, Clone)]
pub struct Play {
    /// The control client.
    pub control: Arc<Control>,
    /// The stream to watch.
    pub stream_id: String,
    /// The session id to offer under.
    pub session_id: String,
    /// The clock the cameras stamp with.
    pub clock: Arc<dyn Clock>,
    /// The cameras' stamp origin.
    pub origin: Instant,
    /// Offer to receive audio too, as a browser does.
    pub audio: bool,
    /// Ends the viewing.
    pub stop: CancellationToken,
}

/// Sends what the viewer wants sent; a lost datagram is the network's.
async fn send_all(socket: &UdpSocket, out: &mut Vec<Outgoing>) {
    for datagram in out.drain(..) {
        let _sent = socket
            .send_to(&datagram.payload, datagram.destination)
            .await;
    }
}

/// Offers, plays until `play.stop`, hangs up, and reports.
pub async fn view(play: Play) -> ViewerStats {
    let mut stats = ViewerStats::default();
    if let Err(err) = view_into(&play, &mut stats).await {
        stats.error = Some(err);
    }
    stats
}

/// [`view`], with setup failures as errors.
async fn view_into(play: &Play, stats: &mut ViewerStats) -> Result<(), String> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("viewer socket: {err}"))?;
    let addr = socket
        .local_addr()
        .map_err(|err| format!("viewer socket: {err}"))?;
    let clock = &play.clock;
    let mut viewer = if play.audio {
        Viewer::new_with_audio(addr, clock.now())?
    } else {
        Viewer::new(addr, clock.now())?
    };
    let offered_at = clock.now();
    let (subscription, _result, mut events) = play
        .control
        .subscribe(json!({
            "type": "webrtc/offer",
            "stream_id": play.stream_id,
            "session_id": play.session_id,
            "sdp": viewer.offer(),
            "ice_servers": [],
        }))
        .await
        .map_err(|err| format!("webrtc/offer: {err}"))?;
    let mut out = Vec::new();
    let mut buf = vec![0_u8; MAX_DATAGRAM];
    let mut open = true;
    while open {
        let wait = viewer
            .next_timeout()
            .map_or(IDLE_TICK, |at| at.saturating_duration_since(clock.now()));
        tokio::select! {
            event = events.recv() => match event {
                Some(event) => open = on_event(&event, &mut viewer, &mut out, stats, clock.now(), offered_at)?,
                None => open = false,
            },
            received = socket.recv_from(&mut buf) => {
                if let Ok((n, from)) = received {
                    viewer.receive(clock.now(), from, buf.get(..n).unwrap_or_default(), &mut out);
                }
            }
            () = clock.sleep(wait) => viewer.timeout(clock.now(), &mut out),
            () = play.stop.cancelled() => break,
        }
        if stats.connected_after.is_none() && viewer.is_connected() {
            stats.connected_after = Some(clock.now().saturating_duration_since(offered_at));
        }
        let packets = viewer.take_packets();
        stats.account(packets.iter().map(Arrival::from), play.origin, offered_at);
        let audio = viewer.take_audio_packets().len();
        stats.audio_packets = stats
            .audio_packets
            .saturating_add(u64::try_from(audio).unwrap_or(u64::MAX));
        send_all(&socket, &mut out).await;
    }
    if stats.closed_by_daemon.is_none() {
        viewer.close(&mut out);
        send_all(&socket, &mut out).await;
        play.control
            .command(json!({ "type": "unsubscribe", "subscription": subscription }))
            .await
            .map_err(|err| format!("unsubscribe: {err}"))?;
    }
    Ok(())
}

/// One event of the session's subscription; `false` once it closed.
fn on_event(
    event: &Value,
    viewer: &mut Viewer,
    out: &mut Vec<Outgoing>,
    stats: &mut ViewerStats,
    now: Instant,
    offered_at: Instant,
) -> Result<bool, String> {
    let field = |name| event.get(name).and_then(Value::as_str).unwrap_or_default();
    match field("type") {
        "answer" => {
            stats.answer_after = Some(now.saturating_duration_since(offered_at));
            stats.audio_codec = audio_codec(field("sdp"));
            viewer
                .accept_answer(field("sdp"), out)
                .map_err(|err| format!("the answer: {err}"))?;
        }
        "candidate" if !field("candidate").is_empty() => {
            viewer.add_remote_candidate(field("candidate"), out);
        }
        "closed" => {
            stats.closed_by_daemon = Some(field("code").to_owned());
            return Ok(false);
        }
        _ => {}
    }
    Ok(true)
}

/// The codec of the first payload type of the audio m-line of `sdp`
/// (RFC 8866 §5.14, `a=rtpmap` of §6.6), lowercase.
pub fn audio_codec(sdp: &str) -> Option<String> {
    let mut lines = sdp.lines().skip_while(|line| !line.starts_with("m=audio "));
    let pt = lines.next()?.split_whitespace().nth(3)?;
    let prefix = format!("a=rtpmap:{pt} ");
    lines
        .take_while(|line| !line.starts_with("m="))
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .and_then(|codec| codec.split('/').next())
        .map(str::to_lowercase)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::clock::SystemClock;

    use super::*;
    use crate::latency::stamp_sei;

    #[test]
    fn the_answers_audio_codec_is_its_first_payload_types_rfc8866_5_14() {
        let sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 H264/90000\r\n\
                   m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\na=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:111 opus/48000/2\r\n";
        assert_eq!(audio_codec(sdp).as_deref(), Some("opus"));
        let pcmu = "m=audio 9 RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\nm=video 9 RTP/SAVPF 96\r\n";
        assert_eq!(audio_codec(pcmu).as_deref(), Some("pcmu"));
        assert_eq!(audio_codec("m=video 9 RTP/SAVPF 96\r\n"), None);
        assert_eq!(
            audio_codec(
                "m=audio 9 RTP/SAVPF 8\r\nm=video 9 RTP/SAVPF 8\r\na=rtpmap:8 PCMA/8000\r\n"
            ),
            None
        );
    }

    #[test]
    fn accounting_counts_frames_keyframes_gaps_and_live_latency_only() {
        let origin = SystemClock.now();
        let at = |ms| origin + Duration::from_millis(ms);
        let old_stamp = stamp_sei(Duration::from_millis(1));
        let live_stamp = stamp_sei(Duration::from_millis(100));
        let idr = [0x65_u8, 0x88];
        let packets = [
            // A catch-up frame from the GOP cache: stamped before the
            // viewer's first packet, so not latency.
            Arrival {
                seq: 10,
                marker: false,
                payload: &old_stamp,
                at: at(95),
            },
            Arrival {
                seq: 11,
                marker: true,
                payload: &idr,
                at: at(95),
            },
            // Live: 3 ms after its stamp; seq 12 never arrives.
            Arrival {
                seq: 13,
                marker: false,
                payload: &live_stamp,
                at: at(103),
            },
            Arrival {
                seq: 14,
                marker: true,
                payload: &[0x41, 0x9a],
                at: at(104),
            },
        ];
        let mut stats = ViewerStats::default();
        stats.account(packets[..2].iter().copied(), origin, at(90));
        stats.account(packets[2..].iter().copied(), origin, at(90));
        assert_eq!(stats.packets, 4);
        assert_eq!(stats.bytes, 36 + 2 + 36 + 2);
        assert_eq!(stats.frames, 2);
        assert_eq!(stats.keyframes, 1);
        assert_eq!(stats.lost, 1);
        assert_eq!(stats.first_packet_after, Some(Duration::from_millis(5)));
        assert_eq!(stats.first_keyframe_after, Some(Duration::from_millis(5)));
        assert_eq!(stats.last_packet_at, Some(at(104)));
        assert_eq!(stats.latency.count(), 1);
        assert_eq!(stats.latency.percentile(50), Some(Duration::from_millis(3)));
    }
}
