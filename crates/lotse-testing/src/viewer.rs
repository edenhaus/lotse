//! A headless browser stand-in on str0m: offers `recvonly` video the way
//! Chrome does (standard extensions plus `playout-delay`, and
//! `abs-capture-time` as Chrome offers it to a page that asks), takes the
//! daemon's answer, and collects the RTP it receives.
//!
//! Sans-IO like the session it talks to, so the same viewer runs in memory
//! against a `Session` and over real UDP against a worker; the caller moves
//! the datagrams and the clock.

use std::net::SocketAddr;
use std::time::Instant;

use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::crypto::CryptoProvider;
use str0m::media::{KeyframeRequestKind, MediaKind, Mid};
use str0m::net::{DatagramRecv, Protocol, Receive, TcpType};
use str0m::rtp::{Extension, ExtensionMap, RtpPacket};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

/// The direction [`Viewer::audio_direction`] reports.
pub use str0m::media::Direction;

/// How a viewer offers talk-back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TalkbackOffer {
    /// A third audio m-line after the video one, `sendonly` and without a
    /// track, as a talk-back capable frontend adds it: the recommended
    /// shape.
    Dedicated,
    /// The downlink audio m-line `sendrecv`, as a player that sends
    /// talk-back on its downlink m-line offers it (observed 2026-10-07).
    SendRecv,
}

/// The audio m-lines a viewer offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AudioOffer {
    /// None.
    Off,
    /// A `recvonly` one before the video.
    Receive,
    /// Talk-back as well.
    Talkback(TalkbackOffer),
}

/// A datagram the viewer wants sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// Over ICE-TCP rather than UDP.
    pub tcp: bool,
    /// The viewer's address.
    pub source: SocketAddr,
    /// The daemon's address.
    pub destination: SocketAddr,
    /// The datagram.
    pub payload: Vec<u8>,
}

/// The stand-in.
pub struct Viewer {
    /// The engine.
    rtc: Rtc,
    /// The viewer's address, its one host candidate.
    addr: SocketAddr,
    /// The candidate is an active ICE-TCP one, as browsers offer
    /// (RFC 6544 §4.1), not UDP.
    tcp: bool,
    /// The offer until the answer is applied.
    pending: Option<SdpPendingOffer>,
    /// The offer's SDP.
    offer: String,
    /// The video mid.
    mid: Mid,
    /// Video RTP received, in arrival order.
    packets: Vec<RtpPacket>,
    /// The audio mid, without an audio m-line `None`.
    audio_mid: Option<Mid>,
    /// The mid talk-back is offered on, without it `None`.
    talkback_mid: Option<Mid>,
    /// The payload types of the offer's audio m-line, empty without one.
    audio_pts: Vec<u8>,
    /// Audio RTP received, in arrival order.
    audio_packets: Vec<RtpPacket>,
    /// ICE states seen.
    ice_states: Vec<IceConnectionState>,
    /// `Event::Connected` seen.
    connected: bool,
    /// `Event::Closed` seen: the daemon's DTLS `close_notify` arrived.
    closed: bool,
    /// The engine's next timeout.
    timeout: Option<Instant>,
}

impl std::fmt::Debug for Viewer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Viewer")
            .field("addr", &self.addr)
            .field("packets", &self.packets.len())
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

/// Whether an RFC 6184 payload starts an IDR access unit: an IDR NAL, a
/// STAP-A carrying one, or the first fragment of one (§5.6, §5.7, §5.8).
pub fn starts_keyframe(payload: &[u8]) -> bool {
    let Some(&first) = payload.first() else {
        return false;
    };
    match first & 0x1f {
        5 => true,
        24 => {
            let mut rest = payload.get(1..).unwrap_or(&[]);
            while let Some((&[hi, lo], tail)) = rest.split_at_checked(2) {
                let len = usize::from(u16::from_be_bytes([hi, lo]));
                let Some((nal, tail)) = tail.split_at_checked(len) else {
                    return false;
                };
                if nal.first().is_some_and(|h| h & 0x1f == 5) {
                    return true;
                }
                rest = tail;
            }
            false
        }
        28 => payload
            .get(1)
            .is_some_and(|fu| fu & 0x80 != 0 && fu & 0x1f == 5),
        _ => false,
    }
}

impl Viewer {
    /// A viewer at `addr` whose offer is ready; `Err` names what the
    /// engine refused (an unroutable address).
    pub fn new(addr: SocketAddr, now: Instant) -> Result<Self, String> {
        Self::with_transport(addr, false, AudioOffer::Off, &[], now)
    }

    /// A viewer whose only video codecs are H.265 entries, one per
    /// `(profile-id, tier-flag, level-id)` (RFC 7798 §7.1), at most three:
    /// a receiver str0m's own entry (Main, Main tier, level 6.0) does not
    /// stand for, such as one that offers only the High tier. Its offer
    /// names exactly the payload types it receives.
    pub fn new_h265(
        addr: SocketAddr,
        now: Instant,
        entries: &[(u8, u8, u8)],
    ) -> Result<Self, String> {
        Self::with_transport(addr, false, AudioOffer::Off, entries, now)
    }

    /// A viewer that also receives audio: a `recvonly` audio m-line before
    /// the video one, as a web player offers them.
    pub fn new_with_audio(addr: SocketAddr, now: Instant) -> Result<Self, String> {
        Self::with_transport(addr, false, AudioOffer::Receive, &[], now)
    }

    /// A viewer that receives audio and offers talk-back the way `offer`
    /// says, with no track to send yet: the browser has not asked for the
    /// microphone.
    pub fn new_with_talkback(
        addr: SocketAddr,
        now: Instant,
        offer: TalkbackOffer,
    ) -> Result<Self, String> {
        Self::with_transport(addr, false, AudioOffer::Talkback(offer), &[], now)
    }

    /// A viewer whose one candidate is an active ICE-TCP one at `addr`, as
    /// a browser on a network that blocks UDP offers it. The caller opens
    /// the connection a TCP [`Outgoing`] asks for and frames it.
    pub fn new_tcp(addr: SocketAddr, now: Instant) -> Result<Self, String> {
        Self::with_transport(addr, true, AudioOffer::Off, &[], now)
    }

    /// A viewer with a UDP or an active ICE-TCP candidate, with or without
    /// audio, with str0m's video codecs or only the `h265` entries. It runs
    /// on str0m's process-default crypto provider, which
    /// the caller installs first with `lotse_webrtc::install_crypto_provider`
    /// (this crate cannot depend on `lotse-webrtc`); without one it is an
    /// error, not str0m's panic.
    fn with_transport(
        addr: SocketAddr,
        tcp: bool,
        audio: AudioOffer,
        h265: &[(u8, u8, u8)],
        now: Instant,
    ) -> Result<Self, String> {
        if CryptoProvider::get_default().is_none() {
            return Err(
                "no crypto provider: call lotse_webrtc::install_crypto_provider() first".to_owned(),
            );
        }
        let mut extensions = ExtensionMap::standard();
        extensions.set(5, Extension::PlayoutDelay);
        // As Chrome offers it when the page asks for it
        // (`setHeaderExtensionsToNegotiate`, as the browser test's page
        // does), under an id of its own: 13 is CVO in str0m's map.
        extensions.set(12, Extension::AbsoluteCaptureTime);
        let mut config = Rtc::builder()
            .set_rtp_mode(true)
            .set_extension_map(extensions);
        if audio != AudioOffer::Off {
            // What browsers offer for audio: Opus, G.722, PCMU and PCMA.
            config = config
                .enable_g722(true, false)
                .enable_pcmu(true, false)
                .enable_pcma(true, false);
        }
        if !h265.is_empty() {
            config = config.clear_codecs();
            for (&(profile, tier, level), (pt, rtx)) in
                h265.iter().zip([(96, 97), (98, 99), (100, 101)])
            {
                config
                    .codec_config()
                    .add_h265(pt.into(), Some(rtx.into()), profile, tier, level);
            }
        }
        let mut rtc = config.build(now);
        let host = if tcp {
            Candidate::builder()
                .tcp()
                .host(addr)
                .tcptype(TcpType::Active)
                .build()
        } else {
            Candidate::host(addr, "udp")
        }
        .map_err(|err| err.to_string())?;
        rtc.add_local_candidate(host);
        let mut api = rtc.sdp_api();
        let downlink = match audio {
            AudioOffer::Off => None,
            AudioOffer::Receive | AudioOffer::Talkback(TalkbackOffer::Dedicated) => {
                Some(Direction::RecvOnly)
            }
            AudioOffer::Talkback(TalkbackOffer::SendRecv) => Some(Direction::SendRecv),
        };
        let audio_mid =
            downlink.map(|direction| api.add_media(MediaKind::Audio, direction, None, None, None));
        let mid = api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
        let talkback_mid = match audio {
            AudioOffer::Talkback(TalkbackOffer::Dedicated) => {
                Some(api.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None))
            }
            AudioOffer::Talkback(TalkbackOffer::SendRecv) => audio_mid,
            AudioOffer::Off | AudioOffer::Receive => None,
        };
        let (offer, pending) = api
            .apply()
            .ok_or_else(|| "the offer has no changes".to_owned())?;
        let offer = offer.to_sdp_string();
        let audio_pts = offer
            .lines()
            .find_map(|line| line.strip_prefix("m=audio "))
            .map(|rest| {
                rest.split(' ')
                    .skip(2)
                    .filter_map(|pt| pt.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            rtc,
            addr,
            tcp,
            pending: Some(pending),
            offer,
            mid,
            packets: Vec::new(),
            audio_mid,
            talkback_mid,
            audio_pts,
            audio_packets: Vec::new(),
            ice_states: Vec::new(),
            connected: false,
            closed: false,
            timeout: None,
        })
    }

    /// The offer's SDP.
    pub fn offer(&self) -> &str {
        &self.offer
    }

    /// The viewer's address.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The video mid.
    pub const fn mid(&self) -> Mid {
        self.mid
    }

    /// The direction the applied answer gives the audio m-line, from the
    /// viewer's side (`recvonly` while the daemon sends, `inactive` when
    /// it sends nothing); `None` without an audio m-line, before the
    /// answer, or when the answer rejected it with port 0 (RFC 3264 §6).
    pub fn audio_direction(&self) -> Option<Direction> {
        if self.pending.is_some() {
            return None;
        }
        self.audio_mid
            .and_then(|mid| self.rtc.media(mid))
            .filter(|media| !media.disabled())
            .map(str0m::media::Media::direction)
    }

    /// The direction the applied answer gives the m-line talk-back is
    /// offered on, from the viewer's side (`sendonly` or `sendrecv` while
    /// the daemon takes talk-back, else `recvonly` or `inactive`); `None`
    /// without talk-back offered, before the answer, or when the answer
    /// rejected it.
    pub fn talkback_direction(&self) -> Option<Direction> {
        if self.pending.is_some() {
            return None;
        }
        self.talkback_mid
            .and_then(|mid| self.rtc.media(mid))
            .filter(|media| !media.disabled())
            .map(str0m::media::Media::direction)
    }

    /// Applies the daemon's answer.
    pub fn accept_answer(&mut self, sdp: &str, out: &mut Vec<Outgoing>) -> Result<(), String> {
        let answer = SdpAnswer::from_sdp_string(sdp).map_err(|err| err.to_string())?;
        let pending = self.pending.take().ok_or("answer already applied")?;
        self.rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .map_err(|err| err.to_string())?;
        self.drain(out);
        Ok(())
    }

    /// A trickled candidate line from the daemon.
    pub fn add_remote_candidate(&mut self, line: &str, out: &mut Vec<Outgoing>) {
        if let Ok(candidate) = Candidate::from_sdp_string(line) {
            self.rtc.add_remote_candidate(candidate);
        }
        self.drain(out);
    }

    /// A datagram from the daemon.
    pub fn receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        bytes: &[u8],
        out: &mut Vec<Outgoing>,
    ) {
        let Ok(contents) = DatagramRecv::try_from(bytes) else {
            return;
        };
        let receive = Receive {
            proto: if self.tcp {
                Protocol::Tcp
            } else {
                Protocol::Udp
            },
            source,
            destination: self.addr,
            contents,
        };
        if self.rtc.handle_input(Input::Receive(now, receive)).is_ok() {
            self.drain(out);
        }
    }

    /// Time passed.
    pub fn timeout(&mut self, now: Instant, out: &mut Vec<Outgoing>) {
        if self.rtc.handle_input(Input::Timeout(now)).is_ok() {
            self.drain(out);
        }
    }

    /// When the viewer next wants [`Viewer::timeout`].
    pub const fn next_timeout(&self) -> Option<Instant> {
        self.timeout
    }

    /// ICE and DTLS are up.
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    /// The daemon closed the transport: its DTLS `close_notify` alert
    /// (RFC 6347 §4.2.7, RFC 5246 §7.2.1) arrived, which str0m reports
    /// as `Event::Closed`.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// The ICE states seen, in order.
    pub fn ice_states(&self) -> &[IceConnectionState] {
        &self.ice_states
    }

    /// The video RTP received so far.
    pub fn packets(&self) -> &[RtpPacket] {
        &self.packets
    }

    /// Takes the video RTP received so far, leaving none: how a long run
    /// keeps its memory flat.
    pub fn take_packets(&mut self) -> Vec<RtpPacket> {
        std::mem::take(&mut self.packets)
    }

    /// The audio RTP packets received, in order.
    pub fn audio_packets(&self) -> &[RtpPacket] {
        &self.audio_packets
    }

    /// Takes the audio RTP packets received so far.
    pub fn take_audio_packets(&mut self) -> Vec<RtpPacket> {
        std::mem::take(&mut self.audio_packets)
    }

    /// How many received packets start an IDR access unit.
    pub fn keyframe_starts(&self) -> usize {
        self.packets
            .iter()
            .filter(|packet| starts_keyframe(&packet.payload))
            .count()
    }

    /// Asks the daemon for a keyframe with a PLI.
    pub fn request_keyframe(&mut self, out: &mut Vec<Outgoing>) {
        if let Some(stream) = self.rtc.direct_api().stream_rx_by_mid(self.mid, None) {
            stream.request_keyframe(KeyframeRequestKind::Pli);
        }
        self.drain(out);
    }

    /// Hangs up the way a browser does: DTLS `close_notify` goes out.
    pub fn close(&mut self, out: &mut Vec<Outgoing>) {
        if let Err(err) = self.rtc.close() {
            tracing::debug!(error = %err, "viewer close");
        }
        self.drain(out);
    }

    /// Collects everything the engine has.
    fn drain(&mut self, out: &mut Vec<Outgoing>) {
        loop {
            match self.rtc.poll_output() {
                Ok(Output::Timeout(at)) => {
                    self.timeout = Some(at);
                    return;
                }
                Ok(Output::Transmit(transmit)) => out.push(Outgoing {
                    tcp: transmit.proto != Protocol::Udp,
                    source: transmit.source,
                    destination: transmit.destination,
                    payload: Vec::from(transmit.contents),
                }),
                Ok(Output::Event(Event::RtpPacket(packet))) => {
                    if self.audio_pts.contains(&*packet.header.payload_type) {
                        self.audio_packets.push(packet);
                    } else {
                        self.packets.push(packet);
                    }
                }
                Ok(Output::Event(Event::IceConnectionStateChange(state))) => {
                    self.ice_states.push(state);
                }
                Ok(Output::Event(Event::Connected)) => self.connected = true,
                Ok(Output::Event(Event::Closed)) => self.closed = true,
                Ok(Output::Event(_)) => {}
                Err(err) => {
                    tracing::debug!(error = %err, "viewer engine error");
                    return;
                }
            }
        }
    }
}

/// The capture time of a received `packet` by its stream's last Sender
/// Report (RFC 3550 §6.4.1), in seconds since the Unix epoch: how a
/// browser lines audio up with video. `None` before the first report.
pub fn capture_seconds(packet: &RtpPacket) -> Option<f64> {
    let sr = packet.last_sender_info?;
    let ntp = sr
        .ntp_time
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    Some(ntp + packet.time.as_seconds() - sr.rtp_time.as_seconds())
}

/// `offer` with its video m-line's codecs replaced by `codecs` (rtpmap,
/// fmtp and rtcp-fb lines, one per line), the payload type list rebuilt
/// from them: how a browser's codec set is tested against the engine
/// without that browser. The lines go at the end of the section, after its
/// `c=` line, where SDP (RFC 8866 §5) puts attributes.
pub fn with_video_codecs(offer: &str, codecs: &str) -> String {
    with_codecs(offer, "m=video", codecs)
}

/// [`with_video_codecs`] for the audio m-lines.
pub fn with_audio_codecs(offer: &str, codecs: &str) -> String {
    with_codecs(offer, "m=audio", codecs)
}

/// `offer` with the codecs of its m-lines starting with `media` replaced
/// by `codecs`.
fn with_codecs(offer: &str, media: &str, codecs: &str) -> String {
    let pts: Vec<&str> = codecs
        .lines()
        .filter_map(|line| line.strip_prefix("a=rtpmap:"))
        .filter_map(|rest| rest.split(' ').next())
        .collect();
    let mut out = String::new();
    let codec_lines = |out: &mut String| {
        for codec in codecs.lines() {
            out.push_str(codec);
            out.push_str("\r\n");
        }
    };
    let mut inside = false;
    for line in offer.lines() {
        if line.starts_with("m=") {
            if inside {
                codec_lines(&mut out);
            }
            inside = line.starts_with(media);
            if inside {
                let prefix: Vec<&str> = line.split(' ').take(3).collect();
                out.push_str(&prefix.join(" "));
                out.push(' ');
                out.push_str(&pts.join(" "));
                out.push_str("\r\n");
                continue;
            }
        }
        let codec_line = ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"]
            .iter()
            .any(|prefix| line.starts_with(prefix));
        if !(inside && codec_line) {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    if inside {
        codec_lines(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use lotse_core::clock::{Clock as _, SystemClock};

    use super::*;

    #[test]
    fn without_a_crypto_provider_there_is_no_viewer() {
        // Nothing in this crate installs one; `lotse_webrtc` does.
        let now = SystemClock.now();
        let err = Viewer::new("192.0.2.20:40000".parse().unwrap(), now).unwrap_err();
        assert!(err.contains("install_crypto_provider"), "{err}");
    }

    #[test]
    fn keyframe_detection_covers_single_nal_stap_a_and_fu_a_rfc6184() {
        assert!(starts_keyframe(&[0x65, 0x88]));
        assert!(!starts_keyframe(&[0x41, 0x9a]));
        assert!(!starts_keyframe(&[]));
        assert!(starts_keyframe(&[24, 0, 1, 0x67, 0, 1, 0x65]));
        assert!(!starts_keyframe(&[24, 0, 1, 0x67, 0, 5, 0x65]));
        assert!(!starts_keyframe(&[24, 0, 1, 0x67]));
        assert!(starts_keyframe(&[28, 0x85, 0]));
        assert!(!starts_keyframe(&[28, 0x05, 0]));
        assert!(!starts_keyframe(&[28, 0x81, 0]));
    }
}
