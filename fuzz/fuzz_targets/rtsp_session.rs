//! `rtsp_session`: a camera that answers with arbitrary bytes never panics
//! the RTSP source, never hangs it, and never makes it allocate beyond what
//! the bytes describe. A fake camera on loopback plays the script; the real
//! `RtspSource` connects to it through retina, so every byte from the camera
//! takes the production path: retina's RTSP response parser (RFC 2326 §7,
//! §12.37 `Session`, §12.39 `Transport`, §12.33 `RTP-Info`), its SDP and
//! `fmtp` parsing (RFC 8866, RFC 6184 §8.1 `sprop-parameter-sets`, RFC 7798
//! §7.1 `sprop-vps`, `sprop-sps` and `sprop-pps` with retina's H.265 SPS and
//! PPS parsers, RFC 3640 §4.1 `config`), the interleaved frames (RFC 2326
//! §10.12) with their RTP and RTCP (RFC 3550 §5.1, §6.4.1), then ours: the
//! stream selection and codec declaration, the timestamp guard and new
//! epochs, the H.264, H.265 and AAC normalizers, the track's publication,
//! and the Sender Reports into the clock mapper. Once the camera hangs up
//! the attempt ends with a typed error.
//!
//! The source opts in, so once its session plays it probes the camera's
//! ONVIF backchannel (ONVIF Streaming Specification §5.3.1) with a
//! `DESCRIBE` carrying `Require` on a connection of its own, which the
//! camera answers from the same script, and a fuzzed `a=sendonly` audio
//! media takes the backchannel's path (§5.3.2): retina's stream
//! direction, our reading of its format and `a=ptime` from the raw SDP
//! (RFC 8866 §5.14, §6.4, §6.6, §6.7) and its matching stream; once
//! offered, a talker's claim opens it in a session of its own on a third
//! connection, its `SETUP` alone with the fuzzed answer, its `PLAY`, and
//! one packet through retina's send path. The camera serves the
//! connections side by side.
//! Run with `mise run fuzz rtsp_session`, which passes libFuzzer's time and
//! memory limits (`scripts/fuzz.sh`).
//!
//! The input is `[flags][describe][setup][play]stream`, each middle section
//! a little-endian `u16` length and its bytes. A flag bit set sends that
//! section as the whole response; clear, the section goes into a canned
//! `200 OK`: the SDP body of `DESCRIBE`, the `Transport` of every `SETUP`
//! (empty echoes the request's), the `RTP-Info` of `PLAY` (empty: none).
//! After `PLAY` the stream follows, raw (flag bit 3) or as
//! `[channel][len:u16 le][payload]` records the camera frames, and then the
//! camera closes the connection.
//!
//! Flag bit 4 asks for `transport: "udp"` (RFC 2326 §12.39): the relay's
//! translation of `SETUP` meets the fuzzed `Transport` answer (empty
//! echoes the request's `client_port`, with no `server_port`), and each
//! record goes as a datagram from the camera's address to the client
//! port of the record's stream (channel 0 and 1 the first `SETUP`, RTCP
//! on odd channels), through the relay's datagram checks into retina's
//! interleaved path; a raw stream still goes on the RTSP connection.
//!
//! The URL carries credentials, as a camera's does, and the attempt's
//! error never shows its password unless the camera sent it: the camera
//! records every byte it writes, as it writes them (headers without their
//! CR and LF), and only a password among them may come back quoted.
//! Flag bit 5
//! makes the camera challenge first (RFC 2326 §7.1.1, RFC 7235 §3.1): the
//! first request on each connection, the source's, the backchannel
//! probe's and the talker's, is answered `401 Unauthorized` with a
//! `WWW-Authenticate` header, and the script answers the retried request
//! and the rest as above. retina reads the challenge (RFC 7235 §4.1:
//! RFC 7616 §3.3 Digest, RFC 7617 §2 Basic), sends the request again with
//! `Authorization` (RFC 7616 §3.4, RFC 7617 §2), and keeps sending it on
//! every request of that session; a second `401` (a whole-response
//! section can be one) ends the attempt as a credential failure. With bit
//! 6 clear the challenge is a fixed Digest one. With bit 6 set too, it is
//! the fuzzer's: a fourth section, `[len:u16 le][bytes]` after `[play]`
//! with its CR and LF dropped, cut from the front of the stream, so the
//! input is `[flags][describe][setup][play][challenge]stream`.
//!
//! Bits 5 and 6 were unused before, so a corpus input with bit 5 clear
//! plays as it did; one with bit 5 set and bit 6 clear plays the same
//! script after one Digest round trip; one with both set gives its
//! stream's first bytes to the challenge.

#![no_main]

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::clock_map::ClockMapper;
use lotse_core::media::{MediaPacket, RtpHeaderFields};
use lotse_core::source::{
    BackchannelSlot, ClockInput, ResolvedPeer, SourceCtx, SourceExit, SourceFactory as _, TrackSet,
};
use lotse_core::source_url::SourceUrl;
use lotse_core::track::TrackLimits;
use lotse_rtsp::RtspFactory;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// How long the camera waits for the next request before it hangs up.
const IDLE: Duration = Duration::from_millis(50);

/// The password of the camera URL's credentials; no error may show it.
const PASSWORD: &str = "pw-4e2d81";

/// The challenge of flag bit 5 when bit 6 leaves it to the camera: a
/// Digest one (RFC 7616 §3.3) with the fields retina answers.
const DIGEST: &[u8] = br#"Digest realm="lotse", nonce="4f1c2b", qop="auth", algorithm=MD5"#;

/// The camera's script, cut from the input.
struct Script<'a> {
    /// Which sections are whole responses.
    flags: u8,
    /// The `DESCRIBE` section.
    describe: &'a [u8],
    /// The `SETUP` section.
    setup: &'a [u8],
    /// The `PLAY` section.
    play: &'a [u8],
    /// The `WWW-Authenticate` of the first answer on each connection,
    /// when flag bit 5 asks for one.
    challenge: Option<&'a [u8]>,
    /// What follows `PLAY`.
    stream: &'a [u8],
}

/// Cuts a `[len:u16 le][bytes]` section off the front of `rest`.
fn section<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, tail) = rest.split_first_chunk::<2>()?;
    let (body, tail) = tail.split_at_checked(usize::from(u16::from_le_bytes(*len)))?;
    *rest = tail;
    Some(body)
}

impl<'a> Script<'a> {
    /// The script in `data`, if it is long enough to be one.
    fn parse(data: &'a [u8]) -> Option<Self> {
        let (&flags, mut rest) = data.split_first()?;
        let describe = section(&mut rest)?;
        let setup = section(&mut rest)?;
        let play = section(&mut rest)?;
        let challenge = match flags & 0x60 {
            0x60 => Some(section(&mut rest)?),
            0x20 => Some(DIGEST),
            _ => None,
        };
        Some(Self {
            flags,
            describe,
            setup,
            play,
            challenge,
            stream: rest,
        })
    }

    /// The bytes after `PLAY`.
    fn stream(&self) -> Vec<u8> {
        if self.flags & 8 != 0 {
            return self.stream.to_vec();
        }
        let mut out = Vec::new();
        let mut rest = self.stream;
        while let Some((&channel, tail)) = rest.split_first() {
            rest = tail;
            let Some(payload) = section(&mut rest) else {
                break;
            };
            let Ok(len) = u16::try_from(payload.len()) else {
                break;
            };
            out.push(b'$');
            out.push(channel);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }
}

/// A header value without the bytes that would end the header.
fn header_value(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace(['\r', '\n'], "")
}

/// The records of `stream` as `(channel, payload)`.
fn records(mut rest: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let Some((&channel, tail)) = rest.split_first() {
        rest = tail;
        let Some(payload) = section(&mut rest) else {
            break;
        };
        out.push((channel, payload));
    }
    out
}

/// The first port of a `client_port` parameter, if the transport has one.
fn client_port(transport: &str) -> Option<u16> {
    transport
        .split(';')
        .find_map(|param| param.trim().strip_prefix("client_port="))
        .and_then(|range| range.split('-').next())
        .and_then(|port| port.parse().ok())
}

/// One request's method, CSeq and Transport, read up to its blank line;
/// `None` once the connection ends.
async fn request(socket: &mut TcpStream, buf: &mut Vec<u8>) -> Option<(String, String, String)> {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            buf.drain(..end + 4);
            let method = head.split(' ').next().unwrap_or_default().to_owned();
            let header = |name: &str| {
                head.lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case(name)
                            .then(|| value.trim().to_owned())
                    })
                    .unwrap_or_default()
            };
            return Some((method, header("CSeq"), header("Transport")));
        }
        let mut chunk = [0_u8; 1024];
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Plays `script` to every connection on `listener`, side by side: the
/// backchannel's probe and its session come on connections of their own
/// while the stream's plays. Every byte it sends, on any connection or as
/// a datagram, is appended to `sent`.
async fn camera(listener: TcpListener, base: String, script: Script<'_>, sent: &RefCell<Vec<u8>>) {
    let mut plays: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>>> = Vec::new();
    loop {
        let accepted = std::future::poll_fn(|cx| {
            plays.retain_mut(|play| play.as_mut().poll(cx).is_pending());
            listener.poll_accept(cx)
        })
        .await;
        let Ok((socket, _)) = accepted else {
            return;
        };
        plays.push(Box::pin(play(socket, &base, &script, sent)));
    }
}

/// Plays `script` on `socket`, then hangs up; returns once the source
/// closed its end. What it writes is appended to `sent` first.
async fn play(mut socket: TcpStream, base: &str, script: &Script<'_>, sent: &RefCell<Vec<u8>>) {
    // A reset, not a TIME_WAIT, when the attempt is over: tens of
    // thousands of connections a minute would run out of ports.
    let _ = socket.set_zero_linger();
    let _ = socket.set_nodelay(true);
    let mut buf = Vec::new();
    // The client ports of the streams set up over UDP, in order.
    let mut client_ports = Vec::new();
    // The challenge the connection's first request is answered with.
    let mut challenge = script.challenge;
    // A client that stops asking is waiting for the rest of a response
    // the script cut short: the camera hangs up instead of letting the
    // read deadline run out.
    while let Ok(Some((method, cseq, transport))) =
        tokio::time::timeout(IDLE, request(&mut socket, &mut buf)).await
    {
        let ok = |headers: &str, body: &[u8]| {
            let mut out = format!(
                "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n{headers}Content-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            out.extend_from_slice(body);
            out
        };
        if let Some(www_authenticate) = challenge.take() {
            let reply = format!(
                "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: {}\r\nContent-Length: 0\r\n\r\n",
                header_value(www_authenticate)
            );
            sent.borrow_mut().extend_from_slice(reply.as_bytes());
            if socket.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
            continue;
        }
        let (reply, then_stream) = match method.as_str() {
            "DESCRIBE" if script.flags & 1 != 0 => (script.describe.to_vec(), false),
            "DESCRIBE" => (
                ok(
                    &format!("Content-Type: application/sdp\r\nContent-Base: {base}/\r\n"),
                    script.describe,
                ),
                false,
            ),
            "SETUP" if script.flags & 2 != 0 => {
                client_ports.extend(client_port(&transport));
                (script.setup.to_vec(), false)
            }
            "SETUP" => {
                client_ports.extend(client_port(&transport));
                let given = header_value(script.setup);
                let transport = if given.is_empty() { transport } else { given };
                (
                    ok(
                        &format!("Transport: {transport}\r\nSession: 4f1c2b;timeout=60\r\n"),
                        &[],
                    ),
                    false,
                )
            }
            "PLAY" if script.flags & 4 != 0 => (script.play.to_vec(), true),
            "PLAY" => {
                let info = header_value(script.play);
                let info = if info.is_empty() {
                    String::new()
                } else {
                    format!("RTP-Info: {info}\r\n")
                };
                (ok(&format!("Session: 4f1c2b\r\n{info}"), &[]), true)
            }
            _ => (ok("", &[]), false),
        };
        sent.borrow_mut().extend_from_slice(&reply);
        if socket.write_all(&reply).await.is_err() {
            return;
        }
        if then_stream {
            if script.flags & 0x18 == 0x10 {
                send_datagrams(script, &client_ports, sent).await;
            } else {
                let stream = script.stream();
                sent.borrow_mut().extend_from_slice(&stream);
                let _ = socket.write_all(&stream).await;
            }
            break;
        }
    }
    let _ = socket.shutdown().await;
    // Held open, reading, until the source closes it: the source must end
    // on the hang-up alone.
    let mut sink = [0_u8; 1024];
    while matches!(socket.read(&mut sink).await, Ok(n) if n > 0) {}
}

/// The talker's half: once the source offers a backchannel on `slot`, a
/// claim opens it and puts one 20 ms PCMU packet into it, for retina to
/// send on what the fuzzed SDP and `SETUP` answer made of it.
async fn talk(slot: BackchannelSlot) {
    loop {
        if let Some(offer) = slot.current() {
            let Ok(session) = offer.opener.open().await else {
                break;
            };
            let _ = session.sender.try_send(MediaPacket {
                arrival: std::time::Instant::now(),
                rtp: RtpHeaderFields {
                    pt: 0,
                    seq: 1,
                    ts: 160,
                    marker: true,
                    ssrc: 1,
                },
                frame_start: true,
                keyframe_start: false,
                epoch: 0,
                lateness: Duration::ZERO,
                payload: Arc::from(&[0xff_u8; 160][..]),
            });
            // Held while the source runs.
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    std::future::pending::<()>().await;
}

/// Sends the script's records as datagrams to the client's ports, each
/// appended to `sent` first, then gives the relay a moment to read them
/// before the hang-up.
async fn send_datagrams(script: &Script<'_>, client_ports: &[u16], sent: &RefCell<Vec<u8>>) {
    let Ok(sender) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
        return;
    };
    for (channel, payload) in records(script.stream) {
        let Some(&port) = client_ports.get(usize::from(channel / 2)) else {
            continue;
        };
        let port = port.saturating_add(u16::from(channel & 1));
        sent.borrow_mut().extend_from_slice(payload);
        let _ = sender.send_to(payload, ("127.0.0.1", port)).await;
    }
    tokio::time::sleep(Duration::from_millis(2)).await;
}

fuzz_target!(|data: &[u8]| {
    let Some(script) = Script::parse(data) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async move {
        // Four workers outpace TIME_WAIT and run the ephemeral ports out
        // (macOS, 2026-10-03): wait for a port instead of reporting the
        // machine as a finding.
        let listener = loop {
            match TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => break listener,
                Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(err) => panic!("a loopback port: {err}"),
            }
        };
        let addr = listener.local_addr().expect("its address");
        let base = format!("rtsp://{addr}/stream");
        let url = SourceUrl::parse(&format!("rtsp://user:{PASSWORD}@{addr}/stream")).expect("a source url");
        let transport = if script.flags & 0x10 != 0 {
            "udp"
        } else {
            "tcp"
        };
        let source = RtspFactory::default()
            .validate(
                &url,
                &serde_json::json!({ "timeout_ms": 2_000, "transport": transport, "backchannel": true }),
            )
            .expect("a valid source");
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let tracks = TrackSet::new(TrackLimits::default(), clock.now());
        let mapper = Arc::new(ClockMapper::new());
        let (clock_input, mut reports) = ClockInput::channel(Arc::clone(&mapper));
        let slot = BackchannelSlot::default();
        let ctx = SourceCtx {
            peer: ResolvedPeer {
                host: "127.0.0.1".into(),
                addrs: vec![addr],
            },
            tracks: tracks.publisher(),
            clock: clock_input,
            time: clock,
            backchannel: slot.clone(),
            cancel: CancellationToken::new(),
        };
        // The runner's half: Sender Reports reach the mapper while the
        // packets that follow them are mapped.
        let ingest = async {
            while let Some(report) = reports.recv().await {
                mapper.ingest(report);
            }
            std::future::pending::<()>().await;
        };
        // Every byte the camera sent: the password may come back only
        // when it is among them.
        let sent = RefCell::new(Vec::new());
        let exit = tokio::select! {
            exit = source.run(ctx) => exit,
            () = camera(listener, base, script, &sent) => unreachable!("the camera never ends"),
            () = ingest => unreachable!("the ingest never ends"),
            () = talk(slot) => unreachable!("the talker never ends"),
        };
        let SourceExit::Ended(err) = exit else {
            panic!("an RTSP camera resolves to nothing: {exit:?}");
        };
        let secret = PASSWORD.as_bytes();
        let sent = sent.into_inner();
        if !sent.windows(secret.len()).any(|window| window == secret) {
            assert!(
                !err.to_string().contains(PASSWORD),
                "the error shows the password: {err}"
            );
        }
        for track in tracks.tracks() {
            let _ = mapper.map(track.id(), 0, std::time::Instant::now());
        }
    });
});
