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

#![no_main]

use std::sync::Arc;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::clock_map::ClockMapper;
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
        Some(Self {
            flags,
            describe,
            setup,
            play,
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

/// Plays `script` to the first connection on `listener`, then hangs up.
async fn camera(listener: TcpListener, base: String, script: Script<'_>) {
    let Ok((mut socket, _)) = listener.accept().await else {
        return;
    };
    // A reset, not a TIME_WAIT, when the attempt is over: tens of
    // thousands of connections a minute would run out of ports.
    let _ = socket.set_zero_linger();
    let _ = socket.set_nodelay(true);
    let mut buf = Vec::new();
    // The client ports of the streams set up over UDP, in order.
    let mut client_ports = Vec::new();
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
        if socket.write_all(&reply).await.is_err() {
            return;
        }
        if then_stream {
            if script.flags & 0x18 == 0x10 {
                send_datagrams(&script, &client_ports).await;
            } else {
                let _ = socket.write_all(&script.stream()).await;
            }
            break;
        }
    }
    let _ = socket.shutdown().await;
    // Held open, reading, until the attempt is over and the runtime drops
    // it: the source must end on the hang-up alone.
    let mut sink = [0_u8; 1024];
    while matches!(socket.read(&mut sink).await, Ok(n) if n > 0) {}
    std::future::pending::<()>().await;
}

/// Sends the script's records as datagrams to the client's ports, then
/// gives the relay a moment to read them before the hang-up.
async fn send_datagrams(script: &Script<'_>, client_ports: &[u16]) {
    let Ok(sender) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
        return;
    };
    for (channel, payload) in records(script.stream) {
        let Some(&port) = client_ports.get(usize::from(channel / 2)) else {
            continue;
        };
        let port = port.saturating_add(u16::from(channel & 1));
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
        let url = SourceUrl::parse(&base).expect("a source url");
        let transport = if script.flags & 0x10 != 0 {
            "udp"
        } else {
            "tcp"
        };
        let source = RtspFactory::default()
            .validate(
                &url,
                &serde_json::json!({ "timeout_ms": 2_000, "transport": transport }),
            )
            .expect("a valid source");
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let tracks = TrackSet::new(TrackLimits::default(), clock.now());
        let mapper = Arc::new(ClockMapper::new());
        let (clock_input, mut reports) = ClockInput::channel(Arc::clone(&mapper));
        let ctx = SourceCtx {
            peer: ResolvedPeer {
                host: "127.0.0.1".into(),
                addrs: vec![addr],
            },
            tracks: tracks.publisher(),
            clock: clock_input,
            time: clock,
            backchannel: BackchannelSlot::default(),
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
        let exit = tokio::select! {
            exit = source.run(ctx) => exit,
            () = camera(listener, base, script) => unreachable!("the camera never ends"),
            () = ingest => unreachable!("the ingest never ends"),
        };
        assert!(
            matches!(exit, SourceExit::Ended(_)),
            "an RTSP camera resolves to nothing"
        );
        for track in tracks.tracks() {
            let _ = mapper.map(track.id(), 0, std::time::Instant::now());
        }
    });
});
