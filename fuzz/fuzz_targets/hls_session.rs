//! `hls_session`: an HTTP server that answers with arbitrary playlists,
//! segments, statuses and bytes never panics the HTTP source, never hangs
//! it, and never makes it allocate beyond what the answers describe. A
//! scripted server on loopback serves the input; the real `HttpSource`,
//! built by `HttpFactory`, fetches from it, so every byte takes the
//! production path: hyper's HTTP/1.1 response parser (RFC 9112 §4, §6:
//! status line, fields, `Content-Length` and chunked bodies), redirects
//! (RFC 9110 §15.4) and challenges (RFC 7617, RFC 7616 through
//! http-auth), the sniff of the first answer, the HLS playlist parser and
//! the variant, rendition and live-edge choice (RFC 8216 §4, §6.3), the
//! fetch tasks with their reloads and stall detection (§6.3.2, §6.3.4,
//! §6.2.1), the MPEG-TS demultiplexer (ISO/IEC 13818-1) and the fMP4
//! reader (ISO/IEC 14496-12), the merge of the streams, the pacer, the
//! normalizers and the tracks. The attempt ends with a typed error on its
//! own, or is cancelled once the server keeps it going and ends within the
//! cancel contract; an error never shows the URL's password.
//! Run with `mise run fuzz hls_session`, which passes libFuzzer's time and
//! memory limits (`scripts/fuzz.sh`).
//!
//! The input is `[flags]` and then up to eight resources, served at `/0`
//! to `/7` (the source is `/0`), each `[len:u16 le][kind][bytes]` with
//! `len` counting the kind byte. The kind's low three bits say what the
//! bytes are:
//!
//! - 0: a 200 body, its `Content-Type` from bits 3 and 4 (an HLS
//!   playlist, MPEG-TS, MP4, or none).
//! - 1: the whole response, written as is; then the server hangs up.
//! - 2: an empty answer of status 200 + (first two bytes, LE) % 400, with
//!   `Location: /<third byte % 8>` and a Basic challenge (RFC 7617 §2).
//! - 3: a media playlist built from the bytes (`media_playlist`), live
//!   ones growing by a segment at every load.
//! - 4: a multivariant playlist built from the bytes (`multivariant`).
//! - 5: a recorded segment (`crates/lotse-http/testdata/`) picked by the
//!   first byte, the rest written over it at the offset the next two give.
//! - 6: a 200 whose body stops short of its `Content-Length`.
//! - 7: no answer.
//!
//! Bit 5 closes the connection after the answer (RFC 9112 §9.6); bit 6
//! sends the bodies of kinds 0, 3, 4 and 5 chunked (RFC 9112 §7.1). The
//! flags put credentials in the URL (bit 0), pick `max_bandwidth` (bits 1
//! and 2) and a short `timeout_ms` (bit 3).
//!
//! The source runs on a fake clock that moves 250 ms per real millisecond,
//! so segments, reloads, stalls and deadlines pass quickly; after 2000
//! steps (500 s of its time) a source still playing is cancelled.

#![no_main]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use lotse_core::clock::{Clock, FakeClock};
use lotse_core::clock_map::ClockMapper;
use lotse_core::source::{
    BackchannelSlot, ClockInput, ResolvedPeer, SourceCtx, SourceExit, SourceFactory as _, TrackSet,
};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_core::track::TrackLimits;
use lotse_http::HttpFactory;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// The password of a URL with credentials; no error may show it.
const PASSWORD: &str = "pw-7f3a9c";

/// How far the source's clock moves per real millisecond.
const STEP: Duration = Duration::from_millis(250);

/// How many steps the source plays before it is cancelled.
const STEPS: u32 = 2_000;

/// How long a cancelled source may take to end, in real time: the cancel
/// contract's 100 ms, with room for the sanitizer.
const CANCEL_GRACE: Duration = Duration::from_secs(1);

/// The recorded segments kind 5 serves.
const FIXTURES: [&[u8]; 14] = [
    include_bytes!("../../crates/lotse-http/testdata/live_0.m2t"),
    include_bytes!("../../crates/lotse-http/testdata/live_1.m2t"),
    include_bytes!("../../crates/lotse-http/testdata/live_2.m2t"),
    include_bytes!("../../crates/lotse-http/testdata/h264_aac.m2t"),
    include_bytes!("../../crates/lotse-http/testdata/h265_v1.m2t"),
    include_bytes!("../../crates/lotse-http/testdata/h264_aac_init.mp4"),
    include_bytes!("../../crates/lotse-http/testdata/h264_aac_0.m4s"),
    include_bytes!("../../crates/lotse-http/testdata/h264_aac_1.m4s"),
    include_bytes!("../../crates/lotse-http/testdata/h265_init.mp4"),
    include_bytes!("../../crates/lotse-http/testdata/h265_0.m4s"),
    include_bytes!("../../crates/lotse-http/testdata/split_video_init.mp4"),
    include_bytes!("../../crates/lotse-http/testdata/split_video_0.m4s"),
    include_bytes!("../../crates/lotse-http/testdata/split_audio_init.mp4"),
    include_bytes!("../../crates/lotse-http/testdata/split_audio_0.m4s"),
];

/// The `CODECS` a multivariant playlist's variants pick from (RFC 6381).
const CODECS: [&str; 4] = [
    "avc1.42c00a,mp4a.40.2",
    "avc1.42c00a",
    "hvc1.1.6.L93.B0,mp4a.40.2",
    "mp4a.40.2",
];

/// The `Content-Type`s of kind 0.
const CONTENT_TYPES: [Option<&str>; 4] = [
    Some("application/vnd.apple.mpegurl"),
    Some("video/mp2t"),
    Some("video/mp4"),
    None,
];

/// One resource of the script.
struct Resource<'a> {
    /// The kind byte.
    kind: u8,
    /// The bytes after it.
    bytes: &'a [u8],
}

/// Cuts a `[len:u16 le][bytes]` section off the front of `rest`.
fn section<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, tail) = rest.split_first_chunk::<2>()?;
    let (body, tail) = tail.split_at_checked(usize::from(u16::from_le_bytes(*len)))?;
    *rest = tail;
    Some(body)
}

/// The script: the flags and the resources by number.
fn script(data: &[u8]) -> Option<(u8, Vec<Resource<'_>>)> {
    let (&flags, mut rest) = data.split_first()?;
    let mut resources = Vec::new();
    while resources.len() < 8 {
        let Some(section) = section(&mut rest) else {
            break;
        };
        let Some((&kind, bytes)) = section.split_first() else {
            break;
        };
        resources.push(Resource { kind, bytes });
    }
    Some((flags, resources))
}

/// A media playlist from `bytes`, as its `load`th load shows it. The first
/// byte: target duration 1 to 4 s (bits 0 and 1), `EXT-X-ENDLIST` once
/// every segment is out (bit 2), live (bit 3: the playlist grows by one
/// segment per load and keeps the last three), `EXT-X-MAP` (bit 4),
/// `EXT-X-START` (bit 5). The second: the map's resource (bits 0 to 2) and
/// the first media sequence number. Every later byte a segment: its
/// resource (bits 0 to 2), an `EXT-X-DISCONTINUITY` before it (bit 3), its
/// duration in half seconds (bits 4 to 6, plus one).
fn media_playlist(bytes: &[u8], load: usize) -> String {
    let head = bytes.first().copied().unwrap_or_default();
    let second = bytes.get(1).copied().unwrap_or_default();
    let segments = bytes.get(2..).unwrap_or_default();
    let (lo, hi) = if head & 8 != 0 {
        let hi = segments.len().min(load.saturating_add(1));
        (hi.saturating_sub(3), hi)
    } else {
        (0, segments.len())
    };
    let mut text = format!(
        "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:{}\n#EXT-X-MEDIA-SEQUENCE:{}\n",
        (head & 3) + 1,
        u64::from(second >> 3) + lo as u64
    );
    if head & 16 != 0 {
        let _ = writeln!(text, "#EXT-X-MAP:URI=\"/{}\"", second & 7);
    }
    if head & 32 != 0 {
        text.push_str("#EXT-X-START:TIME-OFFSET=-2\n");
    }
    for &segment in &segments[lo..hi] {
        if segment & 8 != 0 {
            text.push_str("#EXT-X-DISCONTINUITY\n");
        }
        let duration = f64::from(((segment >> 4) & 7) + 1) / 2.0;
        let _ = write!(text, "#EXTINF:{duration:.3},\n/{}\n", segment & 7);
    }
    if head & 4 != 0 && hi == segments.len() {
        text.push_str("#EXT-X-ENDLIST\n");
    }
    text
}

/// A multivariant playlist from `bytes`. The first byte: an audio
/// rendition in group `a` (bit 0) at the resource of bits 5 to 7, its
/// `DEFAULT` (bit 1). Every later pair a variant: its `CODECS` (bits 0 and
/// 1), whether it names the audio group (bit 2), its resource (bits 3 to
/// 5); its `BANDWIDTH` from the second byte.
fn multivariant(bytes: &[u8]) -> String {
    let head = bytes.first().copied().unwrap_or_default();
    let mut text = String::from("#EXTM3U\n#EXT-X-VERSION:7\n");
    if head & 1 != 0 {
        let _ = writeln!(
            text,
            "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",NAME=\"a\",DEFAULT={},URI=\"/{}\"",
            if head & 2 != 0 { "YES" } else { "NO" },
            head >> 5
        );
    }
    for pair in bytes.get(1..).unwrap_or_default().chunks_exact(2) {
        let (variant, bandwidth) = (pair[0], pair[1]);
        let audio = if variant & 4 != 0 { ",AUDIO=\"a\"" } else { "" };
        let _ = write!(
            text,
            "#EXT-X-STREAM-INF:BANDWIDTH={},CODECS=\"{}\"{audio}\n/{}\n",
            u32::from(bandwidth) * 10_000 + 1,
            CODECS[usize::from(variant & 3)],
            (variant >> 3) & 7
        );
    }
    text
}

/// A recorded segment picked by `bytes`, overwritten by its rest.
fn fixture(bytes: &[u8]) -> Vec<u8> {
    let pick = bytes.first().copied().unwrap_or_default();
    let mut out = FIXTURES[usize::from(pick) % FIXTURES.len()].to_vec();
    if let Some((offset, patch)) = bytes
        .get(1..)
        .and_then(|rest| rest.split_first_chunk::<2>())
    {
        let offset = usize::from(u16::from_le_bytes(*offset)) % out.len().max(1);
        for (byte, &new) in out.iter_mut().skip(offset).zip(patch) {
            *byte = new;
        }
    }
    out
}

/// What the server does with one request.
enum Answer {
    /// Writes these bytes, then closes the connection or keeps it.
    Write(Vec<u8>, bool),
    /// Writes these bytes and holds the connection without answering on.
    Hold(Vec<u8>),
}

/// A 200 with `body`, chunked or not.
fn ok(content_type: Option<&str>, body: &[u8], close: bool, chunked: bool) -> Vec<u8> {
    let mut head = String::from("HTTP/1.1 200 OK\r\n");
    if let Some(content_type) = content_type {
        let _ = write!(head, "Content-Type: {content_type}\r\n");
    }
    if close {
        head.push_str("Connection: close\r\n");
    }
    let mut out;
    if chunked {
        head.push_str("Transfer-Encoding: chunked\r\n\r\n");
        out = head.into_bytes();
        let (first, second) = body.split_at(body.len() / 2);
        for chunk in [first, second] {
            if !chunk.is_empty() {
                out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                out.extend_from_slice(chunk);
                out.extend_from_slice(b"\r\n");
            }
        }
        out.extend_from_slice(b"0\r\n\r\n");
    } else {
        let _ = write!(head, "Content-Length: {}\r\n\r\n", body.len());
        out = head.into_bytes();
        out.extend_from_slice(body);
    }
    out
}

/// The answer to the `load`th request for `resource`.
fn answer(resource: Option<&Resource<'_>>, load: usize) -> Answer {
    let Some(Resource { kind, bytes }) = resource else {
        return Answer::Write(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            false,
        );
    };
    let close = kind & 0x20 != 0;
    let chunked = kind & 0x40 != 0;
    let playlist = Some("application/vnd.apple.mpegurl");
    match kind & 7 {
        0 => Answer::Write(
            ok(
                CONTENT_TYPES[usize::from((kind >> 3) & 3)],
                bytes,
                close,
                chunked,
            ),
            close,
        ),
        1 => Answer::Write(bytes.to_vec(), true),
        2 => {
            let code = bytes
                .first_chunk::<2>()
                .map_or(200, |code| 200 + u16::from_le_bytes(*code) % 400);
            let location = bytes.get(2).copied().unwrap_or_default() % 8;
            Answer::Write(
                format!(
                    "HTTP/1.1 {code} Fuzz\r\nLocation: /{location}\r\nWWW-Authenticate: Basic realm=\"fuzz\"\r\nContent-Length: 0\r\n{}\r\n",
                    if close { "Connection: close\r\n" } else { "" }
                )
                .into_bytes(),
                close,
            )
        }
        3 => Answer::Write(
            ok(
                playlist,
                media_playlist(bytes, load).as_bytes(),
                close,
                chunked,
            ),
            close,
        ),
        4 => Answer::Write(
            ok(playlist, multivariant(bytes).as_bytes(), close, chunked),
            close,
        ),
        5 => Answer::Write(
            ok(Some("video/mp2t"), &fixture(bytes), close, chunked),
            close,
        ),
        6 => {
            let mut out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nContent-Length: {}\r\n\r\n",
                bytes.len() + 1
            )
            .into_bytes();
            out.extend_from_slice(bytes);
            Answer::Hold(out)
        }
        _ => Answer::Hold(Vec::new()),
    }
}

/// The request target of one request read up to its blank line, without
/// its query; `None` once the connection ends.
async fn request(socket: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            buf.drain(..end + 4);
            let target = head.split(' ').nth(1).unwrap_or_default();
            return Some(target.split('?').next().unwrap_or_default().to_owned());
        }
        let mut chunk = [0_u8; 1024];
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Serves one connection from `resources`, counting the loads.
async fn connection(
    mut socket: TcpStream,
    resources: Arc<Vec<(u8, Vec<u8>)>>,
    loads: Arc<Mutex<HashMap<usize, usize>>>,
) {
    // A reset, not a TIME_WAIT, when the attempt is over: thousands of
    // connections a minute would run out of ports.
    let _ = socket.set_zero_linger();
    let _ = socket.set_nodelay(true);
    let mut buf = Vec::new();
    while let Some(target) = request(&mut socket, &mut buf).await {
        let index = target
            .strip_prefix('/')
            .and_then(|n| n.parse::<usize>().ok());
        let load = index.map_or(0, |index| {
            let mut loads = loads.lock().expect("not poisoned");
            let count = loads.entry(index).or_default();
            *count += 1;
            *count - 1
        });
        let resource = index
            .and_then(|index| resources.get(index))
            .map(|(kind, bytes)| Resource { kind: *kind, bytes });
        match answer(resource.as_ref(), load) {
            Answer::Write(bytes, close) => {
                if socket.write_all(&bytes).await.is_err() || close {
                    break;
                }
            }
            Answer::Hold(bytes) => {
                let _ = socket.write_all(&bytes).await;
                std::future::pending::<()>().await;
            }
        }
    }
    let _ = socket.shutdown().await;
    // Held open until the runtime drops it: the source ends on its own.
    let mut sink = [0_u8; 1024];
    while matches!(socket.read(&mut sink).await, Ok(n) if n > 0) {}
    std::future::pending::<()>().await;
}

/// Accepts connections on `listener` and serves each from `resources`.
async fn server(listener: TcpListener, resources: Vec<(u8, Vec<u8>)>) {
    let resources = Arc::new(resources);
    let loads = Arc::new(Mutex::new(HashMap::new()));
    while let Ok((socket, _)) = listener.accept().await {
        drop(spawn_named(
            "fuzz.connection",
            connection(socket, Arc::clone(&resources), Arc::clone(&loads)),
        ));
    }
    std::future::pending::<()>().await;
}

fuzz_target!(|data: &[u8]| {
    let Some((flags, resources)) = script(data) else {
        return;
    };
    let resources: Vec<(u8, Vec<u8>)> = resources
        .into_iter()
        .map(|resource| (resource.kind, resource.bytes.to_vec()))
        .collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async move {
        // Wait for a port instead of reporting the machine as a finding.
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
        let userinfo = if flags & 1 != 0 {
            format!("user:{PASSWORD}@")
        } else {
            String::new()
        };
        let url = SourceUrl::parse(&format!("http://{userinfo}{addr}/0")).expect("a source url");
        let mut options = serde_json::json!({
            "timeout_ms": if flags & 8 != 0 { 500 } else { 10_000 },
        });
        match (flags >> 1) & 3 {
            0 => {}
            1 => options["max_bandwidth"] = 1.into(),
            2 => options["max_bandwidth"] = 100_000.into(),
            _ => options["max_bandwidth"] = 10_000_000.into(),
        }
        let source = HttpFactory
            .validate(&url, &options)
            .expect("a valid source");
        let clock = Arc::new(FakeClock::from_system());
        let time: Arc<dyn Clock> = Arc::<FakeClock>::clone(&clock);
        let tracks = TrackSet::new(TrackLimits::default(), time.now());
        let mapper = Arc::new(ClockMapper::new());
        let (clock_input, _reports) = ClockInput::channel(Arc::clone(&mapper));
        let cancel = CancellationToken::new();
        let ctx = SourceCtx {
            peer: ResolvedPeer {
                host: "127.0.0.1".into(),
                addrs: vec![addr],
            },
            tracks: tracks.publisher(),
            clock: clock_input,
            time,
            backchannel: BackchannelSlot::default(),
            cancel: cancel.clone(),
        };
        let run = source.run(ctx);
        tokio::pin!(run);
        let serve = server(listener, resources);
        tokio::pin!(serve);
        let mut exit = None;
        for _ in 0..STEPS {
            tokio::select! {
                done = &mut run => {
                    exit = Some(done);
                    break;
                }
                () = &mut serve => unreachable!("the server never ends"),
                () = tokio::time::sleep(Duration::from_millis(1)) => clock.advance(STEP),
            }
        }
        let exit = match exit {
            Some(exit) => exit,
            None => {
                cancel.cancel();
                tokio::select! {
                    done = &mut run => done,
                    () = &mut serve => unreachable!("the server never ends"),
                    () = tokio::time::sleep(CANCEL_GRACE) => {
                        panic!("the source did not end within {CANCEL_GRACE:?} of its cancel")
                    }
                }
            }
        };
        let SourceExit::Ended(err) = exit else {
            panic!("an HTTP source resolves to nothing: {exit:?}");
        };
        let secret = PASSWORD.as_bytes();
        if !data.windows(secret.len()).any(|window| window == secret) {
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
