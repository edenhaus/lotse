//! `ws_message`: the control API's WebSocket server never panics or hangs
//! on whatever a client sends after the upgrade: arbitrary bytes, or
//! well-formed masked frames of any opcode, flags and payload (RFC 6455
//! §5.2), text frames included that reach the command parser. Every
//! message the server sends back is a JSON object with a `type` (RFC 8259)
//! or a close frame, and the server closes the connection once the client
//! half-closed it.
//! Run with `cargo +nightly fuzz run ws_message` from the repository root.
//!
//! One server per process on a Unix socket in a fresh 0700 directory;
//! each input is one connection. The input is `[mode]` then bytes: mode
//! bit 0 sends them raw after the upgrade, otherwise they are frames
//! `[flags and opcode][len][payload]` the harness masks.

#![no_main]

use std::future::Future;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use lotse_api::{Config, ConnectionId, Handler, Outcome, Server};
use lotse_api_types::command::Command;
use lotse_api_types::frame::{Hello, HelloTag};
use lotse_core::clock::SystemClock;
use tokio_util::sync::CancellationToken;

/// Answers every command with an empty result.
struct Answering;

impl Handler for Answering {
    fn hello(&self) -> Hello {
        Hello {
            kind: HelloTag::default(),
            api: lotse_api_types::API_VERSION.into(),
            version: "0.0.0-fuzz".into(),
            outputs: vec![],
            features: vec![],
        }
    }

    fn handle(
        &self,
        _connection: ConnectionId,
        _command: Command,
    ) -> impl Future<Output = Outcome> + Send {
        std::future::ready(Outcome::Result(serde_json::json!({})))
    }
}

/// The server's socket, started once per process.
fn socket() -> &'static PathBuf {
    static SOCKET: OnceLock<PathBuf> = OnceLock::new();
    SOCKET.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("lotse-fuzz-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("a private dir");
        let uid = std::fs::metadata(&dir).expect("its metadata").uid();
        let socket = dir.join("lotse.sock");
        let server = Server::bind(Config {
            socket: socket.clone(),
            owner_uid: uid,
            allow_uid: uid,
            max_connections: 1024,
            max_subscriptions: 1024,
        })
        .expect("the control socket binds");
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            let _ = runtime.block_on(server.serve(
                Arc::new(Answering),
                Arc::new(SystemClock),
                CancellationToken::new(),
            ));
        });
        socket
    })
}

/// A client frame: FIN, RSV and opcode from `flags`, masked (RFC 6455
/// §5.3).
fn frame(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    let mut out = vec![flags];
    match u16::try_from(payload.len()) {
        Ok(len) if len < 126 => out.push(0x80 | u8::try_from(len).unwrap()),
        Ok(len) => {
            out.push(0x80 | 126);
            out.extend_from_slice(&len.to_be_bytes());
        }
        Err(_) => unreachable!("payloads are short"),
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// The server's messages after its upgrade response: text payloads must
/// be JSON objects with a `type`; a close frame ends them.
fn check_server_frames(mut rest: &[u8]) {
    while let Some((&first, tail)) = rest.split_first() {
        let Some((&second, tail)) = tail.split_first() else {
            return;
        };
        assert_eq!(second & 0x80, 0, "server frames are not masked");
        let (len, tail) = match second & 0x7f {
            126 => match tail.split_first_chunk::<2>() {
                Some((len, tail)) => (usize::from(u16::from_be_bytes(*len)), tail),
                None => return,
            },
            127 => match tail.split_first_chunk::<8>() {
                Some((len, tail)) => (usize::try_from(u64::from_be_bytes(*len)).unwrap(), tail),
                None => return,
            },
            len => (usize::from(len), tail),
        };
        let Some((payload, tail)) = tail.split_at_checked(len) else {
            return;
        };
        rest = tail;
        match first & 0x0f {
            0x1 => {
                let value: serde_json::Value =
                    serde_json::from_slice(payload).expect("a text message is JSON");
                assert!(
                    value.get("type").is_some_and(serde_json::Value::is_string),
                    "a message has a type: {value}"
                );
            }
            0x8 => return,
            _ => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut stream = UnixStream::connect(socket()).expect("the server listens");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read timeout");
    stream
        .write_all(
            b"GET /v0/ws HTTP/1.1\r\nHost: lotse\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .expect("the upgrade request goes out");
    // The upgrade completes before the client sends anything else, as a
    // client waits for it; the server's first frames may follow at once.
    let mut answer = Vec::new();
    let head_end = loop {
        if let Some(end) = answer.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let mut chunk = [0_u8; 1024];
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            // libFuzzer's `-timeout` (scripts/fuzz.sh) is a SIGALRM every
            // few seconds, which interrupts a blocking read (EINTR);
            // `read_to_end` below retries on its own.
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => panic!("the upgrade response: {err}"),
        };
        assert_ne!(n, 0, "the server answers the upgrade");
        answer.extend_from_slice(&chunk[..n]);
    };
    assert!(answer.starts_with(b"HTTP/1.1 101"), "upgraded");
    let mut bytes = Vec::new();
    if mode & 1 != 0 {
        bytes.extend_from_slice(rest);
    } else {
        let mut rest = rest;
        while let Some((&flags, tail)) = rest.split_first() {
            let Some((&len, tail)) = tail.split_first() else {
                break;
            };
            let Some((payload, tail)) = tail.split_at_checked(usize::from(len)) else {
                break;
            };
            rest = tail;
            bytes.extend(frame(flags, payload));
        }
    }
    // The server may close before it read everything.
    let _ = stream.write_all(&bytes);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    match stream.read_to_end(&mut answer) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(err) => panic!("the server never closed the connection: {err}"),
    }
    check_server_frames(&answer[head_end..]);
});
