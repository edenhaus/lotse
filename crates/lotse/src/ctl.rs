//! `lotse ctl`: the debugging client over the control socket.
//!
//! Speaks the WebSocket API like any other client: connect, `hello`, one
//! command, its `result`, and for a subscription the events after it.
//! Results and events are printed as JSON on stdout, the one place in the
//! binary that writes there; a failed result prints its `error` and exits 1.

#![expect(
    clippy::print_stdout,
    reason = "`lotse ctl` output is the one stdout writer in the binary (Cargo.toml lints)"
)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Args, Subcommand};
use futures_util::{SinkExt as _, StreamExt as _};
use lotse_api_types::{API_VERSION, ApiVersion, WS_PATH};
use serde_json::{Map, Value, json};
use tokio::net::UnixStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

/// `lotse ctl`.
#[derive(Debug, Args)]
pub(crate) struct CtlArgs {
    /// The daemon's control socket.
    #[arg(long, env = "LOTSE_SOCKET", value_name = "PATH")]
    pub(crate) socket: PathBuf,

    /// One line of JSON per result instead of pretty output; events are
    /// always one per line.
    #[arg(long)]
    pub(crate) compact: bool,

    /// What to ask.
    #[command(subcommand)]
    pub(crate) command: CtlCommand,
}

/// The commands.
#[derive(Debug, Subcommand)]
pub(crate) enum CtlCommand {
    /// Version, build, schemes, outputs, codecs, limits and sandbox.
    Info,
    /// Process and stream counters.
    Metrics,
    /// The JSON Schema bundle of the API.
    Schema,
    /// Streams.
    Stream {
        /// What to do.
        #[command(subcommand)]
        command: StreamCommand,
    },
    /// Send one command as written and print every frame up to its result;
    /// `id` is filled in when missing.
    Raw {
        /// The command, a JSON object with a `type`.
        json: String,
    },
}

/// `lotse ctl stream ...`.
#[derive(Debug, Subcommand)]
pub(crate) enum StreamCommand {
    /// Every stream.
    List,
    /// One stream.
    Get {
        /// The stream.
        stream_id: String,
    },
    /// Create or update a stream's desired state.
    Put {
        /// The stream.
        stream_id: String,
        /// A source URL; repeat for several sources. The command line is
        /// visible to every user of the host (`ps`, `/proc/<pid>/cmdline`)
        /// and stays in the shell history: give a URL with credentials
        /// through `--url-file` instead.
        #[arg(
            long = "url",
            value_name = "URL",
            required_unless_present = "url_file",
            conflicts_with = "url_file"
        )]
        urls: Vec<String>,
        /// Read the source URLs from this file, or from stdin with `-`,
        /// one per line (blank lines skipped), so credentials stay off the
        /// command line.
        #[arg(long, value_name = "PATH|-")]
        url_file: Option<PathBuf>,
        /// Per-scheme options as a JSON object, applied to every source.
        #[arg(long, value_name = "JSON")]
        options: Option<String>,
        /// Keep the stream connected without viewers.
        #[arg(long)]
        preload: bool,
        /// Audio handling: `auto` or `off`.
        #[arg(long, value_name = "auto|off", default_value = "auto")]
        audio: String,
    },
    /// Delete a stream; succeeds when it does not exist.
    Delete {
        /// The stream.
        stream_id: String,
    },
    /// Print the state of every stream (or one), then every change, one
    /// event per line, until the daemon goes away or the limit is reached.
    Subscribe {
        /// One stream instead of all.
        stream_id: Option<String>,
        /// Stop after this many events.
        #[arg(long, value_name = "N")]
        limit: Option<u64>,
    },
}

/// Runs the command on a small runtime of its own; the exit code is 0 for
/// a successful result, 1 for a failed one.
pub(crate) fn run(args: &CtlArgs) -> anyhow::Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("runtime")?;
    runtime.block_on(async {
        let mut client = Client::connect(&args.socket).await?;
        match &args.command {
            CtlCommand::Raw { json } => {
                let command: Value =
                    serde_json::from_str(json).context("the raw command is not JSON")?;
                client.raw(command, args.compact).await
            }
            CtlCommand::Stream {
                command: StreamCommand::Subscribe { stream_id, limit },
            } => client.subscribe(stream_id.as_deref(), *limit).await,
            other => {
                let command = command_of(other, std::io::stdin().lock())?;
                let frame = client.call(command).await?;
                Ok(report(&frame, args.compact))
            }
        }
    })
}

/// The command frame (without `id`) a subcommand sends; `stdin` is read
/// only for `stream put --url-file -`.
fn command_of(command: &CtlCommand, stdin: impl Read) -> anyhow::Result<Value> {
    Ok(match command {
        CtlCommand::Info => json!({ "type": "info" }),
        CtlCommand::Metrics => json!({ "type": "metrics/get" }),
        CtlCommand::Schema => json!({ "type": "schema" }),
        CtlCommand::Stream { command } => match command {
            StreamCommand::List => json!({ "type": "stream/list" }),
            StreamCommand::Get { stream_id } => {
                json!({ "type": "stream/get", "stream_id": stream_id })
            }
            StreamCommand::Delete { stream_id } => {
                json!({ "type": "stream/delete", "stream_id": stream_id })
            }
            StreamCommand::Put {
                stream_id,
                urls,
                url_file,
                options,
                preload,
                audio,
            } => {
                let urls = source_urls(urls, url_file.as_deref(), stdin)?;
                anyhow::ensure!(
                    audio == "auto" || audio == "off",
                    "--audio must be `auto` or `off`, not {audio:?}"
                );
                let options: Map<String, Value> = match options {
                    Some(text) => {
                        serde_json::from_str(text).context("--options is not a JSON object")?
                    }
                    None => Map::new(),
                };
                let sources: Vec<Value> = urls
                    .iter()
                    .map(|url| json!({ "url": url, "options": options }))
                    .collect();
                json!({ "type": "stream/put", "stream_id": stream_id, "sources": sources,
                        "preload": preload, "audio": audio })
            }
            StreamCommand::Subscribe { .. } => anyhow::bail!("subscribe is streamed, not called"),
        },
        CtlCommand::Raw { .. } => anyhow::bail!("raw is sent as written"),
    })
}

/// The source URLs of `stream put`: the `--url`s, or the lines of
/// `--url-file` (`-` is `stdin`), trimmed, blank ones skipped. An error
/// names the file, never its text, which holds credentials.
fn source_urls(
    urls: &[String],
    url_file: Option<&Path>,
    stdin: impl Read,
) -> anyhow::Result<Vec<String>> {
    let Some(path) = url_file else {
        return Ok(urls.to_vec());
    };
    let (text, from) = if path == Path::new("-") {
        let text = std::io::read_to_string(stdin).context("reading the source URLs from stdin")?;
        (text, "stdin".to_owned())
    } else {
        let from = path.display().to_string();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the source URLs from {from}"))?;
        (text, from)
    };
    let urls: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    anyhow::ensure!(!urls.is_empty(), "{from} holds no source URL");
    Ok(urls)
}

/// Prints one JSON value.
fn print(value: &Value, compact: bool) {
    if compact {
        println!("{value}");
    } else {
        // The alternate form is serde_json's pretty printer.
        println!("{value:#}");
    }
}

/// The `type` of a frame.
fn kind(frame: &Value) -> Option<&str> {
    frame.get("type").and_then(Value::as_str)
}

/// The `id` of a frame.
fn id_of(frame: &Value) -> Option<u64> {
    frame.get("id").and_then(Value::as_u64)
}

/// Prints a command's outcome: the `result` on success, `{ "error": ... }`
/// on failure, a `pong` as is. The exit code follows.
fn report(frame: &Value, compact: bool) -> ExitCode {
    if kind(frame) == Some("pong") {
        print(frame, compact);
        return ExitCode::SUCCESS;
    }
    if frame.get("success").and_then(Value::as_bool) == Some(true) {
        print(frame.get("result").unwrap_or(&Value::Null), compact);
        ExitCode::SUCCESS
    } else {
        print(
            &json!({ "error": frame.get("error").cloned().unwrap_or(Value::Null) }),
            compact,
        );
        ExitCode::FAILURE
    }
}

/// One control connection.
struct Client {
    /// The WebSocket over the Unix socket.
    ws: WebSocketStream<UnixStream>,
    /// The next command id; strictly increasing per connection.
    next_id: u64,
}

/// Accepts a `hello` whose API version this client can use
/// ([`ApiVersion::accepts`]).
fn check_hello(hello: &Value) -> anyhow::Result<()> {
    anyhow::ensure!(kind(hello) == Some("hello"), "expected hello, got {hello}");
    let api = hello.get("api").and_then(Value::as_str);
    anyhow::ensure!(
        api.and_then(ApiVersion::parse)
            .is_some_and(|daemon| lotse_api_types::version::CURRENT.accepts(daemon)),
        "the daemon speaks api {api:?}, this client api {API_VERSION}"
    );
    Ok(())
}

impl Client {
    /// Connects, upgrades and reads `hello`.
    async fn connect(socket: &Path) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connecting to {}", socket.display()))?;
        let (ws, _response) =
            tokio_tungstenite::client_async(format!("ws://lotse{WS_PATH}"), stream)
                .await
                .context("websocket upgrade refused")?;
        let mut client = Self { ws, next_id: 1 };
        let hello = client
            .next()
            .await?
            .context("the daemon closed the connection before hello")?;
        check_hello(&hello)?;
        Ok(client)
    }

    /// The next JSON frame, or `None` once the connection is closed.
    async fn next(&mut self) -> anyhow::Result<Option<Value>> {
        loop {
            match self.ws.next().await {
                None | Some(Ok(Message::Close(_))) => return Ok(None),
                Some(Err(err)) => return Err(err).context("reading from the daemon"),
                Some(Ok(Message::Text(text))) => {
                    return serde_json::from_str(&text)
                        .map(Some)
                        .context("the daemon sent a frame that is not JSON");
                }
                Some(Ok(
                    Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_),
                )) => {}
            }
        }
    }

    /// Sends `command` with an id, returning the id.
    async fn send(&mut self, mut command: Value) -> anyhow::Result<u64> {
        let object = command
            .as_object_mut()
            .context("a command is a JSON object")?;
        let given = object.get("id").and_then(Value::as_u64);
        let id = given.unwrap_or(self.next_id);
        if given.is_none() {
            object.insert("id".to_owned(), json!(id));
        }
        self.next_id = id.saturating_add(1);
        self.ws
            .send(Message::Text(command.to_string().into()))
            .await
            .context("sending the command")?;
        Ok(id)
    }

    /// Sends `command` and returns its `result` (or `pong`), skipping
    /// anything else.
    async fn call(&mut self, command: Value) -> anyhow::Result<Value> {
        let id = self.send(command).await?;
        loop {
            let frame = self
                .next()
                .await?
                .context("the daemon closed the connection before the result")?;
            if kind(&frame) == Some("shutdown") {
                anyhow::bail!("the daemon is shutting down");
            }
            if id_of(&frame) == Some(id) && matches!(kind(&frame), Some("result" | "pong")) {
                return Ok(frame);
            }
        }
    }

    /// Sends `command` as written and prints every frame up to its result.
    async fn raw(&mut self, command: Value, compact: bool) -> anyhow::Result<ExitCode> {
        let id = self.send(command).await?;
        loop {
            let frame = self
                .next()
                .await?
                .context("the daemon closed the connection before the result")?;
            print(&frame, compact);
            if kind(&frame) == Some("shutdown") {
                return Ok(ExitCode::FAILURE);
            }
            if id_of(&frame) == Some(id) && matches!(kind(&frame), Some("result" | "pong")) {
                let failed = frame.get("success").and_then(Value::as_bool) == Some(false);
                return Ok(if failed {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                });
            }
        }
    }

    /// `stream/subscribe`, printing one event per line.
    async fn subscribe(
        &mut self,
        stream_id: Option<&str>,
        limit: Option<u64>,
    ) -> anyhow::Result<ExitCode> {
        let mut command = json!({ "type": "stream/subscribe" });
        if let (Some(stream_id), Some(object)) = (stream_id, command.as_object_mut()) {
            object.insert("stream_id".to_owned(), json!(stream_id));
        }
        let id = self.send(command).await?;
        let result = self.call_result(id).await?;
        if result.get("success").and_then(Value::as_bool) != Some(true) {
            return Ok(report(&result, true));
        }
        let mut seen = 0_u64;
        while limit.is_none_or(|limit| seen < limit) {
            let Some(frame) = self.next().await? else {
                break;
            };
            match kind(&frame) {
                Some("event") if id_of(&frame) == Some(id) => {
                    print(frame.get("event").unwrap_or(&Value::Null), true);
                    seen = seen.saturating_add(1);
                }
                Some("shutdown") => break,
                _ => {}
            }
        }
        Ok(ExitCode::SUCCESS)
    }

    /// The `result` of the command already sent as `id`.
    async fn call_result(&mut self, id: u64) -> anyhow::Result<Value> {
        loop {
            let frame = self
                .next()
                .await?
                .context("the daemon closed the connection before the result")?;
            if kind(&frame) == Some("shutdown") {
                anyhow::bail!("the daemon is shutting down");
            }
            if id_of(&frame) == Some(id) && kind(&frame) == Some("result") {
                return Ok(frame);
            }
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

    use super::*;

    #[test]
    fn hello_is_accepted_only_at_a_compatible_api_version() {
        let hello = |api: Value| json!({ "type": "hello", "api": api, "version": "0.0.0" });
        assert!(check_hello(&hello(json!(API_VERSION))).is_ok());
        assert!(
            check_hello(&hello(json!("0.1.7"))).is_ok(),
            "a later patch only adds"
        );
        for api in [
            json!("0.2.0"),
            json!("1.1.0"),
            json!("0.1"),
            json!(1),
            Value::Null,
        ] {
            let err = check_hello(&hello(api.clone())).unwrap_err().to_string();
            assert!(err.contains("the daemon speaks api"), "{api}: {err}");
        }
        let err = check_hello(&json!({ "type": "result" }))
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("expected hello"), "{err}");
    }

    #[test]
    fn subcommands_map_onto_command_frames() {
        assert_eq!(
            command_of(&CtlCommand::Info, b"".as_slice()).unwrap(),
            json!({ "type": "info" })
        );
        assert_eq!(
            command_of(&CtlCommand::Metrics, b"".as_slice()).unwrap(),
            json!({ "type": "metrics/get" })
        );
        assert_eq!(
            command_of(&CtlCommand::Schema, b"".as_slice()).unwrap(),
            json!({ "type": "schema" })
        );
        let stream = |command| CtlCommand::Stream { command };
        assert_eq!(
            command_of(&stream(StreamCommand::List), b"".as_slice()).unwrap(),
            json!({ "type": "stream/list" })
        );
        assert_eq!(
            command_of(
                &stream(StreamCommand::Get {
                    stream_id: "front".into()
                }),
                b"".as_slice()
            )
            .unwrap(),
            json!({ "type": "stream/get", "stream_id": "front" })
        );
        assert_eq!(
            command_of(
                &stream(StreamCommand::Delete {
                    stream_id: "front".into()
                }),
                b"".as_slice()
            )
            .unwrap(),
            json!({ "type": "stream/delete", "stream_id": "front" })
        );
        let put = |options: Option<&str>, audio: &str| {
            stream(StreamCommand::Put {
                stream_id: "front".into(),
                urls: vec!["rtsp://cam/a".into(), "rtsp://cam/b".into()],
                url_file: None,
                options: options.map(str::to_owned),
                preload: true,
                audio: audio.into(),
            })
        };
        assert_eq!(
            command_of(&put(Some(r#"{"transport":"tcp"}"#), "off"), b"".as_slice()).unwrap(),
            json!({ "type": "stream/put", "stream_id": "front", "preload": true, "audio": "off",
                    "sources": [ { "url": "rtsp://cam/a", "options": { "transport": "tcp" } },
                                 { "url": "rtsp://cam/b", "options": { "transport": "tcp" } } ] })
        );
        assert_eq!(
            command_of(&put(None, "auto"), b"".as_slice()).unwrap()["sources"][0]["options"],
            json!({})
        );
        let err = command_of(&put(None, "loud"), b"".as_slice()).unwrap_err();
        assert!(err.to_string().contains("--audio"), "{err}");
        let err = command_of(&put(Some("[]"), "auto"), b"".as_slice()).unwrap_err();
        assert!(err.to_string().contains("--options"), "{err}");
        assert!(
            command_of(
                &stream(StreamCommand::Subscribe {
                    stream_id: None,
                    limit: None
                }),
                b"".as_slice()
            )
            .is_err()
        );
        assert!(command_of(&CtlCommand::Raw { json: "{}".into() }, b"".as_slice()).is_err());
    }

    #[test]
    fn stream_put_reads_its_urls_from_a_file_or_stdin_off_the_command_line() {
        let put = |url_file: &str| CtlCommand::Stream {
            command: StreamCommand::Put {
                stream_id: "front".into(),
                urls: Vec::new(),
                url_file: Some(PathBuf::from(url_file)),
                options: None,
                preload: false,
                audio: "auto".into(),
            },
        };
        let urls = |frame: Value| -> Vec<Value> {
            frame["sources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|source| source["url"].clone())
                .collect()
        };
        let stdin = "  rtsp://user:secret@cam/a \r\n\n\trtsp://cam/b\n";
        assert_eq!(
            urls(command_of(&put("-"), stdin.as_bytes()).unwrap()),
            [json!("rtsp://user:secret@cam/a"), json!("rtsp://cam/b")]
        );
        let dir = std::env::temp_dir().join(format!("lotse-ctl-urls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("urls");
        std::fs::write(&file, "rtsp://user:secret@cam/c\n").unwrap();
        let path = file.to_str().unwrap();
        assert_eq!(
            urls(command_of(&put(path), b"rtsp://ignored/".as_slice()).unwrap()),
            [json!("rtsp://user:secret@cam/c")]
        );
        // No URL in the file is an error naming it and nothing it holds.
        std::fs::write(&file, " \n\n").unwrap();
        let err = command_of(&put(path), b"".as_slice()).unwrap_err();
        assert_eq!(err.to_string(), format!("{path} holds no source URL"));
        let err = command_of(&put("-"), b"".as_slice()).unwrap_err();
        assert_eq!(err.to_string(), "stdin holds no source URL");
        let missing = dir.join("missing");
        let missing = missing.to_str().unwrap();
        let err = command_of(&put(missing), b"".as_slice()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("reading the source URLs from {missing}")
        );
        let err = command_of(&put("-"), [0xff_u8].as_slice()).unwrap_err();
        assert_eq!(err.to_string(), "reading the source URLs from stdin");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn results_report_success_failure_and_pong() {
        let ok =
            json!({ "type": "result", "id": 1, "success": true, "result": { "created": true } });
        assert_eq!(report(&ok, true), ExitCode::SUCCESS);
        let failed = json!({ "type": "result", "id": 1, "success": false,
                             "error": { "code": "stream_not_found", "message": "no" } });
        assert_eq!(report(&failed, false), ExitCode::FAILURE);
        let pong = json!({ "type": "pong", "id": 1 });
        assert_eq!(report(&pong, true), ExitCode::SUCCESS);
        assert_eq!(kind(&pong), Some("pong"));
        assert_eq!(id_of(&pong), Some(1));
    }

    /// One step of a scripted daemon.
    enum Step {
        /// Read the client's next frame, a command, and keep it.
        Read,
        /// Send this frame.
        Send(Message),
        /// Drop the connection without a closing handshake.
        Drop,
    }

    /// A text frame of `value`.
    fn text(value: &Value) -> Step {
        Step::Send(Message::text(value.to_string()))
    }

    /// A daemon that accepts one connection on `listener` and upgrades it,
    /// sends `hello` when `greet` and plays `script`; unless that ends in
    /// [`Step::Drop`], it then reads on until the client is gone, so the
    /// client answers a ping or reads to the end without a broken pipe.
    /// Returns the commands it read.
    async fn daemon(
        listener: tokio::net::UnixListener,
        greet: bool,
        script: Vec<Step>,
    ) -> Vec<Value> {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        if greet {
            let hello = json!({ "type": "hello", "api": API_VERSION, "version": "0" });
            ws.send(Message::text(hello.to_string())).await.unwrap();
        }
        let mut read = Vec::new();
        for step in script {
            match step {
                Step::Read => {
                    let frame = ws.next().await.unwrap().unwrap();
                    read.push(serde_json::from_str(frame.to_text().unwrap()).unwrap());
                }
                Step::Send(message) => {
                    // The client may be gone already, as after `--limit`.
                    let _client_gone = ws.send(message).await;
                }
                Step::Drop => return read,
            }
        }
        while let Some(Ok(_frame)) = ws.next().await {}
        read
    }

    /// Runs `client` against a [`daemon`] playing `script` on a fresh
    /// socket; returns what the client returned and the commands the daemon
    /// read.
    async fn against<T>(
        test: &str,
        greet: bool,
        script: Vec<Step>,
        client: impl AsyncFnOnce(&Path) -> T,
    ) -> (T, Vec<Value>) {
        let dir = std::env::temp_dir().join(format!("lotse-ctl-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("lotse.sock");
        let _stale = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (out, read) = tokio::join!(client(&socket), daemon(listener, greet, script));
        std::fs::remove_dir_all(&dir).unwrap();
        (out, read)
    }

    /// Connects and runs `command` through [`Client::call`].
    async fn call(socket: &Path, command: Value) -> anyhow::Result<Value> {
        Client::connect(socket).await?.call(command).await
    }

    #[tokio::test]
    async fn call_numbers_the_command_and_skips_everything_but_its_result() {
        let script = vec![
            Step::Read,
            Step::Send(Message::Ping(b"ping".to_vec().into())),
            Step::Send(Message::Binary(b"binary".to_vec().into())),
            text(&json!({ "type": "event", "id": 1, "event": {} })),
            text(&json!({ "type": "result", "id": 2, "success": true })),
            text(&json!({ "type": "result", "id": 1, "success": true, "result": {} })),
        ];
        let (frame, read) = against("call", true, script, async |socket| {
            call(socket, json!({ "type": "stream/list" }))
                .await
                .unwrap()
        })
        .await;
        assert_eq!(
            frame,
            json!({ "type": "result", "id": 1, "success": true, "result": {} })
        );
        assert_eq!(read, [json!({ "type": "stream/list", "id": 1 })]);
    }

    #[tokio::test]
    async fn call_fails_on_shutdown_close_a_dropped_connection_and_a_non_json_frame() {
        let cases = [
            (
                text(&json!({ "type": "shutdown" })),
                "the daemon is shutting down",
            ),
            (
                Step::Send(Message::Close(None)),
                "the daemon closed the connection before the result",
            ),
            (Step::Drop, "reading from the daemon"),
            (
                Step::Send(Message::text("not json")),
                "the daemon sent a frame that is not JSON",
            ),
        ];
        for (n, (last, expected)) in cases.into_iter().enumerate() {
            let script = vec![Step::Read, last];
            let (err, _read) = against(&format!("call-fails-{n}"), true, script, async |socket| {
                call(socket, json!({ "type": "info" })).await.unwrap_err()
            })
            .await;
            assert_eq!(err.to_string(), expected, "{err:#}");
        }
    }

    #[tokio::test]
    async fn connect_fails_without_an_upgrade_a_hello_or_a_compatible_api() {
        // No upgrade: the listener closes the connection unanswered.
        let dir = std::env::temp_dir().join(format!("lotse-ctl-no-upgrade-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("lotse.sock");
        let _stale = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (connected, ()) = tokio::join!(Client::connect(&socket), async {
            drop(listener.accept().await.unwrap());
        });
        let err = connected.err().unwrap();
        assert_eq!(err.to_string(), "websocket upgrade refused", "{err:#}");
        std::fs::remove_dir_all(&dir).unwrap();

        let (err, _read) = against("no-hello", false, vec![Step::Drop], async |socket| {
            Client::connect(socket).await.err().unwrap()
        })
        .await;
        assert_eq!(err.to_string(), "reading from the daemon", "{err:#}");
        let (err, _read) = against(
            "closed-hello",
            false,
            vec![Step::Send(Message::Close(None))],
            async |socket| Client::connect(socket).await.err().unwrap(),
        )
        .await;
        assert_eq!(
            err.to_string(),
            "the daemon closed the connection before hello"
        );
        let (err, _read) = against(
            "old-hello",
            false,
            vec![text(&json!({ "type": "hello", "api": "9.0.0" }))],
            async |socket| Client::connect(socket).await.err().unwrap(),
        )
        .await;
        assert!(err.to_string().contains("the daemon speaks api"), "{err:#}");
    }

    #[tokio::test]
    async fn raw_keeps_a_given_id_and_prints_every_frame_up_to_its_result() {
        let script = vec![
            Step::Read,
            text(&json!({ "type": "event", "id": 1, "event": {} })),
            text(&json!({ "type": "pong", "id": 7 })),
            Step::Read,
            text(&json!({ "type": "result", "id": 8, "success": false, "error": {} })),
            Step::Read,
            text(&json!({ "type": "result", "id": 9, "success": true, "result": {} })),
            Step::Read,
            text(&json!({ "type": "shutdown" })),
            // The last command, then the connection is dropped.
            Step::Read,
            Step::Drop,
        ];
        let (codes, read) = against("raw", true, script, async |socket| {
            let mut client = Client::connect(socket).await.unwrap();
            let mut codes = Vec::new();
            for command in [
                json!({ "type": "ping", "id": 7 }),
                json!({ "type": "stream/get" }),
                json!({ "type": "stream/list" }),
                json!({ "type": "info" }),
            ] {
                codes.push(client.raw(command, true).await.unwrap());
            }
            let err = client.raw(json!([]), true).await.unwrap_err();
            assert_eq!(err.to_string(), "a command is a JSON object");
            let err = client
                .raw(json!({ "type": "info" }), false)
                .await
                .unwrap_err();
            assert_eq!(err.to_string(), "reading from the daemon", "{err:#}");
            codes
        })
        .await;
        assert_eq!(
            codes,
            [
                ExitCode::SUCCESS,
                ExitCode::FAILURE,
                ExitCode::SUCCESS,
                ExitCode::FAILURE
            ]
        );
        let ids: Vec<Option<u64>> = read.iter().map(id_of).collect();
        assert_eq!(
            ids,
            [Some(7), Some(8), Some(9), Some(10), Some(11)],
            "numbered on from a given id"
        );
    }

    #[tokio::test]
    async fn raw_fails_when_the_connection_closes_before_the_result() {
        let script = vec![Step::Read, Step::Send(Message::Close(None))];
        let (err, _read) = against("raw-closed", true, script, async |socket| {
            let mut client = Client::connect(socket).await.unwrap();
            client
                .raw(json!({ "type": "info" }), true)
                .await
                .unwrap_err()
        })
        .await;
        assert_eq!(
            err.to_string(),
            "the daemon closed the connection before the result"
        );
    }

    /// `subscribe` against a daemon that answers its command with `result`
    /// and then sends `then`; the exit code and the command it read.
    async fn subscribe(
        test: &str,
        stream_id: Option<&str>,
        limit: Option<u64>,
        result: Value,
        then: Vec<Step>,
    ) -> (anyhow::Result<ExitCode>, Value) {
        let mut script = vec![
            Step::Read,
            text(&json!({ "type": "event", "id": 1, "event": {} })),
            text(&result),
        ];
        script.extend(then);
        let (code, read) = against(test, true, script, async |socket| {
            Client::connect(socket)
                .await
                .unwrap()
                .subscribe(stream_id, limit)
                .await
        })
        .await;
        (code, read.into_iter().next().unwrap())
    }

    #[tokio::test]
    async fn subscribe_prints_its_events_until_the_limit_a_close_or_shutdown() {
        let ok = json!({ "type": "result", "id": 1, "success": true, "result": {} });
        let events = || {
            vec![
                text(&json!({ "type": "event", "id": 1, "event": { "n": 1 } })),
                text(&json!({ "type": "event", "id": 2, "event": { "n": 0 } })),
                text(&json!({ "type": "pong", "id": 1 })),
                text(&json!({ "type": "event", "id": 1, "event": { "n": 2 } })),
            ]
        };
        let (code, command) =
            subscribe("sub-limit", Some("front"), Some(2), ok.clone(), events()).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(
            command,
            json!({ "type": "stream/subscribe", "stream_id": "front", "id": 1 })
        );
        let mut closed = events();
        closed.push(Step::Send(Message::Close(None)));
        let (code, command) = subscribe("sub-close", None, None, ok.clone(), closed).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(command, json!({ "type": "stream/subscribe", "id": 1 }));
        let mut shutdown = events();
        shutdown.push(text(&json!({ "type": "shutdown" })));
        let (code, _command) = subscribe("sub-shutdown", None, None, ok, shutdown).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn subscribe_reports_a_failed_result_and_fails_without_one() {
        let failed = json!({ "type": "result", "id": 1, "success": false, "error": {} });
        let (code, _command) = subscribe("sub-failed", None, None, failed, Vec::new()).await;
        assert_eq!(code.unwrap(), ExitCode::FAILURE);
        let shutdown = json!({ "type": "shutdown" });
        let (code, _command) =
            subscribe("sub-shutdown-first", None, None, shutdown, Vec::new()).await;
        assert_eq!(code.unwrap_err().to_string(), "the daemon is shutting down");
        let close = json!({ "type": "pong", "id": 1 });
        let (code, _command) = subscribe(
            "sub-closed-first",
            None,
            None,
            close,
            vec![Step::Send(Message::Close(None))],
        )
        .await;
        assert_eq!(
            code.unwrap_err().to_string(),
            "the daemon closed the connection before the result"
        );
    }
}
