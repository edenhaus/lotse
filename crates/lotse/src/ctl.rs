//! `lotse ctl`: the debugging client over the control socket.
//!
//! Speaks the WebSocket API like any other client: connect, `hello`, one
//! command, its `result`, and for a subscription the events after it.
//! Results and events are printed as JSON on stdout, which only this and
//! `lotse identity` write to; a failed result prints its `error` and exits 1.
//! `stream clip` also fetches the clip's file over HTTP on a second
//! connection to the same socket (`GET /v0/clips/{clip_id}`), as any client
//! does.

#![expect(
    clippy::print_stdout,
    reason = "`lotse ctl` output is one of the binary's two stdout writers, with `lotse identity` (Cargo.toml lints)"
)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Args, Subcommand};
use futures_util::{SinkExt as _, Stream, StreamExt as _};
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::StatusCode;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use lotse_api_types::{API_VERSION, ApiVersion, WS_PATH};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::signal::unix::SignalKind;
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
    /// The control TLS listener's clients.
    Clients {
        /// What to do.
        #[command(subcommand)]
        command: ClientsCommand,
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
        /// Keep this much of the stream's last media in memory for event
        /// clips (`30s`, `500ms`, `2m`); none when not given. It fills only
        /// while the stream is connected for `--preload` or a viewer.
        #[arg(long, value_name = "DURATION", value_parser = duration_ms)]
        preroll: Option<u32>,
    },
    /// Record an event clip into a file: start it, write its fragmented MP4
    /// as it comes and print its events, one per line. Ctrl-C stops the
    /// clip and its file ends whole; a second Ctrl-C leaves at once. Exits 0
    /// when the file is whole and the clip ended as asked.
    Clip {
        /// The stream.
        stream_id: String,
        /// How far back the clip starts, out of the stream's pre-roll
        /// window (`10s`, `500ms`, `2m`).
        #[arg(long, value_name = "DURATION", default_value = "0s", value_parser = duration_ms)]
        before: u32,
        /// How long the clip runs from now on; without it, until Ctrl-C or
        /// the daemon's `limits.clip_max_ms`.
        #[arg(long, value_name = "DURATION", value_parser = duration_ms)]
        after: Option<u32>,
        /// Leave the audio out.
        #[arg(long)]
        no_audio: bool,
        /// The file the clip is written to; created, or emptied first.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
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

/// `lotse ctl clients ...`.
#[derive(Debug, Subcommand)]
pub(crate) enum ClientsCommand {
    /// Every client certificate pin the TLS listener lets in, fixed by the
    /// configuration or enrolled by pairing.
    List,
    /// Remove an enrolled client and close its connections; succeeds when
    /// it is not enrolled.
    Remove {
        /// The client certificate's SHA-256, 64 hex digits, optionally with
        /// a colon between each pair.
        pin: String,
    },
}

/// `lotse pair`.
#[derive(Debug, Args)]
pub(crate) struct PairArgs {
    /// The daemon's control socket.
    #[arg(long, env = "LOTSE_SOCKET", value_name = "PATH")]
    pub(crate) socket: PathBuf,
}

/// `future` on a small runtime of its own. The runtime is left without
/// waiting for its blocking threads: a write to the clip's file that never
/// returns (a FIFO nobody reads) would otherwise hold the process after a
/// second Ctrl-C gave up on it.
fn on_runtime<T>(future: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("runtime")?;
    let out = runtime.block_on(future);
    runtime.shutdown_background();
    out
}

/// Asks the daemon for a pairing code (`pairing/create`) and prints the
/// code alone, to be copied into the client; a refusal prints the error
/// and exits 1.
pub(crate) fn pair(args: &PairArgs) -> anyhow::Result<ExitCode> {
    on_runtime(async {
        let mut client = Client::connect(&args.socket).await?;
        let frame = client.call(json!({ "type": "pairing/create" })).await?;
        let code = frame
            .get("result")
            .and_then(|result| result.get("code"))
            .and_then(Value::as_str);
        Ok(match code {
            Some(code) => {
                println!("{code}");
                ExitCode::SUCCESS
            }
            None => report(&frame, false),
        })
    })
}

/// Runs the command on a small runtime of its own; the exit code is 0 for
/// a successful result, 1 for a failed one.
pub(crate) fn run(args: &CtlArgs) -> anyhow::Result<ExitCode> {
    on_runtime(async {
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
            CtlCommand::Stream {
                command:
                    StreamCommand::Clip {
                        stream_id,
                        before,
                        after,
                        no_audio,
                        output,
                    },
            } => {
                // Opened before Ctrl-C has a handler, so one still ends an
                // open that blocks (a FIFO without its reader).
                let file = create(output)?;
                let interrupts = interrupts()?;
                let command = clip_command(stream_id, *before, *after, *no_audio);
                let out = (file, args.compact);
                client.clip(&args.socket, command, out, interrupts).await
            }
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
        CtlCommand::Clients { command } => match command {
            ClientsCommand::List => json!({ "type": "clients/list" }),
            ClientsCommand::Remove { pin } => json!({ "type": "clients/remove", "pin": pin }),
        },
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
                preroll,
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
                let mut put = json!({ "type": "stream/put", "stream_id": stream_id,
                                      "sources": sources, "preload": preload, "audio": audio });
                if let (Some(ms), Some(object)) = (preroll, put.as_object_mut()) {
                    object.insert("preroll_ms".to_owned(), json!(ms));
                }
                put
            }
            StreamCommand::Subscribe { .. } => anyhow::bail!("subscribe is streamed, not called"),
            StreamCommand::Clip { .. } => anyhow::bail!("clip is streamed, not called"),
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

/// A duration on the command line in milliseconds: a whole number with
/// the unit `ms`, `s` or `m`, at most `u32::MAX` ms.
fn duration_ms(text: &str) -> Result<u32, String> {
    let invalid = || format!("{text:?} is not a duration like 500ms, 10s or 2m");
    let at = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at_checked(at).ok_or_else(invalid)?;
    let scale: u64 = match unit {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        _ => return Err(invalid()),
    };
    let number: u64 = number.parse().map_err(|_| invalid())?;
    number
        .checked_mul(scale)
        .and_then(|ms| u32::try_from(ms).ok())
        .ok_or_else(invalid)
}

/// The `clip/start` of `stream clip`; `after_ms` only when given, so the
/// clip is open-ended without it.
fn clip_command(stream_id: &str, before_ms: u32, after_ms: Option<u32>, no_audio: bool) -> Value {
    let mut command = json!({ "type": "clip/start", "stream_id": stream_id,
                              "before_ms": before_ms, "audio": !no_audio });
    if let (Some(ms), Some(object)) = (after_ms, command.as_object_mut()) {
        object.insert("after_ms".to_owned(), json!(ms));
    }
    command
}

/// The stop reasons of a clip that ended as asked: its file is what was
/// asked for.
const CLIP_ENDED_AS_ASKED: [&str; 3] = ["completed", "stopped", "max_duration"];

/// The most of a refused `GET`'s error body `stream clip` reads and prints.
const MAX_ERROR_BODY: usize = 64 * 1024;

/// What stops `stream clip`: one item per Ctrl-C in the binary, a scripted
/// stream in the tests. One type, not a generic, so the code that takes it
/// is compiled once.
type Interrupts = Pin<Box<dyn Stream<Item = ()> + Send>>;

/// Where `stream clip` writes the clip's file: the file on a blocking
/// thread in the binary ([`create`]), a scripted writer in the tests.
/// Asynchronous, so a write that blocks (a full FIFO, a stalled network
/// filesystem) holds the body alone, never the runtime that reads the
/// clip's events and Ctrl-C.
type Output = Pin<Box<dyn AsyncWrite + Send>>;

/// The clip's file at `path`, created or emptied, written through tokio's
/// blocking pool one write at a time: at most one write is in flight, so
/// a file that takes no bytes holds back the body, not the process.
fn create(path: &Path) -> anyhow::Result<Output> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("creating the clip's file {}", path.display()))?;
    Ok(Box::pin(tokio::fs::File::from_std(file)))
}

/// Ctrl-C (`SIGINT`), one item per press. The handler is in place once
/// this returns, so a press after it never ends the process.
fn interrupts() -> anyhow::Result<Interrupts> {
    let signal =
        tokio::signal::unix::signal(SignalKind::interrupt()).context("listening for Ctrl-C")?;
    let presses = futures_util::stream::unfold(signal, |mut signal| async move {
        signal.recv().await.map(|()| ((), signal))
    });
    Ok(Box::pin(presses.fuse()))
}

/// `GET url` of a clip's body on a connection of its own to `socket`
/// (HTTP/1.1, RFC 9112), written to `file` as it comes; the bytes written.
/// An error when the daemon refuses (its status and error body), or when
/// the body ends without its last chunk (RFC 9112 §7.1): the clip's file is
/// then cut, and holds what came. The bytes count once `file` has them all.
async fn fetch(socket: &Path, url: &str, file: &mut Output) -> anyhow::Result<u64> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connecting for the clip's file")?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("the clip's HTTP connection")?;
    let request = hyper::Request::get(url)
        .header(hyper::header::HOST, "lotse")
        .body(Empty::<Bytes>::new())
        .context("the clip's request")?;
    let body = async move {
        let response = sender
            .send_request(request)
            .await
            .context("asking for the clip's file")?;
        let status = response.status();
        let mut body = response.into_body();
        if status != StatusCode::OK {
            let text = Limited::new(body, MAX_ERROR_BODY).collect().await;
            let text = text
                .map(http_body_util::Collected::to_bytes)
                .unwrap_or_default();
            anyhow::bail!("GET {url}: {status} {}", String::from_utf8_lossy(&text));
        }
        let mut written = 0_u64;
        while let Some(frame) = body.frame().await {
            let frame = frame.context("the clip's file is cut")?;
            // A data frame; trailers, which the route never sends, write
            // nothing.
            let data = frame.into_data().unwrap_or_default();
            file.write_all(&data)
                .await
                .context("writing the clip's file")?;
            written = written.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        }
        // The last write may still be in flight; its error shows here.
        file.flush().await.context("writing the clip's file")?;
        Ok(written)
    };
    // The connection ends with the body: the daemon closes it after one.
    let (written, _connection) = tokio::join!(body, connection);
    written
}

/// How the events of `stream clip`'s clip ended.
enum ClipEnd {
    /// Its `stopped`, with the reason (empty without one).
    Stopped(String),
    /// The connection closed or the daemon shut down first.
    Gone,
}

/// What `frame`, read on `stream clip`'s connection, says of the clip
/// subscribed as `id`: an event of it is printed; the end once there is
/// one, `None` while the clip runs on.
fn clip_end(frame: &Value, id: u64) -> Option<ClipEnd> {
    match kind(frame) {
        Some("event") if id_of(frame) == Some(id) => {
            let event = frame.get("event").unwrap_or(&Value::Null);
            print(event, true);
            (kind(event) == Some("stopped")).then(|| {
                let reason = event.get("reason").and_then(Value::as_str);
                ClipEnd::Stopped(reason.unwrap_or_default().to_owned())
            })
        }
        Some("shutdown") => Some(ClipEnd::Gone),
        _ => None,
    }
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

    /// `stream clip`: sends `command`, a `clip/start`, prints its result,
    /// then writes the clip's body to `output.0` while the clip's events
    /// print, one per line, until both have ended, in whichever order. The
    /// first of `interrupts` stops the clip (`clip/stop`, unless it has
    /// ended), the second gives up, whether the events or the body is still
    /// awaited. A refused or cut body is an error and ends the connection,
    /// which stops the clip; the exit code is 0 when the file is whole and
    /// the clip ended as asked.
    async fn clip(
        &mut self,
        socket: &Path,
        command: Value,
        output: (Output, bool),
        mut interrupts: Interrupts,
    ) -> anyhow::Result<ExitCode> {
        let (mut file, compact) = output;
        let id = self.send(command).await?;
        let frame = self.call_result(id).await?;
        if frame.get("success").and_then(Value::as_bool) != Some(true) {
            return Ok(report(&frame, compact));
        }
        let result = frame.get("result").unwrap_or(&Value::Null);
        print(result, compact);
        let field = |name: &str| {
            let value = result.get(name).and_then(Value::as_str).map(str::to_owned);
            value.with_context(|| format!("the clip/start result has no {name}"))
        };
        let (clip_id, url) = (field("clip_id")?, field("url")?);
        let body = fetch(socket, &url, &mut file);
        tokio::pin!(body);
        // The body and the events run on separate connections, so either
        // may end first; Ctrl-C counts across both.
        let (mut whole, mut ended, mut stopping) = (false, None, false);
        while !whole || ended.is_none() {
            tokio::select! {
                biased;
                written = &mut body, if !whole => {
                    // A refused or cut body ends it at once.
                    written?;
                    whole = true;
                }
                frame = self.next(), if ended.is_none() => {
                    ended = match frame? {
                        Some(frame) => clip_end(&frame, id),
                        None => Some(ClipEnd::Gone),
                    };
                }
                Some(()) = interrupts.next() => {
                    anyhow::ensure!(!stopping, "interrupted again; the clip's file may be cut");
                    stopping = true;
                    if ended.is_none() {
                        self.send(json!({ "type": "clip/stop", "clip_id": clip_id })).await?;
                    } else {
                        tracing::debug!(clip.id = %clip_id, "the clip has ended; its body is still coming");
                    }
                }
            }
        }
        let as_asked = matches!(&ended, Some(ClipEnd::Stopped(reason))
                                if CLIP_ENDED_AS_ASKED.contains(&reason.as_str()));
        Ok(if as_asked {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
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
    use tokio::io::AsyncReadExt as _;

    #[test]
    fn hello_is_accepted_only_at_a_compatible_api_version() {
        let hello = |api: Value| json!({ "type": "hello", "api": api, "version": "0.0.0" });
        let current = lotse_api_types::version::CURRENT;
        assert!(check_hello(&hello(json!(API_VERSION))).is_ok());
        assert!(
            check_hello(&hello(json!(format!(
                "{}.{}.{}",
                current.major,
                current.minor,
                current.patch + 7
            ))))
            .is_ok(),
            "a later patch only adds"
        );
        for api in [
            json!(format!("{}.{}.0", current.major, current.minor + 1)),
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
        let clients = |command| CtlCommand::Clients { command };
        assert_eq!(
            command_of(&clients(ClientsCommand::List), b"".as_slice()).unwrap(),
            json!({ "type": "clients/list" })
        );
        assert_eq!(
            command_of(
                &clients(ClientsCommand::Remove { pin: "ab".into() }),
                b"".as_slice()
            )
            .unwrap(),
            json!({ "type": "clients/remove", "pin": "ab" })
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
                preroll: None,
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
                preroll: None,
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
        /// Serve the next connection on the socket as HTTP: read the
        /// request's head (kept as a string), write `response`, then close
        /// at once when `cut`, else wait for the client to close.
        Http { response: Vec<u8>, cut: bool },
        /// As [`Step::Http`], but hold the connection open and go on with
        /// the script: the body has more to come.
        HttpHold(Vec<u8>),
        /// Write this on the connection [`Step::HttpHold`] holds, then wait
        /// for the client to close it.
        HttpRest(Vec<u8>),
        /// Let the client run before the next step: what was sent so far
        /// reaches it first.
        Yield,
    }

    /// A text frame of `value`.
    fn text(value: &Value) -> Step {
        Step::Send(Message::text(value.to_string()))
    }

    /// A daemon that accepts one connection on `listener` and upgrades it,
    /// sends `hello` when `greet` and plays `script`; unless that ends in
    /// [`Step::Drop`], it then reads on until the client is gone, so the
    /// client answers a ping or reads to the end without a broken pipe, and
    /// keeps the commands among what it reads. Returns the commands it read.
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
        let mut held = None;
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
                Step::Http { response, cut } => {
                    let mut http = serve_head(&listener, &mut read).await;
                    http.write_all(&response).await.unwrap();
                    if !cut {
                        let _until_closed = http.read_to_end(&mut Vec::new()).await;
                    }
                }
                Step::HttpHold(response) => {
                    let mut http = serve_head(&listener, &mut read).await;
                    http.write_all(&response).await.unwrap();
                    held = Some(http);
                }
                Step::HttpRest(rest) => {
                    let mut http = held.take().unwrap();
                    http.write_all(&rest).await.unwrap();
                    let _until_closed = http.read_to_end(&mut Vec::new()).await;
                }
                Step::Yield => tokio::task::yield_now().await,
            }
        }
        while let Some(Ok(frame)) = ws.next().await {
            if let Ok(command) = serde_json::from_str(frame.to_text().unwrap_or_default()) {
                read.push(command);
            }
        }
        read
    }

    /// Accepts the next connection on `listener` and reads an HTTP request's
    /// head off it into `read`, as a string.
    async fn serve_head(listener: &tokio::net::UnixListener, read: &mut Vec<Value>) -> UnixStream {
        let (mut http, _addr) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(http.read_u8().await.unwrap());
        }
        read.push(Value::String(String::from_utf8(head).unwrap()));
        http
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

    #[test]
    fn durations_take_a_unit_and_fit_in_milliseconds() {
        assert_eq!(duration_ms("500ms"), Ok(500));
        assert_eq!(duration_ms("10s"), Ok(10_000));
        assert_eq!(duration_ms("2m"), Ok(120_000));
        assert_eq!(duration_ms("0s"), Ok(0));
        assert_eq!(duration_ms("4294967295ms"), Ok(u32::MAX));
        for bad in [
            "10",
            "s",
            "1.5s",
            "10h",
            "-1s",
            "4294968s",
            "99999999999999999999ms",
        ] {
            assert_eq!(
                duration_ms(bad),
                Err(format!("{bad:?} is not a duration like 500ms, 10s or 2m")),
                "{bad}"
            );
        }
    }

    #[test]
    fn stream_clip_and_put_with_a_window_map_onto_their_commands() {
        assert_eq!(
            clip_command("front", 10_000, Some(30_000), true),
            json!({ "type": "clip/start", "stream_id": "front", "before_ms": 10_000,
                    "after_ms": 30_000, "audio": false })
        );
        assert_eq!(
            clip_command("front", 0, None, false),
            json!({ "type": "clip/start", "stream_id": "front", "before_ms": 0, "audio": true })
        );
        let put = CtlCommand::Stream {
            command: StreamCommand::Put {
                stream_id: "front".into(),
                urls: vec!["rtsp://cam/a".into()],
                url_file: None,
                options: None,
                preload: true,
                audio: "auto".into(),
                preroll: Some(30_000),
            },
        };
        assert_eq!(
            command_of(&put, b"".as_slice()).unwrap()["preroll_ms"],
            json!(30_000)
        );
        let clip = CtlCommand::Stream {
            command: StreamCommand::Clip {
                stream_id: "front".into(),
                before: 0,
                after: None,
                no_audio: false,
                output: PathBuf::from("clip.mp4"),
            },
        };
        assert!(command_of(&clip, b"".as_slice()).is_err());
    }

    /// The `clip/start` result of clip `k1`.
    fn clip_started() -> Step {
        text(&json!({ "type": "result", "id": 1, "success": true,
                      "result": { "clip_id": "k1", "url": "/v0/clips/k1" } }))
    }

    /// The event `event` of the clip's subscription.
    fn clip_event(event: &Value) -> Step {
        text(&json!({ "type": "event", "id": 1, "event": event }))
    }

    /// `stopped` with `reason`.
    fn stopped(reason: &str) -> Step {
        clip_event(&json!({ "type": "stopped", "reason": reason, "bytes": 8 }))
    }

    /// A `200` whose chunked body is `chunks`, ended by the last chunk
    /// unless `cut` (RFC 9112 §7.1), on a connection that closes after it.
    fn clip_body(chunks: &[&str], cut: bool) -> Step {
        let mut response = String::from(
            "HTTP/1.1 200 OK\r\ncontent-type: video/mp4\r\ntransfer-encoding: chunked\r\n\
             connection: close\r\n\r\n",
        );
        for chunk in chunks {
            std::fmt::Write::write_fmt(
                &mut response,
                format_args!("{:x}\r\n{chunk}\r\n", chunk.len()),
            )
            .unwrap();
        }
        if !cut {
            response.push_str("0\r\n\r\n");
        }
        Step::Http {
            response: response.into_bytes(),
            cut,
        }
    }

    /// `stream clip` of `front` (`command`, from [`clip_command`]) with
    /// `interrupts` against a daemon that plays `script`; what the client
    /// returned, the file it wrote and what the daemon read.
    async fn record(
        test: &str,
        command: Value,
        interrupts: usize,
        script: Vec<Step>,
    ) -> (anyhow::Result<ExitCode>, Vec<u8>, Vec<Value>) {
        let dir =
            std::env::temp_dir().join(format!("lotse-ctl-file-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("clip.mp4");
        let (code, read) = against(test, true, script, async |socket| {
            let interrupts = Box::pin(futures_util::stream::iter(vec![(); interrupts]));
            let mut client = Client::connect(socket).await.unwrap();
            let output = create(&file).unwrap();
            client
                .clip(socket, command, (output, true), interrupts)
                .await
        })
        .await;
        let written = std::fs::read(&file).unwrap_or_default();
        std::fs::remove_dir_all(&dir).unwrap();
        (code, written, read)
    }

    #[tokio::test]
    async fn stream_clip_writes_the_whole_file_and_prints_the_events_until_stopped() {
        let command = clip_command("front", 10_000, Some(20_000), false);
        let script = vec![
            Step::Read,
            // Another subscription's events, even its `stopped`, are not
            // the clip's.
            text(&json!({ "type": "event", "id": 7, "event": {} })),
            clip_started(),
            text(&json!({ "type": "event", "id": 7,
                          "event": { "type": "stopped", "reason": "internal_error" } })),
            clip_event(&json!({ "type": "started", "clip_id": "k1" })),
            text(&json!({ "type": "pong", "id": 3 })),
            clip_body(&["ftyp", "moov"], false),
            stopped("completed"),
        ];
        let (code, file, read) = record("whole", command.clone(), 0, script).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(file, b"ftypmoov");
        let mut sent = command;
        sent["id"] = json!(1);
        assert_eq!(read[0], sent);
        let head = read[1].as_str().unwrap();
        assert!(head.starts_with("GET /v0/clips/k1 HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("host: lotse\r\n"), "{head}");
    }

    #[tokio::test]
    async fn stream_clip_stops_on_the_first_interrupt_and_gives_up_on_the_second() {
        let command = clip_command("front", 0, None, true);
        let script = vec![
            Step::Read,
            clip_started(),
            Step::Read,
            clip_body(&["ftyp"], false),
            stopped("stopped"),
        ];
        let (code, file, read) = record("interrupt", command.clone(), 1, script).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(file, b"ftyp");
        assert_eq!(
            read[1],
            json!({ "type": "clip/stop", "clip_id": "k1", "id": 2 })
        );
        let script = vec![Step::Read, clip_started()];
        let (code, file, _read) = record("interrupt-twice", command, 2, script).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            "interrupted again; the clip's file may be cut"
        );
        assert!(file.is_empty());
    }

    #[tokio::test]
    async fn stream_clip_fails_when_the_daemon_refuses_or_the_file_is_cut() {
        let command = || clip_command("front", 0, Some(1_000), true);
        let refused = json!({ "type": "result", "id": 1, "success": false,
                              "error": { "code": "limit_reached", "message": "no" } });
        let (code, _file, read) =
            record("refused", command(), 0, vec![Step::Read, text(&refused)]).await;
        assert_eq!(code.unwrap(), ExitCode::FAILURE);
        assert_eq!(read.len(), 1, "no GET");

        let no_url = json!({ "type": "result", "id": 1, "success": true,
                             "result": { "clip_id": "k1" } });
        let (code, _file, _read) =
            record("no-url", command(), 0, vec![Step::Read, text(&no_url)]).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            "the clip/start result has no url"
        );

        let script = vec![
            Step::Read,
            clip_started(),
            clip_body(&["ftyp"], true),
            stopped("worker_crashed"),
        ];
        let (code, file, _read) = record("cut", command(), 0, script).await;
        assert_eq!(code.unwrap_err().to_string(), "the clip's file is cut");
        assert_eq!(file, b"ftyp", "what came is kept");

        let error = r#"{"code":"clip_already_fetched","message":"taken"}"#;
        let response = format!(
            "HTTP/1.1 409 Conflict\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{error}",
            error.len()
        );
        let script = vec![
            Step::Read,
            clip_started(),
            Step::Http {
                response: response.into_bytes(),
                cut: false,
            },
        ];
        let (code, _file, _read) = record("conflict", command(), 0, script).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            format!("GET /v0/clips/k1: 409 Conflict {error}")
        );
    }

    #[tokio::test]
    async fn stream_clip_exits_1_unless_the_clip_ended_as_asked() {
        let cases = [
            ("internal-error", vec![stopped("internal_error")]),
            ("shutdown", vec![text(&json!({ "type": "shutdown" }))]),
            ("closed", vec![Step::Send(Message::Close(None))]),
            (
                "reasonless",
                vec![clip_event(&json!({ "type": "stopped" }))],
            ),
        ];
        for (test, last) in cases {
            let mut script = vec![Step::Read, clip_started()];
            script.extend(last);
            script.push(clip_body(&[], false));
            let command = clip_command("front", 0, Some(1_000), true);
            let (code, file, _read) = record(test, command, 0, script).await;
            assert_eq!(code.unwrap(), ExitCode::FAILURE, "{test}");
            assert!(file.is_empty(), "{test}");
        }
    }

    #[tokio::test]
    async fn stream_clip_needs_a_file_it_can_create() {
        let err = create(Path::new("/nonexistent/clip.mp4")).err().unwrap();
        assert_eq!(
            err.to_string(),
            "creating the clip's file /nonexistent/clip.mp4"
        );
    }

    /// The daemon's error body is printed up to [`MAX_ERROR_BODY`], so a
    /// long one is printed whole.
    #[tokio::test]
    async fn stream_clip_prints_a_long_error_body_whole() {
        let error = format!(
            r#"{{"code":"internal_error","message":"{}"}}"#,
            "x".repeat(4_096)
        );
        let response = format!(
            "HTTP/1.1 500 Internal Server Error\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{error}",
            error.len()
        );
        let script = vec![
            Step::Read,
            clip_started(),
            Step::Http {
                response: response.into_bytes(),
                cut: false,
            },
        ];
        let command = clip_command("front", 0, Some(1_000), false);
        let (code, _file, _read) = record("long-error", command, 0, script).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            format!("GET /v0/clips/k1: 500 Internal Server Error {error}")
        );
    }

    /// A writer as the test scripts it: each write sends `presses`
    /// interrupts, then either takes its bytes into `taken` or, when
    /// `stall`, never completes, as a full FIFO, and sends no more. Its
    /// flush and shutdown fail, as on a full disk.
    struct Scripted {
        /// Where the interrupts go.
        interrupt: tokio::sync::mpsc::UnboundedSender<()>,
        /// The interrupts each write sends.
        presses: usize,
        /// No write completes.
        stall: bool,
        /// What the writer took.
        taken: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for Scripted {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            for _ in 0..this.presses {
                this.interrupt.send(()).unwrap();
            }
            if this.stall {
                this.presses = 0;
                return std::task::Poll::Pending;
            }
            this.taken.lock().unwrap().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("no space left")))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("no space left")))
        }
    }

    /// `stream clip` against a daemon playing `script`, writing into a
    /// [`Scripted`] writer (`presses` per write, `stall`) whose writes are
    /// the only interrupts; what the client returned, what the writer took
    /// and what the daemon read.
    async fn record_scripted(
        test: &str,
        (presses, stall): (usize, bool),
        script: Vec<Step>,
    ) -> (anyhow::Result<ExitCode>, Vec<u8>, Vec<Value>) {
        let (interrupt, heard) = tokio::sync::mpsc::unbounded_channel();
        let taken = std::sync::Arc::default();
        let writer = Scripted {
            interrupt,
            presses,
            stall,
            taken: std::sync::Arc::clone(&taken),
        };
        let interrupts = futures_util::stream::unfold(heard, |mut heard| async move {
            heard.recv().await.map(|()| ((), heard))
        });
        let command = clip_command("front", 0, None, false);
        let (code, read) = against(test, true, script, async |socket| {
            let mut client = Client::connect(socket).await.unwrap();
            let output: Output = Box::pin(writer);
            client
                .clip(socket, command, (output, true), Box::pin(interrupts))
                .await
        })
        .await;
        let taken = taken.lock().unwrap().clone();
        (code, taken, read)
    }

    /// A file that takes no bytes (a full FIFO, a stalled network
    /// filesystem) holds the body alone: the first Ctrl-C still stops the
    /// clip and the second still gives up. Regression: the file was written
    /// on the runtime's one thread, and a write that blocked held the
    /// events and Ctrl-C with it.
    #[tokio::test]
    async fn stream_clip_stops_and_gives_up_while_its_file_takes_no_bytes() {
        let script = vec![
            Step::Read,
            clip_started(),
            clip_body(&["ftyp"], false),
            Step::Read,
        ];
        let (code, taken, read) = record_scripted("stalled", (2, true), script).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            "interrupted again; the clip's file may be cut"
        );
        assert!(taken.is_empty());
        assert_eq!(
            read[2],
            json!({ "type": "clip/stop", "clip_id": "k1", "id": 2 })
        );
    }

    /// The last write's error, which a file written on the blocking pool
    /// reports at the flush, fails the clip as a refused write does.
    #[tokio::test]
    async fn stream_clip_fails_when_its_file_fails_the_last_write() {
        let script = vec![
            Step::Read,
            clip_started(),
            clip_body(&["ftyp"], false),
            stopped("completed"),
        ];
        let (code, taken, _read) = record_scripted("flush", (0, false), script).await;
        let err = code.unwrap_err();
        assert_eq!(err.to_string(), "writing the clip's file");
        assert_eq!(err.root_cause().to_string(), "no space left");
        assert_eq!(taken, b"ftyp");
        let (interrupt, _heard) = tokio::sync::mpsc::unbounded_channel();
        let mut writer = Scripted {
            interrupt,
            presses: 0,
            stall: false,
            taken: std::sync::Arc::default(),
        };
        assert!(writer.shutdown().await.is_err(), "as its flush");
    }

    /// The head of a chunked `200` whose chunks come later.
    const CHUNKED: &str = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";

    /// `stopped` may come before the body's end, on its own connection:
    /// Ctrl-C still counts while the body is awaited, and a clip that has
    /// ended is not stopped. The yield lets the client read `stopped`
    /// before the chunk that presses Ctrl-C arrives. Regression: once
    /// `stopped` had come, Ctrl-C was taken and dropped, and a body that
    /// never ended held `lotse ctl` for good.
    #[tokio::test]
    async fn stream_clip_gives_up_on_a_body_that_outlasts_stopped() {
        let script = vec![
            Step::Read,
            clip_started(),
            Step::HttpHold(CHUNKED.into()),
            stopped("stopped"),
            Step::Yield,
            // A chunk, and with it two presses.
            Step::HttpRest(b"4\r\nftyp\r\n".to_vec()),
        ];
        let (code, taken, read) = record_scripted("event-first", (2, false), script).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            "interrupted again; the clip's file may be cut"
        );
        assert_eq!(taken, b"ftyp");
        assert_eq!(read.len(), 2, "clip/start and GET, no clip/stop: {read:?}");
    }

    /// The Ctrl-C that stopped the clip counts when the next comes after
    /// `stopped`, while the body is still awaited: that one gives up.
    #[tokio::test]
    async fn stream_clip_counts_the_ctrl_c_before_stopped_with_the_one_after() {
        let script = vec![
            Step::Read,
            clip_started(),
            // The first chunk is the first press: the clip is stopped.
            Step::HttpHold(format!("{CHUNKED}4\r\nftyp\r\n").into_bytes()),
            Step::Read,
            stopped("stopped"),
            Step::Yield,
            // The second chunk, after `stopped`, is the second press.
            Step::HttpRest(b"4\r\nmoov\r\n".to_vec()),
        ];
        let (code, taken, read) = record_scripted("count", (1, false), script).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            "interrupted again; the clip's file may be cut"
        );
        assert_eq!(taken, b"ftypmoov");
        assert_eq!(read.len(), 3, "clip/start, GET, one clip/stop: {read:?}");
        assert_eq!(
            read[2],
            json!({ "type": "clip/stop", "clip_id": "k1", "id": 2 })
        );
    }

    /// The runtime is left without waiting for a blocking thread that does
    /// not return, as one writing into a FIFO nobody reads. Regression:
    /// dropping it waited for that thread for good.
    #[test]
    fn the_runtime_leaves_a_blocking_thread_that_does_not_return() {
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let out = on_runtime(async move {
            let (started, running) = tokio::sync::oneshot::channel();
            let _stuck = lotse_core::task::spawn_blocking_named("test.stuck", move || {
                started.send(()).unwrap();
                blocked.recv()
            });
            running.await.unwrap();
            Ok(7)
        });
        assert_eq!(out.unwrap(), 7);
        drop(release);
    }
}
