//! `lotse ctl`: the debugging client over the control socket.
//!
//! Speaks the WebSocket API like any other client: connect, `hello`, one
//! command, its `result`, and for a subscription the events after it.
//! Results and events are printed as JSON on stdout, which only this and
//! `lotse identity` write to; a failed result prints its `error` and exits 1.
//! `recording create` writes its lines through tokio's stdout, on the blocking
//! pool, so a stdout that takes no bytes holds back its lines, never the
//! recording's events or its body.
//! `recording create` also fetches the recording's file over HTTP on a second
//! connection to the same socket (`GET /v0/recording/{recording_id}`), as any client
//! does.

#![expect(
    clippy::print_stdout,
    reason = "`lotse ctl` output is one of the binary's two stdout writers, with `lotse identity` (Cargo.toml lints)"
)]

use std::collections::VecDeque;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Args, Subcommand};
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::StatusCode;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use lotse_api_types::{API_VERSION, ApiVersion, WS_PATH};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
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
    /// Event recordings.
    Recording {
        /// What to do.
        #[command(subcommand)]
        command: RecordingCommand,
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
        /// recordings (`30s`, `500ms`, `2m`); none when not given. It fills only
        /// while the stream is connected for `--preload` or a viewer.
        #[arg(long, value_name = "DURATION", value_parser = duration_ms)]
        prerecord: Option<u32>,
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

/// `lotse ctl recording ...`.
#[derive(Debug, Subcommand)]
pub(crate) enum RecordingCommand {
    /// Record a stream into a file: create the recording, write its
    /// fragmented MP4 as it comes and print its events, one per line. The
    /// recording runs the duration asked for; Ctrl-C leaves at once, which
    /// ends it `session_closed` with its file cut. Exits 0 when the file is
    /// whole and the recording ended as asked.
    Create {
        /// The stream.
        stream_id: String,
        /// How far back the recording starts, out of the stream's
        /// pre-record window (`10s`, `500ms`, `2m`).
        #[arg(long, value_name = "DURATION", default_value = "0s", value_parser = duration_ms)]
        prerecord: u32,
        /// How long the recording runs from now on, up to the daemon's
        /// `limits.max_recording_ms`.
        #[arg(long, value_name = "DURATION", value_parser = duration_ms)]
        duration: u32,
        /// Leave the audio out.
        #[arg(long)]
        no_audio: bool,
        /// The file the recording is written to; created, or emptied first.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
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
/// waiting for its blocking threads: a write to the recording's file that never
/// returns (a FIFO nobody reads) would otherwise hold the process after an
/// error ended the command.
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
            CtlCommand::Recording {
                command:
                    RecordingCommand::Create {
                        stream_id,
                        prerecord,
                        duration,
                        no_audio,
                        output,
                    },
            } => {
                let file = create(output)?;
                let command = recording_command(stream_id, *prerecord, *duration, *no_audio);
                let out = RecordingOutput {
                    file,
                    stdout: Box::pin(tokio::io::stdout()),
                    compact: args.compact,
                };
                client.recording(&args.socket, command, out).await
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
                prerecord,
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
                if let (Some(ms), Some(object)) = (prerecord, put.as_object_mut()) {
                    object.insert("prerecord_ms".to_owned(), json!(ms));
                }
                put
            }
            StreamCommand::Subscribe { .. } => anyhow::bail!("subscribe is streamed, not called"),
        },
        CtlCommand::Recording { .. } => anyhow::bail!("recording create is streamed, not called"),
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

/// The `recording/create` of `recording create`.
fn recording_command(
    stream_id: &str,
    prerecord_ms: u32,
    duration_ms: u32,
    no_audio: bool,
) -> Value {
    json!({ "type": "recording/create", "stream_id": stream_id, "prerecord_ms": prerecord_ms,
            "duration_ms": duration_ms, "audio": !no_audio })
}

/// The close reason of a recording that ended as asked: its file is what was
/// asked for.
const RECORDING_ENDED_AS_ASKED: &str = "completed";

/// The most of a refused `GET`'s error body `recording create` reads and prints.
const MAX_ERROR_BODY: usize = 64 * 1024;

/// Where `recording create` writes: the recording's file ([`create`]) and stdout
/// (tokio's), each on tokio's blocking pool in the binary, and scripted
/// writers in the tests. Asynchronous, so a write that blocks (a full FIFO
/// or pipe, a stalled network filesystem) holds back that output alone,
/// never the runtime that reads the recording's events and its body.
type Output = Pin<Box<dyn AsyncWrite + Send>>;

/// Where `recording create` writes.
struct RecordingOutput {
    /// The recording's file ([`create`]).
    file: Output,
    /// Its result and events, through a [`Printer`]: tokio's stdout in the
    /// binary.
    stdout: Output,
    /// The result on one line; events are always one per line.
    compact: bool,
}

/// What `recording create` prints, on its way to stdout. Lines are queued as
/// they come and written by the loop that also reads the recording's body and
/// its events, so a stdout that takes no bytes (a full pipe whose reader
/// stopped, a stalled network filesystem) holds back the lines alone.
/// Regression (PR #74 review): they were printed with `println!` on the
/// runtime's one thread, and a write that blocked held the body.
struct Printer {
    /// Where the lines go.
    out: Output,
    /// The bytes `out` has not taken yet, oldest first. It grows only while
    /// `out` takes none, and only by the recording's result and events.
    queued: VecDeque<u8>,
    /// A line was queued that no flush has seen land yet.
    pending: bool,
}

impl Printer {
    /// Nothing queued yet.
    fn new(out: Output) -> Self {
        Self {
            out,
            queued: VecDeque::new(),
            pending: false,
        }
    }

    /// Queues `value` ([`render`]) and a newline.
    fn push(&mut self, value: &Value, compact: bool) {
        self.queued.extend(render(value, compact).bytes());
        self.queued.push_back(b'\n');
        self.pending = true;
    }

    /// Writes what is queued and flushes it; done once `out` has it all.
    /// Cancel-safe, as a `select!` branch must be: `write_all_buf` takes
    /// from `queued` only what `out` took, and a flush cut short starts
    /// again the next time.
    async fn write(&mut self) -> anyhow::Result<()> {
        self.out
            .write_all_buf(&mut self.queued)
            .await
            .context("writing stdout")?;
        self.out.flush().await.context("writing stdout")?;
        self.pending = false;
        Ok(())
    }

    /// Waits until `out` has every queued line; nothing when none is
    /// queued. A stdout that takes no bytes holds `lotse ctl` until then,
    /// or until Ctrl-C ends it.
    async fn finish(&mut self) -> anyhow::Result<()> {
        if self.pending {
            self.write().await?;
        }
        Ok(())
    }
}

/// The recording's file at `path`, created or emptied, written through tokio's
/// blocking pool one write at a time: at most one write is in flight, so
/// a file that takes no bytes holds back the body, not the process.
fn create(path: &Path) -> anyhow::Result<Output> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("creating the recording's file {}", path.display()))?;
    Ok(Box::pin(tokio::fs::File::from_std(file)))
}

/// `GET url` of a recording's body on a connection of its own to `socket`
/// (HTTP/1.1, RFC 9112), written to `file` as it comes; the bytes written.
/// An error when the daemon refuses (its status and error body), or when
/// the body ends without its last chunk (RFC 9112 §7.1): the recording's file is
/// then cut, and holds what came. The bytes count once `file` has them all.
async fn fetch(socket: &Path, url: &str, file: &mut Output) -> anyhow::Result<u64> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connecting for the recording's file")?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("the recording's HTTP connection")?;
    let request = hyper::Request::get(url)
        .header(hyper::header::HOST, "lotse")
        .body(Empty::<Bytes>::new())
        .context("the recording's request")?;
    let body = async move {
        let response = sender
            .send_request(request)
            .await
            .context("asking for the recording's file")?;
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
            let frame = match frame {
                Ok(frame) => frame,
                Err(err) => {
                    // What came is kept: the write still in flight lands
                    // first. Its own error would hide the cut, so it goes.
                    let _landed = file.flush().await;
                    return Err(err).context("the recording's file is cut");
                }
            };
            // A data frame; trailers, which the route never sends, write
            // nothing.
            let data = frame.into_data().unwrap_or_default();
            file.write_all(&data)
                .await
                .context("writing the recording's file")?;
            written = written.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        }
        // The last write may still be in flight; its error shows here.
        file.flush().await.context("writing the recording's file")?;
        Ok(written)
    };
    // The connection ends with the body: the daemon closes it after one.
    let (written, _connection) = tokio::join!(body, connection);
    written
}

/// How the events of `recording create`'s recording ended.
enum RecordingEnd {
    /// Its `closed`, with the reason (empty without one).
    Closed(String),
    /// The connection closed or the daemon shut down first.
    Gone,
}

/// What `frame`, read on `recording create`'s connection, says of the recording
/// subscribed as `id`: an event of it is queued on `printer`; the end once
/// there is one, `None` while the recording runs on.
fn recording_end(frame: &Value, id: u64, printer: &mut Printer) -> Option<RecordingEnd> {
    match kind(frame) {
        Some("event") if id_of(frame) == Some(id) => {
            let event = frame.get("event").unwrap_or(&Value::Null);
            printer.push(event, true);
            (kind(event) == Some("closed")).then(|| {
                let reason = event.get("reason").and_then(Value::as_str);
                RecordingEnd::Closed(reason.unwrap_or_default().to_owned())
            })
        }
        Some("shutdown") => Some(RecordingEnd::Gone),
        _ => None,
    }
}

/// One JSON value as `lotse ctl` prints it, without the newline: one line
/// when `compact`, else `serde_json`'s pretty printer (the alternate form).
fn render(value: &Value, compact: bool) -> String {
    if compact {
        value.to_string()
    } else {
        format!("{value:#}")
    }
}

/// Prints one JSON value ([`render`]) and a newline.
fn print(value: &Value, compact: bool) {
    println!("{}", render(value, compact));
}

/// The `type` of a frame.
fn kind(frame: &Value) -> Option<&str> {
    frame.get("type").and_then(Value::as_str)
}

/// The `id` of a frame.
fn id_of(frame: &Value) -> Option<u64> {
    frame.get("id").and_then(Value::as_u64)
}

/// A command's outcome as printed: the `result` on success,
/// `{ "error": ... }` on failure, a `pong` as is; and the exit code that
/// follows.
fn outcome(frame: &Value) -> (Value, ExitCode) {
    if kind(frame) == Some("pong") {
        return (frame.clone(), ExitCode::SUCCESS);
    }
    if frame.get("success").and_then(Value::as_bool) == Some(true) {
        (
            frame.get("result").cloned().unwrap_or(Value::Null),
            ExitCode::SUCCESS,
        )
    } else {
        (
            json!({ "error": frame.get("error").cloned().unwrap_or(Value::Null) }),
            ExitCode::FAILURE,
        )
    }
}

/// Prints a command's outcome ([`outcome`]); the exit code follows.
fn report(frame: &Value, compact: bool) -> ExitCode {
    let (value, code) = outcome(frame);
    print(&value, compact);
    code
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

    /// `recording create`: sends `command`, a `recording/create`, prints its result,
    /// then writes the recording's body to `output.file` while the recording's events
    /// print, one per line, until both have ended, in whichever order. A
    /// refused or cut body is an error and ends the connection, which ends
    /// the recording; the exit code is 0 when the file is whole and the recording
    /// ended as asked. The result and the events are queued and written to
    /// `output.stdout` as it takes them; `lotse ctl` leaves once stdout has
    /// every line. An error returns at once and does not wait for stdout,
    /// nor does a stdout that fails (a reader gone), which ends the
    /// connection and so the recording.
    async fn recording(
        &mut self,
        socket: &Path,
        command: Value,
        output: RecordingOutput,
    ) -> anyhow::Result<ExitCode> {
        let RecordingOutput {
            mut file,
            stdout,
            compact,
        } = output;
        let mut printer = Printer::new(stdout);
        let id = self.send(command).await?;
        let frame = self.call_result(id).await?;
        if frame.get("success").and_then(Value::as_bool) != Some(true) {
            let (value, code) = outcome(&frame);
            printer.push(&value, compact);
            printer.finish().await?;
            return Ok(code);
        }
        let result = frame.get("result").unwrap_or(&Value::Null);
        printer.push(result, compact);
        let url = result
            .get("url")
            .and_then(Value::as_str)
            .context("the recording/create result has no url")?;
        let body = fetch(socket, url, &mut file);
        tokio::pin!(body);
        // The body and the events run on separate connections, so either
        // may end first.
        let (mut whole, mut ended) = (false, None);
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
                        Some(frame) => recording_end(&frame, id, &mut printer),
                        None => Some(RecordingEnd::Gone),
                    };
                }
                flushed = printer.write(), if printer.pending => flushed?,
            }
        }
        printer.finish().await?;
        let as_asked = matches!(&ended, Some(RecordingEnd::Closed(reason)) if reason == RECORDING_ENDED_AS_ASKED);
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
                prerecord: None,
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
                prerecord: None,
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
    }

    /// A text frame of `value`.
    fn text(value: &Value) -> Step {
        Step::Send(Message::text(value.to_string()))
    }

    /// A daemon that accepts one connection on `listener` and upgrades it,
    /// sends `hello` when `greet` and plays `script`; unless that ends in
    /// [`Step::Drop`], it then reads on until the client is gone, so the
    /// client answers a ping or reads to the end without a broken pipe.
    /// Returns the commands the script read.
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
                Step::Http { response, cut } => {
                    let mut http = serve_head(&listener, &mut read).await;
                    http.write_all(&response).await.unwrap();
                    if !cut {
                        let _until_closed = http.read_to_end(&mut Vec::new()).await;
                    }
                }
            }
        }
        while let Some(Ok(_frame)) = ws.next().await {}
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
        let (out, read) =
            bounded(async { tokio::join!(client(&socket), daemon(listener, greet, script)) }).await;
        std::fs::remove_dir_all(&dir).unwrap();
        (out, read)
    }

    /// The bound on a client and its scripted daemon, generous for a loaded
    /// CI runner: past it a client that waits for something that never
    /// comes (a regression of a stdout test) fails the test instead of
    /// holding the job.
    const BOUND: std::time::Duration = std::time::Duration::from_secs(60);

    /// `future`, or a panic once it has taken [`BOUND`].
    #[expect(
        clippy::disallowed_methods,
        reason = "a real-time bound on a test that would otherwise hang; no injected clock here"
    )]
    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(BOUND, future)
            .await
            .expect("the client and its scripted daemon did not finish in time")
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

    /// Only the result of the command's own id ends `raw`: a stale result of
    /// another id, and an event under the command's id, are printed and
    /// read past. Both would end it in success, so only the failed result
    /// of its own id gives the failure asserted.
    #[tokio::test]
    async fn raw_ends_only_at_the_result_of_its_own_id() {
        let script = vec![
            Step::Read,
            text(&json!({ "type": "result", "id": 99, "success": true, "result": {} })),
            text(&json!({ "type": "event", "id": 1, "event": {} })),
            text(&json!({ "type": "result", "id": 1, "success": false, "error": {} })),
        ];
        let (code, _read) = against("raw-own-id", true, script, async |socket| {
            let mut client = Client::connect(socket).await.unwrap();
            client.raw(json!({ "type": "info" }), true).await.unwrap()
        })
        .await;
        assert_eq!(code, ExitCode::FAILURE);
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

    /// Another subscription's event does not count toward the limit: the
    /// client reads on, here into a frame that is not JSON.
    #[tokio::test]
    async fn subscribe_counts_only_its_own_events() {
        let ok = json!({ "type": "result", "id": 1, "success": true, "result": {} });
        let then = vec![
            text(&json!({ "type": "event", "id": 1, "event": { "n": 1 } })),
            text(&json!({ "type": "event", "id": 2, "event": { "n": 0 } })),
            Step::Send(Message::Text("not json".into())),
        ];
        let (code, _command) = subscribe("sub-own", None, Some(2), ok, then).await;
        assert!(code.is_err(), "read past the other subscription's event");
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
    fn recording_create_and_put_with_a_window_map_onto_their_commands() {
        assert_eq!(
            recording_command("front", 10_000, 30_000, true),
            json!({ "type": "recording/create", "stream_id": "front", "prerecord_ms": 10_000,
                    "duration_ms": 30_000, "audio": false })
        );
        assert_eq!(
            recording_command("front", 0, 1, false),
            json!({ "type": "recording/create", "stream_id": "front", "prerecord_ms": 0,
                    "duration_ms": 1, "audio": true })
        );
        let put = CtlCommand::Stream {
            command: StreamCommand::Put {
                stream_id: "front".into(),
                urls: vec!["rtsp://cam/a".into()],
                url_file: None,
                options: None,
                preload: true,
                audio: "auto".into(),
                prerecord: Some(30_000),
            },
        };
        assert_eq!(
            command_of(&put, b"".as_slice()).unwrap()["prerecord_ms"],
            json!(30_000)
        );
        let recording = CtlCommand::Recording {
            command: RecordingCommand::Create {
                stream_id: "front".into(),
                prerecord: 0,
                duration: 1,
                no_audio: false,
                output: PathBuf::from("recording.mp4"),
            },
        };
        assert!(command_of(&recording, b"".as_slice()).is_err());
    }

    /// The `recording/create` result of recording `k1`.
    fn recording_started() -> Step {
        text(&json!({ "type": "result", "id": 1, "success": true,
                      "result": { "recording_id": "k1", "url": "/v0/recording/k1" } }))
    }

    /// The event `event` of the recording's subscription.
    fn recording_event(event: &Value) -> Step {
        text(&json!({ "type": "event", "id": 1, "event": event }))
    }

    /// `closed` with `reason`.
    fn closed(reason: &str) -> Step {
        recording_event(&json!({ "type": "closed", "reason": reason, "bytes": 8 }))
    }

    /// A `200` whose chunked body is `chunks`, ended by the last chunk
    /// unless `cut` (RFC 9112 §7.1), on a connection that closes after it.
    fn recording_body(chunks: &[&str], cut: bool) -> Step {
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

    /// `recording create` of `front` (`command`, from [`recording_command`]) against
    /// a daemon that plays `script`, stdout a sink; what the client
    /// returned, the file it wrote and what the daemon read.
    async fn record(
        test: &str,
        command: Value,
        script: Vec<Step>,
    ) -> (anyhow::Result<ExitCode>, Vec<u8>, Vec<Value>) {
        let stdout: Output = Box::pin(tokio::io::sink());
        record_into(test, command, (stdout, true), script).await
    }

    /// As [`record`], with `stdout` (and whether the result prints
    /// `compact`) as given.
    async fn record_into(
        test: &str,
        command: Value,
        (stdout, compact): (Output, bool),
        script: Vec<Step>,
    ) -> (anyhow::Result<ExitCode>, Vec<u8>, Vec<Value>) {
        let dir =
            std::env::temp_dir().join(format!("lotse-ctl-file-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("recording.mp4");
        let (code, read) = against(test, true, script, async |socket| {
            let mut client = Client::connect(socket).await.unwrap();
            let output = RecordingOutput {
                file: create(&file).unwrap(),
                stdout,
                compact,
            };
            client.recording(socket, command, output).await
        })
        .await;
        let written = std::fs::read(&file).unwrap_or_default();
        std::fs::remove_dir_all(&dir).unwrap();
        (code, written, read)
    }

    #[tokio::test]
    async fn recording_create_writes_the_whole_file_and_prints_the_events_until_closed() {
        let command = recording_command("front", 10_000, 20_000, false);
        let script = vec![
            Step::Read,
            // Another subscription's events, even its `closed`, are not
            // the recording's.
            text(&json!({ "type": "event", "id": 7, "event": {} })),
            recording_started(),
            text(&json!({ "type": "event", "id": 7,
                          "event": { "type": "closed", "reason": "internal_error" } })),
            recording_event(&json!({ "type": "started", "recording_id": "k1" })),
            text(&json!({ "type": "pong", "id": 3 })),
            recording_body(&["ftyp", "moov"], false),
            closed("completed"),
        ];
        let (code, file, read) = record("whole", command.clone(), script).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(file, b"ftypmoov");
        let mut sent = command;
        sent["id"] = json!(1);
        assert_eq!(read[0], sent);
        let head = read[1].as_str().unwrap();
        assert!(
            head.starts_with("GET /v0/recording/k1 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("host: lotse\r\n"), "{head}");
    }

    #[tokio::test]
    async fn recording_create_fails_when_the_daemon_refuses_or_the_file_is_cut() {
        let command = || recording_command("front", 0, 1_000, true);
        let refused = json!({ "type": "result", "id": 1, "success": false,
                              "error": { "code": "limit_reached", "message": "no" } });
        let (code, _file, read) =
            record("refused", command(), vec![Step::Read, text(&refused)]).await;
        assert_eq!(code.unwrap(), ExitCode::FAILURE);
        assert_eq!(read.len(), 1, "no GET");

        let no_url = json!({ "type": "result", "id": 1, "success": true,
                             "result": { "recording_id": "k1" } });
        let (code, _file, _read) =
            record("no-url", command(), vec![Step::Read, text(&no_url)]).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            "the recording/create result has no url"
        );

        let script = vec![
            Step::Read,
            recording_started(),
            recording_body(&["ftyp"], true),
            closed("worker_crashed"),
        ];
        let (code, file, _read) = record("cut", command(), script).await;
        assert_eq!(code.unwrap_err().to_string(), "the recording's file is cut");
        assert_eq!(file, b"ftyp", "what came is kept");

        let error = r#"{"code":"recording_already_fetched","message":"taken"}"#;
        let response = format!(
            "HTTP/1.1 409 Conflict\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{error}",
            error.len()
        );
        let script = vec![
            Step::Read,
            recording_started(),
            Step::Http {
                response: response.into_bytes(),
                cut: false,
            },
        ];
        let (code, _file, _read) = record("conflict", command(), script).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            format!("GET /v0/recording/k1: 409 Conflict {error}")
        );
    }

    #[tokio::test]
    async fn recording_create_exits_1_unless_the_recording_ended_as_asked() {
        let cases = [
            ("internal-error", vec![closed("internal_error")]),
            ("shutdown", vec![text(&json!({ "type": "shutdown" }))]),
            ("closed", vec![Step::Send(Message::Close(None))]),
            (
                "reasonless",
                vec![recording_event(&json!({ "type": "closed" }))],
            ),
        ];
        for (test, last) in cases {
            let mut script = vec![Step::Read, recording_started()];
            script.extend(last);
            script.push(recording_body(&[], false));
            let command = recording_command("front", 0, 1_000, true);
            let (code, file, _read) = record(test, command, script).await;
            assert_eq!(code.unwrap(), ExitCode::FAILURE, "{test}");
            assert!(file.is_empty(), "{test}");
        }
    }

    #[tokio::test]
    async fn recording_create_needs_a_file_it_can_create() {
        let err = create(Path::new("/nonexistent/recording.mp4"))
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "creating the recording's file /nonexistent/recording.mp4"
        );
    }

    /// The daemon's error body is printed up to [`MAX_ERROR_BODY`], so a
    /// long one is printed whole.
    #[tokio::test]
    async fn recording_create_prints_a_long_error_body_whole() {
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
            recording_started(),
            Step::Http {
                response: response.into_bytes(),
                cut: false,
            },
        ];
        let command = recording_command("front", 0, 1_000, false);
        let (code, _file, _read) = record("long-error", command, script).await;
        assert_eq!(
            code.unwrap_err().to_string(),
            format!("GET /v0/recording/k1: 500 Internal Server Error {error}")
        );
    }

    /// A writer (the recording's file, or stdout) as the test scripts it: each
    /// write takes its bytes into `taken`; its flush and shutdown fail, as on
    /// a full disk.
    struct Scripted {
        /// What the writer took.
        taken: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for Scripted {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.get_mut().taken.lock().unwrap().extend_from_slice(buf);
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

    /// `recording create` against a daemon playing `script`, writing into a
    /// [`Scripted`] writer that takes every write; what the client
    /// returned, what the writer took and what the daemon read.
    async fn record_scripted(
        test: &str,
        script: Vec<Step>,
    ) -> (anyhow::Result<ExitCode>, Vec<u8>, Vec<Value>) {
        let taken = std::sync::Arc::default();
        let writer = Scripted {
            taken: std::sync::Arc::clone(&taken),
        };
        let command = recording_command("front", 0, 1_000, false);
        let (code, read) = against(test, true, script, async |socket| {
            let mut client = Client::connect(socket).await.unwrap();
            let output = RecordingOutput {
                file: Box::pin(writer),
                stdout: Box::pin(tokio::io::sink()),
                compact: true,
            };
            client.recording(socket, command, output).await
        })
        .await;
        let taken = taken.lock().unwrap().clone();
        (code, taken, read)
    }

    /// The last write's error, which a file written on the blocking pool
    /// reports at the flush, fails the recording as a refused write does.
    #[tokio::test]
    async fn recording_create_fails_when_its_file_fails_the_last_write() {
        let script = vec![
            Step::Read,
            recording_started(),
            recording_body(&["ftyp"], false),
            closed("completed"),
        ];
        let (code, taken, _read) = record_scripted("flush", script).await;
        let err = code.unwrap_err();
        assert_eq!(err.to_string(), "writing the recording's file");
        assert_eq!(err.root_cause().to_string(), "no space left");
        assert_eq!(taken, b"ftyp");
        let mut writer = Scripted {
            taken: std::sync::Arc::default(),
        };
        assert!(writer.shutdown().await.is_err(), "as its flush");
    }

    /// A writer whose writes land only at the flush, as with tokio's `File`
    /// and stdout, which report a write done once the blocking pool has it.
    struct Lagging {
        /// Written, not yet landed.
        in_flight: Vec<u8>,
        /// What landed.
        landed: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for Lagging {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.get_mut().in_flight.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let landed = std::mem::take(&mut this.in_flight);
            this.landed.lock().unwrap().extend(landed);
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    /// A cut body keeps what came, the write still in flight included.
    /// Regression: the cut was reported while the last write was still on
    /// the blocking pool, and the file could be left without it.
    #[tokio::test]
    async fn recording_create_lands_the_write_in_flight_when_the_body_is_cut() {
        let landed = std::sync::Arc::default();
        let writer = Lagging {
            in_flight: Vec::new(),
            landed: std::sync::Arc::clone(&landed),
        };
        let script = vec![
            Step::Read,
            recording_started(),
            recording_body(&["ftyp"], true),
        ];
        let command = recording_command("front", 0, 1_000, false);
        let (code, _read) = against("lagging", true, script, async |socket| {
            let mut client = Client::connect(socket).await.unwrap();
            let output = RecordingOutput {
                file: Box::pin(writer),
                stdout: Box::pin(tokio::io::sink()),
                compact: true,
            };
            client.recording(socket, command, output).await
        })
        .await;
        assert_eq!(code.unwrap_err().to_string(), "the recording's file is cut");
        assert_eq!(*landed.lock().unwrap(), b"ftyp");
        let mut writer = Lagging {
            in_flight: b"moov".to_vec(),
            landed: std::sync::Arc::default(),
        };
        writer.shutdown().await.unwrap();
        assert_eq!(*writer.landed.lock().unwrap(), b"moov", "as its flush");
    }

    /// A [`Scripted`] stdout, and what it takes.
    fn quiet_stdout() -> (Scripted, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        let taken = std::sync::Arc::<std::sync::Mutex<Vec<u8>>>::default();
        let writer = Scripted {
            taken: std::sync::Arc::clone(&taken),
        };
        (writer, taken)
    }

    /// The result and the events are printed through stdout, in order and
    /// flushed, the result pretty unless `--compact` and the events one per
    /// line; so is a refused start.
    #[tokio::test]
    async fn recording_create_prints_its_result_and_events_once_stdout_has_them() {
        let landed = std::sync::Arc::<std::sync::Mutex<Vec<u8>>>::default();
        let stdout = Lagging {
            in_flight: Vec::new(),
            landed: std::sync::Arc::clone(&landed),
        };
        let started = json!({ "type": "started", "recording_id": "k1" });
        let script = vec![
            Step::Read,
            recording_started(),
            recording_event(&started),
            recording_body(&["ftyp"], false),
            closed("completed"),
        ];
        let command = recording_command("front", 0, 1_000, false);
        let (code, file, _read) =
            record_into("prints", command.clone(), (Box::pin(stdout), false), script).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(file, b"ftyp");
        let result = json!({ "recording_id": "k1", "url": "/v0/recording/k1" });
        let closed = json!({ "type": "closed", "reason": "completed", "bytes": 8 });
        let expected = format!("{result:#}\n{started}\n{closed}\n");
        assert_eq!(
            String::from_utf8(landed.lock().unwrap().clone()).unwrap(),
            expected
        );

        let landed = std::sync::Arc::<std::sync::Mutex<Vec<u8>>>::default();
        let stdout = Lagging {
            in_flight: Vec::new(),
            landed: std::sync::Arc::clone(&landed),
        };
        let error = json!({ "code": "stream_not_found", "message": "no" });
        let refused = json!({ "type": "result", "id": 1, "success": false, "error": error });
        let (code, _file, _read) = record_into(
            "prints-refused",
            command,
            (Box::pin(stdout), true),
            vec![Step::Read, text(&refused)],
        )
        .await;
        assert_eq!(code.unwrap(), ExitCode::FAILURE);
        let expected = format!("{}\n", json!({ "error": error }));
        assert_eq!(
            String::from_utf8(landed.lock().unwrap().clone()).unwrap(),
            expected
        );
    }

    /// A stdout that takes no bytes (a full pipe whose reader stopped, a
    /// stalled network filesystem) holds back its lines alone: the body is
    /// written meanwhile, and `lotse ctl` leaves once stdout has every
    /// line. Regression (PR #74 review): the lines were printed with
    /// `println!` on the runtime's one thread, and a write that blocked
    /// held the body. The file is a [`Lagging`] one, not a file on the
    /// blocking pool, so the body is whole once the daemon sees its
    /// connection close.
    #[tokio::test]
    async fn recording_create_writes_its_body_while_stdout_takes_no_bytes_and_waits_for_stdout() {
        let (stdout, mut lines) = tokio::io::duplex(1);
        let landed = std::sync::Arc::<std::sync::Mutex<Vec<u8>>>::default();
        let file = Lagging {
            in_flight: Vec::new(),
            landed: std::sync::Arc::clone(&landed),
        };
        let script = vec![
            Step::Read,
            recording_started(),
            closed("completed"),
            recording_body(&["ftyp"], false),
        ];
        let command = recording_command("front", 0, 1_000, false);
        let client = against("stdout-stalled", true, script, async |socket| {
            let mut client = Client::connect(socket).await.unwrap();
            let output = RecordingOutput {
                file: Box::pin(file),
                stdout: Box::pin(stdout),
                compact: true,
            };
            client.recording(socket, command, output).await
        });
        let reader = async {
            // Nothing is read off stdout until the body is written.
            while landed.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
            let mut printed = Vec::new();
            lines.read_to_end(&mut printed).await.unwrap();
            printed
        };
        let ((code, read), printed) =
            Box::pin(bounded(async { tokio::join!(client, reader) })).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(*landed.lock().unwrap(), b"ftyp");
        let printed = String::from_utf8(printed).unwrap();
        assert_eq!(
            printed.lines().count(),
            2,
            "the result and closed: {printed}"
        );
        assert_eq!(read.len(), 2, "recording/create and GET: {read:?}");
    }

    /// `write` hands every queued line to stdout and flushes it, and fails
    /// with stdout: a write that returned at once would leave the line
    /// queued.
    #[tokio::test]
    async fn printer_write_hands_the_queued_lines_to_stdout_and_flushes() {
        let (stdout, taken) = quiet_stdout();
        let mut printer = Printer::new(Box::pin(stdout));
        printer.push(&json!({ "a": 1 }), true);
        let err = bounded(printer.write()).await.unwrap_err();
        assert_eq!(err.to_string(), "writing stdout");
        assert_eq!(&*taken.lock().unwrap(), b"{\"a\":1}\n");
        assert!(printer.queued.is_empty());
    }

    /// `finish` has nothing to wait for without a queued line.
    #[tokio::test]
    async fn printer_finish_waits_for_nothing_unqueued() {
        let (stdout, _taken) = quiet_stdout();
        let mut printer = Printer::new(Box::pin(stdout));
        bounded(printer.finish()).await.unwrap();
    }

    /// A stdout that fails (a reader gone: `EPIPE`) fails the recording with the
    /// error. Regression: `println!` panicked on it, and `panic = "abort"`
    /// killed `lotse ctl` mid-recording.
    #[tokio::test]
    async fn recording_create_fails_when_stdout_fails() {
        let (stdout, taken) = quiet_stdout();
        let script = vec![Step::Read, recording_started()];
        let command = recording_command("front", 0, 1_000, false);
        let (code, _file, _read) =
            record_into("stdout-fails", command, (Box::pin(stdout), true), script).await;
        let err = code.unwrap_err();
        assert_eq!(err.to_string(), "writing stdout");
        assert_eq!(err.root_cause().to_string(), "no space left");
        assert_eq!(
            *taken.lock().unwrap(),
            b"{\"recording_id\":\"k1\",\"url\":\"/v0/recording/k1\"}\n"
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
