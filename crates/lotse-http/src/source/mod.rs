//! The HTTP source: one connection attempt fetches the source URL, tells
//! from the answer what it serves, and plays it until the server ends it,
//! it fails, or core cancels it.
//!
//! What the answer is, is read from its first bytes, not trusted from its
//! `Content-Type` (RFC 9110 §8.3: a recipient may look at the content),
//! since cameras and CDNs label HLS and MPEG-TS every way there is:
//!
//! - `#EXTM3U` first: an HLS playlist (RFC 8216 §4.3.1.1).
//! - the sync byte `0x47` at offsets 0, 188 and 376: MPEG-TS (ISO/IEC
//!   13818-1 §2.4.3.2, `sync_byte`, 188-byte transport packets), streamed
//!   as long as the server sends it.
//! - `Content-Type: multipart/x-mixed-replace` (RFC 2046 §5.1, the MJPEG
//!   stream of many cameras): refused, as is anything else, naming its
//!   `Content-Type` only, never the URL.
//!
//! HLS follows RFC 8216 §6.3: a multivariant playlist picks a variant
//! and its audio rendition ([`crate::hls::choose_variant`], §6.3.1); each
//! media playlist is followed by a fetch task of its own (§6.3.2: the
//! segments a reload adds, in order; §6.3.4: the reload interval), which
//! fetches at most two segments ahead of the playback. Segments are
//! MPEG-TS (§3.2), read with a demultiplexer per
//! timeline, or fragmented MP4 (§3.3) read against their `EXT-X-MAP`
//! init segment (§4.3.2.5). An `EXT-X-DISCONTINUITY` (§4.3.2.3), segments
//! the playlist removed before they were fetched, and a restarted
//! playlist start a new epoch with a fresh reader; a program whose tracks
//! change ends the attempt, so the next one declares them anew; the end of
//! the playlist (`EXT-X-ENDLIST`, §4.3.3.4) ends it once the last segment
//! is played. A variant with a separate audio rendition plays both media
//! playlists as one program, the rendition's tracks after the variant's,
//! their units merged by decoding time.
//!
//! The units are released at their own time ([`crate::publish`]). `https`
//! runs the same over TLS from `lotse_tls` (RFC 9110 §4.2.2), offering
//! `http/1.1` by ALPN (RFC 7301 §3.1). The attempt honors cancellation
//! within the current await, whatever it waits for, and the fetch tasks
//! and connections end with it. The URL's path, query and credentials
//! never reach a log line or an error.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use lotse_core::source::{Source, SourceCtx, SourceDescriptor, SourceError, SourceExit};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::BoxFuture;
use lotse_tls::{TlsStream, TlsTarget};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::client::{Body, Client, Connect, Plain, Response};
use crate::fmp4;
use crate::hls::{self, Playlist};
use crate::media::{Event, Layout, Unit};
use crate::options::HttpOptions;
use crate::publish::Publisher;
use crate::ts::Demuxer;

mod fetch;

#[cfg(test)]
mod test_data;
#[cfg(test)]
mod tests;

use fetch::{Feed, Format, Segment};

/// The protocol name the source reports, for both schemes.
pub const PROTOCOL: &str = "http";

/// The size of an MPEG-TS transport packet (ISO/IEC 13818-1 §2.4.3.2).
const TS_PACKET: usize = 188;

/// `sync_byte`, the first byte of every transport packet (ISO/IEC 13818-1
/// §2.4.3.3).
const SYNC_BYTE: u8 = 0x47;

/// How many bytes of the first answer are read before it is sniffed: up
/// to the third transport packet's sync byte.
const SNIFF_BYTES: usize = 2 * TS_PACKET + 1;

/// The media type of the MJPEG stream many cameras serve (RFC 2046 §5.1).
const MJPEG: &str = "multipart/x-mixed-replace";

/// How far ahead a unit may be due before the pacer takes it for a jump of
/// the timestamps ([`crate::pace::Pacer::new`]). A unit is read only once
/// the units before it are released, so in a stream that keeps its
/// timeline it is due at most the tracks' interleaving ahead, well under
/// a second; a jump further than this is a new timeline.
const MAX_LEAD: Duration = Duration::from_secs(5);

/// The ALPN protocol `https` offers (RFC 7301 §6, the IANA registry's
/// `http/1.1`): the client speaks HTTP/1.1 only.
const HTTP_1_1: &[u8] = b"http/1.1";

/// The reason of a cancelled attempt, as the RTSP source reports it.
fn cancelled() -> SourceError {
    SourceError::Ended("cancelled".into())
}

/// A playlist, init segment or media segment that cannot be read, as a
/// protocol error.
fn protocol(err: impl std::fmt::Display) -> SourceError {
    SourceError::Protocol(err.to_string())
}

/// Runs `future` unless `cancel` fires first, or has: a cancelled attempt
/// ends as cancelled even when what it waited for ended with it (a fetch
/// task stopped by the same token).
async fn cancellable<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, SourceError>>,
) -> Result<T, SourceError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(cancelled()),
        result = future => result,
    }
}

/// One validated `http://` or `https://` source.
#[derive(Debug)]
pub struct HttpSource {
    /// The URL, credentials inside.
    url: SourceUrl,
    /// The options.
    options: HttpOptions,
    /// For `https`: the server name and the certificate check.
    tls: Option<TlsTarget>,
}

impl HttpSource {
    /// A source for `url` with `options`; `tls` is set exactly for
    /// `https`.
    pub const fn new(url: SourceUrl, options: HttpOptions, tls: Option<TlsTarget>) -> Self {
        Self { url, options, tls }
    }
}

impl Source for HttpSource {
    fn describe(&self) -> SourceDescriptor {
        SourceDescriptor {
            protocol: PROTOCOL,
            url: self.url.clone(),
            options: self.options.redacted(),
        }
    }

    fn connection_options(&self) -> serde_json::Value {
        self.options.connection_key()
    }

    fn run(&self, ctx: SourceCtx) -> BoxFuture<'static, SourceExit> {
        let url = self.url.clone();
        let options = self.options.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let Err(exit) = match tls {
                None => attempt(Plain, url, options, ctx).await,
                Some(target) => attempt(Https(target), url, options, ctx).await,
            };
            SourceExit::Ended(exit)
        })
    }
}

/// TLS over TCP, for `https`: the certificate checked as the source's
/// options say, `http/1.1` offered by ALPN.
#[derive(Debug, Clone)]
struct Https(TlsTarget);

impl Connect for Https {
    type Io = TlsStream<TcpStream>;

    /// The server name comes from the target, which was built from the
    /// URL's host when the source was validated.
    fn connect(
        &self,
        addr: std::net::SocketAddr,
        host: &str,
    ) -> BoxFuture<'static, Result<Self::Io, SourceError>> {
        let target = self.0.clone();
        let tcp = Plain.connect(addr, host);
        Box::pin(async move { lotse_tls::connect(tcp.await?, &target, &[HTTP_1_1]).await })
    }
}

/// What the first answer is.
enum Sniffed {
    /// An HLS playlist, whole, and the URL it came from.
    Playlist {
        /// The playlist.
        bytes: Bytes,
        /// Its URL after redirects, its URIs' base (RFC 8216 §4.1).
        base: Url,
    },
    /// MPEG-TS: its first bytes and the rest of the body.
    Mpegts {
        /// The bytes read to sniff it.
        head: Bytes,
        /// The rest.
        body: Body,
    },
}

/// Whether `bytes` start with three transport packets' sync bytes
/// (ISO/IEC 13818-1 §2.4.3.2).
fn is_mpegts(bytes: &[u8]) -> bool {
    [0, TS_PACKET, 2 * TS_PACKET]
        .iter()
        .all(|&offset| bytes.get(offset) == Some(&SYNC_BYTE))
}

/// Tells what the first answer is, reading as much of its body as that
/// takes: a playlist whole (at most [`hls::MAX_PLAYLIST_BYTES`]), MPEG-TS
/// only its first [`SNIFF_BYTES`].
async fn sniff(response: Response) -> Result<Sniffed, SourceError> {
    let content_type = response.content_type().map(str::to_owned);
    let essence = content_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if essence.is_some_and(|essence| essence.eq_ignore_ascii_case(MJPEG)) {
        return Err(SourceError::Protocol(format!(
            "the source serves MJPEG ({MJPEG}, RFC 2046 §5.1), which is not supported"
        )));
    }
    let base = response.url().clone();
    let mut body = response.into_body();
    let mut head = BytesMut::new();
    while head.len() < SNIFF_BYTES {
        let Some(chunk) = body.chunk().await? else {
            break;
        };
        head.extend_from_slice(&chunk);
    }
    if head.starts_with(b"#EXTM3U") {
        let rest = body
            .bytes(hls::MAX_PLAYLIST_BYTES.saturating_sub(head.len()))
            .await?;
        head.extend_from_slice(&rest);
        return Ok(Sniffed::Playlist {
            bytes: head.freeze(),
            base,
        });
    }
    if is_mpegts(&head) {
        return Ok(Sniffed::Mpegts {
            head: head.freeze(),
            body,
        });
    }
    let labelled = content_type.map_or_else(
        || "no Content-Type".to_owned(),
        |value| format!("Content-Type {value}"),
    );
    Err(SourceError::Protocol(format!(
        "the source is neither an HLS playlist (RFC 8216 §4.3.1.1) nor MPEG-TS (ISO/IEC 13818-1 §2.4.3.2): {labelled}"
    )))
}

/// One connection attempt through `connector`: the first GET, the sniff,
/// the fetch tasks and the playback, until it ends. Every fetch task and
/// connection ends with it.
async fn attempt<C: Connect + Clone + 'static>(
    connector: C,
    url: SourceUrl,
    options: HttpOptions,
    ctx: SourceCtx,
) -> Result<Infallible, SourceError> {
    let stop = ctx.cancel.child_token();
    let _stop_on_exit = stop.clone().drop_guard();
    let client = |connector: C| {
        Client::new(
            connector,
            &url,
            ctx.peer.clone(),
            Arc::clone(&ctx.time),
            options.timeout(),
            stop.clone(),
        )
    };
    let mut first = client(connector.clone());
    tracing::info!(host = %ctx.peer.host, scheme = url.scheme(), "http: fetching the source");
    let sniffed = cancellable(&ctx.cancel, async {
        sniff(first.get(url.url()).await?).await
    })
    .await?;
    let feeds = match sniffed {
        Sniffed::Mpegts { head, body } => {
            tracing::info!(host = %ctx.peer.host, "http: the source serves MPEG-TS; streaming it");
            vec![fetch::mpegts(head, body, &stop)]
        }
        Sniffed::Playlist { bytes, base } => match hls::parse(&bytes, &base).map_err(protocol)? {
            Playlist::Media(media) => {
                tracing::info!(host = %ctx.peer.host, "http: the source serves an HLS media playlist");
                vec![fetch::follow(
                    first,
                    base,
                    Some(media),
                    "media",
                    &ctx.time,
                    &stop,
                )]
            }
            Playlist::Multivariant(multivariant) => {
                let choice =
                    hls::choose_variant(&multivariant, options.max_bandwidth).map_err(protocol)?;
                tracing::info!(
                    host = %ctx.peer.host,
                    variants = multivariant.variants.len(),
                    bandwidth = choice.variant.bandwidth,
                    codecs = choice.variant.codecs.as_deref(),
                    audio = choice.audio.as_ref().map(|audio| audio.name.as_str()),
                    separate_audio = choice.audio_playlist().is_some(),
                    "http: the source serves an HLS multivariant playlist; chose a variant"
                );
                if choice.over_cap {
                    tracing::warn!(
                        bandwidth = choice.variant.bandwidth,
                        max_bandwidth = options.max_bandwidth,
                        "http: no variant fits max_bandwidth; playing the lowest instead"
                    );
                }
                let variant = choice.variant.uri.clone();
                let mut feeds = vec![fetch::follow(
                    first, variant, None, "variant", &ctx.time, &stop,
                )];
                if let Some(audio) = choice.audio_playlist() {
                    let rendition = client(connector);
                    feeds.push(fetch::follow(
                        rendition,
                        audio.clone(),
                        None,
                        "audio rendition",
                        &ctx.time,
                        &stop,
                    ));
                }
                feeds
            }
        },
    };
    Program::new(feeds, ctx).play().await
}

/// What a stream's queue holds, in the order its reader produced it.
#[derive(Debug)]
enum Item {
    /// The stream's tracks from here on.
    Layout(Layout),
    /// A new timeline starts here.
    Epoch,
    /// A unit, indexing the stream's own layout.
    Unit(Unit),
}

impl Item {
    /// Where it goes in the merge of the streams: layouts and epochs at
    /// once (`None` sorts first), units by decoding time.
    const fn order(&self) -> Option<i64> {
        match self {
            Self::Layout(_) | Self::Epoch => None,
            Self::Unit(unit) => Some(unit.decode_time),
        }
    }
}

impl From<Event> for Item {
    fn from(event: Event) -> Self {
        match event {
            Event::Layout(layout) => Self::Layout(layout),
            Event::Unit(unit) => Self::Unit(unit),
        }
    }
}

/// How far, in 90 kHz ticks, a unit moves ahead of the queued units of
/// its stream to stand in decoding order: one second, the longest any
/// data stays in the decoder's buffers (ISO/IEC 13818-1 §2.4.2.6, T-STD),
/// so the longest a multiplex delivers a unit before its decoding time. A
/// demultiplexer hands an audio PES packet's frames on only once it ends,
/// after the video multiplexed alongside it; queued as they came, they
/// would be released when that video is, up to a PES packet's duration
/// late (ffmpeg's default `-max_delay` packs 0.7 s of audio into one). A
/// unit decoded more than this before the units queued ahead of it
/// starts another timeline (a timestamp reset) and stays behind them.
const REORDER_TICKS: i64 = 90_000;

/// Queues `item` behind the items of `queue`, a unit ahead of the units of
/// its timeline it is decoded before (within [`REORDER_TICKS`]): never
/// ahead of a layout or an epoch, nor of a unit with the same decoding
/// time, which keep their order.
fn enqueue(queue: &mut VecDeque<Item>, item: Item) {
    let mut at = queue.len();
    if let Item::Unit(unit) = &item {
        while let Some(before) = at.checked_sub(1) {
            let Some(Item::Unit(queued)) = queue.get(before) else {
                break;
            };
            let ahead = queued.decode_time.saturating_sub(unit.decode_time);
            if ahead <= 0 || ahead > REORDER_TICKS {
                break;
            }
            at = before;
        }
    }
    queue.insert(at, item);
}

/// Transport packets a segment's continuity errors say were lost
/// (ISO/IEC 13818-1 §2.4.3.3).
#[derive(Debug)]
struct Lost(u64);

/// One media stream of the program: the variant's or the raw MPEG-TS, or
/// an audio rendition's.
#[derive(Debug)]
struct Stream {
    /// Its segments.
    feed: Feed,
    /// What its reader produced and the merge has not taken yet, units in
    /// decoding order ([`enqueue`]).
    queue: VecDeque<Item>,
    /// The MPEG-TS reader of the current timeline, with the continuity
    /// errors already counted.
    ts: Option<(Demuxer, u64)>,
    /// The fragmented MP4 reader of the current timeline, with the init
    /// segment it read.
    fmp4: Option<(fmp4::Reader, Bytes)>,
    /// Its tracks, once known.
    layout: Option<Layout>,
    /// Why its feed ended, once it has: it has no segment left.
    ended: Option<SourceError>,
}

impl Stream {
    /// A stream on `feed`, nothing read yet.
    const fn new(feed: Feed) -> Self {
        Self {
            feed,
            queue: VecDeque::new(),
            ts: None,
            fmp4: None,
            layout: None,
            ended: None,
        }
    }

    /// Whether the merge has to wait for its next segment.
    fn starved(&self) -> bool {
        self.queue.is_empty() && self.ended.is_none()
    }

    /// Takes the feed's next segment into the queue: the continuity errors
    /// it brought. An ended feed ([`SourceError::Ended`]) leaves the stream
    /// to be played out; any other error ends the attempt, and so does a
    /// feed whose task is gone without a reason: it was stopped.
    async fn receive(&mut self, max_frame_bytes: usize) -> Result<Lost, SourceError> {
        match self.feed.recv().await.ok_or_else(cancelled)? {
            Ok(segment) => self.read(segment, max_frame_bytes).map(Lost),
            Err(SourceError::Ended(reason)) => {
                self.ended = Some(SourceError::Ended(reason));
                Ok(Lost(0))
            }
            Err(err) => Err(err),
        }
    }

    /// Reads `segment` into the queue, after an epoch and with fresh
    /// readers when it starts a new timeline.
    fn read(&mut self, segment: Segment, max_frame_bytes: usize) -> Result<u64, SourceError> {
        if segment.discontinuity {
            self.ts = None;
            self.fmp4 = None;
            self.queue.push_back(Item::Epoch);
        }
        let mut events = Vec::new();
        let mut lost = 0;
        match segment.format {
            Format::Ts => {
                let (demuxer, counted) = self
                    .ts
                    .get_or_insert_with(|| (Demuxer::new(max_frame_bytes), 0));
                demuxer.push(&segment.data, &mut events);
                if segment.ends {
                    demuxer.flush(&mut events);
                }
                let errors = demuxer.stats().continuity_errors;
                lost = errors.saturating_sub(*counted);
                *counted = errors;
            }
            Format::Fmp4 { init } => {
                let mut reader = match self.fmp4.take() {
                    Some((reader, read)) if read == init => reader,
                    _ => {
                        let reader = fmp4::Reader::new(&init, max_frame_bytes)
                            .map_err(|err| protocol(format_args!("fmp4: {err}")))?;
                        events.push(Event::Layout(reader.layout().clone()));
                        reader
                    }
                };
                let mut units = Vec::new();
                let read = reader.read_segment(&segment.data, &mut units);
                self.fmp4 = Some((reader, init));
                read.map_err(|err| protocol(format_args!("fmp4: {err}")))?;
                events.extend(units.into_iter().map(Event::Unit));
            }
        }
        for event in events {
            enqueue(&mut self.queue, Item::from(event));
        }
        Ok(lost)
    }
}

/// The program of one attempt: its streams merged into one timeline and
/// published on the connection's tracks.
#[derive(Debug)]
struct Program {
    /// The streams, the variant's (or the only one) first.
    streams: Vec<Stream>,
    /// The publisher, once every stream's tracks are known.
    publisher: Option<Publisher>,
    /// Transport packets lost and not yet counted on the tracks.
    lost: u64,
    /// The largest frame the tracks accept; the readers' bound.
    max_frame_bytes: usize,
    /// The source's context.
    ctx: SourceCtx,
}

impl Program {
    /// The program of `feeds`, in that order.
    fn new(feeds: Vec<Feed>, ctx: SourceCtx) -> Self {
        Self {
            streams: feeds.into_iter().map(Stream::new).collect(),
            publisher: None,
            lost: 0,
            max_frame_bytes: ctx.tracks.tracks().limits().max_frame_bytes,
            ctx,
        }
    }

    /// Plays until a stream fails, every stream has ended and is played
    /// out, the program's tracks change, or the attempt is cancelled.
    async fn play(mut self) -> Result<Infallible, SourceError> {
        loop {
            if let Some(stream) = self.streams.iter_mut().find(|stream| stream.starved()) {
                let Lost(lost) =
                    cancellable(&self.ctx.cancel, stream.receive(self.max_frame_bytes)).await?;
                let ended = stream.ended.is_some();
                self.lost = self.lost.saturating_add(lost);
                if ended && self.publisher.is_none() {
                    self.declare()?;
                }
                if let Some(publisher) = self.publisher.as_mut() {
                    publisher.count_lost(std::mem::take(&mut self.lost), self.ctx.time.now());
                }
                continue;
            }
            let Some((index, item)) = self.take() else {
                return Err(self.finished());
            };
            match item {
                Item::Layout(layout) => {
                    if let Some(stream) = self.streams.get_mut(index) {
                        stream.layout = Some(layout);
                    }
                    self.declare()?;
                }
                Item::Epoch => {
                    if let Some(publisher) = self.publisher.as_mut() {
                        publisher.new_epoch("an HLS discontinuity, gap or restart");
                    }
                }
                Item::Unit(mut unit) => {
                    unit.track = unit.track.saturating_add(self.offset(index));
                    self.release(unit).await?;
                }
            }
        }
    }

    /// The next item of the merge and the stream it is from: a layout or
    /// an epoch at a stream's head first, else the unit due first.
    fn take(&mut self) -> Option<(usize, Item)> {
        let (_, index) = self
            .streams
            .iter()
            .enumerate()
            .filter_map(|(index, stream)| Some((stream.queue.front()?.order(), index)))
            .min()?;
        Some((index, self.streams.get_mut(index)?.queue.pop_front()?))
    }

    /// Why the attempt ends once every stream ended and is played out:
    /// the first stream's reason.
    fn finished(&mut self) -> SourceError {
        self.streams
            .iter_mut()
            .find_map(|stream| stream.ended.take())
            .unwrap_or_else(cancelled)
    }

    /// The index of stream `index`'s first track in the program: the
    /// tracks of the streams before it.
    fn offset(&self, index: usize) -> usize {
        self.streams
            .iter()
            .take(index)
            .filter_map(|stream| stream.layout.as_ref())
            .map(|layout| layout.tracks.len())
            .sum()
    }

    /// The program's tracks: every stream's, in stream order.
    fn layout(&self) -> Layout {
        let layouts = || {
            self.streams
                .iter()
                .filter_map(|stream| stream.layout.as_ref())
        };
        Layout {
            program_number: layouts().next().map_or(0, |layout| layout.program_number),
            tracks: layouts()
                .flat_map(|layout| layout.tracks.iter().cloned())
                .collect(),
        }
    }

    /// Declares the program's tracks once every stream that still plays
    /// knows its own, or takes a new layout of the same tracks; a layout
    /// with other tracks ends the attempt.
    fn declare(&mut self) -> Result<(), SourceError> {
        if !self
            .streams
            .iter()
            .all(|stream| stream.layout.is_some() || stream.ended.is_some())
        {
            return Ok(());
        }
        let layout = self.layout();
        if let Some(publisher) = self.publisher.as_mut() {
            return publisher
                .relayout(&layout)
                .map_err(|changed| SourceError::Ended(changed.to_string()));
        }
        let publisher = Publisher::new(
            &mut self.ctx.tracks,
            self.ctx.clock.clone(),
            &layout,
            MAX_LEAD,
        )?;
        tracing::info!(
            tracks = layout.tracks.len(),
            streams = self.streams.len(),
            "http: playing"
        );
        self.publisher = Some(publisher);
        Ok(())
    }

    /// Publishes `unit` when it is due, waiting for it on the clock. A
    /// unit comes only after its stream's layout, and the program is
    /// declared once every playing stream has one.
    async fn release(&mut self, unit: Unit) -> Result<(), SourceError> {
        let publisher = self
            .publisher
            .as_mut()
            .ok_or(SourceError::Ended(String::new()))?;
        while let Some(at) = publisher.due(&unit, self.ctx.time.now()) {
            let wait = at.saturating_duration_since(self.ctx.time.now());
            cancellable(&self.ctx.cancel, async {
                self.ctx.time.sleep(wait).await;
                Ok(())
            })
            .await?;
        }
        publisher.publish(unit, self.ctx.time.now());
        Ok(())
    }
}
