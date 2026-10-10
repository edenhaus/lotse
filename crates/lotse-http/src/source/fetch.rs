//! The fetch tasks of the HTTP source: one per HLS media playlist, which
//! reloads it and fetches its segments in order (RFC 8216 §6.3.2,
//! §6.3.4), or one that streams a raw MPEG-TS body. Each hands its
//! segments to the playback through a bounded channel, so it runs at most
//! [`QUEUED_SEGMENTS`] segments ahead, and ends with the attempt's stop
//! token. Its last message is why it ended.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use lotse_core::clock::Clock;
use lotse_core::source::SourceError;
use lotse_core::task::spawn_named;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{cancelled, is_mpegts, protocol};
use crate::client::{Body, Client, Connect};
use crate::hls::{self, Event, Fetch, MediaPlaylist, Playlist, Tracker};

/// How many fetched segments wait for the playback at most: the one being
/// played is read already, these are the next ones, so a reload that
/// comes late or a slow segment does not starve the playback.
pub(super) const QUEUED_SEGMENTS: usize = 2;

/// The largest media segment fetched, in bytes: 32 MiB, a 4-second segment
/// at 64 Mbit/s. A segment is held whole, so at most
/// [`QUEUED_SEGMENTS`] + 2 of them are in memory per stream.
pub(super) const MAX_SEGMENT_BYTES: usize = 32 << 20;

/// The largest init segment fetched (RFC 8216 §4.3.2.5), in bytes: a
/// movie box with its sample descriptions, a few kilobytes in practice.
pub(super) const MAX_INIT_BYTES: usize = 1 << 20;

/// How many target durations a live playlist may go without a new segment
/// before the source has stalled: twice the 1.5 the server must keep to
/// (RFC 8216 §6.2.1, a new version with a new segment no later than 1.5
/// times the target duration after the previous one).
pub(super) const STALL_TARGET_DURATIONS: u32 = 3;

/// The segments of one stream, then why it ended.
pub(super) type Feed = mpsc::Receiver<Result<Segment, SourceError>>;

/// How a segment's bytes are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Format {
    /// MPEG-TS (RFC 8216 §3.2).
    Ts,
    /// Fragmented MP4 (RFC 8216 §3.3) against this init segment.
    Fmp4 {
        /// The `EXT-X-MAP` init segment.
        init: Bytes,
    },
}

/// One fetched segment, or one piece of a raw MPEG-TS body.
#[derive(Debug)]
pub(super) struct Segment {
    /// The bytes.
    pub(super) data: Bytes,
    /// How to read them.
    pub(super) format: Format,
    /// Whether a new timeline starts with them ([`Fetch::discontinuity`]).
    pub(super) discontinuity: bool,
    /// Whether they end a segment, so the reader's open units end too: an
    /// HLS segment, not a piece of a raw body.
    pub(super) ends: bool,
}

/// Starts the fetch task of the media playlist at `url` (`what` it is,
/// for the logs), its first load already in hand as `first` when the
/// source URL was the media playlist itself.
pub(super) fn follow<C: Connect + 'static>(
    client: Client<C>,
    url: Url,
    first: Option<MediaPlaylist>,
    what: &'static str,
    clock: &Arc<dyn Clock>,
    stop: &CancellationToken,
) -> Feed {
    let (tx, rx) = mpsc::channel(QUEUED_SEGMENTS);
    let mut follower = Follower {
        client,
        url,
        what,
        clock: Arc::clone(clock),
        tracker: Tracker::new(),
        map: None,
    };
    let stop = stop.clone();
    let _detached = spawn_named("http.hls", async move {
        tokio::select! {
            () = stop.cancelled() => {}
            () = async {
                let Err(end) = follower.run(first, &tx).await;
                tracing::debug!(playlist = what, error = %end, "http: the playlist's fetch task ends");
                let _closed = tx.send(Err(end)).await;
            } => {}
        }
    });
    rx
}

/// Starts the task that streams a raw MPEG-TS body, `head` already read.
pub(super) fn mpegts(head: Bytes, body: Body, stop: &CancellationToken) -> Feed {
    let (tx, rx) = mpsc::channel(QUEUED_SEGMENTS);
    let stop = stop.clone();
    let _detached = spawn_named("http.mpegts", async move {
        tokio::select! {
            () = stop.cancelled() => {}
            () = async {
                let Err(end) = stream(head, body, &tx).await;
                let _closed = tx.send(Err(end)).await;
            } => {}
        }
    });
    rx
}

/// Hands the body on piece by piece as it arrives, until it ends: the
/// server ended the stream ([`SourceError::Ended`]).
async fn stream(
    mut piece: Bytes,
    mut body: Body,
    tx: &mpsc::Sender<Result<Segment, SourceError>>,
) -> Result<Infallible, SourceError> {
    loop {
        let segment = Segment {
            data: piece,
            format: Format::Ts,
            discontinuity: false,
            ends: false,
        };
        tx.send(Ok(segment)).await.map_err(|_| cancelled())?;
        piece = body
            .chunk()
            .await?
            .ok_or_else(|| SourceError::Ended("the server ended the MPEG-TS stream".into()))?;
    }
}

/// Follows one media playlist.
struct Follower<C: Connect> {
    /// Its client, one request at a time.
    client: Client<C>,
    /// The playlist's URL.
    url: Url,
    /// What the playlist is, for logs and errors: "media", "variant" or
    /// "audio rendition".
    what: &'static str,
    /// Reload times and the stall deadline.
    clock: Arc<dyn Clock>,
    /// Which segments each load adds.
    tracker: Tracker,
    /// The last `EXT-X-MAP` fetched: its URL and the init segment.
    map: Option<(Url, Bytes)>,
}

impl<C: Connect> Follower<C> {
    /// Loads, fetches and reloads until the playlist ends or something
    /// fails: `Ended` after the last segment of a playlist with
    /// `EXT-X-ENDLIST`, `Timeout` for a live playlist that stopped adding
    /// segments, the client's error for a failed fetch.
    async fn run(
        &mut self,
        mut first: Option<MediaPlaylist>,
        tx: &mpsc::Sender<Result<Segment, SourceError>>,
    ) -> Result<Infallible, SourceError> {
        let mut grew_at = self.clock.now();
        loop {
            let loaded_at = self.clock.now();
            let playlist = match first.take() {
                Some(playlist) => playlist,
                None => self.load().await?,
            };
            let update = self.tracker.update(&playlist);
            self.log(update.event);
            if !update.segments.is_empty() {
                grew_at = loaded_at;
            } else if !playlist.end_list {
                self.check_stall(&playlist, grew_at, loaded_at)?;
            }
            for fetch in update.segments {
                let segment = self.segment(fetch).await?;
                tx.send(Ok(segment)).await.map_err(|_| cancelled())?;
            }
            let after = update.reload_after.ok_or_else(|| {
                SourceError::Ended(format!(
                    "the {} playlist ended (EXT-X-ENDLIST, RFC 8216 §4.3.3.4)",
                    self.what
                ))
            })?;
            let since = self.clock.now().saturating_duration_since(loaded_at);
            self.clock.sleep(after.saturating_sub(since)).await;
        }
    }

    /// Loads the playlist, which must be a media playlist.
    async fn load(&mut self) -> Result<MediaPlaylist, SourceError> {
        let response = self.client.get(&self.url).await?;
        let base = response.url().clone();
        let bytes = response.into_body().bytes(hls::MAX_PLAYLIST_BYTES).await?;
        match hls::parse(&bytes, &base).map_err(protocol)? {
            Playlist::Media(playlist) => Ok(playlist),
            Playlist::Multivariant(_) => Err(SourceError::Protocol(format!(
                "the {} playlist is a multivariant playlist, not a media playlist (RFC 8216 §4.3.4.2)",
                self.what
            ))),
        }
    }

    /// Logs what a load found besides new segments; the next segment
    /// starts a new timeline for it.
    fn log(&self, event: Option<Event>) {
        match event {
            Some(Event::Gap { lost }) => tracing::warn!(
                playlist = self.what,
                lost,
                "http: the playlist moved past segments not yet fetched; they are lost (RFC 8216 §6.3.2)"
            ),
            Some(Event::Restart) => tracing::info!(
                playlist = self.what,
                "http: the playlist restarted; playing from its live edge"
            ),
            None => {}
        }
    }

    /// Fails when the live playlist went [`STALL_TARGET_DURATIONS`] target
    /// durations without a new segment, from `grew_at` to `loaded_at`. An
    /// ended playlist adds none and is no stall.
    fn check_stall(
        &self,
        playlist: &MediaPlaylist,
        grew_at: Instant,
        loaded_at: Instant,
    ) -> Result<(), SourceError> {
        let still = loaded_at.saturating_duration_since(grew_at);
        let limit = playlist
            .target_duration
            .saturating_mul(STALL_TARGET_DURATIONS);
        if still >= limit {
            tracing::warn!(
                playlist = self.what,
                still_ms = still.as_millis(),
                target_duration_ms = playlist.target_duration.as_millis(),
                "http: the live playlist stopped adding segments"
            );
            return Err(SourceError::Timeout(format!(
                "the {} playlist added no segment in {} ms, {STALL_TARGET_DURATIONS} times its target duration (RFC 8216 §6.2.1)",
                self.what,
                still.as_millis()
            )));
        }
        Ok(())
    }

    /// Fetches one segment, and its init segment when the `EXT-X-MAP`
    /// changed. A segment without one must be MPEG-TS (RFC 8216 §3.2).
    async fn segment(&mut self, fetch: Fetch) -> Result<Segment, SourceError> {
        let format = match &fetch.segment.map {
            Some(map) => Format::Fmp4 {
                init: self.init(map).await?,
            },
            None => Format::Ts,
        };
        let data = self
            .client
            .get(&fetch.segment.uri)
            .await?
            .into_body()
            .bytes(MAX_SEGMENT_BYTES)
            .await?;
        if format == Format::Ts && !is_mpegts(&data) {
            return Err(SourceError::Protocol(format!(
                "segment {} of the {} playlist is neither MPEG-TS (RFC 8216 §3.2) nor fragmented MP4 with an EXT-X-MAP (§3.3); packed audio (§3.4) is not supported",
                fetch.sequence, self.what
            )));
        }
        tracing::debug!(
            playlist = self.what,
            sequence = fetch.sequence,
            discontinuity_sequence = fetch.discontinuity_sequence,
            discontinuity = fetch.discontinuity,
            bytes = data.len(),
            "http: segment fetched"
        );
        Ok(Segment {
            data,
            format,
            discontinuity: fetch.discontinuity,
            ends: true,
        })
    }

    /// The init segment at `map`, fetched only when it differs from the
    /// last one (RFC 8216 §4.3.2.5: it applies until the next
    /// `EXT-X-MAP`).
    async fn init(&mut self, map: &Url) -> Result<Bytes, SourceError> {
        if let Some((current, init)) = &self.map
            && current == map
        {
            return Ok(init.clone());
        }
        let init = self
            .client
            .get(map)
            .await?
            .into_body()
            .bytes(MAX_INIT_BYTES)
            .await?;
        tracing::info!(
            playlist = self.what,
            bytes = init.len(),
            "http: init segment fetched (EXT-X-MAP)"
        );
        self.map = Some((map.clone(), init.clone()));
        Ok(init)
    }
}
