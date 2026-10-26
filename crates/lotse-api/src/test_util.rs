//! A stand-in for the handler's clips, for tests (`test-util`): what a
//! test [`Handler`](crate::Handler) answers `clip_body` with, and the
//! producer's end that writes a clip's bytes and reports its end, as a
//! worker writes its pipe and the supervisor relays its report.

use std::collections::HashMap;
use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};

use lotse_core::id::ClipId;
use tokio::io::{AsyncWriteExt as _, DuplexStream};
use tokio::sync::oneshot;

use crate::{ClipBody, ClipBodyError};

/// How many bytes of a fake clip may be written and not yet read: a Linux
/// pipe's default capacity (pipe(7)).
const BUFFERED: usize = 64 * 1024;

/// Clips by id, each one's body handed out once, as the supervisor hands
/// them out.
#[derive(Debug, Default)]
pub struct FakeClips {
    /// Each open clip's body, `None` once taken.
    clips: Mutex<HashMap<String, Option<ClipBody>>>,
}

impl FakeClips {
    /// Opens clip `clip_id`, replacing one of that id, and returns the end
    /// that writes its bytes.
    pub fn open(&self, clip_id: &str) -> FakeClipWriter {
        let (reader, writer) = tokio::io::duplex(BUFFERED);
        let (report, written) = oneshot::channel();
        let body = ClipBody {
            reader: Box::new(reader),
            written,
        };
        self.lock().insert(clip_id.to_owned(), Some(body));
        FakeClipWriter {
            writer,
            report,
            bytes: 0,
        }
    }

    /// What `Handler::clip_body` answers: the body of an open clip once,
    /// [`ClipBodyError::AlreadyFetched`] after, and
    /// [`ClipBodyError::NotFound`] for an id never opened.
    pub fn take(&self, clip_id: &ClipId) -> Result<ClipBody, ClipBodyError> {
        self.lock()
            .get_mut(clip_id.as_str())
            .ok_or(ClipBodyError::NotFound)?
            .take()
            .ok_or(ClipBodyError::AlreadyFetched)
    }

    /// The clips, whatever a panicking test left behind.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Option<ClipBody>>> {
        self.clips.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The producer's end of a [`FakeClips`] clip. Dropped unfinished, it ends
/// the clip as a crashed worker does: its bytes end and no report comes.
#[derive(Debug)]
pub struct FakeClipWriter {
    /// Where the clip's bytes go.
    writer: DuplexStream,
    /// The report of the bytes written.
    report: oneshot::Sender<u64>,
    /// The bytes written so far.
    bytes: u64,
}

impl FakeClipWriter {
    /// Writes `bytes` to the clip, waiting while 64 KiB, a pipe's capacity,
    /// wait for the reader; fails once the reader is gone, as a pipe whose
    /// read end closed does (`EPIPE`).
    pub async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer.write_all(bytes).await?;
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(len);
        Ok(())
    }

    /// Ends the clip whole: its bytes end and the report names every one
    /// written.
    pub fn finish(self) {
        let bytes = self.bytes;
        self.finish_reporting(bytes);
    }

    /// Ends the clip with a report of `bytes` written, whatever was.
    pub fn finish_reporting(self, bytes: u64) {
        drop(self.writer);
        let _reported = self.report.send(bytes);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use futures_util::FutureExt as _;
    use tokio::io::AsyncReadExt as _;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_7_a_fake_clip_holds_64_kib_unread_and_its_producer_waits_past_that() {
        let clips = FakeClips::default();
        let mut writer = clips.open("c1");
        let full = vec![1_u8; 64 * 1024];
        assert!(
            writer
                .write(&full)
                .now_or_never()
                .is_some_and(|written| written.is_ok()),
            "a pipe's capacity is written without a reader"
        );
        assert!(
            writer.write(b"x").now_or_never().is_none(),
            "one byte more waits for the reader"
        );
        let mut body = clips.take(&ClipId::new("c1").unwrap()).unwrap();
        let mut read = vec![0_u8; 64 * 1024];
        body.reader.read_exact(&mut read).await.unwrap();
        assert_eq!(read, full);
        writer.finish();
        assert_eq!(body.written.await.unwrap(), 64 * 1024);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_fake_clip_dropped_unfinished_ends_its_bytes_without_a_report() {
        let clips = FakeClips::default();
        let mut writer = clips.open("c1");
        writer.write(b"ftyp").await.unwrap();
        drop(writer);
        let mut body = clips.take(&ClipId::new("c1").unwrap()).unwrap();
        let mut bytes = Vec::new();
        body.reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"ftyp");
        assert!(body.written.await.is_err(), "no report");
    }
}
