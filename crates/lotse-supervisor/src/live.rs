//! Live outputs as the supervisor keeps them: which stream and source
//! connection each plays, which control connection's subscription gets its
//! events, the `live/create` that waits for its MIME type, the read end of
//! the pipe its worker writes until `GET /v0/live/{live_id}` takes it, and the
//! mapping of a worker's live reports onto the API's events
//! (`lotse_api_types::live`).
//!
//! The worker makes the output; the supervisor owns its signaling and its
//! body, and never sees a byte of it: the bytes go from the worker's write
//! end to the body through the kernel. A live output is demand on its
//! connection, as a viewer is, from `live/create` until it ends. Its id is a
//! ULID the supervisor generates, so no client can make two outputs share one.
//!
//! A worker's report is untrusted, as its recording reports are: it is
//! accepted only for an output of that worker's own connection; the MIME
//! type of `Started` must be printable ASCII of at most [`MAX_MIME_BYTES`]
//! starting with `video/mp4`, a warning's code a known one (its message made
//! [`plain`] and capped), a `Closed`'s reason a worker's own one, and a
//! second `Started` breaks the contract too. A report that breaks it is
//! dropped, logged, and ends its output `internal_error`.
//!
//! An output ends with its worker's `Closed`. When the supervisor ends one
//! itself (`live/close`, `closed`; its subscription or control connection
//! gone, `session_closed`; its body not fetched within
//! [`LiveLimits::fetch_timeout`], `not_fetched`; its stream deleted or moved,
//! `stream_deleted` and `stream_changed`; shutdown) it asks the worker
//! through a slot reserved in the driver's queue at `live/create` and waits
//! for that report, its own reason in place of the worker's
//! [`STOPPED_AS_ASKED`]. A start that never reached a worker ends at once,
//! and so does every output of a worker that exits (`worker_crashed`, or the
//! reason the supervisor gave), whose body then ends as its pipe's write end
//! closed. `limits.max_live` counts every open output, and
//! `limits.max_live_per_stream` those of one stream; reaching either is
//! `limit_reached`, logged at warn, rate-limited, as a client can ask again
//! and again.

use std::time::Duration;

use lotse_api::{ConnectionId, Event, EventClass, LiveBody, LiveBodyError};
use lotse_api_types::live::{LiveCloseReason, LiveEvent, LiveWarningCode};
use lotse_core::text::plain;
use lotse_ipc::{LiveReport, STOPPED_AS_ASKED};
use tokio::net::unix::pipe;
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::oneshot;

use crate::driver::DriverCommand;
use crate::recording::RecordingTimer;
use crate::registry::State;
use crate::worker_text::{MAX_MESSAGE_BYTES, MAX_NAME_BYTES};

/// Events a live output's subscription holds: its one warning and `closed`,
/// with room to spare; its own events never fill it.
pub(crate) const LIVE_QUEUE: usize = 4;

/// The longest MIME type a worker's `Started` may carry: a video and an
/// audio `codecs` entry fit many times over.
pub(crate) const MAX_MIME_BYTES: usize = 256;

/// The limits on live outputs, `limits.live_*`, `limits.max_live` and
/// `limits.max_live_per_stream` as the binary resolves them. A supervisor
/// with a live output keeps them; one without keeps [`LiveLimits::NONE`],
/// and its workers refuse every live output. The worker's share
/// (`start_timeout`, `max_live_per_stream`) reaches each worker as its
/// flags, so both processes hold the same bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveLimits {
    /// `limits.live_buffer_bytes`: what one output holds in its worker that
    /// its reader has not taken, past which it drops to the next keyframe.
    pub buffer_bytes: u32,
    /// `limits.live_fetch_timeout_ms`: how long an output's body waits for
    /// its `GET` from the `live/create` result on.
    pub fetch_timeout: Duration,
    /// `limits.live_start_timeout_ms`: how long `live/create` waits for the
    /// worker's init segment, and the worker for the tracks, a video codec it
    /// carries and, after the fetch, a keyframe.
    pub start_timeout: Duration,
    /// `limits.max_live`: live outputs open at once over every stream.
    pub max_live: u32,
    /// `limits.max_live_per_stream`: live outputs open at once on one stream,
    /// and in one worker.
    pub max_live_per_stream: u32,
}

impl LiveLimits {
    /// The defaults: 1 MiB of bytes in flight per output (2 s of a 4 Mbit/s
    /// camera, so a client that falls behind drops early instead of
    /// lagging), 10 s to fetch and to start (the worker's
    /// `DEFAULT_LIVE_START_TIMEOUT`), 16 outputs, 8 per stream (the worker's
    /// `DEFAULT_MAX_LIVE_PER_STREAM`).
    pub const DEFAULT: Self = Self {
        buffer_bytes: 1024 * 1024,
        fetch_timeout: Duration::from_secs(10),
        start_timeout: Duration::from_secs(10),
        max_live: 16,
        max_live_per_stream: 8,
    };

    /// No live output: a supervisor without a live container says so with
    /// these zeros.
    pub const NONE: Self = Self {
        buffer_bytes: 0,
        fetch_timeout: Self::DEFAULT.fetch_timeout,
        start_timeout: Self::DEFAULT.start_timeout,
        max_live: 0,
        max_live_per_stream: 0,
    };
}

/// [`LiveLimits::NONE`]: what a supervisor holds until it knows it has a
/// live container.
impl Default for LiveLimits {
    fn default() -> Self {
        Self::NONE
    }
}

/// The control connection's subscription that gets an output's events.
#[derive(Debug)]
pub(crate) struct LiveOwner {
    /// The control connection.
    pub(crate) connection: ConnectionId,
    /// The subscription: the id of its `live/create`.
    pub(crate) subscription: u64,
    /// Where the events go; dropping it ends the subscription.
    pub(crate) events: mpsc::Sender<Event>,
}

/// What `live/create` waits for: the worker's MIME type and audio, or the
/// reason the output ended first.
pub(crate) type StartWait = oneshot::Sender<Result<String, LiveCloseReason>>;

/// One open live output.
#[derive(Debug)]
pub(crate) struct LiveEntry {
    /// Unique over the daemon's lifetime, so its timer never acts on a
    /// later output.
    pub(crate) serial: u64,
    /// The stream it plays.
    pub(crate) stream_id: String,
    /// The source connection whose worker writes it.
    pub(crate) connection: String,
    /// The subscription, until the control connection closes or
    /// unsubscribes.
    pub(crate) owner: Option<LiveOwner>,
    /// The `live/create` waiting for the MIME type, until `Started`.
    pub(crate) waiting: Option<StartWait>,
    /// The MIME type, once started.
    pub(crate) mime: Option<String>,
    /// The body, until its `GET` takes it.
    pub(crate) body: Option<pipe::Receiver>,
    /// The slot reserved in the driver's queue for the fetch.
    pub(crate) fetch_slot: Option<OwnedPermit<DriverCommand>>,
    /// The slot reserved in the driver's queue for the stop: a full queue
    /// never keeps a stop from the worker.
    pub(crate) stop_slot: Option<OwnedPermit<DriverCommand>>,
    /// The supervisor asked the worker to stop it, for this reason, which
    /// its `closed` then carries.
    pub(crate) ending: Option<LiveCloseReason>,
    /// The worker's `audio_omitted` went out.
    pub(crate) warned: bool,
    /// The fetch deadline, from the result on.
    pub(crate) timer: Option<RecordingTimer>,
}

/// A live event as the server queues it: signaling, never shed.
pub(crate) fn live_event(event: &LiveEvent) -> Event {
    Event {
        class: EventClass::Signaling,
        payload: serde_json::to_value(event).unwrap_or_default(),
    }
}

/// Whether `mime` is a MIME type a worker may report: printable ASCII,
/// at most [`MAX_MIME_BYTES`], of the live container's `video/mp4`.
fn valid_mime(mime: &str) -> bool {
    mime.len() <= MAX_MIME_BYTES
        && mime.starts_with("video/mp4")
        && mime
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

/// The API's reason of a worker's `Closed`: its own reasons, or the one the
/// supervisor gave for its own stop ([`STOPPED_AS_ASKED`]); `None` for a
/// reason the worker may not give.
fn worker_reason(reason: &str, ending: Option<LiveCloseReason>) -> Option<LiveCloseReason> {
    if reason == STOPPED_AS_ASKED {
        return ending;
    }
    LiveCloseReason::parse(reason).filter(|reason| {
        !matches!(
            reason,
            LiveCloseReason::Closed
                | LiveCloseReason::SessionClosed
                | LiveCloseReason::NotFetched
                | LiveCloseReason::WorkerCrashed
        )
    })
}

/// What a worker's report does to its output.
enum Applied {
    /// It started, with this MIME type.
    Started(String),
    /// It warned: the code and the message, made plain.
    Warned(LiveWarningCode, String),
    /// The output ends, with these figures.
    End {
        /// Why.
        reason: LiveCloseReason,
        /// The bytes the worker wrote.
        bytes: u64,
        /// The frames it dropped.
        dropped_frames: u64,
        /// How often it dropped.
        drops: u32,
    },
}

impl LiveEntry {
    /// Passes `event` to the owner; a full or closed subscription drops it.
    fn deliver(&self, live_id: &str, event: &LiveEvent) {
        if let Some(owner) = &self.owner
            && owner.events.try_send(live_event(event)).is_err()
        {
            tracing::debug!(
                live.id = live_id,
                "live event dropped: its subscription is gone or full"
            );
        }
    }

    /// Applies one worker report; the reason it breaks the contract.
    fn apply(&mut self, live_id: &str, report: LiveReport) -> Result<Applied, &'static str> {
        match report {
            LiveReport::Started { mime, .. } => {
                if self.mime.is_some() {
                    return Err("a second started");
                }
                if !valid_mime(&mime) {
                    return Err("a MIME type that is not the live container's");
                }
                tracing::info!(event = "live_started", live.id = live_id, mime = %mime, "live output started");
                self.mime = Some(mime.clone());
                if let Some(waiting) = self.waiting.take() {
                    // The command gave up meanwhile: nobody to tell.
                    let _told = waiting.send(Ok(mime.clone()));
                }
                Ok(Applied::Started(mime))
            }
            LiveReport::Warning { code, message } => {
                let Some(code) = LiveWarningCode::parse(&code) else {
                    return Err("an unknown warning");
                };
                if self.warned {
                    return Err("a repeated warning");
                }
                self.warned = true;
                let message = plain(&message, MAX_MESSAGE_BYTES);
                tracing::info!(live.id = live_id, code = code.as_str(), message = %message, "live output warned");
                self.deliver(
                    live_id,
                    &LiveEvent::Warning {
                        code,
                        message: message.clone(),
                    },
                );
                Ok(Applied::Warned(code, message))
            }
            LiveReport::Closed {
                reason,
                bytes,
                dropped_frames,
                drops,
            } => {
                let reason = worker_reason(&reason, self.ending)
                    .ok_or("a reason the worker may not give")?;
                Ok(Applied::End {
                    reason,
                    bytes,
                    dropped_frames,
                    drops,
                })
            }
        }
    }

    /// Asks the worker to stop the output through its reserved slot.
    fn ask_stop(&mut self, live_id: &str) {
        if let Some(slot) = self.stop_slot.take() {
            drop(slot.send(DriverCommand::StopLive {
                live_id: live_id.to_owned(),
            }));
        }
    }
}

impl State {
    /// A worker's report about one of its live outputs. One about an output
    /// the supervisor does not hold is dropped (its subscription and body are
    /// gone; a pipe nobody reads ends the worker's output `client_gone`), one
    /// about another connection's is refused, and one that breaks the
    /// contract ends the output `internal_error`.
    pub(crate) fn live_report(&mut self, connection: &str, live_id: &str, report: LiveReport) {
        let last = matches!(report, LiveReport::Closed { .. });
        let Some(entry) = self.lives.get_mut(live_id) else {
            tracing::debug!(
                live.id = %plain(live_id, MAX_NAME_BYTES),
                connection.id = connection,
                "report for a live output the supervisor does not hold; dropped"
            );
            return;
        };
        if entry.connection != connection {
            tracing::warn!(
                live.id = live_id,
                connection.id = connection,
                "a worker reported a live output it does not run; ignored"
            );
            return;
        }
        match entry.apply(live_id, report) {
            Ok(Applied::Started(mime)) => self.hls_live_started(live_id, &mime),
            Ok(Applied::Warned(code, message)) => self.hls_live_warned(live_id, code, &message),
            Ok(Applied::End {
                reason,
                bytes,
                dropped_frames,
                drops,
            }) => self.close_live(live_id, reason, (bytes, dropped_frames, drops)),
            Err(why) => {
                tracing::warn!(
                    live.id = live_id,
                    connection.id = connection,
                    why,
                    "a worker reported a malformed live report; output ended"
                );
                if last {
                    // The worker runs the output no more.
                    self.close_live(live_id, LiveCloseReason::InternalError, (0, 0, 0));
                } else {
                    self.end_live(live_id, LiveCloseReason::InternalError);
                }
            }
        }
    }

    /// Ends live output `live_id` for a reason of the supervisor's own: the
    /// worker is asked to stop it and the output stays until its `Closed`
    /// comes, which then carries `reason`. Idempotent: an unknown output, or
    /// one already being stopped, changes nothing. A `live/create` still
    /// waiting gets `reason` at once.
    pub(crate) fn end_live(&mut self, live_id: &str, reason: LiveCloseReason) {
        let Some(entry) = self.lives.get_mut(live_id) else {
            tracing::debug!(
                live.id = live_id,
                reason = reason.as_str(),
                "end of a live output that is not open; nothing to do"
            );
            return;
        };
        if entry.ending.is_some() {
            return;
        }
        entry.ending = Some(reason);
        if let Some(waiting) = entry.waiting.take() {
            let _told = waiting.send(Err(reason));
        }
        entry.ask_stop(live_id);
        tracing::info!(
            event = "live_stopping",
            live.id = live_id,
            stream.id = %entry.stream_id,
            reason = reason.as_str(),
            "live output stop asked of its worker"
        );
    }

    /// Ends every live output `matches` picks for `reason`.
    pub(crate) fn end_lives_where(
        &mut self,
        matches: impl Fn(&LiveEntry) -> bool,
        reason: LiveCloseReason,
    ) {
        let ids: Vec<String> = self
            .lives
            .iter()
            .filter(|(_, entry)| matches(entry))
            .map(|(id, _)| id.clone())
            .collect();
        for live_id in ids {
            self.end_live(&live_id, reason);
        }
    }

    /// Live output `live_id` is over for `reason` with the worker's
    /// `(bytes, dropped_frames, drops)`: it leaves the registry and its
    /// connection's demand, its owner gets `closed` and its subscription
    /// ends, and a `live/create` still waiting gets `reason`. A body not
    /// fetched yet goes with it.
    pub(crate) fn close_live(
        &mut self,
        live_id: &str,
        reason: LiveCloseReason,
        (bytes, dropped_frames, drops): (u64, u64, u32),
    ) {
        let Some(mut entry) = self.lives.remove(live_id) else {
            return;
        };
        if let Some(waiting) = entry.waiting.take() {
            let _told = waiting.send(Err(reason));
        }
        tracing::info!(
            event = "live_closed",
            live.id = live_id,
            stream.id = %entry.stream_id,
            reason = reason.as_str(),
            bytes,
            dropped_frames,
            drops,
            "live output closed"
        );
        entry.deliver(
            live_id,
            &LiveEvent::Closed {
                live_id: live_id.to_owned(),
                reason,
                bytes,
                dropped_frames,
                drops,
            },
        );
        let connection = entry.connection.clone();
        drop(entry);
        self.refresh_connection(&connection);
        self.hls_live_closed(live_id, reason);
    }

    /// The control connection `connection` closed: its live outputs end
    /// `session_closed`.
    pub(crate) fn lives_connection_closed(&mut self, connection: ConnectionId) {
        self.end_lives_where(
            |entry| {
                entry
                    .owner
                    .as_ref()
                    .is_some_and(|owner| owner.connection == connection)
            },
            LiveCloseReason::SessionClosed,
        );
    }

    /// `unsubscribe` of `connection`'s `subscription`: the live output it
    /// names ends `session_closed`; whether there was one.
    pub(crate) fn unsubscribe_live(&mut self, connection: ConnectionId, subscription: u64) -> bool {
        let found = self.lives.iter().find_map(|(id, entry)| {
            entry
                .owner
                .as_ref()
                .filter(|owner| {
                    owner.connection == connection && owner.subscription == subscription
                })
                .map(|_| id.clone())
        });
        let Some(live_id) = found else {
            return false;
        };
        if let Some(entry) = self.lives.get_mut(&live_id) {
            // The subscription's end is what `unsubscribe` answers.
            entry.owner = None;
        }
        self.end_live(&live_id, LiveCloseReason::SessionClosed);
        true
    }

    /// The fetch deadline of live output `serial`, `live_id`, passed: one
    /// whose body is still here ends `not_fetched`.
    pub(crate) fn live_fetch_deadline(&mut self, live_id: &str, serial: u64) {
        let unfetched = self
            .lives
            .get(live_id)
            .is_some_and(|entry| entry.serial == serial && entry.body.is_some());
        if unfetched {
            tracing::info!(live.id = live_id, "live output not fetched in time");
            self.end_live(live_id, LiveCloseReason::NotFetched);
        }
    }

    /// The body of live output `live_id` for its one `GET`: the worker is
    /// told a reader took it, and the fetch deadline ends.
    pub(crate) fn take_live_body(&mut self, live_id: &str) -> Result<LiveBody, LiveBodyError> {
        let entry = self.lives.get_mut(live_id).ok_or(LiveBodyError::NotFound)?;
        // Not started yet: the result that names it has not gone out.
        let mime = entry.mime.clone().ok_or(LiveBodyError::NotFound)?;
        let reader = entry.body.take().ok_or(LiveBodyError::AlreadyFetched)?;
        entry.timer = None;
        if let Some(slot) = entry.fetch_slot.take() {
            drop(slot.send(DriverCommand::FetchLive {
                live_id: live_id.to_owned(),
            }));
        }
        tracing::info!(event = "live_fetched", live.id = live_id, "live body taken");
        Ok(LiveBody {
            reader: Box::new(reader),
            mime,
        })
    }

    /// `connection`'s worker is gone: its live outputs end now, as their
    /// pipes' write ends closed, `worker_crashed` or the reason the
    /// supervisor gave.
    pub(crate) fn lives_worker_gone(&mut self, connection: &str) {
        self.close_lives_of(connection, LiveCloseReason::WorkerCrashed);
    }

    /// `connection` was released, no stream playing it any more, and its
    /// driver goes with its worker: its live outputs end now, for the
    /// reason the supervisor gave (a deleted stream's), else
    /// `stream_changed`: their stream moved to another connection.
    pub(crate) fn lives_connection_released(&mut self, connection: &str) {
        self.close_lives_of(connection, LiveCloseReason::StreamChanged);
    }

    /// Closes `connection`'s live outputs at once, each for the reason the
    /// supervisor gave, else `otherwise`.
    fn close_lives_of(&mut self, connection: &str, otherwise: LiveCloseReason) {
        let gone: Vec<(String, LiveCloseReason)> = self
            .lives
            .iter()
            .filter(|(_, entry)| entry.connection == connection)
            .map(|(id, entry)| (id.clone(), entry.ending.unwrap_or(otherwise)))
            .collect();
        for (live_id, reason) in gone {
            self.close_live(&live_id, reason, (0, 0, 0));
        }
    }

    /// Live output `live_id`'s start left its driver's queue without
    /// reaching a worker: it ends now, for the reason the supervisor gave.
    pub(crate) fn live_unqueued(&mut self, live_id: &str) {
        let reason = self
            .lives
            .get(live_id)
            .and_then(|entry| entry.ending)
            .unwrap_or(LiveCloseReason::InternalError);
        self.close_live(live_id, reason, (0, 0, 0));
    }

    /// Live outputs open on `stream_id`, and in all.
    pub(crate) fn lives_open(&self, stream_id: &str) -> (usize, usize) {
        let on_stream = self
            .lives
            .values()
            .filter(|entry| entry.stream_id == stream_id)
            .count();
        (on_stream, self.lives.len())
    }
}

#[cfg(test)]
mod tests;
