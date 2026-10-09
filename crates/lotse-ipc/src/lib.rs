//! Supervisor-worker messages, length-prefixed framing on a stream
//! socketpair, fd passing (`SCM_RIGHTS`) and, from M5, memfd bulk transfer.
//!
//! Used by the supervisor and the worker only. On the supervisor side a
//! worker's messages are untrusted input: typed (`postcard`), size-capped
//! ([`MAX_MESSAGE_BYTES`]) and fuzzed (`ipc_message`). The message types
//! are plain data on purpose: this crate knows nothing of `lotse-core`, so
//! a worker can never hand the supervisor a domain object, only fields the
//! supervisor validates. The control channel is `SOCK_STREAM` rather than
//! `SOCK_SEQPACKET` because a SEQPACKET message cannot exceed the socket
//! send buffer, which the unprivileged default caps below the message
//! limit, and because macOS has no SEQPACKET at all; the datagram channel
//! of the demux (M1) is SEQPACKET.
//!
//! Standards: `unix(7)`, `socket(2)` `SOCK_CLOEXEC`, `cmsg(3)` `SCM_RIGHTS`,
//! `memfd_create(2)`.

pub mod channel;
pub mod codec;
pub mod datagram;
pub mod message;
mod pair;

pub use channel::{Channel, Decoded, Message, Receiver, Sender};
pub use codec::{IpcError, MAX_MESSAGE_BYTES, decode, encode};
pub use message::{
    SessionEvent, SessionSpec, SourceSpec, SourceState, ToSupervisor, ToWorker, TrackInfo,
    TrackStats, WorkerStats,
};
