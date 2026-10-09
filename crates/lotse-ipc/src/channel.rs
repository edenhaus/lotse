//! The control channel: one `SOCK_STREAM` socketpair per worker, carrying
//! length-prefixed messages with descriptors attached by `SCM_RIGHTS`.
//!
//! Implements `unix(7)` socketpairs and `cmsg(3)` `SCM_RIGHTS`. A frame is
//! a 4-byte little-endian length followed by the encoded message; the
//! descriptors of a frame are attached to the write that carries its
//! prefix, and the receiver never reads across a frame boundary, so they
//! arrive with the frame they belong to. A frame announcing more than
//! [`MAX_MESSAGE_BYTES`], or carrying more than [`MAX_FDS`] descriptors,
//! is a protocol violation and ends the channel. Received descriptors are
//! close-on-exec from the moment they exist on Linux (`recvmsg(2)`
//! `MSG_CMSG_CLOEXEC`), so a process spawned meanwhile never inherits one.
//!
//! A frame whose descriptors the kernel discarded still arrives whole,
//! without any of them and marked [`Message::fds_truncated`]. The kernel
//! discards them when the receiver's own descriptor table is full (Linux
//! `scm_detach_fds` sets `MSG_CTRUNC`; macOS fails the receive with
//! `EMFILE`), which says nothing about the peer, or when a write carried
//! more than the ancillary buffer holds (more than [`MAX_FDS`] arrive
//! first, which ends the channel as above). [`Receiver::recv_msg`] refuses
//! such a frame as [`IpcError::FdsTruncated`]; [`Receiver::recv_decoded`]
//! hands it to a caller that can survive the loss, and the channel stays
//! in step either way.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::Arc;

use rustix::io::FdFlags;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketType,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::unix::AsyncFd;

use crate::codec::{IpcError, MAX_MESSAGE_BYTES, decode, encode};

/// The most descriptors one message may carry; enforced on send and on
/// receive, so a peer cannot fill the receiver's descriptor table.
pub const MAX_FDS: usize = 8;

/// The frame prefix: a little-endian `u32` length.
const PREFIX_LEN: usize = 4;

/// One received frame.
#[derive(Debug)]
pub struct Message {
    /// The encoded message.
    pub payload: Vec<u8>,
    /// The descriptors that came with it; none when they were truncated.
    pub fds: Vec<OwnedFd>,
    /// The kernel discarded descriptors sent with the frame: this process
    /// had no free descriptor for one, or a write carried more than the
    /// ancillary buffer holds. Every descriptor of the frame is closed.
    pub fds_truncated: bool,
}

/// A decoded message, its descriptors and whether the kernel truncated
/// them ([`Message::fds_truncated`]).
#[derive(Debug)]
pub struct Decoded<T> {
    /// The message.
    pub message: T,
    /// The descriptors that came with it; none when they were truncated.
    pub fds: Vec<OwnedFd>,
    /// See [`Message::fds_truncated`].
    pub fds_truncated: bool,
}

/// The descriptor a channel's socket is on.
#[derive(Debug)]
enum Descriptor {
    /// One the channel owns and closes when dropped.
    Owned(OwnedFd),
    /// Standard input, used at its own number and never closed (see
    /// [`Channel::from_stdin`]).
    Stdin(io::Stdin),
}

impl AsFd for Descriptor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Owned(fd) => fd.as_fd(),
            Self::Stdin(stdin) => stdin.as_fd(),
        }
    }
}

impl AsRawFd for Descriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}

/// The socket both halves share.
#[derive(Debug)]
struct Socket {
    /// The non-blocking socket, registered with the runtime.
    fd: AsyncFd<Descriptor>,
}

impl Socket {
    /// Registers `fd` after making it non-blocking and close-on-exec.
    fn new(fd: Descriptor) -> io::Result<Self> {
        rustix::io::ioctl_fionbio(&fd, true)?;
        rustix::io::fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
        Ok(Self {
            fd: AsyncFd::new(fd)?,
        })
    }
}

/// One end of a control channel. Split it to send and receive from
/// different tasks.
#[derive(Debug)]
pub struct Channel {
    /// The socket.
    socket: Arc<Socket>,
}

impl Channel {
    /// A connected pair: the caller's end and the raw descriptor for the
    /// other process (the worker's stdin), both close-on-exec from
    /// creation, so no other worker spawned meanwhile inherits either.
    pub fn pair() -> io::Result<(Self, OwnedFd)> {
        let (ours, theirs) = crate::pair::unix_pair(SocketType::STREAM)?;
        Ok((Self::from_fd(ours)?, theirs))
    }

    /// The channel on an inherited descriptor.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            socket: Arc::new(Socket::new(Descriptor::Owned(fd))?),
        })
    }

    /// The channel on standard input, as a worker receives it: descriptor
    /// 0 itself, neither duplicated nor ever closed, so the channel keeps
    /// the number the worker's seccomp filter lets carry `SCM_RIGHTS` and
    /// keeps from being closed or replaced.
    pub fn from_stdin() -> io::Result<Self> {
        Ok(Self {
            socket: Arc::new(Socket::new(Descriptor::Stdin(io::stdin()))?),
        })
    }

    /// The two halves.
    pub fn split(self) -> (Sender, Receiver) {
        (
            Sender {
                socket: Arc::clone(&self.socket),
            },
            Receiver {
                socket: self.socket,
                buf: vec![0; PREFIX_LEN.saturating_add(MAX_MESSAGE_BYTES)],
                have: 0,
                fds: Vec::new(),
                fds_truncated: false,
            },
        )
    }
}

/// The sending half.
#[derive(Debug)]
pub struct Sender {
    /// The socket.
    socket: Arc<Socket>,
}

impl Sender {
    /// Sends one encoded message with up to [`MAX_FDS`] descriptors.
    pub async fn send(&mut self, payload: &[u8], fds: &[BorrowedFd<'_>]) -> Result<(), IpcError> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(IpcError::TooLarge {
                len: payload.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        if fds.len() > MAX_FDS {
            return Err(IpcError::TooManyFds(fds.len()));
        }
        // At most `MAX_MESSAGE_BYTES`, checked above, which fits a `u32`.
        let prefix = u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes();
        let mut frame = Vec::with_capacity(PREFIX_LEN.saturating_add(payload.len()));
        frame.extend_from_slice(&prefix);
        frame.extend_from_slice(payload);

        let mut sent = 0;
        while sent < frame.len() {
            let rest = frame.get(sent..).unwrap_or_default();
            // The descriptors ride on the first write, which carries the prefix.
            let attach = if sent == 0 { fds } else { &[] };
            let mut guard = self.socket.fd.writable().await?;
            if let Ok(written) =
                guard.try_io(|inner| send_once(inner.get_ref().as_fd(), rest, attach))
            {
                sent = sent.saturating_add(written?);
            }
        }
        Ok(())
    }

    /// Encodes and sends `message`.
    pub async fn send_msg<T: Serialize + Sync + ?Sized>(
        &mut self,
        message: &T,
        fds: &[BorrowedFd<'_>],
    ) -> Result<(), IpcError> {
        let payload = encode(message)?;
        self.send(&payload, fds).await
    }
}

/// One `sendmsg`.
fn send_once(fd: BorrowedFd<'_>, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(io::Error::other(
            "ancillary buffer too small for the descriptors",
        ));
    }
    let written = rustix::net::sendmsg(fd, &[IoSlice::new(bytes)], &mut ancillary, send_flags())?;
    Ok(written)
}

/// `MSG_NOSIGNAL` where it exists; elsewhere Rust already ignores `SIGPIPE`.
#[cfg(target_os = "linux")]
const fn send_flags() -> SendFlags {
    SendFlags::NOSIGNAL
}

/// See the Linux variant.
#[cfg(not(target_os = "linux"))]
const fn send_flags() -> SendFlags {
    SendFlags::empty()
}

/// The receiving half.
#[derive(Debug)]
pub struct Receiver {
    /// The socket.
    socket: Arc<Socket>,
    /// The frame being assembled: prefix, then payload.
    buf: Vec<u8>,
    /// Bytes of the current frame received so far.
    have: usize,
    /// Descriptors received for the current frame.
    fds: Vec<OwnedFd>,
    /// The kernel truncated descriptors of the current frame.
    fds_truncated: bool,
}

impl Receiver {
    /// The next message, or `None` once the peer closed the channel cleanly.
    pub async fn recv(&mut self) -> Result<Option<Message>, IpcError> {
        loop {
            let want = self.wanted()?;
            if want == 0 {
                return Ok(Some(self.take()));
            }
            let mut guard = self.socket.fd.readable().await?;
            let read = match guard.try_io(|inner| {
                recv_once(
                    inner.get_ref().as_fd(),
                    self.buf
                        .get_mut(self.have..self.have.saturating_add(want))
                        .unwrap_or_default(),
                    &mut self.fds,
                )
            }) {
                Ok(Ok(read)) => read,
                // A peer that closed with our messages unread: Linux fails
                // the read with `ECONNRESET` (`unix_release_sock` in
                // net/unix/af_unix.c; observed on Linux 7.0, 2026-10-09)
                // where macOS returns end of file. Between frames both
                // are a close.
                Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionReset && self.have == 0 => {
                    return Ok(None);
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(_would_block) => continue,
            };
            if self.fds.len() > MAX_FDS {
                // More than a message may carry: only the peer does that.
                let count = self.fds.len();
                self.fds.clear();
                return Err(IpcError::TooManyFds(count));
            }
            if read.fds_truncated || self.fds_truncated {
                // The kernel discarded what it could not deliver; the
                // frame's bytes still follow, so the channel stays in step
                // and the frame's other descriptors are closed.
                self.fds.clear();
                self.fds_truncated = true;
            }
            if read.bytes == 0 {
                if self.have == 0 {
                    return Ok(None);
                }
                return Err(IpcError::Truncated {
                    have: self.have,
                    want: self.have.saturating_add(want),
                });
            }
            self.have = self.have.saturating_add(read.bytes);
        }
    }

    /// Receives and decodes the next message; one whose descriptors the
    /// kernel truncated is [`IpcError::FdsTruncated`].
    pub async fn recv_msg<T: DeserializeOwned>(
        &mut self,
    ) -> Result<Option<(T, Vec<OwnedFd>)>, IpcError> {
        let Some(decoded) = self.recv_decoded().await? else {
            return Ok(None);
        };
        if decoded.fds_truncated {
            return Err(IpcError::FdsTruncated);
        }
        Ok(Some((decoded.message, decoded.fds)))
    }

    /// Receives and decodes the next message, one whose descriptors the
    /// kernel truncated included: the caller decides what that loss means.
    pub async fn recv_decoded<T: DeserializeOwned>(
        &mut self,
    ) -> Result<Option<Decoded<T>>, IpcError> {
        let Some(message) = self.recv().await? else {
            return Ok(None);
        };
        Ok(Some(Decoded {
            message: decode(&message.payload)?,
            fds: message.fds,
            fds_truncated: message.fds_truncated,
        }))
    }

    /// How many more bytes complete the current frame; zero when complete.
    fn wanted(&self) -> Result<usize, IpcError> {
        if self.have < PREFIX_LEN {
            return Ok(PREFIX_LEN.saturating_sub(self.have));
        }
        let len = self.announced_len()?;
        Ok(PREFIX_LEN.saturating_add(len).saturating_sub(self.have))
    }

    /// The length the prefix announces, checked against the cap.
    fn announced_len(&self) -> Result<usize, IpcError> {
        let prefix: [u8; PREFIX_LEN] = self
            .buf
            .get(..PREFIX_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or_default();
        let len = usize::try_from(u32::from_le_bytes(prefix)).unwrap_or(usize::MAX);
        if len > MAX_MESSAGE_BYTES {
            return Err(IpcError::TooLarge {
                len,
                max: MAX_MESSAGE_BYTES,
            });
        }
        Ok(len)
    }

    /// Takes the complete frame out of the buffer.
    fn take(&mut self) -> Message {
        let payload = self
            .buf
            .get(PREFIX_LEN..self.have)
            .unwrap_or_default()
            .to_vec();
        self.have = 0;
        Message {
            payload,
            fds: std::mem::take(&mut self.fds),
            fds_truncated: std::mem::take(&mut self.fds_truncated),
        }
    }
}

/// What one `recvmsg` brought besides the descriptors.
#[derive(Debug)]
struct Received {
    /// Bytes read; zero at end of stream.
    bytes: usize,
    /// The kernel discarded descriptors: it set `MSG_CTRUNC` (more came
    /// than the ancillary buffer holds, [`MAX_FDS`], or this process's
    /// descriptor table had no room for one, Linux `scm_detach_fds`), or,
    /// off Linux, refused the receive with `EMFILE` (see [`recvmsg`]).
    fds_truncated: bool,
}

/// One `recvmsg` into `into`, appending every descriptor that came with it
/// to `fds`, close-on-exec (see [`recv_flags`]). The ancillary buffer is
/// always drained in full, so each received descriptor is owned, and
/// closed when dropped.
fn recv_once(fd: BorrowedFd<'_>, into: &mut [u8], fds: &mut Vec<OwnedFd>) -> io::Result<Received> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let (received, refused) = recvmsg(fd, into, &mut ancillary)?;
    let first_new = fds.len();
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(received_fds) = message {
            fds.extend(received_fds);
        }
    }
    for received_fd in fds.get(first_new..).unwrap_or_default() {
        #[cfg(not(target_os = "linux"))]
        rustix::io::fcntl_setfd(received_fd, FdFlags::CLOEXEC)?;
        tracing::trace!(fd = received_fd.as_raw_fd(), "descriptor received");
    }
    Ok(Received {
        bytes: received.bytes,
        fds_truncated: refused || received.flags.contains(ReturnFlags::CTRUNC),
    })
}

/// One `recvmsg(2)`, and `true` when the kernel refused the receive for
/// want of a free descriptor and discarded the descriptors. Linux never
/// does: a full table truncates the descriptors with `MSG_CTRUNC` and the
/// bytes arrive (`scm_detach_fds`). macOS fails the receive with `EMFILE`,
/// discards the descriptors and leaves the bytes queued, so one more
/// receive takes the bytes alone (observed on macOS 27, Darwin 27.0.0,
/// 2026-10-09; a development platform only). One function for both, as
/// with [`recv_flags`].
fn recvmsg(
    fd: BorrowedFd<'_>,
    into: &mut [u8],
    ancillary: &mut RecvAncillaryBuffer<'_>,
) -> io::Result<(rustix::net::RecvMsg, bool)> {
    let received = rustix::net::recvmsg(fd, &mut [IoSliceMut::new(into)], ancillary, recv_flags());
    #[cfg(not(target_os = "linux"))]
    if matches!(received, Err(rustix::io::Errno::MFILE)) {
        let received =
            rustix::net::recvmsg(fd, &mut [IoSliceMut::new(into)], ancillary, recv_flags())?;
        return Ok((received, true));
    }
    Ok((received?, false))
}

/// The `recvmsg` flags. On Linux `MSG_CMSG_CLOEXEC`: the kernel creates
/// the received descriptors close-on-exec (`recvmsg(2)`, Linux 2.6.23).
/// Elsewhere (macOS, a development platform only) there is no such flag
/// and [`recv_once`] sets `FD_CLOEXEC` right after `recvmsg`, which is not
/// atomic with the receipt. One function for both, so the mutation tests,
/// which run on Linux, never mutate a variant that is not built.
const fn recv_flags() -> RecvFlags {
    #[cfg(target_os = "linux")]
    {
        RecvFlags::CMSG_CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        RecvFlags::empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use rustix::net::{AddressFamily, SocketFlags};
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixStream;

    use super::*;
    use crate::codec::encode;
    use crate::message::{SourceState, ToSupervisor, ToWorker};

    /// A raw blocking end to write forged bytes on, and a receiver on the
    /// other end.
    fn raw_pair() -> (std::os::unix::net::UnixStream, Receiver) {
        let (theirs, ours) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::empty(),
            None,
        )
        .unwrap();
        let raw = std::os::unix::net::UnixStream::from(theirs);
        let receiver = Channel::from_fd(ours).unwrap().split().1;
        (raw, receiver)
    }

    fn pair() -> (Sender, Receiver, Sender, Receiver) {
        let (a, b_fd) = Channel::pair().unwrap();
        let b = Channel::from_fd(b_fd).unwrap();
        let (a_tx, a_rx) = a.split();
        let (b_tx, b_rx) = b.split();
        (a_tx, a_rx, b_tx, b_rx)
    }

    #[tokio::test]
    async fn both_ends_of_a_pair_are_close_on_exec_socket_2_sock_cloexec() {
        // IPC-11: created with the flag, not given it afterwards.
        let (ours, theirs) = Channel::pair().unwrap();
        for fd in [ours.socket.fd.get_ref().as_fd(), theirs.as_fd()] {
            assert!(
                rustix::io::fcntl_getfd(fd)
                    .unwrap()
                    .contains(FdFlags::CLOEXEC)
            );
        }
    }

    /// The variable that turns this test binary into the stdin child.
    const STDIN_CHILD: &str = "LOTSE_IPC_STDIN_CHILD";

    /// The stdin child: the channel on its standard input, as a worker's,
    /// echoes the one message it gets with its descriptors, and leaves
    /// standard input open when dropped.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the child reads the variable that marks it"
    )]
    fn stdin_child() {
        if std::env::var_os(STDIN_CHILD).is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let channel = Channel::from_stdin().unwrap();
            assert_eq!(channel.socket.fd.get_ref().as_raw_fd(), 0);
            let (mut tx, mut rx) = channel.split();
            let (message, fds) = rx.recv_msg::<ToWorker>().await.unwrap().unwrap();
            assert_eq!(message, ToWorker::Shutdown { deadline_ms: 7 });
            let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
            tx.send_msg(&ToSupervisor::Ready { pid: 7 }, &borrowed)
                .await
                .unwrap();
        });
        rustix::io::fcntl_getfd(io::stdin()).expect("standard input is still open");
    }

    /// A worker's control channel stays on descriptor 0, the number its
    /// seccomp filter lets carry descriptors, instead of a duplicate at
    /// whatever number was free.
    #[tokio::test]
    #[expect(
        clippy::disallowed_methods,
        reason = "spawns this test binary as the stdin child"
    )]
    async fn the_channel_on_stdin_stays_on_descriptor_zero() {
        let (ours, theirs) = Channel::pair().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "channel::tests::stdin_child", "--nocapture"])
            .env(STDIN_CHILD, "1")
            .stdin(std::process::Stdio::from(theirs))
            .spawn()
            .unwrap();
        let (mut tx, mut rx) = ours.split();
        let (kept, passed) = passable(1);
        tx.send_msg(&ToWorker::Shutdown { deadline_ms: 7 }, &[passed[0].as_fd()])
            .await
            .unwrap();
        drop(passed);
        let (message, fds) = rx.recv_msg::<ToSupervisor>().await.unwrap().unwrap();
        assert_eq!(message, ToSupervisor::Ready { pid: 7 });
        assert_eq!(fds.len(), 1, "the descriptor came back");
        // The child exits on its own once it has answered.
        let status = child.wait().unwrap();
        assert!(status.success(), "{status}");
        assert!(!peer_closed(&kept[0]), "the copy that came back is open");
        drop(fds);
        assert!(peer_closed(&kept[0]));
    }

    #[tokio::test]
    async fn messages_cross_in_both_directions_in_order() {
        let (mut a_tx, mut a_rx, mut b_tx, mut b_rx) = pair();
        for pid in 1..=3 {
            a_tx.send_msg(&ToSupervisor::Ready { pid }, &[])
                .await
                .unwrap();
        }
        b_tx.send_msg(&ToWorker::Shutdown { deadline_ms: 5 }, &[])
            .await
            .unwrap();
        for pid in 1..=3 {
            let (message, fds) = b_rx.recv_msg::<ToSupervisor>().await.unwrap().unwrap();
            assert_eq!(message, ToSupervisor::Ready { pid });
            assert!(fds.is_empty());
        }
        let (message, _) = a_rx.recv_msg::<ToWorker>().await.unwrap().unwrap();
        assert_eq!(message, ToWorker::Shutdown { deadline_ms: 5 });
    }

    #[tokio::test]
    async fn a_large_message_arrives_whole() {
        let (mut a_tx, _a_rx, _b_tx, mut b_rx) = pair();
        let payload: Vec<u8> = (0..MAX_MESSAGE_BYTES)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        // Larger than the socket buffer, so the send only completes while
        // the receiver drains: both sides must run at once, and a receive
        // that fails ends the test rather than leaving the send waiting.
        let received = async {
            b_rx.recv()
                .await?
                .ok_or(IpcError::Truncated { have: 0, want: 0 })
        };
        let ((), received) = tokio::try_join!(a_tx.send(&payload, &[]), received).unwrap();
        assert_eq!(received.payload, payload);
        assert_eq!(received.payload.len(), MAX_MESSAGE_BYTES);
    }

    #[tokio::test]
    async fn descriptors_travel_with_their_frame() {
        let (mut a_tx, _a_rx, _b_tx, mut b_rx) = pair();
        let (ours, theirs) = UnixStream::pair().unwrap();
        let theirs: OwnedFd = theirs.into_std().unwrap().into();
        a_tx.send(b"first", &[]).await.unwrap();
        a_tx.send(b"with fd", &[theirs.as_fd()]).await.unwrap();
        a_tx.send(b"after", &[]).await.unwrap();
        drop(theirs);

        let first = b_rx.recv().await.unwrap().unwrap();
        assert_eq!(
            (first.payload.as_slice(), first.fds.len()),
            (&b"first"[..], 0)
        );
        let with_fd = b_rx.recv().await.unwrap().unwrap();
        assert_eq!(with_fd.payload, b"with fd");
        assert_eq!(with_fd.fds.len(), 1);
        let flags = rustix::io::fcntl_getfd(&with_fd.fds[0]).unwrap();
        assert!(flags.contains(FdFlags::CLOEXEC));
        let after = b_rx.recv().await.unwrap().unwrap();
        assert_eq!(
            (after.payload.as_slice(), after.fds.len()),
            (&b"after"[..], 0)
        );

        // The received descriptor is the other end of `ours`.
        let received = with_fd.fds.into_iter().next().unwrap();
        let std_stream = std::os::unix::net::UnixStream::from(received);
        std_stream.set_nonblocking(true).unwrap();
        let mut received = UnixStream::from_std(std_stream).unwrap();
        received.write_all(b"hello").await.unwrap();
        drop(received);
        let mut ours = ours;
        let mut text = String::new();
        ours.read_to_string(&mut text).await.unwrap();
        assert_eq!(text, "hello");
    }

    #[tokio::test]
    async fn a_clean_close_ends_the_channel_and_a_cut_frame_is_an_error() {
        let (mut a_tx, a_rx, _b_tx, mut b_rx) = pair();
        a_tx.send(b"last", &[]).await.unwrap();
        drop(a_tx);
        drop(a_rx);
        assert_eq!(b_rx.recv().await.unwrap().unwrap().payload, b"last");
        assert!(b_rx.recv().await.unwrap().is_none());
        assert!(b_rx.recv().await.unwrap().is_none(), "stays closed");

        let (raw, mut b_rx) = raw_pair();
        // Write a prefix announcing ten bytes, then only three, then close.
        {
            use std::io::Write as _;
            let mut raw = raw;
            raw.write_all(&10_u32.to_le_bytes()).unwrap();
            raw.write_all(b"abc").unwrap();
        }
        let err = b_rx.recv().await.unwrap_err();
        assert!(
            matches!(err, IpcError::Truncated { have: 7, want: 14 }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_peer_that_closes_with_our_messages_unread_ends_the_channel_unix_7() {
        // Linux fails the read with ECONNRESET here, macOS returns end of
        // file: between frames both are a close.
        let (a_tx, a_rx, mut b_tx, mut b_rx) = pair();
        b_tx.send(b"never read", &[]).await.unwrap();
        drop((a_tx, a_rx));
        assert!(b_rx.recv().await.unwrap().is_none());

        // Inside a frame it is still an error.
        let (theirs, ours) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::empty(),
            None,
        )
        .unwrap();
        let (mut tx, mut rx) = Channel::from_fd(ours).unwrap().split();
        tx.send(b"never read", &[]).await.unwrap();
        {
            use std::io::Write as _;
            let mut raw = std::os::unix::net::UnixStream::from(theirs);
            raw.write_all(&10_u32.to_le_bytes()).unwrap();
            raw.write_all(b"abc").unwrap();
        }
        assert!(rx.recv().await.is_err());
    }

    #[tokio::test]
    async fn an_oversize_frame_is_refused_on_both_sides() {
        let (mut a_tx, _a_rx, _b_tx, _b_rx) = pair();
        let big = vec![0_u8; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(
            a_tx.send(&big, &[]).await.unwrap_err(),
            IpcError::TooLarge { .. }
        ));
        let fds: Vec<OwnedFd> = (0..=MAX_FDS)
            .map(|_| {
                let (s, _t) = UnixStream::pair().unwrap();
                s.into_std().unwrap().into()
            })
            .collect();
        let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
        assert!(matches!(
            a_tx.send(b"x", &borrowed).await.unwrap_err(),
            IpcError::TooManyFds(9)
        ));

        // A forged prefix past the cap ends the channel before any payload.
        let (mut raw, mut b_rx) = raw_pair();
        {
            use std::io::Write as _;
            raw.write_all(&u32::MAX.to_le_bytes()).unwrap();
        }
        assert!(matches!(
            b_rx.recv().await.unwrap_err(),
            IpcError::TooLarge { .. }
        ));
    }

    /// `count` socketpairs: the ends the test keeps, and the ends it passes.
    fn passable(count: usize) -> (Vec<std::os::unix::net::UnixStream>, Vec<OwnedFd>) {
        (0..count)
            .map(|_| {
                let (kept, passed) = std::os::unix::net::UnixStream::pair().unwrap();
                (kept, OwnedFd::from(passed))
            })
            .unzip()
    }

    /// One `sendmsg` of `bytes` with `fds` attached, on a buffer with room
    /// for more than [`MAX_FDS`], as a misbehaving peer would send.
    fn send_raw(raw: &std::os::unix::net::UnixStream, bytes: &[u8], fds: &[OwnedFd]) {
        let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4 * MAX_FDS))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&borrowed)));
        let sent = rustix::net::sendmsg(
            raw,
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
        assert_eq!(sent, bytes.len());
    }

    /// Whether every copy of the descriptor paired with `kept` is closed:
    /// the stream then reads end of file.
    fn peer_closed(kept: &std::os::unix::net::UnixStream) -> bool {
        use std::io::Read as _;
        kept.set_nonblocking(true).unwrap();
        matches!((&*kept).read(&mut [0_u8; 1]), Ok(0))
    }

    #[test]
    fn one_write_refuses_more_descriptors_than_its_cmsg_3_buffer_holds() {
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        // `cmsg_space!` may round the buffer up past `MAX_FDS`, never 8-fold.
        let (_kept, passed) = passable(8 * MAX_FDS);
        let borrowed: Vec<BorrowedFd<'_>> = passed.iter().map(AsFd::as_fd).collect();
        let err = send_once(ours.as_fd(), b"x", &borrowed).unwrap_err();
        assert_eq!(
            err.to_string(),
            "ancillary buffer too small for the descriptors"
        );
        let sent = send_once(ours.as_fd(), b"x", &borrowed[..MAX_FDS]).unwrap();
        assert_eq!(sent, 1, "the buffer holds exactly MAX_FDS");
    }

    #[tokio::test]
    async fn max_fds_descriptors_in_one_frame_are_accepted_across_writes() {
        let (raw, mut rx) = raw_pair();
        let (kept, passed) = passable(MAX_FDS);
        let (first, second) = passed.split_at(MAX_FDS / 2);
        send_raw(&raw, &[2, 0, 0, 0, b'a'], first);
        send_raw(&raw, b"b", second);
        drop(passed);
        let message = rx.recv().await.unwrap().unwrap();
        assert_eq!(message.payload, b"ab");
        assert_eq!(message.fds.len(), MAX_FDS);
        assert!(
            kept.iter().all(|kept| !peer_closed(kept)),
            "held by the message"
        );
        drop(message);
        assert!(kept.iter().all(peer_closed));
    }

    #[tokio::test]
    async fn more_than_max_fds_across_one_frames_writes_are_refused_and_closed() {
        // IPC-1: descriptors piling up over a frame's writes, past the cap.
        let (raw, mut rx) = raw_pair();
        let (kept, passed) = passable(2 * (MAX_FDS - 3));
        let (first, second) = passed.split_at(MAX_FDS - 3);
        send_raw(&raw, &[2, 0, 0, 0, b'a'], first);
        send_raw(&raw, b"b", second);
        drop(passed);
        assert!(matches!(
            rx.recv().await.unwrap_err(),
            IpcError::TooManyFds(10)
        ));
        assert!(
            kept.iter().all(peer_closed),
            "every received descriptor is closed"
        );
    }

    #[tokio::test]
    async fn more_than_max_fds_in_one_write_are_refused_and_closed() {
        // IPC-1: the kernel truncates the ancillary data (`MSG_CTRUNC`).
        let (raw, mut rx) = raw_pair();
        let (kept, passed) = passable(MAX_FDS + 1);
        send_raw(&raw, &[1, 0, 0, 0, b'a'], &passed);
        drop(passed);
        assert!(matches!(
            rx.recv().await.unwrap_err(),
            IpcError::TooManyFds(9)
        ));
        assert!(
            kept.iter().all(peer_closed),
            "every received descriptor is closed"
        );
    }

    /// Lowers this process's descriptor limit to its lowest free
    /// descriptor, so the table has no room for another; returns the
    /// limit to restore. nextest runs each test in its own process.
    fn starve_descriptors() -> Rlimit {
        let limit = getrlimit(Resource::Nofile);
        let probe = std::fs::File::open("/dev/null").unwrap();
        let lowest = u64::try_from(probe.as_raw_fd()).unwrap();
        drop(probe);
        let starved = Rlimit {
            current: Some(lowest),
            maximum: limit.maximum,
        };
        setrlimit(Resource::Nofile, starved).unwrap();
        limit
    }

    /// A `ToWorker` message in its frame.
    fn framed(message: &ToWorker) -> Vec<u8> {
        let payload = encode(message).unwrap();
        let mut frame = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    #[tokio::test]
    async fn a_full_descriptor_table_truncates_the_descriptors_and_keeps_the_frame() {
        // WRK-20: the receiver's own table is full. Linux installs what it
        // can, sets `MSG_CTRUNC` and closes the rest (`scm_detach_fds`,
        // net/core/scm.c); macOS refuses the receive with `EMFILE` and
        // keeps the bytes (observed 2026-10-09). The frame arrives either
        // way, without its descriptors, and the channel stays in step.
        let (raw, mut rx) = raw_pair();
        let (kept, mut passed) = passable(3);
        let last = passed.pop().unwrap();
        let later = passed.pop().unwrap();
        let first = passed.pop().unwrap();
        send_raw(&raw, &[2, 0, 0, 0, b'a'], &[first]);
        let limit = starve_descriptors();
        let message = {
            let receiving = rx.recv();
            tokio::pin!(receiving);
            // The frame's first write is read while the table is full; its
            // second, with a descriptor of its own, after: closed as well.
            for _ in 0..10_000 {
                if peer_closed(&kept[0]) {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = &mut receiving => panic!("the frame is not complete yet"),
                    () = tokio::task::yield_now() => {}
                }
            }
            assert!(peer_closed(&kept[0]), "the kernel closed what it discarded");
            setrlimit(Resource::Nofile, limit).unwrap();
            send_raw(&raw, b"b", &[later]);
            receiving.await.unwrap().unwrap()
        };
        assert_eq!(message.payload, b"ab");
        assert!(message.fds_truncated && message.fds.is_empty());
        assert!(peer_closed(&kept[1]), "the frame's later one is closed too");
        send_raw(&raw, &[1, 0, 0, 0, b'c'], &[last]);
        let message = rx.recv().await.unwrap().unwrap();
        assert_eq!(
            (message.payload.as_slice(), message.fds.len()),
            (&b"c"[..], 1)
        );
        assert!(!message.fds_truncated, "the flag is the frame's own");
    }

    #[tokio::test]
    async fn recv_msg_refuses_truncated_descriptors_and_recv_decoded_hands_them_over() {
        let (raw, mut rx) = raw_pair();
        let shutdown = ToWorker::Shutdown { deadline_ms: 7 };
        let (_kept, passed) = passable(3);
        for fd in &passed {
            send_raw(&raw, &framed(&shutdown), std::slice::from_ref(fd));
        }
        let limit = starve_descriptors();
        let refused = rx.recv_msg::<ToWorker>().await;
        let decoded = rx.recv_decoded::<ToWorker>().await;
        setrlimit(Resource::Nofile, limit).unwrap();
        assert!(matches!(refused.unwrap_err(), IpcError::FdsTruncated));
        let decoded = decoded.unwrap().unwrap();
        assert_eq!(decoded.message, shutdown);
        assert!(decoded.fds_truncated && decoded.fds.is_empty());
        let (message, fds) = rx.recv_msg::<ToWorker>().await.unwrap().unwrap();
        assert_eq!((message, fds.len()), (shutdown, 1));
        drop(raw);
        // One instantiation of `recv_msg` sees every outcome, the end too.
        assert!(rx.recv_msg::<ToWorker>().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn received_descriptors_are_close_on_exec() {
        // IPC-2: `MSG_CMSG_CLOEXEC` on Linux, `FD_CLOEXEC` right after elsewhere.
        let (raw, mut rx) = raw_pair();
        let (_kept, passed) = passable(MAX_FDS);
        for fd in &passed {
            rustix::io::fcntl_setfd(fd, FdFlags::empty()).unwrap();
        }
        send_raw(&raw, &[1, 0, 0, 0, b'a'], &passed);
        let message = rx.recv().await.unwrap().unwrap();
        assert_eq!(message.fds.len(), MAX_FDS);
        for fd in &message.fds {
            assert!(
                rustix::io::fcntl_getfd(fd)
                    .unwrap()
                    .contains(FdFlags::CLOEXEC)
            );
        }
    }

    #[tokio::test]
    async fn a_message_that_does_not_decode_is_an_error() {
        let (mut a_tx, _a_rx, _b_tx, mut b_rx) = pair();
        a_tx.send(&[0xff; 6], &[]).await.unwrap();
        assert!(matches!(
            b_rx.recv_msg::<ToSupervisor>().await.unwrap_err(),
            IpcError::Decode(_)
        ));
        a_tx.send_msg(&ToSupervisor::SourceState(SourceState::Live), &[])
            .await
            .unwrap();
        let (message, _) = b_rx.recv_msg::<ToSupervisor>().await.unwrap().unwrap();
        assert_eq!(message, ToSupervisor::SourceState(SourceState::Live));
    }
}
