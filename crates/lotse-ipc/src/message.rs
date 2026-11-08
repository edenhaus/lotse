//! The messages: `ToWorker` from the supervisor, `ToSupervisor` from the
//! worker. Plain data, no domain types: the supervisor validates every
//! field it uses and never treats one as a path or a command.
//!
//! Both ends are always the same binary (the supervisor re-executes
//! itself), so variants may be added freely; the wire format needs no
//! versioning.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// What the supervisor tells a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToWorker {
    /// Run this source connection until told to stop. A worker runs one.
    RunSource(SourceSpec),
    /// The grant for the connection attempt the worker last announced
    /// (`Connecting` or `Reconnecting`): it may connect now. The supervisor
    /// holds a `sources.connect_concurrency` permit for it until the
    /// attempt ends.
    ConnectGranted,
    /// Close every session, tear the source down and exit, within
    /// `deadline_ms`.
    Shutdown {
        /// The budget before the supervisor kills the worker.
        deadline_ms: u32,
    },
    /// The shared UDP socket and the worker's end of the datagram channel
    /// follow as descriptors, in that order. Sent once per worker; the
    /// worker refuses a second one.
    Sockets,
    /// An ICE-TCP connection whose first STUN request named one of this
    /// worker's sessions; its descriptor follows.
    IceTcp {
        /// The local ufrag of the session it belongs to.
        local_ufrag: String,
        /// The browser's address in canonical form: IPv4-mapped IPv6 as
        /// IPv4, as the UDP path reports sources.
        peer: SocketAddr,
        /// The RFC 4571 frame already read: the STUN request.
        first_frame: Vec<u8>,
    },
    /// Connect this source as the standby of the one running: the tracks
    /// switch to it at its first keyframe, and the old source stops. A
    /// standby still connecting is replaced.
    SwitchSource(SourceSpec),
    /// The connection asks for the camera's backchannel from now on (a
    /// stream on it opted in), or no longer (the last one opted out): the
    /// running source and the standby probe it, at once while they play,
    /// or stop and drop what they found, which frees it from its talker.
    /// Nothing restarts.
    Backchannel {
        /// Whether the connection asks.
        asks: bool,
    },
    /// The grant for the standby's last announced attempt.
    SwitchConnectGranted,
    /// The grant for the probe the worker announced (`ProbeConnecting`):
    /// it may connect now, under a `sources.connect_concurrency` permit
    /// the supervisor holds until its `ProbeEnded`. A worker whose probe
    /// with that id is over discards it.
    ProbeConnectGranted {
        /// The id of the probe, as its `ProbeConnecting` named it.
        probe: u64,
    },
    /// Open a viewer session on this connection's tracks.
    OpenSession(SessionSpec),
    /// A trickle candidate from the browser; empty means end of candidates.
    RemoteCandidate {
        /// The session.
        session_id: String,
        /// The `candidate:` line.
        candidate: String,
    },
    /// A re-offer from the browser (`webrtc/renegotiate`); a
    /// `Renegotiated` or `RenegotiateRefused` report answers it.
    Renegotiate {
        /// The session.
        session_id: String,
        /// The browser's SDP re-offer.
        sdp: String,
    },
    /// A relay candidate for a session: the address a TURN allocation
    /// relays from. What the session sends from it goes to the
    /// allocation's server as `ChannelData`: from the shared socket for a
    /// UDP allocation, padded on the datagram channel to the supervisor,
    /// which owns the connection, for a TCP one.
    RelayCandidate {
        /// The session.
        session_id: String,
        /// The relayed transport address (RFC 8656 §7.3).
        relayed: SocketAddr,
        /// The TURN server, in canonical form.
        server: SocketAddr,
        /// The host address the allocation's traffic leaves from: the
        /// candidate's local interface.
        local: SocketAddr,
        /// The allocation reaches its server over TCP (RFC 8656 §3.1).
        tcp: bool,
    },
    /// A channel the TURN server bound on a session's relay candidate to
    /// one peer (RFC 8656 §12).
    RelayChannel {
        /// The session.
        session_id: String,
        /// The relay candidate's address.
        relayed: SocketAddr,
        /// The peer, in canonical form.
        peer: SocketAddr,
        /// The channel number, 0x4000 to 0x4FFF.
        channel: u16,
    },
    /// The stream's orientation changed (a `stream/put`): an open session
    /// turns the picture from its next frame, one still waiting for its
    /// answer answers with it.
    SessionOrientation {
        /// The session.
        session_id: String,
        /// The orientation by its number, as in [`SessionSpec`].
        orientation: u8,
    },
    /// Close a session with this code and message.
    CloseSession {
        /// The session.
        session_id: String,
        /// The `closed` event's code.
        code: String,
        /// The `closed` event's message.
        message: String,
    },
    /// Free the connection's backchannel from its talker
    /// (`backchannel/release`); a `Talker` report follows when one held
    /// it, and the next offer that asks for talk-back claims it.
    ReleaseBackchannel {
        /// Free it only if this session holds it, decided in the worker
        /// against the claims; any talker when `None`.
        session_id: Option<String>,
    },
    /// The connection's pre-record window changed (a `stream/put`): its
    /// tracks keep the last `ms` of media in memory for recordings from now
    /// on, or none when 0. Nothing reconnects; a new worker gets the
    /// window with its [`SourceSpec::prerecord_ms`].
    Prerecord {
        /// The window in milliseconds, 0 for none.
        ms: u32,
    },
    /// Start an event recording; the write end of the pipe its bytes go to
    /// follows as the one descriptor. Reports come back as
    /// [`ToSupervisor::Recording`], the last a [`RecordingReport::Closed`], after
    /// which the worker holds the write end no more.
    StartRecording(RecordingSpec),
    /// End the recording `recording_id` cleanly for a reason of the supervisor's
    /// own (its body not fetched in time, its subscription gone): its last
    /// fragment is written and it reports `Closed` with
    /// [`STOPPED_AS_ASKED`], in whose place the supervisor puts its reason.
    /// One the worker does not run is ignored. A client never stops a recording:
    /// it runs the length it asked for.
    StopRecording {
        /// The recording.
        recording_id: String,
    },
    /// What the supervisor answers a signaled source's signaling
    /// ([`ToSupervisor::Signal`]) with: the control-API client's relay.
    Signal(SignalCommand),
}

impl ToWorker {
    /// The message's kind, for the log: its variant's name in snake case,
    /// without the fields, some of which are secrets or a peer's text.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::RunSource(_) => "run_source",
            Self::ConnectGranted => "connect_granted",
            Self::Shutdown { .. } => "shutdown",
            Self::Sockets => "sockets",
            Self::IceTcp { .. } => "ice_tcp",
            Self::SwitchSource(_) => "switch_source",
            Self::Backchannel { .. } => "backchannel",
            Self::SwitchConnectGranted => "switch_connect_granted",
            Self::ProbeConnectGranted { .. } => "probe_connect_granted",
            Self::OpenSession(_) => "open_session",
            Self::RemoteCandidate { .. } => "remote_candidate",
            Self::Renegotiate { .. } => "renegotiate",
            Self::RelayCandidate { .. } => "relay_candidate",
            Self::RelayChannel { .. } => "relay_channel",
            Self::SessionOrientation { .. } => "session_orientation",
            Self::CloseSession { .. } => "close_session",
            Self::ReleaseBackchannel { .. } => "release_backchannel",
            Self::Prerecord { .. } => "prerecord",
            Self::StartRecording(_) => "start_recording",
            Self::StopRecording { .. } => "stop_recording",
        }
    }
}

/// An event recording to start: what the client asked for, checked against
/// the limits by the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingSpec {
    /// The recording id, the client's or a generated one.
    pub recording_id: String,
    /// How far before now the recording should start, in milliseconds; what
    /// the pre-record window holds bounds what it gets.
    pub prerecord_ms: u32,
    /// How long it runs after the worker gets it, in milliseconds: what
    /// is left of the client's `duration_ms`, the supervisor taking off what
    /// the start waited for a worker; bounded by the worker's longest
    /// recording.
    pub duration_ms: u32,
    /// Take the stream's audio into the recording when it has one that fits.
    pub audio: bool,
}

/// A session to open: the browser's offer, the ICE credentials the
/// supervisor generated (its demux verifies them), and the local
/// candidates the supervisor gathered for the shared socket.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSpec {
    /// The session id, the client's or a generated one.
    pub session_id: String,
    /// The output kind that opens it (`webrtc`).
    pub kind: String,
    /// The browser's SDP offer.
    pub offer: String,
    /// The local ICE ufrag.
    pub ice_ufrag: String,
    /// The local ICE password.
    pub ice_pass: String,
    /// Host candidates: the shared socket's addresses.
    pub candidates: Vec<SocketAddr>,
    /// Passive ICE-TCP host candidates: the listener's addresses.
    pub tcp_candidates: Vec<SocketAddr>,
    /// Negotiate audio when the stream has it.
    pub audio: bool,
    /// The stream's orientation by its number, 1 (none) to 8
    /// (`lotse_core::Orientation::code`).
    pub orientation: u8,
}

impl fmt::Debug for SessionSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSpec")
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .field("offer_len", &self.offer.len())
            .field("ice_ufrag", &self.ice_ufrag)
            .field("ice_pass", &"****")
            .field("candidates", &self.candidates)
            .field("tcp_candidates", &self.tcp_candidates)
            .field("audio", &self.audio)
            .field("orientation", &self.orientation)
            .finish()
    }
}

/// What a session reports, in the order 04 lists the events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionEvent {
    /// The SDP answer.
    Answer {
        /// The SDP.
        sdp: String,
        /// The talk-back codec the answer negotiated (`opus`, `pcmu`,
        /// `pcma`); `None` when talk-back is off.
        talkback: Option<String>,
    },
    /// The answer to a re-offer (`Renegotiate`).
    Renegotiated {
        /// The SDP.
        sdp: String,
        /// The talk-back codec the answer negotiated (`opus`, `pcmu`,
        /// `pcma`); `None` when talk-back is off now.
        talkback: Option<String>,
    },
    /// A re-offer (`Renegotiate`) was not applied; the session goes on
    /// as it was.
    RenegotiateRefused {
        /// The error code (`invalid_sdp`, `no_video_track`).
        code: String,
        /// For humans.
        message: String,
    },
    /// The offer or re-offer asked for talk-back the session did not get:
    /// its talk-back m-line was answered without it. One per offer, after
    /// its `Answer` or `Renegotiated`.
    TalkbackDeclined {
        /// Why: `unsupported`, `busy` or `refused`.
        reason: String,
        /// The camera's status code, when it refused with one.
        status: Option<u16>,
        /// For humans.
        message: String,
    },
    /// A local candidate; empty means end of candidates.
    Candidate {
        /// The `candidate:` line, or empty.
        candidate: String,
        /// The mid it belongs to.
        mid: Option<String>,
    },
    /// The relay candidate the supervisor handed over for `relayed`: its
    /// `candidate:` line for the browser, or `None` when the session did
    /// not take it. Ends that relay's gathering.
    Relayed {
        /// The relayed address.
        relayed: SocketAddr,
        /// The `candidate:` line.
        candidate: Option<String>,
    },
    /// The session sends from the relay candidate at `relayed` to `peer`,
    /// which has no channel yet: the supervisor binds one (RFC 8656 §12).
    ChannelWanted {
        /// The relayed address.
        relayed: SocketAddr,
        /// The peer, in canonical form.
        peer: SocketAddr,
    },
    /// ICE or DTLS changed.
    State {
        /// The ICE state name.
        ice: String,
        /// The DTLS state name.
        dtls: String,
    },
    /// Non-fatal.
    Warning {
        /// The code.
        code: String,
        /// For humans.
        message: String,
    },
    /// The last event.
    Closed {
        /// The code.
        code: String,
        /// For humans.
        message: String,
    },
}

/// A source connection to run. Carries the credentials, which exist in the
/// supervisor and in the one worker that uses them; `Debug` redacts the URL
/// and the options, whose values can carry a secret too.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpec {
    /// The supervisor's id for the connection, echoed in reports.
    pub connection_id: String,
    /// What names the source: its URL, or a signaled source's protocol.
    pub target: SourceTarget,
    /// The protocol's fields but the URL, as JSON text: what its
    /// factory parses.
    pub options: String,
    /// The host name, for the protocol URL and TLS SNI; empty for a
    /// signaled source, which has no address.
    pub peer_host: String,
    /// The resolved addresses to try, in order (workers have no DNS); none
    /// for a signaled source.
    pub peer_addrs: Vec<SocketAddr>,
    /// Where the reconnect schedule starts: where the connection's earlier
    /// workers left it, so a source that keeps failing is not retried at
    /// the first step's pace, nor at once again, whenever a worker starts
    /// over.
    pub backoff: BackoffPosition,
    /// The pre-record window the connection's tracks keep, in milliseconds,
    /// 0 for none; [`ToWorker::Prerecord`] changes it later.
    pub prerecord_ms: u32,
}

/// What names a source a worker runs. `Debug` redacts the URL, which
/// carries the credentials.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceTarget {
    /// A source the worker connects to: its full URL, credentials
    /// included, whose scheme is a protocol the worker's registry has.
    Url(String),
    /// A source whose signaling the control-API client relays, by its
    /// protocol (`webrtc`), which the worker's registry has as a signaled
    /// one: it has no address, and each attempt opens a signaling channel.
    Signaled(String),
}

impl fmt::Debug for SourceTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(_) => f.write_str("Url(****)"),
            Self::Signaled(protocol) => f.debug_tuple("Signaled").field(protocol).finish(),
        }
    }
}

/// Where a source's reconnect schedule stands: all a new worker needs to
/// continue it exactly. The wire form of
/// `lotse_core::backoff::BackoffPosition`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackoffPosition {
    /// Delays handed out since the schedule last started over.
    pub attempts: u32,
    /// The immediate attempt after a live period has been used since then.
    pub immediate_used: bool,
}

impl fmt::Debug for SourceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceSpec")
            .field("connection_id", &self.connection_id)
            .field("target", &self.target)
            .field("options", &"****")
            .field("peer_host", &self.peer_host)
            .field("peer_addrs", &self.peer_addrs)
            .field("backoff", &self.backoff)
            .field("prerecord_ms", &self.prerecord_ms)
            .finish()
    }
}

/// What a worker tells the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToSupervisor {
    /// The worker is up, sandboxed, and listening. Its
    /// `/proc/self/smaps_rollup`, opened before the sandbox, may follow as
    /// a descriptor: the supervisor reads the worker's memory through it,
    /// since a worker is not dumpable and its `/proc` entry closed to
    /// others. `Ready` is the first message, sent before the worker has
    /// read a byte from a camera or a peer, so the descriptor is the one
    /// it opened, not one a compromised worker chose.
    Ready {
        /// Its process id, for the supervisor's own bookkeeping only; the
        /// supervisor already knows it from the spawn.
        pid: u32,
    },
    /// The source connection changed state.
    SourceState(SourceState),
    /// The standby source changed state; the connection's own state is
    /// the running source's until `Switched`.
    SwitchState(SourceState),
    /// The tracks switched to the standby, which is the source now; its
    /// tracks follow.
    Switched,
    /// The tracks the source declared, sent when it goes live, when a
    /// derived track comes or goes, and before the next counters when a
    /// track's state changed since (its `sync`, with the camera's first
    /// Sender Report).
    Tracks(Vec<TrackInfo>),
    /// The once-per-second counters.
    Stats(WorkerStats),
    /// A session reported something.
    Session {
        /// The session.
        session_id: String,
        /// What happened.
        event: SessionEvent,
    },
    /// The talker of the connection's backchannel changed.
    Talker(TalkerChange),
    /// A source of the worker probes the device's backchannel on a
    /// connection of its own and waits for a connect permit, as an
    /// attempt does; the `ProbeConnectGranted` naming it lets it go. The
    /// worker runs one probe at a time: its `ProbeEnded` comes before the
    /// next one's `ProbeConnecting`.
    ProbeConnecting {
        /// The probe's id, unique within the worker.
        probe: u64,
    },
    /// The probe is over: its permit, or its wait for one, ends.
    ProbeEnded {
        /// The probe's id, as its `ProbeConnecting` named it.
        probe: u64,
    },
    /// An event recording reported something.
    Recording {
        /// The recording, as its [`ToWorker::StartRecording`] named it.
        recording_id: String,
        /// What happened.
        event: RecordingReport,
    },
    /// A signaled source's signaling: it asks for a channel to the
    /// control-API client that relays its signaling, or sends on one;
    /// [`ToWorker::Signal`] answers.
    Signal(SignalReport),
}

/// The most bytes of SDP a [`SignalCommand::Answer`] carries, and the
/// bound of a [`SignalReport::Offer`]'s tighter cap
/// ([`MAX_SIGNAL_OFFER_BYTES`]): the control API's cap on an SDP
/// (`MAX_SDP_CHARS`, 64 Ki characters, which its frame bounds to as many
/// bytes). With [`MAX_SIGNAL_TEXT_BYTES`] for the rest, a signal message
/// stays far below the frame's [`MAX_MESSAGE_BYTES`](crate::MAX_MESSAGE_BYTES),
/// so encoding one never fails for its size; the sender drops a longer one.
pub const MAX_SIGNAL_SDP_BYTES: usize = 64 * 1024;

/// The most bytes of any other text a signal message carries: a
/// candidate line, a `mid`, a code or a message. The control API's cap
/// on a candidate line (`MAX_TEXT_CHARS`, 1024 characters) in bytes,
/// four per character.
pub const MAX_SIGNAL_TEXT_BYTES: usize = 4 * 1024;

/// The most bytes of SDP a worker's [`SignalReport::Offer`] carries: what
/// the supervisor passes on to the client. A WebRTC offer of audio, video
/// and a data channel, its host candidates included, is two or three KiB.
/// The worker ends a signal whose offer is longer itself, so the
/// supervisor never has to reject one.
pub const MAX_SIGNAL_OFFER_BYTES: usize = 16 * 1024;

/// The most bytes of a worker's [`SignalReport::Candidate`] line or `mid`:
/// the control API's cap on a candidate line (`MAX_TEXT_CHARS`, 1024
/// characters), which the supervisor checks it against in bytes. The
/// worker ends a signal whose candidate is longer itself, as for an
/// offer over [`MAX_SIGNAL_OFFER_BYTES`].
pub const MAX_SIGNAL_CANDIDATE_BYTES: usize = 1024;

/// What a worker's signaled source sends toward the control-API client
/// that relays its signaling (`lotse_core::signaling`), in the order it
/// sends it. A channel is asked for with `Open` and named by the
/// supervisor's `signal_id` from its [`SignalCommand::Opened`] on; its
/// `Closed` is its last report.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalReport {
    /// A connection attempt asks for a signaling channel; `Opened` or
    /// `Refused` with the same `request` answers it.
    Open {
        /// The worker's id for the open, unique within the worker.
        request: u64,
    },
    /// The attempt that sent `Open` with `request` is over before an
    /// answer came: none is needed any more, and an `Opened` that
    /// crosses this is closed at once.
    Cancel {
        /// The open's id.
        request: u64,
    },
    /// The source's SDP offer (RFC 8829 §5.2), once per signal. `Debug`
    /// shows its length only: it carries the ICE password (RFC 8839 §5.4).
    Offer {
        /// The signal.
        signal_id: String,
        /// The SDP, at most [`MAX_SIGNAL_OFFER_BYTES`].
        sdp: String,
    },
    /// A local candidate trickled after the offer (RFC 8838 §8), or the
    /// end-of-candidates indication, an empty `candidate` (RFC 8838 §13).
    Candidate {
        /// The signal.
        signal_id: String,
        /// The `candidate:` attribute without `a=`, or empty; at most
        /// [`MAX_SIGNAL_CANDIDATE_BYTES`].
        candidate: String,
        /// The `a=mid` of its media section (RFC 8843 §7.1), at most
        /// [`MAX_SIGNAL_CANDIDATE_BYTES`].
        mid: Option<String>,
        /// The index of its media section, 0 for the first.
        mline_index: Option<u16>,
    },
    /// The source closed the channel: the signal is over.
    Closed {
        /// The signal.
        signal_id: String,
        /// The source's close code (`lotse_core::signaling::close`).
        code: String,
        /// What happened, for humans.
        message: String,
    },
}

impl fmt::Debug for SignalReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { request } => f.debug_struct("Open").field("request", request).finish(),
            Self::Cancel { request } => f.debug_struct("Cancel").field("request", request).finish(),
            Self::Offer { signal_id, sdp } => f
                .debug_struct("Offer")
                .field("signal_id", signal_id)
                .field("sdp_len", &sdp.len())
                .finish(),
            Self::Candidate {
                signal_id,
                candidate,
                mid,
                mline_index,
            } => f
                .debug_struct("Candidate")
                .field("signal_id", signal_id)
                .field("candidate", candidate)
                .field("mid", mid)
                .field("mline_index", mline_index)
                .finish(),
            Self::Closed {
                signal_id,
                code,
                message,
            } => f
                .debug_struct("Closed")
                .field("signal_id", signal_id)
                .field("code", code)
                .field("message", message)
                .finish(),
        }
    }
}

/// What the supervisor tells a worker about its signaled sources'
/// signaling: the answer to an `Open`, and what the control-API client
/// relays on an open signal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalCommand {
    /// The open `request` got a channel, the signal `signal_id`.
    Opened {
        /// The open's id, as its `Open` named it.
        request: u64,
        /// The signal's id, which every later message about it names.
        signal_id: String,
        /// The host addresses the source may gather candidates on,
        /// enumerated by the supervisor before the worker was sandboxed.
        local_addrs: Vec<IpAddr>,
    },
    /// The open `request` got no channel: the attempt ends unreachable.
    Refused {
        /// The open's id.
        request: u64,
        /// Why (`no_signaling_client`).
        code: String,
        /// What happened, for humans.
        message: String,
    },
    /// The camera's SDP answer (RFC 8829 §5.3). `Debug` shows its length
    /// only: it carries the camera's ICE password.
    Answer {
        /// The signal.
        signal_id: String,
        /// The SDP, at most [`MAX_SIGNAL_SDP_BYTES`].
        sdp: String,
    },
    /// A candidate of the camera's (RFC 8838 §10), or its
    /// end-of-candidates indication, an empty `candidate`.
    Candidate {
        /// The signal.
        signal_id: String,
        /// The `candidate:` attribute without `a=`, or empty.
        candidate: String,
        /// The `a=mid` of its media section.
        mid: Option<String>,
        /// The index of its media section, 0 for the first.
        mline_index: Option<u16>,
    },
    /// The camera or its integration ended the signal with an error;
    /// nothing follows.
    Failed {
        /// The signal.
        signal_id: String,
        /// The client's code.
        code: String,
        /// What happened, for humans.
        message: String,
    },
    /// The client relaying the signal went away; nothing follows.
    Gone {
        /// The signal.
        signal_id: String,
    },
}

impl fmt::Debug for SignalCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opened {
                request,
                signal_id,
                local_addrs,
            } => f
                .debug_struct("Opened")
                .field("request", request)
                .field("signal_id", signal_id)
                .field("local_addrs", local_addrs)
                .finish(),
            Self::Refused {
                request,
                code,
                message,
            } => f
                .debug_struct("Refused")
                .field("request", request)
                .field("code", code)
                .field("message", message)
                .finish(),
            Self::Answer { signal_id, sdp } => f
                .debug_struct("Answer")
                .field("signal_id", signal_id)
                .field("sdp_len", &sdp.len())
                .finish(),
            Self::Candidate {
                signal_id,
                candidate,
                mid,
                mline_index,
            } => f
                .debug_struct("Candidate")
                .field("signal_id", signal_id)
                .field("candidate", candidate)
                .field("mid", mid)
                .field("mline_index", mline_index)
                .finish(),
            Self::Failed {
                signal_id,
                code,
                message,
            } => f
                .debug_struct("Failed")
                .field("signal_id", signal_id)
                .field("code", code)
                .field("message", message)
                .finish(),
            Self::Gone { signal_id } => f
                .debug_struct("Gone")
                .field("signal_id", signal_id)
                .finish(),
        }
    }
}

/// The reason of a [`RecordingReport::Closed`] that ends a recording as the
/// supervisor asked ([`ToWorker::StopRecording`]): no reason of the API, since
/// the supervisor puts its own in its place.
pub const STOPPED_AS_ASKED: &str = "stopped";

/// What an event recording reports, in the order the API's events come: one
/// `Started` unless it ends first, warnings and gaps, and `Closed` last.
/// Names and numbers only; the supervisor checks each against what it
/// knows before the client sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordingReport {
    /// The recording's first fragment is under way.
    Started {
        /// How far before this report the recording begins, in milliseconds:
        /// the age, when the container started (which is when the worker
        /// sends this), of the keyframe it starts at. The supervisor
        /// stamps the API's `at` on the report's arrival, so
        /// `at − prerecord_ms` is that keyframe's capture time.
        prerecord_ms: u32,
        /// The video codec by its API name (`h264`, `h265`).
        video: String,
        /// The picture's width and height in pixels, cropping applied,
        /// when the sequence parameter set gives them.
        picture: Option<(u32, u32)>,
        /// The audio codec by its API name (`aac_lc`, `opus`); `None` for
        /// a recording without audio.
        audio: Option<String>,
    },
    /// Non-fatal (`audio_omitted`).
    Warning {
        /// The code.
        code: String,
        /// For humans.
        message: String,
    },
    /// The recording has a hole.
    Gap {
        /// Why (`reconnect`, `overflow`, `lagged`, `frames_dropped`).
        reason: String,
        /// Where the hole begins, in milliseconds of recording media time.
        from_ms: u32,
        /// Where it ends.
        to_ms: u32,
    },
    /// The last report: the recording ended and the worker closed its pipe.
    Closed {
        /// Why (`completed`, `client_gone`, ...), or [`STOPPED_AS_ASKED`]
        /// for the end of a [`ToWorker::StopRecording`].
        reason: String,
        /// The file's length: the bytes written to the pipe, and the last
        /// ones its reader did not take in time, which the pipe never got;
        /// a body that read fewer is cut.
        bytes: u64,
        /// The media time the recording covers, in milliseconds.
        duration_ms: u32,
        /// The gaps it reported.
        gaps: u32,
    },
}

/// A change of the connection's talker: the session it concerns, the new
/// talker after `claimed`, the one that let go after `session_closed`,
/// `released`, `renegotiated`, `refused` or `opted_out`, when the channel is free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TalkerChange {
    /// The session.
    pub session_id: String,
    /// `claimed`, `session_closed`, `released`, `renegotiated`,
    /// `refused` or `opted_out`.
    pub reason: String,
    /// When, in milliseconds since the Unix epoch.
    pub at_ms: u64,
}

/// One session's talk-back counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TalkbackStats {
    /// Talk-back packets the session received and took.
    pub packets_received: u64,
    /// Those dropped because the session did not hold the backchannel.
    pub packets_dropped_busy: u64,
    /// Payload bytes handed to the backchannel.
    pub bytes_sent: u64,
}

/// The source connection's state, mirroring the runner's events with
/// plain strings for the error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceState {
    /// An attempt started after idle or a backoff.
    Connecting {
        /// Attempts so far, this one included.
        attempt: u32,
    },
    /// Tracks are ready; media flows.
    Live,
    /// The source has streamed long enough that its reconnect schedule
    /// starts over: the position a new worker continues from is the first
    /// step again ([`SourceSpec::backoff`]).
    Stable,
    /// The live source dropped; an attempt starts at once: the schedule's
    /// immediate attempt, used from now on.
    Reconnecting {
        /// The error code (`source_timeout`, ...).
        code: String,
        /// The error message.
        message: String,
    },
    /// An attempt failed; the next one starts in `retry_ms`.
    Backoff {
        /// The error code.
        code: String,
        /// The error message.
        message: String,
        /// The wait.
        retry_ms: u32,
        /// Where the reconnect schedule stands, this delay included: where
        /// a new worker's continues ([`SourceSpec::backoff`]).
        position: BackoffPosition,
    },
    /// The runner stopped.
    Stopped,
}

/// One track as the API reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackInfo {
    /// The track id (`v0`, `a0`).
    pub id: String,
    /// `video` or `audio`.
    pub kind: String,
    /// The codec name (`h264`, `aac_lc`, ...).
    pub codec: String,
    /// `arrival` or `sender_reports`, as the connection's clock mapper has
    /// it when sent; a derived track's is its source's.
    pub sync: String,
    /// The native track a derived track is transcoded from; `None` for a
    /// native track.
    pub derived_from: Option<String>,
    /// The delay a derived track's transcoder adds, in milliseconds;
    /// `None` for a native track.
    pub audio_delay_ms: Option<u32>,
    /// The codec's parameters, as far as they are known.
    pub params: TrackParams,
}

/// A track's codec parameters, as far as the worker knows them: each is
/// `None` where the codec has no such parameter or it is not known yet.
/// Bytes and numbers, never text, so the supervisor formats what it
/// reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrackParams {
    /// An H.264 track's `profile_idc`, constraint flags and `level_idc`,
    /// the three bytes RFC 6184 §8.1 spells as `profile-level-id`, once
    /// its sequence parameter set is known.
    pub profile_level_id: Option<[u8; 3]>,
    /// A video track's picture width and height in pixels, cropping
    /// applied, from its sequence parameter set once known (ISO/IEC
    /// 14496-10 §7.4.2.1.1, ITU-T H.265 §7.4.3.2.1).
    pub picture: Option<(u32, u32)>,
    /// An audio track's sampling rate in Hz.
    pub sample_rate: Option<u32>,
    /// An audio track's channel count.
    pub channels: Option<u8>,
}

/// One track's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackStats {
    /// Payload bytes of the packets published.
    pub packet_bytes: u64,
    /// Frames accepted on the side branch.
    pub frames: u64,
    /// Payload bytes of those frames.
    pub frame_bytes: u64,
    /// Frames dropped as oversize.
    pub frames_dropped_oversize: u64,
    /// Frames the live path carried in more RTP packets than some
    /// libwebrtc receivers assemble.
    pub frames_over_browser_limit: u64,
    /// The pre-record ring, while a window is set; `None` without one.
    pub prerecord: Option<PrerecordStats>,
}

/// A track's pre-record ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrerecordStats {
    /// What the held frames count against `limits.max_prerecord_bytes`: their
    /// payload plus a fixed overhead each.
    pub bytes: u64,
    /// The capture time from the oldest held frame to the newest, in
    /// milliseconds: how far back a recording can start now.
    pub held_ms: u32,
    /// GOPs that alone outgrew `limits.max_prerecord_bytes`, so only their
    /// start was held, over the track's life.
    pub truncations: u64,
}

/// The worker's counters, pushed once per second.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WorkerStats {
    /// Per track, keyed by track id.
    pub tracks: Vec<(String, TrackStats)>,
    /// Open sessions.
    pub sessions: u32,
    /// Datagrams the sessions could not send: a full UDP buffer, or an
    /// ICE-TCP connection that is full or gone.
    pub send_failures: u64,
    /// Times the skew watchdog withdrew the source's audio; at most one,
    /// since it stays withdrawn while the source runs.
    pub av_sync_lost: u64,
    /// Datagrams from a relay candidate to a peer without a channel yet,
    /// or too long for `ChannelData`, dropped.
    pub relay_unbound: u64,
    /// Tokio tasks alive in the worker's runtime.
    pub tasks: u64,
    /// RTP packets the source's sequence numbers say never arrived.
    pub packets_lost: u64,
    /// RTP packets the source dropped as duplicates or as late.
    pub packets_out_of_order: u64,
    /// Datagrams the source refused before reading them: another sender,
    /// not RTP, another synchronization source.
    pub datagrams_rejected: u64,
    /// Per session whose answer negotiated talk-back, keyed by session id.
    pub talkback: Vec<(String, TalkbackStats)>,
    /// The codec of the backchannel the running source offers now, by its
    /// API name (`pcmu`); `None` while it offers none.
    pub backchannel: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::codec::{decode, encode};

    #[test]
    fn session_spec_debug_redacts_the_password_and_shows_the_candidates() {
        let spec = SessionSpec {
            session_id: "s1".into(),
            kind: "webrtc".into(),
            offer: "v=0".into(),
            ice_ufrag: "ufrag".into(),
            ice_pass: "hunter2hunter2hunter2hu".into(),
            candidates: vec!["192.0.2.1:18556".parse().unwrap()],
            tcp_candidates: vec!["192.0.2.1:18557".parse().unwrap()],
            audio: true,
            orientation: 6,
        };
        let text = format!("{spec:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("tcp_candidates: [192.0.2.1:18557]"), "{text}");
        assert!(text.contains("orientation: 6"), "{text}");
        let open = ToWorker::OpenSession(spec);
        assert_eq!(decode::<ToWorker>(&encode(&open).unwrap()).unwrap(), open);
        let tcp = ToWorker::IceTcp {
            local_ufrag: "ufrag".into(),
            peer: "192.0.2.9:50000".parse().unwrap(),
            first_frame: vec![0, 1],
        };
        assert_eq!(decode::<ToWorker>(&encode(&tcp).unwrap()).unwrap(), tcp);
    }

    #[test]
    fn source_spec_debug_redacts_the_url() {
        let spec = SourceSpec {
            connection_id: "c1".into(),
            target: SourceTarget::Url("rtsp://admin:hunter2@cam/main".into()),
            options: "{}".into(),
            peer_host: "cam".into(),
            peer_addrs: vec!["192.168.1.10:554".parse().unwrap()],
            backoff: BackoffPosition {
                attempts: 3,
                immediate_used: true,
            },
            prerecord_ms: 30_000,
        };
        let text = format!("{spec:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("target: Url(****)"), "{text}");
        assert!(text.contains("options: \"****\""), "{text}");
        assert!(text.contains("192.168.1.10:554"), "{text}");
        assert!(
            text.contains("backoff: BackoffPosition { attempts: 3, immediate_used: true }"),
            "{text}"
        );
        assert!(text.contains("prerecord_ms: 30000"), "{text}");
        let wrapped = ToWorker::RunSource(spec.clone());
        assert!(!format!("{wrapped:?}").contains("hunter2"));
        assert_eq!(
            decode::<ToWorker>(&encode(&wrapped).unwrap()).unwrap(),
            wrapped
        );
        // A signaled source: its protocol, no address.
        let signaled = SourceSpec {
            target: SourceTarget::Signaled("webrtc".into()),
            peer_host: String::new(),
            peer_addrs: vec![],
            ..spec
        };
        assert!(
            format!("{signaled:?}").contains(r#"target: Signaled("webrtc")"#),
            "{signaled:?}"
        );
        let wrapped = ToWorker::SwitchSource(signaled);
        assert_eq!(
            decode::<ToWorker>(&encode(&wrapped).unwrap()).unwrap(),
            wrapped
        );
    }

    #[test]
    fn the_reconnect_position_round_trips() {
        for message in [
            ToSupervisor::SourceState(SourceState::Stable),
            ToSupervisor::SwitchState(SourceState::Backoff {
                code: "source_timeout".into(),
                message: "stall".into(),
                retry_ms: 5_000,
                position: BackoffPosition {
                    attempts: 6,
                    immediate_used: false,
                },
            }),
        ] {
            assert_eq!(
                decode::<ToSupervisor>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
    }

    #[test]
    fn tracks_round_trip_with_their_codec_parameters() {
        let messages = vec![
            ToSupervisor::Tracks(vec![TrackInfo {
                id: "v0".into(),
                kind: "video".into(),
                codec: "h264".into(),
                sync: "arrival".into(),
                derived_from: None,
                audio_delay_ms: None,
                params: TrackParams {
                    profile_level_id: Some([0x42, 0xc0, 0x28]),
                    picture: Some((640, 480)),
                    sample_rate: None,
                    channels: None,
                },
            }]),
            ToSupervisor::Tracks(vec![TrackInfo {
                id: "a1".into(),
                kind: "audio".into(),
                codec: "opus".into(),
                sync: "sender_reports".into(),
                derived_from: Some("a0".into()),
                audio_delay_ms: Some(88),
                params: TrackParams {
                    sample_rate: Some(48_000),
                    channels: Some(2),
                    ..TrackParams::default()
                },
            }]),
        ];
        for message in messages {
            assert_eq!(
                decode::<ToSupervisor>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
    }

    #[test]
    fn every_message_round_trips() {
        let messages = vec![
            ToSupervisor::Ready { pid: 1 },
            ToSupervisor::SourceState(SourceState::Connecting { attempt: 2 }),
            ToSupervisor::SourceState(SourceState::Live),
            ToSupervisor::SourceState(SourceState::Reconnecting {
                code: "source_ended".into(),
                message: "eof".into(),
            }),
            ToSupervisor::SourceState(SourceState::Stopped),
            ToSupervisor::Stats(WorkerStats {
                tracks: vec![(
                    "v0".into(),
                    TrackStats {
                        packet_bytes: 2,
                        frames: 3,
                        frame_bytes: 4,
                        frames_dropped_oversize: 6,
                        frames_over_browser_limit: 7,
                        prerecord: Some(PrerecordStats {
                            bytes: 14_201_337,
                            held_ms: 29_800,
                            truncations: 1,
                        }),
                    },
                )],
                sessions: 0,
                send_failures: 0,
                av_sync_lost: 1,
                relay_unbound: 2,
                tasks: 3,
                packets_lost: 4,
                packets_out_of_order: 5,
                datagrams_rejected: 6,
                talkback: vec![],
                backchannel: Some("pcmu".into()),
            }),
            ToSupervisor::Session {
                session_id: "s1".into(),
                event: SessionEvent::Relayed {
                    relayed: "203.0.113.1:49153".parse().unwrap(),
                    candidate: Some("candidate:1 1 udp 1 203.0.113.1 49153 typ relay".into()),
                },
            },
            ToSupervisor::Session {
                session_id: "s1".into(),
                event: SessionEvent::ChannelWanted {
                    relayed: "203.0.113.1:49153".parse().unwrap(),
                    peer: "192.0.2.9:50000".parse().unwrap(),
                },
            },
        ];
        for message in messages {
            assert_eq!(
                decode::<ToSupervisor>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
        for message in [
            ToWorker::Shutdown { deadline_ms: 2_000 },
            ToWorker::ConnectGranted,
            ToWorker::ProbeConnectGranted { probe: 7 },
            ToWorker::RelayCandidate {
                session_id: "s1".into(),
                relayed: "203.0.113.1:49153".parse().unwrap(),
                server: "192.0.2.3:3478".parse().unwrap(),
                local: "192.0.2.1:18556".parse().unwrap(),
                tcp: true,
            },
            ToWorker::RelayChannel {
                session_id: "s1".into(),
                relayed: "203.0.113.1:49153".parse().unwrap(),
                peer: "192.0.2.9:50000".parse().unwrap(),
                channel: 0x4000,
            },
            ToWorker::SessionOrientation {
                session_id: "s1".into(),
                orientation: 8,
            },
        ] {
            assert_eq!(
                decode::<ToWorker>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
        assert_eq!(WorkerStats::default().sessions, 0);
    }

    #[test]
    fn the_talk_back_messages_round_trip() {
        for message in [
            ToSupervisor::Stats(WorkerStats {
                talkback: vec![(
                    "s1".into(),
                    TalkbackStats {
                        packets_received: 7,
                        packets_dropped_busy: 1,
                        bytes_sent: 960,
                    },
                )],
                ..WorkerStats::default()
            }),
            ToSupervisor::Talker(TalkerChange {
                session_id: "s1".into(),
                reason: "claimed".into(),
                at_ms: 1_791_280_800_000,
            }),
            ToSupervisor::ProbeConnecting { probe: 7 },
            ToSupervisor::ProbeEnded { probe: 7 },
            ToSupervisor::Session {
                session_id: "s1".into(),
                event: SessionEvent::Answer {
                    sdp: "v=0".into(),
                    talkback: Some("pcmu".into()),
                },
            },
            ToSupervisor::Session {
                session_id: "s1".into(),
                event: SessionEvent::Renegotiated {
                    sdp: "v=0".into(),
                    talkback: None,
                },
            },
            ToSupervisor::Session {
                session_id: "s1".into(),
                event: SessionEvent::RenegotiateRefused {
                    code: "invalid_sdp".into(),
                    message: "no".into(),
                },
            },
            ToSupervisor::Session {
                session_id: "s1".into(),
                event: SessionEvent::TalkbackDeclined {
                    reason: "refused".into(),
                    status: Some(503),
                    message: "the camera refused".into(),
                },
            },
        ] {
            assert_eq!(
                decode::<ToSupervisor>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
        for release in [
            ToWorker::Renegotiate {
                session_id: "s1".into(),
                sdp: "v=0".into(),
            },
            ToWorker::Backchannel { asks: true },
            ToWorker::Backchannel { asks: false },
            ToWorker::ReleaseBackchannel { session_id: None },
            ToWorker::ReleaseBackchannel {
                session_id: Some("s1".into()),
            },
        ] {
            assert_eq!(
                decode::<ToWorker>(&encode(&release).unwrap()).unwrap(),
                release
            );
        }
    }

    fn signal_reports() -> Vec<SignalReport> {
        vec![
            SignalReport::Open { request: 1 },
            SignalReport::Cancel { request: u64::MAX },
            SignalReport::Offer {
                signal_id: "01JSIG".into(),
                sdp: "v=0\r\na=ice-pwd:hunter2hunter2hunter2hu\r\n".into(),
            },
            SignalReport::Candidate {
                signal_id: "01JSIG".into(),
                candidate: "candidate:1 1 udp 2130706431 192.0.2.7 50000 typ host".into(),
                mid: Some("0".into()),
                mline_index: Some(0),
            },
            SignalReport::Candidate {
                signal_id: "01JSIG".into(),
                candidate: String::new(),
                mid: None,
                mline_index: None,
            },
            SignalReport::Closed {
                signal_id: "01JSIG".into(),
                code: "answer_timeout".into(),
                message: "no answer within 20 s".into(),
            },
        ]
    }

    fn signal_commands() -> Vec<SignalCommand> {
        vec![
            SignalCommand::Opened {
                request: 1,
                signal_id: "01JSIG".into(),
                local_addrs: vec!["192.0.2.7".parse().unwrap(), "2001:db8::7".parse().unwrap()],
            },
            SignalCommand::Refused {
                request: 2,
                code: "no_signaling_client".into(),
                message: "no client relays this stream's signaling".into(),
            },
            SignalCommand::Answer {
                signal_id: "01JSIG".into(),
                sdp: "v=0\r\na=ice-pwd:hunter2hunter2hunter2hu\r\n".into(),
            },
            SignalCommand::Candidate {
                signal_id: "01JSIG".into(),
                candidate: "candidate:2 1 udp 1 198.51.100.9 5000 typ host".into(),
                mid: Some("1".into()),
                mline_index: Some(1),
            },
            SignalCommand::Failed {
                signal_id: "01JSIG".into(),
                code: "webrtc_session_ended".into(),
                message: "the camera ended the session".into(),
            },
            SignalCommand::Gone {
                signal_id: "01JSIG".into(),
            },
        ]
    }

    #[test]
    fn the_signal_messages_round_trip() {
        for report in signal_reports() {
            let message = ToSupervisor::Signal(report);
            assert_eq!(
                decode::<ToSupervisor>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
        for command in signal_commands() {
            let message = ToWorker::Signal(command);
            assert_eq!(
                decode::<ToWorker>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
    }

    #[test]
    fn rfc8839_5_4_signal_debug_shows_an_sdp_s_length_not_its_ice_password() {
        let reports: Vec<String> = signal_reports()
            .into_iter()
            .map(|report| format!("{:?}", ToSupervisor::Signal(report)))
            .collect();
        let commands: Vec<String> = signal_commands()
            .into_iter()
            .map(|command| format!("{:?}", ToWorker::Signal(command)))
            .collect();
        for text in reports.iter().chain(&commands) {
            assert!(!text.contains("hunter2"), "{text}");
        }
        assert_eq!(
            reports,
            [
                "Signal(Open { request: 1 })",
                "Signal(Cancel { request: 18446744073709551615 })",
                "Signal(Offer { signal_id: \"01JSIG\", sdp_len: 40 })",
                "Signal(Candidate { signal_id: \"01JSIG\", candidate: \"candidate:1 1 udp 2130706431 192.0.2.7 50000 typ host\", mid: Some(\"0\"), mline_index: Some(0) })",
                "Signal(Candidate { signal_id: \"01JSIG\", candidate: \"\", mid: None, mline_index: None })",
                "Signal(Closed { signal_id: \"01JSIG\", code: \"answer_timeout\", message: \"no answer within 20 s\" })",
            ]
        );
        assert_eq!(
            commands,
            [
                "Signal(Opened { request: 1, signal_id: \"01JSIG\", local_addrs: [192.0.2.7, 2001:db8::7] })",
                "Signal(Refused { request: 2, code: \"no_signaling_client\", message: \"no client relays this stream's signaling\" })",
                "Signal(Answer { signal_id: \"01JSIG\", sdp_len: 40 })",
                "Signal(Candidate { signal_id: \"01JSIG\", candidate: \"candidate:2 1 udp 1 198.51.100.9 5000 typ host\", mid: Some(\"1\"), mline_index: Some(1) })",
                "Signal(Failed { signal_id: \"01JSIG\", code: \"webrtc_session_ended\", message: \"the camera ended the session\" })",
                "Signal(Gone { signal_id: \"01JSIG\" })",
            ]
        );
    }

    /// The caps in bytes: an offer of a few KiB fits many times over, a
    /// candidate line as the control API's 1024 characters, an answer as
    /// its 64 Ki, any other text four bytes per such character.
    #[test]
    fn the_signal_caps_are_16_kib_for_an_offer_and_the_control_api_s_for_the_rest() {
        assert_eq!(MAX_SIGNAL_OFFER_BYTES, 16_384);
        assert_eq!(MAX_SIGNAL_CANDIDATE_BYTES, 1_024);
        assert_eq!(MAX_SIGNAL_SDP_BYTES, 65_536);
        assert_eq!(MAX_SIGNAL_TEXT_BYTES, 4_096);
    }

    #[test]
    fn the_longest_signal_messages_fit_a_frame() {
        let text = "x".repeat(MAX_SIGNAL_TEXT_BYTES);
        let sdp = "x".repeat(MAX_SIGNAL_SDP_BYTES);
        let messages = [
            encode(&ToSupervisor::Signal(SignalReport::Offer {
                signal_id: text.clone(),
                sdp: sdp.clone(),
            })),
            encode(&ToSupervisor::Signal(SignalReport::Candidate {
                signal_id: text.clone(),
                candidate: text.clone(),
                mid: Some(text.clone()),
                mline_index: Some(u16::MAX),
            })),
            encode(&ToWorker::Signal(SignalCommand::Answer {
                signal_id: text.clone(),
                sdp,
            })),
            encode(&ToWorker::Signal(SignalCommand::Failed {
                signal_id: text.clone(),
                code: text.clone(),
                message: text,
            })),
        ];
        for message in messages {
            assert!(message.unwrap().len() < crate::MAX_MESSAGE_BYTES);
        }
    }

    #[test]
    fn the_recording_messages_round_trip() {
        for message in [
            ToWorker::Prerecord { ms: 30_000 },
            ToWorker::Prerecord { ms: 0 },
            ToWorker::StartRecording(RecordingSpec {
                recording_id: "01JB".into(),
                prerecord_ms: 10_000,
                duration_ms: 20_000,
                audio: true,
            }),
            ToWorker::StartRecording(RecordingSpec {
                recording_id: "short".into(),
                prerecord_ms: 0,
                duration_ms: 1,
                audio: false,
            }),
            ToWorker::StopRecording {
                recording_id: "01JB".into(),
            },
        ] {
            assert_eq!(
                decode::<ToWorker>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
        for event in [
            RecordingReport::Started {
                prerecord_ms: 9_800,
                video: "h264".into(),
                picture: Some((1920, 1080)),
                audio: Some("aac_lc".into()),
            },
            RecordingReport::Started {
                prerecord_ms: 0,
                video: "h265".into(),
                picture: None,
                audio: None,
            },
            RecordingReport::Warning {
                code: "audio_omitted".into(),
                message: "pcmu does not fit an MP4".into(),
            },
            RecordingReport::Gap {
                reason: "reconnect".into(),
                from_ms: 12_040,
                to_ms: 15_310,
            },
            RecordingReport::Closed {
                reason: "completed".into(),
                bytes: 24_117_248,
                duration_ms: 29_800,
                gaps: 1,
            },
        ] {
            let message = ToSupervisor::Recording {
                recording_id: "01JB".into(),
                event,
            };
            assert_eq!(
                decode::<ToSupervisor>(&encode(&message).unwrap()).unwrap(),
                message
            );
        }
    }

    /// Every message's kind names its variant, and only that: a source's
    /// URL and a session's offer stay out of the log.
    #[test]
    fn every_message_names_its_kind_without_its_fields() {
        let source = SourceSpec {
            connection_id: "c1".into(),
            url: "rtsp://admin:hunter2@cam/main".into(),
            options: "{}".into(),
            peer_host: "cam".into(),
            peer_addrs: vec![],
            backoff: BackoffPosition::default(),
            prerecord_ms: 0,
        };
        let session = SessionSpec {
            session_id: "s1".into(),
            kind: "webrtc".into(),
            offer: "v=0".into(),
            ice_ufrag: "ufrag".into(),
            ice_pass: "p".repeat(24),
            candidates: vec![],
            tcp_candidates: vec![],
            audio: false,
            orientation: 1,
        };
        let addr: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let named = [
            (ToWorker::RunSource(source.clone()), "run_source"),
            (ToWorker::ConnectGranted, "connect_granted"),
            (ToWorker::Shutdown { deadline_ms: 1 }, "shutdown"),
            (ToWorker::Sockets, "sockets"),
            (
                ToWorker::IceTcp {
                    local_ufrag: "u".into(),
                    peer: addr,
                    first_frame: vec![],
                },
                "ice_tcp",
            ),
            (ToWorker::SwitchSource(source), "switch_source"),
            (ToWorker::Backchannel { asks: true }, "backchannel"),
            (ToWorker::SwitchConnectGranted, "switch_connect_granted"),
            (
                ToWorker::ProbeConnectGranted { probe: 1 },
                "probe_connect_granted",
            ),
            (ToWorker::OpenSession(session), "open_session"),
            (
                ToWorker::RemoteCandidate {
                    session_id: "s1".into(),
                    candidate: String::new(),
                },
                "remote_candidate",
            ),
            (
                ToWorker::Renegotiate {
                    session_id: "s1".into(),
                    sdp: "v=0".into(),
                },
                "renegotiate",
            ),
            (
                ToWorker::RelayCandidate {
                    session_id: "s1".into(),
                    relayed: addr,
                    server: addr,
                    local: addr,
                    tcp: false,
                },
                "relay_candidate",
            ),
            (
                ToWorker::RelayChannel {
                    session_id: "s1".into(),
                    relayed: addr,
                    peer: addr,
                    channel: 0x4000,
                },
                "relay_channel",
            ),
            (
                ToWorker::SessionOrientation {
                    session_id: "s1".into(),
                    orientation: 1,
                },
                "session_orientation",
            ),
            (
                ToWorker::CloseSession {
                    session_id: "s1".into(),
                    code: "gone".into(),
                    message: String::new(),
                },
                "close_session",
            ),
            (
                ToWorker::ReleaseBackchannel { session_id: None },
                "release_backchannel",
            ),
            (ToWorker::Prerecord { ms: 0 }, "prerecord"),
            (
                ToWorker::StartRecording(RecordingSpec {
                    recording_id: "k1".into(),
                    prerecord_ms: 0,
                    duration_ms: 1,
                    audio: false,
                }),
                "start_recording",
            ),
            (
                ToWorker::StopRecording {
                    recording_id: "k1".into(),
                },
                "stop_recording",
            ),
        ];
        for (message, name) in &named {
            assert_eq!(message.name(), *name, "{message:?}");
        }
    }
}
