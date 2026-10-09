//! The messages: `ToWorker` from the supervisor, `ToSupervisor` from the
//! worker. Plain data, no domain types: the supervisor validates every
//! field it uses and never treats one as a path or a command.
//!
//! Both ends are always the same binary (the supervisor re-executes
//! itself), so variants may be added freely; the wire format needs no
//! versioning.

use std::fmt;
use std::net::SocketAddr;

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
    /// follow as descriptors, in that order.
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
    /// The grant for the standby's last announced attempt.
    SwitchConnectGranted,
    /// Open a viewer session on this connection's tracks.
    OpenSession(SessionSpec),
    /// A trickle candidate from the browser; empty means end of candidates.
    RemoteCandidate {
        /// The session.
        session_id: String,
        /// The `candidate:` line.
        candidate: String,
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
/// supervisor and in the one worker that uses them; `Debug` redacts the URL.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpec {
    /// The supervisor's id for the connection, echoed in reports.
    pub connection_id: String,
    /// The full source URL, credentials included.
    pub url: String,
    /// The per-scheme options as JSON text.
    pub options: String,
    /// The host name, for the protocol URL and TLS SNI.
    pub peer_host: String,
    /// The resolved addresses to try, in order (workers have no DNS).
    pub peer_addrs: Vec<SocketAddr>,
}

impl fmt::Debug for SourceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceSpec")
            .field("connection_id", &self.connection_id)
            .field("url", &"****")
            .field("options", &self.options)
            .field("peer_host", &self.peer_host)
            .field("peer_addrs", &self.peer_addrs)
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
    /// The live source dropped; an attempt starts at once.
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
    /// Ticks per second.
    pub clock_rate: u32,
    /// `arrival` or `sender_reports`, as the connection's clock mapper has
    /// it when sent; a derived track's is its source's.
    pub sync: String,
    /// The native track a derived track is transcoded from; `None` for a
    /// native track.
    pub derived_from: Option<String>,
    /// The delay a derived track's transcoder adds, in milliseconds;
    /// `None` for a native track.
    pub audio_delay_ms: Option<u32>,
}

/// One track's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackStats {
    /// Packets published.
    pub packets: u64,
    /// Payload bytes of those packets.
    pub packet_bytes: u64,
    /// Frames accepted on the side branch.
    pub frames: u64,
    /// Payload bytes of those frames.
    pub frame_bytes: u64,
    /// Keyframes among them.
    pub keyframes: u64,
    /// Frames dropped as oversize.
    pub frames_dropped_oversize: u64,
    /// Frames the live path carried in more RTP packets than some
    /// libwebrtc receivers assemble.
    pub frames_over_browser_limit: u64,
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
            url: "rtsp://admin:hunter2@cam/main".into(),
            options: "{}".into(),
            peer_host: "cam".into(),
            peer_addrs: vec!["192.168.1.10:554".parse().unwrap()],
        };
        let text = format!("{spec:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("url: \"****\""), "{text}");
        assert!(text.contains("192.168.1.10:554"), "{text}");
        let wrapped = ToWorker::RunSource(spec);
        assert!(!format!("{wrapped:?}").contains("hunter2"));
        assert_eq!(
            decode::<ToWorker>(&encode(&wrapped).unwrap()).unwrap(),
            wrapped
        );
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
            ToSupervisor::Tracks(vec![TrackInfo {
                id: "v0".into(),
                kind: "video".into(),
                codec: "h264".into(),
                clock_rate: 90_000,
                sync: "arrival".into(),
                derived_from: None,
                audio_delay_ms: None,
            }]),
            ToSupervisor::Tracks(vec![TrackInfo {
                id: "a1".into(),
                kind: "audio".into(),
                codec: "opus".into(),
                clock_rate: 48_000,
                sync: "sender_reports".into(),
                derived_from: Some("a0".into()),
                audio_delay_ms: Some(88),
            }]),
            ToSupervisor::Stats(WorkerStats {
                tracks: vec![(
                    "v0".into(),
                    TrackStats {
                        packets: 1,
                        packet_bytes: 2,
                        frames: 3,
                        frame_bytes: 4,
                        keyframes: 5,
                        frames_dropped_oversize: 6,
                        frames_over_browser_limit: 7,
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
}
