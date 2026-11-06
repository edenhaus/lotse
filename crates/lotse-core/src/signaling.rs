//! The contract by which a source whose signaling the control-API client
//! relays opens one signaling channel per connection attempt.
//!
//! A WebRTC camera behind a cloud (Nest, Ring, Matter) is reached only
//! through its integration in the client: lotse makes the offer, the client
//! hands it to the camera and relays the camera's answer, candidates and
//! errors back. Core knows nothing of SDP or ICE: it carries opaque
//! strings. The source opens a [`SignalingChannel`] through the
//! [`SignalingOpener`] in its context ([`crate::source::SourceCtx::signaling`])
//! at each attempt, sends its offer and candidates on it, reads the answer,
//! candidates and failures from it, and closes it with a code when the
//! attempt ends; a dropped channel closes as [`close::SOURCE_STOPPED`]. The
//! opener's side of the same channel is its [`SignalingRelay`], made with it
//! by [`channel`]. Both directions are bounded.
//!
//! Standards: RFC 8829 (JSEP) for the offer/answer exchange the channel
//! carries (lotse is the offerer); RFC 8838 (Trickle ICE) for candidates
//! that follow the offer and the end-of-candidates indication; W3C WebRTC
//! 1.0's `RTCIceCandidateInit` (`candidate`, `sdpMid`, `sdpMLineIndex`),
//! the shape the client relays a candidate in.

use std::fmt;
use std::net::IpAddr;

use tokio::sync::{mpsc, oneshot};

use crate::task::BoxFuture;

/// Signals a source may have queued toward the client before it waits for
/// the relay to take one: an offer and its candidates, one per local
/// address and the end-of-candidates indication, fit many times over.
pub const OUTGOING_CAPACITY: usize = 32;

/// Signals the relay may have queued toward the source before it must
/// wait: the answer, the client's candidates (at most 64 per signal) and a
/// failure. A relay that cannot queue one ends the signal.
pub const INCOMING_CAPACITY: usize = 64;

/// The codes a source closes its signaling channel with
/// ([`SignalingChannel::close`]): the source side of the control API's
/// `SignalCloseCode`, which the supervisor maps the worker's untrusted
/// string onto. Each is lowercase ASCII, digits and `_`.
pub mod close {
    /// The source stopped: its attempt was cancelled, or the channel was
    /// dropped without a code.
    pub const SOURCE_STOPPED: &str = "source_stopped";
    /// The client relayed no answer in time.
    pub const ANSWER_TIMEOUT: &str = "answer_timeout";
    /// The answer could not be applied to the offer.
    pub const INVALID_ANSWER: &str = "invalid_answer";
    /// No candidate pair connected in time.
    pub const ICE_FAILED: &str = "ice_failed";
    /// The peer stopped consenting to receive (RFC 7675).
    pub const CONSENT_LOST: &str = "consent_lost";
    /// The peer closed the connection (a DTLS `close_notify`).
    pub const PEER_CLOSED: &str = "peer_closed";
    /// The camera ended the signal with an error, relayed by the client.
    pub const CAMERA_ERROR: &str = "camera_error";
    /// The client relaying the signal went away.
    pub const SIGNALING_LOST: &str = "signaling_lost";
}

/// One ICE candidate as the client relays it, the fields of W3C WebRTC
/// 1.0's `RTCIceCandidateInit`. An empty `candidate` is the
/// end-of-candidates indication (RFC 8838 §13): no candidate follows it
/// for that media section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalCandidate {
    /// The candidate attribute as `RTCIceCandidateInit` carries it,
    /// `candidate:` and its value (RFC 8839 §5.1) without `a=`; empty for
    /// the end-of-candidates indication.
    pub candidate: String,
    /// The `a=mid` of the media section it belongs to (RFC 8843 §7.1),
    /// if the sender named it.
    pub sdp_mid: Option<String>,
    /// The index of the media section it belongs to, 0 for the first,
    /// if the sender named it. A source always names it on its own
    /// candidates: some cameras' integrations need it.
    pub sdp_mline_index: Option<u16>,
}

impl SignalCandidate {
    /// The end-of-candidates indication (RFC 8838 §13) for the media
    /// section `sdp_mid`, `sdp_mline_index`: an empty candidate.
    pub const fn end_of_candidates(sdp_mid: Option<String>, sdp_mline_index: Option<u16>) -> Self {
        Self {
            candidate: String::new(),
            sdp_mid,
            sdp_mline_index,
        }
    }

    /// Whether it is the end-of-candidates indication: an empty candidate.
    pub const fn is_end_of_candidates(&self) -> bool {
        self.candidate.is_empty()
    }
}

/// What a source sends the client on its channel.
#[derive(Clone, PartialEq, Eq)]
pub enum LocalSignal {
    /// The SDP offer (RFC 8829 §5.2), first and once. `Debug` shows its
    /// length only: it carries the ICE password (RFC 8839 §5.4).
    Offer(String),
    /// A local candidate trickled after the offer (RFC 8838 §8), or the
    /// end-of-candidates indication, last.
    Candidate(SignalCandidate),
}

impl fmt::Debug for LocalSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offer(sdp) => f.debug_struct("Offer").field("len", &sdp.len()).finish(),
            Self::Candidate(candidate) => f.debug_tuple("Candidate").field(candidate).finish(),
        }
    }
}

/// What the client relays to a source on its channel.
#[derive(Clone, PartialEq, Eq)]
pub enum RemoteSignal {
    /// The camera's SDP answer to the offer (RFC 8829 §5.3). `Debug`
    /// shows its length only: it carries the camera's ICE password.
    Answer(String),
    /// A candidate of the camera's, trickled (RFC 8838 §10), or its
    /// end-of-candidates indication.
    Candidate(SignalCandidate),
    /// The camera or its integration ended the signal with an error:
    /// nothing follows it.
    Failed {
        /// The client's error code, untrusted text.
        code: String,
        /// What happened, for humans.
        message: String,
    },
}

impl fmt::Debug for RemoteSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Answer(sdp) => f.debug_struct("Answer").field("len", &sdp.len()).finish(),
            Self::Candidate(candidate) => f.debug_tuple("Candidate").field(candidate).finish(),
            Self::Failed { code, message } => f
                .debug_struct("Failed")
                .field("code", code)
                .field("message", message)
                .finish(),
        }
    }
}

/// How a channel was closed, as its relay learns it
/// ([`SignalClosed::wait`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalClose {
    /// One of [`close`]'s codes.
    pub code: &'static str,
    /// What happened, for humans.
    pub message: String,
}

impl SignalClose {
    /// The close of a channel dropped without a code.
    fn stopped() -> Self {
        Self {
            code: close::SOURCE_STOPPED,
            message: "the source stopped".to_owned(),
        }
    }
}

/// Why an opener could not open a channel: the code (`no_signaling_client`
/// when no client relays the source's signaling) and what happened. The
/// source's attempt ends unreachable with it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct SignalingRefused {
    /// The refusal's code.
    pub code: String,
    /// What happened, for humans.
    pub message: String,
}

/// Opens a signaled source's signaling channel, one per connection attempt
/// (in the worker: through the supervisor to the control-API client that
/// relays the source's signaling).
pub trait SignalingOpener: fmt::Debug + Send + Sync {
    /// Opens a channel: resolves once the relay took it, or with why not.
    /// Dropping the future before it resolves abandons the open.
    fn open(&self) -> BoxFuture<'static, Result<SignalingChannel, SignalingRefused>>;
}

/// A source's end of one signaling channel, for one connection attempt.
/// Close it with [`SignalingChannel::close`] and the code of why the
/// attempt ended; dropped instead, the relay learns
/// [`close::SOURCE_STOPPED`]. The fields may be moved out one by one; the
/// channel closes once its private closer is dropped or used.
#[derive(Debug)]
pub struct SignalingChannel {
    /// The signal's id, unique to this channel; for logs.
    pub id: String,
    /// The local addresses the source may gather host candidates on,
    /// enumerated before the worker was sandboxed.
    pub local_addrs: Vec<IpAddr>,
    /// Where the offer and the local candidates go, in the order sent.
    pub outgoing: mpsc::Sender<LocalSignal>,
    /// The answer, the camera's candidates and a failure, in the order
    /// relayed; `None` once the client is gone, when nothing more comes.
    pub incoming: mpsc::Receiver<RemoteSignal>,
    /// Tells the relay how the channel was closed; dropped unused, the
    /// relay takes it as [`close::SOURCE_STOPPED`].
    closer: oneshot::Sender<SignalClose>,
}

impl SignalingChannel {
    /// Closes the channel with `code`, one of [`close`]'s, and `message`,
    /// what happened: the relay ends the signal with them.
    pub fn close(self, code: &'static str, message: String) {
        tracing::debug!(signal = %self.id, code, detail = %message, "signaling channel closed by its source");
        // A relay that is gone has nobody to tell.
        let _relay_gone = self.closer.send(SignalClose { code, message });
    }
}

/// The opener's end of a signaling channel: it relays what the source
/// sends to the client and what the client sends back. Read `outgoing`
/// ahead of `closed` (a `biased` select), so every signal the source sent
/// before its close is relayed before the close.
#[derive(Debug)]
pub struct SignalingRelay {
    /// The signal's id, the channel's.
    pub id: String,
    /// The source's offer and candidates.
    pub outgoing: mpsc::Receiver<LocalSignal>,
    /// Where the client's answer, candidates and failure go; dropped, the
    /// source learns the client is gone. A full queue is the relay's to
    /// handle: it ends the signal.
    pub incoming: mpsc::Sender<RemoteSignal>,
    /// How the source closed the channel.
    pub closed: SignalClosed,
}

/// Resolves with how the source closed its channel ([`SignalClosed::wait`]).
#[derive(Debug)]
pub struct SignalClosed(oneshot::Receiver<SignalClose>);

impl SignalClosed {
    /// How the source closed its channel, once it did: with its code, or
    /// [`close::SOURCE_STOPPED`] once the channel was dropped.
    pub async fn wait(self) -> SignalClose {
        self.0
            .await
            .unwrap_or_else(|_dropped| SignalClose::stopped())
    }
}

/// A signaling channel `id` whose source may gather on `local_addrs`: the
/// source's end, handed out by the opener, and the relay's, which the
/// opener keeps. Both directions are bounded ([`OUTGOING_CAPACITY`],
/// [`INCOMING_CAPACITY`]).
pub fn channel(id: String, local_addrs: Vec<IpAddr>) -> (SignalingChannel, SignalingRelay) {
    let (outgoing, outgoing_rx) = mpsc::channel(OUTGOING_CAPACITY);
    let (incoming_tx, incoming) = mpsc::channel(INCOMING_CAPACITY);
    let (closer, on_close) = oneshot::channel();
    let relay = SignalingRelay {
        id: id.clone(),
        outgoing: outgoing_rx,
        incoming: incoming_tx,
        closed: SignalClosed(on_close),
    };
    let channel = SignalingChannel {
        id,
        local_addrs,
        outgoing,
        incoming,
        closer,
    };
    (channel, relay)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::net::Ipv4Addr;

    use super::*;

    fn host() -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
    }

    fn candidate(value: &str) -> SignalCandidate {
        SignalCandidate {
            candidate: value.to_owned(),
            sdp_mid: Some("0".to_owned()),
            sdp_mline_index: Some(0),
        }
    }

    #[tokio::test]
    async fn a_channel_carries_signals_both_ways_in_order_and_its_close() {
        let (mut channel, mut relay) = channel("sig-1".to_owned(), host());
        assert_eq!(channel.id, "sig-1");
        assert_eq!(relay.id, "sig-1");
        assert_eq!(channel.local_addrs, host());

        let host_candidate = candidate("candidate:1 1 udp 2130706431 192.0.2.7 9 typ host");
        channel
            .outgoing
            .send(LocalSignal::Offer("v=0 offer".to_owned()))
            .await
            .unwrap();
        channel
            .outgoing
            .send(LocalSignal::Candidate(host_candidate.clone()))
            .await
            .unwrap();
        assert_eq!(
            relay.outgoing.recv().await,
            Some(LocalSignal::Offer("v=0 offer".to_owned()))
        );
        assert_eq!(
            relay.outgoing.recv().await,
            Some(LocalSignal::Candidate(host_candidate))
        );

        let failed = RemoteSignal::Failed {
            code: "webrtc_offer_failed".to_owned(),
            message: "the camera said no".to_owned(),
        };
        for signal in [
            RemoteSignal::Answer("v=0 answer".to_owned()),
            RemoteSignal::Candidate(candidate("candidate:2 1 udp 1 192.0.2.9 5000 typ host")),
            failed.clone(),
        ] {
            relay.incoming.send(signal).await.unwrap();
        }
        assert_eq!(
            channel.incoming.recv().await,
            Some(RemoteSignal::Answer("v=0 answer".to_owned()))
        );
        assert!(matches!(
            channel.incoming.recv().await,
            Some(RemoteSignal::Candidate(_))
        ));
        assert_eq!(channel.incoming.recv().await, Some(failed));

        channel.close(close::CAMERA_ERROR, "webrtc_offer_failed".to_owned());
        assert_eq!(
            relay.closed.wait().await,
            SignalClose {
                code: close::CAMERA_ERROR,
                message: "webrtc_offer_failed".to_owned(),
            }
        );
        // The source's end is gone with its close.
        assert_eq!(relay.outgoing.recv().await, None);
    }

    #[tokio::test]
    async fn a_dropped_channel_closes_as_source_stopped() {
        let (channel, relay) = channel("sig-2".to_owned(), vec![]);
        drop(channel);
        assert_eq!(
            relay.closed.wait().await,
            SignalClose {
                code: close::SOURCE_STOPPED,
                message: "the source stopped".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn a_channel_whose_fields_were_moved_out_closes_once_the_rest_is_dropped() {
        let (channel, relay) = channel("sig-3".to_owned(), host());
        let incoming = {
            let channel = channel;
            channel.incoming
        };
        assert_eq!(relay.closed.wait().await.code, close::SOURCE_STOPPED);
        drop(incoming);
    }

    #[tokio::test]
    async fn the_source_learns_the_client_is_gone_once_the_relay_drops_its_sender() {
        let (mut channel, relay) = channel("sig-4".to_owned(), host());
        drop(relay);
        assert_eq!(channel.incoming.recv().await, None);
        // A close toward a relay that is gone is no error.
        channel.close(close::SIGNALING_LOST, "the client is gone".to_owned());
    }

    #[tokio::test]
    async fn both_directions_are_bounded() {
        let (channel, relay) = channel("sig-5".to_owned(), host());
        for _ in 0..OUTGOING_CAPACITY {
            channel
                .outgoing
                .try_send(LocalSignal::Offer(String::new()))
                .unwrap();
        }
        assert!(
            channel
                .outgoing
                .try_send(LocalSignal::Offer(String::new()))
                .is_err()
        );
        for _ in 0..INCOMING_CAPACITY {
            relay
                .incoming
                .try_send(RemoteSignal::Answer(String::new()))
                .unwrap();
        }
        assert!(
            relay
                .incoming
                .try_send(RemoteSignal::Answer(String::new()))
                .is_err()
        );
    }

    #[test]
    fn an_empty_candidate_is_end_of_candidates_rfc8838_section_13() {
        let end = SignalCandidate::end_of_candidates(Some("0".to_owned()), Some(0));
        assert!(end.is_end_of_candidates());
        assert_eq!(end.candidate, "");
        assert_eq!(end.sdp_mid.as_deref(), Some("0"));
        assert_eq!(end.sdp_mline_index, Some(0));
        assert!(!candidate("candidate:1 1 udp 1 192.0.2.7 9 typ host").is_end_of_candidates());
    }

    #[test]
    fn debug_shows_an_offers_and_an_answers_length_not_their_ice_password_rfc8839_section_5_4() {
        let sdp = "v=0\r\na=ice-pwd:asd88fgpdd777uzjYhagZg\r\n".to_owned();
        let offer = format!("{:?}", LocalSignal::Offer(sdp.clone()));
        let answer = format!("{:?}", RemoteSignal::Answer(sdp.clone()));
        assert_eq!(offer, format!("Offer {{ len: {} }}", sdp.len()));
        assert_eq!(answer, format!("Answer {{ len: {} }}", sdp.len()));
        let local = format!("{:?}", LocalSignal::Candidate(candidate("candidate:x")));
        let remote = format!("{:?}", RemoteSignal::Candidate(candidate("candidate:y")));
        assert!(local.starts_with("Candidate(SignalCandidate { candidate: \"candidate:x\""));
        assert!(remote.starts_with("Candidate(SignalCandidate { candidate: \"candidate:y\""));
        let failed = RemoteSignal::Failed {
            code: "camera_offline".to_owned(),
            message: "offline".to_owned(),
        };
        assert_eq!(
            format!("{failed:?}"),
            "Failed { code: \"camera_offline\", message: \"offline\" }"
        );
    }

    #[test]
    fn a_refusal_shows_its_code_and_message() {
        let refused = SignalingRefused {
            code: "no_signaling_client".to_owned(),
            message: "no client relays this stream's signaling".to_owned(),
        };
        assert_eq!(
            refused.to_string(),
            "no_signaling_client: no client relays this stream's signaling"
        );
    }

    #[test]
    fn close_codes_are_the_apis_lowercase_identifiers() {
        let codes = [
            close::SOURCE_STOPPED,
            close::ANSWER_TIMEOUT,
            close::INVALID_ANSWER,
            close::ICE_FAILED,
            close::CONSENT_LOST,
            close::PEER_CLOSED,
            close::CAMERA_ERROR,
            close::SIGNALING_LOST,
        ];
        for code in codes {
            assert!(
                !code.is_empty()
                    && code.len() <= 64
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{code}"
            );
        }
        let mut unique = codes.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len());
    }
}
