//! The camera as the backchannel's connections reach it: the probe's and
//! each talker's session, every one on a TCP connection of its own (and
//! its TLS session for `rtsps`), dialed as the source dials its own
//! ([`Dialer`]), with retina's sans-I/O core driven on it
//! ([`crate::driver`]).
//!
//! The backchannel is always set up TCP interleaved, whatever the stream's
//! `transport`: retina sends on no other path. Its requests carry the
//! source URL itself as their Request-URI (RFC 2326 §6.1, RFC 7826 §19.2),
//! `rtsps` included, credentials left out (RFC 2326 §10.2).
//!
//! Implements RFC 2326 §10.12 (interleaved data on the session's
//! connection), §10.7 (the `TEARDOWN` of a session, within the source's
//! budget) and RFC 7826 §19.2 (`rtsps`, through `lotse_tls`); ONVIF
//! Streaming Specification §5.3.1 (the `Require` header retina sends on
//! these connections) and §5.3.2 (the backchannel media in the `DESCRIBE`
//! answer, the stream retina sends it on).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::Clock;
use lotse_core::source::SourceError;
use lotse_core::source_url::SourceUrl;
use lotse_tls::TlsTarget;
use retina::client::{SessionOptions, StreamDirection, TeardownPolicy};
use tokio_util::sync::CancellationToken;

use super::session::{Candidate, Offer, offer};
use crate::driver::Driver;
use crate::framer::MAX_MESSAGE;
use crate::options::RtspOptions;
use crate::relay::Listener;
use crate::source::{Dialer, TEARDOWN, credentials, within_on};

/// The camera of one source, as its backchannel's connections reach it.
/// Cloned into the probe and the opener; holds no connection itself.
#[derive(Debug, Clone)]
pub(crate) struct Camera {
    /// The source URL, credentials inside.
    pub(crate) url: SourceUrl,
    /// The source's options: its read deadline and user agent.
    pub(crate) options: RtspOptions,
    /// For `rtsps`: the server name and the certificate check.
    pub(crate) tls: Option<TlsTarget>,
    /// Where the relays of the source's `transport: "udp"` attempts
    /// listen; the backchannel's connections take none.
    pub(crate) relay: Listener,
    /// The camera's address, the one the source's attempt connects to.
    pub(crate) addr: SocketAddr,
    /// The clock of the deadlines.
    pub(crate) time: Arc<dyn Clock>,
}

impl Camera {
    /// The source's read deadline (`timeout_ms`).
    pub(crate) const fn deadline(&self) -> Duration {
        Duration::from_millis(self.options.timeout_ms)
    }

    /// The retina session options of a backchannel connection: the
    /// source's credentials and user agent, the most bytes of an RTSP
    /// message it reads, the `TEARDOWN` of a session it set up (retina's
    /// `Auto` policy), and the ONVIF backchannel asked for (retina's
    /// `Require` header on its `DESCRIBE`, and on the `SETUP`, `PLAY` and
    /// `TEARDOWN` of its backchannel, ONVIF Streaming Specification
    /// §5.3.1).
    pub(crate) fn session_options(&self) -> SessionOptions {
        SessionOptions::default()
            .creds(credentials(&self.url))
            .user_agent(self.options.user_agent().to_owned())
            .teardown(TeardownPolicy::Auto)
            .max_message_size(MAX_MESSAGE)
            .backchannel(true)
    }

    /// How the backchannel's connections dial the camera: as the source
    /// dials its own.
    fn dialer(&self) -> Dialer {
        Dialer {
            addr: self.addr,
            tls: self.tls.clone(),
        }
    }

    /// The Request-URI of the backchannel's `DESCRIBE`: the source URL
    /// itself, credentials left out (RFC 2326 §6.1, §10.2; RFC 7826
    /// §19.2).
    pub(crate) fn target(&self) -> url::Url {
        self.url.expose_url().clone()
    }

    /// Connects to the camera (TCP, then the TLS handshake for `rtsps`),
    /// within `deadline` and until `cancel`, and hands the connection to
    /// a fresh retina session; `what` names the connection in the log and
    /// the error, which is scrubbed of the URL.
    pub(crate) async fn connect(
        &self,
        what: &str,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> Result<Driver, SourceError> {
        let addr = self.addr;
        tracing::info!(%addr, tls = self.tls.is_some(), what, "rtsp: connecting");
        let dialed = within_on(&*self.time, cancel, deadline, what, self.dialer().dial()).await;
        let conn = dialed.map_err(|err| err.scrubbed(&self.url))?;
        Ok(Driver::new(
            conn,
            self.session_options(),
            Arc::clone(&self.time),
        ))
    }

    /// Ends `driver`'s session on the camera (RFC 2326 §10.7), its
    /// `TEARDOWN` with `Require` when the backchannel was set up, within
    /// the budget the source's own session has ([`TEARDOWN`]): retries go
    /// on fresh connections dialed as the first was, when retina's policy
    /// makes them. The connection closes when it returns, as a camera may
    /// stay in two-way mode until it does. `why` is the session's end, for
    /// the log. Nothing cuts the budget short: the claim's close that
    /// usually precedes it is the session's normal end, not a deadline,
    /// and the next claim's session waits for this one to close on the
    /// camera (`BackchannelTasks`); the worker's shutdown bounds its own
    /// wait for the task.
    pub(crate) async fn tear_down(&self, driver: Driver, why: &(dyn std::fmt::Display + Sync)) {
        let dialer = self.dialer();
        let dial = || dialer.boxed();
        tracing::debug!(%why, "rtsp: tearing the backchannel session down");
        // No cancellation applies to the backchannel's teardown: a token
        // nobody holds never fires.
        driver
            .teardown(&dial, TEARDOWN, &CancellationToken::new())
            .await;
    }
}

/// The camera's backchannel in the `DESCRIBE` answer `driver` holds (ONVIF
/// Streaming Specification §5.3.2): the media [`offer`] finds in the raw
/// SDP, and the retina stream that sends on it ([`Offer::stream`], from
/// each stream's direction, payload type and control URL: the one at that
/// media's index, whose direction is `Sending` with that media's first
/// payload type, RFC 8866 §5.14; when retina skipped media, the one on
/// that media's control URL, RFC 2326 §C.3), not merely the first such
/// stream, which another media could carry. `None` when there is none, or
/// the mapping is uncertain.
pub(crate) fn backchannel_stream(driver: &Driver) -> Option<(usize, Offer)> {
    let offer = offer(driver.sdp())?;
    let streams: Vec<Candidate<'_>> = driver
        .streams()
        .iter()
        .map(|stream| Candidate {
            sending: stream.direction() == StreamDirection::Sending,
            payload_type: stream.rtp_payload_type(),
            control: stream.control().map(url::Url::as_str),
        })
        .collect();
    let index = offer.stream(&streams);
    if index.is_none() {
        tracing::info!(
            media = offer.media,
            payload_type = offer.first_payload_type,
            "rtsp: no stream retina sends on carries the backchannel's media; no backchannel"
        );
    }
    index.map(|index| (index, offer))
}
