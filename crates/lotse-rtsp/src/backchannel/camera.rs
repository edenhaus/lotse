//! The camera as the backchannel's connections reach it: the probe's and
//! each talker's session, every one on a TCP connection of its own (and
//! its TLS session for `rtsps`), through a loopback relay of its own, as
//! the session that plays the stream reaches it ([`crate::relay`]).
//!
//! The backchannel is always set up TCP interleaved, whatever the stream's
//! `transport`: retina sends on no other path, so these connections never
//! go through the UDP relay.
//!
//! Implements RFC 2326 §10.12 (interleaved data on the session's
//! connection) and RFC 7826 §19.2 (`rtsps`, through `lotse_tls`); ONVIF
//! Streaming Specification §5.3.2 (the backchannel media in the
//! `DESCRIBE` answer, the stream retina sends it on).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::Clock;
use lotse_core::source::SourceError;
use lotse_core::source_url::SourceUrl;
use lotse_tls::TlsTarget;
use retina::client::{
    Described, Session, SessionGroup, SessionOptions, StreamDirection, TeardownPolicy,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use super::session::{Offer, offer};
use crate::framer::MAX_MESSAGE;
use crate::options::RtspOptions;
use crate::relay::{self, Listener, Listening, Media};
use crate::rtcp::{ReceiverReports, Seed, SetupRates};
use crate::source::{credentials, within_on};

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
    /// Where the relays listen.
    pub(crate) relay: Listener,
    /// The camera's address, the one the source's attempt connects to.
    pub(crate) addr: SocketAddr,
    /// The clock of the deadlines.
    pub(crate) time: Arc<dyn Clock>,
}

/// A connection to the camera, plain TCP or TLS over it.
pub(crate) trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A connection to the camera with its relay ready for retina: the
/// camera's side, the relay's listener, and the URL retina connects to.
pub(crate) type Connected = (Box<dyn Duplex>, Listening, url::Url);

impl Camera {
    /// The source's read deadline (`timeout_ms`).
    pub(crate) const fn deadline(&self) -> Duration {
        Duration::from_millis(self.options.timeout_ms)
    }

    /// The retina session options of a backchannel connection: the
    /// source's credentials and user agent, the ONVIF backchannel asked
    /// for (retina's `Require` header on its `DESCRIBE`, and on the
    /// `SETUP`, `PLAY` and `TEARDOWN` of its backchannel), and the
    /// `TEARDOWN` of a dropped session awaited in `group`.
    pub(crate) fn session_options(&self, group: &Arc<SessionGroup>) -> SessionOptions {
        SessionOptions::default()
            .creds(credentials(&self.url))
            .user_agent(self.options.user_agent().to_owned())
            .teardown(TeardownPolicy::Auto)
            .max_message_size(MAX_MESSAGE)
            .session_group(Arc::clone(group))
            .backchannel(true)
    }

    /// Connects to the camera (TCP, then the TLS handshake for `rtsps`)
    /// and takes a relay listener, within `deadline` and until `cancel`;
    /// `what` names the connection in the log and the error.
    pub(crate) async fn connect(
        &self,
        what: &str,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> Result<Connected, SourceError> {
        let addr = self.addr;
        tracing::info!(%addr, tls = self.tls.is_some(), what, "rtsp: connecting");
        let connected = within_on(&*self.time, cancel, deadline, what, async {
            let tcp = relay::tcp(addr).await?;
            let stream: Box<dyn Duplex> = match &self.tls {
                None => Box::new(tcp),
                Some(tls) => Box::new(lotse_tls::connect(tcp, tls, &[]).await?),
            };
            let (listening, local) = relay::listen(&self.relay).await?;
            Ok((stream, listening, relay::relay_url(&self.url, local)))
        })
        .await;
        connected.map_err(|err| err.scrubbed(&self.url))
    }

    /// Runs `session`, retina's side, beside the relay between retina and
    /// `stream`, interleaved: the session's output, or why the relay ended
    /// first. The connection closes when it returns.
    pub(crate) async fn relayed<T>(
        &self,
        stream: Box<dyn Duplex>,
        listening: Listening,
        session: impl Future<Output = T>,
    ) -> Result<T, SourceError> {
        let reports = ReceiverReports::new(Arc::new(SetupRates::default()), Seed::random());
        let media = Media::Interleaved(reports, Arc::clone(&self.time));
        let pump = relay::pump(listening, stream, media);
        relay::beside(pump, session).await.session()
    }
}

/// The camera's backchannel in the `DESCRIBE` answer `session` holds
/// (ONVIF Streaming Specification §5.3.2): the media [`offer`] finds in
/// the raw SDP, and the retina stream that sends on it, the one whose
/// direction is `Sending` with that media's first payload type (RFC 8866
/// §5.14), since retina's stream indices skip media it cannot parse.
/// `None` when there is none.
pub(crate) fn backchannel_stream(session: &Session<Described>) -> Option<(usize, Offer)> {
    let offer = offer(session.sdp())?;
    let index = session.streams().iter().position(|stream| {
        stream.direction() == StreamDirection::Sending
            && stream.rtp_payload_type() == offer.first_payload_type
    });
    if index.is_none() {
        tracing::info!(
            media = offer.media,
            payload_type = offer.first_payload_type,
            "rtsp: no stream retina sends on has the backchannel's payload type; no backchannel"
        );
    }
    index.map(|index| (index, offer))
}
