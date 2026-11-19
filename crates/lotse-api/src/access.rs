//! What a TLS client's role reaches. A `metrics` client
//! ([`ClientRole::Metrics`]) may read `GET /v0/metrics` and nothing else:
//! every other route that exists, the WebSocket upgrade and a recording's
//! bytes included and whatever the method, is refused before its handler
//! runs with 403 `not_permitted` (RFC 9110 §15.5.4: the client presented
//! credentials, and they do not grant this), in the error body of every
//! other refusal. A path no route has is 404 for every client, as the
//! router answers it; a pairing connection never reaches the router. A
//! `control` client and a peer on the Unix socket pass, and so does a TLS
//! client removed since its handshake: each route refuses that one itself
//! (the upgrade closes it at once, a recording is refused 403).
//!
//! The role is looked up in the client store on every request, never taken
//! from the certificate, which the client made itself. A refusal is a
//! decision, logged as a warning with the pin and the route's template
//! (fixed in the code, never the path the client sent), throttled per pin
//! ([`lotse_core::throttle`]): an authenticated client can repeat it.
//!
//! Standards: RFC 9110 §15.5.4 (403 Forbidden), §15.5.5 (404 Not Found).

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use lotse_api_types::clients::ClientRole;
use lotse_api_types::error::ErrorCode;
use lotse_core::fingerprint::Fingerprint;
use lotse_core::throttle::CallSites;

use crate::clients::ClientStore;
use crate::connection::refuse;
use crate::listener::PeerInfo;

/// The rate limits of the refusals' warnings, one per pin: only an
/// enrolled or fixed `metrics` pin is ever counted, so the map stays as
/// small as the client list.
pub(crate) type RefusalLines = CallSites<Fingerprint>;

/// The check of one route that only a `control` client may take.
#[derive(Clone)]
pub(crate) struct ControlOnly {
    /// The TLS listener's clients, whose roles decide; `None` without a
    /// listener, when every peer is on the socket.
    pub(crate) clients: Option<Arc<ClientStore>>,
    /// The rate limits of the refusals' warnings.
    pub(crate) lines: Arc<RefusalLines>,
    /// The route's template, as the router has it, for the log.
    pub(crate) route: &'static str,
}

impl ControlOnly {
    /// The refusal of `peer`'s request, when `peer` is a TLS client whose
    /// pin has the `metrics` role; `None` lets the request through. Not
    /// generic over anything, so every route shares it.
    fn refusal(&self, peer: &PeerInfo) -> Option<Response> {
        let PeerInfo::Tls { pin, .. } = peer else {
            return None;
        };
        let clients = self.clients.as_deref()?;
        if clients.role(pin) != Some(ClientRole::Metrics) {
            return None;
        }
        if let Some(refused) = self.lines.hit(*pin) {
            tracing::warn!(
                %peer,
                client_pin = %pin,
                route = self.route,
                refused,
                "request refused: a metrics client may only read GET /v0/metrics"
            );
        }
        Some(refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::NotPermitted,
            "a metrics client may only read GET /v0/metrics",
        ))
    }
}

/// The layer of a route only a `control` client may take: `check`'s
/// refusal, or the route.
pub(crate) async fn control_only(
    State(check): State<ControlOnly>,
    Extension(peer): Extension<PeerInfo>,
    request: Request,
    next: Next,
) -> Response {
    match check.refusal(&peer) {
        Some(refusal) => refusal,
        None => next.run(request).await,
    }
}
