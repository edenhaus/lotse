//! One-time pairing for the control TLS listener: a client is enrolled by
//! pasting a code once, instead of pins being copied both ways by hand.
//!
//! The code is `LOTSE1-<server pin>-<secret>`: the SHA-256 of the daemon's
//! certificate and a 128-bit random secret, each as lowercase hex. The
//! client compares the pin with the certificate it fetches before the
//! secret leaves it, and connects with mutual TLS presenting a certificate
//! of its own, so the secret only ever reaches the real daemon and only
//! inside an authenticated, encrypted connection. While a code is open the
//! listener lets an unknown client certificate through its handshake (the
//! handshake signature is still verified), and such a connection can make
//! exactly one request, `POST /v1/pair` with the secret. A match enrolls the
//! pin of the certificate the handshake proved, never one the request
//! names, closes the code and the connection; the client reconnects as an
//! enrolled one.
//!
//! At most one code is open, for [`CODE_LIFETIME`] on the injected clock,
//! and only in memory. A new one replaces it. A wrong secret leaves it open:
//! a 128-bit secret cannot be guessed online, and closing the code would
//! only let anyone stop the pairing. A matching secret takes the code out
//! while the pin is stored, so no second request can use it and nothing
//! waits on the disk for the lock the handshakes read; a failed store puts
//! it back, unless a new code replaced it meanwhile. The store runs to its
//! end even when its connection is closed first, and the connection's
//! admission lasts until then; one whose connection closed before it began
//! stores nothing. While no client is enrolled the daemon logs a code at
//! startup; that is the one secret it ever logs, and it is useless once
//! used or expired.
//!
//! Standards: RFC 9110 §9.3.3 (`POST`), §15.3.5 (204), §15.5.1 (400),
//! §15.5.4 (403), §15.5.11 (410), §15.6.1 (500); RFC 8259 (the JSON body);
//! RFC 8446 §4.4.2 (the certificate the enrolled pin is taken from).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::pairing::PairingCreateResult;
use lotse_core::clock::Clock;
use lotse_core::fingerprint::Fingerprint;
use lotse_core::secret::Secret;
use lotse_core::task::spawn_blocking_named;
use lotse_core::task::spawn_named;
use rustls::crypto::SecureRandom;
use serde::Deserialize;
use subtle::ConstantTimeEq as _;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::clients::ClientStore;
use crate::{MAX_UPGRADE_HEADER_BYTES, MAX_UPGRADE_HEADERS};

/// How long a code stays valid: 10 minutes.
pub const CODE_LIFETIME: Duration = Duration::from_secs(600);

/// The code's first part, which names its format.
pub const CODE_PREFIX: &str = "LOTSE1";

/// Where a pairing connection sends the secret.
pub const PAIR_PATH: &str = "/v1/pair";

/// The largest pairing request body: 256 bytes, several times
/// `{"secret":"<32 hex digits>"}`. A longer one is answered 413.
pub const MAX_PAIR_REQUEST_BYTES: usize = 256;

/// From the end of the handshake to the end of the pairing request: 3 s,
/// within the pre-authentication budget the handshake held.
pub const PAIR_TIMEOUT: Duration = Duration::from_secs(3);

/// The secret's length: 128 bits.
const SECRET_BYTES: usize = 16;

/// A code's secret, which never prints.
type SecretBytes = Secret<[u8; SECRET_BYTES]>;

/// The open code.
struct OpenCode {
    /// What the client must send.
    secret: SecretBytes,
    /// When it stops working.
    expires: Instant,
}

/// The code slot, with a count of the codes opened so far: a redemption
/// that took the code out puts it back only if no code was opened since.
#[derive(Default)]
struct Slot {
    /// The open code, if any.
    open: Option<OpenCode>,
    /// Codes opened, wrapping.
    generation: u64,
}

/// The pairing state: at most one open code.
pub(crate) struct Pairing {
    /// The open code. Its lock is only ever held to look at or change the
    /// slot, never across storing a pin: the TLS verifier reads it on the
    /// runtime's threads.
    slot: Mutex<Slot>,
    /// The daemon's pin, the code's first part.
    server_pin: Fingerprint,
    /// Times the code's lifetime.
    clock: Arc<dyn Clock>,
    /// Draws the secrets.
    random: &'static dyn SecureRandom,
}

impl fmt::Debug for Pairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pairing")
            .field("server_pin", &self.server_pin)
            .finish_non_exhaustive()
    }
}

/// A code just opened. `Debug` redacts the secret; [`PairingCode::reveal`]
/// spells it out for the one place it goes.
#[derive(Debug, Clone)]
pub(crate) struct PairingCode {
    /// The daemon's pin.
    server_pin: Fingerprint,
    /// The secret.
    secret: SecretBytes,
}

impl PairingCode {
    /// `LOTSE1-<server pin>-<secret>`, both lowercase hex.
    pub(crate) fn reveal(&self) -> String {
        format!(
            "{CODE_PREFIX}-{}-{}",
            self.server_pin.to_hex(),
            hex(self.secret.expose_secret())
        )
    }

    /// The result of `pairing/create`.
    pub(crate) fn result(&self) -> PairingCreateResult {
        PairingCreateResult {
            code: self.reveal(),
            expires_in_ms: u64::try_from(CODE_LIFETIME.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect()
}

/// How a pairing request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Redeemed {
    /// The pin is enrolled and the code closed.
    Enrolled,
    /// The secret is not the open code's; the code stays open.
    WrongSecret,
    /// No code is open: it expired, or another client used it or is
    /// using it.
    NoCode,
    /// The connection closed before the request's turn: nothing was
    /// tried.
    Abandoned,
}

impl Pairing {
    /// No code open yet, for the daemon with pin `server_pin`.
    pub(crate) fn new(
        server_pin: Fingerprint,
        clock: Arc<dyn Clock>,
        random: &'static dyn SecureRandom,
    ) -> Self {
        Self {
            slot: Mutex::default(),
            server_pin,
            clock,
            random,
        }
    }

    /// The slot, under the lock; a poisoned lock is still usable.
    fn lock(&self) -> std::sync::MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a new code, valid for [`CODE_LIFETIME`], replacing any open
    /// one; `None` when the system cannot provide randomness.
    pub(crate) fn open(&self) -> Option<PairingCode> {
        let mut secret = [0_u8; SECRET_BYTES];
        self.random.fill(&mut secret).ok()?;
        let expires = self.clock.now().checked_add(CODE_LIFETIME)?;
        let secret = Secret::new(secret);
        let mut slot = self.lock();
        slot.open = Some(OpenCode {
            secret: secret.clone(),
            expires,
        });
        slot.generation = slot.generation.wrapping_add(1);
        drop(slot);
        Some(PairingCode {
            server_pin: self.server_pin,
            secret,
        })
    }

    /// Whether a code is open, so an unknown certificate may pair.
    pub(crate) fn is_open(&self) -> bool {
        let now = self.clock.now();
        self.lock()
            .open
            .as_ref()
            .is_some_and(|open| now < open.expires)
    }

    /// Checks `secret` against the open code in constant time and, on a
    /// match, takes the code out and runs `enroll` without the lock, so a
    /// code enrolls one client however many requests race and the lock is
    /// never held across `enroll`. A failed `enroll` puts the code back,
    /// unless another was opened meanwhile. Blocking when `enroll` is.
    pub(crate) fn redeem(
        &self,
        secret: &[u8; SECRET_BYTES],
        enroll: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Redeemed> {
        let now = self.clock.now();
        let mut slot = self.lock();
        let Some(open) = slot.open.as_ref().filter(|open| now < open.expires) else {
            return Ok(Redeemed::NoCode);
        };
        if !bool::from(open.secret.expose_secret().ct_eq(secret)) {
            return Ok(Redeemed::WrongSecret);
        }
        let taken = slot.open.take();
        let generation = slot.generation;
        drop(slot);
        if let Err(err) = enroll() {
            let mut slot = self.lock();
            if slot.generation == generation {
                slot.open = taken;
            }
            drop(slot);
            return Err(err);
        }
        Ok(Redeemed::Enrolled)
    }
}

/// The pairing request's body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairRequest {
    /// The code's secret, 32 hex digits.
    secret: String,
}

/// The secret of a pairing request body, `{"secret":"<32 hex digits>"}`
/// (either case); `None` for anything else. Runs on bytes from a client
/// that only proved it holds some key: it never panics (fuzzed).
pub fn parse_request(body: &[u8]) -> Option<[u8; SECRET_BYTES]> {
    // RFC 8259 §2, §4: an object, so `{` after any whitespace. serde reads
    // a struct from an array too (`["<32 hex digits>"]`), which is not the
    // request.
    let start = body
        .iter()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'));
    if start != Some(&b'{') {
        return None;
    }
    let request: PairRequest = serde_json::from_slice(body).ok()?;
    let digits = request.secret.as_bytes();
    if digits.len() != SECRET_BYTES.saturating_mul(2) || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut secret = [0_u8; SECRET_BYTES];
    for (byte, pair) in secret.iter_mut().zip(digits.as_chunks::<2>().0) {
        let text = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(text, 16).ok()?;
    }
    Some(secret)
}

/// What the pairing route needs.
#[derive(Clone)]
pub(crate) struct PairContext {
    /// The open code.
    pairing: Arc<Pairing>,
    /// Where the pin is enrolled.
    store: Arc<ClientStore>,
    /// The pin of the certificate the handshake proved.
    pin: Fingerprint,
    /// The client's address, for the log.
    addr: SocketAddr,
    /// The connection's redemptions, which [`serve`] waits for: one runs
    /// to its end even when its connection closes first.
    redemptions: TaskTracker,
    /// Cancelled once the connection is closed: a redemption that has not
    /// begun by then does nothing.
    closed: CancellationToken,
}

impl PairContext {
    /// The context of a pairing connection from `addr`, whose handshake
    /// proved `pin`.
    pub(crate) fn new(
        pairing: Arc<Pairing>,
        store: Arc<ClientStore>,
        pin: Fingerprint,
        addr: SocketAddr,
    ) -> Self {
        Self {
            pairing,
            store,
            pin,
            addr,
            redemptions: TaskTracker::new(),
            closed: CancellationToken::new(),
        }
    }
}

/// Serves the one request a pairing connection may make, within
/// [`PAIR_TIMEOUT`], then closes it and waits for a redemption it began.
/// Anything but `POST /v1/pair` is 404 (405 for another method on it).
pub(crate) async fn serve(
    stream: TlsStream<TcpStream>,
    context: PairContext,
    clock: Arc<dyn Clock>,
    shutdown: CancellationToken,
) {
    let (pin, addr) = (context.pin, context.addr);
    let (redemptions, closed) = (context.redemptions.clone(), context.closed.clone());
    let app = Router::new()
        .route(PAIR_PATH, post(pair))
        .layer(DefaultBodyLimit::max(MAX_PAIR_REQUEST_BYTES))
        .with_state(context);
    let mut http = http1::Builder::new();
    http.keep_alive(false)
        .max_buf_size(MAX_UPGRADE_HEADER_BYTES)
        .max_headers(MAX_UPGRADE_HEADERS);
    let connection = http.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app));
    tokio::select! {
        _served = connection => {}
        () = clock.sleep(PAIR_TIMEOUT) => {
            let timeout_ms = PAIR_TIMEOUT.as_millis();
            tracing::info!(%addr, client_pin = %pin, timeout_ms, "pairing connection closed: no request before the deadline");
        }
        () = shutdown.cancelled() => {}
    }
    closed.cancel();
    redemptions.close();
    redemptions.wait().await;
}

/// `POST /v1/pair`: 204 once enrolled, 400 for a body that is not a
/// secret, 403 for a wrong secret (the code stays open), 410 when no code
/// is open any more, 500 when the pin could not be stored. The redemption
/// is a task of its own, tracked by the connection, so it ends and is
/// logged even if this handler is dropped with its connection.
async fn pair(State(context): State<PairContext>, body: Bytes) -> Response {
    let Some(secret) = parse_request(&body) else {
        let (pin, addr) = (context.pin, context.addr);
        tracing::info!(%addr, client_pin = %pin, "pairing request refused: not a secret");
        return error(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidRequest,
            "the body must be {\"secret\": \"<32 hex digits>\"}",
        );
    };
    let redemption = context
        .redemptions
        .track_future(redeem(context.clone(), secret));
    match spawn_named("api.pair", redemption)
        .await
        .map_err(io::Error::other)
        .and_then(|redeemed| redeemed)
    {
        Ok(Redeemed::Enrolled) => StatusCode::NO_CONTENT.into_response(),
        Ok(Redeemed::WrongSecret) => error(
            StatusCode::FORBIDDEN,
            ErrorCode::NotPermitted,
            "the secret is not the open code's",
        ),
        Ok(Redeemed::NoCode | Redeemed::Abandoned) => error(
            StatusCode::GONE,
            ErrorCode::NotPermitted,
            "no pairing code is open: it expired or was used",
        ),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::InternalError,
            "the client could not be stored",
        ),
    }
}

/// Redeems `secret` for the connection's pin on the blocking pool, unless
/// the connection closed before its turn, and logs the outcome.
async fn redeem(context: PairContext, secret: [u8; SECRET_BYTES]) -> io::Result<Redeemed> {
    let PairContext {
        pairing,
        store,
        pin,
        addr,
        closed,
        ..
    } = context;
    let outcome = spawn_blocking_named("api.pair_store", move || {
        if closed.is_cancelled() {
            return Ok(Redeemed::Abandoned);
        }
        pairing.redeem(&secret, || store.enroll(pin))
    })
    .await
    .map_err(io::Error::other)
    .and_then(|redeemed| redeemed);
    match &outcome {
        Ok(Redeemed::Enrolled) => tracing::info!(
            event = "control_client_enrolled",
            client_pin = %pin,
            %addr,
            "control client enrolled by pairing"
        ),
        Ok(Redeemed::WrongSecret) => {
            tracing::warn!(%addr, client_pin = %pin, "pairing request refused: wrong secret");
        }
        Ok(Redeemed::NoCode) => {
            tracing::info!(%addr, client_pin = %pin, "pairing request refused: no code open");
        }
        Ok(Redeemed::Abandoned) => {
            tracing::info!(%addr, client_pin = %pin, "pairing request dropped: its connection closed first");
        }
        Err(err) => {
            tracing::error!(%addr, client_pin = %pin, error = %err, "enrolling the paired client failed");
        }
    }
    outcome
}

/// A JSON error body.
fn error(status: StatusCode, code: ErrorCode, message: &str) -> Response {
    let body = serde_json::to_string(&ApiError::new(code, message)).unwrap_or_default();
    (status, [("content-type", "application/json")], body).into_response()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::PathBuf;
    use std::sync::Barrier;

    use lotse_core::clock::FakeClock;

    use super::test_support::{NO_RANDOM, capture};
    use super::*;

    fn pairing(clock: &Arc<FakeClock>) -> Pairing {
        Pairing::new(
            Fingerprint::of(b"server"),
            Arc::<FakeClock>::clone(clock),
            rustls::crypto::ring::default_provider().secure_random,
        )
    }

    /// An enrollment that succeeds.
    #[expect(clippy::unnecessary_wraps, reason = "the shape `redeem` takes")]
    fn stored() -> io::Result<()> {
        Ok(())
    }

    fn secret_of(code: &PairingCode) -> [u8; SECRET_BYTES] {
        *code.secret.expose_secret()
    }

    #[test]
    fn a_code_is_the_prefix_the_server_pin_and_a_secret_in_hex() {
        let clock = Arc::new(FakeClock::default());
        let code = pairing(&clock).open().unwrap();
        let text = code.reveal();
        let parts: Vec<&str> = text.split('-').collect();
        assert_eq!(parts.len(), 3, "{text}");
        assert_eq!(parts[0], "LOTSE1");
        assert_eq!(parts[1], Fingerprint::of(b"server").to_hex());
        assert_eq!(parts[2].len(), 32);
        assert!(
            parts[2]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert!(
            !format!("{code:?}").contains(parts[2]),
            "Debug redacts the secret"
        );
        let result = code.result();
        assert_eq!(result.code, text);
        assert_eq!(result.expires_in_ms, 600_000);
        assert!(format!("{:?}", pairing(&clock)).contains("server_pin"));
    }

    #[test]
    fn a_code_works_once_and_a_new_one_replaces_the_open_one() {
        let clock = Arc::new(FakeClock::default());
        let pairing = pairing(&clock);
        assert!(!pairing.is_open());
        let first = pairing.open().unwrap();
        let second = pairing.open().unwrap();
        assert_ne!(secret_of(&first), secret_of(&second));
        assert!(pairing.is_open());
        assert_eq!(
            pairing.redeem(&secret_of(&first), stored).unwrap(),
            Redeemed::WrongSecret,
            "replaced"
        );
        let mut enrolled = 0;
        let outcome = pairing.redeem(&secret_of(&second), || {
            enrolled += 1;
            Ok(())
        });
        assert_eq!(outcome.unwrap(), Redeemed::Enrolled);
        assert_eq!(enrolled, 1);
        assert!(!pairing.is_open());
        assert_eq!(
            pairing.redeem(&secret_of(&second), stored).unwrap(),
            Redeemed::NoCode
        );
    }

    #[test]
    fn a_wrong_secret_or_a_failed_enrollment_leaves_the_code_open() {
        let clock = Arc::new(FakeClock::default());
        let pairing = pairing(&clock);
        let code = pairing.open().unwrap();
        assert_eq!(
            pairing.redeem(&[0; SECRET_BYTES], stored).unwrap(),
            Redeemed::WrongSecret
        );
        let failed = pairing.redeem(&secret_of(&code), || Err(io::Error::other("disk")));
        assert!(failed.is_err());
        assert!(pairing.is_open());
        assert_eq!(
            pairing.redeem(&secret_of(&code), stored).unwrap(),
            Redeemed::Enrolled
        );
    }

    #[test]
    fn a_matching_request_takes_the_code_out_while_it_stores_the_pin() {
        let clock = Arc::new(FakeClock::default());
        let pairing = pairing(&clock);
        let code = pairing.open().unwrap();
        let failed = pairing.redeem(&secret_of(&code), || {
            // The lock is free: the handshakes' check and a racing request
            // answer at once, and the code is no longer theirs.
            assert!(!pairing.is_open());
            assert_eq!(
                pairing.redeem(&secret_of(&code), stored).unwrap(),
                Redeemed::NoCode
            );
            Err(io::Error::other("disk"))
        });
        assert!(failed.is_err());
        assert!(pairing.is_open(), "put back after the failed store");
        assert_eq!(
            pairing.redeem(&secret_of(&code), stored).unwrap(),
            Redeemed::Enrolled
        );
    }

    #[test]
    fn a_failed_store_never_puts_back_a_code_a_new_one_replaced() {
        let clock = Arc::new(FakeClock::default());
        let pairing = pairing(&clock);
        let first = pairing.open().unwrap();
        let mut replacement = None;
        let failed = pairing.redeem(&secret_of(&first), || {
            replacement = pairing.open();
            Err(io::Error::other("disk"))
        });
        assert!(failed.is_err());
        let replacement = replacement.unwrap();
        assert_eq!(
            pairing.redeem(&secret_of(&first), stored).unwrap(),
            Redeemed::WrongSecret,
            "the replacement stays"
        );
        // Replaced and used meanwhile: the slot stays empty.
        let failed = pairing.redeem(&secret_of(&replacement), || {
            let newer = pairing.open().unwrap();
            assert_eq!(
                pairing.redeem(&secret_of(&newer), stored).unwrap(),
                Redeemed::Enrolled
            );
            Err(io::Error::other("disk"))
        });
        assert!(failed.is_err());
        assert!(!pairing.is_open());
    }

    fn store(name: &str) -> (PathBuf, ClientStore) {
        let dir = std::env::temp_dir().join(format!("lotse-pairing-{name}-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let runtime = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let data = std::fs::File::open(&dir).unwrap();
        let store = ClientStore::open(&data, &dir, &[], runtime).unwrap();
        (dir, store)
    }

    fn addr() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], 50_000))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_redemption_is_logged_and_one_whose_connection_closed_first_stores_nothing() {
        let (logs, _guard) = capture();
        let (dir, store) = store("outcomes");
        let store = Arc::new(store);
        let clock = Arc::new(FakeClock::default());
        let pairing = Arc::new(pairing(&clock));
        let code = pairing.open().unwrap();
        let pin = Fingerprint::of(b"client");
        let context = || PairContext::new(Arc::clone(&pairing), Arc::clone(&store), pin, addr());
        let closed = context();
        closed.closed.cancel();
        let outcome = redeem(closed, secret_of(&code)).await.unwrap();
        assert_eq!(outcome, Redeemed::Abandoned);
        assert!(pairing.is_open());
        assert!(!store.allows(&pin));
        assert!(logs.text().contains("its connection closed first"));
        let outcome = redeem(context(), [0; SECRET_BYTES]).await.unwrap();
        assert_eq!(outcome, Redeemed::WrongSecret);
        assert!(logs.text().contains("wrong secret"));
        let blocker = dir.join(crate::clients::CLIENTS_DIR).join("pins.partial");
        std::fs::create_dir(&blocker).unwrap();
        assert!(redeem(context(), secret_of(&code)).await.is_err());
        assert!(logs.text().contains("enrolling the paired client failed"));
        std::fs::remove_dir(&blocker).unwrap();
        let outcome = redeem(context(), secret_of(&code)).await.unwrap();
        assert_eq!(outcome, Redeemed::Enrolled);
        assert!(store.allows(&pin));
        let outcome = redeem(context(), secret_of(&code)).await.unwrap();
        assert_eq!(outcome, Redeemed::NoCode);
        assert!(logs.text().contains("no code open"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Both sides of the store held open by
    /// `a_redemption_outlives_its_connection_and_is_waited_for_and_logged`.
    static STORING: Barrier = Barrier::new(2);

    #[tokio::test(flavor = "current_thread")]
    async fn a_redemption_outlives_its_connection_and_is_waited_for_and_logged() {
        let (logs, _guard) = capture();
        let (dir, store) = store("outlives");
        let store = Arc::new(store.with_sync_dir(|_| {
            STORING.wait();
            STORING.wait();
            Ok(())
        }));
        let clock = Arc::new(FakeClock::default());
        let pairing = Arc::new(pairing(&clock));
        let code = pairing.open().unwrap();
        let pin = Fingerprint::of(b"client");
        let context = PairContext::new(Arc::clone(&pairing), Arc::clone(&store), pin, addr());
        let (redemptions, closed) = (context.redemptions.clone(), context.closed.clone());
        let body = format!(r#"{{"secret":"{}"}}"#, hex(&secret_of(&code)));
        let handler = spawn_named("test.pair", pair(State(context), Bytes::from(body)));
        spawn_blocking_named("test.storing", || STORING.wait())
            .await
            .unwrap();
        // The connection closes mid-store, as `serve` closes it at the
        // deadline: its handler is dropped, the store is not.
        handler.abort();
        closed.cancel();
        redemptions.close();
        assert_eq!(redemptions.len(), 1, "still storing");
        spawn_blocking_named("test.stored", || STORING.wait())
            .await
            .unwrap();
        redemptions.wait().await;
        assert!(store.allows(&pin));
        assert!(!pairing.is_open());
        assert!(logs.text().contains("control client enrolled by pairing"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_code_expires_after_ten_minutes_on_the_clock() {
        let clock = Arc::new(FakeClock::default());
        let pairing = pairing(&clock);
        let code = pairing.open().unwrap();
        clock.advance(CODE_LIFETIME.checked_sub(Duration::from_millis(1)).unwrap());
        assert!(pairing.is_open());
        clock.advance(Duration::from_millis(1));
        assert!(!pairing.is_open());
        assert_eq!(
            pairing.redeem(&secret_of(&code), stored).unwrap(),
            Redeemed::NoCode
        );
    }

    #[test]
    fn without_randomness_no_code_opens() {
        let clock = Arc::new(FakeClock::default());
        let pairing = Pairing::new(Fingerprint::of(b"server"), clock, &NO_RANDOM);
        assert!(pairing.open().is_none());
        assert!(!pairing.is_open());
    }

    #[test]
    fn rfc8259_a_request_is_one_secret_of_32_hex_digits() {
        let secret = "00112233445566778899aabbccddeeff";
        let parsed = parse_request(format!(r#"{{"secret":"{secret}"}}"#).as_bytes()).unwrap();
        assert_eq!(hex(&parsed), secret);
        let upper = format!(r#"{{"secret":"{}"}}"#, secret.to_uppercase());
        assert_eq!(parse_request(upper.as_bytes()), Some(parsed));
        let spaced = format!(" \t\r\n{{\"secret\":\"{secret}\"}} ");
        assert_eq!(
            parse_request(spaced.as_bytes()),
            Some(parsed),
            "§2 whitespace"
        );
        for (case, bad) in [
            String::new(),
            "{}".to_owned(),
            r#"{"secret":1}"#.to_owned(),
            format!(r#"{{"secret":"{secret}","pin":"x"}}"#),
            format!(r#"{{"secret":"{}"}}"#, &secret[..30]),
            format!(r#"{{"secret":"{secret}00"}}"#),
            format!(r#"{{"secret":"+{}"}}"#, &secret[1..]),
            format!(r#"{{"secret":"g{}"}}"#, &secret[1..]),
            format!(r#"{{"secret":"é{}"}}"#, &secret[2..]),
            // An array: serde reads a struct from one, the request is an
            // object. Found by the `pair_request` fuzz target.
            format!(r#"["{secret}"]"#),
            format!(r#" ["{secret}"]"#),
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(parse_request(bad.as_bytes()), None, "case {case}");
        }
    }
}

/// What the tests of this crate share about pairing: a system without
/// randomness, and the log lines of the test's thread.
#[cfg(test)]
pub(crate) mod test_support {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use std::sync::{Arc, Mutex};

    use rustls::crypto::{GetRandomFailed, SecureRandom};

    /// A system without randomness.
    #[derive(Debug)]
    pub(crate) struct NoRandom;

    impl SecureRandom for NoRandom {
        fn fill(&self, _buf: &mut [u8]) -> Result<(), GetRandomFailed> {
            Err(GetRandomFailed)
        }
    }

    pub(crate) static NO_RANDOM: NoRandom = NoRandom;

    /// A log writer that keeps every line.
    #[derive(Clone, Default)]
    pub(crate) struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        /// Everything logged so far.
        pub(crate) fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    /// Captures this thread's log lines until the guard is dropped.
    pub(crate) fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        std::io::Write::flush(&mut captured.clone()).unwrap();
        (captured, tracing::subscriber::set_default(subscriber))
    }
}
