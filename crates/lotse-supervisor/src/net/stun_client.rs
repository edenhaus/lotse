//! The STUN client of server-reflexive gathering: a Binding Request to
//! each `stun:` server from the shared socket, so the mapped address is
//! the port the daemon uses, with retransmission and a per-server cache.
//!
//! Implements RFC 8489 §6.2.1 (retransmission: RTO doubling, `Rc`
//! attempts) and §7.2 (a request needs no attributes); responses arrive
//! through the demux by transaction id.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;

use super::demux::StunResponses;
use super::stun;

/// The tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunClientConfig {
    /// The first retransmission timeout (§6.2.1 default: 500 ms).
    pub rto: Duration,
    /// Retransmissions after the first request (§6.2.1 `Rc` = 7).
    pub retries: u32,
    /// How long a server's answer is reused.
    pub cache: Duration,
}

impl Default for StunClientConfig {
    fn default() -> Self {
        Self {
            rto: Duration::from_millis(500),
            retries: 7,
            cache: Duration::from_secs(300),
        }
    }
}

/// Why no reflexive address came back.
#[derive(Debug, thiserror::Error)]
pub enum StunClientError {
    /// No answer within the retransmissions.
    #[error("no answer from the stun server")]
    Timeout,
    /// The request could not be sent.
    #[error("sending to the stun server: {0}")]
    Send(#[source] io::Error),
    /// The server answered with an error.
    #[error("stun server error {code}: {reason}")]
    ErrorResponse {
        /// The ERROR-CODE.
        code: u16,
        /// Its reason.
        reason: String,
    },
    /// A success response without a mapped address.
    #[error("stun response carries no mapped address")]
    NoMappedAddress,
    /// No entropy for a transaction id.
    #[error("transaction id: {0}")]
    Entropy(getrandom::Error),
}

/// The client.
#[derive(Debug)]
pub struct StunClient {
    /// The shared socket to send from.
    socket: Arc<UdpSocket>,
    /// Where the demux delivers responses.
    responses: Arc<StunResponses>,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// The tunables.
    config: StunClientConfig,
    /// Answers by server, with when they were learned.
    cache: Mutex<HashMap<SocketAddr, (Instant, SocketAddr)>>,
}

impl StunClient {
    /// A client sending from `socket`.
    pub fn new(
        socket: Arc<UdpSocket>,
        responses: Arc<StunResponses>,
        clock: Arc<dyn Clock>,
        config: StunClientConfig,
    ) -> Self {
        Self {
            socket,
            responses,
            clock,
            config,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The daemon's address as `server` sees it, cached.
    pub async fn reflexive(&self, server: SocketAddr) -> Result<SocketAddr, StunClientError> {
        let now = self.clock.now();
        let cached = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&server)
            .filter(|(at, _)| now.saturating_duration_since(*at) < self.config.cache)
            .map(|(_, mapped)| *mapped);
        if let Some(mapped) = cached {
            return Ok(mapped);
        }
        let mapped = self.gather(server).await?;
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(server, (self.clock.now(), mapped));
        Ok(mapped)
    }

    /// One transaction with retransmissions (§6.2.1).
    async fn gather(&self, server: SocketAddr) -> Result<SocketAddr, StunClientError> {
        let mut transaction_id = [0_u8; 12];
        getrandom::fill(&mut transaction_id).map_err(StunClientError::Entropy)?;
        let request = stun::binding_request(transaction_id);
        let local = self.socket.local_addr().ok();
        let mut reply = self.responses.expect(transaction_id);
        let mut timeout = self.config.rto;
        let outcome = async {
            for attempt in 0..=self.config.retries {
                if let Err(err) = self.socket.send_to(&request, egress(local, server)) {
                    return Err(StunClientError::Send(err));
                }
                tracing::debug!(%server, attempt, timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX), "stun binding request sent");
                tokio::select! {
                    answer = &mut reply => {
                        let Ok(answer) = answer else {
                            return Err(StunClientError::Timeout);
                        };
                        if let Some((code, reason)) = answer.error {
                            return Err(StunClientError::ErrorResponse { code, reason });
                        }
                        return answer.mapped.ok_or(StunClientError::NoMappedAddress);
                    }
                    () = self.clock.sleep(timeout) => {}
                }
                timeout = timeout.saturating_mul(2);
            }
            Err(StunClientError::Timeout)
        }
        .await;
        self.responses.forget(&transaction_id);
        match &outcome {
            Ok(mapped) => tracing::info!(%server, %mapped, "server-reflexive address gathered"),
            Err(err) => tracing::warn!(%server, error = %err, "server-reflexive gathering failed"),
        }
        outcome
    }
}

/// The address to send to from the shared socket: an IPv4 server of a
/// dual-stack socket is addressed as IPv4-mapped (RFC 4291 §2.5.5.2).
pub(super) fn egress(local: Option<SocketAddr>, server: SocketAddr) -> SocketAddr {
    match (local, server) {
        (Some(SocketAddr::V6(_)), SocketAddr::V4(v4)) => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => server,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::clock::{FakeClock, SystemClock};

    use super::super::demux::Demux;
    use super::super::stun::{Builder, Class, METHOD_BINDING};
    use super::*;

    /// A STUN server on loopback that answers `answers` requests with the
    /// sender's address, then goes silent.
    fn fake_server(answers: usize, error: bool) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            for _ in 0..answers {
                let (n, from) = socket.recv_from(&mut buf).unwrap();
                let request = stun::parse(&buf[..n]).unwrap();
                assert!(request.is_binding_request());
                let reply = if error {
                    Builder::new(Class::Error, METHOD_BINDING, request.transaction_id)
                        .attribute(stun::ATTR_ERROR_CODE, &[0, 0, 4, 0, b'B', b'a', b'd'])
                        .build()
                } else {
                    Builder::new(Class::Success, METHOD_BINDING, request.transaction_id)
                        .xor_mapped_address(from)
                        .build()
                };
                socket.send_to(&reply, from).unwrap();
            }
        });
        (addr, thread)
    }

    fn client(
        answers: usize,
        error: bool,
    ) -> (StunClient, Demux, SocketAddr, std::thread::JoinHandle<()>) {
        let bound = super::super::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = bound.local;
        let demux = Demux::start(
            Arc::clone(&bound.socket),
            local,
            vec![local],
            Arc::new(SystemClock),
        )
        .unwrap();
        let (server, thread) = fake_server(answers, error);
        let client = StunClient::new(
            bound.socket,
            demux.responses(),
            Arc::new(SystemClock),
            StunClientConfig {
                rto: Duration::from_millis(50),
                retries: 2,
                cache: Duration::from_secs(60),
            },
        );
        (client, demux, server, thread)
    }

    #[tokio::test]
    async fn the_mapped_address_is_gathered_and_cached() {
        let (client, demux, server, thread) = client(1, false);
        let mapped = client.reflexive(server).await.unwrap();
        assert_eq!(mapped.port(), demux_port(&demux, &client));
        // The server answers once; the second call is served from the cache.
        assert_eq!(client.reflexive(server).await.unwrap(), mapped);
        thread.join().unwrap();
        demux.stop();
    }

    fn demux_port(_demux: &Demux, client: &StunClient) -> u16 {
        client.socket.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn an_ipv4_server_is_reached_from_a_dual_stack_socket() {
        let bound = super::super::udp::test_support::bind_dual_stack();
        let local = bound.local;
        let demux = Demux::start(
            Arc::clone(&bound.socket),
            local,
            vec![],
            Arc::new(SystemClock),
        )
        .unwrap();
        let (server, thread) = fake_server(1, false);
        let client = StunClient::new(
            bound.socket,
            demux.responses(),
            Arc::new(SystemClock),
            StunClientConfig::default(),
        );
        let mapped = tokio::select! {
            mapped = client.reflexive(server) => mapped.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no mapped address"),
        };
        assert!(
            mapped.is_ipv4() && mapped.port() == local.port(),
            "{mapped}"
        );
        thread.join().unwrap();
        demux.stop();
        assert_eq!(
            egress(Some(local), "192.0.2.1:3478".parse().unwrap()),
            "[::ffff:192.0.2.1]:3478".parse().unwrap()
        );
        assert_eq!(
            egress(None, "192.0.2.1:3478".parse().unwrap()),
            "192.0.2.1:3478".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn a_silent_server_times_out_after_the_retransmissions() {
        let (client, demux, server, thread) = client(0, false);
        let err = client.reflexive(server).await.unwrap_err();
        assert!(matches!(err, StunClientError::Timeout), "{err}");
        assert_eq!(err.to_string(), "no answer from the stun server");
        drop(thread);
        demux.stop();
    }

    #[tokio::test]
    async fn a_request_the_socket_cannot_send_is_an_error() {
        let bound = super::super::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let client = StunClient::new(
            bound.socket,
            Arc::new(StunResponses::default()),
            Arc::new(FakeClock::default()),
            StunClientConfig::default(),
        );
        // An IPv4 socket has no way to an IPv6 server.
        let err = client
            .reflexive("[::1]:3478".parse().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, StunClientError::Send(_)), "{err}");
    }

    /// A transaction whose waiter goes (the demux forgot it) ends at once
    /// as a timeout, without waiting out the retransmissions (RFC 8489
    /// §6.2.1).
    #[tokio::test]
    async fn rfc8489_6_2_1_a_transaction_given_up_elsewhere_ends_as_a_timeout() {
        let bound = super::super::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let responses = Arc::new(StunResponses::default());
        // The fake clock never moves: no retransmission, no timeout.
        let client = StunClient::new(
            bound.socket,
            Arc::clone(&responses),
            Arc::new(FakeClock::default()),
            StunClientConfig::default(),
        );
        let mut gathering = Box::pin(client.reflexive(server.local_addr().unwrap()));
        // One poll sends the request and waits for the answer.
        let early = tokio::select! {
            biased;
            out = &mut gathering => Some(out),
            () = std::future::ready(()) => None,
        };
        assert!(early.is_none(), "still waiting");
        let mut buf = [0_u8; 1500];
        let (n, _) = server.recv_from(&mut buf).unwrap();
        let request = stun::parse(&buf[..n]).unwrap();
        assert_eq!(responses.outstanding(), 1);
        responses.forget(&request.transaction_id);
        let err = gathering.await.unwrap_err();
        assert!(matches!(err, StunClientError::Timeout), "{err}");
    }

    #[tokio::test]
    async fn an_error_response_is_reported() {
        let (client, demux, server, thread) = client(1, true);
        let err = client.reflexive(server).await.unwrap_err();
        assert!(
            matches!(err, StunClientError::ErrorResponse { code: 400, ref reason } if reason == "Bad"),
            "{err}"
        );
        thread.join().unwrap();
        demux.stop();
    }
}
