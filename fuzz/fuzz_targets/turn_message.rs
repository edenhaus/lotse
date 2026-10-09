//! `turn_message`: the supervisor's TURN readers never panic on bytes from
//! a TURN server; ChannelData data is exactly the claimed length and never
//! exceeds the datagram, and what the framer makes parses back; the TCP
//! splitter cuts ChannelData frames that parse whole; a challenge, when one
//! is accepted, signs requests that verify under its key only and only over
//! the bytes they cover; the allocation state machine, answered with these
//! bytes under the transaction ids of its own requests, keeps its
//! invariants (RFC 8656 §7 to §12.6, §18; RFC 8489 §6.2, §9.2.5, §14.5,
//! §14.6).
//! Run with `cargo +nightly fuzz run turn_message` from the repository root.

#![no_main]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use lotse_core::secret::Secret;
use lotse_supervisor::net::allocation::{Allocation, AllocationConfig, Event, Transport};
use lotse_supervisor::net::credential::{
    Authenticator, Challenge, Credentials, password_algorithms, security_features,
};
use lotse_supervisor::net::stun::{Builder, Class, parse};
use lotse_supervisor::net::turn::{
    CHANNEL_DATA_HEADER_LEN, Kind, METHOD_REFRESH, channel_number, data_indication,
    frame_channel_data, kind, lifetime, parse_channel_data, relayed_address, stream_frame_len,
};

fuzz_target!(|data: &[u8]| {
    // ChannelData from a UDP datagram.
    if let Ok(message) = parse_channel_data(data) {
        let claimed = usize::from(u16::from_be_bytes([data[2], data[3]]));
        assert_eq!(message.data.len(), claimed);
        assert!(CHANNEL_DATA_HEADER_LEN + message.data.len() <= data.len());
        assert_eq!(kind(data[0]), Kind::ChannelData);
        for pad in [false, true] {
            let mut framed = Vec::new();
            frame_channel_data(message.channel, message.data, pad, &mut framed)
                .expect("parsed data fits the length field");
            assert_eq!(parse_channel_data(&framed), Ok(message));
            assert!(!pad || framed.len() % 4 == 0);
        }
    }
    // The same bytes as a TCP stream: every frame the splitter cuts is
    // whole, and a ChannelData frame parses.
    let mut rest = data;
    while let Ok(Some(len)) = stream_frame_len(rest) {
        assert!(len >= CHANNEL_DATA_HEADER_LEN);
        let Some((frame, tail)) = rest.split_at_checked(len) else {
            break;
        };
        if kind(frame[0]) == Kind::ChannelData {
            let message = parse_channel_data(frame).expect("a cut channeldata frame parses");
            assert!(message.data.len() + CHANNEL_DATA_HEADER_LEN <= len);
            assert!(
                len - message.data.len() - CHANNEL_DATA_HEADER_LEN < 4,
                "only padding"
            );
        }
        rest = tail;
    }
    // STUN-formatted TURN messages.
    if let Ok(message) = parse(data) {
        let _ = relayed_address(&message);
        let _ = lifetime(&message);
        if let Some(channel) = channel_number(&message) {
            assert!((0x4000..=0x4fff).contains(&channel.number()));
        }
        if let Some((_, payload)) = data_indication(&message) {
            assert!(payload.len() <= data.len());
        }
        // A signed request repeats the challenge's attributes, so one from a
        // message over half the STUN size limit might not fit; libFuzzer's
        // inputs stay far below.
        let challenge = Challenge::from_response(&message).ok();
        if let Some(challenge) = challenge.filter(|_| data.len() <= usize::from(u16::MAX) / 2) {
            if let Some(raw) = &challenge.algorithms {
                assert!(password_algorithms(raw).is_some());
            }
            let credentials = Credentials {
                username: "user".to_owned(),
                password: Secret::new("pass".to_owned()),
            };
            let auth = Authenticator::new(&credentials, challenge);
            let signed = auth
                .sign(Builder::new(
                    Class::Request,
                    METHOD_REFRESH,
                    message.transaction_id,
                ))
                .build();
            let request = parse(&signed).expect("a signed request parses");
            assert!(auth.verify(&request, &signed), "verifies under its key");
            let other = Credentials {
                username: "user".to_owned(),
                password: Secret::new("other".to_owned()),
            };
            let stranger = Authenticator::new(&other, auth.challenge().clone());
            assert!(!stranger.verify(&request, &signed), "only under its key");
            let mut forged = signed.clone();
            forged[8] ^= 1;
            let request = parse(&forged).expect("the forgery still parses");
            assert!(
                !auth.verify(&request, &forged),
                "only over the bytes it covers"
            );
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = security_features(text);
    }
    let _ = password_algorithms(data);
    allocation(data);
});

/// Feeds `data` to an allocation as its server's answers: length-prefixed
/// messages, each given the transaction id of the oldest request still
/// unanswered, with time moving by the byte after each. Whatever comes
/// back, nothing panics, every request it sends parses, it has a
/// deadline exactly while it lives, it is allocated exactly when its last
/// say was `Allocated`, and nothing follows `Closed`.
fn allocation(data: &[u8]) {
    let credentials = Credentials {
        username: "user".to_owned(),
        password: Secret::new("pass".to_owned()),
    };
    let server: SocketAddr = "192.0.2.1:3478".parse().expect("an address");
    let peer: SocketAddr = "192.0.2.9:5000".parse().expect("an address");
    let mut now = Instant::now();
    let transport = if data.first().is_some_and(|b| b & 1 == 1) {
        Transport::Tcp
    } else {
        Transport::Udp
    };
    let mut machine = Allocation::new(
        server,
        transport,
        credentials.clone(),
        AllocationConfig::default(),
        [0; 32],
        now,
    );
    let lease = machine
        .add_session(&credentials)
        .expect("a new allocation takes sessions");
    let _ = machine.permit(now, lease, peer.ip());
    let _ = machine.bind_channel(now, lease, peer);
    let mut pending = Vec::new();
    let mut allocated = false;
    let mut closed = false;
    let mut rest = data.get(1..).unwrap_or_default();
    loop {
        while let Some(transmit) = machine.poll_transmit() {
            assert!(!closed, "nothing is sent after Closed");
            let request = parse(&transmit.bytes).expect("every request parses");
            assert_eq!(request.class, Class::Request);
            pending.push(transmit.transaction_id);
        }
        while let Some(event) = machine.poll_event() {
            assert!(!closed, "nothing follows Closed");
            match event {
                Event::Allocated { .. } => allocated = true,
                Event::Lost { .. } => allocated = false,
                Event::Closed { .. } => {
                    allocated = false;
                    closed = true;
                }
                Event::Permission { .. } | Event::Channel { .. } => {}
            }
        }
        assert_eq!(machine.is_closed(), closed);
        assert_eq!(machine.relayed().is_some(), allocated);
        assert_eq!(machine.poll_timeout().is_some(), !closed);
        let Some((&[high, low], tail)) = rest.split_first_chunk::<2>() else {
            break;
        };
        let len = usize::from(u16::from_be_bytes([high, low]));
        let Some((message, tail)) = tail.split_at_checked(len.min(tail.len())) else {
            break;
        };
        let mut message = message.to_vec();
        pending.retain(|id| machine.is_pending(id));
        if let (Some(id), Some(slot)) = (pending.first(), message.get_mut(8..20)) {
            slot.copy_from_slice(id);
        }
        let _ = machine.handle_input(now, &message);
        let Some((&step, tail)) = tail.split_first() else {
            break;
        };
        now += Duration::from_secs(u64::from(step));
        machine.handle_timeout(now);
        if step == 0xFF {
            machine.remove_session(now, lease);
        }
        rest = tail;
    }
}
