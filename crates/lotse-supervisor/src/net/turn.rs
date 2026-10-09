//! TURN messages for the supervisor's TURN client: the requests that
//! create, refresh and delete an allocation, install permissions and bind
//! channels, the attributes their responses carry, Data indications, and
//! `ChannelData` framing on UDP and on a TCP stream to the server.
//!
//! Implements RFC 8656 §5 (SOFTWARE in Allocate and Refresh), §7.1
//! (Allocate), §8.1 (Refresh, LIFETIME 0 deletes), §10.1
//! (`CreatePermission`), §11.4 (Data indications), §12 (channel numbers
//! 0x4000 to 0x4FFF), §12.1 (`ChannelBind`), §12.4 to §12.6 (`ChannelData`:
//! framing, padding on TCP, what a receiver discards), §17 (methods), §18
//! (attributes), on the STUN codec of RFC 8489 (`stun`); first-byte
//! demultiplexing per RFC 8656 Table 3 (RFC 7983 §7). Requests come back as
//! a [`Builder`], so the long-term credential (`credential`) can sign them.
//! Every byte from a TURN server comes from the network, so the readers
//! are total and fuzzed (`turn_message`).

use std::net::SocketAddr;
use std::time::Duration;

use super::stun::{ATTR_SOFTWARE, Builder, Class, HEADER_LEN, Message};

/// Allocate (§17).
pub const METHOD_ALLOCATE: u16 = 0x003;
/// Refresh (§17).
pub const METHOD_REFRESH: u16 = 0x004;
/// Send, indications only (§17).
pub const METHOD_SEND: u16 = 0x006;
/// Data, indications only (§17).
pub const METHOD_DATA: u16 = 0x007;
/// `CreatePermission` (§17).
pub const METHOD_CREATE_PERMISSION: u16 = 0x008;
/// `ChannelBind` (§17).
pub const METHOD_CHANNEL_BIND: u16 = 0x009;

/// CHANNEL-NUMBER (§18.1).
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
/// LIFETIME (§18.2).
pub const ATTR_LIFETIME: u16 = 0x000D;
/// XOR-PEER-ADDRESS (§18.3).
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
/// DATA (§18.4).
pub const ATTR_DATA: u16 = 0x0013;
/// XOR-RELAYED-ADDRESS (§18.5).
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
/// REQUESTED-ADDRESS-FAMILY (§18.6).
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
/// REQUESTED-TRANSPORT (§18.8).
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

/// The protocol number of UDP, the only transport REQUESTED-TRANSPORT may
/// ask for (§18.8, §7.1).
const PROTOCOL_UDP: u8 = 17;

/// The IPv6 family of REQUESTED-ADDRESS-FAMILY (§18.6, RFC 8489 §14.1).
const FAMILY_IPV6: u8 = 0x02;

/// The `ChannelData` header: channel number and length (§12.4).
pub const CHANNEL_DATA_HEADER_LEN: usize = 4;

/// What every Allocate and Refresh request names as its software (§5,
/// RFC 8489 §14.14: fewer than 128 characters).
const SOFTWARE: &str = concat!("lotse ", env!("CARGO_PKG_VERSION"));

/// A channel number in the range a client may bind, 0x4000 through 0x4FFF
/// (§12, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Channel(u16);

impl Channel {
    /// The first channel number (§12).
    pub const MIN: Self = Self(0x4000);
    /// The last channel number (§12).
    pub const MAX: Self = Self(0x4FFF);

    /// `number` as a channel, if it is in the bindable range (§12).
    pub const fn new(number: u16) -> Option<Self> {
        if number >= Self::MIN.0 && number <= Self::MAX.0 {
            Some(Self(number))
        } else {
            None
        }
    }

    /// The number.
    pub const fn number(self) -> u16 {
        self.0
    }
}

/// An Allocate request for a UDP relay (§7.1): REQUESTED-TRANSPORT UDP,
/// REQUESTED-ADDRESS-FAMILY only for an IPv6 relay (IPv4 is the default,
/// and a server without RFC 8656's address families then still answers),
/// and SOFTWARE (§5). Unsigned: the first request carries no credentials
/// (RFC 8489 §9.2.3.1); later ones go through the authenticator.
pub fn allocate(transaction_id: [u8; 12], ipv6: bool) -> Builder {
    let builder = Builder::new(Class::Request, METHOD_ALLOCATE, transaction_id)
        .attribute(ATTR_REQUESTED_TRANSPORT, &[PROTOCOL_UDP, 0, 0, 0]);
    let builder = if ipv6 {
        builder.attribute(ATTR_REQUESTED_ADDRESS_FAMILY, &[FAMILY_IPV6, 0, 0, 0])
    } else {
        builder
    };
    builder.attribute(ATTR_SOFTWARE, SOFTWARE.as_bytes())
}

/// A Refresh request asking for `lifetime` (§8.1); zero deletes the
/// allocation. Whole seconds, saturating at the attribute's 32 bits
/// (§18.2).
pub fn refresh(transaction_id: [u8; 12], lifetime: Duration) -> Builder {
    let seconds = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
    Builder::new(Class::Request, METHOD_REFRESH, transaction_id)
        .attribute(ATTR_LIFETIME, &seconds.to_be_bytes())
        .attribute(ATTR_SOFTWARE, SOFTWARE.as_bytes())
}

/// A `CreatePermission` request for the IP addresses of `peers` (§10.1): one
/// XOR-PEER-ADDRESS each; the server ignores the ports (§9).
pub fn create_permission(transaction_id: [u8; 12], peers: &[SocketAddr]) -> Builder {
    peers.iter().fold(
        Builder::new(Class::Request, METHOD_CREATE_PERMISSION, transaction_id),
        |builder, peer| builder.xor_address(ATTR_XOR_PEER_ADDRESS, *peer),
    )
}

/// A `ChannelBind` request binding `channel` to `peer` (§12.1): CHANNEL-NUMBER
/// with its reserved half zero (§18.1) and XOR-PEER-ADDRESS.
pub fn channel_bind(transaction_id: [u8; 12], channel: Channel, peer: SocketAddr) -> Builder {
    let [high, low] = channel.number().to_be_bytes();
    Builder::new(Class::Request, METHOD_CHANNEL_BIND, transaction_id)
        .attribute(ATTR_CHANNEL_NUMBER, &[high, low, 0, 0])
        .xor_address(ATTR_XOR_PEER_ADDRESS, peer)
}

/// The relayed transport address of an Allocate success response (§7.3,
/// §18.5).
pub fn relayed_address(message: &Message<'_>) -> Option<SocketAddr> {
    message.xor_address(ATTR_XOR_RELAYED_ADDRESS)
}

/// The LIFETIME of an Allocate or Refresh response, in seconds (§18.2).
/// `None` when absent or not four bytes.
pub fn lifetime(message: &Message<'_>) -> Option<Duration> {
    let value: [u8; 4] = message.attribute(ATTR_LIFETIME)?.try_into().ok()?;
    Some(Duration::from_secs(u64::from(u32::from_be_bytes(value))))
}

/// The CHANNEL-NUMBER of a message, if it is a bindable channel (§18.1:
/// the reserved half is ignored).
pub fn channel_number(message: &Message<'_>) -> Option<Channel> {
    let value = message.attribute(ATTR_CHANNEL_NUMBER)?;
    if value.len() != 4 {
        return None;
    }
    Channel::new(u16::from_be_bytes([*value.first()?, *value.get(1)?]))
}

/// The peer and the data of a Data indication (§11.4): an indication of
/// the Data method with XOR-PEER-ADDRESS and DATA. `None` for anything
/// else, which includes one that only reports ICMP (§11.6).
pub fn data_indication<'a>(message: &Message<'a>) -> Option<(SocketAddr, &'a [u8])> {
    if message.class != Class::Indication || message.method != METHOD_DATA {
        return None;
    }
    let peer = message.xor_address(ATTR_XOR_PEER_ADDRESS)?;
    Some((peer, message.attribute(ATTR_DATA)?))
}

/// What the first byte of a message from a TURN server says it is (§12,
/// Table 3; RFC 7983 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 0 to 3: a STUN-formatted message.
    Stun,
    /// 64 to 79: `ChannelData`.
    ChannelData,
    /// Anything else: dropped (§12, Table 3).
    Other,
}

/// The kind of the message that starts with `first`.
pub const fn kind(first: u8) -> Kind {
    match first {
        0..=3 => Kind::Stun,
        64..=79 => Kind::ChannelData,
        _ => Kind::Other,
    }
}

/// Why bytes are not a `ChannelData` message to accept (§12.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelDataError {
    /// Shorter than the header.
    #[error("shorter than the channeldata header")]
    Short,
    /// The channel number is outside 0x4000 to 0x4FFF, reserved values
    /// included: discarded (§12.6).
    #[error("channel number outside the bindable range")]
    Channel,
    /// The datagram is shorter than the length claims: discarded (§12.6).
    #[error("channeldata length exceeds the datagram")]
    Length,
    /// The data does not fit the 16-bit length field.
    #[error("data longer than a channeldata message carries")]
    TooLong,
}

/// A `ChannelData` message; the data borrows the datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelData<'a> {
    /// The channel, which names the peer.
    pub channel: Channel,
    /// The application data, exactly as many bytes as the length field
    /// says; padding after it is not part of it (§12.4, §12.5).
    pub data: &'a [u8],
}

/// Parses a `ChannelData` message (§12.4, §12.6). Bytes after the claimed
/// length are padding (UDP may carry it, TCP must) and ignored; a length
/// past the end is an error, so the data is always inside `bytes`.
pub fn parse_channel_data(bytes: &[u8]) -> Result<ChannelData<'_>, ChannelDataError> {
    let (header, rest) = bytes
        .split_at_checked(CHANNEL_DATA_HEADER_LEN)
        .ok_or(ChannelDataError::Short)?;
    let [c0, c1, l0, l1] = <[u8; 4]>::try_from(header).map_err(|_| ChannelDataError::Short)?;
    let channel = Channel::new(u16::from_be_bytes([c0, c1])).ok_or(ChannelDataError::Channel)?;
    let length = usize::from(u16::from_be_bytes([l0, l1]));
    let data = rest.get(..length).ok_or(ChannelDataError::Length)?;
    Ok(ChannelData { channel, data })
}

/// Appends a `ChannelData` message carrying `data` on `channel` to `out`
/// (§12.4), padded to four bytes when `pad` is set, as a TCP stream needs
/// (§12.5; on UDP padding is optional). Data longer than the 16-bit
/// length field is an error and appends nothing.
pub fn frame_channel_data(
    channel: Channel,
    data: &[u8],
    pad: bool,
    out: &mut Vec<u8>,
) -> Result<(), ChannelDataError> {
    let length = u16::try_from(data.len()).map_err(|_| ChannelDataError::TooLong)?;
    out.extend_from_slice(&channel.number().to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(data);
    if pad {
        let padding = data.len().next_multiple_of(4).saturating_sub(data.len());
        out.extend(std::iter::repeat_n(0, padding));
    }
    Ok(())
}

/// Why a TCP stream from a TURN server cannot be split into messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// The next message is neither STUN nor `ChannelData`: the stream is out
    /// of step and the connection must be closed (§12, Table 3).
    #[error("neither stun nor channeldata on the turn stream")]
    Unframed,
}

/// The length of the next message on a TCP stream from a TURN server, of
/// which `buffered` holds the start, or `None` until its first four bytes
/// are there. STUN messages are their header plus the length field (RFC
/// 8489 §5, a multiple of four); `ChannelData` messages are their header plus
/// the length rounded up to four (§12.5). The length counts from the
/// stream position, so a reader takes exactly that many bytes next.
pub fn stream_frame_len(buffered: &[u8]) -> Result<Option<usize>, StreamError> {
    let Some(&[first, _, high, low]) = buffered.first_chunk::<4>() else {
        return Ok(None);
    };
    let length = usize::from(u16::from_be_bytes([high, low]));
    match kind(first) {
        Kind::Stun => Ok(Some(HEADER_LEN.saturating_add(length))),
        Kind::ChannelData => Ok(Some(
            CHANNEL_DATA_HEADER_LEN.saturating_add(length.next_multiple_of(4)),
        )),
        Kind::Other => Err(StreamError::Unframed),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::super::stun::{ATTR_ERROR_CODE, METHOD_BINDING, parse};
    use super::*;

    const ID: [u8; 12] = [9; 12];

    fn v4() -> SocketAddr {
        "192.0.2.10:40000".parse().unwrap()
    }

    fn v6() -> SocketAddr {
        "[2001:db8::10]:40001".parse().unwrap()
    }

    #[test]
    fn rfc8656_17_methods_encode_into_the_stun_type() {
        // Method 0x003 as a request is 0x0003; ChannelBind 0x009 as a
        // success response is 0x0109; Data 0x007 as an indication 0x0017.
        assert_eq!(allocate(ID, false).build()[..2], [0x00, 0x03]);
        let success = Builder::new(Class::Success, METHOD_CHANNEL_BIND, ID).build();
        assert_eq!(success[..2], [0x01, 0x09]);
        let data = Builder::new(Class::Indication, METHOD_DATA, ID).build();
        assert_eq!(data[..2], [0x00, 0x17]);
        let send = parse(&Builder::new(Class::Indication, METHOD_SEND, ID).build())
            .unwrap()
            .method;
        assert_eq!(send, 0x006);
    }

    #[test]
    fn rfc8656_7_1_allocate_asks_for_a_udp_relay() {
        let bytes = allocate(ID, false).build();
        let message = parse(&bytes).unwrap();
        assert_eq!(
            (message.class, message.method),
            (Class::Request, METHOD_ALLOCATE)
        );
        assert_eq!(message.transaction_id, ID);
        assert_eq!(
            message.attribute(ATTR_REQUESTED_TRANSPORT),
            Some(&[17, 0, 0, 0][..])
        );
        assert_eq!(message.attribute(ATTR_REQUESTED_ADDRESS_FAMILY), None);
        let software = message.attribute(ATTR_SOFTWARE).unwrap();
        assert!(software.starts_with(b"lotse "));
        assert!(software.len() < 128);
        let message_v6 = allocate(ID, true).build();
        let message_v6 = parse(&message_v6).unwrap();
        assert_eq!(
            message_v6.attribute(ATTR_REQUESTED_ADDRESS_FAMILY),
            Some(&[2, 0, 0, 0][..])
        );
    }

    #[test]
    fn rfc8656_8_1_refresh_carries_the_lifetime_and_zero_deletes() {
        let bytes = refresh(ID, Duration::from_secs(600)).build();
        let message = parse(&bytes).unwrap();
        assert_eq!(message.method, METHOD_REFRESH);
        assert_eq!(lifetime(&message), Some(Duration::from_secs(600)));
        assert!(message.attribute(ATTR_SOFTWARE).is_some());
        let delete = refresh(ID, Duration::ZERO).build();
        assert_eq!(lifetime(&parse(&delete).unwrap()), Some(Duration::ZERO));
        let huge = refresh(ID, Duration::from_secs(u64::MAX)).build();
        assert_eq!(
            lifetime(&parse(&huge).unwrap()),
            Some(Duration::from_secs(u64::from(u32::MAX)))
        );
        // Sub-second parts are dropped.
        let fraction = refresh(ID, Duration::from_millis(1999)).build();
        assert_eq!(
            lifetime(&parse(&fraction).unwrap()),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn rfc8656_18_2_a_lifetime_of_another_size_is_none() {
        let short = Builder::new(Class::Success, METHOD_REFRESH, ID)
            .attribute(ATTR_LIFETIME, &[0, 0, 2])
            .build();
        assert_eq!(lifetime(&parse(&short).unwrap()), None);
        let none = Builder::new(Class::Success, METHOD_REFRESH, ID).build();
        assert_eq!(lifetime(&parse(&none).unwrap()), None);
    }

    #[test]
    fn rfc8656_10_1_create_permission_lists_every_peer() {
        let bytes = create_permission(ID, &[v4(), "192.0.2.11:1".parse().unwrap()]).build();
        let message = parse(&bytes).unwrap();
        assert_eq!(message.method, METHOD_CREATE_PERMISSION);
        let peers = message
            .attributes
            .iter()
            .filter(|(t, _)| *t == ATTR_XOR_PEER_ADDRESS)
            .count();
        assert_eq!(peers, 2);
        assert_eq!(message.xor_address(ATTR_XOR_PEER_ADDRESS), Some(v4()));
        let none = create_permission(ID, &[]).build();
        assert_eq!(none.len(), HEADER_LEN);
    }

    #[test]
    fn rfc8656_12_1_channel_bind_names_channel_and_peer() {
        let channel = Channel::new(0x4001).unwrap();
        for peer in [v4(), v6()] {
            let bytes = channel_bind(ID, channel, peer).build();
            let message = parse(&bytes).unwrap();
            assert_eq!(message.method, METHOD_CHANNEL_BIND);
            assert_eq!(
                message.attribute(ATTR_CHANNEL_NUMBER),
                Some(&[0x40, 0x01, 0, 0][..])
            );
            assert_eq!(channel_number(&message), Some(channel));
            assert_eq!(message.xor_address(ATTR_XOR_PEER_ADDRESS), Some(peer));
        }
    }

    #[test]
    fn rfc8656_18_1_channel_number_ignores_rffu_and_checks_the_range() {
        let with = |value: &[u8]| {
            let bytes = Builder::new(Class::Request, METHOD_CHANNEL_BIND, ID)
                .attribute(ATTR_CHANNEL_NUMBER, value)
                .build();
            channel_number(&parse(&bytes).unwrap())
        };
        assert_eq!(with(&[0x4f, 0xff, 0xab, 0xcd]), Channel::new(0x4fff));
        assert_eq!(with(&[0x50, 0x00, 0, 0]), None, "reserved");
        assert_eq!(with(&[0x3f, 0xff, 0, 0]), None, "never a channel");
        assert_eq!(with(&[0x40, 0x00, 0]), None, "short");
        assert_eq!(with(&[0x40, 0x00, 0, 0, 0]), None, "long");
        let none = Builder::new(Class::Request, METHOD_CHANNEL_BIND, ID).build();
        assert_eq!(channel_number(&parse(&none).unwrap()), None);
    }

    #[test]
    fn rfc8656_12_the_bindable_range_is_0x4000_to_0x4fff() {
        assert_eq!(Channel::new(0x3fff), None);
        assert_eq!(Channel::new(0x4000), Some(Channel::MIN));
        assert_eq!(Channel::new(0x4fff), Some(Channel::MAX));
        assert_eq!(Channel::new(0x5000), None);
        assert_eq!(Channel::MIN.number(), 0x4000);
        assert_eq!(Channel::MAX.number(), 0x4fff);
    }

    #[test]
    fn rfc8656_7_3_the_relayed_address_of_a_success_response() {
        for relay in [v4(), v6()] {
            let bytes = Builder::new(Class::Success, METHOD_ALLOCATE, ID)
                .xor_address(ATTR_XOR_RELAYED_ADDRESS, relay)
                .xor_mapped_address("198.51.100.1:5000".parse().unwrap())
                .attribute(ATTR_LIFETIME, &600_u32.to_be_bytes())
                .build();
            let message = parse(&bytes).unwrap();
            assert_eq!(relayed_address(&message), Some(relay));
            assert_eq!(lifetime(&message), Some(Duration::from_secs(600)));
            assert_eq!(
                message.xor_mapped_address(),
                Some("198.51.100.1:5000".parse().unwrap())
            );
        }
        let bare = Builder::new(Class::Success, METHOD_ALLOCATE, ID).build();
        assert_eq!(relayed_address(&parse(&bare).unwrap()), None);
    }

    #[test]
    fn rfc8656_11_4_data_indications_yield_peer_and_data() {
        let bytes = Builder::new(Class::Indication, METHOD_DATA, ID)
            .xor_address(ATTR_XOR_PEER_ADDRESS, v6())
            .attribute(ATTR_DATA, b"hello")
            .build();
        let message = parse(&bytes).unwrap();
        assert_eq!(data_indication(&message), Some((v6(), &b"hello"[..])));
        // Without DATA (an ICMP report, §11.6) or without a peer: nothing.
        let no_data = Builder::new(Class::Indication, METHOD_DATA, ID)
            .xor_address(ATTR_XOR_PEER_ADDRESS, v4())
            .build();
        assert_eq!(data_indication(&parse(&no_data).unwrap()), None);
        let no_peer = Builder::new(Class::Indication, METHOD_DATA, ID)
            .attribute(ATTR_DATA, b"x")
            .build();
        assert_eq!(data_indication(&parse(&no_peer).unwrap()), None);
        // Another method or class: nothing.
        let send = Builder::new(Class::Indication, METHOD_SEND, ID)
            .xor_address(ATTR_XOR_PEER_ADDRESS, v4())
            .attribute(ATTR_DATA, b"x")
            .build();
        assert_eq!(data_indication(&parse(&send).unwrap()), None);
        let request = Builder::new(Class::Request, METHOD_DATA, ID)
            .xor_address(ATTR_XOR_PEER_ADDRESS, v4())
            .attribute(ATTR_DATA, b"x")
            .build();
        assert_eq!(data_indication(&parse(&request).unwrap()), None);
    }

    #[test]
    fn rfc8656_12_table_3_first_byte_demultiplexing() {
        for byte in 0..=255_u8 {
            let expected = match byte {
                0..=3 => Kind::Stun,
                64..=79 => Kind::ChannelData,
                _ => Kind::Other,
            };
            assert_eq!(kind(byte), expected, "{byte}");
        }
    }

    #[test]
    fn rfc8656_12_4_channel_data_round_trips_with_and_without_padding() {
        let channel = Channel::new(0x4abc).unwrap();
        for pad in [false, true] {
            for len in 0_usize..=9 {
                let data: Vec<u8> = (0..len).map(|i| u8::try_from(i).unwrap() + 1).collect();
                let mut out = vec![0xee];
                frame_channel_data(channel, &data, pad, &mut out).unwrap();
                let framed = &out[1..];
                assert_eq!(framed[..4], [0x4a, 0xbc, 0, u8::try_from(len).unwrap()]);
                let expected_len = if pad {
                    4 + len.next_multiple_of(4)
                } else {
                    4 + len
                };
                assert_eq!(framed.len(), expected_len, "pad {pad} len {len}");
                assert!(framed[4 + len..].iter().all(|&b| b == 0), "zero padding");
                let parsed = parse_channel_data(framed).unwrap();
                assert_eq!(
                    parsed,
                    ChannelData {
                        channel,
                        data: &data
                    }
                );
                assert_eq!(kind(framed[0]), Kind::ChannelData);
                assert_eq!(
                    stream_frame_len(framed),
                    Ok(Some(4 + len.next_multiple_of(4)))
                );
            }
        }
    }

    #[test]
    fn rfc8656_12_6_channel_data_receivers_discard_what_is_wrong() {
        assert_eq!(
            parse_channel_data(&[0x40, 0x00, 0x00]),
            Err(ChannelDataError::Short)
        );
        assert_eq!(
            parse_channel_data(&[0x50, 0x00, 0x00, 0x00]),
            Err(ChannelDataError::Channel),
            "reserved for DTLS-SRTP"
        );
        assert_eq!(
            parse_channel_data(&[0x3f, 0xff, 0x00, 0x00]),
            Err(ChannelDataError::Channel)
        );
        assert_eq!(
            parse_channel_data(&[0x40, 0x00, 0x00, 0x05, 1, 2, 3, 4]),
            Err(ChannelDataError::Length),
            "datagram shorter than the claimed length"
        );
        // Zero is a valid length.
        assert_eq!(
            parse_channel_data(&[0x40, 0x00, 0x00, 0x00]).unwrap().data,
            b""
        );
        let mut out = Vec::new();
        assert_eq!(
            frame_channel_data(Channel::MIN, &vec![0; 65536], true, &mut out),
            Err(ChannelDataError::TooLong)
        );
        assert!(out.is_empty());
        frame_channel_data(Channel::MIN, &vec![7; 65535], false, &mut out).unwrap();
        assert_eq!(parse_channel_data(&out).unwrap().data.len(), 65535);
        assert_eq!(
            ChannelDataError::Length.to_string(),
            "channeldata length exceeds the datagram"
        );
    }

    #[test]
    fn rfc8489_5_and_rfc8656_12_5_the_tcp_stream_splits_into_messages() {
        let stun = allocate(ID, false).build();
        let mut stream = stun.clone();
        frame_channel_data(Channel::MIN, b"abcde", true, &mut stream).unwrap();
        let error = Builder::new(Class::Error, METHOD_BINDING, ID)
            .attribute(ATTR_ERROR_CODE, &[0, 0, 4, 37])
            .build();
        stream.extend_from_slice(&error);
        let mut rest = &stream[..];
        let mut frames = Vec::new();
        while let Some(len) = stream_frame_len(rest).unwrap() {
            assert!(len >= 4, "every message has a header");
            let (frame, tail) = rest.split_at(len);
            frames.push(frame);
            rest = tail;
        }
        assert!(rest.is_empty());
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], &stun[..]);
        assert_eq!(parse_channel_data(frames[1]).unwrap().data, b"abcde");
        assert_eq!(frames[1].len(), 12);
        assert_eq!(frames[2], &error[..]);
        assert_eq!(stream_frame_len(&[]), Ok(None));
        assert_eq!(stream_frame_len(&[0x40, 0, 0]), Ok(None));
        assert_eq!(
            stream_frame_len(&[0x00, 0x01, 0xff, 0xfc]),
            Ok(Some(20 + 0xfffc))
        );
        assert_eq!(
            stream_frame_len(&[0x4f, 0xff, 0xff, 0xff]),
            Ok(Some(4 + 0x1_0000))
        );
        assert_eq!(
            stream_frame_len(&[0x16, 3, 1, 0]),
            Err(StreamError::Unframed)
        );
        assert_eq!(
            StreamError::Unframed.to_string(),
            "neither stun nor channeldata on the turn stream"
        );
    }
}
