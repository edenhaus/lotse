//! STUN messages, the subset ICE and the TURN client need from the
//! supervisor: parse a request or response, read USERNAME and the
//! XOR-encoded addresses, verify MESSAGE-INTEGRITY with a session's ICE
//! password or a long-term key, MESSAGE-INTEGRITY-SHA256 and FINGERPRINT,
//! and build the Binding Request of the server-reflexive gathering and the
//! TURN requests on top of [`Builder`].
//!
//! Implements RFC 8489 §5 (header), §14 (attribute format), §14.2
//! (XOR-MAPPED-ADDRESS, also the encoding of TURN's XOR-PEER-ADDRESS and
//! XOR-RELAYED-ADDRESS, RFC 8656 §18.3, §18.5), §14.3 (USERNAME), §14.5
//! (MESSAGE-INTEGRITY; with short-term credentials RFC 8445 §7.2.2 makes
//! the ICE password the key, with long-term ones `credential` derives it),
//! §14.6 (MESSAGE-INTEGRITY-SHA256), §14.7 (FINGERPRINT), §14.8
//! (ERROR-CODE); the fingerprint's CRC-32 is ISO 3309 as RFC 1952 §8
//! tabulates it. Every byte here comes from the network, so the parser is
//! total and fuzzed (`stun_message`, `turn_message`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

/// The magic cookie of RFC 8489 §5.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// The header length (§5).
pub const HEADER_LEN: usize = 20;

/// The Binding method (§18.3.1).
pub const METHOD_BINDING: u16 = 0x0001;

/// USERNAME (§14.3).
pub const ATTR_USERNAME: u16 = 0x0006;
/// MESSAGE-INTEGRITY (§14.5).
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
/// ERROR-CODE (§14.8).
pub const ATTR_ERROR_CODE: u16 = 0x0009;
/// REALM (§14.9, §18.3.1).
pub const ATTR_REALM: u16 = 0x0014;
/// NONCE (§14.10, §18.3.1).
pub const ATTR_NONCE: u16 = 0x0015;
/// MESSAGE-INTEGRITY-SHA256 (§14.6, §18.3.2).
pub const ATTR_MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
/// PASSWORD-ALGORITHM (§14.12, §18.3.2).
pub const ATTR_PASSWORD_ALGORITHM: u16 = 0x001D;
/// USERHASH (§14.4, §18.3.2).
pub const ATTR_USERHASH: u16 = 0x001E;
/// XOR-MAPPED-ADDRESS (§14.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// PASSWORD-ALGORITHMS (§14.11, §18.3.2).
pub const ATTR_PASSWORD_ALGORITHMS: u16 = 0x8002;
/// SOFTWARE (§14.14, §18.3.1).
pub const ATTR_SOFTWARE: u16 = 0x8022;
/// FINGERPRINT (§14.7).
pub const ATTR_FINGERPRINT: u16 = 0x8028;

/// The length of a MESSAGE-INTEGRITY value, an HMAC-SHA1 (§14.5).
const INTEGRITY_LEN: usize = 20;
/// The length of a full MESSAGE-INTEGRITY-SHA256 value (§14.6).
const INTEGRITY_SHA256_LEN: usize = 32;
/// The shortest MESSAGE-INTEGRITY-SHA256 value a sender may truncate to
/// (§14.6: at least 16 bytes and a multiple of 4).
const INTEGRITY_SHA256_MIN: usize = 16;

/// The value `XOR`ed into the fingerprint (§14.7).
const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// The class of a message (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A request.
    Request,
    /// An indication.
    Indication,
    /// A success response.
    Success,
    /// An error response.
    Error,
}

/// Why bytes are not a STUN message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    /// Shorter than the header.
    #[error("shorter than the stun header")]
    Short,
    /// The first two bits are not zero.
    #[error("not a stun message: first bits set")]
    NotStun,
    /// The magic cookie is missing.
    #[error("not a stun message: no magic cookie")]
    NoCookie,
    /// The length field disagrees with the bytes.
    #[error("message length does not match")]
    Length,
    /// An attribute runs past the end.
    #[error("attribute truncated")]
    Attribute,
}

/// A parsed message; attribute values borrow the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// The class.
    pub class: Class,
    /// The method (Binding is the only one ICE uses).
    pub method: u16,
    /// The transaction id.
    pub transaction_id: [u8; 12],
    /// Attributes in order, with their raw values.
    pub attributes: Vec<(u16, &'a [u8])>,
    /// Where the MESSAGE-INTEGRITY attribute starts, if present.
    integrity_at: Option<usize>,
    /// Where the MESSAGE-INTEGRITY-SHA256 attribute starts, if present.
    integrity_sha256_at: Option<usize>,
    /// Where the FINGERPRINT attribute starts, if present.
    fingerprint_at: Option<usize>,
}

/// A quick look: could these bytes be a STUN message?
pub fn is_stun(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_LEN
        && bytes.first().is_some_and(|b| b & 0xc0 == 0)
        && bytes.get(4..8) == Some(&MAGIC_COOKIE.to_be_bytes())
}

/// Reads a big-endian `u16`.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at.checked_add(2)?)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_be_bytes)
}

/// Parses `bytes` (§5, §14.1).
pub fn parse(bytes: &[u8]) -> Result<Message<'_>, StunError> {
    if bytes.len() < HEADER_LEN {
        return Err(StunError::Short);
    }
    let kind = u16_at(bytes, 0).ok_or(StunError::Short)?;
    if kind & 0xc000 != 0 {
        return Err(StunError::NotStun);
    }
    if bytes.get(4..8) != Some(&MAGIC_COOKIE.to_be_bytes()) {
        return Err(StunError::NoCookie);
    }
    let length = usize::from(u16_at(bytes, 2).ok_or(StunError::Short)?);
    if length != bytes.len().saturating_sub(HEADER_LEN) || !length.is_multiple_of(4) {
        return Err(StunError::Length);
    }
    let class = match ((kind >> 4) & 0x01, (kind >> 8) & 0x01) {
        (0, 0) => Class::Request,
        (1, 0) => Class::Indication,
        (0, _) => Class::Success,
        _ => Class::Error,
    };
    let method = (kind & 0x000f) | ((kind & 0x00e0) >> 1) | ((kind & 0x3e00) >> 2);
    let transaction_id: [u8; 12] = bytes
        .get(8..20)
        .and_then(|b| <[u8; 12]>::try_from(b).ok())
        .ok_or(StunError::Short)?;
    let mut attributes = Vec::new();
    let mut integrity_at = None;
    let mut integrity_sha256_at = None;
    let mut fingerprint_at = None;
    let mut at = HEADER_LEN;
    while at < bytes.len() {
        let attr_type = u16_at(bytes, at).ok_or(StunError::Attribute)?;
        let attr_len =
            usize::from(u16_at(bytes, at.saturating_add(2)).ok_or(StunError::Attribute)?);
        let value_at = at.saturating_add(4);
        let value = bytes
            .get(value_at..value_at.saturating_add(attr_len))
            .ok_or(StunError::Attribute)?;
        match attr_type {
            ATTR_MESSAGE_INTEGRITY if integrity_at.is_none() => integrity_at = Some(at),
            ATTR_MESSAGE_INTEGRITY_SHA256 if integrity_sha256_at.is_none() => {
                integrity_sha256_at = Some(at);
            }
            ATTR_FINGERPRINT if fingerprint_at.is_none() => fingerprint_at = Some(at),
            _ => {}
        }
        attributes.push((attr_type, value));
        at = value_at.saturating_add(attr_len.div_ceil(4).saturating_mul(4));
    }
    Ok(Message {
        class,
        method,
        transaction_id,
        attributes,
        integrity_at,
        integrity_sha256_at,
        fingerprint_at,
    })
}

impl<'a> Message<'a> {
    /// The first attribute of `attr_type` (§14: only the first occurrence
    /// needs processing).
    pub fn attribute(&self, attr_type: u16) -> Option<&'a [u8]> {
        self.attributes
            .iter()
            .find(|(t, _)| *t == attr_type)
            .map(|(_, v)| *v)
    }

    /// A Binding Request.
    pub fn is_binding_request(&self) -> bool {
        self.class == Class::Request && self.method == METHOD_BINDING
    }

    /// USERNAME as text (§14.3).
    pub fn username(&self) -> Option<&str> {
        self.attribute(ATTR_USERNAME)
            .and_then(|v| std::str::from_utf8(v).ok())
    }

    /// The local part of an ICE USERNAME, `local:remote` (RFC 8445 §7.2.2).
    pub fn local_ufrag(&self) -> Option<&str> {
        self.username()?.split_once(':').map(|(local, _)| local)
    }

    /// XOR-MAPPED-ADDRESS decoded (§14.2).
    pub fn xor_mapped_address(&self) -> Option<SocketAddr> {
        self.xor_address(ATTR_XOR_MAPPED_ADDRESS)
    }

    /// An attribute of `attr_type` encoded as XOR-MAPPED-ADDRESS is (§14.2;
    /// RFC 8656 §18.3 XOR-PEER-ADDRESS and §18.5 XOR-RELAYED-ADDRESS are).
    pub fn xor_address(&self, attr_type: u16) -> Option<SocketAddr> {
        let value = self.attribute(attr_type)?;
        let family = *value.get(1)?;
        let port = u16_at(value, 2)? ^ u16::try_from(MAGIC_COOKIE >> 16).ok()?;
        let ip = match family {
            0x01 => {
                let raw: [u8; 4] = value.get(4..8)?.try_into().ok()?;
                let x = u32::from_be_bytes(raw) ^ MAGIC_COOKIE;
                IpAddr::V4(Ipv4Addr::from(x))
            }
            0x02 => {
                let raw: [u8; 16] = value.get(4..20)?.try_into().ok()?;
                let mut key = [0_u8; 16];
                key.get_mut(..4)?
                    .copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                key.get_mut(4..)?.copy_from_slice(&self.transaction_id);
                let mut octets = [0_u8; 16];
                for (i, out) in octets.iter_mut().enumerate() {
                    *out = raw.get(i).copied().unwrap_or(0) ^ key.get(i).copied().unwrap_or(0);
                }
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// ERROR-CODE as the number and its reason (§14.8).
    pub fn error_code(&self) -> Option<(u16, &str)> {
        let value = self.attribute(ATTR_ERROR_CODE)?;
        let class = u16::from(*value.get(2)? & 0x07);
        let number = u16::from(*value.get(3)?);
        let reason = std::str::from_utf8(value.get(4..)?).ok()?;
        Some((class.saturating_mul(100).saturating_add(number), reason))
    }

    /// Whether the MESSAGE-INTEGRITY attribute, present, matches `key`
    /// (§14.5): HMAC-SHA1 over the message up to the attribute, with the
    /// header's length set as if the message ended right after it. The key
    /// is the ICE password for short-term credentials (§9.1.1) and the
    /// derived long-term key otherwise (§9.2.2). A message without the
    /// attribute never verifies.
    pub fn verify_integrity(&self, bytes: &[u8], key: &[u8]) -> bool {
        let Some(at) = self.integrity_at else {
            return false;
        };
        let Some(expected) = value_at(bytes, at).filter(|v| v.len() == INTEGRITY_LEN) else {
            return false;
        };
        covered_mac::<Hmac<Sha1>>(bytes, at, INTEGRITY_LEN, key)
            .is_some_and(|mac| mac.verify_slice(expected).is_ok())
    }

    /// Whether the MESSAGE-INTEGRITY-SHA256 attribute, present, matches
    /// `key` (§14.6): HMAC-SHA256 computed as for MESSAGE-INTEGRITY, of
    /// which the attribute may carry an initial portion of 16 to 32 bytes
    /// in steps of 4. A message without the attribute, or with a value of
    /// another length, never verifies.
    pub fn verify_integrity_sha256(&self, bytes: &[u8], key: &[u8]) -> bool {
        let Some(at) = self.integrity_sha256_at else {
            return false;
        };
        let Some(expected) = value_at(bytes, at).filter(|v| {
            (INTEGRITY_SHA256_MIN..=INTEGRITY_SHA256_LEN).contains(&v.len())
                && v.len().is_multiple_of(4)
        }) else {
            return false;
        };
        covered_mac::<Hmac<Sha256>>(bytes, at, expected.len(), key)
            .is_some_and(|mac| mac.verify_truncated_left(expected).is_ok())
    }

    /// Whether the FINGERPRINT attribute, when present, matches (§14.7);
    /// `true` when absent, since the extension is optional.
    pub fn fingerprint_ok(&self, bytes: &[u8]) -> bool {
        let Some(at) = self.fingerprint_at else {
            return true;
        };
        // Bytes other than the parsed ones may end before the attribute's
        // value does.
        let Some((covered, value)) = bytes.split_at_checked(at).and_then(|(covered, attribute)| {
            let value = <[u8; 4]>::try_from(attribute.get(4..8)?).ok()?;
            Some((covered, value))
        }) else {
            return false;
        };
        fingerprint_of(covered, at.saturating_add(8)) == u32::from_be_bytes(value)
    }
}

/// The value of the attribute that starts at `at` in `bytes`.
fn value_at(bytes: &[u8], at: usize) -> Option<&[u8]> {
    let len = usize::from(u16_at(bytes, at.checked_add(2)?)?);
    let start = at.checked_add(4)?;
    bytes.get(start..start.checked_add(len)?)
}

/// An HMAC under `key` fed what an integrity attribute starting at `at`
/// with a value of `value_len` bytes covers (§14.5, §14.6): the message up
/// to the attribute, with the header's length set as if the message ended
/// right after it. `None` when `at` is not past the header or the key is
/// unusable.
fn covered_mac<M: Mac + KeyInit>(
    bytes: &[u8],
    at: usize,
    value_len: usize,
    key: &[u8],
) -> Option<M> {
    let header = bytes.get(..HEADER_LEN)?;
    let body = bytes.get(HEADER_LEN..at)?;
    let end = at.checked_add(4)?.checked_add(value_len)?;
    let adjusted = u16::try_from(end.checked_sub(HEADER_LEN)?).ok()?;
    let mut mac = <M as KeyInit>::new_from_slice(key).ok()?;
    mac.update(header.get(..2)?);
    mac.update(&adjusted.to_be_bytes());
    mac.update(header.get(4..)?);
    mac.update(body);
    Some(mac)
}

/// The fingerprint of a message whose header claims `total_len` bytes
/// after the attribute: CRC-32 over the bytes with the adjusted length,
/// `XOR`ed with the constant (§14.7).
fn fingerprint_of(covered: &[u8], total_len: usize) -> u32 {
    let adjusted = u16::try_from(total_len.saturating_sub(HEADER_LEN)).unwrap_or(u16::MAX);
    let mut crc = Crc32::new();
    crc.update(covered.get(..2).unwrap_or(&[]));
    crc.update(&adjusted.to_be_bytes());
    crc.update(covered.get(4..).unwrap_or(&[]));
    crc.finish() ^ FINGERPRINT_XOR
}

/// CRC-32 (ISO 3309, reflected, polynomial `0xedb88320`) as RFC 1952 §8
/// tabulates it.
struct Crc32(u32);

impl Crc32 {
    /// Ready for the first byte.
    const fn new() -> Self {
        Self(0xffff_ffff)
    }

    /// Feeds `bytes`.
    fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u32::from(byte);
            for _ in 0..8 {
                self.0 = if self.0 & 1 == 1 {
                    (self.0 >> 1) ^ 0xedb8_8320
                } else {
                    self.0 >> 1
                };
            }
        }
    }

    /// The checksum.
    const fn finish(&self) -> u32 {
        self.0 ^ 0xffff_ffff
    }
}

/// Builds a message: header, attributes, then MESSAGE-INTEGRITY or
/// MESSAGE-INTEGRITY-SHA256 with a key and FINGERPRINT when asked.
#[derive(Debug, Clone)]
pub struct Builder {
    /// The bytes so far.
    bytes: Vec<u8>,
}

impl Builder {
    /// A message of `class` and `method` with `transaction_id`.
    pub fn new(class: Class, method: u16, transaction_id: [u8; 12]) -> Self {
        let class_bits: u16 = match class {
            Class::Request => 0x0000,
            Class::Indication => 0x0010,
            Class::Success => 0x0100,
            Class::Error => 0x0110,
        };
        let method_bits = (method & 0x000f) | ((method & 0x0070) << 1) | ((method & 0x0f80) << 2);
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&(class_bits | method_bits).to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&transaction_id);
        Self { bytes }
    }

    /// Appends one attribute, padded to four bytes (§14.1).
    #[must_use]
    pub fn attribute(mut self, attr_type: u16, value: &[u8]) -> Self {
        self.bytes.extend_from_slice(&attr_type.to_be_bytes());
        self.bytes
            .extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        self.bytes.extend_from_slice(value);
        let padding = value
            .len()
            .div_ceil(4)
            .saturating_mul(4)
            .saturating_sub(value.len());
        self.bytes.extend(std::iter::repeat_n(0, padding));
        self.set_length();
        self
    }

    /// USERNAME (§14.3).
    #[must_use]
    pub fn username(self, username: &str) -> Self {
        self.attribute(ATTR_USERNAME, username.as_bytes())
    }

    /// XOR-MAPPED-ADDRESS (§14.2).
    #[must_use]
    pub fn xor_mapped_address(self, addr: SocketAddr) -> Self {
        self.xor_address(ATTR_XOR_MAPPED_ADDRESS, addr)
    }

    /// An attribute of `attr_type` encoded as XOR-MAPPED-ADDRESS (§14.2;
    /// RFC 8656 §18.3 XOR-PEER-ADDRESS).
    #[must_use]
    pub fn xor_address(self, attr_type: u16, addr: SocketAddr) -> Self {
        let transaction_id: [u8; 12] = self
            .bytes
            .get(8..20)
            .and_then(|b| <[u8; 12]>::try_from(b).ok())
            .unwrap_or([0; 12]);
        let mut value = vec![0, 0];
        let port = addr.port() ^ u16::try_from(MAGIC_COOKIE >> 16).unwrap_or(0);
        value.extend_from_slice(&port.to_be_bytes());
        match addr.ip() {
            IpAddr::V4(ip) => {
                value.splice(1..2, [0x01]);
                value.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes());
            }
            IpAddr::V6(ip) => {
                value.splice(1..2, [0x02]);
                let mut key = [0_u8; 16];
                if let Some(head) = key.get_mut(..4) {
                    head.copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                }
                if let Some(tail) = key.get_mut(4..) {
                    tail.copy_from_slice(&transaction_id);
                }
                value.extend(ip.octets().iter().zip(key.iter()).map(|(a, k)| a ^ k));
            }
        }
        self.attribute(attr_type, &value)
    }

    /// MESSAGE-INTEGRITY over everything so far (§14.5), HMAC-SHA1 under
    /// `key`.
    #[must_use]
    pub fn integrity(self, key: &[u8]) -> Self {
        let digest = self.mac::<Hmac<Sha1>>(INTEGRITY_LEN, key);
        self.attribute(ATTR_MESSAGE_INTEGRITY, &digest)
    }

    /// MESSAGE-INTEGRITY-SHA256 over everything so far (§14.6), the full 32
    /// bytes of HMAC-SHA256 under `key`.
    #[must_use]
    pub fn integrity_sha256(self, key: &[u8]) -> Self {
        let digest = self.mac::<Hmac<Sha256>>(INTEGRITY_SHA256_LEN, key);
        self.attribute(ATTR_MESSAGE_INTEGRITY_SHA256, &digest)
    }

    /// The HMAC an integrity attribute of `len` bytes appended now carries,
    /// or zeros (which never verify) when the key is unusable; HMAC takes
    /// keys of any length, so that does not happen.
    fn mac<M: Mac + KeyInit>(&self, len: usize, key: &[u8]) -> Vec<u8> {
        covered_mac::<M>(&self.bytes, self.bytes.len(), len, key)
            .map_or_else(|| vec![0; len], |mac| mac.finalize().into_bytes().to_vec())
    }

    /// FINGERPRINT over everything so far (§14.7); must come last.
    #[must_use]
    pub fn fingerprint(mut self) -> Self {
        let total = self.bytes.len().saturating_add(8);
        let value = fingerprint_of(&self.bytes, total);
        self.bytes
            .extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        self.bytes.extend_from_slice(&4_u16.to_be_bytes());
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self.set_length();
        self
    }

    /// The bytes.
    pub fn build(self) -> Vec<u8> {
        self.bytes
    }

    /// Keeps the header's length field current.
    fn set_length(&mut self) {
        let length = u16::try_from(self.bytes.len().saturating_sub(HEADER_LEN)).unwrap_or(u16::MAX);
        if let Some(field) = self.bytes.get_mut(2..4) {
            field.copy_from_slice(&length.to_be_bytes());
        }
    }
}

/// The Binding Request of a server-reflexive gathering: no attributes
/// (RFC 8489 §7.2, a request to a public server needs none).
pub fn binding_request(transaction_id: [u8; 12]) -> Vec<u8> {
    Builder::new(Class::Request, METHOD_BINDING, transaction_id).build()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    /// RFC 5769 §2.1: a Binding Request with SOFTWARE, PRIORITY,
    /// ICE-CONTROLLED, USERNAME, MESSAGE-INTEGRITY and FINGERPRINT.
    const REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74,
        0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e,
        0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
        0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20,
        0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e,
        0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5,
        0x7a, 0x3b, 0xcf,
    ];

    /// RFC 5769 §2.2: the IPv4 Binding Response.
    const RESPONSE: &[u8] = &[
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76,
        0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1,
        0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
        0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00,
        0x04, 0xc0, 0x7d, 0x4c, 0x96,
    ];

    const PASSWORD: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";
    const TRANSACTION: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    #[test]
    fn the_rfc5769_request_parses_and_verifies() {
        assert!(is_stun(REQUEST));
        let message = parse(REQUEST).unwrap();
        assert!(message.is_binding_request());
        assert_eq!(message.transaction_id, TRANSACTION);
        assert_eq!(message.username(), Some("evtj:h6vY"));
        assert_eq!(message.local_ufrag(), Some("evtj"));
        assert_eq!(message.attributes.len(), 6);
        assert!(message.verify_integrity(REQUEST, PASSWORD));
        assert!(!message.verify_integrity(REQUEST, b"wrong"));
        assert!(message.fingerprint_ok(REQUEST));
        let mut tampered = REQUEST.to_vec();
        tampered[30] ^= 0x01;
        let message = parse(&tampered).unwrap();
        assert!(!message.verify_integrity(&tampered, PASSWORD));
        assert!(!message.fingerprint_ok(&tampered));
        // Bytes that end inside the FINGERPRINT attribute, or before it,
        // do not match (RFC 8489 §14.7).
        let message = parse(REQUEST).unwrap();
        assert!(!message.fingerprint_ok(&REQUEST[..REQUEST.len() - 1]));
        assert!(!message.fingerprint_ok(&REQUEST[..HEADER_LEN]));
        assert!(message.xor_mapped_address().is_none());
        assert!(message.error_code().is_none());
    }

    #[test]
    fn the_rfc5769_response_yields_the_mapped_address() {
        let message = parse(RESPONSE).unwrap();
        assert_eq!(message.class, Class::Success);
        assert_eq!(message.method, METHOD_BINDING);
        assert_eq!(
            message.xor_mapped_address(),
            Some("192.0.2.1:32853".parse().unwrap())
        );
        assert!(message.verify_integrity(RESPONSE, PASSWORD));
        assert!(message.fingerprint_ok(RESPONSE));
    }

    /// A message past the 16-bit length of the header (RFC 8489 §5) has no
    /// length MESSAGE-INTEGRITY can cover: its value is zeros, which never
    /// verify.
    #[test]
    fn rfc8489_5_a_message_too_long_for_its_length_gets_an_integrity_of_zeros() {
        let big = vec![7_u8; 40_000];
        let bytes = Builder::new(Class::Request, METHOD_BINDING, TRANSACTION)
            .attribute(0x8030, &big)
            .attribute(0x8030, &big)
            .integrity(b"pass")
            .build();
        assert_eq!(&bytes[bytes.len() - INTEGRITY_LEN..], [0; INTEGRITY_LEN]);
    }

    #[test]
    fn built_messages_round_trip_with_integrity_and_fingerprint() {
        let v6: SocketAddr = "[2001:db8::7]:4242".parse().unwrap();
        let bytes = Builder::new(Class::Success, METHOD_BINDING, TRANSACTION)
            .xor_mapped_address(v6)
            .integrity(b"pass")
            .fingerprint()
            .build();
        let message = parse(&bytes).unwrap();
        assert_eq!(message.xor_mapped_address(), Some(v6));
        assert!(message.verify_integrity(&bytes, b"pass"));
        assert!(message.fingerprint_ok(&bytes));
        let request = Builder::new(Class::Request, METHOD_BINDING, [1; 12])
            .username("abcd:efgh")
            .integrity(b"secret")
            .fingerprint()
            .build();
        let message = parse(&request).unwrap();
        assert!(message.is_binding_request());
        assert_eq!(message.local_ufrag(), Some("abcd"));
        assert!(message.verify_integrity(&request, b"secret"));
        assert!(!message.verify_integrity(&request, b"other"));
        // A bare gathering request has no attributes and no integrity to verify.
        let bare = binding_request([2; 12]);
        assert_eq!(bare.len(), HEADER_LEN);
        let message = parse(&bare).unwrap();
        assert!(!message.verify_integrity(&bare, b"x"));
        assert!(message.fingerprint_ok(&bare));
        let error = Builder::new(Class::Error, METHOD_BINDING, [3; 12])
            .attribute(
                ATTR_ERROR_CODE,
                &[0, 0, 4, 1, b'U', b'n', b'a', b'u', b't', b'h'],
            )
            .build();
        let message = parse(&error).unwrap();
        assert_eq!(message.class, Class::Error);
        assert_eq!(message.error_code(), Some((401, "Unauth")));
    }

    #[test]
    fn rfc8489_14_8_an_error_code_without_a_reason_phrase_reads() {
        // coturn 4.18.0 sends its 401, 437 and 438 so (observed 2026-10-02).
        let error = Builder::new(Class::Error, METHOD_BINDING, [3; 12])
            .attribute(ATTR_ERROR_CODE, &[0, 0, 4, 38])
            .build();
        assert_eq!(parse(&error).unwrap().error_code(), Some((438, "")));
    }

    #[test]
    fn rfc8489_14_6_truncated_sha256_integrity_of_16_to_32_bytes_in_steps_of_4() {
        let full = Builder::new(Class::Request, METHOD_BINDING, TRANSACTION)
            .username("u")
            .integrity_sha256(b"key")
            .build();
        let message = parse(&full).unwrap();
        assert!(message.verify_integrity_sha256(&full, b"key"));
        assert!(!message.verify_integrity_sha256(&full, b"other"));
        let digest = message
            .attribute(ATTR_MESSAGE_INTEGRITY_SHA256)
            .unwrap()
            .to_vec();
        assert_eq!(digest.len(), 32);
        let unsigned = Builder::new(Class::Request, METHOD_BINDING, TRANSACTION).username("u");
        // A truncated value is the initial portion of the HMAC computed with
        // the length adjusted to the shorter attribute.
        for len in [16, 20, 24, 28, 32] {
            let at = unsigned.clone().build().len();
            let end = u16::try_from(at + 4 + len - HEADER_LEN).unwrap();
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"key").unwrap();
            let base = unsigned.clone().build();
            mac.update(&base[..2]);
            mac.update(&end.to_be_bytes());
            mac.update(&base[4..]);
            let tag = mac.finalize().into_bytes();
            let bytes = unsigned
                .clone()
                .attribute(ATTR_MESSAGE_INTEGRITY_SHA256, &tag[..len])
                .build();
            let message = parse(&bytes).unwrap();
            assert!(message.verify_integrity_sha256(&bytes, b"key"), "{len}");
        }
        // A real HMAC prefix of a length that is not a multiple of 4 does
        // not count either.
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"key").unwrap();
        let base = unsigned.clone().build();
        let end = u16::try_from(base.len() + 4 + 18 - HEADER_LEN).unwrap();
        mac.update(&base[..2]);
        mac.update(&end.to_be_bytes());
        mac.update(&base[4..]);
        let tag = mac.finalize().into_bytes();
        let odd = unsigned
            .clone()
            .attribute(ATTR_MESSAGE_INTEGRITY_SHA256, &tag[..18])
            .build();
        assert!(!parse(&odd).unwrap().verify_integrity_sha256(&odd, b"key"));
        // Only the first MESSAGE-INTEGRITY-SHA256 counts.
        let twice = unsigned
            .clone()
            .integrity_sha256(b"key")
            .attribute(ATTR_MESSAGE_INTEGRITY_SHA256, &[0; 32])
            .build();
        assert!(
            parse(&twice)
                .unwrap()
                .verify_integrity_sha256(&twice, b"key")
        );
        for len in [0, 4, 12, 18, 36] {
            let bytes = unsigned
                .clone()
                .attribute(ATTR_MESSAGE_INTEGRITY_SHA256, &vec![0; len])
                .build();
            assert!(
                !parse(&bytes)
                    .unwrap()
                    .verify_integrity_sha256(&bytes, b"key"),
                "{len}"
            );
        }
        // MESSAGE-INTEGRITY takes exactly 20 bytes.
        let signed = unsigned.clone().integrity(b"key").build();
        let mut short = signed.clone();
        short.truncate(short.len() - 4);
        short[HEADER_LEN + 8 + 2..HEADER_LEN + 8 + 4].copy_from_slice(&16_u16.to_be_bytes());
        let length = u16::try_from(short.len() - HEADER_LEN).unwrap();
        short[2..4].copy_from_slice(&length.to_be_bytes());
        assert!(parse(&signed).unwrap().verify_integrity(&signed, b"key"));
        assert!(!parse(&short).unwrap().verify_integrity(&short, b"key"));
        // A message without the attribute never verifies.
        let without = unsigned.build();
        assert!(
            !parse(&without)
                .unwrap()
                .verify_integrity_sha256(&without, b"key")
        );
        // Both attributes in one message verify independently.
        let both = Builder::new(Class::Request, METHOD_BINDING, TRANSACTION)
            .integrity(b"k1")
            .integrity_sha256(b"k2")
            .fingerprint()
            .build();
        let message = parse(&both).unwrap();
        assert!(message.verify_integrity(&both, b"k1"));
        assert!(message.verify_integrity_sha256(&both, b"k2"));
        assert!(message.fingerprint_ok(&both));
    }

    #[test]
    fn rfc8489_14_2_any_attribute_can_carry_an_xor_address() {
        let v4: SocketAddr = "203.0.113.5:9".parse().unwrap();
        let bytes = Builder::new(Class::Success, METHOD_BINDING, TRANSACTION)
            .xor_address(0x0016, v4)
            .build();
        let message = parse(&bytes).unwrap();
        assert_eq!(message.xor_address(0x0016), Some(v4));
        assert_eq!(message.xor_mapped_address(), None);
        assert_eq!(message.attribute(0x0016).map(<[u8]>::len), Some(8));
        // An unknown address family, or a value too short for its family,
        // is no address.
        for value in [
            &[0, 3, 0, 9, 1, 2, 3, 4][..],
            &[0, 1, 0, 9, 1, 2, 3],
            &[0, 2, 0, 9, 1, 2, 3, 4],
        ] {
            let bytes = Builder::new(Class::Success, METHOD_BINDING, TRANSACTION)
                .attribute(0x0016, value)
                .build();
            assert_eq!(parse(&bytes).unwrap().xor_address(0x0016), None);
        }
    }

    #[test]
    fn broken_input_is_an_error_never_a_panic() {
        assert_eq!(parse(&[]), Err(StunError::Short));
        assert_eq!(parse(&[0x80; 20]), Err(StunError::NotStun));
        assert!(!is_stun(&[0x80; 20]));
        let mut no_cookie = REQUEST.to_vec();
        no_cookie[4] = 0;
        assert_eq!(parse(&no_cookie), Err(StunError::NoCookie));
        let mut bad_len = REQUEST.to_vec();
        bad_len[3] = 0x57;
        assert_eq!(parse(&bad_len), Err(StunError::Length));
        let mut truncated = REQUEST[..24].to_vec();
        truncated[3] = 4;
        truncated[23] = 0xff;
        assert_eq!(parse(&truncated), Err(StunError::Attribute));
        assert_eq!(StunError::Short.to_string(), "shorter than the stun header");
        assert_eq!(Crc32::new().finish(), 0);
        let mut crc = Crc32::new();
        crc.update(b"123456789");
        assert_eq!(crc.finish(), 0xcbf4_3926, "the CRC-32 check value");
    }
}
