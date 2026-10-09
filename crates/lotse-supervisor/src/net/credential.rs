//! The long-term credential mechanism of STUN, as the TURN client uses it
//! to authenticate its requests: read the server's challenge (a 401 or 438
//! error with REALM and NONCE), derive the key from the `ice_servers`
//! username and credential, sign every later request and check the
//! integrity of the responses.
//!
//! Implements RFC 8489 §9.2 (the nonce cookie and its security features,
//! §18.1), §9.2.2 (the key), §9.2.3.2 (subsequent requests), §9.2.5
//! (receiving a 401 or 438, the bid-down checks, response integrity),
//! §14.4 (USERHASH), §14.11 and §14.12 (PASSWORD-ALGORITHMS,
//! PASSWORD-ALGORITHM), §18.5.1 (the MD5 and SHA-256 algorithms), and RFC
//! 8656 §6 (SHA-256 wins when a server offers both). The nonce cookie's
//! features are base64 (RFC 4648 §4). The challenge comes from the network
//! unauthenticated, so its parser is total and fuzzed (`turn_message`).

use std::fmt;

use lotse_core::secret::Secret;
use md5::{Digest as _, Md5};
use sha2::Sha256;

use super::stun::{
    ATTR_NONCE, ATTR_PASSWORD_ALGORITHM, ATTR_PASSWORD_ALGORITHMS, ATTR_REALM, ATTR_USERHASH,
    ATTR_USERNAME, Builder, Class, Message,
};

/// The prefix of a NONCE from a server that implements RFC 8489 (§9.2).
const NONCE_COOKIE: &str = "obMatJos2";

/// The base64 characters after the cookie that carry the 24 security
/// feature bits (§9.2).
const FEATURES_LEN: usize = 4;

/// The "Password algorithms" bit, bit 0 (§18.1), the least significant of
/// the 24 and so of the last base64 character (Errata 6290).
const FEATURE_PASSWORD_ALGORITHMS: u8 = 0b01;

/// The "Username anonymity" bit, bit 1 (§18.1, Errata 6290).
const FEATURE_USERNAME_ANONYMITY: u8 = 0b10;

/// The longest REALM or NONCE a receiver must decode: fewer than 128
/// characters, up to 763 bytes (§14.9, §14.10). Longer ones are refused,
/// which also bounds what a signed request repeats.
const MAX_TEXT_LEN: usize = 763;

/// 401 (Unauthenticated) (§14.8).
pub const ERROR_UNAUTHENTICATED: u16 = 401;

/// 438 (Stale Nonce) (§14.8).
pub const ERROR_STALE_NONCE: u16 = 438;

/// A password algorithm of the "STUN Password Algorithms" registry (§18.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgorithm {
    /// MD5, `0x0001`, a 16-byte key (§18.5.1.1).
    Md5,
    /// SHA-256, `0x0002`, a 32-byte key (§18.5.1.2).
    Sha256,
}

impl PasswordAlgorithm {
    /// The registry number (§18.5).
    pub const fn number(self) -> u16 {
        match self {
            Self::Md5 => 0x0001,
            Self::Sha256 => 0x0002,
        }
    }

    /// The algorithm a registry number names, if lotse knows it.
    pub const fn from_number(number: u16) -> Option<Self> {
        match number {
            0x0001 => Some(Self::Md5),
            0x0002 => Some(Self::Sha256),
            _ => None,
        }
    }
}

/// The STUN security features a nonce cookie announces (§9.2, §18.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityFeatures {
    /// "Password algorithms": the server lists PASSWORD-ALGORITHMS, and a
    /// challenge without the list was tampered with (§9.2.5).
    pub password_algorithms: bool,
    /// "Username anonymity": requests carry USERHASH, not USERNAME (§9.2.5).
    pub username_anonymity: bool,
}

/// The security features of `nonce`, or `None` when it does not start
/// with the nonce cookie: `obMatJos2` and four base64 characters that
/// carry the 24 feature bits (§9.2). Bit 0 is the least significant, as
/// the verified Errata 6290 to §18.1 has it and the corrected Appendix B.1
/// vector (Errata 6268) uses; §9.2 still says the most significant, and
/// coturn sends no cookie at all, so the errata decide. A cookie whose
/// characters are not base64 counts as none: the server checks the nonce
/// it issued, so a tampered one fails there.
pub fn security_features(nonce: &str) -> Option<SecurityFeatures> {
    let encoded = nonce.strip_prefix(NONCE_COOKIE)?.get(..FEATURES_LEN)?;
    let mut last = 0;
    for byte in encoded.bytes() {
        last = base64_value(byte)?;
    }
    Some(SecurityFeatures {
        password_algorithms: last & FEATURE_PASSWORD_ALGORITHMS != 0,
        username_anonymity: last & FEATURE_USERNAME_ANONYMITY != 0,
    })
}

/// The six bits a character of the base64 alphabet stands for (RFC 4648
/// §4, Table 1).
const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(byte.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0').wrapping_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The algorithm numbers of a PASSWORD-ALGORITHMS value, in the server's
/// order (§14.11): each a 16-bit number and its parameters, length-prefixed
/// and padded to four bytes. `None` when an entry runs past the end.
pub fn password_algorithms(value: &[u8]) -> Option<Vec<u16>> {
    let mut numbers = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (head, tail) = rest.split_at_checked(4)?;
        let number = u16::from_be_bytes([*head.first()?, *head.get(1)?]);
        let params = usize::from(u16::from_be_bytes([*head.get(2)?, *head.get(3)?]));
        let padded = params.div_ceil(4).checked_mul(4)?;
        rest = tail.get(padded..)?;
        numbers.push(number);
    }
    Some(numbers)
}

/// The long-term credential of one `ice_servers` entry: its username and
/// credential, the password (§9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The username, sent in USERNAME or hashed into USERHASH.
    pub username: String,
    /// The password; it never leaves the key derivation.
    pub password: Secret<String>,
}

/// An HMAC key derived from a long-term credential (§9.2.2). `Debug`
/// redacts it: whoever has the key can sign as the user.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(Vec<u8>);

impl Key {
    /// The key for `username`, `realm` and `password` under `algorithm`:
    /// the algorithm's hash of `username ":" realm ":" password`, with
    /// trailing NULs removed from realm and password (§9.2.2, §18.5.1).
    ///
    /// Username, realm and password are used as given, not prepared with
    /// the `OpaqueString` profile (`SPEC-DEVIATION`).
    pub fn derive(
        algorithm: PasswordAlgorithm,
        username: &str,
        realm: &str,
        password: &str,
    ) -> Self {
        // SPEC-DEVIATION(RFC 8489 §9.2.2, §14.3, §14.9): no OpaqueString
        // preparation (RFC 8265 §4.2), which is the identity for ASCII
        // without control characters, what TURN servers issue; gate:
        // rfc8489_9_2_2_the_md5_key_of_user_realm_pass.
        let input = [
            username,
            ":",
            realm.trim_end_matches('\0'),
            ":",
            password.trim_end_matches('\0'),
        ]
        .concat();
        Self(match algorithm {
            PasswordAlgorithm::Md5 => Md5::digest(input.as_bytes()).to_vec(),
            PasswordAlgorithm::Sha256 => Sha256::digest(input.as_bytes()).to_vec(),
        })
    }

    /// The key bytes, for the HMAC.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(****)")
    }
}

/// The USERHASH of `username` in `realm`: SHA-256 of `username ":" realm`
/// (§14.4), trailing NULs removed from the realm.
pub fn userhash(username: &str, realm: &str) -> [u8; 32] {
    // SPEC-DEVIATION(RFC 8489 §14.4): no OpaqueString preparation, as in
    // `Key::derive`; gate: rfc8489_14_4_userhash_matches_appendix_b_1.
    Sha256::digest(
        [username, ":", realm.trim_end_matches('\0')]
            .concat()
            .as_bytes(),
    )
    .into()
}

/// Why an error response is no challenge to answer (§9.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
    /// Not an error response with 401 or 438.
    #[error("not a 401 or 438 error response")]
    NotAChallenge,
    /// No REALM, or one that is not UTF-8 or too long (§14.9).
    #[error("challenge without a realm")]
    Realm,
    /// No NONCE, or one that is not UTF-8 or too long (§14.10).
    #[error("challenge without a nonce")]
    Nonce,
    /// The nonce cookie announces PASSWORD-ALGORITHMS but the attribute is
    /// missing: a bid-down attack, never retried (§9.2.5).
    #[error("password algorithms announced but missing")]
    AlgorithmsStripped,
    /// PASSWORD-ALGORITHMS does not parse (§14.11).
    #[error("malformed password algorithms")]
    MalformedAlgorithms,
    /// PASSWORD-ALGORITHMS lists no algorithm lotse supports; never retried
    /// (§9.2.5).
    #[error("no supported password algorithm")]
    NoSupportedAlgorithm,
}

/// A server's challenge: what a 401 or 438 error response asks the next
/// request to carry (§9.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// REALM, copied into requests and into the key.
    pub realm: String,
    /// NONCE, copied into requests.
    pub nonce: String,
    /// The PASSWORD-ALGORITHMS value as received, echoed unchanged; `None`
    /// for a server that sent none (the legacy MD5 path).
    pub algorithms: Option<Vec<u8>>,
    /// The algorithm the key is derived with.
    pub algorithm: PasswordAlgorithm,
    /// Requests carry USERHASH instead of USERNAME.
    pub anonymous: bool,
}

impl Challenge {
    /// Reads the challenge of an error response with 401 or 438 (§9.2.5).
    /// From the offered PASSWORD-ALGORITHMS it picks SHA-256 when present,
    /// as RFC 8656 §6 requires of a TURN client, else the first it
    /// supports; without the attribute the algorithm is MD5.
    pub fn from_response(message: &Message<'_>) -> Result<Self, ChallengeError> {
        let code = message.error_code().map(|(code, _)| code);
        if message.class != Class::Error
            || !matches!(code, Some(ERROR_UNAUTHENTICATED | ERROR_STALE_NONCE))
        {
            return Err(ChallengeError::NotAChallenge);
        }
        let realm = text(message, ATTR_REALM).ok_or(ChallengeError::Realm)?;
        let nonce = text(message, ATTR_NONCE).ok_or(ChallengeError::Nonce)?;
        let features = security_features(&nonce).unwrap_or_default();
        let raw = message.attribute(ATTR_PASSWORD_ALGORITHMS);
        if features.password_algorithms && raw.is_none() {
            return Err(ChallengeError::AlgorithmsStripped);
        }
        let algorithm = match raw {
            None => PasswordAlgorithm::Md5,
            Some(value) => {
                let offered: Vec<PasswordAlgorithm> = password_algorithms(value)
                    .ok_or(ChallengeError::MalformedAlgorithms)?
                    .into_iter()
                    .filter_map(PasswordAlgorithm::from_number)
                    .collect();
                if offered.contains(&PasswordAlgorithm::Sha256) {
                    PasswordAlgorithm::Sha256
                } else {
                    *offered
                        .first()
                        .ok_or(ChallengeError::NoSupportedAlgorithm)?
                }
            }
        };
        Ok(Self {
            realm,
            nonce,
            algorithms: raw.map(<[u8]>::to_vec),
            algorithm,
            anonymous: features.username_anonymity,
        })
    }
}

/// An attribute's value as UTF-8 text of at most [`MAX_TEXT_LEN`] bytes.
fn text(message: &Message<'_>, attr_type: u16) -> Option<String> {
    let value = message
        .attribute(attr_type)
        .filter(|value| value.len() <= MAX_TEXT_LEN)?;
    std::str::from_utf8(value).ok().map(str::to_owned)
}

/// Signs requests to one server and checks its responses, from a
/// credential and the server's latest challenge (§9.2.3.2, §9.2.5). A new
/// challenge (a 438 with a fresh nonce) makes a new authenticator.
#[derive(Debug, Clone)]
pub struct Authenticator {
    /// USERNAME, or the USERHASH input when the server wants anonymity.
    username: String,
    /// The challenge being answered.
    challenge: Challenge,
    /// The key derived for it.
    key: Key,
}

impl Authenticator {
    /// The authenticator for `credentials` answering `challenge`.
    pub fn new(credentials: &Credentials, challenge: Challenge) -> Self {
        let key = Key::derive(
            challenge.algorithm,
            &credentials.username,
            &challenge.realm,
            credentials.password.expose_secret(),
        );
        Self {
            username: credentials.username.clone(),
            challenge,
            key,
        }
    }

    /// Appends the authentication of a request (§9.2.3.2, §9.2.5): USERNAME
    /// or USERHASH, REALM, NONCE, and when the server listed algorithms the
    /// list as received and the one chosen; then MESSAGE-INTEGRITY-SHA256
    /// when the server listed algorithms (§9.2.5: all later requests use
    /// it), MESSAGE-INTEGRITY otherwise. Nothing may follow but
    /// FINGERPRINT.
    #[must_use]
    pub fn sign(&self, builder: Builder) -> Builder {
        let challenge = &self.challenge;
        let builder = if challenge.anonymous {
            builder.attribute(ATTR_USERHASH, &userhash(&self.username, &challenge.realm))
        } else {
            builder.attribute(ATTR_USERNAME, self.username.as_bytes())
        };
        let builder = builder
            .attribute(ATTR_REALM, challenge.realm.as_bytes())
            .attribute(ATTR_NONCE, challenge.nonce.as_bytes());
        match &challenge.algorithms {
            Some(algorithms) => {
                // The number and an empty parameter list (§14.12, §18.5.1).
                let [high, low] = challenge.algorithm.number().to_be_bytes();
                builder
                    .attribute(ATTR_PASSWORD_ALGORITHMS, algorithms)
                    .attribute(ATTR_PASSWORD_ALGORITHM, &[high, low, 0, 0])
                    .integrity_sha256(self.key.expose_secret())
            }
            None => builder.integrity(self.key.expose_secret()),
        }
    }

    /// Whether a response to a signed request is authentic (§9.2.5): it
    /// carries the integrity attribute the request did, valid under the
    /// key. A response without it is not, and the caller discards it.
    pub fn verify(&self, message: &Message<'_>, bytes: &[u8]) -> bool {
        if self.challenge.algorithms.is_some() {
            message.verify_integrity_sha256(bytes, self.key.expose_secret())
        } else {
            message.verify_integrity(bytes, self.key.expose_secret())
        }
    }

    /// The challenge being answered.
    pub const fn challenge(&self) -> &Challenge {
        &self.challenge
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

    /// RFC 5769 §2.4: a request with long-term authentication.
    const LONG_TERM_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72,
        0xc0, 0x29, 0xda, 0x41, 0x2e, 0x00, 0x06, 0x00, 0x12, 0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88,
        0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf, 0xe3, 0x82, 0xb9, 0x00, 0x00, 0x00,
        0x15, 0x00, 0x1c, 0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36,
        0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73,
        0x41, 0x00, 0x14, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72,
        0x67, 0x00, 0x00, 0x08, 0x00, 0x14, 0xf6, 0x70, 0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02,
        0xb8, 0xe0, 0x71, 0x2e, 0x85, 0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66,
    ];

    /// The username of the RFC 5769 §2.4 and RFC 8489 B.1 vectors.
    const MATRIX_USER: &str = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";

    /// The USERHASH value of RFC 8489 B.1.
    const B1_USERHASH: [u8; 32] = [
        0x4a, 0x3c, 0xf3, 0x8f, 0xef, 0x69, 0x92, 0xbd, 0xa9, 0x52, 0xc6, 0x78, 0x04, 0x17, 0xda,
        0x0f, 0x24, 0x81, 0x94, 0x15, 0x56, 0x9e, 0x60, 0xb2, 0x05, 0xc4, 0x6e, 0x41, 0x40, 0x7f,
        0x17, 0x04,
    ];

    /// RFC 8489 Appendix B.1 as corrected by the verified Errata 6268: a
    /// request with USERHASH, NONCE, REALM, PASSWORD-ALGORITHM (SHA-256)
    /// and MESSAGE-INTEGRITY-SHA256.
    const B1_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x90, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72,
        0xc0, 0x29, 0xda, 0x41, 0x2e, 0x00, 0x1e, 0x00, 0x20, 0x4a, 0x3c, 0xf3, 0x8f, 0xef, 0x69,
        0x92, 0xbd, 0xa9, 0x52, 0xc6, 0x78, 0x04, 0x17, 0xda, 0x0f, 0x24, 0x81, 0x94, 0x15, 0x56,
        0x9e, 0x60, 0xb2, 0x05, 0xc4, 0x6e, 0x41, 0x40, 0x7f, 0x17, 0x04, 0x00, 0x15, 0x00, 0x29,
        0x6f, 0x62, 0x4d, 0x61, 0x74, 0x4a, 0x6f, 0x73, 0x32, 0x41, 0x41, 0x41, 0x43, 0x66, 0x2f,
        0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36, 0x4f, 0x4c, 0x33, 0x34, 0x6f,
        0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73, 0x41, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00,
        0x00, 0x1d, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x20, 0xb5, 0xc7, 0xbf,
        0x00, 0x5b, 0x6c, 0x52, 0xa2, 0x1c, 0x51, 0xc5, 0xe8, 0x92, 0xf8, 0x19, 0x24, 0x13, 0x62,
        0x96, 0xcb, 0x92, 0x7c, 0x43, 0x14, 0x93, 0x09, 0x27, 0x8c, 0xc6, 0x51, 0x8e, 0x65,
    ];

    /// The nonce of the Appendix B.1 vector.
    const B1_NONCE: &str = "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA";

    fn credentials() -> Credentials {
        Credentials {
            username: "user".to_owned(),
            password: Secret::new("pass".to_owned()),
        }
    }

    /// An error response with `code`, and REALM, NONCE and
    /// PASSWORD-ALGORITHMS when given.
    fn error(
        code: u16,
        realm: Option<&str>,
        nonce: Option<&str>,
        algorithms: Option<&[u8]>,
    ) -> Vec<u8> {
        let class = u8::try_from(code / 100).unwrap();
        let number = u8::try_from(code % 100).unwrap();
        let mut builder = Builder::new(Class::Error, 0x003, [7; 12])
            .attribute(ATTR_ERROR_CODE, &[0, 0, class, number]);
        if let Some(realm) = realm {
            builder = builder.attribute(ATTR_REALM, realm.as_bytes());
        }
        if let Some(nonce) = nonce {
            builder = builder.attribute(ATTR_NONCE, nonce.as_bytes());
        }
        if let Some(algorithms) = algorithms {
            builder = builder.attribute(ATTR_PASSWORD_ALGORITHMS, algorithms);
        }
        builder.build()
    }

    fn challenge_of(bytes: &[u8]) -> Result<Challenge, ChallengeError> {
        Challenge::from_response(&parse(bytes).unwrap())
    }

    /// MD5 then SHA-256, both without parameters (§14.11).
    const BOTH: &[u8] = &[0, 1, 0, 0, 0, 2, 0, 0];

    #[test]
    fn rfc8489_9_2_2_the_md5_key_of_user_realm_pass() {
        let key = Key::derive(PasswordAlgorithm::Md5, "user", "realm", "pass");
        assert_eq!(
            key.expose_secret(),
            [
                0x84, 0x93, 0xfb, 0xc5, 0x3b, 0xa5, 0x82, 0xfb, 0x4c, 0x04, 0x4c, 0x45, 0x6b, 0xdc,
                0x40, 0xeb
            ]
        );
        // Trailing NULs of realm and password are removed first.
        assert_eq!(
            Key::derive(PasswordAlgorithm::Md5, "user", "realm\0", "pass\0\0"),
            key
        );
        assert_ne!(
            Key::derive(PasswordAlgorithm::Md5, "user\0", "realm", "pass"),
            key
        );
        assert_eq!(format!("{key:?}"), "Key(****)");
    }

    #[test]
    fn rfc8489_18_5_1_2_the_sha256_key_hashes_the_same_input() {
        let key = Key::derive(PasswordAlgorithm::Sha256, "user", "realm", "pass");
        assert_eq!(
            key.expose_secret(),
            Sha256::digest(b"user:realm:pass").as_slice()
        );
        assert_eq!(key.expose_secret().len(), 32);
    }

    #[test]
    fn rfc5769_2_4_the_long_term_request_verifies_under_its_md5_key() {
        let message = parse(LONG_TERM_REQUEST).unwrap();
        let key = Key::derive(
            PasswordAlgorithm::Md5,
            MATRIX_USER,
            "example.org",
            "TheMatrIX",
        );
        assert!(message.verify_integrity(LONG_TERM_REQUEST, key.expose_secret()));
        let wrong = Key::derive(
            PasswordAlgorithm::Md5,
            MATRIX_USER,
            "example.org",
            "TheMatrix",
        );
        assert!(!message.verify_integrity(LONG_TERM_REQUEST, wrong.expose_secret()));
    }

    #[test]
    fn rfc8489_b_1_errata_6268_the_sha256_request_verifies_and_rebuilds() {
        let message = parse(B1_REQUEST).unwrap();
        let key = Key::derive(
            PasswordAlgorithm::Sha256,
            MATRIX_USER,
            "example.org",
            "TheMatrIX",
        );
        assert!(message.verify_integrity_sha256(B1_REQUEST, key.expose_secret()));
        assert!(!message.verify_integrity(B1_REQUEST, key.expose_secret()));
        let md5 = Key::derive(
            PasswordAlgorithm::Md5,
            MATRIX_USER,
            "example.org",
            "TheMatrIX",
        );
        assert!(!message.verify_integrity_sha256(B1_REQUEST, md5.expose_secret()));
        assert_eq!(message.attribute(ATTR_NONCE), Some(B1_NONCE.as_bytes()));
        assert!(security_features(B1_NONCE).unwrap().username_anonymity);
        // The builder makes the same bytes, HMAC included.
        let rebuilt = Builder::new(Class::Request, METHOD_BINDING, message.transaction_id)
            .attribute(ATTR_USERHASH, &userhash(MATRIX_USER, "example.org"))
            .attribute(ATTR_NONCE, B1_NONCE.as_bytes())
            .attribute(ATTR_REALM, b"example.org")
            .attribute(ATTR_PASSWORD_ALGORITHM, &[0, 2, 0, 0])
            .integrity_sha256(key.expose_secret())
            .build();
        assert_eq!(rebuilt, B1_REQUEST);
    }

    #[test]
    fn rfc8489_14_4_userhash_matches_appendix_b_1() {
        assert_eq!(userhash(MATRIX_USER, "example.org"), B1_USERHASH);
        assert_eq!(userhash(MATRIX_USER, "example.org\0"), B1_USERHASH);
    }

    #[test]
    fn rfc8489_18_1_errata_6290_bit_0_is_the_least_significant_feature_bit() {
        let both = SecurityFeatures {
            password_algorithms: true,
            username_anonymity: true,
        };
        assert_eq!(security_features("f//499k954d6OL34oL9FSTvy64sA"), None);
        assert_eq!(security_features("obMatJos2AAA"), None, "too short");
        assert_eq!(security_features("obMatJos2AA*Arest"), None, "not base64");
        assert_eq!(security_features("obMatJos2AAA*"), None, "not base64");
        assert_eq!(
            security_features("obMatJos2AAAAxyz"),
            Some(SecurityFeatures::default())
        );
        // 0x000001: bit 0, "Password algorithms".
        assert_eq!(
            security_features("obMatJos2AAABxyz"),
            Some(SecurityFeatures {
                password_algorithms: true,
                username_anonymity: false
            })
        );
        // 0x000002: bit 1, "Username anonymity", as in Appendix B.1.
        assert_eq!(
            security_features("obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA"),
            Some(SecurityFeatures {
                password_algorithms: false,
                username_anonymity: true
            })
        );
        assert_eq!(security_features("obMatJos2AAAD"), Some(both));
        assert_eq!(security_features("obMatJos2////"), Some(both));
        // The unassigned bits 2 to 23 are ignored, the top ones included.
        assert_eq!(
            security_features("obMatJos2///8"),
            Some(SecurityFeatures::default())
        );
        assert_eq!(
            security_features("obMatJos2wAAA"),
            Some(SecurityFeatures::default())
        );
    }

    #[test]
    fn rfc4648_4_every_base64_character_has_its_value() {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (value, &byte) in alphabet.iter().enumerate() {
            assert_eq!(base64_value(byte), Some(u8::try_from(value).unwrap()));
        }
        for byte in *b"=-_ @[`{:." {
            assert_eq!(base64_value(byte), None);
        }
    }

    #[test]
    fn rfc8489_14_11_password_algorithms_parse_with_padded_parameters() {
        assert_eq!(password_algorithms(&[]), Some(vec![]));
        assert_eq!(password_algorithms(BOTH), Some(vec![1, 2]));
        // An unknown algorithm with 5 bytes of parameters, padded to 8.
        let with_params = [0, 9, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0, 0, 2, 0, 0];
        assert_eq!(password_algorithms(&with_params), Some(vec![9, 2]));
        assert_eq!(password_algorithms(&with_params[..12]), Some(vec![9]));
        assert_eq!(password_algorithms(&with_params[..11]), None, "padding cut");
        assert_eq!(password_algorithms(&[0, 1, 0]), None, "header cut");
        assert_eq!(PasswordAlgorithm::from_number(9), None);
        for algorithm in [PasswordAlgorithm::Md5, PasswordAlgorithm::Sha256] {
            assert_eq!(
                PasswordAlgorithm::from_number(algorithm.number()),
                Some(algorithm)
            );
        }
    }

    #[test]
    fn rfc8489_9_2_5_a_legacy_challenge_signs_with_md5_and_message_integrity() {
        let challenge = challenge_of(&error(401, Some("realm"), Some("abc"), None)).unwrap();
        assert_eq!(challenge.algorithm, PasswordAlgorithm::Md5);
        assert_eq!(challenge.algorithms, None);
        assert!(!challenge.anonymous);
        let auth = Authenticator::new(&credentials(), challenge.clone());
        assert_eq!(auth.challenge(), &challenge);
        let request = auth
            .sign(Builder::new(Class::Request, 0x003, [1; 12]))
            .build();
        let message = parse(&request).unwrap();
        assert_eq!(message.username(), Some("user"));
        assert_eq!(message.attribute(ATTR_REALM), Some(&b"realm"[..]));
        assert_eq!(message.attribute(ATTR_NONCE), Some(&b"abc"[..]));
        assert_eq!(message.attribute(ATTR_PASSWORD_ALGORITHM), None);
        assert_eq!(message.attribute(ATTR_PASSWORD_ALGORITHMS), None);
        let key = Key::derive(PasswordAlgorithm::Md5, "user", "realm", "pass");
        assert!(message.verify_integrity(&request, key.expose_secret()));
        assert!(!message.verify_integrity_sha256(&request, key.expose_secret()));
        // The server's response carries MESSAGE-INTEGRITY under the same key.
        let response = Builder::new(Class::Success, 0x003, [1; 12])
            .integrity(key.expose_secret())
            .build();
        assert!(auth.verify(&parse(&response).unwrap(), &response));
        let forged = Builder::new(Class::Success, 0x003, [1; 12])
            .integrity(b"other")
            .build();
        assert!(!auth.verify(&parse(&forged).unwrap(), &forged));
        let bare = Builder::new(Class::Success, 0x003, [1; 12]).build();
        assert!(!auth.verify(&parse(&bare).unwrap(), &bare));
    }

    #[test]
    fn rfc8656_6_a_server_offering_both_algorithms_gets_sha256() {
        let nonce = "obMatJos2AAABnonce";
        let challenge = challenge_of(&error(401, Some("realm"), Some(nonce), Some(BOTH))).unwrap();
        assert_eq!(challenge.algorithm, PasswordAlgorithm::Sha256);
        assert_eq!(challenge.algorithms.as_deref(), Some(BOTH));
        let auth = Authenticator::new(&credentials(), challenge);
        let request = auth
            .sign(Builder::new(Class::Request, 0x003, [2; 12]))
            .build();
        let message = parse(&request).unwrap();
        assert_eq!(message.attribute(ATTR_PASSWORD_ALGORITHMS), Some(BOTH));
        assert_eq!(
            message.attribute(ATTR_PASSWORD_ALGORITHM),
            Some(&[0, 2, 0, 0][..])
        );
        let key = Key::derive(PasswordAlgorithm::Sha256, "user", "realm", "pass");
        assert!(message.verify_integrity_sha256(&request, key.expose_secret()));
        assert!(!message.verify_integrity(&request, key.expose_secret()));
        // Responses must carry MESSAGE-INTEGRITY-SHA256: MESSAGE-INTEGRITY
        // under the right key does not do (no bid-down to SHA-1).
        let response = Builder::new(Class::Success, 0x003, [2; 12])
            .integrity_sha256(key.expose_secret())
            .build();
        assert!(auth.verify(&parse(&response).unwrap(), &response));
        let sha1_only = Builder::new(Class::Success, 0x003, [2; 12])
            .integrity(key.expose_secret())
            .build();
        assert!(!auth.verify(&parse(&sha1_only).unwrap(), &sha1_only));
    }

    #[test]
    fn rfc8489_9_2_5_the_first_supported_algorithm_without_sha256() {
        // An unknown algorithm first, then MD5: MD5 is chosen, and with a
        // list the request still uses MESSAGE-INTEGRITY-SHA256.
        let list = [0, 9, 0, 0, 0, 1, 0, 0];
        let challenge = challenge_of(&error(438, Some("r"), Some("n"), Some(&list))).unwrap();
        assert_eq!(challenge.algorithm, PasswordAlgorithm::Md5);
        let auth = Authenticator::new(&credentials(), challenge);
        let request = auth
            .sign(Builder::new(Class::Request, 0x004, [3; 12]))
            .build();
        let message = parse(&request).unwrap();
        assert_eq!(
            message.attribute(ATTR_PASSWORD_ALGORITHM),
            Some(&[0, 1, 0, 0][..])
        );
        let key = Key::derive(PasswordAlgorithm::Md5, "user", "r", "pass");
        assert!(message.verify_integrity_sha256(&request, key.expose_secret()));
    }

    #[test]
    fn rfc8489_9_2_5_username_anonymity_sends_userhash() {
        let challenge = challenge_of(&error(
            401,
            Some("example.org"),
            Some("obMatJos2AAACn"),
            None,
        ))
        .unwrap();
        assert!(challenge.anonymous);
        let creds = Credentials {
            username: MATRIX_USER.to_owned(),
            password: Secret::new("TheMatrIX".to_owned()),
        };
        let request = Authenticator::new(&creds, challenge)
            .sign(Builder::new(Class::Request, 0x003, [4; 12]))
            .build();
        let message = parse(&request).unwrap();
        assert_eq!(message.username(), None);
        assert_eq!(message.attribute(ATTR_USERHASH), Some(&B1_USERHASH[..]));
    }

    #[test]
    fn rfc8489_9_2_5_challenges_that_must_not_be_answered() {
        assert_eq!(
            challenge_of(&error(400, Some("r"), Some("n"), None)),
            Err(ChallengeError::NotAChallenge)
        );
        let success = Builder::new(Class::Success, METHOD_BINDING, [5; 12])
            .attribute(ATTR_ERROR_CODE, &[0, 0, 4, 1])
            .build();
        assert_eq!(challenge_of(&success), Err(ChallengeError::NotAChallenge));
        let no_code = Builder::new(Class::Error, METHOD_BINDING, [5; 12]).build();
        assert_eq!(challenge_of(&no_code), Err(ChallengeError::NotAChallenge));
        assert_eq!(
            challenge_of(&error(401, None, Some("n"), None)),
            Err(ChallengeError::Realm)
        );
        assert_eq!(
            challenge_of(&error(401, Some("\u{fffd}"), None, None)),
            Err(ChallengeError::Nonce)
        );
        let bad_realm = Builder::new(Class::Error, 0x003, [6; 12])
            .attribute(ATTR_ERROR_CODE, &[0, 0, 4, 1])
            .attribute(ATTR_REALM, &[0xff, 0xfe])
            .attribute(ATTR_NONCE, b"n")
            .build();
        assert_eq!(challenge_of(&bad_realm), Err(ChallengeError::Realm));
        // At most 763 bytes each (§14.9, §14.10).
        let long = "r".repeat(MAX_TEXT_LEN);
        assert!(challenge_of(&error(401, Some(&long), Some(&long), None)).is_ok());
        let longer = "r".repeat(MAX_TEXT_LEN + 1);
        assert_eq!(
            challenge_of(&error(401, Some(&longer), Some("n"), None)),
            Err(ChallengeError::Realm)
        );
        assert_eq!(
            challenge_of(&error(401, Some("r"), Some(&longer), None)),
            Err(ChallengeError::Nonce)
        );
        // The cookie announces the list, an attacker removed it: bid-down.
        assert_eq!(
            challenge_of(&error(401, Some("r"), Some("obMatJos2AAABx"), None)),
            Err(ChallengeError::AlgorithmsStripped)
        );
        assert_eq!(
            challenge_of(&error(401, Some("r"), Some("n"), Some(&[0, 1, 0]))),
            Err(ChallengeError::MalformedAlgorithms)
        );
        assert_eq!(
            challenge_of(&error(401, Some("r"), Some("n"), Some(&[0, 9, 0, 0]))),
            Err(ChallengeError::NoSupportedAlgorithm)
        );
        assert_eq!(
            challenge_of(&error(401, Some("r"), Some("n"), Some(&[]))),
            Err(ChallengeError::NoSupportedAlgorithm)
        );
        assert_eq!(
            ChallengeError::AlgorithmsStripped.to_string(),
            "password algorithms announced but missing"
        );
    }
}
