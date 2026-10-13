//! The SHA-256 fingerprint of a DER certificate, the pin that names exactly
//! one certificate wherever lotse trusts one by its hash rather than by a
//! chain: a camera's `tls_fingerprint` and the control listener's pins.
//!
//! Standards: FIPS 180-4 (SHA-256), RFC 5280 §4.1 (the DER certificate that
//! is hashed whole).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

/// The length of a SHA-256 digest in bytes.
const FINGERPRINT_LEN: usize = 32;

/// A SHA-256 fingerprint of a DER certificate: a camera's `tls_fingerprint`
/// pin, and the pins of the control listener's server and clients.
///
/// Parsed from 64 hex digits, upper or lower case, either run together or
/// as 32 colon-separated pairs (what `openssl x509 -fingerprint -sha256`
/// prints). Printed as lowercase pairs joined by colons, which is also the
/// canonical form in a camera's connection key, so every spelling of one pin
/// is one camera session. Not a secret: a certificate is public.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

/// Why a `tls_fingerprint` does not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "a certificate fingerprint must be its SHA-256 as 64 hex digits, optionally with a colon between each pair, not {0:?}"
)]
pub struct FingerprintError(String);

impl Fingerprint {
    /// The fingerprint of a DER-encoded certificate.
    pub fn of(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    /// Parses the hex form, with or without colons between the pairs.
    pub fn parse(text: &str) -> Result<Self, FingerprintError> {
        let error = || FingerprintError(text.to_owned());
        let digits: Vec<u8> = if text.contains(':') {
            let mut digits = Vec::with_capacity(FINGERPRINT_LEN * 2);
            for pair in text.split(':') {
                if pair.len() != 2 {
                    return Err(error());
                }
                digits.extend_from_slice(pair.as_bytes());
            }
            digits
        } else {
            text.as_bytes().to_vec()
        };
        if digits.len() != FINGERPRINT_LEN * 2 || !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(error());
        }
        let value = |digit: &u8| char::from(*digit).to_digit(16);
        let mut bytes = [0_u8; FINGERPRINT_LEN];
        for (byte, [high, low]) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
            *byte = value(high)
                .zip(value(low))
                .and_then(|(high, low)| u8::try_from(high.checked_mul(16)?.checked_add(low)?).ok())
                .ok_or_else(error)?;
        }
        Ok(Self(bytes))
    }
}

impl FromStr for Fingerprint {
    type Err = FingerprintError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    /// FIPS 180-2 Appendix B.1: SHA-256("abc").
    const ABC: &str = "ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad";

    #[test]
    fn a_fingerprint_is_the_sha256_of_the_der_fips_180_2_b_1() {
        assert_eq!(Fingerprint::of(b"abc").to_string(), ABC);
        assert_eq!(
            format!("{:?}", Fingerprint::of(b"abc")),
            format!("Fingerprint({ABC})")
        );
    }

    #[test]
    fn fingerprints_parse_with_or_without_colons_in_any_case() {
        let expected = Fingerprint::of(b"abc");
        let plain = ABC.replace(':', "");
        for text in [
            ABC.to_owned(),
            ABC.to_uppercase(),
            plain.clone(),
            plain.to_uppercase(),
        ] {
            assert_eq!(Fingerprint::parse(&text).unwrap(), expected, "{text}");
        }
        let short = &plain[..62];
        let long = format!("{plain}00");
        let odd_pairs = ABC.replacen(':', "", 1);
        let not_hex = plain.replacen('b', "g", 1);
        let not_ascii = format!("é{}", &plain[2..]);
        let colon_not_hex = ABC.replacen('b', "x", 1);
        for bad in [
            "",
            short,
            &long,
            &odd_pairs,
            &not_hex,
            &not_ascii,
            &colon_not_hex,
            "ab:cd",
            &format!("{ABC}:"),
            "+b78a16bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ] {
            let err = Fingerprint::parse(bad).unwrap_err();
            assert!(err.to_string().contains("64 hex digits"), "{bad}: {err}");
        }
    }

    #[test]
    fn fingerprints_parse_from_str_as_from_parse() {
        assert_eq!(ABC.parse::<Fingerprint>().unwrap(), Fingerprint::of(b"abc"));
        assert!("ab".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn fingerprints_serialize_canonically() {
        let pin: Fingerprint =
            serde_json::from_value(serde_json::json!(ABC.to_uppercase())).unwrap();
        assert_eq!(serde_json::to_value(pin).unwrap(), serde_json::json!(ABC));
        assert!(serde_json::from_value::<Fingerprint>(serde_json::json!("ab")).is_err());
        assert!(serde_json::from_value::<Fingerprint>(serde_json::json!(1)).is_err());
    }
}
