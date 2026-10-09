//! The crypto provider str0m runs on: `RustCrypto` for SRTP, the STUN MAC
//! and certificate fingerprints, `dimpl` on its `RustCrypto` backend for
//! DTLS, and `rcgen` on `ring` for each session's self-signed DTLS
//! certificate.
//!
//! str0m 0.24 ships the same choice as its `rust-crypto` feature
//! (`str0m-rust-crypto`), but that crate enables `dimpl`'s `rcgen` feature,
//! which enables `dimpl`'s `aws-lc-rs` feature: aws-lc is then compiled
//! and linked, and `dimpl` prefers it over `RustCrypto` for every handshake
//! whose provider is not set explicitly, which `str0m-rust-crypto` never
//! does. This provider is that crate's without the aws-lc path, and names
//! `dimpl`'s `RustCrypto` provider explicitly. `.cargo/deny.toml` bans
//! aws-lc so it cannot come back through another crate.
//!
//! Standards: RFC 3711 §4.1.1 (AES-CM) and §4.3 (key derivation), RFC 7714
//! (AEAD AES-GCM for SRTP), RFC 5764 (DTLS-SRTP), RFC 8489 §14.5 (STUN
//! MESSAGE-INTEGRITY), RFC 8122 §5 (certificate fingerprints), RFC 8827
//! §6.5 (self-signed DTLS certificates).

use std::sync::Arc;
use std::time::Instant;

use aes::cipher::consts::{U12, U16};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, BlockSizeUser, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, Tag};
use hmac::{Hmac, Mac};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SignatureAlgorithm};
use sha2::{Digest, Sha256};
use str0m::crypto::dtls::{
    DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider, DtlsVersion, ProtocolVersion,
};
use str0m::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, Aes128CmSha1_80Cipher, CryptoError, CryptoProvider,
    Sha1HmacProvider, Sha256Provider, SrtpProvider, SupportedAeadAes128Gcm, SupportedAeadAes256Gcm,
    SupportedAes128CmSha1_80,
};

/// The length of an AES-GCM authentication tag (RFC 7714 §5.2.2: 16 octets).
const GCM_TAG_LEN: usize = 16;

/// The AES block: 16 octets (FIPS 197 §3.1).
const AES_BLOCK_LEN: usize = 16;

/// The Common Name of the session's DTLS certificate. A WebRTC peer
/// authenticates the certificate by its SDP fingerprint, never by its
/// names (RFC 8827 §6.5), so any fixed name does.
const CERTIFICATE_NAME: &str = "lotse";

/// AES-128 in counter mode, the SRTP keystream (RFC 3711 §4.1.1).
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// HMAC-SHA1, the STUN MESSAGE-INTEGRITY MAC (RFC 8489 §14.5).
type HmacSha1 = Hmac<sha1::Sha1>;

/// The provider every session's `Rtc` runs on; `install_crypto_provider`
/// makes it the process default.
pub(crate) fn provider() -> CryptoProvider {
    CryptoProvider {
        srtp_provider: &Srtp,
        sha1_hmac_provider: &StunMac,
        sha256_provider: &Fingerprint,
        dtls_provider: &Dtls,
    }
}

/// The SRTP ciphers and the key derivation's AES block.
#[derive(Debug)]
struct Srtp;

impl SrtpProvider for Srtp {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &AesCm
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &Gcm128
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &Gcm256
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        encrypt_block::<aes::Aes128>(key, input, output);
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        encrypt_block::<aes::Aes256>(key, input, output);
    }
}

/// One AES block of the SRTP key derivation (RFC 3711 §4.3.3: the PRF is
/// AES-CM, one block per call): `input` encrypted under `key` into the
/// first 16 octets of `output`, the only ones str0m reads. A key, input
/// or output of the wrong size leaves `output` unchanged; str0m never
/// passes one.
fn encrypt_block<C>(key: &[u8], input: &[u8], output: &mut [u8])
where
    C: KeyInit + BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    let (Ok(cipher), Ok(block), Some(out)) = (
        C::new_from_slice(key),
        <[u8; AES_BLOCK_LEN]>::try_from(input),
        output.get_mut(..AES_BLOCK_LEN),
    ) else {
        let (key, input, output) = (key.len(), input.len(), output.len());
        tracing::warn!(
            key,
            input,
            output,
            "SRTP key derivation block of the wrong size"
        );
        return;
    };
    let mut block = GenericArray::from(block);
    cipher.encrypt_block(&mut block);
    out.copy_from_slice(&block);
}

/// The `SRTP_AES128_CM_HMAC_SHA1_80` profile's cipher factory; str0m
/// computes the HMAC itself.
#[derive(Debug)]
struct AesCm;

impl SupportedAes128CmSha1_80 for AesCm {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(AesCmCipher { key })
    }
}

/// An AES-128-CM session key; counter mode is its own inverse.
struct AesCmCipher {
    /// The session encryption key. Never logged.
    key: [u8; 16],
}

impl std::fmt::Debug for AesCmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesCmCipher(<redacted>)")
    }
}

impl AesCmCipher {
    /// XORs the keystream that starts at `iv` (RFC 3711 §4.1.1) over
    /// `input` into the front of `output`.
    fn apply(&self, iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        let out = output
            .get_mut(..input.len())
            .ok_or_else(|| too_short(input.len(), "AES-CM output"))?;
        out.copy_from_slice(input);
        Aes128Ctr::new(&self.key.into(), &(*iv).into()).apply_keystream(out);
        Ok(())
    }
}

impl Aes128CmSha1_80Cipher for AesCmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.apply(iv, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.apply(iv, input, output)
    }
}

/// The `SRTP_AEAD_AES_128_GCM` profile's cipher factory (RFC 7714).
#[derive(Debug)]
struct Gcm128;

impl SupportedAeadAes128Gcm for Gcm128 {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        Box::new(GcmCipher(Aes128Gcm::new(&key.into())))
    }
}

/// The `SRTP_AEAD_AES_256_GCM` profile's cipher factory (RFC 7714).
#[derive(Debug)]
struct Gcm256;

impl SupportedAeadAes256Gcm for Gcm256 {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        Box::new(GcmCipher(Aes256Gcm::new(&key.into())))
    }
}

/// An AES-GCM failure as str0m's error, saying `what` failed: one
/// closure for sealing, which fails only on an input over `P_MAX`
/// (2³⁶ − 31 octets, RFC 5116 §5.1), and for opening, which fails on a
/// forged packet.
fn gcm_failed(what: &'static str) -> impl FnOnce(aes_gcm::Error) -> CryptoError {
    move |_| CryptoError::Other(what.to_owned())
}

/// An AES-GCM session key of either size. Encrypts in place into str0m's
/// buffer, so a packet costs no allocation.
struct GcmCipher<C>(C);

impl<C> std::fmt::Debug for GcmCipher<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GcmCipher(<redacted>)")
    }
}

impl<C: AeadInPlace<NonceSize = U12, TagSize = U16>> GcmCipher<C> {
    /// Writes the ciphertext of `input` followed by its tag
    /// (RFC 7714 §5.2.1) to the front of `output`.
    fn seal(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let sealed_len = input.len().saturating_add(GCM_TAG_LEN);
        let (body, rest) = output
            .get_mut(..sealed_len)
            .and_then(|out| out.split_at_mut_checked(input.len()))
            .ok_or_else(|| too_short(sealed_len, "AES-GCM output"))?;
        body.copy_from_slice(input);
        let tag = self
            .0
            .encrypt_in_place_detached(&(*iv).into(), aad, body)
            .map_err(gcm_failed("AES-GCM input too long"))?;
        rest.copy_from_slice(&tag);
        Ok(())
    }

    /// Authenticates `input` (ciphertext and tag, RFC 7714 §5.2.2) over
    /// the concatenated `aads` and writes the plaintext to the front of
    /// `output`, returning its length. A forged or truncated packet is an
    /// error.
    fn open(
        &self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let (ciphertext, tag) = input
            .split_last_chunk::<GCM_TAG_LEN>()
            .ok_or_else(|| too_short(GCM_TAG_LEN, "AES-GCM input"))?;
        let body = output
            .get_mut(..ciphertext.len())
            .ok_or_else(|| too_short(ciphertext.len(), "AES-GCM output"))?;
        body.copy_from_slice(ciphertext);
        let aad = aads.concat();
        self.0
            .decrypt_in_place_detached(&(*iv).into(), &aad, body, &Tag::from(*tag))
            .map_err(gcm_failed("AES-GCM authentication failed"))?;
        Ok(ciphertext.len())
    }
}

impl AeadAes128GcmCipher for GcmCipher<Aes128Gcm> {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}

impl AeadAes256GcmCipher for GcmCipher<Aes256Gcm> {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}

/// The error for a buffer shorter than the `needed` octets.
fn too_short(needed: usize, what: &str) -> CryptoError {
    CryptoError::Other(format!("{what} shorter than {needed} octets"))
}

/// STUN MESSAGE-INTEGRITY: HMAC-SHA1 over the message (RFC 8489 §14.5).
#[derive(Debug)]
struct StunMac;

impl Sha1HmacProvider for StunMac {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        // HMAC takes a key of any length (RFC 2104 §2), so this never fails.
        <HmacSha1 as Mac>::new_from_slice(key).map_or([0; 20], |mut mac| {
            for payload in payloads {
                mac.update(payload);
            }
            mac.finalize().into_bytes().into()
        })
    }
}

/// SHA-256, the certificate fingerprint's hash (RFC 8122 §5).
#[derive(Debug)]
struct Fingerprint;

impl Sha256Provider for Fingerprint {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }
}

/// DTLS by `dimpl` on its `RustCrypto` backend, and the session's
/// certificate.
#[derive(Debug)]
struct Dtls;

impl DtlsProvider for Dtls {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        self_signed(&rcgen::PKCS_ECDSA_P256_SHA256)
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
        mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        // ICE has verified return routability before DTLS starts, so the
        // server cookie (RFC 6347 §4.2.1) adds a round trip and nothing
        // else, as in str0m's own providers.
        let mut builder = dimpl::Config::builder()
            .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
            .use_server_cookie(false);
        if let Some(mtu) = mtu {
            builder = builder.mtu(mtu);
        }
        let config = Arc::new(builder.build().map_err(CryptoError::DtlsImpl)?);
        let cert = cert.clone();
        let dtls = match dtls_version {
            DtlsVersion::Dtls13 => dimpl::Dtls::new_13(config, cert, now),
            DtlsVersion::Auto => dimpl::Dtls::new_auto(config, cert, now),
            // `Dtls12`, str0m's default. The enum is non-exhaustive, but
            // str0m 0.24 has no other variant; an upgrade revisits this.
            _ => dimpl::Dtls::new_12(config, cert, now),
        };
        Ok(Box::new(DtlsSession(dtls)))
    }
}

/// A self-signed certificate for `alg` with a fresh key pair, or `None`
/// (logged) when the backend cannot make one; str0m then refuses the
/// session. Validity is rcgen's fixed window and the serial is derived
/// from the public key, so it is unique per certificate as Firefox
/// requires and nothing reads a clock: a WebRTC peer accepts the
/// certificate by its SDP fingerprint (RFC 8827 §6.5), not its dates.
fn self_signed(alg: &'static SignatureAlgorithm) -> Option<DtlsCert> {
    let generated = KeyPair::generate_for(alg).and_then(|key| {
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, CERTIFICATE_NAME);
        params.distinguished_name = name;
        let cert = params.self_signed(&key)?;
        Ok(DtlsCert {
            certificate: cert.der().to_vec(),
            private_key: key.serialize_der(),
        })
    });
    match generated {
        Ok(cert) => {
            tracing::debug!("DTLS certificate generated");
            Some(cert)
        }
        Err(err) => {
            tracing::error!(%err, "DTLS certificate generation failed");
            None
        }
    }
}

/// One `dimpl` connection behind str0m's DTLS interface.
#[derive(Debug)]
struct DtlsSession(dimpl::Dtls);

impl DtlsInstance for DtlsSession {
    fn set_active(&mut self, active: bool) {
        self.0.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.0.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.0.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.0.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.0.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.0.is_active()
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.0.protocol_version()
    }

    fn is_closing(&self) -> bool {
        self.0.is_closing()
    }

    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.0.close()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::Duration;

    use lotse_core::clock::{Clock as _, SystemClock};
    use str0m::crypto::dtls::{KeyingMaterial, SrtpProfile};

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn array<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    #[test]
    fn rfc3711_b_2_the_aes_cm_keystream_is_the_test_vector_and_its_own_inverse() {
        let keystream = hex("E03EAD0935C95E80E166B16DD92B4EB4
                             D23513162B02D0F72A43A2FE4A5F97AB
                             41E95B3BB0A2E8DD477901E4FCA894C0");
        let iv = array::<16>("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000");
        let mut cipher = AesCm.create_cipher(array("2B7E151628AED2A6ABF7158809CF4F3C"), true);
        // str0m's buffer is larger than the packet: only the front is written.
        let mut out = [0xee; 50];
        cipher.encrypt(&iv, &[0; 48], &mut out).unwrap();
        assert_eq!(out[..48], keystream[..]);
        assert_eq!(out[48..], [0xee; 2]);

        let mut back = [0; 48];
        cipher.decrypt(&iv, &out[..48], &mut back).unwrap();
        assert_eq!(back, [0; 48]);

        let mut short = [0; 47];
        assert!(cipher.encrypt(&iv, &[0; 48], &mut short).is_err());
        assert!(cipher.decrypt(&iv, &[0; 48], &mut short).is_err());
    }

    #[test]
    fn rfc3711_b_3_the_key_derivation_block_gives_the_session_key() {
        // The cipher key (label 0x00, r = 0): one AES block of the master
        // key over the master salt shifted 16 bits (RFC 3711 §4.3.1).
        let mut out = [0; 32];
        Srtp.srtp_aes_128_ecb_round(
            &hex("E1F97A0D3E018BE0D64FA32C06DE4139"),
            &hex("0EC675AD498AFEEBB6960B3AABE60000"),
            &mut out,
        );
        assert_eq!(out[..16], hex("C61E7A93744F39EE10734AFE3FF7A087")[..]);
        // Only the first block is written; str0m reads no more.
        assert_eq!(out[16..], [0; 16]);
    }

    #[test]
    fn fips197_c_3_the_aes_256_key_derivation_block() {
        let mut out = [0; 32];
        Srtp.srtp_aes_256_ecb_round(
            &hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            &hex("00112233445566778899aabbccddeeff"),
            &mut out,
        );
        assert_eq!(out[..16], hex("8ea2b7ca516745bfeafc49904b496089")[..]);
    }

    #[test]
    fn a_key_derivation_block_of_the_wrong_size_leaves_the_output_alone() {
        let key = [7; 16];
        let mut out = [0xee; 16];
        Srtp.srtp_aes_128_ecb_round(&key[..15], &[0; 16], &mut out);
        Srtp.srtp_aes_128_ecb_round(&key, &[0; 15], &mut out);
        Srtp.srtp_aes_256_ecb_round(&key, &[0; 16], &mut out);
        assert_eq!(out, [0xee; 16]);
        let mut short = [0xee; 15];
        Srtp.srtp_aes_128_ecb_round(&key, &[0; 16], &mut short);
        assert_eq!(short, [0xee; 15]);
    }

    /// The GCM specification's test cases 2 (AES-128) and 14 (AES-256):
    /// a zero key, IV and block, no associated data.
    const GCM_CASE_2: (&str, &str) = (
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    );
    const GCM_CASE_14: (&str, &str) = (
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919",
    );

    #[test]
    fn rfc7714_aes_128_gcm_seals_to_the_gcm_test_vector_and_opens_it() {
        let mut cipher = Gcm128.create_cipher([0; 16], true);
        let mut out = [0xee; 34];
        cipher.encrypt(&[0; 12], &[], &[0; 16], &mut out).unwrap();
        assert_eq!(out[..16], hex(GCM_CASE_2.0)[..]);
        assert_eq!(out[16..32], hex(GCM_CASE_2.1)[..]);
        assert_eq!(out[32..], [0xee; 2]);

        let mut plain = [0xee; 17];
        assert_eq!(
            cipher
                .decrypt(&[0; 12], &[&[]], &out[..32], &mut plain)
                .unwrap(),
            16
        );
        assert_eq!(plain, [[0; 16].as_slice(), &[0xee]].concat()[..]);
    }

    #[test]
    fn rfc7714_aes_256_gcm_seals_to_the_gcm_test_vector_and_opens_it() {
        let mut cipher = Gcm256.create_cipher([0; 32], true);
        let mut out = [0; 32];
        cipher.encrypt(&[0; 12], &[], &[0; 16], &mut out).unwrap();
        assert_eq!(out[..16], hex(GCM_CASE_14.0)[..]);
        assert_eq!(out[16..], hex(GCM_CASE_14.1)[..]);

        let mut plain = [0xee; 16];
        assert_eq!(cipher.decrypt(&[0; 12], &[], &out, &mut plain).unwrap(), 16);
        assert_eq!(plain, [0; 16]);
    }

    #[test]
    fn rfc7714_9_1_the_associated_data_slices_are_authenticated_as_one() {
        // The RTP header as the AAD (RFC 7714 §9.1), handed over in two
        // slices on receive as str0m does for SRTCP.
        let header = [0x80, 0x60, 0, 1, 0, 0, 0, 2, 0xde, 0xad, 0xbe, 0xef];
        let iv = [9; 12];
        let mut cipher = Gcm128.create_cipher([3; 16], true);
        let mut sealed = [0; 21];
        cipher.encrypt(&iv, &header, b"hello", &mut sealed).unwrap();
        let mut plain = [0; 5];
        let opened = cipher
            .decrypt(&iv, &[&header[..4], &header[4..]], &sealed, &mut plain)
            .unwrap();
        assert_eq!(&plain[..opened], b"hello");

        // A different header, a flipped tag bit or a truncated packet
        // does not open.
        let mut other = header;
        other[3] = 2;
        assert!(cipher.decrypt(&iv, &[&other], &sealed, &mut plain).is_err());
        let mut forged = sealed;
        forged[20] ^= 1;
        assert!(
            cipher
                .decrypt(&iv, &[&header], &forged, &mut plain)
                .is_err()
        );
        assert!(
            cipher
                .decrypt(&iv, &[&header], &sealed[..15], &mut plain)
                .is_err()
        );
        // Nor does it fit an output buffer too short for it.
        assert!(
            cipher
                .decrypt(&iv, &[&header], &sealed, &mut plain[..4])
                .is_err()
        );
        assert!(
            cipher
                .encrypt(&iv, &header, b"hello", &mut sealed[..20])
                .is_err()
        );

        // The same for AES-256.
        let mut cipher = Gcm256.create_cipher([3; 32], true);
        let mut sealed = [0; 21];
        cipher.encrypt(&iv, &header, b"hello", &mut sealed).unwrap();
        let mut plain = [0; 5];
        assert!(
            cipher
                .decrypt(&iv, &[&header[..4]], &sealed, &mut plain)
                .is_err()
        );
        assert!(
            cipher
                .encrypt(&iv, &header, b"hello", &mut sealed[..20])
                .is_err()
        );
        assert!(
            cipher
                .decrypt(&iv, &[&header], &sealed, &mut plain[..4])
                .is_err()
        );
        assert!(
            cipher
                .decrypt(&iv, &[&header], &sealed[..15], &mut plain)
                .is_err()
        );
        assert_eq!(
            cipher
                .decrypt(&iv, &[&header], &sealed, &mut plain)
                .unwrap(),
            5
        );
    }

    #[test]
    fn session_keys_are_redacted_in_debug() {
        let cm = format!("{:?}", AesCm.create_cipher([0x2b; 16], true));
        let gcm = format!("{:?}", Gcm128.create_cipher([0x2b; 16], true));
        let gcm256 = format!("{:?}", Gcm256.create_cipher([0x2b; 32], true));
        assert_eq!(cm, "AesCmCipher(<redacted>)");
        assert_eq!(gcm, "GcmCipher(<redacted>)");
        assert_eq!(gcm256, "GcmCipher(<redacted>)");
    }

    #[test]
    fn rfc8489_14_5_message_integrity_is_hmac_sha1_over_the_payloads() {
        // RFC 2202 §3 test cases 1 and 2, the message split as str0m does.
        assert_eq!(
            StunMac.sha1_hmac(&[0x0b; 20], &[b"Hi ", b"There"]),
            array("b617318655057264e28bc0b6fb378c8ef146be00")
        );
        assert_eq!(
            StunMac.sha1_hmac(b"Jefe", &[b"what do ya want for nothing?"]),
            array("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        );
    }

    /// `aes` 0.8 and `polyval` 0.6 use the `ARMv8` crypto extensions (by
    /// runtime detection) only under these cfgs, which `.cargo/config.toml`
    /// sets for every aarch64 target; without them SRTP runs on software
    /// AES-GCM. The test vectors above then check the hardware backends.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_builds_use_the_armv8_crypto_backends() {
        let set = [cfg!(aes_armv8), cfg!(polyval_armv8)];
        assert_eq!(set, [true, true], "--cfg aes_armv8, --cfg polyval_armv8");
    }

    #[test]
    fn rfc8122_5_the_fingerprint_hash_is_sha_256() {
        // FIPS 180-2 Appendix B.1.
        assert_eq!(
            Fingerprint.sha256(b"abc"),
            array("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn the_provider_hands_out_these_implementations() {
        let provider = provider();
        assert_eq!(
            provider.sha256_provider.sha256(b"abc"),
            Fingerprint.sha256(b"abc")
        );
        assert_eq!(
            provider.sha1_hmac_provider.sha1_hmac(b"k", &[b"m"]),
            StunMac.sha1_hmac(b"k", &[b"m"])
        );
        let mut out = [0; 16];
        let mut expected = [0; 16];
        provider
            .srtp_provider
            .srtp_aes_128_ecb_round(&[1; 16], &[2; 16], &mut out);
        Srtp.srtp_aes_128_ecb_round(&[1; 16], &[2; 16], &mut expected);
        assert_eq!(out, expected);
        let mut out = [0; 16];
        let mut expected = [0; 16];
        provider
            .srtp_provider
            .srtp_aes_256_ecb_round(&[1; 32], &[2; 16], &mut out);
        Srtp.srtp_aes_256_ecb_round(&[1; 32], &[2; 16], &mut expected);
        assert_eq!(out, expected);
        let mut a = [0; 4];
        let mut b = [0; 4];
        let iv = [5; 16];
        let profile = provider.srtp_provider;
        profile
            .aes_128_cm_sha1_80()
            .create_cipher([1; 16], true)
            .encrypt(&iv, &[0; 4], &mut a)
            .unwrap();
        AesCm
            .create_cipher([1; 16], true)
            .encrypt(&iv, &[0; 4], &mut b)
            .unwrap();
        assert_eq!(a, b);
        let mut a = [0; 20];
        let mut b = [0; 20];
        profile
            .aead_aes_128_gcm()
            .create_cipher([1; 16], true)
            .encrypt(&[0; 12], &[], &[0; 4], &mut a)
            .unwrap();
        Gcm128
            .create_cipher([1; 16], true)
            .encrypt(&[0; 12], &[], &[0; 4], &mut b)
            .unwrap();
        assert_eq!(a, b);
        profile
            .aead_aes_256_gcm()
            .create_cipher([1; 32], true)
            .encrypt(&[0; 12], &[], &[0; 4], &mut a)
            .unwrap();
        Gcm256
            .create_cipher([1; 32], true)
            .encrypt(&[0; 12], &[], &[0; 4], &mut b)
            .unwrap();
        assert_eq!(a, b);
        assert!(provider.dtls_provider.generate_certificate().is_some());
    }

    #[test]
    fn rfc8827_6_5_each_certificate_is_a_fresh_self_signed_p256_one() {
        let a = Dtls.generate_certificate().expect("a certificate");
        let b = Dtls.generate_certificate().expect("a certificate");
        assert_ne!(a.certificate, b.certificate);
        assert_ne!(a.private_key, b.private_key);
        // ecdsa-with-SHA256 (RFC 5758 §3.2) and the P-256 curve
        // (RFC 5480 §2.1.1.1), DER-encoded.
        let der = &a.certificate;
        let has = |oid: &[u8]| der.windows(oid.len()).any(|w| w == oid);
        assert!(has(&hex("06082a8648ce3d040302")));
        assert!(has(&hex("06082a8648ce3d030107")));
        assert!(has(CERTIFICATE_NAME.as_bytes()));
    }

    #[test]
    fn a_backend_that_cannot_make_the_key_gives_no_certificate() {
        // `ring` cannot generate RSA keys.
        assert!(self_signed(&rcgen::PKCS_RSA_SHA256).is_none());
    }

    /// Everything one endpoint emitted until its next timeout.
    #[derive(Default)]
    struct Drained {
        packets: Vec<Vec<u8>>,
        connected: bool,
        peer_cert: Option<Vec<u8>>,
        keys: Option<(KeyingMaterial, SrtpProfile)>,
        app_data: Vec<Vec<u8>>,
        close_notify: bool,
    }

    fn drain(dtls: &mut dyn DtlsInstance, into: &mut Drained) {
        let mut buf = [0; 2048];
        loop {
            match dtls.poll_output(&mut buf) {
                DtlsOutput::Packet(p) => into.packets.push(p.to_vec()),
                DtlsOutput::Connected => into.connected = true,
                DtlsOutput::PeerCert(cert) => into.peer_cert = Some(cert.to_vec()),
                DtlsOutput::KeyingMaterial(km, profile) => into.keys = Some((km, profile)),
                DtlsOutput::ApplicationData(data) => into.app_data.push(data.to_vec()),
                DtlsOutput::CloseNotify => into.close_notify = true,
                // `Timeout`, or `BufferTooSmall`, which 2048 octets never
                // see (an unfinished exchange would show it).
                _ => return,
            }
        }
    }

    /// Moves datagrams both ways until `done` holds for the two endpoints.
    fn exchange(
        client: &mut dyn DtlsInstance,
        server: &mut dyn DtlsInstance,
        now: &mut Instant,
        out: &mut (Drained, Drained),
        done: impl Fn(&(Drained, Drained)) -> bool,
    ) {
        let finished = (0..50).any(|_| {
            client.handle_timeout(*now).unwrap();
            server.handle_timeout(*now).unwrap();
            drain(client, &mut out.0);
            drain(server, &mut out.1);
            for packet in std::mem::take(&mut out.0.packets) {
                server.handle_packet(&packet).unwrap();
            }
            for packet in std::mem::take(&mut out.1.packets) {
                client.handle_packet(&packet).unwrap();
            }
            *now += Duration::from_millis(10);
            done(out)
        });
        assert!(finished, "the exchange did not finish");
    }

    /// A full DTLS-SRTP handshake (RFC 5764 §4) between two instances of
    /// this provider, then data and the close, at `client` and `server`.
    fn handshake(client_version: DtlsVersion, server_version: DtlsVersion) -> ProtocolVersion {
        let mut now = SystemClock.now();
        let client_cert = Dtls.generate_certificate().unwrap();
        let server_cert = Dtls.generate_certificate().unwrap();
        let mut client = Dtls
            .new_dtls(&client_cert, now, client_version, None)
            .unwrap();
        let mut server = Dtls
            .new_dtls(&server_cert, now, server_version, Some(1150))
            .unwrap();
        client.set_active(true);
        server.set_active(false);
        assert!(client.is_active());
        assert!(!server.is_active());

        let mut out = (Drained::default(), Drained::default());
        exchange(&mut *client, &mut *server, &mut now, &mut out, |(c, s)| {
            c.connected && s.connected
        });
        // Each side sees the other's certificate, the one its SDP
        // fingerprint names, and both derive the same SRTP keys.
        assert_eq!(
            out.0.peer_cert.as_deref(),
            Some(&server_cert.certificate[..])
        );
        assert_eq!(
            out.1.peer_cert.as_deref(),
            Some(&client_cert.certificate[..])
        );
        let (client_keys, client_profile) = out.0.keys.take().unwrap();
        let (server_keys, server_profile) = out.1.keys.take().unwrap();
        assert_eq!(*client_keys, *server_keys);
        assert_eq!(client_profile, server_profile);

        // Application data (SCTP's carrier) goes through.
        client.send_application_data(b"ping").unwrap();
        exchange(&mut *client, &mut *server, &mut now, &mut out, |(_, s)| {
            !s.app_data.is_empty()
        });
        assert_eq!(out.1.app_data, [b"ping".to_vec()]);

        let version = client.protocol_version().unwrap();
        assert_eq!(server.protocol_version(), Some(version));

        assert!(!client.is_closing() && !client.is_closed());
        client.close().unwrap();
        // Closing until its `close_notify` is polled out.
        assert!(client.is_closing() && !client.is_closed());
        exchange(&mut *client, &mut *server, &mut now, &mut out, |(_, s)| {
            s.close_notify
        });
        drain(&mut *client, &mut out.0);
        if version == ProtocolVersion::DTLS1_2 {
            // DTLS 1.3 closes only the write half (RFC 8446 §6.1).
            assert!(client.is_closed());
        }
        version
    }

    #[test]
    fn rfc5764_4_dtls_1_2_completes_between_two_sessions() {
        assert_eq!(
            handshake(DtlsVersion::Dtls12, DtlsVersion::Dtls12),
            ProtocolVersion::DTLS1_2
        );
    }

    #[test]
    fn rfc9147_dtls_1_3_completes_between_two_sessions() {
        assert_eq!(
            handshake(DtlsVersion::Dtls13, DtlsVersion::Dtls13),
            ProtocolVersion::DTLS1_3
        );
    }

    #[test]
    fn an_auto_server_follows_the_client_version() {
        assert_eq!(
            handshake(DtlsVersion::Dtls13, DtlsVersion::Auto),
            ProtocolVersion::DTLS1_3
        );
    }

    #[test]
    fn an_mtu_too_small_for_a_dtls_record_is_refused() {
        let cert = Dtls.generate_certificate().unwrap();
        let err = Dtls
            .new_dtls(&cert, SystemClock.now(), DtlsVersion::Dtls12, Some(10))
            .unwrap_err();
        assert!(matches!(err, CryptoError::DtlsImpl(_)), "{err}");
    }
}
