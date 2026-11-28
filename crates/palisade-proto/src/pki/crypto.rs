//! The one place in `palisade-proto` that calls a cryptography library.
//!
//! ADR 0008 picks `ring` and requires call sites to go through a thin
//! `crypto` module, so a later provider swap (for example a FIPS-validated
//! one) is a one-module change. Nothing else in the crate names `ring`.
//!
//! Algorithms, and nothing else:
//!
//! | [`SignatureAlgorithm`] | Signing and verification | Signature bytes |
//! |---|---|---|
//! | `EcdsaP384Sha384` | ECDSA over P-384, SHA-384 of the message | 96: `r ‖ s`, each 48 bytes big-endian |
//! | `Ed25519` | Pure Ed25519 (RFC 8032) | 64 |
//!
//! ECDSA signatures use the fixed-length `r ‖ s` form, not DER, so every
//! signature has exactly one length and the envelope can check it before
//! verification. `ring` generates ECDSA nonces internally and hedges them
//! with the message digest.
//!
//! MACs are HMAC-SHA-256 (ADR 0008), used for the policy anti-rollback
//! record (`policy_bundle::record`). Tags are checked in constant time.
//!
//! Data at rest is sealed with AES-256-GCM ([`AeadKey`], ADR 0017). The
//! seal call takes no nonce: each one is drawn here from the OS secure
//! random source, so no caller can choose or reuse one.

#![forbid(unsafe_code)]

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{
    self as ring_sig, EcdsaKeyPair, Ed25519KeyPair, KeyPair, UnparsedPublicKey,
    VerificationAlgorithm,
};

use super::key::SignatureAlgorithm;

/// SHA-256 of `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    for (o, b) in out.iter_mut().zip(digest.as_ref()) {
        *o = *b;
    }
    out
}

/// An HMAC-SHA-256 key. `Debug` never prints it.
pub(crate) struct MacKey(ring::hmac::Key);

impl MacKey {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key))
    }

    /// The 32-byte tag over `message`.
    pub(crate) fn tag(&self, message: &[u8]) -> [u8; 32] {
        let tag = ring::hmac::sign(&self.0, message);
        let mut out = [0u8; 32];
        for (o, b) in out.iter_mut().zip(tag.as_ref()) {
            *o = *b;
        }
        out
    }

    /// Whether `tag` is the tag over `message`, compared in constant time.
    pub(crate) fn verify(&self, message: &[u8], tag: &[u8]) -> bool {
        ring::hmac::verify(&self.0, message, tag).is_ok()
    }
}

impl fmt::Debug for MacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MacKey(..)")
    }
}

/// Verifies `signature` over `message` with a raw public key (the uncompressed
/// P-384 point, or the 32-byte Ed25519 key). Any failure, including a
/// malformed key, is `false`.
pub(crate) fn verify(
    alg: SignatureAlgorithm,
    raw_public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let ring_alg: &'static dyn VerificationAlgorithm = match alg {
        SignatureAlgorithm::EcdsaP384Sha384 => &ring_sig::ECDSA_P384_SHA384_FIXED,
        SignatureAlgorithm::Ed25519 => &ring_sig::ED25519,
    };
    UnparsedPublicKey::new(ring_alg, raw_public_key)
        .verify(message, signature)
        .is_ok()
}

/// Fills `out` from the operating system's secure random source.
pub(crate) fn random(out: &mut [u8]) -> Result<(), CryptoError> {
    use ring::rand::SecureRandom as _;
    SystemRandom::new()
        .fill(out)
        .map_err(|_| CryptoError("the secure random source failed"))
}

/// The AES-GCM nonce length.
pub(crate) const NONCE_LEN: usize = ring::aead::NONCE_LEN;
/// The AES-GCM tag length.
pub(crate) const TAG_LEN: usize = 16;

/// An AES-256-GCM key. `Debug` never prints it.
pub(crate) struct AeadKey(ring::aead::LessSafeKey);

impl AeadKey {
    pub(crate) fn new(key: &[u8; 32]) -> Result<Self, CryptoError> {
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
            .map(|k| Self(ring::aead::LessSafeKey::new(k)))
            .map_err(|_| CryptoError("not an AES-256 key"))
    }

    /// Seals `plaintext` with a fresh random nonce, authenticating `aad`
    /// too. Returns `nonce ‖ ciphertext ‖ tag`.
    pub(crate) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        random(&mut nonce)?;
        let mut out = Vec::with_capacity(
            NONCE_LEN
                .saturating_add(plaintext.len())
                .saturating_add(TAG_LEN),
        );
        out.extend_from_slice(&nonce);
        let mut body = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(aad),
                &mut body,
            )
            .map_err(|_| CryptoError("sealing failed"))?;
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Opens `nonce ‖ ciphertext ‖ tag`. `None` unless the tag verifies
    /// over the ciphertext and `aad`.
    pub(crate) fn open(&self, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        let (nonce, body) = sealed.split_at_checked(NONCE_LEN)?;
        if body.len() < TAG_LEN {
            return None;
        }
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut body = body.to_vec();
        let len = self
            .0
            .open_in_place(nonce, ring::aead::Aad::from(aad), &mut body)
            .ok()?
            .len();
        body.truncate(len);
        Some(body)
    }

    /// Seals with a nonce the caller gives. Only for the known-answer test.
    #[cfg(test)]
    pub(crate) fn seal_with_nonce(
        &self,
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut body = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(aad),
                &mut body,
            )
            .unwrap();
        body
    }
}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKey(..)")
    }
}

/// The secure random source, shared by key generation and ECDSA signing.
pub(crate) struct Rng(SystemRandom);

impl Rng {
    pub(crate) fn new() -> Self {
        Self(SystemRandom::new())
    }
}

impl Rng {
    /// Fills `out` from the operating system's secure random source.
    #[cfg(feature = "issuance")]
    pub(crate) fn fill(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        use ring::rand::SecureRandom as _;
        self.0
            .fill(out)
            .map_err(|_| CryptoError("the secure random source failed"))
    }
}

impl fmt::Debug for Rng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rng")
    }
}

/// A key generation, import or signing operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CryptoError(pub(crate) &'static str);

/// A private signing key held in process memory.
pub(crate) enum PrivateKey {
    EcdsaP384(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

impl fmt::Debug for PrivateKey {
    // Never prints key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

/// Generates a new private key and returns its unencrypted PKCS#8 document,
/// for a key whose owner stores it (the device key, #223). The caller wipes
/// it.
pub(crate) fn generate_pkcs8(alg: SignatureAlgorithm, rng: &Rng) -> Result<Vec<u8>, CryptoError> {
    const ERR: CryptoError = CryptoError("key generation failed");
    let doc = match alg {
        SignatureAlgorithm::EcdsaP384Sha384 => {
            EcdsaKeyPair::generate_pkcs8(&ring_sig::ECDSA_P384_SHA384_FIXED_SIGNING, &rng.0)
        }
        SignatureAlgorithm::Ed25519 => Ed25519KeyPair::generate_pkcs8(&rng.0),
    }
    .map_err(|_| ERR)?;
    Ok(doc.as_ref().to_vec())
}

impl PrivateKey {
    /// Generates a new private key. The key never leaves process memory: the
    /// PKCS#8 document `ring` produces is parsed straight back and dropped.
    pub(crate) fn generate(alg: SignatureAlgorithm, rng: &Rng) -> Result<Self, CryptoError> {
        const ERR: CryptoError = CryptoError("key generation failed");
        match alg {
            SignatureAlgorithm::EcdsaP384Sha384 => {
                let doc = EcdsaKeyPair::generate_pkcs8(
                    &ring_sig::ECDSA_P384_SHA384_FIXED_SIGNING,
                    &rng.0,
                )
                .map_err(|_| ERR)?;
                Self::from_pkcs8(alg, doc.as_ref(), rng).map_err(|_| ERR)
            }
            SignatureAlgorithm::Ed25519 => {
                let doc = Ed25519KeyPair::generate_pkcs8(&rng.0).map_err(|_| ERR)?;
                Self::from_pkcs8(alg, doc.as_ref(), rng).map_err(|_| ERR)
            }
        }
    }

    /// Reads an unencrypted PKCS#8 private key of the given algorithm.
    ///
    /// ECDSA keys must carry their public key (PKCS#8 v1 `ECPrivateKey` with
    /// the optional public key), which is checked against the private key.
    /// Ed25519 keys may be PKCS#8 v1 or v2; a v2 public key is checked.
    pub(crate) fn from_pkcs8(
        alg: SignatureAlgorithm,
        der: &[u8],
        rng: &Rng,
    ) -> Result<Self, CryptoError> {
        const ERR: CryptoError =
            CryptoError("not an unencrypted PKCS#8 key of the stated algorithm");
        match alg {
            SignatureAlgorithm::EcdsaP384Sha384 => {
                EcdsaKeyPair::from_pkcs8(&ring_sig::ECDSA_P384_SHA384_FIXED_SIGNING, der, &rng.0)
                    .map(Self::EcdsaP384)
                    .map_err(|_| ERR)
            }
            SignatureAlgorithm::Ed25519 => Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
                .map(Self::Ed25519)
                .map_err(|_| ERR),
        }
    }

    pub(crate) fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::EcdsaP384(_) => SignatureAlgorithm::EcdsaP384Sha384,
            Self::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }

    /// The raw public key, in the form [`verify`] takes.
    pub(crate) fn raw_public_key(&self) -> &[u8] {
        match self {
            Self::EcdsaP384(k) => k.public_key().as_ref(),
            Self::Ed25519(k) => k.public_key().as_ref(),
        }
    }

    /// Signs `message` (which the algorithm hashes itself).
    pub(crate) fn sign(&self, rng: &Rng, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::EcdsaP384(k) => k
                .sign(&rng.0, message)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| CryptoError("signing failed")),
            Self::Ed25519(k) => Ok(k.sign(message).as_ref().to_vec()),
        }
    }

    /// Signs `message` for an X.509 structure: an ECDSA P-384 signature
    /// over the SHA-384 of `message`, DER-encoded as `ECDSA-Sig-Value`
    /// (RFC 5480), the form certificates and revocation lists carry.
    /// Ed25519 keys are refused: no key purpose that issues certificates
    /// allows them.
    pub(crate) fn sign_x509(&self, rng: &Rng, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::EcdsaP384(k) => {
                let fixed = k
                    .sign(&rng.0, message)
                    .map_err(|_| CryptoError("signing failed"))?;
                Ok(ecdsa_fixed_to_der(fixed.as_ref()))
            }
            Self::Ed25519(_) => Err(CryptoError("Ed25519 keys do not sign certificates")),
        }
    }
}

/// Converts a fixed-length ECDSA signature (`r ‖ s`, each half the length)
/// to DER `SEQUENCE { INTEGER r, INTEGER s }`. Each integer is minimal:
/// leading zero bytes are dropped and one is added back when the high bit
/// is set, so the value stays positive. For P-384 the whole encoding is at
/// most 104 bytes, so every length fits the short form.
pub(crate) fn ecdsa_fixed_to_der(fixed: &[u8]) -> Vec<u8> {
    let (r, s) = fixed.split_at(fixed.len() / 2);
    let mut body = Vec::with_capacity(fixed.len().saturating_add(6));
    for half in [r, s] {
        let start = half.iter().position(|&b| b != 0).unwrap_or(half.len());
        let digits = half.get(start..).unwrap_or_default();
        let pad = digits.first().is_none_or(|&b| b & 0x80 != 0);
        body.push(0x02);
        body.push(short_len(digits.len().saturating_add(usize::from(pad))));
        if pad {
            body.push(0x00);
        }
        body.extend_from_slice(digits);
    }
    let mut der = Vec::with_capacity(body.len().saturating_add(2));
    der.push(0x30);
    der.push(short_len(body.len()));
    der.extend_from_slice(&body);
    der
}

/// A DER short-form length. Callers only pass lengths below 128.
fn short_len(len: usize) -> u8 {
    u8::try_from(len).unwrap_or(u8::MAX) & 0x7f
}

/// Verifies a DER `ECDSA-Sig-Value` P-384 SHA-384 signature over `message`
/// with a raw (uncompressed) P-384 public key. For tests of the X.509 path.
#[cfg(test)]
pub(crate) fn verify_p384_der(raw_public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ring_sig::ECDSA_P384_SHA384_ASN1, raw_public_key)
        .verify(message, signature)
        .is_ok()
}

/// A fresh unencrypted PKCS#8 key, for import tests. Test keys are made at
/// run time so no private key is ever committed.
#[cfg(test)]
pub(crate) fn test_pkcs8(alg: SignatureAlgorithm) -> Vec<u8> {
    let rng = SystemRandom::new();
    let doc = match alg {
        SignatureAlgorithm::EcdsaP384Sha384 => {
            EcdsaKeyPair::generate_pkcs8(&ring_sig::ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
        }
        SignatureAlgorithm::Ed25519 => Ed25519KeyPair::generate_pkcs8(&rng),
    };
    doc.unwrap().as_ref().to_vec()
}
