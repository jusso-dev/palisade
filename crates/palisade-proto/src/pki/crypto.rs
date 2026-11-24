//! The one place in `palisade-proto` that calls a cryptography library.
//!
//! ADR 0008 picks `ring` and requires call sites to go through a thin
//! `crypto` module, so a later provider swap (for example a FIPS-validated
//! one) is a one-module change. Nothing else in `pki` names `ring`.
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

/// The secure random source, shared by key generation and ECDSA signing.
pub(crate) struct Rng(SystemRandom);

impl Rng {
    pub(crate) fn new() -> Self {
        Self(SystemRandom::new())
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
