//! The one place that calls a signature-verification library.
//!
//! ADR 0008 picks `ring` for signature verification and requires call sites
//! to go through a thin `crypto` module, so swapping the provider later is a
//! one-module change. Outside this module, only the hash cache's MAC
//! module (`hash/mac.rs`) names `ring`.
//!
//! What `ring` 0.17 verifies, and so what Palisade verifies:
//!
//! | Scheme | Digests | Key sizes |
//! |---|---|---|
//! | RSA PKCS#1 v1.5 | SHA-1, SHA-256, SHA-384, SHA-512 | 2048 to 8192 bits (1024 to 8192 for SHA-1, SHA-256 and SHA-512) |
//! | RSA-PSS (MGF1 with the same digest, salt length equal to the digest length) | SHA-256, SHA-384, SHA-512 | 2048 to 8192 bits |
//! | ECDSA P-256 | SHA-256, SHA-384 | |
//! | ECDSA P-384 | SHA-256, SHA-384 | |
//!
//! Anything else (ECDSA P-521, other digest and curve pairings, PSS with
//! other parameters, Ed25519, Ed448, MD5 or MD2) is reported as
//! [`Unsupported`] and is **never** treated as valid.

#![forbid(unsafe_code)]

use ring::signature::{self as ring_sig, UnparsedPublicKey, VerificationAlgorithm};

use super::signature::{Curve, DigestAlgorithm, Unsupported};

/// A signer's public key, borrowed from its certificate.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PublicKey<'a> {
    /// An RSA key: the DER `RSAPublicKey` and the modulus size in bits.
    Rsa { der: &'a [u8], bits: u32 },
    /// An elliptic-curve key: the curve and the encoded point.
    Ec { curve: Curve, point: &'a [u8] },
}

/// The signature scheme a signer used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    /// RSA PKCS#1 v1.5 over the digest.
    RsaPkcs1(DigestAlgorithm),
    /// RSA-PSS with MGF1, both over this digest, and a salt as long as it.
    /// Other parameter sets are rejected before verification.
    RsaPss(DigestAlgorithm),
    /// ECDSA over the digest, DER-encoded `(r, s)`.
    Ecdsa(DigestAlgorithm),
}

/// The outcome of one verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verified {
    /// The signature is valid for the message and key.
    Valid,
    /// The signature is not valid for the message and key.
    Invalid,
    /// The scheme, key or digest cannot be verified here.
    Unsupported(Unsupported),
}

/// Verifies `signature` over `message` (which the scheme hashes itself).
pub(crate) fn verify(
    scheme: Scheme,
    key: PublicKey<'_>,
    message: &[u8],
    signature: &[u8],
) -> Verified {
    let (alg, key_bytes): (&'static dyn VerificationAlgorithm, &[u8]) = match (scheme, key) {
        (Scheme::RsaPkcs1(digest), PublicKey::Rsa { der, bits }) => match rsa_pkcs1(digest, bits) {
            Ok(alg) => (alg, der),
            Err(why) => return Verified::Unsupported(why),
        },
        (Scheme::RsaPss(digest), PublicKey::Rsa { der, bits }) => match rsa_pss(digest, bits) {
            Ok(alg) => (alg, der),
            Err(why) => return Verified::Unsupported(why),
        },
        (Scheme::Ecdsa(digest), PublicKey::Ec { curve, point }) => match ecdsa(curve, digest) {
            Ok(alg) => (alg, point),
            Err(why) => return Verified::Unsupported(why),
        },
        _ => return Verified::Unsupported(Unsupported::KeyAlgorithmMismatch),
    };
    match UnparsedPublicKey::new(alg, key_bytes).verify(message, signature) {
        Ok(()) => Verified::Valid,
        Err(_) => Verified::Invalid,
    }
}

fn weak_or_unknown(digest: DigestAlgorithm) -> Unsupported {
    if digest.is_broken() {
        Unsupported::WeakAlgorithm(digest)
    } else {
        Unsupported::Digest(digest)
    }
}

fn rsa_pkcs1(
    digest: DigestAlgorithm,
    bits: u32,
) -> Result<&'static dyn VerificationAlgorithm, Unsupported> {
    if !(1024..=8192).contains(&bits) {
        return Err(Unsupported::RsaKeySize(bits));
    }
    let large = bits >= 2048;
    Ok(match (digest, large) {
        (DigestAlgorithm::Sha1, true) => &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        (DigestAlgorithm::Sha1, false) => &ring_sig::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        (DigestAlgorithm::Sha256, true) => &ring_sig::RSA_PKCS1_2048_8192_SHA256,
        (DigestAlgorithm::Sha256, false) => {
            &ring_sig::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
        }
        (DigestAlgorithm::Sha384, true) => &ring_sig::RSA_PKCS1_2048_8192_SHA384,
        (DigestAlgorithm::Sha512, true) => &ring_sig::RSA_PKCS1_2048_8192_SHA512,
        (DigestAlgorithm::Sha512, false) => {
            &ring_sig::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
        }
        (DigestAlgorithm::Sha384, false) => return Err(Unsupported::RsaKeySize(bits)),
        (other, _) => return Err(weak_or_unknown(other)),
    })
}

fn rsa_pss(
    digest: DigestAlgorithm,
    bits: u32,
) -> Result<&'static dyn VerificationAlgorithm, Unsupported> {
    if !(2048..=8192).contains(&bits) {
        return Err(Unsupported::RsaKeySize(bits));
    }
    Ok(match digest {
        DigestAlgorithm::Sha256 => &ring_sig::RSA_PSS_2048_8192_SHA256,
        DigestAlgorithm::Sha384 => &ring_sig::RSA_PSS_2048_8192_SHA384,
        DigestAlgorithm::Sha512 => &ring_sig::RSA_PSS_2048_8192_SHA512,
        other => return Err(weak_or_unknown(other)),
    })
}

fn ecdsa(
    curve: Curve,
    digest: DigestAlgorithm,
) -> Result<&'static dyn VerificationAlgorithm, Unsupported> {
    Ok(match (curve, digest) {
        (Curve::P256, DigestAlgorithm::Sha256) => &ring_sig::ECDSA_P256_SHA256_ASN1,
        (Curve::P256, DigestAlgorithm::Sha384) => &ring_sig::ECDSA_P256_SHA384_ASN1,
        (Curve::P384, DigestAlgorithm::Sha256) => &ring_sig::ECDSA_P384_SHA256_ASN1,
        (Curve::P384, DigestAlgorithm::Sha384) => &ring_sig::ECDSA_P384_SHA384_ASN1,
        (Curve::P256 | Curve::P384, other) if other.is_broken() => {
            return Err(Unsupported::WeakAlgorithm(other));
        }
        (curve @ (Curve::P256 | Curve::P384), other) => {
            return Err(Unsupported::CurveDigest {
                curve,
                digest: other,
            });
        }
        (curve, _) => return Err(Unsupported::Curve(curve)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_combinations_are_never_valid() {
        let rsa = PublicKey::Rsa {
            der: &[],
            bits: 2048,
        };
        let ec = |curve| PublicKey::Ec { curve, point: &[] };
        let cases = [
            (
                Scheme::RsaPkcs1(DigestAlgorithm::Md5),
                rsa,
                Unsupported::WeakAlgorithm(DigestAlgorithm::Md5),
            ),
            (
                Scheme::RsaPkcs1(DigestAlgorithm::Sha256),
                PublicKey::Rsa {
                    der: &[],
                    bits: 512,
                },
                Unsupported::RsaKeySize(512),
            ),
            (
                Scheme::RsaPkcs1(DigestAlgorithm::Sha256),
                PublicKey::Rsa {
                    der: &[],
                    bits: 16384,
                },
                Unsupported::RsaKeySize(16384),
            ),
            (
                Scheme::RsaPkcs1(DigestAlgorithm::Sha384),
                PublicKey::Rsa {
                    der: &[],
                    bits: 1024,
                },
                Unsupported::RsaKeySize(1024),
            ),
            (
                Scheme::RsaPss(DigestAlgorithm::Sha1),
                rsa,
                Unsupported::Digest(DigestAlgorithm::Sha1),
            ),
            (
                Scheme::RsaPss(DigestAlgorithm::Sha256),
                PublicKey::Rsa {
                    der: &[],
                    bits: 1024,
                },
                Unsupported::RsaKeySize(1024),
            ),
            (
                Scheme::Ecdsa(DigestAlgorithm::Sha256),
                ec(Curve::P521),
                Unsupported::Curve(Curve::P521),
            ),
            (
                Scheme::Ecdsa(DigestAlgorithm::Sha512),
                ec(Curve::P256),
                Unsupported::CurveDigest {
                    curve: Curve::P256,
                    digest: DigestAlgorithm::Sha512,
                },
            ),
            (
                Scheme::Ecdsa(DigestAlgorithm::Sha1),
                ec(Curve::P384),
                Unsupported::CurveDigest {
                    curve: Curve::P384,
                    digest: DigestAlgorithm::Sha1,
                },
            ),
            (
                Scheme::Ecdsa(DigestAlgorithm::Sha256),
                rsa,
                Unsupported::KeyAlgorithmMismatch,
            ),
            (
                Scheme::RsaPkcs1(DigestAlgorithm::Sha256),
                ec(Curve::P256),
                Unsupported::KeyAlgorithmMismatch,
            ),
        ];
        for (scheme, key, why) in cases {
            assert_eq!(
                verify(scheme, key, b"m", b"s"),
                Verified::Unsupported(why),
                "{scheme:?}"
            );
        }
    }

    #[test]
    fn garbage_keys_and_signatures_are_invalid() {
        let rsa = PublicKey::Rsa {
            der: &[0x30, 0x00],
            bits: 2048,
        };
        assert_eq!(
            verify(
                Scheme::RsaPkcs1(DigestAlgorithm::Sha256),
                rsa,
                b"m",
                &[0; 256]
            ),
            Verified::Invalid
        );
        let ec = PublicKey::Ec {
            curve: Curve::P256,
            point: &[0x04; 65],
        };
        assert_eq!(
            verify(
                Scheme::Ecdsa(DigestAlgorithm::Sha256),
                ec,
                b"m",
                &[0x30, 0x00]
            ),
            Verified::Invalid
        );
    }
}
