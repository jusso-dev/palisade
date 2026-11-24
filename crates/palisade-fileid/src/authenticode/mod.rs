//! Authenticode for PE images.
//!
//! - [`hash`]: the Authenticode image hash (#47), which identifies a PE file
//!   independently of its embedded signature.
//! - Signature parsing and verification (#48): [`verify_pe`],
//!   [`verify_signatures`] and [`verify_certificate_table`] read every
//!   `WIN_CERTIFICATE` entry, decode each PKCS#7 SignedData and its nested
//!   signatures, and check them. The result is a [`SignatureReport`] with
//!   one [`SignatureInfo`] per signature, the primary signature and the
//!   file's [`SigningState`].
//!
//! # What "valid" means here
//!
//! A signature is [`SignatureStatus::Valid`] when all of these hold:
//!
//! 1. it parses as an Authenticode SignedData: content type
//!    `SPC_INDIRECT_DATA`, a `SPC_PE_IMAGE_DATA` indirect data, exactly one
//!    SignerInfo with `contentType` and `messageDigest` attributes;
//! 2. the `messageDigest` attribute equals the hash of the encoded
//!    `SpcIndirectDataContent`;
//! 3. a certificate in the blob matches the SignerInfo's signer identifier,
//!    and the signature over the DER-encoded authenticated attributes
//!    verifies with its public key;
//! 4. the image digest in the indirect data equals the file's Authenticode
//!    digest under the same algorithm;
//! 5. neither digest is MD2 or MD5.
//!
//! It does **not** mean the signer is trusted. Building and validating the
//! certificate chain, EKUs and signer attributes is #49; timestamps, expiry
//! and revocation are #50. [`SignatureInfo::timestamp_tokens`] and
//! [`SignatureInfo::certs_in_blob`] carry what those modules need.
//!
//! # Untrusted input
//!
//! The certificate table and everything in it is attacker-controlled. The
//! ASN.1 layer (one module, `asn1.rs`, kept small for audit) accepts DER only, rejects BER indefinite lengths
//! and oversized or non-minimal lengths with a typed [`Asn1Error`], and
//! borrows instead of allocating, so no declared length sizes an
//! allocation. Fixed limits bound the rest: [`MAX_CERTIFICATE_ENTRIES`],
//! [`MAX_CERTIFICATE_TABLE_SIZE`], [`MAX_NESTING_DEPTH`],
//! [`MAX_SIGNATURES`], [`MAX_CERTIFICATES`], [`MAX_TIMESTAMPS`] and
//! [`MAX_WARNINGS`]. Nothing panics.
//!
//! # Cryptography
//!
//! Signature verification goes through one thin module that wraps `ring`
//! (ADR 0008). RSA PKCS#1 v1.5 (SHA-1, SHA-256, SHA-384, SHA-512), RSA-PSS
//! (SHA-256, SHA-384, SHA-512, with MGF1 over the same digest and a salt as
//! long as it) and ECDSA P-256 and P-384 (SHA-256, SHA-384) are verified.
//! ECDSA P-521, Ed25519, Ed448 and other combinations are reported as
//! [`SignatureStatus::Unsupported`], never as valid.
//!
//! # OS-native signer rules
//!
//! OS code integrity accepts only RSA signers of up to 4096 bits, and no
//! MD2 or MD5. [`SignatureInfo::os_ci_compatible`] is `false`, with the
//! reasons in [`SignatureInfo::os_ci_issues`], for any other signer, so a
//! compiled rule never silently fails.

#![forbid(unsafe_code)]

mod asn1;
mod crypto;
pub mod hash;
mod pkcs7;
mod signature;
mod verify;

pub use asn1::{Asn1Error, Asn1ErrorKind, ObjectId};
pub use hash::{
    AuthenticodeError, AuthenticodeHashes, AuthenticodeStatus, HashRanges, HashScenario,
    NonConformance, RangeHasher, authenticode_hashes, hash_pe,
};
pub use pkcs7::{MAX_CERTIFICATES, MAX_TIMESTAMPS, MAX_WARNINGS};
pub use signature::{
    BadSignature, CertificateEntry, CertificateTableError, Curve, DigestAlgorithm, InvalidReason,
    KeyAlgorithm, OsCiIssue, PageHashes, ReportWarning, SignatureAlgorithm, SignatureCheck,
    SignatureError, SignatureInfo, SignatureKind, SignatureReport, SignatureStatus,
    SignatureWarning, SignerAttributes, SignerIdentifier, SigningState, StatementType,
    TimestampKind, TimestampToken, Unsupported, VerifyOptions,
};
pub use verify::{
    MAX_CERTIFICATE_ENTRIES, MAX_CERTIFICATE_TABLE_SIZE, MAX_NESTING_DEPTH, MAX_SIGNATURES,
    verify_certificate_table, verify_pe, verify_signatures,
};
