//! Key inventory, signed trust sets and signing for Palisade's internal PKI
//! (part of #224).
//!
//! Both the agent and the server need this code: the server builds and signs
//! trust sets, and the agent verifies them. ADR 0003 puts code shared by the
//! sibling binaries in `palisade-proto`. It cannot go in `palisade-core`,
//! which has no third-party dependencies and builds `no_std` for the kernel
//! driver, while signatures need `ring` (ADR 0008).
//!
//! - [`key`]: key IDs, purposes, algorithms, the key lifecycle and the
//!   device-certificate binding.
//! - [`trust_set`]: the signed trust-set manifest, its canonical encoding,
//!   and the agent's acceptance rule.
//! - [`signer`]: the [`Signer`] interface and an in-memory software back end.
//! - [`lifecycle`]: renewal, expiry-alert and rotation-overlap schedules,
//!   and trust-version adoption.
//! - [`time`]: validity windows with clock-skew tolerance, and the clock.
//!
//! Every signature covers a [`Domain`] prefix followed by the payload, so a
//! signature made for one purpose can never verify as another
//! (threat: T-signer-02). The only module that calls `ring` is the
//! crate-private `crypto` module.

#![forbid(unsafe_code)]

pub(crate) mod crypto;
pub mod key;
pub mod lifecycle;
pub mod signer;
pub mod time;
pub mod trust_set;

#[cfg(test)]
mod tests;

use std::fmt;

pub use key::{
    CertificateBinding, KeyAlgorithm, KeyBackend, KeyError, KeyPurpose, KeyRecord, KeyStatus,
    KeyType, Kid, PublicKey, SignatureAlgorithm, spki_sha256,
};
pub use lifecycle::{
    Adoption, ExpiryAlert, ExpiryAlerts, LifecycleError, RenewalPolicy, RenewalStatus,
    RotationPhase, RotationPlan,
};
pub use signer::{Signature, Signer, SignerError, SoftwareSigner};
pub use time::{Clock, FixedClock, SkewTolerance, SystemClock, TimeError, Validity};
pub use trust_set::{
    DecodeError, Rejection, SignedTrustSet, TrustAnchor, TrustSet, TrustSetError, TrustedKey,
    UpdateRootPointer, VerifyError,
};

/// What a signature is for. Each domain has its own prefix, and only keys of
/// the matching purposes may sign for it (threats: T-signer-02, T-signer-06).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Domain {
    /// A trust-set manifest. Signed by `root-ca` or `trust-set` keys.
    TrustSet,
    /// A policy bundle (#225). Signed by `policy-signing` keys.
    Policy,
    /// A break-glass unlock token (#222). Signed by `unlock-token` keys.
    Unlock,
}

impl Domain {
    /// Every domain.
    pub const ALL: &'static [Self] = &[Self::TrustSet, Self::Policy, Self::Unlock];

    /// The domain-separation prefix, including its terminating NUL byte.
    #[must_use]
    pub const fn prefix(self) -> &'static [u8] {
        match self {
            Self::TrustSet => b"palisade-trustset-v1\0",
            Self::Policy => b"palisade-policy-v1\0",
            Self::Unlock => b"palisade-unlock-v1\0",
        }
    }

    /// The prefix without its NUL, for messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TrustSet => "palisade-trustset-v1",
            Self::Policy => "palisade-policy-v1",
            Self::Unlock => "palisade-unlock-v1",
        }
    }

    /// Whether a key of `purpose` may sign for this domain.
    #[must_use]
    pub const fn signed_by(self, purpose: KeyPurpose) -> bool {
        matches!(
            (self, purpose),
            (Self::TrustSet, KeyPurpose::RootCa | KeyPurpose::TrustSet)
                | (Self::Policy, KeyPurpose::PolicySigning)
                | (Self::Unlock, KeyPurpose::UnlockToken)
        )
    }

    /// The signed message: the prefix followed by `payload`.
    pub(crate) fn message(self, payload: &[u8]) -> Vec<u8> {
        let prefix = self.prefix();
        let mut message = Vec::with_capacity(prefix.len().saturating_add(payload.len()));
        message.extend_from_slice(prefix);
        message.extend_from_slice(payload);
        message
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
