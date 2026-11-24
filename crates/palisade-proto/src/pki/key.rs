//! The key inventory: key IDs, purposes, algorithms, lifecycle states and
//! public keys.

use std::fmt;
use std::str::FromStr;

use crate::events::{Hex, Sha256Hex, Timestamp};

use super::crypto;
use super::time::Validity;

/// A key ID: the first 16 bytes of the SHA-256 of the key's DER
/// `SubjectPublicKeyInfo`, written as 32 lowercase hex digits.
///
/// The ID is derived from the public key, never assigned, so two records
/// with the same `kid` always describe the same key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kid([u8; 16]);

impl Kid {
    /// Wraps raw key-ID bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw key-ID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The key ID of a DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn of_spki(spki_der: &[u8]) -> Self {
        let digest = crypto::sha256(spki_der);
        let mut kid = [0u8; 16];
        for (k, d) in kid.iter_mut().zip(digest) {
            *k = d;
        }
        Self(kid)
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hex::from_bytes(self.0).fmt(f)
    }
}

impl fmt::Debug for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kid({self})")
    }
}

impl FromStr for Kid {
    type Err = KeyError;

    /// Accepts exactly 32 lowercase hex digits.
    fn from_str(s: &str) -> Result<Self, KeyError> {
        Hex::<16>::from_str(s)
            .map(|h| Self(*h.as_bytes()))
            .map_err(|_| KeyError::InvalidKid)
    }
}

/// The SHA-256 of a DER `SubjectPublicKeyInfo`: the form of a server CA pin
/// and of a device certificate's key fingerprint.
#[must_use]
pub fn spki_sha256(spki_der: &[u8]) -> Sha256Hex {
    Sha256Hex::from_bytes(crypto::sha256(spki_der))
}

/// Declares a fieldless enum with a stable text label and a stable one-byte
/// wire code for each variant.
macro_rules! labelled_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident ($what:literal) {
            $( $(#[$vmeta:meta])* $variant:ident = ($code:literal, $label:literal), )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The text label.
            #[must_use]
            pub const fn label(self) -> &'static str {
                match self { $(Self::$variant => $label,)+ }
            }

            /// The one-byte code used in signed manifests. Codes are never
            /// reused.
            #[must_use]
            pub const fn code(self) -> u8 {
                match self { $(Self::$variant => $code,)+ }
            }

            /// The variant with this wire code.
            #[must_use]
            pub const fn from_code(code: u8) -> Option<Self> {
                match code { $($code => Some(Self::$variant),)+ _ => None }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.label())
            }
        }

        impl FromStr for $name {
            type Err = KeyError;

            fn from_str(s: &str) -> Result<Self, KeyError> {
                match s {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(KeyError::UnknownLabel($what)),
                }
            }
        }
    };
}

labelled_enum! {
    /// What a key is for. Keys are never shared between purposes, so a stolen
    /// key's blast radius is one purpose (threat: T-signer-06).
    pub enum KeyPurpose ("key purpose") {
        /// Offline root: signs intermediate CA certificates and trust sets.
        RootCa = (1, "root-ca"),
        /// Online issuing CA: issues device, relay and server certificates.
        IssuingCa = (2, "issuing-ca"),
        /// The server's TLS key.
        ServerTls = (3, "server-tls"),
        /// The online trust-set key, endorsed by the root through a trust set,
        /// which signs later trust sets.
        TrustSet = (4, "trust-set"),
        /// Signs policy bundles (#225).
        PolicySigning = (5, "policy-signing"),
        /// Signs release metadata. Held by the release pipeline (#226).
        UpdateSigning = (6, "update-signing"),
        /// Signs break-glass unlock tokens (#222).
        UnlockToken = (7, "unlock-token"),
        /// Encrypts escrowed device secrets.
        Escrow = (8, "escrow"),
        /// Anchors the admin audit hash chain (#229).
        AuditChain = (9, "audit-chain"),
    }
}

labelled_enum! {
    /// A key's algorithm. Signing keys use one of the two Palisade-native
    /// signature algorithms of ADR 0008. The escrow key is an encryption key.
    pub enum KeyAlgorithm ("key algorithm") {
        /// ECDSA over P-384 with SHA-384. The default for every signing key.
        EcdsaP384Sha384 = (1, "ecdsa-p384-sha384"),
        /// Ed25519. Opt-in, for `policy-signing` and `unlock-token` only.
        Ed25519 = (2, "ed25519"),
        /// ECDH over P-384, for the escrow key. Not a signature algorithm.
        EcdhP384 = (3, "ecdh-p384"),
    }
}

labelled_enum! {
    /// A signature algorithm, as named in a signature envelope.
    pub enum SignatureAlgorithm ("signature algorithm") {
        /// ECDSA over P-384 with SHA-384, fixed-length `r ‖ s` (96 bytes).
        EcdsaP384Sha384 = (1, "ecdsa-p384-sha384"),
        /// Ed25519 (64 bytes).
        Ed25519 = (2, "ed25519"),
    }
}

labelled_enum! {
    /// Where a private key lives.
    pub enum KeyBackend ("key backend") {
        /// A software key. `SoftwareSigner` holds it in process memory; at-rest
        /// encryption of key files is #227.
        File = (1, "file"),
        /// A hardware security module, through PKCS#11.
        Pkcs11 = (2, "pkcs11"),
        /// A cloud key-management service.
        Kms = (3, "kms"),
    }
}

labelled_enum! {
    /// A key's lifecycle state.
    ///
    /// Legal transitions:
    ///
    /// | From | To |
    /// |---|---|
    /// | `pending` | `active`, `retired` (never used), `compromised` |
    /// | `active` | `retiring`, `compromised` |
    /// | `retiring` | `retired`, `active` (rotation aborted), `compromised` |
    /// | `retired` | `compromised` |
    /// | `compromised` | none |
    ///
    /// Only `active` keys sign. `active` and `retiring` keys verify, which
    /// gives rotations their overlap. `compromised` is final.
    pub enum KeyStatus ("key status") {
        /// Generated or imported, not yet in use.
        Pending = (1, "pending"),
        /// Signs and verifies.
        Active = (2, "active"),
        /// Verifies only, while its successor takes over.
        Retiring = (3, "retiring"),
        /// No longer used.
        Retired = (4, "retired"),
        /// Must never be trusted again.
        Compromised = (5, "compromised"),
    }
}

impl KeyPurpose {
    /// Whether a key of this purpose may use `alg`.
    #[must_use]
    pub const fn allows(self, alg: KeyAlgorithm) -> bool {
        match self {
            Self::PolicySigning | Self::UnlockToken => {
                matches!(alg, KeyAlgorithm::EcdsaP384Sha384 | KeyAlgorithm::Ed25519)
            }
            Self::Escrow => matches!(alg, KeyAlgorithm::EcdhP384),
            Self::RootCa
            | Self::IssuingCa
            | Self::ServerTls
            | Self::TrustSet
            | Self::UpdateSigning
            | Self::AuditChain => matches!(alg, KeyAlgorithm::EcdsaP384Sha384),
        }
    }
}

impl KeyAlgorithm {
    /// The signature algorithm, or `None` for an encryption key.
    #[must_use]
    pub const fn signature(self) -> Option<SignatureAlgorithm> {
        match self {
            Self::EcdsaP384Sha384 => Some(SignatureAlgorithm::EcdsaP384Sha384),
            Self::Ed25519 => Some(SignatureAlgorithm::Ed25519),
            Self::EcdhP384 => None,
        }
    }

    /// The type of public key this algorithm uses.
    #[must_use]
    pub const fn key_type(self) -> KeyType {
        match self {
            Self::EcdsaP384Sha384 | Self::EcdhP384 => KeyType::P384,
            Self::Ed25519 => KeyType::Ed25519,
        }
    }
}

impl SignatureAlgorithm {
    /// The key algorithm that produces this signature.
    #[must_use]
    pub const fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::EcdsaP384Sha384 => KeyAlgorithm::EcdsaP384Sha384,
            Self::Ed25519 => KeyAlgorithm::Ed25519,
        }
    }

    /// The exact length of a signature, in bytes.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Self::EcdsaP384Sha384 => 96,
            Self::Ed25519 => 64,
        }
    }
}

impl KeyStatus {
    /// Whether moving from `self` to `next` is a legal transition.
    #[must_use]
    pub const fn can_become(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Pending,
                Self::Active | Self::Retired | Self::Compromised
            ) | (Self::Active, Self::Retiring | Self::Compromised)
                | (
                    Self::Retiring,
                    Self::Retired | Self::Active | Self::Compromised
                )
                | (Self::Retired, Self::Compromised)
        )
    }

    /// Whether a key in this state may make new signatures.
    #[must_use]
    pub const fn signs(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether signatures by a key in this state are still accepted.
    #[must_use]
    pub const fn verifies(self) -> bool {
        matches!(self, Self::Active | Self::Retiring)
    }
}

/// The type of a public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyType {
    /// An elliptic-curve key on NIST P-384.
    P384,
    /// An Ed25519 key.
    Ed25519,
}

/// DER prefix of a P-384 `SubjectPublicKeyInfo` (id-ecPublicKey with the
/// named curve secp384r1, then the BIT STRING header). The uncompressed
/// point (`04 ‖ x ‖ y`, 97 bytes) follows.
const P384_SPKI_PREFIX: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];
const P384_POINT_LEN: usize = 97;

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410). The 32-byte
/// key follows.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_KEY_LEN: usize = 32;

/// The longest `SubjectPublicKeyInfo` accepted, in bytes (P-384).
pub const MAX_SPKI_LEN: usize = P384_SPKI_PREFIX.len() + P384_POINT_LEN;

/// A public key, held as its DER `SubjectPublicKeyInfo`.
///
/// Only two encodings are accepted, each byte for byte: a P-384 key with the
/// named curve and an uncompressed point, and an Ed25519 key. Every key
/// therefore has exactly one encoding and so exactly one [`Kid`]. A point
/// that is not on the curve is caught at verification, which then fails.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    key_type: KeyType,
    spki: Vec<u8>,
}

impl PublicKey {
    /// Reads a DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnsupportedPublicKey`] for anything but the two accepted
    /// encodings.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, KeyError> {
        let key_type = if der.len() == P384_SPKI_PREFIX.len() + P384_POINT_LEN
            && der.starts_with(&P384_SPKI_PREFIX)
            && der.get(P384_SPKI_PREFIX.len()) == Some(&0x04)
        {
            KeyType::P384
        } else if der.len() == ED25519_SPKI_PREFIX.len() + ED25519_KEY_LEN
            && der.starts_with(&ED25519_SPKI_PREFIX)
        {
            KeyType::Ed25519
        } else {
            return Err(KeyError::UnsupportedPublicKey);
        };
        Ok(Self {
            key_type,
            spki: der.to_vec(),
        })
    }

    /// Builds the `SubjectPublicKeyInfo` around a raw key: the uncompressed
    /// P-384 point, or the 32-byte Ed25519 key.
    pub(crate) fn from_raw(key_type: KeyType, raw: &[u8]) -> Result<Self, KeyError> {
        let prefix: &[u8] = match key_type {
            KeyType::P384 => &P384_SPKI_PREFIX,
            KeyType::Ed25519 => &ED25519_SPKI_PREFIX,
        };
        let mut der = Vec::with_capacity(prefix.len() + raw.len());
        der.extend_from_slice(prefix);
        der.extend_from_slice(raw);
        let key = Self::from_spki_der(&der)?;
        if key.key_type == key_type {
            Ok(key)
        } else {
            Err(KeyError::UnsupportedPublicKey)
        }
    }

    /// The key type.
    #[must_use]
    pub const fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// The DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }

    /// The key ID.
    #[must_use]
    pub fn kid(&self) -> Kid {
        Kid::of_spki(&self.spki)
    }

    /// The SHA-256 of the `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn spki_sha256(&self) -> Sha256Hex {
        spki_sha256(&self.spki)
    }

    /// The raw key after the fixed prefix.
    fn raw(&self) -> &[u8] {
        let prefix_len = match self.key_type {
            KeyType::P384 => P384_SPKI_PREFIX.len(),
            KeyType::Ed25519 => ED25519_SPKI_PREFIX.len(),
        };
        self.spki.get(prefix_len..).unwrap_or_default()
    }

    /// Verifies a signature over `domain`'s prefix followed by `payload`.
    ///
    /// Returns `false` if the algorithm does not fit this key, or the
    /// signature is invalid or has the wrong length.
    #[must_use]
    pub fn verify(
        &self,
        alg: SignatureAlgorithm,
        domain: super::Domain,
        payload: &[u8],
        signature: &[u8],
    ) -> bool {
        if alg.key_algorithm().key_type() != self.key_type || signature.len() != alg.signature_len()
        {
            return false;
        }
        crypto::verify(alg, self.raw(), &domain.message(payload), signature)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({:?}, kid {})", self.key_type, self.kid())
    }
}

/// One key in the inventory: its public half and everything recorded about
/// it. The private half lives in a [`Signer`](super::Signer) back end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    public_key: PublicKey,
    purpose: KeyPurpose,
    algorithm: KeyAlgorithm,
    created_at: Timestamp,
    validity: Validity,
    status: KeyStatus,
    backend: KeyBackend,
}

impl KeyRecord {
    /// A new record, in state [`KeyStatus::Pending`].
    ///
    /// # Errors
    ///
    /// [`KeyError::AlgorithmNotAllowed`] if the purpose does not allow the
    /// algorithm (ADR 0008, #224), and [`KeyError::KeyTypeMismatch`] if the
    /// public key is not of the algorithm's type.
    pub fn new(
        public_key: PublicKey,
        purpose: KeyPurpose,
        algorithm: KeyAlgorithm,
        created_at: Timestamp,
        validity: Validity,
        backend: KeyBackend,
    ) -> Result<Self, KeyError> {
        if !purpose.allows(algorithm) {
            return Err(KeyError::AlgorithmNotAllowed { purpose, algorithm });
        }
        if algorithm.key_type() != public_key.key_type() {
            return Err(KeyError::KeyTypeMismatch);
        }
        Ok(Self {
            public_key,
            purpose,
            algorithm,
            created_at,
            validity,
            status: KeyStatus::Pending,
            backend,
        })
    }

    /// The key ID.
    #[must_use]
    pub fn kid(&self) -> Kid {
        self.public_key.kid()
    }

    /// The public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The purpose.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// When the key was generated or imported.
    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// The validity window.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// The lifecycle state.
    #[must_use]
    pub const fn status(&self) -> KeyStatus {
        self.status
    }

    /// Where the private key lives.
    #[must_use]
    pub const fn backend(&self) -> KeyBackend {
        self.backend
    }

    /// Moves the key to `next`.
    ///
    /// # Errors
    ///
    /// [`KeyError::IllegalTransition`] if [`KeyStatus::can_become`] forbids
    /// it. The record is unchanged.
    pub fn transition(&mut self, next: KeyStatus) -> Result<(), KeyError> {
        if self.status.can_become(next) {
            self.status = next;
            Ok(())
        } else {
            Err(KeyError::IllegalTransition {
                from: self.status,
                to: next,
            })
        }
    }

    /// Whether the key may sign at `now`: it is active and inside its
    /// validity window, with no skew allowance. Signing happens on the
    /// server, whose clock is synchronised.
    #[must_use]
    pub fn can_sign(&self, now: Timestamp) -> bool {
        self.status.signs() && self.validity.contains(now)
    }
}

/// A device or relay certificate as the server enrolled it: its serial and
/// the SHA-256 of its public key (threat: T-ca-02).
///
/// A presented certificate matches only if **both** agree, so a certificate
/// minted by a stolen issuing CA with a reused serial and a new key is
/// refused. Wiring this into the mTLS handshake is #223.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateBinding {
    serial: Vec<u8>,
    spki_sha256: Sha256Hex,
}

impl CertificateBinding {
    /// The longest serial accepted, in bytes (RFC 5280 allows 20 octets).
    pub const MAX_SERIAL_LEN: usize = 20;

    /// Records a certificate's serial (the DER INTEGER content octets) and
    /// public key.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidSerial`] if the serial is empty or longer than
    /// [`Self::MAX_SERIAL_LEN`].
    pub fn new(serial: &[u8], spki_der: &[u8]) -> Result<Self, KeyError> {
        if serial.is_empty() || serial.len() > Self::MAX_SERIAL_LEN {
            return Err(KeyError::InvalidSerial);
        }
        Ok(Self {
            serial: serial.to_vec(),
            spki_sha256: spki_sha256(spki_der),
        })
    }

    /// The SHA-256 of the enrolled public key.
    #[must_use]
    pub const fn spki_sha256(&self) -> &Sha256Hex {
        &self.spki_sha256
    }

    /// Whether a presented certificate's serial and public key both match.
    #[must_use]
    pub fn matches(&self, serial: &[u8], spki_der: &[u8]) -> bool {
        self.serial == serial && self.spki_sha256 == spki_sha256(spki_der)
    }
}

/// A key-inventory value is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// A key ID is not 32 lowercase hex digits.
    InvalidKid,
    /// A text label is not one of the known values; names which kind.
    UnknownLabel(&'static str),
    /// The public key is not a P-384 or Ed25519 key in the accepted encoding.
    UnsupportedPublicKey,
    /// The purpose does not allow the algorithm.
    AlgorithmNotAllowed {
        /// The key's purpose.
        purpose: KeyPurpose,
        /// The rejected algorithm.
        algorithm: KeyAlgorithm,
    },
    /// The public key is not of the algorithm's key type.
    KeyTypeMismatch,
    /// The lifecycle does not allow this transition.
    IllegalTransition {
        /// The current state.
        from: KeyStatus,
        /// The requested state.
        to: KeyStatus,
    },
    /// A certificate serial is empty or too long.
    InvalidSerial,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKid => f.write_str("a key ID is 32 lowercase hexadecimal digits"),
            Self::UnknownLabel(what) => write!(f, "unknown {what}"),
            Self::UnsupportedPublicKey => {
                f.write_str("expected a P-384 or Ed25519 SubjectPublicKeyInfo")
            }
            Self::AlgorithmNotAllowed { purpose, algorithm } => {
                write!(f, "a {purpose} key may not use {algorithm}")
            }
            Self::KeyTypeMismatch => f.write_str("the public key does not fit the algorithm"),
            Self::IllegalTransition { from, to } => {
                write!(f, "a key cannot go from {from} to {to}")
            }
            Self::InvalidSerial => f.write_str("a certificate serial is 1 to 20 bytes"),
        }
    }
}

impl std::error::Error for KeyError {}
