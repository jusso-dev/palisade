//! The [`Signer`] interface and its in-memory software back end.

use std::collections::BTreeMap;
use std::fmt;

use super::Domain;
use super::crypto::{PrivateKey, Rng};
use super::key::{KeyError, KeyPurpose, KeyType, Kid, PublicKey, SignatureAlgorithm};

/// One signature: the signing key, the algorithm and the signature bytes.
/// This is the `{kid, alg, sig}` entry of ADR 0008's envelope.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    kid: Kid,
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}

impl Signature {
    /// Wraps signature bytes.
    ///
    /// # Errors
    ///
    /// [`SignerError::BadSignatureLength`] unless `bytes` has exactly
    /// [`SignatureAlgorithm::signature_len`] bytes.
    pub fn new(
        kid: Kid,
        algorithm: SignatureAlgorithm,
        bytes: Vec<u8>,
    ) -> Result<Self, SignerError> {
        if bytes.len() != algorithm.signature_len() {
            return Err(SignerError::BadSignatureLength);
        }
        Ok(Self {
            kid,
            algorithm,
            bytes,
        })
    }

    /// The signing key's ID.
    #[must_use]
    pub const fn kid(&self) -> Kid {
        self.kid
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The signature bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}, kid {})", self.algorithm, self.kid)
    }
}

/// A holder of private signing keys: a software key store, an HSM or a
/// cloud key service (#224).
///
/// The interface takes a [`Domain`] and the payload, not a digest or raw
/// message, so a back end always adds the domain-separation prefix itself
/// and refuses a domain that the key's purpose may not sign
/// (threats: T-signer-02, T-signer-06). It never exposes private keys.
///
/// The signer does not track lifecycle state: the caller checks
/// [`KeyRecord::can_sign`](super::KeyRecord::can_sign) against the key
/// inventory first. Recording each signature in the admin audit log
/// (T-signer-03) is #132.
pub trait Signer {
    /// The public key for `kid`, if this signer holds that key.
    fn public_key(&self, kid: &Kid) -> Option<PublicKey>;

    /// The purpose of the key `kid`, if this signer holds that key.
    fn purpose(&self, kid: &Kid) -> Option<KeyPurpose>;

    /// Signs `domain`'s prefix followed by `payload` with the key `kid`.
    ///
    /// # Errors
    ///
    /// [`SignerError::UnknownKey`] if the signer does not hold `kid`,
    /// [`SignerError::WrongPurpose`] if the key's purpose may not sign for
    /// `domain`, and [`SignerError::Failed`] if the back end fails.
    fn sign(&self, kid: &Kid, domain: Domain, payload: &[u8]) -> Result<Signature, SignerError>;
}

struct SoftwareKey {
    private: PrivateKey,
    public: PublicKey,
    purpose: KeyPurpose,
}

/// A [`Signer`] that holds software keys in process memory: generated here,
/// or imported from unencrypted PKCS#8.
///
/// For tests, labs and the offline root ceremony machine. Encrypting key
/// files at rest and the production-mode warning are #227; HSM and cloud
/// key-service back ends are later work under #224. `ring` does not wipe
/// key memory on drop, so the process must be trusted with the keys for its
/// whole life (threat: T-signer-04).
pub struct SoftwareSigner {
    rng: Rng,
    keys: BTreeMap<Kid, SoftwareKey>,
}

impl SoftwareSigner {
    /// An empty signer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: Rng::new(),
            keys: BTreeMap::new(),
        }
    }

    /// Generates a key for `purpose` and returns its ID.
    ///
    /// # Errors
    ///
    /// [`SignerError::Key`] if the purpose does not allow the algorithm or
    /// is not a signing purpose, and [`SignerError::Failed`] if generation
    /// fails.
    pub fn generate(
        &mut self,
        purpose: KeyPurpose,
        algorithm: SignatureAlgorithm,
    ) -> Result<Kid, SignerError> {
        check_purpose(purpose, algorithm)?;
        let private =
            PrivateKey::generate(algorithm, &self.rng).map_err(|e| SignerError::Failed(e.0))?;
        self.insert(private, purpose)
    }

    /// Imports an unencrypted PKCS#8 private key for `purpose` and returns
    /// its ID. Importing a key that is already held is an error.
    ///
    /// ECDSA keys must be PKCS#8 v1 with the public key included, which is
    /// checked against the private key. Ed25519 keys may be PKCS#8 v1 or v2.
    ///
    /// # Errors
    ///
    /// As [`Self::generate`], plus [`SignerError::BadKeyEncoding`] and
    /// [`SignerError::DuplicateKey`].
    pub fn import_pkcs8(
        &mut self,
        purpose: KeyPurpose,
        algorithm: SignatureAlgorithm,
        der: &[u8],
    ) -> Result<Kid, SignerError> {
        check_purpose(purpose, algorithm)?;
        let private = PrivateKey::from_pkcs8(algorithm, der, &self.rng)
            .map_err(|_| SignerError::BadKeyEncoding)?;
        self.insert(private, purpose)
    }

    /// The IDs of the keys held, in order.
    pub fn kids(&self) -> impl Iterator<Item = Kid> + '_ {
        self.keys.keys().copied()
    }

    fn insert(&mut self, private: PrivateKey, purpose: KeyPurpose) -> Result<Kid, SignerError> {
        let key_type = match private.algorithm() {
            SignatureAlgorithm::EcdsaP384Sha384 => KeyType::P384,
            SignatureAlgorithm::Ed25519 => KeyType::Ed25519,
        };
        let public =
            PublicKey::from_raw(key_type, private.raw_public_key()).map_err(SignerError::Key)?;
        let kid = public.kid();
        if self.keys.contains_key(&kid) {
            return Err(SignerError::DuplicateKey(kid));
        }
        self.keys.insert(
            kid,
            SoftwareKey {
                private,
                public,
                purpose,
            },
        );
        Ok(kid)
    }
}

impl Default for SoftwareSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SoftwareSigner {
    // Lists key IDs and purposes only, never key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.keys.iter().map(|(kid, key)| (kid, key.purpose)))
            .finish()
    }
}

impl Signer for SoftwareSigner {
    fn public_key(&self, kid: &Kid) -> Option<PublicKey> {
        self.keys.get(kid).map(|k| k.public.clone())
    }

    fn purpose(&self, kid: &Kid) -> Option<KeyPurpose> {
        self.keys.get(kid).map(|k| k.purpose)
    }

    fn sign(&self, kid: &Kid, domain: Domain, payload: &[u8]) -> Result<Signature, SignerError> {
        let key = self.keys.get(kid).ok_or(SignerError::UnknownKey(*kid))?;
        if !domain.signed_by(key.purpose) {
            return Err(SignerError::WrongPurpose {
                purpose: key.purpose,
                domain,
            });
        }
        let bytes = key
            .private
            .sign(&self.rng, &domain.message(payload))
            .map_err(|e| SignerError::Failed(e.0))?;
        Signature::new(*kid, key.private.algorithm(), bytes)
    }
}

/// Software keys are signing keys of an allowed algorithm.
fn check_purpose(purpose: KeyPurpose, algorithm: SignatureAlgorithm) -> Result<(), SignerError> {
    let key_alg = algorithm.key_algorithm();
    if purpose.allows(key_alg) {
        Ok(())
    } else {
        Err(SignerError::Key(KeyError::AlgorithmNotAllowed {
            purpose,
            algorithm: key_alg,
        }))
    }
}

/// A signing operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerError {
    /// The signer does not hold this key.
    UnknownKey(Kid),
    /// The signer already holds this key.
    DuplicateKey(Kid),
    /// The key's purpose may not sign for this domain.
    WrongPurpose {
        /// The key's purpose.
        purpose: KeyPurpose,
        /// The requested domain.
        domain: Domain,
    },
    /// A key-inventory rule was broken.
    Key(KeyError),
    /// The private key is not an unencrypted PKCS#8 key of the stated
    /// algorithm, or its public and private halves disagree.
    BadKeyEncoding,
    /// The signature is not the algorithm's exact length.
    BadSignatureLength,
    /// The cryptographic back end failed.
    Failed(&'static str),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(kid) => write!(f, "no key {kid}"),
            Self::DuplicateKey(kid) => write!(f, "key {kid} is already held"),
            Self::WrongPurpose { purpose, domain } => {
                write!(f, "a {purpose} key may not sign {}", domain.label())
            }
            Self::Key(e) => e.fmt(f),
            Self::BadKeyEncoding => f.write_str(
                "not an unencrypted PKCS#8 key of the stated algorithm, or its halves disagree",
            ),
            Self::BadSignatureLength => f.write_str("the signature has the wrong length"),
            Self::Failed(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for SignerError {}
