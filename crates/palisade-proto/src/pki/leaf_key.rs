//! Software keys for end-entity certificates (#223): above all the device
//! key, which an endpoint generates at enrolment, proves it holds, and
//! authenticates every mTLS connection with afterwards. The development
//! server's TLS key is one too.
//!
//! [`LeafKey`] is the software back end: an ECDSA P-384 key held in
//! process memory. It signs two things, and nothing else:
//!
//! - the enrolment proof of possession, over the [`Domain::Enrol`] prefix
//!   followed by the request payload ([`LeafKey::sign_enrolment`]), so the
//!   signature can never pass for a trust set, policy bundle or unlock token;
//! - TLS handshakes, as `ecdsa_secp384r1_sha384` with a DER signature
//!   ([`LeafKey::sign_tls`]). A TLS 1.3 `CertificateVerify` message starts
//!   with 64 spaces (RFC 8446, 4.4.3) and a TLS 1.2 one with the handshake
//!   hash, so neither can collide with a domain prefix, which starts with `p`.
//!
//! Protecting the key at rest is the caller's job: [`LeafKey::generate`]
//! returns the PKCS#8 document once, as a [`Pkcs8`] that never prints and is
//! wiped on drop, for the agent to seal (machine-scope DPAPI today). A
//! non-exportable TPM or software key storage provider key (#220) replaces
//! this back end behind the same two operations.

use std::fmt;

use zeroize::Zeroizing;

use super::Domain;
use super::crypto::{self, PrivateKey, Rng};
use super::key::{KeyError, KeyType, PublicKey, SignatureAlgorithm};
use super::signer::SignerError;

/// A leaf key's algorithm: ECDSA P-384 with SHA-384, the default of #223.
pub const ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::EcdsaP384Sha384;

/// An unencrypted PKCS#8 private key document. `Debug` never prints it, and
/// the bytes are wiped when it is dropped.
pub struct Pkcs8(Zeroizing<Vec<u8>>);

impl Pkcs8 {
    /// Wraps a document read back from protected storage.
    #[must_use]
    pub fn new(der: Vec<u8>) -> Self {
        Self(Zeroizing::new(der))
    }

    /// The DER bytes, to seal. Do not log or send them anywhere.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Pkcs8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pkcs8([REDACTED])")
    }
}

/// Generates a new private key of `algorithm` and returns only its PKCS#8
/// document, for a key kept outside the process and imported with
/// [`SoftwareSigner::import_pkcs8`](super::SoftwareSigner::import_pkcs8)
/// (the development server's CA keys).
///
/// # Errors
///
/// [`SignerError::Failed`] if the secure random source fails.
pub fn generate_pkcs8(algorithm: SignatureAlgorithm) -> Result<Pkcs8, SignerError> {
    crypto::generate_pkcs8(algorithm, &Rng::new())
        .map(Pkcs8::new)
        .map_err(|e| SignerError::Failed(e.0))
}

/// An end-entity private key, in process memory.
pub struct LeafKey {
    rng: Rng,
    private: PrivateKey,
    public: PublicKey,
}

impl LeafKey {
    /// Generates a new P-384 leaf key. Returns the key and its PKCS#8
    /// document, the only copy that leaves this type.
    ///
    /// # Errors
    ///
    /// [`SignerError::Failed`] if the secure random source fails.
    pub fn generate() -> Result<(Self, Pkcs8), SignerError> {
        let rng = Rng::new();
        let der = crypto::generate_pkcs8(ALGORITHM, &rng).map_err(|e| SignerError::Failed(e.0))?;
        let key = Self::from_pkcs8_with(rng, &der)?;
        Ok((key, Pkcs8::new(der)))
    }

    /// Reads a leaf key back from its PKCS#8 document.
    ///
    /// # Errors
    ///
    /// [`SignerError::BadKeyEncoding`] unless it is a P-384 PKCS#8 v1 key
    /// that carries its public key.
    pub fn from_pkcs8(pkcs8: &Pkcs8) -> Result<Self, SignerError> {
        Self::from_pkcs8_with(Rng::new(), pkcs8.expose())
    }

    fn from_pkcs8_with(rng: Rng, der: &[u8]) -> Result<Self, SignerError> {
        let private = PrivateKey::from_pkcs8(ALGORITHM, der, &rng)
            .map_err(|_| SignerError::BadKeyEncoding)?;
        let public = PublicKey::from_raw(KeyType::P384, private.raw_public_key())
            .map_err(SignerError::Key)?;
        Ok(Self {
            rng,
            private,
            public,
        })
    }

    /// The public key, which the leaf certificate certifies.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Signs an enrolment request payload: the fixed-length `r ‖ s`
    /// signature over the [`Domain::Enrol`] prefix and `payload`. Check it
    /// with [`verify_enrolment`].
    ///
    /// # Errors
    ///
    /// [`SignerError::Failed`] if the back end fails.
    pub fn sign_enrolment(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.private
            .sign(&self.rng, &Domain::Enrol.message(payload))
            .map_err(|e| SignerError::Failed(e.0))
    }

    /// Signs a TLS handshake message: a DER `ECDSA-Sig-Value` over the
    /// SHA-384 of `message`, the `ecdsa_secp384r1_sha384` scheme.
    ///
    /// # Errors
    ///
    /// [`SignerError::NotX509`] if `message` starts like a domain-prefixed
    /// message (it never does for TLS), and [`SignerError::Failed`] if the
    /// back end fails.
    pub fn sign_tls(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        // Every domain prefix starts with `palisade-`; refuse anything that
        // does, so this path can never produce a domain signature, even
        // though TLS uses DER signatures and domains use `r ‖ s`.
        if message.starts_with(b"palisade-") {
            return Err(SignerError::NotX509);
        }
        self.private
            .sign_x509(&self.rng, message)
            .map_err(|e| SignerError::Failed(e.0))
    }
}

impl fmt::Debug for LeafKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LeafKey(kid {})", self.public.kid())
    }
}

/// Checks an enrolment proof of possession: `signature` is `public_key`'s
/// `r ‖ s` signature over the [`Domain::Enrol`] prefix and `payload`.
///
/// # Errors
///
/// [`KeyError::KeyTypeMismatch`] unless the key is P-384, and
/// [`KeyError::UnsupportedPublicKey`] if the signature does not verify.
pub fn verify_enrolment(
    public_key: &PublicKey,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), KeyError> {
    if public_key.key_type() != KeyType::P384 {
        return Err(KeyError::KeyTypeMismatch);
    }
    if public_key.verify(ALGORITHM, Domain::Enrol, payload, signature) {
        Ok(())
    } else {
        Err(KeyError::UnsupportedPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{KeyPurpose, Signer, SoftwareSigner};

    #[test]
    fn a_generated_key_round_trips_through_pkcs8() {
        let (key, pkcs8) = LeafKey::generate().unwrap();
        let again = LeafKey::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(key.public_key(), again.public_key());
        assert_eq!(format!("{pkcs8:?}"), "Pkcs8([REDACTED])");
        assert!(format!("{key:?}").starts_with("LeafKey(kid "));
        assert_eq!(key.public_key().key_type(), KeyType::P384);
    }

    #[test]
    fn exported_keys_import_into_a_signer() {
        use crate::pki::KeyPurpose;
        let pkcs8 = generate_pkcs8(ALGORITHM).unwrap();
        let mut signer = SoftwareSigner::new();
        let kid = signer
            .import_pkcs8(KeyPurpose::IssuingCa, ALGORITHM, pkcs8.expose())
            .unwrap();
        assert_eq!(signer.purpose(&kid), Some(KeyPurpose::IssuingCa));
    }

    #[test]
    fn garbage_and_ed25519_keys_are_refused() {
        assert_eq!(
            LeafKey::from_pkcs8(&Pkcs8::new(vec![0x30, 0x00])).unwrap_err(),
            SignerError::BadKeyEncoding
        );
        let ed = crypto::test_pkcs8(SignatureAlgorithm::Ed25519);
        assert_eq!(
            LeafKey::from_pkcs8(&Pkcs8::new(ed)).unwrap_err(),
            SignerError::BadKeyEncoding
        );
    }

    #[test]
    fn the_enrolment_proof_verifies_only_for_its_key_and_payload() {
        let (key, _) = LeafKey::generate().unwrap();
        let (other, _) = LeafKey::generate().unwrap();
        let sig = key.sign_enrolment(b"payload").unwrap();
        assert_eq!(sig.len(), ALGORITHM.signature_len());
        verify_enrolment(key.public_key(), b"payload", &sig).unwrap();
        assert!(verify_enrolment(key.public_key(), b"payloaD", &sig).is_err());
        assert!(verify_enrolment(other.public_key(), b"payload", &sig).is_err());
        assert!(verify_enrolment(key.public_key(), b"payload", sig.get(1..).unwrap()).is_err());
        // The same bytes signed for another domain do not pass.
        assert!(
            !key.public_key()
                .verify(ALGORITHM, Domain::Policy, b"payload", &sig)
        );
    }

    #[test]
    fn an_ed25519_key_never_verifies_an_enrolment_proof() {
        let mut signer = SoftwareSigner::new();
        let kid = signer
            .generate(KeyPurpose::PolicySigning, SignatureAlgorithm::Ed25519)
            .unwrap();
        let ed = signer.public_key(&kid).unwrap();
        assert_eq!(
            verify_enrolment(&ed, b"x", &[0; 96]),
            Err(KeyError::KeyTypeMismatch)
        );
    }

    #[test]
    fn tls_signatures_are_der_and_never_domain_messages() {
        let (key, _) = LeafKey::generate().unwrap();
        let sig = key.sign_tls(b"\x20\x20handshake").unwrap();
        assert_eq!(sig.first(), Some(&0x30));
        assert!(crypto::verify_p384_der(
            key.public_key().raw(),
            b"\x20\x20handshake",
            &sig
        ));
        for domain in Domain::ALL {
            assert_eq!(
                key.sign_tls(&domain.message(b"x")),
                Err(SignerError::NotX509)
            );
        }
    }
}
