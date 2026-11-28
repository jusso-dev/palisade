//! X.509 issuance for the internal CA hierarchy (#224). Only with the
//! `issuance` feature, which the server and the offline ceremony tool
//! enable and the agent does not.
//!
//! The hierarchy:
//!
//! ```text
//! root-ca (offline, self-signed, pathLen 1)
//!   └── issuing-ca (online, pathLen 0)
//!         ├── device certificate   clientAuth            CN = device ID, URNs for device and tenant
//!         ├── relay certificate    serverAuth, clientAuth DNS names, URNs for relay and tenant
//!         └── server certificate   serverAuth            DNS names
//! ```
//!
//! A new root is introduced by cross-signing: the old root signs a
//! certificate for the new root's name and key ([`CaCertificate::cross_signed`]),
//! so a chain that ends in the new root also builds to the old one while
//! agents still pin it. Revocation lists ([`revocation_list`]) are signed by
//! the CA whose certificates they list: the root lists revoked issuing CAs,
//! and an issuing CA lists revoked leaves.
//!
//! Every certificate key is ECDSA P-384 and every signature is ECDSA P-384
//! with SHA-384 (ADR 0017). `rcgen` only encodes: it is built without a
//! cryptography back end, and every signature comes from a [`Signer`]
//! through [`Signer::sign_x509`], which only `root-ca` and `issuing-ca` keys
//! may use.
//!
//! Each certificate gets a random 16-byte serial from the operating
//! system's secure random source. Times are whole seconds: X.509 has no
//! smaller unit, so each bound is rounded down, and the [`Validity`]
//! returned is the one written. A child never outlives its issuer, and a
//! device certificate lives at most [`MAX_DEVICE_LIFETIME_DAYS`] days (#223).
//!
//! Key identifiers (`subjectKeyIdentifier` and `authorityKeyIdentifier`) are
//! the first 20 bytes of the SHA-256 of the DER `SubjectPublicKeyInfo`, the
//! same digest the [`Kid`] takes its first 16 bytes from.
//!
//! Not here yet: loading a stored CA certificate back (the ceremony CLI,
//! #15), recording issuance in the audit log (T-ca-04, #132), and the mTLS
//! handshake that checks device certificates (#223).

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests;

use std::cell::Cell;
use std::fmt;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyUsagePurpose, PublicKeyData, SanType,
    SerialNumber, SigningKey,
};
use time::OffsetDateTime;

use crate::events::{DnsName, HostId, TenantId, Timestamp};

use super::crypto::{self, Rng};
use super::key::{KeyPurpose, KeyType, Kid, PublicKey};
use super::signer::{Signer, SignerError};
use super::time::Validity;

/// The longest lifetime of a device certificate, in days (#223: 1 to 90).
pub const MAX_DEVICE_LIFETIME_DAYS: i64 = 90;

/// The most DNS names one server or relay certificate may carry.
pub const MAX_DNS_NAMES: usize = 16;

/// The longest CA common name, in characters (RFC 5280 `ub-common-name`).
pub const MAX_NAME_LEN: usize = 64;

const MICROS_PER_SECOND: i64 = 1_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// A CA certificate: a root, a cross-signed root or an issuing CA.
#[derive(Clone, PartialEq, Eq)]
pub struct CaCertificate {
    der: Vec<u8>,
    name: String,
    public_key: PublicKey,
    purpose: KeyPurpose,
    validity: Validity,
    serial: Vec<u8>,
}

/// An end-entity certificate: a device, relay or server certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct LeafCertificate {
    der: Vec<u8>,
    profile: LeafProfile,
    validity: Validity,
    serial: Vec<u8>,
}

/// What an end-entity certificate is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LeafProfile {
    /// An enrolled device: `clientAuth` only.
    Device,
    /// A relay: `serverAuth` towards endpoints, `clientAuth` upstream.
    Relay,
    /// The management server: `serverAuth` only.
    Server,
}

/// One revoked certificate in a revocation list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoked {
    /// The certificate's serial: the DER INTEGER content octets, 1 to 20
    /// bytes, as [`CaCertificate::serial`] and [`LeafCertificate::serial`]
    /// return it.
    pub serial: Vec<u8>,
    /// When the CA processed the revocation.
    pub revoked_at: Timestamp,
    /// Why, if known.
    pub reason: Option<RevocationReason>,
}

/// Why a certificate was revoked (RFC 5280, 5.3.1): the reasons Palisade
/// uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    /// The certificate's private key is known or suspected to be
    /// compromised.
    KeyCompromise,
    /// The issuing CA's key is known or suspected to be compromised.
    CaCompromise,
    /// A newer certificate replaces it.
    Superseded,
    /// The device or service is retired.
    CessationOfOperation,
}

impl CaCertificate {
    /// A self-signed root certificate for the `root-ca` key `kid`, with
    /// `pathLenConstraint` 1 (one issuing CA below it).
    ///
    /// # Errors
    ///
    /// [`IssueError::WrongPurpose`] unless `signer` holds `kid` as a
    /// `root-ca` key, [`IssueError::BadName`], and the encoding and signing
    /// errors of every issuance.
    pub fn self_signed_root<S: Signer + ?Sized>(
        signer: &S,
        kid: &Kid,
        name: &str,
        validity: Validity,
    ) -> Result<Self, IssueError> {
        let public_key = held_key(signer, kid, KeyPurpose::RootCa)?;
        let mut params = ca_params(name, &public_key, 1)?;
        let validity = set_validity(&mut params, validity)?;
        let serial = set_serial(&mut params)?;
        let key = CaKey::new(signer, *kid, &public_key);
        let der = params
            .self_signed(&key)
            .map_err(|e| key.error(&e))?
            .der()
            .to_vec();
        Ok(Self {
            der,
            name: name.to_owned(),
            public_key,
            purpose: KeyPurpose::RootCa,
            validity,
            serial,
        })
    }

    /// An issuing CA certificate for `subject_key`, signed by `root`, with
    /// `pathLenConstraint` 0 (it issues only end-entity certificates).
    ///
    /// # Errors
    ///
    /// [`IssueError::WrongIssuer`] unless `root` is a root certificate,
    /// [`IssueError::WrongPurpose`] unless `signer` holds `root`'s key as a
    /// `root-ca` key, [`IssueError::SameKey`] if `subject_key` is the root's
    /// key, and the errors of every issuance.
    pub fn issuing_ca<S: Signer + ?Sized>(
        signer: &S,
        root: &Self,
        subject_key: &PublicKey,
        name: &str,
        validity: Validity,
    ) -> Result<Self, IssueError> {
        root.expect(KeyPurpose::RootCa)?;
        if *subject_key == root.public_key {
            return Err(IssueError::SameKey);
        }
        let params = ca_params(name, subject_key, 0)?;
        let (der, validity, serial) = root.sign(signer, params, subject_key, validity)?;
        Ok(Self {
            der,
            name: name.to_owned(),
            public_key: subject_key.clone(),
            purpose: KeyPurpose::IssuingCa,
            validity,
            serial,
        })
    }

    /// A cross-certificate: `old_root` certifies `new_root`'s name and key,
    /// with `pathLenConstraint` 1 as on the new root itself. With it, a
    /// chain that ends in the new root also builds to the old root, so
    /// agents that still pin the old root accept certificates from the new
    /// hierarchy during the transition (#224).
    ///
    /// The result is a CA certificate for the new root's key, so it can
    /// also issue: what it signs carries the new root's name and key
    /// identifier, the same as the new root's self-signed certificate.
    ///
    /// # Errors
    ///
    /// [`IssueError::WrongIssuer`] unless both are root certificates,
    /// [`IssueError::SameKey`] if they share a key, and the errors of every
    /// issuance.
    pub fn cross_signed<S: Signer + ?Sized>(
        signer: &S,
        old_root: &Self,
        new_root: &Self,
        validity: Validity,
    ) -> Result<Self, IssueError> {
        old_root.expect(KeyPurpose::RootCa)?;
        new_root.expect(KeyPurpose::RootCa)?;
        if new_root.public_key == old_root.public_key {
            return Err(IssueError::SameKey);
        }
        let params = ca_params(&new_root.name, &new_root.public_key, 1)?;
        let (der, validity, serial) =
            old_root.sign(signer, params, &new_root.public_key, validity)?;
        Ok(Self {
            der,
            name: new_root.name.clone(),
            public_key: new_root.public_key.clone(),
            purpose: KeyPurpose::RootCa,
            validity,
            serial,
        })
    }

    /// The certificate, DER.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The common name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The certified public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The certified key's ID.
    #[must_use]
    pub fn kid(&self) -> Kid {
        self.public_key.kid()
    }

    /// `root-ca` or `issuing-ca`.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The validity written in the certificate.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// The serial: the DER INTEGER content octets.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    fn expect(&self, purpose: KeyPurpose) -> Result<(), IssueError> {
        if self.purpose == purpose {
            Ok(())
        } else {
            Err(IssueError::WrongIssuer {
                expected: purpose,
                actual: self.purpose,
            })
        }
    }

    /// The `rcgen` issuer for this CA: its name, key identifier and key
    /// usages, which must match what its own certificate carries.
    fn issuer_params(&self) -> Result<CertificateParams, IssueError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = name(&self.name)?;
        params.key_identifier_method = KeyIdMethod::PreSpecified(key_id(&self.public_key));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Ok(params)
    }

    /// Signs a certificate for `subject_key` with `params`, adding the
    /// validity, a fresh serial and the authority key identifier. Returns
    /// the DER, the validity written and the serial.
    fn sign<S: Signer + ?Sized>(
        &self,
        signer: &S,
        mut params: CertificateParams,
        subject_key: &PublicKey,
        validity: Validity,
    ) -> Result<(Vec<u8>, Validity, Vec<u8>), IssueError> {
        held_key_matching(signer, self)?;
        let validity = set_validity(&mut params, validity)?;
        if validity.not_before() < self.validity.not_before()
            || validity.not_after() > self.validity.not_after()
        {
            return Err(IssueError::OutlivesIssuer);
        }
        let serial = set_serial(&mut params)?;
        params.use_authority_key_identifier_extension = true;
        let key = CaKey::new(signer, self.kid(), &self.public_key);
        let issuer = rcgen::Issuer::new(self.issuer_params()?, &key);
        let der = params
            .signed_by(&SubjectKey(subject_key), &issuer)
            .map_err(|e| key.error(&e))?
            .der()
            .to_vec();
        Ok((der, validity, serial))
    }
}

impl fmt::Debug for CaCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CaCertificate({}, {:?}, kid {})",
            self.purpose,
            self.name,
            self.kid()
        )
    }
}

impl LeafCertificate {
    /// A device certificate for `subject_key`, signed by the issuing CA
    /// `issuing` (#223): common name the device ID, subject alternative
    /// names `urn:palisade:device:<device>` and `urn:palisade:tenant:<tenant>`,
    /// extended key usage `clientAuth` only, so it cannot pose as a relay or
    /// server (threat: T-ca-07).
    ///
    /// # Errors
    ///
    /// [`IssueError::LifetimeTooLong`] above [`MAX_DEVICE_LIFETIME_DAYS`],
    /// and the errors of every leaf.
    pub fn device<S: Signer + ?Sized>(
        signer: &S,
        issuing: &CaCertificate,
        subject_key: &PublicKey,
        device: HostId,
        tenant: TenantId,
        validity: Validity,
    ) -> Result<Self, IssueError> {
        let lifetime = validity
            .not_after()
            .unix_micros()
            .saturating_sub(validity.not_before().unix_micros());
        if lifetime > MAX_DEVICE_LIFETIME_DAYS * SECONDS_PER_DAY * MICROS_PER_SECOND {
            return Err(IssueError::LifetimeTooLong);
        }
        let mut params = leaf_params(subject_key)?;
        params
            .distinguished_name
            .push(DnType::CommonName, device.0.to_string());
        params.subject_alt_names = vec![
            urn("device", &device.0.to_string())?,
            urn("tenant", &tenant.0.to_string())?,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        Self::issue(
            signer,
            issuing,
            params,
            subject_key,
            LeafProfile::Device,
            validity,
        )
    }

    /// A relay certificate: the DNS names endpoints reach it by, plus
    /// `urn:palisade:relay:<relay>` and `urn:palisade:tenant:<tenant>`, with
    /// `serverAuth` (endpoints connect to it) and `clientAuth` (it connects
    /// upstream) (#223).
    ///
    /// # Errors
    ///
    /// [`IssueError::NoNames`] or [`IssueError::TooManyNames`], and the
    /// errors of every leaf.
    pub fn relay<S: Signer + ?Sized>(
        signer: &S,
        issuing: &CaCertificate,
        subject_key: &PublicKey,
        relay: HostId,
        tenant: TenantId,
        dns_names: &[DnsName],
        validity: Validity,
    ) -> Result<Self, IssueError> {
        let mut params = leaf_params(subject_key)?;
        params
            .distinguished_name
            .push(DnType::CommonName, relay.0.to_string());
        let mut sans = dns_sans(dns_names)?;
        sans.push(urn("relay", &relay.0.to_string())?);
        sans.push(urn("tenant", &tenant.0.to_string())?);
        params.subject_alt_names = sans;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        Self::issue(
            signer,
            issuing,
            params,
            subject_key,
            LeafProfile::Relay,
            validity,
        )
    }

    /// A server TLS certificate for the DNS names agents connect to, with
    /// `serverAuth` only. The common name is the first name.
    ///
    /// # Errors
    ///
    /// [`IssueError::NoNames`] or [`IssueError::TooManyNames`], and the
    /// errors of every leaf.
    pub fn server<S: Signer + ?Sized>(
        signer: &S,
        issuing: &CaCertificate,
        subject_key: &PublicKey,
        dns_names: &[DnsName],
        validity: Validity,
    ) -> Result<Self, IssueError> {
        let mut params = leaf_params(subject_key)?;
        let sans = dns_sans(dns_names)?;
        if let Some(first) = dns_names.first() {
            params
                .distinguished_name
                .push(DnType::CommonName, first.as_str());
        }
        params.subject_alt_names = sans;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        Self::issue(
            signer,
            issuing,
            params,
            subject_key,
            LeafProfile::Server,
            validity,
        )
    }

    fn issue<S: Signer + ?Sized>(
        signer: &S,
        issuing: &CaCertificate,
        params: CertificateParams,
        subject_key: &PublicKey,
        profile: LeafProfile,
        validity: Validity,
    ) -> Result<Self, IssueError> {
        issuing.expect(KeyPurpose::IssuingCa)?;
        if *subject_key == issuing.public_key {
            return Err(IssueError::SameKey);
        }
        let (der, validity, serial) = issuing.sign(signer, params, subject_key, validity)?;
        Ok(Self {
            der,
            profile,
            validity,
            serial,
        })
    }

    /// The certificate, DER.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// What the certificate is for.
    #[must_use]
    pub const fn profile(&self) -> LeafProfile {
        self.profile
    }

    /// The validity written in the certificate.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// The serial: the DER INTEGER content octets. Record it with the key
    /// in a [`CertificateBinding`](super::CertificateBinding).
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }
}

impl fmt::Debug for LeafCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LeafCertificate({:?}, {} bytes)",
            self.profile,
            self.der.len()
        )
    }
}

/// A revocation list (CRL, RFC 5280 section 5) signed by `issuer`, listing
/// `revoked`, valid from `this_update` until `next_update`. `crl_number`
/// must grow with each list the issuer publishes.
///
/// The root's list names revoked issuing CAs, and an issuing CA's list
/// names revoked leaves. The server checks device certificates against its
/// database as well, so a revocation takes effect at once (#223); lists are
/// for relays and other verifiers.
///
/// # Errors
///
/// [`IssueError::BadCrlWindow`] unless `next_update` is after
/// `this_update` and both are inside the issuer's validity,
/// [`IssueError::BadSerial`] for a serial that is empty or longer than 20
/// bytes, [`IssueError::WrongPurpose`] if `signer` does not hold the
/// issuer's key, and the encoding and signing errors.
pub fn revocation_list<S: Signer + ?Sized>(
    signer: &S,
    issuer: &CaCertificate,
    crl_number: u64,
    this_update: Timestamp,
    next_update: Timestamp,
    revoked: &[Revoked],
) -> Result<Vec<u8>, IssueError> {
    held_key_matching(signer, issuer)?;
    let (this_dt, this_ts) = x509_time(this_update)?;
    let (next_dt, next_ts) = x509_time(next_update)?;
    if next_ts <= this_ts
        || this_ts < issuer.validity.not_before()
        || next_ts > issuer.validity.not_after()
    {
        return Err(IssueError::BadCrlWindow);
    }
    let mut revoked_certs = Vec::with_capacity(revoked.len());
    for r in revoked {
        if r.serial.is_empty() || r.serial.len() > 20 {
            return Err(IssueError::BadSerial);
        }
        revoked_certs.push(rcgen::RevokedCertParams {
            serial_number: SerialNumber::from_slice(&r.serial),
            revocation_time: x509_time(r.revoked_at)?.0,
            reason_code: r.reason.map(|reason| match reason {
                RevocationReason::KeyCompromise => rcgen::RevocationReason::KeyCompromise,
                RevocationReason::CaCompromise => rcgen::RevocationReason::CaCompromise,
                RevocationReason::Superseded => rcgen::RevocationReason::Superseded,
                RevocationReason::CessationOfOperation => {
                    rcgen::RevocationReason::CessationOfOperation
                }
            }),
            invalidity_date: None,
        });
    }
    let params = CertificateRevocationListParams {
        this_update: this_dt,
        next_update: next_dt,
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::PreSpecified(key_id(&issuer.public_key)),
    };
    let key = CaKey::new(signer, issuer.kid(), &issuer.public_key);
    let rc_issuer = rcgen::Issuer::new(issuer.issuer_params()?, &key);
    Ok(params
        .signed_by(&rc_issuer)
        .map_err(|e| key.error(&e))?
        .der()
        .to_vec())
}

/// Issuance failed. Nothing was signed unless the error says the signer
/// failed part-way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// The signer does not hold the CA's key with the expected purpose.
    WrongPurpose {
        /// The purpose the operation needs.
        expected: KeyPurpose,
        /// The purpose the signer holds the key for, if it holds it.
        actual: Option<KeyPurpose>,
    },
    /// The issuing certificate is the wrong kind of CA for this operation.
    WrongIssuer {
        /// The kind needed.
        expected: KeyPurpose,
        /// The kind given.
        actual: KeyPurpose,
    },
    /// The subject key is the issuer's own key.
    SameKey,
    /// The subject key is not a P-384 key.
    UnsupportedSubjectKey,
    /// A CA name is empty, longer than [`MAX_NAME_LEN`], blank or has a
    /// control character.
    BadName,
    /// A server or relay certificate needs at least one DNS name.
    NoNames,
    /// More than [`MAX_DNS_NAMES`] DNS names.
    TooManyNames,
    /// The validity is not inside the issuer's validity.
    OutlivesIssuer,
    /// A device certificate longer than [`MAX_DEVICE_LIFETIME_DAYS`].
    LifetimeTooLong,
    /// A revocation list's window is empty or outside the issuer's
    /// validity.
    BadCrlWindow,
    /// A serial is empty or longer than 20 bytes.
    BadSerial,
    /// A time cannot be written in a certificate.
    TimeOutOfRange,
    /// The signer refused or failed.
    Signer(SignerError),
    /// The certificate could not be encoded.
    Encoding,
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPurpose { expected, actual } => match actual {
                Some(actual) => write!(f, "the signer holds this key as {actual}, not {expected}"),
                None => write!(f, "the signer does not hold the {expected} key"),
            },
            Self::WrongIssuer { expected, actual } => {
                write!(f, "this needs a {expected} certificate, not {actual}")
            }
            Self::SameKey => f.write_str("the subject key is the issuer's own key"),
            Self::UnsupportedSubjectKey => f.write_str("certificate keys must be P-384"),
            Self::BadName => write!(
                f,
                "a CA name is 1 to {MAX_NAME_LEN} characters, not blank, without control characters"
            ),
            Self::NoNames => f.write_str("at least one DNS name is needed"),
            Self::TooManyNames => write!(f, "at most {MAX_DNS_NAMES} DNS names"),
            Self::OutlivesIssuer => f.write_str("the validity is not inside the issuer's"),
            Self::LifetimeTooLong => write!(
                f,
                "a device certificate lives at most {MAX_DEVICE_LIFETIME_DAYS} days"
            ),
            Self::BadCrlWindow => {
                f.write_str("the revocation list window is empty or outside the issuer's validity")
            }
            Self::BadSerial => f.write_str("a serial is 1 to 20 bytes"),
            Self::TimeOutOfRange => f.write_str("the time cannot be written in a certificate"),
            Self::Signer(e) => write!(f, "signing failed: {e}"),
            Self::Encoding => f.write_str("the certificate could not be encoded"),
        }
    }
}

impl std::error::Error for IssueError {}

// ---------------------------------------------------------------------------
// rcgen adapters
// ---------------------------------------------------------------------------

/// A subject's public key, as `rcgen` reads it.
struct SubjectKey<'a>(&'a PublicKey);

impl PublicKeyData for SubjectKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0.raw()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P384_SHA384
    }
}

/// A CA key held by a [`Signer`]. `rcgen` errors carry no detail, so the
/// signer's own error is kept here and reported instead.
struct CaKey<'a, S: ?Sized> {
    signer: &'a S,
    kid: Kid,
    public_key: &'a PublicKey,
    failure: Cell<Option<SignerError>>,
}

impl<'a, S: Signer + ?Sized> CaKey<'a, S> {
    const fn new(signer: &'a S, kid: Kid, public_key: &'a PublicKey) -> Self {
        Self {
            signer,
            kid,
            public_key,
            failure: Cell::new(None),
        }
    }

    /// The error to report for a failed `rcgen` call.
    fn error(&self, _e: &rcgen::Error) -> IssueError {
        self.failure
            .take()
            .map_or(IssueError::Encoding, IssueError::Signer)
    }
}

impl<S: Signer + ?Sized> PublicKeyData for CaKey<'_, S> {
    fn der_bytes(&self) -> &[u8] {
        self.public_key.raw()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P384_SHA384
    }
}

impl<S: Signer + ?Sized> SigningKey for CaKey<'_, S> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.signer.sign_x509(&self.kid, msg).map_err(|e| {
            self.failure.set(Some(e));
            rcgen::Error::RemoteKeyError
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The signer's public key for `kid`, which it must hold as `purpose`.
fn held_key<S: Signer + ?Sized>(
    signer: &S,
    kid: &Kid,
    purpose: KeyPurpose,
) -> Result<PublicKey, IssueError> {
    let actual = signer.purpose(kid);
    let key = signer.public_key(kid);
    match (actual, key) {
        (Some(p), Some(key)) if p == purpose => {
            p384(&key)?;
            Ok(key)
        }
        (actual, _) => Err(IssueError::WrongPurpose {
            expected: purpose,
            actual,
        }),
    }
}

/// The signer must hold `ca`'s certified key with `ca`'s purpose. The key
/// ID is a SHA-256 prefix of the key, so holding the ID is holding the key.
fn held_key_matching<S: Signer + ?Sized>(signer: &S, ca: &CaCertificate) -> Result<(), IssueError> {
    held_key(signer, &ca.kid(), ca.purpose).map(|_| ())
}

fn p384(key: &PublicKey) -> Result<(), IssueError> {
    if key.key_type() == KeyType::P384 {
        Ok(())
    } else {
        Err(IssueError::UnsupportedSubjectKey)
    }
}

/// The key identifier: the first 20 bytes of the SHA-256 of the DER
/// `SubjectPublicKeyInfo`.
fn key_id(key: &PublicKey) -> Vec<u8> {
    crypto::sha256(key.spki_der())
        .get(..20)
        .unwrap_or_default()
        .to_vec()
}

fn name(common_name: &str) -> Result<DistinguishedName, IssueError> {
    let chars = common_name.chars().count();
    if chars == 0
        || chars > MAX_NAME_LEN
        || common_name.trim().is_empty()
        || common_name.chars().any(char::is_control)
    {
        return Err(IssueError::BadName);
    }
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    Ok(dn)
}

/// Parameters for a CA certificate. The `subjectKeyIdentifier` is written
/// for CA certificates only, from `key_identifier_method`.
fn ca_params(
    common_name: &str,
    subject_key: &PublicKey,
    path_len: u8,
) -> Result<CertificateParams, IssueError> {
    p384(subject_key)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = name(common_name)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::PreSpecified(key_id(subject_key));
    Ok(params)
}

/// Parameters for an end-entity certificate: `CA:FALSE` (which also writes
/// the `subjectKeyIdentifier`) and `digitalSignature`, which TLS with an
/// ECDSA key needs.
fn leaf_params(subject_key: &PublicKey) -> Result<CertificateParams, IssueError> {
    p384(subject_key)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.key_identifier_method = KeyIdMethod::PreSpecified(key_id(subject_key));
    Ok(params)
}

fn dns_sans(names: &[DnsName]) -> Result<Vec<SanType>, IssueError> {
    if names.is_empty() {
        return Err(IssueError::NoNames);
    }
    if names.len() > MAX_DNS_NAMES {
        return Err(IssueError::TooManyNames);
    }
    names
        .iter()
        .map(|n| {
            n.as_str()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|_| IssueError::Encoding)
        })
        .collect()
}

fn urn(kind: &str, id: &str) -> Result<SanType, IssueError> {
    format!("urn:palisade:{kind}:{id}")
        .try_into()
        .map(SanType::URI)
        .map_err(|_| IssueError::Encoding)
}

/// `t` rounded down to a whole second, as `time` and as a [`Timestamp`].
fn x509_time(t: Timestamp) -> Result<(OffsetDateTime, Timestamp), IssueError> {
    let seconds = t.unix_micros().div_euclid(MICROS_PER_SECOND);
    let dt =
        OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| IssueError::TimeOutOfRange)?;
    let rounded = seconds
        .checked_mul(MICROS_PER_SECOND)
        .and_then(Timestamp::from_unix_micros)
        .ok_or(IssueError::TimeOutOfRange)?;
    Ok((dt, rounded))
}

fn set_validity(
    params: &mut CertificateParams,
    validity: Validity,
) -> Result<Validity, IssueError> {
    let (not_before, nb) = x509_time(validity.not_before())?;
    let (not_after, na) = x509_time(validity.not_after())?;
    params.not_before = not_before;
    params.not_after = not_after;
    Validity::new(nb, na).map_err(|_| IssueError::TimeOutOfRange)
}

/// A fresh random 16-byte serial. The top bit is cleared so the INTEGER is
/// positive, and the next one set so it is always exactly 16 bytes.
fn set_serial(params: &mut CertificateParams) -> Result<Vec<u8>, IssueError> {
    let mut serial = [0u8; 16];
    Rng::new()
        .fill(&mut serial)
        .map_err(|e| IssueError::Signer(SignerError::Failed(e.0)))?;
    if let Some(first) = serial.first_mut() {
        *first = (*first & 0x7f) | 0x40;
    }
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    Ok(serial.to_vec())
}
