//! The certificate authority the server issues device certificates from
//! (#223, #224): the issuing CA, the root it chains to, and the signed trust
//! set agents receive.
//!
//! [`Authority::generate`] builds a throwaway hierarchy in memory: a root,
//! an issuing CA, a trust set signed by the root that pins the root as the
//! server CA, and a server TLS certificate for the given names from the
//! same issuing CA. It is for development (`palisade-server dev-pki`) and
//! tests only. A production server loads its issuing CA from the offline
//! ceremony (#15, #224) and never holds the root key; that loader is still
//! owed.

use std::fmt;
use std::sync::Arc;

use palisade_proto::events::{DnsName, HostId, TenantId, Timestamp};
use palisade_proto::pki::issue::{CaCertificate, IssueError, LeafCertificate};
use palisade_proto::pki::leaf_key::{self, LeafKey, Pkcs8};
use palisade_proto::pki::{
    KeyPurpose, KeyStatus, Kid, PublicKey, SignatureAlgorithm, SignedTrustSet, Signer,
    SoftwareSigner, TrustSet, TrustedKey, Validity,
};

const MICROS_PER_DAY: i64 = 86_400 * 1_000_000;

/// The issuing CA and what goes with it.
pub struct Authority {
    signer: SoftwareSigner,
    policy_kid: Kid,
    root: CaCertificate,
    issuing: CaCertificate,
    trust_set: Arc<[u8]>,
    trust_version: u64,
}

/// A development hierarchy: the authority plus the server's TLS identity.
pub struct DevPki {
    /// The authority.
    pub authority: Authority,
    /// The server certificate chain, DER, leaf first.
    pub server_chain: Vec<Vec<u8>>,
    /// The server TLS key's PKCS#8 document.
    pub server_key: Pkcs8,
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("root", &self.root.kid())
            .field("issuing", &self.issuing.kid())
            .field("trust_version", &self.trust_version)
            .finish()
    }
}

/// Building the authority failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityError(pub String);

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuthorityError {}

fn err(what: &str) -> impl Fn(&dyn fmt::Display) -> AuthorityError + '_ {
    move |e| AuthorityError(format!("{what}: {e}"))
}

fn days(now: Timestamp, from: i64, to: i64) -> Result<Validity, AuthorityError> {
    let at = |d: i64| {
        Timestamp::from_unix_micros(now.unix_micros().saturating_add(d * MICROS_PER_DAY))
            .ok_or_else(|| AuthorityError("a validity bound is out of range".to_owned()))
    };
    Validity::new(at(from)?, at(to)?).map_err(|e| err("validity")(&e))
}

impl Authority {
    /// A fresh development hierarchy at `now`, with a server certificate for
    /// `server_names`.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] if key generation or issuance fails.
    pub fn generate(now: Timestamp, server_names: &[DnsName]) -> Result<DevPki, AuthorityError> {
        let p384 = SignatureAlgorithm::EcdsaP384Sha384;
        let mut signer = SoftwareSigner::new();
        let root_kid = signer
            .generate(KeyPurpose::RootCa, p384)
            .map_err(|e| err("root key")(&e))?;
        let issuing_kid = signer
            .generate(KeyPurpose::IssuingCa, p384)
            .map_err(|e| err("issuing key")(&e))?;
        let policy_kid = signer
            .generate(KeyPurpose::PolicySigning, p384)
            .map_err(|e| err("policy key")(&e))?;
        let root = CaCertificate::self_signed_root(
            &signer,
            &root_kid,
            "Palisade Development Root",
            days(now, -1, 3650)?,
        )
        .map_err(|e| err("root certificate")(&e))?;
        let issuing_key = signer
            .public_key(&issuing_kid)
            .ok_or_else(|| AuthorityError("the issuing key vanished".to_owned()))?;
        let issuing = CaCertificate::issuing_ca(
            &signer,
            &root,
            &issuing_key,
            "Palisade Development Issuing CA",
            days(now, -1, 1825)?,
        )
        .map_err(|e| err("issuing certificate")(&e))?;

        let mut set = TrustSet::new(1, now, &[p384]).map_err(|e| err("trust set")(&e))?;
        set.add_trust_key(
            TrustedKey::new(
                root.public_key().clone(),
                KeyPurpose::RootCa,
                p384,
                KeyStatus::Active,
                root.validity(),
            )
            .map_err(|e| err("trust set")(&e))?,
        )
        .map_err(|e| err("trust set")(&e))?;
        set.add_server_pin(root.public_key().spki_sha256())
            .map_err(|e| err("trust set")(&e))?;
        let policy_key = signer
            .public_key(&policy_kid)
            .ok_or_else(|| AuthorityError("the policy key vanished".to_owned()))?;
        set.add_policy_key(
            TrustedKey::new(
                policy_key,
                KeyPurpose::PolicySigning,
                p384,
                KeyStatus::Active,
                days(now, -1, 365)?,
            )
            .map_err(|e| err("trust set")(&e))?,
        )
        .map_err(|e| err("trust set")(&e))?;
        let trust_set = SignedTrustSet::sign(&set, &signer, &[root_kid])
            .map_err(|e| err("trust set")(&e))?
            .encode();

        let authority = Self {
            signer,
            policy_kid,
            root,
            issuing,
            trust_set: Arc::from(trust_set),
            trust_version: 1,
        };
        let (server_key, server_pkcs8) = LeafKey::generate().map_err(|e| err("server key")(&e))?;
        let server = LeafCertificate::server(
            &authority.signer,
            &authority.issuing,
            server_key.public_key(),
            server_names,
            days(now, -1, 365)?,
        )
        .map_err(|e| err("server certificate")(&e))?;
        // The root goes in the chain too: agents pin it by its key hash and
        // anchor the chain on the copy the server sends (#223).
        let server_chain = vec![
            server.der().to_vec(),
            authority.issuing.der().to_vec(),
            authority.root.der().to_vec(),
        ];
        Ok(DevPki {
            authority,
            server_chain,
            server_key: server_pkcs8,
        })
    }

    /// Issues a device certificate for `key`, valid from `now` for
    /// `lifetime_days` (1 to 90).
    ///
    /// # Errors
    ///
    /// [`IssueError`] from issuance.
    pub fn issue_device(
        &self,
        key: &PublicKey,
        device: HostId,
        tenant: TenantId,
        now: Timestamp,
        lifetime_days: u16,
    ) -> Result<LeafCertificate, IssueError> {
        let validity =
            days(now, 0, i64::from(lifetime_days)).map_err(|_| IssueError::TimeOutOfRange)?;
        LeafCertificate::device(&self.signer, &self.issuing, key, device, tenant, validity)
    }

    /// Signs a canonical policy bundle with the policy key the trust set
    /// lists, as the envelope agents store (#325).
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] if the bundle is not canonical or signing fails.
    pub fn sign_policy(&self, bundle: &[u8]) -> Result<Vec<u8>, AuthorityError> {
        palisade_proto::policy_bundle::envelope::Envelope::sign_bundle(
            bundle,
            &self.signer,
            &[self.policy_kid],
        )
        .map(|e| e.encode())
        .map_err(|e| err("policy bundle")(&e))
    }

    /// The chain to send with a device certificate: the issuing CA.
    #[must_use]
    pub fn chain(&self) -> Vec<Vec<u8>> {
        vec![self.issuing.der().to_vec()]
    }

    /// The root certificate, DER: what the agent listener's client CA
    /// bundle and the agent's trust anchor are built from.
    #[must_use]
    pub fn root_der(&self) -> &[u8] {
        self.root.der()
    }

    /// The issuing CA certificate, DER.
    #[must_use]
    pub fn issuing_der(&self) -> &[u8] {
        self.issuing.der()
    }

    /// The root key, which signs trust sets and whose SPKI hash agents are
    /// installed with.
    #[must_use]
    pub fn root_key(&self) -> &PublicKey {
        self.root.public_key()
    }

    /// The current signed trust set.
    #[must_use]
    pub fn trust_set(&self) -> Arc<[u8]> {
        Arc::clone(&self.trust_set)
    }

    /// The current trust version.
    #[must_use]
    pub const fn trust_version(&self) -> u64 {
        self.trust_version
    }
}

/// Exposes [`leaf_key::generate_pkcs8`] for callers that only import this
/// module.
pub use leaf_key::generate_pkcs8;

#[cfg(test)]
mod tests {
    use super::*;
    use palisade_proto::events::Uuid7;
    use palisade_proto::pki::{SkewTolerance, TrustAnchor};
    use std::str::FromStr;

    fn now() -> Timestamp {
        Timestamp::from_str("2026-11-29T00:00:00.000000Z").unwrap()
    }

    #[test]
    fn the_development_hierarchy_issues_device_certificates_and_a_valid_trust_set() {
        let dev = Authority::generate(now(), &[DnsName::from_str("localhost").unwrap()]).unwrap();
        let a = &dev.authority;
        assert_eq!(dev.server_chain.len(), 3);
        assert!(a.sign_policy(b"not a bundle").is_err());
        assert_eq!(a.trust_version(), 1);
        // An agent pinned to the root accepts the trust set.
        let mut anchor = TrustAnchor::new(a.root_key().clone(), SkewTolerance::DEFAULT).unwrap();
        let set = anchor.accept(&a.trust_set(), now()).unwrap();
        assert!(set.pins(a.root_key().spki_der()));
        assert_eq!(set.policy_keys().count(), 1);

        let (key, _) = LeafKey::generate().unwrap();
        let device = HostId(Uuid7::from_str("019a0000-0000-7000-8000-000000000001").unwrap());
        let tenant = TenantId(Uuid7::from_str("019a0000-0000-7000-8000-0000000000aa").unwrap());
        let cert = a
            .issue_device(key.public_key(), device, tenant, now(), 30)
            .unwrap();
        assert_eq!(
            cert.validity().not_after().unix_micros() - cert.validity().not_before().unix_micros(),
            30 * MICROS_PER_DAY
        );
        assert_eq!(
            a.issue_device(key.public_key(), device, tenant, now(), 91),
            Err(IssueError::LifetimeTooLong)
        );
        assert!(format!("{a:?}").starts_with("Authority"));
        assert_eq!(a.chain(), vec![a.issuing_der().to_vec()]);
        assert!(!a.root_der().is_empty());
    }
}
