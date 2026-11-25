//! Certificate chain building (#49).
//!
//! For one signer certificate and the certificates embedded beside it, this
//! module builds:
//!
//! - the **as-provided chain**: the embedded certificates only, ordered from
//!   the leaf up as far as they reach, with no online lookups;
//! - the **full chain**: the same search over the embedded certificates
//!   plus a [`TrustConfig`]: the Palisade-managed anchor bundle and extra
//!   intermediates that policy ships (#6, #9). It reports whether the chain
//!   is complete and which anchor, if any, it reaches.
//!
//! The PCA (the highest certificate provided in the file below the root)
//! and the root are taken from the **full chain**: its embedded prefix
//! from the leaf up. The embedded certificate set is not signed, so anyone
//! can add certificates to it; a certificate that is not on the path to the
//! trusted anchor must never become the PCA.
//!
//! Every link is checked: the issuer's subject must equal the child's issuer
//! name byte for byte, key identifiers must agree when both are present,
//! the issuer must be a CA allowed to sign certificates (`cA` set, and
//! `keyCertSign` if it has a key usage), path length constraints must
//! hold, and the child's signature must verify with the issuer's key. These
//! apply to configured anchors too, when they issue a certificate: an
//! anchor that is an end-entity certificate (a pinned self-signed signer)
//! can be the top of a chain but can issue nothing. Only an anchor of
//! version 1 or 2, which has no extensions to say so, is taken to be a CA.
//! A certificate with a critical extension this crate does not process is
//! never used, unless it is itself a configured anchor. A name match alone
//! never links two certificates.
//!
//! **Trust is decided downwards from the anchors.** Starting from each
//! configured anchor, every certificate whose issuer name matches a trusted
//! certificate's subject is checked with that trusted key, breadth first;
//! a certificate whose signature verifies becomes trusted in turn. Only
//! links verified this way can make an anchored path. So every check that
//! decides trust uses a key from policy, or one an anchor vouched for, and
//! only certificates reachable upwards from the leaf by issuer name are
//! looked at, so unrelated policy entries cost nothing. Each certificate is
//! checked at most once per trusted key, and at most
//! [`MAX_EMBEDDED_CERTIFICATES`] embedded certificates are used, so what a
//! file adds costs at most that many checks per trusted key sharing a
//! name. This phase has its own budget, [`MAX_TRUST_CHECKS`] per build,
//! which earlier and nested signatures cannot spend. Links into the leaf
//! and into policy certificates are checked first, on a separate pool of
//! checks and candidate steps from links into other embedded certificates,
//! so nothing a file adds can spend what those links need. That pool can
//! still run out, but only through the trust configuration itself (more
//! than 64 trusted keys sharing one subject name); it then fails closed
//! and is reported as [`ChainIssue::WorkLimitReached`].
//!
//! The as-provided chain, and the full chain when nothing is anchored, are
//! then searched upwards from the leaf with whatever keys the file holds.
//! The search enumerates every path, detects loops, stops at
//! [`MAX_CHAIN_LENGTH`] certificates and keeps the best [`MAX_CHAIN_PATHS`]
//! paths (anchored before unanchored, complete before incomplete, then
//! paths whose every certificate permits code signing, then the shortest);
//! the others are reported as alternatives, which is how
//! cross-signed paths show up. These checks, with the self-signatures of
//! self-issued certificates, spend at most [`MAX_SIGNATURE_CHECKS`] per
//! build and [`MAX_FILE_SIGNATURE_CHECKS`] per file. Verification results
//! are cached per issuer key, so copies of one key cost one check. Running
//! out fails closed: a link not checked is not made, and a certificate
//! whose self-signature was not checked is not self-signed. Neither ever
//! affects trust.
//!
//! Policy can relax one certificate's basic constraints
//! ([`TrustConfig::ignore_basic_constraints`]): it may then issue although it
//! is not a CA or its path length is exceeded, with every other check kept,
//! and the links that needed it are reported. Certificates the Windows
//! backend reads from the OS stores are added with
//! [`TrustConfig::add_os_store_anchor`] and
//! [`TrustConfig::add_os_store_intermediate`] and reported as
//! [`AnchorSource::OsStore`].
//!
//! Not checked here: validity periods (whose nesting is only reported, in
//! [`ChainReport::time_nesting_violations`]), timestamps and revocation
//! (#50). Reading the OS stores and the OS trust-verification cross-check
//! are the Windows backend's (`os-trust`, #48).

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};

use serde::Serialize;

use super::asn1::{Asn1Error, Asn1ErrorKind, ObjectId, tag};
use super::crypto::Verified;
use super::eku;
use super::signature::{KeyAlgorithm, SignatureAlgorithm, Unsupported};
use super::x509::{self, Budget, CertSummary, CertificateError, KeyUsage};

/// The longest path built, in certificates, leaf and root included.
pub const MAX_CHAIN_LENGTH: usize = 10;
/// The most candidate paths recorded per search.
pub const MAX_CHAIN_PATHS: usize = 8;
/// The most certificate signatures verified with keys a file supplies
/// (self-signatures, and links in the untrusted searches) per chain build.
pub const MAX_SIGNATURE_CHECKS: usize = 128;
/// The most certificate signatures verified with keys a file supplies
/// (self-signatures and the untrusted searches) for all the signatures of
/// one file, by [`super::evaluate_trust`]. Trust does not depend on these
/// checks.
pub const MAX_FILE_SIGNATURE_CHECKS: usize = 512;
/// The most signatures verified per chain build while deciding trust,
/// downwards from the anchors, in each of two pools: links into the leaf
/// and into policy certificates, and links into other embedded
/// certificates.
///
/// Each certificate is checked at most once per trusted key whose subject
/// it names as its issuer, and at most [`MAX_EMBEDDED_CERTIFICATES`]
/// embedded certificates are used, so certificates added to a file cause at
/// most `MAX_EMBEDDED_CERTIFICATES` checks per trusted key sharing a name.
/// Added certificates spend only the second pool, checks and candidate
/// steps alike, so they cannot keep the leaf's link or a policy-supplied
/// chain from being verified. The first pool is spent only by the leaf and
/// policy certificates, so it can run out only for a trust configuration
/// with very many trusted keys sharing a subject name; it then fails closed
/// and the report says [`ChainIssue::WorkLimitReached`].
pub const MAX_TRUST_CHECKS: usize = 4096;
/// The most embedded certificates [`build_chain`] uses: as many as one
/// signature keeps ([`super::MAX_CERTIFICATES`]). The signer is always
/// used; later certificates beyond the limit are ignored and reported as
/// [`ChainIssue::TooManyCertificates`].
pub const MAX_EMBEDDED_CERTIFICATES: usize = super::MAX_CERTIFICATES;
/// The most per-certificate issues recorded per chain build. The limit
/// markers ([`ChainIssue::TooLong`], [`ChainIssue::TooManyPaths`],
/// [`ChainIssue::TooManyCertificates`], [`ChainIssue::WorkLimitReached`] and
/// [`ChainIssue::IssuesTruncated`]) are kept beyond it, at most once each,
/// so a report holds at most `MAX_CHAIN_ISSUES + 5` issues.
pub const MAX_CHAIN_ISSUES: usize = 32;

/// A trust anchor from the policy-shipped bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustAnchor {
    /// A name for reports, from the bundle.
    pub label: String,
    /// The anchor certificate.
    pub cert: CertSummary,
    /// Where it came from: [`AnchorSource::Policy`] or
    /// [`AnchorSource::OsStore`].
    pub source: AnchorSource,
}

/// How a [`TrustConfig`] names one certificate: only by forms that bind its
/// key. Issuer and serial do not (anyone can issue a certificate with any
/// issuer name and serial), so they cannot pin.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificatePin {
    /// The SHA-256 thumbprint, hex (either case).
    Sha256Thumbprint(String),
    /// A TBS hash, hex (either case), under the certificate's own digest or
    /// SHA-256.
    TbsHash(String),
}

impl CertificatePin {
    /// Whether this pins `cert`. Hex is compared ignoring case.
    #[must_use]
    pub fn matches(&self, cert: &CertSummary) -> bool {
        match self {
            Self::Sha256Thumbprint(t) => cert.sha256_thumbprint.eq_ignore_ascii_case(t),
            Self::TbsHash(h) => super::revocation::tbs_matches(cert, h),
        }
    }
}

/// An OS-vendor root's well-known ID, keyed by its TBS hash. OS code
/// integrity policies name these roots by ID rather than by TBS hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WellKnownRoot {
    /// The well-known root ID used by the OS policy schema.
    pub id: u8,
    /// The root's TBS hash: lowercase hex, 40, 64, 96 or 128 characters.
    pub tbs_hash: String,
}

/// Why a [`WellKnownRoot`] was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WellKnownRootError {
    /// The hash is not 40, 64, 96 or 128 hex characters.
    BadHash,
}

/// What chains are built against: trust anchors, extra intermediates and
/// the well-known root table, all from policy content (#6, #9). Nothing
/// here is built in; an empty configuration trusts nothing.
#[derive(Debug, Clone, Default)]
pub struct TrustConfig {
    anchors: Vec<TrustAnchor>,
    intermediates: Vec<CertSummary>,
    /// The source of each intermediate, in [`Self::intermediates`] order.
    intermediate_sources: Vec<AnchorSource>,
    well_known_roots: Vec<WellKnownRoot>,
    /// Certificates whose basic constraints are not enforced when they
    /// issue ([`Self::ignore_basic_constraints`]).
    basic_constraints_exempt: Vec<CertificatePin>,
}

impl TrustConfig {
    /// An empty configuration: no anchors, so nothing is trusted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a trust anchor certificate from the policy bundle. Returns its
    /// index.
    pub fn add_anchor(
        &mut self,
        label: impl Into<String>,
        der: &[u8],
    ) -> Result<usize, CertificateError> {
        self.push_anchor(label.into(), der, AnchorSource::Policy)
    }

    /// Adds a trust anchor read from the OS machine root store. The Windows
    /// backend reads the store (the `os-trust` feature, #48); this crate
    /// only records where the anchor came from, so a chain that reaches it
    /// reports [`AnchorSource::OsStore`] and policy can tell the two apart.
    /// Returns its index in [`Self::anchors`].
    pub fn add_os_store_anchor(
        &mut self,
        label: impl Into<String>,
        der: &[u8],
    ) -> Result<usize, CertificateError> {
        self.push_anchor(label.into(), der, AnchorSource::OsStore)
    }

    fn push_anchor(
        &mut self,
        label: String,
        der: &[u8],
        source: AnchorSource,
    ) -> Result<usize, CertificateError> {
        let cert = CertSummary::from_der(der)?;
        self.anchors.push(TrustAnchor {
            label,
            cert,
            source,
        });
        Ok(self.anchors.len() - 1)
    }

    /// Adds an intermediate certificate from policy that chains may use but
    /// that is not trusted by itself. Returns its index.
    pub fn add_intermediate(&mut self, der: &[u8]) -> Result<usize, CertificateError> {
        self.push_intermediate(der, AnchorSource::Policy)
    }

    /// Adds an intermediate read from the OS machine intermediate store
    /// (see [`Self::add_os_store_anchor`]). It is not trusted by itself.
    /// Returns its index in [`Self::intermediates`].
    pub fn add_os_store_intermediate(&mut self, der: &[u8]) -> Result<usize, CertificateError> {
        self.push_intermediate(der, AnchorSource::OsStore)
    }

    fn push_intermediate(
        &mut self,
        der: &[u8],
        source: AnchorSource,
    ) -> Result<usize, CertificateError> {
        self.intermediates.push(CertSummary::from_der(der)?);
        self.intermediate_sources.push(source);
        Ok(self.intermediates.len() - 1)
    }

    /// Where the intermediate at `index` came from.
    #[must_use]
    pub fn intermediate_source(&self, index: usize) -> Option<AnchorSource> {
        self.intermediate_sources.get(index).copied()
    }

    /// Lets the certificate `pin` names issue certificates even though its
    /// basic constraints forbid it: it is not a CA (`cA` absent or FALSE),
    /// or its `pathLenConstraint` is exceeded. This is the "ignore basic
    /// constraints" relaxation of a trusted-publisher rule (#50).
    ///
    /// Only those two checks are relaxed, and only for that certificate as
    /// an issuer. Its key usage must still allow `keyCertSign`, the child's
    /// signature must still verify with its key, and trust is still decided
    /// downwards from the anchors. Every link that used the relaxation is
    /// listed in [`ChainReport::basic_constraints_ignored`].
    pub fn ignore_basic_constraints(&mut self, pin: CertificatePin) {
        if !self.basic_constraints_exempt.contains(&pin) {
            self.basic_constraints_exempt.push(pin);
        }
    }

    /// The certificates [`Self::ignore_basic_constraints`] names.
    #[must_use]
    pub fn basic_constraints_exempt(&self) -> &[CertificatePin] {
        &self.basic_constraints_exempt
    }

    /// Adds a well-known root. The hash may be upper- or lowercase.
    pub fn add_well_known_root(
        &mut self,
        id: u8,
        tbs_hash: &str,
    ) -> Result<(), WellKnownRootError> {
        let ok_len = matches!(tbs_hash.len(), 40 | 64 | 96 | 128);
        if !ok_len || !tbs_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(WellKnownRootError::BadHash);
        }
        self.well_known_roots.push(WellKnownRoot {
            id,
            tbs_hash: tbs_hash.to_ascii_lowercase(),
        });
        Ok(())
    }

    /// The trust anchors.
    #[must_use]
    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    /// The extra intermediates.
    #[must_use]
    pub fn intermediates(&self) -> &[CertSummary] {
        &self.intermediates
    }

    /// The well-known ID of `cert`, if its TBS hash is in the table.
    #[must_use]
    pub fn well_known_root_id(&self, cert: &CertSummary) -> Option<u8> {
        self.well_known_roots
            .iter()
            .find(|r| {
                cert.tbs_hash.as_deref() == Some(r.tbs_hash.as_str())
                    || cert.tbs_hash_sha256 == r.tbs_hash
            })
            .map(|r| r.id)
    }
}

/// Where a certificate in a [`ChainReport`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertOrigin {
    /// Embedded in the signature: an index into
    /// [`super::SignatureInfo::certs_in_blob`].
    Embedded(usize),
    /// A [`TrustConfig`] intermediate, by index. It came from policy or,
    /// for one added with [`TrustConfig::add_os_store_intermediate`], from
    /// the OS store ([`TrustConfig::intermediate_source`]).
    PolicyIntermediate(usize),
    /// A [`TrustConfig`] anchor, by index; its
    /// [`TrustAnchor::source`] says whether from policy or the OS store.
    PolicyAnchor(usize),
}

/// Where the anchor a chain reaches came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AnchorSource {
    /// A [`TrustConfig`] anchor from policy.
    Policy,
    /// A [`TrustConfig`] anchor read from the OS machine root store
    /// ([`TrustConfig::add_os_store_anchor`]).
    OsStore,
    /// The chain reaches no anchor.
    None,
}

/// The anchor a chain reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorRef {
    /// The anchor's index in [`TrustConfig::anchors`].
    pub index: usize,
    /// The anchor's label.
    pub label: String,
    /// The anchor's SHA-256 thumbprint.
    pub sha256_thumbprint: String,
}

/// One certificate of a [`ChainReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainCert {
    /// Where it came from.
    pub origin: CertOrigin,
    /// The anchor index, when the certificate is (byte for byte) a
    /// [`TrustConfig`] anchor.
    pub anchor: Option<usize>,
    /// The certificate.
    pub cert: CertSummary,
}

/// One path: indices into [`ChainReport::certificates`], leaf first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainPath {
    /// The certificates, leaf first, each issued by the next.
    pub certs: Vec<usize>,
    /// The path ends at a trust anchor (only for full-chain paths).
    pub anchored: bool,
    /// The path ends at a self-signed certificate or a trust anchor:
    /// nothing is missing above it.
    pub complete: bool,
}

/// Something found while building a chain. Certificates are indices into
/// [`ChainReport::certificates`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChainIssue {
    /// An embedded certificate could not be parsed and was not used.
    UnparseableCertificate {
        /// Its index in the signature's embedded certificates.
        embedded: usize,
        /// Why.
        error: CertificateError,
    },
    /// A certificate has a critical extension this crate does not process,
    /// so it cannot be part of a chain (RFC 5280, 4.2).
    UnhandledCriticalExtension {
        /// The certificate.
        cert: usize,
        /// The extension.
        oid: ObjectId,
    },
    /// A certificate with the right name is not a CA (no `basicConstraints`
    /// with `cA` set), so it cannot be an issuer.
    IssuerNotCa {
        /// The would-be issuer.
        issuer: usize,
    },
    /// A would-be issuer's `keyUsage` lacks `keyCertSign`.
    IssuerKeyUsage {
        /// The would-be issuer.
        issuer: usize,
    },
    /// A would-be issuer's `pathLenConstraint` is exceeded.
    PathLengthExceeded {
        /// The would-be issuer.
        issuer: usize,
    },
    /// A child's authority key identifier differs from a would-be issuer's
    /// subject key identifier.
    KeyIdMismatch {
        /// The child.
        child: usize,
        /// The would-be issuer.
        issuer: usize,
    },
    /// A certificate's signature does not verify with the key of a
    /// certificate whose name matches its issuer: a forged or unrelated
    /// issuer.
    SignatureInvalid {
        /// The child.
        child: usize,
        /// The would-be issuer.
        issuer: usize,
    },
    /// A certificate's signature could not be checked with a would-be
    /// issuer's key.
    SignatureUnsupported {
        /// The child.
        child: usize,
        /// The would-be issuer.
        issuer: usize,
        /// Why.
        why: Unsupported,
    },
    /// A path would revisit a certificate.
    Loop {
        /// The certificate that would be revisited.
        cert: usize,
    },
    /// A path would be longer than [`MAX_CHAIN_LENGTH`].
    TooLong,
    /// More than [`MAX_CHAIN_PATHS`] paths exist; the rest were not built.
    TooManyPaths,
    /// More than [`MAX_EMBEDDED_CERTIFICATES`] embedded certificates; the
    /// rest were ignored.
    TooManyCertificates,
    /// The signature-check budget ([`MAX_SIGNATURE_CHECKS`] per build,
    /// [`MAX_FILE_SIGNATURE_CHECKS`] per file) ran out; further links were
    /// not made, and further self-issued certificates were not treated as
    /// self-signed.
    WorkLimitReached,
    /// More than [`MAX_CHAIN_ISSUES`] per-certificate issues; the rest were
    /// dropped.
    IssuesTruncated,
}

/// The chains of one signer certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainReport {
    /// Every certificate referred to: the signer first, then the other
    /// embedded certificates that parsed, in blob order (duplicates
    /// dropped), then any policy certificates a path or issue uses.
    pub certificates: Vec<ChainCert>,
    /// The signer certificate.
    pub leaf: usize,
    /// The as-provided chain: embedded certificates only, leaf first.
    pub as_provided: ChainPath,
    /// Other as-provided paths (cross-signed alternatives), best first.
    pub as_provided_alternatives: Vec<ChainPath>,
    /// The embedded certificates of the full chain between the leaf and
    /// the root, lowest first: the full chain's embedded prefix, without
    /// the leaf and without a self-signed root.
    pub intermediates: Vec<usize>,
    /// The "PCA": the highest certificate provided in the file on the full
    /// chain, excluding the root. `None` when the file carries no
    /// intermediate on it (only the leaf, or the leaf and a root), in which
    /// case Publisher-level OS rules cannot be made for it.
    pub pca: Option<usize>,
    /// The self-signed root of the full chain, if the file carries it. For
    /// a self-signed leaf, the leaf itself.
    pub root_as_provided: Option<usize>,
    /// The chosen full chain, built over the embedded certificates and the
    /// [`TrustConfig`].
    pub full_chain: ChainPath,
    /// Other full paths, best first. When the full chain is anchored, only
    /// other anchored paths.
    pub alternatives: Vec<ChainPath>,
    /// The full chain ends at a self-signed certificate or a trust anchor.
    pub chain_complete: bool,
    /// The anchor the full chain reaches.
    pub anchored_to: Option<AnchorRef>,
    /// Where that anchor came from.
    pub anchor_source: AnchorSource,
    /// The well-known ID of the full chain's root (its self-signed top or
    /// anchor), from [`TrustConfig`]'s table.
    pub well_known_root_id: Option<u8>,
    /// The issuers on the full chain that issued their child only because
    /// [`TrustConfig::ignore_basic_constraints`] relaxed their basic
    /// constraints: indices into [`Self::certificates`], lowest first.
    /// Empty when no relaxation was needed.
    pub basic_constraints_ignored: Vec<usize>,
    /// The certificates on the full chain whose validity period is not
    /// inside their issuer's ("not time nested"): indices into
    /// [`Self::certificates`], lowest first. This is reported, not judged:
    /// whether it fails a signature is policy's call (#50,
    /// `ValidityPolicy::require_time_nesting`), as the OS ignores it for
    /// code signing by default.
    pub time_nesting_violations: Vec<usize>,
    /// What was found along the way.
    pub issues: Vec<ChainIssue>,
}

impl ChainReport {
    /// The certificate at `index` in [`Self::certificates`].
    #[must_use]
    pub fn cert(&self, index: usize) -> Option<&CertSummary> {
        self.certificates.get(index).map(|c| &c.cert)
    }

    /// The signer certificate.
    #[must_use]
    pub fn leaf_cert(&self) -> Option<&CertSummary> {
        self.cert(self.leaf)
    }

    /// The PCA certificate.
    #[must_use]
    pub fn pca_cert(&self) -> Option<&CertSummary> {
        self.pca.and_then(|i| self.cert(i))
    }

    /// The as-provided root certificate.
    #[must_use]
    pub fn root_cert(&self) -> Option<&CertSummary> {
        self.root_as_provided.and_then(|i| self.cert(i))
    }

    /// The certificates of the full chain, leaf first.
    pub fn full_chain_certs(&self) -> impl Iterator<Item = &CertSummary> {
        self.full_chain.certs.iter().filter_map(|i| self.cert(*i))
    }

    /// Whether the signer certificate's `extKeyUsage` lists `eku`.
    #[must_use]
    pub fn leaf_has_eku(&self, eku: &ObjectId) -> bool {
        self.leaf_cert().is_some_and(|c| c.has_eku(eku))
    }

    /// Whether `eku` is in force for the whole full chain: the leaf lists
    /// it, and no certificate above restricts it away (each has no
    /// `extKeyUsage`, or lists `eku` or `anyExtendedKeyUsage`). This is
    /// how the OS treats EKUs on issuers.
    #[must_use]
    pub fn chain_has_eku(&self, eku: &ObjectId) -> bool {
        self.leaf_has_eku(eku) && self.full_chain_certs().skip(1).all(|c| c.permits_eku(eku))
    }

    /// Whether the full chain may sign code: every certificate permits the
    /// Code Signing EKU (has no `extKeyUsage`, or lists Code Signing or
    /// `anyExtendedKeyUsage`).
    #[must_use]
    pub fn permits_code_signing(&self) -> bool {
        let code_signing = eku::CODE_SIGNING.id();
        self.full_chain_certs()
            .all(|c| c.permits_eku(&code_signing))
    }

    /// Whether every key in the full chain is at least `min_rsa_bits` (RSA)
    /// or `min_ec_bits` (elliptic curve) long. Any other key algorithm
    /// fails.
    #[must_use]
    pub fn meets_min_key_bits(&self, min_rsa_bits: u32, min_ec_bits: u32) -> bool {
        self.full_chain_certs()
            .all(|c| match (&c.public_key_alg, c.key_bits) {
                (KeyAlgorithm::Rsa, Some(bits)) => bits >= min_rsa_bits,
                (KeyAlgorithm::Ec(_), Some(bits)) => bits >= min_ec_bits,
                _ => false,
            })
    }

    /// Whether every certificate signature in the full chain uses an
    /// algorithm in `allowed`. The signature of a self-signed certificate,
    /// and of the anchor at the top of an anchored chain, is not counted:
    /// nothing relies on it.
    #[must_use]
    pub fn cert_sig_algs_allowed(&self, allowed: &[SignatureAlgorithm]) -> bool {
        let last = self.full_chain.certs.len().saturating_sub(1);
        self.full_chain_certs()
            .enumerate()
            .filter(|(pos, c)| !c.is_self_signed && !(self.full_chain.anchored && *pos == last))
            .all(|(_, c)| allowed.contains(&c.sig_alg))
    }
}

/// A certificate the search may use.
struct Node<'a> {
    cert: &'a CertSummary,
    origin: CertOrigin,
    anchor: Option<usize>,
    /// The certificate is a policy intermediate or anchor, even if the
    /// file also embeds a copy (which keeps the embedded origin).
    from_policy: bool,
    /// [`TrustConfig::ignore_basic_constraints`] names it.
    bc_exempt: bool,
}

/// Builds the chains of the signer certificate `certs[signer]`, where
/// `certs` are the DER certificates embedded in its signature.
///
/// Fails only when the signer certificate itself cannot be parsed.
pub fn build_chain(
    certs: &[Vec<u8>],
    signer: usize,
    config: &TrustConfig,
) -> Result<ChainReport, CertificateError> {
    build_chain_within(
        certs,
        signer,
        config,
        &mut Budget::new(MAX_SIGNATURE_CHECKS),
    )
}

/// [`build_chain`], charging `file_budget` for the checks that use keys the
/// file supplies ([`MAX_SIGNATURE_CHECKS`] at most per build). Trust checks
/// have a budget of their own, [`MAX_TRUST_CHECKS`] per build.
pub(crate) fn build_chain_within(
    certs: &[Vec<u8>],
    signer: usize,
    config: &TrustConfig,
    file_budget: &mut Budget,
) -> Result<ChainReport, CertificateError> {
    let mut issues = Issues::default();
    let anchors_by_thumbprint: HashMap<&str, usize> = config
        .anchors
        .iter()
        .enumerate()
        .map(|(i, a)| (a.cert.sha256_thumbprint.as_str(), i))
        .rev()
        .collect();

    // Parse the embedded certificates; the signer must parse.
    let leaf_der = certs.get(signer).ok_or(CertificateError::Asn1(Asn1Error {
        kind: Asn1ErrorKind::Missing {
            expected: tag::SEQUENCE,
        },
        offset: 0,
    }))?;
    // Self-signature checks while parsing come out of the same budget as
    // link checks.
    let mut parse_budget = Budget::new(file_budget.left().min(MAX_SIGNATURE_CHECKS));
    let leaf_summary = match x509::parse_within(leaf_der, &mut parse_budget) {
        Ok(c) => c,
        Err(e) => {
            file_budget.absorb(&parse_budget);
            return Err(e);
        }
    };
    let mut embedded: Vec<(usize, CertSummary)> = vec![(signer, leaf_summary)];
    // Every entry tried counts against the limit, parsed or not, so
    // malformed entries cannot make the builder read the whole slice.
    let mut tried = 1_usize;
    for (i, der) in certs.iter().enumerate() {
        if i == signer {
            continue;
        }
        if tried >= MAX_EMBEDDED_CERTIFICATES {
            issues.push(ChainIssue::TooManyCertificates);
            break;
        }
        tried += 1;
        match x509::parse_within(der, &mut parse_budget) {
            Ok(c) => embedded.push((i, c)),
            Err(error) => issues.push(ChainIssue::UnparseableCertificate { embedded: i, error }),
        }
    }

    // The pool: the signer, the other embedded certificates in blob order,
    // then policy intermediates and anchors. A certificate already present
    // (same SHA-256 thumbprint) is not added again. The search tries
    // issuers in the reverse of this order, so policy certificates first.
    let anchor_of = |cert: &CertSummary| {
        anchors_by_thumbprint
            .get(cert.sha256_thumbprint.as_str())
            .copied()
    };
    let policy_thumbprints: HashSet<&str> = config
        .intermediates
        .iter()
        .chain(config.anchors.iter().map(|a| &a.cert))
        .map(|c| c.sha256_thumbprint.as_str())
        .collect();
    let exempt = |cert: &CertSummary| {
        config
            .basic_constraints_exempt
            .iter()
            .any(|pin| pin.matches(cert))
    };
    let mut pool: Vec<Node<'_>> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for (i, cert) in &embedded {
        if seen.insert(cert.sha256_thumbprint.as_str()) {
            pool.push(Node {
                cert,
                origin: CertOrigin::Embedded(*i),
                anchor: anchor_of(cert),
                from_policy: policy_thumbprints.contains(cert.sha256_thumbprint.as_str()),
                bc_exempt: exempt(cert),
            });
        }
    }
    let embedded_count = pool.len();
    for (i, cert) in config.intermediates.iter().enumerate() {
        if seen.insert(cert.sha256_thumbprint.as_str()) {
            pool.push(Node {
                cert,
                origin: CertOrigin::PolicyIntermediate(i),
                anchor: anchor_of(cert),
                from_policy: true,
                bc_exempt: exempt(cert),
            });
        }
    }
    for (i, anchor) in config.anchors.iter().enumerate() {
        if seen.insert(anchor.cert.sha256_thumbprint.as_str()) {
            pool.push(Node {
                cert: &anchor.cert,
                origin: CertOrigin::PolicyAnchor(i),
                anchor: Some(i),
                from_policy: true,
                bc_exempt: exempt(&anchor.cert),
            });
        }
    }
    // The signer is pool node 0, and so report certificate 0.
    let leaf = 0;

    file_budget.absorb(&parse_budget);

    let mut search = Search::new(&pool, &mut issues);
    // Trust first, verifying downwards from the anchors with trusted keys
    // only, on a budget of its own that nothing in the file can spend.
    let mut trust_budget = Budget::new(MAX_TRUST_CHECKS);
    let mut embedded_trust_budget = Budget::new(MAX_TRUST_CHECKS);
    search.mark_trusted(leaf, &mut trust_budget, &mut embedded_trust_budget);
    let anchored_paths = search.run(leaf, pool.len(), Mode::Trusted, &mut trust_budget);
    // Then the informational paths, checked with whatever keys the file
    // holds. The per-build cap covers the self-signature checks too.
    let mut budget = Budget::new(
        file_budget
            .left()
            .min(MAX_SIGNATURE_CHECKS.saturating_sub(parse_budget.used())),
    );
    search.relax = false;
    let provided_paths = search.run(leaf, embedded_count, Mode::Untrusted, &mut budget);
    search.relax = true;
    let full_anchored = !anchored_paths.is_empty();
    let full_paths = if full_anchored {
        anchored_paths
    } else {
        search.run(leaf, pool.len(), Mode::Untrusted, &mut budget)
    };
    drop(search);
    file_budget.absorb(&budget);
    if budget.exhausted
        || trust_budget.exhausted
        || embedded_trust_budget.exhausted
        || parse_budget.exhausted
    {
        issues.push(ChainIssue::WorkLimitReached);
    }

    let trivial = || vec![leaf];
    let provided = rank(provided_paths, &pool, false);
    let full = rank(full_paths, &pool, full_anchored);

    // Map pool indices to report indices: every embedded certificate, then
    // policy certificates in first-use order.
    let mut out: Vec<ChainCert> = Vec::new();
    let mut map: HashMap<usize, usize> = HashMap::new();
    let mut index_of = |p: usize, out: &mut Vec<ChainCert>| -> usize {
        *map.entry(p).or_insert_with(|| {
            if let Some(node) = pool.get(p) {
                out.push(ChainCert {
                    origin: node.origin,
                    anchor: node.anchor,
                    cert: node.cert.clone(),
                });
            }
            out.len().saturating_sub(1)
        })
    };
    for p in 0..embedded_count {
        index_of(p, &mut out);
    }
    let mut to_path = |path: &[usize], out: &mut Vec<ChainCert>, with_anchor: bool| {
        let certs: Vec<usize> = path.iter().map(|p| index_of(*p, out)).collect();
        let (anchored, complete) = path_state(path, &pool, with_anchor);
        ChainPath {
            certs,
            anchored,
            complete,
        }
    };
    let mut provided_iter = provided.into_iter();
    let as_provided = to_path(
        &provided_iter.next().unwrap_or_else(trivial),
        &mut out,
        false,
    );
    let as_provided_alternatives: Vec<ChainPath> = provided_iter
        .map(|p| to_path(&p, &mut out, false))
        .collect();
    let mut full_iter = full.into_iter();
    let full_chain = to_path(
        &full_iter.next().unwrap_or_else(trivial),
        &mut out,
        full_anchored,
    );
    let alternatives: Vec<ChainPath> = full_iter
        .map(|p| to_path(&p, &mut out, full_anchored))
        .collect();
    let issue_list: Vec<ChainIssue> = issues
        .list
        .into_iter()
        .map(|issue| remap(issue, &mut |p| index_of(p, &mut out)))
        .collect();

    // The PCA, intermediates and root come from the full chain's embedded
    // prefix, never from a path the full chain does not take.
    let embedded_prefix: Vec<usize> = full_chain
        .certs
        .iter()
        .copied()
        .take_while(|i| {
            out.get(*i)
                .is_some_and(|c| matches!(c.origin, CertOrigin::Embedded(_)))
        })
        .collect();
    let prefix_is_whole = embedded_prefix.len() == full_chain.certs.len();
    // The root: a self-signed top, or a self-issued anchor (whose own
    // signature is never relied on, and may use an algorithm that is not
    // verified here).
    let anchored = full_chain.anchored;
    let root_as_provided = embedded_prefix
        .last()
        .copied()
        .filter(|t| prefix_is_whole && out.get(*t).is_some_and(|c| is_root(c, anchored)));
    let below_root = embedded_prefix
        .len()
        .saturating_sub(usize::from(root_as_provided.is_some()));
    let intermediates: Vec<usize> = embedded_prefix
        .get(1..below_root)
        .unwrap_or_default()
        .to_vec();
    let pca = intermediates.last().copied();

    let top = full_chain.certs.last().and_then(|t| out.get(*t));
    let anchored_to = if full_chain.anchored {
        top.and_then(|c| c.anchor)
            .and_then(|i| config.anchors.get(i).map(|a| (i, a)))
            .map(|(index, a)| AnchorRef {
                index,
                label: a.label.clone(),
                sha256_thumbprint: a.cert.sha256_thumbprint.clone(),
            })
    } else {
        None
    };
    let well_known_root_id = top
        .filter(|c| full_chain.complete && (is_root(c, anchored) || c.anchor.is_some()))
        .and_then(|c| config.well_known_root_id(&c.cert));
    // The issuers on the chosen full chain that issued only because policy
    // relaxed their basic constraints: worked out from that chain alone,
    // with the same rules the search applied to it.
    let basic_constraints_ignored = relaxed_issuers(&full_chain, &out, anchored, config);
    let time_nesting_violations: Vec<usize> = full_chain
        .certs
        .windows(2)
        .filter_map(|pair| match pair {
            [child, issuer] => {
                let (c, i) = (&out.get(*child)?.cert, &out.get(*issuer)?.cert);
                (c.not_before < i.not_before || c.not_after > i.not_after).then_some(*child)
            }
            _ => None,
        })
        .collect();

    Ok(ChainReport {
        leaf,
        pca,
        root_as_provided,
        intermediates,
        chain_complete: full_chain.complete,
        anchor_source: anchored_to
            .as_ref()
            .and_then(|a| config.anchors.get(a.index))
            .map_or(AnchorSource::None, |a| a.source),
        anchored_to,
        well_known_root_id,
        basic_constraints_ignored,
        time_nesting_violations,
        as_provided,
        as_provided_alternatives,
        full_chain,
        alternatives,
        issues: issue_list,
        certificates: out,
    })
}

/// The issuers on `chain` that are not CAs, or whose path length is
/// exceeded on it, and that a [`TrustConfig::ignore_basic_constraints`] pin
/// names: the links the chain could make only through that relaxation.
/// A v1 or v2 anchor counts as a CA in an anchored chain, as the trusted
/// search treats it.
fn relaxed_issuers(
    chain: &ChainPath,
    certs: &[ChainCert],
    anchored: bool,
    config: &TrustConfig,
) -> Vec<usize> {
    let mut out = Vec::new();
    for (pos, &issuer) in chain.certs.iter().enumerate().skip(1) {
        let Some(node) = certs.get(issuer) else {
            continue;
        };
        let cert = &node.cert;
        if !config
            .basic_constraints_exempt
            .iter()
            .any(|pin| pin.matches(cert))
        {
            continue;
        }
        let legacy_anchor = anchored && node.anchor.is_some() && cert.version < 3;
        let is_ca = cert.basic_constraints.map_or(legacy_anchor, |bc| bc.ca);
        // Non-self-issued intermediates below this issuer (not the leaf).
        let below = chain
            .certs
            .iter()
            .take(pos)
            .skip(1)
            .filter_map(|i| certs.get(*i))
            .filter(|c| c.cert.subject.der != c.cert.issuer.der)
            .count();
        let path_exceeded = cert
            .basic_constraints
            .and_then(|bc| bc.path_len)
            .is_some_and(|max| u32::try_from(below).unwrap_or(u32::MAX) > max);
        if !is_ca || path_exceeded {
            out.push(issuer);
        }
    }
    out
}

/// Whether `c`, the top of a full chain, is a root: self-signed, or (in an
/// anchored chain) a self-issued anchor.
fn is_root(c: &ChainCert, anchored: bool) -> bool {
    c.cert.is_self_signed
        || (anchored && c.anchor.is_some() && c.cert.subject.der == c.cert.issuer.der)
}

/// Rewrites the certificate indices in `issue` with `f`.
fn remap(issue: ChainIssue, f: &mut impl FnMut(usize) -> usize) -> ChainIssue {
    match issue {
        ChainIssue::UnhandledCriticalExtension { cert, oid } => {
            ChainIssue::UnhandledCriticalExtension { cert: f(cert), oid }
        }
        ChainIssue::IssuerNotCa { issuer } => ChainIssue::IssuerNotCa { issuer: f(issuer) },
        ChainIssue::IssuerKeyUsage { issuer } => ChainIssue::IssuerKeyUsage { issuer: f(issuer) },
        ChainIssue::PathLengthExceeded { issuer } => {
            ChainIssue::PathLengthExceeded { issuer: f(issuer) }
        }
        ChainIssue::KeyIdMismatch { child, issuer } => ChainIssue::KeyIdMismatch {
            child: f(child),
            issuer: f(issuer),
        },
        ChainIssue::SignatureInvalid { child, issuer } => ChainIssue::SignatureInvalid {
            child: f(child),
            issuer: f(issuer),
        },
        ChainIssue::SignatureUnsupported { child, issuer, why } => {
            ChainIssue::SignatureUnsupported {
                child: f(child),
                issuer: f(issuer),
                why,
            }
        }
        ChainIssue::Loop { cert } => ChainIssue::Loop { cert: f(cert) },
        other => other,
    }
}

/// Whether `path` ends at an anchor (only when `with_anchor`), and whether
/// it is complete: anchored, or ending at a self-signed certificate.
fn path_state(path: &[usize], pool: &[Node<'_>], with_anchor: bool) -> (bool, bool) {
    let top = path.last().and_then(|p| pool.get(*p));
    let anchored = with_anchor && top.is_some_and(|n| n.anchor.is_some());
    let complete = anchored || top.is_some_and(|n| n.cert.is_self_signed);
    (anchored, complete)
}

/// The sort key of a path: anchored, then complete, then permitting code
/// signing, then shorter, then earlier certificates. So when one issuer
/// key has two certificates and only one restricts its extended key usage
/// away from code signing, the chain chosen (and everything taken from it:
/// trust, the PCA, identity) is the one that may sign code.
fn path_key(
    path: &[usize],
    pool: &[Node<'_>],
    with_anchor: bool,
) -> (bool, bool, bool, usize, Vec<usize>) {
    let (anchored, complete) = path_state(path, pool, with_anchor);
    let code_signing = eku::CODE_SIGNING.id();
    let permits = path
        .iter()
        .filter_map(|p| pool.get(*p))
        .all(|n| n.cert.permits_eku(&code_signing));
    (!anchored, !complete, !permits, path.len(), path.to_vec())
}

/// Sorts paths best first (see [`path_key`]).
fn rank(mut paths: Vec<Vec<usize>>, pool: &[Node<'_>], with_anchor: bool) -> Vec<Vec<usize>> {
    paths.sort_by_cached_key(|p| path_key(p, pool, with_anchor));
    paths
}

/// Issues, deduplicated and capped.
#[derive(Default)]
struct Issues {
    list: Vec<ChainIssue>,
}

impl Issues {
    /// Adds `issue` unless it is already recorded. Past
    /// [`MAX_CHAIN_ISSUES`], per-certificate issues are replaced by one
    /// [`ChainIssue::IssuesTruncated`]. The limit markers (`TooLong`,
    /// `TooManyPaths`, `WorkLimitReached`) are always kept, because they say
    /// the search was cut short.
    fn push(&mut self, issue: ChainIssue) {
        if self.list.contains(&issue) {
            return;
        }
        let marker = matches!(
            issue,
            ChainIssue::TooLong
                | ChainIssue::TooManyPaths
                | ChainIssue::TooManyCertificates
                | ChainIssue::WorkLimitReached
        );
        if marker || self.list.len() < MAX_CHAIN_ISSUES {
            self.list.push(issue);
        } else if !self.list.contains(&ChainIssue::IssuesTruncated) {
            self.list.push(ChainIssue::IssuesTruncated);
        }
    }
}

/// The most issuer candidates examined in one search. Every step costs a
/// few comparisons at most; signature checks are bounded by budgets.
const MAX_SEARCH_STEPS: usize = 4096;

/// Whether a certificate may issue others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MayIssue {
    No,
    Yes,
    /// Only because [`TrustConfig::ignore_basic_constraints`] relaxes its
    /// basic constraints.
    Relaxed,
}

/// Which links a search may make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Only links verified downwards from an anchor, by
    /// [`Search::mark_trusted`]; only paths that end at an anchor count.
    Trusted,
    /// Any link whose signature verifies, checked as needed with the
    /// issuer's key, whoever supplied it. Paths end at self-signed
    /// certificates; anchors are not recognised.
    Untrusted,
}

struct Search<'p, 'i> {
    pool: &'p [Node<'p>],
    /// Pool indices by subject name, policy certificates first.
    by_subject: HashMap<&'p [u8], Vec<usize>>,
    /// Pool indices by issuer name.
    by_issuer: HashMap<&'p [u8], Vec<usize>>,
    /// Link verification results, by child and the issuer key's SPKI hash:
    /// a signature checked once with a key is not checked again with
    /// another certificate for the same key.
    verified: HashMap<(usize, &'p str), bool>,
    /// Certificates verified downwards from an anchor (anchors included).
    trusted: Vec<bool>,
    steps: usize,
    issues: &'i mut Issues,
    /// Whether [`TrustConfig::ignore_basic_constraints`] applies in this
    /// search. It does in the trusted search and the unanchored full-chain
    /// search, never in the as-provided one, which shows the file's own
    /// chain without policy.
    relax: bool,
    paths: Vec<Vec<usize>>,
    /// Only pool indices below this are used.
    limit: usize,
    mode: Mode,
}

impl<'p, 'i> Search<'p, 'i> {
    fn new(pool: &'p [Node<'p>], issues: &'i mut Issues) -> Self {
        let mut by_subject: HashMap<&'p [u8], Vec<usize>> = HashMap::new();
        let mut by_issuer: HashMap<&'p [u8], Vec<usize>> = HashMap::new();
        // Later pool entries first: policy anchors, then policy
        // intermediates, then embedded certificates from the last.
        for (i, node) in pool.iter().enumerate().rev() {
            by_subject
                .entry(node.cert.subject.der.as_slice())
                .or_default()
                .push(i);
        }
        for (i, node) in pool.iter().enumerate().rev() {
            by_issuer
                .entry(node.cert.issuer.der.as_slice())
                .or_default()
                .push(i);
        }
        Self {
            pool,
            by_subject,
            by_issuer,
            verified: HashMap::new(),
            trusted: vec![false; pool.len()],
            steps: 0,
            issues,
            relax: true,
            paths: Vec::new(),
            limit: pool.len(),
            mode: Mode::Untrusted,
        }
    }

    /// Whether `node` may be in a path at all. A certificate with a
    /// critical extension this crate does not process may not, unless it
    /// is a configured anchor in a trusted search.
    fn usable(&mut self, node: usize) -> bool {
        let Some(n) = self.pool.get(node) else {
            return false;
        };
        if self.mode == Mode::Trusted && n.anchor.is_some() {
            return true;
        }
        let mut ok = true;
        for oid in &n.cert.unhandled_critical_extensions {
            self.issues.push(ChainIssue::UnhandledCriticalExtension {
                cert: node,
                oid: oid.clone(),
            });
            ok = false;
        }
        ok
    }

    /// Whether `issuer` may issue certificates: usable, a CA, and allowed
    /// `keyCertSign` by its key usage. A v1 or v2 certificate has no
    /// extensions to say it is a CA; it is taken as one only when it is a
    /// configured anchor in a trusted search.
    ///
    /// A certificate [`TrustConfig::ignore_basic_constraints`] names may
    /// issue without being a CA; the answer is then [`MayIssue::Relaxed`].
    fn may_issue(&mut self, issuer: usize) -> MayIssue {
        if !self.usable(issuer) {
            return MayIssue::No;
        }
        let Some(node) = self.pool.get(issuer) else {
            return MayIssue::No;
        };
        let i = node.cert;
        let legacy_anchor = self.mode == Mode::Trusted && node.anchor.is_some() && i.version < 3;
        let is_ca = match i.basic_constraints {
            Some(bc) => bc.ca,
            None => legacy_anchor,
        };
        let answer = match (is_ca, node.bc_exempt && self.relax) {
            (true, _) => MayIssue::Yes,
            (false, true) => MayIssue::Relaxed,
            (false, false) => {
                self.issues.push(ChainIssue::IssuerNotCa { issuer });
                return MayIssue::No;
            }
        };
        if i.key_usage
            .is_some_and(|ku| !ku.contains(KeyUsage::KEY_CERT_SIGN))
        {
            self.issues.push(ChainIssue::IssuerKeyUsage { issuer });
            return MayIssue::No;
        }
        answer
    }

    /// Whether the key identifiers of `child` and `issuer` agree (or one is
    /// absent).
    fn key_ids_agree(&mut self, child: usize, issuer: usize) -> bool {
        let (Some(c), Some(i)) = (self.pool.get(child), self.pool.get(issuer)) else {
            return false;
        };
        match (&c.cert.authority_key_id, &i.cert.subject_key_id) {
            (Some(aki), Some(ski)) if aki != ski => {
                self.issues
                    .push(ChainIssue::KeyIdMismatch { child, issuer });
                false
            }
            _ => true,
        }
    }

    /// Verifies `child`'s signature with `issuer`'s key, once per key,
    /// charging `budget`.
    fn check(&mut self, child: usize, issuer: usize, budget: &mut Budget) -> bool {
        let (Some(c), Some(i)) = (self.pool.get(child), self.pool.get(issuer)) else {
            return false;
        };
        let key = (child, i.cert.spki_sha256.as_str());
        if let Some(ok) = self.verified.get(&key) {
            return *ok;
        }
        if !budget.take() {
            return false;
        }
        let ok = match verify_link(c.cert, i.cert) {
            Verified::Valid => true,
            Verified::Invalid => {
                self.issues
                    .push(ChainIssue::SignatureInvalid { child, issuer });
                false
            }
            Verified::Unsupported(why) => {
                self.issues
                    .push(ChainIssue::SignatureUnsupported { child, issuer, why });
                false
            }
        };
        self.verified.insert(key, ok);
        ok
    }

    /// The pool nodes a path from `leaf` could use: those reached upwards
    /// from it by issuer name, within [`MAX_CHAIN_LENGTH`] certificates.
    /// No signature is checked; this only keeps the trust walk away from
    /// certificates that cannot be on the leaf's chain.
    fn reachable_from(&self, leaf: usize) -> Vec<bool> {
        let mut seen = vec![false; self.pool.len()];
        let mut frontier = vec![leaf];
        if let Some(s) = seen.get_mut(leaf) {
            *s = true;
        }
        for _ in 1..MAX_CHAIN_LENGTH {
            let mut next = Vec::new();
            for n in frontier {
                let Some(node) = self.pool.get(n) else {
                    continue;
                };
                for &i in self
                    .by_subject
                    .get(node.cert.issuer.der.as_slice())
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                {
                    if let Some(s) = seen.get_mut(i) {
                        if !*s {
                            *s = true;
                            next.push(i);
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        seen
    }

    /// Verifies downwards from the anchors: every certificate that could be
    /// on the leaf's chain and whose issuer name is a trusted certificate's
    /// subject is checked with that trusted key, breadth first, at most
    /// [`MAX_CHAIN_LENGTH`] deep. Every check uses a key from an anchor or
    /// from a certificate an anchor vouched for, never a key someone added
    /// to the file.
    ///
    /// Links into the leaf and into policy certificates are checked on
    /// `policy_budget` and their own [`MAX_SEARCH_STEPS`] candidate steps;
    /// links into other embedded certificates, which anyone can add, on
    /// `embedded_budget` and a separate step count. So added certificates
    /// cannot spend the steps or checks that the leaf's own link and
    /// policy-supplied chains need.
    fn mark_trusted(
        &mut self,
        leaf: usize,
        policy_budget: &mut Budget,
        embedded_budget: &mut Budget,
    ) {
        self.mode = Mode::Trusted;
        self.limit = self.pool.len();
        let reachable = self.reachable_from(leaf);
        let on_chain = |i: usize| reachable.get(i).copied().unwrap_or(false);
        let mut depth = vec![0_usize; self.pool.len()];
        let mut queue = VecDeque::new();
        for (i, node) in self.pool.iter().enumerate() {
            if node.anchor.is_some() && on_chain(i) {
                if let (Some(t), Some(d)) = (self.trusted.get_mut(i), depth.get_mut(i)) {
                    *t = true;
                    *d = 1;
                }
                queue.push_back(i);
            }
        }
        // Candidate steps, in the same two pools as the checks: added
        // certificates never spend the leaf's or policy certificates' steps.
        let mut policy_steps = 0_usize;
        let mut embedded_steps = 0_usize;
        while let Some(t) = queue.pop_front() {
            let (Some(node), Some(&d)) = (self.pool.get(t), depth.get(t)) else {
                continue;
            };
            if d >= MAX_CHAIN_LENGTH {
                continue;
            }
            // The leaf and policy certificates first, then embedded ones.
            let mut children: Vec<usize> = self
                .by_issuer
                .get(node.cert.subject.der.as_slice())
                .map(|v| {
                    v.iter()
                        .copied()
                        // Anchors are trusted already and end every
                        // trusted path, so they are never checked as
                        // children (two re-keyed roots sharing a name).
                        .filter(|c| *c != t && on_chain(*c))
                        .filter(|c| self.pool.get(*c).is_some_and(|n| n.anchor.is_none()))
                        .collect()
                })
                .unwrap_or_default();
            children.sort_by_key(|c| (!self.privileged(*c, leaf), *c));
            if children.is_empty() {
                continue;
            }
            if self.may_issue(t) == MayIssue::No {
                continue;
            }
            for c in children {
                let privileged = self.privileged(c, leaf);
                let (steps, budget) = if privileged {
                    (&mut policy_steps, &mut *policy_budget)
                } else {
                    (&mut embedded_steps, &mut *embedded_budget)
                };
                if *steps >= MAX_SEARCH_STEPS {
                    budget.exhausted = true;
                    if privileged {
                        return;
                    }
                    // Children are sorted privileged first, so the rest of
                    // this list is embedded too.
                    break;
                }
                *steps += 1;
                if !self.key_ids_agree(c, t) || !self.usable(c) {
                    continue;
                }
                let ok = self.check(c, t, budget);
                let newly = !self.trusted.get(c).copied().unwrap_or(true);
                if ok && newly {
                    if let (Some(tc), Some(dc)) = (self.trusted.get_mut(c), depth.get_mut(c)) {
                        *tc = true;
                        *dc = d + 1;
                    }
                    queue.push_back(c);
                }
            }
        }
    }

    /// Whether `node` is the leaf or a policy certificate, whose links are
    /// checked on the budget added certificates cannot spend.
    fn privileged(&self, node: usize, leaf: usize) -> bool {
        node == leaf || self.pool.get(node).is_some_and(|n| n.from_policy)
    }

    /// The best maximal paths from `leaf` over pool indices below `limit`.
    fn run(
        &mut self,
        leaf: usize,
        limit: usize,
        mode: Mode,
        budget: &mut Budget,
    ) -> Vec<Vec<usize>> {
        self.limit = limit;
        self.mode = mode;
        self.paths.clear();
        self.steps = 0;
        let mut path = vec![leaf];
        if self.usable(leaf) {
            self.extend(&mut path, budget);
        }
        std::mem::take(&mut self.paths)
    }

    /// Keeps `path` if it is among the best [`MAX_CHAIN_PATHS`] so far.
    /// Over the cap, the worst path is dropped, so a dead end can never
    /// displace an anchored or complete path.
    fn record(&mut self, path: &[usize]) {
        let anchored = self.mode == Mode::Trusted;
        if anchored
            && !path
                .last()
                .and_then(|t| self.pool.get(*t))
                .is_some_and(|n| n.anchor.is_some())
        {
            return;
        }
        let key = |p: &[usize]| path_key(p, self.pool, anchored);
        if self.paths.len() < MAX_CHAIN_PATHS {
            self.paths.push(path.to_vec());
            return;
        }
        self.issues.push(ChainIssue::TooManyPaths);
        let worst = self
            .paths
            .iter()
            .enumerate()
            .max_by_key(|(_, p)| key(p))
            .map(|(i, p)| (i, key(p)));
        if let Some((i, worst_key)) = worst {
            if key(path) < worst_key {
                if let Some(slot) = self.paths.get_mut(i) {
                    *slot = path.to_vec();
                }
            }
        }
    }

    fn extend(&mut self, path: &mut Vec<usize>, budget: &mut Budget) {
        let Some(&top) = path.last() else {
            return;
        };
        let Some(node) = self.pool.get(top) else {
            return;
        };
        let stop = match self.mode {
            Mode::Trusted => node.anchor.is_some(),
            Mode::Untrusted => node.cert.is_self_signed,
        };
        if stop {
            self.record(path);
            return;
        }
        let trusted_only = self.mode == Mode::Trusted;
        let candidates: Vec<usize> = self
            .by_subject
            .get(node.cert.issuer.der.as_slice())
            .map(|v| {
                v.iter()
                    .copied()
                    // A self-issued certificate names itself as issuer; it
                    // is not its own issuer candidate.
                    .filter(|c| *c != top && *c < self.limit)
                    .filter(|c| !trusted_only || self.trusted.get(*c).copied().unwrap_or(false))
                    .collect()
            })
            .unwrap_or_default();
        let mut extended = false;
        for issuer in candidates {
            if self.steps >= MAX_SEARCH_STEPS {
                budget.exhausted = true;
                break;
            }
            self.steps += 1;
            if path.contains(&issuer) {
                self.issues.push(ChainIssue::Loop { cert: issuer });
                continue;
            }
            if path.len() >= MAX_CHAIN_LENGTH {
                // The path is recorded as it is, incomplete.
                self.issues.push(ChainIssue::TooLong);
                continue;
            }
            if !self.link(path, issuer, budget) {
                continue;
            }
            extended = true;
            path.push(issuer);
            self.extend(path, budget);
            path.pop();
        }
        if !extended {
            self.record(path);
        }
    }

    /// Whether `issuer` issued the top of `path`, with every constraint
    /// that applies to it. Anchors are held to the same CA, key usage and
    /// path length rules when they issue a certificate. A trusted search
    /// makes no new signature checks: it uses only links
    /// [`Self::mark_trusted`] verified.
    fn link(&mut self, path: &[usize], issuer: usize, budget: &mut Budget) -> bool {
        let Some(&child) = path.last() else {
            return false;
        };
        if !self.key_ids_agree(child, issuer) {
            return false;
        }
        if self.may_issue(issuer) == MayIssue::No {
            return false;
        }
        if let Some(max) = self
            .pool
            .get(issuer)
            .and_then(|n| n.cert.basic_constraints)
            .and_then(|b| b.path_len)
        {
            // Non-self-issued intermediates below this issuer (the leaf
            // does not count).
            let below = path
                .iter()
                .skip(1)
                .filter_map(|p| self.pool.get(*p))
                .filter(|n| n.cert.subject.der != n.cert.issuer.der)
                .count();
            let exempt = self.relax && self.pool.get(issuer).is_some_and(|n| n.bc_exempt);
            if u32::try_from(below).unwrap_or(u32::MAX) > max && !exempt {
                self.issues.push(ChainIssue::PathLengthExceeded { issuer });
                return false;
            }
        }
        match self.mode {
            Mode::Trusted => {
                let Some(i) = self.pool.get(issuer) else {
                    return false;
                };
                self.verified
                    .get(&(child, i.cert.spki_sha256.as_str()))
                    .copied()
                    .unwrap_or(false)
            }
            Mode::Untrusted => self.check(child, issuer, budget),
        }
    }
}

/// Verifies `child`'s signature with `issuer`'s key. Weak digests (MD2,
/// MD5) are never accepted.
fn verify_link(child: &CertSummary, issuer: &CertSummary) -> Verified {
    if let Some(d) = x509::signature_digest(&child.sig_alg).filter(|d| d.is_broken()) {
        return Verified::Unsupported(Unsupported::WeakAlgorithm(d));
    }
    let (Ok(c), Ok(i)) = (x509::split(&child.der), x509::split(&issuer.der)) else {
        return Verified::Invalid;
    };
    x509::check_signed_by(&c, &child.sig_alg, &i, &issuer.public_key_alg)
}
