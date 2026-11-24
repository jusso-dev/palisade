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
//! The search enumerates every path, detects loops and stops at
//! [`MAX_CHAIN_LENGTH`] certificates. Policy certificates are tried before
//! embedded ones, and anchored or complete paths always displace dead ends,
//! so certificates added to a file cannot crowd out its trusted chain. The
//! best [`MAX_CHAIN_PATHS`] paths are kept: anchored before unanchored,
//! complete before incomplete, then the shortest. The others are reported
//! as alternatives, which is how cross-signed paths show up. At
//! most [`MAX_SIGNATURE_CHECKS`] certificate signatures (links, and the
//! self-signatures of self-issued certificates) are verified per build, and
//! [`MAX_FILE_SIGNATURE_CHECKS`] per file, so hostile certificate sets
//! cannot make it slow. Running out fails closed: links not checked are not
//! made, and a certificate whose self-signature was not checked is not
//! self-signed, so the chain is only shorter, never trusted wrongly.
//!
//! Not checked here: validity periods, timestamps and revocation (#50), and
//! the OS trust store (the `os-trust` cross-check in #48).

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

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
/// The most certificate signatures (links and self-signatures) verified
/// per chain build.
pub const MAX_SIGNATURE_CHECKS: usize = 128;
/// The most certificate signatures verified for all the signatures of one
/// file, by [`super::evaluate_trust`].
pub const MAX_FILE_SIGNATURE_CHECKS: usize = 512;
/// The most per-certificate issues recorded per chain build. The limit
/// markers ([`ChainIssue::TooLong`], [`ChainIssue::TooManyPaths`],
/// [`ChainIssue::WorkLimitReached`] and [`ChainIssue::IssuesTruncated`]) are
/// kept beyond it, at most once each, so a report holds at most
/// `MAX_CHAIN_ISSUES + 4` issues.
pub const MAX_CHAIN_ISSUES: usize = 32;

/// A trust anchor from the policy-shipped bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustAnchor {
    /// A name for reports, from the bundle.
    pub label: String,
    /// The anchor certificate.
    pub cert: CertSummary,
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
    well_known_roots: Vec<WellKnownRoot>,
}

impl TrustConfig {
    /// An empty configuration: no anchors, so nothing is trusted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a trust anchor certificate. Returns its index.
    pub fn add_anchor(
        &mut self,
        label: impl Into<String>,
        der: &[u8],
    ) -> Result<usize, CertificateError> {
        let cert = CertSummary::from_der(der)?;
        self.anchors.push(TrustAnchor {
            label: label.into(),
            cert,
        });
        Ok(self.anchors.len() - 1)
    }

    /// Adds an intermediate certificate that chains may use but that is not
    /// trusted by itself. Returns its index.
    pub fn add_intermediate(&mut self, der: &[u8]) -> Result<usize, CertificateError> {
        self.intermediates.push(CertSummary::from_der(der)?);
        Ok(self.intermediates.len() - 1)
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
    /// A [`TrustConfig`] intermediate, by index.
    PolicyIntermediate(usize),
    /// A [`TrustConfig`] anchor, by index.
    PolicyAnchor(usize),
}

/// Where the anchor a chain reaches came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AnchorSource {
    /// A [`TrustConfig`] anchor from policy.
    Policy,
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
    /// Other full paths, best first.
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
    /// algorithm in `allowed`. A self-signed root's own signature is not
    /// counted: nothing relies on it.
    #[must_use]
    pub fn cert_sig_algs_allowed(&self, allowed: &[SignatureAlgorithm]) -> bool {
        self.full_chain_certs()
            .filter(|c| !c.is_self_signed)
            .all(|c| allowed.contains(&c.sig_alg))
    }
}

/// A certificate the search may use.
struct Node<'a> {
    cert: &'a CertSummary,
    origin: CertOrigin,
    anchor: Option<usize>,
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

/// [`build_chain`], verifying at most [`MAX_SIGNATURE_CHECKS`] certificate
/// signatures, and no more than `budget` has left. `budget` is charged for
/// every verification.
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
    let mut budget = Budget::new(file_budget.left().min(MAX_SIGNATURE_CHECKS));
    let parsed = x509::parse_within(leaf_der, &mut budget);
    file_budget.absorb(&budget);
    let leaf_summary = parsed?;
    let mut embedded: Vec<(usize, CertSummary)> = vec![(signer, leaf_summary)];
    for (i, der) in certs.iter().enumerate() {
        if i == signer {
            continue;
        }
        match x509::parse_within(der, &mut budget) {
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
    let mut pool: Vec<Node<'_>> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for (i, cert) in &embedded {
        if seen.insert(cert.sha256_thumbprint.as_str()) {
            pool.push(Node {
                cert,
                origin: CertOrigin::Embedded(*i),
                anchor: anchor_of(cert),
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
            });
        }
    }
    for (i, anchor) in config.anchors.iter().enumerate() {
        if seen.insert(anchor.cert.sha256_thumbprint.as_str()) {
            pool.push(Node {
                cert: &anchor.cert,
                origin: CertOrigin::PolicyAnchor(i),
                anchor: Some(i),
            });
        }
    }
    // The signer is pool node 0, and so report certificate 0.
    let leaf = 0;

    let mut search = Search::new(&pool, &mut issues, budget);
    let provided_paths = search.run(leaf, embedded_count, false);
    let full_paths = search.run(leaf, pool.len(), true);
    let budget = search.budget;
    drop(search);
    file_budget.absorb(&budget);
    if budget.exhausted {
        issues.push(ChainIssue::WorkLimitReached);
    }

    let trivial = || vec![leaf];
    let provided = rank(provided_paths, &pool, false);
    let full = rank(full_paths, &pool, true);

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
    let full_chain = to_path(&full_iter.next().unwrap_or_else(trivial), &mut out, true);
    let alternatives: Vec<ChainPath> = full_iter.map(|p| to_path(&p, &mut out, true)).collect();
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
    let root_as_provided = embedded_prefix
        .last()
        .copied()
        .filter(|t| prefix_is_whole && out.get(*t).is_some_and(|c| c.cert.is_self_signed));
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
        .filter(|c| full_chain.complete && (c.cert.is_self_signed || c.anchor.is_some()))
        .and_then(|c| config.well_known_root_id(&c.cert));

    Ok(ChainReport {
        leaf,
        pca,
        root_as_provided,
        intermediates,
        chain_complete: full_chain.complete,
        anchor_source: if anchored_to.is_some() {
            AnchorSource::Policy
        } else {
            AnchorSource::None
        },
        anchored_to,
        well_known_root_id,
        as_provided,
        as_provided_alternatives,
        full_chain,
        alternatives,
        issues: issue_list,
        certificates: out,
    })
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

/// The sort key of a path: anchored, then complete, then shorter, then
/// earlier certificates.
fn path_key(
    path: &[usize],
    pool: &[Node<'_>],
    with_anchor: bool,
) -> (bool, bool, usize, Vec<usize>) {
    let (anchored, complete) = path_state(path, pool, with_anchor);
    (!anchored, !complete, path.len(), path.to_vec())
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
            ChainIssue::TooLong | ChainIssue::TooManyPaths | ChainIssue::WorkLimitReached
        );
        if marker || self.list.len() < MAX_CHAIN_ISSUES {
            self.list.push(issue);
        } else if !self.list.contains(&ChainIssue::IssuesTruncated) {
            self.list.push(ChainIssue::IssuesTruncated);
        }
    }
}

/// The most issuer candidates examined in one search. Every step costs a
/// few comparisons at most; signature checks are bounded by the budget.
const MAX_SEARCH_STEPS: usize = 4096;

struct Search<'p, 'i> {
    pool: &'p [Node<'p>],
    by_subject: HashMap<&'p [u8], Vec<usize>>,
    /// Link verification results, by (child, issuer).
    verified: HashMap<(usize, usize), bool>,
    budget: Budget,
    steps: usize,
    issues: &'i mut Issues,
    paths: Vec<Vec<usize>>,
    /// Only pool indices below this are used.
    limit: usize,
    anchors: bool,
}

impl<'p, 'i> Search<'p, 'i> {
    fn new(pool: &'p [Node<'p>], issues: &'i mut Issues, budget: Budget) -> Self {
        let mut by_subject: HashMap<&'p [u8], Vec<usize>> = HashMap::new();
        // Later pool entries first: policy anchors, then policy
        // intermediates, then embedded certificates from the last.
        for (i, node) in pool.iter().enumerate().rev() {
            by_subject
                .entry(node.cert.subject.der.as_slice())
                .or_default()
                .push(i);
        }
        Self {
            pool,
            by_subject,
            verified: HashMap::new(),
            budget,
            steps: 0,
            issues,
            paths: Vec::new(),
            limit: 0,
            anchors: false,
        }
    }

    /// Whether `node` may be in a path at all. A certificate with a
    /// critical extension this crate does not process may not, unless it
    /// is a configured anchor and anchors are in use.
    fn usable(&mut self, node: usize) -> bool {
        let Some(n) = self.pool.get(node) else {
            return false;
        };
        if self.anchors && n.anchor.is_some() {
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

    /// The best maximal paths from `leaf` over pool indices below `limit`.
    fn run(&mut self, leaf: usize, limit: usize, anchors: bool) -> Vec<Vec<usize>> {
        self.limit = limit;
        self.anchors = anchors;
        self.paths.clear();
        self.steps = 0;
        let mut path = vec![leaf];
        if self.usable(leaf) {
            self.extend(&mut path);
        }
        std::mem::take(&mut self.paths)
    }

    /// Keeps `path` if it is among the best [`MAX_CHAIN_PATHS`] so far.
    /// Over the cap, the worst path is dropped, so a dead end can never
    /// displace an anchored or complete path.
    fn record(&mut self, path: &[usize]) {
        let key = |p: &[usize]| path_key(p, self.pool, self.anchors);
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

    fn extend(&mut self, path: &mut Vec<usize>) {
        let Some(&top) = path.last() else {
            return;
        };
        let Some(node) = self.pool.get(top) else {
            return;
        };
        if (self.anchors && node.anchor.is_some()) || node.cert.is_self_signed {
            self.record(path);
            return;
        }
        let candidates: Vec<usize> = self
            .by_subject
            .get(node.cert.issuer.der.as_slice())
            .map(|v| v.iter().copied().filter(|c| *c < self.limit).collect())
            .unwrap_or_default();
        let mut extended = false;
        for issuer in candidates {
            if self.steps >= MAX_SEARCH_STEPS {
                self.budget.exhausted = true;
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
            if !self.link(path, issuer) {
                continue;
            }
            extended = true;
            path.push(issuer);
            self.extend(path);
            path.pop();
        }
        if !extended {
            self.record(path);
        }
    }

    /// Whether `issuer` issued the top of `path`, with every constraint
    /// that applies to it. Anchors are held to the same CA, key usage and
    /// path length rules when they issue a certificate.
    fn link(&mut self, path: &[usize], issuer: usize) -> bool {
        let (Some(&child), Some(issuer_node)) = (path.last(), self.pool.get(issuer)) else {
            return false;
        };
        let Some(child_node) = self.pool.get(child) else {
            return false;
        };
        let (c, i) = (child_node.cert, issuer_node.cert);
        if let (Some(aki), Some(ski)) = (&c.authority_key_id, &i.subject_key_id) {
            if aki != ski {
                self.issues
                    .push(ChainIssue::KeyIdMismatch { child, issuer });
                return false;
            }
        }
        if !self.usable(issuer) {
            return false;
        }
        // A v1 or v2 certificate has no extensions to say it is a CA; it is
        // accepted as one only when it is a configured anchor.
        let legacy_anchor = self.anchors && issuer_node.anchor.is_some() && i.version < 3;
        let is_ca = match i.basic_constraints {
            Some(bc) => bc.ca,
            None => legacy_anchor,
        };
        if !is_ca {
            self.issues.push(ChainIssue::IssuerNotCa { issuer });
            return false;
        }
        if i.key_usage
            .is_some_and(|ku| !ku.contains(KeyUsage::KEY_CERT_SIGN))
        {
            self.issues.push(ChainIssue::IssuerKeyUsage { issuer });
            return false;
        }
        if let Some(max) = i.basic_constraints.and_then(|b| b.path_len) {
            // Non-self-issued intermediates below this issuer (the leaf
            // does not count).
            let below = path
                .iter()
                .skip(1)
                .filter_map(|p| self.pool.get(*p))
                .filter(|n| n.cert.subject.der != n.cert.issuer.der)
                .count();
            if u32::try_from(below).unwrap_or(u32::MAX) > max {
                self.issues.push(ChainIssue::PathLengthExceeded { issuer });
                return false;
            }
        }
        if let Some(ok) = self.verified.get(&(child, issuer)) {
            return *ok;
        }
        if !self.budget.take() {
            return false;
        }
        let ok = match verify_link(c, i) {
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
        self.verified.insert((child, issuer), ok);
        ok
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
