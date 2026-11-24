//! Signer trust and identity (#49): chains for every signature, the
//! trust-aware primary signature, and the identity strings publisher rules
//! match on.
//!
//! A [`SignatureStatus::Valid`] signature is sound and signs the file, but
//! anyone can sign a file, and anyone can append a nested signature to a
//! signed file. So [`evaluate_trust`] builds each valid signature's chain
//! against a [`TrustConfig`], and chooses the primary signature only among
//! the **trusted** ones. An untrusted signer, nested or not, never becomes
//! primary, and only a trusted primary yields a [`SignerIdentity`].
//!
//! "Trusted" here means: the signature is valid, its signer certificate
//! chains to a configured anchor, every certificate in that chain permits
//! code signing, and the signer's key usage (if restricted) allows digital
//! signatures. Validity periods, timestamps and revocation are not checked
//! yet (#50), and the OS trust store is not consulted (the `os-trust`
//! cross-check in #48).
//!
//! Everything here is plain data. Policy (#31) matches on it without
//! depending on this crate's internals.

#![forbid(unsafe_code)]

use serde::Serialize;

use super::chain::{ChainReport, MAX_FILE_SIGNATURE_CHECKS, TrustConfig, build_chain_within};
use super::signature::{
    DigestAlgorithm, KeyAlgorithm, SignatureInfo, SignatureReport, SignatureStatus,
};
use super::x509::Budget;
use super::x509::{AttributeKind, CertSummary, CertificateError, KeyUsage};
use crate::pe::version::{FileVersionQuad, VersionField, VersionInfo};

/// Why a signature is not trusted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UntrustedReason {
    /// The signature is not [`SignatureStatus::Valid`].
    NotValid,
    /// The signer certificate could not be parsed, so no chain was built.
    SignerCertificate(CertificateError),
    /// The chain reaches no configured trust anchor.
    NoTrustAnchor,
    /// A certificate in the chain restricts its extended key usage to
    /// purposes other than code signing.
    CodeSigningNotPermitted,
    /// The signer certificate's key usage does not include
    /// `digitalSignature`.
    SignerKeyUsage,
}

/// One signature's chain and trust verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignerTrust {
    /// The signature: an index into [`SignatureReport::signatures`].
    pub signature: usize,
    /// The chains of its signer certificate. `None` when the signature has
    /// no usable signer (not valid, or its certificate did not parse).
    pub chain: Option<ChainReport>,
    /// Whether the signer is trusted: [`Self::untrusted`] is empty.
    pub trusted: bool,
    /// Why it is not trusted.
    pub untrusted: Vec<UntrustedReason>,
    /// The signature's image digest algorithm.
    pub digest_alg: Option<DigestAlgorithm>,
    /// The SignerInfo's digest algorithm. Primary selection ranks a
    /// signature by the weaker of the two.
    pub signer_digest_alg: Option<DigestAlgorithm>,
    /// Whether an OS-native code integrity signer rule can use this signer:
    /// the signature itself is compatible
    /// ([`SignatureInfo::os_ci_compatible`]), and every certificate in the
    /// full chain has an RSA key of at most 4096 bits. Conservative: a
    /// `false` only means a rule must fall back to a hash level.
    pub os_ci_compatible: bool,
}

impl SignerTrust {
    /// Whether every key in the full chain is at least this long (see
    /// [`ChainReport::meets_min_key_bits`]). `false` without a chain.
    #[must_use]
    pub fn meets_min_key_bits(&self, min_rsa_bits: u32, min_ec_bits: u32) -> bool {
        self.chain
            .as_ref()
            .is_some_and(|c| c.meets_min_key_bits(min_rsa_bits, min_ec_bits))
    }
}

/// How [`PublisherName`] was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    /// The leaf subject's `CN`.
    CommonName,
    /// The leaf subject's `O`, because it has no `CN`.
    Organization,
}

/// The publisher name rules match on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PublisherName {
    /// The name.
    pub value: String,
    /// Which attribute it came from.
    pub source: NameSource,
}

/// The root part of an OS-native Publisher rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OsRuleRoot {
    /// The chain's root is an OS-vendor well-known root, named by its ID.
    WellKnown(u8),
    /// The TBS hash of the PCA certificate (lowercase hex, under its own
    /// signature digest).
    PcaTbsHash(String),
}

/// The OS "Publisher" level: a root (PCA TBS hash or well-known root) and
/// the leaf `CN`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PublisherOsRule {
    /// The root part.
    pub root: OsRuleRoot,
    /// The leaf subject's `CN`.
    pub leaf_cn: String,
}

/// The OS "FilePublisher" level: Publisher, the file name and a minimum
/// version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FilePublisherOsRule {
    /// The Publisher level.
    pub publisher: PublisherOsRule,
    /// The file name from the version resource's fallback chain
    /// ([`VersionInfo::effective_file_name`]).
    pub file_name: String,
    /// The field the file name came from. Serialised as its OS event
    /// name, such as `"OriginalFileName"`.
    #[serde(serialize_with = "serialize_field")]
    pub file_name_field: VersionField,
    /// The file's version, the lowest a rule made from this file allows.
    /// Serialised as `"major.minor.build.revision"`.
    #[serde(serialize_with = "serialize_version")]
    pub min_version: FileVersionQuad,
}

fn serialize_field<S: serde::Serializer>(field: &VersionField, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(field.event_name())
}

fn serialize_version<S: serde::Serializer>(v: &FileVersionQuad, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(v)
}

/// Something that limits which publisher rules can be made for a signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityIssue {
    /// The leaf subject's `CN` (or, with no `CN`, its `O`) is not an exact
    /// decoding, is empty or only whitespace, or holds a control
    /// character, so it is not used as a name.
    UnusableName,
    /// A leaf subject attribute is not an exact, control-free decoding, so
    /// no `publisher_dn` is given.
    UnusableDn,
    /// The leaf subject has more than one `CN`; the first is used.
    MultipleCommonNames,
    /// The leaf subject has neither `CN` nor `O`.
    NoName,
    /// The leaf subject has no usable `CN` (the publisher name came from
    /// `O`), so the OS Publisher and FilePublisher levels, which need the
    /// leaf `CN`, cannot be made.
    NoCommonName,
    /// The file carries no intermediate, so there is no PCA, and the root
    /// is not a well-known root: Publisher-level OS rules cannot be made.
    NoPca,
    /// The PCA's signature digest has no TBS hash form (not SHA-1 or
    /// SHA-2).
    NoPcaTbsHash,
    /// The version resource has no `ProductName`.
    NoProductName,
    /// The version resource has no usable file name or version.
    NoFileNameOrVersion,
}

/// The identity of a trusted signer, as publisher rules use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignerIdentity {
    /// The signature it comes from.
    pub signature: usize,
    /// The leaf `CN`, or `O` when there is no `CN`.
    pub publisher_name: Option<PublisherName>,
    /// The full canonical subject DN of the leaf. `None` when any subject
    /// attribute is not an exact, control-free decoding (see
    /// [`super::NameAttribute::lossy`]), because such a DN could match a
    /// pattern meant for another name.
    pub publisher_dn: Option<String>,
    /// The product name from the version resource (`ProductName`).
    pub product_name: Option<String>,
    /// `(publisher_name, product_name)`: both present, for publisher plus
    /// product rules (ISM-1471).
    pub publisher_product: Option<(String, String)>,
    /// The OS "Publisher" level.
    pub publisher_os_rule: Option<PublisherOsRule>,
    /// The OS "FilePublisher" level.
    pub file_publisher_os_rule: Option<FilePublisherOsRule>,
    /// What limits the rules above.
    pub issues: Vec<IdentityIssue>,
}

/// The vendor a file claims, unverified: the version resource's
/// `CompanyName`. Only for display, discovery grouping and warnings about
/// unverified vendors. It is a separate type from [`SignerIdentity`] so it
/// can never satisfy a publisher rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VendorHint {
    /// The claimed company name, as stored.
    pub company_name: String,
    /// Always `true`.
    pub unverified: bool,
}

/// The trust verdict on a file's signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustReport {
    /// One entry per signature, in [`SignatureReport::signatures`] order.
    pub signers: Vec<SignerTrust>,
    /// The primary signature, chosen after trust: the first trusted
    /// signature with the strongest digest (SHA-2 beats SHA-1). `None` if
    /// no signature is trusted. An index into
    /// [`SignatureReport::signatures`].
    pub primary: Option<usize>,
    /// The identity of the primary signer.
    pub identity: Option<SignerIdentity>,
    /// When no signature is trusted: the `CompanyName` the file claims,
    /// marked unverified.
    pub vendor_hint: Option<VendorHint>,
}

impl TrustReport {
    /// The primary signer's trust entry.
    #[must_use]
    pub fn primary_signer(&self) -> Option<&SignerTrust> {
        self.primary.and_then(|i| self.signers.get(i))
    }
}

/// Builds the chain of every valid signature in `report`, decides which are
/// trusted under `config`, and chooses the primary signature among the
/// trusted ones. `version` is the file's version resource
/// ([`crate::pe::PeInfo::version_info`]), for the product and file names.
#[must_use]
pub fn evaluate_trust(
    report: &SignatureReport,
    config: &TrustConfig,
    version: Option<&VersionInfo>,
) -> TrustReport {
    let mut budget = Budget::new(MAX_FILE_SIGNATURE_CHECKS);
    let signers: Vec<SignerTrust> = report
        .signatures
        .iter()
        .map(|sig| signer_trust(sig, config, &mut budget))
        .collect();
    let primary = select_primary(&signers);
    let identity = primary.and_then(|p| {
        let chain = signers.get(p)?.chain.as_ref()?;
        Some(identity(p, chain, version))
    });
    let vendor_hint = match primary {
        Some(_) => None,
        None => version
            .and_then(|v| v.get(VersionField::CompanyName))
            .filter(|name| !name.trim().is_empty())
            .map(|name| VendorHint {
                company_name: name.to_owned(),
                unverified: true,
            }),
    };
    TrustReport {
        signers,
        primary,
        identity,
        vendor_hint,
    }
}

fn signer_trust(sig: &SignatureInfo, config: &TrustConfig, budget: &mut Budget) -> SignerTrust {
    let mut untrusted = Vec::new();
    // Only a valid signature's signer is looked at. `signer` is also set
    // for a tolerated digest mismatch, which is never trusted.
    let signer = match (&sig.status, &sig.signer) {
        (SignatureStatus::Valid, Some(attrs)) if !sig.untrusted_signer_attrs => {
            Some(attrs.signer_cert)
        }
        _ => None,
    };
    let chain = match signer {
        Some(index) => match build_chain_within(&sig.certs_in_blob, index, config, budget) {
            Ok(chain) => Some(chain),
            Err(e) => {
                untrusted.push(UntrustedReason::SignerCertificate(e));
                None
            }
        },
        None => {
            untrusted.push(UntrustedReason::NotValid);
            None
        }
    };
    if let Some(chain) = &chain {
        if !chain.full_chain.anchored {
            untrusted.push(UntrustedReason::NoTrustAnchor);
        }
        if !chain.permits_code_signing() {
            untrusted.push(UntrustedReason::CodeSigningNotPermitted);
        }
        let leaf_ku = chain.leaf_cert().and_then(|c| c.key_usage);
        if leaf_ku.is_some_and(|ku| !ku.contains(KeyUsage::DIGITAL_SIGNATURE)) {
            untrusted.push(UntrustedReason::SignerKeyUsage);
        }
    }
    let os_ci_compatible = sig.os_ci_compatible()
        && chain.as_ref().is_some_and(|c| {
            c.full_chain_certs().all(|cert| {
                matches!(
                    (&cert.public_key_alg, cert.key_bits),
                    (KeyAlgorithm::Rsa, Some(bits)) if bits <= 4096
                )
            })
        });
    SignerTrust {
        signature: sig.index,
        trusted: untrusted.is_empty(),
        untrusted,
        chain,
        digest_alg: sig.digest_alg,
        signer_digest_alg: sig.signer_digest_alg,
        os_ci_compatible,
    }
}

/// The first trusted signature with the strongest digest, ranking each by
/// the weaker of its image and signer digests (as #48 does).
fn select_primary(signers: &[SignerTrust]) -> Option<usize> {
    let rank = |d: Option<DigestAlgorithm>| match d {
        Some(a) if a.is_sha2() => 2,
        Some(DigestAlgorithm::Sha1) => 1,
        _ => 0,
    };
    let mut best: Option<(usize, u8)> = None;
    for s in signers.iter().filter(|s| s.trusted) {
        let r = rank(s.digest_alg).min(rank(s.signer_digest_alg));
        if best.is_none_or(|(_, b)| r > b) {
            best = Some((s.signature, r));
        }
    }
    best.map(|(i, _)| i)
}

fn identity(
    signature: usize,
    chain: &ChainReport,
    version: Option<&VersionInfo>,
) -> SignerIdentity {
    let mut issues = Vec::new();
    let leaf = chain.leaf_cert();
    let (publisher_name, leaf_cn) = match leaf {
        Some(cert) => names(cert, &mut issues),
        None => (None, None),
    };
    let publisher_dn = leaf
        .filter(|c| {
            c.subject
                .attributes()
                .all(|a| !a.lossy && !a.value.chars().any(char::is_control))
        })
        .map(|c| c.subject.canonical.clone());
    if leaf.is_some() && publisher_dn.is_none() {
        issues.push(IdentityIssue::UnusableDn);
    }

    let product_name = version
        .and_then(|v| v.get(VersionField::ProductName))
        .filter(|p| !p.trim().is_empty())
        .map(str::to_owned);
    if product_name.is_none() {
        issues.push(IdentityIssue::NoProductName);
    }
    let publisher_product = publisher_name
        .as_ref()
        .zip(product_name.as_ref())
        .map(|(n, p)| (n.value.clone(), p.clone()));

    let root = match (chain.well_known_root_id, chain.pca_cert()) {
        (Some(id), _) => Some(OsRuleRoot::WellKnown(id)),
        (None, Some(pca)) => {
            let hash = pca.tbs_hash.clone().map(OsRuleRoot::PcaTbsHash);
            if hash.is_none() {
                issues.push(IdentityIssue::NoPcaTbsHash);
            }
            hash
        }
        (None, None) => {
            issues.push(IdentityIssue::NoPca);
            None
        }
    };
    let publisher_os_rule = root
        .zip(leaf_cn)
        .map(|(root, leaf_cn)| PublisherOsRule { root, leaf_cn });

    let file = version.and_then(|v| {
        let name = v.effective_file_name(VersionField::OriginalFileName)?;
        Some((name.value.to_owned(), name.field, v.file_version()?))
    });
    if file.is_none() {
        issues.push(IdentityIssue::NoFileNameOrVersion);
    }
    let file_publisher_os_rule = publisher_os_rule.clone().zip(file).map(
        |(publisher, (file_name, file_name_field, min_version))| FilePublisherOsRule {
            publisher,
            file_name,
            file_name_field,
            min_version,
        },
    );

    SignerIdentity {
        signature,
        publisher_name,
        publisher_dn,
        product_name,
        publisher_product,
        publisher_os_rule,
        file_publisher_os_rule,
        issues,
    }
}

/// The publisher name and the leaf `CN` for OS rules. A name that is not
/// clean is not used, and no fallback replaces it: falling back to `O`
/// would let a garbled `CN` change the identity.
fn names(
    cert: &CertSummary,
    issues: &mut Vec<IdentityIssue>,
) -> (Option<PublisherName>, Option<String>) {
    let subject = &cert.subject;
    if subject.values(AttributeKind::CommonName).count() > 1 {
        issues.push(IdentityIssue::MultipleCommonNames);
    }
    let (attr, source) = match (
        subject.first(AttributeKind::CommonName),
        subject.first(AttributeKind::Organization),
    ) {
        (Some(cn), _) => (cn, NameSource::CommonName),
        (None, Some(o)) => (o, NameSource::Organization),
        (None, None) => {
            issues.push(IdentityIssue::NoName);
            return (None, None);
        }
    };
    if !attr.is_clean() {
        issues.push(IdentityIssue::UnusableName);
        return (None, None);
    }
    let leaf_cn = (source == NameSource::CommonName).then(|| attr.value.clone());
    if leaf_cn.is_none() {
        issues.push(IdentityIssue::NoCommonName);
    }
    (
        Some(PublisherName {
            value: attr.value.clone(),
            source,
        }),
        leaf_cn,
    )
}
