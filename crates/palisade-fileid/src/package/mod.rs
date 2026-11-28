//! Packaged apps (#53): `.msix`/`.appx` packages and `.msixbundle`/
//! `.appxbundle` bundles.
//!
//! [`parse_package`] reads a package or bundle from memory and returns a
//! [`PackageIdentity`]: the manifest identity, the publisher ID, package
//! family name and package full name, the display names, applications,
//! capabilities, extensions and dependencies, for a bundle its member
//! packages, and the package signature checked against the package.
//!
//! # Layers
//!
//! - `zip`: a strict ZIP reader that accepts only the shape packaging tools
//!   write and refuses anything ZIP readers disagree about.
//! - `xml`: a bounded, namespace-aware XML tree with no DTD support.
//! - `manifest`, `blockmap`, `identity`: the package formats.
//! - this module: the signature and the identity record.
//!
//! # The signature
//!
//! `AppxSignature.p7x` is the bytes `PKCX` followed by an Authenticode
//! SignedData. Its indirect data is `SPC_SIPINFO` naming the package subject
//! type (`0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1` for a package,
//! `0F5F58B3-AADE-4B9A-A434-95742D92ECEB` for a bundle), and its digest is
//! not one hash but a tagged list ([`signed_digest`]):
//!
//! - `APPX`, then
//! - `AXPC` and the hash of every local file record (header, data, data
//!   descriptor) except the signature's, in archive order;
//! - `AXCD` and the hash of the central directory without the signature's
//!   entry, followed by end records rewritten for that shorter directory
//!   (its entry count, size and offset, with the disk fields zero);
//! - `AXCT` and the hash of `[Content_Types].xml`, uncompressed;
//! - `AXBM` and the hash of `AppxBlockMap.xml`, uncompressed;
//! - `AXCI` and the hash of `AppxMetadata/CodeIntegrity.cat`, if present.
//!
//! All under the block map's hash method. The archive must have ZIP64 end
//! records: the OS signing tool always writes them, and the OS rejects a
//! signature on a classic archive whatever its digest
//! ([`PackageSignatureIssue::NotZip64`]). The signature also must be the
//! last local record and the last central directory entry, so nothing
//! unsigned can sit after it.
//!
//! [`SignatureKind::Package`] signatures go through the same SignedData
//! decoder, signer certificate lookup, `messageDigest` and signature checks
//! as PE signatures, nested signatures included. A signature is valid only
//! when, in addition, the block map verifies against every file
//! ([`blockmap::verify`]) and the subject DN of the signer of **every**
//! valid signature, nested ones included, rendered as the OS renders it,
//! equals `Identity@Publisher` exactly; a different publisher is
//! [`PackageSignatureIssue::PublisherMismatch`]. Special parts
//! (`AppxSignature.p7x`, the manifests, the block map) are found by part
//! name: percent-decoded and ASCII case-insensitive, as OPC compares them. The report then feeds
//! [`crate::authenticode::evaluate_trust`] and
//! [`crate::authenticode::evaluate_validity`] unchanged.
//!
//! # Fail conservative
//!
//! Any archive this reader refuses is an error, never an unsigned package.
//! Anything wrong with the signature, the block map or the publisher
//! demotes every signature so that none is valid. Bundles are identified
//! by their bundle manifest; their member packages are listed, not parsed
//! or verified one by one. A bundle's block map lists only the bundle
//! manifest; each payload package must be a stored member at the offset
//! and of the size the bundle manifest gives ([`blockmap::verify_bundle`]),
//! and the signature covers its bytes through the local records (`AXPC`).

#![forbid(unsafe_code)]

pub mod blockmap;
pub mod identity;
pub mod manifest;
mod os_ids;
pub mod xml;
pub mod zip;

use std::fmt;

use crate::authenticode::pkcs7::Subject;
use crate::authenticode::verify::{Expected, verify_detached};
use crate::authenticode::{
    CertSummary, DigestAlgorithm, InvalidReason, SignatureKind, SignatureReport, SignatureStatus,
    SigningState,
};
use crate::hash::{AlgorithmSet, Digest, MultiHasher, sha256_of};

pub use identity::{PackageVersion, family_name, full_name, publisher_id};
pub use manifest::{Application, BundleMember, Capability, Dependency, Extension, ManifestError};

use blockmap::BlockMapError;
use zip::{Archive, Member, ZipError};

/// The largest package read: 4 GiB.
pub const MAX_PACKAGE_SIZE: u64 = 4 * 1024 * 1024 * 1024;
/// The largest manifest, block map, content types file or code integrity
/// catalog read or hashed: 16 MiB.
pub const MAX_METADATA_SIZE: u64 = 16 * 1024 * 1024;
/// The largest signature file read: 16 MiB.
pub const MAX_SIGNATURE_SIZE: u64 = 16 * 1024 * 1024;

/// The package subject type GUID, as encoded.
pub const SIP_GUID_PACKAGE: [u8; 16] = [
    0x4b, 0xdf, 0xc5, 0x0a, 0x07, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0, 0x9f, 0xd1,
];
/// The bundle subject type GUID, as encoded.
pub const SIP_GUID_BUNDLE: [u8; 16] = [
    0xb3, 0x58, 0x5f, 0x0f, 0xde, 0xaa, 0x9a, 0x4b, 0xa4, 0x34, 0x95, 0x74, 0x2d, 0x92, 0xec, 0xeb,
];

const SIGNATURE: &str = "AppxSignature.p7x";
const BLOCK_MAP: &str = "AppxBlockMap.xml";
const CONTENT_TYPES: &str = "[Content_Types].xml";
const CODE_INTEGRITY: &str = "AppxMetadata/CodeIntegrity.cat";
const MANIFEST: &str = "AppxManifest.xml";
const BUNDLE_MANIFEST: &str = "AppxMetadata/AppxBundleManifest.xml";

/// Why a file could not be read as a package at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackageError {
    /// Larger than [`MAX_PACKAGE_SIZE`].
    TooLarge(u64),
    /// Not an archive this reader accepts.
    Archive(ZipError),
    /// Neither `AppxManifest.xml` nor a bundle manifest.
    NotPackage,
    /// A manifest member that cannot be read, or is too large.
    Member(String),
    /// The manifest could not be used.
    Manifest(ManifestError),
}

impl fmt::Display for PackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, "package of {n} bytes exceeds {MAX_PACKAGE_SIZE}"),
            Self::Archive(e) => write!(f, "archive: {e}"),
            Self::NotPackage => f.write_str("not an app package or bundle"),
            Self::Member(n) => write!(f, "cannot read {n}"),
            Self::Manifest(e) => write!(f, "manifest: {e}"),
        }
    }
}

impl std::error::Error for PackageError {}

/// Why a package signature that is cryptographically sound is still not
/// valid for this package.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackageSignatureIssue {
    /// `AppxSignature.p7x` does not start with `PKCX`, or is too large.
    BadContainer,
    /// The signature is not the last record and the last central directory
    /// entry, so data could follow it unsigned.
    NotLast,
    /// The block map is missing, unreadable, or does not match the files.
    BlockMap(BlockMapError),
    /// `[Content_Types].xml` is missing.
    NoContentTypes,
    /// The signer's subject is not the manifest's publisher: the signer's
    /// rendered DN, then `Identity@Publisher`.
    PublisherMismatch {
        /// The signer's subject as the OS renders it.
        signer: String,
        /// The manifest's publisher.
        publisher: String,
    },
    /// The signer certificate could not be read to compare its subject.
    SignerUnreadable,
    /// The archive has no ZIP64 end records. The OS checks the package
    /// digest of a signed package only as the ZIP64 archive its own signing
    /// tool writes, so it rejects a signature on a classic archive
    /// (`TRUST_E_BAD_DIGEST`), whatever the digest: such a signature is
    /// never valid here either.
    NotZip64,
    /// A part the package digest covers could not be read, so there is no
    /// digest to check the signature against (#333).
    DigestInput(DigestInputError),
}

/// Which input of the package digest ([`signed_digest`]) could not be
/// read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestInputError {
    /// The part is larger than [`MAX_METADATA_SIZE`] uncompressed. These
    /// parts are not in the block map, so nothing else bounds them. The
    /// part name, then its size.
    TooLarge(String, u64),
    /// The part could not be inflated (its compressed data is broken).
    Unreadable(String),
    /// The archive's end records could not be rebuilt for the digest.
    EndRecords,
    /// The block map's hash method has no digest here.
    HashMethod,
}

impl fmt::Display for DigestInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n, size) => {
                write!(
                    f,
                    "{n} is {size} bytes, over the {MAX_METADATA_SIZE}-byte limit"
                )
            }
            Self::Unreadable(n) => write!(f, "{n} cannot be read"),
            Self::EndRecords => f.write_str("the end records cannot be rebuilt"),
            Self::HashMethod => f.write_str("the block map's hash method has no digest"),
        }
    }
}

/// The package-level verdict on a package signature, distinct from the
/// per-signature [`SignatureStatus`] (#333).
///
/// A signature that matches the package digest but fails a package check
/// (the publisher, the block map, ZIP64) is reported in the shared
/// Authenticode report as [`SignatureStatus::DigestMismatch`], so every
/// consumer of that report (trust, validity, policy facts) already treats
/// it as not covering the file, exactly as a tampered file. This status
/// says which of the two it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageSignatureStatus {
    /// Valid: the Authenticode checks and every package check passed.
    Valid,
    /// The package was rejected by a package-level check, whatever its
    /// signatures said.
    Rejected(PackageSignatureIssue),
    /// The package passed the package checks, but no signature is valid
    /// for it: the per-signature statuses in the report say why (most
    /// often [`SignatureStatus::DigestMismatch`]: the file changed after
    /// signing).
    Invalid,
}

/// The package signature: the Authenticode report and any package-level
/// problem.
#[derive(Debug, Clone)]
pub struct PackageSignature {
    /// The signatures. When [`Self::issue`] is set, none is valid.
    pub report: SignatureReport,
    /// Why the signature is not valid for this package, beyond the
    /// Authenticode checks.
    pub issue: Option<PackageSignatureIssue>,
}

impl PackageSignature {
    /// The package-level verdict ([`PackageSignatureStatus`]).
    #[must_use]
    pub fn status(&self) -> PackageSignatureStatus {
        match (&self.issue, self.report.primary) {
            (Some(issue), _) => PackageSignatureStatus::Rejected(issue.clone()),
            (None, Some(_)) => PackageSignatureStatus::Valid,
            (None, None) => PackageSignatureStatus::Invalid,
        }
    }
}

/// The identity of a package or bundle.
#[derive(Debug, Clone)]
pub struct PackageIdentity {
    /// `Identity@Name`.
    pub name: String,
    /// `Identity@Publisher`, exactly as written.
    pub publisher_dn: String,
    /// The 13-character publisher ID.
    pub publisher_id: String,
    /// The package family name.
    pub pfn: String,
    /// The package full name.
    pub full_name: String,
    /// `Identity@Version`.
    pub version: PackageVersion,
    /// `Identity@ProcessorArchitecture`, lowercased; empty for neutral and
    /// for bundles.
    pub arch: String,
    /// `Identity@ResourceId`; empty when absent.
    pub resource_id: String,
    /// `Properties/DisplayName` (packages only).
    pub display_name: Option<String>,
    /// `Properties/PublisherDisplayName` (packages only).
    pub publisher_display_name: Option<String>,
    /// Whether the package is a framework.
    pub is_framework: bool,
    /// Whether the package is a resource package.
    pub is_resource_package: bool,
    /// Applications (packages only).
    pub apps: Vec<Application>,
    /// Capabilities (packages only).
    pub capabilities: Vec<Capability>,
    /// Extensions (packages only).
    pub extensions: Vec<Extension>,
    /// Dependencies (packages only).
    pub dependencies: Vec<Dependency>,
    /// Whether this is a bundle.
    pub is_bundle: bool,
    /// For a bundle, the packages it lists.
    pub members: Vec<BundleMember>,
    /// The signature, `None` when the package has no `AppxSignature.p7x`.
    pub signature: Option<PackageSignature>,
    /// The flat SHA-256 of the file.
    pub flat_sha256: Digest,
}

impl PackageIdentity {
    /// Whether the package has a signature that is valid for it: the
    /// Authenticode checks, the package digest, the block map and the
    /// publisher. Says nothing about whether the signer is trusted.
    #[must_use]
    pub fn signature_valid(&self) -> bool {
        self.signature
            .as_ref()
            .is_some_and(|s| s.issue.is_none() && s.report.primary.is_some())
    }

    /// Whether the package declares the restricted `runFullTrust`
    /// capability.
    #[must_use]
    pub fn runs_full_trust(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.is_restricted() && c.name == "runFullTrust")
    }
}

fn read_metadata(archive: &Archive<'_>, m: &Member) -> Result<Vec<u8>, PackageError> {
    if m.size > MAX_METADATA_SIZE {
        return Err(PackageError::Member(m.name.clone()));
    }
    archive
        .read(m)
        .map_err(|_| PackageError::Member(m.name.clone()))
}

/// Whether `m` is the signature part (part names compare
/// case-insensitively, percent-decoded).
fn is_signature(m: &Member) -> bool {
    zip::fold(&m.part) == zip::fold(SIGNATURE)
}

/// Parses a package or bundle.
pub fn parse_package(data: &[u8]) -> Result<PackageIdentity, PackageError> {
    let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
    if size > MAX_PACKAGE_SIZE {
        return Err(PackageError::TooLarge(size));
    }
    let archive = Archive::parse(data).map_err(PackageError::Archive)?;
    let bundle_member = archive.member(BUNDLE_MANIFEST);
    let manifest_member = archive.member(MANIFEST);
    let mut out = match (bundle_member, manifest_member) {
        (Some(b), None) => {
            let m = manifest::parse_bundle_manifest(&read_metadata(&archive, b)?)
                .map_err(PackageError::Manifest)?;
            identity_record(&m.identity, true, data, |r| r.members = m.members)
        }
        (None, Some(p)) => {
            let m = manifest::parse_package_manifest(&read_metadata(&archive, p)?)
                .map_err(PackageError::Manifest)?;
            identity_record(&m.identity, false, data, |r| {
                r.display_name = m.display_name.clone();
                r.publisher_display_name = m.publisher_display_name.clone();
                r.is_framework = m.is_framework;
                r.is_resource_package = m.is_resource_package;
                r.apps = m.applications.clone();
                r.capabilities = m.capabilities.clone();
                r.extensions = m.extensions.clone();
                r.dependencies = m.dependencies.clone();
            })
        }
        // Both, or neither: not a package this reader can identify.
        _ => return Err(PackageError::NotPackage),
    };
    out.signature = verify_signature(&archive, &out);
    Ok(out)
}

fn identity_record(
    id: &manifest::Identity,
    is_bundle: bool,
    data: &[u8],
    fill: impl FnOnce(&mut PackageIdentity),
) -> PackageIdentity {
    let pid = publisher_id(&id.publisher);
    let mut r = PackageIdentity {
        name: id.name.clone(),
        publisher_dn: id.publisher.clone(),
        pfn: family_name(&id.name, &pid),
        full_name: full_name(&id.name, id.version, &id.arch, &id.resource_id, &pid),
        publisher_id: pid,
        version: id.version,
        arch: id.arch.clone(),
        resource_id: id.resource_id.clone(),
        display_name: None,
        publisher_display_name: None,
        is_framework: false,
        is_resource_package: false,
        apps: Vec::new(),
        capabilities: Vec::new(),
        extensions: Vec::new(),
        dependencies: Vec::new(),
        is_bundle,
        members: Vec::new(),
        signature: None,
        flat_sha256: sha256_of(data),
    };
    fill(&mut r);
    r
}

/// The signed digest of `archive` under `alg`: the tagged list described
/// in the module documentation. `None` when a part it needs is missing or
/// cannot be read; [`signed_digest_checked`] says which.
#[must_use]
pub fn signed_digest(archive: &Archive<'_>, alg: DigestAlgorithm) -> Option<Vec<u8>> {
    signed_digest_checked(archive, alg).ok().flatten()
}

/// [`signed_digest`], saying why there is none: `Ok(None)` when a part it
/// needs (`[Content_Types].xml`, the block map) is missing, `Err` when a
/// part is present but cannot be read.
pub fn signed_digest_checked(
    archive: &Archive<'_>,
    alg: DigestAlgorithm,
) -> Result<Option<Vec<u8>>, DigestInputError> {
    let h = alg.hash_algorithm().ok_or(DigestInputError::HashMethod)?;
    let one = |feed: &mut dyn FnMut(&mut MultiHasher)| -> Option<Vec<u8>> {
        let mut hasher = MultiHasher::new(AlgorithmSet::from(h));
        feed(&mut hasher);
        hasher.finalize().get(h).map(|d| d.as_bytes().to_vec())
    };
    let member_hash = |name: &str| -> Result<Option<Vec<u8>>, DigestInputError> {
        let Some(m) = archive.member(name) else {
            return Ok(None);
        };
        // These members are not in the block map, so nothing else bounds
        // how much they inflate to.
        if m.size > MAX_METADATA_SIZE {
            return Err(DigestInputError::TooLarge(m.name.clone(), m.size));
        }
        let mut hasher = MultiHasher::new(AlgorithmSet::from(h));
        archive
            .stream(m, |c| hasher.update(c))
            .map_err(|_| DigestInputError::Unreadable(m.name.clone()))?;
        Ok(hasher.finalize().get(h).map(|d| d.as_bytes().to_vec()))
    };
    let end = DigestInputError::EndRecords;
    let signed: Vec<&Member> = archive
        .members
        .iter()
        .filter(|m| !is_signature(m))
        .collect();
    // AXPC: the local records, in archive order.
    let axpc = one(&mut |hasher| {
        for m in &signed {
            hasher.update(archive.bytes(m.local_offset, m.end_offset));
        }
    })
    .ok_or(DigestInputError::HashMethod)?;
    // AXCD: the central directory without the signature, then end records
    // for it. Local records keep their offsets (the signature is last).
    let cd_offset: u64 = signed.last().map_or(0, |m| m.end_offset);
    let cd_size = signed
        .iter()
        .try_fold(0_u64, |n, m| {
            n.checked_add(u64::try_from(archive.central_bytes(m).len()).ok()?)
        })
        .ok_or_else(|| end.clone())?;
    let count = u64::try_from(signed.len()).map_err(|_| end.clone())?;
    let mut tail = Vec::new();
    if archive.zip64 {
        tail.extend_from_slice(&0x0606_4b50_u32.to_le_bytes());
        tail.extend_from_slice(&44_u64.to_le_bytes());
        // Version made by and needed, as in the original record.
        let rec = archive.bytes(archive.central_end + 12, archive.central_end + 16);
        tail.extend_from_slice(rec);
        tail.extend_from_slice(&0_u32.to_le_bytes());
        tail.extend_from_slice(&0_u32.to_le_bytes());
        tail.extend_from_slice(&count.to_le_bytes());
        tail.extend_from_slice(&count.to_le_bytes());
        tail.extend_from_slice(&cd_size.to_le_bytes());
        tail.extend_from_slice(&cd_offset.to_le_bytes());
        tail.extend_from_slice(&0x0706_4b50_u32.to_le_bytes());
        tail.extend_from_slice(&0_u32.to_le_bytes());
        tail.extend_from_slice(&(cd_offset + cd_size).to_le_bytes());
        tail.extend_from_slice(&1_u32.to_le_bytes());
    }
    let eocd_at = if archive.zip64 {
        archive.central_end + 56 + 20
    } else {
        archive.central_end
    };
    let eocd = archive.bytes(eocd_at, eocd_at + 22);
    let field16 = |o: usize| {
        eocd.get(o..o + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_le_bytes)
    };
    let field32 = |o: usize| {
        eocd.get(o..o + 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
    };
    tail.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    tail.extend_from_slice(&[0, 0, 0, 0]);
    let n16 = |orig: Option<u16>| -> Option<u16> {
        if orig? == 0xffff {
            Some(0xffff)
        } else {
            u16::try_from(count).ok()
        }
    };
    tail.extend_from_slice(&n16(field16(8)).ok_or_else(|| end.clone())?.to_le_bytes());
    tail.extend_from_slice(&n16(field16(10)).ok_or_else(|| end.clone())?.to_le_bytes());
    let n32 = |orig: Option<u32>, v: u64| -> Option<u32> {
        if orig? == u32::MAX {
            Some(u32::MAX)
        } else {
            u32::try_from(v).ok()
        }
    };
    tail.extend_from_slice(
        &n32(field32(12), cd_size)
            .ok_or_else(|| end.clone())?
            .to_le_bytes(),
    );
    tail.extend_from_slice(
        &n32(field32(16), cd_offset)
            .ok_or_else(|| end.clone())?
            .to_le_bytes(),
    );
    tail.extend_from_slice(&0_u16.to_le_bytes());
    let axcd = one(&mut |hasher| {
        for m in &signed {
            hasher.update(archive.central_bytes(m));
        }
        hasher.update(&tail);
    })
    .ok_or(DigestInputError::HashMethod)?;
    let Some(axct) = member_hash(CONTENT_TYPES)? else {
        return Ok(None);
    };
    let Some(axbm) = member_hash(BLOCK_MAP)? else {
        return Ok(None);
    };
    let mut out = b"APPX".to_vec();
    for (tag, hash) in [
        (b"AXPC", axpc),
        (b"AXCD", axcd),
        (b"AXCT", axct),
        (b"AXBM", axbm),
    ] {
        out.extend_from_slice(tag);
        out.extend_from_slice(&hash);
    }
    if archive.member(CODE_INTEGRITY).is_some() {
        let Some(axci) = member_hash(CODE_INTEGRITY)? else {
            return Ok(None);
        };
        out.extend_from_slice(b"AXCI");
        out.extend_from_slice(&axci);
    }
    Ok(Some(out))
}

fn verify_signature(archive: &Archive<'_>, id: &PackageIdentity) -> Option<PackageSignature> {
    let sig = archive.member(SIGNATURE)?;
    let subject = Subject::SipBlob(if id.is_bundle {
        SIP_GUID_BUNDLE
    } else {
        SIP_GUID_PACKAGE
    });
    let fail = |report: SignatureReport, issue| {
        let mut s = PackageSignature {
            report,
            issue: Some(issue),
        };
        demote(&mut s.report);
        Some(s)
    };
    let empty = || {
        verify_detached(
            &[],
            &Expected::Blob(&|_| None),
            subject,
            SignatureKind::Package,
        )
    };
    let raw = if sig.size <= MAX_SIGNATURE_SIZE {
        archive.read(sig).ok()
    } else {
        None
    };
    let Some(der) = raw.as_deref().and_then(|r| r.strip_prefix(b"PKCX")) else {
        return fail(empty(), PackageSignatureIssue::BadContainer);
    };
    // The signature is the last record and the last directory entry.
    if !archive.members.last().is_some_and(is_signature) {
        return fail(empty(), PackageSignatureIssue::NotLast);
    }
    // The OS signing tool always writes ZIP64 end records, and the OS
    // rejects a signed classic archive however its digest is computed
    // (Windows CI: osslsigncode's signature on a classic archive is
    // TRUST_E_BAD_DIGEST, the OS signing tool's on the same input,
    // rewritten as ZIP64, verifies). Never valid, then.
    if !archive.zip64 {
        return fail(empty(), PackageSignatureIssue::NotZip64);
    }
    let blockmap = archive
        .member(BLOCK_MAP)
        .ok_or_else(|| BlockMapError::Malformed("missing".into()))
        .and_then(|m| {
            if m.size > MAX_METADATA_SIZE {
                return Err(BlockMapError::Malformed("too large".into()));
            }
            archive
                .read(m)
                .map_err(|e| BlockMapError::Malformed(e.to_string()))
        })
        .and_then(|b| blockmap::parse(&b));
    // The package digest uses the block map's hash method; a signature
    // under another digest does not match. It is computed once, however
    // many signatures the file carries.
    let digest_result = blockmap
        .as_ref()
        .ok()
        .map(|m| signed_digest_checked(archive, m.hash).map(|d| d.map(|d| (m.hash, d))));
    let digest_error = match &digest_result {
        Some(Err(e)) => Some(e.clone()),
        _ => None,
    };
    let digest = digest_result.and_then(Result::ok).flatten();
    let expected = |alg: DigestAlgorithm| -> Option<Vec<u8>> {
        digest
            .as_ref()
            .filter(|(a, _)| *a == alg)
            .map(|(_, d)| d.clone())
    };
    let report = verify_detached(
        der,
        &Expected::Blob(&expected),
        subject,
        SignatureKind::Package,
    );
    if archive.member(CONTENT_TYPES).is_none() {
        return fail(report, PackageSignatureIssue::NoContentTypes);
    }
    // A digest input that is present but unreadable: say which, rather
    // than leave only "digest unavailable" on the signature.
    if let Some(e) = digest_error {
        return fail(report, PackageSignatureIssue::DigestInput(e));
    }
    let map = match blockmap {
        Ok(m) => m,
        Err(e) => return fail(report, PackageSignatureIssue::BlockMap(e)),
    };
    // The signer of every valid signature, nested ones included, is the
    // publisher: trust and validity evaluation may pick any of them, so
    // one from another publisher would let it vouch for this identity.
    for sig in report.signatures.iter().filter(|s| s.status.is_valid()) {
        let cert = sig
            .signer
            .as_ref()
            .and_then(|s| sig.certs_in_blob.get(s.signer_cert))
            .and_then(|der| CertSummary::from_der(der).ok());
        let Some(cert) = cert else {
            return fail(report, PackageSignatureIssue::SignerUnreadable);
        };
        let clean = cert.subject.attributes().all(|a| a.is_clean());
        if !clean || cert.subject.canonical != id.publisher_dn {
            return fail(
                report,
                PackageSignatureIssue::PublisherMismatch {
                    signer: cert.subject.canonical,
                    publisher: id.publisher_dn.clone(),
                },
            );
        }
    }
    // The block map, last: it inflates every file, so it runs only for a
    // signature that is otherwise sound.
    if report.primary.is_some() {
        let checked = if id.is_bundle {
            let payloads: Vec<blockmap::Payload<'_>> = id
                .members
                .iter()
                .map(|m| blockmap::Payload {
                    file_name: &m.file_name,
                    offset: m.offset,
                    size: m.size,
                })
                .collect();
            blockmap::verify_bundle(&map, archive, &payloads)
        } else {
            blockmap::verify(&map, archive)
        };
        if let Err(e) = checked {
            return fail(report, PackageSignatureIssue::BlockMap(e));
        }
    }
    Some(PackageSignature {
        report,
        issue: None,
    })
}

/// Marks every valid signature as not valid (the package-level check
/// failed) and clears the primary.
fn demote(report: &mut SignatureReport) {
    for sig in &mut report.signatures {
        if sig.status.is_valid() {
            sig.status = SignatureStatus::DigestMismatch;
            sig.signer = None;
        }
    }
    report.primary = None;
    report.signing_state = match report.signatures.first() {
        Some(first) => SigningState::Invalid(InvalidReason::Signature(first.status.clone())),
        None => SigningState::Invalid(InvalidReason::Signature(SignatureStatus::DigestMismatch)),
    };
}
