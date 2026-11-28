//! The bridge from a file's identity to the facts policy evaluates
//! (#318, #328).
//!
//! [`from_identity`] turns a `palisade_fileid` [`FileIdentity`] into the
//! [`ObjectFacts`] `palisade_policy` evaluates, and says which fact classes
//! the record covered ([`Bridged::computed`]), so the engine asks for the
//! rest ([`palisade_policy::engine::Request::computed`]).
//!
//! It lives in the agent, not in `palisade-policy`: policy may depend on
//! `palisade-fileid` by ADR 0003, but fileid's graph reaches `windows-sys`
//! (through `ring` on Arm64 Windows, and through its optional `os-trust`
//! feature in a workspace build), which `cargo xtask check-deps` bans from
//! policy's graph. The agent already depends on both.
//!
//! # Fail closed (ADR 0018)
//!
//! A fact the record does not hold, or holds only as a reason
//! ([`Field::NotRequested`], [`Field::Unavailable`] and so on), is absent,
//! so every criterion on it is unknown: never a match, never a mismatch.
//! The mapping never invents a value, and removing a fact from the record
//! only ever removes facts here (`tests/facts.rs` checks this as a
//! property: no decision becomes more permissive). In particular:
//!
//! - **Signers.** The list is set only when it is complete: every embedded
//!   signature was read (fewer than the reader's limit) and the catalog
//!   lookup could show which catalogs list the file. An incomplete list is
//!   `None`, not a shorter list, because a negated signer test on a
//!   shorter list could match. A signature is trusted (`valid`,
//!   `valid_expired_timestamped`, `catalog_signed`) only when fileid
//!   counts it usable: its signer is trusted, its validity checks passed,
//!   and neither its digests nor a catalog match rely on SHA-1. A revoked
//!   signer or file is `revoked`, an expired one `expired`; any other
//!   signature that verifies but does not vouch is `untrusted_root`. A
//!   signature that does not verify at all (not even a digest mismatch)
//!   is `untrusted_root` with **no** facts: its certificates are not bound
//!   to it, so nothing it names is known.
//! - **Paths.** The path is the opened file's final path, never the name as
//!   written (which a link may point elsewhere), and never a claimed name
//!   hint. Its volume is `fixed` only for fileid's `os_volume` and
//!   `other_fixed`; a RAM disk, virtual disk or unknown volume has no
//!   volume kind, so a path on it is never trusted
//!   ([`PathFact::acl_proven`]). It counts as user-writable when a
//!   non-administrator can write it or change its permissions.
//! - **Hashes.** The Authenticode hashes are used only when the image's
//!   layout conforms; otherwise they are a best effort, and the flat hash
//!   is the identity.
//! - **Text facts** that fileid reports as `unknown` (a drive type, or a
//!   bus it could not name) are absent.
//!
//! Not filled here: the location classes (the engine derives them from the
//! path and its volume), the origin (#115, #118), the path's alias (the OS
//! final path of a network file is already its UNC form) and the
//! `meta.detected_type` and `meta.extension_type` facts (#376).
//!
//! # Where the agent calls it
//!
//! The execution path is not wired yet: no subsystem receives an execution
//! event and decides it (the event sources are #58 and #59, enforcement is
//! #113). This is its seam: it identifies the file with `palisade_fileid`,
//! calls [`from_identity`], builds the request with [`Bridged::request`]
//! (adding the file key and session for the decision cache), and passes it
//! to [`crate::policy_cache::Active::evaluate`]. On
//! [`NeedFacts`](palisade_policy::engine::Outcome::NeedFacts) it runs the
//! tiers that compute the named classes (hashes: hash; signers and
//! metadata: trust, classify and deep; path ACL: context), merges, bridges
//! and asks again.

#![forbid(unsafe_code)]

use palisade_core::VerificationError;
use palisade_core::path::VolumeMap;
use palisade_fileid::authenticode::{DigestAlgorithm as FileidDigest, KeyAlgorithm};
use palisade_fileid::identity::{
    CatalogMatchSummary, CatalogState, CertBrief, Field, FileIdentity, SignatureSummary,
};
use palisade_fileid::pe::{Machine, Subsystem};
use palisade_policy::demand::FactSet;
use palisade_policy::facts::{
    DigestAlgorithm, KeyFact, KeyKind, ObjectFacts, PathFact, SignatureSource, SignerDetails,
    SignerFact, SignerStatus,
};
use palisade_policy::model::Field as PolicyField;
use palisade_policy::unknown::VolumeKind;

/// The facts of one file, and which fact classes they cover.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bridged {
    /// The facts.
    pub facts: ObjectFacts,
    /// The classes the record's tiers computed. A fact of one of these
    /// classes that is absent is unknown for this decision; a class not
    /// here is one the engine may ask for.
    pub computed: FactSet,
}

impl Bridged {
    /// The engine request for these facts: `computed` is what the record
    /// covered, so the engine answers
    /// [`NeedFacts`](palisade_policy::engine::Outcome::NeedFacts) for any
    /// class a rule needs that the tiers run so far did not compute. The
    /// caller runs the tiers it names, merges the records
    /// ([`FileIdentity::merge`]), bridges again and asks again.
    #[must_use]
    pub fn request<'a>(
        &'a self,
        object_type: palisade_policy::model::ObjectType,
        variables: &'a palisade_policy::facts::PathVariables,
        context: &'a palisade_policy::context::EvaluationContext,
        state: &'a palisade_policy::mode::DeviceState,
        trace_id: palisade_policy::decision::TraceId,
    ) -> palisade_policy::engine::Request<'a> {
        palisade_policy::engine::Request {
            subject: palisade_policy::evaluate::Subject {
                object_type,
                facts: &self.facts,
                variables,
                context,
            },
            computed: self.computed,
            state,
            trace_id,
            file: None,
            session: None,
            expires_before: None,
        }
    }
}

/// The policy facts of `id`. `volumes` maps NT device paths to drive
/// letters, for a final path the OS gave in device form.
#[must_use]
pub fn from_identity(id: &FileIdentity, volumes: &VolumeMap) -> Bridged {
    let mut out = Bridged::default();
    hashes(id, &mut out);
    signers(id, &mut out);
    path(id, volumes, &mut out);
    metadata(id, &mut out);
    out
}

fn hashes(id: &FileIdentity, out: &mut Bridged) {
    let Some(h) = id.hashes.computed() else {
        return;
    };
    out.computed |= FactSet::HASHES;
    // Every empty file has the same digests: they identify nothing.
    if h.empty {
        return;
    }
    let f = &mut out.facts;
    for (field, value) in [
        (PolicyField::HashSha256, &h.sha256),
        (PolicyField::HashSha384, &h.sha384),
        (PolicyField::HashSha512, &h.sha512),
        (PolicyField::HashSha1, &h.sha1),
        (PolicyField::HashMd5, &h.md5),
    ] {
        if let Some(v) = value {
            f.set(field, v.clone());
        }
    }
    if let Some(a) = h.authenticode.computed().filter(|a| a.conformant) {
        for (field, value) in [
            (PolicyField::HashAuthenticodeSha256, &a.sha256),
            (PolicyField::HashAuthenticodeSha1, &a.sha1),
            (PolicyField::HashPageSha256, &a.page_sha256),
            (PolicyField::HashPageSha1, &a.page_sha1),
        ] {
            if let Some(v) = value {
                f.set(field, v.clone());
            }
        }
    }
    if let Some(v) = h.msi_normalised_sha256.computed() {
        f.set(PolicyField::HashMsiFuzzySha256, v.clone());
    }
}

/// The most signatures fileid reads from one file; a file with this many
/// may have more.
const MAX_SIGNATURES: usize = palisade_fileid::authenticode::MAX_SIGNATURES;

fn signers(id: &FileIdentity, out: &mut Bridged) {
    let Some(state) = id.signing_state.computed() else {
        return;
    };
    out.computed |= FactSet::SIGNERS;
    let embedded = match &id.signatures {
        Field::Computed(list) if list.len() < MAX_SIGNATURES => list.as_slice(),
        _ => return,
    };
    let catalog_complete = state.catalog != CatalogState::NotChecked
        && !id
            .errors
            .iter()
            .any(|e| e.code == "catalog_matches_truncated");
    let catalogs = match (&id.catalog_matches, catalog_complete) {
        (Field::Computed(list), true) => list.as_slice(),
        _ => return,
    };
    let file_revoked = state.verification_error == VerificationError::RevokedByHash;
    let list: Option<Vec<SignerFact>> = embedded
        .iter()
        .map(embedded_signer)
        .chain(
            catalogs
                .iter()
                .map(|m| Some(catalog_signer(m, file_revoked))),
        )
        .collect();
    out.facts.signers = list;
}

/// Whether both digests of a signature are SHA-2.
fn sha2(s: &SignatureSummary) -> bool {
    s.digest_alg.is_some_and(FileidDigest::is_sha2)
        && s.signer_digest_alg.is_some_and(FileidDigest::is_sha2)
}

/// One embedded signature. `None` when its status cannot be established,
/// which makes the whole list unknown.
fn embedded_signer(s: &SignatureSummary) -> Option<SignerFact> {
    let status = match s.status {
        "valid" => {
            if s.trusted && s.validity_error.is_ok() && sha2(s) {
                match (s.expired_now?, s.trusted_signing_time) {
                    (false, _) => SignerStatus::Valid,
                    (true, Some(_)) => SignerStatus::ValidExpiredTimestamped,
                    // Valid only because policy ignores expiry: not
                    // vouched for by default.
                    (true, None) => SignerStatus::Expired,
                }
            } else {
                untrusted_status(s.validity_error)
            }
        }
        "digest_mismatch" => SignerStatus::DigestMismatch,
        // It does not verify, so its certificates are not bound to it.
        _ => {
            return Some(SignerFact::new(
                SignerStatus::UntrustedRoot,
                SignatureSource::Embedded,
            ));
        }
    };
    let mut fact = SignerFact::new(status, SignatureSource::Embedded);
    if let Some(chain) = &s.chain {
        chain_facts(&chain.certs, chain.complete, &mut fact);
        fact.details.algorithms = chain
            .complete
            .then(|| {
                [s.digest_alg, s.signer_digest_alg]
                    .into_iter()
                    .chain(chain.certs.iter().map(|c| c.signature_digest))
                    .map(|d| d.map(digest))
                    .collect::<Option<Vec<_>>>()
            })
            .flatten();
    }
    fact.details.timestamp = s.trusted_signing_time;
    fact.details.countersigned = s.rfc3161_timestamp;
    Some(fact)
}

/// The status of a signature that verifies but does not vouch.
fn untrusted_status(error: VerificationError) -> SignerStatus {
    match error {
        VerificationError::Revoked | VerificationError::RevokedByHash => SignerStatus::Revoked,
        VerificationError::Expired => SignerStatus::Expired,
        _ => SignerStatus::UntrustedRoot,
    }
}

fn catalog_signer(m: &CatalogMatchSummary, file_revoked: bool) -> SignerFact {
    let validity_ok = m.validity.is_some_and(VerificationError::is_ok);
    let status = if m.signer_revoked || file_revoked {
        SignerStatus::Revoked
    } else if m.trusted && validity_ok && !m.relies_on_sha1 {
        SignerStatus::CatalogSigned
    } else if m.validity == Some(VerificationError::Expired) {
        SignerStatus::Expired
    } else {
        SignerStatus::UntrustedRoot
    };
    let mut fact = SignerFact::new(status, SignatureSource::Catalog);
    chain_facts(&m.signer_chain, m.signer_chain_complete, &mut fact);
    fact
}

/// The certificate facts of a chain, leaf first. The root, the
/// intermediates and every whole-chain fact need a complete chain: an
/// incomplete one's last certificate is not a root, and certificates are
/// missing above it.
fn chain_facts(certs: &[CertBrief], complete: bool, fact: &mut SignerFact) {
    let Some(leaf) = certs.first() else {
        return;
    };
    fact.publisher.clone_from(&leaf.subject_cn);
    fact.issuer.clone_from(&leaf.issuer_cn);
    fact.leaf_thumbprint_sha256 = Some(leaf.sha256_thumbprint.clone());
    let d: &mut SignerDetails = &mut fact.details;
    d.subject_organization.clone_from(&leaf.subject_o);
    d.subject_dn.clone_from(&leaf.subject_rfc4514);
    d.leaf_thumbprint_sha1 = Some(leaf.sha1_thumbprint.clone());
    d.leaf_tbs_hash.clone_from(&leaf.tbs_hash);
    d.leaf_spki_sha256 = Some(leaf.spki_sha256.clone());
    d.eku = Some(leaf.extended_key_usage.clone().unwrap_or_default());
    if !complete {
        return;
    }
    let root = certs.last().unwrap_or(leaf);
    let between = certs
        .get(1..certs.len().saturating_sub(1))
        .unwrap_or_default();
    // The highest certificate below the root; none when the leaf was
    // issued by the root (or is it).
    d.pca = match between.last() {
        Some(pca) => pca.subject_cn.clone(),
        None => None,
    };
    d.root_thumbprint_sha256 = Some(root.sha256_thumbprint.clone());
    d.root_thumbprint_sha1 = Some(root.sha1_thumbprint.clone());
    d.root_tbs_hash.clone_from(&root.tbs_hash);
    d.root_spki_sha256 = Some(root.spki_sha256.clone());
    d.intermediate_tbs_hashes = between.iter().map(|c| c.tbs_hash.clone()).collect();
    d.intermediate_spki_sha256 = Some(between.iter().map(|c| c.spki_sha256.clone()).collect());
    d.keys = certs.iter().map(key).collect();
}

fn key(c: &CertBrief) -> Option<KeyFact> {
    let kind = match c.key_alg {
        KeyAlgorithm::Rsa => KeyKind::Rsa,
        KeyAlgorithm::Ec(_) => KeyKind::Ec,
        _ => KeyKind::Other,
    };
    Some(KeyFact {
        kind,
        bits: c.key_bits?,
    })
}

const fn digest(d: FileidDigest) -> DigestAlgorithm {
    match d {
        FileidDigest::Md2 => DigestAlgorithm::Md2,
        FileidDigest::Md5 => DigestAlgorithm::Md5,
        FileidDigest::Sha1 => DigestAlgorithm::Sha1,
        FileidDigest::Sha256 => DigestAlgorithm::Sha256,
        FileidDigest::Sha384 => DigestAlgorithm::Sha384,
        FileidDigest::Sha512 => DigestAlgorithm::Sha512,
    }
}

fn metadata(id: &FileIdentity, out: &mut Bridged) {
    // `meta.*` and `msi.*` are one class: covered once the PE facts are
    // known, and the installer facts are known or cannot apply (the
    // content is not an installer package).
    let installer_known = !matches!(id.installer, Field::NotRequested)
        || id
            .kind
            .computed()
            .is_some_and(|k| !matches!(k.content_kind.as_str(), "msi" | "msp" | "mst" | "msm"));
    if !matches!(id.pe, Field::NotRequested) && installer_known {
        out.computed |= FactSet::METADATA;
    }
    let on_disk = out
        .facts
        .path
        .as_ref()
        .and_then(|p| p.path.file_name())
        .map(str::to_owned);
    let f = &mut out.facts;
    if let Some(size) = id.size.computed() {
        f.set(PolicyField::MetaFileSize, size.to_string());
    }
    // The effective name: the first of the version resource's original
    // file name, internal name, file description and product name that is
    // not blank; or, when the image is known to have none (or is no PE),
    // the name on disk. That is the opened file's final name, never the
    // name it was asked for by or a claimed name hint.
    let from_version = id.pe.computed().and_then(|pe| {
        let v = pe.version.as_ref()?;
        [
            &v.original_file_name,
            &v.internal_name,
            &v.file_description,
            &v.product_name,
        ]
        .into_iter()
        .flatten()
        .find(|n| !n.trim().is_empty())
        .cloned()
    });
    let fallback = match (&id.pe, from_version) {
        (_, Some(name)) => Some(name),
        (Field::Computed(_) | Field::NotApplicable, None) => on_disk,
        _ => None,
    };
    if let Some(name) = fallback {
        f.set(PolicyField::MetaFileNameFallback, name);
    }
    if let Some(pe) = id.pe.computed() {
        if let Some(m) = machine(pe.machine) {
            f.set(PolicyField::MetaPeMachine, m);
        }
        if let Some(s) = subsystem(pe.subsystem) {
            f.set(PolicyField::MetaPeSubsystem, s);
        }
        f.set(
            PolicyField::MetaIsDotnet,
            if pe.is_dotnet { "true" } else { "false" },
        );
        if let Some(v) = &pe.version {
            for (field, value) in [
                (PolicyField::MetaOriginalFilename, &v.original_file_name),
                (PolicyField::MetaInternalName, &v.internal_name),
                (PolicyField::MetaFileDescription, &v.file_description),
                (PolicyField::MetaProductName, &v.product_name),
                (PolicyField::MetaCompanyName, &v.company_name),
                (PolicyField::MetaLegalCopyright, &v.legal_copyright),
                (PolicyField::MetaLanguage, &v.language),
            ] {
                if let Some(value) = value {
                    f.set(field, value.clone());
                }
            }
            for (field, quad, text) in [
                (
                    PolicyField::MetaFileVersion,
                    &v.file_version_quad,
                    &v.file_version,
                ),
                (
                    PolicyField::MetaProductVersion,
                    &v.product_version_quad,
                    &v.product_version,
                ),
            ] {
                if let Some(value) = quad.as_ref().or(text.as_ref()) {
                    f.set(field, value.clone());
                }
            }
        }
    }
    if let Some(i) = id.installer.computed() {
        for (field, value) in [
            (PolicyField::MsiProductCode, &i.product_code),
            (PolicyField::MsiUpgradeCode, &i.upgrade_code),
            (PolicyField::MsiPackageCode, &i.package_code),
            (PolicyField::MsiProductName, &i.product_name),
            (PolicyField::MsiManufacturer, &i.manufacturer),
        ] {
            if let Some(value) = value {
                f.set(field, value.clone());
            }
        }
        if let Some(v) = i
            .product_version_quad
            .as_ref()
            .or(i.product_version.as_ref())
        {
            f.set(PolicyField::MsiProductVersion, v.clone());
        }
    }
}

/// The `meta.pe_machine` name of a COFF machine value. `None` for an
/// unknown or unnamed one.
fn machine(raw: u16) -> Option<&'static str> {
    Some(match Machine::from_raw(raw) {
        Machine::I386 => "i386",
        Machine::Amd64 => "amd64",
        Machine::Arm64 => "arm64",
        Machine::Arm64Ec => "arm64_ec",
        Machine::Arm64X => "arm64_x",
        Machine::ArmNt => "arm_nt",
        Machine::Arm => "arm",
        Machine::Thumb => "thumb",
        Machine::ChpeX86 => "chpe_x86",
        Machine::Ia64 => "ia64",
        Machine::Ebc => "ebc",
        _ => return None,
    })
}

/// The `meta.pe_subsystem` name of a subsystem value. `None` for an
/// unknown or unnamed one.
fn subsystem(raw: u16) -> Option<&'static str> {
    Some(match Subsystem::from_raw(raw) {
        Subsystem::Native => "native",
        Subsystem::WindowsGui => "windows_gui",
        Subsystem::WindowsCui => "windows_cui",
        Subsystem::Os2Cui => "os2_cui",
        Subsystem::PosixCui => "posix_cui",
        Subsystem::NativeWindows => "native_windows",
        Subsystem::WindowsCeGui => "windows_ce_gui",
        Subsystem::EfiApplication => "efi_application",
        Subsystem::EfiBootServiceDriver => "efi_boot_service_driver",
        Subsystem::EfiRuntimeDriver => "efi_runtime_driver",
        Subsystem::EfiRom => "efi_rom",
        Subsystem::Xbox => "xbox",
        Subsystem::WindowsBootApplication => "windows_boot_application",
        _ => return None,
    })
}

fn path(id: &FileIdentity, volumes: &VolumeMap, out: &mut Bridged) {
    out.computed |= FactSet::PATH;
    if !matches!(id.fs.user_writable, Field::NotRequested) {
        out.computed |= FactSet::PATH_ACL;
    }
    // The opened file's final path, never a claimed name. Without a rule
    // key (a component in a case-sensitive directory, or a volume whose
    // case folding is unknown), names that differ only in case may be
    // different files, which policy's case-insensitive comparison cannot
    // tell apart: no path.
    let Some(final_path) = id
        .fs
        .path
        .computed()
        .filter(|p| !p.claimed && p.rule_key.is_some())
        .and_then(|p| p.final_path.as_deref())
    else {
        return;
    };
    // The OS expands every short name in a final path.
    let mut fact = PathFact::new(final_path, volumes);
    // A stream whose final path lost its stream would read as its host.
    if id.name.stream.is_some() && fact.path.stream().is_none() {
        return;
    }
    if let Some(w) = id.fs.user_writable.computed() {
        fact.user_writable = Some(w.path_user_writable || w.change_perms_by_non_admin);
        fact.user_can_change_acl = Some(w.change_perms_by_non_admin);
    }
    if let Some(v) = id.fs.volume.computed() {
        fact.volume = match v.location.as_str() {
            "os_volume" | "other_fixed" => Some(VolumeKind::Fixed),
            "removable" => Some(VolumeKind::Removable),
            "optical" => Some(VolumeKind::Optical),
            "network" => Some(VolumeKind::Network),
            _ => None,
        };
        fact.drive_type = known(v.drive_type.as_deref());
        fact.bus = known(v.bus_type.as_deref());
    }
    out.facts.path = Some(fact);
}

/// A name fileid reports, unless it says the value is unknown (`unknown`,
/// or `unknown(<n>)` for a bus number it does not name).
fn known(name: Option<&str>) -> Option<String> {
    name.filter(|n| !n.is_empty() && !n.starts_with("unknown"))
        .map(str::to_owned)
}
