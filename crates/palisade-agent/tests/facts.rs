//! The file identity → policy facts bridge (`palisade_agent::facts`,
//! #318, #328): each field's mapping, the fail-closed cases, and the
//! property that a record with any fact removed never evaluates to a more
//! permissive decision. Built on `palisade_fileid`'s synthetic images and
//! signature fixtures; no binary is checked in. Runs on every OS.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

#[path = "../../palisade-fileid/tests/common/mod.rs"]
mod common;

use common::PeBuilder;
use palisade_agent::facts::{Bridged, from_identity};
use palisade_core::VerificationError;
use palisade_core::path::VolumeMap;
use palisade_fileid::authenticode::{
    CertSelection, DigestAlgorithm as FileidDigest, RevocationSet, TrustConfig,
    extract_certificates,
};
use palisade_fileid::hash::{Digest, HashAlgorithm};
use palisade_fileid::identity::{
    Field, FileIdentity, IdentityContext, PathInfo, Tiers, VolumeSummary, WritableSummary,
    identify_bytes,
};
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::Outcome;
use palisade_policy::demand::FactSet;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{ObjectFacts, PathVariables};
use palisade_policy::facts::{SignatureSource, SignerStatus};
use palisade_policy::model::ObjectType;
use palisade_policy::model::{Field as P, Operator, SignerOptions, TbsPosition};
use palisade_policy::test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, TRACE, criterion};
use palisade_policy::unknown::VolumeKind;
use palisade_policy::validate::ValidatedPolicy;
use proptest::prelude::*;

const FILEID: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../palisade-fileid/tests/fixtures"
);

/// 2030-01-01T00:00:00Z: inside every fixture's validity.
const Y2030: i64 = 1_893_456_000;

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FILEID}/{path}")).unwrap()
}

/// The default synthetic image, with `pkcs7` as its one `WIN_CERTIFICATE`.
fn signed_image(pkcs7: &[u8]) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&(u32::try_from(pkcs7.len()).unwrap() + 8).to_le_bytes());
    entry.extend_from_slice(&0x0200_u16.to_le_bytes());
    entry.extend_from_slice(&2_u16.to_le_bytes());
    entry.extend_from_slice(pkcs7);
    while entry.len() % 8 != 0 {
        entry.push(0);
    }
    PeBuilder {
        certificate: Some(entry),
        ..PeBuilder::default()
    }
    .build()
}

fn embedded_root(pkcs7: &[u8]) -> Vec<u8> {
    extract_certificates(&signed_image(pkcs7), CertSelection::All)
        .unwrap()
        .certificates
        .into_iter()
        .find(|c| c.is_root)
        .unwrap()
        .cert
        .der
}

/// The enforce-mode outcome for an executable with `facts`.
fn decide(facts: &ObjectFacts, policy: &ValidatedPolicy) -> Outcome {
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts,
        variables: &PathVariables::new(),
        context: &EvaluationContext::new(),
    };
    Evaluator::new(policy)
        .unwrap()
        .evaluate(&subject, TRACE)
        .outcome()
}

fn bridge(id: &FileIdentity) -> Bridged {
    from_identity(id, &VolumeMap::new())
}

/// A catalog store with nothing loaded: a lookup that finds nothing.
fn empty_store() -> palisade_fileid::catalog::CatalogStore {
    palisade_fileid::catalog::CatalogStoreBuilder::new(
        palisade_fileid::catalog::StoreLimits::default(),
    )
    .build()
}

/// The record of `pkcs7` over the synthetic image, with its root trusted
/// or not, and a catalog lookup that found nothing.
fn signed_record(pkcs7: &str, trusted: bool, revocation: Option<&RevocationSet>) -> FileIdentity {
    let p7 = fixture(pkcs7);
    let mut trust = TrustConfig::new();
    if trusted {
        trust.add_anchor("test root", &embedded_root(&p7)).unwrap();
    }
    let store = empty_store();
    let mut ctx = IdentityContext::untrusted(Y2030);
    ctx.code_trust = &trust;
    ctx.tsa_trust = &trust;
    ctx.catalogs = Some(&store);
    if let Some(r) = revocation {
        ctx.revocation = r;
    }
    identify_bytes(&signed_image(&p7), Some("signed.exe"), Tiers::ALL, &ctx)
}

/// A record with a final path on disk and the context-tier facts, as the
/// agent's Windows reader fills them.
fn with_fs(mut id: FileIdentity, location: &str, path_user_writable: bool) -> FileIdentity {
    id.fs.path = Field::Computed(PathInfo {
        original: r"C:\Tools\signed.exe".into(),
        claimed: false,
        normalized: Some(r"C:\Tools\signed.exe".into()),
        normalize_error: None,
        final_path: Some(r"C:\Tools\signed.exe".into()),
        lexical_key: Some(r"c:\tools\signed.exe".into()),
        rule_key: Some(r"c:\tools\signed.exe".into()),
        final_case_sensitive: Vec::new(),
        final_fold_unknown: false,
    });
    id.fs.volume = Field::Computed(VolumeSummary {
        fs_type: Some("ntfs".into()),
        location: location.into(),
        drive_type: Some("fixed".into()),
        bus_type: Some("nvme".into()),
        is_hotplug: Some(false),
        is_os_volume: Some(true),
        serial: Some(7),
        supports_owner: true,
    });
    id.fs.user_writable = Field::Computed(WritableSummary {
        path_user_writable,
        file_user_writable: path_user_writable,
        first_user_writable_ancestor: None,
        change_perms_by_non_admin: false,
        principals_with_write: Vec::new(),
    });
    id
}

// ---------------------------------------------------------------------------
// Field by field.

#[test]
fn hashes_map_by_field() {
    let image = PeBuilder::default().build();
    let id = identify_bytes(
        &image,
        Some("a.exe"),
        Tiers::ALL,
        &IdentityContext::untrusted(Y2030),
    );
    let b = bridge(&id);
    let h = id.hashes.computed().unwrap();
    let a = h.authenticode.computed().unwrap();
    for (field, want) in [
        (P::HashSha256, h.sha256.as_deref()),
        (P::HashSha1, h.sha1.as_deref()),
        (P::HashMd5, h.md5.as_deref()),
        (P::HashSha384, h.sha384.as_deref()),
        (P::HashSha512, h.sha512.as_deref()),
        (P::HashAuthenticodeSha256, a.sha256.as_deref()),
        (P::HashAuthenticodeSha1, a.sha1.as_deref()),
        (P::HashPageSha256, a.page_sha256.as_deref()),
        (P::HashPageSha1, a.page_sha1.as_deref()),
        (P::HashMsiFuzzySha256, None),
    ] {
        assert_eq!(b.facts.get(field), want, "{field:?}");
    }
    assert!(b.facts.get(P::HashSha256).is_some());
    assert!(b.computed.contains(FactSet::HASHES));

    // A non-conformant image's Authenticode digests are not authoritative.
    let mut odd = id.clone();
    if let Field::Computed(h) = &mut odd.hashes
        && let Field::Computed(a) = &mut h.authenticode
    {
        a.conformant = false;
    }
    let b = bridge(&odd);
    assert_eq!(b.facts.get(P::HashAuthenticodeSha256), None);
    assert_eq!(b.facts.get(P::HashPageSha256), None);
    assert!(b.facts.get(P::HashSha256).is_some());

    // An empty file's digests identify nothing.
    let empty = identify_bytes(
        b"",
        Some("e.exe"),
        Tiers::ALL,
        &IdentityContext::untrusted(Y2030),
    );
    let b = bridge(&empty);
    assert_eq!(b.facts.get(P::HashSha256), None);
    assert!(b.computed.contains(FactSet::HASHES));

    // Hashes not computed: no fact, and the class is not covered.
    let stat = identify_bytes(
        &image,
        Some("a.exe"),
        palisade_fileid::identity::Tier::Stat.into(),
        &IdentityContext::untrusted(Y2030),
    );
    let b = bridge(&stat);
    assert_eq!(b.facts.get(P::HashSha256), None);
    assert!(!b.computed.contains(FactSet::HASHES));
}

#[test]
fn metadata_maps_by_field() {
    let spec = common::VersionSpec {
        fixed: Some(common::fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![("040904B0", common::all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    };
    let id = identify_bytes(
        &common::with_version(&spec).build(),
        Some("renamed.exe"),
        Tiers::ALL,
        &IdentityContext::untrusted(Y2030),
    );
    let b = bridge(&id);
    for (field, want) in [
        (P::MetaOriginalFilename, Some("extool.exe")),
        (P::MetaInternalName, Some("extool")),
        (P::MetaFileDescription, Some("Example tool")),
        (P::MetaProductName, Some("Example Suite")),
        (P::MetaCompanyName, Some("Example Org")),
        (P::MetaLegalCopyright, Some("(c) Example Org")),
        (P::MetaLanguage, Some("040904B0")),
        (P::MetaFileVersion, Some("1.2.3.4")),
        (P::MetaProductVersion, Some("1.2.0.0")),
        (P::MetaFileNameFallback, Some("extool.exe")),
        (P::MetaPeMachine, Some("amd64")),
        (P::MetaPeSubsystem, Some("windows_gui")),
        (P::MetaIsDotnet, Some("false")),
    ] {
        assert_eq!(b.facts.get(field), want, "{field:?}");
    }
    let size = id.size.computed().unwrap().to_string();
    assert_eq!(b.facts.get(P::MetaFileSize), Some(size.as_str()));
    assert!(b.computed.contains(FactSet::METADATA));
    // A PE with no version resource: the effective name would be the name
    // on disk, which a byte upload does not have, so it is unknown; never
    // the name hint.
    let bare = identify_bytes(
        &PeBuilder::default().build(),
        Some("claimed.exe"),
        Tiers::ALL,
        &IdentityContext::untrusted(Y2030),
    );
    let b = bridge(&bare);
    assert_eq!(b.facts.get(P::MetaFileNameFallback), None);
    assert_eq!(b.facts.get(P::MetaOriginalFilename), None);
    // With a final path, it is the final name.
    let b = bridge(&with_fs(bare, "os_volume", false));
    assert_eq!(b.facts.get(P::MetaFileNameFallback), Some("signed.exe"));
}

#[test]
fn pe_names_cover_every_named_value() {
    for (machine, want) in [
        (0x014c, Some("i386")),
        (0xaa64, Some("arm64")),
        (0xa641, Some("arm64_ec")),
        (0x0000, None),
        (0x1234, None),
    ] {
        let id = identify_bytes(
            &PeBuilder {
                machine,
                ..PeBuilder::default()
            }
            .build(),
            Some("a.exe"),
            Tiers::ALL,
            &IdentityContext::untrusted(Y2030),
        );
        assert_eq!(
            bridge(&id).facts.get(P::MetaPeMachine),
            want,
            "{machine:#x}"
        );
    }
    for (subsystem, want) in [
        (2, Some("windows_gui")),
        (1, Some("native")),
        (10, Some("efi_application")),
        (0, None),
        (99, None),
    ] {
        let id = identify_bytes(
            &PeBuilder {
                subsystem,
                ..PeBuilder::default()
            }
            .build(),
            Some("a.exe"),
            Tiers::ALL,
            &IdentityContext::untrusted(Y2030),
        );
        assert_eq!(
            bridge(&id).facts.get(P::MetaPeSubsystem),
            want,
            "{subsystem}"
        );
    }
}

#[test]
fn installer_facts_map_by_field() {
    let id = identify_bytes(
        &fixture("installer/product.msi"),
        Some("product.msi"),
        Tiers::ALL,
        &IdentityContext::untrusted(Y2030),
    );
    let i = id.installer.computed().unwrap();
    let b = bridge(&id);
    for (field, want) in [
        (P::MsiProductCode, i.product_code.as_deref()),
        (P::MsiUpgradeCode, i.upgrade_code.as_deref()),
        (P::MsiPackageCode, i.package_code.as_deref()),
        (P::MsiProductName, i.product_name.as_deref()),
        (P::MsiManufacturer, i.manufacturer.as_deref()),
        (
            P::MsiProductVersion,
            i.product_version_quad
                .as_deref()
                .or(i.product_version.as_deref()),
        ),
    ] {
        assert!(want.is_some(), "{field:?}: the fixture has it");
        assert_eq!(b.facts.get(field), want, "{field:?}");
    }
    // Not a PE: no PE facts.
    assert_eq!(b.facts.get(P::MetaPeMachine), None);
    assert!(b.computed.contains(FactSet::METADATA));
    // Without the deep tier, the installer facts are not known, so the
    // class is not covered.
    let early = identify_bytes(
        &fixture("installer/product.msi"),
        Some("product.msi"),
        Tiers::EXECUTION,
        &IdentityContext::untrusted(Y2030),
    );
    let b = bridge(&early);
    assert_eq!(b.facts.get(P::MsiProductCode), None);
    assert!(!b.computed.contains(FactSet::METADATA));
}

#[test]
fn path_facts_map_from_the_context_tier() {
    let base = signed_record("authenticode/rsa2048-sha256.p7", false, None);
    // A byte upload has no path at all, and nothing more to ask for.
    assert!(bridge(&base).facts.path.is_none());
    assert!(bridge(&base).computed.contains(FactSet::PATH));
    assert_eq!(base.fs.user_writable, Field::NotApplicable);
    assert!(bridge(&base).computed.contains(FactSet::PATH_ACL));

    let b = bridge(&with_fs(base.clone(), "os_volume", false));
    let p = b.facts.path.as_ref().unwrap();
    assert_eq!(p.path.as_str(), r"C:\Tools\signed.exe");
    assert_eq!(p.volume, Some(VolumeKind::Fixed));
    assert_eq!(p.user_writable, Some(false));
    assert_eq!(p.user_can_change_acl, Some(false));
    assert_eq!(p.drive_type.as_deref(), Some("fixed"));
    assert_eq!(p.bus.as_deref(), Some("nvme"));
    assert!(p.acl_proven());
    assert!(b.computed.contains(FactSet::PATH_ACL));

    for (location, want) in [
        ("other_fixed", Some(VolumeKind::Fixed)),
        ("removable", Some(VolumeKind::Removable)),
        ("optical", Some(VolumeKind::Optical)),
        ("network", Some(VolumeKind::Network)),
        ("ram_disk", None),
        ("virtual_disk", None),
        ("unknown", None),
    ] {
        let b = bridge(&with_fs(base.clone(), location, false));
        let p = b.facts.path.unwrap();
        assert_eq!(p.volume, want, "{location}");
        assert_eq!(
            p.acl_proven(),
            want == Some(VolumeKind::Fixed),
            "{location}"
        );
    }

    // User-writable, or a non-administrator can change the ACL: not proven.
    let b = bridge(&with_fs(base.clone(), "os_volume", true));
    assert_eq!(b.facts.path.unwrap().user_writable, Some(true));
    let mut acl = with_fs(base.clone(), "os_volume", false);
    if let Field::Computed(w) = &mut acl.fs.user_writable {
        w.change_perms_by_non_admin = true;
    }
    let p = bridge(&acl).facts.path.unwrap();
    assert_eq!(p.user_writable, Some(true));
    assert_eq!(p.user_can_change_acl, Some(true));

    // An unknown bus or drive type is no fact.
    let mut unk = with_fs(base.clone(), "os_volume", false);
    if let Field::Computed(v) = &mut unk.fs.volume {
        v.bus_type = Some("unknown(42)".into());
        v.drive_type = Some("unknown".into());
    }
    let p = bridge(&unk).facts.path.unwrap();
    assert_eq!(p.bus, None);
    assert_eq!(p.drive_type, None);

    // A claimed path, a path with no final form, or one with no rule key
    // (case-sensitive directory, unknown fold) is no path.
    for change in [
        (|p: &mut PathInfo| p.claimed = true) as fn(&mut PathInfo),
        |p| p.final_path = None,
        |p| p.rule_key = None,
    ] {
        let mut id = with_fs(base.clone(), "os_volume", false);
        if let Field::Computed(p) = &mut id.fs.path {
            change(p);
        }
        assert!(bridge(&id).facts.path.is_none());
    }

    // The ACL tier did not run: no ACL facts, never "not writable".
    let mut no_acl = with_fs(base, "os_volume", false);
    no_acl.fs.user_writable = Field::NotRequested;
    let b = bridge(&no_acl);
    let p = b.facts.path.unwrap();
    assert_eq!(p.user_writable, None);
    assert!(!p.acl_proven());
    assert!(!b.computed.contains(FactSet::PATH_ACL));
}

// ---------------------------------------------------------------------------
// Signers.

#[test]
fn a_trusted_signature_carries_every_signer_fact() {
    let id = signed_record("authenticode/rsa2048-sha256.p7", true, None);
    let b = bridge(&id);
    assert!(b.computed.contains(FactSet::SIGNERS));
    let signers = b.facts.signers.as_ref().unwrap();
    assert_eq!(signers.len(), 1);
    let s = &signers[0];
    assert_eq!(s.status, SignerStatus::Valid);
    assert_eq!(s.source, SignatureSource::Embedded);
    let chain = id.signatures.computed().unwrap()[0].chain.clone().unwrap();
    let (leaf, root) = (&chain.certs[0], chain.certs.last().unwrap());
    assert!(s.publisher.as_deref().unwrap().contains("Signer"));
    assert_eq!(s.publisher, leaf.subject_cn);
    assert_eq!(s.issuer, leaf.issuer_cn);
    assert_eq!(
        s.leaf_thumbprint_sha256.as_ref(),
        Some(&leaf.sha256_thumbprint)
    );
    let d = &s.details;
    assert_eq!(d.subject_organization, leaf.subject_o);
    assert_eq!(d.subject_dn, leaf.subject_rfc4514);
    assert_eq!(d.leaf_thumbprint_sha1.as_ref(), Some(&leaf.sha1_thumbprint));
    assert_eq!(d.leaf_tbs_hash, leaf.tbs_hash);
    assert_eq!(d.leaf_spki_sha256.as_ref(), Some(&leaf.spki_sha256));
    assert_eq!(d.root_spki_sha256.as_ref(), Some(&root.spki_sha256));
    assert_eq!(d.root_tbs_hash, root.tbs_hash);
    assert_eq!(
        d.root_thumbprint_sha256.as_ref(),
        Some(&root.sha256_thumbprint)
    );
    assert_eq!(d.root_thumbprint_sha1.as_ref(), Some(&root.sha1_thumbprint));
    // Leaf issued by the root: no intermediates, no PCA.
    assert_eq!(chain.certs.len(), 2);
    assert_eq!(d.intermediate_spki_sha256, Some(Vec::new()));
    assert_eq!(d.intermediate_tbs_hashes, Some(Vec::new()));
    assert_eq!(d.pca, None);
    assert_eq!(
        d.eku,
        Some(leaf.extended_key_usage.clone().unwrap_or_default())
    );
    let keys = d.keys.as_ref().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| k.bits == 2048));
    assert_eq!(
        d.algorithms.as_deref(),
        Some(
            &[
                palisade_policy::facts::DigestAlgorithm::Sha256,
                palisade_policy::facts::DigestAlgorithm::Sha256,
                palisade_policy::facts::DigestAlgorithm::Sha256,
                palisade_policy::facts::DigestAlgorithm::Sha256,
            ][..]
        )
    );
    assert_eq!(d.timestamp, None);
    assert_eq!(d.countersigned, Some(false));
}

#[test]
fn signer_spki_criteria_match_the_bridged_key() {
    let id = signed_record("authenticode/rsa2048-sha256.p7", true, None);
    let b = bridge(&id);
    let leaf_spki = b.facts.signers.as_ref().unwrap()[0]
        .details
        .leaf_spki_sha256
        .clone()
        .unwrap();
    let policy = |position, value: &str| {
        let mut c = criterion(P::SignerSpkiSha256, Operator::Equals, &[value]);
        if let palisade_policy::model::Match::Criterion(c) = &mut c {
            c.signer = Some(Box::new(SignerOptions {
                position: Some(position),
                ..SignerOptions::default()
            }));
        }
        PolicyBuilder::new()
            .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, c)))
            .validate()
    };
    // An allow on the leaf key lets it run; the same key at the root's
    // position, or another key, does not.
    assert_eq!(
        decide(&b.facts, &policy(TbsPosition::Leaf, &leaf_spki)),
        Outcome::Allowed
    );
    let other = "ab".repeat(32);
    assert_eq!(
        decide(&b.facts, &policy(TbsPosition::Leaf, &other)),
        Outcome::Blocked
    );
    assert_eq!(
        decide(&b.facts, &policy(TbsPosition::Root, &leaf_spki)),
        Outcome::Blocked
    );
    // Without the trust tier the key is unknown: never allowed.
    let mut early = id.clone();
    early.signing_state = Field::NotRequested;
    assert_eq!(
        decide(
            &bridge(&early).facts,
            &policy(TbsPosition::Leaf, &leaf_spki)
        ),
        Outcome::Blocked
    );
}

#[test]
fn untrusted_and_revoked_signers_never_vouch() {
    // Nothing trusted: `untrusted_root`, with its facts.
    let b = bridge(&signed_record(
        "authenticode/rsa2048-sha256.p7",
        false,
        None,
    ));
    let s = &b.facts.signers.as_ref().unwrap()[0];
    assert_eq!(s.status, SignerStatus::UntrustedRoot);
    assert!(s.details.leaf_spki_sha256.is_some());

    // The file's hash revoked: `revoked`.
    let id = signed_record("authenticode/rsa2048-sha256.p7", true, None);
    let sha256 = id.hashes.computed().unwrap().sha256.clone().unwrap();
    let mut revocation = RevocationSet::new();
    revocation.add_file_hash(Digest::parse(HashAlgorithm::Sha256, &sha256).unwrap());
    let revoked = signed_record("authenticode/rsa2048-sha256.p7", true, Some(&revocation));
    let b = bridge(&revoked);
    assert_eq!(
        b.facts.signers.as_ref().unwrap()[0].status,
        SignerStatus::Revoked
    );

    // A SHA-1 primary signature is valid but vouches for nothing: the
    // SHA-1 signature never reads as trusted.
    let b = bridge(&signed_record(
        "authenticode/rsa2048-sha1-nested-sha256.p7",
        true,
        None,
    ));
    let signers = b.facts.signers.unwrap();
    assert!(signers.len() >= 2);
    let id = signed_record("authenticode/rsa2048-sha1-nested-sha256.p7", true, None);
    for (s, sig) in signers.iter().zip(id.signatures.computed().unwrap()) {
        let sha1 = sig.digest_alg == Some(FileidDigest::Sha1)
            || sig.signer_digest_alg == Some(FileidDigest::Sha1);
        if sha1 {
            assert!(!s.status.is_trusted(), "{s:?}");
        }
    }
}

#[test]
fn embedded_status_follows_the_record() {
    let base = signed_record("authenticode/rsa2048-sha256.p7", true, None);
    let status = |change: fn(&mut palisade_fileid::identity::SignatureSummary)| {
        let mut id = base.clone();
        if let Field::Computed(list) = &mut id.signatures {
            change(&mut list[0]);
        }
        bridge(&id)
            .facts
            .signers
            .map(|s| (s[0].status, s[0].details.leaf_spki_sha256.is_some()))
    };
    assert_eq!(status(|_| {}), Some((SignerStatus::Valid, true)));
    // Expired with a trusted timestamp; expired without one (valid only
    // because policy ignored expiry) is not vouched for.
    assert_eq!(
        status(|s| {
            s.expired_now = Some(true);
            s.trusted_signing_time = Some(1);
        }),
        Some((SignerStatus::ValidExpiredTimestamped, true))
    );
    assert_eq!(
        status(|s| s.expired_now = Some(true)),
        Some((SignerStatus::Expired, true))
    );
    // Not known whether it expired: the list is unknown.
    assert_eq!(status(|s| s.expired_now = None), None);
    assert_eq!(
        status(|s| s.trusted = false),
        Some((SignerStatus::UntrustedRoot, true))
    );
    assert_eq!(
        status(|s| s.validity_error = VerificationError::Expired),
        Some((SignerStatus::Expired, true))
    );
    assert_eq!(
        status(|s| s.validity_error = VerificationError::Revoked),
        Some((SignerStatus::Revoked, true))
    );
    assert_eq!(
        status(|s| s.signer_digest_alg = Some(FileidDigest::Sha1)),
        Some((SignerStatus::UntrustedRoot, true))
    );
    assert_eq!(
        status(|s| s.status = "digest_mismatch"),
        Some((SignerStatus::DigestMismatch, true))
    );
    // A signature that does not verify: no facts at all.
    assert_eq!(
        status(|s| s.status = "bad_signature"),
        Some((SignerStatus::UntrustedRoot, false))
    );
    // An incomplete chain: the leaf's facts, nothing about the root.
    let mut id = base.clone();
    if let Field::Computed(list) = &mut id.signatures {
        list[0].chain.as_mut().unwrap().complete = false;
    }
    let s = bridge(&id).facts.signers.unwrap().remove(0);
    assert!(s.details.leaf_spki_sha256.is_some());
    assert_eq!(s.details.root_spki_sha256, None);
    assert_eq!(s.details.intermediate_spki_sha256, None);
    assert_eq!(s.details.keys, None);
    assert_eq!(s.details.algorithms, None);
}

#[test]
fn an_incomplete_signature_list_is_unknown() {
    let base = signed_record("authenticode/rsa2048-sha256.p7", true, None);
    assert!(bridge(&base).facts.signers.is_some());
    // No catalog lookup: the file may be catalog-signed.
    let mut no_catalogs = base.clone();
    if let Field::Computed(s) = &mut no_catalogs.signing_state {
        s.catalog = palisade_fileid::identity::CatalogState::NotChecked;
    }
    assert!(bridge(&no_catalogs).facts.signers.is_none());
    no_catalogs = base.clone();
    no_catalogs.catalog_matches = Field::NotRequested;
    assert!(bridge(&no_catalogs).facts.signers.is_none());
    // Embedded signatures not read.
    let mut unread = base.clone();
    unread.signatures = Field::Unavailable("x".into());
    assert!(bridge(&unread).facts.signers.is_none());
    // As many signatures as the reader's limit: there may be more.
    let mut full = base.clone();
    if let Field::Computed(list) = &mut full.signatures {
        let one = list[0].clone();
        list.resize(palisade_fileid::authenticode::MAX_SIGNATURES, one);
    }
    assert!(bridge(&full).facts.signers.is_none());
    // The trust tier did not run: no facts and the class is not covered.
    let mut early = base;
    early.signing_state = Field::NotRequested;
    let b = bridge(&early);
    assert!(b.facts.signers.is_none());
    assert!(!b.computed.contains(FactSet::SIGNERS));
}

#[test]
fn an_unsigned_file_is_known_unsigned() {
    let store = empty_store();
    let mut ctx = IdentityContext::untrusted(Y2030);
    ctx.catalogs = Some(&store);
    let id = identify_bytes(
        &PeBuilder::default().build(),
        Some("a.exe"),
        Tiers::ALL,
        &ctx,
    );
    assert_eq!(bridge(&id).facts.signers, Some(Vec::new()));
}

// ---------------------------------------------------------------------------
// A missing fact never makes a decision more permissive (ADR 0018).

/// How permissive an outcome is: higher lets more run.
fn rank(o: Outcome) -> u8 {
    match o {
        Outcome::Blocked => 0,
        Outcome::PendingUser => 1,
        Outcome::AllowedAudit | Outcome::AllowedOverride => 2,
        Outcome::Ignored => 3,
        Outcome::Allowed => 4,
    }
}

/// Allow and deny rules over each bridged fact family, positive and
/// negated, so a fact that disappears could flip any of them.
fn policies(id: &FileIdentity) -> Vec<ValidatedPolicy> {
    let b = bridge(id);
    let sha = b.facts.get(P::HashSha256).unwrap_or("00").to_owned();
    let signer = b.facts.signers.as_ref().and_then(|s| s.first().cloned());
    let spki = signer
        .as_ref()
        .and_then(|s| s.details.leaf_spki_sha256.clone())
        .unwrap_or_else(|| "cd".repeat(32));
    let publisher = signer
        .and_then(|s| s.publisher)
        .unwrap_or_else(|| "Nobody".into());
    let trees = vec![
        criterion(P::HashSha256, Operator::Equals, &[&sha]),
        criterion(P::SignerPublisher, Operator::Equals, &[&publisher]),
        criterion(P::SignerSpkiSha256, Operator::Equals, &[&spki]),
        criterion(P::PathDirectory, Operator::StartsWith, &[r"C:\Tools"]),
        criterion(P::MetaPeMachine, Operator::Equals, &["amd64"]),
        criterion(P::MetaFileSize, Operator::Gt, &["10"]),
        criterion(P::PathDriveType, Operator::Equals, &["fixed"]),
    ];
    let mut out = Vec::new();
    for tree in trees {
        let negated = palisade_policy::test_util::not(tree.clone());
        let anchor = criterion(P::HashSha256, Operator::Equals, &[&sha]);
        for (allow, t) in [
            (
                true,
                palisade_policy::test_util::all(vec![anchor.clone(), tree.clone()]),
            ),
            (false, tree.clone()),
            (false, negated),
        ] {
            let set = if allow {
                RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, t))
            } else {
                RuleSetBuilder::blocklist(1).rule(RuleBuilder::deny(1, t))
            };
            let validated = PolicyBuilder::new().rule_set(set).build().validate();
            if let Ok(v) = validated {
                out.push(v);
            }
        }
    }
    out
}

/// Every way to take one fact out of a record, as fileid would report it
/// had the fact not been computed.
/// A named way to take a fact out of a record.
type Removal = (&'static str, fn(&mut FileIdentity));

fn removals() -> Vec<Removal> {
    vec![
        ("hashes", |id| id.hashes = Field::NotRequested),
        ("authenticode", |id| {
            if let Field::Computed(h) = &mut id.hashes {
                h.authenticode = Field::Unavailable("x".into());
            }
        }),
        ("signing_state", |id| id.signing_state = Field::NotRequested),
        ("signatures", |id| {
            id.signatures = Field::Unavailable("x".into())
        }),
        ("catalogs", |id| id.catalog_matches = Field::NotRequested),
        ("chain", |id| {
            if let Field::Computed(l) = &mut id.signatures {
                for s in l {
                    s.chain = None;
                }
            }
        }),
        ("expired_now", |id| {
            if let Field::Computed(l) = &mut id.signatures {
                for s in l {
                    s.expired_now = None;
                }
            }
        }),
        ("timestamp", |id| {
            if let Field::Computed(l) = &mut id.signatures {
                for s in l {
                    s.rfc3161_timestamp = None;
                    s.trusted_signing_time = None;
                }
            }
        }),
        ("leaf_names", |id| {
            if let Field::Computed(l) = &mut id.signatures {
                for c in l.iter_mut().filter_map(|s| s.chain.as_mut()) {
                    for cert in &mut c.certs {
                        cert.subject_cn = None;
                        cert.subject_o = None;
                        cert.issuer_cn = None;
                        cert.subject_rfc4514 = None;
                        cert.extended_key_usage = None;
                        cert.key_bits = None;
                        cert.signature_digest = None;
                    }
                }
            }
        }),
        ("pe", |id| id.pe = Field::Unavailable("x".into())),
        ("size", |id| id.size = Field::NotRequested),
        ("path", |id| id.fs.path = Field::NotRequested),
        ("volume", |id| id.fs.volume = Field::Unavailable("x".into())),
        ("writable", |id| {
            id.fs.user_writable = Field::Unavailable("x".into())
        }),
        ("installer", |id| id.installer = Field::NotRequested),
    ]
}

fn records() -> Vec<FileIdentity> {
    vec![
        with_fs(
            signed_record("authenticode/rsa2048-sha256.p7", true, None),
            "os_volume",
            false,
        ),
        with_fs(
            signed_record("authenticode/rsa2048-sha256.p7", false, None),
            "network",
            true,
        ),
        with_fs(
            signed_record("authenticode/rsa2048-sha1-nested-sha256.p7", true, None),
            "removable",
            false,
        ),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any set of facts removed from a record never lets more run.
    #[test]
    fn removing_facts_never_relaxes_a_decision(
        which in 0usize..3,
        mask in proptest::collection::vec(any::<bool>(), 15),
    ) {
        let full = records().remove(which);
        let mut reduced = full.clone();
        for ((_, remove), on) in removals().into_iter().zip(&mask) {
            if *on {
                remove(&mut reduced);
            }
        }
        let (a, b) = (bridge(&full), bridge(&reduced));
        for policy in policies(&full) {
            let before = decide(&a.facts, &policy);
            let after = decide(&b.facts, &policy);
            prop_assert!(
                rank(after) <= rank(before),
                "{before:?} -> {after:?} with {:?}",
                removals().iter().zip(&mask).filter(|(_, on)| **on).map(|((n, _), _)| *n).collect::<Vec<_>>()
            );
        }
    }
}

/// Each single removal, checked exhaustively, with a name on failure.
#[test]
fn removing_any_one_fact_never_relaxes_a_decision() {
    for full in records() {
        let a = bridge(&full);
        let policies = policies(&full);
        assert!(policies.len() >= 10, "{}", policies.len());
        // The trusted record is allowed by some rule, so the property is
        // tested against permissive decisions too.
        if full.trusted_signer().is_some() {
            assert!(
                policies
                    .iter()
                    .any(|p| decide(&a.facts, p) == Outcome::Allowed)
            );
        }
        for (name, remove) in removals() {
            let mut reduced = full.clone();
            remove(&mut reduced);
            let b = bridge(&reduced);
            // A removed fact is gone or the same, never another value.
            for f in P::ALL {
                if let Some(v) = b.facts.get(f) {
                    assert_eq!(a.facts.get(f), Some(v), "{name}: {f:?}");
                }
            }
            for policy in &policies {
                let before = decide(&a.facts, policy);
                let after = decide(&b.facts, policy);
                assert!(
                    rank(after) <= rank(before),
                    "{name}: {before:?} -> {after:?}"
                );
            }
        }
    }
}
