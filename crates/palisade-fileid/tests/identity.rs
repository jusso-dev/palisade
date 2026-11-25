//! Tests of the unified file identity record (#55): tiers, merging,
//! comparison, the serialised form and the no-panic guarantee. The
//! manifest-driven corpus is `identity_corpus.rs`.

// Test code: helpers may unwrap, since a failure should fail loudly.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use palisade_fileid::identity::{
    Field, IdentityContext, IdentityStrength, MASQUERADE_THRESHOLD, RuleLevel, SCHEMA_VERSION,
    SigningStateKind, Tier, Tiers, compare, identify, identify_bytes, recommend,
};
use proptest::prelude::*;

const NOW: i64 = 1_795_564_800;

fn ctx() -> IdentityContext<'static> {
    IdentityContext::untrusted(NOW)
}

fn tool_image(version: (u16, u16, u16, u16)) -> Vec<u8> {
    let spec = VersionSpec {
        fixed: Some(fixed_info(version, version)),
        tables: vec![("040904B0", all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    };
    with_version(&spec).build()
}

#[test]
fn tiers_compute_only_what_was_asked() {
    let image = PeBuilder::default().build();
    let stat = identify_bytes(&image, Some("a.exe"), Tiers::only(Tier::Stat), &ctx());
    assert_eq!(stat.size, Field::Computed(1536));
    assert_eq!(stat.pe, Field::NotRequested);
    assert_eq!(stat.hashes, Field::NotRequested);
    assert_eq!(stat.signing_state, Field::NotRequested);
    assert_eq!(stat.computed_tiers.iter().collect::<Vec<_>>(), [Tier::Stat]);
    // The PE checks need the classify tier, so they are open, not clean.
    assert!(stat.masquerade.unassessed.contains(&"name_mismatch"));

    let classify = identify_bytes(&image, Some("a.exe"), Tier::Classify.into(), &ctx());
    assert!(classify.pe.is_computed());
    assert_eq!(classify.hashes, Field::NotRequested);
    let kind = classify.kind.computed().unwrap();
    assert_eq!(kind.content_kind, "pe");
    assert_eq!(kind.pe_sub_kind.as_deref(), Some("exe"));
    assert!(kind.executable_content);
    assert_eq!(kind.mismatch_severity, "none");

    // The trust tier needs the digests, so it computes and reports them.
    let trust = identify_bytes(&image, Some("a.exe"), Tier::Trust.into(), &ctx());
    assert!(trust.hashes.is_computed());
    assert!(trust.signing_state.is_computed());
    assert!(trust.computed_tiers.contains(Tier::Hash));
    assert_eq!(trust.pe, Field::NotRequested);

    let all = identify_bytes(&image, Some("a.exe"), Tiers::ALL, &ctx());
    assert!(matches!(all.installer, Field::NotYetSupported(_)));
    assert!(matches!(all.script, Field::NotYetSupported(p) if p.issues == [52]));
    // Uploads have no file system context.
    assert_eq!(all.fs.owner, Field::NotApplicable);
    assert!(!all.computed_tiers.contains(Tier::Deep));
    assert!(all.computed_tiers.contains(Tier::Trust));
}

#[test]
fn merging_tiers_equals_computing_them_together() {
    let image = tool_image((1, 2, 3, 4));
    let mut early = identify_bytes(&image, Some("extool.exe"), Tiers::EXECUTION, &ctx());
    let late = identify_bytes(
        &image,
        Some("extool.exe"),
        [Tier::Context, Tier::Deep].into_iter().collect(),
        &ctx(),
    );
    assert!(early.merge(late, &ctx()));
    let all = identify_bytes(&image, Some("extool.exe"), Tiers::ALL, &ctx());
    assert_eq!(early, all);
}

#[test]
fn merging_refuses_another_file() {
    let a = PeBuilder::default().build();
    let b = PeBuilder::dll().build();
    let mut x = identify_bytes(&a, None, Tiers::EXECUTION, &ctx());
    let before = x.clone();
    let y = identify_bytes(&b, None, Tiers::ALL, &ctx());
    assert!(!x.merge(y, &ctx()));
    assert_eq!(x, before);
}

#[test]
fn compare_reports_rule_relevant_differences() {
    let v1 = identify_bytes(
        &tool_image((1, 2, 3, 4)),
        Some("extool.exe"),
        Tiers::ALL,
        &ctx(),
    );
    let v2 = identify_bytes(
        &tool_image((2, 0, 0, 0)),
        Some("extool.exe"),
        Tiers::ALL,
        &ctx(),
    );
    let diffs = compare(&v1, &v2);
    let names: Vec<&str> = diffs.iter().map(|d| d.attribute).collect();
    assert!(names.contains(&"sha256"), "{names:?}");
    assert!(names.contains(&"file_version"), "{names:?}");
    assert!(!names.contains(&"product_name"), "{names:?}");
    assert!(!names.contains(&"original_file_name"), "{names:?}");
    assert!(compare(&v1, &v1).is_empty());
}

#[test]
fn strengths_follow_the_issue_table() {
    let image = PeBuilder::default().build();
    let id = identify_bytes(&image, Some("a.exe"), Tiers::ALL, &ctx());
    let strength = |name: &str| {
        id.strengths
            .iter()
            .find(|s| s.attribute == name)
            .map(|s| s.strength)
    };
    assert_eq!(strength("sha256"), Some(IdentityStrength::Strong));
    assert_eq!(
        strength("authenticode_sha256"),
        Some(IdentityStrength::Strong)
    );
    assert_eq!(strength("sha1"), Some(IdentityStrength::Insecure));
    assert_eq!(strength("md5"), Some(IdentityStrength::Insecure));
    assert_eq!(
        strength("authenticode_sha1"),
        Some(IdentityStrength::Insecure)
    );
    assert_eq!(strength("file_name"), Some(IdentityStrength::Weak));
    assert_eq!(strength("signer_chain"), None, "no signer");

    let empty = identify_bytes(&[], Some("e.exe"), Tiers::ALL, &ctx());
    assert!(
        empty
            .strengths
            .iter()
            .filter(|s| s.attribute.starts_with("sha") || s.attribute == "md5")
            .all(|s| s.strength == IdentityStrength::Insecure)
    );
    assert_eq!(recommend(&empty).level, RuleLevel::None);

    let tool = identify_bytes(
        &tool_image((1, 0, 0, 0)),
        Some("extool.exe"),
        Tiers::ALL,
        &ctx(),
    );
    let weak = |name: &str| {
        tool.strengths
            .iter()
            .any(|s| s.attribute == name && s.strength == IdentityStrength::Weak)
    };
    for name in [
        "original_file_name",
        "company_name",
        "product_name",
        "file_description",
        "internal_name",
    ] {
        assert!(weak(name), "{name} on an unsigned file is weak");
    }
}

#[test]
fn non_conformant_images_hash_by_the_flat_digest() {
    // A certificate table that is not the last thing in the file makes the
    // image non-conformant (#47).
    let image = PeBuilder {
        certificate: Some(vec![0; 16]),
        overlay: b"trailing".to_vec(),
        ..PeBuilder::default()
    }
    .build();
    let id = identify_bytes(&image, Some("a.exe"), Tiers::ALL, &ctx());
    let h = id.hashes.computed().unwrap();
    assert_eq!(h.authoritative, "sha256");
    assert!(!h.authenticode.computed().unwrap().conformant);
    assert!(
        id.strengths
            .iter()
            .any(|s| s.attribute == "authenticode_sha256"
                && s.strength == IdentityStrength::Insecure)
    );
    // The zeroed certificate table is a broken signature, so the file is
    // invalid and gets no allow rule at all.
    let state = id.signing_state.computed().unwrap();
    assert_eq!(state.state, SigningStateKind::Invalid);
    assert_eq!(recommend(&id).level, RuleLevel::None);

    // Unsigned and non-conformant: a gap before the first section's data
    // (its `PointerToRawData` moved one sector on, with the bytes padded).
    // A hash rule on the flat digest, never on the Authenticode one.
    let mut gapped = PeBuilder::default().build();
    let ptr = PeBuilder::default().section_table_offset() + 20;
    gapped[ptr..ptr + 4].copy_from_slice(&0x600_u32.to_le_bytes());
    let mut padded = gapped[..0x400].to_vec();
    padded.extend(std::iter::repeat_n(0_u8, 0x200));
    padded.extend_from_slice(&gapped[0x400..]);
    let id = identify_bytes(&padded, Some("a.exe"), Tiers::ALL, &ctx());
    let h = id.hashes.computed().unwrap();
    let a = h.authenticode.computed().unwrap();
    assert!(!a.conformant, "{a:?}");
    assert!(
        a.non_conformance.iter().any(|r| r.contains("start")),
        "{a:?}"
    );
    assert_eq!(h.authoritative, "sha256");
    assert_eq!(
        id.signing_state.computed().unwrap().state,
        SigningStateKind::Unverified
    );
    let rec = recommend(&id);
    assert_eq!(rec.level, RuleLevel::Hash);
    assert_eq!(rec.values[0].0, "sha256");
}

#[test]
fn masquerade_blocks_recommendations() {
    let image = tool_image((1, 0, 0, 0));
    let id = identify_bytes(&image, Some("invoice\u{202e}fdp.exe"), Tiers::ALL, &ctx());
    assert!(id.masquerade.score >= MASQUERADE_THRESHOLD);
    assert_eq!(recommend(&id).level, RuleLevel::None);
}

#[test]
fn serialised_form_is_stable() {
    let image = PeBuilder::default().build();
    let id = identify_bytes(&image, Some("a.exe"), Tiers::EXECUTION, &ctx());
    let v = serde_json::to_value(&id).unwrap();
    assert_eq!(v["schema"], SCHEMA_VERSION);
    assert_eq!(
        v["requested_tiers"],
        serde_json::json!(["stat", "classify", "hash", "trust"])
    );
    assert_eq!(
        v["size"],
        serde_json::json!({"status": "computed", "value": 1536})
    );
    assert_eq!(
        v["fs"]["owner"],
        serde_json::json!({"status": "not_requested"})
    );
    assert_eq!(v["kind"]["status"], "computed");
    assert_eq!(v["kind"]["value"]["content_kind"], "pe");
    assert_eq!(v["kind"]["value"]["extension_kind"], "pe");
    assert_eq!(
        v["installer"],
        serde_json::json!({"status": "not_requested"})
    );
    assert_eq!(v["signing_state"]["value"]["state"], "unverified");
    assert_eq!(
        v["hashes"]["value"]["authenticode"]["value"]["sha256"],
        "5d876fe0b3bdd41254d4349c547926bd02e4fa093498f289e712a29027f2589f"
    );
    // Every top-level group is present whatever was computed, so the shape
    // of the record never depends on the tiers.
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    for k in [
        "schema",
        "library_version",
        "path",
        "name_hint",
        "requested_tiers",
        "computed_tiers",
        "name",
        "size",
        "timestamps",
        "kind",
        "pe",
        "hashes",
        "signing_state",
        "signatures",
        "catalog_matches",
        "installer",
        "package",
        "script",
        "fs",
        "derived",
        "masquerade",
        "strengths",
        "errors",
    ] {
        assert!(keys.contains(&k), "missing {k}");
    }
    assert_eq!(keys.len(), 23, "{keys:?}");
}

#[test]
fn identify_reads_a_file() {
    let dir = std::env::temp_dir().join(format!("palisade-identity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("extool.exe");
    let image = tool_image((1, 2, 3, 4));
    std::fs::write(&path, &image).unwrap();
    let id = identify(&path, Tiers::ALL, &ctx()).unwrap();
    assert_eq!(id.size, Field::Computed(image.len() as u64));
    assert!(id.timestamps.computed().unwrap().modified.is_some());
    let from_bytes = identify_bytes(&image, Some("extool.exe"), Tiers::ALL, &ctx());
    assert_eq!(id.hashes, from_bytes.hashes);
    assert_eq!(id.pe, from_bytes.pe);
    assert_eq!(id.signing_state, from_bytes.signing_state);
    assert!(id.fs.path.computed().is_some_and(|p| !p.claimed));
    assert!(matches!(id.fs.owner, Field::NotYetSupported(_)));
    // A directory and a missing file are errors, not records.
    assert!(identify(&dir, Tiers::ALL, &ctx()).is_err());
    assert!(identify(&dir.join("missing"), Tiers::ALL, &ctx()).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A tier that was not requested keeps `not_requested`, and an error is
/// charged only to requested tiers.
#[test]
fn unrequested_tiers_stay_untouched() {
    let image = PeBuilder::default().build();
    // The hash tier alone still knows the content is a PE: a missing
    // Authenticode digest would be `unavailable`, and here it is computed.
    let h = identify_bytes(&image, None, Tier::Hash.into(), &ctx());
    assert!(h.hashes.computed().unwrap().authenticode.is_computed());
    assert_eq!(h.pe, Field::NotRequested);
    assert_eq!(h.kind, Field::NotRequested);
    let text = identify_bytes(b"plain text", None, Tier::Hash.into(), &ctx());
    assert_eq!(
        text.hashes.computed().unwrap().authenticode,
        Field::NotApplicable
    );

    // Only the requested tiers are filled in, or charged with errors.
    let dir = std::env::temp_dir().join(format!("palisade-tiers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a.exe");
    std::fs::write(&path, &image).unwrap();
    let classify = identify(&path, Tier::Classify.into(), &ctx()).unwrap();
    assert_eq!(classify.hashes, Field::NotRequested);
    assert!(classify.errors.iter().all(|e| e.tier == Tier::Classify));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn large_files_are_hashed_but_not_parsed() {
    let image = PeBuilder::default().build();
    let mut c = ctx();
    c.max_in_memory = 100;
    let id = identify_bytes(&image, Some("a.exe"), Tiers::ALL, &c);
    assert!(id.hashes.is_computed(), "hashes are streamed");
    assert!(matches!(id.pe, Field::Unavailable(_)));
    assert!(matches!(id.signatures, Field::Unavailable(_)));
    assert_eq!(
        id.signing_state.computed().unwrap().state,
        SigningStateKind::Unverified,
        "never read as unsigned"
    );
    assert!(id.errors.iter().any(|e| e.code == "too_large"));
    assert!(id.masquerade.unassessed.contains(&"name_mismatch"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// No input panics, and the record always serialises.
    #[test]
    fn any_bytes_identify(
        data in prop::collection::vec(any::<u8>(), 0..4096),
        name in "[a-zA-Z0-9 ._\u{202e}\u{0430}-]{0,24}",
    ) {
        let id = identify_bytes(&data, Some(&name), Tiers::ALL, &ctx());
        prop_assert!(serde_json::to_string(&id).is_ok());
        prop_assert!(id.masquerade.score <= 100);
    }

    /// Mutating a valid image never panics either.
    #[test]
    fn mutated_images_identify(
        flips in prop::collection::vec((0_usize..1536, any::<u8>()), 1..16),
        cut in 0_usize..1536,
    ) {
        let mut image = tool_image((1, 0, 0, 0));
        for (at, v) in flips {
            let at = at % image.len();
            image[at] = v;
        }
        image.truncate(cut.max(64).min(image.len()));
        let id = identify_bytes(&image, Some("extool.exe"), Tiers::ALL, &ctx());
        prop_assert!(serde_json::to_string(&id).is_ok());
    }
}
