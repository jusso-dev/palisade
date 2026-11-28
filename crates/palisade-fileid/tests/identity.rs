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
    // A PE image is no installer, package or script.
    assert_eq!(all.installer, Field::NotApplicable);
    assert_eq!(all.package, Field::NotApplicable);
    assert_eq!(all.script, Field::NotApplicable);
    let h = all.hashes.computed().unwrap();
    assert_eq!(h.msi_normalised_sha256, Field::NotApplicable);
    assert_eq!(h.script_normalised_sha256, Field::NotApplicable);
    // Uploads have no file system context.
    assert_eq!(all.fs.owner, Field::NotApplicable);
    // A PE's deep tier is its content tags, when the content rules are
    // built in.
    assert_eq!(
        all.computed_tiers.contains(Tier::Deep),
        cfg!(feature = "content-rules")
    );
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
fn merging_needs_the_same_content() {
    // Two files of the same size and name: a classify-only record of one
    // and a trust-only record of the other must not be joined, though
    // neither has the hash tier's flat SHA-256.
    let a = PeBuilder::default().build();
    let mut b = a.clone();
    let last = b.len() - 1;
    b[last] ^= 0x01;
    let classify = Tiers::only(Tier::Classify);
    let trust = Tiers::only(Tier::Trust);
    let mut x = identify_bytes(&a, Some("same.exe"), classify, &ctx());
    assert!(x.content_sha256.is_some());
    let before = x.clone();
    let y = identify_bytes(&b, Some("same.exe"), trust, &ctx());
    assert!(!x.merge(y, &ctx()));
    assert_eq!(x, before);
    // The same content in both: merged.
    let z = identify_bytes(&a, Some("same.exe"), trust, &ctx());
    assert!(x.merge(z, &ctx()));
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
        "content_sha256",
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
        "content_tags",
        "os_cross_check",
        "fs",
        "derived",
        "masquerade",
        "strengths",
        "errors",
    ] {
        assert!(keys.contains(&k), "missing {k}");
    }
    assert_eq!(keys.len(), 26, "{keys:?}");
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
    // The file system context comes from the Windows file system only;
    // elsewhere it is unavailable, never guessed. The provenance tag has
    // no reader yet.
    if cfg!(windows) {
        assert!(id.fs.file_id.is_computed() || matches!(id.fs.file_id, Field::Unavailable(_)));
    } else {
        for f in [
            matches!(id.fs.owner, Field::Unavailable(_)),
            matches!(id.fs.user_writable, Field::Unavailable(_)),
            matches!(id.fs.streams, Field::Unavailable(_)),
            matches!(id.fs.reparse, Field::Unavailable(_)),
            matches!(id.fs.file_id, Field::Unavailable(_)),
            matches!(id.fs.volume, Field::Unavailable(_)),
        ] {
            assert!(f, "{:?}", id.fs);
        }
    }
    assert!(matches!(id.fs.provenance, Field::NotYetSupported(_)));
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

/// #294 review (CodeRabbit, `compose.rs`): a file revoked by a digest in
/// an algorithm the caller did not ask for (the flat SHA-384, or the
/// Authenticode SHA-1) is still found revoked: every algorithm the
/// revocation list uses is computed.
#[test]
fn revocation_by_any_algorithm_is_found() {
    use palisade_fileid::authenticode::{RevocationSet, hash_pe};
    use palisade_fileid::hash::{AlgorithmSet, Digest, HashAlgorithm};
    use sha2::Digest as _;
    let image = tool_image((1, 0, 0, 0));
    let flat384 = sha2::Sha384::digest(&image);
    let ah = hash_pe(&image, AlgorithmSet::SHA1).unwrap();
    let auth_sha1 = ah.get(HashAlgorithm::Sha1).unwrap().clone();
    for digest in [
        Digest::new(HashAlgorithm::Sha384, &flat384).unwrap(),
        auth_sha1,
    ] {
        let mut rev = RevocationSet::new();
        rev.add_file_hash(digest.clone());
        let mut c = ctx();
        c.revocation = &rev;
        let id = identify_bytes(&image, Some("extool.exe"), Tiers::ALL, &c);
        let s = id.signing_state.computed().unwrap();
        assert_eq!(s.state, SigningStateKind::Invalid, "{digest:?}: {s:?}");
        assert_eq!(recommend(&id).level, RuleLevel::None);
    }
}

/// #294 review (CodeRabbit, `mod.rs`): a final path one record resolved
/// survives a merge with a record that did not, so a third record that
/// resolved a different final path is still refused.
#[test]
fn merging_keeps_a_known_final_path() {
    let image = PeBuilder::default().build();
    let with_final = |p: Option<&str>| {
        let mut id = identify_bytes(&image, Some(r"C:\t\a.exe"), Tiers::ALL, &ctx());
        if let Field::Computed(info) = &mut id.fs.path {
            info.final_path = p.map(str::to_owned);
        }
        id
    };
    let mut x = with_final(None);
    assert!(x.merge(with_final(Some(r"C:\real\a.exe")), &ctx()));
    assert_eq!(
        x.fs.path.computed().unwrap().final_path.as_deref(),
        Some(r"C:\real\a.exe")
    );
    let before = x.clone();
    assert!(!x.merge(with_final(Some(r"C:\other\a.exe")), &ctx()));
    assert_eq!(x, before);
}

/// #294 review minors: a name made wholly of lookalikes of a protected
/// binary's name is a homoglyph (`сmd.exe` with a Cyrillic `с`, `.exe`
/// Latin, has no Latin letter in its label to mix with); a PE with a
/// version resource but no name leaves the name check open; and a
/// context tier that computed nothing is not marked computed.
#[test]
fn review_minors_in_the_record() {
    let mut c = ctx();
    let list = palisade_fileid::identity::ProtectedList::defaults();
    c.protected = &list;
    let image = PeBuilder::default().build();
    let id = identify_bytes(&image, Some("\u{ff43}\u{ff4d}\u{ff44}.exe"), Tiers::ALL, &c);
    assert!(
        id.masquerade.reasons.iter().any(|r| matches!(
            r,
            palisade_fileid::identity::MasqueradeReason::Homoglyph { .. }
        )),
        "{:?}",
        id.masquerade
    );
    let tool = tool_image((1, 0, 0, 0));
    let id = identify_bytes(&tool, None, Tiers::ALL, &ctx());
    assert!(
        id.masquerade.unassessed.contains(&"name_mismatch"),
        "{:?}",
        id.masquerade
    );
    assert_eq!(recommend(&id).level, RuleLevel::None);
    // A context tier whose every field is pending or unavailable did not
    // compute: off Windows, a file has neither a mark of the web nor a
    // Windows path to take variables from.
    if !cfg!(windows) {
        let dir = std::env::temp_dir().join(format!("palisade-ctx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("extool.exe");
        std::fs::write(&path, &tool).unwrap();
        let id = identify(&path, Tiers::ALL, &ctx()).unwrap();
        assert!(!id.fs.motw.is_computed() && !id.fs.path_variables.is_computed());
        assert!(!id.computed_tiers.contains(Tier::Context));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// #55 wiring: a path is Medium only when the access check proved that no
/// non-administrator can write the file or a folder above it, or change
/// their permissions; anything else, unknown included, is Weak. A path
/// rule is never recommended.
#[test]
fn path_strength_follows_proven_writability() {
    use palisade_fileid::identity::{IdentityStrength, WritableSummary, strength};
    let image = tool_image((1, 0, 0, 0));
    let dir = ScratchDir::new("writable");
    let path = dir.0.join("extool.exe");
    std::fs::write(&path, &image).unwrap();
    let mut id = identify(&path, Tiers::ALL, &ctx()).unwrap();
    drop(dir);
    let volume = |location: &str| {
        Field::Computed(palisade_fileid::identity::VolumeSummary {
            fs_type: Some("ntfs".to_owned()),
            location: location.to_owned(),
            drive_type: None,
            bus_type: None,
            is_hotplug: Some(false),
            is_os_volume: Some(location == "os_volume"),
            serial: None,
            supports_owner: true,
        })
    };
    id.fs.volume = volume("os_volume");
    let path_strength = |id: &palisade_fileid::identity::FileIdentity| {
        strength::classify(id)
            .into_iter()
            .find(|s| s.attribute == "path")
            .map(|s| s.strength)
    };
    let safe = WritableSummary {
        path_user_writable: false,
        file_user_writable: false,
        first_user_writable_ancestor: None,
        change_perms_by_non_admin: false,
        principals_with_write: Vec::new(),
    };
    for (field, want) in [
        (
            Field::Unavailable("not read".to_owned()),
            IdentityStrength::Weak,
        ),
        (Field::Computed(safe.clone()), IdentityStrength::Medium),
        (
            Field::Computed(WritableSummary {
                path_user_writable: true,
                first_user_writable_ancestor: Some(r"C:\Users\alice".to_owned()),
                ..safe.clone()
            }),
            IdentityStrength::Weak,
        ),
        (
            Field::Computed(WritableSummary {
                change_perms_by_non_admin: true,
                ..safe.clone()
            }),
            IdentityStrength::Weak,
        ),
    ] {
        id.fs.user_writable = field.clone();
        assert_eq!(path_strength(&id), Some(want), "{field:?}");
        let rec = recommend(&id);
        assert_ne!(rec.level, RuleLevel::Path, "{field:?}");
        assert!(
            rec.refused.iter().any(|(l, _)| *l == RuleLevel::Path),
            "{field:?}"
        );
    }
    // #344 review m2: a proven-safe ACL counts only on a local fixed disk.
    id.fs.user_writable = Field::Computed(safe);
    for (location, want) in [
        ("other_fixed", IdentityStrength::Medium),
        ("network", IdentityStrength::Weak),
        ("removable", IdentityStrength::Weak),
        ("virtual_disk", IdentityStrength::Weak),
        ("unknown", IdentityStrength::Weak),
    ] {
        id.fs.volume = volume(location);
        assert_eq!(path_strength(&id), Some(want), "{location}");
    }
    id.fs.volume = Field::Unavailable("not read".to_owned());
    assert_eq!(path_strength(&id), Some(IdentityStrength::Weak));
}

/// #344 review: merge compares each part of the file key on its own. A part
/// only one record knows (no change journal on one side) does not refuse
/// the merge; a known part that differs does.
#[test]
fn merging_compares_each_part_of_the_file_key() {
    use palisade_fileid::identity::FileIdSummary;
    let image = tool_image((1, 0, 0, 0));
    let key = |usn: Option<i64>, journal: Option<u64>, file_id: &str| {
        Field::Computed(FileIdSummary {
            volume_serial: Some(7),
            file_id: Some(file_id.to_owned()),
            usn_journal_id: journal,
            usn,
            link_count: Some(1),
            link_names: Vec::new(),
        })
    };
    let with = |k: Field<FileIdSummary>, tiers: Tiers| {
        let mut id = identify_bytes(&image, Some("extool.exe"), tiers, &ctx());
        id.fs.file_id = k;
        id
    };
    let early = Tiers::EXECUTION;
    let late: Tiers = [Tier::Context, Tier::Deep].into_iter().collect();
    // One side has no change journal: the USN is not compared.
    let mut a = with(key(None, None, "01"), early);
    assert!(a.merge(with(key(Some(5), Some(9), "01"), late), &ctx()));
    // A known USN that differs, or another file ID, refuses.
    let mut a = with(key(Some(4), Some(9), "01"), early);
    assert!(!a.merge(with(key(Some(5), Some(9), "01"), late), &ctx()));
    let mut a = with(key(None, None, "01"), early);
    assert!(!a.merge(with(key(None, None, "02"), late), &ctx()));
}

/// #55 wiring: the OS cross-check is a diagnostic (ADR 0018). A recorded
/// disagreement changes neither the signing state nor the recommendation,
/// and uploads, which the OS cannot verify, have none.
#[test]
fn os_cross_check_never_decides() {
    use palisade_fileid::identity::{OsComparisonSummary, OsCrossCheckSummary, masquerade};
    let image = tool_image((1, 0, 0, 0));
    let mut id = identify_bytes(&image, Some("extool.exe"), Tiers::ALL, &ctx());
    assert_eq!(id.os_cross_check, Field::NotApplicable);
    let state = id.signing_state.clone();
    let level = recommend(&id).level;
    id.os_cross_check = Field::Computed(OsCrossCheckSummary {
        agrees: false,
        comparisons: vec![OsComparisonSummary {
            os_index: 0,
            os_code: Some(0x8009_6010),
            outcome: "rust_accepts_os_rejects".to_owned(),
        }],
        secondary_count_differs: false,
    });
    let c = ctx();
    id.masquerade = masquerade::assess(&id, c.protected, c.code_trust, c.known_folders);
    assert_eq!(id.signing_state, state);
    assert_eq!(recommend(&id).level, level);
    // A file on disk: the cross-check is recorded where the OS API exists.
    let dir = std::env::temp_dir().join(format!("palisade-oscheck-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("extool.exe");
    std::fs::write(&path, &image).unwrap();
    let id = identify(&path, Tiers::ALL, &ctx()).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    if cfg!(windows) {
        assert!(!matches!(id.os_cross_check, Field::NotRequested));
    } else {
        assert!(matches!(id.os_cross_check, Field::Unavailable(_)));
    }
}

/// #55 wiring: the deep tier tags content (#44), and the tags are
/// descriptive only.
#[test]
fn deep_tier_tags_content() {
    let image = tool_image((1, 0, 0, 0));
    let id = identify_bytes(&image, Some("extool.exe"), Tiers::ALL, &ctx());
    if cfg!(feature = "content-rules") {
        let tags = id.content_tags.computed().unwrap();
        assert!(tags.complete);
        assert!(id.computed_tiers.contains(Tier::Deep));
        // A plain image carries none of the built-in tags.
        assert!(tags.tags.is_empty(), "{tags:?}");
    } else {
        assert!(matches!(id.content_tags, Field::Unavailable(_)));
    }
    let early = identify_bytes(&image, Some("extool.exe"), Tiers::EXECUTION, &ctx());
    assert_eq!(early.content_tags, Field::NotRequested);
}

/// #345 review m4: `IdentityContext::content_rules` exists whatever the
/// features, so a context built field by field compiles either way.
#[test]
fn a_context_built_field_by_field_compiles_with_any_features() {
    use palisade_fileid::authenticode::{RevocationSet, TrustConfig, ValidityPolicy};
    use palisade_fileid::hash::{AlgorithmSet, HashOptions};
    use palisade_fileid::identity::{MAX_IN_MEMORY, ProtectedList};
    let trust = TrustConfig::new();
    let revocation = RevocationSet::new();
    let validity = ValidityPolicy::default();
    let protected = ProtectedList::defaults();
    let c = IdentityContext {
        code_trust: &trust,
        tsa_trust: &trust,
        catalogs: None,
        revocation: &revocation,
        validity: &validity,
        now: NOW,
        clock_floor: None,
        protected: &protected,
        known_folders: None,
        flat_algorithms: AlgorithmSet::DEFAULT,
        hash_options: HashOptions::default(),
        max_in_memory: MAX_IN_MEMORY,
        content_rules: None,
    };
    let id = identify_bytes(&tool_image((1, 0, 0, 0)), Some("a.exe"), Tiers::ALL, &c);
    assert!(matches!(id.content_tags, Field::Unavailable(_)));
}
