//! Golden policy bundles (#43): fixed policies whose canonical bytes and
//! hashes are committed in `tests/golden/bundles/`. A changed byte is a
//! changed bundle format, reviewed in the PR. Every platform must produce
//! the same bytes, which is what makes `bundle_hash` reproducible across
//! the CI runners (Linux, macOS, Windows x64 and ARM64).
//!
//! Regenerate with
//! `PALISADE_BLESS=1 cargo test -p palisade-policy --all-features --test bundle_golden`.

// `clippy.toml` allows unwrap inside `#[test]` functions only; the helpers
// here are test code too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use palisade_core::Uuid7;
use palisade_policy::bundle::format::hex;
use palisade_policy::bundle::{
    AgentVersion, Body, BundleLimits, Header, InlineLibrary, PolicyBundle, SetContent,
    SourceRevisions, Target, TargetScope, decode_header,
};
use palisade_policy::hashset::Digests;
use palisade_policy::library::{LibraryId, LibraryRef, Pin};
use palisade_policy::model::{Criterion, Field, Match, Mode, PolicyDocument};
use palisade_policy::test_util::{
    PolicyBuilder, RuleBuilder, RuleSetBuilder, all, hash, publisher, under,
};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/bundles")
}

fn id(text: &str) -> Uuid7 {
    text.parse().unwrap()
}

fn header(scope: TargetScope, version: u64) -> Header {
    Header {
        min_agent_version: AgentVersion::new(0, 1, 0),
        expires_at: Some(1_767_225_600_000_000),
        ..Header::new(
            Target {
                tenant: id("01890a5d-ac96-774b-bcce-b302099a8057"),
                scope,
            },
            version,
            1_764_201_600_000_000,
        )
    }
}

fn bundle(doc: PolicyDocument, scope: TargetScope, version: u64) -> PolicyBundle {
    let sources = SourceRevisions {
        policies: vec![(doc.policy.id, doc.policy.revision)],
        libraries: Vec::new(),
    };
    PolicyBundle::new(
        header(scope, version),
        Body::new(doc, Vec::new(), sources).unwrap(),
    )
}

/// The fixed bundles, by file stem.
fn cases() -> Vec<(&'static str, PolicyBundle)> {
    let group = TargetScope::Group(id("01890a5d-ac96-774b-bcce-b302099a8058"));
    let device = TargetScope::Device(id("01890a5d-ac96-774b-bcce-b302099a8059"));
    let minimal = PolicyBuilder::new().build();
    let mut baseline = PolicyBuilder::new()
        .mode(Mode::Audit)
        .rule_set(
            RuleSetBuilder::allowlist(1)
                .rule(RuleBuilder::allow(
                    1,
                    publisher("CN=Example Software, O=Example, C=AU"),
                ))
                .rule(RuleBuilder::allow(
                    2,
                    all(vec![under("C:\\Program Files\\Example"), hash('a')]),
                )),
        )
        .rule_set(RuleSetBuilder::mandatory_blocklist(2).rule(RuleBuilder::deny(3, hash('b'))))
        .build();
    // Text in a decomposed form is written in NFC.
    baseline.rule_sets[0].rules[0].name = "Cafe\u{301} tools".to_owned();
    baseline.rule_sets[0].rules[0].metadata.ticket_ref = Some("CHG-1".to_owned());
    vec![
        ("minimal", bundle(minimal, group, 1)),
        ("baseline", bundle(baseline, device, 42)),
        ("hash_set", hash_set_bundle(group)),
    ]
}

/// A hash set (#368): an allow on `member_of` a library set, and the set
/// inlined as sorted raw digests.
fn hash_set_bundle(scope: TargetScope) -> PolicyBundle {
    let set = LibraryRef {
        id: LibraryId(id("01890a5d-ac96-774b-bcce-b302099a8068")),
        pin: Pin::Version(3),
    };
    let mut doc = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
        .build();
    doc.rule_sets[0].rules[0].match_ =
        Match::Criterion(Criterion::in_hash_set(Field::HashSha256, set, false));
    let library = InlineLibrary {
        id: set.id,
        resolved_version: 3,
        content: SetContent::HashSet {
            field: Field::HashSha256,
            digests: Digests::from_digests([[0xcc; 32], [0xaa; 32], [0xbb; 32]]),
        },
    };
    let sources = SourceRevisions {
        policies: vec![(doc.policy.id, doc.policy.revision)],
        libraries: vec![(set.id, 3)],
    };
    PolicyBundle::new(
        header(scope, 7),
        Body::new(doc, vec![library], sources).unwrap(),
    )
}

fn summary(b: &PolicyBundle, bytes: &[u8]) -> String {
    format!(
        "bundle_hash {}\ndecision_hash {}\nmetadata_digest {}\nbytes {}\n",
        hex(&b.bundle_hash().unwrap()),
        hex(&b.decision_hash().unwrap()),
        hex(b.body.metadata_digest()),
        bytes.len()
    )
}

#[test]
fn golden_bundles_are_byte_identical() {
    let bless = std::env::var_os("PALISADE_BLESS").is_some();
    for (name, bundle) in cases() {
        let bytes = bundle.to_bytes().unwrap();
        let text = summary(&bundle, &bytes);
        let (bin, sum) = (
            dir().join(format!("{name}.cbor")),
            dir().join(format!("{name}.txt")),
        );
        if bless {
            fs::create_dir_all(dir()).unwrap();
            fs::write(&bin, &bytes).unwrap();
            fs::write(&sum, &text).unwrap();
            continue;
        }
        let hint = "Regenerate with:\n  PALISADE_BLESS=1 cargo test -p palisade-policy --all-features --test bundle_golden";
        let committed = fs::read(&bin).unwrap_or_default();
        assert!(committed == bytes, "{name}.cbor differs. {hint}");
        let committed = fs::read_to_string(&sum)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        assert_eq!(committed, text, "{name}.txt differs. {hint}");
    }
}

#[test]
fn golden_bundles_decode_to_what_wrote_them() {
    for (name, bundle) in cases() {
        let bytes = fs::read(dir().join(format!("{name}.cbor"))).unwrap();
        let decoded = PolicyBundle::decode(&bytes, &BundleLimits::DEFAULT).unwrap();
        assert_eq!(decoded, bundle, "{name}");
        assert_eq!(
            decode_header(&bytes, &BundleLimits::DEFAULT).unwrap(),
            bundle.header,
            "{name}"
        );
        decoded.validate().unwrap();
    }
}
