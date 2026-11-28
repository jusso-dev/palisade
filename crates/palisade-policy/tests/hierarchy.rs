//! The hierarchy fixture suite (#37).
//!
//! Each file in `tests/hierarchy/*.yaml` gives a hierarchy snapshot, one
//! device and its dynamic groups, and the decision expected for objects
//! identified by SHA-256. The suite reads the snapshot with the strict YAML
//! reader, validates it, computes the device's effective policy, and checks
//!
//! - every expected decision, made by the evaluator in the effective mode;
//! - the effective policy against `tests/snapshots/hierarchy/<name>.json`:
//!   the flattened document, the content hash and the explain output (the
//!   provenance of every rule and every setting a layer offered, and the
//!   mode with its floor and adjustments);
//! - that shuffling the snapshot's nodes, policies and libraries does not
//!   change the content hash.
//!
//! After a deliberate change, regenerate the snapshots with
//! `PALISADE_BLESS=1 cargo test -p palisade-policy --test hierarchy`.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use palisade_core::ObjectType;
use palisade_core::path::VolumeMap;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::TraceId;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{ObjectFacts, PathFact, PathVariables};
use palisade_policy::hierarchy::{EffectivePolicy, HierarchyDocument, Membership, NodeId};
use palisade_policy::mode::DeviceState;
use palisade_policy::model::Field;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    description: String,
    device: NodeId,
    #[serde(default)]
    membership: Vec<NodeId>,
    snapshot: serde_json::Value,
    decisions: BTreeMap<String, String>,
}

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn effective(snapshot: &serde_json::Value, f: &Fixture) -> EffectivePolicy {
    let h = HierarchyDocument::from_json(&snapshot.to_string())
        .unwrap()
        .validate()
        .unwrap_or_else(|e| panic!("{e:#?}"));
    h.effective_policy(
        f.device,
        &Membership {
            dynamic_groups: f.membership.clone(),
        },
    )
    .unwrap_or_else(|e| panic!("{e:#?}"))
}

fn decide(e: &EffectivePolicy, sha256: &str) -> String {
    let p = e.policy().unwrap();
    let facts = ObjectFacts::new()
        .with(Field::HashSha256, sha256)
        .with_path(
            PathFact::new("C:\\Tools\\tool.exe", &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(palisade_policy::unknown::VolumeKind::Fixed),
        );
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &variables,
        context: &context,
    };
    let d = Evaluator::new(p)
        .unwrap()
        .evaluate_in(
            &subject,
            &DeviceState::of(&p.document().policy),
            TraceId([3; 16]),
        )
        .unwrap();
    serde_json::to_value(d.outcome())
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

/// The explain output and the document, as one stable JSON value.
fn snapshot_of(e: &EffectivePolicy) -> serde_json::Value {
    let doc = e.policy().unwrap().document();
    serde_json::json!({
        "content_hash": e.content_hash(),
        "libraries": e.libraries().iter().map(|(id, v)| format!("{id} v{v}")).collect::<Vec<_>>(),
        "precedence": e.precedence(),
        "mode": e.mode(),
        "rules": e.rules(),
        // Only settings some layer offered.
        "settings": e.settings().iter().filter(|(_, p)| !p.steps.is_empty()).collect::<BTreeMap<_, _>>(),
        "document": doc,
    })
}

/// A deterministic shuffle of every list in the snapshot's top level.
fn shuffled(mut v: serde_json::Value, mut seed: u64) -> serde_json::Value {
    for key in ["nodes", "policies", "libraries"] {
        let Some(list) = v.get_mut(key).and_then(serde_json::Value::as_array_mut) else {
            continue;
        };
        for i in (1..list.len()).rev() {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let j = usize::try_from((seed >> 33) % (i as u64 + 1)).unwrap();
            list.swap(i, j);
        }
    }
    v
}

#[test]
fn hierarchy_fixtures() {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir().join("hierarchy"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    paths.sort();
    assert!(paths.len() >= 2);
    let bless = std::env::var_os("PALISADE_BLESS").is_some();
    for path in paths {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).unwrap();
        let value =
            palisade_policy::dsl::to_json_value(&text, &palisade_policy::dsl::Limits::default())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        let f: Fixture = serde_json::from_value(value).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!f.description.is_empty());
        let e = effective(&f.snapshot, &f);
        for (sha, want) in &f.decisions {
            assert_eq!(&decide(&e, sha), want, "{name}: object {sha}");
        }
        for seed in 0..8 {
            let other = effective(&shuffled(f.snapshot.clone(), seed), &f);
            assert_eq!(
                other.content_hash(),
                e.content_hash(),
                "{name}: shuffle {seed}"
            );
        }
        let actual = serde_json::to_string_pretty(&snapshot_of(&e)).unwrap() + "\n";
        let snap = dir()
            .join("snapshots/hierarchy")
            .join(format!("{name}.json"));
        if bless {
            fs::create_dir_all(snap.parent().unwrap()).unwrap();
            fs::write(&snap, &actual).unwrap();
            continue;
        }
        let expected = fs::read_to_string(&snap)
            .unwrap_or_else(|_| panic!("{}: missing; bless it", snap.display()))
            .replace("\r\n", "\n");
        assert!(
            expected == actual,
            "{name}: the effective policy differs from {}; after a deliberate change, run with PALISADE_BLESS=1\n{actual}",
            snap.display()
        );
    }
}
