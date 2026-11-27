//! Benchmarks for matching one compiled criterion against an object's facts
//! (`CompiledCriterion::eval`), the unit that whole-rule and whole-policy
//! evaluation is built from.
//!
//! ```sh
//! cargo bench -p palisade-policy --bench criterion_eval
//! ```
//!
//! CI only builds and smoke-runs this (`cargo test --bench criterion_eval`), because
//! timings on shared hosted runners are too noisy to compare (docs/testing.md).
//! The policy-size benchmarks from #25 (100 to 100k rules) arrive with
//! whole-policy evaluation.
//!
//! The `counters` and `analyse` groups measure the rule lifecycle (#40):
//! one hit on a rule's counter, and the policy assistant on a 50,000-rule
//! policy.

// `criterion_group!` generates an undocumented public function.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion as Bench, criterion_group, criterion_main};
use palisade_core::path::VolumeMap;
use palisade_policy::analysis::{Facts, analyse};
use palisade_policy::context::EvaluationContext;
use palisade_policy::evaluate::Evaluator;
use palisade_policy::facts::{ObjectFacts, PathFact, PathVariables};
use palisade_policy::model::{ActionKind, Criterion, Field, Operator, PolicyDocument, Timestamp};
use palisade_policy::ops::{CompiledCriterion, EvalContext, Tri};

const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn compile(field: Field, operator: Operator, values: &[&str]) -> CompiledCriterion {
    let criterion = Criterion::new(field, operator, values.iter().copied());
    match CompiledCriterion::compile(&criterion) {
        Ok(compiled) => compiled,
        Err(errors) => panic!("{field:?} {operator:?} {values:?}: {errors:?}"),
    }
}

fn eval(c: &mut Bench) {
    let variables = PathVariables::new();
    let mut context = EvaluationContext::default();
    // 64 local addresses and 64 groups: a large host.
    context.network.addresses = Some(
        (0..64u8)
            .map(|i| std::net::IpAddr::from([10, 1, 2, i]))
            .collect(),
    );
    context.user.groups = Some((0..64).map(|i| format!("S-1-5-21-1-2-3-{i}")).collect());
    let ctx = EvalContext {
        action: ActionKind::Deny,
        variables: &variables,
        context: &context,
    };
    let facts = ObjectFacts::new()
        .with(Field::HashSha256, SHA)
        .with(Field::MetaProductName, "Example Suite")
        .with(Field::MetaFileVersion, "10.2.3.4")
        .with_path(
            PathFact::new(r"C:\Program Files\Example\bin\tool.exe", &VolumeMap::new())
                .with_user_writable(false),
        );

    let cases = [
        (
            "ip_in_cidr_any_of_64",
            compile(
                Field::NetIp,
                Operator::IpInCidr,
                &["10.1.2.63/32", "10.1.0.0/16"],
            ),
        ),
        (
            "groups_all_of",
            compile(
                Field::UserGroups,
                Operator::AllOf,
                &["S-1-5-21-1-2-3-7", "S-1-5-21-1-2-3-63"],
            ),
        ),
        (
            "hash_equals",
            compile(Field::HashSha256, Operator::Equals, &[SHA]),
        ),
        (
            "text_equals_25_values",
            compile(
                Field::MetaProductName,
                Operator::Equals,
                &[
                    "a",
                    "b",
                    "c",
                    "d",
                    "e",
                    "f",
                    "g",
                    "h",
                    "i",
                    "j",
                    "k",
                    "l",
                    "m",
                    "n",
                    "o",
                    "p",
                    "q",
                    "r",
                    "s",
                    "t",
                    "u",
                    "v",
                    "w",
                    "x",
                    "Example Suite",
                ],
            ),
        ),
        (
            "path_wildcard",
            compile(
                Field::PathFull,
                Operator::Wildcard,
                &[r"C:\Program Files\*\bin\*.exe"],
            ),
        ),
        (
            "text_regex",
            compile(
                Field::MetaProductName,
                Operator::Regex,
                &["Ex[a-z]+ (Suite|Tool)"],
            ),
        ),
        (
            "version_between",
            compile(
                Field::MetaFileVersion,
                Operator::VersionBetween,
                &["10.0", "10.65535.65535.65535"],
            ),
        ),
    ];
    let mut group = c.benchmark_group("criterion_eval");
    for (name, criterion) in &cases {
        // Every case matches, so the benchmark measures the whole match.
        assert_eq!(criterion.eval(&facts, &ctx).result, Tri::Match, "{name}");
        group.bench_function(*name, |b| {
            b.iter(|| black_box(criterion.eval(black_box(&facts), &ctx)));
        });
    }
    group.finish();
}

const LIFECYCLE_POLICY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";
const LIFECYCLE_SET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001";

/// A policy of `n` rules: mostly hash allows, with publisher allows and
/// denies and a few path allows, as a large estate's policy looks.
fn lifecycle_policy(n: u32) -> PolicyDocument {
    let rules: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            let id = format!("01936b2e-{:04x}-7{:03x}-9f21-0a1b2c3d4e61", i >> 12, i & 0xfff);
            let (tree, action) = match i % 50 {
                0 => (
                    serde_json::json!({"criterion": {"field": "signer.publisher", "operator": "equals", "values": [format!("Publisher {}", i / 50)]}}),
                    "deny",
                ),
                1 => (
                    serde_json::json!({"all": [
                        {"criterion": {"field": "signer.publisher", "operator": "equals", "values": [format!("Publisher {}", i / 50)]}},
                        {"criterion": {"field": "meta.product_name", "operator": "equals", "values": ["Tool"]}},
                    ]}),
                    "allow",
                ),
                2 => (
                    serde_json::json!({"criterion": {"field": "path.directory", "operator": "starts_with", "values": [format!("C:\\Apps\\{i}")]}}),
                    "allow",
                ),
                _ => (
                    serde_json::json!({"criterion": {"field": "hash.sha256", "operator": "equals", "values": [format!("{i:064x}")]}}),
                    "allow",
                ),
            };
            serde_json::json!({"id": id, "name": "R", "match": tree, "action": {"type": action},
                "metadata": {"created_at": "2026-01-01T00:00:00Z"}})
        })
        .collect();
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {"id": LIFECYCLE_POLICY, "name": "Bench", "revision": 1, "mode": "enforce", "rule_sets": [LIFECYCLE_SET]},
        "rule_sets": [{"id": LIFECYCLE_SET, "name": "S", "kind": "mixed", "rules": rules}],
    });
    match PolicyDocument::from_json(&json.to_string()) {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    }
}

/// Rule lifecycle (#40): recording a hit on a rule's counter, which the
/// decision path pays (budget: under 5 ns), and the policy assistant on a
/// 50,000-rule policy (budget: under 500 ms).
fn lifecycle(c: &mut Bench) {
    let small = match lifecycle_policy(100).validate() {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    };
    let evaluator = match Evaluator::new(&small) {
        Ok(e) => e,
        Err(e) => panic!("{e}"),
    };
    let counters = evaluator.counters();
    let key = palisade_policy::lifecycle::counters::object_key(&[0xabu8; 32]);
    // The agent computes an object's key once, so the per-decision cost is
    // `hit_key`.
    c.bench_function("counters/hit_key", |b| {
        b.iter(|| counters.hit_key(black_box(7), black_box(key), black_box(Timestamp(1))));
    });

    let large = lifecycle_policy(50_000);
    let now = Timestamp(1_795_564_800);
    let facts = Facts::default();
    let mut group = c.benchmark_group("analyse");
    group.sample_size(10);
    group.bench_function("50k_rules", |b| {
        b.iter(|| black_box(analyse(black_box(&large), &facts, now)));
    });
    group.finish();
}

criterion_group!(benches, eval, lifecycle);
criterion_main!(benches);
