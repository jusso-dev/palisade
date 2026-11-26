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

// `criterion_group!` generates an undocumented public function.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion as Bench, criterion_group, criterion_main};
use palisade_core::path::VolumeMap;
use palisade_policy::context::EvaluationContext;
use palisade_policy::facts::{ObjectFacts, PathFact, PathVariables};
use palisade_policy::model::{ActionKind, Criterion, Field, Operator};
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

criterion_group!(benches, eval);
criterion_main!(benches);
