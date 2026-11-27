//! Whole-policy benchmarks (#42): evaluation on the reference policy, the
//! decision cache, and loading.
//!
//! ```sh
//! cargo bench -p palisade-policy --bench policy_eval
//! ```
//!
//! The reference policy is in `src/reference.rs`: 10,000 rules, a 100,000
//! entry hash set, 500 publisher rules, 200 path rules and 50 regex leaves.
//! The suites and their names are those of #42; the budgets they are held
//! to are in `perf-budget.toml` and checked by `tests/budget.rs`. CI only
//! builds and smoke-runs this (`cargo test --bench policy_eval`), because
//! timings on shared hosted runners are too noisy to compare
//! (docs/testing.md); the regression comparison is `cargo xtask
//! bench-compare` (#25).
//!
//! Group names are stable, so baselines can be compared across commits:
//! `policy_eval/<suite>`, `decision_cache/cache_hit`,
//! `policy_load/<suite>`.

// `criterion_group!` generates an undocumented public function.
#![allow(missing_docs)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use palisade_policy::decision::TraceId;
use palisade_policy::demand::FactSet;
use palisade_policy::engine::{Engine, EngineConfig, FileIdentity, Request, SystemClock};
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::PathVariables;
use palisade_policy::mode::DeviceState;
use palisade_policy::model::{ObjectType, PrecedenceModel};
use palisade_policy::reference::{self, Case, Size};

const TRACE: TraceId = TraceId([0; 16]);

fn eval(c: &mut Criterion) {
    let policy = reference::policy(Size::Reference, PrecedenceModel::DenyWins);
    let evaluator = Evaluator::new(&policy).unwrap_or_else(|e| panic!("{e}"));
    let state = DeviceState::of(&policy.document().policy);
    let variables = PathVariables::new();
    let context = reference::context();
    let mut group = c.benchmark_group("policy_eval");
    for case in Case::ALL {
        let objects: Vec<_> = (0..64).map(|i| case.facts(i, Size::Reference)).collect();
        let mut i = 0usize;
        group.bench_function(case.name(), |b| {
            b.iter(|| {
                i = (i + 1) % objects.len();
                let subject = Subject {
                    object_type: ObjectType::Executable,
                    facts: &objects[i],
                    variables: &variables,
                    context: &context,
                };
                black_box(evaluator.evaluate_in(black_box(&subject), &state, TRACE))
            });
        });
    }
    // The same objects under the ordered models, which decide differently.
    for (name, model) in [
        ("eval_first_match_10k", PrecedenceModel::FirstMatch),
        ("eval_specificity_10k", PrecedenceModel::Specificity),
    ] {
        let policy = reference::policy(Size::Reference, model);
        let evaluator = Evaluator::new(&policy).unwrap_or_else(|e| panic!("{e}"));
        let objects: Vec<_> = (0..64)
            .map(|i| Case::ALL[i as usize % Case::ALL.len()].facts(i, Size::Reference))
            .collect();
        let mut i = 0usize;
        group.bench_function(name, |b| {
            b.iter(|| {
                i = (i + 1) % objects.len();
                let subject = Subject {
                    object_type: ObjectType::Executable,
                    facts: &objects[i],
                    variables: &variables,
                    context: &context,
                };
                black_box(evaluator.evaluate_in(black_box(&subject), &state, TRACE))
            });
        });
    }
    group.finish();
}

fn cache(c: &mut Criterion) {
    let policy = reference::policy(Size::Reference, PrecedenceModel::DenyWins);
    let state = DeviceState::of(&policy.document().policy);
    let engine = Engine::new(policy, EngineConfig::default()).unwrap_or_else(|e| panic!("{e}"));
    let variables = PathVariables::new();
    let context = reference::context();
    let clock = SystemClock::new();
    let facts = Case::HashHit.facts(1, Size::Reference);
    let request = Request {
        subject: Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        },
        computed: FactSet::ALL,
        state: &state,
        trace_id: TRACE,
        file: Some(FileIdentity::Sha256([1; 32])),
        session: None,
        expires_before: None,
    };
    black_box(engine.evaluate(&request, &clock));
    let mut group = c.benchmark_group("decision_cache");
    group.bench_function("cache_hit", |b| {
        b.iter(|| black_box(engine.evaluate(black_box(&request), &clock)));
    });
    group.finish();
}

fn load(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_load");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    for (name, size) in [
        ("load_reference_policy", Size::Reference),
        ("load_1m_hashset", Size::Million),
    ] {
        let doc = reference::document(size, PrecedenceModel::DenyWins);
        group.bench_function(name, |b| {
            b.iter(|| {
                let policy = doc.clone().validate().unwrap_or_else(|e| panic!("{e:?}"));
                black_box(
                    Engine::new(policy, EngineConfig::default()).unwrap_or_else(|e| panic!("{e}")),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(benches, eval, cache, load);
criterion_main!(benches);
