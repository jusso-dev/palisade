//! The performance budget of #42, read from `perf-budget.toml`.
//!
//! Two modes:
//!
//! - **Smoke** (the default, and what CI runs): builds the reference
//!   policies, checks that every case decides as expected, checks the
//!   memory budget (counted by a counting allocator, so the same on every
//!   machine), and runs a few hundred timed decisions through the
//!   histogram without comparing them to the budget. It catches a harness
//!   that no longer builds or runs, and any memory regression.
//! - **Enforce** (`PALISADE_BUDGET=enforce`, release build): measures each
//!   case and fails if a percentile or the load time is over budget. Run it
//!   on reference hardware:
//!
//!   ```sh
//!   PALISADE_BUDGET=enforce cargo test --release -p palisade-policy --test budget -- --nocapture
//!   ```
//!
//! Shared CI runners are too noisy for absolute timings to be compared
//! (docs/testing.md). Timing regressions against `main` are caught by the
//! criterion benches and `cargo xtask bench-compare` (#25).

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use hdrhistogram::Histogram;
use serde::Deserialize;

use palisade_policy::bundle::{self, BundleLimits};
use palisade_policy::decision::TraceId;
use palisade_policy::demand::FactSet;
use palisade_policy::engine::{Engine, EngineConfig, FileIdentity, Outcome, Request, SystemClock};
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::PathVariables;
use palisade_policy::mode::DeviceState;
use palisade_policy::model::{ObjectType, PrecedenceModel};
use palisade_policy::reference::{self, Case, Size};

#[derive(Deserialize)]
struct Budgets {
    regression_pct: u32,
    samples: u64,
    budget: Sections,
}

#[derive(Deserialize)]
struct Sections {
    eval: Percentiles,
    eval_1m_hashset: Percentiles,
    cache_hit: Percentiles,
    load_reference_policy: Load,
    memory: Memory,
}

#[derive(Deserialize)]
struct Percentiles {
    p50_ns: Option<u64>,
    p99_ns: Option<u64>,
    p999_ns: Option<u64>,
}

#[derive(Deserialize)]
struct Load {
    max_ms: u64,
}

#[derive(Deserialize)]
struct Memory {
    reference_policy_mib: u64,
    million_hashset_mib: u64,
    decision_cache_mib: u64,
}

fn budgets() -> Budgets {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/perf-budget.toml");
    let text = std::fs::read_to_string(path).expect("perf-budget.toml");
    toml::from_str(&text).expect("perf-budget.toml is valid")
}

fn enforce() -> bool {
    std::env::var("PALISADE_BUDGET").is_ok_and(|v| v == "enforce")
}

/// The number of timed decisions per case.
fn samples(b: &Budgets) -> u64 {
    if enforce() { b.samples } else { 300 }
}

/// Checks a histogram against a budget, or only reports it in smoke mode.
fn check(name: &str, h: &Histogram<u64>, budget: &Percentiles, failures: &mut Vec<String>) {
    let report = format!(
        "{name}: p50 {} ns, p99 {} ns, p99.9 {} ns, max {} ns ({} samples)",
        h.value_at_quantile(0.5),
        h.value_at_quantile(0.99),
        h.value_at_quantile(0.999),
        h.max(),
        h.len()
    );
    eprintln!("{report}");
    if !enforce() {
        return;
    }
    for (q, label, limit) in [
        (0.5, "p50", budget.p50_ns),
        (0.99, "p99", budget.p99_ns),
        (0.999, "p99.9", budget.p999_ns),
    ] {
        if let Some(limit) = limit {
            let got = h.value_at_quantile(q);
            if got > limit {
                failures.push(format!("{name} {label} {got} ns > {limit} ns"));
            }
        }
    }
}

fn histogram() -> Histogram<u64> {
    // 1 ns to 1 s, three significant digits.
    Histogram::new_with_bounds(1, 1_000_000_000, 3).unwrap()
}

fn nanos(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .max(1)
}

/// Times pure evaluation of every case on `size`'s reference policy.
fn eval_cases(size: Size, samples: u64) -> Vec<(Case, Histogram<u64>)> {
    let policy = reference::policy(size, PrecedenceModel::DenyWins);
    let evaluator = Evaluator::new(&policy).unwrap();
    let state = DeviceState::of(&policy.document().policy);
    let variables = PathVariables::new();
    let context = reference::context();
    let mut out = Vec::new();
    for case in Case::ALL {
        // A pool of objects, so a run is not one object's cache lines.
        let objects: Vec<_> = (0..256).map(|i| case.facts(i, size)).collect();
        let mut h = histogram();
        for round in 0..samples + samples / 10 {
            let facts = &objects[usize::try_from(round % 256).unwrap()];
            let subject = Subject {
                object_type: ObjectType::Executable,
                facts,
                variables: &variables,
                context: &context,
            };
            #[expect(
                clippy::disallowed_methods,
                reason = "times the operation to check its performance bound"
            )]
            let start = Instant::now();
            let d = evaluator.evaluate_in(&subject, &state, TraceId([0; 16]));
            let t = nanos(start);
            let d = std::hint::black_box(d).unwrap();
            assert_eq!(d.outcome(), case.expected(), "{case:?}");
            // The first tenth warms up.
            if round >= samples / 10 {
                h.record(t).unwrap();
            }
        }
        out.push((case, h));
    }
    out
}

#[test]
fn the_budget_file_is_complete() {
    let b = budgets();
    assert_eq!(b.regression_pct, 10);
    assert!(b.samples >= 10_000);
    let e = &b.budget.eval;
    assert_eq!(
        (e.p50_ns, e.p99_ns, e.p999_ns),
        (Some(5_000), Some(50_000), Some(200_000))
    );
    assert_eq!(b.budget.eval_1m_hashset.p99_ns, Some(60_000));
    assert_eq!(b.budget.cache_hit.p99_ns, Some(1_000));
    assert_eq!(b.budget.load_reference_policy.max_ms, 500);
    assert_eq!(
        b.budget.memory.decision_cache_mib * (1 << 20),
        EngineConfig::default().cache.max_bytes as u64
    );
}

#[test]
fn pure_evaluation_is_within_budget() {
    let b = budgets();
    let mut failures = Vec::new();
    for (case, h) in eval_cases(Size::Reference, samples(&b)) {
        check(case.name(), &h, &b.budget.eval, &mut failures);
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_million_hash_set_is_within_budget() {
    let b = budgets();
    let mut failures = Vec::new();
    for (case, h) in eval_cases(Size::Million, samples(&b) / 4) {
        check(
            &format!("{}_1m", case.name()),
            &h,
            &b.budget.eval_1m_hashset,
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_cache_hit_is_within_budget() {
    let b = budgets();
    let policy = reference::policy(Size::Reference, PrecedenceModel::DenyWins);
    let state = DeviceState::of(&policy.document().policy);
    let engine = Engine::new(policy, EngineConfig::default()).unwrap();
    let variables = PathVariables::new();
    let context = reference::context();
    let clock = SystemClock::new();
    let objects: Vec<_> = (0..256)
        .map(|i| Case::HashHit.facts(i, Size::Reference))
        .collect();
    let mut h = histogram();
    let n = samples(&b);
    for round in 0..n + 256 {
        let i = usize::try_from(round % 256).unwrap();
        let request = Request {
            subject: Subject {
                object_type: ObjectType::Executable,
                facts: &objects[i],
                variables: &variables,
                context: &context,
            },
            computed: FactSet::ALL,
            state: &state,
            trace_id: TraceId([0; 16]),
            file: Some(FileIdentity::File {
                volume_serial: 1,
                file_id: i as u128,
                change_stamp: 0,
                size: 1,
            }),
            session: None,
            expires_before: None,
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "times the operation to check its performance bound"
        )]
        let start = Instant::now();
        let out = engine.evaluate(&request, &clock);
        let t = nanos(start);
        assert!(matches!(
            std::hint::black_box(out),
            Outcome::Decided(Some(_))
        ));
        // The first 256 fill the cache.
        if round >= 256 {
            h.record(t).unwrap();
        }
    }
    assert!(engine.cache_stats().hits >= n);
    let mut failures = Vec::new();
    check("cache_hit", &h, &b.budget.cache_hit, &mut failures);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn loading_the_reference_policy_is_within_budget() {
    let b = budgets();
    let doc = reference::document(Size::Reference, PrecedenceModel::DenyWins);
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = Instant::now();
    let policy = doc.validate().unwrap();
    let engine = Engine::new(policy, EngineConfig::default()).unwrap();
    let ms = start.elapsed().as_millis();
    eprintln!("load_reference_policy: {ms} ms (validate, compile and index)");
    std::hint::black_box(&engine);
    if enforce() {
        let limit = u128::from(b.budget.load_reference_policy.max_ms);
        assert!(ms <= limit, "load {ms} ms > {limit} ms");
    }
}

/// The agent's path (#43): bundle bytes with 100,000 hash rules to a
/// policy ready to decide, in one step, within the same budget.
#[test]
fn loading_the_reference_bundle_is_within_budget() {
    let b = budgets();
    let bytes = reference::bundle(Size::Reference, PrecedenceModel::DenyWins);
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = Instant::now();
    let loaded = bundle::load(&bytes, &BundleLimits::DEFAULT, None).unwrap();
    let ms = start.elapsed().as_millis();
    eprintln!(
        "load_reference_bundle: {ms} ms for {} bytes (decode, validate, compile and index)",
        bytes.len()
    );
    // It decides as the policy it was compiled from.
    let engine = Engine::from_loaded(loaded, EngineConfig::default());
    let policy = engine.snapshot();
    let state = DeviceState::of(&policy.policy().document().policy);
    let variables = PathVariables::new();
    let context = reference::context();
    for case in Case::ALL {
        let facts = case.facts(7, Size::Reference);
        let subject = Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        };
        let d = policy
            .evaluator()
            .evaluate_in(&subject, &state, TraceId([0; 16]))
            .unwrap();
        assert_eq!(d.outcome(), case.expected(), "{case:?}");
    }
    if enforce() {
        let limit = u128::from(b.budget.load_reference_policy.max_ms);
        assert!(ms <= limit, "bundle load {ms} ms > {limit} ms");
    }
}

/// The same 100,000 hashes as one first-class hash set (#368): raw
/// digests in the bundle, one rule that names the set. Within the same
/// budget, and much smaller than 4,000 rules of 25 hex values.
#[test]
fn loading_a_hash_set_bundle_is_within_budget() {
    let b = budgets();
    let rules = reference::bundle(Size::Reference, PrecedenceModel::DenyWins);
    let bytes = reference::hash_set_bundle(Size::Reference, PrecedenceModel::DenyWins);
    // Raw digests save at least the hex half of every hash, and the rule
    // around each 25 of them.
    assert!(
        rules.len() - bytes.len() >= 100_000 * 32,
        "{} bytes as a set, {} as rules",
        bytes.len(),
        rules.len()
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = Instant::now();
    let loaded = bundle::load(&bytes, &BundleLimits::DEFAULT, None).unwrap();
    let ms = start.elapsed().as_millis();
    eprintln!(
        "load_hash_set_bundle: {ms} ms for {} bytes (rules: {} bytes)",
        bytes.len(),
        rules.len()
    );
    let engine = Engine::from_loaded(loaded, EngineConfig::default());
    let policy = engine.snapshot();
    let state = DeviceState::of(&policy.policy().document().policy);
    let variables = PathVariables::new();
    let context = reference::context();
    for case in Case::ALL {
        for i in [0, 7, 99_999] {
            let facts = case.facts(i, Size::Reference);
            let subject = Subject {
                object_type: ObjectType::Executable,
                facts: &facts,
                variables: &variables,
                context: &context,
            };
            let d = policy
                .evaluator()
                .evaluate_in(&subject, &state, TraceId([0; 16]))
                .unwrap();
            assert_eq!(d.outcome(), case.expected(), "{case:?} {i}");
        }
    }
    if enforce() {
        let limit = u128::from(b.budget.load_reference_policy.max_ms);
        assert!(ms <= limit, "hash set bundle load {ms} ms > {limit} ms");
    }
}

/// The heap a loaded policy holds, counted by the allocator: everything
/// still allocated once the engine is built, including the validated
/// document the snapshot keeps. Building the JSON form the document is
/// read from is not counted: the agent reads a bundle (#43), not JSON.
fn resident_mib(size: Size) -> u64 {
    let json = reference::document(size, PrecedenceModel::DenyWins);
    let mut engine = None;
    let info = allocation_counter::measure(|| {
        let doc = json.clone();
        engine = Some(Engine::new(doc.validate().unwrap(), EngineConfig::default()).unwrap());
    });
    let bytes = u64::try_from(info.bytes_current.max(0)).unwrap_or(u64::MAX);
    drop(engine);
    bytes.div_ceil(1 << 20)
}

#[test]
fn memory_is_within_budget() {
    let b = budgets();
    let reference = resident_mib(Size::Reference);
    let million = resident_mib(Size::Million);
    eprintln!("memory: reference policy {reference} MiB, 1M hash set {million} MiB");
    assert!(
        reference <= b.budget.memory.reference_policy_mib,
        "reference policy {reference} MiB > {} MiB",
        b.budget.memory.reference_policy_mib
    );
    assert!(
        million <= b.budget.memory.million_hashset_mib,
        "1M hash set {million} MiB > {} MiB",
        b.budget.memory.million_hashset_mib
    );
}
