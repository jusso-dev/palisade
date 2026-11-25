//! Benchmarks for the policy simulator and the decision trace (#41).
//!
//! ```sh
//! cargo bench -p palisade-policy --bench simulate
//! ```
//!
//! - `simulate/decide_all_1_thread`: simulated decisions per second on one
//!   core, for a reference corpus of 10,000 snapshots against a policy of
//!   1,000 rules. The #41 target is at least 200,000 per second per core.
//! - `simulate/evaluate_in_1_thread`: the evaluator alone on the same
//!   inputs. The simulator calls nothing else per event, so the two are
//!   within noise of each other, and the simulator's throughput is the
//!   evaluator's: the indexes and caches of #42 raise both.
//! - `trace/{minimal,standard,full}`: the cost of one trace at each level,
//!   for the overhead budget of #42.
//!
//! Timings on shared hosted runners are too noisy to compare
//! (docs/testing.md), so CI only builds this.

// `criterion_group!` generates an undocumented public function.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use palisade_policy::decision::TraceId;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::mode::DeviceState;
use palisade_policy::model::{ObjectType, PolicyDocument};
use palisade_policy::trace::simulate::{FactsSnapshot, Simulator, read_snapshots};
use palisade_policy::trace::{ObjectExtras, TraceLevel, TraceOptions, Tracer};
use palisade_policy::validate::ValidatedPolicy;

/// A policy of `n` rules: hash allows, publisher-and-product allows, folder
/// allows and hash denies, in four rule sets.
fn policy(n: u32) -> ValidatedPolicy {
    let set = |k: u32, kind: &str, rules: Vec<serde_json::Value>| {
        serde_json::json!({
            "id": format!("01936b2e-8c4a-7b3d-9f21-0a1b2c3d{k:04x}"),
            "name": format!("Set {k}"),
            "kind": kind,
            "rules": rules,
        })
    };
    let rule = |i: u32, tree: serde_json::Value, action: &str| {
        serde_json::json!({
            "id": format!("01936b2e-{:04x}-7b3d-9f21-{:012x}", i % 0xffff, i),
            "name": format!("Rule {i}"),
            "object_types": ["executable"],
            "match": tree,
            "action": {"type": action},
        })
    };
    let crit = |field: &str, op: &str, v: String| serde_json::json!({"criterion": {"field": field, "operator": op, "values": [v]}});
    let mut allow = Vec::new();
    let mut deny = Vec::new();
    for i in 0..n {
        match i % 4 {
            0 => allow.push(rule(
                i,
                crit("hash.sha256", "equals", format!("{i:064x}")),
                "allow",
            )),
            1 => allow.push(rule(
                i,
                serde_json::json!({"all": [
                    crit("signer.publisher", "equals", format!("Publisher {i}")),
                    crit("meta.product_name", "equals", format!("Product {i}")),
                ]}),
                "allow",
            )),
            2 => allow.push(rule(
                i,
                serde_json::json!({"all": [
                    crit("signer.publisher", "equals", format!("Publisher {i}")),
                    crit("path.directory", "starts_with", format!("C:\\Apps\\{i}")),
                ]}),
                "allow",
            )),
            _ => deny.push(rule(
                i,
                crit("hash.sha256", "equals", format!("{:064x}", i + 1_000_000)),
                "deny",
            )),
        }
    }
    let doc = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Reference",
            "revision": 1,
            "mode": "audit",
            "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001", "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002"],
        },
        "rule_sets": [set(1, "allowlist", allow), set(2, "blocklist", deny)],
    });
    match PolicyDocument::from_json(&doc.to_string()).map(PolicyDocument::validate) {
        Ok(Ok(p)) => p,
        other => panic!("reference policy: {other:?}"),
    }
}

/// `n` snapshots: a mix of hash hits, publisher hits and unknown objects.
fn corpus(n: usize) -> Vec<FactsSnapshot> {
    let mut yaml = String::from("facts_schema_version: \"1.0.0\"\nsnapshots:\n");
    for i in 0..n {
        let r = i % 1000;
        yaml.push_str(&format!(
            "  - event_id: e{i}\n    device_id: d{}\n    object_type: executable\n    facts:\n      values: {{hash.sha256: '{:064x}', meta.product_name: 'Product {r}'}}\n      path: {{path: 'C:\\Apps\\{r}\\a.exe', user_writable: false}}\n      signers: [{{status: valid, publisher: 'Publisher {r}'}}]\n",
            i % 100,
            if i % 3 == 0 { r } else { r + 5_000_000 },
        ));
    }
    match read_snapshots(&yaml) {
        Ok(f) => f.snapshots,
        Err(e) => panic!("corpus: {e}"),
    }
}

fn simulate(c: &mut Criterion) {
    let p = policy(1_000);
    let snaps = corpus(10_000);
    let sim = match Simulator::new(&p) {
        Ok(s) => s.with_threads(1),
        Err(e) => panic!("{e}"),
    };
    let mut g = c.benchmark_group("simulate");
    g.throughput(Throughput::Elements(snaps.len() as u64));
    g.sample_size(10);
    g.bench_function("decide_all_1_thread", |b| {
        b.iter(|| black_box(sim.decide_all(black_box(&snaps))));
    });
    // The evaluator alone, on the same inputs: the simulator's own cost is
    // the difference.
    let inputs: Vec<_> = snaps
        .iter()
        .map(|s| match s.inputs() {
            Ok(i) => i,
            Err(e) => panic!("{e}"),
        })
        .collect();
    let evaluator = match Evaluator::new(&p) {
        Ok(e) => e,
        Err(e) => panic!("{e}"),
    };
    let state = DeviceState::of(&p.document().policy);
    g.bench_function("evaluate_in_1_thread", |b| {
        b.iter(|| {
            for i in &inputs {
                let subject = Subject {
                    object_type: ObjectType::Executable,
                    facts: &i.facts,
                    variables: &i.variables,
                    context: &i.context,
                };
                black_box(evaluator.evaluate_in(&subject, &state, TraceId([0; 16])));
            }
        });
    });
    g.finish();
}

fn trace(c: &mut Criterion) {
    let p = policy(1_000);
    let snaps = corpus(3);
    let tracer = match Tracer::new(&p) {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    let inputs = match snaps[1].inputs() {
        Ok(i) => i,
        Err(e) => panic!("{e}"),
    };
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &inputs.facts,
        variables: &inputs.variables,
        context: &inputs.context,
    };
    let state = DeviceState::of(&p.document().policy);
    let mut g = c.benchmark_group("trace");
    for level in [TraceLevel::Minimal, TraceLevel::Standard, TraceLevel::Full] {
        let options = TraceOptions::at(level);
        g.bench_function(format!("{level:?}").to_lowercase(), |b| {
            b.iter(|| {
                black_box(tracer.trace(
                    black_box(&subject),
                    &ObjectExtras::default(),
                    &state,
                    TraceId([0; 16]),
                    &options,
                ))
            });
        });
    }
    g.finish();
}

criterion_group!(benches, simulate, trace);
criterion_main!(benches);
