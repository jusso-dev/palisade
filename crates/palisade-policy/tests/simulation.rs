//! The policy-as-code tests and recorded facts in
//! `docs/examples/simulation/` against their policy (#41). CI runs these,
//! so a policy change that breaks its tests fails the build.

#![allow(clippy::unwrap_used)]

use std::path::Path;

use palisade_policy::dsl;
use palisade_policy::model::Mode;
use palisade_policy::trace::readiness::{ReadinessOptions, readiness};
use palisade_policy::trace::simulate::{Candidate, Simulator, read_snapshots};
use palisade_policy::trace::{TraceLevel, TraceOptions, policy_test};
use palisade_policy::validate::ValidatedPolicy;

fn read(rel: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/examples")
            .join(rel),
    )
    .unwrap()
}

fn policy() -> ValidatedPolicy {
    dsl::from_str(&read("policies/staged-rollout.yaml"))
        .unwrap()
        .validate()
        .unwrap()
        .into_policy()
}

#[test]
fn the_example_policy_passes_its_tests() {
    let file = policy_test::read_tests(&read("simulation/staged-rollout.tests.yaml")).unwrap();
    let report = policy_test::run(&policy(), "staged-rollout", &file).unwrap();
    for r in &report.results {
        assert!(
            r.passed,
            "{}: {:?}\n{}",
            r.name,
            r.failures,
            r.explanation.as_deref().unwrap_or("")
        );
    }
    assert_eq!(report.exit_code(), 0);
    let junit = report.junit();
    assert!(junit.contains("tests=\"6\" failures=\"0\""), "{junit}");
}

#[test]
fn moving_the_example_to_enforce_is_simulated_and_gated() {
    let p = policy();
    let snaps = read_snapshots(&read("simulation/staged-rollout.snapshots.yaml"))
        .unwrap()
        .snapshots;
    let report = Simulator::new(&p)
        .unwrap()
        .run(&snaps, Some(&Candidate::Mode(Mode::Enforce)))
        .unwrap();
    // Newly blocked: the two cleanup.ps1 runs and the old unknown script
    // (no rule allows them), and the remote access tool. Its blocklist stays
    // in monitor, so its deny is set aside, but no rule allows the tool, and
    // the implicit deny now enforces (#36: a blocklist in monitor never lets
    // through what another rule blocks). The bypass tool and the retired
    // script host were blocked already.
    assert_eq!(report.summary.newly_blocked, 4, "{report:#?}");
    assert_eq!(report.summary.newly_allowed, 0);
    let remote = report
        .changes
        .iter()
        .find(|c| c.event_id == "ws-02-0001")
        .unwrap();
    assert_eq!(
        remote.candidate.as_ref().unwrap().rule,
        None,
        "blocked by the implicit deny"
    );
    let r = readiness(
        &p,
        &snaps,
        &ReadinessOptions {
            until: 1_700_604_800,
            days: 7,
            max_would_block: 0,
            ack_threshold: Some(0),
            top_objects: 3,
        },
    )
    .unwrap();
    assert_eq!(
        r.gate.message,
        "3 would-block events across 2 devices in the last 7 days"
    );
    assert!(r.gate.ack_required);
    assert_eq!(r.events_outside_window, 1);
    assert_eq!(r.top_objects[0].would_block, 2);
    assert!(r.top_objects[0].object.starts_with("sha256:cccc"));
    // Every event can be explained.
    let sim = Simulator::new(&p).unwrap();
    for s in &snaps {
        let t = sim.trace(s, &TraceOptions::at(TraceLevel::Full)).unwrap();
        assert_eq!(t.level, TraceLevel::Full);
    }
}
