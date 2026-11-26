//! Fuzzes the compiler of criterion values, wildcards and regular
//! expressions (#32, #25), and matching with the result. Patterns come from
//! policies, and facts from untrusted files. No pattern may panic, and the
//! per-input time limit catches any match that is not linear.
//!
//! Input: one byte (the low seven bits pick the field and operator, the high
//! bit `case_sensitive`), then the pattern, a zero byte, and the fact the
//! pattern is matched against. For `path.file_name` the fact is a file name,
//! placed in a directory so that it is a full path.
//!
//! Besides not panicking, it checks the fail-closed rules of #31 and #32:
//! a path test in an allow rule never matches a path whose permissions are
//! unknown or writable by users, and a regular expression on `path.full`
//! never matches an alternate data stream.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_core::path::VolumeMap;
use palisade_policy::context::EvaluationContext;
use palisade_policy::facts::{ObjectFacts, PathFact, PathVariable, PathVariables};
use palisade_policy::model::{ActionKind, Criterion};
use palisade_policy::ops::{CompiledCriterion, EvalContext, Tri};

fn operator_is_positive(operator: &str) -> bool {
    !operator.starts_with("not_")
}

const FIELDS: [&str; 3] = ["path.full", "meta.product_name", "path.file_name"];
const OPERATORS: [&str; 10] = [
    "wildcard",
    "not_wildcard",
    "regex",
    "not_regex",
    "equals",
    "not_equals",
    "starts_with",
    "ends_with",
    "contains",
    "not_contains",
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let (pattern, fact) = match rest.iter().position(|&b| b == 0) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &[][..]),
    };
    let (Ok(pattern), Ok(fact)) = (std::str::from_utf8(pattern), std::str::from_utf8(fact)) else {
        return;
    };
    // The low seven bits pick the field and operator, the high bit the case.
    let pick = usize::from(selector & 0x7f);
    let field = FIELDS[pick % FIELDS.len()];
    let operator = OPERATORS[pick / FIELDS.len() % OPERATORS.len()];
    let case_sensitive = selector & 0x80 != 0;
    // Built from JSON, so new optional criterion fields never break this.
    let json = serde_json::json!({
        "field": field,
        "operator": operator,
        "values": [pattern],
        "case_sensitive": case_sensitive,
    });
    let Ok(criterion) = serde_json::from_value::<Criterion>(json) else {
        return;
    };
    let Ok(compiled) = CompiledCriterion::compile(&criterion) else {
        return;
    };
    let variables = PathVariables::new().with(PathVariable::ProgramFiles, &[r"C:\Program Files"]);
    let context = EvaluationContext::new();
    let eval = |facts: &ObjectFacts, action| {
        compiled
            .eval(
                facts,
                &EvalContext {
                    action,
                    variables: &variables,
                    context: &context,
                },
            )
            .result
    };
    if !field.starts_with("path.") {
        let facts = ObjectFacts::new().with(criterion.field, fact);
        for action in [ActionKind::Allow, ActionKind::Deny] {
            let _ = eval(&facts, action);
        }
        return;
    }
    let raw = if field == "path.file_name" {
        format!(r"C:\dir\{fact}")
    } else {
        fact.to_owned()
    };
    let mut volumes = VolumeMap::new();
    volumes.insert(r"\Device\HarddiskVolume3", 'C');
    let path = PathFact::new(&raw, &volumes);
    let is_stream = path.path.stream().is_some();
    for writable in [Some(false), Some(true), None] {
        let facts = ObjectFacts::new().with_path(PathFact {
            user_writable: writable,
            ..path.clone()
        });
        let allow = eval(&facts, ActionKind::Allow);
        let deny = eval(&facts, ActionKind::Deny);
        if writable != Some(false) && operator_is_positive(operator) {
            assert_ne!(allow, Tri::Match, "allow trusted an unsafe path");
        }
        if is_stream && field == "path.full" && operator == "regex" {
            assert_ne!(deny, Tri::Match, "a regex matched a stream");
        }
    }
});
