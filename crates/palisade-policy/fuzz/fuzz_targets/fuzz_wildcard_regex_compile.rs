//! Fuzzes the compiler of criterion values, wildcards and regular
//! expressions (#32, #25), and matching with the result. Patterns come from
//! policies, and facts from untrusted files. No pattern may panic, and the
//! per-input time limit catches any match that is not linear.
//!
//! Input: one byte (the low seven bits pick the field and operator, the high
//! bit `case_sensitive`), then the pattern, a zero byte, and the fact the
//! pattern is matched against.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_core::path::VolumeMap;
use palisade_policy::context::EvaluationContext;
use palisade_policy::facts::{ObjectFacts, PathFact, PathVariable, PathVariables};
use palisade_policy::model::{ActionKind, Criterion};
use palisade_policy::ops::{CompiledCriterion, EvalContext};

const FIELDS: [&str; 3] = ["path.full", "meta.product_name", "path.file_name"];
const OPERATORS: [&str; 8] = [
    "wildcard",
    "not_wildcard",
    "regex",
    "not_regex",
    "equals",
    "starts_with",
    "contains",
    "ends_with",
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
    let facts = if field.starts_with("path.") {
        ObjectFacts::new()
            .with_path(PathFact::new(fact, &VolumeMap::new()).with_user_writable(false))
    } else {
        ObjectFacts::new().with(criterion.field, fact)
    };
    let variables = PathVariables::new().with(PathVariable::ProgramFiles, &[r"C:\Program Files"]);
    let context = EvaluationContext::new();
    for action in [ActionKind::Allow, ActionKind::Deny] {
        let _ = compiled.eval(
            &facts,
            &EvalContext {
                action,
                variables: &variables,
                context: &context,
            },
        );
    }
});
