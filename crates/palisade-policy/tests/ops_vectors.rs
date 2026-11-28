//! Table-driven operator vectors (#32): every `tests/vectors/ops/*.toml`
//! case, compiled and evaluated. See `tests/vectors/ops/README.md` for the
//! format.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;

use palisade_core::path::VolumeMap;
use palisade_policy::context::{
    Date, EvaluationContext, IntegrityLevel, Probe, ProcessContext, Weekday,
};
use palisade_policy::facts::{ObjectFacts, PathFact, PathVariables};
use palisade_policy::model::{ActionKind, Criterion};
use palisade_policy::ops::net::{parse_ip, parse_mac};
use palisade_policy::ops::{CompileErrorKind, CompiledCriterion, EvalContext, Tri};

fn error_name(kind: &CompileErrorKind) -> &'static str {
    match kind {
        CompileErrorKind::OperatorFieldMismatch => "operator_field_mismatch",
        CompileErrorKind::ValueCount => "value_count",
        CompileErrorKind::InvalidValue(_) => "invalid_value",
        CompileErrorKind::RegexLookAround => "regex_look_around",
        CompileErrorKind::RegexBackreference => "regex_backreference",
        CompileErrorKind::PatternTooLarge => "pattern_too_large",
        CompileErrorKind::RegexSyntax(_) => "regex_syntax",
        CompileErrorKind::CaseSensitivityNotApplicable => "case_sensitivity_not_applicable",
        CompileErrorKind::OptionNotApplicable(..) => "option_not_applicable",
    }
}

fn strings(v: &toml::Value) -> Vec<String> {
    v.as_array()
        .expect("a list")
        .iter()
        .map(|s| s.as_str().expect("a string").to_owned())
        .collect()
}

fn context(table: Option<&toml::Value>) -> EvaluationContext {
    let mut ctx = EvaluationContext::new();
    let Some(table) = table else { return ctx };
    for (key, value) in table.as_table().expect("a table") {
        let text = || value.as_str().expect("a string").to_owned();
        let number = || value.as_integer().expect("an integer");
        match key.as_str() {
            "user.groups" => ctx.user.groups = Some(strings(value)),
            "user.dn" => ctx.user.dn = Some(text()),
            "user.integrity_level" => {
                ctx.user.integrity_level = Some(IntegrityLevel::from_name(&text()).unwrap());
            }
            "device.os_build" => ctx.device.os_build = Some(u32::try_from(number()).unwrap()),
            "device.dn" => ctx.device.dn = Some(text()),
            "session.id" => ctx.session.id = Some(u32::try_from(number()).unwrap()),
            "session.client_ip" => ctx.session.client_ip = Some(parse_ip(&text()).unwrap()),
            "net.ip" => {
                ctx.network.addresses = Some(
                    strings(value)
                        .iter()
                        .map(|s| parse_ip(s).unwrap())
                        .collect(),
                );
            }
            "net.mac" => {
                ctx.network.macs = Some(
                    strings(value)
                        .iter()
                        .map(|s| parse_mac(s).unwrap())
                        .collect(),
                );
            }
            "net.dns_suffix" => ctx.network.dns_suffixes = Some(strings(value)),
            "net.locations" => ctx.network.locations = Some(strings(value)),
            "time.weekday" => ctx.time.weekday = Some(Weekday::from_name(&text()).unwrap()),
            "time.minute" => ctx.time.minute_of_day = Some(u16::try_from(number()).unwrap()),
            "time.date" => ctx.time.date = Some(Date::parse(&text()).unwrap()),
            "process.command_line" => {
                ctx.process = ProcessContext::with_command_line(text());
            }
            other => panic!("unknown context key `{other}`"),
        }
    }
    ctx
}

fn run_case(file: &str, case: &toml::Table) {
    let name = case["name"].as_str().unwrap();
    let label = format!("{file}: {name}");
    let criterion_json = serde_json::to_value(&case["criterion"]).unwrap();
    let criterion: Criterion = serde_json::from_value(criterion_json)
        .unwrap_or_else(|e| panic!("{label}: the criterion does not read: {e}"));
    let compiled = CompiledCriterion::compile(&criterion);
    if let Some(error) = case.get("error") {
        let errors = compiled
            .err()
            .unwrap_or_else(|| panic!("{label}: compiled"));
        assert_eq!(
            error_name(&errors[0].kind),
            error.as_str().unwrap(),
            "{label}"
        );
        return;
    }
    let compiled = compiled.unwrap_or_else(|e| panic!("{label}: {e:?}"));
    let mut facts = ObjectFacts::new();
    if let Some(fact) = case.get("fact") {
        facts.set(criterion.field, fact.as_str().unwrap());
    }
    if let Some(path) = case.get("path") {
        let mut p = PathFact::new(path.as_str().unwrap(), &VolumeMap::new());
        p.user_writable = case.get("user_writable").map(|w| w.as_bool().unwrap());
        p.fold_unknown = case
            .get("fold_unknown")
            .is_some_and(|w| w.as_bool().unwrap());
        p.volume = match case.get("volume").map(|v| v.as_str().unwrap()) {
            None => None,
            Some("fixed") => Some(palisade_policy::unknown::VolumeKind::Fixed),
            Some("removable") => Some(palisade_policy::unknown::VolumeKind::Removable),
            Some("optical") => Some(palisade_policy::unknown::VolumeKind::Optical),
            Some("network") => Some(palisade_policy::unknown::VolumeKind::Network),
            Some(other) => panic!("{label}: unknown volume `{other}`"),
        };
        facts = facts.with_path(p);
    }
    let action = match case.get("action").map(|a| a.as_str().unwrap()) {
        None | Some("deny") => ActionKind::Deny,
        Some("allow") => ActionKind::Allow,
        Some(other) => panic!("{label}: unknown action `{other}`"),
    };
    let mut ctx = context(case.get("context"));
    // What the agent found at the criterion's target (#329): `absent`,
    // `present`, `other` (a value of another type), a string or a number.
    if let Some(probe) = case.get("probe") {
        let found = match probe {
            toml::Value::String(t) if t == "absent" => Probe::Absent,
            toml::Value::String(t) if t == "present" => Probe::Present,
            toml::Value::String(t) if t == "other" => Probe::Other,
            toml::Value::String(t) if t == "timed_out" => Probe::TimedOut,
            toml::Value::String(t) => Probe::Text(t.clone()),
            toml::Value::Integer(n) => Probe::Number(u64::try_from(*n).unwrap()),
            other => panic!("{label}: unknown probe {other:?}"),
        };
        assert!(
            ctx.probes.insert(
                criterion.field,
                criterion.target.as_deref().unwrap(),
                criterion.value_name.as_deref(),
                found
            ),
            "{label}: the probe was not recorded"
        );
    }
    let variables = PathVariables::new();
    let result = compiled
        .eval(
            &facts,
            &EvalContext {
                action,
                variables: &variables,
                context: &ctx,
            },
        )
        .result;
    let expected = match case["expect"].as_str().unwrap() {
        "match" => Tri::Match,
        "no_match" => Tri::NoMatch,
        "unknown" => Tri::Unknown,
        other => panic!("{label}: unknown expectation `{other}`"),
    };
    assert_eq!(result, expected, "{label}");
}

#[test]
fn every_operator_vector_holds() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ops");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    assert!(files.len() >= 5, "vector files are missing");
    let mut cases = 0usize;
    for path in files {
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        let doc: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        for case in doc["case"].as_array().unwrap() {
            run_case(&file, case.as_table().unwrap());
            cases += 1;
        }
    }
    assert!(cases >= 80, "only {cases} cases");
}
