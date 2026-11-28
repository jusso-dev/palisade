//! Seed inputs for the palisade-policy fuzz targets (#25, #30, #32), written
//! on request. `cargo xtask fuzz` runs these before each target. To run one
//! by hand:
//!
//! ```sh
//! PALISADE_FUZZ_SEED_DIR=/tmp/seeds \
//!     cargo test -p palisade-policy --test fuzz_seeds -- --ignored write_policy_json_fuzz_seeds
//! ```

// `clippy.toml` allows unwrap and expect inside `#[test]` functions only;
// the helpers here are test code too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The directory to write into, from `PALISADE_FUZZ_SEED_DIR`.
fn seed_dir() -> PathBuf {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = PathBuf::from(dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Every file with `extension` in `dir` and its subdirectories, sorted.
fn files(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == extension) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Copies every file in `sources` into `dir` as `seed-<i>`.
fn copy_all(dir: &Path, sources: &[PathBuf]) {
    assert!(!sources.is_empty(), "no seed sources");
    for (i, source) in sources.iter().enumerate() {
        fs::copy(source, dir.join(format!("seed-{i}"))).unwrap();
    }
}

/// Every JSON fixture: valid, invalid and malformed documents.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_policy_json_fuzz_seeds() {
    copy_all(
        &seed_dir(),
        &files(&manifest_dir().join("tests/fixtures"), "json"),
    );
}

/// Every YAML fixture and example policy.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_policy_yaml_fuzz_seeds() {
    let mut sources = files(&manifest_dir().join("tests/fixtures/yaml"), "yaml");
    sources.extend(files(
        &manifest_dir().join("../../docs/examples/policies"),
        "yaml",
    ));
    copy_all(&seed_dir(), &sources);
}

/// The fields and operators of `fuzz_wildcard_regex_compile`, in its order.
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

/// The selector byte for a field, an operator and the case.
fn selector(field: &str, operator: &str, case_sensitive: bool) -> u8 {
    let f = FIELDS.iter().position(|x| *x == field).unwrap();
    let o = OPERATORS.iter().position(|x| *x == operator).unwrap();
    let pick = u8::try_from(o * FIELDS.len() + f).unwrap();
    assert!(pick < 0x80);
    pick | if case_sensitive { 0x80 } else { 0 }
}

/// Seed patterns: field, operator, case-sensitive, pattern, fact, and the
/// result in a deny rule (which trusts any path). For `path.file_name` the
/// fact is a file name; the target places it in a directory.
const PATTERNS: &[(&str, &str, bool, &str, &str, bool)] = &[
    // Recursive and single-component wildcards, streams, variables, escapes.
    (
        "path.full",
        "wildcard",
        false,
        r"C:\Program Files\**\*.exe",
        r"C:\Program Files\App\bin\app.exe",
        true,
    ),
    (
        "path.full",
        "wildcard",
        false,
        r"%PROGRAMFILES%\*\app?.exe",
        r"C:\Program Files\X\app1.exe",
        true,
    ),
    (
        "path.full",
        "wildcard",
        false,
        r"C:\x\*:*",
        r"C:\x\a.txt:payload",
        true,
    ),
    (
        "path.full",
        "wildcard",
        false,
        r"**\[*]odd[?].exe",
        r"D:\a\*odd?.exe",
        true,
    ),
    (
        "path.full",
        "not_wildcard",
        false,
        r"\\server\share\**",
        r"\\server\share\dir\f.exe",
        false,
    ),
    (
        "path.full",
        "regex",
        false,
        r"C:\\x\\.*",
        r"C:\x\a.txt:payload",
        false,
    ),
    (
        "path.full",
        "starts_with",
        false,
        r"C:\Tools",
        r"\Device\HarddiskVolume3\tools\a.exe",
        true,
    ),
    // Text wildcards and linear-time regular expressions.
    (
        "meta.product_name",
        "wildcard",
        false,
        "Ex*Suite ?",
        "Example Suite 2",
        true,
    ),
    (
        "meta.product_name",
        "regex",
        false,
        "Ex[a-z]+ (Suite|Tool)",
        "Example Tool",
        true,
    ),
    (
        "meta.product_name",
        "regex",
        false,
        "(a|aa)*b",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac",
        false,
    ),
    (
        "meta.product_name",
        "regex",
        false,
        r"\p{L}+\d{1,3}",
        "\u{dc}n\u{ef}code42",
        true,
    ),
    (
        "meta.product_name",
        "not_contains",
        false,
        "beta",
        "Example Suite",
        true,
    ),
    // File-name text operators.
    (
        "path.file_name",
        "starts_with",
        false,
        "notepad",
        "NOTEPAD.EXE",
        true,
    ),
    (
        "path.file_name",
        "ends_with",
        false,
        ".exe",
        "setup.EXE",
        true,
    ),
    (
        "path.file_name",
        "not_equals",
        false,
        "cmd.exe",
        "CMD.EXE",
        false,
    ),
    // Case-sensitive variants.
    (
        "path.full",
        "wildcard",
        true,
        r"C:\Tools\*",
        r"c:\tools\a.exe",
        false,
    ),
    ("meta.product_name", "regex", true, "Ex.*", "example", false),
];

/// Patterns and facts in the target's input format: a selector byte, the
/// pattern, a zero byte, then the fact.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_pattern_fuzz_seeds() {
    let dir = seed_dir();
    for (i, (field, operator, case, pattern, fact, _)) in PATTERNS.iter().enumerate() {
        let mut bytes = vec![selector(field, operator, *case)];
        bytes.extend_from_slice(pattern.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(fact.as_bytes());
        fs::write(dir.join(format!("seed-{i}")), bytes).unwrap();
    }
}

/// Every pattern seed decodes to the field and operator it names, compiles,
/// and gives the stated result, so a seed cannot silently stop exercising
/// the matcher. The facts are prepared as the fuzz target prepares them.
#[test]
fn pattern_seeds_compile_and_match_as_stated() {
    use palisade_core::path::VolumeMap;
    use palisade_policy::context::EvaluationContext;
    use palisade_policy::facts::{ObjectFacts, PathFact, PathVariable, PathVariables};
    use palisade_policy::model::{ActionKind, Criterion};
    use palisade_policy::ops::{CompiledCriterion, EvalContext, Tri};

    let variables = PathVariables::new().with(PathVariable::ProgramFiles, &[r"C:\Program Files"]);
    let context = EvaluationContext::new();
    let mut volumes = VolumeMap::new();
    volumes.insert(r"\Device\HarddiskVolume3", 'C');
    for (field, operator, case, pattern, fact, expected) in PATTERNS {
        let s = selector(field, operator, *case);
        let pick = usize::from(s & 0x7f);
        assert_eq!(FIELDS[pick % FIELDS.len()], *field);
        assert_eq!(OPERATORS[pick / FIELDS.len() % OPERATORS.len()], *operator);
        let criterion: Criterion = serde_json::from_value(serde_json::json!({
            "field": field,
            "operator": operator,
            "values": [pattern],
            "case_sensitive": case,
        }))
        .unwrap();
        let compiled = CompiledCriterion::compile(&criterion)
            .unwrap_or_else(|e| panic!("{field} {operator} {pattern:?}: {e:?}"));
        let facts = if field.starts_with("path.") {
            let raw = if *field == "path.file_name" {
                format!(r"C:\dir\{fact}")
            } else {
                (*fact).to_owned()
            };
            ObjectFacts::new().with_path(PathFact::new(&raw, &volumes))
        } else {
            ObjectFacts::new().with(criterion.field, *fact)
        };
        let result = compiled
            .eval(
                &facts,
                &EvalContext {
                    action: ActionKind::Deny,
                    variables: &variables,
                    context: &context,
                },
            )
            .result;
        let want = if *expected { Tri::Match } else { Tri::NoMatch };
        assert_eq!(result, want, "{field} {operator} {pattern:?} on {fact:?}");
    }
}

/// The golden bundles, and each truncated after its header, so the fuzzer
/// starts from inputs that pass the header and reach the body.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_bundle_fuzz_seeds() {
    let dir = seed_dir();
    let sources = files(&manifest_dir().join("tests/golden/bundles"), "cbor");
    assert!(!sources.is_empty(), "no golden bundles");
    for (i, source) in sources.iter().enumerate() {
        let bytes = fs::read(source).unwrap();
        fs::write(dir.join(format!("seed-{i}")), &bytes).unwrap();
        fs::write(
            dir.join(format!("seed-{i}-half")),
            &bytes[..bytes.len() / 2],
        )
        .unwrap();
    }
}

/// The golden bundles' delta, from `minimal` to `baseline`, and malformed
/// variants: truncated, with a trailing byte, and with each hash changed.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_bundle_delta_fuzz_seeds() {
    use palisade_policy::bundle::{BundleDelta, BundleLimits, PolicyBundle, diff};

    let dir = seed_dir();
    let golden = manifest_dir().join("tests/golden/bundles");
    let limits = BundleLimits::DEFAULT;
    let read =
        |name: &str| PolicyBundle::decode(&fs::read(golden.join(name)).unwrap(), &limits).unwrap();
    let delta = diff(&read("minimal.cbor"), &read("baseline.cbor")).unwrap();
    let bytes = delta.to_bytes().unwrap();
    assert_eq!(BundleDelta::from_bytes(&bytes, &limits).unwrap(), delta);
    fs::write(dir.join("seed-delta"), &bytes).unwrap();
    fs::write(dir.join("seed-delta-half"), &bytes[..bytes.len() / 2]).unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    fs::write(dir.join("seed-delta-trailing"), &trailing).unwrap();
    let mut other = delta.clone();
    other.result_bundle_hash = [0; 32];
    fs::write(dir.join("seed-delta-result"), other.to_bytes().unwrap()).unwrap();
    other.base_bundle_hash = [0; 32];
    fs::write(dir.join("seed-delta-base"), other.to_bytes().unwrap()).unwrap();
}
