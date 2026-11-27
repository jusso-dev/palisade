//! Policy-as-code tests (#41): `given` facts, `expect` a decision.
//!
//! A test file sits next to a policy and holds its tests:
//!
//! ```yaml
//! policy_tests_version: "1.0.0"
//! tests:
//!   - name: the signed tool runs
//!     given:
//!       object_type: executable
//!       facts:
//!         signers: [{status: valid, publisher: Example Ltd}]
//!     expect:
//!       outcome: allowed
//!       rule: R-000123
//! ```
//!
//! `given` is a facts snapshot ([`super::simulate::FactsSnapshot`]) without
//! the event fields. `expect` checks any of `outcome`, `would_have_been`,
//! `reason_code`, `mode` and the deciding `rule` (by short ID or rule ID;
//! `no_rule: true` expects the implicit deny). Each test is decided by the
//! simulator, so by the agent's evaluator.
//!
//! [`run`] gives a [`TestReport`]: [`TestReport::exit_code`] is non-zero
//! when a test fails, and [`TestReport::junit`] writes JUnit XML for CI.
//! The `pal policy test` command (#15) reads the files and prints these.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::dsl::{self, Limits};
use crate::model::{Mode, ObjectType};
use crate::validate::ValidatedPolicy;

use super::simulate::{
    FactsSnapshot, SimError, SimOutcome, Simulator, SnapshotContext, SnapshotFacts, SnapshotState,
};
use super::{Catalog, TraceLevel, TraceOptions, Verbosity, explain, render_text};

/// The version of the test file format.
pub const POLICY_TESTS_VERSION: &str = "1.0.0";

/// The most tests in one file.
pub const MAX_TESTS: usize = 10_000;

/// A test file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestFile {
    /// [`POLICY_TESTS_VERSION`].
    pub policy_tests_version: String,
    /// The tests.
    pub tests: Vec<TestCase>,
}

/// One test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    /// Its name, unique in the file.
    pub name: String,
    /// The inputs.
    pub given: Given,
    /// What must be decided.
    pub expect: Expect,
}

/// The inputs of a test: a facts snapshot without the event fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Given {
    /// The object's type.
    pub object_type: ObjectType,
    /// Its facts.
    #[serde(default)]
    pub facts: SnapshotFacts,
    /// The path variables.
    #[serde(default)]
    pub variables: std::collections::BTreeMap<String, Vec<String>>,
    /// The user, device and session.
    #[serde(default)]
    pub context: SnapshotContext,
    /// The device's state.
    #[serde(default)]
    pub device_state: SnapshotState,
}

/// What a test expects. Unset fields are not checked; at least one must
/// be set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    /// The outcome.
    #[serde(default)]
    pub outcome: Option<SimOutcome>,
    /// The enforce-mode outcome.
    #[serde(default)]
    pub would_have_been: Option<SimOutcome>,
    /// The reason code, such as `explicit_deny`.
    #[serde(default)]
    pub reason_code: Option<String>,
    /// The effective mode.
    #[serde(default)]
    pub mode: Option<Mode>,
    /// The deciding rule: its short ID (`R-000123`) or rule ID.
    #[serde(default)]
    pub rule: Option<String>,
    /// No rule decides: the implicit deny, or a disabled device.
    #[serde(default)]
    pub no_rule: bool,
}

/// A test file could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TestFileError {
    /// It does not parse.
    Parse(String),
    /// Its version is not readable.
    UnsupportedVersion(String),
    /// Two tests have the same name, a test expects nothing, or there are
    /// too many tests.
    Invalid(String),
}

impl core::fmt::Display for TestFileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "not a policy test file: {m}"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "policy_tests_version {v} is not readable ({POLICY_TESTS_VERSION})"
            ),
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for TestFileError {}

/// Reads a test file, YAML or JSON.
///
/// # Errors
///
/// [`TestFileError`] if it does not parse, has another major version, has
/// duplicate names, or a test expects nothing.
pub fn read_tests(input: &str) -> Result<TestFile, TestFileError> {
    let value = dsl::to_json_value(input, &Limits::DEFAULT)
        .map_err(|e| TestFileError::Parse(e.to_string()))?;
    let version = value
        .get("policy_tests_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TestFileError::Parse("missing policy_tests_version".to_owned()))?
        .to_owned();
    if !readable(&version) {
        return Err(TestFileError::UnsupportedVersion(version));
    }
    if let Some(n) = value
        .get("tests")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        && n > MAX_TESTS
    {
        return Err(TestFileError::Invalid(format!(
            "{n} tests; at most {MAX_TESTS}"
        )));
    }
    let file: TestFile =
        serde_json::from_value(value).map_err(|e| TestFileError::Parse(e.to_string()))?;
    file.validate()?;
    Ok(file)
}

/// Whether this reader can read test files of `version`.
fn readable(version: &str) -> bool {
    version
        .parse::<palisade_core::SchemaVersion>()
        .ok()
        .zip(
            POLICY_TESTS_VERSION
                .parse::<palisade_core::SchemaVersion>()
                .ok(),
        )
        .is_some_and(|(v, r)| super::simulate::readable(v, r))
}

impl TestFile {
    /// Checks what [`read_tests`] checks after parsing: the version, the
    /// number of tests, unique names, and that each test expects something
    /// and does not set both `rule` and `no_rule`. [`run`] checks it too,
    /// so a file built in code is held to the same rules as one read.
    ///
    /// # Errors
    ///
    /// [`TestFileError::UnsupportedVersion`] or [`TestFileError::Invalid`].
    pub fn validate(&self) -> Result<(), TestFileError> {
        if !readable(&self.policy_tests_version) {
            return Err(TestFileError::UnsupportedVersion(
                self.policy_tests_version.clone(),
            ));
        }
        if self.tests.len() > MAX_TESTS {
            return Err(TestFileError::Invalid(format!(
                "{} tests; at most {MAX_TESTS}",
                self.tests.len()
            )));
        }
        let mut names = BTreeSet::new();
        for t in &self.tests {
            if !names.insert(t.name.as_str()) {
                return Err(TestFileError::Invalid(format!(
                    "test {:?} appears more than once",
                    t.name
                )));
            }
            if t.expect == Expect::default() {
                return Err(TestFileError::Invalid(format!(
                    "test {:?} expects nothing",
                    t.name
                )));
            }
            if t.expect.no_rule && t.expect.rule.is_some() {
                return Err(TestFileError::Invalid(format!(
                    "test {:?} sets both rule and no_rule",
                    t.name
                )));
            }
        }
        Ok(())
    }
}

/// The result of one test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TestResult {
    /// The test.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// One line per expectation that failed.
    pub failures: Vec<String>,
    /// For a failure, the explanation of what was decided.
    pub explanation: Option<String>,
}

/// The results of a test file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TestReport {
    /// The suite's name, such as the file name.
    pub suite: String,
    /// The results, in file order.
    pub results: Vec<TestResult>,
}

impl TestReport {
    /// How many failed.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    /// 0 if every test passed, 1 otherwise.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        i32::from(self.failed() > 0)
    }

    /// The report as JUnit XML.
    #[must_use]
    pub fn junit(&self) -> String {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str(&format!(
            "<testsuites tests=\"{}\" failures=\"{}\">\n  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\">\n",
            self.results.len(),
            self.failed(),
            xml(&self.suite),
            self.results.len(),
            self.failed()
        ));
        for r in &self.results {
            out.push_str(&format!(
                "    <testcase classname=\"{}\" name=\"{}\"",
                xml(&self.suite),
                xml(&r.name)
            ));
            if r.passed {
                out.push_str("/>\n");
            } else {
                out.push_str(">\n");
                out.push_str(&format!(
                    "      <failure message=\"{}\">{}</failure>\n",
                    xml(&r.failures.join("; ")),
                    xml(r.explanation.as_deref().unwrap_or(""))
                ));
                out.push_str("    </testcase>\n");
            }
        }
        out.push_str("  </testsuite>\n</testsuites>\n");
        out
    }
}

/// Runs a test file against a policy.
///
/// # Errors
///
/// [`SimError::Tests`] if the file breaks the rules [`read_tests`] checks
/// (for example, a test expects nothing), or another [`SimError`] if a
/// test's inputs cannot be used or the policy cannot be compiled.
pub fn run(policy: &ValidatedPolicy, suite: &str, file: &TestFile) -> Result<TestReport, SimError> {
    file.validate().map_err(SimError::Tests)?;
    let sim = Simulator::new(policy)
        .map_err(|e| SimError::Candidate(super::simulate::CandidateError::Build(e)))?;
    let snapshots: Vec<FactsSnapshot> = file
        .tests
        .iter()
        .map(|t| FactsSnapshot {
            event_id: t.name.clone(),
            device_id: None,
            timestamp: None,
            object_type: t.given.object_type,
            facts: t.given.facts.clone(),
            variables: t.given.variables.clone(),
            context: t.given.context.clone(),
            device_state: t.given.device_state,
            recorded: None,
        })
        .collect();
    let decisions = sim.decide_all(&snapshots).map_err(SimError::Snapshot)?;
    let mut results = Vec::with_capacity(file.tests.len());
    for ((t, s), d) in file.tests.iter().zip(&snapshots).zip(&decisions) {
        let e = &t.expect;
        let mut failures = Vec::new();
        let got = SimOutcome::of(d.as_ref());
        if let Some(want) = e.outcome
            && want != got
        {
            failures.push(format!(
                "outcome: expected {}, got {}",
                name(&want),
                name(&got)
            ));
        }
        if let Some(want) = e.would_have_been {
            let got = d.as_ref().map(SimOutcome::enforce_of);
            if got != Some(want) {
                failures.push(format!(
                    "would_have_been: expected {}, got {}",
                    name(&want),
                    got.as_ref().map_or_else(|| "none".to_owned(), name)
                ));
            }
        }
        if let Some(want) = &e.reason_code {
            let got = d
                .as_ref()
                .map_or_else(|| "none".to_owned(), |d| name(&d.reason_code()));
            if got != *want {
                failures.push(format!("reason_code: expected {want}, got {got}"));
            }
        }
        if let Some(want) = e.mode {
            let got = d
                .as_ref()
                .map_or(Mode::Disabled, crate::decision::Decision::mode);
            if got != want {
                failures.push(format!(
                    "mode: expected {}, got {}",
                    name(&want),
                    name(&got)
                ));
            }
        }
        let rule = d.as_ref().and_then(|d| d.matched_rule().copied());
        if let Some(want) = &e.rule {
            let hit = rule.is_some_and(|r| {
                r.rule_id.to_string() == *want
                    || r.display_id.is_some_and(|x| x.to_string() == *want)
            });
            if !hit {
                failures.push(format!("rule: expected {want}, got {}", rule_name(rule)));
            }
        }
        if e.no_rule && rule.is_some() {
            failures.push(format!("rule: expected none, got {}", rule_name(rule)));
        }
        let explanation = (!failures.is_empty())
            .then(|| sim.trace(s, &TraceOptions::at(TraceLevel::Full)).ok())
            .flatten()
            .map(|tr| render_text(&explain(&tr, Verbosity::Normal), &Catalog::english()));
        results.push(TestResult {
            name: t.name.clone(),
            passed: failures.is_empty(),
            failures,
            explanation,
        });
    }
    Ok(TestReport {
        suite: suite.to_owned(),
        results,
    })
}

fn rule_name(r: Option<crate::decision::RuleRef>) -> String {
    r.map_or_else(
        || "none".to_owned(),
        |r| {
            r.display_id
                .map_or_else(|| r.rule_id.to_string(), |d| format!("{d} ({})", r.rule_id))
        },
    )
}

fn name<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Escapes text for an XML attribute or element. Characters XML 1.0 does
/// not allow are replaced with U+FFFD.
fn xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}
