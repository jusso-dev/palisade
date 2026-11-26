//! The decision trace, explanations and policy simulation (#41).
//!
//! Every decision can be explained. This module has three parts:
//!
//! - **Trace** ([`Tracer`], [`Trace`]): a structured, bounded record of one
//!   evaluation. It lists the stages that ran, the rules that matched and
//!   the part each played, the rules that nearly matched and the criteria
//!   that failed them, the rules that would have matched but are disabled,
//!   the facts that were missing and what that did to the decision, the
//!   warnings, the effective mode with each step of its resolution, and the
//!   decision itself. Its JSON form is versioned
//!   ([`TRACE_SCHEMA_VERSION`]) and snapshot-tested.
//! - **Explain** ([`explain`]): turns a trace into paragraphs and a table
//!   for people, rendered as plain text, Markdown or one short sentence,
//!   with localisable message templates.
//! - **Simulate** ([`simulate`], [`readiness`], [`policy_test`],
//!   [`effective`]): runs a policy, or a proposed change to it, over
//!   recorded facts and reports what would change, how ready devices are
//!   for enforce mode, whether policy-as-code tests pass, and what a device
//!   enforces.
//!
//! # The trace is the evaluator's
//!
//! [`Tracer::trace`] calls [`Evaluator::evaluate_in`], and the trace
//! embeds that decision unchanged. The set of rules that matched is taken
//! from the evaluator too. The trace then explains each rule by evaluating
//! its criteria one by one, with the same compiled criteria and the same
//! three-valued logic, without stopping early. It never decides anything
//! itself. Tests check over random policies, facts and device states that
//! the trace and the evaluator agree.
//!
//! # Levels
//!
//! | Level | Contents |
//! |---|---|
//! | `minimal` | The decision, the deciding rule and the effective mode. Built from the decision alone, with no further evaluation. |
//! | `standard` | Adds the stages, every rule that matched, the deciding rule's criteria, disabled rules that would have matched, rules whose scope excluded the subject, unknown facts, warnings, mode resolution steps, provenance, and a draft rule that would allow a blocked object. |
//! | `full` | Adds near misses, with the failing criteria and the observed and expected values, and every fact the evaluation read. |
//!
//! [`LevelPolicy`] chooses the level the agent records: `minimal` for an
//! object that runs, `standard` for a block or a would-block, and `full`
//! with a per-device debug flag or during a time-boxed diagnostic session.
//! The simulator always records `full`.
//!
//! # Bounds
//!
//! A trace never grows with the size of the policy. Each list has a limit
//! ([`limits`]), and what was left out is counted in [`Trace::omitted`]
//! and in each entry's `*_omitted` field. Every value is cut to
//! [`privacy::MAX_VALUE_CHARS`] characters, and at most
//! [`privacy::MAX_VALUES`] values of one fact are written. The JSON of a
//! trace is at most [`limits::MAX_TRACE_BYTES`]; a test builds the largest
//! trace the limits allow and checks it.
//!
//! # Privacy
//!
//! Facts are written as [`Privacy`] allows, when the trace is built: see
//! [`privacy`]. The defaults write object facts and paths, withhold the
//! user, device and session, and redact nothing.

pub mod effective;
mod explain;
mod modes;
pub mod policy_test;
pub mod privacy;
pub mod readiness;
mod record;
pub mod simulate;

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::decision::{Decision, Outcome, RuleRef, TraceId};
use crate::evaluate::{BuildError, Evaluator, Subject};
use crate::mode::DeviceState;
use crate::model::{
    ActionKind, Field, Mode, ObjectType, Operator, Policy, PolicyId, PrecedenceModel, RuleId,
    UnknownAs,
};
use crate::ops::{Note, Tri};
use crate::validate::ValidatedPolicy;

pub use explain::{
    Catalog, ExplainDoc, Message, TableRow, Verbosity, explain, render_markdown, render_text,
    render_tray,
};
pub use modes::{ModeStep, ModeStepKind};
pub use privacy::{Observed, Privacy, Redactor};
pub use record::{RuleStage, TriState};

use privacy::clip;
use record::{RuleResult, TracedRule};

/// The version of the trace JSON. The major version changes when a field
/// is removed or changes meaning; the minor version when one is added.
pub const TRACE_SCHEMA_VERSION: &str = "1.0.0";

/// The limits that bound a trace.
pub mod limits {
    /// The most matched rules listed.
    pub const MAX_MATCHED: usize = 64;
    /// The most near misses listed (#41: "capped at 10").
    pub const MAX_NEAR_MISSES: usize = 10;
    /// The most failing criteria listed per near miss.
    pub const MAX_FAILING: usize = 8;
    /// The most disabled rules that would have matched, listed.
    pub const MAX_INACTIVE: usize = 16;
    /// The most scope rejections listed.
    pub const MAX_SCOPE_REJECTIONS: usize = 16;
    /// The most rules named by one unknown fact or one warning.
    pub const MAX_RULES_PER_ENTRY: usize = 10;
    /// The most entries of each list of the decision, in the trace's JSON.
    pub const MAX_DECISION_LIST: usize = 10;
    /// The most bytes of a trace's JSON (compact form), for the largest
    /// trace the other limits allow.
    pub const MAX_TRACE_BYTES: usize = 1024 * 1024;
}

use limits::{MAX_FAILING, MAX_INACTIVE, MAX_MATCHED, MAX_NEAR_MISSES, MAX_RULES_PER_ENTRY};

/// How much a trace records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceLevel {
    /// The decision, the deciding rule and the effective mode.
    Minimal,
    /// Adds what matched and why, unknown facts and warnings.
    Standard,
    /// Adds near misses and the facts used.
    Full,
}

/// The default length of a diagnostic session, in seconds (30 minutes).
pub const DIAGNOSTIC_SESSION_SECS: u64 = 30 * 60;

/// How an agent chooses the trace level of each decision (#41).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LevelPolicy {
    /// The device's debug flag: every decision is traced at `full`.
    pub debug_full: bool,
    /// The end of a diagnostic session, on the agent's monotonic clock in
    /// seconds. Until then, every decision is traced at `full`.
    pub diagnostic_until: Option<u64>,
}

impl LevelPolicy {
    /// A diagnostic session from `now_monotonic` for `secs` seconds
    /// ([`DIAGNOSTIC_SESSION_SECS`] by default).
    #[must_use]
    pub const fn with_diagnostic_session(mut self, now_monotonic: u64, secs: u64) -> Self {
        self.diagnostic_until = Some(now_monotonic.saturating_add(secs));
        self
    }

    /// The level for a decision made at `now_monotonic`: `full` with the
    /// debug flag or in a diagnostic session; otherwise `standard` for a
    /// block or a would-block, and `minimal` for anything else. A device
    /// that is disabled has no decision and gets `minimal`.
    #[must_use]
    pub fn level_for(&self, decision: Option<&Decision>, now_monotonic: u64) -> TraceLevel {
        if self.debug_full || self.diagnostic_until.is_some_and(|end| now_monotonic < end) {
            return TraceLevel::Full;
        }
        match decision {
            Some(d)
                if d.outcome() == Outcome::Blocked || d.would_have_been() == Outcome::Blocked =>
            {
                TraceLevel::Standard
            }
            _ => TraceLevel::Minimal,
        }
    }
}

/// What a trace is built with.
#[derive(Clone, Debug)]
pub struct TraceOptions {
    /// How much to record.
    pub level: TraceLevel,
    /// What may be said about the facts.
    pub privacy: Privacy,
    /// The decision-relevant hash of the policy bundle the decision was
    /// made under, if the caller has one (#43).
    pub bundle_hash: Option<String>,
}

impl TraceOptions {
    /// `level`, with the default privacy settings and no bundle hash.
    #[must_use]
    pub const fn at(level: TraceLevel) -> Self {
        Self {
            level,
            privacy: Privacy::DEFAULT,
            bundle_hash: None,
        }
    }
}

/// A check the agent relaxed when it verified a signature (#50, #256),
/// because a certificate option of the policy allowed it. The trace warns
/// about every one, so an allow that rests on a relaxed signature is
/// visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub struct SignatureRelaxation {
    /// The index of the signature in [`ObjectFacts::signers`](crate::facts::ObjectFacts::signers).
    pub signature: usize,
    /// The relaxation used.
    pub flag: RelaxationFlag,
    /// The failure it suppressed.
    pub suppressed: palisade_core::VerificationError,
}

/// A certificate option that relaxes one signature check (#256).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaxationFlag {
    /// An expired certificate was accepted.
    IgnoreExpiry,
    /// A certificate whose revocation could not be checked was accepted.
    IgnoreRevocationUnknown,
    /// A certificate with the wrong key usage was accepted.
    IgnoreInvalidUsage,
    /// A complete chain to an untrusted root was accepted.
    AllowUntrustedRoot,
}

/// What the agent knows about the object besides its facts, for the trace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectExtras {
    /// The signature checks that were relaxed.
    pub signature_relaxations: Vec<SignatureRelaxation>,
}

/// A source of monotonic nanoseconds, for stage timing. Evaluation reads no
/// clock; a caller that wants timing passes one to [`Tracer::trace_timed`].
pub trait NanoClock {
    /// The current reading, in nanoseconds since an arbitrary origin.
    fn now_ns(&self) -> u64;
}

/// One evaluation, explained. Build one with [`Tracer::trace`].
///
/// Every field is always present, in declaration order: lists are empty
/// and absent values `null` when the level does not record them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Trace {
    /// [`TRACE_SCHEMA_VERSION`].
    pub trace_schema_version: &'static str,
    /// The trace ID, the same as the decision's.
    pub trace_id: TraceId,
    /// The level recorded.
    pub level: TraceLevel,
    /// The policy.
    pub policy_id: PolicyId,
    /// The policy's revision.
    pub policy_revision: u64,
    /// The bundle hash, if the caller supplied one (#43).
    pub bundle_hash: Option<String>,
    /// The object's type.
    pub object_type: ObjectType,
    /// The effective mode of the decision: `disabled` when the device is
    /// disabled and nothing was decided.
    pub effective_mode: Mode,
    /// How the effective mode was resolved, step by step (#36). Standard
    /// and full.
    pub mode_resolution: Vec<ModeStep>,
    /// The policy's precedence model (#35).
    pub precedence_model: PrecedenceModel,
    /// The pipeline stages, in order. Standard and full.
    pub stages: Vec<StageTrace>,
    /// The deciding rule, or `null` for the implicit deny or a disabled
    /// device. Its criteria are listed at standard and full.
    pub decisive: Option<DecisiveRule>,
    /// Every rule that matched, by rule ID. Standard and full.
    pub matched: Vec<MatchedRule>,
    /// Rules whose identity anchor matched but another criterion did not,
    /// most nearly matching first. Full.
    pub near_misses: Vec<NearMiss>,
    /// Disabled rules that would have matched. Standard and full.
    pub inactive_matches: Vec<InactiveMatch>,
    /// Rules whose tree matched but whose scope excluded the subject.
    /// Standard and full: every enabled rule whose tree matched but whose
    /// scopes (#38) took it out, by rule ID. Such a rule behaves as
    /// absent, so it is in no other list.
    pub scope_rejections: Vec<ScopeRejection>,
    /// Facts the evaluation needed but did not have, and what that did to
    /// the decision. Standard and full.
    pub unknown_facts: Vec<UnknownFact>,
    /// Every fact the evaluated criteria read, by field. Full.
    pub facts_used: Vec<Observed>,
    /// Warnings, by code. Standard and full.
    pub warnings: Vec<Warning>,
    /// Where the deciding rule comes from, outermost first (#37). Standard
    /// and full.
    pub inheritance: Vec<InheritanceStep>,
    /// The smallest allow rule that would match a blocked object, as a
    /// draft for approvals and recommendations (#5, #11). Standard and
    /// full, for a block or a would-block only. The trace never creates a
    /// rule.
    pub allow_suggestion: Option<RuleDraft>,
    /// What the limits left out.
    pub omitted: Omitted,
    /// The decision, exactly as the evaluator made it, or `null` for a
    /// disabled device. Its JSON is the decision's stable form (#34), in
    /// the same field order, with
    /// `overridden`, `annotations` and `directives.trust_sources` cut to
    /// [`limits::MAX_DECISION_LIST`] entries and the number left out added
    /// as `overridden_omitted`, `annotations_omitted` and
    /// `trust_sources_omitted`, so a decision over many rules cannot make
    /// the trace unbounded. The Rust value is never cut.
    #[serde(serialize_with = "bounded_decision")]
    pub decision: Option<Decision>,
}

/// What the limits left out of a trace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Omitted {
    /// Matched rules past [`limits::MAX_MATCHED`].
    pub matched: u32,
    /// Near misses past [`limits::MAX_NEAR_MISSES`].
    pub near_misses: u32,
    /// Inactive matches past [`limits::MAX_INACTIVE`].
    pub inactive_matches: u32,
    /// Scope rejections past [`limits::MAX_INACTIVE`].
    pub scope_rejections: u32,
}

/// A pipeline stage (#35).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageName {
    /// 1: mandatory denies.
    MandatoryDeny,
    /// 2: exclusions.
    Exclusion,
    /// 3: override sessions, which lower the mode of stages 4 and 6.
    SessionOverride,
    /// 4: the precedence model.
    Policy,
    /// 5: post-allow attribute rules (#33; not yet present).
    Attribute,
    /// 6: the implicit deny.
    Unknown,
}

/// What a stage did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageOutcome {
    /// It decided.
    Decided,
    /// It ran and passed to the next stage.
    Passed,
    /// It did not run.
    Skipped,
}

/// One stage of one evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StageTrace {
    /// The stage.
    pub name: StageName,
    /// What it did.
    pub outcome: StageOutcome,
    /// How many matching rules took part in it.
    pub candidates: u32,
    /// The time the trace's recording pass spent evaluating the stage's
    /// rules, if a clock was given ([`Tracer::trace_timed`]). The recording
    /// pass evaluates every criterion without stopping early, so this is an
    /// upper bound on the evaluator's own time. `null` without a clock.
    pub duration_ns: Option<u64>,
}

/// The deciding rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DecisiveRule {
    /// The rule.
    pub rule: RuleRef,
    /// Its name.
    pub name: String,
    /// The stage it decided in.
    pub stage: RuleStage,
    /// Its action.
    pub action: ActionKind,
    /// Its specificity tier, 1 (hash) to 7 (#35).
    pub specificity_tier: u8,
    /// Its criteria and their results. Standard and full.
    pub criteria: Vec<CriterionTrace>,
}

/// The part a matching rule played.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchRole {
    /// It decided.
    Decided,
    /// It lost to the deciding rule, or was set aside by a mode (#35, #36).
    Overridden,
    /// An `audit` rule: an annotation.
    Annotation,
    /// A `trust_source` rule whose grant the object carries.
    Granted,
}

/// A rule that matched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MatchedRule {
    /// The rule.
    pub rule: RuleRef,
    /// Its name.
    pub name: String,
    /// Its stage.
    pub stage: RuleStage,
    /// Its action.
    pub action: ActionKind,
    /// Its specificity tier, 1 to 7.
    pub specificity_tier: u8,
    /// In tier 6, the depth of its directory.
    pub specificity_depth: u16,
    /// Its `order`, if any.
    pub order: Option<u32>,
    /// Its `priority`, if any.
    pub priority: Option<i32>,
    /// The part it played.
    pub role: MatchRole,
    /// It applied because its tree was unknown and it is a deny with
    /// `unknown_as: match`.
    pub via_unknown: bool,
}

/// One criterion of a rule, and its result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CriterionTrace {
    /// Where it is, as a JSON Pointer relative to the rule.
    pub pointer: String,
    /// The field.
    pub field: Field,
    /// The operator.
    pub operator: Operator,
    /// It is under an odd number of `not` nodes.
    pub under_not: bool,
    /// The result the tree used.
    pub result: TriState,
    /// The result the rule needed from it: `match`, or `no_match` under
    /// `not`.
    pub needed: TriState,
    /// The criterion's own result, which differs from `result` only when
    /// a deny reads an unparseable version as matching, or an unknown
    /// `safety_critical` criterion of a mandatory deny fails closed.
    pub raw_result: TriState,
    /// What the evaluation noticed (`fact_missing`, `path_acl_unsafe` and
    /// so on).
    pub notes: Vec<&'static str>,
    /// The rule's values, redacted and cut like observed values.
    pub expected: Vec<String>,
    /// Some expected values were cut or left out.
    pub expected_truncated: bool,
    /// Whether its result is part of why the tree has its result. A
    /// criterion in a branch that the tree's logic absorbed (an `all` that
    /// another child already failed, an `any` that another child already
    /// matched) does not count.
    pub contributing: bool,
    /// The object's fact, as privacy allows. Full only.
    pub observed: Option<Observed>,
}

/// A rule whose identity anchor matched, but which did not apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NearMiss {
    /// The rule.
    pub rule: RuleRef,
    /// Its name.
    pub name: String,
    /// Its stage.
    pub stage: RuleStage,
    /// Its action.
    pub action: ActionKind,
    /// Its tree's result.
    pub tree: TriState,
    /// How many of its criteria pulled it towards matching.
    pub matched_criteria: u32,
    /// How many criteria it has.
    pub total_criteria: u32,
    /// The criteria that kept it from matching, in document order.
    pub failing: Vec<CriterionTrace>,
    /// Failing criteria past [`limits::MAX_FAILING`].
    pub failing_omitted: u32,
}

/// Why a rule that would have matched did not take part.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InactiveReason {
    /// The rule is disabled. Expiry and schedules arrive with #40.
    Disabled,
}

/// A rule that would have matched but is inactive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InactiveMatch {
    /// The rule.
    pub rule: RuleRef,
    /// Its name.
    pub name: String,
    /// Its action.
    pub action: ActionKind,
    /// Why it is inactive.
    pub reason: InactiveReason,
}

/// A rule whose tree matched but whose scope excluded the subject (#38).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScopeRejection {
    /// The rule.
    pub rule: RuleRef,
    /// Its name.
    pub name: String,
    /// Where the scope that excluded it is: `policy`, `rule_set` or `rule`.
    pub level: &'static str,
    /// The dimension that excluded it, if one did alone.
    pub dimension: Option<&'static str>,
}

/// What an unknown fact did to one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownEffect {
    /// A rule that would let the object run, trust it or exclude it did not
    /// apply (it fails closed).
    AllowNotApplied,
    /// A deny did not apply (`unknown_as: no_match`, the default).
    DenyNotApplied,
    /// A deny applied (`unknown_as: match`: it fails closed).
    DenyAppliedFailClosed,
    /// An `audit` rule did not annotate.
    AnnotationNotApplied,
}

/// A fact some rule needed, and did not have or could not trust.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnknownFact {
    /// The field.
    pub field: Field,
    /// Why it was unknown.
    pub notes: Vec<&'static str>,
    /// What it did, over every rule whose result it left unknown.
    pub effects: Vec<UnknownEffect>,
    /// Those rules, by rule ID.
    pub rules: Vec<RuleRef>,
    /// Rules past [`limits::MAX_RULES_PER_ENTRY`].
    pub rules_omitted: u32,
}

/// A warning code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    /// A path test in a rule that lets an object run matched a path users
    /// may be able to write, so it did not count.
    PathAclUnsafe,
    /// The path has a short (8.3) name the agent could not expand.
    ShortNameUnresolved,
    /// Group membership used by a scope is stale (#38).
    ScopeStale,
    /// A condition ran out of time (#33).
    ConditionTimeout,
    /// A criterion read context the user controls (#33).
    UserControlledContext,
    /// The clock is not trusted (ADR 0012, #38).
    ClockUntrusted,
    /// A signature was accepted only because a certificate option relaxed
    /// a check (#256).
    SignatureRelaxed,
}

/// A warning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Warning {
    /// The code.
    pub code: WarningCode,
    /// The rules it concerns, by rule ID.
    pub rules: Vec<RuleRef>,
    /// Rules past [`limits::MAX_RULES_PER_ENTRY`].
    pub rules_omitted: u32,
    /// Details, such as the relaxed checks.
    pub details: Vec<String>,
}

/// One level of where a rule comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InheritanceStep {
    /// `policy`, `rule_set` or `rule`.
    pub node: &'static str,
    /// Its ID.
    pub id: String,
    /// Its name.
    pub name: String,
}

/// How firmly a [`RuleDraft`] identifies the object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftIdentity {
    /// A file hash.
    Hash,
    /// A publisher with a product name and a file version.
    PublisherProductVersion,
    /// A publisher with a product name.
    PublisherProduct,
    /// A publisher alone.
    Publisher,
    /// A full path users cannot write.
    Path,
}

/// A draft allow rule. Never applied by the engine: the approval and
/// recommendation flows (#5, #11) decide what to do with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleDraft {
    /// `allow`.
    pub action: ActionKind,
    /// The object's type.
    pub object_types: Vec<ObjectType>,
    /// The identity used.
    pub identity: DraftIdentity,
    /// The match tree, as a policy document writes it.
    pub r#match: crate::model::Match,
    /// Why the draft may not be enough: `mandatory_deny_matched` (nothing
    /// overrides it) and `deny_rule_matched` (under `deny_wins` the deny
    /// always wins; under the other models it may).
    pub caveats: Vec<&'static str>,
}

/// Builds traces for one policy. It holds an [`Evaluator`], which makes
/// every decision, and its own view of every rule for the explanations.
#[derive(Debug)]
pub struct Tracer<'p> {
    evaluator: Evaluator<'p>,
    policy: &'p Policy,
    rules: Vec<TracedRule<'p>>,
    by_id: BTreeMap<RuleId, usize>,
}

impl<'p> Tracer<'p> {
    /// Compiles the policy for evaluation and tracing.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if a tree does not compile, which validation
    /// rules out.
    pub fn new(validated: &'p ValidatedPolicy) -> Result<Self, BuildError> {
        Self::with_library(validated, &crate::scope::NoLibrary)
    }

    /// Compiles the policy for evaluation and tracing, resolving the
    /// library sets scopes reference through `library` (#37, #38), as
    /// [`Evaluator::with_library`] does.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if a tree does not compile, which validation
    /// rules out.
    pub fn with_library(
        validated: &'p ValidatedPolicy,
        library: &dyn crate::scope::ScopeLibrary,
    ) -> Result<Self, BuildError> {
        let evaluator = Evaluator::with_library(validated, library)?;
        let doc = validated.document();
        let policy = &doc.policy;
        let sets: BTreeMap<_, _> = doc.rule_sets.iter().map(|s| (s.id, s)).collect();
        let mut rules = Vec::new();
        for id in &policy.rule_sets {
            let Some(set) = sets.get(id).copied() else {
                continue;
            };
            for rule in &set.rules {
                if let Some(traced) = TracedRule::build(policy, set, rule)? {
                    rules.push(traced);
                }
            }
        }
        let by_id = rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.rule.id, i))
            .collect();
        Ok(Self {
            evaluator,
            policy,
            rules,
            by_id,
        })
    }

    /// The evaluator every decision comes from.
    #[must_use]
    pub const fn evaluator(&self) -> &Evaluator<'p> {
        &self.evaluator
    }

    /// Decides one object on a device in `state`, and traces the decision.
    #[must_use]
    pub fn trace(
        &self,
        subject: &Subject<'_>,
        extras: &ObjectExtras,
        state: &DeviceState,
        trace_id: TraceId,
        options: &TraceOptions,
    ) -> Trace {
        self.trace_inner(subject, extras, state, trace_id, options, None)
    }

    /// The same as [`trace`](Self::trace), timing each stage of the
    /// recording pass with `clock`.
    #[must_use]
    pub fn trace_timed(
        &self,
        subject: &Subject<'_>,
        extras: &ObjectExtras,
        state: &DeviceState,
        trace_id: TraceId,
        options: &TraceOptions,
        clock: &dyn NanoClock,
    ) -> Trace {
        self.trace_inner(subject, extras, state, trace_id, options, Some(clock))
    }

    fn traced(&self, id: RuleId) -> Option<&TracedRule<'p>> {
        self.by_id.get(&id).map(|&i| &self.rules[i])
    }

    fn trace_inner(
        &self,
        subject: &Subject<'_>,
        extras: &ObjectExtras,
        state: &DeviceState,
        trace_id: TraceId,
        options: &TraceOptions,
        clock: Option<&dyn NanoClock>,
    ) -> Trace {
        let decision = self.evaluator.evaluate_in(subject, state, trace_id);
        let decider = decision
            .as_ref()
            .and_then(|d| d.matched_rule())
            .and_then(|r| self.traced(r.rule_id));
        let mut trace = Trace {
            trace_schema_version: TRACE_SCHEMA_VERSION,
            trace_id,
            level: options.level,
            policy_id: self.policy.id,
            policy_revision: self.policy.revision,
            bundle_hash: options.bundle_hash.as_deref().map(|h| clip(h).0),
            object_type: subject.object_type,
            effective_mode: decision.as_ref().map_or(Mode::Disabled, Decision::mode),
            mode_resolution: Vec::new(),
            precedence_model: self.policy.precedence_model,
            stages: Vec::new(),
            decisive: decider.map(|r| DecisiveRule {
                rule: r.reference,
                name: clip(&r.rule.name).0,
                stage: r.stage,
                action: r.action(),
                specificity_tier: r.spec.tier.number(),
                criteria: Vec::new(),
            }),
            matched: Vec::new(),
            near_misses: Vec::new(),
            inactive_matches: Vec::new(),
            scope_rejections: Vec::new(),
            unknown_facts: Vec::new(),
            facts_used: Vec::new(),
            warnings: Vec::new(),
            inheritance: Vec::new(),
            allow_suggestion: None,
            omitted: Omitted::default(),
            decision: None,
        };
        if options.level == TraceLevel::Minimal {
            trace.decision = decision;
            return trace;
        }
        // A disabled device consults no rule (#36): there is nothing to
        // explain but the mode.
        if decision.is_none() {
            trace.mode_resolution = modes::disabled_steps(state);
            trace.stages = stages(None, None, &[], state, &BTreeMap::new());
            return trace;
        }
        let full = options.level == TraceLevel::Full;
        let privacy = &options.privacy;

        // The recording pass: every rule, enabled or not, in stage order so
        // that each stage can be timed.
        let mut results: Vec<Option<RuleResult>> = vec![None; self.rules.len()];
        let mut durations: BTreeMap<RuleStage, u64> = BTreeMap::new();
        for stage in [
            RuleStage::MandatoryDeny,
            RuleStage::Exclusion,
            RuleStage::Policy,
            RuleStage::Annotation,
            RuleStage::TrustSource,
        ] {
            let start = clock.map(NanoClock::now_ns);
            for (i, r) in self.rules.iter().enumerate() {
                if r.stage == stage {
                    results[i] = Some(r.evaluate(subject));
                }
            }
            if let (Some(c), Some(s)) = (clock, start) {
                durations.insert(stage, c.now_ns().saturating_sub(s));
            }
        }
        let result = |i: usize| results[i].as_ref();
        // The scopes of every enabled rule whose type applies (#38), as
        // the evaluator read them. A rule they take out is absent.
        let scopes: Vec<Option<crate::scope::ScopeEvaluation>> = self
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let applies = r.rule.enabled && result(i).is_some_and(|x| x.type_applies);
                if applies {
                    self.evaluator.scope_of(r.rule.id, subject)
                } else {
                    None
                }
            })
            .collect();
        let out_of_scope = |i: usize| scopes[i].as_ref().is_some_and(|s| s.result == Tri::NoMatch);
        // A rule whose scopes are not `Match` cannot be a near miss: its
        // criteria are not what kept it from applying.
        let scope_open = |i: usize| scopes[i].as_ref().is_none_or(|s| s.result == Tri::Match);
        let scope_unknown = |i: usize| scopes[i].as_ref().is_some_and(|s| s.result == Tri::Unknown);

        let matched_ids: BTreeSet<RuleId> =
            self.evaluator.matching_ids(subject).into_iter().collect();
        let decision_ref = decision.as_ref();

        // The deciding rule's criteria.
        if let (Some(d), Some(r)) = (trace.decisive.as_mut(), decider) {
            if let Some(res) = self.by_id.get(&r.rule.id).and_then(|&i| result(i)) {
                d.criteria = criteria(r, res, subject, privacy, full, None);
            }
        }

        // Matched rules, by rule ID.
        let mut matched: Vec<&TracedRule<'p>> = matched_ids
            .iter()
            .filter_map(|id| self.traced(*id))
            .collect();
        matched.sort_by_key(|r| r.rule.id);
        trace.omitted.matched = count(matched.len().saturating_sub(MAX_MATCHED));
        trace.matched = matched
            .iter()
            .take(MAX_MATCHED)
            .map(|r| {
                let i = self.by_id.get(&r.rule.id).copied();
                let res = i.and_then(result);
                // It applied only through an unknown: its tree's, or its
                // scopes' (a deny with `unknown_as: match`).
                let via_unknown = res.is_some_and(|x| x.applies && x.tree == Tri::Unknown)
                    || i.is_some_and(scope_unknown);
                MatchedRule {
                    rule: r.reference,
                    name: clip(&r.rule.name).0,
                    stage: r.stage,
                    action: r.action(),
                    specificity_tier: r.spec.tier.number(),
                    specificity_depth: r.spec.depth,
                    order: r.rule.order,
                    priority: r.rule.priority,
                    role: role_of(r.reference, decision_ref),
                    via_unknown,
                }
            })
            .collect();

        // Stages.
        trace.stages = stages(decision_ref, decider, &matched, state, &durations);

        // Inactive matches: disabled rules whose tree matches.
        let mut inactive: Vec<&TracedRule<'p>> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(i, r)| !r.rule.enabled && result(*i).is_some_and(|x| x.tree == Tri::Match))
            .map(|(_, r)| r)
            .collect();
        inactive.sort_by_key(|r| r.rule.id);
        trace.omitted.inactive_matches = count(inactive.len().saturating_sub(MAX_INACTIVE));
        trace.inactive_matches = inactive
            .iter()
            .take(MAX_INACTIVE)
            .map(|r| InactiveMatch {
                rule: r.reference,
                name: clip(&r.rule.name).0,
                action: r.action(),
                reason: InactiveReason::Disabled,
            })
            .collect();

        // Scope rejections: the tree matched, the scopes did not.
        let mut rejected: Vec<(&TracedRule<'p>, crate::scope::ScopeFailure)> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(i, _)| result(*i).is_some_and(|x| x.tree == Tri::Match))
            .filter_map(|(i, r)| Some((r, scopes[i].as_ref()?.failure?)))
            .collect();
        rejected.sort_by_key(|(r, _)| r.rule.id);
        trace.omitted.scope_rejections = count(rejected.len().saturating_sub(MAX_INACTIVE));
        trace.scope_rejections = rejected
            .iter()
            .take(MAX_INACTIVE)
            .map(|(r, f)| ScopeRejection {
                rule: r.reference,
                name: clip(&r.rule.name).0,
                level: scope_level_name(f.level),
                dimension: f.dimension.map(dimension_name),
            })
            .collect();

        // Unknown facts and warnings, over the enabled rules in scope.
        let mut unknown: BTreeMap<Field, UnknownTally> = BTreeMap::new();
        let mut warn: BTreeMap<WarningCode, BTreeMap<RuleId, RuleRef>> = BTreeMap::new();
        let mut used: BTreeSet<Field> = BTreeSet::new();
        for (i, r) in self.rules.iter().enumerate() {
            let Some(res) = result(i) else { continue };
            if !r.rule.enabled || !res.type_applies {
                continue;
            }
            // A scope note is worth a warning on a rule whose tree did not
            // rule it out: the note is why it applied or not.
            if let Some(s) = scopes[i].as_ref().filter(|_| res.tree != Tri::NoMatch) {
                for (note, code) in [
                    (crate::scope::ScopeNote::ScopeStale, WarningCode::ScopeStale),
                    (
                        crate::scope::ScopeNote::ClockUntrusted,
                        WarningCode::ClockUntrusted,
                    ),
                ] {
                    if s.notes.contains(note) {
                        warn.entry(code)
                            .or_default()
                            .insert(r.reference.rule_id, r.reference);
                    }
                }
            }
            if out_of_scope(i) {
                continue;
            }
            let contributing = r.contributing(res);
            for ((leaf, lr), counts) in r.leaves.iter().zip(&res.leaves).zip(contributing) {
                used.insert(leaf.criterion.field);
                if lr.notes.contains(Note::PathAclUnsafe) {
                    warn.entry(WarningCode::PathAclUnsafe)
                        .or_default()
                        .insert(r.reference.rule_id, r.reference);
                }
                if lr.notes.contains(Note::ShortNameUnresolved) {
                    warn.entry(WarningCode::ShortNameUnresolved)
                        .or_default()
                        .insert(r.reference.rule_id, r.reference);
                }
                // Only an unknown that left the rule's result unknown had an
                // effect on it: one Kleene logic did not absorb.
                if counts && lr.effective == Tri::Unknown && res.tree == Tri::Unknown {
                    let e = unknown.entry(leaf.criterion.field).or_default();
                    e.0.extend(lr.notes.iter().map(Note::as_str));
                    e.1.insert(unknown_effect(r));
                    e.2.insert(r.reference.rule_id, r.reference);
                }
            }
        }
        trace.unknown_facts = unknown
            .into_iter()
            .map(|(field, (notes, effects, rules))| {
                let (rules, rules_omitted) = capped_rules(rules);
                UnknownFact {
                    field,
                    notes: notes.into_iter().collect(),
                    effects: effects.into_iter().collect(),
                    rules,
                    rules_omitted,
                }
            })
            .collect();
        let mut warnings: Vec<Warning> = warn
            .into_iter()
            .map(|(code, rules)| {
                let (rules, rules_omitted) = capped_rules(rules);
                Warning {
                    code,
                    rules,
                    rules_omitted,
                    details: Vec::new(),
                }
            })
            .collect();
        if !extras.signature_relaxations.is_empty() {
            let mut details: Vec<String> = extras
                .signature_relaxations
                .iter()
                .take(MAX_RULES_PER_ENTRY)
                .map(|x| {
                    format!(
                        "signature {}: {} suppressed {} ({})",
                        x.signature,
                        relaxation_name(x.flag),
                        x.suppressed.as_str(),
                        x.suppressed.code()
                    )
                })
                .collect();
            details.sort();
            details.dedup();
            // The rules that rest on a signer: every matched rule that has a
            // signer criterion that matched.
            let signer_rules: BTreeMap<RuleId, RuleRef> = matched
                .iter()
                .filter(|r| {
                    self.by_id
                        .get(&r.rule.id)
                        .and_then(|&i| result(i))
                        .is_some_and(|res| {
                            r.leaves.iter().zip(&res.leaves).any(|(l, lr)| {
                                matches!(
                                    l.criterion.field,
                                    Field::SignerPublisher
                                        | Field::SignerIssuer
                                        | Field::SignerLeafThumbprint
                                ) && lr.effective == Tri::Match
                            })
                        })
                })
                .map(|r| (r.rule.id, r.reference))
                .collect();
            let (rules, rules_omitted) = capped_rules(signer_rules);
            warnings.push(Warning {
                code: WarningCode::SignatureRelaxed,
                rules,
                rules_omitted,
                details,
            });
            warnings.sort_by_key(|w| w.code);
        }
        trace.warnings = warnings;

        // Mode resolution.
        if let Some(d) = decision_ref {
            trace.mode_resolution = modes::steps(
                self.policy,
                subject.object_type,
                decider.map(|r| (r.set, r.rule)),
                state,
                d,
            );
        } else {
            trace.mode_resolution = modes::disabled_steps(state);
        }

        // Provenance of the deciding rule within the policy document. The
        // group steps of #37's effective policy are a follow-up under #41.
        if let Some(r) = decider {
            trace.inheritance = vec![
                InheritanceStep {
                    node: "policy",
                    id: self.policy.id.to_string(),
                    name: clip(&self.policy.name).0,
                },
                InheritanceStep {
                    node: "rule_set",
                    id: r.set.id.to_string(),
                    name: clip(&r.set.name).0,
                },
                InheritanceStep {
                    node: "rule",
                    id: r.rule.id.to_string(),
                    name: clip(&r.rule.name).0,
                },
            ];
        }

        // A draft allow for a block or a would-block. Not for an instance
        // limit (#38): an allow already decided, and another allow would
        // not change what limits it.
        if decision_ref.is_some_and(|d| {
            d.would_have_been() == Outcome::Blocked
                && d.reason_code() != crate::decision::ReasonCode::InstanceLimit
        }) {
            trace.allow_suggestion = suggest(subject, privacy, &matched, extras);
        }

        if full {
            let in_scope: Vec<Option<RuleResult>> = results
                .iter()
                .enumerate()
                .map(|(i, r)| if scope_open(i) { r.clone() } else { None })
                .collect();
            trace.near_misses = self.near_misses(
                &in_scope,
                &matched_ids,
                subject,
                privacy,
                &mut trace.omitted,
            );
            trace.facts_used = used
                .into_iter()
                .map(|f| Observed::new(f, observe(f, subject), privacy))
                .collect();
        }
        trace.decision = decision;
        trace
    }

    fn near_misses(
        &self,
        results: &[Option<RuleResult>],
        matched: &BTreeSet<RuleId>,
        subject: &Subject<'_>,
        privacy: &Privacy,
        omitted: &mut Omitted,
    ) -> Vec<NearMiss> {
        let mut candidates: Vec<(usize, &TracedRule<'p>, &RuleResult)> = self
            .rules
            .iter()
            .zip(results)
            .filter_map(|(r, res)| Some((r, res.as_ref()?)))
            .filter(|(r, res)| {
                r.rule.enabled
                    && res.type_applies
                    && !matched.contains(&r.rule.id)
                    && r.anchor_matched(res)
            })
            .map(|(r, res)| (r.satisfied_count(res), r, res))
            .collect();
        // Most matched criteria first, then the lowest rule ID.
        candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.rule.id.cmp(&b.1.rule.id)));
        omitted.near_misses = count(candidates.len().saturating_sub(MAX_NEAR_MISSES));
        candidates
            .into_iter()
            .take(MAX_NEAR_MISSES)
            .map(|(n, r, res)| {
                let failing = r.failing(res);
                let failing_omitted = count(failing.len().saturating_sub(MAX_FAILING));
                let keep: BTreeSet<usize> =
                    failing.iter().take(MAX_FAILING).map(|(i, _)| *i).collect();
                NearMiss {
                    rule: r.reference,
                    name: clip(&r.rule.name).0,
                    stage: r.stage,
                    action: r.action(),
                    tree: res.tree.into(),
                    matched_criteria: count(n),
                    total_criteria: count(r.leaves.len()),
                    failing: criteria(r, res, subject, privacy, true, Some(&keep)),
                    failing_omitted,
                }
            })
            .collect()
    }
}

/// The name of a scope level in a trace.
const fn scope_level_name(l: crate::scope::ScopeLevel) -> &'static str {
    match l {
        crate::scope::ScopeLevel::Policy => "policy",
        crate::scope::ScopeLevel::RuleSet => "rule_set",
        crate::scope::ScopeLevel::Rule => "rule",
    }
}

/// The name of a scope dimension in a trace.
const fn dimension_name(d: crate::scope::Dimension) -> &'static str {
    match d {
        crate::scope::Dimension::Principals => "principals",
        crate::scope::Dimension::Devices => "devices",
        crate::scope::Dimension::Network => "network",
        crate::scope::Dimension::Sessions => "sessions",
        crate::scope::Dimension::Schedule => "schedule",
    }
}

/// Per unknown field: its notes, its effects and the rules it affected.
type UnknownTally = (
    BTreeSet<&'static str>,
    BTreeSet<UnknownEffect>,
    BTreeMap<RuleId, RuleRef>,
);

/// The traced criteria of `rule`: all of them, or those in `only`.
fn criteria(
    rule: &TracedRule<'_>,
    res: &RuleResult,
    subject: &Subject<'_>,
    privacy: &Privacy,
    with_observed: bool,
    only: Option<&BTreeSet<usize>>,
) -> Vec<CriterionTrace> {
    let contributing = rule.contributing(res);
    rule.leaves
        .iter()
        .zip(&res.leaves)
        .enumerate()
        .filter(|(i, _)| only.is_none_or(|o| o.contains(i)))
        .map(|(i, (leaf, lr))| {
            let c = leaf.criterion;
            let mut expected_truncated = c.values.len() > privacy::MAX_VALUES;
            let expected = c
                .values
                .iter()
                .take(privacy::MAX_VALUES)
                .map(|v| {
                    // The policy's values pass the same redactor as the
                    // facts: a path criterion can name a user as well.
                    let (t, cut) = privacy.text(v);
                    expected_truncated |= cut;
                    t
                })
                .collect();
            CriterionTrace {
                pointer: leaf.pointer.clone(),
                field: c.field,
                operator: c.operator,
                under_not: leaf.negated,
                result: lr.effective.into(),
                needed: if leaf.negated {
                    TriState::NoMatch
                } else {
                    TriState::Match
                },
                raw_result: lr.raw.into(),
                notes: lr.notes.iter().map(Note::as_str).collect(),
                expected,
                expected_truncated,
                contributing: contributing.get(i).copied().unwrap_or(false),
                observed: with_observed
                    .then(|| Observed::new(c.field, observe(c.field, subject), privacy)),
            }
        })
        .collect()
}

/// The raw values of a fact, or `None` if it is unknown.
fn observe(field: Field, subject: &Subject<'_>) -> Option<Vec<String>> {
    use crate::context::ContextFact;
    let facts = subject.facts;
    if field.is_context() {
        return Some(match subject.context.fact(field)? {
            ContextFact::Text(t) => vec![t.to_owned()],
            ContextFact::Names(a, u) => a.into_iter().chain(u).map(str::to_owned).collect(),
            ContextFact::Set(s) => s.to_vec(),
            ContextFact::Bool(b) => vec![b.to_string()],
            ContextFact::Session(s) => vec![s.as_str().to_owned()],
            ContextFact::Number(n) => vec![n.to_string()],
            ContextFact::Level(l) => vec![l.as_str().to_owned()],
            ContextFact::Ip(ip) => vec![ip.to_string()],
            ContextFact::Ips(ips) => ips.iter().map(ToString::to_string).collect(),
            ContextFact::Macs(macs) => macs
                .iter()
                .map(|m| {
                    m.iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":")
                })
                .collect(),
            ContextFact::Weekday(d) => vec![d.as_str().to_owned()],
            ContextFact::Minute(m) => vec![format!("{:02}:{:02}", m / 60, m % 60)],
            ContextFact::Date(d) => vec![d.to_string()],
        });
    }
    match field {
        Field::SignerPublisher | Field::SignerIssuer | Field::SignerLeafThumbprint => {
            let signers = facts.signers.as_ref()?;
            Some(
                signers
                    .iter()
                    .map(|s| {
                        let v = match field {
                            Field::SignerPublisher => s.publisher.as_deref(),
                            Field::SignerIssuer => s.issuer.as_deref(),
                            _ => s.leaf_thumbprint_sha256.as_deref(),
                        }
                        .unwrap_or("(none)");
                        if s.status.is_trusted() {
                            v.to_owned()
                        } else {
                            format!("{v} ({})", signer_status(s.status))
                        }
                    })
                    .collect(),
            )
        }
        Field::PathFull | Field::PathDirectory | Field::PathFileName | Field::PathExtension => {
            let p = facts.path.as_ref()?;
            let pick = |n: &palisade_core::path::NormalizedPath| -> String {
                match field {
                    Field::PathFull => n.as_str().to_owned(),
                    Field::PathDirectory => n.directory().unwrap_or("").to_owned(),
                    Field::PathFileName => n.file_name().unwrap_or("").to_owned(),
                    _ => n.extension().unwrap_or("").to_owned(),
                }
            };
            Some(std::iter::once(&p.path).chain(&p.alias).map(pick).collect())
        }
        _ => facts.get(field).map(|v| vec![v.to_owned()]),
    }
}

const fn signer_status(s: crate::facts::SignerStatus) -> &'static str {
    use crate::facts::SignerStatus as S;
    match s {
        S::Valid => "valid",
        S::ValidExpiredTimestamped => "valid_expired_timestamped",
        S::CatalogSigned => "catalog_signed",
        S::Expired => "expired",
        S::Revoked => "revoked",
        S::UntrustedRoot => "untrusted_root",
        S::DigestMismatch => "digest_mismatch",
    }
}

const fn relaxation_name(f: RelaxationFlag) -> &'static str {
    match f {
        RelaxationFlag::IgnoreExpiry => "ignore_expiry",
        RelaxationFlag::IgnoreRevocationUnknown => "ignore_revocation_unknown",
        RelaxationFlag::IgnoreInvalidUsage => "ignore_invalid_usage",
        RelaxationFlag::AllowUntrustedRoot => "allow_untrusted_root",
    }
}

fn unknown_effect(r: &TracedRule<'_>) -> UnknownEffect {
    match r.action() {
        ActionKind::Deny => {
            if matches!(&r.rule.action, crate::model::Action::Deny(o) if o.unknown_as == UnknownAs::Match)
            {
                UnknownEffect::DenyAppliedFailClosed
            } else {
                UnknownEffect::DenyNotApplied
            }
        }
        ActionKind::Audit => UnknownEffect::AnnotationNotApplied,
        _ => UnknownEffect::AllowNotApplied,
    }
}

fn role_of(r: RuleRef, decision: Option<&Decision>) -> MatchRole {
    let Some(d) = decision else {
        return MatchRole::Overridden;
    };
    if d.matched_rule() == Some(&r) {
        MatchRole::Decided
    } else if d.annotations().contains(&r) {
        MatchRole::Annotation
    } else if d.directives().trust_sources.iter().any(|g| g.rule == r) {
        MatchRole::Granted
    } else {
        MatchRole::Overridden
    }
}

fn stages(
    decision: Option<&Decision>,
    decider: Option<&TracedRule<'_>>,
    matched: &[&TracedRule<'_>],
    state: &DeviceState,
    durations: &BTreeMap<RuleStage, u64>,
) -> Vec<StageTrace> {
    let n = |s: RuleStage| count(matched.iter().filter(|r| r.stage == s).count());
    let decided = match (decision, decider) {
        (None, _) => None,
        (Some(_), Some(r)) => Some(match r.stage {
            RuleStage::MandatoryDeny => StageName::MandatoryDeny,
            RuleStage::Exclusion => StageName::Exclusion,
            _ => StageName::Policy,
        }),
        (Some(_), None) => Some(StageName::Unknown),
    };
    let order = [
        StageName::MandatoryDeny,
        StageName::Exclusion,
        StageName::SessionOverride,
        StageName::Policy,
        StageName::Attribute,
        StageName::Unknown,
    ];
    let position = decided.and_then(|d| order.iter().position(|s| *s == d));
    order
        .iter()
        .enumerate()
        .map(|(i, &name)| {
            let outcome = match position {
                None => StageOutcome::Skipped,
                Some(p) if i == p => StageOutcome::Decided,
                // Attribute rules do not exist yet (#33), and a session
                // stage only runs with a session.
                Some(p) if i < p => match name {
                    StageName::Attribute => StageOutcome::Skipped,
                    // Lockdown suspends every session (#36).
                    StageName::SessionOverride if state.session.is_none() || state.lockdown => {
                        StageOutcome::Skipped
                    }
                    _ => StageOutcome::Passed,
                },
                Some(_) => StageOutcome::Skipped,
            };
            let (candidates, duration_ns) = match name {
                StageName::MandatoryDeny => (
                    n(RuleStage::MandatoryDeny),
                    durations.get(&RuleStage::MandatoryDeny).copied(),
                ),
                StageName::Exclusion => (
                    n(RuleStage::Exclusion),
                    durations.get(&RuleStage::Exclusion).copied(),
                ),
                StageName::Policy => (
                    n(RuleStage::Policy),
                    durations.get(&RuleStage::Policy).copied(),
                ),
                _ => (0, None),
            };
            StageTrace {
                name,
                outcome,
                candidates,
                duration_ns,
            }
        })
        .collect()
}

/// The smallest allow rule that identifies the subject, from the strongest
/// identity the privacy settings let the trace reveal.
fn suggest(
    subject: &Subject<'_>,
    privacy: &Privacy,
    matched: &[&TracedRule<'_>],
    extras: &ObjectExtras,
) -> Option<RuleDraft> {
    use crate::model::{Criterion, Match};
    let facts = subject.facts;
    // A criterion is offered only if validation would accept it: the value
    // is revealed and unchanged by redaction, not empty, has no control
    // character, is within the size limit, and the criterion compiles. If
    // not, the next identity is tried.
    let clean = |field: Field, v: &str| {
        privacy.reveals(field)
            && privacy.redactor.redact(v) == v
            && !v.is_empty()
            && !v.chars().any(char::is_control)
            && v.len() <= crate::model::limits::MAX_VALUE_BYTES
    };
    let criterion = |field: Field, operator: Operator, v: &str| -> Option<Match> {
        let c = Criterion::new(field, operator, [v]);
        (clean(field, v) && crate::ops::CompiledCriterion::compile(&c).is_ok())
            .then_some(Match::Criterion(c))
    };
    let hash = [
        Field::HashSha256,
        Field::HashAuthenticodeSha256,
        Field::HashSha384,
        Field::HashSha512,
    ]
    .into_iter()
    .find_map(|f| {
        // The fact must be what the matcher accepts: bare hex digits of the
        // field's length (a `0x` prefix makes it malformed, so no criterion
        // could match it). The criterion is written in lowercase.
        let raw = facts.get(f)?;
        match f.class() {
            crate::model::FieldClass::Hash { hex_len }
                if raw.len() == hex_len && raw.bytes().all(|b| b.is_ascii_hexdigit()) => {}
            _ => return None,
        }
        if !clean(f, raw) {
            return None;
        }
        criterion(f, Operator::Equals, &raw.to_ascii_lowercase())
    });
    // A signer is only offered if no check of its signature was relaxed.
    let relaxed: BTreeSet<usize> = extras
        .signature_relaxations
        .iter()
        .map(|r| r.signature)
        .collect();
    let publisher = facts.signers.as_ref().and_then(|s| {
        s.iter()
            .enumerate()
            .filter(|(i, s)| s.status.is_trusted() && !relaxed.contains(i))
            .find_map(|(_, s)| {
                criterion(
                    Field::SignerPublisher,
                    Operator::Equals,
                    s.publisher.as_deref()?,
                )
            })
    });
    let product = facts
        .get(Field::MetaProductName)
        .and_then(|v| criterion(Field::MetaProductName, Operator::Equals, v));
    // The recorded version must itself be revealed and unredacted; the
    // draft uses its numeric part.
    let version = facts
        .get(Field::MetaFileVersion)
        .filter(|v| clean(Field::MetaFileVersion, v))
        .and_then(crate::ops::Version::parse_fact)
        .and_then(|(v, _)| criterion(Field::MetaFileVersion, Operator::VersionGe, &v.to_string()));
    let (identity, tree) = if let Some(h) = hash {
        (DraftIdentity::Hash, h)
    } else if let Some(p) = publisher {
        match (product, version) {
            (Some(pr), Some(v)) => (
                DraftIdentity::PublisherProductVersion,
                Match::All(vec![p, pr, v]),
            ),
            (Some(pr), None) => (DraftIdentity::PublisherProduct, Match::All(vec![p, pr])),
            _ => (DraftIdentity::Publisher, p),
        }
    } else {
        let p = facts.path.as_ref().filter(|p| {
            p.user_writable == Some(false) && !p.short_name_unresolved && p.path.is_resolved()
        })?;
        (
            DraftIdentity::Path,
            criterion(Field::PathFull, Operator::Equals, p.path.as_str())?,
        )
    };
    let mut caveats = Vec::new();
    if matched.iter().any(|r| r.stage == RuleStage::MandatoryDeny) {
        caveats.push("mandatory_deny_matched");
    }
    if matched
        .iter()
        .any(|r| r.stage == RuleStage::Policy && r.action() == ActionKind::Deny)
    {
        caveats.push("deny_rule_matched");
    }
    Some(RuleDraft {
        action: ActionKind::Allow,
        object_types: vec![subject.object_type],
        identity,
        r#match: tree,
        caveats,
    })
}

/// The decision's JSON with its lists cut ([`Trace::decision`]): the
/// decision's own fields in their stable order, then the counts.
fn bounded_decision<S: serde::Serializer>(d: &Option<Decision>, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Bounded {
        #[serde(flatten)]
        decision: Decision,
        overridden_omitted: usize,
        annotations_omitted: usize,
        trust_sources_omitted: usize,
    }
    match d {
        None => s.serialize_none(),
        Some(d) => {
            let (decision, [o, a, t]) = d.with_lists_cut(limits::MAX_DECISION_LIST);
            Bounded {
                decision,
                overridden_omitted: o,
                annotations_omitted: a,
                trust_sources_omitted: t,
            }
            .serialize(s)
        }
    }
}

fn capped_rules(rules: BTreeMap<RuleId, RuleRef>) -> (Vec<RuleRef>, u32) {
    let mut v: Vec<RuleRef> = rules.into_values().collect();
    let omitted = count(v.len().saturating_sub(MAX_RULES_PER_ENTRY));
    v.truncate(MAX_RULES_PER_ENTRY);
    (v, omitted)
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests;
