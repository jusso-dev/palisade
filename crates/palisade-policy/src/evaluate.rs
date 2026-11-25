//! The evaluation pipeline: from one object to one [`Decision`] (#35,
//! ADR 0004).
//!
//! An [`Evaluator`] is built once from a [`ValidatedPolicy`]. It compiles
//! the match tree of every enabled rule in the rule sets the policy
//! references. [`Evaluator::evaluate`] then evaluates every rule that
//! applies to the object's type and runs the stages below, in this fixed
//! order, whatever the precedence model. Each stage either decides or
//! passes to the next.
//!
//! 1. **Mandatory deny.** Rules in a `mandatory` blocklist. If one
//!    matches, the object is blocked (`mandatory_deny`). No allow, trust
//!    source, elevation or exclusion can change that, under any model.
//! 2. **Exclusion.** `ignore` rules. If one matches, the object is
//!    `ignored`.
//! 3. **Override session.** An active session (#9) lowers the effective
//!    mode of stages 4 and 6 ([`crate::mode`]). It never affects stage 1.
//! 4. **Policy.** The policy's precedence model ([`crate::precedence`])
//!    chooses among the matching `allow`, `allow_contained`,
//!    `allow_elevated` and `deny` rules.
//! 5. **Attribute.** Not yet: post-allow attribute rules are #33.
//! 6. **Unknown.** If nothing decided, the implicit deny
//!    (`implicit_deny_unknown`, #39).
//!
//! # Scopes
//!
//! A rule is a candidate only if it is in scope (#38, [`crate::scope`]):
//! its own `scope`, the scopes of its rule set's assignment and the
//! policy's `scope` are evaluated first, and a rule applies when the `AND`
//! of those scopes and its match tree is `Match` (or `Unknown`, for a deny
//! with `unknown_as: match`). A rule that is out of scope behaves as if it
//! were absent in every stage: it never decides and is not listed as
//! overridden. The scope notes of every rule whose tree was not `NoMatch`
//! (in scope or not) are in [`Decision::scope_notes`].
//!
//! Two scope settings act on the deciding rule:
//!
//! - **Instance limit.** If an allow that decides has a scope with
//!   `max_instances_per_session` and the session already runs that many
//!   instances (or the count is unknown), the object is blocked with
//!   `instance_limit`, naming the allow. A mode that relaxes the block
//!   runs the object with the allow's directives.
//! - **Window close.** If the object is allowed and a scope on the way to
//!   the deciding rule has a schedule with `on_window_close`, the decision
//!   carries a [`WindowClose`] directive with the instant the schedule
//!   closes.
//!
//! Two kinds of rule never decide:
//!
//! - `audit` rules that match are listed in [`Decision::annotations`],
//!   whichever stage decides.
//! - `trust_source` rules that match add their grant to
//!   [`Directives::trust_sources`](crate::decision::Directives::trust_sources),
//!   but only when the object is allowed. A trust source never lets an
//!   object run by itself (#114). When the object is blocked or ignored,
//!   they are listed as overridden instead.
//!
//! `defer` rules have no opinion. They are never evaluated, so a `defer`
//! that matches makes `first_match` continue with the next rule.
//!
//! When several mandatory denies match, or several exclusions, the one
//! with the most specific identity decides, then the one with the lowest
//! rule ID.
//!
//! # Overridden rules
//!
//! [`Decision::overridden`] lists every other rule that matched and would
//! have decided, or attached a grant, if the deciding rule had not: the
//! other candidates of the deciding stage (including those with the same
//! outcome), every candidate of the later stages, and every `trust_source`
//! rule when the object is not allowed.
//!
//! # Unknown facts
//!
//! A rule applies only when its match tree is `Match` ([`crate::condition`]),
//! so an unknown fact never allows, trusts or excludes. A `deny` rule
//! decides how it treats an unknown result with two options:
//!
//! - `unknown_as: match` makes it apply when its tree is `Unknown`, so it
//!   blocks unless the precedence model prefers an allow. The default,
//!   `no_match`, means an unknown fact does not block.
//! - `on_unparseable: match` makes each criterion whose version fact is not
//!   a version count towards the deny applying
//!   ([`Unparseable::FavourMatch`]). The default leaves it `Unknown`.
//!
//! A file the agent could not parse has no facts, so no rule can allow it,
//! and unless a deny fails closed it gets the implicit deny (ADR 0012).
//!
//! Mandatory denies follow the same options. They default to `no_match`
//! like any other deny; making the criteria of the shipped blocklists
//! `safety_critical`, which defaults them to `match`, is #32 and #87.
//!
//! # Modes
//!
//! [`Evaluator::evaluate`] computes the enforce-mode decision, before
//! anything relaxes it: its [`Decision::mode`] is always `enforce`.
//! [`Evaluator::evaluate_in`] applies the effective mode of the device
//! ([`crate::mode`]): the policy's `mode`, the modes per object type, each
//! rule set's `mode_override`, each rule's `enforcement_override`, the
//! per-class control levels, connectivity, override sessions and
//! emergency lockdown. It keeps the enforce-mode outcome in
//! [`Decision::would_have_been`].
//!
//! # Determinism
//!
//! Evaluation is a pure function of the policy and the object. Every
//! stage chooses by keys that end with the unique rule ID, and the lists in
//! a decision are sorted by rule ID, so the decision does not depend on
//! the order of rule sets in the policy or of rules in a rule set. Only
//! `first_match` and `priority` depend on rules' `order` and `priority`.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::condition::{CompiledMatch, TreeError, Unparseable};
use crate::context::EvaluationContext;
use crate::decision::{Decision, Directives, Outcome, RuleRef, TraceId, TrustGrant, WindowClose};
use crate::facts::{ObjectFacts, PathVariables};
use crate::mode::{self, DeviceState};
use crate::model::{Action, Mode, ObjectType, Policy, Rule, RuleId, RuleSet, RuleSetId, UnknownAs};
use crate::ops::{EvalContext, Tri};
use crate::precedence::{Candidate, MatchSet, Precedence, Resolver, Spec, Verdict, most_specific};
use crate::scope::compile::Env;
use crate::scope::{
    Bias, CompiledScope, NoLibrary, OnWindowClose, ScopeEvaluation, ScopeLevel, ScopeLibrary,
    ScopeNote, ScopeNotes, eval_chain,
};
use crate::validate::ValidatedPolicy;

/// The object being decided, and what is known about it.
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    /// The object's type. Only rules whose `object_types` are empty or
    /// include it apply.
    pub object_type: ObjectType,
    /// The facts about the object.
    pub facts: &'a ObjectFacts,
    /// The path variables, for the user the process runs as.
    pub variables: &'a PathVariables,
    /// The user, device and session.
    pub context: &'a EvaluationContext,
}

/// A rule's tree did not compile. Validation compiles every tree, so this
/// cannot happen for a validated policy; the error says which rule it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildError {
    /// The rule.
    pub rule_id: RuleId,
    /// What is wrong with its tree.
    pub errors: Vec<TreeError>,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "rule {}: the match tree does not compile", self.rule_id)
    }
}

impl std::error::Error for BuildError {}

/// What a rule does in the pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// A deny in a mandatory rule set: stage 1.
    Mandatory,
    /// An `ignore` rule: stage 2.
    Exclusion,
    /// An allow or a deny for the precedence model: stage 4.
    Policy(Verdict),
    /// An `audit` rule: an annotation.
    Annotation,
    /// A `trust_source` rule: a grant if the object is allowed.
    Trust,
}

/// One enabled rule, ready to evaluate.
#[derive(Debug)]
struct Compiled<'p> {
    set: &'p RuleSet,
    rule: &'p Rule,
    tree: CompiledMatch,
    role: Role,
    spec: Spec,
    unknown_as: UnknownAs,
    unparseable: Unparseable,
    reference: RuleRef,
    /// The scopes on the way to the rule: the policy's, the rule set
    /// assignment's, then its own.
    scopes: Vec<(ScopeLevel, Arc<CompiledScope>)>,
    bias: Bias,
}

impl Compiled<'_> {
    fn candidate(&self, verdict: Verdict) -> Candidate {
        Candidate {
            rule: self.reference,
            verdict,
            spec: self.spec,
            order: self.rule.order,
            priority: self.rule.priority,
            curated: self.set.read_only,
            band: self.set.band,
        }
    }

    /// The scopes on the way to the rule, evaluated for the subject.
    pub(crate) fn scope_eval(&self, subject: &Subject<'_>) -> ScopeEvaluation {
        if self.scopes.is_empty() {
            return ScopeEvaluation::MATCH;
        }
        eval_chain(&self.scopes, subject.context, self.bias)
    }

    /// Whether the rule applies to the subject. The scopes are evaluated
    /// before the tree; when they are `NoMatch` and noticed nothing, the
    /// tree is not evaluated. `notes` gathers the scope notes of a rule
    /// whose tree is not `NoMatch`, including one its scopes took out:
    /// a stale group or an untrusted clock is worth reporting exactly when
    /// it kept a matching rule from applying.
    fn applies(&self, subject: &Subject<'_>, notes: &mut ScopeNotes) -> bool {
        if !self.rule.object_types.is_empty()
            && !self.rule.object_types.contains(&subject.object_type)
        {
            return false;
        }
        let scope = self.scope_eval(subject);
        if scope.result == Tri::NoMatch && scope.notes.is_empty() {
            return false;
        }
        let ctx = EvalContext {
            action: self.rule.action.kind(),
            variables: subject.variables,
            context: subject.context,
        };
        let tree = self
            .tree
            .eval_with(subject.facts, &ctx, self.unparseable)
            .result;
        if tree == Tri::NoMatch {
            return false;
        }
        notes.extend(scope.notes);
        match scope.result.and(tree) {
            Tri::Match => true,
            Tri::Unknown => self.unknown_as == UnknownAs::Match,
            Tri::NoMatch => false,
        }
    }

    /// The per-session instance limit of the rule's scopes, the smallest
    /// that is set, or `None`.
    fn instance_limit(&self) -> Option<u32> {
        self.scopes
            .iter()
            .map(|(_, s)| s.max_instances_per_session())
            .filter(|n| *n > 0)
            .min()
    }

    /// What to do when a schedule on the way to the rule closes: the
    /// strictest action, the earliest close, and the shortest grace period
    /// of the schedules that terminate.
    ///
    /// Only a schedule whose closing ends the rule's match counts: one in
    /// a scope with `combine: all` and no `negate`. Validation rejects
    /// `on_window_close` anywhere else, so this only matters for library
    /// schedules.
    fn window_close(&self, subject: &Subject<'_>) -> Option<WindowClose> {
        let facts = &subject.context.scope;
        let mut out: Option<WindowClose> = None;
        for (_, scope) in &self.scopes {
            let Some(schedule) = scope.closing_schedule() else {
                continue;
            };
            if schedule.on_window_close() == OnWindowClose::None {
                continue;
            }
            let closes_at = facts.time.filter(|t| t.trusted).and_then(|t| {
                let (tz, _) = schedule.zone(facts).ok()?;
                schedule.closes_at(t.unix_secs, &tz)
            });
            let this = WindowClose {
                action: schedule.on_window_close(),
                grace_secs: schedule.grace_secs(),
                closes_at,
            };
            out = Some(match out {
                None => this,
                Some(o) => WindowClose {
                    action: o.action.max(this.action),
                    grace_secs: match (o.action, this.action) {
                        (OnWindowClose::WarnThenTerminate, OnWindowClose::WarnThenTerminate) => {
                            o.grace_secs.min(this.grace_secs)
                        }
                        (OnWindowClose::WarnThenTerminate, _) => o.grace_secs,
                        (_, OnWindowClose::WarnThenTerminate) => this.grace_secs,
                        _ => o.grace_secs.min(this.grace_secs),
                    },
                    closes_at: match (o.closes_at, this.closes_at) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    },
                },
            });
        }
        out
    }
}

/// The result of one relaxation layer of [`Evaluator::evaluate_in`].
struct Layer<'a, 'p> {
    /// The decision over the rules kept.
    decision: Decision,
    /// Its deciding rule, or `None` for the implicit deny.
    winner: Option<&'a Compiled<'p>>,
    /// The rules decided over.
    kept: Vec<&'a Compiled<'p>>,
    /// The denies set aside because they do not enforce.
    dropped: Vec<RuleRef>,
    /// Whether the decision blocks in an enforcing mode.
    blocks: bool,
}

impl Layer<'_, '_> {
    /// The directives an object that runs gets: an allow's, if one
    /// decided (also one its instance limit blocked), otherwise none.
    fn directives(&self) -> Directives {
        self.decision.runnable_directives()
    }
}

/// Evaluates objects against one validated policy.
#[derive(Debug)]
pub struct Evaluator<'p> {
    policy: &'p Policy,
    rules: Vec<Compiled<'p>>,
    resolver: Resolver,
}

impl<'p> Evaluator<'p> {
    /// Compiles every enabled rule of the rule sets the policy references,
    /// with no library: every library set a scope references is unknown.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if a tree does not compile, which validation
    /// rules out.
    pub fn new(validated: &'p ValidatedPolicy) -> Result<Self, BuildError> {
        Self::with_library(validated, &NoLibrary)
    }

    /// Compiles every enabled rule of the rule sets the policy references,
    /// resolving the library sets scopes reference through `library` (#37).
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if a tree does not compile, which validation
    /// rules out.
    pub fn with_library(
        validated: &'p ValidatedPolicy,
        library: &dyn ScopeLibrary,
    ) -> Result<Self, BuildError> {
        let doc = validated.document();
        let policy = &doc.policy;
        let sets: BTreeMap<RuleSetId, &RuleSet> = doc.rule_sets.iter().map(|s| (s.id, s)).collect();
        let env = Env {
            library,
            basis: policy.settings.time_zone_basis,
        };
        let max_age = policy.settings.group_cache_max_age_secs;
        let compile = |s| Arc::new(CompiledScope::compile(s, env, max_age));
        let policy_scope = policy.scope.as_ref().map(compile);
        let mut rules = Vec::new();
        for id in &policy.rule_sets {
            let Some(set) = sets.get(id).copied() else {
                continue;
            };
            let mut chain: Vec<(ScopeLevel, Arc<CompiledScope>)> = Vec::new();
            if let Some(s) = &policy_scope {
                chain.push((ScopeLevel::Policy, Arc::clone(s)));
            }
            for assignment in policy.rule_set_scopes.iter().filter(|a| a.rule_set == *id) {
                for s in &assignment.scopes {
                    chain.push((ScopeLevel::RuleSet, compile(s)));
                }
            }
            for rule in set.rules.iter().filter(|r| r.enabled) {
                let role = match &rule.action {
                    _ if set.mandatory => Role::Mandatory,
                    Action::Ignore {} => Role::Exclusion,
                    Action::Audit {} => Role::Annotation,
                    Action::TrustSource(_) => Role::Trust,
                    Action::Defer {} => continue,
                    action => match Verdict::of(action) {
                        Some(v) => Role::Policy(v),
                        None => continue,
                    },
                };
                let tree = CompiledMatch::compile(&rule.match_).map_err(|errors| BuildError {
                    rule_id: rule.id,
                    errors,
                })?;
                let (unknown_as, unparseable) = match &rule.action {
                    Action::Deny(o) => (
                        o.unknown_as,
                        match o.on_unparseable {
                            UnknownAs::Match => Unparseable::FavourMatch,
                            UnknownAs::NoMatch => Unparseable::Unknown,
                        },
                    ),
                    _ => (UnknownAs::NoMatch, Unparseable::Unknown),
                };
                let mut scopes = chain.clone();
                if let Some(s) = &rule.scope {
                    scopes.push((ScopeLevel::Rule, compile(s)));
                }
                rules.push(Compiled {
                    set,
                    rule,
                    tree,
                    role,
                    spec: Spec::of(&rule.match_),
                    unknown_as,
                    unparseable,
                    reference: RuleRef::new(policy, set, rule),
                    scopes,
                    bias: Bias::of(rule.action.kind()),
                });
            }
        }
        Ok(Self {
            policy,
            rules,
            resolver: Resolver::new(policy.precedence_model, &policy.precedence_options),
        })
    }

    /// The policy being evaluated.
    #[must_use]
    pub const fn policy(&self) -> &'p Policy {
        self.policy
    }

    /// Decides one object, as enforce mode sees it: [`Decision::mode`] is
    /// `enforce`, whatever the policy's modes. This is the simulated result
    /// that readiness reports use (#41); [`evaluate_in`](Self::evaluate_in)
    /// applies the modes.
    #[must_use]
    pub fn evaluate(&self, subject: &Subject<'_>, trace_id: TraceId) -> Decision {
        let (matched, notes) = self.matching_with_notes(subject);
        self.run(&matched, subject, trace_id)
            .0
            .with_scope_notes(notes)
    }

    /// Decides one object on a device in `state`, applying the effective
    /// mode ([`crate::mode`]). Returns `None` when the device is disabled:
    /// the engine is not consulted, and nothing is decided or reported.
    ///
    /// [`Decision::would_have_been`] is the enforce-mode outcome
    /// ([`evaluate`](Self::evaluate)). An object that enforce mode allows
    /// or ignores gets the same decision, in its effective mode. A block
    /// is relaxed in two layers, so that each relaxation is reported as
    /// what it is:
    ///
    /// 1. **Modes.** Using the modes without the override session, every
    ///    matching deny whose effective mode does not enforce is set
    ///    aside, and the remaining rules are decided again. If that still
    ///    blocks in an enforcing mode (an enforcing deny, a mandatory deny,
    ///    or an enforcing implicit deny), the object is blocked by it: a
    ///    blocklist in `audit` never lets through what another rule blocks.
    ///    Otherwise the object runs as `allowed_audit`, naming the rule
    ///    enforce mode decided by.
    /// 2. **Session.** If layer 1 blocks and an override session is active,
    ///    the same is done with the session's modes, starting from the
    ///    rules layer 1 kept. If that still blocks in an enforcing mode,
    ///    the object is blocked. Otherwise it runs as `allowed_override`,
    ///    naming the rule layer 1 blocked by: the one the session bypassed.
    ///
    /// Every deny set aside is listed as overridden. A relaxed decision
    /// keeps the named rule's effects except the notification, so the
    /// would-block event is still logged. Its directives are those of the
    /// last decision taken: if an allow decided it, the object runs with
    /// that allow's containment, elevation and trust-source grants (which
    /// are then no longer listed as overridden); otherwise it has none, so
    /// nothing is terminated or requested. In `learning`, an object that
    /// only the implicit deny would block is a learning candidate.
    ///
    /// Mandatory denies always enforce (ADR 0004, #125).
    #[must_use]
    pub fn evaluate_in(
        &self,
        subject: &Subject<'_>,
        state: &DeviceState,
        trace_id: TraceId,
    ) -> Option<Decision> {
        if mode::device_mode(self.policy, state) == Mode::Disabled {
            return None;
        }
        let (matched, notes) = self.matching_with_notes(subject);
        self.decide_in(subject, &matched, state, trace_id)
            .map(|d| d.with_scope_notes(notes))
    }

    /// [`evaluate_in`](Self::evaluate_in) over the rules that apply.
    fn decide_in(
        &self,
        subject: &Subject<'_>,
        matched: &[&Compiled<'p>],
        state: &DeviceState,
        trace_id: TraceId,
    ) -> Option<Decision> {
        let t = subject.object_type;
        let (full, winner) = self.run(matched, subject, trace_id);
        if full.outcome() != Outcome::Blocked {
            let mode = self.mode_of(t, winner, state).mode;
            return Some(full.in_mode(mode));
        }
        // Layer 1: the modes, without the session.
        let base = DeviceState {
            session: None,
            ..*state
        };
        let one = self.enforcing(subject, matched, (full.clone(), winner), &base, trace_id);
        if !one.blocks {
            let effective = self.mode_of(t, winner, &base);
            let learning = effective.mode == Mode::Learning && winner.is_none();
            let directives = one.directives();
            return Some(full.relaxed(effective, directives, learning));
        }
        let Some(_) = state.session else {
            return Some(
                one.decision
                    .with_overridden(one.dropped)
                    .in_mode(Mode::Enforce),
            );
        };
        // Layer 2: what the session relaxes of what layer 1 enforced.
        let two = self.enforcing(
            subject,
            &one.kept,
            (one.decision.clone(), one.winner),
            state,
            trace_id,
        );
        let mut dropped = one.dropped.clone();
        dropped.extend(two.dropped.iter().copied());
        if two.blocks {
            return Some(two.decision.with_overridden(dropped).in_mode(Mode::Enforce));
        }
        let effective = self.mode_of(t, one.winner, state);
        let directives = two.directives();
        Some(
            one.decision
                .with_overridden(one.dropped)
                .relaxed(effective, directives, false),
        )
    }

    /// The effective mode of a decision decided by `rule`, or by the
    /// implicit deny.
    fn mode_of(
        &self,
        t: ObjectType,
        rule: Option<&Compiled<'_>>,
        state: &DeviceState,
    ) -> mode::EffectiveMode {
        mode::resolve(self.policy, t, rule.map(|r| (r.set, r.rule)), state)
    }

    /// One relaxation layer. `first` is the decision over `rules`. If it
    /// blocks in a mode that enforces under `state`, it stands. Otherwise
    /// every deny that does not enforce under `state` is set aside, and the
    /// rest are decided again.
    fn enforcing<'a>(
        &self,
        subject: &Subject<'_>,
        rules: &[&'a Compiled<'p>],
        first: (Decision, Option<&'a Compiled<'p>>),
        state: &DeviceState,
        trace_id: TraceId,
    ) -> Layer<'a, 'p> {
        let t = subject.object_type;
        let enforces = |r: Option<&Compiled<'_>>| self.mode_of(t, r, state).mode == Mode::Enforce;
        let (decision, winner) = first;
        if decision.outcome() == Outcome::Blocked && enforces(winner) {
            return Layer {
                decision,
                winner,
                kept: rules.to_vec(),
                dropped: Vec::new(),
                blocks: true,
            };
        }
        let (dropped, kept): (Vec<&Compiled<'p>>, Vec<&Compiled<'p>>) = rules
            .iter()
            .partition(|r| matches!(r.role, Role::Policy(Verdict::Deny)) && !enforces(Some(r)));
        let (decision, winner) = self.run(&kept, subject, trace_id);
        let blocks = decision.outcome() == Outcome::Blocked && enforces(winner);
        Layer {
            decision,
            winner,
            kept,
            dropped: dropped.iter().map(|r| r.reference).collect(),
            blocks,
        }
    }

    /// The enabled rules that apply to the subject.
    fn matching(&self, subject: &Subject<'_>) -> Vec<&Compiled<'p>> {
        self.matching_with_notes(subject).0
    }

    /// The enabled rules that apply to the subject, and the scope notes of
    /// every rule whose tree was not `NoMatch`.
    fn matching_with_notes(&self, subject: &Subject<'_>) -> (Vec<&Compiled<'p>>, ScopeNotes) {
        let mut notes = ScopeNotes::default();
        let matched = self
            .rules
            .iter()
            .filter(|r| r.applies(subject, &mut notes))
            .collect();
        (matched, notes)
    }

    /// Runs the stages over the rules that apply, and returns the decision
    /// and the deciding rule (`None` for the implicit deny).
    fn run<'a>(
        &self,
        matched: &[&'a Compiled<'p>],
        subject: &Subject<'_>,
        trace_id: TraceId,
    ) -> (Decision, Option<&'a Compiled<'p>>) {
        let mut mandatory = Vec::new();
        let mut exclusions = Vec::new();
        let mut policy = Vec::new();
        let mut annotations = Vec::new();
        let mut trust = Vec::new();
        for &rule in matched {
            match rule.role {
                Role::Mandatory => mandatory.push(rule),
                Role::Exclusion => exclusions.push(rule),
                Role::Policy(v) => policy.push((rule, v)),
                Role::Annotation => annotations.push(rule.reference),
                Role::Trust => trust.push(rule),
            }
        }

        // Stage 1, then stage 2. Every candidate of a stage does the same
        // thing, so the most specific one decides; `most_specific` does not
        // read the verdict.
        for stage in [&mandatory, &exclusions] {
            let set = MatchSet {
                candidates: stage.iter().map(|r| r.candidate(Verdict::Deny)).collect(),
            };
            if let Some(i) = most_specific(&set) {
                let winner = stage[i];
                let overridden = mandatory
                    .iter()
                    .chain(&exclusions)
                    .chain(policy.iter().map(|(r, _)| r))
                    .chain(&trust)
                    .filter(|r| r.rule.id != winner.rule.id)
                    .map(|r| r.reference)
                    .collect();
                let d =
                    self.decide(winner, trace_id)
                        .with_context(overridden, annotations, Vec::new());
                return (d, Some(winner));
            }
        }

        // Stage 4: the precedence model.
        let set = MatchSet {
            candidates: policy.iter().map(|(r, v)| r.candidate(*v)).collect(),
        };
        let Some(i) = self.resolver.resolve(&set).winner else {
            // Stage 6: nothing decided.
            let overridden = trust.iter().map(|r| r.reference).collect();
            let d =
                Decision::implicit_deny(trace_id).with_context(overridden, annotations, Vec::new());
            return (d, None);
        };
        let (winner, verdict) = policy[i];
        let mut overridden: Vec<RuleRef> = policy
            .iter()
            .filter(|(r, _)| r.rule.id != winner.rule.id)
            .map(|(r, _)| r.reference)
            .collect();
        let grants = if verdict.allows() {
            trust
                .iter()
                .filter_map(|r| match &r.rule.action {
                    Action::TrustSource(d) => Some(TrustGrant::new(r.reference, d)),
                    _ => None,
                })
                .collect()
        } else {
            overridden.extend(trust.iter().map(|r| r.reference));
            Vec::new()
        };
        let mut d = self
            .decide(winner, trace_id)
            .with_context(overridden, annotations, grants);
        if verdict.allows() {
            if let Some(close) = winner.window_close(subject) {
                d = d.with_window_close(close);
            }
            if let Some(limit) = winner.instance_limit() {
                // The count is a fact like any other: unknown never allows.
                let running = subject.context.scope.instances_in_session;
                if running.is_none_or(|n| n >= limit) {
                    return (
                        d.instance_limit()
                            .with_scope_notes(note(ScopeNote::InstanceLimit)),
                        Some(winner),
                    );
                }
            }
        }
        (d, Some(winner))
    }

    /// The decision of a deciding rule. Only enabled rules with a terminal
    /// action reach this, so `from_rule` always gives one; if it ever did
    /// not, the object is blocked rather than allowed.
    fn decide(&self, winner: &Compiled<'_>, trace_id: TraceId) -> Decision {
        Decision::from_rule(self.policy, winner.set, winner.rule, trace_id)
            .unwrap_or_else(|| Decision::implicit_deny(trace_id))
    }
}

// The decision trace (#41, `crate::trace`) lists the rules that applied as
// `evaluate` found them, so it can never disagree with the evaluator.
impl Evaluator<'_> {
    /// The IDs of the enabled rules that apply to the subject.
    pub(crate) fn matching_ids(&self, subject: &Subject<'_>) -> Vec<RuleId> {
        self.matching(subject).iter().map(|r| r.rule.id).collect()
    }

    /// The scopes of an enabled rule, evaluated for the subject (#38), as
    /// the evaluator reads them; `None` for a rule it does not hold.
    pub(crate) fn scope_of(&self, rule: RuleId, subject: &Subject<'_>) -> Option<ScopeEvaluation> {
        self.rules
            .iter()
            .find(|r| r.rule.id == rule)
            .map(|r| r.scope_eval(subject))
    }
}

/// A set of one note.
fn note(n: ScopeNote) -> ScopeNotes {
    let mut notes = ScopeNotes::default();
    notes.insert(n);
    notes
}

#[cfg(test)]
mod tests;
