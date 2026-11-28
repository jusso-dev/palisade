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
//!    `allow_elevated` and `deny` rules. Two kinds of rule are floors,
//!    decided over only when nothing above them matched: the managed
//!    `system_baseline` (#39), and below it the policy's `catch_all` rules
//!    (#329), its default for every object no other rule matched.
//! 5. **Attribute.** Only after stage 4 allowed: post-allow attribute
//!    rules (`attribute: true`, #33, #329). A matching attribute `deny`
//!    blocks the object (the most specific one decides, and the allow is
//!    listed as overridden); an attribute `audit` annotates it.
//! 6. **Unknown.** If nothing decided, the policy's unknown-application
//!    policy decides ([`crate::unknown`], #39). Its default blocks
//!    (`implicit_deny_unknown`), the implicit deny of ADR 0004.
//!
//! Between stages 1 and 2, an object that is one of Palisade's own pinned
//! images ([`Evaluator::with_self_images`]) is allowed (`self_allow`).
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
//! # Rule lifecycle
//!
//! A rule outside its activity window (`activates_at`, `expires_at`, #40)
//! behaves as absent, exactly like a disabled rule
//! ([`crate::lifecycle::activity`]). [`Evaluator::at`] sets the clock.
//! Without one, or while the agent is offline-started (the clock is not
//! anchored, ADR 0018), a time-bounded rule that lets an object run,
//! trusts it or excludes it is inactive; without one, any other is active. An expired rule with
//! `on_expire: convert_to_audit` only annotates.
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
use crate::decision::{
    Decision, Directives, ReasonCode, RuleRef, TraceId, TrustGrant, WindowClose,
};
use crate::demand::FactSet;
use crate::facts::{ObjectFacts, PathVariables};
use crate::mode::{self, DeviceState};
use crate::model::{
    Action, Mode, ObjectType, Policy, Rule, RuleId, RuleSet, RuleSetId, RuleSetKind, UnknownAs,
};
use crate::ops::{EvalContext, Tri};
use crate::precedence::{Candidate, Precedence, Resolver, Spec, Verdict, most_specific};
use crate::scope::compile::Env;
use crate::scope::{
    Bias, CompiledScope, NoLibrary, OnWindowClose, ScopeEvaluation, ScopeLevel, ScopeLibrary,
    ScopeNote, ScopeNotes, eval_chain,
};
use crate::unknown::{SelfImage, StageSix, UnknownScope};

/// The rules of one decision, kept inline: a decision with up to this many
/// matching rules does not allocate for them (#42).
type Rules<'a, 'p> = smallvec::SmallVec<[&'a Compiled<'p>; 16]>;
use crate::validate::ValidatedPolicy;

pub mod index;

#[cfg(test)]
pub(crate) use index::tests as index_tests;

pub use index::{ALWAYS_EVAL_WARN, IndexStats, NeedFacts, RequiredFacts};

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
    /// A post-allow attribute rule: stage 5, only for an object stage 4
    /// allowed. `deny` blocks it; otherwise it annotates (#329).
    Attribute {
        /// Whether it denies.
        deny: bool,
    },
}

/// The candidates of one stage, kept inline.
type Candidates = smallvec::SmallVec<[Candidate; 16]>;

/// A rule's match tree, ready to evaluate.
#[derive(Debug)]
enum Tree<'p> {
    /// A compiled tree.
    Compiled(CompiledMatch),
    /// A single `equals` test of a hash field, read straight from the
    /// validated document, whose values are canonical lowercase hex. The
    /// hash index holds the same digests, so a compiled copy would only
    /// double the memory of a large hash set (#42). Matching is the same as
    /// a compiled criterion's: a missing or malformed fact is `Unknown`.
    Hash {
        field: crate::model::Field,
        hex_len: usize,
        values: &'p [String],
    },
}

impl Tree<'_> {
    fn compile<'p>(rule: &'p Rule) -> Result<Tree<'p>, Vec<crate::condition::TreeError>> {
        use crate::model::{FieldClass, Match, Operator};
        if let Match::Criterion(c) = &rule.match_ {
            // Only a criterion with no options: `safety_critical` changes
            // what an unknown hash means (#32).
            if let (FieldClass::Hash { hex_len }, Operator::Equals, None, false) = (
                c.field.class(),
                c.operator,
                c.case_sensitive,
                c.safety_critical,
            ) {
                // The leaf thumbprint is read from the signers, not the
                // hash facts.
                let canonical = c.values.iter().all(|v| {
                    v.len() == hex_len
                        && v.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                });
                if !c.field.is_signer() && canonical && !c.values.is_empty() {
                    return Ok(Tree::Hash {
                        field: c.field,
                        hex_len,
                        values: &c.values,
                    });
                }
            }
        }
        CompiledMatch::compile(&rule.match_).map(Tree::Compiled)
    }

    /// The tree's result. `mandatory` is whether the rule is a mandatory
    /// deny, whose `safety_critical` criteria fail closed (#32, #87).
    fn eval(
        &self,
        facts: &ObjectFacts,
        ctx: &EvalContext<'_>,
        unparseable: Unparseable,
        mandatory: bool,
    ) -> Tri {
        match self {
            Self::Compiled(tree) if mandatory => {
                tree.eval_mandatory(facts, ctx, unparseable).result
            }
            Self::Compiled(tree) => tree.eval_with(facts, ctx, unparseable).result,
            Self::Hash {
                field,
                hex_len,
                values,
            } => match facts.get(*field) {
                Some(fact)
                    if fact.len() == *hex_len && fact.bytes().all(|b| b.is_ascii_hexdigit()) =>
                {
                    Tri::from_bool(values.iter().any(|v| fact.eq_ignore_ascii_case(v)))
                }
                _ => Tri::Unknown,
            },
        }
    }
}

/// One enabled rule, ready to evaluate.
#[derive(Debug)]
struct Compiled<'p> {
    set: &'p RuleSet,
    rule: &'p Rule,
    tree: Tree<'p>,
    role: Role,
    spec: Spec,
    unknown_as: UnknownAs,
    unparseable: Unparseable,
    reference: RuleRef,
    /// The scopes on the way to the rule: the policy's, the rule set
    /// assignment's, then its own.
    scopes: Vec<(ScopeLevel, Arc<CompiledScope>)>,
    bias: Bias,
    /// A rule of the managed `system_baseline` (#39): a floor that only
    /// decides when no tenant stage-4 rule matched.
    floor: bool,
    /// A `catch_all` rule (#329): the lowest floor, which decides only when
    /// neither a tenant rule nor the `system_baseline` matched.
    catch_all: bool,
    /// The rule has an activity window, so its activity depends on the
    /// clock (#40).
    timed: bool,
    /// The `audit` stand-in of an expired rule with `on_expire:
    /// convert_to_audit`: live only once the rule has expired.
    twin: bool,
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
        let tree = self.tree.eval(
            subject.facts,
            &ctx,
            self.unparseable,
            self.role == Role::Mandatory,
        );
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
    kept: Rules<'a, 'p>,
    /// The denies set aside because they do not enforce.
    dropped: smallvec::SmallVec<[RuleRef; 4]>,
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
    self_images: Vec<SelfImage>,
    /// Where the policy's unknown settings apply (#38, #39).
    unknown_scope: UnknownScope,
    clock: Option<crate::lifecycle::RuleClock>,
    /// The candidate indexes over `rules` (#42).
    index: index::RuleIndex,
    /// Whether a decision can depend on facts the decision cache does not
    /// key (#42): scopes (#38) and activity windows (#40).
    cache_unsafe: bool,
    /// Whether the unknown-application policy can prompt (#39), whose
    /// directive carries the file's SHA-256.
    prompts: bool,
    /// Whether a level of the unknown-application policy depends on the
    /// object's location class (#39), which reads the path's ACL.
    by_location: bool,
}

/// What one evaluation knows besides the matching rules.
struct Inputs<'a> {
    six: StageSix<'a>,
    pinned: bool,
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
        let mut twins = Vec::new();
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
                    // Validation allows only `deny` and `audit` here.
                    Action::Deny(_) if rule.attribute => Role::Attribute { deny: true },
                    Action::Audit {} if rule.attribute => Role::Attribute { deny: false },
                    _ if rule.attribute => continue,
                    Action::Ignore {} => Role::Exclusion,
                    Action::Audit {} => Role::Annotation,
                    Action::TrustSource(_) => Role::Trust,
                    Action::Defer {} => continue,
                    action => match Verdict::of(action) {
                        Some(v) => Role::Policy(v),
                        None => continue,
                    },
                };
                let tree = Tree::compile(rule).map_err(|errors| BuildError {
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
                let timed = rule.activates_at.is_some() || rule.expires_at.is_some();
                // A native `audit` rule gets a twin too: it stops at expiry
                // like any rule, and its twin carries on, so it annotates
                // exactly once before and after.
                let converts = rule.expires_at.is_some()
                    && rule.on_expire == crate::model::OnExpire::ConvertToAudit
                    && !set.mandatory;
                let mut scopes = chain.clone();
                if let Some(s) = &rule.scope {
                    scopes.push((ScopeLevel::Rule, compile(s)));
                }
                let compiled = Compiled {
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
                    floor: crate::unknown::baseline::is_system_baseline(set),
                    catch_all: rule.catch_all,
                    timed,
                    twin: false,
                };
                if converts {
                    twins.push(Compiled {
                        set,
                        rule,
                        tree: Tree::compile(rule).map_err(|errors| BuildError {
                            rule_id: rule.id,
                            errors,
                        })?,
                        role: Role::Annotation,
                        spec: compiled.spec,
                        unknown_as: UnknownAs::NoMatch,
                        unparseable: Unparseable::Unknown,
                        reference: compiled.reference,
                        // The same scopes as the rule: an audit twin
                        // annotates only where the rule would have applied.
                        scopes: compiled.scopes.clone(),
                        bias: Bias::of(crate::model::ActionKind::Audit),
                        floor: false,
                        catch_all: false,
                        timed: true,
                        twin: true,
                    });
                }
                rules.push(compiled);
            }
        }
        let unknown_scope = UnknownScope::new(
            policy_scope,
            policy.unknown.scopes.iter().map(compile).collect(),
            policy
                .unknown
                .scope_limits
                .iter()
                .map(|l| {
                    (
                        l.all_of.iter().map(compile).collect(),
                        l.any_of.iter().map(compile).collect(),
                    )
                })
                .collect(),
        );
        // Twins come last, so the ordinals of real rules (for counters) are
        // positions in the policy. The index is built over every rule,
        // twins included, so its ordinals are positions in `rules`.
        rules.extend(twins);
        let index = index::RuleIndex::build(&rules);
        let cache_unsafe = policy.scope.is_some()
            || !policy.rule_set_scopes.is_empty()
            || rules.iter().any(|r| !r.scopes.is_empty() || r.timed);
        Ok(Self {
            policy,
            rules,
            resolver: Resolver::new(policy.precedence_model, &policy.precedence_options),
            self_images: Vec::new(),
            unknown_scope,
            clock: None,
            index,
            cache_unsafe,
            prompts: {
                use crate::model::Level;
                let u = &policy.unknown;
                u.default == Level::Prompt
                    || u.by_location.values().any(|l| *l == Level::Prompt)
                    || u.by_origin.values().any(|l| *l == Level::Prompt)
                    || u.by_type.values().any(|l| *l == Level::Prompt)
            },
            by_location: !policy.unknown.by_location.is_empty(),
        })
    }

    /// The same evaluator, deciding at `clock`: rules outside their
    /// activity window behave as absent ([`crate::lifecycle`], #40).
    #[must_use]
    pub const fn at(mut self, clock: crate::lifecycle::RuleClock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Hit counters for this evaluator's rules, by ordinal (#40).
    #[must_use]
    pub fn counters(&self) -> crate::lifecycle::Counters {
        crate::lifecycle::Counters::new(
            self.policy.id,
            self.policy.revision,
            self.rules
                .iter()
                .filter(|r| !r.twin)
                .map(|r| r.reference)
                .collect(),
        )
    }

    /// Sets the clock rules are judged at (#40). The agent sets it before
    /// each decision, or whenever its trusted time or floor moves.
    pub const fn set_clock(&mut self, clock: crate::lifecycle::RuleClock) {
        self.clock = Some(clock);
    }

    /// Whether `rule` takes part at this evaluator's clock, and why not:
    /// [`crate::lifecycle::activity_at`] at the clock. With no clock, a
    /// time-bounded rule that lets an object run, trusts it or excludes it
    /// is `not_yet_active`, and any other is active (the closed direction);
    /// with an unanchored clock, such a rule is inactive too.
    /// The decision trace (#41) reports inactive rules with this.
    #[must_use]
    pub fn activity_of(&self, rule: &Rule) -> crate::lifecycle::Activity {
        crate::lifecycle::activity_at(rule, self.clock.as_ref())
    }

    /// Whether a compiled rule takes part at the evaluator's clock.
    fn live(&self, r: &Compiled<'_>) -> bool {
        use crate::lifecycle::Activity;
        if !r.timed {
            return true;
        }
        let activity = self.activity_of(r.rule);
        if r.twin {
            activity == Activity::Expired
        } else {
            activity == Activity::Active
        }
    }

    /// The same evaluator, with Palisade's own images pinned (#39): an
    /// object that is one of them is allowed after stage 1, whatever the
    /// ordinary rules say ([`crate::unknown::selfpin`]).
    #[must_use]
    pub fn with_self_images(mut self, images: Vec<SelfImage>) -> Self {
        self.self_images = images;
        self
    }

    /// The inputs of stages 2 to 6 for one subject.
    fn inputs<'a>(&'a self, subject: &Subject<'a>, matched: &[&Compiled<'p>]) -> Inputs<'a> {
        // An object is blocklisted when a rule that denies it matched, or a
        // native `audit` entry of a blocklist set (a blocklist's watch
        // entry: the user is not asked to allow it, #39). The `audit` twin
        // of an expired rule never counts: an expired rule only annotates.
        // `ignore` is valid only in `mixed` sets and never denies.
        let blocklisted = matched.iter().any(|r| {
            !r.twin
                && (matches!(
                    r.role,
                    Role::Mandatory | Role::Policy(Verdict::Deny) | Role::Attribute { deny: true }
                ) || (r.role == Role::Annotation && r.set.kind == RuleSetKind::Blocklist))
        });
        Inputs {
            six: StageSix::new(
                &self.policy.unknown,
                &self.unknown_scope,
                subject.object_type,
                subject.facts,
                subject.variables,
                subject.context,
                blocklisted,
            ),
            pinned: self
                .self_images
                .iter()
                .any(|i| i.matches(subject.object_type, subject.facts)),
        }
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
        let selection = self.select_all(subject);
        let inputs = self.inputs(subject, &selection.matched);
        self.run(&selection.matched, subject, &inputs, trace_id)
            .0
            .with_scope_notes(selection.notes)
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
        let selection = self.select_all(subject);
        Some(
            self.decide_in(subject, &selection.matched, state, trace_id)
                .with_scope_notes(selection.notes),
        )
    }

    /// Decides one object with the facts computed so far, as the agent's
    /// lazy fact protocol needs (#42, [`index`]): `computed` names the
    /// classes the agent has computed, besides the cheap ones and any
    /// whose facts are present.
    ///
    /// Returns `Ok(None)` when the device is disabled, as
    /// [`evaluate_in`](Self::evaluate_in) does. Once the decision no longer
    /// depends on a missing fact, the result is the same as `evaluate_in`
    /// with the same facts.
    ///
    /// # Errors
    ///
    /// [`NeedFacts`] with the classes to compute next, when a rule that
    /// could still apply reads a class that has not been computed.
    pub fn evaluate_with(
        &self,
        subject: &Subject<'_>,
        computed: FactSet,
        state: &DeviceState,
        trace_id: TraceId,
    ) -> Result<Option<Decision>, NeedFacts> {
        match self.evaluate_watched(subject, computed, state, trace_id, &mut |_| false) {
            Ok(d) => Ok(d.map(|(d, _)| d)),
            Err(index::Stop::Need(need)) => Err(need),
            // Nothing expires without a watchdog; if it did, block.
            Err(index::Stop::Timeout(t)) => Ok(Some(self.timed_out(subject, &t, true, trace_id))),
        }
    }

    /// [`evaluate_with`](Self::evaluate_with), with a watchdog asked before
    /// each match tree is evaluated, and whether the decision rests on an
    /// unknown fact, for the decision cache ([`crate::engine`]).
    pub(crate) fn evaluate_watched(
        &self,
        subject: &Subject<'_>,
        computed: FactSet,
        state: &DeviceState,
        trace_id: TraceId,
        expired: &mut dyn FnMut(&RuleRef) -> bool,
    ) -> Result<Option<(Decision, bool)>, index::Stop> {
        if mode::device_mode(self.policy, state) == Mode::Disabled {
            return Ok(None);
        }
        let selection = self.select(subject, computed, expired)?;
        let decision = self
            .decide_in(subject, &selection.matched, state, trace_id)
            .with_scope_notes(selection.notes);
        // A decision that rests on an unknown fact, or on facts the cache
        // does not key, is not cached.
        Ok(Some((decision, selection.unknown || self.cache_unsafe)))
    }

    /// The fallback decision of a selection the watchdog stopped (#42).
    ///
    /// - A mandatory deny that already matched decides, as it always does
    ///   (ADR 0004): the object is blocked by it, in every mode.
    /// - If the mandatory tier was not finished, a mandatory deny could
    ///   still match, so the object is blocked, whatever `block` says.
    /// - Otherwise the implicit deny, with the reason `eval_timeout`, in
    ///   enforce mode if `block`, and relaxed to `allowed_audit` if not.
    pub(crate) fn timed_out(
        &self,
        subject: &Subject<'_>,
        timeout: &index::Timeout,
        block: bool,
        trace_id: TraceId,
    ) -> Decision {
        // The mandatory denies that matched decide as stage 1 does: the
        // most specific, with the others listed as overridden.
        let mandatory: Rules<'_, 'p> = timeout
            .mandatory
            .iter()
            .filter_map(|&i| self.rules.get(i as usize))
            .collect();
        if !mandatory.is_empty() {
            let inputs = self.inputs(subject, &mandatory);
            return self.run(&mandatory, subject, &inputs, trace_id).0;
        }
        let blocked = Decision::implicit_deny(trace_id).with_reason(ReasonCode::EvalTimeout);
        if block || !timeout.mandatory_done {
            blocked
        } else {
            blocked
                .timed_out_audit()
                .with_reason(ReasonCode::EvalTimeout)
        }
    }

    /// The decision of the linear scan over every rule, with every fact
    /// computed: the reference the indexes are tested against.
    #[cfg(test)]
    pub(crate) fn evaluate_linear(&self, subject: &Subject<'_>, trace_id: TraceId) -> Decision {
        let (matched, notes) = self.matching_with_notes(subject);
        let inputs = self.inputs(subject, &matched);
        self.run(&matched, subject, &inputs, trace_id)
            .0
            .with_scope_notes(notes)
    }

    /// The facts the policy can read, computed when it was loaded.
    #[must_use]
    pub const fn required_facts(&self) -> RequiredFacts {
        self.index.required()
    }

    /// What the candidate indexes hold.
    #[must_use]
    pub const fn index_stats(&self) -> IndexStats {
        self.index.stats()
    }

    /// [`evaluate_in`](Self::evaluate_in) over the rules that apply, on a
    /// device that is not disabled.
    fn decide_in(
        &self,
        subject: &Subject<'_>,
        matched: &[&Compiled<'p>],
        state: &DeviceState,
        trace_id: TraceId,
    ) -> Decision {
        let t = subject.object_type;
        let inputs = self.inputs(subject, matched);
        let (full, winner) = self.run(matched, subject, &inputs, trace_id);
        // Only stage 6 follows `driver_boot_policy`.
        let boot = inputs.six.boot_audit && full.unhandled();
        if !full.outcome().stops() {
            let mode = self.mode_of(t, winner, state, boot).mode;
            let learning = mode == Mode::Learning && full.unhandled();
            return full.in_mode(mode).with_learning(learning);
        }
        // Layer 1: the modes, without the session.
        let base = DeviceState {
            session: None,
            ..*state
        };
        let one = self.enforcing(
            subject,
            matched,
            (full.clone(), winner),
            &base,
            &inputs,
            trace_id,
        );
        if !one.blocks {
            let effective = self.mode_of(t, winner, &base, boot);
            let learning = effective.mode == Mode::Learning && full.unhandled();
            let directives = one.directives();
            return full.relaxed(effective, directives, learning);
        }
        let Some(_) = state.session else {
            return one
                .decision
                .with_overridden(one.dropped)
                .in_mode(Mode::Enforce);
        };
        // Layer 2: what the session relaxes of what layer 1 enforced.
        let two = self.enforcing(
            subject,
            &one.kept,
            (one.decision.clone(), one.winner),
            state,
            &inputs,
            trace_id,
        );
        let mut dropped = one.dropped.clone();
        dropped.extend(two.dropped.iter().copied());

        if two.blocks {
            return two.decision.with_overridden(dropped).in_mode(Mode::Enforce);
        }
        let effective = self.mode_of(t, one.winner, state, boot);
        let directives = two.directives();
        one.decision
            .with_overridden(one.dropped)
            .relaxed(effective, directives, false)
    }

    /// The effective mode of a decision decided by `rule`, or by stage 6
    /// when `rule` is `None`. With `boot_audit` (a driver in early boot
    /// under `driver_boot_policy: audit`), stage 6 does not enforce, except
    /// in lockdown.
    fn mode_of(
        &self,
        t: ObjectType,
        rule: Option<&Compiled<'_>>,
        state: &DeviceState,
        boot_audit: bool,
    ) -> mode::EffectiveMode {
        let mut m = mode::resolve(self.policy, t, rule.map(|r| (r.set, r.rule)), state);
        if rule.is_none() && boot_audit && !state.lockdown {
            m.mode = mode::capped(m.mode, Mode::Audit);
            m.by_session = false;
        }
        m
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
        inputs: &Inputs<'_>,
        trace_id: TraceId,
    ) -> Layer<'a, 'p> {
        let t = subject.object_type;
        let enforces = |d: &Decision, r: Option<&Compiled<'_>>| {
            let boot = inputs.six.boot_audit && d.unhandled();
            self.mode_of(t, r, state, boot).mode == Mode::Enforce
        };
        let (decision, winner) = first;
        if decision.outcome().stops() && enforces(&decision, winner) {
            return Layer {
                decision,
                winner,
                kept: rules.iter().copied().collect(),
                dropped: smallvec::SmallVec::new(),
                blocks: true,
            };
        }
        let mut kept = Rules::new();
        let mut dropped = smallvec::SmallVec::new();
        for &r in rules {
            if matches!(
                r.role,
                Role::Policy(Verdict::Deny) | Role::Attribute { deny: true }
            ) && !enforces(&decision, Some(r))
            {
                dropped.push(r.reference);
            } else {
                kept.push(r);
            }
        }
        let (decision, winner) = self.run(&kept, subject, inputs, trace_id);
        let blocks = decision.outcome().stops() && enforces(&decision, winner);
        Layer {
            decision,
            winner,
            kept,
            dropped,
            blocks,
        }
    }

    /// The enabled rules that apply to the subject, found through the
    /// candidate indexes ([`index`]). Kept with this signature for code
    /// that lists the matching rules, such as the decision trace (#41).
    #[allow(dead_code)]
    fn matching(&self, subject: &Subject<'_>) -> Vec<&Compiled<'p>> {
        self.select_all(subject).matched.into_vec()
    }

    /// The same rules, found by evaluating every rule, and the scope notes
    /// of every rule whose tree was not `NoMatch`: the reference the
    /// indexes are tested against.
    fn matching_with_notes(&self, subject: &Subject<'_>) -> (Vec<&Compiled<'p>>, ScopeNotes) {
        let mut notes = ScopeNotes::default();
        let matched = self
            .rules
            .iter()
            .filter(|r| self.live(r) && r.applies(subject, &mut notes))
            .collect();
        (matched, notes)
    }

    /// The rules that apply, found by evaluating every rule.
    #[cfg(test)]
    fn matching_linear(&self, subject: &Subject<'_>) -> Vec<&Compiled<'p>> {
        self.matching_with_notes(subject).0
    }

    /// Runs the stages over the rules that apply, and returns the decision
    /// and the deciding rule (`None` when stage 6 or a pinned image
    /// decided).
    fn run<'a>(
        &self,
        matched: &[&'a Compiled<'p>],
        subject: &Subject<'_>,
        inputs: &Inputs<'_>,
        trace_id: TraceId,
    ) -> (Decision, Option<&'a Compiled<'p>>) {
        let mut mandatory = Rules::new();
        let mut exclusions = Rules::new();
        let mut policy: smallvec::SmallVec<[(&Compiled<'p>, Verdict); 16]> =
            smallvec::SmallVec::new();
        let mut annotations = crate::decision::RuleRefs::new();
        let mut trust = Rules::new();
        let mut attribute = Rules::new();
        for &rule in matched {
            match rule.role {
                Role::Mandatory => mandatory.push(rule),
                Role::Exclusion => exclusions.push(rule),
                Role::Policy(v) => policy.push((rule, v)),
                Role::Annotation => annotations.push(rule.reference),
                Role::Trust => trust.push(rule),
                Role::Attribute { .. } => attribute.push(rule),
            }
        }

        // Stage 1, then stage 2. Every candidate of a stage does the same
        // thing, so the most specific one decides; `most_specific` does not
        // read the verdict. A pinned Palisade image is allowed between them.
        for (n, stage) in [&mandatory, &exclusions].into_iter().enumerate() {
            if n == 1 && inputs.pinned {
                let overridden = exclusions
                    .iter()
                    .chain(policy.iter().map(|(r, _)| r))
                    .chain(trust.iter())
                    .map(|r| r.reference)
                    .collect();
                let d = Decision::self_allow(trace_id).with_context(
                    overridden,
                    annotations,
                    Vec::new(),
                );
                return (d, None);
            }
            let set: Candidates = stage.iter().map(|r| r.candidate(Verdict::Deny)).collect();
            if let Some(i) = most_specific(&set) {
                let winner = stage[i];
                let overridden = mandatory
                    .iter()
                    .chain(&exclusions)
                    .chain(policy.iter().map(|(r, _)| r))
                    .chain(trust.iter())
                    .filter(|r| r.rule.id != winner.rule.id)
                    .map(|r| r.reference)
                    .collect();
                let d =
                    self.decide(winner, trace_id)
                        .with_context(overridden, annotations, Vec::new());
                return (d, Some(winner));
            }
        }

        // Stage 4: the precedence model, over the highest tier that has a
        // candidate. The managed `system_baseline` is a floor: its rules are
        // decided over only when no tenant rule matched, so under no model
        // does it override a tenant's rule. A `catch_all` rule is the
        // lowest floor, the policy's own default for what nothing else
        // matched (#329), so it never overrides the baseline either.
        let tier = |r: &Compiled<'_>| u8::from(r.floor) + 2 * u8::from(r.catch_all);
        let top = policy.iter().map(|(r, _)| tier(r)).min();
        let deciding: smallvec::SmallVec<[(&Compiled<'p>, Verdict); 16]> = policy
            .iter()
            .filter(|(r, _)| Some(tier(r)) == top)
            .copied()
            .collect();
        let set: Candidates = deciding.iter().map(|(r, v)| r.candidate(*v)).collect();
        let Some(i) = self.resolver.pick(&set) else {
            // Stage 6: nothing decided. Trust sources only grant to an
            // object a rule allowed, so they are overridden here.
            let overridden = trust.iter().map(|r| r.reference).collect();
            let d = inputs
                .six
                .decide(trace_id)
                .with_context(overridden, annotations, Vec::new());
            return (d, None);
        };
        let (winner, verdict) = deciding[i];
        // Stage 5: post-allow attribute rules (#329). Only after an allow;
        // a matching attribute deny blocks, the most specific deciding,
        // and every other rule is overridden. Attribute audits annotate an
        // object that stays allowed.
        if verdict.allows() {
            let denies: Rules = attribute
                .iter()
                .copied()
                .filter(|r| r.role == Role::Attribute { deny: true })
                .collect();
            let set: Candidates = denies.iter().map(|r| r.candidate(Verdict::Deny)).collect();
            if let Some(j) = most_specific(&set) {
                let blocker = denies[j];
                let overridden = policy
                    .iter()
                    .map(|(r, _)| r)
                    .chain(trust.iter())
                    .chain(denies.iter())
                    .filter(|r| r.rule.id != blocker.rule.id)
                    .map(|r| r.reference)
                    .collect();
                let d = self.decide(blocker, trace_id).with_context(
                    overridden,
                    annotations,
                    Vec::new(),
                );
                return (d, Some(blocker));
            }
            annotations.extend(
                attribute
                    .iter()
                    .filter(|r| r.role == Role::Attribute { deny: false })
                    .map(|r| r.reference),
            );
        }
        let mut overridden: crate::decision::RuleRefs = policy
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
