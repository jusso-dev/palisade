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
//! 3. **Override session.** Not yet: sessions are #9 and #36.
//! 4. **Policy.** The policy's precedence model ([`crate::precedence`])
//!    chooses among the matching `allow`, `allow_contained`,
//!    `allow_elevated` and `deny` rules.
//! 5. **Attribute.** Not yet: post-allow attribute rules are #33.
//! 6. **Unknown.** If nothing decided, the implicit deny
//!    (`implicit_deny_unknown`, #39).
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
//! The evaluator computes the enforce-mode decision, before anything that
//! relaxes it: [`Decision::mode`] is always `enforce`. The policy's `mode`,
//! each rule's `enforcement_override` (such as `never_enforce`) and the
//! per-class control levels in the policy settings (`dll_control` and the
//! others) are applied on top of it by the mode state machine (#36), which
//! keeps this result in [`Decision::would_have_been`]. Until then a
//! decision is the simulated enforce-mode result, and no component
//! enforces it.
//!
//! # Determinism
//!
//! Evaluation is a pure function of the policy and the object. Every
//! stage chooses by keys that end with the unique rule ID, and the lists in
//! a decision are sorted by rule ID, so the decision does not depend on
//! the order of rule sets in the policy or of rules in a rule set. Only
//! `first_match` and `priority` depend on rules' `order` and `priority`.

use std::collections::BTreeMap;

use crate::condition::{CompiledMatch, TreeError, Unparseable};
use crate::context::EvaluationContext;
use crate::decision::{Decision, RuleRef, TraceId, TrustGrant};
use crate::facts::{ObjectFacts, PathVariables};
use crate::model::{Action, ObjectType, Policy, Rule, RuleId, RuleSet, RuleSetId, UnknownAs};
use crate::ops::{EvalContext, Tri};
use crate::precedence::{Candidate, MatchSet, Precedence, Resolver, Spec, Verdict, most_specific};
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
        }
    }

    /// Whether the rule applies to the subject.
    fn applies(&self, subject: &Subject<'_>) -> bool {
        if !self.rule.object_types.is_empty()
            && !self.rule.object_types.contains(&subject.object_type)
        {
            return false;
        }
        let ctx = EvalContext {
            action: self.rule.action.kind(),
            variables: subject.variables,
            context: subject.context,
        };
        match self
            .tree
            .eval_with(subject.facts, &ctx, self.unparseable)
            .result
        {
            Tri::Match => true,
            Tri::Unknown => self.unknown_as == UnknownAs::Match,
            Tri::NoMatch => false,
        }
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
    /// Compiles every enabled rule of the rule sets the policy references.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if a tree does not compile, which validation
    /// rules out.
    pub fn new(validated: &'p ValidatedPolicy) -> Result<Self, BuildError> {
        let doc = validated.document();
        let policy = &doc.policy;
        let sets: BTreeMap<RuleSetId, &RuleSet> = doc.rule_sets.iter().map(|s| (s.id, s)).collect();
        let mut rules = Vec::new();
        for id in &policy.rule_sets {
            let Some(set) = sets.get(id).copied() else {
                continue;
            };
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
                rules.push(Compiled {
                    set,
                    rule,
                    tree,
                    role,
                    spec: Spec::of(&rule.match_),
                    unknown_as,
                    unparseable,
                    reference: RuleRef::new(policy, set, rule),
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

    /// Decides one object, as enforce mode sees it.
    #[must_use]
    pub fn evaluate(&self, subject: &Subject<'_>, trace_id: TraceId) -> Decision {
        let mut mandatory = Vec::new();
        let mut exclusions = Vec::new();
        let mut policy = Vec::new();
        let mut annotations = Vec::new();
        let mut trust = Vec::new();
        for rule in self.rules.iter().filter(|r| r.applies(subject)) {
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
                return self.decide(winner, trace_id).with_context(
                    overridden,
                    annotations,
                    Vec::new(),
                );
            }
        }

        // Stage 4: the precedence model.
        let set = MatchSet {
            candidates: policy.iter().map(|(r, v)| r.candidate(*v)).collect(),
        };
        let Some(i) = self.resolver.resolve(&set).winner else {
            // Stage 6: nothing decided.
            let overridden = trust.iter().map(|r| r.reference).collect();
            return Decision::implicit_deny(trace_id).with_context(
                overridden,
                annotations,
                Vec::new(),
            );
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
        self.decide(winner, trace_id)
            .with_context(overridden, annotations, grants)
    }

    /// The decision of a deciding rule. Only enabled rules with a terminal
    /// action reach this, so `from_rule` always gives one; if it ever did
    /// not, the object is blocked rather than allowed.
    fn decide(&self, winner: &Compiled<'_>, trace_id: TraceId) -> Decision {
        Decision::from_rule(self.policy, winner.set, winner.rule, trace_id)
            .unwrap_or_else(|| Decision::implicit_deny(trace_id))
    }
}

#[cfg(test)]
mod tests;
