//! The trace's own view of every rule: its match tree as an arena of
//! compiled criteria, evaluated leaf by leaf without short-circuiting, so
//! the trace can say which criteria matched, which did not, and why.
//!
//! The evaluator ([`crate::evaluate`]) stays the authority on which rules
//! applied: the trace takes that set from it. This view only explains each
//! result. It uses the same compiled criteria ([`CompiledCriterion`]) and
//! the same Kleene logic as [`crate::condition`], so the two agree; the
//! tests check that over random policies.

use serde::Serialize;

use crate::condition::{CompiledMatch, Unparseable};
use crate::decision::RuleRef;
use crate::evaluate::{BuildError, Subject};
use crate::model::{
    Action, ActionKind, Criterion, Field, Match, Operator, Policy, Rule, RuleSet, UnknownAs,
};
use crate::ops::{CompiledCriterion, EvalContext, Note, Notes, Tri};
use crate::precedence::Spec;

/// A three-valued result, as a trace writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriState {
    /// The test holds.
    Match,
    /// The test does not hold.
    NoMatch,
    /// A fact the test needs is missing or cannot be trusted.
    Unknown,
}

impl From<Tri> for TriState {
    fn from(t: Tri) -> Self {
        match t {
            Tri::Match => Self::Match,
            Tri::NoMatch => Self::NoMatch,
            Tri::Unknown => Self::Unknown,
        }
    }
}

/// Which pipeline stage a rule takes part in (#35).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStage {
    /// Stage 1: a rule of a mandatory rule set.
    MandatoryDeny,
    /// Stage 2: an `ignore` rule.
    Exclusion,
    /// Stage 4: an allow or deny for the precedence model.
    Policy,
    /// An `audit` rule: an annotation, never a decision.
    Annotation,
    /// A `trust_source` rule: a grant if the object is allowed.
    TrustSource,
    /// Stage 5: a post-allow attribute rule (#329).
    Attribute,
}

impl RuleStage {
    /// The stage of a rule, exactly as the evaluator assigns it. `None` for
    /// `defer`, which the evaluator never evaluates.
    pub(crate) const fn of(set: &RuleSet, rule: &Rule) -> Option<Self> {
        if set.mandatory {
            return Some(Self::MandatoryDeny);
        }
        if rule.attribute {
            return match rule.action {
                Action::Deny(_) | Action::Audit {} => Some(Self::Attribute),
                _ => None,
            };
        }
        Some(match rule.action {
            Action::Ignore {} => Self::Exclusion,
            Action::Audit {} => Self::Annotation,
            Action::TrustSource(_) => Self::TrustSource,
            Action::Defer {} => return None,
            Action::Allow {}
            | Action::Deny(_)
            | Action::AllowContained(_)
            | Action::AllowElevated(_) => Self::Policy,
        })
    }
}

#[derive(Clone, Debug)]
enum Node {
    All(Vec<u32>),
    Any(Vec<u32>),
    Not(u32),
    Leaf(u32),
}

/// One criterion of a traced rule.
#[derive(Debug)]
pub(crate) struct Leaf<'p> {
    pub criterion: &'p Criterion,
    pub compiled: CompiledCriterion,
    /// The JSON Pointer of the criterion, relative to the rule, such as
    /// `/match/all/0/criterion`.
    pub pointer: String,
    /// Whether an odd number of `not` nodes are above it.
    pub negated: bool,
}

/// One rule of the policy, enabled or not, ready to be explained.
#[derive(Debug)]
pub(crate) struct TracedRule<'p> {
    pub set: &'p RuleSet,
    pub rule: &'p Rule,
    pub stage: RuleStage,
    pub spec: Spec,
    pub reference: RuleRef,
    unknown_as: UnknownAs,
    unparseable: Unparseable,
    nodes: Vec<Node>,
    pub leaves: Vec<Leaf<'p>>,
}

/// The result of one criterion.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LeafResult {
    /// The criterion's own result.
    pub raw: Tri,
    /// The result the tree used: `raw`, unless the rule reads unparseable
    /// versions as matching (`on_unparseable: match`), or the criterion is
    /// `safety_critical` in a mandatory deny.
    pub effective: Tri,
    pub notes: Notes,
}

impl LeafResult {
    /// Whether the criterion pulled the rule towards matching: `Match`, or
    /// `NoMatch` under an odd number of `not` nodes.
    pub fn satisfied(&self, negated: bool) -> bool {
        self.effective == if negated { Tri::NoMatch } else { Tri::Match }
    }
}

/// The result of evaluating one traced rule against one subject.
#[derive(Clone, Debug)]
pub(crate) struct RuleResult {
    /// Whether the rule's `object_types` include the subject's type.
    pub type_applies: bool,
    /// The tree's result. `NoMatch` when the type does not apply.
    pub tree: Tri,
    /// Whether the rule applies: the type applies and the tree is `Match`,
    /// or `Unknown` for a deny with `unknown_as: match`.
    pub applies: bool,
    nodes: Vec<Tri>,
    /// One result per leaf, in [`TracedRule::leaves`] order. Empty when
    /// the type does not apply.
    pub leaves: Vec<LeafResult>,
}

impl<'p> TracedRule<'p> {
    /// Builds the traced form of `rule`. Returns `Ok(None)` for `defer`.
    pub fn build(
        policy: &Policy,
        set: &'p RuleSet,
        rule: &'p Rule,
    ) -> Result<Option<Self>, BuildError> {
        let Some(stage) = RuleStage::of(set, rule) else {
            return Ok(None);
        };
        // The same compilation and limits as the evaluator, so a tree the
        // evaluator accepts is within the depth that `add` recurses to.
        CompiledMatch::compile(&rule.match_).map_err(|errors| BuildError {
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
        let mut out = Self {
            set,
            rule,
            stage,
            spec: Spec::of(&rule.match_),
            reference: RuleRef::new(policy, set, rule),
            unknown_as,
            unparseable,
            nodes: Vec::new(),
            leaves: Vec::new(),
        };
        out.add(&rule.match_, "/match".to_owned(), false)
            .map_err(|errors| BuildError {
                rule_id: rule.id,
                errors,
            })?;
        Ok(Some(out))
    }

    fn add(
        &mut self,
        node: &'p Match,
        pointer: String,
        negated: bool,
    ) -> Result<u32, Vec<crate::condition::TreeError>> {
        let entry = match node {
            Match::All(items) | Match::Any(items) => {
                let key = if matches!(node, Match::All(_)) {
                    "all"
                } else {
                    "any"
                };
                let mut ids = Vec::with_capacity(items.len());
                for (i, child) in items.iter().enumerate() {
                    ids.push(self.add(child, format!("{pointer}/{key}/{i}"), negated)?);
                }
                if matches!(node, Match::All(_)) {
                    Node::All(ids)
                } else {
                    Node::Any(ids)
                }
            }
            Match::Not(child) => Node::Not(self.add(child, format!("{pointer}/not"), !negated)?),
            // As the evaluator: the hierarchy resolves every reference
            // before evaluation (#37), and validation rejects one left over.
            Match::Ref(_) => {
                return Err(vec![crate::condition::TreeError::UnresolvedRef {
                    pointer: format!("{pointer}/ref"),
                }]);
            }
            Match::Criterion(c) => {
                let compiled = CompiledCriterion::compile(c).map_err(|errors| {
                    vec![crate::condition::TreeError::Criterion {
                        pointer: format!("{pointer}/criterion"),
                        errors,
                    }]
                })?;
                self.leaves.push(Leaf {
                    criterion: c,
                    compiled,
                    pointer: format!("{pointer}/criterion"),
                    negated,
                });
                Node::Leaf(index(self.leaves.len() - 1))
            }
        };
        self.nodes.push(entry);
        Ok(index(self.nodes.len() - 1))
    }

    /// The rule's action.
    pub fn action(&self) -> ActionKind {
        self.rule.action.kind()
    }

    /// Evaluates every criterion of the rule, without short-circuiting.
    pub fn evaluate(&self, subject: &Subject<'_>) -> RuleResult {
        if !self.rule.object_types.is_empty()
            && !self.rule.object_types.contains(&subject.object_type)
        {
            return RuleResult {
                type_applies: false,
                tree: Tri::NoMatch,
                applies: false,
                nodes: Vec::new(),
                leaves: Vec::new(),
            };
        }
        let ctx = EvalContext {
            action: self.rule.action.kind(),
            variables: subject.variables,
            context: subject.context,
        };
        let mut nodes = vec![Tri::Unknown; self.nodes.len()];
        let mut leaves = Vec::with_capacity(self.leaves.len());
        for leaf in &self.leaves {
            let e = leaf.compiled.eval_under(subject.facts, &ctx, leaf.negated);
            // As the evaluator (`CompiledMatch::eval_mandatory`): a
            // safety-critical criterion of a mandatory deny that is unknown
            // counts towards the deny applying (#32, #87).
            let fail_closed = self.stage == RuleStage::MandatoryDeny
                && e.result == Tri::Unknown
                && leaf.compiled.safety_critical();
            let effective = if fail_closed
                || (e.result == Tri::Unknown
                    && self.unparseable == Unparseable::FavourMatch
                    && e.notes.contains(Note::VersionUnparseable))
            {
                Tri::from_bool(!leaf.negated)
            } else {
                e.result
            };
            leaves.push(LeafResult {
                raw: e.result,
                effective,
                notes: e.notes,
            });
        }
        // Children always come before their parent in the arena.
        for (i, node) in self.nodes.iter().enumerate() {
            nodes[i] = match node {
                Node::All(c) => c
                    .iter()
                    .fold(Tri::Match, |acc, &n| acc.and(nodes[n as usize])),
                Node::Any(c) => c
                    .iter()
                    .fold(Tri::NoMatch, |acc, &n| acc.or(nodes[n as usize])),
                Node::Not(n) => nodes[*n as usize].not(),
                Node::Leaf(l) => leaves[*l as usize].effective,
            };
        }
        let tree = nodes.last().copied().unwrap_or(Tri::Unknown);
        let applies = match tree {
            Tri::Match => true,
            Tri::Unknown => self.unknown_as == UnknownAs::Match,
            Tri::NoMatch => false,
        };
        RuleResult {
            type_applies: true,
            tree,
            applies,
            nodes,
            leaves,
        }
    }

    /// The leaves that kept the rule from matching, each with the result it
    /// needed (`Match`, or `NoMatch` under `not`), in document order. Empty
    /// when the tree matched.
    pub fn failing(&self, result: &RuleResult) -> Vec<(usize, Tri)> {
        let mut out = Vec::new();
        if result.type_applies && !self.nodes.is_empty() {
            self.collect_failing(index(self.nodes.len() - 1), Tri::Match, result, &mut out);
        }
        out.sort_by_key(|(leaf, _)| *leaf);
        out
    }

    fn collect_failing(&self, id: u32, want: Tri, r: &RuleResult, out: &mut Vec<(usize, Tri)>) {
        if r.nodes[id as usize] == want {
            return;
        }
        match &self.nodes[id as usize] {
            // `all` wanted `Match`: every child that is not `Match` failed.
            // `all` wanted `NoMatch` (under `not`): no child was `NoMatch`,
            // so every child failed. `any` is the mirror image. A child that
            // already gives `want` returns at once.
            Node::All(children) | Node::Any(children) => {
                for &c in children {
                    self.collect_failing(c, want, r, out);
                }
            }
            Node::Not(child) => {
                let flipped = if want == Tri::Match {
                    Tri::NoMatch
                } else {
                    Tri::Match
                };
                self.collect_failing(*child, flipped, r, out);
            }
            Node::Leaf(l) => out.push((*l as usize, want)),
        }
    }

    /// For each leaf, whether its result is part of why the tree has its
    /// result: walking down from the root, a node's children count when
    /// their result is the node's (every child of an `all` that matched or
    /// an `any` that did not; the matching children of an `any`, the
    /// failing children of an `all`; the unknown children of an unknown
    /// node), and a `not` node's child always counts. A leaf in a branch
    /// that Kleene logic absorbed does not count.
    pub fn contributing(&self, result: &RuleResult) -> Vec<bool> {
        let mut out = vec![false; self.leaves.len()];
        if result.type_applies && !self.nodes.is_empty() {
            self.mark(index(self.nodes.len() - 1), result, &mut out);
        }
        out
    }

    fn mark(&self, id: u32, r: &RuleResult, out: &mut [bool]) {
        let mine = r.nodes[id as usize];
        match &self.nodes[id as usize] {
            Node::All(children) | Node::Any(children) => {
                for &c in children {
                    if r.nodes[c as usize] == mine {
                        self.mark(c, r, out);
                    }
                }
            }
            Node::Not(child) => self.mark(*child, r, out),
            Node::Leaf(l) => {
                if let Some(slot) = out.get_mut(*l as usize) {
                    *slot = true;
                }
            }
        }
    }

    /// Whether the rule has a positive identity criterion (an object fact,
    /// not under `not`) that matched: the anchor of a near miss.
    pub fn anchor_matched(&self, result: &RuleResult) -> bool {
        self.leaves.iter().zip(&result.leaves).any(|(leaf, r)| {
            !leaf.negated
                && leaf.criterion.operator.is_positive()
                && leaf.criterion.field.strength().is_some()
                && r.effective == Tri::Match
        })
    }

    /// The number of criteria that pulled the rule towards matching.
    pub fn satisfied_count(&self, result: &RuleResult) -> usize {
        self.leaves
            .iter()
            .zip(&result.leaves)
            .filter(|(leaf, r)| r.satisfied(leaf.negated))
            .count()
    }
}

/// The stable name of a field, as a document writes it.
pub(crate) fn field_name(field: Field) -> String {
    match serde_json::to_value(field) {
        Ok(serde_json::Value::String(s)) => s,
        _ => format!("{field:?}"),
    }
}

/// The stable name of an operator, as a document writes it.
pub(crate) fn operator_name(operator: Operator) -> String {
    match serde_json::to_value(operator) {
        Ok(serde_json::Value::String(s)) => s,
        _ => format!("{operator:?}"),
    }
}

/// An arena index. Rule trees are limited far below `u32::MAX` nodes.
fn index(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}
