//! Evaluating a whole match tree (#33).
//!
//! A [`Match`] is compiled once, when the policy is loaded, into a
//! [`CompiledMatch`]: an arena of nodes with every criterion compiled
//! ([`CompiledCriterion`]). Compiling checks the limits that validation
//! checks ([`crate::model::limits`]), so a compiled tree is always within
//! them, and evaluation needs no recursion limit of its own.
//!
//! # Three-valued logic
//!
//! A tree evaluates to a [`Tri`] with Kleene logic:
//!
//! - `all` is `NoMatch` if any child is `NoMatch`, else `Unknown` if any
//!   child is `Unknown`, else `Match`.
//! - `any` is `Match` if any child is `Match`, else `Unknown` if any child
//!   is `Unknown`, else `NoMatch`.
//! - `not` swaps `Match` and `NoMatch`, and keeps `Unknown`.
//!
//! `all` stops at the first `NoMatch` and `any` at the first `Match`. Both
//! operations are commutative, so the order of children never changes the
//! result, and a later version may reorder them by cost (#42). The notes of
//! an evaluation only come from the criteria that were evaluated, so they
//! can depend on the order.
//!
//! # Rule level
//!
//! [`TreeEvaluation::matches`] decides whether the rule matches: only
//! `Match` does. `Unknown` counts as no match for every action. For an allow
//! rule that fails closed: an unknown fact never allows. For a deny rule it
//! means the rule does not apply, so an unknown fact does not block either;
//! that is the default (`no_match`) that #32 sets for deny rules.
//!
//! A deny rule can change both halves (#35). `unknown_as: match` makes it
//! apply on `Unknown` as well, which the pipeline in [`crate::evaluate`]
//! checks. `on_unparseable: match` is applied here, by
//! [`CompiledMatch::eval_with`] and [`Unparseable::FavourMatch`]: a
//! criterion that is `Unknown` only because its version fact is not a
//! version becomes `Match` where the tree would match with it, and
//! `NoMatch` under an odd number of `not` nodes. So it always counts
//! towards the deny applying, and the rest of the tree is evaluated as
//! usual.
//!
//! A criterion marked `safety_critical` in a mandatory blocklist works the
//! same way for any unknown fact ([`CompiledMatch::eval_mandatory`]), so the
//! shipped blocklists block an object whose facts are missing rather than
//! let it through (#32, #87).

use crate::facts::ObjectFacts;
use crate::model::Match;
use crate::model::limits::{MAX_CRITERIA_PER_RULE, MAX_TREE_DEPTH};
use crate::ops::{CompileError, CompiledCriterion, EvalContext, Note, Notes, Tri};

/// A match tree ready to be evaluated. Build one with
/// [`CompiledMatch::compile`].
#[derive(Clone, Debug)]
pub struct CompiledMatch {
    /// Every node; the root is the last.
    nodes: Vec<Node>,
    /// The children of `all` and `any` nodes, as indices into `nodes`.
    children: Vec<u32>,
    /// The compiled criteria, in document order.
    leaves: Vec<CompiledCriterion>,
}

#[derive(Clone, Copy, Debug)]
enum Node {
    /// `children[start..start + len]`.
    All { start: u32, len: u32 },
    /// `children[start..start + len]`.
    Any { start: u32, len: u32 },
    /// The node at this index.
    Not(u32),
    /// The leaf at this index.
    Leaf(u32),
}

/// Why a tree could not be compiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeError {
    /// The tree is nested more deeply than [`MAX_TREE_DEPTH`].
    TooDeep,
    /// The tree holds more than [`MAX_CRITERIA_PER_RULE`] criteria.
    TooManyCriteria,
    /// An `all` or `any` node has no children. `pointer` is relative to the
    /// tree's root, such as `/all/1/any`.
    EmptyGroup {
        /// Where the group is, relative to the root.
        pointer: String,
    },
    /// The tree still holds a library reference, which the hierarchy
    /// resolves before evaluation (#37). `pointer` is relative to the root.
    UnresolvedRef {
        /// Where the reference is, relative to the root.
        pointer: String,
    },
    /// A criterion did not compile. `pointer` is relative to the tree's
    /// root, such as `/all/0/criterion`.
    Criterion {
        /// Where the criterion is, relative to the root.
        pointer: String,
        /// What is wrong with it.
        errors: Vec<CompileError>,
    },
}

impl core::fmt::Display for TreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooDeep => write!(f, "the tree is nested more than {MAX_TREE_DEPTH} deep"),
            Self::TooManyCriteria => {
                write!(
                    f,
                    "the tree holds more than {MAX_CRITERIA_PER_RULE} criteria"
                )
            }
            Self::EmptyGroup { pointer } => {
                write!(f, "{pointer}: a group needs at least one condition")
            }
            Self::UnresolvedRef { pointer } => {
                write!(f, "{pointer}: a library reference was not resolved")
            }
            Self::Criterion { pointer, errors } => {
                write!(f, "{pointer}: ")?;
                for (i, e) in errors.iter().enumerate() {
                    if i > 0 {
                        f.write_str("; ")?;
                    }
                    match e.value {
                        Some(v) => write!(f, "value {v}: {}", e.kind)?,
                        None => write!(f, "{}", e.kind)?,
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for TreeError {}

/// How a criterion whose version fact is not a version is read (#32, #35).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Unparseable {
    /// It is `Unknown`, like any other fact that cannot be trusted. The
    /// default, and the only choice for a rule that is not a deny.
    #[default]
    Unknown,
    /// It counts towards the tree matching: `Match`, or `NoMatch` under an
    /// odd number of `not` nodes. A deny rule's `on_unparseable: match`.
    FavourMatch,
}

/// The result of evaluating a tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeEvaluation {
    /// The three-valued result.
    pub result: Tri,
    /// What the evaluated criteria noticed.
    pub notes: Notes,
}

impl TreeEvaluation {
    /// Whether the rule matches: only `Match` does. `Unknown` is no match
    /// for every action, so an allow rule does not allow and a deny rule
    /// does not block (see the module docs).
    #[must_use]
    pub fn matches(&self) -> bool {
        self.result == Tri::Match
    }
}

impl CompiledMatch {
    /// Compiles a tree. Validation compiles every rule's tree, so the tree
    /// of a validated policy always compiles.
    ///
    /// # Errors
    ///
    /// Returns every problem: the limits first, and if the tree is within
    /// them, each empty group and each criterion that does not compile.
    pub fn compile(tree: &Match) -> Result<Self, Vec<TreeError>> {
        let mut errors = Vec::new();
        if tree.depth() > MAX_TREE_DEPTH {
            errors.push(TreeError::TooDeep);
        }
        if leaf_count(tree) > MAX_CRITERIA_PER_RULE {
            errors.push(TreeError::TooManyCriteria);
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let mut out = Self {
            nodes: Vec::new(),
            children: Vec::new(),
            leaves: Vec::new(),
        };
        // The depth was checked, so this recursion is bounded.
        out.add(tree, String::new(), &mut errors);
        if errors.is_empty() {
            Ok(out)
        } else {
            Err(errors)
        }
    }

    /// Adds `node` and everything below it, and returns its index.
    fn add(&mut self, node: &Match, pointer: String, errors: &mut Vec<TreeError>) -> u32 {
        let entry = match node {
            Match::All(items) | Match::Any(items) => {
                let key = if matches!(node, Match::All(_)) {
                    "all"
                } else {
                    "any"
                };
                // An empty `all` at the root matches every object: the match
                // of a `catch_all` rule. Validation rejects it on any other
                // rule (#329); below the root it is always an error.
                let catch_all_root = pointer.is_empty() && matches!(node, Match::All(_));
                if items.is_empty() && !catch_all_root {
                    errors.push(TreeError::EmptyGroup {
                        pointer: format!("{pointer}/{key}"),
                    });
                }
                let ids: Vec<u32> = items
                    .iter()
                    .enumerate()
                    .map(|(i, child)| self.add(child, format!("{pointer}/{key}/{i}"), errors))
                    .collect();
                let start = index(self.children.len());
                let len = index(ids.len());
                self.children.extend(ids);
                if matches!(node, Match::All(_)) {
                    Node::All { start, len }
                } else {
                    Node::Any { start, len }
                }
            }
            Match::Not(child) => Node::Not(self.add(child, format!("{pointer}/not"), errors)),
            Match::Ref(_) => {
                errors.push(TreeError::UnresolvedRef {
                    pointer: format!("{pointer}/ref"),
                });
                Node::Leaf(u32::MAX)
            }
            Match::Criterion(c) => match CompiledCriterion::compile(c) {
                Ok(compiled) => {
                    self.leaves.push(compiled);
                    Node::Leaf(index(self.leaves.len() - 1))
                }
                Err(e) => {
                    errors.push(TreeError::Criterion {
                        pointer: format!("{pointer}/criterion"),
                        errors: e,
                    });
                    Node::Leaf(u32::MAX)
                }
            },
        };
        self.nodes.push(entry);
        index(self.nodes.len() - 1)
    }

    /// The compiled criteria, in document order.
    #[must_use]
    pub fn criteria(&self) -> &[CompiledCriterion] {
        &self.leaves
    }

    /// Evaluates the tree against one object's facts and the context.
    #[must_use]
    pub fn eval(&self, facts: &ObjectFacts, ctx: &EvalContext<'_>) -> TreeEvaluation {
        self.eval_with(facts, ctx, Unparseable::Unknown)
    }

    /// Evaluates the tree, reading criteria on unparseable versions as
    /// `unparseable` says. With [`Unparseable::Unknown`] this is
    /// [`eval`](Self::eval).
    #[must_use]
    pub fn eval_with(
        &self,
        facts: &ObjectFacts,
        ctx: &EvalContext<'_>,
        unparseable: Unparseable,
    ) -> TreeEvaluation {
        self.eval_full(facts, ctx, unparseable, false)
    }

    /// Evaluates the tree of a mandatory deny: as [`eval_with`](Self::eval_with),
    /// and each `safety_critical` criterion that is `Unknown` counts towards
    /// the deny applying (`Match`, or `NoMatch` under an odd number of `not`
    /// nodes), so the shipped blocklists fail closed (#32, #87).
    #[must_use]
    pub fn eval_mandatory(
        &self,
        facts: &ObjectFacts,
        ctx: &EvalContext<'_>,
        unparseable: Unparseable,
    ) -> TreeEvaluation {
        self.eval_full(facts, ctx, unparseable, true)
    }

    fn eval_full(
        &self,
        facts: &ObjectFacts,
        ctx: &EvalContext<'_>,
        unparseable: Unparseable,
        safety_critical: bool,
    ) -> TreeEvaluation {
        let mut eval = Eval {
            facts,
            ctx,
            unparseable,
            safety_critical,
            notes: Notes::default(),
        };
        let root = index(self.nodes.len() - 1);
        let result = self.eval_node(root, false, &mut eval);
        TreeEvaluation {
            result,
            notes: eval.notes,
        }
    }

    /// Evaluates one node. `negated` is whether an odd number of `not`
    /// nodes are above it.
    fn eval_node(&self, id: u32, negated: bool, eval: &mut Eval<'_, '_>) -> Tri {
        match self.nodes[id as usize] {
            Node::All { start, len } => {
                let mut result = Tri::Match;
                for &child in self.group(start, len) {
                    result = result.and(self.eval_node(child, negated, eval));
                    if result == Tri::NoMatch {
                        break;
                    }
                }
                result
            }
            Node::Any { start, len } => {
                let mut result = Tri::NoMatch;
                for &child in self.group(start, len) {
                    result = result.or(self.eval_node(child, negated, eval));
                    if result == Tri::Match {
                        break;
                    }
                }
                result
            }
            Node::Not(child) => self.eval_node(child, !negated, eval).not(),
            Node::Leaf(leaf) => {
                let criterion = &self.leaves[leaf as usize];
                let evaluation = criterion.eval_under(eval.facts, eval.ctx, negated);
                eval.notes.extend(evaluation.notes);
                if evaluation.result == Tri::Unknown
                    && eval.safety_critical
                    && criterion.safety_critical()
                {
                    // A safety-critical criterion of a mandatory deny fails
                    // closed: whatever made it unknown, it counts towards
                    // the deny applying.
                    Tri::from_bool(!negated)
                } else if evaluation.result == Tri::Unknown
                    && eval.unparseable == Unparseable::FavourMatch
                    && evaluation.notes.contains(Note::VersionUnparseable)
                {
                    // Each criterion tests one fact, so this `Unknown` comes
                    // from the unparseable version and nothing else.
                    Tri::from_bool(!negated)
                } else {
                    evaluation.result
                }
            }
        }
    }

    fn group(&self, start: u32, len: u32) -> &[u32] {
        &self.children[start as usize..(start + len) as usize]
    }
}

/// The inputs of one evaluation, and the notes gathered so far.
struct Eval<'f, 'c> {
    facts: &'f ObjectFacts,
    ctx: &'f EvalContext<'c>,
    unparseable: Unparseable,
    /// Whether `safety_critical` criteria fail closed: only in a mandatory
    /// deny.
    safety_critical: bool,
    notes: Notes,
}

/// The number of criteria in a tree, counted without recursion.
fn leaf_count(tree: &Match) -> usize {
    let mut count = 0usize;
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        if matches!(node, Match::Criterion(_)) {
            count += 1;
        }
        stack.extend(node.children());
    }
    count
}

/// An arena index. The limits keep every tree far below `u32::MAX` nodes.
fn index(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests;
