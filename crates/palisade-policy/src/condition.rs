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
//! `Match` does. `Unknown` counts as no match for every action, which fails
//! closed for allow rules, and is the documented default for deny rules
//! (#32). The per-rule `unknown_as` option and the mandatory-deny defaults
//! are part of precedence (#35).

use crate::facts::ObjectFacts;
use crate::model::Match;
use crate::model::limits::{MAX_CRITERIA_PER_RULE, MAX_TREE_DEPTH};
use crate::ops::{CompileError, CompiledCriterion, EvalContext, Notes, Tri};

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
    /// A criterion did not compile. `pointer` is relative to the tree's
    /// root, such as `/all/0/criterion`.
    Criterion {
        /// Where the criterion is, relative to the root.
        pointer: String,
        /// What is wrong with it.
        errors: Vec<CompileError>,
    },
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
    /// Whether the rule matches: only `Match` does, so `Unknown` fails
    /// closed.
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
                if items.is_empty() {
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
        let mut notes = Notes::default();
        let root = index(self.nodes.len() - 1);
        let result = self.eval_node(root, facts, ctx, &mut notes);
        TreeEvaluation { result, notes }
    }

    fn eval_node(
        &self,
        id: u32,
        facts: &ObjectFacts,
        ctx: &EvalContext<'_>,
        notes: &mut Notes,
    ) -> Tri {
        match self.nodes[id as usize] {
            Node::All { start, len } => {
                let mut result = Tri::Match;
                for &child in self.group(start, len) {
                    result = result.and(self.eval_node(child, facts, ctx, notes));
                    if result == Tri::NoMatch {
                        break;
                    }
                }
                result
            }
            Node::Any { start, len } => {
                let mut result = Tri::NoMatch;
                for &child in self.group(start, len) {
                    result = result.or(self.eval_node(child, facts, ctx, notes));
                    if result == Tri::Match {
                        break;
                    }
                }
                result
            }
            Node::Not(child) => self.eval_node(child, facts, ctx, notes).not(),
            Node::Leaf(leaf) => {
                let evaluation = self.leaves[leaf as usize].eval(facts, ctx);
                notes.extend(evaluation.notes);
                evaluation.result
            }
        }
    }

    fn group(&self, start: u32, len: u32) -> &[u32] {
        &self.children[start as usize..(start + len) as usize]
    }
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
