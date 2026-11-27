//! What a rule's tree guarantees about the object, for the policy
//! assistant (#40). Conservative in the same way as validation (#31):
//! `all` guarantees the strongest of its children, `any` only the weakest,
//! and `not` nothing.

use crate::model::{Criterion, Field, FieldClass, Match, Strength};

/// The weakest identity every path through a tree checks, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Guaranteed {
    /// Some path checks no positive identity.
    None,
    /// Some path checks only SHA-1 or MD5.
    WeakHash,
    /// Some path checks only weak identities: file names, extensions or
    /// version-resource strings.
    Weak,
    /// Every path checks a path identity at best (a medium identity whose
    /// trust depends on the path's ACL).
    Path,
    /// Every path checks a publisher at best.
    Publisher,
    /// Every path checks a strong hash or a certificate thumbprint.
    Strong,
}

impl Guaranteed {
    /// Whether this is weak for an allow: no identity, a weak hash, or a
    /// weak identity.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(self, Self::None | Self::WeakHash | Self::Weak)
    }
}

fn of_criterion(c: &Criterion) -> Guaranteed {
    if !c.operator.is_positive() {
        return Guaranteed::None;
    }
    match c.field.strength() {
        None => Guaranteed::None,
        Some(_) if c.field.is_weak_hash() => Guaranteed::WeakHash,
        Some(Strength::Weak) => Guaranteed::Weak,
        Some(Strength::Strong) => Guaranteed::Strong,
        Some(Strength::Medium) => match c.field.class() {
            FieldClass::Path => Guaranteed::Path,
            _ => Guaranteed::Publisher,
        },
    }
}

/// The weakest identity every path through `tree` checks. A tree deeper
/// than validation allows guarantees nothing, and is not walked.
#[must_use]
pub fn weakest_identity(tree: &Match) -> Guaranteed {
    if tree.depth() > crate::model::limits::MAX_TREE_DEPTH {
        return Guaranteed::None;
    }
    weakest(tree)
}

fn weakest(tree: &Match) -> Guaranteed {
    match tree {
        Match::All(children) => children
            .iter()
            .map(weakest)
            .max()
            .unwrap_or(Guaranteed::None),
        Match::Any(children) => children
            .iter()
            .map(weakest)
            .min()
            .unwrap_or(Guaranteed::None),
        // An unresolved library reference says nothing about the object.
        Match::Not(_) | Match::Ref(_) => Guaranteed::None,
        Match::Criterion(c) => of_criterion(c),
    }
}

/// Whether some path through `tree` relies on a path for its identity: its
/// strongest identity is a path. Such an allow is only as safe as the
/// path's ACL (#31).
#[must_use]
pub fn has_path_identity(tree: &Match) -> bool {
    weakest_identity(tree) == Guaranteed::Path
}

/// How selective a criterion is as an index key: lower is more selective.
fn selectivity(c: &Criterion) -> u8 {
    match c.field.class() {
        FieldClass::Hash { .. } => 0,
        _ if c.field == Field::SignerLeafThumbprint => 0,
        _ if c.field == Field::SignerPublisher => 1,
        FieldClass::Path | FieldClass::FileName => 2,
        FieldClass::Text | FieldClass::Version => 3,
        _ => 4,
    }
}

/// Every criterion that every match of `tree` must satisfy: under the
/// root, nested `all` nodes, or an `any` with one child.
pub(crate) fn required_all(tree: &Match) -> Vec<&Criterion> {
    let mut out: Vec<&Criterion> = Vec::new();
    if tree.depth() > crate::model::limits::MAX_TREE_DEPTH {
        return out;
    }
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        match node {
            Match::Criterion(c) => out.push(c),
            Match::All(children) => stack.extend(children),
            Match::Any(children) if children.len() == 1 => stack.push(&children[0]),
            Match::Any(_) | Match::Not(_) | Match::Ref(_) => {}
        }
    }
    out
}

/// The most selective criterion that every match of `tree` must satisfy,
/// if there is one: under the root or nested `all` nodes. Used only to
/// file a rule in an index.
pub(crate) fn best_required(tree: &Match) -> Option<&Criterion> {
    let mut out: Vec<&Criterion> = Vec::new();
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        match node {
            Match::Criterion(c) => out.push(c),
            Match::All(children) => stack.extend(children),
            Match::Any(children) if children.len() == 1 => stack.push(&children[0]),
            Match::Any(_) | Match::Not(_) | Match::Ref(_) => {}
        }
    }
    out.into_iter()
        .min_by_key(|c| (selectivity(c), c.values.len()))
}

/// The most branches [`branches`] expands a tree into.
pub(crate) const MAX_BRANCHES: usize = 256;

/// The tree in disjunctive form: one list per way it can match, holding
/// the criteria that way requires to match positively. A criterion with a
/// negative operator, and anything under `not`, only narrows a match and
/// never identifies an object, so it is left out. `None` if there would be
/// more than [`MAX_BRANCHES`] branches, or the tree is too deep.
pub(crate) fn branches(tree: &Match) -> Option<Vec<Vec<&Criterion>>> {
    if tree.depth() > crate::model::limits::MAX_TREE_DEPTH {
        return None;
    }
    dnf(tree)
}

fn dnf(tree: &Match) -> Option<Vec<Vec<&Criterion>>> {
    Some(match tree {
        Match::Criterion(c) if c.operator.is_positive() => vec![vec![c]],
        Match::Criterion(_) | Match::Not(_) | Match::Ref(_) => vec![Vec::new()],
        Match::Any(children) => {
            let mut out = Vec::new();
            for c in children {
                out.extend(dnf(c)?);
                if out.len() > MAX_BRANCHES {
                    return None;
                }
            }
            out
        }
        Match::All(children) => {
            let mut out: Vec<Vec<&Criterion>> = vec![Vec::new()];
            for c in children {
                let parts = dnf(c)?;
                if out.len().saturating_mul(parts.len()) > MAX_BRANCHES {
                    return None;
                }
                out = out
                    .iter()
                    .flat_map(|a| {
                        parts.iter().map(move |b| {
                            let mut v = a.clone();
                            v.extend(b.iter().copied());
                            v
                        })
                    })
                    .collect();
            }
            out
        }
    })
}

/// Every criterion in `tree` with whether a match of it counts towards
/// the tree matching (`true`) or against it (`false`): its operator's
/// polarity, flipped under each `not`.
pub(crate) fn literals(tree: &Match) -> Vec<(&Criterion, bool)> {
    let mut out = Vec::new();
    let mut stack = vec![(tree, true)];
    while let Some((node, positive)) = stack.pop() {
        match node {
            Match::All(c) | Match::Any(c) => stack.extend(c.iter().rev().map(|m| (m, positive))),
            Match::Not(c) => stack.push((c, !positive)),
            Match::Ref(_) => {}
            Match::Criterion(c) => out.push((c, positive == c.operator.is_positive())),
        }
    }
    out
}

/// Every criterion in `tree`, in document order.
pub(crate) fn criteria(tree: &Match) -> Vec<&Criterion> {
    let mut out = Vec::new();
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        match node {
            Match::All(c) | Match::Any(c) => stack.extend(c.iter().rev()),
            Match::Not(c) => stack.push(c),
            Match::Ref(_) => {}
            Match::Criterion(c) => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Operator;

    fn crit(field: Field, operator: Operator) -> Match {
        Match::Criterion(Criterion::new(field, operator, ["x"]))
    }

    #[test]
    fn all_takes_the_strongest_and_any_the_weakest() {
        let hash = crit(Field::HashSha256, Operator::Equals);
        let name = crit(Field::PathFileName, Operator::Equals);
        let dir = crit(Field::PathDirectory, Operator::StartsWith);
        let publisher = crit(Field::SignerPublisher, Operator::Equals);
        assert_eq!(
            weakest_identity(&Match::All(vec![hash.clone(), name.clone()])),
            Guaranteed::Strong
        );
        assert_eq!(
            weakest_identity(&Match::Any(vec![hash.clone(), name.clone()])),
            Guaranteed::Weak
        );
        assert_eq!(weakest_identity(&dir), Guaranteed::Path);
        assert_eq!(weakest_identity(&publisher), Guaranteed::Publisher);
        assert_eq!(
            weakest_identity(&Match::Not(Box::new(hash))),
            Guaranteed::None
        );
        assert_eq!(
            weakest_identity(&crit(Field::HashSha1, Operator::Equals)),
            Guaranteed::WeakHash
        );
        assert!(has_path_identity(&dir));
        assert!(!has_path_identity(&Match::All(vec![
            dir.clone(),
            publisher.clone()
        ])));
    }

    #[test]
    fn branches_and_literals_track_any_and_not() {
        let p = crit(Field::SignerPublisher, Operator::Equals);
        let h = crit(Field::HashSha256, Operator::Equals);
        let n = crit(Field::PathFileName, Operator::Equals);
        let tree = Match::All(vec![
            Match::Any(vec![p.clone(), h.clone()]),
            Match::Not(Box::new(n.clone())),
        ]);
        let b = branches(&tree).unwrap();
        assert_eq!(b.len(), 2);
        assert!(b.iter().all(|br| br.len() == 1));
        let found = literals(&tree);
        assert_eq!(found.iter().filter(|(_, pos)| *pos).count(), 2);
        assert!(
            found
                .iter()
                .any(|(c, pos)| c.field == Field::PathFileName && !pos)
        );
        let double = Match::Not(Box::new(crit(Field::PathFileName, Operator::NotEquals)));
        assert!(literals(&double)[0].1);
        // Too many branches.
        let wide = Match::All(
            (0..9)
                .map(|_| Match::Any(vec![p.clone(), h.clone()]))
                .collect(),
        );
        assert!(branches(&wide).is_none());
    }
}
