//! What a rule's tree guarantees about the object, for the policy
//! assistant (#40). Conservative in the same way as validation (#31):
//! `all` guarantees the strongest of its children, `any` only the weakest,
//! and `not` nothing.

use crate::model::{Criterion, Field, FieldClass, Match, Operator, Strength};

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

/// The weakest identity every path through `tree` checks.
#[must_use]
pub fn weakest_identity(tree: &Match) -> Guaranteed {
    match tree {
        Match::All(children) => children
            .iter()
            .map(weakest_identity)
            .max()
            .unwrap_or(Guaranteed::None),
        Match::Any(children) => children
            .iter()
            .map(weakest_identity)
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

/// Every positive criterion on `field` that every match must satisfy: the
/// criteria directly under the root or under nested `all` nodes.
pub(crate) fn required<'a>(tree: &'a Match, field: Field, out: &mut Vec<&'a Criterion>) {
    match tree {
        Match::All(children) => {
            for c in children {
                required(c, field, out);
            }
        }
        Match::Criterion(c) if c.field == field && c.operator.is_positive() => out.push(c),
        Match::Any(children) if children.len() == 1 => required(&children[0], field, out),
        _ => {}
    }
}

/// One criterion that every match of `tree` must satisfy, if there is
/// one: the first under the root or nested `all` nodes. Used only to file
/// a rule in an index, so which one does not matter.
pub(crate) fn first_required(tree: &Match) -> Option<&Criterion> {
    match tree {
        Match::Criterion(c) => Some(c),
        Match::All(children) => children.iter().find_map(first_required),
        Match::Any(children) if children.len() == 1 => first_required(&children[0]),
        Match::Any(_) | Match::Not(_) | Match::Ref(_) => None,
    }
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

/// Whether `tree` is a positive path test that every match must satisfy,
/// on `path.full` or `path.directory`.
pub(crate) fn required_paths(tree: &Match) -> Vec<&Criterion> {
    let mut out = Vec::new();
    required(tree, Field::PathFull, &mut out);
    required(tree, Field::PathDirectory, &mut out);
    out.retain(|c| {
        matches!(
            c.operator,
            Operator::Equals | Operator::StartsWith | Operator::Wildcard | Operator::Regex
        )
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!has_path_identity(&Match::All(vec![dir, publisher])));
    }
}
