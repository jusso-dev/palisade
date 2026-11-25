//! Which facts an evaluation needs: the lazy fact demand protocol (#42).
//!
//! Facts cost very different amounts to compute. The path, the process,
//! the user and the file ID are known when an event arrives. A hash needs
//! the whole file read, a signature needs a chain built, and an ACL check
//! needs every directory above the file examined. The engine therefore
//! never asks for an expensive fact unless a rule that could still decide
//! needs it.
//!
//! A [`FactSet`] names classes of facts. The agent says which classes it
//! has computed ([`FactSet::CHEAP`] is always taken as computed), and the
//! engine either decides or answers `NeedFacts` with the classes it needs
//! next ([`crate::engine::Engine::evaluate`]). It asks for them in a fixed
//! order, one round at a time ([`FactSet::ROUNDS`]):
//!
//! 1. the hashes ([`FactSet::HASHES`]),
//! 2. the signatures and the version resource ([`FactSet::SIGNERS`],
//!    [`FactSet::METADATA`]),
//! 3. the path ACL ([`FactSet::PATH_ACL`]).
//!
//! So a decision takes at most three extra rounds. Within a computed class,
//! a fact that is absent is unknown, as always ([`crate::facts`]).

use crate::model::{Field, FieldClass};

/// A set of fact classes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FactSet(u32);

/// The hash fields, in the order of their bits in a [`FactSet`].
const HASH_FIELDS: [Field; 10] = [
    Field::HashSha256,
    Field::HashSha384,
    Field::HashSha512,
    Field::HashAuthenticodeSha256,
    Field::HashAuthenticodeSha1,
    Field::HashPageSha256,
    Field::HashPageSha1,
    Field::HashMsiFuzzySha256,
    Field::HashSha1,
    Field::HashMd5,
];

const HASH_SHIFT: u32 = 2;

impl FactSet {
    /// No class.
    pub const EMPTY: Self = Self(0);
    /// The object's normalised path (`path.*` criteria), without its ACL.
    pub const PATH: Self = Self(1);
    /// The user, device and session (`user.*`, `device.*`, `session.*`).
    pub const CONTEXT: Self = Self(1 << 1);
    /// Every hash field, one class each.
    pub const HASHES: Self = Self(((1 << HASH_FIELDS.len()) - 1) << HASH_SHIFT);
    /// The signatures and their signers (`signer.*` criteria).
    pub const SIGNERS: Self = Self(1 << 12);
    /// The version resource strings (`meta.*` criteria).
    pub const METADATA: Self = Self(1 << 13);
    /// Whether users can write the file or a directory above it
    /// ([`PathFact::user_writable`](crate::facts::PathFact::user_writable)).
    /// Rules that let an object run, trust it or exclude it need it for
    /// every path criterion.
    pub const PATH_ACL: Self = Self(1 << 14);
    /// What the agent knows when an event arrives. Always taken as
    /// computed.
    pub const CHEAP: Self = Self(Self::PATH.0 | Self::CONTEXT.0);
    /// Every class.
    pub const ALL: Self = Self(
        Self::CHEAP.0 | Self::HASHES.0 | Self::SIGNERS.0 | Self::METADATA.0 | Self::PATH_ACL.0,
    );
    /// The rounds of the protocol, in the order the engine asks for them.
    pub const ROUNDS: [Self; 3] = [
        Self::HASHES,
        Self(Self::SIGNERS.0 | Self::METADATA.0),
        Self::PATH_ACL,
    ];

    /// The set with exactly the classes of `bits`; bits that name no class
    /// are dropped.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// The classes as bits, for compact storage.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Each class of the set on its own.
    pub fn classes(self) -> impl Iterator<Item = Self> {
        (0..32)
            .map(|b| Self(1 << b))
            .filter(move |c| self.contains(*c) && !c.is_empty())
    }

    /// The class of one hash field. Fields that are not hashes have no
    /// class of their own: see [`Self::of_field`].
    #[must_use]
    pub fn hash(field: Field) -> Self {
        HASH_FIELDS
            .iter()
            .position(|f| *f == field)
            .map_or(Self::EMPTY, |i| Self(1 << (HASH_SHIFT as usize + i)))
    }

    /// The class a criterion on `field` reads. The leaf thumbprint is a
    /// signer fact, not a hash of the file.
    #[must_use]
    pub fn of_field(field: Field) -> Self {
        if field.is_context() {
            return Self::CONTEXT;
        }
        match field {
            Field::SignerPublisher | Field::SignerIssuer | Field::SignerLeafThumbprint => {
                Self::SIGNERS
            }
            _ => match field.class() {
                FieldClass::Hash { .. } => Self::hash(field),
                FieldClass::Path | FieldClass::FileName => Self::PATH,
                _ => Self::METADATA,
            },
        }
    }

    /// Both sets together.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The classes in both sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The classes of `self` that are not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether every class of `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether the sets share a class.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The hash fields in the set, in a fixed order.
    pub fn hash_fields(self) -> impl Iterator<Item = Field> {
        HASH_FIELDS
            .into_iter()
            .filter(move |f| self.contains(Self::hash(*f)))
    }

    /// The part of the set in the earliest round that it touches: what the
    /// engine asks for next. Classes outside every round (the cheap ones)
    /// are kept as they are.
    #[must_use]
    pub fn first_round(self) -> Self {
        Self::ROUNDS
            .into_iter()
            .map(|round| self.intersection(round))
            .find(|part| !part.is_empty())
            .unwrap_or(self)
    }

    /// The number of the round, from 1, in which the engine asks for a
    /// class of `self`, or 0 for the cheap classes.
    #[must_use]
    pub fn round(self) -> usize {
        Self::ROUNDS
            .iter()
            .position(|round| self.intersects(*round))
            .map_or(0, |i| i + 1)
    }
}

impl core::ops::BitOr for FactSet {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for FactSet {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_field_has_one_class() {
        for field in Field::ALL {
            let class = FactSet::of_field(field);
            assert!(!class.is_empty(), "{field:?}");
            assert!(FactSet::ALL.contains(class), "{field:?}");
            let rounds = FactSet::ROUNDS
                .iter()
                .filter(|r| r.intersects(class))
                .count();
            assert!(rounds <= 1, "{field:?} is in {rounds} rounds");
        }
    }

    #[test]
    fn hash_classes_are_distinct() {
        let mut seen = FactSet::EMPTY;
        for field in HASH_FIELDS {
            let class = FactSet::hash(field);
            assert!(!seen.intersects(class), "{field:?}");
            seen |= class;
        }
        assert_eq!(seen, FactSet::HASHES);
        assert_eq!(seen.hash_fields().collect::<Vec<_>>(), HASH_FIELDS);
        assert_eq!(FactSet::hash(Field::PathFull), FactSet::EMPTY);
        assert_eq!(
            FactSet::of_field(Field::SignerLeafThumbprint),
            FactSet::SIGNERS
        );
    }

    #[test]
    fn rounds_are_disjoint_and_cover_the_expensive_classes() {
        let mut all = FactSet::CHEAP;
        for (i, round) in FactSet::ROUNDS.iter().enumerate() {
            assert!(!all.intersects(*round));
            assert_eq!(round.round(), i + 1);
            all |= *round;
        }
        assert_eq!(all, FactSet::ALL);
        assert_eq!(FactSet::CHEAP.round(), 0);
    }

    #[test]
    fn first_round_takes_the_earliest_part() {
        let want = FactSet::PATH_ACL | FactSet::SIGNERS | FactSet::hash(Field::HashSha256);
        assert_eq!(want.first_round(), FactSet::hash(Field::HashSha256));
        assert_eq!(
            (FactSet::PATH_ACL | FactSet::METADATA).first_round(),
            FactSet::METADATA
        );
        assert_eq!(FactSet::PATH_ACL.first_round(), FactSet::PATH_ACL);
        assert_eq!(FactSet::EMPTY.first_round(), FactSet::EMPTY);
    }

    #[test]
    fn set_operations() {
        let a = FactSet::PATH | FactSet::SIGNERS;
        assert!(a.contains(FactSet::PATH));
        assert!(!a.contains(FactSet::CHEAP));
        assert_eq!(a.difference(FactSet::PATH), FactSet::SIGNERS);
        assert_eq!(a.intersection(FactSet::CHEAP), FactSet::PATH);
        assert!(FactSet::EMPTY.is_empty());
    }
}
