//! Computation tiers: which attribute groups [`super::identify`] computes.

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;

use serde::{Serialize, Serializer};

/// One computation tier. Each costs more than the one before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// T0: size, times and path forms, from the opened handle. No content
    /// is read.
    Stat,
    /// T1: PE headers, version resource, manifest, imports and exports.
    Classify,
    /// T2: flat hashes, Authenticode image hashes and page hashes.
    Hash,
    /// T3: embedded signatures, chains, timestamps, revocation and the
    /// catalog lookup. Needs T2's digests, so it computes them too.
    Trust,
    /// T4: owner, writability, streams, mark-of-the-web and path
    /// variables.
    Context,
    /// T5: installer tables, package manifests, script signatures and
    /// content tags (#44, #52, #53).
    Deep,
}

impl Tier {
    /// Every tier, cheapest first.
    pub const ALL: [Self; 6] = [
        Self::Stat,
        Self::Classify,
        Self::Hash,
        Self::Trust,
        Self::Context,
        Self::Deep,
    ];

    /// `t0` to `t5`.
    #[must_use]
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Stat => "t0",
            Self::Classify => "t1",
            Self::Hash => "t2",
            Self::Trust => "t3",
            Self::Context => "t4",
            Self::Deep => "t5",
        }
    }

    /// The serde name (`stat`, `classify` and so on).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stat => "stat",
            Self::Classify => "classify",
            Self::Hash => "hash",
            Self::Trust => "trust",
            Self::Context => "context",
            Self::Deep => "deep",
        }
    }

    const fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of [`Tier`]s.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Tiers(u8);

impl Tiers {
    /// No tier.
    pub const EMPTY: Self = Self(0);
    /// Every tier.
    pub const ALL: Self = Self(0b11_1111);
    /// T0 to T3: what the agent computes synchronously at execution time.
    pub const EXECUTION: Self = Self(0b00_1111);

    /// The set holding only `tier`.
    #[must_use]
    pub const fn only(tier: Tier) -> Self {
        Self(tier.bit())
    }

    /// Whether `tier` is in the set.
    #[must_use]
    pub const fn contains(self, tier: Tier) -> bool {
        self.0 & tier.bit() != 0
    }

    /// Adds `tier`.
    pub const fn insert(&mut self, tier: Tier) {
        self.0 |= tier.bit();
    }

    /// The union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The tiers in the set, cheapest first.
    pub fn iter(self) -> impl Iterator<Item = Tier> {
        Tier::ALL.into_iter().filter(move |t| self.contains(*t))
    }
}

impl From<Tier> for Tiers {
    fn from(tier: Tier) -> Self {
        Self::only(tier)
    }
}

impl FromIterator<Tier> for Tiers {
    fn from_iter<I: IntoIterator<Item = Tier>>(iter: I) -> Self {
        let mut set = Self::EMPTY;
        for t in iter {
            set.insert(t);
        }
        set
    }
}

impl fmt::Debug for Tiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl Serialize for Tiers {
    /// As a list of tier names, cheapest first.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

/// Why a tier list did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierParseError(pub String);

impl fmt::Display for TierParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown tier {:?}: use all, t0 to t5, a range such as t0..t3, or a tier name",
            self.0
        )
    }
}

impl std::error::Error for TierParseError {}

impl FromStr for Tier {
    type Err = TierParseError;

    /// `t0` to `t5`, or a tier name, in any case.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|t| t.short_name().eq_ignore_ascii_case(s) || t.name().eq_ignore_ascii_case(s))
            .ok_or_else(|| TierParseError(s.to_owned()))
    }
}

impl FromStr for Tiers {
    type Err = TierParseError;

    /// `all`, or a comma-separated list of tiers and inclusive ranges such
    /// as `t0..t3`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut set = Self::EMPTY;
        for part in s.split(',').map(str::trim) {
            if part.eq_ignore_ascii_case("all") {
                set = Self::ALL;
            } else if let Some((a, b)) = part.split_once("..") {
                let (a, b) = (a.parse::<Tier>()?, b.parse::<Tier>()?);
                if a > b {
                    return Err(TierParseError(part.to_owned()));
                }
                for t in Tier::ALL.into_iter().filter(|t| (a..=b).contains(t)) {
                    set.insert(t);
                }
            } else {
                set.insert(part.parse()?);
            }
        }
        if set.is_empty() {
            return Err(TierParseError(s.to_owned()));
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tiers() {
        assert_eq!("all".parse::<Tiers>(), Ok(Tiers::ALL));
        assert_eq!("t0..t3".parse::<Tiers>(), Ok(Tiers::EXECUTION));
        let set: Tiers = "t1, hash".parse().unwrap();
        assert_eq!(set.iter().collect::<Vec<_>>(), [Tier::Classify, Tier::Hash]);
        assert!("t3..t1".parse::<Tiers>().is_err());
        assert!("t9".parse::<Tiers>().is_err());
        assert!("".parse::<Tiers>().is_err());
        assert_eq!(
            Tiers::ALL.iter().count(),
            Tier::ALL.len(),
            "ALL holds every tier"
        );
    }

    #[test]
    fn serialises_as_names() {
        let json = serde_json::to_string(&Tiers::EXECUTION).unwrap();
        assert_eq!(json, r#"["stat","classify","hash","trust"]"#);
    }
}
