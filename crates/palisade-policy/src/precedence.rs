//! Precedence models: choosing one rule from the rules that match (#35,
//! ADR 0004).
//!
//! A policy names one [`PrecedenceModel`] and its [`PrecedenceOptions`].
//! The model only decides among the ordinary rules of stage 4 of the
//! pipeline in [`crate::evaluate`]: the rules that `allow`, `allow_contained`,
//! `allow_elevated` or `deny` outside a mandatory rule set. The mandatory
//! deny tier and exclusions are decided before it, under every model, and
//! the implicit deny after it.
//!
//! Each model is a [`Precedence`] implementation: a pure function from a
//! [`MatchSet`] to a [`Resolution`]. It reads nothing but the candidates'
//! metadata, so it is deterministic. Every key ends with the rule ID, which
//! is unique, so no two candidates ever compare equal, and the winner never
//! depends on the order of the match set. The rule-order models
//! (`first_match`, `priority`) depend on `order` and `priority` by design,
//! but not on where a rule or rule set sits in a list.
//!
//! # The models
//!
//! - **`deny_wins`** (the default): if any candidate denies, a deny decides;
//!   otherwise an allow does.
//! - **`allow_wins`**: if any candidate allows, an allow decides; otherwise
//!   a deny does. With `granularity_tiebreak`, the candidates of each rule
//!   set are first narrowed to that set's most specific ones, so a denied
//!   file inside an allowed folder of the same set stays denied. Validation
//!   warns that `allow_wins` is not recommended for Essential Eight.
//! - **`specificity`**: the candidate with the most specific identity
//!   ([`Spec`]) decides. Between equally specific candidates, a deny beats
//!   an allow unless `same_tier_tiebreak: allow`.
//! - **`first_match`**: candidates are sorted by `order`, lowest first. Ties
//!   go to the newer rule, which is the higher rule ID because rule IDs are
//!   UUIDv7, whose leading bits are the creation time; IDs created in the
//!   same millisecond fall back to the rest of the ID. With `curated_first`
//!   (the default), rules of read-only (curated) rule sets come before
//!   every custom rule. In an effective policy built from a hierarchy
//!   (#37), each rule set carries the band of the level that assigned it,
//!   and a lower band comes before everything else, so the levels are
//!   evaluated in their configured order. `defer`, `audit` and `trust_source` rules are never
//!   candidates, so a matching `defer` falls through to the next rule.
//! - **`priority`**: the lowest `priority` number decides
//!   (`priority_direction: higher_wins` reverses this). Between equal
//!   priorities: `deny`, then `allow_contained`, `allow`, `allow_elevated`
//!   with `condition: always`, and `allow_elevated` with `if_required`
//!   last.
//!
//! A rule the model needs a position or priority for, but that has none,
//! sorts after every rule that has one. Validation rejects such rules
//! (`order_required`, `priority_required`).
//!
//! # Ties between candidates of the same kind
//!
//! In `deny_wins`, `allow_wins` and `specificity`, several allows can
//! qualify. `allow_tiebreak` picks among them: `most_restrictive` (the
//! default) prefers `allow_contained`, then `allow`, then `allow_elevated`
//! with `always`, then with `if_required`; `most_permissive` is the
//! reverse. Several denies, or allows of the same kind, are then ranked by
//! specificity, and finally by the lowest rule ID, the oldest rule. That
//! decides which rule's directives and effects (notification, severity,
//! `kill_running`) the decision carries; every other candidate is listed as
//! overridden.

use core::cmp::Reverse;
use std::collections::BTreeMap;

use crate::decision::RuleRef;
use crate::facts::PathVariable;
use crate::model::{
    Action, ActionKind, AllowTiebreak, ElevationCondition, Field, Match, Operator, PrecedenceModel,
    PrecedenceOptions, PriorityDirection, RuleId, RuleSetId, TierTiebreak,
};

/// How specifically a rule identifies an object, for the `specificity`
/// model and for ranking equal candidates in the others. Declared from the
/// most specific to the least, so the smaller tier is the more specific.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// 1: a file hash (`hash.*`).
    Hash,
    /// 2: a signer with a file name and a version, tested together.
    SignerFileVersion,
    /// 3: a signer with a product name, tested together.
    SignerProduct,
    /// 4: a signer alone: its publisher or its certificate thumbprint.
    Signer,
    /// 5: one file by its full path (`path.full` with `equals`).
    PathFile,
    /// 6: a directory: `path.directory`, or `path.full` with
    /// `starts_with`, `wildcard` or `regex`. Deeper directories are more
    /// specific. `contains` and `ends_with` on a path fix no directory and
    /// are in tier 7.
    PathDirectory,
    /// 7: version-resource metadata, a file name, an extension or a
    /// certificate issuer (which names a whole certification authority),
    /// or no guaranteed identity at all.
    Metadata,
}

impl Tier {
    /// The tier's number, 1 to 7.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Hash => 1,
            Self::SignerFileVersion => 2,
            Self::SignerProduct => 3,
            Self::Signer => 4,
            Self::PathFile => 5,
            Self::PathDirectory => 6,
            Self::Metadata => 7,
        }
    }
}

/// A rule's specificity: its tier and, in tier 6, the depth of its
/// directory. Ordered from the most specific to the least: a lower tier
/// first, then a deeper directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    /// The tier.
    pub tier: Tier,
    /// The number of directory components below the root that the rule
    /// fixes, in tier 6. Zero in the other tiers.
    pub depth: u16,
}

impl Ord for Spec {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.tier, Reverse(self.depth)).cmp(&(other.tier, Reverse(other.depth)))
    }
}

impl PartialOrd for Spec {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Spec {
    /// The least specific value.
    pub const LEAST: Self = Self {
        tier: Tier::Metadata,
        depth: 0,
    };

    const fn tier(tier: Tier) -> Self {
        Self { tier, depth: 0 }
    }

    /// The specificity of a match tree, from its strongest identity that
    /// every match must satisfy, like the identity analysis of validation:
    ///
    /// - A positive criterion has the tier of its field. A negated one,
    ///   and a context criterion, identify nothing.
    /// - `all` takes its most specific child. Its criteria together can
    ///   also reach tier 2 (a signer, a file name and a version) or tier 3
    ///   (a signer and a product name), counting criteria in nested `all`
    ///   nodes too.
    /// - `any` takes its least specific child, because the object may
    ///   match through that one.
    /// - `not` identifies nothing.
    ///
    /// A tree that identifies nothing on some path is in tier 7, and so is
    /// a tree deeper than validation allows.
    #[must_use]
    pub fn of(tree: &Match) -> Self {
        // Validated trees are within the limit; a deeper tree built in code
        // is not walked recursively.
        if tree.depth() > crate::model::limits::MAX_TREE_DEPTH {
            return Self::LEAST;
        }
        spec_of(tree).unwrap_or(Self::LEAST)
    }
}

/// Which facts an `all` node's criteria fix, for tiers 2 and 3.
#[derive(Clone, Copy, Default)]
struct Features {
    signer: bool,
    file: bool,
    version: bool,
    product: bool,
}

impl Features {
    fn union(self, other: Self) -> Self {
        Self {
            signer: self.signer || other.signer,
            file: self.file || other.file,
            version: self.version || other.version,
            product: self.product || other.product,
        }
    }

    fn spec(self) -> Option<Spec> {
        if self.signer && self.file && self.version {
            Some(Spec::tier(Tier::SignerFileVersion))
        } else if self.signer && self.product {
            Some(Spec::tier(Tier::SignerProduct))
        } else {
            None
        }
    }
}

/// `None` when some path through the tree identifies nothing.
fn spec_of(node: &Match) -> Option<Spec> {
    match node {
        Match::Criterion(c) => criterion_spec(c),
        // A reference is resolved before evaluation; one left over
        // identifies nothing.
        Match::Not(_) | Match::Ref(_) => None,
        Match::Any(children) => {
            // The least specific child; `None` if any child identifies
            // nothing.
            let mut least: Option<Spec> = None;
            for child in children {
                let s = spec_of(child)?;
                least = Some(least.map_or(s, |l| l.max(s)));
            }
            least
        }
        Match::All(children) => {
            let most = children.iter().filter_map(spec_of).min();
            let combined = features(node).spec();
            match (most, combined) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        }
    }
}

/// The features of the criteria that an `all` node and the `all` nodes
/// nested directly in it fix.
fn features(node: &Match) -> Features {
    match node {
        Match::Criterion(c) if c.operator.is_positive() => {
            let f = c.field;
            Features {
                signer: matches!(f, Field::SignerPublisher | Field::SignerLeafThumbprint),
                file: matches!(
                    f,
                    Field::PathFileName | Field::MetaOriginalFilename | Field::MetaInternalName
                ),
                version: matches!(f, Field::MetaFileVersion | Field::MetaProductVersion),
                product: f == Field::MetaProductName,
            }
        }
        Match::All(children) => children
            .iter()
            .map(features)
            .fold(Features::default(), Features::union),
        Match::Criterion(_) | Match::Any(_) | Match::Not(_) | Match::Ref(_) => Features::default(),
    }
}

fn criterion_spec(c: &crate::model::Criterion) -> Option<Spec> {
    if !c.operator.is_positive() || c.field.is_context() {
        return None;
    }
    let tier = match c.field {
        Field::HashSha256
        | Field::HashSha384
        | Field::HashSha512
        | Field::HashAuthenticodeSha256
        | Field::HashAuthenticodeSha1
        | Field::HashPageSha256
        | Field::HashPageSha1
        | Field::HashMsiFuzzySha256
        | Field::HashSha1
        | Field::HashMd5 => Tier::Hash,
        Field::SignerPublisher | Field::SignerLeafThumbprint => Tier::Signer,
        Field::PathFull if c.operator == Operator::Equals => Tier::PathFile,
        Field::PathFull | Field::PathDirectory
            if matches!(
                c.operator,
                Operator::Equals | Operator::StartsWith | Operator::Wildcard | Operator::Regex
            ) =>
        {
            let depth = c
                .values
                .iter()
                .map(|v| path_depth(v, c.operator))
                .min()
                .unwrap_or(0);
            return Some(Spec {
                tier: Tier::PathDirectory,
                depth,
            });
        }
        _ => Tier::Metadata,
    };
    Some(Spec::tier(tier))
}

/// The number of fixed directory components below the root in a path
/// value, read the way matching reads it ([`crate::ops`]):
///
/// - A value without a path variable is normalised first
///   ([`palisade_core::path::normalize`]), so `.` and `..` components,
///   repeated separators and the `\??\` and `\\?\UNC\` prefixes count as
///   the path they stand for. A value that does not normalise to a drive or
///   UNC path fixes nothing.
/// - A leading path variable counts as the depth of its default location
///   (`%PROGRAMFILES%` is `C:\Program Files`, depth 1; `%TEMP%` is
///   `C:\Users\name\AppData\Local\Temp`, depth 5), plus the components after
///   it.
/// - With `wildcard`, counting stops at the first component with `*`, `?`
///   or `[`, and a wildcard in the root (a drive such as `*:\`, or a UNC
///   server or share such as `\\*\share` or `\\**\dir`) fixes nothing. With
///   `equals` and `starts_with` every character is literal.
/// - A regular expression fixes nothing.
/// - A stream name is not a directory component.
fn path_depth(value: &str, operator: Operator) -> u16 {
    let wildcard = match operator {
        Operator::Regex => return 0,
        Operator::Wildcard => true,
        _ => false,
    };
    let (base, path) = match variable_prefix(value) {
        Some((variable, rest)) => (
            variable_depth(variable),
            palisade_core::path::normalize(&format!("C:\\{rest}")),
        ),
        None => {
            let b = value.as_bytes();
            if wildcard && b.len() >= 2 && matches!(b[0], b'?' | b'*') && b[1] == b':' {
                return 0;
            }
            (0, palisade_core::path::normalize(value))
        }
    };
    // A wildcard in the root (`\\*\share`, `\\server\*`, `\\**\dir`)
    // matches many roots, so nothing below it is fixed.
    if !path.is_resolved() || (wildcard && path.root().contains(['*', '?', '['])) {
        return 0;
    }
    let below_root = path
        .without_stream()
        .get(path.root().len()..)
        .unwrap_or_default();
    let fixed = below_root
        .split('\\')
        .filter(|c| !c.is_empty())
        .take_while(|c| !wildcard || !c.contains(['*', '?', '[']))
        .count();
    base.saturating_add(u16::try_from(fixed).unwrap_or(u16::MAX))
}

/// A leading `%NAME%` that names a known path variable, and the text after
/// it.
fn variable_prefix(value: &str) -> Option<(PathVariable, &str)> {
    let (name, rest) = value.strip_prefix('%')?.split_once('%')?;
    Some((PathVariable::from_name(name)?, rest))
}

/// The depth of a path variable's default location below the root.
const fn variable_depth(variable: PathVariable) -> u16 {
    match variable {
        PathVariable::OsDrive => 0,
        PathVariable::Windir | PathVariable::ProgramFiles | PathVariable::ProgramData => 1,
        PathVariable::System32 | PathVariable::UserProfile | PathVariable::Public => 2,
        PathVariable::AppData | PathVariable::LocalAppData => 4,
        PathVariable::Temp => 5,
    }
}

/// The action of a stage-4 candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// `deny`.
    Deny,
    /// `allow_contained`.
    AllowContained,
    /// `allow`.
    Allow,
    /// `allow_elevated`, with its condition.
    AllowElevated(ElevationCondition),
}

impl Verdict {
    /// The verdict of an action, or `None` for an action that is not
    /// decided by the precedence model (`audit`, `trust_source`, `ignore`,
    /// `defer`).
    #[must_use]
    pub const fn of(action: &Action) -> Option<Self> {
        Some(match action {
            Action::Deny(_) => Self::Deny,
            Action::AllowContained(_) => Self::AllowContained,
            Action::Allow {} => Self::Allow,
            Action::AllowElevated(e) => Self::AllowElevated(e.condition),
            Action::Audit {} | Action::TrustSource(_) | Action::Ignore {} | Action::Defer {} => {
                return None;
            }
        })
    }

    /// The action kind.
    #[must_use]
    pub const fn kind(self) -> ActionKind {
        match self {
            Self::Deny => ActionKind::Deny,
            Self::AllowContained => ActionKind::AllowContained,
            Self::Allow => ActionKind::Allow,
            Self::AllowElevated(_) => ActionKind::AllowElevated,
        }
    }

    /// Whether the object runs.
    #[must_use]
    pub const fn allows(self) -> bool {
        !matches!(self, Self::Deny)
    }

    /// The rank of an allow under `allow_tiebreak`, lowest preferred. A
    /// deny ranks 0: it is never compared with allows here.
    const fn allow_rank(self, tiebreak: AllowTiebreak) -> u8 {
        let restrictive = match self {
            Self::Deny | Self::AllowContained => 0,
            Self::Allow => 1,
            Self::AllowElevated(ElevationCondition::Always) => 2,
            Self::AllowElevated(ElevationCondition::IfRequired) => 3,
        };
        match (tiebreak, self) {
            (AllowTiebreak::MostRestrictive, _) | (_, Self::Deny) => restrictive,
            (AllowTiebreak::MostPermissive, _) => 3 - restrictive,
        }
    }

    /// The fixed rank between equal priorities, lowest preferred.
    const fn priority_rank(self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::AllowContained => 1,
            Self::Allow => 2,
            Self::AllowElevated(ElevationCondition::Always) => 3,
            Self::AllowElevated(ElevationCondition::IfRequired) => 4,
        }
    }
}

/// One matching rule the model may choose, with the metadata it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The rule.
    pub rule: RuleRef,
    /// What it decides.
    pub verdict: Verdict,
    /// How specifically it identifies the object.
    pub spec: Spec,
    /// Its `order`, for `first_match`.
    pub order: Option<u32>,
    /// Its `priority`, for `priority`.
    pub priority: Option<i32>,
    /// Whether its rule set is curated (read-only), for `curated_first`.
    pub curated: bool,
    /// The hierarchy band of its rule set, for `first_match` (#37): a
    /// lower band comes first. 0 outside a hierarchy.
    pub band: u8,
}

impl Candidate {
    const fn id(&self) -> RuleId {
        self.rule.rule_id
    }

    const fn set(&self) -> RuleSetId {
        self.rule.rule_set_id
    }
}

/// The candidates of one evaluation, in any order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatchSet {
    /// The candidates.
    pub candidates: Vec<Candidate>,
}

/// What a model chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// The index of the deciding candidate in the match set, or `None` if
    /// the set is empty. Every other candidate is overridden.
    pub winner: Option<usize>,
}

/// A precedence model. `resolve` must be a pure function of the match set's
/// candidates, and its winner must not depend on their order.
pub trait Precedence {
    /// Chooses the deciding candidate.
    fn resolve(&self, matches: &MatchSet) -> Resolution;
}

/// The index of the candidate with the smallest key, among those `keep`
/// accepts. Keys end with the unique rule ID, so the result does not depend
/// on the order of the candidates.
fn best<K: Ord>(
    matches: &MatchSet,
    keep: impl Fn(&Candidate) -> bool,
    key: impl Fn(&Candidate) -> K,
) -> Option<usize> {
    matches
        .candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| keep(c))
        .min_by_key(|(_, c)| key(c))
        .map(|(i, _)| i)
}

/// `deny_wins`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenyWins {
    /// Which allow decides among allows.
    pub allow_tiebreak: AllowTiebreak,
}

impl Precedence for DenyWins {
    fn resolve(&self, matches: &MatchSet) -> Resolution {
        let tiebreak = self.allow_tiebreak;
        let winner = best(matches, |c| !c.verdict.allows(), |c| (c.spec, c.id())).or_else(|| {
            best(
                matches,
                |c| c.verdict.allows(),
                |c| (c.verdict.allow_rank(tiebreak), c.spec, c.id()),
            )
        });
        Resolution { winner }
    }
}

/// `allow_wins`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowWins {
    /// Which allow decides among allows.
    pub allow_tiebreak: AllowTiebreak,
    /// Narrow each rule set's candidates to its most specific ones first.
    pub granularity_tiebreak: bool,
}

impl AllowWins {
    /// The most specific candidate of each rule set, with
    /// `granularity_tiebreak`. Candidates less specific than their set's
    /// are left out.
    fn most_specific_per_set(&self, matches: &MatchSet) -> Option<BTreeMap<RuleSetId, Spec>> {
        if !self.granularity_tiebreak {
            return None;
        }
        let mut most: BTreeMap<RuleSetId, Spec> = BTreeMap::new();
        for c in &matches.candidates {
            most.entry(c.set())
                .and_modify(|s| *s = (*s).min(c.spec))
                .or_insert(c.spec);
        }
        Some(most)
    }
}

impl Precedence for AllowWins {
    fn resolve(&self, matches: &MatchSet) -> Resolution {
        let tiebreak = self.allow_tiebreak;
        let most = self.most_specific_per_set(matches);
        let survives = |c: &Candidate| {
            most.as_ref()
                .is_none_or(|m| m.get(&c.set()).is_none_or(|s| *s == c.spec))
        };
        let winner = best(
            matches,
            |c| c.verdict.allows() && survives(c),
            |c| (c.verdict.allow_rank(tiebreak), c.spec, c.id()),
        )
        .or_else(|| {
            best(
                matches,
                |c| !c.verdict.allows() && survives(c),
                |c| (c.spec, c.id()),
            )
        });
        Resolution { winner }
    }
}

/// `specificity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Specificity {
    /// Which allow decides among equally specific allows.
    pub allow_tiebreak: AllowTiebreak,
    /// Which action wins between equally specific candidates.
    pub same_tier_tiebreak: TierTiebreak,
}

impl Precedence for Specificity {
    fn resolve(&self, matches: &MatchSet) -> Resolution {
        let winner = best(
            matches,
            |_| true,
            |c| {
                let side = match (self.same_tier_tiebreak, c.verdict.allows()) {
                    (TierTiebreak::Deny, false) | (TierTiebreak::Allow, true) => 0u8,
                    _ => 1,
                };
                (
                    c.spec,
                    side,
                    c.verdict.allow_rank(self.allow_tiebreak),
                    c.id(),
                )
            },
        );
        Resolution { winner }
    }
}

/// `first_match`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirstMatch {
    /// Curated rules come before custom ones.
    pub curated_first: bool,
}

impl Precedence for FirstMatch {
    fn resolve(&self, matches: &MatchSet) -> Resolution {
        let winner = best(
            matches,
            |_| true,
            |c| {
                (
                    c.band,
                    self.curated_first && !c.curated,
                    c.order.is_none(),
                    c.order,
                    // The newer rule first.
                    Reverse(c.id()),
                )
            },
        );
        Resolution { winner }
    }
}

/// `priority`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    /// Which number wins.
    pub direction: PriorityDirection,
}

impl Precedence for Priority {
    fn resolve(&self, matches: &MatchSet) -> Resolution {
        let winner = best(
            matches,
            |_| true,
            |c| {
                let key = c.priority.map(|p| match self.direction {
                    PriorityDirection::LowerWins => i64::from(p),
                    PriorityDirection::HigherWins => -i64::from(p),
                });
                (key.is_none(), key, c.verdict.priority_rank(), c.id())
            },
        );
        Resolution { winner }
    }
}

/// The model a policy selects, with its options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolver {
    /// `deny_wins`.
    DenyWins(DenyWins),
    /// `allow_wins`.
    AllowWins(AllowWins),
    /// `specificity`.
    Specificity(Specificity),
    /// `first_match`.
    FirstMatch(FirstMatch),
    /// `priority`.
    Priority(Priority),
}

impl Resolver {
    /// The resolver for a model and its options. Options the model does not
    /// use are ignored.
    #[must_use]
    pub const fn new(model: PrecedenceModel, o: &PrecedenceOptions) -> Self {
        match model {
            PrecedenceModel::DenyWins => Self::DenyWins(DenyWins {
                allow_tiebreak: o.allow_tiebreak,
            }),
            PrecedenceModel::AllowWins => Self::AllowWins(AllowWins {
                allow_tiebreak: o.allow_tiebreak,
                granularity_tiebreak: o.granularity_tiebreak,
            }),
            PrecedenceModel::Specificity => Self::Specificity(Specificity {
                allow_tiebreak: o.allow_tiebreak,
                same_tier_tiebreak: o.same_tier_tiebreak,
            }),
            PrecedenceModel::FirstMatch => Self::FirstMatch(FirstMatch {
                curated_first: o.curated_first,
            }),
            PrecedenceModel::Priority => Self::Priority(Priority {
                direction: o.priority_direction,
            }),
        }
    }
}

impl Precedence for Resolver {
    fn resolve(&self, matches: &MatchSet) -> Resolution {
        match self {
            Self::DenyWins(m) => m.resolve(matches),
            Self::AllowWins(m) => m.resolve(matches),
            Self::Specificity(m) => m.resolve(matches),
            Self::FirstMatch(m) => m.resolve(matches),
            Self::Priority(m) => m.resolve(matches),
        }
    }
}

/// The candidate with the most specific identity, then the lowest rule ID:
/// how the pipeline picks among several mandatory denies, or several
/// exclusions, where every candidate has the same verdict.
pub(crate) fn most_specific(matches: &MatchSet) -> Option<usize> {
    best(matches, |_| true, |c| (c.spec, c.id()))
}

#[cfg(test)]
mod tests;
