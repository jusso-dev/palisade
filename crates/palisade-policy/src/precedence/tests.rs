//! Tests of the precedence models (#35).
//!
//! Unit tests pin each model's documented choice, and property tests check
//! that every model is deterministic and never depends on the order of the
//! match set, and that `deny_wins` always lets a deny decide.

use proptest::prelude::*;

use super::*;
use crate::decision::RuleRef;
use crate::model::{Criterion, PolicyId};
use palisade_core::Uuid7;

/// A UUIDv7 whose time is `n`, so a larger `n` is a newer rule.
fn uuid(n: u64) -> Uuid7 {
    let mut b = [0u8; 16];
    b[..6].copy_from_slice(&n.to_be_bytes()[2..]);
    b[6] = 0x70;
    b[8] = 0x80;
    Uuid7::from_bytes(b).unwrap()
}

fn candidate(n: u64, set: u64, verdict: Verdict, tier: Tier) -> Candidate {
    Candidate {
        rule: RuleRef {
            rule_id: RuleId(uuid(n)),
            display_id: None,
            rule_set_id: RuleSetId(uuid(1_000 + set)),
            policy_id: PolicyId(uuid(9_999)),
            policy_revision: 1,
        },
        verdict,
        spec: Spec { tier, depth: 0 },
        order: None,
        priority: None,
        curated: false,
        band: 0,
    }
}

fn set(candidates: &[Candidate]) -> MatchSet {
    MatchSet {
        candidates: candidates.to_vec(),
    }
}

/// The rule number of the winner.
fn winner(model: &impl Precedence, candidates: &[Candidate]) -> Option<RuleId> {
    let m = set(candidates);
    model
        .resolve(&m)
        .winner
        .map(|i| m.candidates[i].rule.rule_id)
}

fn id(n: u64) -> Option<RuleId> {
    Some(RuleId(uuid(n)))
}

const ALWAYS: Verdict = Verdict::AllowElevated(ElevationCondition::Always);
const IF_REQUIRED: Verdict = Verdict::AllowElevated(ElevationCondition::IfRequired);

fn resolver(model: PrecedenceModel) -> Resolver {
    Resolver::new(model, &PrecedenceOptions::default())
}

#[test]
fn an_empty_match_set_has_no_winner() {
    for model in [
        PrecedenceModel::DenyWins,
        PrecedenceModel::AllowWins,
        PrecedenceModel::Specificity,
        PrecedenceModel::FirstMatch,
        PrecedenceModel::Priority,
    ] {
        assert_eq!(resolver(model).resolve(&MatchSet::default()).winner, None);
    }
}

#[test]
fn deny_wins_prefers_any_deny_then_the_most_restrictive_allow() {
    let m = resolver(PrecedenceModel::DenyWins);
    let hash_allow = candidate(1, 0, Verdict::Allow, Tier::Hash);
    let folder_deny = candidate(2, 0, Verdict::Deny, Tier::PathDirectory);
    assert_eq!(winner(&m, &[hash_allow, folder_deny]), id(2));
    // Among allows: allow_contained, allow, allow_elevated (always), then
    // if_required, whatever their specificity.
    let allows = [
        candidate(3, 0, IF_REQUIRED, Tier::Hash),
        candidate(4, 0, ALWAYS, Tier::Hash),
        candidate(5, 0, Verdict::Allow, Tier::Hash),
        candidate(6, 0, Verdict::AllowContained, Tier::Metadata),
    ];
    for n in 0..allows.len() {
        // Each allow beats every one listed before it.
        assert_eq!(winner(&m, &allows[..=n]), id(3 + u64::try_from(n).unwrap()));
    }
    // most_permissive reverses the order.
    let permissive = Resolver::new(
        PrecedenceModel::DenyWins,
        &PrecedenceOptions {
            allow_tiebreak: AllowTiebreak::MostPermissive,
            ..PrecedenceOptions::default()
        },
    );
    assert_eq!(winner(&permissive, &allows), id(3));
    // Among denies, the most specific, then the oldest.
    let denies = [
        candidate(7, 0, Verdict::Deny, Tier::Signer),
        candidate(8, 0, Verdict::Deny, Tier::Hash),
        candidate(9, 0, Verdict::Deny, Tier::Hash),
    ];
    assert_eq!(winner(&m, &denies), id(8));
}

#[test]
fn allow_wins_prefers_any_allow() {
    let m = resolver(PrecedenceModel::AllowWins);
    let folder_allow = candidate(1, 0, Verdict::Allow, Tier::PathDirectory);
    let hash_deny = candidate(2, 0, Verdict::Deny, Tier::Hash);
    assert_eq!(winner(&m, &[hash_deny, folder_allow]), id(1));
    assert_eq!(winner(&m, &[hash_deny]), id(2));
}

#[test]
fn allow_wins_with_granularity_keeps_a_denied_file_in_an_allowed_folder_denied() {
    let m = Resolver::new(
        PrecedenceModel::AllowWins,
        &PrecedenceOptions {
            granularity_tiebreak: true,
            ..PrecedenceOptions::default()
        },
    );
    let folder_allow = candidate(1, 0, Verdict::Allow, Tier::PathDirectory);
    let file_deny = candidate(2, 0, Verdict::Deny, Tier::PathFile);
    assert_eq!(winner(&m, &[folder_allow, file_deny]), id(2));
    // Granularity only applies within one rule set: an allow in another
    // set still wins.
    let other_set_allow = candidate(3, 1, Verdict::Allow, Tier::PathDirectory);
    assert_eq!(
        winner(&m, &[folder_allow, file_deny, other_set_allow]),
        id(3)
    );
    // Without the option, the folder allow wins.
    assert_eq!(
        winner(
            &resolver(PrecedenceModel::AllowWins),
            &[folder_allow, file_deny]
        ),
        id(1)
    );
}

#[test]
fn allow_wins_lets_the_most_lenient_of_several_rules_win() {
    // A regression from the products that resolve towards the most lenient
    // rule: a user-wide deny and an administrators' allow both match, and
    // the allow wins. With most_permissive, the elevation wins over a
    // plain allow too.
    let m = Resolver::new(
        PrecedenceModel::AllowWins,
        &PrecedenceOptions {
            allow_tiebreak: AllowTiebreak::MostPermissive,
            ..PrecedenceOptions::default()
        },
    );
    let everyone_deny = candidate(1, 0, Verdict::Deny, Tier::Signer);
    let admin_allow = candidate(2, 1, Verdict::Allow, Tier::Signer);
    let admin_elevate = candidate(3, 1, ALWAYS, Tier::Signer);
    assert_eq!(winner(&m, &[everyone_deny, admin_allow]), id(2));
    assert_eq!(
        winner(&m, &[everyone_deny, admin_allow, admin_elevate]),
        id(3)
    );
}

#[test]
fn specificity_ranks_tiers_then_breaks_ties_by_action() {
    let m = resolver(PrecedenceModel::Specificity);
    let hash_allow = candidate(1, 0, Verdict::Allow, Tier::Hash);
    let signer_deny = candidate(2, 0, Verdict::Deny, Tier::Signer);
    assert_eq!(winner(&m, &[signer_deny, hash_allow]), id(1));
    let signer_allow = candidate(3, 0, Verdict::Allow, Tier::Signer);
    assert_eq!(winner(&m, &[signer_deny, signer_allow]), id(2));
    let allow_ties = Resolver::new(
        PrecedenceModel::Specificity,
        &PrecedenceOptions {
            same_tier_tiebreak: TierTiebreak::Allow,
            ..PrecedenceOptions::default()
        },
    );
    assert_eq!(winner(&allow_ties, &[signer_deny, signer_allow]), id(3));
    // A deeper directory beats a shallower one.
    let mut shallow_allow = candidate(4, 0, Verdict::Allow, Tier::PathDirectory);
    shallow_allow.spec.depth = 1;
    let mut deep_deny = candidate(5, 0, Verdict::Deny, Tier::PathDirectory);
    deep_deny.spec.depth = 3;
    assert_eq!(winner(&m, &[shallow_allow, deep_deny]), id(5));
    assert_eq!(winner(&allow_ties, &[shallow_allow, deep_deny]), id(5));
}

#[test]
fn first_match_takes_the_lowest_order_then_the_newer_rule() {
    let m = resolver(PrecedenceModel::FirstMatch);
    let mut late_deny = candidate(1, 0, Verdict::Deny, Tier::Hash);
    late_deny.order = Some(200_000);
    let mut early_allow = candidate(2, 0, Verdict::Allow, Tier::Metadata);
    early_allow.order = Some(150_000);
    assert_eq!(winner(&m, &[late_deny, early_allow]), id(2));
    // Equal orders: the newer rule (the larger UUIDv7) wins.
    let mut old = candidate(3, 0, Verdict::Deny, Tier::Hash);
    old.order = Some(150_000);
    let mut new = candidate(4, 0, Verdict::Allow, Tier::Hash);
    new.order = Some(150_000);
    assert_eq!(winner(&m, &[old, new]), id(4));
    // A rule without an order sorts last.
    let unordered = candidate(5, 0, Verdict::Deny, Tier::Hash);
    assert_eq!(winner(&m, &[unordered, late_deny]), id(1));
}

#[test]
fn first_match_puts_curated_rules_first_unless_turned_off() {
    let mut custom = candidate(1, 0, Verdict::Allow, Tier::Hash);
    custom.order = Some(100_001);
    let mut curated = candidate(2, 1, Verdict::Deny, Tier::Hash);
    curated.order = Some(100_000);
    curated.curated = true;
    let mut late_curated = curated;
    late_curated.rule.rule_id = RuleId(uuid(3));
    late_curated.order = Some(999_000);
    let m = resolver(PrecedenceModel::FirstMatch);
    assert_eq!(winner(&m, &[custom, late_curated]), id(3));
    let off = Resolver::new(
        PrecedenceModel::FirstMatch,
        &PrecedenceOptions {
            curated_first: false,
            ..PrecedenceOptions::default()
        },
    );
    assert_eq!(winner(&off, &[custom, late_curated]), id(1));
    assert_eq!(winner(&off, &[custom, curated]), id(2));
}

#[test]
fn priority_takes_the_winning_number_then_the_fixed_action_order() {
    let mk = |n, verdict, p| {
        let mut c = candidate(n, 0, verdict, Tier::Hash);
        c.priority = Some(p);
        c
    };
    let m = resolver(PrecedenceModel::Priority);
    let low_allow = mk(1, Verdict::Allow, -5);
    let high_deny = mk(2, Verdict::Deny, 10);
    assert_eq!(winner(&m, &[high_deny, low_allow]), id(1));
    let higher = Resolver::new(
        PrecedenceModel::Priority,
        &PrecedenceOptions {
            priority_direction: PriorityDirection::HigherWins,
            ..PrecedenceOptions::default()
        },
    );
    assert_eq!(winner(&higher, &[high_deny, low_allow]), id(2));
    // Equal priority: deny, allow_contained, allow, always, if_required.
    let band = [
        mk(3, IF_REQUIRED, 0),
        mk(4, ALWAYS, 0),
        mk(5, Verdict::Allow, 0),
        mk(6, Verdict::AllowContained, 0),
        mk(7, Verdict::Deny, 0),
    ];
    for n in 0..band.len() {
        assert_eq!(winner(&m, &band[..=n]), id(3 + u64::try_from(n).unwrap()));
    }
    // i32 extremes do not overflow.
    let min = mk(8, Verdict::Allow, i32::MIN);
    let max = mk(9, Verdict::Allow, i32::MAX);
    assert_eq!(winner(&m, &[max, min]), id(8));
    assert_eq!(winner(&higher, &[max, min]), id(9));
}

fn crit(field: Field, operator: Operator, values: &[&str]) -> Match {
    Match::Criterion(Criterion {
        field,
        operator,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive: None,
    })
}

#[test]
fn tiers_come_from_the_strongest_guaranteed_identity() {
    let hash = crit(Field::HashSha256, Operator::Equals, &[&"a".repeat(64)]);
    let publisher = crit(Field::SignerPublisher, Operator::Equals, &["Example Ltd"]);
    let product = crit(Field::MetaProductName, Operator::Equals, &["Editor"]);
    let file = crit(Field::MetaOriginalFilename, Operator::Equals, &["edit.exe"]);
    let version = crit(Field::MetaFileVersion, Operator::VersionGe, &["1.0"]);
    let full = crit(Field::PathFull, Operator::Equals, &["C:\\Tools\\a.exe"]);
    let dir = crit(
        Field::PathDirectory,
        Operator::StartsWith,
        &["C:\\Tools\\Sub"],
    );
    let ext = crit(Field::PathExtension, Operator::Equals, &["exe"]);
    let issuer = crit(Field::SignerIssuer, Operator::Equals, &["Example CA"]);
    let admin = crit(Field::UserIsAdmin, Operator::IsTrue, &[]);
    let all = |v: &[&Match]| Match::All(v.iter().map(|m| (*m).clone()).collect());
    let any = |v: &[&Match]| Match::Any(v.iter().map(|m| (*m).clone()).collect());
    let tier = |m: &Match| Spec::of(m).tier.number();
    assert_eq!(tier(&hash), 1);
    assert_eq!(tier(&all(&[&publisher, &file, &version])), 2);
    // Nested `all` nodes combine too.
    assert_eq!(tier(&all(&[&publisher, &all(&[&file, &version])])), 2);
    assert_eq!(tier(&all(&[&publisher, &product])), 3);
    assert_eq!(tier(&publisher), 4);
    assert_eq!(tier(&full), 5);
    assert_eq!(tier(&dir), 6);
    assert_eq!(tier(&ext), 7);
    // An issuer names a whole certification authority.
    assert_eq!(tier(&issuer), 7);
    assert_eq!(tier(&all(&[&issuer, &product])), 7);
    // `all` takes the strongest, `any` the weakest.
    assert_eq!(tier(&all(&[&dir, &hash])), 1);
    assert_eq!(tier(&any(&[&dir, &hash])), 6);
    // Negations and context identify nothing.
    assert_eq!(tier(&Match::Not(Box::new(hash.clone()))), 7);
    assert_eq!(tier(&all(&[&admin, &publisher])), 4);
    assert_eq!(tier(&any(&[&admin, &hash])), 7);
    // A signer and a product across an `any` are not tested together.
    assert_eq!(tier(&all(&[&publisher, &any(&[&product, &ext])])), 4);
}

#[test]
fn directory_depth_counts_fixed_components() {
    let depth = |op, v: &str| Spec::of(&crit(Field::PathDirectory, op, &[v])).depth;
    assert_eq!(depth(Operator::StartsWith, "C:\\"), 0);
    assert_eq!(depth(Operator::StartsWith, "C:\\Tools"), 1);
    assert_eq!(depth(Operator::StartsWith, "C:\\Tools\\Sub\\"), 2);
    assert_eq!(depth(Operator::Wildcard, "C:\\Tools\\*\\Bin"), 1);
    assert_eq!(depth(Operator::StartsWith, "%PROGRAMFILES%\\App"), 2);
    assert_eq!(depth(Operator::StartsWith, "%TEMP%"), 5);
    assert_eq!(depth(Operator::StartsWith, "\\\\server\\share\\dir"), 1);
    assert_eq!(depth(Operator::Regex, "C:\\\\Tools\\\\.*"), 0);
    // Values are normalised as matching normalises them.
    assert_eq!(depth(Operator::StartsWith, "C:\\a\\..\\.."), 0);
    assert_eq!(depth(Operator::StartsWith, "C:\\Tools\\.\\.\\."), 1);
    assert_eq!(depth(Operator::StartsWith, "C:\\Tools\\Sub\\.."), 1);
    assert_eq!(depth(Operator::StartsWith, "C:\\A\\B\\..\\..\\Tools"), 1);
    assert_eq!(depth(Operator::StartsWith, "\\??\\C:\\Tools\\Sub"), 2);
    assert_eq!(depth(Operator::StartsWith, "\\\\?\\UNC\\server\\share"), 0);
    assert_eq!(
        depth(Operator::StartsWith, "\\\\?\\UNC\\server\\share\\dir"),
        1
    );
    assert_eq!(depth(Operator::StartsWith, "C:\\\\Tools\\\\Sub"), 2);
    assert_eq!(depth(Operator::StartsWith, "C:/Tools/Sub"), 2);
    // A wildcard drive fixes nothing; `[` is literal outside wildcards.
    assert_eq!(depth(Operator::Wildcard, "*:\\Tools\\Sub"), 0);
    assert_eq!(depth(Operator::Wildcard, "?:\\Tools\\Sub"), 0);
    // A wildcard UNC server or share fixes nothing either.
    for root in [
        "\\\\*\\*\\Tools\\Sub\\Bin",
        "\\\\server\\*\\Tools\\Sub",
        "\\\\**\\Tools\\Sub\\Bin",
        "\\\\?\\UNC\\*\\share\\Tools\\Sub",
        "\\\\srv?\\share\\Tools",
        "\\\\server\\sh[a]re\\Tools",
    ] {
        assert_eq!(depth(Operator::Wildcard, root), 0, "{root}");
    }
    // Under `starts_with` they are literal names.
    assert_eq!(depth(Operator::StartsWith, "\\\\server\\sh[a]re\\Tools"), 1);
    // A wildcard allow across every share never outranks a concrete deny.
    let any_share = Spec::of(&crit(
        Field::PathDirectory,
        Operator::Wildcard,
        &["\\\\*\\*\\Tools\\Sub\\Bin"],
    ));
    let restricted = Spec::of(&crit(
        Field::PathDirectory,
        Operator::StartsWith,
        &["\\\\corp-fs\\restricted\\Tools"],
    ));
    assert!(restricted < any_share);
    assert_eq!(depth(Operator::StartsWith, "C:\\Apps\\[v2]\\Sub"), 3);
    assert_eq!(depth(Operator::Wildcard, "C:\\Apps\\[v2]\\Sub"), 1);
    assert_eq!(depth(Operator::StartsWith, "%PROGRAMFILES%\\App\\Bin"), 3);
    // An unresolvable value fixes nothing.
    assert_eq!(depth(Operator::StartsWith, "relative\\dir"), 0);
    // A parent written with `..` never outranks its subdirectory.
    let parent = Spec::of(&crit(
        Field::PathDirectory,
        Operator::StartsWith,
        &["C:\\Tools\\Sub\\.."],
    ));
    let sub = Spec::of(&crit(
        Field::PathDirectory,
        Operator::StartsWith,
        &["C:\\Tools\\Sub"],
    ));
    assert!(sub < parent);
    // Several values: the shallowest, since any may match.
    let both = crit(
        Field::PathDirectory,
        Operator::StartsWith,
        &["C:\\A\\B\\C", "C:\\A"],
    );
    assert_eq!(Spec::of(&both).depth, 1);
    let deeper = Spec::of(&crit(
        Field::PathDirectory,
        Operator::StartsWith,
        &["C:\\A\\B"],
    ));
    let shallower = Spec::of(&crit(
        Field::PathDirectory,
        Operator::StartsWith,
        &["C:\\A"],
    ));
    assert!(deeper < shallower);
}

#[test]
fn spec_of_a_tree_deeper_than_the_limit_is_the_least_specific() {
    let mut tree = crit(Field::HashSha256, Operator::Equals, &[&"a".repeat(64)]);
    for _ in 0..10_000 {
        tree = Match::All(vec![tree]);
    }
    assert_eq!(Spec::of(&tree), Spec::LEAST);
}

fn verdict() -> impl Strategy<Value = Verdict> {
    prop_oneof![
        Just(Verdict::Deny),
        Just(Verdict::AllowContained),
        Just(Verdict::Allow),
        Just(ALWAYS),
        Just(IF_REQUIRED),
    ]
}

fn tier() -> impl Strategy<Value = Tier> {
    proptest::sample::select(vec![
        Tier::Hash,
        Tier::SignerFileVersion,
        Tier::SignerProduct,
        Tier::Signer,
        Tier::PathFile,
        Tier::PathDirectory,
        Tier::Metadata,
    ])
}

/// Up to 12 candidates with unique rule IDs, in 3 rule sets, with small
/// ranges of order and priority so that ties are common.
fn candidates() -> impl Strategy<Value = Vec<Candidate>> {
    proptest::collection::btree_map(
        0u64..64,
        (
            0u64..3,
            verdict(),
            tier(),
            0u16..3,
            proptest::option::of(0u32..3),
            proptest::option::of(-1i32..2),
            any::<bool>(),
        ),
        0..12,
    )
    .prop_map(|m| {
        m.into_iter()
            .map(|(n, (s, verdict, tier, depth, order, priority, curated))| {
                let mut c = candidate(n, s, verdict, tier);
                c.spec.depth = if tier == Tier::PathDirectory {
                    depth
                } else {
                    0
                };
                c.order = order;
                c.priority = priority;
                c.curated = curated;
                c
            })
            .collect()
    })
}

fn any_resolver() -> impl Strategy<Value = Resolver> {
    (
        proptest::sample::select(vec![
            PrecedenceModel::DenyWins,
            PrecedenceModel::AllowWins,
            PrecedenceModel::Specificity,
            PrecedenceModel::FirstMatch,
            PrecedenceModel::Priority,
        ]),
        crate::model::arbitrary::precedence_options(),
    )
        .prop_map(|(model, options)| Resolver::new(model, &options))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Every model: the same input gives the same winner, and shuffling the
    /// match set never changes which rule wins. For `first_match` and
    /// `priority` this is the guarantee that only `order`, `priority` and
    /// the rule ID matter, never the position of a rule in a list.
    #[test]
    fn winners_are_deterministic_and_order_independent(
        m in any_resolver(),
        (cs, shuffled) in candidates().prop_flat_map(|cs| (Just(cs.clone()), Just(cs).prop_shuffle())),
    ) {
        let first = winner(&m, &cs);
        prop_assert_eq!(winner(&m, &cs), first);
        prop_assert_eq!(winner(&m, &shuffled), first);
        // Some candidate wins whenever there is one.
        prop_assert_eq!(first.is_some(), !cs.is_empty());
    }

    /// `deny_wins`: whenever a deny matches, a deny decides (ADR 0004, the
    /// invariant behind #125 for ordinary rules).
    #[test]
    fn deny_wins_never_lets_an_allow_beat_a_deny(cs in candidates(), o in crate::model::arbitrary::precedence_options()) {
        let m = Resolver::new(PrecedenceModel::DenyWins, &o);
        let set = set(&cs);
        if let Some(i) = m.resolve(&set).winner {
            let any_deny = cs.iter().any(|c| !c.verdict.allows());
            prop_assert_eq!(set.candidates[i].verdict.allows(), !any_deny);
        }
    }

    /// `allow_wins` without granularity: whenever an allow matches, an
    /// allow decides.
    #[test]
    fn allow_wins_lets_any_allow_decide(cs in candidates()) {
        let m = resolver(PrecedenceModel::AllowWins);
        let set = set(&cs);
        if let Some(i) = m.resolve(&set).winner {
            let any_allow = cs.iter().any(|c| c.verdict.allows());
            prop_assert_eq!(set.candidates[i].verdict.allows(), any_allow);
        }
    }

    /// `specificity`: no candidate is more specific than the winner.
    #[test]
    fn specificity_picks_a_most_specific_rule(cs in candidates()) {
        let m = resolver(PrecedenceModel::Specificity);
        let set = set(&cs);
        if let Some(i) = m.resolve(&set).winner {
            let w = set.candidates[i].spec;
            prop_assert!(cs.iter().all(|c| c.spec >= w));
        }
    }
}
