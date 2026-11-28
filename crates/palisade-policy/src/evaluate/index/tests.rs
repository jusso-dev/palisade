//! Tests of the candidate indexes and the lazy fact protocol (#42).
//!
//! The central property: over random valid policies and random facts, the
//! indexed evaluator gives exactly the decision of the linear scan, with
//! the same deciding rule, under every model and device state. The facts
//! are drawn from a small pool of values that the generated criteria also
//! use, so rules really match, miss and are unknown.

use proptest::collection::vec;
use proptest::prelude::*;

use palisade_core::path::VolumeMap;

use super::super::Evaluator;
use super::*;
use crate::context::{EvaluationContext, SessionType};
use crate::decision::TraceId;
use crate::facts::{PathFact, PathVariables, SignatureSource, SignerFact, SignerStatus};
use crate::mode::{Connectivity, DeviceState, SessionKind};
use crate::model::{
    Criterion, Match, Mode, Operator, PolicyDocument, PrecedenceModel, Rule, RuleSetKind,
};
use crate::validate::ValidatedPolicy;

const TRACE: TraceId = TraceId([3; 16]);

fn hex(c: char, n: usize) -> String {
    std::iter::repeat_n(c, n).collect()
}

/// The values the pool draws from, per field class.
const HASH_CHARS: [char; 3] = ['a', 'b', 'C'];
const PATHS: [&str; 4] = [
    r"C:\Tools\Sub\tool.exe",
    r"C:\Program Files\App\app.exe",
    r"\\srv\share\x.exe",
    r"C:\Windows\System32\cmd.exe",
];
const PUBLISHERS: [&str; 3] = ["Example Ltd", "EXAMPLE LTD", "Other Corp"];
const PRODUCTS: [&str; 3] = ["Suite", "suite", "Tool"];
const SIDS: [&str; 3] = ["S-1-5-32-544", "s-1-5-21-1-2-3-1001", "S-1-5-18"];

fn pool_value(field: Field, k: usize) -> String {
    match field.class() {
        FieldClass::Hash { hex_len } => hex(HASH_CHARS[k % 3], hex_len),
        FieldClass::Path => {
            let p = PATHS[k % PATHS.len()];
            match (field, k % 3) {
                (Field::PathDirectory, _) => p.rsplit_once('\\').map_or(p, |(d, _)| d).to_owned(),
                (_, 1) => p.rsplit_once('\\').map_or(p, |(d, _)| d).to_owned(),
                (_, 2) => p.to_lowercase(),
                _ => p.to_owned(),
            }
        }
        FieldClass::FileName if field == Field::PathExtension => {
            ["exe", "EXE", "dll"][k % 3].into()
        }
        FieldClass::FileName => ["tool.exe", "APP.EXE", "cmd.exe"][k % 3].into(),
        FieldClass::Text if field == Field::SignerPublisher => PUBLISHERS[k % 3].into(),
        FieldClass::Text => PRODUCTS[k % 3].into(),
        FieldClass::Sid => SIDS[k % 3].into(),
        FieldClass::PrincipalSet => SIDS[k % 3].into(),
        FieldClass::Version => ["10.0", "1.2.3.4", "10.0.0.1"][k % 3].into(),
        FieldClass::TagSet => ["a", "b", "c"][k % 3].into(),
        FieldClass::SessionType => ["console", "rdp", "service"][k % 3].into(),
        FieldClass::PrincipalName => [r"DOM\user", r"DOM\admin", r"X\y"][k % 3].into(),
        FieldClass::Bool => String::new(),
        // The classes of #32's numeric, network, set and time operators,
        // in ascending order, so `between` bounds drawn in order are valid.
        FieldClass::Number => ["19045", "22000", "22631"][k % 3].into(),
        FieldClass::IntegrityLevel => ["low", "medium", "high"][k % 3].into(),
        FieldClass::DistinguishedName => [
            "OU=A,DC=corp,DC=example",
            "OU=B,OU=A,DC=corp,DC=example",
            "OU=C,DC=corp,DC=example",
        ][k % 3]
            .into(),
        FieldClass::Ip | FieldClass::IpSet => ["10.0.0.1", "10.0.0.2", "192.168.1.1"][k % 3].into(),
        FieldClass::MacSet => [
            "aa:bb:cc:00:00:01",
            "aa:bb:cc:00:00:02",
            "aa:bb:cc:00:00:03",
        ][k % 3]
            .into(),
        FieldClass::NameSet => ["corp.example.org", "corporate", "home"][k % 3].into(),
        FieldClass::Weekday => ["mon", "wed", "sun"][k % 3].into(),
        FieldClass::TimeOfDay => ["08:00", "12:00", "18:00"][k % 3].into(),
        FieldClass::Date => ["2026-01-01", "2026-06-01", "2026-12-31"][k % 3].into(),
        // Main's signer fields (#316): the TBS hash and the EKU set.
        FieldClass::Digest => hex(HASH_CHARS[k % 3], 64),
        // #328's MSI codes: either case, with or without braces.
        FieldClass::Guid => [
            "{12345678-9ABC-DEF0-1234-56789ABCDEF0}",
            "12345678-9abc-def0-1234-56789abcdef0",
            "{00000000-0000-0000-0000-000000000001}",
        ][k % 3]
            .into(),
        FieldClass::OidSet => [
            "1.3.6.1.5.5.7.3.3",
            "1.3.6.1.4.1.311.10.3.6",
            "1.3.6.1.5.5.7.3.1",
        ][k % 3]
            .into(),
    }
}

/// A criterion on `field` with values from the pool, for an operator that
/// fits the field.
fn pool_criterion() -> impl Strategy<Value = Criterion> {
    // Mostly fields the pool's facts set, so criteria really match; any
    // field now and then, so every kind of criterion is covered.
    let common = proptest::sample::select(vec![
        Field::HashSha256,
        Field::HashSha1,
        Field::PathFull,
        Field::PathDirectory,
        Field::PathFileName,
        Field::PathExtension,
        Field::SignerPublisher,
        Field::SignerLeafThumbprint,
        Field::SignerTbsHash,
        Field::MetaProductName,
        Field::MetaFileVersion,
        Field::UserSid,
        Field::UserGroups,
        Field::SessionType,
        Field::UserIsAdmin,
    ]);
    let field = prop_oneof![4 => common, 1 => proptest::sample::select(Field::ALL.to_vec())];
    (
        field,
        any::<prop::sample::Index>(),
        vec(0usize..6, 1..3),
        0usize..5,
    )
        .prop_map(|(field, op, ks, position)| {
            let ops: Vec<Operator> = Operator::ALL
                .iter()
                .copied()
                .filter(|o| o.applies_to(field.class()))
                .filter(|o| !o.is_regex())
                .filter(|o| !o.is_version() || field.class() == FieldClass::Version)
                .collect();
            let operator = *op.get(&ops);
            let (min, max) = operator.value_count();
            let mut values: Vec<String> = ks.iter().map(|k| pool_value(field, *k)).collect();
            values.truncate(max);
            while values.len() < min {
                values.push(pool_value(field, values.len()));
            }
            if operator == Operator::Wildcard && field.class() == FieldClass::Path {
                for v in &mut values {
                    if let Some((dir, _)) = v.rsplit_once('\\') {
                        *v = format!(r"{dir}\*.exe");
                    }
                }
            }
            if operator == Operator::VersionBetween {
                values.sort_by_key(|v| crate::ops::Version::parse_strict(v));
            }
            if operator.value_count() == (2, 2) && operator != Operator::VersionBetween {
                // Pool values are listed in ascending order.
                values.sort_by_key(|v| (0..6).find(|k| pool_value(field, *k) == *v));
                values.dedup();
                while values.len() < 2 {
                    values.push(pool_value(field, 2));
                }
            }
            let mut c = Criterion::new(field, operator, values);
            // A TBS-hash test at each position, or the default (`any`): only
            // `leaf` is indexed (#42).
            if field == Field::SignerTbsHash && position < 4 {
                c.signer = Some(Box::new(crate::model::SignerOptions {
                    position: Some(
                        [
                            crate::model::TbsPosition::Leaf,
                            crate::model::TbsPosition::Leaf,
                            crate::model::TbsPosition::Root,
                            crate::model::TbsPosition::Any,
                        ][position],
                    ),
                    ..Default::default()
                }));
            }
            c
        })
}

/// A tree over pool criteria. The root is `all` with an identity first, as
/// validation needs; the identity is from the pool too.
fn pool_tree() -> impl Strategy<Value = Match> {
    let leaf = pool_criterion().prop_map(Match::Criterion);
    let inner = leaf.prop_recursive(1, 4, 2, |inner| {
        prop_oneof![
            vec(inner.clone(), 1..3).prop_map(Match::All),
            vec(inner.clone(), 1..3).prop_map(Match::Any),
            inner.prop_map(|m| Match::Not(Box::new(m))),
        ]
    });
    let identity = prop_oneof![
        (0usize..3).prop_map(|k| (
            Field::HashSha256,
            Operator::Equals,
            pool_value(Field::HashSha256, k)
        )),
        (0usize..3).prop_map(|k| (
            Field::SignerPublisher,
            Operator::Equals,
            pool_value(Field::SignerPublisher, k)
        )),
        (0usize..6).prop_map(|k| (
            Field::PathFull,
            Operator::StartsWith,
            pool_value(Field::PathFull, k)
        )),
        (0usize..6).prop_map(|k| (
            Field::PathDirectory,
            Operator::Equals,
            pool_value(Field::PathDirectory, k)
        )),
        (0usize..4, 0usize..3).prop_map(|(k, form)| {
            let path = PATHS[k];
            let dir = path.rsplit_once('\\').map_or(path, |(d, _)| d);
            let pattern = match form {
                0 => format!(r"{dir}\*.exe"),
                1 => format!(r"{dir}\**"),
                _ => format!(r"{}?\*", &dir[..dir.len() - 1]),
            };
            (Field::PathFull, Operator::Wildcard, pattern)
        }),
    ];
    let identity = prop_oneof![
        5 => identity.prop_map(|(field, operator, value)| {
            Match::Criterion(Criterion::new(field, operator, [value]))
        }),
        // A leaf TBS hash alone, so some rules rest only on that anchor.
        1 => (0usize..3).prop_map(|k| {
            let mut c = Criterion::new(Field::SignerTbsHash, Operator::Equals, [hex(HASH_CHARS[k], 64)]);
            c.signer = Some(Box::new(crate::model::SignerOptions {
                position: Some(crate::model::TbsPosition::Leaf),
                ..Default::default()
            }));
            Match::Criterion(c)
        }),
    ];
    // The identity alone, or an `any` of two identities (so a rule's anchor
    // spans several classes, such as a path or a hash), in either order
    // with the other children.
    let anchor = prop_oneof![
        3 => identity.clone(),
        2 => vec(identity, 2..3).prop_map(Match::Any),
    ];
    (anchor, vec(inner, 0..2), any::<bool>()).prop_map(|(anchor, rest, last)| {
        let mut children = rest;
        if last {
            children.push(anchor);
        } else {
            children.insert(0, anchor);
        }
        Match::All(children)
    })
}

/// Random facts from the pool: each class present or not.
#[derive(Clone, Debug)]
pub(crate) struct PoolFacts {
    pub(crate) facts: ObjectFacts,
    pub(crate) context: EvaluationContext,
}

pub(crate) fn pool_facts() -> impl Strategy<Value = PoolFacts> {
    (
        (
            proptest::option::weighted(0.8, 0usize..3),
            proptest::option::of(0usize..3),
            proptest::option::weighted(
                0.9,
                (
                    0usize..6,
                    proptest::option::weighted(0.7, any::<bool>()),
                    proptest::bool::weighted(0.2),
                ),
            ),
        ),
        (
            proptest::option::weighted(0.8, vec((0usize..3, 0usize..4), 0..3)),
            proptest::option::of(0usize..3),
            proptest::option::of(0usize..3),
        ),
        (
            proptest::option::of(0usize..3),
            proptest::option::of(vec(0usize..3, 0..3)),
            proptest::option::of(0usize..3),
            proptest::option::of(any::<bool>()),
        ),
    )
        .prop_map(
            |((sha, sha1, path), (signers, product, version), (sid, groups, session, admin))| {
                let mut facts = ObjectFacts::new();
                if let Some(k) = sha {
                    facts.set(Field::HashSha256, pool_value(Field::HashSha256, k));
                }
                if let Some(k) = sha1 {
                    facts.set(Field::HashSha1, pool_value(Field::HashSha1, k));
                }
                if let Some((k, writable, alias)) = path {
                    let mut fact = PathFact::new(PATHS[k % PATHS.len()], &VolumeMap::new());
                    fact.user_writable = writable;
                    if alias {
                        fact.alias =
                            Some(palisade_core::path::normalize(PATHS[(k + 1) % PATHS.len()]));
                    }
                    facts.path = Some(fact);
                }
                if let Some(list) = signers {
                    facts.signers = Some(
                        list.into_iter()
                            .map(|(p, status)| SignerFact {
                                status: [
                                    SignerStatus::Valid,
                                    SignerStatus::CatalogSigned,
                                    SignerStatus::Revoked,
                                    SignerStatus::Expired,
                                ][status],
                                source: SignatureSource::Embedded,
                                publisher: Some(PUBLISHERS[p].to_owned()),
                                issuer: None,
                                leaf_thumbprint_sha256: Some(hex(HASH_CHARS[p], 64)),
                                // The leaf's TBS hash, in either case, so
                                // the index folds it as the evaluator does.
                                details: crate::facts::SignerDetails {
                                    leaf_tbs_hash: Some(if p == 1 {
                                        hex(HASH_CHARS[p], 64).to_ascii_uppercase()
                                    } else {
                                        hex(HASH_CHARS[p], 64)
                                    }),
                                    ..Default::default()
                                },
                            })
                            .collect(),
                    );
                }
                if let Some(k) = product {
                    facts.set(Field::MetaProductName, PRODUCTS[k]);
                }
                if let Some(k) = version {
                    facts.set(Field::MetaFileVersion, ["10.0", "1.2.3.4", "garbage"][k]);
                }
                let mut context = EvaluationContext::new();
                context.user.sid = sid.map(|k| SIDS[k].to_owned());
                context.user.groups =
                    groups.map(|g| g.into_iter().map(|k| SIDS[k].to_owned()).collect());
                context.session.session_type = session
                    .map(|k| [SessionType::Console, SessionType::Rdp, SessionType::Service][k]);
                context.user.is_admin = admin;
                PoolFacts { facts, context }
            },
        )
}

/// A random valid document whose trees come from the pool. The policy,
/// its model, modes and rule sets come from
/// [`crate::model::arbitrary::document`]; each rule set is then filled
/// with 4 to 16 copies of its generated rules, each with a fresh ID and a
/// pool tree, so a policy has many overlapping rules.
///
/// The rule lifecycle (#40) is covered too: rules get activity windows a
/// few days either side of [`POOL_NOW`], some with `on_expire:
/// convert_to_audit` (whose audit stand-ins are indexed like any rule),
/// and a quarter of the policies get the managed `system_baseline`, added
/// after validation as the engine adds it.
pub(crate) fn pool_document() -> impl Strategy<Value = ValidatedPolicy> {
    (
        crate::model::arbitrary::document(),
        vec(pool_tree(), 64),
        4usize..16,
        any::<u16>(),
    )
        .prop_filter_map("valid", |(mut doc, trees, copies, salt)| {
            let mut trees = trees.into_iter().cycle();
            let mut n = 0u32;
            for set in &mut doc.rule_sets {
                let base = std::mem::take(&mut set.rules);
                for k in 0..copies {
                    for rule in &base {
                        let mut rule = rule.clone();
                        n += 1;
                        let mut id = *rule.id.0.as_bytes();
                        id[0..2].copy_from_slice(&salt.to_be_bytes());
                        id[2..6].copy_from_slice(&n.to_be_bytes());
                        rule.id = crate::model::RuleId(palisade_core::Uuid7::from_bytes(id)?);
                        rule.display_id = None;
                        rule.match_ = trees.next()?;
                        rule.enabled = k % 5 != 4;
                        let day = |d: i64| crate::model::Timestamp(POOL_NOW.0 + d * 86_400);
                        let converts = !set.mandatory;
                        let (from, to, audit) = match n % 7 {
                            1 => (None, Some(-3), false),
                            2 => (Some(3), None, false),
                            3 => (Some(-5), Some(5), false),
                            4 => (None, Some(0), converts),
                            5 => (Some(-2), Some(2), converts),
                            _ => (None, None, false),
                        };
                        rule.activates_at = from.map(day);
                        rule.expires_at = to.map(day);
                        if audit {
                            rule.on_expire = crate::model::OnExpire::ConvertToAudit;
                        }
                        // Some denies fail closed, so the always-evaluated
                        // list is exercised.
                        if let crate::model::Action::Deny(o) = &mut rule.action
                            && k % 3 == 0
                        {
                            o.unknown_as = crate::model::UnknownAs::Match;
                        }
                        set.rules.push(rule);
                    }
                }
            }
            let validated = doc.validate().ok()?;
            Some(if salt % 4 == 0 {
                validated
                    .with_system_baseline(&crate::unknown::baseline::SystemBaseline {
                        publishers: vec![PUBLISHERS[0].to_owned()],
                        writable_dirs: Vec::new(),
                    })
                    .ok()?
            } else {
                validated
            })
        })
}

/// The time the pool's activity windows are placed around:
/// 2026-11-25T00:00:00Z.
pub(crate) const POOL_NOW: crate::model::Timestamp = crate::model::Timestamp(1_795_564_800);

/// No rule clock, an anchored one, or an offline-started one (ADR 0018),
/// a few days either side of [`POOL_NOW`], with a floor that may lag.
pub(crate) fn rule_clock() -> impl Strategy<Value = Option<crate::lifecycle::RuleClock>> {
    proptest::option::weighted(0.8, (-8i64..8, 0i64..4, any::<bool>())).prop_map(|c| {
        c.map(|(now, lag, anchored)| {
            let now = crate::model::Timestamp(POOL_NOW.0 + now * 86_400);
            let floor = crate::model::Timestamp(now.0 - lag * 86_400);
            if anchored {
                crate::lifecycle::RuleClock {
                    now,
                    floor,
                    anchored: true,
                }
            } else {
                crate::lifecycle::RuleClock::offline_started(now, floor)
            }
        })
    })
}

pub(crate) fn state() -> impl Strategy<Value = DeviceState> {
    (
        proptest::sample::select(vec![
            Mode::Monitor,
            Mode::Audit,
            Mode::Learning,
            Mode::Enforce,
        ]),
        any::<bool>(),
        proptest::sample::select(vec![
            None,
            Some(SessionKind::Audit),
            Some(SessionKind::FullBypass),
        ]),
        proptest::bool::weighted(0.1),
    )
        .prop_map(|(mode, offline, session, lockdown)| DeviceState {
            mode,
            connectivity: if offline {
                Connectivity::Disconnected
            } else {
                Connectivity::Connected
            },
            session,
            lockdown,
        })
}

pub(crate) fn variables() -> PathVariables {
    PathVariables::new().with(PathVariable::ProgramFiles, &[r"C:\Program Files"])
}

pub(crate) fn subject<'a>(
    t: ObjectType,
    pool: &'a PoolFacts,
    variables: &'a PathVariables,
) -> Subject<'a> {
    Subject {
        object_type: t,
        facts: &pool.facts,
        variables,
        context: &pool.context,
    }
}

/// An object type that some rule of the policy applies to, if any, so
/// the decision is not always the implicit deny.
pub(crate) fn type_of(policy: &ValidatedPolicy, pick: prop::sample::Index) -> ObjectType {
    let types: Vec<ObjectType> = policy
        .document()
        .rule_sets
        .iter()
        .flat_map(|s| &s.rules)
        .flat_map(|r| {
            if r.object_types.is_empty() {
                ObjectType::ALL.to_vec()
            } else {
                r.object_types.clone()
            }
        })
        .collect();
    if types.is_empty() {
        ObjectType::Executable
    } else {
        *pick.get(&types)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// The indexed evaluator gives the decision of the linear scan, with
    /// the same deciding rule and every other field, for random policies,
    /// facts, object types and device states, and rule clocks: none,
    /// anchored, or offline-started (#40, ADR 0018).
    #[test]
    fn indexed_equals_linear(
        policy in pool_document(),
        pool in pool_facts(),
        pick in any::<prop::sample::Index>(),
        state in state(),
        clock in rule_clock(),
    ) {
        let t = type_of(&policy, pick);
        let mut e = Evaluator::new(&policy).unwrap();
        if let Some(c) = clock {
            e.set_clock(c);
        }
        let variables = variables();
        let s = subject(t, &pool, &variables);
        let linear = e.matching_linear(&s);
        let indexed = e.matching(&s);
        let ids = |v: &[&Compiled<'_>]| v.iter().map(|r| r.rule.id).collect::<Vec<_>>();
        prop_assert_eq!(ids(&indexed), ids(&linear));
        prop_assert_eq!(&e.evaluate(&s, TRACE), &e.evaluate_linear(&s, TRACE));
        prop_assert_eq!(
            e.evaluate_in(&s, &state, TRACE),
            Some(e.decide_in(&s, &linear, &state, TRACE))
        );
    }

    /// The lazy protocol: starting from the cheap facts and adding each
    /// class the engine asks for, it decides within three rounds, asks for
    /// each class once, only asks for a class that a rule not yet ruled out
    /// by the facts computed so far reads, and ends with the decision of the
    /// full facts.
    #[test]
    fn need_facts_rounds(
        policy in pool_document(),
        pool in pool_facts(),
        pick in any::<prop::sample::Index>(),
        state in state(),
        clock in rule_clock(),
    ) {
        let t = type_of(&policy, pick);
        let mut e = Evaluator::new(&policy).unwrap();
        if let Some(c) = clock {
            e.set_clock(c);
        }
        let variables = variables();
        let full = subject(t, &pool, &variables);
        let want = e.evaluate_in(&full, &state, TRACE);

        // What the agent has computed so far, as facts: start with the
        // cheap ones (path without its ACL, and the context).
        let mut computed = FactSet::CHEAP;
        let mut asked = FactSet::EMPTY;
        let mut rounds = 0;
        let mut last_round = 0;
        loop {
            let partial = restrict(&pool, computed);
            let s = subject(t, &partial, &variables);
            match e.evaluate_with(&s, computed, &state, TRACE) {
                Ok(d) => {
                    // Stage 6 records the location classes it saw (#39).
                    // Unless a level depends on them, the path's ACL is not
                    // asked for, so the record of what the ACL decides
                    // differs: the location classes, `user_writable_other`
                    // among the unknown ones, and `user_writable` among the
                    // missing facts. With no level by location, none of
                    // them changes the level or the fallback; nothing else
                    // may differ.
                    let record = |d: &Option<crate::decision::Decision>| {
                        let mut v = serde_json::to_value(d).unwrap();
                        if policy.document().policy.unknown.by_location.is_empty()
                            && let Some(u) = v.get_mut("unknown").and_then(|u| u.as_object_mut()) {
                                u.remove("locations");
                                for (key, acl) in [
                                    ("unknown_locations", "user_writable_other"),
                                    ("missing_facts", "user_writable"),
                                ] {
                                    if let Some(list) = u.get_mut(key).and_then(|l| l.as_array_mut()) {
                                        list.retain(|x| x != acl);
                                    }
                                }
                            }
                        v
                    };
                    prop_assert_eq!(record(&d), record(&want));
                    break;
                }
                Err(NeedFacts(need)) => {
                    rounds += 1;
                    prop_assert!(rounds <= 3, "more than three rounds");
                    prop_assert!(!need.is_empty());
                    prop_assert!(!asked.intersects(need), "asked twice for {:?}", need);
                    prop_assert!(!computed.intersects(need));
                    // Only the classes of one round, and rounds in order.
                    let r = need.round();
                    prop_assert!(r > 0 && FactSet::ROUNDS[r - 1].contains(need));
                    prop_assert!(r > last_round, "round {} after round {}", r, last_round);
                    last_round = r;
                    // Every class asked for is read by a rule of this type
                    // that the facts computed so far have not settled: its
                    // tree is still `Unknown` on them. A rule settled as
                    // `NoMatch` is ruled out, and one settled as `Match`
                    // needs nothing more.
                    let viable = e.rules.iter().enumerate().filter(|(_, c)| {
                        (c.rule.object_types.is_empty() || c.rule.object_types.contains(&t))
                            && c.tree_result(&s) == Tri::Unknown
                    });
                    // Or by the stages after selection (#39): stage 6
                    // reads the path's ACL for its location class.
                    let read: FactSet = viable
                        .map(|(i, _)| e.index.reads[i])
                        .fold(e.after_selection(&s), FactSet::union);
                    for class in need.classes() {
                        prop_assert!(read.contains(class), "{:?} is read by no viable rule", class);
                    }
                    asked |= need;
                    computed |= need;
                }
            }
        }
    }
}

/// The facts of `pool` in the classes of `computed` only.
pub(crate) fn restrict(pool: &PoolFacts, computed: FactSet) -> PoolFacts {
    let mut facts = ObjectFacts::new();
    for field in Field::ALL {
        if let Some(v) = pool.facts.get(field)
            && computed.contains(FactSet::of_field(field))
        {
            facts.set(field, v);
        }
    }
    if computed.contains(FactSet::SIGNERS) {
        facts.signers.clone_from(&pool.facts.signers);
    }
    facts.path = pool.facts.path.clone().map(|mut p| {
        if !computed.contains(FactSet::PATH_ACL) {
            p.user_writable = None;
        }
        p
    });
    PoolFacts {
        facts,
        context: pool.context.clone(),
    }
}

// Unit tests.

fn crit(field: Field, operator: Operator, value: &str) -> Match {
    Match::Criterion(Criterion::new(field, operator, [value]))
}

fn anchors(tree: &Match) -> Option<Vec<Field>> {
    tree_anchor(tree).map(|a| a.iter().map(LeafAnchor::field).collect())
}

#[test]
fn tree_anchors() {
    let hash = crit(Field::HashSha256, Operator::Equals, &hex('a', 64));
    let publisher = crit(Field::SignerPublisher, Operator::Equals, "X");
    let path = crit(Field::PathFull, Operator::StartsWith, r"C:\x");
    let regex = crit(Field::MetaProductName, Operator::Regex, "x.*");
    // `all` takes its anchored child on the cheapest facts: the path
    // before the publisher, so the publisher is only asked for when the
    // path matches.
    assert_eq!(
        anchors(&Match::All(vec![
            path.clone(),
            publisher.clone(),
            regex.clone()
        ])),
        Some(vec![Field::PathFull])
    );
    // Among children on equally expensive facts, the most selective.
    let product = crit(Field::MetaProductName, Operator::Equals, "P");
    assert_eq!(
        anchors(&Match::All(vec![publisher.clone(), product])),
        Some(vec![Field::SignerPublisher])
    );
    assert_eq!(
        anchors(&Match::All(vec![regex.clone(), hash.clone()])),
        Some(vec![Field::HashSha256])
    );
    // `any` needs every child anchored.
    assert_eq!(
        anchors(&Match::Any(vec![hash.clone(), path.clone()])),
        Some(vec![Field::HashSha256, Field::PathFull])
    );
    assert_eq!(
        anchors(&Match::Any(vec![hash.clone(), regex.clone()])),
        None
    );
    // `not` has none.
    assert_eq!(anchors(&Match::Not(Box::new(hash))), None);
    assert_eq!(anchors(&regex), None);
}

fn doc(rules: Vec<serde_json::Value>, mandatory: Vec<serde_json::Value>) -> ValidatedPolicy {
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Index",
            "revision": 1,
            "mode": "enforce",
            "rule_sets": [
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002"
            ],
        },
        "rule_sets": [
            {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
                "name": "Rules",
                "kind": "mixed",
                "rules": rules,
            },
            {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002",
                "name": "Mandatory",
                "kind": "blocklist",
                "mandatory": true,
                "rules": mandatory,
            }
        ],
    });
    PolicyDocument::from_json(&json.to_string())
        .unwrap()
        .validate()
        .unwrap_or_else(|e| panic!("{e:#?}"))
}

fn rule_json(n: u32, field: &str, operator: &str, value: &str, action: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61"),
        "name": format!("Rule {n}"),
        "object_types": ["executable"],
        "match": {"criterion": {"field": field, "operator": operator, "values": [value]}},
        "action": {"type": action},
    })
}

fn exe_facts(sha: Option<char>, path: &str, writable: Option<bool>) -> ObjectFacts {
    let mut f = ObjectFacts::new();
    if let Some(c) = sha {
        f.set(Field::HashSha256, hex(c, 64));
    }
    let mut p = PathFact::new(path, &VolumeMap::new());
    p.user_writable = writable;
    f.with_path(p)
}

fn evaluate_with(
    policy: &ValidatedPolicy,
    facts: &ObjectFacts,
    computed: FactSet,
) -> Result<Option<crate::decision::Decision>, NeedFacts> {
    let e = Evaluator::new(policy).unwrap();
    let context = EvaluationContext::new();
    let variables = PathVariables::new();
    e.evaluate_with(
        &Subject {
            object_type: ObjectType::Executable,
            facts,
            variables: &variables,
            context: &context,
        },
        computed,
        &DeviceState::of(&policy.document().policy),
        TRACE,
    )
}

#[test]
fn no_candidate_needs_no_expensive_fact() {
    // Only path rules for another folder: nothing can match, and nothing
    // expensive is asked for, not even the ACL of the path.
    let p = doc(
        vec![rule_json(
            1,
            "path.directory",
            "starts_with",
            r"C:\Allowed",
            "allow",
        )],
        vec![],
    );
    let d = evaluate_with(
        &p,
        &exe_facts(None, r"D:\Other\x.exe", None),
        FactSet::CHEAP,
    )
    .unwrap()
    .unwrap();
    assert_eq!(d.outcome(), crate::decision::Outcome::Blocked);
    assert!(d.matched_rule().is_none());
}

#[test]
fn selection_applies_scopes_activity_and_safety_critical() {
    use crate::decision::Outcome;
    let sha_a = hex('a', 64);
    // An allow scoped to console sessions, an allow that expired, and a
    // mandatory deny on a version marked `safety_critical`.
    let mut scoped = rule_json(1, "hash.sha256", "equals", &sha_a, "allow");
    scoped["scope"] = serde_json::json!({"sessions": {"types": ["console"]}});
    let mut expired = rule_json(2, "hash.sha256", "equals", &hex('b', 64), "allow");
    expired["expires_at"] = serde_json::json!("2000-01-01T00:00:00Z");
    let critical = serde_json::json!({
        "id": "01936b2e-0003-7b3d-9f21-0a1b2c3d4e61",
        "name": "Vulnerable",
        "object_types": ["executable"],
        "match": {"all": [
            {"criterion": {"field": "signer.publisher", "operator": "equals", "values": ["Vulnerable Ltd"], "safety_critical": true}},
            {"criterion": {"field": "meta.file_version", "operator": "version_lt", "values": ["3.2"], "safety_critical": true}},
        ]},
        "action": {"type": "deny"},
    });
    let p = doc(vec![scoped, expired], vec![critical]);
    let e = Evaluator::new(&p)
        .unwrap()
        .at(crate::lifecycle::RuleClock::at(crate::model::Timestamp(
            1_800_000_000,
        )));
    let variables = PathVariables::new();
    let state = DeviceState::of(&p.document().policy);
    let decide = |facts: &ObjectFacts, context: &EvaluationContext| {
        let s = Subject {
            object_type: ObjectType::Executable,
            facts,
            variables: &variables,
            context,
        };
        let indexed = e
            .evaluate_with(&s, FactSet::ALL, &state, TRACE)
            .unwrap()
            .unwrap();
        assert_eq!(indexed, e.evaluate_in(&s, &state, TRACE).unwrap());
        let (linear, notes) = e.matching_with_notes(&s);
        assert_eq!(
            e.matching(&s).iter().map(|r| r.rule.id).collect::<Vec<_>>(),
            linear.iter().map(|r| r.rule.id).collect::<Vec<_>>()
        );
        assert_eq!(indexed.scope_notes(), notes.iter().collect::<Vec<_>>());
        indexed
    };
    let mut console = EvaluationContext::new();
    console.session.session_type = Some(crate::context::SessionType::Console);
    let mut rdp = EvaluationContext::new();
    rdp.session.session_type = Some(crate::context::SessionType::Rdp);
    // In scope: allowed by the scoped rule; out of scope: not.
    // Signed by another publisher, so the safety-critical deny below is
    // `NoMatch` for them.
    let signed = |f: ObjectFacts| {
        f.with_signers(vec![SignerFact {
            status: SignerStatus::Valid,
            source: SignatureSource::Embedded,
            publisher: Some("Example Ltd".to_owned()),
            issuer: None,
            leaf_thumbprint_sha256: None,
            details: Default::default(),
        }])
    };
    let a = signed(exe_facts(Some('a'), r"C:\Tools\a.exe", Some(false)));
    assert_eq!(decide(&a, &console).outcome(), Outcome::Allowed);
    assert_ne!(decide(&a, &rdp).outcome(), Outcome::Allowed);
    // The expired allow never applies.
    let b = signed(exe_facts(Some('b'), r"C:\Tools\b.exe", Some(false)));
    assert!(decide(&b, &console).matched_rule().is_none());
    // Unsigned, with no version: the facts hold none of the deny's anchor
    // keys, and the safety-critical deny still fails closed.
    let c = exe_facts(Some('c'), r"C:\Tools\c.exe", Some(false));
    assert_eq!(
        decide(&c, &console).reason_code(),
        crate::decision::ReasonCode::MandatoryDeny
    );
}

#[test]
fn a_hash_rule_needs_the_hash_first() {
    let p = doc(
        vec![rule_json(
            1,
            "hash.sha256",
            "equals",
            &hex('a', 64),
            "allow",
        )],
        vec![rule_json(
            2,
            "signer.publisher",
            "equals",
            "Bad Ltd",
            "deny",
        )],
    );
    let facts = exe_facts(None, r"C:\x.exe", None);
    assert_eq!(
        evaluate_with(&p, &facts, FactSet::CHEAP),
        Err(NeedFacts(FactSet::hash(Field::HashSha256)))
    );
    // Then the signers, for the mandatory deny on the publisher.
    let facts = exe_facts(Some('a'), r"C:\x.exe", None);
    assert_eq!(
        evaluate_with(&p, &facts, FactSet::CHEAP),
        Err(NeedFacts(FactSet::SIGNERS))
    );
    let facts = facts.with_signers(vec![]);
    let d = evaluate_with(&p, &facts, FactSet::CHEAP).unwrap().unwrap();
    assert_eq!(d.outcome(), crate::decision::Outcome::Allowed);
}

#[test]
fn a_path_allow_needs_the_acl_only_when_its_prefix_matches() {
    let p = doc(
        vec![rule_json(
            1,
            "path.directory",
            "starts_with",
            r"C:\Tools",
            "allow",
        )],
        vec![],
    );
    assert_eq!(
        evaluate_with(
            &p,
            &exe_facts(None, r"C:\Tools\a.exe", None),
            FactSet::CHEAP
        ),
        Err(NeedFacts(FactSet::PATH_ACL))
    );
    let d = evaluate_with(
        &p,
        &exe_facts(None, r"C:\Tools\a.exe", Some(false)),
        FactSet::CHEAP,
    )
    .unwrap()
    .unwrap();
    assert_eq!(d.outcome(), crate::decision::Outcome::Allowed);
    // A deny on a path does not need the ACL.
    let p = doc(
        vec![rule_json(
            1,
            "path.directory",
            "starts_with",
            r"C:\Tools",
            "deny",
        )],
        vec![],
    );
    let d = evaluate_with(
        &p,
        &exe_facts(None, r"C:\Tools\a.exe", None),
        FactSet::CHEAP,
    )
    .unwrap()
    .unwrap();
    assert_eq!(d.reason_code(), crate::decision::ReasonCode::ExplicitDeny);
}

#[test]
fn a_declared_class_with_no_fact_is_unknown_not_needed() {
    let p = doc(
        vec![rule_json(
            1,
            "hash.sha256",
            "equals",
            &hex('a', 64),
            "allow",
        )],
        vec![],
    );
    // The agent computed the hash and could not get one (an unreadable
    // file): the rule is unknown, so the implicit deny decides.
    let d = evaluate_with(
        &p,
        &exe_facts(None, r"C:\x.exe", None),
        FactSet::CHEAP | FactSet::HASHES,
    )
    .unwrap()
    .unwrap();
    assert!(d.matched_rule().is_none());
}

#[test]
fn hash_sets_are_one_probe() {
    // 2,000 hash rules of 25 digests each: the index holds 50,000 keys and
    // one probe finds the rule.
    let rules: Vec<serde_json::Value> = (0..2000u32)
        .map(|n| {
            let values: Vec<String> = (0..25u32)
                .map(|k| format!("{:064x}", u64::from(n) * 25 + u64::from(k)))
                .collect();
            serde_json::json!({
                "id": format!("01936b2e-{:04x}-7b3d-9f21-0a1b2c3d4e61", n),
                "name": format!("Rule {n}"),
                "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": values}},
                "action": {"type": "allow"},
            })
        })
        .collect();
    let p = doc(rules, vec![]);
    let e = Evaluator::new(&p).unwrap();
    let stats = e.index_stats();
    assert_eq!(stats.indexed_rules, 2000);
    assert_eq!(stats.always_eval, 0);
    assert_eq!(stats.keys, 50_000);
    assert!(e.required_facts().hash_eagerly());
    let facts = ObjectFacts::new().with(Field::HashSha256, format!("{:064X}", 1234 * 25 + 7));
    let d = evaluate_with(&p, &facts, FactSet::CHEAP).unwrap().unwrap();
    assert_eq!(d.outcome(), crate::decision::Outcome::Allowed);
    assert_eq!(
        d.matched_rule().map(|r| r.rule_id.to_string()),
        Some(format!("01936b2e-{:04x}-7b3d-9f21-0a1b2c3d4e61", 1234))
    );
}

#[test]
fn wildcards_are_found_under_their_literal_part() {
    for pattern in [
        r"C:\Tools\*\*.exe",
        r"C:\Tools\Su?\tool.exe",
        r"C:\Tools\**",
        r"C:\To*\Sub\tool.exe",
    ] {
        let p = doc(
            vec![rule_json(1, "path.full", "wildcard", pattern, "deny")],
            vec![],
        );
        let e = Evaluator::new(&p).unwrap();
        let facts = exe_facts(None, r"C:\Tools\Sub\tool.exe", None);
        let v = PathVariables::new();
        let context = EvaluationContext::new();
        let s = Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &v,
            context: &context,
        };
        assert_eq!(e.index_stats().indexed_rules, 1, "{pattern}");
        assert_eq!(e.matching(&s).len(), 1, "{pattern}");
    }
}

#[test]
fn malformed_digests_find_nothing() {
    let p = doc(
        vec![rule_json(
            1,
            "hash.sha256",
            "equals",
            &hex('a', 64),
            "allow",
        )],
        vec![],
    );
    let facts = ObjectFacts::new().with(Field::HashSha256, "zz");
    let d = evaluate_with(&p, &facts, FactSet::CHEAP).unwrap().unwrap();
    assert!(d.matched_rule().is_none());
}

#[test]
fn fail_closed_denies_are_always_evaluated() {
    let json = serde_json::json!({
        "id": "01936b2e-0001-7b3d-9f21-0a1b2c3d4e61",
        "name": "Fail closed",
        "object_types": ["executable"],
        "match": {"criterion": {"field": "signer.publisher", "operator": "equals", "values": ["Bad"]}},
        "action": {"type": "deny", "unknown_as": "match"},
    });
    let p = doc(vec![json], vec![]);
    let e = Evaluator::new(&p).unwrap();
    assert_eq!(e.index_stats().always_eval, 1);
    // With the signers computed and unknown (absent), the deny applies.
    let facts = exe_facts(None, r"C:\x.exe", None);
    let d = evaluate_with(&p, &facts, FactSet::CHEAP | FactSet::SIGNERS)
        .unwrap()
        .unwrap();
    assert_eq!(d.reason_code(), crate::decision::ReasonCode::ExplicitDeny);
}

#[test]
fn variables_and_aliases_are_probed() {
    let p = doc(
        vec![rule_json(
            1,
            "path.full",
            "starts_with",
            r"%PROGRAMFILES%\App",
            "deny",
        )],
        vec![],
    );
    let e = Evaluator::new(&p).unwrap();
    let context = EvaluationContext::new();
    let facts = exe_facts(None, r"C:\Program Files\App\a.exe", None);
    let s = |v| Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: v,
        context: &context,
    };
    let set = variables();
    assert_eq!(e.matching(&s(&set)).len(), 1);
    assert_eq!(e.matching(&s(&PathVariables::new())).len(), 0);

    // A UNC rule matches a mapped drive through its alias.
    let p = doc(
        vec![rule_json(
            1,
            "path.directory",
            "equals",
            r"\\srv\share",
            "deny",
        )],
        vec![],
    );
    let e = Evaluator::new(&p).unwrap();
    let mut facts = exe_facts(None, r"Z:\x.exe", None);
    if let Some(path) = facts.path.as_mut() {
        path.alias = Some(palisade_core::path::normalize(r"\\srv\share\x.exe"));
    }
    let v = PathVariables::new();
    let s = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &v,
        context: &context,
    };
    assert_eq!(e.matching(&s).len(), 1);
    assert_eq!(e.matching(&s).len(), e.matching_linear(&s).len());
}

#[test]
fn principal_rules_are_indexed() {
    let json = serde_json::json!({
        "id": "01936b2e-0001-7b3d-9f21-0a1b2c3d4e61",
        "name": "Admins",
        "object_types": ["executable"],
        "match": {"all": [
            {"criterion": {"field": "path.directory", "operator": "starts_with", "values": ["C:\\Tools"]}},
            {"criterion": {"field": "user.groups", "operator": "member_of", "values": ["S-1-5-32-544"]}},
        ]},
        "action": {"type": "deny"},
    });
    let p = doc(vec![json], vec![]);
    let e = Evaluator::new(&p).unwrap();
    let facts = exe_facts(None, r"C:\Tools\a.exe", None);
    let v = PathVariables::new();
    let count = |c: &EvaluationContext| {
        e.matching(&Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &v,
            context: c,
        })
        .len()
    };
    let mut context = EvaluationContext::new();
    assert_eq!(count(&context), 0);
    context.user.groups = Some(vec!["s-1-5-32-544".into()]);
    assert_eq!(count(&context), 1);
}

#[test]
fn every_policy_model_agrees_on_a_large_policy() {
    // Many overlapping rules of every anchor kind, under each model.
    let mut rules = Vec::new();
    for n in 0..60u32 {
        let (field, op, value) = match n % 6 {
            0 => (
                "hash.sha256",
                "equals",
                hex(HASH_CHARS[(n % 3) as usize], 64),
            ),
            1 => (
                "signer.publisher",
                "equals",
                PUBLISHERS[(n % 3) as usize].to_owned(),
            ),
            2 => ("path.full", "wildcard", r"C:\Tools\*\*.exe".to_owned()),
            3 => ("path.directory", "starts_with", r"C:\Tools".to_owned()),
            4 => (
                "meta.product_name",
                "equals",
                PRODUCTS[(n % 3) as usize].to_owned(),
            ),
            _ => ("path.full", "equals", PATHS[(n % 4) as usize].to_owned()),
        };
        let action = if n % 4 == 0 { "deny" } else { "allow" };
        let mut r = rule_json(n + 1, field, op, &value, action);
        r["order"] = (200_000 + n).into();
        r["priority"] = n.into();
        rules.push(r);
    }
    for model in [
        PrecedenceModel::DenyWins,
        PrecedenceModel::AllowWins,
        PrecedenceModel::Specificity,
        PrecedenceModel::FirstMatch,
        PrecedenceModel::Priority,
    ] {
        let mut d = doc(rules.clone(), vec![]).into_document();
        d.policy.precedence_model = model;
        let p = d.validate().unwrap_or_else(|e| panic!("{e:#?}"));
        let e = Evaluator::new(&p).unwrap();
        let v = PathVariables::new();
        let context = EvaluationContext::new();
        for c in HASH_CHARS {
            for path in PATHS {
                let facts = exe_facts(Some(c), path, Some(false))
                    .with(Field::MetaProductName, "suite")
                    .with_signers(vec![SignerFact {
                        status: SignerStatus::Valid,
                        source: SignatureSource::Catalog,
                        publisher: Some("example ltd".into()),
                        issuer: None,
                        leaf_thumbprint_sha256: None,
                        details: Default::default(),
                    }]);
                let s = Subject {
                    object_type: ObjectType::Executable,
                    facts: &facts,
                    variables: &v,
                    context: &context,
                };
                let linear = e.evaluate_linear(&s, TRACE);
                assert_eq!(e.evaluate(&s, TRACE), linear, "{model:?} {c} {path}");
            }
        }
    }
}

#[test]
fn rule_kinds_reads() {
    let mut rule: Rule =
        serde_json::from_value(rule_json(1, "path.full", "equals", r"C:\a", "allow")).unwrap();
    assert_eq!(reads(&rule), FactSet::PATH | FactSet::PATH_ACL);
    rule.action = crate::model::Action::Deny(crate::model::DenyOptions::default());
    assert_eq!(reads(&rule), FactSet::PATH);
    let _ = RuleSetKind::Mixed;
}

/// The leaf TBS hash is an index anchor (#42, now that #316 has
/// `signer.tbs_hash`); a CA-position TBS hash is evaluated always. Either
/// way the decision is the linear scan's.
#[test]
fn a_leaf_tbs_hash_is_indexed_and_a_ca_one_is_not() {
    let tbs = |n: u32, position: &str| {
        serde_json::json!({"id": format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61"), "name": "T",
            "match": {"criterion": {"field": "signer.tbs_hash", "operator": "equals",
                "values": ["AB".repeat(32)], "signer": {"position": position}}},
            "action": {"type": "deny"}})
    };
    let leaf = doc(vec![tbs(1, "leaf")], vec![]);
    let e = Evaluator::new(&leaf).unwrap();
    assert_eq!(
        (e.index_stats().indexed_rules, e.index_stats().always_eval),
        (1, 0)
    );
    for position in ["root", "intermediate", "any"] {
        let ca = doc(vec![tbs(1, position)], vec![]);
        let e = Evaluator::new(&ca).unwrap();
        assert_eq!(e.index_stats().always_eval, 1, "{position}");
    }
    let variables = variables();
    let signer = |hash: Option<&str>| SignerFact {
        status: SignerStatus::Valid,
        source: SignatureSource::Embedded,
        publisher: Some("Example Ltd".into()),
        issuer: None,
        leaf_thumbprint_sha256: None,
        details: crate::facts::SignerDetails {
            leaf_tbs_hash: hash.map(str::to_owned),
            ..Default::default()
        },
    };
    for (hash, matches) in [
        (Some("ab".repeat(32)), true),
        (Some("AB".repeat(32)), true),
        (Some("cd".repeat(32)), false),
        (Some("not a digest".to_owned()), false),
        (None, false),
    ] {
        let pool = PoolFacts {
            facts: ObjectFacts::new().with_signers(vec![signer(hash.as_deref())]),
            context: EvaluationContext::new(),
        };
        let s = subject(ObjectType::Executable, &pool, &variables);
        let indexed = e_matching_ids(&leaf, &s);
        assert_eq!(indexed.len() == 1, matches, "{hash:?}");
        let e = Evaluator::new(&leaf).unwrap();
        assert_eq!(
            e.evaluate(&s, TRACE),
            e.evaluate_linear(&s, TRACE),
            "{hash:?}"
        );
    }
}

fn e_matching_ids(p: &ValidatedPolicy, s: &Subject<'_>) -> Vec<crate::model::RuleId> {
    let e = Evaluator::new(p).unwrap();
    let linear: Vec<_> = e.matching_linear(s).iter().map(|r| r.rule.id).collect();
    let indexed: Vec<_> = e.matching(s).iter().map(|r| r.rule.id).collect();
    assert_eq!(indexed, linear);
    indexed
}
