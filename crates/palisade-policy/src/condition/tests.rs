//! Tests for match-tree evaluation (#33).

use proptest::prelude::*;

use super::{CompiledMatch, TreeError};
use crate::context::EvaluationContext;
use crate::facts::{ObjectFacts, PathVariables};
use crate::model::limits::{MAX_CRITERIA_PER_RULE, MAX_TREE_DEPTH};
use crate::model::{ActionKind, Criterion, Field, Match, Operator};
use crate::ops::{EvalContext, Note, Tri};

use Tri::{Match as Yes, NoMatch as No, Unknown};

fn crit(field: Field, operator: Operator, values: &[&str]) -> Match {
    Match::Criterion(Criterion {
        field,
        operator,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive: None,
    })
}

/// A criterion with a known result under [`context`]: `user.is_admin` is
/// true, and `user.is_elevated` was not collected.
fn leaf(result: Tri) -> Match {
    match result {
        Yes => crit(Field::UserIsAdmin, Operator::IsTrue, &[]),
        No => crit(Field::UserIsAdmin, Operator::IsFalse, &[]),
        Unknown => crit(Field::UserIsElevated, Operator::IsTrue, &[]),
    }
}

fn context() -> EvaluationContext {
    let mut ctx = EvaluationContext::new();
    ctx.user.is_admin = Some(true);
    ctx
}

fn eval_tree(tree: &Match) -> (Tri, crate::ops::Notes) {
    let compiled = CompiledMatch::compile(tree).unwrap();
    let variables = PathVariables::new();
    let context = context();
    let e = compiled.eval(
        &ObjectFacts::new(),
        &EvalContext {
            action: ActionKind::Deny,
            variables: &variables,
            context: &context,
        },
    );
    (e.result, e.notes)
}

/// The obvious recursive evaluator, with no short-circuit and no arena.
fn reference(tree: &Match) -> Tri {
    match tree {
        Match::All(children) => children.iter().map(reference).fold(Yes, Tri::and),
        Match::Any(children) => children.iter().map(reference).fold(No, Tri::or),
        Match::Not(child) => reference(child).not(),
        Match::Criterion(c) => match (c.field, c.operator) {
            (Field::UserIsAdmin, Operator::IsTrue) => Yes,
            (Field::UserIsAdmin, Operator::IsFalse) => No,
            _ => Unknown,
        },
    }
}

/// The next number from a 64-bit LCG (Knuth's MMIX constants): enough
/// to vary the order.
fn next(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed >> 33
}

/// The same tree with the children of every group permuted, driven by
/// `seed`.
fn permute(tree: &Match, seed: &mut u64) -> Match {
    match tree {
        Match::All(children) | Match::Any(children) => {
            let mut items: Vec<Match> = children.iter().map(|c| permute(c, seed)).collect();
            for i in (1..items.len()).rev() {
                let j = usize::try_from(next(seed) % (i as u64 + 1)).unwrap();
                items.swap(i, j);
            }
            if matches!(tree, Match::All(_)) {
                Match::All(items)
            } else {
                Match::Any(items)
            }
        }
        Match::Not(child) => Match::Not(Box::new(permute(child, seed))),
        Match::Criterion(_) => tree.clone(),
    }
}

/// Random trees within the limits, over leaves with known results.
fn tree() -> impl Strategy<Value = Match> {
    let leaf = prop_oneof![Just(Yes), Just(No), Just(Unknown)].prop_map(leaf);
    leaf.prop_recursive(6, 30, 5, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 1..5).prop_map(Match::All),
            proptest::collection::vec(inner.clone(), 1..5).prop_map(Match::Any),
            inner.prop_map(|m| Match::Not(Box::new(m))),
        ]
    })
    .prop_filter("within the limits", |t| {
        t.depth() <= MAX_TREE_DEPTH && super::leaf_count(t) <= MAX_CRITERIA_PER_RULE
    })
}

proptest! {
    #[test]
    fn evaluation_agrees_with_the_reference(t in tree()) {
        prop_assert_eq!(eval_tree(&t).0, reference(&t));
    }

    #[test]
    fn child_order_never_changes_the_result(t in tree(), seed in any::<u64>()) {
        let mut seed = seed;
        let shuffled = permute(&t, &mut seed);
        prop_assert_eq!(eval_tree(&shuffled).0, eval_tree(&t).0);
    }

    #[test]
    fn de_morgan_holds(t in proptest::collection::vec(tree(), 1..4)) {
        // not(all(xs)) == any(not(x) for x in xs), in three-valued logic.
        let lhs = Match::Not(Box::new(Match::All(t.clone())));
        let rhs = Match::Any(t.into_iter().map(|x| Match::Not(Box::new(x))).collect());
        if lhs.depth() <= MAX_TREE_DEPTH && rhs.depth() <= MAX_TREE_DEPTH
            && super::leaf_count(&lhs) <= MAX_CRITERIA_PER_RULE
        {
            prop_assert_eq!(eval_tree(&lhs).0, eval_tree(&rhs).0);
        }
    }
}

#[test]
fn kleene_truth_tables() {
    // Written out cell by cell, so a regression in `Tri` itself is caught.
    let and = [
        (Yes, Yes, Yes),
        (Yes, No, No),
        (Yes, Unknown, Unknown),
        (No, Yes, No),
        (No, No, No),
        (No, Unknown, No),
        (Unknown, Yes, Unknown),
        (Unknown, No, No),
        (Unknown, Unknown, Unknown),
    ];
    let or = [
        (Yes, Yes, Yes),
        (Yes, No, Yes),
        (Yes, Unknown, Yes),
        (No, Yes, Yes),
        (No, No, No),
        (No, Unknown, Unknown),
        (Unknown, Yes, Yes),
        (Unknown, No, Unknown),
        (Unknown, Unknown, Unknown),
    ];
    for (a, b, want) in and {
        let tree = Match::All(vec![leaf(a), leaf(b)]);
        assert_eq!(eval_tree(&tree).0, want, "{a:?} and {b:?}");
    }
    for (a, b, want) in or {
        let tree = Match::Any(vec![leaf(a), leaf(b)]);
        assert_eq!(eval_tree(&tree).0, want, "{a:?} or {b:?}");
    }
    for (a, want) in [(Yes, No), (No, Yes), (Unknown, Unknown)] {
        assert_eq!(
            eval_tree(&Match::Not(Box::new(leaf(a)))).0,
            want,
            "not {a:?}"
        );
    }
    // `all` of unknown and match is unknown, and `any` of unknown and no
    // match is unknown: neither becomes a match.
    assert_eq!(
        eval_tree(&Match::All(vec![leaf(Unknown), leaf(Yes)])).0,
        Unknown
    );
    assert_eq!(
        eval_tree(&Match::Any(vec![leaf(Unknown), leaf(No)])).0,
        Unknown
    );
    // A negated unknown is unknown.
    assert_eq!(eval_tree(&Match::Not(Box::new(leaf(Unknown)))).0, Unknown);
}

#[test]
fn groups_stop_at_a_deciding_child() {
    // The unknown leaf after a deciding child is never evaluated, so its
    // note is not recorded.
    let (result, notes) = eval_tree(&Match::All(vec![leaf(No), leaf(Unknown)]));
    assert_eq!(result, No);
    assert!(!notes.contains(Note::FactMissing));
    let (result, notes) = eval_tree(&Match::Any(vec![leaf(Yes), leaf(Unknown)]));
    assert_eq!(result, Yes);
    assert!(!notes.contains(Note::FactMissing));
    // Before the deciding child, it is.
    let (result, notes) = eval_tree(&Match::All(vec![leaf(Unknown), leaf(No)]));
    assert_eq!(result, No);
    assert!(notes.contains(Note::FactMissing));
}

#[test]
fn only_match_makes_a_rule_match() {
    let compiled = CompiledMatch::compile(&leaf(Unknown)).unwrap();
    let variables = PathVariables::new();
    let context = context();
    for action in [ActionKind::Allow, ActionKind::Deny, ActionKind::Audit] {
        let e = compiled.eval(
            &ObjectFacts::new(),
            &EvalContext {
                action,
                variables: &variables,
                context: &context,
            },
        );
        assert_eq!(e.result, Unknown);
        assert!(!e.matches(), "{action:?}");
    }
    let compiled = CompiledMatch::compile(&leaf(Yes)).unwrap();
    let e = compiled.eval(
        &ObjectFacts::new(),
        &EvalContext {
            action: ActionKind::Allow,
            variables: &variables,
            context: &context,
        },
    );
    assert!(e.matches());
}

#[test]
fn identity_and_context_together() {
    // A publisher, for administrators only.
    let tree = Match::All(vec![
        crit(
            Field::SignerPublisher,
            Operator::Equals,
            &["Example Tools Ltd"],
        ),
        crit(Field::UserGroups, Operator::MemberOf, &["S-1-5-32-544"]),
    ]);
    let compiled = CompiledMatch::compile(&tree).unwrap();
    let facts = ObjectFacts::new().with_signers(vec![crate::facts::SignerFact {
        status: crate::facts::SignerStatus::Valid,
        source: crate::facts::SignatureSource::Embedded,
        publisher: Some("Example Tools Ltd".to_owned()),
        issuer: None,
        leaf_thumbprint_sha256: None,
    }]);
    let variables = PathVariables::new();
    let run = |context: &EvaluationContext| {
        compiled
            .eval(
                &facts,
                &EvalContext {
                    action: ActionKind::Allow,
                    variables: &variables,
                    context,
                },
            )
            .result
    };
    let mut admin = EvaluationContext::new();
    admin.user.groups = Some(vec!["S-1-5-32-544".to_owned()]);
    let mut user = EvaluationContext::new();
    user.user.groups = Some(vec!["S-1-5-32-545".to_owned()]);
    assert_eq!(run(&admin), Yes);
    assert_eq!(run(&user), No);
    // Unknown membership fails closed.
    assert_eq!(run(&EvaluationContext::new()), Unknown);
    assert_eq!(compiled.criteria().len(), 2);
}

#[test]
fn compile_checks_the_limits() {
    let mut deep = leaf(Yes);
    for _ in 0..MAX_TREE_DEPTH {
        deep = Match::Not(Box::new(deep));
    }
    assert_eq!(
        CompiledMatch::compile(&deep).unwrap_err(),
        vec![TreeError::TooDeep]
    );

    let wide = Match::Any(vec![leaf(Yes); MAX_CRITERIA_PER_RULE + 1]);
    assert_eq!(
        CompiledMatch::compile(&wide).unwrap_err(),
        vec![TreeError::TooManyCriteria]
    );
    let full = Match::Any(vec![leaf(Yes); MAX_CRITERIA_PER_RULE]);
    assert!(CompiledMatch::compile(&full).is_ok());

    // A very deep tree is rejected without recursion.
    let mut hostile = leaf(Yes);
    for _ in 0..100_000 {
        hostile = Match::Not(Box::new(hostile));
    }
    assert_eq!(
        CompiledMatch::compile(&hostile).unwrap_err(),
        vec![TreeError::TooDeep]
    );
}

#[test]
fn compile_enforces_value_bytes_and_case_like_validation() {
    use crate::model::limits::MAX_VALUE_BYTES;
    use crate::ops::{CompileError, CompileErrorKind};

    // A tag of exactly the limit compiles; one byte more does not.
    let at_limit = "t".repeat(MAX_VALUE_BYTES);
    let over = "t".repeat(MAX_VALUE_BYTES + 1);
    assert!(
        CompiledMatch::compile(&crit(Field::DeviceTags, Operator::MemberOf, &[&at_limit])).is_ok()
    );
    let errors =
        CompiledMatch::compile(&crit(Field::DeviceTags, Operator::MemberOf, &["ok", &over]))
            .unwrap_err();
    let [TreeError::Criterion { pointer, errors }] = errors.as_slice() else {
        panic!("{errors:?}");
    };
    assert_eq!(pointer, "/criterion");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].value, Some(1));
    assert!(
        matches!(&errors[0].kind, CompileErrorKind::InvalidValue(why) if why.contains("at most 2048")),
        "{errors:?}"
    );

    // `case_sensitive` on a field with no case is rejected even when it is
    // `false`, which is also the default; leaving it out still compiles.
    for case in [Some(false), Some(true)] {
        let tree = Match::All(vec![
            leaf(Yes),
            Match::Criterion(Criterion {
                field: Field::UserIsAdmin,
                operator: Operator::IsTrue,
                values: Vec::new(),
                case_sensitive: case,
            }),
        ]);
        assert_eq!(
            CompiledMatch::compile(&tree).unwrap_err(),
            vec![TreeError::Criterion {
                pointer: "/all/1/criterion".to_owned(),
                errors: vec![CompileError {
                    value: None,
                    kind: CompileErrorKind::CaseSensitivityNotApplicable,
                }],
            }],
            "{case:?}"
        );
    }
    assert!(CompiledMatch::compile(&leaf(Yes)).is_ok());
    // A field with a case still takes the option.
    let tag = Match::Criterion(Criterion {
        field: Field::DeviceTags,
        operator: Operator::MemberOf,
        values: vec!["Finance".to_owned()],
        case_sensitive: Some(true),
    });
    assert!(CompiledMatch::compile(&tag).is_ok());
}

#[test]
fn compile_reports_every_bad_node_with_its_pointer() {
    let tree = Match::All(vec![
        leaf(Yes),
        Match::Any(Vec::new()),
        Match::Not(Box::new(crit(Field::UserSid, Operator::Equals, &["alice"]))),
        crit(Field::HashSha256, Operator::Contains, &["ab"]),
    ]);
    let errors = CompiledMatch::compile(&tree).unwrap_err();
    let pointers: Vec<&str> = errors
        .iter()
        .map(|e| match e {
            TreeError::EmptyGroup { pointer } | TreeError::Criterion { pointer, .. } => {
                pointer.as_str()
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        pointers,
        ["/all/1/any", "/all/2/not/criterion", "/all/3/criterion"]
    );
}

/// Evaluates with facts whose file version is not a version, and whose
/// SHA-256 is `a`×64.
fn eval_unparseable(tree: &Match, unparseable: super::Unparseable) -> Tri {
    let compiled = CompiledMatch::compile(tree).unwrap();
    let variables = PathVariables::new();
    let context = context();
    let facts = ObjectFacts::new()
        .with(Field::MetaFileVersion, "not a version")
        .with(Field::HashSha256, "a".repeat(64));
    compiled
        .eval_with(
            &facts,
            &EvalContext {
                action: ActionKind::Deny,
                variables: &variables,
                context: &context,
            },
            unparseable,
        )
        .result
}

#[test]
fn unparseable_versions_favour_the_match_only_when_asked() {
    use super::Unparseable::{FavourMatch, Unknown as Keep};
    let older = crit(Field::MetaFileVersion, Operator::VersionLt, &["2.0"]);
    let hash = crit(Field::HashSha256, Operator::Equals, &[&"a".repeat(64)]);
    let other_hash = crit(Field::HashSha256, Operator::Equals, &[&"b".repeat(64)]);
    let missing = crit(Field::MetaProductVersion, Operator::VersionLt, &["2.0"]);
    let not = |m: &Match| Match::Not(Box::new(m.clone()));
    let cases = [
        // (tree, default, with on_unparseable: match)
        (older.clone(), Unknown, Yes),
        // Under `not`, the criterion is taken as `NoMatch`, so the `not`
        // matches: still in the direction of the deny applying.
        (not(&older), Unknown, Yes),
        (not(&not(&older)), Unknown, Yes),
        (Match::All(vec![hash.clone(), older.clone()]), Unknown, Yes),
        // The rest of the tree still has to match.
        (Match::All(vec![other_hash.clone(), older.clone()]), No, No),
        (Match::Any(vec![other_hash, not(&older)]), Unknown, Yes),
        // Only unparseable versions change: a missing fact stays unknown.
        (missing.clone(), Unknown, Unknown),
        (Match::All(vec![hash, missing]), Unknown, Unknown),
    ];
    for (tree, default, favoured) in cases {
        assert_eq!(eval_unparseable(&tree, Keep), default, "{tree:?}");
        assert_eq!(eval_unparseable(&tree, FavourMatch), favoured, "{tree:?}");
    }
}
