//! Property tests of four-part version comparison (#25): every version
//! operator, and `version_between` with its inclusive bounds, agree with a
//! reference that compares the four parts as plain integers.
//!
//! The reference is deliberately naive: it turns each version into one
//! 64-bit number (`a << 48 | b << 32 | c << 16 | d`), so its ordering cannot
//! share a bug with the engine's part-by-part comparison. Values are drawn
//! close to each other, so off-by-one bugs at the bounds are found quickly.
//!
//! proptest saves failing cases next to this file, in
//! `version_properties.proptest-regressions`, and replays them first on every
//! run (docs/testing.md#property-tests).
//!
//! Checked by planting bugs: an exclusive maximum in `version_between`, and
//! `version_ge` as `>`, each failed `between_is_inclusive_at_both_ends` or
//! `comparisons_agree_with_the_reference` at once, with equal versions as
//! the shrunk case.

#![allow(clippy::unwrap_used)]

use palisade_policy::context::EvaluationContext;
use palisade_policy::facts::{ObjectFacts, PathVariables};
use palisade_policy::model::{ActionKind, Criterion, Field, Operator};
use palisade_policy::ops::{CompiledCriterion, EvalContext, Tri};
use proptest::prelude::*;

type Quad = [u16; 4];

/// The reference: the version as one integer.
fn key(v: Quad) -> u64 {
    v.iter().fold(0, |acc, part| (acc << 16) | u64::from(*part))
}

fn text(v: Quad) -> String {
    format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])
}

/// A version near `base`: each part moved by at most one, saturating, or
/// set to 0 or 65535. Neighbours exercise every bound.
fn near(base: Quad) -> impl Strategy<Value = Quad> {
    let part = |p: u16| {
        prop_oneof![
            Just(p),
            Just(p.saturating_add(1)),
            Just(p.saturating_sub(1)),
            Just(0),
            Just(u16::MAX),
        ]
    };
    (part(base[0]), part(base[1]), part(base[2]), part(base[3]))
        .prop_map(|(a, b, c, d)| [a, b, c, d])
}

fn quad() -> impl Strategy<Value = Quad> {
    prop_oneof![
        any::<Quad>(),
        // Small parts, as real versions have.
        [0..4u16, 0..4u16, 0..4u16, 0..4u16],
    ]
}

/// `(fact, value)`, with the value usually near the fact.
fn pair() -> impl Strategy<Value = (Quad, Quad)> {
    quad().prop_flat_map(|fact| (Just(fact), prop_oneof![near(fact), quad()]))
}

fn eval(operator: Operator, values: &[String], fact: Quad, action: ActionKind) -> Tri {
    let criterion = Criterion {
        field: Field::MetaFileVersion,
        operator,
        values: values.to_vec(),
        case_sensitive: None,
        anchored: None,
        match_ads: None,
        include_sub_ous: None,
        safety_critical: false,
        signer: None,
    };
    let compiled = CompiledCriterion::compile(&criterion).unwrap();
    let facts = ObjectFacts::new().with(Field::MetaFileVersion, text(fact));
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let ctx = EvalContext {
        action,
        variables: &variables,
        context: &context,
    };
    compiled.eval(&facts, &ctx).result
}

fn expect(matches: bool) -> Tri {
    if matches { Tri::Match } else { Tri::NoMatch }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Every single-value operator orders versions like the reference, the
    /// same way in allow and deny rules.
    #[test]
    fn comparisons_agree_with_the_reference((fact, value) in pair(), deny in any::<bool>()) {
        let action = if deny { ActionKind::Deny } else { ActionKind::Allow };
        let (f, v) = (key(fact), key(value));
        for (operator, holds) in [
            (Operator::VersionEq, f == v),
            (Operator::VersionGt, f > v),
            (Operator::VersionGe, f >= v),
            (Operator::VersionLt, f < v),
            (Operator::VersionLe, f <= v),
        ] {
            prop_assert_eq!(
                eval(operator, &[text(value)], fact, action),
                expect(holds),
                "{} {:?} {}", text(fact), operator, text(value)
            );
        }
    }

    /// `version_between` includes both bounds and nothing outside them.
    #[test]
    fn between_is_inclusive_at_both_ends(
        (fact, a) in pair(),
        b in quad(),
        deny in any::<bool>(),
    ) {
        let action = if deny { ActionKind::Deny } else { ActionKind::Allow };
        let (min, max) = if key(a) <= key(b) { (a, b) } else { (b, a) };
        let holds = key(min) <= key(fact) && key(fact) <= key(max);
        prop_assert_eq!(
            eval(Operator::VersionBetween, &[text(min), text(max)], fact, action),
            expect(holds),
            "{} in [{}, {}]", text(fact), text(min), text(max)
        );
        // Each bound is in the range.
        let bounds = [text(min), text(max)];
        prop_assert_eq!(eval(Operator::VersionBetween, &bounds, min, action), Tri::Match);
        prop_assert_eq!(eval(Operator::VersionBetween, &bounds, max, action), Tri::Match);
    }

    /// Short forms mean the missing parts are zero: `1.2` is `1.2.0.0`.
    #[test]
    fn short_versions_pad_with_zeros(v in quad(), parts in 1..=4usize) {
        let mut padded = v;
        for p in padded.iter_mut().skip(parts) {
            *p = 0;
        }
        let short: Vec<String> = padded[..parts].iter().map(u16::to_string).collect();
        prop_assert_eq!(
            eval(Operator::VersionEq, &[short.join(".")], padded, ActionKind::Allow),
            Tri::Match
        );
    }
}
