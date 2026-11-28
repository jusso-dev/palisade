//! A conservative proof that one match tree matches whenever another does
//! (#40): `covers(a, b)` is true only if every object and context for
//! which `b` is `Match` also makes `a` `Match`. It never claims more, so a
//! rule the policy assistant calls shadowed or ineffective truly never
//! decides. It does not find every such pair: an unproven pair is just not
//! reported.
//!
//! The proof works on the trees' shapes. `a` covers `b` when:
//!
//! - `b` is an `any`: `a` covers each child of `b`;
//! - `a` is an `all`: each child of `a` covers `b`;
//! - `a` is an `any`: some child of `a` covers `b`;
//! - `b` is an `all`: some child of `b` is covered by `a`;
//! - both are criteria, and the criterion `a` accepts every fact value the
//!   criterion `b` accepts ([`criterion_covers`]).
//!
//! `not` is only covered by an identical `not`. The order of these rules
//! matters only for how much is proven, never for soundness.

use crate::model::{Criterion, Field, FieldClass, Match, Operator};
use crate::ops::{Version, fold};

/// Whether `a` is `Match` whenever `b` is.
#[must_use]
pub fn covers(a: &Match, b: &Match) -> bool {
    covers_depth(a, b, 0)
}

/// The search is bounded: trees are at most 8 deep (#33), and the bound
/// keeps a hand-built deeper tree from recursing without limit.
const MAX_DEPTH: usize = 32;

fn covers_depth(a: &Match, b: &Match, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let d = depth + 1;
    // An unresolved library reference is never proven to match anything:
    // its tree is only known once the hierarchy expands it (#37).
    if matches!(a, Match::Ref(_)) || matches!(b, Match::Ref(_)) {
        return false;
    }
    if a == b && !contains_ref(a) {
        return true;
    }
    if let Match::Any(bs) = b {
        return !bs.is_empty() && bs.iter().all(|bc| covers_depth(a, bc, d));
    }
    if let Match::All(as_) = a {
        return !as_.is_empty() && as_.iter().all(|ac| covers_depth(ac, b, d));
    }
    if let Match::Any(as_) = a
        && as_.iter().any(|ac| covers_depth(ac, b, d))
    {
        return true;
    }
    if let Match::All(bs) = b
        && bs.iter().any(|bc| covers_depth(a, bc, d))
    {
        return true;
    }
    match (a, b) {
        (Match::Criterion(ca), Match::Criterion(cb)) => criterion_covers(ca, cb),
        _ => false,
    }
}

/// Whether a tree holds a library reference anywhere.
fn contains_ref(tree: &Match) -> bool {
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        match node {
            Match::Ref(_) => return true,
            Match::All(c) | Match::Any(c) => stack.extend(c),
            Match::Not(c) => stack.push(c),
            Match::Criterion(_) => {}
        }
    }
    false
}

/// Whether the criterion `a` is `Match` whenever `b` is.
///
/// Only cases whose meaning is fully known are proven: the same field, and
/// either the same operator with `a`'s values a superset of `b`'s (for a
/// positive operator, where any value matching suffices), or a version
/// range that contains another. Case sensitivity must agree, or `a` must
/// be case-insensitive while `b` is not, because folding only widens a
/// match. Likewise each option that widens a match (`anchored: false`,
/// `match_ads`, `include_sub_ous`, `safety_critical`, #32) set on `b` must
/// be set on `a`. Anything else is not proven.
#[must_use]
pub fn criterion_covers(a: &Criterion, b: &Criterion) -> bool {
    if a.field != b.field {
        return false;
    }
    // `a` insensitive and `b` sensitive is fine; the reverse is not.
    let a_sensitive = a.case_sensitive.unwrap_or(false);
    let b_sensitive = b.case_sensitive.unwrap_or(false);
    if a_sensitive && !b_sensitive {
        return false;
    }
    // Options that widen a match (#32): `a` must widen wherever `b` does.
    // An unanchored regex matches substrings, `match_ads` also matches a
    // file's streams, `include_sub_ous` also matches units below, and
    // `safety_critical` makes an unknown fact count as a match.
    let widens = |x: &Criterion| {
        [
            x.anchored == Some(false),
            x.match_ads == Some(true),
            x.include_sub_ous == Some(true),
            x.safety_critical,
        ]
    };
    if widens(b).iter().zip(widens(a)).any(|(&wb, wa)| wb && !wa) {
        return false;
    }
    // Signer options (#31) restrict which signatures take part and what
    // each must satisfy (`min_key_bits`, `accept_status`, the signature's
    // source and index, ...). They are not compared by strength, so a
    // proof needs them equal: otherwise `a` could reject a signature `b`
    // accepts, and a rule reported as covered would still decide.
    if a.signer != b.signer {
        return false;
    }
    // A probed field (#329) tests what its target names: two targets are
    // two facts.
    if a.target != b.target || a.value_name != b.value_name || a.arg_index != b.arg_index {
        return false;
    }
    let class = a.field.class();
    if matches!(class, FieldClass::Version)
        && let (Some(ra), Some(rb)) = (range(a), range(b))
    {
        return ra.0 <= rb.0 && rb.1 <= ra.1;
    }
    if a.operator != b.operator || !a.operator.is_positive() {
        return false;
    }
    match a.operator {
        Operator::IsTrue | Operator::IsFalse => true,
        // Patterns are compared as written: folding their text could change
        // what they mean (`\w` and `\W`). Case must then agree too.
        Operator::Wildcard | Operator::Regex => {
            a_sensitive == b_sensitive && b.values.iter().all(|v| a.values.contains(v))
        }
        Operator::Equals
        | Operator::MemberOf
        | Operator::EndsWith
        | Operator::Contains
        | Operator::StartsWith => {
            // Any value of `b` that matches is also a value of `a`.
            let key = |v: &str| value_key(a.field, v, a_sensitive);
            let theirs: Vec<String> = a.values.iter().map(|v| key(v)).collect();
            b.values.iter().all(|v| theirs.contains(&key(v)))
        }
        _ => false,
    }
}

/// How a value compares to another of the same field: hashes as lowercase
/// hex, paths after normalisation, text after case folding where the
/// match folds it.
fn value_key(field: Field, v: &str, case_sensitive: bool) -> String {
    match field.class() {
        FieldClass::Hash { .. } => crate::ops::normalize_hex(v).unwrap_or_else(|| v.to_owned()),
        FieldClass::Path => crate::ops::fold_path_value(&v.replace('/', "\\"), case_sensitive),
        _ if crate::ops::is_path_name(field) => crate::ops::fold_path_value(v, case_sensitive),
        _ if field.class().has_case() => fold(v, case_sensitive),
        _ => v.to_owned(),
    }
}

/// The closed version interval a version criterion accepts, if it is one
/// that can be compared: `version_eq` with one value, `version_ge`,
/// `version_le` and `version_between`. Strict bounds (`gt`, `lt`) are left
/// out, so no off-by-one can make a proof wrong.
fn range(c: &Criterion) -> Option<(Version, Version)> {
    const MIN: Version = Version([0; 4]);
    const MAX: Version = Version([u16::MAX; 4]);
    let v = |i: usize| c.values.get(i).and_then(|s| Version::parse_strict(s));
    Some(match c.operator {
        Operator::VersionEq if c.values.len() == 1 => (v(0)?, v(0)?),
        Operator::VersionGe => (v(0)?, MAX),
        Operator::VersionLe => (MIN, v(0)?),
        Operator::VersionBetween => (v(0)?, v(1)?),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(field: Field, op: Operator, values: &[&str]) -> Match {
        Match::Criterion(Criterion::new(field, op, values.iter().copied()))
    }

    #[test]
    fn values_and_structure() {
        let pub_ab = c(Field::SignerPublisher, Operator::Equals, &["A", "B"]);
        let pub_a = c(Field::SignerPublisher, Operator::Equals, &["a"]);
        let hash = c(Field::HashSha256, Operator::Equals, &["ab"]);
        assert!(covers(&pub_ab, &pub_a));
        assert!(!covers(&pub_a, &pub_ab));
        assert!(covers(
            &pub_a,
            &Match::All(vec![pub_a.clone(), hash.clone()])
        ));
        assert!(!covers(
            &Match::All(vec![pub_a.clone(), hash.clone()]),
            &pub_a
        ));
        assert!(covers(
            &Match::Any(vec![hash.clone(), pub_a.clone()]),
            &pub_a
        ));
        assert!(covers(
            &pub_ab,
            &Match::Any(vec![
                pub_a.clone(),
                c(Field::SignerPublisher, Operator::Equals, &["B"])
            ])
        ));
        let not = Match::Not(Box::new(hash.clone()));
        assert!(covers(&not, &not));
        assert!(!covers(&not, &hash));
        // Negative operators are never proven by value sets.
        let ne = c(Field::SignerPublisher, Operator::NotEquals, &["A", "B"]);
        assert!(!covers(
            &ne,
            &c(Field::SignerPublisher, Operator::NotEquals, &["A"])
        ));
    }

    #[test]
    fn versions_and_case() {
        let ge = c(Field::MetaFileVersion, Operator::VersionGe, &["1.0"]);
        let between = c(
            Field::MetaFileVersion,
            Operator::VersionBetween,
            &["1.2", "3"],
        );
        let gt = c(Field::MetaFileVersion, Operator::VersionGt, &["1.0"]);
        assert!(covers(&ge, &between));
        assert!(!covers(&between, &ge));
        assert!(!covers(&ge, &gt));
        let mut sensitive = Criterion::new(Field::MetaProductName, Operator::Equals, ["X"]);
        sensitive.case_sensitive = Some(true);
        let insensitive = Criterion {
            case_sensitive: None,
            ..sensitive.clone()
        };
        assert!(criterion_covers(&insensitive, &sensitive));
        assert!(!criterion_covers(&sensitive, &insensitive));
        sensitive.values = vec!["x".into()];
        assert!(criterion_covers(&insensitive, &sensitive));
        // Regular expressions are never folded.
        let re = |p: &str| Criterion::new(Field::MetaProductName, Operator::Regex, [p]);
        assert!(!criterion_covers(&re("\\W+"), &re("\\w+")));
        assert!(criterion_covers(&re("a|b"), &re("a|b")));
    }

    #[test]
    fn an_option_that_widens_b_must_widen_a() {
        let re = |anchored| {
            let mut c = Criterion::new(Field::MetaProductName, Operator::Regex, ["tool"]);
            c.anchored = anchored;
            c
        };
        assert!(criterion_covers(&re(Some(false)), &re(None)));
        assert!(!criterion_covers(&re(None), &re(Some(false))));
        assert!(!criterion_covers(&re(Some(true)), &re(Some(false))));
        let path = |ads| {
            let mut c = Criterion::new(Field::PathFull, Operator::Equals, ["C:\\a.exe"]);
            c.match_ads = ads;
            c
        };
        assert!(criterion_covers(&path(Some(true)), &path(None)));
        assert!(!criterion_covers(&path(None), &path(Some(true))));
        let ou = |sub| {
            let mut c = Criterion::new(Field::DeviceOu, Operator::Equals, ["OU=A,DC=corp"]);
            c.include_sub_ous = sub;
            c
        };
        assert!(criterion_covers(&ou(Some(true)), &ou(None)));
        assert!(!criterion_covers(&ou(Some(false)), &ou(Some(true))));
        let mut critical = Criterion::new(Field::MetaFileVersion, Operator::VersionLe, ["3.2"]);
        critical.safety_critical = true;
        let plain = Criterion::new(Field::MetaFileVersion, Operator::VersionLe, ["3.2"]);
        assert!(criterion_covers(&critical, &plain));
        assert!(!criterion_covers(&plain, &critical));
    }
}
