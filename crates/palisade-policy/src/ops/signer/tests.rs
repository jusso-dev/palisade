//! Tests for signer criteria (#31): each criterion and option gives
//! `Match`, `NoMatch` and `Unknown`, and an absent fact is never a match.

use proptest::prelude::*;

use crate::context::EvaluationContext;
use crate::facts::{
    DigestAlgorithm, KeyFact, KeyKind, ObjectFacts, PathVariables, SignatureSource, SignerDetails,
    SignerFact, SignerStatus,
};
use crate::model::{
    ActionKind, Criterion, Field, Operator, SignerOptions, SignerSource, Strength,
    SubjectComponent, TbsPosition,
};
use crate::ops::{CompileErrorKind, CompiledCriterion, EvalContext, Note, Tri};

use Tri::{Match, NoMatch, Unknown};

static NO_CONTEXT: EvaluationContext = EvaluationContext::EMPTY;

const LEAF_TBS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const MID_TBS: &str = "2222222222222222222222222222222222222222";
const ROOT_TBS: &str = "33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";
const LEAF_KEY: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const MID_KEY: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const ROOT_KEY: &str = "6666666666666666666666666666666666666666666666666666666666666666";
const LEAF_SHA1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROOT_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_SHA1: &str = "cccccccccccccccccccccccccccccccccccccccc";
const CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
/// 2024-01-01T00:00:00Z.
const JAN_2024: i64 = 1_704_067_200;

/// A valid embedded signature with every fact known.
fn full() -> SignerFact {
    SignerFact {
        publisher: Some("Example Software Ltd".to_owned()),
        issuer: Some("Example Issuing CA".to_owned()),
        leaf_thumbprint_sha256: Some(LEAF_TBS.replace('1', "d")),
        details: SignerDetails {
            subject_organization: Some("Example Software".to_owned()),
            subject_dn: Some("CN=Example Software Ltd,O=Example Software,C=AU".to_owned()),
            leaf_thumbprint_sha1: Some(LEAF_SHA1.to_owned()),
            pca: Some("Example Code Signing PCA".to_owned()),
            root_thumbprint_sha256: Some(ROOT_SHA256.to_owned()),
            root_thumbprint_sha1: Some(ROOT_SHA1.to_owned()),
            leaf_tbs_hash: Some(LEAF_TBS.to_owned()),
            intermediate_tbs_hashes: Some(vec![MID_TBS.to_owned()]),
            root_tbs_hash: Some(ROOT_TBS.to_owned()),
            leaf_spki_sha256: Some(LEAF_KEY.to_owned()),
            intermediate_spki_sha256: Some(vec![MID_KEY.to_owned()]),
            root_spki_sha256: Some(ROOT_KEY.to_owned()),
            eku: Some(vec![CODE_SIGNING.to_owned()]),
            timestamp: Some(JAN_2024 + 86_400),
            countersigned: Some(true),
            keys: Some(vec![
                KeyFact {
                    kind: KeyKind::Rsa,
                    bits: 3072,
                },
                KeyFact {
                    kind: KeyKind::Ec,
                    bits: 384,
                },
            ]),
            algorithms: Some(vec![DigestAlgorithm::Sha256, DigestAlgorithm::Sha384]),
        },
        ..SignerFact::new(SignerStatus::Valid, SignatureSource::Embedded)
    }
}

/// A valid embedded signature with nothing known but its status.
fn bare() -> SignerFact {
    SignerFact::new(SignerStatus::Valid, SignatureSource::Embedded)
}

fn with_status(status: SignerStatus) -> SignerFact {
    SignerFact { status, ..full() }
}

fn crit(field: Field, operator: Operator, values: &[&str], o: SignerOptions) -> Criterion {
    Criterion {
        signer: Some(Box::new(o)),
        ..Criterion::new(field, operator, values.iter().copied())
    }
}

fn compile(c: &Criterion) -> CompiledCriterion {
    CompiledCriterion::compile(c).unwrap_or_else(|e| panic!("{c:?}: {e:?}"))
}

fn run(
    c: &CompiledCriterion,
    signers: Option<Vec<SignerFact>>,
    action: ActionKind,
) -> (Tri, bool, bool) {
    let mut facts = ObjectFacts::new();
    facts.signers = signers;
    let variables = PathVariables::new();
    let ctx = EvalContext {
        action,
        variables: &variables,
        context: &NO_CONTEXT,
    };
    let e = c.eval(&facts, &ctx);
    (
        e.result,
        e.notes.contains(Note::FactMissing),
        e.notes.contains(Note::SignerNotTrusted),
    )
}

/// Evaluates in an allow rule, whose fail-closed behaviour matters most.
fn eval(c: &Criterion, signers: Vec<SignerFact>) -> Tri {
    run(&compile(c), Some(signers), ActionKind::Allow).0
}

/// `Match` on [`full`], `NoMatch` with `miss` applied, and `Unknown` with
/// `forget` applied, in both an allow and a deny; the negated operator is
/// the Kleene complement each time, so an unknown fact never lets a
/// negation match either.
fn three_ways(c: &Criterion, miss: impl Fn(&mut SignerFact), forget: impl Fn(&mut SignerFact)) {
    let mut missed = full();
    miss(&mut missed);
    let mut forgotten = full();
    forget(&mut forgotten);
    let negated = Criterion {
        operator: match c.operator {
            Operator::Equals => Operator::NotEquals,
            Operator::MemberOf => Operator::NotMemberOf,
            other => other,
        },
        ..c.clone()
    };
    for action in [ActionKind::Allow, ActionKind::Deny] {
        for (signer, expected) in [
            (full(), Match),
            (missed.clone(), NoMatch),
            (forgotten.clone(), Unknown),
        ] {
            let got = run(&compile(c), Some(vec![signer.clone()]), action).0;
            assert_eq!(got, expected, "{:?} {action:?} {signer:#?}", c.field);
            if negated.operator != c.operator {
                let neg = run(&compile(&negated), Some(vec![signer]), action).0;
                assert_eq!(neg, expected.not(), "not {:?}", c.field);
            }
        }
    }
}

fn opts() -> SignerOptions {
    SignerOptions::default()
}

#[test]
fn publisher_components() {
    let cn = crit(
        Field::SignerPublisher,
        Operator::Equals,
        &["example software ltd"],
        opts(),
    );
    three_ways(
        &cn,
        |s| s.publisher = Some("Other".into()),
        |s| s.publisher = None,
    );
    let o = crit(
        Field::SignerPublisher,
        Operator::Equals,
        &["Example Software"],
        SignerOptions {
            component: Some(SubjectComponent::O),
            ..opts()
        },
    );
    three_ways(
        &o,
        |s| s.details.subject_organization = Some("Other".into()),
        |s| s.details.subject_organization = None,
    );
    // The CN does not stand in for an unknown O.
    let mut no_o = full();
    no_o.details.subject_organization = None;
    assert_eq!(eval(&o, vec![no_o]), Unknown);
    let dn = crit(
        Field::SignerPublisher,
        Operator::Wildcard,
        &["CN=Example Software Ltd,*"],
        SignerOptions {
            component: Some(SubjectComponent::FullDn),
            ..opts()
        },
    );
    three_ways(
        &dn,
        |s| s.details.subject_dn = Some("CN=Other,O=Example Software".into()),
        |s| s.details.subject_dn = None,
    );
}

#[test]
fn pca_and_issuer() {
    let pca = crit(
        Field::SignerPca,
        Operator::Equals,
        &["Example Code Signing PCA"],
        opts(),
    );
    three_ways(
        &pca,
        |s| s.details.pca = Some("Other PCA".into()),
        |s| s.details.pca = None,
    );
    let issuer = crit(
        Field::SignerIssuer,
        Operator::Equals,
        &["Example Issuing CA"],
        opts(),
    );
    three_ways(
        &issuer,
        |s| s.issuer = Some("Other".into()),
        |s| s.issuer = None,
    );
}

#[test]
fn thumbprints() {
    let leaf1 = crit(
        Field::SignerLeafThumbprintSha1,
        Operator::Equals,
        &[&LEAF_SHA1.to_ascii_uppercase()],
        opts(),
    );
    three_ways(
        &leaf1,
        |s| s.details.leaf_thumbprint_sha1 = Some(ROOT_SHA1.into()),
        |s| s.details.leaf_thumbprint_sha1 = None,
    );
    let root = crit(
        Field::SignerRootThumbprint,
        Operator::Equals,
        &[&format!("0x{ROOT_SHA256}")],
        opts(),
    );
    three_ways(
        &root,
        |s| s.details.root_thumbprint_sha256 = Some(LEAF_TBS.into()),
        |s| s.details.root_thumbprint_sha256 = None,
    );
    let root1 = crit(
        Field::SignerRootThumbprintSha1,
        Operator::Equals,
        &[ROOT_SHA1],
        opts(),
    );
    three_ways(
        &root1,
        |s| s.details.root_thumbprint_sha1 = Some(LEAF_SHA1.into()),
        |s| s.details.root_thumbprint_sha1 = None,
    );
    // A thumbprint of the wrong length is a malformed fact: unknown.
    let mut short = full();
    short.details.root_thumbprint_sha1 = Some("abc".into());
    assert_eq!(eval(&root1, vec![short]), Unknown);
    // Lengths are checked per field.
    assert!(
        CompiledCriterion::compile(&crit(
            Field::SignerRootThumbprint,
            Operator::Equals,
            &[ROOT_SHA1],
            opts()
        ))
        .is_err()
    );
}

#[test]
fn tbs_hash_positions() {
    let at = |position, value: &str| {
        crit(
            Field::SignerTbsHash,
            Operator::Equals,
            &[value],
            SignerOptions { position, ..opts() },
        )
    };
    three_ways(
        &at(Some(TbsPosition::Leaf), LEAF_TBS),
        |s| s.details.leaf_tbs_hash = Some(ROOT_TBS.into()),
        |s| s.details.leaf_tbs_hash = None,
    );
    three_ways(
        &at(
            Some(TbsPosition::Intermediate),
            &MID_TBS.to_ascii_uppercase(),
        ),
        |s| s.details.intermediate_tbs_hashes = Some(vec![]),
        |s| s.details.intermediate_tbs_hashes = None,
    );
    three_ways(
        &at(Some(TbsPosition::Root), ROOT_TBS),
        |s| s.details.root_tbs_hash = Some(LEAF_TBS.into()),
        |s| s.details.root_tbs_hash = None,
    );
    // A hash at another position does not match.
    assert_eq!(
        eval(&at(Some(TbsPosition::Leaf), ROOT_TBS), vec![full()]),
        NoMatch
    );
    assert_eq!(
        eval(&at(Some(TbsPosition::Root), MID_TBS), vec![full()]),
        NoMatch
    );
    // `any` (the default) finds each, and is unknown while any position
    // that could hold it is unknown.
    for value in [LEAF_TBS, MID_TBS, ROOT_TBS] {
        assert_eq!(eval(&at(None, value), vec![full()]), Match, "{value}");
    }
    let mut partial = full();
    partial.details.root_tbs_hash = None;
    assert_eq!(eval(&at(None, MID_TBS), vec![partial.clone()]), Match);
    assert_eq!(eval(&at(None, &"4".repeat(64)), vec![partial]), Unknown);
    assert_eq!(eval(&at(None, &"4".repeat(64)), vec![full()]), NoMatch);
    // Values are 40, 64, 96 or 128 hex digits.
    for bad in [
        "abc",
        &"1".repeat(63),
        "xyz1111111111111111111111111111111111111",
    ] {
        assert!(matches!(
            CompiledCriterion::compile(&at(None, bad)).unwrap_err()[0].kind,
            CompileErrorKind::InvalidValue(_)
        ));
    }
}

#[test]
fn spki_hash_positions() {
    let at = |position, value: &str| {
        crit(
            Field::SignerSpkiSha256,
            Operator::Equals,
            &[value],
            SignerOptions { position, ..opts() },
        )
    };
    three_ways(
        &at(Some(TbsPosition::Leaf), LEAF_KEY),
        |s| s.details.leaf_spki_sha256 = Some(ROOT_KEY.into()),
        |s| s.details.leaf_spki_sha256 = None,
    );
    three_ways(
        &at(
            Some(TbsPosition::Intermediate),
            &MID_KEY.to_ascii_uppercase(),
        ),
        |s| s.details.intermediate_spki_sha256 = Some(vec![]),
        |s| s.details.intermediate_spki_sha256 = None,
    );
    three_ways(
        &at(Some(TbsPosition::Root), ROOT_KEY),
        |s| s.details.root_spki_sha256 = Some(LEAF_KEY.into()),
        |s| s.details.root_spki_sha256 = None,
    );
    // A key at another position does not match.
    assert_eq!(
        eval(&at(Some(TbsPosition::Leaf), ROOT_KEY), vec![full()]),
        NoMatch
    );
    // `any` (the default) finds each, and is unknown while any position
    // that could hold it is unknown.
    for value in [LEAF_KEY, MID_KEY, ROOT_KEY] {
        assert_eq!(eval(&at(None, value), vec![full()]), Match, "{value}");
    }
    let mut partial = full();
    partial.details.root_spki_sha256 = None;
    assert_eq!(eval(&at(None, MID_KEY), vec![partial.clone()]), Match);
    assert_eq!(eval(&at(None, &"7".repeat(64)), vec![partial]), Unknown);
    assert_eq!(eval(&at(None, &"7".repeat(64)), vec![full()]), NoMatch);
    // A malformed key hash is unknown, never a match, at any position.
    for bad in ["abc", "z".repeat(64).as_str(), &"4".repeat(40)] {
        let mut odd = full();
        odd.details.leaf_spki_sha256 = Some(bad.to_owned());
        assert_eq!(
            eval(&at(Some(TbsPosition::Leaf), LEAF_KEY), vec![odd.clone()]),
            Unknown
        );
        odd.details.intermediate_spki_sha256 = Some(vec![bad.to_owned()]);
        assert_eq!(
            eval(&at(Some(TbsPosition::Intermediate), MID_KEY), vec![odd]),
            Unknown
        );
    }
    // Values are SHA-256 only: 64 hex digits, optionally after `0x`.
    assert_eq!(
        eval(&at(None, &format!("0x{LEAF_KEY}")), vec![full()]),
        Match
    );
    for bad in ["abc", &"1".repeat(40), &"1".repeat(96)] {
        assert!(matches!(
            CompiledCriterion::compile(&at(None, bad)).unwrap_err()[0].kind,
            CompileErrorKind::InvalidValue(_)
        ));
    }
}

#[test]
fn a_key_hash_follows_a_reissued_certificate() {
    // The CA reissues the stolen key's certificate: new serial and
    // validity, so a new TBS hash and thumbprint, but the same key (#318).
    let mut reissued = full();
    reissued.details.leaf_tbs_hash = Some("9".repeat(64));
    reissued.leaf_thumbprint_sha256 = Some("8".repeat(64));
    let leaf = SignerOptions {
        position: Some(TbsPosition::Leaf),
        ..opts()
    };
    let key = crit(
        Field::SignerSpkiSha256,
        Operator::Equals,
        &[LEAF_KEY],
        leaf.clone(),
    );
    let tbs = crit(Field::SignerTbsHash, Operator::Equals, &[LEAF_TBS], leaf);
    assert_eq!(eval(&key, vec![full()]), Match);
    assert_eq!(eval(&tbs, vec![full()]), Match);
    assert_eq!(eval(&key, vec![reissued.clone()]), Match);
    assert_eq!(eval(&tbs, vec![reissued]), NoMatch);
}

#[test]
fn eku_sets() {
    let c = crit(
        Field::SignerEku,
        Operator::MemberOf,
        &["1.3.6.1.5.5.7.3.03"],
        opts(),
    );
    three_ways(
        &c,
        |s| s.details.eku = Some(vec![]),
        |s| s.details.eku = None,
    );
    let both = crit(
        Field::SignerEku,
        Operator::AllOf,
        &[CODE_SIGNING, "1.3.6.1.4.1.311.10.3.5"],
        opts(),
    );
    assert_eq!(eval(&both, vec![full()]), NoMatch);
    let mut driver = full();
    driver.details.eku = Some(vec![CODE_SIGNING.into(), "1.3.6.1.4.1.311.10.3.5".into()]);
    assert_eq!(eval(&both, vec![driver]), Match);
    // An unreadable OID could be the one asked for.
    let mut odd = full();
    odd.details.eku = Some(vec!["garbage".into()]);
    assert_eq!(eval(&c, vec![odd.clone()]), Unknown);
    let not = Criterion {
        operator: Operator::NotMemberOf,
        ..c.clone()
    };
    assert_eq!(eval(&not, vec![odd]), Unknown);
    assert!(
        CompiledCriterion::compile(&crit(
            Field::SignerEku,
            Operator::MemberOf,
            &["code signing"],
            opts()
        ))
        .is_err()
    );
    assert!(
        CompiledCriterion::compile(&crit(
            Field::SignerEku,
            Operator::Equals,
            &[CODE_SIGNING],
            opts()
        ))
        .is_err()
    );
}

fn publisher(o: SignerOptions) -> Criterion {
    crit(
        Field::SignerPublisher,
        Operator::Equals,
        &["Example Software Ltd"],
        o,
    )
}

#[test]
fn signed_after_needs_a_trusted_timestamp() {
    let c = publisher(SignerOptions {
        signed_after: Some("2024-01-01T00:00:00Z".into()),
        ..opts()
    });
    three_ways(
        &c,
        |s| s.details.timestamp = Some(JAN_2024 - 1),
        |s| s.details.timestamp = None,
    );
    // At the instant itself.
    let mut exact = full();
    exact.details.timestamp = Some(JAN_2024);
    assert_eq!(eval(&c, vec![exact]), Match);
    // Offsets are honoured: 2024-01-01T10:00:00+10:00 is midnight UTC.
    let c = publisher(SignerOptions {
        signed_after: Some("2024-01-01T10:00:00+10:00".into()),
        ..opts()
    });
    let mut exact = full();
    exact.details.timestamp = Some(JAN_2024);
    assert_eq!(eval(&c, vec![exact]), Match);
}

#[test]
fn fractional_signed_after_rounds_up() {
    // Trusted timestamps are whole seconds: a threshold half a second after
    // midnight needs a timestamp of at least one second after it.
    let c = publisher(SignerOptions {
        signed_after: Some("2024-01-01T00:00:00.500Z".into()),
        ..opts()
    });
    for (at, expected) in [
        (JAN_2024 - 1, NoMatch),
        (JAN_2024, NoMatch),
        (JAN_2024 + 1, Match),
        (JAN_2024 + 2, Match),
    ] {
        let mut s = full();
        s.details.timestamp = Some(at);
        assert_eq!(eval(&c, vec![s]), expected, "{at}");
    }
    // A whole-second threshold is unchanged.
    assert_eq!(super::instant("2024-01-01T00:00:00Z"), Some(JAN_2024));
    assert_eq!(
        super::instant("2024-01-01T00:00:00.000000001Z"),
        Some(JAN_2024 + 1)
    );
    assert_eq!(super::instant("2023-12-31T23:59:59.999Z"), Some(JAN_2024));
}

#[test]
fn observations_follow_the_selectors() {
    let s = full();
    let sel =
        |field, o: SignerOptions| super::Selector::of(&crit(field, Operator::Equals, &["x"], o));
    let at = |position| {
        sel(
            Field::SignerTbsHash,
            SignerOptions {
                position: Some(position),
                ..opts()
            },
        )
    };
    let of = |component| {
        sel(
            Field::SignerPublisher,
            SignerOptions {
                component: Some(component),
                ..opts()
            },
        )
    };
    let observed = |field, sel| super::observed(field, sel, &s);
    assert_eq!(
        observed(Field::SignerTbsHash, at(TbsPosition::Leaf)).as_deref(),
        Some(LEAF_TBS)
    );
    assert_eq!(
        observed(Field::SignerTbsHash, at(TbsPosition::Root)).as_deref(),
        Some(ROOT_TBS)
    );
    assert_eq!(
        observed(Field::SignerTbsHash, at(TbsPosition::Intermediate)).as_deref(),
        Some(MID_TBS)
    );
    assert_eq!(
        observed(Field::SignerTbsHash, sel(Field::SignerTbsHash, opts())),
        Some(format!("{LEAF_TBS}, {MID_TBS}, {ROOT_TBS}"))
    );
    let key = |position| {
        sel(
            Field::SignerSpkiSha256,
            SignerOptions {
                position: Some(position),
                ..opts()
            },
        )
    };
    assert_eq!(
        observed(Field::SignerSpkiSha256, key(TbsPosition::Leaf)).as_deref(),
        Some(LEAF_KEY)
    );
    assert_eq!(
        observed(Field::SignerSpkiSha256, key(TbsPosition::Root)).as_deref(),
        Some(ROOT_KEY)
    );
    assert_eq!(
        observed(Field::SignerSpkiSha256, key(TbsPosition::Intermediate)).as_deref(),
        Some(MID_KEY)
    );
    assert_eq!(
        observed(
            Field::SignerSpkiSha256,
            sel(Field::SignerSpkiSha256, opts())
        ),
        Some(format!("{LEAF_KEY}, {MID_KEY}, {ROOT_KEY}"))
    );
    assert_eq!(
        observed(Field::SignerPublisher, of(SubjectComponent::Cn)).as_deref(),
        Some("Example Software Ltd")
    );
    assert_eq!(
        observed(Field::SignerPublisher, of(SubjectComponent::O)).as_deref(),
        Some("Example Software")
    );
    assert_eq!(
        observed(Field::SignerPublisher, of(SubjectComponent::FullDn)).as_deref(),
        Some("CN=Example Software Ltd,O=Example Software,C=AU")
    );
    // An unknown position is unknown, not another position's hash.
    let mut no_root = full();
    no_root.details.root_tbs_hash = None;
    assert_eq!(
        super::observed(Field::SignerTbsHash, at(TbsPosition::Root), &no_root),
        None
    );
    // An option on a field it does not apply to selects nothing.
    let stray = sel(
        Field::SignerIssuer,
        SignerOptions {
            component: Some(SubjectComponent::O),
            ..opts()
        },
    );
    assert_eq!(stray, super::Selector::default());
}

#[test]
fn countersigned() {
    let c = publisher(SignerOptions {
        countersigned: true,
        ..opts()
    });
    three_ways(
        &c,
        |s| s.details.countersigned = Some(false),
        |s| s.details.countersigned = None,
    );
    // Without the option, an unknown countersignature does not matter.
    let mut unknown = full();
    unknown.details.countersigned = None;
    assert_eq!(eval(&publisher(opts()), vec![unknown]), Match);
}

#[test]
fn min_key_bits_covers_every_key() {
    let c = publisher(SignerOptions {
        min_key_bits: Some(2048),
        ..opts()
    });
    three_ways(
        &c,
        |s| {
            s.details.keys.as_mut().unwrap().push(KeyFact {
                kind: KeyKind::Rsa,
                bits: 1024,
            });
        },
        |s| s.details.keys = None,
    );
    // Elliptic curves count in RSA-equivalent bits: P-256 is 3072.
    let mut ec = full();
    ec.details.keys = Some(vec![KeyFact {
        kind: KeyKind::Ec,
        bits: 256,
    }]);
    let strict = publisher(SignerOptions {
        min_key_bits: Some(3072),
        ..opts()
    });
    assert_eq!(eval(&strict, vec![ec.clone()]), Match);
    let stricter = publisher(SignerOptions {
        min_key_bits: Some(4096),
        ..opts()
    });
    assert_eq!(eval(&stricter, vec![ec]), NoMatch);
    // A key of another algorithm cannot be checked: unknown, and a weak
    // key elsewhere in the chain still fails it.
    let mut other = full();
    other.details.keys = Some(vec![KeyFact {
        kind: KeyKind::Other,
        bits: 256,
    }]);
    assert_eq!(eval(&c, vec![other.clone()]), Unknown);
    other.details.keys.as_mut().unwrap().push(KeyFact {
        kind: KeyKind::Rsa,
        bits: 1024,
    });
    assert_eq!(eval(&c, vec![other]), NoMatch);
    // A chain with no keys is malformed.
    let mut none = full();
    none.details.keys = Some(vec![]);
    assert_eq!(eval(&c, vec![none]), Unknown);
}

#[test]
fn disallowed_algorithms() {
    let c = publisher(SignerOptions {
        disallowed_algorithms: vec![DigestAlgorithm::Sha1, DigestAlgorithm::Md5],
        ..opts()
    });
    three_ways(
        &c,
        |s| {
            s.details
                .algorithms
                .as_mut()
                .unwrap()
                .push(DigestAlgorithm::Sha1)
        },
        |s| s.details.algorithms = None,
    );
    let mut none = full();
    none.details.algorithms = Some(vec![]);
    assert_eq!(eval(&c, vec![none]), Unknown);
}

#[test]
fn accept_status_and_digest_mismatch() {
    let default = publisher(opts());
    // The default refuses revoked, digest-mismatched and unsigned objects.
    for status in [
        SignerStatus::Revoked,
        SignerStatus::DigestMismatch,
        SignerStatus::Expired,
        SignerStatus::UntrustedRoot,
    ] {
        let (r, _, untrusted) = run(
            &compile(&default),
            Some(vec![with_status(status)]),
            ActionKind::Allow,
        );
        assert_eq!((r, untrusted), (NoMatch, true), "{status:?}");
    }
    assert_eq!(eval(&default, vec![]), NoMatch);
    // `accept_status` replaces the default set.
    let expired = publisher(SignerOptions {
        accept_status: Some(vec![SignerStatus::Expired]),
        ..opts()
    });
    assert_eq!(
        eval(&expired, vec![with_status(SignerStatus::Expired)]),
        Match
    );
    assert_eq!(
        eval(&expired, vec![with_status(SignerStatus::Valid)]),
        NoMatch
    );
    assert_eq!(
        eval(&expired, vec![with_status(SignerStatus::DigestMismatch)]),
        NoMatch
    );
    // Nothing but `allow_digest_mismatch` lets a tampered file match, and
    // it adds only that status to the accepted set.
    let tampered = publisher(SignerOptions {
        allow_digest_mismatch: true,
        ..opts()
    });
    assert_eq!(
        eval(&tampered, vec![with_status(SignerStatus::DigestMismatch)]),
        Match
    );
    assert_eq!(
        eval(&tampered, vec![with_status(SignerStatus::Valid)]),
        Match
    );
    assert_eq!(
        eval(&tampered, vec![with_status(SignerStatus::Revoked)]),
        NoMatch
    );
    // `digest_mismatch` cannot be accepted by listing it.
    let listed = publisher(SignerOptions {
        accept_status: Some(vec![SignerStatus::DigestMismatch]),
        ..opts()
    });
    assert!(CompiledCriterion::compile(&listed).is_err());
}

#[test]
fn source_and_signature_index() {
    let catalog = || SignerFact {
        source: SignatureSource::Catalog,
        status: SignerStatus::CatalogSigned,
        publisher: Some("Catalog Signer".into()),
        ..full()
    };
    let nested = || SignerFact {
        publisher: Some("Nested Signer".into()),
        ..full()
    };
    let signatures = vec![full(), catalog(), nested()];
    let on = |name: &str, source, index| {
        crit(
            Field::SignerPublisher,
            Operator::Equals,
            &[name],
            SignerOptions {
                source,
                signature_index: index,
                ..opts()
            },
        )
    };
    for (name, source, index, expected) in [
        // Any signature by default.
        ("Catalog Signer", None, None, Match),
        ("Nested Signer", None, None, Match),
        (
            "Catalog Signer",
            Some(SignerSource::Embedded),
            None,
            NoMatch,
        ),
        ("Catalog Signer", Some(SignerSource::Catalog), None, Match),
        (
            "Example Software Ltd",
            Some(SignerSource::Catalog),
            None,
            NoMatch,
        ),
        // Indexes count within the source.
        (
            "Example Software Ltd",
            Some(SignerSource::Embedded),
            Some(0),
            Match,
        ),
        (
            "Nested Signer",
            Some(SignerSource::Embedded),
            Some(0),
            NoMatch,
        ),
        (
            "Nested Signer",
            Some(SignerSource::Embedded),
            Some(1),
            Match,
        ),
        (
            "Catalog Signer",
            Some(SignerSource::Catalog),
            Some(0),
            Match,
        ),
        ("Nested Signer", None, Some(2), Match),
        ("Nested Signer", None, Some(3), NoMatch),
    ] {
        assert_eq!(
            eval(&on(name, source, index), signatures.clone()),
            expected,
            "{name} {source:?} {index:?}"
        );
    }
    // An untrusted signature at the index is not replaced by another one.
    let mut revoked = full();
    revoked.status = SignerStatus::Revoked;
    let at0 = on("Example Software Ltd", None, Some(0));
    assert_eq!(eval(&at0, vec![revoked, full()]), NoMatch);
    // Unknown signatures stay unknown.
    assert_eq!(run(&compile(&at0), None, ActionKind::Allow).0, Unknown);
}

#[test]
fn constraints_bind_to_the_signature_that_matched() {
    // The publisher's signature is weak; a strong one is by someone else.
    let mut weak = full();
    weak.details.keys = Some(vec![KeyFact {
        kind: KeyKind::Rsa,
        bits: 1024,
    }]);
    let mut strong_other = full();
    strong_other.publisher = Some("Other".into());
    let c = publisher(SignerOptions {
        min_key_bits: Some(2048),
        ..opts()
    });
    assert_eq!(eval(&c, vec![weak, strong_other]), NoMatch);
    // A signature that fails the field test is not unknown because a
    // constraint's fact is.
    let mut other_bare = bare();
    other_bare.publisher = Some("Other".into());
    assert_eq!(eval(&c, vec![other_bare, full()]), Match);
}

#[test]
fn absent_facts_never_match() {
    // Every signer field, with every option that needs a fact, on a
    // signature that has no facts: never `Match`, in any action, and the
    // negation is never `Match` either.
    let all = SignerOptions {
        signed_after: Some("2024-01-01T00:00:00Z".into()),
        countersigned: true,
        min_key_bits: Some(2048),
        disallowed_algorithms: vec![DigestAlgorithm::Sha1],
        ..opts()
    };
    let cases: Vec<Criterion> = vec![
        crit(
            Field::SignerPublisher,
            Operator::Equals,
            &["x"],
            all.clone(),
        ),
        crit(Field::SignerIssuer, Operator::Equals, &["x"], all.clone()),
        crit(Field::SignerPca, Operator::Equals, &["x"], all.clone()),
        crit(
            Field::SignerLeafThumbprint,
            Operator::Equals,
            &[ROOT_SHA256],
            all.clone(),
        ),
        crit(
            Field::SignerLeafThumbprintSha1,
            Operator::Equals,
            &[LEAF_SHA1],
            all.clone(),
        ),
        crit(
            Field::SignerRootThumbprint,
            Operator::Equals,
            &[ROOT_SHA256],
            all.clone(),
        ),
        crit(
            Field::SignerRootThumbprintSha1,
            Operator::Equals,
            &[ROOT_SHA1],
            all.clone(),
        ),
        crit(
            Field::SignerTbsHash,
            Operator::Equals,
            &[LEAF_TBS],
            all.clone(),
        ),
        crit(
            Field::SignerEku,
            Operator::MemberOf,
            &[CODE_SIGNING],
            all.clone(),
        ),
        crit(
            Field::SignerSpkiSha256,
            Operator::Equals,
            &[LEAF_KEY],
            all.clone(),
        ),
    ];
    for c in &cases {
        let compiled = compile(c);
        for action in [ActionKind::Allow, ActionKind::Deny] {
            let (r, missing, _) = run(&compiled, Some(vec![bare()]), action);
            assert_eq!((r, missing), (Unknown, true), "{:?}", c.field);
            assert_eq!(run(&compiled, None, action).0, Unknown, "{:?}", c.field);
        }
    }
}

#[test]
fn options_are_checked() {
    let problems = |c: &Criterion| -> Vec<&'static str> {
        super::option_problems(c)
            .into_iter()
            .map(|(p, _)| p)
            .collect()
    };
    let mut c = Criterion::new(Field::MetaProductName, Operator::Equals, ["x"]);
    c.signer = Some(Box::default());
    assert_eq!(problems(&c), ["signer"]);
    let c = crit(
        Field::SignerIssuer,
        Operator::Equals,
        &["x"],
        SignerOptions {
            component: Some(SubjectComponent::O),
            position: Some(TbsPosition::Root),
            accept_status: Some(vec![]),
            signature_index: Some(64),
            signed_after: Some("2024-01-01".into()),
            min_key_bits: Some(0),
            ..opts()
        },
    );
    assert_eq!(
        problems(&c),
        [
            "signer/component",
            "signer/position",
            "signer/accept_status",
            "signer/signature_index",
            "signer/signed_after",
            "signer/min_key_bits",
        ]
    );
    assert!(CompiledCriterion::compile(&c).is_err());
}

#[test]
fn strength_and_compatibility() {
    use Strength::{Medium, Strong, Weak};
    for (field, strength) in [
        (Field::SignerTbsHash, Strong),
        (Field::SignerSpkiSha256, Strong),
        (Field::SignerLeafThumbprint, Strong),
        (Field::SignerPublisher, Medium),
        (Field::SignerLeafThumbprintSha1, Weak),
        (Field::SignerRootThumbprint, Weak),
        (Field::SignerRootThumbprintSha1, Weak),
        (Field::SignerPca, Weak),
        (Field::SignerIssuer, Weak),
        (Field::SignerEku, Weak),
    ] {
        assert_eq!(field.strength(), Some(strength), "{field:?}");
        assert!(field.is_signer());
    }
    assert!(Field::SignerLeafThumbprintSha1.is_weak_hash());
    assert!(Field::SignerRootThumbprintSha1.is_weak_hash());
    for op in Operator::ALL {
        assert_eq!(
            op.applies_to_field(Field::SignerTbsHash),
            matches!(op, Operator::Equals | Operator::NotEquals),
            "{op:?}"
        );
        assert_eq!(op.applies_to_field(Field::SignerEku), op.is_set(), "{op:?}");
        assert_eq!(
            op.applies_to_field(Field::SignerPca),
            op.is_text(),
            "{op:?}"
        );
    }
}

#[test]
fn rsa_equivalent_bits() {
    let ec = |bits| {
        KeyFact {
            kind: KeyKind::Ec,
            bits,
        }
        .rsa_equivalent_bits()
    };
    assert_eq!(
        [ec(192), ec(224), ec(256), ec(384), ec(521)],
        [Some(1024), Some(2048), Some(3072), Some(7680), Some(15_360)]
    );
    assert_eq!(
        KeyFact {
            kind: KeyKind::Rsa,
            bits: 4096
        }
        .rsa_equivalent_bits(),
        Some(4096)
    );
    assert_eq!(
        KeyFact {
            kind: KeyKind::Other,
            bits: 4096
        }
        .rsa_equivalent_bits(),
        None
    );
}

fn signer_strategy() -> impl Strategy<Value = SignerFact> {
    (
        proptest::sample::select(SignerStatus::ALL.to_vec()),
        any::<bool>(),
        proptest::option::of(proptest::sample::select(vec![
            "Example Software Ltd",
            "Other",
        ])),
        proptest::option::of(proptest::option::of(JAN_2024 - 10..JAN_2024 + 10)),
        proptest::option::of(any::<bool>()),
        proptest::option::of(proptest::collection::vec(
            (any::<bool>(), 512u32..5000),
            0..3,
        )),
    )
        .prop_map(
            |(status, catalog, publisher, timestamp, countersigned, keys)| {
                let mut s = full();
                s.status = status;
                if catalog {
                    s.source = SignatureSource::Catalog;
                }
                s.publisher = publisher.map(str::to_owned);
                if let Some(t) = timestamp {
                    s.details.timestamp = t;
                }
                s.details.countersigned = countersigned;
                s.details.keys = keys.map(|k| {
                    k.into_iter()
                        .map(|(rsa, bits)| KeyFact {
                            kind: if rsa { KeyKind::Rsa } else { KeyKind::Ec },
                            bits,
                        })
                        .collect()
                });
                s
            },
        )
}

fn options_strategy() -> impl Strategy<Value = SignerOptions> {
    (
        proptest::option::of(proptest::collection::vec(
            proptest::sample::select(
                SignerStatus::ALL
                    .into_iter()
                    .filter(|s| *s != SignerStatus::DigestMismatch)
                    .collect::<Vec<_>>(),
            ),
            1..3,
        )),
        any::<bool>(),
        proptest::sample::select(vec![
            SignerSource::Any,
            SignerSource::Embedded,
            SignerSource::Catalog,
        ]),
        proptest::option::of(0u8..3),
        any::<bool>(),
        any::<bool>(),
        proptest::option::of(1024u32..4096),
    )
        .prop_map(
            |(
                accept_status,
                allow_digest_mismatch,
                source,
                signature_index,
                after,
                countersigned,
                min_key_bits,
            )| SignerOptions {
                accept_status,
                allow_digest_mismatch,
                source: Some(source),
                signature_index,
                signed_after: after.then(|| "2024-01-01T00:00:00Z".to_owned()),
                countersigned,
                min_key_bits,
                ..SignerOptions::default()
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A match needs a signature that takes part and whose every needed
    /// fact is known and passes; nothing else can match. A digest
    /// mismatch only ever matches with `allow_digest_mismatch`.
    #[test]
    fn a_match_always_has_a_witness(
        signers in proptest::collection::vec(signer_strategy(), 0..4),
        o in options_strategy(),
    ) {
        let c = publisher(o.clone());
        let r = eval(&c, signers.clone());
        if r == Match {
            let compiled = super::compile_options(&c);
            let mut nth = 0usize;
            let witness = signers.iter().filter(|s| compiled.includes(s.source)).any(|s| {
                let index = nth;
                nth += 1;
                o.signature_index.is_none_or(|i| usize::from(i) == index)
                    && compiled.accepts(s.status)
                    && (s.status != SignerStatus::DigestMismatch || o.allow_digest_mismatch)
                    && s.publisher.as_deref() == Some("Example Software Ltd")
                    && (o.signed_after.is_none() || s.details.timestamp.is_some_and(|t| t >= JAN_2024))
                    && (!o.countersigned || s.details.countersigned == Some(true))
                    && o.min_key_bits.is_none_or(|min| {
                        s.details.keys.as_ref().is_some_and(|k| {
                            !k.is_empty() && k.iter().all(|k| k.rsa_equivalent_bits().is_some_and(|b| b >= min))
                        })
                    })
            });
            prop_assert!(witness, "{signers:#?} {o:#?}");
        }
    }

    /// A negated signer test is the Kleene complement of the positive one,
    /// so an unknown fact never lets it match.
    #[test]
    fn negation_is_the_kleene_complement(
        signers in proptest::option::of(proptest::collection::vec(signer_strategy(), 0..4)),
        o in options_strategy(),
    ) {
        let pos = compile(&publisher(o.clone()));
        let neg = compile(&Criterion { operator: Operator::NotEquals, ..publisher(o) });
        let p = run(&pos, signers.clone(), ActionKind::Allow).0;
        let n = run(&neg, signers, ActionKind::Allow).0;
        prop_assert_eq!(n, p.not());
    }

    /// Forgetting a fact never turns a result into a match.
    #[test]
    fn forgetting_a_fact_never_creates_a_match(
        signers in proptest::collection::vec(signer_strategy(), 1..4),
        o in options_strategy(),
        which in 0usize..4,
        at in 0usize..4,
    ) {
        let c = publisher(o);
        let before = eval(&c, signers.clone());
        let mut fewer = signers;
        let n = fewer.len();
        let s = &mut fewer[at % n];
        match which {
            0 => s.publisher = None,
            1 => s.details.timestamp = None,
            2 => s.details.countersigned = None,
            _ => s.details.keys = None,
        }
        let after = eval(&c, fewer);
        prop_assert!(after != Match || before == Match);
    }
}
