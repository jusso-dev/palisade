//! Tests for criterion matching (#31, #32).

use std::time::{Duration, Instant};

use proptest::prelude::*;

use palisade_core::path::VolumeMap;

use super::{
    CompileErrorKind, CompiledCriterion, EvalContext, Note, REGEX_SIZE_LIMIT, Tri, Version, fold,
};
use crate::context::EvaluationContext;
use crate::facts::{
    ObjectFacts, PathFact, PathVariable, PathVariables, SignatureSource, SignerFact, SignerStatus,
};
use crate::model::{ActionKind, Criterion, Field, Operator, Strength};

use Tri::{Match, NoMatch, Unknown};

/// No context facts, for criteria on the object.
static NO_CONTEXT: EvaluationContext = EvaluationContext::EMPTY;

const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn crit(field: Field, operator: Operator, values: &[&str]) -> Criterion {
    Criterion::new(field, operator, values.iter().copied())
}

fn compile(field: Field, operator: Operator, values: &[&str]) -> CompiledCriterion {
    CompiledCriterion::compile(&crit(field, operator, values))
        .unwrap_or_else(|e| panic!("{field:?} {operator:?} {values:?}: {e:?}"))
}

fn compile_err(field: Field, operator: Operator, values: &[&str]) -> CompileErrorKind {
    match CompiledCriterion::compile(&crit(field, operator, values)) {
        Ok(_) => panic!("{field:?} {operator:?} {values:?} compiled"),
        Err(mut e) => e.remove(0).kind,
    }
}

fn deny_ctx(variables: &PathVariables) -> EvalContext<'_> {
    EvalContext {
        action: ActionKind::Deny,
        variables,
        context: &NO_CONTEXT,
    }
}

/// Evaluates in a deny rule, which has no path-ACL requirement.
fn eval(c: &CompiledCriterion, facts: &ObjectFacts) -> Tri {
    c.eval(facts, &deny_ctx(&PathVariables::new())).result
}

fn at_path(raw: &str) -> ObjectFacts {
    ObjectFacts::new().with_path(
        PathFact::new(raw, &VolumeMap::new())
            .with_user_writable(false)
            .with_volume(crate::unknown::VolumeKind::Fixed),
    )
}

fn text_facts(field: Field, value: &str) -> ObjectFacts {
    ObjectFacts::new().with(field, value)
}

fn signer(status: SignerStatus, publisher: &str) -> SignerFact {
    SignerFact {
        status,
        source: SignatureSource::Embedded,
        publisher: Some(publisher.to_owned()),
        issuer: Some("Example Issuing CA".to_owned()),
        leaf_thumbprint_sha256: Some(SHA.to_owned()),
        details: Default::default(),
    }
}

fn signed(signers: Vec<SignerFact>) -> ObjectFacts {
    ObjectFacts::new().with_signers(signers)
}

#[test]
fn kleene_logic() {
    let all = [NoMatch, Match, Unknown];
    for a in all {
        assert_eq!(a.not().not(), a);
        for b in all {
            assert_eq!(a.and(b), b.and(a));
            assert_eq!(a.or(b), b.or(a));
            // De Morgan holds in Kleene logic.
            assert_eq!(a.and(b).not(), a.not().or(b.not()));
        }
    }
    assert_eq!(Unknown.not(), Unknown);
    assert_eq!(Unknown.and(NoMatch), NoMatch);
    assert_eq!(Unknown.and(Match), Unknown);
    assert_eq!(Unknown.or(Match), Match);
    assert_eq!(Unknown.or(NoMatch), Unknown);
}

/// One row per operator: match, no match, and unknown (fact missing),
/// with several values.
#[test]
fn every_operator_matches_misses_and_is_unknown_without_the_fact() {
    let f = Field::MetaProductName;
    let v = Field::MetaFileVersion;
    let rows: &[(Field, Operator, &[&str], &str, &str)] = &[
        (
            f,
            Operator::Equals,
            &["Other", "Editor"],
            "editor",
            "Editors",
        ),
        (
            f,
            Operator::NotEquals,
            &["Other", "Editor"],
            "Editors",
            "EDITOR",
        ),
        (f, Operator::StartsWith, &["x", "Ed"], "editor", "Red"),
        (f, Operator::EndsWith, &["x", "tor"], "Editor", "Editors"),
        (f, Operator::Contains, &["x", "dit"], "EDITOR", "Edtor"),
        (f, Operator::NotContains, &["x", "dit"], "Edtor", "editor"),
        (f, Operator::Wildcard, &["x", "E?it*"], "editor 2", "Edtor"),
        (f, Operator::NotWildcard, &["x", "E?it*"], "Edtor", "edit"),
        (
            f,
            Operator::Regex,
            &["x", "ed[a-z]+r"],
            "EDITOR",
            "editor 2",
        ),
        (
            f,
            Operator::NotRegex,
            &["x", "ed[a-z]+r"],
            "editor 2",
            "EDITOR",
        ),
        (v, Operator::Equals, &["1.0", "2.5"], "2.5.0.0", "2.5.0.1"),
        (v, Operator::NotEquals, &["1.0", "2.5"], "2.5.0.1", "2.5"),
        (
            v,
            Operator::VersionEq,
            &["1.0", "2.5"],
            "2.5.0.0",
            "2.5.0.1",
        ),
        (v, Operator::VersionGt, &["2.5"], "2.5.0.1", "2.5"),
        (v, Operator::VersionGe, &["2.5"], "2.5", "2.4.65535"),
        (v, Operator::VersionLt, &["2.5"], "2.4.9", "2.5"),
        (v, Operator::VersionLe, &["2.5"], "2.5", "2.5.0.1"),
        (
            v,
            Operator::VersionBetween,
            &["2.0", "3.0"],
            "3.0",
            "3.0.0.1",
        ),
    ];
    for (field, op, values, hit, miss) in rows {
        let c = compile(*field, *op, values);
        assert_eq!(eval(&c, &text_facts(*field, hit)), Match, "{op:?} {hit:?}");
        assert_eq!(
            eval(&c, &text_facts(*field, miss)),
            NoMatch,
            "{op:?} {miss:?}"
        );
        let missing = c.eval(&ObjectFacts::new(), &deny_ctx(&PathVariables::new()));
        assert_eq!(missing.result, Unknown, "{op:?} on a missing fact");
        assert!(missing.notes.contains(Note::FactMissing));
    }
}

#[test]
fn negative_operators_need_every_value_to_miss() {
    let c = compile(Field::MetaProductName, Operator::NotContains, &["a", "b"]);
    assert_eq!(eval(&c, &text_facts(Field::MetaProductName, "xyz")), Match);
    assert_eq!(
        eval(&c, &text_facts(Field::MetaProductName, "xaz")),
        NoMatch
    );
    assert_eq!(
        eval(&c, &text_facts(Field::MetaProductName, "xbz")),
        NoMatch
    );
    let c = compile(Field::MetaProductName, Operator::NotEquals, &["a", "b"]);
    assert_eq!(eval(&c, &text_facts(Field::MetaProductName, "c")), Match);
    assert_eq!(eval(&c, &text_facts(Field::MetaProductName, "B")), NoMatch);
}

#[test]
fn negation_never_turns_unknown_into_a_match() {
    for op in [
        Operator::NotEquals,
        Operator::NotContains,
        Operator::NotWildcard,
        Operator::NotRegex,
    ] {
        for (field, value) in [
            (Field::MetaProductName, "x"),
            (Field::PathFull, "C:\\Tools"),
            (Field::SignerPublisher, "x"),
            (Field::PathExtension, "exe"),
        ] {
            // A path is not a valid regular expression.
            let value = if op == Operator::NotRegex && field == Field::PathFull {
                "C:.*"
            } else {
                value
            };
            let c = compile(field, op, &[value]);
            for action in [ActionKind::Allow, ActionKind::Deny, ActionKind::Audit] {
                let vars = PathVariables::new();
                let ctx = EvalContext {
                    action,
                    variables: &vars,
                    context: &NO_CONTEXT,
                };
                assert_eq!(
                    c.eval(&ObjectFacts::new(), &ctx).result,
                    Unknown,
                    "{field:?} {op:?}"
                );
            }
        }
    }
    let hash = compile(Field::HashSha256, Operator::NotEquals, &[SHA]);
    assert_eq!(eval(&hash, &ObjectFacts::new()), Unknown);
}

#[test]
fn text_case_folding_is_simple_and_locale_free() {
    let c = compile(Field::MetaCompanyName, Operator::Equals, &["Straße İnc"]);
    // `ß` has no one-character upper case, so it does not fold to `SS`.
    assert_eq!(
        eval(&c, &text_facts(Field::MetaCompanyName, "STRASSE İNC")),
        NoMatch
    );
    assert_eq!(
        eval(&c, &text_facts(Field::MetaCompanyName, "straße İnc")),
        Match
    );
    // Dotted capital İ is distinct from i and I; dotless ı folds to I.
    let i = compile(Field::MetaCompanyName, Operator::Equals, &["file"]);
    assert_eq!(eval(&i, &text_facts(Field::MetaCompanyName, "FILE")), Match);
    assert_eq!(eval(&i, &text_facts(Field::MetaCompanyName, "fıle")), Match);
    assert_eq!(
        eval(&i, &text_facts(Field::MetaCompanyName, "FİLE")),
        NoMatch
    );
    assert_eq!(fold("ǆ", false), "Ǆ");
}

#[test]
fn case_sensitive_override() {
    let mut c = crit(Field::MetaProductName, Operator::Equals, &["Editor"]);
    c.case_sensitive = Some(true);
    let c = CompiledCriterion::compile(&c).unwrap();
    assert_eq!(
        eval(&c, &text_facts(Field::MetaProductName, "Editor")),
        Match
    );
    assert_eq!(
        eval(&c, &text_facts(Field::MetaProductName, "editor")),
        NoMatch
    );

    let mut r = crit(Field::MetaProductName, Operator::Regex, &["edit.*"]);
    r.case_sensitive = Some(true);
    let r = CompiledCriterion::compile(&r).unwrap();
    assert_eq!(
        eval(&r, &text_facts(Field::MetaProductName, "editor")),
        Match
    );
    assert_eq!(
        eval(&r, &text_facts(Field::MetaProductName, "Editor")),
        NoMatch
    );

    let mut p = crit(Field::PathFull, Operator::Equals, &["C:\\Tools\\A.exe"]);
    p.case_sensitive = Some(true);
    let p = CompiledCriterion::compile(&p).unwrap();
    assert_eq!(
        eval(&p, &at_path("c:\\Tools\\A.exe")),
        Match,
        "drive letter"
    );
    assert_eq!(eval(&p, &at_path("C:\\tools\\A.exe")), NoMatch);
}

#[test]
fn unicode_is_compared_after_nfc() {
    let composed = "caf\u{e9}";
    let decomposed = "cafe\u{301}";
    for op in [Operator::Equals, Operator::Regex, Operator::Wildcard] {
        let c = compile(Field::MetaProductName, op, &[decomposed]);
        assert_eq!(
            eval(&c, &text_facts(Field::MetaProductName, composed)),
            Match,
            "{op:?}"
        );
        let c = compile(Field::MetaProductName, op, &[composed]);
        assert_eq!(
            eval(
                &c,
                &text_facts(Field::MetaProductName, &decomposed.to_uppercase())
            ),
            Match,
            "{op:?}"
        );
    }
    let p = compile(Field::PathFull, Operator::Equals, &["C:\\Caf\u{e9}\\a.exe"]);
    assert_eq!(eval(&p, &at_path("c:\\CAFE\u{301}\\A.EXE")), Match);
}

#[test]
fn hashes_compare_as_hex_in_either_case() {
    let upper = SHA.to_ascii_uppercase();
    let prefixed = format!("0x{upper}");
    let c = compile(Field::HashSha256, Operator::Equals, &[&prefixed]);
    assert_eq!(eval(&c, &text_facts(Field::HashSha256, SHA)), Match);
    assert_eq!(eval(&c, &text_facts(Field::HashSha256, &upper)), Match);
    let other = SHA.replace('9', "8");
    assert_eq!(eval(&c, &text_facts(Field::HashSha256, &other)), NoMatch);
    // A malformed fact is unknown, so `not_equals` cannot match it.
    let not = compile(Field::HashSha256, Operator::NotEquals, &[SHA]);
    let short = not.eval(
        &text_facts(Field::HashSha256, "abc"),
        &deny_ctx(&PathVariables::new()),
    );
    assert_eq!(short.result, Unknown);
    assert!(short.notes.contains(Note::FactMalformed));

    for (field, len) in [
        (Field::HashSha384, 96),
        (Field::HashSha512, 128),
        (Field::HashMd5, 32),
        (Field::HashPageSha1, 40),
    ] {
        let ok = "a".repeat(len);
        assert_eq!(
            eval(
                &compile(field, Operator::Equals, &[&ok]),
                &text_facts(field, &ok)
            ),
            Match
        );
        let bad = "a".repeat(len - 1);
        assert!(matches!(
            compile_err(field, Operator::Equals, &[&bad]),
            CompileErrorKind::InvalidValue(_)
        ));
    }
}

#[test]
fn compatibility_table() {
    // Identity fields; context fields have their own table test.
    for field in Field::ALL.into_iter().filter(|f| !f.is_context()) {
        for op in [
            Operator::Equals,
            Operator::Contains,
            Operator::Wildcard,
            Operator::Regex,
            Operator::VersionGe,
            Operator::VersionBetween,
        ] {
            let class = field.class();
            let expected = match class {
                crate::model::FieldClass::Hash { .. }
                | crate::model::FieldClass::Digest
                | crate::model::FieldClass::Guid => op == Operator::Equals,
                // #328's file size and .NET flag.
                crate::model::FieldClass::OidSet
                | crate::model::FieldClass::Number
                | crate::model::FieldClass::Bool => false,
                crate::model::FieldClass::Version => {
                    matches!(
                        op,
                        Operator::Equals | Operator::VersionGe | Operator::VersionBetween
                    )
                }
                _ => !op.is_version(),
            };
            assert_eq!(op.applies_to(class), expected, "{field:?} {op:?}");
        }
    }
    assert_eq!(
        compile_err(Field::HashSha256, Operator::Contains, &["ab"]),
        CompileErrorKind::OperatorFieldMismatch
    );
    assert_eq!(
        compile_err(Field::PathFull, Operator::VersionGe, &["1.0"]),
        CompileErrorKind::OperatorFieldMismatch
    );
    assert_eq!(
        compile_err(Field::MetaFileVersion, Operator::VersionBetween, &["1.0"]),
        CompileErrorKind::ValueCount
    );
    assert_eq!(
        compile_err(Field::MetaFileVersion, Operator::VersionGe, &["1.0", "2.0"]),
        CompileErrorKind::ValueCount
    );
}

#[test]
fn versions_parse_and_compare_symmetrically() {
    assert_eq!(Version::parse_strict("10"), Some(Version([10, 0, 0, 0])));
    assert_eq!(
        Version::parse_strict("1.2.3.65535"),
        Some(Version([1, 2, 3, 65535]))
    );
    for bad in [
        "",
        "1.",
        ".1",
        "1..2",
        "1.2.3.4.5",
        "65536",
        "1.0a",
        " 1.0",
        "1,0",
    ] {
        assert_eq!(Version::parse_strict(bad), None, "{bad:?}");
    }
    assert_eq!(
        Version::parse_fact("10.0.19041.1 (WinBuild.160101.0800)"),
        Some((Version([10, 0, 19041, 1]), true))
    );
    assert_eq!(
        Version::parse_fact("10, 0, 19041, 1"),
        Some((Version([10, 0, 19041, 1]), false))
    );
    assert_eq!(Version::parse_fact("1.2.3.4.5"), None);
    assert_eq!(Version::parse_fact("v1.0"), None);

    // The same range means the same thing in allow and deny rules.
    let range = compile(
        Field::MetaFileVersion,
        Operator::VersionBetween,
        &["2.0", "3.0"],
    );
    for action in [ActionKind::Allow, ActionKind::Deny] {
        let vars = PathVariables::new();
        let ctx = EvalContext {
            action,
            variables: &vars,
            context: &NO_CONTEXT,
        };
        for (fact, expected) in [
            ("1.9.65535.65535", NoMatch),
            ("2.0", Match),
            ("2.5", Match),
            ("3.0.0.0", Match),
            ("3.0.0.1", NoMatch),
        ] {
            assert_eq!(
                range
                    .eval(&text_facts(Field::MetaFileVersion, fact), &ctx)
                    .result,
                expected,
                "{action:?} {fact}"
            );
        }
    }
    assert!(matches!(
        compile_err(
            Field::MetaFileVersion,
            Operator::VersionBetween,
            &["3.0", "2.0"]
        ),
        CompileErrorKind::InvalidValue(_)
    ));

    // An unparseable fact never satisfies a version test, in either
    // direction, and says why.
    for op in [Operator::VersionGe, Operator::VersionLt] {
        let c = compile(Field::MetaFileVersion, op, &["1.0"]);
        let e = c.eval(
            &text_facts(Field::MetaFileVersion, "unknown"),
            &deny_ctx(&PathVariables::new()),
        );
        assert_eq!(e.result, Unknown);
        assert!(e.notes.contains(Note::VersionUnparseable));
    }
    let not = compile(Field::MetaFileVersion, Operator::NotEquals, &["1.0"]);
    assert_eq!(
        eval(&not, &text_facts(Field::MetaFileVersion, "x")),
        Unknown
    );
    let suffix = compile(Field::MetaFileVersion, Operator::VersionGe, &["10.0"]);
    let e = suffix.eval(
        &text_facts(Field::MetaFileVersion, "10.0.1 beta"),
        &deny_ctx(&PathVariables::new()),
    );
    assert_eq!(e.result, Match);
    assert!(e.notes.contains(Note::VersionSuffixStripped));
}

#[test]
fn path_spellings_are_one_object() {
    let c = compile(
        Field::PathFull,
        Operator::Equals,
        &["C:\\Tools\\App\\run.exe"],
    );
    let mut volumes = VolumeMap::new();
    volumes.insert("\\Device\\HarddiskVolume3", 'C');
    for spelling in [
        "C:\\Tools\\App\\run.exe",
        "c:/tools/app/RUN.EXE",
        "C:\\Tools\\\\App\\.\\run.exe",
        "C:\\Tools\\Other\\..\\App\\run.exe",
        "\\\\?\\C:\\Tools\\App\\run.exe",
        "\\??\\C:\\Tools\\App\\run.exe",
        "\\Device\\HarddiskVolume3\\Tools\\App\\run.exe",
        "C:\\Tools\\App\\run.exe::$DATA",
        "C:\\Tools\\App::$INDEX_ALLOCATION\\run.exe",
    ] {
        let facts = ObjectFacts::new().with_path(
            PathFact::new(spelling, &volumes)
                .with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed),
        );
        assert_eq!(eval(&c, &facts), Match, "{spelling}");
    }
    // Trailing dots and spaces are significant.
    assert_eq!(eval(&c, &at_path("C:\\Tools\\App\\run.exe.")), NoMatch);
    assert_eq!(eval(&c, &at_path("C:\\Tools\\App\\run.exe ")), NoMatch);
    // An unmapped device path is unknown, not a miss.
    let e = c.eval(
        &at_path("\\Device\\HarddiskVolume9\\Tools\\App\\run.exe"),
        &deny_ctx(&PathVariables::new()),
    );
    assert_eq!(e.result, Unknown);
    assert!(e.notes.contains(Note::PathUnresolved));
}

#[test]
fn unc_and_mapped_drives_match_both_forms() {
    let unc = compile(Field::PathFull, Operator::StartsWith, &["\\\\fs01\\apps"]);
    let drive = compile(Field::PathFull, Operator::StartsWith, &["Z:\\"]);
    let mut fact = PathFact::new("Z:\\tool.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    fact.alias = Some(palisade_core::path::normalize("\\\\fs01\\apps\\tool.exe"));
    let facts = ObjectFacts::new().with_path(fact);
    assert_eq!(eval(&unc, &facts), Match);
    assert_eq!(eval(&drive, &facts), Match);
    assert_eq!(eval(&unc, &at_path("\\\\?\\UNC\\FS01\\Apps\\x.exe")), Match);
    assert_eq!(eval(&unc, &at_path("\\\\fs01\\appsx\\x.exe")), NoMatch);
}

#[test]
fn starts_with_on_paths_ends_at_a_component() {
    let c = compile(Field::PathFull, Operator::StartsWith, &["C:\\Tools"]);
    assert_eq!(eval(&c, &at_path("C:\\Tools\\a.exe")), Match);
    assert_eq!(eval(&c, &at_path("C:\\Tools")), Match);
    assert_eq!(eval(&c, &at_path("C:\\ToolsX\\a.exe")), NoMatch);
    let root = compile(Field::PathFull, Operator::StartsWith, &["C:\\"]);
    assert_eq!(eval(&root, &at_path("C:\\a.exe")), Match);
    let dir = compile(Field::PathDirectory, Operator::Equals, &["C:\\Tools"]);
    assert_eq!(eval(&dir, &at_path("C:\\Tools\\a.exe")), Match);
    assert_eq!(eval(&dir, &at_path("C:\\Tools\\sub\\a.exe")), NoMatch);
    let top = compile(Field::PathDirectory, Operator::Equals, &["C:\\"]);
    assert_eq!(eval(&top, &at_path("C:\\a.exe")), Match);
}

#[test]
fn path_wildcards() {
    let rows: &[(&str, &str, Tri)] = &[
        ("C:\\Tools\\*.exe", "C:\\Tools\\a.exe", Match),
        ("C:\\Tools\\*.exe", "C:\\Tools\\sub\\a.exe", NoMatch),
        // A whole-component `*` needs a component.
        ("C:\\*", "C:\\", NoMatch),
        ("?:\\*", "C:\\", NoMatch),
        ("C:\\**\\*", "C:\\", NoMatch),
        ("C:\\**\\*", "C:\\a", Match),
        ("\\\\srv\\share\\*", "\\\\srv\\share", NoMatch),
        ("C:\\Tools\\*", "C:\\Tools", NoMatch),
        ("C:\\a*", "C:\\a", Match),
        ("C:\\Tools\\**", "C:\\Tools", Match),
        ("C:\\Tools\\**", "C:\\Tools\\a\\b\\c.exe", Match),
        ("C:\\Tools\\**", "C:\\ToolsX\\a.exe", NoMatch),
        ("C:\\Tools\\**\\run.exe", "C:\\Tools\\run.exe", Match),
        ("C:\\Tools\\**\\run.exe", "C:\\Tools\\a\\b\\run.exe", Match),
        ("C:\\Tools\\**\\run.exe", "C:\\Tools\\a\\xrun.exe", NoMatch),
        ("**\\cmd.exe", "C:\\Windows\\System32\\cmd.exe", Match),
        ("**\\cmd.exe", "C:\\Windows\\System32\\xcmd.exe", NoMatch),
        ("C:\\T?ols\\a.exe", "C:\\Tools\\a.exe", Match),
        ("C:\\T?ols\\a.exe", "C:\\Tols\\a.exe", NoMatch),
        ("C:\\a?b", "C:\\a\\b", NoMatch),
        ("C:\\a[*]b", "C:\\a*b", Match),
        ("C:\\a[*]b", "C:\\axb", NoMatch),
        ("C:\\a[?]", "C:\\a?", Match),
        ("C:/Tools/*.EXE", "c:\\tools\\A.exe", Match),
        ("C:\\x\\*", "C:\\x\\a.txt:payload", NoMatch),
        ("C:\\x\\*:*", "C:\\x\\a.txt:payload", Match),
        ("C:\\(a)+$\\*", "C:\\(a)+$\\b", Match),
    ];
    for (pattern, path, expected) in rows {
        let c = compile(Field::PathFull, Operator::Wildcard, &[pattern]);
        assert_eq!(eval(&c, &at_path(path)), *expected, "{pattern} on {path}");
    }
    // On other fields `*` crosses everything and `**` is the same.
    let t = compile(Field::MetaFileDescription, Operator::Wildcard, &["a**z"]);
    assert_eq!(
        eval(&t, &text_facts(Field::MetaFileDescription, "a\\b\\z")),
        Match
    );
    let t = compile(Field::MetaFileDescription, Operator::Wildcard, &["a*z"]);
    assert_eq!(
        eval(&t, &text_facts(Field::MetaFileDescription, "a\\b\\z")),
        Match
    );
}

#[test]
fn alternate_data_streams_are_their_own_object() {
    let ads = at_path("C:\\x\\a.txt:payload");
    for (field, op, value, expected) in [
        (Field::PathFull, Operator::Equals, "C:\\x\\a.txt", NoMatch),
        (
            Field::PathFull,
            Operator::Equals,
            "C:\\x\\a.txt:payload",
            Match,
        ),
        (Field::PathFull, Operator::StartsWith, "C:\\x", NoMatch),
        (Field::PathFull, Operator::EndsWith, "a.txt", NoMatch),
        (Field::PathFull, Operator::EndsWith, ":payload", Match),
        (Field::PathFull, Operator::Regex, "C:\\\\x\\\\.*", NoMatch),
        (Field::PathDirectory, Operator::Equals, "C:\\x", Match),
        (Field::PathFileName, Operator::Equals, "a.txt", Match),
        (Field::PathExtension, Operator::Equals, "txt", Match),
    ] {
        let c = compile(field, op, &[value]);
        assert_eq!(eval(&c, &ads), expected, "{field:?} {op:?} {value}");
    }
}

#[test]
fn file_names_and_extensions() {
    let ext = compile(Field::PathExtension, Operator::Equals, &["exe", "ps1"]);
    assert_eq!(eval(&ext, &at_path("C:\\a.PS1")), Match);
    assert_eq!(eval(&ext, &at_path("C:\\a.exe.txt")), NoMatch);
    assert_eq!(eval(&ext, &at_path("C:\\noext")), NoMatch);
    let none = compile(Field::PathExtension, Operator::NotEquals, &["exe"]);
    assert_eq!(eval(&none, &at_path("C:\\noext")), Match);
    let name = compile(Field::PathFileName, Operator::Wildcard, &["setup*.exe"]);
    assert_eq!(eval(&name, &at_path("D:\\dl\\Setup-1.2.exe")), Match);
    assert!(matches!(
        compile_err(Field::PathExtension, Operator::Equals, &[".exe"]),
        CompileErrorKind::InvalidValue(_)
    ));
    assert!(matches!(
        compile_err(Field::PathFileName, Operator::Equals, &["a\\b"]),
        CompileErrorKind::InvalidValue(_)
    ));
}

#[test]
fn short_names_that_were_not_expanded_are_unknown() {
    let c = compile(
        Field::PathFull,
        Operator::StartsWith,
        &["C:\\Program Files"],
    );
    let mut fact = PathFact::new("C:\\PROGRA~1\\a.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    fact.short_name_unresolved = true;
    let facts = ObjectFacts::new().with_path(fact);
    let e = c.eval(&facts, &deny_ctx(&PathVariables::new()));
    assert_eq!(e.result, Unknown);
    assert!(e.notes.contains(Note::ShortNameUnresolved));
    // A negated path test cannot be dodged with a short name either.
    let not = compile(
        Field::PathFull,
        Operator::NotWildcard,
        &["C:\\Program Files\\**"],
    );
    assert_eq!(eval(&not, &facts), Unknown);
}

#[test]
fn path_variables_expand_per_evaluation() {
    let vars = PathVariables::new()
        .with(
            PathVariable::ProgramFiles,
            &["C:\\Program Files", "C:\\Program Files (x86)"],
        )
        .with(
            PathVariable::Temp,
            &["C:\\Users\\u1\\AppData\\Local\\Temp\\"],
        )
        .with(PathVariable::OsDrive, &["C:\\"]);
    let ctx = deny_ctx(&vars);
    let rows: &[(Operator, &str, &str, Tri)] = &[
        (
            Operator::StartsWith,
            "%PROGRAMFILES%\\App",
            "C:\\Program Files (x86)\\App\\a.exe",
            Match,
        ),
        (
            Operator::StartsWith,
            "%programfiles%",
            "C:\\Program Files\\a.exe",
            Match,
        ),
        (
            Operator::StartsWith,
            "%PROGRAMFILES%\\App",
            "C:\\Program Files\\AppX\\a.exe",
            NoMatch,
        ),
        (
            Operator::Equals,
            "%TEMP%\\a.exe",
            "c:\\users\\U1\\appdata\\local\\temp\\A.EXE",
            Match,
        ),
        (
            Operator::Equals,
            "%TMP%\\a.exe",
            "C:\\Users\\u1\\AppData\\Local\\Temp\\a.exe",
            Match,
        ),
        (
            Operator::Wildcard,
            "%TEMP%\\**",
            "C:\\Users\\u1\\AppData\\Local\\Temp\\x\\y.exe",
            Match,
        ),
        (
            Operator::Wildcard,
            "%TEMP%\\**",
            "C:\\Users\\u1\\AppData\\Local\\TempX\\y.exe",
            NoMatch,
        ),
        (
            Operator::Wildcard,
            "%TEMP%\\*.exe",
            "C:\\Users\\u1\\AppData\\Local\\Temp\\y.exe",
            Match,
        ),
        (Operator::Equals, "%OSDRIVE%", "C:\\", Match),
        (
            Operator::StartsWith,
            "%OSDRIVE%\\Tools",
            "C:\\Tools\\a.exe",
            Match,
        ),
    ];
    for (op, value, path, expected) in rows {
        let c = compile(Field::PathFull, *op, &[value]);
        assert_eq!(
            c.eval(&at_path(path), &ctx).result,
            *expected,
            "{op:?} {value} {path}"
        );
    }
    // A variable with no value here is unknown, with a note.
    let c = compile(Field::PathFull, Operator::StartsWith, &["%APPDATA%"]);
    let e = c.eval(&at_path("C:\\x.exe"), &ctx);
    assert_eq!(e.result, Unknown);
    assert!(e.notes.contains(Note::UnknownVariable));
    // Values that misuse variables do not compile.
    for bad in [
        "%NOPE%\\x",
        "%TEMP%x",
        "%TEMP%\\..\\x",
        "relative\\x",
        "%TEMP%\\.\\x",
    ] {
        assert!(
            matches!(
                compile_err(Field::PathFull, Operator::StartsWith, &[bad]),
                CompileErrorKind::InvalidValue(_)
            ),
            "{bad}"
        );
    }
}

#[test]
fn every_action_that_runs_trusts_or_excludes_only_trusts_safe_paths() {
    // #34: the path-ACL rule covers every action with `needs_identity`, so
    // none of them can be used to trust a user-writable path.
    let c = compile(Field::PathDirectory, Operator::Equals, &["C:\\Tools"]);
    let vars = PathVariables::new();
    for action in crate::model::ActionKind::ALL {
        let ctx = EvalContext {
            action,
            variables: &vars,
            context: &NO_CONTEXT,
        };
        for writable in [Some(true), None] {
            let mut fact = PathFact::new("C:\\Tools\\a.exe", &VolumeMap::new());
            fact.user_writable = writable;
            let e = c.eval(&ObjectFacts::new().with_path(fact), &ctx);
            if action.needs_identity() {
                assert_eq!(e.result, Unknown, "{action} {writable:?}");
                assert!(e.notes.contains(Note::PathAclUnsafe), "{action}");
            } else {
                assert_eq!(e.result, Match, "{action} {writable:?}");
                assert!(!e.notes.contains(Note::PathAclUnsafe), "{action}");
            }
        }
        // A path users cannot write matches for every action.
        assert_eq!(
            c.eval(&at_path("C:\\Tools\\a.exe"), &ctx).result,
            Match,
            "{action}"
        );
    }
}

#[test]
fn path_location_facts() {
    use crate::unknown::VolumeKind;
    let on = |raw: &str, volume: Option<VolumeKind>| {
        let mut p = PathFact::new(raw, &VolumeMap::new());
        p.volume = volume;
        p.drive_type = Some("removable".to_owned());
        p.bus = Some("usb".to_owned());
        p.user_can_change_acl = Some(false);
        ObjectFacts::new().with_path(p)
    };
    let usb = on("E:\\a.exe", Some(VolumeKind::Removable));
    let share = on("\\\\srv\\Tools\\a.exe", Some(VolumeKind::Network));
    let stream = on("C:\\x\\a.txt:payload", Some(VolumeKind::Fixed));
    let unknown_volume = on("C:\\a.exe", None);
    let check = |field, op, values: &[&str], facts: &ObjectFacts, want| {
        assert_eq!(
            eval(&compile(field, op, values), facts),
            want,
            "{field:?} {op:?} {values:?}"
        );
    };
    check(
        Field::PathDriveType,
        Operator::Equals,
        &["REMOVABLE"],
        &usb,
        Match,
    );
    check(Field::PathBus, Operator::Equals, &["usb"], &usb, Match);
    check(Field::PathBus, Operator::NotEquals, &["usb"], &usb, NoMatch);
    check(Field::PathIsUnc, Operator::IsTrue, &[], &share, Match);
    check(Field::PathIsUnc, Operator::IsFalse, &[], &usb, Match);
    // A drive path on a volume of unknown kind may be a mapped share.
    check(
        Field::PathIsUnc,
        Operator::IsFalse,
        &[],
        &unknown_volume,
        Unknown,
    );
    check(
        Field::PathShare,
        Operator::Equals,
        &["\\\\SRV\\tools"],
        &share,
        Match,
    );
    // A file on no share has no share: `equals` cannot match, and the
    // negation does.
    check(
        Field::PathShare,
        Operator::Equals,
        &["\\\\srv\\tools"],
        &usb,
        NoMatch,
    );
    check(
        Field::PathShare,
        Operator::NotEquals,
        &["\\\\srv\\tools"],
        &usb,
        Match,
    );
    check(
        Field::PathShare,
        Operator::NotEquals,
        &["\\\\x\\y"],
        &unknown_volume,
        Unknown,
    );
    check(Field::PathIsAds, Operator::IsTrue, &[], &stream, Match);
    check(Field::PathIsAds, Operator::IsTrue, &[], &usb, NoMatch);
    check(
        Field::PathUserCanChangeAcl,
        Operator::IsFalse,
        &[],
        &usb,
        Match,
    );
    // A mapped drive's UNC alias is a share.
    let mut mapped = PathFact::new("Z:\\a.exe", &VolumeMap::new());
    mapped.alias = Some(palisade_core::path::normalize("\\\\srv\\share\\a.exe"));
    let mapped = ObjectFacts::new().with_path(mapped);
    check(Field::PathIsUnc, Operator::IsTrue, &[], &mapped, Match);
    check(
        Field::PathShare,
        Operator::Equals,
        &["\\\\srv\\share"],
        &mapped,
        Match,
    );
    // Unknown facts are unknown, never a match, and neither is their
    // negation: an `unknown` drive type or bus is not known.
    let mut bare = PathFact::new("C:\\a.exe", &VolumeMap::new());
    bare.drive_type = Some("unknown".to_owned());
    let bare = ObjectFacts::new().with_path(bare);
    for (field, op, values) in [
        (Field::PathDriveType, Operator::NotEquals, &["fixed"][..]),
        (Field::PathBus, Operator::NotEquals, &["usb"][..]),
        (Field::PathUserCanChangeAcl, Operator::IsFalse, &[][..]),
    ] {
        check(field, op, values, &bare, Unknown);
        check(field, op, values, &ObjectFacts::new(), Unknown);
    }
    // These facts are read from the path, never stored by field.
    let mut f = ObjectFacts::new();
    assert!(!f.set(Field::PathBus, "usb"));
    for field in Field::ALL.into_iter().filter(|f| f.is_path_location()) {
        assert_eq!(field.strength(), Some(Strength::Weak), "{field:?}");
    }
}

#[test]
fn removable_and_hot_variables() {
    use crate::facts::PathVariable;
    assert_eq!(
        PathVariable::from_name("removable"),
        Some(PathVariable::Removable)
    );
    assert_eq!(PathVariable::from_name("HOT"), Some(PathVariable::Hot));
    let c = compile(Field::PathFull, Operator::StartsWith, &["%HOT%"]);
    let vars = PathVariables::new().with(PathVariable::Hot, &["E:\\", "F:\\"]);
    let ctx = deny_ctx(&vars);
    assert_eq!(c.eval(&at_path("F:\\setup.exe"), &ctx).result, Match);
    assert_eq!(c.eval(&at_path("C:\\setup.exe"), &ctx).result, NoMatch);
    // With no such volume mounted the agent sets no value: unknown.
    let none = PathVariables::new();
    assert_eq!(
        c.eval(&at_path("F:\\setup.exe"), &deny_ctx(&none)).result,
        Unknown
    );
}

#[test]
fn allow_rules_only_trust_paths_on_a_fixed_volume() {
    // #328: an ACL only protects a path on a local fixed disk.
    use crate::unknown::VolumeKind;
    let c = compile(Field::PathDirectory, Operator::Equals, &["C:\\Tools"]);
    let vars = PathVariables::new();
    let allow = EvalContext {
        action: ActionKind::Allow,
        variables: &vars,
        context: &NO_CONTEXT,
    };
    for volume in [
        None,
        Some(VolumeKind::Removable),
        Some(VolumeKind::Optical),
        Some(VolumeKind::Network),
    ] {
        let mut fact =
            PathFact::new("C:\\Tools\\a.exe", &VolumeMap::new()).with_user_writable(false);
        fact.volume = volume;
        assert!(!fact.acl_proven(), "{volume:?}");
        let facts = ObjectFacts::new().with_path(fact);
        let e = c.eval(&facts, &allow);
        assert_eq!(e.result, Unknown, "{volume:?}");
        assert!(e.notes.contains(Note::PathAclUnsafe), "{volume:?}");
        assert_eq!(c.eval(&facts, &deny_ctx(&vars)).result, Match, "{volume:?}");
    }
    let fixed = PathFact::new("C:\\Tools\\a.exe", &VolumeMap::new()).with_volume(VolumeKind::Fixed);
    assert!(!fixed.acl_proven(), "no ACL fact");
    assert!(fixed.clone().with_user_writable(false).acl_proven());
    assert!(!fixed.with_user_writable(true).acl_proven());
}

#[test]
fn allow_rules_only_trust_paths_users_cannot_write() {
    let c = compile(Field::PathDirectory, Operator::Equals, &["C:\\Tools"]);
    let vars = PathVariables::new();
    let allow = EvalContext {
        action: ActionKind::Allow,
        variables: &vars,
        context: &NO_CONTEXT,
    };
    for writable in [Some(true), None] {
        let mut fact = PathFact::new("C:\\Tools\\a.exe", &VolumeMap::new());
        fact.user_writable = writable;
        let facts = ObjectFacts::new().with_path(fact);
        let e = c.eval(&facts, &allow);
        assert_eq!(e.result, Unknown, "{writable:?}");
        assert!(e.notes.contains(Note::PathAclUnsafe));
        // Deny rules do not need the ACL fact.
        assert_eq!(c.eval(&facts, &deny_ctx(&vars)).result, Match);
    }
    assert_eq!(c.eval(&at_path("C:\\Tools\\a.exe"), &allow).result, Match);
    // A miss is a miss whatever the ACL.
    let unsafe_miss =
        ObjectFacts::new().with_path(PathFact::new("C:\\Other\\a.exe", &VolumeMap::new()));
    assert_eq!(c.eval(&unsafe_miss, &allow).result, NoMatch);
}

#[test]
fn signer_criteria_only_trust_good_signatures() {
    let c = compile(
        Field::SignerPublisher,
        Operator::Equals,
        &["Example Software Ltd"],
    );
    assert_eq!(
        eval(
            &c,
            &signed(vec![signer(SignerStatus::Valid, "Example Software Ltd")])
        ),
        Match
    );
    for status in [
        SignerStatus::ValidExpiredTimestamped,
        SignerStatus::CatalogSigned,
    ] {
        assert_eq!(
            eval(&c, &signed(vec![signer(status, "example software ltd")])),
            Match,
            "{status:?}"
        );
    }
    for status in [
        SignerStatus::Revoked,
        SignerStatus::DigestMismatch,
        SignerStatus::Expired,
        SignerStatus::UntrustedRoot,
    ] {
        let e = c.eval(
            &signed(vec![signer(status, "Example Software Ltd")]),
            &deny_ctx(&PathVariables::new()),
        );
        assert_eq!(e.result, NoMatch, "{status:?}");
        assert!(e.notes.contains(Note::SignerNotTrusted));
    }
    // Unsigned: known to have no signer.
    assert_eq!(eval(&c, &signed(vec![])), NoMatch);
    // Not examined: unknown.
    assert_eq!(eval(&c, &ObjectFacts::new()), Unknown);
    // Any good signature can match; a bad one is skipped.
    let both = signed(vec![
        signer(SignerStatus::Revoked, "Example Software Ltd"),
        signer(SignerStatus::Valid, "Other Ltd"),
        signer(SignerStatus::CatalogSigned, "Example Software Ltd"),
    ]);
    assert_eq!(eval(&c, &both), Match);

    let issuer = compile(
        Field::SignerIssuer,
        Operator::StartsWith,
        &["example issuing"],
    );
    assert_eq!(
        eval(&issuer, &signed(vec![signer(SignerStatus::Valid, "x")])),
        Match
    );
    let thumb = compile(
        Field::SignerLeafThumbprint,
        Operator::Equals,
        &[&SHA.to_ascii_uppercase()],
    );
    assert_eq!(
        eval(&thumb, &signed(vec![signer(SignerStatus::Valid, "x")])),
        Match
    );
    // A good signature with the attribute missing is unknown.
    let mut partial = signer(SignerStatus::Valid, "x");
    partial.publisher = None;
    assert_eq!(eval(&c, &signed(vec![partial])), Unknown);
}

#[test]
fn regex_rejects_look_around_and_backreferences_with_guidance() {
    for pattern in ["chkdsk(?! /f)", "(?=a)b", "(?<=a)b", "(?<!a)b"] {
        let kind = compile_err(Field::MetaProductName, Operator::Regex, &[pattern]);
        assert_eq!(kind, CompileErrorKind::RegexLookAround, "{pattern}");
        assert!(kind.to_string().contains("not_regex"));
    }
    for pattern in ["(a)\\1", "(a)(b)\\2"] {
        assert_eq!(
            compile_err(Field::MetaProductName, Operator::Regex, &[pattern]),
            CompileErrorKind::RegexBackreference,
            "{pattern}"
        );
    }
    assert!(matches!(
        compile_err(Field::MetaProductName, Operator::Regex, &["a("]),
        CompileErrorKind::RegexSyntax(_)
    ));
}

#[test]
fn regex_is_anchored() {
    let c = compile(Field::MetaProductName, Operator::Regex, &["dit"]);
    assert_eq!(
        eval(&c, &text_facts(Field::MetaProductName, "editor")),
        NoMatch
    );
    let c = compile(Field::MetaProductName, Operator::Regex, &[".*dit.*"]);
    assert_eq!(
        eval(&c, &text_facts(Field::MetaProductName, "editor")),
        Match
    );
    // An alternation cannot escape the anchors.
    let c = compile(Field::MetaProductName, Operator::Regex, &["a|b"]);
    assert_eq!(eval(&c, &text_facts(Field::MetaProductName, "xa")), NoMatch);
    assert_eq!(eval(&c, &text_facts(Field::MetaProductName, "b")), Match);
    // Paths are case-insensitive by default.
    let p = compile(
        Field::PathFull,
        Operator::Regex,
        &["c:\\\\tools\\\\[a-z]+\\.exe"],
    );
    assert_eq!(eval(&p, &at_path("C:\\TOOLS\\RUN.EXE")), Match);
}

#[test]
fn oversized_patterns_are_rejected() {
    // Nested bounded repetition compiles to far more than the limit.
    let big = "(((a{100}){100}){100})";
    assert_eq!(
        compile_err(Field::MetaProductName, Operator::Regex, &[big]),
        CompileErrorKind::PatternTooLarge
    );
    assert_eq!(REGEX_SIZE_LIMIT, 1 << 20, "the default from #32");
}

#[test]
fn pathological_patterns_match_in_linear_time() {
    // `(a+)+$` takes exponential time in a backtracking engine.
    let c = compile(Field::MetaFileDescription, Operator::Regex, &["(a+)+b"]);
    let text = "a".repeat(2048);
    let facts = text_facts(Field::MetaFileDescription, &text);
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = Instant::now();
    for _ in 0..100 {
        assert_eq!(eval(&c, &facts), NoMatch);
    }
    let w = compile(
        Field::MetaFileDescription,
        Operator::Wildcard,
        &["*a*a*a*a*a*a*a*a*b"],
    );
    for _ in 0..100 {
        assert_eq!(eval(&w, &facts), NoMatch);
    }
    // A backtracking engine needs longer than the age of the universe for
    // either; a linear one needs milliseconds. The bound is loose for slow
    // CI machines and debug builds.
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn strength_ratings() {
    use Strength::{Medium, Strong, Weak};
    for (field, expected) in [
        (Field::HashSha256, Strong),
        (Field::HashAuthenticodeSha256, Strong),
        (Field::SignerLeafThumbprint, Strong),
        (Field::SignerPublisher, Medium),
        (Field::PathFull, Medium),
        (Field::HashSha1, Weak),
        (Field::HashMd5, Weak),
        (Field::HashPageSha256, Weak),
        (Field::PathFileName, Weak),
        (Field::PathExtension, Weak),
        (Field::MetaProductName, Weak),
        (Field::MetaFileVersion, Weak),
    ] {
        assert_eq!(field.strength(), Some(expected), "{field:?}");
    }
    // #328: every version-resource, PE and installer fact is one the file's
    // author writes, so none identifies an object alone. MSI codes are
    // GUIDs anyone can copy into another package.
    for field in [
        Field::MetaLegalCopyright,
        Field::MetaLanguage,
        Field::MetaFileNameFallback,
        Field::MetaFileSize,
        Field::MetaPeMachine,
        Field::MetaPeSubsystem,
        Field::MetaIsDotnet,
        Field::MsiProductCode,
        Field::MsiUpgradeCode,
        Field::MsiProductName,
        Field::MsiManufacturer,
        Field::MsiProductVersion,
        Field::MsiPackageCode,
    ] {
        assert_eq!(field.strength(), Some(Weak), "{field:?}");
        assert!(!field.is_context() && !field.is_signer(), "{field:?}");
        assert_eq!(
            crate::demand::FactSet::of_field(field),
            crate::demand::FactSet::METADATA,
            "{field:?}"
        );
    }
    assert!(Strong > Medium && Medium > Weak);
    // Every weak hash is also rated weak.
    for field in Field::ALL {
        if field.is_weak_hash() {
            assert_eq!(field.strength(), Some(Weak), "{field:?}");
        }
    }
}

#[test]
fn stored_number_bool_and_guid_facts() {
    // A number fact compares as a number, not as text.
    let big = compile(Field::MetaFileSize, Operator::Gt, &["9"]);
    assert_eq!(eval(&big, &text_facts(Field::MetaFileSize, "10")), Match);
    assert_eq!(eval(&big, &text_facts(Field::MetaFileSize, "9")), NoMatch);
    for odd in ["", "x", "-1", "1e3", "99999999999999999999999"] {
        assert_eq!(
            eval(&big, &text_facts(Field::MetaFileSize, odd)),
            Unknown,
            "{odd:?}"
        );
    }
    assert_eq!(eval(&big, &ObjectFacts::new()), Unknown);
    // A yes-or-no fact is exactly `true` or `false`.
    let dotnet = compile(Field::MetaIsDotnet, Operator::IsTrue, &[]);
    assert_eq!(
        eval(&dotnet, &text_facts(Field::MetaIsDotnet, "true")),
        Match
    );
    assert_eq!(
        eval(&dotnet, &text_facts(Field::MetaIsDotnet, "false")),
        NoMatch
    );
    assert_eq!(
        eval(&dotnet, &text_facts(Field::MetaIsDotnet, "TRUE")),
        Unknown
    );
    // A GUID compares in canonical form.
    let code = compile(
        Field::MsiProductCode,
        Operator::NotEquals,
        &["{12345678-9abc-DEF0-1234-56789abcdef0}"],
    );
    assert_eq!(
        eval(
            &code,
            &text_facts(
                Field::MsiProductCode,
                "12345678-9ABC-def0-1234-56789ABCDEF0"
            )
        ),
        NoMatch
    );
    assert_eq!(
        eval(
            &code,
            &text_facts(
                Field::MsiProductCode,
                "{00000000-0000-0000-0000-000000000000}"
            )
        ),
        Match
    );
    // A malformed GUID fact cannot satisfy the negation.
    assert_eq!(
        eval(&code, &text_facts(Field::MsiProductCode, "not a guid")),
        Unknown
    );
}

#[test]
fn guids_are_canonical() {
    use super::canonical_guid;
    let canon = Some("{12345678-9ABC-DEF0-1234-56789ABCDEF0}".to_owned());
    assert_eq!(
        canonical_guid("{12345678-9abc-def0-1234-56789abcdef0}"),
        canon
    );
    assert_eq!(
        canonical_guid("12345678-9ABC-DEF0-1234-56789ABCDEF0"),
        canon
    );
    for bad in [
        "",
        "{}",
        "{12345678-9ABC-DEF0-1234-56789ABCDEF0",
        "12345678-9ABC-DEF0-1234-56789ABCDEF0}",
        "12345678-9ABC-DEF0-1234",
        "12345678-9ABC-DEF0-1234-56789ABCDEF0-0",
        "1234567-89ABC-DEF0-1234-56789ABCDEF0",
        "1234567G-9ABC-DEF0-1234-56789ABCDEF0",
        "123456789ABCDEF0123456789ABCDEF0",
        "{{12345678-9ABC-DEF0-1234-56789ABCDEF0}}",
    ] {
        assert_eq!(canonical_guid(bad), None, "{bad:?}");
    }
}

#[test]
fn facts_keep_path_and_signer_fields_out_of_the_map() {
    let mut facts = ObjectFacts::new();
    assert!(!facts.set(Field::PathFull, "C:\\x"));
    assert!(!facts.set(Field::SignerPublisher, "x"));
    assert!(facts.set(Field::MetaProductName, "x"));
    assert_eq!(facts.get(Field::PathFull), None);
    assert_eq!(facts.get(Field::MetaProductName), Some("x"));
    assert_eq!(PathVariable::from_name("tmp"), Some(PathVariable::Temp));
    assert_eq!(PathVariable::from_name("NOPE"), None);
    // Unresolved variable values are dropped.
    let vars = PathVariables::new().with(PathVariable::Temp, &["relative"]);
    assert!(vars.get(PathVariable::Temp).is_empty());
}

/// A reference wildcard matcher for non-path fields, by recursion over
/// the pattern. Exponential in the worst case, so only used on short input.
fn naive_wildcard(pattern: &[char], text: &[char]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some(('*', rest)) => (0..=text.len()).any(|i| naive_wildcard(rest, &text[i..])),
        Some(('?', rest)) => !text.is_empty() && naive_wildcard(rest, &text[1..]),
        Some((c, rest)) => text.first() == Some(c) && naive_wildcard(rest, &text[1..]),
    }
}

proptest! {
    #[test]
    fn wildcard_agrees_with_a_naive_matcher(
        pattern in "[ab*?]{0,8}",
        text in "[ab]{0,10}",
    ) {
        let c = compile(Field::MetaFileDescription, Operator::Wildcard, &[&pattern]);
        let facts = text_facts(Field::MetaFileDescription, &text);
        let p: Vec<char> = pattern.chars().collect();
        let t: Vec<char> = text.chars().collect();
        // An empty pattern is rejected by validation, but compiles here.
        prop_assert_eq!(eval(&c, &facts), Tri::from_bool(naive_wildcard(&p, &t)));
    }

    #[test]
    fn path_star_never_crosses_a_component(
        a in "[a-z]{1,5}",
        b in "[a-z]{1,5}",
    ) {
        let c = compile(Field::PathFull, Operator::Wildcard, &["C:\\*"]);
        prop_assert_eq!(eval(&c, &at_path(&format!("C:\\{a}"))), Match);
        prop_assert_eq!(eval(&c, &at_path(&format!("C:\\{a}\\{b}"))), NoMatch);
    }

    #[test]
    fn negation_is_the_kleene_complement(
        value in "[a-c]{1,3}",
        fact in proptest::option::of("[a-c]{0,4}"),
    ) {
        let facts = fact
            .as_deref()
            .map_or_else(ObjectFacts::new, |f| text_facts(Field::MetaProductName, f));
        for (pos, neg) in [
            (Operator::Equals, Operator::NotEquals),
            (Operator::Contains, Operator::NotContains),
            (Operator::Wildcard, Operator::NotWildcard),
            (Operator::Regex, Operator::NotRegex),
        ] {
            let p = eval(&compile(Field::MetaProductName, pos, &[&value]), &facts);
            let n = eval(&compile(Field::MetaProductName, neg, &[&value]), &facts);
            prop_assert_eq!(n, p.not());
        }
    }

    #[test]
    fn hash_normalisation_is_idempotent(hex in "(0x|0X)?[0-9a-fA-F]{1,70}") {
        let once = super::normalize_hex(&hex).unwrap();
        prop_assert_eq!(super::normalize_hex(&once), Some(once.clone()));
        prop_assert!(!once.starts_with("0x") || hex.to_ascii_lowercase().starts_with("0x0x"));
        prop_assert_eq!(once.to_ascii_lowercase(), once);
    }

    #[test]
    fn compile_never_panics(
        field in proptest::sample::select(Field::ALL.to_vec()),
        operator in proptest::sample::select(Operator::ALL.to_vec()),
        values in proptest::collection::vec("\\PC{0,30}", 0..4),
        fact in "\\PC{0,40}",
    ) {
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        if let Ok(c) = CompiledCriterion::compile(&crit(field, operator, &refs)) {
            let mut facts = ObjectFacts::new().with(field, fact.as_str());
            facts.path = Some(PathFact::new(&fact, &VolumeMap::new()));
            let _ = eval(&c, &facts);
            // Context fields read the same arbitrary text from the context.
            let mut context = NO_CONTEXT.clone();
            context.user.sid = Some(fact.clone());
            context.user.account_name = Some(fact.clone());
            context.user.groups = Some(vec![fact.clone()]);
            context.device.hostname = Some(fact.clone());
            context.device.tags = Some(vec![fact.clone()]);
            context.device.os_version = Some(fact.clone());
            let vars = PathVariables::new();
            let ctx = EvalContext { action: ActionKind::Allow, variables: &vars, context: &context };
            let _ = c.eval(&facts, &ctx);
        }
    }
}

#[test]
fn drive_root_variables_and_stream_text() {
    let vars = PathVariables::new().with(PathVariable::OsDrive, &["C:\\"]);
    let ctx = deny_ctx(&vars);
    for (pattern, path, expected) in [
        ("%OSDRIVE%", "C:\\", Match),
        ("%OSDRIVE%", "C:\\a.exe", NoMatch),
        ("%OSDRIVE%\\*", "C:\\a.exe", Match),
        ("%OSDRIVE%\\**", "C:\\", Match),
        ("%OSDRIVE%\\**", "D:\\a.exe", NoMatch),
    ] {
        let c = compile(Field::PathFull, Operator::Wildcard, &[pattern]);
        assert_eq!(
            c.eval(&at_path(path), &ctx).result,
            expected,
            "{pattern} {path}"
        );
    }
    // A drive letter's `:` does not name a stream.
    let c = compile(Field::PathFull, Operator::Contains, &["C:\\x"]);
    assert_eq!(eval(&c, &at_path("C:\\x\\a.txt:s")), NoMatch);
    assert_eq!(eval(&c, &at_path("C:\\x\\a.txt")), Match);
}

#[test]
fn regex_cannot_escape_its_anchors() {
    // Unbalanced groups would close the anchoring group early if the
    // pattern were pasted into text; they are syntax errors instead.
    for pattern in ["a)|(?:b", "foo)|bar|(?:baz", "a)|.*|(?:b", ")", "(?:a"] {
        assert!(
            matches!(
                compile_err(Field::MetaProductName, Operator::Regex, &[pattern]),
                CompileErrorKind::RegexSyntax(_)
            ),
            "{pattern}"
        );
    }
    // Flags inside the pattern stay inside it.
    let c = compile(Field::MetaProductName, Operator::Regex, &["(?-i)a|b"]);
    assert_eq!(eval(&c, &text_facts(Field::MetaProductName, "xb")), NoMatch);
    assert_eq!(eval(&c, &text_facts(Field::MetaProductName, "B")), NoMatch);
    assert_eq!(eval(&c, &text_facts(Field::MetaProductName, "b")), Match);
    // `$` and `^` inside a pattern are ordinary anchors; multi-line mode
    // cannot widen the match past the whole value.
    let m = compile(Field::MetaProductName, Operator::Regex, &["(?m)a$"]);
    assert_eq!(
        eval(&m, &text_facts(Field::MetaProductName, "a\nb")),
        NoMatch
    );
}

#[test]
fn stream_detection_and_variable_values() {
    // A one-character file name with a stream names a stream.
    let c = compile(Field::PathFull, Operator::EndsWith, &["a:payload"]);
    assert_eq!(eval(&c, &at_path("C:\\dir\\a:payload")), Match);
    // `%TEMP%\..::$DATA` cannot hide a `..` behind a stream type.
    for bad in ["%TEMP%\\..::$DATA\\x", "%TEMP%\\.:$DATA"] {
        assert!(
            matches!(
                compile_err(Field::PathFull, Operator::StartsWith, &[bad]),
                CompileErrorKind::InvalidValue(_)
            ),
            "{bad}"
        );
    }
    // A variable followed only by a stream type is the variable itself.
    let vars = PathVariables::new().with(PathVariable::Temp, &["C:\\Temp"]);
    let c = compile(
        Field::PathFull,
        Operator::Equals,
        &["%TEMP%\\::$INDEX_ALLOCATION"],
    );
    assert_eq!(c.eval(&at_path("C:\\Temp"), &deny_ctx(&vars)).result, Match);
    // File-name and extension checks apply to wildcards too.
    for (field, bad) in [
        (Field::PathFileName, "a\\*"),
        (Field::PathExtension, ".ex*"),
    ] {
        assert!(
            matches!(
                compile_err(field, Operator::Wildcard, &[bad]),
                CompileErrorKind::InvalidValue(_)
            ),
            "{field:?} {bad}"
        );
    }
}

#[test]
fn consecutive_double_stars_match_zero_components() {
    for (pattern, path, expected) in [
        ("C:\\a\\**\\**\\b.exe", "C:\\a\\b.exe", Match),
        ("C:\\a\\**\\**\\b.exe", "C:\\a\\x\\y\\b.exe", Match),
        ("C:\\a\\**\\**", "C:\\a", Match),
        ("**\\**\\**\\cmd.exe", "C:\\cmd.exe", Match),
        ("**\\**\\cmd.exe", "C:\\xcmd.exe", NoMatch),
    ] {
        let c = compile(Field::PathFull, Operator::Wildcard, &[pattern]);
        assert_eq!(eval(&c, &at_path(path)), expected, "{pattern} on {path}");
    }
}

#[test]
fn stream_values_and_plain_values_do_not_cross() {
    let file = at_path("C:\\Tools\\app.exe");
    let ads = at_path("C:\\Program Files\\App\\readme.txt:payload");
    for (op, value) in [
        (Operator::Wildcard, "**:**"),
        (Operator::Wildcard, "*:**"),
        (Operator::Contains, "e:p"),
    ] {
        let c = compile(Field::PathFull, op, &[value]);
        assert_eq!(eval(&c, &file), NoMatch, "{op:?} {value} on a file");
    }
    let c = compile(
        Field::PathFull,
        Operator::Contains,
        &[":\\Program Files\\App\\"],
    );
    assert_eq!(eval(&c, &ads), NoMatch);
    assert_eq!(eval(&c, &at_path("C:\\Program Files\\App\\a.exe")), Match);
    // A wildcard drive is a drive, not a stream.
    let root = compile(Field::PathFull, Operator::Wildcard, &["?:\\"]);
    assert_eq!(eval(&root, &at_path("C:\\")), Match);
    let any_drive = compile(Field::PathFull, Operator::Wildcard, &["?:\\Tools\\*.exe"]);
    assert_eq!(eval(&any_drive, &file), Match);
    assert_eq!(eval(&any_drive, &at_path("C:\\Tools\\a.exe:s")), NoMatch);
}

#[test]
fn bare_roots_have_no_name_or_directory() {
    for stream_root in ["C:\\:evil.ps1", "\\\\srv\\share\\:evil.ps1"] {
        let facts = at_path(stream_root);
        for (field, op, value) in [
            (Field::PathFileName, Operator::NotEquals, "cmd.exe"),
            (Field::PathExtension, Operator::NotEquals, "ps1"),
            (Field::PathDirectory, Operator::Equals, "C:\\"),
        ] {
            let e = compile(field, op, &[value]).eval(&facts, &deny_ctx(&PathVariables::new()));
            assert_eq!(e.result, Unknown, "{field:?} on {stream_root}");
        }
    }
    let root = at_path("C:\\");
    for (field, op, value) in [
        (Field::PathFileName, Operator::NotEquals, "cmd.exe"),
        (Field::PathExtension, Operator::NotEquals, "exe"),
        (Field::PathDirectory, Operator::NotEquals, "C:\\Tools"),
    ] {
        let e = compile(field, op, &[value]).eval(&root, &deny_ctx(&PathVariables::new()));
        assert_eq!(e.result, Unknown, "{field:?}");
        assert!(e.notes.contains(Note::FactMissing));
    }
}

#[test]
fn text_operators_on_paths_reject_variables() {
    for op in [
        Operator::Contains,
        Operator::NotContains,
        Operator::EndsWith,
    ] {
        assert!(
            matches!(
                compile_err(Field::PathFull, op, &["%TEMP%"]),
                CompileErrorKind::InvalidValue(_)
            ),
            "{op:?}"
        );
    }
    // Anywhere in the value, not only at the start.
    for v in [
        "\\%TEMP%\\",
        "\\%TEMP%\\a.exe",
        "%NOTAVAR%\\%appdata%",
        "50%%TEMP%",
    ] {
        assert!(
            matches!(
                compile_err(Field::PathFull, Operator::Contains, &[v]),
                CompileErrorKind::InvalidValue(_)
            ),
            "{v}"
        );
    }
    // Text that only looks like a variable is fine.
    compile(Field::PathFull, Operator::Contains, &["%NOTAVAR%"]);
    compile(Field::PathFull, Operator::Contains, &["100% done"]);
    // A variable value that names a stream is dropped.
    let vars = PathVariables::new().with(PathVariable::Temp, &["C:\\Temp:s"]);
    assert!(vars.get(PathVariable::Temp).is_empty());
}

#[test]
fn unicode_classes_compile_within_the_limit() {
    // The class is built from the parsed tree, not printed out as text and
    // parsed again, so a long run of `\w` is bounded by the size limit.
    let many = "\\w".repeat(1000);
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = Instant::now();
    let r = CompiledCriterion::compile(&crit(Field::MetaProductName, Operator::Regex, &[&many]));
    assert!(
        matches!(
            r.map(|_| ()).map_err(|mut e| e.remove(0).kind),
            Ok(()) | Err(CompileErrorKind::PatternTooLarge)
        ),
        "neither compiled nor too large"
    );
    assert!(start.elapsed() < Duration::from_secs(20));
}

/// A reference path-glob matcher, over components: a whole `**`
/// component matches any number of components, and other components
/// match one component with `*` and `?`.
fn naive_path_glob(pattern: &[&str], text: &[&str]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((&"**", rest)) => (0..=text.len()).any(|i| naive_path_glob(rest, &text[i..])),
        Some((p, rest)) => {
            let p: Vec<char> = p.chars().collect();
            text.first().is_some_and(|t| {
                let t: Vec<char> = t.chars().collect();
                naive_wildcard(&p, &t)
            }) && naive_path_glob(rest, &text[1..])
        }
    }
}

proptest! {
    #[test]
    fn path_wildcard_agrees_with_a_naive_matcher(
        rooted in any::<bool>(),
        pattern in proptest::collection::vec(
            proptest::sample::select(vec!["a", "b", "*", "?", "**", "a*", "*b", "?b"]),
            1..5,
        ),
        text in proptest::collection::vec(
            proptest::sample::select(vec!["a", "b", "ab", "ba", "bb"]),
            0..5,
        ),
    ) {
        // The bare root `C:\` is written with its separator, which the
        // per-component reference cannot express for an unrooted pattern.
        if !rooted && text.is_empty() {
            return Ok(());
        }
        let fact = format!("C:\\{}", text.join("\\"));
        let mut ps: Vec<&str> = Vec::new();
        if rooted {
            ps.push("C:");
        }
        ps.extend(pattern.iter().copied());
        let mut ts = vec!["C:"];
        ts.extend(text.iter().copied());
        let c = compile(Field::PathFull, Operator::Wildcard, &[&ps.join("\\")]);
        prop_assert_eq!(
            eval(&c, &at_path(&fact)),
            Tri::from_bool(naive_path_glob(&ps, &ts)),
            "{} on {}", ps.join("\\"), fact
        );
    }
}

#[test]
fn variables_are_only_expanded_at_the_start() {
    for (op, v) in [
        (Operator::Wildcard, "**\\%TEMP%\\*.exe"),
        (Operator::StartsWith, "%OSDRIVE%\\%WINDIR%"),
        (Operator::Equals, "C:\\%TEMP%\\a.exe"),
    ] {
        assert!(
            matches!(
                compile_err(Field::PathFull, op, &[v]),
                CompileErrorKind::InvalidValue(_)
            ),
            "{op:?} {v}"
        );
    }
    // A bare `?:` is drive-relative, like `C:`, and is not a drive root.
    let c = compile(Field::PathFull, Operator::Wildcard, &["?:"]);
    assert_eq!(eval(&c, &at_path("C:\\")), NoMatch);
}

#[test]
fn unanchored_regex_matches_a_substring() {
    let mut c = crit(Field::MetaProductName, Operator::Regex, &["Suite [0-9]+"]);
    let anchored = CompiledCriterion::compile(&c).unwrap();
    c.anchored = Some(false);
    let substring = CompiledCriterion::compile(&c).unwrap();
    let facts = text_facts(Field::MetaProductName, "Example Suite 12 (x64)");
    assert_eq!(eval(&anchored, &facts), NoMatch);
    assert_eq!(eval(&substring, &facts), Match);
    // Explicitly anchored is the default.
    c.anchored = Some(true);
    assert_eq!(
        eval(&CompiledCriterion::compile(&c).unwrap(), &facts),
        NoMatch
    );
    // `not_regex` takes it too.
    let mut n = crit(Field::MetaProductName, Operator::NotRegex, &["beta"]);
    n.anchored = Some(false);
    let n = CompiledCriterion::compile(&n).unwrap();
    assert_eq!(
        eval(&n, &text_facts(Field::MetaProductName, "App beta 2")),
        NoMatch
    );
    assert_eq!(
        eval(&n, &text_facts(Field::MetaProductName, "App 2")),
        Match
    );
    // Only regular expressions take it.
    let mut w = crit(Field::MetaProductName, Operator::Wildcard, &["x*"]);
    w.anchored = Some(false);
    assert!(matches!(
        CompiledCriterion::compile(&w).unwrap_err()[0].kind,
        CompileErrorKind::OptionNotApplicable("anchored", _)
    ));
}

#[test]
fn match_ads_lets_a_file_value_match_its_streams() {
    let stream = at_path(r"C:\Tools\a.exe:payload");
    let file = at_path(r"C:\Tools\a.exe");
    for (operator, value) in [
        (Operator::Wildcard, r"C:\Tools\*"),
        (Operator::Equals, r"C:\Tools\a.exe"),
        (Operator::StartsWith, r"C:\Tools"),
        (Operator::Regex, r"C:\\Tools\\a\.exe"),
        (Operator::EndsWith, "a.exe"),
    ] {
        let mut c = crit(Field::PathFull, operator, &[value]);
        let plain = CompiledCriterion::compile(&c).unwrap();
        c.match_ads = Some(true);
        let with = CompiledCriterion::compile(&c).unwrap();
        assert_eq!(eval(&plain, &stream), NoMatch, "{operator:?} {value}");
        assert_eq!(eval(&with, &stream), Match, "{operator:?} {value}");
        assert_eq!(eval(&with, &file), Match, "{operator:?} {value}");
    }
    // A value that names a stream still only matches that stream.
    let mut c = crit(
        Field::PathFull,
        Operator::Equals,
        &[r"C:\Tools\a.exe:other"],
    );
    c.match_ads = Some(true);
    let named = CompiledCriterion::compile(&c).unwrap();
    assert_eq!(eval(&named, &stream), NoMatch);
    // Only positive tests of `path.full` take it: a negation would let a
    // stream escape a rule written for its file.
    for (field, operator) in [
        (Field::PathFull, Operator::NotWildcard),
        (Field::PathDirectory, Operator::Equals),
        (Field::MetaProductName, Operator::Equals),
    ] {
        let mut c = crit(field, operator, &[r"C:\Tools"]);
        c.match_ads = Some(true);
        assert!(
            matches!(
                CompiledCriterion::compile(&c).unwrap_err()[0].kind,
                CompileErrorKind::OptionNotApplicable("match_ads", _)
            ),
            "{field:?} {operator:?}"
        );
    }
}
