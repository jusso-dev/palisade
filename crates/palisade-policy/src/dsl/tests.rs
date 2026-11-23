use proptest::prelude::*;

use super::*;
use crate::model::arbitrary;
use crate::validate::ErrorCode;

const MINIMAL: &str = "\
schema_version: 1.0.0
policy:
  id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f
  name: Minimal
  revision: 1
  mode: audit
";

/// `MINIMAL` with `extra` appended under `policy:` (indented by the caller).
fn minimal_with(extra: &str) -> String {
    format!("{MINIMAL}{extra}")
}

fn err(input: &str) -> YamlError {
    from_str(input).unwrap_err()
}

fn at(e: &YamlError) -> (usize, usize) {
    let l = e.location().unwrap();
    (l.line, l.column)
}

#[test]
fn minimal_yaml_equals_minimal_json() {
    let json = PolicyDocument::from_json(
        r#"{"schema_version": "1.0.0", "policy": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "Minimal", "revision": 1, "mode": "audit"}}"#,
    )
    .unwrap();
    assert_eq!(PolicyDocument::from_yaml(MINIMAL).unwrap(), json);
}

#[test]
fn json_text_is_accepted() {
    let json = include_str!("../../tests/fixtures/valid/workstation-baseline.json");
    assert_eq!(
        PolicyDocument::from_yaml(json).unwrap(),
        PolicyDocument::from_json(json).unwrap()
    );
}

#[test]
fn byte_order_mark_is_allowed() {
    let text = format!("\u{feff}{MINIMAL}");
    assert!(from_str(&text).is_ok());
}

#[test]
fn crlf_line_endings_give_the_same_document_and_locations() {
    let crlf = minimal_with("  colour: red\n").replace('\n', "\r\n");
    let e = err(&crlf);
    assert_eq!(e.kind(), YamlErrorKind::Mismatch);
    assert_eq!(at(&e), (7, 3));
    let ok = MINIMAL.replace('\n', "\r\n");
    assert_eq!(
        PolicyDocument::from_yaml(&ok).unwrap(),
        PolicyDocument::from_yaml(MINIMAL).unwrap()
    );
}

#[test]
fn anchors_aliases_tags_and_merge_keys_are_rejected() {
    for (input, line, column) in [
        ("a: &x 1\nb: *x\n", 1, 7),
        ("&x a: 1\n", 1, 4),
        ("a: !!str 1\n", 1, 10),
        ("a: !local x\n", 1, 11),
        ("--- !!map\na: 1\n", 2, 1),
        ("a: 1\n<<: {b: 2}\n", 2, 1),
        ("{\"a\": [&x 1]}\n", 1, 11),
    ] {
        let e = err(input);
        assert_eq!(
            e.kind(),
            YamlErrorKind::UnsupportedFeature,
            "{input:?}: {e}"
        );
        assert_eq!(at(&e), (line, column), "{input:?}: {e}");
    }
    // An alias with no anchor is a syntax error before it is an alias.
    assert!(from_str("a: *x\n").is_err());
}

#[test]
fn billion_laughs_is_rejected_at_the_first_anchor() {
    let mut text = String::from("l0: &l0 [lol, lol, lol, lol, lol, lol, lol, lol, lol]\n");
    for i in 1..10 {
        let refs = vec![format!("*l{}", i - 1); 9].join(", ");
        text.push_str(&format!("l{i}: &l{i} [{refs}]\n"));
    }
    let e = err(&text);
    assert_eq!(e.kind(), YamlErrorKind::UnsupportedFeature);
    // Reported at the anchored value.
    assert_eq!(at(&e), (1, 9));
}

#[test]
fn directives_other_than_yaml_1_2_are_rejected() {
    assert!(from_str(&format!("%YAML 1.2\n---\n{MINIMAL}")).is_ok());
    for input in [
        format!("%YAML 1.1\n---\n{MINIMAL}"),
        format!("%TAG !e! tag:example.org,2026:\n---\n{MINIMAL}"),
    ] {
        let e = err(&input);
        assert_eq!(e.kind(), YamlErrorKind::UnsupportedFeature, "{e}");
        assert_eq!(at(&e), (1, 1));
    }
}

#[test]
fn directives_are_checked_before_every_document_only() {
    for (input, line) in [
        (format!("{MINIMAL}...\n%YAML 1.1\n---\n{MINIMAL}"), 8),
        (
            format!("{MINIMAL}...\n# note\n%TAG ! tag:example.org,2026:\n---\n{MINIMAL}"),
            9,
        ),
        (format!("%FOO bar\n---\n{MINIMAL}"), 1),
    ] {
        let e = from_str_all(&input, &Limits::DEFAULT).unwrap_err();
        assert_eq!(
            e.kind(),
            YamlErrorKind::UnsupportedFeature,
            "{input:?}: {e}"
        );
        assert_eq!(at(&e), (line, 1), "{input:?}: {e}");
    }
    // The parser's character index drifts after a long block-scalar line
    // of multi-byte text; directives after it are still found.
    let long = "\u{e9}".repeat(50);
    for (input, line) in [
        (
            format!("{MINIMAL}  description: |\n    {long}\n...\n%YAML 1.1\n---\n{MINIMAL}"),
            10,
        ),
        (
            format!("{MINIMAL}  description: |\n    {long}\n...\r\n%TAG ! x:\r\n---\n{MINIMAL}"),
            10,
        ),
        (
            format!("{MINIMAL}  description: |\n    {long}\n...\n\n%FOO\n--- {MINIMAL}"),
            11,
        ),
    ] {
        let e = from_str_all(&input, &Limits::DEFAULT).unwrap_err();
        assert_eq!(
            e.kind(),
            YamlErrorKind::UnsupportedFeature,
            "{input:?}: {e}"
        );
        assert_eq!(at(&e), (line, 1), "{input:?}: {e}");
    }
    // And a `%` line inside a later document's content is not a directive.
    let input = format!("a: |\n  {long}\n--- \"x\n%not a directive\n y\"\n");
    let mut roots = Vec::new();
    parse::parse(&input, &Limits::DEFAULT, false, |root| {
        roots.push(root);
        Ok(())
    })
    .unwrap();
    assert_eq!(roots.len(), 2);
    assert_eq!(
        roots[1].value,
        parse::Value::Str("x %not a directive y".to_owned())
    );
    // Comments and `%YAML 1.2` with a comment are fine; a `%` inside a
    // document's content is not a directive.
    assert!(from_str(&format!("# c\n%YAML 1.2 # c\n---\n{MINIMAL}")).is_ok());
    let v = to_json_value("--- |\n%not a directive\n", &Limits::DEFAULT).unwrap();
    assert_eq!(v, serde_json::json!("%not a directive\n"));
}

#[test]
fn deep_input_before_a_directive_is_bounded_by_the_limits() {
    // A directive line after deep nesting must not make the reader scan or
    // buffer the whole input before the depth limit applies.
    for tail in ["\n%", "\n...\n%YAML 1.1\n---\na: 1\n"] {
        let input = format!("{}x{tail}", "- ".repeat(200_000));
        let e = err(&input);
        assert_eq!(e.kind(), YamlErrorKind::LimitExceeded, "{e}");
        assert_eq!(at(&e).0, 1);
    }
}

#[test]
fn source_locations_scale_linearly_with_findings() {
    // Every `advanced` key is a finding; locating them must not take time
    // proportional to the map size for each one.
    let keys: String = (0..200_000).map(|i| format!("      k{i}: 1\n")).collect();
    let text = minimal_with(&format!("  settings:\n    advanced:\n{keys}"));
    let started = std::time::Instant::now();
    let errors = from_str(&text).unwrap().validate().unwrap_err();
    assert_eq!(errors.len(), 200_001);
    let last = errors.last().unwrap();
    assert_eq!(last.error.path, "/policy/settings/advanced/k99999");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn duplicate_keys_are_rejected_in_every_map() {
    for (input, line, column) in [
        (minimal_with("  name: Again\n"), 7, 3),
        (minimal_with("  \"name\": Again\n"), 7, 3),
        ("{\"a\": 1, \"a\": 2}".to_owned(), 1, 10),
        (
            minimal_with(
                "  settings:\n    advanced:\n      a.b: 1\n      a.b: 2\n    allow_unknown_advanced: true\n",
            ),
            10,
            7,
        ),
    ] {
        let e = err(&input);
        assert_eq!(e.kind(), YamlErrorKind::DuplicateKey, "{input}: {e}");
        assert_eq!(at(&e), (line, column), "{input}: {e}");
        assert!(e.message().contains("first used at line"), "{e}");
    }
}

#[test]
fn unknown_fields_are_rejected_with_location_and_pointer() {
    let e = err(&minimal_with("  colour: red\n"));
    assert_eq!(e.kind(), YamlErrorKind::Mismatch);
    assert_eq!(at(&e), (7, 3));
    assert_eq!(e.pointer(), Some("/policy/colour"));
    assert!(e.message().contains("unknown field `colour`"), "{e}");
    assert_eq!(
        e.to_string(),
        format!(
            "error[model_mismatch] line 7, column 3 /policy/colour: {}",
            e.message()
        )
    );
}

#[test]
fn norway_problem_scalars_are_rejected() {
    for word in ["yes", "No", "NO", "on", "OFF", "y", "N"] {
        let e = err(&minimal_with(&format!("  description: {word}\n")));
        assert_eq!(e.kind(), YamlErrorKind::AmbiguousScalar, "{word}: {e}");
        assert_eq!(at(&e), (7, 16), "{word}");
        // Quoted, it is text.
        let doc = PolicyDocument::from_yaml(&minimal_with(&format!("  description: '{word}'\n")))
            .unwrap();
        assert_eq!(doc.policy.description.as_deref(), Some(word));
    }
}

#[test]
fn non_json_numbers_are_rejected() {
    for number in [
        "010", "+1", "0x1f", "0o17", "0b11", "1_000", "1:30", ".5", "1.", "-.inf", ".NaN", "0X1F",
        "0O17", "0B11",
    ] {
        // Rejected while typing the scalar, not later as a type mismatch,
        // so a numeric field cannot accept the same spelling either.
        for field in ["description", "revision"] {
            let text = if field == "revision" {
                MINIMAL.replace("revision: 1", &format!("revision: {number}"))
            } else {
                minimal_with(&format!("  description: {number}\n"))
            };
            let e = err(&text);
            assert_eq!(
                e.kind(),
                YamlErrorKind::AmbiguousScalar,
                "{field}: {number}: {e}"
            );
        }
    }
    // These look numeric but are text in every YAML version.
    for text in [
        "1.0.0",
        "2027-06-30",
        "1-2",
        "0x",
        "e5",
        "1e",
        "1.2.3.4",
        "R-000001",
    ] {
        let doc = PolicyDocument::from_yaml(&minimal_with(&format!("  description: {text}\n")))
            .unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(doc.policy.description.as_deref(), Some(text));
    }
}

#[test]
fn values_are_never_coerced_to_the_field_type() {
    // A number where text is wanted.
    let e = err(&minimal_with("  description: 12\n"));
    assert_eq!(e.kind(), YamlErrorKind::Mismatch);
    assert_eq!(e.pointer(), Some("/policy/description"));
    assert!(e.message().contains("quote the value"), "{e}");
    // Text where a number is wanted.
    let e = err(&MINIMAL.replace("revision: 1", "revision: \"1\""));
    assert_eq!(e.pointer(), Some("/policy/revision"));
    assert_eq!(at(&e), (5, 13));
    // A float where an integer is wanted.
    let e = err(&MINIMAL.replace("revision: 1", "revision: 1.0"));
    assert_eq!(e.pointer(), Some("/policy/revision"));
    // A boolean where text is wanted.
    let e = err(&minimal_with("  description: true\n"));
    assert_eq!(e.pointer(), Some("/policy/description"));
    // Out of range.
    let e = err(&MINIMAL.replace("revision: 1", "revision: 18446744073709551616"));
    assert_eq!(e.pointer(), Some("/policy/revision"));
    let e = err(&MINIMAL.replace("revision: 1", "revision: -1"));
    assert_eq!(e.pointer(), Some("/policy/revision"));
    // `-0` is a float, as it is to the JSON reader.
    let e = err(&MINIMAL.replace("revision: 1", "revision: -0"));
    assert_eq!(e.pointer(), Some("/policy/revision"));
    let json = r#"{"schema_version": "1.0.0", "policy": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "M", "revision": -0, "mode": "audit"}}"#;
    assert!(PolicyDocument::from_json(json).is_err());
    assert_eq!(
        to_json_value("a: -0\n", &Limits::DEFAULT).unwrap(),
        serde_json::from_str::<serde_json::Value>(r#"{"a": -0}"#).unwrap()
    );
}

#[test]
fn quote_hint_is_given_only_where_text_is_expected() {
    for (from, to, hint) in [
        ("name: Minimal", "name: 12", true),
        ("mode: audit", "mode: 1", true),
        ("id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "id: 1", true),
        ("revision: 1", "revision: 1.0", false),
        ("revision: 1", "revision: true", false),
        (
            "mode: audit",
            "mode: audit\n  settings: {capture_command_line: 1}",
            false,
        ),
        ("mode: audit", "mode: audit\n  metadata: {tags: 1}", false),
    ] {
        let e = err(&MINIMAL.replace(from, to));
        assert_eq!(e.message().contains("quote the value"), hint, "{to}: {e}");
    }
    // A match tree is a map, so a number there gets no quoting hint.
    let e = err(&with_action("{type: deny}")
        .replace("match: {criterion", "match: 1\n        x: {criterion"));
    assert!(e.message().contains("expected enum Match"), "{e}");
    assert!(!e.message().contains("quote the value"), "{e}");
}

#[test]
fn keys_must_be_text() {
    for input in [
        "1: a\n",
        "true: a\n",
        "? [a]\n: b\n",
        "? {a: 1}\n: b\n",
        "yes: a\n",
    ] {
        let e = err(input);
        assert!(
            matches!(
                e.kind(),
                YamlErrorKind::Mismatch | YamlErrorKind::AmbiguousScalar
            ),
            "{input:?}: {e}"
        );
        assert_eq!(at(&e).0, 1, "{input:?}");
    }
    // A quoted key is text, whatever it spells.
    assert!(to_json_value("\"1\": a\n'yes': b\n", &Limits::DEFAULT).is_ok());
}

#[test]
fn null_and_absent_optional_fields_are_the_same() {
    for null in ["null", "~", "", "Null", "NULL"] {
        let doc = PolicyDocument::from_yaml(&minimal_with(&format!("  description: {null}\n")))
            .unwrap_or_else(|e| panic!("{null:?}: {e}"));
        assert_eq!(doc, PolicyDocument::from_yaml(MINIMAL).unwrap());
    }
}

#[test]
fn control_characters_in_the_text_are_rejected() {
    for (input, line, column) in [
        ("schema_version: 1.0.0\0policy: x\n", 1, 22),
        ("a: b\nc: x\u{7}y\n", 2, 5),
        ("a: 'x\u{1b}'\n", 1, 6),
        // Line breaks to YAML 1.1 but not to YAML 1.2.
        ("a: b # c\u{85}d: e\n", 1, 9),
        ("a: b # c\u{2028}d: e\n", 1, 9),
        ("a: 'x\u{2029}'\n", 1, 6),
        // A byte order mark is only allowed as the first character.
        ("a: \u{feff}x\n", 1, 4),
        ("\u{feff}\u{feff}a: 1\n", 1, 1),
        ("a: 1\n...\n\u{feff}--- b\n", 3, 1),
    ] {
        let e = err(input);
        assert_eq!(e.kind(), YamlErrorKind::Syntax, "{input:?}: {e}");
        assert_eq!(at(&e), (line, column), "{input:?}: {e}");
    }
    // Escapes are fine; validation then decides whether the value is allowed.
    let doc = PolicyDocument::from_yaml(&minimal_with("  description: \"a\\u0007b\"\n")).unwrap();
    assert_eq!(doc.policy.description.as_deref(), Some("a\u{7}b"));
    let errors = from_str(&minimal_with("  description: \"a\\u0007b\"\n"))
        .unwrap()
        .validate()
        .unwrap_err();
    assert_eq!(errors[0].error.code, ErrorCode::InvalidText);
    assert_eq!(
        errors[0].location,
        Location {
            line: 7,
            column: 16
        }
    );
}

#[test]
fn input_size_depth_and_node_count_are_bounded() {
    let limits = Limits {
        max_bytes: 64,
        max_depth: 4,
        max_nodes: 10,
        max_lookahead: 1024,
    };
    let e = from_str_with_limits(MINIMAL, &limits).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::LimitExceeded);
    assert_eq!(e.location(), None);

    let limits = Limits {
        max_depth: 4,
        ..Limits::DEFAULT
    };
    // The root map is level 1, so three nested sequences reach level 4.
    assert!(to_json_value("a: [[[x]]]\n", &limits).is_ok());
    let e = from_str_with_limits("a: [[[[x]]]]\n", &limits).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::LimitExceeded);
    assert_eq!(at(&e), (1, 7));

    let limits = Limits {
        max_nodes: 10,
        ..Limits::DEFAULT
    };
    let e = from_str_with_limits(MINIMAL, &limits).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::LimitExceeded);
}

#[test]
fn deepest_allowed_input_deserializes_on_a_small_stack() {
    // The default depth reaches the deserializer, which recurses once per
    // level; it must fit a thread's stack with plenty to spare.
    let mut tree = String::from("{criterion: {field: hash.sha256, operator: equals, values: [x]}}");
    for _ in 0..118 {
        tree = format!("{{not: {tree}}}");
    }
    let text = format!(
        "{MINIMAL}  rule_sets: [01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60]
rule_sets:
  - id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60
    name: Set
    kind: mixed
    rules:
      - id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61
        name: Deep
        match: {tree}
        action: {{type: deny}}
"
    );
    let loaded = std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(move || from_str(&text).map(|d| d.document().rule_sets[0].rules[0].match_.depth()))
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(loaded.unwrap(), 119);
}

#[test]
fn default_depth_limit_stops_deep_input_without_overflow() {
    // Block sequences are not bounded by the parser itself.
    let deep = format!("{}x\n", "- ".repeat(100_000));
    let e = err(&deep);
    assert_eq!(e.kind(), YamlErrorKind::LimitExceeded);
    let deep_flow = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(from_str(&deep_flow).is_err());
    let deep_map = (0..100_000).fold(String::new(), |mut s, i| {
        s.push_str(&" ".repeat(i % 200));
        s.push_str("a:\n");
        s
    });
    assert!(from_str(&deep_map).is_err());
}

#[test]
fn match_trees_deeper_than_the_model_allows_still_load() {
    // Depth is a validation finding (tree_too_deep), not a load error, as in
    // the JSON form, so the user gets the stable code and its location.
    let mut tree = String::from("criterion: {field: hash.sha256, operator: equals, values: [x]}");
    for _ in 0..20 {
        tree = format!("not: {{{tree}}}");
    }
    let text = format!(
        "{MINIMAL}  rule_sets: [01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60]
rule_sets:
  - id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60
    name: Set
    kind: mixed
    rules:
      - id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61
        name: Deep
        match: {{{tree}}}
        action: {{type: deny}}
"
    );
    let errors = from_str(&text).unwrap().validate().unwrap_err();
    let deep = errors
        .iter()
        .find(|e| e.error.code == ErrorCode::TreeTooDeep)
        .unwrap();
    assert_eq!(deep.error.path, "/rule_sets/0/rules/0/match");
    assert_eq!(
        deep.location,
        Location {
            line: 15,
            column: 16
        }
    );
}

#[test]
fn empty_and_multi_document_input() {
    for input in ["", "# only a comment\n", "\u{feff}"] {
        assert_eq!(err(input).kind(), YamlErrorKind::Syntax, "{input:?}");
    }
    let two = format!("{MINIMAL}---\n{MINIMAL}");
    let e = err(&two);
    assert_eq!(e.kind(), YamlErrorKind::UnsupportedFeature);
    // The `---` that starts the second document.
    assert_eq!(at(&e).0, 7);
    let all = from_str_all(&two, &Limits::DEFAULT).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].document(), all[1].document());
    // The second document's errors point into the second document.
    let bad = format!("{MINIMAL}---\n{}", minimal_with("  colour: red\n"));
    let e = from_str_all(&bad, &Limits::DEFAULT).unwrap_err();
    assert_eq!(at(&e), (14, 3));
}

#[test]
fn schema_version_is_checked_before_the_body() {
    let e = err(&MINIMAL
        .replace("1.0.0", "2.0.0")
        .replace("mode: audit", "mode: future"));
    assert_eq!(e.kind(), YamlErrorKind::UnsupportedSchemaVersion);
    assert_eq!(
        e.kind().code(),
        ErrorCode::UnsupportedSchemaVersion.as_str()
    );
    assert_eq!(e.pointer(), Some("/schema_version"));
    assert_eq!(at(&e), (1, 17));
    for input in [
        MINIMAL.replace("schema_version: 1.0.0\n", ""),
        MINIMAL.replace("1.0.0", "1"),
        MINIMAL.replace("1.0.0", "[1]"),
    ] {
        assert_eq!(err(&input).kind(), YamlErrorKind::MissingSchemaVersion);
    }
    assert_eq!(err("- a\n").kind(), YamlErrorKind::Mismatch);
    // A newer minor version is readable.
    assert!(from_str(&MINIMAL.replace("1.0.0", "1.7.0")).is_ok());
}

#[test]
fn syntax_errors_have_locations() {
    let e = err("a: [1, 2\n");
    assert_eq!(e.kind(), YamlErrorKind::Syntax);
    assert_eq!(at(&e), (2, 1));
    let e = err("a: b\n c: d\n");
    assert_eq!(e.kind(), YamlErrorKind::Syntax);
    assert_eq!(at(&e).0, 2);
}

#[test]
fn enums_take_their_names_or_a_single_key_map() {
    let base = "\
schema_version: 1.0.0
policy:
  id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f
  name: Trees
  revision: 1
  mode: enforce
  rule_sets: [01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60]
rule_sets:
  - id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60
    name: Set
    kind: mixed
    rules:
      - id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61
        name: Rule
        action: {type: deny}
        match:
";
    let ok = format!(
        "{base}          any:\n            - criterion: {{field: path.extension, operator: equals, values: [ps1]}}\n"
    );
    assert!(from_str(&ok).unwrap().validate().is_ok());
    let two_keys = format!("{base}          any: []\n          all: []\n");
    let e = err(&two_keys);
    assert_eq!(e.kind(), YamlErrorKind::Mismatch);
    assert_eq!(e.pointer(), Some("/rule_sets/0/rules/0/match"));
    assert_eq!(at(&e), (17, 11));
    let unknown = format!("{base}          some: []\n");
    let e = err(&unknown);
    assert_eq!(e.pointer(), Some("/rule_sets/0/rules/0/match/some"));
    assert_eq!(at(&e), (17, 11));
}

#[test]
fn validation_findings_keep_codes_and_paths_and_gain_locations() {
    let text = include_str!("../../tests/fixtures/invalid/multiple-errors.json");
    let json_errors = PolicyDocument::from_json(text)
        .unwrap()
        .validate()
        .unwrap_err();
    let yaml = to_string(&PolicyDocument::from_json(text).unwrap()).unwrap();
    let located = from_str(&yaml).unwrap().validate().unwrap_err();
    assert_eq!(
        located.iter().map(|l| l.error.clone()).collect::<Vec<_>>(),
        json_errors
    );
    let loaded = from_str(&yaml).unwrap();
    let source_map = loaded.source_map();
    for l in &located {
        assert_eq!(source_map.locate(&l.error.path), l.location);
    }
    // The first finding is `invalid_name /policy/name`: the value of `name:`.
    assert_eq!(located[0].error.path, "/policy/name");
    let line = yaml.lines().nth(located[0].location.line - 1).unwrap();
    assert!(line.starts_with("  name: "), "{line:?}");
    assert_eq!(located[0].location.column, "  name: ".len() + 1);
    assert_eq!(
        located[0].to_string(),
        format!(
            "line {}, column {}: {}",
            located[0].location.line, located[0].location.column, located[0].error
        )
    );
}

#[test]
fn locate_falls_back_to_the_nearest_present_value() {
    let loaded = from_str(MINIMAL).unwrap();
    let map = loaded.source_map();
    assert_eq!(map.locate(""), Location { line: 1, column: 1 });
    assert_eq!(map.locate("/policy"), Location { line: 3, column: 3 });
    assert_eq!(map.locate("/policy/name"), Location { line: 4, column: 9 });
    assert_eq!(
        map.locate("/policy/settings/advanced"),
        Location { line: 3, column: 3 }
    );
    assert_eq!(
        map.locate("/policy/name/0"),
        Location { line: 4, column: 9 }
    );
}

#[test]
fn pointer_tokens_are_escaped() {
    let text = minimal_with(
        "  settings:\n    allow_unknown_advanced: true\n    advanced:\n      \"a/b~c\": 1\n",
    );
    let errors = from_str(&text).unwrap().validate().unwrap_err();
    assert_eq!(errors[0].error.path, "/policy/settings/advanced/a~1b~0c");
    assert_eq!(
        errors[0].location,
        Location {
            line: 10,
            column: 16
        }
    );
}

#[test]
fn writer_output_is_canonical() {
    let doc = PolicyDocument::from_json(include_str!(
        "../../tests/fixtures/valid/workstation-baseline.json"
    ))
    .unwrap();
    let yaml = to_string(&doc).unwrap();
    assert!(yaml.starts_with(SCHEMA_HEADER));
    let body = yaml.strip_prefix(SCHEMA_HEADER).unwrap();
    assert!(
        body.starts_with(
            "schema_version: \"1.0.0\"\npolicy:\n  id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f\n"
        ),
        "{body}"
    );
    assert!(!body.contains('\t'));
    for line in body.lines() {
        let spaces = line.len() - line.trim_start_matches(' ').len();
        assert_eq!(spaces % 2, 0, "{line:?}");
        assert!(!line.ends_with(' '), "{line:?}");
    }
    // Writing what was read gives the same bytes.
    assert_eq!(
        to_string(&PolicyDocument::from_yaml(&yaml).unwrap()).unwrap(),
        yaml
    );
}

#[test]
fn writer_quotes_every_ambiguous_string() {
    for s in [
        "",
        " a",
        "a ",
        "yes",
        "No",
        "on",
        "null",
        "~",
        "true",
        "1",
        "-1",
        "1.5",
        "1e3",
        "010",
        "0x1f",
        "0X1F",
        "0B1",
        "1_000",
        "1:30",
        ".inf",
        "1.0.0",
        "2027-06-30",
        "12:30:00",
        "a: b",
        "a #b",
        "- a",
        "[a]",
        "{a}",
        "&a",
        "*a",
        "!a",
        "%a",
        "@a",
        "`a",
        "'a",
        "\"a",
        "a\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "\u{feff}a",
        "a\u{7}b",
        "a\u{7f}b",
        "?a",
        "|a",
        ">a",
        "<<",
        "---",
        "...",
        "é",
        "a,b",
    ] {
        let mut doc = PolicyDocument::from_yaml(MINIMAL).unwrap();
        doc.policy.description = Some(s.to_owned());
        let yaml = to_string(&doc).unwrap();
        let back =
            PolicyDocument::from_yaml(&yaml).unwrap_or_else(|e| panic!("{s:?}: {e}\n{yaml}"));
        assert_eq!(back.policy.description.as_deref(), Some(s), "{yaml}");
        let line = yaml
            .lines()
            .find(|l| l.starts_with("  description:"))
            .unwrap();
        let value = line.strip_prefix("  description: ").unwrap();
        assert!(value.starts_with('"'), "{s:?} written unquoted: {line}");
    }
    // Simple text stays readable.
    for s in [
        "Example Editor",
        "hash.sha256",
        "Tools\\x.exe",
        "R-000001",
        "a-b_c.d",
    ] {
        let mut doc = PolicyDocument::from_yaml(MINIMAL).unwrap();
        doc.policy.description = Some(s.to_owned());
        let yaml = to_string(&doc).unwrap();
        assert!(yaml.contains(&format!("  description: {s}\n")), "{yaml}");
    }
}

#[test]
fn writer_handles_keys_longer_than_yaml_implicit_keys_allow() {
    // Not a valid document (advanced keys are at most 128 bytes), but the
    // writer must still produce YAML that reads back.
    let mut doc = PolicyDocument::from_yaml(MINIMAL).unwrap();
    let key = format!("k{}", "\u{e9}".repeat(1500));
    doc.policy
        .settings
        .advanced
        .insert(key.clone(), crate::model::AdvancedValue::Int(1));
    let yaml = to_string(&doc).unwrap();
    assert!(yaml.contains("? "), "{yaml}");
    assert_eq!(PolicyDocument::from_yaml(&yaml).unwrap(), doc);
}

#[test]
fn json_value_view_matches_serde_json() {
    let text = include_str!("../../tests/fixtures/valid/workstation-baseline.json");
    assert_eq!(
        to_json_value(text, &Limits::DEFAULT).unwrap(),
        serde_json::from_str::<serde_json::Value>(text).unwrap()
    );
    let v = to_json_value("a: [1, -2, 0.5, true, null, x]\n", &Limits::DEFAULT).unwrap();
    assert_eq!(v, serde_json::json!({"a": [1, -2, 0.5, true, null, "x"]}));
}

fn cases(default: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default);
    ProptestConfig::with_cases(cases)
}

proptest! {
    // The acceptance criterion in #190: random valid policy -> YAML -> parse -> equal.
    #![proptest_config(cases(10_000))]

    #[test]
    fn yaml_round_trip_is_lossless(doc in arbitrary::document()) {
        let yaml = to_string(&doc).unwrap();
        let back = PolicyDocument::from_yaml(&yaml);
        prop_assert!(back.is_ok(), "{}\n{}", back.unwrap_err(), yaml);
        let back = back.unwrap();
        prop_assert_eq!(&back, &doc);
        // Writing again gives the same bytes.
        prop_assert_eq!(to_string(&back).unwrap(), yaml.clone());
        // YAML and JSON describe the same document.
        let json = PolicyDocument::from_json(&doc.to_json_pretty().unwrap()).unwrap();
        prop_assert_eq!(&json, &back);
        prop_assert_eq!(
            to_json_value(&yaml, &Limits::DEFAULT).unwrap(),
            serde_json::to_value(&doc).unwrap()
        );
    }
}

proptest! {
    #![proptest_config(cases(512))]

    #[test]
    fn json_text_reads_the_same_as_yaml(doc in arbitrary::document()) {
        let json = doc.to_json_pretty().unwrap();
        prop_assert_eq!(PolicyDocument::from_yaml(&json).unwrap(), doc.clone());
        let compact = serde_json::to_string(&doc).unwrap();
        prop_assert_eq!(PolicyDocument::from_yaml(&compact).unwrap(), doc);
    }

    #[test]
    fn from_yaml_never_panics(text in "\\PC{0,200}") {
        let _ = from_str(&text);
    }

    #[test]
    fn from_yaml_never_panics_on_yaml_like_input(
        text in "([a-z]{0,3}|[-:,'\"&*!%|>#{}\\[\\]?<~ \\n\\t]){0,120}"
    ) {
        let _ = from_str(&text);
        let _ = to_json_value(&text, &Limits::DEFAULT);
    }

    #[test]
    fn mutated_documents_fail_with_a_location(doc in arbitrary::document(), cut in 0usize..4000) {
        let yaml = to_string(&doc).unwrap();
        // Truncating at a line start leaves well-formed YAML that usually
        // no longer matches the model; any error must still be located.
        let cut = yaml.char_indices().map(|(i, _)| i).filter(|i| *i == 0 || yaml.as_bytes()[i - 1] == b'\n').nth(cut % 40);
        if let Some(cut) = cut {
            if let Err(e) = from_str(&yaml[..cut]) {
                prop_assert!(e.location().is_some(), "{}", e);
            }
        }
    }
}

// Review round 2 (PR #237) regression tests.

/// A document with one rule, whose `action:` line is `action`.
fn with_action(action: &str) -> String {
    format!(
        "{MINIMAL}  rule_sets: [01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60]
rule_sets:
  - id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60
    name: Set
    kind: mixed
    rules:
      - id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61
        name: R
        match: {{criterion: {{field: path.extension, operator: equals, values: [ps1]}}}}
        action: {action}
"
    )
}

#[test]
fn structs_are_only_read_from_maps() {
    // A sequence would otherwise bind to fields by position.
    let e = err(&minimal_with(
        "  settings: [enforce, {}, enforce, enforce, true, 900, 300, [], device_local, 8, {}, false]\n",
    ));
    assert_eq!(e.kind(), YamlErrorKind::Mismatch);
    assert_eq!(e.pointer(), Some("/policy/settings"));
    assert_eq!(at(&e), (7, 13));
    assert!(e.message().contains("invalid type: sequence"), "{e}");
    let e =
        err("schema_version: 1.0.0\npolicy: [01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f, M, null, 1]\n");
    assert_eq!(e.pointer(), Some("/policy"));
    let e = err(&minimal_with("  metadata: [a, b]\n"));
    assert_eq!(e.pointer(), Some("/policy/metadata"));
    // A map field (`script_control_by_kind`) too.
    let e = err(&minimal_with(
        "  settings:\n    script_control_by_kind: [[powershell, audit]]\n",
    ));
    assert_eq!(e.pointer(), Some("/policy/settings/script_control_by_kind"));
    // The named form still loads.
    let doc =
        PolicyDocument::from_yaml(&minimal_with("  settings: {capture_command_line: true}\n"))
            .unwrap();
    assert!(doc.policy.settings.capture_command_line);
}

#[test]
fn actions_are_only_read_from_maps() {
    for action in ["[deny]", "[deny, extra]", "deny"] {
        let e = err(&with_action(action));
        assert_eq!(e.kind(), YamlErrorKind::Mismatch, "{action}: {e}");
        assert_eq!(e.pointer(), Some("/rule_sets/0/rules/0/action"), "{action}");
        assert_eq!(at(&e), (16, 17), "{action}");
    }
    assert!(from_str(&with_action("{type: deny}")).is_ok());
    let e = err(&with_action("{type: deny, kill_running: true}"));
    assert!(e.message().contains("unknown field"), "{e}");
    // The JSON reader uses the same type, so it agrees.
    let json = serde_json::json!({"type": "deny"});
    assert!(serde_json::from_value::<crate::model::Action>(json).is_ok());
    let json = serde_json::json!(["deny"]);
    assert!(serde_json::from_value::<crate::model::Action>(json).is_err());
}

#[test]
fn unit_enum_variants_are_only_read_as_names() {
    for mode in ["{audit: null}", "{audit: ~}", "{audit: 1}", "{audit: {}}"] {
        let e = err(&MINIMAL.replace("mode: audit", &format!("mode: {mode}")));
        assert_eq!(e.kind(), YamlErrorKind::Mismatch, "{mode}: {e}");
        assert_eq!(e.pointer(), Some("/policy/mode/audit"), "{mode}");
        assert!(e.message().contains("plain name `audit`"), "{e}");
    }
    // A variant with content is still a one-key map.
    assert!(from_str(&with_action("{type: deny}")).is_ok());
}

#[test]
fn source_map_cannot_drift_from_its_document() {
    let loaded = from_str(MINIMAL).unwrap();
    let doc = loaded.document().clone();
    assert_eq!(loaded.source_map().locate("/policy/name").line, 4);
    // Editing needs the document by value, which drops the source map.
    let mut owned = loaded.into_document();
    owned.policy.name = "Edited".to_owned();
    assert_ne!(owned, doc);
}

#[test]
fn warnings_on_a_valid_policy_have_locations() {
    let text = MINIMAL.replace("mode: audit", "mode: audit\n  precedence_model: allow_wins");
    let validated = from_str(&text).unwrap().validate().unwrap();
    assert_eq!(validated.warnings().len(), 1);
    let warning = &validated.warnings()[0];
    assert_eq!(warning.error.code, ErrorCode::AllowWinsNotRecommended);
    assert_eq!(warning.error.path, "/policy/precedence_model");
    assert_eq!(
        warning.location,
        Location {
            line: 7,
            column: 21
        }
    );
    // The same findings as the unlocated ones, in the same order.
    assert_eq!(
        validated.policy().warnings(),
        validated
            .warnings()
            .iter()
            .map(|w| w.error.clone())
            .collect::<Vec<_>>()
            .as_slice()
    );
    assert!(
        from_str(MINIMAL)
            .unwrap()
            .validate()
            .unwrap()
            .warnings()
            .is_empty()
    );
}

#[test]
fn stream_errors_are_reported_in_source_order() {
    // The first document has no `schema_version`; the second is broken
    // YAML. The first problem in the text wins.
    let e = from_str_all("a: 1\n---\na: [\n", &Limits::DEFAULT).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::MissingSchemaVersion, "{e}");
    assert_eq!(at(&e).0, 1);
    // A later error is still reported when every earlier document loads.
    let e = from_str_all(&format!("{MINIMAL}---\na: [\n"), &Limits::DEFAULT).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::Syntax, "{e}");
    assert_eq!(at(&e).0, 9);
    // And a strictness error in a later document.
    let e = from_str_all(&format!("{MINIMAL}---\na: &x 1\n"), &Limits::DEFAULT).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::UnsupportedFeature, "{e}");
    let e = from_str_all(&format!("a: 1\n---\n{MINIMAL}"), &Limits::DEFAULT).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::MissingSchemaVersion, "{e}");
}

#[test]
fn single_document_readers_stop_at_the_second_document() {
    // The second document is not read at all: its syntax error is not the
    // error reported.
    let e = err(&format!("{MINIMAL}---\na: [\n"));
    assert_eq!(e.kind(), YamlErrorKind::UnsupportedFeature, "{e}");
    assert_eq!(at(&e).0, 7);
    // A model error in the first document comes before the second `---`.
    let e = err(&format!("a: 1\n---\n{MINIMAL}"));
    assert_eq!(e.kind(), YamlErrorKind::MissingSchemaVersion, "{e}");
    assert_eq!(at(&e).0, 1);
}

#[test]
fn json_surrogate_pair_escapes_are_decoded() {
    let json = |name: &str| {
        format!(
            r#"{{"schema_version": "1.0.0", "policy": {{"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "{name}", "revision": 1, "mode": "audit"}}}}"#
        )
    };
    let literal = PolicyDocument::from_yaml(&json("Shield \u{1F6E1} \u{1D11E}")).unwrap();
    for escaped in [
        r"Shield \ud83d\udee1 \uD834\uDD1E",
        r"Shield \uD83D\uDEE1 \ud834\udd1e",
    ] {
        let text = json(escaped);
        assert_eq!(
            PolicyDocument::from_yaml(&text).unwrap(),
            literal,
            "{escaped}"
        );
        assert_eq!(
            PolicyDocument::from_json(&text).unwrap(),
            literal,
            "{escaped}"
        );
    }
    // Locations after the decoded string are unchanged.
    let text = json(r"\ud83d\udee1\ud83d\udee1\ud83d\udee1\nx")
        .replace(", \"mode\"", ",\n\"colour\": 1, \"mode\"");
    let e = err(&text);
    assert_eq!(e.pointer(), Some("/policy/colour"));
    let line2 = text.lines().nth(1).unwrap();
    assert_eq!(at(&e), (2, line2.find("\"colour\"").unwrap() + 1));
    // A lone or reversed surrogate is still an error, in both readers.
    for bad in [r"\ud83d", r"\udee1", r"\udee1\ud83d", r"\ud83dx"] {
        let text = json(bad);
        assert!(PolicyDocument::from_json(&text).is_err(), "{bad}");
        let e = err(&text);
        assert_eq!(e.kind(), YamlErrorKind::Syntax, "{bad}: {e}");
    }
    // An escaped backslash before `u` is not an escape.
    let text = json(r"C:\\ud83d\\udee1");
    let doc = PolicyDocument::from_yaml(&text).unwrap();
    assert_eq!(doc.policy.name, r"C:\ud83d\udee1");
    // YAML text is not rewritten.
    let e = err(&minimal_with("  description: \"\\ud83d\\udee1\"\n"));
    assert_eq!(e.kind(), YamlErrorKind::Syntax, "{e}");
    assert!(PolicyDocument::from_yaml(&minimal_with("  description: \"\\U0001F6E1\"\n")).is_ok());
}

#[test]
fn only_yaml_1_1_base_60_numbers_are_ambiguous() {
    for number in [
        "1:30",
        "190:20:30",
        "1:5",
        "-1:30",
        "+1:30",
        "1_0:00",
        "1:30.5",
        "0:30.5",
        "1:30.",
    ] {
        let e = err(&minimal_with(&format!("  description: {number}\n")));
        assert_eq!(e.kind(), YamlErrorKind::AmbiguousScalar, "{number}: {e}");
    }
    // Text in YAML 1.1 and 1.2: a part over 59, a three-digit part, a
    // leading zero on an integer, or a part that is not digits.
    for text in [
        "1:60",
        "1:99",
        "1:300",
        "0:30",
        "01:30",
        "1:3a",
        "1::30",
        "12:30.5.1",
    ] {
        let doc = PolicyDocument::from_yaml(&minimal_with(&format!("  description: {text}\n")))
            .unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(doc.policy.description.as_deref(), Some(text));
    }
}

#[test]
fn wide_flow_collections_are_bounded_by_the_lookahead_limit() {
    let limits = Limits {
        max_lookahead: 10_000,
        ..Limits::DEFAULT
    };
    // YAML flow collections (not JSON, so the YAML parser reads them) that
    // start a line are read whole before the first value is reported.
    let items = vec!["x"; 100_000].join(",");
    for wide in [
        format!("[{items}]"),
        format!("---\n[{items}]"),
        format!("- [{items}]"),
        format!("[[{items}]]"),
        format!(
            "{{{}}}",
            (0..20_000)
                .map(|i| format!("k{i}: 1"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ] {
        let e = to_json_value(&wide, &limits).unwrap_err();
        assert_eq!(e.kind(), YamlErrorKind::LimitExceeded, "{e}");
        assert!(e.message().contains("characters to find"), "{e}");
    }
    // After `key: `, the same collection streams within a small budget.
    assert!(to_json_value(&format!("a: [{items}]\n"), &limits).is_ok());
    // An input that ends exactly at the budget is not misreported.
    let exact = "a".repeat(9_999);
    assert!(to_json_value(&exact, &limits).is_ok());
}

#[test]
fn lookahead_limit_bounds_memory_before_the_node_limit() {
    // With the default limits, a 64 MB YAML flow sequence (32 million
    // items, 8 times the node limit) fails after reading at most
    // `max_lookahead` characters, rather than queueing every token first.
    let wide = format!("[{}]", vec!["x"; 32_000_000].join(","));
    let started = std::time::Instant::now();
    let e = to_json_value(&wide, &Limits::DEFAULT).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::LimitExceeded, "{e}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn json_input_is_streamed_with_the_same_rules() {
    // A large JSON document whose objects each start a line inside an
    // array: the YAML parser would read each one whole before reporting it.
    let big = serde_json::to_string(&serde_json::json!({
        "a": (0..300_000).map(|i| serde_json::json!({"k": i})).collect::<Vec<_>>()
    }))
    .unwrap();
    assert!(big.len() > Limits::DEFAULT.max_lookahead);
    let value = to_json_value(&big, &Limits::DEFAULT).unwrap();
    assert_eq!(
        value,
        serde_json::from_str::<serde_json::Value>(&big).unwrap()
    );
    // The node limit applies while streaming: 32 million items.
    let wide = format!("[{}]", vec!["1"; 32_000_000].join(","));
    let e = to_json_value(&wide, &Limits::DEFAULT).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::LimitExceeded, "{e}");
    assert!(e.message().contains("nodes"), "{e}");
    // So do the depth limit, duplicate keys and typing, with locations.
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    assert_eq!(err(&deep).kind(), YamlErrorKind::LimitExceeded);
    let e = to_json_value("{\n  \"a\": 1,\n  \"a\": 2\n}", &Limits::DEFAULT).unwrap_err();
    assert_eq!(e.kind(), YamlErrorKind::DuplicateKey);
    assert_eq!(at(&e), (3, 3));
    let e = to_json_value("[1, \"x\", 1.5e400]", &Limits::DEFAULT);
    assert!(e.is_err(), "out of range float");
    let v = to_json_value(
        "{\"a\":\t[true, null, -0.5, \"\\u00e9\"]}",
        &Limits::DEFAULT,
    )
    .unwrap();
    assert_eq!(v, serde_json::json!({"a": [true, null, -0.5, "\u{e9}"]}));
    // Text that is not valid JSON goes to the YAML parser as before.
    assert_eq!(
        to_json_value("[a, b]", &Limits::DEFAULT).unwrap(),
        serde_json::json!(["a", "b"])
    );
    // A JSON document loads as a policy, with locations from the JSON text.
    let text = include_str!("../../tests/fixtures/valid/workstation-baseline.json");
    assert!(from_str(text).unwrap().validate().is_ok());
    let e = err(&text.replacen("\"revision\": 42", "\"revision\": 42, \"colour\": 1", 1));
    assert_eq!(e.pointer(), Some("/policy/colour"));
    let line = text
        .lines()
        .position(|l| l.contains("\"revision\": 42"))
        .unwrap()
        + 1;
    assert_eq!(at(&e).0, line);
}

/// The tree `parse` builds, with the JSON reader or the YAML parser.
fn tree(input: &str, json_fast_path: bool) -> Result<Vec<parse::Node>, YamlError> {
    let mut roots = Vec::new();
    parse::parse_with(input, &Limits::DEFAULT, false, json_fast_path, |root| {
        roots.push(root);
        Ok(())
    })?;
    Ok(roots)
}

proptest! {
    #![proptest_config(cases(512))]

    // The JSON reader is an optimisation: on JSON the YAML parser can read,
    // both build the same tree, with the same locations.
    #[test]
    fn json_reader_and_yaml_parser_agree(doc in arbitrary::document()) {
        for text in [doc.to_json_pretty().unwrap(), serde_json::to_string(&doc).unwrap()] {
            prop_assert!(parse::is_json(&text));
            prop_assert_eq!(tree(&text, true).unwrap(), tree(&text, false).unwrap());
        }
    }

    #[test]
    fn json_reader_and_yaml_parser_agree_on_any_json(value in json_value()) {
        let text = serde_json::to_string_pretty(&value).unwrap();
        let json = tree(&text, true);
        let yaml = tree(&text, false);
        match (&json, &yaml) {
            (Ok(a), Ok(b)) => prop_assert_eq!(a, b),
            // Both reject (for example a key the typing rules refuse), at
            // the same place.
            (Err(a), Err(b)) => {
                prop_assert_eq!(a.kind(), b.kind());
                prop_assert_eq!(a.location(), b.location());
            }
            _ => prop_assert!(false, "{:?} vs {:?}\n{}", json, yaml, text),
        }
    }
}

/// Small JSON values with keys and strings that exercise typing and escapes.
fn json_value() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::from),
        any::<i64>().prop_map(serde_json::Value::from),
        (-1e6f64..1e6).prop_map(serde_json::Value::from),
        "[a-z0-9 .:\\-\"\\\\\u{e9}\u{1F6E1}]{0,12}".prop_map(serde_json::Value::from),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::from),
            proptest::collection::btree_map("[a-z][a-z0-9_.]{0,8}", inner, 0..6)
                .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}
