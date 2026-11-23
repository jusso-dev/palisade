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
        (format!("a: 1\n...\n%YAML 1.1\n---\n{MINIMAL}"), 3),
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
        "010", "+1", "0x1f", "0o17", "0b11", "1_000", "1:30", ".5", "1.", "-.inf", ".NaN",
    ] {
        let e = err(&minimal_with(&format!("  description: {number}\n")));
        assert!(
            matches!(
                e.kind(),
                YamlErrorKind::AmbiguousScalar | YamlErrorKind::Mismatch
            ),
            "{number}: {e}"
        );
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
        .spawn(move || from_str(&text).map(|d| d.document.rule_sets[0].rules[0].match_.depth()))
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
    assert_eq!(at(&e).0, 8);
    let all = from_str_all(&two, &Limits::DEFAULT).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].document, all[1].document);
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
    let source_map = from_str(&yaml).unwrap().source_map;
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
    let map = from_str(MINIMAL).unwrap().source_map;
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
