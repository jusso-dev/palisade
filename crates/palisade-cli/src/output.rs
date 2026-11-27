//! Rendering records as JSON, YAML or a human-readable table.

use std::fmt::Write as _;

use serde_json::Value;

/// How to print a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One line per attribute (the default).
    Table,
    /// JSON: pretty for one record, one compact object per line for many.
    Json,
    /// YAML, one document per record.
    Yaml,
}

/// Renders one record. `many` is set when it is one of several (a
/// directory), which makes JSON one object per line.
///
/// Every format is terminal-safe: no control or bidirectional formatting
/// character from a file reaches the output raw. JSON and YAML write them
/// as `\uXXXX` escapes (which parse back to the same string), the table as
/// `\u{...}`.
pub fn render(value: &Value, format: Format, many: bool) -> String {
    match format {
        Format::Json if many => format!("{}\n", json_safe(&value.to_string())),
        Format::Json => {
            let mut s = json_safe(&serde_json::to_string_pretty(value).unwrap_or_default());
            s.push('\n');
            s
        }
        Format::Yaml => {
            let mut out = String::from("---\n");
            yaml_node(value, 0, &mut out);
            out
        }
        Format::Table => {
            let mut out = String::new();
            flatten(value, "", &mut out);
            if many {
                out.push('\n');
            }
            out
        }
    }
}

/// Whether `c` must never reach a terminal raw.
fn unsafe_char(c: char) -> bool {
    // Controls (Cc), and the format characters (Cf), line and paragraph
    // separators (Zl, Zp) that change how text looks without being seen:
    // bidi controls, zero-width characters, the soft hyphen, the byte
    // order mark, invisible operators and tag characters.
    c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

/// JSON text with every unsafe character outside the ASCII escapes
/// `serde_json` already writes (DEL, C1 controls, bidi controls) written as
/// a `\uXXXX` escape. Such characters only occur inside strings, where
/// the escape means the same character.
fn json_safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        // `\n` and the indentation of pretty output are structure, not data.
        if unsafe_char(c) && c != '\n' {
            let mut buf = [0_u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A scalar in YAML: strings double-quoted with JSON escapes (a JSON string
/// is a valid YAML double-quoted scalar, so every unsafe character is an
/// escape), everything else as JSON writes it.
fn yaml_scalar(value: &Value) -> String {
    match value {
        Value::String(s) => json_safe(&Value::String(s.clone()).to_string()),
        Value::Array(a) if a.is_empty() => "[]".to_owned(),
        Value::Object(o) if o.is_empty() => "{}".to_owned(),
        other => other.to_string(),
    }
}

fn is_block(value: &Value) -> bool {
    match value {
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => false,
    }
}

/// Writes `value` as a block node indented by `indent` spaces. A block
/// collection starts on the next line; the caller has written its key or
/// dash.
fn yaml_node(value: &Value, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(o) if !o.is_empty() => {
            for (k, v) in o {
                let key = yaml_scalar(&Value::String(k.clone()));
                if is_block(v) {
                    let _ = writeln!(out, "{pad}{key}:");
                    yaml_node(v, indent + 2, out);
                } else {
                    let _ = writeln!(out, "{pad}{key}: {}", yaml_scalar(v));
                }
            }
        }
        Value::Array(a) if !a.is_empty() => {
            for v in a {
                if is_block(v) {
                    let _ = writeln!(out, "{pad}-");
                    yaml_node(v, indent + 2, out);
                } else {
                    let _ = writeln!(out, "{pad}- {}", yaml_scalar(v));
                }
            }
        }
        other => {
            let _ = writeln!(out, "{pad}{}", yaml_scalar(other));
        }
    }
}

/// A field wrapper (`{"status": ..., "value": ...}`) as its value, or as a
/// short note for the statuses without one. `None` when it is not a
/// wrapper.
fn unwrap_field(value: &Value) -> Option<Result<&Value, String>> {
    let o = value.as_object()?;
    let status = o.get("status")?.as_str()?;
    if o.len() > 2 || o.keys().any(|k| k != "status" && k != "value") {
        return None;
    }
    let inner = o.get("value");
    Some(match status {
        "computed" => Ok(inner.unwrap_or(&Value::Null)),
        "not_requested" => Err("(not requested)".to_owned()),
        "not_applicable" => Err("(not applicable)".to_owned()),
        "not_yet_supported" => {
            let issues: Vec<String> = inner
                .and_then(|v| v.get("issues"))
                .and_then(Value::as_array)
                .map(|a| a.iter().map(|i| format!("#{i}")).collect())
                .unwrap_or_default();
            Err(format!("(not yet supported: {})", issues.join(", ")))
        }
        "unavailable" => Err(format!(
            "(unavailable: {})",
            escape(inner.and_then(Value::as_str).unwrap_or("unknown"))
        )),
        other => Err(format!("({other})")),
    })
}

/// Writes `value` as `key: value` lines, one per leaf.
fn flatten(value: &Value, prefix: &str, out: &mut String) {
    let value = match unwrap_field(value) {
        Some(Ok(v)) => v,
        Some(Err(note)) => {
            let _ = writeln!(out, "{prefix}: {note}");
            return;
        }
        None => value,
    };
    let join = |k: &str| {
        if prefix.is_empty() {
            k.to_owned()
        } else {
            format!("{prefix}.{k}")
        }
    };
    match value {
        Value::Null => {}
        Value::Object(o) => {
            for (k, v) in o {
                flatten(v, &join(k), out);
            }
        }
        Value::Array(a) if a.is_empty() => {}
        Value::Array(a) if a.iter().all(|v| !v.is_object() && !v.is_array()) => {
            let items: Vec<String> = a.iter().map(scalar).collect();
            let _ = writeln!(out, "{prefix}: {}", items.join(", "));
        }
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                flatten(v, &format!("{prefix}[{i}]"), out);
            }
        }
        _ => {
            let _ = writeln!(out, "{prefix}: {}", scalar(value));
        }
    }
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(s) => escape(s),
        other => other.to_string(),
    }
}

/// `s` with control and bidirectional formatting characters written as
/// `\u{...}`, so a crafted name cannot rewrite the terminal or reorder
/// what is shown.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if unsafe_char(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invisible_characters_are_escaped() {
        for c in [
            '\u{00ad}',
            '\u{200b}',
            '\u{200d}',
            '\u{2028}',
            '\u{2029}',
            '\u{2060}',
            '\u{feff}',
            '\u{e0041}',
            '\u{202e}',
            '\u{1b}',
            '\u{9b}',
        ] {
            let text = format!("a{c}b");
            assert!(!escape(&text).contains(c), "{:x}", u32::from(c));
        }
        assert_eq!(escape("plain café.exe"), "plain café.exe");
    }

    #[test]
    fn table_unwraps_fields() {
        let v = serde_json::json!({
            "size": {"status": "computed", "value": 12},
            "kind": {"status": "not_yet_supported", "value": {"issues": [44]}},
            "pe": {"status": "not_requested"},
            "hashes": {"status": "unavailable", "value": "too large"},
            "name": {"file_name": "a\u{202e}b.exe", "extension": "exe"},
            "list": ["x", "y"],
            "nested": [{"a": 1}],
            "none": null
        });
        // Keys come out sorted (serde_json's map order).
        let t = render(&v, Format::Table, false);
        assert_eq!(
            t,
            "hashes: (unavailable: too large)\n\
             kind: (not yet supported: #44)\n\
             list: x, y\n\
             name.extension: exe\n\
             name.file_name: a\\u{202e}b.exe\n\
             nested[0].a: 1\n\
             pe: (not requested)\n\
             size: 12\n"
        );
    }

    #[test]
    fn json_lines_for_many() {
        let v = serde_json::json!({"a": 1});
        assert_eq!(render(&v, Format::Json, true), "{\"a\":1}\n");
        assert!(render(&v, Format::Json, false).contains("\n  \"a\": 1\n"));
    }

    /// Hostile text: terminal escapes, C1 CSI, DEL, a bidi override, and
    /// YAML and JSON syntax.
    const HOSTILE: &str = "a\u{1b}[31m\u{9b}2J\u{7f}\u{202e}b: [c] # \"d\" \\ - e\n";

    fn assert_terminal_safe(text: &str) {
        assert!(
            !text.chars().any(|c| unsafe_char(c) && c != '\n'),
            "raw unsafe character in {text:?}"
        );
    }

    #[test]
    fn yaml_round_trips_and_is_terminal_safe() {
        let v = serde_json::json!({
            "a": [1, "b", [], {}],
            "c": {"d": true, "e": null, "f": 1.5, "g": [{"h": "i"}]},
            "hostile": HOSTILE,
            "true": "null",
            "": "",
        });
        let y = render(&v, Format::Yaml, false);
        assert!(y.starts_with("---\n"), "{y}");
        assert_terminal_safe(&y);
        let docs = yaml_rust2::YamlLoader::load_from_str(&y).unwrap();
        let d = &docs[0];
        assert_eq!(d["hostile"].as_str(), Some(HOSTILE));
        assert_eq!(d["true"].as_str(), Some("null"));
        assert_eq!(d[""].as_str(), Some(""));
        assert_eq!(d["a"][0].as_i64(), Some(1));
        assert!(d["a"][2].as_vec().is_some_and(Vec::is_empty));
        assert_eq!(d["c"]["d"].as_bool(), Some(true));
        assert!(d["c"]["e"].is_null());
        assert_eq!(d["c"]["g"][0]["h"].as_str(), Some("i"));
    }

    #[test]
    fn json_is_terminal_safe_and_round_trips() {
        let v = serde_json::json!({"hostile": HOSTILE, "list": [HOSTILE]});
        for many in [false, true] {
            let j = render(&v, Format::Json, many);
            assert_terminal_safe(&j);
            let back: Value = serde_json::from_str(&j).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn table_is_terminal_safe() {
        let v = serde_json::json!({
            "hostile": HOSTILE,
            "f": {"status": "unavailable", "value": HOSTILE},
        });
        assert_terminal_safe(&render(&v, Format::Table, false));
    }
}
