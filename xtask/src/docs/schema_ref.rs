//! Reference pages generated from a committed JSON Schema: one page per
//! object type (`$defs` entry with properties), plus one page for the
//! value types (enumerations, string formats and other definitions).
//!
//! Each field row gives the name, the type, the default, the constraints,
//! whether it is required, and the schema version that added it. The
//! version comes from a `since` function, so the event schema's `ADDED`
//! table (in `palisade-proto`) drives it without this crate linking that
//! one: the pages are checked against `x-schema-version`, and fields the
//! function does not know default to the first version.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::markdown::{cell, code, prose};

/// One generated page: its file name (relative to the reference
/// directory) and Markdown content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub file: String,
    pub title: String,
    pub content: String,
}

/// The schema version that added the property at a JSON Pointer of the
/// root document (`/file/hashes`), or `None` for "the first".
pub type Since<'a> = &'a dyn Fn(&str) -> Option<String>;

/// What to call a schema and where its pages go.
pub struct Spec<'a> {
    /// Short directory name, for example `policy`.
    pub dir: &'a str,
    /// Heading used on the index page, for example `Policy reference`.
    pub title: &'a str,
    /// The repository path of the committed schema.
    pub source: &'a str,
    /// The command that regenerates the schema itself.
    pub regenerate: &'a str,
    /// The schema version that added the property at a JSON Pointer of
    /// the root document (`/file/hashes`), or `None` for "the first". A
    /// schema without such a table (`None` here) must still be at its
    /// first version (`x.0.0`), so the column cannot silently be wrong.
    pub since: Option<Since<'a>>,
}

/// A definition name to the file name of its page.
fn page_file(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('-');
        }
        out.push(c.to_ascii_lowercase());
    }
    out + ".md"
}

fn defs(schema: &Value) -> Result<&Map<String, Value>, String> {
    schema
        .get("$defs")
        .and_then(Value::as_object)
        .ok_or_else(|| "the schema has no `$defs`".to_owned())
}

fn ref_name(value: &Value) -> Option<&str> {
    value
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| r.strip_prefix("#/$defs/"))
}

/// `true` for a definition that gets its own page: an object with
/// properties.
fn is_object_def(def: &Value) -> bool {
    def.get("properties").and_then(Value::as_object).is_some()
}

/// How the type of `node` reads in a table, with links to other pages.
/// `here` is the directory the link is written from: `""` for a page in the
/// same directory.
fn type_of(node: &Value, defs: &Map<String, Value>) -> String {
    if let Some(name) = ref_name(node) {
        return link_to(name, defs);
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(options) = node.get(key).and_then(Value::as_array) {
            // Options that only add constraints (`{"format": "ipv4"}`) say
            // nothing about the type: the node's own `type` does.
            if options.iter().all(|o| !says_type(o)) {
                continue;
            }
            // `T or null` reads as an optional `T`.
            let parts: Vec<String> = options
                .iter()
                .filter(|o| o.get("type").and_then(Value::as_str) != Some("null"))
                .map(|o| type_of(o, defs))
                .collect();
            if options.iter().all(|o| o.get("const").is_some()) {
                return "enum".to_owned();
            }
            if !parts.is_empty() {
                let mut parts = parts;
                parts.dedup();
                return parts.join(" or ");
            }
        }
    }
    if node.get("const").is_some() {
        return "constant".to_owned();
    }
    if node.get("enum").is_some() {
        return "enum".to_owned();
    }
    let types: Vec<&str> = match node.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(ts)) => ts
            .iter()
            .filter_map(Value::as_str)
            .filter(|t| *t != "null")
            .collect(),
        _ => Vec::new(),
    };
    let named: Vec<String> = types
        .iter()
        .map(|t| match *t {
            "array" => match node.get("items") {
                Some(items) => format!("array of {}", type_of(items, defs)),
                None => "array".to_owned(),
            },
            "object" => match node.get("additionalProperties") {
                Some(v @ Value::Object(_)) => format!("map of {}", type_of(v, defs)),
                _ => match node.get("properties").and_then(Value::as_object) {
                    Some(_) => "object".to_owned(),
                    None => "map".to_owned(),
                },
            },
            other => other.to_owned(),
        })
        .collect();
    if named.is_empty() {
        "any".to_owned()
    } else {
        named.join(" or ")
    }
}

/// `true` if a subschema names a type: `type`, `$ref`, `const`, `enum`,
/// or a union of those.
fn says_type(node: &Value) -> bool {
    ["type", "$ref", "const", "enum"]
        .iter()
        .any(|k| node.get(k).is_some())
        || ["anyOf", "oneOf"].iter().any(|k| {
            node.get(k)
                .and_then(Value::as_array)
                .is_some_and(|o| o.iter().any(says_type))
        })
}

/// A definition that is only a cross-field rule (`ChangeRule`: which keys
/// each `op` requires), not a type of its own. The schema applies it with
/// `allOf` on the object it constrains.
fn is_rule_def(def: &Value) -> bool {
    !says_type(def) && def.get("properties").is_none()
}

fn link_to(name: &str, defs: &Map<String, Value>) -> String {
    let target = defs.get(name);
    if target.is_some_and(|d| is_object_def(d) || has_object_variants(d)) {
        format!("[`{name}`]({})", page_file(name))
    } else {
        format!("[`{name}`](types.md#{})", name.to_ascii_lowercase())
    }
}

/// The constraints of `node`, in words.
fn constraints(node: &Value) -> String {
    let mut out = Vec::new();
    let num = |k: &str| node.get(k).map(Value::to_string);
    if let Some(v) = node.get("const") {
        out.push(format!("always `{v}`"));
    }
    if let Some(Value::Array(values)) = node.get("enum") {
        let list: Vec<String> = values.iter().map(|v| format!("`{}`", unquote(v))).collect();
        out.push(format!("one of {}", list.join(", ")));
    }
    match (num("minimum"), num("maximum")) {
        (Some(a), Some(b)) => out.push(format!("{a} to {b}")),
        (Some(a), None) => out.push(format!("at least {a}")),
        (None, Some(b)) => out.push(format!("at most {b}")),
        (None, None) => {}
    }
    for (key, words) in [
        ("exclusiveMinimum", "greater than"),
        ("exclusiveMaximum", "less than"),
    ] {
        if let Some(v) = num(key) {
            out.push(format!("{words} {v}"));
        }
    }
    let lengths = [
        ("minLength", "maxLength", "characters"),
        ("minItems", "maxItems", "items"),
        ("minProperties", "maxProperties", "entries"),
    ];
    for (lo, hi, unit) in lengths {
        match (num(lo), num(hi)) {
            (Some(a), Some(b)) if a == b => out.push(format!("exactly {a} {unit}")),
            (Some(a), Some(b)) => out.push(format!("{a} to {b} {unit}")),
            (Some(a), None) => out.push(format!("at least {a} {unit}")),
            (None, Some(b)) => out.push(format!("at most {b} {unit}")),
            (None, None) => {}
        }
    }
    if node.get("uniqueItems") == Some(&Value::Bool(true)) {
        out.push("no duplicates".to_owned());
    }
    if let Some(Value::String(format)) = node.get("format") {
        out.push(format!("format `{format}`"));
    }
    for key in ["anyOf", "oneOf"] {
        let Some(options) = node.get(key).and_then(Value::as_array) else {
            continue;
        };
        let formats: Vec<String> = options
            .iter()
            .filter(|o| !says_type(o))
            .filter_map(|o| o.get("format").and_then(Value::as_str))
            .map(|f| format!("`{f}`"))
            .collect();
        if !formats.is_empty() && formats.len() == options.len() {
            out.push(format!("format {}", formats.join(" or ")));
        }
    }
    if let Some(Value::String(pattern)) = node.get("pattern") {
        out.push(format!("matches {}", code(pattern)));
    }
    if let Some(names) = node.get("propertyNames") {
        let inner = constraints(names);
        if !inner.is_empty() {
            out.push(format!("keys: {inner}"));
        }
    }
    out.join("; ")
}

fn unquote(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn description(node: &Value) -> String {
    prose(&strip_intra_doc_links(
        node.get("description")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ))
}

/// Schema descriptions come from Rust doc comments, where ``[`Name`]`` is a
/// rustdoc link. Outside rustdoc it would show its brackets, so keep only
/// the code span. Only a whole code span directly inside `[` and `]` is
/// such a link, and not when a `(` or `[` follows (a real Markdown link).
/// Code spans are found per line, as Markdown finds them.
fn strip_intra_doc_links(text: &str) -> String {
    let lines: Vec<String> = text
        .split('\n')
        .map(|line| {
            let bytes = line.as_bytes();
            let mut drop = Vec::new();
            for (start, end) in super::markdown::code_spans(line) {
                let opened = start > 0 && bytes[start - 1] == b'[';
                let closed = bytes.get(end) == Some(&b']');
                let followed = matches!(bytes.get(end + 1), Some(b'(' | b'['));
                if opened && closed && !followed {
                    drop.push(start - 1);
                    drop.push(end);
                }
            }
            line.char_indices()
                .filter(|(i, _)| !drop.contains(i))
                .map(|(_, c)| c)
                .collect()
        })
        .collect();
    lines.join("\n")
}

/// Every pointer at which each object definition appears, from the root:
/// `Hashes` -> [`/file/hashes`, `/process/hashes`, ...]. Arrays are
/// transparent, as in the event schema's `ADDED` table.
fn def_pointers(schema: &Value, defs: &Map<String, Value>) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    walk(schema, defs, "", &mut out, 0);
    out
}

fn walk(
    node: &Value,
    defs: &Map<String, Value>,
    at: &str,
    out: &mut BTreeMap<String, Vec<String>>,
    depth: usize,
) {
    if depth > 16 {
        return;
    }
    let mut node = node;
    let mut guard = 0;
    while let Some(name) = ref_name(node) {
        let entry = out.entry(name.to_owned()).or_default();
        if entry.iter().any(|p| p == at) || guard > 8 {
            return;
        }
        entry.push(at.to_owned());
        match defs.get(name) {
            Some(def) => node = def,
            None => return,
        }
        guard += 1;
    }
    for key in ["anyOf", "oneOf", "allOf"] {
        if let Some(options) = node.get(key).and_then(Value::as_array) {
            for o in options {
                walk(o, defs, at, out, depth + 1);
            }
        }
    }
    if let Some(items) = node.get("items") {
        walk(items, defs, at, out, depth + 1);
    }
    if let Some(Value::Object(props)) = node.get("properties") {
        for (key, child) in props {
            walk(child, defs, &format!("{at}/{key}"), out, depth + 1);
        }
    }
}

/// The version that added a field: the oldest version over every pointer
/// it appears at, so a field shared by an old and a new parent shows when it
/// first appeared anywhere (the oldest).
fn field_since(pointers: &[String], field: &str, spec: &Spec<'_>, first: &str) -> String {
    let mut versions: Vec<String> = pointers
        .iter()
        .map(|p| {
            spec.since
                .and_then(|since| since(&format!("{p}/{field}")))
                .unwrap_or_else(|| first.to_owned())
        })
        .collect();
    versions.sort_by(|a, b| compare_versions(a, b));
    versions
        .into_iter()
        .next()
        .unwrap_or_else(|| first.to_owned())
}

fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parse(a).cmp(&parse(b))
}

/// The fields table of an object node.
fn fields_table(
    node: &Value,
    defs: &Map<String, Value>,
    pointers: &[String],
    spec: &Spec<'_>,
    first: &str,
) -> String {
    let Some(Value::Object(props)) = node.get("properties") else {
        return String::new();
    };
    let required: Vec<&str> = node
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut out = String::from(
        "| Field | Type | Required | Default | Constraints | Since | Description |\n|---|---|---|---|---|---|---|\n",
    );
    for (name, prop) in props {
        let default = prop
            .get("default")
            .map_or_else(String::new, |d| format!("`{d}`"));
        let required = if required.contains(&name.as_str()) {
            "yes"
        } else {
            "no"
        };
        let since = field_since(pointers, name, spec, first);
        out.push_str(&format!(
            "| `{name}` | {} | {required} | {} | {} | {since} | {} |\n",
            cell(&type_of(prop, defs)),
            cell(&default),
            cell(&constraints(prop)),
            cell(&description(prop)),
        ));
    }
    out
}

/// The variants of a `oneOf` of objects (tagged actions, match nodes,
/// conditional rules) as sub-sections.
fn variants(
    node: &Value,
    defs: &Map<String, Value>,
    pointers: &[String],
    spec: &Spec<'_>,
    first: &str,
) -> String {
    let Some(options) = node.get("oneOf").and_then(Value::as_array) else {
        return String::new();
    };
    let mut out = String::new();
    for option in options {
        let Some(Value::Object(props)) = option.get("properties") else {
            continue;
        };
        // The tag is the property with a `const`, or the only required key.
        let tag = props
            .iter()
            .find_map(|(k, v)| v.get("const").map(|c| format!("{k}: {}", unquote(c))))
            .or_else(|| {
                option
                    .get("required")
                    .and_then(Value::as_array)
                    .and_then(|r| r.first())
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "variant".to_owned());
        out.push_str(&format!("### `{tag}`\n\n"));
        let text = description(option);
        if !text.is_empty() {
            out.push_str(&text);
            out.push_str("\n\n");
        }
        out.push_str(&fields_table(option, defs, pointers, spec, first));
        out.push('\n');
    }
    out
}

fn values_list(def: &Value) -> Option<String> {
    if let Some(options) = def.get("oneOf").and_then(Value::as_array)
        && options.iter().all(|o| o.get("const").is_some())
    {
        let mut out = String::from("| Value | Meaning |\n|---|---|\n");
        for o in options {
            out.push_str(&format!(
                "| `{}` | {} |\n",
                cell(&unquote(&o["const"])),
                cell(&description(o))
            ));
        }
        return Some(out);
    }
    if let Some(Value::Array(values)) = def.get("enum") {
        let list: Vec<String> = values.iter().map(|v| format!("`{}`", unquote(v))).collect();
        return Some(format!("Values: {}.\n", list.join(", ")));
    }
    None
}

fn generated_note(spec: &Spec<'_>) -> String {
    format!(
        "<!-- Generated by `cargo xtask docs generate` from `{}`. Do not edit by hand. -->\n\n",
        spec.source
    )
}

/// Generates every page of one schema.
pub fn pages(schema: &Value, spec: &Spec<'_>) -> Result<Vec<Page>, String> {
    let defs = defs(schema)?;
    let version = schema
        .get("x-schema-version")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{}: no `x-schema-version`", spec.source))?;
    let first = format!("{}.0.0", version.split('.').next().unwrap_or("1"));
    if spec.since.is_none() && version != first {
        return Err(format!(
            "{}: version {version} is past {first}, so the reference needs to know which version added each field; give it a `since` table (as the event schema's `ADDED`)",
            spec.source
        ));
    }
    let pointers = def_pointers(schema, defs);
    let note = generated_note(spec);
    let mut pages = Vec::new();

    // The document root.
    let root_title = schema
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or(spec.title);
    let mut root = format!(
        "# {root_title}\n\n{note}{}\n\nSchema: [`{}`](https://github.com/jusso-dev/palisade/blob/main/{}) (`$id` `{}`), version {version}. Regenerate the schema with `{}`, then these pages with `cargo xtask docs generate`.\n\n## Fields\n\n",
        description(schema),
        spec.source,
        spec.source,
        schema.get("$id").and_then(Value::as_str).unwrap_or(""),
        spec.regenerate,
    );
    root.push_str(&fields_table(schema, defs, &[String::new()], spec, &first));
    if let Some(rules) = schema.get("allOf").and_then(Value::as_array) {
        root.push_str(&format!(
            "\nThe schema also has {} cross-field rules (`allOf`), for example which field sets each event type requires and which fields an older `schema_version` may not use.\n",
            rules.len()
        ));
    }
    root.push_str("\n## Object types\n\n");
    for (name, def) in defs {
        if is_object_def(def) || has_object_variants(def) {
            root.push_str(&format!(
                "- {}: {}\n",
                link_to_page(name),
                first_sentence(def)
            ));
        }
    }
    root.push_str("\nEnumerations and string formats: [Value types](types.md).\n");
    pages.push(Page {
        file: "index.md".to_owned(),
        title: root_title.to_owned(),
        content: root,
    });

    // One page per object type, and per tagged union of objects.
    for (name, def) in defs {
        if !(is_object_def(def) || has_object_variants(def)) {
            continue;
        }
        let at = pointers.get(name).cloned().unwrap_or_default();
        let mut content = format!("# {name}\n\n{note}{}\n\n", description(def));
        if !at.is_empty() {
            let shown: Vec<String> = at
                .iter()
                .take(6)
                .map(|p| {
                    if p.is_empty() {
                        "`/`".to_owned()
                    } else {
                        format!("`{p}`")
                    }
                })
                .collect();
            content.push_str(&format!(
                "Appears at: {}{}.\n\n",
                shown.join(", "),
                if at.len() > 6 { ", and more" } else { "" }
            ));
        }
        if is_object_def(def) {
            content.push_str("## Fields\n\n");
            content.push_str(&fields_table(def, defs, &at, spec, &first));
        } else {
            content.push_str("## Variants\n\n");
            content.push_str(&variants(def, defs, &at, spec, &first));
        }
        if def.get("additionalProperties") == Some(&Value::Bool(false)) {
            content.push_str("\nUnknown fields are rejected.\n");
        }
        pages.push(Page {
            file: page_file(name),
            title: name.clone(),
            content,
        });
    }

    // Everything else on one page.
    let mut types = format!(
        "# Value types\n\n{note}Enumerations, identifiers and string formats used by the [{}](index.md).\n\n",
        root_title
    );
    for (name, def) in defs {
        if is_object_def(def) || has_object_variants(def) || is_rule_def(def) {
            continue;
        }
        types.push_str(&format!("## {name}\n\n"));
        let text = description(def);
        if !text.is_empty() {
            types.push_str(&text);
            types.push_str("\n\n");
        }
        match values_list(def) {
            Some(list) => types.push_str(&list),
            None => {
                let kind = type_of(def, defs);
                let rules = constraints(def);
                types.push_str(&format!(
                    "Type: {}{}.\n",
                    cell(&kind),
                    if rules.is_empty() {
                        String::new()
                    } else {
                        format!("; {}", cell(&rules))
                    }
                ));
            }
        }
        types.push('\n');
    }
    let rules: Vec<(&String, &Value)> = defs.iter().filter(|(_, d)| is_rule_def(d)).collect();
    if !rules.is_empty() {
        types.push_str(
            "## Cross-field rules\n\nConstraints the schema applies to the objects that use them, beyond their field tables.\n\n| Rule | Applies to | Rule |\n|---|---|---|\n",
        );
        for (name, def) in rules {
            let at: Vec<String> = pointers
                .get(name.as_str())
                .map(|ps| ps.iter().map(|p| format!("`{p}`")).collect())
                .unwrap_or_default();
            types.push_str(&format!(
                "| `{name}` | {} | {} |\n",
                cell(&at.join(", ")),
                cell(&description(def))
            ));
        }
    }
    pages.push(Page {
        file: "types.md".to_owned(),
        title: "Value types".to_owned(),
        content: types,
    });
    Ok(pages)
}

fn link_to_page(name: &str) -> String {
    format!("[`{name}`]({})", page_file(name))
}

/// A `oneOf` whose options are objects with properties (a tagged union).
fn has_object_variants(def: &Value) -> bool {
    def.get("oneOf").and_then(Value::as_array).is_some_and(|o| {
        o.iter().any(|v| {
            v.get("properties").is_some() && v.get("type").and_then(Value::as_str) == Some("object")
        })
    })
}

fn first_sentence(def: &Value) -> String {
    let text = description(def);
    let first = text.split("\n\n").next().unwrap_or("").replace('\n', " ");
    cell(&first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(since: Option<Since<'_>>) -> Spec<'_> {
        Spec {
            dir: "t",
            title: "T reference",
            source: "schemas/t/v1.json",
            regenerate: "regen",
            since,
        }
    }

    fn sample() -> Value {
        json!({
            "$id": "https://example.invalid/t.json",
            "title": "T document",
            "description": "A document.",
            "x-schema-version": "1.2.0",
            "required": ["thing"],
            "properties": {
                "thing": { "$ref": "#/$defs/Thing", "description": "The thing." },
                "count": { "type": ["integer", "null"], "minimum": 0, "maximum": 9, "default": 3, "description": "How many | which" }
            },
            "$defs": {
                "Thing": {
                    "description": "A thing <x>.\n\nMore.",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["kind"],
                    "properties": {
                        "kind": { "$ref": "#/$defs/Kind" },
                        "tags": { "type": "array", "items": { "type": "string", "maxLength": 8 }, "maxItems": 4 },
                        "new_field": { "type": "string", "pattern": "^a`b$" },
                        "act": { "$ref": "#/$defs/Action" },
                        "rule": { "type": "object", "allOf": [{ "$ref": "#/$defs/OpRule" }] }
                    }
                },
                "Kind": { "oneOf": [
                    { "const": "a", "description": "First." },
                    { "const": "b", "description": "Second <kind>." }
                ]},
                "Action": { "oneOf": [
                    { "type": "object", "properties": { "type": { "const": "go" }, "fast": { "type": "boolean" } }, "required": ["type"] }
                ]},
                "Id": { "type": "string", "pattern": "^[0-9]+$" },
                "Ip": { "type": "string", "anyOf": [{ "format": "ipv4" }, { "format": "ipv6" }] },
                "OpRule": {
                    "description": "`add` has `new` only.",
                    "oneOf": [{ "properties": { "op": { "const": "add" } }, "required": ["new"] }]
                }
            }
        })
    }

    #[test]
    fn pages_cover_every_definition() {
        let since = |p: &str| (p == "/thing/new_field").then(|| "1.2.0".to_owned());
        let pages = pages(&sample(), &spec(Some(&since))).unwrap();
        let files: Vec<&str> = pages.iter().map(|p| p.file.as_str()).collect();
        assert_eq!(files, ["index.md", "action.md", "thing.md", "types.md"]);
        let root = &pages[0].content;
        assert!(root.starts_with("# T document\n"));
        assert!(
            root.contains("| `thing` | [`Thing`](thing.md) | yes |  |  | 1.0.0 | The thing. |")
        );
        assert!(
            root.contains("| `count` | integer | no | `3` | 0 to 9 | 1.0.0 | How many \\| which |")
        );
        let thing = &pages[2].content;
        assert!(thing.contains("Appears at: `/thing`."));
        assert!(thing.contains("A thing &lt;x&gt;.\n\nMore."));
        assert!(thing.contains("| `kind` | [`Kind`](types.md#kind) | yes |"));
        assert!(thing.contains("| `act` | [`Action`](action.md) | no |"));
        assert!(thing.contains("| `tags` | array of string | no |  | at most 4 items |"));
        assert!(thing.contains("| `new_field` | string | no |  | matches `` ^a`b$ `` | 1.2.0 |"));
        assert!(thing.contains("Unknown fields are rejected."));
        let action = &pages[1].content;
        assert!(action.contains("### `type: go`"));
        assert!(action.contains("| `fast` | boolean | no |"));
        let types = &pages[3].content;
        assert!(types.contains("## Kind\n\n| Value | Meaning |"));
        assert!(types.contains("| `b` | Second &lt;kind&gt;. |"));
        assert!(types.contains("## Id\n\nType: string; matches `^[0-9]+$`."));
        assert!(
            types.contains("## Ip\n\nType: string; format `ipv4` or `ipv6`."),
            "{types}"
        );
        // A cross-field rule is not a type and has no page of its own.
        assert!(!types.contains("## OpRule"));
        assert!(
            types.contains("| `OpRule` | `/thing/rule` | `add` has `new` only. |"),
            "{types}"
        );
    }

    #[test]
    fn a_schema_without_a_version_or_defs_is_an_error() {
        assert!(pages(&json!({"$defs": {}}), &spec(None)).is_err());
        assert!(pages(&json!({"x-schema-version": "1.0.0"}), &spec(None)).is_err());
        // Past x.0.0 without a `since` table: the column would be wrong.
        let e = pages(&sample(), &spec(None)).unwrap_err();
        assert!(e.contains("version 1.2.0 is past 1.0.0"), "{e}");
        let mut first = sample();
        first["x-schema-version"] = json!("1.0.3");
        assert!(pages(&first, &spec(None)).is_err());
        first["x-schema-version"] = json!("2.0.0");
        assert!(pages(&first, &spec(None)).is_ok());
    }

    #[test]
    fn rustdoc_links_lose_their_brackets() {
        assert_eq!(
            strip_intra_doc_links(
                "See [`Event::file`] and [`a`](x.md) or [b]. is [`super::Event::user`]."
            ),
            "See `Event::file` and [`a`](x.md) or [b]. is `super::Event::user`."
        );
        assert_eq!(strip_intra_doc_links("[`x` and `y`]"), "[`x` and `y`]");
        assert_eq!(strip_intra_doc_links("[`unclosed"), "[`unclosed");
        // Brackets inside separate code spans are not a link.
        assert_eq!(
            strip_intra_doc_links("Use `[` and `]`."),
            "Use `[` and `]`."
        );
        assert_eq!(strip_intra_doc_links("[`]"), "[`]");
        // A bracketed code span that holds a bracket is still one link.
        assert_eq!(strip_intra_doc_links("[``]``]"), "``]``");
        assert_eq!(strip_intra_doc_links("`[` x `]`"), "`[` x `]`");
        // A reference-style link keeps its brackets.
        assert_eq!(strip_intra_doc_links("[`Name`][ref]"), "[`Name`][ref]");
        assert_eq!(strip_intra_doc_links("[``a`b``]"), "``a`b``");
        assert_eq!(strip_intra_doc_links("[`a`]\n[`b`] é"), "`a`\n`b` é");
    }

    #[test]
    fn file_names() {
        assert_eq!(page_file("PolicySettings"), "policy-settings.md");
        assert_eq!(page_file("Uuid7"), "uuid7.md");
    }

    #[test]
    fn since_takes_the_oldest_parent() {
        let since = |p: &str| (p == "/b/x").then(|| "1.1.0".to_owned());
        let s = spec(Some(&since));
        assert_eq!(
            field_since(&["/a".into(), "/b".into()], "x", &s, "1.0.0"),
            "1.0.0"
        );
        assert_eq!(field_since(&["/b".into()], "x", &s, "1.0.0"), "1.1.0");
        assert_eq!(
            compare_versions("1.10.0", "1.9.0"),
            std::cmp::Ordering::Greater
        );
    }
}
