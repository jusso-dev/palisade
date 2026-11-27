//! `cargo xtask threat-coverage`: keeps the threat model
//! (`docs/security/threat-model.md`, #219) consistent with itself and with
//! the code.
//!
//! The threat model is a Markdown document, so nothing stops it from
//! claiming a mitigation that does not exist. This check reads its tables
//! and fails when:
//!
//! - a STRIDE row does not have nine cells, its ID is not
//!   `T-<component>-<nn>`, an ID is used twice, its STRIDE letter or status
//!   is not one of the allowed values, or an `N/A` row gives no reason;
//! - a component's table does not consider all six STRIDE categories;
//! - the mitigation table does not have exactly one row for each threat that
//!   is not `N/A`, in the same order, with the same issue column;
//! - a threat is `implemented` or `verified` but its verification column has
//!   no `TEST:`, `fuzz:` or `CI:` entry, or a `verified` threat has no
//!   `BYP-*` or `RT-*` entry;
//! - a `TEST:` entry names a crate that does not exist, or a test function
//!   that the crate does not have; a `fuzz:` entry names an unknown fuzz
//!   target; or a `CI:` entry names a command no workflow runs. These are
//!   checked on every row, `planned` ones included, so a citation cannot go
//!   stale;
//! - the "Summary by status" table does not match the counts in the STRIDE
//!   tables;
//! - the document, or any tracked `.rs` or `.md` file, mentions a threat ID
//!   of a known component that the STRIDE tables do not define (for
//!   example a threat annotation comment whose number the tables do not
//!   have).
//!
//! The format of the verification column is described in the threat model
//! itself, under "Bypass attack trees". A test is any function preceded by a
//! `#[test]` or `#[tokio::test]` attribute, including inside `proptest!`
//! blocks. Only the last segment of a cited test path, the function name,
//! is checked; the module path in front of it is for the reader.

use std::collections::{BTreeMap, BTreeSet};

/// Where the threat model lives, relative to the repository root.
pub const DOCUMENT: &str = "docs/security/threat-model.md";

/// Allowed values of the Status column.
const STATUSES: &[&str] = &["planned", "implemented", "verified", "retired"];

/// The STRIDE letters, in order.
const STRIDE: &[&str] = &["S", "T", "R", "I", "D", "E"];

/// What the check compares the document against, gathered from the
/// repository by the caller.
#[derive(Debug, Default)]
pub struct Facts {
    /// Test function names, by crate name.
    pub tests: BTreeMap<String, BTreeSet<String>>,
    /// Every cargo-fuzz target name.
    pub fuzz_targets: BTreeSet<String>,
    /// Every `run:` command of every workflow, with runs of whitespace
    /// collapsed to one space.
    pub ci_commands: BTreeSet<String>,
}

/// One row of a STRIDE table.
#[derive(Debug)]
struct Threat {
    id: String,
    component: String,
    letter: String,
    /// `None` for an `N/A` row.
    status: Option<String>,
    issues: String,
    line: usize,
}

/// One row of the mitigation table.
#[derive(Debug)]
struct Mitigation {
    id: String,
    issues: String,
    verification: String,
    line: usize,
}

/// Checks the threat model `doc` against `facts`. Returns one message per
/// violation, with the document line it refers to.
pub fn check(doc: &str, facts: &Facts) -> Vec<String> {
    let mut v = Vec::new();
    let (threats, mitigations, summary) = parse(doc, &mut v);
    if threats.is_empty() {
        v.push(format!("{DOCUMENT}: no STRIDE rows found"));
        return v;
    }
    check_threats(&threats, &mut v);
    check_mitigations(&threats, &mitigations, facts, &mut v);
    check_summary(&threats, &summary, &mut v);
    let ids: BTreeSet<String> = threats.iter().map(|t| t.id.clone()).collect();
    let components: BTreeSet<String> = threats.iter().map(|t| t.component.clone()).collect();
    v.extend(check_references(DOCUMENT, doc, &ids, &components));
    v
}

/// The cells of a Markdown table row, trimmed. `None` if `line` is not a
/// table row.
fn cells(line: &str) -> Option<Vec<&str>> {
    let inner = line.trim().strip_prefix('|')?.strip_suffix('|')?;
    Some(inner.split('|').map(str::trim).collect())
}

/// `true` for a Markdown table separator cell such as `---` or `:-:`.
fn is_separator(cell: &str) -> bool {
    !cell.is_empty() && cell.bytes().all(|b| b == b'-' || b == b':')
}

/// `(component, number)` of a threat ID `T-<component>-<nn>`, where the
/// component is lowercase ASCII letters and the number is two digits.
fn split_id(id: &str) -> Option<(&str, &str)> {
    let rest = id.strip_prefix("T-")?;
    let (component, number) = rest.rsplit_once('-')?;
    let valid = !component.is_empty()
        && component.bytes().all(|b| b.is_ascii_lowercase())
        && number.len() == 2
        && number.bytes().all(|b| b.is_ascii_digit());
    valid.then_some((component, number))
}

type Parsed = (
    Vec<Threat>,
    Vec<Mitigation>,
    Vec<(String, Vec<String>, usize)>,
);

/// Reads the STRIDE rows, the mitigation rows and the summary rows
/// (`(component or "Total", counts, line)`).
fn parse(doc: &str, v: &mut Vec<String>) -> Parsed {
    let mut section = "";
    let mut threats = Vec::new();
    let mut mitigations = Vec::new();
    let mut summary = Vec::new();
    for (index, line) in doc.lines().enumerate() {
        let n = index + 1;
        if let Some(heading) = line.strip_prefix("## ") {
            section = heading.trim();
            continue;
        }
        let Some(row) = cells(line) else { continue };
        let first = row.first().copied().unwrap_or("");
        // Header and separator rows; every other row is data.
        if matches!(first, "ID" | "Threat" | "Component") || row.iter().all(|c| is_separator(c)) {
            continue;
        }
        match section {
            "STRIDE per component" if first.starts_with('`') || first == "**Total**" => {
                let name = first.trim_matches(|c| c == '`' || c == '*').to_owned();
                let counts = row[1..]
                    .iter()
                    .map(|c| c.trim_matches('*').to_owned())
                    .collect();
                summary.push((name, counts, n));
            }
            "STRIDE per component" => {
                if let Some(t) = parse_threat(&row, n, v) {
                    threats.push(t);
                }
            }
            "Mitigation mapping" => {
                if row.len() != 4 {
                    v.push(format!(
                        "{DOCUMENT}:{n}: a mitigation row needs 4 cells (threat, mitigation, issue, verification), found {}",
                        row.len()
                    ));
                } else if split_id(first).is_none() {
                    v.push(format!(
                        "{DOCUMENT}:{n}: `{first}` is not a threat ID of the form T-<component>-<nn>"
                    ));
                } else {
                    for (name, cell) in [("mitigation", row[1]), ("verification", row[3])] {
                        if cell.is_empty() {
                            v.push(format!("{DOCUMENT}:{n}: {first}: the {name} cell is empty"));
                        }
                    }
                    mitigations.push(Mitigation {
                        id: row[0].to_owned(),
                        issues: row[2].to_owned(),
                        verification: row[3].to_owned(),
                        line: n,
                    });
                }
            }
            _ => {}
        }
    }
    (threats, mitigations, summary)
}

fn parse_threat(row: &[&str], n: usize, v: &mut Vec<String>) -> Option<Threat> {
    if row.len() != 9 {
        v.push(format!(
            "{DOCUMENT}:{n}: a STRIDE row needs 9 cells, found {}",
            row.len()
        ));
        return None;
    }
    let id = row[0];
    let Some((component, _)) = split_id(id) else {
        v.push(format!(
            "{DOCUMENT}:{n}: `{id}` is not a threat ID of the form T-<component>-<nn>"
        ));
        return None;
    };
    let letter = row[1];
    if !STRIDE.contains(&letter) {
        v.push(format!(
            "{DOCUMENT}:{n}: {id}: STRIDE category `{letter}` is not one of S, T, R, I, D, E"
        ));
    }
    let status = if let Some(reason) = row[2].strip_prefix("N/A:") {
        if reason.trim().is_empty() {
            v.push(format!("{DOCUMENT}:{n}: {id}: `N/A` needs a reason"));
        }
        if row[3..].iter().any(|c| !c.is_empty()) {
            v.push(format!(
                "{DOCUMENT}:{n}: {id}: an `N/A` row leaves every cell after the reason empty"
            ));
        }
        None
    } else {
        let status = row[7];
        if !STATUSES.contains(&status) {
            v.push(format!(
                "{DOCUMENT}:{n}: {id}: status `{status}` is not one of {}",
                STATUSES.join(", ")
            ));
        }
        for (name, cell) in [
            ("description", row[2]),
            ("preconditions", row[3]),
            ("impact", row[4]),
            ("likelihood", row[5]),
            ("issue", row[6]),
            ("residual risk", row[8]),
        ] {
            if cell.is_empty() {
                v.push(format!("{DOCUMENT}:{n}: {id}: the {name} cell is empty"));
            }
        }
        for (name, cell) in [("impact", row[4]), ("likelihood", row[5])] {
            if !cell.is_empty() && !["L", "M", "H"].contains(&cell) {
                v.push(format!(
                    "{DOCUMENT}:{n}: {id}: {name} `{cell}` is not L, M or H"
                ));
            }
        }
        Some(status.to_owned())
    };
    Some(Threat {
        id: id.to_owned(),
        component: component.to_owned(),
        letter: letter.to_owned(),
        status,
        issues: row[6].to_owned(),
        line: n,
    })
}

fn check_threats(threats: &[Threat], v: &mut Vec<String>) {
    let mut seen = BTreeMap::new();
    let mut letters: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for t in threats {
        if let Some(first) = seen.insert(t.id.as_str(), t.line) {
            v.push(format!(
                "{DOCUMENT}:{}: {} is already defined on line {first}; threat IDs are never reused",
                t.line, t.id
            ));
        }
        letters
            .entry(t.component.as_str())
            .or_default()
            .insert(t.letter.as_str());
    }
    for (component, found) in letters {
        let missing: Vec<&str> = STRIDE
            .iter()
            .copied()
            .filter(|l| !found.contains(l))
            .collect();
        if !missing.is_empty() {
            v.push(format!(
                "{DOCUMENT}: component `{component}` does not consider STRIDE {}; add a row, or an `N/A` row with the reason",
                missing.join(", ")
            ));
        }
    }
}

fn check_mitigations(
    threats: &[Threat],
    mitigations: &[Mitigation],
    facts: &Facts,
    v: &mut Vec<String>,
) {
    let expected: Vec<&Threat> = threats.iter().filter(|t| t.status.is_some()).collect();
    let by_id: BTreeMap<&str, &Threat> = threats.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut covered = BTreeSet::new();
    for (index, m) in mitigations.iter().enumerate() {
        let Some(threat) = by_id.get(m.id.as_str()) else {
            v.push(format!(
                "{DOCUMENT}:{}: {} has a mitigation row but no STRIDE row",
                m.line, m.id
            ));
            continue;
        };
        if threat.status.is_none() {
            v.push(format!(
                "{DOCUMENT}:{}: {} is `N/A` and must not have a mitigation row",
                m.line, m.id
            ));
            continue;
        }
        if !covered.insert(m.id.as_str()) {
            v.push(format!(
                "{DOCUMENT}:{}: {} has a second mitigation row",
                m.line, m.id
            ));
            continue;
        }
        if expected.get(index).map(|t| t.id.as_str()) != Some(m.id.as_str()) {
            v.push(format!(
                "{DOCUMENT}:{}: {} is out of order; the mitigation table follows the STRIDE tables",
                m.line, m.id
            ));
        }
        if threat.issues != m.issues {
            v.push(format!(
                "{DOCUMENT}:{}: {}: issue column `{}` differs from the STRIDE row (line {}): `{}`",
                m.line, m.id, m.issues, threat.line, threat.issues
            ));
        }
        let status = threat.status.as_deref().unwrap_or("");
        check_verification(m, status, facts, v);
    }
    for t in expected {
        if !covered.contains(t.id.as_str()) {
            v.push(format!(
                "{DOCUMENT}:{}: {} has no row in the mitigation table",
                t.line, t.id
            ));
        }
    }
}

/// The text between each pair of backticks in `s`.
fn backticked(s: &str) -> Vec<&str> {
    s.split('`').skip(1).step_by(2).collect()
}

/// The items of an untagged verification entry: split on commas outside
/// parentheses, so `TEST-x (#1, #2)` stays one item.
fn items(entry: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in entry.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(entry[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(entry[start..].trim());
    out
}

/// `true` if `item` starts with a proposed verification ID: one of the
/// prefixes, then lowercase letters, digits and `-`, not empty.
fn proposed_id<'a>(item: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    let id = item.split_whitespace().next().unwrap_or("");
    let (prefix, rest) = prefixes
        .iter()
        .find_map(|p| id.strip_prefix(p).map(|r| (*p, r)))?;
    let valid = !rest.is_empty()
        && !rest.starts_with('-')
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    valid.then(|| &id[..prefix.len() + rest.len()])
}

fn check_verification(m: &Mitigation, status: &str, facts: &Facts, v: &mut Vec<String>) {
    let at = format!("{DOCUMENT}:{}: {}", m.line, m.id);
    let mut on_main = false;
    let mut scenario = false;
    for entry in m.verification.split(';').map(str::trim) {
        if let Some(rest) = entry.strip_prefix("TEST:") {
            on_main = true;
            check_tests(&at, rest, facts, v);
        } else if let Some(rest) = entry.strip_prefix("fuzz:") {
            on_main = true;
            let targets = backticked(rest);
            if targets.is_empty() {
                v.push(format!("{at}: `fuzz:` names no target in backticks"));
            }
            for target in targets {
                if !facts.fuzz_targets.contains(target) {
                    v.push(format!("{at}: fuzz target `{target}` does not exist"));
                }
            }
        } else if let Some(rest) = entry.strip_prefix("CI:") {
            on_main = true;
            match backticked(rest).first() {
                Some(command) => {
                    let command = command.split_whitespace().collect::<Vec<_>>().join(" ");
                    if !facts.ci_commands.contains(&command) {
                        v.push(format!(
                            "{at}: no workflow under .github/workflows runs `{command}`"
                        ));
                    }
                }
                None => v.push(format!("{at}: `CI:` names no command in backticks")),
            }
        } else if entry.starts_with("None yet") {
            // An honest gap, allowed only on planned rows (checked below).
        } else {
            // Proposed IDs for #230 and other issues: every item must be
            // one, so a citation with a mistyped or missing tag fails.
            for item in items(entry) {
                if proposed_id(item, &["BYP-", "RT-"]).is_some() {
                    scenario = true;
                } else if proposed_id(item, &["FUZZ-", "TEST-"]).is_none() {
                    v.push(format!(
                        "{at}: verification entry `{item}` is not `TEST:`, `fuzz:` or `CI:` followed by backticked names, or a `BYP-`, `RT-`, `FUZZ-` or `TEST-` ID; separate entries with `;`"
                    ));
                }
            }
        }
    }
    if matches!(status, "implemented" | "verified") && !on_main {
        v.push(format!(
            "{at}: marked `{status}`, so the verification column needs a `TEST:`, `fuzz:` or `CI:` entry for a check on main"
        ));
    }
    if status == "verified" && !scenario {
        v.push(format!(
            "{at}: marked `verified`, so the verification column needs a `BYP-*` or `RT-*` scenario"
        ));
    }
}

/// `rest` is the text after `TEST:`: a crate name in backticks, then test
/// paths in backticks. A later backticked crate name switches the crate.
fn check_tests(at: &str, rest: &str, facts: &Facts, v: &mut Vec<String>) {
    let mut crate_name: Option<&str> = None;
    let mut tests = 0;
    // Whether the current crate has had a test named after it.
    let mut named = true;
    for token in backticked(rest) {
        if facts.tests.contains_key(token) {
            if !named {
                v.push(format!(
                    "{at}: `TEST:` names crate `{}` with no test after it",
                    crate_name.unwrap_or(token)
                ));
            }
            crate_name = Some(token);
            named = false;
            continue;
        }
        let Some(name) = crate_name else {
            v.push(format!(
                "{at}: `TEST:` must name a workspace crate in backticks before `{token}`"
            ));
            return;
        };
        tests += 1;
        named = true;
        let function = token.rsplit("::").next().unwrap_or(token);
        if !facts.tests[name].contains(function) {
            v.push(format!("{at}: crate `{name}` has no test `{function}`"));
        }
    }
    if tests == 0 {
        v.push(format!("{at}: `TEST:` names no test in backticks"));
    } else if !named {
        v.push(format!(
            "{at}: `TEST:` names crate `{}` with no test after it",
            crate_name.unwrap_or("")
        ));
    }
}

fn check_summary(
    threats: &[Threat],
    summary: &[(String, Vec<String>, usize)],
    v: &mut Vec<String>,
) {
    // [threats, planned, implemented, verified]. `N/A` rows are not
    // threats, so they are not counted; `retired` ones count only as threats.
    let mut counts: BTreeMap<String, [usize; 4]> = BTreeMap::new();
    for t in threats {
        let Some(status) = t.status.as_deref() else {
            continue;
        };
        for key in [t.component.clone(), "Total".to_owned()] {
            let c = counts.entry(key).or_default();
            c[0] += 1;
            match status {
                "planned" => c[1] += 1,
                "implemented" => c[2] += 1,
                "verified" => c[3] += 1,
                _ => {}
            }
        }
    }
    if summary.is_empty() {
        v.push(format!("{DOCUMENT}: no \"Summary by status\" table found"));
        return;
    }
    let mut listed = BTreeSet::new();
    for (name, found, line) in summary {
        listed.insert(name.as_str());
        let Some(want) = counts.get(name) else {
            v.push(format!(
                "{DOCUMENT}:{line}: summary row `{name}` is not a component with threats"
            ));
            continue;
        };
        let want: Vec<String> = want.iter().map(ToString::to_string).collect();
        if *found != want {
            v.push(format!(
                "{DOCUMENT}:{line}: summary row `{name}` says {} (threats, planned, implemented, verified), the tables give {}",
                found.join("/"),
                want.join("/")
            ));
        }
    }
    for name in counts.keys() {
        if !listed.contains(name.as_str()) {
            v.push(format!(
                "{DOCUMENT}: the summary table has no row for `{name}`"
            ));
        }
    }
}

/// Every mention in `text` of a threat ID whose component is in
/// `components` but which is not in `ids`. On a line with a `threat:` or
/// `threats:` annotation, any `T-...` token that is not a defined ID fails,
/// whatever its component or number of digits.
pub fn check_references(
    path: &str,
    text: &str,
    ids: &BTreeSet<String>,
    components: &BTreeSet<String>,
) -> Vec<String> {
    let mut v = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let annotated = line.contains("threat:") || line.contains("threats:");
        let bytes = line.as_bytes();
        let mut start = 0;
        while let Some(offset) = line[start..].find("T-") {
            let at = start + offset;
            start = at + 2;
            // A word boundary before the ID.
            if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'-') {
                continue;
            }
            let end = line[at + 2..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .map_or(line.len(), |e| at + 2 + e);
            let candidate = line[at..end].trim_end_matches('-');
            let known_component = split_id(candidate).is_some_and(|(c, _)| components.contains(c));
            let looks_like_id = candidate.len() > 2
                && candidate[2..].contains('-')
                && candidate.as_bytes()[2].is_ascii_lowercase();
            if (known_component || (annotated && looks_like_id)) && !ids.contains(candidate) {
                v.push(format!(
                    "{path}:{}: {candidate} is not a threat in {DOCUMENT}",
                    index + 1
                ));
            }
        }
    }
    v
}

/// Names of the test functions in Rust `source`: each `fn` item preceded by
/// a `#[test]` or `#[tokio::test(...)]` attribute, at any nesting depth
/// (including inside `proptest!` and other macro bodies). Tests that are
/// also `#[ignore]`d do not run by default, so they are left out. The source
/// is tokenised, so text in comments and string literals never counts.
/// `None` if `source` does not tokenise.
pub fn test_functions(source: &str) -> Option<Vec<String>> {
    use proc_macro2::{Delimiter, TokenStream, TokenTree};
    use std::str::FromStr as _;

    let mut found = Vec::new();
    let mut stack = vec![TokenStream::from_str(source).ok()?];
    while let Some(stream) = stack.pop() {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        let mut is_test = false;
        let mut ignored = false;
        let mut i = 0;
        while i < tokens.len() {
            match &tokens[i] {
                TokenTree::Punct(p) if p.as_char() == '#' => {
                    if let Some(TokenTree::Group(g)) = tokens.get(i + 1)
                        && g.delimiter() == Delimiter::Bracket
                    {
                        // The attribute's path: idents and `::`, up to
                        // its arguments (`(...)` or `= ...`).
                        let path: Vec<String> = g
                            .stream()
                            .into_iter()
                            .take_while(|t| match t {
                                TokenTree::Ident(_) => true,
                                TokenTree::Punct(p) => p.as_char() == ':',
                                _ => false,
                            })
                            .map(|t| t.to_string())
                            .collect();
                        match path.concat().as_str() {
                            "test" | "tokio::test" => is_test = true,
                            "ignore" => ignored = true,
                            _ => {}
                        }
                        stack.push(g.stream());
                        i += 2;
                        continue;
                    }
                }
                TokenTree::Ident(ident) if ident == "fn" => {
                    if let Some(TokenTree::Ident(name)) = tokens.get(i + 1)
                        && is_test
                        && !ignored
                    {
                        found.push(name.to_string());
                    }
                    is_test = false;
                    ignored = false;
                }
                TokenTree::Group(g) => {
                    stack.push(g.stream());
                    // A body ends the item the attributes belonged to.
                    if g.delimiter() == Delimiter::Brace {
                        is_test = false;
                        ignored = false;
                    }
                }
                TokenTree::Punct(p) if p.as_char() == ';' => {
                    is_test = false;
                    ignored = false;
                }
                _ => {}
            }
            i += 1;
        }
    }
    found.sort();
    Some(found)
}

/// The threat IDs and component names the STRIDE tables of `doc` define,
/// read with the same parser as [`check`].
pub fn defined_ids(doc: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let (threats, _, _) = parse(doc, &mut Vec::new());
    (
        threats.iter().map(|t| t.id.clone()).collect(),
        threats.iter().map(|t| t.component.clone()).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        let mut tests = BTreeMap::new();
        tests.insert(
            "palisade-policy".to_owned(),
            ["a_real_test", "another_test"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
        tests.insert("xtask".to_owned(), BTreeSet::new());
        Facts {
            tests,
            fuzz_targets: ["pe_parse".to_owned()].into(),
            ci_commands: ["cargo xtask check-workflows".to_owned()].into(),
        }
    }

    /// A small, valid threat model with one component, `x`, with `{rows}`
    /// and `{mitigations}` appended to its tables and `{summary}` as the
    /// counts (threats/planned/implemented/verified).
    fn doc(extra_rows: &str, extra_mitigations: &str, summary: &str) -> String {
        let s: Vec<&str> = summary.split('/').collect();
        format!(
            "# Threat model\n\n## STRIDE per component\n\n\
             | Component | Threats | Planned | Implemented | Verified |\n|---|---|---|---|---|\n\
             | `x` | {a} | {b} | {c} | {d} |\n| **Total** | **{a}** | **{b}** | **{c}** | **{d}** |\n\n\
             | ID | STRIDE | Threat | Preconditions | Impact | Likelihood | Mitigation issue | Status | Residual risk |\n\
             |---|---|---|---|---|---|---|---|---|\n\
             | T-x-01 | S | Spoof. | Any | H | M | #1 | planned | None. |\n\
             | T-x-02 | T | Tamper. | Any | H | M | #1, #2 | implemented | None. |\n\
             | T-x-03 | R | N/A: Nothing to deny. | | | | | | |\n\
             | T-x-04 | I | Leak. | Any | M | L | #3 | planned | None. |\n\
             | T-x-05 | D | Flood. | Any | M | L | #3 | planned | None. |\n\
             | T-x-06 | E | Escalate. | Any | H | L | #4 | planned | None. |\n\
             {extra_rows}\n\
             ## Bypass attack trees\n\n- AT-01 leaf → T-x-01; BYP-x-01\n\n\
             ## Mitigation mapping\n\n| Threat | Mitigation | Issue | Verification |\n|---|---|---|---|\n\
             | T-x-01 | Check. | #1 | BYP-x-01 |\n\
             | T-x-02 | Check. | #1, #2 | TEST: `palisade-policy` `mod::a_real_test`; fuzz: `pe_parse`; CI: `cargo xtask   check-workflows` (`runner-guard` job) |\n\
             | T-x-04 | Check. | #3 | TEST-x (#3) |\n\
             | T-x-05 | Check. | #3 | RT-x-01 |\n\
             | T-x-06 | Check. | #4 | TEST: `palisade-policy` `another_test` |\n\
             {extra_mitigations}\n\
             ## Residual-risk register\n\n| R-01 | Risk. | T-x-06 | Why. | Alert. | #4 |\n",
            a = s[0],
            b = s[1],
            c = s[2],
            d = s[3],
        )
    }

    fn run(extra_rows: &str, extra_mitigations: &str, summary: &str) -> Vec<String> {
        check(&doc(extra_rows, extra_mitigations, summary), &facts())
    }

    #[test]
    fn a_consistent_document_passes() {
        assert_eq!(run("", "", "5/4/1/0"), Vec::<String>::new());
    }

    #[test]
    fn the_real_threat_model_passes_its_own_format_rules() {
        // Only the rules that need no repository facts: every TEST/fuzz/CI
        // citation fails against empty facts, so filter those out. The full
        // check runs as `cargo xtask threat-coverage` in CI.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(DOCUMENT);
        let text = std::fs::read_to_string(path).unwrap();
        let v: Vec<String> = check(&text, &Facts::default())
            .into_iter()
            .filter(|m| {
                !(m.contains("has no test")
                    || m.contains("must name a workspace crate")
                    || m.contains("fuzz target")
                    || m.contains("no workflow"))
            })
            .collect();
        assert_eq!(v, Vec::<String>::new());
    }

    #[test]
    fn implemented_needs_a_check_on_main() {
        let v = run(
            "| T-x-07 | E | More. | Any | H | L | #5 | implemented | None. |\n",
            "| T-x-07 | Check. | #5 | TEST-x (#5), BYP-x-02 |\n",
            "6/4/2/0",
        );
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("T-x-07: marked `implemented`"), "{v:?}");
    }

    #[test]
    fn verified_needs_a_check_and_a_scenario() {
        let v = run(
            "| T-x-07 | E | More. | Any | H | L | #5 | verified | None. |\n",
            "| T-x-07 | Check. | #5 | TEST: `palisade-policy` `a_real_test` |\n",
            "6/4/1/1",
        );
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("`BYP-*` or `RT-*`"), "{v:?}");
    }

    #[test]
    fn citations_must_exist_even_on_planned_rows() {
        let v = run(
            "| T-x-07 | E | More. | Any | H | L | #5 | planned | None. |\n",
            "| T-x-07 | Check. | #5 | TEST: `palisade-policy` `gone::missing_test`; TEST: `palisade-nope` `x`; fuzz: `no_target`; CI: `cargo xtask nothing` |\n",
            "6/5/1/0",
        );
        assert_eq!(v.len(), 4, "{v:?}");
        assert!(v[0].contains("crate `palisade-policy` has no test `missing_test`"));
        assert!(v[1].contains("must name a workspace crate in backticks before `palisade-nope`"));
        assert!(v[2].contains("fuzz target `no_target` does not exist"));
        assert!(v[3].contains("no workflow under .github/workflows runs `cargo xtask nothing`"));
    }

    #[test]
    fn a_later_crate_name_switches_the_crate() {
        let v = run(
            "| T-x-07 | E | More. | Any | H | L | #5 | implemented | None. |\n",
            "| T-x-07 | Check. | #5 | TEST: `palisade-policy` `a_real_test`, `xtask` `a_real_test` |\n",
            "6/4/2/0",
        );
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(
            v[0].ends_with(": T-x-07: crate `xtask` has no test `a_real_test`"),
            "{v:?}"
        );
    }

    #[test]
    fn every_threat_has_one_mitigation_row_in_order_with_the_same_issues() {
        let mut text = doc("", "", "5/4/1/0");
        // Remove T-x-04's row, duplicate T-x-05's, change T-x-06's issues.
        text = text.replace("| T-x-04 | Check. | #3 | TEST-x (#3) |\n", "");
        text = text.replace(
            "| T-x-05 | Check. | #3 | RT-x-01 |\n",
            "| T-x-05 | Check. | #3 | RT-x-01 |\n| T-x-05 | Again. | #3 | RT-x-01 |\n",
        );
        text = text.replace("| T-x-06 | Check. | #4 |", "| T-x-06 | Check. | #4, #9 |");
        let v = check(&text, &facts());
        let joined = v.join("\n");
        assert!(joined.contains("T-x-05 is out of order"), "{joined}");
        assert!(
            joined.contains("T-x-05 has a second mitigation row"),
            "{joined}"
        );
        assert!(
            joined.contains("T-x-06: issue column `#4, #9` differs"),
            "{joined}"
        );
        assert!(
            joined.contains("T-x-04 has no row in the mitigation table"),
            "{joined}"
        );
    }

    #[test]
    fn na_rows_need_a_reason_and_no_mitigation() {
        let mut text = doc("", "| T-x-03 | Check. | | BYP-x-01 |\n", "5/4/1/0");
        text = text.replace("N/A: Nothing to deny.", "N/A:");
        let v = check(&text, &facts());
        let joined = v.join("\n");
        assert!(joined.contains("T-x-03: `N/A` needs a reason"), "{joined}");
        assert!(
            joined.contains("T-x-03 is `N/A` and must not have a mitigation row"),
            "{joined}"
        );
    }

    #[test]
    fn row_shape_ids_categories_and_statuses_are_checked() {
        let v = run(
            "| T-x-1 | S | Bad ID. | Any | H | L | #5 | planned | None. |\n\
             | T-x-07 | Q | Bad letter. | Any | H | L | #5 | done | None. |\n\
             | T-x-01 | S | Reused. | Any | X | | #5 | planned | None. |\n\
             | T-x-08 | S | Short row. | Any |\n",
            "",
            "5/4/1/0",
        );
        let joined = v.join("\n");
        for want in [
            "`T-x-1` is not a threat ID",
            "T-x-07: STRIDE category `Q`",
            "T-x-07: status `done`",
            "T-x-01: impact `X` is not L, M or H",
            "T-x-01: the likelihood cell is empty",
            "T-x-01 is already defined on line",
            "a STRIDE row needs 9 cells, found 4",
        ] {
            assert!(joined.contains(want), "missing {want:?} in:\n{joined}");
        }
    }

    #[test]
    fn every_component_considers_all_six_categories() {
        let text = doc("", "", "5/4/1/0").replace(
            "| T-x-05 | D | Flood. | Any | M | L | #3 | planned | None. |\n",
            "",
        );
        let text = text.replace("| T-x-05 | Check. | #3 | RT-x-01 |\n", "");
        let v = check(
            &text
                .replace("| 5 | 4 |", "| 4 | 3 |")
                .replace("**5** | **4**", "**4** | **3**"),
            &facts(),
        );
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(
            v[0].contains("component `x` does not consider STRIDE D"),
            "{v:?}"
        );
    }

    #[test]
    fn the_summary_must_match_the_tables() {
        let v = run("", "", "5/5/0/0");
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v[0].contains("summary row `x` says 5/5/0/0"), "{v:?}");
        assert!(v[0].contains("the tables give 5/4/1/0"), "{v:?}");
        assert!(v[1].contains("summary row `Total`"), "{v:?}");
    }

    #[test]
    fn unknown_threat_ids_are_found_in_any_text() {
        let ids: BTreeSet<String> = ["T-agent-01".to_owned()].into();
        let components: BTreeSet<String> = ["agent".to_owned()].into();
        let text = [
            "// threat",
            ": T-agent-01\n// threat",
            ": T-agent-02, see T-agent-1 and XT-agent-03\nATT&CK T-1218, T-other-01, (T-agent-04).",
        ]
        .concat();
        let v = check_references("src/a.rs", &text, &ids, &components);
        assert_eq!(
            v,
            [
                "src/a.rs:2: T-agent-02 is not a threat in docs/security/threat-model.md",
                // On a `threat:` line even a malformed ID is reported.
                "src/a.rs:2: T-agent-1 is not a threat in docs/security/threat-model.md",
                "src/a.rs:3: T-agent-04 is not a threat in docs/security/threat-model.md",
            ]
        );
        // Attack trees and the residual-risk register count too.
        let v = run("", "", "5/4/1/0");
        assert!(v.is_empty());
        let text = doc("", "", "5/4/1/0").replace("leaf → T-x-01", "leaf → T-x-09");
        let v = check(&text, &facts());
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("T-x-09 is not a threat"), "{v:?}");
    }

    #[test]
    fn untagged_or_mistyped_verification_entries_fail() {
        let v = run(
            "| T-x-07 | E | More. | Any | H | L | #5 | implemented | None. |\n",
            "| T-x-07 | Check. | #5 | TEST: `palisade-policy` `a_real_test`; `palisade-policy` `gone`; Test: `x`; BYP-; TEST-ok (#5, #6) |\n",
            "6/4/2/0",
        );
        assert_eq!(v.len(), 3, "{v:?}");
        assert!(v[0].contains("entry ``palisade-policy` `gone``"), "{v:?}");
        assert!(v[1].contains("entry `Test: `x``"), "{v:?}");
        assert!(v[2].contains("entry `BYP-`"), "{v:?}");
    }

    #[test]
    fn comma_separated_scenarios_count_for_verified() {
        let v = run(
            "| T-x-07 | E | More. | Any | H | L | #5 | verified | None. |\n",
            "| T-x-07 | Check. | #5 | TEST: `palisade-policy` `a_real_test`; FUZZ-x, TEST-y (#5), RT-x-01 |\n",
            "6/4/1/1",
        );
        assert_eq!(v, Vec::<String>::new());
    }

    #[test]
    fn a_crate_named_without_a_test_fails() {
        let v = run(
            "| T-x-07 | E | More. | Any | H | L | #5 | implemented | None. |\n",
            "| T-x-07 | Check. | #5 | TEST: `palisade-policy` `a_real_test`, `xtask` |\n",
            "6/4/2/0",
        );
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(
            v[0].contains("names crate `xtask` with no test after it"),
            "{v:?}"
        );
    }

    #[test]
    fn every_data_row_is_checked_and_no_cell_is_blank() {
        let v = run(
            "| t-x-07 | E | Lowercase ID. | Any | H | L | #5 | planned | None. |\n\
             | T-x-08 | E | No preconditions. | | H | L | #5 | planned | None. |\n",
            "| X-09 | Check. | #5 | BYP-x |\n| T-x-08 | | #5 | BYP-x |\n",
            "6/5/1/0",
        );
        let joined = v.join("\n");
        for want in [
            "`t-x-07` is not a threat ID",
            "T-x-08: the preconditions cell is empty",
            "`X-09` is not a threat ID",
            "T-x-08: the mitigation cell is empty",
        ] {
            assert!(joined.contains(want), "missing {want:?} in:\n{joined}");
        }
    }

    #[test]
    fn threat_annotations_must_name_defined_threats() {
        let ids: BTreeSet<String> = ["T-agent-01".to_owned()].into();
        let components: BTreeSet<String> = ["agent".to_owned()].into();
        let text = [
            "// threat",
            ": T-policy-05\n// threats",
            ": T-agent-01, T-agent-3\nprose about T-1218 and T-cell-x\n",
        ]
        .concat();
        let v = check_references("a.rs", &text, &ids, &components);
        assert_eq!(
            v,
            [
                "a.rs:1: T-policy-05 is not a threat in docs/security/threat-model.md",
                "a.rs:2: T-agent-3 is not a threat in docs/security/threat-model.md",
            ]
        );
    }

    #[test]
    fn defined_ids_come_from_the_stride_tables_only() {
        let text = doc("", "", "5/4/1/0") + "\n## Other\n\n| T-y-01 | not a threat row |\n";
        let (ids, components) = defined_ids(&text);
        assert_eq!(ids.len(), 6);
        assert!(ids.contains("T-x-03"));
        assert_eq!(components, ["x".to_owned()].into());
    }

    #[test]
    fn test_functions_follow_test_attributes() {
        let source = r##"
#[test]
fn plain() {}

#[tokio::test(flavor = "multi_thread")]
async fn on_tokio() {}

#[test]
#[cfg(windows)]
#[should_panic(
    expected = "multi-line attribute"
)]
/// Documented.
// Commented.
pub fn with_attributes() {}

#[test]
#[ignore = "writes fuzz seeds"]
fn ignored_seed_writer() {}

proptest! {
    #[test]
    fn inside_proptest(x in 0..1u8) {}
}

mod nested {
    #[test]
    fn in_a_module() {}
}

fn not_a_test() {}

const TEXT: &str = "#[test] fn in_a_string() {}";
// #[test] fn in_a_comment() {}
"##;
        assert_eq!(
            test_functions(source).unwrap(),
            [
                "in_a_module",
                "inside_proptest",
                "on_tokio",
                "plain",
                "with_attributes"
            ]
        );
        assert_eq!(test_functions("fn (("), None);
    }
}
