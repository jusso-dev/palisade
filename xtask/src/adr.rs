//! `cargo xtask adr new|index|lint`: the tooling for the ADR process in
//! `docs/adr/PROCESS.md` (#20).
//!
//! - [`lint`] checks every ADR file and the index in `docs/adr/README.md`:
//!   the file name and number, the title line, the Status, Date and
//!   Deciders lines, every template section present, in order and not
//!   empty (Security impact included) as the Markdown renders, so HTML
//!   comments and fenced code never count; for `superseded by NNNN`, a
//!   later, in-force ADR with a `Supersedes:` bullet naming the old one; and
//!   an index that matches the files exactly.
//! - [`index`] renders the table between the `adr-index` markers.
//! - [`new_adr`] copies the template with the next number and a title.
//!
//! Nothing here reads git history, so the lint cannot tell whether an
//! accepted ADR was edited; reviewers check that against PROCESS.md.

use std::collections::BTreeMap;
use std::path::Path;

/// The ADR directory, relative to the repository root.
pub const DIR: &str = "docs/adr";

/// The template's file name.
pub const TEMPLATE: &str = "0000-template.md";

const INDEX_START: &str = "<!-- adr-index:start -->";
const INDEX_END: &str = "<!-- adr-index:end -->";

/// The headings every ADR has, in order, after the title and the status
/// list. `###` headings belong to the `##` heading before them.
pub const SECTIONS: &[&str] = &[
    "## Context",
    "## Decision drivers",
    "## Considered options",
    "## Decision",
    "## Consequences",
    "### Positive",
    "### Negative",
    "## Security impact",
    "## Links",
];

/// One parsed ADR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adr {
    /// The 4-digit number.
    pub number: u32,
    /// The file name, such as `0002-enforcement-strategy.md`.
    pub file: String,
    /// The title from the first line, without `# NNNN. `.
    pub title: String,
    /// The Status value.
    pub status: String,
}

/// `true` if `status` is one of the values PROCESS.md allows.
fn valid_status(status: &str) -> bool {
    matches!(status, "proposed" | "accepted" | "deprecated" | "rejected")
        || superseded_by(status).is_some()
}

/// The number in `superseded by NNNN`.
fn superseded_by(status: &str) -> Option<u32> {
    let n = status.strip_prefix("superseded by ")?;
    (n.len() == 4 && n.bytes().all(|b| b.is_ascii_digit()))
        .then(|| n.parse().ok())
        .flatten()
}

/// The number and slug of an ADR file name `NNNN-kebab-title.md`, or why
/// it is not one.
fn parse_file_name(name: &str) -> Result<u32, String> {
    let stem = name
        .strip_suffix(".md")
        .ok_or_else(|| format!("{name}: an ADR file name ends in `.md`"))?;
    let (number, slug) = stem
        .split_once('-')
        .ok_or_else(|| format!("{name}: an ADR file name is `NNNN-kebab-title.md`"))?;
    if number.len() != 4 || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{name}: the number must be 4 digits"));
    }
    let kebab = !slug.is_empty()
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--")
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !kebab {
        return Err(format!(
            "{name}: the title part must be lowercase kebab-case (`a-z`, `0-9`, `-`)"
        ));
    }
    number
        .parse()
        .map_err(|_| format!("{name}: the number must be 4 digits"))
}

/// The lines of `text` as a reader of the rendered Markdown sees them:
/// HTML comments (`<!-- ... -->`, across lines too) are removed, and lines
/// inside fenced code blocks (```` ``` ```` or `~~~`) are replaced by
/// [`CODE`], so a `## ` line in a comment or a code example is never a
/// heading, and a comment alone is never content.
fn visible_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_comment = false;
    let mut fence: Option<&str> = None;
    for line in text.lines() {
        if let Some(marker) = fence {
            if line.trim_start().starts_with(marker) {
                fence = None;
            }
            out.push(CODE.to_owned());
            continue;
        }
        let mut visible = String::new();
        let mut rest = line;
        loop {
            if in_comment {
                match rest.find("-->") {
                    Some(end) => {
                        in_comment = false;
                        rest = &rest[end + 3..];
                    }
                    None => break,
                }
            } else if let Some(start) = rest.find("<!--") {
                visible.push_str(&rest[..start]);
                in_comment = true;
                rest = &rest[start + 4..];
            } else {
                visible.push_str(rest);
                break;
            }
        }
        let trimmed = visible.trim_start();
        if !in_comment {
            for marker in ["```", "~~~"] {
                if trimmed.starts_with(marker) {
                    fence = Some(marker);
                }
            }
        }
        if fence.is_some() {
            out.push(CODE.to_owned());
        } else {
            out.push(visible.trim_end().to_owned());
        }
    }
    out
}

/// Stands in for a line of a fenced code block: content, never a heading.
const CODE: &str = "\u{0}code";

/// Checks one ADR file, `name` with `text`. Returns the parsed ADR, if the
/// header could be read, and the violations.
pub fn check_file(name: &str, text: &str) -> (Option<Adr>, Vec<String>) {
    let mut v = Vec::new();
    let template = name == TEMPLATE;
    let number = match parse_file_name(name) {
        Ok(n) => Some(n),
        Err(e) => {
            v.push(format!("{DIR}/{e}"));
            None
        }
    };
    if number == Some(0) && !template {
        v.push(format!("{DIR}/{name}: 0000 is reserved for {TEMPLATE}"));
    }
    let at = format!("{DIR}/{name}");
    let lines: Vec<&str> = text.lines().collect();

    // Title: `# NNNN. Title`, with NNNN the file's number, or the literal
    // `NNNN` in the template (which `adr new` replaces).
    let want = if template {
        "NNNN".to_owned()
    } else {
        number.map_or_else(|| "NNNN".to_owned(), |n| format!("{n:04}"))
    };
    let title = lines
        .first()
        .and_then(|l| l.strip_prefix("# "))
        .and_then(|rest| rest.split_once(". "))
        .filter(|(n, t)| {
            !t.trim().is_empty()
                && if number.is_some() {
                    *n == want
                } else {
                    n.len() == 4
                }
        })
        .map(|(_, t)| t.trim().to_owned());
    if title.is_none() {
        v.push(format!("{at}:1: the first line must be `# {want}. Title`"));
    }

    // The status list: line 2 is blank, lines 3 to 5 are Status, Date and
    // Deciders. The template keeps `proposed` and the `YYYY-MM-DD`
    // placeholder, because `adr new` copies the one and fills in the other.
    let field = |index: usize, key: &str| -> Option<&str> {
        lines
            .get(index)
            .and_then(|l| l.strip_prefix(&format!("- {key}: ")))
            .map(str::trim)
    };
    if lines.get(1).is_none_or(|l| !l.trim().is_empty()) {
        v.push(format!("{at}:2: a blank line follows the title"));
    }
    let status = field(2, "Status");
    match status {
        None => v.push(format!("{at}:3: missing `- Status: <status>`")),
        Some(s) if template && s != "proposed" => {
            v.push(format!("{at}:3: the template's status must be `proposed`"));
        }
        Some(s) if !valid_status(s) => v.push(format!(
            "{at}:3: status `{s}` is not one of proposed, accepted, superseded by NNNN, deprecated, rejected"
        )),
        Some(_) => {}
    }
    match field(3, "Date") {
        None => v.push(format!("{at}:4: missing `- Date: YYYY-MM-DD`")),
        Some(d) if template && d != "YYYY-MM-DD" => {
            v.push(format!("{at}:4: the template's date must be `YYYY-MM-DD`"));
        }
        Some(d) if !template && !crate::supply_chain::is_date(d) => {
            v.push(format!("{at}:4: date `{d}` is not a valid YYYY-MM-DD date"));
        }
        Some(_) => {}
    }
    match field(4, "Deciders") {
        None => v.push(format!("{at}:5: missing `- Deciders: <who>`")),
        Some("") => v.push(format!("{at}:5: Deciders is empty")),
        Some(_) => {}
    }

    // Sections, as rendered: present once, in order, each with content.
    let visible = visible_lines(text);
    let mut found: Vec<(usize, &str)> = Vec::new();
    for (i, line) in visible.iter().enumerate() {
        if line.starts_with("## ") || line.starts_with("### ") {
            found.push((i, line.as_str()));
        }
    }
    let headings: Vec<&str> = found.iter().map(|(_, h)| *h).collect();
    for want in SECTIONS {
        match headings.iter().filter(|h| *h == want).count() {
            0 => v.push(format!("{at}: missing section `{want}`")),
            1 => {}
            _ => v.push(format!("{at}: section `{want}` appears more than once")),
        }
    }
    let order: Vec<&str> = headings
        .iter()
        .copied()
        .filter(|h| SECTIONS.contains(h))
        .collect();
    let expected: Vec<&str> = SECTIONS
        .iter()
        .copied()
        .filter(|s| order.contains(s))
        .collect();
    if order != expected {
        v.push(format!(
            "{at}: sections are out of order; the order is {}",
            SECTIONS.join(", ")
        ));
    }
    for (k, (line, heading)) in found.iter().enumerate() {
        if !SECTIONS.contains(heading) {
            continue;
        }
        // A `##` section runs to the next `##` heading, so its `###`
        // subsections count as its content; a `###` section runs to the
        // next heading of either level.
        let level_two = heading.starts_with("## ");
        let end = found[k + 1..]
            .iter()
            .find(|(_, h)| !level_two || h.starts_with("## "))
            .map_or(visible.len(), |(next, _)| *next);
        let body = &visible[line + 1..end];
        let has_content = body.iter().any(|l| !l.trim().is_empty());
        // `## Consequences` must hold its own subsections, not just any text.
        let consequences_ok = *heading != "## Consequences"
            || ["### Positive", "### Negative"]
                .iter()
                .all(|sub| body.iter().any(|l| l == sub));
        if !has_content {
            v.push(format!("{at}:{}: section `{heading}` is empty", line + 1));
        } else if !consequences_ok {
            v.push(format!(
                "{at}:{}: `### Positive` and `### Negative` belong under `## Consequences`",
                line + 1
            ));
        }
    }

    let adr = match (number, title, status) {
        (Some(number), Some(title), Some(status)) => Some(Adr {
            number,
            file: name.to_owned(),
            title,
            status: status.to_owned(),
        }),
        _ => None,
    };
    (adr, v)
}

/// Checks the whole directory: `files` is `(file name, text)` for every
/// `.md` file in `docs/adr/` except `README.md` and `PROCESS.md`, and
/// `readme` is the text of `README.md`.
pub fn lint(files: &[(String, String)], readme: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut adrs: BTreeMap<u32, Adr> = BTreeMap::new();
    let mut has_template = false;
    for (name, text) in files {
        if name == TEMPLATE {
            has_template = true;
        }
        let (adr, problems) = check_file(name, text);
        v.extend(problems);
        if let Some(adr) = adr {
            if adr.number == 0 {
                continue;
            }
            if let Some(other) = adrs.get(&adr.number) {
                v.push(format!(
                    "{DIR}/{}: number {:04} is already used by {}; numbers are never reused",
                    adr.file, adr.number, other.file
                ));
            } else {
                adrs.insert(adr.number, adr);
            }
        }
    }
    if !has_template {
        v.push(format!("{DIR}/{TEMPLATE}: missing"));
    }
    // Monotonic numbering: no gaps from 0001 up.
    for (expected, number) in (1..).zip(adrs.keys()) {
        if *number != expected {
            v.push(format!(
                "{DIR}: ADR {expected:04} is missing; numbers increase by one from 0001"
            ));
            break;
        }
    }
    v.extend(check_supersession(files, &adrs));
    // The index.
    match current_index(&normalise(readme)) {
        Some(current) => {
            let want = index(&adrs.into_values().collect::<Vec<_>>());
            if current != want {
                v.push(format!(
                    "{DIR}/README.md: the ADR index is out of date; run `cargo xtask adr index`"
                ));
            }
        }
        None => v.push(format!(
            "{DIR}/README.md: missing the `{INDEX_START}` and `{INDEX_END}` markers"
        )),
    }
    v
}

/// `superseded by NNNN` must name a later ADR that is itself in force
/// (`accepted` or `proposed`), and that ADR's Links section must have a
/// visible `Supersedes:` bullet naming the old number (plain, or as a
/// Markdown link such as `[0005](0005-x.md)` or `[ADR 0005](...)`).
fn check_supersession(files: &[(String, String)], adrs: &BTreeMap<u32, Adr>) -> Vec<String> {
    let mut v = Vec::new();
    for adr in adrs.values() {
        let Some(by) = superseded_by(&adr.status) else {
            continue;
        };
        let at = format!("{DIR}/{}", adr.file);
        let Some(newer) = adrs.get(&by) else {
            v.push(format!("{at}: superseded by {by:04}, which does not exist"));
            continue;
        };
        if by <= adr.number {
            v.push(format!(
                "{at}: superseded by {by:04}; an ADR is superseded only by a later one"
            ));
            continue;
        }
        if !matches!(newer.status.as_str(), "accepted" | "proposed") {
            v.push(format!(
                "{at}: superseded by {by:04}, whose status is `{}`; the superseding ADR must be accepted or proposed",
                newer.status
            ));
            continue;
        }
        let newer_text = files
            .iter()
            .find(|(n, _)| n == &newer.file)
            .map_or("", |(_, t)| t.as_str());
        if !supersedes(newer_text).contains(&adr.number) {
            v.push(format!(
                "{DIR}/{}: supersedes {:04}, so its Links section needs a `- Supersedes: {:04}` bullet",
                newer.file, adr.number, adr.number
            ));
        }
    }
    v
}

/// The ADR numbers named by visible `- Supersedes:` bullets in the Links
/// section of `text`.
fn supersedes(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in visible_lines(text) {
        if line.starts_with("## ") {
            inside = line == "## Links";
            continue;
        }
        let Some(rest) = line
            .trim_start()
            .strip_prefix("- Supersedes:")
            .filter(|_| inside)
        else {
            continue;
        };
        // Every run of exactly 4 digits that stands alone.
        let bytes = rest.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let alone = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
                if i - start == 4
                    && alone
                    && (i == bytes.len() || !bytes[i].is_ascii_alphanumeric())
                    && let Ok(n) = rest[start..i].parse()
                {
                    out.push(n);
                }
            } else {
                i += 1;
            }
        }
    }
    out
}

/// `text` with CRLF line endings turned into LF.
fn normalise(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// The ADR files in `dir` as `(file name, text)`, sorted by name: every
/// `.md` file except `README.md` and `PROCESS.md`. Fails on a symbolic link
/// (README.md and PROCESS.md included, since `adr index` writes the README),
/// a subdirectory, or any other file, so nothing in the directory is read
/// from somewhere else or skipped unseen. Dotfiles such as `.gitattributes`
/// are allowed.
pub fn read_dir(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| format!("{}: file name is not UTF-8: {n:?}", dir.display()))?;
        // `file_type` does not follow symbolic links.
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cannot stat {DIR}/{name}: {e}"))?;
        if file_type.is_symlink() {
            return Err(format!(
                "{DIR}/{name}: symbolic links are not allowed in {DIR}"
            ));
        }
        if name.starts_with('.') && file_type.is_file() {
            continue;
        }
        if !file_type.is_file() {
            return Err(format!("{DIR}/{name}: only files belong in {DIR}"));
        }
        if name == "README.md" || name == "PROCESS.md" {
            continue;
        }
        if !name.ends_with(".md") {
            return Err(format!(
                "{DIR}/{name}: only ADRs (`NNNN-kebab-title.md`), README.md and PROCESS.md belong here"
            ));
        }
        let text = std::fs::read_to_string(entry.path())
            .map_err(|e| format!("cannot read {DIR}/{name}: {e}"))?;
        files.push((name, text));
    }
    files.sort();
    Ok(files)
}

/// The index entries for `files`: every ADR whose header parses, with the
/// template left out. Fails on a header that does not parse or a number
/// used twice, so `adr index` never writes a table `adr lint` would reject
/// for those reasons.
pub fn index_entries(files: &[(String, String)]) -> Result<Vec<Adr>, String> {
    let mut adrs: BTreeMap<u32, Adr> = BTreeMap::new();
    for (name, text) in files {
        let (adr, problems) = check_file(name, text);
        let Some(adr) = adr else {
            return Err(problems.join("\n"));
        };
        if adr.number == 0 {
            continue;
        }
        if let Some(other) = adrs.get(&adr.number) {
            return Err(format!(
                "{DIR}/{}: number {:04} is already used by {}",
                adr.file, adr.number, other.file
            ));
        }
        adrs.insert(adr.number, adr);
    }
    Ok(adrs.into_values().collect())
}

/// Escapes `|` so a title cannot break the index table.
fn cell(s: &str) -> String {
    s.replace('|', "\\|")
}

/// The index table for `adrs`, sorted by number, as it goes between the
/// markers (without them).
pub fn index(adrs: &[Adr]) -> String {
    let mut sorted: Vec<&Adr> = adrs.iter().filter(|a| a.number != 0).collect();
    sorted.sort_by_key(|a| a.number);
    let mut out = String::from("| ADR | Title | Status |\n|---|---|---|\n");
    for a in sorted {
        out.push_str(&format!(
            "| [{:04}]({}) | {} | {} |\n",
            a.number,
            a.file,
            cell(&a.title),
            cell(&a.status)
        ));
    }
    out
}

/// The text between the index markers in `readme`, if both are present in
/// order, each on its own line.
fn current_index(readme: &str) -> Option<String> {
    let start = readme.find(&format!("{INDEX_START}\n"))? + INDEX_START.len() + 1;
    let end = start + readme[start..].find(INDEX_END)?;
    Some(readme[start..end].to_owned())
}

/// `readme` with the text between the index markers replaced by the index
/// of `adrs`, keeping the file's line endings (CRLF in a Windows checkout).
pub fn replace_index(readme: &str, adrs: &[Adr]) -> Result<String, String> {
    let crlf = readme.contains("\r\n");
    let readme = normalise(readme);
    let start = readme
        .find(&format!("{INDEX_START}\n"))
        .ok_or_else(|| format!("{DIR}/README.md: missing `{INDEX_START}`"))?
        + INDEX_START.len()
        + 1;
    let end = start
        + readme[start..].find(INDEX_END).ok_or_else(|| {
            format!("{DIR}/README.md: missing `{INDEX_END}` after the start marker")
        })?;
    let updated = format!("{}{}{}", &readme[..start], index(adrs), &readme[end..]);
    Ok(if crlf {
        updated.replace('\n', "\r\n")
    } else {
        updated
    })
}

/// The kebab-case slug of `title`: lowercase ASCII letters and digits, runs
/// of anything else become one `-`.
pub fn slug(title: &str) -> String {
    let mut out = String::new();
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// A new ADR: `(file name, text)`, numbered one above the highest number
/// in `existing` (file names), from `template`, dated `today`. The title
/// must give a non-empty slug and fit on one line.
pub fn new_adr(
    existing: &[String],
    template: &str,
    title: &str,
    today: &str,
) -> Result<(String, String), String> {
    let title = title.trim();
    if title.contains('\n') || title.contains('\r') {
        return Err("the title must be one line".to_owned());
    }
    let slug = slug(title);
    if slug.is_empty() {
        return Err("the title needs at least one ASCII letter or digit".to_owned());
    }
    let next = existing
        .iter()
        .filter_map(|f| parse_file_name(f).ok())
        .max()
        .unwrap_or(0)
        + 1;
    if next > 9999 {
        return Err("no 4-digit ADR numbers are left".to_owned());
    }
    let mut lines = template.lines();
    if lines.next().is_none_or(|l| !l.starts_with("# NNNN. ")) {
        return Err(format!(
            "{DIR}/{TEMPLATE}: the first line must be `# NNNN. ...`"
        ));
    }
    let rest: Vec<&str> = lines.collect();
    let body = rest
        .join("\n")
        .replacen("- Date: YYYY-MM-DD", &format!("- Date: {today}"), 1);
    let text = format!("# {next:04}. {title}\n{body}\n");
    Ok((format!("{next:04}-{slug}.md"), text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE_TEXT: &str = "# NNNN. Short title in sentence case

- Status: proposed
- Date: YYYY-MM-DD
- Deciders: Palisade maintainer

<!--
How to use this template.
-->

## Context

What forces are at play.

## Decision drivers

- Drivers.

## Considered options

1. **Option one.**

## Decision

The chosen option.

## Consequences

### Positive

- Easier.

### Negative

- Harder.

## Security impact

Required and never empty.

## Links

- Issues.
";

    fn adr(number: u32, status: &str) -> (String, String) {
        let title = format!("Decision {number}");
        let (name, text) = new_adr(
            &[format!("{:04}-x.md", number - 1)],
            TEMPLATE_TEXT,
            &title,
            "2026-11-25",
        )
        .unwrap();
        (
            name,
            text.replace("- Status: proposed", &format!("- Status: {status}")),
        )
    }

    fn set(entries: &[(String, String)]) -> (Vec<(String, String)>, String) {
        let mut files = vec![(TEMPLATE.to_owned(), TEMPLATE_TEXT.to_owned())];
        files.extend(entries.iter().cloned());
        let adrs: Vec<Adr> = files
            .iter()
            .filter_map(|(n, t)| check_file(n, t).0)
            .collect();
        let readme = format!("# ADRs\n\n{INDEX_START}\n{}{INDEX_END}\n", index(&adrs));
        (files, readme)
    }

    #[test]
    fn a_consistent_directory_passes() {
        let (files, readme) = set(&[adr(1, "accepted"), adr(2, "proposed")]);
        assert_eq!(lint(&files, &readme), Vec::<String>::new());
    }

    #[test]
    fn this_repository_passes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(DIR);
        let files = read_dir(&root).unwrap();
        let readme = std::fs::read_to_string(root.join("README.md")).unwrap();
        assert_eq!(lint(&files, &readme), Vec::<String>::new());
    }

    #[test]
    fn missing_or_invalid_status_is_rejected() {
        let (name, text) = adr(1, "accepted");
        for (bad, want) in [
            (
                text.replace("- Status: accepted\n", ""),
                "missing `- Status",
            ),
            (
                text.replace("- Status: accepted", "- Status: approved"),
                "status `approved`",
            ),
            (
                text.replace("- Status: accepted", "- Status: superseded by 12"),
                "status `superseded by 12`",
            ),
        ] {
            let (_, v) = check_file(&name, &bad);
            assert!(v.iter().any(|m| m.contains(want)), "{want}: {v:?}");
        }
    }

    #[test]
    fn missing_or_empty_security_impact_is_rejected() {
        let (name, text) = adr(1, "accepted");
        let removed = text.replace("## Security impact\n\nRequired and never empty.\n\n", "");
        let (_, v) = check_file(&name, &removed);
        assert!(
            v.iter()
                .any(|m| m.contains("missing section `## Security impact`")),
            "{v:?}"
        );
        let empty = text.replace("Required and never empty.", "");
        let (_, v) = check_file(&name, &empty);
        assert!(
            v.iter()
                .any(|m| m.contains("section `## Security impact` is empty")),
            "{v:?}"
        );
        // A comment alone is still empty.
        let comment = text.replace("Required and never empty.", "<!-- TODO -->");
        let (_, v) = check_file(&name, &comment);
        assert!(
            v.iter()
                .any(|m| m.contains("`## Security impact` is empty")),
            "{v:?}"
        );
    }

    #[test]
    fn sections_must_be_in_order_and_unique() {
        let (name, text) = adr(1, "accepted");
        let swapped = text
            .replace("## Context\n", "## TMP\n")
            .replace("## Decision drivers\n", "## Context\n")
            .replace("## TMP\n", "## Decision drivers\n");
        let (_, v) = check_file(&name, &swapped);
        assert!(v.iter().any(|m| m.contains("out of order")), "{v:?}");
        let twice = text.replace("## Links\n", "## Context\n\nAgain.\n\n## Links\n");
        let (_, v) = check_file(&name, &twice);
        assert!(
            v.iter()
                .any(|m| m.contains("`## Context` appears more than once")),
            "{v:?}"
        );
    }

    #[test]
    fn file_names_titles_and_dates_are_checked() {
        let (_, text) = adr(1, "accepted");
        for (name, want) in [
            ("1-x.md", "4 digits"),
            ("0001_x.md", "NNNN-kebab-title.md"),
            ("0001-Bad-Case.md", "kebab-case"),
            ("0001-x.txt", "ends in `.md`"),
        ] {
            let (_, v) = check_file(name, &text);
            assert!(v.iter().any(|m| m.contains(want)), "{name}: {v:?}");
        }
        let (_, v) = check_file("0002-x.md", &text);
        assert!(
            v.iter()
                .any(|m| m.contains("first line must be `# 0002. Title`")),
            "{v:?}"
        );
        let (_, v) = check_file("0001-x.md", &text.replace("2026-11-25", "2026-13-01"));
        assert!(v.iter().any(|m| m.contains("date `2026-13-01`")), "{v:?}");
        let (_, v) = check_file("0000-x.md", &text.replace("# 0001.", "# 0000."));
        assert!(v.iter().any(|m| m.contains("0000 is reserved")), "{v:?}");
    }

    #[test]
    fn numbers_are_unique_and_have_no_gaps() {
        let mut dup = adr(2, "accepted");
        dup.0 = "0002-other.md".to_owned();
        let (files, readme) = set(&[adr(1, "accepted"), adr(2, "accepted"), dup]);
        let v = lint(&files, &readme);
        assert!(
            v.iter().any(|m| m.contains("number 0002 is already used")),
            "{v:?}"
        );
        let (files, readme) = set(&[adr(1, "accepted"), adr(3, "accepted")]);
        let v = lint(&files, &readme);
        assert!(v.iter().any(|m| m.contains("ADR 0002 is missing")), "{v:?}");
    }

    #[test]
    fn supersession_needs_a_target_and_a_link_back() {
        let old = adr(1, "superseded by 0002");
        let new = adr(2, "accepted");
        let (files, readme) = set(&[old.clone(), new.clone()]);
        let v = lint(&files, &readme);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(
            v[0].contains("needs a `- Supersedes: 0001` bullet"),
            "{v:?}"
        );
        let linked = (
            new.0.clone(),
            new.1.replace("- Issues.", "- Supersedes: 0001\n- Issues."),
        );
        let (files, readme) = set(&[old.clone(), linked]);
        assert_eq!(lint(&files, &readme), Vec::<String>::new());
        let (files, readme) = set(&[adr(1, "superseded by 0009")]);
        let v = lint(&files, &readme);
        assert!(
            v.iter().any(|m| m.contains("0009, which does not exist")),
            "{v:?}"
        );
    }

    #[test]
    fn a_stale_index_fails_and_index_regenerates_it() {
        let (files, readme) = set(&[adr(1, "accepted"), adr(2, "proposed")]);
        let stale = readme.replace("| proposed |", "| accepted |");
        let v = lint(&files, &stale);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("run `cargo xtask adr index`"), "{v:?}");
        let adrs: Vec<Adr> = files
            .iter()
            .filter_map(|(n, t)| check_file(n, t).0)
            .collect();
        let fixed = replace_index(&stale, &adrs).unwrap();
        assert_eq!(fixed, readme);
        assert!(
            lint(&files, "no markers")
                .iter()
                .any(|m| m.contains("missing the"))
        );
        // A CRLF checkout (Windows) reads the same.
        assert_eq!(
            lint(&files, &readme.replace('\n', "\r\n")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn index_rows_are_sorted_and_escaped() {
        let adrs = vec![
            Adr {
                number: 2,
                file: "0002-b.md".into(),
                title: "B | c".into(),
                status: "accepted".into(),
            },
            Adr {
                number: 1,
                file: "0001-a.md".into(),
                title: "A".into(),
                status: "superseded by 0002".into(),
            },
        ];
        assert_eq!(
            index(&adrs),
            "| ADR | Title | Status |\n|---|---|---|\n\
             | [0001](0001-a.md) | A | superseded by 0002 |\n\
             | [0002](0002-b.md) | B \\| c | accepted |\n"
        );
    }

    #[test]
    fn new_takes_the_next_number_and_fills_the_header() {
        let existing = vec![
            TEMPLATE.to_owned(),
            "0001-a.md".to_owned(),
            "0019-z.md".to_owned(),
            "README.md".to_owned(),
        ];
        let (name, text) = new_adr(
            &existing,
            TEMPLATE_TEXT,
            "  Use HTTP/3 for push?  ",
            "2026-11-25",
        )
        .unwrap();
        assert_eq!(name, "0020-use-http-3-for-push.md");
        assert!(text.starts_with(
            "# 0020. Use HTTP/3 for push?\n\n- Status: proposed\n- Date: 2026-11-25\n"
        ));
        let (adr, v) = check_file(&name, &text);
        assert_eq!(v, Vec::<String>::new());
        assert_eq!(adr.unwrap().status, "proposed");
        assert!(new_adr(&existing, TEMPLATE_TEXT, "!!!", "2026-11-25").is_err());
        assert!(new_adr(&existing, TEMPLATE_TEXT, "a\nb", "2026-11-25").is_err());
        assert!(new_adr(&existing, "no header", "x", "2026-11-25").is_err());
    }

    #[test]
    fn commented_out_or_fenced_sections_do_not_count() {
        let (name, text) = adr(1, "accepted");
        let section = "## Security impact\n\nRequired and never empty.\n";
        for hidden in [
            format!("<!--\n{section}-->\n"),
            format!("<!-- {section} -->\n"),
            format!("```text\n{section}```\n"),
        ] {
            let bad = text.replace(section, &hidden);
            let (_, v) = check_file(&name, &bad);
            assert!(
                v.iter()
                    .any(|m| m.contains("missing section `## Security impact`")),
                "{hidden:?}: {v:?}"
            );
        }
        // A multi-line comment as the only content is empty.
        let bad = text.replace("Required and never empty.", "<!--\nTODO\n-->");
        let (_, v) = check_file(&name, &bad);
        assert!(
            v.iter()
                .any(|m| m.contains("`## Security impact` is empty")),
            "{v:?}"
        );
        // A code block is content.
        let code = text.replace("Required and never empty.", "```\nsee below\n```");
        assert_eq!(check_file(&name, &code).1, Vec::<String>::new());
    }

    #[test]
    fn subsections_are_content_of_their_section() {
        let (name, text) = adr(1, "accepted");
        let with_sub = text.replace(
            "1. **Option one.**",
            "### Policy cache\n\n1. **Option one.**",
        );
        assert_eq!(check_file(&name, &with_sub).1, Vec::<String>::new());
        // An unknown `##` heading splits Consequences from its subsections.
        let split = text.replace("### Positive", "## Extra\n\n### Positive");
        let (_, v) = check_file(&name, &split);
        assert!(
            v.iter().any(|m| m.contains("`## Consequences` is empty")),
            "{v:?}"
        );
    }

    #[test]
    fn the_template_keeps_its_placeholders() {
        assert_eq!(check_file(TEMPLATE, TEMPLATE_TEXT).1, Vec::<String>::new());
        for (bad, want) in [
            (
                TEMPLATE_TEXT.replace("# NNNN.", "# 0000."),
                "`# NNNN. Title`",
            ),
            (
                TEMPLATE_TEXT.replace("- Status: proposed", "- Status: accepted"),
                "must be `proposed`",
            ),
            (
                TEMPLATE_TEXT.replace("YYYY-MM-DD", "2026-11-25"),
                "must be `YYYY-MM-DD`",
            ),
        ] {
            let (_, v) = check_file(TEMPLATE, &bad);
            assert!(v.iter().any(|m| m.contains(want)), "{want}: {v:?}");
        }
    }

    #[test]
    fn impossible_dates_are_rejected() {
        let (name, text) = adr(1, "accepted");
        let (_, v) = check_file(&name, &text.replace("2026-11-25", "2026-02-30"));
        assert!(v.iter().any(|m| m.contains("date `2026-02-30`")), "{v:?}");
    }

    #[test]
    fn supersession_links_may_be_markdown_but_must_be_visible_and_forward() {
        let old = adr(1, "superseded by 0002");
        let new = adr(2, "accepted");
        let link = |line: &str| {
            (
                new.0.clone(),
                new.1.replace("- Issues.", &format!("{line}\n- Issues.")),
            )
        };
        for ok in [
            "- Supersedes: [0001](0001-decision-1.md)",
            "- Supersedes: [ADR 0001](0001-decision-1.md)",
        ] {
            let (files, readme) = set(&[old.clone(), link(ok)]);
            assert_eq!(lint(&files, &readme), Vec::<String>::new(), "{ok}");
        }
        for bad in [
            "<!-- - Supersedes: 0001 -->",
            "Supersedes: 0001",
            "- Supersedes: 00010",
        ] {
            let (files, readme) = set(&[old.clone(), link(bad)]);
            let v = lint(&files, &readme);
            assert!(
                v.iter()
                    .any(|m| m.contains("needs a `- Supersedes: 0001` bullet")),
                "{bad}: {v:?}"
            );
        }
        // Backward, and a superseding ADR that is not in force.
        let (files, readme) = set(&[adr(1, "accepted"), adr(2, "superseded by 0001")]);
        assert!(
            lint(&files, &readme)
                .iter()
                .any(|m| m.contains("only by a later one"))
        );
        let (files, readme) = set(&[old.clone(), adr(2, "rejected")]);
        assert!(
            lint(&files, &readme)
                .iter()
                .any(|m| m.contains("must be accepted or proposed"))
        );
    }

    #[test]
    fn index_keeps_crlf_line_endings() {
        let (files, readme) = set(&[adr(1, "accepted")]);
        let crlf = readme.replace('\n', "\r\n");
        let adrs = index_entries(&files).unwrap();
        assert_eq!(replace_index(&crlf, &adrs).unwrap(), crlf);
        assert_eq!(replace_index(&readme, &adrs).unwrap(), readme);
    }

    #[test]
    fn index_entries_refuse_duplicates_and_broken_headers() {
        let mut dup = adr(1, "accepted");
        dup.0 = "0001-other.md".to_owned();
        let (files, _) = set(&[adr(1, "accepted"), dup]);
        assert!(index_entries(&files).unwrap_err().contains("already used"));
        let (files, _) = set(&[("0001-x.md".to_owned(), "no header".to_owned())]);
        assert!(index_entries(&files).is_err());
    }

    #[test]
    fn read_dir_rejects_links_and_stray_files() {
        let dir = std::env::temp_dir().join(format!("xtask-adr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("README.md"), "x").unwrap();
        std::fs::write(dir.join("0001-a.md"), "a").unwrap();
        std::fs::write(dir.join(".gitattributes"), "* -text").unwrap();
        assert_eq!(
            read_dir(&dir).unwrap(),
            [("0001-a.md".to_owned(), "a".to_owned())]
        );
        std::fs::write(dir.join("notes.txt"), "x").unwrap();
        assert!(read_dir(&dir).unwrap_err().contains("notes.txt"));
        std::fs::remove_file(dir.join("notes.txt")).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        assert!(read_dir(&dir).unwrap_err().contains("only files"));
        std::fs::remove_dir(dir.join("sub")).unwrap();
        #[cfg(unix)]
        {
            std::fs::remove_file(dir.join("README.md")).unwrap();
            std::os::unix::fs::symlink("0001-a.md", dir.join("README.md")).unwrap();
            assert!(read_dir(&dir).unwrap_err().contains("symbolic links"));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn slugs_are_kebab_case() {
        assert_eq!(
            slug("Agent-server protocol (v2)"),
            "agent-server-protocol-v2"
        );
        assert_eq!(slug("--MSRV & unsafe--"), "msrv-unsafe");
    }
}
