//! `cargo xtask docs`: the documentation site (#27).
//!
//! The book's sources are the repository's own Markdown: `docs/`, the root
//! policy files (`README.md`, `CONTRIBUTING.md`, ...) and every crate
//! README, so nothing is copied by hand and each page keeps working on
//! GitHub. `docs/book/` holds only what is new: `book.toml`, the theme
//! (the disclaimer banner), the introduction and concept pages, and the
//! generated reference pages, which are committed so a reviewer sees them
//! change in a pull request.
//!
//! - `generate` writes the generated pages: the policy and event reference
//!   from the committed JSON Schemas, the CLI reference from each binary's
//!   `--help`, and the crate map from the dependency rules.
//! - `check` regenerates them in memory and fails if a committed page
//!   differs, then checks every source page: it must be in `SUMMARY.md`
//!   (or be listed as not in the book), have one title and no skipped
//!   heading levels, give every image alt text, and every policy example
//!   must pass the schema and validation. Rust code blocks in the book must
//!   be marked `ignore` or `text`, because the API examples live in rustdoc,
//!   where `cargo test --doc` runs them.
//! - `build` stages the sources into `target/book-src` (see [`stage`]),
//!   runs `mdbook build` (with the Mermaid preprocessor, which renders
//!   every diagram and so fails on a broken one), fails on any warning, and
//!   checks every internal link and anchor with `lychee --offline`. The
//!   site is written to `target/book`. With `--site-url <path>`, links are
//!   built for that base path (`/palisade/latest/`).
//! - `assemble <dir> --version <name>` assembles the GitHub Pages tree: the
//!   book under `<dir>/<name>/`, the Rust API docs under
//!   `<dir>/<name>/api/rust/`, the version list, and a root redirect.

pub mod assemble;
pub mod markdown;
pub mod schema_ref;
pub mod stage;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The book directory, relative to the repository root.
pub const BOOK: &str = "docs/book";
/// Generated pages, relative to the repository root.
pub const GENERATED: &str = "docs/book/src/reference/generated";
/// Where `build` stages the sources, under the target directory.
pub const STAGE: &str = "book-src";
/// Where `build` writes the site, under the target directory.
pub const OUT: &str = "book";

/// Cargo's target directory: `CARGO_TARGET_DIR`, or `<root>/target`.
pub fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

/// A tool `docs build` runs: its name (also the command), the version CI
/// installs, and how to install it. The Mermaid preprocessor also needs
/// the headless browser its README names, which it starts itself; without
/// one it fails with its own error.
pub struct DocsTool {
    pub name: &'static str,
    pub version: &'static str,
    pub install: &'static str,
}

/// Everything `docs build` needs, at the versions in `ci.yml` (a test in
/// `ci.rs` checks they match).
pub const TOOLS: &[DocsTool] = &[
    DocsTool {
        name: "mdbook",
        version: "0.5.2",
        install: "cargo install --locked mdbook@0.5.2",
    },
    DocsTool {
        name: "mdbook-mermaid-ssr",
        version: "0.3.0",
        install: "cargo install --locked mdbook-mermaid-ssr@0.3.0, plus the headless browser its README names",
    },
    DocsTool {
        name: "lychee",
        version: "0.24.2",
        install: "the release archive from https://github.com/lycheeverse/lychee/releases (CI uses 0.24.2)",
    },
];

/// One file the generator writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    /// Repository-relative path.
    pub path: String,
    pub content: String,
}

/// The binaries whose `--help` goes into the CLI reference, as `(package,
/// binary, subcommands)`. Each subcommand path gets its own section.
pub const CLIS: &[(&str, &str, &[&[&str]])] = &[
    (
        "palisade-server",
        "palisade-server",
        &[
            &[],
            &["serve"],
            &["check-config"],
            &["version"],
            &["migrate"],
            &["migrate", "up"],
            &["migrate", "status"],
            &["migrate", "verify"],
        ],
    ),
    ("palisade-agent", "palisade-agent", &[&[]]),
    ("palisade-cli", "pal", &[&[]]),
];

/// The event schema's `since` table, read from the `palisade-proto`
/// source so xtask does not link the crate. Fails if the table cannot be
/// found, so a refactor there cannot silently drop the versions.
fn event_added(root: &Path) -> Result<Vec<(String, String)>, String> {
    let path = root.join("crates/palisade-proto/src/events/mod.rs");
    let source = read(&path)?;
    let start = source
        .find("pub const ADDED: &[(&str, SchemaVersion)] = &[")
        .ok_or("crates/palisade-proto/src/events/mod.rs: `pub const ADDED` not found")?;
    let body = &source[start..];
    let end = body.find("];").ok_or("ADDED: no closing `];`")?;
    let mut out = Vec::new();
    for line in body[..end].lines().skip(1) {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("(\"") else {
            continue;
        };
        let (pointer, version) = rest
            .split_once("\", V")
            .ok_or_else(|| format!("ADDED: cannot read `{line}`"))?;
        let version = version.trim_end_matches("),");
        let (major, minor) = version
            .split_once('_')
            .ok_or_else(|| format!("ADDED: cannot read the version in `{line}`"))?;
        out.push((pointer.to_owned(), format!("{major}.{minor}.0")));
    }
    if out.is_empty() {
        return Err("ADDED: no entries found".to_owned());
    }
    Ok(out)
}

fn since_from(added: &[(String, String)], pointer: &str) -> Option<String> {
    added
        .iter()
        .filter(|(p, _)| {
            pointer
                .strip_prefix(p.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .map(|(_, v)| v.clone())
        .max_by(|a, b| {
            let parse =
                |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
            parse(a).cmp(&parse(b))
        })
}

/// Every generated page, from the committed schemas and the given CLI help.
pub fn generate(root: &Path, help: &[(String, String)]) -> Result<Vec<Generated>, String> {
    let mut out = Vec::new();
    let added = event_added(root)?;
    let events_since = |p: &str| since_from(&added, p);
    let specs: [(&str, schema_ref::Spec<'_>); 2] = [
        (
            "schemas/policy/v1.json",
            schema_ref::Spec {
                dir: "policy",
                title: "Policy reference",
                source: "schemas/policy/v1.json",
                regenerate: "PALISADE_BLESS=1 cargo test -p palisade-policy --test schema",
                // The policy schema has no minor versions yet (1.0.0).
                since: None,
            },
        ),
        (
            "schemas/events/v1.json",
            schema_ref::Spec {
                dir: "events",
                title: "Event reference",
                source: "schemas/events/v1.json",
                regenerate: "PALISADE_BLESS=1 cargo test -p palisade-proto --test events_schema",
                since: Some(&events_since),
            },
        ),
    ];
    for (path, spec) in &specs {
        let schema: Value = serde_json::from_str(&read(&root.join(path))?)
            .map_err(|e| format!("{path}: invalid JSON: {e}"))?;
        for page in schema_ref::pages(&schema, spec)? {
            let mut content = page.content;
            if spec.dir == "policy" && page.file == "index.md" {
                content.push_str(&examples_section(root)?);
            }
            out.push(Generated {
                path: format!("{GENERATED}/{}/{}", spec.dir, page.file),
                content,
            });
        }
    }
    out.push(Generated {
        path: format!("{GENERATED}/cli.md"),
        content: cli_page(help),
    });
    out.push(Generated {
        path: format!("{GENERATED}/crates.md"),
        content: crates_page(root)?,
    });
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// The `SUMMARY.md` lines for the generated reference pages, between the
/// `generated:start` and `generated:end` markers. Generated with the pages
/// so a new schema type appears in the navigation too.
pub fn summary_block(pages: &[Generated]) -> String {
    let mut out = String::new();
    for (dir, title) in [
        ("policy", "Policy reference"),
        ("events", "Event reference"),
    ] {
        let prefix = format!("{GENERATED}/{dir}/");
        let mut files: Vec<&Generated> = pages
            .iter()
            .filter(|p| p.path.starts_with(&prefix))
            .collect();
        files.sort_by_key(|p| (!p.path.ends_with("/index.md"), p.path.clone()));
        for page in files {
            let rel = page.path.trim_start_matches("docs/book/src/");
            let name = page
                .content
                .lines()
                .next()
                .and_then(|l| l.strip_prefix("# "))
                .unwrap_or("Page");
            if page.path.ends_with("/index.md") {
                out.push_str(&format!("- [{title}]({rel})\n"));
            } else {
                out.push_str(&format!("    - [{name}]({rel})\n"));
            }
        }
    }
    out
}

/// The `SUMMARY.md` lines for the ADRs, between the `adr:start` and
/// `adr:end` markers: every `docs/adr/NNNN-*.md` except the template, in
/// number order, titled from its first heading. Generated, so an ADR added
/// by any pull request is in the book once `docs generate` runs.
pub fn adr_block(root: &Path) -> Result<String, String> {
    let dir = root.join("docs/adr");
    let mut adrs = Vec::new();
    for entry in
        std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let numbered = name.len() > 8
            && name.as_bytes()[..4].iter().all(u8::is_ascii_digit)
            && name.as_bytes()[4] == b'-'
            && name.ends_with(".md");
        if numbered && !name.starts_with("0000-") {
            adrs.push(name);
        }
    }
    adrs.sort();
    let mut out = String::new();
    for name in adrs {
        let text = read(&dir.join(&name))?;
        let title = text
            .lines()
            .find_map(|l| l.strip_prefix("# "))
            .ok_or_else(|| format!("docs/adr/{name}: no `# NNNN. Title` heading"))?;
        out.push_str(&format!(
            "    - [{}](../../adr/{name})\n",
            title.replace(['[', ']'], "")
        ));
    }
    Ok(out)
}

/// Replaces the block between `<!-- {marker}:start -->` and
/// `<!-- {marker}:end -->` in `SUMMARY.md`.
pub fn with_block(summary: &str, marker: &str, block: &str) -> Result<String, String> {
    let start_line = format!("<!-- {marker}:start -->\n");
    let end_line = format!("<!-- {marker}:end -->");
    let start = summary
        .find(&start_line)
        .ok_or_else(|| format!("docs/book/src/SUMMARY.md: no `<!-- {marker}:start -->` line"))?;
    let end = summary
        .find(&end_line)
        .ok_or_else(|| format!("docs/book/src/SUMMARY.md: no `<!-- {marker}:end -->` line"))?;
    if end < start {
        return Err(format!(
            "docs/book/src/SUMMARY.md: the `{marker}` markers are out of order"
        ));
    }
    Ok(format!(
        "{}{start_line}{block}{}",
        &summary[..start],
        &summary[end..]
    ))
}

/// `SUMMARY.md` with both generated blocks filled in.
pub fn summary_with_blocks(
    root: &Path,
    summary: &str,
    pages: &[Generated],
) -> Result<String, String> {
    let summary = with_block(summary, "generated", &summary_block(pages))?;
    with_block(&summary, "adr", &adr_block(root)?)
}

/// The policy reference's list of examples: every file in [`EXAMPLES`],
/// with the first line of its header comment. `palisade-policy`'s
/// `tests/yaml.rs` validates each one, and the concept pages show them.
fn examples_section(root: &Path) -> Result<String, String> {
    let mut names: Vec<String> = Vec::new();
    let dir = root.join(EXAMPLES);
    for entry in
        std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let name = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name.ends_with(".yaml") {
            names.push(name);
        }
    }
    names.sort();
    let mut out = String::from(
        "\n## Examples\n\nEach example passes this schema and full validation (`cargo test -p palisade-policy --test yaml`, in CI).\n\n",
    );
    for name in names {
        let text = read(&dir.join(&name))?;
        // The first paragraph of the header comment, after the editor
        // schema line: the consecutive non-empty `#` lines.
        let summary = text
            .lines()
            .skip_while(|l| l.starts_with("# yaml-language-server:"))
            .map(|l| l.strip_prefix('#').map(str::trim))
            .skip_while(|l| l.is_some_and(str::is_empty))
            .take_while(|l| l.is_some_and(|t| !t.is_empty()))
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        out.push_str(&format!(
            "- [`{name}`](../../../../../examples/policies/{name}): {}\n",
            markdown::cell(&summary)
        ));
    }
    Ok(out)
}

fn cli_page(help: &[(String, String)]) -> String {
    let mut out = String::from(
        "# CLI reference\n\n<!-- Generated by `cargo xtask docs generate` from each binary's `--help`. Do not edit by hand. -->\n\n\
         Every command and subcommand, with its `--help` output. The `pal` CLI is still a placeholder (#189); \
         its commands appear here as they are added.\n\n",
    );
    for (title, text) in help {
        out.push_str(&format!(
            "## `{title}`\n\n```text\n{}\n```\n\n",
            text.trim_end()
        ));
    }
    out.trim_end().to_owned() + "\n"
}

/// The crate map: each crate's purpose (its README's first paragraph),
/// platforms and the workspace crates it may use (from `check-deps`).
fn crates_page(root: &Path) -> Result<String, String> {
    let rules = crate::deps::allowed_rules();
    let mut out = String::from(
        "# Crate map\n\n<!-- Generated by `cargo xtask docs generate` from the crate READMEs and xtask/src/deps.rs. Do not edit by hand. -->\n\n\
         The workspace has one crate per component. `cargo xtask check-deps` enforces the allowed dependencies \
         ([ADR 0003](../../../../adr/0003-crate-boundaries-and-dependency-direction.md), [workspace rules](../../../../workspace.md)). \
         How data flows between the components, and across which trust boundaries, is in the \
         [threat model's data-flow diagrams](../../../../security/threat-model.md#data-flow-diagrams).\n\n\
         ```mermaid\nflowchart RL\n",
    );
    for (name, allowed) in rules {
        for dep in *allowed {
            // Only the direct layering, not every transitive permission.
            let direct = rules
                .iter()
                .filter(|(other, _)| allowed.contains(other))
                .all(|(_, theirs)| !theirs.contains(dep));
            if direct {
                out.push_str(&format!("    {} --> {}\n", short(name), short(dep)));
            }
        }
    }
    out.push_str("```\n\n| Crate | Purpose | May use |\n|---|---|---|\n");
    for (name, allowed) in rules {
        let readme = if *name == "xtask" {
            "xtask/README.md".to_owned()
        } else {
            format!("crates/{name}/README.md")
        };
        let text = read(&root.join(&readme))?;
        let purpose = text
            .split("\n\n")
            .find(|p| !p.trim_start().starts_with('#') && !p.trim().is_empty())
            .unwrap_or("")
            .to_owned();
        let uses = if allowed.is_empty() {
            "no workspace crate".to_owned()
        } else {
            allowed
                .iter()
                .map(|a| format!("`{a}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "| [`{name}`](../../../../../{readme}) | {} | {uses} |\n",
            markdown::cell(&purpose)
        ));
    }
    Ok(out)
}

fn short(name: &str) -> &str {
    name.strip_prefix("palisade-").unwrap_or(name)
}

/// Runs `--help` for every command in [`CLIS`], building the binaries
/// first. Help text is taken as printed; each binary prints its own name.
pub fn cli_help(root: &Path) -> Result<Vec<(String, String)>, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut build = Command::new(&cargo);
    build
        .args(["build", "--locked", "--quiet"])
        .current_dir(root);
    for (package, _, _) in CLIS {
        build.args(["-p", package]);
    }
    let status = build
        .status()
        .map_err(|e| format!("cannot run cargo build: {e}"))?;
    if !status.success() {
        return Err("cargo build of the CLI binaries failed".to_owned());
    }
    let target = target_dir(root).join("debug");
    let mut out = Vec::new();
    for (_, bin, commands) in CLIS {
        let exe = target.join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
        for command in *commands {
            let output = Command::new(&exe)
                .args(*command)
                .arg("--help")
                // Help text must not depend on the caller's environment:
                // clap shows the value of an `env` default in it. Windows
                // processes need `SystemRoot` to start.
                .env_clear()
                .envs(std::env::var_os("SystemRoot").map(|v| ("SystemRoot", v)))
                .env("NO_COLOR", "1")
                .output()
                .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
            let text = normalise_help(
                bin,
                &String::from_utf8_lossy(if output.stdout.is_empty() {
                    &output.stderr
                } else {
                    &output.stdout
                }),
            );
            let title = std::iter::once(*bin)
                .chain(command.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            out.push((title, text));
        }
    }
    Ok(out)
}

/// Help text as every platform prints it: LF line endings, and the binary
/// named without `.exe`. clap takes the name in `Usage:` lines from how the
/// program was started, so on Windows it says `palisade-server.exe`.
fn normalise_help(bin: &str, text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace(&format!("{bin}.exe"), bin)
}

/// Writes the generated pages and the SUMMARY block. Removes generated
/// pages that are no longer produced.
pub fn write(root: &Path, pages: &[Generated]) -> Result<(), String> {
    let dir = root.join(GENERATED);
    let wanted: BTreeSet<PathBuf> = pages.iter().map(|p| root.join(&p.path)).collect();
    for existing in walk_files(&dir)? {
        if !wanted.contains(&existing) {
            std::fs::remove_file(&existing)
                .map_err(|e| format!("cannot remove {}: {e}", existing.display()))?;
        }
    }
    for page in pages {
        let path = root.join(&page.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, &page.content)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    let summary_path = root.join(BOOK).join("src/SUMMARY.md");
    let summary = summary_with_blocks(root, &read(&summary_path)?.replace("\r\n", "\n"), pages)?;
    std::fs::write(&summary_path, summary)
        .map_err(|e| format!("cannot write {}: {e}", summary_path.display()))
}

/// Every file under `dir`, recursively; empty if `dir` does not exist.
pub fn walk_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = std::fs::read_dir(&current)
            .map_err(|e| format!("cannot read {}: {e}", current.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read {}: {e}", current.display()))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
            if kind.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Compares the committed generated pages and SUMMARY block with `pages`.
pub fn stale(root: &Path, pages: &[Generated]) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    let regenerate = "run `cargo xtask docs generate` and commit the result";
    let wanted: BTreeSet<String> = pages.iter().map(|p| p.path.clone()).collect();
    for page in pages {
        let path = root.join(&page.path);
        match std::fs::read_to_string(&path) {
            Ok(text) if text.replace("\r\n", "\n") == page.content => {}
            Ok(_) => v.push(format!("{}: out of date; {regenerate}", page.path)),
            Err(_) => v.push(format!("{}: missing; {regenerate}", page.path)),
        }
    }
    for existing in walk_files(&root.join(GENERATED))? {
        let rel = relative(root, &existing);
        if !wanted.contains(&rel) {
            v.push(format!("{rel}: no longer generated; {regenerate}"));
        }
    }
    let summary = read(&root.join(BOOK).join("src/SUMMARY.md"))?.replace("\r\n", "\n");
    if summary_with_blocks(root, &summary, pages)? != summary {
        v.push(format!(
            "docs/book/src/SUMMARY.md: the generated reference or ADR list is out of date; {regenerate}"
        ));
    }
    Ok(v)
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The disclaimer every page carries (#27). The same sentence opens the
/// root README; [`check_sources`] keeps the two identical.
pub const DISCLAIMER: &str = "Palisade is an educational, personal-development project. It is not a replacement for commercial application control products and comes with no support or warranty. Do not rely on it to protect production systems.";

/// Where policy examples live. `palisade-policy`'s `tests/yaml.rs` checks
/// every file here against the schema and validates it, so the book shows
/// them with `{{#include}}` rather than inline.
pub const EXAMPLES: &str = "docs/examples/policies/";

/// `true` if `crates/<name>/README.md` is the crate's library docs, so its
/// Rust code blocks run as doctests.
fn readme_is_doctested(root: &Path, path: &str) -> bool {
    let Some(name) = path
        .strip_prefix("crates/")
        .and_then(|p| p.strip_suffix("/README.md"))
    else {
        return false;
    };
    std::fs::read_to_string(root.join("crates").join(name).join("src/lib.rs"))
        .is_ok_and(|lib| lib.contains("include_str!(\"../README.md\")"))
}

/// The `check` rules over the book's sources: every candidate page is a
/// chapter, pages are accessible, policy examples come from [`EXAMPLES`]
/// and every example is shown, Rust blocks are tested or marked `ignore`,
/// and the disclaimer is in the README and the theme.
pub fn check_sources(root: &Path, files: &[String]) -> Result<Vec<String>, String> {
    let summary = read(&root.join(BOOK).join("src/SUMMARY.md"))?;
    let chapters = stage::summary_chapters(&summary)?;
    let mut v = Vec::new();
    let in_book: BTreeSet<String> = chapters.iter().map(|c| c.source.clone()).collect();
    for c in &chapters {
        if !files.contains(&c.source) {
            v.push(format!(
                "docs/book/src/SUMMARY.md:{}: `{}` is not a file in the repository",
                c.line, c.link
            ));
        }
    }
    for path in files.iter().filter(|p| stage::is_book_candidate(p)) {
        if !in_book.contains(path) && !stage::NOT_IN_BOOK.contains(&path.as_str()) {
            v.push(format!(
                "{path}: not in docs/book/src/SUMMARY.md; add it to the book, or to NOT_IN_BOOK in xtask/src/docs/stage.rs with a reason"
            ));
        }
    }
    let mut included = BTreeSet::new();
    for path in &in_book {
        let Ok(text) = std::fs::read_to_string(root.join(path)) else {
            continue;
        };
        let text = text.replace("\r\n", "\n");
        v.extend(markdown::accessibility(path, &text));
        for line in text.lines() {
            if let Some(target) = stage::include_target(line) {
                if let Some(resolved) = stage::resolve(stage::dir_of(path), target) {
                    included.insert(resolved);
                }
            }
        }
        for (line, info, body) in markdown::fenced_blocks(&text) {
            let words: Vec<&str> = info.split([' ', ',']).filter(|w| !w.is_empty()).collect();
            let marked = words.iter().any(|w| matches!(*w, "ignore" | "text"));
            if words.first() == Some(&"rust") && !marked && !readme_is_doctested(root, path) {
                v.push(format!(
                    "{path}:{line}: this `rust` block is not tested; put it in the crate's docs (a doctest) or mark it `rust,ignore`"
                ));
            }
            let is_yaml = matches!(words.first(), Some(&("yaml" | "yml")));
            if is_yaml && body.lines().any(|l| l.starts_with("schema_version:")) {
                v.push(format!(
                    "{path}:{line}: an inline policy example; put it in {EXAMPLES} (where tests/yaml.rs validates it) and `{{{{#include}}}}` it"
                ));
            }
        }
    }
    for example in files
        .iter()
        .filter(|f| f.starts_with(EXAMPLES) && f.ends_with(".yaml"))
    {
        if !included.contains(example) {
            v.push(format!(
                "{example}: not shown in the book; `{{{{#include}}}}` it from a page"
            ));
        }
    }
    let readme = read(&root.join("README.md"))?;
    if !readme.contains(&format!("**{DISCLAIMER}**")) {
        v.push("README.md: must contain the disclaimer, in bold, word for word (xtask/src/docs/mod.rs DISCLAIMER)".to_owned());
    }
    let header = read(&root.join(BOOK).join("theme/header.hbs"))?;
    if !header.contains(DISCLAIMER) {
        v.push("docs/book/theme/header.hbs: must contain the disclaimer word for word".to_owned());
    }
    Ok(v)
}

/// Checks each of [`TOOLS`] with `probe`: an error naming every missing
/// one, and otherwise one warning line per tool at another version than
/// CI's.
pub fn check_tools(probe: &mut dyn crate::tools::Probe) -> Result<Vec<String>, String> {
    use crate::tools::{Status, check, problem};
    let (mut missing, mut warnings) = (Vec::new(), Vec::new());
    for DocsTool {
        name,
        version,
        install,
    } in TOOLS
    {
        let command = [(*name).to_owned(), "--version".to_owned()];
        let status = check(probe, &command, Some(version));
        if let Some(line) = problem(name, Some(version), install, &status) {
            if status == Status::Missing {
                missing.push(format!("  {line}"));
            } else {
                warnings.push(line);
            }
        }
    }
    if missing.is_empty() {
        Ok(warnings)
    } else {
        Err(format!("missing tools:\n{}", missing.join("\n")))
    }
}

/// [`check_tools`] with the real tools, printing any version warnings.
pub fn require_tools() -> Result<(), String> {
    for warning in check_tools(&mut crate::tools::ProcessProbe)? {
        println!("docs: warning: {warning}");
    }
    Ok(())
}

/// `docs build`: stage, `mdbook build`, then the offline link check. Any
/// mdBook warning or error line fails the build.
pub fn build(root: &Path, files: &[String], site_url: Option<&str>) -> Result<Vec<String>, String> {
    require_tools()?;
    let stage_dir = target_dir(root).join(STAGE);
    let out_dir = target_dir(root).join(OUT);
    for dir in [&stage_dir, &out_dir] {
        if dir.exists() {
            std::fs::remove_dir_all(dir)
                .map_err(|e| format!("cannot remove {}: {e}", dir.display()))?;
        }
    }
    let problems = stage::stage(root, files, &stage_dir)?;
    if !problems.is_empty() {
        return Ok(problems);
    }
    let mut mdbook = Command::new("mdbook");
    mdbook
        .arg("build")
        .arg(&stage_dir)
        .arg("--dest-dir")
        .arg(&out_dir)
        // The preprocessor's own logs: warnings and errors only.
        .env("RUST_LOG", "warn");
    if let Some(url) = site_url {
        mdbook.env("MDBOOK_OUTPUT__HTML__SITE_URL", url);
    }
    let output = mdbook
        .output()
        .map_err(|e| format!("cannot run mdbook: {e}"))?;
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{log}");
    let mut v: Vec<String> = log
        .lines()
        .filter(|l| is_warning(l))
        .map(|l| format!("mdbook: {}", l.trim()))
        .collect();
    if !output.status.success() {
        v.push(format!("mdbook build failed ({})", output.status));
    }
    if !v.is_empty() {
        return Ok(v);
    }
    let lychee = Command::new("lychee")
        .args([
            "--offline",
            "--include-fragments",
            "--no-progress",
            // mdBook's 404 page resolves every link against
            // `<base href="{site-url}">`, which only exists on the
            // published site; it is mdBook's own template, not a chapter.
            "--exclude-path",
            "404\\.html$",
        ])
        .arg(&out_dir)
        .status()
        .map_err(|e| format!("cannot run lychee: {e}"))?;
    if !lychee.success() {
        v.push("lychee: broken internal links or anchors (listed above)".to_owned());
    }
    v.extend(pages_without_disclaimer(&out_dir)?);
    Ok(v)
}

/// Every rendered chapter carries the disclaimer banner from the theme.
fn pages_without_disclaimer(out_dir: &Path) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    let mut pages = 0;
    for path in walk_files(out_dir)? {
        if path.extension().is_none_or(|e| e != "html") {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // mdBook's sidebar frame is not a page.
        if name == "toc.html" {
            continue;
        }
        pages += 1;
        if !read(&path)?.contains(DISCLAIMER) {
            v.push(format!("{}: no disclaimer banner", path.display()));
        }
    }
    if pages == 0 {
        v.push(format!("{}: no pages were built", out_dir.display()));
    }
    Ok(v)
}

/// A log line that fails the build: mdBook's own `WARN` and `ERROR` lines,
/// and the Mermaid preprocessor's (`[<time> WARN  mdbook_mermaid_ssr] ...`).
/// Lines logged by the libraries the preprocessor uses to drive the
/// browser are about its connection, not the book, and are ignored.
fn is_warning(line: &str) -> bool {
    let line = line.trim_start();
    if let Some(rest) = line.strip_prefix('[') {
        let Some((head, _)) = rest.split_once(']') else {
            return false;
        };
        let mut words = head.split_whitespace();
        let (_time, level, target) = (words.next(), words.next(), words.next());
        return matches!(level, Some("WARN" | "ERROR"))
            && target.is_some_and(|t| t.starts_with("mdbook"));
    }
    line.starts_with("WARN ") || line.starts_with("ERROR ")
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_tools_are_detected() {
        use crate::tools::tests::FakeProbe;
        let all_present = [
            ("mdbook --version", Some("mdbook v0.5.2\n")),
            (
                "mdbook-mermaid-ssr --version",
                Some("mdbook-mermaid-ssr 0.3.0\n"),
            ),
            ("lychee --version", Some("lychee 0.24.2\n")),
        ];
        assert_eq!(
            check_tools(&mut FakeProbe::with(&all_present)),
            Ok(Vec::new())
        );
        // Another version: a warning, not an error.
        let mut old = all_present;
        old[0].1 = Some("mdbook v0.4.40\n");
        assert_eq!(
            check_tools(&mut FakeProbe::with(&old)).unwrap(),
            ["mdbook 0.5.2 is needed, found `mdbook v0.4.40`: cargo install --locked mdbook@0.5.2"]
        );
        // Missing tools: one error naming every one, with how to install.
        let err = check_tools(&mut FakeProbe::with(&all_present[..1])).unwrap_err();
        assert_eq!(
            err,
            "missing tools:\n  mdbook-mermaid-ssr 0.3.0 is not installed: cargo install --locked mdbook-mermaid-ssr@0.3.0, plus the headless browser its README names\n  lychee 0.24.2 is not installed: the release archive from https://github.com/lycheeverse/lychee/releases (CI uses 0.24.2)"
        );
    }

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    #[test]
    fn event_added_reads_the_proto_table() {
        let added = event_added(&root()).unwrap();
        assert!(
            added.contains(&("/network".to_owned(), "1.1.0".to_owned())),
            "{added:?}"
        );
        assert_eq!(
            since_from(&added, "/network/remote_ip").as_deref(),
            Some("1.1.0")
        );
        assert_eq!(since_from(&added, "/networkx"), None);
        assert_eq!(since_from(&added, "/file/size"), None);
    }

    #[test]
    fn summary_block_replaces_only_between_markers() {
        let s = "# Summary\n\n<!-- generated:start -->\nold\n<!-- generated:end -->\n- [X](x.md)\n";
        assert_eq!(
            with_block(s, "generated", "new\n").unwrap(),
            "# Summary\n\n<!-- generated:start -->\nnew\n<!-- generated:end -->\n- [X](x.md)\n"
        );
        assert!(with_block("no markers", "generated", "x").is_err());
        assert!(with_block(s, "adr", "x").is_err());
        assert!(
            with_block(
                "<!-- generated:end -->\n<!-- generated:start -->\n",
                "generated",
                "x"
            )
            .is_err()
        );
    }

    #[test]
    fn adr_block_lists_numbered_adrs_without_the_template() {
        let block = adr_block(&root()).unwrap();
        assert!(block.starts_with("    - [0001. Record architecture decisions](../../adr/0001-record-architecture-decisions.md)\n"));
        assert!(!block.contains("0000-template"));
        assert!(!block.contains("PROCESS"));
    }

    #[test]
    fn warnings_fail_the_build() {
        assert!(is_warning(" WARN unclosed HTML tag `<b>` found in `a.md`"));
        assert!(is_warning(
            "[2026-11-24T23:07:25Z ERROR mdbook_mermaid_ssr] Failed to render"
        ));
        assert!(is_warning("ERROR Error updating \"{{#include x}}\""));
        assert!(!is_warning(" INFO Book building has started"));
        assert!(!is_warning(
            "[2026-11-24T23:07:23Z WARN  browser_driver::transport] x"
        ));
        assert!(!is_warning(
            "[2026-11-24T23:07:23Z INFO  mdbook_mermaid_ssr] Rendering"
        ));
        assert!(!is_warning("a page that says WARN in passing"));
    }

    #[test]
    fn crate_map_lists_every_crate_once() {
        let page = crates_page(&root()).unwrap();
        for (name, _) in crate::deps::allowed_rules() {
            assert_eq!(page.matches(&format!("| [`{name}`]")).count(), 1, "{name}");
        }
        assert!(page.contains("    fileid --> core\n"));
        assert!(
            !page.contains("    policy --> core\n"),
            "only direct layers are drawn"
        );
    }

    #[test]
    fn help_is_the_same_on_every_platform() {
        assert_eq!(
            normalise_help("pal", "Usage: pal.exe [OPTIONS]\r\n  pal.exe help\r\n"),
            "Usage: pal [OPTIONS]\n  pal help\n"
        );
        assert_eq!(normalise_help("pal", "Usage: pal x"), "Usage: pal x");
    }

    #[test]
    fn cli_page_has_one_section_per_command() {
        let page = cli_page(&[
            ("a".to_owned(), "Usage: a\n".to_owned()),
            ("a b".to_owned(), "Usage: a b\r\n".to_owned()),
        ]);
        assert!(page.contains("## `a`\n\n```text\nUsage: a\n```"));
        assert!(page.contains("## `a b`\n\n```text\nUsage: a b\n```"));
        assert!(page.ends_with("```\n"));
    }

    /// A scratch repository with a minimal book, for the failure paths.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("palisade-docs-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let s = Self(dir);
            s.write("README.md", &format!("# Project\n\n**{DISCLAIMER}**\n"));
            s.write(
                "docs/book/theme/header.hbs",
                &format!("<div>{DISCLAIMER}</div>"),
            );
            s.write("docs/book/book.toml", "[book]\ntitle = \"t\"\n");
            s.write(
                "docs/book/src/SUMMARY.md",
                "# Summary\n\n[Intro](intro.md)\n- [CI](../../ci.md)\n- [Readme](../../../README.md)\n- [Crate](../../../crates/c/README.md)\n- [Example](example.md)\n<!-- generated:start -->\n<!-- generated:end -->\n<!-- adr:start -->\n    - [0001. First](../../adr/0001-first.md)\n<!-- adr:end -->\n",
            );
            s.write("docs/book/src/intro.md", "# Intro\n");
            s.write(
                "docs/book/src/example.md",
                "# Example\n\n{{#include ../../examples/policies/a.yaml}}\n",
            );
            s.write("docs/examples/policies/a.yaml", "x: 1\n");
            s.write("docs/ci.md", "# CI\n\n[intro](book/src/intro.md)\n");
            s.write("crates/c/README.md", "# c\n\n```rust\nlet x = 1;\n```\n");
            s.write(
                "crates/c/src/lib.rs",
                "#![doc = include_str!(\"../README.md\")]\n",
            );
            s.write("docs/adr/0001-first.md", "# 0001. First\n");
            s
        }

        fn write(&self, path: &str, text: &str) {
            let path = self.0.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        fn files(&self) -> Vec<String> {
            walk_files(&self.0)
                .unwrap()
                .iter()
                .map(|p| relative(&self.0, p))
                .collect()
        }

        fn check(&self) -> Vec<String> {
            check_sources(&self.0, &self.files()).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn check_sources_passes_a_good_book() {
        let s = Scratch::new("good");
        assert_eq!(s.check(), Vec::<String>::new());
    }

    #[test]
    fn check_sources_reports_each_rule() {
        let s = Scratch::new("bad");
        s.write("docs/orphan.md", "# Orphan\n");
        s.write("docs/examples/policies/unshown.yaml", "x: 2\n");
        s.write("docs/ci.md", "## CI\n\n![](x.png)\n\n```rust\nfn f() {}\n```\n\n```yaml\nschema_version: \"1.0.0\"\n```\n");
        s.write("docs/book/theme/header.hbs", "no banner");
        s.write("README.md", "# Project\n");
        let v = s.check();
        let expect = [
            "docs/orphan.md: not in docs/book/src/SUMMARY.md",
            "docs/ci.md:1: the first heading must be level 1",
            "docs/ci.md:3: an image without alt text",
            "docs/ci.md:5: this `rust` block is not tested",
            "docs/ci.md:9: an inline policy example",
            "docs/examples/policies/unshown.yaml: not shown in the book",
            "README.md: must contain the disclaimer",
            "docs/book/theme/header.hbs: must contain the disclaimer",
        ];
        for e in expect {
            assert!(
                v.iter().any(|m| m.starts_with(e)),
                "missing `{e}` in {v:#?}"
            );
        }
        assert_eq!(v.len(), expect.len(), "{v:#?}");
        // A doctested crate README may have plain `rust` blocks; marked
        // blocks are fine anywhere.
        assert!(!v.iter().any(|m| m.starts_with("crates/c/README.md")));
    }

    #[test]
    fn stale_reports_changed_missing_and_orphaned_pages() {
        let s = Scratch::new("stale");
        let pages = vec![
            Generated {
                path: format!("{GENERATED}/a.md"),
                content: "# A\n".to_owned(),
            },
            Generated {
                path: format!("{GENERATED}/b.md"),
                content: "# B\n".to_owned(),
            },
        ];
        write(&s.0, &pages).unwrap();
        assert_eq!(stale(&s.0, &pages).unwrap(), Vec::<String>::new());
        // write() fills both SUMMARY blocks and drops pages no longer made.
        let summary = std::fs::read_to_string(s.0.join("docs/book/src/SUMMARY.md")).unwrap();
        assert!(summary.contains("    - [0001. First](../../adr/0001-first.md)\n"));
        s.write(&format!("{GENERATED}/a.md"), "# A edited\n");
        std::fs::remove_file(s.0.join(format!("{GENERATED}/b.md"))).unwrap();
        s.write(&format!("{GENERATED}/old.md"), "# Old\n");
        s.write("docs/adr/0002-second.md", "# 0002. Second\n");
        let v = stale(&s.0, &pages).unwrap();
        assert_eq!(v.len(), 4, "{v:#?}");
        assert!(v[0].starts_with(&format!("{GENERATED}/a.md: out of date")));
        assert!(v[1].starts_with(&format!("{GENERATED}/b.md: missing")));
        assert!(v[2].starts_with(&format!("{GENERATED}/old.md: no longer generated")));
        assert!(v[3].contains("ADR list is out of date"));
        write(&s.0, &pages).unwrap();
        assert!(!s.0.join(format!("{GENERATED}/old.md")).exists());
        assert_eq!(stale(&s.0, &pages).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn stage_writes_chapters_includes_and_summary() {
        let s = Scratch::new("stage");
        let out = s.0.join("stage");
        assert_eq!(
            stage::stage(&s.0, &s.files(), &out).unwrap(),
            Vec::<String>::new()
        );
        let read_out = |p: &str| std::fs::read_to_string(out.join("src").join(p)).unwrap();
        let summary = read_out("SUMMARY.md");
        assert!(summary.contains("[Intro](intro.md)"), "{summary}");
        assert!(summary.contains(&format!("[Readme]({})", stage::ROOT_README)));
        assert!(summary.contains("[Crate](crates/c/README.md)"));
        assert!(!summary.contains("<!--"));
        // The first chapter is at the root, and links to it are rewritten.
        assert!(read_out("docs/ci.md").contains("[intro](../intro.md)"));
        assert!(read_out("docs/ci.md").contains(&format!(
            "Source: [`docs/ci.md`]({}docs/ci.md)",
            stage::BLOB
        )));
        assert_eq!(read_out("docs/examples/policies/a.yaml"), "x: 1\n");
        assert!(
            read_out("docs/book/src/example.md")
                .contains("{{#include ../../examples/policies/a.yaml}}")
        );
        assert!(out.join("theme/header.hbs").is_file() && out.join("book.toml").is_file());
        // The first chapter cannot use includes (mdBook copies it to the
        // root `index.html`); a broken link or include fails.
        s.write(
            "docs/book/src/SUMMARY.md",
            "# Summary\n\n[CI](../../ci.md)\n- [Intro](intro.md)\n- [Example](example.md)\n",
        );
        s.write("docs/ci.md", "# CI\n\n[gone](gone.md)\n\n{{#include nope.yaml}}\n\n{{#include examples/policies/a.yaml}}\n");
        let v = stage::stage(&s.0, &s.files(), &out).unwrap();
        assert_eq!(v.len(), 3, "{v:#?}");
        assert!(v[0].starts_with("docs/ci.md:3: broken link `gone.md`"));
        assert!(v[1].contains("`{{#include nope.yaml}}`: no such file"));
        assert!(
            v[2].contains("the first chapter and the root README cannot use"),
            "{v:#?}"
        );
    }

    #[test]
    fn every_built_page_needs_the_banner() {
        let s = Scratch::new("banner");
        s.write("out/a.html", DISCLAIMER);
        s.write("out/toc.html", "frame");
        assert_eq!(
            pages_without_disclaimer(&s.0.join("out")).unwrap(),
            Vec::<String>::new()
        );
        s.write("out/sub/b.html", "no banner");
        let v = pages_without_disclaimer(&s.0.join("out")).unwrap();
        assert_eq!(v.len(), 1);
        assert!(v[0].ends_with("b.html: no disclaimer banner"));
        assert_eq!(
            pages_without_disclaimer(&s.0.join("empty")).unwrap().len(),
            1
        );
    }
}
