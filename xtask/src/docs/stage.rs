//! Staging the book: `docs/book/src/SUMMARY.md` names repository files by
//! their path relative to it (`../../ci.md`, `../../../README.md`). mdBook
//! only reads chapters under its `src` directory, so [`stage`] builds that
//! directory in `target/book-src/src/`, mirroring the repository layout:
//!
//! - each chapter is copied to its repository path (`docs/ci.md` to
//!   `src/docs/ci.md`), so the relative links between chapters keep
//!   working unchanged;
//! - a link to a repository file that is not a chapter (a workflow, a
//!   script, a fixture, a directory) becomes a link to that file on GitHub
//!   at `main`;
//! - a link to a chapter's `.md` file stays relative, and mdBook turns it
//!   into a link to the `.html` page. mdBook renders a `README.md` chapter
//!   as `index.html` but does not rewrite links to it, so a link to a
//!   `README.md` chapter is rewritten to the same directory's `index.md`;
//! - a link to a path that does not exist fails the build, with the file
//!   and line;
//! - in a ```` ```mermaid ```` block, `'` becomes Mermaid's entity code
//!   `#39;`, which renders the same. The Mermaid preprocessor passes each
//!   diagram to the browser inside a single-quoted string, so a plain `'`
//!   in a label fails the build although the diagram is valid (GitHub
//!   renders it). Everything else is staged byte for byte.
//!
//! mdBook also copies the first chapter to the root `index.html` without
//! rewriting its links, so the first chapter's relative links are written
//! as seen from the root, and that chapter is staged at the root
//! (`docs/book/src/introduction.md` becomes `introduction.md`).
//!
//! The `SUMMARY.md` itself is rewritten to the staged paths. `book.toml`
//! and `theme/` are copied as they are.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use super::markdown::{self, Line};
use super::{BOOK, read};

/// Where the root `README.md` is staged. mdBook renders any `README.md`
/// chapter as its directory's `index.html`, so at the root it would replace
/// the introduction as the landing page.
pub const ROOT_README: &str = "project-overview.md";

/// The staged path of a chapter: the root README and the first chapter
/// are staged at the root, everything else at its repository path.
pub fn staged_path<'a>(source: &'a str, first: &str) -> &'a str {
    if source == "README.md" {
        ROOT_README
    } else if source == first {
        source.rsplit('/').next().unwrap_or(source)
    } else {
        source
    }
}

/// The relative path from directory `from` to repository path `to`.
fn relative_to(from: &str, to: &str) -> String {
    let from: Vec<&str> = from.split('/').filter(|p| !p.is_empty()).collect();
    let to_parts: Vec<&str> = to.split('/').collect();
    let common = from
        .iter()
        .zip(&to_parts)
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = "../".repeat(from.len() - common);
    out.push_str(&to_parts[common..].join("/"));
    out
}

/// Where repository files that are not chapters are linked to.
pub const BLOB: &str = "https://github.com/jusso-dev/palisade/blob/main/";
/// The same, for directories.
pub const TREE: &str = "https://github.com/jusso-dev/palisade/tree/main/";

/// Markdown files that are deliberately not book chapters, with the reason.
/// Every other `docs/**/*.md`, crate README and root policy file must be in
/// `SUMMARY.md`, so a new document cannot be left out of the site by
/// accident.
pub const NOT_IN_BOOK: &[&str] = &[
    // The ADR template is a file to copy, not a page to read; the ADR
    // process page links to it, on GitHub.
    "docs/adr/0000-template.md",
    // Generated from registry.yaml for GitHub readers; the event reference
    // is generated from the schema instead.
    "crates/palisade-proto/events/REGISTRY.md",
];

/// One chapter of `SUMMARY.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chapter {
    /// The 1-based line in `SUMMARY.md`.
    pub line: usize,
    /// The link as written, relative to `docs/book/src/`.
    pub link: String,
    /// The repository path it names.
    pub source: String,
}

/// Normalises `base/relative` to a repository path, or `None` if it leaves
/// the repository.
pub fn resolve(base_dir: &str, relative: &str) -> Option<String> {
    let mut parts: Vec<&str> = if base_dir.is_empty() {
        Vec::new()
    } else {
        base_dir.split('/').collect()
    };
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(p) => parts.push(p.to_str()?),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(parts.join("/"))
}

/// The directory part of a repository path (`""` at the root).
pub fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The file an mdBook `{{#include path}}` (or `{{#include path:anchor}}`)
/// on this line names, if any.
pub fn include_target(line: &str) -> Option<&str> {
    let rest = &line[line.find("{{#include ")? + "{{#include ".len()..];
    let end = rest.find("}}")?;
    let target = rest[..end].trim();
    Some(target.split(':').next().unwrap_or(target))
}

/// The chapters of `SUMMARY.md`, in order. Draft chapters (`[Name]()`) and
/// external links are not allowed: every chapter is a repository file.
pub fn summary_chapters(summary: &str) -> Result<Vec<Chapter>, String> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for (index, line) in summary.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim_start();
        let item = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
            .unwrap_or(trimmed);
        if !item.starts_with('[') {
            continue;
        }
        let Some(open) = item.find("](") else {
            continue;
        };
        let Some(close) = item[open..].find(')') else {
            continue;
        };
        let link = &item[open + 2..open + close];
        if link.is_empty() {
            errors.push(format!(
                "docs/book/src/SUMMARY.md:{number}: draft chapters are not allowed; link a file"
            ));
            continue;
        }
        if link.contains("://") || link.contains('#') {
            errors.push(format!(
                "docs/book/src/SUMMARY.md:{number}: `{link}`: a chapter must be a repository file"
            ));
            continue;
        }
        match resolve("docs/book/src", link) {
            Some(source) if source.ends_with(".md") => out.push(Chapter {
                line: number,
                link: link.to_owned(),
                source,
            }),
            _ => errors.push(format!(
                "docs/book/src/SUMMARY.md:{number}: `{link}` is not a Markdown file in the repository"
            )),
        }
    }
    let mut seen = BTreeSet::new();
    for c in &out {
        if !seen.insert(c.source.clone()) {
            errors.push(format!(
                "docs/book/src/SUMMARY.md:{}: `{}` is already a chapter",
                c.line, c.link
            ));
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors.join("\n"))
    }
}

/// `true` for the Markdown files that must be chapters (or in
/// [`NOT_IN_BOOK`]): everything under `docs/`, every crate README, and the
/// root Markdown files.
pub fn is_book_candidate(path: &str) -> bool {
    if !path.ends_with(".md") || path == "docs/book/src/SUMMARY.md" {
        return false;
    }
    if path.starts_with("docs/") {
        return true;
    }
    if !path.contains('/') {
        return true;
    }
    if path == "xtask/README.md" {
        return true;
    }
    match path.strip_prefix("crates/") {
        Some(rest) => {
            rest.matches('/').count() == 1 && rest.ends_with("/README.md")
                || rest.starts_with("palisade-proto/events/")
        }
        None => false,
    }
}

/// What a link destination in a staged chapter becomes.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// Leave it: external, an in-page anchor, or a link to another
    /// chapter, which works as written because chapters keep their
    /// relative layout.
    Keep,
    /// Replace it with this URL.
    Replace(String),
    /// Broken: the message.
    Broken(String),
}

/// What a link means, and what it becomes, from the chapter at repository
/// path `from`, staged at `staged_from`. `first` is the first chapter.
fn target(
    from: &str,
    staged_from: &str,
    dest: &str,
    files: &BTreeSet<&str>,
    dirs: &BTreeSet<String>,
    chapters: &BTreeSet<&str>,
    first: &str,
) -> Target {
    if dest.starts_with('#')
        || dest.contains("://")
        || dest.starts_with("mailto:")
        || dest.starts_with("data:")
    {
        return Target::Keep;
    }
    if dest.starts_with('/') {
        return Target::Broken(format!(
            "`{dest}`: use a relative link, so it works on GitHub and in the book"
        ));
    }
    let (path, fragment) = match dest.split_once('#') {
        Some((p, f)) => (p, Some(f)),
        None => (dest, None),
    };
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    if query.is_some() {
        return Target::Broken(format!("`{dest}`: a query string in a relative link"));
    }
    let Some(resolved) = resolve(dir_of(from), path) else {
        return Target::Broken(format!("`{dest}`: leaves the repository"));
    };
    let resolved = resolved.trim_end_matches('/').to_owned();
    let fragment = fragment.map_or_else(String::new, |f| format!("#{f}"));
    if chapters.contains(resolved.as_str()) {
        // The chapter's staged path, and `index.md` for a README chapter:
        // mdBook renders it as `index.html` but does not rewrite links to
        // it.
        let staged = staged_path(&resolved, first);
        let staged = match staged.strip_suffix("README.md") {
            Some(dir) if staged == "README.md" || dir.ends_with('/') => format!("{dir}index.md"),
            _ => staged.to_owned(),
        };
        let link = format!("{}{fragment}", relative_to(dir_of(staged_from), &staged));
        return if link == dest {
            Target::Keep
        } else {
            Target::Replace(link)
        };
    }
    if files.contains(resolved.as_str()) {
        return Target::Replace(format!("{BLOB}{resolved}{fragment}"));
    }
    if resolved.is_empty() || dirs.contains(&resolved) {
        return Target::Replace(format!("{TREE}{resolved}{fragment}"));
    }
    Target::Broken(format!("`{dest}`: no such file or directory ({resolved})"))
}

/// Rewrites one chapter's links. Returns the new text and any broken
/// links as `path:line: message`.
fn rewrite_chapter(
    path: &str,
    source: &str,
    files: &BTreeSet<&str>,
    dirs: &BTreeSet<String>,
    chapters: &BTreeSet<&str>,
    first: &str,
) -> (String, Vec<String>) {
    let staged_from = staged_path(path, first);
    let mut out = Vec::new();
    let mut broken = Vec::new();
    let mut in_mermaid = false;
    for (index, line) in markdown::lines(source).into_iter().enumerate() {
        match line {
            Line::Open { line, info } => {
                in_mermaid = info.split_whitespace().next() == Some("mermaid");
                out.push(line.to_owned());
            }
            Line::Code(line) if in_mermaid => out.push(line.replace('\'', "#39;")),
            Line::Close(line) => {
                in_mermaid = false;
                out.push(line.to_owned());
            }
            Line::Text(text) => {
                let rewritten = markdown::rewrite_links(text, &mut |dest| match target(
                    path,
                    staged_from,
                    dest,
                    files,
                    dirs,
                    chapters,
                    first,
                ) {
                    Target::Keep => Ok(None),
                    Target::Replace(url) => Ok(Some(url)),
                    Target::Broken(message) => {
                        broken.push(format!("{path}:{}: broken link {message}", index + 1));
                        Ok(None)
                    }
                });
                out.push(rewritten.unwrap_or_else(|_| text.to_owned()));
            }
            Line::Code(line) => out.push(line.to_owned()),
        }
    }
    (markdown::join(&out), broken)
}

/// The directories of the repository, from its file list.
fn dirs_of(files: &[String]) -> BTreeSet<String> {
    let mut dirs = BTreeSet::new();
    for f in files {
        let mut d = dir_of(f);
        while !d.is_empty() {
            if !dirs.insert(d.to_owned()) {
                break;
            }
            d = dir_of(d);
        }
    }
    dirs
}

/// Builds the staged book in `stage_dir`. Returns the problems found
/// (broken links, missing chapters); the stage is only usable if there are
/// none.
pub fn stage(root: &Path, files: &[String], stage_dir: &Path) -> Result<Vec<String>, String> {
    let book = root.join(BOOK);
    let summary = read(&book.join("src/SUMMARY.md"))?.replace("\r\n", "\n");
    let chapters = summary_chapters(&summary)?;
    let file_set: BTreeSet<&str> = files.iter().map(String::as_str).collect();
    let dirs = dirs_of(files);
    let chapter_set: BTreeSet<&str> = chapters.iter().map(|c| c.source.as_str()).collect();
    let first = chapters.first().map_or("", |c| c.source.as_str());
    let src = stage_dir.join("src");
    let mut problems = Vec::new();
    let mut staged: BTreeMap<String, String> = BTreeMap::new();
    let mut includes: BTreeSet<String> = BTreeSet::new();
    for c in &chapters {
        if !file_set.contains(c.source.as_str()) {
            problems.push(format!(
                "docs/book/src/SUMMARY.md:{}: `{}` is not a file in the repository",
                c.line, c.link
            ));
            continue;
        }
        let text = read(&root.join(&c.source))?.replace("\r\n", "\n");
        let (text, broken) =
            rewrite_chapter(&c.source, &text, &file_set, &dirs, &chapter_set, first);
        problems.extend(broken);
        // Included files are copied next to the chapter's copy, at their
        // repository path, so the relative include still resolves.
        for line in text.lines() {
            let Some(target) = include_target(line) else {
                continue;
            };
            match resolve(dir_of(&c.source), target) {
                Some(included) if file_set.contains(included.as_str()) => {
                    if staged_path(&c.source, first) != c.source {
                        problems.push(format!(
                            "{}: the first chapter and the root README cannot use `{{{{#include}}}}`",
                            c.source
                        ));
                    }
                    includes.insert(included);
                }
                _ => problems.push(format!(
                    "{}: `{{{{#include {target}}}}}`: no such file in the repository",
                    c.source
                )),
            }
        }
        staged.insert(c.source.clone(), text);
    }
    if !problems.is_empty() {
        return Ok(problems);
    }
    for path in includes.iter().filter(|p| !staged.contains_key(*p)) {
        copy(&root.join(path), &src.join(path))?;
    }
    for (path, text) in &staged {
        write(&src.join(staged_path(path, first)), text)?;
    }
    // The SUMMARY, with each link pointing at the staged copy. The
    // generator's marker comments are dropped: mdBook's SUMMARY parser
    // loses the list item next to an HTML comment.
    let mut lines = Vec::new();
    let by_line: BTreeMap<usize, &Chapter> = chapters.iter().map(|c| (c.line, c)).collect();
    for (index, line) in summary.split('\n').enumerate() {
        if line.trim_start().starts_with("<!--") {
            continue;
        }
        match by_line.get(&(index + 1)) {
            Some(c) => lines.push(line.replacen(
                &format!("]({})", c.link),
                &format!("]({})", staged_path(&c.source, first)),
                1,
            )),
            None => lines.push(line.to_owned()),
        }
    }
    write(&src.join("SUMMARY.md"), &lines.join("\n"))?;
    // book.toml and the theme, as they are.
    copy(&book.join("book.toml"), &stage_dir.join("book.toml"))?;
    for path in super::walk_files(&book.join("theme"))? {
        let rel = path
            .strip_prefix(&book)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        copy(&path, &stage_dir.join(rel))?;
    }
    Ok(problems)
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn copy(from: &Path, to: &PathBuf) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("cannot copy {} to {}: {e}", from.display(), to.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_stays_inside_the_repository() {
        assert_eq!(
            resolve("docs/book/src", "../../ci.md").as_deref(),
            Some("docs/ci.md")
        );
        assert_eq!(
            resolve("docs", "./adr/0001.md").as_deref(),
            Some("docs/adr/0001.md")
        );
        assert_eq!(resolve("", "README.md").as_deref(), Some("README.md"));
        assert_eq!(resolve("docs", "../../x"), None);
        assert_eq!(resolve("docs", "/etc/passwd"), None);
    }

    #[test]
    fn summary_chapters_need_repository_files() {
        let s = "# Summary\n\n[Intro](intro.md)\n\n# Part\n\n- [CI](../../ci.md)\n    - [Readme](../../../README.md)\n- [Draft]()\n- [Web](https://x.invalid/a.md)\n- [Toml](../book.toml)\n";
        let e = summary_chapters(s).unwrap_err();
        assert_eq!(e.lines().count(), 3, "{e}");
        let ok = "[Intro](intro.md)\n- [CI](../../ci.md)\n    - [R](../../../README.md)\n";
        let c = summary_chapters(ok).unwrap();
        let sources: Vec<&str> = c.iter().map(|c| c.source.as_str()).collect();
        assert_eq!(
            sources,
            ["docs/book/src/intro.md", "docs/ci.md", "README.md"]
        );
        assert!(summary_chapters("- [A](a.md)\n- [B](./a.md)\n").is_err());
    }

    #[test]
    fn include_targets() {
        assert_eq!(
            include_target("{{#include ../../examples/policies/minimal.yaml}}"),
            Some("../../examples/policies/minimal.yaml")
        );
        assert_eq!(include_target("  {{#include a.rs:anchor}} "), Some("a.rs"));
        assert_eq!(include_target("{{#include a.rs:2:5}}"), Some("a.rs"));
        assert_eq!(include_target("no include"), None);
    }

    #[test]
    fn candidates() {
        for yes in [
            "README.md",
            "docs/ci.md",
            "docs/adr/0001-x.md",
            "crates/palisade-core/README.md",
            "xtask/README.md",
            "crates/palisade-proto/events/REGISTRY.md",
        ] {
            assert!(is_book_candidate(yes), "{yes}");
        }
        for no in [
            "docs/book/src/SUMMARY.md",
            ".github/pull_request_template.md",
            "crates/palisade-core/src/x.md",
            "crates/a/tests/fixtures/x.md",
            "docs/x.yaml",
        ] {
            assert!(!is_book_candidate(no), "{no}");
        }
    }

    #[test]
    fn links_are_kept_redirected_or_reported() {
        let files: Vec<String> = [
            "README.md",
            "docs/adr/README.md",
            "docs/ci.md",
            "docs/adr/0001.md",
            "docs/book/src/intro.md",
            ".github/workflows/ci.yml",
            "LICENSE-MIT",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let set: BTreeSet<&str> = files.iter().map(String::as_str).collect();
        let dirs = dirs_of(&files);
        let chapters: BTreeSet<&str> = [
            "docs/book/src/intro.md",
            "README.md",
            "docs/adr/README.md",
            "docs/ci.md",
            "docs/adr/0001.md",
        ]
        .into_iter()
        .collect();
        let first = "docs/book/src/intro.md";
        let t = |from: &str, dest: &str| {
            target(
                from,
                staged_path(from, first),
                dest,
                &set,
                &dirs,
                &chapters,
                first,
            )
        };
        assert_eq!(t("docs/ci.md", "adr/0001.md#x"), Target::Keep);
        assert_eq!(t("docs/ci.md", "#anchor"), Target::Keep);
        assert_eq!(t("docs/ci.md", "https://example.invalid/"), Target::Keep);
        // README chapters are `index.md`; the root README is staged at
        // ROOT_README; the first chapter is staged at the root.
        assert_eq!(
            t("docs/ci.md", "adr/README.md#a"),
            Target::Replace("adr/index.md#a".to_owned())
        );
        assert_eq!(
            t("docs/ci.md", "../README.md#a"),
            Target::Replace(format!("../{ROOT_README}#a"))
        );
        assert_eq!(
            t("docs/adr/0001.md", "../../README.md"),
            Target::Replace(format!("../../{ROOT_README}"))
        );
        assert_eq!(
            t("README.md", "README.md#b"),
            Target::Replace(format!("{ROOT_README}#b"))
        );
        assert_eq!(
            t("docs/ci.md", "book/src/intro.md"),
            Target::Replace("../intro.md".to_owned())
        );
        assert_eq!(
            t("docs/book/src/intro.md", "../../ci.md#x"),
            Target::Replace("docs/ci.md#x".to_owned())
        );
        assert_eq!(
            t("docs/book/src/intro.md", "../../../README.md"),
            Target::Replace(ROOT_README.to_owned())
        );
        assert_eq!(
            t("docs/ci.md", "../.github/workflows/ci.yml"),
            Target::Replace(format!("{BLOB}.github/workflows/ci.yml"))
        );
        assert_eq!(
            t("README.md", "LICENSE-MIT"),
            Target::Replace(format!("{BLOB}LICENSE-MIT"))
        );
        assert_eq!(
            t("README.md", "docs/adr/"),
            Target::Replace(format!("{TREE}docs/adr"))
        );
        assert_eq!(t("docs/ci.md", "../"), Target::Replace(TREE.to_owned()));
        assert!(matches!(t("docs/ci.md", "nope.md"), Target::Broken(_)));
        assert!(matches!(t("docs/ci.md", "/abs.md"), Target::Broken(_)));
        assert!(matches!(t("docs/ci.md", "../../out.md"), Target::Broken(_)));
        assert!(matches!(t("docs/ci.md", "x.md?y"), Target::Broken(_)));

        let (text, broken) = rewrite_chapter(
            "docs/ci.md",
            "[a](adr/0001.md) [w](../.github/workflows/ci.yml)\n```\n[x](nope.md)\n```\n[b](gone.md)",
            &set,
            &dirs,
            &chapters,
            first,
        );
        assert_eq!(
            text,
            format!(
                "[a](adr/0001.md) [w]({BLOB}.github/workflows/ci.yml)\n```\n[x](nope.md)\n```\n[b](gone.md)"
            )
        );
        assert_eq!(
            broken,
            ["docs/ci.md:5: broken link `gone.md`: no such file or directory (docs/gone.md)"]
        );

        let (text, _) = rewrite_chapter(
            "docs/ci.md",
            "it's\n```mermaid\nA[\"Operator's\"]\n```\n```text\nit's\n```",
            &set,
            &dirs,
            &chapters,
            first,
        );
        assert_eq!(
            text,
            "it's\n```mermaid\nA[\"Operator#39;s\"]\n```\n```text\nit's\n```"
        );
    }

    #[test]
    fn relative_paths() {
        assert_eq!(relative_to("docs", "docs/ci.md"), "ci.md");
        assert_eq!(relative_to("docs/adr", "docs/ci.md"), "../ci.md");
        assert_eq!(relative_to("", "docs/ci.md"), "docs/ci.md");
        assert_eq!(
            relative_to("docs/book/src", "intro.md"),
            "../../../intro.md"
        );
    }
}
