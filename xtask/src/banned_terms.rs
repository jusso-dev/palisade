//! `cargo xtask check-banned-terms`: no commercial vendor or product names
//! anywhere in the repository (`docs/NAMING.md`, #27).
//!
//! The list is [`LIST_PATH`]. It holds SHA-256 digests rather than the
//! names, so the repository never contains the words it bans (the same
//! approach as the service names in `check-workflows`). Each line is one of:
//!
//! - `term <length> <sha256>`: a banned term. The term is lowercase ASCII
//!   letters, digits and single spaces, and the digest is of exactly that
//!   text. `cargo xtask check-banned-terms --digest "<term>"` prints the
//!   line to add.
//! - `allow <path> <reason>`: the tracked file at `path` (relative to the
//!   repository root) is not scanned. It is for the rare file that must
//!   contain an identifier the operating system requires, such as a fixed
//!   XML namespace. The path must exist, and the reason must not be empty.
//! - blank lines and lines starting with `#`.
//!
//! Every tracked and untracked-but-not-ignored file is scanned, and so is
//! every path. Matching is case-insensitive and by whole words: text is
//! split into words (runs of ASCII letters and digits; anything else,
//! including `_`, `-`, `.` and `/`, ends a word), and a term of `n` words
//! matches `n` consecutive words that are separated by spaces only. A
//! word that merely contains a term, such as `central`, does not match.
//! `_` and `-` split words so that identifiers like `the_name_here` or
//! `the-name` are still caught. A file that is not UTF-8 is scanned as
//! bytes, and the non-ASCII bytes end words.

use std::collections::BTreeSet;
use std::path::Path;

use sha2::{Digest as _, Sha256};

/// The list of banned terms, relative to the repository root.
pub const LIST_PATH: &str = "docs/banned-terms.txt";

/// The parsed [`LIST_PATH`].
#[derive(Debug, Default)]
pub struct List {
    /// `(length in bytes, lowercase hex SHA-256)` of each term.
    pub terms: Vec<(usize, String)>,
    /// Paths that are not scanned, with the line they were allowed on.
    pub allowed: Vec<(String, usize)>,
}

/// Parses [`LIST_PATH`]. Errors name the line.
pub fn parse_list(source: &str) -> Result<List, Vec<String>> {
    let mut list = List::default();
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, line) in source.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = format!("{LIST_PATH}:{number}");
        let mut fields = line.splitn(3, ' ');
        match (fields.next(), fields.next(), fields.next()) {
            (Some("term"), Some(length), Some(digest)) => {
                let Ok(length) = length.parse::<usize>() else {
                    errors.push(format!("{at}: `{length}` is not a term length"));
                    continue;
                };
                let is_hex = digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
                if !is_hex || length == 0 {
                    errors.push(format!(
                        "{at}: expected `term <length> <64 lowercase hex digits>`"
                    ));
                } else if !seen.insert(digest.to_owned()) {
                    errors.push(format!("{at}: duplicate term"));
                } else {
                    list.terms.push((length, digest.to_owned()));
                }
            }
            (Some("allow"), Some(path), Some(reason)) if !reason.trim().is_empty() => {
                list.allowed.push((path.to_owned(), number));
            }
            (Some("allow"), _, _) => {
                errors.push(format!("{at}: expected `allow <path> <reason>`"));
            }
            _ => errors.push(format!(
                "{at}: expected `term <length> <sha256>` or `allow <path> <reason>`"
            )),
        }
    }
    if list.terms.is_empty() {
        errors.push(format!("{LIST_PATH}: no terms"));
    }
    if errors.is_empty() {
        Ok(list)
    } else {
        Err(errors)
    }
}

/// The `term` line for `term`, or an error if it is not in the canonical
/// form (lowercase ASCII letters and digits, words separated by one space).
pub fn digest_line(term: &str) -> Result<String, String> {
    let canonical = term
        .split(' ')
        .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_alphanumeric()))
        && !term.bytes().any(|b| b.is_ascii_uppercase());
    if !canonical {
        return Err(format!(
            "`{term}` must be lowercase ASCII letters and digits, with single spaces between words"
        ));
    }
    Ok(format!(
        "term {} {}",
        term.len(),
        sha256_hex(term.as_bytes())
    ))
}

/// Byte offsets `(start, end)` of every word of `text`, lowercase.
fn words(text: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, b) in text.iter().enumerate() {
        match (b.is_ascii_alphanumeric(), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, text.len()));
    }
    out
}

/// Every banned term in `text`, as the 1-based line of its start. A term
/// is reported once per line.
pub fn find(text: &[u8], terms: &[(usize, String)]) -> Vec<usize> {
    if terms.is_empty() {
        return Vec::new();
    }
    let lower = text.to_ascii_lowercase();
    let lengths: BTreeSet<usize> = terms.iter().map(|(len, _)| *len).collect();
    let digests: BTreeSet<&str> = terms.iter().map(|(_, d)| d.as_str()).collect();
    let max_len = lengths.iter().copied().max().unwrap_or(0);
    let words = words(&lower);
    let mut lines = BTreeSet::new();
    for (i, &(start, _)) in words.iter().enumerate() {
        // Extend over following words while only single spaces separate
        // them, and test each span whose length is a term length.
        let mut end = words[i].1;
        let mut j = i;
        loop {
            let len = end - start;
            if len > max_len {
                break;
            }
            if lengths.contains(&len) && digests.contains(sha256_hex(&lower[start..end]).as_str()) {
                let line = 1 + lower[..start].iter().filter(|&&b| b == b'\n').count();
                lines.insert(line);
            }
            match words.get(j + 1) {
                Some(&(next, next_end)) if next == end + 1 && lower[end] == b' ' => {
                    end = next_end;
                    j += 1;
                }
                _ => break,
            }
        }
    }
    lines.into_iter().collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Checks the paths and contents of `files` (repository-relative) under
/// `root` against the list.
pub fn check(root: &Path, files: &[String], list: &List) -> Result<Vec<String>, String> {
    let mut violations = Vec::new();
    let tracked: BTreeSet<&str> = files.iter().map(String::as_str).collect();
    let mut allowed = BTreeSet::new();
    for (path, line) in &list.allowed {
        if tracked.contains(path.as_str()) {
            allowed.insert(path.as_str());
        } else {
            violations.push(format!(
                "{LIST_PATH}:{line}: `allow {path}`: no such file in the repository"
            ));
        }
    }
    for path in files {
        if !find(path.as_bytes(), &list.terms).is_empty() {
            violations.push(format!(
                "{path}: the path contains a banned term (docs/NAMING.md)"
            ));
        }
        if allowed.contains(path.as_str()) {
            continue;
        }
        let bytes =
            std::fs::read(root.join(path)).map_err(|e| format!("cannot read {path}: {e}"))?;
        for line in find(&bytes, &list.terms) {
            violations.push(format!(
                "{path}:{line}: banned vendor or product name; use the neutral term from docs/NAMING.md"
            ));
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_of(terms: &[&str]) -> List {
        let source: String = terms
            .iter()
            .map(|t| digest_line(t).unwrap() + "\n")
            .collect();
        parse_list(&source).unwrap()
    }

    #[test]
    fn whole_words_match_case_insensitively() {
        let list = list_of(&["acme", "big corp"]);
        assert_eq!(find(b"uses Acme today", &list.terms), [1]);
        assert_eq!(find(b"one\nACME\n", &list.terms), [2]);
        assert_eq!(find(b"a Big Corp product", &list.terms), [1]);
        // Identifier and path separators end words, so these are caught.
        for text in [
            "the_acme_driver",
            "acme-agent",
            "c:\\acme\\x",
            "acme.exe",
            "(acme)",
        ] {
            assert_eq!(find(text.as_bytes(), &list.terms), [1], "{text}");
        }
    }

    #[test]
    fn words_that_contain_a_term_do_not_match() {
        let list = list_of(&["entr", "acme", "big corp"]);
        for text in [
            "central",
            "entrance",
            "acmes",
            "macme",
            "acme2",
            "bigcorp",
            "big  corp",
            "big\ncorp",
            "big-corp",
        ] {
            assert!(find(text.as_bytes(), &list.terms).is_empty(), "{text}");
        }
    }

    #[test]
    fn each_line_is_reported_once() {
        let list = list_of(&["acme"]);
        assert_eq!(find(b"acme acme\nno\nacme", &list.terms), [1, 3]);
    }

    #[test]
    fn non_utf8_bytes_end_words() {
        let list = list_of(&["acme"]);
        assert_eq!(find(b"\xffacme\xfe", &list.terms), [1]);
        assert!(find(b"\xffacmex", &list.terms).is_empty());
    }

    #[test]
    fn digest_line_needs_the_canonical_form() {
        assert!(digest_line("big corp").is_ok());
        for bad in ["Acme", "big  corp", " acme", "acme ", "ac-me", ""] {
            assert!(digest_line(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            digest_line("abc").unwrap(),
            "term 3 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn list_errors_name_the_line() {
        let source = "# comment\n\nterm x abc\nterm 3 xyz\nallow docs/x.md\nbogus\n";
        let errors = parse_list(source).unwrap_err();
        assert_eq!(errors.len(), 5, "{errors:#?}");
        assert!(errors[0].starts_with("docs/banned-terms.txt:3:"));
        assert!(errors[1].starts_with("docs/banned-terms.txt:4:"));
        assert!(errors[2].starts_with("docs/banned-terms.txt:5:"));
        assert!(errors[3].starts_with("docs/banned-terms.txt:6:"));
        assert!(errors[4].ends_with("no terms"));
        let dup = format!("{0}\n{0}\n", digest_line("acme").unwrap());
        assert!(parse_list(&dup).unwrap_err()[0].ends_with("duplicate term"));
    }

    fn scratch(name: &str, files: &[(&str, &[u8])]) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("palisade-banned-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (path, body) in files {
            let path = dir.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        dir
    }

    #[test]
    fn check_reports_contents_paths_and_stale_allows() {
        let dir = scratch(
            "check",
            &[
                ("ok.md", b"central"),
                ("bad.md", b"x\nAcme y"),
                ("acme/readme.md", b"fine"),
                ("allowed.rs", b"acme"),
            ],
        );
        let mut list = list_of(&["acme"]);
        list.allowed = vec![("allowed.rs".to_owned(), 7), ("gone.rs".to_owned(), 8)];
        let files: Vec<String> = ["ok.md", "bad.md", "acme/readme.md", "allowed.rs"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let v = check(&dir, &files, &list).unwrap();
        assert_eq!(v.len(), 3, "{v:#?}");
        assert!(v[0].starts_with("docs/banned-terms.txt:8: `allow gone.rs`"));
        assert!(v[1].starts_with("bad.md:2: banned"));
        assert!(v[2].starts_with("acme/readme.md: the path"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The committed list parses, and the repository passes it.
    #[test]
    fn this_repository_passes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let source = std::fs::read_to_string(root.join(LIST_PATH)).unwrap();
        let list = parse_list(&source).unwrap();
        // The two service names `check-workflows` blocks are on the list too.
        for (len, digest) in crate::workflows::FORBIDDEN_TERM_DIGESTS {
            assert!(
                list.terms.iter().any(|(l, d)| l == len && d == digest),
                "{LIST_PATH} must include every FORBIDDEN_TERM_DIGESTS entry"
            );
        }
        // A source archive without git metadata cannot list tracked files;
        // `cargo xtask check-banned-terms` still fails closed there.
        if !root.join(".git").exists() {
            return;
        }
        let (files, _) = crate::unsafe_code::repository_files(&root).unwrap();
        let violations = check(&root, &files, &list).unwrap();
        assert!(violations.is_empty(), "{violations:#?}");
    }
}
