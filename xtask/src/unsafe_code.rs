//! `cargo xtask check-unsafe`: where `unsafe` code may be allowed.
//!
//! The policy is in ADR 0011 (`docs/adr/0011-msrv-and-unsafe-code-policy.md`).
//! The compiler does most of the work: the workspace sets
//! `unsafe_code = "forbid"`, so `unsafe` anywhere fails to build. This check
//! is the second layer, which still holds once the workspace lowers the lint
//! to `deny` for the first FFI module. It fails when:
//!
//! - a Rust file relaxes the `unsafe_code` lint (`allow`, `expect` or `warn`,
//!   as an inner or outer attribute, including inside `cfg_attr`) and is not
//!   listed in `unsafe-allowlist.txt`;
//! - `unsafe-allowlist.txt` lists a file that does not relax the lint, does
//!   not exist, or is outside the locations ADR 0011 allows
//!   ([`ALLOWED_LOCATIONS`]);
//! - a crate in [`FORBID_AT_ROOT`] has a library or binary root without
//!   `#![forbid(unsafe_code)]`;
//! - the root `Cargo.toml` sets `unsafe_code` to anything but `forbid` or
//!   `deny`, or a `.cargo/config.toml` rustflag mentions `unsafe_code` or
//!   `cap-lints`.
//!
//! Every `.rs` file under the repository is scanned, except in `target`,
//! `.git` and `node_modules` directories. Comments and string literals are
//! skipped, so documentation and test fixtures that quote an attribute are
//! not counted. Code generated at build time (for example by a build script
//! into `OUT_DIR`) is not in the repository and is not scanned; the
//! workspace `forbid` still applies to it.

use std::path::Path;

/// Repository-relative path prefixes where ADR 0011 allows a file to relax
/// `unsafe_code`. A prefix ending in `/` covers a directory (a module and its
/// submodules); one ending in `.rs` is a single module file.
pub const ALLOWED_LOCATIONS: &[&str] = &[
    "crates/palisade-agent/src/ffi.rs",
    "crates/palisade-agent/src/ffi/",
    "crates/palisade-tray/src/ffi.rs",
    "crates/palisade-tray/src/ffi/",
    "crates/palisade-fileid/src/win.rs",
    "crates/palisade-fileid/src/win/",
    "crates/palisade-driver/",
];

/// Crates that have no allowlisted module, so ADR 0011 requires
/// `#![forbid(unsafe_code)]` at the root of their library and binaries.
pub const FORBID_AT_ROOT: &[&str] = &[
    "palisade-core",
    "palisade-policy",
    "palisade-proto",
    "palisade-server",
    "palisade-console",
    "palisade-cli",
    "xtask",
];

/// Directory names that are never scanned.
const SKIPPED_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Repository-relative paths (with `/` separators) of every `.rs` file under
/// `root`, sorted.
pub fn rust_files(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
            let name = entry.file_name();
            if file_type.is_dir() {
                if !SKIPPED_DIRS.iter().any(|s| name == *s) {
                    stack.push(path);
                }
            } else if file_type.is_file() && path.extension().is_some_and(|e| e == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let parts: Vec<String> = relative
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                files.push(parts.join("/"));
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Entries of `unsafe-allowlist.txt`: one repository-relative path per line.
/// Blank lines and lines starting with `#` are ignored.
pub fn parse_allowlist(source: &str) -> Vec<String> {
    source
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// Compares the files that relax `unsafe_code` with the allowlist.
/// `files` maps each repository-relative path to its source.
pub fn check_files(files: &[(String, String)], allowlist: &[String]) -> Vec<String> {
    let mut v = Vec::new();
    let relaxing: Vec<&str> = files
        .iter()
        .filter(|(_, source)| relaxes_unsafe_code(source))
        .map(|(path, _)| path.as_str())
        .collect();

    for path in &relaxing {
        if !allowlist.iter().any(|a| a == path) {
            v.push(format!(
                "{path} allows unsafe code but is not listed in unsafe-allowlist.txt (ADR 0011)"
            ));
        }
    }

    let mut seen: Vec<&str> = Vec::new();
    for entry in allowlist {
        if seen.contains(&entry.as_str()) {
            v.push(format!("unsafe-allowlist.txt lists {entry} twice"));
            continue;
        }
        seen.push(entry);
        if !is_allowed_location(entry) {
            v.push(format!(
                "unsafe-allowlist.txt lists {entry}, which is outside the locations ADR 0011 allows: {}",
                ALLOWED_LOCATIONS.join(", ")
            ));
        }
        if !files.iter().any(|(path, _)| path == entry) {
            v.push(format!(
                "unsafe-allowlist.txt lists {entry}, which is not a Rust file in the repository"
            ));
        } else if !relaxing.contains(&entry.as_str()) {
            v.push(format!(
                "unsafe-allowlist.txt lists {entry}, which does not allow unsafe code; remove the entry"
            ));
        }
    }
    v
}

/// `path` is under one of [`ALLOWED_LOCATIONS`].
pub fn is_allowed_location(path: &str) -> bool {
    !path.split('/').any(|part| part == "..")
        && ALLOWED_LOCATIONS.iter().any(|loc| {
            if loc.ends_with('/') {
                path.starts_with(loc)
            } else {
                path == *loc
            }
        })
}

/// `true` when the source has an attribute that relaxes `unsafe_code`.
pub fn relaxes_unsafe_code(source: &str) -> bool {
    attributes(&strip_comments_and_strings(source))
        .iter()
        .any(|a| a.relaxes_unsafe_code())
}

/// `true` when the source has the inner attribute `#![forbid(unsafe_code)]`.
pub fn forbids_unsafe_code(source: &str) -> bool {
    attributes(&strip_comments_and_strings(source))
        .iter()
        .any(|a| a.inner && a.body == "forbid(unsafe_code)")
}

/// The workspace `unsafe_code` level from the root `Cargo.toml` must be
/// `forbid` or `deny`.
pub fn check_workspace_lint(root_manifest: &str) -> Result<Vec<String>, String> {
    let manifest: toml::Table = root_manifest
        .parse()
        .map_err(|e| format!("Cargo.toml: invalid TOML: {e}"))?;
    let level = manifest
        .get("workspace")
        .and_then(|w| w.get("lints"))
        .and_then(|l| l.get("rust"))
        .and_then(|r| r.get("unsafe_code"));
    let level = match level {
        Some(toml::Value::String(s)) => Some(s.as_str()),
        Some(toml::Value::Table(t)) => t.get("level").and_then(toml::Value::as_str),
        _ => None,
    };
    Ok(match level {
        Some("forbid" | "deny") => Vec::new(),
        _ => vec![
            "Cargo.toml: [workspace.lints.rust] unsafe_code must be \"forbid\" or \"deny\" (ADR 0011)"
                .to_owned(),
        ],
    })
}

/// No rustflag in `.cargo/config.toml` may change `unsafe_code` or cap lints.
pub fn check_cargo_config(path: &str, source: &str) -> Vec<String> {
    // A plain text match: any mention outside a comment fails, wherever the
    // flag sits (`[build]`, `[target.*]`, a string or an array).
    let found = source
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .any(|l| l.contains("unsafe_code") || l.contains("cap-lints"));
    if found {
        vec![format!(
            "{path}: rustflags must not change the unsafe_code lint or cap lints"
        )]
    } else {
        Vec::new()
    }
}

/// One attribute: `inner` for `#![...]`, and its body with all whitespace
/// removed, for example `cfg_attr(test,allow(unsafe_code))`.
#[derive(Debug, PartialEq, Eq)]
struct Attribute {
    inner: bool,
    body: String,
}

impl Attribute {
    /// `allow`, `expect` or `warn` together with `unsafe_code` anywhere in
    /// the attribute. This errs on the side of failing: an attribute such
    /// as `cfg_attr(x, deny(unsafe_code), allow(dead_code))` is also counted.
    fn relaxes_unsafe_code(&self) -> bool {
        let idents = identifiers(&self.body);
        idents.contains(&"unsafe_code")
            && idents
                .iter()
                .any(|i| matches!(*i, "allow" | "expect" | "warn"))
    }
}

fn identifiers(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Every `#[...]` and `#![...]` attribute in code that has already had its
/// comments and strings removed.
fn attributes(code: &str) -> Vec<Attribute> {
    let chars: Vec<char> = code.chars().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars.get(i) != Some(&'#') {
            i += 1;
            continue;
        }
        let mut j = skip_whitespace(&chars, i + 1);
        let inner = chars.get(j) == Some(&'!');
        if inner {
            j = skip_whitespace(&chars, j + 1);
        }
        if chars.get(j) != Some(&'[') {
            i += 1;
            continue;
        }
        let mut depth = 0usize;
        let mut body = String::new();
        let mut k = j;
        while let Some(&c) = chars.get(k) {
            match c {
                '[' | '(' | '{' => depth += 1,
                ']' | ')' | '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth == 0 {
                break;
            }
            if k > j && !c.is_whitespace() {
                body.push(c);
            }
            k += 1;
        }
        found.push(Attribute { inner, body });
        i = k + 1;
    }
    found
}

fn skip_whitespace(chars: &[char], mut i: usize) -> usize {
    while chars.get(i).is_some_and(|c| c.is_whitespace()) {
        i += 1;
    }
    i
}

/// Replaces comments, string literals and character literals with spaces,
/// keeping everything else. Handles nested block comments, escapes, byte and
/// C strings, and raw strings with any number of `#`. A `'` that starts a
/// lifetime or label is kept.
fn strip_comments_and_strings(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let at = |i: usize| chars.get(i).copied();
    let mut i = 0;
    while let Some(c) = at(i) {
        // Line comment.
        if c == '/' && at(i + 1) == Some('/') {
            while at(i).is_some_and(|c| c != '\n') {
                i += 1;
            }
            out.push(' ');
            continue;
        }
        // Block comment, possibly nested.
        if c == '/' && at(i + 1) == Some('*') {
            let mut depth = 0usize;
            while let Some(c) = at(i) {
                if c == '/' && at(i + 1) == Some('*') {
                    depth += 1;
                    i += 2;
                } else if c == '*' && at(i + 1) == Some('/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        // Raw string: r"..", r#".."#, br"..", cr"..".
        let prev_is_ident = i > 0 && at(i - 1).is_some_and(|p| p.is_alphanumeric() || p == '_');
        if !prev_is_ident {
            let mut j = i;
            if matches!(at(j), Some('b' | 'c')) && at(j + 1) == Some('r') {
                j += 1;
            }
            if at(j) == Some('r') {
                let mut k = j + 1;
                let mut hashes = 0;
                while at(k) == Some('#') {
                    hashes += 1;
                    k += 1;
                }
                if at(k) == Some('"') {
                    k += 1;
                    loop {
                        match at(k) {
                            None => break,
                            Some('"') if (1..=hashes).all(|h| at(k + h) == Some('#')) => {
                                k += 1 + hashes;
                                break;
                            }
                            Some(_) => k += 1,
                        }
                    }
                    i = k;
                    out.push(' ');
                    continue;
                }
            }
        }
        // Ordinary string, including b"..", c"..".
        if c == '"' {
            i += 1;
            while let Some(c) = at(i) {
                i += 1;
                match c {
                    '\\' => i += 1,
                    '"' => break,
                    _ => {}
                }
            }
            out.push(' ');
            continue;
        }
        // Character literal ('a', '\n', '\u{1F600}', '"'), but not a lifetime.
        if c == '\'' {
            // After a backslash, the escaped character (possibly `'`) is
            // skipped before looking for the closing quote.
            let close = if at(i + 1) == Some('\\') {
                (i + 3..chars.len().min(i + 13)).find(|&k| at(k) == Some('\''))
            } else if at(i + 2) == Some('\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(close) = close {
                i = close + 1;
                out.push(' ');
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, source: &str) -> (String, String) {
        (path.to_owned(), source.to_owned())
    }

    #[test]
    fn every_spelling_of_relaxing_the_lint_is_found() {
        for source in [
            "#![allow(unsafe_code)]",
            "#[allow(unsafe_code)] fn f() {}",
            "#![expect(unsafe_code)]",
            "#![warn(unsafe_code)]",
            "# ! [ allow ( unsafe_code ) ]",
            "#![allow(dead_code, unsafe_code)]",
            "#![cfg_attr(windows, allow(unsafe_code))]",
            "#![cfg_attr(all(windows, not(test)), expect(unsafe_code, reason = \"ffi\"))]",
            "#[allow(\n    unsafe_code\n)]\nmod ffi;",
            "macro_rules! m { () => { #[allow(unsafe_code)] fn g() {} } }",
        ] {
            assert!(relaxes_unsafe_code(source), "{source}");
        }
    }

    #[test]
    fn forbid_deny_and_unrelated_attributes_are_not_relaxing() {
        for source in [
            "#![forbid(unsafe_code)]",
            "#![deny(unsafe_code)]",
            "#![allow(dead_code)]",
            "#[allow(clippy::unwrap_used)] fn unsafe_code() {}",
            "let unsafe_code = 1; #[allow(unused)] fn f() {}",
        ] {
            assert!(!relaxes_unsafe_code(source), "{source}");
        }
    }

    #[test]
    fn comments_and_strings_are_ignored() {
        for source in [
            "// #![allow(unsafe_code)]",
            "/* #![allow(unsafe_code)] */",
            "/* outer /* #![allow(unsafe_code)] */ still comment #![allow(unsafe_code)] */",
            "/// Do not write `#![allow(unsafe_code)]` here.\nfn f() {}",
            "const S: &str = \"#![allow(unsafe_code)]\";",
            "const S: &str = \"escaped \\\" #![allow(unsafe_code)]\";",
            "const S: &str = r#\"#![allow(unsafe_code)] \"still\" inside\"#;",
            "const S: &[u8] = br##\"#![allow(unsafe_code)]\"#\"##;",
            "const S: &[u8] = b\"#![allow(unsafe_code)]\";",
        ] {
            assert!(!relaxes_unsafe_code(source), "{source}");
        }
    }

    #[test]
    fn code_after_strings_chars_and_lifetimes_is_still_scanned() {
        for source in [
            "const S: &str = \"x\"; #![allow(unsafe_code)]",
            "const S: &str = r#\"x\"#; #![allow(unsafe_code)]",
            "const C: char = '\"'; #![allow(unsafe_code)]",
            "const C: char = '\\''; #![allow(unsafe_code)]",
            "fn f<'a>(x: &'a str) -> &'a str { x } #[allow(unsafe_code)] fn g() {}",
            "fn f() { 'outer: loop { break 'outer; } } #[allow(unsafe_code)] fn g() {}",
            "let ident_r = 1; let br = 2; #[allow(unsafe_code)] fn g() {}",
        ] {
            assert!(relaxes_unsafe_code(source), "{source}");
        }
    }

    #[test]
    fn root_forbid_is_recognised() {
        assert!(forbids_unsafe_code("//! Docs\n#![forbid( unsafe_code )]\n"));
        assert!(!forbids_unsafe_code("#![deny(unsafe_code)]"));
        assert!(!forbids_unsafe_code("#[forbid(unsafe_code)] mod m {}"));
        assert!(!forbids_unsafe_code("// #![forbid(unsafe_code)]"));
    }

    #[test]
    fn unlisted_relaxing_file_fails() {
        let files = [file(
            "crates/palisade-core/src/lib.rs",
            "#![allow(unsafe_code)]",
        )];
        let v = check_files(&files, &[]);
        assert_eq!(
            v,
            [
                "crates/palisade-core/src/lib.rs allows unsafe code but is not listed in unsafe-allowlist.txt (ADR 0011)"
            ]
        );
    }

    #[test]
    fn listed_file_in_an_allowed_location_passes() {
        let files = [
            file(
                "crates/palisade-agent/src/ffi/etw.rs",
                "#![allow(unsafe_code)]",
            ),
            file("crates/palisade-agent/src/lib.rs", "mod ffi;"),
        ];
        let allowlist = parse_allowlist("# comment\n\ncrates/palisade-agent/src/ffi/etw.rs\n");
        assert_eq!(check_files(&files, &allowlist), Vec::<String>::new());
    }

    #[test]
    fn listing_a_file_outside_the_allowed_locations_fails() {
        let files = [file(
            "crates/palisade-policy/src/lib.rs",
            "#![allow(unsafe_code)]",
        )];
        let allowlist = parse_allowlist("crates/palisade-policy/src/lib.rs");
        let v = check_files(&files, &allowlist);
        assert_eq!(v.len(), 1);
        assert!(
            v[0].contains("outside the locations ADR 0011 allows"),
            "{v:?}"
        );
    }

    #[test]
    fn stale_missing_and_duplicate_entries_fail() {
        let files = [file("crates/palisade-driver/src/lib.rs", "#![no_std]")];
        let allowlist = parse_allowlist(
            "crates/palisade-driver/src/lib.rs\ncrates/palisade-driver/src/gone.rs\ncrates/palisade-driver/src/lib.rs\n",
        );
        let v = check_files(&files, &allowlist);
        assert_eq!(v.len(), 3, "{v:?}");
        assert!(v[0].ends_with("does not allow unsafe code; remove the entry"));
        assert!(v[1].ends_with("is not a Rust file in the repository"));
        assert!(v[2].ends_with("twice"));
    }

    #[test]
    fn allowed_locations_match_modules_not_lookalikes() {
        assert!(is_allowed_location("crates/palisade-agent/src/ffi.rs"));
        assert!(is_allowed_location("crates/palisade-agent/src/ffi/mod.rs"));
        assert!(is_allowed_location(
            "crates/palisade-fileid/src/win/catalog.rs"
        ));
        assert!(is_allowed_location("crates/palisade-driver/src/lib.rs"));
        assert!(!is_allowed_location(
            "crates/palisade-agent/src/ffi_helpers.rs"
        ));
        assert!(!is_allowed_location("crates/palisade-agent/src/lib.rs"));
        assert!(!is_allowed_location(
            "crates/palisade-driver/../palisade-core/src/lib.rs"
        ));
    }

    #[test]
    fn workspace_lint_must_be_forbid_or_deny() {
        let check = |s: &str| check_workspace_lint(s).unwrap().len();
        assert_eq!(check("[workspace.lints.rust]\nunsafe_code = \"forbid\""), 0);
        assert_eq!(check("[workspace.lints.rust]\nunsafe_code = \"deny\""), 0);
        assert_eq!(
            check("[workspace.lints.rust]\nunsafe_code = { level = \"deny\", priority = 1 }"),
            0
        );
        assert_eq!(check("[workspace.lints.rust]\nunsafe_code = \"warn\""), 1);
        assert_eq!(check("[workspace.lints.rust]\nmissing_docs = \"warn\""), 1);
    }

    #[test]
    fn cargo_config_must_not_relax_lints() {
        assert!(check_cargo_config("c", "[alias]\nxtask = \"run -p xtask --\"").is_empty());
        assert!(check_cargo_config("c", "# -A unsafe_code is not allowed").is_empty());
        assert_eq!(
            check_cargo_config("c", "[build]\nrustflags = [\"-A\", \"unsafe_code\"]").len(),
            1
        );
        assert_eq!(
            check_cargo_config("c", "[build]\nrustflags = [\"--cap-lints=warn\"]").len(),
            1
        );
    }

    #[test]
    fn this_repository_passes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let paths = rust_files(&root).unwrap();
        assert!(paths.iter().any(|p| p == "xtask/src/unsafe_code.rs"));
        assert!(!paths.iter().any(|p| p.starts_with("target/")));
        let files: Vec<(String, String)> = paths
            .into_iter()
            .map(|p| {
                let source = std::fs::read_to_string(root.join(&p)).unwrap();
                (p, source)
            })
            .collect();
        let allowlist =
            parse_allowlist(&std::fs::read_to_string(root.join("unsafe-allowlist.txt")).unwrap());
        assert_eq!(check_files(&files, &allowlist), Vec::<String>::new());
    }
}
