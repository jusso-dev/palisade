//! `cargo xtask help` and `cargo xtask <command> --help` (#29).
//!
//! [`TEXT`] is the one source of the command list. Each entry in it is one
//! command's usage line (and any continuation lines), then its description
//! indented to [`DESCRIPTION_INDENT`]. [`entries`] splits it into
//! [`Entry`]s, and [`for_args`] picks the ones a `--help` request names, so a
//! command's own help can never disagree with the list. Unit tests snapshot
//! the list and every command's help (`src/snapshots/`).

/// The full help, printed by `cargo xtask help`.
pub const TEXT: &str = "\
Usage: cargo xtask <command>

Commands:
  adr new \"<title>\"
                   Copy docs/adr/0000-template.md to the next ADR number, as `proposed`
  adr index        Regenerate the ADR index table in docs/adr/README.md
  adr lint         Check every ADR's file name, number, status, date and sections (Security
                   impact included), supersession links, and that the index is current
  audit            Run cargo-audit over the root and fuzz lockfiles, ignoring exactly the
                   advisories deny.toml ignores
  ci [--fast]      Run the checks from .github/workflows/ci.yml locally (--fast skips coverage,
                   fuzz, docs, the book build, feature-powerset, msrv, package, sign-test and
                   server-image)
  bench-compare --base <commit>
                   Run every criterion bench at <commit> and at the working tree, and fail if a
                   median is more than 10% slower outside the noise (bench.yml)
  check-commit-msg <file>
                   Check a commit message file against Conventional Commits (the
                   opt-in commit-msg hook in .githooks/ runs this)
  check-banned-terms [--digest <term>]
                   No commercial vendor or product names in any file or path
                   (docs/banned-terms.txt, docs/NAMING.md); --digest prints a list line
  check-deps       Enforce the allowed dependency directions between crates
  check-fuzz-locks Check that every crates/*/fuzz/Cargo.lock is current (cargo metadata --locked)
  check-testdata   Fail if any file in the repository that starts like an executable (MZ) is not
                   allowlisted in testdata/manifest.txt
  check-manifests  Enforce workspace inheritance of package fields, lints and dependency versions,
                   and that every crate README documents its features
  check-supply-chain
                   Enforce the duplicate-version budget, deny.toml ignore expiry and reasons,
                   the cargo-vet criteria and exemption notes, and no audit.toml
  check-unsafe     Enforce the unsafe-code allowlist (unsafe-allowlist.txt, ADR 0011)
  dist [--target <triple>] [--msi] [--sign <signer>] [--out <dir>] [--bump-patch]
       [--compare-sizes <sizes.json>] [--from <dir>] [--no-timestamp]
                   Release-build the Windows binaries (with --msi, the installer package) or the
                   Linux server, with symbols and size reports, as CI does (docs/packaging.md)
  dist driver      Explain how the optional kernel driver is packaged (local-only, #8)
  sign --signer <none|test-ca|pfx|cloud-hsm> [--verify] [--no-timestamp] <file>...
                   Authenticode-sign and verify files (docs/releasing.md#code-signing)
  release <prepare|check-tag|notes|checksums|verify-checksums|provenance|verify> ...
                   The release pipeline's steps (docs/releasing.md)
  docs generate    Regenerate the reference pages in docs/book/src/reference/generated
  docs check       Fail if the generated pages are stale, or a doc page is not in the book,
                   is not accessible, or has an untested example
  docs build [--site-url <path>]
                   Build the book into target/book (warnings are errors), then check every
                   internal link; needs mdbook, mdbook-mermaid-ssr, a headless browser and lychee
  docs serve [--port <n>] [--open]
                   Stage the book and serve it at http://127.0.0.1:3000/ with mdbook serve, until
                   interrupted; run it again after editing a page (links are checked by docs build)
  docs assemble <dir> --version <latest|vX.Y>
                   Assemble the GitHub Pages tree: the book and the Rust API docs under
                   <dir>/<version>/, the version list and the root redirect
  docs version-for-ref <git ref>
                   Print the docs version for a ref: latest for main, vX.Y for tag vX.Y.Z
  deps-report [--base <commit>]
                   Print the dependency report: duplicates, third-party crates per crate,
                   third-party unsafe counts and code that runs at build time; with --base,
                   only when Cargo.lock changed, adding cargo tree -d and unsafe changes
  sbom             Reserved for the SBOM (#226); prints where it will be written and fails
  check-workflows  Enforce the CI runner and action policy for .github/workflows,
                   and that nothing under .github names a cloud-managed build service
  threat-coverage  Check the threat model's tables, and that every test, fuzz target and CI
                   check it cites exists (docs/security/threat-model.md)
  test-summary <label> <junit.xml>
                   Summarise a nextest JUnit report for the GitHub job page
  coverage-summary <label> <coverage.json>
                   Summarise a cargo-llvm-cov JSON summary for the GitHub job page
  coverage-gate --base <commit>
                   Fail if palisade-policy line coverage is lower than at <commit>; needs
                   cargo-llvm-cov and cargo-nextest
  fixtures         Build the generated test fixture corpus into target/fixtures/
  golden [--update]
                   Check the corpus's hashes against testdata/golden/fixtures.txt, or rewrite it
  fuzz [--seconds N] [--target NAME | --shard I/N]
                   Build every cargo-fuzz target, seed it from the test fixtures and run it for
                   N seconds (default 60), or only NAME, or only every N-th target starting at
                   index I (as CI's shards do); needs the pinned nightly and cargo-fuzz
  help             Show this message
";

/// The column every description line starts at.
pub const DESCRIPTION_INDENT: usize = 19;

/// One command in [`TEXT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The command's words, without arguments: `["adr", "new"]`.
    pub key: Vec<String>,
    /// The usage, its continuation lines joined with a newline.
    pub usage: String,
    /// The description lines, without their indent.
    pub description: Vec<String>,
}

impl Entry {
    /// The help `cargo xtask <command> --help` prints for this entry.
    pub fn render(&self) -> String {
        let mut out = format!("Usage: cargo xtask {}\n\n", self.usage);
        for line in &self.description {
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

/// The leading words of a usage line that name the command: every word up
/// to the first argument (`<x>`, `[x]`, `"x"`, `--x` or `...`).
fn command_words(usage: &str) -> Vec<String> {
    usage
        .split_whitespace()
        .take_while(|w| {
            !w.starts_with(['<', '[', '"', '-', '.'])
                && w.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        })
        .map(str::to_owned)
        .collect()
}

/// Every command in [`TEXT`], in order. `Err` if the text does not have
/// the layout described in the module documentation.
pub fn entries() -> Result<Vec<Entry>, String> {
    let body = TEXT
        .split_once("\nCommands:\n")
        .map(|(_, b)| b)
        .ok_or("the help text has no `Commands:` line")?;
    let mut out: Vec<Entry> = Vec::new();
    let indent = " ".repeat(DESCRIPTION_INDENT);
    for line in body.lines() {
        if let Some(text) = line.strip_prefix(&indent) {
            let entry = out
                .last_mut()
                .ok_or_else(|| format!("a description before any command: `{line}`"))?;
            entry.description.push(text.trim_end().to_owned());
        } else if let Some(text) = line.strip_prefix("  ").filter(|t| !t.starts_with(' ')) {
            // A usage line, with the description on the same line if the
            // usage is short enough.
            let (usage, description) = match (
                text.get(..DESCRIPTION_INDENT - 2),
                text.get(DESCRIPTION_INDENT - 2..),
            ) {
                (Some(u), Some(d)) if !d.is_empty() && !d.starts_with(' ') && u.ends_with(' ') => {
                    (u.trim_end(), Some(d))
                }
                _ => (text.trim_end(), None),
            };
            let key = command_words(usage);
            if key.is_empty() {
                return Err(format!("a usage line with no command: `{line}`"));
            }
            out.push(Entry {
                key,
                usage: usage.to_owned(),
                description: description
                    .map(|d| vec![d.trim_end().to_owned()])
                    .unwrap_or_default(),
            });
        } else if let Some(more) = line.strip_prefix("       ") {
            // A usage continuation line (`dist`'s second line).
            let entry = out
                .last_mut()
                .filter(|e| e.description.is_empty())
                .ok_or_else(|| format!("a usage continuation out of place: `{line}`"))?;
            entry.usage.push_str("\n       ");
            entry.usage.push_str(more.trim_end());
        } else if !line.trim().is_empty() {
            return Err(format!("an unexpected help line: `{line}`"));
        }
    }
    if let Some(e) = out.iter().find(|e| e.description.is_empty()) {
        return Err(format!("`{}` has no description", e.usage));
    }
    Ok(out)
}

/// What a command line asks for help with: `None` if it does not ask
/// (no `--help` or `-h` after the first word), `Some(Err(_))` for a
/// command that does not exist, and otherwise the entries to print.
///
/// The command is the leading words before the first flag or argument. The
/// longest leading run of them that some entry's key starts with decides:
/// `docs --help` prints every `docs` command, `dist --help` both `dist`
/// entries, and `adr new "<title>" --help` only `adr new`.
pub fn for_args(args: &[String]) -> Option<Result<Vec<Entry>, String>> {
    let (first, rest) = args.split_first()?;
    if !rest.iter().any(|a| a == "--help" || a == "-h") {
        return None;
    }
    let words: Vec<&str> = std::iter::once(first.as_str())
        .chain(rest.iter().map(String::as_str))
        .take_while(|w| !w.starts_with('-'))
        .collect();
    let all = match entries() {
        Ok(all) => all,
        Err(e) => return Some(Err(e)),
    };
    for n in (1..=words.len()).rev() {
        let prefix = words.get(..n).unwrap_or_default();
        let found: Vec<Entry> = all
            .iter()
            .filter(|e| e.key.len() >= n && e.key.iter().zip(prefix).all(|(k, w)| k == w))
            .cloned()
            .collect();
        if !found.is_empty() {
            return Some(Ok(found));
        }
    }
    Some(Err(format!("unknown command `{first}`")))
}

/// The help for `entries`, one after another with a blank line between.
pub fn render(entries: &[Entry]) -> String {
    entries
        .iter()
        .map(Entry::render)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn keys(result: Option<Result<Vec<Entry>, String>>) -> Vec<String> {
        result
            .unwrap()
            .unwrap()
            .iter()
            .map(|e| e.key.join(" "))
            .collect()
    }

    #[test]
    fn the_command_list_parses_into_unique_entries() {
        let all = entries().unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for e in &all {
            assert!(seen.insert(e.key.clone()), "duplicate {:?}", e.key);
            assert!(!e.description.is_empty(), "{:?}", e.key);
            assert!(e.usage.starts_with(&e.key.join(" ")), "{:?}", e.key);
        }
        // Spot checks of the layout: a usage on its own line, one with
        // the description beside it, and a two-line usage.
        let find = |k: &str| all.iter().find(|e| e.key.join(" ") == k).unwrap();
        assert_eq!(find("adr new").usage, "adr new \"<title>\"");
        assert_eq!(find("ci").usage, "ci [--fast]");
        assert_eq!(find("ci").description.len(), 3);
        assert!(find("dist").usage.contains("\n       [--compare-sizes"));
        assert_eq!(find("check-fuzz-locks").usage, "check-fuzz-locks");
        assert_eq!(all.len(), 35);
    }

    /// Every command `main` dispatches on, as the string literal it
    /// compares the first argument with.
    fn dispatched_commands() -> std::collections::BTreeSet<String> {
        // A Windows checkout may have CRLF line endings, so normalise
        // before splitting on "\n" patterns.
        let main = include_str!("main.rs").replace("\r\n", "\n");
        let body = main
            .split_once("fn main() -> ExitCode {")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(b, _)| b)
            .unwrap();
        let mut out = std::collections::BTreeSet::new();
        for (marker, end) in [("command == \"", '"'), ("\n        \"", '"')] {
            for piece in body.split(marker).skip(1) {
                if let Some((word, _)) = piece.split_once(end)
                    && !word.is_empty()
                    && word.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                {
                    out.insert(word.to_owned());
                }
            }
        }
        out
    }

    #[test]
    fn every_dispatched_command_has_help() {
        let first_words: std::collections::BTreeSet<String> = entries()
            .unwrap()
            .into_iter()
            .map(|e| e.key[0].clone())
            .collect();
        let dispatched = dispatched_commands();
        assert!(dispatched.len() > 25, "{dispatched:?}");
        for command in &dispatched {
            assert!(
                first_words.contains(command),
                "`{command}` has no help entry"
            );
        }
        for command in &first_words {
            assert!(
                dispatched.contains(command),
                "`{command}` is in the help but not dispatched"
            );
        }
    }

    #[test]
    fn the_command_list_is_snapshotted() {
        insta::assert_snapshot!("help", TEXT);
    }

    #[test]
    fn every_command_help_is_snapshotted() {
        for e in entries().unwrap() {
            let request: Vec<String> = e
                .key
                .iter()
                .cloned()
                .chain(std::iter::once("--help".to_owned()))
                .collect();
            // The help a request for exactly this command prints: the
            // entry itself, and any longer command it is a prefix of.
            let printed = render(&for_args(&request).unwrap().unwrap());
            assert!(printed.starts_with(&e.render()), "{:?}", e.key);
            insta::assert_snapshot!(format!("help_{}", e.key.join("_")), printed);
        }
    }

    #[test]
    fn help_requests_are_parsed() {
        // Not a help request.
        assert!(for_args(&[]).is_none());
        assert!(for_args(&args(&["fuzz"])).is_none());
        assert!(for_args(&args(&["fuzz", "--seconds", "5"])).is_none());
        assert!(
            for_args(&args(&["--help"])).is_none(),
            "the top level is `help`"
        );
        // One command, with `--help` or `-h`, anywhere after it.
        assert_eq!(keys(for_args(&args(&["fuzz", "--help"]))), ["fuzz"]);
        assert_eq!(keys(for_args(&args(&["fuzz", "-h"]))), ["fuzz"]);
        assert_eq!(
            keys(for_args(&args(&["fuzz", "--seconds", "5", "--help"]))),
            ["fuzz"]
        );
        assert_eq!(
            keys(for_args(&args(&["check-commit-msg", "msg.txt", "--help"]))),
            ["check-commit-msg"]
        );
        // A group, a command with a sub-command, and a sub-command.
        assert_eq!(
            keys(for_args(&args(&["docs", "--help"]))),
            [
                "docs generate",
                "docs check",
                "docs build",
                "docs serve",
                "docs assemble",
                "docs version-for-ref"
            ]
        );
        assert_eq!(
            keys(for_args(&args(&["dist", "--help"]))),
            ["dist", "dist driver"]
        );
        assert_eq!(
            keys(for_args(&args(&["dist", "driver", "-h"]))),
            ["dist driver"]
        );
        assert_eq!(
            keys(for_args(&args(&["adr", "new", "A title", "--help"]))),
            ["adr new"]
        );
        assert_eq!(
            keys(for_args(&args(&[
                "docs",
                "build",
                "--site-url",
                "/x",
                "--help"
            ]))),
            ["docs build"]
        );
        // An unknown command, or an unknown sub-command of a known one.
        assert_eq!(
            for_args(&args(&["no-such", "--help"])).unwrap(),
            Err("unknown command `no-such`".to_owned())
        );
        assert_eq!(
            keys(for_args(&args(&["adr", "nope", "--help"]))),
            ["adr new", "adr index", "adr lint"]
        );
    }

    #[test]
    fn command_words_stop_at_the_first_argument() {
        for (usage, words) in [
            ("ci [--fast]", vec!["ci"]),
            ("adr new \"<title>\"", vec!["adr", "new"]),
            ("release <prepare|notes> ...", vec!["release"]),
            ("sign --signer <x> <file>...", vec!["sign"]),
            (
                "docs version-for-ref <git ref>",
                vec!["docs", "version-for-ref"],
            ),
            ("check-fuzz-locks", vec!["check-fuzz-locks"]),
        ] {
            assert_eq!(command_words(usage), words, "{usage}");
        }
    }
}
