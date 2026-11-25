//! `cargo xtask coverage-gate --base <commit>`: `palisade-policy` line
//! coverage must not decrease.
//!
//! #25 makes coverage a report, not a gate, with one exception: line
//! coverage of the policy engine may not go down. This measures the crate's
//! own tests at the base commit (in a temporary git worktree) and at the
//! working tree, in the same job and the same way, and fails if the
//! percentage of covered lines dropped.
//!
//! Both runs set a fixed `PROPTEST_RNG_SEED`, so property tests generate the
//! same cases on every run and coverage is reproducible for a given commit.

use std::path::Path;
use std::process::Command;

use crate::coverage::{self, Count};

/// The crate whose line coverage may not decrease.
pub const CRATE: &str = "palisade-policy";

/// The proptest seed both runs use.
pub const PROPTEST_SEED: &str = "25";

/// The result of comparing base and head line coverage.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Coverage stayed the same or went up.
    Kept,
    /// Coverage went down.
    Decreased,
}

/// Compares two line counts as fractions, exactly: `head` passes when
/// `head.covered / head.count >= base.covered / base.count`. A crate with
/// no lines at the base cannot decrease; one with no lines at head (while
/// the base had some) has decreased.
pub fn compare(base: Count, head: Count) -> Verdict {
    if base.count == 0 || base.covered == 0 {
        return Verdict::Kept;
    }
    if head.count == 0 {
        return Verdict::Decreased;
    }
    let base_covered = u128::from(base.covered.min(base.count));
    let head_covered = u128::from(head.covered.min(head.count));
    if head_covered * u128::from(base.count) >= base_covered * u128::from(head.count) {
        Verdict::Kept
    } else {
        Verdict::Decreased
    }
}

/// The lines of [`CRATE`] in a coverage summary taken in `root`.
pub fn crate_lines(json: &str, root: &Path) -> Result<Count, String> {
    let report = coverage::parse(json, &root.to_string_lossy())?;
    report
        .crates
        .get(CRATE)
        .map(|c| c.lines)
        .ok_or_else(|| format!("{CRATE} is not in the coverage report"))
}

/// The Markdown summary and, on a decrease, one `::error` annotation.
pub fn report(base_commit: &str, base: Count, head: Count) -> (String, Option<String>) {
    let verdict = compare(base, head);
    let markdown = format!(
        "### Coverage gate: `{CRATE}`\n\n| | Lines |\n|---|---|\n| Base (`{}`) | {} ({}/{}) |\n| This change | {} ({}/{}) |\n\n{}\n",
        short(base_commit),
        base.percent(),
        base.covered,
        base.count,
        head.percent(),
        head.covered,
        head.count,
        match verdict {
            Verdict::Kept => "Line coverage did not decrease.",
            Verdict::Decreased => {
                "**Line coverage decreased.** Add tests for the new or changed code (docs/testing.md#coverage)."
            }
        }
    );
    let annotation = (verdict == Verdict::Decreased).then(|| {
        format!(
            "::error title=Coverage decreased::{CRATE} line coverage fell from {} to {}",
            base.percent(),
            head.percent()
        )
        .replace('%', "%25")
    });
    (markdown, annotation)
}

/// The commit for display: a full SHA shortened to 12 characters, a ref
/// such as `origin/main` kept as is. Only `[A-Za-z0-9._/-]` is kept, so the
/// value cannot inject Markdown.
fn short(commit: &str) -> String {
    let safe: String = commit
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
        .take(64)
        .collect();
    let is_sha = safe.len() == 40 && safe.chars().all(|c| c.is_ascii_hexdigit());
    if safe.is_empty() {
        "base".to_owned()
    } else if is_sha {
        safe[..12].to_owned()
    } else {
        safe
    }
}

/// The `cargo llvm-cov` arguments for one measurement, writing the summary
/// to `output`.
pub fn llvm_cov_args(output: &Path) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = [
        "llvm-cov",
        "nextest",
        "-p",
        CRATE,
        "--all-features",
        "--locked",
        "--json",
        "--summary-only",
        "--output-path",
    ]
    .iter()
    .map(Into::into)
    .collect();
    args.push(output.into());
    args
}

/// Runs the measurement in `dir` and returns the crate's line count.
/// `target_dir` keeps the base build apart from the head build.
pub fn measure(dir: &Path, target_dir: &Path) -> Result<Count, String> {
    let output = target_dir.join("coverage-gate.json");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(llvm_cov_args(&output))
        .env("CARGO_TARGET_DIR", target_dir)
        .env("PROPTEST_RNG_SEED", PROPTEST_SEED)
        .current_dir(dir)
        .status()
        .map_err(|e| format!("cannot run cargo llvm-cov: {e}"))?;
    if !status.success() {
        return Err(format!(
            "cargo llvm-cov failed in {} (the tests must pass first)",
            dir.display()
        ));
    }
    let json = std::fs::read_to_string(&output)
        .map_err(|e| format!("cannot read {}: {e}", output.display()))?;
    crate_lines(&json, dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(covered: u64, count: u64) -> Count {
        Count { covered, count }
    }

    #[test]
    fn a_lower_percentage_is_a_decrease() {
        assert_eq!(compare(c(90, 100), c(90, 100)), Verdict::Kept);
        assert_eq!(compare(c(90, 100), c(91, 100)), Verdict::Kept);
        // More lines at the same ratio is not a decrease.
        assert_eq!(compare(c(90, 100), c(180, 200)), Verdict::Kept);
        // New uncovered lines are.
        assert_eq!(compare(c(90, 100), c(90, 101)), Verdict::Decreased);
        assert_eq!(compare(c(90, 100), c(89, 100)), Verdict::Decreased);
        // One line in a million still counts: the comparison is exact.
        assert_eq!(
            compare(c(999_999, 1_000_000), c(1_999_997, 2_000_000)),
            Verdict::Decreased
        );
    }

    #[test]
    fn empty_and_malformed_counts_are_handled() {
        assert_eq!(compare(c(0, 0), c(0, 0)), Verdict::Kept);
        assert_eq!(compare(c(0, 10), c(0, 10)), Verdict::Kept);
        assert_eq!(compare(c(5, 10), c(0, 0)), Verdict::Decreased);
        // A report cannot claim more than 100%.
        assert_eq!(compare(c(10, 10), c(20, 10)), Verdict::Kept);
        assert_eq!(compare(c(20, 10), c(9, 10)), Verdict::Decreased);
        let max = c(u64::MAX, u64::MAX);
        assert_eq!(compare(max, max), Verdict::Kept);
    }

    #[test]
    fn the_report_names_both_measurements() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let (md, error) = report(sha, c(90, 100), c(91, 100));
        assert!(
            md.contains("| Base (`0123456789ab`) | 90.0% (90/100) |"),
            "{md}"
        );
        assert!(md.contains("| This change | 91.0% (91/100) |"), "{md}");
        assert!(md.contains("did not decrease"), "{md}");
        assert_eq!(error, None);
        let (md, _) = report("origin/main", c(1, 1), c(1, 1));
        assert!(md.contains("| Base (`origin/main`) |"), "{md}");
        let (md, _) = report("`|", c(1, 1), c(1, 1));
        assert!(md.contains("| Base (`base`) |"), "{md}");
        let (md, error) = report("`|x\n", c(90, 100), c(80, 100));
        assert!(md.contains("| Base (`x`) |"), "{md}");
        assert!(md.contains("**Line coverage decreased.**"), "{md}");
        assert_eq!(
            error.unwrap(),
            "::error title=Coverage decreased::palisade-policy line coverage fell from 90.0%25 to 80.0%25"
        );
    }

    #[test]
    fn crate_lines_reads_the_policy_crate() {
        let json = r#"{"type": "llvm.coverage.json.export", "data": [{"files": [
            {"filename": "/w/crates/palisade-policy/src/lib.rs", "summary": {
                "lines": {"count": 10, "covered": 7},
                "functions": {"count": 1, "covered": 1},
                "regions": {"count": 1, "covered": 1}}},
            {"filename": "/w/crates/palisade-core/src/lib.rs", "summary": {
                "lines": {"count": 10, "covered": 1},
                "functions": {"count": 1, "covered": 1},
                "regions": {"count": 1, "covered": 1}}}
        ]}]}"#;
        assert_eq!(crate_lines(json, Path::new("/w")).unwrap(), c(7, 10));
        assert!(crate_lines(json, Path::new("/elsewhere")).is_err());
    }

    #[test]
    fn llvm_cov_measures_only_the_policy_crate() {
        let args = llvm_cov_args(Path::new("out.json"));
        let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args.join(" "),
            "llvm-cov nextest -p palisade-policy --all-features --locked --json --summary-only --output-path out.json"
        );
    }
}
