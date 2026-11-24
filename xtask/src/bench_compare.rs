//! `cargo xtask bench-compare --base <commit>`: the benchmark regression
//! gate.
//!
//! Runs every criterion bench at the base commit (in a temporary git
//! worktree) and at the working tree, on the same machine in the same job,
//! [`ROUNDS`] times each, alternating (base, head, base, head), and compares
//! each benchmark's median time. Of each side's rounds, the faster median
//! is kept ([`best_of`]): noise on a shared machine almost only ever slows a
//! run down, and alternating means a slow patch hits both sides alike.
//!
//! A benchmark regresses when its median is more than [`THRESHOLD_PERCENT`]
//! slower **and** the two 95% confidence intervals of the median do not
//! overlap. Both conditions together keep run-to-run noise from failing the
//! job, while a real slowdown of 20% clears them.
//!
//! `.github/workflows/bench.yml` runs this weekly (this week's `main` against
//! last week's) and on demand (any branch against `main`). It is not part of
//! PR CI: two full benchmark runs take too long, and timings on hosted
//! runners are only comparable within one job (docs/testing.md).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// A benchmark is a regression above this slowdown.
pub const THRESHOLD_PERCENT: u32 = 10;

/// How many times each side is measured.
pub const ROUNDS: usize = 2;

/// The median of one benchmark and its 95% confidence interval, in
/// nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Median {
    pub point: f64,
    pub lower: f64,
    pub upper: f64,
}

/// How one benchmark changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Slower by more than the threshold, outside the noise.
    Regressed,
    /// Faster by more than the threshold, outside the noise.
    Improved,
    /// Neither.
    Unchanged,
    /// Only at the base: the benchmark was removed or renamed.
    Removed,
    /// Only in this change.
    Added,
}

/// One row of the comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub id: String,
    pub base: Option<Median>,
    pub head: Option<Median>,
    pub change: Change,
}

/// Classifies one benchmark measured at both commits.
pub fn classify(base: Median, head: Median) -> Change {
    let factor = 1.0 + f64::from(THRESHOLD_PERCENT) / 100.0;
    if head.point > base.point * factor && head.lower > base.upper {
        Change::Regressed
    } else if base.point > head.point * factor && base.lower > head.upper {
        Change::Improved
    } else {
        Change::Unchanged
    }
}

/// Compares two sets of results, keyed by benchmark ID. Rows are sorted by
/// ID.
pub fn compare(base: &BTreeMap<String, Median>, head: &BTreeMap<String, Median>) -> Vec<Row> {
    let mut ids: Vec<&String> = base.keys().chain(head.keys()).collect();
    ids.sort();
    ids.dedup();
    ids.into_iter()
        .map(|id| {
            let (b, h) = (base.get(id).copied(), head.get(id).copied());
            let change = match (b, h) {
                (Some(b), Some(h)) => classify(b, h),
                (Some(_), None) => Change::Removed,
                _ => Change::Added,
            };
            Row {
                id: id.clone(),
                base: b,
                head: h,
                change,
            }
        })
        .collect()
}

/// Merges a further round into `best`: for each benchmark, the measurement
/// with the lower median is kept, with its own confidence interval.
pub fn best_of(best: &mut BTreeMap<String, Median>, round: BTreeMap<String, Median>) {
    for (id, median) in round {
        best.entry(id)
            .and_modify(|kept| {
                if median.point < kept.point {
                    *kept = median;
                }
            })
            .or_insert(median);
    }
}

/// Reads every benchmark result under a criterion output directory
/// (`CRITERION_HOME`): each `<id>/new/benchmark.json` with its
/// `estimates.json`. Symbolic links are not followed.
pub fn read_results(home: &Path) -> Result<BTreeMap<String, Median>, String> {
    let mut results = BTreeMap::new();
    let mut stack = vec![home.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
            let kind = entry
                .file_type()
                .map_err(|e| format!("cannot read {}: {e}", entry.path().display()))?;
            if kind.is_dir() {
                stack.push(entry.path());
            }
        }
        if dir.file_name().is_some_and(|n| n == "new") && dir.join("benchmark.json").is_file() {
            let (id, median) = read_one(&dir)?;
            if results.insert(id.clone(), median).is_some() {
                return Err(format!(
                    "benchmark `{id}` appears twice under {}",
                    home.display()
                ));
            }
        }
    }
    Ok(results)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: not JSON: {e}", path.display()))
}

/// One benchmark's ID and median from its criterion `new/` directory.
fn read_one(dir: &Path) -> Result<(String, Median), String> {
    let benchmark = read_json(&dir.join("benchmark.json"))?;
    let id = benchmark["full_id"]
        .as_str()
        .ok_or_else(|| format!("{}: no `full_id`", dir.display()))?
        .to_owned();
    let estimates = read_json(&dir.join("estimates.json"))?;
    let median = &estimates["median"];
    let number = |v: &Value, what: &str| {
        v.as_f64()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .ok_or_else(|| format!("{}: `median.{what}` is not a time", dir.display()))
    };
    Ok((
        id,
        Median {
            point: number(&median["point_estimate"], "point_estimate")?,
            lower: number(&median["confidence_interval"]["lower_bound"], "lower_bound")?,
            upper: number(&median["confidence_interval"]["upper_bound"], "upper_bound")?,
        },
    ))
}

/// A time in nanoseconds, with a unit.
fn time(ns: f64) -> String {
    if ns >= 1e9 {
        format!("{:.3} s", ns / 1e9)
    } else if ns >= 1e6 {
        format!("{:.3} ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.3} µs", ns / 1e3)
    } else {
        format!("{ns:.1} ns")
    }
}

/// Characters a criterion ID may contain in the summary table. Anything
/// else is replaced, so an ID cannot inject Markdown or a workflow command.
fn safe_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | ' ' | ':') {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// The Markdown table for the job summary, and one `::error` annotation per
/// regression.
pub fn markdown(base_label: &str, rows: &[Row]) -> (String, Vec<String>) {
    let mut out = format!(
        "### Benchmark comparison against `{}`\n\nA regression is a median more than {THRESHOLD_PERCENT}% slower, with non-overlapping 95% confidence intervals.\n\n| Benchmark | Base | This change | Change | Result |\n|---|---|---|---|---|\n",
        safe_id(base_label)
    );
    let mut errors = Vec::new();
    for row in rows {
        let cell = |m: Option<Median>| m.map_or_else(|| "-".to_owned(), |m| time(m.point));
        let delta = match (row.base, row.head) {
            (Some(b), Some(h)) if b.point > 0.0 => {
                format!("{:+.1}%", (h.point / b.point - 1.0) * 100.0)
            }
            _ => "-".to_owned(),
        };
        let result = match row.change {
            Change::Regressed => "**regressed**",
            Change::Improved => "improved",
            Change::Unchanged => "ok",
            Change::Removed => "removed",
            Change::Added => "new",
        };
        let id = safe_id(&row.id);
        out.push_str(&format!(
            "| `{id}` | {} | {} | {delta} | {result} |\n",
            cell(row.base),
            cell(row.head)
        ));
        if row.change == Change::Regressed {
            errors.push(
                format!("::error title=Benchmark regressed::{id} is {delta} slower than the base")
                    .replace('%', "%25"),
            );
        }
    }
    let regressed = errors.len();
    out.push_str(&if regressed == 0 {
        "\nNo benchmark regressed.\n".to_owned()
    } else {
        format!("\n**{regressed} benchmark(s) regressed.**\n")
    });
    (out, errors)
}

/// The bench targets in a checkout: the file stem of every
/// `crates/*/benches/*.rs`, sorted. (The `bench` CI job names each one; a
/// test in `ci.rs` keeps that list in step.)
pub fn bench_targets(root: &Path) -> Result<Vec<String>, String> {
    let crates = root.join("crates");
    let mut found = Vec::new();
    let entries =
        std::fs::read_dir(&crates).map_err(|e| format!("cannot read {}: {e}", crates.display()))?;
    for entry in entries {
        let benches = entry
            .map_err(|e| format!("cannot read {}: {e}", crates.display()))?
            .path()
            .join("benches");
        let Ok(files) = std::fs::read_dir(&benches) else {
            continue;
        };
        for file in files {
            let path = file
                .map_err(|e| format!("cannot read {}: {e}", benches.display()))?
                .path();
            if path.extension().is_some_and(|e| e == "rs") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    found.push(stem.to_owned());
                }
            }
        }
    }
    found.sort();
    Ok(found)
}

/// The `cargo bench` arguments for `targets`.
pub fn bench_args(targets: &[String]) -> Vec<String> {
    let mut args: Vec<String> = ["bench", "--workspace", "--all-features", "--locked"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for target in targets {
        args.push("--bench".to_owned());
        args.push(target.clone());
    }
    args
}

/// Runs every bench of the checkout in `dir`, writing criterion's results
/// to `home`, and reads them back. `target_dir` is the Cargo target
/// directory. The base and head runs must use different ones: Cargo decides
/// freshness by file times, and the head's sources are older than a base
/// build made a moment ago, so a shared directory would rerun the base's
/// binaries and compare the base with itself.
pub fn run_benches(
    dir: &Path,
    home: &Path,
    target_dir: &Path,
) -> Result<BTreeMap<String, Median>, String> {
    let targets = bench_targets(dir)?;
    if targets.is_empty() {
        return Ok(BTreeMap::new());
    }
    if home.exists() {
        std::fs::remove_dir_all(home)
            .map_err(|e| format!("cannot remove {}: {e}", home.display()))?;
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(bench_args(&targets))
        .env("CRITERION_HOME", home)
        .env("CARGO_TARGET_DIR", target_dir)
        .current_dir(dir)
        .status()
        .map_err(|e| format!("cannot run cargo bench: {e}"))?;
    if !status.success() {
        return Err(format!("cargo bench failed in {}", dir.display()));
    }
    read_results(home)
}

/// Where the comparison keeps its files: `target/bench-compare/`.
pub fn work_dir(root: &Path) -> PathBuf {
    root.join("target").join("bench-compare")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(point: f64, spread: f64) -> Median {
        Median {
            point,
            lower: point - spread,
            upper: point + spread,
        }
    }

    #[test]
    fn a_twenty_percent_slowdown_is_a_regression() {
        assert_eq!(classify(m(100.0, 2.0), m(120.0, 2.0)), Change::Regressed);
        assert_eq!(classify(m(100.0, 2.0), m(80.0, 2.0)), Change::Improved);
    }

    #[test]
    fn small_or_noisy_changes_are_not() {
        // Within the threshold.
        assert_eq!(classify(m(100.0, 0.1), m(109.0, 0.1)), Change::Unchanged);
        assert_eq!(classify(m(100.0, 0.1), m(110.0, 0.1)), Change::Unchanged);
        // Over the threshold, but the confidence intervals overlap.
        assert_eq!(classify(m(100.0, 10.0), m(115.0, 10.0)), Change::Unchanged);
        assert_eq!(classify(m(100.0, 0.0), m(100.0, 0.0)), Change::Unchanged);
    }

    #[test]
    fn the_faster_round_is_kept() {
        let mut best: BTreeMap<String, Median> = [
            ("a".to_owned(), m(120.0, 5.0)),
            ("b".to_owned(), m(10.0, 1.0)),
        ]
        .into();
        best_of(
            &mut best,
            [
                ("a".to_owned(), m(100.0, 1.0)),
                ("b".to_owned(), m(11.0, 1.0)),
                ("c".to_owned(), m(1.0, 0.1)),
            ]
            .into(),
        );
        assert_eq!(best["a"], m(100.0, 1.0));
        assert_eq!(best["b"], m(10.0, 1.0));
        assert_eq!(best["c"], m(1.0, 0.1));
    }

    #[test]
    fn rows_cover_added_and_removed_benchmarks() {
        let base: BTreeMap<String, Median> = [
            ("a/x".to_owned(), m(100.0, 1.0)),
            ("b/gone".to_owned(), m(5.0, 1.0)),
        ]
        .into();
        let head: BTreeMap<String, Median> = [
            ("a/x".to_owned(), m(130.0, 1.0)),
            ("c/new".to_owned(), m(7.0, 1.0)),
        ]
        .into();
        let rows = compare(&base, &head);
        let changes: Vec<(&str, Change)> = rows.iter().map(|r| (r.id.as_str(), r.change)).collect();
        assert_eq!(
            changes,
            [
                ("a/x", Change::Regressed),
                ("b/gone", Change::Removed),
                ("c/new", Change::Added)
            ]
        );
        let (md, errors) = markdown("main", &rows);
        assert!(
            md.contains("| `a/x` | 100.0 ns | 130.0 ns | +30.0% | **regressed** |"),
            "{md}"
        );
        assert!(
            md.contains("| `b/gone` | 5.0 ns | - | - | removed |"),
            "{md}"
        );
        assert!(md.contains("| `c/new` | - | 7.0 ns | - | new |"), "{md}");
        assert!(md.contains("**1 benchmark(s) regressed.**"), "{md}");
        assert_eq!(
            errors,
            ["::error title=Benchmark regressed::a/x is +30.0%25 slower than the base"]
        );
        let (md, errors) = markdown("x", &compare(&base, &base));
        assert!(md.contains("No benchmark regressed."), "{md}");
        assert!(errors.is_empty());
    }

    #[test]
    fn ids_and_labels_cannot_inject_markup() {
        assert_eq!(safe_id("hash_1mib/sha256"), "hash_1mib/sha256");
        assert_eq!(safe_id("a|b`c\n::x"), "a?b?c?::x");
        assert_eq!(time(1.5e9), "1.500 s");
        assert_eq!(time(2.5e6), "2.500 ms");
        assert_eq!(time(1234.0), "1.234 µs");
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn estimates(point: f64, lower: f64, upper: f64) -> String {
        format!(
            r#"{{"mean": {{"point_estimate": 1.0}}, "median": {{"confidence_interval":
               {{"confidence_level": 0.95, "lower_bound": {lower}, "upper_bound": {upper}}},
               "point_estimate": {point}, "standard_error": 0.1}}}}"#
        )
    }

    #[test]
    fn criterion_output_is_read_by_full_id() {
        let home = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join(format!("xtask-bench-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let new = home.join("hash_1mib").join("sha256").join("new");
        write(
            &new.join("benchmark.json"),
            r#"{"group_id": "hash_1mib", "function_id": "sha256", "full_id": "hash_1mib/sha256"}"#,
        );
        write(&new.join("estimates.json"), &estimates(10.0, 9.0, 11.0));
        // A saved baseline next to it is not a result of this run.
        let base = home.join("hash_1mib").join("sha256").join("base");
        write(
            &base.join("benchmark.json"),
            r#"{"full_id": "hash_1mib/sha256"}"#,
        );
        write(&base.join("estimates.json"), &estimates(99.0, 98.0, 100.0));
        let results = read_results(&home).unwrap();
        assert_eq!(
            results,
            [(
                "hash_1mib/sha256".to_owned(),
                Median {
                    point: 10.0,
                    lower: 9.0,
                    upper: 11.0
                }
            )]
            .into()
        );
        // A malformed estimate is an error, not a silent skip.
        write(&new.join("estimates.json"), &estimates(-1.0, 9.0, 11.0));
        assert!(read_results(&home).is_err());
        write(&new.join("estimates.json"), "{");
        assert!(read_results(&home).is_err());
        std::fs::remove_dir_all(&home).unwrap();
        assert!(read_results(&home).is_err());
    }

    #[test]
    fn every_bench_target_of_the_repository_is_run() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let targets = bench_targets(&root).unwrap();
        assert!(
            targets.contains(&"hash_and_parse".to_owned()),
            "{targets:?}"
        );
        let args = bench_args(&targets).join(" ");
        assert!(
            args.starts_with("bench --workspace --all-features --locked --bench "),
            "{args}"
        );
        for target in &targets {
            assert!(args.contains(&format!("--bench {target}")), "{args}");
        }
    }
}
