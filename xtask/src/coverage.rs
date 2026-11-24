//! `cargo xtask coverage-summary <label> <summary.json>`: turns the JSON
//! summary from `cargo llvm-cov nextest --json --summary-only` into a
//! per-crate table for the job summary page.
//!
//! Coverage is reported, not gated. The crates in [`TARGETS`] have an
//! initial line-coverage target from #25; a crate below its target gets a
//! `::warning` annotation, and the job still passes.

use std::collections::BTreeMap;

use serde_json::Value;

/// `(crate, minimum line coverage in percent)`: the initial targets.
pub const TARGETS: &[(&str, u64)] = &[("palisade-policy", 80), ("palisade-fileid", 80)];

/// Covered and total counts of one kind (lines, functions or regions).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Count {
    pub covered: u64,
    pub count: u64,
}

impl Count {
    fn add(&mut self, other: Self) {
        self.covered = self.covered.saturating_add(other.covered);
        self.count = self.count.saturating_add(other.count);
    }

    /// The percentage with one decimal, or `-` when there is nothing to
    /// cover.
    fn percent(self) -> String {
        if self.count == 0 {
            return "-".to_owned();
        }
        // Tenths of a percent, rounded down, in integers so no float
        // formatting differs between platforms.
        let tenths = u128::from(self.covered.min(self.count)) * 1000 / u128::from(self.count);
        format!("{}.{}%", tenths / 10, tenths % 10)
    }

    /// Whether at least `percent` of the items are covered. Nothing to
    /// cover meets only a zero target, so a crate whose code was compiled
    /// out is not reported as on target.
    fn meets(self, percent: u64) -> bool {
        if self.count == 0 {
            return percent == 0;
        }
        u128::from(self.covered) * 100 >= u128::from(self.count) * u128::from(percent)
    }
}

/// Coverage of one crate, or of the whole report.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    pub lines: Count,
    pub functions: Count,
    pub regions: Count,
}

impl Coverage {
    fn add(&mut self, other: Self) {
        self.lines.add(other.lines);
        self.functions.add(other.functions);
        self.regions.add(other.regions);
    }
}

/// The report: coverage per crate, keyed by crate directory name (`xtask`,
/// `palisade-core`, ...), and the total.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub crates: BTreeMap<String, Coverage>,
    pub total: Coverage,
}

/// Parses an `llvm.coverage.json.export` summary. `root` is the repository
/// root, as the report's absolute file names start with it.
pub fn parse(json: &str, root: &str) -> Result<Report, String> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| format!("not a JSON coverage summary: {e}"))?;
    if value["type"].as_str() != Some("llvm.coverage.json.export") {
        return Err(
            "not an llvm-cov JSON export (no `type: llvm.coverage.json.export`)".to_owned(),
        );
    }
    let data = value["data"]
        .as_array()
        .ok_or("coverage summary has no `data` array")?;
    let mut report = Report::default();
    let root = normalise(root);
    let root = root.trim_end_matches('/');
    for export in data {
        let files = export["files"]
            .as_array()
            .ok_or("coverage summary entry has no `files` array")?;
        for file in files {
            let name = file["filename"]
                .as_str()
                .ok_or("coverage file entry has no `filename`")?;
            let coverage = coverage_of(&file["summary"]).map_err(|e| format!("{name}: {e}"))?;
            let name = normalise(name);
            let relative = strip_root(&name, root).unwrap_or(&name);
            report
                .crates
                .entry(crate_of(relative))
                .or_default()
                .add(coverage);
            report.total.add(coverage);
        }
    }
    Ok(report)
}

/// `path` relative to `root`, comparing ASCII case-insensitively, because
/// Windows tools disagree on the case of drive letters.
fn strip_root<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    let head = path.get(..root.len())?;
    if !head.eq_ignore_ascii_case(root) {
        return None;
    }
    path.get(root.len()..)?.strip_prefix('/')
}

/// Forward slashes, so Windows paths group the same way.
fn normalise(path: &str) -> String {
    path.replace('\\', "/")
}

/// The crate a repository-relative path belongs to.
fn crate_of(relative: &str) -> String {
    let mut parts = relative.split('/');
    match (parts.next(), parts.next()) {
        (Some("crates"), Some(name)) if !name.is_empty() && parts.next().is_some() => {
            name.to_owned()
        }
        (Some("xtask"), Some(_)) => "xtask".to_owned(),
        _ => "(other)".to_owned(),
    }
}

fn coverage_of(summary: &Value) -> Result<Coverage, String> {
    let count = |kind: &str| -> Result<Count, String> {
        let entry = &summary[kind];
        let number = |key: &str| {
            entry[key]
                .as_u64()
                .ok_or_else(|| format!("summary `{kind}.{key}` is not a whole number"))
        };
        Ok(Count {
            covered: number("covered")?,
            count: number("count")?,
        })
    };
    Ok(Coverage {
        lines: count("lines")?,
        functions: count("functions")?,
        regions: count("regions")?,
    })
}

/// The Markdown summary for the job page.
pub fn markdown(label: &str, report: &Report) -> String {
    let mut out = format!(
        "### Coverage: {label}\n\n| Crate | Lines | Functions | Regions | Target |\n|---|---|---|---|---|\n"
    );
    let row = |name: &str, c: &Coverage, target: String| {
        format!(
            "| {name} | {} ({}/{}) | {} | {} | {target} |\n",
            c.lines.percent(),
            c.lines.covered,
            c.lines.count,
            c.functions.percent(),
            c.regions.percent()
        )
    };
    for (name, coverage) in &report.crates {
        let target = match target_of(name) {
            Some(t) if coverage.lines.meets(t) => format!("{t}% lines: met"),
            Some(t) => format!("{t}% lines: **below**"),
            None => String::new(),
        };
        out.push_str(&row(&format!("`{name}`"), coverage, target));
    }
    out.push_str(&row("**Total**", &report.total, String::new()));
    out
}

/// One `::warning` per crate below its target, and per target crate that
/// is missing from the report.
pub fn annotations(label: &str, report: &Report) -> Vec<String> {
    TARGETS
        .iter()
        .filter_map(|(name, target)| match report.crates.get(*name) {
            Some(c) if c.lines.meets(*target) => None,
            Some(c) => Some(format!(
                "::warning title=Coverage below target::{}",
                escape_data(&format!(
                    "{label}: {name} line coverage is {}, below the {target}% target",
                    c.lines.percent()
                ))
            )),
            None => Some(format!(
                "::warning title=Coverage below target::{}",
                escape_data(&format!("{label}: {name} is not in the coverage report"))
            )),
        })
        .collect()
}

/// Escaping for the message part of a workflow command.
fn escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn target_of(name: &str) -> Option<u64> {
    TARGETS.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, lines: (u64, u64), functions: (u64, u64), regions: (u64, u64)) -> String {
        format!(
            r#"{{"filename": "{name}", "summary": {{
                "lines": {{"count": {}, "covered": {}, "percent": 0}},
                "functions": {{"count": {}, "covered": {}, "percent": 0}},
                "regions": {{"count": {}, "covered": {}, "notcovered": 0, "percent": 0}},
                "branches": {{"count": 0, "covered": 0, "notcovered": 0, "percent": 0}}
            }}}}"#,
            lines.1, lines.0, functions.1, functions.0, regions.1, regions.0
        )
    }

    fn export(files: &[String]) -> String {
        format!(
            r#"{{"type": "llvm.coverage.json.export", "version": "3.1.0", "data": [{{"files": [{}], "totals": {{}}}}]}}"#,
            files.join(",")
        )
    }

    #[test]
    fn files_are_grouped_by_crate() {
        let json = export(&[
            file(
                "/r/crates/palisade-policy/src/ops.rs",
                (90, 100),
                (9, 10),
                (80, 100),
            ),
            file(
                "/r/crates/palisade-policy/src/lib.rs",
                (5, 10),
                (1, 2),
                (5, 10),
            ),
            file(
                "/r/crates/palisade-fileid/src/pe/mod.rs",
                (81, 100),
                (1, 1),
                (1, 1),
            ),
            file("/r/xtask/src/ci.rs", (1, 2), (1, 2), (1, 2)),
            file("/r/build/gen.rs", (0, 0), (0, 0), (0, 0)),
        ]);
        let report = parse(&json, "/r/").unwrap();
        let names: Vec<&str> = report.crates.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            ["(other)", "palisade-fileid", "palisade-policy", "xtask"]
        );
        assert_eq!(
            report.crates["palisade-policy"].lines,
            Count {
                covered: 95,
                count: 110
            }
        );
        assert_eq!(
            report.total.lines,
            Count {
                covered: 177,
                count: 212
            }
        );
        let md = markdown("ubuntu-latest", &report);
        assert!(md.starts_with("### Coverage: ubuntu-latest\n"), "{md}");
        assert!(
            md.contains("| `palisade-policy` | 86.3% (95/110) | 83.3% | 77.2% | 80% lines: met |"),
            "{md}"
        );
        assert!(
            md.contains(
                "| `palisade-fileid` | 81.0% (81/100) | 100.0% | 100.0% | 80% lines: met |"
            ),
            "{md}"
        );
        assert!(md.contains("| `(other)` | - (0/0) | - | - |  |"), "{md}");
        assert!(md.contains("| **Total** | 83.4% (177/212) |"), "{md}");
        assert!(annotations("ubuntu-latest", &report).is_empty());
    }

    #[test]
    fn windows_paths_group_the_same_way() {
        let json = export(&[file(
            r"C:\\a\\r\\crates\\palisade-core\\src\\id.rs",
            (1, 1),
            (1, 1),
            (1, 1),
        )]);
        let report = parse(&json, r"c:\a\r").unwrap();
        assert!(report.crates.contains_key("palisade-core"), "{report:?}");
        // A root that is only a prefix of a directory name does not match.
        let report = parse(&json, r"C:\a\r\cr").unwrap();
        assert!(report.crates.contains_key("(other)"), "{report:?}");
    }

    #[test]
    fn crates_below_target_or_missing_are_warned_about() {
        let json = export(&[file(
            "/r/crates/palisade-policy/src/ops.rs",
            (79, 100),
            (0, 0),
            (0, 0),
        )]);
        let report = parse(&json, "/r").unwrap();
        assert!(markdown("x", &report).contains("80% lines: **below**"));
        assert_eq!(
            annotations("windows-latest", &report),
            [
                "::warning title=Coverage below target::windows-latest: palisade-policy line coverage is 79.0%25, below the 80%25 target",
                "::warning title=Coverage below target::windows-latest: palisade-fileid is not in the coverage report",
            ]
        );
    }

    #[test]
    fn percentages_round_down_and_never_overflow() {
        let c = Count {
            covered: 2,
            count: 3,
        };
        assert_eq!(c.percent(), "66.6%");
        assert!(c.meets(66) && !c.meets(67));
        let huge = Count {
            covered: u64::MAX,
            count: u64::MAX,
        };
        assert_eq!(huge.percent(), "100.0%");
        assert!(huge.meets(100));
        let mut sum = huge;
        sum.add(huge);
        assert_eq!(sum, huge);
        // A malformed report cannot show more than 100%.
        assert_eq!(
            Count {
                covered: 5,
                count: 1
            }
            .percent(),
            "100.0%"
        );
        // Nothing to cover meets only a zero target.
        assert!(!Count::default().meets(80));
        assert!(!Count::default().meets(1));
        assert!(Count::default().meets(0));
    }

    #[test]
    fn a_target_crate_with_no_lines_is_warned_about() {
        let json = export(&[
            file(
                "/r/crates/palisade-policy/src/ops.rs",
                (0, 0),
                (0, 0),
                (0, 0),
            ),
            file(
                "/r/crates/palisade-fileid/src/lib.rs",
                (9, 10),
                (1, 1),
                (1, 1),
            ),
            // A file directly under `crates/` is not a crate.
            file("/r/crates/stray.rs", (1, 1), (1, 1), (1, 1)),
        ]);
        let report = parse(&json, "/r").unwrap();
        assert!(report.crates.contains_key("(other)"), "{report:?}");
        assert!(!report.crates.contains_key("stray.rs"), "{report:?}");
        let md = markdown("x", &report);
        assert!(
            md.contains("| `palisade-policy` | - (0/0) | - | - | 80% lines: **below** |"),
            "{md}"
        );
        assert_eq!(
            annotations("x\n::add-mask::y", &report),
            [
                "::warning title=Coverage below target::x%0A::add-mask::y: palisade-policy line coverage is -, below the 80%25 target"
            ]
        );
    }

    #[test]
    fn malformed_summaries_are_errors() {
        assert!(parse("", "/r").is_err());
        assert!(parse("{}", "/r").is_err());
        assert!(parse(r#"{"type": "llvm.coverage.json.export"}"#, "/r").is_err());
        let bad = export(&[
            r#"{"filename": "/r/xtask/src/a.rs", "summary": {"lines": {"count": -1}}}"#.to_owned(),
        ]);
        assert!(parse(&bad, "/r").is_err());
    }
}
