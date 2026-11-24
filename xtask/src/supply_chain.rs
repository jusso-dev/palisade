//! `cargo xtask check-supply-chain`: the dependency rules from #23 that
//! cargo-deny and cargo-vet do not check themselves.
//!
//! - **Duplicate budget.** The resolved graph may hold at most
//!   [`DUPLICATE_BUDGET`] crates that appear in more than one version.
//!   cargo-deny only warns about duplicates (`multiple-versions = "warn"`).
//! - **Advisory ignores.** Every `[advisories] ignore` entry in `deny.toml`
//!   is a table with an advisory `id`, a `reason`, and an `expires` date
//!   (`YYYY-MM-DD`). An expired entry fails, so an ignore cannot outlive its
//!   review date.
//! - **Skips and exceptions need a reason.** Every `[bans] skip` and
//!   `skip-tree` entry, and every `[licenses] exceptions` entry, is a table
//!   with a non-empty `reason`.
//! - **cargo-vet criteria.** `supply-chain/config.toml` requires
//!   `safe-to-deploy` for every product crate and `safe-to-run` for `xtask`,
//!   and every exemption has a `notes` field saying why it is exempt.
//!
//! `cargo xtask deps-report` prints the build-script and proc-macro
//! inventory, the duplicates, and a per-crate count of third-party crates.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use toml::Table;

/// The most crates that may appear in more than one version (#23).
pub const DUPLICATE_BUDGET: usize = 10;

/// Crates that are shipped (or run with privilege), so their whole
/// dependency tree must meet `safe-to-deploy`. Everything else in the
/// workspace is build tooling and needs `safe-to-run`.
pub const SAFE_TO_DEPLOY: &[&str] = &[
    "palisade-core",
    "palisade-fileid",
    "palisade-policy",
    "palisade-proto",
    "palisade-agent",
    "palisade-tray",
    "palisade-server",
    "palisade-console",
    "palisade-cli",
    "palisade-driver",
];

/// Workspace crates that only run on developer machines and in CI.
pub const SAFE_TO_RUN: &[&str] = &["xtask"];

/// Third-party crates that appear in more than one version, with their
/// versions, from `cargo metadata` (all features, every platform).
pub fn duplicates(metadata: &Value) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .ok_or("cargo metadata: missing workspace_members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or("cargo metadata: missing packages")?
    {
        let id = package["id"].as_str().unwrap_or_default();
        if members.contains(id) {
            continue;
        }
        let (Some(name), Some(version)) = (package["name"].as_str(), package["version"].as_str())
        else {
            return Err("cargo metadata: package without name or version".to_owned());
        };
        versions
            .entry(name.to_owned())
            .or_default()
            .insert(version.to_owned());
    }
    versions.retain(|_, v| v.len() > 1);
    Ok(versions)
}

/// Fails when more than `budget` crates are duplicated.
pub fn check_duplicates(dups: &BTreeMap<String, BTreeSet<String>>, budget: usize) -> Vec<String> {
    if dups.len() <= budget {
        return Vec::new();
    }
    let list: Vec<String> = dups
        .iter()
        .map(|(name, versions)| {
            let versions: Vec<&str> = versions.iter().map(String::as_str).collect();
            format!("{name} ({})", versions.join(", "))
        })
        .collect();
    vec![format!(
        "{} crates appear in more than one version, over the budget of {budget}: {}",
        dups.len(),
        list.join("; ")
    )]
}

/// Checks the ignore, skip and exception entries of `deny.toml`. `today` is
/// `YYYY-MM-DD`.
pub fn check_deny_toml(source: &str, today: &str) -> Result<Vec<String>, String> {
    let deny: Table = source
        .parse()
        .map_err(|e| format!("deny.toml: invalid TOML: {e}"))?;
    let mut v = Vec::new();

    let ignores = deny
        .get("advisories")
        .and_then(|a| a.get("ignore"))
        .and_then(toml::Value::as_array);
    for (i, entry) in ignores.into_iter().flatten().enumerate() {
        let at = format!("deny.toml: advisories.ignore[{i}]");
        let Some(entry) = entry.as_table() else {
            v.push(format!(
                "{at} must be a table with `id`, `reason` and `expires`, not a bare ID"
            ));
            continue;
        };
        let id = entry.get("id").and_then(toml::Value::as_str).unwrap_or("");
        if !is_advisory_id(id) {
            v.push(format!(
                "{at}: `id` must be an advisory ID such as RUSTSEC-2024-0001, not `{id}`"
            ));
        }
        if !has_text(entry, "reason") {
            v.push(format!("{at} ({id}): needs a non-empty `reason`"));
        }
        match entry.get("expires").and_then(toml::Value::as_str) {
            Some(date) if is_date(date) => {
                // ISO dates compare correctly as strings.
                if date < today {
                    v.push(format!(
                        "{at} ({id}): expired on {date}; review the advisory and renew or remove the ignore"
                    ));
                }
            }
            _ => v.push(format!(
                "{at} ({id}): needs `expires = \"YYYY-MM-DD\"`, the date it must be reviewed by"
            )),
        }
    }

    let bans = deny.get("bans");
    for key in ["skip", "skip-tree"] {
        let entries = bans
            .and_then(|b| b.get(key))
            .and_then(toml::Value::as_array);
        for (i, entry) in entries.into_iter().flatten().enumerate() {
            let has_reason = entry.as_table().is_some_and(|t| has_text(t, "reason"));
            if !has_reason {
                v.push(format!(
                    "deny.toml: bans.{key}[{i}] must be a table with a non-empty `reason`"
                ));
            }
        }
    }
    let exceptions = deny
        .get("licenses")
        .and_then(|l| l.get("exceptions"))
        .and_then(toml::Value::as_array);
    for (i, entry) in exceptions.into_iter().flatten().enumerate() {
        let has_reason = entry.as_table().is_some_and(|t| has_text(t, "reason"));
        if !has_reason {
            v.push(format!(
                "deny.toml: licenses.exceptions[{i}] must have a non-empty `reason`"
            ));
        }
    }
    Ok(v)
}

/// Checks `supply-chain/config.toml`: the policy for every workspace crate,
/// and a note on every exemption. `members` are the workspace crate names.
pub fn check_vet_config(source: &str, members: &[String]) -> Result<Vec<String>, String> {
    let config: Table = source
        .parse()
        .map_err(|e| format!("supply-chain/config.toml: invalid TOML: {e}"))?;
    let mut v = Vec::new();
    let policy = config.get("policy").and_then(toml::Value::as_table);
    for member in members {
        let expected = if SAFE_TO_RUN.contains(&member.as_str()) {
            "safe-to-run"
        } else if SAFE_TO_DEPLOY.contains(&member.as_str()) {
            "safe-to-deploy"
        } else {
            v.push(format!(
                "{member} is not listed in SAFE_TO_DEPLOY or SAFE_TO_RUN (xtask/src/supply_chain.rs); add it"
            ));
            continue;
        };
        let entry = policy.and_then(|p| p.get(member.as_str()));
        let criteria = entry
            .and_then(|e| e.get("criteria"))
            .and_then(toml::Value::as_str);
        let dev = entry
            .and_then(|e| e.get("dev-criteria"))
            .and_then(toml::Value::as_str);
        if criteria != Some(expected) {
            v.push(format!(
                "supply-chain/config.toml: [policy.{member}] needs criteria = \"{expected}\""
            ));
        }
        if dev != Some("safe-to-run") {
            v.push(format!(
                "supply-chain/config.toml: [policy.{member}] needs dev-criteria = \"safe-to-run\""
            ));
        }
    }
    let exemptions = config.get("exemptions").and_then(toml::Value::as_table);
    for (name, entries) in exemptions.into_iter().flatten() {
        for entry in entries.as_array().into_iter().flatten() {
            let noted = entry.as_table().is_some_and(|t| has_text(t, "notes"));
            if !noted {
                let version = entry
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("?");
                v.push(format!(
                    "supply-chain/config.toml: exemption for {name} {version} needs `notes` saying why it is not audited"
                ));
            }
        }
    }
    Ok(v)
}

/// Third-party crates with a build script or that are proc-macros: code that
/// runs on the build machine. `(name, version, kinds)`, sorted.
pub fn build_time_code(metadata: &Value) -> Vec<(String, String, String)> {
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut out = Vec::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        if members.contains(package["id"].as_str().unwrap_or_default()) {
            continue;
        }
        let mut kinds = BTreeSet::new();
        for target in package["targets"].as_array().into_iter().flatten() {
            for kind in target["kind"].as_array().into_iter().flatten() {
                match kind.as_str() {
                    Some("custom-build") => {
                        kinds.insert("build script");
                    }
                    Some("proc-macro") => {
                        kinds.insert("proc-macro");
                    }
                    _ => {}
                }
            }
        }
        if !kinds.is_empty() {
            out.push((
                package["name"].as_str().unwrap_or_default().to_owned(),
                package["version"].as_str().unwrap_or_default().to_owned(),
                kinds.into_iter().collect::<Vec<_>>().join(", "),
            ));
        }
    }
    out.sort();
    out
}

/// `(name, version, unsafe keyword count, files that could not be read)`
/// for every third-party package, from the `.rs` files under its manifest
/// directory, sorted by count (highest first). `count` is
/// [`crate::unsafe_code::count_unsafe`].
pub fn unsafe_inventory(
    metadata: &Value,
    count: impl Fn(&str) -> Option<usize>,
) -> Vec<(String, String, usize, usize)> {
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut out = Vec::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        if members.contains(package["id"].as_str().unwrap_or_default()) {
            continue;
        }
        let Some(dir) = package["manifest_path"]
            .as_str()
            .and_then(|p| std::path::Path::new(p).parent())
        else {
            continue;
        };
        let (mut total, mut unreadable) = (0, 0);
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&current) else {
                unreadable += 1;
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    match std::fs::read_to_string(&path)
                        .ok()
                        .as_deref()
                        .and_then(&count)
                    {
                        Some(n) => total += n,
                        None => unreadable += 1,
                    }
                }
            }
        }
        out.push((
            package["name"].as_str().unwrap_or_default().to_owned(),
            package["version"].as_str().unwrap_or_default().to_owned(),
            total,
            unreadable,
        ));
    }
    out.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    out
}

/// A new crate with more `unsafe` keywords than this, or a version change
/// that adds more than this, is flagged in the PR report (#23).
pub const UNSAFE_JUMP: usize = 100;

/// `(name, version)` of every registry package in a `Cargo.lock`.
pub fn lock_packages(lock: &str) -> Result<BTreeSet<(String, String)>, String> {
    let lock: Table = lock
        .parse()
        .map_err(|e| format!("Cargo.lock: invalid TOML: {e}"))?;
    Ok(lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get("source").is_some())
        .filter_map(|p| {
            Some((
                p.get("name")?.as_str()?.to_owned(),
                p.get("version")?.as_str()?.to_owned(),
            ))
        })
        .collect())
}

/// One line of the `unsafe` change report.
#[derive(Debug, PartialEq, Eq)]
pub struct UnsafeChange {
    pub line: String,
    pub big_jump: bool,
}

/// Compares the base branch's locked packages with the current `unsafe`
/// inventory. Only current sources are read (the base's are not
/// downloaded), so a version change can show a before and after count only
/// while the old version is still in the graph; otherwise it shows the new
/// count. A new crate is flagged above [`UNSAFE_JUMP`], and a version
/// change when it adds more than [`UNSAFE_JUMP`] or, with no old count to
/// compare, when the new version alone is above it.
pub fn unsafe_changes(
    base: &BTreeSet<(String, String)>,
    current: &[(String, String, usize, usize)],
) -> Vec<UnsafeChange> {
    let mut out = Vec::new();
    let count_of = |name: &str, version: &str| {
        current
            .iter()
            .find(|(n, v, _, _)| n == name && v == version)
            .map(|(_, _, c, _)| *c)
    };
    for (name, version, count, _) in current {
        if base.contains(&(name.clone(), version.clone())) {
            continue;
        }
        let old: Vec<&str> = base
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect();
        if old.is_empty() {
            out.push(UnsafeChange {
                line: format!("new: `{name}` {version}, {count} `unsafe`"),
                big_jump: *count > UNSAFE_JUMP,
            });
            continue;
        }
        let before = old.iter().filter_map(|v| count_of(name, v)).max();
        let (line, big_jump) = match before {
            Some(before) => (
                format!(
                    "changed: `{name}` {} -> {version}, `unsafe` {before} -> {count}",
                    old.join(", ")
                ),
                count.saturating_sub(before) > UNSAFE_JUMP,
            ),
            None => (
                format!(
                    "changed: `{name}` {} -> {version}, now {count} `unsafe`",
                    old.join(", ")
                ),
                *count > UNSAFE_JUMP,
            ),
        };
        out.push(UnsafeChange { line, big_jump });
    }
    for (name, version) in base {
        if !current.iter().any(|(n, v, _, _)| n == name && v == version)
            && !current.iter().any(|(n, _, _, _)| n == name)
        {
            out.push(UnsafeChange {
                line: format!("removed: `{name}` {version}"),
                big_jump: false,
            });
        }
    }
    out
}

fn has_text(table: &toml::map::Map<String, toml::Value>, key: &str) -> bool {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

/// `RUSTSEC-YYYY-NNNN`, or another database's ID of the same shape
/// (`GHSA-xxxx-xxxx-xxxx` is also accepted).
fn is_advisory_id(id: &str) -> bool {
    let rustsec = id.strip_prefix("RUSTSEC-").is_some_and(|rest| {
        let (year, number) = rest.split_once('-').unwrap_or(("", ""));
        year.len() == 4
            && number.len() == 4
            && year
                .bytes()
                .chain(number.bytes())
                .all(|b| b.is_ascii_digit())
    });
    let ghsa = id.strip_prefix("GHSA-").is_some_and(|rest| {
        let parts: Vec<&str> = rest.split('-').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_alphanumeric()))
    });
    rustsec || ghsa
}

/// A `YYYY-MM-DD` date with a plausible month and day.
fn is_date(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let [y, m, d] = parts.as_slice() else {
        return false;
    };
    let number = |p: &str, len: usize| {
        (p.len() == len && p.bytes().all(|b| b.is_ascii_digit())).then(|| p.parse::<u32>().ok())?
    };
    matches!(
        (number(y, 4), number(m, 2), number(d, 2)),
        (Some(_), Some(1..=12), Some(1..=31))
    )
}

/// Today's UTC date as `YYYY-MM-DD`, from the system clock.
pub fn today_utc() -> Result<String, String> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system clock is before 1970: {e}"))?
        .as_secs();
    let days = i64::try_from(secs / 86_400).map_err(|e| e.to_string())?;
    let (y, m, d) = civil_from_days(days);
    Ok(format!("{y:04}-{m:02}-{d:02}"))
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days` algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn duplicates_ignore_workspace_members_and_single_versions() {
        let metadata = json!({
            "workspace_members": ["ws"],
            "packages": [
                {"id": "ws", "name": "syn", "version": "9.9.9"},
                {"id": "a", "name": "syn", "version": "2.0.0"},
                {"id": "b", "name": "syn", "version": "3.0.0"},
                {"id": "c", "name": "serde", "version": "1.0.0"},
            ],
        });
        let dups = duplicates(&metadata).unwrap();
        assert_eq!(dups.len(), 1);
        assert_eq!(dups["syn"].len(), 2);
    }

    #[test]
    fn duplicate_budget_is_enforced() {
        let dups: BTreeMap<String, BTreeSet<String>> = (0..3)
            .map(|i| {
                (
                    format!("crate{i}"),
                    BTreeSet::from(["1.0.0".to_owned(), "2.0.0".to_owned()]),
                )
            })
            .collect();
        assert!(check_duplicates(&dups, 3).is_empty());
        let v = check_duplicates(&dups, 2);
        assert_eq!(v.len(), 1);
        assert!(v[0].starts_with("3 crates appear in more than one version, over the budget of 2"));
        assert!(v[0].contains("crate0 (1.0.0, 2.0.0)"), "{v:?}");
    }

    #[test]
    fn valid_ignores_skips_and_exceptions_pass() {
        let deny = r#"
[advisories]
ignore = [{ id = "RUSTSEC-2024-0001", reason = "not reachable", expires = "2026-12-31" }]
[bans]
skip = [{ crate = "syn@2.0.119", reason = "proc-macro2 still on syn 2" }]
skip-tree = []
[licenses]
exceptions = [{ crate = "x", allow = ["GPL-3.0"], reason = "dev tool only" }]
"#;
        assert_eq!(
            check_deny_toml(deny, "2026-11-24").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn expired_ignore_fails_on_the_day_after() {
        let deny = r#"[advisories]
ignore = [{ id = "RUSTSEC-2024-0001", reason = "r", expires = "2026-11-23" }]"#;
        assert!(check_deny_toml(deny, "2026-11-23").unwrap().is_empty());
        let v = check_deny_toml(deny, "2026-11-24").unwrap();
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("expired on 2026-11-23"), "{v:?}");
    }

    #[test]
    fn incomplete_ignores_fail() {
        let deny = r#"[advisories]
ignore = [
    "RUSTSEC-2024-0001",
    { id = "RUSTSEC-2024-0002", reason = "r" },
    { id = "RUSTSEC-2024-0003", expires = "2027-01-01" },
    { id = "bogus", reason = "r", expires = "2027-01-01" },
    { id = "GHSA-abcd-1234-efgh", reason = "r", expires = "2027-13-01" },
]"#;
        let v = check_deny_toml(deny, "2026-11-24").unwrap();
        assert_eq!(v.len(), 5, "{v:?}");
        assert!(v[0].contains("not a bare ID"));
        assert!(v[1].contains("needs `expires"));
        assert!(v[2].contains("needs a non-empty `reason`"));
        assert!(v[3].contains("not `bogus`"));
        assert!(v[4].contains("needs `expires"));
    }

    #[test]
    fn skips_and_exceptions_without_reason_fail() {
        let deny = r#"
[bans]
skip = ["syn@2.0.119", { crate = "a", reason = " " }]
skip-tree = [{ crate = "b" }]
[licenses]
exceptions = [{ crate = "x", allow = ["GPL-3.0"] }]
"#;
        assert_eq!(check_deny_toml(deny, "2026-11-24").unwrap().len(), 4);
    }

    #[test]
    fn vet_config_requires_criteria_per_crate_and_noted_exemptions() {
        let members = ["palisade-core".to_owned(), "xtask".to_owned()];
        let good = r#"
[policy.palisade-core]
criteria = "safe-to-deploy"
dev-criteria = "safe-to-run"
[policy.xtask]
criteria = "safe-to-run"
dev-criteria = "safe-to-run"
[[exemptions.syn]]
version = "2.0.119"
criteria = "safe-to-deploy"
notes = "baseline at cargo-vet adoption (#23)"
"#;
        assert_eq!(
            check_vet_config(good, &members).unwrap(),
            Vec::<String>::new()
        );
        let bad = r#"
[policy.palisade-core]
criteria = "safe-to-run"
[[exemptions.syn]]
version = "2.0.119"
criteria = "safe-to-deploy"
"#;
        let v = check_vet_config(bad, &members).unwrap();
        assert_eq!(v.len(), 5, "{v:?}");
        let v = check_vet_config(good, &["palisade-new".to_owned()]).unwrap();
        assert!(v[0].starts_with("palisade-new is not listed"), "{v:?}");
    }

    #[test]
    fn build_time_code_lists_build_scripts_and_proc_macros() {
        let metadata = json!({
            "workspace_members": ["ws"],
            "packages": [
                {"id": "ws", "name": "xtask", "version": "0.1.0", "targets": [{"kind": ["custom-build"]}]},
                {"id": "a", "name": "serde_derive", "version": "1.0.0", "targets": [{"kind": ["proc-macro"]}]},
                {"id": "b", "name": "libc", "version": "0.2.0", "targets": [{"kind": ["lib"]}, {"kind": ["custom-build"]}]},
                {"id": "c", "name": "itoa", "version": "1.0.0", "targets": [{"kind": ["lib"]}]},
            ],
        });
        assert_eq!(
            build_time_code(&metadata),
            [
                (
                    "libc".to_owned(),
                    "0.2.0".to_owned(),
                    "build script".to_owned()
                ),
                (
                    "serde_derive".to_owned(),
                    "1.0.0".to_owned(),
                    "proc-macro".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn unsafe_inventory_reads_each_package_directory() {
        let dir = std::env::temp_dir().join(format!("xtask-unsafe-inv-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src/inner")).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "").unwrap();
        std::fs::write(dir.join("src/lib.rs"), "unsafe fn a() {}").unwrap();
        std::fs::write(dir.join("src/inner/b.rs"), "fn b() { unsafe {} }").unwrap();
        std::fs::write(dir.join("src/bad.rs"), "fn c() { \"").unwrap();
        let metadata = json!({
            "workspace_members": ["ws"],
            "packages": [
                {"id": "ws", "name": "own", "version": "0.1.0", "manifest_path": dir.join("Cargo.toml")},
                {"id": "p", "name": "dep", "version": "1.0.0", "manifest_path": dir.join("Cargo.toml")},
            ],
        });
        let inventory = unsafe_inventory(&metadata, crate::unsafe_code::count_unsafe);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(inventory, [("dep".to_owned(), "1.0.0".to_owned(), 2, 1)]);
    }

    #[test]
    fn lock_packages_skips_workspace_members() {
        let lock = "version = 4\n[[package]]\nname = \"xtask\"\nversion = \"0.1.0\"\n[[package]]\nname = \"syn\"\nversion = \"2.0.119\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        assert_eq!(
            lock_packages(lock).unwrap(),
            BTreeSet::from([("syn".to_owned(), "2.0.119".to_owned())])
        );
    }

    #[test]
    fn unsafe_changes_flag_big_new_crates_and_jumps() {
        let base = BTreeSet::from([
            ("same".to_owned(), "1.0.0".to_owned()),
            ("bumped".to_owned(), "1.0.0".to_owned()),
            ("replaced".to_owned(), "1.0.0".to_owned()),
            ("gone".to_owned(), "1.0.0".to_owned()),
        ]);
        let current = vec![
            ("same".to_owned(), "1.0.0".to_owned(), 500, 0),
            ("bumped".to_owned(), "1.0.0".to_owned(), 10, 0),
            ("bumped".to_owned(), "2.0.0".to_owned(), 200, 0),
            ("replaced".to_owned(), "2.0.0".to_owned(), 150, 0),
            ("small".to_owned(), "0.1.0".to_owned(), 3, 0),
            ("big".to_owned(), "0.1.0".to_owned(), 101, 0),
        ];
        let changes = unsafe_changes(&base, &current);
        let lines: Vec<(&str, bool)> = changes
            .iter()
            .map(|c| (c.line.as_str(), c.big_jump))
            .collect();
        assert_eq!(
            lines,
            [
                ("changed: `bumped` 1.0.0 -> 2.0.0, `unsafe` 10 -> 200", true),
                ("changed: `replaced` 1.0.0 -> 2.0.0, now 150 `unsafe`", true),
                ("new: `small` 0.1.0, 3 `unsafe`", false),
                ("new: `big` 0.1.0, 101 `unsafe`", true),
                ("removed: `gone` 1.0.0", false),
            ]
        );
    }

    #[test]
    fn dates_and_ids_are_validated() {
        assert!(is_date("2026-02-28"));
        assert!(!is_date("2026-2-28"));
        assert!(!is_date("2026-00-10"));
        assert!(!is_date("26-01-01"));
        assert!(is_advisory_id("RUSTSEC-2023-0071"));
        assert!(is_advisory_id("GHSA-abcd-1234-efgh"));
        assert!(!is_advisory_id("RUSTSEC-23-71"));
    }

    #[test]
    fn civil_dates_are_correct() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_781), (2026, 11, 24));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn this_repository_passes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let deny = std::fs::read_to_string(root.join("deny.toml")).unwrap();
        assert_eq!(
            check_deny_toml(&deny, &today_utc().unwrap()).unwrap(),
            Vec::<String>::new()
        );
        let vet = std::fs::read_to_string(root.join("supply-chain/config.toml")).unwrap();
        let members: Vec<String> = SAFE_TO_DEPLOY
            .iter()
            .chain(SAFE_TO_RUN)
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            check_vet_config(&vet, &members).unwrap(),
            Vec::<String>::new()
        );
    }
}
