//! `cargo xtask check-supply-chain`: the dependency rules from #23 that
//! cargo-deny and cargo-vet do not check themselves.
//!
//! - **Duplicate budget.** The resolved graph may hold at most
//!   [`DUPLICATE_BUDGET`] crates that appear in more than one version.
//!   cargo-deny only warns about duplicates (`multiple-versions = "warn"`).
//! - **Advisory ignores.** Every `[advisories] ignore` entry in `deny.toml`
//!   is a table with an advisory `id`, a `reason`, and an `expiry` date
//!   (`YYYY-MM-DD`), the key cargo-deny itself reads. An expired entry fails
//!   here even before cargo-deny next sees the advisory, so an ignore cannot
//!   outlive its review date. `deny.toml` is the only place advisories are
//!   ignored: `cargo xtask audit` passes the same IDs to cargo-audit, and
//!   no `audit.toml` may exist in the repository.
//! - **Skips need a reason.** Every `[bans] skip` and `skip-tree` entry is a
//!   table with a non-empty `reason`. cargo-deny's `[licenses] exceptions`
//!   schema has no `reason` key, so each exception needs a `# reason:`
//!   comment on the line above it instead.
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

/// Names of every workspace member, straight from `cargo metadata`, so a
/// crate with no library or binary target is not missed.
pub fn member_names(metadata: &Value) -> Result<Vec<String>, String> {
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .ok_or("cargo metadata: missing workspace_members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut names: Vec<String> = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata: missing packages")?
        .iter()
        .filter(|p| members.contains(p["id"].as_str().unwrap_or_default()))
        .filter_map(|p| p["name"].as_str().map(str::to_owned))
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// The registry source directories holding the third-party packages (the
/// parents of their package directories).
pub fn registry_dirs(metadata: &Value) -> Vec<std::path::PathBuf> {
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let dirs: BTreeSet<std::path::PathBuf> = metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| !members.contains(p["id"].as_str().unwrap_or_default()))
        .filter_map(|p| {
            let manifest = std::path::Path::new(p["manifest_path"].as_str()?);
            Some(manifest.parent()?.parent()?.to_path_buf())
        })
        .collect();
    dirs.into_iter().collect()
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
                "{at} must be a table with `id`, `reason` and `expiry`, not a bare ID"
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
        match entry.get("expiry").and_then(toml::Value::as_str) {
            Some(date) if is_date(date) => {
                // ISO dates compare correctly as strings.
                if date < today {
                    v.push(format!(
                        "{at} ({id}): expired on {date}; review the advisory and renew or remove the ignore"
                    ));
                }
            }
            _ => v.push(format!(
                "{at} ({id}): needs `expiry = \"YYYY-MM-DD\"`, the date it must be reviewed by"
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
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len);
    let commented = exception_reason_comments(source);
    if commented < exceptions {
        v.push(format!(
            "deny.toml: licenses.exceptions has {exceptions} entries but {commented} `# reason:` comments; put one on the line above each entry"
        ));
    }
    Ok(v)
}

/// Advisory IDs ignored in `deny.toml`, to pass to cargo-audit as
/// `--ignore`, so both tools ignore exactly the same advisories.
pub fn ignored_advisories(source: &str) -> Result<Vec<String>, String> {
    let deny: Table = source
        .parse()
        .map_err(|e| format!("deny.toml: invalid TOML: {e}"))?;
    Ok(deny
        .get("advisories")
        .and_then(|a| a.get("ignore"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("id").and_then(toml::Value::as_str))
        .filter(|id| is_advisory_id(id))
        .map(str::to_owned)
        .collect())
}

/// `# reason:` comment lines inside the `exceptions = [ ... ]` array of the
/// `[licenses]` table.
fn exception_reason_comments(source: &str) -> usize {
    let mut in_licenses = false;
    let mut in_exceptions = false;
    let mut count = 0;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") && !in_exceptions {
            in_licenses = trimmed == "[licenses]";
            continue;
        }
        if in_licenses && !in_exceptions && trimmed.starts_with("exceptions") {
            in_exceptions = !trimmed.ends_with(']');
            continue;
        }
        if in_exceptions {
            if trimmed.starts_with("# reason:") && trimmed.len() > "# reason:".len() {
                count += 1;
            }
            if trimmed == "]" {
                in_exceptions = false;
            }
        }
    }
    count
}

/// Repository-relative paths of tracked files named `audit.toml` (cargo-audit
/// config), which must not exist: advisory ignores live in `deny.toml` only.
pub fn check_no_audit_toml(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| {
            p.rsplit('/')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("audit.toml"))
        })
        .map(|p| {
            format!(
                "{p}: cargo-audit configuration is not allowed; ignore advisories in deny.toml, which `cargo xtask audit` passes to cargo-audit"
            )
        })
        .collect()
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
    for (name, entry) in policy.into_iter().flatten() {
        if !members.iter().any(|m| m == name) {
            v.push(format!(
                "supply-chain/config.toml: [policy.{name}] is not a workspace crate; third-party criteria come only from audits and noted exemptions"
            ));
            continue;
        }
        let allowed = ["criteria", "dev-criteria", "notes"];
        for key in entry.as_table().into_iter().flatten().map(|(k, _)| k) {
            if !allowed.contains(&key.as_str()) {
                v.push(format!(
                    "supply-chain/config.toml: [policy.{name}] must not set `{key}`, which can lower what its dependencies need"
                ));
            }
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
        let (total, unreadable) = count_dir(dir, &count);
        out.push((
            package["name"].as_str().unwrap_or_default().to_owned(),
            package["version"].as_str().unwrap_or_default().to_owned(),
            total,
            unreadable,
        ));
    }
    out.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.cmp(&b.1))
    });
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

/// Compares the base branch's locked packages with the current graph.
/// `current` is the `unsafe` inventory of the current graph; `base_count`
/// gives the `unsafe` count of a base package (`None` when its source is not
/// available locally). Versions are matched per crate: the removed and the
/// added versions of a crate are each sorted by version and paired in order,
/// so a bump in one of two duplicate versions is compared with the version
/// it replaced. Unpaired versions are reported as added or removed.
pub fn unsafe_changes(
    base: &BTreeSet<(String, String)>,
    current: &[(String, String, usize, usize)],
    base_count: impl Fn(&str, &str) -> Option<usize>,
) -> Vec<UnsafeChange> {
    let names: BTreeSet<&str> = base
        .iter()
        .map(|(n, _)| n.as_str())
        .chain(current.iter().map(|(n, _, _, _)| n.as_str()))
        .collect();
    let mut out = Vec::new();
    for name in names {
        let mut before: Vec<&str> = base
            .iter()
            .filter(|(n, v)| n == name && !current.iter().any(|(cn, cv, _, _)| cn == n && cv == v))
            .map(|(_, v)| v.as_str())
            .collect();
        let mut after: Vec<(&str, usize)> = current
            .iter()
            .filter(|(n, v, _, _)| n == name && !base.contains(&(n.clone(), v.clone())))
            .map(|(_, v, c, _)| (v.as_str(), *c))
            .collect();
        before.sort_by_key(|v| version_key(v));
        after.sort_by_key(|(v, _)| version_key(v));
        let pairs = before.len().min(after.len());
        for (old, (new, count)) in before.iter().zip(after.iter()) {
            let (old, new, count) = (*old, *new, *count);
            let (line, big_jump) = match base_count(name, old) {
                Some(was) => (
                    format!("changed: `{name}` {old} -> {new}, `unsafe` {was} -> {count}"),
                    count.saturating_sub(was) > UNSAFE_JUMP,
                ),
                // Without the old source, a bump is not flagged: it would
                // warn on every patch release of a large crate.
                None => (
                    format!(
                        "changed: `{name}` {old} -> {new}, now {count} `unsafe` (old count not available)"
                    ),
                    false,
                ),
            };
            out.push(UnsafeChange { line, big_jump });
        }
        for (new, count) in after.iter().skip(pairs) {
            out.push(UnsafeChange {
                line: format!("new: `{name}` {new}, {count} `unsafe`"),
                big_jump: *count > UNSAFE_JUMP,
            });
        }
        for old in before.iter().skip(pairs) {
            out.push(UnsafeChange {
                line: format!("removed: `{name}` {old}"),
                big_jump: false,
            });
        }
    }
    out
}

/// A sort key for a version such as `1.0.107` or `1.0.1+wasi-0.2.4`: the
/// numeric parts of the `MAJOR.MINOR.PATCH` core, then the rest as text.
fn version_key(version: &str) -> (Vec<u64>, String) {
    let core = version.split(['-', '+']).next().unwrap_or(version);
    (
        core.split('.').map(|p| p.parse().unwrap_or(0)).collect(),
        version.to_owned(),
    )
}

/// `(unsafe keywords, unreadable entries)` in the `.rs` files under `dir`.
/// Symbolic links are never followed; they and entries that cannot be read
/// are counted as unreadable.
pub fn count_dir(dir: &std::path::Path, count: &dyn Fn(&str) -> Option<usize>) -> (usize, usize) {
    let (mut total, mut unreadable) = (0, 0);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            unreadable += 1;
            continue;
        };
        for entry in entries {
            // `file_type` does not follow symbolic links, so a link in an
            // unpacked crate can neither loop the walk nor lead it out of
            // the crate.
            let Ok((path, file_type)) = entry.and_then(|e| Ok((e.path(), e.file_type()?))) else {
                unreadable += 1;
                continue;
            };
            if file_type.is_symlink() {
                unreadable += 1;
            } else if file_type.is_dir() {
                stack.push(path);
            } else if crate::unsafe_code::is_rust_path(&path.to_string_lossy()) {
                match std::fs::read_to_string(&path)
                    .ok()
                    .as_deref()
                    .and_then(count)
                {
                    Some(n) => total += n,
                    None => unreadable += 1,
                }
            }
        }
    }
    (total, unreadable)
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
    let (Some(y), Some(m), Some(d)) = (number(y, 4), number(m, 2), number(d, 2)) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d)
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
ignore = [{ id = "RUSTSEC-2024-0001", reason = "not reachable", expiry = "2026-12-31" }]
[bans]
skip = [{ crate = "syn@2.0.119", reason = "proc-macro2 still on syn 2" }]
skip-tree = []
[licenses]
exceptions = [
    # reason: dev tool only, never shipped
    { crate = "x", allow = ["GPL-3.0"] },
]
"#;
        assert_eq!(
            check_deny_toml(deny, "2026-11-24").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn expired_ignore_fails_on_the_day_after() {
        let deny = r#"[advisories]
ignore = [{ id = "RUSTSEC-2024-0001", reason = "r", expiry = "2026-11-23" }]"#;
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
    { id = "RUSTSEC-2024-0003", expiry = "2027-01-01" },
    { id = "bogus", reason = "r", expiry = "2027-01-01" },
    { id = "GHSA-abcd-1234-efgh", reason = "r", expiry = "2027-13-01" },
]"#;
        let v = check_deny_toml(deny, "2026-11-24").unwrap();
        assert_eq!(v.len(), 5, "{v:?}");
        assert!(v[0].contains("not a bare ID"));
        assert!(v[1].contains("needs `expiry"));
        assert!(v[2].contains("needs a non-empty `reason`"));
        assert!(v[3].contains("not `bogus`"));
        assert!(v[4].contains("needs `expiry"));
    }

    #[test]
    fn skips_and_exceptions_without_reason_fail() {
        let deny = r#"
[bans]
skip = ["syn@2.0.119", { crate = "a", reason = " " }]
skip-tree = [{ crate = "b" }]
[licenses]
exceptions = [
    # a comment that is not a reason
    { crate = "x", allow = ["GPL-3.0"] },
]
"#;
        let v = check_deny_toml(deny, "2026-11-24").unwrap();
        assert_eq!(v.len(), 4, "{v:?}");
        assert!(
            v[3].contains("1 entries but 0 `# reason:` comments"),
            "{v:?}"
        );
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

    fn inv(entries: &[(&str, &str, usize)]) -> Vec<(String, String, usize, usize)> {
        entries
            .iter()
            .map(|(n, v, c)| ((*n).to_owned(), (*v).to_owned(), *c, 0))
            .collect()
    }

    fn base(entries: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        entries
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn lines(changes: &[UnsafeChange]) -> Vec<(&str, bool)> {
        changes
            .iter()
            .map(|c| (c.line.as_str(), c.big_jump))
            .collect()
    }

    #[test]
    fn bumps_compare_with_the_replaced_version_when_its_source_is_known() {
        let base = base(&[("libc", "0.2.191"), ("same", "1.0.0")]);
        let current = inv(&[("libc", "0.2.192", 801), ("same", "1.0.0", 500)]);
        let known = |_: &str, _: &str| Some(800);
        assert_eq!(
            lines(&unsafe_changes(&base, &current, known)),
            [(
                "changed: `libc` 0.2.191 -> 0.2.192, `unsafe` 800 -> 801",
                false
            )]
        );
        let jump = |_: &str, _: &str| Some(10);
        assert!(unsafe_changes(&base, &current, jump)[0].big_jump);
    }

    #[test]
    fn a_bump_without_the_old_source_is_not_a_false_alarm() {
        let base = base(&[("libc", "0.2.191")]);
        let current = inv(&[("libc", "0.2.192", 801)]);
        let changes = unsafe_changes(&base, &current, |_, _| None);
        assert_eq!(
            lines(&changes),
            [(
                "changed: `libc` 0.2.191 -> 0.2.192, now 801 `unsafe` (old count not available)",
                false
            )]
        );
    }

    #[test]
    fn duplicate_versions_are_paired_and_removals_reported() {
        // One of two duplicates bumps: compared with the one it replaced.
        let base1 = base(&[("syn", "2.0.119"), ("syn", "3.0.10")]);
        let current = inv(&[("syn", "2.0.119", 50), ("syn", "3.0.11", 60)]);
        let count = |_: &str, v: &str| (v == "3.0.10").then_some(55);
        assert_eq!(
            lines(&unsafe_changes(&base1, &current, count)),
            [("changed: `syn` 3.0.10 -> 3.0.11, `unsafe` 55 -> 60", false)]
        );
        // One duplicate is dropped while the other stays.
        let current = inv(&[("syn", "3.0.10", 60)]);
        assert_eq!(
            lines(&unsafe_changes(&base1, &current, |_, _| None)),
            [("removed: `syn` 2.0.119", false)]
        );
    }

    #[test]
    fn new_crates_are_flagged_above_the_threshold() {
        let current = inv(&[("big", "0.1.0", 101), ("small", "0.1.0", 3)]);
        assert_eq!(
            lines(&unsafe_changes(
                &base(&[("gone", "1.0.0")]),
                &current,
                |_, _| None
            )),
            [
                ("new: `big` 0.1.0, 101 `unsafe`", true),
                ("removed: `gone` 1.0.0", false),
                ("new: `small` 0.1.0, 3 `unsafe`", false),
            ]
        );
    }

    #[test]
    fn ignored_advisories_and_audit_toml() {
        let deny = r#"[advisories]
ignore = [{ id = "RUSTSEC-2024-0001", reason = "r", expiry = "2027-01-01" }, { id = "bad" }]"#;
        assert_eq!(ignored_advisories(deny).unwrap(), ["RUSTSEC-2024-0001"]);
        let paths = [
            ".cargo/audit.toml".to_owned(),
            "crates/x/.cargo/Audit.TOML".to_owned(),
            "docs/audit.toml.md".to_owned(),
        ];
        assert_eq!(check_no_audit_toml(&paths).len(), 2);
    }

    #[test]
    fn vet_policy_cannot_lower_dependency_criteria() {
        let members = ["palisade-core".to_owned()];
        let config = r#"
[policy.palisade-core]
criteria = "safe-to-deploy"
dev-criteria = "safe-to-run"
dependency-criteria = { serde = [] }
[policy.serde]
criteria = "safe-to-run"
audit-as-crates-io = false
"#;
        let v = check_vet_config(config, &members).unwrap();
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v[0].contains("must not set `dependency-criteria`"), "{v:?}");
        assert!(
            v[1].contains("[policy.serde] is not a workspace crate"),
            "{v:?}"
        );
    }

    #[test]
    fn unsafe_inventory_does_not_follow_symlinks() {
        let dir = std::env::temp_dir().join(format!("xtask-unsafe-link-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "").unwrap();
        std::fs::write(dir.join("src/LIB.RS"), "unsafe fn a() {}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("..", dir.join("src/loop")).unwrap();
        let metadata = json!({
            "workspace_members": [],
            "packages": [{"id": "p", "name": "dep", "version": "1.0.0", "manifest_path": dir.join("Cargo.toml")}],
        });
        let inventory = unsafe_inventory(&metadata, crate::unsafe_code::count_unsafe);
        std::fs::remove_dir_all(&dir).unwrap();
        let unreadable = usize::from(cfg!(unix));
        assert_eq!(
            inventory,
            [("dep".to_owned(), "1.0.0".to_owned(), 1, unreadable)]
        );
    }

    #[test]
    fn dates_and_ids_are_validated() {
        assert!(is_date("2026-02-28"));
        assert!(is_date("2028-02-29"));
        assert!(!is_date("2026-02-29"));
        assert!(!is_date("2026-02-31"));
        assert!(!is_date("2026-04-31"));
        assert!(is_date("2000-02-29"));
        assert!(!is_date("1900-02-29"));
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
