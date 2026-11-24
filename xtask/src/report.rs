//! `cargo xtask deps-report [--base <commit>]`: the dependency report shown
//! on the CI job summary.
//!
//! It lists duplicate versions, the number of third-party crates each
//! workspace crate reaches at run time, the `unsafe` keyword count of every
//! third-party crate, and the crates whose build scripts or proc-macros run
//! at build time. With `--base`, it reports only when `Cargo.lock` changed
//! since that commit, and adds `cargo tree -d` and the change in `unsafe`
//! counts, flagging big jumps (#23).

use std::{path::Path, process::Command};

use serde_json::Value;

use crate::{deps, supply_chain, unsafe_code};

/// Builds the report. `base_lock` is `Cargo.lock` at the base commit, and
/// `tree_duplicates` the output of `cargo tree -d`; both only with `--base`.
/// Returns the Markdown and the warnings to print as workflow commands.
pub fn render(
    metadata: &Value,
    base_lock: Option<&str>,
    tree_duplicates: Option<&str>,
    base_count: impl Fn(&str, &str) -> Option<usize>,
) -> Result<(String, Vec<String>), String> {
    let mut out = String::from("## Dependency report\n\n");
    let mut warnings = Vec::new();

    let dups = supply_chain::duplicates(metadata)?;
    out.push_str(&format!(
        "### Duplicate versions ({} of a budget of {})\n\n",
        dups.len(),
        supply_chain::DUPLICATE_BUDGET
    ));
    for (name, versions) in &dups {
        let versions: Vec<&str> = versions.iter().map(String::as_str).collect();
        out.push_str(&format!("- `{name}`: {}\n", versions.join(", ")));
    }
    if dups.is_empty() {
        out.push_str("None.\n");
    }
    if let Some(tree) = tree_duplicates {
        out.push_str(&format!(
            "\n<details><summary><code>cargo tree -d</code></summary>\n\n```text\n{}\n```\n\n</details>\n",
            tree.trim_end().replace("```", "'''")
        ));
    }

    out.push_str(
        "\n### Third-party crates per workspace crate (runtime, all platforms)\n\n| Crate | Third-party crates |\n|---|---|\n",
    );
    for (name, count) in deps::runtime_third_party_counts(metadata)? {
        out.push_str(&format!("| `{name}` | {count} |\n"));
    }

    let inventory = supply_chain::unsafe_inventory(metadata, unsafe_code::count_unsafe);
    if let Some(base_lock) = base_lock {
        let changes = supply_chain::unsafe_changes(
            &supply_chain::lock_packages(base_lock)?,
            &inventory,
            base_count,
        );
        out.push_str(&format!(
            "\n### Change in third-party `unsafe` against the base branch\n\nFlagged: a new crate with more than {jump} `unsafe` keywords, or a new version with more than {jump} more than the version it replaces. Old counts come from the base commit's own locked packages.\n\n",
            jump = supply_chain::UNSAFE_JUMP
        ));
        if changes.is_empty() {
            out.push_str("No crate was added, removed or changed version.\n");
        }
        for change in &changes {
            let mark = if change.big_jump {
                " **(big jump)**"
            } else {
                ""
            };
            out.push_str(&format!("- {}{mark}\n", change.line));
            if change.big_jump {
                warnings.push(format!(
                    "::warning title=Big unsafe increase::{}",
                    change.line.replace(['`', '\n', '\r', '%'], "")
                ));
            }
        }
    }

    let total: usize = inventory.iter().map(|(_, _, n, _)| n).sum();
    out.push_str(&format!(
        "\n### `unsafe` in third-party crates ({total} keywords in {} crates)\n\nCounted as tokens in each crate's `.rs` files (all platforms, tests and examples included), so comments and strings do not count. Workspace crates are covered by `check-unsafe` instead.\n\n| Crate | Version | `unsafe` | Unreadable files |\n|---|---|---|---|\n",
        inventory.len()
    ));
    for (name, version, count, unreadable) in &inventory {
        out.push_str(&format!(
            "| `{name}` | {version} | {count} | {unreadable} |\n"
        ));
    }

    let build = supply_chain::build_time_code(metadata);
    out.push_str(&format!(
        "\n### Code that runs at build time ({} crates)\n\n",
        build.len()
    ));
    for (name, version, kinds) in build {
        out.push_str(&format!("- `{name}` {version}: {kinds}\n"));
    }
    Ok((out, warnings))
}

/// A file's content at a commit (`git show <commit>:<path>`).
pub fn git_show(root: &Path, commit: &str, path: &str) -> Result<String, String> {
    if commit.is_empty() || commit.starts_with('-') || commit.contains(':') {
        return Err(format!("not a commit: `{commit}`"));
    }
    let output = Command::new("git")
        .arg("show")
        .arg(format!("{commit}:{path}"))
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run git show: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git show {commit}:{path} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{path} at {commit} is not UTF-8"))
}

/// `cargo metadata` for the base commit, from a temporary git worktree of it
/// (detached, removed again before returning). `metadata` runs cargo
/// metadata in a directory.
///
/// The worktree goes inside a new directory under `target/`, which only this
/// user can write to on Unix and whose name includes the process ID and the
/// time, so another local user cannot prepare or swap it.
pub fn base_metadata(
    root: &Path,
    commit: &str,
    metadata: impl FnOnce(&Path) -> Result<Value, String>,
) -> Result<Value, String> {
    if commit.is_empty() || commit.starts_with('-') || commit.contains(':') {
        return Err(format!("not a commit: `{commit}`"));
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let parent = root
        .join("target")
        .join(format!("xtask-base-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(root.join("target"))
        .map_err(|e| format!("cannot create target/: {e}"))?;
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    // `create`, not `create_all`: fails if the directory already exists.
    builder
        .create(&parent)
        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    let dir = parent.join("base");
    let git = |args: &[&std::ffi::OsStr]| -> Result<(), String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|e| format!("cannot run git: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "git worktree failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    };
    let os = std::ffi::OsStr::new;
    let added = git(&[
        os("worktree"),
        os("add"),
        os("--detach"),
        os("--quiet"),
        dir.as_os_str(),
        os(commit),
    ]);
    let result = added.and_then(|()| metadata(&dir));
    let removed = git(&[os("worktree"), os("remove"), os("--force"), dir.as_os_str()])
        .or_else(|e| if dir.exists() { Err(e) } else { Ok(()) });
    let cleaned = std::fs::remove_dir_all(&parent)
        .or_else(|e| if parent.exists() { Err(e) } else { Ok(()) })
        .map_err(|e| format!("cannot remove {}: {e}", parent.display()));
    let value = result?;
    removed?;
    cleaned?;
    Ok(value)
}

/// `cargo tree --duplicates` over the whole workspace, every platform.
pub fn cargo_tree_duplicates(root: &Path) -> Result<String, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--duplicates",
            "--locked",
            "--workspace",
            "--all-features",
            "--target",
            "all",
            "--color",
            "never",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run cargo tree: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn metadata() -> Value {
        json!({
            "workspace_members": ["ws"],
            "packages": [
                {"id": "ws", "name": "xtask", "version": "0.1.0", "targets": [], "manifest_path": "/nonexistent/ws/Cargo.toml"},
                {"id": "a", "name": "syn", "version": "2.0.0", "targets": [{"kind": ["lib"]}], "manifest_path": "/nonexistent/a/Cargo.toml"},
                {"id": "b", "name": "syn", "version": "3.0.0", "targets": [{"kind": ["lib"]}], "manifest_path": "/nonexistent/b/Cargo.toml"},
            ],
            "resolve": {"nodes": [
                {"id": "ws", "deps": [{"pkg": "a", "dep_kinds": [{"kind": null}]}]},
                {"id": "a", "deps": []},
                {"id": "b", "deps": []},
            ]},
        })
    }

    #[test]
    fn report_without_base_has_every_section_but_the_diff() {
        let (md, warnings) = render(&metadata(), None, None, |_, _| None).unwrap();
        assert!(
            md.contains("### Duplicate versions (1 of a budget of 10)"),
            "{md}"
        );
        assert!(md.contains("- `syn`: 2.0.0, 3.0.0"), "{md}");
        assert!(md.contains("| `xtask` | 1 |"), "{md}");
        assert!(md.contains("### `unsafe` in third-party crates"), "{md}");
        assert!(
            md.contains("### Code that runs at build time (0 crates)"),
            "{md}"
        );
        assert!(!md.contains("Change in third-party"), "{md}");
        assert!(!md.contains("cargo tree -d"), "{md}");
        assert!(warnings.is_empty());
    }

    #[test]
    fn report_with_base_adds_tree_and_unsafe_changes() {
        let base = "version = 4\n[[package]]\nname = \"old\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\n";
        let (md, _) = render(
            &metadata(),
            Some(base),
            Some("syn v2.0.0\n```\n"),
            |_, _| None,
        )
        .unwrap();
        assert!(
            md.contains("<summary><code>cargo tree -d</code></summary>"),
            "{md}"
        );
        assert!(md.contains("syn v2.0.0\n'''"), "{md}");
        assert!(md.contains("- new: `syn` 2.0.0, 0 `unsafe`"), "{md}");
        assert!(md.contains("- new: `syn` 3.0.0, 0 `unsafe`"), "{md}");
        assert!(md.contains("- removed: `old` 1.0.0"), "{md}");
    }

    #[test]
    fn base_metadata_checks_out_the_commit_and_cleans_up() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if !root.join(".git").exists() {
            return;
        }
        for bad in ["", "--output=/tmp/x", "HEAD:Cargo.toml"] {
            assert!(
                base_metadata(&root, bad, |_| Ok(Value::Null)).is_err(),
                "{bad}"
            );
        }
        let mut seen = None;
        let value = base_metadata(&root, "HEAD", |dir| {
            assert!(dir.join("Cargo.lock").is_file());
            seen = Some(dir.to_path_buf());
            Ok(Value::Bool(true))
        });
        assert_eq!(value.unwrap(), Value::Bool(true));
        let dir = seen.unwrap();
        assert!(!dir.exists());
        assert!(!dir.parent().unwrap().exists());
        // The callback's error is returned, and the worktree is still removed.
        let mut seen = None;
        let err = base_metadata(&root, "HEAD", |dir| {
            seen = Some(dir.to_path_buf());
            Err("boom".to_owned())
        });
        assert_eq!(err.unwrap_err(), "boom");
        assert!(!seen.unwrap().exists());
    }

    #[test]
    fn git_show_rejects_option_like_commits() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(git_show(root, "--output=/tmp/x", "Cargo.lock").is_err());
        assert!(git_show(root, "HEAD:Cargo.toml", "Cargo.lock").is_err());
        assert!(git_show(root, "", "Cargo.lock").is_err());
    }
}
