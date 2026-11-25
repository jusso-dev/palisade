//! `cargo xtask check-fuzz-locks`: every fuzz workspace's committed
//! `Cargo.lock` is current.
//!
//! Each `crates/*/fuzz/` directory is its own Cargo workspace with its own
//! lockfile. A pull request that adds or changes a dependency of a crate a
//! fuzz workspace builds (even indirectly, through a path dependency) leaves
//! that lockfile stale, and the `fuzz` job only finds out after minutes of
//! setup. This check runs `cargo metadata --locked` on each fuzz manifest,
//! which fails in about a second when the lockfile would have to change.
//!
//! The fuzz workspaces are found on disk, not read from
//! [`crate::fuzz::PROJECTS`], so a new one is checked even before it is
//! listed there.

use std::path::Path;
use std::process::Command;

/// Every `crates/<name>/fuzz/Cargo.toml` under `root`, relative to it, with
/// forward slashes, sorted.
pub fn fuzz_manifests(root: &Path) -> Result<Vec<String>, String> {
    let crates = root.join("crates");
    let entries =
        std::fs::read_dir(&crates).map_err(|e| format!("cannot read {}: {e}", crates.display()))?;
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", crates.display()))?;
        if entry.path().join("fuzz").join("Cargo.toml").is_file() {
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                format!("{}: crate directory name is not UTF-8", crates.display())
            })?;
            found.push(format!("crates/{name}/fuzz/Cargo.toml"));
        }
    }
    found.sort();
    Ok(found)
}

/// The command that brings a stale fuzz lockfile up to date with the fewest
/// changes: Cargo resolves only what changed and upgrades nothing else.
/// (`cargo update` would upgrade every package in the lockfile.)
pub fn relock_command(manifest: &str) -> String {
    format!("cargo metadata --format-version 1 --manifest-path {manifest} > /dev/null")
}

/// Checks each manifest with `locked`, which returns `Ok(None)` when the
/// lockfile is current and `Ok(Some(message))` with Cargo's error when it is
/// not. Returns one violation per stale lockfile. An `Err` from `locked`
/// (Cargo could not be run) is returned as is.
pub fn check(
    manifests: &[String],
    mut locked: impl FnMut(&str) -> Result<Option<String>, String>,
) -> Result<Vec<String>, String> {
    let mut violations = Vec::new();
    for manifest in manifests {
        if let Some(message) = locked(manifest)? {
            let lockfile = manifest.trim_end_matches("Cargo.toml");
            violations.push(format!(
                "{lockfile}Cargo.lock is out of date ({}). Re-lock it without upgrading anything, \
                 then commit it:\n    {}",
                last_error_line(&message),
                relock_command(manifest)
            ));
        }
    }
    Ok(violations)
}

/// The last `error:` line of Cargo's output, or its last non-empty line.
fn last_error_line(stderr: &str) -> &str {
    let lines = || stderr.lines().map(str::trim).filter(|l| !l.is_empty());
    lines()
        .rfind(|l| l.starts_with("error"))
        .or_else(|| lines().next_back())
        .unwrap_or("cargo metadata --locked failed")
}

/// Runs `cargo metadata --locked` on `manifest`, relative to `root`.
pub fn cargo_metadata_locked(root: &Path, manifest: &str) -> Result<Option<String>, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--locked", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(root.join(manifest))
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if output.status.success() {
        Ok(None)
    } else {
        Ok(Some(String::from_utf8_lossy(&output.stderr).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    #[test]
    fn finds_every_fuzz_workspace_in_the_repository() {
        let found = fuzz_manifests(&repo()).unwrap();
        assert!(
            found.contains(&"crates/palisade-fileid/fuzz/Cargo.toml".to_owned()),
            "{found:?}"
        );
        // The same set the fuzz runner lists, so both checks see every project.
        let mut listed: Vec<String> = crate::fuzz::PROJECTS
            .iter()
            .map(|p| format!("{}/Cargo.toml", p.dir))
            .collect();
        listed.sort();
        assert_eq!(found, listed);
    }

    #[test]
    fn stale_lockfiles_are_reported_with_the_minimal_fix() {
        let manifests = vec![
            "crates/a/fuzz/Cargo.toml".to_owned(),
            "crates/b/fuzz/Cargo.toml".to_owned(),
        ];
        let violations = check(&manifests, |m| {
            Ok(m.contains("/b/").then(|| {
                "    Updating crates.io index\nerror: the lock file crates/b/fuzz/Cargo.lock \
                 needs to be updated but --locked was passed to prevent this\n"
                    .to_owned()
            }))
        })
        .unwrap();
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(
            violations[0]
                .starts_with("crates/b/fuzz/Cargo.lock is out of date (error: the lock file"),
            "{}",
            violations[0]
        );
        assert!(
            violations[0].ends_with(
                "cargo metadata --format-version 1 --manifest-path crates/b/fuzz/Cargo.toml > /dev/null"
            ),
            "{}",
            violations[0]
        );
        assert!(check(&manifests, |_| Ok(None)).unwrap().is_empty());
        assert!(check(&manifests, |_| Err("no cargo".to_owned())).is_err());
    }

    #[test]
    fn the_error_line_falls_back_to_the_last_line() {
        assert_eq!(last_error_line("a\nerror: x\nnote: y\n"), "error: x");
        assert_eq!(last_error_line("a\n  b  \n\n"), "b");
        assert_eq!(last_error_line(""), "cargo metadata --locked failed");
    }

    /// A throwaway workspace under `target/`, removed on drop.
    struct TempWorkspace(PathBuf);

    impl Drop for TempWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// End to end with real Cargo, offline: a fuzz workspace that reaches a
    /// crate through a path dependency goes stale when that crate gains a
    /// dependency, as happens when a PR adds one to a parser crate.
    #[test]
    fn cargo_metadata_locked_detects_a_stale_lockfile() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let root = repo()
            .join("target")
            .join(format!("xtask-fuzz-locks-{}-{nanos}", std::process::id()));
        let _cleanup = TempWorkspace(root.clone());
        let package = |name: &str, deps: &str| {
            format!(
                "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
                 publish = false\n\n[dependencies]\n{deps}"
            )
        };
        write(&root.join("crates/leaf/Cargo.toml"), &package("leaf", ""));
        write(&root.join("crates/leaf/src/lib.rs"), "");
        write(
            &root.join("crates/parser/Cargo.toml"),
            &package("parser", ""),
        );
        write(&root.join("crates/parser/src/lib.rs"), "");
        let fuzz = format!(
            "{}\n[workspace]\nmembers = [\".\"]\n",
            package("parser-fuzz", "parser = { path = \"..\" }\n")
        );
        write(&root.join("crates/parser/fuzz/Cargo.toml"), &fuzz);
        write(&root.join("crates/parser/fuzz/src/lib.rs"), "");
        // Each test crate is its own workspace, not part of the repository's.
        for dir in ["crates/leaf", "crates/parser"] {
            let path = root.join(dir).join("Cargo.toml");
            let text = std::fs::read_to_string(&path).unwrap();
            write(&path, &format!("{text}\n[workspace]\n"));
        }

        let manifests = fuzz_manifests(&root).unwrap();
        assert_eq!(manifests, ["crates/parser/fuzz/Cargo.toml"]);
        let manifest = manifests[0].as_str();
        // No lockfile yet: `--locked` refuses to create one.
        assert!(cargo_metadata_locked(&root, manifest).unwrap().is_some());
        // The re-lock command writes it; then the check passes.
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(&cargo)
            .args(["metadata", "--format-version", "1", "--manifest-path"])
            .arg(root.join(manifest))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(root.join("crates/parser/fuzz/Cargo.lock").is_file());
        assert_eq!(cargo_metadata_locked(&root, manifest).unwrap(), None);
        assert!(
            check(&manifests, |m| cargo_metadata_locked(&root, m))
                .unwrap()
                .is_empty()
        );

        // The parser crate gains a dependency: the fuzz lockfile is stale.
        write(
            &root.join("crates/parser/Cargo.toml"),
            &format!(
                "{}\n[workspace]\n",
                package("parser", "leaf = { path = \"../leaf\" }\n")
            ),
        );
        let violations = check(&manifests, |m| cargo_metadata_locked(&root, m)).unwrap();
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(
            violations[0].starts_with("crates/parser/fuzz/Cargo.lock is out of date"),
            "{}",
            violations[0]
        );
    }
}
