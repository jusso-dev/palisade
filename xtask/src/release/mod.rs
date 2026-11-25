//! `cargo xtask release` and `cargo xtask sign`: the release pipeline's
//! steps (#24). `.github/workflows/release.yml` runs them; see
//! `docs/releasing.md`.
//!
//! ```text
//! cargo xtask release prepare <version>    bump the workspace version and add the CHANGELOG.md section
//! cargo xtask release check-tag <tag>      the tag is vX.Y.Z[-pre], annotated, signed, and matches Cargo.toml
//! cargo xtask release notes <version>      print the CHANGELOG.md section (the release notes)
//! cargo xtask release checksums <dir>      write <dir>/SHA256SUMS
//! cargo xtask release verify-checksums <dir>
//! cargo xtask release provenance           the provenance hook (#18, #226)
//! cargo xtask release verify <dir> [--allow-untimestamped]
//!                                          every PE and package in <dir>, and every PE inside
//!                                          each package, has a valid timestamped signature
//! cargo xtask sign --signer <kind> [--verify] [--no-timestamp] <file>...
//! ```

pub mod changelog;
pub mod checksums;
pub mod sign;

use std::path::Path;
use std::process::Command;

use crate::dist::version::Version;

/// A release tag: `v` and a SemVer version without build metadata, whose
/// pre-release part, if any, is `alpha.N`, `beta.N` or `rc.N`.
pub fn parse_tag(tag: &str) -> Result<Version, String> {
    let text = tag.strip_prefix('v').ok_or_else(|| {
        format!("tag `{tag}`: release tags are v<MAJOR>.<MINOR>.<PATCH>[-alpha.N|-beta.N|-rc.N]")
    })?;
    let version = Version::parse(text)?;
    if version.build.is_some() {
        return Err(format!("tag `{tag}`: no build metadata in release tags"));
    }
    if let Some(pre) = &version.pre {
        let ok = pre.split_once('.').is_some_and(|(kind, n)| {
            ["alpha", "beta", "rc"].contains(&kind)
                && !n.is_empty()
                && n.bytes().all(|b| b.is_ascii_digit())
                && (n == "0" || !n.starts_with('0'))
        });
        if !ok {
            return Err(format!(
                "tag `{tag}`: the pre-release part must be alpha.N, beta.N or rc.N"
            ));
        }
    }
    Ok(version)
}

/// Whether a version is a pre-release (published with the pre-release flag).
pub const fn is_prerelease(version: &Version) -> bool {
    version.pre.is_some()
}

/// The `workspace.package.version` in a root `Cargo.toml`.
pub fn workspace_version(manifest: &str) -> Result<String, String> {
    let table: toml::Table = manifest.parse().map_err(|e| format!("Cargo.toml: {e}"))?;
    table
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "Cargo.toml: no workspace.package.version".to_owned())
}

/// Replaces the `version = "..."` line of `[workspace.package]`, leaving
/// every other byte as it was.
pub fn set_workspace_version(manifest: &str, version: &str) -> Result<String, String> {
    let mut out = String::with_capacity(manifest.len());
    let mut in_package = false;
    let mut done = false;
    for line in manifest.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[workspace.package]";
        }
        if in_package && !done && trimmed.starts_with("version") && trimmed.contains('=') {
            // Keep the line's own ending (CRLF on a Windows checkout).
            let ending = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            out.push_str(&format!("version = \"{version}\"{ending}"));
            done = true;
        } else {
            out.push_str(line);
        }
    }
    if !done {
        return Err("Cargo.toml: no version line in [workspace.package]".to_owned());
    }
    if workspace_version(&out)? != version {
        return Err("Cargo.toml: the version line could not be replaced".to_owned());
    }
    Ok(out)
}

/// What `git cat-file -p <tag>` shows about a tag object.
#[derive(Debug, PartialEq, Eq)]
pub struct TagObject {
    pub object: String,
    pub signed: bool,
}

/// Parses `git cat-file -t` and `-p` output for a tag. A lightweight tag
/// (type `commit`) is refused.
pub fn parse_tag_object(kind: &str, body: &str) -> Result<TagObject, String> {
    if kind.trim() != "tag" {
        return Err(
            "the tag is lightweight; release tags must be annotated (git tag -s)".to_owned(),
        );
    }
    let object = body
        .lines()
        .find_map(|l| l.strip_prefix("object "))
        .ok_or("the tag object has no `object` line")?
        .to_owned();
    let signed = body.contains("-----BEGIN PGP SIGNATURE-----")
        || body.contains("-----BEGIN SSH SIGNATURE-----");
    Ok(TagObject { object, signed })
}

/// `release check-tag <tag>`: the tag's name, that it is annotated and
/// signed, and that `Cargo.toml` at the tagged commit has its version. The
/// signature's key is checked by GitHub's tag protection and by the
/// maintainer; a runner has no trusted keyring to check it against.
pub fn check_tag(root: &Path, tag: &str) -> Result<Version, String> {
    let version = parse_tag(tag)?;
    let git = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|e| format!("cannot run git: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        String::from_utf8(out.stdout).map_err(|_| "git output is not UTF-8".to_owned())
    };
    let reference = format!("refs/tags/{tag}");
    let kind = git(&["cat-file", "-t", &reference])?;
    let object = parse_tag_object(&kind, &git(&["cat-file", "-p", &reference])?)?;
    if !object.signed {
        return Err(format!(
            "tag {tag} is not signed; sign release tags (git tag -s, with GPG or SSH)"
        ));
    }
    let manifest = git(&["show", &format!("{}:Cargo.toml", object.object)])?;
    let declared = workspace_version(&manifest)?;
    if declared != version.to_string() {
        return Err(format!(
            "tag {tag} is version {version}, but Cargo.toml at that commit says {declared}"
        ));
    }
    Ok(version)
}

/// `release prepare <version>`: the new version in `Cargo.toml` and a new
/// `CHANGELOG.md` section from the commit subjects since the last release
/// tag. Returns the changelog section.
pub fn prepare(root: &Path, version: &str, date: &str) -> Result<String, String> {
    let parsed = parse_tag(&format!("v{version}"))?;
    let manifest_path = root.join("Cargo.toml");
    let manifest = read(&manifest_path)?;
    let current = Version::parse(&workspace_version(&manifest)?)?;
    if !newer(&parsed, &current) && parsed != current {
        return Err(format!(
            "{version} is not newer than the current version {current}"
        ));
    }
    let previous = Command::new("git")
        .args([
            "describe",
            "--tags",
            "--abbrev=0",
            "--match",
            "v[0-9]*",
            "HEAD",
        ])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned());
    let range = previous.map_or_else(|| "HEAD".to_owned(), |tag| format!("{tag}..HEAD"));
    let out = Command::new("git")
        .args(["log", "--first-parent", "--reverse", "--format=%s", &range])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run git log: {e}"))?;
    if !out.status.success() {
        return Err(format!("git log {range} failed"));
    }
    let subjects: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    let section = changelog::render_release(version, date, &subjects);
    let changelog_path = root.join("CHANGELOG.md");
    let existing = std::fs::read_to_string(&changelog_path).unwrap_or_default();
    let updated = changelog::insert(&existing, &section, version)?;
    write(&changelog_path, &updated)?;
    write(&manifest_path, &set_workspace_version(&manifest, version)?)?;
    Ok(section)
}

/// SemVer precedence for the versions release tags allow.
pub fn newer(a: &Version, b: &Version) -> bool {
    let core = |v: &Version| (v.major, v.minor, v.patch);
    if core(a) != core(b) {
        return core(a) > core(b);
    }
    match (&a.pre, &b.pre) {
        (None, Some(_)) => true,
        (Some(_), None) | (None, None) => false,
        (Some(x), Some(y)) => {
            let rank = |p: &str| -> (u8, u64) {
                let (kind, n) = p.split_once('.').unwrap_or((p, "0"));
                let k = match kind {
                    "alpha" => 0,
                    "beta" => 1,
                    _ => 2,
                };
                (k, n.parse().unwrap_or(0))
            };
            rank(x) > rank(y)
        }
    }
}

/// `release provenance`: the slot for SBOM generation, build
/// provenance and the signed update manifest (#18, #226). Until those land
/// it does nothing. Once `enabled` (the `RELEASE_PROVENANCE` repository
/// variable is `on`), it runs `cargo xtask sbom`, which must then exist and
/// succeed.
pub fn provenance(root: &Path, enabled: bool) -> Result<(), String> {
    if !enabled {
        println!(
            "provenance: not enabled yet (#18, #226); set the RELEASE_PROVENANCE variable to `on` once `cargo xtask sbom` exists"
        );
        return Ok(());
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    // `cargo xtask sbom` writes to its reserved directory (#226); the
    // release attaches what it writes there once that issue defines it.
    let status = Command::new(cargo)
        .args(["xtask", "sbom"])
        .current_dir(root)
        .status()
        .map_err(|e| format!("cannot run cargo xtask sbom: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(
            "provenance is enabled, but `cargo xtask sbom` failed or does not exist yet (#226)"
                .to_owned(),
        )
    }
}

/// The files `release verify` checks: every signable file in `dir`, and
/// every PE inside each package, extracted with an administrative install
/// (`msiexec /a`, which only unpacks) into `work`.
pub fn verify_dir(
    root: &Path,
    dir: &Path,
    work: &Path,
    timestamp: sign::Timestamp,
) -> Result<usize, String> {
    let mut runner = sign::ProcessRunner {
        secrets: Vec::new(),
    };
    let mut files = list_signable(dir)?;
    if files.is_empty() {
        return Err(format!("{}: nothing to verify", dir.display()));
    }
    let packages: Vec<std::path::PathBuf> = files
        .iter()
        .filter(|f| f.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi")))
        .cloned()
        .collect();
    for (index, package) in packages.iter().enumerate() {
        // Windows Installer needs absolute paths with backslashes.
        let package =
            std::path::absolute(package).map_err(|e| format!("{}: {e}", package.display()))?;
        let target = std::path::absolute(work.join(format!("msi-{index}")))
            .map_err(|e| format!("{}: {e}", work.display()))?;
        if target.exists() {
            std::fs::remove_dir_all(&target)
                .map_err(|e| format!("cannot clear {}: {e}", target.display()))?;
        }
        std::fs::create_dir_all(&target)
            .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
        let status = Command::new("msiexec")
            .arg("/a")
            .arg(&package)
            .arg("/qn")
            .arg(format!("TARGETDIR={}", target.display()))
            .status()
            .map_err(|e| format!("cannot run msiexec: {e}"))?;
        if !status.success() {
            return Err(format!("{}: cannot unpack ({status})", package.display()));
        }
        let inner = list_signable_recursive(&target)?;
        let pes = inner
            .iter()
            .filter(|f| !f.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi")))
            .count();
        if pes == 0 {
            return Err(format!("{}: no executables inside", package.display()));
        }
        files.extend(
            inner
                .into_iter()
                .filter(|f| !f.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi"))),
        );
    }
    let mut failures = Vec::new();
    for file in &files {
        if let Err(error) = sign::verify_file(root, timestamp, &mut runner, file) {
            println!(
                "::error title=Unsigned or invalid::{}: {error}",
                file.display()
            );
            failures.push(file.display().to_string());
        }
    }
    if failures.is_empty() {
        Ok(files.len())
    } else {
        Err(format!(
            "{} of {} files failed verification: {}",
            failures.len(),
            files.len(),
            failures.join(", ")
        ))
    }
}

fn list_signable(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut out = Vec::new();
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        if path.is_file() && sign::is_signable(&path) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn list_signable_recursive(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)
            .map_err(|e| format!("cannot read {}: {e}", current.display()))?
        {
            let path = entry
                .map_err(|e| format!("cannot read {}: {e}", current.display()))?
                .path();
            if path.is_dir() {
                stack.push(path);
            } else if sign::is_signable(&path) {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_tags() {
        assert_eq!(parse_tag("v0.1.0").unwrap().to_string(), "0.1.0");
        for ok in ["v0.1.0-alpha.1", "v1.2.3-beta.0", "v1.0.0-rc.10"] {
            assert!(parse_tag(ok).is_ok(), "{ok}");
            assert!(is_prerelease(&parse_tag(ok).unwrap()));
        }
        assert!(!is_prerelease(&parse_tag("v1.0.0").unwrap()));
        for bad in [
            "0.1.0",
            "v0.1",
            "v0.1.0+build",
            "v0.1.0-dev.1",
            "v0.1.0-rc",
            "v0.1.0-rc.01",
            "v0.1.0-rc.1.2",
            "vx",
        ] {
            assert!(parse_tag(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn version_precedence() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(newer(&v("0.2.0"), &v("0.1.9")));
        assert!(newer(&v("0.2.0"), &v("0.2.0-rc.1")));
        assert!(newer(&v("0.2.0-rc.2"), &v("0.2.0-rc.1")));
        assert!(newer(&v("0.2.0-rc.1"), &v("0.2.0-beta.9")));
        assert!(newer(&v("0.2.0-beta.1"), &v("0.2.0-alpha.3")));
        assert!(newer(&v("0.2.0-rc.10"), &v("0.2.0-rc.9")));
        assert!(!newer(&v("0.1.0"), &v("0.1.0")));
        assert!(!newer(&v("0.2.0-rc.1"), &v("0.2.0")));
    }

    #[test]
    fn bumps_only_the_workspace_version() {
        let manifest = "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace.dependencies]\nx = { version = \"1.0\" }\n";
        let bumped = set_workspace_version(manifest, "0.2.0-rc.1").unwrap();
        assert_eq!(
            bumped,
            manifest.replace("version = \"0.1.0\"", "version = \"0.2.0-rc.1\"")
        );
        assert_eq!(workspace_version(&bumped).unwrap(), "0.2.0-rc.1");
        assert!(set_workspace_version("[workspace]\n", "1.0.0").is_err());
        let root =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml"))
                .unwrap();
        let current = workspace_version(&root).unwrap();
        assert_eq!(set_workspace_version(&root, &current).unwrap(), root);
        let crlf = manifest.replace('\n', "\r\n");
        assert_eq!(
            set_workspace_version(&crlf, "0.2.0").unwrap(),
            crlf.replace("\"0.1.0\"", "\"0.2.0\"")
        );
    }

    #[test]
    fn tag_objects() {
        let body = "object 1111111111111111111111111111111111111111\ntype commit\ntag v0.1.0\ntagger A <a@example.invalid> 1 +0000\n\nRelease 0.1.0\n";
        let unsigned = parse_tag_object("tag\n", body).unwrap();
        assert_eq!(unsigned.object, "1111111111111111111111111111111111111111");
        assert!(!unsigned.signed);
        for sig in [
            "-----BEGIN SSH SIGNATURE-----",
            "-----BEGIN PGP SIGNATURE-----",
        ] {
            assert!(
                parse_tag_object("tag", &format!("{body}{sig}\nabc\n"))
                    .unwrap()
                    .signed
            );
        }
        assert!(
            parse_tag_object("commit", body)
                .unwrap_err()
                .contains("lightweight")
        );
        assert!(parse_tag_object("tag", "type commit\n").is_err());
    }

    #[test]
    fn provenance_is_a_no_op_until_enabled() {
        assert!(provenance(Path::new("/nonexistent"), false).is_ok());
    }
}

/// The release workflow's safety rules, checked against
/// `.github/workflows/release.yml`.
#[cfg(test)]
mod workflow_tests {
    use yaml_rust2::{Yaml, YamlLoader};

    fn workflow() -> Yaml {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../.github/workflows/release.yml");
        let source = std::fs::read_to_string(path).unwrap();
        YamlLoader::load_from_str(&source).unwrap().remove(0)
    }

    fn jobs(w: &Yaml) -> Vec<(String, Yaml)> {
        w["jobs"]
            .as_hash()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_str().unwrap().to_owned(), v.clone()))
            .collect()
    }

    fn text(job: &Yaml) -> String {
        let mut out = String::new();
        let mut emitter = yaml_rust2::YamlEmitter::new(&mut out);
        emitter.dump(job).unwrap();
        out
    }

    /// Secrets only in the job that runs in the approval-gated environment.
    #[test]
    fn secrets_are_only_in_the_signing_environment() {
        let w = workflow();
        for (name, job) in jobs(&w) {
            let body = text(&job);
            if body.contains("secrets.") {
                assert_eq!(name, "sign", "{name} reads a secret");
                assert_eq!(job["environment"].as_str(), Some("release-signing"));
            }
        }
        let sign = &w["jobs"]["sign"];
        assert_eq!(sign["environment"].as_str(), Some("release-signing"));
        assert!(!text(sign).contains("set -x"));
    }

    /// Pull requests run only the dry run, which can neither sign for real
    /// nor publish.
    #[test]
    fn pull_requests_run_only_the_dry_run() {
        let w = workflow();
        for (name, job) in jobs(&w) {
            let condition = job["if"].as_str().unwrap_or("");
            let on_pr = name == "dry-run";
            assert_eq!(
                condition.contains("'pull_request'"),
                on_pr,
                "{name}: if = {condition}"
            );
            if !on_pr && job["needs"].is_badvalue() {
                assert_eq!(
                    condition, "github.event_name == 'push'",
                    "{name} must only run for tags"
                );
            }
        }
        let dry = text(&w["jobs"]["dry-run"]);
        assert!(dry.contains("--sign test-ca"));
        assert!(!dry.contains("gh release") && !dry.contains("environment"));
        assert!(
            w["jobs"]["dry-run"]["permissions"].is_badvalue(),
            "the dry run stays read-only"
        );
        assert_eq!(w["on"]["push"]["tags"][0].as_str(), Some("v*"));
    }

    /// Release signing never skips timestamps, and the draft is published
    /// only after verification.
    #[test]
    fn releases_are_timestamped_and_verified_before_publishing() {
        let w = workflow();
        let all = text(&w);
        assert!(!all.contains("--no-timestamp"));
        let verify = text(&w["jobs"]["verify"]);
        assert!(
            verify.contains("cargo xtask release verify target/verify\n")
                || verify.ends_with("cargo xtask release verify target/verify")
        );
        assert!(!verify.contains("--allow-untimestamped"));
        let needs: Vec<&str> = w["jobs"]["publish"]["needs"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        assert!(needs.contains(&"verify") && needs.contains(&"provenance"));
        assert!(text(&w["jobs"]["publish"]).contains("--draft=false"));
        // Everything before publishing works on a draft.
        assert!(text(&w["jobs"]["check-tag"]).contains("--draft"));
    }

    /// The tag check refuses to go on without signing configured.
    #[test]
    fn a_tag_without_signing_configured_fails() {
        let check = text(&workflow()["jobs"]["check-tag"]);
        assert!(check.contains("vars.RELEASE_SIGNER") && check.contains("pfx|cloud-hsm)"));
        assert!(check.contains("Signing not configured"));
    }
}
