//! `cargo xtask docs assemble <site> --version <name>`: assembles the
//! GitHub Pages tree in `<site>`, a checkout of the `gh-pages` branch.
//!
//! - `<site>/<name>/` is replaced with the built book (`target/book`), and
//!   `<site>/<name>/api/rust/` with the Rust API docs (`target/doc`).
//! - `<name>` is `latest` for `main`, or `vX.Y` for a release tag.
//! - `<site>/versions.json` lists every version directory, `latest`
//!   first and then releases newest first. The theme's version switcher
//!   reads it.
//! - `<site>/index.html` redirects to `latest/` (or, until `main` is first
//!   published, the newest release), and `<site>/.nojekyll`
//!   makes Pages serve the files as they are.
//!
//! Only `<name>` and the three root files are written, so publishing
//! `latest` never touches a release's directory.

use std::path::Path;

use serde_json::Value;

/// A version number part: digits, no leading zero.
fn is_number(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|b| b.is_ascii_digit())
        && (part.len() == 1 || !part.starts_with('0'))
}

/// `true` for `latest`, or `v<major>.<minor>` with no leading zeros.
pub fn is_version_name(name: &str) -> bool {
    if name == "latest" {
        return true;
    }
    let Some(rest) = name.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 2 && parts.iter().all(|p| is_number(p))
}

/// The docs version for a git ref: `latest` for `refs/heads/main`, `vX.Y`
/// for a release tag `refs/tags/vX.Y.Z`. Pre-release tags (`vX.Y.Z-rc.1`)
/// and anything else are errors, so they never overwrite a release's docs.
pub fn version_for_ref(git_ref: &str) -> Result<String, String> {
    if git_ref == "refs/heads/main" {
        return Ok("latest".to_owned());
    }
    let tag = git_ref
        .strip_prefix("refs/tags/")
        .ok_or_else(|| format!("`{git_ref}`: docs are published from main or a release tag"))?;
    let parts: Vec<&str> = tag.strip_prefix('v').unwrap_or("").split('.').collect();
    match parts.as_slice() {
        [major, minor, patch] if [major, minor, patch].iter().all(|p| is_number(p)) => {
            Ok(format!("v{major}.{minor}"))
        }
        _ => Err(format!(
            "`{tag}` is not a release tag `vX.Y.Z` (pre-releases are not published)"
        )),
    }
}

/// The sorted version list: `latest`, then releases newest first.
pub fn sorted_versions(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut releases: Vec<(u64, u64, String)> = Vec::new();
    let mut latest = false;
    for name in names {
        if name == "latest" {
            latest = true;
        } else if is_version_name(&name) {
            let (major, minor) = name[1..].split_once('.').unwrap_or(("0", "0"));
            releases.push((major.parse().unwrap_or(0), minor.parse().unwrap_or(0), name));
        }
    }
    releases.sort();
    releases.dedup();
    let mut out: Vec<String> = Vec::new();
    if latest {
        out.push("latest".to_owned());
    }
    out.extend(releases.into_iter().rev().map(|(_, _, n)| n));
    out
}

/// The root redirect page, to `version` (`latest`, or the newest release
/// before `main` was first published).
pub fn index_html(version: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Palisade documentation</title>\n<meta http-equiv=\"refresh\" content=\"0; url={version}/\">\n<link rel=\"canonical\" href=\"{version}/\">\n</head>\n<body>\n<p><a href=\"{version}/\">Palisade documentation</a></p>\n</body>\n</html>\n"
    )
}

/// Assembles `site`. `book` and `api` are the built book and `target/doc`.
pub fn assemble(
    site: &Path,
    version: &str,
    book: &Path,
    api: &Path,
) -> Result<Vec<String>, String> {
    if !is_version_name(version) {
        return Err(format!("`{version}`: the version is `latest` or `vX.Y`"));
    }
    if !book.join("index.html").is_file() {
        return Err(format!(
            "{}: no built book; run `cargo xtask docs build` first",
            book.display()
        ));
    }
    if !api.join("palisade_policy/index.html").is_file() {
        return Err(format!(
            "{}: no Rust API docs; run `cargo doc --workspace --no-deps --all-features --locked` first",
            api.display()
        ));
    }
    std::fs::create_dir_all(site).map_err(|e| format!("cannot create {}: {e}", site.display()))?;
    let target = site.join(version);
    if target.exists() {
        std::fs::remove_dir_all(&target)
            .map_err(|e| format!("cannot remove {}: {e}", target.display()))?;
    }
    copy_tree(book, &target)?;
    copy_tree(api, &target.join("api/rust"))?;
    // `cargo doc` leaves a lock file and build stamps that are not pages.
    for leftover in [".lock", ".rustc_info.json", "crates.js.bak"] {
        let _ = std::fs::remove_file(target.join("api/rust").join(leftover));
    }
    std::fs::write(target.join("api/rust/index.html"), api_index(api)?)
        .map_err(|e| format!("cannot write the API index: {e}"))?;

    let mut names = Vec::new();
    for entry in
        std::fs::read_dir(site).map_err(|e| format!("cannot read {}: {e}", site.display()))?
    {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", site.display()))?;
        if entry.path().is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    let versions = sorted_versions(names);
    let json = Value::from(versions.clone());
    std::fs::write(site.join("versions.json"), format!("{json}\n"))
        .map_err(|e| format!("cannot write versions.json: {e}"))?;
    // `versions` holds at least the version just written.
    let first = versions.first().map_or(version, String::as_str);
    std::fs::write(site.join("index.html"), index_html(first))
        .map_err(|e| format!("cannot write index.html: {e}"))?;
    std::fs::write(site.join(".nojekyll"), "")
        .map_err(|e| format!("cannot write .nojekyll: {e}"))?;
    Ok(versions)
}

/// An index of the library crates in `target/doc`, which has none of its
/// own at the top.
fn api_index(api: &Path) -> Result<String, String> {
    let mut crates = Vec::new();
    for entry in
        std::fs::read_dir(api).map_err(|e| format!("cannot read {}: {e}", api.display()))?
    {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", api.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let plain = name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if plain && name.starts_with("palisade_") && entry.path().join("index.html").is_file() {
            crates.push(name);
        }
    }
    crates.sort();
    let items: String = crates
        .iter()
        .map(|c| format!("<li><a href=\"{c}/index.html\"><code>{c}</code></a></li>\n"))
        .collect();
    Ok(format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Palisade Rust API</title>\n</head>\n<body>\n<p><strong>{}</strong></p>\n<h1>Palisade Rust API</h1>\n<p>Generated by <code>cargo doc</code> from the library crates. <a href=\"../../index.html\">Back to the book</a>.</p>\n<ul>\n{items}</ul>\n</body>\n</html>\n",
        super::DISCLAIMER
    ))
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    for path in super::walk_files(from)? {
        let rel = path
            .strip_prefix(from)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let dest = to.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::copy(&path, &dest).map_err(|e| format!("cannot copy {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_names() {
        for ok in ["latest", "v0.1", "v1.0", "v12.34"] {
            assert!(is_version_name(ok), "{ok}");
        }
        for bad in [
            "", "v1", "v1.2.3", "1.2", "v01.2", "v1.02", "vx.y", "../x", "latest/x",
        ] {
            assert!(!is_version_name(bad), "{bad}");
        }
    }

    #[test]
    fn refs_map_to_versions() {
        assert_eq!(version_for_ref("refs/heads/main").unwrap(), "latest");
        assert_eq!(version_for_ref("refs/tags/v0.3.1").unwrap(), "v0.3");
        assert_eq!(version_for_ref("refs/tags/v10.20.30").unwrap(), "v10.20");
        for bad in [
            "refs/heads/feature",
            "refs/tags/1.0.0",
            "refs/tags/v1.0",
            "refs/tags/vx.1.2",
            "refs/tags/v1.0.0-rc.1",
            "refs/tags/vv1.0.0",
            "refs/tags/v1.0.abc",
            "refs/tags/v1.0.",
            "refs/tags/v1.0.01",
            "refs/tags/v01.0.0",
            "refs/tags/v1.0.0.0",
        ] {
            assert!(version_for_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn versions_sort_latest_then_newest() {
        let v = sorted_versions(
            ["v0.9", "latest", "v0.10", "v1.0", "api", "v0.9"]
                .iter()
                .map(|s| (*s).to_owned()),
        );
        assert_eq!(v, ["latest", "v1.0", "v0.10", "v0.9"]);
    }

    #[test]
    fn assemble_writes_only_its_version() {
        let base = std::env::temp_dir().join(format!("palisade-assemble-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (book, api, site) = (base.join("book"), base.join("doc"), base.join("site"));
        for (path, body) in [
            (book.join("index.html"), "book"),
            (api.join("palisade_policy/index.html"), "api"),
            (api.join(".lock"), ""),
            (site.join("v0.1/index.html"), "old release"),
            (site.join("latest/stale.html"), "stale"),
        ] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        let versions = assemble(&site, "latest", &book, &api).unwrap();
        assert_eq!(versions, ["latest", "v0.1"]);
        assert_eq!(
            std::fs::read_to_string(site.join("v0.1/index.html")).unwrap(),
            "old release"
        );
        assert!(!site.join("latest/stale.html").exists());
        assert!(
            site.join("latest/api/rust/palisade_policy/index.html")
                .is_file()
        );
        assert!(!site.join("latest/api/rust/.lock").exists());
        let index = std::fs::read_to_string(site.join("latest/api/rust/index.html")).unwrap();
        assert!(index.contains("palisade_policy/index.html"));
        assert!(index.contains(crate::docs::DISCLAIMER));
        // "Back to the book" leads from <version>/api/rust/ to <version>/.
        assert!(index.contains("href=\"../../index.html\""));
        assert!(site.join("latest/api/rust/../../index.html").is_file());
        assert_eq!(
            std::fs::read_to_string(site.join("versions.json")).unwrap(),
            "[\"latest\",\"v0.1\"]\n"
        );
        assert!(site.join(".nojekyll").is_file());
        let root = std::fs::read_to_string(site.join("index.html")).unwrap();
        assert!(root.contains("url=latest/"));
        // A release assembled into a site with no `latest` yet redirects to it.
        let fresh = base.join("fresh");
        assemble(&fresh, "v0.2", &book, &api).unwrap();
        let root = std::fs::read_to_string(fresh.join("index.html")).unwrap();
        assert!(root.contains("url=v0.2/"), "{root}");
        assert!(assemble(&site, "../x", &book, &api).is_err());
        assert!(assemble(&site, "latest", &base.join("none"), &api).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
