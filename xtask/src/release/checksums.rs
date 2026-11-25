//! `SHA256SUMS`: one `<hex digest>  <file name>` line per release file, in
//! the format `sha256sum --check` reads, sorted by name.

use std::path::Path;

use sha2::{Digest as _, Sha256};

/// The `SHA256SUMS` text for `files`, as `(name, contents)`.
pub fn render(files: &[(String, Vec<u8>)]) -> Result<String, String> {
    let mut lines: Vec<(String, String)> = Vec::with_capacity(files.len());
    for (name, data) in files {
        check_name(name)?;
        if lines.iter().any(|(n, _)| n == name) {
            return Err(format!("SHA256SUMS: `{name}` is listed twice"));
        }
        lines.push((name.clone(), crate::dist::hex(&Sha256::digest(data))));
    }
    lines.sort();
    Ok(lines
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect())
}

/// Reads every regular file directly in `dir` except `SHA256SUMS` and its
/// signature, and renders their checksums.
pub fn for_dir(dir: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", entry.path().display()))?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "SHA256SUMS" || name == "SHA256SUMS.sig" {
            continue;
        }
        let data = std::fs::read(entry.path())
            .map_err(|e| format!("cannot read {}: {e}", entry.path().display()))?;
        files.push((name, data));
    }
    if files.is_empty() {
        return Err(format!("{}: no files to list", dir.display()));
    }
    render(&files)
}

/// Checks `sums` against `files`: every file listed, every listed file
/// present, every digest equal. Returns one message per problem.
pub fn verify(sums: &str, files: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut listed = Vec::new();
    for line in sums.lines() {
        let Some((digest, name)) = line.split_once("  ") else {
            problems.push(format!("SHA256SUMS: malformed line `{line}`"));
            continue;
        };
        listed.push(name);
        match files.iter().find(|(n, _)| n == name) {
            Some((_, data)) if crate::dist::hex(&Sha256::digest(data)) == digest => {}
            Some(_) => problems.push(format!("{name}: SHA-256 does not match SHA256SUMS")),
            None => problems.push(format!("{name}: listed in SHA256SUMS but missing")),
        }
    }
    for (name, _) in files {
        if !listed.contains(&name.as_str()) {
            problems.push(format!("{name}: not listed in SHA256SUMS"));
        }
    }
    problems
}

/// Release file names are plain: no directories, spaces or control
/// characters, so every line parses one way.
pub fn check_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'));
    if ok {
        Ok(())
    } else {
        Err(format!("SHA256SUMS: unexpected file name `{name}`"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<(String, Vec<u8>)> {
        vec![
            ("b.msi".to_owned(), b"bb".to_vec()),
            ("a.zip".to_owned(), b"".to_vec()),
        ]
    }

    #[test]
    fn renders_sorted_sha256sum_lines() {
        let sums = render(&files()).unwrap();
        assert_eq!(
            sums,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  a.zip\n\
             3b64db95cb55c763391c707108489ae18b4112d783300de38e033b4c98c3deaf  b.msi\n"
        );
        assert!(verify(&sums, &files()).is_empty());
    }

    #[test]
    fn verify_reports_every_mismatch() {
        let sums = render(&files()).unwrap();
        let mut changed = files();
        changed[0].1 = b"tampered".to_vec();
        changed.push(("extra.exe".to_owned(), Vec::new()));
        changed.remove(1);
        let problems = verify(&format!("{sums}junk\n"), &changed);
        assert_eq!(
            problems,
            [
                "a.zip: listed in SHA256SUMS but missing",
                "b.msi: SHA-256 does not match SHA256SUMS",
                "SHA256SUMS: malformed line `junk`",
                "extra.exe: not listed in SHA256SUMS",
            ]
        );
    }

    #[test]
    fn refuses_odd_names_and_duplicates() {
        for bad in ["", ".hidden", "a b", "dir/a", "a\nb"] {
            assert!(render(&[(bad.to_owned(), Vec::new())]).is_err(), "{bad:?}");
        }
        let dup = vec![("a".to_owned(), Vec::new()), ("a".to_owned(), Vec::new())];
        assert!(render(&dup).is_err());
    }

    #[test]
    fn lists_a_directory_without_its_own_files() {
        let dir = std::env::temp_dir().join(format!("palisade-sums-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("x.msi"), b"x").unwrap();
        std::fs::write(dir.join("SHA256SUMS"), b"old").unwrap();
        std::fs::write(dir.join("SHA256SUMS.sig"), b"old").unwrap();
        let sums = for_dir(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(sums.lines().count(), 1);
        assert!(sums.ends_with("  x.msi\n"));
    }
}
