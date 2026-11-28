//! End-to-end tests of `pal fileid`, run against the built binary and the
//! identity corpus of `palisade-fileid` (#55), which is built at test time
//! (nothing signed is committed) and written once to a temporary folder.
//!
//! `snapshots/` holds golden output. Regenerate it with:
//!   `PALISADE_BLESS=1 cargo test -p palisade-cli --test fileid`

// Test code: a failure should fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

// The identity corpus's builders, shared with `palisade-fileid`'s own
// corpus test so both see the same bytes.
#[path = "../../palisade-fileid/tests/common/mod.rs"]
mod common;
#[path = "../../palisade-fileid/tests/corpus/mod.rs"]
mod corpus;
#[path = "../../palisade-fileid/tests/fixtures/identity/signed.rs"]
mod signed;
#[path = "../../palisade-fileid/tests/fixtures/identity/synthetic.rs"]
mod synthetic;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_pal");

/// The generated identity corpus files, written once per test process.
fn corpus_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("pal-fileid-corpus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in signed::generated(&synthetic::corpus_files()) {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        dir
    })
}

fn corpus(name: &str) -> PathBuf {
    let path = corpus_dir().join(name);
    assert!(path.is_file(), "no generated corpus file {name}");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pal-fileid-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of a corpus file under `name`, so the snapshot does not depend on
/// where the repository is checked out.
fn staged(dir: &Path, from: &str, name: &str) -> PathBuf {
    let to = dir.join(name);
    std::fs::copy(corpus(from), &to).unwrap();
    to
}

fn anchor() -> String {
    corpus("ca.der").to_string_lossy().into_owned()
}

/// Removes the values that change between machines and runs: paths, times
/// and the library version.
fn scrub(v: &mut Value) {
    match v {
        Value::Object(o) => {
            for key in ["path", "original", "library_version"] {
                if o.contains_key(key) {
                    o.insert(key.to_owned(), Value::String("<scrubbed>".to_owned()));
                }
            }
            // Times, and the OS cross-check (computed on Windows only).
            for key in ["timestamps", "os_cross_check"] {
                if o.contains_key(key) {
                    o.insert(key.to_owned(), Value::String("<scrubbed>".to_owned()));
                }
            }
            for (_, child) in o.iter_mut() {
                scrub(child);
            }
            // `fs.path` holds the scrubbed `original` and keys derived
            // from the temp path.
            if let Some(Value::Object(p)) = o.get_mut("value") {
                for key in [
                    "normalized",
                    "normalize_error",
                    "final_path",
                    "lexical_key",
                    "rule_key",
                ] {
                    if p.contains_key(key) && p.contains_key("claimed") {
                        p.insert(key.to_owned(), Value::String("<scrubbed>".to_owned()));
                    }
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub),
        _ => {}
    }
}

fn check_snapshot(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(name);
    if std::env::var_os("PALISADE_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        expected.replace("\r\n", "\n") == actual,
        "{} is stale. Regenerate it with:\n  PALISADE_BLESS=1 cargo test -p palisade-cli --test fileid\n--- actual ---\n{actual}",
        path.display()
    );
}

#[test]
fn inspect_json_snapshot() {
    let dir = tempdir("snapshot");
    let file = staged(&dir, "signed-tool.exe", "extool.exe");
    let o = run(&[
        "fileid",
        "inspect",
        file.to_str().unwrap(),
        "--json",
        "--tiers",
        "t0..t3",
        "--anchor",
        &anchor(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let mut v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["signing_state"]["value"]["state"], "trusted");
    scrub(&mut v);
    let mut text = serde_json::to_string_pretty(&v).unwrap();
    text.push('\n');
    check_snapshot("inspect-signed-tool.json", &text);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn inspect_table_and_yaml() {
    let file = corpus("signed-tool.exe");
    let o = run(&["fileid", "inspect", file.to_str().unwrap(), "--tiers", "t1"]);
    assert!(o.status.success());
    let t = stdout(&o);
    assert!(
        t.contains("pe.version.original_file_name: extool.exe\n"),
        "{t}"
    );
    assert!(t.contains("hashes: (not requested)\n"), "{t}");
    let o = run(&[
        "fileid",
        "inspect",
        file.to_str().unwrap(),
        "--yaml",
        "--tiers",
        "t0",
    ]);
    assert!(o.status.success());
    assert!(stdout(&o).starts_with("---\n"));
    // Formats are exclusive.
    let o = run(&[
        "fileid",
        "inspect",
        file.to_str().unwrap(),
        "--yaml",
        "--json",
    ]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["fileid", "inspect", file.to_str().unwrap(), "--tiers", "t9"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn inspect_a_directory_prints_json_lines() {
    let dir = tempdir("dir");
    staged(&dir, "signed-tool.exe", "a.exe");
    staged(&dir, "rogue-signed.exe", "b.exe");
    std::fs::create_dir(dir.join("sub")).unwrap();
    staged(&dir, "tampered-tool.exe", "sub/c.exe");
    let flat = run(&[
        "fileid",
        "inspect",
        dir.to_str().unwrap(),
        "--json",
        "--tiers",
        "t0",
    ]);
    assert!(flat.status.success());
    let lines: Vec<Value> = stdout(&flat)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    let deep = run(&[
        "fileid",
        "inspect",
        dir.to_str().unwrap(),
        "--json",
        "--recursive",
        "--tiers",
        "t0",
    ]);
    assert_eq!(stdout(&deep).lines().count(), 3);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn hash_prints_selected_digests() {
    let file = corpus("signed-tool.exe");
    let bytes = std::fs::read(&file).unwrap();
    let sha256 = hex(&Sha256::digest(&bytes));
    let o = run(&[
        "fileid",
        "hash",
        file.to_str().unwrap(),
        "--alg",
        "sha256,authenticode-sha256,page-sha256",
        "--json",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["sha256"], sha256);
    assert_eq!(v.as_object().unwrap().len(), 3);
    assert!(
        v["authenticode-sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64)
    );
    // Not an installer: not available, and a non-zero exit.
    let o = run(&[
        "fileid",
        "hash",
        file.to_str().unwrap(),
        "--alg",
        "msi-normalised",
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("not available"));
}

/// The normalised hashes of an installer and a script, as the crate's
/// fixture sets pin them: the installer's by an independent Python
/// implementation (`fixtures/installer/normalised.py`).
#[test]
fn hash_prints_the_normalised_hashes() {
    let fixtures = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../palisade-fileid/tests/fixtures"
    );
    let pinned =
        std::fs::read_to_string(format!("{fixtures}/installer/product.normalised.txt")).unwrap();
    for msi in ["product.msi", "product-sha256.msi"] {
        let path = format!("{fixtures}/installer/{msi}");
        let o = run(&["fileid", "hash", &path, "--alg", "msi-normalised", "--json"]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(v["msi-normalised"], pinned.trim(), "{msi}");
    }
    let path = format!("{fixtures}/script/ps1-utf8bom-crlf.ps1");
    let o = run(&[
        "fileid",
        "hash",
        &path,
        "--alg",
        "script-normalised,msi-normalised",
        "--json",
    ]);
    assert_eq!(o.status.code(), Some(1));
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(
        v["script-normalised"]
            .as_str()
            .is_some_and(|s| s.len() == 64)
    );
    assert!(v["msi-normalised"].is_null());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn certs_are_extracted() {
    let out = tempdir("certs");
    let o = run(&[
        "fileid",
        "certs",
        corpus("signed-tool.exe").to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--pem",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let files: Vec<_> = std::fs::read_dir(&out).unwrap().collect();
    assert_eq!(files.len(), 2, "leaf and root");
    for f in files {
        let text = std::fs::read_to_string(f.unwrap().path()).unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
    }
    std::fs::remove_dir_all(&out).unwrap();

    // Only the root, as DER: the corpus CA itself.
    let out = tempdir("certs-root");
    let o = run(&[
        "fileid",
        "certs",
        corpus("signed-tool.exe").to_str().unwrap(),
        "--root",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(o.status.success());
    let files: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|f| f.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(
        std::fs::read(&files[0]).unwrap(),
        std::fs::read(corpus("ca.der")).unwrap()
    );
    std::fs::remove_dir_all(&out).unwrap();

    // A catalog's signer certificates.
    let out = tempdir("certs-cat");
    let o = run(&[
        "fileid",
        "certs",
        corpus("corpus.cat").to_str().unwrap(),
        "--leaf",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(stdout(&o).contains("Palisade Corpus OS Signer"));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
    std::fs::remove_dir_all(&out).unwrap();
}

#[test]
fn compare_shows_an_update_keeps_its_publisher() {
    let a = corpus("signed-tool.exe");
    let b = corpus("signed-tool-v2.exe");
    let o = run(&[
        "fileid",
        "compare",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "--json",
        "--anchor",
        &anchor(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    let names: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["attribute"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"file_version"), "{names:?}");
    assert!(names.contains(&"sha256"), "{names:?}");
    assert!(!names.contains(&"publisher"), "{names:?}");
    assert!(
        !names.contains(&"signer_leaf_sha256_thumbprint"),
        "{names:?}"
    );
}

#[test]
fn explain_recommends_a_rule_level() {
    let dir = tempdir("explain");
    let file = staged(&dir, "signed-tool.exe", "extool.exe");
    let o = run(&[
        "fileid",
        "explain",
        file.to_str().unwrap(),
        "--anchor",
        &anchor(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let t = stdout(&o);
    assert!(
        t.contains("recommended rule level: file_publisher\n"),
        "{t}"
    );
    assert!(t.contains("signed by \"Palisade Corpus Vendor\""), "{t}");
    assert!(t.contains("not path: path rule refused"), "{t}");
    // With nothing trusted, a hash rule.
    let o = run(&["fileid", "explain", file.to_str().unwrap(), "--json"]);
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["recommendation"]["level"], "authenticode_hash");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn renamed_protected_binary_is_reported() {
    // The protected PowerShell host, signed by the corpus "OS" signer,
    // copied into a folder as notepad.exe.
    let dir = tempdir("renamed");
    let file = staged(&dir, "signed-powershell.exe", "notepad.exe");
    let ca = std::fs::read(corpus("ca.der")).unwrap();
    let root = palisade_fileid::authenticode::CertSummary::from_der(&ca).unwrap();
    let wkr = format!("9={}", root.tbs_hash.unwrap());
    let o = run(&[
        "fileid",
        "inspect",
        file.to_str().unwrap(),
        "--json",
        "--anchor",
        &anchor(),
        "--well-known-root",
        &wkr,
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    let kinds: Vec<&str> = v["masquerade"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"known_binary_relocated"), "{kinds:?}");
    assert!(kinds.contains(&"name_mismatch"), "{kinds:?}");
    assert!(v["masquerade"]["score"].as_u64().unwrap() >= 80);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn missing_files_fail() {
    let o = run(&["fileid", "inspect", "/nonexistent/palisade/file"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("cannot read"));
    let o = run(&["fileid", "explain", "x", "--anchor", "/nonexistent/ca.der"]);
    assert_eq!(o.status.code(), Some(2));
}

/// Output in every format is terminal-safe for a crafted file name, and
/// error messages are too.
#[test]
fn crafted_names_never_reach_the_terminal_raw() {
    let dir = tempdir("crafted");
    // Windows refuses C0 control characters in file names, so there the
    // escape is the C1 control sequence introducer alone.
    let name = if cfg!(windows) {
        "a\u{9b}2J\u{9b}31m\u{202e}exe.txt"
    } else {
        "a\u{1b}[2J\u{9b}31m\u{202e}exe.txt"
    };
    let file = staged(&dir, "signed-tool.exe", name);
    let raw = |text: &str| {
        text.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t')
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    };
    for format in ["--json", "--yaml", "--table"] {
        let o = run(&[
            "fileid",
            "inspect",
            file.to_str().unwrap(),
            format,
            "--tiers",
            "t0,t1",
        ]);
        assert!(o.status.success(), "{format}");
        let out = stdout(&o);
        assert!(!raw(&out), "{format}: {out:?}");
        if format == "--json" {
            let v: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["name"]["file_name"], name, "JSON escapes parse back");
        }
    }
    let o = run(&[
        "fileid",
        "inspect",
        dir.join(format!("{name}.missing")).to_str().unwrap(),
    ]);
    let err = String::from_utf8(o.stderr).unwrap();
    assert!(!raw(&err), "{err:?}");
    // The other outputs: explain, compare and hash, JSON and text.
    let v2 = corpus("signed-tool-v2.exe");
    for args in [
        vec!["fileid", "explain", file.to_str().unwrap(), "--json"],
        vec!["fileid", "explain", file.to_str().unwrap()],
        vec![
            "fileid",
            "compare",
            file.to_str().unwrap(),
            v2.to_str().unwrap(),
            "--json",
        ],
        vec![
            "fileid",
            "compare",
            file.to_str().unwrap(),
            v2.to_str().unwrap(),
        ],
        vec!["fileid", "hash", file.to_str().unwrap(), "--json"],
    ] {
        let o = run(&args);
        assert!(o.status.success(), "{args:?}");
        let out = stdout(&o);
        assert!(!raw(&out), "{args:?}: {out:?}");
    }
    let o = run(&["fileid", "explain", file.to_str().unwrap(), "--json"]);
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(
        v["masquerade"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "bidi_control"),
        "{v}"
    );
    // A directory listing in JSON lines.
    let o = run(&[
        "fileid",
        "inspect",
        dir.to_str().unwrap(),
        "--json",
        "--tiers",
        "t0",
    ]);
    assert!(!raw(&stdout(&o)));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A bad `--catroot` is an error, not an empty store.
#[test]
fn bad_catroot_fails() {
    let file = corpus("signed-tool.exe");
    let o = run(&[
        "fileid",
        "inspect",
        file.to_str().unwrap(),
        "--catroot",
        "/nonexistent/palisade/catroot",
    ]);
    assert_eq!(o.status.code(), Some(2));
    // A directory holding a file that is not a catalog.
    let dir = tempdir("catroot");
    std::fs::write(dir.join("broken.cat"), b"not a catalog").unwrap();
    let o = run(&[
        "fileid",
        "inspect",
        file.to_str().unwrap(),
        "--catroot",
        dir.to_str().unwrap(),
    ]);
    assert_ne!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A signed cabinet's certificates (#49's extraction).
#[test]
fn certs_from_a_cabinet() {
    let cab = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../palisade-fileid/tests/fixtures/certs/signed.cab"
    );
    let out = tempdir("certs-cab");
    let o = run(&["fileid", "certs", cab, "--out", out.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(std::fs::read_dir(&out).unwrap().count() >= 1);
    std::fs::remove_dir_all(&out).unwrap();
}

/// `certs` reports what it cannot read instead of finding nothing.
#[test]
fn certs_reports_unreadable_input() {
    let out = tempdir("certs-err");
    let o = run(&[
        "fileid",
        "certs",
        "/nonexistent/palisade/x.exe",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    #[cfg(unix)]
    {
        // A FIFO must not hang the read.
        let fifo = out.join("pipe");
        let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(made.success());
        let o = run(&[
            "fileid",
            "certs",
            fifo.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]);
        assert_eq!(o.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&o.stderr).contains("not a regular file"));
    }
    std::fs::remove_dir_all(&out).unwrap();
}

/// `file` is an alias of `fileid`.
#[test]
fn file_alias() {
    let o = run(&["file", "hash", corpus("signed-tool.exe").to_str().unwrap()]);
    assert!(o.status.success());
}

/// #294 review: a record with errors is printed, but `inspect` fails, so
/// a script never reads a partial record as complete. A sparse file over
/// the in-memory limit makes the classify tier record `too_large`.
#[test]
fn inspect_fails_when_the_record_has_errors() {
    let dir = tempdir("inspect-errors");
    let big = dir.join("big.bin");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(palisade_fileid::identity::MAX_IN_MEMORY + 1)
        .unwrap();
    drop(f);
    let o = run(&[
        "fileid",
        "inspect",
        big.to_str().unwrap(),
        "--tiers",
        "t1",
        "--json",
    ]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["errors"][0]["code"], "too_large");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #294 review: an empty `--catroot` is a usage error, not a store that
/// lists nothing (which would read as "not catalog-signed").
#[test]
fn empty_catroot_fails() {
    let dir = tempdir("catroot-empty");
    let file = corpus("signed-tool.exe");
    let o = run(&[
        "fileid",
        "inspect",
        file.to_str().unwrap(),
        "--catroot",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #294 review: a catalog signed by a certificate that has expired, with no
/// timestamp, vouches for nothing through `--catroot` either: the CLI
/// judges every catalog signature's validity.
#[test]
fn an_expired_catalog_vouches_for_nothing() {
    let dir = tempdir("catroot-expired");
    std::fs::copy(corpus("expired.cat"), dir.join("expired.cat")).unwrap();
    let driver = dir.join("palisade.sys");
    std::fs::write(&driver, &synthetic::corpus_files()["driver"]).unwrap();
    let o = run(&[
        "fileid",
        "explain",
        driver.to_str().unwrap(),
        "--json",
        "--anchor",
        &anchor(),
        "--catroot",
        dir.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    let level = v["recommendation"]["level"].as_str().unwrap();
    assert!(
        !["publisher", "publisher_product", "file_publisher"].contains(&level),
        "{v}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #294 review: `certs` checks its input before making the output folder,
/// so a mistyped path leaves nothing behind.
#[test]
fn certs_makes_no_folder_for_a_missing_input() {
    let dir = tempdir("certs-nomkdir");
    let out = dir.join("out");
    let o = run(&[
        "fileid",
        "certs",
        "/nonexistent/palisade/x.exe",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(!out.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #294 review: output that cannot be written (a full disk) fails the run;
/// only a closed pipe is ignored.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_write_fails_the_run() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let o = Command::new(BIN)
        .args([
            "fileid",
            "inspect",
            corpus("signed-tool.exe").to_str().unwrap(),
            "--tiers",
            "t0",
        ])
        .stdout(full)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("writing the output failed"));
}

/// A closed pipe is not a failure.
#[cfg(unix)]
#[test]
fn a_closed_pipe_is_not_a_failure() {
    let mut child = Command::new(BIN)
        .args([
            "fileid",
            "inspect",
            corpus_dir().to_str().unwrap(),
            "--json",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let o = child.wait_with_output().unwrap();
    assert!(
        !String::from_utf8_lossy(&o.stderr).contains("writing the output failed"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// `--include-ads` asks for the context tier, which lists streams. Off the
/// Windows file system they cannot be listed, which is a failure, never
/// "no streams".
#[test]
fn include_ads_needs_the_stream_list() {
    let file = corpus("signed-tool.exe");
    let o = run(&[
        "fileid",
        "inspect",
        file.to_str().unwrap(),
        "--tiers",
        "t0",
        "--include-ads",
        "--json",
    ]);
    let out = stdout(&o);
    let first: Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert!(
        first["requested_tiers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "context")
    );
    if cfg!(windows) {
        // On Windows the stream list is read; a fresh file has none.
        assert!(
            first["fs"]["streams"]["status"] == "computed" || o.status.code() == Some(1),
            "{out}"
        );
    } else {
        assert_eq!(o.status.code(), Some(1), "{out}");
        assert!(out.contains("streams could not be listed"), "{out}");
    }
}
