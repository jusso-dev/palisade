//! Seed inputs for the palisade-policy fuzz targets (#25, #30, #32), written
//! on request. `cargo xtask fuzz` runs these before each target. To run one
//! by hand:
//!
//! ```sh
//! PALISADE_FUZZ_SEED_DIR=/tmp/seeds \
//!     cargo test -p palisade-policy --test fuzz_seeds -- --ignored write_policy_json_fuzz_seeds
//! ```

// `clippy.toml` allows unwrap and expect inside `#[test]` functions only;
// the helpers here are test code too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The directory to write into, from `PALISADE_FUZZ_SEED_DIR`.
fn seed_dir() -> PathBuf {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = PathBuf::from(dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Every file with `extension` in `dir` and its subdirectories, sorted.
fn files(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == extension) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Copies every file in `sources` into `dir` as `seed-<i>`.
fn copy_all(dir: &Path, sources: &[PathBuf]) {
    assert!(!sources.is_empty(), "no seed sources");
    for (i, source) in sources.iter().enumerate() {
        fs::copy(source, dir.join(format!("seed-{i}"))).unwrap();
    }
}

/// Every JSON fixture: valid, invalid and malformed documents.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_policy_json_fuzz_seeds() {
    copy_all(
        &seed_dir(),
        &files(&manifest_dir().join("tests/fixtures"), "json"),
    );
}

/// Every YAML fixture and example policy.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_policy_yaml_fuzz_seeds() {
    let mut sources = files(&manifest_dir().join("tests/fixtures/yaml"), "yaml");
    sources.extend(files(
        &manifest_dir().join("../../docs/examples/policies"),
        "yaml",
    ));
    copy_all(&seed_dir(), &sources);
}

/// Patterns and facts in the target's input format: a selector byte, the
/// pattern, a zero byte, then the fact.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_pattern_fuzz_seeds() {
    let dir = seed_dir();
    let cases: &[(u8, &str, &str)] = &[
        // path.full wildcard: recursive, single-component, streams, variables.
        (
            0,
            r"C:\Program Files\**\*.exe",
            r"C:\Program Files\App\bin\app.exe",
        ),
        (
            0,
            r"%PROGRAMFILES%\*\app?.exe",
            r"C:\Program Files\X\app1.exe",
        ),
        (0, r"C:\x\*:*", r"C:\x\a.txt:payload"),
        (0, r"**\[*]odd[?].exe", r"D:\a\*odd?.exe"),
        (0, r"\\server\share\**", r"\\server\share\dir\f.exe"),
        // meta.product_name wildcard and regex.
        (1, "Ex*Suite ?", "Example Suite 2"),
        (7, "Ex[a-z]+ (Suite|Tool)", "Example Tool"),
        (
            7,
            "(a|aa)*b",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac",
        ),
        (7, r"\p{L}+\d{1,3}", "Ünïcode42"),
        // path.file_name text operators.
        (14, "notepad", "NOTEPAD.EXE"),
        (23, ".exe", "setup.EXE"),
        // Case-sensitive variants.
        (0x80, r"C:\Tools\*", r"c:\tools\a.exe"),
        (0x80 | 7, "Ex.*", "example"),
    ];
    for (i, (selector, pattern, fact)) in cases.iter().enumerate() {
        let mut bytes = vec![*selector];
        bytes.extend_from_slice(pattern.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(fact.as_bytes());
        fs::write(dir.join(format!("seed-{i}")), bytes).unwrap();
    }
}
