//! `pal fileid`: inspect file identities.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{ArgAction, Args, Subcommand, ValueEnum};
use palisade_fileid::authenticode::{
    CertSelection, Extraction, MAX_EXTRACT_INPUT, RevocationSet, TrustConfig, ValidityPolicy,
    extract_certificates,
};
use palisade_fileid::catalog::{
    CatalogSource, CatalogStore, CatalogStoreBuilder, StoreLimits, ValidityOptions,
};
use palisade_fileid::fsctx::{KnownFolders, NormalizedPath, normalize_win32};
use palisade_fileid::hash::{AlgorithmSet, HashOptions};
use palisade_fileid::identity::{
    self, FileIdentity, IdentityContext, ProtectedList, Tier, Tiers, compare, identify, recommend,
};
use serde_json::{Value, json};

use crate::output::{Format, escape, render};

/// How deep `--recursive` goes.
const MAX_DEPTH: usize = 64;
/// The most directory entries one walk lists; past it the walk stops with an
/// error, so a huge tree cannot exhaust memory.
const MAX_ENTRIES: usize = 1_000_000;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the full identity record of a file, or of every file in a
    /// directory (one JSON object per line with --json).
    Inspect {
        /// A file or a directory.
        path: PathBuf,
        /// The tiers to compute: all, t0..t5, or a list such as t0,t2.
        #[arg(long, default_value = "all", value_parser = parse_tiers)]
        tiers: Tiers,
        /// Walk subdirectories too (symbolic links are not followed).
        #[arg(long)]
        recursive: bool,
        #[command(flatten)]
        format: FormatArgs,
        #[command(flatten)]
        trust: TrustArgs,
    },
    /// Print only the selected hashes of a file.
    Hash {
        /// The file.
        path: PathBuf,
        /// Comma-separated: sha256, sha1, md5, sha384, sha512,
        /// authenticode-sha256, authenticode-sha1, page-sha256, page-sha1,
        /// msi-normalised, script-normalised.
        #[arg(long, value_delimiter = ',', default_value = "sha256")]
        alg: Vec<HashKind>,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Extract the certificates of a file's signatures, or of a catalog
    /// file, into a directory. Each is named by its SHA-256 thumbprint.
    Certs {
        /// A PE file, a catalog (.cat), or a directory of them.
        path: PathBuf,
        /// Which certificates.
        #[arg(long, value_enum, default_value_t = Which::All)]
        which: Which,
        /// Only the signer certificates (same as --which leaf).
        #[arg(long, conflicts_with_all = ["which", "root"])]
        leaf: bool,
        /// Only self-signed roots (same as --which root).
        #[arg(long, conflicts_with_all = ["which", "leaf"])]
        root: bool,
        /// Where to write them. Created if missing.
        #[arg(long)]
        out: PathBuf,
        /// Write PEM instead of DER.
        #[arg(long)]
        pem: bool,
    },
    /// Show the rule-relevant attributes in which two files differ, for
    /// example to check that an update keeps its publisher.
    Compare {
        /// The first file.
        a: PathBuf,
        /// The second file.
        b: PathBuf,
        /// Print JSON.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        trust: TrustArgs,
    },
    /// List every attribute with its identity strength, and recommend a
    /// rule level with the reasons.
    Explain {
        /// The file.
        path: PathBuf,
        /// Print JSON.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        trust: TrustArgs,
    },
}

#[derive(Debug, Args)]
pub struct FormatArgs {
    /// Print JSON.
    #[arg(long, conflicts_with_all = ["yaml", "table"])]
    json: bool,
    /// Print YAML.
    #[arg(long, conflicts_with_all = ["json", "table"])]
    yaml: bool,
    /// Print one line per attribute (the default).
    #[arg(long, conflicts_with_all = ["json", "yaml"])]
    table: bool,
}

impl FormatArgs {
    const fn format(&self) -> Format {
        if self.json {
            Format::Json
        } else if self.yaml {
            Format::Yaml
        } else {
            Format::Table
        }
    }
}

/// Where trust comes from. With none, nothing is trusted: signatures are
/// checked, but no signer is trusted.
#[derive(Debug, Args)]
pub struct TrustArgs {
    /// A trust anchor certificate (DER or PEM) for code signers, catalog
    /// signers and timestamping authorities. Repeatable.
    #[arg(long = "anchor", value_name = "CERT", action = ArgAction::Append)]
    anchors: Vec<PathBuf>,
    /// A well-known OS root, as ID=TBS-HASH (hex). Repeatable. Protected
    /// binaries are expected to chain to one of these.
    #[arg(long = "well-known-root", value_name = "ID=HASH", action = ArgAction::Append)]
    well_known_roots: Vec<String>,
    /// A directory of catalog files (`*.cat`) to look files up in, such as
    /// the OS catalog root.
    #[arg(long, value_name = "DIR")]
    catroot: Option<PathBuf>,
    /// Ignore the built-in protected-binary list.
    #[arg(long)]
    no_protected_list: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Which {
    /// Every certificate in every signature.
    All,
    /// The signer certificate of each signature.
    Leaf,
    /// Self-signed certificates only.
    Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HashKind {
    Sha256,
    Sha1,
    Md5,
    Sha384,
    Sha512,
    AuthenticodeSha256,
    AuthenticodeSha1,
    PageSha256,
    PageSha1,
    MsiNormalised,
    ScriptNormalised,
}

impl HashKind {
    fn name(self) -> &'static str {
        self.to_possible_value()
            .map_or("unknown", |v| match v.get_name() {
                "sha256" => "sha256",
                "sha1" => "sha1",
                "md5" => "md5",
                "sha384" => "sha384",
                "sha512" => "sha512",
                "authenticode-sha256" => "authenticode-sha256",
                "authenticode-sha1" => "authenticode-sha1",
                "page-sha256" => "page-sha256",
                "page-sha1" => "page-sha1",
                "msi-normalised" => "msi-normalised",
                _ => "script-normalised",
            })
    }
}

fn parse_tiers(s: &str) -> Result<Tiers, String> {
    s.parse()
        .map_err(|e: identity::TierParseError| e.to_string())
}

/// Runs a `pal fileid` command. Exit codes: 0 success, 1 a file could not
/// be read or a value is not available, 2 a bad argument.
pub fn run(command: Command) -> ExitCode {
    let result = match command {
        Command::Inspect {
            path,
            tiers,
            recursive,
            format,
            trust,
        } => inspect(&path, tiers, recursive, format.format(), &trust),
        Command::Hash { path, alg, json } => hash(&path, &alg, json),
        Command::Certs {
            path,
            which,
            leaf,
            root,
            out,
            pem,
        } => {
            let which = if leaf {
                Which::Leaf
            } else if root {
                Which::Root
            } else {
                which
            };
            certs(&path, which, &out, pem)
        }
        Command::Compare { a, b, json, trust } => compare_files(&a, &b, json, &trust),
        Command::Explain { path, json, trust } => explain(&path, json, &trust),
    };
    match result {
        Ok(_) if OUTPUT_FAILED.load(std::sync::atomic::Ordering::Relaxed) => ExitCode::FAILURE,
        Ok(code) => code,
        // Messages hold paths and file-derived text: escaped here, once.
        Err(Failure::Usage(msg)) => {
            eprintln!("pal: {}", escape(&msg));
            ExitCode::from(2)
        }
        Err(Failure::Runtime(msg)) => {
            eprintln!("pal: {}", escape(&msg));
            ExitCode::FAILURE
        }
    }
}

enum Failure {
    Usage(String),
    Runtime(String),
}

/// What the [`IdentityContext`] borrows.
struct Trust {
    code: TrustConfig,
    catalogs: Option<CatalogStore>,
    revocation: RevocationSet,
    validity: ValidityPolicy,
    protected: ProtectedList,
    folders: Option<KnownFolders>,
}

impl Trust {
    fn load(args: &TrustArgs) -> Result<Self, Failure> {
        let mut code = TrustConfig::new();
        for path in &args.anchors {
            let bytes = fs::read(path)
                .map_err(|e| Failure::Usage(format!("cannot read {}: {e}", path.display())))?;
            let der = pem_or_der(&bytes);
            let label = path.file_name().map_or_else(
                || path.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            code.add_anchor(label, &der).map_err(|e| {
                Failure::Usage(format!("{} is not a certificate: {e}", path.display()))
            })?;
        }
        for spec in &args.well_known_roots {
            let (id, hash) = spec.split_once('=').ok_or_else(|| {
                Failure::Usage(format!("--well-known-root {spec:?}: use ID=HASH"))
            })?;
            let id: u8 = id
                .trim()
                .parse()
                .map_err(|_| Failure::Usage(format!("--well-known-root {spec:?}: bad ID")))?;
            code.add_well_known_root(id, hash.trim())
                .map_err(|_| Failure::Usage(format!("--well-known-root {spec:?}: bad hash")))?;
        }
        let catalogs = match &args.catroot {
            None => None,
            Some(dir) => {
                // Validity is judged for every catalog signature (expiry,
                // revocation, key sizes, timestamps): a catalog whose
                // validity was not judged never vouches for a file.
                let mut b = CatalogStoreBuilder::new(StoreLimits::default())
                    .trust(CatalogSource::System, code.clone())
                    .validity(ValidityOptions {
                        policy: ValidityPolicy::default(),
                        revocation: RevocationSet::new(),
                        tsa_trust: code.clone(),
                        now: now(),
                        clock_floor: None,
                    });
                if !fs::metadata(dir).is_ok_and(|m| m.is_dir()) {
                    return Err(Failure::Usage(format!(
                        "--catroot {}: not a readable directory",
                        dir.display()
                    )));
                }
                let report = b.add_dir(CatalogSource::System, dir);
                for e in &report.errors {
                    eprintln!("pal: catalog: {}", escape(&e.to_string()));
                }
                // Catalogs that could not be read, or whose signature does
                // not verify, make "not listed" unprovable, so they are an
                // error, not a warning.
                let bad = report.errors.len() + report.recorded.saturating_sub(report.valid);
                if bad > 0 {
                    return Err(Failure::Runtime(format!(
                        "--catroot {}: {bad} catalog file(s) could not be loaded or verified",
                        dir.display()
                    )));
                }
                // An empty catalog root proves nothing: "not listed" would
                // read as a lookup that found nothing.
                if report.valid == 0 {
                    return Err(Failure::Usage(format!(
                        "--catroot {}: no catalog files were found there",
                        dir.display()
                    )));
                }
                Some(b.build())
            }
        };
        Ok(Self {
            code,
            catalogs,
            revocation: RevocationSet::new(),
            validity: ValidityPolicy::default(),
            protected: if args.no_protected_list {
                ProtectedList::empty()
            } else {
                ProtectedList::defaults()
            },
            folders: known_folders(),
        })
    }

    fn context(&self) -> IdentityContext<'_> {
        IdentityContext {
            code_trust: &self.code,
            tsa_trust: &self.code,
            catalogs: self.catalogs.as_ref(),
            revocation: &self.revocation,
            validity: &self.validity,
            now: now(),
            clock_floor: None,
            protected: &self.protected,
            known_folders: self.folders.as_ref(),
            flat_algorithms: AlgorithmSet::DEFAULT | AlgorithmSet::SHA384 | AlgorithmSet::SHA512,
            hash_options: HashOptions::default(),
            max_in_memory: identity::MAX_IN_MEMORY,
        }
    }
}

/// The time the CLI checks signatures at. `pal fileid` is a one-shot
/// diagnostic run by a person; it has no Clock of its own (#29).
fn now() -> i64 {
    #[expect(
        clippy::disallowed_methods,
        reason = "a one-shot CLI diagnostic reads the wall clock once; it has no Clock (#29)"
    )]
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The known folders, from the environment on Windows. The environment is
/// the caller's own, so this is for diagnostics only; the agent reads the
/// folders from the OS.
fn known_folders() -> Option<KnownFolders> {
    if !cfg!(windows) {
        return None;
    }
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    // Each folder through the OS's final path, so an 8.3 short name (a
    // `%TEMP%` of `C:\Users\USER~1\...`) is expanded and the folder can be
    // matched; a folder that cannot be resolved stays as written, and a
    // short name in it then matches nothing.
    let path = |s: String| resolve_folder(&s).or_else(|| normalize_win32(&s).ok());
    let join = |base: &Option<String>, rest: &str| {
        base.as_ref().and_then(|b| path(format!("{b}\\{rest}")))
    };
    let windir = var("SystemRoot");
    let mut f = KnownFolders::default();
    let push = |list: &mut Vec<NormalizedPath>, p: Option<NormalizedPath>| list.extend(p);
    push(
        &mut f.os_drive,
        var("SystemDrive").and_then(|d| path(format!("{d}\\"))),
    );
    push(&mut f.windir, windir.clone().and_then(path));
    push(&mut f.system32, join(&windir, "System32"));
    push(&mut f.system32, join(&windir, "SysWOW64"));
    push(&mut f.program_files, var("ProgramFiles").and_then(path));
    push(
        &mut f.program_files,
        var("ProgramFiles(x86)").and_then(path),
    );
    push(&mut f.program_data, var("ProgramData").and_then(path));
    push(&mut f.user_profile, var("USERPROFILE").and_then(path));
    push(&mut f.app_data, var("APPDATA").and_then(path));
    push(&mut f.local_app_data, var("LOCALAPPDATA").and_then(path));
    push(&mut f.temp, var("TEMP").and_then(path));
    push(&mut f.temp, join(&windir, "Temp"));
    Some(f)
}

#[cfg(windows)]
fn resolve_folder(path: &str) -> Option<NormalizedPath> {
    palisade_fileid::win::fsctx::final_path(Path::new(path)).ok()
}

#[cfg(not(windows))]
const fn resolve_folder(_path: &str) -> Option<NormalizedPath> {
    None
}

/// The DER of a PEM certificate, or `bytes` as they are.
fn pem_or_der(bytes: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return bytes.to_vec();
    };
    let Some(start) = text.find("-----BEGIN CERTIFICATE-----") else {
        return bytes.to_vec();
    };
    let body = &text[start + "-----BEGIN CERTIFICATE-----".len()..];
    let Some(end) = body.find("-----END CERTIFICATE-----") else {
        return bytes.to_vec();
    };
    base64_decode(&body[..end]).unwrap_or_else(|| bytes.to_vec())
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    for c in text.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// inspect

fn inspect(
    path: &Path,
    tiers: Tiers,
    recursive: bool,
    format: Format,
    args: &TrustArgs,
) -> Result<ExitCode, Failure> {
    let trust = Trust::load(args)?;
    let ctx = trust.context();
    let meta = fs::metadata(path)
        .map_err(|e| Failure::Runtime(format!("cannot read {}: {e}", path.display())))?;
    if !meta.is_dir() {
        let id = identify(path, tiers, &ctx)
            .map_err(|e| Failure::Runtime(format!("{}: {e}", path.display())))?;
        print(&render(&to_value(&id), format, false));
        // A record with errors is printed in full, but the run did not
        // compute everything that was asked.
        return Ok(if id.errors.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        });
    }
    let mut failed = false;
    for file in walk(path, recursive) {
        match file {
            Ok(file) => match identify(&file, tiers, &ctx) {
                Ok(id) => {
                    failed |= !id.errors.is_empty();
                    print(&render(&to_value(&id), format, true));
                }
                Err(e) => {
                    failed = true;
                    report_failure(&file, &e.to_string(), format);
                }
            },
            Err((file, e)) => {
                failed = true;
                report_failure(&file, &e.to_string(), format);
            }
        }
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn report_failure(path: &Path, message: &str, format: Format) {
    if format == Format::Json {
        let v = json!({"path": path.to_string_lossy(), "error": message});
        print(&render(&v, Format::Json, true));
    } else {
        eprintln!(
            "pal: {}: {}",
            escape(&path.to_string_lossy()),
            escape(message)
        );
    }
}

fn to_value(id: &FileIdentity) -> Value {
    serde_json::to_value(id).unwrap_or(Value::Null)
}

/// Set when writing to standard output failed for any reason other than a
/// closed pipe; [`run`] then fails, so truncated output never exits 0.
static OUTPUT_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn print(text: &str) {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => {}
        // A closed pipe (`| head`) ends the output; there is nothing to
        // report.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {}
        Err(e) => {
            if !OUTPUT_FAILED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!("pal: writing the output failed: {}", escape(&e.to_string()));
            }
        }
    }
}

/// The regular files under `dir`, in name order. Symbolic links and other
/// non-regular entries are skipped; directories are entered only when
/// `recursive`, and at most [`MAX_DEPTH`] deep.
fn walk(dir: &Path, recursive: bool) -> Vec<Result<PathBuf, (PathBuf, io::Error)>> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_owned(), 0_usize)];
    while let Some((d, depth)) = stack.pop() {
        let mut entries = match fs::read_dir(&d) {
            Ok(r) => r.map(|e| e.map(|e| e.path())).collect::<Vec<_>>(),
            Err(e) => {
                out.push(Err((d, e)));
                continue;
            }
        };
        // A total order: paths by name, read errors after them.
        entries.sort_by(|a, b| match (a, b) {
            (Ok(a), Ok(b)) => a.cmp(b),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => std::cmp::Ordering::Equal,
        });
        let mut subdirs = Vec::new();
        if out.len().saturating_add(entries.len()) > MAX_ENTRIES {
            out.push(Err((
                d,
                io::Error::other(format!(
                    "more than {MAX_ENTRIES} entries; the walk stops here"
                )),
            )));
            return out;
        }
        for entry in entries {
            let p = match entry {
                Ok(p) => p,
                Err(e) => {
                    out.push(Err((d.clone(), e)));
                    continue;
                }
            };
            match fs::symlink_metadata(&p) {
                Ok(m) if m.is_file() => out.push(Ok(p)),
                Ok(m) if m.is_dir() && recursive && depth < MAX_DEPTH => subdirs.push(p),
                Ok(_) => {}
                Err(e) => out.push(Err((p, e))),
            }
        }
        for s in subdirs.into_iter().rev() {
            stack.push((s, depth + 1));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// hash

fn hash(path: &Path, algs: &[HashKind], json_out: bool) -> Result<ExitCode, Failure> {
    let trust = Trust::load(&TrustArgs {
        anchors: Vec::new(),
        well_known_roots: Vec::new(),
        catroot: None,
        no_protected_list: true,
    })?;
    let mut ctx = trust.context();
    ctx.flat_algorithms = AlgorithmSet::ALL;
    // The normalised hashes need the installer or script parsed, which the
    // deep tier does; nothing is trusted here, so no verdict is printed.
    let mut tiers = Tiers::only(Tier::Hash);
    if algs
        .iter()
        .any(|a| matches!(a, HashKind::MsiNormalised | HashKind::ScriptNormalised))
    {
        tiers.insert(Tier::Deep);
    }
    let id = identify(path, tiers, &ctx)
        .map_err(|e| Failure::Runtime(format!("{}: {e}", path.display())))?;
    let h = id.hashes.computed();
    let a = h.and_then(|h| h.authenticode.computed());
    let mut missing = false;
    let mut values = serde_json::Map::new();
    let mut lines = String::new();
    for alg in algs {
        let value: Result<Option<String>, String> = match alg {
            HashKind::Sha256 => Ok(h.and_then(|h| h.sha256.clone())),
            HashKind::Sha1 => Ok(h.and_then(|h| h.sha1.clone())),
            HashKind::Md5 => Ok(h.and_then(|h| h.md5.clone())),
            HashKind::Sha384 => Ok(h.and_then(|h| h.sha384.clone())),
            HashKind::Sha512 => Ok(h.and_then(|h| h.sha512.clone())),
            HashKind::AuthenticodeSha256 => Ok(a.and_then(|a| a.sha256.clone())),
            HashKind::AuthenticodeSha1 => Ok(a.and_then(|a| a.sha1.clone())),
            HashKind::PageSha256 => Ok(a.and_then(|a| a.page_sha256.clone())),
            HashKind::PageSha1 => Ok(a.and_then(|a| a.page_sha1.clone())),
            HashKind::MsiNormalised => {
                Ok(h.and_then(|h| h.msi_normalised_sha256.computed().cloned()))
            }
            HashKind::ScriptNormalised => {
                Ok(h.and_then(|h| h.script_normalised_sha256.computed().cloned()))
            }
        };
        let shown = match value {
            Ok(Some(v)) => {
                values.insert(alg.name().to_owned(), Value::String(v.clone()));
                v
            }
            Ok(None) => {
                missing = true;
                values.insert(alg.name().to_owned(), Value::Null);
                "(not available for this file)".to_owned()
            }
            Err(why) => {
                missing = true;
                values.insert(alg.name().to_owned(), Value::Null);
                format!("({why})")
            }
        };
        lines.push_str(&format!("{}  {shown}\n", alg.name()));
    }
    if let Some(a) = a
        && !a.conformant
    {
        eprintln!(
            "pal: warning: the image does not conform to the Authenticode specification; its Authenticode and page hashes are not authoritative"
        );
    }
    if json_out {
        print(&render(&Value::Object(values), Format::Json, true));
    } else {
        print(&lines);
    }
    for e in &id.errors {
        eprintln!("pal: {}: {}", e.tier, escape(&e.message));
    }
    Ok(if missing || !id.errors.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

// ---------------------------------------------------------------------------
// certs

fn certs(path: &Path, which: Which, out: &Path, pem: bool) -> Result<ExitCode, Failure> {
    // The input first, so a mistyped path leaves no empty output directory.
    let meta = fs::metadata(path)
        .map_err(|e| Failure::Runtime(format!("cannot read {}: {e}", path.display())))?;
    fs::create_dir_all(out)
        .map_err(|e| Failure::Runtime(format!("cannot create {}: {e}", out.display())))?;
    let mut failed = false;
    let files: Vec<PathBuf> = if meta.is_dir() {
        walk(path, false)
            .into_iter()
            .filter_map(|r| match r {
                Ok(p) => Some(p),
                Err((p, e)) => {
                    failed = true;
                    eprintln!(
                        "pal: {}: {}",
                        escape(&p.to_string_lossy()),
                        escape(&e.to_string())
                    );
                    None
                }
            })
            .collect()
    } else {
        vec![path.to_owned()]
    };
    let mut written = 0_usize;
    let mut seen = std::collections::HashSet::new();
    for file in files {
        match certs_of(&file, which) {
            Ok(extraction) => {
                for w in &extraction.warnings {
                    eprintln!(
                        "pal: {}: warning: {}",
                        escape(&file.to_string_lossy()),
                        escape(&format!("{w:?}"))
                    );
                }
                for found in &extraction.certificates {
                    let (cert, is_signer) = (&found.cert, found.is_signer);
                    // Each certificate is written once, however many
                    // signatures or files carry it.
                    if !seen.insert(cert.sha256_thumbprint.clone()) {
                        continue;
                    }
                    let name = format!(
                        "{}.{}",
                        cert.sha256_thumbprint,
                        if pem { "pem" } else { "der" }
                    );
                    let target = out.join(name);
                    let bytes = if pem {
                        cert.pem().into_bytes()
                    } else {
                        cert.der.clone()
                    };
                    if let Err(e) = fs::write(&target, bytes) {
                        return Err(Failure::Runtime(format!(
                            "cannot write {}: {e}",
                            target.display()
                        )));
                    }
                    written += 1;
                    print(&format!(
                        "{}\t{}\t{}{}\n",
                        escape(&file.to_string_lossy()),
                        escape(&target.to_string_lossy()),
                        escape(&cert.subject.canonical),
                        if is_signer { "\t(signer)" } else { "" }
                    ));
                }
            }
            Err(e) => {
                failed = true;
                eprintln!("pal: {}: {}", escape(&file.to_string_lossy()), escape(&e));
            }
        }
    }
    if written == 0 && !failed {
        eprintln!("pal: no certificates found");
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// The signature report of a PE image or a catalog.
/// The certificates of a signed PE image, cabinet, catalog or other PKCS#7
/// file, read through [`extract_certificates`] (#49).
fn certs_of(path: &Path, which: Which) -> Result<Extraction, String> {
    let limit = u64::try_from(MAX_EXTRACT_INPUT).unwrap_or(u64::MAX);
    let bytes = read_bounded(path, limit)?;
    let selection = match which {
        Which::All => CertSelection::All,
        Which::Leaf => CertSelection::Leaf,
        Which::Root => CertSelection::Root,
    };
    extract_certificates(&bytes, selection).map_err(|e| e.to_string())
}

/// Reads a regular file of at most `limit` bytes through one handle. The
/// handle is opened without blocking (a FIFO cannot hang the read) and must
/// be a regular file; the length is checked on that handle and the read is
/// bounded, so a file that grows, or a device that reports length 0,
/// cannot exceed `limit`.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".to_owned());
    }
    if meta.len() > limit {
        return Err(format!("{} bytes is over the limit of {limit}", meta.len()));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != meta.len() {
        return Err("the file changed while it was read".to_owned());
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// compare and explain

fn compare_files(
    a: &Path,
    b: &Path,
    json_out: bool,
    args: &TrustArgs,
) -> Result<ExitCode, Failure> {
    let trust = Trust::load(args)?;
    let ctx = trust.context();
    let ida = identify(a, Tiers::EXECUTION, &ctx)
        .map_err(|e| Failure::Runtime(format!("{}: {e}", a.display())))?;
    let idb = identify(b, Tiers::EXECUTION, &ctx)
        .map_err(|e| Failure::Runtime(format!("{}: {e}", b.display())))?;
    let diffs = compare(&ida, &idb);
    if json_out {
        print(&render(
            &serde_json::to_value(&diffs).unwrap_or(Value::Null),
            Format::Json,
            true,
        ));
    } else if diffs.is_empty() {
        print("no differences in rule-relevant attributes\n");
    } else {
        let show = |v: &Option<String>| v.as_deref().map_or_else(|| "-".to_owned(), escape);
        for d in &diffs {
            print(&format!(
                "{}: {} -> {}\n",
                d.attribute,
                show(&d.a),
                show(&d.b)
            ));
        }
    }
    let same_signer = !diffs
        .iter()
        .any(|d| matches!(d.attribute, "publisher" | "publisher_dn" | "product_name"));
    if !same_signer && !json_out {
        print("note: the publisher or product differs\n");
    }
    Ok(ExitCode::SUCCESS)
}

fn explain(path: &Path, json_out: bool, args: &TrustArgs) -> Result<ExitCode, Failure> {
    let trust = Trust::load(args)?;
    let ctx = trust.context();
    let id = identify(path, Tiers::ALL, &ctx)
        .map_err(|e| Failure::Runtime(format!("{}: {e}", path.display())))?;
    let rec = recommend(&id);
    if json_out {
        let v = json!({
            "strengths": id.strengths,
            "masquerade": id.masquerade,
            "recommendation": rec,
        });
        print(&render(&v, Format::Json, true));
        return Ok(ExitCode::SUCCESS);
    }
    let mut text = String::from("attributes:\n");
    for s in &id.strengths {
        text.push_str(&format!(
            "  {:<38} {:<9} {}\n",
            s.attribute,
            format!("{:?}", s.strength).to_lowercase(),
            s.reason
        ));
    }
    text.push_str(&format!("masquerade score: {}\n", id.masquerade.score));
    for r in &id.masquerade.reasons {
        let v = serde_json::to_value(r).unwrap_or(Value::Null);
        text.push_str(&format!("  {}\n", escape(&v.to_string())));
    }
    text.push_str(&format!(
        "recommended rule level: {}\n",
        serde_json::to_value(rec.level)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    ));
    for (k, v) in &rec.values {
        text.push_str(&format!("  {k} = {}\n", escape(v)));
    }
    for line in &rec.rationale {
        text.push_str(&format!("  because: {}\n", escape(line)));
    }
    for (level, why) in &rec.refused {
        let level = serde_json::to_value(level)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        text.push_str(&format!("  not {level}: {}\n", escape(why)));
    }
    print(&text);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_decodes() {
        let der = [0x30_u8, 0x03, 0x02, 0x01, 0x05];
        let pem = "junk\n-----BEGIN CERTIFICATE-----\nMAMCAQU=\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_or_der(pem.as_bytes()), der);
        assert_eq!(pem_or_der(&der), der);
        assert_eq!(base64_decode("!!"), None);
    }
}
