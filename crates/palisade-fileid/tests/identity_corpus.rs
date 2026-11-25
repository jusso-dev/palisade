//! The file identity corpus (#55): every entry of `corpus/manifest.yaml`
//! is identified and checked against its expected values.
//!
//! See `corpus/README.md` for the entry kinds and how the files and the
//! independent digests are made. Synthetic files are built here
//! ([`corpus_files`]); generated files are committed under `corpus/files/`;
//! OS files are read by path on Windows CI only.

// Test code: helpers may unwrap or index, since a failure should fail
// loudly, and fixture sizes are small constants.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use common::*;
use palisade_fileid::authenticode::TrustConfig;
use palisade_fileid::catalog::{CatalogSource, CatalogStoreBuilder, StoreLimits};
use palisade_fileid::fsctx::{KnownFolders, normalize_win32};
use palisade_fileid::identity::{
    ExpectedSigner, FileIdentity, IdentityContext, ProtectedList, ProtectedVendor, Tiers, identify,
    identify_bytes,
};
use yaml_rust2::{Yaml, YamlLoader};

const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus");

/// 2026-11-25T00:00:00Z: inside every corpus certificate's validity.
const NOW: i64 = 1_795_564_800;

// ---------------------------------------------------------------------------
// Synthetic files.

fn version_image(strings: &[(&str, &str)], file: (u16, u16, u16, u16)) -> PeBuilder {
    let spec = VersionSpec {
        fixed: Some(fixed_info(file, file)),
        tables: vec![(
            "040904B0",
            strings.iter().map(|(k, v)| string(k, v)).collect(),
        )],
        translations: vec![(0x0409, 0x04b0)],
    };
    with_version(&spec)
}

/// A version resource that claims to be the OS PowerShell host.
fn powershell_strings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("CompanyName", "Palisade Tests"),
        ("FileDescription", "Windows PowerShell"),
        ("FileVersion", "10.0.0.1"),
        ("InternalName", "POWERSHELL"),
        ("OriginalFilename", "PowerShell.EXE.MUI"),
        ("ProductName", "Palisade Test OS"),
        ("ProductVersion", "10.0.0.1"),
    ]
}

/// A plain tool's version resource.
fn tool_strings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("CompanyName", "Example Org"),
        ("FileDescription", "Example tool"),
        ("FileVersion", "1.2.3.4"),
        ("InternalName", "extool"),
        ("OriginalFilename", "extool.exe"),
        ("ProductName", "Example Suite"),
        ("ProductVersion", "1.2.0.0"),
    ]
}

/// An import section for a section at `rva` importing `module!function`.
fn import_section(rva: u32, module: &str, function: &str) -> Vec<u8> {
    let mut out = vec![0_u8; 40];
    let thunks = out.len();
    out.resize(thunks + 16, 0);
    let hint = out.len();
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(function.as_bytes());
    out.push(0);
    if out.len() % 2 != 0 {
        out.push(0);
    }
    let name = out.len();
    out.extend_from_slice(module.as_bytes());
    out.push(0);
    out[thunks..thunks + 8].copy_from_slice(&u64::from(rva + hint as u32).to_le_bytes());
    out[0..4].copy_from_slice(&(rva + thunks as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(rva + name as u32).to_le_bytes());
    out[16..20].copy_from_slice(&(rva + thunks as u32).to_le_bytes());
    out
}

/// A native-subsystem image importing the kernel: a driver.
fn driver_image() -> Vec<u8> {
    let builder = PeBuilder {
        subsystem: 1,
        ..PeBuilder::default()
    };
    // The import table goes in the second section, at RVA 0x2000.
    let rva = 0x2000;
    let mut image = builder
        .section(
            ".idata",
            import_section(rva, "ntoskrnl.exe", "IoCreateDevice"),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )
        .build();
    let dir = PeBuilder::default().data_directory_offset(1);
    image[dir..dir + 4].copy_from_slice(&rva.to_le_bytes());
    image[dir + 4..dir + 8].copy_from_slice(&40_u32.to_le_bytes());
    image
}

/// A manifest requesting administrator rights.
fn elevated_image() -> Vec<u8> {
    let xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:example:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:example:asm.v3"><security><requestedPrivileges>
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
</requestedPrivileges></security></trustInfo></assembly>"#;
    PeBuilder {
        resources: vec![Leaf {
            type_id: 24,
            name_id: 1,
            lang: 0x0409,
            data: xml.to_vec(),
        }],
        ..PeBuilder::default()
    }
    .build()
}

/// An image with a CLR runtime header directory entry (.NET).
fn dotnet_image() -> Vec<u8> {
    let mut image = PeBuilder::default().build();
    let dir = PeBuilder::default().data_directory_offset(14);
    image[dir..dir + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
    image[dir + 4..dir + 8].copy_from_slice(&72_u32.to_le_bytes());
    image
}

/// Every synthetic corpus file, by its `generator` name. The same bytes
/// are written for `generate.sh` to sign ([`write_corpus_unsigned`]).
fn corpus_files() -> BTreeMap<&'static str, Vec<u8>> {
    let mut m = BTreeMap::new();
    m.insert("plain", PeBuilder::default().build());
    m.insert("dll", PeBuilder::dll().build());
    m.insert(
        "pe32",
        PeBuilder::pe32()
            .section(".data", vec![7; 3000], IMAGE_SCN_CNT_INITIALIZED_DATA)
            .build(),
    );
    m.insert("tool", version_image(&tool_strings(), (1, 2, 3, 4)).build());
    m.insert(
        "tool-v2",
        version_image(&tool_strings(), (2, 0, 0, 0)).build(),
    );
    m.insert(
        "powershell",
        version_image(&powershell_strings(), (10, 0, 0, 1)).build(),
    );
    m.insert("driver", driver_image());
    m.insert("elevated", elevated_image());
    m.insert("dotnet", dotnet_image());
    m.insert(
        "overlay",
        PeBuilder {
            overlay: b"overlay data".to_vec(),
            ..PeBuilder::default()
        }
        .build(),
    );
    // Not a PE image.
    m.insert("text", b"Palisade corpus: a plain text file.\n".to_vec());
    m.insert("empty", Vec::new());
    m.insert(
        "script",
        b"Write-Output 'Palisade corpus script'\r\n".to_vec(),
    );
    // A script whose language its shebang names.
    m.insert(
        "python",
        b"#!/usr/bin/env python3\nprint('Palisade corpus script')\n".to_vec(),
    );
    // The flat member of the catalog fixtures (`tests/catalog.rs`), which
    // `corpus.cat` lists by its flat SHA-256.
    m.insert(
        "flat-member",
        b"Palisade catalog test: a flat (non-PE) member file.\n".to_vec(),
    );
    // A PE whose headers are cut short: not a parseable image.
    let mut truncated = PeBuilder::default().build();
    truncated.truncate(0x90);
    m.insert("truncated", truncated);
    m
}

/// Writes the synthetic files `generate.sh` signs or lists in a catalog.
///
/// ```sh
/// PALISADE_CORPUS_OUT=/tmp/corpus cargo test -p palisade-fileid \
///     --test identity_corpus -- --ignored --exact write_corpus_unsigned
/// ```
#[test]
#[ignore = "writes files; run by corpus/generate.sh"]
fn write_corpus_unsigned() {
    let dir =
        PathBuf::from(std::env::var_os("PALISADE_CORPUS_OUT").expect("set PALISADE_CORPUS_OUT"));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in corpus_files() {
        std::fs::write(dir.join(format!("{name}.bin")), bytes).unwrap();
    }
}

/// Writes fuzz seeds for `identity_bytes`: every synthetic and generated
/// corpus file, each prefixed by a name hint and a NUL.
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/identity_bytes" cargo test -p palisade-fileid \
///     --test identity_corpus -- --ignored write_identity_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_identity_fuzz_seeds() {
    let dir = PathBuf::from(
        std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR"),
    );
    std::fs::create_dir_all(&dir).unwrap();
    let mut seeds: Vec<(String, Vec<u8>)> = corpus_files()
        .into_iter()
        .map(|(name, bytes)| (format!("{name}.exe"), bytes))
        .collect();
    for e in manifest().into_iter().filter(|e| e.source == "generated") {
        let bytes = std::fs::read(format!("{CORPUS}/files/{}", e.file)).unwrap();
        seeds.push((e.path_as.unwrap_or(e.file), bytes));
    }
    for (i, (name, bytes)) in seeds.into_iter().enumerate() {
        let mut seed = name.into_bytes();
        seed.truncate(64);
        seed.push(0);
        seed.extend(bytes);
        std::fs::write(dir.join(format!("seed-{i:02}")), seed).unwrap();
    }
}

// ---------------------------------------------------------------------------
// The manifest.

#[derive(Debug)]
struct Entry {
    id: String,
    file: String,
    source: String,
    generator: String,
    context: String,
    path_as: Option<String>,
    expected: BTreeMap<String, Yaml>,
}

fn str_of(y: &Yaml, key: &str, id: &str) -> String {
    y[key]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: `{key}` must be a string"))
        .to_owned()
}

fn manifest() -> Vec<Entry> {
    let text = std::fs::read_to_string(format!("{CORPUS}/manifest.yaml")).unwrap();
    let docs = YamlLoader::load_from_str(&text).unwrap();
    let list = docs[0].as_vec().expect("the manifest is a list");
    let mut ids = BTreeSet::new();
    list.iter()
        .map(|e| {
            let id = str_of(e, "id", "?");
            assert!(ids.insert(id.clone()), "duplicate id {id}");
            for key in ["licence", "description"] {
                assert!(
                    e[key].as_str().is_some_and(|s| !s.is_empty()),
                    "{id}: `{key}` is required"
                );
            }
            let known = [
                "id",
                "file",
                "source",
                "licence",
                "generator",
                "description",
                "context",
                "path_as",
                "expected",
            ];
            for k in e.as_hash().unwrap().keys() {
                let k = k.as_str().unwrap();
                assert!(known.contains(&k), "{id}: unknown key `{k}`");
            }
            let expected = e["expected"]
                .as_hash()
                .unwrap_or_else(|| panic!("{id}: `expected` is required"))
                .iter()
                .map(|(k, v)| (k.as_str().unwrap().to_owned(), v.clone()))
                .collect();
            Entry {
                file: str_of(e, "file", &id),
                source: str_of(e, "source", &id),
                generator: str_of(e, "generator", &id),
                context: e["context"].as_str().unwrap_or("default").to_owned(),
                path_as: e["path_as"].as_str().map(str::to_owned),
                expected,
                id,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Contexts.

fn corpus_ca() -> Vec<u8> {
    std::fs::read(format!("{CORPUS}/files/ca.der")).unwrap()
}

/// The machine layout corpus paths use.
fn folders() -> KnownFolders {
    let p = |s: &str| normalize_win32(s).unwrap();
    KnownFolders {
        os_drive: vec![p(r"C:\")],
        windir: vec![p(r"C:\Windows")],
        system32: vec![p(r"C:\Windows\System32"), p(r"C:\Windows\SysWOW64")],
        program_files: vec![p(r"C:\Program Files"), p(r"C:\Program Files (x86)")],
        program_data: vec![p(r"C:\ProgramData")],
        user_profile: vec![p(r"C:\Users\alice")],
        app_data: vec![p(r"C:\Users\alice\AppData\Roaming")],
        local_app_data: vec![p(r"C:\Users\alice\AppData\Local")],
        temp: vec![p(r"C:\Users\alice\AppData\Local\Temp")],
    }
}

/// The built-in protected binaries, and two protected vendors: one whose
/// files the corpus vendor signer signs, and the corpus "OS" product.
fn protected_list() -> ProtectedList {
    let mut list = ProtectedList::defaults();
    list.vendors = vec![
        ProtectedVendor {
            names: vec!["Example Org".to_owned()],
            signer: ExpectedSigner::Publisher("Palisade Corpus Vendor".to_owned()),
        },
        ProtectedVendor {
            names: vec!["Palisade Test OS".to_owned()],
            signer: ExpectedSigner::OsVendor,
        },
    ];
    list
}

struct Contexts {
    untrusted: TrustConfig,
    trusted: TrustConfig,
    catalogs: palisade_fileid::catalog::CatalogStore,
    revocation: palisade_fileid::authenticode::RevocationSet,
    validity: palisade_fileid::authenticode::ValidityPolicy,
    protected: ProtectedList,
    folders: KnownFolders,
}

impl Contexts {
    fn new() -> Self {
        let mut trusted = TrustConfig::new();
        trusted.add_anchor("corpus-ca", &corpus_ca()).unwrap();
        // The corpus root stands in for a well-known OS root, so the
        // protected-binary checks can be exercised.
        let root = palisade_fileid::authenticode::CertSummary::from_der(&corpus_ca()).unwrap();
        trusted
            .add_well_known_root(9, root.tbs_hash.as_deref().unwrap())
            .unwrap();
        let mut b = CatalogStoreBuilder::new(StoreLimits::default())
            .trust(CatalogSource::System, trusted.clone());
        let report = b.add_dir(CatalogSource::System, Path::new(&format!("{CORPUS}/files")));
        assert!(report.errors.is_empty(), "{report:?}");
        Self {
            untrusted: TrustConfig::new(),
            trusted,
            catalogs: b.build(),
            revocation: palisade_fileid::authenticode::RevocationSet::new(),
            validity: palisade_fileid::authenticode::ValidityPolicy::default(),
            protected: protected_list(),
            folders: folders(),
        }
    }

    fn get(&self, name: &str) -> IdentityContext<'_> {
        let mut ctx = IdentityContext::untrusted(NOW);
        ctx.revocation = &self.revocation;
        ctx.validity = &self.validity;
        ctx.protected = &self.protected;
        ctx.known_folders = Some(&self.folders);
        match name {
            "default" => {
                ctx.code_trust = &self.untrusted;
                ctx.tsa_trust = &self.untrusted;
            }
            "trusted" => {
                ctx.code_trust = &self.trusted;
                ctx.tsa_trust = &self.trusted;
                ctx.catalogs = Some(&self.catalogs);
            }
            other => panic!("unknown context {other}"),
        }
        ctx
    }
}

// ---------------------------------------------------------------------------
// Checking.

fn identify_entry(e: &Entry, contexts: &Contexts) -> Option<FileIdentity> {
    let ctx = contexts.get(&e.context);
    let name = e.path_as.as_deref().unwrap_or(&e.file);
    match e.source.as_str() {
        "synthetic" => {
            let files = corpus_files();
            let bytes = files
                .get(e.generator.as_str())
                .unwrap_or_else(|| panic!("{}: no synthetic file {}", e.id, e.generator));
            Some(identify_bytes(bytes, Some(name), Tiers::ALL, &ctx))
        }
        "generated" => {
            let bytes = std::fs::read(format!("{CORPUS}/files/{}", e.file))
                .unwrap_or_else(|err| panic!("{}: {err}", e.id));
            Some(identify_bytes(&bytes, Some(name), Tiers::ALL, &ctx))
        }
        "os" => {
            if !cfg!(windows) {
                return None;
            }
            let path = PathBuf::from(&e.generator);
            match identify(&path, Tiers::ALL, &ctx) {
                Ok(id) => Some(id),
                Err(err) if std::env::var_os("CI").is_some() => {
                    panic!("{}: {err}", e.id)
                }
                Err(_) => None,
            }
        }
        other => panic!("{}: unknown source {other}", e.id),
    }
}

/// `value` as a string, for comparison with a manifest scalar.
fn yaml_text(y: &Yaml) -> String {
    match y {
        Yaml::String(s) | Yaml::Real(s) => s.clone(),
        Yaml::Integer(i) => i.to_string(),
        Yaml::Boolean(b) => b.to_string(),
        Yaml::Null => "null".to_owned(),
        other => format!("{other:?}"),
    }
}

fn opt(v: Option<String>) -> String {
    v.unwrap_or_else(|| "null".to_owned())
}

/// The record's value for a manifest key. Every key the manifest may use
/// is here; any other fails the test.
fn actual(id: &FileIdentity, key: &str) -> String {
    let h = id.hashes.computed();
    let a = h.and_then(|h| h.authenticode.computed());
    let v = id.version();
    let pe = id.pe.computed();
    let s = id.signing_state.computed();
    let json = |v: &dyn erased::Ser| v.to_json();
    match key {
        "size" => opt(id.size.computed().map(ToString::to_string)),
        "sha256" => opt(h.and_then(|h| h.sha256.clone())),
        "sha1" => opt(h.and_then(|h| h.sha1.clone())),
        "md5" => opt(h.and_then(|h| h.md5.clone())),
        "empty" => opt(h.map(|h| h.empty.to_string())),
        "authoritative" => opt(h.map(|h| h.authoritative.to_owned())),
        "authenticode_sha256" => opt(a.and_then(|a| a.sha256.clone())),
        "authenticode_conformant" => opt(a.map(|a| a.conformant.to_string())),
        "is_pe" => pe.is_some().to_string(),
        "content_kind" => opt(id.kind.computed().map(|k| match &k.script_kind {
            Some(s) => format!("script:{s}"),
            None => k.content_kind.clone(),
        })),
        "mismatch_severity" => opt(id.kind.computed().map(|k| k.mismatch_severity.clone())),
        "pe_format" => opt(pe.map(|p| p.format.to_owned())),
        "is_dll" => opt(pe.map(|p| p.is_dll.to_string())),
        "is_kernel_driver" => opt(id.derived.is_kernel_driver.map(|b| b.to_string())),
        "is_dotnet" => opt(id.derived.is_dotnet.map(|b| b.to_string())),
        "requires_elevation" => opt(id.derived.requires_elevation.map(|b| b.to_string())),
        "original_file_name" => opt(v.and_then(|v| v.original_file_name.clone())),
        "file_version" => opt(v.and_then(|v| v.file_version_quad.clone())),
        "product_name" => opt(v.and_then(|v| v.product_name.clone())),
        "effective_file_name" => opt(id
            .derived
            .effective_file_name
            .as_ref()
            .map(|n| n.value.clone())),
        "effective_file_name_source" => opt(id
            .derived
            .effective_file_name
            .as_ref()
            .map(|n| n.source.to_owned())),
        "signing_state" => opt(s.map(|s| json(&s.state))),
        "embedded" => opt(s.map(|s| json(&s.embedded))),
        "catalog" => opt(s.map(|s| json(&s.catalog))),
        "verification_error" => opt(s.map(|s| json(&s.verification_error))),
        "signatures" => opt(id.signatures.computed().map(|v| v.len().to_string())),
        "signer_source" => opt(id.trusted_signer().map(|t| json(&t.source))),
        "publisher" => opt(id.derived.publisher_name.clone()),
        "signer_leaf_sha1_thumbprint" => opt(id
            .trusted_signer()
            .and_then(|t| t.leaf.as_ref())
            .map(|c| c.sha1_thumbprint.clone())),
        "catalog_matches" => opt(id.catalog_matches.computed().map(|m| m.len().to_string())),
        "masquerade_score" => id.masquerade.score.to_string(),
        "masquerade_reasons" => {
            let mut kinds: Vec<String> = id
                .masquerade
                .reasons
                .iter()
                .map(|r| {
                    serde_json::to_value(r).unwrap()["kind"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect();
            kinds.sort();
            kinds.join(",")
        }
        "recommended_level" => json(&palisade_fileid::identity::recommend(id).level),
        other => panic!("unknown expected key `{other}`"),
    }
}

mod erased {
    /// Serialises a `snake_case` enum to its name.
    pub trait Ser {
        fn to_json(&self) -> String;
    }
    impl<T: serde::Serialize> Ser for T {
        fn to_json(&self) -> String {
            match serde_json::to_value(self).unwrap() {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            }
        }
    }
}

fn check_expected(e: &Entry, id: &FileIdentity) -> Vec<String> {
    let mut failures = Vec::new();
    for (key, want) in &e.expected {
        let want = match want {
            Yaml::Array(items) => {
                let mut v: Vec<String> = items.iter().map(yaml_text).collect();
                v.sort();
                v.join(",")
            }
            other => yaml_text(other),
        };
        let got = actual(id, key);
        if got != want {
            failures.push(format!("{}: {key}: expected {want}, got {got}", e.id));
        }
    }
    failures
}

#[test]
fn corpus_matches_the_manifest() {
    let entries = manifest();
    let contexts = Contexts::new();
    let mut failures = Vec::new();
    let mut checked = 0;
    for e in &entries {
        let Some(id) = identify_entry(e, &contexts) else {
            continue;
        };
        checked += 1;
        assert_eq!(id.schema, "fileid.v1");
        failures.extend(check_expected(e, &id));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(checked >= 20, "only {checked} entries ran");
}

// ---------------------------------------------------------------------------
// Regression tests that need the corpus files and contexts.

fn signed_powershell() -> Vec<u8> {
    std::fs::read(format!("{CORPUS}/files/signed-powershell.exe")).unwrap()
}

/// A protected binary with a valid embedded signature, judged under a
/// policy that cannot recognise its expected signer: unassessed, never an
/// impostor.
#[test]
fn signed_protected_binary_without_a_root_table_is_unassessed() {
    let contexts = Contexts::new();
    let mut ctx = contexts.get("default");
    // A trust anchor, but no well-known root table.
    let mut anchors = TrustConfig::new();
    anchors.add_anchor("corpus-ca", &corpus_ca()).unwrap();
    for trust in [&contexts.untrusted, &anchors] {
        ctx.code_trust = trust;
        let id = identify_bytes(
            &signed_powershell(),
            Some("powershell.exe"),
            Tiers::ALL,
            &ctx,
        );
        assert_eq!(id.masquerade.score, 0, "{:?}", id.masquerade);
        assert!(id.masquerade.unassessed.contains(&"known_binary_relocated"));
    }
    // Unsigned, the same claim is an impostor whatever the policy.
    let unsigned = corpus_files()["powershell"].clone();
    let mut ctx = contexts.get("trusted");
    ctx.code_trust = &contexts.untrusted;
    let id = identify_bytes(&unsigned, Some("powershell.exe"), Tiers::ALL, &ctx);
    assert!(
        id.masquerade.reasons.iter().any(|r| matches!(
            r,
            palisade_fileid::identity::MasqueradeReason::ProtectedNameClaimed { .. }
        )),
        "{:?}",
        id.masquerade
    );
}

/// A file revoked by hash is never trusted through a catalog.
#[test]
fn revoked_hash_beats_a_catalog_match() {
    use palisade_fileid::hash::{Digest, HashAlgorithm};
    let contexts = Contexts::new();
    let plain = corpus_files()["plain"].clone();
    let trusted = identify_bytes(
        &plain,
        Some("plain.exe"),
        Tiers::ALL,
        &contexts.get("trusted"),
    );
    let state = trusted.signing_state.computed().unwrap();
    assert_eq!(
        state.state,
        palisade_fileid::identity::SigningStateKind::Trusted
    );
    let sha = trusted.hashes.computed().unwrap().sha256.clone().unwrap();

    let mut revocation = palisade_fileid::authenticode::RevocationSet::new();
    revocation.add_file_hash(Digest::parse(HashAlgorithm::Sha256, &sha).unwrap());
    let mut ctx = contexts.get("trusted");
    ctx.revocation = &revocation;
    let id = identify_bytes(&plain, Some("plain.exe"), Tiers::ALL, &ctx);
    let state = id.signing_state.computed().unwrap();
    assert_eq!(
        state.state,
        palisade_fileid::identity::SigningStateKind::Invalid
    );
    assert_eq!(state.verification_error.as_str(), "revoked_by_hash");
    assert!(state.signer.is_none());
    assert_ne!(
        palisade_fileid::identity::recommend(&id).level,
        palisade_fileid::identity::RuleLevel::Publisher
    );

    // Non-PE: the same for a flat-hash catalog member.
    let member = corpus_files()["flat-member"].clone();
    let sha =
        palisade_fileid::hash::hash_bytes(&member, palisade_fileid::hash::AlgorithmSet::SHA256)
            .get(HashAlgorithm::Sha256)
            .unwrap()
            .clone();
    let mut revocation = palisade_fileid::authenticode::RevocationSet::new();
    revocation.add_file_hash(sha);
    ctx.revocation = &revocation;
    let id = identify_bytes(&member, Some("member.txt"), Tiers::ALL, &ctx);
    assert_eq!(
        id.signing_state.computed().unwrap().state,
        palisade_fileid::identity::SigningStateKind::Invalid
    );
}

/// A catalog whose signer certificate is revoked vouches for nothing.
#[test]
fn revoked_catalog_signer_is_not_trusted() {
    use palisade_fileid::authenticode::{
        CertificateMatch, RevocationReason, RevocationSource, RevokedCertificate,
    };
    let contexts = Contexts::new();
    let plain = corpus_files()["plain"].clone();
    let baseline = identify_bytes(
        &plain,
        Some("plain.exe"),
        Tiers::ALL,
        &contexts.get("trusted"),
    );
    let leaf = baseline.trusted_signer().unwrap().leaf.clone().unwrap();
    let mut revocation = palisade_fileid::authenticode::RevocationSet::new();
    revocation.add_certificate(RevokedCertificate {
        cert: CertificateMatch::Sha256Thumbprint(leaf.sha256_thumbprint.clone()),
        revoked_at: None,
        reason: RevocationReason::Unspecified,
        source: RevocationSource::Policy,
    });
    let mut ctx = contexts.get("trusted");
    ctx.revocation = &revocation;
    let id = identify_bytes(&plain, Some("plain.exe"), Tiers::ALL, &ctx);
    let state = id.signing_state.computed().unwrap();
    assert!(state.signer.is_none(), "{state:?}");
    assert_ne!(
        state.state,
        palisade_fileid::identity::SigningStateKind::Trusted
    );
    let matches = id.catalog_matches.computed().unwrap();
    assert!(matches.iter().all(|m| m.signer_revoked));
}

/// A clock before the floor is reported for every file, embedded-signed or
/// not, and revocation is judged at the floor.
#[test]
fn clock_floor_applies_to_catalog_files() {
    let contexts = Contexts::new();
    let mut ctx = contexts.get("trusted");
    ctx.clock_floor = Some(NOW + 86_400);
    for (bytes, name) in [
        (corpus_files()["plain"].clone(), "plain.exe"),
        (corpus_files()["flat-member"].clone(), "member.txt"),
    ] {
        let id = identify_bytes(&bytes, Some(name), Tiers::ALL, &ctx);
        assert!(id.signing_state.computed().unwrap().clock_suspect, "{name}");
    }
    let id = identify_bytes(
        &corpus_files()["plain"],
        Some("plain.exe"),
        Tiers::ALL,
        &contexts.get("trusted"),
    );
    assert!(!id.signing_state.computed().unwrap().clock_suspect);
}

/// Catalog signer revocation is judged at the clock floor: a CRL current
/// by the clock but expired by the floor covers nothing, and fails closed
/// where policy says so.
#[test]
fn catalog_revocation_is_judged_at_the_floor() {
    use palisade_fileid::authenticode::{Crl, RevocationFailure, RevocationMode, RevocationSet};
    let contexts = Contexts::new();
    let crl =
        Crl::from_der(&std::fs::read(format!("{CORPUS}/files/ca-2025-2027.crl")).unwrap()).unwrap();
    let mut revocation = RevocationSet::new();
    revocation.add_crl(crl).unwrap();
    revocation.mode = RevocationMode::OnlineRequired;
    revocation.failure = RevocationFailure::FailClosed;
    let plain = corpus_files()["plain"].clone();
    let state = |now: i64, floor: Option<i64>| {
        let mut ctx = contexts.get("trusted");
        ctx.revocation = &revocation;
        ctx.now = now;
        ctx.clock_floor = floor;
        identify_bytes(&plain, Some("plain.exe"), Tiers::ALL, &ctx)
            .signing_state
            .computed()
            .unwrap()
            .state
    };
    // 2026: the CRL is current, so the signer is not revoked.
    let in_2026 = 1_767_225_600;
    let in_2028 = 1_830_297_600;
    assert_eq!(
        state(in_2026, None),
        palisade_fileid::identity::SigningStateKind::Trusted
    );
    // A clock rolled back to 2026 under a 2028 floor: judged in 2028, when
    // the CRL has expired, so the answer is missing and fails closed.
    assert_ne!(
        state(in_2026, Some(in_2028)),
        palisade_fileid::identity::SigningStateKind::Trusted
    );
}

/// Code in a named stream is reported, and its name is checked as well as
/// the host's.
#[test]
fn named_streams_are_checked() {
    use palisade_fileid::identity::MasqueradeReason as R;
    let contexts = Contexts::new();
    let ctx = contexts.get("default");
    let kinds = |bytes: &[u8], path: &str| -> Vec<String> {
        identify_bytes(bytes, Some(path), Tiers::ALL, &ctx)
            .masquerade
            .reasons
            .iter()
            .map(|r| {
                serde_json::to_value(r).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    };
    let tool = corpus_files()["tool"].clone();
    let k = kinds(&tool, r"C:\temp\a:invoice.pdf.exe");
    assert!(k.contains(&"alternate_data_stream".to_owned()), "{k:?}");
    assert!(k.contains(&"double_extension".to_owned()), "{k:?}");
    // A host whose name the classifier reads, and an extension that is the
    // host's, never the stream's.
    let id = identify_bytes(
        &tool,
        Some(r"C:\temp\extool.pdf:ads:$DATA"),
        Tiers::ALL,
        &ctx,
    );
    assert_eq!(id.name.file_name.as_deref(), Some("extool.pdf"));
    assert_eq!(id.name.extension.as_deref(), Some("pdf"));
    assert!(id.masquerade.score >= 50, "{:?}", id.masquerade);
    let id = identify_bytes(&tool, Some(r"C:\temp\a.txt:evil.exe"), Tiers::ALL, &ctx);
    for r in &id.masquerade.reasons {
        if let R::ExtensionMismatch { extension, .. } = r {
            assert_eq!(extension, "txt", "the host's extension, not the stream's");
        }
    }
    let script = corpus_files()["python"].clone();
    let k = kinds(&script, r"C:\temp\run.py:readme.txt");
    assert!(k.contains(&"alternate_data_stream".to_owned()), "{k:?}");
    // A bare `::$DATA` is a name, not nothing.
    let id = identify_bytes(&tool, Some(r"C:\temp\::$DATA"), Tiers::ALL, &ctx);
    assert!(id.name.file_name.is_some());
}

/// Invalid files (tampered, or revoked by hash) get no allow rule.
#[test]
fn invalid_files_get_no_rule() {
    let contexts = Contexts::new();
    let tampered = std::fs::read(format!("{CORPUS}/files/tampered-tool.exe")).unwrap();
    let id = identify_bytes(
        &tampered,
        Some("x.exe"),
        Tiers::ALL,
        &contexts.get("trusted"),
    );
    assert_eq!(
        id.signing_state.computed().unwrap().state,
        palisade_fileid::identity::SigningStateKind::Invalid
    );
    let rec = palisade_fileid::identity::recommend(&id);
    assert_eq!(rec.level, palisade_fileid::identity::RuleLevel::None);
    assert!(rec.values.is_empty());
}

/// An unsigned PE with no catalog store is unverified, and the reason
/// says so, rather than blaming its file type.
#[test]
fn unverified_reason_names_the_missing_catalog_lookup() {
    let contexts = Contexts::new();
    let id = identify_bytes(
        &corpus_files()["plain"],
        Some("plain.exe"),
        Tiers::ALL,
        &contexts.get("default"),
    );
    let rec = palisade_fileid::identity::recommend(&id);
    let why: Vec<&str> = rec.refused.iter().map(|(_, w)| w.as_str()).collect();
    assert!(
        why.iter().any(|w| w.contains("no catalogs were given")),
        "{why:?}"
    );
    assert!(!why.iter().any(|w| w.contains("#52")), "{why:?}");
    let text = identify_bytes(
        &corpus_files()["text"],
        Some("a.txt"),
        Tiers::ALL,
        &contexts.get("default"),
    );
    let rec = palisade_fileid::identity::recommend(&text);
    assert!(rec.refused.iter().any(|(_, w)| w.contains("#52")));
}

#[test]
fn every_synthetic_file_is_in_the_manifest() {
    let used: BTreeSet<String> = manifest()
        .into_iter()
        .filter(|e| e.source == "synthetic")
        .map(|e| e.generator)
        .collect();
    for name in corpus_files().keys() {
        assert!(
            used.contains(*name),
            "synthetic file {name} has no manifest entry"
        );
    }
}

#[test]
fn every_committed_file_is_in_the_manifest() {
    let listed: BTreeSet<String> = manifest()
        .into_iter()
        .filter(|e| e.source == "generated")
        .map(|e| e.file)
        .collect();
    let support = ["ca.der", "ca-2025-2027.crl", "corpus.cat", ".gitattributes"];
    for entry in std::fs::read_dir(format!("{CORPUS}/files")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert!(
            listed.contains(&name) || support.contains(&name.as_str()),
            "{name} is committed but not in the manifest"
        );
    }
}
