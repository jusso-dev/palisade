//! The file identity corpus (#55): every entry of `fixtures/identity/manifest.yaml`
//! is identified and checked against its expected values.
//!
//! See `fixtures/identity/README.md` for the entry kinds and how the files and the
//! independent digests are made. Synthetic files are built here
//! (`fixtures/identity/synthetic.rs`); generated (signed) files are built here too, by
//! `fixtures/identity/signed.rs`, deterministically, and their digests are
//! the ones `fixtures/identity/generate.sh` computes with independent
//! tools; OS files are read by path on Windows CI only. Nothing signed is
//! committed.

// Test code: helpers may unwrap or index, since a failure should fail
// loudly, and fixture sizes are small constants.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod common;
mod corpus;
#[path = "fixtures/identity/signed.rs"]
mod signed;
#[path = "fixtures/identity/synthetic.rs"]
mod synthetic;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use palisade_fileid::authenticode::TrustConfig;
use palisade_fileid::catalog::{CatalogSource, CatalogStoreBuilder, StoreLimits};
use palisade_fileid::fsctx::{KnownFolders, normalize_win32};
use palisade_fileid::identity::{
    ExpectedSigner, Field, FileIdentity, IdentityContext, ProtectedList, ProtectedVendor, Tiers,
    identify, identify_bytes,
};
use synthetic::corpus_files;
use yaml_rust2::{Yaml, YamlLoader};

const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/identity");

/// 2026-11-25T00:00:00Z: inside every corpus certificate's validity.
const NOW: i64 = 1_795_564_800;

/// 2027-01-01T00:00:00Z: inside the validity of the script, installer and
/// package fixture sets' certificates, which start on 2026-11-24 to 27.
const FIXTURE_NOW: i64 = 1_798_761_600;

/// A file of one of the crate's committed, independently signed fixture
/// sets (`tests/fixtures/<set>/`).
fn fixture_set_file(set: &str, name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{set}/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Every generated corpus file: the signed files, the catalogs, the CA and
/// its CRL, by name, built from the synthetic files.
fn generated_files() -> BTreeMap<&'static str, Vec<u8>> {
    signed::generated(&corpus_files())
}

fn generated(name: &str) -> Vec<u8> {
    generated_files()
        .remove(name)
        .unwrap_or_else(|| panic!("no generated file {name}"))
}

/// Writes every synthetic and generated corpus file, for `generate.sh` to
/// check with independent tools.
///
/// ```sh
/// PALISADE_CORPUS_OUT=/tmp/corpus cargo test -p palisade-fileid \
///     --test identity_corpus -- --ignored --exact write_corpus_files
/// ```
#[test]
#[ignore = "writes files; run by fixtures/identity/generate.sh"]
fn write_corpus_files() {
    let dir =
        PathBuf::from(std::env::var_os("PALISADE_CORPUS_OUT").expect("set PALISADE_CORPUS_OUT"));
    std::fs::create_dir_all(dir.join("unsigned")).unwrap();
    for (name, bytes) in corpus_files() {
        std::fs::write(dir.join("unsigned").join(format!("{name}.bin")), bytes).unwrap();
    }
    for (name, bytes) in generated_files() {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

/// Writes the synthetic files `generate.sh` signs or lists in a catalog.
///
/// ```sh
/// PALISADE_CORPUS_OUT=/tmp/corpus cargo test -p palisade-fileid \
///     --test identity_corpus -- --ignored --exact write_corpus_unsigned
/// ```
#[test]
#[ignore = "writes files; run by fixtures/identity/generate.sh"]
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
        let bytes = generated(&e.file);
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
    /// A crate feature the entry needs (`os-trust`); skipped without it.
    requires: Option<String>,
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
                "requires",
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
                requires: e["requires"].as_str().map(str::to_owned),
                expected,
                id,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Contexts.

fn corpus_ca() -> Vec<u8> {
    generated("ca.der")
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
    /// The throwaway test roots of the script, installer and package
    /// fixture sets (`tests/fixtures/{script,installer,package}/ca.der`).
    fixture_roots: TrustConfig,
    catalogs: palisade_fileid::catalog::CatalogStore,
    revocation: palisade_fileid::authenticode::RevocationSet,
    /// The corpus CA's CRL, which revokes the vendor's second certificate.
    crl_revocation: palisade_fileid::authenticode::RevocationSet,
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
        let b = CatalogStoreBuilder::new(StoreLimits::default())
            .trust(CatalogSource::System, trusted.clone());
        // Validity is judged, as an agent does: a catalog whose validity
        // was not judged never vouches (#50).
        let mut b = b.validity(palisade_fileid::catalog::ValidityOptions {
            policy: palisade_fileid::authenticode::ValidityPolicy::default(),
            revocation: palisade_fileid::authenticode::RevocationSet::new(),
            tsa_trust: trusted.clone(),
            now: NOW,
            clock_floor: None,
        });
        for name in ["corpus.cat", "expired.cat"] {
            let report = b.add_bytes(
                CatalogSource::System,
                Some(PathBuf::from(name)),
                &generated(name),
            );
            assert!(report.errors.is_empty(), "{name}: {report:?}");
        }
        let mut fixture_roots = TrustConfig::new();
        for set in ["script", "installer", "package"] {
            fixture_roots
                .add_anchor(format!("{set} test root"), &fixture_set_file(set, "ca.der"))
                .unwrap();
        }
        Self {
            untrusted: TrustConfig::new(),
            trusted,
            fixture_roots,
            catalogs: b.build(),
            revocation: palisade_fileid::authenticode::RevocationSet::new(),
            crl_revocation: {
                let mut r = palisade_fileid::authenticode::RevocationSet::new();
                r.add_crl(
                    palisade_fileid::authenticode::Crl::from_der(&generated("ca-2025-2027.crl"))
                        .unwrap(),
                )
                .unwrap();
                r
            },
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
            // The script, installer and package fixture roots trusted,
            // at a time inside their certificates' validity.
            "fixture_roots" => {
                ctx.code_trust = &self.fixture_roots;
                ctx.tsa_trust = &self.fixture_roots;
                ctx.now = FIXTURE_NOW;
            }
            // Nothing trusted, at the same time.
            "fixture_untrusted" => {
                ctx.code_trust = &self.untrusted;
                ctx.tsa_trust = &self.untrusted;
                ctx.now = FIXTURE_NOW;
            }
            // Trusted, with the corpus CA's CRL.
            "trusted_crl" => {
                ctx.code_trust = &self.trusted;
                ctx.tsa_trust = &self.trusted;
                ctx.catalogs = Some(&self.catalogs);
                ctx.revocation = &self.crl_revocation;
            }
            other => panic!("unknown context {other}"),
        }
        ctx
    }
}

// ---------------------------------------------------------------------------
// Checking.

fn identify_entry(e: &Entry, contexts: &Contexts) -> Option<FileIdentity> {
    match e.requires.as_deref() {
        None => {}
        Some("os-trust") if cfg!(feature = "os-trust") => {}
        Some("os-trust") => return None,
        Some(other) => panic!("{}: unknown requirement {other}", e.id),
    }
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
            let bytes = generated(&e.file);
            Some(identify_bytes(&bytes, Some(name), Tiers::ALL, &ctx))
        }
        // A file of another committed fixture set, by `set/name`.
        "fixture" => {
            // `set/name`, optionally `+appendN`: the file with N bytes
            // appended (0x41), as the installer tests append them.
            let (path, append) = match e.generator.split_once("+append") {
                Some((p, n)) => (p, n.parse::<usize>().expect("+appendN")),
                None => (e.generator.as_str(), 0),
            };
            let (set, file) = path
                .split_once('/')
                .unwrap_or_else(|| panic!("{}: generator is set/name", e.id));
            let mut bytes = fixture_set_file(set, file);
            bytes.extend(std::iter::repeat_n(0x41, append));
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
        "embedded_invalid_reason" => opt(s.and_then(|s| s.embedded_invalid_reason.clone())),
        "msi_normalised_sha256" => opt(h.and_then(|h| h.msi_normalised_sha256.computed().cloned())),
        "script_normalised_sha256" => {
            opt(h.and_then(|h| h.script_normalised_sha256.computed().cloned()))
        }
        "script_signing_state" => opt(id.script.computed().map(|s| s.signing_state.to_owned())),
        "installer_kind" => opt(id.installer.computed().map(|i| i.kind.to_owned())),
        "product_code" => opt(id.installer.computed().and_then(|i| i.product_code.clone())),
        "package_pfn" => opt(id.package.computed().map(|p| p.pfn.clone())),
        "package_bundle" => opt(id.package.computed().map(|p| p.is_bundle.to_string())),
        "package_signature_issue" => opt(id
            .package
            .computed()
            .and_then(|p| p.signature_issue.clone())),
        "package_display_name" => opt(id
            .trusted_signer()
            .and_then(|t| t.package_display_name.clone())),
        "signature_kind" => opt(id
            .signatures
            .computed()
            .and_then(|v| v.first())
            .map(|s| s.kind.to_owned())),
        "fs_owner_trust_class" => opt(id.fs.owner.computed().map(|o| o.trust_class.clone())),
        "fs_path_user_writable" => opt(id
            .fs
            .user_writable
            .computed()
            .map(|w| w.path_user_writable.to_string())),
        "fs_location" => opt(id.fs.volume.computed().map(|v| v.location.clone())),
        "fs_file_system" => opt(id.fs.volume.computed().and_then(|v| v.fs_type.clone())),
        "fs_reparse" => opt(id
            .fs
            .reparse
            .computed()
            .map(|r| r.as_ref().map_or("none".to_owned(), |r| r.kind.clone()))),
        "fs_has_file_id" => opt(id
            .fs
            .file_id
            .computed()
            .map(|f| f.file_id.is_some().to_string())),
        k if k.starts_with("strength.") => opt(id
            .strengths
            .iter()
            .find(|s| Some(s.attribute) == k.strip_prefix("strength."))
            .map(|s| json(&s.strength))),
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
    generated("signed-powershell.exe")
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
    let crl = Crl::from_der(&generated("ca-2025-2027.crl")).unwrap();
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
    let tampered = generated("tampered-tool.exe");
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
    assert!(
        rec.refused
            .iter()
            .any(|(_, w)| w.contains("signatures are not read")),
        "{rec:?}"
    );
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
fn every_generated_file_is_in_the_manifest() {
    let listed: BTreeSet<String> = manifest()
        .into_iter()
        .filter(|e| e.source == "generated")
        .map(|e| e.file)
        .collect();
    let support = ["ca.der", "ca-2025-2027.crl", "corpus.cat", "expired.cat"];
    for name in generated_files().keys() {
        assert!(
            listed.contains(*name) || support.contains(name),
            "{name} is generated but not in the manifest"
        );
    }
    // Nothing executable is committed: the files are built here.
    assert!(!Path::new(&format!("{CORPUS}/files")).exists());
}

/// B1 (#294 review): a catalog signed by an expired, untimestamped signer
/// under a trusted CA vouches for nothing; B2: a SHA-1-only embedded
/// signature from a trusted signer vouches for nothing either. Neither may
/// give a publisher rule.
#[test]
fn expired_catalogs_and_sha1_signatures_vouch_for_nothing() {
    use palisade_fileid::identity::{RuleLevel, SigningStateKind, recommend};
    let contexts = Contexts::new();
    let ctx = contexts.get("trusted");
    let driver = identify_bytes(
        &corpus_files()["driver"],
        Some("palisade.sys"),
        Tiers::ALL,
        &ctx,
    );
    let s = driver.signing_state.computed().unwrap();
    assert_eq!(s.state, SigningStateKind::Untrusted, "{s:?}");
    assert!(s.signer.is_none());
    let m = &driver.catalog_matches.computed().unwrap()[0];
    assert!(m.trusted, "the signer chains to the trusted CA");
    assert_eq!(
        m.validity,
        Some(palisade_fileid::authenticode::VerificationError::Expired)
    );
    assert!(!matches!(
        recommend(&driver).level,
        RuleLevel::Publisher | RuleLevel::PublisherProduct | RuleLevel::FilePublisher
    ));
    // The same catalog's validity never judged: still no vouching.
    let mut unjudged = CatalogStoreBuilder::new(StoreLimits::default())
        .trust(CatalogSource::System, contexts.trusted.clone());
    unjudged.add_bytes(CatalogSource::System, None, &generated("expired.cat"));
    let store = unjudged.build();
    let mut ctx2 = contexts.get("trusted");
    ctx2.catalogs = Some(&store);
    let id = identify_bytes(
        &corpus_files()["driver"],
        Some("palisade.sys"),
        Tiers::ALL,
        &ctx2,
    );
    assert_ne!(
        id.signing_state.computed().unwrap().state,
        SigningStateKind::Trusted
    );

    let sha1 = identify_bytes(
        &generated("sha1-signed-tool.exe"),
        Some("extool.exe"),
        Tiers::ALL,
        &ctx,
    );
    let s = sha1.signing_state.computed().unwrap();
    assert_eq!(s.embedded, palisade_fileid::identity::EmbeddedState::Valid);
    assert!(s.embedded_sha1_only);
    assert!(s.signer.is_none());
    assert_eq!(s.state, SigningStateKind::Untrusted);
    assert!(!matches!(
        recommend(&sha1).level,
        RuleLevel::Publisher | RuleLevel::PublisherProduct | RuleLevel::FilePublisher
    ));
}

/// M1 (#294 review): a validly signed file whose signer is revoked is
/// invalid and gets no rule at all; M2: a file whose masquerade checks
/// could not run gets no rule either.
#[test]
fn revoked_and_unassessed_files_get_no_rule() {
    use palisade_fileid::identity::{RuleLevel, SigningStateKind, recommend};
    let contexts = Contexts::new();
    let id = identify_bytes(
        &generated("revoked-signed-tool.exe"),
        Some("extool.exe"),
        Tiers::ALL,
        &contexts.get("trusted_crl"),
    );
    let s = id.signing_state.computed().unwrap();
    assert_eq!(s.state, SigningStateKind::Invalid, "{s:?}");
    let rec = recommend(&id);
    assert_eq!(rec.level, RuleLevel::None, "{rec:?}");
    assert!(rec.values.is_empty());

    // Nothing trusted: the PowerShell host at its own path cannot be told
    // from an impostor, so its checks are unassessed and nothing is
    // reported (score 0). Before #294's review this got a hash rule.
    let mut id = identify_bytes(
        &signed_powershell(),
        Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        Tiers::ALL,
        &contexts.get("default"),
    );
    assert_eq!(id.masquerade.score, 0);
    assert!(
        id.masquerade.unassessed.contains(&"known_binary_relocated"),
        "{:?}",
        id.masquerade
    );
    assert_eq!(recommend(&id).level, RuleLevel::None);
    // And with the unassessed checks taken away, its OriginalFilename still
    // names a protected binary no trusted signer vouches for.
    assert!(id.masquerade.claims_protected.is_some());
    id.masquerade.unassessed.clear();
    let rec = recommend(&id);
    assert_eq!(rec.level, RuleLevel::None, "{rec:?}");
    assert!(rec.values.is_empty());
}

/// #294 review (CodeRabbit, `masquerade.rs`): a protected binary is
/// "moved" only when every folder it may live in was resolved. With the
/// machine's System32 known only by an 8.3 short name (which cannot be
/// compared) or not at all, the PowerShell host is never reported as
/// moved, wherever it is: the location is unassessed.
#[test]
fn location_is_unassessed_unless_every_folder_is_known() {
    use palisade_fileid::identity::MasqueradeReason;
    let contexts = Contexts::new();
    let mut short = folders();
    short.system32 = vec![normalize_win32(r"C:\WINDOW~1\System32").unwrap()];
    let mut unknown = folders();
    unknown.system32.clear();
    for (path, partial) in [
        (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            &short,
        ),
        (r"C:\Users\alice\powershell.exe", &short),
        (r"C:\Users\alice\powershell.exe", &unknown),
    ] {
        let mut ctx = contexts.get("trusted");
        ctx.known_folders = Some(partial);
        let id = identify_bytes(&signed_powershell(), Some(path), Tiers::ALL, &ctx);
        assert!(
            !id.masquerade.reasons.iter().any(|r| matches!(
                r,
                MasqueradeReason::KnownBinaryRelocated { moved: true, .. }
            )),
            "{path}: {:?}",
            id.masquerade
        );
        assert!(
            id.masquerade.unassessed.contains(&"known_binary_location"),
            "{path}: {:?}",
            id.masquerade
        );
    }
}

/// #55 wiring: a script's or package's identity never lets a renamed
/// protected binary through.
///
/// - The protected PowerShell host, named as a script or a package, is
///   judged as the PE it is: no script or package reader runs, and the
///   rename is still reported.
/// - A trusted script signer whose signed metadata claims a protected
///   binary's `OriginalFilename` is not that binary's signer: the claim is
///   reported and no rule is recommended.
/// - A package whose display name claims a protected vendor, under a
///   signer that vendor does not expect, is impersonation.
#[test]
fn script_and_package_identity_never_vouch_for_a_protected_binary() {
    use palisade_fileid::identity::{MasqueradeReason, RuleLevel, masquerade, recommend};
    let contexts = Contexts::new();
    let ctx = contexts.get("trusted");
    for name in [
        r"C:\Users\alice\AppData\Local\Temp\notepad.ps1",
        r"C:\Users\alice\AppData\Local\Temp\notepad.msix",
        r"C:\Users\alice\AppData\Local\Temp\notepad.msi",
    ] {
        let id = identify_bytes(&signed_powershell(), Some(name), Tiers::ALL, &ctx);
        assert!(id.pe.is_computed(), "{name}");
        assert_eq!(id.script, Field::NotApplicable, "{name}");
        assert_eq!(id.package, Field::NotApplicable, "{name}");
        assert_eq!(id.installer, Field::NotApplicable, "{name}");
        assert!(
            id.masquerade
                .reasons
                .iter()
                .any(|r| matches!(r, MasqueradeReason::KnownBinaryRelocated { .. })),
            "{name}: {:?}",
            id.masquerade
        );
        assert_eq!(recommend(&id).level, RuleLevel::None, "{name}");
    }

    // A trusted script signer claiming the PowerShell host's name.
    let fixture = contexts.get("fixture_roots");
    let script = fixture_set_file("script", "ps1-utf8bom-crlf.ps1");
    let mut id = identify_bytes(&script, Some("run.ps1"), Tiers::ALL, &fixture);
    assert_eq!(recommend(&id).level, RuleLevel::Publisher);
    if let Field::Computed(s) = &mut id.script {
        let meta = s.signed_metadata.get_or_insert_with(Default::default);
        meta.original_filename = Some("PowerShell.EXE".to_owned());
    }
    id.masquerade = masquerade::assess(
        &id,
        fixture.protected,
        fixture.code_trust,
        fixture.known_folders,
    );
    assert!(
        id.masquerade
            .reasons
            .iter()
            .any(|r| matches!(r, MasqueradeReason::ProtectedNameClaimed { .. })),
        "{:?}",
        id.masquerade
    );
    assert_eq!(recommend(&id).level, RuleLevel::None);

    // A trusted package claiming the protected "OS" vendor in its display
    // name, signed by the package fixture signer, which that vendor does
    // not expect (it expects a well-known OS root, which the fixture roots
    // do not hold, so it is unassessed rather than concluded).
    let msix = fixture_set_file("package", "app-signed.msix");
    let mut id = identify_bytes(&msix, Some("app.msix"), Tiers::ALL, &fixture);
    if let Field::Computed(p) = &mut id.package {
        p.display_name = Some("Palisade Test OS".to_owned());
    }
    id.masquerade = masquerade::assess(
        &id,
        fixture.protected,
        fixture.code_trust,
        fixture.known_folders,
    );
    assert!(
        id.masquerade.unassessed.contains(&"signer_impersonation"),
        "{:?}",
        id.masquerade
    );
    assert_eq!(recommend(&id).level, RuleLevel::None);
    // And a vendor expected by publisher name, which can be judged.
    if let Field::Computed(p) = &mut id.package {
        p.display_name = Some("Example Org Tools".to_owned());
    }
    id.masquerade = masquerade::assess(
        &id,
        fixture.protected,
        fixture.code_trust,
        fixture.known_folders,
    );
    assert!(
        id.masquerade
            .reasons
            .iter()
            .any(|r| matches!(r, MasqueradeReason::SignerImpersonation { .. })),
        "{:?}",
        id.masquerade
    );
    assert_eq!(recommend(&id).level, RuleLevel::None);
}

/// #55 wiring: a script, installer or package signature folds into the
/// signing state fail closed. A script changed after signing, a package
/// changed after signing, and an archive the strict reader refuses are
/// invalid; a script format that is not read stays unverified.
#[test]
fn non_pe_signatures_fold_fail_closed() {
    use palisade_fileid::identity::{EmbeddedState, RuleLevel, SigningStateKind, recommend};
    let contexts = Contexts::new();
    let fixture = contexts.get("fixture_roots");
    let state = |bytes: &[u8], name: &str| {
        let id = identify_bytes(bytes, Some(name), Tiers::ALL, &fixture);
        let s = id.signing_state.computed().unwrap().clone();
        (s, recommend(&id).level)
    };

    // One character of the script's text changed after signing.
    let mut script = fixture_set_file("script", "ps1-utf8bom-crlf.ps1");
    let at = script.windows(5).position(|w| w == b"Write").unwrap();
    script[at] = b'w';
    let (s, level) = state(&script, "run.ps1");
    assert_eq!(s.state, SigningStateKind::Invalid, "{s:?}");
    assert_eq!(s.embedded, EmbeddedState::Invalid);
    assert_eq!(level, RuleLevel::None);

    // A signed installer with a property value changed.
    let mut msi = fixture_set_file("installer", "product-sha256.msi");
    let at = msi
        .windows(21)
        .position(|w| w == b"Palisade Test Product")
        .unwrap();
    msi[at] ^= 0x20;
    let (s, level) = state(&msi, "product.msi");
    assert_eq!(s.state, SigningStateKind::Invalid, "{s:?}");
    assert_eq!(level, RuleLevel::None);

    // A package cut short: its archive has no central directory, so it is
    // not recognised as a package at all and no signature is read. Never
    // "unsigned", and never a signer rule.
    let msix = fixture_set_file("package", "app-signed.msix");
    let (s, level) = state(&msix[..msix.len() - 100], "app.msix");
    assert_eq!(s.state, SigningStateKind::Unverified, "{s:?}");
    assert!(!matches!(
        level,
        RuleLevel::Publisher | RuleLevel::PublisherProduct | RuleLevel::FilePublisher
    ));
    // A package whose central directory names its manifest differently
    // from its local record: whatever reads it, it is never trusted and
    // never unsigned.
    let doubled = {
        let mut b = msix.clone();
        let needle = b"AppxManifest.xml";
        let at = b.windows(needle.len()).rposition(|w| w == needle).unwrap();
        b[at] = b'B';
        b
    };
    let (s, level) = state(&doubled, "app.msix");
    assert_ne!(s.state, SigningStateKind::Trusted, "{s:?}");
    assert_ne!(s.state, SigningStateKind::Unsigned, "{s:?}");
    assert!(!matches!(
        level,
        RuleLevel::Publisher | RuleLevel::PublisherProduct | RuleLevel::FilePublisher
    ));

    // An encoded script is not read: unverified, never unsigned.
    let (s, _) = state(b"#@~^AAAAAA==^#~@", "run.vbe");
    assert_eq!(s.state, SigningStateKind::Unverified, "{s:?}");
    assert_eq!(s.embedded, EmbeddedState::NotChecked);
}

/// #55 wiring: the deep tier merges into an execution-time record of a
/// script, installer or package exactly as computing every tier at once,
/// and a validly signed script whose deep tier did not run gets no rule
/// (its signed metadata could claim a protected binary).
#[test]
fn deep_tier_records_merge_like_one_pass() {
    use palisade_fileid::identity::{RuleLevel, Tier, recommend};
    let contexts = Contexts::new();
    let ctx = contexts.get("fixture_roots");
    for (set, file, name) in [
        ("script", "ps1-utf8bom-crlf.ps1", "run.ps1"),
        ("installer", "product-sha256.msi", "product.msi"),
        ("package", "app-signed.msix", "app.msix"),
    ] {
        let bytes = fixture_set_file(set, file);
        let mut early = identify_bytes(&bytes, Some(name), Tiers::EXECUTION, &ctx);
        if set == "script" {
            assert!(
                early
                    .masquerade
                    .unassessed
                    .contains(&"known_binary_relocated"),
                "{:?}",
                early.masquerade
            );
            assert_eq!(recommend(&early).level, RuleLevel::None);
        }
        let late = identify_bytes(
            &bytes,
            Some(name),
            [Tier::Context, Tier::Deep].into_iter().collect(),
            &ctx,
        );
        assert!(early.merge(late, &ctx), "{name}");
        let all = identify_bytes(&bytes, Some(name), Tiers::ALL, &ctx);
        assert_eq!(early, all, "{name}");
        assert!(all.computed_tiers.contains(Tier::Deep), "{name}");
    }
}

/// #343 review B1: a signed installer with bytes appended after its last
/// sector (the CVE-2020-1464 pattern: an archive glued onto a vendor-signed
/// MSI) is not what its signer signed: invalid, with no rule, whatever it
/// is named. The same for a package: nothing may follow its end-of-archive
/// record.
#[test]
fn appended_data_never_keeps_a_signature() {
    use palisade_fileid::identity::{RuleLevel, SigningStateKind, recommend};
    let contexts = Contexts::new();
    let ctx = contexts.get("fixture_roots");

    let signed = fixture_set_file("installer", "product-sha256.msi");
    let clean = identify_bytes(&signed, Some("product.msi"), Tiers::ALL, &ctx);
    assert_eq!(
        clean.signing_state.computed().unwrap().state,
        SigningStateKind::Trusted
    );
    let mut appended = signed.clone();
    appended.extend_from_slice(&[0x41; 600]);
    for name in ["product.msi", "update.jar"] {
        let id = identify_bytes(&appended, Some(name), Tiers::ALL, &ctx);
        let s = id.signing_state.computed().unwrap();
        assert_eq!(s.state, SigningStateKind::Invalid, "{name}: {s:?}");
        assert!(s.signer.is_none());
        assert!(
            s.embedded_invalid_reason
                .as_deref()
                .is_some_and(|r| r.starts_with("trailing data is not signed")),
            "{name}: {s:?}"
        );
        assert_eq!(recommend(&id).level, RuleLevel::None, "{name}");
        let i = id.installer.computed().unwrap();
        assert_eq!(i.trailing_bytes, Some(600));
        assert!(!i.signature_valid);
    }
    // An unsigned installer with trailing data has no signature to lose.
    let mut unsigned = fixture_set_file("installer", "product.msi");
    unsigned.extend_from_slice(&[0x41; 600]);
    let id = identify_bytes(&unsigned, Some("product.msi"), Tiers::ALL, &ctx);
    assert_ne!(
        id.signing_state.computed().unwrap().state,
        SigningStateKind::Trusted
    );

    // A signed package with bytes after its end-of-archive record.
    let msix = fixture_set_file("package", "app-signed.msix");
    let mut appended = msix.clone();
    appended.extend_from_slice(b"PK\x03\x04appended");
    for name in ["app.msix", "update.jar"] {
        let id = identify_bytes(&appended, Some(name), Tiers::ALL, &ctx);
        let s = id.signing_state.computed().unwrap();
        assert!(
            !matches!(
                s.state,
                SigningStateKind::Trusted | SigningStateKind::Unsigned
            ),
            "{name}: {s:?}"
        );
        assert!(s.signer.is_none());
        assert!(!matches!(
            recommend(&id).level,
            RuleLevel::Publisher | RuleLevel::PublisherProduct | RuleLevel::FilePublisher
        ));
    }
}

/// #343 review (CodeRabbit): with the hash tier alone the file type is not
/// determined, so an installer's or script's normalised hash is
/// unavailable, not "not applicable". A PE image, known from its hashes,
/// has none.
#[test]
fn normalised_hashes_are_unavailable_until_the_type_is_known() {
    let contexts = Contexts::new();
    let ctx = contexts.get("fixture_roots");
    let hash_only = Tiers::only(palisade_fileid::identity::Tier::Hash);
    for (set, file, name) in [
        ("installer", "product-sha256.msi", "product.msi"),
        ("script", "ps1-utf8bom-crlf.ps1", "run.ps1"),
    ] {
        let id = identify_bytes(&fixture_set_file(set, file), Some(name), hash_only, &ctx);
        let h = id.hashes.computed().unwrap();
        assert!(
            matches!(h.msi_normalised_sha256, Field::Unavailable(_)),
            "{name}: {:?}",
            h.msi_normalised_sha256
        );
        assert!(
            matches!(h.script_normalised_sha256, Field::Unavailable(_)),
            "{name}: {:?}",
            h.script_normalised_sha256
        );
    }
    let id = identify_bytes(&signed_powershell(), Some("a.exe"), hash_only, &ctx);
    let h = id.hashes.computed().unwrap();
    assert_eq!(h.msi_normalised_sha256, Field::NotApplicable);
    assert_eq!(h.script_normalised_sha256, Field::NotApplicable);
}

/// #55 wiring, Windows only: every file system field of an OS binary is
/// read (never "not yet supported"), and the path's strength follows the
/// writability the access check reports, Medium only when it proved the
/// path safe. A path rule is never recommended.
#[cfg(all(windows, feature = "os-trust"))]
#[test]
fn fs_context_on_windows_is_consistent() {
    use palisade_fileid::identity::{IdentityStrength, RuleLevel, recommend};
    let contexts = Contexts::new();
    let ctx = contexts.get("default");
    let id = identify(
        Path::new(r"C:\Windows\System32\notepad.exe"),
        Tiers::ALL,
        &ctx,
    )
    .unwrap();
    for (name, computed) in [
        ("file_id", id.fs.file_id.is_computed()),
        ("volume", id.fs.volume.is_computed()),
        ("owner", id.fs.owner.is_computed()),
        ("streams", id.fs.streams.is_computed()),
        ("reparse", id.fs.reparse.is_computed()),
    ] {
        assert!(computed, "{name}: {:?}", id.fs);
    }
    let path = id
        .strengths
        .iter()
        .find(|s| s.attribute == "path")
        .map(|s| s.strength);
    let safe = id
        .fs
        .user_writable
        .computed()
        .is_some_and(|w| !w.path_user_writable && !w.change_perms_by_non_admin);
    assert_eq!(
        path,
        Some(if safe {
            IdentityStrength::Medium
        } else {
            IdentityStrength::Weak
        }),
        "{:?}",
        id.fs.user_writable
    );
    assert_ne!(recommend(&id).level, RuleLevel::Path);
    // A file in a folder every user can write is never Medium.
    let dir = common::ScratchDir::new("fsctx");
    let file = dir.0.join("extool.exe");
    std::fs::write(&file, b"MZ").unwrap();
    let id = identify(&file, Tiers::ALL, &ctx).unwrap();
    drop(dir);
    let path = id
        .strengths
        .iter()
        .find(|s| s.attribute == "path")
        .map(|s| s.strength);
    assert_eq!(
        path,
        Some(IdentityStrength::Weak),
        "{:?}",
        id.fs.user_writable
    );
}

/// #344 review: a named stream has no mark of the web of its own. Its
/// record says so (`not_applicable`) and records no `motw_unreadable`
/// error, while the host file keeps its own reading.
#[cfg(all(windows, feature = "os-trust"))]
#[test]
fn a_stream_has_no_mark_of_the_web_of_its_own() {
    let contexts = Contexts::new();
    let ctx = contexts.get("default");
    let dir = common::ScratchDir::new("stream-motw");
    let host = dir.0.join("host.txt");
    std::fs::write(&host, b"host").unwrap();
    let mut stream = host.as_os_str().to_owned();
    stream.push(":payload");
    std::fs::write(&stream, b"MZ payload").unwrap();
    let id = identify(Path::new(&stream), Tiers::ALL, &ctx).unwrap();
    assert_eq!(id.fs.motw, Field::NotApplicable);
    assert!(
        !id.errors.iter().any(|e| e.code == "motw_unreadable"),
        "{:?}",
        id.errors
    );
    let host_id = identify(&host, Tiers::ALL, &ctx).unwrap();
    assert_eq!(host_id.fs.motw, Field::Computed(None));
}

/// The rule facts the policy bridge reads (#318, #328): each chain
/// certificate's key hash, names, EKUs and key, the whole chain on the
/// trusted signer, the RFC 3161 and expiry facts per signature, and the
/// `LegalCopyright` string.
#[test]
fn rule_facts_for_the_policy_bridge() {
    use palisade_fileid::authenticode::{CertSummary, DigestAlgorithm, KeyAlgorithm};
    let contexts = Contexts::new();
    let id = identify_bytes(
        &generated("signed-tool.exe"),
        Some("extool.exe"),
        Tiers::ALL,
        &contexts.get("trusted"),
    );
    let signer = id.trusted_signer().unwrap();
    let sig = &id.signatures.computed().unwrap()[0];
    let chain = sig.chain.as_ref().unwrap();
    // The full chain, leaf first, ending at the root the record names.
    assert_eq!(chain.certs.len(), 2);
    assert!(chain.complete);
    assert_eq!(chain.certs.first(), signer.leaf.as_ref());
    assert_eq!(chain.certs.last(), signer.root.as_ref());
    let leaf = signer.leaf.as_ref().unwrap();
    let root = CertSummary::from_der(&corpus_ca()).unwrap();
    assert_eq!(signer.root.as_ref().unwrap().spki_sha256, root.spki_sha256);
    assert_eq!(leaf.spki_sha256.len(), 64);
    assert_ne!(leaf.spki_sha256, root.spki_sha256);
    assert_eq!(leaf.subject_cn.as_deref(), Some("Palisade Corpus Vendor"));
    assert_eq!(leaf.subject_o.as_deref(), Some("Palisade Tests"));
    assert_eq!(leaf.issuer_cn.as_deref(), Some("Palisade Corpus Root"));
    assert_eq!(
        leaf.subject_rfc4514.as_deref(),
        Some("CN=Palisade Corpus Vendor,O=Palisade Tests")
    );
    assert_eq!(
        leaf.extended_key_usage.as_deref(),
        Some(&["1.3.6.1.5.5.7.3.3".to_owned()][..])
    );
    assert_eq!(leaf.key_alg, KeyAlgorithm::Rsa);
    assert!(leaf.key_bits.is_some_and(|b| b >= 2048));
    assert_eq!(leaf.signature_digest, Some(DigestAlgorithm::Sha256));
    // The embedded signature: no timestamp, in date.
    assert_eq!(sig.rfc3161_timestamp, Some(false));
    assert_eq!(sig.expired_now, Some(false));
    // Judged after the leaf expired, the same signature is expired now.
    let mut late = contexts.get("trusted");
    late.now = leaf.not_after + 1;
    let late_id = identify_bytes(
        &generated("signed-tool.exe"),
        Some("extool.exe"),
        Tiers::ALL,
        &late,
    );
    let late_sig = &late_id.signatures.computed().unwrap()[0];
    assert_eq!(late_sig.expired_now, Some(true));
    // A catalog match carries its signer's chain too.
    let cat = identify_bytes(
        &corpus_files()["plain"],
        Some("plain.exe"),
        Tiers::ALL,
        &contexts.get("trusted"),
    );
    let cat_signer = cat.trusted_signer().unwrap();
    assert_eq!(
        cat_signer.source,
        palisade_fileid::identity::TrustSource::Catalog
    );
    let m = &cat.catalog_matches.computed().unwrap()[0];
    assert!(m.signer_chain_complete);
    assert_eq!(m.signer_chain.first(), cat_signer.leaf.as_ref());
    assert_eq!(m.signer_chain.last(), cat_signer.root.as_ref());
    assert_eq!(m.signer_chain.first(), m.signer.as_ref());
    // The version resource's copyright, read like the other strings; the
    // corpus tool has none.
    let spec = common::VersionSpec {
        fixed: None,
        tables: vec![("040904B0", common::all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    };
    let with = identify_bytes(
        &common::with_version(&spec).build(),
        Some("extool.exe"),
        Tiers::ALL,
        &contexts.get("default"),
    );
    assert_eq!(
        with.version().unwrap().legal_copyright.as_deref(),
        Some("(c) Example Org")
    );
    let tool = identify_bytes(
        &corpus_files()["tool"],
        Some("extool.exe"),
        Tiers::ALL,
        &contexts.get("default"),
    );
    assert_eq!(tool.version().unwrap().legal_copyright, None);
}
