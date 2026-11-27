//! Meta-tests of the fixture corpus (#25): every fixture is parsed with this
//! crate and checked for the property it was built to have. The corpus
//! itself is built in `tests/corpus/` (see its module docs); `cargo xtask
//! fixtures` writes it to disk with `write_fixture_corpus` below.

// Test code: fixture sizes are small, so narrowing casts cannot truncate,
// and helpers may unwrap or expect, since a failure should fail loudly.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

mod common;
mod corpus;

use corpus::{Kind, Pki, by_name, corpus};
use palisade_fileid::authenticode::{
    BasicConstraints, CertSummary, Crl, DigestAlgorithm, PageHashCheck, RevocationSet,
    SignatureStatus, SigningState, TrustConfig, UntrustedReason, VerifyOptions, build_chain,
    evaluate_trust, verify_pe, verify_signature_page_hashes,
};
use palisade_fileid::catalog::parse_catalog;
use palisade_fileid::filetype::{FileKind, classify_bytes};
use palisade_fileid::pe::{self, Machine, PeFormat, version::VersionField};

fn trust(pki: &Pki) -> TrustConfig {
    let mut config = TrustConfig::new();
    config.add_anchor("test-root", &pki.root.der).unwrap();
    config
}

#[test]
fn the_corpus_has_unique_names_and_every_kind() {
    let c = corpus();
    let names = by_name(&c);
    assert_eq!(names.len(), c.len(), "fixture names must be unique");
    for kind in [
        Kind::Pe,
        Kind::Signed,
        Kind::Tampered,
        Kind::TruncatedSignature,
        Kind::Malformed,
        Kind::Script,
        Kind::Pki,
        Kind::Catalog,
    ] {
        assert!(c.iter().any(|f| f.kind == kind), "no {kind:?} fixture");
    }
}

#[test]
fn the_corpus_is_deterministic() {
    let (a, b) = (corpus(), corpus());
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x.name, y.name);
        if x.deterministic {
            assert_eq!(x.bytes, y.bytes, "{} differs between runs", x.name);
        }
    }
}

#[test]
fn pe_fixtures_have_their_machine_format_and_version_info() {
    let c = corpus();
    for f in c.iter().filter(|f| f.kind == Kind::Pe) {
        let info = pe::parse(&f.bytes).unwrap_or_else(|e| panic!("{}: {e:?}", f.name));
        let (machine, format) = match f.name {
            n if n.contains("x64") => (Machine::Amd64, PeFormat::Pe32Plus),
            n if n.contains("arm64") => (Machine::Arm64, PeFormat::Pe32Plus),
            _ => (Machine::I386, PeFormat::Pe32),
        };
        assert_eq!(info.coff.machine, machine, "{}", f.name);
        assert_eq!(info.optional.format, format, "{}", f.name);
        assert_eq!(
            info.coff.characteristics.is_dll(),
            f.name.ends_with(".dll"),
            "{}",
            f.name
        );
        let v = info.version_info.as_ref().unwrap();
        assert_eq!(v.get(VersionField::OriginalFileName), Some(f.name));
        assert_eq!(v.get(VersionField::ProductName), Some("Palisade Fixtures"));
        assert_eq!(v.get(VersionField::CompanyName), Some("Palisade Tests"));
        assert_eq!(v.get(VersionField::FileVersion), Some("1.2.3.4"));
        assert_eq!(
            classify_bytes(&f.bytes, None).content_kind,
            FileKind::Pe,
            "{}",
            f.name
        );
    }
}

#[test]
fn signed_fixtures_verify_and_chain_to_the_test_root() {
    let c = corpus();
    let pki = Pki::new();
    let config = trust(&pki);
    for name in [
        "signed.exe",
        "signed-dual.exe",
        "signed-page-hashes.exe",
        "signed-ecdsa-p256.exe",
    ] {
        let f = by_name(&c)[name];
        let report = verify_pe(&f.bytes, &VerifyOptions::default()).unwrap();
        assert_eq!(
            report.signing_state,
            SigningState::Valid,
            "{name}: {report:#?}"
        );
        for sig in &report.signatures {
            assert_eq!(sig.status, SignatureStatus::Valid, "{name}");
        }
        let info = pe::parse(&f.bytes).unwrap();
        let t = evaluate_trust(&report, &config, info.version_info.as_ref());
        let primary = t.primary_signer().unwrap();
        assert!(primary.trusted, "{name}: {:?}", primary.untrusted);
        let chain = primary.chain.as_ref().unwrap();
        assert!(chain.chain_complete, "{name}");
    }
    // Dual signed: the nested signature is there and valid too.
    let dual = verify_pe(
        &by_name(&c)["signed-dual.exe"].bytes,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert_eq!(dual.signatures.len(), 2);
    assert_eq!(dual.signatures[1].depth, 1);
}

#[test]
fn the_catalog_is_signed_and_lists_its_unsigned_member() {
    let c = corpus();
    let cat = parse_catalog(&by_name(&c)["catalog.cat"].bytes).unwrap();
    assert!(cat.signature_valid(), "{:#?}", cat.signatures);
    let member = &by_name(&c)["catalog-member.exe"].bytes;
    let digest = corpus::sign::authenticode_sha256(member);
    assert_eq!(
        cat.members_with_digest(DigestAlgorithm::Sha256, &digest)
            .count(),
        1
    );
    // The member has no embedded signature: it is catalog-signed only.
    let report = verify_pe(member, &VerifyOptions::default()).unwrap();
    assert_eq!(report.signing_state, SigningState::Unsigned);
    // The catalog is signed by the test PKI's publisher.
    let sig = cat.signature().unwrap();
    let t = evaluate_trust(&cat.signatures, &trust(&Pki::new()), None);
    assert!(
        t.signers[sig.index].trusted,
        "{:?}",
        t.signers[sig.index].untrusted
    );
}

#[test]
fn the_page_hash_fixture_carries_a_table_that_matches() {
    let c = corpus();
    let f = by_name(&c)["signed-page-hashes.exe"];
    let report = verify_pe(&f.bytes, &VerifyOptions::default()).unwrap();
    let sig = &report.signatures[0];
    assert!(sig.page_hashes.is_some());
    let info = pe::parse(&f.bytes).unwrap();
    let check = verify_signature_page_hashes(&f.bytes, &info, sig).unwrap();
    assert_eq!(check, PageHashCheck::Match);
}

#[test]
fn tampered_and_truncated_fixtures_fail_as_built() {
    let c = corpus();
    let tampered = verify_pe(
        &by_name(&c)["signed-tampered.exe"].bytes,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert_eq!(
        tampered.signatures[0].status,
        SignatureStatus::DigestMismatch
    );
    assert_ne!(tampered.signing_state, SigningState::Valid);
    let truncated = by_name(&c)["signed-truncated.exe"];
    let report = verify_pe(&truncated.bytes, &VerifyOptions::default());
    if let Ok(r) = report {
        assert_ne!(r.signing_state, SigningState::Valid, "{r:#?}");
    }
}

#[test]
fn bad_certificates_are_refused_for_the_reason_they_were_made() {
    let c = corpus();
    let pki = Pki::new();
    let config = trust(&pki);
    let primary = |name: &str| {
        let f = by_name(&c)[name];
        let report = verify_pe(&f.bytes, &VerifyOptions::default()).unwrap();
        // The signatures themselves verify; only trust or validity fails.
        assert_eq!(
            report.signatures[0].status,
            SignatureStatus::Valid,
            "{name}"
        );
        let t = evaluate_trust(&report, &config, None);
        (report, t.signers[0].clone())
    };
    let (_, wrong_eku) = primary("signed-wrong-eku.exe");
    assert!(
        wrong_eku
            .untrusted
            .contains(&UntrustedReason::CodeSigningNotPermitted),
        "{:?}",
        wrong_eku.untrusted
    );
    let (_, self_signed) = primary("signed-self-signed.exe");
    assert!(
        self_signed
            .untrusted
            .contains(&UntrustedReason::NoTrustAnchor),
        "{:?}",
        self_signed.untrusted
    );
    // Expired and revoked chains are trusted for identity; time and
    // revocation are checked by the validity layer.
    let (_, expired) = primary("signed-expired.exe");
    let leaf = &expired.chain.as_ref().unwrap().certificates[0].cert;
    assert!(leaf.not_after < corpus_signing_time(), "{leaf:?}");
    let crl = Crl::from_der(&pki.crl).unwrap();
    let mut set = RevocationSet::new();
    set.add_crl(crl.clone());
    let (_, revoked) = primary("signed-revoked.exe");
    let revoked_leaf = &revoked.chain.as_ref().unwrap().certificates[0].cert;
    assert_eq!(
        crl.entries_for(&revoked_leaf.serial).count(),
        1,
        "the CRL lists the revoked leaf"
    );
    assert_eq!(crl.entries_for(&leaf.serial).count(), 0);
}

fn corpus_signing_time() -> i64 {
    corpus::sign::SIGNING_TIME
}

#[test]
fn the_test_pki_is_a_root_an_intermediate_and_rsa_3072_leaves() {
    let pki = Pki::new();
    let root = CertSummary::from_der(&pki.root.der).unwrap();
    let inter = CertSummary::from_der(&pki.inter.der).unwrap();
    let leaf = CertSummary::from_der(&pki.leaf.der).unwrap();
    assert!(matches!(
        root.basic_constraints,
        Some(BasicConstraints { ca: true, .. })
    ));
    assert!(matches!(
        inter.basic_constraints,
        Some(BasicConstraints { ca: true, .. })
    ));
    assert_eq!(leaf.key_bits, Some(3072));
    assert_eq!(pki.leaf_key.bits(), 3072);
    let chain = build_chain(
        &[pki.leaf.der.clone(), pki.inter.der.clone()],
        0,
        &trust(&pki),
    )
    .unwrap();
    assert!(chain.full_chain.anchored, "{chain:?}");
}

#[test]
fn malformed_fixtures_never_panic_and_never_parse_as_valid_signed_pes() {
    for f in corpus().iter().filter(|f| f.kind == Kind::Malformed) {
        let _ = pe::parse(&f.bytes);
        let _ = classify_bytes(&f.bytes, None);
        if let Ok(report) = verify_pe(&f.bytes, &VerifyOptions::default()) {
            assert_eq!(report.signing_state, SigningState::Unsigned, "{}", f.name);
        }
    }
}

#[test]
fn script_fixtures_are_classified_by_name_and_hold_only_the_marker() {
    for f in corpus().iter().filter(|f| f.kind == Kind::Script) {
        let text = std::str::from_utf8(&f.bytes).unwrap();
        assert!(text.contains("PALISADE-FIXTURE"), "{}", f.name);
        let name = std::ffi::OsStr::new(f.name);
        let kind = classify_bytes(&f.bytes, Some(name)).content_kind;
        assert!(
            matches!(kind, FileKind::Script(_) | FileKind::Hta),
            "{}: {kind:?}",
            f.name
        );
    }
}

/// Writes the corpus for `cargo xtask fixtures`:
///
/// ```sh
/// PALISADE_FIXTURE_DIR=target/fixtures \
///     cargo test -p palisade-fileid --test fixture_corpus -- --ignored --exact write_fixture_corpus
/// ```
///
/// Each fixture goes to `<dir>/<name>`, and `<dir>/MANIFEST` lists each
/// one as `<sha256> <name>` (or `<kind> <name>` when it is not the same on
/// every run).
#[test]
#[ignore = "writes files; run by cargo xtask fixtures"]
fn write_fixture_corpus() {
    use sha2::{Digest as _, Sha256};
    let dir = std::env::var_os("PALISADE_FIXTURE_DIR").expect("set PALISADE_FIXTURE_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let mut manifest = String::new();
    for f in corpus() {
        std::fs::write(dir.join(f.name), &f.bytes).unwrap();
        let hash = if f.deterministic {
            Sha256::digest(&f.bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        } else {
            "nondeterministic".to_owned()
        };
        manifest.push_str(&format!("{hash} {}\n", f.name));
    }
    std::fs::write(dir.join("MANIFEST"), manifest).unwrap();
}

/// Writes fuzz seeds from the corpus (#25: "seed corpora come from the
/// fixture generator"): every PE fixture for the PE targets, each signed
/// fixture's PKCS#7 signature for the PKCS#7 target, and the test PKI's
/// certificates for the X.509 target. Which target reads which seeds is in
/// `xtask/src/fuzz.rs`; each writer runs with `PALISADE_FUZZ_SEED_DIR` set
/// to the target's corpus directory, so it writes every kind and lets the
/// fuzzer keep what is useful.
#[test]
#[ignore = "writes files; run by cargo xtask fuzz"]
fn write_corpus_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for f in corpus() {
        match f.kind {
            Kind::Pe
            | Kind::Signed
            | Kind::Tampered
            | Kind::TruncatedSignature
            | Kind::Malformed => {
                std::fs::write(dir.join(format!("corpus-{}", f.name)), &f.bytes).unwrap();
                if let Ok(info) = pe::parse(&f.bytes)
                    && let Some(range) = info.certificate_table
                {
                    let start = (range.offset as usize).min(f.bytes.len());
                    let end = (range.offset.saturating_add(range.size) as usize).min(f.bytes.len());
                    let table = &f.bytes[start..end];
                    // The PKCS#7 blob after the 8-byte WIN_CERTIFICATE header.
                    if table.len() > 8 {
                        let len = u32::from_le_bytes(table[..4].try_into().unwrap()) as usize;
                        let blob = &table[8..len.clamp(8, table.len())];
                        std::fs::write(dir.join(format!("corpus-{}.p7", f.name)), blob).unwrap();
                    }
                }
            }
            Kind::Pki => std::fs::write(dir.join(format!("corpus-{}", f.name)), &f.bytes).unwrap(),
            Kind::Script | Kind::Catalog => {}
        }
    }
}
