//! Fuzzes timestamp and CRL parsing and verification (#50). The first
//! byte picks the target:
//!
//! - 0: the rest is an RFC 3161 token, attached to the `leaf-rfc3161`
//!   fixture signature in place of its own token, and verified against the
//!   fixture TSA anchor;
//! - 1: the same for a legacy countersignature, on `leaf-legacy`;
//! - 2: the rest is a CRL, parsed, then judged against the fixture chain;
//! - 3: the rest is an OCSP response, parsed, then judged against the OCSP
//!   fixture chain.
//!
//! No input may panic, a valid timestamp must keep every invariant the
//! module documents, a CRL must respect its limits, and an OCSP response
//! may only give answers for a certificate its signer is authorised for.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::{
    CertSummary, Crl, MAX_CRL_ENTRIES, MAX_OCSP_RESPONSES_PER_RESPONSE, MAX_TIMESTAMP_WARNINGS,
    OcspResponse, RevocationSet, SignatureInfo, TimestampStatus, TrustConfig, VerifyOptions,
    verify_pe, verify_timestamps,
};

#[path = "../../tests/common/mod.rs"]
mod common;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/timestamp");

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

fn signature(name: &str) -> SignatureInfo {
    let blob = read(name);
    let mut table = Vec::new();
    table.extend_from_slice(&(blob.len() as u32 + 8).to_le_bytes());
    table.extend_from_slice(&0x0200_u16.to_le_bytes());
    table.extend_from_slice(&2_u16.to_le_bytes());
    table.extend_from_slice(&blob);
    while table.len() % 8 != 0 {
        table.push(0);
    }
    let image = common::PeBuilder {
        certificate: Some(table),
        ..common::PeBuilder::default()
    }
    .build();
    verify_pe(&image, &VerifyOptions::default())
        .unwrap()
        .signatures
        .remove(0)
}

struct Fixtures {
    rfc3161: SignatureInfo,
    legacy: SignatureInfo,
    tsa: TrustConfig,
    chain: Vec<CertSummary>,
    ocsp_chain: Vec<CertSummary>,
}

fn fixtures() -> &'static Fixtures {
    static F: OnceLock<Fixtures> = OnceLock::new();
    F.get_or_init(|| {
        let mut tsa = TrustConfig::new();
        tsa.add_anchor("tsa", &read("tsa-root.der")).unwrap();
        Fixtures {
            rfc3161: signature("leaf-rfc3161.p7"),
            legacy: signature("leaf-legacy.p7"),
            tsa,
            chain: vec![
                CertSummary::from_der(&read("leaf.der")).unwrap(),
                CertSummary::from_der(&read("root.der")).unwrap(),
            ],
            ocsp_chain: vec![
                CertSummary::from_der(&read("../ocsp/leaf.der")).unwrap(),
                CertSummary::from_der(&read("../ocsp/root.der")).unwrap(),
            ],
        }
    })
}

fn timestamp(sig: &SignatureInfo, der: &[u8], tsa: &TrustConfig) {
    let mut sig = sig.clone();
    sig.timestamp_tokens[0].der = der.to_vec();
    for ts in verify_timestamps(&sig, tsa) {
        assert_eq!(ts.valid, ts.status == TimestampStatus::Valid);
        assert!(ts.warnings.len() <= MAX_TIMESTAMP_WARNINGS + 1);
        if ts.valid {
            assert!(ts.time.is_some() && ts.tsa_cert.is_some());
            let chain = ts.tsa_chain.as_ref().unwrap();
            assert!(chain.full_chain.anchored);
            let (earliest, latest) = (ts.earliest().unwrap(), ts.latest().unwrap());
            assert!(earliest <= latest);
            for cert in chain.full_chain_certs() {
                assert!(cert.not_before <= earliest && latest <= cert.not_after);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let f = fixtures();
    match selector % 4 {
        0 => timestamp(&f.rfc3161, rest, &f.tsa),
        1 => timestamp(&f.legacy, rest, &f.tsa),
        3 => {
            let Ok(response) = OcspResponse::from_der(rest) else {
                return;
            };
            assert!(response.responses.len() <= MAX_OCSP_RESPONSES_PER_RESPONSE);
            let (leaf, root) = (&f.ocsp_chain[0], &f.ocsp_chain[1]);
            let answers = response.answers_for(leaf, root);
            if !answers.is_empty() {
                assert!(response.verified_by(root));
                assert!(answers.iter().all(|a| a.names(leaf, root)));
            }
            let mut set = RevocationSet::new();
            set.add_ocsp(response);
            let chain: Vec<&CertSummary> = f.ocsp_chain.iter().collect();
            for now in [0, 1_700_000_000, i64::MAX] {
                let _ = set.state_of(&chain, 0, now);
                let _ = set.state_of(&chain, 1, now);
            }
        }
        _ => {
            let Ok(crl) = Crl::from_der(rest) else {
                return;
            };
            assert!(crl.entries().len() <= MAX_CRL_ENTRIES);
            let mut set = RevocationSet::new();
            set.add_crl(crl);
            let chain: Vec<&CertSummary> = f.chain.iter().collect();
            for now in [0, 1_700_000_000, i64::MAX] {
                let _ = set.state_of(&chain, 0, now);
                let _ = set.state_of(&chain, 1, now);
            }
        }
    }
});
