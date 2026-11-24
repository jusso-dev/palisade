//! Fuzzes X.509 certificate parsing and chain building (#49). The input is
//! split on a marker into up to 64 certificates (as many as a signature
//! keeps); the first is the
//! signer, and the last is also configured as a trust anchor when it
//! parses. No input may panic, and every report must respect the
//! documented limits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::{
    CertSummary, MAX_CHAIN_ISSUES, MAX_CHAIN_LENGTH, MAX_CHAIN_PATHS, TrustConfig, build_chain,
};

/// Separates certificates in the input.
const MARKER: &[u8] = b"\xff\xfeCERT";

fn split(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = data;
    while out.len() < 64 {
        match rest.windows(MARKER.len()).position(|w| w == MARKER) {
            Some(at) => {
                out.push(rest[..at].to_vec());
                rest = &rest[at + MARKER.len()..];
            }
            None => {
                out.push(rest.to_vec());
                break;
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let certs = split(data);
    for der in &certs {
        if let Ok(cert) = CertSummary::from_der(der) {
            assert_eq!(cert.der, *der);
            assert_eq!(cert.tbs_hash_sha256.len(), 64);
            let _ = cert.pem();
        }
    }
    let mut config = TrustConfig::new();
    if let Some(last) = certs.last() {
        let _ = config.add_anchor("fuzz", last);
    }
    let Ok(report) = build_chain(&certs, 0, &config) else {
        return;
    };
    assert!(report.as_provided.certs.len() <= MAX_CHAIN_LENGTH);
    assert!(report.full_chain.certs.len() <= MAX_CHAIN_LENGTH);
    assert!(report.alternatives.len() < MAX_CHAIN_PATHS);
    assert!(report.issues.len() <= MAX_CHAIN_ISSUES + 4);
    assert_eq!(report.full_chain.certs.first(), Some(&report.leaf));
    for path in std::iter::once(&report.full_chain).chain(&report.alternatives) {
        assert!(path.certs.iter().all(|i| *i < report.certificates.len()));
        if path.anchored {
            assert!(report.certificates[*path.certs.last().unwrap()].anchor.is_some());
        }
    }
    assert_eq!(report.anchored_to.is_some(), report.full_chain.anchored);
});
