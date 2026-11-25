//! Fuzzes Authenticode signature parsing and verification (#48): the input
//! is a certificate table, attached to the fixture image the test
//! signatures were made over (`PeBuilder::default()` from `tests/common`).
//! No input may panic, and every report must respect the documented limits
//! and never call a signature valid unless every check passed. The same
//! image, and the table as a bare PKCS#7 blob, also go through certificate
//! extraction (#49).
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::{
    CertSelection, MAX_CERTIFICATE_ENTRIES, MAX_CERTIFICATES, MAX_EXTRACTED_SIGNATURES,
    MAX_NESTING_DEPTH, MAX_SIGNATURES, MAX_TIMESTAMPS, MAX_WARNINGS, SignatureCheck,
    SignatureStatus, SigningState, VerifyOptions, extract_certificates, verify_pe,
};

// The tests' fixture builder, so the image is byte for byte the one the
// fixture signatures (and so the seed corpus) were made over, and valid
// signatures stay reachable.
#[path = "../../tests/common/mod.rs"]
mod common;

/// `PeBuilder::default()` with no certificate table.
fn base_image() -> Vec<u8> {
    common::PeBuilder::default().build()
}

fuzz_target!(|table: &[u8]| {
    let mut image = base_image();
    let at = image.len() as u32;
    image.extend_from_slice(table);
    let dir = common::PeBuilder::default().data_directory_offset(4);
    image[dir..dir + 4].copy_from_slice(&at.to_le_bytes());
    image[dir + 4..dir + 8].copy_from_slice(&(table.len() as u32).to_le_bytes());

    for input in [image.as_slice(), table] {
        for selection in [CertSelection::All, CertSelection::Leaf, CertSelection::Root] {
            if let Ok(out) = extract_certificates(input, selection) {
                assert!(out.signatures <= MAX_EXTRACTED_SIGNATURES);
                assert!(
                    out.certificates
                        .iter()
                        .all(|c| c.signature < out.signatures)
                );
                match selection {
                    CertSelection::Leaf => assert!(out.certificates.iter().all(|c| c.is_signer)),
                    CertSelection::Root => assert!(out.certificates.iter().all(|c| c.is_root)),
                    _ => {}
                }
                // Each certificate once per signature.
                let mut seen = std::collections::HashSet::new();
                assert!(
                    out.certificates
                        .iter()
                        .all(|c| seen.insert((c.signature, c.cert.sha256_thumbprint.clone())))
                );
            }
        }
    }

    for tolerate in [false, true] {
        let options = VerifyOptions {
            tolerate_digest_mismatch: tolerate,
        };
        let Ok(report) = verify_pe(&image, &options) else {
            return;
        };
        assert!(report.entries.len() <= MAX_CERTIFICATE_ENTRIES);
        assert!(report.signatures.len() <= MAX_SIGNATURES);
        for (i, sig) in report.signatures.iter().enumerate() {
            assert_eq!((sig.index, sig.total), (i, report.signatures.len()));
            assert!(sig.depth <= MAX_NESTING_DEPTH);
            assert!(sig.parent.is_none_or(|p| p < i));
            assert!(sig.certs_in_blob.len() <= MAX_CERTIFICATES);
            assert!(sig.timestamp_tokens.len() <= MAX_TIMESTAMPS);
            assert!(sig.warnings.len() <= MAX_WARNINGS + 1);
            if sig.status.is_valid() {
                assert_eq!(sig.signature_valid, SignatureCheck::Valid);
                assert_eq!(sig.digest_match, Some(true));
            }
            if sig.signer.is_some() {
                assert!(
                    sig.status.is_valid()
                        || (tolerate && sig.status == SignatureStatus::DigestMismatch)
                );
                assert!(
                    sig.signer
                        .as_ref()
                        .is_some_and(|s| s.signer_cert < sig.certs_in_blob.len())
                );
            }
            assert_eq!(
                sig.untrusted_signer_attrs,
                !sig.status.is_valid() && sig.signer.is_some()
            );
        }
        match report.primary {
            Some(p) => {
                assert!(report.signatures[p].status.is_valid());
                assert_eq!(report.signing_state, SigningState::Valid);
            }
            None => assert_ne!(report.signing_state, SigningState::Valid),
        }
    }
});
