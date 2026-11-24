//! Fuzzes Authenticode signature parsing and verification (#48): the input
//! is a certificate table, attached to a small fixed PE image built here.
//! No input may panic, and every report must respect the documented limits
//! and never call a signature valid unless every check passed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::{
    MAX_CERTIFICATE_ENTRIES, MAX_CERTIFICATES, MAX_NESTING_DEPTH, MAX_SIGNATURES, MAX_TIMESTAMPS,
    MAX_WARNINGS, SignatureCheck, SignatureStatus, SigningState, VerifyOptions, verify_pe,
};

/// A minimal PE32+ image with one 0x200-byte section and no certificate
/// table: the same layout as `PeBuilder::default()` in the tests.
fn base_image() -> Vec<u8> {
    let mut out = vec![0_u8; 0x400];
    let put16 = |b: &mut [u8], at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    out[..2].copy_from_slice(b"MZ");
    put32(&mut out, 0x3c, 0x40);
    out[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    put16(&mut out, coff, 0x8664);
    put16(&mut out, coff + 2, 1);
    put16(&mut out, coff + 16, 240);
    put16(&mut out, coff + 18, 0x22);
    let o = coff + 20;
    put16(&mut out, o, 0x20b);
    put32(&mut out, o + 16, 0x1000);
    put32(&mut out, o + 20, 0x1000);
    out[o + 24..o + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    put32(&mut out, o + 32, 0x1000);
    put32(&mut out, o + 36, 0x200);
    put16(&mut out, o + 40, 6);
    put16(&mut out, o + 48, 6);
    put32(&mut out, o + 56, 0x2000);
    put32(&mut out, o + 60, 0x400);
    put16(&mut out, o + 68, 2);
    put32(&mut out, o + 108, 16);
    let s = o + 240;
    out[s..s + 8].copy_from_slice(b".text\0\0\0");
    put32(&mut out, s + 8, 0x100);
    put32(&mut out, s + 12, 0x1000);
    put32(&mut out, s + 16, 0x200);
    put32(&mut out, s + 20, 0x400);
    put32(&mut out, s + 36, 0x6000_0020);
    out.extend((0..0x200).map(|i| i as u8));
    out
}

fuzz_target!(|table: &[u8]| {
    let mut image = base_image();
    let at = image.len() as u32;
    image.extend_from_slice(table);
    let dir = 0x44 + 20 + 112 + 4 * 8;
    image[dir..dir + 4].copy_from_slice(&at.to_le_bytes());
    image[dir + 4..dir + 8].copy_from_slice(&(table.len() as u32).to_le_bytes());

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
