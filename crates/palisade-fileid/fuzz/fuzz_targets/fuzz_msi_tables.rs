//! Fuzzes Windows Installer packages (#53): the compound-file reader, the
//! string pool and tables, the summary information, the content and
//! normalised hashes and the package signature check. No input may panic,
//! and nothing that is not a cleanly parsed, correctly hashed package may
//! verify.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::SignatureKind;
use palisade_fileid::installer::{MAX_INVENTORY_ROWS, cfb::CompoundFile, content_digests, parse_installer};

fuzz_target!(|data: &[u8]| {
    let Ok(id) = parse_installer(data) else {
        return;
    };
    assert!(id.embedded.binaries.len() <= MAX_INVENTORY_ROWS);
    assert!(id.embedded.custom_actions.len() <= MAX_INVENTORY_ROWS);
    assert!(id.embedded.cabinets.len() <= MAX_INVENTORY_ROWS);
    if let Some(report) = &id.signature {
        assert_eq!(report.primary.is_some(), id.signature_valid());
        for sig in &report.signatures {
            if sig.depth == 0 {
                assert_eq!(sig.kind, SignatureKind::Msi);
            }
            if sig.status.is_valid() {
                assert_eq!(sig.digest_match, Some(true));
            }
        }
    }
    // Parsing is deterministic, and the content hash agrees with itself.
    let again = parse_installer(data).unwrap();
    assert_eq!(again.normalised_sha256, id.normalised_sha256);
    let cf = CompoundFile::parse(data).unwrap();
    let digests = content_digests(&cf, &cf.root);
    assert!(digests.digests.iter().any(|d| *d == id.content_sha256));
});
