//! Fuzzes app packages (#53): the strict ZIP reader, the manifest and
//! bundle manifest, the block map, the package digest and the package
//! signature. No input may panic, and nothing that is not a cleanly parsed
//! package whose block map, digest and publisher all check may verify.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::SignatureKind;
use palisade_fileid::package::manifest::{parse_bundle_manifest, parse_package_manifest};
use palisade_fileid::package::{blockmap, parse_package, publisher_id};

fuzz_target!(|data: &[u8]| {
    // The XML formats on their own.
    if let Ok(m) = parse_package_manifest(data) {
        assert_eq!(publisher_id(&m.identity.publisher).len(), 13);
    }
    let _ = parse_bundle_manifest(data);
    let _ = blockmap::parse(data);

    let Ok(id) = parse_package(data) else {
        return;
    };
    assert_eq!(id.publisher_id, publisher_id(&id.publisher_dn));
    assert!(id.pfn.ends_with(&id.publisher_id));
    if let Some(sig) = &id.signature {
        if sig.issue.is_some() {
            assert!(sig.report.primary.is_none());
        }
        for s in &sig.report.signatures {
            if s.depth == 0 {
                assert_eq!(s.kind, SignatureKind::Package);
            }
            if s.status.is_valid() {
                assert_eq!(s.digest_match, Some(true));
            }
        }
        assert_eq!(
            id.signature_valid(),
            sig.issue.is_none() && sig.report.primary.is_some()
        );
    }
});
