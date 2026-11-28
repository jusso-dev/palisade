//! Fuzzes the policy bundle readers (#43): the header-only decoder that
//! the signature envelope runs on untrusted bytes, and the strict bundle
//! decoder. No input may panic or exhaust memory. A bundle that decodes
//! must agree with its own header and encode back to bytes that decode to
//! the same bundle; validating it must not panic either, and neither may
//! the one-step loader (`bundle::load`), which an agent runs on the bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_policy::bundle::{BundleLimits, PolicyBundle, decode_header, load};

fuzz_target!(|data: &[u8]| {
    let limits = BundleLimits::DEFAULT;
    let header = decode_header(data, &limits);
    let loaded = load(data, &limits, None);
    let Ok(bundle) = PolicyBundle::decode(data, &limits) else {
        assert!(loaded.is_err());
        return;
    };
    // The loader accepts exactly the bundles that decode and validate.
    assert_eq!(loaded.is_ok(), bundle.validate().is_ok());
    assert_eq!(header.as_ref().ok(), Some(&bundle.header));
    let bytes = bundle.to_bytes().unwrap();
    assert!(bytes.len() <= data.len());
    let again = PolicyBundle::decode(&bytes, &limits).unwrap();
    assert_eq!(again, bundle);
    assert_eq!(again.to_bytes().unwrap(), bytes);
    let _ = bundle.decision_hash();
});
