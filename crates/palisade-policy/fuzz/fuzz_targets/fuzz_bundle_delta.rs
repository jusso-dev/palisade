//! Fuzzes bundle deltas (#43, #325): the strict delta reader and `apply`.
//! An agent reads a delta from the network and applies it to its verified
//! bundle before the signature over the result is checked, so both run on
//! untrusted bytes. No input may panic or exhaust memory. A delta that
//! reads must encode to bytes that read back as the same delta (the reader
//! is not canonical: it accepts, for example, defaults the writer leaves
//! out, which is safe because the signature covers the result bundle, not
//! the delta); one that applies must give a bundle whose bytes hash to the
//! delta's result hash and decode again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_policy::bundle::{BundleDelta, BundleLimits, PolicyBundle, apply, bundle_hash};

/// The base every delta is applied to: the golden minimal bundle.
const BASE: &[u8] = include_bytes!("../../tests/golden/bundles/minimal.cbor");

fuzz_target!(|data: &[u8]| {
    let limits = BundleLimits::DEFAULT;
    let Ok(delta) = BundleDelta::from_bytes(data, &limits) else {
        return;
    };
    let bytes = delta.to_bytes().unwrap();
    let again = BundleDelta::from_bytes(&bytes, &limits).unwrap();
    assert_eq!(again.to_bytes().unwrap(), bytes);
    // Aim at the real base, so the operations are exercised and not just
    // the base check.
    let aimed = BundleDelta {
        base_bundle_hash: bundle_hash(BASE),
        ..delta.clone()
    };
    for d in [&delta, &aimed] {
        if let Ok((bundle, out)) = apply(BASE, d, &limits) {
            assert_eq!(bundle_hash(&out), d.result_bundle_hash);
            assert_eq!(PolicyBundle::decode(&out, &limits).unwrap(), bundle);
        }
    }
});
