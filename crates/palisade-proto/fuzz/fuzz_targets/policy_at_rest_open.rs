//! Fuzzes the policy cache's at-rest formats (#326): the keyring decoder
//! and opening a sealed cache file, both of which the agent reads from
//! disk. No input may panic. A keyring that decodes must re-encode to the
//! same bytes. A sealed file opens only under the key that sealed it, so
//! no fuzz input may open under a fresh keyring.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use palisade_proto::policy_bundle::at_rest::KeyRing;

fn ring() -> &'static KeyRing {
    static RING: OnceLock<KeyRing> = OnceLock::new();
    RING.get_or_init(|| KeyRing::generate().unwrap())
}

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = KeyRing::decode(data) {
        assert_eq!(decoded.encode(), data);
        let _ = decoded.open(data);
    }
    assert!(ring().open(data).is_err(), "a fuzz input opened under a fresh key");
});
