//! Fuzzes the unified file identity record (#55): every parser of the crate
//! runs on one input through `identify_bytes`, with the masquerade,
//! strength and recommendation logic on top. No input may panic, and the
//! record must serialise and respect its documented bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::identity::{
    ExpectedSigner, IdentityContext, ProtectedList, ProtectedVendor, Tiers, identify_bytes,
    recommend,
};

fuzz_target!(|data: &[u8]| {
    // The first bytes, up to a NUL, double as the name hint, so the name
    // checks see fuzzed names too.
    let (name, body) = match data.iter().position(|b| *b == 0) {
        Some(i) if i <= 64 => (std::str::from_utf8(&data[..i]).ok(), &data[i + 1..]),
        _ => (None, data),
    };
    // A protected vendor, so the vendor-name matching is fuzzed too.
    let mut list = ProtectedList::defaults();
    list.vendors.push(ProtectedVendor {
        names: vec!["Example Org".to_owned()],
        signer: ExpectedSigner::Publisher("Example Org".to_owned()),
    });
    let mut ctx = IdentityContext::untrusted(1_795_564_800);
    ctx.protected = &list;
    let id = identify_bytes(body, name, Tiers::ALL, &ctx);
    assert!(id.masquerade.score <= 100);
    assert_eq!(id.size.computed().copied(), Some(body.len() as u64));
    let _ = recommend(&id);
    let _ = std::hint::black_box(serde_json_free_size(&id));
});

/// A cheap traversal of the record without a JSON dependency here.
fn serde_json_free_size(id: &palisade_fileid::identity::FileIdentity) -> usize {
    format!("{id:?}").len()
}
