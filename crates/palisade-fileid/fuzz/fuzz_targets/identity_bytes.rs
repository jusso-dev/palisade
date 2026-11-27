//! Fuzzes the unified file identity record (#55): every parser of the crate
//! runs on one input through `identify_bytes`, with the masquerade,
//! strength and recommendation logic on top. No input may panic, nothing
//! may be trusted under an empty trust configuration, and the record must
//! serialise.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::identity::{
    ExpectedSigner, IdentityContext, ProtectedList, ProtectedVendor, RuleLevel,
    SigningStateKind, Tiers, identify_bytes, recommend,
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
    assert_eq!(id.size.computed().copied(), Some(body.len() as u64));
    // Nothing is trusted under an empty trust configuration, so no input
    // may come out trusted, or be recommended a signer rule.
    if let Some(s) = id.signing_state.computed() {
        assert_ne!(s.state, SigningStateKind::Trusted);
        assert!(s.signer.is_none());
    }
    let rec = recommend(&id);
    assert!(!matches!(
        rec.level,
        RuleLevel::Publisher | RuleLevel::PublisherProduct | RuleLevel::FilePublisher
    ));
    // The record always serialises.
    serde_json::to_vec(&id).expect("the record serialises");
});
