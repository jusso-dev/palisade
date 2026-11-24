//! Fuzzes the trust-set decoders and the agent acceptance rule (#224): the
//! input is a signed trust-set envelope, which an agent receives from the
//! network. No input may panic. Every input that decodes must re-encode to
//! exactly the same bytes, because the format has one encoding per value.
//! An anchor whose root never signed anything must refuse every input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_proto::events::Timestamp;
use palisade_proto::pki::{
    KeyPurpose, SignatureAlgorithm, Signer, SignedTrustSet, SkewTolerance, SoftwareSigner,
    TrustAnchor, TrustSet,
};
use std::sync::OnceLock;

fn anchor() -> &'static TrustAnchor {
    static ANCHOR: OnceLock<TrustAnchor> = OnceLock::new();
    ANCHOR.get_or_init(|| {
        let mut signer = SoftwareSigner::new();
        let root = signer
            .generate(KeyPurpose::RootCa, SignatureAlgorithm::EcdsaP384Sha384)
            .unwrap();
        TrustAnchor::new(signer.public_key(&root).unwrap(), SkewTolerance::DEFAULT).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(set) = TrustSet::decode(data) {
        assert_eq!(set.encode().unwrap(), data);
    }
    if let Ok(signed) = SignedTrustSet::decode(data) {
        assert_eq!(signed.encode(), data);
        let set = TrustSet::decode(signed.payload()).unwrap();
        assert_eq!(set.encode().unwrap(), signed.payload());
    }
    let now = Timestamp::from_unix_micros(1_795_000_000_000_000).unwrap();
    assert!(anchor().check(data, now).is_err());
});
