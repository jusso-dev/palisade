//! Fuzzes catalog files (#51): CTL decoding, the catalog signature check,
//! loading into a store and member lookup. No input may panic, and every
//! result must respect the documented limits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::catalog::{
    CatalogSource, CatalogStoreBuilder, FileDigests, MAX_CTL_WARNINGS, MAX_MATCHES, MAX_MEMBERS,
    MAX_NAME_VALUES, StoreLimits, parse_catalog, parse_ctl,
};

fuzz_target!(|data: &[u8]| {
    for ctl in [parse_ctl(data).ok(), parse_catalog(data).ok().map(|c| c.ctl)]
        .into_iter()
        .flatten()
    {
        assert!(ctl.members.len() <= MAX_MEMBERS);
        assert!(ctl.attributes.len() <= MAX_NAME_VALUES);
        assert!(ctl.warnings.len() <= MAX_CTL_WARNINGS + 1);
        for m in &ctl.members {
            assert!(m.name_values.len() <= MAX_NAME_VALUES);
            if let Some(d) = &m.digest {
                assert_eq!(d.digest.len(), d.alg.digest_len());
            }
        }
    }
    if let Ok(cat) = parse_catalog(data) {
        assert_eq!(cat.signatures.signatures.len(), 1);
        assert_eq!(cat.signature_valid(), cat.signatures.primary.is_some());
    }

    let mut builder = CatalogStoreBuilder::new(StoreLimits::default());
    let report = builder.add_bytes(CatalogSource::Policy, None, data);
    assert_eq!(report.recorded + report.duplicates, 1);
    let store = builder.build();
    // Look up every digest the input itself could carry, so matches are
    // exercised whenever the catalog verifies.
    let mut digests = FileDigests::of_bytes(data);
    for record in store.records() {
        assert!(record.indexed_members <= record.member_count);
        // Nothing is trusted under an empty trust configuration.
        assert!(!record.trusted);
    }
    let result = store.lookup(&digests);
    assert!(result.matches.len() <= MAX_MATCHES);
    digests.authenticode_sha256 = digests.flat_sha256.clone();
    digests.authenticode_sha1 = digests.flat_sha1.clone();
    let _ = store.lookup(&digests);
});
