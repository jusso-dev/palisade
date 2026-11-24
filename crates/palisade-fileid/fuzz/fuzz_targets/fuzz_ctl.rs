//! Fuzzes catalog files (#51): CTL decoding, the catalog signature check,
//! loading into a store and member lookup. No input may panic, and every
//! result must respect the documented limits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::DigestAlgorithm;
use palisade_fileid::catalog::{
    CatalogSource, CatalogStoreBuilder, FileDigests, MAX_CTL_WARNINGS, MAX_MATCHES, MAX_MEMBERS,
    MAX_NAME_VALUES, StoreLimits, parse_catalog, parse_ctl,
};
use palisade_fileid::hash::Digest;

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
    let parsed = parse_catalog(data).ok();
    if let Some(cat) = &parsed {
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

    // Queries built from the catalog's own member digests, in the field
    // each one's algorithm and data type select, so a catalog that verifies
    // exercises successful matches. Every SHA-1 or SHA-256 member of a
    // catalog whose signature is valid is indexed (one catalog stays far
    // inside the store's limits), so each must be found.
    let Some(cat) = parsed else { return };
    for (position, member) in cat.ctl.members.iter().enumerate().take(64) {
        let Some(d) = &member.digest else { continue };
        let Some(digest) = d.alg.hash_algorithm().and_then(|a| Digest::new(a, &d.digest).ok())
        else {
            continue;
        };
        let mut query = FileDigests::default();
        let slot = match (d.alg, d.is_pe_image()) {
            (DigestAlgorithm::Sha256, true) => &mut query.authenticode_sha256,
            (DigestAlgorithm::Sha1, true) => &mut query.authenticode_sha1,
            (DigestAlgorithm::Sha256, false) => &mut query.flat_sha256,
            (DigestAlgorithm::Sha1, false) => &mut query.flat_sha1,
            _ => continue,
        };
        *slot = Some(digest);
        let result = store.lookup(&query);
        assert!(result.matches.len() <= MAX_MATCHES);
        // The match may name another member with the same digest and kind.
        let found = result.matches.iter().any(|m| {
            let listed = cat.ctl.members.get(m.member).and_then(|x| x.digest.as_ref());
            m.catalog == 0
                && m.signer.is_some()
                && listed.is_some_and(|x| {
                    x.alg == d.alg && x.digest == d.digest && x.is_pe_image() == d.is_pe_image()
                })
        });
        assert_eq!(found, cat.signature_valid(), "member {position}");
    }
});
