//! Fuzzes the Authenticode image hash: no input may panic, and for every
//! image that parses, the hashed ranges must be sorted, disjoint, inside
//! the file, and cover every byte except the checksum field, the
//! certificate table entry and the certificate table.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::{HashRanges, RangeHasher, authenticode_hashes};
use palisade_fileid::hash::AlgorithmSet;
use palisade_fileid::pe::{self, DataDirectoryKind, ParseOptions};

fuzz_target!(|data: &[u8]| {
    let len = data.len() as u64;
    let Ok(info) = pe::parse_with(data, &ParseOptions::metadata_only()) else {
        return;
    };
    let ranges = HashRanges::from_pe(&info);
    let mut cursor = 0;
    let mut covered = 0;
    for r in ranges.included() {
        assert!(r.size > 0 && r.offset >= cursor);
        cursor = r.offset + r.size;
        covered += r.size;
    }
    assert!(cursor <= len);
    assert!(ranges.padding() < 8);
    if info.certificate_table.is_some() {
        assert_eq!(ranges.padding(), 0);
    }

    let mut excluded = vec![(info.optional.checksum_offset, 4)];
    if let Some(d) = info.data_directories.get(DataDirectoryKind::Security.index()) {
        excluded.push((d.entry_offset, 8));
    }
    if let Some(c) = info.certificate_table {
        excluded.push((c.offset, c.size));
    }
    let mut outside = 0;
    for i in 0..len {
        if !excluded.iter().any(|(o, s)| (*o..o + s).contains(&i)) {
            outside += 1;
        }
    }
    assert_eq!(covered, outside);

    let whole = authenticode_hashes(data, &info, AlgorithmSet::EMPTY).unwrap();
    assert_eq!(whole.hashed_bytes, covered + ranges.padding());
    // Streaming in odd-sized chunks gives the same result.
    let mut hasher = RangeHasher::new(ranges, AlgorithmSet::SHA256 | AlgorithmSet::SHA1);
    for chunk in data.chunks(61) {
        hasher.update(chunk);
    }
    assert_eq!(hasher.finalize().unwrap(), whole);
});
