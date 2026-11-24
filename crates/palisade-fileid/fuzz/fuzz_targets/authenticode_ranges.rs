//! Fuzzes the Authenticode image hash and page hashes: no input may panic,
//! and for every image that parses, the hashed ranges must be sorted,
//! disjoint, inside the file, and cover every byte except the checksum
//! field, the certificate table entry and the certificate table. Page hash
//! tables, when the image has one, must be in strictly ascending file order
//! inside the file and independent of chunking. Parsing only the header
//! prefix must give the same ranges as parsing the whole file.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::{
    HEADER_PREFIX_LEN, HashRanges, PageHasher, PageLayout, RangeHasher, authenticode_hashes,
};
use palisade_fileid::hash::AlgorithmSet;
use palisade_fileid::pe::{self, DataDirectoryKind, ParseOptions};

fuzz_target!(|data: &[u8]| {
    let len = data.len() as u64;
    let Ok(info) = pe::parse_with(data, &ParseOptions::metadata_only()) else {
        return;
    };
    let ranges = HashRanges::from_pe(&info);
    let mut cursor = 0;
    let mut covered = 0_u64;
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
    if let Some(d) = info
        .data_directories
        .get(DataDirectoryKind::Security.index())
    {
        excluded.push((d.entry_offset, 8));
    }
    if let Some(c) = info.certificate_table {
        excluded.push((c.offset, c.size));
    }
    // Exactly the bytes outside the three regions are hashed.
    for i in 0..len {
        let is_excluded = excluded
            .iter()
            .any(|(o, s)| (*o..o.saturating_add(*s)).contains(&i));
        let is_included = ranges
            .included()
            .iter()
            .any(|r| (r.offset..r.offset + r.size).contains(&i));
        assert_ne!(is_excluded, is_included, "byte {i:#x}");
    }

    let whole = authenticode_hashes(data, &info, AlgorithmSet::EMPTY).unwrap();
    assert_eq!(whole.hashed_bytes, covered + ranges.padding());
    // Streaming in odd-sized chunks gives the same result.
    let mut hasher = RangeHasher::new(ranges, AlgorithmSet::SHA256 | AlgorithmSet::SHA1);
    for chunk in data.chunks(61) {
        hasher.update(chunk);
    }
    let streamed = hasher.finalize().unwrap();
    assert_eq!(streamed.digests, whole.digests);
    assert_eq!(streamed.status, whole.status);

    // The header prefix alone gives the same ranges.
    let prefix = &data[..data.len().min(HEADER_PREFIX_LEN)];
    let from_prefix = pe::parse_prefix(prefix, len).unwrap();
    assert_eq!(HashRanges::from_pe(&from_prefix), HashRanges::from_pe(&info));

    // Page hash tables: ascending, inside the file, chunking-independent.
    if let Some(Ok(tables)) = &whole.page_hashes {
        for table in [&tables.sha1, &tables.sha256].into_iter().flatten() {
            let offsets: Vec<u32> = table.entries().map(|(o, _)| o).collect();
            assert_eq!(offsets.first(), Some(&0));
            assert!(offsets.windows(2).all(|w| w[0] < w[1]));
            assert!(offsets.last().is_some_and(|o| u64::from(*o) <= len));
        }
        let layout = PageLayout::from_pe(&info).unwrap();
        let mut pages = PageHasher::new(layout, AlgorithmSet::SHA1 | AlgorithmSet::SHA256).unwrap();
        for chunk in data.chunks(61) {
            pages.update(chunk);
        }
        assert_eq!(&pages.finalize().unwrap(), tables);
    }
});
