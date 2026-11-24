//! Page hash tests (#47).
//!
//! The reference is an independent signer: `tests/fixtures/page_hash`
//! holds page hash signatures that osslsigncode made over the synthetic
//! images in [`fixture_images`]. Each test rebuilds the image, attaches the
//! signature, and checks that the table this crate computes equals the one
//! the signer wrote, entry for entry.

// Test code: fixture sizes are small constants, so narrowing casts cannot
// truncate, and helpers may unwrap, since a failure should fail loudly.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

mod common;

use common::*;
use palisade_fileid::authenticode::{
    HashRanges, PAGE_SIZE, PageHashCheck, PageHashError, PageHasher, PageHashes, PageLayout,
    PageMismatchKind, SignatureStatus, VerifyOptions, authenticode_hashes, page_hash_table,
    page_hash_tables, verify_page_hashes, verify_pe, verify_signature_page_hashes,
};
use palisade_fileid::hash::{AlgorithmSet, HashAlgorithm};
use palisade_fileid::pe::{self, PeInfo};
use proptest::prelude::*;
use sha1::Sha1;
use sha2::Sha256;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Section data that is not all zeros, so a wrong range shows.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// The images the page hash fixtures sign, by name.
///
/// - `default`: one small section (the image the #48 fixtures use).
/// - `multi`: three sections, the second spanning three pages and ending
///   mid-page, plus an empty (`.bss`-style) section.
/// - `pe32`: a 32-bit image with a section of exactly two pages.
fn fixture_images() -> Vec<(&'static str, PeBuilder)> {
    vec![
        ("default", PeBuilder::default()),
        (
            "multi",
            PeBuilder::default()
                .section(".data", pattern(9000, 7), IMAGE_SCN_CNT_INITIALIZED_DATA)
                .section(".bss", Vec::new(), IMAGE_SCN_CNT_INITIALIZED_DATA)
                .section(".tls", pattern(100, 3), IMAGE_SCN_CNT_INITIALIZED_DATA),
        ),
        (
            "pe32",
            PeBuilder::pe32().section(
                ".data",
                pattern(2 * PAGE_SIZE as usize, 1),
                IMAGE_SCN_CNT_INITIALIZED_DATA,
            ),
        ),
    ]
}

fn builder(name: &str) -> PeBuilder {
    fixture_images()
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap()
        .1
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

/// A `WIN_CERTIFICATE` entry for a PKCS#7 blob: header, data, padding.
fn pkcs7_entry(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u32 + 8).to_le_bytes());
    out.extend_from_slice(&0x0200_u16.to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

/// The image `name`, signed with the fixture `blob`.
fn signed(name: &str, blob: &str) -> Vec<u8> {
    PeBuilder {
        certificate: Some(pkcs7_entry(&fixture(blob))),
        ..builder(name)
    }
    .build()
}

/// The page hash table a signature carries, checked to be from a valid
/// signature over `image`.
fn signed_table(image: &[u8]) -> PageHashes {
    let report = verify_pe(image, &VerifyOptions::default()).unwrap();
    assert_eq!(report.signatures.len(), 1, "{report:#?}");
    let sig = &report.signatures[0];
    assert_eq!(sig.status, SignatureStatus::Valid, "{sig:#?}");
    sig.page_hashes.clone().unwrap()
}

/// An independent page hash table, straight from the description in the
/// module docs: the header page minus the two fields, then each section's
/// pages, each zero-padded to 4 KiB of file bytes, then a zero entry at the
/// end.
fn reference_table<D: sha2::Digest>(data: &[u8], info: &PeInfo) -> Vec<(u32, Vec<u8>)> {
    let page = PAGE_SIZE as usize;
    // `span` is how many file bytes the page covers; the padding takes it
    // to 4 KiB. For the header page the 12 excluded bytes are dropped, not
    // padded, so 4,084 bytes are hashed.
    let hash = |bytes: &[u8], span: usize| {
        let mut h = D::new();
        h.update(bytes);
        h.update(vec![0_u8; page - span]);
        h.finalize().to_vec()
    };
    let checksum = info.optional.checksum_offset as usize;
    let entry = info.data_directories[4].entry_offset as usize;
    let headers = info.optional.size_of_headers as usize;
    let mut first = Vec::new();
    first.extend_from_slice(&data[..checksum]);
    first.extend_from_slice(&data[checksum + 4..entry]);
    first.extend_from_slice(&data[entry + 8..headers]);
    let mut out = vec![(0, hash(&first, headers))];
    let mut end = headers;
    for s in info.sections.iter().filter(|s| s.size_of_raw_data != 0) {
        let start = s.pointer_to_raw_data as usize;
        end = start + s.size_of_raw_data as usize;
        for at in (start..end).step_by(page) {
            let bytes = &data[at..end.min(at + page)];
            out.push((at as u32, hash(bytes, bytes.len())));
        }
    }
    out.push((end as u32, vec![0; <D as sha2::Digest>::output_size()]));
    out
}

fn entries(table: &PageHashes) -> Vec<(u32, Vec<u8>)> {
    table.entries().map(|(o, d)| (o, d.to_vec())).collect()
}

// --- Agreement with the signer. ------------------------------------------------

/// Every fixture: the signer's table equals ours, and both equal the
/// reference.
#[test]
fn tables_match_the_signer() {
    for (name, blob, alg) in [
        (
            "default",
            "authenticode/rsa2048-page-hashes.p7",
            HashAlgorithm::Sha256,
        ),
        ("default", "page_hash/default-sha1.p7", HashAlgorithm::Sha1),
        ("multi", "page_hash/multi-sha256.p7", HashAlgorithm::Sha256),
        ("multi", "page_hash/multi-sha1.p7", HashAlgorithm::Sha1),
        ("pe32", "page_hash/pe32-sha256.p7", HashAlgorithm::Sha256),
    ] {
        let image = signed(name, blob);
        let info = pe::parse(&image).unwrap();
        let theirs = signed_table(&image);
        assert_eq!(theirs.algorithm, alg, "{blob}");
        let ours = page_hash_table(&image, &info, alg).unwrap();
        assert_eq!(entries(&ours), entries(&theirs), "{blob}");
        let reference = match alg {
            HashAlgorithm::Sha1 => reference_table::<Sha1>(&image, &info),
            _ => reference_table::<Sha256>(&image, &info),
        };
        assert_eq!(entries(&ours), reference, "{blob}");
        assert_eq!(
            verify_page_hashes(&image, &info, &theirs),
            PageHashCheck::Match,
            "{blob}"
        );
    }
}

#[test]
fn table_shape() {
    let image = signed("multi", "page_hash/multi-sha256.p7");
    let info = pe::parse(&image).unwrap();
    let table = page_hash_table(&image, &info, HashAlgorithm::Sha256).unwrap();
    let offsets: Vec<u32> = table.entries().map(|(o, _)| o).collect();
    // Headers; .text (one page); .data (9000 bytes, rounded to 9216: three
    // pages); no .bss page; .tls (one page); then the end.
    assert_eq!(offsets, [0x0, 0x400, 0x600, 0x1600, 0x2600, 0x2a00, 0x2c00]);
    assert_eq!(table.len(), offsets.len());
    assert!(table.entries().last().unwrap().1.iter().all(|b| *b == 0));
    assert_eq!(
        PageLayout::from_pe(&info).unwrap().entry_count(),
        offsets.len()
    );
}

/// The header page is the same before and after signing, so the first
/// entry does not depend on the signature.
#[test]
fn header_page_ignores_the_signature() {
    let unsigned = builder("multi").build();
    let info = pe::parse(&unsigned).unwrap();
    let before = page_hash_tables(&unsigned, &info).unwrap();
    let image = signed("multi", "page_hash/multi-sha256.p7");
    let info = pe::parse(&image).unwrap();
    let after = page_hash_tables(&image, &info).unwrap();
    assert_eq!(before, after);
    assert!(before.sha1.is_some() && before.sha256.is_some());
}

// --- Checking a signed table. ----------------------------------------------------

#[test]
fn patched_page_is_reported() {
    let mut image = signed("multi", "page_hash/multi-sha256.p7");
    let info = pe::parse(&image).unwrap();
    let table = signed_table(&image);
    // A byte in the second page of .data.
    image[0x1600 + 10] ^= 0xff;
    let check = verify_page_hashes(&image, &info, &table);
    let PageHashCheck::Mismatch(m) = check else {
        panic!("{check:?}");
    };
    assert_eq!((m.index, m.offset), (3, 0x1600));
    assert!(matches!(m.kind, PageMismatchKind::Digest { .. }));

    // The whole-image digest no longer matches either; the signature is
    // still cryptographically sound, so its page table is checked.
    let report = verify_pe(&image, &VerifyOptions::default()).unwrap();
    let sig = &report.signatures[0];
    assert_eq!(sig.status, SignatureStatus::DigestMismatch);
    let check = verify_signature_page_hashes(&image, &info, sig).unwrap();
    assert!(matches!(check, PageHashCheck::Mismatch(m) if m.offset == 0x1600));
}

#[test]
fn patched_header_is_reported_at_offset_zero() {
    let mut image = signed("default", "authenticode/rsa2048-page-hashes.p7");
    let table = signed_table(&image);
    image[0x80] ^= 1; // inside the optional header
    let info = pe::parse(&image).unwrap();
    let check = verify_page_hashes(&image, &info, &table);
    assert!(matches!(check, PageHashCheck::Mismatch(m) if m.index == 0 && m.offset == 0));
}

#[test]
fn excluded_fields_do_not_change_pages() {
    let mut image = signed("multi", "page_hash/multi-sha256.p7");
    let table = signed_table(&image);
    let checksum = builder("multi").checksum_offset();
    image[checksum..checksum + 4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let info = pe::parse(&image).unwrap();
    assert_eq!(
        verify_page_hashes(&image, &info, &table),
        PageHashCheck::Match
    );
}

#[test]
fn table_shape_mismatches_are_reported() {
    let image = signed("multi", "page_hash/multi-sha256.p7");
    let info = pe::parse(&image).unwrap();
    let table = signed_table(&image);
    let record = 4 + 32;

    let short = PageHashes {
        table: table.table[..table.table.len() - record].to_vec(),
        ..table.clone()
    };
    let check = verify_page_hashes(&image, &info, &short);
    assert!(
        matches!(&check, PageHashCheck::Mismatch(m) if m.kind == PageMismatchKind::MissingEntry && m.index == table.len() - 1),
        "{check:?}"
    );

    let mut long = table.clone();
    long.table.extend_from_slice(&table.table[..record]);
    let check = verify_page_hashes(&image, &info, &long);
    assert!(
        matches!(&check, PageHashCheck::Mismatch(m) if m.kind == PageMismatchKind::ExtraEntry && m.index == table.len()),
        "{check:?}"
    );

    let mut moved = table.clone();
    moved.table[record..record + 4].copy_from_slice(&0x500_u32.to_le_bytes());
    let check = verify_page_hashes(&image, &info, &moved);
    assert!(
        matches!(&check, PageHashCheck::Mismatch(m) if m.index == 1 && m.offset == 0x500 && m.kind == PageMismatchKind::Offset { actual: 0x400 }),
        "{check:?}"
    );
}

#[test]
fn tables_from_bad_signatures_are_not_checked() {
    let blob = fixture("page_hash/multi-sha256.p7");
    // Flip the last byte of the blob: the SignerInfo signature value.
    let mut bad = blob.clone();
    *bad.last_mut().unwrap() ^= 1;
    let image = PeBuilder {
        certificate: Some(pkcs7_entry(&bad)),
        ..builder("multi")
    }
    .build();
    let info = pe::parse(&image).unwrap();
    let report = verify_pe(&image, &VerifyOptions::default()).unwrap();
    let sig = &report.signatures[0];
    assert!(
        matches!(sig.status, SignatureStatus::BadSignature(_)),
        "{sig:#?}"
    );
    assert!(sig.page_hashes.is_some());
    assert_eq!(
        verify_signature_page_hashes(&image, &info, sig),
        Some(PageHashCheck::SignatureNotValid)
    );

    // No table at all.
    let image = PeBuilder {
        certificate: Some(pkcs7_entry(&fixture("authenticode/rsa2048-sha256.p7"))),
        ..PeBuilder::default()
    }
    .build();
    let info = pe::parse(&image).unwrap();
    let report = verify_pe(&image, &VerifyOptions::default()).unwrap();
    assert_eq!(
        verify_signature_page_hashes(&image, &info, &report.signatures[0]),
        None
    );
}

// --- Images with no table. ---------------------------------------------------------

#[test]
fn non_conformant_images_have_no_table() {
    // Data after the certificate table.
    let image = PeBuilder {
        certificate: Some(pkcs7_entry(&fixture("authenticode/rsa2048-page-hashes.p7"))),
        overlay: vec![1, 2, 3, 4, 5, 6, 7, 8],
        ..PeBuilder::default()
    }
    .build();
    let info = pe::parse(&image).unwrap();
    let err = page_hash_tables(&image, &info).unwrap_err();
    assert!(
        matches!(err, PageHashError::NonConformantImage(ref r) if !r.is_empty()),
        "{err}"
    );
    let table = signed_table_unchecked(&image);
    assert!(matches!(
        verify_page_hashes(&image, &info, &table),
        PageHashCheck::Unavailable(PageHashError::NonConformantImage(_))
    ));
    // And the image hash result says why.
    let hashes = authenticode_hashes(&image, &info, AlgorithmSet::EMPTY).unwrap();
    assert!(matches!(
        hashes.page_hashes,
        Some(Err(PageHashError::NonConformantImage(_)))
    ));
}

fn signed_table_unchecked(image: &[u8]) -> PageHashes {
    let report = verify_pe(image, &VerifyOptions::default()).unwrap();
    report.signatures[0].page_hashes.clone().unwrap()
}

#[test]
fn headers_over_one_page_have_no_table() {
    let mut image = PeBuilder::default().build();
    let info = pe::parse(&image).unwrap();
    // Grow SizeOfHeaders past a page, and move the section to match so the
    // image stays conformant.
    let soh = info.optional.offset as usize + 60;
    let mut big = image[..0x400].to_vec();
    big.resize(0x1200, 0);
    big.extend_from_slice(&image[0x400..]);
    big[soh..soh + 4].copy_from_slice(&0x1200_u32.to_le_bytes());
    let ptr = info.sections[0].header_offset as usize + 20;
    big[ptr..ptr + 4].copy_from_slice(&0x1200_u32.to_le_bytes());
    image = big;
    let info = pe::parse(&image).unwrap();
    assert!(HashRanges::from_pe(&info).status().is_conformant());
    assert_eq!(
        page_hash_tables(&image, &info).unwrap_err(),
        PageHashError::HeadersLargerThanPage {
            size_of_headers: 0x1200
        }
    );
}

#[test]
fn sections_out_of_table_order_have_no_table() {
    let mut image = builder("multi").build();
    let info = pe::parse(&image).unwrap();
    // Swap the first two section headers: file order and table order now
    // disagree, though the layout itself is still contiguous.
    let a = info.sections[0].header_offset as usize;
    let b = info.sections[1].header_offset as usize;
    let first: Vec<u8> = image[a..a + 40].to_vec();
    let second: Vec<u8> = image[b..b + 40].to_vec();
    image[a..a + 40].copy_from_slice(&second);
    image[b..b + 40].copy_from_slice(&first);
    let info = pe::parse(&image).unwrap();
    assert!(HashRanges::from_pe(&info).status().is_conformant());
    assert_eq!(
        page_hash_tables(&image, &info).unwrap_err(),
        PageHashError::SectionsNotInFileOrder
    );
}

#[test]
fn only_sha1_and_sha256_have_page_hashes() {
    let image = PeBuilder::default().build();
    let info = pe::parse(&image).unwrap();
    for alg in [
        HashAlgorithm::Md5,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ] {
        assert_eq!(
            page_hash_table(&image, &info, alg).unwrap_err(),
            PageHashError::UnsupportedAlgorithm(alg)
        );
    }
    let layout = PageLayout::from_pe(&info).unwrap();
    assert!(PageHasher::new(layout, AlgorithmSet::SHA384).is_err());
}

#[test]
fn wrong_length_input_is_rejected() {
    let image = PeBuilder::default().build();
    let info = pe::parse(&image).unwrap();
    let mut short =
        PageHasher::new(PageLayout::from_pe(&info).unwrap(), AlgorithmSet::SHA256).unwrap();
    short.update(&image[..image.len() - 1]);
    assert_eq!(
        short.finalize().unwrap_err(),
        PageHashError::LengthMismatch {
            expected: image.len() as u64,
            actual: image.len() as u64 - 1
        }
    );
}

// --- Streaming. --------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The tables do not depend on how the file is split into chunks.
    #[test]
    fn chunking_does_not_matter(chunk in 1_usize..9000) {
        let image = signed("multi", "page_hash/multi-sha256.p7");
        let info = pe::parse(&image).unwrap();
        let whole = page_hash_tables(&image, &info).unwrap();
        let mut hasher = PageHasher::new(
            PageLayout::from_pe(&info).unwrap(),
            AlgorithmSet::SHA1 | AlgorithmSet::SHA256,
        )
        .unwrap();
        for part in image.chunks(chunk) {
            hasher.update(part);
        }
        prop_assert_eq!(hasher.finalize().unwrap(), whole);
    }

    /// Mutated headers: the layout either fails with a typed error or gives
    /// a table that matches the reference.
    #[test]
    fn mutated_images_match_the_reference(
        edits in proptest::collection::vec((0_usize..0x400, any::<u32>()), 1..4),
    ) {
        let mut image = builder("multi").build();
        for (at, value) in edits {
            let at = at.min(image.len() - 4);
            image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let Ok(info) = pe::parse(&image) else {
            return Ok(());
        };
        if let Ok(tables) = page_hash_tables(&image, &info) {
            let expected = reference_table::<Sha256>(&image, &info);
            prop_assert_eq!(entries(tables.sha256.as_ref().unwrap()), expected);
        }
    }
}

/// Writes the unsigned fixture images for `generate.sh`:
///
/// ```sh
/// PALISADE_PAGE_HASH_IMAGES=/tmp/dir \
///     cargo test -p palisade-fileid --test page_hash -- --ignored write_page_hash_images
/// ```
#[test]
#[ignore = "writes files; run by tests/fixtures/page_hash/generate.sh"]
fn write_page_hash_images() {
    let dir = std::env::var_os("PALISADE_PAGE_HASH_IMAGES").expect("set PALISADE_PAGE_HASH_IMAGES");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for (name, b) in fixture_images() {
        std::fs::write(dir.join(format!("{name}.exe")), b.build()).unwrap();
    }
}
