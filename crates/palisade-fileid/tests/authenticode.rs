//! Authenticode image hash tests (#47).
//!
//! Every expected digest is computed here, independently of the library, by
//! [`spec_stream`]: a direct transcription of the steps in the Authenticode
//! PE specification (headers minus two fields, sections sorted by
//! `PointerToRawData`, trailing data up to the certificate table, zero
//! padding to 8 bytes when unsigned). The library builds its byte ranges a
//! different way (the whole file minus three regions), so agreement on
//! conformant images is a real cross-check.

// Test code: fixture sizes are small constants, so narrowing casts cannot
// truncate, and helpers may unwrap, since a failure should fail loudly.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

mod common;

use common::*;
use palisade_fileid::authenticode::{
    AuthenticodeError, AuthenticodeStatus, HashRanges, HashScenario, NonConformance, RangeHasher,
    authenticode_hashes, hash_pe,
};
use palisade_fileid::hash::{AlgorithmSet, HashAlgorithm, MultiHasher, hash_bytes};
use palisade_fileid::pe::{self, DataDirectoryKind, FileRange, PeInfo, WarningKind};
use proptest::prelude::*;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};

fn put16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn get32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

/// The bytes the Authenticode specification hashes, step by step.
///
/// 1. Offset 0 up to the `CheckSum` field; skip it (4 bytes).
/// 2. Up to the certificate table entry; skip it (8 bytes).
/// 3. Up to `SizeOfHeaders`.
/// 4. Each section with a non-zero `SizeOfRawData`, sorted by
///    `PointerToRawData`.
/// 5. Whatever follows, up to the end of the file minus the certificate
///    table's size.
/// 6. With no certificate table, zero bytes up to a multiple of 8.
fn spec_stream(data: &[u8], info: &PeInfo) -> Vec<u8> {
    let checksum = info.optional.checksum_offset as usize;
    let entry = info
        .data_directories
        .get(DataDirectoryKind::Security.index())
        .unwrap();
    let entry_at = entry.entry_offset as usize;
    let size_of_headers = info.optional.size_of_headers as usize;

    let mut out = Vec::new();
    out.extend_from_slice(&data[..checksum]);
    out.extend_from_slice(&data[checksum + 4..entry_at]);
    out.extend_from_slice(&data[entry_at + 8..size_of_headers]);
    let mut sum = size_of_headers;

    let mut sections: Vec<_> = info
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data != 0)
        .collect();
    sections.sort_by_key(|s| s.pointer_to_raw_data);
    for s in sections {
        let start = s.pointer_to_raw_data as usize;
        let end = start + s.size_of_raw_data as usize;
        out.extend_from_slice(&data[start..end]);
        sum += s.size_of_raw_data as usize;
    }

    let signed = entry.size != 0;
    let cert_size = if signed { entry.size as usize } else { 0 };
    if data.len() > sum {
        let extra = data.len() - sum - cert_size;
        out.extend_from_slice(&data[sum..sum + extra]);
    }
    if !signed {
        let pad = (8 - data.len() % 8) % 8;
        out.extend(std::iter::repeat_n(0, pad));
    }
    out
}

/// The whole file minus the checksum field, the certificate table entry and
/// the certificate table, plus the padding: a second, simpler reference
/// that holds for every layout, conformant or not.
fn excluded_stream(data: &[u8], info: &PeInfo) -> Vec<u8> {
    let checksum = info.optional.checksum_offset as usize;
    let entry = info
        .data_directories
        .get(DataDirectoryKind::Security.index())
        .map(|d| d.entry_offset as usize);
    let cert = info
        .certificate_table
        .map(|c| (c.offset as usize, (c.offset + c.size) as usize));
    let mut out: Vec<u8> = data
        .iter()
        .enumerate()
        .filter(|(i, _)| !(checksum..checksum + 4).contains(i))
        .filter(|(i, _)| !entry.is_some_and(|e| (e..e + 8).contains(i)))
        .filter(|(i, _)| !cert.is_some_and(|(s, e)| (s..e).contains(i)))
        .map(|(_, b)| *b)
        .collect();
    if cert.is_none() {
        out.extend(std::iter::repeat_n(0, (8 - data.len() % 8) % 8));
    }
    out
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn sha1(bytes: &[u8]) -> Vec<u8> {
    Sha1::digest(bytes).to_vec()
}

/// The library's Authenticode SHA-256 and SHA-1, and the status.
fn library(data: &[u8]) -> (Vec<u8>, Vec<u8>, AuthenticodeStatus) {
    let info = pe::parse(data).unwrap();
    let hashes = authenticode_hashes(data, &info, AlgorithmSet::EMPTY).unwrap();
    (
        hashes.sha256().unwrap().as_bytes().to_vec(),
        hashes.sha1().unwrap().as_bytes().to_vec(),
        hashes.status,
    )
}

fn sha256_of(data: &[u8]) -> Vec<u8> {
    library(data).0
}

/// Asserts that the library agrees with the specification's steps and that
/// the image is conformant.
fn assert_matches_spec(data: &[u8]) {
    let info = pe::parse(data).unwrap();
    let stream = spec_stream(data, &info);
    let (s256, s1, status) = library(data);
    assert_eq!(status, AuthenticodeStatus::Conformant);
    assert_eq!(s256, sha256(&stream), "SHA-256");
    assert_eq!(s1, sha1(&stream), "SHA-1");
    assert_eq!(stream, excluded_stream(data, &info));
}

/// Signs `unsigned` the way a signer does: zero-pads it to a multiple of 8,
/// appends `cert`, points the certificate table entry at it and writes a
/// checksum.
fn sign(unsigned: &[u8], cert: &[u8], checksum: u32) -> Vec<u8> {
    let info = pe::parse(unsigned).unwrap();
    let entry = info
        .data_directories
        .get(DataDirectoryKind::Security.index())
        .unwrap()
        .entry_offset as usize;
    let mut out = unsigned.to_vec();
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let at = out.len() as u32;
    out.extend_from_slice(cert);
    put32(&mut out, entry, at);
    put32(&mut out, entry + 4, cert.len() as u32);
    put32(&mut out, info.optional.checksum_offset as usize, checksum);
    out
}

/// A fake `WIN_CERTIFICATE`: length, revision 0x0200, type 2, then filler.
/// Its content is never parsed by the image hash.
fn win_certificate(body_len: usize, fill: u8) -> Vec<u8> {
    let len = 8 + body_len;
    let mut out = vec![fill; len];
    put32(&mut out, 0, len as u32);
    put16(&mut out, 4, 0x0200);
    put16(&mut out, 6, 0x0002);
    out
}

fn three_sections() -> PeBuilder {
    PeBuilder::default()
        .section(
            ".data",
            (0..700_u32).map(|i| (i * 7) as u8).collect(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        )
        .section(
            ".rdata",
            vec![0x5a; 0x200],
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )
}

fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let version = VersionSpec {
        fixed: Some(fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![("040904B0", all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    };
    let mut rich = with_version(&version);
    rich.debug = Some(DebugSpec {
        pdb_guid: [7; 16],
        pdb_age: 2,
        pdb_path: "out\\tool.pdb".into(),
        repro: true,
        pogo: true,
    });
    rich.valid_checksum = true;
    let signed = PeBuilder {
        certificate: Some(win_certificate(64, 0x30)),
        ..three_sections()
    };
    vec![
        ("pe32+ unsigned", PeBuilder::default().build()),
        ("pe32 unsigned", PeBuilder::pe32().build()),
        ("rich", rich.build()),
        (
            "rich pe32",
            PeBuilder {
                pe32_plus: false,
                ..rich.clone()
            }
            .build(),
        ),
        ("three sections", three_sections().build()),
        ("signed", signed.build()),
        (
            "signed pe32",
            PeBuilder {
                pe32_plus: false,
                ..signed.clone()
            }
            .build(),
        ),
        (
            "unsigned, odd overlay",
            PeBuilder {
                overlay: vec![0xee; 33],
                ..three_sections()
            }
            .build(),
        ),
        (
            "signed after an overlay",
            sign(
                &PeBuilder {
                    overlay: vec![0xee; 33],
                    ..three_sections()
                }
                .build(),
                &win_certificate(100, 0x41),
                0x1234_5678,
            ),
        ),
        (
            "empty section",
            PeBuilder::default()
                .section(".bss", Vec::new(), IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
                .section(".data", vec![1; 10], IMAGE_SCN_MEM_READ)
                .build(),
        ),
    ]
}

#[test]
fn conformant_images_match_the_specification_steps() {
    for (name, image) in fixtures() {
        let info = pe::parse(&image).unwrap();
        assert!(
            authenticode_hashes(&image, &info, AlgorithmSet::EMPTY)
                .unwrap()
                .status
                .is_conformant(),
            "{name}"
        );
        assert_matches_spec(&image);
    }
}

#[test]
fn the_excluded_regions_are_exactly_the_three_fields() {
    let image = PeBuilder {
        certificate: Some(win_certificate(40, 0x30)),
        ..PeBuilder::default()
    }
    .build();
    let info = pe::parse(&image).unwrap();
    let ranges = HashRanges::from_pe(&info);
    let checksum = info.optional.checksum_offset;
    let entry = info.data_directories[4].entry_offset;
    let cert = info.certificate_table.unwrap();
    assert_eq!(
        ranges.included(),
        [
            FileRange {
                offset: 0,
                size: checksum
            },
            FileRange {
                offset: checksum + 4,
                size: entry - checksum - 4
            },
            FileRange {
                offset: entry + 8,
                size: cert.offset - entry - 8
            },
        ]
    );
    assert_eq!(ranges.padding(), 0);
    assert_eq!(ranges.file_size(), image.len() as u64);
}

#[test]
fn signing_does_not_change_the_hash() {
    // The unsigned image is 33 bytes past a multiple of 8, so its hash
    // includes 7 bytes of padding, which signing then writes for real.
    let unsigned = PeBuilder {
        overlay: vec![0xee; 33],
        ..three_sections()
    }
    .build();
    assert_eq!(unsigned.len() % 8, 1);
    let signed = sign(&unsigned, &win_certificate(200, 0x11), 0xdead_beef);
    assert_eq!(library(&unsigned).0, library(&signed).0);
    assert_eq!(library(&unsigned).1, library(&signed).1);
    // Re-signing with a different certificate and checksum.
    let resigned = sign(&unsigned, &win_certificate(1000, 0x22), 7);
    assert_eq!(sha256_of(&signed), sha256_of(&resigned));
    // The flat hash does change.
    assert_ne!(
        hash_bytes(&unsigned, AlgorithmSet::SHA256).digests,
        hash_bytes(&signed, AlgorithmSet::SHA256).digests
    );
}

#[test]
fn stripping_the_certificate_table_does_not_change_the_hash() {
    // The issue's test plan: remove the table and zero the entry.
    let signed = PeBuilder {
        certificate: Some(win_certificate(64, 0x30)),
        valid_checksum: true,
        ..three_sections()
    }
    .build();
    let info = pe::parse(&signed).unwrap();
    let cert = info.certificate_table.unwrap();
    let entry = info.data_directories[4].entry_offset as usize;
    let mut stripped = signed[..cert.offset as usize].to_vec();
    put32(&mut stripped, entry, 0);
    put32(&mut stripped, entry + 4, 0);
    assert_eq!(sha256_of(&signed), sha256_of(&stripped));
    assert_eq!(library(&stripped).2, AuthenticodeStatus::Conformant);
}

#[test]
fn unsigned_images_are_padded_to_eight_bytes() {
    for extra in 0..16_usize {
        let image = PeBuilder {
            overlay: vec![0x99; extra],
            ..PeBuilder::default()
        }
        .build();
        let info = pe::parse(&image).unwrap();
        let ranges = HashRanges::from_pe(&info);
        assert_eq!(ranges.padding() as usize, (8 - image.len() % 8) % 8);
        let hashes = authenticode_hashes(&image, &info, AlgorithmSet::EMPTY).unwrap();
        assert_eq!(hashes.hashed_bytes % 8, 4, "{extra}"); // 12 bytes excluded
        assert_matches_spec(&image);
    }
}

#[test]
fn overlay_before_the_certificate_table_is_hashed() {
    let base = three_sections().build();
    let with_overlay = PeBuilder {
        overlay: vec![0xee; 40],
        ..three_sections()
    }
    .build();
    let cert = win_certificate(16, 0);
    assert_ne!(
        sha256_of(&sign(&base, &cert, 0)),
        sha256_of(&sign(&with_overlay, &cert, 0))
    );
}

#[test]
fn all_algorithms_and_the_single_digest_api() {
    let image = PeBuilder {
        certificate: Some(win_certificate(24, 1)),
        ..PeBuilder::default()
    }
    .build();
    let info = pe::parse(&image).unwrap();
    let stream = spec_stream(&image, &info);
    let all = authenticode_hashes(&image, &info, AlgorithmSet::ALL).unwrap();
    assert_eq!(all.digests.len(), 5);
    assert_eq!(
        all.get(HashAlgorithm::Sha512).unwrap().as_bytes(),
        Sha512::digest(&stream).as_slice()
    );
    assert_eq!(
        all.get(HashAlgorithm::Md5).unwrap().as_bytes(),
        hash_bytes(&stream, AlgorithmSet::MD5).digests[0].as_bytes()
    );
    // SHA-256 and SHA-1 are always included.
    let base = authenticode_hashes(&image, &info, AlgorithmSet::SHA384).unwrap();
    let algs: Vec<_> = base.digests.iter().map(|d| d.algorithm()).collect();
    assert_eq!(
        algs,
        [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha384
        ]
    );
    assert_eq!(base.hashed_bytes, stream.len() as u64);
}

#[test]
fn one_read_pass_gives_flat_and_authenticode_hashes() {
    let image = fixtures().remove(8).1;
    let info = pe::parse(&image).unwrap();
    let mut image_hasher = RangeHasher::new(HashRanges::from_pe(&info), AlgorithmSet::DEFAULT);
    let mut flat = MultiHasher::new(AlgorithmSet::DEFAULT);
    for chunk in image.chunks(97) {
        image_hasher.update(chunk);
        flat.update(chunk);
    }
    assert_eq!(flat.finalize(), hash_bytes(&image, AlgorithmSet::DEFAULT));
    let expected = authenticode_hashes(&image, &info, AlgorithmSet::MD5).unwrap();
    assert_eq!(image_hasher.finalize().unwrap(), expected);
}

#[test]
fn wrong_length_input_is_an_error() {
    let image = PeBuilder::default().build();
    let info = pe::parse(&image).unwrap();
    let short = &image[..image.len() - 1];
    assert_eq!(
        authenticode_hashes(short, &info, AlgorithmSet::EMPTY),
        Err(AuthenticodeError::LengthMismatch {
            expected: image.len() as u64,
            actual: image.len() as u64 - 1,
        })
    );
    let mut hasher = RangeHasher::new(HashRanges::from_pe(&info), AlgorithmSet::SHA256);
    hasher.update(&image);
    hasher.update(&[0]);
    assert!(matches!(
        hasher.finalize(),
        Err(AuthenticodeError::LengthMismatch { .. })
    ));
}

#[test]
fn non_pe_input_has_no_image_hash() {
    assert!(hash_pe(b"", AlgorithmSet::EMPTY).is_none());
    assert!(hash_pe(b"#!/bin/sh\necho hi\n", AlgorithmSet::EMPTY).is_none());
    assert!(hash_pe(&[0x4d, 0x5a, 0, 0], AlgorithmSet::EMPTY).is_none());
    let image = PeBuilder::default().build();
    assert_eq!(
        hash_pe(&image, AlgorithmSet::EMPTY)
            .unwrap()
            .sha256()
            .unwrap()
            .as_bytes(),
        sha256_of(&image)
    );
}

#[test]
fn scenarios_are_metadata_only() {
    assert_eq!(
        HashScenario::ALL,
        [HashScenario::UserMode, HashScenario::KernelMode]
    );
}

// ---- Non-conformant layouts ----------------------------------------------

/// The status's reasons, asserting the digest still covers every byte
/// outside the three regions.
fn reasons(image: &[u8]) -> Vec<NonConformance> {
    let info = pe::parse(image).unwrap();
    let hashes = authenticode_hashes(image, &info, AlgorithmSet::EMPTY).unwrap();
    assert_eq!(
        hashes.sha256().unwrap().as_bytes(),
        sha256(&excluded_stream(image, &info))
    );
    hashes.status.reasons().to_vec()
}

#[test]
fn data_after_the_certificate_table() {
    // An installer tool appended data after signing.
    let image = PeBuilder {
        certificate: Some(win_certificate(32, 0x30)),
        overlay: vec![0xab; 13],
        ..PeBuilder::default()
    }
    .build();
    let cert = pe::parse(&image).unwrap().certificate_table.unwrap();
    assert_eq!(
        reasons(&image),
        [NonConformance::DataAfterCertificateTable {
            offset: cert.offset + cert.size,
            size: 13
        }]
    );
    // The appended bytes are hashed, so the digest no longer matches the
    // signed original's.
    let original = PeBuilder {
        certificate: Some(win_certificate(32, 0x30)),
        ..PeBuilder::default()
    }
    .build();
    assert_ne!(sha256_of(&image), sha256_of(&original));
}

#[test]
fn misaligned_certificate_table() {
    let mut image = PeBuilder {
        overlay: vec![0; 3],
        ..PeBuilder::default()
    }
    .build();
    let at = image.len();
    assert_ne!(at % 8, 0);
    image.extend_from_slice(&win_certificate(16, 0x30));
    let entry = PeBuilder::default().data_directory_offset(4);
    put32(&mut image, entry, at as u32);
    put32(&mut image, entry + 4, 24);
    assert_eq!(
        reasons(&image),
        [NonConformance::CertificateTableMisaligned { offset: at as u64 }]
    );
}

#[test]
fn rejected_certificate_tables_are_hashed() {
    let builder = PeBuilder::default();
    let entry = builder.data_directory_offset(4);
    let base = builder.build();
    let text = pe::parse(&base).unwrap().sections[0].pointer_to_raw_data;
    let cases = [
        // Past the end of the file.
        (
            base.len() as u32,
            64,
            WarningKind::CertificateTableOutOfFile,
        ),
        // Inside the first section.
        (text, 16, WarningKind::CertificateTableOverlapsSection),
        // Inside the headers.
        (0x100, 16, WarningKind::CertificateTableInvalid),
        // Size without an offset.
        (0, 16, WarningKind::CertificateTableInvalid),
    ];
    for (offset, size, kind) in cases {
        let mut image = base.clone();
        put32(&mut image, entry, offset);
        put32(&mut image, entry + 4, size);
        let info = pe::parse(&image).unwrap();
        assert!(info.certificate_table.is_none());
        assert_eq!(info.certificate_table_issue, Some(kind.clone()));
        assert_eq!(
            reasons(&image),
            [NonConformance::CertificateTableRejected {
                offset,
                size,
                reason: Some(kind),
            }],
            "({offset:#x}, {size})"
        );
        // Nothing is excluded for a rejected table, so it hashes like the
        // unsigned image (whose entry is also excluded).
        assert_eq!(sha256_of(&image), sha256_of(&base));
    }
}

#[test]
fn zero_size_certificate_entry_is_not_a_table() {
    // An offset with a zero size means "unsigned"; the entry is excluded
    // as always, so this hashes like the plain image and stays conformant.
    let builder = PeBuilder::default();
    let mut image = builder.build();
    put32(&mut image, builder.data_directory_offset(4), 0x600);
    assert!(reasons(&image).is_empty());
    assert_eq!(sha256_of(&image), sha256_of(&builder.build()));
}

#[test]
fn certificate_table_inside_unaligned_section_data() {
    // The last section's pointer is 0x401 with 0x200 bytes, so the spec's
    // steps read it up to 0x601. The loader rounds the pointer down to
    // 0x400, so the parser sees the section end at 0x600 and accepts a
    // certificate table there.
    let builder = PeBuilder::default();
    let mut image = builder.build();
    assert_eq!(image.len(), 0x600);
    let table = builder.section_table_offset();
    put32(&mut image, table + 20, 0x401);
    put32(&mut image, OPT_OFFSET + 60, 0x401);
    image.extend_from_slice(&win_certificate(8, 0x30));
    let entry = builder.data_directory_offset(4);
    put32(&mut image, entry, 0x600);
    put32(&mut image, entry + 4, 16);
    assert!(pe::parse(&image).unwrap().certificate_table.is_some());
    assert_eq!(
        reasons(&image),
        [NonConformance::CertificateTableInsideSectionData {
            offset: 0x600,
            sections_end: 0x601,
        }]
    );
}

#[test]
fn gap_between_headers_and_sections() {
    // `SizeOfHeaders` says 0x200, but the first section starts at 0x400.
    let mut image = three_sections().build();
    put32(&mut image, OPT_OFFSET + 60, 0x200);
    assert_eq!(
        reasons(&image),
        [NonConformance::SectionNotContiguous {
            index: 0,
            expected: 0x200,
            pointer_to_raw_data: 0x400,
        }]
    );
}

#[test]
fn overlapping_sections() {
    let builder = three_sections();
    let mut image = builder.build();
    let table = builder.section_table_offset();
    // Point section 2 at section 1's data.
    let second = get32(&image, table + 40 + 20);
    put32(&mut image, table + 80 + 20, second);
    let r = reasons(&image);
    assert!(
        matches!(
            r.as_slice(),
            [NonConformance::SectionNotContiguous { index: 2, .. }]
        ),
        "{r:?}"
    );
}

#[test]
fn gap_between_sections() {
    let builder = three_sections();
    let mut image = builder.build();
    let table = builder.section_table_offset();
    // Shrink section 1 so a gap opens before section 2.
    put32(&mut image, table + 40 + 16, 0x200);
    let r = reasons(&image);
    assert!(
        matches!(
            r.as_slice(),
            [NonConformance::SectionNotContiguous {
                index: 2,
                expected: 0x800,
                ..
            }]
        ),
        "{r:?}"
    );
}

#[test]
fn section_past_the_end_of_the_file() {
    let builder = PeBuilder::default();
    let mut image = builder.build();
    put32(&mut image, builder.section_table_offset() + 16, 0x10_0000);
    assert_eq!(
        reasons(&image),
        [NonConformance::SectionOutOfFile { index: 0 }]
    );
}

#[test]
fn understated_and_overstated_size_of_headers() {
    let mut image = PeBuilder::default().build();
    put32(&mut image, OPT_OFFSET + 60, 0x100);
    let r = reasons(&image);
    assert!(
        matches!(
            r.first(),
            Some(NonConformance::SizeOfHeadersTooSmall {
                size_of_headers: 0x100,
                ..
            })
        ),
        "{r:?}"
    );

    let mut image = PeBuilder::default().build();
    put32(&mut image, OPT_OFFSET + 60, 0x10_0000);
    let r = reasons(&image);
    assert_eq!(
        r.first(),
        Some(&NonConformance::HeadersOutOfFile {
            size_of_headers: 0x10_0000
        })
    );
}

#[test]
fn no_certificate_table_entry() {
    // `NumberOfRvaAndSizes` = 4: the entry's bytes are hashed.
    let builder = PeBuilder::default();
    let mut image = builder.build();
    put32(&mut image, OPT_OFFSET + 108, 4);
    let info = pe::parse(&image).unwrap();
    assert!(info.data_directories.len() < 5);
    assert_eq!(reasons(&image), [NonConformance::NoSecurityDirectoryEntry]);
    assert_eq!(
        HashRanges::from_pe(&info).included().len(),
        2,
        "only the checksum is excluded"
    );
}

#[test]
fn incomplete_section_table() {
    let builder = PeBuilder::default();
    let mut image = builder.build();
    put16(&mut image, COFF_OFFSET + 2, 2000);
    image.resize(0x400 + 2000 * 40, 0);
    let r = reasons(&image);
    assert!(
        r.contains(&NonConformance::SectionTableIncomplete {
            declared: 2000,
            parsed: pe::MAX_SECTIONS as u16,
        }),
        "{r:?}"
    );
}

#[test]
fn non_conformance_is_displayed() {
    let text = NonConformance::DataAfterCertificateTable {
        offset: 0x800,
        size: 3,
    }
    .to_string();
    assert_eq!(text, "3 bytes follow the certificate table at 0x800");
}

// ---- Properties -----------------------------------------------------------

/// Byte offsets that are hashed in `image`: everything but the three
/// regions.
fn hashed_offsets(image: &[u8]) -> Vec<usize> {
    let info = pe::parse(image).unwrap();
    HashRanges::from_pe(&info)
        .included()
        .iter()
        .flat_map(|r| r.offset as usize..(r.offset + r.size) as usize)
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Any checksum and any certificate table, of any length, leave the hash
    /// unchanged.
    #[test]
    fn invariant_under_the_excluded_regions(
        index in 0_usize..10,
        checksum in any::<u32>(),
        cert in proptest::collection::vec(any::<u8>(), 1..600),
        cert2 in proptest::collection::vec(any::<u8>(), 1..600),
    ) {
        let (_, image) = fixtures().swap_remove(index);
        let info = pe::parse(&image).unwrap();
        // Take the image back to unsigned first, if it was signed.
        let unsigned = match info.certificate_table {
            Some(c) => {
                let mut out = image[..c.offset as usize].to_vec();
                let entry = info.data_directories[4].entry_offset as usize;
                put32(&mut out, entry, 0);
                put32(&mut out, entry + 4, 0);
                out
            }
            None => image.clone(),
        };
        let base = sha256_of(&unsigned);
        let mut rechecksummed = unsigned.clone();
        put32(&mut rechecksummed, info.optional.checksum_offset as usize, checksum);
        prop_assert_eq!(sha256_of(&rechecksummed), base.clone());
        let signed = sign(&unsigned, &cert, checksum);
        prop_assert_eq!(sha256_of(&signed), base.clone());
        let resigned = sign(&unsigned, &cert2, checksum ^ 1);
        prop_assert_eq!(sha256_of(&resigned), base);
    }

    /// Changing any hashed byte changes the hash, whether or not the change
    /// also changes how the image parses.
    #[test]
    fn any_other_byte_change_changes_the_hash(
        index in 0_usize..10,
        pick in any::<prop::sample::Index>(),
        mask in 1_u8..=255,
    ) {
        let (_, image) = fixtures().swap_remove(index);
        let offsets = hashed_offsets(&image);
        let at = offsets[pick.index(offsets.len())];
        let mut changed = image.clone();
        changed[at] ^= mask;

        // Over the original ranges, the digest always changes.
        let info = pe::parse(&image).unwrap();
        let mut hasher = RangeHasher::new(HashRanges::from_pe(&info), AlgorithmSet::SHA256);
        hasher.update(&changed);
        let digest = hasher.finalize().unwrap();
        let original = sha256_of(&image);
        prop_assert_ne!(digest.sha256().unwrap().as_bytes(), original.as_slice());

        // Parsed afresh, the change either stops it parsing as a PE image
        // or changes the digest.
        if let Ok(info) = pe::parse(&changed) {
            let fresh = authenticode_hashes(&changed, &info, AlgorithmSet::EMPTY).unwrap();
            prop_assert_ne!(fresh.sha256().unwrap().as_bytes(), original.as_slice());
        }
    }

    /// The digest does not depend on how the file is split into chunks.
    #[test]
    fn independent_of_chunking(
        index in 0_usize..10,
        sizes in proptest::collection::vec(1_usize..300, 1..40),
    ) {
        let (_, image) = fixtures().swap_remove(index);
        let info = pe::parse(&image).unwrap();
        let mut hasher = RangeHasher::new(HashRanges::from_pe(&info), AlgorithmSet::SHA256);
        let mut rest = image.as_slice();
        for size in sizes.iter().cycle() {
            if rest.is_empty() {
                break;
            }
            let (chunk, tail) = rest.split_at((*size).min(rest.len()));
            hasher.update(chunk);
            rest = tail;
        }
        hasher.update(&[]);
        let streamed = hasher.finalize().unwrap();
        let expected = sha256_of(&image);
        prop_assert_eq!(streamed.sha256().unwrap().as_bytes(), expected.as_slice());
    }

    /// On arbitrary mutated images the ranges stay sorted, disjoint and in
    /// the file, exactly the three regions are excluded, and hashing never
    /// panics.
    #[test]
    fn ranges_are_well_formed_on_mutated_images(
        index in 0_usize..10,
        writes in proptest::collection::vec((0_usize..0x600, any::<u32>()), 1..6),
        truncate in proptest::option::of(0_usize..0x2000),
    ) {
        let (_, mut image) = fixtures().swap_remove(index);
        for (at, value) in writes {
            if at + 4 <= image.len() {
                put32(&mut image, at, value);
            }
        }
        if let Some(len) = truncate {
            image.truncate(len);
        }
        let Ok(info) = pe::parse(&image) else {
            return Ok(());
        };
        let ranges = HashRanges::from_pe(&info);
        let mut cursor = 0;
        for r in ranges.included() {
            prop_assert!(r.size > 0);
            prop_assert!(r.offset >= cursor);
            cursor = r.offset + r.size;
        }
        prop_assert!(cursor <= image.len() as u64);
        prop_assert!(ranges.padding() < 8);
        let hashes = authenticode_hashes(&image, &info, AlgorithmSet::EMPTY).unwrap();
        let expected = sha256(&excluded_stream(&image, &info));
        prop_assert_eq!(hashes.sha256().unwrap().as_bytes(), expected.as_slice());
        if hashes.status.is_conformant() {
            let expected = sha256(&spec_stream(&image, &info));
            prop_assert_eq!(hashes.sha256().unwrap().as_bytes(), expected.as_slice());
        }
    }
}
