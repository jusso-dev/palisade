//! Property tests for the parsers and hashers.
//!
//! These run on every `cargo test`, on every platform, and complement the
//! coverage-guided fuzz targets under `fuzz/`. The parser properties check
//! that no input panics and that every result respects the documented
//! bounds. Inputs are random bytes, and mutations (byte flips, truncation,
//! overwrites) of valid synthetic images, which reach much deeper into the
//! parser than random bytes do.

// Fixture sizes are small constants, so narrowing casts cannot truncate.
#![allow(clippy::cast_possible_truncation)]

mod common;

use common::*;
use palisade_fileid::hash::{AlgorithmSet, MultiHasher, hash_bytes};
use palisade_fileid::pe::version::{self, FileVersionQuad, MAX_STRING_TABLES};
use palisade_fileid::pe::{self, MAX_SECTIONS, MAX_WARNINGS, PeInfo};
use proptest::prelude::*;

/// Checks the invariants every successful parse must hold.
fn check_bounds(data: &[u8], info: &PeInfo) {
    assert!(info.parse_warnings.len() <= MAX_WARNINGS);
    assert!(info.sections.len() <= MAX_SECTIONS);
    assert!(info.sections.len() <= data.len() / 40);
    assert!(info.data_directories.len() <= 16);
    assert!(info.e_lfanew <= pe::MAX_E_LFANEW);
    for s in &info.sections {
        if let Some(e) = s.entropy {
            assert!((0.0..=8.0 + 1e-9).contains(&e), "entropy {e}");
        }
    }
    if let Some(cert) = info.certificate_table {
        assert!(cert.offset + cert.size <= data.len() as u64);
    }
    if let Some(overlay) = info.overlay {
        assert_eq!(overlay.offset + overlay.size, data.len() as u64);
    }
    if let Some(res) = &info.resources {
        assert!(res.entry_count <= 65_535);
        for leaf in res.version_entries.iter().chain(&res.manifest_entries) {
            if let Some(bytes) = leaf.bytes(data) {
                assert_eq!(bytes.len(), leaf.size as usize);
            }
        }
    }
    if let Some(v) = &info.version_info {
        assert!(v.all_langs.len() <= MAX_STRING_TABLES);
        if let Some(i) = v.selected {
            assert!(i < v.all_langs.len());
        }
    }
}

fn seed_images() -> Vec<Vec<u8>> {
    let version = VersionSpec {
        fixed: Some(fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![
            ("040904B0", all_standard_strings()),
            ("040704B0", vec![string("ProductName", "Beispiel")]),
        ],
        translations: vec![(0x0407, 0x04b0)],
    };
    let mut rich = with_version(&version);
    rich.debug = Some(DebugSpec {
        pdb_guid: [7; 16],
        pdb_age: 2,
        pdb_path: "out\\tool.pdb".into(),
        repro: true,
        pogo: true,
    });
    rich.certificate = Some(vec![0x30; 40]);
    rich.overlay = vec![0xee; 33];
    vec![
        PeBuilder::default().build(),
        PeBuilder::pe32().build(),
        rich.build(),
        PeBuilder {
            pe32_plus: false,
            ..rich
        }
        .build(),
    ]
}

#[derive(Debug, Clone)]
enum Mutation {
    Flip { at: usize, mask: u8 },
    Write32 { at: usize, value: u32 },
    Truncate { len: usize },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    // Bias offsets toward the headers, where most structure lives.
    let at = prop_oneof![3 => 0_usize..0x400, 1 => any::<usize>()];
    let interesting = prop_oneof![
        Just(0_u32),
        Just(1),
        Just(0x7fff_ffff),
        Just(0x8000_0000),
        Just(0xffff_ffff),
        Just(0xffff),
        any::<u32>(),
    ];
    prop_oneof![
        (at.clone(), any::<u8>()).prop_map(|(at, mask)| Mutation::Flip { at, mask }),
        (at.clone(), interesting).prop_map(|(at, value)| Mutation::Write32 { at, value }),
        at.prop_map(|len| Mutation::Truncate { len }),
    ]
}

fn apply(mut data: Vec<u8>, mutations: &[Mutation]) -> Vec<u8> {
    for m in mutations {
        if data.is_empty() {
            break;
        }
        match *m {
            Mutation::Flip { at, mask } => {
                let i = at % data.len();
                data[i] ^= mask;
            }
            Mutation::Write32 { at, value } => {
                let i = at % data.len();
                for (k, b) in value.to_le_bytes().iter().enumerate() {
                    if let Some(slot) = data.get_mut(i + k) {
                        *slot = *b;
                    }
                }
            }
            Mutation::Truncate { len } => {
                let keep = len % (data.len() + 1);
                data.truncate(keep);
            }
        }
    }
    data
}

proptest! {
    // proptest saves failing cases in `properties.proptest-regressions`
    // beside this file and replays them first on the next run. Commit that
    // file with the fix.
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    #[test]
    fn parse_never_panics_on_random_bytes(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(info) = pe::parse(&data) {
            check_bounds(&data, &info);
        }
    }

    #[test]
    fn parse_never_panics_on_random_bytes_after_a_valid_dos_header(
        tail in proptest::collection::vec(any::<u8>(), 0..4096),
        lfanew in 0_u32..0x200,
    ) {
        let mut data = vec![0_u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
        data.extend(tail);
        if let Some(sig) = data.get_mut(lfanew as usize..lfanew as usize + 4) {
            sig.copy_from_slice(b"PE\0\0");
        }
        if let Ok(info) = pe::parse(&data) {
            check_bounds(&data, &info);
        }
    }

    #[test]
    fn parse_never_panics_on_mutated_images(
        seed in 0_usize..4,
        mutations in proptest::collection::vec(mutation(), 1..12),
    ) {
        let data = apply(seed_images().swap_remove(seed), &mutations);
        if let Ok(info) = pe::parse(&data) {
            check_bounds(&data, &info);
        }
    }

    #[test]
    fn version_info_never_panics(
        mutations in proptest::collection::vec(mutation(), 0..12),
        random in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let seed = VersionSpec {
            fixed: Some(fixed_info((1, 2, 3, 4), (5, 6, 7, 8))),
            tables: vec![("040904B0", all_standard_strings())],
            translations: vec![(0x0409, 0x04b0)],
        }
        .build();
        for data in [apply(seed, &mutations), random] {
            if let Ok(v) = version::parse_version_info(&data) {
                prop_assert!(v.all_langs.len() <= MAX_STRING_TABLES);
                let _ = v.file_version();
                let _ = v.effective_file_name(version::VersionField::OriginalFileName);
            }
        }
    }

    #[test]
    fn hashing_is_independent_of_chunking(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
        cuts in proptest::collection::vec(any::<usize>(), 0..8),
    ) {
        let whole = hash_bytes(&data, AlgorithmSet::ALL);
        let mut points: Vec<usize> = cuts.iter().map(|c| c % (data.len() + 1)).collect();
        points.push(0);
        points.push(data.len());
        points.sort_unstable();
        let mut hasher = MultiHasher::new(AlgorithmSet::ALL);
        for pair in points.windows(2) {
            hasher.update(&data[pair[0]..pair[1]]);
        }
        prop_assert_eq!(hasher.finalize(), whole);
    }

    #[test]
    fn quad_order_matches_tuple_order(a in any::<[u16; 4]>(), b in any::<[u16; 4]>()) {
        let qa = FileVersionQuad(a[0], a[1], a[2], a[3]);
        let qb = FileVersionQuad(b[0], b[1], b[2], b[3]);
        prop_assert_eq!(qa.cmp(&qb), a.cmp(&b));
        // Display and parse round-trip.
        prop_assert_eq!(FileVersionQuad::parse_prefix(&qa.to_string()), Some(qa));
    }

    #[test]
    fn quad_parse_never_panics(text in "\\PC{0,40}") {
        let _ = FileVersionQuad::parse_prefix(&text);
    }
}

#[test]
fn seed_images_parse_cleanly() {
    for image in seed_images() {
        let info = pe::parse(&image).unwrap();
        assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
        check_bounds(&image, &info);
    }
}

/// Every prefix of a rich image parses or fails cleanly.
#[test]
fn every_truncation_of_a_rich_image() {
    let image = seed_images().swap_remove(2);
    for len in 0..image.len() {
        let data = &image[..len];
        if let Ok(info) = pe::parse(data) {
            check_bounds(data, &info);
        }
    }
}

/// Many overlapping sections that each cover the whole file: entropy work is
/// bounded by the file length, not sections times file length.
#[test]
fn overlapping_sections_are_bounded() {
    let builder = PeBuilder::default();
    let mut image = builder.build();
    image.resize(0x8000, 0x41);
    let table = builder.section_table_offset();
    let count = (0x400 - table) / 40;
    image[COFF_OFFSET + 2..COFF_OFFSET + 4].copy_from_slice(&(count as u16).to_le_bytes());
    for i in 0..count {
        let at = table + i * 40;
        image[at + 16..at + 20].copy_from_slice(&0x8000_u32.to_le_bytes());
        image[at + 20..at + 24].copy_from_slice(&0_u32.to_le_bytes());
    }
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.sections.len(), count);
    assert!(info.sections[0].entropy.is_some());
    assert!(info.sections[1].entropy.is_none());
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| matches!(w.kind, pe::WarningKind::EntropyBudgetExhausted { index: 1 }))
    );
}

/// A declared section count above the cap is limited and reported.
#[test]
fn section_count_is_capped() {
    let builder = PeBuilder::default();
    let mut image = builder.build();
    image.resize(builder.section_table_offset() + 40 * (MAX_SECTIONS + 10), 0);
    image[COFF_OFFSET + 2..COFF_OFFSET + 4]
        .copy_from_slice(&((MAX_SECTIONS + 10) as u16).to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.sections.len(), MAX_SECTIONS);
    assert!(info.parse_warnings.iter().any(|w| matches!(
        w.kind,
        pe::WarningKind::TooManySections(n) if usize::from(n) == MAX_SECTIONS + 10
    )));
}

/// Writes the synthetic seed images (and a bare version resource) to the
/// directory in `PALISADE_FUZZ_SEED_DIR`, for seeding the fuzz corpora:
///
/// ```text
/// PALISADE_FUZZ_SEED_DIR=fuzz/corpus/pe_parse \
///     cargo test -p palisade-fileid --test properties -- --ignored write_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpora"]
fn write_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for (i, image) in seed_images().iter().enumerate() {
        std::fs::write(dir.join(format!("seed-pe-{i}")), image).unwrap();
    }
    let version = VersionSpec {
        fixed: Some(fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![("040904B0", all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    };
    std::fs::write(dir.join("seed-version"), version.build()).unwrap();
}
