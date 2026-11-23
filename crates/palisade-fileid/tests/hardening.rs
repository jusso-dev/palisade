//! Regression tests for parser differentials: places where a crafted image
//! could make this parser read something other than what the OS loader
//! reads, or hide a structure from it.

// Test code: fixture sizes are small constants, so narrowing casts cannot
// truncate, and helpers outside `#[test]` functions may unwrap, since a
// failure there should fail the test loudly.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

mod common;

use common::*;
use palisade_fileid::pe::version::{FileVersionQuad, VersionField};
use palisade_fileid::pe::{
    self, DataDirectoryKind, MAX_RESOURCE_ENTRIES, MAX_WARNINGS, ParseOptions, ResourceId,
    WarningKind, resource_type,
};

fn put16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

const DIR: u32 = 0x8000_0000;

/// Writes a resource directory at `at` whose entries are
/// `(name_field, target)` pairs. Named entries (high bit set) must come
/// first; `named` says how many there are.
fn put_dir(buf: &mut Vec<u8>, at: usize, named: u16, entries: &[(u32, u32)]) {
    let end = at + 16 + 8 * entries.len();
    if buf.len() < end {
        buf.resize(end, 0);
    }
    let ids = entries.len() - usize::from(named);
    put16(buf, at + 12, named);
    put16(buf, at + 14, u16::try_from(ids).unwrap());
    for (i, (name, target)) in entries.iter().enumerate() {
        put32(buf, at + 16 + 8 * i, *name);
        put32(buf, at + 20 + 8 * i, *target);
    }
}

/// Writes a data entry at `at` pointing at RVA `rva`, `size` bytes.
fn put_data_entry(buf: &mut Vec<u8>, at: usize, rva: u32, size: u32) {
    if buf.len() < at + 16 {
        buf.resize(at + 16, 0);
    }
    put32(buf, at, rva);
    put32(buf, at + 4, size);
}

/// RVA of a custom section added as the second section (index 1).
const RSRC_RVA: u32 = 0x2000;

/// Builds an image whose second section is `tree`, with the resource data
/// directory pointing at its start.
fn image_with_tree(tree: Vec<u8>) -> Vec<u8> {
    let builder = PeBuilder::default().section(
        ".rsrc",
        tree,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    );
    let mut image = builder.build();
    let at = builder.data_directory_offset(2);
    put32(&mut image, at, RSRC_RVA);
    put32(&mut image, at + 4, 0x100);
    image
}

fn version_blob(name: &str, file: (u16, u16, u16, u16)) -> Vec<u8> {
    VersionSpec {
        fixed: Some(fixed_info(file, file)),
        tables: vec![("040904B0", vec![string("OriginalFilename", name)])],
        translations: vec![(0x0409, 0x04b0)],
    }
    .build()
}

fn has(info: &pe::PeInfo, pred: impl Fn(&WarningKind) -> bool) -> bool {
    info.parse_warnings.iter().any(|w| pred(&w.kind))
}

// ---- RVA mapping ----------------------------------------------------------

/// A resource directory pointing at a section with no file data (`.bss`)
/// must not map to file offset 0 and parse the DOS header as a tree.
#[test]
fn resource_directory_in_virtual_only_section_is_not_mapped() {
    let mut builder = PeBuilder::default();
    builder.sections.push(SectionSpec {
        name: *b".bss\0\0\0\0",
        data: Vec::new(),
        virtual_size: Some(0x1000),
        characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    });
    let mut image = builder.build();
    let at = builder.data_directory_offset(2);
    put32(&mut image, at, 0x2000);
    put32(&mut image, at + 4, 0x10);
    let info = pe::parse(&image).unwrap();
    assert!(info.resources.is_none());
    assert!(has(&info, |k| *k
        == WarningKind::DirectoryNotMapped(DataDirectoryKind::Resource)));
    assert_eq!(info.rva_to_offset(0x2000, 0), None);
    assert_eq!(info.rva_to_offset(0x2000, 16), None);
}

/// One past the end of a section's file data is not mapped, even with a
/// zero length, and neither is one past the end of the headers.
#[test]
fn zero_length_ranges_must_start_inside() {
    let info = pe::parse(&PeBuilder::default().build()).unwrap();
    // `.text`: RVA 0x1000, 0x200 bytes of file data, mapped to 0x2000.
    assert_eq!(info.rva_to_offset(0x11ff, 0), Some(0x5ff));
    assert_eq!(info.rva_to_offset(0x11ff, 1), Some(0x5ff));
    assert_eq!(info.rva_to_offset(0x1200, 0), None);
    assert_eq!(info.rva_to_offset(0x11ff, 2), None);
    // Headers: below both SizeOfHeaders (0x400) and the first section.
    assert_eq!(info.rva_to_offset(0x3ff, 0), Some(0x3ff));
    assert_eq!(info.rva_to_offset(0x400, 0), None);
    // Inside `.text`'s mapped range but past its file data: zero-filled.
    assert!(info.section_for_rva(0x1800).is_some());
    assert_eq!(info.rva_to_offset(0x1800, 0), None);
}

/// A section whose `SizeOfRawData` runs past its aligned `VirtualSize` must
/// not shadow the next section: the loader maps the next section there.
#[test]
fn oversized_raw_data_does_not_shadow_the_next_section() {
    let version = VersionSpec {
        fixed: Some(fixed_info((2, 0, 0, 0), (2, 0, 0, 0))),
        tables: vec![("040904B0", vec![string("OriginalFilename", "real.exe")])],
        translations: vec![(0x0409, 0x04b0)],
    };
    let builder = with_version(&version);
    let mut image = builder.build();
    let honest = pe::parse(&image).unwrap();
    let rsrc_offset = honest.sections[1].pointer_to_raw_data;
    assert_eq!(honest.sections[1].virtual_address, 0x2000);

    // Make `.text` claim 0x2000 bytes of raw data. Its VirtualSize is still
    // 0x101, mapped to 0x1000, so RVA 0x2000 belongs to `.rsrc`.
    let text = builder.section_table_offset();
    put32(&mut image, text + 16, 0x2000);
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.section_for_rva(0x2000).unwrap().name, ".rsrc");
    assert_eq!(info.rva_to_offset(0x2000, 16), Some(u64::from(rsrc_offset)));
    let v = info.version_info.as_ref().unwrap();
    assert_eq!(v.get(VersionField::OriginalFileName), Some("real.exe"));
    assert_eq!(v.file_version(), Some(FileVersionQuad(2, 0, 0, 0)));
}

// ---- Version resource selection ------------------------------------------

/// A decoy RT_VERSION with name ID 0 sorts before the real ID 1, and must
/// not be the one reported.
#[test]
fn version_resource_id_1_is_preferred() {
    let builder = PeBuilder {
        resources: vec![
            Leaf {
                type_id: resource_type::VERSION,
                name_id: 0,
                lang: 0x0409,
                data: version_blob("decoy.exe", (9, 9, 9, 9)),
            },
            Leaf {
                type_id: resource_type::VERSION,
                name_id: 1,
                lang: 0x0409,
                data: version_blob("real.exe", (1, 0, 0, 0)),
            },
        ],
        ..PeBuilder::default()
    };
    let info = pe::parse(&builder.build()).unwrap();
    let res = info.resources.as_ref().unwrap();
    assert_eq!(res.version_entries.len(), 2);
    assert_eq!(res.version_entries[0].name, ResourceId::Id(0));
    assert_eq!(
        res.version_resource.as_ref().unwrap().name,
        ResourceId::Id(1)
    );
    let v = info.version_info.as_ref().unwrap();
    assert_eq!(v.get(VersionField::OriginalFileName), Some("real.exe"));
}

/// Language-neutral is preferred among ID 1 leaves, as the loader does.
#[test]
fn version_resource_prefers_neutral_language() {
    let builder = PeBuilder {
        resources: vec![
            Leaf {
                type_id: resource_type::VERSION,
                name_id: 1,
                lang: 0,
                data: version_blob("neutral.exe", (1, 0, 0, 0)),
            },
            Leaf {
                type_id: resource_type::VERSION,
                name_id: 1,
                lang: 0x0407,
                data: version_blob("german.exe", (1, 0, 0, 0)),
            },
        ],
        ..PeBuilder::default()
    };
    let v = pe::parse(&builder.build()).unwrap().version_info.unwrap();
    assert_eq!(v.get(VersionField::OriginalFileName), Some("neutral.exe"));
}

/// Without an ID 1 leaf there is no version info, and that is reported.
#[test]
fn version_resource_without_id_1_is_reported() {
    let builder = PeBuilder {
        resources: vec![Leaf {
            type_id: resource_type::VERSION,
            name_id: 7,
            lang: 0x0409,
            data: version_blob("other.exe", (1, 0, 0, 0)),
        }],
        ..PeBuilder::default()
    };
    let info = pe::parse(&builder.build()).unwrap();
    assert!(info.version_info.is_none());
    assert!(has(&info, |k| *k == WarningKind::NoStandardVersionResource));
}

/// Version block keys compare case-insensitively, as the OS version API
/// does.
#[test]
fn version_block_keys_are_case_insensitive() {
    let table = block(
        "040904B0",
        &[],
        0,
        1,
        &[string("OriginalFilename", "mixed.exe")],
    );
    let data = block(
        "vs_version_info",
        &fixed_info((3, 1, 0, 0), (3, 1, 0, 0)),
        52,
        0,
        &[block("STRINGFILEINFO", &[], 0, 1, &[table])],
    );
    let v = pe::version::parse_version_info(&data).unwrap();
    assert_eq!(v.get(VersionField::OriginalFileName), Some("mixed.exe"));
    assert_eq!(v.file_version(), Some(FileVersionQuad(3, 1, 0, 0)));
}

// ---- Resource tree shape --------------------------------------------------

/// Layout used by the hand-built trees below:
/// root (0x000), version name directory (0x100), version language directory
/// (0x200), version data entry (0x300), version blob (0x400).
fn version_tree(root_entries: &[(u32, u32)]) -> Vec<u8> {
    let blob = version_blob("tree.exe", (4, 3, 2, 1));
    let mut tree = Vec::new();
    put_dir(&mut tree, 0, 0, root_entries);
    put_dir(&mut tree, 0x100, 0, &[(1, DIR | 0x200)]);
    put_dir(&mut tree, 0x200, 0, &[(0x0409, 0x300)]);
    put_data_entry(&mut tree, 0x300, RSRC_RVA + 0x400, blob.len() as u32);
    tree.resize(0x400, 0);
    tree.extend_from_slice(&blob);
    tree
}

/// Another type pointing at RT_VERSION's subdirectory must not hide it.
#[test]
fn shared_subdirectory_does_not_hide_version() {
    let tree = version_tree(&[
        (u32::from(resource_type::ICON), DIR | 0x100),
        (u32::from(resource_type::VERSION), DIR | 0x100),
    ]);
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    let v = info.version_info.as_ref().unwrap();
    assert_eq!(v.get(VersionField::OriginalFileName), Some("tree.exe"));
    // A shared subtree is not a loop.
    assert!(!has(&info, |k| *k == WarningKind::ResourceLoop));
}

/// Exhausting the general walk's entry budget under an earlier type must
/// not hide RT_VERSION.
#[test]
fn entry_flood_does_not_hide_version() {
    let mut tree = version_tree(&[
        (u32::from(resource_type::ICON), DIR | 0x1000),
        (u32::from(resource_type::VERSION), DIR | 0x100),
    ]);
    // Type 3's name directory: 65,535 leaf entries all pointing at the
    // version data entry.
    let flood: Vec<(u32, u32)> = (0..MAX_RESOURCE_ENTRIES as u32)
        .map(|i| (i & 0xffff, 0x300))
        .collect();
    put_dir(&mut tree, 0x1000, 0, &flood);
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    assert!(has(&info, |k| *k == WarningKind::ResourceEntryLimit));
    let res = info.resources.as_ref().unwrap();
    assert_eq!(res.entry_count, MAX_RESOURCE_ENTRIES);
    assert!(!res.types.contains(&ResourceId::Id(resource_type::VERSION)));
    let v = info.version_info.as_ref().unwrap();
    assert_eq!(v.get(VersionField::OriginalFileName), Some("tree.exe"));
}

/// An ID with bits 16 to 30 set matches nothing for the OS, so it must not
/// be truncated into RT_VERSION.
#[test]
fn ids_with_high_bits_are_rejected() {
    let tree = version_tree(&[(0x0001_0010, DIR | 0x100)]);
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    assert!(info.version_info.is_none());
    assert!(has(&info, |k| *k == WarningKind::ResourceIdInvalid(0x0001_0010)));
}

/// A directory nested deeper than the limit is reported, not followed.
#[test]
fn deep_tree_is_reported() {
    let mut tree = Vec::new();
    for level in 0..6_usize {
        put_dir(
            &mut tree,
            level * 0x20,
            0,
            &[(1, DIR | ((level as u32 + 1) * 0x20))],
        );
    }
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    assert!(has(&info, |k| *k == WarningKind::ResourceTooDeep));
    assert_eq!(info.resources.unwrap().entry_count, 4);
}

/// Named entries are decoded, including under the version type.
#[test]
fn named_entries_are_decoded() {
    let mut tree = version_tree(&[
        (DIR | 0x500, DIR | 0x100),
        (u32::from(resource_type::VERSION), DIR | 0x100),
    ]);
    // A length-prefixed UTF-16 name, "PNG", after the blob.
    let name_at = tree.len().next_multiple_of(4);
    tree.resize(name_at, 0);
    tree.extend_from_slice(&3_u16.to_le_bytes());
    tree.extend("PNG".encode_utf16().flat_map(u16::to_le_bytes));
    put32(&mut tree, 16, DIR | name_at as u32);
    put16(&mut tree, 12, 1); // one named entry
    put16(&mut tree, 14, 1); // one ID entry
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    let res = info.resources.unwrap();
    assert!(res.types.contains(&ResourceId::Name("PNG".into())));
    assert!(info.version_info.is_some());
}

/// More than [`MAX_WARNINGS`] problems set the truncated flag.
#[test]
fn warning_list_is_capped() {
    let bad: Vec<(u32, u32)> = (0..400_u32).map(|i| (0x0001_0000 | i, 0x300)).collect();
    let mut tree = Vec::new();
    put_dir(&mut tree, 0, 0, &bad);
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    assert_eq!(info.parse_warnings.len(), MAX_WARNINGS);
    assert!(info.parse_warnings_truncated);
}

// ---- Certificate table and overlay ---------------------------------------

#[test]
fn half_zero_certificate_entries_are_ignored() {
    let builder = PeBuilder {
        overlay: vec![0xcc; 64],
        ..PeBuilder::default()
    };
    let clean = builder.build();
    let at = builder.data_directory_offset(4);
    let len = clean.len() as u32;
    for (offset, size) in [(len, 0), (0, 64), (0x10, 64)] {
        let mut image = clean.clone();
        put32(&mut image, at, offset);
        put32(&mut image, at + 4, size);
        let info = pe::parse(&image).unwrap();
        assert!(info.certificate_table.is_none(), "({offset:#x}, {size})");
        assert!(has(&info, |k| *k == WarningKind::CertificateTableInvalid));
        // The overlay is still found.
        assert_eq!(info.overlay.unwrap().size, 64);
    }
}

// ---- Section bounds with metadata-only parsing ----------------------------

#[test]
fn metadata_only_still_checks_section_bounds() {
    let image = PeBuilder::default().build();
    let cut = &image[..0x500];
    let info = pe::parse_with(cut, &ParseOptions::metadata_only()).unwrap();
    assert!(has(&info, |k| matches!(
        k,
        WarningKind::SectionDataOutOfFile { index: 0 }
    )));
    assert!(info.sections[0].entropy.is_none());
}

// ---- Debug directory -----------------------------------------------------

/// A CodeView record located only by RVA (file offset zero) is still read.
#[test]
fn codeview_by_rva() {
    let builder = PeBuilder {
        debug: Some(DebugSpec {
            pdb_guid: [1; 16],
            pdb_age: 5,
            pdb_path: "rva.pdb".into(),
            repro: false,
            pogo: false,
        }),
        ..PeBuilder::default()
    };
    let mut image = builder.build();
    let info = pe::parse(&image).unwrap();
    let entry = info.debug.entries[0].entry_offset as usize;
    put32(&mut image, entry + 24, 0); // PointerToRawData
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.debug.codeview.unwrap().path, "rva.pdb");
}

// ---- Loader-style lookups (round 2) ---------------------------------------

/// Writes a length-prefixed UTF-16 resource name at `at`.
fn put_name(buf: &mut Vec<u8>, at: usize, name: &str) {
    let units: Vec<u16> = name.encode_utf16().collect();
    let end = at + 2 + 2 * units.len();
    if buf.len() < end {
        buf.resize(end, 0);
    }
    put16(buf, at, units.len() as u16);
    for (i, u) in units.iter().enumerate() {
        put16(buf, at + 2 + 2 * i, *u);
    }
}

/// Writes `blob` at `at` and a data entry for it at `entry_at`.
fn put_blob(buf: &mut Vec<u8>, entry_at: usize, at: usize, blob: &[u8]) {
    if buf.len() < at + blob.len() {
        buf.resize(at + blob.len(), 0);
    }
    buf[at..at + blob.len()].copy_from_slice(blob);
    put_data_entry(buf, entry_at, RSRC_RVA + at as u32, blob.len() as u32);
}

fn original_name(info: &pe::PeInfo) -> Option<&str> {
    info.version_info
        .as_ref()?
        .get(VersionField::OriginalFileName)
}

/// More decoy names and languages than the enumeration keeps, all sorting
/// before ID 1, cannot hide the real version resource.
#[test]
fn decoys_before_id_1_do_not_hide_version() {
    let decoys = pe::MAX_KEPT_RESOURCES + 6;
    let mut tree = Vec::new();
    // Root: RT_VERSION -> 0x100.
    put_dir(
        &mut tree,
        0,
        0,
        &[(u32::from(resource_type::VERSION), DIR | 0x100)],
    );
    // Name directory: `decoys` named entries, then Id(0) and Id(1).
    let mut names: Vec<(u32, u32)> = (0..decoys).map(|_| (DIR | 0x8000, DIR | 0x9000)).collect();
    names.push((0, DIR | 0x9000));
    names.push((1, DIR | 0xa000));
    put_dir(&mut tree, 0x100, decoys as u16, &names);
    put_name(&mut tree, 0x8000, "AAA");
    // Decoy language directory: `decoys` leaves, all the decoy blob.
    let langs: Vec<(u32, u32)> = (0..decoys as u32).map(|l| (l, 0x9800)).collect();
    put_dir(&mut tree, 0x9000, 0, &langs);
    put_blob(
        &mut tree,
        0x9800,
        0xc000,
        &version_blob("decoy.exe", (9, 9, 9, 9)),
    );
    // Real: Id(1) -> 0x0409 -> real blob.
    put_dir(&mut tree, 0xa000, 0, &[(0x0409, 0xa800)]);
    put_blob(
        &mut tree,
        0xa800,
        0xe000,
        &version_blob("real.exe", (1, 2, 3, 4)),
    );

    let info = pe::parse(&image_with_tree(tree)).unwrap();
    let res = info.resources.as_ref().unwrap();
    assert_eq!(res.version_entries.len(), pe::MAX_KEPT_RESOURCES);
    assert!(
        res.version_entries
            .iter()
            .all(|e| e.name != ResourceId::Id(1))
    );
    assert_eq!(
        res.version_resource.as_ref().unwrap().name,
        ResourceId::Id(1)
    );
    assert_eq!(original_name(&info), Some("real.exe"));
}

/// A root directory with 65,535 named entries cannot starve the numeric
/// type lookup: the loader skips straight to the ID entries.
#[test]
fn named_entry_flood_at_root_does_not_hide_version() {
    let flood = u16::MAX as usize;
    let root_end = 16 + 8 * (flood + 1);
    let sub = root_end.next_multiple_of(0x100);
    let mut tree = Vec::new();
    let mut root: Vec<(u32, u32)> = (0..flood)
        .map(|_| (DIR | (sub + 0x300) as u32, DIR | (sub + 0x400) as u32))
        .collect();
    root.push((u32::from(resource_type::VERSION), DIR | sub as u32));
    put_dir(&mut tree, 0, flood as u16, &root);
    put_dir(&mut tree, sub, 0, &[(1, DIR | (sub + 0x100) as u32)]);
    put_dir(&mut tree, sub + 0x100, 0, &[(0x0409, (sub + 0x200) as u32)]);
    put_name(&mut tree, sub + 0x300, "X");
    put_dir(&mut tree, sub + 0x400, 0, &[]);
    put_blob(
        &mut tree,
        sub + 0x200,
        sub + 0x800,
        &version_blob("real.exe", (1, 0, 0, 0)),
    );

    let info = pe::parse(&image_with_tree(tree)).unwrap();
    assert!(has(&info, |k| *k == WarningKind::ResourceEntryLimit));
    assert_eq!(original_name(&info), Some("real.exe"));
}

/// A numeric ID written into a named-entry slot is not an ID entry for the
/// loader, so it must not be found by a numeric lookup.
#[test]
fn numeric_id_in_named_slot_is_not_matched() {
    let tree = {
        let mut t = version_tree(&[(u32::from(resource_type::VERSION), DIR | 0x100)]);
        put16(&mut t, 12, 1); // the only entry is counted as named
        put16(&mut t, 14, 0);
        t
    };
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    assert!(info.version_info.is_none());
    assert!(info.resources.unwrap().version_resource.is_none());
}

/// A named entry at the language level is never chosen over a numeric
/// language.
#[test]
fn named_language_is_not_chosen() {
    let mut tree = Vec::new();
    put_dir(
        &mut tree,
        0,
        0,
        &[(u32::from(resource_type::VERSION), DIR | 0x100)],
    );
    put_dir(&mut tree, 0x100, 0, &[(1, DIR | 0x200)]);
    put_dir(
        &mut tree,
        0x200,
        1,
        &[(DIR | 0x300, 0x400), (0x0409, 0x500)],
    );
    put_name(&mut tree, 0x300, "A");
    put_blob(
        &mut tree,
        0x400,
        0x1000,
        &version_blob("decoy.exe", (9, 9, 9, 9)),
    );
    put_blob(
        &mut tree,
        0x500,
        0x2000,
        &version_blob("real.exe", (1, 0, 0, 0)),
    );
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    let res = info.resources.as_ref().unwrap();
    assert_eq!(res.version_languages.len(), 1);
    assert_eq!(original_name(&info), Some("real.exe"));
}

/// Unsorted or duplicate IDs on a lookup path are flagged.
#[test]
fn unsorted_id_entries_are_flagged() {
    let tree = version_tree(&[
        (u32::from(resource_type::VERSION), DIR | 0x100),
        (u32::from(resource_type::ICON), DIR | 0x100),
    ]);
    let info = pe::parse(&image_with_tree(tree)).unwrap();
    assert!(has(&info, |k| *k == WarningKind::ResourceDirectoryNotSorted));
    assert_eq!(original_name(&info), Some("tree.exe"));

    let sorted = version_tree(&[(u32::from(resource_type::VERSION), DIR | 0x100)]);
    let info = pe::parse(&image_with_tree(sorted)).unwrap();
    assert!(!has(&info, |k| *k == WarningKind::ResourceDirectoryNotSorted));
}

/// The standard manifests (IDs 1 to 3) are found by lookup, whatever other
/// manifest entries exist.
#[test]
fn standard_manifests_are_looked_up() {
    let manifest = |name_id, body: &str| Leaf {
        type_id: resource_type::MANIFEST,
        name_id,
        lang: 0x0409,
        data: body.as_bytes().to_vec(),
    };
    let builder = PeBuilder {
        resources: vec![
            manifest(0, "<decoy/>"),
            manifest(2, "<dll/>"),
            manifest(1, "<exe/>"),
            manifest(7, "<other/>"),
        ],
        ..PeBuilder::default()
    };
    let image = builder.build();
    let info = pe::parse(&image).unwrap();
    let res = info.resources.unwrap();
    let ids: Vec<_> = res
        .standard_manifests
        .iter()
        .map(|m| m.name.clone())
        .collect();
    assert_eq!(ids, [ResourceId::Id(1), ResourceId::Id(2)]);
    assert_eq!(
        res.standard_manifests[0].bytes(&image),
        Some(&b"<exe/>"[..])
    );
    assert_eq!(res.manifest_entries.len(), 4);
}
