//! Resource tree and version resource parsing on synthetic images.

// Test code: fixture sizes are small constants, so narrowing casts cannot
// truncate, and helpers outside `#[test]` functions may unwrap, since a
// failure there should fail the test loudly.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

mod common;

use common::*;
use palisade_fileid::pe::version::{
    self, FileVersionQuad, LanguageSelection, VersionField, VersionIssueKind,
};
use palisade_fileid::pe::{self, ResourceId, WarningKind, resource_type};

fn standard() -> VersionSpec<'static> {
    VersionSpec {
        fixed: Some(fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![("040904B0", all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    }
}

#[test]
fn extracts_every_standard_field() {
    let image = with_version(&standard()).build();
    let info = pe::parse(&image).unwrap();
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
    let v = info.version_info.unwrap();
    assert!(v.issues.is_empty(), "{:?}", v.issues);
    let expect = [
        (VersionField::OriginalFileName, "extool.exe"),
        (VersionField::InternalName, "extool"),
        (VersionField::FileDescription, "Example tool"),
        (VersionField::ProductName, "Example Suite"),
        (VersionField::CompanyName, "Example Org"),
        (VersionField::FileVersion, "1.2.3.4"),
        (VersionField::ProductVersion, "1.2.0.0"),
        (VersionField::LegalCopyright, "(c) Example Org"),
        (VersionField::LegalTrademarks, "None"),
        (VersionField::Comments, "Synthetic test fixture"),
        (VersionField::PrivateBuild, "pb-7"),
        (VersionField::SpecialBuild, "sb-9"),
    ];
    assert_eq!(expect.len(), VersionField::ALL.len());
    for (field, value) in expect {
        assert_eq!(v.get(field), Some(value), "{field:?}");
    }
    let fixed = v.fixed.unwrap();
    assert_eq!(fixed.file_version, FileVersionQuad(1, 2, 3, 4));
    assert_eq!(fixed.product_version, FileVersionQuad(1, 2, 0, 0));
    assert_eq!(fixed.file_os, 0x0004_0004);
    assert_eq!(fixed.file_type, 1);
    assert_eq!(fixed.file_flags_mask, 0x3f);
    assert_eq!(v.file_version(), Some(FileVersionQuad(1, 2, 3, 4)));
    assert_eq!(v.product_version(), Some(FileVersionQuad(1, 2, 0, 0)));
    assert!(!v.file_version_mismatch());
    assert!(!v.product_version_mismatch());
    assert_eq!(v.selection, Some(LanguageSelection::Translation));
    assert_eq!(v.translations.len(), 1);
    let table = v.selected_table().unwrap();
    assert_eq!(table.key, "040904B0");
    assert_eq!(table.translation.unwrap().language, 0x0409);
}

#[test]
fn resource_summary() {
    let mut builder = with_version(&standard());
    builder.resources.push(Leaf {
        type_id: resource_type::MANIFEST,
        name_id: 1,
        lang: 0x0409,
        data: b"<assembly/>".to_vec(),
    });
    builder.resources.push(Leaf {
        type_id: resource_type::GROUP_ICON,
        name_id: 1,
        lang: 0x0407,
        data: vec![0; 20],
    });
    let image = builder.build();
    let info = pe::parse(&image).unwrap();
    let res = info.resources.unwrap();
    assert!(res.has_icons);
    assert_eq!(res.manifest_entries.len(), 1);
    assert_eq!(
        res.manifest_entries[0].bytes(&image),
        Some(&b"<assembly/>"[..])
    );
    assert_eq!(res.version_entries.len(), 1);
    assert_eq!(
        res.languages.iter().copied().collect::<Vec<_>>(),
        [0x0407, 0x0409]
    );
    assert!(res.types.contains(&ResourceId::Id(resource_type::VERSION)));
    // 3 types + 3 names + 3 languages.
    assert_eq!(res.entry_count, 9);

    let none = pe::parse(&PeBuilder::default().build()).unwrap();
    assert!(none.resources.is_none());
    assert!(none.version_info.is_none());
}

#[test]
fn string_version_disagreeing_with_fixed_info_is_flagged() {
    let spec = VersionSpec {
        fixed: Some(fixed_info((10, 0, 19041, 1), (10, 0, 19041, 1))),
        tables: vec![(
            "040904B0",
            vec![
                string("FileVersion", "10.0.19041.2 (release.200101-1200)"),
                string("ProductVersion", "10.0.19041.1"),
            ],
        )],
        translations: vec![],
    };
    let v = pe::parse(&with_version(&spec).build())
        .unwrap()
        .version_info
        .unwrap();
    // The fixed info wins.
    assert_eq!(v.file_version(), Some(FileVersionQuad(10, 0, 19041, 1)));
    assert!(v.file_version_mismatch());
    assert!(!v.product_version_mismatch());
    // The string is kept as is.
    assert_eq!(
        v.get(VersionField::FileVersion),
        Some("10.0.19041.2 (release.200101-1200)")
    );
}

#[test]
fn version_falls_back_to_string_without_fixed_info() {
    let spec = VersionSpec {
        fixed: None,
        tables: vec![(
            "040904B0",
            vec![string("FileVersion", "5, 812, 10240, 16384")],
        )],
        translations: vec![],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert!(v.fixed.is_none());
    assert_eq!(
        v.file_version(),
        Some(FileVersionQuad(5, 812, 10240, 16384))
    );
    assert!(!v.file_version_mismatch());
    assert_eq!(v.product_version(), None);
}

#[test]
fn language_selection_order() {
    let german = ("040704B0", vec![string("ProductName", "Beispiel")]);
    let english = ("040904B0", vec![string("ProductName", "Example")]);
    let french = ("040C04E4", vec![string("ProductName", "Exemple")]);

    // Translation match wins over English.
    let spec = VersionSpec {
        fixed: None,
        tables: vec![german.clone(), english.clone(), french.clone()],
        translations: vec![(0x040c, 0x04e4)],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert_eq!(v.selection, Some(LanguageSelection::Translation));
    assert_eq!(v.get(VersionField::ProductName), Some("Exemple"));
    assert_eq!(v.all_langs.len(), 3);

    // Missing Translation: English Unicode.
    let spec = VersionSpec {
        fixed: None,
        tables: vec![german.clone(), english.clone()],
        translations: vec![],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert_eq!(v.selection, Some(LanguageSelection::EnglishUnicode));
    assert_eq!(v.get(VersionField::ProductName), Some("Example"));

    // A Translation that matches nothing still falls through to English.
    let spec = VersionSpec {
        fixed: None,
        tables: vec![german.clone(), english],
        translations: vec![(0x0411, 0x04b0)],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert_eq!(v.selection, Some(LanguageSelection::EnglishUnicode));

    // Otherwise the first block.
    let spec = VersionSpec {
        fixed: None,
        tables: vec![french, german],
        translations: vec![],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert_eq!(v.selection, Some(LanguageSelection::First));
    assert_eq!(v.get(VersionField::ProductName), Some("Exemple"));

    // No string tables at all.
    let spec = VersionSpec {
        fixed: Some(fixed_info((1, 0, 0, 0), (1, 0, 0, 0))),
        tables: vec![],
        translations: vec![(0x0409, 0x04b0)],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert_eq!((v.selected, v.selection), (None, None));
    assert_eq!(v.get(VersionField::ProductName), None);
    assert_eq!(v.effective_file_name(VersionField::OriginalFileName), None);
}

#[test]
fn effective_file_name_fallback_chain() {
    let build = |strings: Vec<Vec<u8>>| {
        version::parse_version_info(
            &VersionSpec {
                fixed: None,
                tables: vec![("040904B0", strings)],
                translations: vec![],
            }
            .build(),
        )
        .unwrap()
    };
    let full = build(all_standard_strings());
    let name = full
        .effective_file_name(VersionField::OriginalFileName)
        .unwrap();
    assert_eq!(
        (name.field, name.value),
        (VersionField::OriginalFileName, "extool.exe")
    );
    // Starting lower in the chain skips the earlier fields.
    let name = full
        .effective_file_name(VersionField::FileDescription)
        .unwrap();
    assert_eq!(name.field, VersionField::FileDescription);
    // A field outside the chain is not a level.
    assert_eq!(full.effective_file_name(VersionField::CompanyName), None);

    // Empty and whitespace-only values are skipped.
    let partial = build(vec![
        string("OriginalFilename", ""),
        string("InternalName", "   "),
        string("ProductName", "Example Suite"),
    ]);
    let name = partial
        .effective_file_name(VersionField::OriginalFileName)
        .unwrap();
    assert_eq!(
        (name.field, name.value),
        (VersionField::ProductName, "Example Suite")
    );

    let nothing = build(vec![string("CompanyName", "Example Org")]);
    assert_eq!(
        nothing.effective_file_name(VersionField::OriginalFileName),
        None
    );
}

#[test]
fn nul_padding_and_odd_value_lengths() {
    let units = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    let mut padded = units("extool.exe");
    padded.extend([0, 0, 0, 0]);
    let mut no_nul = units("Example");
    no_nul.truncate(7);
    let spec = VersionSpec {
        fixed: None,
        tables: vec![(
            "040904B0",
            vec![
                string_raw("OriginalFilename", &padded),
                string_raw("ProductName", &no_nul),
                string_raw("Comments", &[]),
            ],
        )],
        translations: vec![],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert_eq!(v.get(VersionField::OriginalFileName), Some("extool.exe"));
    assert_eq!(v.get(VersionField::ProductName), Some("Example"));
    assert_eq!(v.get(VersionField::Comments), Some(""));
    // Lookup is ASCII case-insensitive, like the OS.
    let table = v.selected_table().unwrap();
    assert_eq!(table.get("originalfilename"), Some("extool.exe"));
}

#[test]
fn non_ascii_values_are_preserved() {
    let spec = VersionSpec {
        fixed: None,
        tables: vec![("041104B0", vec![string("ProductName", "製品 Ünïcode ✓")])],
        translations: vec![(0x0411, 0x04b0)],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert_eq!(v.get(VersionField::ProductName), Some("製品 Ünïcode ✓"));
}

#[test]
fn malformed_version_resources() {
    // Wrong root key.
    let bad_root = block("VS_VERSION_INFX", &[], 0, 0, &[]);
    let err = version::parse_version_info(&bad_root).unwrap_err();
    assert_eq!(
        err.kind,
        VersionIssueKind::BadRootKey("VS_VERSION_INFX".into())
    );

    // A fixed info with a wrong signature is ignored, not fatal.
    let mut fixed = fixed_info((1, 0, 0, 0), (1, 0, 0, 0));
    fixed[0] = 0;
    let spec = VersionSpec {
        fixed: Some(fixed),
        tables: vec![("040904B0", vec![string("ProductName", "X")])],
        translations: vec![],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert!(v.fixed.is_none());
    assert!(
        v.issues
            .iter()
            .any(|i| i.kind == VersionIssueKind::BadFixedInfo)
    );
    assert_eq!(v.get(VersionField::ProductName), Some("X"));

    // A bad string table key is reported but the strings are kept.
    let spec = VersionSpec {
        fixed: None,
        tables: vec![("english", vec![string("ProductName", "X")])],
        translations: vec![],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert!(
        v.issues
            .iter()
            .any(|i| i.kind == VersionIssueKind::BadStringTableKey("english".into()))
    );
    assert_eq!(v.get(VersionField::ProductName), Some("X"));

    // A child whose length overruns its parent is cut to the parent, and
    // reported at the child. The root's own length stays valid.
    let mut data = standard().build();
    let total = data.len();
    let root_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    assert_eq!(root_len, total);
    // The root's children start after its 52-byte fixed info.
    let key = "VS_VERSION_INFO".encode_utf16().count() * 2 + 2;
    let child = (6 + key).next_multiple_of(4) + 52;
    let child = child.next_multiple_of(4);
    let child_key: Vec<u8> = "StringFileInfo"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(
        &data[child + 6..child + 6 + child_key.len()],
        &child_key[..]
    );
    let child_len = u16::from_le_bytes([data[child], data[child + 1]]) as usize;
    data[child..child + 2].copy_from_slice(&((child_len + 0x200) as u16).to_le_bytes());
    let v = version::parse_version_info(&data).unwrap();
    let overruns: Vec<_> = v
        .issues
        .iter()
        .filter(|i| i.kind == VersionIssueKind::BlockOverrun)
        .collect();
    assert_eq!(overruns.len(), 1);
    assert_eq!(overruns[0].offset, child as u64);
    assert_eq!(v.get(VersionField::OriginalFileName), Some("extool.exe"));

    // Every truncation point parses or fails without panicking.
    let data = standard().build();
    for cut in 0..data.len() {
        let _ = version::parse_version_info(&data[..cut]);
    }
}

#[test]
fn string_table_count_is_capped() {
    let tables: Vec<(&str, Vec<Vec<u8>>)> = (0..version::MAX_STRING_TABLES + 5)
        .map(|_| ("040904B0", vec![string("ProductName", "X")]))
        .collect();
    let spec = VersionSpec {
        fixed: None,
        tables,
        translations: vec![],
    };
    let v = version::parse_version_info(&spec.build()).unwrap();
    assert_eq!(v.all_langs.len(), version::MAX_STRING_TABLES);
    assert!(
        v.issues
            .iter()
            .any(|i| i.kind == VersionIssueKind::TooManyStringTables)
    );
}

#[test]
fn bad_version_resource_in_image_is_a_warning() {
    let builder = PeBuilder {
        resources: vec![Leaf {
            type_id: resource_type::VERSION,
            name_id: 1,
            lang: 0x0409,
            data: block("NOT_VERSION", &[], 0, 0, &[]),
        }],
        ..PeBuilder::default()
    };
    let info = pe::parse(&builder.build()).unwrap();
    assert!(info.version_info.is_none());
    assert!(info.parse_warnings
        .iter()
        .any(|w| matches!(&w.kind, WarningKind::VersionInfo(i) if matches!(i.kind, VersionIssueKind::BadRootKey(_)))));
}

#[test]
fn resource_loop_is_walked_once() {
    let builder = with_version(&standard());
    let mut image = builder.build();
    let info = pe::parse(&image).unwrap();
    let rsrc = info.sections.iter().find(|s| s.name == ".rsrc").unwrap();
    let root = rsrc.pointer_to_raw_data as usize;
    // Point the root's only entry back at the root directory itself.
    image[root + 20..root + 24].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ResourceLoop)
    );
    assert!(info.version_info.is_none());
}

#[test]
fn resource_entry_out_of_bounds_is_a_warning() {
    let builder = with_version(&standard());
    let mut image = builder.build();
    let info = pe::parse(&image).unwrap();
    let rsrc = info.sections.iter().find(|s| s.name == ".rsrc").unwrap();
    let root = rsrc.pointer_to_raw_data as usize;
    // Claim 0xffff ID entries in the root directory.
    image[root + 14..root + 16].copy_from_slice(&0xffff_u16.to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert!(!info.parse_warnings.is_empty());
    assert!(info.resources.is_some());
}
