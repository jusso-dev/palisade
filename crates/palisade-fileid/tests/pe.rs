//! PE header, section, directory and debug parsing on synthetic images.

// Test code: fixture sizes are small constants, so narrowing casts cannot
// truncate, and helpers outside `#[test]` functions may unwrap, since a
// failure there should fail the test loudly.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

mod common;

use common::*;
use palisade_fileid::pe::{
    self, DataDirectoryKind, DllCharacteristics, Machine, PeErrorKind, PeFormat, Subsystem,
    WarningKind,
};

#[test]
fn parses_pe32_plus_headers() {
    let image = PeBuilder::default().build();
    let info = pe::parse(&image).unwrap();
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
    assert_eq!(info.e_lfanew, 0x40);
    assert_eq!(info.coff.offset, COFF_OFFSET as u64);
    assert_eq!(info.coff.machine, Machine::Amd64);
    assert_eq!(info.coff.time_date_stamp, 0x6000_0000);
    assert!(info.coff.characteristics.is_executable());
    assert!(info.coff.characteristics.is_large_address_aware());
    assert!(!info.coff.characteristics.is_dll());
    let opt = &info.optional;
    assert_eq!(opt.format, PeFormat::Pe32Plus);
    assert_eq!(opt.image_base, 0x1_4000_0000);
    assert_eq!(opt.entry_point, 0x1000);
    assert_eq!(opt.section_alignment, SECTION_ALIGNMENT);
    assert_eq!(opt.file_alignment, FILE_ALIGNMENT);
    assert_eq!(opt.size_of_headers, SIZE_OF_HEADERS);
    assert_eq!(opt.size_of_image, 0x2000);
    assert_eq!(opt.subsystem, Subsystem::WindowsGui);
    assert_eq!(opt.number_of_rva_and_sizes, 16);
    assert_eq!(opt.size_of_stack_reserve, 0x10_0000);
    assert_eq!(opt.size_of_heap_commit, 0x1000);
    assert_eq!(opt.checksum_offset, (OPT_OFFSET + 64) as u64);
    let dll = opt.dll_characteristics;
    for flag in [
        DllCharacteristics::HIGH_ENTROPY_VA,
        DllCharacteristics::DYNAMIC_BASE,
        DllCharacteristics::NX_COMPAT,
        DllCharacteristics::TERMINAL_SERVER_AWARE,
    ] {
        assert!(dll.contains(flag));
    }
    assert!(!dll.contains(DllCharacteristics::GUARD_CF));
    assert_eq!(info.data_directories.len(), 16);
    assert_eq!(info.file_size, image.len() as u64);
}

#[test]
fn parses_pe32_headers() {
    let image = PeBuilder::pe32().build();
    let info = pe::parse(&image).unwrap();
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
    assert_eq!(info.coff.machine, Machine::I386);
    assert_eq!(info.optional.format, PeFormat::Pe32);
    assert_eq!(info.optional.image_base, 0x40_0000);
    assert_eq!(info.optional.size_of_stack_reserve, 0x10_0000);
    assert_eq!(info.optional.size_of_heap_commit, 0x1000);
    assert_eq!(info.optional.number_of_rva_and_sizes, 16);
}

#[test]
fn dll_and_other_machines() {
    let info = pe::parse(&PeBuilder::dll().build()).unwrap();
    assert!(info.coff.characteristics.is_dll());
    assert_eq!(info.optional.entry_point, 0);

    for (raw, machine) in [
        (0xaa64, Machine::Arm64),
        (0xa641, Machine::Arm64Ec),
        (0x01c4, Machine::ArmNt),
        (0x3a64, Machine::ChpeX86),
    ] {
        let image = PeBuilder {
            machine: raw,
            ..PeBuilder::default()
        }
        .build();
        assert_eq!(pe::parse(&image).unwrap().coff.machine, machine);
    }

    let efi = PeBuilder {
        subsystem: 10,
        ..PeBuilder::default()
    }
    .build();
    let info = pe::parse(&efi).unwrap();
    assert_eq!(info.optional.subsystem, Subsystem::EfiApplication);
    assert!(info.optional.subsystem.is_efi());

    let native = PeBuilder {
        subsystem: 1,
        characteristics: 0x1022,
        ..PeBuilder::default()
    }
    .build();
    let info = pe::parse(&native).unwrap();
    assert_eq!(info.optional.subsystem, Subsystem::Native);
    assert!(info.coff.characteristics.is_system());
}

#[test]
fn sections_and_entropy() {
    let image = PeBuilder::default()
        .section(
            ".data",
            vec![0; 0x300],
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        )
        .section(
            ".wx",
            (0..=255).collect(),
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ,
        )
        .build();
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.sections.len(), 3);
    let text = &info.sections[0];
    assert_eq!(text.name, ".text");
    assert_eq!(&text.raw_name, b".text\0\0\0");
    assert_eq!(text.virtual_address, 0x1000);
    assert_eq!(text.pointer_to_raw_data, 0x400);
    assert_eq!(text.size_of_raw_data, 0x200);
    assert_eq!(text.header_offset, (OPT_OFFSET + 240) as u64);
    assert!(!text.is_writable_and_executable());

    let data = &info.sections[1];
    // 0x300 zero bytes: entropy exactly zero.
    assert_eq!(data.entropy, Some(0.0));
    let wx = &info.sections[2];
    assert!(wx.is_writable_and_executable());
    // 256 distinct bytes padded with 256 zeros in a 0x200-byte raw block.
    let e = wx.entropy.unwrap();
    assert!(e > 4.0 && e < 8.0, "{e}");

    assert_eq!(info.section_for_rva(0x2010).unwrap().name, ".data");
    assert!(info.section_for_rva(0x9000).is_none());
    assert_eq!(info.rva_to_offset(0x2010, 4), Some(0x600 + 0x10));
    assert_eq!(info.rva_to_offset(0x10, 4), Some(0x10)); // in the headers
    // `.data` has 0x300 bytes, rounded up to 0x400 of raw data.
    assert_eq!(info.rva_to_offset(0x23fc, 4), Some(0x600 + 0x3fc));
    assert_eq!(info.rva_to_offset(0x23fe, 4), None); // straddles the raw end
    assert_eq!(info.rva_to_offset(u32::MAX, 4), None);
}

#[test]
fn virtual_only_section_is_flagged() {
    let mut builder = PeBuilder::default();
    builder.sections.push(SectionSpec {
        name: *b".bss\0\0\0\0",
        data: Vec::new(),
        virtual_size: Some(0x10_0000),
        characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    });
    let info = pe::parse(&builder.build()).unwrap();
    let bss = &info.sections[1];
    assert!(bss.is_virtual_only());
    assert_eq!(bss.entropy, None);
    assert!(!info.sections[0].is_virtual_only());
}

#[test]
fn checksum_stored_and_computed() {
    let unset = pe::parse(&PeBuilder::default().build()).unwrap();
    assert_eq!(unset.checksum.stored, 0);
    assert!(unset.checksum.computed.is_some());
    assert!(!unset.checksum.is_valid());

    let builder = PeBuilder {
        valid_checksum: true,
        ..PeBuilder::default()
    };
    let mut image = builder.build();
    let info = pe::parse(&image).unwrap();
    assert_ne!(info.checksum.stored, 0);
    assert!(info.checksum.is_valid());

    // Changing one byte outside the checksum field invalidates it.
    let last = image.len() - 1;
    image[last] ^= 0xff;
    assert!(!pe::parse(&image).unwrap().checksum.is_valid());
}

/// The checksum of a known layout, worked out independently: a file of
/// `MZ`, zeros, and a final byte.
#[test]
fn checksum_matches_reference_algorithm() {
    let mut data = vec![0_u8; 0x80];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x7f] = 0x01;
    // Words: 0x5a4d + 0x0100 = 0x5b4d, plus length 0x80.
    assert_eq!(pe::compute_checksum(&data, 0x40), Some(0x5b4d + 0x80));
}

#[test]
fn certificate_table_and_overlay() {
    let builder = PeBuilder {
        certificate: Some(vec![0xab; 24]),
        overlay: b"appended installer payload".to_vec(),
        ..PeBuilder::default()
    };
    let image = builder.build();
    let info = pe::parse(&image).unwrap();
    let cert = info.certificate_table.unwrap();
    assert_eq!(cert.size, 24);
    assert_eq!(cert.offset, 0x600);
    let sec = info.data_directory(DataDirectoryKind::Security).unwrap();
    assert_eq!(u64::from(sec.virtual_address), cert.offset);
    assert_eq!(sec.entry_offset, builder.data_directory_offset(4) as u64);
    let overlay = info.overlay.unwrap();
    assert_eq!(overlay.offset, cert.offset + cert.size);
    assert_eq!(overlay.size, 26);

    let plain = pe::parse(&PeBuilder::default().build()).unwrap();
    assert!(plain.certificate_table.is_none());
    assert!(plain.overlay.is_none());
}

#[test]
fn certificate_table_outside_file_is_a_warning() {
    let builder = PeBuilder::default();
    let mut image = builder.build();
    let at = builder.data_directory_offset(4);
    image[at..at + 4].copy_from_slice(&0x7000_0000_u32.to_le_bytes());
    image[at + 4..at + 8].copy_from_slice(&0x100_u32.to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert!(info.certificate_table.is_none());
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::CertificateTableOutOfFile)
    );
}

#[test]
fn debug_directory_codeview_repro_pogo() {
    let guid = [
        0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let builder = PeBuilder {
        debug: Some(DebugSpec {
            pdb_guid: guid,
            pdb_age: 3,
            pdb_path: "D:\\work\\out\\tool.pdb".into(),
            repro: true,
            pogo: true,
        }),
        ..PeBuilder::default()
    };
    let info = pe::parse(&builder.build()).unwrap();
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
    assert_eq!(info.debug.entries.len(), 3);
    assert!(info.debug.has_repro);
    assert!(info.timestamp_is_reproducible());
    assert!(info.debug.has_pogo);
    let pdb = info.debug.codeview.unwrap();
    assert_eq!(pdb.age, 3);
    assert_eq!(pdb.path, "D:\\work\\out\\tool.pdb");
    assert_eq!(pdb.guid_string(), "{01234567-89AB-CDEF-0123-456789ABCDEF}");

    let no_repro = PeBuilder {
        debug: Some(DebugSpec {
            pdb_guid: guid,
            pdb_age: 1,
            pdb_path: "x.pdb".into(),
            repro: false,
            pogo: false,
        }),
        ..PeBuilder::default()
    };
    let info = pe::parse(&no_repro.build()).unwrap();
    assert!(!info.timestamp_is_reproducible());
    assert_eq!(info.debug.entries.len(), 1);
}

#[test]
fn unmapped_directory_is_a_warning() {
    let builder = PeBuilder::default();
    let mut image = builder.build();
    let at = builder.data_directory_offset(6);
    image[at..at + 4].copy_from_slice(&0x0080_0000_u32.to_le_bytes());
    image[at + 4..at + 8].copy_from_slice(&28_u32.to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::DirectoryNotMapped(DataDirectoryKind::Debug))
    );
    assert!(info.debug.entries.is_empty());
}

#[test]
fn fatal_errors_carry_offsets() {
    let err = |data: &[u8]| pe::parse(data).unwrap_err();
    assert_eq!(err(&[]).kind, PeErrorKind::TooSmall);
    assert_eq!(err(&[0; 64]).kind, PeErrorKind::NoDosSignature);

    let good = PeBuilder::default().build();

    let mut bad = good.clone();
    bad[0x3c..0x40].copy_from_slice(&(pe::MAX_E_LFANEW + 4).to_le_bytes());
    let e = err(&bad);
    assert_eq!(e.kind, PeErrorKind::LfanewOutOfRange(pe::MAX_E_LFANEW + 4));
    assert_eq!(e.offset, 0x3c);

    // No room for the PE signature.
    let mut bad = good.clone();
    bad[0x3c..0x40].copy_from_slice(&(good.len() as u32 - 2).to_le_bytes());
    assert!(matches!(err(&bad).kind, PeErrorKind::LfanewOutOfRange(_)));

    // A PE signature followed by a cut-off COFF header.
    let e = err(&good[..COFF_OFFSET + 10]);
    assert_eq!(
        (e.kind, e.offset),
        (PeErrorKind::TruncatedCoffHeader, COFF_OFFSET as u64)
    );

    let mut bad = good.clone();
    bad[E_LFANEW] = b'X';
    let e = err(&bad);
    assert_eq!((e.kind, e.offset), (PeErrorKind::NoPeSignature, 0x40));

    let mut bad = good.clone();
    bad[OPT_OFFSET..OPT_OFFSET + 2].copy_from_slice(&0x0107_u16.to_le_bytes());
    let e = err(&bad);
    assert_eq!(e.kind, PeErrorKind::UnknownOptionalHeaderMagic(0x107));
    assert_eq!(e.offset, OPT_OFFSET as u64);

    let mut bad = good.clone();
    bad[COFF_OFFSET + 16..COFF_OFFSET + 18].copy_from_slice(&50_u16.to_le_bytes());
    assert_eq!(err(&bad).kind, PeErrorKind::OptionalHeaderTooSmall(50));

    assert_eq!(
        err(&good[..OPT_OFFSET + 50]).kind,
        PeErrorKind::TruncatedOptionalHeader
    );
    assert!(!err(&good[..OPT_OFFSET + 50]).to_string().is_empty());
}

#[test]
fn e_lfanew_at_the_limit_is_accepted() {
    // Place the PE headers exactly at MAX_E_LFANEW by padding the DOS stub.
    let good = PeBuilder::default().build();
    let shift = pe::MAX_E_LFANEW as usize - E_LFANEW;
    let mut image = good[..E_LFANEW].to_vec();
    image.resize(pe::MAX_E_LFANEW as usize, 0);
    image.extend_from_slice(&good[E_LFANEW..]);
    image[0x3c..0x40].copy_from_slice(&pe::MAX_E_LFANEW.to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.e_lfanew, pe::MAX_E_LFANEW);
    assert_eq!(info.coff.machine, Machine::Amd64);
    // The section table moved too, but raw pointers did not, so sections now
    // point into the padding. That is still parsed without failing.
    assert_eq!(info.sections.len(), 1);
    assert!(shift > 0);
}

#[test]
fn truncated_section_table_is_partial() {
    let builder = PeBuilder::default();
    let mut image = builder.build();
    // Declare 200 sections; only one header exists, and the rest of the
    // 0x400-byte header area is zeros, so 15 more (empty) headers fit before
    // the raw data starts and the file holds more past that.
    image[COFF_OFFSET + 2..COFF_OFFSET + 4].copy_from_slice(&200_u16.to_le_bytes());
    let table = builder.section_table_offset();
    let cut = table + 40 * 3 + 7;
    let info = pe::parse(&image[..cut]).unwrap();
    assert_eq!(info.sections.len(), 3);
    assert!(info.parse_warnings.iter().any(|w| matches!(
        w.kind,
        WarningKind::SectionTableTruncated {
            declared: 200,
            parsed: 3
        }
    )));
    // The first section's raw data is gone too.
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| matches!(w.kind, WarningKind::SectionDataOutOfFile { index: 0 }))
    );
}

#[test]
fn data_directory_count_is_capped_and_checked() {
    let builder = PeBuilder::default();
    let mut image = builder.build();
    let count_at = OPT_OFFSET + 108;
    image[count_at..count_at + 4].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.data_directories.len(), 16);
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::TooManyDataDirectories(0xffff_ffff))
    );

    // Fewer directories than 16: only those are read.
    image[count_at..count_at + 4].copy_from_slice(&3_u32.to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.data_directories.len(), 3);
    assert!(info.data_directory(DataDirectoryKind::Debug).is_none());

    // SizeOfOptionalHeader too small for 16 directories.
    image[count_at..count_at + 4].copy_from_slice(&16_u32.to_le_bytes());
    image[COFF_OFFSET + 16..COFF_OFFSET + 18].copy_from_slice(&(112_u16 + 8 * 4).to_le_bytes());
    let info = pe::parse(&image).unwrap();
    assert_eq!(info.data_directories.len(), 4);
    assert!(info.parse_warnings.iter().any(|w| matches!(
        w.kind,
        WarningKind::DataDirectoriesTruncated {
            declared: 16,
            parsed: 4
        }
    )));
}

#[test]
fn huge_section_count_does_not_allocate_from_header() {
    let mut image = PeBuilder::default().build();
    image[COFF_OFFSET + 2..COFF_OFFSET + 4].copy_from_slice(&u16::MAX.to_le_bytes());
    let info = pe::parse(&image).unwrap();
    // Bounded by what fits in the file, not by the declared count.
    assert!(info.sections.len() <= image.len() / 40);
    assert!(info.parse_warnings.len() <= pe::MAX_WARNINGS);
}

#[test]
fn metadata_only_skips_whole_file_scans() {
    let builder = PeBuilder {
        valid_checksum: true,
        ..PeBuilder::default()
    };
    let image = builder.build();
    let full = pe::parse(&image).unwrap();
    assert!(full.checksum.is_valid());
    assert!(full.sections[0].entropy.is_some());

    let quick = pe::parse_with(&image, &pe::ParseOptions::metadata_only()).unwrap();
    assert_eq!(quick.checksum.stored, full.checksum.stored);
    assert_eq!(quick.checksum.computed, None);
    assert!(quick.sections[0].entropy.is_none());
    assert!(quick.parse_warnings.is_empty());
    assert_eq!(quick.coff, full.coff);
    assert_eq!(quick.optional, full.optional);
}
