//! The NE, LE and LX identity reader (#45): module name and description
//! from synthetic images, and no panic or out-of-bounds result on any
//! mutation of them.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use palisade_fileid::pe::legacy::{
    self, LegacyError, LegacyFormat, LegacyWarning, NameKind, TargetOs,
};
use proptest::prelude::*;

const E_LFANEW: usize = 0x80;

fn put16(d: &mut [u8], at: usize, v: u16) {
    d[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(d: &mut [u8], at: usize, v: u32) {
    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// A name table with one entry and its terminator.
fn table(name: &[u8]) -> Vec<u8> {
    let mut t = vec![name.len() as u8];
    t.extend_from_slice(name);
    t.extend_from_slice(&[0, 0, 0]);
    t
}

fn dos(len: usize) -> Vec<u8> {
    let mut d = vec![0_u8; len];
    d[..2].copy_from_slice(b"MZ");
    put32(&mut d, 0x3c, E_LFANEW as u32);
    d
}

/// An NE image named `name`, described by `description`.
fn ne(name: &[u8], description: &[u8]) -> Vec<u8> {
    let resident = table(name);
    let non_resident = table(description);
    let res_at = E_LFANEW + 0x40;
    let non_at = res_at + resident.len();
    let mut d = dos(non_at + non_resident.len());
    d[E_LFANEW..E_LFANEW + 2].copy_from_slice(b"NE");
    d[E_LFANEW + 0x36] = 2;
    put16(&mut d, E_LFANEW + 0x20, non_resident.len() as u16);
    put16(&mut d, E_LFANEW + 0x26, 0x40);
    put32(&mut d, E_LFANEW + 0x2c, non_at as u32);
    d[res_at..non_at].copy_from_slice(&resident);
    d[non_at..].copy_from_slice(&non_resident);
    d
}

/// An LE or LX image.
fn lx(signature: &[u8; 2], name: &[u8], description: &[u8]) -> Vec<u8> {
    let resident = table(name);
    let non_resident = table(description);
    let res_at = E_LFANEW + 0x90;
    let non_at = res_at + resident.len();
    let mut d = dos(non_at + non_resident.len());
    d[E_LFANEW..E_LFANEW + 2].copy_from_slice(signature);
    put16(&mut d, E_LFANEW + 0x0a, 4);
    put32(&mut d, E_LFANEW + 0x58, 0x90);
    put32(&mut d, E_LFANEW + 0x88, non_at as u32);
    put32(&mut d, E_LFANEW + 0x8c, non_resident.len() as u32);
    d[res_at..non_at].copy_from_slice(&resident);
    d[non_at..].copy_from_slice(&non_resident);
    d
}

fn seeds() -> Vec<Vec<u8>> {
    vec![
        ne(b"SAMPLE", b"Sample 16-bit library"),
        lx(b"LE", b"SAMPLED", b"Sample virtual device"),
        lx(b"LX", b"SAMPLE32", b"Sample linear module"),
    ]
}

#[test]
fn ne_module_name_and_description() {
    let info = legacy::parse(&ne(b"SAMPLE", b"Sample  16-bit library")).unwrap();
    assert_eq!(info.format, LegacyFormat::Ne);
    assert_eq!(info.target_os, Some(TargetOs::Windows));
    let name = info.module_name.unwrap();
    assert_eq!(name.text, "SAMPLE");
    assert_eq!(name.offset, (E_LFANEW + 0x40) as u64);
    assert!(name.normalized.matches("sample"));
    let d = info.description.unwrap();
    assert_eq!(d.normalized.normalized(), "Sample 16-bit library");
    assert!(info.warnings.is_empty());
}

#[test]
fn le_and_lx_module_name_and_description() {
    for (sig, format) in [(b"LE", LegacyFormat::Le), (b"LX", LegacyFormat::Lx)] {
        let info = legacy::parse(&lx(sig, b"SAMPLED", b"Sample driver")).unwrap();
        assert_eq!(info.format, format);
        assert_eq!(info.target_os, Some(TargetOs::Win386));
        assert_eq!(info.module_name.unwrap().text, "SAMPLED");
        assert_eq!(info.description.unwrap().text, "Sample driver");
        assert!(info.warnings.is_empty());
    }
}

#[test]
fn non_ascii_bytes_are_replaced_and_flagged() {
    let info = legacy::parse(&ne(b"CAF\xc9", b"ok")).unwrap();
    let name = info.module_name.unwrap();
    assert_eq!(name.text, "CAF\u{FFFD}");
    assert!(name.non_ascii);
    assert_eq!(name.raw, b"CAF\xc9");
    assert!(!info.description.unwrap().non_ascii);
}

#[test]
fn empty_tables_mean_absent_names() {
    let info = legacy::parse(&ne(b"", b"")).unwrap();
    assert_eq!(info.module_name, None);
    assert_eq!(info.description, None);
    assert!(info.warnings.is_empty());
}

#[test]
fn unreadable_names_are_absent_with_a_warning() {
    // The description runs past the end of the file.
    let mut d = ne(b"SAMPLE", b"Sample library");
    d.truncate(d.len() - 6);
    let info = legacy::parse(&d).unwrap();
    assert_eq!(info.module_name.unwrap().text, "SAMPLE");
    assert_eq!(info.description, None);
    assert_eq!(
        info.warnings,
        [LegacyWarning::NameTruncated(NameKind::Description)]
    );
    // The declared table is shorter than its first name.
    let mut d = ne(b"SAMPLE", b"Sample library");
    put16(&mut d, E_LFANEW + 0x20, 4);
    let info = legacy::parse(&d).unwrap();
    assert_eq!(info.description, None);
    assert_eq!(
        info.warnings,
        [LegacyWarning::NameOutsideTable(NameKind::Description)]
    );
    // The resident table starts outside the file.
    let mut d = ne(b"SAMPLE", b"x");
    put16(&mut d, E_LFANEW + 0x26, 0xfff0);
    let info = legacy::parse(&d).unwrap();
    assert_eq!(info.module_name, None);
    assert_eq!(
        info.warnings,
        [LegacyWarning::TableOutOfBounds(NameKind::ModuleName)]
    );
}

#[test]
fn a_truncated_header_gives_the_format_only() {
    let mut d = ne(b"SAMPLE", b"x");
    d.truncate(E_LFANEW + 0x10);
    let info = legacy::parse(&d).unwrap();
    assert_eq!(info.format, LegacyFormat::Ne);
    assert_eq!(info.target_os, None);
    assert_eq!(info.module_name, None);
    assert_eq!(info.warnings, [LegacyWarning::HeaderTruncated]);
}

#[test]
fn big_endian_linear_headers_are_not_read() {
    let mut d = lx(b"LX", b"SAMPLE", b"x");
    d[E_LFANEW + 2] = 1;
    let info = legacy::parse(&d).unwrap();
    assert_eq!(info.module_name, None);
    assert_eq!(info.warnings, [LegacyWarning::BigEndian]);
}

#[test]
fn other_files_are_rejected() {
    assert_eq!(legacy::parse(b"MZ"), Err(LegacyError::TooSmall));
    assert_eq!(legacy::parse(&[0; 64]), Err(LegacyError::NoDosSignature));
    let mut d = dos(0x100);
    d[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");
    assert_eq!(legacy::parse(&d), Err(LegacyError::NoSignature));
    let mut d = dos(0x40);
    put32(&mut d, 0x3c, 0x200);
    assert_eq!(legacy::parse(&d), Err(LegacyError::LfanewOutOfRange(0x200)));
    put32(&mut d, 0x3c, u32::MAX);
    assert_eq!(
        legacy::parse(&d),
        Err(LegacyError::LfanewOutOfRange(u32::MAX))
    );
}

/// Every name reported lies inside the input, at its recorded offset.
fn check(data: &[u8]) {
    let Ok(info) = legacy::parse(data) else {
        return;
    };
    assert!(info.warnings.len() <= 2);
    for n in [&info.module_name, &info.description].into_iter().flatten() {
        let at = usize::try_from(n.offset).unwrap();
        assert_eq!(usize::from(data[at]), n.raw.len());
        assert_eq!(&data[at + 1..at + 1 + n.raw.len()], n.raw.as_slice());
        assert_eq!(n.text.chars().count(), n.raw.len());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn mutated_images_never_panic(
        seed in 0usize..3,
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..16),
        cut in any::<usize>(),
    ) {
        let mut data = seeds()[seed].clone();
        let len = data.len();
        for (at, value) in edits {
            data[at % len] = value;
        }
        data.truncate(cut % (len + 1));
        check(&data);
    }

    #[test]
    fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        check(&data);
    }
}

/// Writes the seeds as a fuzz corpus. Run with
/// `PALISADE_FUZZ_SEED_DIR=<dir> cargo test --test legacy -- --ignored`.
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_legacy_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    for (i, seed) in seeds().iter().enumerate() {
        std::fs::write(
            std::path::Path::new(&dir).join(format!("seed-legacy-{i}")),
            seed,
        )
        .unwrap();
    }
}
