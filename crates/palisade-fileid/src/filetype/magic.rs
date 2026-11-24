//! The fixed magic numbers: a small hand-written table, for auditability.

#![forbid(unsafe_code)]

use super::FileKind;
use crate::pe::read::{bytes, u16_at, u32_at};

/// Builds the on-disk (mixed-endian) byte layout of a GUID.
pub(super) const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

/// The shell link CLSID `{00021401-0000-0000-C000-000000000046}`.
const SHELL_LINK_CLSID: [u8; 16] = guid(0x0002_1401, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);

/// Magic numbers at offset 0 that identify a kind on their own.
const PREFIXES: &[(&[u8], FileKind)] = &[
    // Cabinet: `MSCF` and a zero reserved field.
    (b"MSCF\0\0\0\0", FileKind::Cab),
    // Compiled HTML help: `ITSF`, then the version (3, or 2 in early
    // files) as a 32-bit little-endian word.
    (b"ITSF\x03\0\0\0", FileKind::Chm),
    (b"ITSF\x02\0\0\0", FileKind::Chm),
    (&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], FileKind::SevenZip),
    // RAR 4 and RAR 5.
    (b"Rar!\x1a\x07\x00", FileKind::Rar),
    (b"Rar!\x1a\x07\x01\x00", FileKind::Rar),
    // gzip with the deflate method, the only one defined.
    (&[0x1f, 0x8b, 0x08], FileKind::Gzip),
    (&[0x7f, b'E', b'L', b'F'], FileKind::Elf),
    // Mach-O: 32- and 64-bit, both byte orders.
    (&[0xfe, 0xed, 0xfa, 0xce], FileKind::MachO),
    (&[0xfe, 0xed, 0xfa, 0xcf], FileKind::MachO),
    (&[0xce, 0xfa, 0xed, 0xfe], FileKind::MachO),
    (&[0xcf, 0xfa, 0xed, 0xfe], FileKind::MachO),
];

/// The most architectures a Mach-O fat header is taken to have. The fat
/// magic `CA FE BA BE` is shared with Java class files, whose next four
/// bytes (minor and major version, big-endian) are at least 45, so a small
/// count means a fat binary.
const MAX_FAT_ARCHS: u32 = 30;

/// The kind identified by a fixed magic number, if any.
pub(super) fn fixed(head: &[u8]) -> Option<FileKind> {
    if let Some((_, kind)) = PREFIXES.iter().find(|(magic, _)| head.starts_with(magic)) {
        return Some(*kind);
    }
    if is_lnk(head) {
        return Some(FileKind::Lnk);
    }
    if head.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) || head.starts_with(&[0xca, 0xfe, 0xba, 0xbf]) {
        let count = bytes(head, 4, 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)?;
        if (1..=MAX_FAT_ARCHS).contains(&count) {
            return Some(FileKind::MachO);
        }
    }
    None
}

/// A shell link: `HeaderSize` is `0x4C`, followed by the shell link CLSID.
fn is_lnk(head: &[u8]) -> bool {
    u32_at(head, 0) == Some(0x4c) && bytes(head, 4, 16) == Some(&SHELL_LINK_CLSID[..])
}

/// The disc image system area, in front of the first volume descriptor.
pub(super) const SYSTEM_AREA_LEN: usize = 0x8000;

/// Volume descriptor offsets checked for a disc image: sectors 16, 17 and
/// 18 of 2,048 bytes.
const VOLUME_DESCRIPTORS: [usize; 3] = [0x8000, 0x8800, 0x9000];

/// ISO 9660 (`CD001`) or UDF (`BEA01`, `NSR02`, `NSR03`) volume
/// descriptors, after a 32 KiB system area, inside the head. A descriptor
/// is its type byte, the five-letter identifier and version 1. ISO 9660
/// types are 0 to 3 (boot record, primary, supplementary, partition) and
/// 255 (terminator); the UDF structure descriptors have type 0.
pub(super) fn disc_image(head: &[u8]) -> Option<FileKind> {
    let found = VOLUME_DESCRIPTORS.iter().any(|&at| {
        let Some(&[ty, i0, i1, i2, i3, i4, version]) = bytes(head, at, 7) else {
            return false;
        };
        let id = [i0, i1, i2, i3, i4];
        let id = &id;
        let type_ok = match id {
            b"CD001" => matches!(ty, 0..=3 | 0xff),
            b"BEA01" | b"NSR02" | b"NSR03" => ty == 0,
            _ => false,
        };
        type_ok && version == 1
    });
    found.then_some(FileKind::Iso)
}

/// Python bytecode: a version-specific 16-bit magic followed by `\r\n`.
/// From Python 3.7 (magic 3390) the next word is a flags field of 0 to 3,
/// which makes the match specific enough on its own. Older magic values
/// (Python 3.0 to 3.6, from 3000, and 2.7's 62211) are followed by a
/// timestamp, so they are accepted only with a `.pyc` or `.pyo` name.
///
/// Returns `None` if this is not bytecode, or whether the name was needed.
pub(super) fn python_bytecode(head: &[u8], extension: Option<&str>) -> Option<bool> {
    if head.len() < 16 || bytes(head, 2, 2) != Some(b"\r\n") {
        return None;
    }
    let magic = u16_at(head, 0)?;
    if (3390..=3999).contains(&magic) {
        return u32_at(head, 4).filter(|flags| *flags <= 3).map(|_| false);
    }
    let named = matches!(extension, Some("pyc" | "pyo"));
    (named && ((3000..3390).contains(&magic) || magic == 62211)).then_some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_layout() {
        assert_eq!(
            SHELL_LINK_CLSID,
            [
                0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46
            ]
        );
    }

    #[test]
    fn fat_binary_versus_class_file() {
        assert_eq!(
            fixed(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]),
            Some(FileKind::MachO)
        );
        // A Java class file, version 52.0.
        assert_eq!(fixed(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]), None);
        assert_eq!(fixed(&[0xca, 0xfe, 0xba, 0xbe, 0, 0]), None);
    }

    #[test]
    fn truncated_magic_is_not_matched() {
        assert_eq!(fixed(b"MSCF"), None);
        assert_eq!(fixed(b"Rar!\x1a\x07"), None);
        assert_eq!(fixed(&[0x4c, 0, 0, 0, 0x01, 0x14]), None);
        assert_eq!(disc_image(&[0; 0x8003]), None);
        // The identifier alone, in text, is not a descriptor.
        let mut text = vec![b' '; 0x9000];
        text[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(disc_image(&text), None);
        text[0x8000] = 1;
        text[0x8006] = 1;
        assert_eq!(disc_image(&text), Some(FileKind::Iso));
        assert_eq!(fixed(b"ITSF is a word"), None);
        assert_eq!(python_bytecode(&[0xcb, 0x0d, b'\r', b'\n'], None), None);
    }
}
