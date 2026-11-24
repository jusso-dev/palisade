//! OLE compound files: installer packages are told apart by the root
//! storage CLSID.
//!
//! Only the header and the root directory entry are read: no FAT chain, no
//! streams. The root entry is always the first entry of the first directory
//! sector, so finding it needs one targeted read.

#![forbid(unsafe_code)]

use std::io::{Read, Seek};

use super::magic::guid;
use super::name::NameInfo;
use super::source::Source;
use super::{Classification, Confidence, FileKind, ParseError};
use crate::pe::read::{bytes, u8_at, u16_at, u32_at};

/// The compound file signature.
pub(super) const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

/// `{000C10xx-0000-0000-C000-000000000046}`, the installer CLSID family.
const fn installer(d1: u32) -> [u8; 16] {
    guid(d1, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46])
}

const MSI_CLSID: [u8; 16] = installer(0x000c_1084);
const MSP_CLSID: [u8; 16] = installer(0x000c_1086);
const MST_CLSID: [u8; 16] = installer(0x000c_1082);

/// Root CLSIDs of macro-capable office suite documents: the word processor
/// (97 to current, and 6.0/95), the spreadsheet (97 to current, and 5.0/95)
/// and the presentation program.
const MACRO_CAPABLE_CLSIDS: [[u8; 16]; 5] = [
    guid(0x0002_0906, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]),
    guid(0x0002_0900, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]),
    guid(0x0002_0820, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]),
    guid(0x0002_0810, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]),
    guid(
        0x6481_8d10,
        0x4f9b,
        0x11cf,
        [0x86, 0xea, 0x00, 0xaa, 0x00, 0xb9, 0x29, 0xe8],
    ),
];

/// The largest directory sector number: higher values are markers
/// (`MAXREGSECT`).
const MAX_REGULAR_SECTOR: u32 = 0xffff_fffa;

/// Size of one directory entry.
const DIRECTORY_ENTRY_LEN: usize = 128;

/// Directory entry type of the root storage.
const ROOT_STORAGE: u8 = 5;

/// Reads the root CLSID and sets the kind.
pub(super) fn classify<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    name: &NameInfo,
    out: &mut Classification,
) {
    // A compound file is never anything else, even if broken.
    out.content_kind = FileKind::OtherCfb;
    out.confidence = Confidence::High;
    let clsid = match root_clsid(src) {
        Ok(clsid) => clsid,
        Err(e) => {
            out.parse_error = Some(e);
            return;
        }
    };
    out.content_kind = if clsid == MSI_CLSID {
        // Merge modules share the database CLSID.
        if name.is_ext(&["msm"]) {
            out.extension_assisted = true;
            FileKind::Msm
        } else {
            FileKind::Msi
        }
    } else if clsid == MSP_CLSID {
        FileKind::Msp
    } else if clsid == MST_CLSID {
        FileKind::Mst
    } else {
        out.flags.macro_capable_container = MACRO_CAPABLE_CLSIDS.contains(&clsid);
        FileKind::OtherCfb
    };
}

/// The CLSID of the root storage entry.
fn root_clsid<R: Read + Seek + ?Sized>(src: &mut Source<'_, R>) -> Result<[u8; 16], ParseError> {
    let head = src.head();
    // Byte order mark, then the sector shift: 9 (512-byte sectors, major
    // version 3) or 12 (4,096-byte sectors, major version 4).
    if u16_at(head, 0x1c) != Some(0xfffe) {
        return Err(ParseError::CfbHeader);
    }
    let shift = match (u16_at(head, 0x1a), u16_at(head, 0x1e)) {
        (Some(3), Some(9)) => 9_u32,
        (Some(4), Some(12)) => 12_u32,
        _ => return Err(ParseError::CfbHeader),
    };
    let first = u32_at(head, 0x30).ok_or(ParseError::CfbHeader)?;
    if first > MAX_REGULAR_SECTOR {
        return Err(ParseError::CfbDirectory);
    }
    // Sector `n` starts at `(n + 1) << shift`: the header fills sector -1.
    let offset = (u64::from(first) + 1) << shift;
    let entry = src.read_at(offset, DIRECTORY_ENTRY_LEN)?;
    if u8_at(&entry, 0x42) != Some(ROOT_STORAGE) {
        return Err(ParseError::CfbDirectory);
    }
    bytes(&entry, 0x50, 16)
        .and_then(|b| b.try_into().ok())
        .ok_or(ParseError::CfbDirectory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_clsids() {
        assert_eq!(
            MSI_CLSID,
            [
                0x84, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46
            ]
        );
        assert_ne!(MSI_CLSID, MSP_CLSID);
        assert_ne!(MSP_CLSID, MST_CLSID);
    }
}
