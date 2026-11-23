//! The debug directory: CodeView (RSDS) PDB information, `REPRO` and POGO.

#![forbid(unsafe_code)]

use super::read::{bytes, to_u64, to_usize, u32_at};
use super::{DataDirectory, DataDirectoryKind, Layout, WarningKind, Warnings};

/// At most this many debug directory entries are read.
pub const MAX_DEBUG_ENTRIES: usize = 64;

/// PDB paths longer than this many bytes are cut off.
pub const MAX_PDB_PATH: usize = 4096;

const DEBUG_ENTRY_SIZE: usize = 28;
const RSDS_SIGNATURE: u32 = 0x5344_5352; // "RSDS"
/// The older CodeView format. Valid, but its metadata is not extracted.
const NB10_SIGNATURE: u32 = 0x3031_424e; // "NB10"
const RSDS_FIXED: usize = 24; // signature + GUID + age

/// The `Type` of a debug directory entry (`IMAGE_DEBUG_TYPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DebugType {
    /// `2`: CodeView (PDB reference).
    CodeView,
    /// `12`: compiler and linker feature counts (`VC_FEATURE`).
    VcFeature,
    /// `13`: profile-guided optimisation (POGO) data.
    Pogo,
    /// `16`: reproducible build. The COFF timestamp is then a hash.
    Repro,
    /// `20`: extended DLL characteristics (`EX_DLLCHARACTERISTICS`).
    ExDllCharacteristics,
    /// Any other value.
    Other(u32),
}

impl DebugType {
    const fn from_raw(value: u32) -> Self {
        match value {
            2 => Self::CodeView,
            12 => Self::VcFeature,
            13 => Self::Pogo,
            16 => Self::Repro,
            20 => Self::ExDllCharacteristics,
            other => Self::Other(other),
        }
    }
}

/// One debug directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugEntry {
    /// File offset of the 28-byte entry.
    pub entry_offset: u64,
    /// The entry type.
    pub debug_type: DebugType,
    /// `TimeDateStamp`.
    pub time_date_stamp: u32,
    /// `SizeOfData`.
    pub size_of_data: u32,
    /// `AddressOfRawData` (an RVA).
    pub address_of_raw_data: u32,
    /// `PointerToRawData` (a file offset).
    pub pointer_to_raw_data: u32,
}

/// A CodeView RSDS record: which PDB the image was built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeViewPdb {
    /// File offset of the record.
    pub offset: u64,
    /// The PDB GUID as stored (the first three fields little-endian).
    pub guid: [u8; 16],
    /// The PDB age.
    pub age: u32,
    /// The PDB path, lossily decoded as UTF-8.
    pub path: String,
}

impl CodeViewPdb {
    /// The GUID in registry format, such as
    /// `"{01234567-89AB-CDEF-0123-456789ABCDEF}"`.
    #[must_use]
    pub fn guid_string(&self) -> String {
        let g = &self.guid;
        let mut out = String::with_capacity(38);
        out.push('{');
        for i in [3, 2, 1, 0] {
            push_hex(&mut out, g, i);
        }
        out.push('-');
        for i in [5, 4] {
            push_hex(&mut out, g, i);
        }
        out.push('-');
        for i in [7, 6] {
            push_hex(&mut out, g, i);
        }
        out.push('-');
        for i in 8..10 {
            push_hex(&mut out, g, i);
        }
        out.push('-');
        for i in 10..16 {
            push_hex(&mut out, g, i);
        }
        out.push('}');
        out
    }
}

fn push_hex(out: &mut String, bytes: &[u8; 16], index: usize) {
    use std::fmt::Write as _;
    if let Some(b) = bytes.get(index) {
        let _ = write!(out, "{b:02X}");
    }
}

/// What the debug directory says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugInfo {
    /// Entries read, at most [`MAX_DEBUG_ENTRIES`].
    pub entries: Vec<DebugEntry>,
    /// The first CodeView RSDS record, if any.
    pub codeview: Option<CodeViewPdb>,
    /// A `REPRO` entry is present, so the COFF timestamp is not a time.
    pub has_repro: bool,
    /// A POGO entry is present.
    pub has_pogo: bool,
}

pub(super) fn parse(
    data: &[u8],
    layout: Layout<'_>,
    dir: DataDirectory,
    warnings: &mut Warnings,
) -> DebugInfo {
    let mut info = DebugInfo::default();
    // RVA 0 is the null address: the loader treats the directory as absent
    // whatever its size, so it must not map to the DOS header.
    let mapped = (dir.virtual_address != 0)
        .then(|| layout.rva_to_offset(dir.virtual_address, dir.size))
        .flatten();
    let Some(start) = mapped else {
        warnings.push(
            usize::try_from(dir.entry_offset).unwrap_or(usize::MAX),
            WarningKind::DirectoryNotMapped(DataDirectoryKind::Debug),
        );
        return info;
    };
    let Some(table) = to_usize(dir.size).and_then(|len| bytes(data, start, len)) else {
        warnings.push(start, WarningKind::DebugDirectoryMalformed);
        return info;
    };
    if table.len() % DEBUG_ENTRY_SIZE != 0 {
        warnings.push(start, WarningKind::DebugDirectoryMalformed);
    }
    if table.len() / DEBUG_ENTRY_SIZE > MAX_DEBUG_ENTRIES {
        warnings.push(start, WarningKind::TooManyDebugEntries);
    }
    for (i, raw) in table
        .chunks_exact(DEBUG_ENTRY_SIZE)
        .take(MAX_DEBUG_ENTRIES)
        .enumerate()
    {
        let field = |at| u32_at(raw, at).unwrap_or(0);
        let entry = DebugEntry {
            entry_offset: to_u64(start.saturating_add(i.saturating_mul(DEBUG_ENTRY_SIZE))),
            debug_type: DebugType::from_raw(field(12)),
            time_date_stamp: field(4),
            size_of_data: field(16),
            address_of_raw_data: field(20),
            pointer_to_raw_data: field(24),
        };
        match entry.debug_type {
            DebugType::Repro => info.has_repro = true,
            DebugType::Pogo => info.has_pogo = true,
            DebugType::CodeView if info.codeview.is_none() => {
                match parse_rsds(data, layout, &entry) {
                    CodeView::Rsds(pdb) => info.codeview = Some(pdb),
                    // A recognised older format: skipped, not malformed. A later
                    // RSDS entry can still be used.
                    CodeView::Unsupported => {}
                    CodeView::Malformed => warnings.push(
                        usize::try_from(entry.entry_offset).unwrap_or(usize::MAX),
                        WarningKind::DebugDirectoryMalformed,
                    ),
                }
            }
            _ => {}
        }
        info.entries.push(entry);
    }
    info
}

/// What a CodeView debug entry holds.
#[derive(Debug, PartialEq, Eq)]
enum CodeView {
    /// A valid RSDS record.
    Rsds(CodeViewPdb),
    /// A recognised format whose metadata is not extracted (NB10).
    Unsupported,
    /// Unreadable, out of bounds, unknown, or an RSDS record whose path has
    /// no NUL terminator.
    Malformed,
}

/// Reads a CodeView record. The record is found by its file offset
/// (`PointerToRawData`), or by its RVA when the file offset is zero.
///
/// An RSDS path must end with a NUL inside the record, as PDB readers
/// require. A path is cut at [`MAX_PDB_PATH`] bytes without failing when
/// the record continues past that point.
fn parse_rsds(data: &[u8], layout: Layout<'_>, entry: &DebugEntry) -> CodeView {
    read_codeview(data, layout, entry).unwrap_or(CodeView::Malformed)
}

fn read_codeview(data: &[u8], layout: Layout<'_>, entry: &DebugEntry) -> Option<CodeView> {
    let offset = if entry.pointer_to_raw_data != 0 {
        to_usize(entry.pointer_to_raw_data)?
    } else if entry.address_of_raw_data != 0 {
        layout.rva_to_offset(entry.address_of_raw_data, entry.size_of_data)?
    } else {
        return None;
    };
    let len = to_usize(entry.size_of_data)?;
    let record = bytes(data, offset, len)?;
    match u32_at(record, 0)? {
        RSDS_SIGNATURE => {}
        NB10_SIGNATURE => return Some(CodeView::Unsupported),
        _ => return None,
    }
    let mut guid = [0_u8; 16];
    guid.copy_from_slice(bytes(record, 4, 16)?);
    let age = u32_at(record, 20)?;
    let path_area = record.get(RSDS_FIXED..)?;
    let scanned = path_area.get(..path_area.len().min(MAX_PDB_PATH))?;
    let path_len = match scanned.iter().position(|b| *b == 0) {
        Some(nul) => nul,
        // The scan reached the record's end without a NUL: unterminated.
        None if scanned.len() == path_area.len() => return None,
        // The scan stopped at the cap with more record left: truncate.
        None => scanned.len(),
    };
    let path = String::from_utf8_lossy(scanned.get(..path_len)?).into_owned();
    Some(CodeView::Rsds(CodeViewPdb {
        offset: to_u64(offset),
        guid,
        age,
        path,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_formatting() {
        let pdb = CodeViewPdb {
            offset: 0,
            guid: [
                0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ],
            age: 1,
            path: String::new(),
        };
        assert_eq!(pdb.guid_string(), "{01234567-89AB-CDEF-0123-456789ABCDEF}");
    }

    const NO_SECTIONS: Layout<'static> = Layout {
        sections: &[],
        size_of_headers: 0,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        file_len: usize::MAX,
    };

    fn record() -> Vec<u8> {
        // Eight bytes of padding so the record is at a non-zero file offset.
        let mut data = vec![0_u8; 8];
        data.extend_from_slice(b"RSDS");
        data.extend_from_slice(&[0xaa; 16]);
        data.extend_from_slice(&7_u32.to_le_bytes());
        data.extend_from_slice(b"C:\\build\\app.pdb\0junk");
        data
    }

    fn entry(data: &[u8]) -> DebugEntry {
        DebugEntry {
            entry_offset: 0,
            debug_type: DebugType::CodeView,
            time_date_stamp: 0,
            size_of_data: u32::try_from(data.len() - 8).unwrap(),
            address_of_raw_data: 0,
            pointer_to_raw_data: 8,
        }
    }

    fn rsds(data: &[u8], entry: &DebugEntry) -> CodeViewPdb {
        match parse_rsds(data, NO_SECTIONS, entry) {
            CodeView::Rsds(pdb) => pdb,
            other => panic!("expected RSDS, got {other:?}"),
        }
    }

    #[test]
    fn rsds_needs_signature_and_bounds() {
        let data = record();
        let entry = entry(&data);
        let pdb = rsds(&data, &entry);
        assert_eq!(
            (pdb.age, pdb.path.as_str(), pdb.offset),
            (7, "C:\\build\\app.pdb", 8)
        );

        let malformed = |data: &[u8], entry: &DebugEntry| {
            parse_rsds(data, NO_SECTIONS, entry) == CodeView::Malformed
        };
        let short = DebugEntry {
            size_of_data: 10,
            ..entry.clone()
        };
        assert!(malformed(&data, &short));
        let past_end = DebugEntry {
            size_of_data: u32::MAX,
            ..entry.clone()
        };
        assert!(malformed(&data, &past_end));
        let nowhere = DebugEntry {
            pointer_to_raw_data: 0,
            ..entry.clone()
        };
        assert!(malformed(&data, &nowhere));
        let mut bad = data.clone();
        bad[8] = b'X';
        assert!(malformed(&bad, &entry));
    }

    #[test]
    fn nb10_is_unsupported_not_malformed() {
        let mut data = record();
        data[8..12].copy_from_slice(b"NB10");
        assert_eq!(
            parse_rsds(&data, NO_SECTIONS, &entry(&data)),
            CodeView::Unsupported
        );
    }

    #[test]
    fn rsds_path_must_be_terminated() {
        // The record ends inside the path, before any NUL.
        let mut data = record();
        data.truncate(8 + RSDS_FIXED + 5);
        assert_eq!(
            parse_rsds(&data, NO_SECTIONS, &entry(&data)),
            CodeView::Malformed
        );
        // A NUL as the very last byte is fine.
        data.push(0);
        assert_eq!(rsds(&data, &entry(&data)).path, "C:\\bu");
    }

    #[test]
    fn rsds_path_scan_is_capped() {
        // More record bytes remain past the cap, so the path is truncated
        // rather than rejected.
        let mut data = record();
        data.truncate(8 + RSDS_FIXED);
        data.extend(std::iter::repeat_n(b'a', MAX_PDB_PATH * 4));
        assert_eq!(rsds(&data, &entry(&data)).path.len(), MAX_PDB_PATH);
        // A path exactly MAX_PDB_PATH long with no NUL and nothing after it
        // is unterminated.
        data.truncate(8 + RSDS_FIXED + MAX_PDB_PATH);
        assert_eq!(
            parse_rsds(&data, NO_SECTIONS, &entry(&data)),
            CodeView::Malformed
        );
    }

    #[test]
    fn debug_type_codes() {
        assert_eq!(DebugType::from_raw(12), DebugType::VcFeature);
        assert_eq!(DebugType::from_raw(20), DebugType::ExDllCharacteristics);
        assert_eq!(DebugType::from_raw(99), DebugType::Other(99));
    }
}
