//! Identity of 16-bit NE and 32-bit LE / LX executables (#45).
//!
//! These older `MZ` formats have no version resource that the OS reads, but
//! they name themselves. [`parse`] reads:
//!
//! - the **module name**, the first entry of the resident name table;
//! - the **module description**, the first entry of the non-resident name
//!   table;
//! - the format and target operating system, which are the minimal identity
//!   returned when the names cannot be read.
//!
//! Each name table entry is a length byte, then that many bytes of
//! single-byte text, then an ordinal. A length byte of zero ends the table,
//! so an empty table means the name is absent.
//!
//! The input is untrusted, and the parser fails conservative:
//!
//! - Every read is bounds-checked, and all offset arithmetic is checked. A
//!   name is at most 255 bytes, because its length is one byte, so nothing
//!   is allocated from a size the file declares.
//! - A name is reported only if it lies wholly inside the file and, where
//!   the header gives the table's length, inside the table. Otherwise it is
//!   absent, with a [`LegacyWarning`].
//! - The text is in a code page that the file does not name. Printable
//!   ASCII is kept as it is. Any other byte becomes U+FFFD and
//!   [`LegacyName::non_ascii`] is set, so a rule can never match a guessed
//!   decoding. The exact bytes are kept in [`LegacyName::raw`].
//! - An LE or LX header that declares big-endian byte or word order is
//!   identified, but its names are not read.
//!
//! [`parse`] fails with a [`LegacyError`] only when the file is not one of
//! these formats.

#![forbid(unsafe_code)]

use super::read::{bytes, to_u64, to_usize, u8_at, u16_at, u32_at};
use super::{MAX_E_LFANEW, NormalizedName};

/// Where `e_lfanew` is in the DOS header.
const E_LFANEW_AT: usize = 0x3c;
/// The DOS header is this long.
const DOS_HEADER_LEN: usize = 0x40;

/// NE header fields, relative to the header.
mod ne {
    /// The fields read end here.
    pub const LEN: usize = 0x40;
    pub const NON_RESIDENT_SIZE: usize = 0x20;
    pub const RESIDENT_NAMES: usize = 0x26;
    /// An absolute file offset.
    pub const NON_RESIDENT_NAMES: usize = 0x2c;
    pub const TARGET_OS: usize = 0x36;
}

/// LE and LX header fields, relative to the header.
mod lx {
    /// The fields read end here.
    pub const LEN: usize = 0x90;
    pub const BYTE_ORDER: usize = 0x02;
    pub const WORD_ORDER: usize = 0x03;
    pub const TARGET_OS: usize = 0x0a;
    pub const RESIDENT_NAMES: usize = 0x58;
    /// An absolute file offset.
    pub const NON_RESIDENT_NAMES: usize = 0x88;
    pub const NON_RESIDENT_SIZE: usize = 0x8c;
}

/// The format of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyFormat {
    /// A 16-bit new executable (`NE`).
    Ne,
    /// A linear executable (`LE`), such as a virtual device driver.
    Le,
    /// A linear executable (`LX`).
    Lx,
}

/// The operating system a module targets, from its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetOs {
    /// The header does not say (`0`).
    Unspecified,
    /// OS/2 (`1`).
    Os2,
    /// Windows (`2`).
    Windows,
    /// European multitasking DOS 4 (`3`).
    Dos4,
    /// Windows 386 virtual device drivers (`4`).
    Win386,
    /// Any other value.
    Other(u16),
}

impl TargetOs {
    const fn of(value: u16) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::Os2,
            2 => Self::Windows,
            3 => Self::Dos4,
            4 => Self::Win386,
            other => Self::Other(other),
        }
    }
}

/// A name from a name table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegacyName {
    /// The file offset of the name's length byte.
    pub offset: u64,
    /// The bytes exactly as the file has them.
    pub raw: Vec<u8>,
    /// The text: printable ASCII kept, any other byte U+FFFD.
    pub text: String,
    /// Some byte was not printable ASCII and was replaced.
    pub non_ascii: bool,
    /// The match forms of [`text`](Self::text).
    pub normalized: NormalizedName,
}

impl LegacyName {
    fn new(offset: usize, raw: &[u8]) -> Self {
        let mut non_ascii = false;
        let text: String = raw
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    char::from(b)
                } else {
                    non_ascii = true;
                    char::REPLACEMENT_CHARACTER
                }
            })
            .collect();
        Self {
            offset: to_u64(offset),
            raw: raw.to_vec(),
            normalized: NormalizedName::new(&text),
            text,
            non_ascii,
        }
    }
}

/// Which name a warning is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameKind {
    /// The module name (resident name table).
    ModuleName,
    /// The module description (non-resident name table).
    Description,
}

/// Why something was not read. The result is still returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyWarning {
    /// The file ends inside the header: only the format is known.
    HeaderTruncated,
    /// An LE or LX header declares big-endian byte or word order. Its names
    /// are not read.
    BigEndian,
    /// The name table starts outside the file.
    TableOutOfBounds(NameKind),
    /// The name runs past the end of the file.
    NameTruncated(NameKind),
    /// The name runs past the table length that the header declares.
    NameOutsideTable(NameKind),
}

/// The identity of an NE, LE or LX file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegacyInfo {
    /// The format.
    pub format: LegacyFormat,
    /// The header's file offset (`e_lfanew`).
    pub header_offset: u32,
    /// The target operating system, if the header was read.
    pub target_os: Option<TargetOs>,
    /// The module name, if present and readable.
    pub module_name: Option<LegacyName>,
    /// The module description, if present and readable.
    pub description: Option<LegacyName>,
    /// What could not be read, in the order found.
    pub warnings: Vec<LegacyWarning>,
}

/// Why the file is not an NE, LE or LX file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyError {
    /// The input is shorter than a DOS header (64 bytes).
    TooSmall,
    /// The input does not start with `MZ`.
    NoDosSignature,
    /// `e_lfanew` is above [`MAX_E_LFANEW`] or leaves no room for a
    /// signature.
    LfanewOutOfRange(u32),
    /// There is no `NE`, `LE` or `LX` signature at `e_lfanew`.
    NoSignature,
}

impl core::fmt::Display for LegacyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooSmall => f.write_str("input is smaller than a DOS header"),
            Self::NoDosSignature => f.write_str("missing MZ signature"),
            Self::LfanewOutOfRange(v) => write!(f, "e_lfanew {v:#x} is out of range"),
            Self::NoSignature => f.write_str("no NE, LE or LX signature"),
        }
    }
}

impl std::error::Error for LegacyError {}

/// Reads the identity of an NE, LE or LX file. See the module
/// documentation.
///
/// # Errors
///
/// [`LegacyError`] if `data` is not an NE, LE or LX file.
pub fn parse(data: &[u8]) -> Result<LegacyInfo, LegacyError> {
    if data.len() < DOS_HEADER_LEN {
        return Err(LegacyError::TooSmall);
    }
    if bytes(data, 0, 2) != Some(b"MZ") {
        return Err(LegacyError::NoDosSignature);
    }
    let e_lfanew = u32_at(data, E_LFANEW_AT).ok_or(LegacyError::TooSmall)?;
    let at = to_usize(e_lfanew)
        .filter(|_| e_lfanew <= MAX_E_LFANEW)
        .ok_or(LegacyError::LfanewOutOfRange(e_lfanew))?;
    let format = match bytes(data, at, 2) {
        Some(b"NE") => LegacyFormat::Ne,
        Some(b"LE") => LegacyFormat::Le,
        Some(b"LX") => LegacyFormat::Lx,
        Some(_) => return Err(LegacyError::NoSignature),
        None => return Err(LegacyError::LfanewOutOfRange(e_lfanew)),
    };
    let mut info = LegacyInfo {
        format,
        header_offset: e_lfanew,
        target_os: None,
        module_name: None,
        description: None,
        warnings: Vec::new(),
    };
    let len = match format {
        LegacyFormat::Ne => ne::LEN,
        LegacyFormat::Le | LegacyFormat::Lx => lx::LEN,
    };
    let Some(header) = bytes(data, at, len) else {
        info.warnings.push(LegacyWarning::HeaderTruncated);
        return Ok(info);
    };
    match format {
        LegacyFormat::Ne => read_ne(data, at, header, &mut info),
        LegacyFormat::Le | LegacyFormat::Lx => read_lx(data, at, header, &mut info),
    }
    Ok(info)
}

/// The header fields used. `header` holds at least [`ne::LEN`] bytes, so the
/// field reads cannot fail; a failed one reads as zero (absent).
fn read_ne(data: &[u8], at: usize, header: &[u8], info: &mut LegacyInfo) {
    info.target_os = Some(TargetOs::of(u16::from(
        u8_at(header, ne::TARGET_OS).unwrap_or(0),
    )));
    let resident = u16_at(header, ne::RESIDENT_NAMES).unwrap_or(0);
    // A resident table offset of zero points at the header itself, which
    // is not a name table.
    if resident != 0 {
        let start = at.checked_add(usize::from(resident));
        info.module_name = name(data, start, None, NameKind::ModuleName, info);
    }
    let non_resident = u32_at(header, ne::NON_RESIDENT_NAMES).unwrap_or(0);
    let size = u16_at(header, ne::NON_RESIDENT_SIZE).unwrap_or(0);
    if non_resident != 0 && size != 0 {
        info.description = name(
            data,
            to_usize(non_resident),
            Some(usize::from(size)),
            NameKind::Description,
            info,
        );
    }
}

/// As [`read_ne`], for LE and LX: `header` holds at least [`lx::LEN`] bytes.
fn read_lx(data: &[u8], at: usize, header: &[u8], info: &mut LegacyInfo) {
    info.target_os = Some(TargetOs::of(u16_at(header, lx::TARGET_OS).unwrap_or(0)));
    let byte_order = u8_at(header, lx::BYTE_ORDER).unwrap_or(1);
    let word_order = u8_at(header, lx::WORD_ORDER).unwrap_or(1);
    if byte_order != 0 || word_order != 0 {
        info.warnings.push(LegacyWarning::BigEndian);
        return;
    }
    let resident = u32_at(header, lx::RESIDENT_NAMES).unwrap_or(0);
    if resident != 0 {
        let start = to_usize(resident).and_then(|r| at.checked_add(r));
        info.module_name = name(data, start, None, NameKind::ModuleName, info);
    }
    let non_resident = u32_at(header, lx::NON_RESIDENT_NAMES).unwrap_or(0);
    let size = u32_at(header, lx::NON_RESIDENT_SIZE).unwrap_or(0);
    if non_resident != 0 && size != 0 {
        info.description = name(
            data,
            to_usize(non_resident),
            to_usize(size),
            NameKind::Description,
            info,
        );
    }
}

/// The first entry of the name table at `start`, which is `table_len` bytes
/// long if the header says. `None`, with a warning, if it cannot be read;
/// `None` alone if the table is empty.
fn name(
    data: &[u8],
    start: Option<usize>,
    table_len: Option<usize>,
    kind: NameKind,
    info: &mut LegacyInfo,
) -> Option<LegacyName> {
    let mut warn = |w| {
        info.warnings.push(w);
        None
    };
    let Some((start, len)) = start.and_then(|s| Some((s, u8_at(data, s)?))) else {
        return warn(LegacyWarning::TableOutOfBounds(kind));
    };
    if len == 0 {
        return None;
    }
    let len = usize::from(len);
    if table_len.is_some_and(|t| len.saturating_add(1) > t) {
        return warn(LegacyWarning::NameOutsideTable(kind));
    }
    let Some(raw) = start.checked_add(1).and_then(|s| bytes(data, s, len)) else {
        return warn(LegacyWarning::NameTruncated(kind));
    };
    Some(LegacyName::new(start, raw))
}
