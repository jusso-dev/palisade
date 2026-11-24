//! The summary information stream (`\u{5}SummaryInformation`): an OLE
//! property set with one section, `FMTID_SummaryInformation`.
//!
//! Layout: a 28-byte header (byte order `0xfffe`, format, OS version,
//! CLSID, section count), then one `(FMTID, offset)` pair per section. A
//! section starts with its size and property count, then one `(property
//! ID, offset)` pair per property, offsets relative to the section. Each
//! value starts with its type: `VT_I2` (2), `VT_I4` (3), `VT_LPSTR` (30,
//! a length including the terminator, then the bytes, in the codepage of
//! property 1) or `VT_FILETIME` (64).
//!
//! A property ID that appears twice, a value that runs past the section,
//! or a value whose type is not the one the Windows Installer defines for
//! its ID, makes the whole stream malformed: the summary information is
//! either read exactly or not at all.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

/// `FMTID_SummaryInformation`, F29F85E0-4FF9-1068-AB91-08002B27B3D9, as
/// stored.
const FMTID_SUMMARY: [u8; 16] = [
    0xe0, 0x85, 0x9f, 0xf2, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27, 0xb3, 0xd9,
];

/// The most properties read from the section.
pub const MAX_PROPERTIES: usize = 64;
/// String values longer than this are rejected.
pub const MAX_STRING_LEN: usize = 64 * 1024;

/// Property IDs.
pub(crate) mod pid {
    pub const CODEPAGE: u32 = 1;
    pub const TITLE: u32 = 2;
    pub const SUBJECT: u32 = 3;
    pub const AUTHOR: u32 = 4;
    pub const KEYWORDS: u32 = 5;
    pub const COMMENTS: u32 = 6;
    pub const TEMPLATE: u32 = 7;
    pub const LAST_AUTHOR: u32 = 8;
    pub const REVISION: u32 = 9;
    pub const EDIT_TIME: u32 = 10;
    pub const LAST_PRINTED: u32 = 11;
    pub const CREATED: u32 = 12;
    pub const LAST_SAVED: u32 = 13;
    pub const PAGE_COUNT: u32 = 14;
    pub const WORD_COUNT: u32 = 15;
    pub const CHAR_COUNT: u32 = 16;
    pub const APP_NAME: u32 = 18;
    pub const SECURITY: u32 = 19;
}

const VT_I2: u32 = 2;
const VT_I4: u32 = 3;
const VT_LPSTR: u32 = 30;
const VT_FILETIME: u32 = 64;

/// One property value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    /// `VT_I2`.
    I2(i16),
    /// `VT_I4`.
    I4(i32),
    /// `VT_LPSTR`, decoded, with its raw bytes (terminator removed).
    Text {
        /// The decoded text.
        text: String,
        /// The bytes as stored.
        raw: Vec<u8>,
    },
    /// `VT_FILETIME`: 100 ns ticks since 1601-01-01 UTC.
    FileTime(u64),
}

/// Why the summary information could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SummaryError {
    /// The stream is too short, or a header field is wrong.
    Header(&'static str),
    /// A property is malformed: out of range, the wrong type, or repeated.
    Property(u32),
    /// More than [`MAX_PROPERTIES`] properties.
    TooManyProperties,
}

impl fmt::Display for SummaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(what) => write!(f, "summary information header: {what}"),
            Self::Property(id) => write!(f, "summary information property {id} is malformed"),
            Self::TooManyProperties => f.write_str("too many summary information properties"),
        }
    }
}

impl std::error::Error for SummaryError {}

/// The decoded summary information.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SummaryInfo {
    /// Every property, by ID.
    pub properties: BTreeMap<u32, PropertyValue>,
}

impl SummaryInfo {
    /// The text of property `id`.
    #[must_use]
    pub fn text(&self, id: u32) -> Option<&str> {
        match self.properties.get(&id) {
            Some(PropertyValue::Text { text, .. }) => Some(text),
            _ => None,
        }
    }

    /// The integer value of property `id`.
    #[must_use]
    pub fn int(&self, id: u32) -> Option<i32> {
        match self.properties.get(&id) {
            Some(PropertyValue::I4(v)) => Some(*v),
            Some(PropertyValue::I2(v)) => Some(i32::from(*v)),
            _ => None,
        }
    }

    /// The FILETIME value of property `id`.
    #[must_use]
    pub fn time(&self, id: u32) -> Option<u64> {
        match self.properties.get(&id) {
            Some(PropertyValue::FileTime(v)) => Some(*v),
            _ => None,
        }
    }
}

/// The type the Windows Installer defines for `id`, or `None` for an ID it
/// does not define.
fn expected_type(id: u32) -> Option<u32> {
    use pid::*;
    Some(match id {
        CODEPAGE => VT_I2,
        TITLE | SUBJECT | AUTHOR | KEYWORDS | COMMENTS | TEMPLATE | LAST_AUTHOR | REVISION
        | APP_NAME => VT_LPSTR,
        EDIT_TIME | LAST_PRINTED | CREATED | LAST_SAVED => VT_FILETIME,
        PAGE_COUNT | WORD_COUNT | CHAR_COUNT | SECURITY => VT_I4,
        _ => return None,
    })
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at.checked_add(2)?)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_le_bytes)
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at.checked_add(4)?)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)
}

fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    let b = d.get(at..at.checked_add(8)?)?;
    let mut a = [0_u8; 8];
    a.copy_from_slice(b);
    Some(u64::from_le_bytes(a))
}

/// Parses a summary information stream. Strings are decoded with
/// `decode`, given the bytes and the codepage (property 1, or 0).
pub(crate) fn parse(
    data: &[u8],
    decode: impl Fn(&[u8], u32) -> (String, bool),
) -> Result<SummaryInfo, SummaryError> {
    if u16_at(data, 0) != Some(0xfffe) {
        return Err(SummaryError::Header("byte order"));
    }
    let sections = u32_at(data, 24).ok_or(SummaryError::Header("too short"))?;
    if sections == 0 || sections > 2 {
        return Err(SummaryError::Header("section count"));
    }
    if data.get(28..44) != Some(&FMTID_SUMMARY[..]) {
        return Err(SummaryError::Header("not summary information"));
    }
    let start = u32_at(data, 44)
        .and_then(|o| usize::try_from(o).ok())
        .ok_or(SummaryError::Header("section offset"))?;
    let section_len = u32_at(data, start)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(SummaryError::Header("section offset"))?;
    let section = start
        .checked_add(section_len)
        .and_then(|end| data.get(start..end))
        .filter(|s| s.len() >= 8)
        .ok_or(SummaryError::Header("section size"))?;
    let count = u32_at(section, 4)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(SummaryError::Header("property count"))?;
    if count > MAX_PROPERTIES {
        return Err(SummaryError::TooManyProperties);
    }
    // First pass: the codepage, so strings decode in it whatever order the
    // properties are stored in.
    // Offsets past the section are rejected here, so later offset
    // arithmetic cannot overflow.
    let entry = |i: usize| -> Option<(u32, usize)> {
        let at = 8 + 8 * i;
        let off = usize::try_from(u32_at(section, at + 4)?).ok()?;
        (off < section.len()).then_some((u32_at(section, at)?, off))
    };
    let mut codepage = 0_u32;
    for i in 0..count {
        let (id, off) = entry(i).ok_or(SummaryError::Header("property table"))?;
        if id == pid::CODEPAGE {
            if u32_at(section, off) != Some(VT_I2) {
                return Err(SummaryError::Property(id));
            }
            let cp = u16_at(section, off + 4).ok_or(SummaryError::Property(id))?;
            codepage = u32::from(cp);
        }
    }
    let mut out = SummaryInfo::default();
    for i in 0..count {
        let (id, off) = entry(i).ok_or(SummaryError::Header("property table"))?;
        let bad = || SummaryError::Property(id);
        let ty = u32_at(section, off).ok_or_else(bad)?;
        // Unknown IDs (the thumbnail, vendor additions) are skipped, but
        // their slot must still be inside the section.
        let Some(want) = expected_type(id) else {
            continue;
        };
        if ty != want {
            return Err(bad());
        }
        let value = match ty {
            VT_I2 => PropertyValue::I2(i16::from_le_bytes(
                u16_at(section, off + 4).ok_or_else(bad)?.to_le_bytes(),
            )),
            VT_I4 => PropertyValue::I4(i32::from_le_bytes(
                u32_at(section, off + 4).ok_or_else(bad)?.to_le_bytes(),
            )),
            VT_FILETIME => PropertyValue::FileTime(u64_at(section, off + 4).ok_or_else(bad)?),
            _ => {
                let len = u32_at(section, off + 4)
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|&n| n <= MAX_STRING_LEN)
                    .ok_or_else(bad)?;
                let bytes = section.get(off + 8..off + 8 + len).ok_or_else(bad)?;
                // The length counts the terminator; text ends at the first
                // NUL, as the OS reads it.
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let raw = bytes.get(..end).unwrap_or_default().to_vec();
                let (text, _) = decode(&raw, codepage);
                PropertyValue::Text { text, raw }
            }
        };
        if out.properties.insert(id, value).is_some() {
            return Err(bad());
        }
    }
    Ok(out)
}

/// The FILETIME properties: edit time and the three timestamps.
pub(crate) const TIME_PROPERTIES: [u32; 4] = [
    pid::EDIT_TIME,
    pid::LAST_PRINTED,
    pid::CREATED,
    pid::LAST_SAVED,
];

/// The canonical form of `info` without its FILETIME properties, for the
/// normalised hash: for each remaining property in ID order, its ID and
/// type (u32 LE), then for `VT_I2` 2 bytes, `VT_I4` 4 bytes, `VT_LPSTR`
/// the raw length (u32 LE) and bytes.
pub(crate) fn canonical_without_times(info: &SummaryInfo) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, value) in &info.properties {
        if TIME_PROPERTIES.contains(id) {
            continue;
        }
        out.extend_from_slice(&id.to_le_bytes());
        match value {
            PropertyValue::I2(v) => {
                out.extend_from_slice(&VT_I2.to_le_bytes());
                out.extend_from_slice(&v.to_le_bytes());
            }
            PropertyValue::I4(v) => {
                out.extend_from_slice(&VT_I4.to_le_bytes());
                out.extend_from_slice(&v.to_le_bytes());
            }
            PropertyValue::Text { raw, .. } => {
                out.extend_from_slice(&VT_LPSTR.to_le_bytes());
                let len = u32::try_from(raw.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(raw);
            }
            PropertyValue::FileTime(v) => {
                out.extend_from_slice(&VT_FILETIME.to_le_bytes());
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ascii(b: &[u8], _: u32) -> (String, bool) {
        (String::from_utf8_lossy(b).into_owned(), false)
    }

    fn stream(props: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut section = Vec::new();
        let header = 8 + 8 * props.len();
        let mut values = Vec::new();
        let mut table = Vec::new();
        for (id, ty, data) in props {
            table.extend_from_slice(&id.to_le_bytes());
            table.extend_from_slice(&u32::try_from(header + values.len()).unwrap().to_le_bytes());
            values.extend_from_slice(&ty.to_le_bytes());
            values.extend_from_slice(data);
            while values.len() % 4 != 0 {
                values.push(0);
            }
        }
        section.extend_from_slice(&u32::try_from(header + values.len()).unwrap().to_le_bytes());
        section.extend_from_slice(&u32::try_from(props.len()).unwrap().to_le_bytes());
        section.extend_from_slice(&table);
        section.extend_from_slice(&values);
        let mut out = vec![0xfe, 0xff, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&1_u32.to_le_bytes());
        out.extend_from_slice(&FMTID_SUMMARY);
        out.extend_from_slice(&48_u32.to_le_bytes());
        out.extend_from_slice(&section);
        out
    }

    fn lpstr(s: &str) -> Vec<u8> {
        let mut v = u32::try_from(s.len() + 1).unwrap().to_le_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    }

    #[test]
    fn reads_typed_properties() {
        let data = stream(&[
            (pid::CODEPAGE, VT_I2, 1252_u16.to_le_bytes().to_vec()),
            (pid::REVISION, VT_LPSTR, lpstr("{GUID}")),
            (pid::PAGE_COUNT, VT_I4, 500_u32.to_le_bytes().to_vec()),
            (pid::CREATED, VT_FILETIME, 7_u64.to_le_bytes().to_vec()),
        ]);
        let info = parse(&data, ascii).unwrap();
        assert_eq!(info.text(pid::REVISION), Some("{GUID}"));
        assert_eq!(info.int(pid::PAGE_COUNT), Some(500));
        assert_eq!(info.int(pid::CODEPAGE), Some(1252));
        assert_eq!(info.time(pid::CREATED), Some(7));
        let canon = canonical_without_times(&info);
        let changed = stream(&[
            (pid::CODEPAGE, VT_I2, 1252_u16.to_le_bytes().to_vec()),
            (pid::REVISION, VT_LPSTR, lpstr("{GUID}")),
            (pid::PAGE_COUNT, VT_I4, 500_u32.to_le_bytes().to_vec()),
            (pid::CREATED, VT_FILETIME, 99_u64.to_le_bytes().to_vec()),
        ]);
        assert_eq!(
            canon,
            canonical_without_times(&parse(&changed, ascii).unwrap())
        );
    }

    #[test]
    fn rejects_wrong_types_duplicates_and_overruns() {
        let wrong = stream(&[(pid::REVISION, VT_I4, 1_u32.to_le_bytes().to_vec())]);
        assert_eq!(
            parse(&wrong, ascii),
            Err(SummaryError::Property(pid::REVISION))
        );
        let dup = stream(&[
            (pid::TITLE, VT_LPSTR, lpstr("a")),
            (pid::TITLE, VT_LPSTR, lpstr("b")),
        ]);
        assert_eq!(parse(&dup, ascii), Err(SummaryError::Property(pid::TITLE)));
        let mut long = lpstr("abc");
        long[0] = 200;
        let over = stream(&[(pid::TITLE, VT_LPSTR, long)]);
        assert_eq!(parse(&over, ascii), Err(SummaryError::Property(pid::TITLE)));
        assert!(parse(b"", ascii).is_err());
    }
}
