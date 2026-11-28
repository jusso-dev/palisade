//! The NTFS upcase table and the volume's record of it (#332).
//!
//! NTFS compares two names by upper-casing each UTF-16 code unit through
//! the **volume's** upcase table (`$UpCase`, MFT record 10), written when
//! the volume is formatted. [`super::fold_case`] folds names with the
//! table that Windows 7 and every later version write, and that the OS
//! itself upper-cases with: [`palisade_core::upcase`].
//!
//! # Older volumes
//!
//! A volume formatted by Windows Vista or XP holds an older table, and the
//! OS goes on using it for that volume. Since Windows 8, NTFS records a
//! CRC-64 of the table in the `$Info` stream of `$UpCase`, and checks it at
//! mount against the tables it knows. [`parse_upcase_info`] reads that CRC
//! from the file record the OS returns (`FSCTL_GET_NTFS_FILE_RECORD`), and
//! [`VolumeUpcase::from_crc`] compares it with [`STANDARD_UPCASE_CRC`], the
//! CRC of this table. Only a volume that records exactly that CRC is known
//! to fold as [`super::fold_case`] does. A volume that records another CRC,
//! or none, or whose record cannot be read, is "unknown fold": path keys on
//! it are refused (see [`super::NormalizedPath::mark_fold_unknown`]), so a
//! path rule there is unknown, never matched by a guessed spelling
//! (ADR 0018).
//!
//! The CRC is the volume's own claim. A volume prepared elsewhere (a USB
//! disk, a VHD) can claim the standard CRC over a different table, because
//! NTFS compares the stored value, not the table. Path identity is not
//! trusted on such volumes anyway (only fixed local disks qualify), and
//! reading and checking the table itself is #332's M2 follow-up.

#![forbid(unsafe_code)]

pub use palisade_core::upcase::{STANDARD_UPCASE_CRC, upcase_unit};

/// What a volume records about its upcase table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VolumeUpcase {
    /// The CRC of the standard table ([`STANDARD_UPCASE_CRC`]).
    Standard,
    /// Another CRC: an older or unknown table.
    Other(u64),
    /// No `$UpCase:$Info` stream: the volume predates Windows 8 and has not
    /// been given one since, so its table is not known.
    Unrecorded,
}

impl VolumeUpcase {
    /// The status for the CRC a volume records, if any.
    #[must_use]
    pub const fn from_crc(crc: Option<u64>) -> Self {
        match crc {
            Some(STANDARD_UPCASE_CRC) => Self::Standard,
            Some(c) => Self::Other(c),
            None => Self::Unrecorded,
        }
    }

    /// Whether names on the volume fold as [`super::fold_case`] folds them.
    #[must_use]
    pub const fn folds_as_standard(self) -> bool {
        matches!(self, Self::Standard)
    }
}

/// Why a file record could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileRecordError {
    /// Not a `FILE` record, or a header field out of range.
    BadHeader,
    /// An attribute runs past the record, or does not advance.
    BadAttribute {
        /// The byte offset of the attribute.
        offset: usize,
    },
    /// The `$Info` value is shorter than its CRC.
    ShortInfo,
}

impl std::fmt::Display for FileRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadHeader => f.write_str("not a valid NTFS file record"),
            Self::BadAttribute { offset } => {
                write!(
                    f,
                    "malformed attribute at offset {offset} of the file record"
                )
            }
            Self::ShortInfo => f.write_str("the $UpCase:$Info value is too short"),
        }
    }
}

impl std::error::Error for FileRecordError {}

/// The attribute type of `$DATA`.
const ATTR_DATA: u32 = 0x80;
/// The end-of-attributes marker.
const ATTR_END: u32 = 0xFFFF_FFFF;
/// The update sequence stride: NTFS protects every 512 bytes of a record.
const USA_STRIDE: usize = 512;
/// The most attributes walked. A 4 KiB record holds far fewer.
const MAX_ATTRIBUTES: usize = 256;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Puts back the bytes the update sequence array saved, in each 512-byte
/// stride whose last two bytes still hold the update sequence number. The
/// OS may return the record with this already done; a stride whose bytes
/// differ from the number is left alone, and doing it twice changes
/// nothing, so it is right either way.
fn apply_fixups(record: &mut [u8]) -> Option<()> {
    let usa = usize::from(u16_at(record, 4)?);
    let count = usize::from(u16_at(record, 6)?);
    let usn = u16_at(record, usa)?;
    for i in 1..count {
        let end = i.checked_mul(USA_STRIDE)?;
        let saved = u16_at(record, usa.checked_add(i.checked_mul(2)?)?)?;
        let at = end.checked_sub(2)?;
        if u16_at(record, at)? == usn {
            record
                .get_mut(at..end)?
                .copy_from_slice(&saved.to_le_bytes());
        }
    }
    Some(())
}

/// The CRC-64 recorded in the resident `$Info` data stream of a `$UpCase`
/// file record, as `FSCTL_GET_NTFS_FILE_RECORD` returns it. `Ok(None)` if
/// the record has no such stream. Every offset is checked: the bytes come
/// from the file system, which a damaged or crafted volume controls.
pub fn parse_upcase_info(record: &[u8]) -> Result<Option<u64>, FileRecordError> {
    if record.get(..4) != Some(b"FILE") {
        return Err(FileRecordError::BadHeader);
    }
    let mut record = record.to_vec();
    apply_fixups(&mut record).ok_or(FileRecordError::BadHeader)?;
    let first = usize::from(u16_at(&record, 20).ok_or(FileRecordError::BadHeader)?);
    let in_use = u32_at(&record, 24)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(FileRecordError::BadHeader)?;
    let record = record.get(..in_use).ok_or(FileRecordError::BadHeader)?;
    let mut offset = first;
    for _ in 0..MAX_ATTRIBUTES {
        let bad = FileRecordError::BadAttribute { offset };
        let kind = u32_at(record, offset).ok_or(bad)?;
        if kind == ATTR_END {
            return Ok(None);
        }
        let len = u32_at(record, offset.checked_add(4).ok_or(bad)?)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(bad)?;
        // The smallest attribute header is 16 bytes; a resident one is 24.
        let attr = (len >= 16)
            .then(|| record.get(offset..offset.checked_add(len)?))
            .flatten()
            .ok_or(bad)?;
        let resident = attr.get(8) == Some(&0);
        if kind == ATTR_DATA && resident && attribute_name(attr).ok_or(bad)? == "$Info" {
            let value_len = u32_at(attr, 16)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or(bad)?;
            let value_at = usize::from(u16_at(attr, 20).ok_or(bad)?);
            let value = attr
                .get(value_at..value_at.checked_add(value_len).ok_or(bad)?)
                .ok_or(bad)?;
            return u64_at(value, 8).map(Some).ok_or(FileRecordError::ShortInfo);
        }
        offset = offset.checked_add(len).ok_or(bad)?;
    }
    Err(FileRecordError::BadAttribute { offset })
}

/// The name of an attribute (empty for an unnamed one), or `None` if it
/// runs past the attribute or is not UTF-16.
fn attribute_name(attr: &[u8]) -> Option<String> {
    let units = usize::from(*attr.get(9)?);
    let at = usize::from(u16_at(attr, 10)?);
    let raw = attr.get(at..at.checked_add(units.checked_mul(2)?)?)?;
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file record holding the given attributes, as `(type, name,
    /// resident value)`, with an update sequence array over `size` bytes.
    fn file_record(attrs: &[(u32, &str, &[u8])], size: usize) -> Vec<u8> {
        let mut r = vec![0_u8; size];
        r[..4].copy_from_slice(b"FILE");
        let strides = size / USA_STRIDE;
        r[4..6].copy_from_slice(&0x30_u16.to_le_bytes());
        r[6..8].copy_from_slice(&u16::try_from(strides + 1).unwrap().to_le_bytes());
        let first = (0x30 + 2 * (strides + 1)).next_multiple_of(8);
        r[20..22].copy_from_slice(&u16::try_from(first).unwrap().to_le_bytes());
        let mut at = first;
        for (kind, name, value) in attrs {
            let units: Vec<u16> = name.encode_utf16().collect();
            let name_at = 24;
            let value_at = (name_at + units.len() * 2).next_multiple_of(8);
            let len = (value_at + value.len()).next_multiple_of(8);
            r[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            r[at + 4..at + 8].copy_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
            r[at + 9] = u8::try_from(units.len()).unwrap();
            r[at + 10..at + 12].copy_from_slice(&u16::try_from(name_at).unwrap().to_le_bytes());
            r[at + 16..at + 20].copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
            r[at + 20..at + 22].copy_from_slice(&u16::try_from(value_at).unwrap().to_le_bytes());
            for (i, u) in units.iter().enumerate() {
                r[at + name_at + 2 * i..at + name_at + 2 * i + 2].copy_from_slice(&u.to_le_bytes());
            }
            r[at + value_at..at + value_at + value.len()].copy_from_slice(value);
            at += len;
        }
        r[at..at + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        let in_use = at + 8;
        r[24..28].copy_from_slice(&u32::try_from(in_use).unwrap().to_le_bytes());
        r[28..32].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        // Protect each stride as the disk holds it: the last two bytes are
        // saved in the array and replaced with the sequence number.
        let usn = 0x0007_u16;
        r[0x30..0x32].copy_from_slice(&usn.to_le_bytes());
        for i in 1..=strides {
            let end = i * USA_STRIDE;
            let saved = [r[end - 2], r[end - 1]];
            r[0x30 + 2 * i..0x30 + 2 * i + 2].copy_from_slice(&saved);
            r[end - 2..end].copy_from_slice(&usn.to_le_bytes());
        }
        r
    }

    fn info(crc: u64) -> Vec<u8> {
        let mut v = vec![0_u8; 32];
        v[..4].copy_from_slice(&32_u32.to_le_bytes());
        v[8..16].copy_from_slice(&crc.to_le_bytes());
        v
    }

    #[test]
    fn the_info_crc_is_read() {
        let upcase = file_record(
            &[
                (0x10, "", &[0; 48]),
                (0x30, "", &[0; 0x44]),
                (ATTR_DATA, "", &[]),
                (ATTR_DATA, "$Info", &info(STANDARD_UPCASE_CRC)),
            ],
            1024,
        );
        let crc = parse_upcase_info(&upcase).unwrap();
        assert_eq!(crc, Some(STANDARD_UPCASE_CRC));
        assert_eq!(VolumeUpcase::from_crc(crc), VolumeUpcase::Standard);
        assert!(VolumeUpcase::Standard.folds_as_standard());
        // Another CRC is another table.
        let older = file_record(&[(ATTR_DATA, "$Info", &info(0xBB10_874C_965D_2502))], 1024);
        let v = VolumeUpcase::from_crc(parse_upcase_info(&older).unwrap());
        assert_eq!(v, VolumeUpcase::Other(0xBB10_874C_965D_2502));
        assert!(!v.folds_as_standard());
        // No `$Info`: unrecorded. A non-resident or other-named data
        // stream does not count.
        let mut nonresident = file_record(&[(ATTR_DATA, "$Info", &info(1))], 1024);
        let first = usize::from(u16_at(&nonresident, 20).unwrap());
        nonresident[first + 8] = 1;
        assert_eq!(parse_upcase_info(&nonresident), Ok(None));
        let none = file_record(
            &[(ATTR_DATA, "", &[]), (ATTR_DATA, "$Inf0", &info(1))],
            1024,
        );
        assert_eq!(parse_upcase_info(&none), Ok(None));
        assert_eq!(VolumeUpcase::from_crc(None), VolumeUpcase::Unrecorded);
        assert!(!VolumeUpcase::Unrecorded.folds_as_standard());
    }

    #[test]
    fn fixups_are_applied_once_whether_or_not_the_os_did() {
        // A first attribute long enough to put `$Info`'s CRC across the
        // end of the first 512-byte stride.
        let pad = vec![0xAB_u8; 400];
        let mut r = file_record(
            &[
                (0x10, "", &pad),
                (ATTR_DATA, "$Info", &info(0x1122_3344_5566_7788)),
            ],
            1024,
        );
        assert_eq!(parse_upcase_info(&r), Ok(Some(0x1122_3344_5566_7788)));
        // As the OS may return it, already fixed up.
        apply_fixups(&mut r).unwrap();
        assert_eq!(parse_upcase_info(&r), Ok(Some(0x1122_3344_5566_7788)));
    }

    #[test]
    fn malformed_records_are_errors() {
        assert_eq!(parse_upcase_info(b""), Err(FileRecordError::BadHeader));
        assert_eq!(
            parse_upcase_info(b"BAAD\0\0\0\0"),
            Err(FileRecordError::BadHeader)
        );
        let good = file_record(&[(ATTR_DATA, "$Info", &info(1))], 1024);
        let first = usize::from(u16_at(&good, 20).unwrap());
        // Bytes in use past the end.
        let mut r = good.clone();
        r[24..28].copy_from_slice(&4096_u32.to_le_bytes());
        assert_eq!(parse_upcase_info(&r), Err(FileRecordError::BadHeader));
        // An update sequence array outside the record.
        let mut r = good.clone();
        r[4..6].copy_from_slice(&0xFFF0_u16.to_le_bytes());
        assert_eq!(parse_upcase_info(&r), Err(FileRecordError::BadHeader));
        // An attribute shorter than a header, or past the record.
        for len in [0_u32, 8, 0x1000] {
            let mut r = good.clone();
            r[first + 4..first + 8].copy_from_slice(&len.to_le_bytes());
            assert_eq!(
                parse_upcase_info(&r),
                Err(FileRecordError::BadAttribute { offset: first })
            );
        }
        // A name past the attribute.
        let mut r = good.clone();
        r[first + 9] = 200;
        assert!(matches!(
            parse_upcase_info(&r),
            Err(FileRecordError::BadAttribute { .. })
        ));
        // A value past the attribute.
        let mut r = good.clone();
        r[first + 16..first + 20].copy_from_slice(&0x400_u32.to_le_bytes());
        assert!(matches!(
            parse_upcase_info(&r),
            Err(FileRecordError::BadAttribute { .. })
        ));
        // A value too short for its CRC.
        let short = file_record(&[(ATTR_DATA, "$Info", &[0; 12])], 1024);
        assert_eq!(parse_upcase_info(&short), Err(FileRecordError::ShortInfo));
        // No end marker before the bytes in use run out.
        let mut r = file_record(&[(ATTR_DATA, "", &[])], 1024);
        let end = usize::try_from(u32_at(&r, 24).unwrap()).unwrap() - 8;
        r[end..end + 4].copy_from_slice(&0x10_u32.to_le_bytes());
        assert!(matches!(
            parse_upcase_info(&r),
            Err(FileRecordError::BadAttribute { .. })
        ));
        // Errors describe themselves.
        for e in [
            FileRecordError::BadHeader,
            FileRecordError::BadAttribute { offset: 3 },
            FileRecordError::ShortInfo,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn an_endless_attribute_chain_stops() {
        // Many tiny attributes and no end marker within the limit.
        let attrs: Vec<(u32, &str, &[u8])> = (0..300).map(|_| (0x10, "", &[][..])).collect();
        let r = file_record(&attrs, 8192);
        assert!(matches!(
            parse_upcase_info(&r),
            Err(FileRecordError::BadAttribute { .. })
        ));
    }
}
