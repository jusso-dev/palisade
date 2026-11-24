//! Parsers for the variable-length records that the Windows file
//! information calls return (#46, #54): the alternate data stream list
//! (`FILE_STREAM_INFO`) and the file's change-journal record (`USN_RECORD_V2`
//! or `USN_RECORD_V3`).
//!
//! The Windows backend (`palisade_fileid::win`) fills a byte buffer from the
//! OS and hands it here, so the parsing is pure, bounded and tested on every
//! OS. The bytes come from the file system, not from file content, but a
//! filter driver or a damaged volume can still return anything, so every
//! offset and length is checked and nothing panics.

#![forbid(unsafe_code)]

use std::fmt;

/// The most streams listed for one file. A file can have far more; the rest
/// are reported as [`StreamList::truncated`].
pub const MAX_STREAMS: usize = 4096;

/// The longest stream name, in UTF-16 code units, as NTFS allows (255),
/// plus the `:` prefix and the `:$DATA` suffix.
const MAX_STREAM_NAME_UNITS: usize = 255 + 7;

/// One data stream of a file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamEntry {
    /// The stream name without the leading `:` or the `:$DATA` type, so the
    /// default stream is `""` and `file.txt:Zone.Identifier` is
    /// `Zone.Identifier`.
    pub name: String,
    /// The stream type as the OS reports it (`$DATA` for every stream that
    /// holds data).
    pub kind: String,
    /// The stream size in bytes.
    pub size: u64,
    /// The bytes allocated on disk for the stream.
    pub allocation_size: u64,
}

impl StreamEntry {
    /// Whether this is the file's default (unnamed) data stream.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.name.is_empty()
    }
}

/// The streams of one file, in the order the OS lists them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamList {
    /// The streams read.
    pub streams: Vec<StreamEntry>,
    /// More than [`MAX_STREAMS`] were listed; the rest were not read.
    pub truncated: bool,
}

impl StreamList {
    /// The named data streams: every stream except the default one.
    pub fn alternate(&self) -> impl Iterator<Item = &StreamEntry> {
        self.streams.iter().filter(|s| !s.is_default())
    }
}

/// Why a record could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordError {
    /// A record or one of its fields runs past the buffer.
    Truncated {
        /// The byte offset of the record.
        offset: usize,
    },
    /// A stream name is not of the form `:name:type`, is longer than NTFS
    /// allows, or is not valid UTF-16.
    BadStreamName {
        /// The byte offset of the record.
        offset: usize,
    },
    /// A `NextEntryOffset` points backwards or inside its own header, which
    /// would loop.
    BadNextOffset {
        /// The byte offset of the record.
        offset: usize,
    },
    /// The record is not a version-2 or version-3 change-journal record.
    UnsupportedVersion(u16),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset } => write!(f, "record at offset {offset} is truncated"),
            Self::BadStreamName { offset } => {
                write!(f, "record at offset {offset} has a malformed stream name")
            }
            Self::BadNextOffset { offset } => {
                write!(f, "record at offset {offset} has a bad next-entry offset")
            }
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported change-journal record version {v}")
            }
        }
    }
}

impl std::error::Error for RecordError {}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let bytes = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let bytes = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn i64_at(b: &[u8], at: usize) -> Option<i64> {
    let bytes = b.get(at..at.checked_add(8)?)?;
    Some(i64::from_le_bytes(bytes.try_into().ok()?))
}

/// The fixed part of `FILE_STREAM_INFO`: `NextEntryOffset`,
/// `StreamNameLength`, `StreamSize` and `StreamAllocationSize`.
const STREAM_HEADER: usize = 24;

/// Parses the `FILE_STREAM_INFO` list that `GetFileInformationByHandleEx`
/// returns for `FileStreamInfo`. An empty buffer is a file with no streams
/// (a directory without named streams).
pub fn parse_stream_info(bytes: &[u8]) -> Result<StreamList, RecordError> {
    let mut list = StreamList::default();
    if bytes.is_empty() {
        return Ok(list);
    }
    let mut offset = 0_usize;
    loop {
        if list.streams.len() >= MAX_STREAMS {
            list.truncated = true;
            break;
        }
        let rec = bytes
            .get(offset..)
            .ok_or(RecordError::Truncated { offset })?;
        let (Some(next), Some(name_len), Some(size), Some(alloc)) = (
            u32_at(rec, 0),
            u32_at(rec, 4),
            i64_at(rec, 8),
            i64_at(rec, 16),
        ) else {
            return Err(RecordError::Truncated { offset });
        };
        let name_len = usize::try_from(name_len).map_err(|_| RecordError::Truncated { offset })?;
        if name_len % 2 != 0 || name_len / 2 > MAX_STREAM_NAME_UNITS {
            return Err(RecordError::BadStreamName { offset });
        }
        let raw = STREAM_HEADER
            .checked_add(name_len)
            .and_then(|end| rec.get(STREAM_HEADER..end))
            .ok_or(RecordError::Truncated { offset })?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| {
                u16::from_le_bytes([
                    c.first().copied().unwrap_or(0),
                    c.get(1).copied().unwrap_or(0),
                ])
            })
            .collect();
        let full = String::from_utf16(&units).map_err(|_| RecordError::BadStreamName { offset })?;
        // `:name:type`, where the default stream is `::$DATA`.
        let (name, kind) = full
            .strip_prefix(':')
            .and_then(|rest| rest.rsplit_once(':'))
            .filter(|(name, kind)| !kind.is_empty() && !name.contains(':'))
            .ok_or(RecordError::BadStreamName { offset })?;
        list.streams.push(StreamEntry {
            name: name.to_owned(),
            kind: kind.to_owned(),
            size: u64::try_from(size).unwrap_or(0),
            allocation_size: u64::try_from(alloc).unwrap_or(0),
        });
        if next == 0 {
            break;
        }
        let next = usize::try_from(next).map_err(|_| RecordError::BadNextOffset { offset })?;
        if next < STREAM_HEADER {
            return Err(RecordError::BadNextOffset { offset });
        }
        offset = offset
            .checked_add(next)
            .ok_or(RecordError::BadNextOffset { offset })?;
    }
    Ok(list)
}

/// The change-journal facts in a file's USN record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UsnFacts {
    /// The record version (2 or 3).
    pub major_version: u16,
    /// The file's last update sequence number.
    pub usn: i64,
    /// The 128-bit file reference number as the record gives it. Version 2
    /// records carry 64 bits, zero-extended here.
    pub file_reference: [u8; 16],
}

/// Parses the `USN_RECORD_V2` or `USN_RECORD_V3` that
/// `FSCTL_READ_FILE_USN_DATA` returns.
pub fn parse_usn_record(bytes: &[u8]) -> Result<UsnFacts, RecordError> {
    let truncated = RecordError::Truncated { offset: 0 };
    let length = u32_at(bytes, 0).ok_or(truncated)?;
    let major = u16_at(bytes, 4).ok_or(truncated)?;
    let length = usize::try_from(length).map_err(|_| truncated)?;
    let record = bytes.get(..length).ok_or(truncated)?;
    let mut file_reference = [0_u8; 16];
    let usn = match major {
        2 => {
            // RecordLength, versions, FileReferenceNumber (8),
            // ParentFileReferenceNumber (8), then Usn.
            let id = record.get(8..16).ok_or(truncated)?;
            if let Some(dst) = file_reference.get_mut(..8) {
                dst.copy_from_slice(id);
            }
            i64_at(record, 24).ok_or(truncated)?
        }
        3 => {
            // As version 2, with 16-byte reference numbers.
            let id = record.get(8..24).ok_or(truncated)?;
            file_reference.copy_from_slice(id);
            i64_at(record, 40).ok_or(truncated)?
        }
        other => return Err(RecordError::UnsupportedVersion(other)),
    };
    Ok(UsnFacts {
        major_version: major,
        usn,
        file_reference,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_record(next: u32, name: &str, size: i64) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut out = Vec::new();
        out.extend_from_slice(&next.to_le_bytes());
        out.extend_from_slice(&u32::try_from(units.len() * 2).unwrap().to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(size + 7).to_le_bytes());
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    /// Two records with the first's `NextEntryOffset` set, padded to 8 bytes
    /// as the OS does.
    fn two(a: &str, b: &str) -> Vec<u8> {
        let mut first = stream_record(0, a, 10);
        while first.len() % 8 != 0 {
            first.push(0);
        }
        let next = u32::try_from(first.len()).unwrap();
        first[..4].copy_from_slice(&next.to_le_bytes());
        first.extend(stream_record(0, b, 3));
        first
    }

    #[test]
    fn streams() {
        assert_eq!(parse_stream_info(&[]).unwrap(), StreamList::default());
        let list = parse_stream_info(&two("::$DATA", ":Zone.Identifier:$DATA")).unwrap();
        assert_eq!(list.streams.len(), 2);
        assert!(list.streams[0].is_default());
        assert_eq!(list.streams[0].size, 10);
        assert_eq!(list.streams[0].allocation_size, 17);
        assert_eq!(list.streams[1].name, "Zone.Identifier");
        assert_eq!(list.streams[1].kind, "$DATA");
        assert_eq!(
            list.alternate()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            ["Zone.Identifier"]
        );
        assert!(!list.truncated);
    }

    #[test]
    fn malformed_streams_are_errors() {
        // Truncated header and name.
        assert!(matches!(
            parse_stream_info(&[0; 10]),
            Err(RecordError::Truncated { .. })
        ));
        let mut rec = stream_record(0, "::$DATA", 1);
        rec.truncate(rec.len() - 2);
        assert!(matches!(
            parse_stream_info(&rec),
            Err(RecordError::Truncated { .. })
        ));
        // Names that are not `:name:type`.
        for bad in ["Zone", ":Zone", ":a:b:$DATA", ":Zone:"] {
            assert!(
                matches!(
                    parse_stream_info(&stream_record(0, bad, 1)),
                    Err(RecordError::BadStreamName { .. })
                ),
                "{bad}"
            );
        }
        // An odd name length, and one longer than NTFS allows.
        let mut odd = stream_record(0, "::$DATA", 1);
        odd[4] = 3;
        assert!(matches!(
            parse_stream_info(&odd),
            Err(RecordError::BadStreamName { .. })
        ));
        let long = format!(":{}:$DATA", "a".repeat(300));
        assert!(matches!(
            parse_stream_info(&stream_record(0, &long, 1)),
            Err(RecordError::BadStreamName { .. })
        ));
        // Unpaired surrogate.
        let mut sur = stream_record(0, "::$DATA", 1);
        sur[24] = 0x00;
        sur[25] = 0xd8;
        assert!(matches!(
            parse_stream_info(&sur),
            Err(RecordError::BadStreamName { .. })
        ));
        // A next offset inside the header, which would loop.
        let rec = stream_record(8, "::$DATA", 1);
        assert!(matches!(
            parse_stream_info(&rec),
            Err(RecordError::BadNextOffset { .. })
        ));
        // A next offset past the end.
        let rec = stream_record(4096, "::$DATA", 1);
        assert!(matches!(
            parse_stream_info(&rec),
            Err(RecordError::Truncated { .. })
        ));
        // A negative size reads as zero, never wraps.
        let list = parse_stream_info(&stream_record(0, "::$DATA", -5)).unwrap();
        assert_eq!(list.streams[0].size, 0);
    }

    #[test]
    fn stream_count_is_bounded() {
        let mut one = stream_record(0, ":s:$DATA", 1);
        while one.len() % 8 != 0 {
            one.push(0);
        }
        let step = u32::try_from(one.len()).unwrap();
        one[..4].copy_from_slice(&step.to_le_bytes());
        let mut all = Vec::new();
        for _ in 0..MAX_STREAMS + 5 {
            all.extend_from_slice(&one);
        }
        let list = parse_stream_info(&all).unwrap();
        assert_eq!(list.streams.len(), MAX_STREAMS);
        assert!(list.truncated);
    }

    fn usn_v2(usn: i64) -> Vec<u8> {
        let mut r = vec![0_u8; 64];
        r[..4].copy_from_slice(&64_u32.to_le_bytes());
        r[4..6].copy_from_slice(&2_u16.to_le_bytes());
        r[8..16].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
        r[24..32].copy_from_slice(&usn.to_le_bytes());
        r
    }

    #[test]
    fn usn_records() {
        let f = parse_usn_record(&usn_v2(12345)).unwrap();
        assert_eq!((f.major_version, f.usn), (2, 12345));
        assert_eq!(
            f.file_reference[..8],
            0x1122_3344_5566_7788_u64.to_le_bytes()
        );
        assert_eq!(f.file_reference[8..], [0; 8]);

        let mut v3 = vec![0_u8; 80];
        v3[..4].copy_from_slice(&80_u32.to_le_bytes());
        v3[4..6].copy_from_slice(&3_u16.to_le_bytes());
        v3[8..24].copy_from_slice(&[9; 16]);
        v3[40..48].copy_from_slice(&77_i64.to_le_bytes());
        let f = parse_usn_record(&v3).unwrap();
        assert_eq!((f.major_version, f.usn, f.file_reference), (3, 77, [9; 16]));

        // Version 4 has no USN in this place; other versions are refused.
        let mut v4 = usn_v2(1);
        v4[4..6].copy_from_slice(&4_u16.to_le_bytes());
        assert_eq!(
            parse_usn_record(&v4),
            Err(RecordError::UnsupportedVersion(4))
        );
        // RecordLength past the buffer, or too short for the USN.
        let mut long = usn_v2(1);
        long[..4].copy_from_slice(&1000_u32.to_le_bytes());
        assert!(parse_usn_record(&long).is_err());
        let mut short = usn_v2(1);
        short[..4].copy_from_slice(&20_u32.to_le_bytes());
        assert!(parse_usn_record(&short).is_err());
        assert!(parse_usn_record(&[]).is_err());
    }
}
