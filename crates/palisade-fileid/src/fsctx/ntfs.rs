//! Parsers for the variable-length records that the Windows file
//! information calls return (#46, #54): the alternate data stream list
//! (`FILE_STREAM_INFO`) and the file's change-journal record (`USN_RECORD_V2`
//! or `USN_RECORD_V3`). For the file inventory (#60), also the volume's
//! journal state (`USN_JOURNAL_DATA`) and the record lists that reading the
//! journal (`FSCTL_READ_USN_JOURNAL`) and enumerating the master file table
//! (`FSCTL_ENUM_USN_DATA`) return.
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

/// The longest stream name, in UTF-16 code units, as NTFS allows.
pub const MAX_STREAM_NAME_UNITS: usize = 255;

/// The longest stream type accepted, in UTF-16 code units. The longest the
/// OS defines is `$LOGGED_UTILITY_STREAM` (22).
pub const MAX_STREAM_TYPE_UNITS: usize = 64;

/// The longest `:name:type` field accepted, in UTF-16 code units.
const MAX_FIELD_UNITS: usize = 2 + MAX_STREAM_NAME_UNITS + MAX_STREAM_TYPE_UNITS;

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
    /// Whether this is a data stream (`$DATA`, compared without regard to
    /// ASCII case, as the OS compares stream types).
    #[must_use]
    pub fn is_data(&self) -> bool {
        self.kind.eq_ignore_ascii_case("$DATA")
    }

    /// Whether this is the file's default data stream: unnamed and `$DATA`.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.name.is_empty() && self.is_data()
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
    /// The named data streams (alternate data streams): every named
    /// `$DATA` stream. Unnamed and non-data streams are left out.
    pub fn alternate(&self) -> impl Iterator<Item = &StreamEntry> {
        self.streams
            .iter()
            .filter(|s| !s.name.is_empty() && s.is_data())
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
    /// A stream name is not of the form `:name:type`, its name is longer
    /// than NTFS allows or its type longer than [`MAX_STREAM_TYPE_UNITS`],
    /// it holds a path separator or NUL, or it is not valid UTF-16.
    BadStreamName {
        /// The byte offset of the record.
        offset: usize,
    },
    /// A `NextEntryOffset` points inside its own record (its header or its
    /// name), which would overlap or loop.
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
        if name_len % 2 != 0 || name_len / 2 > MAX_FIELD_UNITS {
            return Err(RecordError::BadStreamName { offset });
        }
        let raw = STREAM_HEADER
            .checked_add(name_len)
            .and_then(|end| rec.get(STREAM_HEADER..end))
            .ok_or(RecordError::Truncated { offset })?;
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let full = String::from_utf16(&units).map_err(|_| RecordError::BadStreamName { offset })?;
        // `:name:type`, where the default stream is `::$DATA`.
        // A name or type holding a separator or NUL could change the path a
        // caller builds from it, so it is malformed.
        let plain = |t: &str| !t.contains(['\\', '/', '\0', ':']);
        let (name, kind) = full
            .strip_prefix(':')
            .and_then(|rest| rest.rsplit_once(':'))
            .filter(|(name, kind)| {
                !kind.is_empty()
                    && plain(name)
                    && plain(kind)
                    && name.encode_utf16().count() <= MAX_STREAM_NAME_UNITS
                    && kind.encode_utf16().count() <= MAX_STREAM_TYPE_UNITS
            })
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
        if next < STREAM_HEADER.saturating_add(name_len) {
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

/// The longest file name a change-journal record may carry, in UTF-16 code
/// units: the NTFS and ReFS limit.
pub const MAX_JOURNAL_NAME_UNITS: usize = 255;

/// The `USN_REASON_*` flags of a change-journal record.
pub mod reason {
    /// The default data stream was overwritten.
    pub const DATA_OVERWRITE: u32 = 0x0000_0001;
    /// The default data stream was extended.
    pub const DATA_EXTEND: u32 = 0x0000_0002;
    /// The default data stream was truncated.
    pub const DATA_TRUNCATION: u32 = 0x0000_0004;
    /// A named data stream was overwritten.
    pub const NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
    /// A named data stream was extended.
    pub const NAMED_DATA_EXTEND: u32 = 0x0000_0020;
    /// A named data stream was truncated.
    pub const NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
    /// The file or folder was created.
    pub const FILE_CREATE: u32 = 0x0000_0100;
    /// The file or folder was deleted.
    pub const FILE_DELETE: u32 = 0x0000_0200;
    /// Its extended attributes changed.
    pub const EA_CHANGE: u32 = 0x0000_0400;
    /// Its security descriptor changed.
    pub const SECURITY_CHANGE: u32 = 0x0000_0800;
    /// It was renamed; the record carries the old name.
    pub const RENAME_OLD_NAME: u32 = 0x0000_1000;
    /// It was renamed; the record carries the new name.
    pub const RENAME_NEW_NAME: u32 = 0x0000_2000;
    /// Its indexed attribute changed.
    pub const INDEXABLE_CHANGE: u32 = 0x0000_4000;
    /// Its basic information (attributes, times) changed.
    pub const BASIC_INFO_CHANGE: u32 = 0x0000_8000;
    /// A hard link was added or removed.
    pub const HARD_LINK_CHANGE: u32 = 0x0001_0000;
    /// Compression was turned on or off.
    pub const COMPRESSION_CHANGE: u32 = 0x0002_0000;
    /// Encryption was turned on or off.
    pub const ENCRYPTION_CHANGE: u32 = 0x0004_0000;
    /// Its object ID changed.
    pub const OBJECT_ID_CHANGE: u32 = 0x0008_0000;
    /// Its reparse point was added, changed or removed.
    pub const REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
    /// A named stream was added, removed or renamed.
    pub const STREAM_CHANGE: u32 = 0x0020_0000;
    /// A transacted change.
    pub const TRANSACTED_CHANGE: u32 = 0x0040_0000;
    /// Its integrity setting changed (ReFS).
    pub const INTEGRITY_CHANGE: u32 = 0x0080_0000;
    /// The last handle to the file closed: the changes above are complete.
    pub const CLOSE: u32 = 0x8000_0000;

    /// Every reason that changes what a file contains: any data or stream
    /// change. A record with one of these needs the file hashed again.
    pub const CONTENT: u32 = DATA_OVERWRITE
        | DATA_EXTEND
        | DATA_TRUNCATION
        | NAMED_DATA_OVERWRITE
        | NAMED_DATA_EXTEND
        | NAMED_DATA_TRUNCATION
        | STREAM_CHANGE
        | REPARSE_POINT_CHANGE
        | EA_CHANGE
        | HARD_LINK_CHANGE
        | TRANSACTED_CHANGE;
}

/// The state of a volume's change journal (`USN_JOURNAL_DATA_V0` and
/// later, which share these fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalData {
    /// The journal's ID. A new journal (deleted and created again) has a
    /// new ID, and every saved cursor for the old one is void.
    pub journal_id: u64,
    /// The first USN the journal ever wrote.
    pub first_usn: i64,
    /// The USN the next record will get.
    pub next_usn: i64,
    /// The oldest USN still readable. A cursor below it has missed
    /// records: the journal wrapped.
    pub lowest_valid_usn: i64,
    /// The largest USN the journal can reach.
    pub max_usn: i64,
    /// The journal's target size, in bytes.
    pub maximum_size: u64,
}

impl JournalData {
    /// Whether a cursor saved as `(journal_id, next_usn)` can still be
    /// read from without missing a record: same journal, and not below
    /// the oldest readable USN or past the next one. Anything else needs a
    /// reconciliation scan of the volume.
    #[must_use]
    pub const fn can_resume(&self, journal_id: u64, next_usn: i64) -> bool {
        journal_id == self.journal_id
            && next_usn >= self.lowest_valid_usn
            && next_usn <= self.next_usn
    }
}

/// Parses the `USN_JOURNAL_DATA` that `FSCTL_QUERY_USN_JOURNAL` returns.
pub fn parse_journal_data(bytes: &[u8]) -> Result<JournalData, RecordError> {
    let truncated = RecordError::Truncated { offset: 0 };
    let u64_at = |at| i64_at(bytes, at).map(i64::cast_unsigned).ok_or(truncated);
    let i64_get = |at| i64_at(bytes, at).ok_or(truncated);
    Ok(JournalData {
        journal_id: u64_at(0)?,
        first_usn: i64_get(8)?,
        next_usn: i64_get(16)?,
        lowest_valid_usn: i64_get(24)?,
        max_usn: i64_get(32)?,
        maximum_size: u64_at(40)?,
    })
}

/// One change-journal record (`USN_RECORD_V2` or `USN_RECORD_V3`), in full.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JournalRecord {
    /// The record version (2 or 3).
    pub major_version: u16,
    /// The file's 128-bit reference number. Version 2 records carry 64
    /// bits, zero-extended here.
    pub file_reference: [u8; 16],
    /// The reference number of the folder holding the name, the same way.
    pub parent_reference: [u8; 16],
    /// The record's update sequence number.
    pub usn: i64,
    /// When the record was written, as a `FILETIME` (100 ns since 1601).
    pub timestamp: i64,
    /// The `USN_REASON_*` flags ([`reason`]) gathered since the file was
    /// opened.
    pub reason: u32,
    /// The `USN_SOURCE_*` flags.
    pub source_info: u32,
    /// The security ID in the volume's security descriptor stream.
    pub security_id: u32,
    /// The `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// The file's name (one component, not a path).
    pub name: String,
    /// The name held an unpaired surrogate, which NTFS allows, and was
    /// decoded with replacement characters: it may equal another file's
    /// name. Never match a rule on it.
    pub name_lossy: bool,
}

impl JournalRecord {
    /// `FILE_ATTRIBUTE_DIRECTORY`.
    const DIRECTORY: u32 = 0x0010;

    /// Whether the record is about a folder.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.attributes & Self::DIRECTORY != 0
    }

    /// Whether every reason in `mask` is set.
    #[must_use]
    pub const fn has(&self, mask: u32) -> bool {
        self.reason & mask == mask
    }

    /// Whether any reason in `mask` is set.
    #[must_use]
    pub const fn has_any(&self, mask: u32) -> bool {
        self.reason & mask != 0
    }
}

/// The fixed part of a version-2 record, up to its file name.
const USN_V2_HEADER: usize = 60;
/// The fixed part of a version-3 record, up to its file name.
const USN_V3_HEADER: usize = 76;

/// Parses one full record at the start of `bytes`, which must hold the
/// whole record. Returns it and its length.
fn parse_journal_record(
    bytes: &[u8],
    offset: usize,
) -> Result<(JournalRecord, usize), RecordError> {
    let truncated = RecordError::Truncated { offset };
    let length = usize::try_from(u32_at(bytes, 0).ok_or(truncated)?).map_err(|_| truncated)?;
    let major = u16_at(bytes, 4).ok_or(truncated)?;
    let record = bytes.get(..length).ok_or(truncated)?;
    let mut file_reference = [0_u8; 16];
    let mut parent_reference = [0_u8; 16];
    // Offsets of the fields after the reference numbers.
    let (header, rest) = match major {
        2 => {
            copy_into(&mut file_reference, record.get(8..16).ok_or(truncated)?);
            copy_into(&mut parent_reference, record.get(16..24).ok_or(truncated)?);
            (USN_V2_HEADER, 24)
        }
        3 => {
            copy_into(&mut file_reference, record.get(8..24).ok_or(truncated)?);
            copy_into(&mut parent_reference, record.get(24..40).ok_or(truncated)?);
            (USN_V3_HEADER, 40)
        }
        other => return Err(RecordError::UnsupportedVersion(other)),
    };
    if length < header {
        return Err(truncated);
    }
    let field = |at: usize| u32_at(record, rest + at).ok_or(truncated);
    let name_len = usize::from(u16_at(record, rest + 32).ok_or(truncated)?);
    let name_offset = usize::from(u16_at(record, rest + 34).ok_or(truncated)?);
    let bad_name = RecordError::BadStreamName { offset };
    if name_len % 2 != 0 || name_len / 2 > MAX_JOURNAL_NAME_UNITS || name_offset < header {
        return Err(bad_name);
    }
    let name_bytes = record
        .get(name_offset..name_offset.checked_add(name_len).ok_or(truncated)?)
        .ok_or(truncated)?;
    let units: Vec<u16> = name_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    if units.is_empty() || units.iter().any(|&u| u == 0 || u == u16::from(b'\\')) {
        return Err(bad_name);
    }
    let (name, name_lossy) = match String::from_utf16(&units) {
        Ok(n) => (n, false),
        Err(_) => (String::from_utf16_lossy(&units), true),
    };
    Ok((
        JournalRecord {
            major_version: major,
            file_reference,
            parent_reference,
            usn: i64_at(record, rest).ok_or(truncated)?,
            timestamp: i64_at(record, rest + 8).ok_or(truncated)?,
            reason: field(16)?,
            source_info: field(20)?,
            security_id: field(24)?,
            attributes: field(28)?,
            name,
            name_lossy,
        },
        length,
    ))
}

fn copy_into(dst: &mut [u8; 16], src: &[u8]) {
    if let Some(d) = dst.get_mut(..src.len()) {
        d.copy_from_slice(src);
    }
}

/// The records after the 8-byte cursor that both journal reads start with.
/// A record that is short, overlaps the next or is of another version fails
/// the whole buffer: a change the agent cannot read must never be skipped
/// silently.
fn parse_records(bytes: &[u8]) -> Result<Vec<JournalRecord>, RecordError> {
    let mut out = Vec::new();
    let mut at = 8;
    while at < bytes.len() {
        let rest = bytes.get(at..).unwrap_or_default();
        let (record, length) = parse_journal_record(rest, at)?;
        // Each record is at least its header long, so this always moves.
        out.push(record);
        at = at
            .checked_add(length)
            .ok_or(RecordError::Truncated { offset: at })?;
    }
    Ok(out)
}

/// Parses the output of `FSCTL_READ_USN_JOURNAL`: the USN to read from
/// next, then the records. The cursor is only advanced to the returned USN
/// once every record has been handled.
pub fn parse_read_journal(bytes: &[u8]) -> Result<(i64, Vec<JournalRecord>), RecordError> {
    let next = i64_at(bytes, 0).ok_or(RecordError::Truncated { offset: 0 })?;
    Ok((next, parse_records(bytes)?))
}

/// Parses the output of `FSCTL_ENUM_USN_DATA`, which lists every file and
/// folder of a volume from its master file table: the file reference to
/// continue from, then one record per file.
pub fn parse_enum_usn_data(bytes: &[u8]) -> Result<(u64, Vec<JournalRecord>), RecordError> {
    let next = i64_at(bytes, 0)
        .map(i64::cast_unsigned)
        .ok_or(RecordError::Truncated { offset: 0 })?;
    Ok((next, parse_records(bytes)?))
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
        while !first.len().is_multiple_of(8) {
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
        // Unnamed or non-data streams are neither default nor alternate.
        let mut odd = stream_record(0, "::$INDEX_ALLOCATION", 0);
        while !odd.len().is_multiple_of(8) {
            odd.push(0);
        }
        let next = u32::try_from(odd.len()).unwrap();
        odd[..4].copy_from_slice(&next.to_le_bytes());
        let mut tail = stream_record(0, ":$EFS:$LOGGED_UTILITY_STREAM", 0);
        while !tail.len().is_multiple_of(8) {
            tail.push(0);
        }
        let next2 = u32::try_from(tail.len()).unwrap();
        tail[..4].copy_from_slice(&next2.to_le_bytes());
        odd.extend(tail);
        odd.extend(stream_record(0, ":lower:$data", 1));
        let list = parse_stream_info(&odd).unwrap();
        assert_eq!(list.streams.len(), 3);
        assert!(!list.streams[0].is_default());
        assert_eq!(
            list.alternate()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            ["lower"],
            "a lower-case `$data` type is still data"
        );
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
        // Separators and NUL in the name or type.
        for bad in [":a\\..\\b:$DATA", ":a/b:$DATA", ":a\0:$DATA", ":a:$DA/TA"] {
            assert!(
                matches!(
                    parse_stream_info(&stream_record(0, bad, 1)),
                    Err(RecordError::BadStreamName { .. })
                ),
                "{bad:?}"
            );
        }
        // A 255-unit name with the longest OS type is fine; 256 is not.
        let max = format!(":{}:$LOGGED_UTILITY_STREAM", "n".repeat(255));
        assert_eq!(
            parse_stream_info(&stream_record(0, &max, 1))
                .unwrap()
                .streams[0]
                .kind,
            "$LOGGED_UTILITY_STREAM"
        );
        let over = format!(":{}:x", "n".repeat(256));
        assert!(matches!(
            parse_stream_info(&stream_record(0, &over, 1)),
            Err(RecordError::BadStreamName { .. })
        ));
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
        let mut surrogate = stream_record(0, "::$DATA", 1);
        surrogate[24] = 0x00;
        surrogate[25] = 0xd8;
        assert!(matches!(
            parse_stream_info(&surrogate),
            Err(RecordError::BadStreamName { .. })
        ));
        // A next offset inside the header, which would loop, or inside the
        // record's own name, which would overlap.
        for next in [8, 24, 24 + 12] {
            let rec = stream_record(next, "::$DATA", 1);
            assert!(
                matches!(
                    parse_stream_info(&rec),
                    Err(RecordError::BadNextOffset { .. })
                ),
                "{next}"
            );
        }
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
        while !one.len().is_multiple_of(8) {
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

    /// A full journal record of `version` (2 or 3) for `name`, padded to 8
    /// bytes as the OS pads it.
    fn journal_record(
        version: u16,
        id: u8,
        parent: u8,
        usn: i64,
        reason: u32,
        name: &str,
    ) -> Vec<u8> {
        let (header, rest, id_len) = if version == 2 {
            (60, 24, 8)
        } else {
            (76, 40, 16)
        };
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut r = vec![0_u8; header];
        r[4..6].copy_from_slice(&version.to_le_bytes());
        r[8..8 + id_len].fill(id);
        r[8 + id_len..8 + 2 * id_len].fill(parent);
        r[rest..rest + 8].copy_from_slice(&usn.to_le_bytes());
        r[rest + 8..rest + 16].copy_from_slice(&1234_i64.to_le_bytes());
        r[rest + 16..rest + 20].copy_from_slice(&reason.to_le_bytes());
        r[rest + 28..rest + 32].copy_from_slice(&0x20_u32.to_le_bytes());
        r[rest + 32..rest + 34]
            .copy_from_slice(&u16::try_from(units.len() * 2).unwrap().to_le_bytes());
        r[rest + 34..rest + 36].copy_from_slice(&u16::try_from(header).unwrap().to_le_bytes());
        for u in units {
            r.extend_from_slice(&u.to_le_bytes());
        }
        while !r.len().is_multiple_of(8) {
            r.push(0);
        }
        let len = u32::try_from(r.len()).unwrap();
        r[..4].copy_from_slice(&len.to_le_bytes());
        r
    }

    fn with_cursor(cursor: i64, records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = cursor.to_le_bytes().to_vec();
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    #[test]
    fn journal_reads() {
        let buf = with_cursor(
            900,
            &[
                journal_record(2, 7, 5, 800, reason::FILE_CREATE | reason::CLOSE, "a.exe"),
                journal_record(3, 9, 6, 850, reason::RENAME_NEW_NAME, "b.dll"),
            ],
        );
        let (next, records) = parse_read_journal(&buf).unwrap();
        assert_eq!(next, 900);
        assert_eq!(records.len(), 2);
        let a = &records[0];
        assert_eq!((a.major_version, a.usn, a.timestamp), (2, 800, 1234));
        assert_eq!(a.file_reference[..8], [7; 8]);
        assert_eq!(a.file_reference[8..], [0; 8]);
        assert_eq!(a.parent_reference[..8], [5; 8]);
        assert_eq!(a.name, "a.exe");
        assert!(!a.name_lossy && !a.is_directory());
        assert_eq!(a.attributes, 0x20);
        assert!(a.has(reason::FILE_CREATE | reason::CLOSE));
        assert!(!a.has(reason::FILE_DELETE | reason::CLOSE));
        assert!(a.has_any(reason::FILE_DELETE | reason::CLOSE));
        assert!(!a.has_any(reason::CONTENT));
        let b = &records[1];
        assert_eq!(
            (b.major_version, b.file_reference, b.parent_reference),
            (3, [9; 16], [6; 16])
        );
        assert_eq!(b.name, "b.dll");

        // A cursor and nothing else is an empty read.
        assert_eq!(
            parse_read_journal(&with_cursor(5, &[])).unwrap(),
            (5, Vec::new())
        );
        // The enumeration's cursor is a file reference.
        let (next, records) =
            parse_enum_usn_data(&with_cursor(-1, &[journal_record(2, 1, 1, 0, 0, "x")])).unwrap();
        assert_eq!((next, records.len()), (u64::MAX, 1));
        assert!(parse_enum_usn_data(&[1, 2]).is_err());
        assert!(parse_read_journal(&[]).is_err());
    }

    #[test]
    fn folders_and_lossy_names() {
        let mut dir = journal_record(2, 1, 1, 0, 0, "d");
        dir[52..56].copy_from_slice(&0x10_u32.to_le_bytes());
        let (_, r) = parse_read_journal(&with_cursor(0, &[dir])).unwrap();
        assert!(r[0].is_directory());
        // An unpaired surrogate, which NTFS allows, decodes lossily and
        // says so.
        let mut odd = journal_record(2, 1, 1, 0, 0, "ab");
        odd[60..62].copy_from_slice(&0xd800_u16.to_le_bytes());
        let (_, r) = parse_read_journal(&with_cursor(0, &[odd])).unwrap();
        assert!(r[0].name_lossy);
        assert_eq!(r[0].name.chars().next(), Some(char::REPLACEMENT_CHARACTER));
    }

    #[test]
    fn malformed_journal_records_fail_the_whole_read() {
        let good = journal_record(2, 1, 1, 0, 0, "ok");
        let check = |bad: Vec<u8>, what: &str| {
            assert!(
                parse_read_journal(&with_cursor(0, &[good.clone(), bad])).is_err(),
                "{what}"
            );
        };
        // A record length of zero, shorter than its header, or past the end.
        let mut r = good.clone();
        r[..4].copy_from_slice(&0_u32.to_le_bytes());
        check(r, "zero length");
        let mut r = good.clone();
        r[..4].copy_from_slice(&40_u32.to_le_bytes());
        check(r, "shorter than the header");
        let mut r = good.clone();
        r[..4].copy_from_slice(&4096_u32.to_le_bytes());
        check(r, "past the end");
        // Another version.
        let mut r = good.clone();
        r[4..6].copy_from_slice(&4_u16.to_le_bytes());
        check(r, "version 4");
        // An odd, empty or over-long name, one that starts inside the
        // header or runs past the record, and a name with NUL or `\`.
        for (len, off, what) in [
            (3_u16, 60_u16, "odd"),
            (0, 60, "empty"),
            (512, 60, "too long"),
            (4, 40, "inside the header"),
            (4, 62, "past the record"),
        ] {
            let mut r = good.clone();
            r[56..58].copy_from_slice(&len.to_le_bytes());
            r[58..60].copy_from_slice(&off.to_le_bytes());
            check(r, what);
        }
        for bad in ["a\\b", "a\0b"] {
            check(journal_record(2, 1, 1, 0, 0, bad), bad);
        }
        // A truncated cursor-only buffer and a truncated record.
        let mut cut = with_cursor(0, std::slice::from_ref(&good));
        cut.truncate(cut.len() - 9);
        assert!(parse_read_journal(&cut).is_err());
        let mut v3 = journal_record(3, 1, 1, 0, 0, "x");
        v3[..4].copy_from_slice(&70_u32.to_le_bytes());
        check(v3, "v3 shorter than its header");
    }

    #[test]
    fn journal_data_and_resume() {
        let mut b = vec![0_u8; 64];
        for (i, v) in [7_i64, 10, 500, 100, i64::MAX, 32 << 20]
            .into_iter()
            .enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        let j = parse_journal_data(&b).unwrap();
        assert_eq!(
            j,
            JournalData {
                journal_id: 7,
                first_usn: 10,
                next_usn: 500,
                lowest_valid_usn: 100,
                max_usn: i64::MAX,
                maximum_size: 32 << 20,
            }
        );
        assert!(j.can_resume(7, 100));
        assert!(j.can_resume(7, 500));
        assert!(!j.can_resume(8, 200), "another journal");
        assert!(!j.can_resume(7, 99), "the journal wrapped past the cursor");
        assert!(!j.can_resume(7, 501), "a cursor from the future");
        assert!(parse_journal_data(&b[..47]).is_err());
    }
}
