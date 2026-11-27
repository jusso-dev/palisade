//! A strict, bounded ZIP reader for app packages (OPC containers).
//!
//! App packages are ZIP files written by packaging tools in one
//! predictable shape, so this reader accepts only that shape and rejects
//! everything ZIP readers disagree about. A package that reads here reads
//! the same in every reader, so its signature and identity cannot depend
//! on which reader looked at it:
//!
//! - exactly one end-of-central-directory record, found at the very end
//!   (an archive comment is not allowed), and, when the archive needs
//!   ZIP64, exactly one ZIP64 locator and record right before it, with
//!   counts, sizes and offsets that agree with the classic record;
//! - one disk only (with ZIP64, the classic record's two disk numbers may
//!   both be the `0xffff` marker, as the OS packaging tool writes them; the
//!   ZIP64 record's must still be 0);
//! - the central directory runs from its stated offset to the ZIP64
//!   record or the end record, with no gap and nothing after it;
//! - local entries tile the file from offset 0 to the central directory
//!   in central-directory order: each local header, its data and its data
//!   descriptor end where the next local header starts;
//! - a data descriptor's sizes are 8 bytes when the archive has ZIP64 end
//!   records or the entry a ZIP64 extra field, and 4 bytes otherwise (the
//!   OS packaging tool writes ZIP64 archives with 8-byte descriptor sizes
//!   for every entry, extra field or not, and signing tools read them that
//!   way);
//! - each local header agrees with its central entry (name, method,
//!   flags, CRC and sizes, or zero for those three when a data descriptor
//!   follows, which must carry its signature and whose values must then
//!   agree);
//! - a central entry's extra data, if any, is exactly one ZIP64 block with
//!   exactly the fields its `0xffffffff` markers call for (the package
//!   digest writes entries that way, so anything else would be read
//!   differently from how it is signed);
//! - names, and their percent-decoded OPC part names, are valid UTF-8, not
//!   empty, without `\`, a leading `/`, empty, `.` or `..` segments, or
//!   NUL; and part names are unique compared ASCII-case-insensitively, as
//!   OPC compares them, so two spellings of one part are a duplicate;
//! - extra data, in a local header or a central entry, is either empty or
//!   exactly one ZIP64 block with exactly the fields its `0xffffffff`
//!   markers call for (none with a data descriptor);
//! - method 0 (stored, sizes equal) or 8 (deflate); no encryption, no
//!   patch data, no strong encryption flags;
//! - every member's data inflates to exactly its declared size and CRC.
//!
//! Member reads are bounded by [`MAX_MEMBER_SIZE`], and the whole archive
//! by [`MAX_ENTRIES`]. Inflation is streamed in fixed chunks with a size
//! cap, so a small member cannot claim gigabytes.

#![forbid(unsafe_code)]

use std::fmt;

/// The most central directory entries.
pub const MAX_ENTRIES: usize = 65_535;
/// The largest member decompressed into memory: 64 MiB.
pub const MAX_MEMBER_SIZE: u64 = 64 * 1024 * 1024;

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const DESCRIPTOR_SIG: u32 = 0x0807_4b50;

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_DESCRIPTOR: u16 = 0x0008;
const FLAG_PATCH: u16 = 0x0020;
const FLAG_STRONG: u16 = 0x0040;
const FLAG_UTF8: u16 = 0x0800;
const FLAG_MASKED: u16 = 0x2000;

/// Why an archive is not one this reader accepts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZipError {
    /// No end-of-central-directory record at the end of the file, or a
    /// comment after it, or more than one.
    EndRecord,
    /// The ZIP64 records are missing where needed, present where not,
    /// or disagree with the classic record.
    Zip64,
    /// More than one disk.
    MultiDisk,
    /// The central directory is malformed or not where it says.
    CentralDirectory,
    /// Too many entries.
    TooManyEntries,
    /// A local header is malformed, disagrees with its central entry, or
    /// is not where the tiling requires.
    LocalHeader(String),
    /// A name is not acceptable (see the module documentation).
    BadName(String),
    /// Two entries have the same name.
    DuplicateName(String),
    /// An unsupported method or flag (encryption, patch data).
    Unsupported(String),
    /// A member's data does not inflate to its declared size and CRC.
    Corrupt(String),
    /// A member is larger than [`MAX_MEMBER_SIZE`].
    TooLarge(String),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndRecord => f.write_str("no single end-of-central-directory record at the end"),
            Self::Zip64 => f.write_str("ZIP64 records missing, unexpected or inconsistent"),
            Self::MultiDisk => f.write_str("multi-disk archives are not supported"),
            Self::CentralDirectory => f.write_str("malformed central directory"),
            Self::TooManyEntries => write!(f, "more than {MAX_ENTRIES} entries"),
            Self::LocalHeader(n) => write!(f, "local header of {n:?} is inconsistent"),
            Self::BadName(n) => write!(f, "unacceptable member name {n:?}"),
            Self::DuplicateName(n) => write!(f, "duplicate member name {n:?}"),
            Self::Unsupported(n) => write!(f, "unsupported method or flags in {n:?}"),
            Self::Corrupt(n) => write!(f, "member {n:?} does not match its size and CRC"),
            Self::TooLarge(n) => write!(f, "member {n:?} exceeds {MAX_MEMBER_SIZE} bytes"),
        }
    }
}

impl std::error::Error for ZipError {}

type Result<T> = std::result::Result<T, ZipError>;

/// One member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The name, as stored.
    pub name: String,
    /// The OPC part name: [`Self::name`] percent-decoded. Names are checked
    /// and compared in this form, so two spellings of one part are one
    /// name.
    pub part: String,
    /// Whether the central entry carries a ZIP64 extra field, which makes
    /// its data descriptor use 8-byte sizes.
    pub has_zip64_extra: bool,
    /// 0 stored, 8 deflate.
    pub method: u16,
    /// The CRC-32.
    pub crc32: u32,
    /// Compressed size.
    pub compressed_size: u64,
    /// Uncompressed size.
    pub size: u64,
    /// Offset of the local header.
    pub local_offset: u64,
    /// Offset of the data.
    pub data_offset: u64,
    /// Offset just past the data and any data descriptor: the next local
    /// header, or the central directory.
    pub end_offset: u64,
    /// The raw central directory entry (header, name, extra, comment).
    pub central_raw: (usize, usize),
}

/// A parsed archive.
#[derive(Debug, Clone)]
pub struct Archive<'a> {
    data: &'a [u8],
    /// Members, in central-directory (and so file) order.
    pub members: Vec<Member>,
    /// Offset of the central directory.
    pub central_offset: u64,
    /// Offset just past the central directory: where the ZIP64 record or
    /// the end record starts.
    pub central_end: u64,
    /// Whether the archive has ZIP64 end records.
    pub zip64: bool,
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
    d.get(at..at.checked_add(8)?)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
}

fn to_usize(v: u64) -> Option<usize> {
    usize::try_from(v).ok()
}

/// The ZIP64 extended information extra field (ID 1): the 64-bit values
/// for each 32-bit field that is `0xffffffff`, in order.
fn zip64_extra(extra: &[u8], want: [bool; 3]) -> Option<[Option<u64>; 3]> {
    // Empty, or exactly one ZIP64 block (ID 1) and nothing else, and only
    // when a field calls for it.
    let mut out = [None; 3];
    if extra.is_empty() {
        return want.iter().all(|w| !w).then_some(out);
    }
    if !want.iter().any(|&w| w) || u16_at(extra, 0)? != 1 {
        return None;
    }
    let len = usize::from(u16_at(extra, 2)?);
    if extra.len() != 4 + len {
        return None;
    }
    let body = extra.get(4..)?;
    let mut pos = 0;
    for (slot, &w) in out.iter_mut().zip(&want) {
        if w {
            *slot = Some(u64_at(body, pos)?);
            pos += 8;
        }
    }
    // Nothing after the values we need (a disk number would be at the
    // end, and is not allowed here).
    (pos == body.len()).then_some(out)
}

/// Percent-decodes an OPC part name. `None` for a bad escape or a result
/// that is not UTF-8.
pub fn decode_part_name(name: &str) -> Option<String> {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let s = std::str::from_utf8(hex).ok()?;
            let v = u8::from_str_radix(s, 16).ok()?;
            // OPC forbids an escaped `/` or `\` in a segment.
            if v == b'/' || v == b'\\' {
                return None;
            }
            out.push(v);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The folded form names are compared in: ASCII case-insensitive, as OPC
/// part names are.
#[must_use]
pub fn fold(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn check_name(name: &str) -> Result<()> {
    let bad = || ZipError::BadName(name.to_owned());
    if name.is_empty() || name.starts_with('/') || name.contains('\\') || name.contains('\0') {
        return Err(bad());
    }
    // A directory entry ends with `/`; every other segment must be a real
    // name.
    let body = name.strip_suffix('/').unwrap_or(name);
    if body
        .split('/')
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(bad());
    }
    Ok(())
}

fn crc32(data: &[u8], mut crc: u32) -> u32 {
    crc = !crc;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

impl<'a> Archive<'a> {
    /// Parses `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let len = data.len();
        // The end record is the last 22 bytes: no comment.
        let eocd = len.checked_sub(22).ok_or(ZipError::EndRecord)?;
        if u32_at(data, eocd) != Some(EOCD_SIG) || u16_at(data, eocd + 20) != Some(0) {
            return Err(ZipError::EndRecord);
        }
        let field16 = |o| u16_at(data, eocd + o).ok_or(ZipError::EndRecord);
        let field32 = |o| u32_at(data, eocd + o).ok_or(ZipError::EndRecord);
        let (disk, cd_disk) = (field16(4)?, field16(6)?);
        let (n_disk, n_total) = (field16(8)?, field16(10)?);
        let (cd_size32, cd_off32) = (field32(12)?, field32(16)?);

        let needs64 =
            n_total == 0xffff || n_disk == 0xffff || cd_size32 == u32::MAX || cd_off32 == u32::MAX;
        let has_locator = eocd >= 20 && u32_at(data, eocd - 20) == Some(ZIP64_LOCATOR_SIG);
        let (entries, cd_size, cd_off, cd_end, zip64) = if has_locator {
            let loc = eocd - 20;
            if u32_at(data, loc + 4) != Some(0) || u32_at(data, loc + 16) != Some(1) {
                return Err(ZipError::MultiDisk);
            }
            let rec = u64_at(data, loc + 8)
                .and_then(to_usize)
                .ok_or(ZipError::Zip64)?;
            if u32_at(data, rec) != Some(ZIP64_EOCD_SIG) {
                return Err(ZipError::Zip64);
            }
            // The record is exactly 56 bytes (no extensible data) and ends
            // at the locator.
            if u64_at(data, rec + 4) != Some(44) || rec.checked_add(56) != Some(loc) {
                return Err(ZipError::Zip64);
            }
            if u32_at(data, rec + 16) != Some(0) || u32_at(data, rec + 20) != Some(0) {
                return Err(ZipError::MultiDisk);
            }
            let e_disk = u64_at(data, rec + 24).ok_or(ZipError::Zip64)?;
            let e_total = u64_at(data, rec + 32).ok_or(ZipError::Zip64)?;
            let size = u64_at(data, rec + 40).ok_or(ZipError::Zip64)?;
            let off = u64_at(data, rec + 48).ok_or(ZipError::Zip64)?;
            // Each classic field is either its value or the marker.
            let agrees16 = |c: u16, v: u64| c == 0xffff || u64::from(c) == v;
            let agrees32 = |c: u32, v: u64| c == u32::MAX || u64::from(c) == v;
            if e_disk != e_total
                || !agrees16(n_disk, e_disk)
                || !agrees16(n_total, e_total)
                || !agrees32(cd_size32, size)
                || !agrees32(cd_off32, off)
            {
                return Err(ZipError::Zip64);
            }
            (e_total, size, off, rec as u64, true)
        } else {
            if needs64 {
                return Err(ZipError::Zip64);
            }
            (
                u64::from(n_total),
                u64::from(cd_size32),
                u64::from(cd_off32),
                eocd as u64,
                false,
            )
        };
        // With ZIP64, the classic disk numbers may be the `0xffff` marker
        // (packaging tools write it); the ZIP64 record, checked above, holds
        // the real ones, which must be 0.
        let disk_ok = disk == 0 || (zip64 && disk == 0xffff);
        if !disk_ok || cd_disk != disk || (!zip64 && n_disk != n_total) {
            return Err(ZipError::MultiDisk);
        }
        let count = to_usize(entries).ok_or(ZipError::TooManyEntries)?;
        if count > MAX_ENTRIES {
            return Err(ZipError::TooManyEntries);
        }
        // The central directory ends exactly where the end records start.
        if cd_off.checked_add(cd_size) != Some(cd_end) {
            return Err(ZipError::CentralDirectory);
        }

        let mut members: Vec<Member> = Vec::with_capacity(count.min(len / 46));
        let mut at = to_usize(cd_off).ok_or(ZipError::CentralDirectory)?;
        let mut folded: Vec<String> = Vec::with_capacity(count.min(len / 46));
        for _ in 0..count {
            let m = Self::central_entry(data, at)?;
            at = m.central_raw.0 + m.central_raw.1;
            folded.push(fold(&m.part));
            members.push(m);
        }
        if at as u64 != cd_end {
            return Err(ZipError::CentralDirectory);
        }
        folded.sort_unstable();
        if let Some(w) = folded.windows(2).find(|w| w.first() == w.get(1)) {
            return Err(ZipError::DuplicateName(
                w.first().cloned().unwrap_or_default(),
            ));
        }

        // Local entries tile [0, cd_off) in order.
        let mut next = 0_u64;
        for m in &mut members {
            if m.local_offset != next {
                return Err(ZipError::LocalHeader(m.name.clone()));
            }
            Self::local_entry(data, m, zip64)?;
            next = m.end_offset;
        }
        if next != cd_off {
            return Err(ZipError::LocalHeader(String::from(
                "(after the last member)",
            )));
        }
        Ok(Self {
            data,
            members,
            central_offset: cd_off,
            central_end: cd_end,
            zip64,
        })
    }

    fn central_entry(data: &[u8], at: usize) -> Result<Member> {
        let bad = || ZipError::CentralDirectory;
        if u32_at(data, at) != Some(CENTRAL_SIG) {
            return Err(bad());
        }
        let flags = u16_at(data, at + 8).ok_or_else(bad)?;
        let method = u16_at(data, at + 10).ok_or_else(bad)?;
        let crc = u32_at(data, at + 16).ok_or_else(bad)?;
        let csize32 = u32_at(data, at + 20).ok_or_else(bad)?;
        let usize32 = u32_at(data, at + 24).ok_or_else(bad)?;
        let name_len = usize::from(u16_at(data, at + 28).ok_or_else(bad)?);
        let extra_len = usize::from(u16_at(data, at + 30).ok_or_else(bad)?);
        let comment_len = usize::from(u16_at(data, at + 32).ok_or_else(bad)?);
        let disk = u16_at(data, at + 34).ok_or_else(bad)?;
        let off32 = u32_at(data, at + 42).ok_or_else(bad)?;
        let name_bytes = data.get(at + 46..at + 46 + name_len).ok_or_else(bad)?;
        let extra = data
            .get(at + 46 + name_len..at + 46 + name_len + extra_len)
            .ok_or_else(bad)?;
        let total = 46 + name_len + extra_len + comment_len;
        if data.get(at..at + total).is_none() {
            return Err(bad());
        }
        let name = if flags & FLAG_UTF8 != 0 || name_bytes.is_ascii() {
            std::str::from_utf8(name_bytes)
                .map_err(|_| ZipError::BadName(String::from_utf8_lossy(name_bytes).into_owned()))?
                .to_owned()
        } else {
            return Err(ZipError::BadName(
                String::from_utf8_lossy(name_bytes).into_owned(),
            ));
        };
        // The raw name and its decoded part name must both be clean, so an
        // escaped `/`, `\`, `..` or NUL cannot hide.
        check_name(&name)?;
        let part = decode_part_name(&name).ok_or_else(|| ZipError::BadName(name.clone()))?;
        check_name(&part)?;
        if disk != 0 {
            return Err(ZipError::MultiDisk);
        }
        if flags & (FLAG_ENCRYPTED | FLAG_PATCH | FLAG_STRONG | FLAG_MASKED) != 0
            || !matches!(method, 0 | 8)
        {
            return Err(ZipError::Unsupported(name));
        }
        let want = [usize32 == u32::MAX, csize32 == u32::MAX, off32 == u32::MAX];
        // The package digest rewrites each central entry with only its
        // ZIP64 block as extra data, so any other extra field would make
        // the bytes read here differ from the bytes signed: refused.
        if !extra.is_empty() && (u16_at(extra, 0) != Some(1) || want.iter().all(|w| !w)) {
            return Err(ZipError::Unsupported(
                String::from_utf8_lossy(name_bytes).into_owned(),
            ));
        }
        let [u64v, c64v, o64v] = zip64_extra(extra, want).ok_or(ZipError::Zip64)?;
        let size = u64v.unwrap_or(u64::from(usize32));
        let compressed_size = c64v.unwrap_or(u64::from(csize32));
        let local_offset = o64v.unwrap_or(u64::from(off32));
        if method == 0 && size != compressed_size {
            return Err(ZipError::Corrupt(name));
        }
        Ok(Member {
            name,
            part,
            has_zip64_extra: !extra.is_empty(),
            method,
            crc32: crc,
            compressed_size,
            size,
            local_offset,
            data_offset: 0,
            end_offset: 0,
            central_raw: (at, total),
        })
    }

    fn local_entry(data: &[u8], m: &mut Member, zip64: bool) -> Result<()> {
        let bad = || ZipError::LocalHeader(m.name.clone());
        let at = to_usize(m.local_offset).ok_or_else(bad)?;
        if u32_at(data, at) != Some(LOCAL_SIG) {
            return Err(bad());
        }
        let flags = u16_at(data, at + 6).ok_or_else(bad)?;
        let method = u16_at(data, at + 8).ok_or_else(bad)?;
        let crc = u32_at(data, at + 14).ok_or_else(bad)?;
        let csize32 = u32_at(data, at + 18).ok_or_else(bad)?;
        let usize32 = u32_at(data, at + 22).ok_or_else(bad)?;
        let name_len = usize::from(u16_at(data, at + 26).ok_or_else(bad)?);
        let extra_len = usize::from(u16_at(data, at + 28).ok_or_else(bad)?);
        let name = data.get(at + 30..at + 30 + name_len).ok_or_else(bad)?;
        let extra = data
            .get(at + 30 + name_len..at + 30 + name_len + extra_len)
            .ok_or_else(bad)?;
        if name != m.name.as_bytes() || method != m.method {
            return Err(bad());
        }
        // Local extra data is not used, and would make the local header size
        // the block map records ambiguous: none is allowed beyond a ZIP64
        // field when the local sizes need one.
        // With a data descriptor, the local sizes are zero and no ZIP64
        // field is needed; otherwise only the one `zip64_extra` accepts.
        if !extra.is_empty() && flags & FLAG_DESCRIPTOR != 0 {
            return Err(bad());
        }
        // Flags must agree except for bits that only describe the central
        // record (none that matter here): compare the meaningful ones.
        let meaningful = FLAG_ENCRYPTED | FLAG_DESCRIPTOR | FLAG_PATCH | FLAG_STRONG | FLAG_UTF8;
        let central_flags = u16_at(data, m.central_raw.0 + 8).ok_or_else(bad)?;
        if flags & meaningful != central_flags & meaningful {
            return Err(bad());
        }
        let data_offset = (at + 30 + name_len + extra_len) as u64;
        let data_end = data_offset
            .checked_add(m.compressed_size)
            .filter(|&e| e <= data.len() as u64)
            .ok_or_else(bad)?;
        let end = if flags & FLAG_DESCRIPTOR != 0 {
            // Local CRC and sizes are zero; the descriptor carries them.
            if crc != 0 || csize32 != 0 || usize32 != 0 {
                return Err(bad());
            }
            // The descriptor must carry its signature: the package digest
            // writes one, so one without would hash differently.
            let d = to_usize(data_end).ok_or_else(bad)?;
            if u32_at(data, d) != Some(DESCRIPTOR_SIG) {
                return Err(bad());
            }
            let p = d + 4;
            let d_crc = u32_at(data, p).ok_or_else(bad)?;
            // 8-byte sizes in a ZIP64 archive or with a ZIP64 extra field:
            // the OS packaging tool writes them for every descriptor of the
            // ZIP64 archives it makes, and osslsigncode reads them so.
            let (dc, du, n) = if zip64 || m.has_zip64_extra {
                (
                    u64_at(data, p + 4).ok_or_else(bad)?,
                    u64_at(data, p + 12).ok_or_else(bad)?,
                    20,
                )
            } else {
                (
                    u64::from(u32_at(data, p + 4).ok_or_else(bad)?),
                    u64::from(u32_at(data, p + 8).ok_or_else(bad)?),
                    12,
                )
            };
            if d_crc != m.crc32 || dc != m.compressed_size || du != m.size {
                return Err(bad());
            }
            (p + n) as u64
        } else {
            let want = [usize32 == u32::MAX, csize32 == u32::MAX, false];
            let [u64v, c64v, _] = zip64_extra(extra, want).ok_or_else(bad)?;
            let lsize = u64v.unwrap_or(u64::from(usize32));
            let lcsize = c64v.unwrap_or(u64::from(csize32));
            if crc != m.crc32 || lsize != m.size || lcsize != m.compressed_size {
                return Err(bad());
            }
            data_end
        };
        m.data_offset = data_offset;
        m.end_offset = end;
        Ok(())
    }

    /// The member whose part name is `name`, compared as part names are
    /// (percent-decoded, ASCII case-insensitive). Part names are unique
    /// under that comparison, so there is at most one.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Member> {
        let want = fold(name);
        self.members.iter().find(|m| fold(&m.part) == want)
    }

    /// The raw bytes of `[from, to)` in the file.
    #[must_use]
    pub fn bytes(&self, from: u64, to: u64) -> &'a [u8] {
        match (to_usize(from), to_usize(to)) {
            (Some(a), Some(b)) => self.data.get(a..b).unwrap_or_default(),
            _ => &[],
        }
    }

    /// The member's compressed data.
    #[must_use]
    pub fn raw_data(&self, m: &Member) -> &'a [u8] {
        self.bytes(
            m.data_offset,
            m.data_offset.saturating_add(m.compressed_size),
        )
    }

    /// The member's content, decompressed and checked against its size and
    /// CRC.
    pub fn read(&self, m: &Member) -> Result<Vec<u8>> {
        if m.size > MAX_MEMBER_SIZE {
            return Err(ZipError::TooLarge(m.name.clone()));
        }
        let mut out = Vec::with_capacity(to_usize(m.size).unwrap_or(0));
        self.stream(m, |chunk| out.extend_from_slice(chunk))?;
        Ok(out)
    }

    /// Feeds the member's decompressed content to `sink` in chunks, then
    /// checks its size and CRC. Unlike [`Self::read`], works for members
    /// of any size; `sink` may have seen data from a member that then
    /// fails the check, so callers must discard their result on error.
    pub fn stream(&self, m: &Member, mut sink: impl FnMut(&[u8])) -> Result<()> {
        let raw = self.raw_data(m);
        let corrupt = || ZipError::Corrupt(m.name.clone());
        let mut crc = 0_u32;
        let mut total = 0_u64;
        if m.method == 0 {
            crc = crc32(raw, crc);
            total = raw.len() as u64;
            sink(raw);
        } else {
            use miniz_oxide::inflate::stream::{InflateState, inflate};
            use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
            let mut state = InflateState::new_boxed(DataFormat::Raw);
            let mut buf = vec![0_u8; 64 * 1024];
            let mut input = raw;
            // Streamed into a fixed buffer. `Finish` would ask for the whole
            // output at once, so `None` is used and progress is required on
            // every call: a call that neither reads nor writes means the
            // data is truncated or invalid.
            loop {
                let r = inflate(&mut state, input, &mut buf, MZFlush::None);
                input = input.get(r.bytes_consumed..).unwrap_or_default();
                let chunk = buf.get(..r.bytes_written).unwrap_or_default();
                total = total.saturating_add(chunk.len() as u64);
                if total > m.size {
                    return Err(corrupt());
                }
                crc = crc32(chunk, crc);
                sink(chunk);
                match r.status {
                    Ok(MZStatus::StreamEnd) => break,
                    Ok(MZStatus::Ok) | Err(MZError::Buf)
                        if r.bytes_written > 0 || r.bytes_consumed > 0 => {}
                    _ => return Err(corrupt()),
                }
            }
            // The deflate stream must use all of the compressed data.
            if !input.is_empty() {
                return Err(corrupt());
            }
        }
        if total != m.size || crc != m.crc32 {
            return Err(corrupt());
        }
        Ok(())
    }

    /// The raw central directory entry of `m`.
    #[must_use]
    pub fn central_bytes(&self, m: &Member) -> &'a [u8] {
        let (at, len) = m.central_raw;
        self.data
            .get(at..at.saturating_add(len))
            .unwrap_or_default()
    }
}

/// CRC-32 (IEEE), exposed for the package hash code and tests.
#[must_use]
pub fn crc(data: &[u8]) -> u32 {
    crc32(data, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(id: u16, body: &[u8]) -> Vec<u8> {
        let mut v = id.to_le_bytes().to_vec();
        v.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn zip64_extra_accepts_exactly_the_needed_block() {
        let all = [true, true, true];
        let none = [false, false, false];
        let body: Vec<u8> = [1_u64, 2, 3].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(
            zip64_extra(&block(1, &body), all),
            Some([Some(1), Some(2), Some(3)])
        );
        // Only the uncompressed size called for: one value.
        assert_eq!(
            zip64_extra(&block(1, &7_u64.to_le_bytes()), [true, false, false]),
            Some([Some(7), None, None])
        );
        assert_eq!(zip64_extra(&[], none), Some([None; 3]));
        // Missing when needed.
        assert_eq!(zip64_extra(&[], all), None);
        // Present when not needed, even empty.
        assert_eq!(zip64_extra(&block(1, &[]), none), None);
        assert_eq!(zip64_extra(&block(1, &body), none), None);
        // Another block after it, or before it, or instead of it.
        let mut trailing = block(1, &body);
        trailing.extend(block(0xcafe, &[0; 4]));
        assert_eq!(zip64_extra(&trailing, all), None);
        let mut leading = block(0xcafe, &[0; 4]);
        leading.extend(block(1, &body));
        assert_eq!(zip64_extra(&leading, all), None);
        assert_eq!(zip64_extra(&block(0xcafe, &body), all), None);
        // Values left over (a disk number), or too few.
        let mut extra_body = body.clone();
        extra_body.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(zip64_extra(&block(1, &extra_body), all), None);
        assert_eq!(zip64_extra(&block(1, &body[..16]), all), None);
        // A length running past the field.
        let mut short = block(1, &body);
        short.truncate(10);
        assert_eq!(zip64_extra(&short, all), None);
    }

    #[test]
    fn crc_known_value() {
        assert_eq!(crc(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc(b""), 0);
    }

    #[test]
    fn names() {
        for ok in ["AppxManifest.xml", "a/b.dll", "dir/"] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "/abs", "a\\b", "a/../b", "a//b", "./a", "a\0"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rejects_trailing_comment_and_garbage() {
        assert_eq!(Archive::parse(b"").unwrap_err(), ZipError::EndRecord);
        let mut empty = vec![0x50, 0x4b, 5, 6];
        empty.extend_from_slice(&[0; 18]);
        assert!(Archive::parse(&empty).is_ok());
        let mut commented = empty.clone();
        commented[20] = 1;
        commented.push(b'x');
        assert_eq!(Archive::parse(&commented).unwrap_err(), ZipError::EndRecord);
    }
}
