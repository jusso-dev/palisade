//! ZIP containers, classified by their entry names.
//!
//! Only the end records and the central directory are read; nothing is
//! decompressed and local file headers are not read. The directory is read
//! the one way the APPNOTE layout gives: the last end record, whose comment
//! reaches the end of the file, the ZIP64 records just before it, and a
//! directory that ends exactly where they start and holds the recorded
//! number of entries. ZIP readers differ in how they handle anything else
//! (a second end record, trailing data, fields that disagree, a shifted or
//! understated directory), so any such structure is reported as
//! [`ParseError::ZipDirectoryAmbiguous`] or
//! [`ParseError::ZipDirectoryMalformed`] instead of being guessed at, and
//! the caller treats it as possibly executable
//! ([`Classification::is_executable_content`]).

#![forbid(unsafe_code)]

use std::io::{Read, Seek};

use super::name::NameInfo;
use super::source::Source;
use super::{
    Classification, Confidence, FileKind, MAX_ZIP_DIRECTORY, MAX_ZIP_ENTRIES, ParseError,
    ScriptKind,
};
use crate::pe::read::{bytes, u16_at, u32_at, u64_at};

const LOCAL_HEADER: &[u8; 4] = b"PK\x03\x04";
const END_OF_DIRECTORY: &[u8; 4] = b"PK\x05\x06";
const ZIP64_LOCATOR: &[u8; 4] = b"PK\x06\x07";
const ZIP64_END: &[u8; 4] = b"PK\x06\x06";
const DIRECTORY_ENTRY: &[u8; 4] = b"PK\x01\x02";
const SPANNED: &[u8; 4] = b"PK\x07\x08";

/// The end of central directory record without its comment.
const END_LEN: usize = 22;
/// The longest archive comment.
const MAX_COMMENT: usize = 0xffff;
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_END_LEN: usize = 56;
const DIRECTORY_ENTRY_LEN: usize = 46;

/// Whether the head starts with a ZIP record: a local file header, an empty
/// archive's end record, or a spanned-archive marker.
pub(super) fn starts_like_zip(head: &[u8]) -> bool {
    [LOCAL_HEADER, END_OF_DIRECTORY, SPANNED]
        .iter()
        .any(|sig| head.starts_with(*sig))
}

/// The entry names that decide the kind.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Entries {
    appx_manifest: bool,
    appx_signature: bool,
    bundle_manifest: bool,
    jar_manifest: bool,
    python_main: bool,
    vba_project: bool,
}

impl Entries {
    /// Notes an entry under every name a reader could give it: the name
    /// itself, the name up to its first NUL byte (some readers stop there),
    /// the name percent-decoded (the package reader decodes part names),
    /// and the name in any Unicode path extra field (some readers use that
    /// instead; its checksum is not checked, so a mismatch over-counts).
    /// `scratch` is reused for decoding, so no entry allocates. The work is
    /// linear in the entry's length.
    fn note_entry(&mut self, name: &[u8], extra: &[u8], scratch: &mut Vec<u8>) {
        self.note_name(name, scratch);
        let mut rest = extra;
        while let (Some(id), Some(len)) = (u16_at(rest, 0), u16_at(rest, 2)) {
            let Some(body) = bytes(rest, 4, usize::from(len)) else {
                break;
            };
            if id == UNICODE_PATH {
                // A version byte and the checksum, then the name.
                if let Some(unicode) = body.get(5..) {
                    self.note_name(unicode, scratch);
                }
            }
            rest = rest.get(4 + usize::from(len)..).unwrap_or_default();
        }
    }

    /// Notes `name`, its part before a NUL byte if it has one, and its
    /// percent-decoded form if it has an escape. Each form is a different
    /// name, so no form is compared twice.
    fn note_name(&mut self, name: &[u8], scratch: &mut Vec<u8>) {
        self.note_with_nul(name);
        if percent_decode_into(name, scratch) {
            let decoded = std::mem::take(scratch);
            self.note_with_nul(&decoded);
            *scratch = decoded;
        }
    }

    fn note_with_nul(&mut self, name: &[u8]) {
        self.note(name);
        if let Some(nul) = name.iter().position(|b| *b == 0) {
            self.note(name.get(..nul).unwrap_or_default());
        }
    }

    /// Matches one name. Each length has at most one candidate name, so a
    /// name is compared with at most two targets (one name, and the macro
    /// project suffix).
    fn note(&mut self, name: &[u8]) {
        let is = |want: &[u8]| same_name(name, want);
        match name.len() {
            11 => self.python_main |= is(b"__main__.py"),
            12 => self.python_main |= is(b"__main__.pyc"),
            16 => self.appx_manifest |= is(b"AppxManifest.xml"),
            17 => self.appx_signature |= is(b"AppxSignature.p7x"),
            20 => self.jar_manifest |= is(b"META-INF/MANIFEST.MF"),
            35 => self.bundle_manifest |= is(b"AppxMetadata/AppxBundleManifest.xml"),
            _ => {}
        }
        // Macro-enabled office suite documents keep their macros here
        // (`word/vbaProject.bin`, `xl/vbaProject.bin`, ...).
        if !self.vba_project && matches!(name.last(), Some(b'n' | b'N')) {
            self.vba_project = name
                .len()
                .checked_sub(15)
                .filter(|start| *start > 0)
                .and_then(|start| name.get(start..))
                .is_some_and(|tail| same_name(tail, b"/vbaProject.bin"));
        }
    }
}

/// Whether `name` is `want`, ignoring ASCII case and taking a backslash as
/// `/` (some tools write it as the separator; the package reader accepts
/// it).
fn same_name(name: &[u8], want: &[u8]) -> bool {
    let fold = |b: u8| if b == b'\\' { b'/' } else { b };
    name.len() == want.len()
        && name
            .iter()
            .zip(want)
            .all(|(a, b)| fold(*a).eq_ignore_ascii_case(b))
}

/// Writes `name` with every `%XX` escape decoded into `out`, replacing its
/// contents; other bytes are kept. Returns whether there was an escape, so
/// an unchanged name is not matched again.
fn percent_decode_into(name: &[u8], out: &mut Vec<u8>) -> bool {
    let hex = |b: Option<&u8>| {
        b.and_then(|b| char::from(*b).to_digit(16))
            .and_then(|d| u8::try_from(d).ok())
    };
    let escape = |i: usize| hex(name.get(i + 1)).zip(hex(name.get(i + 2)));
    let Some(first) = name
        .iter()
        .enumerate()
        .position(|(i, b)| *b == b'%' && escape(i).is_some())
    else {
        return false;
    };
    out.clear();
    out.extend_from_slice(name.get(..first).unwrap_or_default());
    let mut i = first;
    while let Some(&b) = name.get(i) {
        match escape(i) {
            Some((hi, lo)) if b == b'%' => {
                out.push(hi << 4 | lo);
                i += 3;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    true
}

/// Classifies a ZIP archive by its entries. `behind_shebang` is set when
/// the file starts with a `#!` line, as a zip application does; then only a
/// zip application is reported, and anything else leaves `out` unchanged.
pub(super) fn classify<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    name: &NameInfo,
    out: &mut Classification,
    behind_shebang: bool,
) -> bool {
    let (entries, error) = match read_entries(src) {
        Ok(found) => found,
        Err(_) if behind_shebang => return false,
        Err(e) => {
            out.content_kind = FileKind::Zip;
            out.confidence = Confidence::High;
            out.parse_error = Some(e);
            return true;
        }
    };
    if behind_shebang {
        // Only a clean zip application is reported; anything else is the
        // script the shebang names.
        if !entries.python_main || error.is_some() {
            return false;
        }
        out.flags.python_zipapp = true;
        out.content_kind = FileKind::Script(ScriptKind::Python);
        out.confidence = Confidence::High;
        out.parse_error = error;
        return true;
    }
    out.confidence = Confidence::High;
    out.parse_error = error;
    out.flags.macro_capable_container = entries.vba_project;
    out.content_kind = if entries.bundle_manifest {
        out.flags.package_signature_present = entries.appx_signature;
        if name.is_ext(&["appxbundle"]) {
            out.extension_assisted = true;
            FileKind::AppxBundle
        } else {
            FileKind::MsixBundle
        }
    } else if entries.appx_manifest {
        out.flags.package_signature_present = entries.appx_signature;
        if name.is_ext(&["appx"]) {
            out.extension_assisted = true;
            FileKind::Appx
        } else {
            FileKind::Msix
        }
    } else if entries.jar_manifest {
        FileKind::Jar
    } else if entries.python_main && name.is_ext(&["pyz", "pyzw"]) {
        out.flags.python_zipapp = true;
        out.extension_assisted = true;
        FileKind::Script(ScriptKind::Python)
    } else {
        FileKind::Zip
    };
    true
}

/// Bytes at the end of the file searched for the end records: the longest
/// archive comment and the 32-bit end record, plus room for a ZIP64 end
/// record and locator in front of them (some readers look for the ZIP64
/// record in this whole window).
const TAIL_LEN: usize = MAX_COMMENT + END_LEN + ZIP64_END_LEN + ZIP64_LOCATOR_LEN;

/// The size of a ZIP64 end record without extensible data, as its "size of
/// record" field gives it (the record less its first 12 bytes).
const ZIP64_PLAIN_SIZE: u64 = 44;

/// The Unicode path extra field: a UTF-8 name some readers use instead of
/// the entry's own.
const UNICODE_PATH: u16 = 0x7075;

/// The central directory, as the end records describe it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Directory {
    /// File offset of the first entry.
    offset: u64,
    /// Size in bytes.
    size: u64,
    /// Number of entries.
    count: u64,
}

/// Reads the central directory the end records describe, and only that.
///
/// There is one reading: the directory at its recorded offset, of its
/// recorded size, ending where the next record (the ZIP64 end record, or
/// the end record) starts, holding exactly the recorded number of entries.
/// When the structure allows any other reading, so that ZIP readers could
/// disagree on the entries, the error is
/// [`ParseError::ZipDirectoryAmbiguous`]; when an entry runs past the
/// directory, [`ParseError::ZipDirectoryMalformed`]; when the directory is
/// over the limits, [`ParseError::ZipDirectoryTruncated`]. The entries read
/// before such a point are returned with the error. The caller treats any of
/// them as possibly executable, so a misread fails closed.
fn read_entries<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
) -> Result<(Entries, Option<ParseError>), ParseError> {
    let dir = find_directory(src)?;
    walk(src, dir)
}

/// Walks the central directory once, entry by entry. The work is linear in
/// the directory's size, which is capped at [`MAX_ZIP_DIRECTORY`] bytes and
/// [`MAX_ZIP_ENTRIES`] entries.
fn walk<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    dir: Directory,
) -> Result<(Entries, Option<ParseError>), ParseError> {
    let cap = to_u64(MAX_ZIP_DIRECTORY);
    let over = dir.size > cap;
    let want = usize::try_from(dir.size.min(cap)).unwrap_or(MAX_ZIP_DIRECTORY);
    let data = src.read_at(dir.offset, want)?;
    let mut entries = Entries::default();
    let mut scratch = Vec::new();
    if data.len() != want {
        // The file ended early: the reader returned less than its length.
        return Ok((entries, Some(ParseError::ZipDirectoryMalformed)));
    }
    // An entry cut by the size cap is not malformed; it is past the limit.
    let cut = |e: ParseError| {
        if over {
            ParseError::ZipDirectoryTruncated
        } else {
            e
        }
    };
    let mut at = 0_usize;
    let mut seen = 0_usize;
    let error = loop {
        if at == data.len() {
            break if over {
                Some(ParseError::ZipDirectoryTruncated)
            } else if to_u64(seen) != dir.count {
                // Readers that trust the count and readers that trust the
                // size see different entries.
                Some(ParseError::ZipDirectoryAmbiguous)
            } else {
                None
            };
        }
        if seen >= MAX_ZIP_ENTRIES {
            break Some(ParseError::ZipDirectoryTruncated);
        }
        let rest = data.get(at..).unwrap_or_default();
        let Some(sig) = rest.get(..4) else {
            break Some(cut(ParseError::ZipDirectoryMalformed));
        };
        if sig != DIRECTORY_ENTRY {
            // Another record inside the directory, such as a digital
            // signature record: readers that stop there and readers that
            // skip it can see different entries.
            break Some(ParseError::ZipDirectoryAmbiguous);
        }
        let Some(header) = rest.get(..DIRECTORY_ENTRY_LEN) else {
            break Some(cut(ParseError::ZipDirectoryMalformed));
        };
        let field = |off| u16_at(header, off).map_or(0, usize::from);
        let (name_len, extra_len, comment_len) = (field(28), field(30), field(32));
        let name_at = at.saturating_add(DIRECTORY_ENTRY_LEN);
        let Some(name) = bytes(&data, name_at, name_len) else {
            break Some(cut(ParseError::ZipDirectoryMalformed));
        };
        let extra = name_at
            .checked_add(name_len)
            .and_then(|e| bytes(&data, e, extra_len));
        // Names that fit count even if the entry's tail does not.
        entries.note_entry(name, extra.unwrap_or_default(), &mut scratch);
        let next = name_at
            .checked_add(name_len)
            .and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comment_len))
            .filter(|n| *n <= data.len());
        let Some(next) = next else {
            break Some(cut(ParseError::ZipDirectoryMalformed));
        };
        seen = seen.saturating_add(1);
        at = next;
    };
    Ok((entries, error))
}

/// A `usize` as a `u64`. Always exact on the targets Palisade supports.
fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Finds the one central directory the end records describe.
///
/// The end record is the last end record signature in the last
/// [`TAIL_LEN`] bytes, and its comment must reach exactly to the end of the
/// file. A ZIP64 locator just before it must point at a ZIP64 end record
/// just before the locator, without extensible data, and every 32-bit field
/// must be the ZIP64 value or its sentinel. Finally the directory's recorded
/// offset plus its size must be where the next record starts. Any other
/// layout (a second end record, data after the comment, a ZIP64 record
/// elsewhere or without a locator, fields that disagree, a directory
/// shifted by data in front of the archive) lets readers find different
/// directories, and is [`ParseError::ZipDirectoryAmbiguous`].
fn find_directory<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
) -> Result<Directory, ParseError> {
    let len = src.len();
    let tail_start = len.saturating_sub(to_u64(TAIL_LEN));
    let tail = src.read_at(tail_start, TAIL_LEN)?;
    if to_u64(tail.len()) != len - tail_start {
        // The reader returned less than its length.
        return Err(ParseError::ZipDirectoryMalformed);
    }
    let last = |sig: &[u8; 4], from: usize| {
        tail.get(from..)
            .and_then(|t| t.windows(4).rposition(|w| w == sig))
            .map(|i| i + from)
    };
    let end_at = last(END_OF_DIRECTORY, 0).ok_or(ParseError::ZipDirectoryMissing)?;
    // The last signature, so no reader takes a later one; and its comment
    // ends at the end of the file, so no reader takes an earlier one.
    let end = bytes(&tail, end_at, END_LEN).ok_or(ParseError::ZipDirectoryAmbiguous)?;
    let comment = u16_at(end, 20).map_or(0, usize::from);
    if end_at + END_LEN + comment != tail.len() {
        return Err(ParseError::ZipDirectoryAmbiguous);
    }
    // An earlier end record whose comment holds this one (or that
    // overlaps it): a reader that rejects this record, or checks only that
    // a comment reaches the end, could take that one instead. Earlier
    // signatures that end before this record (inside stored entry data,
    // say) are not taken by readers that accept this one.
    let nested = (0..end_at).any(|p| {
        bytes(&tail, p, 4) == Some(&END_OF_DIRECTORY[..])
            && u16_at(&tail, p + 20).is_none_or(|c| p + END_LEN + usize::from(c) > end_at)
    });
    if nested {
        return Err(ParseError::ZipDirectoryAmbiguous);
    }
    let end_pos = tail_start + to_u64(end_at);

    let f16 = |off| u16_at(end, off).unwrap_or(0);
    let f32 = |off| u32_at(end, off).unwrap_or(0);
    let (disk, dir_disk, here, total) = (f16(4), f16(6), f16(8), f16(10));
    let (size, offset) = (f32(12), f32(16));

    let locator_at = end_at.checked_sub(ZIP64_LOCATOR_LEN);
    let record_at = locator_at.and_then(|l| l.checked_sub(ZIP64_END_LEN));
    let locator = locator_at
        .and_then(|l| bytes(&tail, l, ZIP64_LOCATOR_LEN))
        .filter(|l| l.get(..4) == Some(&ZIP64_LOCATOR[..]));
    let record = record_at
        .and_then(|r| bytes(&tail, r, ZIP64_END_LEN))
        .filter(|r| r.get(..4) == Some(&ZIP64_END[..]));

    let (dir, next_record) = match (locator, record, record_at) {
        (Some(locator), Some(record), Some(record_at)) => {
            let record_pos = tail_start + to_u64(record_at);
            let disk_of_record = u32_at(locator, 4);
            let declared = u64_at(locator, 8);
            let disks = u32_at(locator, 16);
            // Readers that see more or fewer than one disk do not use
            // the ZIP64 record.
            if disk_of_record != Some(0) || disks != Some(1) || declared != Some(record_pos) {
                return Err(ParseError::ZipDirectoryAmbiguous);
            }
            // Extensible data, or a size that does not reach the locator.
            if u64_at(record, 4) != Some(ZIP64_PLAIN_SIZE) {
                return Err(ParseError::ZipDirectoryAmbiguous);
            }
            // A later ZIP64 signature: a reader that takes the last one
            // falls back to the 32-bit record.
            if last(ZIP64_END, record_at + 4).is_some() {
                return Err(ParseError::ZipDirectoryAmbiguous);
            }
            let g32 = |off| u32_at(record, off).unwrap_or(u32::MAX);
            let g64 = |off| u64_at(record, off).unwrap_or(u64::MAX);
            let dir = Directory {
                offset: g64(48),
                size: g64(40),
                count: g64(32),
            };
            // Spanned archives, or the two entry counts disagree (readers
            // use either).
            if g32(16) != 0 || g32(20) != 0 || g64(24) != dir.count {
                return Err(ParseError::ZipDirectoryAmbiguous);
            }
            // Readers use the 32-bit fields unless one is a sentinel, so
            // each must be the ZIP64 value or the sentinel.
            let agrees16 = |v: u16, want: u64| v == u16::MAX || u64::from(v) == want;
            let agrees32 = |v: u32, want: u64| v == u32::MAX || u64::from(v) == want;
            let agree = agrees16(disk, 0)
                && agrees16(dir_disk, 0)
                && agrees16(here, dir.count)
                && agrees16(total, dir.count)
                && agrees32(size, dir.size)
                && agrees32(offset, dir.offset);
            if !agree {
                return Err(ParseError::ZipDirectoryAmbiguous);
            }
            (dir, record_pos)
        }
        // A locator without its record, or a record without a locator
        // (some readers take a ZIP64 record there without one).
        (Some(_), _, _) | (None, Some(_), _) => return Err(ParseError::ZipDirectoryAmbiguous),
        (None, None, _) => {
            // Spanned archives, or the two entry counts disagree (readers
            // use either).
            if disk != 0 || dir_disk != 0 || here != total {
                return Err(ParseError::ZipDirectoryAmbiguous);
            }
            // ZIP64 sentinels with no ZIP64 record.
            if size == u32::MAX || offset == u32::MAX {
                return Err(ParseError::ZipDirectoryMalformed);
            }
            let dir = Directory {
                offset: u64::from(offset),
                size: u64::from(size),
                count: u64::from(total),
            };
            (dir, end_pos)
        }
    };
    // Readers find the directory from its recorded offset or from where it
    // ends; both must give the same start. Data in front of the archive is
    // fine only when the offsets already count it.
    if dir.offset.checked_add(dir.size) != Some(next_record) {
        return Err(ParseError::ZipDirectoryAmbiguous);
    }
    Ok(dir)
}
