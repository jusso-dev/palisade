//! A bounded reader for compound files (MS-CFB, "structured storage"), the
//! container Windows Installer packages use.
//!
//! The whole file is in memory. [`CompoundFile::parse`] checks the header,
//! loads the FAT, the mini FAT and the directory, walks the directory tree
//! from the root and builds an [`Entry`] tree of every reachable stream
//! and storage. Stream data is read on demand by [`CompoundFile::stream`].
//!
//! # Fail closed
//!
//! A package's identity and its signature both rest on what this reader
//! returns, so anything ambiguous is an error, never a guess:
//!
//! - a sector chain that loops, runs off the file or the FAT, or is shorter
//!   or longer than its stream (every chain of a known length must end in
//!   `ENDOFCHAIN` exactly where its data does), and a DIFAT chain longer
//!   than the FAT;
//! - a sector (or mini sector) claimed by two chains, or by a chain and the
//!   FAT, DIFAT, directory or mini FAT, so no two streams can share bytes
//!   and no data is read twice;
//! - a directory entry reached twice, a child of the wrong type, two
//!   siblings with the same name (names compare case-insensitively, as the
//!   format requires), or a name that is empty or has a character the
//!   format forbids (`/`, `\`, `:`, `!`);
//! - a header that is not version 3 with 512-byte sectors or version 4 with
//!   4096-byte sectors, a mini sector size other than 64, or a mini stream
//!   cutoff other than 4096.
//!
//! Unreachable directory entries are ignored, as the OS ignores them.
//!
//! For version 3 files, the upper 32 bits of a stream size are ignored, as
//! the format specification recommends (older writers left them
//! uninitialised).

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::fmt;

/// The compound file signature.
pub(crate) const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

/// The most directory entries read.
pub const MAX_DIRECTORY_ENTRIES: usize = 65_536;
/// The deepest storage nesting accepted.
pub const MAX_STORAGE_DEPTH: usize = 16;

const HEADER_LEN: usize = 512;
const DIR_ENTRY_LEN: usize = 128;
const MINI_SECTOR_LEN: usize = 64;
const MINI_STREAM_CUTOFF: u64 = 4096;
const HEADER_DIFAT_ENTRIES: usize = 109;

const MAXREGSECT: u32 = 0xffff_fffa;
const ENDOFCHAIN: u32 = 0xffff_fffe;
const FREESECT: u32 = 0xffff_ffff;
const NOSTREAM: u32 = 0xffff_ffff;

const TYPE_UNUSED: u8 = 0;
const TYPE_STORAGE: u8 = 1;
const TYPE_STREAM: u8 = 2;
const TYPE_ROOT: u8 = 5;

/// Why a compound file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CfbError {
    /// Shorter than the header, or not a compound file.
    NotCompoundFile,
    /// A header field has a value the format does not allow.
    BadHeader(&'static str),
    /// A sector number is past the end of the file or of the FAT.
    SectorOutOfRange(u32),
    /// A sector chain ends before its stream does.
    TruncatedChain,
    /// A sector chain does not end (with `ENDOFCHAIN`) where its stream
    /// does.
    ChainTooLong,
    /// A sector or mini sector is claimed twice: a loop, or two chains that
    /// share data.
    SharedSector(u32),
    /// A directory entry is malformed (bad name length, unknown type, a
    /// child or sibling ID out of range).
    BadDirectoryEntry(u32),
    /// A directory entry is reached twice while walking the tree.
    DirectoryCycle(u32),
    /// Two entries in one storage have the same name.
    DuplicateName,
    /// More than [`MAX_DIRECTORY_ENTRIES`] entries, or storages nested
    /// deeper than [`MAX_STORAGE_DEPTH`].
    TooComplex,
}

impl fmt::Display for CfbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCompoundFile => f.write_str("not a compound file"),
            Self::BadHeader(what) => write!(f, "bad compound file header: {what}"),
            Self::SectorOutOfRange(s) => write!(f, "sector {s} is out of range"),
            Self::TruncatedChain => f.write_str("a sector chain ends before its stream"),
            Self::ChainTooLong => f.write_str("a sector chain runs past its stream"),
            Self::SharedSector(s) => write!(f, "sector {s} is claimed twice"),
            Self::BadDirectoryEntry(i) => write!(f, "directory entry {i} is malformed"),
            Self::DirectoryCycle(i) => write!(f, "directory entry {i} is reached twice"),
            Self::DuplicateName => f.write_str("two entries in one storage share a name"),
            Self::TooComplex => f.write_str("too many directory entries or storage levels"),
        }
    }
}

impl std::error::Error for CfbError {}

type Result<T> = std::result::Result<T, CfbError>;

/// One reachable directory entry: a stream or a storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name as UTF-16 code units, without the terminator.
    pub name: Vec<u16>,
    /// Its directory entry number.
    pub id: u32,
    /// The CLSID (16 bytes, as stored). All zero for streams.
    pub clsid: [u8; 16],
    /// The state bits.
    pub state_bits: [u8; 4],
    /// Creation and modification times (FILETIME, as stored).
    pub times: [u8; 16],
    /// The stream size, or 0 for a storage.
    pub size: u64,
    /// The stream's size field exactly as stored (all 8 bytes).
    pub raw_size: [u8; 8],
    /// The children, for a storage. Empty for a stream.
    pub children: Vec<Entry>,
    /// Whether this is a storage (the root counts as one).
    pub is_storage: bool,
    /// Where the stream's data is: a list of `(offset, len)` byte ranges
    /// in the file, in order, summing to `size`.
    extents: Vec<(usize, usize)>,
}

impl Entry {
    /// The name as text, lossily (MSI stream names use private-use code
    /// points that decode fine; unpaired surrogates become U+FFFD).
    #[must_use]
    pub fn name_lossy(&self) -> String {
        String::from_utf16_lossy(&self.name)
    }

    /// The child with this name, compared case-insensitively as the
    /// format (and the OS) compares names. Names are unique under that
    /// comparison, so there is at most one.
    #[must_use]
    pub fn child(&self, name: &[u16]) -> Option<&Entry> {
        let want = fold(name);
        self.children.iter().find(|c| fold(&c.name) == want)
    }

    /// Whether this entry's name equals `name` case-insensitively.
    #[must_use]
    pub fn is_named(&self, name: &str) -> bool {
        let units: Vec<u16> = name.encode_utf16().collect();
        fold(&self.name) == fold(&units)
    }
}

/// A parsed compound file.
#[derive(Debug, Clone)]
pub struct CompoundFile<'a> {
    data: &'a [u8],
    /// The root storage.
    pub root: Entry,
    /// The major version (3 or 4).
    pub version: u16,
    /// Bytes after the last sector any structure or stream uses. Nothing
    /// covers them, so they can hide data in a signed package.
    pub trailing_bytes: u64,
}

impl<'a> CompoundFile<'a> {
    /// Parses `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Parser::new(data)?.run()
    }

    /// The content of `entry`, a stream of this file. Its extents were
    /// checked during parsing, so this cannot fail; a storage reads as
    /// empty.
    #[must_use]
    pub fn stream(&self, entry: &Entry) -> Vec<u8> {
        let mut out = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
        for &(offset, len) in &entry.extents {
            if let Some(chunk) = self.data.get(offset..offset.saturating_add(len)) {
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    /// Feeds the content of `entry` to `sink` chunk by chunk.
    pub fn for_each_chunk(&self, entry: &Entry, mut sink: impl FnMut(&[u8])) {
        for &(offset, len) in &entry.extents {
            if let Some(chunk) = self.data.get(offset..offset.saturating_add(len)) {
                sink(chunk);
            }
        }
    }
}

/// Ownership of sectors, so that no sector is used twice.
struct Claims(Vec<bool>);

impl Claims {
    fn claim(&mut self, sector: u32) -> Result<()> {
        let slot = usize::try_from(sector)
            .ok()
            .and_then(|i| self.0.get_mut(i))
            .ok_or(CfbError::SectorOutOfRange(sector))?;
        if *slot {
            return Err(CfbError::SharedSector(sector));
        }
        *slot = true;
        Ok(())
    }
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    let mut b = [0_u8; 2];
    if let Some(s) = data.get(at..at.saturating_add(2)) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    let mut b = [0_u8; 4];
    if let Some(s) = data.get(at..at.saturating_add(4)) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

fn array_at<const N: usize>(data: &[u8], at: usize) -> [u8; N] {
    let mut b = [0_u8; N];
    if let Some(s) = data.get(at..at.saturating_add(N)) {
        b.copy_from_slice(s);
    }
    b
}

struct Parser<'a> {
    data: &'a [u8],
    version: u16,
    sector_len: usize,
    /// Whole sectors after the header.
    sector_count: u32,
    fat: Vec<u32>,
    claims: Claims,
    minifat: Vec<u32>,
    mini_claims: Claims,
    /// The mini stream's sectors, in order.
    mini_stream: Vec<u32>,
    mini_stream_len: u64,
    dir: Vec<u8>,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < HEADER_LEN || data.get(..8) != Some(&SIGNATURE[..]) {
            return Err(CfbError::NotCompoundFile);
        }
        let version = u16_at(data, 0x1a);
        let byte_order = u16_at(data, 0x1c);
        let sector_shift = u16_at(data, 0x1e);
        let mini_shift = u16_at(data, 0x20);
        if byte_order != 0xfffe {
            return Err(CfbError::BadHeader("byte order"));
        }
        let sector_len = match (version, sector_shift) {
            (3, 9) => 512,
            (4, 12) => 4096,
            _ => return Err(CfbError::BadHeader("version and sector size")),
        };
        if mini_shift != 6 {
            return Err(CfbError::BadHeader("mini sector size"));
        }
        if u64::from(u32_at(data, 0x38)) != MINI_STREAM_CUTOFF {
            return Err(CfbError::BadHeader("mini stream cutoff"));
        }
        if version == 3 && u32_at(data, 0x28) != 0 {
            return Err(CfbError::BadHeader("directory sector count"));
        }
        if data.len() < sector_len {
            return Err(CfbError::BadHeader("file shorter than one sector"));
        }
        // A final sector may be cut short; stream data in it is checked
        // against the end of the file when read.
        let body = data.len().saturating_sub(sector_len);
        let sector_count = u32::try_from(body.div_ceil(sector_len))
            .ok()
            .filter(|&n| n <= MAXREGSECT)
            .ok_or(CfbError::BadHeader("too many sectors"))?;
        let claims = Claims(vec![false; usize::try_from(sector_count).unwrap_or(0)]);
        Ok(Self {
            data,
            version,
            sector_len,
            sector_count,
            fat: Vec::new(),
            claims,
            minifat: Vec::new(),
            mini_claims: Claims(Vec::new()),
            mini_stream: Vec::new(),
            mini_stream_len: 0,
            dir: Vec::new(),
        })
    }

    /// The byte offset of sector `s`. The sector starts inside the file;
    /// whether it is long enough is checked where it is read.
    fn sector(&self, s: u32) -> Result<usize> {
        if s >= self.sector_count {
            return Err(CfbError::SectorOutOfRange(s));
        }
        usize::try_from(s)
            .ok()
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(self.sector_len))
            .filter(|&o| o < self.data.len())
            .ok_or(CfbError::SectorOutOfRange(s))
    }

    /// A whole sector (FAT, DIFAT, mini FAT and directory sectors must be
    /// complete).
    fn sector_bytes(&self, s: u32) -> Result<&'a [u8]> {
        let at = self.sector(s)?;
        self.data
            .get(at..at.saturating_add(self.sector_len))
            .ok_or(CfbError::SectorOutOfRange(s))
    }

    /// `len` bytes of stream data at `at`, which must be inside the file.
    fn extent(&self, at: usize, len: usize, s: u32) -> Result<(usize, usize)> {
        if at
            .checked_add(len)
            .is_some_and(|end| end <= self.data.len())
        {
            Ok((at, len))
        } else {
            Err(CfbError::SectorOutOfRange(s))
        }
    }

    fn run(mut self) -> Result<CompoundFile<'a>> {
        self.load_fat()?;
        self.load_directory()?;
        self.load_minifat()?;
        let root = self.walk()?;
        // The end of the last claimed sector (or of its stream data, if
        // that sector is the short final one).
        let last = self
            .claims
            .0
            .iter()
            .rposition(|&c| c)
            .map_or(1, |i| i.saturating_add(2));
        let used = last.saturating_mul(self.sector_len).min(self.data.len());
        let trailing_bytes =
            u64::try_from(self.data.len().saturating_sub(used)).unwrap_or(u64::MAX);
        Ok(CompoundFile {
            data: self.data,
            root,
            version: self.version,
            trailing_bytes,
        })
    }

    fn load_fat(&mut self) -> Result<()> {
        let fat_count = u32_at(self.data, 0x2c);
        if fat_count > self.sector_count {
            return Err(CfbError::BadHeader("FAT sector count"));
        }
        let fat_count = usize::try_from(fat_count).unwrap_or(usize::MAX);
        let mut fat_sectors: Vec<u32> = Vec::with_capacity(fat_count);
        for i in 0..HEADER_DIFAT_ENTRIES.min(fat_count) {
            fat_sectors.push(u32_at(self.data, 0x4c + 4 * i));
        }
        // The DIFAT chain lists the rest.
        let per_difat = self.sector_len / 4 - 1;
        let mut next = u32_at(self.data, 0x44);
        let mut difat_left = u32_at(self.data, 0x48);
        while fat_sectors.len() < fat_count {
            if difat_left == 0 || next > MAXREGSECT {
                return Err(CfbError::BadHeader("DIFAT ends before the FAT"));
            }
            self.claims.claim(next)?;
            let sector = self.sector_bytes(next)?;
            for i in 0..per_difat {
                if fat_sectors.len() == fat_count {
                    break;
                }
                fat_sectors.push(u32_at(sector, 4 * i));
            }
            next = u32_at(sector, 4 * per_difat);
            difat_left -= 1;
        }
        // The DIFAT chain ends where the FAT does.
        let read_any = fat_count > HEADER_DIFAT_ENTRIES;
        if difat_left != 0 || (read_any && next != ENDOFCHAIN && next != FREESECT) {
            return Err(CfbError::BadHeader("DIFAT longer than the FAT"));
        }
        let per_sector = self.sector_len / 4;
        let mut fat = Vec::with_capacity(fat_count.saturating_mul(per_sector));
        for &s in &fat_sectors {
            self.claims.claim(s)?;
            let sector = self.sector_bytes(s)?;
            for i in 0..per_sector {
                fat.push(u32_at(sector, 4 * i));
            }
        }
        self.fat = fat;
        Ok(())
    }

    /// The FAT chain from `start`, `count` sectors long (or to its end when
    /// `count` is `None`), claiming each sector.
    fn chain(&mut self, start: u32, count: Option<usize>) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut s = start;
        loop {
            if count.is_some_and(|c| out.len() == c) {
                // A chain of a known length must end exactly there: a
                // longer one would share sectors, loop or hide data.
                return if s == ENDOFCHAIN {
                    Ok(out)
                } else {
                    Err(CfbError::ChainTooLong)
                };
            }
            if s == ENDOFCHAIN {
                return match count {
                    Some(_) => Err(CfbError::TruncatedChain),
                    None => Ok(out),
                };
            }
            if s > MAXREGSECT {
                return Err(CfbError::SectorOutOfRange(s));
            }
            self.sector(s)?;
            self.claims.claim(s)?;
            out.push(s);
            s = usize::try_from(s)
                .ok()
                .and_then(|i| self.fat.get(i))
                .copied()
                .ok_or(CfbError::SectorOutOfRange(s))?;
        }
    }

    fn load_directory(&mut self) -> Result<()> {
        let start = u32_at(self.data, 0x30);
        // Version 4 states how many directory sectors there are; the chain
        // must be exactly that long (version 3 states 0, checked earlier).
        let count = if self.version == 4 {
            let n = u32_at(self.data, 0x28);
            if n == 0 || n > self.sector_count {
                return Err(CfbError::BadHeader("directory sector count"));
            }
            Some(usize::try_from(n).map_err(|_| CfbError::BadHeader("directory sector count"))?)
        } else {
            None
        };
        let sectors = self.chain(start, count)?;
        let per = self.sector_len / DIR_ENTRY_LEN;
        if sectors.len().saturating_mul(per) > MAX_DIRECTORY_ENTRIES {
            return Err(CfbError::TooComplex);
        }
        let mut dir = Vec::with_capacity(sectors.len().saturating_mul(self.sector_len));
        for s in sectors {
            dir.extend_from_slice(self.sector_bytes(s)?);
        }
        if dir.is_empty() {
            return Err(CfbError::BadHeader("empty directory"));
        }
        self.dir = dir;
        Ok(())
    }

    fn load_minifat(&mut self) -> Result<()> {
        let start = u32_at(self.data, 0x3c);
        let count = u32_at(self.data, 0x40);
        if count > self.sector_count {
            return Err(CfbError::BadHeader("mini FAT sector count"));
        }
        let sectors = if count == 0 {
            Vec::new()
        } else {
            self.chain(start, Some(usize::try_from(count).unwrap_or(usize::MAX)))?
        };
        let per_sector = self.sector_len / 4;
        let mut minifat = Vec::with_capacity(sectors.len().saturating_mul(per_sector));
        for s in sectors {
            let sector = self.sector_bytes(s)?;
            for i in 0..per_sector {
                minifat.push(u32_at(sector, 4 * i));
            }
        }
        self.minifat = minifat;

        // The root entry's stream is the mini stream.
        let root = self.raw_entry(0)?;
        if root.kind != TYPE_ROOT {
            return Err(CfbError::BadDirectoryEntry(0));
        }
        let len = root.size(self.version);
        let needed = self.sectors_for(len, self.sector_len)?;
        self.mini_stream = if needed == 0 {
            Vec::new()
        } else {
            self.chain(root.start, Some(needed))?
        };
        self.mini_stream_len = len;
        let mini_sectors = len.div_ceil(MINI_SECTOR_LEN as u64);
        self.mini_claims = Claims(vec![false; usize::try_from(mini_sectors).unwrap_or(0)]);
        Ok(())
    }

    fn sectors_for(&self, len: u64, unit: usize) -> Result<usize> {
        let n = len.div_ceil(unit as u64);
        // A chain can never be longer than the file has sectors.
        let limit = u64::from(self.sector_count).saturating_mul(self.sector_len as u64);
        if len > limit {
            return Err(CfbError::TruncatedChain);
        }
        usize::try_from(n).map_err(|_| CfbError::TruncatedChain)
    }

    fn raw_entry(&self, id: u32) -> Result<RawEntry> {
        let at = usize::try_from(id)
            .ok()
            .and_then(|i| i.checked_mul(DIR_ENTRY_LEN))
            .ok_or(CfbError::BadDirectoryEntry(id))?;
        let e = self
            .dir
            .get(at..at + DIR_ENTRY_LEN)
            .ok_or(CfbError::BadDirectoryEntry(id))?;
        let name_len = usize::from(u16_at(e, 0x40));
        let kind = e.get(0x42).copied().unwrap_or(0);
        if kind == TYPE_UNUSED {
            return Ok(RawEntry::unused());
        }
        if !matches!(kind, TYPE_STORAGE | TYPE_STREAM | TYPE_ROOT)
            // At least one character: MS-CFB does not allow an empty name.
            || !(4..=64).contains(&name_len)
            || name_len % 2 != 0
        {
            return Err(CfbError::BadDirectoryEntry(id));
        }
        let units = name_len / 2 - 1;
        let name: Vec<u16> = (0..units).map(|i| u16_at(e, 2 * i)).collect();
        // MS-CFB 2.6.1: these characters are not allowed in a name.
        let illegal = [
            0,
            u16::from(b'/'),
            u16::from(b'\\'),
            u16::from(b':'),
            u16::from(b'!'),
        ];
        if u16_at(e, 2 * units) != 0 || name.iter().any(|u| illegal.contains(u)) {
            return Err(CfbError::BadDirectoryEntry(id));
        }
        Ok(RawEntry {
            kind,
            name,
            left: u32_at(e, 0x44),
            right: u32_at(e, 0x48),
            child: u32_at(e, 0x4c),
            clsid: array_at(e, 0x50),
            state_bits: array_at(e, 0x60),
            times: array_at(e, 0x64),
            start: u32_at(e, 0x74),
            raw_size: array_at(e, 0x78),
        })
    }

    fn entry_count(&self) -> u32 {
        u32::try_from(self.dir.len() / DIR_ENTRY_LEN).unwrap_or(u32::MAX)
    }

    /// Walks the tree from the root, depth first, with every entry visited
    /// at most once.
    fn walk(&mut self) -> Result<Entry> {
        let count = self.entry_count();
        let mut visited = vec![false; usize::try_from(count).unwrap_or(0)];
        let mut mark = |id: u32| -> Result<()> {
            let slot = usize::try_from(id)
                .ok()
                .and_then(|i| visited.get_mut(i))
                .ok_or(CfbError::BadDirectoryEntry(id))?;
            if *slot {
                return Err(CfbError::DirectoryCycle(id));
            }
            *slot = true;
            Ok(())
        };
        mark(0)?;
        let root_raw = self.raw_entry(0)?;
        let mut root = self.make_entry(0, &root_raw)?;
        root.children = self.build_children(&root_raw, 0, &mut mark)?;
        Ok(root)
    }

    /// The IDs in the sibling tree rooted at `top`, in tree order, each
    /// marked as visited.
    fn siblings(&self, top: u32, mark: &mut impl FnMut(u32) -> Result<()>) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        if top == NOSTREAM {
            return Ok(out);
        }
        let count = self.entry_count();
        let mut pending = vec![top];
        while let Some(id) = pending.pop() {
            if id >= count {
                return Err(CfbError::BadDirectoryEntry(id));
            }
            mark(id)?;
            if out.len() >= MAX_DIRECTORY_ENTRIES {
                return Err(CfbError::TooComplex);
            }
            let raw = self.raw_entry(id)?;
            if !matches!(raw.kind, TYPE_STORAGE | TYPE_STREAM) {
                return Err(CfbError::BadDirectoryEntry(id));
            }
            out.push(id);
            for next in [raw.left, raw.right] {
                if next != NOSTREAM {
                    pending.push(next);
                }
            }
        }
        Ok(out)
    }

    fn build_children(
        &mut self,
        storage: &RawEntry,
        depth: usize,
        mark: &mut impl FnMut(u32) -> Result<()>,
    ) -> Result<Vec<Entry>> {
        if depth >= MAX_STORAGE_DEPTH {
            return Err(CfbError::TooComplex);
        }
        let ids = self.siblings(storage.child, mark)?;
        let mut children = Vec::with_capacity(ids.len());
        for id in ids {
            let raw = self.raw_entry(id)?;
            let mut entry = self.make_entry(id, &raw)?;
            if raw.kind == TYPE_STORAGE {
                entry.children = self.build_children(&raw, depth + 1, mark)?;
            }
            children.push(entry);
        }
        // Names are unique within a storage, compared case-insensitively.
        let mut keys: Vec<Vec<u16>> = children.iter().map(|c| fold(&c.name)).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(CfbError::DuplicateName);
        }
        children.sort_by(|a, b| tree_order(&a.name, &b.name));
        Ok(children)
    }

    fn make_entry(&mut self, id: u32, raw: &RawEntry) -> Result<Entry> {
        let is_storage = raw.kind != TYPE_STREAM;
        let size = if is_storage {
            0
        } else {
            raw.size(self.version)
        };
        let extents = if is_storage || size == 0 {
            Vec::new()
        } else if size < MINI_STREAM_CUTOFF {
            self.mini_extents(raw.start, size)?
        } else {
            let n = self.sectors_for(size, self.sector_len)?;
            let sectors = self.chain(raw.start, Some(n))?;
            let mut left = size;
            let mut out = Vec::with_capacity(sectors.len());
            for s in sectors {
                let at = self.sector(s)?;
                let len = usize::try_from(left.min(self.sector_len as u64)).unwrap_or(0);
                out.push(self.extent(at, len, s)?);
                left -= len as u64;
            }
            out
        };
        Ok(Entry {
            name: raw.name.clone(),
            id,
            clsid: raw.clsid,
            state_bits: raw.state_bits,
            times: raw.times,
            size,
            raw_size: raw.raw_size,
            children: Vec::new(),
            is_storage,
            extents,
        })
    }

    fn mini_extents(&mut self, start: u32, size: u64) -> Result<Vec<(usize, usize)>> {
        let n = usize::try_from(size.div_ceil(MINI_SECTOR_LEN as u64)).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(n);
        let mut s = start;
        let mut left = size;
        for _ in 0..n {
            if s > MAXREGSECT {
                return Err(CfbError::TruncatedChain);
            }
            self.mini_claims.claim(s)?;
            let len = left.min(MINI_SECTOR_LEN as u64);
            let begin = u64::from(s) * MINI_SECTOR_LEN as u64;
            if begin.saturating_add(len) > self.mini_stream_len {
                return Err(CfbError::SectorOutOfRange(s));
            }
            // Map the mini stream offset to the file.
            let sector_index = usize::try_from(begin / self.sector_len as u64)
                .map_err(|_| CfbError::SectorOutOfRange(s))?;
            let within = usize::try_from(begin % self.sector_len as u64).unwrap_or(0);
            let host = *self
                .mini_stream
                .get(sector_index)
                .ok_or(CfbError::SectorOutOfRange(s))?;
            let at = self.sector(host)?.saturating_add(within);
            let len = usize::try_from(len).unwrap_or(0);
            out.push(self.extent(at, len, s)?);
            left -= len as u64;
            s = usize::try_from(s)
                .ok()
                .and_then(|i| self.minifat.get(i))
                .copied()
                .ok_or(CfbError::SectorOutOfRange(s))?;
        }
        if s != ENDOFCHAIN {
            return Err(CfbError::ChainTooLong);
        }
        Ok(out)
    }
}

struct RawEntry {
    kind: u8,
    name: Vec<u16>,
    left: u32,
    right: u32,
    child: u32,
    clsid: [u8; 16],
    state_bits: [u8; 4],
    times: [u8; 16],
    start: u32,
    raw_size: [u8; 8],
}

impl RawEntry {
    fn unused() -> Self {
        Self {
            kind: TYPE_UNUSED,
            name: Vec::new(),
            left: NOSTREAM,
            right: NOSTREAM,
            child: NOSTREAM,
            clsid: [0; 16],
            state_bits: [0; 4],
            times: [0; 16],
            start: ENDOFCHAIN,
            raw_size: [0; 8],
        }
    }

    fn size(&self, version: u16) -> u64 {
        let full = u64::from_le_bytes(self.raw_size);
        if version == 3 {
            full & 0xffff_ffff
        } else {
            full
        }
    }
}

/// The case-folded form of a name, for duplicate detection: each code unit
/// that is a character with a single-unit uppercase form is uppercased.
fn fold(name: &[u16]) -> Vec<u16> {
    name.iter()
        .map(|&u| {
            char::from_u32(u32::from(u))
                .and_then(|c| {
                    let mut up = c.to_uppercase();
                    match (up.next(), up.next()) {
                        (Some(x), None) => u16::try_from(u32::from(x)).ok(),
                        _ => None,
                    }
                })
                .unwrap_or(u)
        })
        .collect()
}

/// The format's directory order: shorter names first, then by uppercased
/// code unit. Used only to give children a stable order.
fn tree_order(a: &[u16], b: &[u16]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| fold(a).cmp(&fold(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_and_foreign_input() {
        assert_eq!(
            CompoundFile::parse(b"").unwrap_err(),
            CfbError::NotCompoundFile
        );
        assert_eq!(
            CompoundFile::parse(&[0_u8; 1024]).unwrap_err(),
            CfbError::NotCompoundFile
        );
    }

    #[test]
    fn fold_is_case_insensitive_for_ascii_and_keeps_private_use() {
        assert_eq!(fold(&[u16::from(b'a')]), vec![u16::from(b'A')]);
        assert_eq!(fold(&[0x4840]), vec![0x4840]);
        // A lone surrogate is kept as is.
        assert_eq!(fold(&[0xd800]), vec![0xd800]);
    }
}
