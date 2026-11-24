//! The Windows file backend for hashing and the hash cache (#46).
//!
//! - [`open_for_hashing`] opens a file the way the hash cache needs:
//!   sharing read, write and delete, so hashing never blocks a writer or an
//!   installer, and with `FILE_FLAG_SEQUENTIAL_SCAN`, since every byte is
//!   read once in order.
//! - [`WinStamps`] implements [`FileStamp`]: the strong key from
//!   `FileIdInfo` and the change journal, or the weak key on a volume
//!   without one, all read from the **opened handle**.
//! - [`FileFacts`] is everything about a file the cache and inventory need
//!   (IDs, USN, the four timestamps, attributes, links, size, volume), from
//!   the same handle.
//! - [`hash_open_file`] hashes an opened file, memory-mapped in windows for
//!   a large file on a local fixed volume, and with buffered reads
//!   otherwise. It skips cloud placeholders during inventory scans.
//! - [`hash_streams`] hashes every alternate data stream of a file on its
//!   own, as a `path:stream` identity (`include_ads`).
//!
//! Every call here uses the caller's security context. A privileged service
//! must not call these with a path a less privileged caller chose (threat
//! model T-agent-13).

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use super::sys;
use crate::fsctx::ntfs::{StreamEntry, parse_stream_info, parse_usn_record};
use crate::fsctx::{FsType, normalize_win32};
use crate::hash::{
    FileKey, FileStamp, FileTime, HashError, HashOptions, HashPurpose, HashStatus, MultiHasher,
    skip_for_inventory,
};

/// `FILE_SUPPORTS_USN_JOURNAL`, in the volume flags.
const FILE_SUPPORTS_USN_JOURNAL: u32 = 0x0200_0000;

/// Files at least this large on a local fixed volume are hashed through a
/// memory mapping: 16 MiB, as #46 asks.
pub const MMAP_THRESHOLD: u64 = 16 * 1024 * 1024;

/// The size of each mapped window: 8 MiB, a multiple of every allocation
/// granularity. Each window is unmapped before the next is mapped, which
/// also drops its pages from the working set, so memory use stays bounded
/// (#46: under 16 MB to hash a 1 GB file), whatever the file size.
pub const MAP_WINDOW: u64 = 8 * 1024 * 1024;

/// Opens `path` for hashing: read access, sharing read, write and delete,
/// with `FILE_FLAG_SEQUENTIAL_SCAN`.
///
/// Sharing write and delete means a writer can change the file while it is
/// hashed. That is detected afterwards by comparing stamps
/// ([`crate::hash::hash_through`]), never prevented by locking writers out.
pub fn open_for_hashing(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
}

/// Converts a `FILETIME`-style `i64` (100 ns since 1601) to a
/// [`FileTime`]. A negative value, which the OS never reports for a real
/// time, reads as 0.
fn file_time(t: i64) -> FileTime {
    FileTime(u64::try_from(t).unwrap_or(0))
}

/// The facts about one file that the cache and inventory need, all read
/// from one handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFacts {
    /// The 64-bit volume serial number (`FileIdInfo`).
    pub volume_serial: u64,
    /// The 128-bit file ID (`FileIdInfo`).
    pub file_id: [u8; 16],
    /// The change journal's ID and the file's last USN, if the volume keeps
    /// a journal and it is active.
    pub usn: Option<(u64, i64)>,
    /// The creation time.
    pub creation: FileTime,
    /// The last access time.
    pub last_access: FileTime,
    /// The last write time.
    pub last_write: FileTime,
    /// The last change time (content, attributes or security).
    pub change: FileTime,
    /// The `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// The size of the default data stream.
    pub size: u64,
    /// The number of hard links (names) the file has.
    pub number_of_links: u32,
    /// The handle is a directory.
    pub directory: bool,
    /// The file is being deleted.
    pub delete_pending: bool,
    /// The volume's file system.
    pub fs_type: FsType,
    /// The volume's 32-bit serial number (`GetVolumeInformationByHandleW`).
    pub volume_serial_32: u32,
    /// The volume says it supports a change journal.
    pub supports_usn: bool,
}

impl FileFacts {
    /// Reads every fact about the opened `file`.
    pub fn read(file: &File) -> io::Result<Self> {
        let id = sys::file_id_info(file)?;
        let basic = sys::basic_info(file)?;
        let standard = sys::standard_info(file)?;
        let volume = sys::volume_information(file)?;
        let supports_usn = volume.flags & FILE_SUPPORTS_USN_JOURNAL != 0;
        let usn = if supports_usn { read_usn(file) } else { None };
        Ok(Self {
            volume_serial: id.VolumeSerialNumber,
            file_id: id.FileId.Identifier,
            usn,
            creation: file_time(basic.CreationTime),
            last_access: file_time(basic.LastAccessTime),
            last_write: file_time(basic.LastWriteTime),
            change: file_time(basic.ChangeTime),
            attributes: basic.FileAttributes,
            size: standard.end_of_file,
            number_of_links: standard.number_of_links,
            directory: standard.directory,
            delete_pending: standard.delete_pending,
            fs_type: FsType::from_name(&volume.fs_name),
            volume_serial_32: volume.serial,
            supports_usn,
        })
    }
}

/// The journal ID and the file's USN, or `None` if the journal is not
/// active (the volume supports one, but none was created) or cannot be
/// read.
fn read_usn(file: &File) -> Option<(u64, i64)> {
    let journal = sys::usn_journal_id(file).ok()?;
    let record = sys::read_file_usn_bytes(file).ok()?;
    let facts = parse_usn_record(&record).ok()?;
    Some((journal, facts.usn))
}

/// The [`FileStamp`] backend: opens with [`open_for_hashing`] and stamps
/// the handle.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinStamps;

impl WinStamps {
    /// The key of the opened `file`, whose path is `path`, from `facts`.
    /// Strong when the volume has an active change journal; otherwise weak,
    /// keyed by the normalised final path of the handle.
    pub fn key_from(file: &File, facts: &FileFacts) -> io::Result<FileKey> {
        if let Some((usn_journal_id, usn)) = facts.usn {
            return Ok(FileKey::Strong {
                volume_serial: facts.volume_serial,
                file_id: facts.file_id,
                usn_journal_id,
                usn,
                last_write: facts.last_write,
                size: facts.size,
            });
        }
        let final_path = sys::final_path_by_handle(file, 0)?;
        let key = normalize_win32(&final_path)
            .and_then(|mut p| {
                p.mark_long_names_verified();
                p.match_key()
            })
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(FileKey::Weak {
            path: key,
            size: facts.size,
            last_write: facts.last_write,
            creation: facts.creation,
        })
    }
}

impl FileStamp for WinStamps {
    type File = File;
    type Error = io::Error;

    fn open(&self, path: &str) -> io::Result<File> {
        open_for_hashing(Path::new(path))
    }

    fn stamp(&self, file: &File) -> io::Result<FileKey> {
        let facts = FileFacts::read(file)?;
        if facts.directory {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file"));
        }
        Self::key_from(file, &facts)
    }

    fn rewind(&self, file: &File) -> io::Result<()> {
        let mut f: &File = file;
        f.seek(SeekFrom::Start(0)).map(|_| ())
    }
}

/// How [`hash_open_file`] reads a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadStrategy {
    /// Through a memory mapping, one window at a time.
    Mapped,
    /// With buffered reads of [`HashOptions::buffer_size`] bytes.
    Buffered,
}

/// The strategy #46 asks for: mapped for files of at least
/// [`MMAP_THRESHOLD`] bytes on a local fixed volume (`local_fixed`), and
/// buffered for smaller files and for network and removable volumes, where
/// a mapped read that fails partway raises an exception instead of an
/// error.
#[must_use]
pub const fn choose_strategy(size: u64, local_fixed: bool) -> ReadStrategy {
    if local_fixed && size >= MMAP_THRESHOLD {
        ReadStrategy::Mapped
    } else {
        ReadStrategy::Buffered
    }
}

/// Hashes the opened `file` (its default data stream) from its first byte.
///
/// `local_fixed` says whether the file is on a local fixed volume (from
/// [`crate::fsctx::VolumeInfo::location_class`]); only then is a large
/// file mapped. During an inventory scan (`purpose`), a cloud placeholder is
/// not read and the result is [`HashStatus::Deferred`].
///
/// The size is checked against [`HashOptions::max_hash_size`] before any
/// read, and the number of bytes read must equal the size read first, or
/// the result is [`HashError::SizeChanged`].
pub fn hash_open_file(
    file: &File,
    options: &HashOptions,
    purpose: HashPurpose,
    local_fixed: bool,
) -> Result<HashStatus, HashError> {
    options.validate()?;
    let basic = sys::basic_info(file)?;
    if let Some(reason) = skip_for_inventory(basic.FileAttributes, purpose) {
        return Ok(HashStatus::Deferred(reason));
    }
    let standard = sys::standard_info(file)?;
    if standard.directory {
        return Err(HashError::NotAFile);
    }
    let size = standard.end_of_file;
    if size > options.max_hash_size {
        return Ok(HashStatus::TooLarge {
            limit: options.max_hash_size,
        });
    }
    let mut f: &File = file;
    f.seek(SeekFrom::Start(0))?;
    let hashes = match choose_strategy(size, local_fixed) {
        ReadStrategy::Mapped => hash_mapped(file, size, options)?,
        ReadStrategy::Buffered => {
            match crate::hash::hash_reader(file.take(size.saturating_add(1)), options)? {
                HashStatus::Complete(h) => h,
                other => return Ok(other),
            }
        }
    };
    if hashes.size != size {
        return Err(HashError::SizeChanged {
            expected: size,
            actual: hashes.size,
        });
    }
    Ok(HashStatus::Complete(hashes))
}

/// Hashes `size` bytes of `file` through a mapping, [`MAP_WINDOW`] bytes at
/// a time.
fn hash_mapped(
    file: &File,
    size: u64,
    options: &HashOptions,
) -> Result<crate::hash::FlatHashes, HashError> {
    let mut hasher = MultiHasher::new(options.algorithms);
    if size == 0 {
        return Ok(hasher.finalize());
    }
    let mapping = sys::Mapping::new(file)?;
    let window = MAP_WINDOW - MAP_WINDOW % sys::allocation_granularity();
    let mut offset = 0_u64;
    while offset < size {
        let len = (size - offset).min(window);
        let len = usize::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "window too large"))?;
        let view = mapping.view(offset, len)?;
        hasher.update(view.bytes());
        drop(view);
        offset = offset.saturating_add(window);
    }
    Ok(hasher.finalize())
}

/// One alternate data stream, hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHash {
    /// The stream, as listed.
    pub stream: StreamEntry,
    /// Its identity: the file's path, `:`, and the stream name.
    pub identity: String,
    /// The result of hashing it.
    pub status: HashStatus,
}

/// Lists the streams of the opened `file`.
pub fn list_streams(file: &File) -> io::Result<crate::fsctx::ntfs::StreamList> {
    let bytes = sys::stream_info_bytes(file)?;
    parse_stream_info(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Hashes every alternate data stream of the file at `path` on its own,
/// as `path:stream` identities (`include_ads` in #46). The default stream
/// is not included; hash it with [`hash_open_file`].
///
/// `path` must be a fully qualified path to a file, not a stream. Each
/// stream is opened by name, so a stream that is deleted between listing
/// and opening is skipped.
pub fn hash_streams(path: &Path, options: &HashOptions) -> Result<Vec<StreamHash>, HashError> {
    let base = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not valid Unicode"))?;
    if !path.is_absolute()
        || base
            .rsplit(['\\', '/'])
            .next()
            .is_some_and(|l| l.contains(':'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must name a file, not a stream",
        )
        .into());
    }
    let file = open_for_hashing(path)?;
    let list = list_streams(&file)?;
    let mut out = Vec::new();
    for stream in list.alternate().filter(|s| s.kind == "$DATA") {
        let identity = format!("{base}:{}", stream.name);
        let stream_path = format!("{identity}:$DATA");
        let handle = match open_for_hashing(Path::new(&stream_path)) {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if stream.size > options.max_hash_size {
            out.push(StreamHash {
                stream: stream.clone(),
                identity,
                status: HashStatus::TooLarge {
                    limit: options.max_hash_size,
                },
            });
            continue;
        }
        let status = crate::hash::hash_reader(
            handle.take(options.max_hash_size.saturating_add(1)),
            options,
        )?;
        out.push(StreamHash {
            stream: stream.clone(),
            identity,
            status,
        });
    }
    Ok(out)
}

/// The peak working set of this process, in bytes, as the OS reports it.
/// For memory budgets and health reporting (#65, #67), and for the test
/// that hashing a large file keeps memory bounded.
pub fn peak_working_set_bytes() -> io::Result<u64> {
    sys::peak_working_set()
}
