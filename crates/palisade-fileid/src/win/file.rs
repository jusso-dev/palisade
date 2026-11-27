//! The Windows file backend for hashing and the hash cache (#46).
//!
//! - [`open_for_hashing`] opens a file the way the hash cache needs:
//!   sharing read, write and delete, so hashing never blocks a writer or an
//!   installer, and with `FILE_FLAG_SEQUENTIAL_SCAN`, since every byte is
//!   read once in order. [`open_for_inventory`] also asks the OS not to
//!   recall a cloud placeholder just because it was opened.
//! - [`WinStamps`] implements [`FileStamp`]: the strong key from
//!   `FileIdInfo` and the volume's change journal, or the weak key, all
//!   read from the **opened handle**. A network file, or a volume without
//!   an active journal or without 128-bit file IDs, gets the weak key.
//! - [`FileFacts`] is everything about a file the cache and inventory need
//!   (IDs, USN, the four timestamps, attributes, links, size, volume), from
//!   the same handle.
//! - [`hash_open_file`] hashes an opened file, memory-mapped in windows for
//!   a large file on a local fixed volume, and with buffered reads
//!   otherwise. It skips cloud placeholders during inventory scans, and
//!   never maps one.
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
    FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};

use super::sys;
use crate::fsctx::ntfs::{StreamEntry, StreamList, parse_stream_info, parse_usn_record};
use crate::fsctx::{FsType, normalize_win32};
use crate::hash::{
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FileKey, FileStamp, FileTime, FlatHashes, HashError, HashOptions, HashPurpose, HashStatus,
    MultiHasher, skip_for_inventory,
};

/// `FILE_SUPPORTS_USN_JOURNAL`, in the volume flags.
const FILE_SUPPORTS_USN_JOURNAL: u32 = 0x0200_0000;
/// `FILE_NAMED_STREAMS`, in the volume flags.
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
/// `VOLUME_NAME_DOS` and `VOLUME_NAME_GUID` for `GetFinalPathNameByHandleW`.
const VOLUME_NAME_DOS: u32 = 0;
const VOLUME_NAME_GUID: u32 = 1;
/// `VOLUME_NAME_NONE | FILE_NAME_OPENED`: the path as opened, without the
/// volume. No volume-manager lookup and no walk of parent folders to expand
/// short names, so it works on network shares and below folders the caller
/// cannot list.
const OPENED_NAME_NO_VOLUME: u32 = 0x4 | 0x8;
/// `VOLUME_NAME_GUID | FILE_NAME_OPENED`.
const OPENED_NAME_GUID: u32 = 0x1 | 0x8;

/// Files at least this large on a local fixed volume are hashed through a
/// memory mapping: 16 MiB, as #46 asks.
pub const MMAP_THRESHOLD: u64 = 16 * 1024 * 1024;

/// The size of each mapped window: 8 MiB, a multiple of every allocation
/// granularity. Each window is unmapped before the next is mapped, which
/// also drops its pages from the working set, so memory use stays bounded
/// (#46: under 16 MB to hash a 1 GB file), whatever the file size.
pub const MAP_WINDOW: u64 = 8 * 1024 * 1024;

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Opens `path` for hashing: read access, sharing read, write and delete,
/// with `FILE_FLAG_SEQUENTIAL_SCAN`.
///
/// Sharing write and delete means a writer can change the file while it is
/// hashed. That is detected afterwards by comparing stamps
/// ([`crate::hash::hash_through`]), never prevented by locking writers out.
pub fn open_for_hashing(path: &Path) -> io::Result<File> {
    open_with(path, FILE_FLAG_SEQUENTIAL_SCAN)
}

/// As [`open_for_hashing`], with `FILE_FLAG_OPEN_NO_RECALL`, for inventory
/// scans: opening a `RECALL_ON_OPEN` placeholder then does not download it,
/// so [`hash_open_file`] can defer it.
pub fn open_for_inventory(path: &Path) -> io::Result<File> {
    open_with(path, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_NO_RECALL)
}

fn open_with(path: &Path, flags: u32) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(flags)
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
    /// The 64-bit volume serial number and the 128-bit file ID
    /// (`FileIdInfo`), if the file system reports them.
    pub file_id: Option<(u64, [u8; 16])>,
    /// The change journal's ID and the file's last USN, if the file is on a
    /// local volume that keeps an active journal.
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
    /// The file is on a remote file system, through a network redirector.
    pub remote: bool,
    /// The volume's file system. [`FsType::Network`] for a remote file,
    /// whatever file system the server reports.
    pub fs_type: Option<FsType>,
    /// The volume's 32-bit serial number (`GetVolumeInformationByHandleW`).
    pub volume_serial_32: Option<u32>,
    /// The volume's `FILE_*` capability flags.
    pub volume_flags: Option<u32>,
    /// The handle is a **named stream** (`file.txt:name`), not a file's
    /// default stream. Its file ID, USN and timestamps are the host file's,
    /// so it never gets a strong key (see [`WinStamps::key_from`]).
    pub named_stream: bool,
}

impl FileFacts {
    /// Reads every fact about the opened `file`. Only the basic and
    /// standard information are required; anything else the file system
    /// does not report is `None`.
    pub fn read(file: &File) -> io::Result<Self> {
        if !sys::is_disk_file(file) {
            return Err(invalid_input("not a file on disk"));
        }
        let basic = sys::basic_info(file)?;
        let standard = sys::standard_info(file)?;
        // Any sign of a redirector, not only `FileRemoteProtocolInfo`,
        // which has been seen to miss a share (#54).
        let remote = super::volume::network_evidence(file, None).is_network();
        let file_id = sys::file_id_info(file)
            .ok()
            .map(|id| (id.VolumeSerialNumber, id.FileId.Identifier))
            // An all-zero ID means the file system has none to report.
            .filter(|(_, id)| *id != [0; 16]);
        let volume = sys::volume_information(file).ok();
        let fs_type = if remote {
            Some(FsType::Network)
        } else {
            volume.as_ref().map(|v| FsType::from_name(&v.fs_name))
        };
        let journal = !remote
            && file_id.is_some()
            && volume
                .as_ref()
                .is_some_and(|v| v.flags & FILE_SUPPORTS_USN_JOURNAL != 0);
        // The final path of a named-stream handle ends in `:name`. If it
        // cannot be read, assume a named stream: that only weakens the key.
        let named_stream = sys::final_path_by_handle(file, OPENED_NAME_NO_VOLUME)
            .map_or(true, |p| is_stream_path(&p));
        let usn = if journal && !named_stream {
            read_usn(file)
        } else {
            None
        };
        Ok(Self {
            file_id,
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
            remote,
            fs_type,
            volume_serial_32: volume.as_ref().map(|v| v.serial),
            volume_flags: volume.as_ref().map(|v| v.flags),
            named_stream,
        })
    }

    /// Whether the file is a cloud placeholder: offline, or recalled on
    /// open or on data access.
    #[must_use]
    pub const fn is_placeholder(&self) -> bool {
        is_placeholder(self.attributes)
    }
}

/// Whether a path (`\dir\file.txt:name`) names a named stream: a `:` in
/// its last component, other than an explicit default stream
/// (`file.txt::$DATA`, in any case).
fn is_stream_path(path: &str) -> bool {
    let Some(last) = path.rsplit('\\').next() else {
        return false;
    };
    match last.split_once(':') {
        None => false,
        Some((name, rest)) => !(rest.eq_ignore_ascii_case(":$DATA") && !name.is_empty()),
    }
}

const fn is_placeholder(attributes: u32) -> bool {
    attributes
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0
}

/// The volume root of the opened `file`, as a volume GUID path, from its
/// final path.
pub(crate) fn volume_root(file: &File) -> io::Result<String> {
    let guid_path = sys::final_path_by_handle(file, OPENED_NAME_GUID)?;
    // `\\?\Volume{GUID}\rest`: the volume device is everything before the
    // fourth backslash, without it.
    let end = guid_path
        .match_indices('\\')
        .nth(3)
        .map(|(i, _)| i)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a volume GUID path"))?;
    let root = guid_path.get(..end).unwrap_or_default();
    if !root.starts_with(r"\\?\Volume{") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a volume GUID path",
        ));
    }
    Ok(root.to_owned())
}

/// The journal ID of the volume `file` is on, and the file's USN. `None`
/// if the volume has no active journal, or either cannot be read.
fn read_usn(file: &File) -> Option<(u64, i64)> {
    let record = sys::read_file_usn_bytes(file).ok()?;
    let facts = parse_usn_record(&record).ok()?;
    let journal = journal_id_attempts(file)
        .into_iter()
        .find_map(|(_, r)| r.ok())?;
    Some((journal, facts.usn))
}

/// Ways to get the journal ID of the volume `file` is on, tried in order
/// until one works: `FSCTL_QUERY_USN_JOURNAL` on the file's own handle,
/// then on the file's own volume device (by its volume GUID, never a drive
/// letter, which could name another volume), opened with no access rights
/// and then with read access (which needs administrator rights). Each
/// attempt is labelled, so a test can report which one the system accepts.
/// Stops at the first success, or when the volume says it has no active
/// journal.
pub(crate) fn journal_id_attempts(file: &File) -> Vec<(&'static str, io::Result<u64>)> {
    let mut out: Vec<(&'static str, io::Result<u64>)> = Vec::new();
    let r = sys::usn_journal_id(file);
    let ok = r.is_ok();
    out.push(("file handle", r));
    if ok {
        return out;
    }
    let root = match volume_root(file) {
        Ok(r) => r,
        Err(e) => {
            out.push(("volume root", Err(e)));
            return out;
        }
    };
    // Only the file's own volume, by its GUID: a drive letter could name
    // another volume (a volume mounted in a folder has its host's letter).
    // No access rights first (enough for this control code); then
    // `GENERIC_READ`, which needs administrator rights on a volume. A
    // volume that says its journal is not active has none to report, so
    // nothing more is tried.
    for (label, access) in [
        ("volume GUID, no access", 0_u32),
        ("volume GUID, read", 0x8000_0000),
    ] {
        let r = OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&root)
            .and_then(|v| sys::usn_journal_id(&v));
        let stop = match &r {
            Ok(_) => true,
            // ERROR_JOURNAL_DELETE_IN_PROGRESS, ERROR_JOURNAL_NOT_ACTIVE.
            Err(e) => matches!(e.raw_os_error(), Some(1178 | 1179)),
        };
        out.push((label, r));
        if stop {
            break;
        }
    }
    out
}

/// The [`FileStamp`] backend: opens with [`open_for_hashing`] and stamps
/// the handle.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinStamps;

impl WinStamps {
    /// The key of the opened `file` from `facts`: strong when the file is
    /// local, its volume keeps an active change journal and reports 128-bit
    /// file IDs, and the handle is a file's default stream; otherwise weak,
    /// keyed by the normalised final path of the handle (the drive-letter
    /// form, or the volume GUID form for a volume mounted without a drive
    /// letter).
    ///
    /// A named stream shares its host file's ID, USN and timestamps, so a
    /// strong key could not tell `file.exe` from a same-sized
    /// `file.exe:payload`. Its weak key holds the stream name, so the two
    /// never share a cache entry.
    pub fn key_from(file: &File, facts: &FileFacts) -> io::Result<FileKey> {
        if let (Some((volume_serial, file_id)), Some((usn_journal_id, usn)), false, false) =
            (facts.file_id, facts.usn, facts.remote, facts.named_stream)
        {
            return Ok(FileKey::Strong {
                volume_serial,
                file_id,
                usn_journal_id,
                usn,
                last_write: facts.last_write,
                size: facts.size,
            });
        }
        let final_path = sys::final_path_by_handle(file, VOLUME_NAME_DOS)
            .or_else(|_| sys::final_path_by_handle(file, VOLUME_NAME_GUID))?;
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
            return Err(invalid_input("not a file"));
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
/// buffered for smaller files and for network and removable volumes.
///
/// A mapped read that fails partway (a network drop, removed media, a cloud
/// recall that fails) raises an in-page exception instead of returning an
/// error, so only a local fixed disk is mapped, and [`hash_open_file`]
/// never maps a cloud placeholder.
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
/// file mapped, and never when it is a cloud placeholder. During an
/// inventory scan (`purpose`), a cloud placeholder is not read and the
/// result is [`HashStatus::Deferred`].
///
/// The size is checked against [`HashOptions::max_hash_size`] before any
/// read. The bytes hashed must be exactly the size read first, and the size
/// is read again afterwards and must not have changed; otherwise the result
/// is [`HashError::SizeChanged`]. Inside [`crate::hash::hash_through`],
/// prefer [`hash_open_file_for_cache`], which turns a size change into a
/// retry instead of an error.
pub fn hash_open_file(
    file: &File,
    options: &HashOptions,
    purpose: HashPurpose,
    local_fixed: bool,
) -> Result<HashStatus, HashError> {
    hash_handle(file, options, purpose, local_fixed, true)
}

/// The body of [`hash_open_file`]; `strict` adds the size checks.
fn hash_handle(
    file: &File,
    options: &HashOptions,
    purpose: HashPurpose,
    local_fixed: bool,
    strict: bool,
) -> Result<HashStatus, HashError> {
    options.validate()?;
    if !sys::is_disk_file(file) {
        return Err(HashError::NotAFile);
    }
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
    let mapped = !is_placeholder(basic.FileAttributes)
        && choose_strategy(size, local_fixed) == ReadStrategy::Mapped;
    let hashes = match mapped.then(|| hash_mapped(file, size, options)) {
        Some(Ok(h)) => h,
        // The file shrank before it could be mapped. Strictly, that is a
        // size change; otherwise read it buffered and let the stamp check
        // that follows see the new size.
        Some(Err(HashError::SizeChanged { .. })) if !strict => {
            f.seek(SeekFrom::Start(0))?;
            match crate::hash::hash_reader(file.take(size.saturating_add(1)), options)? {
                HashStatus::Complete(h) => h,
                other => return Ok(other),
            }
        }
        Some(Err(e)) => return Err(e),
        None => match crate::hash::hash_reader(file.take(size.saturating_add(1)), options)? {
            HashStatus::Complete(h) => h,
            other => return Ok(other),
        },
    };
    if !strict {
        return Ok(HashStatus::Complete(hashes));
    }
    let after = sys::standard_info(file)?.end_of_file;
    if hashes.size != size || after != size {
        return Err(HashError::SizeChanged {
            expected: size,
            actual: if hashes.size == size {
                after
            } else {
                hashes.size
            },
        });
    }
    Ok(HashStatus::Complete(hashes))
}

/// [`hash_open_file`] for use as the `compute` step of
/// [`crate::hash::hash_through`]. It does not check the size again after
/// hashing, and returns whatever was hashed: `hash_through` stamps the
/// handle afterwards, and any change in size moves the stamp (size and USN
/// are part of the key), so a file that changed is retried and finally
/// reported [`crate::hash::Through::Unstable`], with any cached entry for it
/// dropped, rather than ending the lookup with an error.
pub fn hash_open_file_for_cache(
    file: &File,
    options: &HashOptions,
    purpose: HashPurpose,
    local_fixed: bool,
) -> Result<HashStatus, HashError> {
    hash_handle(file, options, purpose, local_fixed, false)
}

/// Hashes `size` bytes of `file` through a mapping, [`MAP_WINDOW`] bytes at
/// a time. The mapped bytes are copied into a private buffer before they
/// are hashed, so no reference is ever made to memory another process can
/// write.
fn hash_mapped(file: &File, size: u64, options: &HashOptions) -> Result<FlatHashes, HashError> {
    let mut hasher = MultiHasher::new(options.algorithms);
    if size == 0 {
        return Ok(hasher.finalize());
    }
    let mapping = match sys::Mapping::new(file, size) {
        Ok(m) => m,
        Err(e) => {
            let now = sys::standard_info(file)?.end_of_file;
            if now != size {
                return Err(HashError::SizeChanged {
                    expected: size,
                    actual: now,
                });
            }
            return Err(e.into());
        }
    };
    let granularity = sys::allocation_granularity();
    let window = (MAP_WINDOW / granularity)
        .max(1)
        .saturating_mul(granularity);
    let mut buffer = vec![0_u8; options.buffer_size];
    let mut offset = 0_u64;
    while offset < size {
        let len = usize::try_from((size - offset).min(window))
            .map_err(|_| invalid_input("window too large"))?;
        let view = match mapping.view(offset, len) {
            Ok(v) => v,
            // The section is `size` bytes and holds the file at least that
            // long, so a failed view inside it is an I/O error, unless the
            // size has changed in a way the OS reports this way.
            Err(e) => {
                let now = sys::standard_info(file)?.end_of_file;
                if now != size {
                    return Err(HashError::SizeChanged {
                        expected: size,
                        actual: now,
                    });
                }
                return Err(e.into());
            }
        };
        let mut at = 0;
        while at < view.len() {
            let n = (view.len() - at).min(buffer.len());
            let chunk = buffer.get_mut(..n).unwrap_or_default();
            view.copy_to(at, chunk)?;
            hasher.update(chunk);
            at += n;
        }
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

/// The alternate data streams of a file, hashed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamHashes {
    /// One entry per named `$DATA` stream, in the order the OS lists them.
    pub streams: Vec<StreamHash>,
    /// The file had more than [`crate::fsctx::ntfs::MAX_STREAMS`] streams;
    /// the rest were not listed or hashed. A caller must not treat the
    /// file's streams as fully known.
    pub truncated: bool,
}

/// Lists the streams of the opened `file`. A file on a volume without
/// named streams has only its default stream.
pub fn list_streams(file: &File) -> io::Result<StreamList> {
    let named = sys::volume_information(file).map_or(true, |v| v.flags & FILE_NAMED_STREAMS != 0);
    if !named {
        return Ok(StreamList::default());
    }
    let bytes = sys::stream_info_bytes(file)?;
    parse_stream_info(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Hashes every alternate data stream of the file at `path` on its own,
/// as `path:stream` identities (`include_ads` in #46). The default stream
/// is not included; hash it with [`hash_open_file`].
///
/// `path` must be a fully qualified path to a file, not a stream, without a
/// trailing separator, and (unless it is a literal `\\?\` path) without a
/// trailing dot or space, since the Win32 layer strips those from the file
/// name but not from a stream path built on it. The streams are listed from
/// the opened file, then each is opened through the file's **final path**
/// and checked to be on the same file (same 128-bit file ID), so a path
/// swapped in between cannot substitute another file's stream. A stream
/// that is deleted in between is skipped; any other failure is an error.
pub fn hash_streams(path: &Path, options: &HashOptions) -> Result<StreamHashes, HashError> {
    options.validate()?;
    let base = path
        .to_str()
        .ok_or_else(|| invalid_input("path is not valid Unicode"))?;
    let verbatim = base.starts_with(r"\\?\");
    let separators: &[char] = if verbatim { &['\\'] } else { &['\\', '/'] };
    let last = base.rsplit(separators).next().unwrap_or("");
    if !path.is_absolute()
        || base.ends_with(separators)
        || (!verbatim && base.ends_with(['.', ' ']))
        || last.contains(':')
    {
        return Err(invalid_input("path must name a file, not a stream").into());
    }
    let file = open_for_hashing(path)?;
    if !sys::is_disk_file(&file) || sys::standard_info(&file)?.directory {
        return Err(HashError::NotAFile);
    }
    let list = list_streams(&file)?;
    let mut out = StreamHashes {
        streams: Vec::new(),
        truncated: list.truncated,
    };
    if list.alternate().next().is_none() {
        return Ok(out);
    }
    let file_id = sys::file_id_info(&file)?;
    if file_id.FileId.Identifier == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the file system reports no file ID, so streams cannot be bound to the file",
        )
        .into());
    }
    // The literal final path of the opened file, in the drive or volume GUID
    // form, so appending a stream name cannot be changed by normalisation.
    let final_path = sys::final_path_by_handle(&file, VOLUME_NAME_DOS)
        .or_else(|_| sys::final_path_by_handle(&file, VOLUME_NAME_GUID))?;
    for stream in list.alternate() {
        let identity = format!("{base}:{}", stream.name);
        let stream_path = format!("{final_path}:{}:$DATA", stream.name);
        let handle = match open_for_hashing(Path::new(&stream_path)) {
            Ok(h) => h,
            // Skipped only if the stream really is gone from this file: the
            // path may instead have been moved or swapped for another file.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let still = list_streams(&file)?;
                let folded = crate::fsctx::fold_case(&stream.name);
                // If the list was cut, the stream may be past the cut, so
                // its absence cannot be shown.
                if still.truncated
                    || still
                        .alternate()
                        .any(|s| crate::fsctx::fold_case(&s.name) == folded)
                {
                    return Err(io::Error::other(
                        "the file moved or changed while its streams were hashed",
                    )
                    .into());
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let same = sys::file_id_info(&handle)?;
        if same.VolumeSerialNumber != file_id.VolumeSerialNumber
            || same.FileId.Identifier != file_id.FileId.Identifier
        {
            return Err(io::Error::other("the file changed while its streams were hashed").into());
        }
        let status = if stream.size > options.max_hash_size {
            HashStatus::TooLarge {
                limit: options.max_hash_size,
            }
        } else {
            crate::hash::hash_reader(
                handle.take(options.max_hash_size.saturating_add(1)),
                options,
            )?
        };
        out.streams.push(StreamHash {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Which journal-ID query the system accepts; at least one must, on
    /// the runners' system volume.
    #[test]
    fn journal_id_on_the_system_volume() {
        let windir = std::env::var("WINDIR").unwrap();
        let f = open_for_hashing(&Path::new(&windir).join(r"System32\cmd.exe")).unwrap();
        let mut attempts = journal_id_attempts(&f);
        for (label, r) in &attempts {
            eprintln!("journal ID via {label}: {r:?}");
        }
        // The hosted runners may come without an active journal on the
        // system volume. On CI, create one (the runners are elevated) and
        // try again; elsewhere leave the machine alone.
        if !attempts.iter().any(|(_, r)| r.is_ok()) && std::env::var_os("CI").is_some() {
            let drive: String = windir.chars().take(2).collect();
            let status = std::process::Command::new("fsutil")
                .args(["usn", "createjournal", "m=33554432", "a=4194304", &drive])
                .status()
                .unwrap();
            eprintln!("fsutil usn createjournal {drive}: {status}");
            attempts = journal_id_attempts(&f);
            for (label, r) in &attempts {
                eprintln!("journal ID via {label}: {r:?}");
            }
            assert!(attempts.iter().any(|(_, r)| r.is_ok()), "{attempts:?}");
        }
    }

    #[test]
    fn stream_paths() {
        assert!(is_stream_path(r"\dir\file.txt:payload"));
        assert!(is_stream_path(r"\dir\file.txt:payload:$DATA"));
        assert!(!is_stream_path(r"\dir\file.txt"));
        assert!(!is_stream_path(r"\dir\file.txt::$DATA"));
        assert!(!is_stream_path(r"\dir\file.txt::$data"));
        assert!(is_stream_path(r"\dir\file.txt::$INDEX_ALLOCATION"));
        assert!(
            !is_stream_path(r"\dir:x\file.txt"),
            "only the last component counts"
        );
        assert!(!is_stream_path(""));
    }
}
