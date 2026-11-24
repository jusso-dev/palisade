//! File stamps: what identifies one version of one file, for the hash
//! cache (#46).
//!
//! A cached digest may be reused only while the file is provably the same
//! file, unchanged. On a volume with a change journal that is the
//! **strong** key: volume serial, 128-bit file ID, the journal's ID, the
//! file's last USN, last-write time and size. Any write moves the USN, so
//! a match means the content is the one that was hashed. The journal ID
//! is part of the key because a deleted and recreated journal restarts its
//! USNs, so an old USN could otherwise come round again.
//!
//! A rename also moves the file's USN, so on its own it is a miss (which
//! fails safe: the file is hashed again). The journal consumer (#60), which
//! can see that every journal record since the cached USN is a rename and
//! nothing else, may carry the entry over: it finds the cached key with
//! [`super::HashCache::key_of`] and calls
//! [`super::HashCache::rekey_after_rename`].
//!
//! Without a journal (FAT, exFAT, ReFS without one, network shares) the
//! key falls back to the normalised path, size, last-write and creation
//! times. Timestamps can be set by anyone who can write the file, so such
//! a key is **weak** ([`FileKey::is_weak`]), and the verify mode can
//! refuse to trust it ([`super::cache::HashVerifyMode`]).
//!
//! Reading these values needs OS calls (`GetFileInformationByHandleEx`
//! with `FileIdInfo`, and `FSCTL_READ_FILE_USN_DATA`). They belong to the
//! agent's Windows backend, which implements [`FileStamp`] (#54, #29). This
//! module only defines the types, so the cache logic is portable and
//! tested everywhere.

#![forbid(unsafe_code)]

use std::fmt;

/// A point in time as the file system records it: 100-nanosecond intervals
/// since 1601-01-01 UTC (a Windows `FILETIME`), kept raw so no precision
/// is lost or invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileTime(pub u64);

/// The identity and change markers of one version of one file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileKey {
    /// From a volume with a change journal.
    Strong {
        /// The volume serial number (64-bit, as `FileIdInfo` reports it).
        volume_serial: u64,
        /// The 128-bit file ID.
        file_id: [u8; 16],
        /// The volume's change journal ID (`UsnJournalID`).
        usn_journal_id: u64,
        /// The file's last update sequence number.
        usn: i64,
        /// The last-write time.
        last_write: FileTime,
        /// The size of the default data stream, in bytes.
        size: u64,
    },
    /// From a volume without a change journal: anyone who can write the
    /// file can also restore its timestamps.
    Weak {
        /// The normalised path (a match key, such as
        /// [`crate::fsctx::NormalizedPath::match_key`]).
        path: String,
        /// The size of the default data stream, in bytes.
        size: u64,
        /// The last-write time.
        last_write: FileTime,
        /// The creation time.
        creation: FileTime,
    },
}

impl FileKey {
    /// Whether this is a fallback key without a change journal
    /// (`weak_key=true` in #46).
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        matches!(self, Self::Weak { .. })
    }

    /// The file size the key records.
    #[must_use]
    pub const fn size(&self) -> u64 {
        match self {
            Self::Strong { size, .. } | Self::Weak { size, .. } => *size,
        }
    }

    /// A canonical encoding of every component, used for the record MAC.
    /// Each variant has its own tag byte and every field a fixed width or
    /// a length prefix, so two different keys never encode the same.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Strong {
                volume_serial,
                file_id,
                usn_journal_id,
                usn,
                last_write,
                size,
            } => {
                out.push(1);
                out.extend_from_slice(&volume_serial.to_le_bytes());
                out.extend_from_slice(file_id);
                out.extend_from_slice(&usn_journal_id.to_le_bytes());
                out.extend_from_slice(&usn.to_le_bytes());
                out.extend_from_slice(&last_write.0.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
            }
            Self::Weak {
                path,
                size,
                last_write,
                creation,
            } => {
                out.push(2);
                let len = u64::try_from(path.len()).unwrap_or(u64::MAX);
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(path.as_bytes());
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&last_write.0.to_le_bytes());
                out.extend_from_slice(&creation.0.to_le_bytes());
            }
        }
    }

    /// An estimate of the key's memory use, for the cache's byte budget.
    pub(crate) fn weight(&self) -> usize {
        match self {
            Self::Strong { .. } => 56,
            Self::Weak { path, .. } => 32usize.saturating_add(path.len()),
        }
    }
}

impl fmt::Display for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strong {
                volume_serial,
                file_id,
                usn,
                size,
                ..
            } => {
                write!(f, "volume {volume_serial:016x} file ")?;
                for b in file_id {
                    write!(f, "{b:02x}")?;
                }
                write!(f, " usn {usn} size {size}")
            }
            Self::Weak { path, size, .. } => write!(f, "{path} size {size} (weak key)"),
        }
    }
}

/// Opens files and reads their [`FileKey`]; implemented by the OS
/// backend (#54).
///
/// Everything is done through **one opened handle**. The key read before
/// hashing, the bytes hashed and the key read after hashing must all come
/// from the same file object, never from three separate path lookups:
/// otherwise a link or junction swapped between them could pair one file's
/// key with another file's digest, and the cache would then vouch for the
/// wrong file. [`super::cache::hash_through`] opens the file once, stamps
/// that handle, hashes through it, and stamps it again.
///
/// On Windows the backend opens the file with sharing for read, write and
/// delete, and reads the key from the handle
/// (`GetFileInformationByHandleEx` with `FileIdInfo`, and
/// `FSCTL_READ_FILE_USN_DATA`).
pub trait FileStamp {
    /// An opened file.
    type File;
    /// The error the backend reports.
    type Error;

    /// Opens the file at `path` for reading.
    fn open(&self, path: &str) -> Result<Self::File, Self::Error>;

    /// The current key of the opened `file`.
    fn stamp(&self, file: &Self::File) -> Result<FileKey, Self::Error>;

    /// Moves `file` back to its first byte. [`super::cache::hash_through`]
    /// calls it before every hashing attempt, so a retry after a change
    /// reads the whole file again rather than from where the last attempt
    /// stopped. A backend that reads by position can do nothing here.
    fn rewind(&self, file: &Self::File) -> Result<(), Self::Error>;
}
