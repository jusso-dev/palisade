//! A file's identity, timestamps, attributes and hard links as file-system
//! context (#54).
//!
//! The Windows backend reads these from one open handle
//! (`FILE_BASIC_INFO`, `FILE_STANDARD_INFO`, `FILE_ID_INFO` and the
//! change-journal record) and from `FindFirstFileNameW`. The types here are
//! portable, so a server or CLI can fill them from other metadata and a
//! consumer can test them anywhere.

#![forbid(unsafe_code)]

use crate::hash::FileTime;

/// `FILE_ATTRIBUTE_*` bits, as the file system reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    /// `FILE_ATTRIBUTE_READONLY`.
    pub const READONLY: u32 = 0x0000_0001;
    /// `FILE_ATTRIBUTE_HIDDEN`.
    pub const HIDDEN: u32 = 0x0000_0002;
    /// `FILE_ATTRIBUTE_SYSTEM`.
    pub const SYSTEM: u32 = 0x0000_0004;
    /// `FILE_ATTRIBUTE_DIRECTORY`.
    pub const DIRECTORY: u32 = 0x0000_0010;
    /// `FILE_ATTRIBUTE_SPARSE_FILE`.
    pub const SPARSE: u32 = 0x0000_0200;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    pub const REPARSE_POINT: u32 = 0x0000_0400;
    /// `FILE_ATTRIBUTE_COMPRESSED`.
    pub const COMPRESSED: u32 = 0x0000_0800;
    /// `FILE_ATTRIBUTE_OFFLINE`.
    pub const OFFLINE: u32 = crate::hash::FILE_ATTRIBUTE_OFFLINE;
    /// `FILE_ATTRIBUTE_ENCRYPTED`.
    pub const ENCRYPTED: u32 = 0x0000_4000;
    /// `FILE_ATTRIBUTE_RECALL_ON_OPEN`.
    pub const RECALL_ON_OPEN: u32 = crate::hash::FILE_ATTRIBUTE_RECALL_ON_OPEN;
    /// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`.
    pub const RECALL_ON_DATA_ACCESS: u32 = crate::hash::FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

    const fn has(self, bit: u32) -> bool {
        self.0 & bit != 0
    }

    /// Read-only.
    #[must_use]
    pub const fn readonly(self) -> bool {
        self.has(Self::READONLY)
    }
    /// Hidden.
    #[must_use]
    pub const fn hidden(self) -> bool {
        self.has(Self::HIDDEN)
    }
    /// System.
    #[must_use]
    pub const fn system(self) -> bool {
        self.has(Self::SYSTEM)
    }
    /// A directory.
    #[must_use]
    pub const fn directory(self) -> bool {
        self.has(Self::DIRECTORY)
    }
    /// Sparse.
    #[must_use]
    pub const fn sparse(self) -> bool {
        self.has(Self::SPARSE)
    }
    /// Has a reparse point.
    #[must_use]
    pub const fn reparse_point(self) -> bool {
        self.has(Self::REPARSE_POINT)
    }
    /// Compressed by the file system.
    #[must_use]
    pub const fn compressed(self) -> bool {
        self.has(Self::COMPRESSED)
    }
    /// Offline: the data is not stored locally.
    #[must_use]
    pub const fn offline(self) -> bool {
        self.has(Self::OFFLINE)
    }
    /// Encrypted by the file system.
    #[must_use]
    pub const fn encrypted(self) -> bool {
        self.has(Self::ENCRYPTED)
    }
    /// Opening the file fetches it from elsewhere.
    #[must_use]
    pub const fn recall_on_open(self) -> bool {
        self.has(Self::RECALL_ON_OPEN)
    }
    /// Reading the file's data fetches it from elsewhere.
    #[must_use]
    pub const fn recall_on_data_access(self) -> bool {
        self.has(Self::RECALL_ON_DATA_ACCESS)
    }
    /// A cloud placeholder: offline, or recalled on open or on data access.
    #[must_use]
    pub const fn is_placeholder(self) -> bool {
        self.offline() || self.recall_on_open() || self.recall_on_data_access()
    }
}

/// A file's IDs, timestamps and attributes: "timestamps and IDs" in #54.
/// The timestamps and attributes are always read with the handle; the IDs
/// are `None` where the file system does not report them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileMeta {
    /// The 64-bit volume serial number (`FILE_ID_INFO`).
    pub volume_serial: Option<u64>,
    /// The 128-bit file ID. `None` if the file system reports none (an
    /// all-zero ID).
    pub file_id: Option<[u8; 16]>,
    /// The change journal's ID and the file's last USN, on a local volume
    /// with an active journal.
    pub usn: Option<(u64, i64)>,
    /// The creation time.
    pub creation: FileTime,
    /// The last write time.
    pub last_write: FileTime,
    /// The last change time (content, attributes or security).
    pub change: FileTime,
    /// The last access time.
    pub last_access: FileTime,
    /// The attributes.
    pub attributes: FileAttributes,
}

/// The most names [`HardLinks`] lists, as #54 asks.
pub const MAX_HARD_LINK_NAMES: usize = 16;

/// The names of one file (hard links).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HardLinks {
    /// How many names the file has (`FILE_STANDARD_INFO.NumberOfLinks`).
    pub count: u32,
    /// Up to [`MAX_HARD_LINK_NAMES`] of them, each relative to its volume
    /// root (`\dir\file.exe`), in the order the OS lists them. Empty when
    /// the file has one name.
    pub names: Vec<String>,
    /// Not every name is in `names`: there are more than the cap, or
    /// listing them failed part way or not at all.
    pub truncated: bool,
}

impl HardLinks {
    /// The links of a file with `count` names, of which `names` were
    /// listed. Keeps at most [`MAX_HARD_LINK_NAMES`]. `complete` says the
    /// listing ran to its end; even then the list is marked truncated if it
    /// holds fewer names than `count`, since the count is the file
    /// system's own.
    #[must_use]
    pub fn new(count: u32, mut names: Vec<String>, complete: bool) -> Self {
        let cut = names.len() > MAX_HARD_LINK_NAMES;
        names.truncate(MAX_HARD_LINK_NAMES);
        let listed = u32::try_from(names.len()).unwrap_or(u32::MAX);
        Self {
            count,
            truncated: count > 1 && (cut || !complete || listed < count),
            names,
        }
    }

    /// True if the file has more than one name, so writing through one
    /// changes what the others name.
    #[must_use]
    pub const fn has_other_names(&self) -> bool {
        self.count > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_bits() {
        let a = FileAttributes(0x0000_0007);
        assert!(a.readonly() && a.hidden() && a.system());
        assert!(!a.sparse() && !a.encrypted() && !a.compressed() && !a.is_placeholder());
        let b = FileAttributes(0x0000_0200 | 0x0000_0800 | 0x0000_4000 | 0x0000_0400 | 0x10);
        assert!(b.sparse() && b.compressed() && b.encrypted() && b.reparse_point());
        assert!(b.directory());
        for bit in [
            FileAttributes::OFFLINE,
            FileAttributes::RECALL_ON_OPEN,
            FileAttributes::RECALL_ON_DATA_ACCESS,
        ] {
            assert!(FileAttributes(bit).is_placeholder(), "{bit:#x}");
        }
        assert!(FileAttributes(FileAttributes::RECALL_ON_OPEN).recall_on_open());
        assert!(FileAttributes(FileAttributes::RECALL_ON_DATA_ACCESS).recall_on_data_access());
        assert!(FileAttributes(FileAttributes::OFFLINE).offline());
    }

    #[test]
    fn hard_links_are_capped() {
        let names = |n: usize| (0..n).map(|i| format!(r"\d\{i}.exe")).collect::<Vec<_>>();
        let one = HardLinks::new(1, Vec::new(), true);
        assert!(!one.truncated && !one.has_other_names());
        let all = HardLinks::new(3, names(3), true);
        assert!(!all.truncated && all.has_other_names());
        assert_eq!(all.names.len(), 3);
        // Exactly the cap is complete.
        let cap = HardLinks::new(16, names(16), true);
        assert!(!cap.truncated);
        // More names than the cap, or fewer listed than the count.
        let many = HardLinks::new(30, names(30), true);
        assert_eq!(many.names.len(), MAX_HARD_LINK_NAMES);
        assert!(many.truncated);
        assert!(HardLinks::new(30, names(16), true).truncated);
        assert!(HardLinks::new(3, names(2), true).truncated);
        // A listing that stopped early, or never ran.
        assert!(HardLinks::new(3, names(3), false).truncated);
        assert!(HardLinks::new(2, Vec::new(), false).truncated);
    }
}
