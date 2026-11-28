//! A volume's change journal and master file table, for the file inventory
//! (#60): the journal state, reading records from a saved cursor,
//! enumerating every file for an initial scan, and opening a file by its
//! ID.
//!
//! The OS calls are in `sys`; the records are parsed by the portable
//! [`crate::fsctx::ntfs`] parsers. Reading the journal and enumerating the
//! master file table need a handle to the volume device with read access,
//! which needs administrator rights: the agent runs as `SYSTEM`.
//!
//! Opening by ID never follows a reparse point, and the inventory reads
//! a file through that handle, so a link planted where the file was cannot
//! redirect the read (threat model T-agent-13).

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;

use super::file::volume_root;
use super::sys;
use crate::fsctx::ntfs::{
    JournalData, JournalRecord, parse_enum_usn_data, parse_journal_data, parse_read_journal,
};

/// `GENERIC_READ`.
const GENERIC_READ: u32 = 0x8000_0000;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
/// `READ_CONTROL`.
const READ_CONTROL: u32 = 0x0002_0000;
/// `FILE_FLAG_BACKUP_SEMANTICS`, needed to open a folder.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_SEQUENTIAL_SCAN`.
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
/// `FILE_FLAG_OPEN_NO_RECALL`: opening a cloud placeholder does not
/// download it.
const FILE_FLAG_OPEN_NO_RECALL: u32 = 0x0010_0000;

/// One volume, opened for its change journal.
#[derive(Debug)]
pub struct JournalVolume {
    device: File,
    root: String,
}

impl JournalVolume {
    /// Opens the volume `root`, a volume GUID path (`\\?\Volume{GUID}`,
    /// no trailing separator), with read access. Needs administrator
    /// rights.
    pub fn open(root: &str) -> io::Result<Self> {
        if !root.starts_with(r"\\?\Volume{") || root.ends_with('\\') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a volume GUID path without a trailing separator",
            ));
        }
        let device = OpenOptions::new()
            .access_mode(GENERIC_READ)
            .share_mode(0x7)
            .open(root)?;
        Ok(Self {
            device,
            root: root.to_owned(),
        })
    }

    /// Opens the volume the open `file` is on, found from the handle's own
    /// final path (never a drive letter, which could name another volume).
    pub fn of_file(file: &File) -> io::Result<Self> {
        Self::open(&volume_root(file)?)
    }

    /// The volume GUID path.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// The journal's state. Fails if the volume has no active journal
    /// (`ERROR_JOURNAL_NOT_ACTIVE`), or it is being deleted.
    pub fn query(&self) -> io::Result<JournalData> {
        let bytes = sys::usn_journal_bytes(&self.device)?;
        parse_journal_data(&bytes).map_err(invalid)
    }

    /// Reads the records from `start_usn` of journal `journal_id`, at most
    /// one batch, without waiting. Returns the USN to continue from and
    /// the records, which may be empty when nothing new was written.
    ///
    /// A journal that was deleted or replaced fails with
    /// `ERROR_JOURNAL_DELETE_IN_PROGRESS` or `ERROR_JOURNAL_NOT_ACTIVE`, and
    /// a cursor below the oldest readable USN with
    /// `ERROR_JOURNAL_ENTRY_DELETED`: check
    /// [`JournalData::can_resume`] first, and reconcile otherwise.
    pub fn read(&self, journal_id: u64, start_usn: i64) -> io::Result<(i64, Vec<JournalRecord>)> {
        let bytes = sys::read_usn_journal_bytes(&self.device, journal_id, start_usn, u32::MAX)?;
        parse_read_journal(&bytes).map_err(invalid)
    }

    /// One batch of the master file table's files and folders, from the
    /// file reference `start` (0 for the first), with USNs up to
    /// `high_usn` (the journal's `next_usn` when the scan started).
    /// Returns the reference to continue from and the records, or `None`
    /// once every file has been listed.
    pub fn enumerate(
        &self,
        start: u64,
        high_usn: i64,
    ) -> io::Result<Option<(u64, Vec<JournalRecord>)>> {
        let bytes = sys::enum_usn_data_bytes(&self.device, start, high_usn)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let (next, records) = parse_enum_usn_data(&bytes).map_err(invalid)?;
        if records.is_empty() && next <= start {
            // A batch that neither lists a file nor moves the cursor would
            // loop for ever.
            return Err(invalid("the enumeration did not advance"));
        }
        Ok(Some((next, records)))
    }

    /// Opens the file with ID `file_id` on this volume to read its content
    /// and security descriptor, without following a reparse point and
    /// without recalling a cloud placeholder.
    pub fn open_file_by_id(&self, file_id: [u8; 16]) -> io::Result<File> {
        sys::open_by_id(
            &self.device,
            file_id,
            GENERIC_READ,
            FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_NO_RECALL,
        )
    }

    /// Opens the file or folder with ID `file_id` on this volume to read its
    /// attributes, security descriptor and final path only.
    pub fn open_entry_by_id(&self, file_id: [u8; 16]) -> io::Result<File> {
        sys::open_by_id(
            &self.device,
            file_id,
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    }
}

fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_volume_guid_roots_open() {
        for bad in [r"C:\", r"C:", r"\\?\Volume{x}\", r"\\server\share"] {
            assert_eq!(
                JournalVolume::open(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad}"
            );
        }
    }
}
