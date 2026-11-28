//! The file inventory (#60): every executable-content file on the
//! endpoint's volumes, with its identity, first-seen, last-modified and
//! last-executed times, kept current from the change journal.
//!
//! - [`entry`]: the inventory record ([`entry::InvEntry`]) and its
//!   identity summary.
//! - [`scope`]: what the inventory covers, and the phase-1 prefilter by
//!   name.
//! - [`store`]: the storage trait (ADR 0007 leaves the backend to a spike)
//!   and an in-memory store.
//! - [`track`]: changes coalesced per file, applied to the entries, and
//!   what each needs next (identify, reassess the location).
//! - [`engine`]: the initial scan with checkpoints and a throttling seam
//!   (#65), journal polling, and reconciliation when the journal cursor is
//!   lost.
//! - [`subsystem`]: the `inventory` subsystem, over the volumes a
//!   [`subsystem::VolumeProvider`] gives: on Windows every fixed NTFS or
//!   ReFS volume, read by file ID through `palisade_fileid::win::journal`.
//!
//! [`changes_from_journal`] turns change-journal records
//! (`palisade_fileid::fsctx::ntfs`, read by `palisade_fileid::win::journal`
//! on Windows) into [`track::Change`]s.

#![forbid(unsafe_code)]

pub mod engine;
pub mod entry;
pub mod scope;
pub mod store;
pub mod subsystem;
pub mod track;
#[cfg(windows)]
mod windows;

use palisade_fileid::fsctx::ntfs::{JournalRecord, reason};

use entry::EntryKey;
use track::{Change, ChangeFlags};

/// The change one journal record reports, on the volume `volume_serial`.
/// The path is left for the caller to resolve from the parent reference,
/// and is `None` here. A rename's old-name record is not a change of its
/// own: the new-name record that follows carries it. Returns `None` for
/// records with nothing the inventory tracks.
#[must_use]
pub fn changes_from_journal(volume_serial: u64, record: &JournalRecord) -> Option<Change> {
    let mapping = [
        (reason::FILE_CREATE, ChangeFlags::CREATED),
        (reason::CONTENT, ChangeFlags::CONTENT),
        (reason::RENAME_NEW_NAME, ChangeFlags::RENAMED),
        (reason::FILE_DELETE, ChangeFlags::DELETED),
        (reason::SECURITY_CHANGE, ChangeFlags::SECURITY),
        (
            reason::BASIC_INFO_CHANGE
                | reason::COMPRESSION_CHANGE
                | reason::ENCRYPTION_CHANGE
                | reason::OBJECT_ID_CHANGE
                | reason::INDEXABLE_CHANGE
                | reason::INTEGRITY_CHANGE,
            ChangeFlags::BASIC_INFO,
        ),
        (reason::CLOSE, ChangeFlags::CLOSED),
    ];
    let flags = mapping
        .iter()
        .filter(|(mask, _)| record.has_any(*mask))
        .fold(ChangeFlags::NONE, |acc, (_, f)| acc | *f);
    if flags == ChangeFlags::NONE {
        return None;
    }
    Some(Change {
        key: EntryKey {
            volume_serial,
            file_id: record.file_reference,
        },
        flags,
        directory: record.is_directory(),
        path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(reason: u32, attributes: u32) -> JournalRecord {
        JournalRecord {
            major_version: 3,
            file_reference: [4; 16],
            parent_reference: [5; 16],
            usn: 1,
            timestamp: 0,
            reason,
            source_info: 0,
            security_id: 0,
            attributes,
            name: "a.exe".into(),
            name_lossy: false,
        }
    }

    #[test]
    fn journal_reasons_map_to_changes() {
        let c = changes_from_journal(9, &record(reason::FILE_CREATE | reason::DATA_EXTEND, 0x20))
            .unwrap();
        assert_eq!(
            c.key,
            EntryKey {
                volume_serial: 9,
                file_id: [4; 16]
            }
        );
        assert!(
            c.flags
                .contains(ChangeFlags::CREATED | ChangeFlags::CONTENT)
        );
        assert!(!c.directory && c.path.is_none());
        for (r, f) in [
            (reason::DATA_OVERWRITE, ChangeFlags::CONTENT),
            (reason::STREAM_CHANGE, ChangeFlags::CONTENT),
            (reason::HARD_LINK_CHANGE, ChangeFlags::CONTENT),
            (reason::REPARSE_POINT_CHANGE, ChangeFlags::CONTENT),
            (reason::RENAME_NEW_NAME, ChangeFlags::RENAMED),
            (reason::FILE_DELETE, ChangeFlags::DELETED),
            (reason::SECURITY_CHANGE, ChangeFlags::SECURITY),
            (reason::BASIC_INFO_CHANGE, ChangeFlags::BASIC_INFO),
            (reason::ENCRYPTION_CHANGE, ChangeFlags::BASIC_INFO),
            (reason::CLOSE, ChangeFlags::CLOSED),
        ] {
            assert_eq!(
                changes_from_journal(1, &record(r, 0)).unwrap().flags,
                f,
                "{r:#x}"
            );
        }
        assert!(
            changes_from_journal(1, &record(reason::SECURITY_CHANGE, 0x10))
                .unwrap()
                .directory
        );
        // The old name of a rename, alone, is not a change.
        assert_eq!(
            changes_from_journal(1, &record(reason::RENAME_OLD_NAME, 0)),
            None
        );
        assert_eq!(changes_from_journal(1, &record(0, 0)), None);
    }
}
