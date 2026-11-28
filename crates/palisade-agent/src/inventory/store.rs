//! Where the inventory keeps its entries and its per-volume cursors.
//!
//! ADR 0007 leaves the embedded store (`redb` or SQLite) to a spike, and
//! says #60 starts against a storage trait so the backend can be swapped.
//! [`InventoryStore`] is that trait; [`MemoryStore`] is the in-memory
//! implementation the agent uses until the spike decides the backend. The
//! inventory can be rebuilt from a scan, so losing it costs time, never a
//! wrong decision.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use palisade_core::platform::UtcTime;

use super::entry::{EntryKey, EntryState, InvEntry};

/// Where a volume's change tracking has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalCursor {
    /// The journal's ID.
    pub journal_id: u64,
    /// The next USN to read.
    pub next_usn: i64,
}

/// Where an interrupted initial scan of a volume resumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScanCheckpoint {
    /// The file reference to continue the enumeration from.
    pub next_reference: u64,
    /// The journal cursor taken when the scan started: changes from there
    /// on are read from the journal once the scan ends.
    pub start: JournalCursor,
    /// Files listed so far.
    pub files_seen: u64,
}

/// A failed store operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

/// The inventory's storage.
pub trait InventoryStore: Send {
    /// The entry for `key`.
    fn get(&self, key: &EntryKey) -> Result<Option<InvEntry>, StoreError>;
    /// Inserts or replaces an entry.
    fn put(&mut self, entry: InvEntry) -> Result<(), StoreError>;
    /// Removes an entry for good.
    fn remove(&mut self, key: &EntryKey) -> Result<(), StoreError>;
    /// The keys of every entry on the volume `volume_serial`.
    fn keys_on(&self, volume_serial: u64) -> Result<Vec<EntryKey>, StoreError>;
    /// The number of entries.
    fn len(&self) -> Result<usize, StoreError>;
    /// Whether there are no entries.
    fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    /// The saved journal cursor of the volume `volume_serial`.
    fn cursor(&self, volume_serial: u64) -> Result<Option<JournalCursor>, StoreError>;
    /// Saves the journal cursor of the volume `volume_serial`. Saved only
    /// after every record before it has been applied.
    fn set_cursor(&mut self, volume_serial: u64, cursor: JournalCursor) -> Result<(), StoreError>;
    /// Forgets a volume's cursor, so it is reconciled next time.
    fn clear_cursor(&mut self, volume_serial: u64) -> Result<(), StoreError>;

    /// The checkpoint of an initial scan in progress on the volume.
    fn checkpoint(&self, volume_serial: u64) -> Result<Option<ScanCheckpoint>, StoreError>;
    /// Saves, or with `None` clears, the scan checkpoint.
    fn set_checkpoint(
        &mut self,
        volume_serial: u64,
        checkpoint: Option<ScanCheckpoint>,
    ) -> Result<(), StoreError>;

    /// Removes deleted entries whose `deleted_at` is before `before`.
    /// Returns how many went.
    fn purge_deleted(&mut self, before: UtcTime) -> Result<usize, StoreError>;
}

/// The in-memory store.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: BTreeMap<EntryKey, InvEntry>,
    cursors: BTreeMap<u64, JournalCursor>,
    checkpoints: BTreeMap<u64, ScanCheckpoint>,
}

impl InventoryStore for MemoryStore {
    fn get(&self, key: &EntryKey) -> Result<Option<InvEntry>, StoreError> {
        Ok(self.entries.get(key).cloned())
    }

    fn put(&mut self, entry: InvEntry) -> Result<(), StoreError> {
        self.entries.insert(entry.key, entry);
        Ok(())
    }

    fn remove(&mut self, key: &EntryKey) -> Result<(), StoreError> {
        self.entries.remove(key);
        Ok(())
    }

    fn keys_on(&self, volume_serial: u64) -> Result<Vec<EntryKey>, StoreError> {
        let from = EntryKey {
            volume_serial,
            file_id: [0; 16],
        };
        Ok(self
            .entries
            .range(from..)
            .map(|(k, _)| *k)
            .take_while(|k| k.volume_serial == volume_serial)
            .collect())
    }

    fn len(&self) -> Result<usize, StoreError> {
        Ok(self.entries.len())
    }

    fn cursor(&self, volume_serial: u64) -> Result<Option<JournalCursor>, StoreError> {
        Ok(self.cursors.get(&volume_serial).copied())
    }

    fn set_cursor(&mut self, volume_serial: u64, cursor: JournalCursor) -> Result<(), StoreError> {
        self.cursors.insert(volume_serial, cursor);
        Ok(())
    }

    fn clear_cursor(&mut self, volume_serial: u64) -> Result<(), StoreError> {
        self.cursors.remove(&volume_serial);
        Ok(())
    }

    fn checkpoint(&self, volume_serial: u64) -> Result<Option<ScanCheckpoint>, StoreError> {
        Ok(self.checkpoints.get(&volume_serial).copied())
    }

    fn set_checkpoint(
        &mut self,
        volume_serial: u64,
        checkpoint: Option<ScanCheckpoint>,
    ) -> Result<(), StoreError> {
        match checkpoint {
            Some(c) => self.checkpoints.insert(volume_serial, c),
            None => self.checkpoints.remove(&volume_serial),
        };
        Ok(())
    }

    fn purge_deleted(&mut self, before: UtcTime) -> Result<usize, StoreError> {
        let n = self.entries.len();
        self.entries.retain(|_, e| {
            !(e.state == EntryState::Deleted && e.deleted_at.is_some_and(|d| d < before))
        });
        Ok(n - self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::entry::Discovery;

    fn key(volume_serial: u64, n: u8) -> EntryKey {
        EntryKey {
            volume_serial,
            file_id: [n; 16],
        }
    }

    #[test]
    fn entries_cursors_and_checkpoints() {
        let mut s = MemoryStore::default();
        assert!(s.is_empty().unwrap());
        for (v, n) in [(1, 1), (1, 2), (2, 1), (3, 0)] {
            s.put(InvEntry::new(
                key(v, n),
                "p".into(),
                UtcTime(0),
                Discovery::Change,
            ))
            .unwrap();
        }
        assert_eq!(s.len().unwrap(), 4);
        assert_eq!(s.keys_on(1).unwrap(), [key(1, 1), key(1, 2)]);
        assert_eq!(s.keys_on(3).unwrap(), [key(3, 0)]);
        assert!(s.keys_on(9).unwrap().is_empty());
        s.remove(&key(1, 1)).unwrap();
        assert_eq!(s.get(&key(1, 1)).unwrap(), None);

        let c = JournalCursor {
            journal_id: 5,
            next_usn: 10,
        };
        s.set_cursor(1, c).unwrap();
        assert_eq!(s.cursor(1).unwrap(), Some(c));
        s.clear_cursor(1).unwrap();
        assert_eq!(s.cursor(1).unwrap(), None);

        let cp = ScanCheckpoint {
            next_reference: 7,
            start: c,
            files_seen: 3,
        };
        s.set_checkpoint(2, Some(cp)).unwrap();
        assert_eq!(s.checkpoint(2).unwrap(), Some(cp));
        s.set_checkpoint(2, None).unwrap();
        assert_eq!(s.checkpoint(2).unwrap(), None);
    }

    #[test]
    fn purge_removes_only_old_deleted_entries() {
        let mut s = MemoryStore::default();
        let mut old = InvEntry::new(key(1, 1), "a".into(), UtcTime(0), Discovery::Change);
        old.state = EntryState::Deleted;
        old.deleted_at = Some(UtcTime(10));
        let mut recent = old.clone();
        recent.key = key(1, 2);
        recent.deleted_at = Some(UtcTime(100));
        let mut odd = old.clone();
        odd.key = key(1, 3);
        odd.deleted_at = None;
        let present = InvEntry::new(key(1, 4), "d".into(), UtcTime(0), Discovery::Change);
        for e in [old, recent, odd, present] {
            s.put(e).unwrap();
        }
        assert_eq!(s.purge_deleted(UtcTime(50)).unwrap(), 1);
        assert_eq!(s.keys_on(1).unwrap(), [key(1, 2), key(1, 3), key(1, 4)]);
    }
}
