//! The inventory engine: the initial scan, reconciliation and change
//! tracking of one volume, over a [`VolumeSource`] and an [`Identifier`].
//!
//! The source is the OS: on Windows the master file table and the change
//! journal (`palisade_fileid::win::journal`); in tests, a scripted volume.
//! The engine itself is portable, so every path through it is tested on any
//! OS.
//!
//! - [`Engine::scan`] lists every file of a volume in batches, keeps the
//!   candidates ([`super::scope::InventoryScope::candidate`]), and records
//!   them. It saves a [`ScanCheckpoint`] every [`CHECKPOINT_FILES`] files
//!   or [`CHECKPOINT_INTERVAL`], so a restart resumes instead of starting
//!   again, and asks the [`Throttle`] before every batch: the resource
//!   budgets (#65) plug in there.
//! - [`Engine::poll`] reads the journal from the saved cursor and applies
//!   the changes ([`super::track`]). If the journal was replaced, or
//!   wrapped past the cursor, it reconciles the volume instead (a scan
//!   with [`Discovery::Rescan`] that marks files no longer listed as
//!   deleted) and reports that it did.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::time::Duration;

use palisade_core::platform::{MonotonicTime, UtcTime};
use palisade_fileid::fsctx::ntfs::JournalData;

use super::entry::{Discovery, EntryKey, EntryState, IdentitySummary, InvEntry};
use super::scope::InventoryScope;
use super::store::{InventoryStore, JournalCursor, ScanCheckpoint, StoreError};
use super::track::{self, Action, Change, Coalescer, DeltaKind};

/// A checkpoint is saved at least every this many files.
pub const CHECKPOINT_FILES: u64 = 10_000;
/// A checkpoint is saved at least this often.
pub const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);

/// One file or folder a volume listing returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// Its 128-bit ID.
    pub file_id: [u8; 16],
    /// Its full path, if the source could resolve it.
    pub path: Option<String>,
    /// Whether it is a folder.
    pub directory: bool,
}

/// A failed read of the volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// The saved cursor can no longer be read: the journal was deleted,
    /// replaced or wrapped. The volume must be reconciled.
    CursorLost,
    /// Any other failure, with its reason.
    Other(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CursorLost => f.write_str("the change journal cursor is no longer readable"),
            Self::Other(m) => f.write_str(m),
        }
    }
}

/// One volume, as the engine reads it.
pub trait VolumeSource {
    /// The volume's serial number.
    fn serial(&self) -> u64;
    /// The journal's state, or `None` if the volume keeps no journal (FAT,
    /// exFAT, network): it is then rescanned on a schedule instead.
    fn journal(&mut self) -> Result<Option<JournalData>, SourceError>;
    /// One batch of the volume's files from `start` (0 for the first), or
    /// `None` when every file has been listed. The cursor returned must be
    /// passed back to continue.
    fn list(
        &mut self,
        start: u64,
        high_usn: i64,
    ) -> Result<Option<(u64, Vec<Listed>)>, SourceError>;
    /// Changes from `cursor`, and the cursor to continue from.
    fn changes(&mut self, cursor: JournalCursor) -> Result<(i64, Vec<Change>), SourceError>;
    /// The full path of the file with `file_id`, from its ID, never a
    /// path a user could have swapped. `None` if it is gone.
    fn resolve(&mut self, file_id: [u8; 16]) -> Option<String>;
}

/// What identifying a file found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identified {
    /// The file's identity, and whether its location is user-writable
    /// (`None` if that could not be assessed).
    Known {
        /// Its identity summary.
        summary: Box<IdentitySummary>,
        /// Its location's writability.
        user_writable: Option<bool>,
    },
    /// It was not read, on purpose (a cloud placeholder, or a deferral).
    Deferred,
    /// It could not be read.
    Unreadable(String),
    /// It is gone.
    Gone,
}

/// Computes identities, through `palisade_fileid` (#55), opening each file
/// by its ID. Called off the async workers.
pub trait Identifier {
    /// Identifies the file with `key`: its content kind, hashes and trust,
    /// and its location's writability.
    fn identify(&mut self, key: EntryKey) -> Identified;
}

/// The seam for the resource budgets (#65).
pub trait Throttle {
    /// Waits, if needed, before the next batch of about `files` files.
    /// Returns `false` to stop the work for now (a stop was requested, or
    /// the budget says not now); the checkpoint lets it resume.
    fn admit(&mut self, files: usize) -> bool;
}

/// A throttle that admits everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct Unthrottled;

impl Throttle for Unthrottled {
    fn admit(&mut self, _files: usize) -> bool {
        true
    }
}

/// What a scan did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Files listed (candidates or not).
    pub listed: u64,
    /// Entries added.
    pub added: u64,
    /// Entries marked deleted, by a reconciliation.
    pub deleted: u64,
    /// The scan finished; `false` if the throttle stopped it.
    pub complete: bool,
    /// Changes to report (#62).
    pub deltas: Vec<(EntryKey, DeltaKind)>,
}

/// What one poll did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// Changes were read and applied.
    Applied {
        /// Changes to report (#62).
        deltas: Vec<(EntryKey, DeltaKind)>,
    },
    /// The volume keeps no journal: rescan it on the periodic schedule.
    NoJournal,
    /// The cursor was lost, so the volume was reconciled.
    Reconciled(ScanReport),
    /// The volume has never been scanned, or its scan was interrupted:
    /// scan it first.
    NeedsScan,
}

/// The inventory of one volume.
#[derive(Debug)]
pub struct Engine {
    /// The scope.
    pub scope: InventoryScope,
    /// Coalesces changes between polls.
    pub coalescer: Coalescer,
}

impl Engine {
    /// An engine with this scope.
    #[must_use]
    pub fn new(scope: &InventoryScope) -> Self {
        Self {
            scope: scope.clone(),
            coalescer: Coalescer::default(),
        }
    }

    /// Scans `source` into `store`, resuming from a saved checkpoint.
    /// `discovery` is [`Discovery::InitialScan`] for the first scan and
    /// [`Discovery::Rescan`] for a reconciliation, which also marks entries
    /// no longer listed as deleted.
    #[allow(clippy::too_many_arguments)]
    pub fn scan(
        &mut self,
        source: &mut dyn VolumeSource,
        store: &mut dyn InventoryStore,
        identifier: &mut dyn Identifier,
        throttle: &mut dyn Throttle,
        clock: &dyn Fn() -> (UtcTime, MonotonicTime),
        discovery: Discovery,
    ) -> Result<ScanReport, ScanError> {
        let serial = source.serial();
        let (now, mut last_save) = clock();
        let mut checkpoint = match store.checkpoint(serial)? {
            Some(c) => c,
            None => {
                let start = match source.journal()? {
                    Some(j) => JournalCursor {
                        journal_id: j.journal_id,
                        next_usn: j.next_usn,
                    },
                    None => JournalCursor {
                        journal_id: 0,
                        next_usn: i64::MAX,
                    },
                };
                let c = ScanCheckpoint {
                    next_reference: 0,
                    start,
                    files_seen: 0,
                };
                store.set_checkpoint(serial, Some(c))?;
                c
            }
        };
        let mut report = ScanReport::default();
        let mut saved_at_files = checkpoint.files_seen;
        // A reconciliation that resumes has lost the set of IDs listed
        // before the restart, so it never marks deletions from a partial
        // view: it rescans from the start instead.
        let mut seen = BTreeSet::new();
        if discovery == Discovery::Rescan && checkpoint.next_reference != 0 {
            checkpoint.next_reference = 0;
            checkpoint.files_seen = 0;
        }
        loop {
            if !throttle.admit(1024) {
                store.set_checkpoint(serial, Some(checkpoint))?;
                return Ok(report);
            }
            let Some((next, batch)) =
                source.list(checkpoint.next_reference, checkpoint.start.next_usn)?
            else {
                break;
            };
            for item in batch {
                report.listed += 1;
                checkpoint.files_seen += 1;
                let key = EntryKey {
                    volume_serial: serial,
                    file_id: item.file_id,
                };
                if item.directory {
                    continue;
                }
                seen.insert(key);
                self.record_listed(store, identifier, key, item, now, discovery, &mut report)?;
            }
            checkpoint.next_reference = next;
            let (_, mono) = clock();
            let elapsed = mono.0.saturating_sub(last_save.0);
            if checkpoint.files_seen - saved_at_files >= CHECKPOINT_FILES
                || elapsed >= u64::try_from(CHECKPOINT_INTERVAL.as_micros()).unwrap_or(u64::MAX)
            {
                store.set_checkpoint(serial, Some(checkpoint))?;
                saved_at_files = checkpoint.files_seen;
                last_save = mono;
            }
        }
        if discovery == Discovery::Rescan {
            for key in store.keys_on(serial)? {
                if seen.contains(&key) {
                    continue;
                }
                if let Some(mut e) = store.get(&key)?
                    && e.state != EntryState::Deleted
                {
                    e.state = EntryState::Deleted;
                    e.deleted_at = Some(now);
                    e.stale = true;
                    store.put(e)?;
                    report.deleted += 1;
                    report.deltas.push((key, DeltaKind::Deleted));
                }
            }
        }
        // The scan is complete: changes since it started come from the
        // journal.
        if checkpoint.start.journal_id != 0 || checkpoint.start.next_usn != i64::MAX {
            store.set_cursor(serial, checkpoint.start)?;
        } else {
            store.clear_cursor(serial)?;
        }
        store.set_checkpoint(serial, None)?;
        report.complete = true;
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_listed(
        &self,
        store: &mut dyn InventoryStore,
        identifier: &mut dyn Identifier,
        key: EntryKey,
        item: Listed,
        now: UtcTime,
        discovery: Discovery,
        report: &mut ScanReport,
    ) -> Result<(), StoreError> {
        let Some(path) = item.path else {
            return Ok(());
        };
        if self.scope.excludes(&path) {
            return Ok(());
        }
        let existing = store.get(&key)?;
        let user_writable = existing
            .as_ref()
            .is_none_or(InvEntry::in_user_writable_location);
        let name = path.rsplit('\\').next().unwrap_or(&path);
        if self.scope.candidate(name, user_writable).is_none() {
            return Ok(());
        }
        match existing {
            Some(mut e) => {
                // Known: keep its identity unless it moved or was deleted.
                let moved = e.move_to(path);
                if e.state == EntryState::Deleted {
                    e.state = EntryState::Present;
                    e.deleted_at = None;
                    e.stale = true;
                }
                if moved {
                    e.user_writable_location = None;
                    report.deltas.push((key, DeltaKind::Renamed));
                }
                store.put(e)
            }
            None => {
                let mut e = InvEntry::new(key, path, now, discovery);
                identify_into(&mut e, identifier);
                // Phase 1: a file whose content cannot run code is not kept.
                if e.identity
                    .as_ref()
                    .is_some_and(|i| i.executable_content == Some(false))
                {
                    return Ok(());
                }
                store.put(e)?;
                report.added += 1;
                report.deltas.push((key, DeltaKind::Added));
                Ok(())
            }
        }
    }

    /// Reads and applies the changes since the saved cursor.
    #[allow(clippy::too_many_arguments)]
    pub fn poll(
        &mut self,
        source: &mut dyn VolumeSource,
        store: &mut dyn InventoryStore,
        identifier: &mut dyn Identifier,
        throttle: &mut dyn Throttle,
        clock: &dyn Fn() -> (UtcTime, MonotonicTime),
    ) -> Result<PollOutcome, ScanError> {
        let serial = source.serial();
        if store.checkpoint(serial)?.is_some() {
            return Ok(PollOutcome::NeedsScan);
        }
        let Some(cursor) = store.cursor(serial)? else {
            return Ok(match source.journal()? {
                Some(_) if store.keys_on(serial)?.is_empty() => PollOutcome::NeedsScan,
                Some(_) => self.reconcile(source, store, identifier, throttle, clock)?,
                None => PollOutcome::NoJournal,
            });
        };
        let journal = source.journal()?;
        let resumable = journal.is_some_and(|j| j.can_resume(cursor.journal_id, cursor.next_usn));
        if !resumable {
            return self.reconcile(source, store, identifier, throttle, clock);
        }
        let (next, changes) = match source.changes(cursor) {
            Ok(c) => c,
            Err(SourceError::CursorLost) => {
                return self.reconcile(source, store, identifier, throttle, clock);
            }
            Err(e) => return Err(e.into()),
        };
        let (now, mono) = clock();
        for change in changes {
            let key = change.key;
            let invalidation = self.coalescer.push(change, mono);
            track::invalidate(store, &key, invalidation)?;
        }
        // The cursor moves only once every change it covers is held or
        // applied: the invalidations above are already in the store.
        store.set_cursor(
            serial,
            JournalCursor {
                journal_id: cursor.journal_id,
                next_usn: next,
            },
        )?;
        let mut deltas = Vec::new();
        for mut c in self.coalescer.ready(mono) {
            if c.path.is_none() && !c.flags.contains(track::ChangeFlags::DELETED) {
                c.path = source.resolve(c.key.file_id);
            }
            let applied = track::apply(store, &c, now)?;
            if let Some(d) = applied.delta {
                deltas.push((c.key, d));
            }
            self.follow_up(source, store, identifier, &c, applied.action)?;
        }
        Ok(PollOutcome::Applied { deltas })
    }

    fn follow_up(
        &self,
        source: &mut dyn VolumeSource,
        store: &mut dyn InventoryStore,
        identifier: &mut dyn Identifier,
        change: &track::Coalesced,
        action: Action,
    ) -> Result<(), StoreError> {
        match action {
            Action::Identify | Action::ReassessLocation => {
                if let Some(mut e) = store.get(&change.key)? {
                    identify_into(&mut e, identifier);
                    store.put(e)?;
                }
            }
            Action::Directory => {
                if let Some(folder) = source.resolve(change.key.file_id) {
                    track::invalidate_under(store, change.key.volume_serial, &folder)?;
                }
            }
            Action::ResolvePath | Action::None => {}
        }
        Ok(())
    }

    fn reconcile(
        &mut self,
        source: &mut dyn VolumeSource,
        store: &mut dyn InventoryStore,
        identifier: &mut dyn Identifier,
        throttle: &mut dyn Throttle,
        clock: &dyn Fn() -> (UtcTime, MonotonicTime),
    ) -> Result<PollOutcome, ScanError> {
        let serial = source.serial();
        tracing::warn!(
            volume = serial,
            "change journal cursor lost; reconciling the volume"
        );
        // Held changes are applied first, so none is lost.
        let (now, _) = clock();
        for c in self.coalescer.drain() {
            let applied = track::apply(store, &c, now)?;
            self.follow_up(source, store, identifier, &c, applied.action)?;
        }
        store.clear_cursor(serial)?;
        let report = self.scan(
            source,
            store,
            identifier,
            throttle,
            clock,
            Discovery::Rescan,
        )?;
        // A reconciliation re-reads known files whose stamps may have
        // changed while the journal was not read.
        for key in store.keys_on(serial)? {
            if let Some(mut e) = store.get(&key)?
                && e.state == EntryState::Present
            {
                identify_into(&mut e, identifier);
                store.put(e)?;
            }
        }
        Ok(PollOutcome::Reconciled(report))
    }
}

/// Identifies `e` and records the result on it.
fn identify_into(e: &mut InvEntry, identifier: &mut dyn Identifier) {
    match identifier.identify(e.key) {
        Identified::Known {
            summary,
            user_writable,
        } => {
            e.identity = Some(*summary);
            e.user_writable_location = user_writable;
            e.state = EntryState::Present;
            e.stale = false;
        }
        Identified::Deferred => {
            e.state = EntryState::Deferred;
            e.stale = true;
        }
        Identified::Unreadable(reason) => {
            tracing::debug!(path = %e.path, %reason, "inventory could not read a file");
            e.state = EntryState::Unreadable;
            e.stale = true;
        }
        Identified::Gone => {
            e.state = EntryState::Deleted;
            e.stale = true;
        }
    }
}

/// Why a scan or poll failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// The store failed.
    Store(StoreError),
    /// The volume could not be read.
    Source(SourceError),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "inventory store: {e}"),
            Self::Source(e) => write!(f, "volume read: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<StoreError> for ScanError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<SourceError> for ScanError {
    fn from(e: SourceError) -> Self {
        Self::Source(e)
    }
}

#[cfg(test)]
mod tests;
