//! Incremental change tracking: changes are coalesced per file, then
//! applied to the inventory.
//!
//! A change source (the NTFS change journal on Windows, directory
//! notifications or a periodic rescan elsewhere) reports [`Change`]s. The
//! [`Coalescer`] gathers every change to one file within
//! [`COALESCE_WINDOW`] and releases them as one [`Coalesced`] once the file
//! has been closed, or after [`MAX_HOLD`] if it never is. [`apply`] then
//! updates the entry and says what work it needs ([`Action`]).
//!
//! Fail closed (ADR 0018): [`Coalescer::push`] returns at once whether the
//! change made the entry's identity or location unreliable, and
//! [`invalidate`] marks it so before the coalesced change is applied. A
//! file never keeps its old identity while it is being rewritten.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::time::Duration;

use palisade_core::platform::{MonotonicTime, UtcTime};

use super::entry::{Discovery, EntryKey, EntryState, InvEntry};
use super::store::{InventoryStore, StoreError};

/// How long changes to one file are gathered before they are applied.
pub const COALESCE_WINDOW: Duration = Duration::from_secs(2);

/// How long changes to a file that is never closed are held before they
/// are applied anyway.
pub const MAX_HOLD: Duration = Duration::from_secs(60);

/// The most files held at once. Past it, the oldest are released early.
pub const MAX_PENDING: usize = 100_000;

/// What happened to a file. Several can be set at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ChangeFlags(u16);

impl ChangeFlags {
    /// Nothing.
    pub const NONE: Self = Self(0);
    /// It was created.
    pub const CREATED: Self = Self(1);
    /// Its content changed: data, a stream, extended attributes, a reparse
    /// point or a hard link.
    pub const CONTENT: Self = Self(1 << 1);
    /// It was renamed or moved; the change carries the new name.
    pub const RENAMED: Self = Self(1 << 2);
    /// It was deleted.
    pub const DELETED: Self = Self(1 << 3);
    /// Its security descriptor changed.
    pub const SECURITY: Self = Self(1 << 4);
    /// Its attributes or times changed.
    pub const BASIC_INFO: Self = Self(1 << 5);
    /// The last handle closed: the changes before it are complete.
    pub const CLOSED: Self = Self(1 << 6);

    /// Whether every flag of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any flag of `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for ChangeFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// One reported change to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The file.
    pub key: EntryKey,
    /// What happened.
    pub flags: ChangeFlags,
    /// Whether it is a folder.
    pub directory: bool,
    /// Its full path after the change, if the source knows it. A journal
    /// gives only the name and parent; the caller resolves it.
    pub path: Option<String>,
}

/// Every change to one file in its window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coalesced {
    /// The file.
    pub key: EntryKey,
    /// Every flag reported.
    pub flags: ChangeFlags,
    /// Whether it is a folder.
    pub directory: bool,
    /// The last path reported.
    pub path: Option<String>,
    /// Released without a close, after [`MAX_HOLD`] or to make room: the
    /// file may still be being written.
    pub forced: bool,
}

#[derive(Debug)]
struct Pending {
    change: Coalesced,
    first: MonotonicTime,
}

/// Gathers changes per file.
#[derive(Debug, Default)]
pub struct Coalescer {
    pending: BTreeMap<EntryKey, Pending>,
}

/// What a change means for the entry right now, before it is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalidation {
    /// Nothing to do yet.
    None,
    /// The content is changing: the identity must not be relied on.
    Content,
    /// The location's writability may have changed.
    Location,
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

impl Coalescer {
    /// Adds a change seen at `now`. Returns what it already invalidates.
    pub fn push(&mut self, change: Change, now: MonotonicTime) -> Invalidation {
        let invalidation = if change
            .flags
            .intersects(ChangeFlags::CONTENT | ChangeFlags::DELETED | ChangeFlags::CREATED)
        {
            Invalidation::Content
        } else if change
            .flags
            .intersects(ChangeFlags::SECURITY | ChangeFlags::RENAMED)
        {
            Invalidation::Location
        } else {
            Invalidation::None
        };
        let p = self.pending.entry(change.key).or_insert_with(|| Pending {
            change: Coalesced {
                key: change.key,
                flags: ChangeFlags::NONE,
                directory: change.directory,
                path: None,
                forced: false,
            },
            first: now,
        });
        p.change.flags = p.change.flags | change.flags;
        p.change.directory |= change.directory;
        if change.path.is_some() {
            p.change.path = change.path;
        }
        invalidation
    }

    /// The number of files with changes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Releases the files whose window has passed and that were closed (or
    /// deleted), those held past [`MAX_HOLD`], and, past [`MAX_PENDING`],
    /// the oldest. In key order within each group.
    pub fn ready(&mut self, now: MonotonicTime) -> Vec<Coalesced> {
        let age = |p: &Pending| now.0.saturating_sub(p.first.0);
        let mut out = Vec::new();
        self.pending.retain(|_, p| {
            let done = p
                .change
                .flags
                .intersects(ChangeFlags::CLOSED | ChangeFlags::DELETED);
            let release = (done && age(p) >= micros(COALESCE_WINDOW)) || age(p) >= micros(MAX_HOLD);
            if release {
                let mut c = p.change.clone();
                c.forced = !done;
                out.push(c);
            }
            !release
        });
        if self.pending.len() > MAX_PENDING {
            let mut by_age: Vec<_> = self.pending.iter().map(|(k, p)| (p.first, *k)).collect();
            by_age.sort_unstable();
            let extra = self.pending.len() - MAX_PENDING;
            for (_, k) in by_age.into_iter().take(extra) {
                if let Some(p) = self.pending.remove(&k) {
                    let mut c = p.change;
                    c.forced = true;
                    out.push(c);
                }
            }
        }
        out
    }

    /// Releases everything, as at shutdown or before a reconciliation.
    pub fn drain(&mut self) -> Vec<Coalesced> {
        std::mem::take(&mut self.pending)
            .into_values()
            .map(|p| {
                let mut c = p.change;
                c.forced = !c
                    .flags
                    .intersects(ChangeFlags::CLOSED | ChangeFlags::DELETED);
                c
            })
            .collect()
    }
}

/// Marks the entry for `key` as [`Coalescer::push`] said, at once.
pub fn invalidate(
    store: &mut dyn InventoryStore,
    key: &EntryKey,
    invalidation: Invalidation,
) -> Result<(), StoreError> {
    if invalidation == Invalidation::None {
        return Ok(());
    }
    if let Some(mut e) = store.get(key)? {
        match invalidation {
            Invalidation::Content => e.stale = true,
            Invalidation::Location => e.user_writable_location = None,
            Invalidation::None => {}
        }
        store.put(e)?;
    }
    Ok(())
}

/// The change to report to the server for one applied change (#62).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeltaKind {
    /// A new file.
    Added,
    /// Its content changed.
    Modified,
    /// It moved.
    Renamed,
    /// It was deleted.
    Deleted,
    /// Its state or location changed.
    StateChanged,
}

/// What [`apply`] needs done next for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Nothing.
    None,
    /// Compute its identity (a new file, or new content). Evict its hash
    /// cache entry first (#46).
    Identify,
    /// Assess its location's writability again.
    ReassessLocation,
    /// A folder changed: assess every entry under it again (its security,
    /// or its name and so every path below it).
    Directory,
    /// Its path is unknown: resolve it from its ID.
    ResolvePath,
}

/// The result of [`apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// What to do next.
    pub action: Action,
    /// What to report, if anything.
    pub delta: Option<DeltaKind>,
}

/// Applies one coalesced change at wall time `now`.
pub fn apply(
    store: &mut dyn InventoryStore,
    change: &Coalesced,
    now: UtcTime,
) -> Result<Applied, StoreError> {
    let applied = |action, delta| Ok(Applied { action, delta });
    if change.directory {
        let relevant = change
            .flags
            .intersects(ChangeFlags::SECURITY | ChangeFlags::RENAMED | ChangeFlags::DELETED);
        return applied(
            if relevant {
                Action::Directory
            } else {
                Action::None
            },
            None,
        );
    }
    let existing = store.get(&change.key)?;
    let created = change.flags.contains(ChangeFlags::CREATED);
    if change.flags.contains(ChangeFlags::DELETED) {
        let Some(mut e) = existing else {
            // Created and deleted within the window, or never inventoried.
            return applied(Action::None, None);
        };
        if e.state == EntryState::Deleted {
            return applied(Action::None, None);
        }
        e.state = EntryState::Deleted;
        e.deleted_at = Some(now);
        e.stale = true;
        store.put(e)?;
        return applied(Action::None, Some(DeltaKind::Deleted));
    }
    let Some(mut e) = existing else {
        // A file the inventory did not have: new, or created while the
        // agent was not looking.
        let Some(path) = change.path.clone() else {
            return applied(Action::ResolvePath, None);
        };
        let mut e = InvEntry::new(change.key, path, now, Discovery::Change);
        e.last_modified = Some(now);
        store.put(e)?;
        return applied(Action::Identify, Some(DeltaKind::Added));
    };
    let revived = e.state == EntryState::Deleted;
    if revived {
        // The ID was reused, or a delete was undone: treat it as new
        // content.
        e.state = EntryState::Present;
        e.deleted_at = None;
    }
    let content = created || revived || change.flags.intersects(ChangeFlags::CONTENT);
    let mut moved = false;
    if change.flags.contains(ChangeFlags::RENAMED) {
        match &change.path {
            Some(p) => moved = e.move_to(p.clone()),
            None => {
                e.user_writable_location = None;
                store.put(e)?;
                return applied(Action::ResolvePath, None);
            }
        }
    }
    let location = moved || change.flags.contains(ChangeFlags::SECURITY);
    if location {
        e.user_writable_location = None;
    }
    if content {
        // A file released without a close may be half written: it stays
        // stale until it is identified again, like any other change.
        e.stale = true;
        e.last_modified = Some(now);
    }
    let delta = if content {
        Some(DeltaKind::Modified)
    } else if moved {
        Some(DeltaKind::Renamed)
    } else if location {
        Some(DeltaKind::StateChanged)
    } else {
        None
    };
    let action = if content || e.stale {
        Action::Identify
    } else if location || e.user_writable_location.is_none() {
        // A location not yet assessed is assessed now (it counts as
        // writable meanwhile).
        Action::ReassessLocation
    } else {
        Action::None
    };
    store.put(e)?;
    applied(action, delta)
}

/// Forgets the writability of every entry whose path is at or under
/// `folder` on the volume `volume_serial`, after a folder's security or name
/// changed. Returns how many were marked.
pub fn invalidate_under(
    store: &mut dyn InventoryStore,
    volume_serial: u64,
    folder: &str,
) -> Result<usize, StoreError> {
    let prefix = palisade_fileid::fsctx::fold_case(folder.trim_end_matches('\\'));
    let mut n = 0;
    for key in store.keys_on(volume_serial)? {
        let Some(mut e) = store.get(&key)? else {
            continue;
        };
        let path = palisade_fileid::fsctx::fold_case(&e.path);
        let under = path
            .strip_prefix(prefix.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'));
        if under && e.user_writable_location.is_some() {
            e.user_writable_location = None;
            store.put(e)?;
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::store::MemoryStore;

    fn key(n: u8) -> EntryKey {
        EntryKey {
            volume_serial: 1,
            file_id: [n; 16],
        }
    }

    fn change(n: u8, flags: ChangeFlags, path: Option<&str>) -> Change {
        Change {
            key: key(n),
            flags,
            directory: false,
            path: path.map(str::to_owned),
        }
    }

    const S: u64 = 1_000_000;

    #[test]
    fn changes_coalesce_until_close_and_the_window() {
        let mut c = Coalescer::default();
        assert!(c.is_empty());
        assert_eq!(
            c.push(
                change(1, ChangeFlags::CREATED, Some(r"C:\a.exe")),
                MonotonicTime(0)
            ),
            Invalidation::Content
        );
        assert_eq!(
            c.push(change(1, ChangeFlags::CONTENT, None), MonotonicTime(S / 2)),
            Invalidation::Content
        );
        assert!(c.ready(MonotonicTime(3 * S)).is_empty(), "not closed yet");
        assert_eq!(
            c.push(change(1, ChangeFlags::CLOSED, None), MonotonicTime(3 * S)),
            Invalidation::None
        );
        let out = c.ready(MonotonicTime(3 * S));
        assert_eq!(out.len(), 1);
        let one = &out[0];
        assert!(
            one.flags
                .contains(ChangeFlags::CREATED | ChangeFlags::CONTENT)
        );
        assert_eq!(one.path.as_deref(), Some(r"C:\a.exe"), "kept from earlier");
        assert!(!one.forced);
        assert_eq!(c.len(), 0);

        // Closed at once: still waits for the window.
        c.push(
            change(2, ChangeFlags::CONTENT | ChangeFlags::CLOSED, None),
            MonotonicTime(10 * S),
        );
        assert!(c.ready(MonotonicTime(11 * S)).is_empty());
        assert_eq!(c.ready(MonotonicTime(12 * S)).len(), 1);
    }

    #[test]
    fn invalidation_kinds() {
        let mut c = Coalescer::default();
        let t = MonotonicTime(0);
        assert_eq!(
            c.push(change(1, ChangeFlags::DELETED, None), t),
            Invalidation::Content
        );
        assert_eq!(
            c.push(change(2, ChangeFlags::SECURITY, None), t),
            Invalidation::Location
        );
        assert_eq!(
            c.push(change(3, ChangeFlags::RENAMED, Some("x")), t),
            Invalidation::Location
        );
        assert_eq!(
            c.push(change(4, ChangeFlags::BASIC_INFO, None), t),
            Invalidation::None
        );
    }

    #[test]
    fn files_never_closed_are_forced_out() {
        let mut c = Coalescer::default();
        c.push(change(1, ChangeFlags::CONTENT, None), MonotonicTime(0));
        assert!(c.ready(MonotonicTime(59 * S)).is_empty());
        let out = c.ready(MonotonicTime(60 * S));
        assert!(out[0].forced);
        // Draining marks unclosed files forced, and closed or deleted ones
        // not.
        c.push(change(2, ChangeFlags::CONTENT, None), MonotonicTime(0));
        c.push(change(3, ChangeFlags::DELETED, None), MonotonicTime(0));
        let mut d = c.drain();
        d.sort_by_key(|x| x.key);
        assert_eq!(
            d.iter().map(|x| x.forced).collect::<Vec<_>>(),
            [true, false]
        );
        assert!(c.is_empty());
    }

    #[test]
    fn the_oldest_are_released_past_the_limit() {
        let mut c = Coalescer::default();
        for i in 0..=MAX_PENDING {
            let id = u32::try_from(i).unwrap().to_le_bytes();
            let mut file_id = [0; 16];
            file_id[..4].copy_from_slice(&id);
            c.push(
                Change {
                    key: EntryKey {
                        volume_serial: 1,
                        file_id,
                    },
                    flags: ChangeFlags::CONTENT,
                    directory: false,
                    path: None,
                },
                MonotonicTime(u64::try_from(i).unwrap()),
            );
        }
        let out = c.ready(MonotonicTime(MAX_PENDING as u64 + 1));
        assert_eq!(out.len(), 1);
        assert!(out[0].forced);
        assert_eq!(out[0].key.file_id[..4], [0; 4], "the oldest");
        assert_eq!(c.len(), MAX_PENDING);
    }

    fn coalesced(n: u8, flags: ChangeFlags, path: Option<&str>) -> Coalesced {
        Coalesced {
            key: key(n),
            flags,
            directory: false,
            path: path.map(str::to_owned),
            forced: false,
        }
    }

    fn known(store: &mut MemoryStore, n: u8, path: &str) {
        let mut e = InvEntry::new(key(n), path.into(), UtcTime(0), Discovery::InitialScan);
        e.stale = false;
        e.user_writable_location = Some(false);
        store.put(e).unwrap();
    }

    #[test]
    fn new_files_are_added_and_identified() {
        let mut s = MemoryStore::default();
        let r = apply(
            &mut s,
            &coalesced(
                1,
                ChangeFlags::CREATED | ChangeFlags::CLOSED,
                Some(r"C:\a.exe"),
            ),
            UtcTime(5),
        )
        .unwrap();
        assert_eq!(
            (r.action, r.delta),
            (Action::Identify, Some(DeltaKind::Added))
        );
        let e = s.get(&key(1)).unwrap().unwrap();
        assert_eq!(
            (e.discovery, e.existing_at_install),
            (Discovery::Change, false)
        );
        assert_eq!(e.last_modified, Some(UtcTime(5)));
        assert!(e.stale);
        // Without a path, it must be resolved first.
        let r = apply(
            &mut s,
            &coalesced(2, ChangeFlags::CREATED, None),
            UtcTime(5),
        )
        .unwrap();
        assert_eq!((r.action, r.delta), (Action::ResolvePath, None));
        assert_eq!(s.get(&key(2)).unwrap(), None);
    }

    #[test]
    fn content_changes_mark_stale_and_rehash() {
        let mut s = MemoryStore::default();
        known(&mut s, 1, r"C:\a.exe");
        let r = apply(
            &mut s,
            &coalesced(1, ChangeFlags::CONTENT, None),
            UtcTime(9),
        )
        .unwrap();
        assert_eq!(
            (r.action, r.delta),
            (Action::Identify, Some(DeltaKind::Modified))
        );
        let e = s.get(&key(1)).unwrap().unwrap();
        assert!(e.stale);
        assert_eq!(e.last_modified, Some(UtcTime(9)));
        assert_eq!(e.user_writable_location, Some(false), "same place");
    }

    #[test]
    fn renames_keep_the_entry_and_its_history() {
        let mut s = MemoryStore::default();
        known(&mut s, 1, r"C:\a.exe");
        let r = apply(
            &mut s,
            &coalesced(1, ChangeFlags::RENAMED, Some(r"C:\b\a.exe")),
            UtcTime(9),
        )
        .unwrap();
        assert_eq!(
            (r.action, r.delta),
            (Action::ReassessLocation, Some(DeltaKind::Renamed))
        );
        let e = s.get(&key(1)).unwrap().unwrap();
        assert_eq!(e.path, r"C:\b\a.exe");
        assert_eq!(e.path_history, [r"C:\a.exe"]);
        assert!(!e.stale, "content unchanged");
        assert_eq!(e.user_writable_location, None, "new place: unknown");
        // A rename whose new path is not known yet.
        let r = apply(
            &mut s,
            &coalesced(1, ChangeFlags::RENAMED, None),
            UtcTime(9),
        )
        .unwrap();
        assert_eq!(r.action, Action::ResolvePath);
        // A rename to the same path is nothing new.
        known(&mut s, 2, r"C:\c.exe");
        let r = apply(
            &mut s,
            &coalesced(2, ChangeFlags::RENAMED, Some(r"C:\c.exe")),
            UtcTime(9),
        )
        .unwrap();
        assert_eq!((r.action, r.delta), (Action::None, None));
    }

    #[test]
    fn security_changes_reassess_the_location() {
        let mut s = MemoryStore::default();
        known(&mut s, 1, r"C:\a.exe");
        let r = apply(
            &mut s,
            &coalesced(1, ChangeFlags::SECURITY, None),
            UtcTime(9),
        )
        .unwrap();
        assert_eq!(
            (r.action, r.delta),
            (Action::ReassessLocation, Some(DeltaKind::StateChanged))
        );
        assert_eq!(
            s.get(&key(1)).unwrap().unwrap().user_writable_location,
            None
        );
        // Times alone change nothing.
        let r = apply(
            &mut s,
            &coalesced(1, ChangeFlags::BASIC_INFO, None),
            UtcTime(9),
        )
        .unwrap();
        assert_eq!((r.action, r.delta), (Action::ReassessLocation, None));
    }

    #[test]
    fn deletes_are_kept_then_revived_as_new_content() {
        let mut s = MemoryStore::default();
        known(&mut s, 1, r"C:\a.exe");
        let r = apply(
            &mut s,
            &coalesced(1, ChangeFlags::DELETED, None),
            UtcTime(9),
        )
        .unwrap();
        assert_eq!(
            (r.action, r.delta),
            (Action::None, Some(DeltaKind::Deleted))
        );
        let e = s.get(&key(1)).unwrap().unwrap();
        assert_eq!(
            (e.state, e.deleted_at),
            (EntryState::Deleted, Some(UtcTime(9)))
        );
        assert_eq!(e.current_identity(), None);
        // Deleting again, or deleting an unknown file, is nothing.
        let r = apply(
            &mut s,
            &coalesced(1, ChangeFlags::DELETED, None),
            UtcTime(10),
        )
        .unwrap();
        assert_eq!(r.delta, None);
        let r = apply(
            &mut s,
            &coalesced(7, ChangeFlags::DELETED, None),
            UtcTime(10),
        )
        .unwrap();
        assert_eq!(r.delta, None);
        // The ID back again is new content.
        let r = apply(
            &mut s,
            &coalesced(1, ChangeFlags::BASIC_INFO, None),
            UtcTime(11),
        )
        .unwrap();
        assert_eq!(
            (r.action, r.delta),
            (Action::Identify, Some(DeltaKind::Modified))
        );
        let e = s.get(&key(1)).unwrap().unwrap();
        assert_eq!((e.state, e.deleted_at), (EntryState::Present, None));
    }

    #[test]
    fn folders_ask_for_their_entries_to_be_reassessed() {
        let mut s = MemoryStore::default();
        let mut d = coalesced(9, ChangeFlags::SECURITY, None);
        d.directory = true;
        assert_eq!(
            apply(&mut s, &d, UtcTime(0)).unwrap().action,
            Action::Directory
        );
        d.flags = ChangeFlags::BASIC_INFO;
        assert_eq!(apply(&mut s, &d, UtcTime(0)).unwrap().action, Action::None);

        known(&mut s, 1, r"C:\Tools\a.exe");
        known(&mut s, 2, r"C:\Tools\sub\b.exe");
        known(&mut s, 3, r"C:\ToolsX\c.exe");
        known(&mut s, 4, r"C:\tools");
        assert_eq!(invalidate_under(&mut s, 1, r"c:\TOOLS\").unwrap(), 3);
        assert_eq!(
            s.get(&key(3)).unwrap().unwrap().user_writable_location,
            Some(false)
        );
        assert_eq!(
            invalidate_under(&mut s, 1, r"C:\Tools").unwrap(),
            0,
            "already"
        );
    }

    #[test]
    fn invalidation_marks_at_once() {
        let mut s = MemoryStore::default();
        known(&mut s, 1, "a");
        invalidate(&mut s, &key(1), Invalidation::None).unwrap();
        assert!(!s.get(&key(1)).unwrap().unwrap().stale);
        invalidate(&mut s, &key(1), Invalidation::Location).unwrap();
        assert_eq!(
            s.get(&key(1)).unwrap().unwrap().user_writable_location,
            None
        );
        invalidate(&mut s, &key(1), Invalidation::Content).unwrap();
        assert!(s.get(&key(1)).unwrap().unwrap().stale);
        // Unknown files are left alone.
        invalidate(&mut s, &key(2), Invalidation::Content).unwrap();
        assert_eq!(s.get(&key(2)).unwrap(), None);
    }
}
