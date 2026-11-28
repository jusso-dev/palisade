use std::cell::Cell;
use std::collections::BTreeMap;

use super::*;
use crate::inventory::store::MemoryStore;
use crate::inventory::track::{COALESCE_WINDOW, ChangeFlags};

const SERIAL: u64 = 7;

fn id(n: u32) -> [u8; 16] {
    let mut f = [0; 16];
    f[..4].copy_from_slice(&n.to_le_bytes());
    f
}

fn key(n: u32) -> EntryKey {
    EntryKey {
        volume_serial: SERIAL,
        file_id: id(n),
    }
}

/// A scripted volume: files by ID, a journal and queued changes.
#[derive(Default)]
struct FakeVolume {
    files: BTreeMap<u32, (String, bool)>,
    journal: Option<JournalData>,
    changes: Vec<Change>,
    lose_cursor: bool,
    batch: usize,
    list_calls: u32,
}

impl FakeVolume {
    fn with_journal() -> Self {
        Self {
            journal: Some(JournalData {
                journal_id: 1,
                first_usn: 0,
                next_usn: 100,
                lowest_valid_usn: 0,
                max_usn: i64::MAX,
                maximum_size: 1 << 20,
            }),
            batch: 2,
            ..Self::default()
        }
    }

    fn file(mut self, n: u32, path: &str) -> Self {
        self.files.insert(n, (path.into(), false));
        self
    }

    fn dir(mut self, n: u32, path: &str) -> Self {
        self.files.insert(n, (path.into(), true));
        self
    }
}

impl VolumeSource for FakeVolume {
    fn serial(&self) -> u64 {
        SERIAL
    }

    fn journal(&mut self) -> Result<Option<JournalData>, SourceError> {
        Ok(self.journal)
    }

    fn list(
        &mut self,
        start: u64,
        _high_usn: i64,
    ) -> Result<Option<(u64, Vec<Listed>)>, SourceError> {
        self.list_calls += 1;
        let items: Vec<_> = self
            .files
            .range(u32::try_from(start).unwrap()..)
            .take(self.batch)
            .map(|(n, (p, d))| (*n, p.clone(), *d))
            .collect();
        let Some(&(last, _, _)) = items.last() else {
            return Ok(None);
        };
        Ok(Some((
            u64::from(last) + 1,
            items
                .into_iter()
                .map(|(n, path, directory)| Listed {
                    file_id: id(n),
                    path: Some(path),
                    directory,
                })
                .collect(),
        )))
    }

    fn changes(&mut self, cursor: JournalCursor) -> Result<(i64, Vec<Change>), SourceError> {
        if self.lose_cursor {
            return Err(SourceError::CursorLost);
        }
        let c = std::mem::take(&mut self.changes);
        let next = cursor.next_usn + i64::try_from(c.len()).unwrap();
        // The journal has written those records.
        if let Some(j) = self.journal.as_mut() {
            j.next_usn = j.next_usn.max(next);
        }
        Ok((next, c))
    }

    fn resolve(&mut self, file_id: [u8; 16]) -> Option<String> {
        let n = u32::from_le_bytes(file_id[..4].try_into().unwrap());
        self.files.get(&n).map(|(p, _)| p.clone())
    }
}

/// Identifies every file as a writable PE, except names with `.txt` (not
/// executable), `cloud` (deferred), `locked` (unreadable) and `gone`.
struct FakeIdentifier<'v> {
    files: &'v BTreeMap<u32, (String, bool)>,
    calls: u32,
}

impl Identifier for FakeIdentifier<'_> {
    fn identify(&mut self, key: EntryKey) -> Identified {
        self.calls += 1;
        let n = u32::from_le_bytes(key.file_id[..4].try_into().unwrap());
        let Some((path, _)) = self.files.get(&n) else {
            return Identified::Gone;
        };
        if path.contains("cloud") {
            return Identified::Deferred;
        }
        if path.contains("locked") {
            return Identified::Unreadable("denied".into());
        }
        Identified::Known {
            summary: Box::new(IdentitySummary {
                executable_content: Some(!path.ends_with(".txt.exe")),
                ..IdentitySummary::default()
            }),
            user_writable: Some(path.contains("Users")),
        }
    }
}

fn clock() -> impl Fn() -> (UtcTime, MonotonicTime) {
    let t = Cell::new(0_u64);
    move || {
        let now = t.get();
        t.set(now + 3_000_000);
        (UtcTime(i64::try_from(now).unwrap()), MonotonicTime(now))
    }
}

/// Runs `f` with a fresh identifier over a snapshot of `vol`'s files.
fn ident(vol: &FakeVolume) -> BTreeMap<u32, (String, bool)> {
    vol.files.clone()
}

#[test]
fn initial_scan_keeps_candidates_and_sets_the_cursor() {
    let scope = InventoryScope::default();
    let mut vol = FakeVolume::with_journal()
        .dir(1, r"C:\Windows")
        .file(2, r"C:\Windows\a.exe")
        .file(3, r"C:\Users\u\doc.pdf")
        .file(4, r"C:\pagefile.sys")
        .file(5, r"C:\Users\u\b.dll")
        .file(6, r"C:\Users\u\fake.txt.exe")
        .file(7, r"C:\Users\u\cloud.exe")
        .file(8, r"C:\Users\u\locked.ps1");
    let files = ident(&vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    let mut store = MemoryStore::default();
    let mut engine = Engine::new(&scope);
    let report = engine
        .scan(
            &mut vol,
            &mut store,
            &mut id,
            &mut Unthrottled,
            &clock(),
            Discovery::InitialScan,
        )
        .unwrap();
    assert!(report.complete);
    assert_eq!(report.listed, 8);
    // Not the folder, the PDF, the pagefile, or the non-executable file.
    assert_eq!(report.added, 4);
    assert_eq!(
        store.keys_on(SERIAL).unwrap(),
        [key(2), key(5), key(7), key(8)]
    );
    let a = store.get(&key(2)).unwrap().unwrap();
    assert!(a.existing_at_install);
    assert_eq!(a.discovery, Discovery::InitialScan);
    assert_eq!(a.user_writable_location, Some(false));
    assert!(a.current_identity().is_some());
    assert_eq!(
        store.get(&key(7)).unwrap().unwrap().state,
        EntryState::Deferred
    );
    assert_eq!(
        store.get(&key(8)).unwrap().unwrap().state,
        EntryState::Unreadable
    );
    assert_eq!(
        store.cursor(SERIAL).unwrap(),
        Some(JournalCursor {
            journal_id: 1,
            next_usn: 100
        })
    );
    assert_eq!(store.checkpoint(SERIAL).unwrap(), None);
    assert!(report.deltas.iter().all(|(_, d)| *d == DeltaKind::Added));
}

/// Stops after a number of batches, as a stop request or the budget would.
struct StopAfter(u32);

impl Throttle for StopAfter {
    fn admit(&mut self, _files: usize) -> bool {
        if self.0 == 0 {
            return false;
        }
        self.0 -= 1;
        true
    }
}

#[test]
fn an_interrupted_scan_resumes_from_its_checkpoint() {
    let scope = InventoryScope::default();
    let mut vol = FakeVolume::with_journal();
    for n in 1..=6 {
        vol = vol.file(n, &format!(r"C:\p\{n}.exe"));
    }
    let files = ident(&vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    let mut store = MemoryStore::default();
    let mut engine = Engine::new(&scope);
    let clock = clock();
    let first = engine
        .scan(
            &mut vol,
            &mut store,
            &mut id,
            &mut StopAfter(2),
            &clock,
            Discovery::InitialScan,
        )
        .unwrap();
    assert!(!first.complete);
    assert_eq!(first.added, 4);
    let cp = store.checkpoint(SERIAL).unwrap().unwrap();
    assert_eq!((cp.next_reference, cp.files_seen), (5, 4));
    assert_eq!(store.cursor(SERIAL).unwrap(), None, "not until complete");
    // Polling before the scan finishes asks for the scan.
    assert_eq!(
        engine
            .poll(&mut vol, &mut store, &mut id, &mut Unthrottled, &clock)
            .unwrap(),
        PollOutcome::NeedsScan
    );
    // The journal moves on meanwhile; the resumed scan keeps the cursor
    // from when it started.
    vol.journal.as_mut().unwrap().next_usn = 500;
    let rest = engine
        .scan(
            &mut vol,
            &mut store,
            &mut id,
            &mut Unthrottled,
            &clock,
            Discovery::InitialScan,
        )
        .unwrap();
    assert!(rest.complete);
    assert_eq!(rest.added, 2);
    assert_eq!(store.len().unwrap(), 6);
    assert_eq!(store.cursor(SERIAL).unwrap().unwrap().next_usn, 100);
}

#[test]
fn checkpoints_are_saved_by_time() {
    let scope = InventoryScope::default();
    let mut vol = FakeVolume::with_journal();
    vol.batch = 1;
    for n in 1..=40 {
        vol = vol.file(n, &format!(r"C:\p\{n}.exe"));
    }
    let files = ident(&vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    // Each clock read advances 3 s, so a checkpoint lands every 10
    // batches; stopping after 25 resumes from the one saved at the stop.
    let mut store = MemoryStore::default();
    let mut engine = Engine::new(&scope);
    engine
        .scan(
            &mut vol,
            &mut store,
            &mut id,
            &mut StopAfter(25),
            &clock(),
            Discovery::InitialScan,
        )
        .unwrap();
    assert_eq!(store.checkpoint(SERIAL).unwrap().unwrap().files_seen, 25);
}

fn scanned(scope: &InventoryScope, vol: &mut FakeVolume, store: &mut MemoryStore) {
    let files = ident(vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    Engine::new(scope)
        .scan(
            vol,
            store,
            &mut id,
            &mut Unthrottled,
            &clock(),
            Discovery::InitialScan,
        )
        .unwrap();
}

fn change(n: u32, flags: ChangeFlags) -> Change {
    Change {
        key: key(n),
        flags,
        directory: false,
        path: None,
    }
}

#[test]
fn polling_applies_coalesced_changes() {
    let scope = InventoryScope::default();
    let mut vol = FakeVolume::with_journal()
        .file(1, r"C:\Users\u\a.exe")
        .file(2, r"C:\Users\u\b.exe");
    let mut store = MemoryStore::default();
    scanned(&scope, &mut vol, &mut store);

    // a.exe is rewritten and closed; b.exe moves; c.exe is new.
    vol.files
        .insert(2, (r"C:\Users\u\moved\b.exe".into(), false));
    vol.files.insert(3, (r"C:\Users\u\c.exe".into(), false));
    vol.changes = vec![
        change(1, ChangeFlags::CONTENT),
        change(1, ChangeFlags::CLOSED),
        change(2, ChangeFlags::RENAMED | ChangeFlags::CLOSED),
        change(3, ChangeFlags::CREATED | ChangeFlags::CLOSED),
    ];
    let files = ident(&vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    let mut engine = Engine::new(&scope);
    let t = Cell::new(0_u64);
    let clock = || {
        let now = t.get();
        (UtcTime(i64::try_from(now).unwrap()), MonotonicTime(now))
    };
    let out = engine
        .poll(&mut vol, &mut store, &mut id, &mut Unthrottled, &clock)
        .unwrap();
    assert_eq!(out, PollOutcome::Applied { deltas: Vec::new() });
    // Seen at once: the rewritten file is stale already.
    assert!(store.get(&key(1)).unwrap().unwrap().stale);
    assert_eq!(store.cursor(SERIAL).unwrap().unwrap().next_usn, 104);

    t.set(u64::try_from(COALESCE_WINDOW.as_micros()).unwrap());
    let PollOutcome::Applied { mut deltas } = engine
        .poll(&mut vol, &mut store, &mut id, &mut Unthrottled, &clock)
        .unwrap()
    else {
        panic!("applied")
    };
    deltas.sort_by_key(|(k, _)| *k);
    assert_eq!(
        deltas,
        [
            (key(1), DeltaKind::Modified),
            (key(2), DeltaKind::Renamed),
            (key(3), DeltaKind::Added)
        ]
    );
    let a = store.get(&key(1)).unwrap().unwrap();
    assert!(!a.stale, "identified again");
    let b = store.get(&key(2)).unwrap().unwrap();
    assert_eq!(b.path, r"C:\Users\u\moved\b.exe");
    assert_eq!(b.path_history, [r"C:\Users\u\b.exe"]);
    assert_eq!(b.user_writable_location, Some(true), "reassessed");
    assert!(
        store
            .get(&key(3))
            .unwrap()
            .unwrap()
            .current_identity()
            .is_some()
    );
}

#[test]
fn a_folder_change_reassesses_entries_under_it() {
    let scope = InventoryScope::default();
    let mut vol = FakeVolume::with_journal()
        .dir(9, r"C:\Tools")
        .file(1, r"C:\Tools\a.exe");
    let mut store = MemoryStore::default();
    scanned(&scope, &mut vol, &mut store);
    assert_eq!(
        store.get(&key(1)).unwrap().unwrap().user_writable_location,
        Some(false)
    );
    vol.changes = vec![Change {
        key: key(9),
        flags: ChangeFlags::SECURITY | ChangeFlags::CLOSED,
        directory: true,
        path: None,
    }];
    let files = ident(&vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    let mut engine = Engine::new(&scope);
    let t = Cell::new(0_u64);
    let clock = || {
        let now = t.get();
        (UtcTime(0), MonotonicTime(now))
    };
    engine
        .poll(&mut vol, &mut store, &mut id, &mut Unthrottled, &clock)
        .unwrap();
    t.set(u64::try_from(COALESCE_WINDOW.as_micros()).unwrap());
    engine
        .poll(&mut vol, &mut store, &mut id, &mut Unthrottled, &clock)
        .unwrap();
    assert_eq!(
        store.get(&key(1)).unwrap().unwrap().user_writable_location,
        None,
        "unknown until reassessed: counts as writable"
    );
}

#[test]
fn a_lost_cursor_reconciles_the_volume() {
    let scope = InventoryScope::default();
    let mut vol = FakeVolume::with_journal()
        .file(1, r"C:\p\a.exe")
        .file(2, r"C:\p\b.exe");
    let mut store = MemoryStore::default();
    scanned(&scope, &mut vol, &mut store);

    // While the journal was not read: b.exe went, c.exe came, a.exe moved.
    vol.files.remove(&2);
    vol.files.insert(3, (r"C:\p\c.exe".into(), false));
    vol.files.insert(1, (r"C:\q\a.exe".into(), false));
    vol.lose_cursor = true;
    let files = ident(&vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    let mut engine = Engine::new(&scope);
    let out = engine
        .poll(&mut vol, &mut store, &mut id, &mut Unthrottled, &clock())
        .unwrap();
    let PollOutcome::Reconciled(report) = out else {
        panic!("{out:?}")
    };
    assert!(report.complete);
    assert_eq!((report.added, report.deleted), (1, 1));
    let b = store.get(&key(2)).unwrap().unwrap();
    assert_eq!(b.state, EntryState::Deleted);
    let a = store.get(&key(1)).unwrap().unwrap();
    assert_eq!(a.path, r"C:\q\a.exe");
    assert!(!a.existing_at_install || a.discovery == Discovery::InitialScan);
    assert_eq!(
        store.get(&key(3)).unwrap().unwrap().discovery,
        Discovery::Rescan
    );
    assert!(store.cursor(SERIAL).unwrap().is_some());
}

#[test]
fn a_replaced_or_wrapped_journal_reconciles_too() {
    let scope = InventoryScope::default();
    for (journal_id, lowest) in [(2, 0), (1, 101)] {
        let mut vol = FakeVolume::with_journal().file(1, r"C:\p\a.exe");
        let mut store = MemoryStore::default();
        scanned(&scope, &mut vol, &mut store);
        let j = vol.journal.as_mut().unwrap();
        j.journal_id = journal_id;
        j.lowest_valid_usn = lowest;
        j.next_usn = 200;
        let files = ident(&vol);
        let mut id = FakeIdentifier {
            files: &files,
            calls: 0,
        };
        let out = Engine::new(&scope)
            .poll(&mut vol, &mut store, &mut id, &mut Unthrottled, &clock())
            .unwrap();
        assert!(matches!(out, PollOutcome::Reconciled(_)), "{out:?}");
        assert_eq!(
            store.cursor(SERIAL).unwrap(),
            Some(JournalCursor {
                journal_id,
                next_usn: 200
            })
        );
    }
}

#[test]
fn a_reconciliation_never_marks_deletions_from_a_partial_listing() {
    let scope = InventoryScope::default();
    let mut vol = FakeVolume::with_journal()
        .file(1, r"C:\p\a.exe")
        .file(2, r"C:\p\b.exe")
        .file(3, r"C:\p\c.exe");
    let mut store = MemoryStore::default();
    scanned(&scope, &mut vol, &mut store);
    let files = ident(&vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    let mut engine = Engine::new(&scope);
    // A rescan stopped part way leaves a checkpoint...
    let partial = engine
        .scan(
            &mut vol,
            &mut store,
            &mut id,
            &mut StopAfter(1),
            &clock(),
            Discovery::Rescan,
        )
        .unwrap();
    assert!(!partial.complete);
    assert_eq!(partial.deleted, 0);
    // ...and resuming starts over, so it sees every file.
    let calls = vol.list_calls;
    let done = engine
        .scan(
            &mut vol,
            &mut store,
            &mut id,
            &mut Unthrottled,
            &clock(),
            Discovery::Rescan,
        )
        .unwrap();
    assert_eq!(done.listed, 3);
    assert_eq!(done.deleted, 0);
    assert!(vol.list_calls - calls >= 2);
}

#[test]
fn volumes_without_a_journal() {
    let scope = InventoryScope::default();
    let mut vol = FakeVolume {
        batch: 4,
        ..FakeVolume::default()
    }
    .file(1, r"E:\a.exe");
    let mut store = MemoryStore::default();
    scanned(&scope, &mut vol, &mut store);
    assert_eq!(store.len().unwrap(), 1);
    assert_eq!(store.cursor(SERIAL).unwrap(), None);
    let files = ident(&vol);
    let mut id = FakeIdentifier {
        files: &files,
        calls: 0,
    };
    let out = Engine::new(&scope)
        .poll(&mut vol, &mut store, &mut id, &mut Unthrottled, &clock())
        .unwrap();
    assert_eq!(out, PollOutcome::NoJournal);
    // A volume with a journal never scanned asks for a scan.
    let mut fresh = FakeVolume::with_journal();
    let out = Engine::new(&scope)
        .poll(
            &mut fresh,
            &mut MemoryStore::default(),
            &mut id,
            &mut Unthrottled,
            &clock(),
        )
        .unwrap();
    assert_eq!(out, PollOutcome::NeedsScan);
}

#[test]
fn errors_name_their_source() {
    assert_eq!(
        ScanError::Source(SourceError::CursorLost).to_string(),
        "volume read: the change journal cursor is no longer readable"
    );
    assert_eq!(
        ScanError::from(StoreError("full".into())).to_string(),
        "inventory store: full"
    );
    assert_eq!(SourceError::Other("x".into()).to_string(), "x");
}
