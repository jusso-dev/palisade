//! Where the spool's segments live: the [`Storage`] trait, the
//! [`FileStorage`] under the agent's data directory, and the
//! [`MemoryStorage`] used when there is no data directory, in tests, and
//! to simulate crashes.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use super::segment::Class;

/// One segment: its class and the sequence number of its first record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentId {
    /// The class of every record in it.
    pub class: Class,
    /// The sequence number of its first record.
    pub first_seq: u64,
}

impl SegmentId {
    /// Its file name: `<class>-<first_seq, 20 digits>.seg`.
    #[must_use]
    pub fn file_name(self) -> String {
        format!("{}-{:020}.seg", self.class.as_str(), self.first_seq)
    }

    /// The segment a file name stands for, if it is one.
    #[must_use]
    pub fn from_file_name(name: &str) -> Option<Self> {
        let stem = name.strip_suffix(".seg")?;
        let (class, seq) = stem.rsplit_once('-')?;
        if seq.len() != 20 || !seq.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            class: Class::from_name(class)?,
            first_seq: seq.parse().ok()?,
        })
    }
}

/// The largest segment file the spool reads: anything past it is treated
/// as a torn tail. Generous next to the default segment size, so only a
/// damaged or planted file reaches it.
pub const MAX_SEGMENT_READ: u64 = 64 << 20;

/// The largest state file the spool reads.
const MAX_STATE_READ: u64 = 4096;

/// Segment and state storage. Each call is one operation; the spool
/// decides the order, so a crash between two calls leaves a state it can
/// recover from.
pub trait Storage: Send {
    /// Every segment there is, in no particular order.
    fn list(&mut self) -> io::Result<Vec<SegmentId>>;
    /// The whole segment, up to [`MAX_SEGMENT_READ`] bytes.
    fn read(&mut self, id: SegmentId) -> io::Result<Vec<u8>>;
    /// Creates a segment holding `bytes` (the magic).
    fn create(&mut self, id: SegmentId, bytes: &[u8]) -> io::Result<()>;
    /// Appends to a segment.
    fn append(&mut self, id: SegmentId, bytes: &[u8]) -> io::Result<()>;
    /// Makes everything appended to a segment durable.
    fn sync(&mut self, id: SegmentId) -> io::Result<()>;
    /// Cuts a segment to `len` bytes, durably.
    fn truncate(&mut self, id: SegmentId, len: u64) -> io::Result<()>;
    /// Deletes a segment. A missing one is not an error.
    fn remove(&mut self, id: SegmentId) -> io::Result<()>;
    /// The state record, if there is one.
    fn read_state(&mut self) -> io::Result<Option<Vec<u8>>>;
    /// Replaces the state record, durably and atomically.
    fn write_state(&mut self, bytes: &[u8]) -> io::Result<()>;
}

/// Segments as files in one directory, which the installer creates and
/// restricts to SYSTEM (#183, #220).
#[derive(Debug)]
pub struct FileStorage {
    dir: PathBuf,
    /// The segment last appended to, kept open.
    open: Option<(SegmentId, File)>,
}

impl FileStorage {
    /// The name of the state file.
    pub const STATE: &'static str = "spool.state";

    /// Storage in `dir`, which is created if missing.
    ///
    /// # Errors
    ///
    /// The directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir, open: None })
    }

    /// The directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: SegmentId) -> PathBuf {
        self.dir.join(id.file_name())
    }

    fn handle(&mut self, id: SegmentId) -> io::Result<&mut File> {
        if self.open.as_ref().is_none_or(|(open, _)| *open != id) {
            let file = OpenOptions::new().append(true).open(self.path(id))?;
            self.open = Some((id, file));
        }
        match &mut self.open {
            Some((_, file)) => Ok(file),
            None => Err(io::Error::other("no open segment")),
        }
    }

    fn close(&mut self, id: SegmentId) {
        if self.open.as_ref().is_some_and(|(open, _)| *open == id) {
            self.open = None;
        }
    }
}

fn read_limited(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    match File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(limit).read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

impl Storage for FileStorage {
    fn list(&mut self) -> io::Result<Vec<SegmentId>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            if let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(SegmentId::from_file_name)
            {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    fn read(&mut self, id: SegmentId) -> io::Result<Vec<u8>> {
        read_limited(&self.path(id), MAX_SEGMENT_READ)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, id.file_name()))
    }

    fn create(&mut self, id: SegmentId, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path(id))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        sync_dir(&self.dir);
        self.close(id);
        Ok(())
    }

    fn append(&mut self, id: SegmentId, bytes: &[u8]) -> io::Result<()> {
        self.handle(id)?.write_all(bytes)
    }

    fn sync(&mut self, id: SegmentId) -> io::Result<()> {
        self.handle(id)?.sync_data()
    }

    fn truncate(&mut self, id: SegmentId, len: u64) -> io::Result<()> {
        self.close(id);
        let file = OpenOptions::new().write(true).open(self.path(id))?;
        file.set_len(len)?;
        file.sync_all()
    }

    fn remove(&mut self, id: SegmentId) -> io::Result<()> {
        self.close(id);
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn read_state(&mut self) -> io::Result<Option<Vec<u8>>> {
        read_limited(&self.dir.join(Self::STATE), MAX_STATE_READ)
    }

    fn write_state(&mut self, bytes: &[u8]) -> io::Result<()> {
        let temp = self.dir.join("spool.state.tmp");
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, self.dir.join(Self::STATE))?;
        sync_dir(&self.dir);
        Ok(())
    }
}

/// Makes a directory's entries durable where the OS allows it. Windows
/// cannot open a directory this way; there, `MoveFileEx` with
/// write-through gives the same guarantee for renames, and creations
/// become durable with the file's own flush.
fn sync_dir(dir: &Path) {
    if cfg!(unix)
        && let Ok(d) = File::open(dir)
    {
        let _ = d.sync_all();
    }
}

#[derive(Debug, Default)]
struct MemoryInner {
    /// Each segment's bytes, and how many of them are durable.
    files: BTreeMap<SegmentId, (Vec<u8>, usize)>,
    state: Option<Vec<u8>>,
    /// Fail every write from now on, as a full disk would.
    fail_writes: bool,
}

/// Segments in memory. Clones share the same files, so a test can keep a
/// handle, simulate a crash with [`MemoryStorage::crash`] and open a new
/// spool on what is left.
#[derive(Clone, Debug, Default)]
pub struct MemoryStorage(Arc<Mutex<MemoryInner>>);

impl MemoryStorage {
    fn inner(&self) -> std::sync::MutexGuard<'_, MemoryInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Simulates a crash: each segment keeps its durable bytes and
    /// `keep(unsynced)` of the bytes after them.
    pub fn crash(&self, mut keep: impl FnMut(usize) -> usize) {
        for (bytes, durable) in self.inner().files.values_mut() {
            let unsynced = bytes.len().saturating_sub(*durable);
            let len = *durable + keep(unsynced).min(unsynced);
            bytes.truncate(len);
            *durable = len;
        }
    }

    /// Makes every write fail from now on (`true`), as a full disk would,
    /// or succeed again.
    pub fn fail_writes(&self, fail: bool) {
        self.inner().fail_writes = fail;
    }

    /// Changes the stored bytes of a segment, for tests of damaged files.
    pub fn corrupt(&self, id: SegmentId, edit: impl FnOnce(&mut Vec<u8>)) {
        if let Some((bytes, durable)) = self.inner().files.get_mut(&id) {
            edit(bytes);
            *durable = (*durable).min(bytes.len());
        }
    }

    /// Replaces the state record, for tests of a damaged state.
    pub fn set_state(&self, state: Option<Vec<u8>>) {
        self.inner().state = state;
    }

    /// Every segment there is, in order.
    #[must_use]
    pub fn list_ids(&self) -> Vec<SegmentId> {
        self.inner().files.keys().copied().collect()
    }

    /// The bytes stored in all segments.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.inner().files.values().map(|(b, _)| b.len()).sum()
    }
}

fn full() -> io::Error {
    io::Error::new(io::ErrorKind::StorageFull, "simulated full disk")
}

fn missing(id: SegmentId) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, id.file_name())
}

impl Storage for MemoryStorage {
    fn list(&mut self) -> io::Result<Vec<SegmentId>> {
        Ok(self.inner().files.keys().copied().collect())
    }

    fn read(&mut self, id: SegmentId) -> io::Result<Vec<u8>> {
        let inner = self.inner();
        let (bytes, _) = inner.files.get(&id).ok_or_else(|| missing(id))?;
        let limit = usize::try_from(MAX_SEGMENT_READ).unwrap_or(usize::MAX);
        Ok(bytes.get(..limit).unwrap_or(bytes).to_vec())
    }

    fn create(&mut self, id: SegmentId, bytes: &[u8]) -> io::Result<()> {
        let mut inner = self.inner();
        if inner.fail_writes {
            return Err(full());
        }
        if inner.files.contains_key(&id) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, id.file_name()));
        }
        inner.files.insert(id, (bytes.to_vec(), bytes.len()));
        Ok(())
    }

    fn append(&mut self, id: SegmentId, bytes: &[u8]) -> io::Result<()> {
        let mut inner = self.inner();
        if inner.fail_writes {
            return Err(full());
        }
        let (file, _) = inner.files.get_mut(&id).ok_or_else(|| missing(id))?;
        file.extend_from_slice(bytes);
        Ok(())
    }

    fn sync(&mut self, id: SegmentId) -> io::Result<()> {
        let mut inner = self.inner();
        let (file, durable) = inner.files.get_mut(&id).ok_or_else(|| missing(id))?;
        *durable = file.len();
        Ok(())
    }

    fn truncate(&mut self, id: SegmentId, len: u64) -> io::Result<()> {
        let mut inner = self.inner();
        let (file, durable) = inner.files.get_mut(&id).ok_or_else(|| missing(id))?;
        file.truncate(usize::try_from(len).unwrap_or(usize::MAX));
        *durable = file.len();
        Ok(())
    }

    fn remove(&mut self, id: SegmentId) -> io::Result<()> {
        self.inner().files.remove(&id);
        Ok(())
    }

    fn read_state(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inner().state.clone())
    }

    fn write_state(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut inner = self.inner();
        if inner.fail_writes {
            return Err(full());
        }
        inner.state = Some(bytes.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("palisade-agent-spool-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const ID: SegmentId = SegmentId {
        class: Class::Blocked,
        first_seq: 42,
    };

    #[test]
    fn file_names_round_trip_and_reject_strangers() {
        assert_eq!(ID.file_name(), "blocked-00000000000000000042.seg");
        assert_eq!(SegmentId::from_file_name(&ID.file_name()), Some(ID));
        for bad in [
            "blocked-42.seg",
            "blocked-0000000000000000004x.seg",
            "nope-00000000000000000042.seg",
            "blocked-00000000000000000042.tmp",
            "blocked00000000000000000042.seg",
            "blocked-99999999999999999999.seg",
        ] {
            assert_eq!(SegmentId::from_file_name(bad), None, "{bad}");
        }
    }

    fn exercise(storage: &mut dyn Storage) {
        assert!(storage.list().unwrap().is_empty());
        assert_eq!(storage.read_state().unwrap(), None);
        storage.create(ID, b"magic").unwrap();
        assert!(storage.create(ID, b"again").is_err());
        storage.append(ID, b"-one").unwrap();
        storage.append(ID, b"-two").unwrap();
        storage.sync(ID).unwrap();
        assert_eq!(storage.read(ID).unwrap(), b"magic-one-two");
        storage.truncate(ID, 9).unwrap();
        assert_eq!(storage.read(ID).unwrap(), b"magic-one");
        storage.append(ID, b"!").unwrap();
        assert_eq!(storage.read(ID).unwrap(), b"magic-one!");
        assert_eq!(storage.list().unwrap(), [ID]);
        storage.write_state(b"s1").unwrap();
        storage.write_state(b"s2").unwrap();
        assert_eq!(storage.read_state().unwrap().as_deref(), Some(&b"s2"[..]));
        storage.remove(ID).unwrap();
        storage.remove(ID).unwrap();
        assert!(storage.read(ID).is_err());
        assert!(storage.append(ID, b"x").is_err());
        assert!(storage.list().unwrap().is_empty());
    }

    #[test]
    fn file_storage_works() {
        let dir = TempDir::new("files");
        let mut storage = FileStorage::open(&dir.0).unwrap();
        assert_eq!(storage.dir(), dir.0);
        // Files that are not segments are left alone.
        fs::write(dir.0.join("notes.txt"), b"x").unwrap();
        fs::create_dir(dir.0.join("info-00000000000000000001.seg")).unwrap();
        exercise(&mut storage);
        assert!(dir.0.join("notes.txt").exists());
    }

    #[test]
    fn memory_storage_works_and_simulates_crashes_and_full_disks() {
        let mut storage = MemoryStorage::default();
        exercise(&mut storage);
        let handle = storage.clone();
        storage.create(ID, b"abc").unwrap();
        storage.append(ID, b"defgh").unwrap();
        handle.crash(|unsynced| unsynced - 2);
        assert_eq!(storage.read(ID).unwrap(), b"abcdef");
        assert_eq!(handle.stored_bytes(), 6);
        handle.corrupt(ID, |b| b[0] = b'X');
        assert_eq!(storage.read(ID).unwrap(), b"Xbcdef");
        handle.set_state(Some(b"state".to_vec()));
        assert_eq!(
            storage.read_state().unwrap().as_deref(),
            Some(&b"state"[..])
        );
        handle.fail_writes(true);
        assert_eq!(
            storage.append(ID, b"x").unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert!(
            storage
                .create(SegmentId { first_seq: 1, ..ID }, b"x")
                .is_err()
        );
        assert!(storage.write_state(b"x").is_err());
        handle.fail_writes(false);
        storage.append(ID, b"x").unwrap();
        let other = SegmentId { first_seq: 7, ..ID };
        assert!(storage.sync(other).is_err());
        assert!(storage.truncate(other, 0).is_err());
    }
}
