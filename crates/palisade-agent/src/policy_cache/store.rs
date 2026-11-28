//! The policy cache on disk (ADR 0007): the `active`, `previous` and
//! `pending` files under the agent's store directory, and the copies of the
//! anti-rollback record.
//!
//! Every write goes to a temporary file that is flushed to disk, then
//! renamed over its target. On Windows the rename is `MoveFileExW` with
//! `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`, so it is durable
//! before the call returns. Elsewhere it is `rename(2)` followed by a flush
//! of the directory. A power loss therefore leaves either the old file or
//! the new one, never a torn file.
//!
//! The directory must be SYSTEM-only (#220); the installer creates it. The
//! files are authenticated by their signatures, not by their permissions.
//! With a [`Sealer`] (#326) each cache file is sealed with AES-256-GCM
//! under a data key whose keyring is protected by machine-scope DPAPI; the
//! opened bytes are still the signed envelope, verified as before.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use std::sync::{Arc, Mutex};

use palisade_policy::bundle::format::DEFAULT_MAX_BYTES;
use palisade_proto::policy_bundle::{
    at_rest::{self, KeyRing},
    record::SEALED_LEN_WITH_FALLBACK,
    select::CacheFile,
};

use super::protect::{KEYRING_PURPOSE, Protector, RECORD_PURPOSE};

/// The largest cache file the agent reads: the 64 MiB bundle limit (#225)
/// plus 1 MiB for the envelope around it. A larger file is not read at all
/// and counts as unreadable.
pub const MAX_FILE_BYTES: u64 = DEFAULT_MAX_BYTES as u64 + (1 << 20);

/// The largest sealed keyring or protected record copy read: far above
/// what DPAPI makes of either.
const MAX_SECRET_BYTES: u64 = 16 * 1024;

/// The `active`, `previous` and `pending` files in one directory.
#[derive(Debug, Clone)]
pub struct PolicyStore {
    dir: PathBuf,
    sealer: Option<Arc<Sealer>>,
}

impl PolicyStore {
    /// The store in `dir`, which is created if it does not exist.
    ///
    /// # Errors
    ///
    /// The I/O error if the directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir, sealer: None })
    }

    /// The same store, sealing every cache file it writes and opening every
    /// one it reads with `sealer` (#326). A file that does not open reads
    /// as [`io::ErrorKind::InvalidData`], which the cache treats as
    /// unreadable, never as trusted.
    #[must_use]
    pub fn sealed(mut self, sealer: Arc<Sealer>) -> Self {
        self.sealer = Some(sealer);
        self
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The path of a cache file.
    pub fn path(&self, file: CacheFile) -> PathBuf {
        self.dir.join(match file {
            CacheFile::Active => "active",
            CacheFile::Previous => "previous",
            CacheFile::Pending => "pending",
        })
    }

    /// Reads a whole cache file into memory, up to [`MAX_FILE_BYTES`].
    /// `Ok(None)` if it does not exist.
    ///
    /// # Errors
    ///
    /// The I/O error, or [`io::ErrorKind::InvalidData`] for a file over the
    /// limit.
    pub fn read(&self, file: CacheFile) -> io::Result<Option<Vec<u8>>> {
        let limit = MAX_FILE_BYTES.saturating_add(at_rest::OVERHEAD as u64);
        let Some(bytes) = read_limited(&self.path(file), limit)? else {
            return Ok(None);
        };
        match &self.sealer {
            None => Ok(Some(bytes)),
            Some(sealer) => sealer.open_file(&bytes).map(Some),
        }
    }

    /// Replaces a cache file with `bytes`, durably.
    ///
    /// # Errors
    ///
    /// The I/O error. The old file, if any, is then unchanged.
    pub fn write(&self, file: CacheFile, bytes: &[u8]) -> io::Result<()> {
        match &self.sealer {
            None => write_atomic(&self.dir, &self.path(file), bytes),
            Some(sealer) => write_atomic(&self.dir, &self.path(file), &sealer.seal(bytes)?),
        }
    }

    /// Renames `pending` over `active`, durably (ADR 0007 step 4).
    ///
    /// # Errors
    ///
    /// The I/O error. `active` is then unchanged.
    pub fn promote_pending(&self) -> io::Result<()> {
        replace_durably(
            &self.path(CacheFile::Pending),
            &self.path(CacheFile::Active),
            &self.dir,
        )
    }

    /// Deletes a cache file. A file that does not exist is not an error.
    ///
    /// # Errors
    ///
    /// Any other I/O error.
    pub fn remove(&self, file: CacheFile) -> io::Result<()> {
        match fs::remove_file(self.path(file)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

/// Seals and opens cache files under the data keyring (#326, ADR 0017).
///
/// The keyring lives in `keyring` next to the cache files, protected by a
/// [`Protector`] (machine-scope DPAPI on Windows). Before each seal the
/// seal count is raised and the protected keyring written durably, so the
/// persisted count is never below the seals made. A keyring that is missing
/// or does not unprotect or decode is replaced by a new one: files sealed
/// under the old one no longer open and count as unreadable, so the cache
/// falls back as for any corrupt file (ADR 0018), and never trusts them.
#[derive(Debug)]
pub struct Sealer {
    path: PathBuf,
    dir: PathBuf,
    protector: Box<dyn Protector>,
    ring: Mutex<KeyRing>,
}

impl Sealer {
    /// The keyring in `dir/keyring`, read or created.
    ///
    /// # Errors
    ///
    /// The I/O error if a new keyring cannot be written, or the secure
    /// random source fails.
    pub fn open(dir: impl Into<PathBuf>, protector: Box<dyn Protector>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let path = dir.join("keyring");
        let existing = read_limited(&path, MAX_SECRET_BYTES)
            .ok()
            .flatten()
            .and_then(|b| protector.unprotect(&b, KEYRING_PURPOSE).ok())
            .and_then(|b| KeyRing::decode(&b).ok());
        let fresh = existing.is_none();
        let ring = match existing {
            Some(ring) => ring,
            None => KeyRing::generate().map_err(io::Error::other)?,
        };
        let sealer = Self {
            path,
            dir,
            protector,
            ring: Mutex::new(ring),
        };
        if fresh {
            tracing::warn!(
                "the policy cache keyring was missing or unreadable; a new one was made"
            );
            let ring = sealer.ring();
            sealer.persist(&ring)?;
        }
        Ok(sealer)
    }

    fn ring(&self) -> std::sync::MutexGuard<'_, KeyRing> {
        self.ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn persist(&self, ring: &KeyRing) -> io::Result<()> {
        let blob = self.protector.protect(&ring.encode(), KEYRING_PURPOSE)?;
        write_atomic(&self.dir, &self.path, &blob)
    }

    /// Seals `plaintext`: reserves a seal, persists the keyring, then
    /// seals.
    ///
    /// # Errors
    ///
    /// The I/O error if the keyring cannot be persisted (nothing is then
    /// sealed), or the secure random source fails.
    pub fn seal(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut ring = self.ring();
        ring.reserve().map_err(io::Error::other)?;
        self.persist(&ring)?;
        ring.seal(plaintext).map_err(io::Error::other)
    }

    /// Opens a sealed file.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidData`] for a file that does not open.
    pub fn open_file(&self, sealed: &[u8]) -> io::Result<Vec<u8>> {
        self.ring()
            .open(sealed)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Where the copies of the anti-rollback record are kept.
///
/// #225 asks for copies in separate stores (a DPAPI-protected file and a
/// registry mirror, later a TPM-sealed blob), so that replacing one is
/// detected by the others. [`ProtectedRecordStore`] keeps them (#326);
/// [`FileRecordStore`] keeps two plain files, for tests.
pub trait RecordStore: Send + Sync + fmt::Debug {
    /// Every copy, always in the same order. `None` for a copy that does not
    /// exist. A copy that exists but cannot be read is returned as empty
    /// bytes, which never unseal, so it counts as corrupt rather than
    /// missing.
    fn read(&self) -> Vec<Option<Vec<u8>>>;

    /// Writes `sealed` to every copy, trying them all.
    ///
    /// # Errors
    ///
    /// The first I/O error. Some copies may then hold the new value and
    /// some the old: startup tells that apart from tampering
    /// ([`RecordCopies::interrupted_activation`](palisade_proto::policy_bundle::record::RecordCopies::interrupted_activation)).
    fn write(&self, sealed: &[u8]) -> io::Result<()>;
}

/// Two record copies as files, `record.1` and `record.2`, in a directory.
/// A stand-in for #326's separate stores.
#[derive(Debug, Clone)]
pub struct FileRecordStore {
    dir: PathBuf,
}

impl FileRecordStore {
    const NAMES: [&'static str; 2] = ["record.1", "record.2"];

    /// The copies in `dir`, which is created if it does not exist.
    ///
    /// # Errors
    ///
    /// The I/O error if the directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
}

impl RecordStore for FileRecordStore {
    fn read(&self) -> Vec<Option<Vec<u8>>> {
        Self::NAMES
            .iter()
            .map(|name| {
                // One byte over the longest copy is enough to tell that a
                // copy is too long.
                read_limited(&self.dir.join(name), SEALED_LEN_WITH_FALLBACK as u64)
                    .unwrap_or_else(|_| Some(Vec::new()))
            })
            .collect()
    }

    fn write(&self, sealed: &[u8]) -> io::Result<()> {
        let mut first = Ok(());
        for name in Self::NAMES {
            let result = write_atomic(&self.dir, &self.dir.join(name), sealed);
            if first.is_ok() {
                first = result;
            }
        }
        first
    }
}

/// One place a record copy is kept: a file, a registry value, later a TPM
/// blob. Each holds opaque bytes.
pub trait RecordSlot: Send + Sync + fmt::Debug {
    /// The bytes, `Ok(None)` if absent.
    ///
    /// # Errors
    ///
    /// The I/O error for a copy that exists but cannot be read.
    fn read(&self) -> io::Result<Option<Vec<u8>>>;

    /// Replaces the bytes, durably.
    ///
    /// # Errors
    ///
    /// The I/O error.
    fn write(&self, bytes: &[u8]) -> io::Result<()>;
}

/// A record copy in a file, written atomically.
#[derive(Debug, Clone)]
pub struct FileSlot {
    path: PathBuf,
}

impl FileSlot {
    /// The copy at `path`. Its directory is created if it does not exist.
    ///
    /// # Errors
    ///
    /// The I/O error if the directory cannot be created.
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        Ok(Self { path })
    }
}

impl RecordSlot for FileSlot {
    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        read_limited(&self.path, MAX_SECRET_BYTES)
    }

    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        write_atomic(dir, &self.path, bytes)
    }
}

/// A record copy in a `REG_BINARY` value under `HKEY_LOCAL_MACHINE`. The
/// key must be writable by SYSTEM only (#220).
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct RegistrySlot {
    key: String,
    value: String,
}

#[cfg(windows)]
impl RegistrySlot {
    /// The value `value` under `HKEY_LOCAL_MACHINE\<key>`.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// A registry error as an I/O error.
#[cfg(windows)]
fn reg(e: impl fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(windows)]
impl RecordSlot for RegistrySlot {
    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        // `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`.
        const NOT_FOUND: i32 = 0x8007_0002_u32.cast_signed();
        let key = match windows_registry::LOCAL_MACHINE.open(&self.key) {
            Ok(key) => key,
            Err(e) if e.code().0 == NOT_FOUND => return Ok(None),
            Err(e) => return Err(reg(e)),
        };
        match key.get_value(&self.value) {
            Ok(v) if v.ty() == windows_registry::Type::Bytes => {
                if v.len() as u64 > MAX_SECRET_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "record copy too long",
                    ));
                }
                Ok(Some(v.to_vec()))
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "record copy is not REG_BINARY",
            )),
            Err(e) if e.code().0 == NOT_FOUND => Ok(None),
            Err(e) => Err(reg(e)),
        }
    }

    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        windows_registry::LOCAL_MACHINE
            .create(&self.key)
            .map_err(reg)?
            .set_bytes(&self.value, windows_registry::Type::Bytes, bytes)
            .map_err(reg)
    }
}

/// The anti-rollback record copies, each protected by a [`Protector`]
/// (machine-scope DPAPI) and kept in its own [`RecordSlot`] (#326): a file
/// next to the cache and a registry mirror on Windows. A copy that does
/// not unprotect reads as corrupt, never as missing, so replacing or
/// damaging one is reported (`tamper.policy.rollback_suspected`).
#[derive(Debug)]
pub struct ProtectedRecordStore {
    slots: Vec<Box<dyn RecordSlot>>,
    protector: Box<dyn Protector>,
}

impl ProtectedRecordStore {
    /// Copies in `slots`, in this order, protected by `protector`.
    pub fn new(slots: Vec<Box<dyn RecordSlot>>, protector: Box<dyn Protector>) -> Self {
        Self { slots, protector }
    }

    /// The agent's copies on Windows: `dir/record` and the registry value
    /// `PolicyRecord` under `HKLM\<key>`, protected by DPAPI.
    ///
    /// # Errors
    ///
    /// The I/O error if `dir` cannot be created.
    #[cfg(windows)]
    pub fn windows(dir: &Path, key: &str) -> io::Result<Self> {
        Ok(Self::new(
            vec![
                Box::new(FileSlot::new(dir.join("record"))?),
                Box::new(RegistrySlot::new(key, "PolicyRecord")),
            ],
            super::protect::platform(),
        ))
    }
}

impl RecordStore for ProtectedRecordStore {
    fn read(&self) -> Vec<Option<Vec<u8>>> {
        self.slots
            .iter()
            .map(|slot| match slot.read() {
                Ok(None) => None,
                Ok(Some(blob)) => Some(
                    self.protector
                        .unprotect(&blob, RECORD_PURPOSE)
                        .unwrap_or_default(),
                ),
                // Exists but cannot be read: corrupt, not missing.
                Err(_) => Some(Vec::new()),
            })
            .collect()
    }

    fn write(&self, sealed: &[u8]) -> io::Result<()> {
        let blob = self.protector.protect(sealed, RECORD_PURPOSE)?;
        let mut first = Ok(());
        for slot in &self.slots {
            let result = slot.write(&blob);
            if first.is_ok() {
                first = result;
            }
        }
        first
    }
}

/// Reads at most `limit` bytes of `path`. `Ok(None)` if it does not exist.
fn read_limited(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is over the {limit}-byte limit", path.display()),
        ));
    }
    Ok(Some(bytes))
}

/// Writes `bytes` to `<path>.tmp`, flushes it, then renames it over `path`.
fn write_atomic(dir: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    replace_durably(&tmp, path, dir)
}

/// Renames `from` over `to`, and returns once the rename is on disk.
#[cfg(windows)]
fn replace_durably(from: &Path, to: &Path, _dir: &Path) -> io::Result<()> {
    crate::ffi::replace_file_durably(from, to)
}

/// Renames `from` over `to`, and returns once the rename is on disk.
#[cfg(not(windows))]
fn replace_durably(from: &Path, to: &Path, dir: &Path) -> io::Result<()> {
    fs::rename(from, to)?;
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_limited_refuses_a_file_over_the_limit() {
        let dir = super::super::tests::TempDir::new("limit");
        let path = dir.path().join("f");
        fs::write(&path, [0_u8; 5]).unwrap();
        assert_eq!(read_limited(&path, 5).unwrap().unwrap().len(), 5);
        let err = read_limited(&path, 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            read_limited(&dir.path().join("missing"), 4)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn writes_replace_and_leave_no_temporary_file() {
        let dir = super::super::tests::TempDir::new("write");
        let store = PolicyStore::open(dir.path().join("policy")).unwrap();
        store.write(CacheFile::Pending, b"one").unwrap();
        store.write(CacheFile::Pending, b"two").unwrap();
        store.promote_pending().unwrap();
        assert_eq!(store.read(CacheFile::Active).unwrap().unwrap(), b"two");
        assert!(store.read(CacheFile::Pending).unwrap().is_none());
        let names: Vec<_> = fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["active"]);
        store.remove(CacheFile::Active).unwrap();
        store.remove(CacheFile::Active).unwrap();
        assert!(store.read(CacheFile::Active).unwrap().is_none());
    }

    fn memory() -> Box<dyn Protector> {
        Box::new(super::super::protect::MemoryProtector::new().unwrap())
    }

    #[test]
    fn a_sealed_store_round_trips_and_never_writes_plaintext() {
        let dir = super::super::tests::TempDir::new("sealed");
        let sealer = Arc::new(Sealer::open(dir.path(), memory()).unwrap());
        let store = PolicyStore::open(dir.path().join("policy"))
            .unwrap()
            .sealed(Arc::clone(&sealer));
        store.write(CacheFile::Pending, b"envelope").unwrap();
        let raw = fs::read(store.path(CacheFile::Pending)).unwrap();
        assert!(at_rest::looks_sealed(&raw));
        assert!(!raw.windows(8).any(|w| w == b"envelope"));
        assert_eq!(
            store.read(CacheFile::Pending).unwrap().unwrap(),
            b"envelope"
        );
        store.promote_pending().unwrap();
        assert_eq!(store.read(CacheFile::Active).unwrap().unwrap(), b"envelope");
        assert_eq!(
            sealer
                .open_file(&fs::read(store.path(CacheFile::Active)).unwrap())
                .unwrap(),
            b"envelope"
        );

        // A plaintext or damaged file does not open: invalid data.
        fs::write(store.path(CacheFile::Previous), b"envelope").unwrap();
        assert_eq!(
            store.read(CacheFile::Previous).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(store.read(CacheFile::Pending).unwrap().is_none());
    }

    #[test]
    fn the_keyring_persists_its_seal_count_before_each_seal() {
        let dir = super::super::tests::TempDir::new("keyring");
        let protector = std::sync::Arc::new(super::super::protect::MemoryProtector::new().unwrap());
        #[derive(Debug)]
        struct Shared(std::sync::Arc<super::super::protect::MemoryProtector>);
        impl Protector for Shared {
            fn protect(&self, d: &[u8], p: &[u8]) -> io::Result<Vec<u8>> {
                self.0.protect(d, p)
            }
            fn unprotect(&self, d: &[u8], p: &[u8]) -> io::Result<Vec<u8>> {
                self.0.unprotect(d, p)
            }
        }
        let sealer = Sealer::open(dir.path(), Box::new(Shared(protector.clone()))).unwrap();
        let first = sealer.seal(b"one").unwrap();
        sealer.seal(b"two").unwrap();
        let read_count = || {
            let blob = fs::read(dir.path().join("keyring")).unwrap();
            KeyRing::decode(&protector.unprotect(&blob, KEYRING_PURPOSE).unwrap())
                .unwrap()
                .seals()
        };
        assert_eq!(read_count(), 2);
        // Reopened with the same protector: the same key, so old files open.
        let again = Sealer::open(dir.path(), Box::new(Shared(protector.clone()))).unwrap();
        assert_eq!(again.open_file(&first).unwrap(), b"one");
        again.seal(b"three").unwrap();
        assert_eq!(read_count(), 3);

        // A keyring that does not unprotect (another machine, or replaced)
        // is replaced: old files no longer open.
        let replaced = Sealer::open(dir.path(), memory()).unwrap();
        assert!(replaced.open_file(&first).is_err());

        // A keyring that cannot be persisted refuses to seal.
        let ro = super::super::tests::TempDir::new("keyring-ro");
        let s = Sealer::open(ro.path(), memory()).unwrap();
        fs::remove_file(ro.path().join("keyring")).unwrap();
        fs::create_dir(ro.path().join("keyring")).unwrap();
        fs::write(ro.path().join("keyring").join("x"), b"x").unwrap();
        assert!(s.seal(b"x").is_err());
    }

    #[test]
    fn protected_record_copies_read_back_and_damage_reads_as_corrupt() {
        let dir = super::super::tests::TempDir::new("protected-records");
        let slots: Vec<Box<dyn RecordSlot>> = vec![
            Box::new(FileSlot::new(dir.path().join("a/record")).unwrap()),
            Box::new(FileSlot::new(dir.path().join("b/record")).unwrap()),
        ];
        let store = ProtectedRecordStore::new(slots, memory());
        assert_eq!(store.read(), [None, None]);
        store.write(b"sealed").unwrap();
        assert_eq!(
            store.read(),
            [Some(b"sealed".to_vec()), Some(b"sealed".to_vec())]
        );
        let raw = fs::read(dir.path().join("a/record")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"sealed"));
        // A copy replaced with one from elsewhere, or garbage, is corrupt.
        fs::write(dir.path().join("b/record"), b"sealed").unwrap();
        assert_eq!(store.read()[1], Some(Vec::new()));
        // One that cannot be read is corrupt too; the write still reaches
        // the other and reports the failure.
        fs::remove_file(dir.path().join("b/record")).unwrap();
        fs::create_dir(dir.path().join("b/record")).unwrap();
        fs::write(dir.path().join("b/record/x"), b"x").unwrap();
        assert_eq!(store.read()[1], Some(Vec::new()));
        assert!(store.write(b"next").is_err());
        assert_eq!(store.read()[0], Some(b"next".to_vec()));
        // A slot path with no parent still works.
        assert!(FileSlot::new("relative-record").is_ok());
    }

    #[test]
    fn a_record_copy_that_cannot_be_read_counts_as_corrupt() {
        let dir = super::super::tests::TempDir::new("records");
        let records = FileRecordStore::open(dir.path()).unwrap();
        assert_eq!(records.read(), [None, None]);
        records.write(b"sealed").unwrap();
        assert_eq!(
            records.read(),
            [Some(b"sealed".to_vec()), Some(b"sealed".to_vec())]
        );
        // A directory where a copy should be cannot be read as a file.
        fs::remove_file(dir.path().join("record.2")).unwrap();
        fs::create_dir(dir.path().join("record.2")).unwrap();
        assert_eq!(records.read(), [Some(b"sealed".to_vec()), Some(Vec::new())]);
        // The write still reaches the first copy, and reports the failure.
        assert!(records.write(b"next").is_err());
        assert_eq!(records.read()[0], Some(b"next".to_vec()));
    }
}
