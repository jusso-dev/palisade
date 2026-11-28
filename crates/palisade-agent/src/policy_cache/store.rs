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
//! Encryption at rest is #326.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use palisade_policy::bundle::format::DEFAULT_MAX_BYTES;
use palisade_proto::policy_bundle::{record::SEALED_LEN_WITH_FALLBACK, select::CacheFile};

/// The largest cache file the agent reads: the 64 MiB bundle limit (#225)
/// plus 1 MiB for the envelope around it. A larger file is not read at all
/// and counts as unreadable.
pub const MAX_FILE_BYTES: u64 = DEFAULT_MAX_BYTES as u64 + (1 << 20);

/// The `active`, `previous` and `pending` files in one directory.
#[derive(Debug, Clone)]
pub struct PolicyStore {
    dir: PathBuf,
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
        Ok(Self { dir })
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
        read_limited(&self.path(file), MAX_FILE_BYTES)
    }

    /// Replaces a cache file with `bytes`, durably.
    ///
    /// # Errors
    ///
    /// The I/O error. The old file, if any, is then unchanged.
    pub fn write(&self, file: CacheFile, bytes: &[u8]) -> io::Result<()> {
        write_atomic(&self.dir, &self.path(file), bytes)
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

/// Where the copies of the anti-rollback record are kept.
///
/// #225 asks for copies in separate stores (a DPAPI-protected file and a
/// registry mirror, later a TPM-sealed blob), so that replacing one is
/// detected by the others. That is #326; [`FileRecordStore`] keeps two
/// files until it lands.
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
