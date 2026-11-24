//! The hash cache (#46): digests reused while a file is unchanged.
//!
//! An agent must not rehash a file at every launch. [`HashCache`] keeps the
//! digests of each file under its [`FileKey`], and gives them back only
//! while the file's current key is the same. Any change to a key component
//! is a miss, and the stale entry is dropped.
//!
//! # What is cached
//!
//! A [`CacheValue`] holds the results by computation tier, each with its own
//! version: the flat hashes ([`FlatTier`]) and the Authenticode image digests
//! ([`ImageTier`]). When this library changes how a tier is computed, its
//! version constant ([`FLAT_TIER_VERSION`], [`IMAGE_TIER_VERSION`]) goes up,
//! and cached tiers of an older version are ignored: only the affected tier
//! is recomputed. The value also records the library version that computed
//! it, the file-type classifier version (#44) and when it was computed.
//!
//! # Memory bounds
//!
//! The cache is an LRU bounded by entries and by bytes ([`CacheConfig`];
//! defaults 1,000,000 entries and 256 MiB). Inserting past either bound
//! evicts the least recently used entries first.
//!
//! # Persisted records and tampering
//!
//! The agent persists the cache in its local store (#61, ADR 0007). Records
//! leave memory only through [`HashCache::export`] and come back only
//! through [`HashCache::import`], as [`CacheRecord`]s encoded with
//! [`CacheRecord::encode`]. Each carries an HMAC-SHA-256 tag (ADR 0008) over
//! every byte, keyed with an agent-held [`MacKey`] (#18). A record whose tag
//! does not verify is discarded and counted as a tamper event
//! ([`super::HashMetricsSnapshot::tamper_events`]); the file is simply hashed
//! again, so a tampered store can never turn a deny into an allow. The key
//! inside the record is covered by the tag, so a valid record cannot be
//! moved onto another file, and an old record for the same file carries an
//! old change stamp, so it misses.
//!
//! # Verify-on-launch
//!
//! [`HashVerifyMode`] is the policy setting that says when a cached digest
//! may be used at execution time. [`hash_through`] puts it all together: it
//! stamps the file, uses the cache when allowed, otherwise hashes, checks
//! the file did not change while it was read (retrying up to
//! [`MAX_UNSTABLE_RETRIES`] times, then [`Through::Unstable`]), and caches
//! the result.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Mutex;
use std::time::Instant;

use super::mac::{MAC_LEN, MacKey};
use super::metrics::HashMetrics;
use super::stamp::{FileKey, FileStamp, FileTime};
use super::{Digest, FlatHashes, HashAlgorithm};
use crate::fsctx::LocationClass;

/// The version of the flat-hash tier. Raised when the flat hashes are
/// computed differently, which invalidates every cached flat tier.
pub const FLAT_TIER_VERSION: u32 = 1;
/// The version of the Authenticode image-digest tier.
pub const IMAGE_TIER_VERSION: u32 = 1;
/// This library's version, recorded with every value.
pub const FILEID_LIB_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default [`CacheConfig::max_entries`].
pub const DEFAULT_MAX_ENTRIES: usize = 1_000_000;
/// Default [`CacheConfig::max_bytes`]: 256 MiB.
pub const DEFAULT_MAX_BYTES: usize = 256 * 1024 * 1024;
/// How many times [`hash_through`] rehashes a file that changed while it was
/// read, before it gives up with [`Through::Unstable`].
pub const MAX_UNSTABLE_RETRIES: u32 = 3;

/// The longest path a record may hold, in bytes (32,767 UTF-16 units, at
/// most three UTF-8 bytes each).
const MAX_RECORD_PATH: usize = 32_767 * 3;
/// Record magic and format version.
const RECORD_MAGIC: &[u8; 4] = b"PHC1";
const RECORD_FORMAT: u8 = 1;
/// Fixed per-entry overhead counted against [`CacheConfig::max_bytes`].
const ENTRY_OVERHEAD: usize = 96;

/// The flat hashes of a file, as cached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatTier {
    /// The tier version that computed them ([`FLAT_TIER_VERSION`]).
    pub version: u32,
    /// The digests.
    pub hashes: FlatHashes,
}

/// The Authenticode image digests of a PE file, as cached (#47).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageTier {
    /// The tier version that computed them ([`IMAGE_TIER_VERSION`]).
    pub version: u32,
    /// The image digests, in [`HashAlgorithm::ALL`] order.
    pub digests: Vec<Digest>,
    /// Whether the image layout was Authenticode-conformant. When it was
    /// not, the flat hash is the identity (#55).
    pub conformant: bool,
}

impl ImageTier {
    /// The tier for the Authenticode `hashes` of an image, at the current
    /// tier version.
    #[must_use]
    pub fn from_authenticode(hashes: &crate::authenticode::AuthenticodeHashes) -> Self {
        Self {
            version: IMAGE_TIER_VERSION,
            digests: hashes.digests.clone(),
            conformant: hashes.status.is_conformant(),
        }
    }
}

/// What the cache holds for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheValue {
    /// The flat hashes, if computed.
    pub flat: Option<FlatTier>,
    /// The Authenticode image digests, if the file is a PE image and they
    /// were computed.
    pub image: Option<ImageTier>,
    /// The library version that computed the value ([`FILEID_LIB_VERSION`]).
    pub fileid_lib_version: String,
    /// The file-type classifier version (#44) in force when it was computed.
    pub classifier_version: u32,
    /// When it was computed.
    pub computed_at: FileTime,
}

impl CacheValue {
    /// A value holding only flat hashes, at the current tier version.
    #[must_use]
    pub fn from_flat(hashes: FlatHashes, classifier_version: u32, computed_at: FileTime) -> Self {
        Self {
            flat: Some(FlatTier {
                version: FLAT_TIER_VERSION,
                hashes,
            }),
            image: None,
            fileid_lib_version: FILEID_LIB_VERSION.to_owned(),
            classifier_version,
            computed_at,
        }
    }

    /// The value with every tier of an older version removed.
    #[must_use]
    pub fn current(mut self) -> Self {
        self.flat = self.flat.filter(|t| t.version == FLAT_TIER_VERSION);
        self.image = self.image.filter(|t| t.version == IMAGE_TIER_VERSION);
        self
    }

    /// Whether no tier is left.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.flat.is_none() && self.image.is_none()
    }

    fn weight(&self) -> usize {
        let digests = |d: &[Digest]| d.iter().map(|d| 16 + d.as_bytes().len()).sum::<usize>();
        let flat = self.flat.as_ref().map_or(0, |t| digests(&t.hashes.digests));
        let image = self.image.as_ref().map_or(0, |t| digests(&t.digests));
        flat + image + self.fileid_lib_version.len()
    }
}

/// The bounds of a [`HashCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
    /// The most entries kept. At least 1.
    pub max_entries: usize,
    /// The most bytes of entries kept, by the cache's own estimate of each
    /// entry's size. At least one entry is always kept.
    pub max_bytes: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// What identifies a file across versions: its file ID on a journalled
/// volume, otherwise its path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Identity {
    File {
        volume_serial: u64,
        file_id: [u8; 16],
    },
    Path(String),
}

impl Identity {
    fn of(key: &FileKey) -> Self {
        match key {
            FileKey::Strong {
                volume_serial,
                file_id,
                ..
            } => Self::File {
                volume_serial: *volume_serial,
                file_id: *file_id,
            },
            FileKey::Weak { path, .. } => Self::Path(path.clone()),
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    key: FileKey,
    path: Option<String>,
    value: CacheValue,
    tick: u64,
    weight: usize,
}

/// Why a lookup missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Miss {
    /// Nothing is cached for the file.
    NotCached,
    /// An entry was cached, but the file changed since (a key component
    /// differs). The entry was dropped.
    Changed,
    /// The entry's tiers are all of an older version. It was dropped.
    Outdated,
}

/// The cache. Not synchronised: share it behind a [`Mutex`], as
/// [`hash_through`] expects.
#[derive(Debug)]
pub struct HashCache {
    config: CacheConfig,
    entries: HashMap<Identity, Entry>,
    /// Recency order: tick to identity. The smallest tick is the least
    /// recently used.
    order: BTreeMap<u64, Identity>,
    tick: u64,
    bytes: usize,
    metrics: HashMetrics,
}

impl HashCache {
    /// An empty cache with these bounds (each raised to at least 1).
    #[must_use]
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config: CacheConfig {
                max_entries: config.max_entries.max(1),
                max_bytes: config.max_bytes.max(1),
            },
            entries: HashMap::new(),
            order: BTreeMap::new(),
            tick: 0,
            bytes: 0,
            metrics: HashMetrics::default(),
        }
    }

    /// The counters this cache updates.
    #[must_use]
    pub const fn metrics(&self) -> &HashMetrics {
        &self.metrics
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The bytes used, by the cache's estimate.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// The value cached for the file whose current key is `key`, if it is
    /// still valid. `path` is where the file was seen now: on a hit through
    /// a strong key (the same file ID after a rename) it is recorded as the
    /// entry's latest path.
    ///
    /// A hit or miss is counted in [`Self::metrics`].
    pub fn get(&mut self, key: &FileKey, path: Option<&str>) -> Result<&CacheValue, Miss> {
        let id = Identity::of(key);
        let Some(entry) = self.entries.get(&id) else {
            self.metrics.record_miss();
            return Err(Miss::NotCached);
        };
        if entry.key != *key {
            self.remove(&id);
            self.metrics.record_miss();
            return Err(Miss::Changed);
        }
        let value = entry.value.clone().current();
        if value.is_empty() {
            self.remove(&id);
            self.metrics.record_miss();
            return Err(Miss::Outdated);
        }
        self.metrics.record_hit();
        let tick = self.next_tick();
        let entry = self.entries.get_mut(&id).ok_or(Miss::NotCached)?;
        self.order.remove(&entry.tick);
        self.order.insert(tick, id);
        entry.tick = tick;
        if let Some(p) = path {
            if entry.path.as_deref() != Some(p) {
                entry.path = Some(p.to_owned());
            }
        }
        entry.value = value;
        Ok(&entry.value)
    }

    /// The latest path recorded for the file `key` identifies (whatever its
    /// change stamp), if it is cached.
    #[must_use]
    pub fn path_of(&self, key: &FileKey) -> Option<&str> {
        self.entries.get(&Identity::of(key))?.path.as_deref()
    }

    /// Caches `value` for the file whose current key is `key`, replacing any
    /// entry for the same file. Tiers of an older version are not stored.
    pub fn insert(&mut self, key: FileKey, path: Option<String>, value: CacheValue) {
        let value = value.current();
        if value.is_empty() {
            return;
        }
        let id = Identity::of(&key);
        self.remove(&id);
        let weight = ENTRY_OVERHEAD
            .saturating_add(key.weight())
            .saturating_add(path.as_ref().map_or(0, String::len))
            .saturating_add(value.weight());
        let tick = self.next_tick();
        self.order.insert(tick, id.clone());
        self.bytes = self.bytes.saturating_add(weight);
        self.entries.insert(
            id,
            Entry {
                key,
                path,
                value,
                tick,
                weight,
            },
        );
        while self.entries.len() > self.config.max_entries
            || (self.bytes > self.config.max_bytes && self.entries.len() > 1)
        {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some(e) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(e.weight);
                self.metrics.record_eviction();
            }
        }
    }

    /// Drops the entry for the file with this ID, if any: for the change
    /// journal consumer (#60), which evicts as soon as it sees a change.
    /// Returns whether one was dropped.
    pub fn evict_file(&mut self, volume_serial: u64, file_id: [u8; 16]) -> bool {
        self.remove(&Identity::File {
            volume_serial,
            file_id,
        })
    }

    /// Drops the weak-key entry for this path, if any.
    pub fn evict_path(&mut self, path: &str) -> bool {
        self.remove(&Identity::Path(path.to_owned()))
    }

    /// Drops every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes = 0;
    }

    /// Every entry, least recently used first, as records to persist.
    #[must_use]
    pub fn export(&self) -> Vec<CacheRecord> {
        self.order
            .values()
            .filter_map(|id| self.entries.get(id))
            .map(|e| CacheRecord {
                key: e.key.clone(),
                path: e.path.clone(),
                value: e.value.clone(),
            })
            .collect()
    }

    /// Decodes a persisted record and caches it. A record that fails its
    /// MAC is not cached and is counted as a tamper event; one that is
    /// malformed is not cached either.
    pub fn import(&mut self, bytes: &[u8], mac_key: &MacKey) -> Result<(), RecordError> {
        match CacheRecord::decode(bytes, mac_key) {
            Ok(record) => {
                self.insert(record.key, record.path, record.value);
                Ok(())
            }
            Err(e) => {
                if e == RecordError::BadMac {
                    self.metrics.record_tamper();
                }
                Err(e)
            }
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    fn remove(&mut self, id: &Identity) -> bool {
        match self.entries.remove(id) {
            Some(e) => {
                self.order.remove(&e.tick);
                self.bytes = self.bytes.saturating_sub(e.weight);
                true
            }
            None => false,
        }
    }
}

impl Default for HashCache {
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Records.

/// One cache entry as it is persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRecord {
    /// The file's key when the value was computed.
    pub key: FileKey,
    /// The latest path the file was seen at.
    pub path: Option<String>,
    /// The cached value.
    pub value: CacheValue,
}

/// Why a persisted record was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordError {
    /// The MAC does not verify: the record was changed or made without the
    /// agent's key. A tamper event.
    BadMac,
    /// The MAC verifies but the record does not decode (a record from a
    /// newer format, or a bug). It is ignored.
    Malformed,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadMac => "hash cache record failed its MAC check",
            Self::Malformed => "hash cache record is malformed",
        })
    }
}

impl std::error::Error for RecordError {}

impl CacheRecord {
    /// The record's bytes: a versioned encoding of every field, then an
    /// HMAC-SHA-256 tag over all of it.
    #[must_use]
    pub fn encode(&self, mac_key: &MacKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(RECORD_MAGIC);
        out.push(RECORD_FORMAT);
        self.key.encode(&mut out);
        put_opt_str(&mut out, self.path.as_deref());
        put_str(&mut out, &self.value.fileid_lib_version);
        out.extend_from_slice(&self.value.classifier_version.to_le_bytes());
        out.extend_from_slice(&self.value.computed_at.0.to_le_bytes());
        match &self.value.flat {
            None => out.push(0),
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.version.to_le_bytes());
                out.extend_from_slice(&t.hashes.size.to_le_bytes());
                out.push(u8::from(t.hashes.empty));
                put_digests(&mut out, &t.hashes.digests);
            }
        }
        match &self.value.image {
            None => out.push(0),
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.version.to_le_bytes());
                out.push(u8::from(t.conformant));
                put_digests(&mut out, &t.digests);
            }
        }
        let tag = mac_key.tag(&out);
        out.extend_from_slice(&tag);
        out
    }

    /// Checks the MAC, then decodes. The MAC is checked first, over the
    /// whole record, so unauthenticated bytes are never parsed into a value.
    pub fn decode(bytes: &[u8], mac_key: &MacKey) -> Result<Self, RecordError> {
        let split = bytes
            .len()
            .checked_sub(MAC_LEN)
            .ok_or(RecordError::BadMac)?;
        let (body, tag) = bytes.split_at(split);
        if !mac_key.verify(body, tag) {
            return Err(RecordError::BadMac);
        }
        decode_body(body).ok_or(RecordError::Malformed)
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            put_str(out, s);
        }
    }
}

fn alg_code(alg: HashAlgorithm) -> u8 {
    match alg {
        HashAlgorithm::Sha256 => 1,
        HashAlgorithm::Sha1 => 2,
        HashAlgorithm::Md5 => 3,
        HashAlgorithm::Sha384 => 4,
        HashAlgorithm::Sha512 => 5,
    }
}

fn alg_from_code(code: u8) -> Option<HashAlgorithm> {
    HashAlgorithm::ALL
        .into_iter()
        .find(|a| alg_code(*a) == code)
}

fn put_digest(out: &mut Vec<u8>, d: &Digest) {
    out.push(alg_code(d.algorithm()));
    out.extend_from_slice(d.as_bytes());
}

fn put_digests(out: &mut Vec<u8>, digests: &[Digest]) {
    // At most one per algorithm, so at most five.
    out.push(u8::try_from(digests.len()).unwrap_or(u8::MAX));
    for d in digests {
        put_digest(out, d);
    }
}

/// A bounds-checked reader over a record body.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }

    fn flag(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn string(&mut self, max: usize) -> Option<String> {
        let len = usize::try_from(self.u32()?).ok()?;
        if len > max {
            return None;
        }
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }

    fn digest(&mut self) -> Option<Digest> {
        let alg = alg_from_code(self.u8()?)?;
        Digest::new(alg, self.take(alg.digest_len())?).ok()
    }

    fn digests(&mut self) -> Option<Vec<Digest>> {
        let n = usize::from(self.u8()?);
        if n > HashAlgorithm::ALL.len() {
            return None;
        }
        let mut out: Vec<Digest> = Vec::with_capacity(n);
        for _ in 0..n {
            let d = self.digest()?;
            // Strictly in `HashAlgorithm::ALL` order: one per algorithm.
            if out
                .last()
                .is_some_and(|p| alg_code(p.algorithm()) >= alg_code(d.algorithm()))
            {
                return None;
            }
            out.push(d);
        }
        Some(out)
    }
}

fn decode_body(body: &[u8]) -> Option<CacheRecord> {
    let mut r = Reader(body);
    if r.take(4)? != RECORD_MAGIC || r.u8()? != RECORD_FORMAT {
        return None;
    }
    let key = match r.u8()? {
        1 => FileKey::Strong {
            volume_serial: r.u64()?,
            file_id: r.array()?,
            usn: i64::from_le_bytes(r.array()?),
            last_write: FileTime(r.u64()?),
            size: r.u64()?,
        },
        2 => {
            let len = usize::try_from(r.u64()?).ok()?;
            if len > MAX_RECORD_PATH {
                return None;
            }
            let path = String::from_utf8(r.take(len)?.to_vec()).ok()?;
            FileKey::Weak {
                path,
                size: r.u64()?,
                last_write: FileTime(r.u64()?),
                creation: FileTime(r.u64()?),
            }
        }
        _ => return None,
    };
    let path = if r.flag()? {
        Some(r.string(MAX_RECORD_PATH)?)
    } else {
        None
    };
    let fileid_lib_version = r.string(64)?;
    let classifier_version = r.u32()?;
    let computed_at = FileTime(r.u64()?);
    let flat = if r.flag()? {
        let version = r.u32()?;
        let size = r.u64()?;
        let empty = r.flag()?;
        let digests = r.digests()?;
        Some(FlatTier {
            version,
            hashes: FlatHashes {
                size,
                empty,
                digests,
            },
        })
    } else {
        None
    };
    let image = if r.flag()? {
        Some(ImageTier {
            version: r.u32()?,
            conformant: r.flag()?,
            digests: r.digests()?,
        })
    } else {
        None
    };
    if !r.0.is_empty() {
        return None;
    }
    Some(CacheRecord {
        key,
        path,
        value: CacheValue {
            flat,
            image,
            fileid_lib_version,
            classifier_version,
            computed_at,
        },
    })
}

// ---------------------------------------------------------------------------
// Verify-on-launch.

/// When a cached digest may be used at execution time (`hash_verify_mode`,
/// a policy setting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HashVerifyMode {
    /// Trust the cache whenever the file's key matches. The default.
    #[default]
    Cached,
    /// Always rehash at execution, and compare with the cached value.
    Recompute,
    /// Rehash files in locations a standard user can change, and on
    /// removable media and network shares; trust the cache elsewhere.
    RecomputeUntrustedLocations,
}

/// Where a file is, for [`HashVerifyMode::RecomputeUntrustedLocations`].
/// Each part is optional; anything not known counts as untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileLocation {
    /// The location class of the file's volume ([`crate::fsctx::VolumeInfo::location_class`]).
    pub class: Option<LocationClass>,
    /// Whether a non-administrator may write the file or a folder above it
    /// ([`crate::fsctx::Writability`]).
    pub user_writable: Option<bool>,
}

impl HashVerifyMode {
    /// Whether a file with this key and location must be rehashed rather
    /// than taken from the cache.
    ///
    /// Under [`Self::RecomputeUntrustedLocations`] a file is trusted only
    /// when it is on a fixed local disk, known not to be user-writable, and
    /// has a strong key: a weak key's timestamps can be restored by whoever
    /// can write the file. Missing information means rehash.
    #[must_use]
    pub fn must_recompute(self, key: &FileKey, location: &FileLocation) -> bool {
        match self {
            Self::Cached => false,
            Self::Recompute => true,
            Self::RecomputeUntrustedLocations => {
                key.is_weak()
                    || location.user_writable != Some(false)
                    || location
                        .class
                        .is_none_or(LocationClass::is_untrusted_location)
            }
        }
    }
}

/// Where the value [`hash_through`] returned came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSource {
    /// The cache, without reading the file.
    Cache,
    /// A fresh hash.
    Computed,
}

/// The result of [`hash_through`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Through {
    /// The file's value.
    Done {
        /// The value.
        value: CacheValue,
        /// Where it came from.
        source: ValueSource,
        /// Under [`HashVerifyMode::Recompute`], or a rehash because of the
        /// location: a cached value existed for the same key and its flat
        /// SHA-256 differs from the fresh one. The file changed without its
        /// key changing (a weak key's timestamps restored, or a stale or
        /// tampered entry). The fresh value replaces it; report the event.
        cache_disagreed: bool,
    },
    /// The file changed while it was being hashed on every attempt
    /// (`HashStatus::Unstable` in #46). Nothing was cached.
    Unstable {
        /// Hashing attempts made: 1 plus [`MAX_UNSTABLE_RETRIES`].
        attempts: u32,
    },
}

/// Why [`hash_through`] failed.
#[derive(Debug)]
pub enum ThroughError<S, H> {
    /// Reading the file's stamp failed.
    Stamp(S),
    /// Hashing failed.
    Hash(H),
}

impl<S: fmt::Display, H: fmt::Display> fmt::Display for ThroughError<S, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stamp(e) => write!(f, "could not read the file's stamp: {e}"),
            Self::Hash(e) => write!(f, "could not hash the file: {e}"),
        }
    }
}

impl<S: fmt::Debug + fmt::Display, H: fmt::Debug + fmt::Display> std::error::Error
    for ThroughError<S, H>
{
}

/// Gets the value for the file at `path` from `cache`, or computes it.
///
/// 1. The file is stamped. If `mode` allows ([`HashVerifyMode::must_recompute`])
///    and the cache has a valid value for that key, it is returned and the
///    file is not read.
/// 2. Otherwise `compute` hashes it, and the file is stamped again. If the
///    two stamps differ, the file changed while it was read: the hash is
///    thrown away and retried, up to [`MAX_UNSTABLE_RETRIES`] times, and
///    then the result is [`Through::Unstable`].
/// 3. A stable value is cached and returned.
///
/// The lock is held only to look up and to insert, never while hashing.
/// The time spent hashing and the bytes hashed (the flat tier's size) are
/// added to the cache's metrics.
pub fn hash_through<S, H, F>(
    cache: &Mutex<HashCache>,
    stamps: &S,
    path: &str,
    mode: HashVerifyMode,
    location: &FileLocation,
    mut compute: F,
) -> Result<Through, ThroughError<S::Error, H>>
where
    S: FileStamp,
    F: FnMut() -> Result<CacheValue, H>,
{
    let mut key = stamps.stamp(path).map_err(ThroughError::Stamp)?;
    let recompute = mode.must_recompute(&key, location);
    let cached = {
        let mut guard = lock(cache);
        guard.get(&key, Some(path)).ok().cloned()
    };
    if let (false, Some(value)) = (recompute, &cached) {
        return Ok(Through::Done {
            value: value.clone(),
            source: ValueSource::Cache,
            cache_disagreed: false,
        });
    }
    let mut attempts = 0;
    loop {
        attempts += 1;
        let started = Instant::now();
        let value = compute().map_err(ThroughError::Hash)?;
        let elapsed = started.elapsed();
        let after = stamps.stamp(path).map_err(ThroughError::Stamp)?;
        {
            let guard = lock(cache);
            let bytes = value.flat.as_ref().map_or(0, |t| t.hashes.size);
            guard.metrics.record_hash(bytes, elapsed);
        }
        if after == key {
            let sha256 = |v: &CacheValue| {
                v.flat
                    .as_ref()
                    .and_then(|t| t.hashes.get(HashAlgorithm::Sha256).cloned())
            };
            let cache_disagreed = cached
                .as_ref()
                .is_some_and(|c| sha256(c).is_some() && sha256(c) != sha256(&value));
            lock(cache).insert(key, Some(path.to_owned()), value.clone());
            return Ok(Through::Done {
                value,
                source: ValueSource::Computed,
                cache_disagreed,
            });
        }
        if attempts > MAX_UNSTABLE_RETRIES {
            lock(cache).metrics.record_unstable();
            return Ok(Through::Unstable { attempts });
        }
        key = after;
    }
}

/// Locks the cache, recovering it if a thread panicked while holding it:
/// the cache holds only recomputable data, and every operation leaves it
/// consistent.
fn lock(cache: &Mutex<HashCache>) -> std::sync::MutexGuard<'_, HashCache> {
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
