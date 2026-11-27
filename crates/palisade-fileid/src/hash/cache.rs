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
    /// The image digest for `alg`, if computed.
    #[must_use]
    pub fn get(&self, alg: HashAlgorithm) -> Option<&Digest> {
        self.digests.iter().find(|d| d.algorithm() == alg)
    }

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
        let digests = |d: &[Digest]| {
            d.iter()
                .fold(0_usize, |n, d| n.saturating_add(16 + d.as_bytes().len()))
        };
        let flat = self.flat.as_ref().map_or(0, |t| digests(&t.hashes.digests));
        let image = self.image.as_ref().map_or(0, |t| digests(&t.digests));
        flat.saturating_add(image)
            .saturating_add(self.fileid_lib_version.len())
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
    /// still valid, and marks it recently used. `path` is where the file was
    /// seen now (through a hard link, say); it is recorded as the entry's
    /// latest path, and the byte bound is enforced again.
    ///
    /// A hit or miss is counted in [`Self::metrics`]. A miss for a changed
    /// file drops the stale entry.
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
        self.metrics.record_hit();
        let tick = self.next_tick();
        let Some(entry) = self.entries.get_mut(&id) else {
            return Err(Miss::NotCached);
        };
        self.order.remove(&entry.tick);
        self.order.insert(tick, id.clone());
        entry.tick = tick;
        if let Some(p) = path.filter(|p| entry.path.as_deref() != Some(*p)) {
            let old = entry.path.as_ref().map_or(0, String::len);
            entry.path = Some(p.to_owned());
            entry.weight = entry.weight.saturating_sub(old).saturating_add(p.len());
            self.bytes = self.bytes.saturating_sub(old).saturating_add(p.len());
            // The entry just used is the newest, so it is evicted last.
            self.enforce_bounds();
        }
        self.entries
            .get(&id)
            .map(|e| &e.value)
            .ok_or(Miss::NotCached)
    }

    /// The value cached for `key`, without counting a lookup or changing
    /// recency: for comparing with a fresh hash when the cache is not
    /// trusted to skip one ([`HashVerifyMode::must_recompute`]).
    #[must_use]
    pub fn peek(&self, key: &FileKey) -> Option<&CacheValue> {
        self.entries
            .get(&Identity::of(key))
            .filter(|e| e.key == *key)
            .map(|e| &e.value)
    }

    /// The latest path recorded for the file `key` identifies (whatever its
    /// change stamp), if it is cached.
    #[must_use]
    pub fn path_of(&self, key: &FileKey) -> Option<&str> {
        self.entries.get(&Identity::of(key))?.path.as_deref()
    }

    /// Caches `value` for the file whose current key is `key`, replacing any
    /// entry for the same file. Tiers of an older version are not stored;
    /// if no tier is left, the old entry is still dropped.
    pub fn insert(&mut self, key: FileKey, path: Option<String>, value: CacheValue) {
        let id = Identity::of(&key);
        self.remove(&id);
        let value = value.current();
        if value.is_empty() {
            return;
        }
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
        self.enforce_bounds();
    }

    /// The key cached for the file with this ID, if any: for the change
    /// journal consumer (#60), which knows a file only by its ID and needs
    /// the cached key (and so its USN) to decide what a journal record
    /// means for it.
    #[must_use]
    pub fn key_of(&self, volume_serial: u64, file_id: [u8; 16]) -> Option<&FileKey> {
        self.entries
            .get(&Identity::File {
                volume_serial,
                file_id,
            })
            .map(|e| &e.key)
    }

    /// For the change journal consumer (#60): every journal record for the
    /// file after its cached USN, up to `new`'s, is a rename and nothing
    /// else, so its key is now `new` and its path `new_path`. The entry is
    /// carried over.
    ///
    /// The consumer must have checked that: find the cached key with
    /// [`Self::key_of`], and read the journal from its USN. Only a strong
    /// entry can be rekeyed, and only to a strong key for the same file
    /// (volume and file ID) with the same journal, last-write time and
    /// size, and a **later** USN. Anything else could let a stale entry
    /// describe changed content, so the file's entry is dropped instead.
    /// Returns whether it was kept.
    pub fn rekey_after_rename(&mut self, new: FileKey, new_path: Option<String>) -> bool {
        let id = Identity::of(&new);
        let carried = match (self.entries.get(&id).map(|e| &e.key), &new) {
            (
                Some(FileKey::Strong {
                    usn_journal_id: j1,
                    usn: u1,
                    last_write: w1,
                    size: s1,
                    ..
                }),
                FileKey::Strong {
                    usn_journal_id: j2,
                    usn: u2,
                    last_write: w2,
                    size: s2,
                    ..
                },
            ) => j1 == j2 && u1 < u2 && w1 == w2 && s1 == s2,
            _ => false,
        };
        let value = self.entries.get(&id).map(|e| e.value.clone());
        match value {
            Some(value) if carried => {
                self.insert(new, new_path, value);
                true
            }
            _ => {
                self.remove(&id);
                false
            }
        }
    }

    fn enforce_bounds(&mut self) {
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

    /// Drops the weak-key entry for this path, if any. `path` must be the
    /// same normalised match key as in [`FileKey::Weak`]: the lookup is an
    /// exact string match.
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
            usn_journal_id: r.u64()?,
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
        /// location: a cached value existed for the same key as the fresh
        /// hash, both have a flat SHA-256, and they differ. The file changed without its
        /// key changing (a weak key's timestamps restored, or a stale or
        /// tampered entry). The fresh value replaces it; report the event.
        cache_disagreed: bool,
    },
    /// The file kept changing while it was being hashed, on every attempt,
    /// or the bytes hashed did not match the size its key records
    /// (`HashStatus::Unstable` in #46). Nothing was cached, and any entry
    /// for the file was dropped.
    Unstable {
        /// Hashing attempts made: 1 plus [`MAX_UNSTABLE_RETRIES`] when the
        /// file kept changing, fewer when a size mismatch stopped it early.
        attempts: u32,
    },
}

/// Why [`hash_through`] failed.
#[derive(Debug)]
pub enum ThroughError<S, H> {
    /// Opening the file or reading its stamp failed.
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
/// 1. The file is opened once ([`FileStamp::open`]). Everything after uses
///    that handle, so a link or junction swapped mid-way cannot pair one
///    file's key with another file's content.
/// 2. The handle is stamped. If `mode` allows ([`HashVerifyMode::must_recompute`])
///    and the cache has a valid value for that key, it is returned and the
///    file is not read.
/// 3. Otherwise the handle is rewound ([`FileStamp::rewind`]), `compute`
///    hashes it from its first byte, and the handle is stamped again.
///    `compute` may be called more than once on the same handle. If the two stamps differ, the file changed while it was read:
///    the hash is thrown away and retried, up to [`MAX_UNSTABLE_RETRIES`]
///    times. Then the result is [`Through::Unstable`], and any entry for the
///    file is dropped.
/// 4. A value whose flat hashes cover a different size than the key
///    records is never cached; it is [`Through::Unstable`] too.
/// 5. A stable value is cached and returned.
///
/// Under a recompute mode the cache is consulted without counting a lookup
/// ([`HashCache::peek`]), and only to set `cache_disagreed`. That compares
/// the flat SHA-256 of an entry for the **same** key as the fresh hash, and
/// only when both have one.
///
/// The lock is held only to look up and to insert, never while hashing.
/// The time spent hashing and the bytes hashed are added to the metrics.
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
    F: FnMut(&S::File) -> Result<CacheValue, H>,
{
    let file = stamps.open(path).map_err(ThroughError::Stamp)?;
    let mut key = stamps.stamp(&file).map_err(ThroughError::Stamp)?;
    if !mode.must_recompute(&key, location)
        && let Ok(value) = lock(cache).get(&key, Some(path))
    {
        return Ok(Through::Done {
            value: value.clone(),
            source: ValueSource::Cache,
            cache_disagreed: false,
        });
    }
    let sha256 = |v: &CacheValue| {
        v.flat
            .as_ref()
            .and_then(|t| t.hashes.get(HashAlgorithm::Sha256).cloned())
    };
    let mut attempts = 0;
    loop {
        attempts += 1;
        // Each attempt reads the whole file from its first byte.
        stamps.rewind(&file).map_err(ThroughError::Stamp)?;
        let started = Instant::now();
        let value = compute(&file).map_err(ThroughError::Hash)?;
        let elapsed = started.elapsed();
        let after = stamps.stamp(&file).map_err(ThroughError::Stamp)?;
        let hashed = value.flat.as_ref().map(|t| t.hashes.size);
        lock(cache)
            .metrics
            .record_hash(hashed.unwrap_or(0), elapsed);
        let size_matches = hashed.is_none_or(|n| n == after.size());
        if after == key && size_matches {
            let mut guard = lock(cache);
            let cache_disagreed = guard
                .peek(&key)
                .and_then(sha256)
                .zip(sha256(&value))
                .is_some_and(|(cached, fresh)| cached != fresh);
            guard.insert(key, Some(path.to_owned()), value.clone());
            return Ok(Through::Done {
                value,
                source: ValueSource::Computed,
                cache_disagreed,
            });
        }
        if attempts > MAX_UNSTABLE_RETRIES || after == key {
            let mut guard = lock(cache);
            guard.metrics.record_unstable();
            // Neither key can be trusted any more.
            guard.remove(&Identity::of(&key));
            guard.remove(&Identity::of(&after));
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
