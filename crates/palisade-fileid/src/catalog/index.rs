//! The persistent catalog index (#51).
//!
//! A [`CatalogStore`] is built by reading and verifying every catalog,
//! which can take minutes on a real system. [`CatalogIndex`] keeps what a
//! lookup needs, so the agent can save it and answer lookups at once after a
//! restart:
//!
//! - one [`IndexedCatalog`] per catalog: its ID (SHA-256), path, source,
//!   status, member count, OS attribute, effective date, the signer's
//!   publisher name and thumbprint, whether it is trusted, and whether its
//!   signature passed validity (#50) when that was judged;
//! - the member digests, as two sorted tables (44 bytes per SHA-256 member
//!   and 32 per SHA-1 member, as in the store).
//!
//! # On disk
//!
//! [`CatalogIndex::encode`] writes a versioned record: a magic, the format
//! version [`INDEX_FORMAT`], the library version that built it, the state,
//! the catalogs and the tables, then an HMAC-SHA-256 tag (ADR 0008) under
//! an agent-held [`MacKey`] (#18). [`CatalogIndex::decode`] checks the tag
//! over every byte first, so unauthenticated bytes are never parsed, then
//! rejects an index from another format or library version
//! ([`IndexError::Rebuild`]): a full rebuild follows. A tampered index is
//! [`IndexError::BadMac`], a tamper event; the agent rebuilds from the
//! catalog files, so a changed index can never make a file look
//! catalog-signed. Every count is checked against the bytes left and
//! [`MAX_INDEX_SIZE`] before anything is allocated.
//!
//! # Updates
//!
//! The change feed (#60) reports catalogs added, changed and removed. For a
//! removed or changed catalog, [`CatalogIndex::remove_path`] drops its
//! records and members; for an added or changed one, the agent loads it into
//! a new store and [`CatalogIndex::merge`]s that in. A catalog already in
//! the index (same SHA-256 and source) is not added twice.
//!
//! # While building
//!
//! A fresh agent builds the index for the first time at low priority (#65).
//! Until [`CatalogIndex::finish_build`] marks it [`IndexState::Ready`],
//! [`CatalogIndex::lookup_with`] answers a miss with
//! [`CatalogLookup::Indeterminate`], so the policy engine treats "no
//! catalog found yet" as unknown, never as "not catalog-signed".

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use super::settings::{CatalogLookup, CatalogSettings};
use super::store::{CatalogSource, CatalogStatus, CatalogStore, DigestKind, FileDigests};
use crate::fsctx::NormalizedPath;
use crate::hash::MAC_LEN;
use crate::hash::cache::FILEID_LIB_VERSION;
use crate::hash::{Digest, HashAlgorithm, MacKey};

/// The index record format. Raised when the encoding changes: an index in
/// another format is rebuilt.
pub const INDEX_FORMAT: u8 = 1;
/// The largest encoded index read or written: 512 MiB.
pub const MAX_INDEX_SIZE: usize = 512 * 1024 * 1024;
/// The most catalogs and members an index holds.
const MAX_INDEX_CATALOGS: usize = 1 << 20;
const MAX_INDEX_MEMBERS: usize = 1 << 24;
/// The longest path or name kept, in bytes.
const MAX_INDEX_TEXT: usize = 32_767 * 3;
const MAGIC: &[u8; 4] = b"PCI1";

/// Whether the index is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexState {
    /// The first build is still running: a miss is indeterminate.
    Building,
    /// Every configured catalog directory has been read.
    Ready,
}

/// A catalog's status, as indexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexedStatus {
    /// Its signature is valid; its members are indexed.
    Valid,
    /// Its signature is not valid; nothing is indexed.
    InvalidSignature,
    /// It could not be decoded; nothing is indexed.
    Unreadable,
}

/// One catalog, as indexed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedCatalog {
    /// The SHA-256 of the catalog file. `None` only for a file too large to
    /// read.
    pub id: Option<Digest>,
    /// Where it was read from.
    pub path: Option<PathBuf>,
    /// Its namespace.
    pub source: CatalogSource,
    /// Its status.
    pub status: IndexedStatus,
    /// Whether its signer is trusted.
    pub trusted: bool,
    /// Whether its signature's validity was judged, and passed (#50): see
    /// [`super::CatalogRecord::usable`].
    pub usable: bool,
    /// The trusted signer's publisher name (leaf CN or O).
    pub publisher: Option<String>,
    /// The signer certificate's SHA-256 thumbprint.
    pub signer_thumbprint: Option<String>,
    /// How many members the catalog lists.
    pub member_count: usize,
    /// The catalog-wide OS attribute.
    pub os_attr: Option<String>,
    /// `ctlThisUpdate`.
    pub this_update: Option<i64>,
    /// Whether members were left out of the index.
    pub index_truncated: bool,
    /// Whether the catalog's own signature is SHA-2.
    pub signature_sha2: bool,
}

/// One index entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Entry<const N: usize> {
    digest: [u8; N],
    catalog: u32,
    member: u32,
    pe_image: bool,
}

/// A match in the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexMatch<'a> {
    /// The catalog: an index into [`CatalogIndex::catalogs`].
    pub catalog: usize,
    /// Its record.
    pub record: &'a IndexedCatalog,
    /// The member's position in the catalog's trust list.
    pub member: usize,
    /// Which digest matched.
    pub matched_by: DigestKind,
}

impl IndexMatch<'_> {
    /// Whether the match rests on SHA-1 anywhere (member digest or catalog
    /// signature): never enough for an allow decision alone (ADR 0008).
    #[must_use]
    pub const fn relies_on_sha1(&self) -> bool {
        self.matched_by.is_sha1() || !self.record.signature_sha2
    }
}

/// Why an index could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexError {
    /// The tag does not verify: the index was changed, or made with
    /// another key. A tamper event; rebuild from the catalog files.
    BadMac,
    /// The index is from another format or library version: rebuild.
    Rebuild {
        /// Its format.
        format: u8,
        /// The library version that wrote it.
        library: String,
    },
    /// The tag verifies but the content does not decode (a bug, or a
    /// format this version does not know): rebuild.
    Malformed,
    /// Larger than [`MAX_INDEX_SIZE`].
    TooLarge(usize),
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMac => f.write_str("catalog index failed its MAC check"),
            Self::Rebuild { format, library } => write!(
                f,
                "catalog index format {format} from library {library} needs a rebuild"
            ),
            Self::Malformed => f.write_str("catalog index is malformed"),
            Self::TooLarge(n) => write!(f, "catalog index of {n} bytes is too large"),
        }
    }
}

impl std::error::Error for IndexError {}

/// The persistent catalog index. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogIndex {
    state: IndexState,
    catalogs: Vec<IndexedCatalog>,
    /// Catalog slots dropped by [`Self::remove_path`]: kept, so entry
    /// numbers stay stable, but never matched.
    removed: Vec<bool>,
    seen: BTreeSet<(CatalogSource, [u8; 32])>,
    sha256: Vec<Entry<32>>,
    sha1: Vec<Entry<20>>,
}

impl Default for CatalogIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CatalogIndex {
    /// An empty index, [`IndexState::Building`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: IndexState::Building,
            catalogs: Vec::new(),
            removed: Vec::new(),
            seen: BTreeSet::new(),
            sha256: Vec::new(),
            sha1: Vec::new(),
        }
    }

    /// The index of `store`, still [`IndexState::Building`].
    #[must_use]
    pub fn from_store(store: &CatalogStore) -> Self {
        let mut index = Self::new();
        index.merge(store);
        index
    }

    /// Whether the first build is complete.
    #[must_use]
    pub const fn state(&self) -> IndexState {
        self.state
    }

    /// Marks the first build complete: from now on a miss is a miss.
    pub fn finish_build(&mut self) {
        self.state = IndexState::Ready;
    }

    /// Every catalog slot, in insertion order (removed ones included; see
    /// [`Self::is_removed`]).
    #[must_use]
    pub fn catalogs(&self) -> &[IndexedCatalog] {
        &self.catalogs
    }

    /// Whether the catalog at `index` was removed.
    #[must_use]
    pub fn is_removed(&self, index: usize) -> bool {
        self.removed.get(index).copied().unwrap_or(true)
    }

    /// How many members are indexed, removed catalogs' excluded.
    #[must_use]
    pub fn indexed_members(&self) -> usize {
        let live = |c: u32| !self.is_removed(usize::try_from(c).unwrap_or(usize::MAX));
        self.sha256.iter().filter(|e| live(e.catalog)).count()
            + self.sha1.iter().filter(|e| live(e.catalog)).count()
    }

    /// Adds every catalog of `store` not already indexed (same SHA-256 and
    /// source). Returns how many were added. Past the index's own limits,
    /// further catalogs and members are left out (and those catalogs are
    /// marked truncated): a lookup fails closed.
    pub fn merge(&mut self, store: &CatalogStore) -> usize {
        let mut added = 0;
        // Store catalog index -> index catalog index, for its entries.
        let mut map: Vec<Option<u32>> = Vec::with_capacity(store.records().len());
        for record in store.records() {
            let key = record
                .id
                .as_ref()
                .and_then(|d| <[u8; 32]>::try_from(d.as_bytes()).ok());
            let duplicate = key.is_some_and(|k| self.seen.contains(&(record.source, k)));
            if duplicate || self.catalogs.len() >= MAX_INDEX_CATALOGS {
                map.push(None);
                continue;
            }
            let Ok(slot) = u32::try_from(self.catalogs.len()) else {
                map.push(None);
                continue;
            };
            if let Some(k) = key {
                self.seen.insert((record.source, k));
            }
            let signer = record.signer.and_then(|i| store.signers().get(i));
            let identity = signer.and_then(|s| s.identity.as_ref());
            self.catalogs.push(IndexedCatalog {
                id: record.id.clone(),
                path: record.path.clone(),
                source: record.source,
                status: match record.status {
                    CatalogStatus::Valid => IndexedStatus::Valid,
                    CatalogStatus::InvalidSignature(_) => IndexedStatus::InvalidSignature,
                    _ => IndexedStatus::Unreadable,
                },
                trusted: record.trusted,
                usable: record.usable(),
                publisher: identity
                    .and_then(|i| i.publisher_name.as_ref())
                    .map(|n| n.value.clone()),
                signer_thumbprint: signer
                    .and_then(|s| s.trust.chain.as_ref())
                    .and_then(|c| c.leaf_cert())
                    .map(|c| c.sha256_thumbprint.clone()),
                member_count: record.member_count,
                os_attr: record.os_attr.clone(),
                this_update: record.this_update,
                index_truncated: record.index_truncated,
                signature_sha2: record
                    .signature_digest_alg
                    .is_some_and(crate::authenticode::DigestAlgorithm::is_sha2),
            });
            self.removed.push(false);
            map.push(Some(slot));
            added += 1;
        }
        let room = |n: usize| n < MAX_INDEX_MEMBERS;
        let mut truncated: BTreeSet<u32> = BTreeSet::new();
        for e in store.entries_sha256() {
            let Some(Some(slot)) = map.get(e.0 as usize) else {
                continue;
            };
            if room(self.sha256.len() + self.sha1.len()) {
                self.sha256.push(Entry {
                    digest: e.2,
                    catalog: *slot,
                    member: e.1,
                    pe_image: e.3,
                });
            } else {
                truncated.insert(*slot);
            }
        }
        for e in store.entries_sha1() {
            let Some(Some(slot)) = map.get(e.0 as usize) else {
                continue;
            };
            if room(self.sha256.len() + self.sha1.len()) {
                self.sha1.push(Entry {
                    digest: e.2,
                    catalog: *slot,
                    member: e.1,
                    pe_image: e.3,
                });
            } else {
                truncated.insert(*slot);
            }
        }
        for slot in truncated {
            if let Some(c) = self.catalogs.get_mut(slot as usize) {
                c.index_truncated = true;
            }
        }
        self.sha256.sort_unstable();
        self.sha1.sort_unstable();
        added
    }

    /// Drops every catalog read from `path` (a removed or changed catalog,
    /// from the change feed): its members no longer match, and it may be
    /// added again. Returns how many were dropped.
    pub fn remove_path(&mut self, path: &Path) -> usize {
        let mut dropped = 0;
        for (i, c) in self.catalogs.iter().enumerate() {
            if c.path.as_deref() == Some(path) && !self.removed.get(i).copied().unwrap_or(true) {
                if let Some(r) = self.removed.get_mut(i) {
                    *r = true;
                }
                if let Some(k) =
                    c.id.as_ref()
                        .and_then(|d| <[u8; 32]>::try_from(d.as_bytes()).ok())
                {
                    self.seen.remove(&(c.source, k));
                }
                dropped += 1;
            }
        }
        if dropped > 0 {
            let removed = &self.removed;
            let live = |c: u32| !removed.get(c as usize).copied().unwrap_or(true);
            self.sha256.retain(|e| live(e.catalog));
            self.sha1.retain(|e| live(e.catalog));
        }
        dropped
    }

    /// The catalogs, from any source, that list a file with `digests`, in
    /// the same order as [`CatalogStore::lookup`]: usable first, then
    /// trusted, then by [`DigestKind`], then SHA-2-signed first, then
    /// insertion order. At most [`super::MAX_MATCHES`].
    #[must_use]
    pub fn lookup(&self, digests: &FileDigests) -> Vec<IndexMatch<'_>> {
        self.lookup_in(digests, super::CatalogScope::All.sources())
    }

    /// [`Self::lookup`] under `settings` (see
    /// [`CatalogStore::lookup_with`]). While the index is
    /// [`IndexState::Building`], a lookup that finds nothing is
    /// [`CatalogLookup::Indeterminate`].
    #[must_use]
    pub fn lookup_with(
        &self,
        digests: &FileDigests,
        settings: &CatalogSettings,
        path: Option<&NormalizedPath>,
    ) -> CatalogLookup<Vec<IndexMatch<'_>>> {
        match settings.gate(path, || {
            self.lookup_in(digests, settings.catalog_scope.sources())
        }) {
            CatalogLookup::Done(m) if m.is_empty() && self.state == IndexState::Building => {
                CatalogLookup::Indeterminate
            }
            other => other,
        }
    }

    fn lookup_in(&self, digests: &FileDigests, sources: &[CatalogSource]) -> Vec<IndexMatch<'_>> {
        let mut found: Vec<IndexMatch<'_>> = Vec::new();
        let mut seen = BTreeSet::new();
        let fields = [
            (
                DigestKind::AuthenticodeSha256,
                digests.authenticode_sha256.as_ref(),
            ),
            (
                DigestKind::AuthenticodeSha1,
                digests.authenticode_sha1.as_ref(),
            ),
            (DigestKind::FlatSha256, digests.flat_sha256.as_ref()),
            (DigestKind::FlatSha1, digests.flat_sha1.as_ref()),
        ];
        for (kind, digest) in fields {
            let Some(digest) = digest else { continue };
            let authenticode = matches!(
                kind,
                DigestKind::AuthenticodeSha256 | DigestKind::AuthenticodeSha1
            );
            let hits: Vec<(u32, u32, bool)> = match (kind.is_sha1(), digest.algorithm()) {
                (false, HashAlgorithm::Sha256) => find(&self.sha256, digest.as_bytes())
                    .iter()
                    .map(|e| (e.catalog, e.member, e.pe_image))
                    .collect(),
                (true, HashAlgorithm::Sha1) => find(&self.sha1, digest.as_bytes())
                    .iter()
                    .map(|e| (e.catalog, e.member, e.pe_image))
                    .collect(),
                _ => continue,
            };
            for (catalog, member, pe_image) in hits {
                if pe_image != authenticode {
                    continue;
                }
                let catalog = catalog as usize;
                let Some(record) = self.catalogs.get(catalog) else {
                    continue;
                };
                if self.is_removed(catalog) || !sources.contains(&record.source) {
                    continue;
                }
                if seen.insert(catalog) {
                    found.push(IndexMatch {
                        catalog,
                        record,
                        member: member as usize,
                        matched_by: kind,
                    });
                }
            }
        }
        found.sort_by_key(|m| {
            (
                !m.record.usable,
                !m.record.trusted,
                m.matched_by,
                !m.record.signature_sha2,
                m.catalog,
            )
        });
        found.truncate(super::MAX_MATCHES);
        found
    }

    /// The index as bytes, with an HMAC-SHA-256 tag under `key`.
    #[must_use]
    pub fn encode(&self, key: &MacKey) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(INDEX_FORMAT);
        put_str(&mut out, FILEID_LIB_VERSION);
        out.push(match self.state {
            IndexState::Building => 0,
            IndexState::Ready => 1,
        });
        // Only live catalogs are written; entries are renumbered to match.
        let live: Vec<usize> = (0..self.catalogs.len())
            .filter(|i| !self.is_removed(*i))
            .collect();
        let mut renumber = vec![u32::MAX; self.catalogs.len()];
        for (new, old) in live.iter().enumerate() {
            if let Some(slot) = renumber.get_mut(*old) {
                *slot = u32::try_from(new).unwrap_or(u32::MAX);
            }
        }
        put_u32(&mut out, live.len());
        for i in &live {
            if let Some(c) = self.catalogs.get(*i) {
                put_catalog(&mut out, c);
            }
        }
        let renum = |c: u32| renumber.get(c as usize).copied().unwrap_or(u32::MAX);
        put_u32(&mut out, self.sha256.len());
        for e in &self.sha256 {
            out.extend_from_slice(&e.digest);
            out.extend_from_slice(&renum(e.catalog).to_le_bytes());
            out.extend_from_slice(&e.member.to_le_bytes());
            out.push(u8::from(e.pe_image));
        }
        put_u32(&mut out, self.sha1.len());
        for e in &self.sha1 {
            out.extend_from_slice(&e.digest);
            out.extend_from_slice(&renum(e.catalog).to_le_bytes());
            out.extend_from_slice(&e.member.to_le_bytes());
            out.push(u8::from(e.pe_image));
        }
        let tag = key.tag(&out);
        out.extend_from_slice(&tag);
        out
    }

    /// Reads an index written by [`Self::encode`] under `key`. The tag is
    /// checked first, over every byte.
    pub fn decode(bytes: &[u8], key: &MacKey) -> Result<Self, IndexError> {
        if bytes.len() > MAX_INDEX_SIZE {
            return Err(IndexError::TooLarge(bytes.len()));
        }
        let split = bytes.len().checked_sub(MAC_LEN).ok_or(IndexError::BadMac)?;
        let (body, tag) = bytes.split_at(split);
        if !key.verify(body, tag) {
            return Err(IndexError::BadMac);
        }
        let mut r = Reader(body);
        if r.take(4).ok_or(IndexError::Malformed)? != MAGIC {
            return Err(IndexError::Malformed);
        }
        let format = r.u8().ok_or(IndexError::Malformed)?;
        let library = r.string(64).ok_or(IndexError::Malformed)?;
        if format != INDEX_FORMAT || library != FILEID_LIB_VERSION {
            return Err(IndexError::Rebuild { format, library });
        }
        decode_rest(&mut r).ok_or(IndexError::Malformed)
    }
}

/// The entries with `digest`, from a sorted table.
fn find<'a, const N: usize>(table: &'a [Entry<N>], digest: &[u8]) -> &'a [Entry<N>] {
    let Ok(key) = <[u8; N]>::try_from(digest) else {
        return &[];
    };
    let start = table.partition_point(|e| e.digest < key);
    let len = table
        .get(start..)
        .unwrap_or_default()
        .partition_point(|e| e.digest == key);
    table
        .get(start..start.saturating_add(len))
        .unwrap_or_default()
}

fn put_u32(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => {
            out.push(1);
            put_str(out, s);
        }
        None => out.push(0),
    }
}

fn put_catalog(out: &mut Vec<u8>, c: &IndexedCatalog) {
    match &c.id {
        Some(d) => {
            out.push(1);
            out.extend_from_slice(d.as_bytes());
        }
        None => out.push(0),
    }
    put_opt_str(out, c.path.as_deref().and_then(Path::to_str));
    out.push(match c.source {
        CatalogSource::System => 0,
        CatalogSource::DriverStore => 1,
        _ => 2,
    });
    out.push(match c.status {
        IndexedStatus::Valid => 0,
        IndexedStatus::InvalidSignature => 1,
        IndexedStatus::Unreadable => 2,
    });
    let flags = u8::from(c.trusted)
        | (u8::from(c.usable) << 1)
        | (u8::from(c.index_truncated) << 2)
        | (u8::from(c.signature_sha2) << 3);
    out.push(flags);
    put_opt_str(out, c.publisher.as_deref());
    put_opt_str(out, c.signer_thumbprint.as_deref());
    put_u32(out, c.member_count);
    put_opt_str(out, c.os_attr.as_deref());
    match c.this_update {
        Some(t) => {
            out.push(1);
            out.extend_from_slice(&t.to_le_bytes());
        }
        None => out.push(0),
    }
}

/// A cursor that never reads past its slice.
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

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn flag(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// A count of items of at least `item` bytes each, checked against the
    /// bytes left and `max`, so it never sizes an allocation it cannot
    /// fill.
    fn count(&mut self, item: usize, max: usize) -> Option<usize> {
        let n = usize::try_from(self.u32()?).ok()?;
        (n <= max && n.checked_mul(item)? <= self.0.len()).then_some(n)
    }

    fn string(&mut self, max: usize) -> Option<String> {
        let len = usize::try_from(self.u32()?).ok()?;
        if len > max {
            return None;
        }
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }

    fn opt_string(&mut self, max: usize) -> Option<Option<String>> {
        if self.flag()? {
            Some(Some(self.string(max)?))
        } else {
            Some(None)
        }
    }
}

fn decode_rest(r: &mut Reader<'_>) -> Option<CatalogIndex> {
    let state = match r.u8()? {
        0 => IndexState::Building,
        1 => IndexState::Ready,
        _ => return None,
    };
    // Each catalog takes at least 13 bytes.
    let n = r.count(13, MAX_INDEX_CATALOGS)?;
    let mut catalogs = Vec::with_capacity(n);
    let mut seen = BTreeSet::new();
    for _ in 0..n {
        let id = if r.flag()? {
            let bytes: [u8; 32] = r.take(32)?.try_into().ok()?;
            Some(Digest::new(HashAlgorithm::Sha256, &bytes).ok()?)
        } else {
            None
        };
        let path = r.opt_string(MAX_INDEX_TEXT)?.map(PathBuf::from);
        let source = match r.u8()? {
            0 => CatalogSource::System,
            1 => CatalogSource::DriverStore,
            2 => CatalogSource::Policy,
            _ => return None,
        };
        let status = match r.u8()? {
            0 => IndexedStatus::Valid,
            1 => IndexedStatus::InvalidSignature,
            2 => IndexedStatus::Unreadable,
            _ => return None,
        };
        let flags = r.u8()?;
        if flags & !0x0f != 0 {
            return None;
        }
        let publisher = r.opt_string(MAX_INDEX_TEXT)?;
        let signer_thumbprint = r.opt_string(128)?;
        let member_count = usize::try_from(r.u32()?).ok()?;
        let os_attr = r.opt_string(MAX_INDEX_TEXT)?;
        let this_update = if r.flag()? { Some(r.i64()?) } else { None };
        if let Some(d) = &id {
            let k: [u8; 32] = d.as_bytes().try_into().ok()?;
            if !seen.insert((source, k)) {
                return None;
            }
        }
        catalogs.push(IndexedCatalog {
            id,
            path,
            source,
            status,
            trusted: flags & 1 != 0,
            usable: flags & 2 != 0,
            index_truncated: flags & 4 != 0,
            signature_sha2: flags & 8 != 0,
            publisher,
            signer_thumbprint,
            member_count,
            os_attr,
            this_update,
        });
    }
    let sha256 = entries::<32>(r, catalogs.len())?;
    let sha1 = entries::<20>(r, catalogs.len())?;
    if !r.0.is_empty() || sha256.len() + sha1.len() > MAX_INDEX_MEMBERS {
        return None;
    }
    // Members of a catalog that is not valid can never have been indexed.
    let valid = |c: u32| {
        catalogs
            .get(c as usize)
            .is_some_and(|x| x.status == IndexedStatus::Valid)
    };
    if !sha256.iter().all(|e| valid(e.catalog)) || !sha1.iter().all(|e| valid(e.catalog)) {
        return None;
    }
    let removed = vec![false; catalogs.len()];
    Some(CatalogIndex {
        state,
        catalogs,
        removed,
        seen,
        sha256,
        sha1,
    })
}

/// A sorted table of `N`-byte digests.
fn entries<const N: usize>(r: &mut Reader<'_>, catalogs: usize) -> Option<Vec<Entry<N>>> {
    let n = r.count(N + 9, MAX_INDEX_MEMBERS)?;
    let mut out: Vec<Entry<N>> = Vec::with_capacity(n);
    for _ in 0..n {
        let digest: [u8; N] = r.take(N)?.try_into().ok()?;
        let catalog = r.u32()?;
        let member = r.u32()?;
        let pe_image = r.flag()?;
        if catalog as usize >= catalogs {
            return None;
        }
        let e = Entry {
            digest,
            catalog,
            member,
            pe_image,
        };
        // Sorted, as written: lookups binary-search the table.
        if out.last().is_some_and(|last| *last > e) {
            return None;
        }
        out.push(e);
    }
    Some(out)
}
