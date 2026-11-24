//! The catalog store: catalogs loaded within limits, and the member index
//! from digest to catalog.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::{Catalog, CatalogError, CatalogWarning, MAX_CATALOG_SIZE, SubjectAlgorithm};
use crate::authenticode::{
    AuthenticodeHashes, BadSignature, DigestAlgorithm, SignatureStatus, SignerIdentity,
    SignerTrust, TrustConfig, hash_pe,
};
use crate::hash::{AlgorithmSet, Digest, FlatHashes, HashAlgorithm, hash_bytes};

/// The most matches [`CatalogStore::lookup`] returns. A digest listed in
/// more catalogs keeps the best ones ([`LookupResult::truncated`]).
pub const MAX_MATCHES: usize = 32;
/// The most errors a [`LoadReport`] keeps.
pub const MAX_LOAD_ERRORS: usize = 256;

/// Where a catalog came from. Each source is its own namespace, with its
/// own [`TrustConfig`] ([`CatalogStoreBuilder::trust`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CatalogSource {
    /// The OS catalog store (the `{GUID}` folders under `catroot`).
    System,
    /// The OS driver store (`DriverStore\FileRepository`).
    DriverStore,
    /// Catalogs delivered with policy, kept under the agent's data
    /// directory and never written into the OS store.
    Policy,
}

impl CatalogSource {
    const COUNT: usize = 3;

    const fn index(self) -> usize {
        match self {
            Self::System => 0,
            Self::DriverStore => 1,
            Self::Policy => 2,
        }
    }
}

/// Bounds on what a store loads. Every limit fails closed: whatever is not
/// loaded or indexed matches nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreLimits {
    /// The most catalogs (records) held.
    pub max_catalogs: usize,
    /// The largest catalog file read, at most [`MAX_CATALOG_SIZE`].
    pub max_catalog_size: u64,
    /// The most catalog bytes read in total. A file's length is checked
    /// against what is left before it is read.
    pub max_total_bytes: u64,
    /// The most members indexed in total. A catalog that does not fit is
    /// indexed in part ([`CatalogRecord::index_truncated`]).
    pub max_members: usize,
    /// The deepest directory [`CatalogStoreBuilder::add_dir`] descends to
    /// below its root.
    pub max_depth: usize,
    /// The most directory entries [`CatalogStoreBuilder::add_dir`] looks
    /// at, per call.
    pub max_dir_entries: usize,
}

impl Default for StoreLimits {
    /// 100,000 catalogs, [`MAX_CATALOG_SIZE`] each, 2 GiB in total,
    /// 4,194,304 members (about 180 MB of index), 16 levels and 1,048,576
    /// directory entries.
    fn default() -> Self {
        Self {
            max_catalogs: 100_000,
            max_catalog_size: MAX_CATALOG_SIZE,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_members: 1 << 22,
            max_depth: 16,
            max_dir_entries: 1 << 20,
        }
    }
}

/// The state of a loaded catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CatalogStatus {
    /// Its signature is cryptographically valid; its members are indexed.
    Valid,
    /// It decodes, but its signature is not valid. Nothing is indexed.
    InvalidSignature(SignatureStatus),
    /// It could not be decoded. Nothing is indexed.
    Unreadable(CatalogError),
}

/// What the store knows about one catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRecord {
    /// The SHA-256 of the catalog file. `None` only when it was too large
    /// to read.
    pub id: Option<Digest>,
    /// Where it was read from, if from a file.
    pub path: Option<PathBuf>,
    /// Its namespace.
    pub source: CatalogSource,
    /// Its size in bytes.
    pub size: u64,
    /// Its state.
    pub status: CatalogStatus,
    /// The signer: an index into [`CatalogStore::signers`]. `None` unless
    /// the signature is valid.
    pub signer: Option<usize>,
    /// Whether the signer is trusted: the signature is valid and the chain
    /// reaches a configured anchor (see
    /// [`crate::authenticode::evaluate_trust`]).
    pub trusted: bool,
    /// How many members the catalog lists (up to
    /// [`super::MAX_MEMBERS`]).
    pub member_count: usize,
    /// How many of them are indexed: those with a SHA-256 or SHA-1 digest,
    /// within [`StoreLimits::max_members`].
    pub indexed_members: usize,
    /// Whether members were left out of the index: the catalog lists more
    /// than [`super::MAX_MEMBERS`], or the store's member limit was
    /// reached.
    pub index_truncated: bool,
    /// The digest algorithm of the catalog's own signature (the
    /// SignerInfo's). `None` unless it decoded to a known algorithm.
    pub signature_digest_alg: Option<DigestAlgorithm>,
    /// The CTL's subject algorithm.
    pub subject_algorithm: Option<SubjectAlgorithm>,
    /// The catalog-wide OS attribute (`OSAttr` or `OS`).
    pub os_attr: Option<String>,
    /// `ctlThisUpdate`, in seconds since the Unix epoch (UTC).
    pub this_update: Option<i64>,
    /// The signer's `signingTime` claim, in seconds since the Unix epoch
    /// (UTC). Not a trusted time; timestamps are #50.
    pub signing_time: Option<i64>,
    /// Anything unusual about the file.
    pub warnings: Vec<CatalogWarning>,
}

/// A catalog signer, shared by every catalog in one namespace with the same
/// signer certificate and embedded certificates (so the same chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogSigner {
    /// The namespace whose [`TrustConfig`] decided it.
    pub source: CatalogSource,
    /// The chain and trust verdict.
    pub trust: SignerTrust,
    /// The trusted signer's identity, at signer level (no file version
    /// resource, so no product or file name). `None` unless trusted.
    pub identity: Option<SignerIdentity>,
}

/// Why a catalog was not loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadError {
    /// An I/O error.
    Io {
        /// The path.
        path: PathBuf,
        /// What went wrong.
        kind: io::ErrorKind,
    },
    /// The path is not a regular file.
    NotAFile(PathBuf),
    /// The catalog is larger than [`StoreLimits::max_catalog_size`] (or
    /// [`MAX_CATALOG_SIZE`]). It is recorded as unreadable, with its real
    /// size, and not read.
    TooLarge {
        /// The path, if any.
        path: Option<PathBuf>,
        /// Its size.
        size: u64,
    },
    /// [`StoreLimits::max_catalogs`] was reached; nothing more is loaded.
    CatalogLimit,
    /// [`StoreLimits::max_total_bytes`] would be exceeded; the catalog
    /// was not read or recorded. [`CatalogStoreBuilder::add_dir`] stops
    /// once the budget is spent.
    ByteLimit,
    /// The file's length changed while it was read. It was not recorded.
    Changed(PathBuf),
    /// [`StoreLimits::max_members`] was reached; later members are not
    /// indexed.
    MemberLimit,
    /// A directory deeper than [`StoreLimits::max_depth`] was not read.
    DepthLimit(PathBuf),
    /// [`StoreLimits::max_dir_entries`] was reached; the rest of the tree
    /// was not read.
    EntryLimit,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, kind } => write!(f, "{}: {kind}", path.display()),
            Self::NotAFile(p) => write!(f, "{}: not a regular file", p.display()),
            Self::TooLarge { path, size } => match path {
                Some(p) => write!(f, "{}: {size} bytes is too large", p.display()),
                None => write!(f, "catalog of {size} bytes is too large"),
            },
            Self::CatalogLimit => f.write_str("catalog limit reached"),
            Self::ByteLimit => f.write_str("catalog byte limit reached"),
            Self::Changed(p) => write!(f, "{}: changed while it was read", p.display()),
            Self::MemberLimit => f.write_str("member index limit reached"),
            Self::DepthLimit(p) => write!(f, "{}: too deep", p.display()),
            Self::EntryLimit => f.write_str("directory entry limit reached"),
        }
    }
}

impl std::error::Error for LoadError {}

/// What one load call did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// Catalogs recorded (valid, invalid or unreadable).
    pub recorded: usize,
    /// Of those, catalogs whose signature is valid.
    pub valid: usize,
    /// Catalogs already in the same namespace (same SHA-256), skipped.
    pub duplicates: usize,
    /// Files skipped because their name does not end in `.cat`.
    pub skipped: usize,
    /// What could not be loaded, up to [`MAX_LOAD_ERRORS`].
    pub errors: Vec<LoadError>,
    /// Whether errors past [`MAX_LOAD_ERRORS`] were dropped.
    pub errors_truncated: bool,
}

impl LoadReport {
    fn error(&mut self, e: LoadError) {
        if self.errors.len() < MAX_LOAD_ERRORS {
            if !self.errors.contains(&e) || !is_limit(&e) {
                self.errors.push(e);
            }
        } else {
            self.errors_truncated = true;
        }
    }

    fn merge(&mut self, other: Self) {
        self.recorded = self.recorded.saturating_add(other.recorded);
        self.valid = self.valid.saturating_add(other.valid);
        self.duplicates = self.duplicates.saturating_add(other.duplicates);
        self.skipped = self.skipped.saturating_add(other.skipped);
        self.errors_truncated |= other.errors_truncated;
        for e in other.errors {
            self.error(e);
        }
    }
}

const fn is_limit(e: &LoadError) -> bool {
    matches!(
        e,
        LoadError::CatalogLimit
            | LoadError::ByteLimit
            | LoadError::MemberLimit
            | LoadError::EntryLimit
    )
}

/// Which of a file's digests matched, in lookup order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DigestKind {
    /// The Authenticode SHA-256 image hash, against a PE member.
    AuthenticodeSha256,
    /// The Authenticode SHA-1 image hash, against a PE member. **Not
    /// collision resistant**: compatibility only (ADR 0008).
    AuthenticodeSha1,
    /// The flat SHA-256, against a non-PE member.
    FlatSha256,
    /// The flat SHA-1, against a non-PE member. **Not collision
    /// resistant**: compatibility only (ADR 0008).
    FlatSha1,
}

impl DigestKind {
    /// Whether the digest is SHA-1, which no allow decision may rest on
    /// alone.
    #[must_use]
    pub const fn is_sha1(self) -> bool {
        matches!(self, Self::AuthenticodeSha1 | Self::FlatSha1)
    }

    const fn is_authenticode(self) -> bool {
        matches!(self, Self::AuthenticodeSha256 | Self::AuthenticodeSha1)
    }

    /// The algorithm a digest in this slot must have.
    const fn algorithm(self) -> HashAlgorithm {
        match self {
            Self::AuthenticodeSha256 | Self::FlatSha256 => HashAlgorithm::Sha256,
            Self::AuthenticodeSha1 | Self::FlatSha1 => HashAlgorithm::Sha1,
        }
    }
}

/// The digests of one file that a catalog lookup tries. A digest whose
/// algorithm is not its field's (a SHA-1 digest in a SHA-256 field, say)
/// is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileDigests {
    /// The Authenticode SHA-256 image hash.
    pub authenticode_sha256: Option<Digest>,
    /// The Authenticode SHA-1 image hash.
    pub authenticode_sha1: Option<Digest>,
    /// The flat SHA-256.
    pub flat_sha256: Option<Digest>,
    /// The flat SHA-1.
    pub flat_sha1: Option<Digest>,
}

impl FileDigests {
    /// The digests to look up for a file, from its Authenticode image hash
    /// (if it is a PE image) and its flat hashes.
    ///
    /// The Authenticode digests are left out when the image is not
    /// conformant (#47): such a digest is not authoritative, so it must
    /// not match a catalog, just as it never makes an embedded signature
    /// valid. The flat digests are left out for an empty file, whose
    /// digest is never a file identity.
    #[must_use]
    pub fn from_hashes(
        authenticode: Option<&AuthenticodeHashes>,
        flat: Option<&FlatHashes>,
    ) -> Self {
        let image = authenticode.filter(|a| a.status.is_conformant());
        let flat = flat.filter(|f| !f.empty);
        Self {
            authenticode_sha256: image.and_then(|a| a.get(HashAlgorithm::Sha256)).cloned(),
            authenticode_sha1: image.and_then(|a| a.get(HashAlgorithm::Sha1)).cloned(),
            flat_sha256: flat.and_then(|f| f.get(HashAlgorithm::Sha256)).cloned(),
            flat_sha1: flat.and_then(|f| f.get(HashAlgorithm::Sha1)).cloned(),
        }
    }

    /// Computes the digests of `data`: the Authenticode hashes if it parses
    /// as a PE image, and the flat hashes.
    #[must_use]
    pub fn of_bytes(data: &[u8]) -> Self {
        let image = hash_pe(data, AlgorithmSet::EMPTY);
        let flat = hash_bytes(data, AlgorithmSet::SHA256 | AlgorithmSet::SHA1);
        Self::from_hashes(image.as_ref(), Some(&flat))
    }

    fn in_order(&self) -> [(DigestKind, Option<&Digest>); 4] {
        [
            (
                DigestKind::AuthenticodeSha256,
                self.authenticode_sha256.as_ref(),
            ),
            (
                DigestKind::AuthenticodeSha1,
                self.authenticode_sha1.as_ref(),
            ),
            (DigestKind::FlatSha256, self.flat_sha256.as_ref()),
            (DigestKind::FlatSha1, self.flat_sha1.as_ref()),
        ]
    }
}

/// A catalog that lists a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogMatch<'a> {
    /// The catalog: an index into [`CatalogStore::records`].
    pub catalog: usize,
    /// The catalog's record.
    pub record: &'a CatalogRecord,
    /// The catalog's signer. Always present: only catalogs with a valid
    /// signature are indexed.
    pub signer: Option<&'a CatalogSigner>,
    /// The member's position in the catalog's trust list.
    pub member: usize,
    /// Which digest matched.
    pub matched_by: DigestKind,
}

impl CatalogMatch<'_> {
    /// Whether the catalog's signer is trusted.
    #[must_use]
    pub const fn trusted(&self) -> bool {
        self.record.trusted
    }

    /// Whether the match rests on SHA-1 anywhere: the member digest that
    /// matched, or the catalog's own signature. **Not collision
    /// resistant**: no allow decision may rest on such a match alone (ADR
    /// 0008).
    #[must_use]
    pub fn relies_on_sha1(&self) -> bool {
        self.matched_by.is_sha1() || !self.signature_is_sha2()
    }

    fn signature_is_sha2(&self) -> bool {
        self.record
            .signature_digest_alg
            .is_some_and(DigestAlgorithm::is_sha2)
    }
}

/// The result of [`CatalogStore::lookup`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LookupResult<'a> {
    /// Each catalog that lists the file, once, by its best matching
    /// digest: trusted catalogs first, then by [`DigestKind`] order, then
    /// SHA-2-signed catalogs before SHA-1-signed ones, then in load order.
    /// At most [`MAX_MATCHES`].
    pub matches: Vec<CatalogMatch<'a>>,
    /// Whether more catalogs matched than [`MAX_MATCHES`].
    pub truncated: bool,
}

/// One index entry: a member digest and where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Entry<const N: usize> {
    digest: [u8; N],
    catalog: u32,
    member: u32,
    pe_image: bool,
}

/// A sorted list of entries for one digest length.
#[derive(Debug, Clone, Default)]
struct Index<const N: usize>(Vec<Entry<N>>);

impl<const N: usize> Index<N> {
    fn find(&self, digest: &[u8]) -> &[Entry<N>] {
        let Ok(key) = <[u8; N]>::try_from(digest) else {
            return &[];
        };
        let start = self.0.partition_point(|e| e.digest < key);
        let len = self
            .0
            .get(start..)
            .unwrap_or_default()
            .partition_point(|e| e.digest == key);
        self.0
            .get(start..start.saturating_add(len))
            .unwrap_or_default()
    }
}

/// Loads catalogs into a [`CatalogStore`].
#[derive(Debug, Clone, Default)]
pub struct CatalogStoreBuilder {
    limits: StoreLimits,
    trust: [TrustConfig; CatalogSource::COUNT],
    records: Vec<CatalogRecord>,
    signers: Vec<CatalogSigner>,
    /// Signers by the SHA-256 of what decides their chain.
    signer_keys: BTreeMap<Vec<u8>, usize>,
    /// Bumped by every [`Self::trust`] call, so a signer decided under an
    /// earlier configuration is never reused.
    generation: u64,
    seen: BTreeSet<(CatalogSource, Digest)>,
    sha256: Index<32>,
    sha1: Index<20>,
    members: usize,
    bytes: u64,
}

impl CatalogStoreBuilder {
    /// A builder with `limits`, trusting nothing until
    /// [`Self::trust`] is called.
    #[must_use]
    pub fn new(limits: StoreLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Sets the trust configuration for catalogs from `source` loaded
    /// after this call. A source with none trusts nothing.
    #[must_use]
    pub fn trust(mut self, source: CatalogSource, config: TrustConfig) -> Self {
        if let Some(slot) = self.trust.get_mut(source.index()) {
            *slot = config;
        }
        self.generation = self.generation.saturating_add(1);
        self
    }

    /// Loads one catalog from `bytes`. `path` is recorded, for reports.
    pub fn add_bytes(
        &mut self,
        source: CatalogSource,
        path: Option<PathBuf>,
        bytes: &[u8],
    ) -> LoadReport {
        let mut report = LoadReport::default();
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.admit(source, path.as_ref(), size, &mut report) {
            self.bytes = self.bytes.saturating_add(size);
            let parsed = super::parse_catalog(bytes);
            self.record(source, path, size, parsed, Some(bytes), &mut report);
        }
        report
    }

    /// Loads the catalog file at `path`. Its length is checked against
    /// the size and byte limits before anything is read, and at most that
    /// many bytes are read.
    pub fn add_file(&mut self, source: CatalogSource, path: &Path) -> LoadReport {
        let mut report = LoadReport::default();
        if self.full() {
            report.error(LoadError::CatalogLimit);
            return report;
        }
        let Some(file) = open_regular(path, &mut report) else {
            return report;
        };
        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                report.error(LoadError::Io {
                    path: path.to_owned(),
                    kind: e.kind(),
                });
                return report;
            }
        };
        let path_buf = path.to_owned();
        if !self.admit(source, Some(&path_buf), size, &mut report) {
            return report;
        }
        // One byte more than the length, to notice a file that grew.
        let mut bytes = Vec::new();
        if let Err(e) = file.take(size.saturating_add(1)).read_to_end(&mut bytes) {
            report.error(LoadError::Io {
                path: path_buf,
                kind: e.kind(),
            });
            return report;
        }
        let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(read);
        if read != size {
            report.error(LoadError::Changed(path_buf));
            return report;
        }
        let parsed = super::parse_catalog(&bytes);
        self.record(
            source,
            Some(path_buf),
            size,
            parsed,
            Some(&bytes),
            &mut report,
        );
        report
    }

    /// Loads every `*.cat` file (any case) under `root`, descending at most
    /// [`StoreLimits::max_depth`] levels. Symbolic links (and other reparse
    /// points the OS reports as links) are not followed. Entries are read
    /// in name order, so the result does not depend on the directory's
    /// order.
    ///
    /// For the OS layout, load `catroot` (its `{GUID}` folders) as
    /// [`CatalogSource::System`] and `DriverStore\FileRepository` as
    /// [`CatalogSource::DriverStore`]. An exported catalog folder for
    /// offline analysis loads the same way.
    pub fn add_dir(&mut self, source: CatalogSource, root: &Path) -> LoadReport {
        let mut report = LoadReport::default();
        let mut entries_seen = 0_usize;
        let mut stack = vec![(root.to_owned(), 0_usize)];
        while let Some((dir, depth)) = stack.pop() {
            let listing = match std::fs::read_dir(&dir) {
                Ok(listing) => listing,
                Err(e) => {
                    report.error(LoadError::Io {
                        path: dir,
                        kind: e.kind(),
                    });
                    continue;
                }
            };
            let mut files = Vec::new();
            let mut dirs = Vec::new();
            for entry in listing {
                entries_seen = entries_seen.saturating_add(1);
                if entries_seen > self.limits.max_dir_entries {
                    report.error(LoadError::EntryLimit);
                    return report;
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        report.error(LoadError::Io {
                            path: dir.clone(),
                            kind: e.kind(),
                        });
                        continue;
                    }
                };
                let path = entry.path();
                // `DirEntry::file_type` does not follow symbolic links.
                match entry.file_type() {
                    Ok(t) if t.is_dir() => dirs.push(path),
                    Ok(t) if t.is_file() => files.push(path),
                    Ok(_) => {}
                    Err(e) => report.error(LoadError::Io {
                        path,
                        kind: e.kind(),
                    }),
                }
            }
            files.sort();
            for path in files {
                if !has_cat_extension(&path) {
                    report.skipped = report.skipped.saturating_add(1);
                    continue;
                }
                if self.full() {
                    report.error(LoadError::CatalogLimit);
                    return report;
                }
                if self.remaining_bytes() == 0 {
                    report.error(LoadError::ByteLimit);
                    return report;
                }
                report.merge(self.add_file(source, &path));
            }
            dirs.sort();
            if depth >= self.limits.max_depth {
                for path in dirs {
                    report.error(LoadError::DepthLimit(path));
                }
            } else {
                // Reversed, so the stack pops them in name order.
                for path in dirs.into_iter().rev() {
                    stack.push((path, depth.saturating_add(1)));
                }
            }
        }
        report
    }

    /// Finishes loading.
    #[must_use]
    pub fn build(mut self) -> CatalogStore {
        self.sha256.0.sort_unstable();
        self.sha1.0.sort_unstable();
        CatalogStore {
            records: self.records,
            signers: self.signers,
            sha256: self.sha256,
            sha1: self.sha1,
        }
    }

    fn full(&self) -> bool {
        self.records.len() >= self.limits.max_catalogs
    }

    /// The bytes left in the [`StoreLimits::max_total_bytes`] budget.
    fn remaining_bytes(&self) -> u64 {
        self.limits.max_total_bytes.saturating_sub(self.bytes)
    }

    /// Checks the catalog, size and byte limits for a catalog of `size`
    /// bytes, before it is read. A catalog over the size limit is recorded
    /// as unreadable (with its real size) and not read; one that does not
    /// fit the byte budget is not recorded.
    fn admit(
        &mut self,
        source: CatalogSource,
        path: Option<&PathBuf>,
        size: u64,
        report: &mut LoadReport,
    ) -> bool {
        if self.full() {
            report.error(LoadError::CatalogLimit);
            return false;
        }
        let limit = self.limits.max_catalog_size.min(MAX_CATALOG_SIZE);
        if size > limit {
            report.error(LoadError::TooLarge {
                path: path.cloned(),
                size,
            });
            self.record(
                source,
                path.cloned(),
                size,
                Err(CatalogError::TooLarge(size)),
                None,
                report,
            );
            return false;
        }
        if size > self.remaining_bytes() {
            report.error(LoadError::ByteLimit);
            return false;
        }
        true
    }

    fn record(
        &mut self,
        source: CatalogSource,
        path: Option<PathBuf>,
        size: u64,
        parsed: Result<Catalog, CatalogError>,
        bytes: Option<&[u8]>,
        report: &mut LoadReport,
    ) {
        let catalog = match parsed {
            Ok(catalog) => catalog,
            Err(e) => {
                let id = bytes.and_then(|b| {
                    hash_bytes(b, AlgorithmSet::SHA256)
                        .get(HashAlgorithm::Sha256)
                        .cloned()
                });
                if let Some(id) = &id {
                    if !self.seen.insert((source, id.clone())) {
                        report.duplicates = report.duplicates.saturating_add(1);
                        return;
                    }
                }
                self.records.push(CatalogRecord {
                    id,
                    path,
                    source,
                    size,
                    status: CatalogStatus::Unreadable(e),
                    signer: None,
                    trusted: false,
                    member_count: 0,
                    indexed_members: 0,
                    index_truncated: false,
                    signature_digest_alg: None,
                    subject_algorithm: None,
                    os_attr: None,
                    this_update: None,
                    signing_time: None,
                    warnings: Vec::new(),
                });
                report.recorded = report.recorded.saturating_add(1);
                return;
            }
        };
        let Ok(catalog_index) = u32::try_from(self.records.len()) else {
            report.error(LoadError::CatalogLimit);
            return;
        };
        if !self.seen.insert((source, catalog.id.clone())) {
            report.duplicates = report.duplicates.saturating_add(1);
            return;
        }
        let valid = catalog.signature_valid();
        let signer = if valid {
            self.signer_of(source, &catalog)
        } else {
            None
        };
        let trusted = signer
            .and_then(|i| self.signers.get(i))
            .is_some_and(|s| s.trust.trusted);
        let mut indexed = 0_usize;
        let mut index_truncated = catalog.ctl.members_truncated;
        if valid {
            for (m, member) in catalog.ctl.members.iter().enumerate() {
                let Some(d) = &member.digest else { continue };
                if !matches!(d.alg, DigestAlgorithm::Sha256 | DigestAlgorithm::Sha1) {
                    continue;
                }
                if self.members >= self.limits.max_members {
                    report.error(LoadError::MemberLimit);
                    index_truncated = true;
                    break;
                }
                let Ok(m) = u32::try_from(m) else { break };
                let pe_image = d.is_pe_image();
                let pushed = match d.alg {
                    DigestAlgorithm::Sha256 => <[u8; 32]>::try_from(d.digest.as_slice())
                        .map(|digest| {
                            self.sha256.0.push(Entry {
                                digest,
                                catalog: catalog_index,
                                member: m,
                                pe_image,
                            });
                        })
                        .is_ok(),
                    _ => <[u8; 20]>::try_from(d.digest.as_slice())
                        .map(|digest| {
                            self.sha1.0.push(Entry {
                                digest,
                                catalog: catalog_index,
                                member: m,
                                pe_image,
                            });
                        })
                        .is_ok(),
                };
                if pushed {
                    indexed = indexed.saturating_add(1);
                    self.members = self.members.saturating_add(1);
                }
            }
        }
        let signature = catalog.signature();
        let status = match signature.map(|s| &s.status) {
            Some(SignatureStatus::Valid) => CatalogStatus::Valid,
            Some(other) => CatalogStatus::InvalidSignature(other.clone()),
            // `parse_catalog` always reports one signature.
            None => CatalogStatus::InvalidSignature(SignatureStatus::BadSignature(
                BadSignature::SignatureInvalid,
            )),
        };
        self.records.push(CatalogRecord {
            id: Some(catalog.id.clone()),
            path,
            source,
            size,
            status,
            signer,
            trusted,
            member_count: catalog.ctl.members.len(),
            indexed_members: indexed,
            index_truncated,
            signature_digest_alg: signature.and_then(|s| s.signer_digest_alg),
            subject_algorithm: Some(catalog.ctl.subject_algorithm.clone()),
            os_attr: catalog.ctl.os_attr().map(str::to_owned),
            this_update: Some(catalog.ctl.this_update),
            signing_time: signature
                .and_then(|s| s.signer.as_ref())
                .and_then(|a| a.signing_time),
            warnings: catalog.warnings,
        });
        report.recorded = report.recorded.saturating_add(1);
        if valid {
            report.valid = report.valid.saturating_add(1);
        }
    }
}

impl CatalogStoreBuilder {
    /// The signer of a catalog with a valid signature, shared with earlier
    /// catalogs whose chain is built from the same input.
    fn signer_of(&mut self, source: CatalogSource, catalog: &Catalog) -> Option<usize> {
        let sig = catalog.signature()?;
        let signer_cert = sig.signer.as_ref()?.signer_cert;
        // The verdict depends on the certificates, the signer's position
        // among them, the namespace's trust configuration, and the
        // signature's own digest algorithms (which `SignerTrust` reports
        // and ranks by).
        let mut key = self.generation.to_le_bytes().to_vec();
        key.push(u8::try_from(source.index()).unwrap_or(u8::MAX));
        key.extend(format!("{:?}/{:?};", sig.digest_alg, sig.signer_digest_alg).bytes());
        key.extend(u64::try_from(signer_cert).unwrap_or(u64::MAX).to_le_bytes());
        for cert in &sig.certs_in_blob {
            key.extend(u64::try_from(cert.len()).unwrap_or(u64::MAX).to_le_bytes());
            key.extend(cert);
        }
        let key = hash_bytes(&key, AlgorithmSet::SHA256)
            .get(HashAlgorithm::Sha256)
            .map(|d| d.as_bytes().to_vec())?;
        if let Some(index) = self.signer_keys.get(&key) {
            return Some(*index);
        }
        let config = self.trust.get(source.index())?;
        let report = catalog.trust(config);
        let trust = report.signers.into_iter().next()?;
        let index = self.signers.len();
        self.signers.push(CatalogSigner {
            source,
            trust,
            identity: report.identity,
        });
        self.signer_keys.insert(key, index);
        Some(index)
    }
}

/// Opens `path` for reading if it is a regular file, recording why not.
fn open_regular(path: &Path, report: &mut LoadReport) -> Option<std::fs::File> {
    let io_error = |e: io::Error| LoadError::Io {
        path: path.to_owned(),
        kind: e.kind(),
    };
    // `metadata` first: opening a directory fails on some OSes before
    // anything could be checked, with an OS-specific error.
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => {
            report.error(LoadError::NotAFile(path.to_owned()));
            return None;
        }
        Err(e) => {
            report.error(io_error(e));
            return None;
        }
    }
    let file = match crate::hash::open_without_blocking(path) {
        Ok(file) => file,
        Err(e) => {
            report.error(io_error(e));
            return None;
        }
    };
    // The path may have been replaced since `metadata`.
    match file.metadata() {
        Ok(m) if m.is_file() => Some(file),
        Ok(_) => {
            report.error(LoadError::NotAFile(path.to_owned()));
            None
        }
        Err(e) => {
            report.error(io_error(e));
            None
        }
    }
}

fn has_cat_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("cat"))
}

/// Loaded catalogs and the index of their members.
///
/// The index is in memory: 44 bytes per SHA-256 member and 32 per SHA-1
/// member, sorted for binary search. Only catalogs whose signature is
/// valid are indexed. Each distinct signer is kept once, with its chain.
#[derive(Debug, Clone, Default)]
pub struct CatalogStore {
    records: Vec<CatalogRecord>,
    signers: Vec<CatalogSigner>,
    sha256: Index<32>,
    sha1: Index<20>,
}

impl CatalogStore {
    /// Every catalog recorded, in load order.
    #[must_use]
    pub fn records(&self) -> &[CatalogRecord] {
        &self.records
    }

    /// Every distinct catalog signer.
    #[must_use]
    pub fn signers(&self) -> &[CatalogSigner] {
        &self.signers
    }

    /// How many members are indexed.
    #[must_use]
    pub fn indexed_members(&self) -> usize {
        self.sha256.0.len().saturating_add(self.sha1.0.len())
    }

    /// The catalogs, from any source, that list a file with `digests`.
    #[must_use]
    pub fn lookup(&self, digests: &FileDigests) -> LookupResult<'_> {
        self.lookup_in(
            digests,
            &[
                CatalogSource::System,
                CatalogSource::DriverStore,
                CatalogSource::Policy,
            ],
        )
    }

    /// The catalogs from `sources` that list a file with `digests`. The
    /// Authenticode SHA-256 is tried first, then the Authenticode SHA-1,
    /// the flat SHA-256 and the flat SHA-1. An Authenticode digest matches
    /// only PE members (`SPC_PE_IMAGE_DATA`), and a flat digest only other
    /// members.
    #[must_use]
    pub fn lookup_in(&self, digests: &FileDigests, sources: &[CatalogSource]) -> LookupResult<'_> {
        let mut found: Vec<(usize, usize, DigestKind)> = Vec::new();
        let mut seen = BTreeSet::new();
        for (kind, digest) in digests.in_order() {
            let Some(digest) = digest else { continue };
            // A digest is used only in the slot of its own algorithm, so a
            // SHA-1 digest can never be reported as a SHA-256 match.
            let hits: Box<dyn Iterator<Item = (u32, u32, bool)>> =
                match (kind.algorithm(), digest.algorithm()) {
                    (HashAlgorithm::Sha256, HashAlgorithm::Sha256) => Box::new(
                        self.sha256
                            .find(digest.as_bytes())
                            .iter()
                            .map(|e| (e.catalog, e.member, e.pe_image)),
                    ),
                    (HashAlgorithm::Sha1, HashAlgorithm::Sha1) => Box::new(
                        self.sha1
                            .find(digest.as_bytes())
                            .iter()
                            .map(|e| (e.catalog, e.member, e.pe_image)),
                    ),
                    _ => continue,
                };
            for (catalog, member, pe_image) in hits {
                if pe_image != kind.is_authenticode() {
                    continue;
                }
                let (Ok(catalog), Ok(member)) = (usize::try_from(catalog), usize::try_from(member))
                else {
                    continue;
                };
                let in_scope = self
                    .records
                    .get(catalog)
                    .is_some_and(|r| sources.contains(&r.source));
                // Each catalog once, by its first (best) match.
                if in_scope && seen.insert(catalog) {
                    found.push((catalog, member, kind));
                }
            }
        }
        let mut matches: Vec<CatalogMatch<'_>> = found
            .into_iter()
            .filter_map(|(catalog, member, matched_by)| {
                let record = self.records.get(catalog)?;
                Some(CatalogMatch {
                    catalog,
                    record,
                    signer: record.signer.and_then(|i| self.signers.get(i)),
                    member,
                    matched_by,
                })
            })
            .collect();
        // Trusted first, then by member digest, then SHA-2-signed catalogs
        // before SHA-1-signed ones, then load order.
        matches.sort_by_key(|m| {
            (
                !m.trusted(),
                m.matched_by,
                !m.signature_is_sha2(),
                m.catalog,
            )
        });
        let truncated = matches.len() > MAX_MATCHES;
        matches.truncate(MAX_MATCHES);
        LookupResult { matches, truncated }
    }
}
