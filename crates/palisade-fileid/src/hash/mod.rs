//! Whole-file ("flat") hashes, computed in one streaming pass (#46).
//!
//! [`MultiHasher`] feeds every chunk of input to each selected algorithm at
//! once, so a file is read a single time however many digests are needed.
//! [`hash_reader`] and [`hash_file`] drive it over any [`Read`] source with a
//! fixed-size buffer, so memory use does not grow with the file size.
//!
//! **SHA-256 is the primary identity.** SHA-1 and MD5 are **not collision
//! resistant**. They are computed only to match external lists, imported
//! policies and OS events, and must never be the sole basis of an allow
//! decision (ADR 0008). SHA-384 and SHA-512 are optional extras.
//!
//! The digest of an empty input is a well-known constant that any attacker
//! can produce, so [`FlatHashes::empty`] flags it and rules must never trust
//! it.
//!
//! The rest of #46 lives in submodules:
//!
//! - [`stamp`]: the [`FileKey`] that identifies one version of a file, and
//!   the [`FileStamp`] trait the OS backend implements to read it;
//! - [`cache`]: the [`HashCache`] (an LRU bounded by entries and bytes,
//!   with tiered, versioned values and MAC-protected persisted records), the
//!   [`HashVerifyMode`] policy setting and [`hash_through`], which ties
//!   them together and detects files that change while they are hashed;
//! - [`limit`]: [`HashLimiter`], the `max_parallel_hashes` bound;
//! - [`metrics`]: bytes hashed, cache hit ratio, average latency, and tamper
//!   and unstable-file counts, for health reporting (#67);
//! - [`skip_for_inventory`]: which files an inventory scan must not read,
//!   because reading them would recall them from cloud storage.

#![forbid(unsafe_code)]

pub mod cache;
pub mod limit;
mod mac;
pub mod metrics;
pub mod stamp;

pub use cache::{
    CacheConfig, CacheRecord, CacheValue, FileLocation, FlatTier, HashCache, HashVerifyMode,
    ImageTier, Miss, RecordError, Through, ThroughError, ValueSource, hash_through,
};
pub use limit::{HashLimiter, HashPermit, default_max_parallel_hashes};
pub use mac::{MAC_LEN, MIN_KEY_LEN, MacKey, MacKeyTooShort};
pub use metrics::{HashMetrics, HashMetricsSnapshot};
pub use stamp::{FileKey, FileStamp, FileTime};

use std::fmt;
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::ops::{BitOr, BitOrAssign};
use std::path::Path;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

/// A flat-hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashAlgorithm {
    /// SHA-256, the primary file identity.
    Sha256,
    /// SHA-1. Interop only: **not collision resistant**.
    Sha1,
    /// MD5. Interop only: **not collision resistant**.
    Md5,
    /// SHA-384 (optional).
    Sha384,
    /// SHA-512 (optional).
    Sha512,
}

impl HashAlgorithm {
    /// Every algorithm, in the order digests are reported.
    pub const ALL: [Self; 5] = [
        Self::Sha256,
        Self::Sha1,
        Self::Md5,
        Self::Sha384,
        Self::Sha512,
    ];

    /// The digest length in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha1 => 20,
            Self::Md5 => 16,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// A lowercase name such as `"sha256"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha1 => "sha1",
            Self::Md5 => "md5",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// Whether the algorithm is collision resistant. `false` for SHA-1 and
    /// MD5, which must never be the only identity behind an allow decision.
    #[must_use]
    pub const fn is_collision_resistant(self) -> bool {
        !matches!(self, Self::Sha1 | Self::Md5)
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Sha256 => 1,
            Self::Sha1 => 1 << 1,
            Self::Md5 => 1 << 2,
            Self::Sha384 => 1 << 3,
            Self::Sha512 => 1 << 4,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of [`HashAlgorithm`]s, stored as bit flags.
///
/// Issue #46 calls this `HashSet`. It is named `AlgorithmSet` so it does not
/// shadow `std::collections::HashSet`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlgorithmSet(u8);

impl AlgorithmSet {
    /// No algorithms.
    pub const EMPTY: Self = Self(0);
    /// SHA-256 only.
    pub const SHA256: Self = Self(HashAlgorithm::Sha256.bit());
    /// SHA-1 only.
    pub const SHA1: Self = Self(HashAlgorithm::Sha1.bit());
    /// MD5 only.
    pub const MD5: Self = Self(HashAlgorithm::Md5.bit());
    /// SHA-384 only.
    pub const SHA384: Self = Self(HashAlgorithm::Sha384.bit());
    /// SHA-512 only.
    pub const SHA512: Self = Self(HashAlgorithm::Sha512.bit());
    /// Every algorithm.
    pub const ALL: Self = Self(0b1_1111);
    /// The default set: SHA-256, SHA-1 and MD5.
    pub const DEFAULT: Self = Self(Self::SHA256.0 | Self::SHA1.0 | Self::MD5.0);

    /// Whether `alg` is in the set.
    #[must_use]
    pub const fn contains(self, alg: HashAlgorithm) -> bool {
        self.0 & alg.bit() != 0
    }

    /// Adds `alg` to the set.
    pub fn insert(&mut self, alg: HashAlgorithm) {
        self.0 |= alg.bit();
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The algorithms in the set, in [`HashAlgorithm::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = HashAlgorithm> {
        HashAlgorithm::ALL
            .into_iter()
            .filter(move |alg| self.contains(*alg))
    }
}

impl Default for AlgorithmSet {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl BitOr for AlgorithmSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for AlgorithmSet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl From<HashAlgorithm> for AlgorithmSet {
    fn from(alg: HashAlgorithm) -> Self {
        Self(alg.bit())
    }
}

impl FromIterator<HashAlgorithm> for AlgorithmSet {
    fn from_iter<I: IntoIterator<Item = HashAlgorithm>>(iter: I) -> Self {
        let mut set = Self::EMPTY;
        for alg in iter {
            set.insert(alg);
        }
        set
    }
}

impl fmt::Debug for AlgorithmSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// A digest: the algorithm and the raw bytes, whose length always matches
/// [`HashAlgorithm::digest_len`].
///
/// `Display` prints lowercase hex. [`Digest::parse`] accepts upper- or
/// lowercase hex with an optional `0x` prefix.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest {
    alg: HashAlgorithm,
    bytes: Vec<u8>,
}

impl Digest {
    /// Builds a digest from raw bytes, checking the length.
    pub fn new(alg: HashAlgorithm, bytes: &[u8]) -> Result<Self, DigestError> {
        if bytes.len() != alg.digest_len() {
            return Err(DigestError::WrongLength {
                alg,
                expected: alg.digest_len(),
                actual: bytes.len(),
            });
        }
        Ok(Self {
            alg,
            bytes: bytes.to_vec(),
        })
    }

    /// Parses a hex digest for `alg`. Upper- and lowercase hex are accepted,
    /// with an optional `0x` or `0X` prefix. Anything else, including
    /// whitespace, is rejected.
    pub fn parse(alg: HashAlgorithm, text: &str) -> Result<Self, DigestError> {
        let hex = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        let expected = alg.digest_len().saturating_mul(2);
        if hex.len() != expected {
            return Err(DigestError::WrongHexLength {
                alg,
                expected,
                actual: hex.len(),
            });
        }
        let mut bytes = Vec::with_capacity(alg.digest_len());
        for (pair_index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let index = pair_index.saturating_mul(2);
            let &[hi, lo] = pair else {
                return Err(DigestError::InvalidHex { index });
            };
            let hi = hex_value(hi).ok_or(DigestError::InvalidHex { index })?;
            let lo = hex_value(lo).ok_or(DigestError::InvalidHex {
                index: index.saturating_add(1),
            })?;
            bytes.push((hi << 4) | lo);
        }
        Ok(Self { alg, bytes })
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.alg
    }

    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{self}", self.alg)
    }
}

const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Why a digest could not be built or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestError {
    /// Raw digest bytes of the wrong length were given to [`Digest::new`].
    WrongLength {
        /// The algorithm the digest was for.
        alg: HashAlgorithm,
        /// The expected length in bytes.
        expected: usize,
        /// The length supplied, in bytes.
        actual: usize,
    },
    /// Hex text of the wrong length was given to [`Digest::parse`]. Lengths
    /// count hex characters (bytes of the text), after any `0x` prefix.
    WrongHexLength {
        /// The algorithm the digest was for.
        alg: HashAlgorithm,
        /// The expected number of hex characters.
        expected: usize,
        /// The number supplied.
        actual: usize,
    },
    /// A character that is not a hex digit, at this index of the hex text
    /// (after any `0x` prefix).
    InvalidHex {
        /// Index of the bad character.
        index: usize,
    },
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength {
                alg,
                expected,
                actual,
            } => write!(f, "{alg} digest must be {expected} bytes, got {actual}"),
            Self::WrongHexLength {
                alg,
                expected,
                actual,
            } => write!(
                f,
                "{alg} digest must be {expected} hex digits, got {actual} characters"
            ),
            Self::InvalidHex { index } => write!(f, "invalid hex digit at index {index}"),
        }
    }
}

impl std::error::Error for DigestError {}

/// The flat hashes of one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatHashes {
    /// Number of bytes hashed.
    pub size: u64,
    /// The input was empty, so every digest is the well-known empty digest.
    /// Rules must never trust such a digest as a file identity.
    pub empty: bool,
    /// One digest per selected algorithm, in [`HashAlgorithm::ALL`] order.
    pub digests: Vec<Digest>,
}

impl FlatHashes {
    /// The digest for `alg`, if it was computed.
    #[must_use]
    pub fn get(&self, alg: HashAlgorithm) -> Option<&Digest> {
        self.digests.iter().find(|d| d.alg == alg)
    }
}

/// Feeds input to several hash algorithms in a single pass.
///
/// Call [`update`](Self::update) with consecutive chunks, then
/// [`finalize`](Self::finalize). The result does not depend on how the
/// input is split into chunks.
#[derive(Clone)]
pub struct MultiHasher {
    sha256: Option<Sha256>,
    sha1: Option<Sha1>,
    md5: Option<Md5>,
    sha384: Option<Sha384>,
    sha512: Option<Sha512>,
    size: u64,
}

impl MultiHasher {
    /// A hasher for the algorithms in `set`.
    #[must_use]
    pub fn new(set: AlgorithmSet) -> Self {
        Self {
            sha256: set.contains(HashAlgorithm::Sha256).then(Sha256::new),
            sha1: set.contains(HashAlgorithm::Sha1).then(Sha1::new),
            md5: set.contains(HashAlgorithm::Md5).then(Md5::new),
            sha384: set.contains(HashAlgorithm::Sha384).then(Sha384::new),
            sha512: set.contains(HashAlgorithm::Sha512).then(Sha512::new),
            size: 0,
        }
    }

    /// Feeds the next chunk of input.
    pub fn update(&mut self, chunk: &[u8]) {
        if let Some(h) = &mut self.sha256 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha1 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.md5 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha384 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha512 {
            h.update(chunk);
        }
        let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        self.size = self.size.saturating_add(len);
    }

    /// Bytes fed so far.
    #[must_use]
    pub const fn bytes_hashed(&self) -> u64 {
        self.size
    }

    /// Finishes every hash.
    #[must_use]
    pub fn finalize(self) -> FlatHashes {
        // Each output has exactly the algorithm's length, so building the
        // `Digest` directly keeps the length invariant.
        let mut digests = Vec::with_capacity(5);
        if let Some(h) = self.sha256 {
            digests.push(finished(HashAlgorithm::Sha256, &h.finalize()));
        }
        if let Some(h) = self.sha1 {
            digests.push(finished(HashAlgorithm::Sha1, &h.finalize()));
        }
        if let Some(h) = self.md5 {
            digests.push(finished(HashAlgorithm::Md5, &h.finalize()));
        }
        if let Some(h) = self.sha384 {
            digests.push(finished(HashAlgorithm::Sha384, &h.finalize()));
        }
        if let Some(h) = self.sha512 {
            digests.push(finished(HashAlgorithm::Sha512, &h.finalize()));
        }
        FlatHashes {
            size: self.size,
            empty: self.size == 0,
            digests,
        }
    }
}

fn finished(alg: HashAlgorithm, out: &[u8]) -> Digest {
    debug_assert_eq!(out.len(), alg.digest_len());
    Digest {
        alg,
        bytes: out.to_vec(),
    }
}

impl fmt::Debug for MultiHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = AlgorithmSet::EMPTY;
        if self.sha256.is_some() {
            set.insert(HashAlgorithm::Sha256);
        }
        if self.sha1.is_some() {
            set.insert(HashAlgorithm::Sha1);
        }
        if self.md5.is_some() {
            set.insert(HashAlgorithm::Md5);
        }
        if self.sha384.is_some() {
            set.insert(HashAlgorithm::Sha384);
        }
        if self.sha512.is_some() {
            set.insert(HashAlgorithm::Sha512);
        }
        f.debug_struct("MultiHasher")
            .field("algorithms", &set)
            .field("bytes_hashed", &self.size)
            .finish()
    }
}

/// Hashes an in-memory buffer.
#[must_use]
pub fn hash_bytes(data: &[u8], set: AlgorithmSet) -> FlatHashes {
    let mut hasher = MultiHasher::new(set);
    hasher.update(data);
    hasher.finalize()
}

/// Smallest allowed read buffer: 64 KiB.
pub const MIN_BUFFER_SIZE: usize = 64 * 1024;
/// Largest allowed read buffer: 8 MiB.
pub const MAX_BUFFER_SIZE: usize = 8 * 1024 * 1024;
/// Default read buffer: 1 MiB.
pub const DEFAULT_BUFFER_SIZE: usize = 1024 * 1024;
/// Default size limit: 4 GiB.
pub const DEFAULT_MAX_HASH_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Options for [`hash_reader`] and [`hash_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashOptions {
    /// Algorithms to compute. Defaults to [`AlgorithmSet::DEFAULT`].
    pub algorithms: AlgorithmSet,
    /// Read buffer size in bytes, from [`MIN_BUFFER_SIZE`] to
    /// [`MAX_BUFFER_SIZE`]. Defaults to [`DEFAULT_BUFFER_SIZE`].
    pub buffer_size: usize,
    /// Inputs larger than this many bytes are not hashed and return
    /// [`HashStatus::TooLarge`]. Defaults to [`DEFAULT_MAX_HASH_SIZE`].
    pub max_hash_size: u64,
}

impl Default for HashOptions {
    fn default() -> Self {
        Self {
            algorithms: AlgorithmSet::DEFAULT,
            buffer_size: DEFAULT_BUFFER_SIZE,
            max_hash_size: DEFAULT_MAX_HASH_SIZE,
        }
    }
}

impl HashOptions {
    pub(crate) fn validate(&self) -> Result<(), HashError> {
        if !(MIN_BUFFER_SIZE..=MAX_BUFFER_SIZE).contains(&self.buffer_size) {
            return Err(HashError::InvalidBufferSize(self.buffer_size));
        }
        if self.algorithms.is_empty() {
            return Err(HashError::NoAlgorithms);
        }
        Ok(())
    }
}

/// The outcome of hashing a file or stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashStatus {
    /// Every selected digest was computed.
    Complete(FlatHashes),
    /// The input is larger than [`HashOptions::max_hash_size`], so it was not
    /// hashed. No digest is returned, because a digest of a prefix would be
    /// a wrong identity.
    TooLarge {
        /// The configured limit, in bytes.
        limit: u64,
    },
    /// The file was not read, on purpose. See [`skip_for_inventory`].
    Deferred(DeferReason),
    /// The file kept changing while it was hashed, on every attempt, so no
    /// digest describes it. See [`cache::hash_through`].
    Unstable,
}

/// Why a file was not hashed ([`HashStatus::Deferred`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeferReason {
    /// The file is a cloud placeholder (offline, or recalled on access).
    /// Reading it would download it, so an inventory scan leaves it.
    CloudPlaceholder,
}

/// `FILE_ATTRIBUTE_OFFLINE`.
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
/// `FILE_ATTRIBUTE_RECALL_ON_OPEN`.
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
/// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`.
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

/// Why hashing is happening, which decides whether a cloud placeholder may
/// be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashPurpose {
    /// A background inventory scan (#60). Placeholders are skipped.
    Inventory,
    /// An execution decision. The OS recalls the file to run it anyway, so
    /// it is always hashed.
    Execution,
}

/// Whether a file with these Windows file attributes must be left unread,
/// and why: `Some(DeferReason::CloudPlaceholder)` for an offline or
/// recall-on-access file during an inventory scan, `None` otherwise.
///
/// The attributes come from the OS backend (#54). Sparse files are not
/// skipped on their own: a sparse file that is not a placeholder reads
/// locally.
#[must_use]
pub const fn skip_for_inventory(attributes: u32, purpose: HashPurpose) -> Option<DeferReason> {
    let placeholder = attributes
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0;
    match purpose {
        HashPurpose::Inventory if placeholder => Some(DeferReason::CloudPlaceholder),
        _ => None,
    }
}

/// Why hashing failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum HashError {
    /// [`HashOptions::buffer_size`] is outside 64 KiB to 8 MiB.
    InvalidBufferSize(usize),
    /// [`HashOptions::algorithms`] is empty.
    NoAlgorithms,
    /// The path is not a regular file (a directory, pipe or device).
    NotAFile,
    /// The input did not have the length its metadata gave: the file grew
    /// or shrank while it was read, so its digests would describe no single
    /// version of it.
    SizeChanged {
        /// The length the metadata gave.
        expected: u64,
        /// The bytes actually read (when the file grew, as soon as that
        /// was seen).
        actual: u64,
    },
    /// Reading the input failed.
    Io(io::Error),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBufferSize(size) => write!(
                f,
                "hash buffer size {size} is outside {MIN_BUFFER_SIZE}..={MAX_BUFFER_SIZE} bytes"
            ),
            Self::NoAlgorithms => f.write_str("no hash algorithms selected"),
            Self::NotAFile => f.write_str("not a regular file"),
            Self::SizeChanged { expected, actual } => write!(
                f,
                "file changed size while being hashed: expected {expected} bytes, read {actual}"
            ),
            Self::Io(e) => write!(f, "read failed while hashing: {e}"),
        }
    }
}

impl std::error::Error for HashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for HashError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Hashes everything `reader` yields, in one pass, with a buffer of
/// [`HashOptions::buffer_size`] bytes.
///
/// Reading stops as soon as more than [`HashOptions::max_hash_size`] bytes
/// have been seen, and the result is [`HashStatus::TooLarge`]. Reads that
/// fail with [`ErrorKind::Interrupted`] are retried.
pub fn hash_reader<R: Read>(mut reader: R, options: &HashOptions) -> Result<HashStatus, HashError> {
    options.validate()?;
    let mut buffer = vec![0_u8; options.buffer_size];
    let mut hasher = MultiHasher::new(options.algorithms);
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(HashError::Io(e)),
        };
        let chunk = buffer.get(..n).ok_or_else(|| {
            HashError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "reader reported more bytes than the buffer holds",
            ))
        })?;
        let len = u64::try_from(n).unwrap_or(u64::MAX);
        let over = hasher
            .bytes_hashed()
            .checked_add(len)
            .is_none_or(|total| total > options.max_hash_size);
        if over {
            return Ok(HashStatus::TooLarge {
                limit: options.max_hash_size,
            });
        }
        hasher.update(chunk);
    }
    Ok(HashStatus::Complete(hasher.finalize()))
}

/// Hashes the file at `path` (its default data stream).
///
/// Anything that is not a regular file (a directory, pipe or device) returns
/// [`HashError::NotAFile`]. The opened handle is what is checked and hashed,
/// and it is opened without blocking, so replacing the path with a pipe,
/// even after the path check, cannot stall the call. A file whose metadata
/// length is over the limit returns [`HashStatus::TooLarge`] without reading
/// any content. The limit is also
/// enforced while reading, in case the file grows.
///
/// The file is opened with [`File::open`]. On Windows its default share mode
/// already lets other processes read, write and delete the file while it is
/// hashed. This portable version does not add `FILE_FLAG_SEQUENTIAL_SCAN`,
/// skip cloud placeholders, or detect concurrent modification. The Windows
/// backend does (`palisade_fileid::win::file`, with the `os-trust`
/// feature): `open_for_hashing`, `hash_open_file` and `WinStamps` with
/// [`cache::hash_through`].
pub fn hash_file(path: &Path, options: &HashOptions) -> Result<HashStatus, HashError> {
    options.validate()?;
    // Pipes, devices and directories have no stable content to identify.
    // The path is checked first, for a clear error (on Windows a directory
    // cannot be opened as a file at all). It can be replaced after this
    // check, so the open itself must not block and the opened handle is
    // checked again: only the handle decides what is hashed.
    if !std::fs::metadata(path)?.is_file() {
        return Err(HashError::NotAFile);
    }
    let file = open_without_blocking(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(HashError::NotAFile);
    }
    if metadata.len() > options.max_hash_size {
        return Ok(HashStatus::TooLarge {
            limit: options.max_hash_size,
        });
    }
    hash_reader(file, options)
}

/// Opens `path` for reading without waiting on a FIFO.
///
/// On Unix, opening a FIFO for reading blocks until a writer appears unless
/// `O_NONBLOCK` is set. The flag has no effect on reads from a regular file,
/// which is the only kind of handle [`hash_file`] goes on to read. Opening a
/// named pipe on Windows does not wait for the server, so no flag is needed
/// there.
pub(crate) fn open_without_blocking(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_defaults_and_iteration_order() {
        let set = AlgorithmSet::default();
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha1,
                HashAlgorithm::Md5
            ]
        );
        assert_eq!(AlgorithmSet::ALL.iter().count(), 5);
        assert!(AlgorithmSet::EMPTY.is_empty());
        let built: AlgorithmSet = [HashAlgorithm::Sha512, HashAlgorithm::Sha256]
            .into_iter()
            .collect();
        assert_eq!(built, AlgorithmSet::SHA256 | AlgorithmSet::SHA512);
        assert_eq!(format!("{built:?}"), "{Sha256, Sha512}");
    }

    #[test]
    fn collision_resistance_flags() {
        assert!(HashAlgorithm::Sha256.is_collision_resistant());
        assert!(HashAlgorithm::Sha384.is_collision_resistant());
        assert!(HashAlgorithm::Sha512.is_collision_resistant());
        assert!(!HashAlgorithm::Sha1.is_collision_resistant());
        assert!(!HashAlgorithm::Md5.is_collision_resistant());
    }

    #[test]
    fn hex_values() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'f'), Some(15));
        assert_eq!(hex_value(b'F'), Some(15));
        assert_eq!(hex_value(b'g'), None);
    }

    /// The state just after a path that passed the file check is swapped for
    /// a FIFO: the open must return at once, and the handle check must then
    /// reject it.
    #[cfg(unix)]
    #[test]
    fn open_does_not_block_on_a_swapped_in_fifo() {
        let dir = std::env::temp_dir().join(format!("palisade-fileid-race-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let opened = open_without_blocking(&path).and_then(|f| f.metadata());
            let _ = tx.send(opened.map(|m| m.is_file()));
        });
        let is_file = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("opening a FIFO blocked")
            .unwrap();
        assert!(!is_file);
        // A regular file still opens and reads normally.
        let file = dir.join("data");
        std::fs::write(&file, b"abc").unwrap();
        let mut text = String::new();
        open_without_blocking(&file)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "abc");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn options_are_validated() {
        let mut opts = HashOptions {
            buffer_size: MIN_BUFFER_SIZE - 1,
            ..HashOptions::default()
        };
        assert!(matches!(
            hash_reader(&b""[..], &opts),
            Err(HashError::InvalidBufferSize(_))
        ));
        opts.buffer_size = MAX_BUFFER_SIZE + 1;
        assert!(matches!(
            hash_reader(&b""[..], &opts),
            Err(HashError::InvalidBufferSize(_))
        ));
        opts.buffer_size = MIN_BUFFER_SIZE;
        opts.algorithms = AlgorithmSet::EMPTY;
        assert!(matches!(
            hash_reader(&b""[..], &opts),
            Err(HashError::NoAlgorithms)
        ));
    }
}
