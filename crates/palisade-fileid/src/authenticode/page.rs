//! Authenticode page hashes (#47).
//!
//! A signer can put a table of page hashes in an Authenticode signature
//! (an `SpcSerializedObject` in the signed `SpcPeImageData`: version 1 for
//! SHA-1, version 2 for SHA-256). The OS can then check each page of the
//! file as it maps it, instead of hashing the whole image first. This module
//! builds that table from a file, checks a signed table against a file, and
//! gives the single "page hash" value OS policy hash rules use.
//!
//! # How the table is built
//!
//! Pages are 4 KiB ([`PAGE_SIZE`]). Each entry is a page's file offset (a
//! little-endian `u32`) and the digest of its bytes, zero-padded to 4 KiB:
//!
//! 1. **The header page**, at offset 0: the bytes from 0 to `SizeOfHeaders`,
//!    minus the `CheckSum` field and the certificate table entry (the two
//!    header fields the image hash leaves out too), then zeros up to 4 KiB.
//!    The 12 excluded bytes are dropped, not zeroed, so 4,084 bytes are
//!    hashed.
//! 2. **Section pages**: for each section with raw data, in section table
//!    order (which must also be file order), one entry every 4 KiB from
//!    `PointerToRawData` to `PointerToRawData + SizeOfRawData`. A section's
//!    last page stops at its end and is zero-padded.
//! 3. **A final entry** at the end of the last section's data (or at
//!    `SizeOfHeaders` when no section has raw data), with an all-zero
//!    digest.
//!
//! The tests check this against page hash tables that an open-source
//! signer made over synthetic images (`tests/fixtures/page_hash`).
//!
//! # When there is no table
//!
//! A page table says where each page's bytes are, so it is only built for
//! an image whose layout conforms to the Authenticode specification (see
//! [`super::hash`]) and whose headers fit in one page. Anything else is a
//! [`PageHashError`], never a best-effort table: a guessed table would make
//! rules that silently never match.
//!
//! # Checking a signed table
//!
//! [`verify_page_hashes`] compares a signature's table with the file and
//! reports the first entry that does not match. A signed table is only as
//! trustworthy as the signature that carries it, so
//! [`verify_signature_page_hashes`] checks only tables from signatures that
//! verify cryptographically. That includes signatures whose image digest no
//! longer matches the file: the page check then names the first page that
//! changed.
//!
//! # The code integrity "page hash" rule value
//!
//! For each file, OS policy tooling emits two single-value "page hash"
//! rules (SHA-1 and SHA-256) next to the two Authenticode hash rules. By
//! the current documentation the value is the digest of the file's first
//! page as code integrity lays it out: the header page above.
//! [`PageHashTables::page_sha1`] and [`PageHashTables::page_sha256`] return
//! it. Like the Authenticode digest it is the same for user-mode and
//! kernel-mode rules ([`super::HashScenario`]).
//!
//! The construction is not fully documented, so it is checked against the
//! OS tooling itself: on Windows, `tests/os_policy_tooling.rs` runs the OS
//! policy cmdlets over synthetic images through the committed script
//! `tests/fixtures/page_hash/os-policy-hashes.ps1`, and compares every
//! Authenticode and page hash rule they emit with this crate's values. CI
//! runs it on its Windows runners.
//!
//! # Memory
//!
//! A table holds 24 (SHA-1) or 36 (SHA-256) bytes per 4 KiB page of section
//! data, under 1% of the image size.

#![forbid(unsafe_code)]

use std::fmt;

use super::hash::{AuthenticodeStatus, HashRanges, NonConformance};
use super::signature::{PageHashes, SignatureCheck, SignatureInfo, SignatureStatus};
use crate::hash::{AlgorithmSet, Digest, HashAlgorithm, MultiHasher};
use crate::pe::{DataDirectoryKind, FileRange, PeInfo};

/// The page size page hash tables use: 4 KiB.
pub const PAGE_SIZE: u64 = 4096;

/// Size of the `CheckSum` field.
const CHECKSUM_SIZE: u64 = 4;
/// Size of one data directory entry.
const DIRECTORY_ENTRY_SIZE: u64 = 8;
/// Size of a table entry's offset field.
const OFFSET_SIZE: usize = 4;

/// Why there is no page hash table for an image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageHashError {
    /// The image layout departs from the Authenticode specification, so
    /// where each page's bytes are is not well defined.
    NonConformantImage(Vec<NonConformance>),
    /// `SizeOfHeaders` is larger than one page.
    HeadersLargerThanPage {
        /// `SizeOfHeaders`.
        size_of_headers: u32,
    },
    /// The section data ends past 4 GiB, so an offset does not fit the
    /// table's 32-bit field.
    OffsetTooLarge {
        /// The offset that does not fit.
        offset: u64,
    },
    /// Page hashes exist only for SHA-1 and SHA-256.
    UnsupportedAlgorithm(HashAlgorithm),
    /// The sections with raw data are not in file order in the section
    /// table. Signers list pages in section table order and the loader
    /// looks them up by offset, so the order of such a table is not well
    /// defined.
    SectionsNotInFileOrder,
    /// A page hash table's length is not a whole number of entries.
    MalformedTable {
        /// The table's length in bytes.
        len: usize,
    },
    /// The data hashed is not the length of the file the layout was built
    /// for, so it is not that file.
    LengthMismatch {
        /// [`PageLayout::file_size`].
        expected: u64,
        /// Bytes supplied.
        actual: u64,
    },
}

impl fmt::Display for PageHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonConformantImage(reasons) => {
                f.write_str("the image layout is not Authenticode-conformant")?;
                if let Some(first) = reasons.first() {
                    write!(f, ": {first}")?;
                }
                Ok(())
            }
            Self::HeadersLargerThanPage { size_of_headers } => write!(
                f,
                "SizeOfHeaders {size_of_headers:#x} is larger than one {PAGE_SIZE}-byte page"
            ),
            Self::OffsetTooLarge { offset } => {
                write!(f, "offset {offset:#x} does not fit in 32 bits")
            }
            Self::SectionsNotInFileOrder => f.write_str("the section table is not in file order"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "there are no {alg} page hashes (only sha1 and sha256)")
            }
            Self::MalformedTable { len } => {
                write!(
                    f,
                    "a {len}-byte page hash table is not a whole number of entries"
                )
            }
            Self::LengthMismatch { expected, actual } => write!(
                f,
                "expected {expected} bytes of image data for the page hashes, got {actual}"
            ),
        }
    }
}

impl std::error::Error for PageHashError {}

/// One page: a file range of at most [`PAGE_SIZE`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Page {
    offset: u32,
    len: u32,
}

impl Page {
    fn end(self) -> u64 {
        u64::from(self.offset) + u64::from(self.len)
    }
}

/// Where each page of an image is, built once from the parse with
/// [`PageLayout::from_pe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageLayout {
    file_size: u64,
    /// Sorted, disjoint, non-empty, inside the file and at most
    /// [`PAGE_SIZE`] long each. The first is the header page.
    pages: Vec<Page>,
    /// The two header fields left out of the header page, in file order.
    excluded: [FileRange; 2],
    /// Offset of the final, zero-digest entry.
    end: u32,
}

impl PageLayout {
    /// Works out where each page of the image `info` describes is. Only
    /// `info` is used; no file data is read.
    ///
    /// Fails if the image is not Authenticode-conformant or its headers do
    /// not fit in one page.
    pub fn from_pe(info: &PeInfo) -> Result<Self, PageHashError> {
        if let AuthenticodeStatus::NonConformant(reasons) = HashRanges::from_pe(info).status() {
            return Err(PageHashError::NonConformantImage(reasons.clone()));
        }
        let size_of_headers = info.optional.size_of_headers;
        if u64::from(size_of_headers) > PAGE_SIZE {
            return Err(PageHashError::HeadersLargerThanPage { size_of_headers });
        }
        // A conformant image has a security entry; without one the image
        // was rejected above. Both fields lie inside the header page.
        let security = info
            .data_directories
            .get(DataDirectoryKind::Security.index())
            .ok_or_else(|| {
                PageHashError::NonConformantImage(vec![NonConformance::NoSecurityDirectoryEntry])
            })?;
        let excluded = [
            FileRange {
                offset: info.optional.checksum_offset,
                size: CHECKSUM_SIZE,
            },
            FileRange {
                offset: security.entry_offset,
                size: DIRECTORY_ENTRY_SIZE,
            },
        ];

        // In a conformant image the sections follow the headers and each
        // other without gaps or overlaps and end inside the file, so the
        // pages tile the file from 0 to the end of the section data, and
        // their number is bounded by the file size.
        let sections: Vec<(u32, u32)> = info
            .sections
            .iter()
            .filter(|s| s.size_of_raw_data != 0)
            .map(|s| (s.pointer_to_raw_data, s.size_of_raw_data))
            .collect();
        if !sections.is_sorted_by_key(|(pointer, _)| *pointer) {
            return Err(PageHashError::SectionsNotInFileOrder);
        }
        // Checked before any page is listed, so an image near 4 GiB fails at
        // once instead of after building a table it cannot use.
        if let Some(&(pointer, size)) = sections.last() {
            let end = u64::from(pointer) + u64::from(size);
            if u32::try_from(end).is_err() {
                return Err(PageHashError::OffsetTooLarge { offset: end });
            }
        }
        let mut pages = vec![Page {
            offset: 0,
            len: size_of_headers,
        }];
        let mut end = u64::from(size_of_headers);
        for (pointer, size) in sections {
            end = u64::from(pointer) + u64::from(size);
            let mut offset = u64::from(pointer);
            while offset < end {
                let start =
                    u32::try_from(offset).map_err(|_| PageHashError::OffsetTooLarge { offset })?;
                let len = u32::try_from((end - offset).min(PAGE_SIZE)).unwrap_or(0);
                pages.push(Page { offset: start, len });
                offset += PAGE_SIZE;
            }
        }
        let end = u32::try_from(end).map_err(|_| PageHashError::OffsetTooLarge { offset: end })?;
        Ok(Self {
            file_size: info.file_size,
            pages,
            excluded,
            end,
        })
    }

    /// The length of the file the layout was built for.
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    /// The number of entries in a table for this layout, including the
    /// final zero-digest entry.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.pages.len().saturating_add(1)
    }
}

impl PageHashes {
    /// The number of whole entries in the table (trailing bytes that do not
    /// make an entry are not counted).
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len() / OFFSET_SIZE.saturating_add(self.algorithm.digest_len())
    }

    /// Whether the table has no whole entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The digest of the first entry: the header page, in a table this
    /// module builds.
    #[must_use]
    pub fn first_page(&self) -> Option<Digest> {
        let (_, digest) = self.entries().next()?;
        Digest::new(self.algorithm, digest).ok()
    }
}

/// The page hash tables of one image, for the algorithms asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageHashTables {
    /// The SHA-1 table (page hash version 1). **SHA-1 is not collision
    /// resistant**; it is computed only to match older signatures and OS
    /// policy rules.
    pub sha1: Option<PageHashes>,
    /// The SHA-256 table (page hash version 2).
    pub sha256: Option<PageHashes>,
}

impl PageHashTables {
    /// The table for `alg`, if it was computed. Only SHA-1 and SHA-256
    /// have page hashes.
    #[must_use]
    pub const fn table(&self, alg: HashAlgorithm) -> Option<&PageHashes> {
        match alg {
            HashAlgorithm::Sha1 => self.sha1.as_ref(),
            HashAlgorithm::Sha256 => self.sha256.as_ref(),
            _ => None,
        }
    }

    /// The SHA-1 code integrity "page hash" rule value: the SHA-1 digest of
    /// the header page. **SHA-1 is not collision resistant.**
    #[must_use]
    pub fn page_sha1(&self) -> Option<Digest> {
        self.sha1.as_ref()?.first_page()
    }

    /// The SHA-256 code integrity "page hash" rule value: the SHA-256
    /// digest of the header page.
    #[must_use]
    pub fn page_sha256(&self) -> Option<Digest> {
        self.sha256.as_ref()?.first_page()
    }
}

/// The algorithms page hashes exist for.
fn page_algorithms() -> AlgorithmSet {
    AlgorithmSet::SHA1 | AlgorithmSet::SHA256
}

/// Streams an image through its [`PageLayout`] in one pass and builds its
/// page hash tables.
///
/// Feed the whole file, in order, from offset 0, in chunks of any size. The
/// same chunks can go to a [`super::RangeHasher`] and a [`MultiHasher`] at
/// the same time, so one read gives every digest
/// ([`super::hash_image_reader`] does exactly that).
#[derive(Debug, Clone)]
pub struct PageHasher {
    layout: PageLayout,
    set: AlgorithmSet,
    /// Index of the page being hashed.
    next: usize,
    current: Option<MultiHasher>,
    position: u64,
    sha1: Vec<u8>,
    sha256: Vec<u8>,
}

impl PageHasher {
    /// A hasher over `layout` for the algorithms in `set`, which must be
    /// SHA-1, SHA-256 or both.
    pub fn new(layout: PageLayout, set: AlgorithmSet) -> Result<Self, PageHashError> {
        if let Some(alg) = set.iter().find(|a| !page_algorithms().contains(*a)) {
            return Err(PageHashError::UnsupportedAlgorithm(alg));
        }
        let entries = layout.entry_count();
        let capacity = |alg: HashAlgorithm| {
            if set.contains(alg) {
                entries.saturating_mul(OFFSET_SIZE + alg.digest_len())
            } else {
                0
            }
        };
        Ok(Self {
            sha1: Vec::with_capacity(capacity(HashAlgorithm::Sha1)),
            sha256: Vec::with_capacity(capacity(HashAlgorithm::Sha256)),
            layout,
            set,
            next: 0,
            current: None,
            position: 0,
        })
    }

    /// Feeds the next chunk of the file.
    pub fn update(&mut self, chunk: &[u8]) {
        let start = self.position;
        let end = start.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        while let Some(page) = self.layout.pages.get(self.next).copied() {
            if u64::from(page.offset) >= end {
                break;
            }
            let from = u64::from(page.offset).max(start);
            let to = page.end().min(end);
            if from < to {
                let set = self.set;
                let hasher = self.current.get_or_insert_with(|| MultiHasher::new(set));
                feed_excluding(hasher, chunk, start, from, to, &self.layout.excluded);
            }
            if page.end() > end {
                break;
            }
            self.finish_page(page);
        }
        self.position = end;
    }

    fn finish_page(&mut self, page: Page) {
        let mut hasher = self
            .current
            .take()
            .unwrap_or_else(|| MultiHasher::new(self.set));
        let zeros = [0_u8; 512];
        let mut padding = PAGE_SIZE.saturating_sub(u64::from(page.len));
        while padding > 0 {
            let n = padding.min(512);
            hasher.update(
                zeros
                    .get(..usize::try_from(n).unwrap_or(0))
                    .unwrap_or_default(),
            );
            padding -= n;
        }
        let flat = hasher.finalize();
        for (alg, table) in [
            (HashAlgorithm::Sha1, &mut self.sha1),
            (HashAlgorithm::Sha256, &mut self.sha256),
        ] {
            if let Some(digest) = flat.get(alg) {
                table.extend_from_slice(&page.offset.to_le_bytes());
                table.extend_from_slice(digest.as_bytes());
            }
        }
        self.next = self.next.saturating_add(1);
    }

    /// Finishes the tables. Fails if the bytes fed are not exactly
    /// [`PageLayout::file_size`] long.
    pub fn finalize(mut self) -> Result<PageHashTables, PageHashError> {
        // Every page lies inside the file (the layout is conformant), so all
        // of them are finished once the whole file has been fed.
        if self.position != self.layout.file_size || self.next != self.layout.pages.len() {
            return Err(PageHashError::LengthMismatch {
                expected: self.layout.file_size,
                actual: self.position,
            });
        }
        let end = self.layout.end.to_le_bytes();
        let finish = |alg: HashAlgorithm, mut table: Vec<u8>| {
            self.set.contains(alg).then(|| {
                table.extend_from_slice(&end);
                table.resize(table.len().saturating_add(alg.digest_len()), 0);
                PageHashes {
                    algorithm: alg,
                    table,
                }
            })
        };
        Ok(PageHashTables {
            sha1: finish(HashAlgorithm::Sha1, std::mem::take(&mut self.sha1)),
            sha256: finish(HashAlgorithm::Sha256, std::mem::take(&mut self.sha256)),
        })
    }
}

/// Feeds the file bytes `from..to` of `chunk` (which starts at file offset
/// `start`) to `hasher`, leaving out the `excluded` ranges (sorted).
fn feed_excluding(
    hasher: &mut MultiHasher,
    chunk: &[u8],
    start: u64,
    from: u64,
    to: u64,
    excluded: &[FileRange; 2],
) {
    let mut cursor = from;
    for range in excluded {
        let skip_from = range.offset.clamp(cursor, to);
        feed(hasher, chunk, start, cursor, skip_from);
        cursor = cursor.max(range.offset.saturating_add(range.size).min(to));
    }
    feed(hasher, chunk, start, cursor, to);
}

fn feed(hasher: &mut MultiHasher, chunk: &[u8], start: u64, from: u64, to: u64) {
    if from >= to {
        return;
    }
    // `start <= from < to <= start + chunk.len()`, so both fit.
    let (Ok(a), Ok(b)) = (usize::try_from(from - start), usize::try_from(to - start)) else {
        return;
    };
    if let Some(part) = chunk.get(a..b) {
        hasher.update(part);
    }
}

/// The SHA-1 and SHA-256 page hash tables of `data`, the image `info` was
/// parsed from. Fails if the image has no page hash table (see
/// [`PageLayout::from_pe`]) or `data` is not the length `info` was parsed
/// from.
pub fn page_hash_tables(data: &[u8], info: &PeInfo) -> Result<PageHashTables, PageHashError> {
    let mut hasher = PageHasher::new(PageLayout::from_pe(info)?, page_algorithms())?;
    hasher.update(data);
    hasher.finalize()
}

/// The page hash table of `data` for one algorithm (SHA-1 or SHA-256): the
/// issue's `page_hash_table(alg)`. Read the entries with
/// [`PageHashes::entries`].
pub fn page_hash_table(
    data: &[u8],
    info: &PeInfo,
    alg: HashAlgorithm,
) -> Result<PageHashes, PageHashError> {
    let mut hasher = PageHasher::new(PageLayout::from_pe(info)?, alg.into())?;
    hasher.update(data);
    hasher
        .finalize()?
        .table(alg)
        .cloned()
        .ok_or(PageHashError::UnsupportedAlgorithm(alg))
}

/// The result of checking a signed page hash table against a file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageHashCheck {
    /// Every entry of the signed table matches the file.
    Match,
    /// The signed table does not describe this file.
    Mismatch(PageHashMismatch),
    /// The file has no page hash table to compare with.
    Unavailable(PageHashError),
    /// The signature carrying the table does not verify, so the table was
    /// not checked. Only [`verify_signature_page_hashes`] returns this.
    SignatureNotValid,
}

impl PageHashCheck {
    /// Whether every entry matched.
    #[must_use]
    pub const fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }
}

/// The first entry where a signed page hash table and the file disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageHashMismatch {
    /// Index of the entry, counting from 0.
    pub index: usize,
    /// The file offset of the first page that does not verify: the signed
    /// entry's offset, or the file's when the signed table has no entry
    /// there.
    pub offset: u32,
    /// What differs.
    pub kind: PageMismatchKind,
}

/// How a page hash entry differs from the file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageMismatchKind {
    /// The page is where the table says, but its digest differs: the page
    /// was changed after signing.
    Digest {
        /// The signed digest.
        expected: Vec<u8>,
        /// The file's digest.
        actual: Vec<u8>,
    },
    /// The entry's offset is not where the file's page is.
    Offset {
        /// The file's page offset.
        actual: u32,
    },
    /// The signed table ends before the file's pages do.
    MissingEntry,
    /// The signed table has more entries than the file has pages.
    ExtraEntry,
}

/// Checks the signed page hash table `signed` against `data`, the image
/// `info` was parsed from, and reports the first entry that does not match.
///
/// This checks only that the table describes the file. Whether the table
/// can be trusted depends on the signature that carries it; see
/// [`verify_signature_page_hashes`].
///
/// A page table covers the header page and each section's raw data, not
/// the bytes between the last section and the certificate table (an
/// overlay) or after it. Only the whole-image Authenticode digest covers
/// those, so a [`PageHashCheck::Match`] for a signature whose image digest
/// does not match ([`SignatureStatus::DigestMismatch`]) does not mean the
/// file is unmodified: it means every mapped page is.
#[must_use]
pub fn verify_page_hashes(data: &[u8], info: &PeInfo, signed: &PageHashes) -> PageHashCheck {
    // A table parsed from a signature is always whole entries, but the
    // fields are public: trailing bytes must not be silently ignored.
    let record = OFFSET_SIZE.saturating_add(signed.algorithm.digest_len());
    if signed.table.len() % record != 0 {
        return PageHashCheck::Unavailable(PageHashError::MalformedTable {
            len: signed.table.len(),
        });
    }
    let ours = match page_hash_table(data, info, signed.algorithm) {
        Ok(t) => t,
        Err(e) => return PageHashCheck::Unavailable(e),
    };
    let mut theirs = signed.entries();
    for (index, (offset, digest)) in ours.entries().enumerate() {
        let Some((signed_offset, signed_digest)) = theirs.next() else {
            return PageHashCheck::Mismatch(PageHashMismatch {
                index,
                offset,
                kind: PageMismatchKind::MissingEntry,
            });
        };
        if signed_offset != offset {
            return PageHashCheck::Mismatch(PageHashMismatch {
                index,
                offset: signed_offset,
                kind: PageMismatchKind::Offset { actual: offset },
            });
        }
        if signed_digest != digest {
            return PageHashCheck::Mismatch(PageHashMismatch {
                index,
                offset,
                kind: PageMismatchKind::Digest {
                    expected: signed_digest.to_vec(),
                    actual: digest.to_vec(),
                },
            });
        }
    }
    if let Some((offset, _)) = theirs.next() {
        return PageHashCheck::Mismatch(PageHashMismatch {
            index: ours.len(),
            offset,
            kind: PageMismatchKind::ExtraEntry,
        });
    }
    PageHashCheck::Match
}

/// Checks the page hashes of `signature` against `data`, the image `info`
/// was parsed from: the issue's on-demand `verify_page_hashes()`.
///
/// The table is checked only when the signature itself verifies: its
/// [`SignatureInfo::signature_valid`] is [`SignatureCheck::Valid`] and its
/// status is [`SignatureStatus::Valid`] or [`SignatureStatus::DigestMismatch`].
/// The second case is what page hashes are for: the file was changed after
/// signing, and the check names the first page that changed. Any other
/// signature (a bad or unsupported signature, MD5, a non-conformant image)
/// gives [`PageHashCheck::SignatureNotValid`], because a table it carries
/// is attacker-controlled. Returns `None` when the signature has no page
/// hash table.
///
/// "Verifies" here is the cryptographic check of #48. Whether the signer is
/// trusted is the certificate chain's business (#49). See
/// [`verify_page_hashes`] for what a match does and does not cover.
#[must_use]
pub fn verify_signature_page_hashes(
    data: &[u8],
    info: &PeInfo,
    signature: &SignatureInfo,
) -> Option<PageHashCheck> {
    let table = signature.page_hashes.as_ref()?;
    let verified = signature.signature_valid == SignatureCheck::Valid
        && matches!(
            signature.status,
            SignatureStatus::Valid | SignatureStatus::DigestMismatch
        );
    if !verified {
        return Some(PageHashCheck::SignatureNotValid);
    }
    Some(verify_page_hashes(data, info, table))
}
