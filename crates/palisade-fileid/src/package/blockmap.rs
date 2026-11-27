//! `AppxBlockMap.xml`: the per-file block hashes every package carries, and
//! their check against the archive.
//!
//! The block map lists every file of the package (except the signature,
//! the block map itself, `[Content_Types].xml` and the code integrity
//! catalog) with its uncompressed size, the size of its local file header
//! and the hash of each 64 KiB block of its uncompressed content, under the
//! map's `HashMethod`. The signature signs the block map's hash, so the
//! map is what ties every file's content to the signature.
//!
//! A bundle's block map lists only its bundle manifest; [`verify_bundle`]
//! checks its payload packages against the bundle manifest instead (the
//! signature still covers their bytes, through the local records).
//!
//! [`verify`] checks the map against an [`Archive`] and fails closed: a
//! file the archive has but the map does not list (or the reverse), a name
//! listed twice, a size, local-header size or compressed size that does not
//! match, a deflated file whose blocks do not all give their compressed
//! size, a block count that does not fit the size, or any block whose hash
//! differs is a mismatch.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::xml::{self, Element};
use super::zip::{Archive, MAX_ENTRIES, Member, fold};
use crate::authenticode::DigestAlgorithm;
use crate::hash::{AlgorithmSet, MultiHasher};

/// The block map namespace.
pub const NS: &str = "http://schemas.microsoft.com/appx/2010/blockmap";
/// The uncompressed block size.
pub const BLOCK: u64 = 64 * 1024;

/// Archive members the block map does not list.
pub(crate) const UNMAPPED: [&str; 4] = [
    "AppxSignature.p7x",
    "AppxBlockMap.xml",
    "[Content_Types].xml",
    "AppxMetadata/CodeIntegrity.cat",
];

/// One listed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedFile {
    /// The name, with `/` separators (the map writes `\`).
    pub name: String,
    /// Uncompressed size.
    pub size: u64,
    /// Local file header size.
    pub lfh_size: u64,
    /// The block hashes, raw.
    pub blocks: Vec<Vec<u8>>,
    /// The compressed size of each block, when given.
    pub block_sizes: Vec<Option<u64>>,
}

/// A parsed block map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMap {
    /// The hash method.
    pub hash: DigestAlgorithm,
    /// The files, in map order.
    pub files: Vec<MappedFile>,
}

/// Why the block map does not match, or could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BlockMapError {
    /// The XML is invalid or not a block map.
    Malformed(String),
    /// `HashMethod` is not SHA-256, SHA-384 or SHA-512.
    HashMethod,
    /// A file is listed twice.
    Duplicate(String),
    /// An archive member is not listed, or a listed file is missing.
    Unlisted(String),
    /// A size or the local header size does not match.
    Size(String),
    /// A block hash does not match.
    Hash(String),
}

impl fmt::Display for BlockMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "block map: {why}"),
            Self::HashMethod => f.write_str("block map hash method is not SHA-2"),
            Self::Duplicate(n) => write!(f, "{n:?} is listed twice in the block map"),
            Self::Unlisted(n) => write!(f, "{n:?} is in the package or the block map, not both"),
            Self::Size(n) => write!(f, "{n:?} does not have the size the block map gives"),
            Self::Hash(n) => write!(f, "{n:?} does not match its block hashes"),
        }
    }
}

impl std::error::Error for BlockMapError {}

fn bad(why: &str) -> BlockMapError {
    BlockMapError::Malformed(why.to_owned())
}

/// Standard base64 with padding, strict.
fn base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.chunks(4);
    let n = chunks.len();
    for (i, chunk) in chunks.enumerate() {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != n) {
            return None;
        }
        let mut v = 0_u32;
        for &c in chunk.get(..4 - pad)? {
            v = (v << 6) | val(c)?;
        }
        v <<= 6 * u32::try_from(pad).ok()?;
        let b = v.to_be_bytes();
        out.extend_from_slice(b.get(1..4 - pad)?);
        // Non-canonical padding bits are refused.
        if pad > 0 {
            let mask = if pad == 2 { 0xffff } else { 0xff };
            if v & mask != 0 {
                return None;
            }
        }
    }
    Some(out)
}

fn hash_method(uri: &str) -> Option<DigestAlgorithm> {
    Some(match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => DigestAlgorithm::Sha256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => DigestAlgorithm::Sha384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => DigestAlgorithm::Sha512,
        _ => return None,
    })
}

fn number(e: &Element, name: &str) -> Result<Option<u64>, BlockMapError> {
    e.attr(name)
        .map(|v| {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad("a size is not a decimal number"));
            }
            v.parse().map_err(|_| bad("a size is too large"))
        })
        .transpose()
}

/// Parses `AppxBlockMap.xml`.
pub fn parse(data: &[u8]) -> Result<BlockMap, BlockMapError> {
    let root = xml::parse(data).map_err(|e| BlockMapError::Malformed(e.0))?;
    if &*root.ns != NS || root.name != "BlockMap" {
        return Err(bad("not a block map"));
    }
    let hash = root
        .attr("HashMethod")
        .and_then(hash_method)
        .ok_or(BlockMapError::HashMethod)?;
    let mut files = Vec::new();
    for f in root.children_named(&[NS], "File") {
        if files.len() >= MAX_ENTRIES {
            return Err(bad("too many files"));
        }
        let name = f
            .attr("Name")
            .filter(|n| !n.is_empty())
            .ok_or_else(|| bad("a file has no name"))?
            .replace('\\', "/");
        if name.starts_with('/')
            || name.contains('\0')
            || name
                .split('/')
                .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        {
            return Err(bad("a file name is not a valid part name"));
        }
        let size = number(f, "Size")?.ok_or_else(|| bad("a file has no size"))?;
        let lfh_size = number(f, "LfhSize")?.ok_or_else(|| bad("a file has no LfhSize"))?;
        let mut blocks = Vec::new();
        let mut block_sizes = Vec::new();
        for b in f.children_named(&[NS], "Block") {
            let h = b
                .attr("Hash")
                .and_then(base64)
                .filter(|h| h.len() == hash.digest_len())
                .ok_or_else(|| bad("a block hash is not valid base64 of the right length"))?;
            blocks.push(h);
            let size = number(b, "Size")?;
            if size == Some(0) {
                return Err(bad("a block size is zero"));
            }
            block_sizes.push(size);
        }
        if u64::try_from(blocks.len()).ok() != Some(size.div_ceil(BLOCK)) {
            return Err(BlockMapError::Size(name));
        }
        // Either every block gives its compressed size or none does.
        let with = block_sizes.iter().filter(|s| s.is_some()).count();
        if with != 0 && with != block_sizes.len() {
            return Err(BlockMapError::Size(name));
        }
        files.push(MappedFile {
            name,
            size,
            lfh_size,
            blocks,
            block_sizes,
        });
    }
    Ok(BlockMap { hash, files })
}

/// The size of a member's local file header (signature to data).
fn local_header_len(m: &Member) -> u64 {
    m.data_offset.saturating_sub(m.local_offset)
}

/// A payload package of a bundle, as its bundle manifest lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload<'n> {
    /// `FileName`: the member's name in the bundle.
    pub file_name: &'n str,
    /// `Offset`: where the member's data starts in the bundle file.
    pub offset: Option<u64>,
    /// `Size`: the member's size.
    pub size: Option<u64>,
}

/// Checks `map` against `archive`.
pub fn verify(map: &BlockMap, archive: &Archive<'_>) -> Result<(), BlockMapError> {
    verify_with(map, archive, None)
}

/// Checks a bundle's `map` against `archive`. A bundle's block map lists
/// its bundle manifest and nothing else: the payload packages are not in
/// it. Each payload must instead be listed in `payloads` (the bundle
/// manifest) exactly once, and be a stored member (the OS packaging tool
/// never compresses one) whose data starts at the manifest's `Offset` and
/// has its `Size`, so no member escapes both. Their bytes are covered by
/// the signature through the local records. A payload that is not in the
/// archive (a flat bundle's) is a mismatch.
pub fn verify_bundle(
    map: &BlockMap,
    archive: &Archive<'_>,
    payloads: &[Payload<'_>],
) -> Result<(), BlockMapError> {
    verify_with(map, archive, Some(payloads))
}

fn verify_with(
    map: &BlockMap,
    archive: &Archive<'_>,
    payloads: Option<&[Payload<'_>]>,
) -> Result<(), BlockMapError> {
    // A bundle's payloads, by folded part name; each once.
    let mut by_part: BTreeMap<String, Payload<'_>> = BTreeMap::new();
    for p in payloads.unwrap_or_default() {
        if by_part.insert(fold(p.file_name), *p).is_some() {
            return Err(BlockMapError::Duplicate(p.file_name.to_owned()));
        }
    }
    let mut payloads_seen = BTreeSet::new();
    // A bundle's block map lists its bundle manifest and nothing else (the
    // OS packaging tool writes it so, and the OS reader requires it).
    if payloads.is_some()
        && !(map.files.len() == 1
            && map
                .files
                .first()
                .is_some_and(|f| fold(&f.name) == fold(super::BUNDLE_MANIFEST)))
    {
        let name = map
            .files
            .iter()
            .find(|f| fold(&f.name) != fold(super::BUNDLE_MANIFEST))
            .map_or_else(|| super::BUNDLE_MANIFEST.to_owned(), |f| f.name.clone());
        return Err(BlockMapError::Unlisted(name));
    }
    // Listed files by folded name; each name once.
    let mut listed: BTreeMap<String, &MappedFile> = BTreeMap::new();
    for f in &map.files {
        if listed.insert(fold(&f.name), f).is_some() {
            return Err(BlockMapError::Duplicate(f.name.clone()));
        }
    }
    // A budget first: the whole uncompressed size the block map lists may
    // not exceed what a package may be at all, whatever the archive
    // claims, so a small archive cannot make us inflate more.
    let total = listed
        .values()
        .try_fold(0_u64, |a, f| a.checked_add(f.size))
        .filter(|&t| t <= super::MAX_PACKAGE_SIZE);
    if total.is_none() {
        return Err(BlockMapError::Size("(total)".into()));
    }
    // Every member is listed (by its part name), or is one of the four
    // that are not; and every listed file is exactly one member (part
    // names are unique in the archive).
    let mut seen = BTreeSet::new();
    for m in &archive.members {
        let key = fold(&m.part);
        if UNMAPPED.iter().any(|u| fold(u) == key) {
            continue;
        }
        if let Some(p) = by_part.get(&key) {
            // A payload package: stored, and where and how large the
            // bundle manifest says. The block map must not list it too.
            if m.method != 0
                || p.size != Some(m.size)
                || p.offset != Some(m.data_offset)
                || listed.contains_key(&key)
            {
                return Err(BlockMapError::Size(m.name.clone()));
            }
            payloads_seen.insert(key);
            continue;
        }
        let Some(f) = listed.get(&key) else {
            return Err(BlockMapError::Unlisted(m.name.clone()));
        };
        if !seen.insert(key) {
            return Err(BlockMapError::Duplicate(f.name.clone()));
        }
        if f.size != m.size || f.lfh_size != local_header_len(m) {
            return Err(BlockMapError::Size(f.name.clone()));
        }
        // A deflated file's blocks each give their compressed size (an
        // empty file has no blocks); a stored file's give none. The OS
        // packaging tool compresses each 64 KiB block with a full flush and
        // ends the stream with an empty final block, the two bytes `03 00`
        // that no block counts, so the sizes sum to the compressed size or
        // to two bytes less: the two cases the OS reader accepts, and
        // nothing else.
        let given: Vec<u64> = f.block_sizes.iter().flatten().copied().collect();
        if m.method == 8 {
            let sum = given.iter().try_fold(0_u64, |a, &x| a.checked_add(x));
            let fits = sum.is_some_and(|s| {
                s == m.compressed_size || s.checked_add(2) == Some(m.compressed_size)
            });
            if !f.blocks.is_empty() && (given.len() != f.blocks.len() || !fits) {
                return Err(BlockMapError::Size(f.name.clone()));
            }
        } else if !given.is_empty() {
            return Err(BlockMapError::Size(f.name.clone()));
        }
    }
    if let Some(missing) = by_part.keys().find(|k| !payloads_seen.contains(*k)) {
        let name = by_part
            .get(missing)
            .map_or_else(String::new, |p| p.file_name.to_owned());
        return Err(BlockMapError::Unlisted(name));
    }
    if let Some(missing) = listed.keys().find(|k| !seen.contains(*k)) {
        let name = listed
            .get(missing)
            .map_or_else(String::new, |f| f.name.clone());
        return Err(BlockMapError::Unlisted(name));
    }
    // Only then the content, one member at a time.
    for m in &archive.members {
        if let Some(f) = listed.get(&fold(&m.part)) {
            if !UNMAPPED.iter().any(|u| fold(u) == fold(&m.part)) {
                check_blocks(map.hash, f, archive, m)?;
            }
        }
    }
    Ok(())
}

fn check_blocks(
    alg: DigestAlgorithm,
    f: &MappedFile,
    archive: &Archive<'_>,
    m: &Member,
) -> Result<(), BlockMapError> {
    let Some(h) = alg.hash_algorithm() else {
        return Err(BlockMapError::HashMethod);
    };
    let block = usize::try_from(BLOCK).unwrap_or(usize::MAX);
    let mut pending: Vec<u8> = Vec::with_capacity(block);
    let mut index = 0_usize;
    let mut ok = true;
    let mut finish_block = |data: &[u8], index: &mut usize| {
        let mut hasher = MultiHasher::new(AlgorithmSet::from(h));
        hasher.update(data);
        let digest = hasher.finalize();
        let matches = digest
            .get(h)
            .zip(f.blocks.get(*index))
            .is_some_and(|(d, want)| d.as_bytes() == want.as_slice());
        ok &= matches;
        *index += 1;
    };
    archive
        .stream(m, |mut chunk| {
            while !chunk.is_empty() {
                let take = (block - pending.len()).min(chunk.len());
                let (head, tail) = chunk.split_at(take);
                pending.extend_from_slice(head);
                chunk = tail;
                if pending.len() == block {
                    finish_block(&pending, &mut index);
                    pending.clear();
                }
            }
        })
        .map_err(|_| BlockMapError::Hash(f.name.clone()))?;
    if !pending.is_empty() {
        finish_block(&pending, &mut index);
    }
    if ok && index == f.blocks.len() {
        Ok(())
    } else {
        Err(BlockMapError::Hash(f.name.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_strict() {
        assert_eq!(base64("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(base64("aGVsbA==").as_deref(), Some(&b"hell"[..]));
        assert_eq!(base64("aGVs").as_deref(), Some(&b"hel"[..]));
        for bad in [
            "",
            "aGVsbG8",
            "aGVsbG9=",
            "a=Vs",
            "aG Vs",
            "aGVsbA=="[..7].as_ref(),
        ] {
            assert_eq!(base64(bad), None, "{bad:?}");
        }
    }
}
