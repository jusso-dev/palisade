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
//! [`verify`] checks the map against an [`Archive`] and fails closed: a
//! file the archive has but the map does not list (or the reverse), a name
//! listed twice, a size, local-header size or compressed size that does not
//! match, a block count that does not fit the size, or any block whose hash
//! differs is a mismatch.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use super::xml::{self, Element};
use super::zip::{Archive, MAX_ENTRIES, Member};
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
    if root.ns != NS || root.name != "BlockMap" {
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
            block_sizes.push(number(b, "Size")?);
        }
        if u64::try_from(blocks.len()).ok() != Some(size.div_ceil(BLOCK)) {
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

/// Percent-decodes an OPC part name as stored in the archive.
pub(crate) fn decode_part_name(name: &str) -> Option<String> {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            let s = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(s, 16).ok()?);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The size of a member's local file header (signature to data).
fn local_header_len(m: &Member) -> u64 {
    m.data_offset.saturating_sub(m.local_offset)
}

/// Checks `map` against `archive`.
pub fn verify(map: &BlockMap, archive: &Archive<'_>) -> Result<(), BlockMapError> {
    let mut listed = BTreeSet::new();
    for f in &map.files {
        if !listed.insert(f.name.to_ascii_lowercase()) {
            return Err(BlockMapError::Duplicate(f.name.clone()));
        }
    }
    // Every member is listed (by its decoded part name), or is one of the
    // four that are not; and every listed file is a member.
    let mut seen = BTreeSet::new();
    for m in &archive.members {
        if UNMAPPED.iter().any(|u| m.name.eq_ignore_ascii_case(u)) {
            continue;
        }
        let decoded =
            decode_part_name(&m.name).ok_or_else(|| BlockMapError::Unlisted(m.name.clone()))?;
        let key = decoded.to_ascii_lowercase();
        let Some(f) = map
            .files
            .iter()
            .find(|f| f.name.to_ascii_lowercase() == key)
        else {
            return Err(BlockMapError::Unlisted(m.name.clone()));
        };
        seen.insert(key);
        if f.size != m.size || f.lfh_size != local_header_len(m) {
            return Err(BlockMapError::Size(f.name.clone()));
        }
        if m.method == 8 {
            let sum = f
                .block_sizes
                .iter()
                .try_fold(0_u64, |acc, s| s.map(|s| acc.saturating_add(s)));
            if sum.is_some_and(|s| s != m.compressed_size) {
                return Err(BlockMapError::Size(f.name.clone()));
            }
        }
        check_blocks(map.hash, f, archive, m)?;
    }
    if let Some(missing) = map
        .files
        .iter()
        .find(|f| !seen.contains(&f.name.to_ascii_lowercase()))
    {
        return Err(BlockMapError::Unlisted(missing.name.clone()));
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

    #[test]
    fn part_names_decode() {
        assert_eq!(decode_part_name("a%20b.txt").as_deref(), Some("a b.txt"));
        assert_eq!(decode_part_name("%C3%A9").as_deref(), Some("\u{e9}"));
        assert_eq!(decode_part_name("bad%2"), None);
        assert_eq!(decode_part_name("%FF"), None);
    }
}
