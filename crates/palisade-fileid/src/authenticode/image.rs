//! Every digest of a file in one sequential read (#46, #47).
//!
//! [`hash_image_file`] and [`hash_image_reader`] read a file once, front to
//! back, and compute from the same buffers:
//!
//! - the flat hashes ([`crate::hash`]);
//! - for a PE image, the Authenticode digests and the page hash tables
//!   ([`super::hash`], [`super::page`]).
//!
//! The PE headers are parsed from the first bytes read ([`pe::parse_prefix`],
//! at most [`HEADER_PREFIX_LEN`]), before the rest of the file arrives, so
//! nothing is read twice. Memory use does not grow with the file: one
//! prefix buffer, the read buffers in flight, and the page tables (under 1%
//! of the section data).
//!
//! # Parallel hashing
//!
//! With [`ImageHashOptions::parallel`] each digest runs on its own thread,
//! fed the same read buffers. The read is still a single sequential pass.
//! On a multi-core machine the wall time is then close to that of the
//! slowest single digest, instead of their sum. Every thread reads the same
//! shared buffers, and each holds at most two queued, so at most four read
//! buffers are alive at once. It is off by default: the caller owns the CPU
//! budget (#65) and decides how many hashes run at once (#46).

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;

use super::hash::{AuthenticodeHashes, HashRanges, RangeHasher};
use super::page::{PageHashError, PageHashTables, PageHasher, PageLayout};
use crate::hash::{
    AlgorithmSet, FlatHashes, HashAlgorithm, HashError, HashOptions, MultiHasher,
    open_without_blocking,
};
use crate::pe::{self, MAX_E_LFANEW, MAX_SECTIONS, PeInfo};

/// The most bytes the headers of a PE image the parser accepts can span:
/// `e_lfanew` at its limit, the PE signature, the COFF header, the largest
/// optional header and [`MAX_SECTIONS`] section headers. The prefix read
/// before hashing starts is at most this long (about 1.1 MiB).
pub const HEADER_PREFIX_LEN: usize =
    MAX_E_LFANEW as usize + 4 + 20 + u16::MAX as usize + MAX_SECTIONS * 40;

/// Read buffers in flight per worker thread in parallel mode.
const QUEUE_DEPTH: usize = 2;

/// Options for [`hash_image_reader`] and [`hash_image_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageHashOptions {
    /// The flat hashes, read buffer size and size limit.
    pub hash: HashOptions,
    /// Extra Authenticode digest algorithms, beyond SHA-256 and SHA-1, which
    /// are always computed for a PE image.
    pub authenticode_extra: AlgorithmSet,
    /// Run each digest on its own thread. Off by default.
    pub parallel: bool,
}

impl Default for ImageHashOptions {
    /// The default flat hashes, SHA-256 and SHA-1 Authenticode digests, one
    /// thread.
    fn default() -> Self {
        Self {
            hash: HashOptions::default(),
            authenticode_extra: AlgorithmSet::EMPTY,
            parallel: false,
        }
    }
}

/// Every digest of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageHashes {
    /// The flat hashes of the whole file.
    pub flat: FlatHashes,
    /// The Authenticode digests and page hash tables, if the file is a PE
    /// image (its headers parse). Check
    /// [`AuthenticodeHashes::status`] before treating them as authoritative.
    pub authenticode: Option<AuthenticodeHashes>,
}

/// The outcome of [`hash_image_reader`] or [`hash_image_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageHashStatus {
    /// Every digest was computed.
    Complete(ImageHashes),
    /// The file is larger than [`HashOptions::max_hash_size`], so nothing
    /// was hashed.
    TooLarge {
        /// The configured limit, in bytes.
        limit: u64,
    },
}

/// One consumer of the read buffers.
enum Sink {
    Flat(MultiHasher),
    Image(RangeHasher),
    Pages(PageHasher),
}

impl Sink {
    fn update(&mut self, chunk: &[u8]) {
        match self {
            Self::Flat(h) => h.update(chunk),
            Self::Image(h) => h.update(chunk),
            Self::Pages(h) => h.update(chunk),
        }
    }
}

/// What the sinks produced, merged.
#[derive(Default)]
struct Results {
    flat: Vec<FlatHashes>,
    image: Vec<AuthenticodeHashes>,
    pages: Vec<PageHashTables>,
    page_error: Option<PageHashError>,
}

/// Hashes everything `reader` yields: the flat hashes, and the Authenticode
/// digests and page hash tables if it is a PE image. `file_len` is the
/// length of the file, from its metadata.
///
/// The reader must yield exactly `file_len` bytes. A file that grows or
/// shrinks while it is read fails with [`HashError::SizeChanged`], because
/// its digests would describe no single version of it. A `file_len` over
/// [`HashOptions::max_hash_size`] returns [`ImageHashStatus::TooLarge`]
/// without reading anything.
pub fn hash_image_reader<R: Read>(
    mut reader: R,
    file_len: u64,
    options: &ImageHashOptions,
) -> Result<ImageHashStatus, HashError> {
    options.hash.validate()?;
    if file_len > options.hash.max_hash_size {
        return Ok(ImageHashStatus::TooLarge {
            limit: options.hash.max_hash_size,
        });
    }

    // The headers come first. They are parsed before anything is hashed, so
    // every digest is computed in the same pass.
    let prefix_len = usize::try_from(file_len)
        .unwrap_or(usize::MAX)
        .min(HEADER_PREFIX_LEN);
    let mut prefix = vec![0_u8; prefix_len];
    let got = read_full(&mut reader, &mut prefix)?;
    if got < prefix_len {
        return Err(HashError::SizeChanged {
            expected: file_len,
            actual: to_u64(got),
        });
    }
    let info = pe::parse_prefix(&prefix, file_len).ok();
    let (sinks, no_pages) = make_sinks(info.as_ref(), options);

    let results = if options.parallel && sinks.len() > 1 {
        run_parallel(&mut reader, prefix, file_len, options, sinks)?
    } else {
        run_serial(&mut reader, &prefix, file_len, options, sinks)?
    };
    Ok(ImageHashStatus::Complete(finish(
        results,
        info.is_some(),
        no_pages,
    )))
}

/// Hashes the file at `path` (its default data stream), as
/// [`hash_image_reader`] does, in one sequential read.
///
/// The file is opened as [`crate::hash::hash_file`] opens it: anything that
/// is not a regular file is [`HashError::NotAFile`], and the opened handle
/// is what is checked and read.
pub fn hash_image_file(
    path: &Path,
    options: &ImageHashOptions,
) -> Result<ImageHashStatus, HashError> {
    options.hash.validate()?;
    if !std::fs::metadata(path)?.is_file() {
        return Err(HashError::NotAFile);
    }
    let file: File = open_without_blocking(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(HashError::NotAFile);
    }
    hash_image_reader(file, metadata.len(), options)
}

/// The sinks for one file, and why it has no page hash table if it is a PE
/// image without one.
fn make_sinks(
    info: Option<&PeInfo>,
    options: &ImageHashOptions,
) -> (Vec<Sink>, Option<PageHashError>) {
    let flat = options.hash.algorithms;
    let image = options.authenticode_extra | AlgorithmSet::SHA256 | AlgorithmSet::SHA1;
    let pages = AlgorithmSet::SHA1 | AlgorithmSet::SHA256;
    let mut sinks = Vec::new();
    // In parallel mode every algorithm gets its own sink, so its own thread.
    let split = |set: AlgorithmSet| -> Vec<AlgorithmSet> {
        if options.parallel {
            set.iter().map(AlgorithmSet::from).collect()
        } else {
            vec![set]
        }
    };
    for set in split(flat) {
        sinks.push(Sink::Flat(MultiHasher::new(set)));
    }
    let Some(info) = info else {
        return (sinks, None);
    };
    let ranges = HashRanges::from_pe(info);
    for set in split(image) {
        sinks.push(Sink::Image(RangeHasher::new(ranges.clone(), set)));
    }
    let layout = match PageLayout::from_pe(info) {
        Ok(layout) => layout,
        Err(e) => return (sinks, Some(e)),
    };
    for set in split(pages) {
        match PageHasher::new(layout.clone(), set) {
            Ok(hasher) => sinks.push(Sink::Pages(hasher)),
            Err(e) => return (sinks, Some(e)),
        }
    }
    (sinks, None)
}

fn run_serial<R: Read>(
    reader: &mut R,
    prefix: &[u8],
    file_len: u64,
    options: &ImageHashOptions,
    mut sinks: Vec<Sink>,
) -> Result<Results, HashError> {
    for sink in &mut sinks {
        sink.update(prefix);
    }
    let mut buffer = vec![0_u8; options.hash.buffer_size];
    let mut read = to_u64(prefix.len());
    loop {
        let n = read_some(reader, &mut buffer)?;
        if n == 0 {
            break;
        }
        read = check_len(read, n, file_len)?;
        let chunk = buffer.get(..n).unwrap_or_default();
        for sink in &mut sinks {
            sink.update(chunk);
        }
    }
    if read != file_len {
        return Err(HashError::SizeChanged {
            expected: file_len,
            actual: read,
        });
    }
    finalize_sinks(sinks)
}

fn run_parallel<R: Read>(
    reader: &mut R,
    prefix: Vec<u8>,
    file_len: u64,
    options: &ImageHashOptions,
    sinks: Vec<Sink>,
) -> Result<Results, HashError> {
    std::thread::scope(|scope| {
        let mut senders = Vec::with_capacity(sinks.len());
        let mut workers = Vec::with_capacity(sinks.len());
        for mut sink in sinks {
            let (tx, rx) = mpsc::sync_channel::<Arc<[u8]>>(QUEUE_DEPTH);
            senders.push(tx);
            workers.push(scope.spawn(move || {
                for chunk in rx {
                    sink.update(&chunk);
                }
                sink
            }));
        }
        let send = |chunk: Arc<[u8]>| {
            for tx in &senders {
                // A worker only stops when its sender is dropped, so a send
                // cannot fail while the senders are alive.
                let _ = tx.send(Arc::clone(&chunk));
            }
        };
        let mut read = to_u64(prefix.len());
        send(Arc::from(prefix));
        let outcome = loop {
            let mut buffer = vec![0_u8; options.hash.buffer_size];
            let n = match read_some(reader, &mut buffer) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) => break Err(e),
            };
            read = match check_len(read, n, file_len) {
                Ok(total) => total,
                Err(e) => break Err(e),
            };
            buffer.truncate(n);
            send(Arc::from(buffer));
        };
        drop(senders);
        let mut sinks = Vec::with_capacity(workers.len());
        for worker in workers {
            // Hashing cannot panic; if it somehow did, fail rather than
            // return a result with a digest missing.
            sinks.push(
                worker
                    .join()
                    .map_err(|_| internal("a hash worker panicked"))?,
            );
        }
        outcome?;
        if read != file_len {
            return Err(HashError::SizeChanged {
                expected: file_len,
                actual: read,
            });
        }
        finalize_sinks(sinks)
    })
}

fn finalize_sinks(sinks: Vec<Sink>) -> Result<Results, HashError> {
    let mut out = Results::default();
    for sink in sinks {
        match sink {
            Sink::Flat(h) => out.flat.push(h.finalize()),
            Sink::Image(h) => out
                .image
                .push(h.finalize().map_err(|e| internal(&e.to_string()))?),
            Sink::Pages(h) => match h.finalize() {
                Ok(t) => out.pages.push(t),
                Err(e) => out.page_error = Some(e),
            },
        }
    }
    Ok(out)
}

fn finish(results: Results, is_pe: bool, no_pages: Option<PageHashError>) -> ImageHashes {
    let mut flat = results.flat.into_iter();
    let mut merged = flat.next().unwrap_or(FlatHashes {
        size: 0,
        empty: true,
        digests: Vec::new(),
    });
    for part in flat {
        merged.digests.extend(part.digests);
    }
    merged.digests.sort_by_key(|d| alg_rank(d.algorithm()));

    let mut parts = results.image.into_iter();
    let authenticode = parts.next().filter(|_| is_pe).map(|mut hashes| {
        for part in parts {
            hashes.digests.extend(part.digests);
        }
        hashes.digests.sort_by_key(|d| alg_rank(d.algorithm()));
        let pages = match no_pages.or(results.page_error) {
            Some(e) => Err(e),
            None => {
                let mut tables = PageHashTables {
                    sha1: None,
                    sha256: None,
                };
                for part in results.pages {
                    tables.sha1 = tables.sha1.or(part.sha1);
                    tables.sha256 = tables.sha256.or(part.sha256);
                }
                Ok(tables)
            }
        };
        hashes.page_hashes = Some(pages);
        hashes
    });
    ImageHashes {
        flat: merged,
        authenticode,
    }
}

fn alg_rank(alg: HashAlgorithm) -> usize {
    HashAlgorithm::ALL
        .iter()
        .position(|a| *a == alg)
        .unwrap_or(usize::MAX)
}

/// Fills `buf` from `reader`, retrying interrupted reads. Returns how many
/// bytes were read: fewer than `buf.len()` only at the end of the input.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, HashError> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..).filter(|r| !r.is_empty()) {
        let n = read_some(reader, rest)?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// One read, retrying interrupted ones. A reader that claims to have read
/// more than the buffer holds is an error.
fn read_some<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, HashError> {
    loop {
        match reader.read(buf) {
            Ok(n) if n > buf.len() => {
                return Err(internal("reader reported more bytes than the buffer holds"));
            }
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(HashError::Io(e)),
        }
    }
}

/// Adds `n` to the bytes read so far, failing as soon as the file is longer
/// than its metadata said.
fn check_len(read: u64, n: usize, file_len: u64) -> Result<u64, HashError> {
    match read.checked_add(to_u64(n)) {
        Some(total) if total <= file_len => Ok(total),
        total => Err(HashError::SizeChanged {
            expected: file_len,
            actual: total.unwrap_or(u64::MAX),
        }),
    }
}

fn internal(message: &str) -> HashError {
    HashError::Io(std::io::Error::new(
        ErrorKind::InvalidData,
        message.to_owned(),
    ))
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
