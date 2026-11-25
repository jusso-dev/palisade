//! The scan: one linear pass over bounded chunks.
//!
//! The file is read in chunks of [`CHUNK_LEN`]. Each chunk is searched with
//! the atom automaton, after the last `window - 1` bytes of the previous
//! chunk, so a match that crosses a chunk boundary is still seen whole.
//! Each chunk "owns" the match starts up to `window - 1` bytes before its
//! end (or to its end, for the last chunk of a region), and only owned
//! starts are checked, so every start is checked by exactly one chunk.

#![forbid(unsafe_code)]

use std::io::{self, Read, Seek, SeekFrom};
use std::time::Instant;

use super::rules::{Compiled, Location};
use super::{ContentRules, ScanLimits, ScanStatus, TAIL_SCAN_LEN, TagReport};
use crate::pe;
use crate::pe::read::u16_at;

/// Bytes read per chunk.
pub(super) const CHUNK_LEN: usize = 1024 * 1024;

/// The wall clock is checked after this many candidate checks.
const CLOCK_EVERY: u32 = 4096;

/// Why a scan stopped early.
enum Stop {
    Budget,
    Io(io::ErrorKind),
}

impl From<io::Error> for Stop {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// The scan's running state.
struct Scan<'a, R: ?Sized> {
    reader: &'a mut R,
    compiled: &'a Compiled,
    limits: &'a ScanLimits,
    started: Instant,
    len: u64,
    /// Where a PE image's appended data starts, if the file is one.
    overlay: Option<u64>,
    found: Vec<bool>,
    bytes: u64,
    steps: u64,
    since_clock: u32,
    /// The next entry of `compiled.anchored` to check.
    next_anchored: usize,
    /// For each `unless_start` pattern: whether the file starts with it,
    /// or `None` if that could not be checked.
    prefix_hits: Vec<Option<bool>>,
    /// A read returned fewer bytes than the file length promised.
    short_read: bool,
}

pub(super) fn run<R: Read + Seek + ?Sized>(
    reader: &mut R,
    rules: &ContentRules,
    limits: &ScanLimits,
) -> TagReport {
    let compiled = &rules.compiled;
    let mut report = TagReport {
        tags: Vec::new(),
        status: ScanStatus::Complete,
        builtin_version: super::BUILTIN_VERSION,
        rules_version: rules.rules_version,
        rules_digest: rules.rules_digest,
        file_size: 0,
        is_pe: false,
        bytes_scanned: 0,
        match_steps: 0,
    };
    let len = match reader.seek(SeekFrom::End(0)) {
        Ok(len) => len,
        Err(e) => {
            report.status = ScanStatus::ReadError(e.kind());
            report.tags.extend(report.status.tag().map(str::to_owned));
            return report;
        }
    };
    report.file_size = len;
    let mut scan = Scan {
        reader,
        compiled,
        limits,
        started: Instant::now(),
        len,
        overlay: None,
        found: vec![false; compiled.strings.len()],
        bytes: 0,
        steps: 0,
        since_clock: 0,
        next_anchored: 0,
        prefix_hits: vec![None; compiled.prefixes.len()],
        short_read: false,
    };
    let partial = len > limits.max_file_size;
    let result = scan
        .prefixes()
        .and_then(|()| scan.probe_pe())
        .and_then(|()| {
            if partial {
                let tail = len.saturating_sub(TAIL_SCAN_LEN).max(limits.max_file_size);
                scan.region(0, limits.max_file_size)?;
                scan.region(tail, len)
            } else {
                scan.region(0, len)
            }
        });
    report.status = match result {
        Err(Stop::Io(kind)) => ScanStatus::ReadError(kind),
        Err(Stop::Budget) => ScanStatus::Timeout,
        Ok(()) if partial => ScanStatus::Partial,
        Ok(()) => ScanStatus::Complete,
    };
    report.is_pe = scan.overlay.is_some();
    report.bytes_scanned = scan.bytes;
    report.match_steps = scan.steps;
    for rule in &compiled.rules {
        if rule.require_pe && !report.is_pe {
            continue;
        }
        if rule.max_file_size.is_some_and(|max| len > max) {
            continue;
        }
        // A filter that was not checked is treated as a hit: the rule is
        // not reported on evidence its own filter might rule out.
        if rule
            .unless
            .is_some_and(|i| scan.prefix_hits.get(i).copied().flatten() != Some(false))
        {
            continue;
        }
        let hits = scan
            .found
            .get(rule.strings.clone())
            .map_or(0, |f| f.iter().filter(|&&hit| hit).count());
        if hits >= rule.need {
            report.tags.push(rule.tag.clone());
        }
    }
    report.tags.extend(report.status.tag().map(str::to_owned));
    report
}

impl<R: Read + Seek + ?Sized> Scan<'_, R> {
    /// Reads `len` bytes at `offset`, or up to the file length the reader
    /// reported, charged to the byte budget. A read the budget cannot cover
    /// is not made. If the reader ends before that, the bytes it gave are
    /// returned and [`Self::short_read`] is set; the caller scans them and
    /// then stops with [`Self::eof`], so a truncated file is never reported
    /// as scanned in full.
    fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, Stop> {
        let len = usize::try_from(self.len.saturating_sub(offset)).map_or(len, |a| a.min(len));
        let cost = u64::try_from(len).unwrap_or(u64::MAX);
        let total = self.bytes.saturating_add(cost);
        if total > self.limits.max_scan_bytes {
            return Err(Stop::Budget);
        }
        self.reader.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0_u8; len];
        let got = read_full(self.reader, &mut buf)?;
        buf.truncate(got);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(got).unwrap_or(u64::MAX));
        if got < len {
            self.short_read = true;
        }
        Ok(buf)
    }

    /// Stops the scan if a read came up short.
    fn eof(&self) -> Result<(), Stop> {
        if self.short_read {
            Err(Stop::Io(io::ErrorKind::UnexpectedEof))
        } else {
            Ok(())
        }
    }

    /// Checks every `unless_start` pattern against the start of the file,
    /// before anything else is scanned, so no budget can run out between a
    /// rule's strings and its filter.
    fn prefixes(&mut self) -> Result<(), Stop> {
        let compiled = self.compiled;
        if compiled.prefixes.is_empty() {
            return Ok(());
        }
        let head = self.read_at(0, compiled.prefix_len)?;
        // A file shorter than a pattern does not start with it; a file
        // that ended early might, so nothing is decided.
        self.eof()?;
        for (i, matcher) in compiled.prefixes.iter().enumerate() {
            self.step(matcher.cost())?;
            if let Some(hit) = self.prefix_hits.get_mut(i) {
                *hit = Some(matcher.matches_at(&head, 0));
            }
        }
        Ok(())
    }

    /// Parses the PE headers, as [`crate::filetype::classify`] does: only
    /// the bytes from the DOS header to the end of the section table, with
    /// the parser's directory work off. Sets [`Self::overlay`] if they
    /// parse.
    fn probe_pe(&mut self) -> Result<(), Stop> {
        const DOS_LEN: usize = 0x40;
        const COFF_LEN: u64 = 20;
        const SECTION_HEADER_LEN: u64 = 40;
        if self.len < DOS_LEN as u64 {
            return Ok(());
        }
        let dos = self.read_at(0, DOS_LEN)?;
        self.eof()?;
        let e_lfanew = match (dos.get(..2), dos.get(0x3c..0x40)) {
            (Some(b"MZ"), Some(&[a, b, c, d])) => u32::from_le_bytes([a, b, c, d]),
            _ => return Ok(()),
        };
        if e_lfanew > pe::MAX_E_LFANEW {
            return Ok(());
        }
        let coff_at = u64::from(e_lfanew) + 4;
        let nt = self.read_at(u64::from(e_lfanew), 24)?;
        self.eof()?;
        if nt.get(..4) != Some(&b"PE\0\0"[..]) {
            return Ok(());
        }
        let field = |at| u16_at(&nt, at).map_or(0, u64::from);
        let (sections, optional_len) = (field(6), field(20));
        let sections = sections.min(u64::try_from(pe::MAX_SECTIONS).unwrap_or(u64::MAX));
        let end = coff_at + COFF_LEN + optional_len + sections * SECTION_HEADER_LEN;
        let want = usize::try_from(end).map_err(|_| Stop::Budget)?;
        let headers = self.read_at(0, want)?;
        self.eof()?;
        // A file that ends inside its headers is not mapped by the loader,
        // and the classifier does not call it a PE image either.
        if headers.len() < want {
            return Ok(());
        }
        let Ok(info) = pe::parse_headers_only(&headers, self.len) else {
            return Ok(());
        };
        let file_alignment = info.optional.file_alignment;
        // As the parser finds the overlay: sections whose data starts past
        // the end of the file do not count.
        let sections_end = info
            .sections
            .iter()
            .filter_map(|s| s.file_data(file_alignment))
            .filter(|(start, _)| u64::from(*start) < self.len)
            .map(|(start, size)| u64::from(start).saturating_add(u64::from(size)))
            .max()
            .unwrap_or(0);
        let start = sections_end
            .max(u64::from(info.optional.size_of_headers))
            .max(end)
            .min(self.len);
        self.overlay = Some(start);
        Ok(())
    }

    /// Scans `start..end`, chunk by chunk.
    fn region(&mut self, start: u64, end: u64) -> Result<(), Stop> {
        let end = end.min(self.len);
        if start >= end {
            return Ok(());
        }
        let keep = self.compiled.window.saturating_sub(1);
        let mut buf: Vec<u8> = Vec::new();
        // The file offset of `buf[0]`, and the first start this chunk owns.
        let mut base = start;
        let mut owned_from = start;
        let mut next = start;
        while next < end {
            self.check_clock()?;
            let want = usize::try_from(end - next).map_or(CHUNK_LEN, |n| n.min(CHUNK_LEN));
            let chunk = self.read_at(next, want)?;
            next = next.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            buf.extend_from_slice(&chunk);
            let buf_end = base.saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
            // After a short read, the bytes that did arrive are still
            // scanned, as the last chunk, before the scan stops.
            let last = next >= end || self.short_read;
            let owned_to = if last {
                buf_end
            } else {
                buf_end
                    .saturating_sub(u64::try_from(keep).unwrap_or(u64::MAX))
                    .max(owned_from)
            };
            self.chunk(&buf, base, owned_from, owned_to)?;
            if last {
                return self.eof();
            }
            let drop = usize::try_from(owned_to - base).unwrap_or(buf.len());
            buf.drain(..drop.min(buf.len()));
            base = owned_to;
            owned_from = owned_to;
        }
        Ok(())
    }

    /// Checks every string start in `owned_from..owned_to`; `buf` holds the
    /// bytes from `base`.
    fn chunk(&mut self, buf: &[u8], base: u64, owned_from: u64, owned_to: u64) -> Result<(), Stop> {
        let compiled = self.compiled;
        // Strings at a fixed offset.
        while let Some(a) = compiled.anchored.get(self.next_anchored) {
            if a.start >= owned_to {
                break;
            }
            self.next_anchored += 1;
            if a.start < owned_from {
                continue;
            }
            self.check(buf, base, a.string, a.start)?;
        }
        // Everything else, through its atom.
        let Some(searcher) = &compiled.searcher else {
            return Ok(());
        };
        let Ok(matches) = searcher.try_find_overlapping_iter(buf) else {
            return Err(Stop::Budget);
        };
        for m in matches {
            let at = base.saturating_add(u64::try_from(m.start()).unwrap_or(u64::MAX));
            let users = compiled
                .atom_users
                .get(m.pattern().as_usize())
                .map_or(&[][..], Vec::as_slice);
            for &(string, offset) in users {
                self.step(1)?;
                if self.found.get(string).copied().unwrap_or(true) {
                    continue;
                }
                let Some(start) = at.checked_sub(u64::try_from(offset).unwrap_or(u64::MAX)) else {
                    continue;
                };
                if start < owned_from || start >= owned_to {
                    continue;
                }
                self.check(buf, base, string, start)?;
            }
        }
        Ok(())
    }

    /// Checks string `string` at file offset `start`, if its location
    /// allows it there.
    fn check(&mut self, buf: &[u8], base: u64, string: usize, start: u64) -> Result<(), Stop> {
        let Some(s) = self.compiled.strings.get(string) else {
            return Ok(());
        };
        let allowed = match s.location {
            Location::Anywhere => true,
            Location::At(n) => start == n,
            Location::From(n) => start >= n,
            Location::Range { start: lo, end: hi } => (lo..hi).contains(&start),
            Location::Overlay => self.overlay.is_some_and(|o| start >= o),
            Location::Tail(n) => start >= self.len.saturating_sub(n),
        };
        if !allowed {
            return Ok(());
        }
        self.step(s.matcher.cost())?;
        let Some(at) = start
            .checked_sub(base)
            .and_then(|d| usize::try_from(d).ok())
        else {
            return Ok(());
        };
        if s.matcher.matches_at(buf, at) {
            if let Some(hit) = self.found.get_mut(string) {
                *hit = true;
            }
        }
        Ok(())
    }

    /// Charges `n` steps, and checks the clock now and then.
    fn step(&mut self, n: u64) -> Result<(), Stop> {
        let total = self.steps.saturating_add(n);
        if total > self.limits.max_match_steps {
            return Err(Stop::Budget);
        }
        self.steps = total;
        self.since_clock += 1;
        if self.since_clock >= CLOCK_EVERY {
            self.check_clock()?;
        }
        Ok(())
    }

    fn check_clock(&mut self) -> Result<(), Stop> {
        self.since_clock = 0;
        match self.limits.timeout {
            Some(t) if self.started.elapsed() >= t => Err(Stop::Budget),
            _ => Ok(()),
        }
    }
}

/// Fills `buf` from `reader`, stopping early only at end of input.
fn read_full<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..) {
        if rest.is_empty() {
            break;
        }
        match reader.read(rest) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
