//! Bounded reads from the file being classified.
//!
//! The classifier reads the first [`HEAD_LEN`] bytes once, then makes a few
//! targeted reads at offsets taken from the file's own structures (a PE
//! header beyond the head, a ZIP end-of-directory record, a compound file
//! directory entry). Every targeted read is clamped to the file length and
//! counted against [`MAX_TARGETED_READ`], so no input can make the
//! classifier read, or allocate for, more than a fixed amount.

#![forbid(unsafe_code)]

use std::io::{self, Read, Seek, SeekFrom};

/// Bytes read from the start of every file.
pub const HEAD_LEN: usize = 64 * 1024;

/// The most bytes read outside the head for one file, over all targeted
/// reads. The largest single consumer is the ZIP central directory (capped
/// at [`MAX_ZIP_DIRECTORY`](super::MAX_ZIP_DIRECTORY)); the rest covers the
/// ZIP end records, PE headers past the head and the PE directory probes.
pub const MAX_TARGETED_READ: usize = 4 * 1024 * 1024 + 256 * 1024;

/// Why a read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadError {
    /// The reader returned an error.
    Io(io::ErrorKind),
    /// The read would exceed [`MAX_TARGETED_READ`].
    Budget,
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// The file being classified: its length, its head, and a budget for
/// targeted reads.
pub(super) struct Source<'r, R: ?Sized> {
    reader: &'r mut R,
    len: u64,
    head: Vec<u8>,
    budget: usize,
}

impl<'r, R: Read + Seek + ?Sized> Source<'r, R> {
    /// Finds the length and reads the head.
    pub(super) fn open(reader: &'r mut R) -> Result<Self, ReadError> {
        let len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let want = usize::try_from(len).map_or(HEAD_LEN, |l| l.min(HEAD_LEN));
        let mut head = vec![0_u8; want];
        let got = read_full(reader, &mut head)?;
        head.truncate(got);
        Ok(Self {
            reader,
            len,
            head,
            budget: MAX_TARGETED_READ,
        })
    }

    /// The file length, as the reader reported it when opened.
    pub(super) const fn len(&self) -> u64 {
        self.len
    }

    /// The first [`HEAD_LEN`] bytes, or the whole file if it is shorter.
    pub(super) fn head(&self) -> &[u8] {
        &self.head
    }

    /// Reads up to `len` bytes at `offset`. The result is shorter when the
    /// file ends first. A range inside the head is served from it and costs
    /// nothing; any other read is charged in full to the budget.
    pub(super) fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, ReadError> {
        let available = self.len.saturating_sub(offset);
        let len = usize::try_from(available).map_or(len, |a| a.min(len));
        if len == 0 {
            return Ok(Vec::new());
        }
        if let Some(cached) = usize::try_from(offset)
            .ok()
            .and_then(|start| self.head.get(start..start.checked_add(len)?))
        {
            return Ok(cached.to_vec());
        }
        self.budget = self.budget.checked_sub(len).ok_or(ReadError::Budget)?;
        self.reader.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0_u8; len];
        let got = read_full(self.reader, &mut buf)?;
        buf.truncate(got);
        Ok(buf)
    }
}

/// Fills `buf` from `reader`, stopping early only at end of input. Returns
/// the number of bytes read.
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

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn head_is_capped_and_reads_are_clamped() {
        let data: Vec<u8> = (0..HEAD_LEN + 10).map(|i| (i % 251) as u8).collect();
        let mut cursor = Cursor::new(data.clone());
        let mut src = Source::open(&mut cursor).unwrap();
        assert_eq!(src.len(), data.len() as u64);
        assert_eq!(src.head(), &data[..HEAD_LEN]);
        // Inside the head: free.
        assert_eq!(src.read_at(4, 4).unwrap(), &data[4..8]);
        assert_eq!(src.budget, MAX_TARGETED_READ);
        // Past the head, clamped at end of file.
        let tail = src.read_at(HEAD_LEN as u64 + 5, 100).unwrap();
        assert_eq!(tail, &data[HEAD_LEN + 5..]);
        assert_eq!(src.budget, MAX_TARGETED_READ - 5);
        // Past the end: nothing, at no cost.
        assert!(src.read_at(u64::MAX, 10).unwrap().is_empty());
        assert_eq!(src.budget, MAX_TARGETED_READ - 5);
    }

    #[test]
    fn budget_is_enforced() {
        let data = vec![0_u8; HEAD_LEN + MAX_TARGETED_READ + 10];
        let mut cursor = Cursor::new(data);
        let mut src = Source::open(&mut cursor).unwrap();
        assert!(src.read_at(HEAD_LEN as u64, MAX_TARGETED_READ).is_ok());
        assert_eq!(src.read_at(HEAD_LEN as u64, 1), Err(ReadError::Budget));
    }

    #[test]
    fn short_reads_are_retried() {
        /// Returns at most one byte per call, and is interrupted every
        /// other call.
        struct Trickle(Cursor<Vec<u8>>, bool);
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.1 = !self.1;
                if self.1 {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let n = buf.len().min(1);
                self.0.read(&mut buf[..n])
            }
        }
        impl Seek for Trickle {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.0.seek(pos)
            }
        }
        let mut t = Trickle(Cursor::new(b"hello".to_vec()), false);
        let src = Source::open(&mut t).unwrap();
        assert_eq!(src.head(), b"hello");
    }
}
