//! Fuzzes content-based file type detection: no input may panic, hang or
//! read without bound, under any name hint, and every result must be
//! internally consistent.
#![no_main]

use std::ffi::OsStr;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use libfuzzer_sys::fuzz_target;
use palisade_fileid::filetype::{
    self, CLASSIFIER_VERSION, FileKind, HEAD_LEN, MAX_COM_SIZE, MAX_TARGETED_READ,
    MismatchSeverity,
};

const NAMES: [Option<&str>; 6] = [
    None,
    Some("a.exe"),
    Some("x.com"),
    Some("invoice.pdf.exe"),
    Some("s.ps1"),
    Some("m.msm"),
];

/// Counts every byte read.
struct Counting<'a> {
    inner: Cursor<&'a [u8]>,
    read: usize,
}

impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n;
        Ok(n)
    }
}

impl Seek for Counting<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

fuzz_target!(|data: &[u8]| {
    for name in NAMES {
        let mut reader = Counting {
            inner: Cursor::new(data),
            read: 0,
        };
        let c = filetype::classify(&mut reader, name.map(OsStr::new));
        assert!(reader.read <= HEAD_LEN + MAX_TARGETED_READ);
        assert_eq!(c.classifier_version, CLASSIFIER_VERSION);
        assert_eq!(c.file_size, data.len() as u64);
        assert_eq!(c.mismatch, c.mismatch_severity != MismatchSeverity::None);
        assert_eq!(c.pe.is_some(), c.content_kind == FileKind::Pe);
        if c.content_kind == FileKind::Com {
            assert!(c.heuristic && c.file_size <= MAX_COM_SIZE);
        }
        // A ZIP that could not be read in one consistent way fails closed.
        if c.content_kind == FileKind::Zip && c.parse_error.is_some() {
            assert!(c.is_executable_content());
        }
    }
});
