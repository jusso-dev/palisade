//! One-pass hashing of a whole file: flat hashes, Authenticode digests and
//! page hash tables from a single sequential read (#46, #47).

// Test code: fixture sizes are small constants, so narrowing casts cannot
// truncate, and helpers may unwrap, since a failure should fail loudly.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

mod common;

use std::io::{self, Read};

use common::*;
use palisade_fileid::authenticode::{
    HEADER_PREFIX_LEN, ImageHashOptions, ImageHashStatus, ImageHashes, authenticode_hashes,
    hash_image_file, hash_image_reader,
};
use palisade_fileid::hash::{
    AlgorithmSet, HashAlgorithm, HashError, HashOptions, MIN_BUFFER_SIZE, hash_bytes,
};
use palisade_fileid::pe;
use proptest::prelude::*;

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// A PE image larger than the header prefix and several read buffers, so
/// hashing spans many chunks.
fn big_image() -> Vec<u8> {
    PeBuilder::default()
        .section(
            ".data",
            pattern(HEADER_PREFIX_LEN + 3 * MIN_BUFFER_SIZE + 123, 5),
            IMAGE_SCN_CNT_INITIALIZED_DATA,
        )
        .build()
}

/// A reader that counts how many bytes it hands out and returns them in
/// short, uneven reads.
struct Counting<'a> {
    data: &'a [u8],
    at: usize,
    reads: usize,
    step: usize,
}

impl<'a> Counting<'a> {
    fn new(data: &'a [u8], step: usize) -> Self {
        Self {
            data,
            at: 0,
            reads: 0,
            step,
        }
    }
}

impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        // Every third read is interrupted, which must be retried.
        if self.reads % 3 == 0 {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let n = buf.len().min(self.step).min(self.data.len() - self.at);
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

fn complete(status: ImageHashStatus) -> ImageHashes {
    match status {
        ImageHashStatus::Complete(h) => h,
        other => panic!("{other:?}"),
    }
}

/// What the separate in-memory functions give.
fn expected(data: &[u8], options: &ImageHashOptions) -> ImageHashes {
    let authenticode = pe::parse(data)
        .ok()
        .map(|info| authenticode_hashes(data, &info, options.authenticode_extra).unwrap());
    ImageHashes {
        flat: hash_bytes(data, options.hash.algorithms),
        authenticode,
    }
}

fn options(parallel: bool) -> ImageHashOptions {
    ImageHashOptions {
        hash: HashOptions {
            algorithms: AlgorithmSet::ALL,
            buffer_size: MIN_BUFFER_SIZE,
            ..HashOptions::default()
        },
        authenticode_extra: AlgorithmSet::SHA384,
        parallel,
    }
}

#[test]
fn one_pass_equals_the_separate_functions() {
    let image = big_image();
    for parallel in [false, true] {
        let opts = options(parallel);
        let mut reader = Counting::new(&image, 70_001);
        let got = complete(hash_image_reader(&mut reader, image.len() as u64, &opts).unwrap());
        assert_eq!(got, expected(&image, &opts), "parallel={parallel}");
        // Exactly one pass: every byte was handed out once.
        assert_eq!(reader.at, image.len());
        let auth = got.authenticode.as_ref().unwrap();
        assert!(auth.page_tables().is_some());
        assert!(auth.page_sha256().is_some() && auth.page_sha1().is_some());
        assert!(auth.get(HashAlgorithm::Sha384).is_some());
        assert_eq!(
            got.flat
                .digests
                .iter()
                .map(|d| d.algorithm())
                .collect::<Vec<_>>(),
            HashAlgorithm::ALL
        );
    }
}

#[test]
fn default_options_compute_the_default_sets() {
    let image = PeBuilder::default().build();
    let got = complete(
        hash_image_reader(&image[..], image.len() as u64, &ImageHashOptions::default()).unwrap(),
    );
    assert_eq!(got, expected(&image, &ImageHashOptions::default()));
    let auth = got.authenticode.unwrap();
    assert_eq!(
        auth.digests
            .iter()
            .map(|d| d.algorithm())
            .collect::<Vec<_>>(),
        [HashAlgorithm::Sha256, HashAlgorithm::Sha1]
    );
}

#[test]
fn non_pe_files_get_flat_hashes_only() {
    for data in [
        &b""[..],
        b"#!/bin/sh\necho hi\n",
        b"MZ",
        &pattern(200_000, 9),
    ] {
        for parallel in [false, true] {
            let got =
                complete(hash_image_reader(data, data.len() as u64, &options(parallel)).unwrap());
            assert!(got.authenticode.is_none());
            assert_eq!(got.flat, hash_bytes(data, AlgorithmSet::ALL));
            assert_eq!(got.flat.empty, data.is_empty());
        }
    }
}

/// An image whose layout has no page table still gets its image digests,
/// and the reason there are no page hashes.
#[test]
fn non_conformant_image_reports_why_it_has_no_pages() {
    let image = PeBuilder {
        certificate: Some(vec![0; 16]),
        overlay: vec![1; 8],
        ..PeBuilder::default()
    }
    .build();
    for parallel in [false, true] {
        let got = complete(
            hash_image_reader(&image[..], image.len() as u64, &options(parallel)).unwrap(),
        );
        assert_eq!(got, expected(&image, &options(parallel)));
        let auth = got.authenticode.unwrap();
        assert!(!auth.status.is_conformant());
        assert!(matches!(auth.page_hashes, Some(Err(_))));
    }
}

#[test]
fn a_file_that_changes_size_is_an_error() {
    let image = big_image();
    for parallel in [false, true] {
        let opts = options(parallel);
        // Shorter than its metadata said.
        let err = hash_image_reader(&image[..], image.len() as u64 + 1, &opts).unwrap_err();
        assert!(
            matches!(err, HashError::SizeChanged { expected, actual } if expected == image.len() as u64 + 1 && actual == image.len() as u64),
            "{err}"
        );
        // Longer: it stops as soon as that is seen.
        let err = hash_image_reader(&image[..], image.len() as u64 - 1, &opts).unwrap_err();
        assert!(matches!(err, HashError::SizeChanged { .. }), "{err}");
        // Shorter than the header prefix.
        let small = PeBuilder::default().build();
        let err = hash_image_reader(&small[..], small.len() as u64 + 10, &opts).unwrap_err();
        assert!(matches!(err, HashError::SizeChanged { .. }), "{err}");
    }
}

#[test]
fn size_limit_is_checked_before_reading() {
    let image = big_image();
    let mut opts = options(false);
    opts.hash.max_hash_size = image.len() as u64 - 1;
    let mut reader = Counting::new(&image, 4096);
    assert_eq!(
        hash_image_reader(&mut reader, image.len() as u64, &opts).unwrap(),
        ImageHashStatus::TooLarge {
            limit: image.len() as u64 - 1
        }
    );
    assert_eq!(reader.at, 0);
}

#[test]
fn invalid_options_are_rejected() {
    let mut opts = ImageHashOptions::default();
    opts.hash.algorithms = AlgorithmSet::EMPTY;
    assert!(matches!(
        hash_image_reader(&b""[..], 0, &opts),
        Err(HashError::NoAlgorithms)
    ));
}

#[test]
fn read_errors_are_returned() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("disk on fire"))
        }
    }
    for parallel in [false, true] {
        assert!(matches!(
            hash_image_reader(Failing, 10, &options(parallel)),
            Err(HashError::Io(_))
        ));
    }
    // A reader that fails after the prefix, in the middle of hashing.
    struct FailsLater<'a>(&'a [u8]);
    impl Read for FailsLater<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::Error::other("disk on fire"));
            }
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    let image = big_image();
    for parallel in [false, true] {
        let half = &image[..HEADER_PREFIX_LEN + MIN_BUFFER_SIZE];
        assert!(matches!(
            hash_image_reader(FailsLater(half), image.len() as u64, &options(parallel)),
            Err(HashError::Io(_))
        ));
    }
}

#[test]
fn files_on_disk() {
    let dir = std::env::temp_dir().join(format!("palisade-image-hash-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("image.exe");
    let image = big_image();
    std::fs::write(&path, &image).unwrap();
    let opts = options(true);
    assert_eq!(
        complete(hash_image_file(&path, &opts).unwrap()),
        expected(&image, &opts)
    );
    assert!(matches!(
        hash_image_file(&dir, &opts),
        Err(HashError::NotAFile | HashError::Io(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Any read sizes, any image: the one-pass result equals the separate
    /// functions, serial and parallel.
    #[test]
    fn read_sizes_do_not_matter(
        step in 1_usize..200_000,
        extra in 0_usize..20_000,
        overlay in proptest::collection::vec(any::<u8>(), 0..20),
        parallel in any::<bool>(),
    ) {
        let image = PeBuilder {
            overlay,
            ..PeBuilder::default().section(".data", pattern(extra, 2), IMAGE_SCN_CNT_INITIALIZED_DATA)
        }
        .build();
        let opts = options(parallel);
        let got = complete(
            hash_image_reader(Counting::new(&image, step), image.len() as u64, &opts).unwrap(),
        );
        prop_assert_eq!(got, expected(&image, &opts));
    }
}
