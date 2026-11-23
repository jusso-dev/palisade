//! Flat-hash known-answer tests and streaming behaviour.

// Fixture sizes are small constants, so narrowing casts cannot truncate.
#![allow(clippy::cast_possible_truncation)]

use std::io::{self, Read, Write};

use palisade_fileid::hash::{
    AlgorithmSet, Digest, DigestError, HashAlgorithm, HashOptions, HashStatus, MIN_BUFFER_SIZE,
    MultiHasher, hash_bytes, hash_file, hash_reader,
};

/// FIPS 180-4 / RFC 1321 example messages and their digests.
const VECTORS: &[(&[u8], [&str; 5])] = &[
    (
        b"",
        [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "d41d8cd98f00b204e9800998ecf8427e",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ],
    ),
    (
        b"abc",
        [
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
            "900150983cd24fb0d6963f7d28e17f72",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ],
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        [
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            "8215ef0796a20bcaaae116d3876c664a",
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        ],
    ),
];

const ORDER: [HashAlgorithm; 5] = [
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha1,
    HashAlgorithm::Md5,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
];

#[test]
fn known_answers_for_every_algorithm() {
    for (message, expected) in VECTORS {
        let hashes = hash_bytes(message, AlgorithmSet::ALL);
        assert_eq!(hashes.digests.len(), 5);
        assert_eq!(hashes.size, message.len() as u64);
        for (alg, hex) in ORDER.iter().zip(expected) {
            let digest = hashes.get(*alg).unwrap();
            assert_eq!(&digest.to_string(), hex, "{alg} of {message:?}");
            assert_eq!(digest.as_bytes().len(), alg.digest_len());
        }
    }
}

#[test]
fn million_a_sha256() {
    // FIPS 180-4: one million repetitions of "a".
    let data = vec![b'a'; 1_000_000];
    let hashes = hash_bytes(&data, AlgorithmSet::SHA256);
    assert_eq!(
        hashes.get(HashAlgorithm::Sha256).unwrap().to_string(),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn empty_input_is_flagged() {
    let empty = hash_bytes(b"", AlgorithmSet::DEFAULT);
    assert!(empty.empty);
    assert_eq!(empty.size, 0);
    assert_eq!(empty.digests.len(), 3);
    assert!(!hash_bytes(b"x", AlgorithmSet::DEFAULT).empty);
}

#[test]
fn only_selected_algorithms_are_computed() {
    let hashes = hash_bytes(b"abc", AlgorithmSet::SHA256 | AlgorithmSet::SHA512);
    assert_eq!(hashes.digests.len(), 2);
    assert!(hashes.get(HashAlgorithm::Sha256).is_some());
    assert!(hashes.get(HashAlgorithm::Sha512).is_some());
    assert!(hashes.get(HashAlgorithm::Md5).is_none());
    let default = hash_bytes(b"abc", AlgorithmSet::default());
    let algs: Vec<_> = default.digests.iter().map(Digest::algorithm).collect();
    assert_eq!(
        algs,
        [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha1,
            HashAlgorithm::Md5
        ]
    );
}

#[test]
fn chunking_does_not_change_the_result() {
    let data: Vec<u8> = (0..10_000_u32).map(|i| (i * 7 + 3) as u8).collect();
    let whole = hash_bytes(&data, AlgorithmSet::ALL);
    for chunk in [1, 3, 63, 64, 65, 127, 128, 129, 4096] {
        let mut hasher = MultiHasher::new(AlgorithmSet::ALL);
        for part in data.chunks(chunk) {
            hasher.update(part);
        }
        assert_eq!(hasher.bytes_hashed(), data.len() as u64);
        assert_eq!(hasher.finalize(), whole, "chunk size {chunk}");
    }
}

/// A reader that returns at most `step` bytes per call and fails with
/// `Interrupted` every other call.
struct Trickle<'a> {
    data: &'a [u8],
    step: usize,
    interrupt: bool,
    reads: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.interrupt = true;
        let n = self.step.min(buf.len()).min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

#[test]
fn reader_handles_short_and_interrupted_reads() {
    let data = vec![0x5a_u8; 300_000];
    let reader = Trickle {
        data: &data,
        step: 10_000,
        interrupt: true,
        reads: 0,
    };
    let status = hash_reader(reader, &HashOptions::default()).unwrap();
    let HashStatus::Complete(hashes) = status else {
        panic!("{status:?}");
    };
    assert_eq!(hashes, hash_bytes(&data, AlgorithmSet::DEFAULT));
}

#[test]
fn reader_errors_are_returned() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("disk on fire"))
        }
    }
    let err = hash_reader(Broken, &HashOptions::default()).unwrap_err();
    assert!(err.to_string().contains("disk on fire"));
}

#[test]
fn size_limit_stops_reading() {
    let data = vec![1_u8; MIN_BUFFER_SIZE * 3];
    let options = HashOptions {
        buffer_size: MIN_BUFFER_SIZE,
        max_hash_size: (MIN_BUFFER_SIZE * 2) as u64,
        ..HashOptions::default()
    };
    let status = hash_reader(&data[..], &options).unwrap();
    assert_eq!(
        status,
        HashStatus::TooLarge {
            limit: (MIN_BUFFER_SIZE * 2) as u64
        }
    );
    // Exactly at the limit is fine.
    let status = hash_reader(&data[..MIN_BUFFER_SIZE * 2], &options).unwrap();
    assert!(matches!(status, HashStatus::Complete(h) if h.size == (MIN_BUFFER_SIZE * 2) as u64));
}

#[test]
fn hashes_a_file_on_disk() {
    let dir = std::env::temp_dir().join(format!("palisade-fileid-hash-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sample.bin");
    let data: Vec<u8> = (0..(3 * MIN_BUFFER_SIZE + 17))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&data)
        .unwrap();

    let options = HashOptions {
        algorithms: AlgorithmSet::ALL,
        buffer_size: MIN_BUFFER_SIZE,
        ..HashOptions::default()
    };
    let status = hash_file(&path, &options).unwrap();
    assert_eq!(
        status,
        HashStatus::Complete(hash_bytes(&data, AlgorithmSet::ALL))
    );

    let small_limit = HashOptions {
        max_hash_size: 100,
        ..options
    };
    assert_eq!(
        hash_file(&path, &small_limit).unwrap(),
        HashStatus::TooLarge { limit: 100 }
    );

    std::fs::remove_dir_all(&dir).unwrap();
    assert!(hash_file(&path, &options).is_err());
}

#[test]
fn digest_display_and_parse() {
    let hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let d = Digest::parse(HashAlgorithm::Sha256, hex).unwrap();
    assert_eq!(d.to_string(), hex);
    assert_eq!(format!("{d:?}"), format!("sha256:{hex}"));
    assert_eq!(
        Digest::parse(HashAlgorithm::Sha256, &hex.to_uppercase()).unwrap(),
        d
    );
    assert_eq!(
        Digest::parse(HashAlgorithm::Sha256, &format!("0x{hex}")).unwrap(),
        d
    );
    assert_eq!(
        Digest::parse(HashAlgorithm::Sha256, &format!("0X{}", hex.to_uppercase())).unwrap(),
        d
    );
    assert_eq!(Digest::new(HashAlgorithm::Sha256, d.as_bytes()).unwrap(), d);
}

#[test]
fn digest_parse_rejects_bad_input() {
    let hex = "900150983cd24fb0d6963f7d28e17f72";
    assert!(matches!(
        Digest::parse(HashAlgorithm::Md5, &hex[..30]),
        Err(DigestError::WrongLength {
            expected: 16,
            actual: 15,
            ..
        })
    ));
    assert!(matches!(
        Digest::parse(HashAlgorithm::Sha256, hex),
        Err(DigestError::WrongLength { expected: 32, .. })
    ));
    let mut bad = hex.to_owned();
    bad.replace_range(5..6, "g");
    assert_eq!(
        Digest::parse(HashAlgorithm::Md5, &bad),
        Err(DigestError::InvalidHex { index: 5 })
    );
    let spaced = format!(" {}", &hex[1..]);
    assert_eq!(
        Digest::parse(HashAlgorithm::Md5, &spaced),
        Err(DigestError::InvalidHex { index: 0 })
    );
    // A multi-byte character of the right byte length is not hex.
    let unicode = format!("é{}", &hex[2..]);
    assert!(Digest::parse(HashAlgorithm::Md5, &unicode).is_err());
    assert!(Digest::parse(HashAlgorithm::Md5, "0x").is_err());
    assert!(Digest::new(HashAlgorithm::Sha1, &[0; 19]).is_err());
    assert!(!DigestError::InvalidHex { index: 1 }.to_string().is_empty());
}
