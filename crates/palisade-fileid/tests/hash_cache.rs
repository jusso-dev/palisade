//! The hash cache, verify-on-launch modes, file stamps, the parallel-hash
//! limit and the metrics (#46).

// Test code: helpers may unwrap, since a failure should fail loudly.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use palisade_fileid::fsctx::LocationClass;
use palisade_fileid::hash::cache::{FILEID_LIB_VERSION, IMAGE_TIER_VERSION};
use palisade_fileid::hash::{
    AlgorithmSet, CacheConfig, CacheRecord, CacheValue, DeferReason, FileKey, FileLocation,
    FileStamp, FileTime, FlatTier, HashAlgorithm, HashCache, HashLimiter, HashPurpose,
    HashVerifyMode, ImageTier, MIN_KEY_LEN, MacKey, Miss, RecordError, Through, ValueSource,
    default_max_parallel_hashes, hash_bytes, hash_through, skip_for_inventory,
};
use proptest::prelude::*;

fn strong(file: u8, usn: i64) -> FileKey {
    FileKey::Strong {
        volume_serial: 0xabcd,
        file_id: [file; 16],
        usn_journal_id: 77,
        usn,
        last_write: FileTime(1_000),
        size: 3,
    }
}

fn weak(path: &str, last_write: u64) -> FileKey {
    FileKey::Weak {
        path: path.to_owned(),
        size: 3,
        last_write: FileTime(last_write),
        creation: FileTime(500),
    }
}

fn value(data: &[u8]) -> CacheValue {
    CacheValue::from_flat(hash_bytes(data, AlgorithmSet::DEFAULT), 1, FileTime(42))
}

fn key() -> MacKey {
    MacKey::new(&[7; MIN_KEY_LEN]).unwrap()
}

// --- Keys and invalidation. --------------------------------------------------

#[test]
fn a_hit_needs_every_key_component_to_match() {
    let mut cache = HashCache::default();
    let base = strong(1, 10);
    cache.insert(base.clone(), Some("C:\\a.exe".into()), value(b"abc"));
    assert_eq!(cache.get(&base, None).unwrap(), &value(b"abc"));

    let k = |f: &dyn Fn(&mut FileKey)| {
        let mut k = base.clone();
        f(&mut k);
        k
    };
    let changed = [
        k(&|k| {
            if let FileKey::Strong { usn, .. } = k {
                *usn += 1
            }
        }),
        k(&|k| {
            if let FileKey::Strong { usn_journal_id, .. } = k {
                *usn_journal_id += 1
            }
        }),
        k(&|k| {
            if let FileKey::Strong { last_write, .. } = k {
                last_write.0 += 1
            }
        }),
        k(&|k| {
            if let FileKey::Strong { size, .. } = k {
                *size += 1
            }
        }),
    ];
    for k in changed {
        cache.insert(base.clone(), None, value(b"abc"));
        assert_eq!(cache.get(&k, None), Err(Miss::Changed), "{k}");
        // The stale entry is gone: even the old key misses now.
        assert_eq!(cache.get(&base, None), Err(Miss::NotCached));
    }
    // Another file, or another volume, is a different identity.
    cache.insert(base.clone(), None, value(b"abc"));
    assert_eq!(cache.get(&strong(2, 10), None), Err(Miss::NotCached));
    let other_volume = k(&|k| {
        if let FileKey::Strong { volume_serial, .. } = k {
            *volume_serial = 1;
        }
    });
    assert_eq!(cache.get(&other_volume, None), Err(Miss::NotCached));
    assert_eq!(cache.len(), 1);
}

#[test]
fn a_new_path_to_the_same_key_is_recorded_and_counted() {
    // A hard link: another path to the same file, same key.
    let mut cache = HashCache::new(CacheConfig {
        max_entries: 10,
        max_bytes: 4_000,
    });
    let k = strong(1, 10);
    cache.insert(k.clone(), None, value(b"abc"));
    let before = cache.bytes();
    let long = format!("C:\\{}", "d".repeat(1_000));
    assert!(cache.get(&k, Some(&long)).is_ok());
    assert_eq!(cache.path_of(&k), Some(long.as_str()));
    assert_eq!(cache.bytes(), before + long.len());
    // Back to a short path: the bytes come back down.
    assert!(cache.get(&k, Some("C:\\a")).is_ok());
    assert_eq!(cache.bytes(), before + 4);
    // A path that pushes the cache past its byte bound evicts older
    // entries, never the one just used.
    cache.insert(strong(2, 1), None, value(b"abc"));
    cache.insert(strong(3, 1), None, value(b"abc"));
    assert_eq!(cache.len(), 3);
    // Sized so the three entries no longer fit, but `k` alone does.
    let huge = "e".repeat(4_000 - before);
    assert!(cache.get(&k, Some(&huge)).is_ok());
    assert!(cache.bytes() <= 4_000, "{}", cache.bytes());
    assert!(cache.peek(&k).is_some());
    assert!(
        cache.peek(&strong(2, 1)).is_none(),
        "the oldest is evicted first"
    );
    assert!(cache.metrics().snapshot().evictions >= 1);
}

#[test]
fn a_rename_misses_unless_the_journal_consumer_rekeys_it() {
    // A rename moves the file's USN, so on its own it is a miss.
    let mut cache = HashCache::default();
    let old = strong(1, 10);
    cache.insert(old.clone(), Some("C:\\old.exe".into()), value(b"abc"));
    assert_eq!(cache.get(&strong(1, 11), None), Err(Miss::Changed));

    // The journal consumer knows only the file ID: it finds the cached key,
    // checks the journal from that USN shows only a rename, and carries the
    // entry over to the new key and path.
    cache.insert(old.clone(), Some("C:\\old.exe".into()), value(b"abc"));
    assert_eq!(cache.key_of(0xabcd, [1; 16]), Some(&old));
    assert_eq!(cache.key_of(0xabcd, [2; 16]), None);
    let renamed = strong(1, 11);
    assert!(cache.rekey_after_rename(renamed.clone(), Some("C:\\new.exe".into())));
    assert_eq!(cache.get(&renamed, None).unwrap(), &value(b"abc"));
    assert_eq!(cache.path_of(&renamed), Some("C:\\new.exe"));
    assert_eq!(cache.len(), 1);

    // Anything but a later USN with the same content markers drops the
    // entry instead.
    let with = |usn: i64, f: &dyn Fn(&mut FileKey)| {
        let mut k = strong(1, usn);
        f(&mut k);
        k
    };
    let cases: [(&str, FileKey); 5] = [
        (
            "grown",
            with(12, &|k| {
                if let FileKey::Strong { size, .. } = k {
                    *size += 1
                }
            }),
        ),
        (
            "rewritten",
            with(12, &|k| {
                if let FileKey::Strong { last_write, .. } = k {
                    last_write.0 += 1
                }
            }),
        ),
        (
            "new journal",
            with(12, &|k| {
                if let FileKey::Strong { usn_journal_id, .. } = k {
                    *usn_journal_id += 1
                }
            }),
        ),
        ("same USN", strong(1, 10)),
        ("earlier USN", strong(1, 9)),
    ];
    for (why, new) in cases {
        cache.clear();
        cache.insert(old.clone(), None, value(b"abc"));
        assert!(!cache.rekey_after_rename(new, None), "{why}");
        assert!(cache.is_empty(), "{why}");
    }
    // Nothing cached for the file: nothing to carry over.
    assert!(!cache.rekey_after_rename(strong(2, 11), None));
    // Weak keys are never rekeyed.
    let w = weak("C:\\a.exe", 1);
    cache.insert(w.clone(), None, value(b"abc"));
    assert!(!cache.rekey_after_rename(weak("C:\\a.exe", 2), None));
    assert!(cache.is_empty());
}

#[test]
fn weak_keys_fall_back_to_the_path() {
    let mut cache = HashCache::default();
    let k = weak("\\\\server\\share\\a.exe", 1);
    assert!(k.is_weak() && !strong(1, 1).is_weak());
    cache.insert(k.clone(), None, value(b"abc"));
    assert!(cache.get(&k, None).is_ok());
    // Touching only the timestamp is a miss.
    assert_eq!(
        cache.get(&weak("\\\\server\\share\\a.exe", 2), None),
        Err(Miss::Changed)
    );
    // So is a changed creation time.
    cache.insert(k.clone(), None, value(b"abc"));
    let mut created = k.clone();
    if let FileKey::Weak { creation, .. } = &mut created {
        creation.0 += 1;
    }
    assert_eq!(cache.get(&created, None), Err(Miss::Changed));
    cache.insert(k.clone(), None, value(b"abc"));
    assert!(cache.evict_path("\\\\server\\share\\a.exe"));
    assert!(cache.is_empty());
}

#[test]
fn the_journal_consumer_can_evict_by_file_id() {
    let mut cache = HashCache::default();
    cache.insert(strong(1, 10), None, value(b"abc"));
    assert!(cache.evict_file(0xabcd, [1; 16]));
    assert!(!cache.evict_file(0xabcd, [1; 16]));
    assert_eq!(cache.get(&strong(1, 10), None), Err(Miss::NotCached));
}

#[test]
fn outdated_tiers_are_ignored_and_others_kept() {
    let mut cache = HashCache::default();
    let mut old = value(b"abc");
    old.flat.as_mut().unwrap().version = 0;
    cache.insert(strong(1, 1), None, old.clone());
    assert!(
        cache.is_empty(),
        "a value with only outdated tiers is not stored"
    );
    // And it still replaces a current entry for the same file.
    cache.insert(strong(1, 1), None, value(b"abc"));
    cache.insert(strong(1, 1), None, old);
    assert!(cache.is_empty());

    // A value whose image tier is outdated keeps its flat tier.
    let mut mixed = value(b"abc");
    mixed.image = Some(ImageTier {
        version: IMAGE_TIER_VERSION + 1,
        digests: Vec::new(),
        conformant: true,
    });
    cache.insert(strong(1, 1), None, mixed);
    let got = cache.get(&strong(1, 1), None).unwrap();
    assert!(got.flat.is_some() && got.image.is_none());
    assert_eq!(got.fileid_lib_version, FILEID_LIB_VERSION);
}

// --- Bounds. ------------------------------------------------------------------

#[test]
fn least_recently_used_entries_are_evicted() {
    let mut cache = HashCache::new(CacheConfig {
        max_entries: 3,
        max_bytes: usize::MAX,
    });
    for i in 0..3 {
        cache.insert(strong(i, 1), None, value(b"abc"));
    }
    // Touch 0, so 1 is now the oldest.
    assert!(cache.get(&strong(0, 1), None).is_ok());
    cache.insert(strong(3, 1), None, value(b"abc"));
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.get(&strong(1, 1), None), Err(Miss::NotCached));
    for i in [0, 2, 3] {
        assert!(cache.get(&strong(i, 1), None).is_ok(), "{i}");
    }
    assert_eq!(cache.metrics().snapshot().evictions, 1);
}

#[test]
fn the_byte_bound_holds() {
    let mut cache = HashCache::new(CacheConfig {
        max_entries: usize::MAX,
        max_bytes: 2_000,
    });
    for i in 0..200 {
        cache.insert(strong(i, 1), None, value(b"abc"));
        assert!(cache.bytes() <= 2_000 || cache.len() == 1);
    }
    assert!(cache.len() > 1 && cache.len() < 200);
    // One entry larger than the bound is still kept, alone.
    let mut tiny = HashCache::new(CacheConfig {
        max_entries: 10,
        max_bytes: 1,
    });
    tiny.insert(strong(1, 1), None, value(b"abc"));
    tiny.insert(strong(2, 1), None, value(b"abc"));
    assert_eq!(tiny.len(), 1);
    assert!(tiny.get(&strong(2, 1), None).is_ok());
    assert_eq!(
        CacheConfig::default(),
        CacheConfig {
            max_entries: 1_000_000,
            max_bytes: 256 * 1024 * 1024
        }
    );
}

// --- Persisted records. -------------------------------------------------------

fn rich_record() -> CacheRecord {
    let mut v = CacheValue::from_flat(hash_bytes(b"abc", AlgorithmSet::ALL), 9, FileTime(77));
    v.image = Some(ImageTier {
        version: IMAGE_TIER_VERSION,
        digests: hash_bytes(b"img", AlgorithmSet::SHA256 | AlgorithmSet::SHA1).digests,
        conformant: false,
    });
    CacheRecord {
        key: weak("C:\\Program Files\\é.exe", 5),
        path: Some("C:\\Program Files\\é.exe".into()),
        value: v,
    }
}

#[test]
fn records_round_trip() {
    for record in [
        rich_record(),
        CacheRecord {
            key: strong(9, -1),
            path: None,
            value: value(b""),
        },
    ] {
        let bytes = record.encode(&key());
        assert_eq!(CacheRecord::decode(&bytes, &key()).unwrap(), record);
        let mut cache = HashCache::default();
        cache.import(&bytes, &key()).unwrap();
        assert_eq!(cache.export(), [record]);
    }
}

#[test]
fn every_tampered_byte_is_detected() {
    let bytes = rich_record().encode(&key());
    for i in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[i] ^= 0x01;
        assert_eq!(
            CacheRecord::decode(&bad, &key()),
            Err(RecordError::BadMac),
            "byte {i}"
        );
    }
    // Truncated, extended, empty, or made with another key.
    assert_eq!(
        CacheRecord::decode(&bytes[..bytes.len() - 1], &key()),
        Err(RecordError::BadMac)
    );
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        CacheRecord::decode(&longer, &key()),
        Err(RecordError::BadMac)
    );
    assert_eq!(CacheRecord::decode(&[], &key()), Err(RecordError::BadMac));
    let other = MacKey::new(&[8; MIN_KEY_LEN]).unwrap();
    assert_eq!(
        CacheRecord::decode(&bytes, &other),
        Err(RecordError::BadMac)
    );

    // A tampered record is a miss plus a tamper event.
    let mut cache = HashCache::default();
    let mut bad = bytes.clone();
    bad[10] ^= 1;
    assert_eq!(cache.import(&bad, &key()), Err(RecordError::BadMac));
    assert!(cache.is_empty());
    assert_eq!(cache.metrics().snapshot().tamper_events, 1);
}

#[test]
fn an_authentic_but_undecodable_record_is_malformed() {
    // A body this version cannot decode, signed with the right key: the
    // MAC passes, decoding fails, and it is not a tamper event.
    let mut body = rich_record().encode(&key());
    body.truncate(body.len() - 32);
    body[4] = 99; // unknown format version
    // HMAC-SHA-256 under the same key bytes, computed independently.
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[7; MIN_KEY_LEN]),
        &body,
    );
    let mut bytes = body;
    bytes.extend_from_slice(tag.as_ref());
    assert_eq!(
        CacheRecord::decode(&bytes, &key()),
        Err(RecordError::Malformed)
    );
    let mut cache = HashCache::default();
    assert_eq!(cache.import(&bytes, &key()), Err(RecordError::Malformed));
    assert_eq!(cache.metrics().snapshot().tamper_events, 0);
}

#[test]
fn a_record_cannot_be_moved_to_another_file() {
    // The key is inside the MAC: a record is only ever cached under the
    // file it was made for, so it misses for any other file.
    let record = CacheRecord {
        key: strong(1, 10),
        path: None,
        value: value(b"good"),
    };
    let mut cache = HashCache::default();
    cache.import(&record.encode(&key()), &key()).unwrap();
    assert_eq!(cache.get(&strong(2, 10), None), Err(Miss::NotCached));
    // And an old record for the same file has an old USN, so it misses.
    assert_eq!(cache.get(&strong(1, 11), None), Err(Miss::Changed));
}

#[test]
fn short_mac_keys_are_rejected_and_never_printed() {
    assert!(MacKey::new(&[1; MIN_KEY_LEN - 1]).is_err());
    let k = MacKey::new(&[0x41; 40]).unwrap();
    assert_eq!(format!("{k:?}"), "MacKey(..)");
}

proptest! {
    /// Decoding arbitrary bytes never panics and never yields a record
    /// without the key.
    #[test]
    fn arbitrary_records_are_rejected(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        prop_assert!(CacheRecord::decode(&bytes, &key()).is_err());
    }
}

// --- Verify-on-launch. --------------------------------------------------------

#[test]
fn verify_modes() {
    let trusted = FileLocation {
        class: Some(LocationClass::OsVolume),
        user_writable: Some(false),
    };
    let s = strong(1, 1);
    let w = weak("C:\\a.exe", 1);
    assert_eq!(HashVerifyMode::default(), HashVerifyMode::Cached);
    assert!(!HashVerifyMode::Cached.must_recompute(&w, &FileLocation::default()));
    assert!(HashVerifyMode::Recompute.must_recompute(&s, &trusted));
    let m = HashVerifyMode::RecomputeUntrustedLocations;
    assert!(!m.must_recompute(&s, &trusted));
    assert!(
        m.must_recompute(&w, &trusted),
        "weak keys are never trusted"
    );
    for location in [
        FileLocation {
            user_writable: Some(true),
            ..trusted
        },
        FileLocation {
            user_writable: None,
            ..trusted
        },
        FileLocation {
            class: None,
            ..trusted
        },
        FileLocation {
            class: Some(LocationClass::Removable),
            ..trusted
        },
        FileLocation {
            class: Some(LocationClass::Network),
            ..trusted
        },
        FileLocation {
            class: Some(LocationClass::Unknown),
            ..trusted
        },
    ] {
        assert!(m.must_recompute(&s, &location), "{location:?}");
    }
    assert!(!m.must_recompute(
        &s,
        &FileLocation {
            class: Some(LocationClass::OtherFixed),
            ..trusted
        }
    ));
}

/// A stamp source that returns scripted keys, one per call, then repeats
/// the last.
struct Script(RefCell<VecDeque<FileKey>>, RefCell<FileKey>);

impl Script {
    fn new(keys: &[FileKey]) -> Self {
        Self(
            RefCell::new(keys.iter().cloned().collect()),
            RefCell::new(keys.last().unwrap().clone()),
        )
    }
}

impl FileStamp for Script {
    type File = ();
    type Error = String;
    fn open(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn rewind(&self, _: &()) -> Result<(), String> {
        Ok(())
    }
    fn stamp(&self, _: &()) -> Result<FileKey, String> {
        let next = self.0.borrow_mut().pop_front();
        if let Some(k) = next {
            *self.1.borrow_mut() = k.clone();
            return Ok(k);
        }
        Ok(self.1.borrow().clone())
    }
}

fn done(t: Through) -> (CacheValue, ValueSource, bool) {
    match t {
        Through::Done {
            value,
            source,
            cache_disagreed,
        } => (value, source, cache_disagreed),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_warm_cache_reads_nothing() {
    let cache = Mutex::new(HashCache::default());
    let stamps = Script::new(&[strong(1, 1)]);
    let reads = Cell::new(0);
    let compute = |_: &()| {
        reads.set(reads.get() + 1);
        Ok::<_, String>(value(b"abc"))
    };
    let loc = FileLocation::default();
    let (v, src, _) = done(
        hash_through(
            &cache,
            &stamps,
            "C:\\a.exe",
            HashVerifyMode::Cached,
            &loc,
            compute,
        )
        .unwrap(),
    );
    assert_eq!((src, reads.get()), (ValueSource::Computed, 1));
    for _ in 0..5 {
        let (again, src, _) = done(
            hash_through(
                &cache,
                &stamps,
                "C:\\a.exe",
                HashVerifyMode::Cached,
                &loc,
                compute,
            )
            .unwrap(),
        );
        assert_eq!((src, &again), (ValueSource::Cache, &v));
    }
    assert_eq!(reads.get(), 1, "an unchanged file is never read again");
    let m = cache.lock().unwrap().metrics().snapshot();
    assert_eq!((m.hits, m.misses, m.hashes, m.bytes_hashed), (5, 1, 1, 3));
    assert_eq!(m.hit_ratio(), Some(5.0 / 6.0));
    assert!(m.average_latency().is_some());
}

#[test]
fn recompute_mode_rehashes_and_reports_disagreement() {
    let cache = Mutex::new(HashCache::default());
    let k = weak("C:\\a.exe", 1);
    // A cached value the file no longer matches, though the key does (a
    // restored timestamp).
    cache.lock().unwrap().insert(k.clone(), None, value(b"old"));
    let stamps = Script::new(&[k]);
    let (v, src, disagreed) = done(
        hash_through(
            &cache,
            &stamps,
            "C:\\a.exe",
            HashVerifyMode::Recompute,
            &FileLocation::default(),
            |_: &()| Ok::<_, String>(value(b"new")),
        )
        .unwrap(),
    );
    assert_eq!((src, disagreed), (ValueSource::Computed, true));
    assert_eq!(v, value(b"new"));
    // The fresh value replaced it.
    let k = weak("C:\\a.exe", 1);
    assert_eq!(cache.lock().unwrap().get(&k, None).unwrap(), &value(b"new"));
    // Recompute never counts a lookup: no hit, though an entry exists.
    assert_eq!(cache.lock().unwrap().metrics().snapshot().hits, 1);
    // Agreement is not reported.
    let (_, _, disagreed) = done(
        hash_through(
            &cache,
            &stamps,
            "C:\\a.exe",
            HashVerifyMode::Recompute,
            &FileLocation::default(),
            |_: &()| Ok::<_, String>(value(b"new")),
        )
        .unwrap(),
    );
    assert!(!disagreed);
}

#[test]
fn a_file_changing_while_hashed_is_retried_then_unstable() {
    // The stamp moves on every read: never stable.
    let keys: Vec<FileKey> = (0..20).map(|i| strong(1, i)).collect();
    let cache = Mutex::new(HashCache::default());
    let stamps = Script::new(&keys);
    let attempts = Cell::new(0);
    let t = hash_through(
        &cache,
        &stamps,
        "C:\\a.exe",
        HashVerifyMode::Cached,
        &FileLocation::default(),
        |_: &()| {
            attempts.set(attempts.get() + 1);
            Ok::<_, String>(value(b"abc"))
        },
    )
    .unwrap();
    assert_eq!(t, Through::Unstable { attempts: 4 });
    assert_eq!(attempts.get(), 4);
    assert!(cache.lock().unwrap().is_empty(), "nothing is cached");
    // An entry cached earlier for the file is dropped too.
    let cache = Mutex::new(HashCache::default());
    cache
        .lock()
        .unwrap()
        .insert(strong(1, 0), None, value(b"abc"));
    let stamps = Script::new(&keys);
    let t = hash_through(
        &cache,
        &stamps,
        "C:\\a.exe",
        HashVerifyMode::Recompute,
        &FileLocation::default(),
        |_: &()| Ok::<_, String>(value(b"abc")),
    )
    .unwrap();
    assert!(matches!(t, Through::Unstable { .. }));
    assert!(cache.lock().unwrap().is_empty());
    assert_eq!(cache.lock().unwrap().metrics().snapshot().unstable, 1);

    // It settles on the second attempt: cached under the settled key.
    let cache = Mutex::new(HashCache::default());
    let stamps = Script::new(&[strong(1, 1), strong(1, 2), strong(1, 2)]);
    let (_, src, _) = done(
        hash_through(
            &cache,
            &stamps,
            "p",
            HashVerifyMode::Cached,
            &FileLocation::default(),
            |_: &()| Ok::<_, String>(value(b"abc")),
        )
        .unwrap(),
    );
    assert_eq!(src, ValueSource::Computed);
    assert!(cache.lock().unwrap().get(&strong(1, 2), None).is_ok());
}

#[test]
fn a_file_that_settles_on_a_new_key_is_not_a_disagreement() {
    // Recompute mode, with a cached entry for the first key. The file
    // changes during the first attempt and settles under a new key: the
    // fresh digest differs from the old entry, but that is a change, not a
    // disagreement about the same key.
    let cache = Mutex::new(HashCache::default());
    cache
        .lock()
        .unwrap()
        .insert(strong(1, 1), None, value(b"old"));
    let stamps = Script::new(&[strong(1, 1), strong(1, 2), strong(1, 2)]);
    let (_, src, disagreed) = done(
        hash_through(
            &cache,
            &stamps,
            "p",
            HashVerifyMode::Recompute,
            &FileLocation::default(),
            |_: &()| Ok::<_, String>(value(b"new")),
        )
        .unwrap(),
    );
    assert_eq!((src, disagreed), (ValueSource::Computed, false));
    let guard = cache.lock().unwrap();
    assert!(guard.peek(&strong(1, 1)).is_none());
    assert_eq!(guard.peek(&strong(1, 2)), Some(&value(b"new")));
}

#[test]
fn a_fresh_value_without_sha256_is_not_a_disagreement() {
    let cache = Mutex::new(HashCache::default());
    cache
        .lock()
        .unwrap()
        .insert(strong(1, 1), None, value(b"abc"));
    let md5_only = CacheValue::from_flat(hash_bytes(b"abc", AlgorithmSet::MD5), 1, FileTime(1));
    let (_, _, disagreed) = done(
        hash_through(
            &cache,
            &Script::new(&[strong(1, 1)]),
            "p",
            HashVerifyMode::Recompute,
            &FileLocation::default(),
            |_: &()| Ok::<_, String>(md5_only.clone()),
        )
        .unwrap(),
    );
    assert!(!disagreed);
}

#[test]
fn a_value_for_another_size_is_never_cached() {
    // The key says 3 bytes; the digest covers 4. Whatever was read is not
    // the file the key describes, so nothing is cached and the old entry is
    // dropped.
    let cache = Mutex::new(HashCache::default());
    cache
        .lock()
        .unwrap()
        .insert(strong(1, 1), None, value(b"abc"));
    let t = hash_through(
        &cache,
        &Script::new(&[strong(1, 1)]),
        "p",
        HashVerifyMode::Recompute,
        &FileLocation::default(),
        |_: &()| Ok::<_, String>(value(b"abcd")),
    )
    .unwrap();
    assert_eq!(t, Through::Unstable { attempts: 1 });
    assert!(cache.lock().unwrap().is_empty());
}

#[test]
fn the_same_handle_is_stamped_and_hashed() {
    // A stamp source whose handles are numbered: `hash_through` must open
    // once and use that one handle throughout.
    struct Handles(Cell<u32>, RefCell<Vec<u32>>);
    impl FileStamp for Handles {
        type File = u32;
        type Error = String;
        fn open(&self, _: &str) -> Result<u32, String> {
            self.0.set(self.0.get() + 1);
            Ok(self.0.get())
        }
        fn rewind(&self, _: &u32) -> Result<(), String> {
            Ok(())
        }
        fn stamp(&self, file: &u32) -> Result<FileKey, String> {
            self.1.borrow_mut().push(*file);
            Ok(strong(1, 1))
        }
    }
    let stamps = Handles(Cell::new(0), RefCell::new(Vec::new()));
    let hashed = RefCell::new(Vec::new());
    let cache = Mutex::new(HashCache::default());
    hash_through(
        &cache,
        &stamps,
        "p",
        HashVerifyMode::Cached,
        &FileLocation::default(),
        |f: &u32| {
            hashed.borrow_mut().push(*f);
            Ok::<_, String>(value(b"abc"))
        },
    )
    .unwrap();
    assert_eq!(stamps.0.get(), 1, "opened once");
    assert_eq!(*stamps.1.borrow(), [1, 1]);
    assert_eq!(*hashed.borrow(), [1]);
}

#[test]
fn errors_are_passed_through() {
    struct Failing;
    impl FileStamp for Failing {
        type File = ();
        type Error = &'static str;
        fn open(&self, _: &str) -> Result<(), &'static str> {
            Err("no such file")
        }
        fn rewind(&self, _: &()) -> Result<(), &'static str> {
            Ok(())
        }
        fn stamp(&self, _: &()) -> Result<FileKey, &'static str> {
            Err("no such file")
        }
    }
    let cache = Mutex::new(HashCache::default());
    let r = hash_through(
        &cache,
        &Failing,
        "p",
        HashVerifyMode::Cached,
        &FileLocation::default(),
        |_: &()| Ok::<_, String>(value(b"")),
    );
    assert!(r.unwrap_err().to_string().contains("no such file"));
    let r = hash_through(
        &cache,
        &Script::new(&[strong(1, 1)]),
        "p",
        HashVerifyMode::Cached,
        &FileLocation::default(),
        |_: &()| Err::<CacheValue, _>("disk on fire"),
    );
    assert!(r.unwrap_err().to_string().contains("disk on fire"));
    assert!(cache.lock().unwrap().is_empty());
}

// --- Cloud placeholders. ------------------------------------------------------

#[test]
fn placeholders_are_skipped_only_by_inventory() {
    use palisade_fileid::hash::{
        FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    };
    const SPARSE: u32 = 0x200;
    for attr in [
        FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_RECALL_ON_OPEN,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | SPARSE,
    ] {
        assert_eq!(
            skip_for_inventory(attr, HashPurpose::Inventory),
            Some(DeferReason::CloudPlaceholder)
        );
        assert_eq!(skip_for_inventory(attr, HashPurpose::Execution), None);
    }
    assert_eq!(skip_for_inventory(SPARSE, HashPurpose::Inventory), None);
    assert_eq!(skip_for_inventory(0, HashPurpose::Inventory), None);
}

// --- The parallel-hash limit. -------------------------------------------------

#[test]
fn the_limiter_bounds_concurrent_hashes() {
    assert!(default_max_parallel_hashes() >= 1);
    assert_eq!(HashLimiter::new(0).max(), 1);
    let limiter = Arc::new(HashLimiter::new(2));
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (limiter, running, peak) = (limiter.clone(), running.clone(), peak.clone());
            std::thread::spawn(move || {
                let _permit = limiter.acquire();
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                running.fetch_sub(1, Ordering::SeqCst);
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(limiter.running(), 0);

    let a = limiter.try_acquire().unwrap();
    let _b = limiter.try_acquire().unwrap();
    assert!(limiter.try_acquire().is_none());
    drop(a);
    assert!(limiter.try_acquire().is_some());
}

#[test]
fn metrics_start_empty_and_saturate() {
    let cache = HashCache::default();
    let m = cache.metrics().snapshot();
    assert_eq!(m.hit_ratio(), None);
    assert_eq!(m.average_latency(), None);
    cache
        .metrics()
        .record_hash(u64::MAX, Duration::from_millis(2));
    cache.metrics().record_hash(10, Duration::from_millis(4));
    let m = cache.metrics().snapshot();
    assert_eq!(m.bytes_hashed, u64::MAX);
    assert_eq!(m.average_latency(), Some(Duration::from_millis(3)));
}

#[test]
fn values_carry_their_versions() {
    let v = value(b"abc");
    let FlatTier { version, hashes } = v.flat.clone().unwrap();
    assert_eq!(version, palisade_fileid::hash::cache::FLAT_TIER_VERSION);
    assert_eq!(
        hashes.get(HashAlgorithm::Sha256),
        hash_bytes(b"abc", AlgorithmSet::SHA256).get(HashAlgorithm::Sha256)
    );
    assert_eq!((v.classifier_version, v.computed_at), (1, FileTime(42)));
}

// --- With real files. -----------------------------------------------------------

/// Stamps a real file by its metadata, as a weak key: enough to test the
/// cache end to end on any OS. The Windows backend supplies strong keys.
struct Metadata;

impl FileStamp for Metadata {
    type File = (std::fs::File, String);
    type Error = std::io::Error;
    fn open(&self, path: &str) -> std::io::Result<Self::File> {
        Ok((std::fs::File::open(path)?, path.to_owned()))
    }
    fn rewind(&self, (file, _): &Self::File) -> std::io::Result<()> {
        std::io::Seek::seek(&mut &*file, std::io::SeekFrom::Start(0)).map(|_| ())
    }
    fn stamp(&self, (file, path): &Self::File) -> std::io::Result<FileKey> {
        let m = file.metadata()?;
        let nanos = |t: std::io::Result<std::time::SystemTime>| {
            t.ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos() as u64)
        };
        Ok(FileKey::Weak {
            path: path.clone(),
            size: m.len(),
            last_write: FileTime(nanos(m.modified())),
            creation: FileTime(0),
        })
    }
}

#[test]
fn appending_a_byte_misses_and_an_unchanged_file_is_not_read() {
    use palisade_fileid::hash::{HashOptions, HashStatus, hash_reader};
    let dir = std::env::temp_dir().join(format!("palisade-hash-cache-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tool.exe");
    std::fs::write(&path, vec![0x5a; 200_000]).unwrap();
    let path_str = path.to_str().unwrap().to_owned();

    let cache = Mutex::new(HashCache::default());
    let reads = Cell::new(0);
    let compute = |(file, _): &(std::fs::File, String)| {
        reads.set(reads.get() + 1);
        match hash_reader(file, &HashOptions::default()) {
            Ok(HashStatus::Complete(h)) => Ok(CacheValue::from_flat(h, 1, FileTime(0))),
            other => Err(format!("{other:?}")),
        }
    };
    let run = || {
        done(
            hash_through(
                &cache,
                &Metadata,
                &path_str,
                HashVerifyMode::Cached,
                &FileLocation::default(),
                compute,
            )
            .unwrap(),
        )
    };
    let (first, _, _) = run();
    for _ in 0..3 {
        assert_eq!(run().1, ValueSource::Cache);
    }
    assert_eq!(reads.get(), 1, "a warm cache reads no file content");

    // Append one byte: a miss, and the new digest.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut f, &[1]).unwrap();
    drop(f);
    let (second, src, _) = run();
    assert_eq!(src, ValueSource::Computed);
    assert_ne!(first, second);
    assert_eq!(second.flat.unwrap().hashes.size, 200_001);
    assert_eq!(reads.get(), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A real file that changes while the first attempt reads it, then
/// settles: the retry reads the whole file again through the same handle.
#[test]
fn a_retry_reads_the_whole_file_again() {
    use palisade_fileid::hash::{HashOptions, HashStatus, hash_reader};
    let dir = std::env::temp_dir().join(format!("palisade-hash-retry-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tool.exe");
    std::fs::write(&path, vec![0x11; 100_000]).unwrap();
    let path_str = path.to_str().unwrap().to_owned();
    let cache = Mutex::new(HashCache::default());
    let attempt = Cell::new(0);
    let t = hash_through(
        &cache,
        &Metadata,
        &path_str,
        HashVerifyMode::Cached,
        &FileLocation::default(),
        |(file, _): &(std::fs::File, String)| {
            attempt.set(attempt.get() + 1);
            let status = hash_reader(file, &HashOptions::default());
            if attempt.get() == 1 {
                // A writer replaces the content, with a new size, while
                // the first attempt is running.
                std::fs::write(&path, vec![0x22; 150_000]).unwrap();
            }
            match status {
                Ok(HashStatus::Complete(h)) => Ok(CacheValue::from_flat(h, 1, FileTime(0))),
                other => Err(format!("{other:?}")),
            }
        },
    )
    .unwrap();
    let (v, src, _) = done(t);
    assert_eq!(attempt.get(), 2);
    assert_eq!(src, ValueSource::Computed);
    let flat = v.flat.unwrap().hashes;
    assert_eq!(
        flat,
        hash_bytes(&vec![0x22; 150_000], AlgorithmSet::DEFAULT)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
