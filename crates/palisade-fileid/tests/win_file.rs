//! The Windows file backend for hashing and the hash cache (#46), on real
//! NTFS files. Runs only on Windows with `os-trust`, so on the Windows CI
//! runners, whose temporary folder is on an NTFS volume with a change
//! journal.

#![cfg(all(windows, feature = "os-trust"))]
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use palisade_fileid::fsctx::FsType;
use palisade_fileid::hash::{
    AlgorithmSet, CacheValue, DeferReason, FileKey, FileLocation, FileStamp as _, FileTime,
    HashCache, HashOptions, HashPurpose, HashStatus, HashVerifyMode, Through, ValueSource,
    hash_bytes, hash_through,
};
use palisade_fileid::win::file::{
    FileFacts, MMAP_THRESHOLD, ReadStrategy, WinStamps, choose_strategy, hash_open_file,
    hash_open_file_for_cache, hash_streams, list_streams, open_for_hashing, open_for_inventory,
    peak_working_set_bytes,
};

/// A directory this test created, removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

/// Makes sure the volume of the temporary folder keeps an active change
/// journal, so tests can require strong keys. On CI (the `CI` variable is
/// set, as on the hosted runners) a missing journal is created with the OS
/// tool; elsewhere the machine is left alone and the test is told to skip
/// the strong-key checks by a `false` return.
fn ensure_journal() -> bool {
    use std::sync::OnceLock;
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        let probe =
            std::env::temp_dir().join(format!("palisade-journal-probe-{}", std::process::id()));
        std::fs::write(&probe, b"x").unwrap();
        let active = |p: &Path| {
            FileFacts::read(&open_for_hashing(p).unwrap())
                .unwrap()
                .usn
                .is_some()
        };
        let mut ok = active(&probe);
        if !ok && std::env::var_os("CI").is_some() {
            let drive: String = std::env::temp_dir()
                .to_str()
                .unwrap()
                .chars()
                .take(2)
                .collect();
            let status = std::process::Command::new("fsutil")
                .args(["usn", "createjournal", "m=33554432", "a=4194304", &drive])
                .status()
                .unwrap();
            eprintln!("fsutil usn createjournal {drive}: {status}");
            ok = active(&probe);
            assert!(ok, "no change journal on {drive} even after creating one");
        }
        let _ = std::fs::remove_file(&probe);
        if !ok {
            eprintln!("no active change journal here; strong-key checks skipped (not on CI)");
        }
        ok
    })
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("palisade-win-file-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    Scratch(dir)
}

fn complete(status: HashStatus) -> palisade_fileid::hash::FlatHashes {
    match status {
        HashStatus::Complete(h) => h,
        other => panic!("not complete: {other:?}"),
    }
}

/// The `compute` closure `hash_through` calls: the backend's own hash of
/// the handle it opened.
fn compute(file: &File) -> Result<CacheValue, palisade_fileid::hash::HashError> {
    let h = complete(hash_open_file_for_cache(
        file,
        &HashOptions::default(),
        HashPurpose::Execution,
        true,
    )?);
    Ok(CacheValue::from_flat(h, 1, FileTime(1)))
}

#[test]
fn facts_and_strong_keys_from_the_handle() {
    let dir = scratch("facts");
    let path = dir.join("a.bin");
    std::fs::write(&path, b"abc").unwrap();
    let file = open_for_hashing(&path).unwrap();
    let facts = FileFacts::read(&file).unwrap();
    assert_eq!(facts.size, 3);
    assert_eq!(facts.number_of_links, 1);
    assert!(!facts.directory);
    // The runners' temporary folder is on the system volume: local NTFS
    // with an active change journal, so the key must be strong.
    assert_eq!(facts.fs_type, Some(FsType::Ntfs));
    assert!(!facts.remote);
    assert!(!facts.is_placeholder());
    let (volume_serial, file_id) = facts.file_id.unwrap();
    assert_ne!(file_id, [0; 16]);
    assert!(facts.creation.0 > 0 && facts.last_write.0 > 0 && facts.change.0 > 0);
    assert_eq!(
        u64::from(facts.volume_serial_32.unwrap()),
        volume_serial & 0xFFFF_FFFF
    );
    if !ensure_journal() {
        return;
    }
    let facts = FileFacts::read(&file).unwrap();
    let (_, usn) = facts
        .usn
        .expect("an active change journal on the system volume");
    let key = WinStamps.stamp(&file).unwrap();
    assert_eq!(key.size(), 3);
    let FileKey::Strong { usn: key_usn, .. } = key else {
        panic!("expected a strong key, got {key:?}")
    };
    assert_eq!(key_usn, usn);
    // Without a journal the same file gets the weak key: its final path.
    let weak = WinStamps::key_from(
        &file,
        &FileFacts {
            usn: None,
            ..facts.clone()
        },
    )
    .unwrap();
    let FileKey::Weak { path: wp, size, .. } = &weak else {
        panic!("expected a weak key, got {weak:?}")
    };
    assert!(wp.ends_with(r"\A.BIN"), "{wp}");
    assert_eq!(*size, 3);
    // Two handles to the same file give the same key.
    let again = WinStamps.stamp(&open_for_hashing(&path).unwrap()).unwrap();
    assert_eq!(key, again);

    // A hard link is the same file: same ID, two links.
    let link = dir.join("link.bin");
    std::fs::hard_link(&path, &link).unwrap();
    let via_link = FileFacts::read(&open_for_hashing(&link).unwrap()).unwrap();
    assert_eq!(via_link.file_id, facts.file_id);
    assert_eq!(via_link.number_of_links, 2);

    // A directory is not a file to stamp.
    let d = OpenOptions::new()
        .read(true)
        .custom_flags_for_dir()
        .open(&*dir)
        .unwrap();
    assert!(WinStamps.stamp(&d).is_err());
    // A device is not a file on disk.
    let nul = OpenOptions::new().read(true).open(r"\\.\NUL").unwrap();
    assert!(FileFacts::read(&nul).is_err());
    assert!(matches!(
        hash_open_file(&nul, &HashOptions::default(), HashPurpose::Execution, true),
        Err(palisade_fileid::hash::HashError::NotAFile)
    ));
}

/// `OpenOptions` for a directory handle (`FILE_FLAG_BACKUP_SEMANTICS`).
trait DirFlags {
    fn custom_flags_for_dir(&mut self) -> &mut Self;
}

impl DirFlags for OpenOptions {
    fn custom_flags_for_dir(&mut self) -> &mut Self {
        use std::os::windows::fs::OpenOptionsExt as _;
        self.custom_flags(0x0200_0000)
    }
}

#[test]
fn writers_are_not_blocked_while_a_file_is_open_for_hashing() {
    let dir = scratch("share");
    let path = dir.join("a.bin");
    std::fs::write(&path, b"abc").unwrap();
    let held = open_for_hashing(&path).unwrap();
    // Write, rename and delete all succeed while the hashing handle is open.
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"d")
        .unwrap();
    let moved = dir.join("b.bin");
    std::fs::rename(&path, &moved).unwrap();
    std::fs::remove_file(&moved).unwrap();
    drop(held);
}

#[test]
fn cache_flow_on_ntfs() {
    if !ensure_journal() {
        return;
    }
    let dir = scratch("cache");
    let path = dir.join("tool.exe");
    std::fs::write(&path, b"original").unwrap();
    let p = path.to_str().unwrap();
    let cache = Mutex::new(HashCache::default());
    let loc = FileLocation::default();
    // Counts the content reads: a warm cache must make none (#46).
    let reads = std::cell::Cell::new(0_u32);
    let counted = |file: &File| {
        reads.set(reads.get() + 1);
        compute(file)
    };
    let run =
        || hash_through(&cache, &WinStamps, p, HashVerifyMode::Cached, &loc, counted).unwrap();

    let Through::Done { value, source, .. } = run() else {
        panic!("unstable")
    };
    assert_eq!(source, ValueSource::Computed);
    assert_eq!(
        value.flat.unwrap().hashes,
        hash_bytes(b"original", AlgorithmSet::DEFAULT)
    );
    // Unchanged: served from the cache.
    for _ in 0..3 {
        let Through::Done { source, .. } = run() else {
            panic!("unstable")
        };
        assert_eq!(source, ValueSource::Cache);
    }
    assert_eq!(reads.get(), 1, "an unchanged file is read once");

    // Appending a byte moves the USN, the size and the write time: a miss.
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"!")
        .unwrap();
    let Through::Done { value, source, .. } = run() else {
        panic!("unstable")
    };
    assert_eq!(source, ValueSource::Computed);
    assert_eq!(value.flat.unwrap().hashes.size, 9);

    // Touching only the write time changes the key too: a miss.
    let reads_before = reads.get();
    let f = OpenOptions::new().write(true).open(&path).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "sets a real file's write time on NTFS; no Clock is involved"
    )]
    let now = std::time::SystemTime::now();
    f.set_modified(now + Duration::from_secs(3600)).unwrap();
    drop(f);
    let Through::Done { source, .. } = run() else {
        panic!("unstable")
    };
    assert_eq!(source, ValueSource::Computed);
    assert_eq!(reads.get(), reads_before + 1);

    // A rename keeps the file ID, so the journal consumer can find the
    // entry and rekey it (#60).
    let before = WinStamps.stamp(&open_for_hashing(&path).unwrap()).unwrap();
    let renamed = dir.join("renamed.exe");
    std::fs::rename(&path, &renamed).unwrap();
    let after = WinStamps
        .stamp(&open_for_hashing(&renamed).unwrap())
        .unwrap();
    let (
        FileKey::Strong {
            volume_serial,
            file_id,
            usn,
            ..
        },
        FileKey::Strong {
            file_id: id2,
            usn: usn2,
            ..
        },
    ) = (&before, &after)
    else {
        panic!("expected strong keys: {before:?} {after:?}")
    };
    assert_eq!(file_id, id2, "a rename keeps the file ID");
    assert!(usn2 > usn, "a rename moves the USN");
    let mut guard = cache.lock().unwrap();
    assert_eq!(guard.key_of(*volume_serial, *file_id), Some(&before));
    assert!(guard.rekey_after_rename(after.clone(), Some(renamed.to_str().unwrap().into())));
    assert!(guard.get(&after, None).is_ok());
}

/// A separate writer process that appends to the file for as long as it
/// runs (#46 test plan: "a writer process modifies the file during
/// hashing"). It is this test binary, re-run as [`writer_child`]. It is
/// killed when dropped, even if the test panics.
struct Writer(std::process::Child);

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_writer(path: &Path) -> Writer {
    Writer(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "writer_child", "--nocapture"])
            .env("PALISADE_WRITER_TARGET", path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    )
}

/// The writer process: appends a byte every millisecond until killed.
/// Run only by [`spawn_writer`].
#[test]
#[ignore = "the writer process for a_concurrent_writer_makes_the_hash_unstable"]
fn writer_child() {
    let Some(target) = std::env::var_os("PALISADE_WRITER_TARGET") else {
        return;
    };
    let mut f = OpenOptions::new().append(true).open(target).unwrap();
    loop {
        f.write_all(b"x").unwrap();
        f.flush().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_concurrent_writer_makes_the_hash_unstable() {
    let dir = scratch("writer");
    let path = dir.join("busy.bin");
    std::fs::write(&path, vec![0_u8; 1 << 20]).unwrap();
    let writer = spawn_writer(&path);
    // Wait until the writer has started changing the file.
    let start = std::time::Instant::now();
    while std::fs::metadata(&path).unwrap().len() == 1 << 20 {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "writer never started"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let cache = Mutex::new(HashCache::default());
    let slow = |file: &File| {
        // Give the writer time to change the file during every attempt.
        std::thread::sleep(Duration::from_millis(100));
        compute(file)
    };
    let t = hash_through(
        &cache,
        &WinStamps,
        path.to_str().unwrap(),
        HashVerifyMode::Cached,
        &FileLocation::default(),
        slow,
    );
    drop(writer);
    // Every attempt saw the size change, so the result is unstable after
    // the retries, never an error and never a cached value.
    assert!(
        matches!(t, Ok(Through::Unstable { attempts: 4 })),
        "expected unstable after 4 attempts, got {t:?}"
    );
    assert!(cache.lock().unwrap().is_empty());
    assert_eq!(cache.lock().unwrap().metrics().snapshot().unstable, 1);
}

#[test]
fn placeholders_are_deferred_for_inventory() {
    let dir = scratch("offline");
    let path = dir.join("cloud.bin");
    std::fs::write(&path, b"data").unwrap();
    // Mark the file offline, as a cloud placeholder is, with the OS tool.
    let status = std::process::Command::new("attrib")
        .arg("+O")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success(), "attrib +O failed: {status}");
    let file = open_for_hashing(&path).unwrap();
    let facts = FileFacts::read(&file).unwrap();
    assert_ne!(
        facts.attributes & 0x1000,
        0,
        "FILE_ATTRIBUTE_OFFLINE is set"
    );
    let options = HashOptions::default();
    assert_eq!(
        hash_open_file(&file, &options, HashPurpose::Inventory, true).unwrap(),
        HashStatus::Deferred(DeferReason::CloudPlaceholder)
    );
    // Execution always hashes.
    let h = complete(hash_open_file(&file, &options, HashPurpose::Execution, true).unwrap());
    assert_eq!(h, hash_bytes(b"data", AlgorithmSet::DEFAULT));
}

#[test]
fn mapped_and_buffered_reads_agree_and_memory_stays_bounded() {
    assert_eq!(choose_strategy(MMAP_THRESHOLD, true), ReadStrategy::Mapped);
    assert_eq!(
        choose_strategy(MMAP_THRESHOLD - 1, true),
        ReadStrategy::Buffered
    );
    assert_eq!(choose_strategy(u64::MAX, false), ReadStrategy::Buffered);

    let dir = scratch("mmap");
    let path = dir.join("big.bin");
    // 1 GiB plus an odd tail, so the last window is partial.
    let size: u64 = (1 << 30) + 12_345;
    {
        let mut f = File::create(&path).unwrap();
        let chunk: Vec<u8> = (0..(1 << 20)).map(|i: u32| (i % 251) as u8).collect();
        let mut left = size;
        while left > 0 {
            let n = left.min(chunk.len() as u64) as usize;
            f.write_all(&chunk[..n]).unwrap();
            left -= n as u64;
        }
    }
    let file = open_for_hashing(&path).unwrap();
    let options = HashOptions {
        algorithms: AlgorithmSet::SHA256,
        ..HashOptions::default()
    };
    let before = peak_working_set_bytes().unwrap();
    let mapped = complete(hash_open_file(&file, &options, HashPurpose::Execution, true).unwrap());
    let peak = peak_working_set_bytes().unwrap();
    let buffered =
        complete(hash_open_file(&file, &options, HashPurpose::Execution, false).unwrap());
    assert_eq!(mapped.size, size);
    assert_eq!(mapped, buffered);
    // #46: hashing a 1 GB file uses under 16 MB more memory.
    let grew = peak.saturating_sub(before);
    assert!(grew < 16 << 20, "peak working set grew by {grew} bytes");
}

#[test]
fn small_and_empty_files() {
    let dir = scratch("small");
    for content in [&b""[..], b"x", &[7_u8; 70_000]] {
        let path = dir.join("f.bin");
        std::fs::write(&path, content).unwrap();
        let file = open_for_hashing(&path).unwrap();
        let h = complete(
            hash_open_file(&file, &HashOptions::default(), HashPurpose::Execution, true).unwrap(),
        );
        assert_eq!(h, hash_bytes(content, AlgorithmSet::DEFAULT));
        assert_eq!(h.empty, content.is_empty());
    }
    let path = dir.join("big.bin");
    std::fs::write(&path, [0_u8; 100]).unwrap();
    let options = HashOptions {
        max_hash_size: 99,
        ..HashOptions::default()
    };
    let file = open_for_hashing(&path).unwrap();
    assert_eq!(
        hash_open_file(&file, &options, HashPurpose::Execution, true).unwrap(),
        HashStatus::TooLarge { limit: 99 }
    );
}

#[test]
fn alternate_data_streams_are_hashed_on_their_own() {
    let dir = scratch("ads");
    let path = dir.join("host.txt");
    std::fs::write(&path, b"visible").unwrap();
    let ads = format!("{}:hidden.exe", path.display());
    std::fs::write(&ads, b"MZ hidden payload").unwrap();
    std::fs::write(
        format!("{}:Zone.Identifier", path.display()),
        b"[ZoneTransfer]\r\nZoneId=3\r\n",
    )
    .unwrap();

    let list = list_streams(&open_for_hashing(&path).unwrap()).unwrap();
    let mut names: Vec<_> = list.alternate().map(|s| s.name.clone()).collect();
    names.sort();
    assert_eq!(names, ["Zone.Identifier", "hidden.exe"]);
    assert!(list.streams.iter().any(|s| s.is_default() && s.size == 7));

    let hashes = hash_streams(&path, &HashOptions::default()).unwrap();
    assert!(!hashes.truncated);
    assert_eq!(hashes.streams.len(), 2);
    let hidden = hashes
        .streams
        .iter()
        .find(|h| h.stream.name == "hidden.exe")
        .unwrap();
    assert_eq!(hidden.identity, ads);
    assert_eq!(
        hidden.status,
        HashStatus::Complete(hash_bytes(b"MZ hidden payload", AlgorithmSet::DEFAULT))
    );
    // The default stream's hash is unchanged by the streams.
    let main = complete(
        hash_open_file(
            &open_for_hashing(&path).unwrap(),
            &HashOptions::default(),
            HashPurpose::Execution,
            true,
        )
        .unwrap(),
    );
    assert_eq!(main, hash_bytes(b"visible", AlgorithmSet::DEFAULT));
    // Paths that would mis-name the streams are rejected, never silently
    // skipped: a stream path, a trailing separator, a trailing dot or space.
    let base = path.display().to_string();
    for bad in [
        ads.clone(),
        format!("{ads}\\"),
        format!("{base}."),
        format!("{base} "),
        format!("{base}\\"),
        r"relative\host.txt".to_owned(),
    ] {
        assert!(
            hash_streams(Path::new(&bad), &HashOptions::default()).is_err(),
            "{bad}"
        );
    }
    // The literal `\\?\` form of the same path is accepted.
    let literal =
        hash_streams(Path::new(&format!(r"\\?\{base}")), &HashOptions::default()).unwrap();
    assert_eq!(literal.streams.len(), 2);
    // Invalid options are rejected up front, even for a file without streams.
    let plain = dir.join("plain.txt");
    std::fs::write(&plain, b"x").unwrap();
    let bad_options = HashOptions {
        algorithms: AlgorithmSet::EMPTY,
        ..HashOptions::default()
    };
    assert!(hash_streams(&plain, &bad_options).is_err());
    assert!(
        hash_streams(&plain, &HashOptions::default())
            .unwrap()
            .streams
            .is_empty()
    );
}

#[test]
fn a_file_with_more_streams_than_the_cap_reports_truncation() {
    let dir = scratch("many");
    let path = dir.join("host.txt");
    std::fs::write(&path, b"x").unwrap();
    for i in 0..=palisade_fileid::fsctx::ntfs::MAX_STREAMS {
        std::fs::write(format!("{}:s{i}", path.display()), b"y").unwrap();
    }
    let hashes = hash_streams(&path, &HashOptions::default()).unwrap();
    assert!(hashes.truncated, "the cap must be reported");
    assert!(hashes.streams.len() < palisade_fileid::fsctx::ntfs::MAX_STREAMS);
}

#[test]
fn inventory_opens_do_not_recall() {
    let dir = scratch("norecall");
    let path = dir.join("a.bin");
    std::fs::write(&path, b"abc").unwrap();
    let file = open_for_inventory(&path).unwrap();
    let h = complete(
        hash_open_file(&file, &HashOptions::default(), HashPurpose::Inventory, true).unwrap(),
    );
    assert_eq!(h, hash_bytes(b"abc", AlgorithmSet::DEFAULT));
}

/// The OS's own hash tool, for the reference digests #46 asks for.
fn certutil_hash(path: &Path, alg: &str) -> String {
    let out = std::process::Command::new("certutil")
        .arg("-hashfile")
        .arg(path)
        .arg(alg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "certutil failed on {}",
        path.display()
    );
    let text = String::from_utf8_lossy(&out.stdout);
    // The second line is the digest, in hex, possibly with spaces.
    let line = text.lines().nth(1).unwrap();
    line.chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase()
}

#[test]
fn digests_match_the_os_hash_tool() {
    let dir = scratch("certutil");
    let made = dir.join("made.bin");
    std::fs::write(
        &made,
        (0..300_000_u32)
            .map(|i| (i * 7 % 256) as u8)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let windir = std::env::var_os("WINDIR").unwrap();
    let system = Path::new(&windir).join("System32");
    let files = [
        made,
        system.join("cmd.exe"),
        system.join("kernel32.dll"),
        system.join("notepad.exe"),
    ];
    let options = HashOptions {
        algorithms: AlgorithmSet::ALL,
        ..HashOptions::default()
    };
    for path in files.iter().filter(|p| p.exists()) {
        let file = open_for_hashing(path).unwrap();
        let h = complete(hash_open_file(&file, &options, HashPurpose::Execution, true).unwrap());
        for (alg, name) in [
            (palisade_fileid::hash::HashAlgorithm::Sha256, "SHA256"),
            (palisade_fileid::hash::HashAlgorithm::Sha1, "SHA1"),
            (palisade_fileid::hash::HashAlgorithm::Md5, "MD5"),
            (palisade_fileid::hash::HashAlgorithm::Sha384, "SHA384"),
            (palisade_fileid::hash::HashAlgorithm::Sha512, "SHA512"),
        ] {
            assert_eq!(
                h.get(alg).unwrap().to_string(),
                certutil_hash(path, name),
                "{name} of {}",
                path.display()
            );
        }
    }
}

/// A named stream shares its host file's ID, USN and times, so it must
/// never share the host's cache key: a same-sized `host.exe:payload` must
/// not be answered with `host.exe`'s cached digest.
#[test]
fn a_named_stream_never_shares_its_host_files_key() {
    if !ensure_journal() {
        return;
    }
    let dir = scratch("adskey");
    let host = dir.join("host.exe");
    std::fs::write(&host, b"benign!!").unwrap();
    let ads = format!("{}:payload", host.display());
    std::fs::write(&ads, b"MALWARE!").unwrap();

    let host_key = WinStamps.stamp(&open_for_hashing(&host).unwrap()).unwrap();
    let ads_file = open_for_hashing(Path::new(&ads)).unwrap();
    let facts = FileFacts::read(&ads_file).unwrap();
    assert!(facts.named_stream);
    assert!(facts.usn.is_none());
    let ads_key = WinStamps.stamp(&ads_file).unwrap();
    assert!(matches!(host_key, FileKey::Strong { .. }));
    let FileKey::Weak { path, .. } = &ads_key else {
        panic!("a named stream must get a weak key: {ads_key:?}")
    };
    assert!(path.ends_with(":PAYLOAD"), "{path}");
    assert_ne!(host_key, ads_key);

    // Through the cache: the host is cached, then the stream is looked up.
    let cache = Mutex::new(HashCache::default());
    let loc = FileLocation::default();
    let run = |p: &str| {
        let Through::Done { value, source, .. } =
            hash_through(&cache, &WinStamps, p, HashVerifyMode::Cached, &loc, compute).unwrap()
        else {
            panic!("unstable")
        };
        (value.flat.unwrap().hashes, source)
    };
    let (h, _) = run(host.to_str().unwrap());
    assert_eq!(h, hash_bytes(b"benign!!", AlgorithmSet::DEFAULT));
    let (a, source) = run(&ads);
    assert_eq!(
        source,
        ValueSource::Computed,
        "never served from the host's entry"
    );
    assert_eq!(a, hash_bytes(b"MALWARE!", AlgorithmSet::DEFAULT));
    // And the host's entry is still there.
    let (_, source) = run(host.to_str().unwrap());
    assert_eq!(source, ValueSource::Cache);
}
