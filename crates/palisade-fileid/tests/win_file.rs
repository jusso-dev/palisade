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
    hash_streams, list_streams, open_for_hashing, peak_working_set_bytes,
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
    let h = complete(hash_open_file(
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
    assert_eq!(
        facts.fs_type,
        FsType::Ntfs,
        "the runner's temp folder is NTFS"
    );
    assert!(facts.supports_usn);
    assert_ne!(facts.file_id, [0; 16]);
    assert!(facts.creation.0 > 0 && facts.last_write.0 > 0 && facts.change.0 > 0);
    assert_eq!(
        u64::from(facts.volume_serial_32),
        facts.volume_serial & 0xFFFF_FFFF
    );
    // Whether the system volume keeps an active journal is a system
    // setting; when it does, the key is strong.
    let key = WinStamps.stamp(&file).unwrap();
    assert_eq!(key.size(), 3);
    match (&key, facts.usn) {
        (FileKey::Strong { usn, .. }, Some((_, u))) => assert_eq!(*usn, u),
        (FileKey::Weak { path: p, .. }, None) => assert!(p.ends_with(r"\A.BIN"), "{p}"),
        other => panic!("key and facts disagree: {other:?}"),
    }
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

    // A rename keeps the file ID, so the journal consumer can find the
    // entry and rekey it (#60).
    let before = WinStamps.stamp(&open_for_hashing(&path).unwrap()).unwrap();
    let renamed = dir.join("renamed.exe");
    std::fs::rename(&path, &renamed).unwrap();
    let after = WinStamps
        .stamp(&open_for_hashing(&renamed).unwrap())
        .unwrap();
    if let (
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
    {
        assert_eq!(file_id, id2, "a rename keeps the file ID");
        assert!(usn2 > usn, "a rename moves the USN");
        let mut guard = cache.lock().unwrap();
        assert_eq!(guard.key_of(*volume_serial, *file_id), Some(&before));
        assert!(guard.rekey_after_rename(after.clone(), Some(renamed.to_str().unwrap().into())));
        assert!(guard.get(&after, None).is_ok());
    }
}

/// A separate writer process appends to the file for as long as it runs
/// (#46 test plan: "a writer process modifies the file during hashing").
fn spawn_writer(path: &Path) -> std::process::Child {
    let script = format!(
        "$f = [IO.File]::Open('{}', 'Append', 'Write', 'ReadWrite, Delete'); \
         while ($true) {{ $f.WriteByte(120); $f.Flush(); Start-Sleep -Milliseconds 2 }}",
        path.display()
    );
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .spawn()
        .unwrap()
}

#[test]
fn a_concurrent_writer_makes_the_hash_unstable() {
    let dir = scratch("writer");
    let path = dir.join("busy.bin");
    std::fs::write(&path, vec![0_u8; 1 << 20]).unwrap();
    let mut writer = spawn_writer(&path);
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
    let _ = writer.kill();
    let _ = writer.wait();
    match t {
        Ok(Through::Unstable { .. }) => {}
        // The size can also change mid-read, which the hash reports as an
        // error; either way nothing is cached.
        Err(palisade_fileid::hash::ThroughError::Hash(
            palisade_fileid::hash::HashError::SizeChanged { .. },
        )) => {}
        other => panic!("expected an unstable result, got {other:?}"),
    }
    assert!(cache.lock().unwrap().is_empty());
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
    let hidden = hashes
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
    // A stream path is rejected; it names a stream, not a file.
    assert!(hash_streams(Path::new(&ads), &HashOptions::default()).is_err());
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
