//! The change journal and master file table reads (#60), on the Windows CI
//! runners, whose temporary folder is on an NTFS volume with an active
//! journal and whose tests run with administrator rights.

#![cfg(all(windows, feature = "os-trust"))]
#![allow(clippy::unwrap_used)]

use std::fs::File;

use palisade_fileid::fsctx::ntfs::reason;
use palisade_fileid::win::journal::JournalVolume;
use palisade_fileid::win::links::read_meta;

#[test]
fn a_new_file_appears_in_the_journal_and_opens_by_id() {
    let dir = std::env::temp_dir().join(format!("palisade-journal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("journal-probe.bin");
    std::fs::write(&path, b"one").unwrap();
    let file = File::open(&path).unwrap();
    let volume = JournalVolume::of_file(&file).unwrap();
    let before = volume.query().unwrap();
    assert!(before.can_resume(before.journal_id, before.next_usn));

    // Change it, then read the journal from the cursor taken before.
    std::fs::write(&path, b"two, longer").unwrap();
    let id = read_meta(&file).unwrap().file_id.unwrap();
    let mut usn = before.next_usn;
    let mut seen = 0_u32;
    for _ in 0..64 {
        let (next, records) = volume.read(before.journal_id, usn).unwrap();
        seen |= records
            .iter()
            .filter(|r| r.file_reference == id)
            .fold(0, |acc, r| acc | r.reason);
        if next == usn {
            break;
        }
        usn = next;
    }
    assert_ne!(seen & reason::CONTENT, 0, "reasons {seen:#x}");

    // Opening by ID reaches the same file, and its content.
    let by_id = volume.open_file_by_id(id).unwrap();
    assert_eq!(read_meta(&by_id).unwrap().file_id, Some(id));
    let entry = volume.open_entry_by_id(id).unwrap();
    assert_eq!(read_meta(&entry).unwrap().file_id, Some(id));
    // An ID nothing has fails.
    assert!(volume.open_file_by_id([0xEE; 16]).is_err());

    // The first enumeration batch lists files of the volume.
    let (next, records) = volume.enumerate(0, before.next_usn).unwrap().unwrap();
    assert!(next > 0 && !records.is_empty());
    drop((file, by_id, entry));
    let _ = std::fs::remove_dir_all(dir);
}
