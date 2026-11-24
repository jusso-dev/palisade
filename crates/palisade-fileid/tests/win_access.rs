//! Owners, writability and the OS access-check cross-check (#54), on real
//! NTFS folders with deliberately weak ACLs. Runs only on Windows with
//! `os-trust`, so on the Windows CI runners.
//!
//! The fixture tree is the one #54's acceptance criteria describe: a
//! locked-down "Program Files"-style folder with a user-writable folder
//! inside it, a folder whose inherited allow is blocked by an explicit
//! deny, and a file whose DACL grants `WRITE_DAC` to `BUILTIN\Users`. Each
//! folder's result is compared with the OS's own access check.

#![cfg(all(windows, feature = "os-trust"))]
#![allow(clippy::unwrap_used)]

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use palisade_fileid::fsctx::FsType;
use palisade_fileid::fsctx::acl::{EvaluationOptions, ObjectKind, OwnerTrustClass, WriteRights};
use palisade_fileid::fsctx::sid::well_known as wk;
use palisade_fileid::fsctx::writable::{
    AssessOptions, EnumerateOptions, WritabilityCache, enumerate_user_writable_dirs,
};
use palisade_fileid::win::access::{
    OsDirectories, assess_file, cross_check_writability, open_for_security, read_owner,
};
use palisade_fileid::win::security::{NameCache, read_descriptor, set_security_sddl};

/// A directory this test created, removed when dropped. Its DACLs are reset
/// first, so a locked-down fixture can still be deleted.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::process::Command::new("icacls")
            .arg(&self.0)
            .args(["/reset", "/T", "/C", "/Q"])
            .status();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir =
        std::env::temp_dir().join(format!("palisade-win-access-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    Scratch(dir)
}

/// Opens `path` (file or folder) with `WRITE_OWNER` and `WRITE_DAC` to set
/// its owner and DACL.
fn open_for_dacl(path: &Path) -> File {
    OpenOptions::new()
        .access_mode(0x0008_0000 | 0x0004_0000 | 0x0002_0000) // WRITE_OWNER | WRITE_DAC | READ_CONTROL
        .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS
        .open(path)
        .unwrap()
}

/// SYSTEM and Administrators full control, inherited by children.
const ADMIN_ONLY: &str = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// Users read and execute, inherited.
const USERS_RX: &str = "(A;OICI;0x1200A9;;;BU)";
/// Users modify, inherited.
const USERS_MODIFY: &str = "(A;OICI;0x1301BF;;;BU)";

/// Builds the fixture tree under `root` and returns its paths:
/// `(pf, app, logs, denied, dac_file)`.
fn fixture(root: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let pf = root.join("PF");
    let app = pf.join("App");
    let logs = app.join("logs");
    let denied = app.join("denied");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::create_dir_all(&denied).unwrap();
    let dac_file = app.join("tool.exe");
    std::fs::write(&dac_file, b"MZ").unwrap();
    // Every fixture object is owned by BUILTIN\Administrators: an owner the
    // model counts as an administrator, so only the DACLs decide. The
    // scratch root itself is locked down too, so the walk up from the
    // fixture meets only folders the test controls until the temp folder.
    set_security_sddl(
        &open_for_dacl(root),
        &format!("O:BAD:P{ADMIN_ONLY}{USERS_RX}"),
    )
    .unwrap();
    set_security_sddl(
        &open_for_dacl(&pf),
        &format!("O:BAD:P{ADMIN_ONLY}{USERS_RX}"),
    )
    .unwrap();
    set_security_sddl(
        &open_for_dacl(&app),
        &format!("O:BAD:P{ADMIN_ONLY}{USERS_RX}"),
    )
    .unwrap();
    // A user-writable folder under the locked one.
    set_security_sddl(
        &open_for_dacl(&logs),
        &format!("O:BAD:P{ADMIN_ONLY}{USERS_MODIFY}"),
    )
    .unwrap();
    // A deny for Everyone before an allow of Users modify: not writable.
    set_security_sddl(
        &open_for_dacl(&denied),
        &format!("O:BAD:P(D;OICI;0x000D0156;;;WD){ADMIN_ONLY}{USERS_MODIFY}"),
    )
    .unwrap();
    // Users may change the file's permissions, and nothing else.
    set_security_sddl(
        &open_for_dacl(&dac_file),
        &format!("O:BAD:P{ADMIN_ONLY}(A;;0x1200A9;;;BU)(A;;WD;;;BU)"),
    )
    .unwrap();
    // A child created inside `denied` inherits its ACEs, so NTFS gives it a
    // DACL with an *inherited* deny (#54: "an inherited deny").
    let child = denied.join("child");
    std::fs::create_dir(&child).unwrap();
    // Owned by Administrators like the rest, without touching its
    // inherited DACL.
    assert!(
        std::process::Command::new("icacls")
            .arg(&child)
            .args(["/setowner", "*S-1-5-32-544", "/Q"])
            .status()
            .unwrap()
            .success()
    );
    (pf, app, logs, denied, dac_file)
}

fn descriptor(path: &Path) -> Vec<u8> {
    read_descriptor(&open_for_security(path).unwrap()).unwrap()
}

fn kind(path: &Path) -> ObjectKind {
    if path.is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    }
}

#[test]
fn fixture_matches_the_os_access_check() {
    let dir = scratch("fixture");
    let (pf, app, logs, denied, dac_file) = fixture(&dir.0);
    let opts = EvaluationOptions::default();
    for (path, writable) in [
        (&pf, false),
        (&app, false),
        (&logs, true),
        (&denied, false),
        (&denied.join("child"), false),
        (&dac_file, true),
    ] {
        let check = cross_check_writability(&descriptor(path), kind(path), &opts).unwrap();
        assert!(
            check.missed().is_empty(),
            "{}: the evaluator missed {:?} that the OS grants",
            path.display(),
            check.missed()
        );
        assert!(check.agrees(), "{}: {check:?}", path.display());
        assert_eq!(
            !check.os.is_empty(),
            writable,
            "{}: {check:?}",
            path.display()
        );
    }
    // WRITE_DAC alone on the file.
    let check = cross_check_writability(&descriptor(&dac_file), ObjectKind::File, &opts).unwrap();
    assert_eq!(check.os, WriteRights::WRITE_DAC);
}

#[test]
fn path_assessment_of_the_fixture() {
    let dir = scratch("assess");
    let (_pf, app, logs, denied, dac_file) = fixture(&dir.0);
    let opts = EvaluationOptions::default();
    let mut cache = WritabilityCache::default();

    // A file inside the user-writable folder: its parent is the first
    // user-writable ancestor.
    let inside = logs.join("app.log");
    std::fs::write(&inside, b"x").unwrap();
    let w = assess_file(&inside, &opts, AssessOptions::default(), &mut cache).unwrap();
    assert!(w.file_user_writable, "inherits Users modify");
    assert_eq!(
        w.first_user_writable_ancestor.as_deref(),
        Some(logs.to_str().unwrap())
    );
    assert!(w.path_user_writable());
    assert!(
        w.principals_with_write
            .contains(&palisade_fileid::fsctx::acl::Principal::Sid(wk::USERS))
    );

    // The WRITE_DAC grant is a change-permissions finding and an
    // owner-trust blocker.
    let w = assess_file(&dac_file, &opts, AssessOptions::default(), &mut cache).unwrap();
    assert!(w.file_user_writable);
    assert!(w.change_perms_by_non_admin);
    assert!(w.owner_trust_blockers.contains(WriteRights::WRITE_DAC));
    // Its folders up to the scratch root are locked; above that, the temp
    // folder is user-writable on any stock image.
    let first = w.first_user_writable_ancestor.clone().unwrap();
    assert!(
        !first.starts_with(app.to_str().unwrap()) && !first.starts_with(dir.0.to_str().unwrap()),
        "{first}"
    );

    // The denied folder is not writable itself, nor is its child, whose
    // deny is inherited (checked to be marked inherited on disk).
    let w = assess_file(&denied, &opts, AssessOptions::default(), &mut cache).unwrap();
    assert!(!w.file_user_writable, "{:?}", w.target);
    let child = denied.join("child");
    let sd = palisade_fileid::fsctx::SecurityDescriptor::from_self_relative(&descriptor(&child))
        .unwrap();
    assert!(
        sd.dacl
            .unwrap()
            .iter()
            .any(|a| a.is_inherited()
                && matches!(a.kind, palisade_fileid::fsctx::acl::AceKind::Deny)),
        "the child's deny must be inherited"
    );
    let w = assess_file(&child, &opts, AssessOptions::default(), &mut cache).unwrap();
    assert!(!w.file_user_writable, "{:?}", w.target);

    // Stopping early reads fewer ancestors and gives the same verdict.
    let early = assess_file(
        &inside,
        &opts,
        AssessOptions {
            stop_at_first_writable: true,
        },
        &mut cache,
    )
    .unwrap();
    assert_eq!(early.ancestors.len(), 1);
    assert!(early.path_user_writable());
    // Folders that share a descriptor were evaluated once.
    let (hits, _) = cache.stats();
    assert!(hits > 0);
}

#[test]
fn writable_dirs_under_the_fixture() {
    let dir = scratch("enum");
    let (pf, _app, logs, _denied, _file) = fixture(&dir.0);
    let opts = EvaluationOptions::default();
    let mut cache = WritabilityCache::default();
    let r = enumerate_user_writable_dirs(
        &[pf.to_str().unwrap().to_owned()],
        &mut OsDirectories,
        &opts,
        &EnumerateOptions::default(),
        &mut cache,
    )
    .unwrap();
    let paths: Vec<_> = r.dirs.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(paths, [logs.to_str().unwrap()]);
    assert!(!r.truncated);
    assert_eq!(r.visited, 5, "PF, App, denied, logs, denied\\child");
    assert!(r.incomplete.is_empty(), "{:?}", r.incomplete);

    // A junction to the writable folder is never followed.
    let junction = pf.join("link");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&logs)
        .status()
        .unwrap();
    assert!(status.success());
    let r = enumerate_user_writable_dirs(
        &[pf.to_str().unwrap().to_owned()],
        &mut OsDirectories,
        &opts,
        &EnumerateOptions::default(),
        &mut cache,
    )
    .unwrap();
    assert_eq!(r.dirs.len(), 1, "{r:?}");
    let _ = std::fs::remove_dir(&junction);
}

/// #54 acceptance: the folders the E8 guidance lists as default exceptions
/// are reported user-writable on a stock image when they are, and system
/// folders are not. The OS access check is the reference for each.
#[test]
fn stock_system_folders() {
    let windir = PathBuf::from(std::env::var_os("WINDIR").unwrap());
    let opts = EvaluationOptions::default();
    let candidates = [
        windir.join("Temp"),
        windir.join("Tasks"),
        windir.join(r"System32\spool\drivers\color"),
        windir.join(r"System32\Tasks"),
        windir.join("tracing"),
        windir.join(r"System32"),
        windir.join(r"System32\drivers"),
    ];
    let mut checked = 0;
    let mut writable = Vec::new();
    for path in candidates.iter().filter(|p| p.exists()) {
        // The CI runners run tests elevated, so every folder can be read.
        let bytes = read_descriptor(&open_for_security(path).unwrap()).unwrap();
        let check = cross_check_writability(&bytes, ObjectKind::Directory, &opts).unwrap();
        checked += 1;
        if !check.os.is_empty() {
            writable.push(path.clone());
            assert!(!check.portable.is_empty(), "{}: {check:?}", path.display());
        }
        assert!(
            check.missed().is_empty(),
            "{}: missed {:?} ({check:?})",
            path.display(),
            check.missed()
        );
    }
    assert!(checked >= 4, "only {checked} stock folders exist");
    // `%WINDIR%\Temp` lets standard users create files on a stock image,
    // and `System32\spool\drivers\color` does too: E8 lists both.
    assert!(
        writable
            .iter()
            .any(|p| p.ends_with("Temp") || p.ends_with("color")),
        "no E8 default exception was user-writable: {writable:?}"
    );
    // System32 itself is never user-writable on a stock image.
    let s32 = read_descriptor(&open_for_security(&windir.join("System32")).unwrap()).unwrap();
    let check = cross_check_writability(&s32, ObjectKind::Directory, &opts).unwrap();
    assert!(check.os.is_empty(), "{check:?}");
    assert!(check.portable.is_empty(), "{check:?}");
}

#[test]
fn owners() {
    let dir = scratch("owner");
    let path = dir.0.join("mine.txt");
    std::fs::write(&path, b"x").unwrap();
    let mut names = NameCache::default();
    let f = open_for_security(&path).unwrap();
    // On NTFS, a local disk: the creator (the test's user) owns it.
    let o = read_owner(&f, Some(&FsType::Ntfs), true, &mut names).unwrap();
    assert!(o.owner_supported);
    assert!(o.owner_sid.is_some());
    assert!(o.owner_name.is_some(), "{o:?}");
    // A system file is owned by an administrator-equivalent principal.
    let windir = PathBuf::from(std::env::var_os("WINDIR").unwrap());
    let cmd = open_for_security(&windir.join(r"System32\cmd.exe")).unwrap();
    let o = read_owner(&cmd, Some(&FsType::Ntfs), true, &mut names).unwrap();
    assert_eq!(
        o.owner_trust_class,
        OwnerTrustClass::AdminEquivalent,
        "{o:?}"
    );
    // Non-NTFS or non-local: owners are not reported.
    let o = read_owner(&f, Some(&FsType::Fat), true, &mut names).unwrap();
    assert!(!o.owner_supported && o.owner_sid.is_none());
    let o = read_owner(&f, Some(&FsType::Ntfs), false, &mut names).unwrap();
    assert!(!o.owner_supported);
}

/// A junction inside a locked folder that leads to a user-writable folder
/// must not hide it: the real folders the file lives in are assessed.
#[test]
fn links_cannot_hide_a_writable_folder() {
    let dir = scratch("links");
    let (pf, app, logs, _denied, _file) = fixture(&dir.0);
    let opts = EvaluationOptions::default();
    let mut cache = WritabilityCache::default();
    let payload = logs.join("payload.exe");
    std::fs::write(&payload, b"MZ").unwrap();
    // Lock the payload itself, so only its folder is writable.
    set_security_sddl(
        &open_for_dacl(&payload),
        &format!("O:BAD:P{ADMIN_ONLY}{USERS_RX}"),
    )
    .unwrap();

    // A junction under the locked `PF` that points at the writable `logs`.
    let junction = pf.join("Tools");
    assert!(
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&logs)
            .status()
            .unwrap()
            .success()
    );
    let through = junction.join("payload.exe");
    let w = assess_file(&through, &opts, AssessOptions::default(), &mut cache).unwrap();
    assert!(!w.file_user_writable);
    assert!(
        w.path_user_writable(),
        "the junction hid {}: {w:?}",
        logs.display()
    );
    assert_eq!(
        w.first_user_writable_ancestor
            .as_deref()
            .map(str::to_ascii_lowercase),
        Some(logs.to_str().unwrap().to_ascii_lowercase())
    );
    let _ = std::fs::remove_dir(&junction);

    // A device path is rejected.
    assert!(
        assess_file(
            Path::new(r"\\.\pipe\x"),
            &opts,
            AssessOptions::default(),
            &mut cache
        )
        .is_err()
    );
    let _ = app;
}
