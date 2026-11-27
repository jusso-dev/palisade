//! Volume classification of real files (#54): a VHD attached on the
//! runner, a local SMB share reached through its UNC path, the OS volume,
//! and a case-sensitive folder. Runs only on Windows with `os-trust`, so on
//! the Windows CI runners, which run tests elevated: attaching a VHD and
//! creating a share need administrator rights, and the tests fail rather
//! than skip without them.

#![cfg(all(windows, feature = "os-trust"))]
#![allow(clippy::unwrap_used)]

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use palisade_fileid::fsctx::{BusType, DriveType, FsType, LocationClass};
use palisade_fileid::win::volume::{
    is_case_sensitive_dir, network_evidence, read_volume, read_volume_opened_as,
};

/// A directory this test created, removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("palisade-vol-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    // The long final path: the runners' `%TEMP%` holds an 8.3 short name.
    Scratch(std::fs::canonicalize(&dir).unwrap())
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{cmd:?} failed: {text}");
    text
}

/// Runs a PowerShell `script`. Each value it needs is passed in the
/// environment and read as `$env:NAME`, never written into the script
/// source, so a path with a `'` (`C:\Users\O'Brien\...`) cannot break it.
fn powershell(script: &str, env: &[(&str, &str)]) -> String {
    run(Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(script)
        .envs(env.iter().copied()))
}

/// The wait around DiskPart scripts. The OS command reference ("diskpart
/// scripts and examples") says to "allow at least 15 seconds between each
/// script for a complete shutdown of the previous execution", or the next
/// script may fail.
///
/// nextest runs each test in its own process, so the in-process lock below
/// does not serialise the VHD tests there: `.config/nextest.toml` puts them
/// in the `diskpart` test group (one at a time), and each test also waits
/// this long before its first script, so a script from the test before it
/// has finished. The lock covers `cargo test`, which runs them as threads.
const DISKPART_GAP: Duration = Duration::from_secs(15);

static DISKPART: Mutex<()> = Mutex::new(());

/// Runs the DiskPart script `script` from the file `path`, holding the
/// process-wide lock and waiting [`DISKPART_GAP`] afterwards, whatever the
/// result. Returns whether it succeeded, and its output.
fn diskpart(path: &Path, script: &str) -> (bool, String) {
    // A test that panicked while holding the lock leaves nothing to undo.
    let _guard = DISKPART
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = std::fs::write(path, script)
        .map_err(|e| e.to_string())
        .and_then(|()| {
            Command::new("diskpart")
                .arg("/s")
                .arg(plain(path))
                .output()
                .map_err(|e| e.to_string())
        });
    std::thread::sleep(DISKPART_GAP);
    match result {
        Ok(out) => (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        ),
        Err(e) => (false, e),
    }
}

/// Set when a VHD could not be detached or deleted after its test. The
/// test that attaches the next VHD fails on it, since a disk left attached
/// can change what later tests see.
static CLEANUP_FAILED: AtomicBool = AtomicBool::new(false);

/// `\\?\C:\x` as `C:\x`, for tools that do not take the literal prefix.
fn plain(p: &Path) -> String {
    let s = p.to_str().unwrap();
    s.strip_prefix(r"\\?\").unwrap_or(s).to_owned()
}

fn open_dir(p: &Path) -> File {
    OpenOptions::new()
        .access_mode(0x80)
        .share_mode(0x7)
        .custom_flags(0x0200_0000)
        .open(p)
        .unwrap()
}

#[test]
fn the_temporary_folder_is_on_a_fixed_ntfs_volume() {
    let dir = scratch("tmp");
    let file = dir.0.join("f.txt");
    std::fs::write(&file, b"x").unwrap();
    let v = read_volume(&File::open(&file).unwrap());
    assert_eq!(v.fs_type, Some(FsType::Ntfs), "{v:?}");
    assert_eq!(v.drive_type, Some(DriveType::Fixed), "{v:?}");
    assert!(v.bus_type.is_some(), "{v:?}");
    assert!(v.is_hotplug.is_some(), "{v:?}");
    assert!(v.is_os_volume.is_some(), "{v:?}");
    assert!(
        matches!(
            v.location_class(),
            LocationClass::OsVolume | LocationClass::OtherFixed
        ),
        "{v:?}"
    );
}

/// A VHD attached with the OS disk tool and mounted in a folder, detached
/// and deleted when dropped.
struct Vhd {
    script_dir: Scratch,
    file: PathBuf,
    mount: PathBuf,
    /// [`Vhd::detach`] ran, so `Drop` has nothing left to do.
    detached: bool,
}

impl Vhd {
    fn diskpart(&self, name: &str, script: &str) -> String {
        let (ok, text) = diskpart(&self.script_dir.0.join(name), script);
        assert!(ok, "diskpart {name} failed: {text}");
        text
    }

    fn attach(dir: &Scratch, fs: &str) -> Self {
        assert!(
            !CLEANUP_FAILED.load(Ordering::SeqCst),
            "an earlier VHD was not detached; see its test's output"
        );
        let file = dir.0.join("disk.vhdx");
        let mount = dir.0.join("mnt");
        std::fs::create_dir(&mount).unwrap();
        let vhd = Self {
            script_dir: scratch(&format!("dp-{fs}")),
            file,
            mount,
            detached: false,
        };
        // A script from another test process may have just ended.
        std::thread::sleep(DISKPART_GAP);
        let f = plain(&vhd.file);
        let m = plain(&vhd.mount);
        vhd.diskpart(
            "attach.txt",
            &format!(
                "create vdisk file=\"{f}\" maximum=64 type=expandable\r\n\
                 select vdisk file=\"{f}\"\r\n\
                 attach vdisk\r\n\
                 convert mbr\r\n\
                 create partition primary\r\n\
                 format fs={fs} quick label=PALTEST\r\n\
                 assign mount=\"{m}\"\r\n"
            ),
        );
        vhd
    }
}

impl Vhd {
    /// Detaches and deletes the VHD: `Ok` only if both worked.
    fn try_detach(&mut self) -> Result<(), String> {
        self.detached = true;
        let f = plain(&self.file);
        let (ok, text) = diskpart(
            &self.script_dir.0.join("detach.txt"),
            &format!("select vdisk file=\"{f}\"\r\ndetach vdisk\r\n"),
        );
        if !ok {
            return Err(format!("detaching {f} failed: {text}"));
        }
        std::fs::remove_file(&self.file).map_err(|e| format!("deleting {f} failed: {e}"))
    }

    /// Detaches and deletes the VHD at the end of a test, failing the test
    /// if either step fails.
    fn detach(mut self) {
        if let Err(e) = self.try_detach() {
            panic!("{e}");
        }
    }
}

impl Drop for Vhd {
    /// A fallback for a test that panicked before [`Vhd::detach`]. A panic
    /// here would abort the test binary, so a failure is printed and
    /// flagged instead (see `CLEANUP_FAILED`).
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        if let Err(e) = self.try_detach() {
            CLEANUP_FAILED.store(true, Ordering::SeqCst);
            eprintln!("{e}");
        }
    }
}

#[test]
fn an_attached_vhd_is_a_virtual_disk() {
    let dir = scratch("vhd");
    let vhd = Vhd::attach(&dir, "ntfs");
    let file = vhd.mount.join("payload.exe");
    std::fs::write(&file, b"MZ").unwrap();
    let v = read_volume(&File::open(&file).unwrap());
    eprintln!("VHD volume: {v:?}, class {:?}", v.location_class());
    assert_eq!(v.fs_type, Some(FsType::Ntfs), "{v:?}");
    assert_eq!(v.bus_type, Some(BusType::FileBackedVirtual), "{v:?}");
    assert!(v.is_vhd());
    assert_eq!(v.is_os_volume, Some(false), "{v:?}");
    assert!(
        matches!(
            v.location_class(),
            LocationClass::VirtualDisk | LocationClass::Removable
        ),
        "{v:?}"
    );
    assert!(v.location_class().is_untrusted_location());
    assert!(!v.supports_owner(), "{v:?}");
    // The folder the VHD is mounted in is on the host volume, not the VHD.
    let host = read_volume(&open_dir(&dir.0));
    assert_ne!(host.serial, v.serial);
    assert_ne!(host.bus_type, Some(BusType::FileBackedVirtual));
    vhd.detach();
}

#[test]
fn a_fat_vhd_has_no_owners_or_journal() {
    let dir = scratch("fat");
    let vhd = Vhd::attach(&dir, "fat32");
    let file = vhd.mount.join("payload.exe");
    std::fs::write(&file, b"MZ").unwrap();
    let v = read_volume(&File::open(&file).unwrap());
    assert_eq!(v.fs_type, Some(FsType::Fat), "{v:?}");
    assert_eq!(v.supports_usn, Some(false), "{v:?}");
    assert!(!v.supports_owner());
    assert!(v.location_class().is_untrusted_location());
    vhd.detach();
}

/// An SMB share of a local folder, removed when dropped.
struct Share(String);

impl Drop for Share {
    fn drop(&mut self) {
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg("Remove-SmbShare -Name $env:PALISADE_SHARE -Force")
            .env("PALISADE_SHARE", &self.0)
            .output();
    }
}

#[test]
fn a_file_on_a_local_smb_share_is_on_the_network() {
    let dir = scratch("smb");
    std::fs::write(dir.0.join("tool.exe"), b"MZ").unwrap();
    let share = Share(format!("palisade-vol-{}", std::process::id()));
    powershell(
        "New-SmbShare -Name $env:PALISADE_SHARE -Path $env:PALISADE_PATH -ReadAccess 'Everyone' | Out-Null",
        &[
            ("PALISADE_SHARE", share.0.as_str()),
            ("PALISADE_PATH", plain(&dir.0).as_str()),
        ],
    );
    let unc = format!(r"\\localhost\{}\tool.exe", share.0);
    let file = File::open(&unc).unwrap();
    // The handle alone, and the handle with the name it was opened by.
    for v in [read_volume(&file), read_volume_opened_as(&unc, &file)] {
        let evidence = network_evidence(&file, None);
        assert_eq!(v.fs_type, Some(FsType::Network), "{v:?} {evidence:?}");
        assert_eq!(v.drive_type, Some(DriveType::Network), "{v:?} {evidence:?}");
        assert_eq!(v.location_class(), LocationClass::Network);
        assert!(!v.supports_owner());
    }
    // Whatever any one query says, a UNC name is never read as local.
    assert!(network_evidence(&file, Some(&unc)).is_network());
}

#[test]
fn case_sensitive_folders_are_reported() {
    let dir = scratch("case");
    let cs = dir.0.join("cs");
    std::fs::create_dir(&cs).unwrap();
    assert!(!is_case_sensitive_dir(&cs).unwrap());
    run(Command::new("fsutil")
        .args(["file", "setCaseSensitiveInfo"])
        .arg(plain(&cs))
        .arg("enable"));
    assert!(is_case_sensitive_dir(&cs).unwrap());
    // Two names that differ only in case are two files there.
    std::fs::write(cs.join("a.exe"), b"1").unwrap();
    std::fs::write(cs.join("A.EXE"), b"2").unwrap();
    assert_eq!(std::fs::read(cs.join("a.exe")).unwrap(), b"1");
    assert!(!is_case_sensitive_dir(&dir.0).unwrap());
    assert!(is_case_sensitive_dir(&dir.0.join("missing")).is_err());
}
