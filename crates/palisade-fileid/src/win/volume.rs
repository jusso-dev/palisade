//! Volume and drive classification of real files (#54).
//!
//! [`read_volume`] fills a [`VolumeInfo`] for the volume an **open handle**
//! is on, so the answer is about the file that was opened, not about
//! whatever a drive letter names now:
//!
//! - serial, file system and change-journal support from
//!   `GetVolumeInformationByHandleW`;
//! - the drive type from `GetDriveTypeW` on the volume's GUID root;
//! - the bus and removable-media flag from `IOCTL_STORAGE_QUERY_PROPERTY`,
//!   and the hot-plug state from `IOCTL_STORAGE_GET_HOTPLUG_INFO`, both on
//!   the volume device opened with no access rights;
//! - whether it is the OS volume, by comparing its GUID with the GUID of
//!   the volume that holds the Windows directory.
//!
//! A file opened through a network redirector is [`DriveType::Network`] and
//! [`FsType::Network`], whatever the server reports. Anything that cannot
//! be read stays `None`, and [`VolumeInfo::location_class`] then never
//! promotes the volume to a trusted class.
//!
//! [`is_case_sensitive_dir`] reads the per-directory case-sensitivity flag,
//! which the case-folded keys in [`crate::fsctx::path`] cannot see.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;

use super::file::volume_root;
use super::sys;
use crate::fsctx::volume::{parse_hotplug_info, parse_storage_device_descriptor};
use crate::fsctx::{DriveType, FsType, VolumeInfo};

/// `FILE_SUPPORTS_USN_JOURNAL`, in the volume flags.
const FILE_SUPPORTS_USN_JOURNAL: u32 = 0x0200_0000;
/// `FILE_FLAG_BACKUP_SEMANTICS`, needed to open a folder.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a link itself, not its target.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
/// `SECURITY_SQOS_PRESENT` with `SECURITY_ANONYMOUS`.
const SQOS_ANONYMOUS: u32 = 0x0010_0000;

/// Opens a volume device (`\\?\Volume{GUID}`, no trailing separator) with
/// no access rights, which is enough for the storage queries and needs no
/// privilege.
fn open_volume_device(root: &str) -> io::Result<File> {
    OpenOptions::new().access_mode(0).share_mode(0x7).open(root)
}

/// The GUID root (`\\?\Volume{GUID}`) of the volume holding the Windows
/// directory, read once per call.
fn os_volume_root() -> io::Result<String> {
    let windir = sys::windows_directory()?;
    let dir = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(0x7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | SQOS_ANONYMOUS)
        .open(windir)?;
    volume_root(&dir)
}

/// What is known about the volume the open `file` is on. Never fails: a
/// value that cannot be read is `None`.
#[must_use]
pub fn read_volume(file: &File) -> VolumeInfo {
    let mut info = VolumeInfo::default();
    let facts = sys::volume_information(file).ok();
    info.serial = facts.as_ref().map(|f| f.serial);
    if sys::is_remote(file) {
        info.fs_type = Some(FsType::Network);
        info.drive_type = Some(DriveType::Network);
        info.supports_usn = Some(false);
        return info;
    }
    info.fs_type = facts.as_ref().map(|f| FsType::from_name(&f.fs_name));
    info.supports_usn = facts
        .as_ref()
        .map(|f| f.flags & FILE_SUPPORTS_USN_JOURNAL != 0);
    let Ok(root) = volume_root(file) else {
        return info;
    };
    info.drive_type = sys::drive_type(&format!("{root}\\"))
        .ok()
        .map(DriveType::from_win32);
    info.is_os_volume = os_volume_root()
        .ok()
        .map(|os| os.eq_ignore_ascii_case(&root));
    if let Ok(device) = open_volume_device(&root) {
        let storage = sys::storage_device_bytes(&device)
            .ok()
            .and_then(|b| parse_storage_device_descriptor(&b));
        info.bus_type = storage.map(|s| s.bus_type);
        let hotplug = sys::hotplug_bytes(&device)
            .ok()
            .and_then(|b| parse_hotplug_info(&b));
        // Removable media counts as hot-pluggable: it can be swapped while
        // the system runs, whatever the device says.
        let removable = storage.is_some_and(|s| s.removable_media);
        info.is_hotplug = match hotplug {
            Some(h) => Some(h.is_hotplug() || removable),
            None if removable => Some(true),
            None => None,
        };
    }
    info
}

/// Whether the folder at `dir` is marked case-sensitive, so two names that
/// differ only in case are two entries in it. The folder is opened without
/// following a reparse point. `Ok(false)` on a file system or OS without
/// the flag.
pub fn is_case_sensitive_dir(dir: &Path) -> io::Result<bool> {
    let handle = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(0x7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | SQOS_ANONYMOUS)
        .open(dir)?;
    match sys::case_sensitive_dir(&handle) {
        Ok(flag) => Ok(flag),
        // ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED and
        // ERROR_INVALID_FUNCTION: the file system or OS has no such flag,
        // so every folder on it is case-insensitive.
        Err(e) if matches!(e.raw_os_error(), Some(1 | 50 | 87)) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsctx::LocationClass;

    #[test]
    fn the_windows_directory_is_on_the_os_volume() {
        let windir = sys::windows_directory().unwrap();
        let f = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(0x7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&windir)
            .unwrap();
        let v = read_volume(&f);
        assert_eq!(v.is_os_volume, Some(true), "{v:?}");
        assert_eq!(v.drive_type, Some(DriveType::Fixed), "{v:?}");
        assert_eq!(v.fs_type, Some(FsType::Ntfs), "{v:?}");
        assert_eq!(v.supports_usn, Some(true), "{v:?}");
        assert!(v.serial.is_some());
        // The hosted runners' OS disk is a fixed, non-pluggable virtual
        // or NVMe disk; whatever the bus, it must have been read.
        assert!(v.bus_type.is_some(), "{v:?}");
        assert_eq!(v.is_hotplug, Some(false), "{v:?}");
        assert_eq!(v.location_class(), LocationClass::OsVolume, "{v:?}");
    }

    #[test]
    fn os_root_is_a_volume_guid() {
        let root = os_volume_root().unwrap();
        assert!(root.starts_with(r"\\?\Volume{"), "{root}");
        assert!(!root.ends_with('\\'));
    }
}
