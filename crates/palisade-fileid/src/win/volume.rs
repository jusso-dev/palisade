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
//! [`FsType::Network`], whatever the server reports. No single query
//! decides that ([`network_evidence`]): the redirector query, the handle's
//! NT path (`\Device\Mup\…`) and the name the file was opened by each
//! count, and a handle without a local volume GUID root keeps only its
//! serial ([`VolumeInfo::settle`]), so a share is never reported as a local
//! NTFS volume. Anything that cannot be read stays `None`, and
//! [`VolumeInfo::location_class`] then never promotes the volume to a
//! trusted class.
//!
//! [`is_case_sensitive_dir`] reads the per-directory case-sensitivity flag,
//! and [`OsCaseSensitivity`] feeds it to
//! [`crate::fsctx::NormalizedPath::resolve_case_sensitivity`], so a
//! folded key is never produced for a name in a case-sensitive directory
//! (#332).

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;

use super::file::volume_root;
use super::sys;
use crate::fsctx::volume::{
    NetworkEvidence, combined_hotplug, nt_path_on_network, opened_name_on_network,
    parse_hotplug_info, parse_storage_device_descriptor,
};
use crate::fsctx::{DriveType, FsType, Root, VolumeInfo, normalize_win32};

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

/// `VOLUME_NAME_NT | FILE_NAME_OPENED`: the NT path of the handle as
/// opened (`\Device\Mup\server\share\…` through a redirector), with
/// no walk of parent folders that a share may refuse.
const OPENED_NAME_NT: u32 = 0x2 | 0x8;
/// `DRIVE_REMOTE`.
const DRIVE_REMOTE: u32 = 4;

/// The independent signs that `file` was reached through a network
/// redirector: the redirector query, the handle's NT path, and, if given,
/// the name it was `opened` by (a UNC path, or a drive letter the OS
/// reports as remote). See [`NetworkEvidence`].
#[must_use]
pub fn network_evidence(file: &File, opened: Option<&str>) -> NetworkEvidence {
    let remote_protocol = match sys::remote_protocol(file) {
        Ok(_) => Some(true),
        // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED and
        // ERROR_INVALID_PARAMETER: the file system has no remote protocol.
        Err(e) if matches!(e.raw_os_error(), Some(1 | 50 | 87)) => Some(false),
        Err(_) => None,
    };
    let nt_path = sys::final_path_by_handle(file, OPENED_NAME_NT)
        .ok()
        .and_then(|p| nt_path_on_network(&p));
    let opened_as_network =
        opened
            .and_then(|o| normalize_win32(o).ok())
            .and_then(|p| match p.root() {
                Root::Drive(letter) => sys::drive_type(&format!("{letter}:\\"))
                    .ok()
                    .map(|t| t == DRIVE_REMOTE),
                _ => opened_name_on_network(&p),
            });
    NetworkEvidence {
        remote_protocol,
        nt_path_on_network: nt_path,
        opened_as_network,
    }
}

/// What is known about the volume the open `file` is on. Never fails: a
/// value that cannot be read is `None`. Use [`read_volume_opened_as`] when
/// the name the file was opened by is known.
#[must_use]
pub fn read_volume(file: &File) -> VolumeInfo {
    read_volume_with(file, None)
}

/// As [`read_volume`], for a `file` opened by the name `opened`. A UNC
/// name, or a drive letter the OS reports as remote, makes the volume a
/// network volume even if the handle's own queries say otherwise.
#[must_use]
pub fn read_volume_opened_as(opened: &str, file: &File) -> VolumeInfo {
    read_volume_with(file, Some(opened))
}

fn read_volume_with(file: &File, opened: Option<&str>) -> VolumeInfo {
    let facts = sys::volume_information(file).ok();
    let serial = facts.as_ref().map(|f| f.serial);
    let evidence = network_evidence(file, opened);
    if evidence.is_network() {
        return VolumeInfo::network(serial);
    }
    let mut info = VolumeInfo {
        serial,
        fs_type: facts.as_ref().map(|f| FsType::from_name(&f.fs_name)),
        supports_usn: facts
            .as_ref()
            .map(|f| f.flags & FILE_SUPPORTS_USN_JOURNAL != 0),
        ..VolumeInfo::default()
    };
    // A handle with no local volume GUID root may be a share whose
    // redirector went unnoticed: `settle` then drops what the server said.
    let Ok(root) = volume_root(file) else {
        return VolumeInfo::settle(info, evidence, false);
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
        info.is_hotplug = combined_hotplug(storage, hotplug);
    }
    VolumeInfo::settle(info, evidence, true)
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

/// Per-directory case sensitivity from the file system, for
/// [`crate::fsctx::NormalizedPath::resolve_case_sensitivity`]. A directory
/// whose flag cannot be read is `None`, which the path treats as
/// case-sensitive.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsCaseSensitivity;

impl crate::fsctx::CaseSensitivityResolver for OsCaseSensitivity {
    fn is_case_sensitive(&self, dir: &crate::fsctx::NormalizedPath) -> Option<bool> {
        is_case_sensitive_dir(Path::new(&dir.to_win32_string())).ok()
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
    fn a_local_file_shows_no_sign_of_the_network() {
        let windir = sys::windows_directory().unwrap();
        let path = format!(r"{windir}\System32\cmd.exe");
        let f = File::open(&path).unwrap();
        let e = network_evidence(&f, Some(&path));
        // The remote-protocol query does not answer reliably either way on
        // every runner (#54: on Windows 11 Arm64 it fails on a local file
        // with an error outside the "not supported" set, so it is unknown).
        // It must never say "network" here; the other two signs decide.
        eprintln!(
            "remote_protocol on a local file: {:?}",
            sys::remote_protocol(&f)
        );
        assert_ne!(e.remote_protocol, Some(true), "{e:?}");
        assert_eq!(e.nt_path_on_network, Some(false), "{e:?}");
        assert_eq!(e.opened_as_network, Some(false), "{e:?}");
        assert_eq!(
            read_volume_opened_as(&path, &f).location_class(),
            LocationClass::OsVolume
        );
    }

    /// Every raw answer the OS gives for a file on a local SMB share, in
    /// the test output, so a runner on which a query misses the redirector
    /// (#54: the Windows 11 Arm64 image) shows which one and why. Needs
    /// administrator rights, which the CI runners have; it fails, not
    /// skips, without them.
    #[test]
    fn smb_share_queries_are_reported() {
        use std::fmt::Write as _;
        use std::process::Command;

        /// Runs `script`; each value it needs is passed in the environment
        /// (`$env:NAME`), never written into the script source.
        fn ps(script: &str, env: &[(&str, &str)]) -> String {
            let out = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .envs(env.iter().copied())
                .output()
                .unwrap();
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            )
        }

        let dir = std::env::temp_dir().join(format!("palisade-smbdiag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let plain = dir.to_str().unwrap().trim_start_matches(r"\\?\").to_owned();
        std::fs::write(dir.join("tool.exe"), b"MZ").unwrap();
        let share = format!("palisade-diag-{}", std::process::id());
        let vars = [
            ("PALISADE_SHARE", share.as_str()),
            ("PALISADE_PATH", plain.as_str()),
        ];
        let created = ps(
            "New-SmbShare -Name $env:PALISADE_SHARE -Path $env:PALISADE_PATH -ReadAccess 'Everyone' | Out-Null; 'ok'",
            &vars,
        );
        assert!(created.ends_with("ok"), "{created}");

        let host = std::env::var("COMPUTERNAME").unwrap_or_default();
        let mut report = String::new();
        let _ = writeln!(
            report,
            "OS: {}",
            ps(
                "$o = Get-CimInstance Win32_OperatingSystem; \"$($o.Caption) $($o.Version) $($o.OSArchitecture) type=$($o.ProductType)\"",
                &[]
            )
        );
        let mut networked = Vec::new();
        for server in ["localhost", "127.0.0.1", host.as_str()] {
            let unc = format!(r"\\{server}\{share}\tool.exe");
            let f = match File::open(&unc) {
                Ok(f) => f,
                Err(e) => {
                    let _ = writeln!(report, "{unc}: open failed: {e}");
                    networked.push(false);
                    continue;
                }
            };
            let _ = writeln!(report, "{unc}:");
            let _ = writeln!(report, "  remote_protocol: {:?}", sys::remote_protocol(&f));
            for (name, flags) in [
                ("DOS", 0x0),
                ("GUID", 0x1),
                ("NT", 0x2),
                ("NONE", 0x4),
                ("opened NT", 0xA),
            ] {
                let _ = writeln!(
                    report,
                    "  final path {name}: {:?}",
                    sys::final_path_by_handle(&f, flags)
                );
            }
            let _ = writeln!(report, "  volume info: {:?}", sys::volume_information(&f));
            let _ = writeln!(
                report,
                "  drive type of share root: {:?}",
                sys::drive_type(&format!(r"\\{server}\{share}\"))
            );
            let e = network_evidence(&f, None);
            let _ = writeln!(report, "  evidence (handle only): {e:?}");
            let _ = writeln!(report, "  read_volume: {:?}", read_volume(&f));
            networked.push(e.is_network());
        }
        let _ = writeln!(
            report,
            "SMB connections: {}",
            ps(
                "Get-SmbConnection | Format-Table -AutoSize ServerName,ShareName,Dialect | Out-String",
                &[]
            )
        );
        let _ = writeln!(
            report,
            "Services: {}",
            ps(
                "Get-Service LanmanWorkstation,LanmanServer,MRxSmb -ErrorAction SilentlyContinue | Format-Table -AutoSize Name,Status | Out-String",
                &[]
            )
        );
        let _ = writeln!(
            report,
            "Redirector drivers: {}",
            ps(
                "Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match '^(mrxsmb|mrxsmb20|rdbss|mup|bowser|srv2|srvnet)$' } | Format-Table -AutoSize Name,State | Out-String",
                &[]
            )
        );
        let _ = ps("Remove-SmbShare -Name $env:PALISADE_SHARE -Force", &vars);
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("{report}");
        // Through the handle alone, every name of the share must show some
        // sign of the network.
        assert!(networked.iter().all(|&n| n), "{report}");
    }

    #[test]
    fn os_root_is_a_volume_guid() {
        let root = os_volume_root().unwrap();
        assert!(root.starts_with(r"\\?\Volume{"), "{root}");
        assert!(!root.ends_with('\\'));
    }
}
