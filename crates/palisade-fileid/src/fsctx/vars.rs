//! Palisade path variables (`%WINDIR%`, `%PROGRAMFILES%` and so on).
//!
//! Rules can name well-known folders portably, and the policy compilers turn
//! the variables into the OS's own macros where it has them (#6). Here, a
//! normalised path is matched against the folders a variable stands for,
//! and [`path_variables_matched`] lists every variable whose folder contains
//! the path.
//!
//! The folder locations differ per machine and, for the profile folders, per
//! user. The OS backend reads them; the caller passes them in
//! [`KnownFolders`]. `%SYSTEM32%` covers both `System32` and `SysWOW64`, and
//! `%PROGRAMFILES%` both Program Files folders, so the caller lists both.
//!
//! A path that may still contain an 8.3 short name matches no variable: it
//! must be expanded first (see [`super::path`]). The same goes for each
//! folder in [`KnownFolders`].
//!
//! Folder matching compares names case-insensitively, as on an ordinary
//! NTFS directory. A directory can be made case-sensitive, and then
//! `C:\Parent\Temp` and `C:\Parent\temp` are different folders. Matching
//! goes through [`NormalizedPath::starts_with`], which compares a component
//! exactly when either path has read its directory's flag and found it
//! case-sensitive (or unreadable). Final paths from the Windows backend
//! carry the flags (#332); a path whose flags were never read
//! ([`NormalizedPath::case_sensitivity_checked`]) is still folded
//! throughout.

#![forbid(unsafe_code)]

use std::fmt;

use super::path::{NormalizedPath, PathError};
use super::volume::{LocationClass, VolumeInfo};

/// A Palisade path variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathVariable {
    /// `%OSDRIVE%`: the root of the OS volume.
    OsDrive,
    /// `%WINDIR%`.
    WinDir,
    /// `%SYSTEM32%`: `System32` and `SysWOW64`.
    System32,
    /// `%PROGRAMFILES%`: both Program Files folders.
    ProgramFiles,
    /// `%PROGRAMDATA%`.
    ProgramData,
    /// `%USERPROFILE%`.
    UserProfile,
    /// `%APPDATA%` (roaming application data).
    AppData,
    /// `%LOCALAPPDATA%`.
    LocalAppData,
    /// `%TEMP%`: the user's and the system's temporary folders.
    Temp,
    /// `%REMOVABLE%`: any path on removable media.
    Removable,
    /// `%HOT%`: any path on a hot-pluggable device.
    Hot,
    /// `%NETWORK%`: any path on a network share.
    Network,
}

impl PathVariable {
    /// Every variable, in the order [`path_variables_matched`] reports them.
    pub const ALL: [Self; 12] = [
        Self::OsDrive,
        Self::WinDir,
        Self::System32,
        Self::ProgramFiles,
        Self::ProgramData,
        Self::UserProfile,
        Self::AppData,
        Self::LocalAppData,
        Self::Temp,
        Self::Removable,
        Self::Hot,
        Self::Network,
    ];

    /// The variable as written in a rule, such as `%WINDIR%`.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::OsDrive => "%OSDRIVE%",
            Self::WinDir => "%WINDIR%",
            Self::System32 => "%SYSTEM32%",
            Self::ProgramFiles => "%PROGRAMFILES%",
            Self::ProgramData => "%PROGRAMDATA%",
            Self::UserProfile => "%USERPROFILE%",
            Self::AppData => "%APPDATA%",
            Self::LocalAppData => "%LOCALAPPDATA%",
            Self::Temp => "%TEMP%",
            Self::Removable => "%REMOVABLE%",
            Self::Hot => "%HOT%",
            Self::Network => "%NETWORK%",
        }
    }

    /// Parses a token, ignoring ASCII case.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|v| v.token().eq_ignore_ascii_case(token))
    }
}

impl fmt::Display for PathVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// The folders the folder variables stand for. Every path must already have
/// its short names expanded. Empty lists match nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownFolders {
    /// The root of the OS volume (`C:\`).
    pub os_drive: Vec<NormalizedPath>,
    /// The Windows folder.
    pub windir: Vec<NormalizedPath>,
    /// `System32` and `SysWOW64`.
    pub system32: Vec<NormalizedPath>,
    /// Both Program Files folders.
    pub program_files: Vec<NormalizedPath>,
    /// `ProgramData`.
    pub program_data: Vec<NormalizedPath>,
    /// The user's profile folder.
    pub user_profile: Vec<NormalizedPath>,
    /// The user's roaming application-data folder.
    pub app_data: Vec<NormalizedPath>,
    /// The user's local application-data folder.
    pub local_app_data: Vec<NormalizedPath>,
    /// The user's and the system's temporary folders.
    pub temp: Vec<NormalizedPath>,
}

impl KnownFolders {
    fn folders(&self, v: PathVariable) -> &[NormalizedPath] {
        match v {
            PathVariable::OsDrive => &self.os_drive,
            PathVariable::WinDir => &self.windir,
            PathVariable::System32 => &self.system32,
            PathVariable::ProgramFiles => &self.program_files,
            PathVariable::ProgramData => &self.program_data,
            PathVariable::UserProfile => &self.user_profile,
            PathVariable::AppData => &self.app_data,
            PathVariable::LocalAppData => &self.local_app_data,
            PathVariable::Temp => &self.temp,
            PathVariable::Removable | PathVariable::Hot | PathVariable::Network => &[],
        }
    }
}

/// Every variable that covers `path`, in [`PathVariable::ALL`] order. A
/// path usually matches several (a file under `%SYSTEM32%` is also under
/// `%WINDIR%` and `%OSDRIVE%`). The location variables come from `volume`,
/// the volume the path is on, when known.
///
/// Fails if `path` may still contain an unexpanded 8.3 short name. A known
/// folder that may contain one is skipped, so it matches nothing.
pub fn path_variables_matched(
    path: &NormalizedPath,
    folders: &KnownFolders,
    volume: Option<&VolumeInfo>,
) -> Result<Vec<PathVariable>, PathError> {
    path.require_long_names()?;
    let mut out = Vec::new();
    for v in PathVariable::ALL {
        let hit = match v {
            PathVariable::Removable => {
                volume.is_some_and(|vol| vol.location_class() == LocationClass::Removable)
            }
            PathVariable::Hot => volume.is_some_and(|vol| vol.is_hotplug == Some(true)),
            PathVariable::Network => {
                volume.is_some_and(|vol| vol.location_class() == LocationClass::Network)
                    || matches!(path.root(), super::path::Root::Unc { .. })
            }
            _ => folders
                .folders(v)
                .iter()
                .any(|f| f.short_name_candidates().is_empty() && path.starts_with(f)),
        };
        if hit {
            out.push(v);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::path::normalize_win32;
    use super::super::volume::DriveType;
    use super::*;

    fn p(s: &str) -> NormalizedPath {
        normalize_win32(s).unwrap()
    }

    fn folders() -> KnownFolders {
        KnownFolders {
            os_drive: vec![p(r"C:\")],
            windir: vec![p(r"C:\Windows")],
            system32: vec![p(r"C:\Windows\System32"), p(r"C:\Windows\SysWOW64")],
            program_files: vec![p(r"C:\Program Files"), p(r"C:\Program Files (x86)")],
            program_data: vec![p(r"C:\ProgramData")],
            user_profile: vec![p(r"C:\Users\alice")],
            app_data: vec![p(r"C:\Users\alice\AppData\Roaming")],
            local_app_data: vec![p(r"C:\Users\alice\AppData\Local")],
            temp: vec![
                p(r"C:\Users\alice\AppData\Local\Temp"),
                p(r"C:\Windows\Temp"),
            ],
        }
    }

    struct SensitiveUsers;

    impl super::super::path::CaseSensitivityResolver for SensitiveUsers {
        fn is_case_sensitive(&self, dir: &NormalizedPath) -> Option<bool> {
            Some(dir.case_folded() == r"C:\USERS")
        }
    }

    #[test]
    fn case_sensitive_folders_match_exactly() {
        let f = folders();
        // `C:\Users` is case-sensitive, so `ALICE` is not `alice` there.
        let mut other = p(r"C:\Users\ALICE\x.exe");
        other.resolve_case_sensitivity(&SensitiveUsers);
        let vars = path_variables_matched(&other, &f, None).unwrap();
        assert!(!vars.contains(&PathVariable::UserProfile), "{vars:?}");
        assert!(vars.contains(&PathVariable::OsDrive));
        let mut same = p(r"C:\Users\alice\x.exe");
        same.resolve_case_sensitivity(&SensitiveUsers);
        let vars = path_variables_matched(&same, &f, None).unwrap();
        assert!(vars.contains(&PathVariable::UserProfile), "{vars:?}");
    }

    #[test]
    fn folder_variables() {
        let f = folders();
        let m = |s: &str| path_variables_matched(&p(s), &f, None).unwrap();
        assert_eq!(
            m(r"c:\windows\syswow64\x.dll"),
            [
                PathVariable::OsDrive,
                PathVariable::WinDir,
                PathVariable::System32
            ]
        );
        assert_eq!(
            m(r"C:\Program Files (x86)\App\a.exe"),
            [PathVariable::OsDrive, PathVariable::ProgramFiles]
        );
        assert_eq!(
            m(r"C:\Users\Alice\AppData\Local\Temp\x.exe"),
            [
                PathVariable::OsDrive,
                PathVariable::UserProfile,
                PathVariable::LocalAppData,
                PathVariable::Temp
            ]
        );
        assert_eq!(
            m(r"C:\Windows\Temp\x.exe"),
            [
                PathVariable::OsDrive,
                PathVariable::WinDir,
                PathVariable::Temp
            ]
        );
        // A sibling whose name starts the same is not inside.
        assert_eq!(m(r"C:\Windows2\x.exe"), [PathVariable::OsDrive]);
        assert_eq!(m(r"D:\x.exe"), []);
    }

    #[test]
    fn location_variables() {
        let f = KnownFolders::default();
        let usb = VolumeInfo {
            drive_type: Some(DriveType::Removable),
            is_hotplug: Some(true),
            ..VolumeInfo::default()
        };
        assert_eq!(
            path_variables_matched(&p(r"E:\x.exe"), &f, Some(&usb)).unwrap(),
            [PathVariable::Removable, PathVariable::Hot]
        );
        assert_eq!(
            path_variables_matched(&p(r"\\server\share\x.exe"), &f, None).unwrap(),
            [PathVariable::Network]
        );
    }

    #[test]
    fn short_names_must_be_expanded() {
        let f = folders();
        assert!(path_variables_matched(&p(r"C:\PROGRA~1\x.exe"), &f, None).is_err());
        let bad = KnownFolders {
            program_files: vec![p(r"C:\PROGRA~1")],
            ..KnownFolders::default()
        };
        assert_eq!(
            path_variables_matched(&p(r"C:\Program Files\x.exe"), &bad, None).unwrap(),
            []
        );
    }

    #[test]
    fn tokens() {
        for v in PathVariable::ALL {
            assert_eq!(PathVariable::from_token(&v.token().to_lowercase()), Some(v));
        }
        assert_eq!(PathVariable::from_token("%NOPE%"), None);
    }
}
