//! What the inventory covers (policy `inventory.*`, #60) and the phase-1
//! prefilter: which files are candidates to classify, and in which order.

#![forbid(unsafe_code)]

use std::ffi::OsStr;

use palisade_fileid::filetype::{ExtensionKind, FileKind, classify_bytes};
use palisade_fileid::fsctx::fold_case;

/// Which volumes the inventory scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VolumeScope {
    /// The volume holding the Windows directory only.
    OsOnly,
    /// Every fixed volume.
    #[default]
    AllFixed,
    /// Every fixed and removable volume.
    AllFixedAndRemovable,
    /// The volumes listed in [`InventoryScope::custom_volumes`].
    Custom,
}

/// How hard the scan may use the machine. The budgets themselves are #65.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanPriority {
    /// Background I/O priority and an idle-time preference.
    #[default]
    Low,
    /// Normal priority.
    Normal,
    /// As fast as the budgets allow.
    High,
}

/// The inventory's scope settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryScope {
    /// Which volumes to scan.
    pub volumes: VolumeScope,
    /// Volume GUID paths for [`VolumeScope::Custom`].
    pub custom_volumes: Vec<String>,
    /// UNC paths to include. Off (empty) by default.
    pub network_paths: Vec<String>,
    /// Count archives (ZIP, CAB and the like) as candidates too.
    pub include_archives: bool,
    /// Path prefixes to leave out, matched case-insensitively on whole
    /// components.
    pub exclude_paths: Vec<String>,
    /// File names to leave out anywhere (`pagefile.sys` and the like).
    pub exclude_names: Vec<String>,
    /// Classify files whose extension says nothing about their content by
    /// reading them, in user-writable locations.
    pub sniff_unknown_extensions: bool,
    /// Count OS-vendor-signed files under the Windows directory, without
    /// uploading them one by one.
    pub skip_os_vendor_signed_in_windir: bool,
    /// Files larger than this are classified but not hashed.
    pub max_file_size_for_hash: u64,
    /// Scan alternate data streams on NTFS.
    pub ads_scan: bool,
    /// Scan priority.
    pub scan_priority: ScanPriority,
    /// Days a deleted entry is kept before it is purged.
    pub deleted_retention_days: u32,
}

impl Default for InventoryScope {
    fn default() -> Self {
        Self {
            volumes: VolumeScope::default(),
            custom_volumes: Vec::new(),
            network_paths: Vec::new(),
            include_archives: false,
            exclude_paths: vec![
                r"\System Volume Information".into(),
                r"\$Recycle.Bin".into(),
            ],
            exclude_names: vec![
                "pagefile.sys".into(),
                "hiberfil.sys".into(),
                "swapfile.sys".into(),
            ],
            sniff_unknown_extensions: true,
            skip_os_vendor_signed_in_windir: false,
            max_file_size_for_hash: 4 << 30,
            ads_scan: true,
            scan_priority: ScanPriority::default(),
            deleted_retention_days: 14,
        }
    }
}

/// What the name alone says about a file, before its content is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Candidate {
    /// A PE image by its extension: scanned first.
    Pe,
    /// A script by its extension.
    Script,
    /// An installer or app package by its extension.
    Installer,
    /// Another executable-content extension.
    OtherExecutable,
    /// An archive, when archives are included.
    Archive,
    /// No extension, or one the classifier does not know: its content
    /// must be read to tell.
    Unknown,
}

impl InventoryScope {
    /// Whether `path` (a Win32 path, with its volume root) is left out.
    #[must_use]
    pub fn excludes(&self, path: &str) -> bool {
        let folded = fold_case(path);
        let name = folded.rsplit(['\\', '/']).next().unwrap_or_default();
        if self.exclude_names.iter().any(|n| fold_case(n) == name) {
            return true;
        }
        self.exclude_paths.iter().any(|prefix| {
            let p = fold_case(prefix.trim_end_matches('\\'));
            if p.starts_with('\\') && !p.starts_with(r"\\") {
                // Rooted at any volume: match after the root.
                folded.match_indices(p.as_str()).any(|(at, _)| {
                    is_root_end(&folded[..at]) && component_ends(&folded, at + p.len())
                })
            } else {
                folded.starts_with(p.as_str()) && component_ends(&folded, p.len())
            }
        })
    }

    /// What the name says, or `None` if the file is not a candidate at
    /// all: its extension says it is a document, image or other content
    /// that never runs code. `user_writable` decides whether a file with
    /// an unknown extension is sniffed ([`Self::sniff_unknown_extensions`]
    /// applies to user-writable locations; elsewhere it is not).
    #[must_use]
    pub fn candidate(&self, name: &str, user_writable: bool) -> Option<Candidate> {
        // The classifier's extension table, with no content.
        let c = classify_bytes(&[], Some(OsStr::new(name)));
        match c.extension_kind {
            ExtensionKind::Kind(kind) => self.by_kind(kind),
            ExtensionKind::Inert => None,
            ExtensionKind::None | ExtensionKind::Other => {
                (self.sniff_unknown_extensions && user_writable).then_some(Candidate::Unknown)
            }
            _ => Some(Candidate::Unknown),
        }
    }

    fn by_kind(&self, kind: FileKind) -> Option<Candidate> {
        match kind {
            FileKind::Pe => Some(Candidate::Pe),
            FileKind::Script(_) => Some(Candidate::Script),
            FileKind::Msi
            | FileKind::Msp
            | FileKind::Mst
            | FileKind::Msm
            | FileKind::Msix
            | FileKind::Appx
            | FileKind::MsixBundle
            | FileKind::AppxBundle => Some(Candidate::Installer),
            k if k.is_executable_content() => Some(Candidate::OtherExecutable),
            FileKind::Zip | FileKind::Cab | FileKind::SevenZip | FileKind::Rar
                if self.include_archives =>
            {
                Some(Candidate::Archive)
            }
            _ => None,
        }
    }
}

/// Whether `before` is a whole volume root (`c:` or a `\\?\…` prefix up
/// to its root), so a rooted exclusion matches only at the volume's top.
fn is_root_end(before: &str) -> bool {
    let b = before.trim_start_matches(r"\\?\");
    let volume = b
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("volume{"));
    (b.len() == 2 && b.ends_with(':')) || (volume && b.ends_with('}') && !b.contains('\\'))
}

/// Whether `text` ends at `at` or has a separator there.
fn component_ends(text: &str, at: usize) -> bool {
    matches!(text.as_bytes().get(at), None | Some(b'\\' | b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_exclusions() {
        let s = InventoryScope::default();
        for p in [
            r"C:\pagefile.sys",
            r"D:\HIBERFIL.SYS",
            r"C:\System Volume Information\x.exe",
            r"C:\$Recycle.Bin\S-1-5-21\a.exe",
            r"\\?\Volume{abc}\$Recycle.Bin\a.exe",
        ] {
            assert!(s.excludes(p), "{p}");
        }
        for p in [
            r"C:\Windows\System32\cmd.exe",
            r"C:\data\System Volume Information\x.exe",
            r"C:\$Recycle.Bin2\a.exe",
            r"C:\x\pagefile.sys.exe",
        ] {
            assert!(!s.excludes(p), "{p}");
        }
    }

    #[test]
    fn absolute_exclusions_match_whole_components() {
        let s = InventoryScope {
            exclude_paths: vec![r"C:\ProgramData\Palisade\".into()],
            ..InventoryScope::default()
        };
        assert!(s.excludes(r"c:\programdata\palisade"));
        assert!(s.excludes(r"C:\ProgramData\Palisade\store\x.exe"));
        assert!(!s.excludes(r"C:\ProgramData\PalisadeX\x.exe"));
    }

    #[test]
    fn candidates_by_name() {
        let s = InventoryScope::default();
        assert_eq!(s.candidate("a.EXE", false), Some(Candidate::Pe));
        assert_eq!(s.candidate("a.dll", false), Some(Candidate::Pe));
        assert_eq!(s.candidate("a.ps1", false), Some(Candidate::Script));
        assert_eq!(s.candidate("a.msi", false), Some(Candidate::Installer));
        assert_eq!(
            s.candidate("a.lnk", false),
            Some(Candidate::OtherExecutable)
        );
        assert_eq!(s.candidate("a.pdf", true), None, "inert");
        assert_eq!(s.candidate("a.zip", false), None, "archives off");
        // Unknown extensions are sniffed only where users can write.
        assert_eq!(s.candidate("a.xyz", true), Some(Candidate::Unknown));
        assert_eq!(s.candidate("noext", true), Some(Candidate::Unknown));
        assert_eq!(s.candidate("a.xyz", false), None);
        let s = InventoryScope {
            include_archives: true,
            sniff_unknown_extensions: false,
            ..InventoryScope::default()
        };
        assert_eq!(s.candidate("a.zip", false), Some(Candidate::Archive));
        assert_eq!(s.candidate("a.xyz", true), None);
        // PE first, then scripts, installers and the rest.
        assert!(Candidate::Pe < Candidate::Script);
        assert!(Candidate::Script < Candidate::Installer);
        assert!(Candidate::Installer < Candidate::OtherExecutable);
    }
}
