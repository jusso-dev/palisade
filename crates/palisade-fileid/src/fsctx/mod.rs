//! File-system context (#54): the attributes of a file that come from where
//! and how it is stored, not from its content.
//!
//! Path rules, owner-based trust, location conditions and download
//! provenance all depend on these. Everything in this module is pure and
//! portable, so it is unit-tested on every OS:
//!
//! - [`path`]: one canonical form for every way of naming a file (device
//!   paths, `\\?\`, `\??\`, `GLOBALROOT`, UNC, trailing dots and spaces,
//!   streams, case folding, an 8.3 short-name hook);
//! - [`vars`]: Palisade path variables such as `%WINDIR%`;
//! - [`sid`]: security identifiers;
//! - [`acl`]: security descriptors, owner classification and the
//!   user-writability decision for a file and its ancestor folders;
//! - [`volume`]: file system, drive and bus types, and the location class;
//! - [`motw`]: the `Zone.Identifier` mark-of-the-web.
//!
//! The OS reads live in the Windows-only `palisade_fileid::win::fsctx`
//! module (ADR 0003), compiled only on Windows with the `os-trust` feature.
//! It reads a file's final path and its `Zone.Identifier` stream so far.
//! Reading the owner and DACL, the drive and bus type, volume GUIDs and DFS
//! targets, and the OS access check, are still to come (#54). [`FsContext`] keeps every attribute
//! optional, so a caller fills in what it could read and leaves the rest
//! `None`, and a consumer never mistakes "not read" for "absent".

#![forbid(unsafe_code)]

pub mod acl;
pub mod motw;
pub mod path;
pub mod sid;
pub mod vars;
pub mod volume;

pub use acl::{
    Ace, AceKind, AdminSids, Ancestor, DescriptorError, EvaluationOptions, ObjectKind,
    ObjectWritability, OwnerInfo, OwnerTrustClass, Principal, PrincipalRights, SecurityDescriptor,
    Writability, WriteRights, assess_path, evaluate,
};
pub use motw::{Motw, MotwWarning, Zone, parse_zone_identifier};
pub use path::{
    NormalizedPath, PathError, PathNotes, Prefix, Root, ShortNameResolver, Stream, fold_case,
    normalize_nt, normalize_win32,
};
pub use sid::{Sid, SidError};
pub use vars::{KnownFolders, PathVariable, path_variables_matched};
pub use volume::{BusType, DriveType, FsType, LocationClass, VolumeInfo};

/// The forms of one file's path. Only `original` is always present; each
/// other form needs an OS lookup and is `None` until one fills it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathForms {
    /// The path as given.
    pub original: String,
    /// `original`, normalised. `Err` if it cannot be (a relative path, a
    /// reserved device name and so on).
    pub normalized: Result<NormalizedPath, PathError>,
    /// The NT device form (`\Device\HarddiskVolumeN\...`).
    pub nt_path: Option<NormalizedPath>,
    /// The drive-letter form (`C:\...`).
    pub dos_path: Option<NormalizedPath>,
    /// The volume GUID form (`\\?\Volume{GUID}\...`).
    pub volume_guid_path: Option<NormalizedPath>,
    /// The path with every 8.3 short name expanded.
    pub long_path: Option<NormalizedPath>,
    /// The UNC form, for a mapped drive or a network path.
    pub unc_path: Option<NormalizedPath>,
    /// The DFS target, for a path in a DFS namespace.
    pub dfs_target: Option<NormalizedPath>,
    /// The final path of the opened handle, with links and junctions
    /// resolved. Decisions should use this form (threat model T-agent-13).
    pub final_path: Option<NormalizedPath>,
}

impl PathForms {
    /// The forms that can be worked out without the OS: `normalized`, and
    /// `dos_path` or `unc_path` when the path is already in that form and
    /// holds no short-name candidate (so it is also `long_path`).
    #[must_use]
    pub fn from_original(original: &str) -> Self {
        Self::from_normalized(original, normalize_win32(original))
    }

    fn from_normalized(original: &str, normalized: Result<NormalizedPath, PathError>) -> Self {
        let mut forms = Self {
            original: original.to_owned(),
            normalized: normalized.clone(),
            nt_path: None,
            dos_path: None,
            volume_guid_path: None,
            long_path: None,
            unc_path: None,
            dfs_target: None,
            final_path: None,
        };
        if let Ok(p) = normalized {
            if p.short_name_candidates().is_empty() {
                match p.root() {
                    Root::Drive(_) => forms.dos_path = Some(p.clone()),
                    Root::Unc { .. } => forms.unc_path = Some(p.clone()),
                    Root::NtDevice(_) => forms.nt_path = Some(p.clone()),
                    Root::VolumeGuid(_) => forms.volume_guid_path = Some(p.clone()),
                    Root::DosDevice(_) => {}
                }
                forms.long_path = Some(p);
            }
        }
        forms
    }

    /// As [`Self::from_original`], for an NT object path as the kernel
    /// reports image paths (`\Device\HarddiskVolume3\...`).
    #[must_use]
    pub fn from_nt(original: &str) -> Self {
        Self::from_normalized(original, normalize_nt(original))
    }

    /// The form to match rules about the opened file against: the final
    /// path of the opened handle. `None` until a caller has read it.
    ///
    /// The other forms describe the name as written. Through a symbolic
    /// link, junction or mount point, that name can belong to a different
    /// file from the one opened, so there is no fallback to them here
    /// (threat model T-agent-13). Use [`Self::lexical`] to match the name
    /// itself.
    #[must_use]
    pub fn canonical(&self) -> Option<&NormalizedPath> {
        self.final_path.as_ref()
    }

    /// [`NormalizedPath::match_key`] of [`Self::canonical`]: the key for
    /// link-aware rule matching. `None` until the final path is known.
    #[must_use]
    pub fn case_folded(&self) -> Option<String> {
        self.canonical().and_then(|p| p.match_key().ok())
    }

    /// The name as written, with every short name expanded: the long path.
    /// It does not resolve links, so it says what the path names, not which
    /// file opening it reaches.
    #[must_use]
    pub fn lexical(&self) -> Option<&NormalizedPath> {
        self.long_path.as_ref()
    }

    /// [`NormalizedPath::match_key`] of [`Self::lexical`], for matching the
    /// name rather than the opened file.
    #[must_use]
    pub fn lexical_key(&self) -> Option<String> {
        self.lexical().and_then(|p| p.match_key().ok())
    }
}

/// Everything known about where a file is stored. See the module
/// documentation. Fields this crate cannot fill yet (streams, reparse
/// points, hard links, file ID, USN and Palisade provenance tags) come with
/// the rest of #54.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsContext {
    /// The path forms.
    pub path: PathForms,
    /// The volume the file is on.
    pub volume: Option<VolumeInfo>,
    /// The owner.
    pub owner: Option<OwnerInfo>,
    /// Writability by non-administrators. Expensive, so computed on demand.
    pub writability: Option<Writability>,
    /// The mark-of-the-web. `None` means it was not read; a read that found
    /// no `Zone.Identifier` stream is `Some(None)`.
    pub motw: Option<Option<Motw>>,
    /// The Palisade path variables that cover the canonical path.
    pub path_variables_matched: Option<Vec<PathVariable>>,
}

impl FsContext {
    /// A context holding only the path forms that need no OS lookup.
    #[must_use]
    pub fn from_path(original: &str) -> Self {
        Self {
            path: PathForms::from_original(original),
            volume: None,
            owner: None,
            writability: None,
            motw: None,
            path_variables_matched: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_forms_without_the_os() {
        let f = PathForms::from_original(r"c:\windows\system32\cmd.exe.");
        assert_eq!(
            f.dos_path
                .as_ref()
                .map(NormalizedPath::to_win32_string)
                .as_deref(),
            Some(r"C:\windows\system32\cmd.exe")
        );
        assert_eq!(
            f.lexical_key().as_deref(),
            Some(r"C:\WINDOWS\SYSTEM32\CMD.EXE")
        );
        // With no final path there is no link-aware key, only the lexical one.
        assert_eq!(f.canonical(), None);
        assert_eq!(f.case_folded(), None);

        let s = PathForms::from_original(r"C:\PROGRA~1\x.exe");
        assert!(s.normalized.is_ok());
        assert_eq!(s.long_path, None);
        assert_eq!(s.lexical_key(), None);
        assert_eq!(s.case_folded(), None);

        let u = PathForms::from_original(r"\\srv\share\x.exe");
        assert!(u.unc_path.is_some());
        assert!(u.dos_path.is_none());

        let bad = PathForms::from_original(r"relative\x.exe");
        assert_eq!(bad.normalized, Err(PathError::NotFullyQualified));
        assert_eq!(bad.canonical(), None);
        assert_eq!(bad.lexical(), None);

        let nt = PathForms::from_nt(r"\Device\HarddiskVolume3\Windows\x.exe");
        assert!(nt.nt_path.is_some());
        assert!(nt.lexical().is_some());
        assert!(nt.canonical().is_none());

        let ctx = FsContext::from_path(r"C:\x.exe");
        assert!(ctx.motw.is_none());
        assert!(ctx.path.lexical().is_some());
        assert!(ctx.path.canonical().is_none());
    }

    #[test]
    fn rule_key_uses_the_final_path() {
        // `C:\trusted\link.exe` is a link to `C:\untrusted\payload.exe`.
        let mut f = PathForms::from_original(r"C:\trusted\link.exe");
        assert_eq!(f.case_folded(), None);
        f.final_path = normalize_win32(r"C:\untrusted\payload.exe").ok();
        assert_eq!(
            f.case_folded().as_deref(),
            Some(r"C:\UNTRUSTED\PAYLOAD.EXE")
        );
        assert_eq!(f.lexical_key().as_deref(), Some(r"C:\TRUSTED\LINK.EXE"));
        // A final path with an unexpanded short name still yields no key.
        f.final_path = normalize_win32(r"C:\PROGRA~1\x.exe").ok();
        assert_eq!(f.case_folded(), None);
    }
}
