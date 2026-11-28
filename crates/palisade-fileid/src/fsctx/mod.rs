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
//! - [`motw`]: the `Zone.Identifier` mark-of-the-web;
//! - [`ntfs`]: the stream list and change-journal records the OS returns;
//! - [`dfs`]: DFS namespace resolution with a timeout and a cache;
//! - [`meta`]: file IDs, USNs, timestamps, attributes and hard links;
//! - [`reparse`]: reparse data buffers (links, junctions, mount points,
//!   app execution aliases, cloud placeholders, deduplication);
//! - [`streams`]: alternate data streams, tagged and sniffed;
//! - [`upcase`]: which upcase table a volume records, so path keys are
//!   refused where names may fold differently (#332);
//! - [`writable`]: the per-descriptor writability cache, streaming
//!   ancestor assessment and `enumerate_user_writable_dirs`.
//!
//! The OS reads live in the Windows-only `palisade_fileid::win::fsctx`
//! module (ADR 0003), compiled only on Windows with the `os-trust` feature.
//! It reads a file's final path, its `Zone.Identifier` stream, owners and
//! security descriptors, writability of real paths, and the OS access
//! check (`palisade_fileid::win::access`). [`FsContext`] keeps every attribute
//! optional, so a caller fills in what it could read and leaves the rest
//! `None`, and a consumer never mistakes "not read" for "absent".

#![forbid(unsafe_code)]

pub mod acl;
pub mod dfs;
pub mod meta;
pub mod motw;
pub mod ntfs;
pub mod path;
pub mod reparse;
pub mod sid;
pub mod streams;
pub mod upcase;
pub mod vars;
pub mod volume;
pub mod writable;

pub use acl::{
    Ace, AceKind, AdminSids, Ancestor, DescriptorError, EvaluationOptions, ObjectKind,
    ObjectWritability, OsCheck, OwnerInfo, OwnerTrustClass, Principal, PrincipalRights,
    SecurityDescriptor, Writability, WriteRights, assess_path, evaluate, sanitized_self_relative,
};
pub use motw::{Motw, MotwWarning, Zone, parse_zone_identifier};
pub use path::{
    CaseSensitivityResolver, NormalizedPath, PathError, PathNotes, Prefix, Root, ShortNameResolver,
    Stream, fold_case, normalize_nt, normalize_win32,
};
pub use sid::{Sid, SidError};
pub use upcase::{STANDARD_UPCASE_CRC, VolumeUpcase, parse_upcase_info};
pub use vars::{KnownFolders, PathVariable, path_variables_matched};
pub use volume::{
    BusType, DriveType, FsType, HotplugInfo, LocationClass, NetworkEvidence, StorageDevice,
    VolumeInfo, combined_hotplug, nt_path_on_network, opened_name_on_network, parse_hotplug_info,
    parse_storage_device_descriptor,
};

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
    /// What the DFS lookup of the UNC form said. `None` if none was made.
    /// [`Self::network_key`] reads it: a timed-out or failed lookup leaves
    /// the file without a network key, never with the namespace's.
    pub dfs: Option<dfs::DfsOutcome>,
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
            dfs: None,
            final_path: None,
        };
        if let Ok(p) = normalized
            && p.short_name_candidates().is_empty()
        {
            match p.root() {
                Root::Drive(_) => forms.dos_path = Some(p.clone()),
                Root::Unc { .. } => forms.unc_path = Some(p.clone()),
                Root::NtDevice(_) => forms.nt_path = Some(p.clone()),
                Root::VolumeGuid(_) => forms.volume_guid_path = Some(p.clone()),
                Root::DosDevice(_) => {}
            }
            forms.long_path = Some(p);
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

    /// The key of the file's network name: the DFS target when known,
    /// otherwise the UNC form (for a UNC path, or a mapped drive the OS
    /// resolved). A mapped drive, a DFS namespace path and a short-name
    /// spelling of one file on a share all give the key of its long UNC
    /// path. `None` for a local file, while a short name is unexpanded,
    /// and when a DFS lookup timed out or failed ([`Self::dfs_unresolved`]):
    /// the UNC form may then be a namespace path whose target is unknown,
    /// and its key would not match the target's rules. A caller treats such
    /// a file as unknown, never as matching no network rule.
    #[must_use]
    pub fn network_key(&self) -> Option<String> {
        if self.dfs_unresolved() {
            return None;
        }
        self.dfs_target
            .as_ref()
            .or(self.unc_path.as_ref())
            .and_then(|p| p.match_key().ok())
    }

    /// True if a DFS lookup was made and did not finish (timed out or
    /// failed), so the path may be in a namespace whose target is unknown.
    #[must_use]
    pub fn dfs_unresolved(&self) -> bool {
        matches!(
            self.dfs,
            Some(dfs::DfsOutcome::TimedOut | dfs::DfsOutcome::Failed(_))
        )
    }

    /// [`NormalizedPath::match_key`] of [`Self::lexical`], for matching the
    /// name rather than the opened file.
    #[must_use]
    pub fn lexical_key(&self) -> Option<String> {
        self.lexical().and_then(|p| p.match_key().ok())
    }
}

/// Everything known about where a file is stored. See the module
/// documentation. The Palisade provenance tag comes with the rest of #54.
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
    /// The file ID, USN, timestamps and attributes.
    pub meta: Option<meta::FileMeta>,
    /// The hard links.
    pub hard_links: Option<meta::HardLinks>,
    /// The alternate data streams.
    pub streams: Option<streams::FsStreams>,
    /// The reparse point of the name's **last component** itself (a link,
    /// junction or alias at that name). `None` means it was not read; a
    /// read that found none is `Some(None)`.
    ///
    /// A folder above it can be a junction or mount point too, and this
    /// does not say so. Whether the name reaches a different file from the
    /// one it spells is told by comparing the original path with
    /// [`PathForms::final_path`]; rules match the final path (T-agent-13).
    pub reparse: Option<Option<reparse::ReparsePoint>>,
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
            meta: None,
            hard_links: None,
            streams: None,
            reparse: None,
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
        assert!(ctx.meta.is_none() && ctx.hard_links.is_none());
        assert!(ctx.streams.is_none() && ctx.reparse.is_none());
        assert!(ctx.path.lexical().is_some());
        assert!(ctx.path.canonical().is_none());
    }

    #[test]
    fn an_unresolved_dfs_lookup_gives_no_network_key() {
        let ns = r"\\corp\dfs\apps\tool.exe";
        let mut f = PathForms::from_original(ns);
        let key = f.network_key();
        assert_eq!(key.as_deref(), Some(r"\\CORP\DFS\APPS\TOOL.EXE"));
        f.dfs = Some(dfs::DfsOutcome::NotDfs);
        assert_eq!(f.network_key(), key);
        assert!(!f.dfs_unresolved());
        for outcome in [
            dfs::DfsOutcome::TimedOut,
            dfs::DfsOutcome::Failed("unreachable".into()),
        ] {
            f.dfs = Some(outcome);
            assert!(f.dfs_unresolved());
            assert_eq!(f.network_key(), None);
            // The name itself can still be matched lexically.
            assert!(f.lexical_key().is_some());
        }
        let target = normalize_win32(r"\\srv\apps\tool.exe").unwrap();
        f.dfs = Some(dfs::DfsOutcome::Resolved(target.clone()));
        f.dfs_target = Some(target);
        assert_eq!(f.network_key().as_deref(), Some(r"\\SRV\APPS\TOOL.EXE"));
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
        // Nor does one on a volume whose upcase table is unknown (#332).
        let mut odd = normalize_win32(r"D:\x.exe").unwrap();
        odd.mark_fold_unknown();
        f.final_path = Some(odd);
        assert_eq!(f.case_folded(), None);
    }
}
