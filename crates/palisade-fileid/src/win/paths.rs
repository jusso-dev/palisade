//! The OS lookups behind [`PathForms`] and [`FsContext`] (#54).
//!
//! [`read_path_forms`] fills every form of a file's path that the OS can
//! give, from the name as written and from the **open handle**:
//!
//! - `long_path`: the name as written with every 8.3 short name expanded,
//!   one component at a time, through [`OsShortNames`] (`FindFirstFileExW`
//!   on the exact entry, never a wildcard);
//! - `unc_path`: for a mapped drive letter, the UNC path it stands for in
//!   **this process's logon session** (`WNetGetConnectionW`). A service
//!   resolving a user's path must run the lookup in that user's session
//!   (#59 supplies it);
//! - `final_path`, `nt_path` and `volume_guid_path`: the handle's own final
//!   path in its DOS, NT (`\Device\…`) and volume GUID forms
//!   (`GetFinalPathNameByHandleW`), which never hold short names;
//! - `dfs_target`: the target of a DFS namespace path, through a
//!   [`DfsCache`] over [`OsDfs`] (`NetDfsGetClientInfo`), with the 2 s
//!   timeout and the cache in [`crate::fsctx::dfs`].
//!
//! [`read_context`] adds the volume ([`super::volume::read_volume_opened_as`],
//! so a UNC or mapped-drive name is never read as local) to make
//! an [`FsContext`].
//!
//! Every lookup uses the caller's security context and logon session.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io;

use super::sys;
use crate::fsctx::dfs::{DfsCache, DfsOutcome, DfsReferral, DfsResolver};
use crate::fsctx::path::ShortNameResolver;
use crate::fsctx::{FsContext, NormalizedPath, PathForms, Root, normalize_nt, normalize_win32};

/// `GetFinalPathNameByHandleW` volume forms.
const VOLUME_NAME_DOS: u32 = 0;
const VOLUME_NAME_GUID: u32 = 1;
const VOLUME_NAME_NT: u32 = 2;

/// Expands 8.3 short names with the file system's directory entries.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsShortNames;

impl ShortNameResolver for OsShortNames {
    fn long_name(&self, parent: &NormalizedPath, name: &str) -> Option<String> {
        // A wildcard would match some other entry; an 8.3 name never has one.
        if name.contains(['*', '?', '<', '>', '"']) {
            return None;
        }
        let mut path = parent.to_win32_string();
        if !path.ends_with('\\') {
            path.push('\\');
        }
        path.push_str(name);
        sys::find_long_name(&path).ok()
    }
}

/// DFS referrals from the OS (`NetDfsGetClientInfo`). Use it through a
/// [`DfsCache`], which adds the timeout and the cache.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsDfs;

impl DfsResolver for OsDfs {
    fn referral(&self, path: &NormalizedPath) -> io::Result<Option<DfsReferral>> {
        let Some((entry, target)) = sys::dfs_client_info(&path.to_win32_string())? else {
            return Ok(None);
        };
        let bad = |e| io::Error::new(io::ErrorKind::InvalidData, e);
        Ok(Some(DfsReferral {
            entry: normalize_win32(&entry).map_err(bad)?,
            target: normalize_win32(&target).map_err(bad)?,
        }))
    }
}

/// The UNC form of `path` when it is on a mapped drive letter, in this
/// process's logon session. `None` if the letter is not mapped or the
/// result is not a valid path.
#[must_use]
pub fn mapped_drive_unc(path: &NormalizedPath) -> Option<NormalizedPath> {
    let Root::Drive(d) = path.root() else {
        return None;
    };
    let remote = sys::mapped_drive_target(*d).ok()??;
    let onto = normalize_win32(&remote).ok()?;
    let drive_root = normalize_win32(&format!("{d}:\\")).ok()?;
    path.rebase(&drive_root, &onto)?.ok()
}

/// The handle's final path in the volume form `flags`, normalised, with
/// its components marked as long names and each directory's
/// case-sensitivity flag read (the NT form is opened through the
/// `\\?\GLOBALROOT` Win32 form).
fn final_form(file: &File, flags: u32) -> Option<NormalizedPath> {
    let text = sys::final_path_by_handle(file, flags).ok()?;
    let mut p = if flags == VOLUME_NAME_NT {
        normalize_nt(&text).ok()?
    } else {
        normalize_win32(&text).ok()?
    };
    p.mark_long_names_verified();
    p.resolve_case_sensitivity(&super::volume::OsCaseSensitivity);
    Some(p)
}

/// Every form of the path of `file`, opened from `original`. See the
/// module documentation. `dfs` resolves `dfs_target` when given, and its
/// outcome is kept in `PathForms::dfs`. Pass `None::<&mut DfsCache<OsDfs>>`
/// for no DFS lookup.
#[must_use]
pub fn read_path_forms<R: DfsResolver>(
    original: &str,
    file: &File,
    dfs: Option<&mut DfsCache<R>>,
) -> PathForms {
    let mut forms = PathForms::from_original(original);
    if let Ok(n) = &forms.normalized {
        let mut long = n.clone();
        if long.resolve_short_names(&OsShortNames).is_ok()
            && long.short_name_candidates().is_empty()
        {
            forms.long_path = Some(long);
        }
    }
    if let Some(long) = forms.long_path.clone() {
        match long.root() {
            Root::Drive(_) => {
                forms.dos_path.get_or_insert(long.clone());
                if let Some(unc) = mapped_drive_unc(&long) {
                    forms.unc_path = Some(unc);
                }
            }
            Root::Unc { .. } => {
                forms.unc_path.get_or_insert(long.clone());
            }
            _ => {}
        }
    }
    forms.final_path = final_form(file, VOLUME_NAME_DOS);
    forms.nt_path = final_form(file, VOLUME_NAME_NT);
    forms.volume_guid_path = final_form(file, VOLUME_NAME_GUID);
    if let Some(cache) = dfs {
        let unc = forms.unc_path.clone().or_else(|| {
            forms
                .final_path
                .clone()
                .filter(|p| matches!(p.root(), Root::Unc { .. }))
        });
        if let Some(u) = unc {
            // The outcome is kept whatever it is, so a timeout or failure
            // is never mistaken for "not DFS" (see `PathForms::network_key`).
            let outcome = cache.resolve(&u);
            if let DfsOutcome::Resolved(t) = &outcome {
                forms.dfs_target = Some(t.clone());
            }
            forms.dfs = Some(outcome);
        }
    }
    forms
}

/// The path forms and the volume of `file`, opened from `original`. The
/// other attributes stay `None` for the caller to fill.
#[must_use]
pub fn read_context<R: DfsResolver>(
    original: &str,
    file: &File,
    dfs: Option<&mut DfsCache<R>>,
) -> FsContext {
    let mut ctx = FsContext::from_path(original);
    ctx.path = read_path_forms(original, file, dfs);
    ctx.volume = Some(super::volume::read_volume_opened_as(original, file));
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_of_a_system_file() {
        let windir = sys::windows_directory().unwrap();
        let path = format!(r"{windir}\System32\cmd.exe");
        let file = File::open(&path).unwrap();
        let forms = read_path_forms(&path, &file, None::<&mut DfsCache<OsDfs>>);
        let nt = forms.nt_path.as_ref().unwrap();
        assert!(
            matches!(nt.root(), Root::NtDevice(d) if d.to_ascii_lowercase().starts_with("harddiskvolume")),
            "{nt}"
        );
        let guid = forms.volume_guid_path.as_ref().unwrap();
        assert!(matches!(guid.root(), Root::VolumeGuid(_)), "{guid}");
        // Three names of one file: the same components after the root.
        let fp = forms.final_path.as_ref().unwrap();
        assert_eq!(nt.components().len(), fp.components().len());
        assert_eq!(guid.case_folded().rsplit('\\').next(), Some("CMD.EXE"));
        assert_eq!(forms.lexical_key(), forms.case_folded());
        assert!(forms.unc_path.is_none());
    }

    #[test]
    fn wildcards_are_never_looked_up() {
        let windir = normalize_win32(&sys::windows_directory().unwrap()).unwrap();
        assert_eq!(OsShortNames.long_name(&windir, "SYS*"), None);
        assert_eq!(OsShortNames.long_name(&windir, "SYSTEM?2"), None);
        assert_eq!(
            OsShortNames
                .long_name(&windir, "system32")
                .map(|s| s.to_ascii_lowercase())
                .as_deref(),
            Some("system32")
        );
        assert_eq!(OsShortNames.long_name(&windir, "no-such-entry"), None);
    }
}
