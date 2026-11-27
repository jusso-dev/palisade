//! Location classes from a normalised path and ACL facts (#39, #4).
//!
//! The agent normally sets [`ObjectFacts::location_class`](crate::facts::ObjectFacts::location_class)
//! itself, because it knows the volume type and the writable-path scanner's
//! results. [`classify`] is the reference rule it uses, and the engine falls
//! back to it, with no volume facts and no scanner results, when the agent
//! left the classes unset. Every rule below only ever adds classes, so
//! a missing ACL fact can only make an object look less safe.
//!
//! Volume facts are the exception: without them, a drive path is taken to
//! be on a fixed volume. A file on a USB drive or a disc whose volume kind
//! is not known therefore loses the `removable` or `optical` class, and
//! it is classified as if it were on a fixed disk:
//!
//! - it can be `program_files` or `windows`, which a known removable or
//!   optical volume never is. With `%PROGRAMFILES%` and `%WINDIR%` set, only
//!   a path under those folders is (so in practice only the system drive).
//!   Without them, the drive-root fallbacks give `X:\Program Files` and
//!   `X:\Windows` on **any** drive, including `D:\Windows\a.exe` on a USB
//!   drive;
//! - otherwise, it is `other_fixed`.
//!
//! A policy that is stricter for `removable` or `optical` than for the
//! classes such a file gets instead (such as `removable: block` with
//! `default: detect`) is only as strict as the volume facts: the agent must
//! supply the volume kind ([`Hints::volume`]) or the location classes
//! themselves for those entries to apply, and should supply the path
//! variables so the drive-root fallbacks are not used.
//!
//! | Class | When |
//! |---|---|
//! | `ads` | the path names an alternate data stream |
//! | `network` | a UNC path, a mapped drive (its alias is UNC), or a network volume |
//! | `removable`, `optical` | the volume is of that kind |
//! | `user_profile` | under `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%` or `%PUBLIC%`, or under `X:\Users\<name>` on any drive |
//! | `temp` | under `%TEMP%` or `%WINDIR%\Temp` (without `%WINDIR%`, `X:\Windows\Temp`), any `INetCache` or `Temporary Internet Files` folder below the drive or share root, or a directory the agent lists as a temporary cache |
//! | `user_writable_other` | the ACL facts say a non-administrator can write the file or a directory above it, or they are not known; under a directory the scanner flagged; or the path is not a drive or UNC path |
//! | `program_files` | under `%PROGRAMFILES%`; without that variable, `X:\Program Files` or `X:\Program Files (x86)` |
//! | `windows` | under `%WINDIR%`; without that variable, `X:\Windows` |
//! | `other_fixed` | a drive path on a fixed (or unknown) volume in none of `user_profile`, `temp`, `program_files` and `windows`; it can come with `user_writable_other` and `ads` |
//!
//! `program_files` and `windows` are the protected classes, so they are
//! never given to a file on a removable, optical or network volume, or to
//! a network path: a disc or share holding its own `\Windows` folder is
//! not the system's. The drive-letter fallbacks apply only when the
//! variables are not set. When the path has an alias (the other spelling
//! of a mapped drive or a UNC path), both spellings are classified and the
//! classes joined, except that the protected classes need both spellings
//! to be local. Paths compare without case, at component boundaries.

use std::collections::BTreeSet;

use palisade_core::path::{NormalizedPath, PathKind};

use crate::facts::{PathFact, PathVariable, PathVariables};
use crate::model::LocationClass;
use crate::ops::fold;

/// The kind of volume a file is on, as the agent reports it (#4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VolumeKind {
    /// A fixed disk.
    Fixed,
    /// A removable volume, such as a USB drive.
    Removable,
    /// An optical disc.
    Optical,
    /// A network volume.
    Network,
}

/// Facts the agent adds to the path when it classifies a location.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hints<'a> {
    /// The kind of volume, if known.
    pub volume: Option<VolumeKind>,
    /// Directories the writable-path scanner flagged as writable by a
    /// non-administrator (#5, #17).
    pub writable_dirs: &'a [NormalizedPath],
    /// Further temporary and cache directories the agent knows of, such as
    /// a browser's download cache or a mail client's attachment cache.
    pub temp_dirs: &'a [NormalizedPath],
}

/// Folder names that are temporary internet caches wherever they are.
const CACHE_COMPONENTS: [&str; 2] = ["INetCache", "Temporary Internet Files"];

/// The location classes of `path`, with no volume or scanner facts.
#[must_use]
pub fn classify(
    path: &PathFact,
    variables: &PathVariables,
    volume: Option<VolumeKind>,
    writable_dirs: &[NormalizedPath],
) -> BTreeSet<LocationClass> {
    classify_with(
        path,
        variables,
        &Hints {
            volume,
            writable_dirs,
            temp_dirs: &[],
        },
    )
}

/// The location classes of `path`, with the agent's hints.
#[must_use]
pub fn classify_with(
    path: &PathFact,
    variables: &PathVariables,
    hints: &Hints<'_>,
) -> BTreeSet<LocationClass> {
    let mut out = classify_one(&path.path, path, variables, hints);
    if let Some(alias) = &path.alias {
        let other = classify_one(alias, path, variables, hints);
        let both_local =
            !out.contains(&LocationClass::Network) && !other.contains(&LocationClass::Network);
        out.extend(other);
        if out.contains(&LocationClass::Network) || !both_local {
            out.remove(&LocationClass::ProgramFiles);
            out.remove(&LocationClass::Windows);
            out.insert(LocationClass::Network);
        }
        // `other_fixed` means none of the other places.
        if [
            LocationClass::UserProfile,
            LocationClass::Temp,
            LocationClass::ProgramFiles,
            LocationClass::Windows,
            LocationClass::Removable,
            LocationClass::Optical,
            LocationClass::Network,
        ]
        .iter()
        .any(|c| out.contains(c))
        {
            out.remove(&LocationClass::OtherFixed);
        }
    }
    out
}

/// The classes of one spelling `p` of the file described by `path`.
fn classify_one(
    p: &NormalizedPath,
    path: &PathFact,
    variables: &PathVariables,
    hints: &Hints<'_>,
) -> BTreeSet<LocationClass> {
    use LocationClass as L;
    let mut out = BTreeSet::new();
    if p.stream().is_some() {
        out.insert(L::Ads);
    }
    if p.kind() == PathKind::Unc || hints.volume == Some(VolumeKind::Network) {
        out.insert(L::Network);
    }
    match hints.volume {
        Some(VolumeKind::Removable) => {
            out.insert(L::Removable);
        }
        Some(VolumeKind::Optical) => {
            out.insert(L::Optical);
        }
        Some(VolumeKind::Fixed | VolumeKind::Network) | None => {}
    }
    if !p.is_resolved() || path.short_name_unresolved {
        out.insert(L::UserWritableOther);
        return out;
    }
    let file = p.without_stream();
    let under_var = |vars: &[PathVariable]| {
        vars.iter()
            .flat_map(|v| variables.get(*v))
            .any(|base| under(file, base.as_str()))
    };
    let under_root = |rel: &str| {
        // `X:\<rel>` on the file's own drive.
        p.kind() == PathKind::Drive && under(file, &format!("{}{rel}", p.root()))
    };
    // Only a fixed (or unknown) local volume can hold the system's own
    // folders.
    let local =
        p.kind() == PathKind::Drive && matches!(hints.volume, None | Some(VolumeKind::Fixed));
    let has = |v: PathVariable| !variables.get(v).is_empty();

    if under_var(&[
        PathVariable::UserProfile,
        PathVariable::AppData,
        PathVariable::LocalAppData,
        PathVariable::Public,
    ]) || in_users_dir(p)
    {
        out.insert(L::UserProfile);
    }
    let windir_temp = if has(PathVariable::Windir) {
        variables.get(PathVariable::Windir).iter().any(|w| {
            under(
                file,
                &format!("{}\\Temp", w.as_str().trim_end_matches('\\')),
            )
        })
    } else {
        under_root("Windows\\Temp")
    };
    if under_var(&[PathVariable::Temp])
        || windir_temp
        || has_cache_component(p)
        || hints.temp_dirs.iter().any(|d| under(file, d.as_str()))
    {
        out.insert(L::Temp);
    }
    if path.user_writable != Some(false)
        || hints.writable_dirs.iter().any(|d| under(file, d.as_str()))
    {
        out.insert(L::UserWritableOther);
    }
    let program_files = if has(PathVariable::ProgramFiles) {
        under_var(&[PathVariable::ProgramFiles])
    } else {
        under_root("Program Files") || under_root("Program Files (x86)")
    };
    if local && program_files {
        out.insert(L::ProgramFiles);
    }
    let windows = if has(PathVariable::Windir) {
        under_var(&[PathVariable::Windir])
    } else {
        under_root("Windows")
    };
    if local && windows {
        out.insert(L::Windows);
    }
    let placed = [L::UserProfile, L::Temp, L::ProgramFiles, L::Windows]
        .iter()
        .any(|c| out.contains(c));
    if local && !placed {
        out.insert(L::OtherFixed);
    }
    out
}

/// Whether `path` is `base` or below it, without case, at a component
/// boundary.
fn under(path: &str, base: &str) -> bool {
    let base = fold(base.trim_end_matches('\\'), false);
    if base.is_empty() {
        return false;
    }
    let path = fold(path, false);
    path.strip_prefix(base.as_str())
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
}

/// Whether a drive path is inside a user's folder: `X:\Users\<name>\…`.
fn in_users_dir(p: &NormalizedPath) -> bool {
    if p.kind() != PathKind::Drive {
        return false;
    }
    let body = &p.without_stream()[p.root().len()..];
    let mut parts = body.split('\\').filter(|s| !s.is_empty());
    matches!(parts.next(), Some(first) if fold(first, false) == "USERS") && parts.next().is_some()
}

/// Whether a directory above the file, below the drive or share root, is
/// a temporary internet cache. A UNC path's server and share names are
/// part of its root, not directories.
fn has_cache_component(p: &NormalizedPath) -> bool {
    let body = &p.without_stream()[p.root().len()..];
    let mut parts: Vec<&str> = body.split('\\').filter(|s| !s.is_empty()).collect();
    // The last component is the file itself.
    parts.pop();
    let wanted: Vec<String> = CACHE_COMPONENTS.iter().map(|c| fold(c, false)).collect();
    parts.iter().any(|c| wanted.contains(&fold(c, false)))
}
