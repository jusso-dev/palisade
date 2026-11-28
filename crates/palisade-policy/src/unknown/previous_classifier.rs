//! The location classifier as it was at 8923bd8, before location classes
//! became three-valued (#39, round five). Test-only: the oracle for "full,
//! consistent facts give exactly the classes they gave before".
#![allow(dead_code, clippy::all, clippy::pedantic)]

use std::collections::BTreeSet;

use palisade_core::path::{NormalizedPath, PathKind};

use crate::facts::{PathFact, PathVariable, PathVariables};
use crate::model::LocationClass;
use crate::ops::fold_path;

use crate::unknown::VolumeKind;

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
    /// The file's volume is known to be the one Windows runs from. Only
    /// then, with `volume` known to be fixed, do the drive-root fallbacks
    /// give `program_files` and `windows` when `%PROGRAMFILES%` or
    /// `%WINDIR%` is not set. `false`, the default, means not known.
    pub os_volume: bool,
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
            os_volume: false,
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
    if !p.is_resolved() || path.short_name_unresolved || path.fold_unknown {
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
    // A drive-root fallback may grant a protected class only on a volume
    // known to be the fixed OS volume: a missing fact never grants one
    // (ADR 0018). Under a variable the path is on the OS volume already.
    let os_root =
        p.kind() == PathKind::Drive && hints.volume == Some(VolumeKind::Fixed) && hints.os_volume;
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
        os_root && (under_root("Program Files") || under_root("Program Files (x86)"))
    };
    if local && program_files {
        out.insert(L::ProgramFiles);
    }
    let windows = if has(PathVariable::Windir) {
        under_var(&[PathVariable::Windir])
    } else {
        os_root && under_root("Windows")
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
    let base = fold_path(base.trim_end_matches('\\'), false);
    if base.is_empty() {
        return false;
    }
    let path = fold_path(path, false);
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
    matches!(parts.next(), Some(first) if fold_path(first, false) == "USERS")
        && parts.next().is_some()
}

/// Whether a directory above the file, below the drive or share root, is
/// a temporary internet cache. A UNC path's server and share names are
/// part of its root, not directories.
fn has_cache_component(p: &NormalizedPath) -> bool {
    let body = &p.without_stream()[p.root().len()..];
    let mut parts: Vec<&str> = body.split('\\').filter(|s| !s.is_empty()).collect();
    // The last component is the file itself.
    parts.pop();
    let wanted: Vec<String> = CACHE_COMPONENTS
        .iter()
        .map(|c| fold_path(c, false))
        .collect();
    parts.iter().any(|c| wanted.contains(&fold_path(c, false)))
}
