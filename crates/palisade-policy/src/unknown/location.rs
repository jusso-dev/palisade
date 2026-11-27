//! Location classes from a normalised path and ACL facts (#39, #4).
//!
//! The agent normally sets [`ObjectFacts::location_class`](crate::facts::ObjectFacts::location_class)
//! itself, because it knows the volume type and the writable-path scanner's
//! results. [`classify`] is the reference rule it uses, and the engine falls
//! back to it, with no volume facts and no scanner results, when the agent
//! left the classes unset. Every rule below only ever adds classes, so
//! a missing ACL fact can only make an object look less safe.
//!
//! The protected classes `program_files` and `windows` are the exception
//! that needs care, because a missing fact must never grant one (ADR 0018):
//!
//! - With `%PROGRAMFILES%` or `%WINDIR%` set, the class comes from the
//!   variable: a path under it, on a drive whose volume is fixed or not
//!   known. The variable names a folder on the volume Windows runs from,
//!   so a path under it is on that volume, and a missing volume fact does
//!   not change that. A path on a volume known to be removable, optical or
//!   network never gets the class.
//! - Without the variable, the drive-root fallback (`X:\Program Files`,
//!   `X:\Program Files (x86)`, `X:\Windows`) counts only when the volume
//!   is known to be fixed ([`Hints::volume`]) **and** known to be the volume
//!   Windows runs from ([`Hints::os_volume`]). A `\Windows` folder on a USB
//!   drive, a second disk, or a volume the agent did not describe gets no
//!   protected class from it.
//!
//! So removing a volume or variable fact never adds a protected class: a
//! missing fact can make an object look less safe, never more.
//!
//! Without a volume fact, a drive path is otherwise treated as on a fixed
//! volume, so a file on a USB drive or a disc whose volume kind is not
//! known loses only the `removable` or `optical` class. A policy that is
//! stricter for `removable` or `optical` than for the classes such a file
//! gets instead (such as `removable: block` with `default: detect`) is only
//! as strict as the volume facts: the agent must supply the volume kind or
//! the location classes themselves for those entries to apply. Such a file
//! is `other_fixed` only as the table says: a drive path on a fixed or
//! unknown volume that is in none of `user_profile`, `temp`,
//! `program_files` and `windows` (`D:\Users\alice\a.exe` is
//! `user_profile`, not `other_fixed`).
//!
//! The `%WINDIR%\Temp` fallback (`X:\Windows\Temp` on any drive, without
//! `%WINDIR%`) is kept as it is: `temp` makes an object look less safe, so
//! granting it on a missing fact fails closed.
//!
//! | Class | When |
//! |---|---|
//! | `ads` | the path names an alternate data stream |
//! | `network` | a UNC path, a mapped drive (its alias is UNC), or a network volume |
//! | `removable`, `optical` | the volume is of that kind |
//! | `user_profile` | under `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%` or `%PUBLIC%`, or under `X:\Users\<name>` on any drive |
//! | `temp` | under `%TEMP%` or `%WINDIR%\Temp` (without `%WINDIR%`, `X:\Windows\Temp`), any `INetCache` or `Temporary Internet Files` folder below the drive or share root, or a directory the agent lists as a temporary cache |
//! | `user_writable_other` | the ACL facts say a non-administrator can write the file or a directory above it, or they are not known; under a directory the scanner flagged; or the path is not a drive or UNC path |
//! | `program_files` | under `%PROGRAMFILES%`; without that variable, `X:\Program Files` or `X:\Program Files (x86)` on a volume known to be fixed and the OS volume |
//! | `windows` | under `%WINDIR%`; without that variable, `X:\Windows` on a volume known to be fixed and the OS volume |
//! | `other_fixed` | a drive path on a fixed or unknown volume that is in none of `user_profile`, `temp`, `program_files` and `windows`; it can come with `user_writable_other` and `ads` |
//!
//! `program_files` and `windows` are the protected classes, so they are
//! never given to a file on a removable, optical or network volume, or to
//! a network path: a disc or share holding its own `\Windows` folder is
//! not the system's. The drive-letter fallbacks apply only when the
//! variables are not set, and only on the known fixed OS volume. When the
//! path has an alias (the other spelling of a mapped drive or a UNC path),
//! both spellings are classified and the classes joined, except that the
//! protected classes need both spellings to be local. Paths compare without case, at component boundaries.

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
