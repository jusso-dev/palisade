//! Location classes from a normalised path and ACL facts (#39, #4).
//!
//! The agent normally sets [`ObjectFacts::location_class`](crate::facts::ObjectFacts::location_class)
//! itself, because it knows the volume, the path variables and the
//! writable-path scanner's results. Those classes are facts: exactly those,
//! and no others. [`classify`] is the reference rule the agent follows, and
//! the engine uses it, with the path's volume fact
//! ([`PathFact::volume`](crate::facts::PathFact::volume)) and the path
//! variables of the evaluation, when the agent left the classes unset.
//!
//! # Three-valued classes
//!
//! A location class can relax a decision as well as tighten it: stage 6
//! takes the most restrictive entry among the classes an object is in, and
//! `default` when it is in none with an entry. So the classifier never
//! grants a class from a guess. For each class it answers, with the crate's
//! Kleene logic ([`Tri`]):
//!
//! - `Match`: the facts establish it;
//! - `NoMatch`: the facts rule it out;
//! - `Unknown`: a missing fact could make it true. The missing facts are
//!   listed ([`Classified::missing`], [`MissingFact`]).
//!
//! Stage 6 resolves the level from the `Match` classes, as before, and then
//! also applies every `Unknown` class's entry (or `default` where it has
//! none), taking the most restrictive ([`crate::unknown`]). Removing a fact
//! only turns a `Match` or `NoMatch` class into `Unknown`, which can only
//! add to that maximum, so **a missing fact never makes an object look
//! safer** (ADR 0018). With every fact present nothing is `Unknown`, and
//! the classes are exactly those this classifier gave before.
//!
//! What makes a class `Unknown`:
//!
//! - **A missing path variable**, for the classes it decides. Without
//!   `%WINDIR%`, `windows` and the `%WINDIR%\Temp` part of `temp` are
//!   `Unknown` for every path; without `%PROGRAMFILES%`, `program_files`
//!   is; without `%TEMP%`, `temp` is (unless a cache folder or the agent's
//!   temporary folders establish it); without `%USERPROFILE%`, `%APPDATA%`,
//!   `%LOCALAPPDATA%` or `%PUBLIC%`, `user_profile` is (unless the path is
//!   under `X:\Users\<name>`). There are no drive-root guesses: a folder
//!   named `\Windows`, `\Program Files` or `\Windows\Temp` is not the
//!   system's unless the variable says so. With a variable present, it
//!   decides: `Match` or `NoMatch`, never `Unknown`, for the folders it
//!   lists, so a `%PROGRAMFILES%` that lists only `C:\Program Files` makes
//!   `C:\Program Files (x86)` `NoMatch`.
//! - **An unknown volume kind**, for `removable`, `optical`, `network` (on
//!   a drive path), and the classes that need a fixed volume:
//!   `program_files`, `windows` and `other_fixed`.
//! - **No usable path** (none, or not a drive or UNC path, an 8.3 short
//!   name the agent could not expand, or a volume whose case folding is
//!   not known, #399): every class the path decides. A
//!   known removable, optical or network volume still rules out
//!   `program_files`, `windows` and `other_fixed`, which no path on it can
//!   be in.
//! - **No ACL fact** ([`PathFact::user_writable`](crate::facts::PathFact::user_writable)):
//!   `user_writable_other`, unless a directory the scanner flagged
//!   establishes it. A writable ACL or a flagged directory is `Match`, and
//!   a safe ACL is `NoMatch`.
//! - Derived classes follow the logic: `other_fixed` (a drive path on a
//!   fixed volume in none of `user_profile`, `temp`, `program_files` and
//!   `windows`) is `Unknown` whenever one of those is.
//!
//! **Consequence.** A missing variable can make many paths `Unknown` for
//! one class, so a policy with a strict entry for that class blocks more
//! unknown objects while the fact is missing. That fails closed, and only
//! affects objects no rule decided. The endpoint agent is expected to
//! supply the volume kind and every variable; the decision names what was
//! missing ([`crate::unknown::UnknownHandling::missing_facts`]).
//!
//! | Class | `Match` when |
//! |---|---|
//! | `ads` | the path names an alternate data stream |
//! | `network` | a UNC path, a mapped drive (its alias is UNC), or a network volume |
//! | `removable`, `optical` | the volume is of that kind |
//! | `user_profile` | under `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%` or `%PUBLIC%`, or under `X:\Users\<name>` on any drive |
//! | `temp` | under `%TEMP%` or `%WINDIR%\Temp`, any `INetCache` or `Temporary Internet Files` folder below the drive or share root, or a directory the agent lists as a temporary cache |
//! | `user_writable_other` | the ACL facts say a non-administrator can write the file or a directory above it, or it is under a directory the scanner flagged; `Unknown` without the ACL fact, or when the path is not usable |
//! | `program_files` | under `%PROGRAMFILES%`, on a fixed volume |
//! | `windows` | under `%WINDIR%`, on a fixed volume |
//! | `other_fixed` | a drive path on a fixed volume that is in none of `user_profile`, `temp`, `program_files` and `windows`; it can come with `user_writable_other` and `ads` |
//!
//! `program_files` and `windows` are the protected classes, so they are
//! never given to a file on a removable, optical or network volume, or to
//! a network path: a disc or share holding its own `\Windows` folder is
//! not the system's. When the path has an alias (the other spelling of a
//! mapped drive or a UNC path), both spellings are classified and a class
//! is the `or` of the two, except that a network spelling of either rules
//! out the protected classes. Paths compare without case, at component
//! boundaries.

use std::collections::BTreeSet;

use palisade_core::path::{NormalizedPath, PathKind};

use super::{Classes, MissingFact};
use crate::facts::{PathFact, PathVariable, PathVariables};
use crate::model::LocationClass;
use crate::ops::{Tri, fold_path};

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
    /// The kind of volume, if known. Without it, `removable`, `optical`,
    /// `network` (for a drive path) and every class that needs a fixed
    /// volume are `Unknown`.
    pub volume: Option<VolumeKind>,
    /// Directories the writable-path scanner flagged as writable by a
    /// non-administrator (#5, #17).
    pub writable_dirs: &'a [NormalizedPath],
    /// Further temporary and cache directories the agent knows of, such as
    /// a browser's download cache or a mail client's attachment cache.
    pub temp_dirs: &'a [NormalizedPath],
}

/// The location classes of one path: what the facts say about each class,
/// and the facts that were missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    /// `Match`, `NoMatch` or `Unknown` for every class.
    pub classes: Classes<LocationClass>,
    /// The facts whose absence left a class `Unknown`.
    pub missing: BTreeSet<MissingFact>,
}

/// Folder names that are temporary internet caches wherever they are.
const CACHE_COMPONENTS: [&str; 2] = ["INetCache", "Temporary Internet Files"];

/// The location classes of `path`, with no scanner or temporary-folder
/// facts.
#[must_use]
pub fn classify(
    path: &PathFact,
    variables: &PathVariables,
    volume: Option<VolumeKind>,
    writable_dirs: &[NormalizedPath],
) -> Classified {
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

/// The classes of an object with no path: every class is `Unknown`.
#[must_use]
pub fn unclassified() -> Classified {
    Classified {
        classes: Classes::new(&LocationClass::ALL, |_| Tri::Unknown),
        missing: BTreeSet::from([MissingFact::Path]),
    }
}

/// The location classes of `path`, with the agent's hints.
#[must_use]
pub fn classify_with(path: &PathFact, variables: &PathVariables, hints: &Hints<'_>) -> Classified {
    use LocationClass as L;
    let mut missing = BTreeSet::new();
    let a = classify_one(&path.path, path, variables, hints, &mut missing);
    let Some(alias) = &path.alias else {
        return Classified {
            classes: a,
            missing,
        };
    };
    let b = classify_one(alias, path, variables, hints, &mut missing);
    let either = |c: L| a.get(c).or(b.get(c));
    // A network spelling of either form makes it a network file, which is
    // never in a protected class.
    let network = either(L::Network);
    let program_files = either(L::ProgramFiles).and(network.not());
    let windows = either(L::Windows).and(network.not());
    let placed = [L::UserProfile, L::Temp, L::Removable, L::Optical]
        .into_iter()
        .map(either)
        .fold(network.or(program_files).or(windows), Tri::or);
    let other_fixed = either(L::OtherFixed).and(placed.not());
    let classes = Classes::new(&L::ALL, |c| match c {
        L::Network => network,
        L::ProgramFiles => program_files,
        L::Windows => windows,
        L::OtherFixed => other_fixed,
        _ => either(c),
    });
    Classified { classes, missing }
}

/// What `variables` say about `file` being under `v`: `Unknown`, and
/// recorded as missing, when the variable is not set.
fn under_variable(
    file: &str,
    variables: &PathVariables,
    v: PathVariable,
    missing: &mut BTreeSet<MissingFact>,
) -> Tri {
    let values = variables.get(v);
    if values.is_empty() {
        if let Some(fact) = MissingFact::variable(v) {
            missing.insert(fact);
        }
        return Tri::Unknown;
    }
    Tri::from_bool(values.iter().any(|base| under(file, base.as_str())))
}

/// The classes of one spelling `p` of the file described by `path`.
fn classify_one(
    p: &NormalizedPath,
    path: &PathFact,
    variables: &PathVariables,
    hints: &Hints<'_>,
    missing: &mut BTreeSet<MissingFact>,
) -> Classes<LocationClass> {
    use LocationClass as L;
    let volume = |kind: VolumeKind, missing: &mut BTreeSet<MissingFact>| match hints.volume {
        Some(v) => Tri::from_bool(v == kind),
        None => {
            missing.insert(MissingFact::VolumeKind);
            Tri::Unknown
        }
    };
    let ads = Tri::from_bool(p.stream().is_some());
    let removable = volume(VolumeKind::Removable, missing);
    let optical = volume(VolumeKind::Optical, missing);
    let network = if p.kind() == PathKind::Unc {
        Tri::Match
    } else {
        volume(VolumeKind::Network, missing)
    };
    if !p.is_resolved() || path.short_name_unresolved || path.fold_unknown {
        // Without a usable path nothing the path decides is known, except
        // what the volume rules out: a known removable, optical or network
        // volume can hold no protected folder and no `other_fixed` file.
        missing.insert(MissingFact::Path);
        let on_fixed = match hints.volume {
            Some(v) => Tri::from_bool(v == VolumeKind::Fixed),
            None => Tri::Unknown,
        };
        return Classes::new(&L::ALL, |c| match c {
            L::Ads => ads,
            L::Removable => removable,
            L::Optical => optical,
            L::Network => network,
            L::ProgramFiles | L::Windows | L::OtherFixed => on_fixed.and(Tri::Unknown),
            _ => Tri::Unknown,
        });
    }
    let file = p.without_stream();
    let mut var = |v| under_variable(file, variables, v, missing);
    let user_profile = [
        PathVariable::UserProfile,
        PathVariable::AppData,
        PathVariable::LocalAppData,
        PathVariable::Public,
    ]
    .into_iter()
    .map(&mut var)
    .fold(Tri::from_bool(in_users_dir(p)), Tri::or);
    let windir_temp = if variables.get(PathVariable::Windir).is_empty() {
        var(PathVariable::Windir)
    } else {
        Tri::from_bool(variables.get(PathVariable::Windir).iter().any(|w| {
            under(
                file,
                &format!("{}\\Temp", w.as_str().trim_end_matches('\\')),
            )
        }))
    };
    let temp = var(PathVariable::Temp)
        .or(windir_temp)
        .or(Tri::from_bool(has_cache_component(p)))
        .or(Tri::from_bool(
            hints.temp_dirs.iter().any(|d| under(file, d.as_str())),
        ));
    let program_files_var = var(PathVariable::ProgramFiles);
    let windows_var = var(PathVariable::Windir);
    // A scanner-flagged directory or a writable ACL establishes the class;
    // a safe ACL rules it out; without the ACL fact it is `Unknown`.
    let writable = if hints.writable_dirs.iter().any(|d| under(file, d.as_str())) {
        Tri::Match
    } else {
        match path.user_writable {
            Some(w) => Tri::from_bool(w),
            None => {
                missing.insert(MissingFact::UserWritable);
                Tri::Unknown
            }
        }
    };
    // Only a fixed local volume can hold the system's own folders, and
    // `other_fixed` is a drive path on one.
    let fixed = if p.kind() == PathKind::Drive {
        volume(VolumeKind::Fixed, missing)
    } else {
        Tri::NoMatch
    };
    let program_files = program_files_var.and(fixed);
    let windows = windows_var.and(fixed);
    let placed = user_profile.or(temp).or(program_files).or(windows);
    let other_fixed = fixed.and(placed.not());
    Classes::new(&L::ALL, |c| match c {
        L::Ads => ads,
        L::Network => network,
        L::Removable => removable,
        L::Optical => optical,
        L::UserProfile => user_profile,
        L::Temp => temp,
        L::UserWritableOther => writable,
        L::ProgramFiles => program_files,
        L::Windows => windows,
        L::OtherFixed => other_fixed,
    })
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
