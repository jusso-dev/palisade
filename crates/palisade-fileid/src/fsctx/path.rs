//! Path normalisation: one canonical form for every way of naming a file.
//!
//! A file on Windows can be named in many ways (threat model T-engine-04,
//! AT-04): `C:\Dir\File.exe`, `c:/dir/file.exe.`, `\\?\C:\Dir\File.exe`,
//! `\\.\C:\Dir\..\Dir\File.exe`, `\??\C:\Dir\File.exe`,
//! `\\?\GLOBALROOT\Device\HarddiskVolume3\Dir\File.exe`,
//! `C:\Dir\File.exe::$DATA`, `C:\DIR~1\FILE.EXE` and so on. Path rules must
//! see one form, so a file cannot dodge a rule, or match another rule, by
//! being named differently.
//!
//! [`normalize_win32`] takes a path as a Win32 API receives it, and
//! [`normalize_nt`] takes an NT object path as the kernel reports it
//! (`\Device\HarddiskVolume3\...`). Both return a [`NormalizedPath`]: a
//! [`Root`] (drive, UNC share, volume GUID, NT device or other DOS device),
//! the components, and an optional named stream. Nothing here touches the
//! file system or depends on the host OS.
//!
//! # What Win32 normalisation does
//!
//! Unless a path starts exactly with `\\?\` or `\??\`, the Win32 layer
//! rewrites it before the kernel sees it, and so does this module:
//!
//! - `/` becomes `\`, and runs of separators collapse to one;
//! - `.` components are removed, and `..` removes the previous component,
//!   but never the drive (`C:\`) or the UNC server and share. In a `\\.\`
//!   device path nothing is protected, so `..` can remove the device itself;
//! - a component followed by a separator loses one trailing `.`. One that
//!   ends with two or more dots is rejected, because sources disagree on how
//!   many the Win32 layer removes;
//! - unless the path ends with a separator, the last component loses all
//!   trailing dots and spaces (`file.exe. .` is `file.exe`);
//! - a reserved DOS device name (`CON`, `NUL`, `COM1`, `LPT1`, `CONIN$` and
//!   so on, with any extension) as the last component of a drive path names
//!   a device, not a file. Windows versions disagree about this, so such a
//!   path is rejected ([`PathError::ReservedDeviceName`]).
//!
//! A path that starts exactly with `\\?\` or `\??\` skips all of that and
//! is taken literally: `\\?\C:\Dir\file.exe.` names a file whose name really
//! ends with a dot, a different file from `C:\Dir\file.exe`. Literal `.` and
//! `..` components, and empty ones, cannot name a file, so they are rejected.
//!
//! Relative and drive-relative paths (`dir\file`, `\dir\file`, `C:file`)
//! depend on per-process state, so they are rejected
//! ([`PathError::NotFullyQualified`]).
//!
//! # Streams
//!
//! `file.txt:evil.exe` names the stream `evil.exe` of `file.txt`, and the
//! stream is part of the normalised path ([`NormalizedPath::stream`]), so a
//! rule for `file.txt` does not match it. `file::$DATA` is the file itself
//! and normalises to `file`. `dir::$INDEX_ALLOCATION` and
//! `dir:$I30:$INDEX_ALLOCATION` are the directory itself, anywhere in the
//! path, and normalise to `dir`. Both rewrites are recorded in
//! [`PathNotes`].
//!
//! # Case
//!
//! NTFS compares names by upper-casing each UTF-16 code unit with the
//! volume's upcase table. [`NormalizedPath::case_folded`] does the same with
//! Unicode simple upper-case mappings, limited to mappings that keep one
//! UTF-16 code unit (so `ß` stays `ß`, as on NTFS). The volume's own table
//! can differ for some non-ASCII letters; it is authoritative and reading it
//! is left to the OS backend (#54). Unicode normalisation (NFC/NFD) is not
//! applied, because NTFS does not apply it either: the two forms are two
//! different files.
//!
//! A directory can be marked case-sensitive, and then two names that differ
//! only in case are two entries. The folded key and
//! [`NormalizedPath::starts_with`] cannot see that flag, so they treat such
//! names as one. Reading the flag needs the OS and is left to the OS
//! backend (#54).
//!
//! # 8.3 short names
//!
//! A short name such as `PROGRA~1` names the same entry as its long name,
//! so a rule must never be matched against it (AT-04.5). A component that
//! could be a generated short name (8.3 shape with a `~`) is recorded as a
//! candidate, and [`NormalizedPath::match_key`] refuses to produce a key
//! until every candidate has been expanded through a [`ShortNameResolver`],
//! which is the OS hook. A long name can legitimately contain `~`; the
//! resolver then returns it unchanged. Paths from the OS's normalised final
//! path (`GetFinalPathNameByHandleW`) contain only long names.
//!
//! Short names that an administrator sets by hand need not contain `~`;
//! that is an administrator action and out of scope.
//!
//! # A string is a name, not an object
//!
//! A drive letter is looked up in the DOS device map of the logon session
//! that opens the path, and a standard user can add their own (`subst`,
//! `DefineDosDevice`). Junctions, symbolic links, mount points and hard links
//! give one file more names. So a normalised string says what a path *says*,
//! not which file it opens. Decisions about a file use the final path of the
//! opened handle, normalised here (threat model T-agent-13, AT-04.2, AT-04.3).
//! Mapping NT device names, volume GUIDs and drive letters to one volume
//! identity, and mapped drives and DFS paths to their targets, needs the OS
//! and is left to the OS backend (#54).

#![forbid(unsafe_code)]

use std::fmt;

/// The longest path accepted, in UTF-16 code units: the most a
/// `UNICODE_STRING` can hold.
pub const MAX_PATH_UNITS: usize = 32_767;

/// The classic `MAX_PATH` limit, minus the terminator. Longer paths are
/// supported; [`NormalizedPath::is_long`] reports them.
pub const LEGACY_MAX_PATH: usize = 259;

/// What a path is rooted at.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Root {
    /// A drive letter, upper-case ASCII (`C`).
    Drive(char),
    /// A UNC share, `\\server\share`, as written.
    Unc {
        /// The server name.
        server: String,
        /// The share name.
        share: String,
    },
    /// A volume GUID path, `\\?\Volume{…}\`. The GUID is kept in lower case,
    /// with its braces.
    VolumeGuid(String),
    /// An NT device, as in `\Device\HarddiskVolume3`. Holds the device
    /// name (`HarddiskVolume3`).
    NtDevice(String),
    /// Any other DOS device (`\\.\pipe`, `\\.\PhysicalDrive0`). Such paths
    /// do not name files on a volume.
    DosDevice(String),
}

/// A named stream, or a stream of a type other than the default data stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Stream {
    /// The stream name, as written. Empty for an unnamed stream of a type
    /// other than `$DATA`.
    pub name: String,
    /// The stream type in upper case, such as `$DATA`.
    pub kind: String,
}

/// How a path was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Prefix {
    /// A plain drive or UNC path.
    #[default]
    None,
    /// `\\?\` or `\??\`: taken literally, without Win32 normalisation.
    Verbatim,
    /// `\\.\` (or `\\?\` spelt with forward slashes): a device path that
    /// is still normalised.
    Device,
    /// An NT object path given to [`normalize_nt`].
    NtNamespace,
}

/// Facts about how a path was written that its canonical form drops.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PathNotes {
    /// The prefix used.
    pub prefix: Prefix,
    /// Win32 normalisation removed trailing dots or spaces.
    pub trimmed: bool,
    /// A `::$DATA` suffix (the default stream) was removed.
    pub default_stream_suffix: bool,
    /// A directory index-stream suffix (`::$INDEX_ALLOCATION`,
    /// `:$I30:$INDEX_ALLOCATION`) was removed.
    pub directory_stream_suffix: bool,
    /// The path is on a volume shadow copy (`HarddiskVolumeShadowCopyN`).
    pub is_shadow_copy: bool,
    /// The UNC server is a loopback name (`localhost`, `127.x.x.x`,
    /// `::1`), so the share may be a local folder. Comparing the server
    /// with the computer's own names needs the OS.
    pub loopback_server: bool,
}

/// The state of the 8.3 short-name check.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ShortNames {
    /// These component indexes may be short names.
    Candidates(Vec<usize>),
    /// The components are known to be long names.
    Verified,
}

/// A normalised path. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedPath {
    root: Root,
    components: Vec<String>,
    stream: Option<Stream>,
    notes: PathNotes,
    short_names: ShortNames,
}

/// Why a path could not be normalised. A caller that cannot normalise a
/// path must not treat it as "matches no rule"; it falls back to the final
/// path of the opened handle, or treats the file as unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathError {
    /// The path is empty.
    Empty,
    /// Longer than [`MAX_PATH_UNITS`] UTF-16 code units.
    TooLong,
    /// The path contains a NUL character.
    Nul,
    /// A relative, rooted (`\dir`) or drive-relative (`C:dir`) path.
    NotFullyQualified,
    /// A drive "letter" that is not an ASCII letter.
    InvalidDrive,
    /// A UNC path without a server or share.
    MissingShare,
    /// A component that cannot name a file: empty, `.` or `..` in a
    /// literal path, a component that becomes `..` after trimming, or a
    /// stream in a directory component.
    InvalidComponent(String),
    /// Stream syntax that is not `name:stream[:$TYPE]`.
    InvalidStream(String),
    /// The last component of a drive path is a reserved DOS device name.
    ReservedDeviceName(String),
    /// The path names a volume or device, not a file or directory on it
    /// (`\\.\C:`, `\Device\HarddiskVolume3` without a trailing separator).
    DeviceNotDirectory,
    /// An NT path outside `\??`, `\GLOBAL??`, `\DosDevices` and `\Device`,
    /// such as `\SystemRoot\...`. Resolving it needs the object manager.
    UnsupportedNtPath(String),
    /// A component may be an 8.3 short name that has not been expanded.
    UnresolvedShortName(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty path"),
            Self::TooLong => write!(f, "path longer than {MAX_PATH_UNITS} UTF-16 code units"),
            Self::Nul => f.write_str("path contains a NUL character"),
            Self::NotFullyQualified => f.write_str("path is not fully qualified"),
            Self::InvalidDrive => f.write_str("drive is not an ASCII letter"),
            Self::MissingShare => f.write_str("UNC path without a server and share"),
            Self::InvalidComponent(c) => write!(f, "component {c:?} cannot name a file"),
            Self::InvalidStream(c) => write!(f, "invalid stream syntax in {c:?}"),
            Self::ReservedDeviceName(c) => write!(f, "{c:?} is a reserved DOS device name"),
            Self::DeviceNotDirectory => f.write_str("path names a device, not a file"),
            Self::UnsupportedNtPath(c) => write!(f, "unsupported NT path root {c:?}"),
            Self::UnresolvedShortName(c) => {
                write!(
                    f,
                    "component {c:?} may be an 8.3 short name and is not expanded"
                )
            }
        }
    }
}

impl std::error::Error for PathError {}

/// The OS hook that expands 8.3 short names.
pub trait ShortNameResolver {
    /// The long name of the entry `name` in the directory `parent`, or
    /// `None` if it cannot be determined (the entry does not exist, or the
    /// lookup failed). If `name` is already a long name, returns it.
    fn long_name(&self, parent: &NormalizedPath, name: &str) -> Option<String>;
}

// ---------------------------------------------------------------------------
// Entry points.

/// Normalises a path the way the Win32 layer does before opening it. See
/// the module documentation.
pub fn normalize_win32(input: &str) -> Result<NormalizedPath, PathError> {
    check_input(input)?;
    if let Some(rest) = input
        .strip_prefix(r"\\?\")
        .or_else(|| input.strip_prefix(r"\??\"))
    {
        let (comps, ends_sep) = literal_components(rest)?;
        let mut notes = PathNotes {
            prefix: Prefix::Verbatim,
            ..PathNotes::default()
        };
        let (root, used) = identify_device(&comps, 0, &mut notes)?;
        return finish(root, comps, used, ends_sep, notes, false);
    }

    let s = input.replace('/', "\\");
    if let Some(after) = s.strip_prefix(r"\\") {
        // `\\.\` and `\\?\` spelt any other way (`//?/`) are device paths
        // that are still normalised, with nothing protected from `..`.
        let device = after
            .strip_prefix(".\\")
            .or_else(|| after.strip_prefix("?\\"));
        if let Some(rest) = device {
            let mut notes = PathNotes {
                prefix: Prefix::Device,
                ..PathNotes::default()
            };
            let w = win32_components(rest, 0, &mut notes)?;
            let (root, used) = identify_device(&w.names, 0, &mut notes)?;
            if matches!(root, Root::Unc { .. }) {
                // In a device path nothing is protected, so Win32 trimming
                // may have reached the server or share, whichever route
                // (`UNC`, `GLOBALROOT\Device\Mup`, after `..`) led there.
                // A trimmed server or share is ambiguous.
                for i in used.saturating_sub(2)..used {
                    if w.trimmed.get(i).copied().unwrap_or(true) {
                        let name = w.names.get(i).cloned().unwrap_or_default();
                        return Err(PathError::InvalidComponent(name));
                    }
                }
            }
            // `\\.\C:\.` and `\\.\C:\a\..` name the root directory: a separator
            // followed the volume in the input, even though `.` and `..`
            // removed what came after it. `\\.\X:\..\C:` does not.
            let root_dir = used
                .checked_sub(1)
                .and_then(|i| w.sep_after.get(i).copied())
                .unwrap_or(false);
            return finish_with(root, w.names, used, w.ends_sep, root_dir, notes, false);
        }
        if after == "." || after == "?" {
            return Err(PathError::DeviceNotDirectory);
        }
        let mut notes = PathNotes::default();
        let w = win32_components(after, 2, &mut notes)?;
        let (root, used) = unc_root(&w.names, 0, &mut notes)?;
        return finish(root, w.names, used, w.ends_sep, notes, false);
    }

    let mut chars = s.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(letter), Some(':'), Some('\\')) => {
            if !letter.is_ascii_alphabetic() {
                return Err(PathError::InvalidDrive);
            }
            let rest = chars.as_str();
            let mut notes = PathNotes::default();
            let w = win32_components(rest, 0, &mut notes)?;
            let root = Root::Drive(letter.to_ascii_uppercase());
            finish(root, w.names, 0, w.ends_sep, notes, true)
        }
        (Some(letter), Some(':'), _) if !letter.is_ascii_alphabetic() => {
            Err(PathError::InvalidDrive)
        }
        _ => Err(PathError::NotFullyQualified),
    }
}

/// Normalises an NT object path, as the kernel reports image paths:
/// `\Device\HarddiskVolume3\...`, `\Device\Mup\server\share\...`, or
/// `\??\C:\...` (also spelt `\GLOBAL??\` and `\DosDevices\`). Components
/// are taken literally, as the kernel does.
pub fn normalize_nt(input: &str) -> Result<NormalizedPath, PathError> {
    check_input(input)?;
    let Some(rest) = input.strip_prefix('\\') else {
        return Err(PathError::NotFullyQualified);
    };
    let (comps, ends_sep) = literal_components(rest)?;
    let mut notes = PathNotes {
        prefix: Prefix::NtNamespace,
        ..PathNotes::default()
    };
    let (root, used) = identify_nt(&comps, 0, 0, &mut notes)?;
    finish(root, comps, used, ends_sep, notes, false)
}

// ---------------------------------------------------------------------------
// Parsing helpers.

fn check_input(input: &str) -> Result<(), PathError> {
    if input.is_empty() {
        return Err(PathError::Empty);
    }
    if input.encode_utf16().nth(MAX_PATH_UNITS).is_some() {
        return Err(PathError::TooLong);
    }
    if input.contains('\0') {
        return Err(PathError::Nul);
    }
    Ok(())
}

/// Splits a literal path. Every component must be non-empty and not `.` or
/// `..`; a single trailing separator is allowed.
fn literal_components(rest: &str) -> Result<(Vec<String>, bool), PathError> {
    if rest.is_empty() {
        return Err(PathError::Empty);
    }
    let ends_sep = rest.ends_with('\\');
    let body = if ends_sep {
        rest.get(..rest.len() - 1).unwrap_or("")
    } else {
        rest
    };
    let mut comps = Vec::new();
    for part in body.split('\\') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(PathError::InvalidComponent(part.to_owned()));
        }
        comps.push(part.to_owned());
    }
    Ok((comps, ends_sep))
}

/// The components left after Win32 normalisation.
struct Win32Components {
    /// The component names.
    names: Vec<String>,
    /// Per component: trimming removed a dot or space from it.
    trimmed: Vec<bool>,
    /// Per component: a separator followed it in the input.
    sep_after: Vec<bool>,
    /// The input ended with a separator.
    ends_sep: bool,
}

/// Applies Win32 normalisation to the part of a path after its prefix.
/// The first `protected` components (the UNC server and share) are kept
/// as they are and cannot be removed by `..`.
fn win32_components(
    rest: &str,
    protected: usize,
    notes: &mut PathNotes,
) -> Result<Win32Components, PathError> {
    let ends_sep = rest.ends_with('\\');
    let parts: Vec<&str> = rest.split('\\').filter(|p| !p.is_empty()).collect();
    let mut names: Vec<String> = Vec::with_capacity(parts.len());
    let mut trimmed: Vec<bool> = Vec::with_capacity(parts.len());
    let mut sep_after: Vec<bool> = Vec::with_capacity(parts.len());
    let last_index = parts.len().checked_sub(1);
    for (i, part) in parts.iter().enumerate() {
        let followed_by_separator = Some(i) != last_index || ends_sep;
        if i < protected {
            // The server and share are not trimmed or collapsed. A name
            // that Win32 trimming might change is ambiguous, so it is
            // rejected rather than guessed.
            check_unc_name(part)?;
            names.push((*part).to_owned());
            trimmed.push(false);
            sep_after.push(followed_by_separator);
            continue;
        }
        match *part {
            "." => {}
            ".." => {
                if names.len() > protected {
                    names.pop();
                    trimmed.pop();
                    sep_after.pop();
                }
            }
            name => {
                if followed_by_separator && name.ends_with("..") {
                    // Sources disagree on whether Win32 removes one dot or
                    // all of them here, so the name is ambiguous.
                    return Err(PathError::InvalidComponent(name.to_owned()));
                }
                let mut name = name.to_owned();
                let mut was_trimmed = false;
                if followed_by_separator && name.ends_with('.') {
                    name.pop();
                    notes.trimmed = true;
                    was_trimmed = true;
                }
                names.push(name);
                trimmed.push(was_trimmed);
                sep_after.push(followed_by_separator);
            }
        }
    }
    if !ends_sep && names.len() > protected {
        // The final trim applies to whatever ends the path, even a
        // component that was followed by `\.` or `\..` in the input.
        if let Some(last) = names.last_mut() {
            let kept = last.trim_end_matches(['.', ' ']).len();
            if kept != last.len() {
                last.truncate(kept);
                notes.trimmed = true;
                if let Some(t) = trimmed.last_mut() {
                    *t = true;
                }
            }
            if last.is_empty() {
                names.pop();
                trimmed.pop();
                sep_after.pop();
            }
        }
    }
    for c in names.iter().skip(protected) {
        // One-dot trimming can turn `...` into `..`, which no longer
        // means "parent" but cannot name a file either.
        if c == "." || c == ".." {
            return Err(PathError::InvalidComponent(c.clone()));
        }
    }
    Ok(Win32Components {
        names,
        trimmed,
        sep_after,
        ends_sep,
    })
}

/// Reads a UNC server and share from `comps[at..]`.
fn unc_root(
    comps: &[String],
    at: usize,
    notes: &mut PathNotes,
) -> Result<(Root, usize), PathError> {
    let (Some(server), Some(share)) = (comps.get(at), comps.get(at + 1)) else {
        return Err(PathError::MissingShare);
    };
    check_unc_name(server)?;
    check_unc_name(share)?;
    if server == "?" {
        // `\\\?\x` collapses to a UNC path with server `?`, which reads
        // back as the device prefix `\\?\`. It is not a server name.
        return Err(PathError::InvalidComponent(server.clone()));
    }
    if server.contains(':') && !server.starts_with('[') {
        // Only a bracketed IPv6 literal may contain a colon.
        return Err(PathError::InvalidComponent(server.clone()));
    }
    if share.contains(':') {
        return Err(PathError::InvalidComponent(share.clone()));
    }
    notes.loopback_server = is_loopback(server);
    Ok((
        Root::Unc {
            server: server.clone(),
            share: share.clone(),
        },
        at + 2,
    ))
}

/// Checks a UNC server or share name, whichever way the path reached it
/// (plain, `\\?\UNC`, `\\.\UNC`, `\Device\Mup`). The server and share are
/// never trimmed or collapsed, so a name that Win32 trimming might change
/// (a trailing dot or space), a `.` or `..`, or one holding a `/` (which a
/// plain path would read as a separator) is ambiguous and rejected.
fn check_unc_name(name: &str) -> Result<(), PathError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || name.contains('/')
    {
        return Err(PathError::InvalidComponent(name.to_owned()));
    }
    Ok(())
}

fn is_loopback(server: &str) -> bool {
    let s = server.to_ascii_lowercase();
    s == "localhost"
        || s == "::1"
        || s == "[::1]"
        || s == "0--1.ipv6-literal.net"
        || s.strip_prefix("127.").is_some_and(|rest| {
            rest.split('.').count() == 3
                && rest
                    .split('.')
                    .all(|o| !o.is_empty() && o.len() <= 3 && o.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Identifies the device named by `comps[at]`, the first component after
/// a `\\?\`, `\\.\` or `\??\` prefix.
fn identify_device(
    comps: &[String],
    at: usize,
    notes: &mut PathNotes,
) -> Result<(Root, usize), PathError> {
    identify_device_depth(comps, at, 0, notes)
}

/// `GLOBALROOT` and `\??` can nest; this bounds how deep.
const MAX_NT_NESTING: u8 = 8;

fn identify_device_depth(
    comps: &[String],
    at: usize,
    depth: u8,
    notes: &mut PathNotes,
) -> Result<(Root, usize), PathError> {
    let Some(name) = comps.get(at) else {
        return Err(PathError::DeviceNotDirectory);
    };
    let bytes = name.as_bytes();
    if let [letter, b':'] = bytes {
        if letter.is_ascii_alphabetic() {
            return Ok((Root::Drive(char::from(letter.to_ascii_uppercase())), at + 1));
        }
        return Err(PathError::InvalidDrive);
    }
    if name.eq_ignore_ascii_case("UNC") {
        return unc_root(comps, at + 1, notes);
    }
    if name.eq_ignore_ascii_case("GLOBALROOT") {
        return identify_nt(comps, at + 1, depth + 1, notes);
    }
    if let Some(guid) = volume_guid(name) {
        return Ok((Root::VolumeGuid(guid), at + 1));
    }
    if is_harddisk_volume(name) {
        notes.is_shadow_copy = is_shadow_copy(name);
        return Ok((Root::NtDevice(name.clone()), at + 1));
    }
    if name.contains(':') {
        return Err(PathError::InvalidComponent(name.clone()));
    }
    Ok((Root::DosDevice(name.clone()), at + 1))
}

/// Identifies the root of an NT object path starting at `comps[at]`.
fn identify_nt(
    comps: &[String],
    at: usize,
    depth: u8,
    notes: &mut PathNotes,
) -> Result<(Root, usize), PathError> {
    if depth > MAX_NT_NESTING {
        return Err(PathError::UnsupportedNtPath("too deeply nested".to_owned()));
    }
    let Some(first) = comps.get(at) else {
        return Err(PathError::DeviceNotDirectory);
    };
    if first == "??"
        || first.eq_ignore_ascii_case("GLOBAL??")
        || first.eq_ignore_ascii_case("DosDevices")
    {
        return identify_device_depth(comps, at + 1, depth + 1, notes);
    }
    if first.eq_ignore_ascii_case("Device") {
        let Some(device) = comps.get(at + 1) else {
            return Err(PathError::DeviceNotDirectory);
        };
        if device.eq_ignore_ascii_case("Mup") || device.eq_ignore_ascii_case("LanmanRedirector") {
            // Redirector prefixes such as `;LanmanRedirector` and
            // `;Z:000000000001a2b3` come before the server.
            let mut i = at + 2;
            while comps.get(i).is_some_and(|c| c.starts_with(';')) {
                i += 1;
            }
            return unc_root(comps, i, notes);
        }
        if device.contains(':') {
            return Err(PathError::InvalidComponent(device.clone()));
        }
        notes.is_shadow_copy = is_shadow_copy(device);
        return Ok((Root::NtDevice(device.clone()), at + 2));
    }
    Err(PathError::UnsupportedNtPath(first.clone()))
}

/// `Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`, returning the braced
/// GUID in lower case.
fn volume_guid(name: &str) -> Option<String> {
    let prefix = name.get(..6)?;
    if !prefix.eq_ignore_ascii_case("Volume") {
        return None;
    }
    let guid = name.get(6..)?;
    let inner = guid.strip_prefix('{')?.strip_suffix('}')?;
    let groups: Vec<&str> = inner.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    if groups.len() != lens.len()
        || groups
            .iter()
            .zip(lens)
            .any(|(g, n)| g.len() != n || !g.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(guid.to_ascii_lowercase())
}

fn digits_after(name: &str, prefix: &str) -> bool {
    name.get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        && name
            .get(prefix.len()..)
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// `HarddiskVolumeN` and `HarddiskVolumeShadowCopyN`. The mount manager
/// links these DOS device names to the NT devices of the same name.
fn is_harddisk_volume(name: &str) -> bool {
    digits_after(name, "HarddiskVolume") || is_shadow_copy(name)
}

fn is_shadow_copy(name: &str) -> bool {
    digits_after(name, "HarddiskVolumeShadowCopy")
}

/// The reserved DOS device names (`CON`, `COM1`, ...). The digit may be a
/// superscript one, two or three, as the OS accepts.
fn is_reserved_device_name(component: &str) -> bool {
    let base = component
        .split(['.', ':'])
        .next()
        .unwrap_or("")
        .trim_end_matches(' ');
    let upper = base.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            let mut chars = upper.chars();
            let head: String = chars.by_ref().take(3).collect();
            let rest: Vec<char> = chars.collect();
            (head == "COM" || head == "LPT")
                && matches!(rest.as_slice(), [d] if d.is_ascii_digit() || matches!(d, '\u{b9}' | '\u{b2}' | '\u{b3}'))
        }
    }
}

/// True if a component could be an NTFS-generated 8.3 short name: an 8.3
/// shape (a base of 1 to 8 characters, an optional extension of up to 3)
/// with a `~` in the base.
#[must_use]
pub fn is_short_name_candidate(component: &str) -> bool {
    let (base, ext) = match component.rsplit_once('.') {
        Some((b, e)) => (b, Some(e)),
        None => (component, None),
    };
    let base_len = base.chars().count();
    (1..=8).contains(&base_len)
        && base.contains('~')
        && !base.contains('.')
        && ext.is_none_or(|e| e.chars().count() <= 3)
}

/// Splits the last component into its name and stream.
struct LastComponent {
    name: String,
    stream: Option<Stream>,
}

fn split_stream(comp: &str, notes: &mut PathNotes) -> Result<LastComponent, PathError> {
    let parts: Vec<&str> = comp.split(':').collect();
    let bad = || PathError::InvalidStream(comp.to_owned());
    let (name, stream, kind) = match parts.as_slice() {
        [name] => {
            return Ok(LastComponent {
                name: (*name).to_owned(),
                stream: None,
            });
        }
        [name, stream] => (*name, *stream, None),
        [name, stream, kind] => (*name, *stream, Some(*kind)),
        _ => return Err(bad()),
    };
    if name.is_empty() {
        return Err(bad());
    }
    let kind = match kind {
        None => {
            if stream.is_empty() {
                return Err(bad());
            }
            "$DATA".to_owned()
        }
        Some(k) => {
            if k.len() < 2 || !k.starts_with('$') {
                return Err(bad());
            }
            k.to_ascii_uppercase()
        }
    };
    if stream.is_empty() && kind == "$DATA" {
        notes.default_stream_suffix = true;
        return Ok(LastComponent {
            name: name.to_owned(),
            stream: None,
        });
    }
    if is_directory_index(stream, &kind) {
        notes.directory_stream_suffix = true;
        return Ok(LastComponent {
            name: name.to_owned(),
            stream: None,
        });
    }
    Ok(LastComponent {
        name: name.to_owned(),
        stream: Some(Stream {
            name: stream.to_owned(),
            kind,
        }),
    })
}

fn is_directory_index(stream: &str, kind: &str) -> bool {
    kind == "$INDEX_ALLOCATION" && (stream.is_empty() || stream.eq_ignore_ascii_case("$I30"))
}

/// Checks the components after the root and builds the result.
fn finish(
    root: Root,
    comps: Vec<String>,
    used: usize,
    ends_sep: bool,
    notes: PathNotes,
    drive_win32: bool,
) -> Result<NormalizedPath, PathError> {
    finish_with(root, comps, used, ends_sep, ends_sep, notes, drive_win32)
}

/// As [`finish`]. `root_dir` says whether a separator followed the root in
/// the input, so an empty remainder names the root directory rather than
/// the volume or device itself.
fn finish_with(
    root: Root,
    comps: Vec<String>,
    used: usize,
    ends_sep: bool,
    root_dir: bool,
    mut notes: PathNotes,
    drive_win32: bool,
) -> Result<NormalizedPath, PathError> {
    let mut rest: Vec<String> = comps.into_iter().skip(used).collect();
    // A device prefix followed by just a volume (`\\.\C:`, `\\?\Volume{…}`)
    // opens the volume itself, not its root directory. A plain `C:\` and a
    // UNC share always name the root directory.
    if rest.is_empty() && !root_dir && !drive_win32 && !matches!(root, Root::Unc { .. }) {
        return Err(PathError::DeviceNotDirectory);
    }
    let last = rest.len().checked_sub(1);
    let mut stream = None;
    for (i, comp) in rest.iter_mut().enumerate() {
        if Some(i) == last {
            let split = split_stream(comp, &mut notes)?;
            stream = split.stream;
            *comp = split.name;
        } else if comp.contains(':') {
            // Only the directory's own index stream may appear here.
            let parts: Vec<&str> = comp.split(':').collect();
            let ok = match parts.as_slice() {
                [name, stream, kind] if !name.is_empty() => {
                    is_directory_index(stream, &kind.to_ascii_uppercase())
                }
                _ => false,
            };
            if !ok {
                return Err(PathError::InvalidComponent(comp.clone()));
            }
            notes.directory_stream_suffix = true;
            let name = parts.first().copied().unwrap_or("").to_owned();
            *comp = name;
        }
        if comp == "." || comp == ".." || comp.is_empty() {
            return Err(PathError::InvalidComponent(comp.clone()));
        }
    }
    if ends_sep && stream.is_some() {
        // `C:\dir:s\` would name a stream as if it were a directory.
        let name = rest.last().cloned().unwrap_or_default();
        return Err(PathError::InvalidStream(name));
    }
    if drive_win32 {
        if let Some(last) = rest.last() {
            if is_reserved_device_name(last) {
                return Err(PathError::ReservedDeviceName(last.clone()));
            }
        }
    }
    let candidates: Vec<usize> = rest
        .iter()
        .enumerate()
        .filter(|(_, c)| is_short_name_candidate(c))
        .map(|(i, _)| i)
        .collect();
    let path = NormalizedPath {
        root,
        components: rest,
        stream,
        notes,
        short_names: if candidates.is_empty() {
            ShortNames::Verified
        } else {
            ShortNames::Candidates(candidates)
        },
    };
    // The canonical form can be longer than the input (a `\\?\GLOBALROOT`
    // prefix, say). It must itself be a valid path.
    path.check_length()?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// Case folding.

/// Upper-cases a name the way NTFS compares names: each character maps to
/// its simple upper-case form only when that is a single character of the
/// same UTF-16 length. See the module documentation.
#[must_use]
pub fn fold_case(s: &str) -> String {
    s.chars().map(fold_char).collect()
}

fn fold_char(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_uppercase();
    }
    if c.len_utf16() != 1 {
        return c;
    }
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) if u.len_utf16() == 1 => u,
        // A full mapping of more than one character. The simple mapping
        // may still be a single code unit.
        (Some(_), Some(_)) => simple_upper_exception(c).unwrap_or(c),
        _ => c,
    }
}

/// The Basic Multilingual Plane characters whose full upper-case mapping
/// has more than one character but whose simple mapping is a single
/// character (`UnicodeData.txt` against `SpecialCasing.txt`): the Greek
/// letters with a combining iota subscript. Every other character with a
/// multi-character full mapping (`ß`, `ŉ`, the ligatures) has no simple
/// mapping and stays unchanged.
const SIMPLE_UPPER_EXCEPTIONS: [(char, char); 27] = [
    ('\u{1F80}', '\u{1F88}'),
    ('\u{1F81}', '\u{1F89}'),
    ('\u{1F82}', '\u{1F8A}'),
    ('\u{1F83}', '\u{1F8B}'),
    ('\u{1F84}', '\u{1F8C}'),
    ('\u{1F85}', '\u{1F8D}'),
    ('\u{1F86}', '\u{1F8E}'),
    ('\u{1F87}', '\u{1F8F}'),
    ('\u{1F90}', '\u{1F98}'),
    ('\u{1F91}', '\u{1F99}'),
    ('\u{1F92}', '\u{1F9A}'),
    ('\u{1F93}', '\u{1F9B}'),
    ('\u{1F94}', '\u{1F9C}'),
    ('\u{1F95}', '\u{1F9D}'),
    ('\u{1F96}', '\u{1F9E}'),
    ('\u{1F97}', '\u{1F9F}'),
    ('\u{1FA0}', '\u{1FA8}'),
    ('\u{1FA1}', '\u{1FA9}'),
    ('\u{1FA2}', '\u{1FAA}'),
    ('\u{1FA3}', '\u{1FAB}'),
    ('\u{1FA4}', '\u{1FAC}'),
    ('\u{1FA5}', '\u{1FAD}'),
    ('\u{1FA6}', '\u{1FAE}'),
    ('\u{1FA7}', '\u{1FAF}'),
    ('\u{1FB3}', '\u{1FBC}'),
    ('\u{1FC3}', '\u{1FCC}'),
    ('\u{1FF3}', '\u{1FFC}'),
];

fn simple_upper_exception(c: char) -> Option<char> {
    SIMPLE_UPPER_EXCEPTIONS
        .binary_search_by_key(&c, |&(from, _)| from)
        .ok()
        .and_then(|i| SIMPLE_UPPER_EXCEPTIONS.get(i))
        .map(|&(_, to)| to)
}

// ---------------------------------------------------------------------------
// The result.

impl NormalizedPath {
    /// The root.
    #[must_use]
    pub fn root(&self) -> &Root {
        &self.root
    }

    /// The components after the root, as written (case kept).
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// The named stream, if the path names one.
    #[must_use]
    pub fn stream(&self) -> Option<&Stream> {
        self.stream.as_ref()
    }

    /// How the path was written.
    #[must_use]
    pub fn notes(&self) -> &PathNotes {
        &self.notes
    }

    /// The last component, if any.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    /// Indexes of components that may be unexpanded 8.3 short names.
    #[must_use]
    pub fn short_name_candidates(&self) -> &[usize] {
        match &self.short_names {
            ShortNames::Candidates(c) => c,
            ShortNames::Verified => &[],
        }
    }

    /// True if the path is on a volume shadow copy.
    #[must_use]
    pub fn is_shadow_copy(&self) -> bool {
        self.notes.is_shadow_copy
    }

    /// True if the Win32 form is longer than [`LEGACY_MAX_PATH`].
    #[must_use]
    pub fn is_long(&self) -> bool {
        self.to_win32_string().encode_utf16().count() > LEGACY_MAX_PATH
    }

    /// The path to the directory that contains this one, without a stream.
    /// `None` at the root.
    ///
    /// The parent can need a longer canonical form than the path itself: in
    /// `C:\…\dir \x`, the space in `dir ` is kept, so once `dir ` is the
    /// last component the literal `\\?\` form is needed to name it. A parent
    /// whose canonical form would exceed [`MAX_PATH_UNITS`] is
    /// `Some(Err(PathError::TooLong))`, never a path that does not re-parse.
    /// Such a folder still exists; a caller that needs its ACL must treat it
    /// as unreadable.
    #[must_use]
    pub fn parent(&self) -> Option<Result<Self, PathError>> {
        let n = self.components.len().checked_sub(1)?;
        Some(self.checked_prefix_of(n))
    }

    /// Every ancestor directory, immediate parent first and the root last:
    /// the folders whose ACLs a writability check must read.
    ///
    /// The ancestors are built one at a time, so a caller that stops early
    /// does not pay for the rest. An ancestor whose canonical form would be
    /// too long is an `Err` item, as for [`Self::parent`], and the
    /// traversal goes on to the shorter ones.
    pub fn ancestors(&self) -> impl Iterator<Item = Result<Self, PathError>> + '_ {
        (0..self.components.len())
            .rev()
            .map(|n| self.checked_prefix_of(n))
    }

    /// [`Self::prefix_of`], rejecting a result that is too long to re-parse.
    fn checked_prefix_of(&self, n: usize) -> Result<Self, PathError> {
        let prefix = self.prefix_of(n);
        prefix.check_length()?;
        Ok(prefix)
    }

    /// Fails if the canonical form is longer than [`MAX_PATH_UNITS`].
    fn check_length(&self) -> Result<(), PathError> {
        if self
            .to_win32_string()
            .encode_utf16()
            .nth(MAX_PATH_UNITS)
            .is_some()
        {
            return Err(PathError::TooLong);
        }
        Ok(())
    }

    /// The first `n` components, with no stream.
    fn prefix_of(&self, n: usize) -> Self {
        let components: Vec<String> = self.components.iter().take(n).cloned().collect();
        let short_names = match &self.short_names {
            ShortNames::Candidates(c) => {
                let kept: Vec<usize> = c.iter().copied().filter(|i| *i < n).collect();
                if kept.is_empty() {
                    ShortNames::Verified
                } else {
                    ShortNames::Candidates(kept)
                }
            }
            ShortNames::Verified => ShortNames::Verified,
        };
        Self {
            root: self.root.clone(),
            components,
            stream: None,
            notes: PathNotes {
                default_stream_suffix: false,
                directory_stream_suffix: false,
                trimmed: false,
                ..self.notes.clone()
            },
            short_names,
        }
    }

    /// Expands short-name candidates through `resolver`, left to right, so
    /// each lookup sees a parent whose earlier components are already long.
    /// Candidates the resolver cannot expand stay unresolved.
    ///
    /// Long names can make the path longer than [`MAX_PATH_UNITS`]. Then
    /// nothing is changed, every candidate stays unresolved, and the result
    /// is [`PathError::TooLong`].
    pub fn resolve_short_names(
        &mut self,
        resolver: &dyn ShortNameResolver,
    ) -> Result<(), PathError> {
        let ShortNames::Candidates(candidates) = &self.short_names else {
            return Ok(());
        };
        let original = self.clone();
        let candidates = candidates.clone();
        let mut unresolved = Vec::new();
        for i in candidates {
            if !unresolved.is_empty() {
                // An ancestor is still unexpanded, so later lookups would
                // run against a parent that is not known to be long.
                unresolved.push(i);
                continue;
            }
            let parent = Self {
                short_names: ShortNames::Verified,
                ..self.prefix_of(i)
            };
            let Some(current) = self.components.get(i) else {
                continue;
            };
            match resolver.long_name(&parent, current) {
                Some(long) if is_plain_name(&long) => {
                    if let Some(slot) = self.components.get_mut(i) {
                        *slot = long;
                    }
                }
                _ => unresolved.push(i),
            }
        }
        self.short_names = if unresolved.is_empty() {
            ShortNames::Verified
        } else {
            ShortNames::Candidates(unresolved)
        };
        if let Err(e) = self.check_length() {
            *self = original;
            return Err(e);
        }
        Ok(())
    }

    /// Marks every component as a long name. Only for paths taken from the
    /// OS's normalised final path, which never contains short names.
    #[cfg(all(windows, feature = "os-trust"))]
    pub(crate) fn mark_long_names_verified(&mut self) {
        self.short_names = ShortNames::Verified;
    }

    /// The path in Win32 syntax. Drive and UNC paths use the plain form
    /// (`C:\Dir\file.exe`) unless a component would be changed by Win32
    /// normalisation, in which case the literal `\\?\` form is used. Other
    /// roots always use a `\\?\` form. Normalising the result with
    /// [`normalize_win32`] gives this path back.
    #[must_use]
    pub fn to_win32_string(&self) -> String {
        let mut tail = self.components.join("\\");
        if let Some(s) = &self.stream {
            tail.push(':');
            tail.push_str(&s.name);
            if s.kind != "$DATA" {
                tail.push(':');
                tail.push_str(&s.kind);
            }
        }
        match &self.root {
            Root::Drive(d) => {
                if self.needs_literal(true) {
                    format!(r"\\?\{d}:\{tail}")
                } else {
                    format!(r"{d}:\{tail}")
                }
            }
            Root::Unc { server, share } => {
                let sep = if tail.is_empty() { "" } else { "\\" };
                if self.needs_literal(false) {
                    format!(r"\\?\UNC\{server}\{share}{sep}{tail}")
                } else {
                    format!(r"\\{server}\{share}{sep}{tail}")
                }
            }
            Root::VolumeGuid(g) => format!(r"\\?\Volume{g}\{tail}"),
            Root::NtDevice(d) => format!(r"\\?\GLOBALROOT\Device\{d}\{tail}"),
            Root::DosDevice(d) => format!(r"\\?\{d}\{tail}"),
        }
    }

    /// True if Win32 normalisation would change some component.
    fn needs_literal(&self, drive: bool) -> bool {
        let n = self.components.len();
        let mut last_full = self.components.last().cloned().unwrap_or_default();
        if let Some(s) = &self.stream {
            last_full.push(':');
            last_full.push_str(&s.name);
            if s.kind != "$DATA" {
                last_full.push(':');
                last_full.push_str(&s.kind);
            }
        }
        let intermediate_changes = self
            .components
            .iter()
            .take(n.saturating_sub(1))
            .any(|c| c.contains('/') || c.ends_with('.'));
        let last_changes = n > 0
            && (last_full.contains('/')
                || last_full.ends_with('.')
                || last_full.ends_with(' ')
                || (drive
                    && self
                        .components
                        .last()
                        .is_some_and(|c| is_reserved_device_name(c))));
        intermediate_changes || last_changes
    }

    /// The case-folded key form: the root, then each component folded with
    /// [`fold_case`], then the stream. Two paths have the same folded form
    /// exactly when they name the same entry under NTFS comparison rules,
    /// given the same root.
    ///
    /// It is built from the parts, not from [`Self::to_win32_string`],
    /// because whether that adds the literal `\\?\` prefix depends on the
    /// spelling (the reserved-name check is ASCII-only), and two spellings
    /// that fold alike must give one key. For a plain drive or UNC path it
    /// is the upper-cased Win32 form (`C:\WINDOWS\CMD.EXE`). It is a key,
    /// not a path to open.
    ///
    /// Per-directory case sensitivity is not modelled: every component is
    /// folded (see the module documentation).
    #[must_use]
    pub fn case_folded(&self) -> String {
        let mut key = root_key(&self.root);
        let unc = matches!(self.root, Root::Unc { .. });
        if !(unc && self.components.is_empty()) {
            key.push('\\');
        }
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                key.push('\\');
            }
            key.push_str(&fold_case(c));
        }
        if let Some(s) = &self.stream {
            key.push(':');
            key.push_str(&fold_case(&s.name));
            if s.kind != "$DATA" {
                key.push(':');
                key.push_str(&s.kind);
            }
        }
        key
    }

    /// Fails with [`PathError::UnresolvedShortName`] if some component may
    /// still be an unexpanded 8.3 short name.
    pub fn require_long_names(&self) -> Result<(), PathError> {
        if let Some(i) = self.short_name_candidates().first() {
            let name = self.components.get(*i).cloned().unwrap_or_default();
            return Err(PathError::UnresolvedShortName(name));
        }
        Ok(())
    }

    /// The key to match path rules against: [`Self::case_folded`], but only
    /// once every short-name candidate has been expanded.
    pub fn match_key(&self) -> Result<String, PathError> {
        self.require_long_names()?;
        Ok(self.case_folded())
    }

    /// True if `prefix` is this path or a directory above it: same root,
    /// and its components are a leading run of these components, compared
    /// case-insensitively. A prefix with a stream never matches.
    #[must_use]
    pub fn starts_with(&self, prefix: &Self) -> bool {
        prefix.stream.is_none()
            && root_key(&self.root) == root_key(&prefix.root)
            && prefix.components.len() <= self.components.len()
            && prefix
                .components
                .iter()
                .zip(&self.components)
                .all(|(a, b)| fold_case(a) == fold_case(b))
    }
}

fn root_key(root: &Root) -> String {
    match root {
        Root::Drive(d) => format!("{d}:"),
        Root::Unc { server, share } => fold_case(&format!(r"\\{server}\{share}")),
        Root::VolumeGuid(g) => format!("VOLUME{g}"),
        Root::NtDevice(d) => fold_case(&format!(r"\DEVICE\{d}")),
        Root::DosDevice(d) => fold_case(&format!(r"\\.\{d}")),
    }
}

/// A name a resolver may return: non-empty, no separators or colon, and
/// not `.` or `..`.
fn is_plain_name(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['\\', '/', ':', '\0'])
}

impl fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_win32_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> String {
        normalize_win32(s).unwrap().to_win32_string()
    }

    fn key(s: &str) -> String {
        normalize_win32(s).unwrap().case_folded()
    }

    #[test]
    fn plain_drive_paths() {
        assert_eq!(
            w(r"C:\Windows\System32\cmd.exe"),
            r"C:\Windows\System32\cmd.exe"
        );
        assert_eq!(w(r"c:\windows"), r"C:\windows");
        assert_eq!(w(r"C:\"), r"C:\");
        assert_eq!(
            w(r"C:/Windows//System32\\\cmd.exe"),
            r"C:\Windows\System32\cmd.exe"
        );
    }

    #[test]
    fn dot_segments() {
        assert_eq!(w(r"C:\a\.\b\..\c"), r"C:\a\c");
        assert_eq!(w(r"C:\..\..\a"), r"C:\a");
        assert_eq!(w(r"C:\a\b\.."), r"C:\a");
        assert_eq!(w(r"C:\a\."), r"C:\a");
        // `...` loses one dot when followed by a separator and becomes `..`,
        // which is not evaluated and cannot name a file.
        assert!(matches!(
            normalize_win32(r"C:\a\...\b"),
            Err(PathError::InvalidComponent(_))
        ));
        // As the last component it loses all its dots.
        assert_eq!(w(r"C:\a\..."), r"C:\a");
    }

    #[test]
    fn trailing_dots_and_spaces() {
        assert_eq!(w(r"C:\dir\cmd.exe. . "), r"C:\dir\cmd.exe");
        assert!(normalize_win32(r"C:\dir\cmd.exe.").unwrap().notes().trimmed);
        // One dot is removed from a component followed by a separator.
        assert_eq!(
            w(r"C:\Windows.\System32\cmd.exe"),
            r"C:\Windows\System32\cmd.exe"
        );
        // A trailing space before a separator is kept, so the literal form
        // is needed to name it again.
        assert_eq!(w(r"C:\dir \x"), r"C:\dir \x");
        assert_eq!(w(r"C:\dir. \"), r"\\?\C:\dir. ");
        // The final trim reaches back through `\.` and `\..`.
        assert_eq!(w(r"C:\dir. \."), r"C:\dir");
        assert_eq!(w(r"C:\dir. \x\.."), r"C:\dir");
    }

    #[test]
    fn literal_paths_are_not_normalised() {
        let p = normalize_win32(r"\\?\C:\dir\cmd.exe.").unwrap();
        assert_eq!(p.components(), [r"dir", "cmd.exe."]);
        assert_eq!(p.to_win32_string(), r"\\?\C:\dir\cmd.exe.");
        assert_ne!(p.case_folded(), key(r"C:\dir\cmd.exe"));
        assert_eq!(key(r"\\?\C:\dir\cmd.exe"), key(r"c:\DIR\CMD.EXE"));
        assert_eq!(key(r"\??\C:\dir\cmd.exe"), key(r"C:\dir\cmd.exe"));
        for bad in [r"\\?\C:\a\..\b", r"\\?\C:\a\.\b", r"\\?\C:\a\\b", r"\\?\"] {
            assert!(normalize_win32(bad).is_err(), "{bad}");
        }
        // Forward slashes are literal characters here.
        assert_eq!(
            normalize_win32(r"\\?\C:\a/b").unwrap().components(),
            ["a/b"]
        );
    }

    #[test]
    fn device_paths_are_normalised() {
        assert_eq!(key(r"\\.\C:\a\..\b"), key(r"C:\b"));
        assert_eq!(key(r"//?/C:/a/b."), key(r"C:\a\b"));
        // Nothing is protected: `..` can remove the device itself.
        assert_eq!(key(r"\\.\X:\..\C:\a"), key(r"C:\a"));
        assert_eq!(normalize_win32(r"\\.\C:\").unwrap().components().len(), 0);
        assert_eq!(normalize_win32(r"\\.\C:\.").unwrap().components().len(), 0);
        assert_eq!(
            normalize_win32(r"\\.\C:\a\..").unwrap().components().len(),
            0
        );
        for volume in [
            r"\\.\GLOBALROOT\Device\HarddiskVolume3",
            r"//?/GLOBALROOT/Device/HarddiskVolume3",
            r"\\.\GLOBALROOT\??\C:",
            r"\\.\.\C:",
            r"\\.\X:\..\C:",
        ] {
            assert_eq!(
                normalize_win32(volume),
                Err(PathError::DeviceNotDirectory),
                "{volume}"
            );
        }
        assert!(normalize_win32(r"\\.\GLOBALROOT\Device\HarddiskVolume3\").is_ok());
        // Streams on device paths.
        for (dev, plain) in [
            (r"\\.\C:\dir\file.txt:evil.exe", r"C:\dir\file.txt:evil.exe"),
            (r"//?/C:/file.txt:evil.exe", r"C:\file.txt:evil.exe"),
            (r"\\.\UNC\server\share\f.txt:s", r"\\server\share\f.txt:s"),
        ] {
            let p = normalize_win32(dev).unwrap();
            assert!(p.stream().is_some(), "{dev}");
            assert_eq!(p.case_folded(), key(plain));
        }
        assert_eq!(
            normalize_win32(r"\\.\C:"),
            Err(PathError::DeviceNotDirectory)
        );
        assert_eq!(
            normalize_win32(r"\\?\C:"),
            Err(PathError::DeviceNotDirectory)
        );
        assert_eq!(
            normalize_win32(r"\\.\pipe\name").unwrap().root(),
            &Root::DosDevice("pipe".into())
        );
    }

    #[test]
    fn unc_paths() {
        let p = normalize_win32(r"\\Server\Share\a\..\..\..\b").unwrap();
        assert_eq!(
            p.root(),
            &Root::Unc {
                server: "Server".into(),
                share: "Share".into()
            }
        );
        assert_eq!(p.to_win32_string(), r"\\Server\Share\b");
        assert_eq!(key(r"\\?\UNC\server\share\b"), key(r"\\SERVER\share\B"));
        assert_eq!(key(r"\\.\UNC\server\share\b"), key(r"\\server\share\b"));
        assert_eq!(key(r"//server/share/b"), key(r"\\server\share\b"));
        assert_eq!(normalize_win32(r"\\server"), Err(PathError::MissingShare));
        for bad in [
            r"\\server.\share\x",
            r"\\server\share \x",
            r"\\server\..\x",
            r"\\\?\share\x",
            r"\\\.\share\x",
            r"\\?\UNC\server.\share\x",
            r"\\?\UNC\server\share \x",
            r"\\?\UNC\srv/a\share\x",
            r"\\.\UNC\server.\share\x",
            r"\\.\UNC\server \share\x",
            r"\\.\unc\server\share.\x",
            r"\\.\.\UNC\server.\share\x",
            r"\\.\UNC.\server.\share\x",
            r"\\.\X\..\UNC\server.\share\x",
            r"\\.\UNC\a\b\..\..\server.\share\x",
            r"\\.\.\UNC\server\share ",
            r"\\.\GLOBALROOT\Device\Mup\server.\share\x",
        ] {
            assert!(
                matches!(normalize_win32(bad), Err(PathError::InvalidComponent(_))),
                "{bad}"
            );
        }
        assert_eq!(
            normalize_win32(r"\\server\share")
                .unwrap()
                .to_win32_string(),
            r"\\server\share"
        );
        assert!(
            normalize_win32(r"\\localhost\c$\x")
                .unwrap()
                .notes()
                .loopback_server
        );
        assert!(
            normalize_win32(r"\\127.0.0.1\c$\x")
                .unwrap()
                .notes()
                .loopback_server
        );
        assert!(
            !normalize_win32(r"\\127.0.0.1x\c$\x")
                .unwrap()
                .notes()
                .loopback_server
        );
        // UNC paths do not name reserved devices.
        assert!(normalize_win32(r"\\server\share\CON").is_ok());
    }

    #[test]
    fn volume_and_nt_paths() {
        let g = r"\\?\Volume{B75E2C83-0000-0000-0000-602F00000000}\Dir\f.exe";
        let p = normalize_win32(g).unwrap();
        assert_eq!(
            p.root(),
            &Root::VolumeGuid("{b75e2c83-0000-0000-0000-602f00000000}".into())
        );
        assert_eq!(normalize_win32(&p.to_win32_string()).unwrap(), p);

        let nt = normalize_nt(r"\Device\HarddiskVolume3\Windows\x.exe").unwrap();
        assert_eq!(nt.root(), &Root::NtDevice("HarddiskVolume3".into()));
        let via_globalroot =
            normalize_win32(r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\x.exe").unwrap();
        assert_eq!(nt.case_folded(), via_globalroot.case_folded());
        let via_dos = normalize_win32(r"\\.\HarddiskVolume3\Windows\x.exe").unwrap();
        assert_eq!(nt.case_folded(), via_dos.case_folded());

        assert_eq!(
            normalize_nt(r"\??\C:\x").unwrap().case_folded(),
            key(r"C:\x")
        );
        assert_eq!(
            normalize_nt(r"\GLOBAL??\C:\x").unwrap().case_folded(),
            key(r"C:\x")
        );
        assert_eq!(
            normalize_nt(r"\Device\Mup\server\share\x")
                .unwrap()
                .case_folded(),
            key(r"\\server\share\x")
        );
        assert_eq!(
            normalize_nt(r"\Device\Mup\;LanmanRedirector\;Z:000000000001a2b3\server\share\x")
                .unwrap()
                .case_folded(),
            key(r"\\server\share\x")
        );
        for bad in [
            r"\Device\Mup\server.\share\x",
            r"\Device\Mup\server\share \x",
            r"\Device\Mup\srv/a\share\x",
        ] {
            assert!(
                matches!(normalize_nt(bad), Err(PathError::InvalidComponent(_))),
                "{bad}"
            );
        }
        assert!(matches!(
            normalize_nt(r"\SystemRoot\System32\x.sys"),
            Err(PathError::UnsupportedNtPath(_))
        ));
        assert_eq!(
            normalize_nt(r"\Device\HarddiskVolume3"),
            Err(PathError::DeviceNotDirectory)
        );
        assert!(normalize_nt(r"\Device\HarddiskVolume3\").is_ok());
        let shadow = normalize_nt(r"\Device\HarddiskVolumeShadowCopy2\Windows\x.exe").unwrap();
        assert!(shadow.is_shadow_copy());
        assert!(
            normalize_win32(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\x")
                .unwrap()
                .is_shadow_copy()
        );
        // Nesting is bounded.
        let deep = format!(r"\\?\{}C:\x", r"GLOBALROOT\??\".repeat(20));
        assert!(normalize_win32(&deep).is_err());
    }

    #[test]
    fn not_fully_qualified() {
        for p in [r"dir\file", r"\dir\file", r"C:dir", "C:", r"..\x", "file"] {
            assert_eq!(normalize_win32(p), Err(PathError::NotFullyQualified), "{p}");
        }
        assert_eq!(normalize_win32(r"1:\x"), Err(PathError::InvalidDrive));
        assert_eq!(normalize_win32(""), Err(PathError::Empty));
        assert_eq!(normalize_win32("C:\\a\0b"), Err(PathError::Nul));
        assert_eq!(normalize_nt(r"Device\x"), Err(PathError::NotFullyQualified));
    }

    #[test]
    fn length_limit() {
        let ok = format!(r"C:\{}", "a".repeat(MAX_PATH_UNITS - 3));
        let p = normalize_win32(&ok).unwrap();
        assert!(p.is_long());
        let too_long = format!(r"C:\{}", "a".repeat(MAX_PATH_UNITS - 2));
        assert_eq!(normalize_win32(&too_long), Err(PathError::TooLong));
        // An input within the limit whose canonical form is not.
        let nt = format!(
            r"\Device\HarddiskVolume3\{}",
            "a".repeat(MAX_PATH_UNITS - 30)
        );
        assert_eq!(normalize_nt(&nt), Err(PathError::TooLong));
        let spaced = format!(r"C:\{}. \", "a".repeat(MAX_PATH_UNITS - 6));
        assert_eq!(normalize_win32(&spaced), Err(PathError::TooLong));
    }

    #[test]
    fn streams() {
        let p = normalize_win32(r"C:\dir\file.txt:evil.exe").unwrap();
        assert_eq!(p.file_name(), Some("file.txt"));
        assert_eq!(
            p.stream(),
            Some(&Stream {
                name: "evil.exe".into(),
                kind: "$DATA".into()
            })
        );
        assert_ne!(p.case_folded(), key(r"C:\dir\file.txt"));
        assert_eq!(p.case_folded(), key(r"C:\dir\file.txt:evil.exe:$data"));

        let d = normalize_win32(r"C:\dir\file.exe::$DATA").unwrap();
        assert!(d.notes().default_stream_suffix);
        assert_eq!(d.case_folded(), key(r"C:\dir\file.exe"));

        let i = normalize_win32(r"C:\Windows\Tasks::$INDEX_ALLOCATION\x.exe").unwrap();
        assert!(i.notes().directory_stream_suffix);
        assert_eq!(i.case_folded(), key(r"C:\Windows\Tasks\x.exe"));
        assert_eq!(
            key(r"C:\Windows\Tasks:$I30:$INDEX_ALLOCATION"),
            key(r"C:\Windows\Tasks")
        );
        // A trailing dot on the stream name is trimmed like any other.
        assert_eq!(key(r"C:\f.txt:s."), key(r"C:\f.txt:s"));

        for bad in [
            r"C:\dir\f:a:b:c",
            r"C:\dir\f:",
            r"C:\dir\:s",
            r"C:\dir\f:s:DATA",
            r"C:\dir:s\f",
            r"C:\dir:$I30\f",
        ] {
            assert!(normalize_win32(bad).is_err(), "{bad}");
        }
        let typed = normalize_win32(r"C:\f::$EA").unwrap();
        assert_eq!(typed.stream().unwrap().kind, "$EA");
        assert_eq!(normalize_win32(&typed.to_win32_string()).unwrap(), typed);
    }

    #[test]
    fn reserved_device_names() {
        for p in [
            r"C:\dir\CON",
            r"C:\dir\nul.txt",
            r"C:\dir\COM1:x",
            r"C:\dir\lpt9  .log",
            "C:\\dir\\COM\u{b9}",
            r"C:\dir\CONIN$",
        ] {
            assert!(
                matches!(normalize_win32(p), Err(PathError::ReservedDeviceName(_))),
                "{p}"
            );
        }
        // Only the last component, and not in literal paths.
        assert!(normalize_win32(r"C:\CON\x").is_ok());
        assert!(normalize_win32(r"C:\CONSOLE").is_ok());
        assert!(normalize_win32(r"C:\COM10").is_ok());
        let lit = normalize_win32(r"\\?\C:\dir\CON").unwrap();
        assert_eq!(lit.to_win32_string(), r"\\?\C:\dir\CON");
    }

    #[test]
    fn case_folding() {
        assert_eq!(fold_case("Straße.exe"), "STRAßE.EXE");
        assert_eq!(fold_case("ǆ"), "Ǆ");
        assert_eq!(fold_case("ﬁ"), "ﬁ");
        assert_eq!(fold_case("é"), "É");
        // Supplementary-plane letters are not folded, as on NTFS.
        assert_eq!(fold_case("\u{10428}"), "\u{10428}");
        // A full mapping of two characters, but a one-unit simple mapping.
        assert_eq!(fold_case("\u{1F80}"), "\u{1F88}");
        assert_eq!(fold_case("\u{1FF3}"), "\u{1FFC}");
        assert_eq!(key("C:\\\u{1F80}.exe"), key("C:\\\u{1F88}.EXE"));
        // No simple mapping: unchanged.
        assert_eq!(fold_case("\u{149}"), "\u{149}");
        assert!(SIMPLE_UPPER_EXCEPTIONS.windows(2).all(|w| w[0].0 < w[1].0));
        for (from, to) in SIMPLE_UPPER_EXCEPTIONS {
            assert!(from.to_uppercase().count() > 1, "{from:?}");
            assert_eq!(from.len_utf16(), 1);
            assert_eq!(to.len_utf16(), 1);
        }
        assert_eq!(key(r"C:\Ünïcode\Ä.exe"), key(r"c:\üNÏCODE\ä.EXE"));
    }

    struct Table;

    impl ShortNameResolver for Table {
        fn long_name(&self, parent: &NormalizedPath, name: &str) -> Option<String> {
            match (parent.to_win32_string().as_str(), name) {
                (r"C:\", "PROGRA~1") => Some("Program Files".into()),
                (r"C:\Program Files", "MYAPP~1") => Some("My Application".into()),
                (r"C:\Program Files", "bad~1") => Some(r"..\x".into()),
                _ => None,
            }
        }
    }

    #[test]
    fn short_names() {
        assert!(is_short_name_candidate("PROGRA~1"));
        assert!(is_short_name_candidate("progra~1"));
        assert!(is_short_name_candidate("AB12C~10.TXT"));
        assert!(!is_short_name_candidate("Program Files"));
        assert!(!is_short_name_candidate("README.TXT"));
        assert!(!is_short_name_candidate("LONGNAME~1"));
        assert!(!is_short_name_candidate("ABC~1.TEXT"));
        // `~` is a legal 8.3 character in the extension too.
        assert!(is_short_name_candidate("PROGRA~1.X~1"));
        assert!(is_short_name_candidate("LONGNA~1.A~B"));

        let mut p = normalize_win32(r"C:\PROGRA~1\MYAPP~1\app.exe").unwrap();
        assert_eq!(p.short_name_candidates(), [0, 1]);
        assert!(matches!(
            p.match_key(),
            Err(PathError::UnresolvedShortName(_))
        ));
        p.resolve_short_names(&Table).unwrap();
        assert_eq!(
            p.match_key().unwrap(),
            key(r"C:\Program Files\My Application\app.exe")
        );

        let mut q = normalize_win32(r"C:\PROGRA~1\OTHER~1\app.exe").unwrap();
        q.resolve_short_names(&Table).unwrap();
        assert_eq!(q.short_name_candidates(), [1]);
        assert!(q.match_key().is_err());

        // Once an ancestor fails, its descendants are not looked up.
        let mut u = normalize_win32(r"C:\NOSUCH~1\PROGRA~1\x").unwrap();
        u.resolve_short_names(&Table).unwrap();
        assert_eq!(u.short_name_candidates(), [0, 1]);

        // A resolver answer that is not a plain name is ignored.
        let mut r = normalize_win32(r"C:\PROGRA~1\bad~1").unwrap();
        r.resolve_short_names(&Table).unwrap();
        assert_eq!(r.short_name_candidates(), [1]);
    }

    /// Expands `PROGRA~1` to a name long enough to overflow the limit.
    struct Overlong;

    impl ShortNameResolver for Overlong {
        fn long_name(&self, _parent: &NormalizedPath, name: &str) -> Option<String> {
            (name == "PROGRA~1").then(|| "P".repeat(MAX_PATH_UNITS))
        }
    }

    #[test]
    fn short_name_expansion_respects_the_length_limit() {
        let mut p = normalize_win32(r"C:\PROGRA~1\x.exe").unwrap();
        let before = p.clone();
        assert_eq!(p.resolve_short_names(&Overlong), Err(PathError::TooLong));
        // Nothing was installed, and the path is still unverified.
        assert_eq!(p, before);
        assert!(matches!(
            p.match_key(),
            Err(PathError::UnresolvedShortName(_))
        ));
    }

    /// `C:\` plus components of `a`s, then `dir \x`, exactly at the limit.
    fn path_at_limit_ending_in_spaced_dir() -> String {
        let mut s = String::from(r"C:\");
        let tail = r"dir \x";
        while s.len() + tail.len() < MAX_PATH_UNITS {
            let room = MAX_PATH_UNITS - s.len() - tail.len();
            let n = room.saturating_sub(1).clamp(1, 200);
            s.push_str(&"a".repeat(n));
            s.push('\\');
        }
        s.push_str(tail);
        s
    }

    #[test]
    fn over_limit_parent_is_reported() {
        let input = path_at_limit_ending_in_spaced_dir();
        assert_eq!(input.encode_utf16().count(), MAX_PATH_UNITS);
        let p = normalize_win32(&input).unwrap();
        // The parent ends in `dir `, which needs the four-unit literal
        // prefix, so it no longer fits.
        assert_eq!(p.parent(), Some(Err(PathError::TooLong)));
        let mut ancestors = p.ancestors();
        assert_eq!(ancestors.next(), Some(Err(PathError::TooLong)));
        // Shorter ancestors are still produced, and every one re-parses.
        let rest: Vec<NormalizedPath> = ancestors.map(Result::unwrap).collect();
        assert_eq!(
            rest.last().map(NormalizedPath::to_win32_string).as_deref(),
            Some(r"C:\")
        );
        for a in &rest {
            assert_eq!(normalize_win32(&a.to_win32_string()).as_ref(), Ok(a));
        }
    }

    #[test]
    fn ancestors_are_lazy() {
        let p = normalize_win32(r"C:\a\b\c\d").unwrap();
        let first: Vec<String> = p
            .ancestors()
            .take(1)
            .map(|a| a.unwrap().to_win32_string())
            .collect();
        assert_eq!(first, [r"C:\a\b\c"]);
    }

    #[test]
    fn match_key_ignores_the_display_prefix() {
        // U+0131 (dotless i) folds to `I`, so these name the same entry,
        // but only the ASCII spelling is a reserved name that needs the
        // literal prefix in its Win32 form.
        let ascii = normalize_win32(r"\\?\C:\CONIN$").unwrap();
        let dotless = normalize_win32("\\\\?\\C:\\CON\u{131}N$").unwrap();
        assert!(ascii.starts_with(&dotless) && dotless.starts_with(&ascii));
        assert_ne!(ascii.to_win32_string(), dotless.to_win32_string());
        assert_eq!(ascii.match_key(), dotless.match_key());
        assert_eq!(ascii.match_key().unwrap(), r"C:\CONIN$");
        // A literal path with a trailing dot keeps its own key.
        assert_ne!(key(r"\\?\C:\x.exe."), key(r"C:\x.exe"));
        // Keys for other roots.
        assert_eq!(key(r"\\srv\share"), r"\\SRV\SHARE");
        assert_eq!(key(r"\\srv\share\a"), r"\\SRV\SHARE\A");
        assert_eq!(key(r"C:\"), r"C:\");
        assert_eq!(key(r"C:\f.txt:s:$DATA"), r"C:\F.TXT:S");
        assert_eq!(key(r"C:\f.txt:s:$BITMAP"), r"C:\F.TXT:S:$BITMAP");
    }

    #[test]
    fn ancestors_and_prefixes() {
        let p = normalize_win32(r"C:\Program Files\App\app.exe:s").unwrap();
        let a: Vec<String> = p
            .ancestors()
            .map(|a| a.unwrap().to_win32_string())
            .collect();
        assert_eq!(a, [r"C:\Program Files\App", r"C:\Program Files", r"C:\"]);
        assert_eq!(
            p.parent().unwrap().unwrap().to_win32_string(),
            r"C:\Program Files\App"
        );
        assert!(normalize_win32(r"C:\").unwrap().parent().is_none());
        let pf = normalize_win32(r"c:\program files").unwrap();
        assert!(p.starts_with(&pf));
        assert!(!pf.starts_with(&p));
        assert!(
            !normalize_win32(r"C:\Program FilesX\a")
                .unwrap()
                .starts_with(&pf)
        );
        assert!(
            !normalize_win32(r"D:\Program Files\a")
                .unwrap()
                .starts_with(&pf)
        );
    }
}
