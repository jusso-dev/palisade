//! Lexical normalisation of Windows paths (#32).
//!
//! Facts and rule patterns both pass through [`normalize`], so two
//! spellings of one path compare equal. The rules, in order:
//!
//! 1. `/` becomes `\`.
//! 2. The `\\?\`, `\??\` and `\\.\` prefixes are removed. `\\?\UNC\server\share`
//!    becomes `\\server\share`, and `\\?\GLOBALROOT\Device\...` becomes
//!    `\Device\...`.
//! 3. An NT device path (`\Device\HarddiskVolume3\x`) becomes a drive path
//!    when a [`VolumeMap`] entry names its device. The device name must end
//!    at a separator, so `\Device\HarddiskVolume33` never matches an entry
//!    for `\Device\HarddiskVolume3`. An unmapped device path keeps
//!    [`PathKind::Device`].
//! 4. Repeated separators collapse, and a leading run of two or more
//!    becomes the two that start a UNC path. A trailing separator is
//!    removed, except after a drive root (`C:\`).
//! 5. In an absolute path, `.` components are removed, and `..` removes
//!    the component before it. `..` never climbs above the root (`C:\..\x`
//!    is `C:\x`), and never removes the server or share of a UNC path.
//!    Relative paths keep `.` and `..`.
//! 6. NTFS stream-type suffixes that name the object itself are removed:
//!    `::$DATA` (and `:name:$DATA` becomes `:name`) on the last component,
//!    and `::$INDEX_ALLOCATION` or `:$I30:$INDEX_ALLOCATION` on any
//!    component. A chain of them (`a::$INDEX_ALLOCATION::$DATA`) is
//!    removed whole. These spellings are the same object on disk, so
//!    leaving them would let a file escape a path rule. Removing them never
//!    turns a relative path into an absolute one: a `.` component is kept
//!    in front when the rest would read as a drive, device or NT prefix.
//! 7. The drive letter is upper-cased. Nothing else changes case: case
//!    folding is part of comparison, not of normalisation.
//!
//! Trailing dots and spaces are kept, because the file system keeps them
//! for names created through the `\\?\` prefix: `a.exe.` is not `a.exe`.
//! A named stream (`file.txt:payload`) is kept, and [`NormalizedPath::stream`]
//! reports it. Short (8.3) names are not expanded here: that needs the file
//! system, and the agent supplies the long path (#4).
//!
//! Normalisation is idempotent: normalising a normalised path gives the same
//! path.

use alloc::string::String;
use alloc::vec::Vec;

/// What a normalised path is rooted at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathKind {
    /// A drive-letter path: `C:\...`.
    Drive,
    /// A UNC path: `\\server\share\...`.
    Unc,
    /// An NT device or volume path that the volume map did not resolve,
    /// such as `\Device\HarddiskVolume9\x` or `\\?\Volume{...}\x`.
    Device,
    /// Not absolute: relative (`a\b`), drive-relative (`C:a`, or `C:`
    /// alone), or rooted on the current drive (`\a`). Also used for wildcard patterns such as
    /// `**\cmd.exe`.
    Relative,
}

/// Maps NT device names to drive letters, such as `\Device\HarddiskVolume3`
/// to `C:`. The agent builds it from the volume list (#4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeMap {
    /// `(device, drive)` pairs. Devices have no trailing separator.
    entries: Vec<(String, char)>,
}

impl VolumeMap {
    /// An empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a mapping from `device` (for example `\Device\HarddiskVolume3`)
    /// to `drive` (an ASCII letter). Returns `false`, and adds nothing, if
    /// the device does not start with `\Device\` or the drive is not an
    /// ASCII letter.
    pub fn insert(&mut self, device: &str, drive: char) -> bool {
        let device = device.replace('/', "\\");
        let device = device.trim_end_matches('\\');
        if !drive.is_ascii_alphabetic()
            || !starts_with_ignore_ascii_case(device, DEVICE_PREFIX)
            || device.len() <= DEVICE_PREFIX.len()
        {
            return false;
        }
        self.entries
            .push((String::from(device), drive.to_ascii_uppercase()));
        true
    }

    /// The drive for the device that `path` starts with, and the rest of
    /// the path after the device name.
    fn resolve<'a>(&self, path: &'a str) -> Option<(char, &'a str)> {
        self.entries.iter().find_map(|(device, drive)| {
            let rest = strip_prefix_ignore_ascii_case(path, device)?;
            (rest.is_empty() || rest.starts_with('\\')).then_some((*drive, rest))
        })
    }
}

/// A lexically normalised path. Build one with [`normalize`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NormalizedPath {
    text: String,
    kind: PathKind,
    /// The byte length of the root: `C:\`, `\\server\share`, or the device
    /// name. For relative paths, the `\` or `C:` they start with, if any.
    root_len: usize,
    /// The byte offset of the `:` that starts a named stream in the last
    /// component.
    stream: Option<usize>,
}

const DEVICE_PREFIX: &str = "\\Device\\";

/// Normalises `raw` without a volume map. See the [module docs](self).
#[must_use]
pub fn normalize(raw: &str) -> NormalizedPath {
    normalize_with(raw, &VolumeMap::new())
}

/// Normalises `raw`, resolving NT device paths through `volumes`. See the
/// [module docs](self).
///
/// One pass of the rules can uncover another spelling: resolving `.` or
/// `..` under `\\?\GLOBALROOT` can leave `\Device\...`, which the next
/// pass maps to a drive. The rules are therefore applied until the result
/// no longer changes, so the result is always a fixed point: normalising
/// it again gives the same text and kind.
///
/// A path that is not absolute stays [`PathKind::Relative`] in every pass:
/// a later pass never reads it as a drive, UNC or device path.
#[must_use]
pub fn normalize_with(raw: &str, volumes: &VolumeMap) -> NormalizedPath {
    let mut path = normalize_once(raw, volumes);
    // After the first pass, every pass that changes the path removes a
    // prefix or a component and so shortens it, so the text length bounds
    // the number of passes. In practice there are at most two.
    for _ in 0..path.text.len() {
        let next = normalize_once(&path.text, volumes);
        if next == path {
            break;
        }
        path = next;
    }
    path
}

/// One pass of the rules.
fn normalize_once(raw: &str, volumes: &VolumeMap) -> NormalizedPath {
    let s = collapse_separators(raw);

    if let Some(rest) = ["\\\\?\\", "\\??\\", "\\\\.\\"]
        .iter()
        .find_map(|p| s.strip_prefix(p))
    {
        if let Some(unc) = strip_prefix_ignore_ascii_case(rest, "UNC\\") {
            return unc_path(unc);
        }
        if let Some(path) = drive_path(rest) {
            return path;
        }
        if let Some(device) = strip_prefix_ignore_ascii_case(rest, "GLOBALROOT")
            && starts_with_ignore_ascii_case(device, DEVICE_PREFIX)
        {
            return device_path(device, volumes);
        }
        return opaque_device(rest);
    }
    if let Some(unc) = s.strip_prefix("\\\\") {
        return unc_path(unc);
    }
    if starts_with_ignore_ascii_case(&s, DEVICE_PREFIX) {
        return device_path(&s, volumes);
    }
    if let Some(path) = drive_path(&s) {
        return path;
    }
    relative_path(&s)
}

impl NormalizedPath {
    /// The normalised text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// What the path is rooted at.
    #[must_use]
    pub const fn kind(&self) -> PathKind {
        self.kind
    }

    /// Whether the path is a drive or UNC path, the only kinds that rules
    /// can be written against.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        matches!(self.kind, PathKind::Drive | PathKind::Unc)
    }

    /// The root: `C:\`, `\\server\share`, or a device name.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.text[..self.root_len]
    }

    /// The named stream, without its leading `:`, if the last component
    /// names one (`file.txt:payload` gives `payload`).
    #[must_use]
    pub fn stream(&self) -> Option<&str> {
        self.stream.map(|i| &self.text[i + 1..])
    }

    /// The path without its stream: the file or directory that holds the
    /// stream. A stream written after a separator (`C:\dir\:s`,
    /// `\\srv\share\:s`) belongs to the directory or root before it, so
    /// that separator is dropped too, except the one that is part of a drive
    /// root (`C:\:s` gives `C:\`).
    #[must_use]
    pub fn without_stream(&self) -> &str {
        &self.text[..self.file_end()]
    }

    /// The byte length of [`without_stream`](Self::without_stream).
    fn file_end(&self) -> usize {
        let Some(end) = self.stream else {
            return self.text.len();
        };
        if end > self.root_len && self.text[..end].ends_with('\\') {
            end - 1
        } else {
            end
        }
    }

    /// The byte offset where the last component of the file that holds the
    /// stream starts, if there is one after the root.
    fn last_component_start(&self) -> Option<usize> {
        let end = self.file_end();
        if end <= self.root_len {
            return None;
        }
        let body = &self.text[self.root_len..end];
        Some(self.root_len + body.rfind('\\').map_or(0, |i| i + 1))
    }

    /// The parent directory: everything before the last component. `None`
    /// for a bare root, and for a stream on a bare root (`C:\:s`).
    #[must_use]
    pub fn directory(&self) -> Option<&str> {
        let start = self.last_component_start()?;
        // A component directly under the root keeps the root as its
        // directory (`C:\`, `\\server\share`).
        let end = if start <= self.root_len + 1 {
            self.root_len
        } else {
            start - 1
        };
        Some(&self.text[..end])
    }

    /// The last component without its stream. `None` for a bare root, and
    /// for a stream on a bare root (`C:\:s`).
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        let start = self.last_component_start()?;
        Some(&self.text[start..self.file_end()])
    }

    /// The text after the last `.` of [`file_name`](Self::file_name), if it
    /// is not empty. `a.tar.gz` gives `gz`; `a.` and `a` give `None`.
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        let name = self.file_name()?;
        let ext = &name[name.rfind('.')? + 1..];
        (!ext.is_empty()).then_some(ext)
    }
}

impl core::fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// `C:\` and what follows, as a drive path. A bare `C:` is relative to the
/// current directory of that drive, so it is not a drive path.
fn drive_path(s: &str) -> Option<NormalizedPath> {
    let mut chars = s.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    if chars.next() != Some(':') {
        return None;
    }
    let rest = &s[2..];
    if !rest.starts_with('\\') {
        return None;
    }
    let mut text = String::with_capacity(s.len());
    text.push(letter.to_ascii_uppercase());
    text.push_str(":\\");
    Some(finish(text, 3, PathKind::Drive, &components(rest, true)))
}

/// `server\share\rest`, after the two leading separators.
///
/// A server of `.`, `..`, `?` or `??`, or none at all, does not name a
/// server, and a share of `.` or `..` does not name a share: the path
/// stays unresolved, in the `\\?\UNC\` form, which normalises to itself.
fn unc_path(body: &str) -> NormalizedPath {
    let (server, after) = split_component(body.trim_start_matches('\\'));
    if matches!(server, "" | "." | ".." | "?" | "??") {
        let mut text = String::from("\\\\?\\UNC");
        if !server.is_empty() {
            text.push('\\');
            text.push_str(server);
        }
        let root_len = text.len();
        return finish(text, root_len, PathKind::Device, &components(after, true));
    }
    let (share, rest) = split_component(after.trim_start_matches('\\'));
    // A share of `.` or `..` would be resolved away on a second pass, so
    // it does not name a share either.
    if matches!(share, "." | "..") {
        let mut text = String::from("\\\\?\\UNC\\");
        text.push_str(server);
        text.push('\\');
        text.push_str(share);
        let root_len = text.len();
        return finish(text, root_len, PathKind::Device, &components(rest, true));
    }
    let mut text = String::with_capacity(body.len() + 2);
    text.push_str("\\\\");
    text.push_str(server);
    if !share.is_empty() {
        text.push('\\');
        text.push_str(share);
    }
    let root_len = text.len();
    finish(text, root_len, PathKind::Unc, &components(rest, true))
}

/// Splits off the first component: the text before the first `\`, and the
/// rest from that `\` on.
fn split_component(s: &str) -> (&str, &str) {
    s.split_at(s.find('\\').unwrap_or(s.len()))
}

/// `\Device\Name\rest`, resolved through the volume map when possible.
fn device_path(s: &str, volumes: &VolumeMap) -> NormalizedPath {
    if let Some((drive, rest)) = volumes.resolve(s) {
        let mut text = String::with_capacity(rest.len() + 3);
        text.push(drive);
        text.push_str(":\\");
        return finish(text, 3, PathKind::Drive, &components(rest, true));
    }
    // The root is `\Device\Name`.
    let after = &s[DEVICE_PREFIX.len()..];
    let name_len = after.find('\\').unwrap_or(after.len());
    let mut text = String::from(DEVICE_PREFIX);
    text.push_str(&after[..name_len]);
    let root_len = text.len();
    finish(
        text,
        root_len,
        PathKind::Device,
        &components(&after[name_len..], true),
    )
}

/// A `\\?\` path that names neither a drive, a UNC share nor a device, such
/// as `\\?\Volume{...}\x`. `rest` is the text after the prefix.
fn opaque_device(rest: &str) -> NormalizedPath {
    let rest = rest.trim_start_matches('\\');
    let name_len = rest.find('\\').unwrap_or(rest.len());
    let mut text = String::from("\\\\?\\");
    text.push_str(&rest[..name_len]);
    let root_len = text.len();
    finish(
        text,
        root_len,
        PathKind::Device,
        &components(&rest[name_len..], true),
    )
}

/// A path that is not absolute. A leading `\` or `C:` is kept as its root.
/// `.` and `..` are kept, because they cannot be resolved without a base.
fn relative_path(s: &str) -> NormalizedPath {
    let (root, rest) = if s.starts_with('\\') {
        ("\\", s.trim_start_matches('\\'))
    } else if s.len() >= 2 && s.as_bytes()[0].is_ascii_alphabetic() && s.as_bytes()[1] == b':' {
        (&s[..2], &s[2..])
    } else {
        ("", s)
    };
    let mut text = String::with_capacity(s.len() + 2);
    if root.len() == 2 {
        text.push(char::from(root.as_bytes()[0].to_ascii_uppercase()));
        text.push(':');
    } else {
        text.push_str(root);
    }
    let mut parts = components(rest, false);
    // Removing a stream type can change what the first component reads as.
    // If the result would read back as a drive (`a:b`), a device path
    // (`\Device\x`) or an NT prefix (`\??\x`), keep a `.` before it, so a
    // relative path never becomes an absolute one on a later pass.
    let reads_as_prefix = match (root, parts.first()) {
        ("", Some(p)) => {
            p.len() >= 2 && p.as_bytes()[0].is_ascii_alphabetic() && p.as_bytes()[1] == b':'
        }
        ("\\", Some(p)) => parts.len() >= 2 && (p.eq_ignore_ascii_case("Device") || p == "??"),
        _ => false,
    };
    if reads_as_prefix {
        parts.insert(0, String::from("."));
    }
    let root_len = text.len();
    finish(text, root_len, PathKind::Relative, &parts)
}

/// Splits `rest` into components and removes stream-type suffixes. With
/// `resolve`, `.` is removed and `..` removes the component before it, and
/// never climbs above the root.
fn components(rest: &str, resolve: bool) -> Vec<String> {
    let mut parts: Vec<String> = rest
        .split('\\')
        .filter(|p| !p.is_empty())
        .map(strip_index_type)
        .collect();
    // Which component is last is only known once `.` and `..` are
    // resolved, and removing `::$DATA` from it can leave an empty, `.` or
    // `..` component to resolve, so repeat until nothing changes.
    loop {
        let mut out: Vec<String> = Vec::with_capacity(parts.len());
        for part in parts {
            match part.as_str() {
                "" => {}
                "." if resolve => {}
                ".." if resolve => {
                    out.pop();
                }
                _ => out.push(part),
            }
        }
        match out.last_mut().map(strip_last_types) {
            Some(true) => parts = out,
            _ => return out,
        }
    }
}

/// Removes `::$INDEX_ALLOCATION` and `:$I30:$INDEX_ALLOCATION`, which name
/// a directory itself, repeatedly.
fn strip_index_type(part: &str) -> String {
    const INDEX: [&str; 2] = ["::$INDEX_ALLOCATION", ":$I30:$INDEX_ALLOCATION"];
    let mut part = part;
    while let Some(p) = INDEX
        .iter()
        .find_map(|suffix| strip_suffix_ignore_ascii_case(part, suffix))
    {
        part = p;
    }
    String::from(part)
}

/// Removes every stream type from the end of the last component, in any
/// order and any number (`a::$INDEX_ALLOCATION::$DATA`), so one pass
/// removes the whole chain. Returns whether anything was removed.
fn strip_last_types(part: &mut String) -> bool {
    let before = part.len();
    loop {
        let len = part.len();
        let index = strip_index_type(part);
        if index.len() < part.len() {
            *part = index;
        }
        strip_data_type(part);
        if part.len() == len {
            return part.len() < before;
        }
    }
}

/// Removes `:$DATA` from the last component when it names the file
/// (`name::$DATA`) or a named stream (`name:s:$DATA`). Returns whether
/// anything was removed. `name:$DATA` is neither spelling, so it is kept.
fn strip_data_type(part: &mut String) -> bool {
    let Some(p) = strip_suffix_ignore_ascii_case(part, ":$DATA") else {
        return false;
    };
    let keep = if let Some(file) = p.strip_suffix(':') {
        file.len()
    } else if p.contains(':') {
        p.len()
    } else {
        return false;
    };
    part.truncate(keep);
    true
}

/// Joins the root and components, and finds the stream.
fn finish(mut text: String, root_len: usize, kind: PathKind, parts: &[String]) -> NormalizedPath {
    let mut needs_separator = !text.is_empty() && !text.ends_with('\\') && !text.ends_with(':');
    for part in parts {
        if needs_separator {
            text.push('\\');
        }
        text.push_str(part);
        needs_separator = true;
    }
    let stream = if parts.is_empty() {
        None
    } else {
        let last_start = text.rfind('\\').map_or(root_len, |i| (i + 1).max(root_len));
        text[last_start..].find(':').map(|i| last_start + i)
    };
    NormalizedPath {
        text,
        kind,
        root_len,
        stream,
    }
}

/// Converts `/` to `\`, turns a leading run of two or more separators into
/// exactly two (the UNC prefix), and collapses every other run into one.
fn collapse_separators(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw
        .chars()
        .map(|c| if c == '/' { '\\' } else { c })
        .peekable();
    let mut leading = 0usize;
    while chars.peek() == Some(&'\\') {
        chars.next();
        leading += 1;
    }
    out.push_str(match leading {
        0 => "",
        1 => "\\",
        _ => "\\\\",
    });
    let mut previous_was_separator = leading > 0;
    for c in chars {
        let is_separator = c == '\\';
        if !(is_separator && previous_was_separator) {
            out.push(c);
        }
        previous_was_separator = is_separator;
    }
    out
}

fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    strip_prefix_ignore_ascii_case(s, prefix).is_some()
}

fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

fn strip_suffix_ignore_ascii_case<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let split = s.len().checked_sub(suffix.len())?;
    let tail = s.get(split..)?;
    tail.eq_ignore_ascii_case(suffix).then(|| &s[..split])
}
