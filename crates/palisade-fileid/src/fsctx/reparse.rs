//! Reparse points (#54): what a link, junction, mount point, app execution
//! alias, cloud placeholder or deduplicated file says it is.
//!
//! The Windows backend reads the reparse data buffer of a file opened
//! without following it (`FSCTL_GET_REPARSE_POINT`) and hands the bytes to
//! [`parse_reparse_point`]. The parser is pure, bounded and fuzzed: the
//! bytes come from the file system, but a standard user can create
//! symbolic links (with developer mode), junctions and app execution
//! aliases in folders they own, so every offset and length is checked and
//! nothing panics.
//!
//! A reparse point is reported, never followed here. Decisions about a
//! file use the final path of the opened handle (threat model T-agent-13);
//! [`ReparsePoint`] says why the name and the file differ. An app execution
//! alias is parsed into its package family name, app user model ID and
//! target executable, so installed-package identity (#53) can use it.

#![forbid(unsafe_code)]

use std::fmt;

/// The longest reparse data buffer the OS allows
/// (`MAXIMUM_REPARSE_DATA_BUFFER_SIZE`, 16 KiB).
pub const MAX_REPARSE_BYTES: usize = 16 * 1024;

/// `IO_REPARSE_TAG_MOUNT_POINT`: a junction or a volume mount point.
pub const TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// `IO_REPARSE_TAG_SYMLINK`.
pub const TAG_SYMLINK: u32 = 0xA000_000C;
/// `IO_REPARSE_TAG_DEDUP`: a file whose data is in the deduplication store.
pub const TAG_DEDUP: u32 = 0x8000_0013;
/// `IO_REPARSE_TAG_APPEXECLINK`: an app execution alias.
pub const TAG_APPEXECLINK: u32 = 0x8000_001B;
/// `IO_REPARSE_TAG_CLOUD`. The sixteen cloud tags `IO_REPARSE_TAG_CLOUD_1`
/// to `_F` differ from it only in bits 12 to 15.
pub const TAG_CLOUD: u32 = 0x9000_001A;
/// The bits that distinguish the sixteen cloud tags.
const CLOUD_MASK: u32 = 0x0000_F000;
/// The name-surrogate bit: the reparse point stands for another named
/// entity (a link, junction or mount point).
const NAME_SURROGATE: u32 = 0x2000_0000;
/// `SYMLINK_FLAG_RELATIVE`.
const SYMLINK_FLAG_RELATIVE: u32 = 1;
/// The longest string in an app execution alias, in UTF-16 code units.
const MAX_ALIAS_UNITS: usize = 32_767;

/// What kind of reparse point a tag names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReparseKind {
    /// A symbolic link to a file or folder.
    Symlink,
    /// A junction: a folder that redirects to another folder.
    Junction,
    /// A volume mount point: a folder where another volume is mounted.
    MountPoint,
    /// An app execution alias, which starts a packaged app's executable.
    AppExecLink,
    /// A cloud-files placeholder (any of the cloud tags).
    CloudPlaceholder,
    /// A deduplicated file.
    Dedup,
    /// Any other tag, as reported.
    Other(u32),
}

impl ReparseKind {
    /// Classifies a tag. A mount-point tag is [`Self::Junction`] until its
    /// target shows it is a volume ([`parse_reparse_point`] decides).
    #[must_use]
    pub const fn from_tag(tag: u32) -> Self {
        match tag {
            TAG_SYMLINK => Self::Symlink,
            TAG_MOUNT_POINT => Self::Junction,
            TAG_APPEXECLINK => Self::AppExecLink,
            TAG_DEDUP => Self::Dedup,
            t if t & !CLOUD_MASK == TAG_CLOUD => Self::CloudPlaceholder,
            t => Self::Other(t),
        }
    }
}

/// The target of a symbolic link, junction or mount point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkTarget {
    /// The substitute name: the path the OS follows, in NT form
    /// (`\??\C:\target`), or relative to the link's folder for a relative
    /// symbolic link.
    pub substitute_name: String,
    /// The print name: the target as shown to users. Can be anything the
    /// link's creator chose; never decide on it.
    pub print_name: String,
    /// A symbolic link whose target is relative to its own folder.
    pub relative: bool,
}

/// The fields of an app execution alias (`IO_REPARSE_TAG_APPEXECLINK`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppExecLink {
    /// The structure version the alias reports (3 on current systems).
    pub version: u32,
    /// The package family name of the app the alias starts.
    pub package_family_name: String,
    /// The app user model ID (`PackageFamilyName!AppId`).
    pub app_user_model_id: String,
    /// The full path of the executable the alias starts.
    pub target_path: String,
    /// Any further strings (version 3 adds the app type), as given.
    pub extra: Vec<String>,
}

/// The target a reparse point names, where it has one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReparseTarget {
    /// A symbolic link, junction or mount point target.
    Link(LinkTarget),
    /// An app execution alias.
    AppExecLink(AppExecLink),
}

/// A reparse point: `reparse { tag, target }` in #54.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReparsePoint {
    /// The raw tag.
    pub tag: u32,
    /// What the tag means.
    pub kind: ReparseKind,
    /// The target, for the kinds that name one.
    pub target: Option<ReparseTarget>,
}

impl ReparsePoint {
    /// Whether the reparse point stands for another named entity (the
    /// name-surrogate bit): opening the name reaches some other object.
    #[must_use]
    pub const fn is_name_surrogate(&self) -> bool {
        self.tag & NAME_SURROGATE != 0
    }

    /// The app execution alias, if this is one.
    #[must_use]
    pub fn app_exec_link(&self) -> Option<&AppExecLink> {
        match &self.target {
            Some(ReparseTarget::AppExecLink(a)) => Some(a),
            _ => None,
        }
    }

    /// The link target, if this is a symbolic link, junction or mount point.
    #[must_use]
    pub fn link_target(&self) -> Option<&LinkTarget> {
        match &self.target {
            Some(ReparseTarget::Link(l)) => Some(l),
            _ => None,
        }
    }
}

/// Why a reparse data buffer could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReparseError {
    /// Shorter than its header or its stated length.
    Truncated,
    /// Longer than [`MAX_REPARSE_BYTES`].
    TooLong,
    /// A name offset or length is odd or points outside the buffer.
    BadName,
    /// A string is not valid UTF-16, or holds a NUL where none may be.
    BadString,
}

impl fmt::Display for ReparseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "reparse data is truncated",
            Self::TooLong => "reparse data is too long",
            Self::BadName => "reparse data has a bad name offset or length",
            Self::BadString => "reparse data holds a malformed string",
        })
    }
}

impl std::error::Error for ReparseError {}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let bytes = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let bytes = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn utf16(bytes: &[u8]) -> Result<String, ReparseError> {
    if bytes.len() % 2 != 0 {
        return Err(ReparseError::BadName);
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            u16::from_le_bytes([
                c.first().copied().unwrap_or(0),
                c.get(1).copied().unwrap_or(0),
            ])
        })
        .collect();
    let s = String::from_utf16(&units).map_err(|_| ReparseError::BadString)?;
    if s.contains('\0') {
        return Err(ReparseError::BadString);
    }
    Ok(s)
}

/// A name in the path buffer that starts at `base`, at `offset` for
/// `len` bytes.
fn name_at(data: &[u8], base: usize, offset: u16, len: u16) -> Result<String, ReparseError> {
    let start = base
        .checked_add(usize::from(offset))
        .ok_or(ReparseError::BadName)?;
    let end = start
        .checked_add(usize::from(len))
        .ok_or(ReparseError::BadName)?;
    utf16(data.get(start..end).ok_or(ReparseError::BadName)?)
}

/// Whether an NT substitute name names a volume root rather than a folder:
/// `\??\Volume{GUID}\`, as a volume mount point's target is.
fn is_volume_target(substitute: &str) -> bool {
    let rest = substitute
        .strip_prefix(r"\??\")
        .unwrap_or(substitute)
        .trim_end_matches('\\');
    rest.len() > 7
        && rest
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("Volume{"))
        && rest.ends_with('}')
        && !rest.contains('\\')
}

/// The string list of an app execution alias: UTF-16 strings, each ended
/// by a NUL. Bytes after the last NUL are ignored.
fn alias_strings(data: &[u8]) -> Result<Vec<String>, ReparseError> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for c in data.chunks_exact(2) {
        let u = u16::from_le_bytes([
            c.first().copied().unwrap_or(0),
            c.get(1).copied().unwrap_or(0),
        ]);
        if u == 0 {
            out.push(String::from_utf16(&current).map_err(|_| ReparseError::BadString)?);
            current.clear();
        } else {
            if current.len() >= MAX_ALIAS_UNITS {
                return Err(ReparseError::BadString);
            }
            current.push(u);
        }
    }
    Ok(out)
}

/// Parses a reparse data buffer (`REPARSE_DATA_BUFFER`, or the GUID form
/// for third-party tags) as `FSCTL_GET_REPARSE_POINT` returns it.
///
/// Symbolic links, junctions, mount points and app execution aliases are
/// parsed for their targets. Other tags are reported by kind only, with
/// their data ignored. An app execution alias with fewer than three
/// strings has no target.
pub fn parse_reparse_point(bytes: &[u8]) -> Result<ReparsePoint, ReparseError> {
    if bytes.len() > MAX_REPARSE_BYTES {
        return Err(ReparseError::TooLong);
    }
    let tag = u32_at(bytes, 0).ok_or(ReparseError::Truncated)?;
    let len = usize::from(u16_at(bytes, 4).ok_or(ReparseError::Truncated)?);
    let data = bytes
        .get(8..8_usize.saturating_add(len))
        .ok_or(ReparseError::Truncated)?;
    let mut kind = ReparseKind::from_tag(tag);
    let target = match tag {
        TAG_SYMLINK | TAG_MOUNT_POINT => {
            let field = |at: usize| u16_at(data, at).ok_or(ReparseError::Truncated);
            let (sub_off, sub_len, print_off, print_len) =
                (field(0)?, field(2)?, field(4)?, field(6)?);
            let (base, relative) = if tag == TAG_SYMLINK {
                let flags = u32_at(data, 8).ok_or(ReparseError::Truncated)?;
                (12, flags & SYMLINK_FLAG_RELATIVE != 0)
            } else {
                (8, false)
            };
            let substitute_name = name_at(data, base, sub_off, sub_len)?;
            let print_name = name_at(data, base, print_off, print_len)?;
            if tag == TAG_MOUNT_POINT && is_volume_target(&substitute_name) {
                kind = ReparseKind::MountPoint;
            }
            Some(ReparseTarget::Link(LinkTarget {
                substitute_name,
                print_name,
                relative,
            }))
        }
        TAG_APPEXECLINK => {
            let version = u32_at(data, 0).ok_or(ReparseError::Truncated)?;
            let strings = alias_strings(data.get(4..).unwrap_or_default())?;
            let mut it = strings.into_iter();
            match (it.next(), it.next(), it.next()) {
                (Some(package_family_name), Some(app_user_model_id), Some(target_path)) => {
                    Some(ReparseTarget::AppExecLink(AppExecLink {
                        version,
                        package_family_name,
                        app_user_model_id,
                        target_path,
                        extra: it.collect(),
                    }))
                }
                _ => None,
            }
        }
        _ => None,
    };
    Ok(ReparsePoint { tag, kind, target })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A symbolic-link or mount-point buffer with the two names.
    pub(super) fn link_buffer(tag: u32, sub: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
        let s = units(sub);
        let p = units(print);
        let mut data = Vec::new();
        data.extend_from_slice(&0_u16.to_le_bytes());
        data.extend_from_slice(&u16::try_from(s.len()).unwrap().to_le_bytes());
        data.extend_from_slice(&u16::try_from(s.len() + 2).unwrap().to_le_bytes());
        data.extend_from_slice(&u16::try_from(p.len()).unwrap().to_le_bytes());
        if let Some(f) = flags {
            data.extend_from_slice(&f.to_le_bytes());
        }
        data.extend_from_slice(&s);
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&p);
        data.extend_from_slice(&[0, 0]);
        let mut out = Vec::new();
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend(data);
        out
    }

    fn alias_buffer(strings: &[&str]) -> Vec<u8> {
        let mut data = 3_u32.to_le_bytes().to_vec();
        for s in strings {
            data.extend(units(s));
            data.extend_from_slice(&[0, 0]);
        }
        let mut out = TAG_APPEXECLINK.to_le_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend(data);
        out
    }

    #[test]
    fn symlinks() {
        let b = link_buffer(
            TAG_SYMLINK,
            r"\??\C:\target\a.exe",
            r"C:\target\a.exe",
            Some(0),
        );
        let r = parse_reparse_point(&b).unwrap();
        assert_eq!(r.kind, ReparseKind::Symlink);
        assert!(r.is_name_surrogate());
        let t = r.link_target().unwrap();
        assert_eq!(t.substitute_name, r"\??\C:\target\a.exe");
        assert_eq!(t.print_name, r"C:\target\a.exe");
        assert!(!t.relative);
        let rel = link_buffer(TAG_SYMLINK, r"..\b.exe", r"..\b.exe", Some(1));
        assert!(
            parse_reparse_point(&rel)
                .unwrap()
                .link_target()
                .unwrap()
                .relative
        );
    }

    #[test]
    fn junctions_and_mount_points() {
        let j = link_buffer(TAG_MOUNT_POINT, r"\??\C:\Program Files\App", "", None);
        let r = parse_reparse_point(&j).unwrap();
        assert_eq!(r.kind, ReparseKind::Junction);
        assert_eq!(
            r.link_target().unwrap().substitute_name,
            r"\??\C:\Program Files\App"
        );
        let m = link_buffer(
            TAG_MOUNT_POINT,
            r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\",
            "",
            None,
        );
        assert_eq!(
            parse_reparse_point(&m).unwrap().kind,
            ReparseKind::MountPoint
        );
        // A folder named like a volume below a drive is still a junction.
        let j2 = link_buffer(TAG_MOUNT_POINT, r"\??\C:\Volume{x}\", "", None);
        assert_eq!(
            parse_reparse_point(&j2).unwrap().kind,
            ReparseKind::Junction
        );
    }

    #[test]
    fn app_execution_aliases() {
        let b = alias_buffer(&[
            "Example.App_8wekyb3d8bbwe",
            "Example.App_8wekyb3d8bbwe!App",
            r"C:\Program Files\WindowsApps\Example.App_1.0.0.0_x64__8wekyb3d8bbwe\app.exe",
            "0",
        ]);
        let r = parse_reparse_point(&b).unwrap();
        assert_eq!(r.kind, ReparseKind::AppExecLink);
        assert!(!r.is_name_surrogate());
        let a = r.app_exec_link().unwrap();
        assert_eq!(a.version, 3);
        assert_eq!(a.package_family_name, "Example.App_8wekyb3d8bbwe");
        assert_eq!(a.app_user_model_id, "Example.App_8wekyb3d8bbwe!App");
        assert!(a.target_path.ends_with(r"\app.exe"));
        assert_eq!(a.extra, ["0"]);
        // Too few strings: the kind is known, the target is not.
        let short = alias_buffer(&["a", "b"]);
        let r = parse_reparse_point(&short).unwrap();
        assert_eq!(r.kind, ReparseKind::AppExecLink);
        assert!(r.target.is_none());
    }

    #[test]
    fn other_tags() {
        for (tag, kind) in [
            (TAG_CLOUD, ReparseKind::CloudPlaceholder),
            (0x9000_101A, ReparseKind::CloudPlaceholder),
            (0x9000_F01A, ReparseKind::CloudPlaceholder),
            (TAG_DEDUP, ReparseKind::Dedup),
            (0x8000_0017, ReparseKind::Other(0x8000_0017)),
        ] {
            let mut b = tag.to_le_bytes().to_vec();
            b.extend_from_slice(&[4, 0, 0, 0, 1, 2, 3, 4]);
            let r = parse_reparse_point(&b).unwrap();
            assert_eq!(r.kind, kind, "{tag:#x}");
            assert!(r.target.is_none());
        }
    }

    #[test]
    fn malformed_buffers_are_errors() {
        assert_eq!(parse_reparse_point(&[]), Err(ReparseError::Truncated));
        assert_eq!(parse_reparse_point(&[0; 7]), Err(ReparseError::Truncated));
        assert_eq!(
            parse_reparse_point(&vec![0; MAX_REPARSE_BYTES + 1]),
            Err(ReparseError::TooLong)
        );
        // Stated length past the end.
        let mut b = link_buffer(TAG_SYMLINK, "a", "b", Some(0));
        b[4] = 0xFF;
        assert_eq!(parse_reparse_point(&b), Err(ReparseError::Truncated));
        // Name offset past the buffer.
        let mut b = link_buffer(TAG_SYMLINK, "a", "b", Some(0));
        b[8] = 0xF0;
        assert_eq!(parse_reparse_point(&b), Err(ReparseError::BadName));
        // Odd name length.
        let mut b = link_buffer(TAG_SYMLINK, "ab", "b", Some(0));
        b[10] = 3;
        assert_eq!(parse_reparse_point(&b), Err(ReparseError::BadName));
        // A NUL inside a name.
        let b = link_buffer(TAG_MOUNT_POINT, "a\0b", "", None);
        assert_eq!(parse_reparse_point(&b), Err(ReparseError::BadString));
        // An unpaired surrogate in an alias.
        let mut b = alias_buffer(&["a", "b", "c"]);
        let at = b.len() - 4;
        b[at..at + 2].copy_from_slice(&0xD800_u16.to_le_bytes());
        assert_eq!(parse_reparse_point(&b), Err(ReparseError::BadString));
        // Every prefix of a valid buffer parses or errors, never panics.
        let full = link_buffer(TAG_SYMLINK, r"\??\C:\x", r"C:\x", Some(0));
        for n in 0..full.len() {
            let _ = parse_reparse_point(&full[..n]);
        }
    }
}
