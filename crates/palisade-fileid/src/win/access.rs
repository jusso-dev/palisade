//! Owners and writability of real files and folders (#54).
//!
//! Everything here is built on [`super::security`] and the portable model
//! in [`crate::fsctx::acl`] and [`crate::fsctx::writable`]:
//!
//! - [`read_owner`]: the owner SID, its class and account name, or
//!   "unsupported" on a file system or location whose owners cannot be
//!   relied on.
//! - [`assess_file`]: writability of a file and of every folder above it,
//!   with each distinct descriptor evaluated once through a
//!   [`WritabilityCache`].
//! - [`cross_check_writability`]: the portable evaluator's verdict for the
//!   synthetic standard user compared with the OS access check on the same
//!   descriptor (#54: "`AuthzAccessCheck` … as the authoritative method on
//!   Windows, with the pure-Rust ACE evaluator as the fallback and the
//!   cross-check").
//! - [`OsDirectories`]: a [`DirectorySource`] over real folders, for
//!   [`crate::fsctx::writable::enumerate_user_writable_dirs`]. It never
//!   follows links, junctions or mount points.
//!
//! Every call uses the caller's security context; a folder the caller cannot
//! read counts as user-writable, which only over-reports.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{FileTypeExt as _, OpenOptionsExt as _};
use std::path::Path;

use super::security::{NameCache, access_check, read_descriptor};
use crate::fsctx::acl::{
    EvaluationOptions, ObjectKind, OwnerInfo, SecurityDescriptor, Writability, WriteRights,
};
use crate::fsctx::writable::{
    AncestorRead, AssessOptions, DirectorySource, ReadDescriptor, WritabilityCache,
    assess_ancestors,
};
use crate::fsctx::{FsType, NormalizedPath, normalize_win32};

/// `FILE_FLAG_BACKUP_SEMANTICS`, needed to open a folder.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a link itself, not its target.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `READ_CONTROL`: enough to read the owner, group and DACL.
const READ_CONTROL: u32 = 0x0002_0000;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x0080;

/// Opens `path` (file or folder) to read its security descriptor, without
/// following a final link or junction.
pub fn open_for_security(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(0x7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// The descriptor of the open `file`, read and parsed. `None` if it cannot
/// be read or does not parse.
#[must_use]
pub fn descriptor_of(file: &File) -> Option<ReadDescriptor> {
    read_descriptor(file)
        .ok()
        .and_then(|b| ReadDescriptor::parse(&b))
}

/// The owner of the open `file`. `fs_type` is the file system and `local`
/// whether the file is on a local fixed disk; owners are only reported
/// where they can be relied on (NTFS or ReFS, local), as
/// [`crate::fsctx::VolumeInfo::supports_owner`] decides. The account name
/// comes from `names`.
pub fn read_owner(
    file: &File,
    fs_type: Option<&FsType>,
    local: bool,
    names: &mut NameCache,
) -> io::Result<OwnerInfo> {
    if !local || !fs_type.is_some_and(FsType::supports_owner) {
        return Ok(OwnerInfo::unsupported());
    }
    let bytes = read_descriptor(file)?;
    let sd = SecurityDescriptor::from_self_relative(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut info = OwnerInfo::from_owner(sd.owner);
    info.owner_name = sd.owner.and_then(|o| names.name(&o));
    Ok(info)
}

/// Writability of the file or folder at `path` and of every folder above
/// it up to the volume root.
///
/// `path` is normalised and its ancestors listed by
/// [`NormalizedPath::ancestors`], immediate parent first. Each is opened
/// without following links and its descriptor read; one that cannot be
/// opened, read or parsed counts as user-writable. A path whose canonical
/// form is too long for an ancestor also counts that ancestor as writable.
pub fn assess_file(
    path: &Path,
    options: &EvaluationOptions,
    assess: AssessOptions,
    cache: &mut WritabilityCache,
) -> io::Result<Writability> {
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not valid Unicode"))?;
    let normalized =
        normalize_win32(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let target = open_for_security(path)?;
    let kind = if target.metadata()?.is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    let target_sd = descriptor_of(&target);
    let ancestors = normalized.ancestors().map(|a| match a {
        Ok(p) => read_ancestor(&p),
        Err(_) => AncestorRead {
            path: String::new(),
            descriptor: None,
        },
    });
    Ok(assess_ancestors(
        target_sd.as_ref(),
        kind,
        ancestors,
        options,
        assess,
        cache,
    ))
}

fn read_ancestor(p: &NormalizedPath) -> AncestorRead {
    let shown = p.to_win32_string();
    let descriptor = open_for_security(Path::new(&shown))
        .ok()
        .and_then(|f| descriptor_of(&f));
    AncestorRead {
        path: shown,
        descriptor,
    }
}

/// The portable verdict and the OS verdict for one descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessCrossCheck {
    /// The write-type rights the portable evaluator says the synthetic
    /// standard user may hold.
    pub portable: WriteRights,
    /// The subset of `portable` it is unsure about.
    pub portable_uncertain: WriteRights,
    /// The write-type rights the OS access check grants a token of the
    /// synthetic standard user's SIDs.
    pub os: WriteRights,
}

impl AccessCrossCheck {
    /// Rights the OS grants that the portable evaluator missed. This must
    /// be empty: the evaluator is meant to over-report, never to miss.
    #[must_use]
    pub const fn missed(&self) -> WriteRights {
        self.os.difference(self.portable)
    }

    /// Rights the evaluator reports for certain that the OS does not grant.
    #[must_use]
    pub const fn over_reported(&self) -> WriteRights {
        self.portable
            .difference(self.portable_uncertain)
            .difference(self.os)
    }

    /// Whether the two agree exactly on what is certain: nothing missed,
    /// nothing certain over-reported.
    #[must_use]
    pub const fn agrees(&self) -> bool {
        self.missed().is_empty() && self.over_reported().is_empty()
    }
}

/// Compares the portable evaluator with the OS access check for the
/// synthetic standard user on the self-relative `descriptor` of an object
/// of `kind`.
///
/// The OS token holds a fresh, unprivileged user SID plus every SID in
/// [`EvaluationOptions::standard_user`]. The OS decides "user-writable";
/// the portable result is reported beside it. Use [`AccessCrossCheck::missed`]
/// to find rights the evaluator would have missed.
pub fn cross_check_writability(
    descriptor: &[u8],
    kind: ObjectKind,
    options: &EvaluationOptions,
) -> io::Result<AccessCrossCheck> {
    let sd = SecurityDescriptor::from_self_relative(descriptor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let w = crate::fsctx::acl::evaluate(&sd, kind, options);
    // A user SID no ACE names, so only the groups decide.
    let user = crate::fsctx::Sid::new(5, &[21, 0x5041_4c49, 0x5341_4445, 0x5445_5354, 0x7fff_fffe])
        .ok_or_else(|| io::Error::other("bad synthetic SID"))?;
    let mut sids = vec![user];
    sids.extend(options.standard_user.iter().copied());
    let granted = access_check(descriptor, &sids)?;
    Ok(AccessCrossCheck {
        portable: w.standard_user,
        portable_uncertain: w.standard_user_uncertain,
        os: WriteRights::from_mask(granted).intersection(WriteRights::relevant(kind)),
    })
}

/// A [`DirectorySource`] over real folders.
///
/// Subfolders are listed with `read_dir`. Entries that are links,
/// junctions or mount points (any reparse point) are skipped, so the walk
/// never leaves its roots or loops. A folder that cannot be listed has no
/// subfolders.
#[derive(Debug, Default)]
pub struct OsDirectories;

impl DirectorySource for OsDirectories {
    type Error = std::convert::Infallible;

    fn descriptor(&mut self, path: &str) -> Result<Option<ReadDescriptor>, Self::Error> {
        Ok(open_for_security(Path::new(path))
            .ok()
            .and_then(|f| descriptor_of(&f)))
    }

    fn subdirectories(&mut self, path: &str) -> Result<Vec<String>, Self::Error> {
        let Ok(entries) = std::fs::read_dir(path) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            // `file_type` does not follow links: a junction or symbolic link
            // to a folder is a symlink here, never a directory.
            if !ft.is_dir() || ft.is_symlink() || ft.is_symlink_dir() {
                continue;
            }
            // Mount points are reparse points that are not symlinks; skip
            // anything with the reparse attribute.
            let reparse = entry
                .metadata()
                .map(|m| {
                    use std::os::windows::fs::MetadataExt as _;
                    m.file_attributes() & 0x400 != 0
                })
                .unwrap_or(true);
            if reparse {
                continue;
            }
            if let Some(p) = entry.path().to_str() {
                out.push(p.to_owned());
            }
        }
        out.sort();
        Ok(out)
    }
}
