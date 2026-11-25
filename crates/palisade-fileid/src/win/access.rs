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
    AncestorRead, AssessOptions, DirectorySource, Listing, ReadDescriptor, WritabilityCache,
    assess_ancestors,
};
use crate::fsctx::{FsType, NormalizedPath, Root, normalize_win32};

/// `FILE_FLAG_BACKUP_SEMANTICS`, needed to open a folder.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a link itself, not its target.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `READ_CONTROL`: enough to read the owner, group and DACL.
const READ_CONTROL: u32 = 0x0002_0000;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
/// `FILE_ATTRIBUTE_DIRECTORY`.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
/// `SECURITY_SQOS_PRESENT` with `SECURITY_ANONYMOUS` (0): if a path turns
/// out to name a named pipe, its server can never impersonate the caller.
const SQOS_ANONYMOUS: u32 = 0x0010_0000;

/// Opens `path` (file or folder) to read its security descriptor, without
/// following a final link or junction.
pub fn open_for_security(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(0x7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | SQOS_ANONYMOUS)
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

/// Opens `path` to read its security descriptor, **following** links, so
/// the handle is the object opening `path` reaches.
fn open_target(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(0x7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | SQOS_ANONYMOUS)
        .open(path)
}

/// Whether `root` names a volume that holds files: a drive, a UNC share,
/// a volume GUID, or an NT disk volume (`\Device\HarddiskVolumeN`, or a
/// shadow copy of one). Pipes, mailslots, consoles and other devices are
/// not.
fn is_file_system_root(root: &Root) -> bool {
    match root {
        Root::Drive(_) | Root::Unc { .. } | Root::VolumeGuid(_) => true,
        Root::NtDevice(name) => {
            let n = name.to_ascii_lowercase();
            n.starts_with("harddiskvolume")
        }
        Root::DosDevice(_) => false,
    }
}

/// Whether two open handles are the same file system object (same volume
/// serial and 128-bit file ID). `false` if either ID cannot be read, or is
/// all zero.
fn same_object(a: &File, b: &File) -> bool {
    match (super::sys::file_id_info(a), super::sys::file_id_info(b)) {
        (Ok(x), Ok(y)) => {
            x.FileId.Identifier != [0; 16]
                && x.VolumeSerialNumber == y.VolumeSerialNumber
                && x.FileId.Identifier == y.FileId.Identifier
        }
        _ => false,
    }
}

/// The `FILE_ATTRIBUTE_*` bits of the open `file`.
fn attributes(file: &File) -> io::Result<u32> {
    use std::os::windows::fs::MetadataExt as _;
    Ok(file.metadata()?.file_attributes())
}

/// Writability of the file or folder that opening `path` reaches, and of
/// every folder above it up to its volume root.
///
/// Links are resolved the way the OS resolves them when the file is run:
/// the target is opened **following** links, and its own final path
/// (`GetFinalPathNameByHandleW`) gives the real chain of folders, so a
/// junction, symbolic link, mount point or `subst` drive in `path` cannot
/// hide a writable folder the file really lives in. Each folder on a chain
/// is opened without following a reparse point; one that is a reparse
/// point, or that cannot be opened, read or parsed, counts as
/// user-writable (the chain is not what it seems, so this fails closed).
/// The lexical ancestors of `path` that are not on the real chain are
/// checked the same way, since the link objects could be replaced.
///
/// If `path` **itself** is a link, junction or other reparse point that
/// leads to another object, the target counts as user-writable too: the
/// link object could be retargeted, or lead through folders neither chain
/// shows. Assess the target's own path instead to judge the target.
///
/// Only paths on a volume are accepted: device paths (`\\.\pipe\…`,
/// `\\?\GLOBALROOT\Device\NamedPipe\…` and the like) are rejected, and
/// every open asks for anonymous impersonation, so even a path that leads
/// to a named pipe cannot lend its server the caller's identity.
///
/// Ancestors are read lazily: with [`AssessOptions::stop_at_first_writable`]
/// nothing is read past the first user-writable folder.
pub fn assess_file(
    path: &Path,
    options: &EvaluationOptions,
    assess: AssessOptions,
    cache: &mut WritabilityCache,
) -> io::Result<Writability> {
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not valid Unicode"))?;
    let lexical =
        normalize_win32(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if !is_file_system_root(lexical.root()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a file-system path",
        ));
    }
    let shown = lexical.to_win32_string();
    let target = open_target(Path::new(&shown))?;
    if !super::sys::is_disk_file(&target) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a file on disk",
        ));
    }
    let attrs = attributes(&target)?;
    let kind = if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    // The object `path` names, without following it. If that is not the
    // object opening `path` reaches, `path` is a link: fail closed.
    let is_link = match open_for_security(Path::new(&shown)) {
        Ok(stub) => !same_object(&stub, &target),
        Err(_) => true,
    };
    let target_sd = if is_link {
        None
    } else {
        descriptor_of(&target)
    };
    // The real chain, from the opened handle.
    let final_text = super::sys::final_path_by_handle(&target, 0)
        .or_else(|_| super::sys::final_path_by_handle(&target, 1))?;
    let mut real =
        normalize_win32(&final_text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    real.mark_long_names_verified();
    // Which folders to read, decided from the paths alone: the real chain,
    // then the lexical ancestors not on it. Nothing is opened yet.
    let mut seen = std::collections::BTreeSet::new();
    let mut chain = Vec::new();
    for a in real.ancestors().chain(lexical.ancestors()) {
        match &a {
            Ok(p) => {
                if seen.insert(p.case_folded()) {
                    chain.push(a);
                }
            }
            Err(_) => chain.push(a),
        }
    }
    Ok(assess_ancestors(
        target_sd.as_ref(),
        kind,
        chain.into_iter().map(read_ancestor_result),
        options,
        assess,
        cache,
    ))
}

fn read_ancestor_result(a: Result<NormalizedPath, crate::fsctx::PathError>) -> AncestorRead {
    match a {
        Ok(p) => read_ancestor(&p),
        Err(_) => AncestorRead {
            path: String::new(),
            descriptor: None,
        },
    }
}

/// One folder on a chain: its descriptor, read without following it. A
/// reparse point counts as unreadable (user-writable), since the chain does
/// not go through it as written.
fn read_ancestor(p: &NormalizedPath) -> AncestorRead {
    let shown = p.to_win32_string();
    let descriptor = open_for_security(Path::new(&shown)).ok().and_then(|f| {
        let reparse = attributes(&f).map_or(true, |a| a & FILE_ATTRIBUTE_REPARSE_POINT != 0);
        if reparse { None } else { descriptor_of(&f) }
    });
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
    // The evaluator leaves administrator SIDs out of the standard user, so
    // the OS token does too; otherwise their rights would look "missed".
    let mut sids = vec![user];
    sids.extend(
        options
            .standard_user
            .iter()
            .copied()
            .filter(|s| !options.admins.contains(s)),
    );
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

    fn subdirectories(&mut self, path: &str) -> Result<Listing, Self::Error> {
        // A root or folder that is itself a reparse point is not listed:
        // listing it would follow it out of the tree.
        let is_reparse = open_for_security(Path::new(path))
            .and_then(|f| attributes(&f))
            .map_or(true, |a| a & FILE_ATTRIBUTE_REPARSE_POINT != 0);
        if is_reparse {
            return Ok(Listing::default());
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return Ok(Listing::default());
        };
        let mut listing = Listing {
            dirs: Vec::new(),
            complete: true,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                listing.complete = false;
                continue;
            };
            let Ok(ft) = entry.file_type() else {
                listing.complete = false;
                continue;
            };
            // `file_type` does not follow links: a junction or symbolic link
            // to a folder is a symlink here, never a directory.
            if ft.is_symlink() || ft.is_symlink_dir() || !ft.is_dir() {
                continue;
            }
            // Mount points are reparse points that are not symlinks.
            let reparse = entry.metadata().map(|m| {
                use std::os::windows::fs::MetadataExt as _;
                m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            });
            match reparse {
                Ok(true) => {}
                Ok(false) => match entry.path().to_str() {
                    Some(p) => listing.dirs.push(p.to_owned()),
                    // A name that is not valid UTF-16 cannot be walked here.
                    None => listing.complete = false,
                },
                Err(_) => listing.complete = false,
            }
        }
        listing.dirs.sort();
        Ok(listing)
    }
}
