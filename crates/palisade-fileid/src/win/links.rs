//! Reparse points and hard links of real files (#54).
//!
//! - [`read_reparse`]: the reparse point of a file or folder, read without
//!   following it (`FSCTL_GET_REPARSE_POINT`) and parsed by
//!   [`crate::fsctx::reparse::parse_reparse_point`]. `Ok(None)` if it is
//!   not a reparse point.
//! - [`hard_links`]: how many names a file has
//!   (`FILE_STANDARD_INFO.NumberOfLinks`) and, up to
//!   [`MAX_HARD_LINK_NAMES`], what they are (`FindFirstFileNameW`).
//! - [`read_streams`]: the alternate data streams of a file, tagged, with
//!   the start of each sniffed for executable content.
//! - [`read_meta`]: the file ID, USN, timestamps and attributes.
//! - [`read_details`]: all of the above, into an [`FsContext`].
//!
//! Every call uses the caller's security context.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;

use super::file::{FileFacts, list_streams, open_for_hashing};
use super::sys;
use crate::fsctx::FsContext;
use crate::fsctx::meta::{FileAttributes, FileMeta, HardLinks, MAX_HARD_LINK_NAMES};
use crate::fsctx::reparse::{ReparsePoint, parse_reparse_point};
use crate::fsctx::streams::{FsStreams, sniff_stream};

/// `VOLUME_NAME_DOS` and `VOLUME_NAME_GUID` for `GetFinalPathNameByHandleW`.
const VOLUME_NAME_DOS: u32 = 0;
const VOLUME_NAME_GUID: u32 = 1;

/// `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, with
/// anonymous impersonation if the path leads to a named pipe.
const OPEN_LINK_ITSELF: u32 = 0x0200_0000 | 0x0020_0000 | 0x0010_0000;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
/// `ERROR_NOT_A_REPARSE_POINT`.
const ERROR_NOT_A_REPARSE_POINT: i32 = 4390;

/// Opens `path` itself (a link, junction or alias, not its target), for
/// reading attributes and the reparse point.
pub fn open_link_itself(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(0x7)
        .custom_flags(OPEN_LINK_ITSELF)
        .open(path)
}

/// The reparse point of the open `file`, which must have been opened
/// without following it ([`open_link_itself`]). `Ok(None)` if it has none.
pub fn read_reparse(file: &File) -> io::Result<Option<ReparsePoint>> {
    let attrs = sys::basic_info(file)?.FileAttributes;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return Ok(None);
    }
    let bytes = match sys::reparse_point_bytes(file) {
        Ok(b) => b,
        Err(e) if e.raw_os_error() == Some(ERROR_NOT_A_REPARSE_POINT) => return Ok(None),
        Err(e) => return Err(e),
    };
    parse_reparse_point(&bytes)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// The hard links of the file at `path`, whose open handle is `file`: the
/// count from the handle and, when there is more than one name, up to
/// [`MAX_HARD_LINK_NAMES`] of them (`FindFirstFileNameW`, by path). A
/// listing that fails, or a `path` that no longer names the opened file
/// (by file ID), leaves the names empty and marks them truncated; the
/// count is still reported.
pub fn hard_links(path: &Path, file: &File) -> io::Result<HardLinks> {
    let count = sys::standard_info(file)?.number_of_links;
    if count <= 1 {
        return Ok(HardLinks::new(count, Vec::new(), true));
    }
    // The names are listed by path, not by handle, so `path` must still
    // name the opened file: checked by file ID before and after listing,
    // as `read_streams` binds each stream. On any mismatch, or if either ID
    // cannot be read, no names are reported and the list is marked cut.
    let unlisted = || HardLinks::new(count, Vec::new(), false);
    let Some(id) = file_id(file) else {
        return Ok(unlisted());
    };
    let same = || {
        open_link_target(path)
            .ok()
            .and_then(|f| file_id(&f))
            .is_some_and(|other| other == id)
    };
    if !same() {
        return Ok(unlisted());
    }
    let listed = path
        .to_str()
        .and_then(|text| sys::hard_link_names(text, MAX_HARD_LINK_NAMES + 1).ok());
    if !same() {
        return Ok(unlisted());
    }
    Ok(match listed {
        Some((names, complete)) => HardLinks::new(count, names, complete),
        None => unlisted(),
    })
}

/// The 64-bit volume serial and 128-bit file ID of the open `file`, or
/// `None` if the file system reports no ID.
fn file_id(file: &File) -> Option<(u64, [u8; 16])> {
    sys::file_id_info(file)
        .ok()
        .map(|i| (i.VolumeSerialNumber, i.FileId.Identifier))
        .filter(|(_, id)| *id != [0; 16])
}

/// Opens the file `path` names now, following links as the caller's open
/// did, for reading its ID only.
fn open_link_target(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(0x7)
        .custom_flags(0x0200_0000 | 0x0010_0000)
        .open(path)
}

/// At most this many streams of one file are read and sniffed; the rest
/// are listed with `is_executable_content: None`.
pub const MAX_SNIFFED_STREAMS: usize = 64;

/// The alternate data streams of the open `file`, tagged, and the content
/// of each (up to [`MAX_SNIFFED_STREAMS`] of them) classified with
/// [`sniff_stream`]: by the bounded streaming classifier, with the stream's
/// name as the hint, and with a parse error counted as executable.
///
/// Each stream is opened through the file's final path and checked to be
/// on the same file (same 128-bit file ID), as
/// [`super::file::hash_streams`] does, so a path swapped in between cannot
/// substitute another file's stream. A stream that cannot be opened or
/// bound to the file keeps `is_executable_content: None`: unknown, never
/// "not executable" (ADR 0018).
pub fn read_streams(file: &File) -> io::Result<FsStreams> {
    let list = list_streams(file)?;
    let mut out = FsStreams::from_list(&list);
    if out.streams.is_empty() {
        return Ok(out);
    }
    let id = sys::file_id_info(file)?;
    if id.FileId.Identifier == [0; 16] {
        return Ok(out);
    }
    let final_path = sys::final_path_by_handle(file, VOLUME_NAME_DOS)
        .or_else(|_| sys::final_path_by_handle(file, VOLUME_NAME_GUID))?;
    for stream in out.streams.iter_mut().take(MAX_SNIFFED_STREAMS) {
        let path = format!("{final_path}:{}:$DATA", stream.name);
        let Ok(handle) = open_for_hashing(Path::new(&path)) else {
            continue;
        };
        let same = sys::file_id_info(&handle).is_ok_and(|s| {
            s.VolumeSerialNumber == id.VolumeSerialNumber
                && s.FileId.Identifier == id.FileId.Identifier
        });
        if !same {
            continue;
        }
        // The classifier reads the open stream itself, within its own
        // bounds, with the stream's name as the hint.
        let mut handle = handle;
        stream.is_executable_content = Some(sniff_stream(&mut handle, &stream.name));
    }
    Ok(out)
}

/// The file ID, USN, timestamps and attributes of the open `file`.
pub fn read_meta(file: &File) -> io::Result<FileMeta> {
    let facts = FileFacts::read(file)?;
    Ok(FileMeta {
        volume_serial: facts.file_id.map(|(serial, _)| serial),
        file_id: facts.file_id.map(|(_, id)| id),
        usn: facts.usn,
        creation: facts.creation,
        last_write: facts.last_write,
        change: facts.change,
        last_access: facts.last_access,
        attributes: FileAttributes(facts.attributes),
    })
}

/// Fills the streams, reparse point, hard links and file metadata of
/// `ctx` for the file at `path`, whose open handle (following links) is
/// `file`. Each field is set only if it could be read, so `None` still
/// means "not read".
///
/// The reparse point is that of `path` itself, opened again without
/// following it: it says why the name and the opened file can differ. The
/// rest is read from `file`. Streams are read and sniffed here, so this is
/// a tier-3 read (#55); call it for the files that need it.
pub fn read_details(ctx: &mut FsContext, path: &Path, file: &File) {
    ctx.meta = read_meta(file).ok();
    ctx.hard_links = hard_links(path, file).ok();
    ctx.streams = read_streams(file).ok();
    ctx.reparse = open_link_itself(path)
        .and_then(|link| read_reparse(&link))
        .ok();
}

/// The final path of the open `file`, normalised: the path the handle
/// names, not the one it was opened by, so it is the opened file's even if
/// that path has since been replaced. Each directory's case-sensitivity
/// flag is read too ([`super::volume::OsCaseSensitivity`]), so its
/// `match_key` is refused for a name in a case-sensitive directory, and
/// for any name on a volume whose upcase table is not known to be the
/// standard one ([`super::volume::folds_as_standard`]).
pub fn final_path_of(file: &File) -> io::Result<crate::fsctx::NormalizedPath> {
    let text = sys::final_path_by_handle(file, VOLUME_NAME_DOS)?;
    let mut normalized = crate::fsctx::normalize_win32(&text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    normalized.mark_long_names_verified();
    normalized.resolve_case_sensitivity(&super::volume::OsCaseSensitivity);
    if !super::volume::folds_as_standard(file) {
        normalized.mark_fold_unknown();
    }
    Ok(normalized)
}

/// The mark of the web of the open `file`: its `Zone.Identifier` stream,
/// opened by the handle's own final path and kept only if it belongs to
/// the same file (same volume and file ID), so a path replaced after the
/// file was opened cannot lend it another file's mark. `Ok(None)` when
/// the file has no such stream.
pub fn read_motw_of(file: &File) -> io::Result<Option<crate::fsctx::Motw>> {
    let id = sys::file_id_info(file)?;
    let final_path = sys::final_path_by_handle(file, VOLUME_NAME_DOS)?;
    let path = Path::new(&final_path);
    let mark = super::fsctx::read_motw(path)?;
    // The stream was opened by name: check the file is still the one the
    // handle has open.
    let again = open_link_itself(path).and_then(|f| sys::file_id_info(&f))?;
    if again.VolumeSerialNumber != id.VolumeSerialNumber
        || again.FileId.Identifier != id.FileId.Identifier
    {
        return Err(io::Error::other(
            "the file at its final path changed while its mark of the web was read",
        ));
    }
    Ok(mark)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsctx::reparse::{ReparseKind, TAG_APPEXECLINK, TAG_MOUNT_POINT};
    use crate::fsctx::streams::BenignStream;
    use std::process::Command;

    /// A folder for one test, removed when dropped. Its path is the long
    /// final path: the runners' `%TEMP%` holds an 8.3 short name.
    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("palisade-links-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let long = std::fs::canonicalize(&dir).unwrap();
        let plain = long
            .to_str()
            .unwrap()
            .trim_start_matches(r"\\?\")
            .to_owned();
        Scratch(plain.into())
    }

    fn cmd(args: &[&str]) {
        let out = Command::new("cmd").arg("/C").args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn reparse_of(p: &Path) -> Option<ReparsePoint> {
        read_reparse(&open_link_itself(p).unwrap()).unwrap()
    }

    /// The bytes of a reparse data buffer with `tag` and `data`.
    fn buffer(tag: u32, data: &[u8]) -> Vec<u8> {
        let mut out = tag.to_le_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(data);
        out
    }

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// A symbolic link, a junction, a volume mount point and an app
    /// execution alias, made on the runner and read back. The runners run
    /// tests elevated, which creating a symbolic link needs; without it
    /// the test fails, not skips.
    #[test]
    fn reparse_fixtures() {
        let dir = scratch("reparse");
        let target = dir.0.join("target.exe");
        std::fs::write(&target, b"MZ").unwrap();
        let plain = Path::new(&target);
        assert_eq!(reparse_of(plain), None);

        let link = dir.0.join("link.exe");
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        let r = reparse_of(&link).unwrap();
        assert_eq!(r.kind, ReparseKind::Symlink, "{r:?}");
        assert!(r.is_name_surrogate());
        let t = r.link_target().unwrap();
        assert!(!t.relative);
        assert!(
            t.substitute_name
                .to_ascii_lowercase()
                .ends_with(r"\target.exe"),
            "{t:?}"
        );

        let rel = dir.0.join("rel.exe");
        std::os::windows::fs::symlink_file("target.exe", &rel).unwrap();
        let r = reparse_of(&rel).unwrap();
        assert!(r.link_target().unwrap().relative, "{r:?}");
        assert_eq!(r.link_target().unwrap().substitute_name, "target.exe");

        let sub = dir.0.join("real");
        std::fs::create_dir(&sub).unwrap();
        let junction = dir.0.join("junction");
        cmd(&[
            "mklink",
            "/J",
            junction.to_str().unwrap(),
            sub.to_str().unwrap(),
        ]);
        let r = reparse_of(&junction).unwrap();
        assert_eq!(r.kind, ReparseKind::Junction, "{r:?}");
        assert!(
            r.link_target()
                .unwrap()
                .substitute_name
                .starts_with(r"\??\"),
            "{r:?}"
        );

        // A volume mount point: a folder whose mount-point target is a
        // volume GUID root, as `mountvol` writes it. The GUID names no
        // volume, so nothing is reachable through the folder whatever
        // later removes it.
        let substitute = r"\??\Volume{00000000-0000-0000-0000-00000000dead}\";
        let mount = dir.0.join("mount");
        std::fs::create_dir(&mount).unwrap();
        let mut data = Vec::new();
        let sub_units = utf16z(substitute);
        let sub_len = u16::try_from(sub_units.len() - 2).unwrap();
        data.extend_from_slice(&0_u16.to_le_bytes());
        data.extend_from_slice(&sub_len.to_le_bytes());
        data.extend_from_slice(&(sub_len + 2).to_le_bytes());
        data.extend_from_slice(&0_u16.to_le_bytes());
        data.extend_from_slice(&sub_units);
        data.extend_from_slice(&[0, 0]);
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(OPEN_LINK_ITSELF)
            .open(&mount)
            .unwrap();
        sys::set_reparse_point(&handle, &buffer(TAG_MOUNT_POINT, &data)).unwrap();
        drop(handle);
        let r = reparse_of(&mount).unwrap();
        assert_eq!(r.kind, ReparseKind::MountPoint, "{r:?}");
        // Removing the folder removes the mount point, not the volume.
        std::fs::remove_dir(&mount).unwrap();

        // An app execution alias, with the layout the OS writes: version
        // 3, then the package family name, app user model ID, target and
        // app type, each NUL-terminated.
        let alias = dir.0.join("alias.exe");
        std::fs::write(&alias, b"").unwrap();
        let mut data = 3_u32.to_le_bytes().to_vec();
        for s in [
            "Example.App_8wekyb3d8bbwe",
            "Example.App_8wekyb3d8bbwe!App",
            r"C:\Program Files\WindowsApps\Example.App_1.0.0.0_x64__8wekyb3d8bbwe\app.exe",
            "0",
        ] {
            data.extend(utf16z(s));
        }
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(OPEN_LINK_ITSELF)
            .open(&alias)
            .unwrap();
        sys::set_reparse_point(&handle, &buffer(TAG_APPEXECLINK, &data)).unwrap();
        drop(handle);
        let r = reparse_of(&alias).unwrap();
        assert_eq!(r.kind, ReparseKind::AppExecLink, "{r:?}");
        let a = r.app_exec_link().unwrap();
        assert_eq!(a.package_family_name, "Example.App_8wekyb3d8bbwe");
        assert_eq!(a.app_user_model_id, "Example.App_8wekyb3d8bbwe!App");
        assert!(a.target_path.ends_with(r"\app.exe"));

        // Through `read_details`, the link's own reparse point and the
        // target's metadata.
        let opened = File::open(&link).unwrap();
        let mut ctx = FsContext::from_path(link.to_str().unwrap());
        read_details(&mut ctx, &link, &opened);
        assert_eq!(
            ctx.reparse.as_ref().unwrap().as_ref().unwrap().kind,
            ReparseKind::Symlink
        );
        let meta = ctx.meta.unwrap();
        assert!(meta.file_id.is_some() && meta.usn.is_some(), "{meta:?}");
        assert!(!meta.attributes.reparse_point());
    }

    #[test]
    fn hard_links_are_counted_and_listed_up_to_the_cap() {
        let dir = scratch("hardlinks");
        let first = dir.0.join("a.exe");
        std::fs::write(&first, b"MZ").unwrap();
        let one = hard_links(&first, &File::open(&first).unwrap()).unwrap();
        assert_eq!((one.count, one.truncated), (1, false));
        assert!(one.names.is_empty());

        for i in 0..2 {
            std::fs::hard_link(&first, dir.0.join(format!("b{i}.exe"))).unwrap();
        }
        let three = hard_links(&first, &File::open(&first).unwrap()).unwrap();
        assert_eq!(three.count, 3);
        assert!(!three.truncated, "{three:?}");
        assert_eq!(three.names.len(), 3);
        assert!(
            three
                .names
                .iter()
                .all(|n| n.starts_with('\\') && !n.contains(':')),
            "{three:?}"
        );

        for i in 2..20 {
            std::fs::hard_link(&first, dir.0.join(format!("b{i}.exe"))).unwrap();
        }
        let many = hard_links(&first, &File::open(&first).unwrap()).unwrap();
        assert_eq!(many.count, 21);
        assert_eq!(many.names.len(), MAX_HARD_LINK_NAMES);
        assert!(many.truncated);

        // The path now names another file with links of its own: the
        // opened file's count is kept, but no names from the other file.
        let opened = File::open(&first).unwrap();
        let moved = dir.0.join("moved.exe");
        std::fs::rename(&first, &moved).unwrap();
        std::fs::write(&first, b"other").unwrap();
        std::fs::hard_link(&first, dir.0.join("other-link.exe")).unwrap();
        let swapped = hard_links(&first, &opened).unwrap();
        assert_eq!(swapped.count, 21, "{swapped:?}");
        assert!(swapped.names.is_empty() && swapped.truncated, "{swapped:?}");
    }

    #[test]
    fn streams_are_tagged_and_sniffed() {
        let dir = scratch("streams");
        let file = dir.0.join("doc.txt");
        std::fs::write(&file, b"plain text").unwrap();
        let base = file.to_str().unwrap();
        std::fs::write(
            format!("{base}:Zone.Identifier"),
            b"[ZoneTransfer]\r\nZoneId=3\r\n",
        )
        .unwrap();
        std::fs::write(format!("{base}:com.example.attrs"), b"{}").unwrap();
        let mut pe = b"MZ".to_vec();
        pe.resize(512, 0);
        std::fs::write(format!("{base}:payload"), &pe).unwrap();
        std::fs::write(format!("{base}:notes"), b"just some words").unwrap();
        std::fs::write(format!("{base}:run.bat"), b"@echo off\r\ncopy a b\r\n").unwrap();

        let s = read_streams(&File::open(&file).unwrap()).unwrap();
        assert!(!s.truncated);
        let by = |n: &str| s.streams.iter().find(|x| x.name == n).unwrap();
        assert_eq!(
            by("Zone.Identifier").benign,
            Some(BenignStream::ZoneIdentifier)
        );
        assert_eq!(by("Zone.Identifier").is_executable_content, Some(false));
        assert_eq!(
            by("com.example.attrs").benign,
            Some(BenignStream::SyncMetadata)
        );
        assert_eq!(by("payload").benign, None);
        assert_eq!(by("payload").is_executable_content, Some(true));
        assert_eq!(by("payload").size, 512);
        assert_eq!(by("notes").is_executable_content, Some(false));
        // The stream's own name is the hint for batch content.
        assert_eq!(by("run.bat").is_executable_content, Some(true));
        assert!(s.any_executable());
        assert_eq!(s.unknown().count(), 3);
        assert!(s.may_hide_executable());

        // A file with no streams has none, and nothing unread.
        let bare = dir.0.join("bare.txt");
        std::fs::write(&bare, b"x").unwrap();
        let none = read_streams(&File::open(&bare).unwrap()).unwrap();
        assert!(none.streams.is_empty() && !none.may_hide_executable());
    }
}
