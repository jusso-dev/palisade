//! The Windows reads behind [`crate::fsctx`] (#54). So far these use only the
//! standard library, with no FFI and no `unsafe` code.
//!
//! - [`final_path`]: the final path of a file, with symbolic links,
//!   junctions and mount points resolved and every 8.3 short name expanded
//!   (the standard library calls `GetFinalPathNameByHandleW` with
//!   `FILE_NAME_NORMALIZED`).
//! - [`read_motw`]: the file's `Zone.Identifier` stream, parsed.
//!
//! Owner, DACL, drive and bus type, volume GUID and DFS lookups and the OS
//! access check need Windows API calls the standard library does not offer.
//! They come with the rest of #54, here, together with the `windows-sys`
//! dependency and the unsafe-code allowlist entry ADR 0011 requires.
//!
//! Both functions open the path they are given, in the caller's security
//! context. A privileged service must not call them with a path a less
//! privileged caller chose (threat model T-agent-13).

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::fsctx::motw::{MAX_ZONE_IDENTIFIER_BYTES, Motw, parse_zone_identifier};
use crate::fsctx::path::{NormalizedPath, normalize_win32};

/// `ERROR_INVALID_NAME`: the file name, directory name or volume label
/// syntax is incorrect.
const ERROR_INVALID_NAME: i32 = 123;

/// The final path of `path`, normalised.
///
/// Fails if the file cannot be opened, or its final path is not valid
/// Unicode or cannot be normalised.
pub fn final_path(path: &Path) -> io::Result<NormalizedPath> {
    let resolved = std::fs::canonicalize(path)?;
    let text = resolved.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "final path is not valid Unicode",
        )
    })?;
    let mut normalized =
        normalize_win32(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // A normalised final path contains only long names, whatever shape a
    // component has.
    normalized.mark_long_names_verified();
    normalized.resolve_case_sensitivity(&super::volume::OsCaseSensitivity);
    Ok(normalized)
}

/// Reads and parses the `Zone.Identifier` stream of `path`.
///
/// Returns `Ok(None)` if the file has no such stream, or is on a file
/// system without alternate data streams (FAT, exFAT, CDFS), and an error if
/// the file itself does not exist. At most
/// [`MAX_ZONE_IDENTIFIER_BYTES`] plus one byte are read, so the parser can
/// report truncation.
///
/// `path` must be a fully qualified path to a file or directory, not a
/// stream, and should be its final path (see [`final_path`]). The stream
/// name is appended to `path` as given, so a path that Win32 normalisation
/// would change can miss the stream. Such paths are rejected: a relative or
/// drive-relative path (`a:Zone.Identifier` would name drive `A:`, not a
/// stream of `.\a`), a trailing separator, and, unless the path is a
/// literal `\\?\` path, a trailing dot or space.
///
/// The existence checks are by pathname: they do not establish that the
/// stream belongs to the same file if the path is replaced between calls.
pub fn read_motw(path: &Path) -> io::Result<Option<Motw>> {
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not valid Unicode"))?;
    // In a literal `\\?\` path, only `\` separates components, and a
    // trailing dot or space is part of the name.
    let verbatim = text.starts_with(r"\\?\");
    let separators: &[char] = if verbatim { &['\\'] } else { &['\\', '/'] };
    let last = text.rsplit(separators).next().unwrap_or("");
    if text.is_empty()
        || !path.is_absolute()
        || text.ends_with(separators)
        || (!verbatim && text.ends_with(['.', ' ']))
        || last.contains(':')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be a final path to a file or directory, not a stream",
        ));
    }
    // A missing file is an error, not "no mark".
    std::fs::symlink_metadata(path)?;
    let mut stream = OsString::from(path.as_os_str());
    stream.push(":Zone.Identifier");
    let file = match File::open(&stream) {
        Ok(f) => f,
        // The stream is missing, unless the file itself has gone since the
        // check above: then this is the same error as a missing file.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::symlink_metadata(path)?;
            return Ok(None);
        }
        // ERROR_INVALID_NAME: the file exists (checked above), so it is the
        // stream syntax the file system rejects, as FAT, exFAT and CDFS do.
        Err(e) if e.raw_os_error() == Some(ERROR_INVALID_NAME) => return Ok(None),
        Err(e) => return Err(e),
    };
    let limit = u64::try_from(MAX_ZONE_IDENTIFIER_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    Ok(Some(parse_zone_identifier(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsctx::motw::Zone;
    use crate::fsctx::path::Root;

    /// A directory this test created, removed when dropped, even if the
    /// test panics.
    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for Scratch {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    /// A new directory under the system temporary folder. `create_dir`
    /// fails if the name exists, so the directory is never one that
    /// something else made; a taken name is retried with the next number.
    fn scratch(name: &str) -> Scratch {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let base = std::env::temp_dir();
        loop {
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = base.join(format!("palisade-fsctx-{name}-{}-{n}", std::process::id()));
            match std::fs::create_dir(&dir) {
                Ok(()) => return Scratch(dir),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < 1000 => {}
                Err(e) => panic!("cannot create {}: {e}", dir.display()),
            }
        }
    }

    #[test]
    fn final_path_of_a_file() {
        let dir = scratch("final");
        let file = dir.join("Example File.txt");
        std::fs::write(&file, b"x").unwrap();
        let p = final_path(&file).unwrap();
        assert_eq!(p.file_name(), Some("Example File.txt"));
        assert!(matches!(p.root(), Root::Drive(_) | Root::Unc { .. }));
        assert!(p.short_name_candidates().is_empty());
        assert!(p.match_key().is_ok());
        // Another spelling of the same path has the same final path. The
        // name keeps its case, so this holds in a case-sensitive directory.
        let other = dir.join(".").join("Example File.txt");
        assert_eq!(final_path(&other).unwrap().case_folded(), p.case_folded());
        assert!(final_path(&dir.join("missing")).is_err());
    }

    #[test]
    fn zone_identifier_stream() {
        let dir = scratch("motw");
        let file = dir.join("download.exe");
        std::fs::write(&file, b"MZ").unwrap();
        assert_eq!(read_motw(&file).unwrap(), None);

        let mut ads = OsString::from(file.as_os_str());
        ads.push(":Zone.Identifier");
        match std::fs::write(
            &ads,
            b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.org/\r\nHostUrl=https://example.org/download.exe\r\n",
        ) {
            Ok(()) => {}
            // The temporary folder is on a volume without streams: the
            // backend must report "no mark" there.
            Err(e) if e.raw_os_error() == Some(ERROR_INVALID_NAME) => {
                assert_eq!(read_motw(&file).unwrap(), None);
                return;
            }
            Err(e) => panic!("cannot create the test stream: {e}"),
        }
        let m = read_motw(&file).unwrap().unwrap();
        assert_eq!(m.zone, Some(Zone::Internet));
        assert_eq!(m.referrer_url.as_deref(), Some("https://example.org/"));
        assert_eq!(
            m.host_url.as_deref(),
            Some("https://example.org/download.exe")
        );
        // The stream is not part of the file's content.
        assert_eq!(std::fs::read(&file).unwrap(), b"MZ");
        // Paths that would miss or mis-name the stream are rejected.
        let mut dotted = OsString::from(file.as_os_str());
        dotted.push(".");
        assert!(read_motw(Path::new(&dotted)).is_err());
        assert!(read_motw(Path::new(&ads)).is_err());
        assert!(read_motw(Path::new("")).is_err());
        // Relative paths are rejected: `a:Zone.Identifier` names drive `A:`.
        for relative in ["a", r"dir\a", r"\dir\a", "C:a"] {
            assert_eq!(
                read_motw(Path::new(relative)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{relative}"
            );
        }
        // A missing file is an error, not "no mark".
        assert!(read_motw(&dir.join("missing.exe")).is_err());
    }
}
