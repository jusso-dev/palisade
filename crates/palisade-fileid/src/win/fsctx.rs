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
    Ok(normalized)
}

/// Reads and parses the `Zone.Identifier` stream of `path`.
///
/// Returns `Ok(None)` if the file has no such stream. At most
/// [`MAX_ZONE_IDENTIFIER_BYTES`] plus one byte are read, so the parser can
/// report truncation.
///
/// `path` must name a file or directory, not a stream, and should be its
/// final path (see [`final_path`]). The stream name is appended to `path`
/// as given, so a path that Win32 normalisation would change (a trailing
/// dot, space or separator) can miss the stream; such paths are rejected.
pub fn read_motw(path: &Path) -> io::Result<Option<Motw>> {
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not valid Unicode"))?;
    if text.ends_with(['.', ' ', '\\', '/'])
        || text
            .rsplit(['\\', '/'])
            .next()
            .is_some_and(|n| n.contains(':'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be a final path to a file or directory, not a stream",
        ));
    }
    let mut stream = OsString::from(path.as_os_str());
    stream.push(":Zone.Identifier");
    let file = match File::open(&stream) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
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

    /// A fresh directory under the system temporary folder.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("palisade-fsctx-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
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
        // Another spelling of the same path has the same final path.
        let other = dir.join(".").join("EXAMPLE FILE.TXT");
        assert_eq!(final_path(&other).unwrap().case_folded(), p.case_folded());
        assert!(final_path(&dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zone_identifier_stream() {
        let dir = scratch("motw");
        let file = dir.join("download.exe");
        std::fs::write(&file, b"MZ").unwrap();
        assert_eq!(read_motw(&file).unwrap(), None);

        let mut ads = OsString::from(file.as_os_str());
        ads.push(":Zone.Identifier");
        std::fs::write(
            &ads,
            b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.org/\r\nHostUrl=https://example.org/download.exe\r\n",
        )
        .unwrap();
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
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
