//! Reading secret files.
//!
//! Secrets (today only the TLS private key) are supplied as paths, never as
//! values in the configuration or the environment. This module reads them
//! into zeroising buffers. Its error messages name the path and the problem,
//! never any part of the contents.

use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

/// Reads a secret file of at most `max_len` bytes.
///
/// The file must be a regular file. On Unix it must not grant any
/// permission to the group or to others (mode `0600` or stricter), so a key
/// that other local users can read is refused rather than used. Windows ACL
/// checks are part of the secrets work in #227.
pub fn read_secret_file(path: &Path, max_len: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let shown = path.display();
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot open secret file {shown}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot inspect secret file {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("secret file {shown} is not a regular file"));
    }
    check_permissions(path, &meta)?;
    if meta.len() > max_len as u64 {
        return Err(format!(
            "secret file {shown} is larger than {max_len} bytes"
        ));
    }
    // Reserve the whole buffer up front, so the contents are never copied
    // into a reallocated buffer that would not be zeroised.
    let mut buf = Zeroizing::new(Vec::with_capacity(max_len.saturating_add(1)));
    let limit = u64::try_from(max_len).unwrap_or(u64::MAX).saturating_add(1);
    (&mut file)
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read secret file {shown}: {e}"))?;
    if buf.len() > max_len {
        return Err(format!(
            "secret file {shown} is larger than {max_len} bytes"
        ));
    }
    Ok(buf)
}

#[cfg(unix)]
fn check_permissions(path: &Path, meta: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "secret file {} has mode {mode:04o}, which lets the group or others access it; restrict it to the owner (for example `chmod 600`)",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "palisade-secret-test-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    const SENTINEL: &[u8] = b"sentinel-secret-value-1234";

    #[test]
    fn reads_owner_only_file() {
        let p = temp_file("ok", SENTINEL);
        let got = read_secret_file(&p, 1024).unwrap();
        assert_eq!(&got[..], SENTINEL);
    }

    #[test]
    fn oversized_file_is_refused_without_leaking() {
        let p = temp_file("big", SENTINEL);
        let e = read_secret_file(&p, 4).unwrap_err();
        assert!(e.contains("larger than 4 bytes"), "{e}");
        assert!(!e.contains("sentinel"), "{e}");
    }

    #[test]
    fn missing_file_names_the_path() {
        let e = read_secret_file(Path::new("/nonexistent/palisade/key.pem"), 10).unwrap_err();
        assert!(e.contains("/nonexistent/palisade/key.pem"), "{e}");
    }

    #[test]
    fn directory_is_refused() {
        let e = read_secret_file(&std::env::temp_dir(), 10).unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_access_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        for mode in [0o640, 0o604, 0o660, 0o644] {
            let p = temp_file(&format!("mode{mode:o}"), SENTINEL);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = read_secret_file(&p, 1024).unwrap_err();
            assert!(e.contains("chmod 600"), "{e}");
            assert!(!e.contains("sentinel"), "{e}");
        }
        let p = temp_file("mode400", SENTINEL);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_secret_file(&p, 1024).is_ok());
    }
}
