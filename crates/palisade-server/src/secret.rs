//! Secret values and reading secret files (#227).
//!
//! Secrets (the TLS private key and the database passwords) are supplied as
//! paths, never as values in the configuration or the environment. This
//! module reads them into [`Secret`] buffers, which are wiped when dropped
//! and never print their contents. Its error messages name the path and the
//! problem, never any part of the contents.

use std::fmt;
use std::io::Read;
use std::path::Path;

use zeroize::Zeroize;

/// What [`Secret`]'s `Debug` and `Display` print instead of the value.
pub const REDACTED: &str = "[REDACTED]";

/// A secret value: wiped from memory when dropped, and printed as
/// `[REDACTED]` by `Debug` and `Display`, so it cannot reach a log line,
/// an error message or a panic message by accident. The value is only
/// reachable through [`Secret::expose`], which makes each use visible in
/// review.
///
/// It is deliberately not `Clone`, `Serialize` or `PartialEq`: a copy would
/// be another buffer to wipe, and a comparison should be constant-time.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps `value`.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The secret value. Keep the borrow short, and never log it.
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// The secret value, mutably, so it can be trimmed in place without a
    /// copy that would escape the wipe.
    pub const fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Reads a secret file of at most `max_len` bytes.
///
/// The file must be a regular file. On Unix it must not grant any
/// permission to the group or to others (mode `0600` or stricter), so a key
/// that other local users can read is refused rather than used. Windows ACL
/// checks are part of the secrets work in #227.
pub fn read_secret_file(path: &Path, max_len: usize) -> Result<Secret<Vec<u8>>, String> {
    let shown = path.display();
    let mut file = std::fs::File::open(path).map_err(|e| {
        // Windows cannot open a directory as a file, so the regular-file
        // check below never runs there. Report it the same way on every OS.
        if path.is_dir() {
            format!("secret file {shown} is not a regular file")
        } else {
            format!("cannot open secret file {shown}: {e}")
        }
    })?;
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
    // Read into a buffer allocated once at its final size and never grown,
    // so the contents are never copied into a buffer that is not zeroised.
    let mut buf = Secret::new(vec![0u8; max_len.saturating_add(1)]);
    let mut filled = 0;
    while let Some(spare) = buf.expose_mut().get_mut(filled..) {
        if spare.is_empty() {
            break;
        }
        match file.read(spare) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("cannot read secret file {shown}: {e}")),
        }
    }
    if filled > max_len {
        return Err(format!(
            "secret file {shown} is larger than {max_len} bytes"
        ));
    }
    // Shrinking never reallocates. The cut-off tail is zero already: it was
    // never written.
    buf.expose_mut().truncate(filled);
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
        assert_eq!(&got.expose()[..], SENTINEL);
    }

    #[test]
    fn exact_limit_is_accepted_without_growing_the_buffer() {
        let p = temp_file("exact", SENTINEL);
        let got = read_secret_file(&p, SENTINEL.len()).unwrap();
        assert_eq!(&got.expose()[..], SENTINEL);
        assert_eq!(got.expose().capacity(), SENTINEL.len() + 1);
    }

    #[test]
    fn secrets_never_print_their_value() {
        let p = temp_file("print", SENTINEL);
        let got = read_secret_file(&p, 1024).unwrap();
        for shown in [format!("{got:?}"), format!("{got}"), format!("{got:#?}")] {
            assert_eq!(shown, REDACTED);
        }
        let text = Secret::new(String::from("sentinel-secret-value-1234"));
        assert_eq!(format!("{text:?} {text}"), "[REDACTED] [REDACTED]");
        // Inside a derived `Debug`, too.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Login {
            user: &'static str,
            password: Secret<String>,
        }
        let login = Login {
            user: "palisade",
            password: text,
        };
        let shown = format!("{login:?}");
        assert!(!shown.contains("sentinel"), "{shown}");
        assert!(shown.contains("[REDACTED]"), "{shown}");
    }

    #[test]
    fn dropping_wipes_the_value() {
        // Zeroize clears the buffer in place before it is freed; check the
        // effect through the same API `Drop` calls.
        let mut s = Secret::new(SENTINEL.to_vec());
        s.expose_mut().zeroize();
        assert!(s.expose().is_empty());
        let mut s = Secret::new(String::from("abc"));
        s.expose_mut().zeroize();
        assert!(s.expose().is_empty());
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
