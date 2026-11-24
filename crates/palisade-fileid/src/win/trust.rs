//! The OS trust-verification cross-check (#48).
//!
//! [`verify_file`] asks the OS trust-verification API (`WinVerifyTrust`
//! with `WINTRUST_ACTION_GENERIC_VERIFY_V2`) about every embedded signature
//! the OS reads in a file: the primary signature, then each secondary
//! (nested) one, one call per signature with `WSS_VERIFY_SPECIFIC`. Its
//! result goes to [`crate::authenticode::cross_check`], which compares it
//! with this crate's own [`crate::authenticode::SignatureReport`] and never
//! changes it.
//!
//! The calls never show UI (`WTD_UI_NONE`), never check revocation
//! (`WTD_REVOKE_NONE`, plus `WTD_REVOCATION_CHECK_NONE` so not even cached
//! revocation data is consulted) and never fetch anything from the network
//! (`WTD_CACHE_ONLY_URL_RETRIEVAL`), so a cross-check cannot stall on a
//! slow or hostile URL in a certificate. Every verify is followed by a
//! close (`WTD_STATEACTION_CLOSE`), even when it fails, so no OS state is
//! leaked.
//!
//! The OS reads the file through the handle passed in, so the cross-check
//! looks at the same file object the caller hashed and parsed, whatever
//! happens to its path in between. The path is passed too, because the OS
//! uses it to pick the signature format by file extension.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WINTRUST_SIGNATURE_SETTINGS, WSS_GET_SECONDARY_SIG_COUNT, WSS_VERIFY_SPECIFIC,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};

use crate::authenticode::{MAX_OS_SIGNATURES, OsSignatureResult, OsTrustResult};

/// `size_of::<T>()` as the `u32` the OS structures' `cbStruct` fields
/// hold. Every structure here is far smaller than 4 GiB.
fn cb<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
}

/// One verify-and-close round for signature `index` of the file. Returns
/// the result code and the secondary-signature count the OS reported.
fn verify_index(file: &File, wide_path: &[u16], index: u32) -> (u32, u32) {
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: cb::<WINTRUST_FILE_INFO>(),
        pcwszFilePath: wide_path.as_ptr(),
        hFile: file.as_raw_handle(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut settings = WINTRUST_SIGNATURE_SETTINGS {
        cbStruct: cb::<WINTRUST_SIGNATURE_SETTINGS>(),
        dwIndex: index,
        dwFlags: WSS_VERIFY_SPECIFIC | WSS_GET_SECONDARY_SIG_COUNT,
        cSecondarySigs: 0,
        dwVerifiedSigIndex: 0,
        pCryptoPolicy: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: cb::<WINTRUST_DATA>(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        pSignatureSettings: &raw mut settings,
        ..WINTRUST_DATA::default()
    };
    data.Anonymous.pFile = &raw mut file_info;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `data` is a fully initialised `WINTRUST_DATA` whose
    // `cbStruct` is its own size. Its `pFile` points at `file_info`, whose
    // path is `wide_path` (NUL-terminated, see `verify_file`) and whose
    // handle is `file`'s open handle; its `pSignatureSettings` points at
    // `settings`. Every one of these lives on this stack frame or is
    // borrowed for it, so all outlive both calls. A null window handle
    // with `WTD_UI_NONE` shows no UI. The OS writes only into `data`
    // (`hWVTStateData`) and `settings`.
    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &raw mut action,
            (&raw mut data).cast(),
        )
    };
    let secondary = settings.cSecondarySigs;

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: the same structures as above, still alive, now with
    // `WTD_STATEACTION_CLOSE` and the `hWVTStateData` the verify call
    // stored. A close releases that state and is required after every
    // verify, whatever it returned; its own result carries no information.
    let _ = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &raw mut action,
            (&raw mut data).cast(),
        )
    };
    (status.cast_unsigned(), secondary)
}

/// Asks the OS about every embedded signature it reads in `file`, whose
/// path is `path`: the primary signature (index 0), then each of the
/// secondary signatures nested in it, up to
/// [`MAX_OS_SIGNATURES`] in total.
///
/// `file` must be open for reading. `path` should be the path it was
/// opened from; the OS uses its extension to pick the signature format.
/// The OS reads through `file`'s handle and may move its file position, so
/// a caller that reads `file` afterwards must seek first.
/// Fails only if `path` contains a NUL character. Every OS result,
/// including "no signature", is a result, not an error.
///
/// The result is a diagnostic: compare it with
/// [`crate::authenticode::cross_check`] and never use it to decide.
pub fn verify_file(file: &File, path: &Path) -> io::Result<OsTrustResult> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL character",
        ));
    }
    wide.push(0);

    let (code, secondary_count) = verify_index(file, &wide, 0);
    let mut result = OsTrustResult {
        signatures: vec![OsSignatureResult { index: 0, code }],
        secondary_count,
        truncated: secondary_count >= MAX_OS_SIGNATURES,
    };
    for index in 1..=secondary_count.min(MAX_OS_SIGNATURES - 1) {
        let (code, _) = verify_index(file, &wide, index);
        result.signatures.push(OsSignatureResult { index, code });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticode::{OsVerdict, code};

    /// A directory this test created, removed when dropped, even if the
    /// test panics.
    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_without_a_signature() {
        let dir = Scratch(
            std::env::temp_dir().join(format!("palisade-win-trust-{}", std::process::id())),
        );
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir(&dir.0).unwrap();
        let path = dir.0.join("plain.txt");
        std::fs::write(&path, b"not a signed file").unwrap();
        let file = File::open(&path).unwrap();
        let r = verify_file(&file, &path).unwrap();
        assert_eq!(r.signatures.len(), 1);
        // A text file has no signature format the OS knows.
        assert_ne!(r.signatures[0].verdict(), OsVerdict::Trusted);
        assert_ne!(r.signatures[0].code, code::S_OK);
        assert_eq!(r.secondary_count, 0);
    }

    #[test]
    fn a_path_with_a_nul_is_rejected() {
        let path = std::env::current_exe().unwrap();
        let file = File::open(&path).unwrap();
        let bad = Path::new("a\0b.exe");
        assert_eq!(
            verify_file(&file, bad).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
