//! The agent's implementations of the `palisade_core::platform` traits.
//!
//! `system` holds the ones built on the standard library and safe wrapper
//! crates, which build and run on every OS. `signature` is the
//! `SignatureVerifier`, which delegates to `palisade_fileid` and so also
//! runs on every OS. `windows` (compiled on Windows only) holds the ones
//! that need the OS: the registry, identity (`IdentityProvider`),
//! processes (`ProcessInfo`) and the file-system context
//! (`WindowsFileSystem`). Each passes the
//! contract checks in `palisade_core::test_util::contract` on the CI
//! runners of its OS.
//!
//! `nt` decodes the raw token and process records the Windows backends
//! read through `palisade_agent::ffi`. It has no `unsafe` code and no OS
//! calls, so it is compiled, and tested, on every OS.
//!
//! The simulator (`palisade-agent --simulate`, feature `test-util`) runs the
//! agent's event building on the mocks.

#![forbid(unsafe_code)]

pub(crate) mod connection;
pub(crate) mod nt;
mod signature;
mod system;
#[cfg(windows)]
pub mod windows;

pub use signature::{DEFAULT_MAX_FILE_SIZE, FileidSignatures, SignatureSettings};
#[cfg(windows)]
pub(crate) use system::absolute;
pub use system::{StdEnvironment, StdFile, StdFileSystem, SystemClock};

use palisade_core::platform::{ErrorKind, PlatformError};

/// Converts an I/O error, keeping its kind.
pub(crate) fn io_error(error: &std::io::Error, context: &str) -> PlatformError {
    let kind = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorKind::AccessDenied,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidFilename => {
            ErrorKind::InvalidInput
        }
        std::io::ErrorKind::Unsupported => ErrorKind::Unsupported,
        _ => ErrorKind::Other,
    };
    PlatformError::new(kind, format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_keep_their_kind() {
        let kind = |k: std::io::ErrorKind| io_error(&std::io::Error::from(k), "x").kind();
        assert_eq!(kind(std::io::ErrorKind::NotFound), ErrorKind::NotFound);
        assert_eq!(
            kind(std::io::ErrorKind::PermissionDenied),
            ErrorKind::AccessDenied
        );
        // An allocation failure is not a size limit.
        assert_eq!(kind(std::io::ErrorKind::OutOfMemory), ErrorKind::Other);
    }
}
