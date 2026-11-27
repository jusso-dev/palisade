//! The agent's implementations of the `palisade_core::platform` traits.
//!
//! `system` holds the ones built on the standard library and safe wrapper
//! crates, which build and run on every OS. `windows` (compiled on Windows
//! only) holds the ones that need the OS: the registry, identity
//! (`IdentityProvider`) and processes (`ProcessInfo`). Each passes the
//! contract checks in `palisade_core::test_util::contract` on the CI
//! runners of its OS.
//!
//! `nt` decodes the raw token and process records the Windows backends
//! read through `palisade_agent::ffi`. It has no `unsafe` code and no OS
//! calls, so it is compiled, and tested, on every OS.
//!
//! Not here yet:
//!
//! - `SignatureVerifier`, and the `FileSystem` owner SIDs, security
//!   descriptors, alternate data streams, file IDs and USNs on Windows,
//!   through `palisade_fileid` (#29, next). Until then those return
//!   [`ErrorKind::Unsupported`].
//!
//! The simulator (`palisade-agent --simulate`, feature `test-util`) runs the
//! agent's event building on the mocks.

#![forbid(unsafe_code)]

pub(crate) mod nt;
mod system;
#[cfg(windows)]
pub mod windows;

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
        std::io::ErrorKind::OutOfMemory => ErrorKind::TooLarge,
        _ => ErrorKind::Other,
    };
    PlatformError::new(kind, format!("{context}: {error}"))
}
