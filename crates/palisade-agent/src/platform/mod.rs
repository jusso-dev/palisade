//! The agent's implementations of the `palisade_core::platform` traits.
//!
//! These use only the standard library and safe wrapper crates, so they
//! build and run on every OS, and their contract tests
//! (`palisade_core::test_util::contract`) run on every CI runner, Windows
//! included. Where Windows needs something else, the difference lives in
//! `windows` (compiled on Windows only).
//!
//! Not here yet, because each needs Windows FFI (ADR 0011) or comes with the
//! M1 code that consumes it:
//!
//! - `FileSystem` owner SIDs, security descriptors, alternate data streams,
//!   file IDs and USNs on Windows: they return [`ErrorKind::Unsupported`]
//!   until the agent is wired to `palisade_fileid::win` (#54) by the file
//!   inventory (#60).
//! - `IdentityProvider`, `ProcessInfo` and `SignatureVerifier`: with the
//!   process tracker, which reads tokens and resolves each image's identity
//!   (#59).
//! - `Registry`: with registry conditions in the evaluation context (#59).
//!
//! Until then, the simulator (`palisade-agent --simulate`, feature
//! `test-util`) runs the agent's event building on the mocks.

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
        _ => ErrorKind::Other,
    };
    PlatformError::new(kind, format!("{context}: {error}"))
}
