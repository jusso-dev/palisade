//! The Windows implementations (compiled on Windows only).
//!
//! - [`WindowsRegistry`], and the host name, domain and OS version the
//!   environment reports, through safe wrapper crates.
//! - [`WindowsIdentity`]: tokens, account names, local groups and the
//!   directory group cache.
//! - [`WindowsProcesses`]: process records keyed by process ID and
//!   creation time, so a reused ID is never mistaken for the process.
//! - [`WindowsFileSystem`]: the standard-library reads, with file IDs,
//!   volume serials, USNs, owners, security descriptors and alternate data
//!   streams through `palisade_fileid::win`.
//!
//! The identity and process backends call the OS through
//! `palisade_agent::ffi`, the agent's one module with `unsafe` code (ADR
//! 0011), and decode what it returns with the portable `platform::nt`.
//! Account names come from `palisade_fileid::win`.

mod fs;
mod identity;
mod process;
mod registry;

pub use fs::{WindowsFile, WindowsFileSystem};
pub use identity::WindowsIdentity;
pub use process::WindowsProcesses;
pub use registry::{WindowsRegistry, domain, hostname, os_version};

use super::io_error as os_error;
