//! Identifiers that Windows itself defines and requires byte for byte.
//!
//! The application manifest schema only recognises its elements in fixed XML
//! namespaces, and the per-machine autostart key lives at a fixed registry
//! path. Both contain the operating system vendor's name, which
//! `docs/NAMING.md` otherwise keeps out of the repository. Like the policy
//! compilers' schema literals, they are allowed here because the OS matches
//! them exactly, and this is the only file that holds them, so the
//! banned-terms check can allow exactly one path.

/// `assembly` and `trustInfo`: the manifest root namespace.
pub const ASM_V1: &str = "urn:schemas-microsoft-com:asm.v1";
/// `trustInfo/security/requestedPrivileges`.
pub const ASM_V3: &str = "urn:schemas-microsoft-com:asm.v3";
/// `compatibility/application/supportedOS`.
pub const COMPATIBILITY_V1: &str = "urn:schemas-microsoft-com:compatibility.v1";
/// `application/windowsSettings/longPathAware`.
pub const WINDOWS_SETTINGS_2016: &str = "http://schemas.microsoft.com/SMI/2016/WindowsSettings";

/// The key under `HKLM` whose `InstallationType` value is `Server Core` on a
/// server installed without the desktop shell (#68).
pub const OS_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// The per-machine `Run` key under `HKLM`: every user's session starts the
/// programs listed here at sign-in.
pub const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
