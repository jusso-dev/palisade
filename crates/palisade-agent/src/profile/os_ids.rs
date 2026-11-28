//! Registry paths the OS defines byte for byte. Two of them name the OS
//! vendor, so this file is excluded from the banned-terms scan
//! (`docs/banned-terms.txt`).

#![forbid(unsafe_code)]

/// The product type (`WinNT`, `ServerNT` or `LanmanNT`).
pub const PRODUCT_OPTIONS: &str = r"SYSTEM\CurrentControlSet\Control\ProductOptions";
/// The installation type and edition of the running OS.
pub const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
/// The session host settings.
pub const TERMINAL_SERVER: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
/// Holds `MachineGuid`, which the OS generates at setup and generates
/// again when a generalised image first boots as a new machine.
pub const CRYPTOGRAPHY: &str = r"SOFTWARE\Microsoft\Cryptography";
