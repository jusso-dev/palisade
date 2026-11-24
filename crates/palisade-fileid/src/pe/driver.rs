//! Kernel driver detection (#45).
//!
//! No single field marks a kernel-mode driver, so [`classify`] combines the
//! signals the loader and driver tooling leave. An image is a kernel
//! driver when its subsystem is `NATIVE` **and** it has a kernel signal:
//! it imports a kernel-mode module, it has an `INIT` section, or it sets
//! `IMAGE_FILE_SYSTEM`. Native user-mode programs (session and boot-time
//! tools) are also `NATIVE`, but they import only `ntdll.dll`, so the
//! subsystem alone is not enough. A non-native image is never classed as
//! a driver, whatever it imports.
//!
//! The reasons are returned too, so a report can say why.

#![forbid(unsafe_code)]

use super::Section;
use super::imports::ImportInfo;
use super::types::{FileCharacteristics, Subsystem};

/// Modules only kernel-mode code imports. Compared ASCII
/// case-insensitively.
pub const KERNEL_MODULES: [&str; 7] = [
    "ntoskrnl.exe",
    "hal.dll",
    "fltmgr.sys",
    "wdfldr.sys",
    "ndis.sys",
    "ksecdd.sys",
    "cng.sys",
];

/// One reason an image is (or looks like) a kernel driver.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DriverSignal {
    /// The subsystem is `NATIVE`.
    NativeSubsystem,
    /// It imports this kernel-mode module (lowercase).
    ImportsKernelModule(String),
    /// It has an `INIT` section (discarded after driver initialisation).
    InitSection,
    /// `IMAGE_FILE_SYSTEM` is set.
    SystemFile,
}

/// The kernel driver verdict ([`super::PeInfo::driver`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverClass {
    /// Whether the image is a kernel-mode driver.
    pub is_kernel_driver: bool,
    /// Every signal found, in a fixed order.
    pub signals: Vec<DriverSignal>,
}

/// Classifies an image from its subsystem, characteristics, sections and
/// imports. `imports` is `None` when the image has no import table.
#[must_use]
pub fn classify(
    subsystem: Subsystem,
    characteristics: FileCharacteristics,
    sections: &[Section],
    imports: Option<&ImportInfo>,
) -> DriverClass {
    let mut signals = Vec::new();
    let native = subsystem == Subsystem::Native;
    if native {
        signals.push(DriverSignal::NativeSubsystem);
    }
    if let Some(imports) = imports {
        for module in KERNEL_MODULES {
            if imports.imports_module(module) {
                signals.push(DriverSignal::ImportsKernelModule(module.to_owned()));
            }
        }
    }
    if sections.iter().any(|s| s.raw_name.starts_with(b"INIT\0")) {
        signals.push(DriverSignal::InitSection);
    }
    if characteristics.is_system() {
        signals.push(DriverSignal::SystemFile);
    }
    let kernel_signal = signals
        .iter()
        .any(|s| !matches!(s, DriverSignal::NativeSubsystem));
    DriverClass {
        is_kernel_driver: native && kernel_signal,
        signals,
    }
}
