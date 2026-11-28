//! Golden images and clones (#68): device identity on VDI, non-persistent
//! and cloned machines.
//!
//! **Sealing.** Before an image is generalised and captured, an
//! administrator stops the agent and runs `palisade-agent --seal-image`.
//! [`seal`] removes everything that identifies *this* device, so that no
//! two clones share it, and writes a seal marker:
//!
//! - removed: the files in [`PER_DEVICE_FILES`] (the stored enrolment
//!   token; the device key, certificate and ID that enrolment, #223, will
//!   write) and the folders in [`PER_DEVICE_DIRS`] (the event queue);
//! - kept: the policy cache, so a clone enforces the image's policy before
//!   its first check-in, the inventory and its caches, as the template's
//!   baseline, the install-time settings, and the logs;
//! - written: [`SEAL_FILE`], recording the machine GUID the OS had when
//!   the image was sealed.
//!
//! **Clone detection** ([`identity_state`]). At every start the agent
//! compares the machine GUID (`HKLM\…\Cryptography\MachineGuid`, which
//! the OS generates again when a generalised image first boots) with the
//! one in the seal marker, or with the one recorded when the device
//! identity was created ([`IDENTITY_FILE`]):
//!
//! - a seal marker on a machine whose GUID **differs** is a clone's first
//!   boot: it must get a new identity ([`IdentityState::FirstBootClone`]);
//! - a seal marker on the **same** machine is the image itself, still
//!   sealed: it must not enrol, or the template would get an identity
//!   every clone then inherits ([`IdentityState::SealedTemplate`]);
//! - a device identity whose recorded GUID differs from the machine's was
//!   copied from another machine, for example by cloning an image that was
//!   never sealed: it must not be used ([`IdentityState::CopiedIdentity`]).
//!
//! Each fails closed (ADR 0018): an identity that may belong to another
//! machine is never used, and an unreadable GUID never counts as a match.
//! Several signals (SMBIOS UUID, machine SID) and server-side duplicate
//! detection come with enrolment (#223) and the server (#10); the machine
//! GUID alone is what the agent can check today without new FFI.

#![forbid(unsafe_code)]

use std::{fmt, fs, io, path::Path};

use palisade_core::platform::{Hive, Registry, RegistryValue};

use crate::profile::os_ids as os_keys;

/// The seal marker, in the data folder.
pub const SEAL_FILE: &str = "image.sealed";
/// The machine GUID the device identity was created on, in the data
/// folder. Enrolment (#223) writes it with the identity
/// ([`record_identity_machine`]).
pub const IDENTITY_FILE: &str = "identity.machine";
/// Per-device files [`seal`] removes, relative to the data folder.
pub const PER_DEVICE_FILES: &[&str] = &[
    crate::bootstrap::PROTECTED_FILE,
    crate::bootstrap::HANDOFF_FILE,
    IDENTITY_FILE,
    "device.id",
    "device.key",
    "device.crt",
];
/// Per-device folders [`seal`] empties and removes, relative to the data
/// folder: the event queue, whose events belong to the template.
pub const PER_DEVICE_DIRS: &[&str] = &["queue"];
/// Folders the seal keeps: the policy cache, and the logs.
pub const KEPT_DIRS: &[&str] = &["policy", "logs"];

/// The longest seal or identity marker read.
const MAX_MARKER_BYTES: u64 = 256;

/// What the agent may do with its device identity at this start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityState {
    /// No seal, and any identity was created on this machine: carry on.
    Normal,
    /// The image itself, still sealed: do not enrol.
    SealedTemplate,
    /// A clone's first boot: create a new identity and enrol, then clear
    /// the seal ([`finish_reidentify`]).
    FirstBootClone,
    /// A device identity from another machine: do not use it; clear it
    /// and enrol again.
    CopiedIdentity,
    /// The machine GUID cannot be read, so whether this is the machine
    /// the identity belongs to is unknown: do not use the identity.
    Unknown(String),
}

impl IdentityState {
    /// Whether the existing device identity may be used.
    #[must_use]
    pub fn identity_usable(&self) -> bool {
        *self == Self::Normal
    }

    /// Whether the agent may enrol now.
    #[must_use]
    pub fn may_enrol(&self) -> bool {
        matches!(
            self,
            Self::Normal | Self::FirstBootClone | Self::CopiedIdentity
        )
    }
}

impl fmt::Display for IdentityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => f.write_str("normal"),
            Self::SealedTemplate => f.write_str("sealed image template: not enrolling"),
            Self::FirstBootClone => f.write_str("first boot of a clone: new identity needed"),
            Self::CopiedIdentity => {
                f.write_str("the device identity was created on another machine: not using it")
            }
            Self::Unknown(why) => write!(f, "cannot check the machine identity: {why}"),
        }
    }
}

/// The machine GUID, from the registry.
///
/// # Errors
///
/// A message if it is missing, empty or not a string, or the read failed.
pub fn machine_guid(registry: &dyn Registry) -> Result<String, String> {
    match registry.value(Hive::LocalMachine, os_keys::CRYPTOGRAPHY, "MachineGuid") {
        Ok(Some(RegistryValue::String(s))) if !s.trim().is_empty() => {
            Ok(s.trim().to_ascii_lowercase())
        }
        Ok(Some(RegistryValue::String(_)) | None) => Err("MachineGuid is missing".to_owned()),
        Ok(Some(_)) => Err("MachineGuid is not a string".to_owned()),
        Err(e) => Err(format!("cannot read MachineGuid: {e}")),
    }
}

/// Decides the identity state from the data folder and the registry (see
/// the module docs).
///
/// # Errors
///
/// The I/O error if a marker exists but cannot be read.
pub fn identity_state(registry: &dyn Registry, data_dir: &Path) -> io::Result<IdentityState> {
    let sealed = read_marker(&data_dir.join(SEAL_FILE))?;
    let identity = read_marker(&data_dir.join(IDENTITY_FILE))?;
    if sealed.is_none() && identity.is_none() {
        return Ok(IdentityState::Normal);
    }
    let guid = match machine_guid(registry) {
        Ok(guid) => guid,
        Err(why) => return Ok(IdentityState::Unknown(why)),
    };
    if let Some(sealed_on) = sealed {
        return Ok(if sealed_on == guid {
            IdentityState::SealedTemplate
        } else {
            IdentityState::FirstBootClone
        });
    }
    Ok(match identity {
        Some(created_on) if created_on != guid => IdentityState::CopiedIdentity,
        _ => IdentityState::Normal,
    })
}

/// What [`seal`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SealReport {
    /// Per-device files and folders removed, relative to the data folder.
    pub removed: Vec<String>,
}

/// Seals the image in `data_dir` (see the module docs). The agent must be
/// stopped. Sealing again is harmless.
///
/// # Errors
///
/// The I/O error if the machine GUID cannot be read (nothing is changed),
/// or a per-device item cannot be removed. The seal marker is written
/// last, so a failed seal never looks sealed.
pub fn seal(registry: &dyn Registry, data_dir: &Path) -> io::Result<SealReport> {
    let guid = machine_guid(registry).map_err(io::Error::other)?;
    let mut report = SealReport::default();
    for name in PER_DEVICE_FILES {
        let path = data_dir.join(name);
        match fs::remove_file(&path) {
            Ok(()) => report.removed.push((*name).to_owned()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    for name in PER_DEVICE_DIRS {
        let path = data_dir.join(name);
        if path.is_dir() {
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                let p = entry.path();
                if entry.file_type()?.is_dir() {
                    fs::remove_dir_all(&p)?;
                } else {
                    fs::remove_file(&p)?;
                }
            }
            report.removed.push(format!("{name}/*"));
        }
    }
    write_marker(&data_dir.join(SEAL_FILE), &guid)?;
    Ok(report)
}

/// After a clone has a new identity: records the machine it was created
/// on and removes the seal marker.
///
/// # Errors
///
/// The I/O error. If recording fails, the seal stays, and the next start
/// treats the machine as a first-boot clone again.
pub fn finish_reidentify(registry: &dyn Registry, data_dir: &Path) -> io::Result<()> {
    record_identity_machine(registry, data_dir)?;
    match fs::remove_file(data_dir.join(SEAL_FILE)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Records the machine GUID the device identity was created on. Enrolment
/// (#223) calls it when it stores a new identity.
///
/// # Errors
///
/// The I/O error, or the machine GUID cannot be read.
pub fn record_identity_machine(registry: &dyn Registry, data_dir: &Path) -> io::Result<()> {
    let guid = machine_guid(registry).map_err(io::Error::other)?;
    write_marker(&data_dir.join(IDENTITY_FILE), &guid)
}

fn read_marker(path: &Path) -> io::Result<Option<String>> {
    use io::Read as _;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut text = String::new();
    file.take(MAX_MARKER_BYTES).read_to_string(&mut text)?;
    // An empty or damaged marker still marks the state; it just matches
    // no machine, which is the fail-closed reading.
    Ok(Some(text.trim().to_ascii_lowercase()))
}

fn write_marker(path: &Path, guid: &str) -> io::Result<()> {
    use io::Write as _;
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(guid.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// `palisade-agent --seal-image`: seals the image in the agent's data
/// folder. Run by an administrator, with the agent stopped, before the
/// image is generalised and captured.
#[cfg(windows)]
pub fn run_seal() -> std::process::ExitCode {
    let dir = match crate::config::default_path() {
        Ok(Some(path)) => path.parent().map(Path::to_path_buf),
        Ok(None) => None,
        Err(e) => {
            eprintln!("palisade-agent: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let Some(dir) = dir else {
        eprintln!("palisade-agent: cannot find the data folder");
        return std::process::ExitCode::FAILURE;
    };
    match seal(&crate::platform::windows::WindowsRegistry, &dir) {
        Ok(report) => {
            for item in &report.removed {
                println!("removed {item}");
            }
            println!(
                "sealed {}: clones get a new device identity on first boot",
                dir.display()
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("palisade-agent: cannot seal the image: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// At start-up: logs the platform profile and the identity state. Never
/// fatal; enrolment (#223) acts on [`identity_state`].
#[cfg(windows)]
pub fn on_start() {
    let registry = crate::platform::windows::WindowsRegistry;
    crate::profile::Profile::read(&registry).log();
    let Ok(Some(path)) = crate::config::default_path() else {
        return;
    };
    let Some(dir) = path.parent() else {
        return;
    };
    match identity_state(&registry, dir) {
        Ok(IdentityState::Normal) => {}
        Ok(state) => tracing::warn!(%state, "device identity"),
        Err(e) => tracing::error!(error = %e, "cannot read the image seal or identity marker"),
    }
}

#[cfg(test)]
mod tests;
