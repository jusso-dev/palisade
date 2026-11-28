//! What kind of Windows the agent runs on (#68): client or server, Server
//! Core, domain controller, multi-session host, and the device class the
//! budgets of #65 key on.
//!
//! Everything is read from the registry through
//! [`palisade_core::platform::Registry`], so it is decided the same way on
//! the mock as on Windows:
//!
//! | Fact | Source under `HKLM` |
//! |---|---|
//! | Product type | `SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType`: `WinNT` (client), `ServerNT` (member or standalone server), `LanmanNT` (domain controller) |
//! | Server Core | `SOFTWARE\…\Windows NT\CurrentVersion\InstallationType` = `Server Core` |
//! | Multi-session client | `…\CurrentVersion\EditionID` = `ServerRdsh` (it reports a server product type) |
//! | Session host role | `SYSTEM\CurrentControlSet\Control\Terminal Server\TSAppCompat` = 1 |
//!
//! **Fail closed (ADR 0018).** The profile only ever turns features *off*
//! that need a desktop (the per-session notifier on Server Core) or picks
//! budgets; it never relaxes enforcement. Where a fact cannot be read, the
//! choice that keeps the agent working is taken: an unknown product type is
//! treated as a client with a desktop, so nothing is switched off on a
//! guess, and the problem is reported.

#![forbid(unsafe_code)]

use std::fmt;

use palisade_core::platform::{Hive, Registry, RegistryValue};

pub mod os_ids;

use os_ids as os_keys;

/// The product type, from `ProductOptions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductType {
    /// `WinNT`: a client edition.
    Workstation,
    /// `ServerNT`: a member or standalone server, or a multi-session client.
    Server,
    /// `LanmanNT`: a domain controller.
    DomainController,
}

/// The device class: what budgets and defaults apply (#65).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    /// A single-user client.
    Workstation,
    /// A server (any role, including domain controllers).
    Server,
    /// Several interactive users at once: a session host server or a
    /// multi-session client edition.
    MultiSession,
}

impl DeviceClass {
    /// The name used in policy and events.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workstation => "Workstation",
            Self::Server => "Server",
            Self::MultiSession => "MultiSession",
        }
    }
}

impl fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The platform profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The product type. `None` if it could not be read.
    pub product_type: Option<ProductType>,
    /// Server Core: no desktop shell, so no notifier or session helper.
    pub server_core: bool,
    /// A multi-session client edition (`ServerRdsh`).
    pub multi_session_edition: bool,
    /// The session host role is on.
    pub session_host: bool,
    /// What could not be read, for the agent's log. Never fatal.
    pub problems: Vec<String>,
}

impl Profile {
    /// Reads the profile through `registry`.
    #[must_use]
    pub fn read(registry: &dyn Registry) -> Self {
        let mut problems = Vec::new();
        let mut text = |path: &str, name: &str| match registry.value(Hive::LocalMachine, path, name)
        {
            Ok(Some(RegistryValue::String(s))) => Some(s),
            Ok(None) => None,
            Ok(Some(_)) => {
                problems.push(format!("{name} is not a string"));
                None
            }
            Err(e) => {
                problems.push(format!("cannot read {name}: {e}"));
                None
            }
        };
        let product = text(os_keys::PRODUCT_OPTIONS, "ProductType");
        let installation = text(os_keys::CURRENT_VERSION, "InstallationType");
        let edition = text(os_keys::CURRENT_VERSION, "EditionID");
        let product_type = match product.as_deref() {
            Some(p) if p.eq_ignore_ascii_case("WinNT") => Some(ProductType::Workstation),
            Some(p) if p.eq_ignore_ascii_case("ServerNT") => Some(ProductType::Server),
            Some(p) if p.eq_ignore_ascii_case("LanmanNT") => Some(ProductType::DomainController),
            Some(_) => {
                problems.push("ProductType has an unknown value".to_owned());
                None
            }
            None => {
                problems.push("ProductType is missing".to_owned());
                None
            }
        };
        let session_host =
            match registry.value(Hive::LocalMachine, os_keys::TERMINAL_SERVER, "TSAppCompat") {
                Ok(Some(RegistryValue::Dword(v))) => v == 1,
                Ok(_) => false,
                Err(e) => {
                    problems.push(format!("cannot read TSAppCompat: {e}"));
                    false
                }
            };
        Self {
            product_type,
            // Only a server can be Server Core; a client edition never
            // reports it, and a value we cannot place does not switch the
            // desktop off.
            server_core: product_type.is_some_and(|p| p != ProductType::Workstation)
                && installation
                    .as_deref()
                    .is_some_and(|i| i.eq_ignore_ascii_case("Server Core")),
            multi_session_edition: edition
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case("ServerRdsh")),
            session_host,
            problems,
        }
    }

    /// The device class.
    #[must_use]
    pub fn device_class(&self) -> DeviceClass {
        if self.multi_session_edition || (self.session_host && !self.server_core) {
            DeviceClass::MultiSession
        } else {
            match self.product_type {
                Some(ProductType::Server | ProductType::DomainController) => DeviceClass::Server,
                Some(ProductType::Workstation) | None => DeviceClass::Workstation,
            }
        }
    }

    /// Whether this is a domain controller.
    #[must_use]
    pub fn domain_controller(&self) -> bool {
        self.product_type == Some(ProductType::DomainController)
    }

    /// Whether the agent should start per-session user-interface helpers
    /// (the notifier, #146, and the session helper, #56). Not on Server
    /// Core, which has no desktop shell.
    #[must_use]
    pub fn interactive_helpers(&self) -> bool {
        !self.server_core
    }

    /// The profile of the running system: the registry on Windows. Off
    /// Windows, a workstation with nothing read.
    #[must_use]
    pub fn current() -> Self {
        #[cfg(windows)]
        {
            Self::read(&crate::platform::windows::WindowsRegistry)
        }
        #[cfg(not(windows))]
        {
            Self {
                product_type: Some(ProductType::Workstation),
                server_core: false,
                multi_session_edition: false,
                session_host: false,
                problems: Vec::new(),
            }
        }
    }

    /// Logs the profile and anything that could not be read.
    pub fn log(&self) {
        tracing::info!(
            device_class = %self.device_class(),
            product_type = ?self.product_type,
            server_core = self.server_core,
            domain_controller = self.domain_controller(),
            session_host = self.session_host,
            multi_session_edition = self.multi_session_edition,
            "platform profile"
        );
        for problem in &self.problems {
            tracing::warn!(%problem, "platform profile: a fact could not be read");
        }
    }
}

#[cfg(test)]
mod tests;
