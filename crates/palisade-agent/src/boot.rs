//! Safe-mode boot detection.
//!
//! Windows creates `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option`
//! only for a safe-mode boot, with the DWORD `OptionValue` saying which
//! kind. The agent reads it once at start-up. In safe mode the supervisor
//! reports [`AgentState::SafeMode`](crate::lifecycle::AgentState::SafeMode)
//! for the whole boot, and enforcement components (E06, E08) apply
//! [`SafeModeBehaviour`](crate::config::SafeModeBehaviour).
//!
//! A registry read that fails is treated as a normal boot and logged. That
//! is the fail-closed reading (ADR 0018): safe mode can only relax
//! enforcement (the default behaviour is audit only), so a fact the agent
//! could not read must not put it there.

#![forbid(unsafe_code)]

use palisade_core::platform::{Hive, Registry, RegistryValue};

/// The key that exists only during a safe-mode boot.
pub const SAFE_BOOT_OPTION_KEY: &str = r"SYSTEM\CurrentControlSet\Control\SafeBoot\Option";
/// Its value naming the kind of safe mode.
pub const SAFE_BOOT_OPTION_VALUE: &str = "OptionValue";

/// How Windows was booted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// A normal boot.
    Normal,
    /// Safe mode (`OptionValue` 1).
    SafeMinimal,
    /// Safe mode with networking (`OptionValue` 2).
    SafeNetwork,
    /// Another safe-boot kind, such as directory services repair, or a
    /// missing or unexpected `OptionValue` under an existing key.
    SafeOther,
}

impl BootMode {
    /// Whether this is any kind of safe-mode boot.
    pub fn is_safe(self) -> bool {
        self != Self::Normal
    }
}

/// Reads the boot mode from `registry`. A read error is
/// [`BootMode::Normal`], logged (see the module docs).
pub fn boot_mode(registry: &dyn Registry) -> BootMode {
    match read(registry) {
        Ok(mode) => mode,
        Err(e) => {
            tracing::warn!(error = %e, "cannot read the safe-boot option; assuming a normal boot");
            BootMode::Normal
        }
    }
}

fn read(registry: &dyn Registry) -> palisade_core::platform::Result<BootMode> {
    if !registry.key_exists(Hive::LocalMachine, SAFE_BOOT_OPTION_KEY)? {
        return Ok(BootMode::Normal);
    }
    // The key exists, so this is a safe boot whatever its value says.
    Ok(
        match registry.value(
            Hive::LocalMachine,
            SAFE_BOOT_OPTION_KEY,
            SAFE_BOOT_OPTION_VALUE,
        ) {
            Ok(Some(RegistryValue::Dword(1))) => BootMode::SafeMinimal,
            Ok(Some(RegistryValue::Dword(2))) => BootMode::SafeNetwork,
            _ => BootMode::SafeOther,
        },
    )
}

/// The boot mode of the running system: the registry on Windows, always
/// [`BootMode::Normal`] elsewhere.
pub fn current() -> BootMode {
    #[cfg(windows)]
    {
        boot_mode(&crate::platform::windows::WindowsRegistry)
    }
    #[cfg(not(windows))]
    {
        BootMode::Normal
    }
}

#[cfg(test)]
mod tests {
    use palisade_core::{
        platform::{ErrorKind, PlatformError},
        test_util::MockRegistry,
    };

    use super::*;

    fn with_option(value: Option<RegistryValue>) -> MockRegistry {
        let mut registry = MockRegistry::new();
        match value {
            Some(v) => registry.set_value(
                Hive::LocalMachine,
                SAFE_BOOT_OPTION_KEY,
                SAFE_BOOT_OPTION_VALUE,
                v,
            ),
            None => registry.create_key(Hive::LocalMachine, SAFE_BOOT_OPTION_KEY),
        }
        registry
    }

    #[test]
    fn the_option_key_marks_a_safe_boot() {
        let mut normal = MockRegistry::new();
        normal.create_key(
            Hive::LocalMachine,
            r"SYSTEM\CurrentControlSet\Control\SafeBoot",
        );
        assert_eq!(boot_mode(&normal), BootMode::Normal);
        assert!(!BootMode::Normal.is_safe());
        for (value, mode) in [
            (Some(RegistryValue::Dword(1)), BootMode::SafeMinimal),
            (Some(RegistryValue::Dword(2)), BootMode::SafeNetwork),
            (Some(RegistryValue::Dword(3)), BootMode::SafeOther),
            (Some(RegistryValue::String("1".into())), BootMode::SafeOther),
            (None, BootMode::SafeOther),
        ] {
            let mode_read = boot_mode(&with_option(value.clone()));
            assert_eq!(mode_read, mode, "{value:?}");
            assert!(mode_read.is_safe());
        }
    }

    struct Broken;

    impl Registry for Broken {
        fn key_exists(&self, _: Hive, _: &str) -> palisade_core::platform::Result<bool> {
            Err(PlatformError::new(ErrorKind::AccessDenied, "denied"))
        }
        fn value(
            &self,
            _: Hive,
            _: &str,
            _: &str,
        ) -> palisade_core::platform::Result<Option<RegistryValue>> {
            Err(PlatformError::new(ErrorKind::AccessDenied, "denied"))
        }
        fn subkeys(&self, _: Hive, _: &str) -> palisade_core::platform::Result<Vec<String>> {
            Err(PlatformError::new(ErrorKind::AccessDenied, "denied"))
        }
    }

    #[test]
    fn an_unreadable_registry_is_a_normal_boot() {
        assert_eq!(boot_mode(&Broken), BootMode::Normal);
    }

    #[cfg(not(windows))]
    #[test]
    fn other_oses_always_boot_normally() {
        assert_eq!(current(), BootMode::Normal);
    }
}
