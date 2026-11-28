use palisade_core::{
    platform::{ErrorKind, PlatformError},
    test_util::MockRegistry,
};

use super::*;

fn reg(
    product: Option<&str>,
    installation: Option<&str>,
    edition: Option<&str>,
    ts: Option<u32>,
) -> MockRegistry {
    let mut r = MockRegistry::new();
    let s = |v: &str| RegistryValue::String(v.to_owned());
    if let Some(p) = product {
        r.set_value(
            Hive::LocalMachine,
            os_keys::PRODUCT_OPTIONS,
            "ProductType",
            s(p),
        );
    }
    if let Some(i) = installation {
        r.set_value(
            Hive::LocalMachine,
            os_keys::CURRENT_VERSION,
            "InstallationType",
            s(i),
        );
    }
    if let Some(e) = edition {
        r.set_value(
            Hive::LocalMachine,
            os_keys::CURRENT_VERSION,
            "EditionID",
            s(e),
        );
    }
    if let Some(t) = ts {
        r.set_value(
            Hive::LocalMachine,
            os_keys::TERMINAL_SERVER,
            "TSAppCompat",
            RegistryValue::Dword(t),
        );
    }
    r
}

#[test]
fn platforms_map_to_their_class() {
    // (product, installation, edition, TSAppCompat) -> (class, core, dc, helpers)
    let cases = [
        // Client.
        (
            reg(Some("WinNT"), Some("Client"), Some("Enterprise"), Some(0)),
            DeviceClass::Workstation,
            false,
            false,
        ),
        // Server with a desktop.
        (
            reg(
                Some("ServerNT"),
                Some("Server"),
                Some("ServerDatacenter"),
                Some(0),
            ),
            DeviceClass::Server,
            false,
            false,
        ),
        // Server Core.
        (
            reg(
                Some("ServerNT"),
                Some("Server Core"),
                Some("ServerStandard"),
                None,
            ),
            DeviceClass::Server,
            true,
            false,
        ),
        // A domain controller on Server Core.
        (
            reg(
                Some("LanmanNT"),
                Some("Server Core"),
                Some("ServerStandard"),
                None,
            ),
            DeviceClass::Server,
            true,
            true,
        ),
        // A domain controller with a desktop.
        (
            reg(Some("LanmanNT"), Some("Server"), None, None),
            DeviceClass::Server,
            false,
            true,
        ),
        // A session host server.
        (
            reg(
                Some("ServerNT"),
                Some("Server"),
                Some("ServerDatacenter"),
                Some(1),
            ),
            DeviceClass::MultiSession,
            false,
            false,
        ),
        // A multi-session client edition: a server product type.
        (
            reg(
                Some("ServerNT"),
                Some("Client"),
                Some("ServerRdsh"),
                Some(1),
            ),
            DeviceClass::MultiSession,
            false,
            false,
        ),
        (
            reg(Some("ServerNT"), Some("Client"), Some("serverrdsh"), None),
            DeviceClass::MultiSession,
            false,
            false,
        ),
        // Server Core cannot host desktop sessions; the role flag alone does
        // not make it multi-session.
        (
            reg(Some("ServerNT"), Some("Server Core"), None, Some(1)),
            DeviceClass::Server,
            true,
            false,
        ),
        // A client never counts as Server Core, whatever it reports.
        (
            reg(Some("WinNT"), Some("Server Core"), None, None),
            DeviceClass::Workstation,
            false,
            false,
        ),
    ];
    for (r, class, core, dc) in cases {
        let p = Profile::read(&r);
        assert!(p.problems.is_empty(), "{p:?}");
        assert_eq!(p.device_class(), class, "{p:?}");
        assert_eq!(p.server_core, core, "{p:?}");
        assert_eq!(p.interactive_helpers(), !core, "{p:?}");
        assert_eq!(p.domain_controller(), dc, "{p:?}");
    }
}

#[test]
fn what_cannot_be_read_never_switches_a_feature_off() {
    for r in [
        reg(None, Some("Server Core"), None, None),
        reg(Some("Something"), Some("Server Core"), None, None),
    ] {
        let p = Profile::read(&r);
        assert_eq!(p.product_type, None);
        assert!(!p.server_core);
        assert!(p.interactive_helpers());
        assert_eq!(p.device_class(), DeviceClass::Workstation);
        assert_eq!(p.problems.len(), 1, "{p:?}");
    }
    let mut wrong = MockRegistry::new();
    wrong.set_value(
        Hive::LocalMachine,
        os_keys::PRODUCT_OPTIONS,
        "ProductType",
        RegistryValue::Dword(1),
    );
    wrong.set_value(
        Hive::LocalMachine,
        os_keys::TERMINAL_SERVER,
        "TSAppCompat",
        RegistryValue::String("1".into()),
    );
    let p = Profile::read(&wrong);
    assert!(!p.session_host);
    assert_eq!(p.problems.len(), 2, "{p:?}");
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
fn an_unreadable_registry_is_a_workstation_with_problems() {
    let p = Profile::read(&Broken);
    assert_eq!(p.device_class(), DeviceClass::Workstation);
    assert!(p.interactive_helpers());
    assert!(!p.problems.is_empty());
    p.log();
    assert_eq!(DeviceClass::MultiSession.to_string(), "MultiSession");
    assert_eq!(DeviceClass::Server.as_str(), "Server");
    assert_eq!(DeviceClass::Workstation.as_str(), "Workstation");
}

#[cfg(not(windows))]
#[test]
fn other_oses_are_a_plain_workstation() {
    let p = Profile::current();
    assert_eq!(p.device_class(), DeviceClass::Workstation);
    assert!(p.interactive_helpers());
}
