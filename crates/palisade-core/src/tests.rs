use alloc::string::ToString;

use proptest::prelude::*;

use crate::{Mode, ObjectType, SchemaVersion, ScriptKind, Uuid7};

const SAMPLE: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";

#[test]
fn uuid7_parses_and_prints_canonical_form() {
    let id: Uuid7 = SAMPLE.parse().unwrap();
    assert_eq!(id.to_string(), SAMPLE);
    assert_eq!(id.as_bytes()[6] >> 4, 7);
}

#[test]
fn uuid7_rejects_non_canonical_text() {
    for bad in [
        "",
        "01936B2E-8C4A-7B3D-9F21-0A1B2C3D4E5F",   // uppercase
        "01936b2e8c4a7b3d9f210a1b2c3d4e5f",       // no hyphens
        "{01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f}", // braces
        "01936b2e-8c4a-4b3d-9f21-0a1b2c3d4e5f",   // version 4
        "01936b2e-8c4a-7b3d-cf21-0a1b2c3d4e5f",   // wrong variant
        "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5g",   // not hex
        "01936b2e-8c4a-7b3d-9f21_0a1b2c3d4e5f",   // wrong separator
        "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5",    // short
        "01936b2e-8c4a-7b3d-9f2-10a1b2c3d4e5f",   // hyphen in the wrong place
    ] {
        assert!(bad.parse::<Uuid7>().is_err(), "accepted {bad:?}");
    }
}

#[test]
fn uuid7_from_bytes_checks_version_and_variant() {
    let mut bytes = [0u8; 16];
    assert!(Uuid7::from_bytes(bytes).is_none());
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    assert!(Uuid7::from_bytes(bytes).is_some());
    bytes[8] = 0xc0;
    assert!(Uuid7::from_bytes(bytes).is_none());
}

#[test]
fn schema_version_text_form_is_strict() {
    let v: SchemaVersion = "1.20.3".parse().unwrap();
    assert_eq!(v, SchemaVersion::new(1, 20, 3));
    assert_eq!(v.to_string(), "1.20.3");
    for bad in [
        "",
        "1",
        "1.0",
        "1.0.0.0",
        "01.0.0",
        "1.00.0",
        "+1.0.0",
        "1.0.0-rc.1",
        "1.0.0+b",
        " 1.0.0",
        "1..0",
        "a.b.c",
    ] {
        assert!(bad.parse::<SchemaVersion>().is_err(), "accepted {bad:?}");
    }
}

#[test]
fn schema_version_readers_accept_same_major_only() {
    let reader = SchemaVersion::new(1, 2, 0);
    assert!(SchemaVersion::new(1, 0, 0).is_readable_by(reader));
    assert!(SchemaVersion::new(1, 9, 4).is_readable_by(reader));
    assert!(!SchemaVersion::new(0, 9, 0).is_readable_by(reader));
    assert!(!SchemaVersion::new(2, 0, 0).is_readable_by(reader));
}

#[test]
fn object_type_names() {
    assert_eq!(ObjectType::Executable.to_string(), "executable");
    assert_eq!(
        ObjectType::ControlPanelApplet.to_string(),
        "control_panel_applet"
    );
    assert_eq!(
        ObjectType::Script(ScriptKind::Powershell).to_string(),
        "script.powershell"
    );
    for bad in ["script", "script.", "script.nope", "Executable", "exe", ""] {
        assert!(bad.parse::<ObjectType>().is_err(), "accepted {bad:?}");
    }
}

#[test]
fn object_type_all_is_complete_and_round_trips() {
    let mut seen = alloc::vec::Vec::new();
    for t in ObjectType::ALL {
        assert!(!seen.contains(&t), "duplicate {t}");
        seen.push(t);
        assert_eq!(t.to_string().parse::<ObjectType>().unwrap(), t);
    }
    for kind in ScriptKind::ALL {
        assert!(seen.contains(&ObjectType::Script(kind)));
    }
}

#[test]
fn mode_orders_weakest_to_strongest() {
    assert!(Mode::Disabled < Mode::Monitor);
    assert!(Mode::Monitor < Mode::Audit);
    assert!(Mode::Learning < Mode::Enforce);
}

#[cfg(feature = "serde")]
#[test]
fn serde_uses_text_forms() {
    let id: Uuid7 = SAMPLE.parse().unwrap();
    assert_eq!(
        serde_json::to_string(&id).unwrap(),
        alloc::format!("\"{SAMPLE}\"")
    );
    assert_eq!(
        serde_json::to_string(&Mode::Enforce).unwrap(),
        "\"enforce\""
    );
    assert_eq!(
        serde_json::to_string(&ObjectType::Script(ScriptKind::Cmd)).unwrap(),
        "\"script.cmd\""
    );
    assert!(serde_json::from_str::<Uuid7>("\"not-a-uuid\"").is_err());
    assert!(serde_json::from_str::<Mode>("2").is_err());
}

prop_compose! {
    fn any_uuid7()(mut bytes in any::<[u8; 16]>()) -> Uuid7 {
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid7::from_bytes(bytes).unwrap()
    }
}

proptest! {
    #[test]
    fn uuid7_text_round_trip(id in any_uuid7()) {
        let text = id.to_string();
        prop_assert_eq!(text.len(), 36);
        prop_assert_eq!(text.to_ascii_lowercase(), text.clone());
        prop_assert_eq!(text.parse::<Uuid7>().unwrap(), id);
    }

    #[test]
    fn uuid7_parse_never_panics(s in "\\PC{0,40}") {
        let _ = s.parse::<Uuid7>();
    }

    #[test]
    fn schema_version_text_round_trip(a: u64, b: u64, c: u64) {
        let v = SchemaVersion::new(a, b, c);
        prop_assert_eq!(v.to_string().parse::<SchemaVersion>().unwrap(), v);
    }

    #[test]
    fn schema_version_parse_never_panics(s in "[0-9.+a-z-]{0,30}") {
        let _ = s.parse::<SchemaVersion>();
    }
}
