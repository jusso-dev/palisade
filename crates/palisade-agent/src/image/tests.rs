use std::path::PathBuf;

use palisade_core::test_util::MockRegistry;

use super::*;

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp(tag: &str) -> Dir {
    let dir =
        std::env::temp_dir().join(format!("palisade-agent-image-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Dir(dir)
}

fn machine(guid: &str) -> MockRegistry {
    let mut r = MockRegistry::new();
    r.set_value(
        Hive::LocalMachine,
        os_keys::CRYPTOGRAPHY,
        "MachineGuid",
        RegistryValue::String(guid.to_owned()),
    );
    r
}

const TEMPLATE: &str = "11111111-2222-3333-4444-555555555555";
const CLONE: &str = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";

/// A data folder as an enrolled template leaves it.
fn populate(dir: &Path) {
    for name in PER_DEVICE_FILES {
        fs::write(dir.join(name), b"per-device").unwrap();
    }
    for name in KEPT_DIRS.iter().chain(PER_DEVICE_DIRS) {
        fs::create_dir_all(dir.join(name)).unwrap();
        fs::write(dir.join(name).join("data"), b"x").unwrap();
    }
    fs::create_dir_all(dir.join("queue/segment")).unwrap();
    fs::write(dir.join("queue/segment/1"), b"event").unwrap();
    fs::write(dir.join("agent.toml"), b"").unwrap();
}

#[test]
fn sealing_removes_the_device_identity_and_keeps_the_baseline() {
    let dir = temp("seal");
    populate(&dir.0);
    let template = machine(TEMPLATE);
    let report = seal(&template, &dir.0).unwrap();
    for name in PER_DEVICE_FILES {
        assert!(!dir.0.join(name).exists(), "{name}");
        assert!(report.removed.contains(&(*name).to_owned()), "{name}");
    }
    assert!(report.removed.contains(&"queue/*".to_owned()));
    assert_eq!(fs::read_dir(dir.0.join("queue")).unwrap().count(), 0);
    for name in KEPT_DIRS {
        assert!(dir.0.join(name).join("data").exists(), "{name}");
    }
    assert!(dir.0.join("agent.toml").exists());
    assert_eq!(fs::read_to_string(dir.0.join(SEAL_FILE)).unwrap(), TEMPLATE);
    assert!(!dir.0.join("image.tmp").exists());

    // The template itself, rebooted before capture, does not enrol.
    let state = identity_state(&template, &dir.0).unwrap();
    assert_eq!(state, IdentityState::SealedTemplate);
    assert!(!state.may_enrol() && !state.identity_usable());

    // Sealing again is harmless.
    let again = seal(&template, &dir.0).unwrap();
    assert!(again.removed.iter().all(|r| r == "queue/*"));
}

#[test]
fn a_clone_gets_a_new_identity_once() {
    let dir = temp("clone");
    populate(&dir.0);
    seal(&machine(TEMPLATE), &dir.0).unwrap();
    let clone = machine(CLONE);
    let state = identity_state(&clone, &dir.0).unwrap();
    assert_eq!(state, IdentityState::FirstBootClone);
    assert!(state.may_enrol() && !state.identity_usable());

    finish_reidentify(&clone, &dir.0).unwrap();
    assert!(!dir.0.join(SEAL_FILE).exists());
    assert_eq!(
        fs::read_to_string(dir.0.join(IDENTITY_FILE)).unwrap(),
        CLONE.to_ascii_lowercase()
    );
    let state = identity_state(&clone, &dir.0).unwrap();
    assert_eq!(state, IdentityState::Normal);
    assert!(state.may_enrol() && state.identity_usable());
    // Finishing twice is harmless.
    finish_reidentify(&clone, &dir.0).unwrap();
}

#[test]
fn an_identity_from_another_machine_is_never_used() {
    let dir = temp("copied");
    record_identity_machine(&machine(TEMPLATE), &dir.0).unwrap();
    assert_eq!(
        identity_state(&machine(TEMPLATE), &dir.0).unwrap(),
        IdentityState::Normal
    );
    // Case and whitespace do not matter.
    assert_eq!(
        identity_state(
            &machine(&format!(" {} ", TEMPLATE.to_ascii_uppercase())),
            &dir.0
        )
        .unwrap(),
        IdentityState::Normal
    );
    let state = identity_state(&machine(CLONE), &dir.0).unwrap();
    assert_eq!(state, IdentityState::CopiedIdentity);
    assert!(state.may_enrol() && !state.identity_usable());
    // An empty or damaged marker matches no machine.
    fs::write(dir.0.join(IDENTITY_FILE), b"").unwrap();
    assert_eq!(
        identity_state(&machine(TEMPLATE), &dir.0).unwrap(),
        IdentityState::CopiedIdentity
    );
}

#[test]
fn without_a_machine_guid_nothing_is_trusted_or_sealed() {
    let dir = temp("noguid");
    // Nothing to check: carry on.
    assert_eq!(
        identity_state(&MockRegistry::new(), &dir.0).unwrap(),
        IdentityState::Normal
    );
    record_identity_machine(&machine(TEMPLATE), &dir.0).unwrap();
    for r in [MockRegistry::new(), machine("  "), {
        let mut r = MockRegistry::new();
        r.set_value(
            Hive::LocalMachine,
            os_keys::CRYPTOGRAPHY,
            "MachineGuid",
            RegistryValue::Dword(1),
        );
        r
    }] {
        let state = identity_state(&r, &dir.0).unwrap();
        assert!(matches!(state, IdentityState::Unknown(_)), "{state:?}");
        assert!(!state.may_enrol() && !state.identity_usable());
        assert!(state.to_string().contains("MachineGuid"));
        // Sealing without the GUID changes nothing.
        assert!(seal(&r, &dir.0).is_err());
        assert!(dir.0.join(IDENTITY_FILE).exists());
        assert!(!dir.0.join(SEAL_FILE).exists());
        assert!(finish_reidentify(&r, &dir.0).is_err());
    }
    for state in [
        IdentityState::Normal,
        IdentityState::SealedTemplate,
        IdentityState::FirstBootClone,
        IdentityState::CopiedIdentity,
    ] {
        assert!(!state.to_string().is_empty());
    }
}

#[test]
fn the_seal_removes_the_enrolment_token() {
    assert!(PER_DEVICE_FILES.contains(&crate::bootstrap::PROTECTED_FILE));
    assert!(PER_DEVICE_FILES.contains(&crate::bootstrap::HANDOFF_FILE));
    // The policy cache is kept: clones enforce before their first check-in.
    assert!(KEPT_DIRS.contains(&"policy"));
    assert!(!PER_DEVICE_DIRS.contains(&"policy"));
}
