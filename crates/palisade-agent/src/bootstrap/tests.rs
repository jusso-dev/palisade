use std::path::PathBuf;

use palisade_core::test_util::{MockFile, MockFileSystem, MockRegistry};
use palisade_fileid::fsctx::{
    acl::{Ace, mask},
    sid::{Sid, well_known},
};

use super::*;
use crate::policy_cache::protect::MemoryProtector;

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp(tag: &str) -> Dir {
    let dir = std::env::temp_dir().join(format!(
        "palisade-agent-bootstrap-{tag}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Dir(dir)
}

fn locked() -> Vec<u8> {
    SecurityDescriptor::new(
        Some(well_known::LOCAL_SYSTEM),
        Some(vec![
            Ace::allow(well_known::LOCAL_SYSTEM, mask::FILE_ALL_ACCESS),
            Ace::allow(well_known::ADMINISTRATORS, mask::FILE_ALL_ACCESS),
        ]),
    )
    .to_self_relative()
    .unwrap()
}

fn writable_by(sid: Sid) -> Vec<u8> {
    SecurityDescriptor::new(
        Some(well_known::LOCAL_SYSTEM),
        Some(vec![
            Ace::allow(well_known::LOCAL_SYSTEM, mask::FILE_ALL_ACCESS),
            Ace::allow(sid, mask::FILE_ALL_ACCESS),
        ]),
    )
    .to_self_relative()
    .unwrap()
}

/// Descriptors for the data folder and the handoff file. `None` means
/// unreadable.
fn descriptors(dir: &Path, dir_sd: Option<Vec<u8>>, file_sd: Option<Vec<u8>>) -> MockFileSystem {
    let mut fs = MockFileSystem::new();
    let mut d = MockFile::directory();
    if let Some(sd) = dir_sd {
        d = d.descriptor(sd);
    }
    fs.insert(&dir.to_string_lossy(), d);
    let mut f = MockFile::new(Vec::new());
    if let Some(sd) = file_sd {
        f = f.descriptor(sd);
    }
    fs.insert(&dir.join(HANDOFF_FILE).to_string_lossy(), f);
    fs
}

const TOKEN: &str = "pal-ABCDEF123456-xyz";

#[test]
fn tokens_are_one_safe_word_and_never_printed() {
    let token = EnrollToken::parse(&format!("  {TOKEN}\r\n")).unwrap();
    assert_eq!(token.expose(), TOKEN);
    let shown = format!("{token:?}");
    assert!(!shown.contains(TOKEN));
    assert!(shown.contains(&TOKEN.len().to_string()));
    for bad in [
        "",
        "   ",
        "two words",
        "quote\"d",
        "semi;colon",
        "line\nbreak",
        "tab\tbed",
        "ünïcode",
    ] {
        assert_eq!(
            EnrollToken::parse(bad),
            Err(HandoffProblem::Malformed),
            "{bad:?}"
        );
    }
    assert!(EnrollToken::parse(&"a".repeat(MAX_TOKEN_BYTES)).is_ok());
    assert!(EnrollToken::parse(&"a".repeat(MAX_TOKEN_BYTES + 1)).is_err());
    assert!(EnrollToken::parse("a-b.c_d~e+f/g=h:i").is_ok());
    for problem in [
        HandoffProblem::Unprotected,
        HandoffProblem::Malformed,
        HandoffProblem::Unreadable,
    ] {
        assert!(!problem.to_string().is_empty());
    }
}

#[test]
fn a_protected_handoff_is_stored_protected_and_deleted() {
    let dir = temp("stored");
    fs::write(dir.0.join(HANDOFF_FILE), format!("{TOKEN}\n")).unwrap();
    let mock = descriptors(&dir.0, Some(locked()), Some(locked()));
    let protector = MemoryProtector::new().unwrap();

    assert_eq!(
        take_handoff(&mock, &protector, &dir.0).unwrap(),
        Handoff::Stored
    );
    assert!(!dir.0.join(HANDOFF_FILE).exists());
    let stored = fs::read(dir.0.join(PROTECTED_FILE)).unwrap();
    assert!(!stored.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    assert!(!dir.0.join("enroll.token.tmp").exists());

    let token = load_token(&protector, &dir.0).unwrap().unwrap();
    assert_eq!(token.expose(), TOKEN);
    // Another machine (another key) cannot read it.
    let other = MemoryProtector::new().unwrap();
    assert!(load_token(&other, &dir.0).is_err());

    // Nothing more to take over.
    assert_eq!(
        take_handoff(&mock, &protector, &dir.0).unwrap(),
        Handoff::Absent
    );
    consume_token(&dir.0).unwrap();
    assert!(load_token(&protector, &dir.0).unwrap().is_none());
    // Consuming twice is fine.
    consume_token(&dir.0).unwrap();
}

#[test]
fn an_unprotected_handoff_is_deleted_and_not_used() {
    for (tag, dir_sd, file_sd) in [
        (
            "file-users",
            Some(locked()),
            Some(writable_by(well_known::USERS)),
        ),
        (
            "dir-everyone",
            Some(writable_by(well_known::EVERYONE)),
            Some(locked()),
        ),
        ("file-unreadable", Some(locked()), None),
        ("dir-unreadable", None, Some(locked())),
        ("file-garbage", Some(locked()), Some(vec![1, 2, 3])),
    ] {
        let dir = temp(tag);
        fs::write(dir.0.join(HANDOFF_FILE), TOKEN).unwrap();
        let mock = descriptors(&dir.0, dir_sd, file_sd);
        let protector = MemoryProtector::new().unwrap();
        assert_eq!(
            take_handoff(&mock, &protector, &dir.0).unwrap(),
            Handoff::Refused(HandoffProblem::Unprotected),
            "{tag}"
        );
        assert!(!dir.0.join(HANDOFF_FILE).exists(), "{tag}");
        assert!(!dir.0.join(PROTECTED_FILE).exists(), "{tag}");
    }
}

#[test]
fn a_malformed_handoff_is_deleted_and_not_used() {
    for (tag, content) in [
        ("empty", Vec::new()),
        ("spaces", b"two words".to_vec()),
        ("binary", vec![0xff, 0xfe, 0x00]),
        ("huge", vec![b'a'; MAX_TOKEN_BYTES + 3]),
    ] {
        let dir = temp(tag);
        fs::write(dir.0.join(HANDOFF_FILE), content).unwrap();
        let mock = descriptors(&dir.0, Some(locked()), Some(locked()));
        let protector = MemoryProtector::new().unwrap();
        assert_eq!(
            take_handoff(&mock, &protector, &dir.0).unwrap(),
            Handoff::Refused(HandoffProblem::Malformed),
            "{tag}"
        );
        assert!(!dir.0.join(HANDOFF_FILE).exists(), "{tag}");
        assert!(!dir.0.join(PROTECTED_FILE).exists(), "{tag}");
    }
}

#[test]
fn a_handoff_that_cannot_be_stored_stays_for_the_next_start() {
    let dir = temp("unstored");
    fs::write(dir.0.join(HANDOFF_FILE), TOKEN).unwrap();
    // A directory where the protected copy should go makes the rename fail.
    fs::create_dir(dir.0.join(PROTECTED_FILE)).unwrap();
    fs::write(dir.0.join(PROTECTED_FILE).join("x"), b"x").unwrap();
    let mock = descriptors(&dir.0, Some(locked()), Some(locked()));
    let protector = MemoryProtector::new().unwrap();
    let error = take_handoff(&mock, &protector, &dir.0).unwrap_err();
    assert!(!error.to_string().contains(TOKEN));
    assert!(dir.0.join(HANDOFF_FILE).exists());
}

#[test]
fn stashing_needs_a_protected_folder() {
    let dir = temp("stash");
    let token = EnrollToken::parse(TOKEN).unwrap();
    let protector = MemoryProtector::new().unwrap();

    for dir_sd in [None, Some(writable_by(well_known::AUTHENTICATED_USERS))] {
        let mock = descriptors(&dir.0, dir_sd, None);
        let error = stash_token(&mock, &protector, &dir.0, &token).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!error.to_string().contains(TOKEN));
        assert!(!dir.0.join(PROTECTED_FILE).exists());
    }

    let mock = descriptors(&dir.0, Some(locked()), None);
    stash_token(&mock, &protector, &dir.0, &token).unwrap();
    assert_eq!(
        load_token(&protector, &dir.0).unwrap().unwrap().expose(),
        TOKEN
    );
    // A second stash (a repair or reinstall with a new token) replaces it.
    let newer = EnrollToken::parse("newer-token").unwrap();
    stash_token(&mock, &protector, &dir.0, &newer).unwrap();
    assert_eq!(
        load_token(&protector, &dir.0).unwrap().unwrap().expose(),
        "newer-token"
    );
}

#[test]
fn a_damaged_stored_token_is_an_error_not_a_token() {
    let dir = temp("damaged");
    let protector = MemoryProtector::new().unwrap();
    fs::write(dir.0.join(PROTECTED_FILE), b"not a protected blob").unwrap();
    assert!(load_token(&protector, &dir.0).is_err());
    fs::write(
        dir.0.join(PROTECTED_FILE),
        protector.protect(b"two words", TOKEN_PURPOSE).unwrap(),
    )
    .unwrap();
    assert_eq!(
        load_token(&protector, &dir.0).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    // Protected for another purpose.
    fs::write(
        dir.0.join(PROTECTED_FILE),
        protector.protect(TOKEN.as_bytes(), b"other").unwrap(),
    )
    .unwrap();
    assert!(load_token(&protector, &dir.0).is_err());
    fs::write(dir.0.join(PROTECTED_FILE), vec![0u8; 20_000]).unwrap();
    assert!(load_token(&protector, &dir.0).is_err());
}

fn registry(values: &[(&str, RegistryValue)]) -> MockRegistry {
    let mut reg = MockRegistry::new();
    for (name, value) in values {
        reg.set_value(Hive::LocalMachine, SETTINGS_KEY, name, value.clone());
    }
    reg
}

fn s(text: &str) -> RegistryValue {
    RegistryValue::String(text.to_owned())
}

#[test]
fn install_settings_are_read_and_checked() {
    let (settings, problems) = InstallSettings::read(&registry(&[
        ("ServerUrl", s("https://palisade.example/")),
        ("GroupKey", s("lab")),
        ("Proxy", s("system")),
        ("Mode", s("enforce")),
    ]))
    .unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(
        settings,
        InstallSettings {
            server_url: Some("https://palisade.example/".into()),
            group_key: Some("lab".into()),
            proxy: Some("system".into()),
            mode: Some(Mode::Enforce),
            skip_enroll: false,
        }
    );
    for (name, mode) in [
        ("disabled", Mode::Disabled),
        ("monitor", Mode::Monitor),
        ("audit", Mode::Audit),
        ("learning", Mode::Learning),
        ("enforce", Mode::Enforce),
    ] {
        assert_eq!(mode_from_name(name), Some(mode));
    }

    let (bad, problems) = InstallSettings::read(&registry(&[
        ("ServerUrl", s("http://palisade.example/")),
        ("Mode", s("damaged")),
        ("GroupKey", RegistryValue::Dword(1)),
        ("Proxy", s("")),
        ("SkipEnroll", s("1")),
    ]))
    .unwrap();
    assert_eq!(
        bad,
        InstallSettings {
            skip_enroll: true,
            ..InstallSettings::default()
        }
    );
    assert_eq!(problems.len(), 3, "{problems:?}");

    let (none, problems) = InstallSettings::read(&MockRegistry::new()).unwrap();
    assert_eq!(none, InstallSettings::default());
    assert!(problems.is_empty());
    assert!(!is_https("https://"));
    assert!(is_https("HTTPS://x"));
}

#[test]
fn the_bootstrap_says_what_enrolment_does_next() {
    let server = || InstallSettings {
        server_url: Some("https://palisade.example/".into()),
        ..InstallSettings::default()
    };
    let cases = [
        (
            InstallSettings {
                skip_enroll: true,
                ..server()
            },
            true,
            NextStep::Offline,
        ),
        (InstallSettings::default(), true, NextStep::NeedsServer),
        (server(), false, NextStep::NeedsToken),
        (server(), true, NextStep::Enrol),
    ];
    for (settings, token_waiting, want) in cases {
        let b = Bootstrap {
            settings,
            token_waiting,
        };
        assert_eq!(b.next_step(), want, "{b:?}");
    }

    let dir = temp("bootstrap");
    let reg = registry(&[("ServerUrl", s("https://palisade.example/"))]);
    let (b, _) = Bootstrap::read(&reg, &dir.0).unwrap();
    assert_eq!(b.next_step(), NextStep::NeedsToken);
    fs::write(dir.0.join(PROTECTED_FILE), b"x").unwrap();
    let (b, _) = Bootstrap::read(&reg, &dir.0).unwrap();
    assert_eq!(b.next_step(), NextStep::Enrol);
}
